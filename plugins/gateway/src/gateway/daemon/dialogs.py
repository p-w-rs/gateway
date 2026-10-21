"""Native dialogs (PLAN-v4 phase 3): the requests, the queue, sealed delivery.

A gateway program that must ask the person (popup.py's broker: a sudo
password, a token, a consent widening, a host key) takes a *lease* on the
agent plane (POST /agent/dialog/lease: a gateway entry point below a
registered session), then opens dialogs with it (the lease plane, /lease/*:
any gateway entry point of this user holding the lease token, because the
pop-up helper that asks is detached from the session's process tree). The
gate mod, inside the Claude Code process (the UI plane), long-polls
/ui/dialog/next and draws the session's current dialog as a pane; the other
requests of that session queue behind it, shown by identity (entry, what).
One dialog at a time per session.

Secrets never travel in plaintext between Claude Code and gated: each open
attempt of a secret dialog gets an X25519 key pair made here (PyNaCl,
libsodium); the private half never leaves this process. The pane's Client
field seals what the person typed with NaCl's box (vendored TweetNaCl in the
mod) to that public key, under a fresh ephemeral key, and the mod forwards
{id, attempt, epk, nonce, box}. Here the box is opened, its plaintext must
name this request and attempt, and the request is rechecked (still open, its
session alive and not paused, its lease's programs alive, the entry still in
the form with the same section, kind and right) before the value is handed,
once, to the program that asked (over the lease plane: a gateway process,
the same trust as a vault read). "Paste from clipboard" makes this process
read the clipboard itself (clipboard.py). A submit carrying a plaintext
value is refused: the route reads boxes only.

The program that asked verifies the value where it can (sudo, an ssh key's
passphrase, a token through its adapter) and answers retry (the dialog
reopens with "That didn't work: ..." and a new key pair, up to MAX_TRIES
attempts) or close (ok / failed / cancelled). The vault's own dialogs
(unlock, set a passphrase) belong to this process: the broker checks them.

Cleanup on every exit path: the key pair and any answer not yet handed over
are dropped when a dialog closes (ok, cancel, timeout, failure, its session
ending, its lease expiring or its programs dying, a pause); a handed-over
answer is dropped at once. Python strings can't be wiped; the plaintext
bytes from a box are overwritten (bytearray) once parsed.

Survival: the requests (metadata only: never a key, a value or a lease
token, only its sha256) are kept in <run>/gated-dialogs.json, so a daemon
restarted after a crash or kill shows them again with new key pairs, and a
mod reloaded mid-dialog finds them here (/reload-plugins).

Events: auth.waiting {request, session, dialog (its kind)} and auth.supplied
{request, outcome}; never a value, a name or text.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable


from . import clipboard, peers

KINDS = ("secret", "confirm", "choice", "checklist", "text", "info", "passphrase", "unlock")
SECRET_KINDS = ("secret", "passphrase", "unlock")
OUTCOMES = ("ok", "cancelled", "timeout", "failed", "unavailable", "paused")
MAX_TRIES = 3
WAIT_MAX = 25.0
DEFAULT_LIFETIME = 1800.0
LEASE_LIFETIME = 1800.0 + 300.0
MAX_VALUE_BYTES = 8192
MAX_LINES = 40
MAX_LINE = 400
MAX_OPTIONS = 40
MAX_OPEN = 50                       # open dialogs at once, all sessions
RECENT_KEEP = 8
REPLAY_TTL = 24 * 3600.0             # CONTRACT-v1 pause_id: how long a pause's answer is replayed
REPLAY_MAX = 500
CLIENT_SURFACES = ("terminal", "desktop")
# gated's own dialogs whose answer goes to a handler in this process (never
# persisted: a restarted gated asks again): "terminal", a password prompt in
# a gateway terminal (daemon/terminals.py); "gated", a confirmation or a
# notice gated itself asks (a remote host's changed host key or machine, a
# refused key: daemon/remote.py, PLAN-v4 phase 6)
OWNED = ("terminal", "gated")
_ID = re.compile(r"d_[0-9a-f]{16}")
_TOKEN = re.compile(r"[0-9a-f]{64}")
_NAME = re.compile(r"[A-Za-z0-9_.@:-]{1,64}")

UNAVAILABLE = {
    "no_session": ("this program isn't running inside a Claude Code session the gateway knows, so "
                   "no gateway dialog can open"),
    "no_mod": ("the gateway mod isn't running in this Claude Code session (mods are switched off, "
               "or Claude Code is older than 2.1.287), so no gateway dialog can open: credential "
               "entry is unavailable here"),
    "print": ("this is claude -p or the Agent SDK, where no gateway dialog can open: credential "
              "entry is unavailable here"),
    "mobile": ("this session draws only on mobile or a Remote Control client, which has no private "
               "input field: credential entry is unavailable there"),
    "vscode": ("this session draws only in VS Code, which shows no gateway dialog yet: credential "
               "entry is unavailable there"),
    "paused": "the task is paused (checkpoint), so nothing is asked until it is resumed",
    "busy": "too many gateway dialogs are open",
}


class DialogError(Exception):
    """A refused dialog call: (http status, code, message)."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def _nacl() -> Any:
    """PyNaCl (libsodium), gated only. The daemon runs with `-I -S` (no site:
    no sitecustomize or .pth file of the env ever runs), so the env's own
    site-packages folder is appended to sys.path here, for this import only
    (stdlib modules still resolve first; .pth files are not processed)."""
    try:
        from nacl import exceptions, public
    except ImportError:
        import sys
        import sysconfig
        for key in ("platlib", "purelib"):
            p = sysconfig.get_paths().get(key)
            if p and p not in sys.path:
                sys.path.append(p)
        from nacl import exceptions, public
    return public, exceptions


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(s: Any, size: int | None = None, limit: int = 65536) -> bytes:
    if not isinstance(s, str) or len(s) > limit * 2:
        raise DialogError(400, "bad_request", "gateway: expected base64 data")
    try:
        raw = base64.b64decode(s, validate=True)
    except ValueError:
        raise DialogError(400, "bad_request", "gateway: expected base64 data") from None
    if size is not None and len(raw) != size:
        raise DialogError(400, "bad_request", "gateway: a sealed value has the wrong size")
    return raw


def clean_text(s: Any, limit: int = MAX_LINE) -> str:
    """One line shown in a pane: printable, no control characters, bounded."""
    if not isinstance(s, str):
        return ""
    s = s.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    s = "".join(c for c in s if c.isprintable())
    return s[:limit]


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _now() -> float:
    return time.time()


class Lease:
    def __init__(self, token_hash: str, session_pid: int, session_start: float | None,
                 session_id: str, expires: float, mode: str = ""):
        self.hash = token_hash
        self.session_pid = session_pid
        self.session_start = session_start
        self.session_id = session_id
        self.expires = expires
        self.mode = mode
        self.pids: dict[int, float | None] = {}

    def to_json(self) -> dict[str, Any]:
        return {"hash": self.hash, "session_pid": self.session_pid,
                "session_start": self.session_start, "session_id": self.session_id,
                "expires": self.expires, "mode": self.mode,
                "pids": [[p, s] for p, s in self.pids.items()]}

    @classmethod
    def from_json(cls, d: dict[str, Any]) -> "Lease":
        le = cls(str(d["hash"]), int(d["session_pid"]), d.get("session_start"),
                 str(d.get("session_id") or ""), float(d["expires"]), str(d.get("mode") or ""))
        for p, s in d.get("pids") or []:
            le.pids[int(p)] = s
        return le


class Request:
    FIELDS = ("id", "kind", "owner", "lease", "session_pid", "session_start", "session_id",
              "title", "entry", "what", "target", "lines", "options", "checked", "default",
              "ok_label", "cancel_label", "default_cancel", "fields", "remember", "paste",
              "input", "check", "pem",
              "created", "deadline", "attempt", "error", "order")

    def __init__(self, **kw: Any):
        self.id: str = kw["id"]
        self.kind: str = kw["kind"]
        self.owner: str = kw.get("owner", "lease")       # "lease" | "vault"
        self.lease: str = kw.get("lease", "")            # the lease's token hash
        self.session_pid: int = int(kw["session_pid"])
        self.session_start: float | None = kw.get("session_start")
        self.session_id: str = kw.get("session_id", "")
        self.title: str = kw.get("title", "")
        self.entry: str = kw.get("entry", "")
        self.what: str = kw.get("what", "")
        self.target: str = kw.get("target", "")
        self.lines: list[str] = list(kw.get("lines") or [])
        self.options: list[str] = list(kw.get("options") or [])
        self.checked: list[str] = list(kw.get("checked") or [])
        self.default: str = kw.get("default", "")
        self.ok_label: str = kw.get("ok_label", "OK")
        self.cancel_label: str = kw.get("cancel_label", "Cancel")
        self.default_cancel: bool = bool(kw.get("default_cancel", False))
        self.fields: int = int(kw.get("fields", 0))
        self.remember: bool | None = kw.get("remember")
        self.paste: bool = bool(kw.get("paste", False))
        self.input: bool = bool(kw.get("input", False))
        self.check: dict[str, Any] | None = kw.get("check")
        # PLAN-v4 phase 7: a PEM certificate and key (an Azure service
        # principal's certificate): Paste may bring several lines
        self.pem: bool = bool(kw.get("pem", False))
        self.created: float = float(kw.get("created", _now()))
        self.deadline: float = float(kw.get("deadline", _now() + DEFAULT_LIFETIME))
        self.attempt: int = int(kw.get("attempt", 1))
        self.error: str = kw.get("error", "")
        self.order: int = int(kw.get("order", 0))
        self.state = "open"                  # open | checking | done
        self.outcome = ""
        self.note = ""
        self.answer: dict[str, Any] | None = None
        self.key: Any = None                 # nacl PrivateKey for secret kinds (this attempt)
        self.busy = False                    # a vault dialog's answer is being checked

    def to_json(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in self.FIELDS}

    def secret(self) -> bool:
        return self.kind in SECRET_KINDS

    def new_key(self) -> None:
        if self.secret():
            public, _exc = _nacl()
            self.key = public.PrivateKey.generate()

    def drop(self) -> None:
        """Forget the key pair and any answer (every exit path)."""
        self.key = None
        if self.answer is not None:
            self.answer.clear()
        self.answer = None

    def public(self, now: float) -> dict[str, Any]:
        out = {"id": self.id, "kind": self.kind, "title": self.title, "entry": self.entry,
               "what": self.what, "target": self.target, "lines": self.lines,
               "options": self.options, "checked": self.checked, "default": self.default,
               "ok_label": self.ok_label, "cancel_label": self.cancel_label,
               "default_cancel": self.default_cancel,
               "fields": self.fields, "remember": self.remember, "paste": self.paste,
               "input": self.input, "pem": self.pem, "attempt": self.attempt, "max": MAX_TRIES,
               "error": self.error, "state": self.state,
               "expires_in": max(0, int(self.deadline - now))}
        if self.secret() and self.key is not None:
            out["pub"] = _b64(bytes(self.key.public_key))
        return out

    def ident(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "entry": self.entry, "what": self.what}


class Dialogs:
    """The dialog store. `daemon` gives registry, broker, events and log."""

    def __init__(self, daemon: Any, path: Path | None = None):
        self.d = daemon
        self.path = path
        self.lock = threading.RLock()
        self.cond = threading.Condition(self.lock)
        self.rev = 1
        self.order = 0
        self.requests: dict[str, Request] = {}
        self.leases: dict[str, Lease] = {}
        self.paused: set[str] = set()
        # CONTRACT-v1 pause_id (PLAN-v4 phase 7): (kind, session, pause_id) ->
        # (when, the first answer); a repeat within REPLAY_TTL gets that answer
        # back and nothing is applied again
        self.replays: dict[str, tuple[float, dict[str, Any]]] = {}
        self.recent: list[dict[str, Any]] = []
        self.handlers: dict[str, Callable[[Request, list[str]], tuple[bool, str]]] = {}
        # gated's own secret dialogs for a password prompt in a gateway terminal
        # (daemon/terminals.py): request id -> (handler, on_close); in memory
        # only (a restarted gated asks again while the prompt still waits)
        self.owned: dict[str, tuple[Callable[[Request, list[str]], tuple[bool, str]],
                                    Callable[[str, str], None] | None]] = {}
        self._done: dict[str, Request] = {}      # recently closed, for a waiter that comes back
        self._load()

    # -- persistence -----------------------------------------------------------
    def _load(self) -> None:
        if self.path is None:
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        now = _now()
        for d in raw.get("leases") or []:
            try:
                le = Lease.from_json(d)
            except (KeyError, TypeError, ValueError):
                continue
            if le.expires > now:
                self.leases[le.hash] = le
        for d in raw.get("requests") or []:
            try:
                r = Request(**{k: d[k] for k in Request.FIELDS if k in d})
            except (KeyError, TypeError, ValueError):
                continue
            if r.kind not in KINDS or not _ID.fullmatch(r.id) or r.deadline <= now:
                continue
            if r.owner == "lease" and r.lease not in self.leases:
                continue
            if r.owner in OWNED:
                continue                       # its handler lived in the old process
            r.new_key()
            self.requests[r.id] = r
            self.order = max(self.order, r.order)
        self.paused = {s for s in raw.get("paused") or [] if isinstance(s, str)}
        for k, v in (raw.get("replays") or {}).items() if isinstance(raw.get("replays"), dict) else []:
            if isinstance(k, str) and isinstance(v, list) and len(v) == 2 and \
                    isinstance(v[0], (int, float)) and isinstance(v[1], dict) and \
                    now - float(v[0]) < REPLAY_TTL:
                self.replays[k] = (float(v[0]), v[1])
        self._save()

    def _save(self) -> None:
        if self.path is None:
            return
        live = [r for r in self.requests.values() if r.state != "done" and r.owner not in OWNED]
        used = {r.lease for r in live}
        data = {"requests": [r.to_json() for r in live],
                "leases": [le.to_json() for h, le in self.leases.items()
                           if h in used or le.expires > _now()],
                "paused": sorted(self.paused),
                "replays": {k: [t, b] for k, (t, b) in self.replays.items()}}
        tmp = self.path.with_name(f".{self.path.name}.{os.getpid()}.tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f)
            os.replace(tmp, self.path)
        except OSError:
            try:
                tmp.unlink()
            except OSError:
                pass

    def _changed(self) -> None:
        self.rev += 1
        self._save()
        self.cond.notify_all()

    # -- who may be asked --------------------------------------------------------
    def available(self, session: Any) -> tuple[bool, str]:
        """Can a dialog open in this session? (False, reason code) otherwise."""
        if session is None:
            return False, "no_session"
        if session.session_id and session.session_id in self.paused:
            return False, "paused"
        if not session.ui:
            return False, "no_mod"
        surfaces = list(getattr(session, "surfaces", None) or [])
        if not surfaces and session.surface:
            surfaces = [session.surface]
        if any(s in CLIENT_SURFACES for s in surfaces):
            return True, ""
        if not surfaces:
            return False, "print"
        if "mobile" in surfaces:
            return False, "mobile"
        if "vscode" in surfaces:
            return False, "vscode"
        return False, "mobile"

    # -- the lease plane (the program that asks) ----------------------------------
    def lease(self, session: Any, peer_pid: int, mode: str = "") -> dict[str, Any]:
        ok, why = self.available(session)
        if not ok:
            return {"ok": True, "available": False, "reason": why, "message": UNAVAILABLE[why]}
        token = secrets.token_hex(32)
        with self.lock:
            le = Lease(_hash(token), session.pid, session.start, session.session_id,
                       _now() + LEASE_LIFETIME, mode)
            le.pids[peer_pid] = peers.started(peer_pid)
            self.leases[le.hash] = le
            self._save()
        return {"ok": True, "available": True, "lease": token, "expires_in": int(LEASE_LIFETIME)}

    def _lease(self, token: Any, peer_pid: int) -> Lease:
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            raise DialogError(403, "lease", "gateway: no valid dialog lease")
        h = _hash(token)
        le = self.leases.get(h)
        if le is None or le.expires <= _now() or not hmac.compare_digest(le.hash, h):
            raise DialogError(403, "lease", "gateway: that dialog lease has expired")
        if peer_pid not in le.pids:
            le.pids[peer_pid] = peers.started(peer_pid)
        return le

    def _req(self, rid: Any) -> Request:
        if not isinstance(rid, str) or not _ID.fullmatch(rid) or rid not in self.requests:
            raise DialogError(404, "no_dialog", "gateway: no such dialog")
        return self.requests[rid]

    def open(self, token: Any, peer_pid: int, spec: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            le = self._lease(token, peer_pid)
            session = self.d.registry.live(le.session_pid)
            if session is None:
                return {"ok": True, "available": False, "reason": "no_session",
                        "message": "gateway: the Claude Code session that asked has ended"}
            ok, why = self.available(session)
            if not ok:
                return {"ok": True, "available": False, "reason": why, "message": UNAVAILABLE[why]}
            if sum(1 for r in self.requests.values() if r.state != "done") >= MAX_OPEN:
                return {"ok": True, "available": False, "reason": "busy", "message": UNAVAILABLE["busy"]}
            r = self._new(spec, owner="lease", lease=le.hash, session=session)
            self._changed()
        self.d.events.emit("auth.waiting", request=r.id, session=r.session_id or None, dialog=r.kind)
        return {"ok": True, "available": True, "id": r.id}

    def _new(self, spec: dict[str, Any], *, owner: str, lease: str, session: Any) -> Request:
        kind = spec.get("kind")
        if kind not in KINDS:
            raise DialogError(400, "bad_request", "gateway: unknown dialog kind")
        lines = [clean_text(x) for x in (spec.get("lines") or [])[:MAX_LINES] if isinstance(x, str)]
        options = [clean_text(x, 120) for x in (spec.get("options") or [])[:MAX_OPTIONS]
                   if isinstance(x, str)]
        checked = [x for x in (spec.get("checked") or []) if isinstance(x, str) and x in options]
        fields = {"secret": 1, "unlock": 1, "passphrase": 2}.get(kind, 0)
        try:
            life = float(spec.get("timeout") or DEFAULT_LIFETIME)
        except (TypeError, ValueError):
            life = DEFAULT_LIFETIME
        life = min(max(life, 5.0), DEFAULT_LIFETIME)
        entry = spec.get("entry") if isinstance(spec.get("entry"), str) and \
            _NAME.fullmatch(spec.get("entry") or "") else ""
        check = spec.get("check") if isinstance(spec.get("check"), dict) else None
        remember = spec.get("remember")
        self.order += 1
        r = Request(id="d_" + secrets.token_hex(8), kind=kind, owner=owner, lease=lease,
                    session_pid=session.pid, session_start=session.start,
                    session_id=session.session_id, title=clean_text(spec.get("title"), 120),
                    entry=entry, what=clean_text(spec.get("what"), 48),
                    target=clean_text(spec.get("target"), 120), lines=lines, options=options,
                    checked=checked, default=clean_text(spec.get("default"), 4000),
                    ok_label=clean_text(spec.get("ok_label") or "OK", 40),
                    cancel_label=clean_text(spec.get("cancel_label") or "Cancel", 40),
                    default_cancel=bool(spec.get("default_cancel")),
                    fields=fields,
                    remember=remember if isinstance(remember, bool) and kind == "secret" else None,
                    paste=bool(spec.get("paste", True)) and kind in ("secret", "unlock"),
                    input=bool(spec.get("input")) and kind == "text",
                    pem=bool(spec.get("pem")) and kind == "secret",
                    check=check, created=_now(), deadline=_now() + life, order=self.order)
        r.new_key()
        self.requests[r.id] = r
        return r

    def _mine(self, le: Lease, rid: Any) -> Request:
        r = self._find(rid)
        if r.owner != "lease" or not hmac.compare_digest(r.lease, le.hash):
            raise DialogError(404, "no_dialog", "gateway: no such dialog")
        return r

    def wait(self, token: Any, peer_pid: int, rid: Any, wait: float) -> dict[str, Any]:
        wait = min(WAIT_MAX, max(0.0, wait))
        end = time.monotonic() + wait
        with self.lock:
            le = self._lease(token, peer_pid)
            r = self._mine(le, rid)
            while True:
                if r.state == "done":
                    return {"ok": True, "state": "done", "outcome": r.outcome, "message": r.note}
                if r.state == "checking" and r.answer is not None:
                    ans, r.answer = dict(r.answer), None      # handed over once
                    return {"ok": True, "state": "answered", "answer": ans,
                            "attempt": r.attempt}
                left = end - time.monotonic()
                if left <= 0:
                    return {"ok": True, "state": r.state, "attempt": r.attempt}
                self.cond.wait(min(left, 1.0))

    def retry(self, token: Any, peer_pid: int, rid: Any, why: Any) -> dict[str, Any]:
        with self.lock:
            le = self._lease(token, peer_pid)
            r = self._mine(le, rid)
            if r.state == "done":
                return {"ok": True, "state": "done", "outcome": r.outcome}
            self._reopen(r, clean_text(why, 200))
            return {"ok": True, "state": r.state, "attempt": r.attempt}

    def _reopen(self, r: Request, why: str) -> None:
        r.drop()
        if r.attempt >= MAX_TRIES:
            self._close(r, "failed", f"didn't work after {MAX_TRIES} tries; nothing was saved")
            return
        r.attempt += 1
        r.error = f"That didn't work: {why}" if why else "That didn't work."
        r.state = "open"
        r.new_key()
        self._changed()

    def close(self, token: Any, peer_pid: int, rid: Any, outcome: Any, note: Any = "") -> dict[str, Any]:
        with self.lock:
            le = self._lease(token, peer_pid)
            r = self._mine(le, rid)
            if r.state != "done":
                oc = outcome if outcome in OUTCOMES else "failed"
                self._close(r, oc, clean_text(note, 200))
            return {"ok": True, "state": "done", "outcome": r.outcome}

    def release(self, token: Any, peer_pid: int) -> dict[str, Any]:
        with self.lock:
            le = self._lease(token, peer_pid)
            for r in list(self.requests.values()):
                if r.owner == "lease" and r.lease == le.hash and r.state != "done":
                    self._close(r, "cancelled", "the program that asked has finished")
            self.leases.pop(le.hash, None)
            self._save()
        return {"ok": True}

    def _close(self, r: Request, outcome: str, note: str = "") -> None:
        """Every exit path: done, key pair and answer dropped, waiters woken."""
        r.drop()
        r.state, r.outcome, r.note = "done", outcome, note
        self.requests.pop(r.id, None)
        self.recent.append({"id": r.id, "entry": r.entry, "what": r.what, "outcome": outcome,
                            "note": note, "session_pid": r.session_pid})
        del self.recent[:-RECENT_KEEP]
        self._done[r.id] = r
        while len(self._done) > 64:
            self._done.pop(next(iter(self._done)))
        self._changed()
        self.d.events.emit("auth.supplied", request=r.id, outcome=outcome)
        hooks = self.owned.pop(r.id, None)
        if hooks is not None and hooks[1] is not None:
            try:
                hooks[1](r.id, outcome)
            except Exception:  # noqa: BLE001 - a callback never breaks a close
                pass

    def _find(self, rid: Any) -> Request:
        """An open dialog, or a recently closed one (a waiter that comes back
        after the close still learns the outcome)."""
        if isinstance(rid, str) and rid in self._done and rid not in self.requests:
            return self._done[rid]
        return self._req(rid)

    # -- the UI plane (the mod, inside Claude Code) --------------------------------
    def _session_reqs(self, session: Any) -> list[Request]:
        rs = [r for r in self.requests.values()
              if r.session_pid == session.pid and r.state != "done"]
        return sorted(rs, key=lambda r: r.order)

    def view(self, session: Any) -> dict[str, Any]:
        now = _now()
        rs = self._session_reqs(session)
        return {"ok": True, "rev": self.rev, "dialog": rs[0].public(now) if rs else None,
                "queue": [r.ident() for r in rs[1:]],
                "recent": [{k: v for k, v in x.items() if k != "session_pid"}
                           for x in self.recent if x["session_pid"] == session.pid],
                "available": self.available(session)[0]}

    def next(self, session: Any, rev: int, wait: float) -> dict[str, Any]:
        wait = min(WAIT_MAX, max(0.0, wait))
        end = time.monotonic() + wait
        with self.lock:
            while self.rev == rev:
                left = end - time.monotonic()
                if left <= 0:
                    break
                self.cond.wait(min(left, 1.0))
            return self.view(session)

    def _ui_req(self, session: Any, rid: Any) -> Request:
        r = self._req(rid)
        if r.session_pid != session.pid:
            raise DialogError(404, "no_dialog", "gateway: no such dialog in this session")
        return r

    def _recheck(self, r: Request) -> tuple[str, str] | None:
        """Before a value is used: (outcome, why) when the request may not be
        answered any more, else None."""
        now = _now()
        if r.state != "open":
            return "failed", "the dialog wasn't waiting for an answer"
        if r.deadline <= now:
            return "timeout", "the dialog timed out"
        session = self.d.registry.live(r.session_pid)
        if session is None or (r.session_start is not None and session.start != r.session_start):
            return "cancelled", "the Claude Code session that asked has ended"
        if r.session_id and r.session_id in self.paused:
            return "paused", "the task is paused; the credential wasn't used"
        if r.owner == "lease":
            le = self.leases.get(r.lease)
            if le is None or le.expires <= now:
                return "cancelled", "the program that asked has stopped"
            if le.pids and not any(peers.alive(p, s) for p, s in le.pids.items()):
                return "cancelled", "the program that asked has stopped"
        why = self._entry_problem(r.check)
        if why:
            return "failed", why
        return None

    def _entry_problem(self, check: dict[str, Any] | None) -> str:
        """The entry the request is for must still be in the form, in the same
        section (and kind, for an account), with the rights it needs not
        switched off in the form or in the effective rights ("right": "sudo",
        "ssh", or a list such as ["ssh", "sudo"] for a remote sudo). "" when
        fine or nothing to check."""
        if not check:
            return ""
        section, name = check.get("section"), check.get("entry")
        if section not in ("hosts", "accounts") or not isinstance(name, str):
            return ""
        try:
            from .. import form as formmod
            f = formmod.load()
        except Exception:  # noqa: BLE001
            return "the gateway form can't be read now"
        if section == "hosts":
            h = f.hosts.get(name)
            if h is None:
                return f"{name} isn't a host in the gateway form any more"
            want = check.get("right")
            rights = [r for r in (want if isinstance(want, list) else [want])
                      if r in ("sudo", "ssh")]
            if not rights:
                return ""
            eff = self.d.effective()
            eh = eff.hosts.get(name) if eff is not None else None
            for right in rights:
                if getattr(h, right, None) is False:
                    return f"{name}'s {right} right is off now"
                if eh is not None and getattr(eh, right, None) is False:
                    return f"{name}'s {right} right is off now"
            return ""
        a = f.accounts.get(name)
        if a is None:
            return f"{name} isn't an account in the gateway form any more"
        kind = check.get("kind")
        if isinstance(kind, str) and kind and a.kind != kind:
            return f"{name} is a {a.kind} account now, not {kind}"
        return ""

    def _accept(self, r: Request, values: list[str], remember: Any) -> dict[str, Any]:
        """A secret value reached gated (sealed box or clipboard): recheck, then
        hand it to the owner. Called with the lock held."""
        problem = self._recheck(r)
        if problem is not None:
            oc, why = problem
            self._close(r, oc, why)
            return {"ok": False, "error": oc, "state": "done", "message": f"gateway: {why}"}
        if r.kind == "passphrase" and (len(values) != 2 or values[0] != values[1]):
            values.clear()
            self._reopen(r, "the two passphrases differ")
            return {"ok": True, "state": r.state, "attempt": r.attempt}
        # "Remember it" where the dialog offers it: the person's choice, or the
        # dialog's own default when the post carries none
        r.answer = {"values": list(values),
                    "remember": (remember if isinstance(remember, bool) else r.remember)
                    if r.remember is not None else None}
        values.clear()
        r.key = None
        r.state = "checking"
        r.error = ""
        self._changed()
        if r.owner in ("vault", "terminal"):
            self._run_vault(r)
        return {"ok": True, "state": "checking", "attempt": r.attempt}

    def submit(self, session: Any, body: dict[str, Any]) -> dict[str, Any]:
        """{id, attempt, epk, nonce, box, remember?}: the Client's sealed box.
        Plaintext values are never accepted here."""
        if "value" in body or "values" in body:
            raise DialogError(400, "plaintext", "gateway: the dialog takes sealed values only")
        epk = _unb64(body.get("epk"), 32)
        nonce = _unb64(body.get("nonce"), 24)
        box = _unb64(body.get("box"), limit=2 * MAX_VALUE_BYTES + 1024)
        if not 16 < len(box) <= 2 * MAX_VALUE_BYTES + 1024:
            raise DialogError(400, "bad_request", "gateway: a sealed value has the wrong size")
        public, exc = _nacl()
        with self.lock:
            r = self._ui_req(session, body.get("id"))
            if not r.secret():
                raise DialogError(400, "bad_request", "gateway: that dialog takes no secret")
            if r.state != "open" or r.key is None or body.get("attempt") != r.attempt:
                raise DialogError(409, "stale", "gateway: that dialog isn't waiting for this answer")
            try:
                plain = bytearray(public.Box(r.key, public.PublicKey(epk)).decrypt(box, nonce))
            except (exc.CryptoError, ValueError, TypeError):
                r.error = "That didn't arrive intact; type it again."
                self._changed()
                raise DialogError(400, "box", "gateway: the sealed value couldn't be opened") from None
            try:
                values = self._parse(r, plain)
            finally:
                for i in range(len(plain)):
                    plain[i] = 0
            if values is None:
                r.error = "That didn't arrive intact; type it again."
                self._changed()
                raise DialogError(400, "box", "gateway: the sealed value isn't for this dialog")
            return self._accept(r, values, body.get("remember"))

    def _parse(self, r: Request, plain: bytearray) -> list[str] | None:
        try:
            doc = json.loads(bytes(plain).decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return None
        if not isinstance(doc, dict) or doc.get("rid") != r.id or doc.get("a") != r.attempt:
            return None
        v = doc.get("v")
        if not isinstance(v, list) or len(v) != r.fields:
            return None
        out: list[str] = []
        for x in v:
            if not isinstance(x, str) or not x or len(x.encode("utf-8", "surrogatepass")) > MAX_VALUE_BYTES:
                return None
            if any(ord(c) < 32 or ord(c) == 127 for c in x):
                return None
            out.append(x)
        doc.clear()
        return out

    def paste(self, session: Any, body: dict[str, Any]) -> dict[str, Any]:
        """{id, env?}: gated reads the OS clipboard itself."""
        with self.lock:
            r = self._ui_req(session, body.get("id"))
            if not r.paste or r.fields != 1 or r.state != "open":
                raise DialogError(409, "stale", "gateway: that dialog can't take a paste now")
            attempt = r.attempt
        try:
            text = clipboard.read(body.get("env"), multiline=r.pem)
        except clipboard.ClipboardError as e:
            with self.lock:
                if r.state == "open":
                    r.error = clean_text(f"Paste didn't work: {e}", 200)
                    self._changed()
            return {"ok": False, "error": "clipboard", "message": f"gateway: {e}"}
        values = [text]
        text = ""
        with self.lock:
            if r.state != "open" or r.attempt != attempt or self.requests.get(r.id) is not r:
                values.clear()
                raise DialogError(409, "stale", "gateway: that dialog isn't waiting any more")
            return self._accept(r, values, body.get("remember"))

    def answer(self, session: Any, body: dict[str, Any]) -> dict[str, Any]:
        """{id, button: ok|cancel, choice?, picked?, text?} for the dialogs
        without a secret (consent, host key, a choice, a selection, text)."""
        with self.lock:
            r = self._ui_req(session, body.get("id"))
            if r.secret():
                raise DialogError(400, "bad_request", "gateway: a secret goes through its field")
            if r.state != "open":
                raise DialogError(409, "stale", "gateway: that dialog isn't waiting for an answer")
            if body.get("button") != "ok":
                self._close(r, "cancelled", "")
                return {"ok": True, "state": "done", "outcome": "cancelled"}
            ans: dict[str, Any] = {"button": "ok"}
            if r.kind == "choice":
                c = body.get("choice")
                if c not in r.options:
                    raise DialogError(400, "bad_request", "gateway: not one of the options")
                ans["choice"] = c
            elif r.kind == "checklist":
                picked = body.get("picked")
                if not isinstance(picked, list):
                    raise DialogError(400, "bad_request", "gateway: no selection")
                ans["picked"] = [x for x in r.options if x in picked]
            elif r.kind == "text" and r.input:
                t = body.get("text")
                ans["text"] = clean_text(t, 400) if isinstance(t, str) else ""
            problem = self._recheck(r)
            if problem is not None:
                self._close(r, *problem)
                return {"ok": False, "error": problem[0], "state": "done"}
            r.answer = ans
            r.state = "checking"
            self._changed()
            if r.owner == "gated":
                self._run_vault(r)          # gated's own confirmation: its handler acts on the OK
            return {"ok": True, "state": "checking"}

    def cancel(self, session: Any, body: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            r = self._ui_req(session, body.get("id"))
            if r.state != "done":
                self._close(r, "cancelled", "")
        return {"ok": True, "state": "done", "outcome": "cancelled"}

    # -- the vault's own dialogs ------------------------------------------------
    def open_vault(self, session: Any, kind: str, spec: dict[str, Any]) -> dict[str, Any]:
        """An unlock or set-a-passphrase dialog owned by gated (one per session)."""
        ok, why = self.available(session)
        if not ok:
            return {"ok": True, "available": False, "reason": why, "message": UNAVAILABLE[why]}
        with self.lock:
            for r in self._session_reqs(session):
                if r.owner == "vault" and r.kind == kind:
                    return {"ok": True, "available": True, "id": r.id, "existing": True}
            r = self._new({**spec, "kind": kind}, owner="vault", lease="", session=session)
            self._changed()
        self.d.events.emit("auth.waiting", request=r.id, session=r.session_id or None, dialog=kind)
        return {"ok": True, "available": True, "id": r.id}

    def open_owned(self, session: Any, spec: dict[str, Any],
                   handler: Callable[[Request, list[str]], tuple[bool, str]],
                   on_close: Callable[[str, str], None] | None = None,
                   terminal: str = "", kind: str = "secret") -> dict[str, Any]:
        """A dialog gated itself asks. kind "secret" (a password prompt in a
        gateway terminal): the answer goes to `handler` on a worker thread,
        which delivers it or says why not; a False answer closes the dialog
        as failed (the terminal moved on: there is nothing to retry). kind
        "confirm" or "info" (a remote host's changed identity, a refused key:
        daemon/remote.py): `handler(request, [])` runs on the person's OK only;
        a cancel, a timeout or the session ending just close it."""
        if kind not in ("secret", "confirm", "info"):
            raise DialogError(400, "bad_request", "gateway: unknown dialog kind")
        ok, why = self.available(session)
        if not ok:
            return {"ok": True, "available": False, "reason": why, "message": UNAVAILABLE[why]}
        owner = "terminal" if kind == "secret" else "gated"
        with self.lock:
            if sum(1 for r in self.requests.values() if r.state != "done") >= MAX_OPEN:
                return {"ok": True, "available": False, "reason": "busy", "message": UNAVAILABLE["busy"]}
            r = self._new({**spec, "kind": kind}, owner=owner, lease="", session=session)
            self.owned[r.id] = (handler, on_close)
            self._changed()
        self.d.events.emit("auth.waiting", request=r.id, session=r.session_id or None,
                           dialog=kind, terminal=terminal or None)
        return {"ok": True, "available": True, "id": r.id}

    def close_owned(self, rid: Any, outcome: str, note: str = "") -> None:
        with self.lock:
            r = self.requests.get(rid) if isinstance(rid, str) else None
            if r is not None and r.owner in OWNED and r.state != "done":
                self._close(r, outcome if outcome in OUTCOMES else "cancelled", note)

    def _run_vault(self, r: Request) -> None:
        owned = r.owner in OWNED
        handler = (self.owned.get(r.id) or (None, None))[0] if owned else self.handlers.get(r.kind)
        values = list((r.answer or {}).get("values") or [])
        r.answer = None
        r.busy = True

        def work() -> None:
            ok, why = False, "the gateway couldn't check it"
            try:
                if handler is not None:
                    ok, why = handler(r, values)
            except Exception as e:  # noqa: BLE001 - never a value in the reason
                ok, why = False, f"the check failed ({type(e).__name__})"
            finally:
                values.clear()
            with self.lock:
                r.busy = False
                if self.requests.get(r.id) is not r:
                    return
                if ok:
                    self._close(r, "ok", why)
                elif owned:
                    self._close(r, "failed", why)
                else:
                    self._reopen(r, why)
        threading.Thread(target=work, daemon=True).start()

    # -- pause (CONTRACT-v1 /v1/pause, /v1/resume) ---------------------------------
    def pause(self, session_id: str) -> int:
        """Record the pause; close that session's dialogs ("paused"). The number closed."""
        n = 0
        with self.lock:
            self.paused.add(session_id)
            for r in list(self.requests.values()):
                if r.session_id == session_id and r.state != "done":
                    self._close(r, "paused", "the task is paused; nothing was used")
                    n += 1
            self._save()
        return n

    def resume(self, session_id: str) -> bool:
        with self.lock:
            was = session_id in self.paused
            self.paused.discard(session_id)
            self._save()
        return was

    @staticmethod
    def _replay_key(kind: str, session_id: str, pause_id: str) -> str:
        return f"{kind}\x1f{session_id}\x1f{pause_id}"

    def replay(self, kind: str, session_id: str, pause_id: str) -> dict[str, Any] | None:
        """The first answer to a pause or resume with this pause_id, or None."""
        now = _now()
        with self.lock:
            for k in [k for k, (t, _b) in self.replays.items() if now - t >= REPLAY_TTL]:
                del self.replays[k]
            hit = self.replays.get(self._replay_key(kind, session_id, pause_id))
        return dict(hit[1]) if hit else None

    def remember_replay(self, kind: str, session_id: str, pause_id: str,
                        answer: dict[str, Any]) -> None:
        with self.lock:
            if len(self.replays) >= REPLAY_MAX:
                for k, _v in sorted(self.replays.items(), key=lambda kv: kv[1][0])[:len(self.replays) - REPLAY_MAX + 1]:
                    del self.replays[k]
            self.replays[self._replay_key(kind, session_id, pause_id)] = (_now(), dict(answer))
            self._save()

    # -- housekeeping -------------------------------------------------------------
    def tick(self) -> None:
        now = _now()
        with self.lock:
            for r in list(self.requests.values()):
                if r.state == "done":
                    continue
                if r.deadline <= now:
                    self._close(r, "timeout", "nobody answered in time")
                    continue
                if self.d.registry.live(r.session_pid) is None:
                    self._close(r, "cancelled", "the Claude Code session that asked has ended")
                    continue
                if r.owner == "lease":
                    le = self.leases.get(r.lease)
                    if le is None or le.expires <= now:
                        self._close(r, "cancelled", "the program that asked has stopped")
                    elif le.pids and not any(peers.alive(p, s) for p, s in le.pids.items()) \
                            and not r.busy:
                        self._close(r, "cancelled", "the program that asked has stopped")
            gone = [h for h, le in self.leases.items() if le.expires <= now]
            for h in gone:
                self.leases.pop(h, None)
            if gone:
                self._save()

    def count(self) -> int:
        with self.lock:
            return sum(1 for r in self.requests.values() if r.state != "done")
