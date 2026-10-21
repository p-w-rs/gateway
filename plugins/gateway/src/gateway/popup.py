"""Asking the user: the only way the gateway does (SPEC 6, PLAN-v4 phase 3).

Every question is a native dialog inside Claude Code: a pane the gate mod
draws, with a private Client field for secrets (dialog.py, daemon/dialogs.py,
hooks/mod/). No OS dialog, browser, web page or terminal prompt is ever used
(the `gate secret` terminal path, its one-time codes and the browser and
device-code sign-ins are gone; DECISIONS "PLAN-v4 phase 3").

Kinds: consent(entry, changes), secret(entry, what, prompt, verify),
choice(entry, question, options), hostkey(entry, old, new), text, checklist,
confirm, info, plus run(entry, what, job) for a multi-step job (gate check,
export) whose dialogs all belong to one request.

Broker (one dialog per (entry, what) across all processes)
---------------------------------------------------------
private/pending/ holds, per request key `<entry>--<what-slug>`:

    <key>.lock    flock taken to decide "create or join"
    <key>.json    the open request (read by hooks_session, gate status):
                  {"entry", "what", "kind", "state": "open", "since", "id",
                   "pid", "session", "detail", "digest"}
    <key>.result  the last outcome of that key: {"id", "outcome", "at"} (never a value)
    <key>.<digest>.line  a public job's message for Claude (export, import,
                  copy-to: `public=True`): {"id", "outcome", "line", "at"},
                  one per request (digest), removed when a requester takes it

1. The first requester takes a dialog lease from the gateway daemon (it runs
   below the Claude Code session, so the daemon knows which session's
   Claude Code draws the dialog). No lease (claude -p, the Agent SDK, mods
   off, mobile, VS Code, Remote Control) means "unavailable": nothing is
   asked any other way, and the reason is printed.
2. It double-forks a detached helper (own session, stdio on /dev/null,
   every other fd closed) that inherits the lease, opens the dialog(s), runs
   the verification (up to 3 tries in the same dialog: it reopens with
   "That didn't work: ..."), stores the answer through the caller's callbacks
   (only once it checked out, and only when the person chose "remember"
   where the dialog offered the choice), writes `<key>.result`, removes
   `<key>.json` and releases the lease. The helper lives at most LIFETIME
   (30 min); its dialogs time out then.
3. The requester waits at most WAIT (90 s) for the helper (the value comes
   back over a private pipe). Then it prints `gateway: the gateway dialog
   for X is still open in Claude Code; tell the user once and carry on with
   other work. Retry after they answer.` and raises StillOpen (a SystemExit
   with code 75, EX_TEMPFAIL). The helper keeps going and stores the answer
   when given.
4. A second requester for the same key joins: it waits on `<key>.result`
   (same id) and, on ok, re-reads the stored value through its `load`
   callback.
5. A job whose answer is a message for Claude (`public=True`: export, import,
   copy-to; its value is the line it prints, never a secret) keeps that line
   in `<key>.<digest>.line` until a requester takes it. When the requester's wait ran
   out before the person answered, the retry Claude was told to make ("Retry
   after they answer") gets the finished job's outcome and line instead of a
   new dialog (same key and digest, within LIFETIME; ok, failed and cancelled
   only), once.

A requester whose request differs from the open one (another digest: other
changes, another user) doesn't join it: it waits for that dialog to end and
then opens its own. The daemon shows one dialog at a time per session; the
others queue behind it with their identity (entry, what) shown.

Outcomes: ok, cancelled (the user pressed Cancel; lazy requests for the same
change are not asked again until the user writes a new prompt: the markers
`private/pending/<key>.cancelled` are global, not tied to the caller's
session id, and the UserPromptSubmit hook deletes them), timeout (nobody
answered), unavailable (no native dialog here), paused (checkpoint paused
the task) and failed (verification failed three times, the request changed
before the answer could be used, or the helper died; nothing was stored).

Templates are fixed. Entry names, addresses and fingerprints are validated
before rendering; Claude-written free text (notes) is never shown. Default
button: Cancel for consent and hostkey.

Modes: "broker" (the default, above) and "direct" (inside the helper: the
dialogs are asked in place).
"""
from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
import re
import secrets as _secrets
import select
import signal
import sys
import time
import urllib.request   # imported before any fork: on macOS its _scproxy import aborts in a forked child
import warnings
from pathlib import Path
from typing import Any, Callable, Iterator, Sequence

from . import dialog, paths, testing
from . import form as formmod


class Outcome:
    OK = "ok"
    CANCELLED = "cancelled"      # user pressed Cancel
    TIMEOUT = "timeout"          # nobody answered
    UNAVAILABLE = "unavailable"  # no native dialog can open here
    FAILED = "failed"            # verification failed 3 times, the request changed, or the helper died
    PAUSED = "paused"            # the task is paused (checkpoint)
    ALL = (OK, CANCELLED, TIMEOUT, UNAVAILABLE, FAILED, PAUSED)


EX_TEMPFAIL = 75
WAIT = 90                 # seconds a requester waits
LIFETIME = 1800           # seconds the detached helper keeps the dialog open
MAX_TRIES = 3
RESULT_KEEP = 600         # seconds a .result file is kept for joiners
UNTAKEN_KEEP = 1800       # seconds a public job's line nobody took is kept for the retry
REPLAYED = ("ok", "failed", "cancelled")   # the outcomes a retry is given instead of a new dialog
LINE_MAX = 4000
TITLE = "Gateway"
NEVER_SEES = "Claude never sees what you type here."
WHERE = ("in Claude Code, in a terminal or the desktop app (not claude -p, VS Code, mobile or "
         "Remote Control)")

_SAFE_TARGET = re.compile(r"[A-Za-z0-9_.@:\[\]/-]{1,120}")
_SAFE_FP = re.compile(r"(?:[a-z0-9-]{3,40} )?SHA256:[A-Za-z0-9+/=]{20,64}")
_WHAT = re.compile(r"[a-z][a-z0-9 ._-]{0,47}")


class StopDialog(Exception):
    """Raised by a secret dialog's verify callback when asking again can't
    help (the file is damaged, not the passphrase wrong): the dialog closes as
    failed, its toast naming `reason` (fixed text, never the value)."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class StillOpen(SystemExit):
    """The requester's wait ran out; the dialog stays open in the helper.
    A SystemExit with code 75, so an uncaught one ends the process right."""

    def __init__(self, entry: str, message: str):
        super().__init__(EX_TEMPFAIL)
        self.entry = entry
        self.message = message


# ---------------------------------------------------------------------------
# Modes
# ---------------------------------------------------------------------------

_MODE = "broker"
_SHOWN_FD: int | None = None     # inside the helper: the pipe to the requester
_LAST_REASON = ""                # why the last request was unavailable (fixed text)


def _shown() -> None:
    """A dialog is about to open: tell the requester once, so it prints its
    "waiting for ... in the gateway dialog" notice only for a job that really
    shows one (round 3)."""
    global _SHOWN_FD
    fd, _SHOWN_FD = _SHOWN_FD, None
    if fd is not None:
        with contextlib.suppress(OSError):
            os.write(fd, b"SHOWN\n")


def mode() -> str:
    return _MODE


def wait_seconds() -> float:
    return float(testing.get("popup_wait", WAIT))


# A cap on how long this process waits for any dialog (time.time()), set by
# a command with an overall time budget: gate check must print its exit-75
# "tell the user once" line before Claude Code's 2-minute Bash timeout kills
# it (review round 4: WAIT counts from each call's own start).
_DEADLINE: float | None = None


def set_deadline(t: float | None) -> None:
    global _DEADLINE
    _DEADLINE = t


def _wait_deadline() -> float:
    d = _now() + wait_seconds()
    return d if _DEADLINE is None else min(d, _DEADLINE)


def lifetime() -> float:
    return float(testing.get("popup_lifetime", LIFETIME))


# ---------------------------------------------------------------------------
# Validation and templates
# ---------------------------------------------------------------------------


def _name(entry: str) -> str:
    if not isinstance(entry, str) or not (formmod.NAME_RE.fullmatch(entry) or entry == "settings"):
        raise ValueError("dialogs are only for validated entry names")
    return entry


def _what(what: str) -> str:
    if not isinstance(what, str) or not _WHAT.fullmatch(what):
        raise ValueError("dialog subjects come from fixed templates")
    return what


def safe_target(s: str | None) -> str | None:
    """user@host:port or a host name, if it may be shown."""
    return s if isinstance(s, str) and _SAFE_TARGET.fullmatch(s) else None


def safe_fingerprint(s: str | None) -> str | None:
    return s if isinstance(s, str) and _SAFE_FP.fullmatch(s) else None


def clean_line(s: Any, limit: int = 200) -> str:
    """One line of generated text (a consent Change), unsafe characters removed."""
    text = s.render() if hasattr(s, "render") else str(s)
    text = formmod.strip_unsafe(text.replace("\n", " ").replace("\r", " "))
    return text[:limit]


def secret_prompt(what: str, entry: str, *, target: str | None = None,
                  fingerprint: str | None = None, note: str | None = None) -> str:
    """The fixed text of a secret dialog: what the secret is, for which
    user@address:port, the host-key fingerprint, and that Claude never sees it."""
    _name(entry)
    _what(what)
    t = safe_target(target)
    lines = [f"The gateway needs the {what} for {entry}" + (f" ({t})" if t else "") + "."]
    fp = safe_fingerprint(fingerprint)
    if fp:
        lines.append(f"Host key: {fp}")
    if note:
        lines.append(clean_line(note, 300))
    lines.append("It is stored encrypted on this computer and used only for " + entry + ".")
    lines.append(NEVER_SEES)
    return "\n".join(lines)


def consent_text(entry: str, changes: Sequence[Any], extra_lines: Sequence[str] = ()) -> str:
    _name(entry)
    who = "the gateway settings" if entry == "settings" else entry
    out = [f"Claude asks for more rights for {who}:", ""]
    for c in changes:
        line = c.what if hasattr(c, "what") else str(c)
        out.append("  - " + clean_line(line))
    extras = [clean_line(x, 300) for x in extra_lines if x]
    if extras:
        out.append("")
        out += extras
    out += ["", "Approve? Decline keeps what you approved before (nothing changes)."]
    return "\n".join(out)


_FP_NOTES = ("(your ~/.ssh/known_hosts has it)", "(not in your ~/.ssh/known_hosts)")


def _fp_shown(s: Any) -> str | None:
    """A fingerprint, optionally followed by one of the fixed known_hosts notes."""
    if not isinstance(s, str):
        return None
    m = _SAFE_FP.match(s)
    if not m:
        return None
    rest = s[m.end():].strip()
    if not rest:
        return m.group(0)
    return f"{m.group(0)} {rest}" if rest in _FP_NOTES else m.group(0)


def hostkey_text(entry: str, old: Sequence[str], new: Sequence[str], *,
                 address: str | None = None, known: bool | None = None) -> str:
    _name(entry)
    a = safe_target(address)
    out = [f"The host key of {entry}" + (f" ({a})" if a else "") + " is not the one the gateway pinned."]
    out.append("Pinned: " + (", ".join(f for f in (_fp_shown(x) for x in old) if f) or "none"))
    out.append("Now:    " + (", ".join(f for f in (_fp_shown(x) for x in new) if f) or "none"))
    if known is True:
        out.append("Your own ~/.ssh/known_hosts already knows the new key.")
    elif known is False:
        out.append("Your own ~/.ssh/known_hosts doesn't know the new key.")
    out += ["", "Trust the new key only if you expect it (for example the machine was reinstalled)."]
    return "\n".join(out)


def phrase(entry: str, what: str) -> str:
    if what == "consent":
        return f"your OK for {entry}"
    return f"the {entry} {what}"


def unavailable_text(entry: str, what: str, reason: str = "") -> str:
    """Why nothing was asked, and what the user can do instead."""
    why = (reason or _LAST_REASON or "no gateway dialog can open here").removeprefix("gateway: ")
    p = f"the user's OK for {entry}" if what == "consent" else phrase(entry, what)
    how = ("by running the same gate command there" if entry == "gateway"
           else f"for example with gate check {entry} there")
    return (f"gateway: {why}, so nothing was asked ({p}). Tell the user once: it can be given "
            f"in the gateway's dialog {WHERE}, {how}.")


def message(outcome: str, entry: str, what: str, reason: str = "") -> str:
    """The standard line for Claude for an outcome other than ok."""
    p = f"the user's OK for {entry}" if what == "consent" else phrase(entry, what)
    if outcome == Outcome.CANCELLED:
        which = f"the consent dialog for {entry}" if what == "consent" else f"the dialog for {p}"
        return f"gateway: the user cancelled {which}; don't ask again unless they say so"
    if outcome == Outcome.TIMEOUT:
        return f"gateway: nobody answered the dialog for {p}; ask the user when they're back"
    if outcome == Outcome.UNAVAILABLE:
        return unavailable_text(entry, what, reason)
    if outcome == Outcome.PAUSED:
        return (f"gateway: the task is paused (checkpoint), so {p} wasn't asked for or used; "
                "it can be given after the user resumes the task")
    if outcome == Outcome.FAILED:
        if reason:
            return f"gateway: {p} wasn't used: {reason.removeprefix('gateway: ')}; nothing was saved"
        return f"gateway: {p} didn't work after {MAX_TRIES} tries; nothing was saved"
    return f"gateway: {p}: {outcome}"


def still_open_message(entry: str) -> str:
    return (f"gateway: the gateway dialog for {entry} is still open in Claude Code; tell the "
            "user once and carry on with other work. Retry after they answer.")


def stale_message(entry: str, what: str, outcome: str = "open") -> str:
    head = f"gateway: the saved {what} for {entry} was rejected"
    if outcome == Outcome.UNAVAILABLE:
        return (f"{head}; {unavailable_text(entry, what).removeprefix('gateway: ')} "
                "Don't retry.")
    if outcome == Outcome.CANCELLED:
        return (f"{head}, and the user cancelled the dialog to enter it again; don't retry "
                "unless they ask")
    return f"{head}; a gateway dialog to enter it again is open in Claude Code; don't retry"


def _say(text: str) -> None:
    try:
        print(text, file=sys.stderr, flush=True)
    except (OSError, ValueError):
        pass


# ---------------------------------------------------------------------------
# Raw dialogs
# ---------------------------------------------------------------------------


def _timeout() -> int:
    if _DEADLINE is not None:
        return max(5, int(_DEADLINE - time.time()))
    return int(testing.get("dialog_timeout", lifetime()))


def _ask(spec: dialog.Spec) -> dialog.Result:
    """Ask once and close (the dialogs without a check)."""
    _shown()
    spec.timeout = spec.timeout if spec.timeout is not None else _timeout()
    d = dialog.Dialog(spec)
    r = d.ask()
    d.close(r.outcome if r.outcome in (Outcome.OK, Outcome.CANCELLED, Outcome.TIMEOUT)
            else Outcome.FAILED)
    _remember_reason(r)
    return r


def _remember_reason(r: dialog.Result) -> None:
    global _LAST_REASON
    if r.outcome in (Outcome.UNAVAILABLE, Outcome.FAILED) and r.reason:
        _LAST_REASON = r.reason


def _confirm(title: str, text: str, ok_label: str, default_cancel: bool = True, *,
             entry: str = "", what: str = "", cancel_label: str = "Cancel") -> str:
    return _ask(dialog.Spec("confirm", text, title=title, ok_label=ok_label,
                            cancel_label=cancel_label, default_cancel=default_cancel,
                            entry=entry, what=what)).outcome


def _text_raw(title: str, text: str, default: str = "", ok_label: str = "OK", *,
              entry: str = "", what: str = "") -> tuple[str, str | None]:
    r = _ask(dialog.Spec("text", text, title=title, default=default, ok_label=ok_label,
                         entry=entry, what=what, input=not default))
    return r.outcome, (r.value if r.ok else None)


def _choice_raw(title: str, text: str, options: Sequence[str], default: str = "", *,
                entry: str = "", what: str = "") -> tuple[str, str | None]:
    r = _ask(dialog.Spec("choice", text, title=title, options=options,
                         default=default or options[0], ok_label="Continue",
                         entry=entry, what=what))
    if not r.ok:
        return r.outcome, None
    v = (r.value or "").strip()
    return (Outcome.OK, v) if v in options else (Outcome.CANCELLED, None)


def _checklist_raw(title: str, text: str, options: Sequence[str],
                   checked: Sequence[str], *, entry: str = "", what: str = ""
                   ) -> tuple[str, list[str] | None]:
    r = _ask(dialog.Spec("checklist", text, title=title, options=options, checked=checked,
                         ok_label="Continue", entry=entry, what=what))
    if not r.ok:
        return r.outcome, None
    return Outcome.OK, [x for x in (r.value or "").split("\n") if x in options]


def _info_raw(title: str, text: str, *, entry: str = "") -> str:
    return _ask(dialog.Spec("info", text, title=title, ok_label="OK", entry=entry,
                            what="notice")).outcome


# ---------------------------------------------------------------------------
# Pending files, cancel markers
# ---------------------------------------------------------------------------


def _key(entry: str, what: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", what.lower()).strip("-")[:40] or "x"
    return f"{entry}--{slug}"


def _pdir() -> Path:
    paths.ensure_private()
    d = paths.pending_dir()
    d.mkdir(mode=0o700, exist_ok=True)
    return d


def _state_path(key: str) -> Path:
    return _pdir() / f"{key}.json"


def _result_path(key: str) -> Path:
    return _pdir() / f"{key}.result"


def _read_json(p: Path) -> dict[str, Any] | None:
    try:
        d = json.loads(p.read_text())
        return d if isinstance(d, dict) else None
    except (OSError, ValueError):
        return None


def _write_json(p: Path, d: dict[str, Any]) -> None:
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(d))
    os.replace(tmp, p)


@contextlib.contextmanager
def _flock(key: str) -> Iterator[int]:
    fd = os.open(_pdir() / f"{key}.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield fd
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _now() -> float:
    return time.time()


def _iso(t: float | None = None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(t if t is not None else _now()))


def _pid_alive(pid: Any) -> bool:
    if not isinstance(pid, int) or pid <= 1:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _alive(st: dict[str, Any]) -> bool:
    """An open request whose helper still runs (and isn't older than its lifetime)."""
    if st.get("state") != "open":
        return False
    started = float(st.get("t", 0) or 0)
    if started and _now() - started > lifetime() + 60:
        return False
    return _pid_alive(st.get("pid"))


def _session() -> str:
    sid = os.environ.get("CLAUDE_CODE_SESSION_ID") or ""
    return re.sub(r"[^A-Za-z0-9_-]", "_", sid)[:80]


def sid_slug(session_id: str | None) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", session_id or "nosession")[:80]


def state_dir() -> Path:
    """private/sessions: per-session state the hooks keep (shown notices, the
    session record prompt.sh writes at the first prompt). In private/, so
    Claude's commands can't fake or delete it."""
    paths.ensure_private()
    d = paths.private_dir() / "sessions"
    d.mkdir(mode=0o700, exist_ok=True)
    return d


def cancel_path(key: str) -> Path:
    """The cancel marker of one request key (global: not tied to the caller's
    session id, which Claude's commands could change)."""
    return _pdir() / f"{key}.cancelled"


def _digest(parts: Sequence[str]) -> str:
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()[:16]


def was_cancelled(key: str, digest: str) -> bool:
    try:
        d = _read_json(cancel_path(key)) or {}
    except (OSError, paths.PathError):
        return False
    return digest in (d.get("digests") or [])


def mark_cancelled(key: str, digest: str) -> None:
    try:
        p = cancel_path(key)
        d = _read_json(p) or {}
        lst = [x for x in (d.get("digests") or []) if isinstance(x, str)]
        if digest not in lst:
            lst.append(digest)
        _write_json(p, {"digests": lst[-20:], "at": _iso()})
    except (OSError, paths.PathError):
        pass


def clear_cancelled() -> int:
    """The user wrote a new prompt: cancelled dialogs may be asked again
    (prompt.sh does the same in sh on every prompt)."""
    n = 0
    try:
        files = list(paths.pending_dir().glob("*.cancelled"))
    except OSError:
        return 0
    for p in files:
        with contextlib.suppress(OSError):
            p.unlink()
            n += 1
    return n


def pending(entry: str | None = None) -> list[dict[str, Any]]:
    """Open requests, validated names only."""
    out = []
    try:
        files = sorted(paths.pending_dir().glob("*.json"))
    except OSError:
        return out
    for p in files:
        d = _read_json(p)
        if not d or not formmod.safe(d.get("entry")):
            continue
        if entry is not None and d.get("entry") != entry:
            continue
        d["_key"] = p.stem
        out.append(d)
    return out


def clear(entry: str, what: str | None = None) -> int:
    """Remove dead pending requests of an entry."""
    n = 0
    for d in pending(entry):
        if what is not None and d.get("what") != what:
            continue
        if d.get("state") == "open" and _alive(d):
            continue
        with contextlib.suppress(OSError):
            (paths.pending_dir() / f"{d['_key']}.json").unlink()
            n += 1
    return n


def cleanup_stale() -> int:
    """Remove dead open requests, old results, records of the removed
    terminal path (.code files, unavailable requests) and orphaned lock
    files. Returns how many files went."""
    n = 0
    try:
        d = paths.pending_dir()
        files = list(d.iterdir())
    except OSError:
        return 0
    now = _now()
    for p in files:
        try:
            age = now - p.stat().st_mtime
        except OSError:
            continue
        drop = False
        if p.suffix == ".json":
            st = _read_json(p)
            if st is None:
                drop = age > 60
            elif st.get("state") == "open":
                drop = not _alive(st) and age > 5
            else:
                drop = True
        elif p.suffix == ".result":
            drop = age > RESULT_KEEP
        elif p.suffix == ".line":
            drop = age > UNTAKEN_KEEP
        elif p.suffix == ".code":
            drop = True                   # the old terminal path's one-time codes
        elif p.suffix == ".cancelled":
            drop = age > 86400
        elif p.suffix == ".lock":
            drop = age > 86400 and not (d / f"{p.stem}.json").exists()
        elif p.name.endswith(".tmp"):
            drop = age > 60
        if drop:
            with contextlib.suppress(OSError):
                p.unlink()
                n += 1
    return n


def _audit(event: str, **kw: Any) -> None:
    try:
        from . import audit
        audit.log(event, **kw)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# The broker
# ---------------------------------------------------------------------------

Job = Callable[[], tuple[str, Any]]


def _close_fds_except(keep: set[int]) -> None:
    try:
        maxfd = min(os.sysconf("SC_OPEN_MAX"), 4096)
    except (ValueError, OSError):
        maxfd = 1024
    for fd in range(3, maxfd):
        if fd not in keep:
            try:
                os.close(fd)
            except OSError:
                pass


def _helper_main(w: int, key: str, rid: str, job: Job, entry: str, what: str, kind: str,
                 detail: dict | None, digest: str, session: str, public: bool = False) -> None:
    """Runs in the detached grandchild. Never returns (os._exit)."""
    global _MODE, _DEADLINE, _SHOWN_FD
    _MODE = "direct"
    _DEADLINE = _now() + lifetime()
    _SHOWN_FD = w
    for s in (signal.SIGHUP, signal.SIGINT, signal.SIGPIPE, signal.SIGTERM):
        with contextlib.suppress(OSError, ValueError):
            signal.signal(s, signal.SIG_IGN if s != signal.SIGTERM else signal.SIG_DFL)
    nul = os.open(os.devnull, os.O_RDWR)
    for fd in (0, 1, 2):
        os.dup2(nul, fd)
    if nul > 2:
        os.close(nul)
    _close_fds_except({w})
    try:
        sys.stdout = sys.stderr = open(os.devnull, "w")
    except OSError:
        pass
    try:
        # No proxies in the helper: macOS's system proxy lookup (_scproxy,
        # CoreFoundation) isn't safe after fork(), and the environment's
        # HTTPS_PROXY/ALL_PROXY come from Claude's Bash (a token being verified
        # must not be routed through a proxy Claude picked). Token checks use
        # entra.urlopen anyway (no proxies, the build's CA bundle).
        urllib.request.getproxies = _no_proxies  # type: ignore[assignment]
    except Exception:  # noqa: BLE001
        pass
    try:
        os.write(w, f"PID {os.getpid()}\n".encode())
    except OSError:
        pass
    outcome, value = Outcome.FAILED, None
    try:
        outcome, value = job()
        if outcome not in Outcome.ALL:
            outcome = Outcome.FAILED
    except BaseException as e:  # noqa: BLE001 - the helper must always report
        outcome, value = Outcome.FAILED, None
        _audit("popup_error", entry=entry, what=what, error=type(e).__name__)
    finally:
        dialog.release_lease()
    payload = base64.b64encode(value.encode()).decode() if isinstance(value, str) else "-"
    result: dict[str, Any] = {"id": rid, "outcome": outcome, "at": _iso()}
    line: dict[str, Any] | None = None
    if public:
        # the job's message for Claude (never a secret: public jobs return the
        # line they print), kept for a retry whose requester stopped waiting
        line = {**result, "line": clean_line(value, LINE_MAX) if isinstance(value, str) else ""}
    value = None
    try:
        # Under the request's lock: the requester may still be writing the state.
        with _flock(key):
            if line is not None:
                _write_json(_line_path(key, digest), line)
            _write_json(_result_path(key), result)
            st = _read_json(_state_path(key))
            if st and st.get("id") == rid:
                _state_path(key).unlink()
        if outcome == Outcome.CANCELLED:
            mark_cancelled(key, digest)
    except Exception:  # noqa: BLE001
        pass
    try:
        os.write(w, f"DONE {outcome} {payload}\n".encode())
    except OSError:
        pass   # the requester stopped waiting; the answer was stored by the job
    payload = None
    _audit("popup", entry=entry, what=what, outcome=outcome)
    os._exit(0)


def _no_proxies() -> dict[str, str]:
    return {}


def _spawn(key: str, rid: str, job: Job, lock_fd: int, entry: str, what: str, kind: str,
           detail: dict | None, digest: str, public: bool = False) -> tuple[int | None, int]:
    """Double-fork the helper. Returns (helper pid, read end of its pipe)."""
    r, w = os.pipe()
    session = _session()
    sys.stdout.flush()
    sys.stderr.flush()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        pid = os.fork()
    if pid == 0:
        try:
            os.close(r)
            os.close(lock_fd)        # the requester unlocks; the helper never holds the lock
            os.setsid()
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                if os.fork() > 0:
                    os._exit(0)
            _helper_main(w, key, rid, job, entry, what, kind, detail, digest, session, public)
        except BaseException:  # noqa: BLE001
            pass
        os._exit(0)
    os.close(w)
    with contextlib.suppress(ChildProcessError):
        os.waitpid(pid, 0)
    helper = None
    buf = b""
    end = _now() + 10
    while _now() < end and b"\n" not in buf:
        rr, _, _ = select.select([r], [], [], 0.5)
        if rr:
            chunk = os.read(r, 256)
            if not chunk:
                break
            buf += chunk
    line, _, rest = buf.partition(b"\n")
    if line.startswith(b"PID "):
        with contextlib.suppress(ValueError):
            helper = int(line[4:])
    _PIPE_REST[r] = rest
    return helper, r


_PIPE_REST: dict[int, bytes] = {}


def _wait_pipe(r: int, deadline: float, on_shown: Callable[[], Any] | None = None
               ) -> tuple[str, str | None] | None:
    buf = _PIPE_REST.pop(r, b"")
    try:
        while True:
            if b"\n" in buf:
                line, _, buf = buf.partition(b"\n")
                if line == b"SHOWN":
                    if on_shown is not None:
                        on_shown()
                        on_shown = None
                    continue
                parts = line.decode(errors="replace").split(" ")
                if len(parts) == 3 and parts[0] == "DONE":
                    val = None if parts[2] == "-" else base64.b64decode(parts[2]).decode()
                    return parts[1], val
                continue
            left = deadline - _now()
            if left <= 0:
                return None
            rr, _, _ = select.select([r], [], [], min(left, 0.5))
            if rr:
                chunk = os.read(r, 65536)
                if not chunk:          # the helper died without an answer
                    return Outcome.FAILED, None
                buf += chunk
    finally:
        with contextlib.suppress(OSError):
            os.close(r)


def _line_path(key: str, digest: str) -> Path:
    """A public job's line for request `digest` (hex) of `key`."""
    return _pdir() / f"{key}.{digest if re.fullmatch(r'[0-9a-f]{1,64}', digest or '') else 'x'}.line"


def _take_locked(key: str, digest: str, rid: str | None = None) -> dict[str, Any] | None:
    """A public job's line for this request (key and digest; of request
    `rid` when given), taken (removed; the caller holds the key's lock): it
    goes to one requester, and the retry after that gets a new dialog. None
    when there is none, it is older than UNTAKEN_KEEP, or another request's."""
    p = _line_path(key, digest)
    rec = _read_json(p)
    if not rec or (rid is not None and rec.get("id") != rid):
        return None
    try:
        fresh = _now() - p.stat().st_mtime <= UNTAKEN_KEEP
    except OSError:
        return None
    with contextlib.suppress(OSError):
        p.unlink()
    return rec if fresh else None


def _take(key: str, digest: str, rid: str | None = None) -> dict[str, Any] | None:
    with _flock(key):
        return _take_locked(key, digest, rid)


def _replayable(rec: dict[str, Any] | None) -> bool:
    """A taken line a retry is given instead of a new dialog."""
    return bool(rec) and rec.get("outcome") in REPLAYED and isinstance(rec.get("line"), str)


def _wait_poll(key: str, rid: str, deadline: float, digest: str | None = None
               ) -> tuple[str, str | None] | None:
    """Wait for request `rid`'s result; a joiner of a public job (`digest`:
    its own request's) takes its line. A requester only waiting for another
    request's dialog to end passes none: that line belongs to its own retry."""
    gone_since = None
    while _now() < deadline:
        res = _read_json(_result_path(key))
        if res and res.get("id") == rid:
            rec = _take(key, digest, rid) if digest is not None else None
            line = rec.get("line") if rec else None
            return str(res.get("outcome")), (line if isinstance(line, str) and line else None)
        st = _read_json(_state_path(key))
        if st is None or st.get("id") != rid:
            gone_since = gone_since or _now()
            if _now() - gone_since > 2:
                return Outcome.FAILED, None
        elif not _alive(st):
            return Outcome.FAILED, None
        time.sleep(0.2)
    return None


def run(entry: str, what: str, job: Job, *, kind: str = "setup", lazy: bool = False,
        digest: str = "", detail: dict | None = None, notice: str | None = None,
        load: Callable[[], Any] | None = None, wait: bool = True,
        public: bool = False) -> tuple[str, Any]:
    """Broker one request (see the module docstring). `job` runs where the
    dialog runs (the detached helper, or in place in direct mode) and returns
    (outcome, value); it stores what must be stored. With lazy=True a request
    the user cancelled in this session isn't shown again. wait=False starts
    the dialog and returns ("open", None) at once (stale re-entry).
    public=True: the job's value is its message for Claude (never a secret);
    it is kept for a retry whose requester stopped waiting (step 5)."""
    global _LAST_REASON
    _name(entry)
    _what(what)
    if _MODE != "broker":
        return job()
    key = _key(entry, what)
    if lazy and was_cancelled(key, digest):
        _say(message(Outcome.CANCELLED, entry, what))
        return Outcome.CANCELLED, None
    cleanup_stale()
    be, why = dialog.backend()
    role, rid, rfd = "", "", -1
    deadline = _wait_deadline()
    replay: dict[str, Any] | None = None
    for _round in range(6):
        with _flock(key) as lock_fd:
            st = _read_json(_state_path(key))
            # the same request's job finished after its requester stopped waiting
            taken = _take_locked(key, digest) if public and not (st and _alive(st)) else None
            if _replayable(taken):
                role, replay = "replay", taken
            elif st and _alive(st):
                other = st.get("digest")
                if digest and other and other != digest:
                    role, rid = "other", str(st.get("id"))    # a different request: wait, then ours
                else:
                    role, rid = "join", str(st.get("id"))
            else:
                lease = None
                if be == "native":
                    lease, why = dialog.take_lease()
                if be is None or (be == "native" and lease is None):
                    _LAST_REASON = why
                    role = "unavailable"
                else:
                    role, rid = "create", _secrets.token_hex(8)
                    started = _now()
                    state = {"entry": entry, "what": what, "kind": kind, "state": "open",
                             "since": _iso(started), "t": started, "id": rid, "pid": os.getpid(),
                             "session": _session() or None, "detail": detail or {},
                             "digest": digest}
                    _write_json(_state_path(key), state)
                    dialog.set_lease(lease)                  # inherited by the helper
                    try:
                        helper, rfd = _spawn(key, rid, job, lock_fd, entry, what, kind, detail,
                                             digest, public)
                    finally:
                        dialog.set_lease(None)
                    if helper is None:
                        with contextlib.suppress(OSError):
                            os.close(rfd)
                        with contextlib.suppress(OSError):
                            _state_path(key).unlink()
                        return Outcome.FAILED, None
                    state["pid"] = helper
                    _write_json(_state_path(key), state)   # the helper finalizes only under this lock
        if role != "other":
            break
        if _round == 0:
            _say(f"gateway: another gateway dialog for {phrase(entry, what)} is open in Claude "
                 "Code; waiting for it to close first")
        if _wait_poll(key, rid, deadline) is None:
            msg = still_open_message(entry)
            _say(msg)
            raise StillOpen(entry, msg)
    else:
        msg = still_open_message(entry)
        _say(msg)
        raise StillOpen(entry, msg)
    if role == "replay" and replay is not None:
        outcome = str(replay.get("outcome"))
        _say(f"gateway: the gateway dialog for {phrase(entry, what)} finished after the last try "
             "stopped waiting; this is its result")
        _audit("popup_replayed", entry=entry, what=what, outcome=outcome)
        return outcome, str(replay.get("line") or "") or None
    if role == "unavailable":
        _audit("popup", entry=entry, what=what, outcome=Outcome.UNAVAILABLE)
        _say(message(Outcome.UNAVAILABLE, entry, what, why))
        return Outcome.UNAVAILABLE, None
    if not wait:
        if rfd >= 0:
            with contextlib.suppress(OSError):
                os.close(rfd)
        return "open", None
    note = notice or (f"gateway: waiting for {phrase(entry, what)} in the gateway dialog in "
                      "Claude Code")
    if role == "create":
        # printed when the helper opens a dialog: a job that needs none (a
        # key that already works, a jump host check) prints nothing
        res = _wait_pipe(rfd, deadline, on_shown=lambda: _say(note))
        if res is not None and public:
            _take(key, digest, rid)               # this requester got the line itself
    else:
        _say(note)
        res = _wait_poll(key, rid, deadline, digest if public else None)
    if res is None:
        msg = still_open_message(entry)
        _say(msg)
        raise StillOpen(entry, msg)
    outcome, value = res
    if outcome == Outcome.CANCELLED:
        mark_cancelled(key, digest)
    if role == "join" and outcome == Outcome.OK and value is None and load is not None:
        value = load()
    return outcome, value


# ---------------------------------------------------------------------------
# The dialog kinds
# ---------------------------------------------------------------------------


def consent(entry: str, changes: Sequence[Any], *, extra_lines: Sequence[str] = (),
            on_ok: Callable[[], Any] | None = None, lazy: bool = False) -> str:
    """One consent dialog listing each widening line; Approve / Decline,
    Decline the default. on_ok runs where the dialog runs (the helper), right
    after the user's OK (e.g. consent.approve with exactly these changes).
    Returns an Outcome."""
    text = consent_text(entry, changes, extra_lines)
    lines = [clean_line(c) for c in changes] + [clean_line(x) for x in extra_lines]

    def job() -> tuple[str, Any]:
        oc = _confirm(f"{TITLE}: allow changes for {entry}?", text, "Approve", default_cancel=True,
                      entry=entry, what="consent", cancel_label="Decline")
        if oc == Outcome.OK and on_ok is not None:
            on_ok()
        return oc, None
    return run(entry, "consent", job, kind="consent", lazy=lazy, digest=_digest(lines))[0]


def confirm(entry: str, lines: Sequence[str], *, title: str, ok_label: str = "Allow",
            what: str = "confirmation") -> str:
    """A yes/no dialog of generated lines (import summary); default button Cancel."""
    _name(entry)
    body = "\n".join(clean_line(x, 300) for x in lines)
    t = clean_line(title, 80)

    def job() -> tuple[str, Any]:
        return _confirm(f"{TITLE}: {t}", body, ok_label, default_cancel=True, entry=entry,
                        what=what), None
    return run(entry, what, job, kind="confirm", digest=_digest([t, body]))[0]


def secret(entry: str, what: str, prompt: str, verify: Callable[[str], tuple[bool, str]] | None = None,
           *, store: Callable[[str], Any] | None = None, load: Callable[[], Any] | None = None,
           lazy: bool = True, detail: dict | None = None, wait: bool = True,
           remember: bool | None = None, check: dict | None = None,
           target: str | None = None, pem: bool = False) -> tuple[str, str | None]:
    """A private field in the gateway dialog; verify(value) -> (ok, message)
    reopens the same dialog with "That didn't work: ..." up to 3 times and
    never stores a failing value; store(value) runs in the helper once the
    value is good and, when `remember` offers the "Remember it" choice (True
    or False: the box's first state; None, the default: no box, stored),
    only if the person kept it ticked. `check` names the form entry the
    daemon rechecks before handing the value over ({"section", "entry",
    "right" (one or a list) or "kind"}); every dialog for a host's or an
    account's secret passes one. Returns (Outcome, value or None). A joined
    request (another process opened the dialog) gets load() on ok."""
    _name(entry)
    _what(what)
    if NEVER_SEES not in prompt:
        prompt = prompt.rstrip() + "\n" + NEVER_SEES
    title = f"{TITLE}: {what} for {entry}"
    tgt = safe_target(target) or ""

    def job() -> tuple[str, Any]:
        _shown()
        d = dialog.Dialog(dialog.Spec("secret", prompt, title=title, ok_label="Save",
                                      entry=entry, what=what, target=tgt, remember=remember,
                                      check=check, timeout=_timeout(),
                                      extra={"pem": True} if pem else {}))
        r = d.ask()
        for attempt in range(1, MAX_TRIES + 1):
            if r.outcome != Outcome.OK:
                _remember_reason(r)
                d.close(r.outcome if r.outcome in Outcome.ALL else Outcome.FAILED)
                return (r.outcome if r.outcome in Outcome.ALL else Outcome.FAILED), None
            v = r.value
            r.value = None
            why = ""
            if not v:
                why = "nothing was typed"
            elif verify is not None:
                try:
                    ok, why = verify(v)
                except StopDialog as stop:
                    # asking again can't help (a damaged file): closed as failed, with why
                    global _LAST_REASON
                    v = None
                    reason = clean_line(stop.reason.removeprefix("gateway: "), 160)
                    _LAST_REASON = reason
                    d.close(Outcome.FAILED, reason)
                    return Outcome.FAILED, None
                except Exception as e:  # noqa: BLE001
                    ok, why = False, f"the check failed ({type(e).__name__})"
                if ok:
                    why = ""
                elif not why:
                    why = "it was rejected"
            if not why:
                keep = r.remember if r.remember is not None else (remember is not False)
                if store is not None and keep:
                    store(v)
                d.close(Outcome.OK, "supplied")
                return Outcome.OK, v
            v = None
            if attempt == MAX_TRIES:
                break
            r = d.retry(clean_line(str(why).removeprefix("gateway: "), 160), attempt + 1, MAX_TRIES)
        d.close(Outcome.FAILED, f"didn't work after {MAX_TRIES} tries")
        return Outcome.FAILED, None
    digest = _digest([what, json.dumps(detail or {}, sort_keys=True)])
    return run(entry, what, job, kind="secret", lazy=lazy, digest=digest, detail=detail,
               load=load, wait=wait)


def choice(entry: str, question: str, options: Sequence[str], *,
           on_answer: Callable[[str], Any] | None = None, lazy: bool = False,
           what: str = "choice") -> tuple[str, str | None]:
    """Pick one of options (fixed texts). Returns (Outcome, option or None)."""
    _name(entry)
    opts = [clean_line(o, 120) for o in options]
    q = clean_line(question, 600)

    def job() -> tuple[str, Any]:
        oc, v = _choice_raw(f"{TITLE}: {entry}", q, opts, entry=entry, what=what)
        if oc == Outcome.OK and on_answer is not None:
            on_answer(v)
        return oc, v
    return run(entry, what, job, kind="choice", lazy=lazy, digest=_digest([q, *opts]))


def text(entry: str, prompt: str, *, default: str = "", what: str = "confirmation") -> tuple[str, str | None]:
    """A visible text field (e.g. typing a host name to confirm a copy), or,
    with `default`, a text to copy (a public key) and OK."""
    _name(entry)
    p = clean_line(prompt, 600)

    def job() -> tuple[str, Any]:
        return _text_raw(f"{TITLE}: {entry}", p, default, entry=entry, what=what)
    return run(entry, what, job, kind="text", digest=_digest([p]))


def checklist(entry: str, prompt: str, options: Sequence[str], checked: Sequence[str], *,
              what: str = "selection") -> tuple[str, list[str] | None]:
    _name(entry)
    p = clean_line(prompt, 600)
    opts = [clean_line(o, 120) for o in options]

    def job() -> tuple[str, Any]:
        oc, v = _checklist_raw(f"{TITLE}: {entry}", p, opts, [c for c in checked if c in opts],
                               entry=entry, what=what)
        return oc, ("\n".join(v) if v is not None else None)
    oc, v = run(entry, what, job, kind="checklist", digest=_digest([p, *opts]))
    return oc, (v.split("\n") if isinstance(v, str) and v else ([] if oc == Outcome.OK else None))


def info(entry: str, text_: str) -> str:
    _name(entry)
    t = clean_line(text_, 1200) if "\n" not in text_ else "\n".join(clean_line(x, 300) for x in text_.split("\n"))
    if _MODE == "broker":
        return run(entry, "notice", lambda: (_info_raw(f"{TITLE}: {entry}", t, entry=entry), None),
                   kind="info")[0]
    return _info_raw(f"{TITLE}: {entry}", t, entry=entry)


def hostkey(entry: str, old: Sequence[str], new: Sequence[str], *, address: str | None = None,
            known: bool | None = None, on_ok: Callable[[], Any] | None = None,
            lazy: bool = True) -> str:
    """Old and new host-key fingerprints; an explicit "Trust new key", the
    default Cancel. on_ok (pin the new key) runs where the dialog runs.
    Returns an Outcome."""
    t = hostkey_text(entry, old, new, address=address, known=known)

    def job() -> tuple[str, Any]:
        oc = _confirm(f"{TITLE}: new host key for {entry}", t, "Trust new key",
                      default_cancel=True, entry=entry, what="host key")
        if oc == Outcome.OK and on_ok is not None:
            on_ok()
        return oc, None
    return run(entry, "host key", job, kind="hostkey", lazy=lazy,
               digest=_digest([*old, "->", *new]))[0]


def reenter(entry: str, what: str, prompt: str, verify: Callable[[str], tuple[bool, str]] | None = None,
            *, store: Callable[[str], Any] | None = None, detail: dict | None = None,
            check: dict | None = None) -> str:
    """A saved credential was rejected: open one re-entry dialog without
    waiting and return the message for the failing command, which says what
    really happened: a dialog is open, none can open here, or the user
    cancelled it earlier."""
    try:
        oc, _ = secret(entry, what, prompt, verify, store=store, detail=detail, lazy=True,
                       wait=False, check=check)
    except StillOpen:
        oc = "open"
    return stale_message(entry, what, oc)


# ---------------------------------------------------------------------------
# Sign-ins that need a browser: unavailable (brief section 11)
# ---------------------------------------------------------------------------

SIGNIN_UNAVAILABLE = (
    "gateway: signing in through a browser or a device code isn't available: the gateway "
    "shows no web page, browser or code to type elsewhere (only its own dialogs inside "
    "Claude Code). {instead} An existing sign-in keeps working (its refresh token is used as "
    "before).")
SIGNIN_INSTEAD = {
    "github": "Use a personal access token instead: create one on GitHub (Settings > Developer "
              "settings > Personal access tokens) and paste it into the gateway's dialog "
              "(gate check NAME).",
    "azure": "Use a service principal instead: set tenant and client_id (the service "
             "principal's application id, not the Azure CLI's) for the account in gateway.toml "
             "and paste its client secret into the gateway's dialog (gate check NAME).",
    "ml-catalog": "A catalog account signs in through Entra in a browser, which isn't "
                  "available; one signed in before keeps working until its refresh token "
                  "expires.",
}


def signin_unavailable(kind: str, name: str = "NAME") -> str:
    instead = SIGNIN_INSTEAD.get(kind, "Use a token or API key instead (gate check NAME).")
    return SIGNIN_UNAVAILABLE.format(instead=instead.replace("NAME", name))
