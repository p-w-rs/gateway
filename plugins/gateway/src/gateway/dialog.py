"""Dialogs: how popup.py reaches the person (PLAN-v4 phase 3, SPEC 6).

Every dialog is a native pane inside Claude Code, drawn by the gate mod
(hooks/mod/), never an OS dialog (osascript, zenity and kdialog are gone), a
web page, a browser or a terminal (the brief, sections 3 and 11.1). popup.py
is the only caller; it keeps its broker (one dialog per request key across
processes, verify-then-store, outcomes) and asks through this module.

Backends
- native (production, and the e2e and TUI harness copies): a request at the
  gateway daemon (daemon/dialogs.py). popup.run takes a *lease* in the
  requesting program (it is below the Claude Code session: the agent plane)
  before it forks its detached helper; the helper opens the dialogs with that
  lease and waits for their answers. A secret typed into the pane's Client
  field is sealed to the dialog's own key and opened only by gated; the
  helper receives it from gated over the daemon's socket (a gateway process,
  like a vault read), checks it where it can and stores it only after that
  (or when the person ticked "remember").
- fake (tests): testing.override(dialog=SCRIPT) runs
  `SCRIPT KIND TITLE MESSAGE DEFAULT` (tests/fakes/fake_dialog.py): exit 0
  with the answer on stdout, 1 cancelled, 5 timeout, anything else
  unavailable. DEFAULT carries the default button for a confirm, the options
  (one per line) for a choice or checklist, else the default text.
- none: under any other test override (no fake, no `native_dialogs` knob):
  unavailable, so a test never reaches a real session's dialog.

Outcomes (Result.outcome): ok, cancelled (the person pressed Cancel or closed
the pane), timeout (nobody answered in time), unavailable (no native dialog
can open: claude -p, the Agent SDK, mods switched off, mobile, VS Code,
Remote Control; Result.reason says which), failed (the request changed or
the daemon gave up), paused (the task is paused, checkpoint's pause).

The session record (private/sessions/<sid>.env, written by the hooks from
Claude Code's own environment) is read here for ssh.py's "use my own SSH
login once" (SSH_AUTH_SOCK); dialogs no longer need the display variables.
"""
from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Sequence

from . import testing

TITLE = "Gateway"
OK, CANCELLED, TIMEOUT, UNAVAILABLE, FAILED, PAUSED = (
    "ok", "cancelled", "timeout", "unavailable", "failed", "paused")
DEFAULT_TIMEOUT = 1800          # seconds a dialog stays open (SPEC 6: up to 30 min)
KINDS = ("confirm", "secret", "text", "choice", "checklist", "info")
WAIT_STEP = 20.0                # one long poll at the daemon


@dataclass
class Result:
    outcome: str
    value: str | None = None     # text typed / option chosen / checklist: chosen labels, one per line
    remember: bool | None = None  # the person's "remember" choice, when the dialog offered one
    reason: str = ""             # why it was unavailable or failed (fixed text, never a value)

    @property
    def ok(self) -> bool:
        return self.outcome == OK


# ---------------------------------------------------------------------------
# Which backend
# ---------------------------------------------------------------------------


def backend() -> tuple[str | None, str]:
    """("native" | "fake" | None, why)."""
    fake = testing.get("dialog")
    if fake is not None:
        if fake in ("none", "", False):
            return None, "dialogs are turned off (test)"
        return "fake", "test dialog"
    if testing.active() is not None and not testing.get("e2e") \
            and not testing.get("native_dialogs"):
        return None, "no gateway dialog under a test override without a fake"
    return "native", "the gateway dialog in Claude Code"


_LEASE: str | None = None


def take_lease() -> tuple[str | None, str]:
    """A dialog lease from the daemon for this program's session (called by
    popup.run in the requesting process, before it forks its helper), or
    (None, the reason no dialog can open here)."""
    from .daemon import client
    r = client.dialog_lease()
    token = r.get("lease")
    if r.get("available") and isinstance(token, str):
        return token, ""
    return None, str(r.get("message") or "no gateway dialog can open here")


def set_lease(token: str | None) -> None:
    global _LEASE
    _LEASE = token


def lease() -> str | None:
    return _LEASE


def release_lease() -> None:
    """Close every dialog of this process's lease (the helper is done)."""
    global _LEASE
    token, _LEASE = _LEASE, None
    if not token:
        return
    try:
        from .daemon import client
        client.lease_call("/lease/release", {"lease": token}, timeout=10, restart_for=0)
    except Exception:  # noqa: BLE001 - its dialogs time out in the daemon anyway
        pass


# ---------------------------------------------------------------------------
# One dialog
# ---------------------------------------------------------------------------


@dataclass
class Spec:
    kind: str
    message: str
    title: str = TITLE
    ok_label: str = "OK"
    cancel_label: str = "Cancel"
    default_cancel: bool = False
    default: str = ""
    options: Sequence[str] = ()
    checked: Sequence[str] = ()
    entry: str = ""
    what: str = ""
    target: str = ""
    remember: bool | None = None
    paste: bool = True
    input: bool = False
    check: dict[str, Any] | None = None
    timeout: float | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class Dialog:
    """One dialog the person may be asked again (retry) after a failed check:
    the native backend keeps one request at the daemon (its queue place) and
    reopens it with "That didn't work: ..."; the fake shows a new one with
    that line first, as the dialog would read."""

    def __init__(self, spec: Spec):
        if spec.kind not in KINDS:
            raise ValueError(f"unknown dialog kind {spec.kind}")
        self.spec = spec
        self.be, self.why = backend()
        self.id: str | None = None
        self.closed = False

    # -- the timeout -------------------------------------------------------------
    def _timeout(self) -> float:
        t = self.spec.timeout
        return float(t if t is not None else testing.get("dialog_timeout", DEFAULT_TIMEOUT))

    # -- asking ------------------------------------------------------------------
    def ask(self) -> Result:
        if self.be is None:
            return Result(UNAVAILABLE, reason=self.why)
        if self.be == "fake":
            return self._fake(self.spec.message)
        return self._native_open()

    def retry(self, why: str, attempt: int = 2, of: int = 3) -> Result:
        """Ask again after a failed check (`why`: fixed text, never the value;
        `attempt` of `of`, as the dialog says)."""
        if self.be == "fake":
            return self._fake(f"That didn't work: {why}\nTry again ({attempt} of {of}).\n\n"
                              + self.spec.message)
        if self.be is None or self.id is None:
            return Result(UNAVAILABLE, reason=self.why)
        from .daemon import client
        try:
            r = client.lease_call("/lease/dialog/retry", {"lease": _LEASE, "id": self.id,
                                                          "why": why})
        except client.DaemonError:
            return Result(FAILED, reason="the gateway daemon stopped answering")
        if r.get("state") == "done":
            self.closed = True
            return Result(str(r.get("outcome") or FAILED))
        return self._native_wait()

    def close(self, outcome: str = OK, note: str = "") -> None:
        """Tell the daemon how it ended (the pane closes); idempotent."""
        if self.closed or self.be != "native" or self.id is None:
            self.closed = True
            return
        self.closed = True
        try:
            from .daemon import client
            client.lease_call("/lease/dialog/close", {"lease": _LEASE, "id": self.id,
                                                      "outcome": outcome, "note": note},
                              timeout=10, restart_for=5)
        except Exception:  # noqa: BLE001 - the daemon closes it at its deadline
            pass

    # -- native -------------------------------------------------------------------
    def _native_spec(self) -> dict[str, Any]:
        s = self.spec
        lines = [ln for ln in s.message.split("\n")]
        while lines and not lines[-1].strip():
            lines.pop()
        return {"kind": s.kind, "title": s.title, "lines": lines, "ok_label": s.ok_label,
                "cancel_label": s.cancel_label, "default_cancel": s.default_cancel,
                "default": s.default, "options": list(s.options), "checked": list(s.checked),
                "entry": s.entry, "what": s.what, "target": s.target, "remember": s.remember,
                "paste": s.paste, "input": s.input, "check": s.check,
                "timeout": self._timeout(), **s.extra}

    def _native_open(self) -> Result:
        if not _LEASE:
            return Result(UNAVAILABLE, reason="no gateway dialog can open here")
        from .daemon import client
        try:
            r = client.lease_call("/lease/dialog/open", {"lease": _LEASE,
                                                         "dialog": self._native_spec()})
        except client.DaemonError as e:
            return Result(UNAVAILABLE, reason=e.message.removeprefix("gateway: "))
        if not r.get("available") or not isinstance(r.get("id"), str):
            return Result(UNAVAILABLE, reason=str(r.get("message") or "no gateway dialog can open"))
        self.id = r["id"]
        return self._native_wait()

    def _native_wait(self) -> Result:
        from .daemon import client
        deadline = time.monotonic() + self._timeout() + 30
        while time.monotonic() < deadline:
            try:
                r = client.lease_call("/lease/dialog/wait",
                                      {"lease": _LEASE, "id": self.id, "wait": WAIT_STEP},
                                      timeout=WAIT_STEP + 15)
            except client.DaemonError as e:
                if e.status in (403, 404):
                    # the daemon lost it (a restart past its deadline, a lease gone)
                    self.closed = True
                    return Result(FAILED, reason="the gateway daemon lost this dialog")
                return Result(FAILED, reason="the gateway daemon stopped answering")
            st = r.get("state")
            if st == "done":
                self.closed = True
                oc = str(r.get("outcome") or FAILED)
                return Result(oc if oc in (OK, CANCELLED, TIMEOUT, UNAVAILABLE, FAILED, PAUSED)
                              else FAILED, reason=str(r.get("message") or ""))
            if st == "answered":
                return self._answer(r.get("answer") or {})
        self.close(TIMEOUT)
        return Result(TIMEOUT)

    def _answer(self, ans: dict[str, Any]) -> Result:
        k = self.spec.kind
        if k == "secret":
            vals = ans.get("values") or []
            v = vals[0] if vals and isinstance(vals[0], str) else None
            rem = ans.get("remember")
            if isinstance(vals, list):
                vals.clear()
            ans.clear()
            if not v:
                return Result(FAILED, reason="nothing arrived")
            return Result(OK, v, remember=rem if isinstance(rem, bool) else None)
        if k == "choice":
            c = ans.get("choice")
            return Result(OK, c) if isinstance(c, str) else Result(CANCELLED)
        if k == "checklist":
            picked = [x for x in ans.get("picked") or [] if isinstance(x, str)]
            return Result(OK, "\n".join(picked))
        if k == "text":
            t = ans.get("text")
            return Result(OK, t if isinstance(t, str) and self.spec.input else self.spec.default)
        return Result(OK)

    # -- fake (tests) -------------------------------------------------------------
    def _fake(self, message: str) -> Result:
        s = self.spec
        exe = testing.get("dialog")
        if not exe:
            return Result(UNAVAILABLE, reason=self.why)
        if s.kind == "confirm":
            d = s.cancel_label if s.default_cancel else s.ok_label
        elif s.kind in ("choice", "checklist"):
            d = "\n".join(s.options)
        else:
            d = s.default
        wait = int(self._timeout())
        try:
            r = subprocess.run([str(exe), s.kind, s.title, message, d], stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=wait + 15,
                               env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        except subprocess.TimeoutExpired:
            return Result(TIMEOUT)
        except OSError:
            return Result(UNAVAILABLE)
        if r.returncode == 1:
            return Result(CANCELLED)
        if r.returncode == 5:
            return Result(TIMEOUT)
        if r.returncode != 0:
            return Result(UNAVAILABLE, reason="no screen (test)")
        out = r.stdout[:-1] if r.stdout.endswith("\n") else r.stdout
        if s.kind in ("confirm", "info"):
            return Result(OK)
        rem = None
        if s.kind == "secret" and s.remember is not None:
            rem = s.remember
            if out.startswith("\x00forget\x00"):       # a test's "don't remember"
                out, rem = out[len("\x00forget\x00"):], False
        return Result(OK, out, remember=rem)


def show(kind: str, message: str, *, title: str = TITLE, default: str = "",
         options: Sequence[str] = (), checked: Sequence[str] = (), ok_label: str = "OK",
         cancel_label: str = "Cancel", default_cancel: bool = False,
         timeout: int | None = None, **meta: Any) -> Result:
    """One dialog, asked once and closed. Never raises for a missing dialog:
    that is Result(UNAVAILABLE)."""
    d = Dialog(Spec(kind, message, title=title, ok_label=ok_label, cancel_label=cancel_label,
                    default_cancel=default_cancel, default=default, options=options,
                    checked=checked, timeout=timeout, **meta))
    r = d.ask()
    d.close(r.outcome if r.outcome in (OK, CANCELLED, TIMEOUT) else FAILED)
    return r


# ---------------------------------------------------------------------------
# The session record (ssh.py: the user's own agent for "use my own SSH login")
# ---------------------------------------------------------------------------

SESSION_VARS = {
    "SSH_AUTH_SOCK": re.compile(r"/[A-Za-z0-9._/@+:-]{1,300}"),
}
_RECORD_RE = re.compile(r"[A-Za-z0-9_-]{1,80}\.env")


def _sid_slug(sid: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", sid or "nosession")[:80]


def _session_record() -> str | None:
    """The text of the session record to trust: this session's (by the
    caller's CLAUDE_CODE_SESSION_ID), else, when that id is missing or names
    no record while records exist, the newest record (the id comes from the
    caller's environment, which Claude's commands control). None only when
    there are no records at all."""
    try:
        from . import paths
        d = paths.private_dir() / "sessions"
    except Exception:  # noqa: BLE001 - PathError
        return None
    sid = os.environ.get("CLAUDE_CODE_SESSION_ID", "")
    if sid:
        try:
            return (d / f"{_sid_slug(sid)}.env").read_text()
        except OSError:
            pass
    newest: tuple[float, os.DirEntry] | None = None
    try:
        with os.scandir(d) as it:
            for e in it:
                if not _RECORD_RE.fullmatch(e.name):
                    continue
                try:
                    if not e.is_file(follow_symlinks=False):
                        continue
                    t = e.stat(follow_symlinks=False).st_mtime
                except OSError:
                    continue
                if newest is None or t > newest[0]:
                    newest = (t, e)
    except OSError:
        return None
    if newest is None:
        return None
    try:
        return Path(newest[1].path).read_text()
    except OSError:
        return ""          # a record exists but can't be read: trust nothing from the caller
