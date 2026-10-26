"""What the other gateway processes call: HTTP/1.1 over the daemon's socket.

    call(method, path, body) -> dict            DaemonError (status, code, message)
    health() -> dict | None                     None when nothing answers
    vault_read() / vault_write(data)            the scoped vault (a wrapped key only)
    cache_read() / cache_write(c) / open_own(blob)

Before connecting, the socket and its folder must be this user's own and
closed to others (foreign_socket); anything else is ForeignSocket (counted
as unreachable, never talked to).

The vault calls start the daemon when it isn't running (lifecycle.ensure_running)
and turn its refusals into vault errors: "locked" into vault.VaultLocked
with the daemon's wording, anything else into vault.VaultError. A daemon that
takes the connection but doesn't answer (stopped, hung) isn't started again
(its instance lock would make a new one exit): the call fails at once as
unreachable, and a hook (whose time is Claude's: every prompt and tool call
waits for it) gives it HOOK_TIMEOUT, not 15 s, and then skips it for
UNRESPONSIVE_TTL (the marker `<run>/gated-unresponsive`, cleared by the next
answer), so a hung daemon costs one short wait, not one per call. A gateway
hook (or `gated start`) whose session isn't registered yet registers it once
and retries (planes.register_agent); a registration refused because the
daemon is stopping starts a new one and registers there (call()). Every vault read asks the daemon: nothing
is kept in this process between reads, so a long-running process (the MCP
server) gets VaultLocked at its next read once the vault is locked, and the
daemon judges each read when it is made (session, scope, lock). The daemon
keeps the decrypted vault itself (broker.Broker.read), so a repeated read
costs a socket round trip, not a decryption. (paths.ENTRY_MODE is this
process's run.py mode.)
"""
from __future__ import annotations

import contextlib
import http.client
import json
import os
import socket
import stat
import time
from pathlib import Path
from typing import Any

from .. import paths, vault

MAX_BODY = 16 * 1024 * 1024
HOOK_TIMEOUT = 5.0          # a hook's vault call (the daemon answers in milliseconds)
UNRESPONSIVE_TTL = 30.0     # how long callers skip a daemon that didn't answer


class DaemonError(vault.VaultError):
    def __init__(self, status: int, code: str, message: str, body: dict | None = None):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message
        self.body = body or {}


class Unreachable(DaemonError):
    def __init__(self, message: str):
        super().__init__(0, "unreachable", message)


class Unresponsive(Unreachable):
    """The daemon took the connection but didn't answer in time (stopped,
    hung, swamped): a process holds its socket, so starting another can't
    help."""


class Refused(vault.VaultLocked):
    """The daemon won't give this program vault data (not a gateway entry
    point, or not inside a session it knows): with a wrapped key that is the
    same as locked for this program, with the daemon's reason."""


class ForeignSocket(Unreachable):
    """The socket at the daemon's path, or its folder, isn't this user's own
    (another owner, open to others, not a socket): nothing is sent to it.
    It counts as unreachable, so a start replaces it (gated's bind removes
    a stale socket from the run folder, which is this user's)."""

    def __init__(self, message: str):
        super().__init__(message)
        self.code = "foreign_socket"


def foreign_socket(sock_path: str) -> str:
    """Why the socket at sock_path mustn't be talked to, or "" (also when
    nothing is there: connect() then fails as unreachable). The folder and
    the socket must be this user's own and closed to others (gated makes
    them 0700 and 0600): a socket another user bound while the folder was
    open to them would get the vault data a stand-in sends, the values the
    mod seals and the answers to consent dialogs (review round 2). Only
    this user can change a 0700 folder, so nothing can be swapped in
    between this check and the connect."""
    uid = os.getuid()
    folder = os.path.dirname(sock_path) or "."
    for p, want in ((folder, stat.S_ISDIR), (sock_path, stat.S_ISSOCK)):
        try:
            st = os.lstat(p)
        except FileNotFoundError:
            return ""
        except OSError as e:
            return f"{p} can't be checked ({type(e).__name__})"
        if not want(st.st_mode):
            return f"{p} isn't a {'folder' if want is stat.S_ISDIR else 'socket'} of its own"
        if st.st_uid != uid:
            return f"{p} belongs to another user (uid {st.st_uid})"
        if st.st_mode & 0o077:
            return f"{p} is open to other users (mode {stat.S_IMODE(st.st_mode):o})"
    return ""


class _UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, sock_path: str, timeout: float):
        super().__init__("gated", timeout=timeout)
        self._sock_path = sock_path

    def connect(self) -> None:
        why = foreign_socket(self._sock_path)
        if why:
            raise ForeignSocket(f"gateway: the gateway daemon's socket isn't this user's own ({why}), "
                                "so the gateway didn't connect to it")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            s.connect(self._sock_path)
        except OSError:
            s.close()
            raise
        self.sock = s


def socket_path() -> Path:
    return paths.gated_socket()


REGISTER = "/agent/register"


def call(method: str, path: str, body: Any = None, *, timeout: float = 15.0,
         sock: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    """One request; the JSON answer, or DaemonError (Unreachable when nothing
    answers at the socket). A session's registration (POST /agent/register:
    a hook, `gated start --register`, a vault call's) that the daemon refuses
    because it is stopping (503 "stopping": its idle exit began) starts a new
    daemon (lifecycle.ensure_running waits for the old one to go) and is
    sent there, once."""
    try:
        return _call(method, path, body, timeout=timeout, sock=sock)
    except DaemonError as e:
        if not (e.code == "stopping" and method == "POST" and path == REGISTER and sock is None):
            raise
    from . import lifecycle
    lifecycle.ensure_running()
    return _call(method, path, body, timeout=timeout, sock=sock)


def _call(method: str, path: str, body: Any = None, *, timeout: float = 15.0,
          sock: str | os.PathLike[str] | None = None) -> dict[str, Any]:
    conn = _UnixHTTPConnection(os.fspath(sock or socket_path()), timeout)
    try:
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Connection": "close"}
        if payload is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=payload, headers=headers)
        r = conn.getresponse()
        raw = r.read(MAX_BODY + 1)
        status = r.status
    except TimeoutError:
        if conn.sock is not None:
            raise Unresponsive("gateway: the gateway daemon took the request but didn't answer in "
                               f"{timeout:g} s (stopped or hung)") from None
        raise Unreachable("gateway: the gateway daemon didn't answer (TimeoutError)") from None
    except (OSError, http.client.HTTPException) as e:
        raise Unreachable(f"gateway: the gateway daemon didn't answer ({type(e).__name__})") from None
    finally:
        conn.close()
    try:
        obj = json.loads(raw.decode("utf-8")) if raw else {}
    except (UnicodeDecodeError, ValueError):
        obj = {}
    if not isinstance(obj, dict):
        obj = {}
    if status >= 400:
        raise DaemonError(status, str(obj.get("error") or "error"),
                          str(obj.get("message") or f"gateway: the gateway daemon refused ({status})"),
                          obj)
    return obj


def health(timeout: float = 2.0, sock: str | os.PathLike[str] | None = None) -> dict[str, Any] | None:
    try:
        h = call("GET", "/health", timeout=timeout, sock=sock)
    except DaemonError:
        return None
    return h if h.get("ok") else None


# ---------------------------------------------------------------------------
# The scoped vault (key mode "wrapped")
# ---------------------------------------------------------------------------

UNREACHABLE = ("gateway: the gateway vault has a passphrase, and the gateway daemon that holds "
               "it couldn't be reached ({why}); nothing was sent. Tell the user (/gate-doctor "
               "shows the daemon's state).")


def _register() -> None:
    call("POST", "/agent/register", {"session_id": os.environ.get("CLAUDE_CODE_SESSION_ID", "")})


def _unresponsive_marker() -> Path:
    return paths.run_dir(create=False) / "gated-unresponsive"


def _contract_pid() -> int:
    try:
        doc = json.loads(paths.contract_path().read_text(encoding="utf-8"))
        pid = doc.get("pid") if isinstance(doc, dict) else None
        return pid if isinstance(pid, int) and pid > 1 else 0
    except (OSError, ValueError):
        return 0


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except OSError:
        return True


def skipping_unresponsive() -> bool:
    """A recent call found the running daemon unresponsive (the marker, not
    older than UNRESPONSIVE_TTL, naming the daemon contract.json names, which
    is still alive): skip it rather than wait again."""
    try:
        p = _unresponsive_marker()
        st = p.stat()
        if not (0 <= time.time() - st.st_mtime <= UNRESPONSIVE_TTL):
            return False
        pid = int(p.read_text(encoding="utf-8").split()[0])
    except (OSError, ValueError, IndexError):
        return False
    return pid > 1 and pid == _contract_pid() and _pid_alive(pid)


def _mark_unresponsive() -> None:
    pid = _contract_pid()
    if not pid:
        return
    p = _unresponsive_marker()
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(f"{pid}\n")
        os.replace(tmp, p)
    except OSError:
        with contextlib.suppress(OSError):
            tmp.unlink()


def _clear_unresponsive() -> None:
    with contextlib.suppress(OSError):
        _unresponsive_marker().unlink()


def _vault_call(path: str, body: dict[str, Any]) -> dict[str, Any]:
    """One vault request; the daemon is started (or an older one replaced,
    lifecycle.ensure_running) only when nothing answers, and a hook whose
    session the daemon doesn't know registers it once. A daemon that takes
    the request but doesn't answer is reported at once (Unresponsive: never
    started again), and a hook skips it for a while (skipping_unresponsive)."""
    from . import lifecycle
    started = registered = False
    hook = paths.ENTRY_MODE.startswith("hook-")
    why_unresponsive = "it isn't answering (stopped or hung); it was skipped for now"
    if hook and skipping_unresponsive():
        raise vault.VaultLocked(UNREACHABLE.format(why=why_unresponsive))
    while True:
        try:
            r = call("POST", path, body, timeout=HOOK_TIMEOUT if hook else 15.0)
            if hook:
                _clear_unresponsive()
            return r
        except Unresponsive as e:
            if hook:
                _mark_unresponsive()
            raise vault.VaultLocked(UNREACHABLE.format(why=e.message.removeprefix("gateway: "))) from None
        except Unreachable as e:
            if started:
                raise vault.VaultLocked(UNREACHABLE.format(why=e.message.removeprefix("gateway: "))) from None
            try:
                lifecycle.ensure_running()
            except DaemonError as e2:
                raise vault.VaultLocked(UNREACHABLE.format(
                    why=e2.message.removeprefix("gateway: "))) from None
            started = True
        except DaemonError as e:
            if hook:
                _clear_unresponsive()             # it answered (a refusal is an answer)
            if e.code == "locked":
                raise vault.VaultLocked(e.message) from None
            if (e.code == "not_registered" and not registered
                    and (paths.ENTRY_MODE.startswith("hook-") or paths.ENTRY_MODE == "gated")):
                try:
                    _register()
                except DaemonError:
                    raise Refused(e.message) from None
                registered = True
                continue
            if e.status == 403:
                raise Refused(e.message) from None
            raise vault.VaultError(e.message) from None


def vault_read() -> dict[str, Any]:
    """This program's view of the vault, asked of the daemon on every call
    (never kept here: a lock, an ended session or a narrower scope applies
    at the next read, also in a process that runs for the whole session)."""
    r = _vault_call("/agent/vault/read", {})
    data = r.get("data")
    if not isinstance(data, dict):
        raise vault.VaultError("gateway: the gateway daemon sent no vault data")
    return data


def vault_write(data: dict[str, Any]) -> None:
    _vault_call("/agent/vault/write", {"data": data})


def cache_read() -> dict[str, Any]:
    c = _vault_call("/agent/vault/cache-read", {}).get("cache")
    return c if isinstance(c, dict) else {"tokens": {}}


def cache_write(c: dict[str, Any]) -> None:
    _vault_call("/agent/vault/cache-write", {"cache": c})


def open_own(blob: bytes) -> bytes:
    from . import broker
    r = _vault_call("/agent/vault/open-own", {"blob": broker.b64(blob)})
    try:
        return broker.unb64(r.get("data"))
    except broker.BrokerError:
        raise vault.VaultError("gateway: the gateway daemon sent no data") from None


# ---------------------------------------------------------------------------
# Native dialogs (daemon/dialogs.py; dialog.py is the caller)
# ---------------------------------------------------------------------------


def _ensure() -> None:
    from . import lifecycle
    lifecycle.ensure_running()


def vault_passphrase(action: str) -> dict[str, Any]:
    """`gate passphrase`: gated opens its own vault dialog for `action`
    ("passphrase", "remove", "start-over") in this program's session:
    {available, id} or {available: False, reason, message}. Starts the
    daemon once when nothing answers."""
    started = False
    while True:
        try:
            return call("POST", "/agent/vault/passphrase", {"action": action}, timeout=15)
        except Unreachable as e:
            if started:
                return {"available": False, "reason": "unreachable",
                        "message": f"gateway: the gateway daemon couldn't be reached "
                                   f"({e.message.removeprefix('gateway: ')})"}
            try:
                _ensure()
            except DaemonError as e2:
                return {"available": False, "reason": "unreachable", "message": e2.message}
            started = True
        except DaemonError as e:
            if e.status == 403 and e.code != "other_config":
                return {"available": False, "reason": "no_session",
                        "message": "gateway: this program isn't running inside a Claude Code "
                                   "session the gateway knows, so no gateway dialog can open; "
                                   "ask Claude in a Claude Code session"}
            return {"available": False, "reason": e.code, "message": e.message}


def dialog_lease() -> dict[str, Any]:
    """A dialog lease for this program's session: {available, lease} or
    {available: False, reason, message}. Starts the daemon once when nothing
    answers (its registry outlives it, so the session is still known)."""
    started = False
    while True:
        try:
            return call("POST", "/agent/dialog/lease", {}, timeout=15)
        except Unreachable as e:
            if started:
                return {"available": False, "reason": "unreachable",
                        "message": "the gateway daemon couldn't be reached "
                                   f"({e.message.removeprefix('gateway: ')})"}
            try:
                _ensure()
            except DaemonError as e2:
                return {"available": False, "reason": "unreachable",
                        "message": e2.message.removeprefix("gateway: ")}
            started = True
        except DaemonError as e:
            if e.code == "other_config":           # another configuration's daemon (GW-ROB-2)
                return {"available": False, "reason": e.code,
                        "message": e.message.removeprefix("gateway: ")}
            if e.status == 403:
                return {"available": False, "reason": "no_session",
                        "message": "this program isn't running inside a Claude Code session "
                                   "the gateway knows, so no gateway dialog can open"}
            return {"available": False, "reason": e.code,
                    "message": e.message.removeprefix("gateway: ")}


def term_call(path: str, body: dict[str, Any], *, timeout: float = 30.0) -> dict[str, Any]:
    """A terminal or job request (/agent/term/*, /agent/job/*) from the gw MCP
    server: the daemon is started once when nothing answers. A refusal comes
    back as {ok: False, error, message} (never raised): the tool shows it."""
    started = False
    while True:
        try:
            return call("POST", path, body, timeout=timeout)
        except Unreachable as e:
            if started:
                return {"ok": False, "error": "unreachable",
                        "message": "gateway: the gateway daemon couldn't be reached "
                                   f"({e.message.removeprefix('gateway: ')}); /gate-doctor says more"}
            try:
                _ensure()
            except DaemonError as e2:
                return {"ok": False, "error": "unreachable", "message": e2.message}
            started = True
        except DaemonError as e:
            body_out = dict(e.body) if isinstance(e.body, dict) else {}
            body_out.update({"ok": False, "error": e.code, "message": e.message})
            return body_out


def lease_call(path: str, body: dict[str, Any], *, timeout: float = 40.0,
               restart_for: float = 15.0) -> dict[str, Any]:
    """A /lease/* call. While the daemon is gone (killed, restarting) it is
    started again and the call retried for up to `restart_for` seconds: the
    dialogs survive a restart (<run>/gated-dialogs.json)."""
    import time
    deadline = time.monotonic() + restart_for
    while True:
        try:
            return call("POST", path, body, timeout=timeout)
        except Unreachable:
            if time.monotonic() > deadline:
                raise
            try:
                _ensure()
            except DaemonError:
                time.sleep(0.5)
