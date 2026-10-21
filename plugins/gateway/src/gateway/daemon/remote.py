"""Remote hosts in gated: the managed remote runtime (PLAN-v4 phase 6).

docs/modules/remote.md has the whole picture; in short:

- **Connection**: the gateway's own ssh (ssh.py / ssh_conf.py: the host's key
  from the vault, its pinned host keys, the per-host ControlMaster shared with
  the ssh stand-in). gated asks only for hosts whose effective ssh right is
  `true` ("ask" can't be asked per command for a terminal or a job). Every
  remote command line is `exec /bin/sh -c '<script>'` (the login shell only
  execs; whatever its rc prints is cut off at a marker), never a secret on it:
  values travel on ssh's stdin.
- **Identity**: at each new master connection (`ssh -O check`'s pid changed)
  gated reads the host's machine id (/etc/machine-id, IOPlatformUUID, else a
  random id kept in the runtime folder) and compares its token (the same
  derivation as localhost's: lifecycle.machine_token) with the one stored
  with the host keys in the vault (`hosts[NAME].machine_id`, first contact
  stores it). A changed host key or machine is a gated-owned confirmation in
  the person's session (phase 3's dialog) and nothing runs meanwhile.
- **Binding**: every command for a runtime first checks the host record's
  marker file in it (`<rt>/hosts/<host id>` holding a nonce gated keeps), so
  a command meant for one host can never act on another host's runtime, even
  at the same path.
- **Runtime**: staged on first need to `<base>/<version>-<platform>/`
  (base: the host's `runtime` path, default ~/.local/share/gateway-runtime;
  0700), uploaded on ssh's stdin, sha256 checked on the host (sha256sum,
  shasum, openssl, else read back and hashed here), unpacked by the target's
  pixi-unpack (TMPDIR inside the folder), probed under `env -i`, then the
  marker `.gateway-runtime` is written; older versions without a live tmux
  server are removed. No elevation, no rc change, nothing outside the folder.
- **RemoteTmux**: the runtime's tmux on a private socket in the runtime
  folder, run under `env -i` with a fixed small environment; the same
  interface as the local Tmux (run, panes) plus the poll (panes, tty modes,
  foreground groups), signals and file writes.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import re
import secrets
import shlex
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .. import audit, paths, runtime_pack, vault
from ..ssh_conf import SshError

DEFAULT_BASE = "~/.local/share/gateway-runtime"
OP_TIMEOUT = 30.0
STAGE_TIMEOUT = 600.0
REMOTE_TICK = 1.0
DOWN_FAST = 3.0                 # an op within this long of a failure fails at once (no new connect)
BACKOFF = (1.0, 2.0, 5.0, 10.0, 20.0, 30.0)
ENV_ESTIMATE = 64 * 1024 * 1024    # the unpacked env (47 MB on linux-aarch64) and some room
SOCK_MAX = 100                     # a unix socket path must stay under 104 bytes (macOS)
MARKER = ".gateway-runtime"
WRONG_HOST = "__GW_WRONG_HOST__"
NOSERVER = "__GW_NOSERVER__"
POLL_END = "__GW_POLL_END__"
DIR_RE = re.compile(r"[0-9a-f]{12}-(?:linux-64|linux-aarch64|osx-arm64|osx-64)")
BASE_RE = re.compile(r"(?:~/|/)[A-Za-z0-9._/@+-]{0,200}")
LANG = {"linux-64": "C.UTF-8", "linux-aarch64": "C.UTF-8", "osx-arm64": "en_US.UTF-8",
        "osx-64": "en_US.UTF-8"}
SYSTEM_PATH = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"
SUDO_COMMS = ("sudo", "su", "doas", "sudoedit", "pkexec")
NOANSWER = "__GW_NOANSWER__"
STALE_AFTER = 10.0                 # a host's last contact older than this: reachable/auth "unknown"
# ssh's own words for "no connection was made" (nothing of the command was
# sent); any other 255 without the gateway's marker may have run the command
NOT_SENT = re.compile(r"(?m)^(?:ssh: connect to host \S+ port [0-9]+: |ssh: Could not resolve "
                      r"hostname |kex_exchange_identification: )")

RC_TEXT = """# gateway: the remote managed shell's rc (PLAN-v4 phase 6); never the user's rc
unset HISTFILE
HISTSIZE=2000
set +o histexpand
PS1='\\[\\e[1m\\]\\u@\\h:\\w\\[\\e[0m\\]\\$ '
PROMPT_COMMAND=
"""


class RemoteError(Exception):
    """A remote host can't be used now: (code, message, http status).

    codes: no_host, right, locked, unreachable, auth, hostkey, machine,
    wrong_host, shell, unsupported, disk, noexec, write, integrity, runtime,
    build, busy."""

    def __init__(self, code: str, message: str, status: int = 503, **extra: Any):
        super().__init__(message)
        self.code, self.message, self.status, self.extra = code, message, status, extra


def q(s: str) -> str:
    return shlex.quote(s)


def base_ok(base: Any) -> bool:
    """A runtime base path the gateway may stage into: absolute or ~/..., a
    safe charset, no `..` component."""
    return isinstance(base, str) and bool(BASE_RE.fullmatch(base)) and \
        ".." not in base.split("/") and "//" not in base


def base_expr(base: str) -> str:
    """The base as a shell word: ~/x -> "$HOME"/'x' (expanded on the host)."""
    if base == "~" or base == "~/":
        return '"$HOME"'
    if base.startswith("~/"):
        return '"$HOME"/' + q(base[2:].rstrip("/"))
    return q(base.rstrip("/") or "/")


def parse_stty(g: str, platform: str) -> tuple[bool, bool] | None:
    """(echo, canonical) from `stty -g` (GNU/busybox: colon-separated hex,
    lflag the 4th; BSD/macOS: gfmt1:lflag=HEX:...), or None."""
    g = (g or "").strip()
    try:
        if g.startswith("gfmt1:"):
            kv = dict(x.split("=", 1) for x in g.split(":")[1:] if "=" in x)
            lflag = int(kv["lflag"], 16)
            return bool(lflag & 0x8), bool(lflag & 0x100)
        parts = g.split(":")
        if len(parts) >= 4:
            lflag = int(parts[3], 16)
            return bool(lflag & 0o10), bool(lflag & 0o2)
    except (KeyError, ValueError):
        return None
    return None


# ---------------------------------------------------------------------------
# One remote host
# ---------------------------------------------------------------------------


class _Mismatch(Exception):
    def __init__(self, name: str, addr: Any, pins: list[str], seen: list[str]):
        super().__init__(name)
        self.name, self.addr, self.pins, self.seen = name, addr, pins, seen


class RemoteHost:
    def __init__(self, mgr: "Remotes", name: str):
        self.mgr = mgr
        self.d = mgr.d
        self.name = name
        self.lock = threading.RLock()        # connection, identity, staging
        self.conn: Any = None
        self.conn_key: tuple | None = None
        self.verified_pid = 0
        self.info: dict[str, Any] = dict(mgr.saved.get(name) or {})
        self.status: dict[str, Any] = {"reach": "unknown", "auth": "unknown",
                                       "identity": "unknown", "runtime": "unknown", "note": ""}
        self.change: dict[str, Any] | None = None     # a pending identity change (dialog)
        self.down_at = 0.0
        self.down_err: RemoteError | None = None
        self.fails = 0
        self.auth_dialog_at = 0.0
        self._st_cache: tuple[tuple, Any] | None = None
        self.checked_at = 0.0       # the last time the host answered (or was found down)
        # the runtime tmux servers' pids as the host last gave them (#{pid}), by
        # runtime folder: a failed list-panes is "no server" only when that pid
        # is gone too (kept in remote.json, so a gated restart still knows them)
        self.server_pids: dict[str, int] = {}
        with contextlib.suppress(ValueError, TypeError, AttributeError):
            sp = json.loads(str(self.info.get("tmux_pids") or "{}"))
            self.server_pids = {str(k): int(v) for k, v in sp.items() if int(v) > 0}

    def note_server_pid(self, rt: str, pid: int) -> None:
        """The runtime tmux server's pid in `rt` (0: it has none any more)."""
        if self.server_pids.get(rt, 0) == pid:
            return
        if pid > 0:
            self.server_pids[rt] = pid
        else:
            self.server_pids.pop(rt, None)
        self.info["tmux_pids"] = json.dumps(self.server_pids, sort_keys=True)
        self._save()

    # -- facts -------------------------------------------------------------------
    @property
    def host_id(self) -> str:
        return self.mgr.host_id(self.name)

    @property
    def machine(self) -> str:
        return str(self.info.get("machine") or "")

    @property
    def rt(self) -> str:
        return str(self.info.get("rt") or "")

    @property
    def platform(self) -> str:
        return str(self.info.get("platform") or "")

    def summary(self, now: float | None = None) -> dict[str, Any]:
        """For snapshots, lists and /gate-doctor: never a path secret, no key.
        What the host said is only as current as the last contact
        (`checked_at`): past STALE_AFTER nobody has asked it since, so
        reachable and auth are "unknown" and a ready runtime "unknown" too
        (`stale`, with what the last contact said in `note`)."""
        now = time.time() if now is None else now
        stale_after = _test_knob("remote_stale")
        stale_after = float(stale_after) if isinstance(stale_after, (int, float)) and \
            not isinstance(stale_after, bool) else STALE_AFTER
        reach, auth, rt = self.status["reach"], self.status["auth"], self.status["runtime"]
        out = {"reachable": reach, "auth": auth, "identity": self.status["identity"],
               "runtime": rt}
        stale_note = ""
        if self.checked_at:
            out["checked_at"] = round(self.checked_at, 3)
            age = now - self.checked_at
            if age > stale_after and (reach, auth) != ("unknown", "unknown"):
                out.update({"reachable": "unknown", "auth": "unknown", "stale": True})
                if rt == "ready":
                    out["runtime"] = "unknown"
                stale_note = (f"gateway: {self.name} was last asked {int(age)} s ago (then: reachable "
                              f"{reach}, auth {auth}, runtime {rt}); nothing has asked it since")
        if self.machine:
            out["machine"] = self.machine
            out["same_machine"] = self.machine == self.mgr.local_machine()
        if self.info.get("rt_version"):
            out["runtime_version"] = self.info["rt_version"]
            out["platform"] = self.platform
        if self.status.get("note"):
            out["note"] = self.status["note"]
        elif stale_note:
            out["note"] = stale_note
        if self.change is not None:
            out["waiting"] = self.change.get("kind")
        return out

    def _set(self, **kw: Any) -> None:
        before = dict(self.status)
        self.status.update(kw)
        if any(before.get(k) != self.status.get(k) for k in ("reach", "auth", "identity", "runtime")):
            self.mgr.emit_state(self)

    def _save(self) -> None:
        self.mgr.save_host(self.name, self.info)

    # -- the form, the vault, the rights ---------------------------------------------
    def state(self) -> Any:
        """ssh.State (vault + form + effective rights), cached while the vault
        and the form files stay the same."""
        from .. import ssh
        key = []
        for p in (paths.vault_path(), paths.form_path()):
            try:
                s = os.stat(p)
                key.append((s.st_mtime_ns, s.st_size, s.st_ino))
            except OSError:
                key.append(None)
        k = tuple(key)
        c = self._st_cache
        if c is not None and c[0] == k:
            return c[1]
        try:
            st = ssh._load()
        except vault.VaultLocked as e:
            raise RemoteError("locked", str(e) or "gateway: the vault is locked (/gate-unlock)",
                              423) from None
        except SshError as e:
            raise RemoteError("locked" if "locked" in e.message else "config", e.message) from None
        self._st_cache = (k, st)
        return st

    def check_rights(self, st: Any) -> Any:
        from .. import ssh
        eh = st.eff.hosts.get(self.name)
        fh = st.form.hosts.get(self.name)
        if eh is None or fh is None:
            raise RemoteError("no_host", f"gateway: {self.name} isn't a host in gateway.toml", 404)
        if fh.is_local:
            raise RemoteError("no_host", "gateway: localhost is this computer (no remote runtime)", 400)
        if eh.new:
            raise RemoteError("right", f"gateway: {self.name} waits for the user's OK; run gate "
                              f"check {self.name} while the user is here", 409)
        if eh.ssh is False:
            raise RemoteError("right", ssh.off_message(self.name, "ssh", fh.ssh), 403)
        if eh.ssh == "ask":
            raise RemoteError("right", f'gateway: ssh on {self.name} is set to "ask": a gateway '
                              "terminal or job there can't ask the user about each command; ask "
                              f"the user to set ssh = true for {self.name}, or run single commands "
                              f"with ssh {self.name} CMD", 403)
        return eh

    def base(self, eh: Any) -> str:
        b = getattr(eh, "runtime", None) or DEFAULT_BASE
        if not base_ok(b):
            raise RemoteError("config", f"gateway: {self.name}'s runtime path isn't a plain absolute "
                              "or ~/ path; fix it in gateway.toml", 400)
        return b

    # -- the connection ---------------------------------------------------------------
    def _fast_fail(self) -> None:
        e = self.down_err
        if e is not None and time.time() - self.down_at < DOWN_FAST and \
                e.code in ("unreachable", "auth", "locked"):
            raise e

    def _down(self, e: RemoteError) -> RemoteError:
        self.down_at, self.down_err = time.time(), e
        self.checked_at = self.down_at
        self.fails += 1
        if e.code == "unreachable":
            self._set(reach="down", note=e.message)
        elif e.code == "auth":
            self._set(reach="ok", auth="refused", note=e.message)
        elif e.code == "locked":
            self._set(auth="locked", note=e.message)
        self.verified_pid = 0
        return e

    def _up(self) -> None:
        self.down_err = None
        self.fails = 0
        self._set(reach="ok", auth="ok", note="" if self.status.get("runtime") != "failed"
                  else self.status.get("note", ""))

    def backoff(self) -> float:
        tick = _test_knob("remote_tick")
        tick = float(tick) if isinstance(tick, (int, float)) and not isinstance(tick, bool) \
            else REMOTE_TICK
        if not self.fails:
            return tick
        if tick < REMOTE_TICK:
            return tick * 2
        return BACKOFF[min(self.fails - 1, len(BACKOFF) - 1)]

    def _close_conn(self) -> None:
        if self.conn is not None:
            with contextlib.suppress(Exception):
                self.conn.close()
        self.conn, self.conn_key, self.verified_pid = None, None, 0

    def close(self) -> None:
        with self.lock:
            self._close_conn()

    def _link(self, st: Any, session: Any) -> Any:
        from .. import ssh

        def mismatch(name: str, addr: Any, pins: list[str], seen: list[str]) -> list[str]:
            raise _Mismatch(name, addr, pins, seen)
        try:
            return ssh._build_link(self.name, st, checked=True, on_mismatch=mismatch)
        except _Mismatch as m:
            raise self._host_key_changed(m, session) from None
        except SshError as e:
            msg = e.message
            code = "unreachable" if e.code == 255 or "didn't answer" in msg else "config"
            if "no pinned host key" in msg or "has no key yet" in msg or "waits for" in msg:
                code = "right"
            if code == "unreachable":
                why = msg.removeprefix("gateway: ").rstrip(".")
                raise self._down(RemoteError("unreachable", f"gateway: {self.name} can't be reached "
                                             f"now (disconnected: {why}); the gateway retries")) from None
            raise RemoteError(code, msg, 409) from None

    def _master_pid(self) -> int:
        c = self.conn
        if c is None:
            return 0
        try:
            r = subprocess.run([*c.base(), "-O", "check", c.alias], capture_output=True, text=True,
                               timeout=5, stdin=subprocess.DEVNULL, env=_ssh_env())
        except (OSError, subprocess.TimeoutExpired, SshError):
            return 0
        m = re.search(r"pid=(\d+)", r.stderr + r.stdout)
        return int(m.group(1)) if r.returncode == 0 and m else 0

    def connect(self, session: Any = None, insist: bool = False) -> Any:
        """The verified connection (rights, host keys, machine identity), or
        RemoteError. A new master is verified before anything else runs on
        it. `insist`: try now even right after a failure (one question that
        settles a lost answer), never the fast fail."""
        from .. import ssh_conf
        with self.lock:
            if not insist:
                self._fast_fail()
            if self.change is not None:
                self._still_changed()
            st = self.state()
            self.check_rights(st)
            link = self._link(st, session)
            key = (link.addr.render(), tuple(link.host_keys), tuple(link.pubkeys),
                   tuple(x.name for x in link.chain()))
            if self.conn is None or self.conn_key != key:
                self._close_conn()
                self.conn = ssh_conf.Conn(link)
                self.conn.prepare()
                self.conn_key = key
            pid = self._master_pid()
            if not pid or pid != self.verified_pid:
                self._verify_identity(st, session)
                self.verified_pid = self._master_pid()
            return self.conn

    def _capture(self, script: str, stdin: bytes | None, timeout: float,
                 session: Any = None) -> tuple[int, bytes, bytes]:
        """One remote command on the current connection: the script through
        `exec /bin/sh -c`, the marker cut, ssh's failures classified."""
        from .. import ssh_conf
        tag = secrets.token_hex(4)
        mo, me = f"__GW_OUT_{tag}__", f"__GW_ERR_{tag}__"
        full = (f"printf '\\n%s\\n' {mo}; printf '\\n%s\\n' {me} >&2; "
                'PATH="${PATH:-/usr/bin:/bin}:/usr/bin:/bin:/usr/sbin:/sbin"; export PATH\n' + script)
        cmd = "exec /bin/sh -c " + q(full)
        try:
            r = self.conn.capture(cmd, stdin=stdin, timeout=timeout)
        except SshError as e:
            # a timeout: the command was handed to ssh and may have run on the
            # host (or still be running): its outcome is unknown, never "not run"
            self._close_conn()
            raise self._down(RemoteError("unreachable", e.message.replace(
                "took too long to answer", "didn't answer in time (disconnected?)"),
                ambiguous=True)) from None
        out, err = r.stdout, r.stderr
        if r.returncode == 255 and mo.encode() not in out:
            text = err.decode("utf-8", "replace")
            target = self.conn.target if self.conn is not None else None
            self._close_conn()
            if ssh_conf.HOSTKEY_FAIL.search(text):
                ssh_conf.cache_clear(self.name)       # the next connect scans the keys again
                # ssh itself refused the host's key (the address choice's scan
                # may have been skipped, cached or too slow): look at the keys now
                # and ask the person at once rather than at some later scan
                if target is not None and target.jump is None:
                    seen = ssh_conf.scan_keys(target.addr.host, target.addr.port)
                    if seen and not ssh_conf.keys_match(seen, target.host_keys):
                        raise self._host_key_changed(_Mismatch(self.name, target.addr,
                                                               list(target.host_keys), seen),
                                                     session)
                raise RemoteError("hostkey", f"gateway: {self.name}'s host key isn't the pinned "
                                  "one; nothing was run there (the gateway asks the user)", 409)
            if ssh_conf.AUTH_FAIL.search(text):
                ssh_conf.mark_authfail(self.name)
                raise self._down(RemoteError(
                    "auth", f"gateway: {self.name} refused the gateway's ssh key (it was removed "
                    "from the host's authorized_keys, or it expired): the user can install it again "
                    f"with gate check {self.name}; the gateway retries meanwhile", 503))
            ssh_conf.cache_clear(self.name)
            # no answer at all: unless ssh says it never got a connection, the
            # command may have run there before the answer was lost (a link
            # dropping after the command ran looks exactly like this)
            raise self._down(RemoteError("unreachable", f"gateway: {self.name} can't be reached "
                                         "now (disconnected); the gateway retries",
                                         ambiguous=not NOT_SENT.search(text)))
        if r.returncode == 255:
            # the command started but ssh lost the connection under it (the
            # gateway's scripts never exit 255): an answer cut off is no answer
            self._close_conn()
            raise self._down(RemoteError("unreachable", f"gateway: the connection to {self.name} "
                                         "dropped during a command (disconnected); the gateway "
                                         "retries", ambiguous=True))
        self.checked_at = time.time()
        i = out.find(mo.encode())
        if i < 0:
            raise RemoteError("shell", f"gateway: {self.name}'s login shell didn't run the "
                              "gateway's sh command line (the remote runtime needs a login shell "
                              "that runs `sh -c` lines: sh, bash, dash, zsh or ksh)", 409)
        out = out[i + len(mo) + 1:]
        j = err.find(me.encode())
        err = err[j + len(me) + 1:] if j >= 0 else err
        return r.returncode, out, err

    def run(self, script: str, stdin: bytes | None = None, timeout: float = OP_TIMEOUT,
            session: Any = None, rt: str | None = None,
            insist: bool = False) -> tuple[int, bytes, bytes]:
        """A script on the verified connection. With `rt` the host record's
        marker in that runtime folder is checked first (exit 97 otherwise)."""
        # one command at a time per host: the connection (its config folder,
        # agent and master) is shared, and a failure closes it
        with self.lock:
            try:
                self.connect(session, insist=insist)
            except RemoteError as e:
                # nothing of `script` was sent: whatever connect() itself ran (the
                # identity check) doesn't make this command's outcome unknown
                e.extra.pop("ambiguous", None)
                raise
            pre = ""
            if rt is not None:
                pre = bind_check(rt, self.host_id, str(self.info.get("nonce") or "-"))
            rc, out, err = self._capture(pre + script, stdin, timeout, session)
            if rt is not None and rc == 97 and WRONG_HOST.encode() in out:
                # the verified host has no marker of this record there: the folder
                # was removed, or it isn't this record's; nothing ran, and the
                # next start looks at the runtime again (and stages it if needed)
                self._set(identity="wrong_host", runtime="unknown",
                          note=f"gateway: the runtime folder on {self.name} doesn't carry this "
                               "host record's marker; nothing was run")
                raise RemoteError("wrong_host", f"gateway: the runtime folder on {self.name} "
                                  "isn't this host's (removed, or another host record's at the "
                                  "same path); nothing was run", 409)
            if self.status["reach"] != "ok" or self.status["auth"] != "ok":
                self._up()
            return rc, out, err

    # -- identity -----------------------------------------------------------------------
    IDENTIFY = (
        'printf "%s\\n" "$(uname -s 2>/dev/null)" "$(uname -m 2>/dev/null)"\n'
        "id=\n"
        "if [ -r /etc/machine-id ]; then IFS= read -r id < /etc/machine-id\n"
        "elif [ -r /var/lib/dbus/machine-id ]; then IFS= read -r id < /var/lib/dbus/machine-id\n"
        "elif [ -x /usr/sbin/ioreg ]; then id=$(/usr/sbin/ioreg -rd1 -c IOPlatformExpertDevice | "
        "sed -n 's/.*\"IOPlatformUUID\" = \"\\([^\"]*\\)\".*/\\1/p')\n"
        "fi\n"
        'if [ -z "$id" ]; then f="$HOME/.local/share/gateway-runtime/.machine-id"\n'
        '  if [ ! -r "$f" ]; then (umask 077; mkdir -p "${f%/*}" && od -An -N16 -tx1 /dev/urandom '
        "| tr -d ' \\n' > \"$f\") 2>/dev/null; fi\n"
        '  IFS= read -r id < "$f" 2>/dev/null && id="gw:$id"\nfi\n'
        'printf "id=%s\\nhome=%s\\n" "$id" "$HOME"\n'
        'echo "gwok-$((40+2))"\n')

    def identify(self, session: Any = None) -> dict[str, str]:
        rc, out, _err = self._capture(self.IDENTIFY, None, OP_TIMEOUT, session)
        lines = out.decode("utf-8", "replace").splitlines()
        if "gwok-42" not in lines or len(lines) < 4:
            raise RemoteError("shell", f"gateway: {self.name}'s login shell didn't run the "
                              "gateway's POSIX sh lines", 409)
        kv = dict(ln.split("=", 1) for ln in lines[2:] if "=" in ln)
        return {"sysname": lines[0].strip(), "machine": lines[1].strip(),
                "id": kv.get("id", "").strip(), "home": kv.get("home", "").strip()}

    @staticmethod
    def token_of(raw: str) -> str:
        from .lifecycle import machine_token
        raw = raw.strip()
        if re.fullmatch(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}", raw):
            raw = raw.upper()                 # IOPlatformUUID, as vault.machine_id spells it
        elif re.fullmatch(r"[0-9A-Fa-f]{32}", raw):
            raw = raw.lower()                 # /etc/machine-id
        return machine_token(raw)

    def _verify_identity(self, st: Any, session: Any) -> None:
        ident = self.identify(session)
        raw = ident["id"]
        if not raw or not re.fullmatch(r"[A-Za-z0-9:-]{8,80}", raw):
            raise RemoteError("machine", f"gateway: {self.name} gave no machine id the gateway can "
                              "use (no /etc/machine-id, no IOPlatformUUID, and the runtime folder "
                              "couldn't keep one)", 409)
        token = self.token_of(raw)
        rec = (st.data.get("hosts") or {}).get(self.name) or {}
        stored = rec.get("machine_id")
        if stored and stored != token:
            raise self._machine_changed(stored, token, session)
        if not stored:
            with vault.edit() as d:
                r = vault.host_record(d, self.name)
                if r.get("machine_id") and r["machine_id"] != token:
                    raise self._machine_changed(r["machine_id"], token, session)
                r["machine_id"] = token
                r["machine_id_at"] = vault.now()
                vault.add_event(d, "machine", f"{self.name}: machine identity recorded at first "
                                              f"contact ({token})")
            self._st_cache = None
            audit.log("remote_identity", host=self.name, machine=token, outcome="recorded")
        self.info.update({"machine": token, "sysname": ident["sysname"][:20],
                          "arch": ident["machine"][:20], "home": ident["home"][:400]})
        self._save()
        self._set(identity="verified")

    # -- identity changes: the person's OK in gated's own dialog --------------------------
    def _addrs(self, st: Any) -> list[str]:
        h = st.form.hosts.get(self.name)
        try:
            return sorted(a.render() for a in h.addresses()) if h is not None else []
        except Exception:  # noqa: BLE001
            return []

    def _addrs_now(self) -> list[str]:
        try:
            return self._addrs(self.state())
        except RemoteError:
            return []

    def _session_for_dialog(self, session: Any) -> Any:
        if session is not None:
            return session
        return self.mgr.owner_session(self.name)

    def _still_changed(self) -> None:
        """A pending change blocks every operation until it is settled; a
        change the user accepted elsewhere (gate check re-pinned) clears it."""
        c = self.change
        if c is None:
            return
        try:
            st = self.state()
        except RemoteError:
            st = None
        if st is not None:
            rec = (st.data.get("hosts") or {}).get(self.name) or {}
            pins = sorted(vault.norm_host_key(k) for k in rec.get("host_keys") or [])
            if self._addrs(st) != c.get("addrs"):
                self.change = None          # the host's addresses changed since: look again
                return
            if c["kind"] == "host_key" and pins != c.get("pins_before"):
                self.change = None
                return
            if c["kind"] == "machine" and rec.get("machine_id") != c.get("old"):
                self.change = None
                return
        if c.get("state") == "declined" and time.time() - c.get("at", 0) > 600:
            self.change = None              # an explicit operation may ask once more
            return
        raise RemoteError(c["code"], c["message"], 409)

    def _ask(self, kind: str, title: str, lines: list[str], ok_label: str,
             on_ok: Callable[[], None], session: Any, what: str) -> dict[str, Any]:
        sess = self._session_for_dialog(session)
        if sess is None:
            return {"available": False, "reason": "no_session"}
        dlg = self.d.dialogs

        def handler(_r: Any, _values: list[str]) -> tuple[bool, str]:
            try:
                on_ok()
            except Exception as e:  # noqa: BLE001
                return False, f"couldn't record it ({type(e).__name__})"
            return True, "accepted"

        def closed(_rid: str, outcome: str) -> None:
            with contextlib.suppress(Exception):
                c = self.change
                if c is not None and c.get("dialog") == _rid and outcome != "ok":
                    c["state"] = "declined"
                    c["at"] = time.time()
                    c["message"] = (f"gateway: the user didn't accept {self.name}'s new {what}; "
                                    f"nothing runs there. If the machine was reinstalled, the user "
                                    f"can run gate check {self.name}")
        try:
            return dlg.open_owned(sess, {"title": title, "entry": self.name, "what": what,
                                         "target": self.name, "lines": lines, "ok_label": ok_label,
                                         "default_cancel": True, "timeout": 1800},
                                  handler=handler, on_close=closed, kind="confirm")
        except Exception as e:  # noqa: BLE001
            self.d.log(f"remote: {self.name}: no dialog ({type(e).__name__})")
            return {"available": False, "reason": "error"}

    def _host_key_changed(self, m: _Mismatch, session: Any) -> RemoteError:
        from .. import popup, ssh
        old = vault.host_key_fingerprints(m.pins)
        new = vault.host_key_fingerprints(m.seen)
        audit.log("hostkey", host=m.name, address=m.addr.render(), outcome="asking", old=old, new=new)
        pins_before = sorted(vault.norm_host_key(k) for k in m.pins)
        if self.change is not None and self.change.get("kind") == "host_key":
            return RemoteError(self.change["code"], self.change["message"], 409)
        try:
            text = popup.hostkey_text(m.name, m.pins, m.seen, address=m.addr.render())
        except Exception:  # noqa: BLE001
            text = f"The host key of {m.name} is not the one the gateway pinned."
        lines = text.split("\n") + [
            "", "Until you answer, the gateway runs nothing on this host (its terminals and jobs "
            "there are reported as waiting)."]

        def ok() -> None:
            ssh._pin_host_keys(m.name, m.addr, m.seen)
            self._st_cache = None
            with self.lock:
                self.change = None
                self._close_conn()
            self._set(identity="unknown", note="")
        self._set(identity="changed_key", note=f"gateway: {m.name}'s host key changed")
        r = self._ask("host_key", f"Gateway: new host key for {m.name}", lines, "Trust new key", ok,
                      session, "host key")
        if r.get("available"):
            msg = (f"gateway: {m.name}'s host key changed; a gateway dialog asks the user whether to "
                   "trust the new one, and nothing runs there until they answer")
            self.change = {"kind": "host_key", "code": "hostkey", "message": msg, "state": "asking",
                           "dialog": r.get("id"), "at": time.time(), "pins_before": pins_before,
                           "addrs": self._addrs_now()}
        else:
            msg = (f"gateway: {m.name}'s host key changed and no gateway dialog could ask the user; "
                   f"nothing runs there. Ask the user to run gate check {m.name} in an interactive "
                   "Claude Code session")
            self.change = {"kind": "host_key", "code": "hostkey", "message": msg,
                           "state": "unavailable", "at": time.time(), "pins_before": pins_before,
                           "addrs": self._addrs_now()}
        return RemoteError("hostkey", msg, 409)

    def _machine_changed(self, old: str, new: str, session: Any) -> RemoteError:
        audit.log("remote_identity", host=self.name, machine=new, previous=old, outcome="asking")
        if self.change is not None and self.change.get("kind") == "machine":
            return RemoteError(self.change["code"], self.change["message"], 409)
        lines = [f"{self.name} answers with its pinned host key, but it is another machine than "
                 "the one the gateway met there before.",
                 f"Recorded machine: {old}", f"Now:              {new}",
                 "", "Accept it only if you expect it (the host was rebuilt, or its disk moved to "
                 "other hardware). Terminals and jobs the gateway started on the old machine can't "
                 "be reached through this host any more; they are reported as unknown.",
                 "Until you answer, the gateway runs nothing on this host."]

        def ok() -> None:
            with vault.edit() as d:
                r = vault.host_record(d, self.name)
                r["machine_id"] = new
                r["machine_id_at"] = vault.now()
                vault.add_event(d, "machine", f"{self.name}: new machine identity accepted ({old} "
                                              f"-> {new})")
            audit.log("remote_identity", host=self.name, machine=new, previous=old, outcome="accepted")
            self._st_cache = None
            with self.lock:
                self.change = None
                self.info = {k: v for k, v in self.info.items()
                             if k in ("nonce",)}           # the old machine's runtime facts go
                self.info["machine"] = new
                self._save()
                self._close_conn()
            self.mgr.machine_changed(self.name, old, new)
            self._set(identity="unknown", runtime="unknown", note="")
        self._set(identity="changed_machine", note=f"gateway: {self.name} is another machine now")
        r = self._ask("machine", f"Gateway: {self.name} is another machine", lines, "Accept new machine",
                      ok, session, "machine")
        if r.get("available"):
            msg = (f"gateway: {self.name} is another machine than before (its machine id changed); "
                   "a gateway dialog asks the user, and nothing runs there until they answer")
            self.change = {"kind": "machine", "code": "machine", "message": msg, "state": "asking",
                           "dialog": r.get("id"), "at": time.time(), "old": old, "new": new,
                           "addrs": self._addrs_now()}
        else:
            msg = (f"gateway: {self.name} is another machine than before and no gateway dialog could "
                   f"ask the user; nothing runs there. Ask the user in an interactive session")
            self.change = {"kind": "machine", "code": "machine", "message": msg,
                           "state": "unavailable", "at": time.time(), "old": old, "new": new,
                           "addrs": self._addrs_now()}
        return RemoteError("machine", msg, 409)

    def auth_notice(self, session: Any) -> None:
        """A refused key: tell the person once per episode (an info dialog in
        the session that owns work there), with the remedy."""
        if time.time() - self.auth_dialog_at < 900:
            return
        sess = self._session_for_dialog(session)
        if sess is None:
            return
        self.auth_dialog_at = time.time()
        lines = [f"{self.name} refused the gateway's ssh key (it was removed from authorized_keys "
                 "there, or it expired).",
                 f"The gateway's terminals and jobs on {self.name} keep running there, but the "
                 "gateway can't reach them until the key works again; it retries every few seconds.",
                 f"To install the key again: gate check {self.name} (in Claude's Bash or your own "
                 "terminal)."]
        with contextlib.suppress(Exception):
            self.d.dialogs.open_owned(sess, {"title": f"Gateway: {self.name} refused the key",
                                             "entry": self.name, "what": "ssh key",
                                             "target": self.name, "lines": lines, "ok_label": "OK",
                                             "timeout": 1800},
                                      handler=lambda _r, _v: (True, "seen"), kind="info")

    # -- the runtime --------------------------------------------------------------------
    def ready(self) -> bool:
        return bool(self.rt) and self.info.get("rt_version") == runtime_pack.version() and \
            bool(self.info.get("nonce")) and self.status.get("runtime") == "ready"

    def ensure_runtime(self, session: Any = None) -> str:
        """The ready runtime folder on the host (staged on first need).
        Raises RemoteError."""
        with self.lock:
            self.connect(session)
            st = self.state()
            eh = self.check_rights(st)
            base = self.base(eh)
            plat = runtime_pack.platform_of(self.info.get("sysname", ""), self.info.get("arch", ""))
            if plat is None:
                self._set(runtime="unsupported")
                raise RemoteError("unsupported", "gateway: " + runtime_pack.unsupported_text(
                    self.info.get("sysname", ""), self.info.get("arch", "")), 409)
            ver = runtime_pack.version()
            if self.info.get("base") != base:
                self.info.pop("rt", None)
                self.info.pop("rt_version", None)
            if self.rt and self.info.get("rt_version") == ver and self.status["runtime"] == "ready":
                return self.rt
            if self.info.get("rt_version") != ver or self.info.get("base") != base:
                # staging (or updating) the runtime writes and runs programs on
                # the host: the host's provision policy (PLAN-v4 phase 7); a
                # runtime staged before stays usable when it is denied later
                from .. import policy
                d = policy.decide(st.eff, "provision", host=self.name)
                if d.word is not True:
                    raise RemoteError("policy", d.message("staging the gateway's managed runtime"),
                                      403)
            self._set(runtime="checking")
            try:
                rt = self._stage(base, plat, ver, session)
            except RemoteError as e:
                if e.code not in ("unreachable", "auth", "locked", "hostkey", "machine"):
                    self._set(runtime="failed", note=e.message)
                else:
                    self._set(runtime="unknown")
                raise
            except runtime_pack.PackError as e:
                self._set(runtime="failed", note=e.message)
                raise RemoteError("build", e.message, 503 if e.code == "build" else 409) from None
            self._set(runtime="ready", note="")
            return rt

    def _prepare_script(self, base: str, dirname: str) -> str:
        return (f"umask 077; b={base_expr(base)}\n"
                'mkdir -p "$b" 2>/dev/null; chmod 700 "$b" 2>/dev/null\n'
                f'd="$b"/{q(dirname)}\n'
                'if [ ! -d "$b" ] || [ ! -w "$b" ]; then echo GW_BASE_NOT_WRITABLE; exit 3; fi\n'
                f'if [ -f "$d/{MARKER}" ]; then echo GW_HAVE; cat "$d/{MARKER}"; echo; fi\n'
                'mkdir -p "$d/terms" "$d/hosts" && chmod 700 "$d" "$d/terms" "$d/hosts" || '
                '{ echo GW_MKDIR_FAILED; exit 3; }\n'
                'printf "dir=%s\\n" "$d"\n'
                'printf "df=%s\\n" "$(df -Pk "$d" 2>/dev/null | tail -n 1)"\n')

    def _stage(self, base: str, plat: str, ver: str, session: Any) -> str:
        dirname = f"{ver}-{plat}"
        rc, out, err = self.run(self._prepare_script(base, dirname), session=session)
        text = out.decode("utf-8", "replace")
        if "GW_BASE_NOT_WRITABLE" in text or "GW_MKDIR_FAILED" in text or rc != 0:
            raise RemoteError("write", f"gateway: the gateway can't make its runtime folder under "
                              f"{base} on {self.name}; set another runtime path for {self.name} in "
                              'gateway.toml (runtime = "/a/folder/you/own"), which the user approves',
                              409)
        kv = {}
        for ln in text.splitlines():
            if "=" in ln and ln.split("=", 1)[0] in ("dir", "df"):
                kv[ln.split("=", 1)[0]] = ln.split("=", 1)[1]
        rt = kv.get("dir", "")
        if not rt.startswith("/") or not rt.endswith("/" + dirname):
            raise RemoteError("runtime", f"gateway: {self.name} gave an unexpected runtime folder", 409)
        if len(rt) + len("/tmux.sock") >= SOCK_MAX:
            raise RemoteError("config", f"gateway: the runtime folder on {self.name} is too long for "
                              "tmux's socket (unix sockets need paths under 104 bytes); set a shorter "
                              f"runtime path for {self.name} in gateway.toml", 409)
        nonce = str(self.info.get("nonce") or "") or secrets.token_hex(16)
        have = None
        if "GW_HAVE" in text:
            try:
                have = json.loads(text.split("GW_HAVE", 1)[1].strip().splitlines()[0])
            except (ValueError, IndexError):
                have = None
        if isinstance(have, dict) and have.get("version") == ver and have.get("platform") == plat:
            probe = self._probe(rt, session)
            if probe is not None:
                self._finish(rt, plat, ver, base, nonce, probe, session, staged=False)
                return rt
        m = runtime_pack.ensure(plat)
        self._check_space(kv.get("df", ""), m, rt)
        self._upload(rt, m, session)
        self._verify(rt, m, session)
        self._unpack(rt, session)
        probe = self._probe(rt, session)
        if probe is None:
            raise RemoteError("runtime", f"gateway: the runtime on {self.name} doesn't start "
                              "(bash or tmux failed their readiness probe under env -i)", 409)
        self._finish(rt, plat, ver, base, nonce, probe, session, staged=True)
        return rt

    def _check_space(self, df: str, m: dict[str, Any], rt: str) -> None:
        parts = df.split()
        need = runtime_pack.total_size(m) + ENV_ESTIMATE
        need_kb = need // 1024
        try:
            avail = int(parts[3])
        except (IndexError, ValueError):
            return                                   # unknown: the upload's errors say it
        fake = _test_knob("remote_df_avail_kb")
        if isinstance(fake, int) and not isinstance(fake, bool):
            avail = fake
        if avail < need_kb:
            raise RemoteError("disk", f"gateway: {self.name} has {avail // 1024} MB free where the "
                              f"runtime goes ({rt}) and it needs about {need_kb // 1024 + 1} MB "
                              "while it is set up: free some space there, or set another runtime "
                              f"path for {self.name} in gateway.toml (runtime = \"/a/folder/with/"
                              "space\"), which the user approves", 507)

    def _classify_write(self, err: bytes, rt: str) -> RemoteError:
        e = err.decode("utf-8", "replace")
        if re.search(r"(?i)no space left|disk quota|file too large", e):
            return RemoteError("disk", f"gateway: {self.name} ran out of disk space where the "
                               f"runtime goes ({rt}): free some space there, or set another runtime "
                               f"path for {self.name} in gateway.toml (runtime = \"/a/folder/with/"
                               "space\")", 507)
        if re.search(r"(?i)read-only file system|permission denied", e):
            return RemoteError("write", f"gateway: the runtime folder on {self.name} isn't writable "
                               f"({rt}); set another runtime path for {self.name} in gateway.toml", 409)
        return RemoteError("write", f"gateway: copying the runtime to {self.name} failed: "
                           + " ".join(e.split())[-200:], 503)

    def _upload(self, rt: str, m: dict[str, Any], session: Any) -> None:
        src = runtime_pack.artifacts_dir(m["platform"], m["version"])
        self.run(f'cd {q(rt)} && rm -rf unpacker env runtime.tar .tmp && mkdir -p unpacker/bin '
                 'unpacker/lib && chmod 700 unpacker', session=session)
        corrupt = _test_knob("remote_corrupt_upload")
        for f in m["files"]:
            rel = f["path"]
            data = (src / rel).read_bytes()
            if corrupt and rel == corrupt:
                data = data[:-1] + bytes([data[-1] ^ 0x5A]) if data else b"x"
            mode = "755" if f.get("mode") == 0o755 else "600"
            script = (f"umask 077; cd {q(rt)} && cat > {q(rel + '.part')} && "
                      f"mv -f {q(rel + '.part')} {q(rel)} && chmod {mode} {q(rel)}")
            rc, _out, err = self.run(script, stdin=data, timeout=STAGE_TIMEOUT, session=session)
            if rc != 0:
                self.run(f"cd {q(rt)} && rm -f {q(rel + '.part')}", session=session)
                raise self._classify_write(err, rt)

    HASH = ('if command -v sha256sum >/dev/null 2>&1; then sha256sum -- "$@"\n'
            'elif command -v shasum >/dev/null 2>&1; then shasum -a 256 -- "$@"\n'
            'elif command -v openssl >/dev/null 2>&1; then for f in "$@"; do '
            'h=$(openssl dgst -sha256 -r "$f" 2>/dev/null) || exit 4; printf "%s\\n" "$h"; done\n'
            "else echo GW_NOHASH; fi\n")

    def remote_hashes(self, rt: str, rels: list[str], session: Any) -> dict[str, str] | None:
        """{rel: sha256} computed on the host, None when it has no hash tool."""
        if _test_knob("remote_no_hash_tool"):
            return None
        script = f"cd {q(rt)} || exit 3\nset -- " + " ".join(q(r) for r in rels) + "\n" + self.HASH
        rc, out, err = self.run(script, session=session)
        text = out.decode("utf-8", "replace")
        if "GW_NOHASH" in text:
            return None
        got: dict[str, str] = {}
        for ln in text.splitlines():
            m = re.match(r"([0-9a-f]{64})\s+\*?(.+)$", ln.strip())
            if m:
                got[m.group(2).strip()] = m.group(1)
        return got

    def _read_back_hash(self, rt: str, rel: str, session: Any) -> str:
        """The fallback without a hash tool on the host: the file read back
        through ssh and hashed here."""
        rc, out, _err = self.run(f"cat -- {q(rt + '/' + rel)}", timeout=STAGE_TIMEOUT, session=session)
        return hashlib.sha256(out).hexdigest() if rc == 0 else ""

    def _verify(self, rt: str, m: dict[str, Any], session: Any) -> None:
        rels = [f["path"] for f in m["files"]]
        got = self.remote_hashes(rt, rels, session)
        how = "on the host"
        if got is None:
            how = "read back"
            got = {rel: self._read_back_hash(rt, rel, session) for rel in rels}
        bad = [f["path"] for f in m["files"] if got.get(f["path"]) != f["sha256"]]
        if bad:
            self.run(f"cd {q(rt)} && rm -rf unpacker runtime.tar", session=session)
            audit.log("remote_runtime", host=self.name, outcome="integrity", files=len(bad), how=how)
            raise RemoteError("integrity", f"gateway: the runtime copied to {self.name} didn't match "
                              f"its sha256 ({len(bad)} file(s), checked {how}); it was removed and "
                              "nothing was unpacked. Try again; if it repeats, something on the way "
                              "changes the files", 502)
        self.info["hash_check"] = how

    def _unpack(self, rt: str, session: Any) -> None:
        script = (f"cd {q(rt)} || exit 3\n"
                  'u="$PWD/unpacker/bin/pixi-unpack"\n'
                  'out=$("$u" --version 2>&1); rc=$?\n'
                  'if [ $rc -eq 126 ]; then printf "GW_EXEC_FAILED %s\\n" "$out"; exit 4; fi\n'
                  'if [ $rc -ne 0 ]; then printf "GW_UNPACKER_FAILED %s\\n" "$out"; exit 5; fi\n'
                  'mkdir -p .tmp && TMPDIR="$PWD/.tmp" "$u" "$PWD/runtime.tar" -o "$PWD" -e env -q '
                  '>/dev/null 2>.unpack.err; rc=$?\n'
                  'rm -rf .tmp runtime.tar\n'
                  'if [ $rc -ne 0 ]; then printf "GW_UNPACK_FAILED "; tail -c 300 .unpack.err; exit 6; fi\n'
                  'rm -rf unpacker .unpack.err\n')
        rc, out, err = self.run(script, timeout=STAGE_TIMEOUT, session=session)
        text = out.decode("utf-8", "replace")
        if rc == 4 or "GW_EXEC_FAILED" in text:
            if re.search(r"(?i)permission denied", text):
                raise RemoteError("noexec", f"gateway: {self.name} doesn't let programs run from the "
                                  f"runtime folder ({rt}: a noexec mount?); set a runtime path for "
                                  f"{self.name} in gateway.toml on a file system that allows it "
                                  '(runtime = "/a/folder/where/programs/run"), which the user '
                                  "approves", 409)
            raise RemoteError("runtime", f"gateway: the runtime's pixi-unpack doesn't run on "
                              f"{self.name}: " + " ".join(text.split())[-200:], 409)
        if rc != 0:
            if re.search(r"(?i)no space left|disk quota", text + err.decode("utf-8", "replace")):
                raise self._classify_write(b"No space left on device", rt)
            raise RemoteError("runtime", f"gateway: unpacking the runtime on {self.name} failed: "
                              + " ".join(text.split())[-240:], 503)

    def _probe(self, rt: str, session: Any) -> dict[str, str] | None:
        """bash --version and tmux -V inside the runtime under env -i; None
        when either fails."""
        script = (f"r={q(rt)}\n"
                  'b=$(env -i HOME="$HOME" PATH=/usr/bin:/bin "$r/env/bin/bash" --noprofile --norc '
                  "-c 'printf %s \"$BASH_VERSION\"' 2>/dev/null) || exit 7\n"
                  't=$(env -i HOME="$HOME" PATH=/usr/bin:/bin "$r/env/bin/tmux" -V 2>/dev/null) || exit 8\n'
                  'printf "bash=%s\\ntmux=%s\\n" "$b" "$t"\n')
        try:
            rc, out, _err = self.run(script, session=session)
        except RemoteError:
            raise
        if rc != 0:
            return None
        kv = dict(ln.split("=", 1) for ln in out.decode("utf-8", "replace").splitlines() if "=" in ln)
        if not kv.get("bash", "").startswith("5.") or not kv.get("tmux", "").startswith("tmux 3"):
            return None
        return {"bash": kv["bash"][:40], "tmux": kv["tmux"][:40]}

    def _finish(self, rt: str, plat: str, ver: str, base: str, nonce: str, probe: dict[str, str],
                session: Any, staged: bool) -> None:
        from .terminals import TMUX_CONF
        marker = json.dumps({"version": ver, "platform": plat, "bash": probe["bash"],
                             "tmux": probe["tmux"], "at": round(time.time(), 3)})
        files = [("tmux.conf", TMUX_CONF), ("gateway.rc", RC_TEXT), (f"hosts/{self.host_id}", nonce + "\n")]
        for rel, text in files:
            rc, _o, err = self.run(f"umask 077; cd {q(rt)} && cat > {q(rel + '.part')} && "
                                   f"mv -f {q(rel + '.part')} {q(rel)}",
                                   stdin=text.encode("utf-8"), session=session)
            if rc != 0:
                raise self._classify_write(err, rt)
        if staged:
            rc, _o, err = self.run(f"umask 077; cd {q(rt)} && cat > {MARKER}.part && "
                                   f"mv -f {MARKER}.part {MARKER}", stdin=marker.encode(),
                                   session=session)
            if rc != 0:
                raise self._classify_write(err, rt)
        self.info.update({"rt": rt, "rt_version": ver, "platform": plat, "base": base,
                          "nonce": nonce, "bash": probe["bash"], "tmux": probe["tmux"],
                          "ready_at": round(time.time(), 3)})
        self._save()
        if staged:
            audit.log("remote_runtime", host=self.name, outcome="staged", version=ver, platform=plat,
                      hash_check=self.info.get("hash_check", ""))
        self.prune_old(base, f"{ver}-{plat}", session)

    def prune_old(self, base: str, keep: str, session: Any = None) -> list[str]:
        """Remove older runtime folders under the base: only folders named
        <12 hex>-<platform> that hold the gateway's marker and whose tmux
        server doesn't answer (a live one still runs work)."""
        rc, out, _err = self.run(f"b={base_expr(base)}; cd \"$b\" 2>/dev/null || exit 0; "
                                 "for d in *; do [ -d \"$d\" ] && printf '%s\\n' \"$d\"; done",
                                 session=session)
        names = [n for n in out.decode("utf-8", "replace").splitlines()
                 if DIR_RE.fullmatch(n) and n != keep]
        if not names:
            return []
        script = (f"b={base_expr(base)}; cd \"$b\" || exit 0\n"
                  "for d in " + " ".join(q(n) for n in names) + "; do\n"
                  f'  [ -f "$d/{MARKER}" ] || [ -f "$d/hosts/{self.host_id}" ] || continue\n'
                  '  if [ -S "$d/tmux.sock" ] && [ -x "$d/env/bin/tmux" ] && env -i PATH=/usr/bin:/bin '
                  '"$d/env/bin/tmux" -S "$d/tmux.sock" list-sessions >/dev/null 2>&1; then '
                  'echo "busy $d"; continue; fi\n'
                  '  rm -rf -- "$d" && echo "removed $d"\n'
                  "done\n")
        _rc, out, _err = self.run(script, session=session)
        gone = [ln.split(" ", 1)[1] for ln in out.decode("utf-8", "replace").splitlines()
                if ln.startswith("removed ")]
        if gone:
            audit.log("remote_runtime", host=self.name, outcome="pruned", folders=len(gone))
        return gone

    # -- host inspection and imports (PLAN-v4 phase 7) ----------------------------------
    def inspect(self, session: Any = None) -> dict[str, Any]:
        """host_inspect for this host: read-only, through the verified
        connection (managed.remote_inspect_script: files read and folders
        listed on the host, variable names; nothing sourced or run), decided
        by the host's read policy; parsed and scrubbed here."""
        from .. import managed, policy, scrub
        st = self.state()
        eh = self.check_rights(st)
        d = policy.decide(st.eff, "read", host=self.name)
        if d.word is not True:
            raise RemoteError("policy", d.message(f"inspecting {self.name}"), 403)
        rc, out, err = self.run(managed.remote_inspect_script(), session=session,
                                timeout=OP_TIMEOUT)
        if rc != 0:
            raise RemoteError("inspect", f"gateway: inspecting {self.name} failed (exit {rc})", 503)
        fh = st.form.hosts.get(self.name)
        allowed = managed.imports_allowed(st.eff, self.name)
        plan = managed.remote_path_plan(eh, self.name, self.rt or "",
                                        fh.shell.path_line if fh else None, allowed)
        ans = managed.parse_remote_inspection(out.decode("utf-8", "replace"),
                                              list(eh.import_path) if allowed else [], plan,
                                              self.name)
        ans["managed"]["env"] = [{"name": n, "origin": f"gateway.toml [hosts.{self.name}.shell] "
                                  f"import_env (from {self.name}'s login environment)"}
                                 for n in (eh.import_env if allowed else [])]
        try:
            return json.loads(scrub.scrub_text(json.dumps(ans)))
        except ValueError:
            raise RemoteError("inspect", "gateway: the inspection couldn't be read", 503) from None

    def imports(self) -> tuple[list[str], list[str]]:
        """The host's approved [hosts.NAME.shell] imports that apply now
        (folders, variable names), or nothing when its env_import policy
        isn't allow."""
        from .. import managed
        try:
            st = self.state()
        except RemoteError:
            return [], []
        eh = st.eff.hosts.get(self.name)
        if eh is None or not managed.imports_allowed(st.eff, self.name):
            return [], []
        return list(eh.import_path), list(eh.import_env)

    def tmux(self, rt: str) -> "RemoteTmux":
        return RemoteTmux(self, rt)


def bind_check(rt: str, host_id: str, nonce: str) -> str:
    """The first lines of every command for a runtime folder: the host
    record's marker there must hold the nonce gated keeps for it."""
    return (f"gw_t=; {{ IFS= read -r gw_t < {q(rt + '/hosts/' + host_id)}; }} 2>/dev/null\n"
            f'[ "$gw_t" = {q(nonce)} ] || {{ printf "\\n%s\\n" {WRONG_HOST}; exit 97; }}\n')


def _ssh_env() -> dict[str, str]:
    from .. import ssh_conf
    return ssh_conf.child_env()


def _test_knob(name: str) -> Any:
    from .. import testing
    if testing.active() is None:
        return None
    return testing.get(name)


# ---------------------------------------------------------------------------
# The runtime's tmux on a host
# ---------------------------------------------------------------------------


class RemoteTmux:
    """The local Tmux's interface (run, panes) for a runtime folder on a
    host, plus the poll, signals and file writes. Every command checks the
    host record's marker first (bind_check)."""

    INFO_FIELDS = ("session_name", "@gw_nonce", "pid", "pane_pid", "pane_tty", "pane_dead",
                   "pane_dead_status", "pane_dead_signal", "pane_width", "pane_height", "cursor_x",
                   "cursor_y", "alternate_on", "history_size", "pane_current_command", "pane_title")

    def __init__(self, host: RemoteHost, rt: str):
        self.host, self.rt = host, rt
        self.server_pid = 0

    def _x(self) -> str:
        lang = LANG.get(self.host.platform, "C.UTF-8")
        return (f'x() {{ env -i HOME="$HOME" USER="${{USER:-}}" LOGNAME="${{LOGNAME:-}}" LANG={lang} '
                f'PATH=/usr/bin:/bin {q(self.rt + "/env/bin/tmux")} -u -S {q(self.rt + "/tmux.sock")} '
                f'-f {q(self.rt + "/tmux.conf")} "$@"; }}\n')

    def _call(self, script: str, stdin: bytes | None = None, timeout: float = OP_TIMEOUT,
              session: Any = None, insist: bool = False) -> tuple[int, bytes, bytes]:
        from .terminals import TermError
        try:
            return self.host.run(script, stdin=stdin, timeout=timeout, session=session, rt=self.rt,
                                 insist=insist)
        except RemoteError as e:
            # `ambiguous`: the command went to the host and its answer was lost
            # (it may have run): the caller must not report it as not done
            raise TermError(e.status if e.status >= 400 else 503, "remote_" + e.code, e.message,
                            ambiguous=bool(e.extra.get("ambiguous"))) from None

    def run(self, *args: str, input: bytes | None = None, timeout: float = OP_TIMEOUT,
            check: bool = True, insist: bool = False) -> bytes:
        from .terminals import TermError, _clean
        rc, out, err = self._call(self._x() + "x " + " ".join(q(a) for a in args), stdin=input,
                                  timeout=timeout, insist=insist)
        if check and rc != 0:
            raise TermError(500, "tmux", f"gateway: the terminal supervisor (tmux) on {self.host.name} "
                            "refused: " + _clean(err.decode("utf-8", "replace"), 200))
        return out

    def panes(self) -> dict[str, dict[str, str]] | None:
        """Every pane of the runtime's tmux server; None when no server
        runs there (proven by the host's answer). Raises TermError when the
        host can't be asked."""
        infos, _ttys = self.poll()
        return infos

    def poll(self, session: Any = None) -> tuple[dict[str, dict[str, str]] | None,
                                                 dict[str, tuple[int, str, str]]]:
        """(panes by session name or None, {session name: (tpgid, stty -g,
        foreground comm)} for the live panes): one ssh round trip."""
        from .terminals import SEP
        fmt = SEP.join("#{" + f + "}" for f in self.INFO_FIELDS)
        pid = int(self.host.server_pids.get(self.rt, 0) or 0)
        script = (self._x() +
                  f'[ -S {q(self.rt + "/tmux.sock")} ] || {{ echo {NOSERVER}; exit 0; }}\n'
                  f"if ! out=$(x list-panes -a -F {q(fmt)} 2>/dev/null); then\n"
                  # a failed query proves nothing by itself (a fork failure, the
                  # binary briefly missing, a full listen queue): "no server" only
                  # when tmux says so AND the server pid it last gave is gone
                  "  err=$(x list-sessions 2>&1 >/dev/null)\n"
                  f"  pid={pid}\n"
                  '  case "$err" in\n'
                  '    *"no server running"*)\n'
                  '      if [ "$pid" -gt 0 ] && kill -0 "$pid" 2>/dev/null && '
                  'ps -o comm= -p "$pid" 2>/dev/null | grep -q tmux; then\n'
                  f"        echo {NOANSWER}; else echo {NOSERVER}; fi ;;\n"
                  f"    *) echo {NOANSWER} ;;\n"
                  "  esac\n"
                  "  exit 0\n"
                  "fi\n"
                  'printf "%s\\n" "$out"\necho __GW_TTYS__\n'
                  "procs=$(ps -axo pid=,pgid=,comm= 2>/dev/null)\n"
                  "x list-panes -a -F '#{session_name} #{pane_tty} #{pane_pid} #{pane_dead}' 2>/dev/null |\n"
                  "while read -r n t p dd; do\n"
                  '  [ "$dd" = 0 ] || continue\n'
                  '  g=$(stty -g < "$t" 2>/dev/null)\n'
                  "  tp=$(ps -o tpgid= -p \"$p\" 2>/dev/null | tr -d ' ')\n"
                  # the foreground group's members (its leader first): a root
                  # prompt may come from any of them (`echo x | sudo tee f`)
                  '  c=; case "$tp" in ""|*[!0-9]*) tp=0 ;; *) c=$(printf "%s\\n" "$procs" | awk -v g="$tp" '
                  "'$2==g { p=$1; $1=\"\"; $2=\"\"; sub(/^ +/, \"\"); n=split($0, a, \"/\"); "
                  "if (p==g) l=a[n]; else if (k<8) { r=r \",\" a[n]; k++ } } "
                  "END { printf \"%s%s\", l, r }') ;; esac\n"
                  '  printf "%s %s %s %s\\n" "$n" "$tp" "${g:--}" "$c"\n'
                  "done\n"
                  f"echo {POLL_END}\n")
        rc, out, _err = self._call(script, session=session)
        return self.parse_poll(out.decode("utf-8", "replace"))

    def parse_poll(self, text: str) -> tuple[dict[str, dict[str, str]] | None,
                                             dict[str, tuple[int, str, str]]]:
        """The poll's answer. "No server" only when the host said so; an
        answer that doesn't end with the end marker (cut off) is no answer:
        TermError, never "no panes"."""
        from .terminals import SEP, TermError
        first = text.split("\n", 1)[0]
        if text.strip() == NOANSWER or (NOANSWER in first and "__GW_TTYS__" not in text):
            # the host answered, but its tmux didn't (while its server process
            # lives): a blip, never "no server" (asked again at the next look)
            raise TermError(503, "remote_noanswer", f"gateway: the runtime's tmux on {self.host.name} "
                            "didn't answer just now (its server still runs); the gateway asks again")
        if text.strip() == NOSERVER or (NOSERVER in first and "__GW_TTYS__" not in text):
            self.host.note_server_pid(self.rt, 0)
            return None, {}
        if not text.rstrip("\n").endswith(POLL_END) or "__GW_TTYS__\n" not in text:
            raise TermError(503, "remote_unreachable", f"gateway: {self.host.name}'s answer was cut "
                            "off (disconnected?); the gateway retries")
        text = text.rstrip("\n")[:-len(POLL_END)]
        head, _, tail = text.partition("__GW_TTYS__\n")
        infos: dict[str, dict[str, str]] = {}
        for line in head.splitlines():
            parts = line.split(SEP, len(self.INFO_FIELDS) - 1)
            if len(parts) != len(self.INFO_FIELDS):
                continue
            d = dict(zip(self.INFO_FIELDS, parts))
            infos.setdefault(d["session_name"], d)
            if d.get("pid", "").isdigit():
                self.server_pid = int(d["pid"])
        if self.server_pid > 0:
            self.host.note_server_pid(self.rt, self.server_pid)
        ttys: dict[str, tuple[int, str, str]] = {}
        for line in tail.splitlines():
            bits = line.split(" ", 3)
            if len(bits) >= 3:
                try:
                    tp = int(bits[1])
                except ValueError:
                    tp = 0
                # the foreground group's program names, its leader first ("a,b,c")
                ttys[bits[0]] = (tp, bits[2], (bits[3] if len(bits) > 3 else "").strip()[:400])
        return infos, ttys

    def claim_start(self, rel: str, pane_id: str) -> str:
        """Settle a start whose answer was lost (PLAN-v4 phase 6). The pane's
        shell begins by renaming its start file (`remote_start_text`: it has
        it open already), and this renames it too: exactly one rename can
        succeed. "never" when this one did: the pane's shell, if it ever
        comes, fails its rename (or finds no file) and its command never runs;
        a session that came up meanwhile is killed and the file removed.
        "started" when the shell renamed it first (its command started), or
        the file isn't there. Raises TermError when the host can't be asked."""
        f = q(self.rt + "/" + rel)
        script = (self._x() +
                  f"if mv -- {f} {f}.void 2>/dev/null; then\n"
                  f"  x kill-session -t {q('=' + pane_id)} >/dev/null 2>&1\n"
                  f"  rm -f -- {f}.void; echo GW_CLAIM_NEVER\n"
                  "else echo GW_CLAIM_STARTED; fi\n")
        _rc, out, _err = self._call(script)
        text = out.decode("utf-8", "replace")
        if "GW_CLAIM_NEVER" in text:
            return "never"
        if "GW_CLAIM_STARTED" in text:
            return "started"
        from .terminals import TermError
        raise TermError(503, "remote_unreachable", f"gateway: {self.host.name} gave no answer about "
                        "the start; the gateway asks again")

    def capture_env(self, rel: str, names: list[str]) -> None:
        """A 0700 folder under the runtime folder holding, for each name the
        host's login environment has, a 0600 file with its value verbatim: a
        remote shell's import_env (PLAN-v4 phase 7). The values are read and
        written on the host (never on a command line, never sent here); the
        start file reads them back by name and removes the folder."""
        names = [n for n in names if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", n)]
        if not names:
            return
        d = q(self.rt + "/" + rel)
        lines = [f"umask 077; d={d}; mkdir -- \"$d\" || exit 3"]
        for n in names:
            lines.append(f'if [ "${{{n}+set}}" = set ]; then printf "%s" "${n}" > "$d/{n}"; fi')
        rc, _o, _e = self._call("\n".join(lines) + "\n")
        if rc != 0:
            from .terminals import TermError
            raise TermError(500, "remote_write", f"gateway: couldn't prepare the imports on "
                            f"{self.host.name}")

    def write_file(self, rel: str, text: str) -> None:
        """A new 0600 file under the runtime folder (noclobber), its text on
        ssh's stdin, never a command line."""
        from .terminals import TermError
        rc, _o, err = self._call(f"umask 077; set -C; cat > {q(self.rt + '/' + rel)}",
                                 stdin=text.encode("utf-8"))
        if rc != 0:
            raise TermError(500, "remote_write", f"gateway: couldn't write a start file on "
                            f"{self.host.name}: " + " ".join(err.decode('utf-8', 'replace').split())[-160:])

    def remove_file(self, rel: str) -> None:
        with contextlib.suppress(Exception):
            self._call(f"rm -f -- {q(self.rt + '/' + rel)}")

    def dir_ok(self, path: str) -> bool:
        rc, out, _err = self._call(f'[ -d {q(path)} ] && echo GW_DIR_OK')
        return b"GW_DIR_OK" in out

    def kill(self, pgid: int, sig: str) -> bool:
        """A signal to a process group on the host (kill -s SIG -- -PGID)."""
        if pgid <= 1 or not re.fullmatch(r"[A-Z0-9]{2,8}", sig):
            return False
        rc, _o, _e = self._call(f"kill -s {sig} -- -{int(pgid)} 2>/dev/null")
        return rc == 0

    def fg_pgrp(self, pid: int) -> int:
        if pid <= 0:
            return 0
        rc, out, _e = self._call(f"ps -o tpgid= -p {int(pid)} 2>/dev/null")
        try:
            return int(out.decode().strip() or 0)
        except ValueError:
            return 0

    def comm(self, pid: int) -> str:
        if pid <= 0:
            return ""
        _rc, out, _e = self._call(f"ps -o comm= -p {int(pid)} 2>/dev/null")
        return os.path.basename(out.decode("utf-8", "replace").strip())[:40]

    def stop_group(self, pgid: int, root: int) -> bool:
        """The local stop_group on the host: the pane's root gets SIGTTOU
        (tmux would resume a SIGSTOPped root), the rest SIGSTOP; True when
        every member shows stopped."""
        if pgid <= 1:
            return False
        script = (f"g={int(pgid)}; r={int(root)}\n"
                  "for p in $(ps -axo pid=,pgid= 2>/dev/null | awk -v g=\"$g\" '$2==g{print $1}'); do\n"
                  '  if [ "$p" = "$r" ]; then kill -s TTOU "$p" 2>/dev/null; else kill -s STOP "$p" 2>/dev/null; fi\n'
                  "done\nsleep 1\n"
                  "ps -axo pid=,pgid=,stat= 2>/dev/null | awk -v g=\"$g\" '$2==g{print $1, $3}'\n")
        _rc, out, _e = self._call(script, timeout=OP_TIMEOUT)
        after = {}
        for ln in out.decode("utf-8", "replace").splitlines():
            b = ln.split()
            if len(b) == 2 and b[0].isdigit():
                after[int(b[0])] = b[1]
        others = [st for pid, st in after.items() if pid != root]
        return bool(after) and all(st.startswith("T") for st in others) and \
            (bool(others) or after.get(root, "").startswith("T"))


# ---------------------------------------------------------------------------
# The manager
# ---------------------------------------------------------------------------


class Remotes:
    """gated's remote hosts. `daemon` gives dialogs, events, registry, log,
    machine_id(), _host_ids()."""

    def __init__(self, daemon: Any, state_path: Path | None = None):
        self.d = daemon
        self.state_path = state_path or paths.gated_remote()
        self.lock = threading.Lock()
        self.saved: dict[str, dict[str, Any]] = {}
        self.hosts: dict[str, RemoteHost] = {}
        self.owner_lookup: Callable[[str], Any] | None = None
        self.on_machine_change: Callable[[str, str, str], None] | None = None
        self._local: str | None = None
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(raw, dict) and isinstance(raw.get("hosts"), dict):
            self.saved = {str(k): v for k, v in raw["hosts"].items() if isinstance(v, dict)}

    def save_host(self, name: str, info: dict[str, Any]) -> None:
        with self.lock:
            self.saved[name] = {k: v for k, v in info.items()
                                if isinstance(v, (str, int, float, bool)) or v is None}
            data = {"version": 1, "hosts": self.saved}
            tmp = self.state_path.with_name(f".{self.state_path.name}.{os.getpid()}.tmp")
            try:
                # never the data folder itself: one an uninstall removed stays removed
                self.state_path.parent.mkdir(exist_ok=True)
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(data, f)
                os.replace(tmp, self.state_path)
            except OSError:
                with contextlib.suppress(OSError):
                    tmp.unlink()

    def get(self, name: str) -> RemoteHost:
        with self.lock:
            h = self.hosts.get(name)
            if h is None:
                h = self.hosts[name] = RemoteHost(self, name)
            return h

    def host_id(self, name: str) -> str:
        try:
            return self.d._host_ids([name]).get(name, "")
        except Exception:  # noqa: BLE001
            return ""

    def local_machine(self) -> str:
        """This machine's token (computed once: it reads the hardware id)."""
        if self._local is None:
            try:
                self._local = self.d.machine_id()
            except Exception:  # noqa: BLE001
                return ""
        return self._local

    def resolve(self, host: Any) -> str | None:
        """A form host name from a name, its contract id (m_...) or its
        verified machine token; None when there is no such remote host."""
        from .. import form as formmod
        if not isinstance(host, str) or not host:
            return None
        try:
            f = formmod.load()
        except Exception:  # noqa: BLE001
            return None
        from . import resolve_remote_host
        names = [n for n, h in f.hosts.items() if not h.is_local]
        if host in names:
            return host
        try:
            ids = self.d._host_ids(names)
        except Exception:  # noqa: BLE001
            ids = {}
        with self.lock:
            saved = dict(self.saved)
        # the approval hook resolves with the same function from the same files
        return resolve_remote_host(host, names, ids, saved)

    def owner_session(self, name: str) -> Any:
        if self.owner_lookup is None:
            return None
        try:
            return self.owner_lookup(name)
        except Exception:  # noqa: BLE001
            return None

    def machine_changed(self, name: str, old: str, new: str) -> None:
        if self.on_machine_change is not None:
            with contextlib.suppress(Exception):
                self.on_machine_change(name, old, new)

    def emit_state(self, h: RemoteHost) -> None:
        st = h.status
        with contextlib.suppress(Exception):
            self.d.events.emit("host.state", host=h.host_id or None, name=h.name,
                               state=st.get("runtime"), reachable=st.get("reach"),
                               auth=st.get("auth"), runtime=st.get("runtime"),
                               identity=st.get("identity"))

    def summary(self, name: str) -> dict[str, Any]:
        h = self.hosts.get(name)
        if h is None:
            info = self.saved.get(name) or {}
            out: dict[str, Any] = {"reachable": "unknown", "auth": "unknown",
                                   "identity": "unknown", "runtime": "unknown"}
            if info.get("machine"):
                out["machine"] = info["machine"]
                out["same_machine"] = info["machine"] == self.local_machine()
            if info.get("rt_version"):
                out["runtime_version"] = info["rt_version"]
                out["platform"] = info.get("platform", "")
            return out
        return h.summary()

    def stop(self) -> None:
        with self.lock:
            hosts = list(self.hosts.values())
        for h in hosts:
            h.close()
