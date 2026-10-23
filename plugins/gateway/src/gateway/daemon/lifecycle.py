"""Starting, running and stopping gated.

Started on demand by whoever needs it first: the mod at session.start
(`$.process.run(["sh", launch.sh, "gated", "start"])`), the async SessionStart
hook (`hook-daemon`, so it also runs without mods and in `claude -p`), a
stand-in, the git helper, the MCP server or gate when the vault key is
wrapped (client.py). ensure_running():

  1. GET /health; an answer from the same or a newer version is used (a newer
     daemon serving an older plugin is reported in the answer's "skew").
  2. An older daemon is asked to restart (/local/restart): it stops when it
     holds no terminals or jobs, and the new version starts; otherwise it is
     kept and reported ("old gateway daemon still runs N jobs").
  `gated status` never starts or restarts it and reports any version
  difference with its plugin copy in "skew" (/gate-doctor shows it).
  /health names the data folder the daemon serves ("data"); `gated
  start|status` from another one (a second CLAUDE_CONFIG_DIR) add
  "other_config", the words /gate-doctor shows (planes.other_config_note).
  3. Otherwise, under <run>/gated.start.lock (flock), `run.py gated serve
     --detach` is started and its /health awaited.

serve(): takes <run>/gated.lock (flock, non-blocking: a second daemon exits at
once), detaches (fork, setsid, fork; stdin /dev/null, stdout and stderr to
<data>/gated/gated.log, umask 077), removes a stale socket (the lock proves
its daemon is gone, even after kill -9), writes <run>/gated.pid (its pid and
start time, for its tmux watchdog), listens on <run>/gated.sock (0600),
then writes ~/.config/gateway/run/contract.json (0600, folder 0700) and
emits daemon.started. It exits after IDLE_EXIT with no live registered
session, terminal or job, when its socket is removed (the run dir deleted:
nobody can reach it), when the plugin folder it runs from is gone (an
uninstall, or an update's sweep of the old version folder: `replaced`) or
marked orphaned by Claude Code (`.orphaned_at`: uninstalled, or replaced by
an update; then only once no live session is registered) and it holds no
terminal or job, on SIGTERM/SIGINT or /local/stop:
daemon.stopping, the vault locked, the socket and contract.json (when still
its own) removed, and its tmux server stopped once no terminal or job of it
runs there (Supervisor.stop_server; a live pane keeps the server for the
next gated to re-adopt).

Uninstalled while terminals or jobs still run (its data folder gone, or the
plugin folder gone or orphaned with no other, not orphaned version beside it
and, orphaned, no live session: `uninstalled_reason`), it drains (`drain`):
contract.json goes at once (checkpoint stops delegating), daemon.draining is
emitted, new terminals, jobs, remote runtimes, pauses and a job's STOP or
TSTP are refused, a job left suspended is resumed (no consumer could resume
it any more; a remote one through the host's live master by the system's
ssh, since the env's may be gone), and what runs is left to finish (never
killed); it exits, with its tmux server, once no local terminal or job runs
(remote ones run on in their hosts' runtimes). From the drain on every log
line also goes to <gateway home>/run/gated-drain.log, which an uninstall
keeps (gated.log goes with the data folder).
The plugin folder gone with another version beside it is an update's sweep:
the daemon serves on, as before, until it holds no terminal or job.

The log (<data>/gated/gated.log, the detached daemon's stdout and stderr) is
rotated to gated.log.1 past LOG_MAX, at start and while the daemon runs
(Daemon.log checks the size after each line), so a flood of refused requests
keeps it bounded.

Test overrides: `run.py --test gated ...` with GATEWAY_TEST_ROOT (and
GATEWAY_TEST_RUN for a short run dir) runs everything inside the test root;
<root>/gated-test.json holds the test knobs (idle_exit, tick, lock_after,
test_routes, test_entries, ring, disk_max, log_max, busy, clipboard, tmux,
watch_tick), read only under a test override.
"""
from __future__ import annotations

import base64
import contextlib
import fcntl
import hashlib
import json
import os
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from .. import paths, ssh_conf, testing, vault
from . import (CONTRACT_ID, CONTRACT_VERSIONS, FEATURES, PROTOCOL, plugin_version, skew_text,
               version_key)
from . import broker as brokermod
from . import client, dialogs, events, planes, remote, server, terminals

IDLE_EXIT = 30 * 60
TICK = 30.0
START_WAIT = 10.0
LOG_MAX = 1_000_000
DRAIN_LOG = "gated-drain.log"   # in the gateway home's run/: the draining daemon's log lines
DRAIN_LOG_MAX = 65536
PAUSE_WAIT = 60.0            # drain waits at most this long for the pauses being applied


class StartError(client.DaemonError):
    def __init__(self, message: str):
        super().__init__(0, "start", message)


# ---------------------------------------------------------------------------
# Test knobs
# ---------------------------------------------------------------------------


def knobs() -> dict[str, Any]:
    """<root>/gated-test.json under a test override (a private file of this
    user), else {}."""
    o = testing.active()
    if o is None or o.root is None:
        return {}
    text = paths._read_private_file(Path(o.root) / "gated-test.json", os.getuid())
    if not text:
        return {}
    try:
        k = json.loads(text)
    except ValueError:
        return {}
    return k if isinstance(k, dict) else {}


def _num(k: dict[str, Any], name: str, default: float) -> float:
    v = k.get(name)
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0 else default


# ---------------------------------------------------------------------------
# The client side: ensure_running
# ---------------------------------------------------------------------------


def _daemon_env() -> dict[str, str]:
    """A small, fixed environment for the daemon (never Claude's Bash
    environment: no CLAUDE_*, no stand-in PATH, no credential variables)."""
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(paths.user_home()),
           "LANG": os.environ.get("LANG", "C.UTF-8")}
    tmp = os.environ.get("TMPDIR", "")
    if tmp and os.path.isabs(tmp):
        env["TMPDIR"] = tmp
    o = testing.active()
    if o is not None and o.root is not None and not testing.get("e2e"):
        env["GATEWAY_TEST_ROOT"] = str(o.root)
        if o.run is not None and Path(o.run) != Path(o.root) / "run":
            env["GATEWAY_TEST_RUN"] = str(o.run)
        if o.machine_id:
            env["GATEWAY_TEST_MACHINE_ID"] = str(o.machine_id)
    return env


def daemon_argv() -> list[str]:
    run_py = str(paths.code_root() / "run.py")
    argv = [sys.executable, "-I", "-S", "-X", f"pycache_prefix={paths.pycache_dir()}", run_py]
    o = testing.active()
    if o is not None and o.root is not None and not testing.get("e2e"):
        argv.append("--test")
    return argv + ["gated", "serve", "--detach"]


def _spawn() -> None:
    p = subprocess.Popen(daemon_argv(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, close_fds=True, start_new_session=True,
                         env=_daemon_env(), cwd="/")
    try:
        p.wait(timeout=START_WAIT)
    except subprocess.TimeoutExpired:
        pass


@contextlib.contextmanager
def _start_lock(timeout: float):
    fd = os.open(paths.gated_start_lock(), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise StartError("gateway: another start of the gateway daemon is taking "
                                     "too long") from None
                time.sleep(0.02)
        yield
    finally:
        os.close(fd)


def _wait_health(deadline: float) -> dict[str, Any] | None:
    while time.monotonic() < deadline:
        h = client.health(timeout=1.0)
        if h is not None:
            return h
        time.sleep(0.025)
    return None


def _wait_gone(pid: int, deadline: float) -> None:
    while time.monotonic() < deadline and _pid_alive(pid):
        time.sleep(0.025)


def _pid_alive(pid: Any) -> bool:
    if not isinstance(pid, int) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _skew(h: dict[str, Any], mine: str, *, older: bool = False) -> dict[str, Any]:
    """health with "skew" when the daemon is newer than this plugin (and,
    with older=True, when it is older: `gated status`, which never restarts
    it)."""
    theirs = str(h.get("version") or "0")
    if version_key(theirs) > version_key(mine) or (older and version_key(theirs) < version_key(mine)):
        h = dict(h)
        h["skew"] = skew_text(theirs, mine)
    if h.get("draining"):
        # an uninstalled copy's daemon finishing what runs (Daemon.drain): it
        # still answers, so no other can start, but it takes no new work
        h = dict(h)
        h["skew"] = "; ".join(t for t in (str(h.get("skew") or ""), DRAINING_SKEW) if t)
    return h


DRAINING_SKEW = ("the gateway daemon of an uninstalled copy is finishing its terminals and jobs and "
                 "takes no new ones; a new one starts once they have ended")


UNRESPONSIVE_GRACE = 3.0   # a daemon that took the connection gets this long to answer /health


def _health_or_unresponsive(timeout: float) -> tuple[dict[str, Any] | None, bool]:
    """(/health, False), or (None, True) when a daemon took the connection
    but didn't answer, or (None, False) when none is there."""
    try:
        h = client.call("GET", "/health", timeout=timeout)
    except client.Unresponsive:
        return None, True
    except client.DaemonError:
        return None, False
    return (h if h.get("ok") else None), False


def ensure_running(wait: float = START_WAIT) -> dict[str, Any]:
    """The running daemon's /health, after starting (or restarting an older)
    one if needed. StartError when none answers. A daemon that holds the
    socket but doesn't answer (stopped, hung) gets UNRESPONSIVE_GRACE (it may
    be finishing its start), then StartError: another start would exit at
    once on its instance lock, so waiting `wait` for it would only stall
    every caller (a hook, the mod's session start)."""
    mine = plugin_version()
    deadline = time.monotonic() + wait
    h, unresponsive = _health_or_unresponsive(1.0)
    if h is None and unresponsive:
        h, unresponsive = _health_or_unresponsive(UNRESPONSIVE_GRACE)
        if h is None and unresponsive:
            raise StartError("gateway: the gateway daemon is running but isn't answering (stopped "
                             "or hung); /gate-doctor shows its state")
    if h is not None and version_key(str(h.get("version") or "0")) >= version_key(mine):
        return _skew(h, mine)
    with _start_lock(wait):
        h = client.health(timeout=1.0)
        if h is not None and version_key(str(h.get("version") or "0")) < version_key(mine):
            try:
                r = client.call("POST", "/local/restart", {"version": mine}, timeout=5)
            except client.DaemonError:
                r = {}
            if not r.get("restarting"):
                h = dict(h)
                h["skew"] = str(r.get("message") or f"an older gateway daemon ({h.get('version')}) "
                                "is still running and couldn't be restarted")
                return h
            _wait_gone(int(h.get("pid") or 0), deadline)
            h = None
        if h is not None:
            return _skew(h, mine)
        _spawn()
        h = _wait_health(deadline)
    if h is None:
        raise StartError(f"gateway: the gateway daemon didn't start (its log: "
                         f"{paths.describe(paths.gated_log())})")
    return _skew(h, mine)


def stop(wait: float = 5.0) -> bool:
    """Ask a running daemon to stop; True once it has (or none was running)."""
    h = client.health(timeout=1.0)
    if h is None:
        return True
    try:
        client.call("POST", "/local/stop", {}, timeout=5)
    except client.DaemonError:
        return False
    deadline = time.monotonic() + wait
    pid = int(h.get("pid") or 0)
    while time.monotonic() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.025)
    return not _pid_alive(pid)


# ---------------------------------------------------------------------------
# The daemon
# ---------------------------------------------------------------------------


from . import machine_token  # noqa: E402,F401  (moved to the package: light importers use it)


class Daemon:
    def __init__(self, k: dict[str, Any] | None = None, log_path: Path | None = None):
        self.k = k if k is not None else knobs()
        # the log file stdout and stderr go to (detached), rotated while running
        self.log_path = log_path
        self.log_max = int(_num(self.k, "log_max", LOG_MAX))
        self._log_lock = threading.Lock()
        self.version = plugin_version()
        self.pid = os.getpid()
        self.started = time.time()
        self.t0 = time.monotonic()
        self.idle_exit = _num(self.k, "idle_exit", IDLE_EXIT)
        self.tick_s = _num(self.k, "tick", TICK)
        if testing.get("e2e"):
            # the e2e suite's and the TUI harness's scratch copies: their run
            # dir goes when they finish, and the daemon with it, at once
            self.tick_s = min(self.tick_s, 0.25)
        self.stopping = threading.Event()
        self.stop_reason = ""
        self.vault_mutex = threading.RLock()
        paths.gated_dir().mkdir(parents=True, exist_ok=True)
        os.chmod(paths.gated_dir(), 0o700)
        self.epoch = events.next_epoch(paths.gated_dir() / "epoch")
        self.events = events.EventLog(paths.gated_dir() / "events", self.epoch,
                                      ring=int(_num(self.k, "ring", 2000)),
                                      disk_max=int(_num(self.k, "disk_max", 2_000_000)))
        la = self.k.get("lock_after")
        self.broker = brokermod.Broker(self.events.emit,
                                       lock_after=float(la) if isinstance(la, (int, float)) else None)
        vault._DAEMON_IDENTITY = self.broker.identity      # this process decrypts with it
        self.registry = planes.Registry(
            paths.gated_sessions(),
            on_drop=lambda s: self.events.emit("session.ended", session=s.session_id or None))
        self.dialogs = dialogs.Dialogs(self, paths.gated_dialogs())
        self._ids_lock = threading.Lock()
        self._machine_ids: dict[str, str] | None = None
        # remote hosts (PLAN-v4 phase 6): connections, identity, the runtime
        self.remote = remote.Remotes(self)
        # terminals and jobs (PLAN-v4 phase 5): the tmux supervisor, started in run()
        self.terminals = terminals.Supervisor(self)
        self.registry.pane_session = self.terminals.session_for_pid
        self.remote.owner_lookup = self.terminals.owner_session_for_host
        self.remote.on_machine_change = self.terminals.machine_changed
        self.dialogs.handlers["unlock"] = self._unlock_answer
        self.dialogs.handlers["passphrase"] = self._passphrase_answer
        self.routes = server.routes(bool(self.k.get("test_routes")) and testing.active() is not None)
        if self.k.get("test_entries") and testing.active() is not None:
            testing.active().extra["gated_test_entries"] = True
        clip = self.k.get("clipboard")
        if isinstance(clip, str) and os.path.isabs(clip) and testing.active() is not None:
            testing.active().extra["clipboard"] = clip     # the dialog's paste reads this program
        tmux = self.k.get("tmux")
        if isinstance(tmux, str) and os.path.isabs(tmux) and testing.active() is not None:
            testing.active().extra["tmux"] = tmux          # the supervisor runs this tmux (a test wrapper)
        if testing.active() is not None:
            # the remote runtime's test knobs (PLAN-v4 phase 6, daemon/remote.py):
            # prebuilt fake artifacts (no pixi-pack, no network), a corrupted
            # upload, no hash tool on the host, a full disk, a faster poll, a
            # shorter staleness window for host status, and an ssh wrapper that
            # records its argv (or drops answers)
            for name in ("runtime_artifacts", "remote_corrupt_upload", "remote_no_hash_tool",
                         "remote_df_avail_kb", "remote_tick", "remote_stale", "system_ssh",
                         "exclusive_tools"):
                if self.k.get(name) is not None:
                    testing.active().extra[name] = self.k[name]
            sshw = self.k.get("ssh")
            if isinstance(sshw, str) and os.path.isabs(sshw):
                testing.active().tools["ssh"] = sshw
            # wrappers for the env's tools (with exclusive_tools, removing one is
            # the env losing it: a plain uninstall)
            tw = self.k.get("tools")
            if isinstance(tw, dict):
                testing.active().tools.update({n: v for n, v in tw.items()
                                               if isinstance(v, str) and os.path.isabs(v)})
        self.last_busy = time.monotonic()
        self.server: server.Server | None = None
        # resolved once: paths.run_dir() creates a missing run dir, and a daemon
        # whose run dir was deleted must not make it again
        self.sock_path = paths.gated_socket()
        self.sock_ino: int | None = None
        # the plugin folder this code runs from (never an override): its removal stops the daemon
        self.code_root = paths.code_root()
        # the plugin's data folder (its env, with this python and the env's tmux; the records;
        # this log): a plain `claude plugin uninstall` deletes it
        self.data_root = paths.data_dir()
        # why the daemon takes no new work ("" while it serves): the plugin was uninstalled
        # while terminals or jobs still ran (drain)
        self.draining = ""
        # where the draining daemon's log lines also go (the gateway home's run/,
        # which an uninstall keeps; resolved now: nothing is imported later)
        self.drain_dir = paths.contract_dir()
        self._drain_logged = False
        # this daemon's pid and start time for its tmux watchdog (write_pid)
        self.pid_path = paths.gated_pid()
        # the pauses being applied right now (pause_begin): drain waits for them, so
        # a job one suspends is resumed with the rest; none starts once draining
        self._pause_cv = threading.Condition()
        self._pauses = 0

    # -- facts -----------------------------------------------------------------
    def log(self, line: str) -> None:
        with self._log_lock:
            stamped = f"{time.strftime('%Y-%m-%dT%H:%M:%S')} gated[{self.pid}] {line}\n"
            try:
                sys.stderr.write(stamped)
                sys.stderr.flush()
            except (OSError, ValueError):
                pass
            if getattr(self, "draining", ""):
                self._drain_note(stamped)
            self._rotate_if_big()

    def _drain_note(self, stamped: str) -> None:
        """While draining, each log line also goes to <gateway home>/run/
        gated-drain.log (0600, started over at a drain's first line, at most
        DRAIN_LOG_MAX): a plain uninstall deleted gated.log with the data
        folder, and this folder (where contract.json was) stays, so what the
        draining daemon waits for, what it resumed and when it left can still
        be read. Never makes a folder (a gateway home deleted too gets nothing)."""
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
        if not self._drain_logged:
            flags |= os.O_TRUNC
        try:
            if not self.drain_dir.is_dir():
                return
            fd = os.open(self.drain_dir / DRAIN_LOG, flags, 0o600)
        except OSError:
            return
        self._drain_logged = True
        try:
            if os.fstat(fd).st_size < DRAIN_LOG_MAX:
                os.write(fd, stamped.encode("utf-8", "replace"))
        except OSError:
            pass
        finally:
            os.close(fd)

    def _rotate_if_big(self) -> None:
        """Past log_max the log becomes gated.log.1 (replacing an older one)
        and a new gated.log takes stdout and stderr: one daemon that refuses
        requests all day keeps at most two files of about log_max."""
        p = self.log_path
        if p is None:
            return
        try:
            if os.fstat(2).st_size <= self.log_max:
                return
        except OSError:
            return
        try:
            os.replace(p, p.with_name(p.name + ".1"))
        except OSError:
            pass                              # gone already: a new one is opened anyway
        try:
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        except OSError:
            return
        try:
            os.dup2(fd, 1)
            os.dup2(fd, 2)
        finally:
            os.close(fd)

    def busy(self) -> str:
        """What keeps the daemon from a restart or an idle exit: its live
        terminals and jobs ("2 terminals and 1 job"; "" when none). A test
        knob can stand in for them."""
        b = self.k.get("busy") if testing.active() is not None else None
        if isinstance(b, str) and b:
            return b
        return self.terminals.busy()

    def health(self) -> dict[str, Any]:
        live = self.registry.count()
        h = {"ok": True, "version": self.version, "protocol": PROTOCOL, "pid": self.pid,
             "epoch": self.epoch, "started": round(self.started, 3),
             "uptime": round(time.monotonic() - self.t0, 1), "vault": self.broker.state(),
             "sessions": live, "socket": str(self.sock_path),
             "lock_after": int(self.broker.lock_after()), "dialogs": self.dialogs.count(),
             # the data folder it serves (its python's): a second Claude Code
             # configuration's `gated status` says it isn't theirs (planes.other_config_note)
             "data": str(paths.data_dir()),
             **self.terminals.counts()}
        if self.draining:
            h["draining"] = self.draining
        return h

    def locked_message(self, peer: Any) -> str:
        """The locked refusal for the caller's session: in one where a gateway
        dialog can open (the mod registered it, on a terminal or the desktop
        app) the unlock dialog opens there now; a session without one (claude
        -p, mods off, mobile, VS Code) can't unlock."""
        s = self.registry.ancestor_session(peer.pid) if peer is not None else None
        if s is not None and self.dialogs.available(s)[0]:
            try:
                r = self.vault_dialog(s)
            except Exception:  # noqa: BLE001 - the refusal stands either way
                r = {}
            if r.get("available"):
                return server.LOCKED_INTERACTIVE
        return server.LOCKED_HEADLESS

    # -- the vault's dialogs (unlock; set a passphrase) --------------------------
    UNLOCK_LINES = ["The gateway vault is locked. Type its passphrase to unlock it.",
                    "It unlocks the vault on this computer only; Claude never sees what you type."]
    SET_LINES = ["Set a passphrase for the gateway vault (at least 12 characters).",
                 "The vault key is then kept encrypted with it (age's scrypt), and only the "
                 "gateway daemon holds it unlocked; you type it again after a restart, a lock "
                 "(/gate-lock) or 8 hours without use.",
                 "A forgotten passphrase can't be recovered: the vault would have to be set "
                 "up again.",
                 "Type it in both fields. Claude never sees what you type."]

    def vault_dialog(self, session: Any) -> dict[str, Any]:
        """Open the unlock dialog (wrapped and locked) or the set-a-passphrase
        dialog (unwrapped) in `session`; or say why neither applies."""
        state = self.broker.state()
        if state == "locked":
            return self.dialogs.open_vault(session, "unlock", {
                "title": "Unlock the gateway vault", "entry": "vault", "what": "vault passphrase",
                "lines": self.UNLOCK_LINES, "ok_label": "Unlock"})
        if state == "unwrapped":
            return self.dialogs.open_vault(session, "passphrase", {
                "title": "Set a vault passphrase", "entry": "vault", "what": "new vault passphrase",
                "lines": self.SET_LINES, "ok_label": "Set passphrase"})
        if state == "unlocked":
            return {"ok": True, "available": False, "reason": "unlocked",
                    "message": "gateway: the vault is unlocked already (/gate-lock locks it)"}
        return {"ok": True, "available": False, "reason": "none",
                "message": "gateway: there is no vault yet (it is made when the first credential "
                           "is stored)"}

    def _unlock_answer(self, r: Any, values: list[str]) -> tuple[bool, str]:
        if self.broker.state() != "locked":
            return True, "the vault was unlocked already"
        try:
            self.broker.unlock(values[0], how="dialog")
        except brokermod.BrokerError as e:
            return False, str(e).removeprefix("gateway: ")
        return True, "the vault is unlocked"

    def _passphrase_answer(self, r: Any, values: list[str]) -> tuple[bool, str]:
        if self.broker.mode() != "unwrapped":
            return True, "the vault key has a passphrase already"
        try:
            self.broker.set_passphrase(values[0])
        except brokermod.BrokerError as e:
            return False, str(e).removeprefix("gateway: ")
        return True, "the vault key has a passphrase now"

    def effective(self, touch: bool = False) -> Any:
        """The effective rights (consent) for the direct rule, policy
        decisions and snapshots; None if unreadable. Reading for these never
        counts as a use of the vault (touch=False), so a consumer polling
        the snapshot can't keep an idle vault unlocked."""
        from .. import consent
        from .. import form as formmod
        try:
            data = self.broker.read(touch=touch) if paths.vault_path().exists() else vault.empty()
            f = formmod.load(last_good=data.get("form_last_good"))
            return consent.compute(f, data)
        except Exception:  # noqa: BLE001
            return None

    def machine_id(self) -> str:
        raw = vault.machine_id() or f"host:{socket.gethostname()}"
        return machine_token(raw)

    def _host_ids(self, names: list[str]) -> dict[str, str]:
        """Stable ids for the form's remote hosts, assigned on first sight and
        kept in <data>/gated/machine-ids.json (verified machine identity comes
        with PLAN-v4 phase 7)."""
        with self._ids_lock:
            return self._host_ids_locked(names)

    def _host_ids_locked(self, names: list[str]) -> dict[str, str]:
        p = paths.gated_dir() / "machine-ids.json"
        if self._machine_ids is None:
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
                self._machine_ids = {str(k): str(v) for k, v in raw.items()} \
                    if isinstance(raw, dict) else {}
            except (OSError, ValueError):
                self._machine_ids = {}
        changed = False
        for n in names:
            if n not in self._machine_ids:
                self._machine_ids[n] = "m_" + base64.b32encode(os.urandom(17)).decode().lower()[:26]
                changed = True
        if changed:
            tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
            try:
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(self._machine_ids, f)
                os.replace(tmp, p)
            except OSError:
                pass
        return self._machine_ids

    def hosts(self) -> list[dict[str, Any]]:
        """The form's hosts for CONTRACT-v1 snapshots: id, name, local, the
        first address (as the form spells it; never a credential); since
        PLAN-v4 phase 6 a remote host's verified machine token, whether it is
        this very machine, and its reachability, authentication and runtime
        readiness (daemon/remote.py)."""
        from .. import form as formmod
        try:
            f = formmod.load()
        except Exception:  # noqa: BLE001
            return []
        names = [n for n, h in f.hosts.items() if not h.is_local]
        ids = self._host_ids(names)
        eff = self.effective()
        if eff is None:
            from .. import consent
            try:
                eff = consent.compute(f, None)
            except Exception:  # noqa: BLE001
                eff = None
        out = []
        for n, h in f.hosts.items():
            local = h.is_local
            try:
                a = h.addresses()
                addr = a[0].render() if a else ""
            except Exception:  # noqa: BLE001
                addr = ""
            rec = {"host": self.machine_id() if local else ids.get(n, ""), "name": n,
                   "local": local, "address": addr,
                   "identity": "machine" if local else "assigned"}
            if local:
                rec["runtime"] = "ready" if paths.env_ready() else "missing"
            else:
                s = self.remote.summary(n)
                if s.get("machine"):
                    rec["identity"] = "verified"
                    rec["machine"] = s["machine"]
                    rec["same_machine"] = bool(s.get("same_machine"))
                rec.update({"reachable": s.get("reachable"), "auth": s.get("auth"),
                            "runtime": s.get("runtime")})
                if s.get("runtime_version"):
                    rec["runtime_version"] = s["runtime_version"]
                    rec["platform"] = s.get("platform")
            if eff is not None:
                # PLAN-v4 phase 7: each action's effective decision (policy.py)
                from .. import policy
                try:
                    rec["rights"] = policy.rights(eff, n)
                except Exception:  # noqa: BLE001
                    pass
            out.append(rec)
        return out

    def accounts(self) -> list[dict[str, Any]]:
        """The form's accounts with their adapter state as the vault knows it
        (adapters.summary: no network, never a value) and their policy
        decisions, for CONTRACT-v1 snapshots and /gate-accounts; a state that
        changed since the last look is published as `account.state`."""
        from .. import adapters, policy
        try:
            data = self.broker.read(touch=False) if paths.vault_path().exists() else vault.empty()
        except Exception:  # noqa: BLE001 - locked: names and kinds only
            data = None
        eff = self.effective()
        try:
            from .. import form as formmod
            f = formmod.load(last_good=(data or {}).get("form_last_good"))
        except Exception:  # noqa: BLE001
            return []
        if data is None:
            rows = [{"account": n, "kind": a.kind, "state": "unknown",
                     "detail": "the vault is locked"} for n, a in f.accounts.items()]
        else:
            rows = adapters.summary(f, data)
        out = []
        seen = getattr(self, "_acct_states", {})
        now: dict[str, str] = {}
        for r in rows:
            rec = {"account": r["account"], "kind": r["kind"], "state": r["state"],
                   **({"checked_at": r["checked_at"]} if r.get("checked_at") else {}),
                   **{k: r[k] for k in ("login", "credential", "expires_at") if r.get(k)}}
            if eff is not None and r["account"] in eff.accounts:
                try:
                    rec["rights"] = policy.account_rights(eff, r["account"])
                except Exception:  # noqa: BLE001
                    pass
            now[r["account"]] = r["state"]
            if seen and seen.get(r["account"]) != r["state"]:
                self.events.emit("account.state", account=r["account"], state=r["state"])
            out.append(rec)
        self._acct_states = now
        return out

    def watch_rights(self) -> None:
        """CONTRACT-v1 `rights.changed` and `account.state` (PLAN-v4 phase 7):
        each entry's effective decisions compared with the last tick's; a
        rise is a widening the person approved, a fall a narrowing, a gone
        entry removed. Never a value, only names and words."""
        from .. import consent, policy
        try:
            eff = self.effective()
            if eff is None:
                return
            now: dict[str, int] = {}
            for n in eff.hosts:
                now[n] = sum(consent.RANK.get({"allow": True, "ask": "ask"}.get(v, False), 0)
                             for v in policy.rights(eff, n).values())
            for n in eff.accounts:
                now[n] = sum(consent.RANK.get({"allow": True, "ask": "ask"}.get(v, False), 0)
                             for v in policy.account_rights(eff, n).values())
            before = getattr(self, "_rights_seen", None)
            if before is not None:
                for n, v in now.items():
                    if n in before and before[n] != v:
                        self.events.emit("rights.changed", entry=n,
                                         change="widened" if v > before[n] else "narrowed")
                for n in before:
                    if n not in now:
                        self.events.emit("rights.changed", entry=n, change="removed")
            self._rights_seen = now
            self.accounts()
        except Exception as e:  # noqa: BLE001 - an event is never worth a crash
            self.log(f"rights watch failed: {type(e).__name__}")

    def ui_manage(self) -> dict[str, Any]:
        """What /gate-hosts and /gate-accounts show (the UI plane): hosts with
        their state (local or remote, reachable, auth, runtime readiness) and
        each action's decision, their workspaces, and the accounts with their
        state; nothing secret."""
        hosts = self.hosts()
        eff = self.effective()
        pending: dict[str, list[str]] = {}
        if eff is not None:
            for c in eff.pending:
                pending.setdefault(c.entry, []).append(c.what)
        for h in hosts:
            h["pending"] = pending.get(h.get("name", ""), [])[:20]
            if eff is not None and h.get("name") in eff.form.hosts:
                fh = eff.form.hosts[h["name"]]
                h["user"] = fh.user() if not fh.is_local else ""
        accts = self.accounts()
        for a in accts:
            a["pending"] = pending.get(a["account"], [])[:20]
        return {"ok": True, "hosts": hosts, "workspaces": self.workspaces(), "accounts": accts,
                "settings_pending": pending.get("settings", [])[:20]}

    def workspaces(self) -> list[dict[str, Any]]:
        """The approved workspaces for CONTRACT-v1 snapshots (PLAN-v4 phase
        7): id (bound to the host's id and the root), name, host, root, and
        the local folder of a path mapping."""
        from . import workspace_id
        eff = self.effective()
        if eff is None:
            return []
        out = []
        names = [n for n, h in eff.form.hosts.items() if not h.is_local]
        ids = self._host_ids(names)
        for hn, eh in eff.hosts.items():
            hid = self.machine_id() if hn == "localhost" else ids.get(hn, "")
            if not hid:
                continue
            for wn, ew in eh.workspaces.items():
                rec = {"workspace": workspace_id(hid, ew.root), "name": wn, "host": hid,
                       "host_name": hn, "root": ew.root}
                if ew.local:
                    rec["local"] = ew.local
                out.append(rec)
        return out

    # -- running ---------------------------------------------------------------
    def stop_soon(self, reason: str) -> None:
        if self.stopping.is_set():
            return
        self.stop_reason = reason
        self.stopping.set()
        self.events.emit("daemon.stopping", reason=reason)

        def _down() -> None:
            time.sleep(0.05)                  # let the answer go out first
            if self.server is not None:
                self.server.shutdown()
        threading.Thread(target=_down, daemon=True).start()

    def socket_gone(self) -> bool:
        """The socket was removed or replaced (the run dir deleted, another
        daemon after this one lost its lock): nobody can reach this one."""
        try:
            return os.lstat(self.sock_path).st_ino != self.sock_ino
        except OSError:
            return True

    # The plugin folder this daemon's code runs from going away: it must stop
    # advertising the contract. Removed: it can't load the rest of its code or
    # start its helpers (checked first in a tick, before anything that might
    # import). Marked orphaned by Claude Code (`.orphaned_at`: `claude plugin
    # uninstall`, or an update that replaced this version; the folder stays
    # until Claude Code sweeps it): once no live session is registered (a
    # session still running this version keeps it, or its next hook would
    # start it again from here).
    def plugin_removed(self) -> bool:
        return not (self.code_root / "run.py").is_file()

    def data_removed(self) -> bool:
        """The plugin's data folder is gone: a plain `claude plugin uninstall`
        deletes it, with the env this python and the env's tmux run from."""
        return not self.data_root.is_dir()

    def plugin_orphaned(self, live: int) -> bool:
        return live == 0 and (self.code_root / ".orphaned_at").exists()

    def newer_sibling(self) -> bool:
        """Another, not orphaned version folder beside this one in Claude
        Code's plugin cache: an update (its sessions use this daemon until it
        is free), not an uninstall."""
        try:
            for d in self.code_root.parent.iterdir():
                if d != self.code_root and (d / "run.py").is_file() and \
                        not (d / ".orphaned_at").exists():
                    return True
        except OSError:
            pass
        return False

    def replaced(self) -> bool:
        """The folder this daemon's code runs from is gone, but another, not
        orphaned version is installed beside it: Claude Code swept an update's
        old version folder (2.1.301 does 14 days after marking it, unless a live
        session uses it) while this daemon still serves its terminals or jobs.
        An update, not an uninstall: it serves on (contract.json kept, new work
        taken, as 0.9.0 did) and exits once it holds no terminal or job, so the
        newer version's sessions start their own daemon then."""
        return self.plugin_removed() and self.newer_sibling()

    def busy_here(self) -> str:
        """The local terminals and jobs (a draining daemon waits for these;
        remote ones run on in their hosts' runtimes without it)."""
        b = self.k.get("busy") if testing.active() is not None else None
        if isinstance(b, str) and b:
            return b
        return self.terminals.busy(local_only=True)

    def drain(self, why: str) -> None:
        """The plugin was uninstalled while terminals or jobs still run: stop
        advertising the contract at once, take no new work, and leave what
        runs to finish (never killed); the ticker exits once nothing does.
        One way: a draining daemon never serves new work again. With the
        contract gone no consumer can lift a pause any more: what a pause
        suspended is resumed (after the pauses being applied right now), and a
        new pause is refused (pause_begin)."""
        with self._pause_cv:
            if self.draining:
                return
            self.draining = why
            self._pause_cv.wait_for(lambda: self._pauses <= 0, timeout=PAUSE_WAIT)
        # nothing new is written into a data folder an uninstall removed (a lazy
        # import's bytecode under pycache_prefix would make it again)
        sys.dont_write_bytecode = True
        self.remove_contract()
        # the env's ssh may be gone with the data folder: a remote job left
        # suspended is then resumed through the live master by the system's ssh
        # (ssh_conf.allow_system_ssh)
        ssh_conf.allow_system_ssh()
        try:
            resumed = self.terminals.resume_stopped()
        except Exception as e:  # noqa: BLE001 - the drain goes on
            self.log(f"terminals: resuming the suspended jobs failed ({type(e).__name__})")
            resumed = []
        c = self.terminals.counts(local_only=True)
        self.events.emit("daemon.draining", reason="uninstalled", terminals=c["terminals"],
                         jobs=c["jobs"], resumed=len(resumed))
        self.log(f"{why}: taking no new work and advertising no contract; still running, left to "
                 f"finish: {self.busy_here() or 'nothing'}; the daemon exits once they have ended"
                 + (f"; resumed what a pause or a stop had suspended ({len(resumed)} job(s)): nothing "
                    "could resume it any more" if resumed else ""))

    def pause_begin(self) -> bool:
        """A pause (/v1/pause) is about to apply: False once draining (the
        contract is gone, so nothing could resume what it suspends: refused).
        Each True is followed by pause_end()."""
        with self._pause_cv:
            if self.draining:
                return False
            self._pauses += 1
            return True

    def pause_end(self) -> None:
        with self._pause_cv:
            self._pauses -= 1
            self._pause_cv.notify_all()

    def uninstalled_reason(self, live: int | None) -> str:
        """Why the plugin this daemon runs from counts as uninstalled, or "".
        `live` None: only the checks that read no state (the first in a tick).
        A code folder removed while another version is installed beside it is
        an update's sweep, not an uninstall (`replaced`)."""
        if self.plugin_removed() and not self.newer_sibling():
            return "the plugin folder it runs from is gone and no other version is installed (uninstalled)"
        if self.data_removed():
            return "the plugin's data folder is gone (uninstalled)"
        if live is not None and self.plugin_orphaned(live) and not self.newer_sibling():
            return "the plugin folder it runs from is orphaned (uninstalled) and no session uses it"
        return ""

    def _ticker(self) -> None:
        while not self.stopping.wait(self.tick_s):
            try:
                if self.socket_gone():
                    self.log("the socket is gone: exiting")
                    self.stop_soon("socket gone")
                    return
                # checked first, before anything that might import from the
                # removed folders
                why = self.uninstalled_reason(None)
                if why and not self.draining:
                    if not self.busy():
                        self.log(f"{why}: exiting")
                        self.stop_soon("plugin removed")
                        return
                    self.drain(why)
                if self.draining:
                    self.broker.tick()
                    self.registry.prune()
                    self.dialogs.tick()
                    if not self.busy_here():
                        self.log(f"{self.draining}; nothing runs any more: exiting")
                        self.stop_soon("plugin removed")
                        return
                    continue
                # an update's old version folder swept while this daemon runs
                # from it: it serves on for what runs, and leaves once nothing does
                replaced = self.replaced()
                if replaced and not self.busy():
                    self.log("the plugin folder it runs from is gone, replaced by an update (another "
                             "version is installed beside it), and nothing runs: exiting")
                    self.stop_soon("plugin removed")
                    return
                self.broker.tick()
                if not replaced:
                    self.watch_rights()          # it imports from the code folder
                live = self.registry.prune()
                if self.plugin_orphaned(live) and not self.busy():
                    self.log("the plugin folder it runs from is orphaned (uninstalled or replaced) and "
                             "no session uses it: exiting")
                    self.stop_soon("plugin removed")
                    return
                why = self.uninstalled_reason(live)
                if why:
                    self.drain(why)
                    continue
                self.dialogs.tick()
                if live or self.busy():
                    self.last_busy = time.monotonic()
                elif time.monotonic() - self.last_busy >= self.idle_exit:
                    self.log(f"no live session for {int(self.idle_exit)} s: exiting")
                    self.stop_soon("idle")
            except Exception as e:  # noqa: BLE001 - the ticker never dies
                self.log(f"tick failed: {type(e).__name__}")

    def write_contract(self) -> None:
        d = paths.contract_dir()
        d.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(d, 0o700)
        doc = {"contract": CONTRACT_ID, "versions": list(CONTRACT_VERSIONS),
               "gateway_version": self.version, "socket": str(self.sock_path),
               "pid": self.pid, "started": round(self.started, 3), "epoch": self.epoch,
               "machine_id": self.machine_id(), "features": list(FEATURES)}
        p = paths.contract_path()
        tmp = p.with_name(f".{p.name}.{self.pid}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
        os.replace(tmp, p)

    def remove_contract(self) -> None:
        p = paths.contract_path()
        try:
            doc = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(doc, dict) and doc.get("pid") == self.pid:
            with contextlib.suppress(OSError):
                p.unlink()

    def bind(self) -> None:
        sock = self.sock_path
        try:
            st = os.lstat(sock)
            if stat.S_ISSOCK(st.st_mode) or stat.S_ISLNK(st.st_mode) or st.st_size == 0:
                os.unlink(sock)               # stale: the instance lock says its daemon is gone
        except FileNotFoundError:
            pass
        server.Handler.daemon = self
        old = os.umask(0o077)
        try:
            self.server = server.Server(str(sock), server.Handler)
        finally:
            os.umask(old)
        os.chmod(sock, 0o600)
        self.sock_ino = os.lstat(sock).st_ino

    def unbind(self) -> None:
        sock = self.sock_path
        try:
            if self.sock_ino is not None and os.lstat(sock).st_ino == self.sock_ino:
                os.unlink(sock)
        except OSError:
            pass

    def write_pid(self) -> None:
        """<run>/gated.pid: `<pid> <start time>` (ps's lstart as the tmux
        watchdog reads it: terminals.ps_start), written whole before the
        socket is bound, so the file names this daemon by the time its socket
        replaces a killed one's. The watchdog tells a killed gated (its socket
        left behind) from a live one by it (terminals.WATCH_SCRIPT)."""
        p = self.pid_path
        start = terminals.ps_start(self.pid)
        tmp = p.with_name(f".{p.name}.{self.pid}.tmp")
        try:
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(f"{self.pid} {start}".rstrip() + "\n")
            os.replace(tmp, p)
        except OSError as e:
            self.log(f"can't write the pid file ({type(e).__name__})")
            # a killed predecessor's file would make the watchdog take this daemon
            # for gone; without one it watches the socket alone
            for q in (tmp, p):
                with contextlib.suppress(OSError):
                    q.unlink()

    def remove_pid(self) -> None:
        p = self.pid_path
        try:
            if p.read_text(encoding="utf-8").split()[:1] == [str(self.pid)]:
                p.unlink()
        except (OSError, ValueError):
            pass

    def run(self) -> int:
        self.write_pid()
        self.bind()
        self.write_contract()
        self.events.emit("daemon.started", version=self.version, pid=self.pid)
        self.log(f"started: version {self.version}, epoch {self.epoch}, vault {self.broker.state()}")
        try:
            self.terminals.start()
        except Exception as e:  # noqa: BLE001 - terminals unavailable; the rest serves on
            self.log(f"terminals: not started ({type(e).__name__})")
        t = threading.Thread(target=self._ticker, daemon=True)
        t.start()
        assert self.server is not None
        try:
            self.server.serve_forever(poll_interval=0.25)
        finally:
            if not self.stopping.is_set():
                self.stop_reason = self.stop_reason or "exit"
                self.stopping.set()
                self.events.emit("daemon.stopping", reason=self.stop_reason)
            self.terminals.stop()
            self.remote.stop()
            if self.stop_reason == "socket gone":
                self.terminals.abandon()
            self.broker.lock("exit")
            self.remove_contract()
            self.unbind()
            self.remove_pid()
            with contextlib.suppress(Exception):
                self.server.server_close()
            if self.stop_reason != "socket gone":
                # its tmux server and watchdog go too once no terminal or job runs
                # there (a live pane keeps them for the next gated to re-adopt;
                # still under the instance lock, so no new gated uses that server yet)
                try:
                    self.terminals.stop_server()
                except Exception as e:  # noqa: BLE001 - the exit goes on
                    self.log(f"terminals: stopping the tmux server failed ({type(e).__name__})")
            self.events.close()
            self.log(f"stopped ({self.stop_reason})")
        return 0


def _rotate_log(p: Path) -> None:
    try:
        if p.stat().st_size > LOG_MAX:
            os.replace(p, p.with_name(p.name + ".1"))
    except OSError:
        pass


def _detach(log: Path) -> bool:
    """Double fork and setsid; True in the daemon, False in the caller."""
    if os.fork() > 0:
        return False
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    os.umask(0o077)
    os.chdir("/")
    _rotate_log(log)
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    null = os.open(os.devnull, os.O_RDONLY)
    os.dup2(null, 0)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    os.close(null)
    os.close(fd)
    return True


def serve(detach: bool = False) -> int:
    """`run.py gated serve [--detach]`: the daemon (see the module docstring)."""
    paths.run_dir()
    lock_fd = os.open(paths.gated_lock(), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(lock_fd)
        print("gateway: the gateway daemon is already running", file=sys.stderr)
        return 0
    if detach:
        paths.gated_dir().mkdir(parents=True, exist_ok=True)
        if not _detach(paths.gated_log()):
            os.close(lock_fd)                 # the daemon holds the lock now
            os._exit(0)
    d = Daemon(log_path=paths.gated_log() if detach else None)
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_a: d.stop_soon("signal"))
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    try:
        return d.run()
    finally:
        vault._DAEMON_IDENTITY = None
        os.close(lock_fd)


def _run_dir_refused(e: paths.PathError) -> dict[str, Any]:
    """`gated start|status` when the run folder can't be used (another user's,
    a link, open to others): its own explanation and remedy for /gate-doctor
    (GW-ROB-1), never a traceback."""
    return {"ok": False, "running": False, "error": "run_dir",
            "message": f"gateway: {paths.explain(e)}"}


def _parent_facts(ppid: int) -> dict[str, Any]:
    """What `gated start|status` says about the process that ran it (the mod
    runs them through $.process.run, and launch.sh execs Python, so that is
    the Claude Code process when the engine starts children directly):
    parent_pid when it is a Claude Code process (the daemon checks the claim
    against the kernel's peer pid either way), claude_install (how it was
    installed, for /gate-doctor; "" when it isn't recognized as Claude Code)
    and, then, parent_exe (its executable's name, so the doctor can say what
    asked); and this machine's platform (sys.platform)."""
    from . import peers
    # platform: the mod has no other way to know it is on Linux, where Paste
    # needs a display (DISPLAY or WAYLAND_DISPLAY; review round 2)
    out: dict[str, Any] = {"claude_install": peers.claude_install(ppid), "platform": sys.platform}
    if out["claude_install"]:
        out["parent_pid"] = ppid
    else:
        out["parent_exe"] = os.path.basename(peers.exe(ppid) or "")[:64]
    return out


def main(args: list[str]) -> int:
    """run.py gated serve [--detach] | start [--register] | status | stop."""
    sub = args[0] if args else "status"
    if sub == "serve":
        return serve(detach="--detach" in args[1:])
    if sub == "start":
        try:
            h = ensure_running()
        except client.DaemonError as e:
            print(json.dumps({"ok": False, "message": e.message}))
            return 1
        except paths.PathError as e:
            print(json.dumps(_run_dir_refused(e), sort_keys=True))
            return 1
        out = dict(h)
        note = planes.other_config_note(out)
        if note:
            out["other_config"] = note
        # The mod runs `launch.sh gated start` through $.process.run; launch.sh
        # execs Python, so the parent is the Claude Code process the mod runs in
        # when the engine starts children directly (named only when it is a
        # Claude Code executable; the daemon checks the claim against the
        # kernel's peer pid either way).
        out.update(_parent_facts(os.getppid()))
        if "--register" in args[1:]:
            try:
                r = client.call("POST", "/agent/register",
                                {"session_id": os.environ.get("CLAUDE_CODE_SESSION_ID", "")})
                out["registered"] = r.get("registered")
            except client.DaemonError as e:
                out["registered"] = None
                out["register_error"] = e.code
        print(json.dumps(out, sort_keys=True))
        return 0
    if sub == "status":
        # never starts or restarts the daemon; a version difference with this
        # plugin copy is reported either way (/gate-doctor shows it)
        try:
            h = client.health(timeout=2.0)
            out = (_skew(h, plugin_version(), older=True) if h is not None
                   else {"ok": False, "running": False, "socket": str(paths.gated_socket())})
            note = planes.other_config_note(out) if h is not None else ""
            if note:
                out = {**out, "other_config": note}
        except paths.PathError as e:
            out = _run_dir_refused(e)
        out.update(_parent_facts(os.getppid()))
        print(json.dumps(out, sort_keys=True))
        return 0
    if sub == "stop":
        ok = stop()
        print(json.dumps({"ok": ok}))
        return 0 if ok else 1
    print("usage: run.py gated serve [--detach] | start [--register] | status | stop",
          file=sys.stderr)
    return 2
