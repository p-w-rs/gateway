"""Guards and hermetic environments shared by every part of the TUI harness.

Everything the harness starts (claude in a PTY, `claude plugin ...`, the fake
API, the git server) gets its environment from `hermetic_env`, and every
directory it hands to Claude Code as CLAUDE_CONFIG_DIR passes `check_scratch`
first. The rules this module enforces:

* The real Claude config (~/.config/claude, ~/.claude), the real gateway home
  (~/.config/gateway) and the real checkpoint state (~/.local/state/checkpoint)
  are never used as a config dir, HOME, TMPDIR or data root. "Real" is taken
  from the password database, not $HOME, so a test that already moved $HOME
  is still checked against the person's actual home.
* Scratch paths must sit under a temp base: tempfile.gettempdir(), /tmp,
  /private/tmp, /var/folders, /private/var/folders, or a base listed in
  $TUI_HARNESS_SCRATCH_BASES (os.pathsep separated).
* The child environment is built from an allowlist (PATH, locale, USER, SHELL
  and a few platform variables) plus what the harness sets, so no CLAUDE_*,
  ANTHROPIC_*, OTEL_*, proxy, token or ssh-agent variable of the caller leaks
  into a test session. ANTHROPIC_BASE_URL stays a loopback URL and
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC stays 1, except when all of the
  session's traffic goes to the harness's own record-only proxy (proxy.py:
  TUI_RECORD_PROXY, HTTPS_PROXY and HTTP_PROXY name one loopback URL), which
  answers everything itself: telemetry is on then and still never leaves.
* The plugins' state roots (CHECKPOINT_HOME, CHECKPOINT_GATEWAY_ENV,
  CHECKPOINT_GATEWAY_CONTRACT, GATEWAY_TEST_ROOT, XDG_*) are scratch paths
  under one state root per Claude config (state_root_for), so a restart sees
  the same plugin state; the ones checkpoint would otherwise take from the
  real home must stay set.

Nothing here reads, lists or stats the protected directories; it only
compares paths (their parents are resolved, never they themselves).
"""
from __future__ import annotations

import hashlib
import os
import pwd
import signal
import subprocess
import tempfile
import time
from pathlib import Path

# Variables copied from the caller's environment (when set).
ALLOW_ENV = (
    "PATH", "USER", "LOGNAME", "SHELL", "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
    "TZ", "__CF_USER_TEXT_ENCODING", "SYSTEMROOT", "COMSPEC",
)
FAKE_API_KEY = "sk-ant-api03-" + "f" * 80 + "-fakeAA"


class UnsafePath(RuntimeError):
    """A path the harness was asked to use is (or is inside) a protected location."""


def real_home() -> Path:
    """The person's home from the password database (ignores $HOME)."""
    try:
        return Path(pwd.getpwuid(os.getuid()).pw_dir)
    except KeyError:  # pragma: no cover
        return Path(os.path.expanduser("~"))


def protected_paths() -> list[Path]:
    """Locations no harness path may equal, contain or sit under.

    Only their parents are resolved (realpath stats each component), so the
    protected directories themselves, ~/.config/gateway above all, are never
    touched, not even by a stat."""
    h = real_home()

    def res(parent: Path, name: str) -> Path:
        return Path(os.path.realpath(parent)) / name

    return [res(h / ".config", "claude"), res(h, ".claude"), res(h, ".claude.json"),
            res(h / ".config", "gateway"), res(h / ".local" / "state", "checkpoint")]


def _real(p: os.PathLike | str) -> Path:
    return Path(os.path.realpath(os.path.abspath(os.fspath(p))))


def _within(p: Path, base: Path) -> bool:
    return p == base or base in p.parents


def overlaps_protected(path: os.PathLike | str) -> bool:
    """True if `path` (made absolute, not resolved) equals, contains or sits
    under a protected location. Pure path arithmetic: nothing is stat'ed."""
    p = Path(os.path.abspath(os.fspath(path)))
    return any(_within(p, pr) or _within(pr, p) for pr in protected_paths())


def is_under(path: os.PathLike | str, base: os.PathLike | str) -> bool:
    """True when `path` is `base` or inside it (both resolved). For scratch
    paths only: resolving stats every component."""
    return _within(_real(path), _real(base))


def scratch_bases(resolved: bool = True) -> list[Path]:
    bases = [tempfile.gettempdir(), "/tmp", "/private/tmp", "/var/folders", "/private/var/folders"]
    extra = os.environ.get("TUI_HARNESS_SCRATCH_BASES", "")
    bases += [b for b in extra.split(os.pathsep) if b]
    if not resolved:
        return [Path(os.path.abspath(b)) for b in bases]
    return [_real(b) for b in bases if os.path.isdir(b)]


def check_scratch(path: os.PathLike | str, what: str = "path") -> Path:
    """Return the resolved `path` if it is a safe scratch location, else raise.

    Safe means: under a temp base (see module doc), not a temp base itself,
    and neither equal to, inside, nor containing a protected location. The
    path is compared as written first and resolved only once it is known to
    lie under a temp base, so a protected path is refused without a stat."""
    a = Path(os.path.abspath(os.fspath(path)))
    if overlaps_protected(a):
        raise UnsafePath(f"{what} {a} overlaps a protected location")
    if not any(_within(a, b) for b in scratch_bases(False) + scratch_bases()):
        raise UnsafePath(f"{what} {a} is not under a temp base")
    p = _real(a)
    if overlaps_protected(p):
        raise UnsafePath(f"{what} {p} overlaps a protected location")
    bases = scratch_bases()
    if not any(_within(p, b) for b in bases):
        raise UnsafePath(f"{what} {p} is not under a temp base {[str(b) for b in bases]}")
    if p in bases:
        raise UnsafePath(f"{what} {p} is a temp base itself; use a fresh directory below it")
    return p


def short_runtime_dir() -> Path:
    """A fresh private directory with a short path under /tmp, for
    XDG_RUNTIME_DIR: Claude Code puts its peer-messaging socket in
    $XDG_RUNTIME_DIR/cc-socks/<pid>.sock and falls back to the shared
    /tmp/cc-socks-<uid>/ when that path would pass the 103-byte socket
    limit, where the person's real sessions would see the test session as a
    peer. The caller removes it (driver.Session.close does)."""
    return Path(tempfile.mkdtemp(prefix="tui-", dir="/tmp"))


def state_root_for(config_dir: os.PathLike | str) -> Path:
    """Where the plugin state of sessions on one Claude config lives:
    `<parent>/<config name>.state`, a sibling of the config dir. Every
    Session and `claude plugin` call on that config (a restart, a new
    Session on an installed config) gets the same CHECKPOINT_HOME, gateway
    stand-in paths and XDG dirs from it, whatever its own HOME is."""
    c = Path(os.path.abspath(os.fspath(config_dir)))
    return c.parent / (c.name + ".state")


# The plugin state roots hermetic_env derives from the state root. Each must
# stay a scratch path; the ones a plugin falls back to the real home without
# (checkpoint: an unset or empty CHECKPOINT_GATEWAY_CONTRACT means
# <password-database home>/.config/gateway/run/contract.json, an unset
# CHECKPOINT_GATEWAY_ENV the real env.sh) must also stay set.
STATE_VARS = ("CHECKPOINT_HOME", "CHECKPOINT_GATEWAY_ENV", "CHECKPOINT_GATEWAY_CONTRACT",
              "GATEWAY_TEST_ROOT", "XDG_STATE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
              "XDG_CACHE_HOME")
MUST_STAY_SET = {"CHECKPOINT_GATEWAY_CONTRACT": "non-empty", "CHECKPOINT_GATEWAY_ENV": "present"}
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")


def state_env(state_root: os.PathLike | str) -> dict[str, str]:
    """The plugin state roots under `state_root` (laid out like a home)."""
    st = Path(state_root)
    return {
        "CHECKPOINT_HOME": str(st / ".local" / "state" / "checkpoint"),
        "CHECKPOINT_GATEWAY_ENV": str(st / ".config" / "gateway" / "env.sh"),
        "CHECKPOINT_GATEWAY_CONTRACT": str(st / ".config" / "gateway" / "run" / "contract.json"),
        "GATEWAY_TEST_ROOT": str(st / "gateway-test-root"),
        "XDG_STATE_HOME": str(st / ".local" / "state"),
        "XDG_CONFIG_HOME": str(st / ".config"),
        "XDG_DATA_HOME": str(st / ".local" / "share"),
        "XDG_CACHE_HOME": str(st / ".cache"),
    }


def _loopback(url: str) -> bool:
    from urllib.parse import urlsplit
    try:
        u = urlsplit(url)
        host = u.hostname or ""
    except ValueError:
        return False
    return u.scheme in ("http", "https") and host in LOOPBACK_HOSTS


def hermetic_env(*, config_dir: os.PathLike | str, home: os.PathLike | str,
                 tmpdir: os.PathLike | str, base_url: str = "http://127.0.0.1:9",
                 runtime_dir: os.PathLike | str | None = None,
                 state_root: os.PathLike | str | None = None,
                 cols: int | None = None, rows: int | None = None,
                 inherit: tuple[str, ...] = (), extra: dict | None = None) -> dict[str, str]:
    """Environment for anything that runs Claude Code under the harness.

    config_dir, home and tmpdir must pass check_scratch (tmpdir is made 0700
    and is also CLAUDE_CODE_TMPDIR); runtime_dir (see short_runtime_dir)
    becomes XDG_RUNTIME_DIR. The plugin state roots (STATE_VARS) come from
    `state_root`, by default state_root_for(config_dir), so every process on
    one config shares them across restarts. base_url is the fake API
    (default: a closed port, for `claude plugin ...` commands that need no
    model) and must be a loopback URL. `inherit` names further caller
    variables to copy; `extra` is applied last (values of None delete a key).
    """
    cfg = check_scratch(config_dir, "CLAUDE_CONFIG_DIR")
    hm = check_scratch(home, "HOME")
    tmp = check_scratch(tmpdir, "TMPDIR")
    st = check_scratch(state_root if state_root is not None else state_root_for(cfg), "state root")
    if tmp.is_dir():
        os.chmod(tmp, 0o700)
    env = {k: os.environ[k] for k in ALLOW_ENV + tuple(inherit) if k in os.environ}
    env.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
    env.update({
        "HOME": str(hm),
        "TMPDIR": str(tmp) + os.sep,
        # Claude Code's own temp root (task dirs, fs.watch probe) is
        # /tmp/claude-<uid>/ unless this names a private 0700 directory.
        "CLAUDE_CODE_TMPDIR": str(tmp),
        "CLAUDE_CONFIG_DIR": str(cfg),
        "ANTHROPIC_BASE_URL": base_url,
        "ANTHROPIC_API_KEY": FAKE_API_KEY,
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
        "DISABLE_AUTOUPDATER": "1",
        "DISABLE_TELEMETRY": "1",
        "DISABLE_ERROR_REPORTING": "1",
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "TERM": "xterm-256color",
    })
    # Plugin state roots: scratch, and shared by every process on this config,
    # so a plugin under test never reaches the person's live checkpoint state,
    # gateway env file or gateway contract, and a restart sees the same state.
    env.update(state_env(st))
    if runtime_dir is not None:
        env["XDG_RUNTIME_DIR"] = str(check_scratch(runtime_dir, "XDG_RUNTIME_DIR"))
    if cols:
        env["COLUMNS"] = str(cols)
    if rows:
        env["LINES"] = str(rows)
    for k, v in (extra or {}).items():
        if v is None:
            env.pop(k, None)
        else:
            env[k] = str(v)
    # Final check: whatever `extra` did, the roots stay scratch.
    for k in ("CLAUDE_CONFIG_DIR", "HOME"):
        if not env.get(k):
            raise UnsafePath(f"{k} must stay set to a scratch path")
        check_scratch(env[k], k)
    for k, how in MUST_STAY_SET.items():
        if k not in env or (how == "non-empty" and not env[k]):
            raise UnsafePath(f"{k} must stay set ({how}) to a scratch path: unset, the plugin "
                             "falls back to the real home")
    for k in STATE_VARS + ("XDG_RUNTIME_DIR", "TMPDIR", "CLAUDE_CODE_TMPDIR"):
        if env.get(k):  # empty means "none" to those plugins
            check_scratch(env[k], k)
    if not _loopback(env.get("ANTHROPIC_BASE_URL", "")):
        raise UnsafePath("ANTHROPIC_BASE_URL must be a loopback URL (the harness's fake API)")
    if env.get("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC") != "1" and not record_proxied(env):
        raise UnsafePath("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC must stay 1 (unless every request "
                         "goes to the harness's record-only proxy, proxy.py)")
    for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
        if env.get(k) and not _loopback(env[k]):
            raise UnsafePath(f"{k} must be a loopback URL (the harness's record-only proxy)")
    return env


PROXY_VARS = ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy")


def record_proxied(env: dict) -> bool:
    """Does every request of this environment go to the harness's record-only
    proxy? TUI_RECORD_PROXY set to a loopback URL that each proxy variable
    names too, and its CA a scratch file."""
    url = env.get("TUI_RECORD_PROXY", "")
    if not url or not _loopback(url) or any(env.get(k) != url for k in PROXY_VARS):
        return False
    ca = env.get("NODE_EXTRA_CA_CERTS", "")
    if not ca:
        return False
    try:
        check_scratch(ca, "NODE_EXTRA_CA_CERTS")
    except UnsafePath:
        return False
    return True


def sha256_file(path: os.PathLike | str) -> str | None:
    """sha256 hex of a file, or None if it does not exist."""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except FileNotFoundError:
        return None


def real_settings_fingerprint() -> dict[str, str | None]:
    """sha256 of the real Claude settings and plugin registry files.

    Read-only; used by tests to prove a run left the real config alone.
    """
    base = real_home() / ".config" / "claude"
    names = ["settings.json", "plugins/installed_plugins.json", "plugins/known_marketplaces.json"]
    return {n: sha256_file(base / n) for n in names}


def _children() -> dict[int, list[int]]:
    """ppid -> [pid] for every live process (one `ps`)."""
    try:
        out = subprocess.run(["ps", "-axo", "pid=,ppid="], capture_output=True, text=True,
                             timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    kids: dict[int, list[int]] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
            kids.setdefault(int(parts[1]), []).append(int(parts[0]))
    return kids


def descendants(pid: int, kids: dict[int, list[int]] | None = None) -> list[int]:
    """All live descendants of `pid` (children first is not guaranteed)."""
    kids = _children() if kids is None else kids
    found, todo = [], [pid]
    while todo:
        for c in kids.get(todo.pop(), []):
            if c not in found:
                found.append(c)
                todo.append(c)
    return found


def sessions_of(pids) -> set[int]:
    """The session ids of the live `pids`, never the harness's own session
    (nor 0 or 1)."""
    out = set()
    for p in pids:
        try:
            out.add(os.getsid(int(p)))
        except OSError:
            pass
    try:
        out.discard(os.getsid(0))
    except OSError:
        pass
    return out - {0, 1}


def session_members(sids, match) -> list[int]:
    """Live processes of this user (not this one) whose session id is in
    `sids` and whose command line satisfies `match`. Finds what a child
    started in a session of its own (Node's `detached: true` calls setsid;
    Claude Code spawns a mod's processes that way) and left behind when its
    parent died: such an orphan is no longer a descendant, but keeps its
    session id."""
    sids = set(sids) - {0, 1}
    if not sids:
        return []
    try:
        out = subprocess.run(["ps", "-axo", "pid=,uid=,command="], capture_output=True,
                             text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    me, mine = str(os.getuid()), os.getpid()
    found = []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 2 or not parts[0].isdigit() or parts[1] != me:
            continue
        pid = int(parts[0])
        if pid == mine or not match(parts[2] if len(parts) == 3 else ""):
            continue
        try:
            if os.getsid(pid) in sids:
                found.append(pid)
        except OSError:
            pass
    return found


def pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


# Exit statuses of direct children reaped by kill_tree (pid -> exit code).
EXIT_STATUS: dict[int, int] = {}


def _gone(pid: int) -> bool:
    """True once `pid` has ended: reaped when it is our child (status kept
    in EXIT_STATUS), else no longer signalable."""
    try:
        got, status = os.waitpid(pid, os.WNOHANG)
        if got == pid:
            EXIT_STATUS[pid] = os.waitstatus_to_exitcode(status)
            return True
        return False  # our child, still running
    except ChildProcessError:
        pass  # not our child (or already reaped)
    except OSError:
        pass
    return pid in EXIT_STATUS or not pid_alive(pid)


def identities(pids) -> dict[int, str]:
    """pid -> "start time + command" for the live ones (to detect pid reuse)."""
    pids = [int(p) for p in pids]
    if not pids:
        return {}
    try:
        out = subprocess.run(["ps", "-o", "pid=,lstart=,comm=", "-p", ",".join(map(str, pids))],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return {}
    ids = {}
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0].isdigit():
            ids[int(parts[0])] = parts[1].strip()
    return ids


def kill_tree(pid: int, grace: float = 2.0, group: bool = True, drain=None,
              sessions=(), match=None) -> None:
    """Terminate `pid`, its process group (when it leads one) and every
    descendant: SIGTERM, up to `grace` seconds, then SIGKILL and up to 3 more
    seconds. A direct child is reaped and its exit code stored in
    EXIT_STATUS. `drain()` is called while waiting (a PTY owner must keep
    reading the master: on macOS a process cannot finish exiting while its
    terminal output is undrained).

    With `match` (a predicate on a command line), each round also takes in
    what joined since the first listing: new descendants of the victims, and
    processes of this user in the victims' sessions (plus `sessions`, ids a
    caller recorded earlier) whose command line matches, such as a helper
    started after the listing by a dying parent in a setsid'd session. A
    last sweep catches any started during the SIGKILL round.

    Only processes the harness started are ever passed here, and a pid is
    signalled only while it still has the start time and command it had
    when it was first listed (so a reused pid is never hit)."""
    victims = [pid] + descendants(pid)
    ids = identities(victims)
    sids = (set(sessions) | sessions_of(victims)) if match is not None else set()
    try:
        pgid = os.getpgid(pid) if group else None
    except OSError:
        pgid = None

    def widen() -> list[int]:
        if match is None:
            return []
        kids = _children()
        new = session_members(sids, match)
        for v in victims + new:   # and whatever those started (their children may
            if not _gone(v):      # not name a scratch path, as `sleep 30` doesn't)
                new += descendants(v, kids)
        new = [p for p in dict.fromkeys(new) if p not in victims]
        if new:
            victims.extend(new)
            ids.update(identities(new))
            sids.update(sessions_of(new))
        return new

    def wait_for(same: list[int], wait: float) -> None:
        end = time.time() + wait
        while time.time() < end and not all(_gone(p) for p in same):
            if drain is not None:
                try:
                    drain()
                except Exception:
                    time.sleep(0.05)
            else:
                time.sleep(0.05)

    for sig, wait in ((signal.SIGTERM, grace), (signal.SIGKILL, 3.0)):
        widen()
        live = [p for p in victims if not _gone(p)]
        if not live:
            break
        now = identities(live)
        same = [p for p in live if p in ids and now.get(p) == ids[p]]
        if pgid and pgid > 1 and pgid != os.getpgrp() and pid in same:
            try:
                os.killpg(pgid, sig)  # the group is ours while its leader is
            except OSError:
                pass
        for p in same:
            try:
                os.kill(p, sig)
            except OSError:
                pass
        wait_for(same, wait)
    for _ in range(3):  # anything started while the last round ran
        if not widen():
            break
        live = [p for p in victims if not _gone(p)]
        now = identities(live)
        same = [p for p in live if p in ids and now.get(p) == ids[p]]
        for p in same:
            try:
                os.kill(p, signal.SIGKILL)
            except OSError:
                pass
        wait_for(same, 3.0)
