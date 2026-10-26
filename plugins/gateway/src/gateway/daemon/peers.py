"""Who is on the other end of a gated connection.

peer_cred(sock) -> Peer(pid, uid, gid), from the kernel at connect time:
  Linux: SO_PEERCRED (struct ucred {pid, uid, gid}).
  macOS: LOCAL_PEERPID (pid_t) and LOCAL_PEERCRED (struct xucred {version,
  uid, ngroups, groups[16]}) at level SOL_LOCAL (0).

Process facts come from kernel lookups by pid (ancestry's helpers:
proc_pidpath / /proc/PID/exe, KERN_PROCARGS2 / /proc/PID/cmdline, the
parent pid, the start time), never from a name the process chose for itself.

entry_of(pid) -> Entry | None: is the process a gateway entry point? Its
executable (by path) must be the daemon's own python or a python of the
daemon's plugin data folder's envs (<data>/envs/<sha12>/.pixi/envs/default/
bin), and its argv `<python> -I -S [-X pycache_prefix=...] <root>/run.py
[--test] MODE ...` (the options every gateway launcher passes, and no
others), where <root> is the daemon's own plugin folder (paths.code_root())
or, when that folder is a version folder of Claude Code's plugin cache
(<config>/plugins/cache/<marketplace>/<plugin>/<version>), a sibling version
folder whose plugin.json names "gate" (sessions of the versions before and
after an update share one daemon). A folder elsewhere with a run.py and a
plugin.json naming "gate" is not an entry point. Under a test override the
test entries (tests/entry.py, harness_ssh.py --entry, a driver in the test
root) count too, with the test root in argv before the mode; production
never accepts them.

This is a guardrail, not a boundary: argv is set by whoever starts a
process, and code already running as the user can run the env's python on
the real run.py with any arguments, or read the daemon's memory. The checks
keep a cooperative model's ad-hoc scripts and other programs from reaching
the vault plane by accident or by a casual attempt (docs/dev/modules/daemon.md).
"""
from __future__ import annotations

import json
import os
import socket
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

from .. import ancestry, paths, testing

# macOS <sys/un.h>
SOL_LOCAL = 0
LOCAL_PEERCRED = 0x001
LOCAL_PEERPID = 0x002
XUCRED_SIZE = 76            # u_int version, uid_t uid, short ngroups (+2 pad), gid_t groups[16]

MAX_DEPTH = 64


@dataclass(frozen=True)
class Peer:
    pid: int
    uid: int
    gid: int


def peer_cred(sock: socket.socket) -> Peer:
    """The connected peer's pid, uid and gid (OSError when the kernel can't say)."""
    if sys.platform == "darwin":  # pragma: no cover - macOS only
        pid = struct.unpack("i", sock.getsockopt(SOL_LOCAL, LOCAL_PEERPID, 4))[0]
        raw = sock.getsockopt(SOL_LOCAL, LOCAL_PEERCRED, XUCRED_SIZE)
        version, uid = struct.unpack_from("II", raw, 0)
        ngroups = struct.unpack_from("h", raw, 8)[0]
        gid = struct.unpack_from("I", raw, 12)[0] if ngroups > 0 else -1
        if version != 0:
            raise OSError("unexpected xucred version")
        return Peer(int(pid), int(uid), int(gid))
    so_peercred = getattr(socket, "SO_PEERCRED", 17)
    raw = sock.getsockopt(socket.SOL_SOCKET, so_peercred, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return Peer(int(pid), int(uid), int(gid))


# ---------------------------------------------------------------------------
# Process facts
# ---------------------------------------------------------------------------


def exe(pid: int) -> str | None:
    return ancestry.exe_path(pid)


def argv(pid: int) -> list[str] | None:
    return ancestry._argv(pid)


def parent(pid: int) -> int:
    return ancestry.parent_pid(pid)


def started(pid: int) -> float | None:
    return ancestry.started_at(pid)


def alive(pid: int, start: float | None = None) -> bool:
    """Is `pid` alive and (when `start` is given) still the process that
    started then? A reused pid has another start time."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        pass                  # alive, another user's
    if start is None:
        return True
    now = started(pid)
    return now is not None and abs(now - start) < 0.05


def chain(pid: int) -> list[int]:
    """pid, its parent, its grandparent, ... up to init (at most MAX_DEPTH)."""
    out: list[int] = []
    seen: set[int] = set()
    while pid > 1 and pid not in seen and len(out) < MAX_DEPTH:
        out.append(pid)
        seen.add(pid)
        pid = parent(pid)
    return out


def _homes() -> list:
    homes: list = [testing.real_user_home()]
    try:
        homes.append(paths.user_home())
    except Exception:  # noqa: BLE001
        pass
    return homes


def exe_is_claude(e: str) -> bool:
    """Is executable path `e` Claude Code's? Named `claude`, npm's native
    binary (`.../node_modules/@anthropic-ai/claude-code/bin/claude.exe`), or
    in the native install's versions folder or the desktop app's copy under
    the person's home (the password database's: a test or e2e override moves
    the gateway's home, never where Claude Code is installed; the live e2e
    check found the native install's `versions/2.1.301` refused under the
    override's home)."""
    return any(ancestry.is_claude_exe(e, h) for h in _homes())


def is_claude(pid: int) -> bool:
    """Is `pid` a Claude Code process, by its executable path?"""
    e = exe(pid)
    return bool(e) and exe_is_claude(e)


def claude_install(pid: int) -> str:
    """How the Claude Code process `pid` was installed, in words for
    /gate-doctor ("" when it isn't recognized as Claude Code)."""
    e = exe(pid)
    if not e or not exe_is_claude(e):
        return ""
    for h in _homes():
        kind = ancestry.claude_install(e, h)
        if kind and not kind.startswith("an executable named"):
            return kind
    return ancestry.claude_install(e)


# ---------------------------------------------------------------------------
# Gateway entry points
# ---------------------------------------------------------------------------

# run.py modes a gateway process may run in (run.py's dispatch). "shim" is
# followed by the stand-in's name.
HOOK_MODES = ("hook-session", "hook-session-async", "hook-subagent", "hook-bash", "hook-files",
              "hook-post", "hook-prompt", "hook-filechanged", "hook-daemon", "hook-mcp",
              "hook-mode")
ENTRY_MODES = HOOK_MODES + ("mcp", "shim", "askpass", "git-credential", "gate", "gated")


@dataclass(frozen=True)
class Entry:
    mode: str            # "shim sudo", "git-credential", "hook-post", "mcp", "gate", ...
    script: str          # the run.py (or test entry) it runs
    exe: str


def _real(p: str) -> str:
    try:
        return os.path.realpath(p)
    except (OSError, ValueError):
        return p


def allowed_pythons() -> set[str]:
    """The daemon's own interpreter (resolved). Env pythons of the plugin
    data folder are recognised by place (python_ok)."""
    return {_real(sys.executable)}


def python_ok(exe_path: str) -> bool:
    r = _real(exe_path)
    if r in allowed_pythons():
        return True
    d = paths.data_from_executable(r)
    if d is None:
        return False
    try:
        return _real(str(d)) == _real(str(paths.data_dir()))
    except Exception:  # noqa: BLE001
        return False


def launcher_options_ok(opts: list[str]) -> bool:
    """The interpreter options before the script are the gateway launchers'
    own (launch.sh, envfile.py_flags, lifecycle.daemon_argv: `-I -S -X
    pycache_prefix=...`): -I and -S both given (no PYTHON* variables, no
    script folder, no site: a planted sitecustomize or .pth never runs), and
    nothing else but -X pycache_prefix."""
    flags: set[str] = set()
    i = 0
    while i < len(opts):
        a = opts[i]
        if a.startswith("-X"):
            v = a[2:] if len(a) > 2 else (opts[i + 1] if i + 1 < len(opts) else "")
            if not v.startswith("pycache_prefix="):
                return False
            i += 1 if len(a) > 2 else 2
            continue
        if len(a) < 2 or a[0] != "-" or not set(a[1:]) <= {"I", "S"}:
            return False
        flags |= set(a[1:])
        i += 1
    return flags == {"I", "S"}


def _script_index(av: list[str]) -> int | None:
    """Where the script is in a python argv (after the interpreter options)."""
    i = 1
    while i < len(av):
        a = av[i]
        if a in ("-c", "-m"):
            return None                  # a command or a module, never a script file
        if a == "--":
            return i + 1 if i + 1 < len(av) else None
        if a in ("-X", "-W"):
            i += 2
            continue
        if a.startswith("-") and len(a) > 1:
            i += 1
            continue
        return i
    return None


_PLUGIN_NAME_CACHE: dict[str, tuple[float, str]] = {}


def _plugin_name(root: str) -> str:
    p = os.path.join(root, ".claude-plugin", "plugin.json")
    try:
        mt = os.stat(p).st_mtime
    except OSError:
        return ""
    hit = _PLUGIN_NAME_CACHE.get(p)
    if hit and hit[0] == mt:
        return hit[1]
    try:
        with open(p, encoding="utf-8") as f:
            name = json.load(f).get("name") or ""
    except (OSError, ValueError, AttributeError):
        name = ""
    name = name if isinstance(name, str) else ""
    _PLUGIN_NAME_CACHE[p] = (mt, name)
    return name


def in_plugin_cache(root: str) -> bool:
    """Is `root` (resolved) a version folder of Claude Code's plugin cache,
    <config>/plugins/cache/<marketplace>/<plugin>/<version>?"""
    parts = Path(root).parts
    return len(parts) >= 6 and parts[-4] == "cache" and parts[-5] == "plugins"


def is_run_py(script: str) -> bool:
    """`script` is the gateway's run.py, by its resolved path: this plugin
    folder's (paths.code_root()), or a sibling version folder's in the same
    plugin cache (its plugin.json naming "gate"; only when this folder is in
    the plugin cache)."""
    if not os.path.isabs(script):
        return False
    r = _real(script)
    if os.path.basename(r) != "run.py" or not os.path.isfile(r):
        return False
    root = os.path.dirname(r)
    mine = _real(str(paths.code_root()))
    if root == mine:
        return True
    return in_plugin_cache(mine) and os.path.dirname(root) == os.path.dirname(mine) and \
        _plugin_name(root) == "gate"


def _test_entry_rest(script: str, av: list[str], i: int) -> list[str] | None:
    """Under a test override that allows it: a test entry (a script in the
    plugin's tests/ folder or in the test root) with the test root in argv;
    what follows the root. None otherwise."""
    o = testing.active()
    if o is None or o.root is None or not testing.get("gated_test_entries", False):
        return None
    r = _real(script)
    roots = [_real(str(paths.code_root() / "tests")), _real(str(o.root))]
    if not any(r == x or r.startswith(x + os.sep) for x in roots):
        return None
    root_s = {str(o.root), _real(str(o.root))}
    for k in range(i + 1, len(av)):
        if av[k] in root_s:
            return av[k + 1:]
    return None


def entry_of(pid: int) -> Entry | None:
    """The gateway entry point `pid` runs, or None (see the module docstring)."""
    e = exe(pid)
    av = argv(pid)
    if not e or not av or not python_ok(e):
        return None
    i = _script_index(av)
    if i is None or not launcher_options_ok(av[1:i]):
        return None
    script = av[i]
    if is_run_py(script):
        rest = av[i + 1:]
    else:
        rest = _test_entry_rest(script, av, i)
        if rest is None:
            return None
    if rest[:1] == ["--test"]:
        rest = rest[1:]
    if not rest or rest[0] not in ENTRY_MODES:
        return None
    mode = rest[0]
    if mode == "shim":
        if len(rest) < 2 or not rest[1].isidentifier():
            return None
        mode = f"shim {rest[1]}"
    return Entry(mode, script, e)


def foreign_data(pid: int) -> Path | None:
    """When `pid` is refused as an entry point only because it belongs to
    another plugin data folder (a second Claude Code configuration, its own
    CLAUDE_CONFIG_DIR: one gated per user serves one data folder, the one
    its python is in): that folder, so the refusal can say so (GW-ROB-2).
    It must otherwise look like a gateway entry point: a python of a data
    folder's env, the launchers' options, a run.py whose plugin.json names
    "gate", a gateway mode. None for anything else (no new trust: the caller
    is refused either way)."""
    e = exe(pid)
    av = argv(pid)
    if not e or not av:
        return None
    other = paths.data_from_executable(_real(e))
    if other is None:
        return None
    try:
        if _real(str(other)) == _real(str(paths.data_dir())):
            return None
    except Exception:  # noqa: BLE001
        return None
    k = _script_index(av)
    if k is None or not launcher_options_ok(av[1:k]):
        return None
    script = av[k]
    if not os.path.isabs(script) or os.path.basename(script) != "run.py" or \
            _plugin_name(os.path.dirname(_real(script))) != "gate":
        return None
    rest = av[k + 1:]
    if rest[:1] == ["--test"]:
        rest = rest[1:]
    return other if rest and rest[0] in ENTRY_MODES else None

