"""Direct vs scripts: who started a stand-in (SPEC 10).

A stand-in supplies a credential only when the caller is *direct*: walking up
from the stand-in's parent, every process until `CLAUDE_PID` is a shell (sh,
bash, dash, zsh, fish) or one of a small set of wrappers (`env nohup time
timeout nice ionice stdbuf xargs sudo`), or — for ssh and git credentials —
also one of `git git-remote-* git-lfs rsync scp sftp ssh gh`.

Processes are identified by their executable *path* (proc_pidpath via ctypes on
macOS, /proc/PID/exe on Linux), never by argv[0] or a name a caller controls.

No `CLAUDE_PID` in the environment (a user's terminal sourcing env.sh, a
checkpoint job): not direct — except that a process tree rooted at the
checkpoint plugin's job runner counts like Claude's shell. It is recognised by
its command line (`…/checkpoint/…/run.py server`), and only when the process's
executable (by path) is a python interpreter and that run.py exists. A command
line is set by whoever starts the process, so code already running as the user
can still imitate the runner; this recognition is a convenience for checkpoint
jobs, not a boundary against such code (docs/dev/modules/sudo.md).

Not direct and the entry has `scripts = true` → allowed. Otherwise the caller
runs the real program with no credential and prints one line.

`is_direct(tool, entry_scripts=False) -> (allowed, culprit)`:
- `allowed` is True when the caller is direct, or when it isn't but
  `entry_scripts` is set.
- `culprit` is the basename of the first non-allowed intermediate (for the
  "sudo started by make got no password" message); "" when direct; "?"
  (UNTRACED) when there is none to name: no CLAUDE_PID, or the walk reached
  init, as for a job still running after its session ended. The refusals
  then name UNTRACED_WHO.

`typed_by_claude() -> (ok, culprit)` is the stricter test for an `"ask"`
right (SPEC 9, 10): Claude Code can only prompt for a command Claude typed,
and the approval hook only sees that command line. So the stand-in must have
been started by Claude's own command shell (the direct child of `CLAUDE_PID`)
or by a fork of it (a pipeline stage, a `( … )` subshell: same executable and
same argv as its parent), with nothing else in between: no wrapper, no git,
rsync, scp or sftp, no script and no `sh -c` shell, and never the checkpoint
runner (a job runs `sh -c WRAPPER ...` then `sh -c CMD`, which already fails
the fork test; CLAUDE_PID naming the runner itself is refused explicitly).
`scripts = true` doesn't relax it. When it refuses and checkpoint's job
runner is the stand-in's parent or any process above it, the culprit is
"checkpoint" (CHECKPOINT), so the stand-ins give the job wording the approval
hook gives job_start ("a job can't use the "ask" right ...; run it with the
Bash tool as its own command ..."), not "run it as its own command", which
would lead Claude to start another job. A job whose runner has ended (its
session closed; the job is then a child of init) isn't recognised: the
generic wording, and `is_direct` finds no direct caller either, so such a
job gets credentials only from entries with `scripts = true`. Nor is anything
run in a gateway terminal or job (gated's tmux panes, PLAN-v4 phase 5) ever
typed: their start file sets `CLAUDE_PID=$$`, the pane's own shell, for
`is_direct` (a command run there is direct, as one in Claude's shell), and a
`CLAUDE_PID` that names a shell is never Claude Code, which asks about
nothing run in a pane. Without that check every stand-in the pane's shell, or
a script it runs, starts would pass the walk (its parent, or its parent's
parent, is `CLAUDE_PID`). The culprit is TERMINAL, for the stand-ins' pane
wording (consent.pane_ask_message).

`claude_ancestor(home) -> reason | None` (SPEC 6, 15: `gate secret` and the
other terminal paths behind a one-time code): walks the whole parent chain
and names why this process counts as started from Claude Code: an ancestor
whose executable (by path) is Claude Code's (basename `claude`, under
`~/.local/share/claude/versions/`, the desktop app's bundled copy under
`~/Library/Application Support/Claude/claude-code/`, npm's
`.../node_modules/@anthropic-ai/claude-code/bin/claude.exe`, or node running
npm's `.../@anthropic-ai/claude-code/cli.js` as its script), or whose pid is
`CLAUDE_PID`, or a chain that can't be read (a parent pid that can't be
read, a loop, too deep; a process of the user's own whose executable can't
be read, except OpenSSH's session process under a root sshd, which Linux
makes unreadable). Another user's process whose executable can't be read
(root's sshd, login, sudo on Linux) isn't Claude Code, which runs as the
user; the walk goes on above it. Above an unreadable process of the user's
own the walk goes on too, so a Claude Code process further up is named
instead of UNREADABLE (on macOS the path of an executable deleted or
replaced while it runs can't be read: a login shell or tmux after a `brew
upgrade` or `port upgrade`; callers tell the user so). A process detached
from Claude's tree (a double fork, a terminal window it opens) isn't seen:
defence in depth behind the one-time code, not a boundary.
"""
from __future__ import annotations

import ctypes
import ctypes.util
import os
import re
import struct
import sys


# Intermediates allowed for every tool.
SHELLS = frozenset({"sh", "bash", "dash", "zsh", "fish", "ash"})
WRAPPERS = frozenset({"env", "nohup", "time", "timeout", "nice", "ionice", "stdbuf",
                      "xargs", "sudo", "doas"})
# Extra intermediates for ssh and git credential tools (git drives ssh/scp and
# the helper through these).
GIT_INTERMEDIATES = frozenset({"git", "git-lfs", "rsync", "scp", "sftp", "ssh", "gh"})
# Tools whose credentials are "ssh/git credentials".
CRED_FAMILY = frozenset({"ssh", "scp", "sftp", "rsync", "git", "git-credential",
                         "git-credential-gateway"})

MAX_DEPTH = 64
CHECKPOINT = "checkpoint"      # typed_by_claude's culprit for a checkpoint job
TERMINAL = "gateway-terminal"  # typed_by_claude's culprit inside a gateway terminal or job
UNTRACED = "?"                 # is_direct's culprit when there is none to name
# How the stand-ins' "started by ... got no key/password/credential" refusals
# name the UNTRACED culprit (ssh, remote and local sudo, git, the account CLIs).
UNTRACED_WHO = ("a program the gateway can't trace back to Claude (such as a job still "
                "running after its session ended)")
# The checkpoint plugin's detached job runner: `.../checkpoint/.../run.py server`.
_CHECKPOINT_RE = re.compile(r"/checkpoint/.*run\.py$")
_PY_EXE = re.compile(r"^python[0-9.]*$", re.I)


def _allowed_names(tool: str) -> frozenset[str]:
    base = SHELLS | WRAPPERS
    if tool in CRED_FAMILY:
        return base | GIT_INTERMEDIATES
    return base


def _is_allowed_name(name: str, allowed: frozenset[str]) -> bool:
    if name in allowed:
        return True
    # git-remote-http, git-remote-https, ... count as git intermediates.
    return name.startswith("git-remote-") and "git" in allowed


# ---------------------------------------------------------------------------
# Per-platform process inspection (ppid, executable path, command line)
# ---------------------------------------------------------------------------

_libc = None


def _mac_libc():  # pragma: no cover - exercised only on macOS
    global _libc
    if _libc is None:
        _libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.dylib", use_errno=True)
    return _libc


_PROC_PIDPATHINFO_MAXSIZE = 4096
_PROC_PIDTBSDINFO = 3
_CTL_KERN = 1
_KERN_ARGMAX = 8
_KERN_PROCARGS2 = 49


class _ProcBsdInfo(ctypes.Structure):  # struct proc_bsdinfo (sys/proc_info.h)
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32), ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32), ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32), ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32), ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32), ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32), ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16), ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32), ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32), ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32), ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64), ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def _mac_bsdinfo(pid: int):  # pragma: no cover - macOS only
    info = _ProcBsdInfo()
    n = _mac_libc().proc_pidinfo(pid, _PROC_PIDTBSDINFO, ctypes.c_uint64(0),
                                 ctypes.byref(info), ctypes.sizeof(info))
    return info if n == ctypes.sizeof(info) else None


_PROC_PIDT_SHORTBSDINFO = 13


class _ProcBsdShortInfo(ctypes.Structure):  # struct proc_bsdshortinfo (sys/proc_info.h)
    _fields_ = [
        ("pbsi_pid", ctypes.c_uint32), ("pbsi_ppid", ctypes.c_uint32),
        ("pbsi_pgid", ctypes.c_uint32), ("pbsi_status", ctypes.c_uint32),
        ("pbsi_comm", ctypes.c_char * 16), ("pbsi_flags", ctypes.c_uint32),
        ("pbsi_uid", ctypes.c_uint32), ("pbsi_gid", ctypes.c_uint32),
        ("pbsi_ruid", ctypes.c_uint32), ("pbsi_rgid", ctypes.c_uint32),
        ("pbsi_svuid", ctypes.c_uint32), ("pbsi_svgid", ctypes.c_uint32),
        ("pbsi_rfu", ctypes.c_uint32),
    ]


def _mac_shortinfo(pid: int):  # pragma: no cover - macOS only
    """PROC_PIDT_SHORTBSDINFO answers for every process, including root's
    (PROC_PIDTBSDINFO returns nothing for them when the caller isn't root,
    so a walk up through setuid sudo used to stop there)."""
    info = _ProcBsdShortInfo()
    n = _mac_libc().proc_pidinfo(pid, _PROC_PIDT_SHORTBSDINFO, ctypes.c_uint64(0),
                                 ctypes.byref(info), ctypes.sizeof(info))
    return info if n == ctypes.sizeof(info) and info.pbsi_pid == pid else None


def _mac_ppid(pid: int) -> int:  # pragma: no cover - macOS only
    short = _mac_shortinfo(pid)
    if short is not None:
        return int(short.pbsi_ppid)
    info = _mac_bsdinfo(pid)
    return int(info.pbi_ppid) if info is not None else 0


def _mac_exe(pid: int) -> str | None:  # pragma: no cover - macOS only
    buf = ctypes.create_string_buffer(_PROC_PIDPATHINFO_MAXSIZE)
    n = _mac_libc().proc_pidpath(pid, buf, _PROC_PIDPATHINFO_MAXSIZE)
    if n <= 0:
        return None
    return buf.value.decode("utf-8", "replace")


def _mac_procargs(pid: int) -> tuple[str, list[str]] | None:  # pragma: no cover - macOS only
    """(exec path, argv) from KERN_PROCARGS2."""
    libc = _mac_libc()
    argmax = ctypes.c_int(0)
    size = ctypes.c_size_t(ctypes.sizeof(argmax))
    mib = (ctypes.c_int * 2)(_CTL_KERN, _KERN_ARGMAX)
    if libc.sysctl(mib, 2, ctypes.byref(argmax), ctypes.byref(size), None, 0) != 0:
        argmax = ctypes.c_int(262144)
    buf = ctypes.create_string_buffer(argmax.value)
    size = ctypes.c_size_t(argmax.value)
    mib3 = (ctypes.c_int * 3)(_CTL_KERN, _KERN_PROCARGS2, pid)
    if libc.sysctl(mib3, 3, buf, ctypes.byref(size), None, 0) != 0:
        return None
    data = buf.raw[:size.value]
    if len(data) < 4:
        return None
    argc = struct.unpack("i", data[:4])[0]
    parts = data[4:].split(b"\x00")
    if not parts:
        return None
    # parts[0] = exec_path; then padding empties; then argc argv strings.
    exec_path = parts[0]
    argv: list[bytes] = []
    for chunk in parts[1:]:
        if chunk == b"" and not argv:
            continue  # skip padding between exec_path and argv[0]
        argv.append(chunk)
        if len(argv) >= argc:
            break
    return (exec_path.decode("utf-8", "replace"),
            [a.decode("utf-8", "replace") for a in argv])


def _mac_argv(pid: int) -> list[str] | None:  # pragma: no cover - macOS only
    r = _mac_procargs(pid)
    return r[1] if r else None


def _mac_cmdline(pid: int) -> str | None:  # pragma: no cover - macOS only
    r = _mac_procargs(pid)
    return " ".join([r[0], *r[1]]) if r else None


def _linux_ppid(pid: int) -> int:
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            raw = f.read()
    except OSError:
        return 0
    # comm (field 2) is in parens and may contain spaces/parens; split after the last ')'.
    rp = raw.rfind(b")")
    if rp < 0:
        return 0
    fields = raw[rp + 2:].split()
    try:
        return int(fields[1])  # ppid is the 2nd field after state
    except (IndexError, ValueError):
        return 0


def _linux_exe(pid: int) -> str | None:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None


def _linux_argv(pid: int) -> list[str] | None:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            raw = f.read()
    except OSError:
        return None
    if raw.endswith(b"\x00"):
        raw = raw[:-1]
    return [a.decode("utf-8", "replace") for a in raw.split(b"\x00")] if raw else []


def _linux_cmdline(pid: int) -> str | None:
    argv = _linux_argv(pid)
    return " ".join(argv).strip() if argv is not None else None


def _ppid(pid: int) -> int:
    return _mac_ppid(pid) if sys.platform == "darwin" else _linux_ppid(pid)


def _exe_path(pid: int) -> str | None:
    """Absolute executable path of a pid (by path, never by name)."""
    return _mac_exe(pid) if sys.platform == "darwin" else _linux_exe(pid)


def _cmdline(pid: int) -> str | None:
    return _mac_cmdline(pid) if sys.platform == "darwin" else _linux_cmdline(pid)


def _argv(pid: int) -> list[str] | None:
    return _mac_argv(pid) if sys.platform == "darwin" else _linux_argv(pid)


def _exe_name(pid: int) -> str:
    p = _exe_path(pid)
    return os.path.basename(p) if p else ""


# Public process helpers (by executable path, never by a name the process
# chose): other modules use these instead of the private names above.
def exe_path(pid: int) -> str | None:
    """Absolute executable path of `pid`, or None."""
    return _exe_path(pid)


def exe_name(pid: int) -> str:
    """Basename of `pid`'s executable path ("" if unknown)."""
    return _exe_name(pid)


def parent_pid(pid: int) -> int:
    """`pid`'s parent (0 if unknown); on macOS also for root's processes."""
    return _ppid(pid)


def started_at(pid: int) -> float | None:
    """When `pid` started (seconds since the epoch; exec keeps it), or None.
    SessionStart times itself with it (hooks_session.session_hook)."""
    if sys.platform == "darwin":
        info = _mac_bsdinfo(pid)
        return None if info is None else info.pbi_start_tvsec + info.pbi_start_tvusec / 1e6
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            raw = f.read()
        with open("/proc/stat", "rb") as f:
            btime = next(int(ln.split()[1]) for ln in f if ln.startswith(b"btime "))
        ticks = int(raw[raw.rfind(b")") + 2:].split()[19])    # field 22, starttime
        return btime + ticks / os.sysconf("SC_CLK_TCK")
    except (OSError, ValueError, IndexError, StopIteration):
        return None


def _claude_pid() -> int | None:
    v = os.environ.get("CLAUDE_PID", "")
    try:
        n = int(v)
    except ValueError:
        return None
    return n if n > 0 else None


def _is_checkpoint_runner(pid: int) -> bool:
    """The checkpoint plugin's job runner: a python interpreter (by executable
    path) running an existing `/…/checkpoint/…/run.py` with a later `server`
    argument. argv is caller-controlled, so this only raises the bar: code
    already running as the user can still dress up as the runner (see
    docs/dev/modules/sudo.md); it can't do so by renaming a shell or with a
    made-up path."""
    if not _PY_EXE.match(_exe_name(pid)):
        return False
    argv = _argv(pid) or []
    for k, a in enumerate(argv):
        if (os.path.isabs(a) and a.endswith("run.py") and _CHECKPOINT_RE.search(a)
                and os.path.isfile(a)):
            return "server" in argv[k + 1:]
    return False


def is_direct(tool: str, entry_scripts: bool = False) -> tuple[bool, str]:
    """(allowed, culprit). See the module docstring."""
    direct, culprit = walk_direct(os.getppid(), _claude_pid(), tool)
    if direct:
        return (True, "")
    # Not direct.
    if entry_scripts:
        return (True, culprit)       # scripts = true: credential allowed anyway
    return (False, culprit)


def walk_direct(pid: int, claude: int | None, tool: str) -> tuple[bool, str]:
    """is_direct's walk: from `pid` (the caller's parent) up to `claude`
    (CLAUDE_PID for a stand-in; the registered session for the gateway
    daemon, which judges its peers the same way). (direct, culprit)."""
    allowed = _allowed_names(tool)
    seen: set[int] = set()
    culprit = ""
    for _ in range(MAX_DEPTH):
        if pid <= 1 or pid in seen:
            break
        seen.add(pid)
        if claude is not None and pid == claude:
            return (True, "")        # reached Claude: direct
        if _is_checkpoint_runner(pid):
            return (True, "")        # the checkpoint job runner counts like Claude's shell
        name = _exe_name(pid)
        if not _is_allowed_name(name, allowed):
            culprit = name or "?"
            break                    # a non-allowed intermediate below Claude
        pid = _ppid(pid)
    else:
        culprit = culprit or "?"     # ran off MAX_DEPTH
    if not culprit:
        # Fell off the top (pid <= 1) without reaching Claude, or no CLAUDE_PID.
        culprit = "?"
    return (False, culprit)


def _same_process_image(pid: int, parent: int) -> bool:
    """Is `pid` a fork of `parent` that hasn't exec'd (same executable path and
    same argv)? An unreadable argv or path counts as no (fail closed)."""
    exe, pexe = _exe_path(pid), _exe_path(parent)
    if not exe or exe != pexe:
        return False
    argv, pargv = _argv(pid), _argv(parent)
    return argv is not None and argv == pargv and bool(argv)


def _under_checkpoint_runner(pid: int) -> bool:
    """Is checkpoint's job runner `pid` or one of its ancestors? (For the
    refusal's wording only: typed_by_claude refuses either way.)"""
    seen: set[int] = set()
    for _ in range(MAX_DEPTH):
        if pid <= 1 or pid in seen:
            return False
        seen.add(pid)
        if _is_checkpoint_runner(pid):
            return True
        pid = _ppid(pid)
    return False


def typed_by_claude() -> tuple[bool, str]:
    """(ok, culprit): was this stand-in started by a command Claude typed, i.e.
    by Claude's command shell or a fork of it, with nothing in between? See
    the module docstring. No CLAUDE_PID, or anything unreadable: not ok. A
    refusal under checkpoint's job runner has the culprit CHECKPOINT."""
    ok, culprit = _typed_walk()
    if not ok and culprit not in (CHECKPOINT, TERMINAL):
        try:
            if _under_checkpoint_runner(os.getppid()):
                return (False, CHECKPOINT)
        except Exception:  # noqa: BLE001 - wording only; the refusal stands
            pass
    return ok, culprit


def _typed_walk() -> tuple[bool, str]:
    claude = _claude_pid()
    if claude is None:
        return (False, "?")
    if _exe_name(claude) in SHELLS:
        # CLAUDE_PID names a shell, never Claude Code: a gateway terminal's or
        # job's own shell (gated's start file exports CLAUDE_PID=$$ for
        # is_direct). Claude Code asks about nothing run in a pane.
        return (False, TERMINAL)
    pid = os.getppid()
    seen: set[int] = set()
    for _ in range(MAX_DEPTH):
        if pid == claude:
            if _is_checkpoint_runner(pid):
                return (False, CHECKPOINT)
            return (True, "")        # Claude's command shell exec'd the stand-in itself
        if pid <= 1 or pid in seen:
            break
        seen.add(pid)
        name = _exe_name(pid)
        if name not in SHELLS:
            return (False, name or "?")
        parent = _ppid(pid)
        if parent == claude:
            # Claude's command shell, unless CLAUDE_PID names checkpoint's job
            # runner (a job's environment): nobody can be asked about a job
            if _is_checkpoint_runner(parent):
                return (False, CHECKPOINT)
            return (True, "")
        if not _same_process_image(pid, parent):
            return (False, name)     # a script or an `sh -c` shell of its own
        pid = parent
    return (False, "?")


# ---------------------------------------------------------------------------
# Started from Claude Code? (gate secret and the other one-time-code paths)
# ---------------------------------------------------------------------------

CLAUDE_EXE = "claude"
CLAUDE_VERSIONS = (".local", "share", "claude", "versions")
DESKTOP_CLAUDE = ("Library", "Application Support", "Claude", "claude-code")
# npm's @anthropic-ai/claude-code (any prefix: npm, pnpm, yarn, bun). From
# 2.1.113 its bin is bin/claude.exe, the platform package's native binary
# that the postinstall links or copies over a placeholder (npm view: the
# "bin" field; 2.1.308 checked 2026-10-22); its fallback launcher runs the
# platform package's binary, named claude. Before that, bin was cli.js, run
# by node: `node <...>/bin/claude ARGS`, the script a link to cli.js.
NPM_PACKAGE = "/node_modules/@anthropic-ai/claude-code/"
NPM_NATIVE = NPM_PACKAGE + "bin/claude.exe"
NPM_CLI = NPM_PACKAGE + "cli.js"
_NODE_EXE = re.compile(r"^node(?:js)?[0-9]*$")
SSHD_COMMS = frozenset({"sshd", "sshd-session"})
UNREADABLE = "a process tree that can't be read"


def is_claude_exe(exe: str, home: str | os.PathLike[str] | None = None) -> bool:
    """Is `exe` (an executable path from the kernel) Claude Code's binary?"""
    if os.path.basename(exe) == CLAUDE_EXE or exe.endswith(NPM_NATIVE):
        return True
    if home is None:
        return False
    bases = {os.fspath(home), os.path.realpath(home)}
    for b in bases:
        for sub in (CLAUDE_VERSIONS, DESKTOP_CLAUDE):
            d = os.path.join(b, *sub)
            if exe.startswith(d + os.sep):
                return True
    return False


def is_claude_node(exe: str, argv: list[str] | None) -> bool:
    """Is this an npm install of Claude Code before 2.1.113: an executable
    named node (nodejs, node22, ...) whose first argument, with no node
    option before it, is an absolute path that resolves to an existing
    .../node_modules/@anthropic-ai/claude-code/cli.js? (npm's shim runs
    `node <prefix>/bin/claude`, a link to cli.js. Options before the script
    could make another script the program, so they aren't accepted.)"""
    if not _NODE_EXE.match(os.path.basename(exe)) or not argv or len(argv) < 2:
        return False
    script = argv[1]
    if not os.path.isabs(script):
        return False
    try:
        real = os.path.realpath(script)
    except (OSError, ValueError):
        return False
    return real.endswith(NPM_CLI) and os.path.isfile(real)


def is_claude_process(pid: int, exe: str, home: str | os.PathLike[str] | None = None) -> bool:
    """Is `pid` (whose executable path is `exe`) Claude Code: its binary
    (is_claude_exe), or node running npm's cli.js (is_claude_node)?"""
    return is_claude_exe(exe, home) or is_claude_node(exe, _argv(pid))


def claude_install(exe: str, argv: list[str] | None = None,
                   home: str | os.PathLike[str] | None = None) -> str:
    """How the Claude Code whose executable is `exe` was installed, in words
    for /gate-doctor ("" when it isn't recognized as Claude Code)."""
    if is_claude_node(exe, argv):
        return "npm (node and cli.js, a version before 2.1.113)"
    if exe.endswith(NPM_NATIVE) or "/node_modules/@anthropic-ai/claude-code-" in exe:
        return "npm (its native binary)"
    if home is not None:
        for b in {os.fspath(home), os.path.realpath(home)}:
            if exe.startswith(os.path.join(b, *CLAUDE_VERSIONS) + os.sep):
                return "the native installer (~/.local/share/claude/versions)"
            if exe.startswith(os.path.join(b, *DESKTOP_CLAUDE) + os.sep):
                return "the desktop app's own copy"
    if os.path.basename(exe) == CLAUDE_EXE:
        return "an executable named claude (" + exe + ")"
    return ""


def _owner(pid: int) -> tuple[int | None, str]:
    """(effective uid or None, kernel comm name) of `pid`."""
    if sys.platform == "darwin":  # pragma: no cover - macOS only
        short = _mac_shortinfo(pid)
        if short is None:
            return None, ""
        return int(short.pbsi_uid), short.pbsi_comm.decode("utf-8", "replace")
    uid: int | None = None
    comm = ""
    try:
        with open(f"/proc/{pid}/status") as f:
            for line in f:
                if line.startswith("Uid:"):
                    uid = int(line.split()[2])
                    break
        with open(f"/proc/{pid}/stat", "rb") as fb:
            raw = fb.read()
        comm = raw[raw.find(b"(") + 1:raw.rfind(b")")].decode("utf-8", "replace")
    except (OSError, ValueError, IndexError):
        pass
    return uid, comm


def claude_ancestor(home: str | os.PathLike[str] | None = None) -> str | None:
    """Why this process counts as started from Claude Code (an ancestor's
    executable path, `CLAUDE_PID`, or UNREADABLE), or None. See the module
    docstring. A process of the user's own whose executable can't be read
    makes the answer UNREADABLE, but the walk goes on above it first: a
    Claude Code process further up is the better reason (review round 5:
    macOS can't read the path of an executable deleted or replaced while it
    runs, such as a login shell or tmux after `brew upgrade` or `port
    upgrade`, so UNREADABLE alone mostly means the user's own terminal)."""
    claude = _claude_pid()
    me = os.geteuid()
    pid = os.getppid()
    seen: set[int] = set()
    unreadable = False
    for _ in range(MAX_DEPTH):
        if pid <= 0 or pid in seen:
            return UNREADABLE
        seen.add(pid)
        if claude is not None and pid == claude:
            return "CLAUDE_PID"
        exe = _exe_path(pid)
        if exe:
            if is_claude_process(pid, exe, home):
                return exe
        else:
            uid, comm = _owner(pid)
            if comm == CLAUDE_EXE:
                return CLAUDE_EXE
            if uid is None:
                return UNREADABLE
            if uid == me and not (comm in SSHD_COMMS and _owner(_ppid(pid))[0] == 0):
                unreadable = True    # refused either way; look on for Claude Code above it
        if pid == 1:
            return UNREADABLE if unreadable else None
        pid = _ppid(pid)
    return UNREADABLE
