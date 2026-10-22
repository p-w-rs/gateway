"""Terminals and jobs: gated's tmux supervisor (PLAN-v4 phase 5).

docs/modules/terminals.md has the whole picture; in short:

- **One tmux server per user**, started by gated from the gateway env's tmux
  on a private socket in the run dir (<run>/tmux.sock) with the gateway's own
  config (<run>/tmux.conf: remain-on-exit, a history limit, no status bar, no
  clipboard, manual window sizes); the user's ~/.tmux.conf and tmux server
  are never touched. tmux runs detached, so the panes outlive a Claude Code
  restart, a plugin reload and gated itself.
- **A terminal** (`t_<ulid>`) is a tmux session with one window running the
  gateway env's interactive bash (no profile, no user rc) with the managed
  environment: the managed shell's PATH and rc (stand-ins first,
  docs/modules/managed.md), the platform variables and approved imports
  from the caller's environment, never a credential-looking name. **A job**
  (`j_<ulid>`) is the same with a command (argv, or a bash command string)
  run once. Values reach the pane through a 0600 start file in the run dir
  that the pane removes once read: never a command line.
- **Records** (<data>/gated/terminals.json, 0600): ids, host, workspace,
  cwd, owner session, agent, task_ref, owner (agent | user), state, exit:
  metadata only (never screen content, input or a secret). A restarted gated
  re-adopts the tmux sessions that are still there (matched by id and a
  per-pane nonce kept as a tmux option); a record whose session is gone is
  reported as gone (a terminal) or unknown (a job: its outcome can't be
  proven). Nothing is ever claimed alive from a saved pid: tmux is asked.
- **Reading**: `capture-pane -e` once per read; plain lines for the agent
  (the physical rows, bounded: rows, columns, history lines, bytes;
  scrubbed, a value across a soft wrap masked in each row it spans by the
  rejoined line, `_agent_rows`), styled runs for the terminal pane. `seq`
  counts screen changes (content, cursor, title, size, alternate screen) and
  every ownership change.
- **Writing**: one writer at a time. `owner` is "agent" or "user"; the user
  takes the input from the pane (a click, a key, the Take button) at once:
  queued agent writes then fail ("input taken by the user; re-read the
  screen"). An agent write quotes the seq it read and is refused when the
  screen moved on; handing the input back bumps seq, so the agent must read
  again. Among agents (the main loop, subagents) one holds the input; another
  takes it with a read (`take`). Text goes in through `load-buffer -` (stdin)
  and `paste-buffer -d`, named keys through `send-keys`: no typed text on a
  command line.
- **Password prompts**: every tick reads each live pane's tty mode (tcgetattr
  of the pane's tty). ECHO off with canonical input means a program waits for
  a password: the pane's owner session gets the gateway's credential dialog
  (daemon/dialogs.py, sealed intake); the value goes to that pane only, after
  a recheck (the same prompt and foreground process group still waiting), by
  paste-buffer, with the job's output pipe paused meanwhile; the agent and
  the transcript see "[credential supplied]". The pane refuses typed text
  from the terminal pane and the agent while such a prompt waits.
- **Jobs' output**: pipe-pane into a FIFO gated reads into a bounded ring
  (counts become job.output events; job_tail returns scrubbed text).
- **Pause** (CONTRACT-v1): per job `on_pause` = continue | interrupt |
  suspend | detach, with the outcome as it happened.
"""
from __future__ import annotations

import collections
import contextlib
import errno
import fcntl
import hashlib
import json
import os
import re
import secrets
import select
import shlex
import signal
import stat
import subprocess
import termios
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .. import paths, testing
from . import peers, screen

TICK = 0.25                  # the supervisor's tick while anything is live
IDLE_TICK = 1.0
SETTLE = 0.15                # after a write, before the screen is read back
MIN_COLS, MAX_COLS = 20, 400
MIN_ROWS, MAX_ROWS = 5, 150
DEFAULT_COLS, DEFAULT_ROWS = 120, 32
LINE_MAX = 1000              # characters of one line in a read
HISTORY_MAX = 2000           # history lines one read may ask for
VIEW_BYTES = 64 * 1024       # text of one read, all lines
RING_MAX = 256 * 1024        # a job's kept output
TAIL_MAX = 64 * 1024         # one job_tail
TEXT_MAX = 16 * 1024         # one write's text
KEYS_MAX = 64
DELAY_MAX_MS = 30_000
MAX_LIVE = 64                # live terminals and jobs at once
RETAIN_DEAD = 3600.0         # an exited pane's tmux session is kept this long for reads
RECORD_KEEP = 24 * 3600.0    # records (and idempotency keys) of ended panes
TMUX_GRACE = 5.0             # a failed list-panes query is tolerated this long before
                             # its panes are called gone (a transient tmux hiccup is not death)
LIST_MAX = 50                # terminal_list / job_list return at most this many to the agent
INTERRUPT_GRACE = 10.0       # on_pause interrupt: TERM after this
UI_POLL = 0.1                # the pane's long poll looks this often
WAIT_MAX = 25.0
ID_RE = re.compile(r"[tj]_[0-9A-HJKMNP-TV-Z]{26}")
_ULID = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
_SAFE_REF = re.compile(r"[A-Za-z0-9_.:@/+-]{1,120}")
ON_PAUSE = ("continue", "interrupt", "suspend", "detach")
# the variables a pane may take from its caller's environment besides the
# approved imports (managed conf env= and mine=): the platform's
PLATFORM_PASS = ("LANG", "TZ", "TMPDIR", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_CACHE_HOME",
                 "XDG_STATE_HOME", "XDG_RUNTIME_DIR", "__CF_USER_TEXT_ENCODING")
KEEP_NAMES = ("HOME|USER|LOGNAME|LANG|LC_*|TERM|TMPDIR|TZ|XDG_*|__CF_USER_TEXT_ENCODING|SHLVL|"
              "PWD|OLDPWD|COLUMNS|LINES")

TAKEN = "input taken by the user; re-read the screen"
REMOTE_SUDO_COMMS = ("sudo", "su", "doas", "sudoedit", "pkexec")
USER_HOLDS = ("gateway: the user holds this terminal's input (they took it in the terminal pane); "
              "wait until they hand it back, then read the screen again")
AUTH_WAITS = ("gateway: a password prompt waits in this terminal; the user answers it in the "
              "gateway's dialog (never type a password into a terminal); read the screen again "
              "after it is answered")
PAUSED = "gateway: the task is paused (checkpoint), so nothing is typed or started until it resumes"
DRAINING = ("gateway: the gateway was uninstalled, so it starts no new terminals, jobs or remote "
            "runtimes; what still runs is left to finish (terminal_list and job_list show it) and "
            "the gateway daemon exits after it")
# a pause that reaches a draining gated: contract.json is gone, so no consumer
# could resume what it suspended (Daemon.drain resumes what is suspended already)
PAUSE_DRAINING = ("gateway: the gateway was uninstalled, so it takes no new pause (nothing could "
                  "resume it); what still runs is left to finish and the gateway daemon exits after it")
# a job's STOP or TSTP reaching a draining gated: the drain resumed what was
# stopped when it began, and a job stopped later would keep gated, its tmux
# server and itself there forever once its session ends
STOP_DRAINING = ("gateway: the gateway was uninstalled, so it stops no job (nothing could resume "
                 "it); what still runs is left to finish and the gateway daemon exits after it")
# a job's STOP or TSTP that didn't hold (ps shows a member not stopped): it is
# continued and not recorded suspended, so nothing claims a stop that isn't there
NOT_STOPPED = ("the job doesn't show as stopped after the stop (a job that is only its pane's own "
               "process can't be stopped, tmux continues that one; or one of its processes ended "
               "meanwhile), so it was continued and runs on")
NOT_STOPPED_AGAIN = ("the job doesn't show as stopped after the stop; it stays recorded as "
                     "suspended by the earlier stop (resuming it continues it)")
STOP_REQ_WORDS = {"undelivered": "not delivered (the host couldn't be reached; nothing was stopped)",
                  "unsure": "outcome unknown (the close went out, its answer was lost; the host is "
                            "asked)"}
UNCONFIRMED = ("gateway: {id}'s start on {host} isn't confirmed yet (its answer was lost); nothing "
               "is sent to it until the host says whether it started (read its state again)")

TMUX_CONF = """# gateway: gated's own tmux server (PLAN-v4 phase 5); not the user's config
set -g remain-on-exit on
set -g history-limit 10000
set -g status off
set -g set-clipboard off
set -g window-size manual
set -g aggressive-resize off
set -g mouse off
set -g set-titles off
set -g allow-rename off
set -g allow-passthrough off
set -g monitor-activity off
set -g visual-activity off
set -g focus-events off
set -g update-environment ""
set -g default-terminal "screen-256color"
set -s escape-time 0
set -s exit-empty on
"""

# gated's own (local) server only: a watchdog session that stops the server
# once its socket is gone or replaced (the run dir removed after gated was
# stopped, e.g. by SIGTERM: nobody can reach that server or its panes again),
# or once gated is gone (it exited, was uninstalled, or was killed) and no
# pane of the server runs anything any more (dead panes kept for reads are
# all that is left), and a hook that lets the server end as before when the
# last real session closes (exit-empty), the watchdog being all that is left.
WATCH_SESSION = "gw-watch"
WATCH_TICK = 5               # seconds between the watchdog's looks
LOCAL_TMUX_CONF = (
    "set-hook -g session-closed "
    "'if -F \"#{==:#{server_sessions},1}\" \"kill-session -t =" + WATCH_SESSION + "\"'\n")
# ps as gated and its watchdog both run it for a start time: one locale and one
# time zone, so the same process prints the same words in both
PS_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "TZ": "UTC0"}
# Run by the server itself (tmux execs it without a shell: the watchdog's
# parent is the server): `sh -c SCRIPT gw-watch <tmux socket> <gated socket>
# <seconds> <gated pid file>`. It notes the socket's inode and checks every
# few seconds that the same socket is still there (a new server's socket at
# the same path is another inode). gated is gone when its socket is missing
# (it exited), or when the socket is still there but the pid file next to it
# (paths.gated_pid: `<pid> <start time>`, written before gated listens, so a
# restarted gated names itself before its socket replaces the old one) names
# a process that is dead (kill -0 fails: gone, or another user's), a zombie,
# or another process (ps shows another start time): a SIGKILL, a crash or the
# OOM killer leave the socket file behind. A pid file that is missing or
# unreadable, or a ps that can't say, counts as gated alive. While gated is
# gone it counts the server's children that have a terminal (each live pane's
# process, this watchdog's own included; a dead pane has none, a pipe-pane
# helper has no tty): only itself left, it stops the server. A listing it
# can't read (no ps, an odd format: its own pane not seen) never stops
# anything.
WATCH_SCRIPT = (
    's=$1; g=${2-}; t=${3:-5}; f=${4-}; set -- $(ls -di "$s" 2>/dev/null); i=${1-}; '
    '[ -n "$i" ] || exit 0; '
    'while sleep "$t"; do [ -S "$s" ] || break; set -- $(ls -di "$s" 2>/dev/null); '
    '[ "${1-}" = "$i" ] || break; '
    '[ -n "$g" ] || continue; '
    'if [ -S "$g" ]; then [ -n "$f" ] && [ -f "$f" ] || continue; p=; l=; '
    'read -r p l 2>/dev/null < "$f"; case "$p" in ""|*[!0-9]*) continue;; esac; '
    'if kill -0 "$p" 2>/dev/null; then '
    'c=$(LC_ALL=C TZ=UTC0 ps -o stat= -o lstart= -p "$p" 2>/dev/null) || continue; '
    'set -- $c; [ "$#" -ge 2 ] || continue; '
    'case "$1" in Z*) ;; *) shift; [ -n "$l" ] && [ "$*" != "$l" ] || continue;; esac; '
    'fi; fi; '
    'o=$(ps -A -o ppid= -o tty= 2>/dev/null) || continue; '
    'n=$(printf "%s\\n" "$o" | awk -v p="$PPID" \'$1 == p && $2 !~ /^[?]+$/ { n++ } END { print n + 0 }\'); '
    '[ "$n" -ge 1 ] 2>/dev/null || continue; [ "$n" -gt 1 ] || break; '
    'done; kill -TERM "$PPID"')


class TermError(Exception):
    """A refused or failed terminal/job request: (http status, code, message)."""

    def __init__(self, status: int, code: str, message: str, **extra: Any):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra


def ulid(prefix: str) -> str:
    """<prefix>_<26 Crockford base32>: 48 bits of milliseconds, 80 random."""
    n = (int(time.time() * 1000) << 80) | int.from_bytes(os.urandom(10), "big")
    out = []
    for _ in range(26):
        out.append(_ULID[n & 31])
        n >>= 5
    return f"{prefix}_{''.join(reversed(out))}"


def _clean(s: Any, limit: int = 120) -> str:
    if not isinstance(s, str):
        return ""
    return "".join(c for c in s if c.isprintable())[:limit]


def _q(s: str) -> str:
    return shlex.quote(s)


# ---------------------------------------------------------------------------
# tmux
# ---------------------------------------------------------------------------


INFO_FIELDS = ("session_name", "@gw_nonce", "pid", "pane_pid", "pane_tty", "pane_dead",
               "pane_dead_status", "pane_dead_signal", "pane_width", "pane_height", "cursor_x",
               "cursor_y", "alternate_on", "history_size", "pane_current_command", "pane_title")
SEP = "\x1f"


class Tmux:
    def __init__(self, binary: str, sock: Path, conf: Path, env: dict[str, str]):
        self.binary, self.sock, self.conf, self.env = binary, sock, conf, env
        self.server_pid = 0                # the server's pid, as tmux last said
        self.server_start: float | None = None   # and its start time (a reused pid has another)

    def argv(self, *args: str) -> list[str]:
        return [self.binary, "-u", "-S", str(self.sock), "-f", str(self.conf), *args]

    def runnable(self) -> bool:
        """Can this tmux still be run? Not once the env it lives in is gone
        (a plain `claude plugin uninstall` deletes the plugin's data folder):
        then no query can reach the server, which runs on from the deleted
        files."""
        return os.path.isfile(self.binary) and os.access(self.binary, os.X_OK)

    def run(self, *args: str, input: bytes | None = None, timeout: float = 10.0,
            check: bool = True, insist: bool = False) -> bytes:
        try:
            r = subprocess.run(self.argv(*args), input=input, capture_output=True,
                               timeout=timeout, env=self.env, cwd="/",
                               stdin=None if input is not None else subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as e:
            raise TermError(500, "tmux", f"gateway: the terminal supervisor (tmux) failed "
                            f"({type(e).__name__})") from None
        if check and r.returncode != 0:
            raise TermError(500, "tmux", "gateway: the terminal supervisor (tmux) refused: "
                            + _clean(r.stderr.decode("utf-8", "replace"), 200))
        return r.stdout

    def panes(self) -> dict[str, dict[str, str]] | None:
        """Every pane of the private server by session name; None when no
        server answers (none was started, or it is gone)."""
        fmt = SEP.join("#{" + f + "}" for f in INFO_FIELDS)
        try:
            r = subprocess.run(self.argv("list-panes", "-a", "-F", fmt), capture_output=True,
                               timeout=10, env=self.env, cwd="/", stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired):
            return None
        if r.returncode != 0:
            return None
        out: dict[str, dict[str, str]] = {}
        for line in r.stdout.decode("utf-8", "replace").splitlines():
            parts = line.split(SEP, len(INFO_FIELDS) - 1)
            if len(parts) != len(INFO_FIELDS):
                continue
            d = dict(zip(INFO_FIELDS, parts))
            out.setdefault(d["session_name"], d)
            if d.get("pid", "").isdigit() and int(d["pid"]) != self.server_pid:
                self.server_pid = int(d["pid"])
                self.server_start = peers.started(self.server_pid)
        return out


# ---------------------------------------------------------------------------
# A pane's record
# ---------------------------------------------------------------------------

RECORD = ("id", "kind", "nonce", "host", "host_id", "workspace", "cwd", "created", "session_pid",
          "session_start", "session_id", "agent", "owner", "holder", "task_ref", "command",
          "on_pause", "idempotency_key", "state", "exit", "signal", "ended", "seq", "cols", "rows",
          "detached", "paused_as", "cancel", "closing", "gone", "via", "title",
          # a remote pane (PLAN-v4 phase 6): its runtime folder on the host, the
          # host's machine token when it started, why the host can't be reached;
          # whether its start is still unconfirmed (recorded before the start went
          # to the host; the answer may have been lost), a stop asked but not
          # (or not provably) delivered
          "rt", "machine", "remote_note", "unconfirmed", "stop_req")


class Pane:
    def __init__(self, **kw: Any):
        self.id: str = kw["id"]
        self.kind: str = kw.get("kind") or ("job" if self.id.startswith("j_") else "terminal")
        self.nonce: str = kw.get("nonce") or secrets.token_hex(8)
        self.host: str = kw.get("host", "localhost")
        self.host_id: str = kw.get("host_id", "")
        self.workspace: str = kw.get("workspace", "")
        self.cwd: str = kw.get("cwd", "")
        self.created: float = float(kw.get("created") or time.time())
        self.session_pid: int = int(kw.get("session_pid") or 0)
        self.session_start: float | None = kw.get("session_start")
        self.session_id: str = kw.get("session_id", "")
        self.agent: str = kw.get("agent", "")
        self.owner: str = kw.get("owner", "agent")          # agent | user
        self.holder: str | None = kw.get("holder")          # the agent holding the input
        self.task_ref: str = kw.get("task_ref", "")
        self.command: str = kw.get("command", "")           # scrubbed, for display
        self.on_pause: str = kw.get("on_pause", "continue")
        self.idempotency_key: str = kw.get("idempotency_key", "")
        self.state: str = kw.get("state", "starting")
        self.exit: int | None = kw.get("exit")
        self.signal: str | None = kw.get("signal")
        self.ended: float | None = kw.get("ended")
        self.seq: int = int(kw.get("seq") or 1)
        self.cols: int = int(kw.get("cols") or DEFAULT_COLS)
        self.rows: int = int(kw.get("rows") or DEFAULT_ROWS)
        self.detached: bool = bool(kw.get("detached", False))
        self.paused_as: str = kw.get("paused_as", "")        # what a pause did: suspended, interrupted
        self.cancel: bool = bool(kw.get("cancel", False))    # a stop was asked (job_signal TERM/KILL)
        self.closing: bool = bool(kw.get("closing", False))
        self.gone: bool = bool(kw.get("gone", False))
        self.via: str = kw.get("via", "agent")               # agent | ui | contract
        self.title: str = kw.get("title", "")
        self.rt: str = kw.get("rt", "")                      # remote: the runtime folder on the host
        self.machine: str = kw.get("machine", "")            # remote: the host's machine token
        self.remote_note: str = kw.get("remote_note", "")    # remote: why the host can't be reached
        # remote: recorded before the start went to the host and not confirmed
        # since (its answer may have been lost: the host is asked, never assumed)
        self.unconfirmed: bool = bool(kw.get("unconfirmed", False))
        # a close/stop asked while the host couldn't take it: "undelivered" (it
        # never reached the host) or "unsure" (its answer was lost); the final
        # state stays what the host says, never "canceled" because of it
        self.stop_req: str = kw.get("stop_req", "")
        # live, never persisted
        self.dispatching = False           # remote: the start is on its way to the host now
        self.dispatched_at = 0.0           # remote: when its answer came (or was lost); only a
                                           # look fetched after that may call the pane lost
        self.pending_bufs: list[str] = []  # remote: input buffers whose paste's outcome was lost
                                           # (removed at the host's next answer: no late paste)
        self.hash = ""
        self.pane_pid = 0
        self.pane_start: float | None = None   # the pane process's start time (with pane_pid)
        self.tty = ""
        self.alive = False
        self.alt = False
        self.cursor = (0, 0)
        self.history = 0
        self.fg = ""                       # tmux's pane_current_command
        self.owner_gen = 0                 # every ownership change
        self.echo_off = False              # the tty: ECHO off with canonical input
        self.auth: dict[str, Any] | None = None
        self.last_auth = ""                # "[credential supplied]" after a supply
        self.secrets: list[str] = []       # supplied values >= 8 chars, for scrubbing (memory only)
        self.write_lock = threading.Lock()
        self.queued = 0
        self.ring = bytearray()
        self.total = 0                     # output bytes seen (jobs)
        self.reported = 0                  # bytes already in a job.output event
        self.reported_at = 0.0
        self.fifo: Path | None = None
        self.fifo_fds: tuple[int, int] | None = None
        self.reader: threading.Thread | None = None
        self.timers: list[threading.Timer] = []
        self.seen = not self.remote        # remote: confirmed by the host since gated started

    @property
    def remote(self) -> bool:
        return self.host != "localhost"

    def to_json(self) -> dict[str, Any]:
        return {k: getattr(self, k) for k in RECORD}

    @property
    def target(self) -> str:
        return f"={self.id}:"

    @property
    def live(self) -> bool:
        return self.ended is None and not self.gone

    def session_key(self) -> str:
        return self.session_id or f"pid:{self.session_pid}"


def session_key(s: Any) -> str:
    return (getattr(s, "session_id", "") or f"pid:{getattr(s, 'pid', 0)}") if s is not None else ""


# ---------------------------------------------------------------------------
# The managed environment a pane gets
# ---------------------------------------------------------------------------


def read_conf() -> dict[str, str]:
    """The managed shell's conf (managed.py writes it): bash, rc, path, env,
    mine. {} when it isn't there yet."""
    from .. import managed
    try:
        text = managed.conf_path().read_text(encoding="utf-8")
    except OSError:
        return {}
    out: dict[str, str] = {}
    for line in text.splitlines():
        if line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        out[k.strip()] = v
    return out


def env_plan(caller_env: Any) -> tuple[str, str, dict[str, str], str]:
    """(bash, managed rc or "", the variables to export, PATH) for a new pane."""
    from .. import managed
    conf = read_conf()
    bash = conf.get("bash") or ""
    if not (bash and os.path.isabs(bash) and os.access(bash, os.X_OK)):
        try:
            bash = paths.tool("bash")
        except Exception:  # noqa: BLE001
            raise TermError(503, "no_bash", "gateway: the gateway's bash isn't there (its env is "
                            "still being set up?); /gate-doctor says what is happening") from None
    rc = conf.get("rc") or ""
    if not (rc and os.path.isabs(rc) and os.path.isfile(rc)):
        rc = ""
    path = conf.get("path") or ":".join([str(paths.bin_dir()), str(managed.runtime_dir()),
                                         *managed.SYSTEM_DIRS])
    allowed_imports = set(conf.get("env", "").split())
    mine = set(conf.get("mine", "").split())
    exports: dict[str, str] = {}
    given = caller_env if isinstance(caller_env, dict) else {}
    for name, value in list(given.items())[:200]:
        if not isinstance(name, str) or not isinstance(value, str) or not _NAME.fullmatch(name):
            continue
        if "\x00" in value or len(value) > 8192:
            continue
        platform = name in PLATFORM_PASS or name.startswith("LC_")
        if platform or (name in allowed_imports and not managed.credential_like(name)) or \
                name in mine:
            exports[name] = value
    exports["HOME"] = str(paths.user_home())
    user = paths.local_user()
    exports["USER"] = user
    exports["LOGNAME"] = user
    exports["SHELL"] = bash
    exports.setdefault("LANG", os.environ.get("LANG") or "C.UTF-8")
    return bash, rc, exports, path


def start_text(p: Pane, *, rc: str, exports: dict[str, str], path: str, me: Path,
               argv: list[str] | None = None, command: str | None = None) -> str:
    """The pane's start file: an interactive bash's --rcfile (a terminal) or
    the script a job's bash runs. It removes itself once read."""
    lines = [f"# gateway {p.kind} {p.id} (PLAN-v4 phase 5): written by gated, read once, removed",
             "for __gw_n in $(compgen -e); do",
             f"  case $__gw_n in {KEEP_NAMES}) ;; *) unset \"$__gw_n\" ;; esac",
             "done; unset __gw_n"]
    for k, v in sorted(exports.items()):
        lines.append(f"export {k}={_q(v)}")
    lines.append(f"export PATH={_q(path)}")
    lines.append(f"export GW_TERMINAL={_q(p.id)}")
    # the stand-ins' direct rule (ancestry): this pane's shell stands where
    # Claude Code's command shell does, so a command typed here is direct and
    # one a script runs is not
    lines.append("export CLAUDE_PID=$$")
    if rc:
        lines.append(f"[ -r {_q(rc)} ] && . {_q(rc)}")
    lines.append(f"command rm -f -- {_q(str(me))}")
    lines.append(f"cd -- {_q(p.cwd)} 2>/dev/null || cd")
    if p.kind == "terminal":
        lines += ["unset HISTFILE", "HISTSIZE=2000",
                  "PS1='\\[\\e[1m\\]\\u@\\h:\\w\\[\\e[0m\\]\\$ '",
                  "PROMPT_COMMAND=", "set +o histexpand"]
        return "\n".join(lines) + "\n"
    lines.append("unset HISTFILE")
    if argv is not None:
        # a child of this bash, never exec'd: the stand-ins' direct rule then
        # sees the program as a command this pane's shell ran (as in a
        # terminal), and its own children as a script's
        lines.append(" ".join(_q(a) for a in argv))
    else:
        lines.append(command or ":")
    return "\n".join(lines) + "\n"


def _remote_path_expr(rt: str, imports: list[str], system: str) -> str:
    """The remote PATH as a shell word: the runtime's bin, the host's
    approved import folders (~/... from the host's $HOME), the system folders."""
    parts = [_q(rt + "/env/bin")]
    for d in imports:
        if d == "~":
            parts.append('"$HOME"')
        elif d.startswith("~/"):
            parts.append('"$HOME"' + _q(d[1:]))
        else:
            parts.append(_q(d))
    parts.append(_q(system))
    return ":".join(parts)


def remote_start_text(p: Pane, *, rt: str, lang: str, me: str, argv: list[str] | None = None,
                      command: str | None = None, imports: list[str] | None = None,
                      env_file: str = "", env_names: list[str] | None = None) -> str:
    """A remote pane's start file (PLAN-v4 phase 6): the runtime's bash with
    the remote managed environment: every variable but the platform's unset
    (the runtime's tmux server itself starts under env -i), the curated PATH
    (the runtime's bin, then the system folders: never the login PATH), the
    gateway's remote rc (never the user's), then it removes itself."""
    from .remote import SYSTEM_PATH
    lines = [f"# gateway remote {p.kind} {p.id} (PLAN-v4 phase 6): written by gated, read once, "
             "removed",
             # the start's claim (RemoteTmux.claim_start): the shell has this file
             # open and renames it; gated settles a start whose answer it lost by
             # renaming it too. Exactly one rename succeeds: when gated's did (the
             # start counts as never run), this one fails and nothing below runs
             f"command mv -f -- {_q(me)} {_q(me + '.run')} 2>/dev/null || exit 125",
             "for __gw_n in $(compgen -e); do",
             f"  case $__gw_n in {KEEP_NAMES}) ;; *) unset \"$__gw_n\" ;; esac",
             "done; unset __gw_n",
             f"export PATH={_remote_path_expr(rt, imports or [], SYSTEM_PATH)}",
             f"export SHELL={_q(rt + '/env/bin/bash')}",
             f"export LANG={_q(lang)}",
             f"export GW_TERMINAL={_q(p.id)}",
             f"export GW_RUNTIME={_q(rt)}"]
    if env_file and env_names:
        # the host's approved import_env values, captured on the host into one
        # file per name (PLAN-v4 phase 7): read back by name, then removed
        pat = "|".join(n for n in env_names if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", n))
        lines += [f"for __gw_f in {_q(env_file)}/*; do",
                  '  [ -f "$__gw_f" ] || continue; __gw_n=${__gw_f##*/}',
                  f'  case $__gw_n in {pat}) export "$__gw_n=$(command cat -- "$__gw_f")" ;; esac',
                  f"done; command rm -rf -- {_q(env_file)}; unset __gw_f __gw_n"]
    lines += [
             f"[ -r {_q(rt + '/gateway.rc')} ] && . {_q(rt + '/gateway.rc')}",
             f"command rm -f -- {_q(me + '.run')}",
             f"cd -- {_q(p.cwd)} 2>/dev/null || cd"]
    if p.kind == "terminal":
        return "\n".join(lines) + "\n"
    lines.append("unset HISTFILE")
    if argv is not None:
        lines.append(" ".join(_q(a) for a in argv))
    else:
        lines.append(command or ":")
    return "\n".join(lines) + "\n"


def _write_private(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


# ---------------------------------------------------------------------------
# tty facts
# ---------------------------------------------------------------------------


def tty_mode(tty: str) -> tuple[bool, bool] | None:
    """(echo, canonical) of a pane's tty, or None when it can't be read.
    Opened without becoming anyone's controlling terminal, and closed at
    once (a slave held open would keep a dead pane's tty from hanging up)."""
    if not tty.startswith("/dev/"):
        return None
    try:
        fd = os.open(tty, os.O_RDONLY | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISCHR(st.st_mode) or st.st_uid != os.getuid():
            return None
        lflag = termios.tcgetattr(fd)[3]
        return bool(lflag & termios.ECHO), bool(lflag & termios.ICANON)
    except (OSError, termios.error):
        return None
    finally:
        os.close(fd)


def foreground_pgrp(pid: int) -> int:
    """The foreground process group of `pid`'s controlling terminal (ps's
    tpgid), 0 when unknown."""
    if pid <= 0:
        return 0
    try:
        r = subprocess.run(["/bin/ps", "-o", "tpgid=", "-p", str(pid)], capture_output=True,
                           text=True, timeout=5, env={"PATH": "/usr/bin:/bin"},
                           stdin=subprocess.DEVNULL)
        return int(r.stdout.strip() or 0)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return 0


def ps_start(pid: int) -> str:
    """`pid`'s start time as the tmux watchdog reads it (ps's lstart under
    PS_ENV, its words single-spaced); "" when ps can't say."""
    if pid <= 0:
        return ""
    try:
        r = subprocess.run(["/bin/ps", "-o", "lstart=", "-p", str(pid)], capture_output=True,
                           text=True, timeout=5, env=dict(PS_ENV), stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return " ".join(r.stdout.split()) if r.returncode == 0 else ""


def group_members(pgid: int) -> dict[int, str]:
    """pid -> ps state of every process in process group `pgid`."""
    try:
        r = subprocess.run(["/bin/ps", "-axo", "pid=,pgid=,stat="], capture_output=True, text=True,
                           timeout=5, env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    out: dict[int, str] = {}
    for line in r.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].isdigit() and parts[1] == str(pgid):
            out[int(parts[0])] = parts[2]
    return out


def stop_group(pgid: int, root: int) -> bool:
    """Suspend a pane's process group; True when every member but the root
    shows stopped (and there is one), or the root itself does. tmux resumes a
    pane's own process (its child) when SIGSTOP stops it (server_child_stopped
    sends SIGCONT for any stop but SIGTTIN/SIGTTOU), so the pane's root process
    gets SIGTTOU and the rest SIGSTOP. The pane's group is orphaned (its
    leader's parent is the tmux server, in another session), so the kernel
    drops SIGTTOU (and SIGTSTP) there: the root, a shell waiting for its
    children, runs on, and a job that is only its root can't be stopped."""
    members = group_members(pgid)
    if not members:
        return False
    for pid in members:
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGTTOU if pid == root else signal.SIGSTOP)
    time.sleep(0.15)
    after = group_members(pgid)
    others = [st for pid, st in after.items() if pid != root]
    return bool(after) and all(st.startswith("T") for st in others) and \
        (bool(others) or after.get(root, "").startswith("T"))


def align_rows(joined: list[str], rows: list[str]) -> list[list[int]] | None:
    """For each logical line of `capture-pane -J` the indexes of the physical
    rows (`capture-pane -N -T`, same region, same command) it joins: each
    logical line is its rows' text end to end (tmux joins a soft-wrapped row
    with the next). None when they don't line up (the caller then reads the
    logical lines)."""
    out: list[list[int]] = []
    i = 0
    for ln in joined:
        if i >= len(rows):
            return None
        acc, idx = rows[i], [i]
        i += 1
        while acc != ln:
            if i >= len(rows) or not ln.startswith(acc):
                return None
            acc += rows[i]
            idx.append(i)
            i += 1
        out.append(idx)
    return out if i == len(rows) else None


def mask_rows(rows: list[str], joined: list[str], groups: list[list[int]],
              spans_of: Callable[[str], list[tuple[int, int]]]) -> list[str]:
    """The physical rows with what the scrubber finds in each logical line
    masked in every row it spans (each masked run in a row becomes `***`): a
    value printed across a soft-wrap boundary is masked in both rows, never
    left as two halves to splice. A line of one row is left to the row's own
    scrub."""
    out = list(rows)
    for ln, idx in zip(joined, groups):
        if len(idx) < 2:
            continue
        spans = spans_of(ln)
        if not spans:
            continue
        off = 0
        for i in idx:
            r = rows[i]
            a, b = off, off + len(r)
            off = b
            hit = [(max(s, a) - a, min(e, b) - a) for s, e in spans if s < b and e > a]
            if not hit:
                continue
            parts, pos = [], 0
            for s, e in hit:                  # sorted and disjoint (merged spans)
                parts += [r[pos:s], "***"]
                pos = e
            parts.append(r[pos:])
            out[i] = "".join(parts)
    return out


def signal_word(sg: str | None) -> str | None:
    """tmux's #{pane_dead_signal} as a name: macOS's tmux says "term", Linux's
    says "15"; both are "TERM" here."""
    if not sg:
        return None
    if sg.isdigit():
        try:
            return signal.Signals(int(sg)).name.removeprefix("SIG")
        except ValueError:
            return sg
    return sg.upper().removeprefix("SIG") if re.fullmatch(r"[A-Za-z0-9]{1,12}", sg) else None


def _exe_word(pid: int) -> str:
    """A foreground program for the dialog: its executable path from the
    kernel (never argv), or, where that can't be read (a setuid program such
    as sudo runs as root), the kernel's short name for it, said to be only a
    name. Limited to a safe shape."""
    e = peers.exe(pid) or ""
    if re.fullmatch(r"/[A-Za-z0-9_./+@-]{1,200}", e):
        return e
    try:
        r = subprocess.run(["/bin/ps", "-o", "comm=", "-p", str(pid)], capture_output=True, text=True,
                           timeout=5, env={"PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL)
        name = os.path.basename(r.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        name = ""
    if re.fullmatch(r"[A-Za-z0-9_.+@-]{1,40}", name):
        return (f"{name} (the kernel's name for it only; its executable can't be read — it may be "
                "setuid like the real sudo, or it was replaced or deleted after it started)")
    return ""


# ---------------------------------------------------------------------------
# The supervisor
# ---------------------------------------------------------------------------


class Supervisor:
    """`daemon` gives registry, dialogs, events, log, machine_id()."""

    def __init__(self, daemon: Any, *, state_path: Path | None = None, sock: Path | None = None,
                 conf: Path | None = None, terms: Path | None = None):
        self.d = daemon
        self.state_path = state_path or paths.gated_terminals()
        self.sock = sock or paths.gated_tmux_socket()
        self.conf = conf or paths.gated_tmux_conf()
        self.terms = terms or paths.gated_terms_dir()
        self.lock = threading.RLock()
        self.cond = threading.Condition(self.lock)
        self.panes: dict[str, Pane] = {}
        self.idem: dict[str, tuple[str, float]] = {}
        self.idem_pending: set[str] = set()     # keys whose job is being started right now
        self.tool_agents: dict[str, tuple[str, str, float]] = {}   # tool_use_id -> (session key, agent, t)
        self.closed_dialogs: collections.deque[tuple[str, str]] = collections.deque()
        self.stopping = threading.Event()
        self.thread: threading.Thread | None = None
        self._dirty = False
        self._tmux: Tmux | None = None
        self.rev = 1
        self._panes_ok_at = time.time()      # last time list-panes answered (transient-failure grace)
        # one tick at a time (the loop, and a signal or a pause that looks at
        # once): two at once could open two dialogs for one password prompt
        self._tick_lock = threading.Lock()
        # remote hosts (PLAN-v4 phase 6): one poller thread per host with live
        # panes (daemon/remote.py runs the commands over ssh)
        self.pollers: dict[str, threading.Thread] = {}

    # -- setup -------------------------------------------------------------------
    @property
    def tmux(self) -> Tmux:
        if self._tmux is None:
            binary = testing.get("tmux") or ""
            if not binary:
                try:
                    binary = paths.tool("tmux")
                except Exception:  # noqa: BLE001
                    raise TermError(503, "no_tmux", "gateway: the gateway env has no tmux yet (it "
                                    "is still being set up, or it predates terminals); a new "
                                    "session sets it up; /gate-doctor says more") from None
            env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(paths.user_home()),
                   "LANG": os.environ.get("LANG") or "C.UTF-8"}
            tmp = os.environ.get("TMPDIR", "")
            if tmp and os.path.isabs(tmp):
                env["TMPDIR"] = tmp
            self._tmux = Tmux(binary, self.sock, self.conf, env)
        return self._tmux

    def _tm(self, p: Pane) -> Any:
        """The tmux a pane lives in: gated's own (localhost) or the runtime's
        on its host (daemon/remote.RemoteTmux), bound to the host record and
        its machine: a pane started on one machine is never reached on
        another."""
        if not p.remote:
            return self.tmux
        rh = self.d.remote.get(p.host)
        if p.machine and rh.machine and p.machine != rh.machine:
            raise TermError(410, "machine", f"gateway: {p.host} is another machine than the one "
                            f"{p.id} started on; it can't be reached through this host")
        if not p.rt:
            raise TermError(410, "gone", f"gateway: {p.id} has no runtime folder on {p.host}")
        return rh.tmux(p.rt)

    def start(self) -> None:
        try:
            self.terms.mkdir(parents=True, exist_ok=True)
            os.chmod(self.terms, 0o700)
            fd = os.open(self.conf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(TMUX_CONF + LOCAL_TMUX_CONF)
        except OSError as e:
            self.d.log(f"terminals: can't write the tmux config ({type(e).__name__})")
        self._load()
        try:
            self.adopt()
        except Exception as e:  # noqa: BLE001
            self.d.log(f"terminals: adopting failed ({type(e).__name__})")
        self.thread = threading.Thread(target=self._loop, daemon=True, name="gw-terminals")
        self.thread.start()

    def abandon(self) -> None:
        """gated leaves because its run dir was removed: the tmux socket went
        with it, so nobody can reach that tmux server again (a tmp cleaner;
        the test harnesses delete their run dirs). Its terminals are lost;
        stop the unreachable server rather than leave it running. Only the
        pid tmux itself reported, and only while it is still the gateway's
        tmux (by executable)."""
        if self._tmux is None:
            return
        pid = self._tmux.server_pid
        if pid <= 0 or self.sock.exists():
            return
        binary = os.path.realpath(self._tmux.binary)
        exe = peers.exe(pid) or ""
        # the pid may have been reused by another server of the same tmux binary
        # (a remote runtime's on this machine, another test's): it must also be
        # the server of THIS socket (a tmux server keeps the command line of the
        # client that started it, which names `-S <sock>`)
        av = peers.argv(pid) or []
        if exe and os.path.realpath(exe) == binary and str(self.sock) in av:
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGTERM)
            self.d.log("terminals: the tmux socket is gone with the run dir; its server was stopped")

    def stop_server(self) -> None:
        """gated is exiting (any reason but its run dir going: abandon): its
        local tmux server and the watchdog go too once no terminal or job runs
        there, so dead panes kept for reads don't linger with nobody to read
        them. A live pane keeps the server: a restarted gated re-adopts it (a
        SIGTERM, an update), and the watchdog stops the server once gated is
        gone and that pane has ended too. Asked of tmux (kill-server); when the
        env's tmux can't be run any more (an uninstall deleted it) and no
        record says a local pane is alive, the server tmux last named is sent
        SIGTERM: only that pid with the start time tmux's answer had, and only
        while its command line names this socket."""
        tm = self._tmux
        if tm is None:
            return
        if tm.runnable():
            infos = tm.panes()
            if infos is None:
                return                           # no server answers: nothing to stop
            live = sorted(n for n, i in infos.items()
                          if n != WATCH_SESSION and i.get("pane_dead") != "1")
            if live:
                self.d.log(f"terminals: {len(live)} pane(s) still run; the tmux server is kept "
                           "for the next gated")
                return
            with contextlib.suppress(TermError):
                tm.run("kill-server", check=False)
            self.d.log("terminals: no terminal or job runs; the tmux server was stopped")
            return
        with self.lock:
            if any(p.alive and not p.remote for p in self.panes.values()):
                return
        pid = tm.server_pid
        if pid <= 0 or not peers.alive(pid, tm.server_start):
            return
        if str(self.sock) not in (peers.argv(pid) or []):
            return
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGTERM)
        self.d.log("terminals: no terminal or job runs and the gateway's tmux can't be run any more; "
                   "its server was stopped")

    def stop(self) -> None:
        self.stopping.set()
        with self.lock:
            for p in self.panes.values():
                for t in p.timers:
                    t.cancel()
                self._close_fifo(p)
            self._save()

    # -- persistence ---------------------------------------------------------------
    def _load(self) -> None:
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(raw, dict):
            return
        now = time.time()
        for d in raw.get("panes") or []:
            try:
                p = Pane(**{k: d[k] for k in RECORD if k in d})
            except (KeyError, TypeError, ValueError):
                continue
            if not ID_RE.fullmatch(p.id):
                continue
            if p.ended is not None and now - p.ended > RECORD_KEEP:
                continue
            self.panes[p.id] = p
        for k, v in (raw.get("idem") or {}).items():
            if isinstance(v, list) and len(v) == 2 and isinstance(v[0], str) and \
                    isinstance(v[1], (int, float)) and now - v[1] < RECORD_KEEP:
                self.idem[k] = (v[0], float(v[1]))

    def _save(self) -> None:
        data = {"version": 1, "panes": [p.to_json() for p in self.panes.values()],
                "idem": {k: [v[0], v[1]] for k, v in self.idem.items()}}
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
        self._dirty = False

    def _changed(self, save: bool = True) -> None:
        self.rev += 1
        if save:
            self._save()
        self.cond.notify_all()

    # -- events ------------------------------------------------------------------------
    def _emit(self, kind: str, **fields: Any) -> None:
        try:
            self.d.events.emit(kind, **fields)
        except Exception:  # noqa: BLE001 - an event is never worth a failure
            pass

    # -- adoption (a restarted gated) -----------------------------------------------
    def adopt(self) -> None:
        """Match the records with what the private tmux server still runs."""
        infos = None
        if self._tmux_ok():
            # a restarted gated has live records: a query that fails (None) here
            # would mark every one gone, so retry a few times before concluding
            # the server is really gone (a reboot or a stopped server answers
            # None every time and is correctly reported gone after the retries)
            retries = 3 if any(p.live for p in self.panes.values()) else 0
            for i in range(retries + 1):
                infos = self.tmux.panes()
                if infos is not None:
                    break
                if i < retries:
                    time.sleep(0.2)
        if infos is not None:
            self._panes_ok_at = time.time()
        changed = False
        remote_hosts = set()
        with self.lock:
            for p in self.panes.values():
                if not p.live:
                    continue
                if p.remote:
                    # asked of its host by the host's poller (never from a
                    # record): until then its last state stands, unconfirmed
                    remote_hosts.add(p.host)
                    continue
                info = (infos or {}).get(p.id)
                if self._lost(p, info):
                    self._mark_gone(p, "the terminal supervisor (tmux) no longer has it: the "
                                       "computer restarted or tmux was stopped")
                    changed = True
                    continue
                self._update(p, info)
                # the screen may have moved while gated was down: a seq read
                # before the restart is stale now
                p.seq += 1
                if p.kind == "job" and p.alive:
                    self._open_fifo(p, restart=True)
                    if p.paused_as == "interrupted":
                        # the SIGTERM timer died with the old gated; keep the
                        # promise this restart would otherwise have dropped
                        self._arm_term_escalation(p)
                changed = True
            # a pane on the private server without a record (its record was lost):
            # shown as an orphan the user can see and close
            for name, info in (infos or {}).items():
                if ID_RE.fullmatch(name) and name not in self.panes:
                    p = Pane(id=name, nonce=info.get("@gw_nonce") or "", owner="user",
                             state="running" if name.startswith("j_") else "open", via="adopted",
                             host_id=self._host_id())
                    self.panes[name] = p
                    self._update(p, info)
                    changed = True
            if changed:
                self._changed()
        for h in sorted(remote_hosts):
            self._ensure_poller(h)

    @staticmethod
    def _lost(p: Pane, info: dict[str, str] | None) -> bool:
        """tmux doesn't list this pane (by id and its nonce): whatever a record
        or a saved pid says, it is not there (adoption and every tick ask)."""
        return info is None or info.get("@gw_nonce") != p.nonce

    def _server_alive(self) -> bool | None:
        """True / False when the last-known tmux server pid is alive / gone,
        None when no pid is known yet."""
        pid = self._tmux.server_pid if self._tmux is not None else 0
        if pid <= 0:
            return None
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except OSError:
            return True

    def _blip(self, now: float) -> bool:
        """A failed list-panes query is a transient blip (not proof the panes
        died) when the tmux server process is still alive; when its pid is
        unknown, tolerate it only within the grace and while the socket is
        there."""
        alive = self._server_alive()
        if alive is True:
            return True
        if alive is False:
            return False
        return now - self._panes_ok_at < TMUX_GRACE and self.sock.exists()

    def _tmux_ok(self) -> bool:
        try:
            self.tmux
        except TermError:
            return False
        return True

    def _host_id(self) -> str:
        try:
            return self.d.machine_id()
        except Exception:  # noqa: BLE001
            return ""

    def _mark_gone(self, p: Pane, why: str) -> None:
        p.gone = True
        p.alive = False
        p.ended = p.ended or time.time()
        if p.kind == "job":
            if p.state not in ("exited", "failed", "canceled"):
                p.state = "unknown"
                self._emit("job.state", job=p.id, state="unknown")
        else:
            p.state = "gone"
            self._emit("terminal.closed", terminal=p.id, reason="gone")
        self._close_fifo(p)
        self.d.log(f"terminals: {p.id} is gone ({why})")

    # -- the tick --------------------------------------------------------------------------
    def _loop(self) -> None:
        while not self.stopping.is_set():
            busy = False
            try:
                busy = self.tick()
            except Exception as e:  # noqa: BLE001 - the loop never dies
                self.d.log(f"terminals: tick failed ({type(e).__name__})")
            self.stopping.wait(TICK if busy else IDLE_TICK)

    def _mask(self, p: Pane, s: Any, limit: int = 120) -> str:
        """A short screen-chosen string (the title) scrubbed: a program can
        put a vault value in its terminal title (OSC 2), which reaches the
        agent through terminal_read / terminal_list / job_status and the
        records, so it is masked wherever it is stored and shown."""
        if not isinstance(s, str) or not s:
            return ""
        from .. import scrub
        return _clean(scrub.scrub_text(s[:1000], extra=list(p.secrets)), limit)

    @staticmethod
    def _live_job_state(p: Pane) -> str:
        """A live job's state from its records (lock held): suspended while a
        stop holds, waiting_auth while its password prompt waits on the
        person, else running."""
        if p.paused_as == "suspended":
            return "suspended"
        if p.auth is not None and p.auth.get("state") in ("asking", "unavailable", "cancelled"):
            return "waiting_auth"
        return "running"

    def _update(self, p: Pane, info: dict[str, str]) -> None:
        """Facts from list-panes (lock held)."""
        def num(k: str) -> int:
            try:
                return int(info.get(k) or 0)
            except ValueError:
                return 0
        dead = info.get("pane_dead") == "1"
        pp = 0 if dead else num("pane_pid")
        if not p.remote and (pp != p.pane_pid or (pp and p.pane_start is None)):
            # (a local pane's process: what a draining gated watches once its
            # tmux can't be run any more, _tick)
            p.pane_start = peers.started(pp) if pp else None
        p.pane_pid = pp
        p.tty = info.get("pane_tty", "")
        p.cols, p.rows = num("pane_width") or p.cols, num("pane_height") or p.rows
        p.history = num("history_size")
        p.fg = _clean(info.get("pane_current_command"), 64)
        p.title = self._mask(p, info.get("pane_title"))
        p.alive = not dead
        if dead and p.ended is None:
            p.ended = time.time()
            st = info.get("pane_dead_status", "")
            sg = info.get("pane_dead_signal", "")
            p.exit = int(st) if st.lstrip("-").isdigit() else None
            p.signal = signal_word(sg)
            if p.kind == "job":
                p.state = "canceled" if p.cancel else "exited"
                self._emit("job.state", job=p.id, state=p.state)
                self._emit("job.exited", job=p.id, exit=p.exit, signal=p.signal, state=p.state)
            else:
                p.state = "exited"
            p.auth = None
            p.echo_off = False
        elif not dead and p.kind == "job":
            want = self._live_job_state(p)
            if want != p.state:
                p.state = want
                self._emit("job.state", job=p.id, state=want)
        elif not dead and p.state in ("starting",) or \
                (not dead and p.kind == "terminal" and p.state in ("disconnected", "waiting_auth",
                                                                   "unknown")):
            p.state = "open"

    def tick(self) -> bool:
        """One look at every pane; True while anything is live."""
        with self._tick_lock:
            return self._tick()

    def _tick(self) -> bool:
        pending = []
        while self.closed_dialogs:
            pending.append(self.closed_dialogs.popleft())
        with self.lock:
            live_all = [p for p in self.panes.values() if p.live]
        live = [p for p in live_all if not p.remote]
        for rid, outcome in pending:
            self._dialog_closed(rid, outcome)
        for h in sorted({p.host for p in live_all if p.remote}):
            self._ensure_poller(h)
        if not live:
            self._prune()
            return bool(live_all)
        fetched = time.time()
        infos = self.tmux.panes()
        # A failed list-panes query (timeout / OSError / a non-zero exit) means
        # "don't know", not "every pane died": one hiccup must not mark live
        # panes gone while tmux still runs them. Tell a blip apart from a dead
        # server by the server's own pid: if that process is still alive the
        # query just failed; if it is gone (or the pid is unknown and the grace
        # has run out) the panes really are gone.
        query_failed = infos is None
        if not query_failed:
            self._panes_ok_at = fetched
        transient = query_failed and self._blip(fetched)
        # The env's tmux itself is gone (an uninstall deleted the plugin's data
        # folder): no query can reach the server, which runs on from the deleted
        # files, so "a blip" would hold forever. The pane's own process (pid and
        # start time from tmux's last answer) is all that is left to watch; one
        # that has ended makes the pane gone/unknown (never "exited": its outcome
        # isn't proven), so a draining gated can leave once nothing runs.
        blind = query_failed and not self.tmux.runnable()
        with self.lock:
            for p in live:
                if not p.live:
                    continue
                info = (infos or {}).get(p.id)
                if self._lost(p, info):
                    if blind:
                        if p.pane_pid and peers.alive(p.pane_pid, p.pane_start):
                            continue
                        self._mark_gone(p, "the gateway's tmux can't be run any more (the gateway "
                                           "was uninstalled) and the pane's process has ended")
                        self._dirty = True
                        continue
                    if transient:
                        continue                   # a query blip; ask again next tick
                    if p.closing:
                        self._closed(p)
                    elif p.created < fetched:      # (one started meanwhile isn't listed yet)
                        self._mark_gone(p, "tmux lost it")
                    continue
                before = (p.state, p.alive)
                self._update(p, info)
                if (p.state, p.alive) != before:
                    self._dirty = True
            if self._dirty:
                self._changed()
        # tty modes (outside the lock: syscalls), then the password prompts
        for p in live:
            if not p.alive or not p.tty:
                continue
            mode = tty_mode(p.tty)
            echo_off = mode is not None and not mode[0] and mode[1]
            self._prompt_step(p, echo_off)
        self._report_output(live)
        self._prune()
        return True

    def _prune(self) -> None:
        now = time.time()
        drop: list[Pane] = []
        with self.lock:
            for p in list(self.panes.values()):
                if p.ended is None:
                    continue
                if not p.gone and not p.closing and now - p.ended > RETAIN_DEAD:
                    p.closing = True
                    drop.append(p)
                if now - p.ended > RECORD_KEEP:
                    self.panes.pop(p.id, None)
                    self._dirty = True
            for k, (_jid, t) in list(self.idem.items()):
                if now - t > RECORD_KEEP:
                    self.idem.pop(k, None)
                    self._dirty = True
            if self._dirty:
                self._changed()
        for p in drop:
            with contextlib.suppress(TermError):
                self._tm(p).run("kill-session", "-t", f"={p.id}", check=False)

    def _closed(self, p: Pane) -> None:
        p.alive = False
        p.ended = p.ended or time.time()
        if p.kind == "job":
            if p.state not in ("exited", "failed", "canceled"):
                p.state = "canceled"
                self._emit("job.state", job=p.id, state="canceled")
        else:
            p.state = "closed"
        self._close_fifo(p)
        self._dirty = True

    # -- lookups and checks ------------------------------------------------------------
    def get(self, pid: Any) -> Pane:
        if not isinstance(pid, str) or not ID_RE.fullmatch(pid):
            raise TermError(400, "bad_id", "gateway: that isn't a terminal or job id (t_... or j_...)")
        p = self.panes.get(pid)
        if p is None:
            raise TermError(404, "no_such", f"gateway: no terminal or job {pid} (terminal_list "
                            "and job_list show what there is)")
        return p

    def _live_session(self, p: Pane) -> Any:
        reg = self.d.registry
        s = reg.live(p.session_pid) if p.session_pid else None
        if s is not None and (p.session_start is None or s.start == p.session_start):
            return s
        if p.session_id:
            with reg.lock:
                cands = list(reg.sessions.values())
            for c in cands:
                if c.session_id == p.session_id and reg.live(c.pid) is not None:
                    return c
        return None

    def _paused(self, key: str) -> bool:
        try:
            return bool(key) and key in self.d.dialogs.paused
        except Exception:  # noqa: BLE001
            return False

    def session_for_pid(self, chain: list[int]) -> Any:
        """The owner session of the supervised pane whose root process is in
        `chain` (a process started inside a gateway terminal or job), if that
        session is alive: planes.Registry.ancestor_session asks this."""
        with self.lock:
            roots = {p.pane_pid: p for p in self.panes.values()
                     if p.alive and p.pane_pid and not p.remote}
        for pid in chain:
            p = roots.get(pid)
            if p is not None:
                return self._live_session(p)
        return None

    def note_agent(self, session: Any, tool_use_id: Any, agent: Any) -> None:
        """The mod's word (UI plane) on which agent loop made a tool call."""
        if not isinstance(tool_use_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,120}", tool_use_id):
            return
        now = time.time()
        with self.lock:
            for k, (_s, _a, t) in list(self.tool_agents.items()):
                if now - t > 300:
                    self.tool_agents.pop(k, None)
            if len(self.tool_agents) < 1000:
                self.tool_agents[tool_use_id] = (session_key(session), _clean(agent, 80), now)

    def agent_of(self, session: Any, tool_use_id: Any) -> str:
        if not isinstance(tool_use_id, str):
            return ""
        with self.lock:
            v = self.tool_agents.get(tool_use_id)
        if v is None or v[0] != session_key(session):
            return ""
        return v[1]

    # -- counts ------------------------------------------------------------------------
    def busy(self, local_only: bool = False) -> str:
        c = self.counts(local_only)
        t, j = c["terminals"], c["jobs"]
        parts = []
        if t:
            parts.append(f"{t} terminal{'s' if t != 1 else ''}")
        if j:
            parts.append(f"{j} job{'s' if j != 1 else ''}")
        return " and ".join(parts)

    def counts(self, local_only: bool = False) -> dict[str, int]:
        with self.lock:
            ps = [p for p in self.panes.values() if p.alive and not (local_only and p.remote)]
        return {"terminals": sum(1 for p in ps if p.kind == "terminal"),
                "jobs": sum(1 for p in ps if p.kind == "job")}

    def check_accepting(self) -> None:
        """New terminals and jobs (and remote runtimes) only while gated isn't
        draining (the plugin was uninstalled: lifecycle.Daemon.drain)."""
        if getattr(self.d, "draining", ""):
            raise TermError(503, "draining", DRAINING)

    # -- starting panes ------------------------------------------------------------------
    # -- binding: host, workspace, policy (PLAN-v4 phase 7) ------------------------------
    def _eff(self) -> Any:
        """The effective rights (consent.compute); with the vault unreadable
        (locked, missing) the form against the baseline approval, so the
        form's restrictions still apply and nothing it raises does."""
        try:
            eff = self.d.effective()
        except Exception:  # noqa: BLE001
            eff = None
        if eff is not None:
            return eff
        from .. import consent
        from .. import form as formmod
        try:
            return consent.compute(formmod.load(), None)
        except Exception:  # noqa: BLE001
            return None

    def _host_id_of(self, name: str) -> str:
        if name == "localhost":
            return self._host_id()
        r = getattr(self.d, "remote", None)
        return r.host_id(name) if r is not None else ""

    def _bind(self, session: Any, via: str, hostname: str, mid: str, workspace: Any, cwd: Any,
              remote: bool, action: str = "exec") -> tuple[Any, str]:
        """(cwd, workspace id) for a new terminal or job: the workspace named
        (its name on that host, or its id) or the one whose root holds cwd,
        cwd defaulting to its root and refused outside it (a path under a
        remote workspace's `local` folder is mapped to the host's root); a
        workspace of another host is refused. Then the policy for the host,
        the workspace and `action` (the person's own panes, via "ui", are
        theirs: Claude Code's permissions don't apply to them either)."""
        from .. import paths as P
        from .. import policy
        from . import workspace_id
        eff = self._eff()
        eh = eff.hosts.get(hostname) if eff is not None else None
        wsmap = dict(eh.workspaces) if eh is not None else {}
        home = str(P.user_home())
        rh_home = ""
        if remote and getattr(self.d, "remote", None) is not None:
            try:
                rh_home = str(self.d.remote.get(hostname).info.get("home") or "")
            except Exception:  # noqa: BLE001
                rh_home = ""

        def expand(path: str, local: bool) -> str:
            h = home if local else rh_home
            if path == "~":
                return h or "~"
            if path.startswith("~/"):
                return (h + path[1:]) if h else path
            return path

        def inside(path: str, root: str) -> bool:
            a, r = os.path.normpath(path), os.path.normpath(root)
            return a == r or a.startswith(r.rstrip("/") + "/")

        ws_name = None
        if workspace not in (None, ""):
            if not isinstance(workspace, str) or len(workspace) > 64:
                raise TermError(400, "bad_workspace", "gateway: workspace is a workspace's name or "
                                "id (w_...)")
            for n, ew in wsmap.items():
                if workspace in (n, workspace_id(mid, ew.root)):
                    ws_name = n
            if ws_name is None:
                for hn, oh in (eff.hosts.items() if eff is not None else []):
                    if hn == hostname:
                        continue
                    for n, ew in oh.workspaces.items():
                        if workspace == workspace_id(self._host_id_of(hn), ew.root):
                            raise TermError(409, "workspace_host",
                                            f"gateway: workspace {n} is on {hn}, not {hostname} "
                                            "(the same path on two hosts is two places); name "
                                            "its host, or a workspace of this one")
                fh = eff.form.hosts.get(hostname) if eff is not None else None
                if fh is not None and workspace in fh.workspaces:
                    raise TermError(409, "policy", f"gateway: workspace {workspace} on {hostname} "
                                    f"waits for the user's OK (gate check {hostname})")
                raise TermError(404, "no_workspace", f"gateway: no workspace {_clean(workspace, 64)!r} "
                                f"on {hostname} in gateway.toml (/gate-hosts lists them)")
        if ws_name is not None:
            ew = wsmap[ws_name]
            root = expand(ew.root, not remote)
            if cwd in (None, ""):
                cwd = root
            elif isinstance(cwd, str):
                if remote and ew.local:
                    loc = expand(ew.local, True)
                    if os.path.isabs(cwd) and inside(cwd, loc):
                        rel = os.path.relpath(os.path.normpath(cwd), os.path.normpath(loc))
                        cwd = root if rel == "." else root.rstrip("/") + "/" + rel
                c = expand(cwd, not remote)
                if not inside(c, root):
                    raise TermError(400, "bad_cwd", f"gateway: cwd isn't inside workspace {ws_name} "
                                    f"({ew.root} on {hostname})")
                cwd = c
        elif isinstance(cwd, str) and cwd:
            c = expand(cwd, not remote)
            best = -1
            for n, ew in wsmap.items():
                r = expand(ew.root, not remote)
                if inside(c, r) and len(r) > best:
                    ws_name, best = n, len(r)
        if via != "ui" and eff is not None:
            d = policy.decide(eff, action, host=hostname, workspace=ws_name)
            if d.word is not True:
                self._emit("policy.denied", host=mid, workspace=None if ws_name is None
                           else workspace_id(mid, wsmap[ws_name].root), action=action,
                           entry=d.entry or None)
                raise TermError(403, "policy", d.message(), rule=d.rule, decision=d.text)
        wid = workspace_id(mid, wsmap[ws_name].root) if ws_name is not None else ""
        return cwd, wid

    def _check_start(self, session: Any, cwd: Any, remote: bool = False) -> str:
        if session is not None and self._paused(session_key(session)):
            raise TermError(409, "paused", PAUSED)
        with self.lock:
            if sum(1 for p in self.panes.values() if p.alive or (p.remote and p.live)) >= MAX_LIVE:
                raise TermError(429, "too_many", f"gateway: {MAX_LIVE} terminals and jobs are "
                                "running already; close some (terminal_close, job_signal)")
        if remote:
            # checked on the host (RemoteTmux.dir_ok); "" is the remote home,
            # ~/... a folder under it (a workspace root as written)
            if cwd in (None, ""):
                return ""
            if isinstance(cwd, str) and (cwd == "~" or cwd.startswith("~/")) and \
                    not re.search(r"[\x00-\x1f\x7f]", cwd) and ".." not in cwd.split("/"):
                return cwd
            if not isinstance(cwd, str) or not os.path.isabs(cwd) or len(cwd) > 1000 or \
                    re.search(r"[\x00-\x1f\x7f]", cwd):
                raise TermError(400, "bad_cwd", "gateway: cwd must be an absolute path on the host")
            return os.path.normpath(cwd)
        if not isinstance(cwd, str) or not cwd:
            cwd = str(paths.user_home())
        if not os.path.isabs(cwd):
            raise TermError(400, "bad_cwd", "gateway: cwd must be an absolute path")
        if not os.path.isdir(cwd):
            raise TermError(400, "bad_cwd", "gateway: cwd isn't a folder on this host")
        return os.path.normpath(cwd)

    def _host(self, host: Any) -> tuple[str, str]:
        """(host name, host id): localhost, or a remote form host by its name,
        its contract id or its machine token (PLAN-v4 phase 6)."""
        mid = self._host_id()
        if host in (None, "", "localhost") or (isinstance(host, str) and host == mid):
            return "localhost", mid
        name = self.d.remote.resolve(host) if getattr(self.d, "remote", None) is not None else None
        if name is None:
            raise TermError(404, "no_host", f"gateway: no host {_clean(host, 64)!r} in gateway.toml "
                            "(gate status lists the hosts)")
        return name, self.d.remote.host_id(name)

    def _remote_ready(self, session: Any, name: str) -> Any:
        """The host's ready runtime (staged on first need): (RemoteHost, rt)."""
        from .remote import RemoteError
        rh = self.d.remote.get(name)
        try:
            rt = rh.ensure_runtime(session)
        except RemoteError as e:
            raise TermError(e.status if e.status >= 400 else 503, "remote_" + e.code,
                            e.message) from None
        return rh, rt

    def _remote_cwd(self, rh: Any, tm: Any, cwd: str) -> str:
        if not cwd:
            home = str(rh.info.get("home") or "")
            return home if home.startswith("/") else "/"
        if cwd == "~" or cwd.startswith("~/"):
            home = str(rh.info.get("home") or "")
            if not home.startswith("/"):
                raise TermError(409, "bad_cwd", f"gateway: {rh.name}'s home folder isn't known "
                                "yet; give an absolute cwd")
            cwd = home.rstrip("/") + cwd[1:]
        if not tm.dir_ok(cwd):
            raise TermError(400, "bad_cwd", f"gateway: cwd isn't a folder on {rh.name}")
        return cwd

    def _size(self, cols: Any, rows: Any) -> tuple[int, int]:
        def clamp(v: Any, lo: int, hi: int, d: int) -> int:
            return max(lo, min(hi, int(v))) if isinstance(v, (int, float)) and not isinstance(v, bool) else d
        return clamp(cols, MIN_COLS, MAX_COLS, DEFAULT_COLS), clamp(rows, MIN_ROWS, MAX_ROWS, DEFAULT_ROWS)

    def _new_session(self, p: Pane, argv: list[str], fifo: bool = False) -> None:
        args = ["new-session", "-d", "-s", p.id, "-x", str(p.cols), "-y", str(p.rows),
                "-c", p.cwd, *argv, ";", "set-option", "-t", p.target, "@gw_nonce", p.nonce]
        if fifo and p.fifo is not None:
            args += [";", "pipe-pane", "-o", "-t", p.target, f"exec cat > {_q(str(p.fifo))}"]
        self._tm(p).run(*args)
        if not p.remote:
            # beside the start, never in its way (a job may end within milliseconds)
            threading.Thread(target=self._watch, daemon=True, name="gw-tmux-watch").start()

    def _watch(self) -> None:
        """The local server's watchdog session (LOCAL_TMUX_CONF), started
        once per server: tmux refuses a second one by name, which is fine."""
        gsock = getattr(self.d, "sock_path", None) or paths.gated_socket()
        gpid = getattr(self.d, "pid_path", None) or paths.gated_pid()
        k = getattr(self.d, "k", None) or {}
        tick = k.get("watch_tick") if testing.active() is not None else None
        tick = str(int(tick)) if isinstance(tick, int) and not isinstance(tick, bool) and 0 < tick <= 60 \
            else str(WATCH_TICK)
        with contextlib.suppress(Exception):
            self.tmux.run("new-session", "-d", "-s", WATCH_SESSION, "-x", "20", "-y", "2",
                          "/bin/sh", "-c", WATCH_SCRIPT, WATCH_SESSION, str(self.sock), str(gsock),
                          tick, str(gpid), check=False)

    def open_terminal(self, session: Any, *, agent: str = "", cwd: Any = None, cols: Any = None,
                      rows: Any = None, env: Any = None, workspace: Any = "", task_ref: Any = "",
                      via: str = "agent", host: Any = None) -> Pane:
        self.check_accepting()
        host, mid = self._host(host)
        remote = host != "localhost"
        cwd, wid = self._bind(session, via, host, mid, workspace, cwd, remote)
        cwd = self._check_start(session, cwd, remote=remote)
        c, r = self._size(cols, rows)
        p = Pane(id=ulid("t"), kind="terminal", host=host, host_id=mid, cwd=cwd,
                 session_pid=getattr(session, "pid", 0), session_start=getattr(session, "start", None),
                 session_id=getattr(session, "session_id", ""), agent=_clean(agent, 80),
                 owner="user" if via == "ui" else "agent",
                 holder=None if via == "ui" else (_clean(agent, 80) or None), cols=c, rows=r,
                 workspace=wid, task_ref=_clean(task_ref, 200), via=via)
        confirmed = True
        if remote:
            confirmed = self._start_remote(session, p)
        else:
            bash, rc, exports, path = env_plan(env)
            me = self.terms / f"{p.id}.{p.nonce}.rc"
            _write_private(me, start_text(p, rc=rc, exports=exports, path=path, me=me))
            try:
                self._new_session(p, [bash, "--noprofile", "--rcfile", str(me), "-i"])
            except TermError:
                with contextlib.suppress(OSError):
                    me.unlink()
                raise
        with self.lock:
            if confirmed and p.state == "starting":     # (a remote poll may have looked already)
                p.state = "open"
            self.panes[p.id] = p
            self._changed()
        if confirmed:
            self._refresh(p)
        if remote:
            self._ensure_poller(p.host)
            self._audit_remote(p, "terminal")
        self._emit("terminal.opened", terminal=p.id, host=mid, session=p.session_id or None,
                   agent=p.agent or None, by=via)
        return p

    def _start_remote(self, session: Any, p: Pane, argv: list[str] | None = None,
                      command: str | None = None, key: str = "") -> bool:
        """Start a pane on its host (PLAN-v4 phase 6): the runtime (staged on
        first need), the start file written on the host (0600, noclobber, its
        text on ssh's stdin), then the session in the runtime's tmux.

        The record (and the job's idempotency key) is saved, state `starting`,
        before the start goes to the host: a lost answer or a gated crash
        can't leave work running there that gated doesn't know about, nor let
        a retry with the same key run it twice. True when the host confirmed
        the start; False when its answer was lost after the command went out:
        the record stays, state `unknown` with the note, unconfirmed, and the
        host's poller settles it (listed by name and nonce: adopted; else the
        start file's claim tells "never started" from "started"). A start that
        provably didn't happen leaves no record and raises."""
        from .remote import LANG
        rh, rt = self._remote_ready(session, p.host)
        p.rt, p.machine = rt, rh.machine
        tm = rh.tmux(rt)
        p.cwd = self._remote_cwd(rh, tm, p.cwd)
        ext = "rc" if p.kind == "terminal" else "sh"
        rel = f"terms/{p.id}.{p.nonce}.{ext}"
        me = f"{rt}/{rel}"
        imp_path, imp_env = rh.imports()
        env_file = ""
        if imp_env:
            env_rel = f"terms/{p.id}.{p.nonce}.imp"
            tm.capture_env(env_rel, imp_env)
            env_file = f"{rt}/{env_rel}"
        tm.write_file(rel, remote_start_text(p, rt=rt, lang=LANG.get(rh.platform, "C.UTF-8"), me=me,
                                             argv=argv, command=command, imports=imp_path,
                                             env_file=env_file, env_names=imp_env))
        bash = f"{rt}/env/bin/bash"
        run = [bash, "--noprofile", "--rcfile", me, "-i"] if p.kind == "terminal" else \
            [bash, "--noprofile", "--norc", me]
        with self.lock:
            p.state, p.unconfirmed, p.dispatching = "starting", True, True
            self.panes[p.id] = p
            if key:
                self.idem[key] = (p.id, time.time())
            self._changed()                  # persisted before the start leaves
        try:
            self._new_session(p, run)
        except TermError as e:
            if not e.extra.get("ambiguous"):
                # provably not started (refused before it went out, or tmux said
                # no): nothing of it runs there, so nothing is recorded
                with self.lock:
                    p.dispatching = False
                    self.panes.pop(p.id, None)
                    if key and self.idem.get(key, ("",))[0] == p.id:
                        self.idem.pop(key, None)
                    self._changed()
                tm.remove_file(rel)
                raise
            what = "job" if p.kind == "job" else "terminal"
            with self.lock:
                p.dispatching, p.dispatched_at = False, time.time()
                p.state, p.seen = "unknown", False
                p.remote_note = (f"gateway: the connection to {p.host} dropped while this {what} was "
                                 "being started, so the gateway doesn't know yet whether it started "
                                 f"there; it asks {p.host} and reports it (don't start it again "
                                 f"before the state says)")
                self._changed()
            if p.kind == "job":
                self._emit("job.state", job=p.id, state="unknown")
            self.d.log(f"terminals: {p.id}: the start's answer from {p.host} was lost ({e.code}); "
                       "asking the host")
            return False
        with self.lock:
            p.dispatching, p.unconfirmed, p.dispatched_at = False, False, time.time()
        return True

    def _audit_remote(self, p: Pane, what: str) -> None:
        from .. import audit
        with contextlib.suppress(Exception):
            audit.use("gated", p.host, None, ["ssh", p.host, f"gateway {what} {p.id}"],
                      remote_runtime=True)

    def start_job(self, session: Any, *, agent: str = "", argv: Any = None, command: Any = None,
                  cwd: Any = None, host: Any = None, workspace: Any = "", task_ref: Any = "",
                  on_pause: Any = None, idempotency_key: Any = None, env: Any = None,
                  via: str = "agent") -> tuple[Pane, bool]:
        """(the job, whether it is a new one): an idempotency_key seen in the
        last 24 h returns the job it started."""
        key = ""
        if idempotency_key not in (None, ""):
            if not isinstance(idempotency_key, str) or not re.fullmatch(r"[A-Za-z0-9_.:@/+=-]{1,200}",
                                                                        idempotency_key):
                raise TermError(400, "bad_key", "gateway: idempotency_key is 1-200 characters of "
                                "letters, digits and _.:@/+=-")
            key = f"{session_key(session)}|{idempotency_key}"
            with self.lock:
                hit = self.idem.get(key)
                if hit is not None and hit[0] in self.panes and time.time() - hit[1] < RECORD_KEEP:
                    return self.panes[hit[0]], False
                if key in self.idem_pending:
                    # the first request with this key is still starting it (staging a
                    # runtime can take minutes): never a second start meanwhile
                    raise TermError(409, "starting", "gateway: a job with this idempotency_key is "
                                    "being started right now; ask again in a moment (the same key "
                                    "then returns it)")
                self.idem_pending.add(key)
        try:
            return self._start_job(session, key, agent=agent, argv=argv, command=command, cwd=cwd,
                                   host=host, workspace=workspace, task_ref=task_ref,
                                   on_pause=on_pause, idempotency_key=idempotency_key, env=env,
                                   via=via)
        finally:
            if key:
                with self.lock:
                    self.idem_pending.discard(key)

    def _start_job(self, session: Any, key: str, *, agent: str, argv: Any, command: Any, cwd: Any,
                   host: Any, workspace: Any, task_ref: Any, on_pause: Any, idempotency_key: Any,
                   env: Any, via: str) -> tuple[Pane, bool]:
        # (after the idempotency lookup: a retry of a job that started before
        # the drain gets that job, never a refusal that would start it twice)
        self.check_accepting()
        has_argv = argv not in (None, [], "")
        has_cmd = command not in (None, "")
        if has_argv == has_cmd:
            raise TermError(400, "bad_command", "gateway: give either argv (a list of strings) or "
                            "command (a bash command string)")
        if has_argv and (not isinstance(argv, list) or not all(isinstance(a, str) for a in argv)
                         or len(argv) > 1000 or sum(len(a) for a in argv) > TEXT_MAX
                         or any("\x00" in a for a in argv)):
            raise TermError(400, "bad_command", "gateway: argv is a list of strings (at most 16 KiB)")
        if has_cmd and (not isinstance(command, str) or len(command) > TEXT_MAX or "\x00" in command):
            raise TermError(400, "bad_command", "gateway: command is a string of at most 16 KiB")
        pol = on_pause if on_pause not in (None, "") else "continue"
        if pol not in ON_PAUSE:
            raise TermError(400, "bad_policy", "gateway: on_pause is continue, interrupt, suspend or "
                            "detach")
        hostname, mid = self._host(host)
        remote = hostname != "localhost"
        cwd, wid = self._bind(session, via, hostname, mid, workspace, cwd, remote)
        cwd = self._check_start(session, cwd, remote=remote)
        from .. import scrub
        shown = shlex.join(argv) if has_argv else command
        p = Pane(id=ulid("j"), kind="job", host=hostname, host_id=mid, cwd=cwd,
                 session_pid=getattr(session, "pid", 0), session_start=getattr(session, "start", None),
                 session_id=getattr(session, "session_id", ""), agent=_clean(agent, 80),
                 owner="agent", holder=_clean(agent, 80), workspace=wid,
                 task_ref=_clean(task_ref, 200), on_pause=pol,
                 idempotency_key=idempotency_key if key else "",
                 command=scrub.scrub_text(_clean(shown.replace("\n", " "), 2000))[:500], via=via)
        confirmed = True
        if remote:
            # a remote job's output is the runtime's tmux history (bounded by
            # its history-limit): no stream leaves the host but what is read;
            # its record and key are saved before the start leaves (_start_remote)
            confirmed = self._start_remote(session, p, argv=argv if has_argv else None,
                                           command=command if has_cmd else None, key=key)
        else:
            bash, rc, exports, path = env_plan(env)
            me = self.terms / f"{p.id}.{p.nonce}.sh"
            _write_private(me, start_text(p, rc=rc, exports=exports, path=path, me=me,
                                          argv=argv if has_argv else None,
                                          command=command if has_cmd else None))
            self._prepare_fifo(p)
            try:
                self._new_session(p, [bash, "--noprofile", "--norc", str(me)], fifo=True)
            except TermError:
                self._close_fifo(p)
                with contextlib.suppress(OSError):
                    me.unlink()
                raise
        with self.lock:
            if confirmed and p.state == "starting":     # (a remote poll may have looked already)
                p.state = "running"
            self.panes[p.id] = p
            if key and self.idem.get(key, ("",))[0] != p.id:
                self.idem[key] = (p.id, time.time())
            self._changed()
            # under the lock that every look at a pane takes, before the first
            # one: a job that ends at once is still reported started first
            self._emit("job.started", job=p.id, host=mid, session=p.session_id or None,
                       task=p.task_ref or None, agent=p.agent or None)
        if not remote:
            self._start_reader(p)
        if confirmed:
            self._refresh(p)
        if remote:
            self._ensure_poller(p.host)
            self._audit_remote(p, "job")
        return p, True

    def _refresh(self, p: Pane) -> None:
        try:
            infos = self._tm(p).panes()
        except TermError:
            return
        info = (infos or {}).get(p.id)
        if info is not None and not self._lost(p, info):
            with self.lock:
                if p.dispatching:
                    return
                self._update(p, info)
                p.seen = True
                p.unconfirmed = False      # listed by its id and nonce: it started

    # -- a job's output stream ---------------------------------------------------------
    def _prepare_fifo(self, p: Pane) -> None:
        f = self.terms / f"{p.id}.{secrets.token_hex(4)}.fifo"
        os.mkfifo(f, 0o600)
        rfd = os.open(f, os.O_RDONLY | os.O_NONBLOCK)
        wfd = os.open(f, os.O_WRONLY | os.O_NONBLOCK)     # keeps a writer, so reads wait for data
        p.fifo, p.fifo_fds = f, (rfd, wfd)

    def _open_fifo(self, p: Pane, restart: bool = False) -> None:
        """(Re)start a job's output pipe into a new FIFO (a re-adopted job:
        the old gated's pipe died with it). The ring starts from tmux's
        history."""
        try:
            self._prepare_fifo(p)
            self.tmux.run("pipe-pane", "-t", p.target, check=False)
            self.tmux.run("pipe-pane", "-o", "-t", p.target, f"exec cat > {_q(str(p.fifo))}")
            if restart:
                hist = self.tmux.run("capture-pane", "-p", "-J", "-S", "-", "-E", "-",
                                     "-t", p.target, check=False)
                p.ring = bytearray(hist[-RING_MAX:])
                p.total = max(p.total, len(hist))
            self._start_reader(p)
        except (OSError, TermError) as e:
            self.d.log(f"terminals: {p.id}: no output pipe ({type(e).__name__})")

    def _start_reader(self, p: Pane) -> None:
        if p.fifo_fds is None:
            return
        rfd = p.fifo_fds[0]

        def run() -> None:
            while not self.stopping.is_set():
                with self.lock:
                    if p.fifo_fds is None or p.fifo_fds[0] != rfd:
                        return
                    done = p.ended is not None
                try:
                    r, _, _ = select.select([rfd], [], [], 0.5)
                except (OSError, ValueError):
                    return
                if not r:
                    if done:
                        with self.lock:
                            self._close_fifo(p)
                        return
                    continue
                try:
                    data = os.read(rfd, 65536)
                except BlockingIOError:
                    continue
                except OSError:
                    return
                if not data:
                    time.sleep(0.05)
                    continue
                with self.lock:
                    p.ring += data
                    if len(p.ring) > RING_MAX:
                        del p.ring[:len(p.ring) - RING_MAX]
                    p.total += len(data)
        t = threading.Thread(target=run, daemon=True, name=f"gw-out-{p.id}")
        p.reader = t
        t.start()

    def _close_fifo(self, p: Pane) -> None:
        fds, f = p.fifo_fds, p.fifo
        p.fifo_fds, p.fifo = None, None
        if fds:
            for fd in fds:
                with contextlib.suppress(OSError):
                    os.close(fd)
        if f is not None:
            with contextlib.suppress(OSError):
                f.unlink()

    def _report_output(self, live: list[Pane]) -> None:
        now = time.monotonic()
        for p in live:
            if p.kind == "job" and p.total != p.reported and now - p.reported_at >= 1.0:
                p.reported, p.reported_at = p.total, now
                self._emit("job.output", job=p.id, bytes=p.total)

    # -- reading ------------------------------------------------------------------------
    INFO_FMT = SEP.join("#{" + f + "}" for f in ("cursor_x", "cursor_y", "alternate_on", "pane_width",
                                                  "pane_height", "history_size", "pane_dead",
                                                  "pane_title"))

    def _capture(self, p: Pane, history: int = 0, *, persist: bool = False) -> dict[str, Any]:
        """One capture of the pane: info, styled lines, plain lines, history
        (plain); updates seq. Raises TermError when the pane is gone. With
        `persist` the record is written whenever seq moves, so a seq handed to
        the agent is never behind what a restart restores (the adopt bump then
        reliably makes a pre-crash seq stale)."""
        args = ["display-message", "-p", "-t", p.target, self.INFO_FMT, ";",
                "capture-pane", "-p", "-e", "-t", p.target]
        hist_n = max(0, min(HISTORY_MAX, int(history or 0)))
        if hist_n:
            args += [";", "capture-pane", "-p", "-S", f"-{hist_n}", "-E", "-1", "-t", p.target]
        try:
            out = self._tm(p).run(*args, timeout=10 if not p.remote else 30)
        except TermError as e:
            if e.code.startswith("remote_") or e.code == "machine":
                raise              # the host can't be asked now: not "gone"
            raise TermError(410, "gone", f"gateway: {p.id} isn't there any more") from None
        text = out.decode("utf-8", "replace")
        first, _, rest = text.partition("\n")
        parts = first.split(SEP, 7)
        if len(parts) < 8:
            raise TermError(500, "tmux", "gateway: the terminal supervisor sent an unreadable screen")

        def num(v: str) -> int:
            try:
                return int(v)
            except ValueError:
                return 0
        cx, cy, alt, w, h, hs = (num(x) for x in parts[:6])
        title = self._mask(p, parts[7])
        lines_raw = rest.split("\n")
        screen_raw = lines_raw[:h] if h else lines_raw
        hist_raw = lines_raw[h:h + hist_n] if hist_n else []
        styled = []
        plain = []
        for ln in screen_raw:
            pl, runs = screen.split_escapes(ln)
            plain.append(pl)
            styled.append(runs)
        digest = hashlib.sha1(("\n".join(plain) + f"|{cx},{cy},{alt},{w},{h}|{title}")
                              .encode("utf-8", "replace")).hexdigest()
        with self.lock:
            if digest != p.hash:
                if p.hash:
                    p.seq += 1
                    if persist:
                        self._save()
                p.hash = digest
                self.cond.notify_all()
            p.cursor, p.alt, p.cols, p.rows, p.history, p.title = (cx, cy), bool(alt), w or p.cols, \
                h or p.rows, hs, title
            seq = p.seq
        return {"plain": plain, "styled": styled, "history": [screen.strip_escapes(x) for x in hist_raw],
                "cursor": (cx, cy), "alt": bool(alt), "cols": w, "rows": h, "title": title,
                "history_size": hs, "seq": seq, "dead": parts[6] == "1"}

    JOINED_MARK = SEP + "GWJOIN" + SEP

    def _capture_joined(self, p: Pane, history: int = 0) -> tuple[list[str], list[str]] | None:
        """The agent's plain lines with tmux soft-wrapped rows rejoined into
        logical lines (`capture-pane -J`): a vault value printed across a wrap
        boundary is one string again, so the scrubber (which looks for the
        whole value) catches it instead of handing the agent two halves it can
        splice. (visible logical lines, history logical lines), or None when
        the pane can't be read (the caller falls back to physical rows)."""
        hist_n = max(0, min(HISTORY_MAX, int(history or 0)))
        args = ["capture-pane", "-p", "-J", "-t", p.target]
        if hist_n:
            args += [";", "display-message", "-p", self.JOINED_MARK, ";",
                     "capture-pane", "-p", "-J", "-S", f"-{hist_n}", "-E", "-1", "-t", p.target]
        try:
            out = self._tm(p).run(*args, timeout=10 if not p.remote else 30)
        except TermError:
            return None
        text = out.decode("utf-8", "replace")
        if hist_n:
            vis, _, hist = text.partition(self.JOINED_MARK)
            return vis.split("\n"), hist.strip("\n").split("\n") if hist.strip("\n") else []
        return text.split("\n"), []

    def _agent_rows(self, p: Pane, history: int = 0) -> tuple[list[str], list[str]] | None:
        """The agent's lines: the screen's physical rows (`capture-pane -N
        -T`, row for row what the pane shows), scrubbed, with every value the
        scrubber finds in a soft-wrap rejoined line (`capture-pane -J`, the
        same region in the same tmux command) masked in each row it spans
        (`mask_rows`), so a value printed across a wrap is never two halves.
        Rows, not the rejoined lines: tmux also joins a row the shell's line
        editor filled exactly (it wraps it by writing the next character) with
        the row the command's output then starts on. History and screen are
        one region, so a value across their boundary is caught too.
        (visible rows, history rows), or None when the pane can't be read
        this way or the two captures don't line up (the caller falls back to
        the rejoined lines)."""
        hist_n = max(0, min(HISTORY_MAX, int(history or 0)))
        mark = SEP + "GW" + secrets.token_hex(6) + SEP
        rng = ["-S", f"-{hist_n}"] if hist_n else []
        args = ["display-message", "-p", "-t", p.target, mark + "#{pane_height} #{history_size}", ";",
                "capture-pane", "-p", "-N", "-T", *rng, "-t", p.target, ";",
                "display-message", "-p", mark, ";",
                "capture-pane", "-p", "-J", *rng, "-t", p.target]
        try:
            out = self._tm(p).run(*args, timeout=10 if not p.remote else 30)
        except TermError:
            return None
        parts = out.decode("utf-8", "replace").split(mark)
        if len(parts) != 3 or parts[0].strip():
            return None
        head, _, rows_text = parts[1].partition("\n")
        nums = head.split()
        if len(nums) != 2 or not all(x.isdigit() for x in nums):
            return None
        h, hs = int(nums[0]), int(nums[1])
        joined_text = parts[2].removeprefix("\n")

        def lines_of(t: str) -> list[str]:
            return (t[:-1] if t.endswith("\n") else t).split("\n")
        rows, joined = lines_of(rows_text), lines_of(joined_text)
        n_hist = min(hist_n, hs)
        if h <= 0 or len(rows) != n_hist + h:
            return None
        groups = align_rows(joined, rows)
        if groups is None:
            return None
        from .. import scrub
        extra = list(p.secrets)
        rows = mask_rows(rows, joined, groups, lambda ln: scrub.text_spans(ln, extra=extra))
        vis, hist = (self._scrub_lines(p, part) for part in (rows[n_hist:], rows[:n_hist]))
        return [r.rstrip(" ") for r in vis], [r.rstrip(" ") for r in hist]

    def _scrub_lines(self, p: Pane, lines: list[str]) -> list[str]:
        if not lines:
            return lines
        from .. import scrub
        text = scrub.scrub_text("\n".join(lines), extra=list(p.secrets))
        out = text.split("\n")
        return out if len(out) == len(lines) else lines[:0] + out[:len(lines)]

    def _bounded(self, lines: list[str], budget: int) -> tuple[list[str], bool, int]:
        out, truncated, used = [], False, 0
        for ln in lines:
            if len(ln) > LINE_MAX:
                ln, truncated = ln[:LINE_MAX], True
            if used + len(ln) + 1 > budget:
                truncated = True
                break
            out.append(ln)
            used += len(ln) + 1
        return out, truncated, used

    def describe(self, p: Pane, me: Any = None) -> dict[str, Any]:
        """A pane's record for lists and status (no screen)."""
        d: dict[str, Any] = {"id": p.id, "kind": p.kind, "state": p.state, "host": p.host,
                             "host_id": p.host_id, "cwd": p.cwd, "owner": p.owner,
                             "created": round(p.created, 3), "session": p.session_id,
                             "agent": p.agent, "title": p.title}
        if p.workspace:
            d["workspace"] = p.workspace
        if p.task_ref:
            d["task_ref"] = p.task_ref
        if p.owner == "agent" and p.holder:
            d["holder_agent"] = p.holder
        if me is not None:
            d["mine"] = p.session_key() == session_key(me)
        if p.kind == "job":
            # an "unknown" job (tmux lost it) has no proven end: its process may
            # still be running, so it carries no `ended` time (that timestamp is
            # only when gated noticed it was gone, not when the job ended)
            ended = None if p.state == "unknown" else (round(p.ended, 3) if p.ended else None)
            d.update({"command": p.command, "on_pause": p.on_pause, "exit": p.exit,
                      "signal": p.signal, "started": round(p.created, 3), "ended": ended})
            if p.detached:
                d["detached"] = True
        if p.gone:
            d["gone"] = True
            d["note"] = ("the terminal supervisor no longer has it (the computer restarted or tmux "
                         "was stopped); " + ("its outcome is unknown" if p.kind == "job" else
                                             "it is gone"))
            if p.remote and p.remote_note:
                d["note"] = p.remote_note + "; " + ("its outcome is unknown" if p.kind == "job"
                                                    else "it is gone")
        if p.auth is not None:
            d["waiting_auth"] = p.auth.get("state") in ("asking", "unavailable", "cancelled")
        if p.last_auth:
            d["auth"] = p.last_auth
        if p.remote:
            d["remote"] = True
            if p.remote_note and not p.gone:
                d["note"] = p.remote_note
            elif not p.seen and p.live:
                d["note"] = (f"not confirmed by {p.host} yet since the gateway daemon started; "
                             "the next look asks it")
            if p.unconfirmed and p.live:
                d["start_confirmed"] = False
            if p.stop_req:
                d["stop_requested"] = STOP_REQ_WORDS.get(p.stop_req, p.stop_req)
        return d

    def read(self, pid: Any, who: Any, *, history: Any = 0, take: bool = False,
             agent: str = "") -> dict[str, Any]:
        p = self.get(pid)
        if take:
            self._agent_take(p, who, agent)
        return self.view(p, history=history, me=who)

    def view(self, p: Pane, *, history: Any = 0, me: Any = None) -> dict[str, Any]:
        out = self.describe(p, me)
        hist_n = int(history) if isinstance(history, (int, float)) and not isinstance(history, bool) else 0
        try:
            cap = self._capture(p, history=hist_n, persist=True)
        except TermError as e:
            out.update({"seq": p.seq, "lines": []})
            out.setdefault("note", e.message)
            return out
        # the agent reads the physical rows with a value split across a
        # soft-wrap boundary masked in both (_agent_rows); if that can't be
        # had, the logical (rejoined) lines, scrubbed whole
        rows = self._agent_rows(p, history=hist_n)
        if rows is not None:
            lines, hist = rows
            keep = cap["cursor"][1] + 1
        else:
            joined = self._capture_joined(p, history=hist_n)
            plain, hist_plain = joined if joined is not None else (cap["plain"], cap["history"])
            lines = self._scrub_lines(p, plain)
            hist = self._scrub_lines(p, hist_plain) if hist_plain else []
            keep = cap["cursor"][1] + 1 if joined is None else 0
        # the record's facts as of now, not as of before the capture (a remote
        # capture takes a round trip: a credential supplied meanwhile is on the
        # screen and must be on the record too)
        out = self.describe(p, me)
        while lines and not lines[-1].strip() and len(lines) > keep:
            lines.pop()
        vis, t1, used = self._bounded(lines, VIEW_BYTES)
        out.update({"seq": cap["seq"], "cols": cap["cols"], "rows": cap["rows"],
                    "cursor": {"x": cap["cursor"][0], "y": cap["cursor"][1]},
                    "alternate_screen": cap["alt"], "title": cap["title"], "lines": vis,
                    "truncated": t1, "history_size": cap["history_size"]})
        if hist:
            hb, t2, _ = self._bounded(list(reversed(hist)), max(0, VIEW_BYTES - used))
            out["history"] = list(reversed(hb))
            out["history_truncated"] = t2 or len(hb) < len(hist)
        if p.echo_off and p.auth is not None:
            out["note"] = self._auth_note(p)
        return out

    def _auth_note(self, p: Pane) -> str:
        st = (p.auth or {}).get("state")
        if st == "asking":
            return ("a password prompt waits: the user answers it in the gateway's dialog; don't "
                    "type into it")
        if st == "unavailable":
            return ("a password prompt waits, and no gateway dialog can open for it here (" +
                    str((p.auth or {}).get("why") or "") + "); ask the user, or send ^C to abort it")
        if st == "cancelled":
            return ("a password prompt waits; the user cancelled the gateway's dialog for it (send "
                    "^C to abort it, or ask the user)")
        if st == "supplied":
            return "[credential supplied]"
        return ""

    def list(self, who: Any = None, kind: str | None = None) -> list[dict[str, Any]]:
        with self.lock:
            ps = sorted(self.panes.values(), key=lambda x: x.created)
        return [self.describe(p, who) for p in ps if kind is None or p.kind == kind]

    def list_bounded(self, who: Any, kind: str | None, limit: int = LIST_MAX) -> dict[str, Any]:
        """A bounded list for the agent's terminal_list / job_list: at most
        `limit` records (live first, then the most recent), so a session that
        has run many jobs in the last 24 h doesn't return a huge result. The
        contract snapshot and the pane's own list stay complete."""
        with self.lock:
            ps = [p for p in self.panes.values() if kind is None or p.kind == kind]
        total = len(ps)
        if total > limit:
            ps = sorted(ps, key=lambda x: (x.live, x.created), reverse=True)[:limit]
        ps.sort(key=lambda x: x.created)
        return {"items": [self.describe(p, who) for p in ps], "total": total,
                "truncated": total > limit}

    # -- ownership --------------------------------------------------------------------
    def _owner_change(self, p: Pane, owner: str, holder: str | None, by: str) -> None:
        """Lock held: a new owner (or holder); queued writes fail, seq moves."""
        p.owner, p.holder = owner, holder
        p.owner_gen += 1
        p.seq += 1
        self._changed()
        self._emit("terminal.owner", terminal=p.id, owner=owner, agent=holder or None, by=by)

    def _agent_take(self, p: Pane, who: Any, agent: str) -> None:
        with self.lock:
            if not p.live:
                raise TermError(410, "ended", f"gateway: {p.id} has ended")
            if p.owner == "user":
                raise TermError(409, "user", USER_HOLDS)
            if p.session_key() != session_key(who):
                if self._live_session(p) is not None:
                    raise TermError(403, "other_session", f"gateway: {p.id} belongs to another "
                                    "Claude Code session that is still running")
                # an orphan (its session ended): this session adopts it
                p.session_pid, p.session_start = who.pid, who.start
                p.session_id = getattr(who, "session_id", "")
            self._owner_change(p, "agent", _clean(agent, 80), "agent")

    def ui_take(self, pid: Any, who: Any) -> dict[str, Any]:
        p = self.get(pid)
        with self.lock:
            if p.owner != "user":
                self._owner_change(p, "user", None, "user")
            return {"ok": True, "owner": p.owner, "seq": p.seq}

    def ui_release(self, pid: Any, who: Any) -> dict[str, Any]:
        p = self.get(pid)
        with self.lock:
            if p.owner != "agent":
                self._owner_change(p, "agent", None, "user")
            return {"ok": True, "owner": p.owner, "seq": p.seq}

    # -- writing ------------------------------------------------------------------------
    def _deliver(self, p: Pane, text: str | None, keys: list[str], enter: bool) -> str:
        """Text through a tmux buffer (stdin; never a command line), keys by name."""
        if p.remote:
            return self._deliver_remote(p, text, keys, enter)
        if text:
            buf = "gw" + secrets.token_hex(6)
            self.tmux.run("load-buffer", "-b", buf, "-", input=text.encode("utf-8"))
            self.tmux.run("paste-buffer", "-d", "-b", buf, "-t", p.target)
        for k in keys:
            self.tmux.run("send-keys", "-t", p.target, k)
        if enter:
            self.tmux.run("send-keys", "-t", p.target, "Enter")
        return "delivered"

    def _deliver_remote(self, p: Pane, text: str | None, keys: list[str], enter: bool) -> str:
        """The same over ssh: the text on ssh's stdin into load-buffer (a
        uniquely named buffer), then one command line with the paste and the
        keys. A lost answer is never reported as "nothing typed": the paste
        deletes its buffer, so a buffer gone means it went in (returns
        "lost_but_delivered"), one still there means it didn't (removed, then
        the error); when the host can't say, the outcome is unknown (409
        outcome_unknown, the seq bumped so a blind repeat is refused as stale)."""
        tm = self._tm(p)
        cmds: list[str] = []
        buf = ""
        if text:
            buf = "gw" + secrets.token_hex(6)
            try:
                tm.run("load-buffer", "-b", buf, "-", input=text.encode("utf-8"))
            except TermError as e:
                # loading types nothing; a buffer that did arrive is removed (now,
                # or at the host's next answer)
                try:
                    tm.run("delete-buffer", "-b", buf, check=False)
                except TermError:
                    if e.extra.get("ambiguous"):
                        with self.lock:
                            p.pending_bufs.append(buf)
                raise
            cmds += ["paste-buffer", "-d", "-b", buf, "-t", p.target]
        for k in keys + (["Enter"] if enter else []):
            cmds += ([";"] if cmds else []) + ["send-keys", "-t", p.target, k]
        if not cmds:
            return "delivered"
        try:
            tm.run(*cmds)
            return "delivered"
        except TermError as e:
            if not e.extra.get("ambiguous"):
                if buf:
                    with contextlib.suppress(TermError):
                        tm.run("delete-buffer", "-b", buf, check=False)
                raise
            left = self._buffer_left(tm, buf) if buf else None
            if left is False:
                # the paste took the buffer: it (and the keys after it, in the
                # same tmux command) went in; only the answer was lost
                return "lost_but_delivered"
            if left is True:
                with contextlib.suppress(TermError):
                    tm.run("delete-buffer", "-b", buf, check=False)
                raise TermError(e.status, e.code, f"{e.message}; nothing was typed (the text "
                                "was still waiting in its buffer, now removed)") from None
            with self.lock:
                p.seq += 1                 # a repeat quoting the old seq is stale now
                if buf:
                    p.pending_bufs.append(buf)
                self._changed()
            raise TermError(409, "outcome_unknown", f"{e.message}; the input went out to "
                            f"{p.host} but its answer was lost, so whether it was typed isn't "
                            "known: read the screen again (terminal_read) before sending "
                            "anything", ambiguous=True) from None

    def _check_text(self, text: Any) -> str | None:
        if text in (None, ""):
            return None
        if not isinstance(text, str) or len(text) > TEXT_MAX:
            raise TermError(400, "bad_text", "gateway: text is a string of at most 16 KiB")
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", text):
            raise TermError(400, "bad_text", "gateway: text can't hold control characters; send "
                            "them as keys (C-c, Escape, Enter, ...)")
        return text

    def _check_keys(self, keys: Any) -> list[str]:
        if keys in (None, []):
            return []
        if isinstance(keys, str):
            keys = [keys]
        if not isinstance(keys, list) or len(keys) > KEYS_MAX:
            raise TermError(400, "bad_keys", f"gateway: keys is a list of at most {KEYS_MAX} key names")
        out = []
        for k in keys:
            t = screen.tmux_key(k)
            if t is None:
                raise TermError(400, "bad_keys", "gateway: unknown key "
                                f"{_clean(k, 20)!r} (Enter, Tab, Escape, BSpace, Up, Down, Left, "
                                "Right, Home, End, PageUp, PageDown, Delete, F1-F12, C-a..C-z, M-x)")
            out.append(t)
        return out

    @staticmethod
    def _stale(current: int, quoted: Any) -> bool:
        """The screen moved on since the seq the agent quoted (checked when the
        input is queued and again right before it goes in)."""
        return current != quoted

    def _writable(self, p: Pane, who: Any, agent: str) -> None:
        """Lock held: may this agent write to the pane now?"""
        if p.live and p.remote and (p.unconfirmed or p.dispatching):
            raise TermError(409, "unconfirmed", UNCONFIRMED.format(id=p.id, host=p.host))
        if not p.live or not p.alive:
            raise TermError(410, "ended", f"gateway: {p.id} has ended" +
                            (f" (exit {p.exit})" if p.exit is not None else ""))
        if self._paused(p.session_key()) or self._paused(session_key(who)):
            raise TermError(409, "paused", PAUSED)
        if p.session_key() != session_key(who):
            raise TermError(403, "other_session", f"gateway: {p.id} belongs to another Claude Code "
                            "session" + ("" if self._live_session(p) is not None else
                                         "; read it with take=true to adopt it"))
        if p.owner == "user":
            raise TermError(409, "user", USER_HOLDS)
        if p.holder is not None and agent != p.holder:
            raise TermError(409, "holder", f"gateway: another agent ({p.holder or 'the main agent'}) "
                            f"holds {p.id}'s input; read it with take=true to take it over")
        if p.auth is not None and p.auth.get("state") == "asking":
            raise TermError(409, "auth", AUTH_WAITS)
        if p.remote and p.state in ("disconnected", "waiting_auth") and p.remote_note:
            raise TermError(503, "disconnected", p.remote_note + " (nothing was typed)")

    def send(self, pid: Any, who: Any, *, agent: str = "", seq: Any = None, text: Any = None,
             keys: Any = None, enter: Any = False, delay_ms: Any = 0,
             read_after: Any = True) -> dict[str, Any]:
        p = self.get(pid)
        text = self._check_text(text)
        klist = self._check_keys(keys)
        enter = bool(enter)
        if not text and not klist and not enter:
            raise TermError(400, "empty", "gateway: nothing to send (text, keys or enter)")
        if not isinstance(seq, int) or isinstance(seq, bool):
            raise TermError(400, "no_seq", "gateway: quote the seq of the screen you read "
                            "(terminal_read gives it)")
        try:
            delay = max(0, min(DELAY_MAX_MS, int(delay_ms or 0))) / 1000.0
        except (TypeError, ValueError):
            delay = 0.0
        agent = _clean(agent, 80)
        with self.lock:
            self._writable(p, who, agent)
            gen = p.owner_gen
        self._capture(p)
        with self.lock:
            if self._stale(p.seq, seq):
                raise TermError(409, "stale", f"gateway: the screen changed since seq {seq} (it is "
                                f"{p.seq} now): read it again (terminal_read) and decide again",
                                seq=p.seq)
            p.queued += 1
            self.rev += 1                      # the pane shows the queue
            self.cond.notify_all()
        try:
            if delay:
                end = time.monotonic() + delay
                with self.lock:
                    while p.owner_gen == gen and p.live and not self.stopping.is_set():
                        left = end - time.monotonic()
                        if left <= 0:
                            break
                        self.cond.wait(min(left, 0.25))
            with p.write_lock:
                with self.lock:
                    if p.owner_gen != gen:
                        raise TermError(409, "taken", f"gateway: {TAKEN}", owner=p.owner, seq=p.seq)
                    self._writable(p, who, agent)
                cap = self._capture(p)
                with self.lock:
                    if p.owner_gen != gen:
                        raise TermError(409, "taken", f"gateway: {TAKEN}", owner=p.owner, seq=p.seq)
                    if self._stale(cap["seq"], seq):
                        raise TermError(409, "stale", f"gateway: the screen changed while the input "
                                        f"waited (seq {seq} -> {cap['seq']}): read it again",
                                        seq=cap["seq"])
                    # the first agent to write holds the input; the main agent's
                    # own id is empty, so None (not "") means unclaimed
                    if p.holder is None:
                        p.holder = agent
                how = self._deliver(p, text, klist, enter)
        finally:
            with self.lock:
                p.queued -= 1
                self.rev += 1
                self.cond.notify_all()
        time.sleep(SETTLE)
        out: dict[str, Any] = {"ok": True, "delivered": True, "id": p.id}
        lost = ""
        if how == "lost_but_delivered":
            lost = (f"{p.host}'s answer was lost, but the text left its buffer there, so it was "
                    "typed; read the screen to see what it did")
        try:
            if read_after not in (False, 0):
                v = self.view(p, me=who)
                out.update({k: v[k] for k in ("seq", "lines", "cursor", "alternate_screen",
                                              "truncated", "owner", "state") if k in v})
                if "note" in v:
                    out["note"] = v["note"]
            else:
                out["seq"] = self._capture(p, persist=True)["seq"]
        except TermError as e:
            if not lost:
                raise
            out["note"] = e.message
        if lost:
            out["note"] = lost + ("; " + out["note"] if out.get("note") else "")
        return out

    def resize(self, pid: Any, who: Any, cols: Any, rows: Any, *, by: str = "agent",
               agent: str = "") -> dict[str, Any]:
        p = self.get(pid)
        c, r = self._size(cols, rows)
        with self.lock:
            if by == "agent":
                if p.owner == "user":
                    raise TermError(409, "user", USER_HOLDS)
                if p.session_key() != session_key(who):
                    raise TermError(403, "other_session", f"gateway: {p.id} belongs to another "
                                    "Claude Code session")
            if p.live and p.remote and (p.unconfirmed or p.dispatching):
                raise TermError(409, "unconfirmed", UNCONFIRMED.format(id=p.id, host=p.host))
            if not p.alive:
                raise TermError(410, "ended", f"gateway: {p.id} has ended")
        if (c, r) != (p.cols, p.rows):
            self._tm(p).run("resize-window", "-t", p.target, "-x", str(c), "-y", str(r))
        cap = self._capture(p)
        return {"ok": True, "id": p.id, "cols": cap["cols"], "rows": cap["rows"], "seq": cap["seq"]}

    def _pgrp(self, p: Pane, foreground: bool) -> int:
        if p.pane_pid <= 0:
            self._refresh(p)
        if p.pane_pid <= 0 and p.remote and p.live:
            # not known from the host yet (a restart, a disconnect): never "ended"
            raise TermError(503, "remote_unreachable", p.remote_note or
                            f"gateway: {p.host} hasn't answered about {p.id} yet; nothing was sent")
        if p.pane_pid <= 0:
            raise TermError(410, "ended", f"gateway: {p.id} has no running process")
        if foreground:
            fg = self._tm(p).fg_pgrp(p.pane_pid) if p.remote else foreground_pgrp(p.pane_pid)
            if fg > 0:
                return fg
        return p.pane_pid

    def _killpg(self, p: Pane, pg: int, name: str) -> None:
        """A signal to a process group of the pane's host (raises
        ProcessLookupError / PermissionError locally like os.killpg)."""
        if p.remote:
            self._tm(p).kill(pg, name)
            return
        os.killpg(pg, screen.SIGNALS[name])

    def _stop_group(self, p: Pane, pg: int) -> bool:
        if p.remote:
            return self._tm(p).stop_group(pg, p.pane_pid)
        return stop_group(pg, p.pane_pid)

    def _cont_group(self, p: Pane, pg: int) -> bool:
        """SIGCONT to a job's process group; True when ps showed a member of it
        stopped (state T) just before (raises like _killpg)."""
        if p.remote:
            return self._tm(p).cont_group(pg)
        was = any(st.startswith("T") for st in group_members(pg).values())
        os.killpg(pg, signal.SIGCONT)
        return was

    def _stop_begin(self) -> bool:
        """A job's STOP or TSTP is about to apply: False once gated drains
        (lifecycle.Daemon.pause_begin, as a pause: the drain waits for the
        ones being applied, so what they stop is resumed with the rest)."""
        begin = getattr(self.d, "pause_begin", None)
        if begin is None:
            return not getattr(self.d, "draining", "")
        return bool(begin())

    def _stop_end(self) -> None:
        end = getattr(self.d, "pause_end", None)
        if end is not None:
            end()

    def signal(self, pid: Any, who: Any, sig: Any, *, by: str = "agent") -> dict[str, Any]:
        p = self.get(pid)
        name = screen.signal_name(sig)
        if name is None:
            raise TermError(400, "bad_signal", "gateway: signal is one of " + ", ".join(screen.SIGNALS))
        # a job's STOP or TSTP suspends it (the group stop below); refused once
        # gated drains: nothing could resume it then (the drain resumed what
        # was stopped when it began)
        suspend = p.kind == "job" and name in ("STOP", "TSTP")
        if suspend and not self._stop_begin():
            raise TermError(503, "draining", STOP_DRAINING)
        try:
            return self._signal(p, who, name, by, suspend)
        finally:
            if suspend:
                self._stop_end()

    def _signal(self, p: Pane, who: Any, name: str, by: str, suspend: bool) -> dict[str, Any]:
        with self.lock:
            if by == "agent":
                if p.kind == "terminal" and p.owner == "user":
                    raise TermError(409, "user", USER_HOLDS)
                if p.session_key() != session_key(who):
                    raise TermError(403, "other_session", f"gateway: {p.id} belongs to another "
                                    "Claude Code session")
                # while the task is paused the agent may stop or cancel work, but
                # not resume it: CONT would undo a pause's suspend (checkpoint's
                # /v1/resume is the way back)
                if name in ("CONT",) and (self._paused(p.session_key()) or
                                          self._paused(session_key(who))):
                    raise TermError(409, "paused", PAUSED)
            if p.live and p.remote and (p.unconfirmed or p.dispatching):
                raise TermError(409, "unconfirmed", UNCONFIRMED.format(id=p.id, host=p.host) +
                                " (terminal_close stops it either way)")
            if not p.alive:
                return {"ok": True, "id": p.id, "state": p.state, "exit": p.exit, "signal": p.signal,
                        "note": f"{p.id} had already ended"}
        # a terminal: its foreground job (as a key would); a job: its process group
        pg = self._pgrp(p, foreground=p.kind == "terminal")
        stopped: bool | None = None           # a job's STOP or TSTP: did it hold (ps)?
        was = p.paused_as
        try:
            if suspend:
                # tmux resumes a pane's own process after any stop but SIGTTIN or
                # SIGTTOU (so a plain SIGTSTP never holds): the group stop, read
                # back in ps; a job is recorded suspended only when it is
                stopped = self._stop_group(p, pg)
                if not stopped and was != "suspended":
                    # nothing is left half stopped without a record (the drain
                    # and /v1/resume continue only what is recorded)
                    self._killpg(p, pg, "CONT")
            elif name == "STOP":
                self._stop_group(p, pg)               # tmux would resume the pane's own process
            else:
                self._killpg(p, pg, name)
        except ProcessLookupError:
            pass
        except PermissionError:
            raise TermError(403, "signal", "gateway: that process group isn't this user's") from None
        with self.lock:
            if p.kind == "job":
                if name in ("TERM", "KILL", "INT", "HUP", "QUIT"):
                    p.cancel = p.cancel or name in ("TERM", "KILL")
                if stopped:
                    p.paused_as = "suspended"
                elif name == "CONT" and p.paused_as == "suspended":
                    p.paused_as = ""
            self._dirty = True
        time.sleep(0.2)
        self._look(p)
        out = {"ok": True, "id": p.id, "signal": name, "state": p.state, "exit": p.exit}
        if stopped is False:
            out["note"] = NOT_STOPPED if was != "suspended" else NOT_STOPPED_AGAIN
        return out

    def _look(self, p: Pane) -> None:
        """Ask again now about this pane: the local tick, or its host's poll."""
        if p.remote:
            try:
                self._poll_host(p.host)
            except Exception as e:  # noqa: BLE001
                self.d.log(f"terminals: polling {p.host} failed ({type(e).__name__})")
        else:
            self.tick()

    def close(self, pid: Any, who: Any, *, by: str = "agent") -> dict[str, Any]:
        p = self.get(pid)
        with self.lock:
            if by == "agent" and p.session_key() != session_key(who) and \
                    self._live_session(p) is not None:
                raise TermError(403, "other_session", f"gateway: {p.id} belongs to another Claude "
                                "Code session")
            if by == "agent" and p.kind == "terminal" and p.owner == "user":
                raise TermError(409, "user", USER_HOLDS)
            was_live = p.live
            if p.dispatching:
                raise TermError(409, "starting", f"gateway: {p.id} is being started on {p.host} right "
                                "now; close it once its start is answered")
            # set before the kill so a look meanwhile reads the end as this close;
            # given back if the close doesn't reach the host (below)
            prev = (p.closing, p.cancel)
            p.closing = True
            if p.kind == "job" and (p.alive or (p.remote and p.live)):
                p.cancel = True
        if p.remote and p.live and p.unconfirmed:
            # a start whose answer was lost: make sure it can't start late (its
            # start file's claim), then kill whatever session came of it
            ext = "rc" if p.kind == "terminal" else "sh"
            try:
                self._tm(p).claim_start(f"terms/{p.id}.{p.nonce}.{ext}", p.id)
            except TermError as e:
                self._close_failed(p, prev, e)
        try:
            self._tm(p).run("kill-session", "-t", f"={p.id}", check=False)
        except TermError as e:
            self._close_failed(p, prev, e)
        with self.lock:
            p.stop_req = ""
            p.unconfirmed = False
            self._closed(p)
            if p.kind == "terminal" and was_live:
                self._emit("terminal.closed", terminal=p.id, reason=by)
            self._changed()
        return {"ok": True, "id": p.id, "state": p.state}

    def _close_failed(self, p: Pane, prev: tuple[bool, bool], e: TermError) -> None:
        """A close that didn't reach the host (or whose answer was lost):
        closing and cancel go back to what they were (a job that later ends
        by itself reports its own end, never "canceled"); `stop_req` records
        the request apart from the state ("undelivered", or "unsure" when it
        may have landed: then the host's next answer decides). Raises."""
        unsure = bool(e.extra.get("ambiguous"))
        with self.lock:
            p.closing, p.cancel = prev
            if p.live and p.remote:
                p.stop_req = "unsure" if unsure else "undelivered"
            self._changed()
        if not p.remote:
            raise e
        if unsure:
            raise TermError(e.status, "outcome_unknown", f"{e.message}; the close went out but its "
                            f"answer was lost, so whether {p.id} was closed isn't known: the "
                            "gateway asks the host and reports it (read its state again)",
                            ambiguous=True) from None
        raise TermError(e.status, e.code, f"{e.message}; {p.id} was not closed (nothing reached "
                        f"{p.host}): close it again when the host can be reached") from None

    # -- jobs -------------------------------------------------------------------------------
    def job(self, pid: Any) -> Pane:
        p = self.get(pid)
        if p.kind != "job":
            raise TermError(400, "not_job", f"gateway: {p.id} is a terminal, not a job")
        return p

    def tail(self, pid: Any, nbytes: Any = 8192, lines: Any = None) -> dict[str, Any]:
        p = self.job(pid)
        try:
            n = max(1, min(TAIL_MAX, int(nbytes or 8192)))
        except (TypeError, ValueError):
            n = 8192
        with self.lock:
            data = bytes(p.ring)
            total = p.total
        note = ""
        if p.remote and not p.gone and not p.closing:
            # a remote job's output is its tmux history on the host (kept an
            # hour after it ended, like a local pane's session)
            try:
                data = self._tm(p).run("capture-pane", "-p", "-J", "-S", "-", "-E", "-", "-t",
                                       p.target, check=False)[-RING_MAX:]
                with self.lock:
                    p.total = max(p.total, len(data))
                    total = p.total
            except TermError as e:
                note = e.message
        elif not data and p.alive:
            with contextlib.suppress(TermError):
                data = self.tmux.run("capture-pane", "-p", "-J", "-S", "-", "-E", "-", "-t",
                                     p.target, check=False)[-RING_MAX:]
        text = screen.clean_stream(data)
        from .. import scrub
        text = scrub.scrub_text(text, extra=list(p.secrets))
        enc = text.encode("utf-8")
        truncated = len(enc) > n or total > len(data)
        if len(enc) > n:
            text = enc[-n:].decode("utf-8", "ignore")
            nl = text.find("\n")
            if 0 <= nl < 200:
                text = text[nl + 1:]
        if isinstance(lines, int) and not isinstance(lines, bool) and lines > 0:
            parts = text.split("\n")
            if len(parts) > lines + 1:
                text = "\n".join(parts[-(lines + 1):])
                truncated = True
        out = {"ok": True, "job": p.id, "state": p.state, "text": text, "truncated": truncated,
               "offset": max(0, total - len(text.encode("utf-8"))), "bytes_total": total}
        if note or (p.remote and p.remote_note):
            out["note"] = note or p.remote_note
        return out

    # -- the terminal pane (UI plane) ---------------------------------------------------
    def ui_view(self, p: Pane) -> dict[str, Any]:
        cap = self._capture(p)
        # scrubbed through the plain text: a line that changed is drawn plain
        masked = self._scrub_lines(p, cap["plain"])
        out_lines = [runs if m == pl else [{"t": m}]
                     for runs, pl, m in zip(cap["styled"], cap["plain"], masked)]
        return {"ok": True, "id": p.id, "kind": p.kind, "state": p.state, "owner": p.owner,
                "seq": cap["seq"], "rev": self.rev, "cols": cap["cols"], "rows": cap["rows"],
                "cursor": {"x": cap["cursor"][0], "y": cap["cursor"][1]},
                "alternate_screen": cap["alt"], "title": cap["title"], "lines": out_lines,
                "echo_off": bool(p.echo_off), "auth": self._auth_note(p) if p.auth else "",
                "agent": p.holder or "", "queued": p.queued, "exit": p.exit,
                "command": p.command if p.kind == "job" else ""}

    def ui_screen(self, pid: Any, seq: Any, wait: Any) -> dict[str, Any]:
        p = self.get(pid)
        try:
            last = int(seq)
        except (TypeError, ValueError):
            last = 0
        try:
            w = max(0.0, min(WAIT_MAX, float(wait or 0)))
        except (TypeError, ValueError):
            w = 0.0
        end = time.monotonic() + w
        rev0 = self.rev
        while True:
            if not p.live:
                # an ended pane still shows its last screen while tmux keeps it
                try:
                    v = self.ui_view(p) if not p.gone and not p.closing else None
                except TermError:
                    v = None
                base = v or {**self.describe(p), "ok": True, "seq": p.seq, "rev": self.rev,
                             "lines": []}
                return {**base, "state": p.state, "exit": p.exit, "ended": True}
            try:
                v = self.ui_view(p)
            except TermError:
                v = {**self.describe(p), "ok": True, "seq": p.seq, "rev": self.rev, "lines": []}
            if v["seq"] != last or self.rev != rev0 or time.monotonic() >= end:
                return v
            with self.lock:
                # a remote pane costs an ssh round trip per look
                self.cond.wait(UI_POLL if not p.remote else 0.5)

    def ui_keys(self, pid: Any, who: Any, items: Any) -> dict[str, Any]:
        """The person's keys from the terminal pane: they take the input (a
        key is a takeover), then go in order. Typed text is refused while a
        password prompt waits (it goes through the gateway's dialog)."""
        p = self.get(pid)
        if not isinstance(items, list) or len(items) > 256:
            raise TermError(400, "bad_keys", "gateway: items is a list")
        with self.lock:
            if p.live and p.remote and (p.unconfirmed or p.dispatching):
                raise TermError(409, "unconfirmed", UNCONFIRMED.format(id=p.id, host=p.host))
            if not p.alive:
                raise TermError(410, "ended", f"gateway: {p.id} has ended")
            if p.owner != "user":
                self._owner_change(p, "user", None, "user")
        sent = 0
        refused = False
        with p.write_lock:
            for it in items:
                if not isinstance(it, dict):
                    continue
                if it.get("k") == "text":
                    t = it.get("v")
                    if not isinstance(t, str) or not t or len(t) > TEXT_MAX or \
                            re.search(r"[\x00-\x08\x0b-\x1f\x7f]", t):
                        continue
                    if p.echo_off:
                        refused = True
                        continue
                    self._deliver(p, t, [], False)
                    sent += 1
                elif it.get("k") == "key":
                    k = screen.tmux_key(it.get("v"))
                    if k is None:
                        continue
                    self._deliver(p, None, [k], False)
                    sent += 1
                elif it.get("k") == "line":
                    t = it.get("v")
                    if not isinstance(t, str) or len(t) > TEXT_MAX or \
                            re.search(r"[\x00-\x08\x0b-\x1f\x7f]", t):
                        continue
                    if p.echo_off:
                        refused = True
                        continue
                    self._deliver(p, t or None, [], True)
                    sent += 1
        out: dict[str, Any] = {"ok": True, "sent": sent, "owner": p.owner}
        if refused:
            out["refused"] = ("a password prompt waits: answer it in the gateway's dialog (typed "
                              "text isn't sent to it from here)")
        return out

    # -- password prompts in a pane ---------------------------------------------------------
    def _sig(self, p: Pane) -> str:
        try:
            cap = self._capture(p)
        except TermError:
            return ""
        last = next((ln for ln in reversed(cap["plain"]) if ln.strip()), "")
        return hashlib.sha1(f"{cap['cursor']}|{cap['history_size']}|{last}".encode()).hexdigest()

    def _prompt_step(self, p: Pane, echo_off: bool, tp: int | None = None, comm: str = "") -> None:
        """One look at a pane's password-prompt state. A remote pane's poll
        passes its foreground group and that program's name (from the host's
        ps; never its argv)."""
        with self.lock:
            was = p.echo_off
            p.echo_off = echo_off
            auth = p.auth
        if auth is not None and auth.get("state") == "supplying":
            return                                   # the dialog's value is going in now
        if not echo_off:
            if auth is not None:
                rid = auth.get("dialog")
                with self.lock:
                    p.auth = None
                    self._changed(save=False)
                if rid and auth.get("state") == "asking":
                    self._cancel_dialog(rid, "the program stopped asking")
            elif was:
                with self.lock:
                    self._changed(save=False)
            return
        sig = self._sig(p)
        if auth is not None and (auth.get("sig") == sig or auth.get("state") == "asking"):
            return
        # a new password prompt (or the same program asking again after an answer)
        check = None
        if p.remote:
            tp = int(tp or 0)
            # the foreground group's programs as the host's ps names them, its
            # leader first: a root prompt may come from any member (`echo x |
            # sudo tee /etc/f` leads with echo), so every member is looked at
            names = [n for n in (comm or "").split(",")
                     if re.fullmatch(r"[A-Za-z0-9_.+@-]{1,40}", n) and n != "-"][:9]
            root = next((n for n in names if n in REMOTE_SUDO_COMMS), "")
            name = root or (names[0] if names else "")
            fg = (f"{name} on {p.host} (the host's name for it only)" if name else "")
            check = {"section": "hosts", "entry": p.host, "right": "ssh"}
            if root:
                # a root password prompt on the host: only where the form lets
                # Claude use sudo there (the dialog's recheck holds it to that)
                check = {"section": "hosts", "entry": p.host, "right": ["ssh", "sudo"]}
                if self._remote_sudo_right(p.host) is False:
                    with self.lock:
                        p.auth = {"state": "unavailable", "sig": sig, "tpgid": tp,
                                  "why": f"sudo on {p.host} is off in gateway.toml, so the gateway "
                                         "asks for no root password there"}
                        self._dirty = True
                        self._changed()
                    return
        else:
            tp = foreground_pgrp(p.pane_pid)
            fg = _exe_word(tp) if tp > 0 else ""
        sess = self._live_session(p)
        ok, why = self.d.dialogs.available(sess) if sess is not None else (False, "no_session")
        if not ok:
            with self.lock:
                p.auth = {"state": "unavailable", "why": self._why(why), "sig": sig, "tpgid": tp}
                self._dirty = True
                self._changed()
            return
        token = secrets.token_hex(8)
        where = f" on {p.host}" if p.remote else ""
        lines = [f"A program in gateway {p.kind} {p.id}{where} is asking for a password (what is "
                 "typed there isn't shown).",
                 f"Foreground program: {fg or 'unknown'}",
                 "What you type here goes to that program only, through the gateway; Claude sees "
                 "only \"[credential supplied]\". Look at the terminal (/gate-terminal) to see the "
                 "prompt; cancel if you don't expect it."]
        spec = {"kind": "secret", "title": "Password for a gateway terminal" + where,
                "entry": "terminal", "what": "terminal password", "target": p.id, "lines": lines,
                "paste": True, "ok_label": "Send", "timeout": 600}
        if check is not None:
            spec["check"] = check
        try:
            r = self.d.dialogs.open_owned(sess, spec,
                                          handler=lambda _r, values: self._supply(p.id, token, values),
                                          on_close=self._on_dialog_close, terminal=p.id)
        except Exception as e:  # noqa: BLE001
            self.d.log(f"terminals: {p.id}: no dialog ({type(e).__name__})")
            r = {"available": False, "reason": "error"}
        with self.lock:
            if r.get("available"):
                p.auth = {"state": "asking", "dialog": r.get("id"), "sig": sig, "tpgid": tp,
                          "token": token}
            else:
                p.auth = {"state": "unavailable", "why": self._why(str(r.get("reason") or "")),
                          "sig": sig, "tpgid": tp}
            self._dirty = True
            self._changed()

    @staticmethod
    def _why(code: str) -> str:
        from . import dialogs
        return dialogs.UNAVAILABLE.get(code, code or "no session to ask in")

    def _on_dialog_close(self, rid: str, outcome: str) -> None:
        # called by dialogs with its lock held: noted without this lock (the
        # tick handles it), so the two locks are never taken in both orders
        self.closed_dialogs.append((rid, outcome))

    def _dialog_closed(self, rid: str, outcome: str) -> None:
        with self.lock:
            for p in self.panes.values():
                a = p.auth
                if a is not None and a.get("dialog") == rid and a.get("state") == "asking":
                    if outcome == "ok":
                        continue            # _supply set it
                    a["state"] = "cancelled"
                    self._changed(save=False)

    def _cancel_dialog(self, rid: str, why: str) -> None:
        try:
            self.d.dialogs.close_owned(rid, "cancelled", why)
        except Exception:  # noqa: BLE001
            pass

    def _supply(self, pid: str, token: str, values: list[str]) -> tuple[bool, str]:
        """The dialog's answer (a worker thread): to the pane that asked, after
        a recheck; never logged."""
        p = self.panes.get(pid)
        if p is None or not values:
            return False, "the terminal isn't there any more"
        with self.lock:
            a = p.auth
            ok = a is not None and a.get("token") == token and a.get("state") == "asking" and p.alive
            tp = a.get("tpgid") if a else 0
            if ok:
                a["state"] = "supplying"     # the tick leaves it alone while the value goes in
        if not ok:
            return False, "the terminal isn't waiting for that password any more"
        if p.remote:
            return self._supply_remote(p, a, tp, values)
        mode = tty_mode(p.tty)
        if mode is None or mode[0] or not mode[1] or foreground_pgrp(p.pane_pid) != tp:
            with self.lock:
                if p.auth is a:
                    a["state"] = "asking"
            return False, "the terminal isn't waiting for that password any more"
        value = values[0]
        piped = p.kind == "job" and p.fifo is not None
        # masked and noted before it goes in: the program may print before this returns
        with self.lock:
            before = p.last_auth
            added = len(value) >= 8 and value not in p.secrets
            if added:
                p.secrets.append(value)
            p.last_auth = "[credential supplied]"
        try:
            if piped:
                self.tmux.run("pipe-pane", "-t", p.target, check=False)
            buf = "gw" + secrets.token_hex(6)
            self.tmux.run("load-buffer", "-b", buf, "-", input=value.encode("utf-8"))
            self.tmux.run("paste-buffer", "-d", "-b", buf, "-t", p.target)
            self.tmux.run("send-keys", "-t", p.target, "Enter")
        except TermError:
            with self.lock:
                if p.auth is a:
                    a["state"] = "asking"
                p.last_auth = before
                if added and value in p.secrets:
                    p.secrets.remove(value)
            return False, "the terminal supervisor couldn't deliver it"
        finally:
            if piped and p.fifo is not None:
                with contextlib.suppress(TermError):
                    self.tmux.run("pipe-pane", "-o", "-t", p.target, f"exec cat > {_q(str(p.fifo))}")
        time.sleep(0.1)
        sig = self._sig(p)
        with self.lock:
            p.auth = {"state": "supplied", "sig": sig, "tpgid": tp}
            self._changed(save=False)
        value = ""
        values.clear()
        return True, "credential supplied to the terminal"

    def _supply_remote(self, p: Pane, a: dict[str, Any], tp: int,
                       values: list[str]) -> tuple[bool, str]:
        """A dialog's value to a remote pane (PLAN-v4 phase 6): the same
        recheck asked of the host (the pane's tty still ECHO off with ICANON
        on, the same foreground group), then the value on ssh's stdin into
        the runtime tmux's load-buffer, pasted with Enter: never on a command
        line here or there, never logged."""
        from .remote import parse_stty

        def back(why: str) -> tuple[bool, str]:
            with self.lock:
                if p.auth is a:
                    a["state"] = "asking"
            return False, why
        try:
            tm = self._tm(p)
            _infos, ttys = tm.poll()
        except TermError:
            return back(f"{p.host} can't be reached now, so nothing was sent")
        cur = ttys.get(p.id)
        mode = parse_stty(cur[1], self.d.remote.get(p.host).platform) if cur else None
        if mode is None or mode[0] or not mode[1] or cur[0] != tp:
            return back("the terminal isn't waiting for that password any more")
        value = values[0]
        with self.lock:
            before = p.last_auth
            added = len(value) >= 8 and value not in p.secrets
            if added:
                p.secrets.append(value)
            p.last_auth = "[credential supplied]"
        buf = "gw" + secrets.token_hex(6)
        try:
            tm.run("load-buffer", "-b", buf, "-", input=value.encode("utf-8"))
            try:
                tm.run("paste-buffer", "-d", "-b", buf, "-t", p.target, ";", "send-keys", "-t",
                       p.target, "Enter")
            except TermError:
                # the answer to the paste was lost (a slow or dropped
                # connection): the buffer is deleted only by the paste, so
                # one that is gone went in; one that is still there didn't
                if self._buffer_left(tm, buf) is not False:
                    raise
        except TermError as e:
            self.d.log(f"terminals: {p.id}: the password didn't go in ({e.code})")
            with self.lock:
                p.last_auth = before
                if added and value in p.secrets:
                    p.secrets.remove(value)
            with contextlib.suppress(TermError):
                tm.run("delete-buffer", "-b", buf, check=False)
            return back(f"the gateway couldn't deliver it to {p.host}")
        time.sleep(0.2)
        sig = self._sig(p)
        with self.lock:
            p.auth = {"state": "supplied", "sig": sig, "tpgid": tp}
            self._changed(save=False)
        value = ""
        values.clear()
        return True, f"credential supplied to the terminal on {p.host}"

    @staticmethod
    def _buffer_left(tm: Any, buf: str) -> bool | None:
        """Is the named paste buffer still on the host's tmux? None when the
        host can't say."""
        try:
            # asked even right after a failure (the host may be fine: only one
            # answer was lost), never skipped by the connection's fast fail
            out = tm.run("list-buffers", "-F", "#{buffer_name}", check=False, insist=True)
        except TermError:
            return None
        return buf in out.decode("utf-8", "replace").split()

    def _remote_sudo_right(self, host: str) -> Any:
        try:
            eff = self.d.effective()
        except Exception:  # noqa: BLE001
            return False
        if eff is None:
            return False
        return eff.right(host, "sudo")

    # -- remote hosts: the pollers (PLAN-v4 phase 6) ----------------------------------------
    def _ensure_poller(self, host: str) -> None:
        if self.stopping.is_set() or getattr(self.d, "remote", None) is None:
            return
        with self.lock:
            t = self.pollers.get(host)
            if t is not None and t.is_alive():
                return
            t = threading.Thread(target=self._poll_loop, args=(host,), daemon=True,
                                 name=f"gw-remote-{host}")
            self.pollers[host] = t
        t.start()

    def _poll_loop(self, host: str) -> None:
        while not self.stopping.is_set():
            try:
                busy, wait = self._poll_host(host)
            except Exception as e:  # noqa: BLE001 - the poller never dies quietly
                self.d.log(f"terminals: polling {host} failed ({type(e).__name__})")
                busy, wait = True, 5.0
            if not busy:
                with self.lock:
                    if self.pollers.get(host) is threading.current_thread():
                        self.pollers.pop(host, None)
                return
            self.stopping.wait(wait)

    def owner_session_for_host(self, host: str) -> Any:
        """A live owner session of work on that host (where gated's dialogs
        about the host open when no caller is at hand)."""
        with self.lock:
            ps = [p for p in self.panes.values() if p.live and p.host == host]
        for p in sorted(ps, key=lambda x: -x.created):
            s = self._live_session(p)
            if s is not None:
                return s
        return None

    def machine_changed(self, host: str, old: str, new: str) -> None:
        """The user accepted that `host` is another machine now: what was
        started on the old one can't be reached through it (unknown, never
        exited)."""
        with self.lock:
            for p in self.panes.values():
                if p.live and p.host == host and p.machine and p.machine != new:
                    self._mark_gone(p, f"{host} is another machine now (accepted by the user); "
                                       "what ran on the old one can't be reached through it")
                    p.remote_note = (f"{host} is another machine now; this "
                                     f"{'job' if p.kind == 'job' else 'terminal'} was on the old one")
            self._changed()

    def _poll_host(self, host: str) -> tuple[bool, float]:
        """Ask the host's runtime tmux about its live panes (one ssh round
        trip per runtime folder): states, exits, password prompts. A host
        that can't be asked leaves its panes disconnected (or waiting_auth for
        a refused key), never ended."""
        from .remote import parse_stty
        with self.lock:
            live = [p for p in self.panes.values() if p.live and p.remote and p.host == host]
        if not live:
            return False, 0.0
        rh = self.d.remote.get(host)
        sess = self.owner_session_for_host(host)
        groups: dict[str, list[Pane]] = {}
        for p in live:
            groups.setdefault(p.rt, []).append(p)
        for rt, ps in groups.items():
            if not rt:
                for p in ps:
                    with self.lock:
                        self._mark_gone(p, "no runtime folder recorded")
                continue
            fetched = time.time()
            try:
                infos, ttys = rh.tmux(rt).poll(session=sess)
            except TermError as e:
                if e.code == "remote_noanswer":
                    self._remote_blip(ps, e)        # the host answered; its tmux didn't, this once
                else:
                    self._remote_down(rh, ps, e, sess)
                continue
            claims = self._remote_seen(rh, ps, infos, fetched)
            for p in claims:
                self._settle_start(rh, p)
            self._drop_pending_buffers(rh, ps)
            for p in ps:
                if not p.alive or p.id not in ttys or p.dispatching:
                    continue
                tp, g, comm = ttys[p.id]
                mode = parse_stty(g, rh.platform)
                echo_off = mode is not None and not mode[0] and mode[1]
                self._prompt_step(p, echo_off, tp=tp, comm=comm)
        return True, rh.backoff()

    def _drop_pending_buffers(self, rh: Any, ps: list[Pane]) -> None:
        """Input whose paste's answer was lost and couldn't be checked then:
        its buffer is removed at the host's next answer, so a paste still on
        its way can't type it late (gone already: it went in then)."""
        for p in ps:
            with self.lock:
                bufs, p.pending_bufs = p.pending_bufs, []
            for i, buf in enumerate(bufs):
                try:
                    rh.tmux(p.rt).run("delete-buffer", "-b", buf, check=False)
                except TermError:
                    with self.lock:
                        p.pending_bufs.extend(bufs[i:])
                    break

    def _settle_start(self, rh: Any, p: Pane) -> None:
        """An unconfirmed start (its answer was lost, or gated stopped while it
        went out) that the host's tmux doesn't list: the start file's claim
        tells "never started" (then the command can't run any more: the job
        is `failed` with the note and its idempotency key is free again) from
        "started" (then the next look's list decides: listed, adopted; not
        listed, lost and `unknown`)."""
        ext = "rc" if p.kind == "terminal" else "sh"
        try:
            how = rh.tmux(p.rt).claim_start(f"terms/{p.id}.{p.nonce}.{ext}", p.id)
        except TermError as e:
            with self.lock:
                if p.live and p.unconfirmed and not p.remote_note:
                    p.remote_note = (f"{e.message} (whether this {p.kind} started isn't known yet; "
                                     "the gateway keeps asking)")
                    self._changed()
            return
        with self.lock:
            if not p.live or not p.unconfirmed:
                return
            p.unconfirmed = False
            if how == "started":
                # its shell took the start file: the command started; the next look
                # decides (listed: running; not listed: lost, unknown)
                p.dispatched_at = time.time()
                self._changed()
                return
            p.alive, p.ended, p.gone = False, time.time(), False
            p.remote_note = (f"never started on {p.host}: the connection dropped before it began, and "
                             "the gateway made sure it can't start late; nothing of it ran")
            if p.kind == "job":
                p.state = "failed"
                # a start that provably never ran frees its key: a retry starts it
                for k, (jid, _t) in list(self.idem.items()):
                    if jid == p.id:
                        self.idem.pop(k, None)
                self._emit("job.state", job=p.id, state="failed")
            else:
                p.state = "closed"
                self._emit("terminal.closed", terminal=p.id, reason="never_started")
            self._changed()
        self.d.log(f"terminals: {p.id}: never started on {p.host} (settled by its start file's claim)")

    def _remote_blip(self, ps: list[Pane], e: TermError) -> None:
        """The host answered but its runtime tmux didn't, while the server
        process lives (RemoteTmux.poll): nothing about the panes changes (the
        local _blip's rule); they say why they weren't refreshed."""
        with self.lock:
            for p in ps:
                if p.live and not p.dispatching and not p.unconfirmed and p.remote_note != e.message:
                    p.remote_note = e.message
                    self._dirty = True
            if self._dirty:
                self._changed()

    def _remote_down(self, rh: Any, ps: list[Pane], e: TermError, sess: Any) -> None:
        code = e.code.removeprefix("remote_")
        state = "waiting_auth" if code == "auth" else "disconnected"
        with self.lock:
            for p in ps:
                if not p.live or p.dispatching:
                    continue
                if p.unconfirmed:
                    # still unknown (whether it started is the open question): its
                    # start's note stays; one recorded before a gated restart gets one
                    if not p.remote_note:
                        p.remote_note = (f"{e.message} (whether this {p.kind} started there isn't "
                                         "known yet; the gateway asks when it can)")
                        self._dirty = True
                    continue
                p.remote_note = e.message
                if p.state != state:
                    p.state = state
                    if p.kind == "job":
                        self._emit("job.state", job=p.id, state=state)
                    self._dirty = True
            if self._dirty:
                self._changed()
        if code == "auth":
            rh.auth_notice(sess)

    def _remote_seen(self, rh: Any, ps: list[Pane], infos: dict[str, dict[str, str]] | None,
                     fetched: float) -> list[Pane]:
        """The host's answer applied to its panes. Returns the unconfirmed
        starts it doesn't list (settled by `_settle_start`, outside the lock)."""
        claims: list[Pane] = []
        with self.lock:
            for p in ps:
                if not p.live or p.dispatching:
                    continue            # a start on its way: its own answer decides first
                if p.machine and rh.machine and p.machine != rh.machine:
                    why = f"{p.host} is another machine than the one it started on"
                    self._mark_gone(p, why)
                    p.remote_note = why
                    continue
                info = (infos or {}).get(p.id)
                lost = self._lost(p, info)
                if lost and fetched <= p.dispatched_at:
                    continue            # asked before the start's answer came: this look can't tell
                if lost and p.unconfirmed and not p.closing:
                    claims.append(p)    # did it ever start? its start file's claim says
                    continue
                back = p.state in ("disconnected", "waiting_auth") and p.auth is None
                if back or not p.seen:
                    # first answer since a disconnect or a gated restart: the
                    # screen may have moved meanwhile, so a seq read before is stale
                    p.seq += 1
                    p.seen = True
                    self._dirty = True
                if p.remote_note:
                    p.remote_note = ""
                    self._dirty = True
                if p.unconfirmed and not lost:
                    # the host lists it by its id and nonce: the start did happen
                    p.unconfirmed = False
                    self._dirty = True
                if lost:
                    if p.closing or (p.stop_req == "unsure" and infos is not None):
                        # (a close whose answer was lost, then the session gone from
                        # a server that still runs: that close is what removed it)
                        self._closed(p)
                        p.stop_req = ""
                    elif p.created < fetched:
                        why = (f"{p.host}'s runtime tmux no longer has it" if infos is not None else
                               f"{p.host}'s runtime tmux server isn't running any more (the host "
                               "restarted, or it was stopped)")
                        self._mark_gone(p, why)
                        p.remote_note = why
                    continue
                before = (p.state, p.alive)
                self._update(p, info)
                if (p.state, p.alive) != before or back:
                    self._dirty = True
            if self._dirty:
                self._changed()
        return claims

    # -- pause and resume (CONTRACT-v1) ----------------------------------------------------
    def session_processes(self, session_key_: str) -> list[tuple[int, Any]]:
        """The Claude Code processes (pid, start time) the panes recorded under
        a session key belong to (PLAN-v4 phase 7: /v1/pause binds a session to
        its caller by them)."""
        with self.lock:
            return list(dict.fromkeys((p.session_pid, p.session_start) for p in self.panes.values()
                                      if p.session_key() == session_key_ and p.session_pid))

    def pause(self, session_id: str, task_ref: Any = None) -> list[dict[str, Any]]:
        outcomes = []
        with self.lock:
            jobs = [p for p in self.panes.values() if p.kind == "job" and
                    (p.alive or (p.remote and p.live)) and
                    p.session_key() == session_id and not p.detached and
                    (not task_ref or p.task_ref == task_ref)]
        for p in jobs:
            outcomes.append(self._pause_one(p))
        return outcomes

    @staticmethod
    def _not_applied(e: TermError) -> str:
        """A pause step the host couldn't take: said as it is, never "ended"."""
        if e.extra.get("ambiguous"):
            return f"outcome unknown: the signal went out but its answer was lost ({e.message})"
        return f"not applied: {e.message}"

    def _pause_one(self, p: Pane) -> dict[str, Any]:
        pol = p.on_pause
        base = {"job": p.id, "policy": pol}
        if p.remote and (p.unconfirmed or p.dispatching):
            return {**base, "outcome": f"not applied: its start on {p.host} isn't confirmed yet (the "
                                       "answer was lost); nothing was sent, the host is asked"}
        if pol == "continue":
            return {**base, "outcome": "still running (on_pause continue)"}
        if pol == "detach":
            with self.lock:
                p.detached = True
                p.task_ref = ""
                self._changed()
            return {**base, "outcome": "detached from the task; still running"}
        # a pause repeated (a consumer's retry, a second pause before any
        # resume) never signals a job the first one already handled
        # (PLAN-v4 phase 7): its SIGINT or SIGSTOP isn't sent again
        if p.paused_as == "interrupted":
            return {**base, "outcome": "already interrupted by an earlier pause (SIGINT not sent "
                                       "again); still running"}
        if p.paused_as == "suspended":
            return {**base, "outcome": "already suspended by an earlier pause"}
        try:
            pg = self._pgrp(p, foreground=False)
        except TermError as e:
            if e.code.startswith("remote_"):
                return {**base, "outcome": self._not_applied(e)}
            return {**base, "outcome": "already ended"}
        if pol == "suspend":
            try:
                stopped = self._stop_group(p, pg)
            except TermError as e:
                return {**base, "outcome": self._not_applied(e)}
            if stopped:
                with self.lock:
                    p.paused_as = "suspended"
                    self._changed()
                self._look(p)
                return {**base, "outcome": "suspended (SIGSTOP)"}
            with contextlib.suppress(OSError, TermError):
                self._killpg(p, pg, "CONT")
            return {**base, "outcome": "SIGSTOP sent but the job doesn't show as stopped; still running"}
        # interrupt: INT now, TERM after the grace if it still runs
        try:
            self._killpg(p, pg, "INT")
        except TermError as e:
            if e.code.startswith("remote_"):
                return {**base, "outcome": self._not_applied(e)}
            return {**base, "outcome": "already ended"}
        except OSError:
            return {**base, "outcome": "already ended"}
        end = time.monotonic() + (1.0 if not p.remote else 2.0)
        while time.monotonic() < end:
            self._look(p)
            if not p.alive:
                return {**base, "outcome": f"interrupted: exited ({self._exit_words(p)})"}
            time.sleep(0.1)
        with self.lock:
            p.paused_as = "interrupted"
            self._changed()             # persisted, so a gated restart re-arms the escalation
        self._arm_term_escalation(p)
        return {**base, "outcome": f"SIGINT sent; still running, SIGTERM follows in "
                                   f"{int(INTERRUPT_GRACE)} s if it doesn't exit"}

    def _arm_term_escalation(self, p: Pane, delay: float = INTERRUPT_GRACE) -> None:
        """An on_pause=interrupt job promised SIGTERM after the grace if it
        didn't exit; the timer is in-process, so a gated restart would silently
        drop that promise (the job stays interrupted forever). adopt re-arms it
        for a re-adopted interrupted job, so the escalation still happens."""
        def escalate() -> None:
            if not p.alive:
                return
            try:
                pg = self._pgrp(p, foreground=False)
            except TermError:
                return
            with contextlib.suppress(OSError, TermError):
                self._killpg(p, pg, "TERM")
            self.d.log(f"terminals: {p.id}: TERM after the interrupt grace")
        t = threading.Timer(delay, escalate)
        t.daemon = True
        with self.lock:
            p.timers.append(t)
        t.start()

    @staticmethod
    def _exit_words(p: Pane) -> str:
        if p.signal:
            return f"signal {p.signal}"
        return f"exit {p.exit}" if p.exit is not None else "exit unknown"

    def resume(self, session_id: str, task_ref: Any = None) -> list[dict[str, Any]]:
        outcomes = []
        with self.lock:
            jobs = [p for p in self.panes.values() if p.kind == "job" and p.session_key() == session_id
                    and (not task_ref or p.task_ref == task_ref or p.detached)]
        for p in jobs:
            base = {"job": p.id, "policy": p.on_pause}
            if not p.alive:
                outcomes.append({**base, "outcome": f"ended ({self._exit_words(p)})"})
                continue
            if p.paused_as == "suspended":
                try:
                    self._killpg(p, self._pgrp(p, foreground=False), "CONT")
                    with self.lock:
                        p.paused_as = ""
                        self._changed()
                    outcomes.append({**base, "outcome": "resumed (SIGCONT)"})
                except (OSError, TermError):
                    outcomes.append({**base, "outcome": "resume failed"})
                continue
            if p.paused_as == "interrupted":
                for t in p.timers:
                    t.cancel()
                with self.lock:
                    p.paused_as = ""
                outcomes.append({**base, "outcome": "still running (it ignored the interrupt)"})
                continue
            outcomes.append({**base, "outcome": "running" + (" (detached)" if p.detached else "")})
        self.tick()
        return outcomes

    def resume_stopped(self) -> list[str]:
        """The plugin was uninstalled (lifecycle.Daemon.drain): contract.json
        is gone, so no consumer can send /v1/resume any more, and a draining
        gated leaves only once no local job runs. A job left suspended (a
        pause's suspend, or job_signal STOP) would stay stopped, and gated, its
        tmux server and the job with it, forever: each is resumed (SIGCONT to
        its process group, as /v1/resume does), the session's pause record
        kept (its consumer still holds the task paused; only the stop is
        lifted). A local pane's process is signalled only while it is still the
        process tmux named (pid and start time: the env's tmux may be deleted
        by now). A pending interrupt escalation is left to happen (it ends the
        job, as the pause asked). The ids resumed."""
        with self.lock:
            jobs = [p for p in self.panes.values() if p.kind == "job" and p.paused_as == "suspended"
                    and (p.alive or (p.remote and p.live))]
        done: list[str] = []
        for p in jobs:
            if not p.remote and p.pane_pid > 0 and p.pane_start is not None and \
                    not peers.alive(p.pane_pid, p.pane_start):
                continue                          # ended meanwhile: nothing to resume
            try:
                was_stopped = self._cont_group(p, self._pgrp(p, foreground=False))
            except ProcessLookupError:
                continue
            except (OSError, TermError) as e:
                self.d.log(f"terminals: {p.id}: resuming it failed "
                           f"({e.code if isinstance(e, TermError) else type(e).__name__})")
                continue
            with self.lock:
                p.paused_as = ""
                # its state too: only _update (list-panes) maps paused_as to the
                # state, and with the env's tmux gone (a plain uninstall deletes
                # it with the data folder) no tick calls _update again, so the
                # job would say suspended while it runs
                if p.state == "suspended":
                    p.state = self._live_job_state(p)
                    self._emit("job.state", job=p.id, state=p.state)
                self._changed()
            # counted (and logged) only when ps showed a member stopped before the
            # SIGCONT: a record that says suspended for a job that runs (continued
            # behind gated's back) is corrected, never reported as resumed
            if was_stopped:
                done.append(p.id)
            else:
                self.d.log(f"terminals: {p.id} was recorded suspended but nothing of it showed "
                           "stopped; the record was corrected")
        if done:
            self.d.log(f"terminals: resumed {', '.join(done)} (SIGCONT): suspended, and nothing "
                       "could resume them any more")
            with contextlib.suppress(Exception):
                self.tick()
        return done

    # -- the contract's views --------------------------------------------------------------
    def contract_job(self, p: Pane) -> dict[str, Any]:
        # an "unknown" job (tmux lost it) has no proven end time: report ended
        # null so checkpoint doesn't read a concrete end for an uncertain outcome
        ended = None if p.state == "unknown" else (round(p.ended, 3) if p.ended else None)
        return {"job": p.id, "state": p.state, "exit": p.exit, "signal": p.signal,
                "started": round(p.created, 3), "ended": ended,
                "host": p.host_id, "host_name": p.host, "cwd": p.cwd, "command": p.command,
                "owner": p.owner, "on_pause": p.on_pause, "session": p.session_id,
                "task_ref": p.task_ref, "workspace": p.workspace or None,
                **({"gone": True} if p.gone else {}), **({"detached": True} if p.detached else {}),
                **({"remote": True} if p.remote else {}),
                **({"note": p.remote_note} if p.remote and p.remote_note else {}),
                **({"start_confirmed": False} if p.remote and p.unconfirmed and p.live else {}),
                **({"stop_requested": STOP_REQ_WORDS.get(p.stop_req, p.stop_req)}
                   if p.stop_req else {})}

    def snapshot(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        with self.lock:
            ps = sorted(self.panes.values(), key=lambda x: x.created)
        terms = [{"terminal": p.id, "host": p.host_id, "host_name": p.host, "state": p.state,
                  "owner": p.owner, "session": p.session_id, "cwd": p.cwd,
                  "created": round(p.created, 3), "task_ref": p.task_ref}
                 for p in ps if p.kind == "terminal"]
        jobs = [self.contract_job(p) for p in ps if p.kind == "job"]
        return terms, jobs
