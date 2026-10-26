"""Registered Claude Code sessions and the plane checks.

A session is a live Claude Code process (by executable path: peers.is_claude)
that registered:

- the mod, from inside that process (`POST /ui/register`: the peer pid must
  be the claimed claude_pid and its executable Claude Code's): a UI session;
- a gateway hook (`POST /agent/register` from a hook-* or gated entry point):
  the claimed claude_pid must be an ancestor of the peer and a Claude Code
  process. This covers sessions without mods (switched off, older Claude
  Code) and `claude -p`.

Sessions are kept in <run>/gated-sessions.json (0600, written whole), so a
restarted daemon still knows them; each is re-checked (alive, with the start
time it registered with: a reused pid has another) when loaded and on every
tick, and a dead one is dropped. The executable is checked when a session
registers, not afterwards: an upgrade deletes or replaces the binary of a
Claude Code that keeps running (macOS then reports no path for it, Linux
"<path> (deleted)"), and it is still the process that registered. Such a
session may register again (the mod at /clear or resume, a hook): a live
registered process counts as Claude Code (Registry.claude_ok).

Plane rules (every connection first: the peer's uid is the daemon's):

    ui        the peer pid is a registered UI session
    agent     a registered session is a strict ancestor of the peer, and the
              peer is a gateway entry point whose mode the route allows
    contract  a registered session is a strict ancestor of the peer
    local     the peer is a gateway entry point (any session or none)
    mode      /agent/session/mode (PLAN-0.11 §2.4): a gateway hook records its
              session's permission mode, a stand-in or the gw MCP server reads
              it; the session is the nearest Claude Code on the peer's real
              process chain, registered (never through a gateway terminal's
              pane, never an outer session past an unregistered inner one)
    signin    /agent/signin/* (PLAN-0.11 §7.1): the gate command below a
              registered session, as for the dialog lease

The UI process itself is never on the agent or contract plane (strict
ancestor), and an agent or contract peer is never on the UI plane: "the
contract plane refuses UI-plane routes and vice versa".
"""
from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .. import paths
from . import peers


@dataclass
class Session:
    pid: int
    start: float | None
    exe: str
    session_id: str = ""
    ui: bool = False
    surface: str = ""
    version: str = ""
    via: str = ""               # "ui" (the mod) or "hook" (a gateway hook)
    registered: float = field(default_factory=time.time)
    # every surface the session draws on ($.session.surfaces(): terminal,
    # desktop, mobile, vscode); empty for claude -p. The native dialogs need
    # terminal or desktop (daemon/dialogs.py).
    surfaces: list = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        return {"pid": self.pid, "session": self.session_id, "ui": self.ui,
                "surface": self.surface, "surfaces": list(self.surfaces), "via": self.via}


class Denied(Exception):
    """A plane check failed: (http status, error code, message)."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def _clean_id(s: Any, limit: int = 120) -> str:
    """A session id or surface name as metadata: printable, bounded."""
    if not isinstance(s, str):
        return ""
    s = "".join(c for c in s if c.isprintable() and c not in "\\\"")
    return s[:limit]


SURFACES = ("terminal", "desktop", "mobile", "vscode")


def _surfaces(given: Any) -> list[str]:
    """The surfaces a registration names (known names only, each once)."""
    out: list[str] = []
    for s in given if isinstance(given, list) else []:
        if isinstance(s, str) and s in SURFACES and s not in out:
            out.append(s)
    return out


class Registry:
    def __init__(self, path: Path, on_drop: Any = None):
        self.path = path
        self.lock = threading.RLock()
        self.sessions: dict[int, Session] = {}
        self.on_drop = on_drop            # called with each session prune() drops
        # the supervisor's mapping (daemon/terminals.py): a process inside a
        # gateway terminal or job belongs to that pane's owner session
        self.pane_session: Any = None
        # each session's recorded permission mode (PLAN-0.11 §2.4): pid ->
        # (the session's start time, mode key, the epoch marker's epoch it was
        # posted under); memory only, so a restarted daemon has none until a
        # hook posts one (the modeless rule meanwhile)
        self.modes: dict[int, tuple[float | None, str, str | None]] = {}
        self._load()

    # -- persistence ---------------------------------------------------------
    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for rec in raw.get("sessions", []) if isinstance(raw, dict) else []:
            try:
                s = Session(**{k: rec[k] for k in Session.__dataclass_fields__ if k in rec})
            except (TypeError, KeyError):
                continue
            if self._valid(s):
                self.sessions[s.pid] = s
        self._save()

    def _save(self) -> None:
        data = {"sessions": [asdict(s) for s in self.sessions.values()]}
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

    @staticmethod
    def _valid(s: Session) -> bool:
        """Still the process that registered: its pid alive with the same
        start time (the executable was checked at registration; see the
        module docstring)."""
        return s.start is not None and peers.alive(s.pid, s.start)

    # -- registration --------------------------------------------------------
    def register(self, pid: int, *, ui: bool, via: str, session_id: Any = "", surface: Any = "",
                 version: Any = "", surfaces: Any = None) -> Session:
        with self.lock:
            start = peers.started(pid)
            if start is None:
                raise Denied(403, "pid", "gateway: registration refused: the gateway daemon can't "
                             "tell when that Claude Code process started")
            old = self.sessions.get(pid)
            if old is not None and old.start != start:
                old = None                    # a reused pid: a new process
                self.modes.pop(pid, None)     # (and the old one's mode with it)
            # the executable checked when this process first registered (later
            # its path may be gone, or read "<path> (deleted)" on Linux)
            exe = (old.exe if old is not None and old.exe else "") or peers.exe(pid) or ""
            keep_ui = bool(old and old.ui)    # a hook re-registering keeps the mod's UI session
            s = Session(pid=pid, start=start, exe=exe,
                        session_id=_clean_id(session_id) or (old.session_id if old else ""),
                        ui=ui or keep_ui,
                        surface=_clean_id(surface, 32) or (old.surface if old else ""),
                        version=_clean_id(version, 32) or (old.version if old else ""),
                        via="ui" if (ui or keep_ui) else via,
                        surfaces=_surfaces(surfaces) if surfaces is not None
                        else (list(old.surfaces) if old else []))
            self.sessions[pid] = s
            self._save()
            return s

    def unregister(self, pid: int) -> bool:
        with self.lock:
            self.modes.pop(pid, None)
            if self.sessions.pop(pid, None) is None:
                return False
            self._save()
            return True

    def prune(self) -> int:
        """Drop dead sessions; the number still alive."""
        with self.lock:
            dead = [p for p, s in self.sessions.items() if not self._valid(s)]
            gone = [self.sessions.pop(p) for p in dead]
            for p in dead:
                self.modes.pop(p, None)
            if dead:
                self._save()
            live = len(self.sessions)
        for s in gone:
            if self.on_drop is not None:
                try:
                    self.on_drop(s)
                except Exception:  # noqa: BLE001 - an event is never worth a crash
                    pass
        return live

    # -- lookups -------------------------------------------------------------
    def live(self, pid: int) -> Session | None:
        with self.lock:
            s = self.sessions.get(pid)
        if s is None:
            return None
        if not peers.alive(s.pid, s.start):
            return None
        return s

    def claude_ok(self, pid: int) -> bool:
        """Is `pid` Claude Code: by its executable, or as the same live process
        (pid and start time) that registered as Claude Code before (its binary
        since deleted or replaced by an upgrade)?"""
        return peers.is_claude(pid) or self.live(pid) is not None

    def ui_session(self, pid: int) -> Session | None:
        s = self.live(pid)
        return s if s is not None and s.ui else None

    def ancestor_session(self, pid: int) -> Session | None:
        """The registered session nearest above `pid` (never `pid` itself);
        for a process inside a gateway terminal or job (below gated's tmux
        server, not below Claude Code) the pane's owner session while it
        lives (PLAN-v4 phase 5)."""
        up = peers.chain(pid)[1:]
        for p in up:
            s = self.live(p)
            if s is not None:
                return s
        if self.pane_session is not None and up:
            try:
                s = self.pane_session(up)
            except Exception:  # noqa: BLE001 - no mapping: no session
                s = None
            if s is not None and self.live(s.pid) is not None:
                return s
        return None

    def chain_session(self, pid: int) -> Session | None:
        """The session of the Claude Code process nearest above `pid` on its
        real process chain (never `pid` itself), or None when that process
        isn't registered: a Claude Code started inside another one's session
        is a session of its own, never the outer one's, until it registers
        (a hook's record registers it). Unlike ancestor_session, never
        through a gateway terminal's or job's pane: nothing started there is
        a command Claude typed or a hook Claude Code ran."""
        for p in peers.chain(pid)[1:]:
            s = self.live(p)
            if s is not None:
                return s
            if self.claude_ok(p):
                return None               # a Claude Code that isn't registered (yet)
        return None

    # -- the recorded permission mode (PLAN-0.11 §2.4) -------------------------
    def set_mode(self, s: Session, mode: str, epoch: str | None = None) -> None:
        """Record `mode` (a key, modes.normalize) for session `s`, under the
        epoch marker's `epoch` (modes.set_marker; None: posted without one)."""
        with self.lock:
            self.modes[s.pid] = (s.start, mode, epoch)

    def mode_of(self, s: Session) -> str | None:
        """The mode recorded for session `s`: only for the same process (pid
        and start time) the record was made for."""
        with self.lock:
            rec = self.modes.get(s.pid)
        if rec is None or rec[0] != s.start:
            return None
        return rec[1]

    def mode_under(self, s: Session, epoch: str | None) -> str | None:
        """mode_of, only when the record was posted under `epoch` (a record
        from before the marker was made again may be stale: modes.py)."""
        with self.lock:
            rec = self.modes.get(s.pid)
        if rec is None or rec[0] != s.start or rec[2] != epoch:
            return None
        return rec[1]

    def count(self) -> int:
        with self.lock:
            return len(self.sessions)

    def public(self) -> list[dict[str, Any]]:
        with self.lock:
            return [s.public() for s in self.sessions.values()]


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------

# Which entry point modes may use which agent routes (the vault plane).
VAULT_MODES = ("shim ", "git-credential", "gate", "mcp", "hook-")
REGISTER_MODES = tuple(m for m in peers.HOOK_MODES) + ("gated",)


def mode_allowed(mode: str, allowed: tuple[str, ...]) -> bool:
    return any(mode == a or (a.endswith((" ", "-")) and mode.startswith(a)) for a in allowed)


def check_uid(peer: peers.Peer) -> None:
    if peer.uid != os.getuid():
        raise Denied(403, "uid", "gateway: the gateway daemon answers only its own user's "
                     "processes")


def check_ui(reg: Registry, peer: peers.Peer) -> Session:
    s = reg.ui_session(peer.pid)
    if s is None:
        raise Denied(403, "plane", "gateway: this is the gateway's UI plane; only the Claude Code "
                     "process itself (its gateway mod) may use it")
    return s


def check_contract(reg: Registry, peer: peers.Peer) -> Session:
    s = reg.ancestor_session(peer.pid)
    if s is None:
        raise Denied(403, "plane", "gateway: this route is for processes started inside a "
                     "Claude Code session the gateway knows (CONTRACT-v1)")
    return s


OTHER_CONFIG = ("the gateway daemon running now serves another Claude Code configuration (its "
                "data folder is {theirs}; this one's is {mine}): one gateway daemon per user "
                "serves one Claude Code configuration (CLAUDE_CONFIG_DIR) at a time, so this "
                "session gets no dialogs (credentials, consent, sudo), terminals or jobs from it, "
                "and no secrets while the vault has a passphrase (without one the stand-ins "
                "still read the vault themselves). Tell the user: quit the other "
                "configuration's Claude Code sessions and let its gateway terminals and jobs "
                "end (the daemon stays while any of them runs and leaves 30 minutes after the "
                "last one; once nothing runs, pkill -f \"run.py gated serve\" stops it at "
                "once), then start a new session here; or do gateway work in one configuration")


def other_config_message(other: Path) -> str:
    """The refusal for a gateway program of another plugin data folder (a
    second Claude Code configuration, CLAUDE_CONFIG_DIR; GW-ROB-2). An
    unwrapped vault is still read locally by the stand-ins; only a wrapped
    key's reads, dialogs, terminals and jobs need this daemon (review round
    2). `gated status` in that configuration says the same (lifecycle)."""
    return "gateway: " + OTHER_CONFIG.format(theirs=paths.describe(paths.data_dir()),
                                             mine=paths.describe(other))


def other_config_note(h: dict[str, Any]) -> str:
    """For `gated status|start` and `gate status` in another configuration:
    OTHER_CONFIG when the daemon's /health names a data folder (`data`)
    that isn't this process's, else "" (also for an older daemon without
    it). The daemon itself never refuses /health, so without this the
    doctor showed it running with no hint (review round 2)."""
    theirs = h.get("data") if isinstance(h, dict) else None
    if not isinstance(theirs, str) or not os.path.isabs(theirs):
        return ""
    try:
        mine = paths.data_dir()
        if os.path.realpath(theirs) == os.path.realpath(mine):
            return ""
        return OTHER_CONFIG.format(theirs=paths.describe(Path(theirs)), mine=paths.describe(mine))
    except Exception:  # noqa: BLE001 - a status line, never a failure
        return ""


def _refused(peer: peers.Peer, entry: peers.Entry | None, code: str, message: str) -> Denied:
    """The refusal for a peer that isn't one of this daemon's entry points
    (or not in a mode the route takes): its own words when it is the gateway
    of another data folder (peers.foreign_data)."""
    other = peers.foreign_data(peer.pid) if entry is None else None
    if other is not None:
        return Denied(403, "other_config", other_config_message(other))
    return Denied(403, code, message)


def check_agent(reg: Registry, peer: peers.Peer,
                allowed: tuple[str, ...] = VAULT_MODES) -> tuple[Session, peers.Entry]:
    entry = peers.entry_of(peer.pid)
    if entry is None or not mode_allowed(entry.mode, allowed):
        raise _refused(peer, entry, "peer", "gateway: the gateway daemon gives vault data only to "
                       "the gateway's own programs (its stand-ins, git helper, gate, MCP server "
                       "and hooks)")
    s = reg.ancestor_session(peer.pid)
    if s is None:
        raise Denied(403, "not_registered", "gateway: this program isn't running inside a Claude "
                     "Code session the gateway knows, so the gateway daemon won't give it vault "
                     "data (start a new Claude Code session; a program left running after its "
                     "session ended gets nothing)")
    return s, entry


# The agent tools for terminals and jobs (the gw MCP server only).
TERM_MODES = ("mcp",)


def check_term(reg: Registry, peer: peers.Peer) -> tuple[Session, peers.Entry]:
    entry = peers.entry_of(peer.pid)
    if entry is None or not mode_allowed(entry.mode, TERM_MODES):
        raise _refused(peer, entry, "peer", "gateway: terminals and jobs are reached through the "
                       "gateway's own tools (the gw MCP server's terminal_* and job_* tools)")
    s = reg.ancestor_session(peer.pid)
    if s is None:
        raise Denied(403, "not_registered", "gateway: this program isn't running inside a Claude "
                     "Code session the gateway knows (start a new Claude Code session)")
    return s, entry


# The session's permission mode (PLAN-0.11 §2.4, /agent/session/mode): the
# Python hooks record it (they read permission_mode from the hook payload);
# the stand-ins and the gw MCP server read it. Both only from their real
# process chain below a registered session (Registry.chain_session).
MODE_RECORD_MODES = ("hook-",)
MODE_READ_MODES = ("shim ", "mcp")


def check_mode(reg: Registry, peer: peers.Peer, record: bool) -> tuple[Session, peers.Entry]:
    entry = peers.entry_of(peer.pid)
    want = MODE_RECORD_MODES if record else MODE_READ_MODES
    if entry is None or not mode_allowed(entry.mode, want):
        raise _refused(peer, entry, "peer", "gateway: only the gateway's hooks record the session's "
                       "permission mode" if record else "gateway: only the gateway's stand-ins "
                       "and MCP server read the session's permission mode")
    s = reg.chain_session(peer.pid)
    if s is None:
        raise Denied(403, "not_registered", "gateway: this program isn't running inside a Claude "
                     "Code session the gateway knows (start a new Claude Code session)")
    return s, entry


# The browser sign-in's lease (PLAN-0.11 §7.1, /agent/signin/*): `gate check`
# or account setup, below a registered session, as for the dialog lease.
SIGNIN_MODES = ("gate", "shim gate")


def check_signin(reg: Registry, peer: peers.Peer) -> tuple[Session, peers.Entry]:
    entry = peers.entry_of(peer.pid)
    if entry is None or not mode_allowed(entry.mode, SIGNIN_MODES):
        raise _refused(peer, entry, "peer", "gateway: a browser sign-in is started only by the "
                       "gateway's own gate command (gate check NAME)")
    s = reg.ancestor_session(peer.pid)
    if s is None:
        raise Denied(403, "not_registered", "gateway: no sign-in can start: this program isn't "
                     "running inside a Claude Code session the gateway knows (start a new Claude "
                     "Code session)")
    return s, entry


def check_local(peer: peers.Peer) -> peers.Entry:
    entry = peers.entry_of(peer.pid)
    if entry is None:
        raise _refused(peer, entry, "peer", "gateway: only the gateway's own programs may stop or "
                       "restart the gateway daemon")
    return entry


def register_ui(reg: Registry, peer: peers.Peer, body: dict[str, Any]) -> Session:
    """The mod's registration: the peer is the Claude Code process it claims
    to be (claude_pid, when given, must be the peer's pid from the kernel)."""
    claimed = body.get("claude_pid", peer.pid)
    if not isinstance(claimed, int) or isinstance(claimed, bool) or claimed != peer.pid:
        raise Denied(403, "pid", "gateway: registration refused: the caller isn't the Claude Code "
                     "process it names")
    if not reg.claude_ok(peer.pid):
        raise Denied(403, "exe", "gateway: registration refused: the caller isn't a Claude Code "
                     "executable")
    surfaces = body.get("surfaces")
    if surfaces is None:
        surfaces = [body.get("surface")] if body.get("surface") else []
    return reg.register(peer.pid, ui=True, via="ui", session_id=body.get("session_id"),
                        surface=body.get("surface"), version=body.get("version"),
                        surfaces=surfaces)


def register_agent(reg: Registry, peer: peers.Peer, body: dict[str, Any]) -> Session:
    """A gateway hook's registration of the Claude Code process above it."""
    entry = peers.entry_of(peer.pid)
    if entry is None or not mode_allowed(entry.mode, REGISTER_MODES):
        raise _refused(peer, entry, "peer", "gateway: only the gateway's hooks register a session")
    claimed = body.get("claude_pid")
    up = peers.chain(peer.pid)[1:]
    if claimed is None:
        claimed = next((p for p in up if reg.claude_ok(p)), None)
    if not isinstance(claimed, int) or isinstance(claimed, bool) or claimed not in up:
        raise Denied(403, "pid", "gateway: registration refused: the Claude Code process named "
                     "isn't above the caller")
    if not reg.claude_ok(claimed):
        raise Denied(403, "exe", "gateway: registration refused: that process isn't a Claude Code "
                     "executable")
    return reg.register(claimed, ui=False, via="hook", session_id=body.get("session_id"),
                        version=body.get("version"))
