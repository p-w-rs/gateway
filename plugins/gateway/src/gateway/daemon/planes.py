"""Registered Claude Code sessions and the plane checks.

A session is a live Claude Code process (by executable path) that registered:

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
            if self.sessions.pop(pid, None) is None:
                return False
            self._save()
            return True

    def prune(self) -> int:
        """Drop dead sessions; the number still alive."""
        with self.lock:
            dead = [p for p, s in self.sessions.items() if not self._valid(s)]
            gone = [self.sessions.pop(p) for p in dead]
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


def check_agent(reg: Registry, peer: peers.Peer,
                allowed: tuple[str, ...] = VAULT_MODES) -> tuple[Session, peers.Entry]:
    entry = peers.entry_of(peer.pid)
    if entry is None or not mode_allowed(entry.mode, allowed):
        raise Denied(403, "peer", "gateway: the gateway daemon gives vault data only to the "
                     "gateway's own programs (its stand-ins, git helper, gate, MCP server and "
                     "hooks)")
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
        raise Denied(403, "peer", "gateway: terminals and jobs are reached through the gateway's "
                     "own tools (the gw MCP server's terminal_* and job_* tools)")
    s = reg.ancestor_session(peer.pid)
    if s is None:
        raise Denied(403, "not_registered", "gateway: this program isn't running inside a Claude "
                     "Code session the gateway knows (start a new Claude Code session)")
    return s, entry


def check_local(peer: peers.Peer) -> peers.Entry:
    entry = peers.entry_of(peer.pid)
    if entry is None:
        raise Denied(403, "peer", "gateway: only the gateway's own programs may stop or restart "
                     "the gateway daemon")
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
        raise Denied(403, "peer", "gateway: only the gateway's hooks register a session")
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
