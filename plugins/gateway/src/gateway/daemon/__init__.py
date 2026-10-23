"""gated: the gateway's per-user daemon (PLAN-v4 phase 2).

One process per user (and per test root), started on demand, detached from
every Claude Code session, reached over a Unix socket in the private run dir
with HTTP/1.1. It authenticates every connection by the kernel's peer
credentials (uid, pid) and sorts callers into planes:

    health    GET /health              any process of this user
    ui        /ui/*                    the Claude Code process itself (a registered pid)
    agent     /agent/*                 a gateway entry point (run.py stand-in, askpass,
                                       git helper, gate, MCP, hook) below a registered session
    lease     /lease/*                 a gateway entry point holding a dialog lease token
                                       (the detached pop-up helper; dialogs.py)
    contract  /v1/*                    any process below a registered session (CONTRACT-v1)
    local     /local/*                 a gateway entry point of this user (stop, restart)
    test      /test/*                  only under a test override that enables it

Modules: peers (who is connecting), planes (sessions and plane checks),
events (event log), broker (the vault key, scoped vault data), dialogs (the
native dialogs: requests, queue, sealed delivery), clipboard (the dialog's
paste), server (HTTP),
lifecycle (start, daemonize, single instance, contract.json, idle exit),
client (what the other gateway processes call). docs/dev/modules/daemon.md.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

PROTOCOL = 1
CONTRACT_ID = "gateway.v1"
CONTRACT_VERSIONS = [1]
# What CONTRACT-v1 features this build serves: hosts and events (phase 2),
# pause (phase 3: recorded per session, honoured by the native dialogs; phase
# 5: per-job on_pause policies), jobs and terminals (phase 5, localhost),
# remote (phase 6: terminals and jobs on remote hosts in the managed runtime).
FEATURES = ["hosts", "events", "pause", "jobs", "terminals", "remote", "workspaces", "accounts",
            "pause_id"]


def machine_token(raw: str) -> str:
    """m_<26 base32>: a stable, non-reversible id from a machine identity."""
    import base64
    import hashlib
    d = hashlib.sha256(("gateway-machine:" + raw).encode("utf-8")).digest()
    return "m_" + base64.b32encode(d).decode("ascii").lower()[:26]


def local_host_id() -> str:
    """This machine's host id on the contract (what gated's snapshot calls
    localhost): derived from the machine id (vault.machine_id), else the host
    name. Light: the MCP server and the approval hook use it to tell a host
    word that is this very machine from a remote one."""
    import socket
    from .. import vault
    return machine_token(vault.machine_id() or f"host:{socket.gethostname()}")


def is_local_host(host: Any) -> bool:
    """A terminal's or job's `host` word that means this machine: absent,
    "", "localhost", or this machine's own contract id (gated's `_host`
    reads them the same way)."""
    if host is None or host in ("", "localhost"):
        return True
    if isinstance(host, str) and re.fullmatch(r"m_[a-z2-7]{26}", host):
        try:
            return host == local_host_id()
        except Exception:  # noqa: BLE001 - no machine id: not this machine
            return False
    return False


def workspace_id(host_id: str, root: str) -> str:
    """w_<26 base32>: a workspace's stable id (PLAN-v4 phase 7), from its
    host's id and its root as written: the same root on another host is
    another workspace, and a renamed workspace keeps its id."""
    import base64
    import hashlib
    d = hashlib.sha256(f"gateway-workspace:{host_id}\x00{root}".encode("utf-8")).digest()
    return "w_" + base64.b32encode(d).decode("ascii").lower()[:26]


def plugin_version(root: Path | None = None) -> str:
    """The plugin's version (plugin.json), or "0" when it can't be read."""
    from .. import paths
    p = (root or paths.code_root()) / ".claude-plugin" / "plugin.json"
    try:
        v = json.loads(p.read_text(encoding="utf-8")).get("version")
    except (OSError, ValueError, AttributeError):
        return "0"
    return v if isinstance(v, str) and re.fullmatch(r"[0-9][0-9A-Za-z.+-]{0,31}", v) else "0"


def version_key(v: str) -> tuple[int, ...]:
    """Dotted numbers for comparing versions ("0.10.0" > "0.9.1")."""
    out = []
    for part in re.split(r"[.+-]", v or "0"):
        m = re.match(r"\d+", part)
        out.append(int(m.group(0)) if m else 0)
    return tuple(out)


def skew_text(theirs: str, mine: str) -> str:
    """What a version difference between the running daemon (`theirs`) and
    this plugin copy (`mine`) means for the user, or "" when they match.
    `gated start` (lifecycle.ensure_running), `gated status` (what
    /gate-doctor runs) and `gate status` report it."""
    t, m = version_key(theirs), version_key(mine)
    if t > m:
        return (f"a newer gateway daemon ({theirs}) answers this plugin ({mine}); start a new "
                "session to use the new plugin")
    if t < m:
        return (f"an older gateway daemon ({theirs}) answers this plugin ({mine}); it is "
                "replaced when a session of this plugin starts and it holds no terminals or jobs")
    return ""


def resolve_remote_host(host: Any, remote_names: list[str], ids: dict[str, str],
                        saved: dict[str, Any]) -> str | None:
    """The one resolver for a terminal's or job's `host` word (PLAN-v4 phase
    6): a form remote host's name from its name, its assigned contract id
    (`m_...`, <data>/gated/machine-ids.json) or its verified machine token
    (<data>/gated/remote.json, when exactly one host has it); None when the
    word names no remote host. gated (`remote.Remotes.resolve`) and the
    approval hook (`hooks_bash._remote_name`) both call it, so the hook judges
    a remote job on the very host gated runs it on."""
    if not isinstance(host, str) or not host:
        return None
    if host in remote_names:
        return host
    for n in remote_names:
        if ids.get(n) == host:
            return n
    matches = [n for n in remote_names
               if isinstance(saved.get(n), dict) and saved[n].get("machine") == host]
    return matches[0] if len(matches) == 1 else None


def read_host_maps(gated_dir: Path) -> tuple[dict[str, str], dict[str, Any]]:
    """(assigned ids by host name, remote.json's hosts) as gated last wrote
    them, for a process that isn't gated (the approval hook); empty when a
    file can't be read."""
    ids: dict[str, str] = {}
    saved: dict[str, Any] = {}
    try:
        raw = json.loads((gated_dir / "machine-ids.json").read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            ids = {str(k): str(v) for k, v in raw.items()}
    except (OSError, ValueError):
        pass
    try:
        raw = json.loads((gated_dir / "remote.json").read_text(encoding="utf-8"))
        if isinstance(raw, dict) and isinstance(raw.get("hosts"), dict):
            saved = {str(k): v for k, v in raw["hosts"].items() if isinstance(v, dict)}
    except (OSError, ValueError):
        pass
    return ids, saved
