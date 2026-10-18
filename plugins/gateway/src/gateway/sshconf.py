"""The gateway's own SSH setup for `ssh` accounts.

Each call writes a private ssh_config and known_hosts into the runner's temp
dir and runs `ssh -F <that file> gw-NAME`; the user's ~/.ssh is never read.

- Routes: an account may have several ways in, in order ("home" on the LAN,
  "away" through a forwarded port). The gateway picks one in Python: a route
  with `when` (a CIDR) applies only if this machine's address toward it is in
  that network, and a route that isn't the last must answer an SSH banner
  within a short probe. The choice is cached for a few minutes.
- One host identity across routes: known_hosts lines are written under a
  HostKeyAlias (gw-NAME), so the same pinned keys hold whichever route is used.
- Host-key policy: pinned (default), accept-new (a test box that gets
  reflashed: a changed key is re-read, stored and logged) or ask (a changed
  key opens the native dialog with both fingerprints). ssh itself always runs
  with StrictHostKeyChecking=yes; replacing a key is the gateway's decision.
- Keys: the newest key plus older ones kept during a rotation, all in the
  call's private agent; IdentitiesOnly offers only those.
- Reuse (ControlMaster) only for a session where the user typed
  `/gate:enable reuse ssh:NAME`. A master is a logged-in session, so it's
  never on by default.
"""
from __future__ import annotations

import ipaddress
import os
import shlex
import socket
import hashlib
import subprocess
import time
from pathlib import Path
from typing import Any

from . import policy, runner, vault

POLICIES = ("pinned", "accept-new", "ask")
COMFORT = {"connect_timeout": 10, "keepalive": 30, "compression": False, "reuse_minutes": 10}
PROBE_TIMEOUT = 2.0
ROUTE_CACHE_S = 300
MAX_JUMPS = 3
_CACHE: dict[str, tuple[float, str, str]] = {}  # ref -> (when, route name, why)


class SshError(Exception):
    """Refused before anything ran (bad account, no key, no pinned host key)."""


def name_of(ref: str) -> str:
    return ref.split(":", 1)[1]


def alias(ref: str) -> str:
    return "gw-" + name_of(ref)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def routes(acct: dict[str, Any]) -> list[dict[str, str]]:
    """The account's routes in order; an account without any has one, from
    its host and port."""
    rs = acct.get("routes") or []
    if not rs:
        return [{"name": "default", "host": acct.get("host", ""),
                 "port": str(acct.get("port") or ""), "when": ""}]
    return [{"name": r.get("name") or f"route{i + 1}", "host": r.get("host", ""),
             "port": str(r.get("port") or ""), "when": r.get("when") or ""}
            for i, r in enumerate(rs)]


def check_routes(rs: Any) -> list[dict[str, str]]:
    """Validate routes from a setup proposal; raises ValueError."""
    if not isinstance(rs, list) or not rs or len(rs) > 8:
        raise ValueError("routes: a list of 1 to 8 {name, host, port, when}")
    out, names = [], set()
    for i, r in enumerate(rs):
        if not isinstance(r, dict):
            raise ValueError("each route is {name, host, port, when}")
        name = str(r.get("name") or f"route{i + 1}").strip().lower()
        host = str(r.get("host", "")).strip().lower()
        port = str(r.get("port") or "").strip()
        when = str(r.get("when") or "").strip()
        if not name.replace("-", "").replace("_", "").isalnum() or name in names:
            raise ValueError(f"route name {name!r}: letters, digits, - and _, each name once")
        if not vault.HOST_RE.fullmatch(host):
            raise ValueError(f"route {name}: {host!r} is not a host name or address")
        if port and not (port.isdigit() and 0 < int(port) < 65536):
            raise ValueError(f"route {name}: port {port!r} is not a port number")
        if when:
            try:
                when = str(ipaddress.ip_network(when, strict=False))
            except ValueError:
                raise ValueError(f"route {name}: when={when!r} is not a network like "
                                 "192.168.0.0/24")
        names.add(name)
        out.append({"name": name, "host": host, "port": port, "when": when})
    return out


def _local_addr_toward(host: str, port: str) -> ipaddress._BaseAddress | None:
    """This machine's source address toward host (a UDP connect sends nothing)."""
    try:
        infos = socket.getaddrinfo(host, int(port or 22), proto=socket.IPPROTO_UDP)
    except (OSError, ValueError):
        return None
    for fam, _, _, _, sa in infos:
        s = socket.socket(fam, socket.SOCK_DGRAM)
        try:
            s.connect(sa)
            return ipaddress.ip_address(s.getsockname()[0].split("%")[0])
        except (OSError, ValueError):
            continue
        finally:
            s.close()
    return None


def _answers_ssh(host: str, port: str, timeout: float) -> bool:
    try:
        with socket.create_connection((host, int(port or 22)), timeout=timeout) as s:
            s.settimeout(timeout)
            return s.recv(8).startswith(b"SSH-")
    except (OSError, ValueError):
        return False


def pick(ref: str, acct: dict[str, Any], skip: tuple[str, ...] = (),
         use_cache: bool = True) -> tuple[dict[str, str], str]:
    """(route, why). Routes in `skip` were just tried and failed."""
    rs = [r for r in routes(acct) if r["name"] not in skip]
    if not rs:
        raise SshError(f"{ref}: no route left to try")
    if len(rs) == 1:
        return rs[0], "its only route" if not skip else "the last route left"
    key = ref + "|" + repr((acct.get("routes"), skip))
    hit = _CACHE.get(key)
    if use_cache and hit and time.time() - hit[0] < ROUTE_CACHE_S:
        for r in rs:
            if r["name"] == hit[1]:
                return r, hit[2] + " (cached)"
    timeout = float(os.environ.get("GATEWAY_ROUTE_PROBE_S") or PROBE_TIMEOUT)
    notes = []
    chosen, why = rs[-1], ""
    for r in rs[:-1]:
        if r["when"]:
            me = _local_addr_toward(r["host"], r["port"])
            if me is None or me not in ipaddress.ip_network(r["when"]):
                notes.append(f"{r['name']}: not on {r['when']}")
                continue
        if _answers_ssh(r["host"], r["port"], timeout):
            chosen, why = r, f"{r['name']} answered"
            break
        notes.append(f"{r['name']}: no answer")
    if not why:
        why = f"{chosen['name']} (the last route)"
    if notes:
        why += "; " + ", ".join(notes)
    _CACHE[key] = (time.time(), chosen["name"], why)
    return chosen, why


# ---------------------------------------------------------------------------
# Accounts as a chain (target, then its jump hosts)
# ---------------------------------------------------------------------------


def keys(acct: dict[str, Any]) -> list[tuple[str, str]]:
    """(private, public) pairs, newest first."""
    s = acct.get("secrets", {})
    out = []
    if s.get("ssh_key"):
        out.append((s["ssh_key"], acct.get("public_key", "")))
    for priv, pub in zip(s.get("old_ssh_keys", []), acct.get("old_public_keys", [])):
        out.append((priv, pub))
    return out


def host_key_policy(acct: dict[str, Any]) -> str:
    p = acct.get("host_key_policy") or "pinned"
    return p if p in POLICIES else "pinned"


def chain(ref: str, data: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    """[(ref, account)] for the target and each jump host after it."""
    out: list[tuple[str, dict[str, Any]]] = []
    cur = ref
    while cur:
        if any(r == cur for r, _ in out):
            raise SshError(f"{ref}: its jump hosts loop back to {cur}")
        if len(out) > MAX_JUMPS:
            raise SshError(f"{ref}: more than {MAX_JUMPS} jump hosts")
        a = data["accounts"].get(cur)
        what = "is" if cur == ref else f"(a jump host of {ref}) is"
        if a is None or a.get("kind") != "ssh":
            raise SshError(f"{cur} {what} not an ssh account; see account_list")
        if not keys(a):
            raise SshError(f"{cur} {what} without an SSH key; ask the user to run "
                           f"/gate:update {cur}")
        if not a.get("known_hosts") and host_key_policy(a) == "pinned":
            raise SshError(f"{cur} has no pinned host key; ask the user to run "
                           f"/gate:update {cur} (it reads the key)")
        out.append((cur, a))
        cur = a.get("jump") or ""
    return out


# ---------------------------------------------------------------------------
# Reuse (ControlMaster), per session, opt-in
# ---------------------------------------------------------------------------


def reuse_on(ref: str, data: dict[str, Any], session_id: str | None) -> bool:
    return bool(session_id) and session_id in data.get("ssh_reuse", {}).get(ref, [])


def mux_dir() -> Path:
    """A 0700 directory for master sockets. A socket path must stay under
    104 bytes (macOS) including ssh's 17-byte temp suffix, so a long data
    folder gives way to /tmp."""
    d = policy.data_dir() / "ssh-mux"
    if len(str(d)) > 48:
        d = Path("/tmp") / f"gw-mux-{os.getuid()}"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    if d.stat().st_uid != os.getuid():
        raise SshError(f"{d} isn't owned by this user, so connection reuse is off")
    return d


def close_masters(ref: str) -> int:
    """Stop the reuse masters of an account (on /gate:disable reuse)."""
    try:
        d = mux_dir()
    except (OSError, SshError):
        return 0
    n = 0
    for sock in d.glob(name_of(ref) + "-*"):
        try:
            subprocess.run([runner._which("ssh"), "-F", os.devnull, "-S", str(sock), "-O", "exit", "x"],
                           capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired, runner.RunnerError):
            pass
        try:
            sock.unlink()
        except OSError:
            pass
        n += 1
    return n


# ---------------------------------------------------------------------------
# The generated config
# ---------------------------------------------------------------------------


def known_hosts_lines(ref: str, acct: dict[str, Any]) -> list[str]:
    out = []
    for line in (acct.get("known_hosts") or "").splitlines():
        parts = line.split()
        if len(parts) >= 3 and not line.startswith("#"):
            out.append(f"{alias(ref)} {parts[1]} {parts[2]}")
    return out


def _q(v: str | Path) -> str:
    s = str(v)
    if any(c in s for c in ' "\t\n#'):
        if '"' in s or "\n" in s:
            raise SshError(f"unusable path for ssh_config: {s!r}")
        return f'"{s}"'
    return s


def write_config(tmp: Path, links: list[tuple[str, dict[str, Any]]],
                 picked: dict[str, dict[str, str]], ssh_bin: str,
                 reuse: bool = False) -> Path:
    """Write tmp/ssh_config + tmp/known_hosts + public key files; return the
    config path. links[0] is the target; each next one is the previous one's
    jump host."""
    cfg = tmp / "ssh_config"
    kh = tmp / "known_hosts"
    lines_kh: list[str] = []
    blocks: list[str] = []
    for i, (ref, acct) in enumerate(links):
        lines_kh += known_hosts_lines(ref, acct)
        route = picked[ref]
        c = {**COMFORT, **(acct.get("comfort") or {})}
        b = [f"Host {alias(ref)}",
             f"  HostName {route['host']}",
             f"  Port {route['port'] or 22}",
             f"  User {acct.get('user')}",
             f"  HostKeyAlias {alias(ref)}",
             f"  UserKnownHostsFile {_q(kh)}",
             "  GlobalKnownHostsFile /dev/null",
             "  StrictHostKeyChecking yes",
             "  CheckHostIP no",
             "  UpdateHostKeys no",
             "  BatchMode yes",
             "  PasswordAuthentication no",
             "  KbdInteractiveAuthentication no",
             "  IdentitiesOnly yes",
             f"  IdentityAgent {_q(tmp / 'agent.sock')}"]
        for j, (_, pub) in enumerate(keys(acct)):
            p = tmp / f"id-{i}-{j}.pub"
            p.write_text(pub.strip() + "\n")
            b.append(f"  IdentityFile {_q(p)}")
        b += ["  ForwardAgent no", "  ForwardX11 no", "  ClearAllForwardings yes",
              "  PermitLocalCommand no", "  Tunnel no",
              f"  ConnectTimeout {int(c['connect_timeout'])}",
              f"  ServerAliveInterval {int(c['keepalive'])}",
              "  ServerAliveCountMax 3",
              f"  Compression {'yes' if c['compression'] else 'no'}"]
        if i + 1 < len(links):
            nxt = alias(links[i + 1][0])
            b.append("  ProxyCommand " + shlex.join([ssh_bin, "-F", str(cfg), "-W",
                                                     "[%h]:%p", nxt]))
        if i == 0 and reuse:
            # One master per route and jump chain (not %C: too long a path).
            ident = "|".join(f"{r}={picked[r]['host']}:{picked[r]['port']}:{a.get('user')}"
                             for r, a in links)
            sock = mux_dir() / f"{name_of(ref)}-{hashlib.sha256(ident.encode()).hexdigest()[:12]}"
            if len(str(sock)) > 86:
                raise SshError(f"the reuse socket path {sock} is too long; reuse is off")
            b += ["  ControlMaster auto",
                  f"  ControlPath {_q(sock)}",
                  f"  ControlPersist {int(c['reuse_minutes'])}m"]
        else:
            b += ["  ControlMaster no", "  ControlPath none"]
        blocks.append("\n".join(b))
    kh.write_text("\n".join(lines_kh) + "\n")
    # Anything else (a typo, a host Claude names) gets nothing.
    blocks.append("Host *\n  BatchMode yes\n  IdentityAgent none\n  IdentityFile none\n"
                  "  StrictHostKeyChecking yes\n  UserKnownHostsFile /dev/null\n"
                  "  GlobalKnownHostsFile /dev/null\n  ProxyCommand none")
    cfg.write_text("\n\n".join(blocks) + "\n")
    return cfg


# ---------------------------------------------------------------------------
# Host keys that changed
# ---------------------------------------------------------------------------

HOSTKEY_FAIL = ("host key verification failed", "remote host identification has changed")


def host_key_failed(stderr: str) -> bool:
    s = stderr.lower()
    return any(m in s for m in HOSTKEY_FAIL)


def _key_set(known_hosts: str) -> set[tuple[str, str]]:
    return {(p[1], p[2]) for p in (l.split() for l in known_hosts.splitlines())
            if len(p) >= 3 and not p[0].startswith("#")}


def refresh_host_keys(links: list[tuple[str, dict[str, Any]]],
                      picked: dict[str, dict[str, str]]) -> list[str]:
    """After a host-key failure: for links whose policy allows it, read the
    key again and store it (accept-new) or ask in the dialog (ask). Returns
    notes about each key stored; empty if nothing changed."""
    from . import dialog
    notes = []
    for ref, acct in links:
        pol = host_key_policy(acct)
        if pol == "pinned":
            continue
        route = picked[ref]
        scanned = vault.keyscan(route["host"], route["port"])
        if not scanned or _key_set(scanned) == _key_set(acct.get("known_hosts", "")):
            continue
        old_fp = vault.host_key_fingerprints(acct.get("known_hosts", "")) or ["(none)"]
        new_fp = vault.host_key_fingerprints(scanned)
        if pol == "ask":
            try:
                ok = dialog.confirm(
                    f"The SSH host key of {ref} ({route['host']}) has changed.\n\n"
                    f"Pinned: {'; '.join(old_fp)}\nNow: {'; '.join(new_fp)}\n\n"
                    "Allow only if you reinstalled or rekeyed that machine.")
            except dialog.Unavailable:
                ok = False
            if not ok:
                policy.audit("host_key", {"account": ref, "outcome": "kept the pinned key",
                                          "new": new_fp})
                continue
        with vault.locked():
            data = vault.load()
            a = data["accounts"].get(ref)
            if a is None:
                continue
            a["known_hosts"] = scanned
            a["host_key_changed"] = vault.now()
            vault.save(data)
        acct["known_hosts"] = scanned
        policy.audit("host_key", {"account": ref, "outcome": f"replaced ({pol})",
                                  "old": old_fp, "new": new_fp})
        notes.append(f"{ref}: its host key changed and was replaced ({pol}); "
                     f"was {'; '.join(old_fp)}, now {'; '.join(new_fp)}")
    return notes


def first_pin(links: list[tuple[str, dict[str, Any]]],
              picked: dict[str, dict[str, str]]) -> list[str]:
    """accept-new/ask links with no key yet: read it now (trust on first use)."""
    return refresh_host_keys([(r, a) for r, a in links if not a.get("known_hosts")], picked)
