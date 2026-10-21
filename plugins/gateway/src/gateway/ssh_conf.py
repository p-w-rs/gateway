"""The gateway's own ssh setup for one call (SPEC 9.2): address choice, the
generated ssh_config, the private agent and the shared connections.

- Address choice: the candidates (approved `address`, then `also`) whose
  `when` network contains this machine's source address toward them are
  probed in parallel (1 s TCP connect + `SSH-` banner); the first in list
  order that answered wins. Its host keys are read once and compared with the
  pins: a non-last candidate showing other keys is skipped (logged; another
  machine on that network), the last one's mismatch is the caller's to raise
  (a hostkey pop-up). The pick is cached for 5 minutes per (host, network
  fingerprint) in the run dir. Hosts behind `via` aren't probed (they can't
  be reached from here): the first candidate whose `when` matches is used.
- Config: one `Host gw-NAME` block per hop (target, then each jump host),
  `HostKeyAlias gw-NAME` with the pinned keys in a per-call known_hosts,
  `StrictHostKeyChecking yes`, `IdentitiesOnly yes`, `IdentityAgent` = the
  call's private agent, `IdentityFile` = each live public key, no
  forwarding, `ControlMaster auto` with `ControlPath <run>/cm-%C` and
  `ControlPersist 120` (form hosts only: two accounts share git@github.com),
  `ProxyJump gw-JUMP`, and a final `Host *` with no identity and an empty
  known_hosts.
- Agent: `ssh-agent -D -a <call dir>/agent.sock` under a watchdog shell that
  kills it when the stand-in's pipe closes (even after SIGKILL), keys loaded
  with `ssh-add -t 300 -` from stdin, killed once this call's own master is
  up or its ssh ends. The socket path is only ever named in the generated
  config.
- Masters: a call that finds no live master takes the lock file next to
  each master socket of its chain (`<run>/cm-%C.lock`, fcntl.flock, sorted,
  at most MASTER_LOCK_WAIT seconds in all), checks again and, if still no
  master answers, starts one, holding the lock until the target's master
  answers or ssh exits (`Conn.master_watch`, for the stand-in's ssh and the
  gate process's `capture` alike: a long remote command doesn't keep it). A
  parallel call to the same host waits on the lock and reuses that master,
  so OpenSSH's "ControlSocket ... already exists, disabling multiplexing"
  (two clients racing under ControlMaster auto) doesn't reach the output.
  Only a lock holder starts a master on that ControlPath: a hop whose lock a
  call doesn't hold (the wait ran out, or scp/sftp, which never keep it) is
  reached without multiplexing (`ControlMaster no`, `ControlPath none` in
  that call's config), so the master that answers there is the holder's own,
  and only the holder kills its agent early; the others keep theirs until
  their ssh exits. The lock files are never removed (a waiter could lock a
  removed file).
- Running: ssh's own messages go to `-E <call dir>/ssh.log` (followed and
  copied to stderr); failures are classified from that log only, never from
  the remote command's stderr.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterator

from . import audit, paths, testing, vault
from . import form as formmod

PROBE_TIMEOUT = 1.0
SCAN_TIMEOUT = 3
ADDR_CACHE_S = 300
CONTROL_PERSIST = 120
MASTER_LOCK_WAIT = 5.0  # a call waits this long (in all) for another call starting the master
AGENT_LIFETIME = 300
CONNECT_TIMEOUT = 10
SERVER_ALIVE = 30
CHILD_ENV = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
             "TZ", "TERM", "TMPDIR", "GIT_PROTOCOL")
CALL_PREFIX = "c-"


class SshError(Exception):
    """Refused or failed before the command ran. `message` starts with
    'gateway:' and says what to do next; `code` is the exit code to use."""

    def __init__(self, message: str, code: int = 2, fix: str | None = None,
                 printed: bool = False):
        super().__init__(message)
        self.message = message
        self.code = code
        self.fix = fix
        self.printed = printed      # the pop-up module already printed it


# The system's ssh, by absolute path, for a draining gated only
# (daemon/lifecycle.Daemon.drain calls allow_system_ssh): a plain uninstall
# deletes the env's ssh with the data folder, and a remote job a pause suspended
# is then resumed through the gateway's live master (its ControlPath in the run
# dir) with the call's generated config (`-F`: no user or system ssh config is
# read). It never starts a master (`ControlMaster=no` on its command line), and
# with no live master the call stops before ssh runs (the agent it would need
# is the env's ssh-agent, gone too). Never used by the stand-ins or `gate`.
SYSTEM_SSH = "/usr/bin/ssh"
_SYSTEM_SSH_OK = threading.Event()


def allow_system_ssh() -> None:
    _SYSTEM_SSH_OK.set()


def _system_ssh() -> str | None:
    if not _SYSTEM_SSH_OK.is_set():
        return None
    p = SYSTEM_SSH
    v = testing.get("system_ssh") if testing.active() is not None else None
    if isinstance(v, str) and os.path.isabs(v):
        p = v                          # a test names the "system" ssh
    return p if os.path.isfile(p) and os.access(p, os.X_OK) else None


def ssh_bin() -> str:
    try:
        return paths.tool("ssh")
    except paths.ToolMissing:
        fb = _system_ssh()
        if fb is not None:
            return fb
        raise SshError("gateway: the gateway's ssh isn't installed yet (first run); try again "
                       "in a minute", 75) from None


def tool(name: str) -> str:
    try:
        return paths.tool(name)
    except paths.ToolMissing:
        raise SshError(f"gateway: the gateway's {name} isn't installed yet (first run); try "
                       "again in a minute", 75) from None


def lock_wait() -> float:
    """MASTER_LOCK_WAIT; a test may shorten it (testing.override(master_lock_wait=S))."""
    v = testing.get("master_lock_wait")
    return MASTER_LOCK_WAIT if v is None else float(v)


def child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """The environment ssh runs with: an allowlist (never SSH_AUTH_SOCK)."""
    env = {k: v for k, v in os.environ.items() if k in CHILD_ENV}
    env.setdefault("PATH", "/usr/bin:/bin")
    env.update(extra or {})
    return env


# ---------------------------------------------------------------------------
# One hop
# ---------------------------------------------------------------------------


@dataclass
class Link:
    name: str                       # form host name (or account name for an endpoint)
    addr: formmod.Address           # chosen address (user filled in)
    host_keys: list[str]            # pinned "type base64"
    pubkeys: list[str]              # public key lines (IdentityFile)
    privkeys: list[str] = field(default_factory=list, repr=False)   # into the agent
    master: bool = True             # ControlMaster auto (form hosts) or no (endpoints)
    jump: "Link | None" = None
    why: str = ""                   # how the address was chosen

    @property
    def alias(self) -> str:
        return "gw-" + self.name

    def chain(self) -> list["Link"]:
        out, cur, seen = [], self, set()
        while cur is not None:
            if cur.name in seen:
                raise SshError(f"gateway: {self.name}'s via chain loops; fix gateway.toml")
            seen.add(cur.name)
            out.append(cur)
            cur = cur.jump
        return out


def _q(v: str | Path) -> str:
    s = str(v)
    if any(c in s for c in '"\n\r\t'):
        raise SshError(f"gateway: a path the gateway needs can't be written into ssh_config")
    return f'"{s}"' if any(c in s for c in " #") else s


def control_dir() -> Path:
    return paths.run_dir()


def write_config(d: Path, target: Link, overrides: dict[str, dict[str, str]] | None = None,
                 solo: frozenset[str] = frozenset()) -> Path:
    """Write d/ssh_config, d/known_hosts and the public key files for
    target's chain; return the config path. `overrides` replaces or adds
    keywords per alias (a test login without the master, a password login).
    The hops in `solo` (aliases) are reached without multiplexing, like an
    endpoint: the call doesn't hold their ControlPath lock (Conn.ensure_agent)."""
    links = target.chain()
    kh, blocks = [], []
    cdir = control_dir()
    for link in links:
        for k in link.host_keys:
            n = vault.norm_host_key(k)
            if n:
                kh.append(f"{link.alias} {n}")
        a = link.addr
        o: dict[str, str] = {
            "HostName": a.host, "Port": str(a.port), "User": a.effective_user(),
            "HostKeyAlias": link.alias, "UserKnownHostsFile": _q(d / "known_hosts"),
            "GlobalKnownHostsFile": "/dev/null", "StrictHostKeyChecking": "yes",
            "CheckHostIP": "no", "UpdateHostKeys": "no", "BatchMode": "yes",
            "PasswordAuthentication": "no", "KbdInteractiveAuthentication": "no",
            "PubkeyAuthentication": "yes", "IdentitiesOnly": "yes",
            "IdentityAgent": _q(d / "agent.sock"),
            "ForwardAgent": "no", "ForwardX11": "no", "PermitLocalCommand": "no",
            "ServerAliveInterval": str(SERVER_ALIVE), "ConnectTimeout": str(CONNECT_TIMEOUT),
        }
        if link.master and link.alias not in solo:
            o.update({"ControlMaster": "auto", "ControlPath": _q(cdir / "cm-%C"),
                      "ControlPersist": str(CONTROL_PERSIST)})
        else:
            o.update({"ControlMaster": "no", "ControlPath": "none"})
        if link.jump is not None:
            o["ProxyJump"] = link.jump.alias
        o.update((overrides or {}).get(link.alias, {}))
        b = [f"Host {link.alias}"] + [f"  {k} {v}" for k, v in o.items() if v is not None]
        for i, pub in enumerate(link.pubkeys):
            p = d / f"{link.name}-{i}.pub"
            _write(p, pub.strip() + "\n")
            b.append(f"  IdentityFile {_q(p)}")
        if not link.pubkeys:   # never fall back to ~/.ssh/id_* (a file that doesn't exist)
            b.append(f"  IdentityFile {_q(d / 'no-identity')}")
        blocks.append("\n".join(b))
    blocks.append("Host *\n  IdentityAgent none\n  IdentitiesOnly yes\n"
                  "  UserKnownHostsFile /dev/null\n  GlobalKnownHostsFile /dev/null\n"
                  "  StrictHostKeyChecking yes\n  BatchMode yes\n  PasswordAuthentication no\n"
                  "  KbdInteractiveAuthentication no\n  ProxyCommand none\n"
                  "  ControlMaster no\n  ControlPath none\n  ForwardAgent no\n"
                  "  PermitLocalCommand no")
    _write(d / "known_hosts", "\n".join(kh) + "\n")
    cfg = d / "ssh_config"
    tmp = d / "ssh_config.tmp"            # whole or not at all (rewritten for solo hops)
    _write(tmp, "\n\n".join(blocks) + "\n")
    os.replace(tmp, cfg)
    return cfg


def _write(p: Path, text: str, mode: int = 0o600) -> None:
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)


# ---------------------------------------------------------------------------
# Per-call directory, agent, masters
# ---------------------------------------------------------------------------


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def sweep_call_dirs() -> None:
    """Remove per-call dirs left by killed stand-ins."""
    try:
        for p in control_dir().glob(CALL_PREFIX + "*"):
            m = re.fullmatch(CALL_PREFIX + r"(\d+)-[0-9a-f]+", p.name)
            if m and not _pid_alive(int(m.group(1))):
                shutil.rmtree(p, ignore_errors=True)
    except (OSError, paths.PathError):
        pass


# The agent runs under a tiny watchdog shell that holds the read end of a pipe
# from the stand-in: when the stand-in ends in any way (even SIGKILL), the
# pipe closes, `read` returns and the agent is killed. No pid files, no pid
# reuse races.
AGENT_WATCHDOG = ('"$1" -D -a "$2" </dev/null >/dev/null 2>&1 & a=$!; echo "$a"; '
                  'trap \'kill "$a" 2>/dev/null; exit 0\' TERM HUP INT; '
                  'read _ignored; kill "$a" 2>/dev/null; wait "$a" 2>/dev/null; exit 0')


class Agent:
    """A private ssh-agent for one call. Never exported: only the generated
    config names its socket. It dies with the stand-in (AGENT_WATCHDOG)."""

    def __init__(self, sock: Path):
        self.sock = sock
        self.proc: subprocess.Popen | None = None
        self.pid: int | None = None

    def start(self, keys: list[str]) -> None:
        self.proc = subprocess.Popen(["/bin/sh", "-c", AGENT_WATCHDOG, "gw-agent",
                                      tool("ssh-agent"), str(self.sock)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, env=child_env(),
                                     start_new_session=True)
        assert self.proc.stdout is not None
        line = self.proc.stdout.readline().strip()
        self.proc.stdout.close()
        self.pid = int(line) if line.isdigit() else None
        deadline = time.time() + 5
        while not self.sock.exists():
            if time.time() > deadline or self.proc.poll() is not None or self.pid is None:
                self.close()
                raise SshError("gateway: could not start the gateway's private ssh-agent; try "
                               "again", 255)
            time.sleep(0.01)
        add = tool("ssh-add")
        for k in keys:
            r = subprocess.run([add, "-q", "-t", str(AGENT_LIFETIME), "-"],
                               input=vault.normalize_key(k).encode(),
                               env=child_env({"SSH_AUTH_SOCK": str(self.sock)}),
                               capture_output=True, timeout=15)
            if r.returncode != 0:
                self.close()
                raise SshError("gateway: a stored ssh key could not be loaded; run gate check "
                               "for that host", 255)

    @property
    def alive(self) -> bool:
        return (self.proc is not None and self.proc.poll() is None and self.pid is not None
                and _pid_alive(self.pid))

    def close(self) -> None:
        p, self.proc = self.proc, None
        apid, self.pid = self.pid, None
        if p is not None:
            with contextlib.suppress(OSError):
                if p.stdin is not None:
                    p.stdin.close()          # the watchdog's `read` returns: it kills the agent
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait(timeout=5)
        if apid is not None and _pid_alive(apid):
            with contextlib.suppress(OSError):
                os.kill(apid, signal.SIGTERM)
        with contextlib.suppress(OSError):
            self.sock.unlink()


def parse_g(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for line in text.splitlines():
        k, _, v = line.partition(" ")
        if k:
            out.setdefault(k.lower(), []).append(v.strip())
    return out


def ssh_g(cfg: Path, args: list[str]) -> dict[str, list[str]]:
    r = subprocess.run([ssh_bin(), "-G", "-F", str(cfg), *args], capture_output=True, text=True,
                       timeout=15, stdin=subprocess.DEVNULL, env=child_env())
    if r.returncode != 0:
        raise SshError("gateway: ssh didn't accept that command line; run plain `ssh NAME CMD`")
    return parse_g(r.stdout)


def master_alive(cfg: Path, alias: str, path: str | None = None) -> bool:
    """Does a master answer on alias's ControlPath (or on `path`: the shared
    one, also when this call's config reaches the hop without it)?"""
    try:
        r = subprocess.run([ssh_bin(), "-F", str(cfg), *(["-S", path] if path else []),
                            "-O", "check", alias],
                           capture_output=True, timeout=10, stdin=subprocess.DEVNULL,
                           env=child_env())
    except (OSError, subprocess.TimeoutExpired):
        return False
    return r.returncode == 0


def _index_path(name: str) -> Path:
    return control_dir() / f"cm-{name}.list"


def record_master(name: str, path: str) -> None:
    """Remember a control socket path for close_masters(name)."""
    try:
        p = _index_path(name)
        known = p.read_text().split("\n") if p.exists() else []
        if path in known:
            return
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, (path + "\n").encode())
        finally:
            os.close(fd)
    except (OSError, paths.PathError):
        pass


def close_recorded(name: str) -> int:
    """`-O exit` every recorded master of `name`; remove the sockets. Returns
    how many masters answered."""
    try:
        p = _index_path(name)
        lines = [x for x in p.read_text().split("\n") if x] if p.exists() else []
    except (OSError, paths.PathError):
        return 0
    n = 0
    try:
        ssh = ssh_bin()
    except SshError:
        ssh = None
    for sock in dict.fromkeys(lines):
        if ssh and os.path.exists(sock):
            try:
                r = subprocess.run([ssh, "-F", "/dev/null", "-S", sock, "-O", "exit", "gw"],
                                   capture_output=True, timeout=10, stdin=subprocess.DEVNULL,
                                   env=child_env())
                n += r.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                pass
        with contextlib.suppress(OSError):
            if os.path.exists(sock) and Path(sock).parent == control_dir():
                os.unlink(sock)
    with contextlib.suppress(OSError, paths.PathError):
        p.unlink()
    return n


# ---------------------------------------------------------------------------
# Address choice
# ---------------------------------------------------------------------------


def source_addr(host: str, port: int = 22) -> ipaddress._BaseAddress | None:
    """This machine's source address toward host (a UDP connect sends nothing)."""
    try:
        infos = socket.getaddrinfo(host, int(port), proto=socket.IPPROTO_UDP)
    except (OSError, ValueError, UnicodeError):
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


def when_ok(a: formmod.Address) -> bool:
    if not a.when:
        return True
    me = source_addr(a.host, a.port)
    try:
        return me is not None and me in ipaddress.ip_network(a.when, strict=False)
    except ValueError:
        return False


def answers_ssh(host: str, port: int, timeout: float = PROBE_TIMEOUT) -> bool:
    """TCP connect plus an `SSH-` banner within `timeout` seconds in all."""
    deadline = time.monotonic() + timeout
    try:
        with socket.create_connection((host, int(port)), timeout=timeout) as s:
            buf = b""
            while len(buf) < 4:
                left = deadline - time.monotonic()
                if left <= 0:
                    return False
                s.settimeout(left)
                chunk = s.recv(64)
                if not chunk:
                    return False
                buf += chunk
            return buf.startswith(b"SSH-")
    except (OSError, ValueError, UnicodeError):
        return False


def net_fingerprint() -> str:
    """Default-route source addresses (v4 and v6), hashed: changes when this
    machine moves to another network."""
    bits = []
    for target in ("203.0.113.1", "2001:db8::1"):
        a = source_addr(target, 9)
        bits.append(str(a) if a else "-")
    return hashlib.sha256("|".join(bits).encode()).hexdigest()[:16]


def scan_keys(host: str, port: int) -> list[str]:
    """The host's keys as 'type base64' ([] if unreachable). Test override:
    testing.override(keyscan=...) like vault.keyscan."""
    fake = testing.get("keyscan")
    if fake is not None:
        return vault.keyscan(host, port)
    if host.startswith("-"):
        return []
    try:
        ks = paths.tool("ssh-keyscan")
    except paths.ToolMissing:
        return []
    cmd = [ks, "-T", str(SCAN_TIMEOUT), "-t", "ed25519,ecdsa,rsa", "-p", str(int(port)), "--", host]
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT * 4 + 5,
                             stdin=subprocess.DEVNULL, env=child_env())
    except (OSError, subprocess.TimeoutExpired):
        return []
    keys = [vault.norm_host_key(l) for l in out.stdout.splitlines()
            if l.strip() and not l.startswith("#")]
    return list(dict.fromkeys(k for k in keys if k))


def keys_match(scanned: list[str], pins: list[str]) -> bool:
    pinset = {vault.norm_host_key(p) for p in pins}
    return any(vault.norm_host_key(s) in pinset for s in scanned)


@dataclass
class Choice:
    addr: formmod.Address
    why: str
    mismatch: list[str] | None = None   # the last candidate showed these keys instead


def _cache_path(name: str) -> Path:
    return control_dir() / f"addr-{name}.json"


def _cands_key(cands: list[formmod.Address]) -> str:
    raw = json.dumps([[a.effective_user(), a.host, a.port, a.when] for a in cands])
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _cache_get(name: str, key: str) -> tuple[int, str] | None:
    try:
        d = json.loads(_cache_path(name).read_text())
        e = d.get(key)
        if e and time.time() - float(e["at"]) < ADDR_CACHE_S:
            return int(e["index"]), str(e.get("why", ""))
    except (OSError, ValueError, KeyError, TypeError, paths.PathError):
        pass
    return None


def _cache_put(name: str, key: str, index: int, why: str) -> None:
    try:
        p = _cache_path(name)
        try:
            d = json.loads(p.read_text())
            if not isinstance(d, dict):
                d = {}
        except (OSError, ValueError):
            d = {}
        now = time.time()
        d = {k: v for k, v in d.items() if isinstance(v, dict)
             and now - float(v.get("at", 0)) < ADDR_CACHE_S}
        d[key] = {"at": now, "index": index, "why": why}
        tmp = p.with_name(p.name + f".{os.getpid()}")
        _write(tmp, json.dumps(d))
        os.replace(tmp, p)
    except (OSError, paths.PathError, ValueError):
        pass


def cache_clear(name: str) -> None:
    with contextlib.suppress(OSError, paths.PathError):
        _cache_path(name).unlink()


WHEN_DEADLINE = 1.0


def parallel(fn: Callable[[Any], Any], items: list[Any], deadline: float) -> list[Any]:
    """fn(item) for each item in daemon threads; None for any that didn't
    finish within `deadline` seconds (a hung getaddrinfo can't delay the
    call, nor the process exit)."""
    import threading
    out: list[Any] = [None] * len(items)
    done = [threading.Event() for _ in items]

    def one(k: int, it: Any) -> None:
        try:
            out[k] = fn(it)
        except Exception:  # noqa: BLE001 - a failed check is "no"
            out[k] = None
        finally:
            done[k].set()

    for k, it in enumerate(items):
        threading.Thread(target=one, args=(k, it), daemon=True).start()
    end = time.monotonic() + deadline
    for ev in done:
        ev.wait(max(0.0, end - time.monotonic()))
    return [out[k] if done[k].is_set() else None for k in range(len(items))]


def _probe(a: formmod.Address) -> str:
    """'elsewhere' (its `when` network isn't this one), 'yes' or 'no'."""
    if not when_ok(a):
        return "elsewhere"
    return "yes" if answers_ssh(a.host, a.port) else "no"


def _no_network(name: str, cands: list[formmod.Address]) -> SshError:
    nets = ", ".join(sorted({a.when for a in cands if a.when}))
    return SshError(f"gateway: none of {name}'s addresses is for this network ({nets}); add an "
                    "address without `when` to reach it from here", 255)


def choose(name: str, cands: list[formmod.Address], pins: list[str], *, via: bool = False,
           verify: bool = True, use_cache: bool = True,
           scan: Callable[[str, int], list[str]] | None = None) -> Choice:
    """Pick the address for a form host (see the module docstring). Raises
    SshError when no candidate can be used; returns a Choice whose
    `mismatch` is set when only the last candidate answered and showed other
    host keys (the caller asks the user)."""
    if not cands:
        raise SshError(f"gateway: {name} has no approved address; run gate check {name} while "
                       "the user is here")
    scan = scan or scan_keys
    if via:
        whens = parallel(when_ok, cands, WHEN_DEADLINE)
        eligible = [(i, a) for i, a in enumerate(cands) if whens[i]]
        if not eligible:
            raise _no_network(name, cands)
        i, a = eligible[0]
        return Choice(a, "behind its jump host (not probed)")
    key = f"{net_fingerprint()}|{_cands_key(cands)}"
    if use_cache:
        hit = _cache_get(name, key)
        if hit is not None and 0 <= hit[0] < len(cands):
            return Choice(cands[hit[0]], (hit[1] + " (cached)").strip())
    # `when` and the probe run together per candidate, names resolved inside
    # the threads: a slow resolver (offline) can't stretch the 1 s probe.
    res = parallel(_probe, cands, PROBE_TIMEOUT + WHEN_DEADLINE)
    eligible = [(i, a) for i, a in enumerate(cands) if res[i] != "elsewhere"]
    if not eligible:
        raise _no_network(name, cands)
    answered = {i: res[i] == "yes" for i, _ in eligible}
    notes: list[str] = []
    last_i = eligible[-1][0]
    for i, a in eligible:
        if not answered[i]:
            notes.append(f"{a.render()} didn't answer")
            continue
        if verify and pins:
            seen = scan(a.host, a.port)
            if seen and not keys_match(seen, pins):
                if i != last_i:
                    notes.append(f"{a.render()} showed another host key (skipped)")
                    audit.log("hostkey_skip", host=name, address=a.render(),
                              seen=vault.host_key_fingerprints(seen))
                    continue
                return Choice(a, "; ".join(notes + [f"{a.render()} answered"]), mismatch=seen)
        why = "; ".join(notes + [f"{a.render()} answered"])
        _cache_put(name, key, i, why)
        return Choice(a, why)
    raise SshError(f"gateway: {name} didn't answer on any address ({'; '.join(notes)}); check "
                   "that it is on, or ask the user", 255)


# ---------------------------------------------------------------------------
# Running ssh
# ---------------------------------------------------------------------------

# ssh's own messages, anchored at line start. The stand-in classifies only
# ssh's log (`-E <call dir>/ssh.log`, which the remote side can't write to);
# the anchors also keep remote output out of the classification where a
# captured stderr mixes both (test_login, the sudo probe).
AUTH_FAIL = re.compile(r"(?m)^(?:\S+@\S+: )?Permission denied \([a-z,-]*publickey")
RATE_LIMIT = re.compile(r"(?m)^(?:kex_exchange_identification: |ssh_exchange_identification: |"
                        r"Connection reset by \S+ port |Connection closed by \S+ port |"
                        r"read: Connection reset by peer)")
HOSTKEY_FAIL = re.compile(r"(?m)^(?:@+ WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED|"
                          r"Host key verification failed\.|No [A-Za-z0-9-]+ host key is known for )")
UNREACHABLE = re.compile(r"(?m)^ssh: (?:connect to host \S+ port [0-9]+: |Could not resolve "
                         r"hostname )")


def authfail_path(name: str) -> Path:
    return control_dir() / f"authfail-{name}"


def mark_authfail(name: str) -> None:
    with contextlib.suppress(OSError, paths.PathError):
        _write(authfail_path(name), str(time.time()))


def recent_authfail(name: str, within: float = 90.0) -> bool:
    try:
        return time.time() - float(authfail_path(name).read_text()) < within
    except (OSError, ValueError, paths.PathError):
        return False


def clear_authfail(name: str) -> None:
    with contextlib.suppress(OSError, paths.PathError):
        authfail_path(name).unlink()


def explain_failure(name: str, rc: int, err: str) -> str | None:
    """The gateway's own message for an ssh failure (exit 255), or None."""
    if rc != 255:
        return None
    if HOSTKEY_FAIL.search(err):
        return (f"gateway: {name}'s host key isn't the pinned one; don't connect. If the machine "
                f"was reinstalled, ask the user to run gate check {name}")
    if AUTH_FAIL.search(err):
        mark_authfail(name)
        return f"gateway: {name} refused Claude's key (installed? run gate check {name})"
    if RATE_LIMIT.search(err) and recent_authfail(name):
        return f"gateway: {name} is rate-limiting after failed logins; wait a minute"
    return None


class Conn:
    """A connection to one target (form host or account endpoint) for one
    stand-in call: per-call dir, generated config, agent when needed."""

    def __init__(self, target: Link, overrides: dict[str, dict[str, str]] | None = None):
        self.target = target
        self.overrides = overrides
        self.dir: Path | None = None
        self.cfg: Path | None = None
        self.agent: Agent | None = None
        self._cp: dict[str, str] = {}
        # False when the command line says ControlMaster=no (scp/sftp): this
        # call reuses a master but never starts one (_verify_cmdline sets it)
        self.starts_master = True
        self._locks: dict[str, int] = {}    # the ControlPath locks held: lock file -> fd
        # the hops (aliases) this call reaches without multiplexing: it doesn't
        # hold their lock, so it may neither start a master there nor count on one
        self.solo: frozenset[str] = frozenset()
        self._mu = threading.Lock()     # _locks and agent: the master watcher changes them too

    def __enter__(self) -> "Conn":
        self.prepare()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def prepare(self) -> Path:
        if self.cfg is not None:
            return self.cfg
        sweep_call_dirs()
        d = control_dir() / f"{CALL_PREFIX}{os.getpid()}-{secrets.token_hex(3)}"
        os.mkdir(d, 0o700)
        self.dir = d
        self.cfg = write_config(d, self.target, self.overrides, self.solo)
        return self.cfg

    @property
    def alias(self) -> str:
        return self.target.alias

    def base(self) -> list[str]:
        b = ssh_bin()
        # the system's ssh (a draining gated, the env's deleted): never a master
        no_master = ["-o", "ControlMaster=no"] if b == _system_ssh() else []
        return [b, "-F", str(self.prepare()), *no_master]

    def control_path(self, link: Link) -> str | None:
        """The hop's shared ControlPath (read once, before any solo rewrite)."""
        if not link.master:
            return None
        if link.alias not in self._cp:
            g = ssh_g(self.prepare(), [link.alias])
            cp = (g.get("controlpath") or [""])[0]
            self._cp[link.alias] = cp
        return self._cp[link.alias] or None

    def master_alive(self) -> bool:
        if not self.target.master:
            return False
        cp = self.control_path(self.target)
        if not cp or not os.path.exists(cp):
            return False
        return master_alive(self.prepare(), self.alias, cp)

    def keys(self) -> list[str]:
        return [k for link in self.target.chain() for k in link.privkeys]

    def _lock_map(self) -> dict[str, list[str]]:
        """Lock file -> the hops (aliases) whose shared ControlPath it guards."""
        out: dict[str, list[str]] = {}
        for link in self.target.chain():
            cp = self.control_path(link)
            if cp and os.path.isabs(cp) and Path(cp).parent == control_dir():
                out.setdefault(cp + ".lock", []).append(link.alias)
        return out

    def _lock_files(self) -> list[str]:
        return sorted(self._lock_map())            # one order for every call: no lock cycles

    def lock_masters(self, wait: float | None = None) -> bool:
        """Take the lock next to each master socket of the chain (blocking
        other calls that are about to start the same masters), waiting at
        most `wait` seconds (lock_wait()) in all. True if every lock is held;
        on a timeout or an error the call goes on without that lock (and
        reaches that hop on its own: ensure_agent)."""
        files = self._lock_files()
        deadline = time.monotonic() + (lock_wait() if wait is None else wait)
        got: dict[str, int] = {}
        for p in files:
            with self._mu:
                if p in self._locks:
                    continue
            try:
                fd = os.open(p, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
            except OSError:
                continue
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    got[p] = fd
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        os.close(fd)
                        break
                    time.sleep(0.05)
                except OSError:
                    os.close(fd)
                    break
        with self._mu:
            self._locks.update(got)
            return all(p in self._locks for p in files)

    def unlock_masters(self) -> None:
        """Release the master locks (closing the file drops the flock).
        Safe from the master watcher and the main thread at once."""
        with self._mu:
            fds, self._locks = list(self._locks.values()), {}
        for fd in fds:
            with contextlib.suppress(OSError):
                os.close(fd)

    def _unheld(self) -> set[str]:
        """The multiplexed hops (aliases) whose lock this call doesn't hold."""
        lm = self._lock_map()
        with self._mu:
            held = {a for p, aliases in lm.items() if p in self._locks for a in aliases}
        return {link.alias for link in self.target.chain()
                if link.master and link.alias not in held}

    def _set_solo(self, solo: set[str]) -> None:
        """Reach these hops without multiplexing (`ControlMaster no`,
        `ControlPath none` in this call's config, rewritten in place)."""
        new = frozenset(solo)
        if new == self.solo:
            return
        for link in self.target.chain():
            self.control_path(link)        # the shared paths, read while the config has them
        self.solo = new
        if self.dir is not None:
            self.cfg = write_config(self.dir, self.target, self.overrides, new)

    def owns_target(self) -> bool:
        """Does this call hold the lock of the target's ControlPath? Then no
        other call starts a master there, so a master that answers is its own."""
        if not self.target.master or self.target.alias in self.solo:
            return False
        cp = self.control_path(self.target)
        with self._mu:
            return bool(cp) and f"{cp}.lock" in self._locks

    def ensure_agent(self) -> None:
        """Get this call ready to connect. A live master of the target serves
        it: no agent, no lock. Otherwise take the ControlPath lock of each hop
        (bounded: a parallel call starting the same masters makes it wait; a
        later ssh run of this call, its agent still up, takes only the locks
        that are free at once) and reuse the target's master if one came up
        meanwhile. Else start the agent. A hop whose lock the call holds may
        get this call's master (the locks go once the target's master answers
        or ssh exits: master_watch); every other hop is reached on its own
        (_set_solo): its lock wasn't free in time, or the call is scp/sftp
        (never a master, so it keeps no lock). Such a call can't start or
        race a master there and keeps its agent until its ssh exits."""
        if self.master_alive():
            self._reuse()
            return
        fresh = self.agent is None or not self.agent.alive
        if self._lock_files():
            self.lock_masters(None if fresh else 0)
            if self.master_alive():
                self._reuse()
                return
            if not self.starts_master:
                self.unlock_masters()     # this call never starts a master: don't hold others
        self._set_solo(self._unheld())
        if not fresh:
            return
        for link in self.target.chain():
            cp = self.control_path(link)
            if cp:
                record_master(link.name, cp)
        assert self.dir is not None
        self.agent = Agent(self.dir / "agent.sock")
        self.agent.start(self.keys())

    def _reuse(self) -> None:
        """The target's master answers: this call's ssh multiplexes over it,
        with no lock and no agent (no ssh of this call runs between runs)."""
        self.unlock_masters()
        self.kill_agent()
        self._set_solo(set())

    def drop_agent_if_master(self) -> None:
        if self.agent is not None and self.master_alive():
            self.kill_agent()

    def kill_agent(self) -> None:
        with self._mu:
            agent, self.agent = self.agent, None
        if agent is not None:
            agent.close()

    def _watch_master(self, stop: threading.Event) -> None:
        delay = 0.05
        while not stop.is_set() and self.agent is not None:
            if self.master_alive():
                self.unlock_masters()      # parallel calls waiting for it reuse it now
                self.kill_agent()
                return
            stop.wait(delay)
            delay = min(delay * 1.5, 0.5)

    @contextlib.contextmanager
    def master_watch(self) -> Iterator[None]:
        """Around this call's ssh (run_child, capture): when this call holds
        the target's lock (owns_target), then once the target's master
        answers (its own: nothing else starts one there meanwhile) release the
        master locks and kill the agent, while the remote command goes on. A
        call without that lock keeps its agent until ssh exits (another
        call's master may answer while it is still logging in). When ssh has
        exited, release the locks anyway (no master came up: the next call
        starts one)."""
        stop = threading.Event()
        watcher = threading.Thread(target=self._watch_master, args=(stop,), daemon=True)
        if self.agent is not None and self.owns_target():
            watcher.start()
        try:
            yield
        finally:
            stop.set()
            self.unlock_masters()
            if watcher.is_alive():
                watcher.join(timeout=2)

    def capture(self, command: str, stdin: bytes | None = None, timeout: float = 60,
                extra: list[str] | None = None) -> subprocess.CompletedProcess:
        """Run one remote command over this connection, output captured."""
        self.ensure_agent()
        try:
            with self.master_watch():
                return subprocess.run([*self.base(), *(extra or []), "-T", "--", self.alias,
                                       command], input=stdin if stdin is not None else b"",
                                      capture_output=True, timeout=timeout, env=child_env())
        except subprocess.TimeoutExpired:
            raise SshError(f"gateway: {self.target.name} took too long to answer", 255) from None
        finally:
            self.drop_agent_if_master()

    def close(self) -> None:
        self.unlock_masters()
        self.kill_agent()
        if self.dir is not None:
            shutil.rmtree(self.dir, ignore_errors=True)
            self.dir = None
            self.cfg = None


TAIL_CAP = 262144
DRAIN_IDLE = 0.5        # after ssh exits: stop reading its stderr after this much quiet
DRAIN_MAX = 5.0         # ... or this long in all (something else holds the pipe)


def log_arg(conn: Conn) -> list[str]:
    """`-E <call dir>/ssh.log`: ssh's own messages go to a file only ssh writes
    (classified there; streamed to stderr by run_child), so the remote's
    stderr can't pose as an ssh failure, and a backgrounded master started
    with -v doesn't keep the stand-in's stderr open."""
    assert conn.dir is not None
    return ["-E", str(conn.dir / "ssh.log")]


def run_child(argv: list[str], conn: Conn, *, scrub: list[str] | None = None,
              stdin: int | None = None, log: Path | None = None) -> tuple[int, str, str]:
    """Run ssh with inherited stdin, stdout passed through (or scrubbed),
    stderr streamed through us (scrubbed when `scrub`). `log` is the `-E`
    file in argv: followed while ssh runs and copied to stderr (scrubbed).
    Kills the agent once the master is up. Signals are forwarded. Returns
    (exit code, the remote stderr seen, ssh's own log text), both capped."""
    import select
    import threading
    from . import scrub as scrubmod

    out_r = out_w = -1
    if scrub:   # our own pipe: pump() closes the read end exactly once (EPIPE -> SIGPIPE)
        out_r, out_w = os.pipe()
    try:
        proc = subprocess.Popen(argv, stdin=stdin, env=child_env(),
                                stdout=out_w if scrub else None,
                                stderr=subprocess.PIPE, bufsize=0)
    except BaseException:
        if out_r >= 0:
            os.close(out_r)
        raise
    finally:
        if out_w >= 0:
            os.close(out_w)
    tail: list[bytes] = []
    size = [0]
    ltail: list[bytes] = []
    lsize = [0]
    exited_at: list[float] = []

    def pump_err() -> None:
        sc = scrubmod.Scrubber(scrub or [])
        assert proc.stderr is not None
        fd = proc.stderr.fileno()
        quiet_since = None
        last_data = time.monotonic()
        while True:
            try:
                ready = select.select([fd], [], [], 0.1)[0]
            except InterruptedError:
                continue
            except (OSError, ValueError):
                break
            if not ready:
                # held-back bytes (a possible start of the password's forms)
                # go out after a moment of quiet: a prompt never stalls
                if sc.holding and time.monotonic() - last_data >= scrubmod.IDLE:
                    out = sc.release()
                    if out:
                        _write_fd(2, out)
                if exited_at:      # ssh is gone; whatever still holds the pipe isn't ssh
                    now = time.monotonic()
                    quiet_since = quiet_since or now
                    if now - quiet_since >= DRAIN_IDLE or now - exited_at[0] >= DRAIN_MAX:
                        break
                continue
            quiet_since = None
            try:
                chunk = os.read(fd, 65536)
            except InterruptedError:
                continue
            except OSError:
                chunk = b""
            if not chunk:
                break
            last_data = time.monotonic()
            if size[0] < TAIL_CAP:
                tail.append(chunk)
                size[0] += len(chunk)
            out = sc.feed(chunk)
            if out:
                _write_fd(2, out)
        rest = sc.flush()
        if rest:
            _write_fd(2, rest)

    stop_log = threading.Event()

    def follow_log() -> None:
        sc = scrubmod.Scrubber(scrub or [])
        f = None
        last_data = time.monotonic()
        try:
            while True:
                last = stop_log.is_set()
                if f is None and log is not None:
                    with contextlib.suppress(OSError):
                        f = open(log, "rb")
                if f is not None:
                    data = f.read()
                    if data:
                        last_data = time.monotonic()
                        if lsize[0] < TAIL_CAP:
                            ltail.append(data)
                            lsize[0] += len(data)
                        out = sc.feed(data)
                        if out:
                            _write_fd(2, out)
                    elif sc.holding and time.monotonic() - last_data >= scrubmod.IDLE:
                        out = sc.release()
                        if out:
                            _write_fd(2, out)
                if last:
                    break
                stop_log.wait(0.05)
        finally:
            if f is not None:
                f.close()
            rest = sc.flush()
            if rest:
                _write_fd(2, rest)

    err_thread = threading.Thread(target=pump_err, daemon=True)
    log_thread = threading.Thread(target=follow_log, daemon=True)
    out_thread = (threading.Thread(target=scrubmod.pump, daemon=True,
                                   args=(out_r, 1, scrubmod.Scrubber(scrub))) if scrub else None)
    old: dict[int, Any] = {}
    signalled: list[int] = []

    def fwd(signum: int, _frame: Any) -> None:
        signalled.append(signum)
        with contextlib.suppress(OSError):
            proc.send_signal(signum)

    if threading.current_thread() is threading.main_thread():
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with contextlib.suppress(OSError, ValueError):
                old[s] = signal.signal(s, fwd)
    try:
        err_thread.start()
        log_thread.start()
        if out_thread is not None:
            out_thread.start()
        with conn.master_watch():          # the locks go once the master answers
            rc = proc.wait()
            exited_at.append(time.monotonic())
        if out_thread is not None:
            # after a forwarded signal a shared master may hold the pipes until the
            # remote command ends: don't wait for that
            out_thread.join(timeout=2 if signalled else None)
        err_thread.join(timeout=DRAIN_MAX + 1)
    finally:
        stop_log.set()
        for s, h in old.items():
            with contextlib.suppress(OSError, ValueError, TypeError):
                signal.signal(s, h)
        if not err_thread.is_alive():       # never close an fd a thread may still read
            with contextlib.suppress(OSError, AttributeError):
                proc.stderr.close()  # type: ignore[union-attr]
    log_thread.join(timeout=2)
    rc = rc if rc >= 0 else 128 - rc
    return (rc, b"".join(tail).decode("utf-8", "replace"),
            b"".join(ltail).decode("utf-8", "replace"))


def _write_fd(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        try:
            n = os.write(fd, view)
        except BrokenPipeError:
            return
        except OSError:
            return
        view = view[n:]
