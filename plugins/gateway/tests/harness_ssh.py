"""Fixtures for the ssh family tests (group 'ssh'). Pure stdlib.

- Sshd: a real unprivileged sshd from the pixi env on a free 127.0.0.1
  port, with a throwaway host key and its own authorized_keys. Every key
  gets a forced command (a wrapper) that sets a known PATH (the fake sudo
  first), XDG_RUNTIME_DIR inside the test dir, and runs the command with
  /bin/sh (the user's own login shell rc can't change PATH that way); sftp
  subsystem requests go to the pixi sftp-server; git keys get a git-shell
  wrapper rooted in a repos dir. Started with -D, pid tracked, killed in
  cleanup and atexit. Remote commands never touch the real home: tests use
  absolute paths, and install/rotate use the `ssh_authorized_keys` test
  override.
- A fake remote sudo: harness.FakeSudo behind a wrapper that emulates real
  sudo's no-tty rule (SUDO_ASKPASS + DISPLAY and no /dev/tty -> askpass).
  The remote askpass answers only when its parent runs as root; the fake
  sudo isn't root, so ssh_env sets the `ssh_remote_euid` override to
  ROOT/remote-euid.sh, which reports 0 for the fake sudo's process (and the
  real effective uid for anything else).
- ssh_env(): a gateway env (harness.gateway_env) with a SHORT run dir under
  /tmp (unix socket paths must stay under 104 bytes: the master sockets and
  the agent live there), stand-in stubs that exec this file as a test entry
  (`--entry ROOT ...`), and per-test knobs in ROOT/ssh-entry.json: the
  override keywords, ancestry.is_direct's answer ("raise": it raises), whether
  git-lfs started the stand-in (`lfs_parent`), scripted pop-up answers.
- cleanup: `-O exit` every master in the run dir, kill every process whose
  command line names the run dir or the test root (agents, masters, jump
  helpers), the remote staging leftovers (`sleep 900`, by recorded process
  group), then the sshds.
"""
from __future__ import annotations

import atexit
import contextlib
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Iterator

TESTS = Path(__file__).resolve().parent
PLUGIN = TESTS.parent

if __name__ != "__main__":
    import harness  # noqa: E402  (installs the path guard)
    from harness import ENV_BIN, PY  # noqa: E402
else:  # pragma: no cover - entry mode sets its own paths below
    ENV_BIN = Path(sys.executable).parent
    PY = sys.executable

USER = None


def real_user() -> str:
    import pwd
    return pwd.getpwuid(os.getuid()).pw_name


LIBEXEC = ENV_BIN.parent / "libexec"
_LIVE: list["SshEnv"] = []
_SSHDS: list["Sshd"] = []


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def keypair(d: Path, label: str) -> tuple[str, str]:
    d.mkdir(parents=True, exist_ok=True)
    k = d / f"key-{label}"
    if not k.exists():
        subprocess.run([str(ENV_BIN / "ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-C",
                        f"test-{label}", "-f", str(k)], check=True, capture_output=True)
    return k.read_text(), (d / f"key-{label}.pub").read_text().strip()


def sq(s: Any) -> str:
    return "'" + str(s).replace("'", "'\\''") + "'"


class Sshd:
    """A real sshd on 127.0.0.1 (see the module docstring)."""

    def __init__(self, base: Path, name: str, *, sudo_password: str = "correct horse battery",
                 nopasswd: bool = False):
        self.dir = base / f"sshd-{name}"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.name = name
        self.port = free_port()
        self.ak = self.dir / "authorized_keys"
        self.ak.write_text("")
        self.log = self.dir / "sshd.log"
        self.xdg = self.dir / "xdg"
        self.xdg.mkdir(exist_ok=True)
        self.repos = self.dir / "repos"
        self.repos.mkdir(exist_ok=True)
        self.pgids = self.dir / "pgids"
        self.pgids.write_text("")
        self.wraplog = self.dir / "commands.log"
        self.wraplog.write_text("")
        subprocess.run([str(ENV_BIN / "ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-C",
                        f"host-{name}", "-f", str(self.dir / "hostkey")], check=True,
                       capture_output=True)
        self.host_key = " ".join((self.dir / "hostkey.pub").read_text().split()[:2])
        self.sudo = harness.FakeSudo(self.dir / "sudo-state", password=sudo_password,
                                     nopasswd=nopasswd, timeout=0)
        self.sudo_bin = self.dir / "sudo-bin"
        self.sudo_bin.mkdir(exist_ok=True)
        fake = f"{sq(PY)} -I -S {sq(TESTS / 'fakes' / 'fake_sudo.py')} --state {sq(self.sudo.dir)}"
        (self.sudo_bin / "sudo").write_text(
            "#!/bin/sh\n# real sudo uses the askpass by itself when there is no tty\n"
            'if [ -n "${SUDO_ASKPASS-}" ] && [ -n "${DISPLAY-}" ] && ! (: </dev/tty) 2>/dev/null; then\n'
            f'  exec {fake} -A "$@"\nfi\nexec {fake} "$@"\n')
        os.chmod(self.sudo_bin / "sudo", 0o755)
        extra = [p for p in ("/opt/local/bin", "/usr/local/bin", "/opt/homebrew/bin")
                 if os.path.isdir(p)]
        self.remote_path = ":".join([str(self.sudo_bin), str(ENV_BIN), *extra,
                                     "/usr/bin", "/bin", "/usr/sbin", "/sbin"])
        self.wrapper = self.dir / "wrapper.sh"
        self.wrapper.write_text(
            "#!/bin/sh\n"
            f"PATH={sq(self.remote_path)}; export PATH\n"
            f"XDG_RUNTIME_DIR={sq(self.xdg)}; export XDG_RUNTIME_DIR\n"
            f"ps -o pgid= -p $$ >> {sq(self.pgids)} 2>/dev/null\n"
            f"{{ printf '%s' \"${{SSH_ORIGINAL_COMMAND-}}\" | tr '\\n' '\\r'; echo; }} >> {sq(self.wraplog)}\n"
            'case "${SSH_ORIGINAL_COMMAND-}" in\n'
            '  "") echo "gwt: no command" >&2; exit 1 ;;\n'
            f"  internal-sftp|sftp) exec {sq(LIBEXEC / 'sftp-server')} ;;\n"
            "esac\n"
            'exec /bin/sh -c "$SSH_ORIGINAL_COMMAND"\n')
        os.chmod(self.wrapper, 0o755)
        self.git_wrapper = self.dir / "git-wrapper.sh"
        self.git_wrapper.write_text(
            "#!/bin/sh\n"
            f"PATH={sq(ENV_BIN)}:/usr/bin:/bin; export PATH\n"
            f'printf "git %s\\n" "${{SSH_ORIGINAL_COMMAND-}}" >> {sq(self.wraplog)}\n'
            f"cd {sq(self.repos)} || exit 1\n"
            "# like GitHub: 'owner/repo' and '/owner/repo' (ssh:// URLs) are the same repo\n"
            "c=$(printf '%s' \"${SSH_ORIGINAL_COMMAND-}\" | sed \"s#'/#'#\")\n"
            'exec git-shell -c "$c"\n')
        os.chmod(self.git_wrapper, 0o755)
        self.cfg = self.dir / "sshd_config"
        self.cfg.write_text("\n".join([
            f"Port {self.port}", "ListenAddress 127.0.0.1",
            f"HostKey {self.dir / 'hostkey'}", f"PidFile {self.dir / 'sshd.pid'}",
            f"AuthorizedKeysFile {self.ak}", "PasswordAuthentication no",
            "KbdInteractiveAuthentication no", "PubkeyAuthentication yes",
            "PermitUserEnvironment no", "PermitUserRC no", "StrictModes no",
            "Subsystem sftp internal-sftp", "LogLevel VERBOSE", "PerSourcePenalties no",
            "ClientAliveInterval 5", "ClientAliveCountMax 3", "MaxStartups 100",
            "MaxSessions 50", "LoginGraceTime 20", "AllowTcpForwarding yes", ""]))
        self.proc: subprocess.Popen | None = None

    def authorize(self, pub: str, git: bool = False) -> None:
        cmd = self.git_wrapper if git else self.wrapper
        with open(self.ak, "a") as f:
            f.write(f'command="{cmd}" {pub.strip()}\n')

    def start(self) -> "Sshd":
        self.proc = subprocess.Popen([str(ENV_BIN / "sshd"), "-D", "-f", str(self.cfg), "-E",
                                      str(self.log)], stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _SSHDS.append(self)
        deadline = time.time() + 10
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError(f"sshd {self.name} exited: {self.log.read_text()[-2000:]}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5) as s:
                    s.settimeout(1)
                    if s.recv(4) == b"SSH-":
                        return self
            except OSError:
                time.sleep(0.05)
        raise RuntimeError(f"sshd {self.name} didn't start")

    def stop(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        self.proc = None
        with contextlib.suppress(ValueError):
            _SSHDS.remove(self)

    def accepted(self) -> int:
        """How many publickey logins this sshd accepted so far."""
        try:
            return self.log.read_text().count("Accepted publickey")
        except OSError:
            return 0

    def commands(self) -> list[str]:
        text = self.wraplog.read_bytes().decode("utf-8", "replace")   # no newline translation
        return [l for l in text.split("\n") if l]                     # \r joins a command's lines

    def addr(self, user: str | None = None) -> str:
        return f"{user or real_user()}@127.0.0.1:{self.port}"


class Blackhole:
    """A listener that accepts TCP but never sends a banner."""

    def __init__(self) -> None:
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.port = self.sock.getsockname()[1]

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.sock.close()


class HoldProxy:
    """A TCP proxy in front of an sshd that can hold a login: while `hold` is
    set, a new connection's client data stops at its second chunk (the key
    exchange, before any authentication) until release(i), i counting the
    held connections in the order they got there. A connection made with
    `hold` off, and the address probe (it only reads the banner), pass."""

    def __init__(self, port: int):
        self.target = port
        self.hold = False
        self.held: list[threading.Event] = []
        self.accepted = 0          # connections accepted (for a test's failure message)
        self.trace: list[str] = []  # what happened to each connection (ditto)
        self._t0 = time.monotonic()
        self._closed = False
        self._mu = threading.Lock()
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self._acceptor = threading.Thread(target=self._accept, daemon=True)
        self._acceptor.start()

    def _accept(self) -> None:
        # Only close() ends this loop: a proxy whose accept thread died (an
        # accept error, a thread it couldn't start on a loaded machine) would
        # leave every later login waiting in the listen queue, which a test
        # sees only as "didn't reach the proxy".
        while not self._closed:
            try:
                c, _ = self.sock.accept()
            except OSError as e:
                if self._closed:
                    return
                if not self.trace or "accept failed" not in self.trace[-1]:
                    self._note(f"accept failed: {type(e).__name__} {e.errno}")
                time.sleep(0.05)
                continue
            if self._closed:          # a closed proxy never serves (see close())
                c.close()
                return
            try:
                self._serve(c)
            except Exception:  # noqa: BLE001 - keep accepting whatever one connection did
                with contextlib.suppress(OSError):
                    c.close()

    def _note(self, what: str) -> None:
        self.trace.append(f"{time.monotonic() - self._t0:.2f}s {what}")

    def _serve(self, c: socket.socket) -> None:
        cid = f"#{sum(1 for x in self.trace if ' accept ' in x) + 1}"
        self._note(f"{cid} accept (hold {'on' if self.hold else 'off'})")
        u = None
        for _ in range(3):
            try:
                u = socket.create_connection(("127.0.0.1", self.target), timeout=10)
                break
            except OSError as e:
                self._note(f"{cid} upstream connect failed: {type(e).__name__} {e.errno}")
                time.sleep(0.2)
        if u is None:
            c.close()
            return
        u.settimeout(None)
        self.accepted += 1
        gate = threading.Event()
        if not self.hold:
            gate.set()
        for args in ((c, u, gate, f"{cid} client"), (u, c, None, f"{cid} server")):
            for _ in range(100):
                try:
                    threading.Thread(target=self._pipe, args=args, daemon=True).start()
                    break
                except RuntimeError:        # can't start a thread right now: wait for one
                    time.sleep(0.05)
            else:
                self._note(f"{cid} no thread could be started")
                for x in (c, u):
                    with contextlib.suppress(OSError):
                        x.close()
                return

    def _pipe(self, a: socket.socket, b: socket.socket, gate: threading.Event | None,
              side: str = "") -> None:
        n = 0
        end = "end of data"
        try:
            while True:
                data = a.recv(65536)
                if not data:
                    break
                n += 1
                if gate is not None and n == 2 and not gate.is_set():
                    with self._mu:
                        self.held.append(gate)
                        self._note(f"{side} held as {len(self.held) - 1}")
                    gate.wait(60)
                b.sendall(data)
        except OSError as e:
            end = f"{type(e).__name__} {e.errno}"
        finally:
            self._note(f"{side} side ended after {n} chunks ({end})")
            for x in (a, b):
                with contextlib.suppress(OSError):
                    x.shutdown(socket.SHUT_RDWR)

    def state(self) -> str:
        """The listener and its accept thread, for a test's failure message."""
        def ask(f: Any) -> Any:
            try:
                return f()
            except OSError as e:
                return f"{type(e).__name__} {e.errno}"
        listening = ask(lambda: bool(self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN)))
        name = ask(self.sock.getsockname)
        fds = len(os.listdir("/proc/self/fd")) if os.path.isdir("/proc/self/fd") else -1
        return (f"listening {listening} on {name}, fd {self.sock.fileno()}, accept thread "
                f"{'alive' if self._acceptor.is_alive() else 'gone'}, {fds} fds open")

    def wait_held(self, n: int, timeout: float = 20) -> bool:
        """True once n connections are (or were) held."""
        end = time.time() + timeout
        while len(self.held) < n and time.time() < end:
            time.sleep(0.02)
        return len(self.held) >= n

    def release(self, i: int) -> None:
        self.held[i].set()

    def close(self) -> None:
        """Stop for good. On Linux close() doesn't wake a thread blocked in
        accept() on the socket: the thread stayed behind and later took a
        connection meant for another test's proxy whose listener got the same
        file descriptor number, and reset it, its own sshd being gone (the
        lock tests' "didn't reach the proxy" / "Connection reset by peer" in
        the Linux VM's full suite). shutdown() wakes it (macOS: close does),
        and the socket is closed only once the thread is gone."""
        self._closed = True
        self.hold = False
        for g in list(self.held):
            g.set()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:                  # macOS: no shutdown of a listener; close() wakes accept there
            with contextlib.suppress(OSError):
                self.sock.close()
        self._acceptor.join(timeout=5)
        with contextlib.suppress(OSError):
            self.sock.close()


# ---------------------------------------------------------------------------
# The gateway env for ssh tests
# ---------------------------------------------------------------------------


class SshEnv:
    def __init__(self, env: Any, run: Path):
        self.env = env
        self.root: Path = env.root
        self.run_dir = run
        self.sshds: list[Sshd] = []
        self.holes: list[Blackhole] = []
        self.proxies: list[HoldProxy] = []
        self.cfg: dict[str, Any] = {"override": {"run": str(run)}, "direct": True,
                                    "culprit": "make", "popup": {}}
        self.keys_dir = self.root / "keys"
        self.save_cfg()

    # -- configuration -------------------------------------------------------
    def save_cfg(self) -> None:
        (self.root / "ssh-entry.json").write_text(json.dumps(self.cfg))

    def set(self, direct: bool | str | None = None, culprit: str | None = None,
            popup: dict[str, list] | None = None, lfs_parent: bool | None = None,
            typed: bool | str | None = None, **override: Any) -> None:
        """Knobs for the stand-in subprocesses (and in-process patches).
        `typed` (ancestry.typed_by_claude) follows `direct` unless set."""
        if direct is not None:
            self.cfg["direct"] = direct
        if typed is not None:
            self.cfg["typed"] = typed
        if lfs_parent is not None:
            self.cfg["lfs_parent"] = lfs_parent
        if culprit is not None:
            self.cfg["culprit"] = culprit
        if popup is not None:
            self.cfg["popup"] = popup
            (self.root / "ssh-popup-queue.json").write_text(json.dumps(popup))
        for k, v in override.items():
            self.cfg["override"][k] = v
            _apply(self.env.o, k, v)
        self.save_cfg()

    def sshd(self, name: str = "target", **kw: Any) -> Sshd:
        s = Sshd(self.root, name, **kw).start()
        self.sshds.append(s)
        return s

    def blackhole(self) -> Blackhole:
        h = Blackhole()
        self.holes.append(h)
        return h

    def proxy(self, port: int) -> HoldProxy:
        px = HoldProxy(port)
        self.proxies.append(px)
        return px

    def key(self, label: str) -> tuple[str, str]:
        return keypair(self.keys_dir, label)

    def write_form(self, text: str) -> None:
        self.env.write_form(text)

    def approve(self) -> None:
        from gateway import consent
        consent.approve_all(self.env.form())

    def vault_edit(self) -> Any:
        from gateway import vault
        return vault.edit()

    def host(self, name: str, sshd: Sshd | None = None, key: str | None = None,
             pins: list[str] | None = None, authorize: list[Sshd] | None = None) -> tuple[str, str]:
        """Give host `name` a key (authorized on `sshd` and `authorize`) and
        pin `pins` (default: sshd's host key) in the vault."""
        from gateway import vault
        priv, pub = self.key(key or name)
        for s in ([sshd] if sshd else []) + list(authorize or []):
            s.authorize(pub)
        with vault.edit() as d:
            r = vault.host_record(d, name)
            if not any(k.get("public") == pub for k in r["keys"]):
                r["keys"].append(vault.key_record(priv, pub))
            r["host_keys"] = list(pins if pins is not None else [sshd.host_key] if sshd else [])
        return priv, pub

    def set_sudo(self, name: str, user: str, pw: str) -> None:
        from gateway import vault
        with vault.edit() as d:
            vault.set_sudo(d, name, user, pw)

    def vault(self) -> dict[str, Any]:
        from gateway import vault
        return vault.load()

    # -- running stand-ins ---------------------------------------------------
    def stub(self, name: str) -> Path:
        from gateway import paths
        return paths.bin_dir() / name

    def proc_env(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        e = self.env.subprocess_env()
        e["PATH"] = f"{self.stub('ssh').parent}:{ENV_BIN}:/opt/local/bin:/usr/local/bin:" \
                    "/usr/bin:/bin:/usr/sbin:/sbin"
        e.update(extra or {})
        return e

    def run(self, tool: str, *args: str, input: str | bytes | None = None,
            extra_env: dict[str, str] | None = None, timeout: float = 60,
            cwd: str | None = None) -> subprocess.CompletedProcess:
        """Run a stand-in stub (ssh, scp, sftp) as a subprocess. Text output."""
        data = input.encode() if isinstance(input, str) else input
        r = subprocess.run([str(self.stub(tool)), *args], input=data, capture_output=True,
                           env=self.proc_env(extra_env), timeout=timeout, cwd=cwd or str(self.root))
        return subprocess.CompletedProcess(r.args, r.returncode,
                                           r.stdout.decode("utf-8", "replace"),
                                           r.stderr.decode("utf-8", "replace"))

    def audit(self, event: str | None = None) -> list[dict[str, Any]]:
        from gateway import audit
        recs = audit.read(0)
        return [r for r in recs if event is None or r.get("event") == event]

    def popup_calls(self) -> list[dict[str, Any]]:
        p = self.root / "ssh-popup-calls.jsonl"
        if not p.exists():
            return []
        return [json.loads(l) for l in p.read_text().splitlines() if l.strip()]

    def masters(self) -> list[Path]:
        return [p for p in self.run_dir.glob("cm-*") if not p.name.endswith((".list", ".lock"))]

    def wait_for(self, fn: Any, timeout: float = 10) -> Any:
        deadline = time.time() + timeout
        while time.time() < deadline:
            v = fn()
            if v:
                return v
            time.sleep(0.05)
        return fn()

    # -- teardown ------------------------------------------------------------
    def leftovers(self) -> list[str]:
        """Processes still naming the run dir or the test root."""
        out = subprocess.run(["ps", "-ax", "-o", "pid=,command="], capture_output=True,
                             text=True).stdout
        marks = (str(self.run_dir), str(self.root), str(self.root.resolve()))
        res = []
        for line in out.splitlines():
            pid, _, cmd = line.strip().partition(" ")
            if pid.isdigit() and int(pid) != os.getpid() and any(m in cmd for m in marks):
                if "ps -ax" in cmd:
                    continue
                res.append(line.strip())
        return res

    def cleanup(self) -> None:
        ssh = str(ENV_BIN / "ssh")
        for sock in self.masters():
            with contextlib.suppress(Exception):
                subprocess.run([ssh, "-F", "/dev/null", "-S", str(sock), "-O", "exit", "x"],
                               capture_output=True, timeout=10)
        time.sleep(0.1)
        for line in self.leftovers():
            pid = int(line.split()[0])
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGTERM)
        # remote staging leftovers: `sleep 900` in the recorded process groups
        pg = set()
        for s in self.sshds:
            with contextlib.suppress(OSError):
                pg |= {int(x) for x in s.pgids.read_text().split() if x.strip().isdigit()}
        if pg:
            out = subprocess.run(["ps", "-ax", "-o", "pid=,pgid=,command="], capture_output=True,
                                 text=True).stdout
            for line in out.splitlines():
                parts = line.split(None, 2)
                if len(parts) == 3 and parts[1].isdigit() and int(parts[1]) in pg and (
                        parts[2].startswith("sleep 900") or "mktemp -d" in parts[2]):
                    with contextlib.suppress(OSError):
                        os.kill(int(parts[0]), signal.SIGTERM)
        for s in self.sshds:
            s.stop()
        for h in self.holes:
            h.close()
        for px in self.proxies:
            px.close()
        time.sleep(0.05)
        for line in self.leftovers():
            with contextlib.suppress(OSError):
                os.kill(int(line.split()[0]), signal.SIGKILL)
        shutil.rmtree(self.run_dir, ignore_errors=True)


# tests only: the fake sudo (python running fake_sudo.py) stands in for the
# setuid-root sudo the remote askpass insists on as its parent.
REMOTE_EUID = """#!/bin/sh
case "$(/bin/ps -o command= -p "$1" 2>/dev/null)" in
  *fake_sudo.py*) echo 0 ;;
  *) /bin/ps -o uid= -p "$1" 2>/dev/null ;;
esac
"""


@contextlib.contextmanager
def ssh_env(**kw: Any) -> Iterator[SshEnv]:
    from gateway import envfile
    run = Path(tempfile.mkdtemp(prefix="gws-", dir="/tmp"))
    os.chmod(run, 0o700)
    senv = None
    try:
        with harness.gateway_env(run=run, **kw) as env:
            env.o.entry = [PY, "-I", "-S", *harness.PYX, str(TESTS / "harness_ssh.py"), "--entry",
                           str(env.root)]
            senv = SshEnv(env, run)
            _LIVE.append(senv)
            envfile.write_stubs(envfile.stand_ins())
            euid = env.root / "remote-euid.sh"
            euid.write_text(REMOTE_EUID)
            os.chmod(euid, 0o755)
            senv.set(ssh_remote_euid=str(euid))
            with inprocess(senv):
                try:
                    yield senv
                finally:
                    senv.cleanup()
    finally:
        if senv is not None and senv in _LIVE:
            _LIVE.remove(senv)
        shutil.rmtree(run, ignore_errors=True)


@atexit.register
def _cleanup_all() -> None:
    for s in list(_LIVE):
        with contextlib.suppress(Exception):
            s.cleanup()
    for d in list(_SSHDS):
        with contextlib.suppress(Exception):
            d.stop()


# ---------------------------------------------------------------------------
# Patching ancestry and popup (in-process and in the entry)
# ---------------------------------------------------------------------------


class FakePopup:
    """Scripted pop-up answers from ROOT/ssh-popup-queue.json
    ({"hostkey": ["ok", ...], "secret": [["ok", "value"], ...]}), with the
    landed popup.py signatures and effects: on_ok/store run on OK, verify
    re-asks up to 3 times, "stillopen" raises popup.StillOpen after printing
    the still-open line, "unavailable" prints the standard line (the real
    broker does), reenter() runs the secret inline and returns the stale
    line. Every call is logged to ROOT/ssh-popup-calls.jsonl. No answer
    left: "unavailable"."""

    def __init__(self, root: Path):
        self.root = Path(root)

    def _log(self, rec: dict[str, Any]) -> None:
        with open(self.root / "ssh-popup-calls.jsonl", "a") as f:
            f.write(json.dumps(rec) + "\n")

    def _next(self, kind: str) -> Any:
        q = self.root / "ssh-popup-queue.json"
        try:
            d = json.loads(q.read_text())
        except (OSError, ValueError):
            d = {}
        items = d.get(kind) or []
        if not items:
            return None
        v = items.pop(0)
        d[kind] = items
        q.write_text(json.dumps(d))
        return v

    def _special(self, outcome: str, entry: str, what: str) -> None:
        from gateway import popup
        if outcome == "stillopen":
            msg = popup.still_open_message(entry)
            print(msg, file=sys.stderr, flush=True)
            raise popup.StillOpen(entry, msg)
        if outcome == "unavailable":
            print(popup.message(outcome, entry, what), file=sys.stderr, flush=True)

    def hostkey(self, entry: str, old: list[str], new: list[str], *, address: str | None = None,
                known: bool | None = None, on_ok: Any = None, lazy: bool = True) -> str:
        v = self._next("hostkey") or "unavailable"
        self._log({"kind": "hostkey", "entry": entry, "old": list(old), "new": list(new),
                   "address": address, "known": known, "outcome": v})
        self._special(v, entry, "host key")
        if v == "ok" and on_ok is not None:
            on_ok()
        return v

    def secret(self, entry: str, what: str, prompt: str, verify: Any = None, *,
               store: Any = None, load: Any = None, lazy: bool = True,
               detail: dict | None = None, wait: bool = True, check: dict | None = None,
               remember: bool | None = None, target: str | None = None) -> tuple[str, Any]:
        for _ in range(3):
            v = self._next("secret") or ["unavailable", None]
            outcome, value = v[0], v[1]
            forget = len(v) > 2 and v[2] == "forget"     # the person unticked "Remember it"
            if len(v) > 2 and isinstance(v[2], dict) and v[2].get("write"):
                path, text = v[2]["write"]                # the form edited while the dialog was open
                Path(path).write_text(text)
            rec: dict[str, Any] = {"kind": "secret", "entry": entry, "what": what,
                                   "prompt": prompt, "outcome": outcome, "detail": detail,
                                   "check": check, "remember": remember}
            if outcome != "ok":
                self._log(rec)
                self._special(outcome, entry, what)
                return outcome, None
            if value is None:        # ["ok", null]: this request joined another's pop-up
                rec["joined"] = True
                self._log(rec)
                return "ok", (load() if load is not None else None)
            if verify is not None:
                ok, msg = verify(value)
                rec.update(verified=bool(ok), message=msg)
                self._log(rec)
                if not ok:
                    continue
            else:
                self._log(rec)
            if store is not None and not (remember is not None and forget):
                store(value)
            return "ok", value
        return "failed", None

    def reenter(self, entry: str, what: str, prompt: str, verify: Any = None, *,
                store: Any = None, detail: dict | None = None, check: dict | None = None) -> str:
        from gateway import popup
        self._log({"kind": "reenter", "entry": entry, "what": what, "check": check})
        try:
            self.secret(entry, what, prompt, verify, store=store, detail=detail, check=check)
        except popup.StillOpen:
            pass
        return popup.stale_message(entry, what)


def patch_modules(root: Path, cfg: dict[str, Any]) -> list[tuple[Any, str, Any]]:
    """Patch ancestry.is_direct and the pop-ups; returns what to restore."""
    from gateway import ancestry, popup
    fp = FakePopup(root)
    saved = [(ancestry, "is_direct", ancestry.is_direct),
             (ancestry, "typed_by_claude", ancestry.typed_by_claude), (popup, "hostkey", popup.hostkey),
             (popup, "secret", popup.secret), (popup, "reenter", getattr(popup, "reenter", None))]

    def is_direct(tool: str, entry_scripts: bool = False) -> tuple[bool, str]:
        c = json.loads((Path(root) / "ssh-entry.json").read_text())
        if c.get("direct") == "raise":
            raise RuntimeError("ancestry walk failed")
        d = bool(c.get("direct", True))
        return (d or entry_scripts), ("" if d else str(c.get("culprit", "make")))

    real_typed = getattr(ancestry.typed_by_claude, "_real", ancestry.typed_by_claude)

    def typed_by_claude() -> tuple[bool, str]:
        # "typed" defaults to "direct": a test that makes the caller indirect
        # makes it untyped too; `typed=False` alone models git/rsync/scp/sftp
        # (direct for credentials, but not a command Claude typed); "real"
        # walks the real process tree (the test sets CLAUDE_PID).
        c = json.loads((Path(root) / "ssh-entry.json").read_text())
        t = c.get("typed", c.get("direct", True))
        if t == "real":
            return real_typed()
        if t == "raise":
            raise RuntimeError("ancestry walk failed")
        t = bool(t)
        return t, ("" if t else str(c.get("culprit", "make")))

    def lfs_parent() -> bool:
        c = json.loads((Path(root) / "ssh-entry.json").read_text())
        return bool(c.get("lfs_parent", False))

    from gateway import ssh
    saved.append((ssh, "_started_by_git_lfs", ssh._started_by_git_lfs))
    ssh._started_by_git_lfs = lfs_parent
    ancestry.is_direct = is_direct
    typed_by_claude._real = real_typed  # type: ignore[attr-defined]
    ancestry.typed_by_claude = typed_by_claude
    popup.hostkey = fp.hostkey
    popup.secret = fp.secret
    popup.reenter = fp.reenter
    return saved


def _apply(o: Any, k: str, v: Any) -> None:
    if k != "extra" and hasattr(o, k):
        setattr(o, k, v)
    else:
        o.extra[k] = v


@contextlib.contextmanager
def inprocess(senv: SshEnv) -> Iterator[None]:
    saved = patch_modules(senv.root, senv.cfg)
    for k, v in senv.cfg["override"].items():
        if k != "run":
            _apply(senv.env.o, k, v)
    try:
        yield
    finally:
        for mod, attr, val in saved:
            setattr(mod, attr, val)


# ---------------------------------------------------------------------------
# Entry mode: the stand-in stubs exec `python -I -S harness_ssh.py --entry ROOT ...`
# ---------------------------------------------------------------------------


def _entry(argv: list[str]) -> int:
    root = Path(argv[0])
    sys.path.insert(0, str(PLUGIN / "src"))
    sys.path.insert(0, str(PLUGIN))
    from gateway import testing
    cfg = json.loads((root / "ssh-entry.json").read_text())
    kw = dict(cfg.get("override") or {})
    with testing.override(root, **kw):
        patch_modules(root, cfg)
        import run
        mode = argv[1] if len(argv) > 1 else ""
        return int(run.dispatch(mode, argv[2:]) or 0)


if __name__ == "__main__":
    if sys.argv[1:2] == ["--entry"]:
        raise SystemExit(_entry(sys.argv[2:]))
    print("harness_ssh.py: test fixtures; run the tests with tests/run_tests.py", file=sys.stderr)
    raise SystemExit(2)
