"""Fixtures for the gateway daemon (gated) tests: a real daemon in a test root.

- daemon_env(): a gateway env (harness.gateway_env) with a SHORT run dir under
  /tmp (the socket path must stay under 104 bytes), test knobs in
  ROOT/gated-test.json (fast ticks, the test routes and test entry points on
  unless asked otherwise) and the daemon started through `run.py --test gated
  start` (GATEWAY_TEST_ROOT, GATEWAY_TEST_RUN). Cleanup stops it and kills
  anything still naming the run dir or the test root.
- FakeClaude: tests/fakes/fake_claude.py run by a copy of the env's python
  named `claude` (the kernel then reports Claude Code's executable name). It
  registers on the UI plane from its own pid and runs children (stand-ins,
  probes) below itself, as Claude Code does.
- named_python(): a copy of the env's python under another name (macOS signs
  it again; a lib/ link keeps it working where python is linked to its lib);
  python_at(): the same at a given prefix (a data folder's env layout).
- probe_root(): a folder with a run.py that only asks the daemon one thing
  (GW_PROBE_* variables) and a .claude-plugin/plugin.json naming "gate" (or
  another name). Inside the test root it is a test entry (DaemonEnv.probe puts
  the test root before the mode); as a sibling version folder of a plugin
  copy in a cache layout (plugin_copy) it is what an updated plugin's run.py
  looks like to the daemon.
- plugin_copy() / DaemonEnv.start_from(): the plugin's code with a chosen
  version at <root>/cfg/plugins/cache/gateway/gate/<version> (Claude Code's
  plugin cache layout), and a daemon started from it.
"""
from __future__ import annotations

import atexit
import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator

import harness as H

TESTS = H.TESTS
PY = H.PY
ENV_PREFIX = Path(sys.executable).resolve().parents[1]
DEFAULT_KNOBS = {"tick": 0.1, "test_routes": True, "test_entries": True}

_BIN_DIR: list[Path] = []


def _bin_base() -> Path:
    if not _BIN_DIR:
        d = Path(tempfile.mkdtemp(prefix="gwbin-", dir=H.tmp_base()))
        atexit.register(shutil.rmtree, d, True)
        _BIN_DIR.append(d)
    return _BIN_DIR[0]


def named_python(name: str, folder: str | None = None) -> Path:
    """A copy of this env's python at <tmp>/<folder or name-py>/bin/<name>
    (cached; made again when it was deleted)."""
    return python_at(_bin_base() / (folder or f"{name}-py"), name)


def python_at(d: Path, name: str = "python3.12") -> Path:
    """A copy of this env's python at <d>/bin/<name>, with <d>/lib linked to
    the env's lib (cached while it exists)."""
    exe = d / "bin" / name
    if exe.exists():
        return exe
    (d / "bin").mkdir(parents=True, exist_ok=True)
    real = Path(os.path.realpath(sys.executable))
    shutil.copyfile(real, exe)
    os.chmod(exe, 0o755)
    lib = d / "lib"
    if not lib.exists():
        lib.symlink_to(ENV_PREFIX / "lib")
    if sys.platform == "darwin":
        subprocess.run(["/usr/bin/codesign", "-s", "-", "-f", str(exe)], capture_output=True,
                       timeout=60, check=True)
    # A new binary's first exec is slow on macOS (~0.5 s native; under Rosetta
    # the copy is translated first, 1.5-2.5 s): pay it here, where the copy is
    # made, never inside a test's timed window (a daemon's idle_exit).
    subprocess.run([str(exe), "-I", "-S", *H.PYX, "-c", ""], env=py_env(),
                   capture_output=True, timeout=120)
    return exe


def py_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    e = {"PATH": "/usr/bin:/bin", "PYTHONHOME": str(ENV_PREFIX), "LANG": "C.UTF-8"}
    e.update(extra or {})
    return e


class FakeClaude:
    def __init__(self, de: "DaemonEnv", *, register: bool = True, surface: str | None = "terminal",
                 session: str = "s-test", exe: Path | None = None, argv: list[str] | None = None,
                 cwd: Path | None = None):
        """argv: the fake's whole command line instead of `<exe> -S -s
        fake_claude.py` (npm's `node <prefix>/bin/claude`: a copy of python
        named node running a copy of fake_claude.py as cli.js)."""
        self.de = de
        self.exe = Path(argv[0]) if argv else (exe or named_python("claude"))
        cmd = [str(a) for a in argv] if argv else \
            [str(self.exe), "-S", "-s", str(TESTS / "fakes" / "fake_claude.py")]
        self.p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
                                  env=py_env({"PYTHONNOUSERSITE": "1"} if argv else None),
                                  start_new_session=True, cwd=str(cwd) if cwd else None)
        line = self.p.stdout.readline()
        self.pid = int(json.loads(line)["pid"])
        de.claudes.append(self)
        self.session = session
        if register:
            st, body = self.http("POST", "/ui/register", {"claude_pid": self.pid, "session_id": session,
                                                          "surface": surface, "version": "2.1.301"})
            assert st == 200, (st, body)

    def _ask(self, req: dict[str, Any]) -> dict[str, Any]:
        assert self.p.stdin and self.p.stdout
        self.p.stdin.write(json.dumps(req) + "\n")
        self.p.stdin.flush()
        line = self.p.stdout.readline()
        assert line, "the fake claude died"
        return json.loads(line)

    def http(self, method: str, path: str, body: Any = None) -> tuple[int, dict[str, Any]]:
        r = self._ask({"op": "http", "method": method, "path": path, "body": body,
                       "sock": str(self.de.sock)})
        return r["status"], r["body"]

    def run(self, argv: list[str], env: dict[str, str] | None = None, input: str | None = None,
            timeout: float = 60, cwd: str | None = None) -> subprocess.CompletedProcess:
        r = self._ask({"op": "run", "argv": [str(a) for a in argv], "env": env, "input": input,
                       "timeout": timeout, "cwd": cwd})
        return subprocess.CompletedProcess(argv, r["rc"], r["stdout"], r["stderr"])

    def asked(self, tool: str, argv: list[str], entries: list[tuple[str, str]],
              cwd: str | None = None) -> None:
        """The approval hook's record that this Claude Code asked about `TOOL
        ARGV` typed in `cwd` (the fake's own folder by default: this test's),
        as hooks_bash writes it when it answers "ask" (asks.record; lead
        decision 19.14). A stand-in it runs passes an "ask" only with one."""
        from gateway import ancestry, asks
        start = ancestry.started_at(self.pid)
        asks.record(tool, f"{self.pid}@{int(start) if start else 0}", cwd or os.getcwd(),
                    [str(a) for a in argv], entries)

    def spawn(self, argv: list[str], env: dict[str, str] | None = None) -> int:
        return int(self._ask({"op": "spawn", "argv": [str(a) for a in argv], "env": env})["pid"])

    def wait(self, pid: int, timeout: float = 60) -> subprocess.CompletedProcess:
        r = self._ask({"op": "wait", "pid": pid, "timeout": timeout})
        return subprocess.CompletedProcess([], r["rc"], r["stdout"], r["stderr"])

    def close(self) -> None:
        if self.p.poll() is None:
            with contextlib.suppress(Exception):
                assert self.p.stdin
                self.p.stdin.write(json.dumps({"op": "exit"}) + "\n")
                self.p.stdin.flush()
            try:
                self.p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.p.kill()
                self.p.wait()
        for f in (self.p.stdin, self.p.stdout):
            with contextlib.suppress(Exception):
                f.close()


PROBE = '''import http.client, json, os, socket, sys
class U(http.client.HTTPConnection):
    def __init__(s, p):
        super().__init__("gated", timeout=30); s._p = p
    def connect(s):
        k = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); k.connect(s._p); s.sock = k
c = U(os.environ["GW_PROBE_SOCK"])
b = os.environ.get("GW_PROBE_BODY")
c.request(os.environ.get("GW_PROBE_METHOD", "POST"), os.environ["GW_PROBE_PATH"],
          body=b.encode() if b else None, headers={"Connection": "close"})
r = c.getresponse()
print(json.dumps({"status": r.status, "body": json.loads(r.read() or b"{}")}))
'''


def probe_root(base: Path, plugin_name: str = "gate", folder: str | None = None) -> Path:
    """A folder (base/probe-<name>, or base/<folder>) with a probe run.py and
    a plugin.json naming `plugin_name`."""
    d = base / (folder or f"probe-{plugin_name}")
    (d / ".claude-plugin").mkdir(parents=True, exist_ok=True)
    (d / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": plugin_name,
                                                                  "version": "0.0.1"}))
    (d / "run.py").write_text(PROBE)
    return d


def plugin_copy(root: Path, version: str, plugin: str = "gate") -> Path:
    """The plugin's code (src, run.py, plugin.json with `version`) at
    <root>/cfg/plugins/cache/gateway/<plugin>/<version>: Claude Code's plugin
    cache layout, where the versions before and after an update are sibling
    folders."""
    dst = root / "cfg" / "plugins" / "cache" / "gateway" / plugin / version
    if (dst / "run.py").exists():
        return dst
    shutil.copytree(H.PLUGIN / "src", dst / "src", ignore=shutil.ignore_patterns("__pycache__"),
                    copy_function=shutil.copyfile)
    shutil.copyfile(H.PLUGIN / "run.py", dst / "run.py")
    (dst / ".claude-plugin").mkdir()
    pj = json.loads((H.PLUGIN / ".claude-plugin" / "plugin.json").read_text())
    pj["version"] = version
    (dst / ".claude-plugin" / "plugin.json").write_text(json.dumps(pj))
    for dp, dn, fn in os.walk(dst):           # a read-only checkout copies read-only
        for n in dn + fn:
            q = os.path.join(dp, n)
            os.chmod(q, os.stat(q).st_mode | 0o200)
    return dst


def plugin_version() -> str:
    return json.loads((H.PLUGIN / ".claude-plugin" / "plugin.json").read_text())["version"]


class DaemonEnv:
    def __init__(self, env: H.GatewayEnv, run: Path):
        self.env = env
        self.root = env.root
        self.run = run
        self.sock = run / "gated.sock"
        self.claudes: list[FakeClaude] = []
        self.knobs_data: dict[str, Any] = {}
        self.plugin = H.PLUGIN            # the plugin copy the daemon was last started from

    # -- knobs and control ---------------------------------------------------
    def knobs(self, **k: Any) -> None:
        self.knobs_data.update(k)
        p = self.root / "gated-test.json"
        p.write_text(json.dumps(self.knobs_data))
        os.chmod(p, 0o600)

    def extra_env(self) -> dict[str, str]:
        return {"GATEWAY_TEST_RUN": str(self.run)}

    def gated(self, *args: str, timeout: float = 60) -> subprocess.CompletedProcess[str]:
        return H.run_py(self.env, "--test", "gated", *args, extra_env=self.extra_env(),
                        timeout=timeout)

    def start(self) -> dict[str, Any]:
        r = self.gated("start")
        assert r.returncode == 0, (r.stdout, r.stderr)
        return json.loads(r.stdout)

    def stop(self) -> None:
        """`gated stop` from the plugin copy the daemon was started from (a
        daemon takes /local/stop only from its own plugin's run.py)."""
        if self.plugin == H.PLUGIN:
            self.gated("stop")
            return
        env = self.env.subprocess_env(self.extra_env())
        subprocess.run([PY, "-I", "-S", *H.PYX, str(self.plugin / "run.py"), "--test", "gated",
                        "stop"], env=env, capture_output=True, text=True, timeout=60,
                       cwd=str(self.root))

    def health(self) -> dict[str, Any] | None:
        from gateway.daemon import client
        return client.health(sock=self.sock)

    def call(self, method: str, path: str, body: Any = None) -> tuple[int, dict[str, Any]]:
        """A request from the test process itself (no registered session above it)."""
        from gateway.daemon import client
        try:
            return 200, client.call(method, path, body, sock=self.sock)
        except client.DaemonError as e:
            return e.status, e.body

    def claude(self, **kw: Any) -> FakeClaude:
        return FakeClaude(self, **kw)

    def probe(self, fc: FakeClaude, script: Path, mode: list[str], path: str, body: Any = None,
              python: Path | None = None, method: str = "POST", test_entry: bool | None = None,
              options: tuple[str, ...] = ("-I", "-S"), through: list[str] | None = None
              ) -> tuple[int, dict[str, Any]]:
        """Ask the daemon from a probe process below the fake claude:
        `<python> -I -S <script> [ROOT] MODE...`. While the test_entries knob is
        on, a script inside the test root is a test entry (the test root goes
        before the mode); with it off, argv is production's. test_entry
        overrides that. `through`: a program that runs the probe (argv prefix)."""
        env = py_env({"GW_PROBE_SOCK": str(self.sock), "GW_PROBE_PATH": path,
                      "GW_PROBE_METHOD": method})
        if body is not None:
            env["GW_PROBE_BODY"] = json.dumps(body)
        if python is None:
            env.pop("PYTHONHOME")
        if test_entry is None:
            test_entry = bool(self.knobs_data.get("test_entries")) and \
                str(Path(script).resolve()).startswith(str(self.root.resolve()) + os.sep)
        root = [str(self.root)] if test_entry else []
        r = fc.run([*(through or []), str(python or PY), *options, str(script), *root, *mode], env=env)
        assert r.returncode == 0, (r.stdout, r.stderr)
        out = json.loads(r.stdout)
        return out["status"], out["body"]

    def start_from(self, plugin: Path) -> dict[str, Any]:
        """`<plugin>/run.py --test gated start` (a daemon running that copy's
        code, or the running one's answer)."""
        env = self.env.subprocess_env(self.extra_env())
        r = subprocess.run([PY, "-I", "-S", *H.PYX, str(plugin / "run.py"), "--test", "gated", "start"],
                           env=env, capture_output=True, text=True, timeout=60, cwd=str(self.root))
        assert r.returncode == 0, (r.stdout, r.stderr)
        self.plugin = plugin
        return json.loads(r.stdout)

    def gated_from(self, plugin: Path, *args: str) -> dict[str, Any]:
        """`<plugin>/run.py --test gated ARGS...`, its JSON line."""
        env = self.env.subprocess_env(self.extra_env())
        r = subprocess.run([PY, "-I", "-S", *H.PYX, str(plugin / "run.py"), "--test", "gated", *args],
                           env=env, capture_output=True, text=True, timeout=60, cwd=str(self.root))
        assert r.returncode == 0, (r.stdout, r.stderr)
        return json.loads(r.stdout)

    def wrap(self, passphrase: str) -> None:
        """Set the vault passphrase through the test route (key.txt goes)."""
        st, body = self.call("POST", "/test/vault/passphrase", {"passphrase": passphrase})
        assert st == 200 and body["vault"] == "unlocked", (st, body)

    def unlock(self, passphrase: str) -> tuple[int, dict[str, Any]]:
        return self.call("POST", "/test/vault/unlock", {"passphrase": passphrase})

    def daemon_pid(self) -> int | None:
        h = self.health()
        return int(h["pid"]) if h else None

    def log(self) -> str:
        from gateway import paths
        p = paths.gated_log()
        return p.read_text(errors="replace") if p.exists() else ""

    def wait_for(self, fn: Any, timeout: float = 10) -> Any:
        deadline = time.time() + timeout
        while time.time() < deadline:
            v = fn()
            if v:
                return v
            time.sleep(0.05)
        return fn()

    # -- teardown ------------------------------------------------------------
    def leftovers(self) -> list[tuple[int, str]]:
        out = subprocess.run(["ps", "-ax", "-o", "pid=,command="], capture_output=True,
                             text=True).stdout
        marks = (str(self.run), str(self.root))
        res = []
        for line in out.splitlines():
            pid, _, cmd = line.strip().partition(" ")
            if pid.isdigit() and int(pid) != os.getpid() and any(m in cmd for m in marks) \
                    and "ps -ax" not in cmd:
                res.append((int(pid), cmd))
        return res

    def cleanup(self) -> None:
        for c in self.claudes:
            c.close()
        with contextlib.suppress(Exception):
            if self.sock.exists():
                self.stop()
        for pid, _cmd in self.leftovers():
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGTERM)
        deadline = time.time() + 3
        while self.leftovers() and time.time() < deadline:
            time.sleep(0.05)
        for pid, _cmd in self.leftovers():
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGKILL)


@contextlib.contextmanager
def attach(env: H.GatewayEnv, run: Path, knobs: dict[str, Any] | None = None,
           start: bool = True) -> Iterator[DaemonEnv]:
    """A daemon for an env another harness made (its run dir must be short)."""
    de = DaemonEnv(env, run)
    de.knobs(**{**DEFAULT_KNOBS, **(knobs or {})})
    try:
        if start:
            de.start()
        yield de
    finally:
        de.cleanup()


# A test entry point for stand-ins (and askpass): applies testing.override
# with ROOT/entry-knobs.json (run dir, tools such as the fake sudo), then runs
# run.py's dispatcher, as the stubs do. GW_DUMP=1 prints, instead, which
# secret slots the scoped vault holds (class, entry, real or redacted, a
# sha256 prefix of the value): never a value.
DRIVER = """import hashlib, json, os, sys
sys.pycache_prefix = {pyc!r}
sys.path.insert(0, {src!r})
sys.path.insert(0, {plugin!r})
from gateway import testing
import run
root, mode, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
with open(os.path.join(root, "entry-knobs.json")) as f:
    kw = json.load(f)
with testing.override(root, **kw):
    if os.environ.get("GW_OPEN_OWN"):
        import hashlib
        from gateway import paths, transfer
        paths.ENTRY_MODE = mode
        try:
            got = transfer.decrypt_own(open(os.environ["GW_OPEN_OWN"], "rb").read())
            print(json.dumps({{"sha": hashlib.sha256(got).hexdigest()[:16]}}))
        except Exception as e:
            print(json.dumps({{"error": type(e).__name__, "message": str(e)}}))
        raise SystemExit(0)
    if os.environ.get("GW_ASK"):
        # A gateway program that asks the user (popup.py's broker, native
        # dialogs): GW_ASK = {{"kind", "entry", "what", "ok": [sha16 of the values
        # the check accepts], "remember", "check", "options"}}; prints
        # {{"outcome", "sha"}} (a sha256 prefix of what arrived, never a value)
        # and, with "store", writes the sha16 of the stored value to that file.
        from gateway import paths, popup
        paths.ENTRY_MODE = mode
        spec = json.loads(os.environ["GW_ASK"])
        sha = lambda v: hashlib.sha256(v.encode()).hexdigest()[:16] if isinstance(v, str) else None
        kind = spec.get("kind", "secret")
        try:
            if kind == "secret":
                ok = spec.get("ok")
                verify = (lambda v: (sha(v) in ok, "the test's check said no")) if ok else None
                store = None
                if spec.get("store"):
                    def store(v):
                        with open(spec["store"], "w") as f:
                            f.write(sha(v))
                oc, val = popup.secret(spec.get("entry", "build"), spec.get("what", "sudo password"),
                                       spec.get("prompt", "The test asks."), verify, store=store,
                                       lazy=False, remember=spec.get("remember"),
                                       check=spec.get("check"), pem=bool(spec.get("pem")))
                print(json.dumps({{"outcome": oc, "sha": sha(val)}}))
            elif kind == "consent":
                oc = popup.consent(spec.get("entry", "build"), spec.get("lines", ["ssh: true"]))
                print(json.dumps({{"outcome": oc}}))
            elif kind == "choice":
                oc, val = popup.choice(spec.get("entry", "build"), "Pick one.", spec["options"])
                print(json.dumps({{"outcome": oc, "choice": val}}))
            elif kind == "hostkey":
                oc = popup.hostkey(spec.get("entry", "build"), spec["old"], spec["new"], lazy=False)
                print(json.dumps({{"outcome": oc}}))
        except popup.StillOpen:
            print(json.dumps({{"outcome": "still-open"}}))
        raise SystemExit(0)
    if os.environ.get("GW_DUMP"):
        from gateway import paths, vault
        from gateway.daemon import broker
        paths.ENTRY_MODE = "shim " + rest[0] if mode == "shim" else mode
        try:
            data = vault.load()
        except vault.VaultError as e:
            print(json.dumps({{"error": type(e).__name__, "message": str(e)}}))
            raise SystemExit(0)
        out = [[c, list(e), "redacted" if vault.is_redacted(d[k]) else "real",
                hashlib.sha256(d[k].encode()).hexdigest()[:16]] for c, e, d, k in broker.slots(data)]
        print(json.dumps({{"slots": out}}))
        raise SystemExit(0)
    raise SystemExit(run.dispatch(mode, rest))
"""


def write_driver(env: H.GatewayEnv, run: Path, **override: Any) -> Path:
    """ROOT/drivers/gw_entry.py (DRIVER) and its knobs; the askpass stub in the
    data folder's bin/ points at it too."""
    from gateway import paths
    d = env.root / "drivers"
    d.mkdir(exist_ok=True)
    drv = d / "gw_entry.py"
    drv.write_text(DRIVER.format(src=str(H.PLUGIN / "src"), plugin=str(H.PLUGIN), pyc=H.PYC))
    knobs = {"run": str(run), **override}
    (env.root / "entry-knobs.json").write_text(json.dumps(knobs))
    paths.bin_dir().mkdir(parents=True, exist_ok=True)
    ap = paths.bin_dir() / "gate-askpass"
    ap.write_text(f"#!/bin/sh\nexec {PY!r} -I -S {str(drv)!r} {str(env.root)!r} askpass\n")
    os.chmod(ap, 0o755)
    return drv


def sha16(v: str) -> str:
    import hashlib
    return hashlib.sha256(v.encode()).hexdigest()[:16]


def full_vault(passphrase: str) -> dict[str, Any]:
    """The whole vault, read by the test with the passphrase it chose (unwrap
    key.wrapped, decrypt vault.age): never through the daemon."""
    from gateway import agepass, paths
    from gateway.daemon import broker
    ident = broker.read_identity(agepass.decrypt(paths.wrapped_key_path().read_bytes(),
                                                 passphrase).decode())
    return json.loads(broker.decrypt_file(ident, paths.vault_path()))


@contextlib.contextmanager
def daemon_env(knobs: dict[str, Any] | None = None, start: bool = True,
               **kw: Any) -> Iterator[DaemonEnv]:
    run = Path(tempfile.mkdtemp(prefix="gwd-", dir="/tmp"))
    os.chmod(run, 0o700)
    try:
        with H.gateway_env(run=run, **kw) as env:
            de = DaemonEnv(env, run)
            de.knobs(**{**DEFAULT_KNOBS, **(knobs or {})})
            try:
                if start:
                    de.start()
                yield de
            finally:
                de.cleanup()
    finally:
        shutil.rmtree(run, ignore_errors=True)
