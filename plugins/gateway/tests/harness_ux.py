"""Fixtures for group 'ux' tests (popup, dialog, gate_setup, transfer, web, MCP, hooks).

- ux_env(): harness.gateway_env + a FakeDialog wired through
  testing.override(dialog=...), short pop-up waits, helper tracking (every
  detached helper is waited for / killed when the test ends).
- setup(env, form_text, approve=True): a form, an empty vault, everything approved.
- fake_ready_env(env): a "built" pixi env (symlink to this python) so
  hooks/launch.sh execs run.py (always with --test).
- run_sh(env, script, payload, test=True): run one of the hooks/*.sh prefilters.
- HTTPFixture: local HTTP(S) servers recording every request.
- patch(obj, name, value): monkeypatch with restore (a context manager).
- ux_entry_cmd(env): `python harness_ux.py --entry ROOT ...`, a test entry
  that runs run.py under testing.override(ROOT, dialog="none", ...).
"""
from __future__ import annotations

import contextlib
import http.server
import json
import os
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path
from typing import Any, Iterator


def _entry() -> int:
    """Test entry: `python -I -S harness_ux.py --entry ROOT gate ARGS...` runs
    run.py's dispatcher under testing.override(ROOT, dialog="none", plus the
    keywords in ROOT/ux-entry.json). No dialog can ever reach the real screen."""
    root = Path(sys.argv[2])
    plugin = Path(__file__).resolve().parents[1]
    sys.path.insert(0, str(plugin / "src"))
    sys.path.insert(0, str(plugin))
    from gateway import testing
    import run
    cfg_path = root / "ux-entry.json"
    cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
    cfg.setdefault("dialog", "none")
    cfg.setdefault("machine_id", "TEST-MACHINE-0001")
    with testing.override(root, **cfg):
        return run.dispatch(sys.argv[3] if len(sys.argv) > 3 else "", sys.argv[4:])


if __name__ == "__main__" and len(sys.argv) > 2 and sys.argv[1] == "--entry":
    raise SystemExit(_entry())

import harness as H  # noqa: E402
from gateway import consent, paths, popup, testing, vault  # noqa: E402

SH_SCRIPTS = H.PLUGIN / "hooks"
_HELPERS: list[int] = []


def _track_spawn():
    orig = popup._spawn

    def spawn(*a, **kw):
        pid, r = orig(*a, **kw)
        if pid:
            _HELPERS.append(pid)
        return pid, r
    return orig, spawn


def wait_helpers(timeout: float = 15.0) -> None:
    """Wait for every detached helper started in this test, then kill leftovers."""
    end = time.time() + timeout
    while _HELPERS and time.time() < end:
        _HELPERS[:] = [p for p in _HELPERS if popup._pid_alive(p)]
        if _HELPERS:
            time.sleep(0.05)
    for p in list(_HELPERS):
        with contextlib.suppress(OSError):
            os.kill(p, signal.SIGKILL)
    _HELPERS.clear()


def _zombie(pid: int) -> bool:
    try:
        r = subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True,
                           text=True, timeout=5)
        return r.stdout.strip().startswith("Z") or not r.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return False


@contextlib.contextmanager
def patch(obj: Any, name: str, value: Any) -> Iterator[None]:
    old = getattr(obj, name)
    setattr(obj, name, value)
    try:
        yield
    finally:
        setattr(obj, name, old)


@contextlib.contextmanager
def env_vars(**kw: str | None) -> Iterator[None]:
    old = {k: os.environ.get(k) for k in kw}
    for k, v in kw.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@contextlib.contextmanager
def ux_env(answers: list[dict[str, Any]] | None = None, *, wait: float = 20, lifetime: float = 30,
           dialog: bool | str = True, session: str | None = "sess-ux", **kw: Any) -> Iterator[H.GatewayEnv]:
    with H.gateway_env(**kw) as env:
        d = UXDialog(env.root / "dlg", answers or [])
        env.dialog = d
        if dialog is True:
            env.o.dialog = str(d.script)
        else:
            env.o.dialog = dialog          # "none": no screen
        env.o.extra.update(popup_wait=wait, popup_lifetime=lifetime, dialog_timeout=lifetime,
                           scrub_seconds=0, history_path=str(env.root / "history.jsonl"))
        orig, spawn = _track_spawn()
        popup._spawn = spawn
        try:
            with env_vars(CLAUDE_CODE_SESSION_ID=session, CLAUDECODE=None, CLAUDE_PID=None):
                yield env
        finally:
            popup._spawn = orig
            wait_helpers()


UX_FAKE = r"""
import fcntl, json, sys, time
queue, log = sys.argv[1], sys.argv[2]
kind, title, message = (sys.argv[3:6] + ["", "", ""])[:3]
default = sys.argv[6] if len(sys.argv) > 6 else ""
with open(queue, "r+") as f:
    fcntl.flock(f, fcntl.LOCK_EX)
    items = json.loads(f.read() or "[]")
    ans = items.pop(0) if items else {"outcome": "cancelled"}
    f.seek(0); f.truncate(); f.write(json.dumps(items))
with open(log, "a") as f:
    f.write(json.dumps({"kind": kind, "title": title, "message": message, "default": default,
                        "outcome": ans.get("outcome")}) + "\n")
time.sleep(float(ans.get("delay", 0)))
out = ans.get("outcome", "cancelled")
if out == "ok":
    sys.stdout.write(str(ans.get("value", "") or "") + "\n"); sys.exit(0)
if out == "unavailable":
    sys.exit(3)
if out == "timeout":
    time.sleep(float(ans.get("sleep", 5))); sys.exit(5)
sys.exit(1)
"""


class UXDialog(H.FakeDialog):
    """FakeDialog plus a per-answer `delay` before any outcome (ok answers
    arriving late), and timeout = sleep then exit 5 (zenity's timeout code)."""

    def __init__(self, directory: Path, answers: list[dict[str, Any]] | None = None):
        super().__init__(directory, answers)
        prog = directory / "ux_fake_dialog.py"
        prog.write_text(UX_FAKE)
        self.script.write_text(f"#!/bin/sh\nexec {H.PY!s} -I -S '{prog}' '{self.queue}' '{self.log}' \"$@\"\n")
        os.chmod(self.script, 0o755)


def setup(env: H.GatewayEnv, form_text: str, approve: bool = True) -> None:
    env.write_form(form_text)
    vault.save(vault.empty())
    if approve:
        consent.approve_all(env.form())


def set_token(name: str, kind: str, value: str, **extra: Any) -> None:
    with vault.edit() as data:
        rec = vault.account_record(data, name, kind)
        rec["token"] = {"value": value, "source": "pasted", "updated": vault.now(), "stale": False}
        rec.update(extra)


def ux_entry_cmd(env: H.GatewayEnv) -> list[str]:
    """argv prefix of the ux test entry (see _entry)."""
    return [H.PY, "-I", "-S", *H.PYX, str(Path(__file__).resolve()), "--entry", str(env.root)]


def fake_ready_env(env: H.GatewayEnv) -> Path:
    py = paths.env_python()
    py.parent.mkdir(parents=True, exist_ok=True)
    if not py.exists():
        os.symlink(H.PY, py)
    (paths.env_dir() / ".ready").write_text("")
    return py


def run_sh(env: H.GatewayEnv, script: str, payload: Any, *, test: bool = True,
           extra_env: dict[str, str] | None = None, timeout: float = 60) -> subprocess.CompletedProcess[str]:
    """sh hooks/SCRIPT [--test] with the payload on stdin. A ready (fake) env
    makes the script exec run.py, so --test is then required."""
    # (mcp_perm.sh too: it hands http and download to Python, PLAN-0.11 §2.10)
    if H.any_env_ready() and not test:
        raise H.GuardTripped("TEST GUARD: a hook script with a ready env needs --test")
    e = env.subprocess_env({"CLAUDE_PLUGIN_DATA": str(env.data), **(extra_env or {})})
    args = ["/bin/sh", str(SH_SCRIPTS / script)] + (["--test"] if test else [])
    data = payload if isinstance(payload, str) else json.dumps(payload)
    return subprocess.run(args, input=data, capture_output=True, text=True, timeout=timeout, env=e,
                          cwd=str(env.root))


def answers(*items: tuple) -> list[dict[str, Any]]:
    """answers(("ok", "v"), ("cancelled",), ("ok", "x", 1.5)) -> FakeDialog queue."""
    out = []
    for it in items:
        d: dict[str, Any] = {"outcome": it[0]}
        if len(it) > 1:
            d["value"] = it[1]
        if len(it) > 2:
            d["sleep" if it[0] == "timeout" else "delay"] = it[2]
        out.append(d)
    return out


# ---------------------------------------------------------------------------
# Local HTTP(S) servers
# ---------------------------------------------------------------------------


class Recorder:
    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        self.lock = threading.Lock()

    def add(self, r: dict[str, Any]) -> None:
        with self.lock:
            self.requests.append(r)

    def last(self) -> dict[str, Any]:
        with self.lock:
            return self.requests[-1]


def _handler(rec: Recorder, routes: dict[str, Any]):
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a: Any) -> None:
            pass

        def _do(self) -> None:
            u = urllib.parse.urlsplit(self.path)
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n) if n else b""
            rec.add({"method": self.command, "path": u.path, "query": u.query,
                     "headers": {k: v for k, v in self.headers.items()}, "body": body,
                     "host": self.headers.get("Host")})
            route = routes.get(u.path)
            if callable(route):
                status, headers, payload = route(self, u, body)
            elif route is not None:
                status, headers, payload = route
            else:
                status, headers, payload = 404, {"Content-Type": "text/plain"}, b"not found"
            if isinstance(payload, str):
                payload = payload.encode()
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            if self.command != "HEAD":
                try:
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass

        do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _do
    return Handler


class Server:
    def __init__(self, routes: dict[str, Any], tls: tuple[str, str] | None = None):
        self.rec = Recorder()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _handler(self.rec, routes))
        self.httpd.daemon_threads = True
        self.scheme = "http"
        if tls:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(tls[0], tls[1])
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
            self.scheme = "https"
        self.port = self.httpd.server_address[1]
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()

    def url(self, path: str = "/", host: str = "127.0.0.1") -> str:
        return f"{self.scheme}://{host}:{self.port}{path}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


@contextlib.contextmanager
def servers(*route_sets: dict[str, Any], tls: tuple[str, str] | None = None) -> Iterator[list[Server]]:
    ss = [Server(r, tls) for r in route_sets]
    try:
        yield ss
    finally:
        for s in ss:
            s.close()


@contextlib.contextmanager
def trickle_server(mode: str, *, step: float = 0.2, total: float = 12.0) -> Iterator[str]:
    """A raw HTTP server on 127.0.0.1 that answers slowly, one byte per `step`
    seconds for up to `total` seconds: mode "headers" trickles the status line
    and headers, mode "body" sends the headers at once and trickles the body.
    Yields its base URL; every socket is closed and the thread joined on exit."""
    import socket as _socket
    stop = threading.Event()
    srv = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
    srv.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    srv.settimeout(0.2)
    conns: list[Any] = []

    def serve_one(c: Any) -> None:
        c.settimeout(5)
        buf = b""
        try:
            while b"\r\n\r\n" not in buf:
                chunk = c.recv(4096)
                if not chunk:
                    return
                buf += chunk
            body = b"x" * 100000
            head = f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(body)}\r\n\r\n".encode()
            slow = head + body if mode == "headers" else body
            if mode == "body":
                c.sendall(head)
            end = time.time() + total
            for i in range(len(slow)):
                if stop.is_set() or time.time() > end:
                    return
                c.sendall(slow[i:i + 1])
                time.sleep(step)
        except OSError:
            return
        finally:
            with contextlib.suppress(OSError):
                c.close()

    def loop() -> None:
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except (_socket.timeout, OSError):
                continue
            conns.append(c)
            threading.Thread(target=serve_one, args=(c,), daemon=True).start()
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    try:
        yield f"http://127.0.0.1:{srv.getsockname()[1]}"
    finally:
        stop.set()
        t.join(5)
        for c in conns:
            with contextlib.suppress(OSError):
                c.close()
        srv.close()


def self_signed(dirpath: Path) -> tuple[str, str] | None:
    """A throwaway certificate for 127.0.0.1/localhost (system openssl), or None."""
    for exe in ("/usr/bin/openssl", "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl"):
        if os.path.exists(exe):
            break
    else:
        return None
    dirpath.mkdir(parents=True, exist_ok=True)
    cert, key = dirpath / "cert.pem", dirpath / "key.pem"
    cfg = dirpath / "openssl.cnf"
    cfg.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=127.0.0.1\n"
                   "[ext]\nsubjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:TRUE\n")
    r = subprocess.run([exe, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-keyout", str(key), "-out", str(cert), "-config", str(cfg)],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0 or not cert.exists():
        return None
    return str(cert), str(key)


# ---------------------------------------------------------------------------
# A local sshd on 127.0.0.1 run by this (unprivileged) user
# ---------------------------------------------------------------------------

_SSHDS: list[subprocess.Popen] = []


def _kill_sshds() -> None:
    for p in list(_SSHDS):
        with contextlib.suppress(OSError):
            p.terminate()
        with contextlib.suppress(Exception):
            p.wait(5)
        with contextlib.suppress(OSError):
            p.kill()
        _SSHDS.remove(p)


import atexit as _atexit  # noqa: E402
_atexit.register(_kill_sshds)


@contextlib.contextmanager
def user_sshd(base: Path, binary: str) -> Iterator[dict[str, Any]]:
    """An sshd (`binary`: the system's /usr/sbin/sshd or pixi's) started by this
    user on a free 127.0.0.1 port, with throwaway keys: what a process of the
    user (Claude's Bash) could run. Yields {"ssh": argv prefix to run a command
    there, "dir": its folder}; killed on exit (and atexit)."""
    import socket as _socket
    d = base / "usersshd"
    d.mkdir(parents=True, exist_ok=True)
    keygen = str(H.ENV_BIN / "ssh-keygen")
    for k in ("hostkey", "userkey"):
        subprocess.run([keygen, "-q", "-t", "ed25519", "-N", "", "-f", str(d / k)], check=True,
                       capture_output=True, timeout=30, stdin=subprocess.DEVNULL)
    (d / "ak").write_text((d / "userkey.pub").read_text())
    s = _socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    (d / "sshd_config").write_text("\n".join([
        f"Port {port}", "ListenAddress 127.0.0.1", f"HostKey {d / 'hostkey'}",
        f"PidFile {d / 'sshd.pid'}", f"AuthorizedKeysFile {d / 'ak'}", "PasswordAuthentication no",
        "KbdInteractiveAuthentication no", "PubkeyAuthentication yes", "StrictModes no",
        "PermitUserEnvironment no", "PermitUserRC no", "PerSourcePenalties no", "LogLevel VERBOSE", ""]))
    (d / "ssh_config").write_text("\n".join([
        "Host peer", "  HostName 127.0.0.1", f"  Port {port}", f"  IdentityFile {d / 'userkey'}",
        "  IdentitiesOnly yes", "  BatchMode yes", "  StrictHostKeyChecking no",
        "  UserKnownHostsFile /dev/null", "  GlobalKnownHostsFile /dev/null", "  LogLevel ERROR",
        "  IdentityAgent none", "  ControlMaster no", ""]))
    proc = subprocess.Popen([binary, "-D", "-f", str(d / "sshd_config"), "-E", str(d / "sshd.log")],
                            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _SSHDS.append(proc)
    try:
        end = time.time() + 10
        while time.time() < end:
            if proc.poll() is not None:
                raise RuntimeError("sshd exited: " + (d / "sshd.log").read_text()[-1500:])
            try:
                with _socket.create_connection(("127.0.0.1", port), timeout=0.5) as c:
                    c.settimeout(1)
                    if c.recv(4) == b"SSH-":
                        break
            except OSError:
                time.sleep(0.05)
        yield {"ssh": [str(H.ENV_BIN / "ssh"), "-F", str(d / "ssh_config"), "peer"], "dir": d}
    finally:
        with contextlib.suppress(OSError):
            proc.terminate()
        with contextlib.suppress(Exception):
            proc.wait(5)
        with contextlib.suppress(OSError):
            proc.kill()
        with contextlib.suppress(ValueError):
            _SSHDS.remove(proc)
