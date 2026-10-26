"""Fixtures for the `accounts` group tests (git, scrub, entra, the CLI
stand-ins, asiml). Pure stdlib; builds on tests/harness.py.

- build_vault(env, ...): a v3 vault with accounts approved and bound, and the
  form to match (so accounts.select and consent agree).
- FakeCLI: a tiny executable that prints a JSON dump of its argv and chosen
  environment variables (and, to test scrubbing, the token it was given).
- GitServer: a smart-HTTP git server with Basic auth and an LFS batch + object
  endpoint, driven through the real system git with the generated include.
- CatalogServer: a fake ML-catalog API (config, search, show, files, transfers).
- EntraServer: a fake Entra token endpoint (rotating refresh tokens).
- RecorderServer: records every request (method, path, headers, body) and
  answers 200 JSON; used as the "attacker" a redirect or proxy would reach.
- self_signed(dir): a throwaway 127.0.0.1 certificate (system openssl) or None.
- run_cli(env, tool, argv): run a stand-in in-process with stdout/stderr
  captured through the scrubber; fake binaries and endpoints come from the
  override.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import http.server
import json
import os
import sys
import shutil
import socket
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable

import harness as H
from gateway import consent, envfile, vault
from gateway import form as formmod
from gateway import paths

PY = H.PY
ENV_BIN = H.ENV_BIN


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ---------------------------------------------------------------------------
# Vault / form
# ---------------------------------------------------------------------------


def build_vault(env: H.GatewayEnv, form_text: str, *, tokens: dict[str, str] | None = None,
                entra: dict[str, dict[str, str]] | None = None,
                ssh_keys: dict[str, str] | None = None,
                host_keys: dict[str, list[str]] | None = None,
                bound_scope: dict[str, str] | None = None,
                approve: bool = True) -> dict[str, Any]:
    """Write the form and a matching vault: every account gets a token/entra
    record and, when approve=True, approved rights and a bound set covering its
    destinations."""
    env.write_form(form_text)
    form = env.form()
    vault.ensure_key()
    data = vault.empty()
    vault.ensure_machine(data)
    for name, a in form.accounts.items():
        rec = vault.account_record(data, name, a.kind)
        if tokens and name in tokens:
            rec["token"] = {"value": tokens[name], "source": "pasted", "updated": vault.now(),
                            "stale": False}
        if ssh_keys and name in ssh_keys:
            priv = ssh_keys[name]
            pub = vault.public_key_of(priv)
            rec["ssh_key"] = {"private": priv, "public": pub, "fingerprint": vault.fingerprint_of(pub)}
        if host_keys and name in host_keys:
            rec["host_keys"] = host_keys[name]
        if entra and name in entra:
            rec["entra"] = dict(entra[name])
        if approve:
            rec["bound"]["hosts"] = list(a.destinations())
            if a.kind == "azure":
                rec["bound"]["tenant"] = a.tenant
                rec["bound"]["client_id"] = a.client_id
            if a.kind == "api-key":
                rec["bound"]["auth"] = a.auth
            if a.kind == "ml-catalog" and bound_scope and name in bound_scope:
                rec["bound"]["scope"] = bound_scope[name]
    if approve:
        data["approved"] = {"form_sha256": form.sha256, "at": vault.now(),
                            "rights": consent.snapshot(form)}
    vault.save(data)
    return data


# ---------------------------------------------------------------------------
# Fake binaries
# ---------------------------------------------------------------------------

_FAKE_CLI = '''#!{py}
import json, os, sys
env = dict(os.environ)
print(json.dumps({{"argv": sys.argv[1:], "env": env}}))
# Echo any credential we were handed, so a test can prove the scrubber masks it.
for name in ("GH_TOKEN", "GH_ENTERPRISE_TOKEN", "HF_TOKEN", "DATABRICKS_TOKEN"):
    if env.get(name):
        print("TOKEN-SEEN:" + env[name])
tp = env.get("HF_TOKEN_PATH")
if tp and os.path.exists(tp):
    import stat as _st
    print("TOKEN-FILE-MODE:" + oct(_st.S_IMODE(os.stat(tp).st_mode)))
    print("TOKEN-SEEN:" + open(tp).read())
dc = env.get("DOCKER_CONFIG")
if dc and os.path.exists(os.path.join(dc, "config.json")):
    cfg = json.load(open(os.path.join(dc, "config.json")))
    for h, v in cfg.get("auths", {{}}).items():
        print("DOCKER-AUTH:" + v.get("auth", ""))
'''


def fake_cli(directory: Path, name: str, envkeys: list[str] | None = None) -> str:
    """A fake binary that prints its argv + full environment as JSON, and
    echoes each credential it was handed (so a test can prove the scrubber
    masks it even when the tool itself prints the token)."""
    directory.mkdir(parents=True, exist_ok=True)
    p = directory / name
    p.write_text(_FAKE_CLI.format(py=PY))
    os.chmod(p, 0o755)
    return str(p)


def install_fakes(env: H.GatewayEnv, **tools: str) -> None:
    """Point the override at fake binaries: install_fakes(env, gh=path, ...)."""
    env.o.tools = dict(env.o.tools or {})
    env.o.tools.update(tools)


# ---------------------------------------------------------------------------
# In-process stand-in runner with fd capture through the scrubber
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def capture_fds():
    # Python's own buffers first: a stand-in run in-process prints with print()
    # (flushed at a real process's exit); unflushed, its output would land in
    # the test log after the fds are back (block-buffered stdout, as on Linux)
    sys.stdout.flush()
    sys.stderr.flush()
    out = tempfile.NamedTemporaryFile(delete=False)
    err = tempfile.NamedTemporaryFile(delete=False)
    save1, save2 = os.dup(1), os.dup(2)
    os.dup2(out.fileno(), 1)
    os.dup2(err.fileno(), 2)
    box: dict[str, bytes] = {}
    try:
        yield box
    finally:
        sys.stdout.flush()
        sys.stderr.flush()
        os.fsync(1)
        os.fsync(2)
        os.dup2(save1, 1)
        os.dup2(save2, 2)
        os.close(save1)
        os.close(save2)
        out.close()
        err.close()
        box["out"] = Path(out.name).read_bytes()
        box["err"] = Path(err.name).read_bytes()
        os.unlink(out.name)
        os.unlink(err.name)


_direct_value: Callable | tuple | None = None


def set_direct(monkey_value: Callable | tuple | None = (True, "")) -> None:
    """Choose what ancestry.is_direct returns during the next stand-in call.
    The monkeypatch is applied only for the duration of run_cli/run_with/
    run_asiml and restored afterwards, so it never leaks into other tests."""
    global _direct_value
    _direct_value = monkey_value


@contextlib.contextmanager
def _patched_direct():
    # Patch only for the duration of the call, then always restore the real
    # ancestry.is_direct so nothing leaks into other test modules. The chosen
    # value persists (every stand-in test sets it first), so repeated calls in
    # one test keep it.
    from gateway import ancestry
    orig = ancestry.is_direct
    if _direct_value is not None:
        if callable(_direct_value):
            ancestry.is_direct = _direct_value  # type: ignore[assignment]
        else:
            ancestry.is_direct = (lambda tool, entry_scripts=False, _v=_direct_value: _v)  # type: ignore[assignment]
    try:
        yield
    finally:
        ancestry.is_direct = orig  # type: ignore[assignment]


def run_cli(tool: str, argv: list[str], cwd: str | None = None) -> tuple[int, str, str]:
    """Run a stand-in in-process; return (rc, stdout, stderr) with output as
    the scrubber produced it."""
    from gateway import clis
    old = os.getcwd()
    if cwd:
        os.chdir(cwd)
    try:
        with _patched_direct(), capture_fds() as box:
            rc = clis.main(tool, argv)
        return rc, box["out"].decode("utf-8", "replace"), box["err"].decode("utf-8", "replace")
    finally:
        if cwd:
            os.chdir(old)


def run_with(argv: list[str], cwd: str | None = None) -> tuple[int, str, str]:
    from gateway import clis
    old = os.getcwd()
    if cwd:
        os.chdir(cwd)
    try:
        with _patched_direct(), capture_fds() as box:
            rc = clis.with_main(argv)
        return rc, box["out"].decode("utf-8", "replace"), box["err"].decode("utf-8", "replace")
    finally:
        if cwd:
            os.chdir(old)


def run_asiml(argv: list[str], cwd: str) -> tuple[int, str, str]:
    from gateway import asiml
    old = os.getcwd()
    os.chdir(cwd)
    try:
        with _patched_direct(), capture_fds() as box:
            rc = asiml.main(argv)
        return rc, box["out"].decode("utf-8", "replace"), box["err"].decode("utf-8", "replace")
    finally:
        os.chdir(old)


# ---------------------------------------------------------------------------
# Git smart-HTTP server (+ LFS)
# ---------------------------------------------------------------------------


class GitServer:
    """A smart-HTTP git server with Basic auth over `git http-backend`, plus a
    minimal LFS batch + object endpoint. Records every (method, path, user,
    password)."""

    def __init__(self, root: Path, git: str):
        self.root = root
        self.git = git
        root.mkdir(parents=True, exist_ok=True)
        self.calls: list[dict[str, str]] = []
        self.lfs: dict[str, bytes] = {}
        self.rejected: set[str] = set()     # passwords answered with 401 (a revoked token)
        self._lock = threading.Lock()
        server = self

        class H2(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def _record(self) -> tuple[str, str]:
                a = self.headers.get("Authorization", "")
                user = pw = ""
                if a.startswith("Basic "):
                    try:
                        user, _, pw = base64.b64decode(a[6:]).decode().partition(":")
                    except Exception:  # noqa: BLE001
                        pass
                with server._lock:
                    server.calls.append({"method": self.command, "path": self.path,
                                         "user": user, "password": pw})
                return user, pw

            def _need_auth(self) -> bool:
                a = self.headers.get("Authorization", "")
                pw = ""
                if a.startswith("Basic "):
                    try:
                        pw = base64.b64decode(a[6:]).decode().partition(":")[2]
                    except Exception:  # noqa: BLE001
                        pw = ""
                if "Authorization" not in self.headers or (pw and pw in server.rejected):
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="gw"')
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return True
                return False

            def do_GET(self) -> None:
                self._any()

            def do_POST(self) -> None:
                self._any()

            def do_PUT(self) -> None:
                self._any()

            def _any(self) -> None:
                path = self.path.split("?", 1)[0]
                if "/lfsobj/" not in path and self._need_auth():
                    self._record()
                    return
                self._record()
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                if "/info/lfs/objects/batch" in path:
                    return self._lfs_batch(path, body)
                if "/lfsobj/" in path:
                    return self._lfs_obj(path, body)
                self._backend(path, body)

            def _lfs_batch(self, path: str, body: bytes) -> None:
                req = json.loads(body)
                base = f"http://{self.headers['Host']}{path.split('/info/lfs')[0]}"
                objs = []
                for o in req["objects"]:
                    act = "upload" if req["operation"] == "upload" else "download"
                    objs.append({"oid": o["oid"], "size": o["size"], "authenticated": True,
                                 "actions": {act: {"href": f"{base}/lfsobj/{o['oid']}"}}})
                out = json.dumps({"transfer": "basic", "objects": objs}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/vnd.git-lfs+json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def _lfs_obj(self, path: str, body: bytes) -> None:
                oid = path.rsplit("/", 1)[1]
                if self.command == "PUT":
                    server.lfs[oid] = body
                    self.send_response(200)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                d = server.lfs.get(oid, b"")
                self.send_response(200)
                self.send_header("Content-Length", str(len(d)))
                self.end_headers()
                self.wfile.write(d)

            def _backend(self, path: str, body: bytes) -> None:
                qs = self.path.split("?", 1)[1] if "?" in self.path else ""
                env = dict(os.environ, GIT_PROJECT_ROOT=str(server.root),
                           GIT_HTTP_EXPORT_ALL="1", PATH_INFO=path, QUERY_STRING=qs,
                           REQUEST_METHOD=self.command,
                           CONTENT_TYPE=self.headers.get("Content-Type", ""), REMOTE_USER="u",
                           CONTENT_LENGTH=str(len(body)),
                           GIT_PROTOCOL=self.headers.get("Git-Protocol", ""))
                r = subprocess.run([server.git, "http-backend"], input=body, env=env,
                                   capture_output=True)
                head, _, rest = r.stdout.partition(b"\r\n\r\n")
                status, hdrs = 200, []
                for line in head.split(b"\r\n"):
                    k, _, v = line.decode().partition(": ")
                    if k.lower() == "status":
                        status = int(v.split()[0])
                    elif k:
                        hdrs.append((k, v))
                self.send_response(status)
                for k, v in hdrs:
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(rest)))
                self.end_headers()
                self.wfile.write(rest)

        self.port = free_port()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), H2)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.port}"

    def make_repo(self, owner: str, name: str) -> Path:
        d = self.root / owner / f"{name}.git"
        d.mkdir(parents=True, exist_ok=True)
        subprocess.run([self.git, "init", "--bare", "-q", str(d)], check=True,
                       capture_output=True)
        subprocess.run([self.git, "-C", str(d), "config", "http.receivepack", "true"],
                       check=True, capture_output=True)
        return d

    def auths(self) -> list[dict[str, str]]:
        return [c for c in self.calls if c["user"]]

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.httpd.shutdown()
            self.httpd.server_close()


def git_env(env: H.GatewayEnv, extra: dict[str, str] | None = None) -> dict[str, str]:
    """A clean environment for running the real git with the gateway's include
    file exactly as the env file wires it (GIT_CONFIG_COUNT)."""
    home = env.root / "githome"
    home.mkdir(exist_ok=True)
    cfg = paths.git_config_path()
    e = {"PATH": f"{ENV_BIN}:/usr/bin:/bin", "HOME": str(home),
         "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(home / ".gitconfig"),
         "GIT_TERMINAL_PROMPT": "0", "GATEWAY_TEST_ROOT": str(env.root),
         "GIT_CONFIG_COUNT": "2",
         "GIT_CONFIG_KEY_0": "include.path", "GIT_CONFIG_VALUE_0": str(cfg),
         "GIT_CONFIG_KEY_1": "protocol.http.allow", "GIT_CONFIG_VALUE_1": "always"}
    if not (home / ".gitconfig").exists():
        (home / ".gitconfig").write_text("")
    e.update(extra or {})
    return e


def git_run(system_git: str, args: list[str], env: dict[str, str], cwd: str | None = None,
            timeout: float = 60) -> subprocess.CompletedProcess[str]:
    return subprocess.run([system_git, *args], env=env, cwd=cwd, capture_output=True, text=True,
                          timeout=timeout)


def system_git_path() -> str:
    """A real git to drive the git tests: the system's own where there is one
    (what the gateway prefers), else the gateway env's git (what it falls back
    to on a machine without git, such as the Debian test VM). The override's
    `system_git` knob only says "pretend there is one" (envfile.system_git
    names /usr/bin/git then), so look for the binary itself."""
    for c in ("/usr/bin/git", "/usr/local/bin/git", "/opt/homebrew/bin/git", "/opt/local/bin/git"):
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    g = H.ENV_BIN / "git"
    assert g.is_file(), "no git for the git tests: neither a system git nor the gateway env's"
    return str(g)


# ---------------------------------------------------------------------------
# Fake catalog + entra servers
# ---------------------------------------------------------------------------


class CatalogServer:
    """A fake ML-catalog API. /api/config returns a clientId; transfers return
    a storage pass pointing at a local 'remote' dir; search/show/files echo."""

    def __init__(self, client_id: str = "99999999-8888-7777-6666-555555555555",
                 expect_bearer: str | None = None, redirect_to: str | None = None,
                 extra_config: dict[str, Any] | None = None):
        self.client_id = client_id
        # more /api/config fields (PLAN-0.11 §7.4: an authority, a tenant or a
        # scope a catalog names must never be used)
        self.extra_config = dict(extra_config or {})
        self.expect_bearer = expect_bearer
        self.redirect_to = redirect_to.rstrip("/") if redirect_to else None
        self.calls: list[dict[str, Any]] = []
        self.remote = tempfile.mkdtemp(prefix="gw-catremote-", dir=H.tmp_base())
        server = self

        class CH(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def _send(self, obj: Any, code: int = 200) -> None:
                out = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def _redirect(self, code: int) -> bool:
                if not server.redirect_to or self.path.split("?", 1)[0] == "/api/config":
                    return False
                server.calls.append({"method": self.command, "path": self.path,
                                     "auth": self.headers.get("Authorization", ""),
                                     "redirected": True})
                self.send_response(code)
                self.send_header("Location", server.redirect_to + self.path)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return True

            def do_GET(self) -> None:
                path = self.path.split("?", 1)[0]
                if self._redirect(302):
                    return
                if path == "/api/config":
                    return self._send({"tenantId": "11111111-2222-3333-4444-555555555555",
                                       "clientId": server.client_id,
                                       "cliClientId": server.client_id, **server.extra_config})
                auth = self.headers.get("Authorization", "")
                server.calls.append({"method": "GET", "path": self.path, "auth": auth})
                if path.startswith("/api/catalog"):
                    return self._send({"items": [{"name": "demo", "kind": "dataset"}]})
                if path.startswith("/api/items/"):
                    return self._send({"name": path.rsplit("/", 1)[1], "latest": "a" * 32})
                if path.startswith("/api/versions/"):
                    return self._send({"files": [{"path": "f.bin", "size": 3}]})
                return self._send({"error": "not found"}, 404)

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                if self._redirect(302):
                    return
                auth = self.headers.get("Authorization", "")
                server.calls.append({"method": "POST", "path": self.path, "auth": auth,
                                     "body": body})
                md5 = "a" * 32
                if self.path.endswith("/pull") or self.path.endswith("/push"):
                    return self._send({"md5": md5, "size": 3, "nFiles": 1,
                                       "remoteUrl": "local://" + server.remote,
                                       "account": "acct", "sasToken": "sig=SECRETSAS123456"})
                if self.path.endswith("/complete"):
                    return self._send({"ok": True})
                return self._send({"error": "not found"}, 404)

        self.port = free_port()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), CH)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.port}"

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.httpd.shutdown()
            self.httpd.server_close()
        shutil.rmtree(self.remote, ignore_errors=True)


class EntraServer:
    """A fake Entra token endpoint. Each refresh rotates the refresh token and
    returns an access token that encodes the scope it was asked for. A
    client-credentials grant (a service principal) gets no refresh token, and
    with `secret` set a wrong client secret is refused (invalid_client)."""

    def __init__(self, secret: str | None = None, cert_pub: Path | None = None,
                 refuse: dict[str, Any] | None = None):
        self.calls: list[dict[str, Any]] = []
        self.counter = 0
        self.secret = secret
        # PLAN-v4 phase 7: a certificate's client assertion is checked against
        # this public key (openssl verifies the RS256 signature); `refuse`
        # answers every request with that Entra error (codes, error, status)
        self.cert_pub = cert_pub
        self.refuse = refuse
        self.assertions: list[dict[str, Any]] = []
        server = self

        class EH(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def do_POST(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                form = {k: v[0] for k, v in __import__("urllib.parse", fromlist=["parse_qs"])
                        .parse_qs(self.rfile.read(n).decode()).items()}
                server.calls.append(form)
                cc = form.get("grant_type") == "client_credentials"

                def fail(status: int, err: str, desc: str, codes: list[int]) -> None:
                    data = json.dumps({"error": err, "error_description": desc,
                                       "error_codes": codes}).encode()
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                if server.refuse is not None:
                    r = server.refuse
                    fail(r.get("status", 400), r.get("error", "invalid_grant"),
                         r.get("description", "AADSTS0: refused"), r.get("codes", []))
                    return
                if cc and form.get("client_assertion"):
                    ok = server.cert_pub is not None and _jwt_ok(form["client_assertion"],
                                                                 server.cert_pub, form.get("client_id"),
                                                                 server.assertions)
                    if not ok:
                        fail(401, "invalid_client", "AADSTS700027: Client assertion failed "
                             "signature validation.", [700027])
                        return
                elif cc and server.secret is not None and form.get("client_secret") != server.secret:
                    data = json.dumps({"error": "invalid_client", "error_description":
                                       "AADSTS7000215: Invalid client secret provided."}).encode()
                    self.send_response(401)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                    return
                server.counter += 1
                scope = form.get("scope", "")
                access = f"ACCESS-{server.counter}-for-{scope.split()[0] if scope else 'none'}"
                out = {"access_token": access, "expires_in": 3600}
                if not cc:
                    out["refresh_token"] = f"ROT-REFRESH-{server.counter}"
                data = json.dumps(out).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.port = free_port()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), EH)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def authority(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.httpd.shutdown()
            self.httpd.server_close()


def _jwt_ok(jwt: str, pub: Path, client_id: Any, seen: list[dict[str, Any]]) -> bool:
    """A client assertion's RS256 signature, checked with the env's openssl
    against the certificate's public key, and its claims."""
    import base64
    import subprocess
    import tempfile
    try:
        h, c, sig = jwt.split(".")
        pad = lambda x: x + "=" * (-len(x) % 4)  # noqa: E731
        header = json.loads(base64.urlsafe_b64decode(pad(h)))
        claims = json.loads(base64.urlsafe_b64decode(pad(c)))
        raw_sig = base64.urlsafe_b64decode(pad(sig))
    except ValueError:
        return False
    with tempfile.TemporaryDirectory() as td:
        sp = Path(td) / "sig"
        sp.write_bytes(raw_sig)
        r = subprocess.run([str(ENV_BIN / "openssl"), "dgst", "-sha256", "-verify", str(pub),
                            "-signature", str(sp)], input=f"{h}.{c}".encode(), capture_output=True)
    seen.append({"header": header, "claims": claims, "verified": r.returncode == 0})
    return (r.returncode == 0 and header.get("alg") == "RS256" and bool(header.get("x5t"))
            and claims.get("iss") == client_id == claims.get("sub"))


def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


class RecorderServer:
    """Records every request (method, raw path, headers, body) and answers
    200 with `reply` as JSON. A proxy request shows up with an absolute URL
    as its path."""

    def __init__(self, reply: Any = None):
        self.reply = reply if reply is not None else {"ok": True}
        self.calls: list[dict[str, Any]] = []
        server = self

        class RH(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def _any(self) -> None:
                n = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(n) if n else b""
                server.calls.append({"method": self.command, "path": self.path,
                                     "headers": {k: v for k, v in self.headers.items()},
                                     "body": body})
                out = json.dumps(server.reply).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            do_GET = do_POST = do_PUT = _any

        self.port = free_port()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), RH)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def saw(self, needle: str) -> bool:
        """Did any request carry `needle` in its path, headers or body?"""
        for c in self.calls:
            blob = c["path"] + json.dumps(c["headers"]) + c["body"].decode("utf-8", "replace")
            if needle in blob:
                return True
        return False

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.httpd.shutdown()
            self.httpd.server_close()


def self_signed(dirpath: Path) -> tuple[str, str] | None:
    """A throwaway certificate for 127.0.0.1 (system openssl), or None."""
    for exe in ("/usr/bin/openssl", "/opt/homebrew/bin/openssl", "/usr/local/bin/openssl",
                "/opt/local/bin/openssl"):
        if os.path.exists(exe):
            break
    else:
        return None
    dirpath.mkdir(parents=True, exist_ok=True)
    cert, key = dirpath / "cert.pem", dirpath / "key.pem"
    cfg = dirpath / "openssl.cnf"
    cfg.write_text("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n"
                   "[dn]\nCN=127.0.0.1\n[ext]\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n"
                   "basicConstraints=CA:TRUE\n")
    r = subprocess.run([exe, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                        "-keyout", str(key), "-out", str(cert), "-config", str(cfg)],
                       capture_output=True, text=True, timeout=60)
    if r.returncode != 0 or not cert.exists():
        return None
    return str(cert), str(key)


class TLSServer:
    """A tiny https server on 127.0.0.1 with the given certificate; GET
    answers 200 {"tls": true}."""

    def __init__(self, cert: str, key: str):
        import ssl

        class TH(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def do_GET(self) -> None:
                out = b'{"tls": true}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), TH)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}/"

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.httpd.shutdown()
            self.httpd.server_close()


@contextlib.contextmanager
def env_vars(**values: str | None):
    """Set (str) or remove (None) environment variables for a block."""
    saved = {k: os.environ.get(k) for k in values}
    try:
        for k, v in values.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        yield
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
