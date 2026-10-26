"""A local fake OAuth server for the browser sign-in (PLAN-0.11 §7.6), and the
browser program gated runs for the `browser` test knob.

OAuthServer, at http://127.0.0.1:PORT (point the gateway at it with the gated
knob `entra_authority`, or testing.override(entra_authority=...)):

- GET /{tenant}/oauth2/v2.0/authorize: checks the request's shape (a code
  request, an S256 challenge, a redirect to http://127.0.0.1:PORT/cb) and
  302s to the redirect_uri with a canned single-use code and the state; mode
  "error" sends error=access_denied with a canary error_description instead.
- POST /{tenant}/oauth2/v2.0/token: the authorization-code grant (the code
  known and unused, the same client and redirect_uri, base64url(sha256(
  code_verifier)) equal to the challenge; else 400 invalid_grant) answers
  SSO-ACCESS-n / SSO-REFRESH-n; the refresh grant rotates (ACCESS-n-for-
  <scope> / ROT-REFRESH-n). token_mode "redirect" answers 302 to
  `redirect_to` instead (a gateway that followed it would hand over the code).

Every request is recorded (`authorize`, `tokens`): tests check what reached
the server, never print a value.

sso(form): a real gated with both (the `browser` and `entra_authority`
knobs), the form and an approved vault, a FakeClaude as the mod's terminal
session (Mod answers its dialogs) and the driver: gate(s, "check", NAME) runs
`gate` below it, result(s, pid) waits for it.

write_browser(dir): an executable the `browser` knob names. It gets the
authorize URL as its argument, records the URL and its environment's names
(JSON lines in its log), then acts by its mode file: "follow" GETs the URL
(urllib follows the 302 to gated's /cb), "wrong_state_first" first calls /cb
with a wrong state, "stall_first" first opens a connection to /cb that sends
nothing, "wait_go" follows only once the file MODEFILE.go exists (at most
120 s; the TUI acceptance looks at the sign-in while it waits), "none" does
nothing. It always exits 0 and records each status.

The OAuth server and write_browser need nothing of the test harness (the TUI
acceptances import them without its guard); sso() and gate() import it.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import http.server
import json
import os
import secrets
import threading
import time
import urllib.parse
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator

CANARY_DESCRIPTION = "AADSTS65004: CANARY-ERRDESC-" + "9f2c41d7"


def s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


class OAuthServer:
    def __init__(self, *, mode: str = "ok", token_mode: str = "ok", redirect_to: str | None = None):
        self.mode = mode
        self.token_mode = token_mode
        self.redirect_to = redirect_to
        self.authorize: list[dict[str, Any]] = []
        self.tokens: list[dict[str, Any]] = []
        self.codes: dict[str, dict[str, Any]] = {}
        self.counter = 0
        server = self

        class OH(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def _json(self, code: int, obj: Any) -> None:
                data = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _redirect(self, location: str) -> None:
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self) -> None:
                u = urllib.parse.urlsplit(self.path)
                parts = u.path.strip("/").split("/")
                if len(parts) != 4 or parts[1:] != ["oauth2", "v2.0", "authorize"]:
                    return self._json(404, {"error": "not_found"})
                q = {k: v[0] for k, v in urllib.parse.parse_qs(u.query).items()}
                server.authorize.append({"tenant": parts[0], **q})
                redirect = q.get("redirect_uri", "")
                ok = (q.get("response_type") == "code" and q.get("code_challenge_method") == "S256"
                      and q.get("code_challenge") and q.get("state")
                      and redirect.startswith("http://127.0.0.1:") and redirect.endswith("/cb"))
                if not ok:
                    return self._json(400, {"error": "invalid_request"})
                sep = "&" if "?" in redirect else "?"
                if server.mode == "error":
                    return self._redirect(redirect + sep + urllib.parse.urlencode(
                        {"error": "access_denied", "error_description": CANARY_DESCRIPTION,
                         "state": q["state"]}))
                code = "CODE-" + secrets.token_hex(12)
                server.codes[code] = {"client_id": q.get("client_id"), "redirect_uri": redirect,
                                      "challenge": q["code_challenge"], "scope": q.get("scope"),
                                      "tenant": parts[0], "used": False}
                self._redirect(redirect + sep + urllib.parse.urlencode({"code": code,
                                                                        "state": q["state"]}))

            def do_POST(self) -> None:
                u = urllib.parse.urlsplit(self.path)
                parts = u.path.strip("/").split("/")
                n = int(self.headers.get("Content-Length") or 0)
                form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}
                if len(parts) != 4 or parts[1:] != ["oauth2", "v2.0", "token"]:
                    return self._json(404, {"error": "not_found"})
                server.tokens.append({"tenant": parts[0], **form})
                if server.token_mode == "redirect" and server.redirect_to:
                    return self._redirect(server.redirect_to + "/stolen")
                if form.get("grant_type") == "authorization_code":
                    c = server.codes.get(form.get("code", ""))
                    good = (c is not None and not c["used"] and c["client_id"] == form.get("client_id")
                            and c["redirect_uri"] == form.get("redirect_uri")
                            and c["tenant"] == parts[0]
                            and s256(form.get("code_verifier", "")) == c["challenge"])
                    if not good:
                        return self._json(400, {"error": "invalid_grant",
                                                "error_description": "AADSTS70008: bad code"})
                    c["used"] = True
                    server.counter += 1
                    return self._json(200, {"access_token": f"SSO-ACCESS-{server.counter}",
                                            "refresh_token": f"SSO-REFRESH-{server.counter}",
                                            "expires_in": 3600, "token_type": "Bearer",
                                            "scope": c["scope"]})
                if form.get("grant_type") == "refresh_token":
                    server.counter += 1
                    scope = form.get("scope", "")
                    return self._json(200, {"access_token": f"ACCESS-{server.counter}-for-"
                                                            f"{scope.split()[0] if scope else 'none'}",
                                            "refresh_token": f"ROT-REFRESH-{server.counter}",
                                            "expires_in": 3600})
                return self._json(400, {"error": "unsupported_grant_type"})

        self.port = _free_port()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), OH)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    @property
    def authority(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.httpd.shutdown()
            self.httpd.server_close()
        self.thread.join(timeout=5)


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


BROWSER = '''#!{py} -I
import json, os, socket, sys, time, urllib.error, urllib.parse, urllib.request
url = sys.argv[1] if len(sys.argv) > 1 else ""
try:
    mode = open({mode!r}).read().strip()
except OSError:
    mode = "follow"
def note(**kw):
    with open({log!r}, "a") as f:
        f.write(json.dumps(kw) + "\\n")
note(url=url, env=sorted(os.environ), argc=len(sys.argv))
opener = urllib.request.build_opener(urllib.request.ProxyHandler({{}}))
def get(u):
    try:
        with opener.open(u, timeout=30) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return type(e).__name__
try:
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    redirect = q.get("redirect_uri", [""])[0]
    held = None
    if mode == "none":
        sys.exit(0)
    if mode == "wrong_state_first" and redirect:
        note(step="wrong_state", status=get(redirect + "?code=CODE-WRONG&state=not-the-state"))
    if mode == "stall_first" and redirect:
        p = urllib.parse.urlsplit(redirect)
        held = socket.create_connection((p.hostname, p.port), timeout=5)
        time.sleep(0.2)
    if mode == "wait_go":
        go = {mode!r} + ".go"
        end = time.time() + 120
        while not os.path.exists(go) and time.time() < end:
            time.sleep(0.2)
        note(step="go", seen=os.path.exists(go))
    note(step="follow", status=get(url))
except SystemExit:
    raise
except Exception as e:
    note(step="error", error=type(e).__name__)
sys.exit(0)
'''


def write_browser(directory: Path, mode: str = "follow",
                  py: str | None = None) -> tuple[Path, Path, Path]:
    """(program, its log, its mode file) in `directory`; `py` the Python it
    runs with (default: the test harness's)."""
    if py is None:
        import harness as H
        py = H.PY
    directory.mkdir(parents=True, exist_ok=True)
    prog, log, modef = directory / "browser", directory / "browser.log", directory / "browser.mode"
    prog.write_text(BROWSER.format(py=py, log=str(log), mode=str(modef)))
    os.chmod(prog, 0o755)
    modef.write_text(mode)
    return prog, log, modef


def opened(log: Path) -> list[dict[str, Any]]:
    """The browser program's records (the URL it was given, its steps)."""
    if not log.exists():
        return []
    return [json.loads(x) for x in log.read_text().splitlines() if x.strip()]


# ---------------------------------------------------------------------------
# A real gated for the sign-in: the mod (a FakeClaude) and `gate` below it
# ---------------------------------------------------------------------------


class Mod:
    """The gate mod's side of the UI plane, played by a FakeClaude."""

    def __init__(self, fc: Any):
        self.fc = fc

    def view(self) -> dict[str, Any]:
        st, body = self.fc.http("GET", "/ui/dialog/next?rev=0&wait=0")
        assert st == 200, body
        return body

    def dialog(self, pred: Any = None, timeout: float = 30) -> dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            d = self.view().get("dialog")
            if d and d.get("state") == "open" and (pred is None or pred(d)):
                return d
            time.sleep(0.05)
        raise AssertionError(f"no dialog (last view: {json.dumps(self.view())[:400]})")

    def post(self, path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        return self.fc.http("POST", path, body)

    def open(self, d: dict[str, Any], env: dict[str, str] | None = None) -> None:
        """Open, with the display variables the mod sends (DISPLAY=:0 unless given)."""
        st, body = self.post("/ui/dialog/answer", {"id": d["id"], "button": "ok",
                                                   "env": {"DISPLAY": ":0"} if env is None else env})
        assert st == 200, body


def is_signin(d: dict[str, Any]) -> bool:
    return d.get("what") == "browser sign-in"


@contextlib.contextmanager
def sso(form_text: str, *, mode: str = "follow", knobs: dict[str, Any] | None = None,
        server: OAuthServer | None = None, approve: bool = True,
        surface: str | None = "terminal") -> Iterator[SimpleNamespace]:
    """A real gated (harness_daemon) with the `browser` knob's program and the
    fake OAuth server as its authority, the form and a vault (approved unless
    asked), a FakeClaude registered as the mod's terminal session, and the
    driver that runs `gate` below it."""
    import harness_accounts as HA
    import harness_daemon as D
    srv = server or OAuthServer()
    try:
        with D.daemon_env(start=False) as de:
            prog, log, modef = write_browser(de.root / "browser", mode)
            de.knobs(browser=str(prog), entra_authority=srv.authority, **(knobs or {}))
            de.env.o.extra["entra_authority"] = srv.authority
            HA.build_vault(de.env, form_text, approve=approve)
            de.start()
            fc = de.claude(surface=surface)
            drv = D.write_driver(de.env, de.run, native_dialogs=True, popup_wait=60,
                                 dialog_timeout=60, gate_check_budget=60)
            yield SimpleNamespace(de=de, srv=srv, fc=fc, mod=Mod(fc), drv=str(drv), log=log,
                                  modef=modef)
    finally:
        if server is None:
            srv.close()


def gate(s: SimpleNamespace, *args: str) -> int:
    """`gate ARGS` below the FakeClaude (the driver: a test entry point); its pid."""
    import harness as H
    env = s.de.env.subprocess_env()
    env.pop("GATEWAY_TEST_ROOT", None)
    env["CLAUDE_PID"] = str(s.fc.pid)
    return s.fc.spawn([H.PY, "-I", "-S", s.drv, str(s.de.root), "gate", *args], env=env)


def result(s: SimpleNamespace, pid: int, timeout: float = 120) -> tuple[int, str, str]:
    r = s.fc.wait(pid, timeout=timeout)
    return r.returncode, r.stdout, r.stderr


def active(s: SimpleNamespace) -> bool:
    """gated's <run>/signin-active (hooks/tool_guard.sh's marker)."""
    return (s.de.run / "signin-active").exists()
