"""logins.verify_login (SPEC 6, 15): a pasted personal access token checked
with GET /user, the expected login, the SSO hint. The device-flow sign-in is
gone (PLAN-v4 phase 3: no code to type on a web page)."""
from __future__ import annotations

import http.server
import json
import threading
import urllib.parse

import harness as H
import harness_accounts as HA
from gateway import logins


class FakeGitHub:
    def __init__(self, token="gho_devflowtoken0123456789abc", login="octo-work",
                 sso=False, pending_once=True):
        self.token, self.login, self.sso = token, login, sso
        self.pending_once = pending_once
        self.polls = 0
        server = self

        class GH(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _json(self, obj, code=200, headers=None):
                out = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(out)))
                self.end_headers()
                self.wfile.write(out)

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}
                if self.path.endswith("/login/device/code"):
                    return self._json({"device_code": "DEV", "user_code": "ABCD-1234",
                                       "verification_uri": "http://x/device", "expires_in": 60,
                                       "interval": 0})
                if self.path.endswith("/login/oauth/access_token"):
                    server.polls += 1
                    if server.pending_once and server.polls == 1:
                        return self._json({"error": "authorization_pending"})
                    return self._json({"access_token": server.token, "token_type": "bearer"})
                return self._json({"error": "not found"}, 404)

            def do_GET(self):
                if self.path == "/user":
                    if server.sso:
                        return self._json({"message": "SSO"}, 403,
                                          {"X-GitHub-SSO": "required; url=https://github.com/x"})
                    return self._json({"login": server.login})
                return self._json({"error": "not found"}, 404)

        self.port = HA.free_port()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), GH)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def bases(self):
        return {"web": f"http://127.0.0.1:{self.port}", "api": f"http://127.0.0.1:{self.port}"}

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def test_there_is_no_device_flow_sign_in_any_more():
    assert not hasattr(logins, "github_login") and not hasattr(logins, "GH_CLIENT_ID")


def test_verify_login_rejects_a_token_of_another_login():
    gh = FakeGitHub(login="someoneelse")
    try:
        with H.gateway_env() as env:
            env.o.extra["github_base"] = gh.bases()
            try:
                logins.verify_login("github.com", "ghp_some_token_value_01234567", expected="octo-work")
                raise AssertionError("a login mismatch must raise")
            except logins.LoginError as e:
                assert "someoneelse" in str(e) and "octo-work" in str(e)
    finally:
        gh.close()


def test_verify_login_sso_hint():
    gh = FakeGitHub(sso=True)
    try:
        with H.gateway_env() as env:
            env.o.extra["github_base"] = gh.bases()
            try:
                logins.verify_login("github.com", "ghp_some_token_value_01234567")
                raise AssertionError("an SSO block must raise")
            except logins.LoginError as e:
                assert "SSO" in str(e) and "authorize" in str(e)
    finally:
        gh.close()


def test_verify_login_only():
    gh = FakeGitHub(login="me")
    try:
        with H.gateway_env() as env:
            env.o.extra["github_base"] = gh.bases()
            assert logins.verify_login("github.com", "tok") == "me"
    finally:
        gh.close()


class RedirectingGitHub:
    """GET /user answers 302 to another host (which would happily say who
    the token belongs to)."""

    def __init__(self, target: str):
        server = self
        self.target = target.rstrip("/")

        class R(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", server.target + self.path)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.port = HA.free_port()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), R)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def bases(self):
        return {"web": f"http://127.0.0.1:{self.port}", "api": f"http://127.0.0.1:{self.port}"}

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def test_verify_login_does_not_follow_a_redirect_with_the_token():
    evil = HA.RecorderServer(reply={"login": "me"})
    gh = RedirectingGitHub(evil.url)
    try:
        with H.gateway_env() as env:
            env.o.extra["github_base"] = gh.bases()
            try:
                logins.verify_login("github.com", "gho_SECRETverifytoken0123456789")
                raise AssertionError("a redirect must not be followed")
            except logins.LoginError as e:
                assert "redirect" in str(e)
            assert not evil.calls and not evil.saw("gho_SECRETverifytoken0123456789")
    finally:
        gh.close()
        evil.close()
