"""Microsoft Entra ID (Azure AD) sign-in and tokens for azure and mlcat accounts.

Sign-in happens only in the user's /gate:account login (the hook):
- browser: authorization code + PKCE with a one-time loopback redirect
  (http://localhost:PORT, which Entra allows for public clients), opened in
  the user's browser, where SSO, MFA and conditional access happen as usual;
- terminal (no browser, e.g. over ssh): the device code flow.
The refresh token goes into the vault. Access tokens are minted in the MCP
server per resource (scope) when a tool needs one, cached in memory until
shortly before they expire, and never shown. Entra rotates refresh tokens on
use; the server stores the new one in place of the old. That is the only
vault write the server makes, and it grants nothing new.

GATEWAY_ENTRA_AUTHORITY overrides https://login.microsoftonline.com (tests).
"""
from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from . import vault, web_form

SCOPES = {
    "arm": "https://management.azure.com/.default",
    "storage": "https://storage.azure.com/.default",
    "graph": "https://graph.microsoft.com/.default",
    "databricks": "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d/.default",
}
LOGIN_TIMEOUT = 270
_CACHE: dict[tuple[str, str], tuple[str, float]] = {}
_LOCK = threading.Lock()


class EntraError(Exception):
    pass


def authority() -> str:
    return (os.environ.get("GATEWAY_ENTRA_AUTHORITY") or "https://login.microsoftonline.com").rstrip("/")


def resolve_scope(scope: str) -> str:
    return SCOPES.get(scope, scope)


def _post(url: str, form: dict[str, str]) -> dict[str, Any]:
    req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try:
            body = json.loads(e.read().decode())
        except Exception:
            body = {}
        raise EntraError(body.get("error_description", "").split("\r\n")[0]
                         or body.get("error") or f"HTTP {e.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise EntraError(f"could not reach Entra: {e}") from None


def _claims(id_token: str) -> dict[str, Any]:
    """The id_token's claims, for the user name only (not trusted for anything)."""
    try:
        part = id_token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:
        return {}


def _token_url(tenant: str) -> str:
    return f"{authority()}/{tenant}/oauth2/v2.0/token"


def login_browser(tenant: str, client_id: str, scope: str,
                  timeout: float = LOGIN_TIMEOUT) -> dict[str, Any]:
    """Authorization code + PKCE through the user's browser. Returns the
    token response plus "claims"."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    state = secrets.token_urlsafe(24)
    got: dict[str, str] = {}
    done = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            port = self.server.server_address[1]
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            ok_host = self.headers.get("Host", "") in (f"localhost:{port}", f"127.0.0.1:{port}")
            if not ok_host or q.get("state", [""])[0] != state or done.is_set():
                self.send_response(404)
                self.end_headers()
                return
            got.update({k: v[0] for k, v in q.items()})
            msg = ("Signed in. You can close this tab and go back to Claude."
                   if "code" in got else "Sign-in did not complete; nothing was saved.")
            body = web_form.DONE.format(msg=msg).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            done.set()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    redirect = f"http://localhost:{server.server_address[1]}"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"{authority()}/{tenant}/oauth2/v2.0/authorize?" + urllib.parse.urlencode({
        "client_id": client_id, "response_type": "code", "redirect_uri": redirect,
        "response_mode": "query", "scope": f"{scope} openid profile offline_access",
        "state": state, "code_challenge": challenge, "code_challenge_method": "S256",
        "prompt": "select_account"})
    try:
        if not web_form._open(url):
            raise web_form.Unavailable("no browser could be opened on this machine")
        if not done.wait(timeout):
            raise EntraError("sign-in timed out")
    finally:
        server.shutdown()
        server.server_close()
    if "code" not in got:
        raise EntraError(got.get("error_description") or got.get("error") or "sign-in cancelled")
    tok = _post(_token_url(tenant), {"client_id": client_id, "grant_type": "authorization_code",
                                     "code": got["code"], "redirect_uri": redirect,
                                     "code_verifier": verifier,
                                     "scope": f"{scope} openid profile offline_access"})
    tok["claims"] = _claims(tok.get("id_token", ""))
    return tok


def login_device(tenant: str, client_id: str, scope: str, show: Callable[[str, str], object],
                 timeout: float = LOGIN_TIMEOUT) -> dict[str, Any]:
    """The device code flow (no browser here): show(code, url) tells the user."""
    dc = _post(f"{authority()}/{tenant}/oauth2/v2.0/devicecode",
               {"client_id": client_id, "scope": f"{scope} openid profile offline_access"})
    show(dc["user_code"], dc.get("verification_uri") or "https://microsoft.com/devicelogin")
    end = time.time() + min(timeout, float(dc.get("expires_in", timeout)))
    interval = float(dc.get("interval", 5))
    while time.time() < end:
        time.sleep(interval)
        try:
            tok = _post(_token_url(tenant), {
                "client_id": client_id, "device_code": dc["device_code"],
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code"})
            tok["claims"] = _claims(tok.get("id_token", ""))
            return tok
        except EntraError as e:
            if "authorization_pending" in str(e).lower() or "pending" in str(e).lower():
                continue
            if "slow_down" in str(e).lower():
                interval += 5
                continue
            raise
    raise EntraError("sign-in timed out")


def access_token(ref: str, scope: str) -> str:
    """A current access token for an account and scope (minted from its
    refresh token; the rotated refresh token replaces the old one)."""
    scope = resolve_scope(scope)
    with _LOCK:
        hit = _CACHE.get((ref, scope))
        if hit and hit[1] > time.time() + 60:
            return hit[0]
        with vault.locked():
            data = vault.load()
            a = data["accounts"].get(ref)
            if a is None:
                raise EntraError(f"no account named {ref}")
            rt = a.get("secrets", {}).get("refresh_token")
            if not rt:
                raise EntraError(f"{ref} is not signed in; ask the user to run "
                                 f"/gate:account login {ref}")
            tok = _post(_token_url(a.get("tenant_id") or a.get("tenant")), {
                "client_id": a["client_id"], "grant_type": "refresh_token",
                "refresh_token": rt, "scope": f"{scope} offline_access"})
            if tok.get("refresh_token") and tok["refresh_token"] != rt:
                a["secrets"]["refresh_token"] = tok["refresh_token"]
                a["token_refreshed"] = vault.now()
                vault.save(data)
        _CACHE[(ref, scope)] = (tok["access_token"], time.time() + float(tok.get("expires_in", 300)))
        return tok["access_token"]


def cached_values() -> list[str]:
    """Access tokens minted in this process (scrubbed from any output)."""
    return [t for t, _ in _CACHE.values()]
