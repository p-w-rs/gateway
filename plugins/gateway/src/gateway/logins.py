"""GitHub token checks (SPEC 6, 15; PLAN-v4 phase 3).

`verify_login(host, token, expected)` checks a personal access token with
`GET /user` against `host` (github.com or a GHES host) and that its login
matches the one the form expects. A 403 that looks like an unauthorized SSO
org turns into a clear hint to authorize the token for the org.

The OAuth device-flow sign-in (a code to type on a GitHub web page) is gone:
the gateway shows no web page or code to type elsewhere (the brief, section
11). A token is pasted into the gateway's dialog instead
(popup.signin_unavailable says so). Tests point the GitHub endpoints at a
local server with testing.override(github_base={"web":..., "api":...}).
Requests go through entra.urlopen: no redirects (urllib would resend the
token header to the new host), no proxy variables, the build's CA bundle.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import entra, testing


class LoginError(Exception):
    pass


def _bases(host: str) -> tuple[str, str]:
    """(web base, api base) for a GitHub host. Tests override both."""
    o = testing.get("github_base")
    if o:
        return o["web"].rstrip("/"), o["api"].rstrip("/")
    bare = host.split(":", 1)[0].lower()
    if bare == "github.com":
        return "https://github.com", "https://api.github.com"
    return f"https://{bare}", f"https://{bare}/api/v3"


def _post(url: str, form: dict[str, str]) -> dict[str, Any]:
    req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode(),
                                 headers={"Accept": "application/json",
                                          "Content-Type": "application/x-www-form-urlencoded"})
    try:
        with entra.urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if entra.is_redirect(e):
            raise LoginError("GitHub answered with a redirect, which the gateway doesn't "
                             "follow during sign-in") from None
        try:
            body = json.loads(e.read().decode())
        except Exception:  # noqa: BLE001
            body = {}
        raise LoginError(body.get("error_description") or body.get("error")
                         or f"HTTP {e.code}") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise LoginError(f"could not reach GitHub ({type(e).__name__})") from None


def verify_login(host: str, token: str, expected: str | None = None) -> str:
    """GET /user with the token; returns the login. Raises LoginError on a
    bad token, an SSO block, or a login that isn't `expected`."""
    _web, api = _bases(host)
    req = urllib.request.Request(api + "/user", headers={
        "Authorization": f"token {token}", "Accept": "application/vnd.github+json",
        "User-Agent": "gateway"})
    try:
        with entra.urlopen(req, timeout=30) as r:
            who = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if entra.is_redirect(e):
            raise LoginError("GitHub answered with a redirect, which the gateway doesn't follow "
                             "with the token") from None
        sso = e.headers.get("X-GitHub-SSO", "") if e.headers else ""
        if e.code in (403, 401) and "required" in sso.lower():
            raise LoginError("the token needs SSO authorization for the org; open the token's "
                             "settings on GitHub and authorize it, then try again") from None
        raise LoginError(f"the token could not be verified (HTTP {e.code})") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise LoginError(f"could not verify the token ({type(e).__name__})") from None
    login = str(who.get("login") or "")
    if not login:
        raise LoginError("GitHub returned no login for this token")
    if expected and login.lower() != expected.lower():
        raise LoginError(f"signed in as {login}, but the account expects {expected}; "
                         "sign in with the right GitHub user")
    return login
