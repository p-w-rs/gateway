"""Microsoft Entra ID (Azure AD) sign-in and tokens (SPEC 9.5, 14).

The vault stores a per-account refresh token and the pinned tenant/client it
was minted for (`accounts[NAME].entra = {refresh_token, client_id,
tenant_id, refreshed}`). `access_token(account, scope)`:

- resolves the scope (arm, graph, storage, a listed Databricks workspace's
  resource, or a passed-through resource/scope);
- returns a cached access token from cache.age if one is valid for at least
  two more minutes;
- otherwise, under the vault lock, mints one from the refresh token, persists
  the rotated refresh token Entra hands back, and caches the access token
  (keyed by account + scope, with its expiry) in cache.age.

The authority and the pinned tenant/client are never re-read from a host that
changed (SPEC 5 bindings): the token is minted for the vault's entra record.

`scope_for_host(account, host, scope=None)` maps an https destination to the
scope the http tool should request, with the http tool's own rules
(web.azure_scope): management.azure.com -> arm, graph.microsoft.com -> graph,
a listed databricks workspace -> the Azure Databricks resource, a listed
storage host -> storage; a listed site needs an explicit `scope`, which may
not be a first-party audience.

`acr_token(host, account)` exchanges an ARM token at a registry's
/oauth2/exchange for an ACR refresh token (cached in cache.age), for crane.

`urlopen(req, timeout)` is the one HTTP client for every credentialed request
in this group (Entra, the ACR exchange, the catalog API, GitHub sign-in): it
never follows a redirect (a 3xx is an HTTPError, so a token is sent only to
the URL the gateway chose), ignores proxy variables, and checks certificates
against the Python build's own CA bundle, never SSL_CERT_FILE/SSL_CERT_DIR
(stand-ins run in Claude's environment, which must not pick who sees a
token; SPEC 9 drops proxy/CA overrides).

A service principal (an account's own app registration and its client
secret, stored as `entra.client_secret` with no refresh token) gets its
tokens with the client-credentials grant (`client_credentials`); gate check
checks a new secret that way before storing it. The browser (authorization
code + PKCE) and device-code sign-ins are gone (PLAN-v4 phase 3: the gateway
shows no web page and no code to type elsewhere); a refresh token stored
before keeps working. Tests point the authority at a local server with
testing.override(entra_authority=...).
"""
from __future__ import annotations

import base64
import json
import os
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from . import audit, testing, vault

# The Azure Databricks first-party resource (constant across tenants).
DATABRICKS_RESOURCE = "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d"
SCOPES = {
    "arm": "https://management.azure.com/.default",
    "management": "https://management.azure.com/.default",
    "storage": "https://storage.azure.com/.default",
    "graph": "https://graph.microsoft.com/.default",
    "databricks": f"{DATABRICKS_RESOURCE}/.default",
}
DEFAULT_AUTHORITY = "https://login.microsoftonline.com"


class EntraError(Exception):
    """Sign-in or token minting failed (message holds no secret). `codes`:
    Entra's AADSTS error codes, `error`: its OAuth error word (adapters.py
    tells expired, revoked and reauthentication-required apart by them)."""

    def __init__(self, message: str, codes: list[str] | None = None, error: str = ""):
        super().__init__(message)
        self.codes = list(codes or [])
        self.error = error


def authority() -> str:
    """The Entra authority. Tests set testing.override(entra_authority=...);
    production always uses login.microsoftonline.com (never an env var)."""
    o = testing.get("entra_authority")
    return (o or DEFAULT_AUTHORITY).rstrip("/")


def resolve_scope(scope: str) -> str:
    return SCOPES.get(scope, scope)


def scope_for_host(account: Any, host: str, scope: str | None = None) -> str:
    """The scope to request for an azure destination (SPEC 14). `account` is
    the form Account. One rule set with the http tool (web.azure_scope): a
    passed `scope` counts only for a listed `site`, must look like
    `…/.default`, and is never the audience of Resource Manager, Graph,
    Storage or Databricks (those go by host); registries are refused (crane
    does the exchange). Raises EntraError with a `gateway:` message."""
    from . import web
    try:
        return web.azure_scope(account, host, scope)
    except web.Refused as e:
        raise EntraError(str(e)) from None


# ---------------------------------------------------------------------------
# HTTP (no redirects, no proxies, the build's own CA bundle)
# ---------------------------------------------------------------------------


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never follow a redirect: urllib would resend headers the caller set
    (Authorization) to the new host. A 3xx surfaces as an HTTPError."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D401
        return None


def tls_context() -> ssl.SSLContext:
    """Certificate and host-name checking against the Python build's own CA
    bundle. SSL_CERT_FILE / SSL_CERT_DIR in the environment are ignored.
    Tests may pass testing.override(ssl_context=...)."""
    o = testing.get("ssl_context")
    if o is not None:
        return o
    p = ssl.get_default_verify_paths()
    cafile = p.openssl_cafile if p.openssl_cafile and os.path.isfile(p.openssl_cafile) else None
    capath = p.openssl_capath if p.openssl_capath and os.path.isdir(p.openssl_capath) else None
    if cafile or capath:
        return ssl.create_default_context(cafile=cafile, capath=capath)
    if not (os.environ.get(p.openssl_cafile_env) or os.environ.get(p.openssl_capath_env)):
        return ssl.create_default_context()
    # No bundle of our own and the environment names one: trust nothing.
    return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def opener() -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                       urllib.request.HTTPSHandler(context=tls_context()))


def urlopen(req: urllib.request.Request | str, timeout: float = 30) -> Any:
    """Open a request with no redirects, no proxies and the build's CA bundle."""
    return opener().open(req, timeout=timeout)


def is_redirect(e: urllib.error.HTTPError) -> bool:
    return 300 <= e.code < 400


# ---------------------------------------------------------------------------
# HTTP to Entra
# ---------------------------------------------------------------------------


def _post(url: str, form: dict[str, str]) -> dict[str, Any]:
    req = urllib.request.Request(url, data=urllib.parse.urlencode(form).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "Accept": "application/json"})
    try:
        with urlopen(req, timeout=30) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if is_redirect(e):
            raise EntraError("Entra answered with a redirect, which the gateway doesn't follow "
                             "with a sign-in") from None
        try:
            body = json.loads(e.read().decode())
        except Exception:  # noqa: BLE001
            body = {}
        msg = (body.get("error_description", "") or "").split("\r\n")[0] or body.get("error")
        codes = [str(c) for c in body.get("error_codes") or [] if isinstance(c, int)]
        err = body.get("error") if isinstance(body.get("error"), str) else ""
        raise EntraError(msg or f"HTTP {e.code}", codes, err) from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise EntraError(f"could not reach Entra: {type(e).__name__}") from None


def _token_url(tenant: str) -> str:
    return f"{authority()}/{tenant}/oauth2/v2.0/token"


def _claims(id_token: str) -> dict[str, Any]:
    try:
        part = id_token.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:  # noqa: BLE001
        return {}


# ---------------------------------------------------------------------------
# Access tokens (cache.age + rotation under the vault lock)
# ---------------------------------------------------------------------------


def _entra_record(data: dict[str, Any], account: str) -> dict[str, Any]:
    a = (data.get("accounts") or {}).get(account)
    if a is None:
        raise EntraError(f"gateway: no account named {account}")
    e = a.get("entra") or {}
    if not e.get("refresh_token") and not e.get("client_secret") and not e.get("client_certificate"):
        raise EntraError(f"gateway: {account} has no Entra credential; run gate check {account} "
                         "while the user is here")
    if not e.get("tenant_id") or not e.get("client_id"):
        raise EntraError(f"gateway: {account}'s sign-in is incomplete; run gate check {account}")
    return e


def access_token(account: str, scope: str) -> str:
    """A current access token for an account and scope. Reuses a cached token
    until two minutes before it expires; otherwise mints one under the vault
    lock and persists the rotated refresh token."""
    scope = resolve_scope(scope)
    cached = vault.cache_get(account, scope)
    if cached:
        return cached
    with vault.locked():
        again = vault.cache_get(account, scope)
        if again:
            return again
        data = vault.load()
        e = _entra_record(data, account)
        rt = e.get("refresh_token")
        if rt:
            tok = _post(_token_url(e["tenant_id"]), {
                "client_id": e["client_id"], "grant_type": "refresh_token",
                "refresh_token": rt, "scope": f"{scope} offline_access"})
        elif e.get("client_certificate"):
            tok = client_certificate(e["tenant_id"], e["client_id"], e["client_certificate"], scope)
        else:
            tok = client_credentials(e["tenant_id"], e["client_id"], e["client_secret"], scope)
        access = tok.get("access_token")
        if not access:
            raise EntraError(f"gateway: {account}'s sign-in was rejected; run gate check {account}")
        new_rt = tok.get("refresh_token")
        if rt and new_rt and new_rt != rt:
            e["refresh_token"] = new_rt
            e["refreshed"] = vault.now()
            data["accounts"][account]["entra"] = e
            vault.save(data)
        expires = time.time() + float(tok.get("expires_in", 3600))
        vault.cache_put(account, scope, access, expires)
    audit.use("entra", account, account, argv=["access-token", scope], secrets=[access])
    try:
        from . import scrub
        scrub.add_values([access])
    except Exception:  # noqa: BLE001
        pass
    return access


# ---------------------------------------------------------------------------
# ACR token exchange (for crane; cached)
# ---------------------------------------------------------------------------

ACR_USER = "00000000-0000-0000-0000-000000000000"


def acr_token(host: str, account: str) -> str:
    """An ACR refresh token for a registry host, exchanged from an ARM token
    and cached in cache.age (SPEC 9.5 crane)."""
    bare = host.split(":", 1)[0]
    ckey = f"acr:{bare}"
    cached = vault.cache_get(account, ckey)
    if cached:
        return cached
    with vault.locked():
        again = vault.cache_get(account, ckey)
        if again:
            return again
        data = vault.load()
        e = _entra_record(data, account)
        tenant = e["tenant_id"]
    arm = access_token(account, "arm")
    scheme = "http" if bare in ("127.0.0.1", "localhost", "::1") else "https"
    form = urllib.parse.urlencode({"grant_type": "access_token", "service": bare,
                                   "tenant": tenant, "access_token": arm}).encode()
    try:
        with urlopen(urllib.request.Request(
                f"{scheme}://{host}/oauth2/exchange", data=form,
                headers={"Content-Type": "application/x-www-form-urlencoded"}), timeout=30) as r:
            rt = json.loads(r.read().decode())["refresh_token"]
    except urllib.error.HTTPError as e:
        why = "it answered with a redirect, which isn't followed" if is_redirect(e) else f"HTTP {e.code}"
        raise EntraError(f"gateway: the registry's token exchange failed ({why})") from None
    except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
        raise EntraError(f"gateway: the registry's token exchange failed ({type(e).__name__})") from None
    # ACR refresh tokens last ~3 hours; cache conservatively for one hour.
    with vault.locked():
        vault.cache_put(account, ckey, rt, time.time() + 3600)
    try:
        from . import scrub
        scrub.add_values([rt])
    except Exception:  # noqa: BLE001
        pass
    return rt


# ---------------------------------------------------------------------------
# Service principals (client credentials)
# ---------------------------------------------------------------------------


def client_credentials(tenant: str, client_id: str, secret: str, scope: str) -> dict[str, Any]:
    """A token for a service principal (the client-credentials grant; scope a
    `.default` resource scope). Raises EntraError (no secret in its text)."""
    if not secret:
        raise EntraError("no client secret")
    tok = _post(_token_url(tenant), {"client_id": client_id, "client_secret": secret,
                                     "grant_type": "client_credentials", "scope": scope})
    if not tok.get("access_token"):
        raise EntraError("Entra gave no token")
    return tok


def client_certificate(tenant: str, client_id: str, pem: str, scope: str) -> dict[str, Any]:
    """A token for a service principal with a certificate (PLAN-v4 phase 7):
    the client-credentials grant with a client assertion (a JWT signed by the
    certificate's private key with the env's openssl, the key on a pipe).
    Raises EntraError (no key material in its text)."""
    from . import adapters
    try:
        cert, key = adapters.cert_parts(pem)
        url = _token_url(tenant)
        assertion = adapters.client_assertion(cert, key, client_id, url)
    except ValueError as e:
        raise EntraError(str(e)) from None
    finally:
        key = ""
    tok = _post(url, {"client_id": client_id, "grant_type": "client_credentials", "scope": scope,
                      "client_assertion_type":
                          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                      "client_assertion": assertion})
    if not tok.get("access_token"):
        raise EntraError("Entra gave no token")
    return tok
