"""Microsoft Entra ID (Azure AD) sign-in and tokens (SPEC 9.5, 14).

The vault stores a per-account credential and the pinned tenant/client it
was minted for (`accounts[NAME].entra = {refresh_token, client_id,
tenant_id, refreshed, kind: "browser", scope}` from the browser sign-in, or
`{client_secret | client_certificate, ..., kind: "service-principal"}`).
Which one is used follows the approved account (consent's snapshot): a
refresh token only for an account approved to sign in through the browser
(ml-catalog, or azure with sign_in = "browser") and only one the gateway's
browser sign-in stored; a service principal's secret or certificate only for
one approved as a service principal. A refresh token from an older gateway
(no kind) is never used: the account signs in again. `access_token(account,
scope)`:

- resolves the scope (arm, graph, storage, a listed Databricks workspace's
  resource, or a passed-through resource/scope);
- returns a cached access token from cache.age if one is valid for at least
  two more minutes;
- otherwise, under the vault lock, mints one from the refresh token, persists
  the rotated refresh token Entra hands back, and caches the access token
  (keyed by account + scope, with its expiry) in cache.age; the mint's
  audit line names the caller's `mode` (default "modeless").

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
checks a new secret that way before storing it.

The browser sign-in (PLAN-0.11 §7: authorization code + PKCE) runs in gated
(daemon/oauth.py), never here: `signin_start(name)` takes a sign-in lease
(POST /agent/signin/start: gate, below a session that draws dialogs) and
gated asks the person in its confirm dialog (Open / Cancel) before anything
happens; `signin_wait(lease, wait)` waits for the fixed outcome. The code,
the PKCE verifier and the tokens never leave gated. `accounts.request_scope`
and `catalog_scopes(client_id)` are the scopes it asks for. The device-code
sign-in is gone. Tests point the authority at a local server with
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

from . import accounts as acctmod
from . import audit, testing, vault

# The Azure Databricks first-party resource (constant across tenants).
DATABRICKS_RESOURCE = "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d"
SCOPES = {
    "arm": acctmod.ARM_SCOPE,
    "management": acctmod.ARM_SCOPE,
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


def catalog_scopes(client_id: str) -> tuple[str, str]:
    """(API scope, request scope) of an ml-catalog sign-in: fixed shapes
    around the catalog's validated client id, never a scope the catalog
    names (so a catalog can't get a management or Graph token minted)."""
    api = f"api://{client_id}/access_as_user"
    return api, f"{api} offline_access"


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
# The browser sign-in's client side (gated runs it: daemon/oauth.py)
# ---------------------------------------------------------------------------

SIGNIN_STEP = 25.0          # one long poll of /agent/signin/wait


def signin_start(name: str) -> dict[str, Any]:
    """A sign-in lease for account `name` (POST /agent/signin/start):
    {"available": True, "lease"}, or {"available": False, "reason",
    "message"} where no confirm dialog can open here (gated's fixed clause),
    or with "refused": True and gated's whole fixed sentence. The daemon is
    started once when nothing answers."""
    from .daemon import client, lifecycle
    started = False
    while True:
        try:
            return client.call("POST", "/agent/signin/start", {"account": name}, timeout=30)
        except client.Unreachable as e:
            why = e.message.removeprefix("gateway: ")
            if not started:
                try:
                    lifecycle.ensure_running()
                    started = True
                    continue
                except client.DaemonError as e2:
                    why = e2.message.removeprefix("gateway: ")
            return {"available": False, "reason": "unreachable",
                    "message": f"the gateway daemon couldn't be reached ({why})"}
        except client.DaemonError as e:
            return {"available": False, "reason": e.code, "message": e.message, "refused": True}


def signin_wait(lease: str, wait: float) -> dict[str, Any]:
    """One long poll for the sign-in's outcome: {"state": "asking" | "open" |
    "done", "outcome", "message"} (fixed texts; never a code or a token)."""
    from .daemon import client
    wait = max(0.0, min(SIGNIN_STEP, wait))
    return client.call("POST", "/agent/signin/wait", {"lease": lease, "wait": wait},
                       timeout=wait + 15)


# ---------------------------------------------------------------------------
# Access tokens (cache.age + rotation under the vault lock)
# ---------------------------------------------------------------------------


def approved_sign_in(data: dict[str, Any], account: str) -> str:
    """How the approved account gets its tokens: "browser" (ml-catalog, or
    azure approved with sign_in = "browser"), "service-principal", or ""
    when the account isn't approved at all."""
    snap = (((data.get("approved") or {}).get("rights") or {}).get("accounts") or {}).get(account)
    if not isinstance(snap, dict):
        return ""
    if snap.get("kind") == "ml-catalog" or snap.get("sign_in") == "browser":
        return "browser"
    return "service-principal"


class _Approved:
    """The approved account's sign-in settings (the vault's approved
    snapshot): what accounts.entra_fits judges a stored credential against.
    They are the effective ones: a change of tenant, client_id, sign_in or
    scope waits for the user's OK (consent), so until then the approved value
    applies."""

    def __init__(self, snap: dict[str, Any]):
        self.kind = str(snap.get("kind") or "")
        self.tenant = str(snap.get("tenant") or "")
        self.client_id = str(snap.get("client_id") or "")
        self.sign_in = "browser" if snap.get("sign_in") == "browser" else ""
        self.scope = str(snap.get("scope") or "")


def approved_account(data: dict[str, Any], account: str) -> _Approved | None:
    snap = (((data.get("approved") or {}).get("rights") or {}).get("accounts") or {}).get(account)
    return _Approved(snap) if isinstance(snap, dict) else None


def _older_text(account: str) -> str:
    """Why a refresh token without the browser sign-in's kind isn't used (an
    older gateway stored it; an export never carries one, PLAN-0.11 §19.12)."""
    return (f"gateway: {account}'s sign-in is from an older gateway, which isn't used any more; "
            f"run gate check {account} while the user is here (a browser sign-in)")


def _entra_record(data: dict[str, Any], account: str) -> dict[str, Any]:
    """The account's Entra record, holding only the credential its approved
    way of signing in uses (a browser sign-in's refresh token, or a service
    principal's secret or certificate). A stored credential made for other
    settings than the effective (approved) ones, after an approved change of
    tenant, client_id, sign_in or scope, is refused until a new sign-in
    (PLAN-0.11 §19.5: accounts.entra_fits, the rule gate check and the status
    lines use)."""
    a = (data.get("accounts") or {}).get(account)
    if a is None:
        raise EntraError(f"gateway: no account named {account}")
    e = dict(a.get("entra") or {})
    how = approved_sign_in(data, account)
    if how == "browser":
        older = bool(e.get("refresh_token")) and e.get("kind") != "browser"
        e = {k: v for k, v in e.items() if k not in ("client_secret", "client_certificate")}
        if older:
            raise EntraError(_older_text(account))
    else:
        e.pop("refresh_token", None)
    if not e.get("refresh_token") and not e.get("client_secret") and not e.get("client_certificate"):
        raise EntraError(f"gateway: {account} has no Entra credential; run gate check {account} "
                         "while the user is here")
    if not e.get("tenant_id") or not e.get("client_id"):
        raise EntraError(f"gateway: {account}'s sign-in is incomplete; run gate check {account}")
    ap = approved_account(data, account)
    if ap is None:
        raise EntraError(f"gateway: {account} isn't approved, so its stored sign-in isn't used; "
                         f"run gate check {account} while the user is here")
    if not acctmod.entra_fits(ap, vault.entra_info(a)):
        raise EntraError(f"gateway: {account}'s stored sign-in was made for other settings (its "
                         "tenant, client_id, sign_in or scope changed since) and isn't used; run "
                         f"gate check {account} while the user is here (a new sign-in)")
    return e


def access_token(account: str, scope: str, mode: str = "modeless") -> str:
    """A current access token for an account and scope. Reuses a cached token
    until two minutes before it expires; otherwise mints one under the vault
    lock and persists the rotated refresh token. `mode`: the caller's, for
    the audit line of a mint (lead decision 19.8)."""
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
            stored = data["accounts"][account]["entra"]
            stored["refresh_token"] = new_rt
            stored["refreshed"] = vault.now()
            vault.save(data)
        expires = time.time() + float(tok.get("expires_in", 3600))
        vault.cache_put(account, scope, access, expires)
    audit.use("entra", account, account, argv=["access-token", scope], secrets=[access], mode=mode)
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


def acr_token(host: str, account: str, mode: str = "modeless") -> str:
    """An ACR refresh token for a registry host, exchanged from an ARM token
    and cached in cache.age (SPEC 9.5 crane; `mode` as for access_token)."""
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
    arm = access_token(account, "arm", mode=mode)
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
