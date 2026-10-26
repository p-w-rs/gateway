"""Account adapters and their states (PLAN-v4 phase 7, docs/dev/modules/accounts.md).

Each service the gateway holds credentials for has an adapter that names the
credential methods it supports and checks a stored credential with one cheap
API call, sent only to the account's bound host (consent.bound_ok) through
the gateway's own HTTP client (entra.urlopen: no redirects with credentials,
no proxies, the Python build's own CA bundle):

    github       a personal access token, fine-grained (github_pat_...) or
                 classic (ghp_...): GET /user on the account's API host
    huggingface  a user access token: GET /api/whoami-v2
    azure        a service principal's client secret or certificate (the
                 client-credentials grant; a certificate signs a client
                 assertion with the env's openssl), or the refresh token of
                 the gateway's browser sign-in (PLAN-0.11 §7; the refresh
                 grant; a rotated refresh token is saved)
    ml-catalog   the browser sign-in's refresh token (no check of its own:
                 configured once stored)

States (told apart from the service's own answers, never guessed):

    missing                    no credential stored
    configured                 stored, not checked yet (or the kind has no check)
    connected                  the last check succeeded
    expired                    the service says so (GitHub: 401 after the
                               expiry the token reported; Entra AADSTS7000222,
                               700082, 70043, 50173 for a lapsed grant)
    revoked                    the service refuses it (GitHub 401 before its
                               expiry, Hugging Face 401, Entra AADSTS7000215,
                               700016, 7000112)
    reauthentication_required  the service needs a person (Entra
                               interaction_required, MFA, consent, a
                               conditional-access policy; GitHub SSO)
    unknown                    no answer (network, rate limit, 5xx)

A browser login is never API authorization: the gateway's states come only
from its own stored credential and the service's API, never from a web
session, `gh auth status` or a cookie. No adapter needs a cookie or session
store: GitHub, Hugging Face and Azure all take API credentials (DECISIONS,
"PLAN-v4 phase 7"); an Entra refresh token is the only session-like state,
kept in the vault's `entra` record as before.

The check's outcome is kept in the vault (`accounts[NAME].status`: state,
checked_at, detail and safe facts such as the login, the token's kind and
expiry; never a value) and published as `account.state` events and in the
CONTRACT-v1 snapshot.
"""
from __future__ import annotations

import base64
import contextlib
import datetime
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

from . import consent, paths, vault
from . import form as formmod

STATES = ("missing", "configured", "connected", "expired", "revoked",
          "reauthentication_required", "unknown")
CHECKED_KINDS = ("github", "huggingface", "azure")
METHODS = {
    "github": ("personal access token (fine-grained or classic)",),
    "huggingface": ("user access token",),
    "azure": ("service principal client secret", "service principal certificate",
              "browser sign-in (sign_in = \"browser\": authorization code with PKCE)"),
    "api-key": ("API key",),
    "ml-catalog": ("browser sign-in (authorization code with PKCE)",),
    "pijul": ("ssh key",),
    "registry": ("username and token",),
}
# Entra's AADSTS codes, by state.
ENTRA_EXPIRED = {"7000222", "700082", "70043", "50173", "700024"}
ENTRA_REVOKED = {"7000215", "700016", "7000112", "700027", "50034", "50057", "50126"}
ENTRA_REAUTH = {"50076", "50079", "50158", "65001", "50105", "53003", "530003"}


@dataclass
class Check:
    state: str
    detail: str = ""                    # safe text for the person and Claude
    meta: dict[str, Any] = field(default_factory=dict)   # safe facts (login, token kind, expiry)
    checked_at: str = ""

    def public(self) -> dict[str, Any]:
        out = {"state": self.state, "detail": self.detail, "checked_at": self.checked_at}
        out.update({k: v for k, v in self.meta.items() if isinstance(v, (str, int, bool))})
        return out


def token_kind(kind: str, value: str) -> str:
    """What kind of token a value is, by its public prefix (never the value)."""
    if kind == "github":
        if value.startswith("github_pat_"):
            return "fine-grained personal access token"
        if value.startswith("ghp_"):
            return "classic personal access token"
        if value.startswith("gho_"):
            return "OAuth token"
        if value.startswith(("ghu_", "ghs_")):
            return "GitHub App token"
        return "token"
    if kind == "huggingface":
        return "user access token" if value.startswith("hf_") else "token"
    return "token"


def credential_of(kind: str, rec: dict[str, Any]) -> str:
    """The stored credential's kind in words, or "" when none is stored."""
    tok = (rec.get("token") or {}).get("value")
    e = rec.get("entra") or {}
    if kind in ("azure", "ml-catalog"):
        if e.get("client_certificate"):
            return "service principal certificate"
        if e.get("client_secret"):
            return "service principal client secret"
        if e.get("refresh_token"):
            return "browser sign-in" if e.get("kind") == "browser" else "refresh token"
        return ""
    if isinstance(tok, str) and tok and not vault.is_redacted(tok):
        return token_kind(kind, tok)
    if (rec.get("ssh_key") or {}).get("private"):
        return "ssh key"
    return ""


def stored_state(a: formmod.Account, rec: dict[str, Any]) -> Check:
    """The state as the vault knows it (no network): missing, configured, or
    the last check's outcome when the credential hasn't changed since."""
    cred = credential_of(a.kind, rec)
    if not cred:
        return Check("missing", f"no credential stored for {a.name}")
    st = rec.get("status") if isinstance(rec.get("status"), dict) else {}
    if st.get("state") in STATES and st.get("cred") == _cred_hash(a.kind, rec):
        return Check(st["state"], str(st.get("detail") or ""),
                     {k: v for k, v in (st.get("meta") or {}).items()
                      if isinstance(v, (str, int, bool))}, str(st.get("checked_at") or ""))
    return Check("configured", f"{cred} stored, not checked yet", {"credential": cred})


def _cred_hash(kind: str, rec: dict[str, Any]) -> str:
    """A short hash naming which credential a status belongs to (a new value
    makes the old status stale). sha256 of the value with a fixed label: the
    vault holds the value itself anyway, and this never leaves the vault."""
    e = rec.get("entra") or {}
    v = ((rec.get("token") or {}).get("value") or e.get("client_certificate")
         or e.get("client_secret") or e.get("refresh_token") or "")
    if not isinstance(v, str) or not v:
        return ""
    return hashlib.sha256(("gateway-status:" + v).encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# The checks
# ---------------------------------------------------------------------------


def _host_of(url: str) -> str:
    u = urllib.parse.urlsplit(url)
    return (u.hostname or "") + (f":{u.port}" if u.port else "")


def canonical_api(kind: str, host: str = "") -> str:
    """The production API base of a kind (never a test override): the host
    the binding is checked against."""
    from . import accounts as acctmod
    if kind == "github":
        h = acctmod._host_only(host or "github.com")
        return "https://api.github.com" if h == "github.com" else (
            f"https://api.{h}" if h.endswith(".ghe.com") else f"https://{host}/api/v3")
    return "https://huggingface.co"


def _bound(data: dict[str, Any], a: formmod.Account, url: str) -> str | None:
    """Why the check's URL may not get the credential, or None."""
    host = _host_of(url)
    if not consent.bound_ok(data, a.name, host) and not consent.bound_ok(
            data, a.name, host.split(":")[0]):
        return (f"{a.name}'s credential isn't bound to {host} (gate check {a.name} binds the "
                "approved destinations)")
    return None


def _expiry(headers: dict[str, str]) -> str:
    """GitHub's github-authentication-token-expiration header as ISO 8601."""
    h = {k.lower(): v for k, v in headers.items()}
    raw = h.get("github-authentication-token-expiration", "")
    m = re.match(r"(\d{4}-\d{2}-\d{2}) (\d{2}:\d{2}:\d{2})", raw or "")
    return f"{m.group(1)}T{m.group(2)}Z" if m else ""


def _past(iso: str) -> bool:
    try:
        t = datetime.datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)
    except ValueError:
        return False
    return t.timestamp() <= time.time()


def check_github(a: formmod.Account, rec: dict[str, Any], data: dict[str, Any]) -> Check:
    from . import gate_setup
    tok = (rec.get("token") or {}).get("value") or ""
    url = f"{gate_setup.api_base('github', a.host)}/user"
    why = _bound(data, a, canonical_api("github", a.host) + "/user")
    if why:
        return Check("unknown", why)
    meta: dict[str, Any] = {"credential": token_kind("github", tok)}
    prev = ((rec.get("status") or {}).get("meta") or {}).get("expires_at") or ""
    code, body, headers = gate_setup.http_json(url, tok)
    exp = _expiry(headers)
    if exp:
        meta["expires_at"] = exp
    if code == 200 and isinstance(body, dict):
        login = str(body.get("login") or "")
        if formmod.LOGIN_RE.fullmatch(login):
            meta["login"] = login
        if a.login and login.lower() != a.login.lower():
            return Check("revoked", f"the token belongs to another login, not {a.login}", meta)
        h = {k.lower(): v for k, v in headers.items()}
        scopes = h.get("x-oauth-scopes")
        if scopes is not None and re.fullmatch(r"[a-z0-9:_, -]{0,300}", scopes):
            meta["scopes"] = scopes
        return Check("connected", "GitHub accepted the token (GET /user)", meta)
    if code == 401:
        if (exp or prev) and _past(exp or prev):
            return Check("expired", f"GitHub refuses the token; it expired {(exp or prev)[:10]}",
                         {**meta, "expires_at": exp or prev})
        return Check("revoked", "GitHub refuses the token (401 Bad credentials): it was revoked "
                     "or deleted", meta)
    if code == 403:
        h = {k.lower(): v for k, v in headers.items()}
        if h.get("x-github-sso"):
            return Check("reauthentication_required", "GitHub wants the token authorized for an "
                         "organization's single sign-on (GitHub Settings > Applications)", meta)
        if h.get("x-ratelimit-remaining") == "0":
            return Check("unknown", "GitHub's rate limit; checked again later", meta)
        return Check("revoked", "GitHub refuses the token (403)", meta)
    return Check("unknown", f"GitHub didn't answer the check (HTTP {code or 'error'})", meta)


def check_huggingface(a: formmod.Account, rec: dict[str, Any], data: dict[str, Any]) -> Check:
    from . import gate_setup
    tok = (rec.get("token") or {}).get("value") or ""
    url = f"{gate_setup.api_base('hf')}/api/whoami-v2"
    why = _bound(data, a, canonical_api("huggingface") + "/api/whoami-v2")
    if why:
        return Check("unknown", why)
    meta: dict[str, Any] = {"credential": token_kind("huggingface", tok)}
    code, body, _h = gate_setup.http_json(url, tok)
    if code == 200 and isinstance(body, dict):
        name = str(body.get("name") or "")
        if formmod.LOGIN_RE.fullmatch(name):
            meta["login"] = name
        role = ((body.get("auth") or {}).get("accessToken") or {}).get("role")
        if isinstance(role, str) and re.fullmatch(r"[a-zA-Z-]{1,20}", role):
            meta["role"] = role
        return Check("connected", "Hugging Face accepted the token (whoami)", meta)
    if code == 401:
        return Check("revoked", "Hugging Face refuses the token (401): it was deleted or "
                     "invalidated", meta)
    return Check("unknown", f"Hugging Face didn't answer the check (HTTP {code or 'error'})", meta)


def _entra_state(e: Exception) -> tuple[str, str]:
    from . import entra
    codes = set(getattr(e, "codes", []) or [])
    err = getattr(e, "error", "") or ""
    text = str(e)
    for c in re.findall(r"AADSTS(\d{5,7})", text):
        codes.add(c)
    if codes & ENTRA_EXPIRED:
        return "expired", "Entra says the credential or its grant expired"
    if codes & ENTRA_REAUTH or err in ("interaction_required", "consent_required",
                                       "login_required"):
        return "reauthentication_required", ("Entra needs the person (MFA, consent or a "
                                             "conditional-access policy): a new browser sign-in "
                                             "(gate login), or a service principal")
    if codes & ENTRA_REVOKED or err in ("invalid_client", "unauthorized_client"):
        return "revoked", "Entra refuses the credential (deleted, wrong or disabled)"
    if isinstance(e, entra.EntraError) and "could not reach" in text:
        return "unknown", "Entra couldn't be reached"
    if err == "invalid_grant":
        return "expired", "Entra no longer accepts the grant"
    return "unknown", "Entra didn't accept the check for an unknown reason"


def check_azure(a: formmod.Account, rec: dict[str, Any], data: dict[str, Any]) -> Check:
    from . import accounts as acctmod
    from . import entra
    e = rec.get("entra") or {}
    url = entra._token_url(e.get("tenant_id") or a.tenant or "common")
    meta: dict[str, Any] = {"credential": credential_of("azure", rec)}
    # the credential use refuses one that doesn't fit the approved account
    # (PLAN-0.11 §19.5), so the check never sends it to Entra either
    ap = entra.approved_account(data, a.name)
    if e and (ap is None or not acctmod.entra_fits(ap, vault.entra_info(rec))):
        return Check("reauthentication_required", "needs a new sign-in: the stored one was made "
                     "for other settings than the approved ones (tenant, client_id, sign_in or "
                     f"scope), or {a.name} isn't approved; gate check {a.name}", meta)
    tenant, client = e.get("tenant_id") or a.tenant, e.get("client_id") or a.client_id
    arm = entra.SCOPES["arm"]
    what = "Azure Resource Manager"
    try:
        if e.get("client_certificate"):
            entra.client_certificate(tenant, client, e["client_certificate"], arm)
        elif e.get("client_secret"):
            entra.client_credentials(tenant, client, e["client_secret"], arm)
        elif e.get("refresh_token"):
            # a browser sign-in is checked with the scope it was made for (an
            # account signed in for Graph alone may get no ARM token at all)
            own = [t for t in str(e.get("scope") or "").split() if t != "offline_access"]
            scope = own[0] if own else arm
            if scope != arm:
                what = "the sign-in's scope"
            entra.access_token(a.name, scope, mode="modeless")   # rotates and saves the refresh token
        else:
            return Check("missing", f"no Entra credential stored for {a.name}")
    except entra.EntraError as err:
        st, why = _entra_state(err)
        return Check(st, why, meta)
    meta["tenant"] = tenant if isinstance(tenant, str) and len(tenant) < 100 else ""
    _ = url
    return Check("connected", f"Entra issued a token for {what}", meta)


def check(a: formmod.Account, rec: dict[str, Any], data: dict[str, Any]) -> Check:
    """One cheap check of a stored credential through the account's adapter."""
    cred = credential_of(a.kind, rec)
    if not cred:
        c = Check("missing", f"no credential stored for {a.name}")
    elif a.kind == "github":
        c = check_github(a, rec, data)
    elif a.kind == "huggingface":
        c = check_huggingface(a, rec, data)
    elif a.kind == "azure":
        c = check_azure(a, rec, data)
    else:
        c = Check("configured", f"{cred} stored; the gateway has no check for {a.kind} accounts",
                  {"credential": cred})
    c.checked_at = vault.now()
    return c


def record(name: str, kind: str, c: Check) -> None:
    """Keep a check's outcome in the vault (safe facts only) and audit it."""
    from . import audit
    with vault.edit() as d:
        rec = (d.get("accounts") or {}).get(name)
        if not isinstance(rec, dict):
            return
        rec["status"] = {"state": c.state, "detail": c.detail[:300], "checked_at": c.checked_at,
                         "meta": {k: v for k, v in c.meta.items() if isinstance(v, (str, int, bool))},
                         "cred": _cred_hash(kind, rec)}
    audit.log("account_state", account=name, state=c.state)


def check_and_record(name: str) -> Check:
    """Check account NAME (form + vault as they are) and record it."""
    data = vault.load()
    form = consent.load_form(data)
    a = form.accounts.get(name)
    if a is None:
        raise KeyError(name)
    rec = (data.get("accounts") or {}).get(name) or {}
    c = check(a, rec, data)
    if credential_of(a.kind, rec):
        record(name, a.kind, c)
    return c


def summary(form: formmod.Form, data: dict[str, Any]) -> list[dict[str, Any]]:
    """Every account's state as the vault knows it (no network): the
    /gate-accounts pane and CONTRACT-v1 snapshots."""
    out = []
    for n, a in form.accounts.items():
        rec = (data.get("accounts") or {}).get(n) or {}
        c = stored_state(a, rec)
        out.append({"account": n, "kind": a.kind, "state": c.state, "detail": c.detail,
                    "checked_at": c.checked_at or None,
                    "methods": list(METHODS.get(a.kind, ())),
                    **{k: v for k, v in c.meta.items() if k in ("login", "credential",
                                                                 "expires_at", "role")}})
    return out


# ---------------------------------------------------------------------------
# Azure certificates: a client assertion signed with the env's openssl
# ---------------------------------------------------------------------------

_PEM = re.compile(r"-----BEGIN ([A-Z0-9 ]+)-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END \1-----")


def pem_blocks(text: str) -> list[tuple[str, bytes]]:
    """(label, DER) for each PEM block of a text; ValueError when there is
    anything else in it."""
    if not isinstance(text, str) or len(text) > 16384:
        raise ValueError("not a PEM certificate and key")
    out = []
    rest = text
    for m in _PEM.finditer(text):
        try:
            der = base64.b64decode("".join(m.group(2).split()), validate=True)
        except ValueError:
            raise ValueError("a PEM block isn't base64") from None
        out.append((m.group(1), der))
        rest = rest.replace(m.group(0), "")
    if rest.strip() or not out:
        raise ValueError("not a PEM certificate and key (paste the certificate and its private "
                         "key, as PEM)")
    return out


def cert_parts(text: str) -> tuple[bytes, str]:
    """(certificate DER, private key PEM) from a PEM text holding both."""
    blocks = pem_blocks(text)
    certs = [der for label, der in blocks if label == "CERTIFICATE"]
    keys = [(label, der) for label, der in blocks if label.endswith("PRIVATE KEY")]
    if len(certs) < 1 or len(keys) != 1:
        raise ValueError("paste the certificate and its private key together, as PEM "
                         "(one CERTIFICATE block and one PRIVATE KEY block)")
    if "ENCRYPTED" in keys[0][0]:
        raise ValueError("the private key has a passphrase; export it without one for the "
                         "gateway (it stays in the gateway's encrypted vault)")
    label, der = keys[0]
    b64 = base64.b64encode(der).decode()
    pem = f"-----BEGIN {label}-----\n" + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64)) \
        + f"\n-----END {label}-----\n"
    return certs[0], pem


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def sign_rs256(key_pem: str, data: bytes) -> bytes:
    """An RS256 signature with the env's openssl, the key on an inherited
    pipe (/dev/fd/N): never a file or a command line."""
    openssl = paths.tool("openssl")
    r, w = os.pipe()
    try:
        os.write(w, key_pem.encode())
    finally:
        os.close(w)
    try:
        p = subprocess.run([openssl, "dgst", "-sha256", "-sign", f"/dev/fd/{r}"],
                           input=data, capture_output=True, timeout=30, pass_fds=(r,),
                           env={"PATH": "/usr/bin:/bin", "OPENSSL_CONF": "/dev/null"})
    finally:
        with contextlib.suppress(OSError):
            os.close(r)
    if p.returncode != 0 or not p.stdout:
        raise ValueError("openssl couldn't sign with that private key (is it an RSA key?)")
    return p.stdout


def client_assertion(cert_der: bytes, key_pem: str, client_id: str, audience: str) -> str:
    """The signed JWT Entra takes as a certificate's client assertion."""
    import uuid
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "x5t": _b64url(hashlib.sha1(cert_der).digest())}
    claims = {"aud": audience, "iss": client_id, "sub": client_id, "jti": str(uuid.uuid4()),
              "nbf": now - 60, "iat": now, "exp": now + 600}
    signing = (_b64url(json.dumps(header, separators=(",", ":")).encode()) + "." +
               _b64url(json.dumps(claims, separators=(",", ":")).encode()))
    sig = sign_rs256(key_pem, signing.encode())
    return signing + "." + _b64url(sig)
