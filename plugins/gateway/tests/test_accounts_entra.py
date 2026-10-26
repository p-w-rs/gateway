"""entra.py (SPEC 9.5, 14): access tokens with cache.age, refresh-token
rotation under the lock, scope mapping and the ACR exchange; and the browser
sign-in (PLAN-0.11 §7: authorization code + PKCE, run by gated,
daemon/oauth.py): its form keys and consent, the confirm dialog (Open /
Cancel), the 127.0.0.1 listener, the state and PKCE checks, the token
exchange without redirects, the tokens stored by gated only, one sign-in at a
time, the lease, no display, the timeout, and hooks/tool_guard.sh's
browser-tool deny while a sign-in runs. A real gated (harness_daemon) with
the fake OAuth server (harness_oauth) and the `browser` knob's program; the
sign-ins' steps also in process (a fake daemon around the real vault): the
outcome against the vault when the timer or gated's stop meets the code
exchange, one valid callback, the account's rechecks. The status lines and
gate check share one rule for an Entra credential (accounts.entra_fits)."""
from __future__ import annotations

import contextlib
import http.server
import io
import json
import os
import re
import secrets
import select
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
from pathlib import Path
from types import SimpleNamespace

import harness as H
import harness_accounts as HA
import harness_daemon as D
import harness_oauth as HO
from gateway import accounts as acctmod
from gateway import consent, entra, gate, gate_setup, hooks_session, popup, vault
from gateway import form as formmod
from gateway.daemon import dialogs as dmod
from gateway.daemon import oauth

AZ_BASE = ('[accounts.azure]\nkind = "azure"\ntenant = "contoso.onmicrosoft.com"\n'
           'databricks = ["adb-123.7.azuredatabricks.net"]\nstorage = ["examplestore"]\n'
           'sites = ["custom.example.com"]\n')
# a browser sign-in (its refresh token): sign_in = "browser" with a public client
AZ = AZ_BASE + 'sign_in = "browser"\nclient_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"\n'
# a service principal (the default)
AZ_SP = AZ_BASE
# the same with its own app registration (a stored secret is used only for
# the approved tenant and client: PLAN-0.11 §19.5)
SP_CLIENT = "99999999-8888-7777-6666-555555555555"
AZ_SPC = AZ_SP + f'client_id = "{SP_CLIENT}"\n'
# a browser sign-in made for AZ's settings (its tenant, client and request
# scope: accounts.entra_fits; the fixtures fit their form, PLAN-0.11 §19.5)
ENTRA = {"azure": {"refresh_token": "SEED-REFRESH-0", "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
                   "tenant_id": "contoso.onmicrosoft.com", "refreshed": "x", "kind": "browser",
                   "scope": "https://management.azure.com/.default offline_access"}}


def test_access_token_mints_caches_and_rotates():
    srv = HA.EntraServer()
    try:
        with H.gateway_env() as env:
            env.o.extra["entra_authority"] = srv.authority
            HA.build_vault(env, AZ, entra=ENTRA)
            t1 = entra.access_token("azure", "arm")
            assert t1.startswith("ACCESS-1")
            assert srv.counter == 1
            # the rotated refresh token was persisted
            assert vault.load()["accounts"]["azure"]["entra"]["refresh_token"] == "ROT-REFRESH-1"
            # a second call for the same scope is served from the cache (no mint)
            t1b = entra.access_token("azure", "arm")
            assert t1b == t1 and srv.counter == 1
            # a different scope mints again and rotates again
            t2 = entra.access_token("azure", "graph")
            assert srv.counter == 2
            assert vault.load()["accounts"]["azure"]["entra"]["refresh_token"] == "ROT-REFRESH-2"
            # the request carried the resolved scope
            scopes = [f.get("scope", "") for f in srv.calls]
            assert any("management.azure.com/.default" in s for s in scopes)
            assert any("graph.microsoft.com/.default" in s for s in scopes)
    finally:
        srv.close()


def test_a_minted_token_is_audited_with_its_callers_mode():
    """Lead decision 19.8 (verify013): a mint's use line names the mode its
    caller decided in ("modeless" unless it says)."""
    from gateway import audit
    srv = HA.EntraServer()
    try:
        with H.gateway_env() as env:
            env.o.extra["entra_authority"] = srv.authority
            HA.build_vault(env, AZ, entra=ENTRA)
            entra.access_token("azure", "arm", mode="auto")
            entra.access_token("azure", "graph")
            uses = [r for r in audit.read(0) if r.get("event") == "use" and r.get("tool") == "entra"]
            assert [u.get("mode") for u in uses] == ["auto", "modeless"], uses
    finally:
        srv.close()


def test_cache_expiry_forces_a_remint():
    srv = HA.EntraServer()
    try:
        with H.gateway_env() as env:
            env.o.extra["entra_authority"] = srv.authority
            HA.build_vault(env, AZ, entra=ENTRA)
            entra.access_token("azure", "arm")
            # expire the cached token in the past
            with vault.locked():
                vault.cache_put("azure", entra.SCOPES["arm"], "OLD", time.time() - 10)
            entra.access_token("azure", "arm")
            assert srv.counter == 2, "an expired cache entry must force a re-mint"
    finally:
        srv.close()


def test_scope_for_host_mapping():
    a = formmod.parse_text(AZ, Path("/x")).accounts["azure"]
    assert entra.scope_for_host(a, "management.azure.com") == entra.SCOPES["arm"]
    assert entra.scope_for_host(a, "graph.microsoft.com") == entra.SCOPES["graph"]
    assert entra.scope_for_host(a, "adb-123.7.azuredatabricks.net") == entra.SCOPES["databricks"]
    assert entra.SCOPES["databricks"].startswith("2ff814a6-3304-4ab8-85cb-cd0e6f879c1d/")
    assert entra.scope_for_host(a, "examplestore.blob.core.windows.net") == entra.SCOPES["storage"]
    assert entra.scope_for_host(a, "examplestore.dfs.core.windows.net") == entra.SCOPES["storage"]
    # a listed site needs an explicit scope
    try:
        entra.scope_for_host(a, "custom.example.com")
        raise AssertionError("a listed site must demand an explicit scope")
    except entra.EntraError as e:
        assert "pass scope=" in str(e)
    assert entra.scope_for_host(a, "custom.example.com", "api://X/.default") == "api://X/.default"
    # phase B request (ux): the same rules as the http tool: a listed site
    # never gets a first-party audience, and a scope must look like .../.default
    for bad in ("https://management.azure.com/.default", "https://x.blob.core.windows.net/.default",
                entra.SCOPES["databricks"], "not a scope"):
        try:
            entra.scope_for_host(a, "custom.example.com", bad)
            raise AssertionError(f"{bad} must be refused for a listed site")
        except entra.EntraError as e:
            assert str(e).startswith("gateway:"), e
    # a passed scope doesn't redirect a host the gateway maps itself
    assert entra.scope_for_host(a, "management.azure.com", "api://X/.default") == entra.SCOPES["arm"]
    # a host that isn't a destination at all
    try:
        entra.scope_for_host(a, "evil.example.com")
        raise AssertionError("an unknown host has no scope")
    except entra.EntraError:
        pass


def test_access_token_refuses_without_signin():
    with H.gateway_env() as env:
        HA.build_vault(env, AZ)  # no entra record
        try:
            entra.access_token("azure", "arm")
            raise AssertionError("no refresh token -> must refuse")
        except entra.EntraError as e:
            assert "has no Entra credential" in str(e) and "gate check azure" in str(e)


def test_a_service_principal_gets_tokens_with_client_credentials():
    srv = HA.EntraServer(secret="sp-secret-for-the-test-0001")
    try:
        with H.gateway_env() as env:
            env.o.extra["entra_authority"] = srv.authority
            sp = {"azure": {"client_secret": "sp-secret-for-the-test-0001",
                            "client_id": SP_CLIENT, "tenant_id": "contoso.onmicrosoft.com",
                            "refreshed": "x", "kind": "service-principal"}}
            HA.build_vault(env, AZ_SPC, entra=sp)
            t = entra.access_token("azure", "arm")
            assert t.startswith("ACCESS-1") and srv.calls[-1]["grant_type"] == "client_credentials"
            assert srv.calls[-1]["client_secret"] == "sp-secret-for-the-test-0001"
            assert "refresh_token" not in vault.load()["accounts"]["azure"]["entra"]
            assert entra.access_token("azure", "arm") == t and srv.counter == 1, "cached"
            try:
                entra.client_credentials("11111111-2222-3333-4444-555555555555",
                                         "99999999-8888-7777-6666-555555555555", "wrong", entra.SCOPES["arm"])
                raise AssertionError("a wrong secret must be refused")
            except entra.EntraError as e:
                assert "Invalid client secret" in str(e) and "wrong" not in str(e)
    finally:
        srv.close()


def test_acr_token_exchange_and_cache():
    srv = HA.EntraServer()
    exchanges = []

    class RH(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            n = int(self.headers.get("Content-Length") or 0)
            form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(n).decode()).items()}
            exchanges.append(form)
            out = json.dumps({"refresh_token": "ACR-REFRESH-" + str(len(exchanges))}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

    port = HA.free_port()
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", port), RH)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with H.gateway_env() as env:
            env.o.extra["entra_authority"] = srv.authority
            HA.build_vault(env, AZ, entra=ENTRA)
            host = f"127.0.0.1:{port}"
            rt = entra.acr_token(host, "azure", mode="acceptEdits")
            assert rt == "ACR-REFRESH-1"
            from gateway import audit
            mint = [r for r in audit.read(0) if r.get("event") == "use" and r.get("tool") == "entra"]
            assert mint and mint[-1].get("mode") == "acceptEdits", "the ARM mint names crane's mode"
            assert exchanges and exchanges[0]["grant_type"] == "access_token"
            assert exchanges[0]["service"] == "127.0.0.1"
            # cached: a second call does not exchange again
            rt2 = entra.acr_token(host, "azure")
            assert rt2 == rt and len(exchanges) == 1
    finally:
        srv.close()
        httpd.shutdown()
        httpd.server_close()


# ---------------------------------------------------------------------------
# The HTTP client: no redirects, no proxies, the build's own CA bundle
# ---------------------------------------------------------------------------


class _Redirector:
    """Answers every request with `code` and Location: target + path."""

    def __init__(self, target: str, code: int = 302):
        server = self
        self.target, self.code = target.rstrip("/"), code

        class R(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _any(self):
                n = int(self.headers.get("Content-Length") or 0)
                if n:
                    self.rfile.read(n)
                self.send_response(server.code)
                self.send_header("Location", server.target + self.path)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_POST = _any

        self.port = HA.free_port()
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", self.port), R)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.port}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


def test_token_endpoint_and_acr_exchange_do_not_follow_redirects():
    evil = HA.RecorderServer(reply={"access_token": "EVIL", "refresh_token": "EVIL-RT",
                                    "expires_in": 3600})
    red = _Redirector(evil.url)
    try:
        with H.gateway_env() as env:
            env.o.extra["entra_authority"] = red.url
            HA.build_vault(env, AZ, entra=ENTRA)
            try:
                entra.access_token("azure", "arm")
                raise AssertionError("a redirected token endpoint must not be followed")
            except entra.EntraError as e:
                assert "redirect" in str(e)
            # the ACR exchange with a cached ARM token, at a redirecting registry
            with vault.locked():
                vault.cache_put("azure", entra.SCOPES["arm"], "ARM-TOKEN-FOR-ACR-0123456",
                                time.time() + 3600)
            try:
                entra.acr_token(f"127.0.0.1:{red.port}", "azure")
                raise AssertionError("a redirected ACR exchange must not be followed")
            except entra.EntraError as e:
                assert "redirect" in str(e)
            assert not evil.calls, "nothing may be sent on to the redirect target"
            # the refresh token was not rotated by the attacker's answer
            assert vault.load()["accounts"]["azure"]["entra"]["refresh_token"] == "SEED-REFRESH-0"
    finally:
        red.close()
        evil.close()


def test_token_minting_ignores_proxy_variables():
    srv = HA.EntraServer()
    evil = HA.RecorderServer(reply={"access_token": "EVIL", "expires_in": 3600})
    try:
        with H.gateway_env() as env:
            env.o.extra["entra_authority"] = srv.authority
            HA.build_vault(env, AZ, entra=ENTRA)
            with HA.env_vars(http_proxy=evil.url, HTTP_PROXY=evil.url, https_proxy=evil.url,
                             HTTPS_PROXY=evil.url, no_proxy=None, NO_PROXY=None):
                tok = entra.access_token("azure", "arm")
            assert tok.startswith("ACCESS-1"), tok
            assert not evil.calls and not evil.saw("SEED-REFRESH-0"), \
                "a proxy in Claude's environment must never see the refresh token"
    finally:
        srv.close()
        evil.close()


def test_urlopen_ignores_ssl_cert_file():
    import ssl
    import urllib.error
    with H.gateway_env() as env:
        tls = HA.self_signed(Path(env.root) / "tls")
        assert tls is not None, "these tests need an openssl binary for a throwaway certificate"
        srv = HA.TLSServer(*tls)
        try:
            # control: trusting the certificate explicitly works, so the server is fine
            env.o.extra["ssl_context"] = ssl.create_default_context(cafile=tls[0])
            with entra.urlopen(srv.url, timeout=10) as r:
                assert json.loads(r.read())["tls"] is True
            del env.o.extra["ssl_context"]
            # SSL_CERT_FILE / SSL_CERT_DIR naming the interceptor's certificate are ignored
            with HA.env_vars(SSL_CERT_FILE=tls[0], SSL_CERT_DIR=str(Path(tls[0]).parent)):
                try:
                    entra.urlopen(srv.url, timeout=10).close()
                    raise AssertionError("SSL_CERT_FILE must not make the gateway trust a certificate")
                except urllib.error.URLError as e:
                    assert "CERTIFICATE_VERIFY_FAILED" in str(e) or "certificate" in str(e).lower(), e
        finally:
            srv.close()


# ---------------------------------------------------------------------------
# Which stored credential is used (PLAN-0.11 §7: no 0.6-era refresh tokens)
# ---------------------------------------------------------------------------


def test_an_older_gateways_refresh_token_is_never_used():
    """A refresh token without the browser sign-in's kind (an older gateway's
    device-code or browser sign-in) mints nothing: the account signs in again."""
    srv = HA.EntraServer()
    try:
        with H.gateway_env() as env:
            env.o.extra["entra_authority"] = srv.authority
            old = {"azure": {k: v for k, v in ENTRA["azure"].items() if k != "kind"}}
            HA.build_vault(env, AZ, entra=old)
            try:
                entra.access_token("azure", "arm")
                raise AssertionError("an older gateway's refresh token was used")
            except entra.EntraError as e:
                assert "older gateway" in str(e) and "gate check azure" in str(e), e
            assert srv.calls == [], "nothing was sent to Entra"
    finally:
        srv.close()


def test_the_approved_way_of_signing_in_picks_the_credential():
    """A service principal's account never uses a refresh token stored beside
    its secret, and a browser account never uses a client secret."""
    srv = HA.EntraServer(secret="sp-secret-for-the-test-0002")
    both = {"azure": {**ENTRA["azure"], "client_secret": "sp-secret-for-the-test-0002"}}
    try:
        with H.gateway_env() as env:
            env.o.extra["entra_authority"] = srv.authority
            HA.build_vault(env, AZ_SPC, entra={"azure": {**both["azure"], "client_id": SP_CLIENT}})
            entra.access_token("azure", "arm")
            assert srv.calls[-1]["grant_type"] == "client_credentials", srv.calls[-1]["grant_type"]
        with H.gateway_env() as env:
            env.o.extra["entra_authority"] = srv.authority
            HA.build_vault(env, AZ, entra=both)
            entra.access_token("azure", "arm")
            assert srv.calls[-1]["grant_type"] == "refresh_token"
            assert "client_secret" not in srv.calls[-1]
            assert vault.load()["accounts"]["azure"]["entra"]["client_secret"], "nothing dropped"
    finally:
        srv.close()


def test_a_credential_that_doesnt_fit_the_approved_account_is_refused_at_use():
    """PLAN-0.11 §19.5 (WS-6): after an approved change of tenant, client_id,
    sign_in or scope, the stored credential (made for the old settings) is
    refused when used, until a new sign-in, not only shown as needing one;
    nothing goes to Entra. A change that waits for the OK changes nothing:
    the approved settings still apply. Tokens minted with the old settings
    (an access token, an ACR token) aren't handed out from the cache either:
    the approval drops them."""
    srv = HA.EntraServer(secret="sp-secret-for-the-test-0003")
    sp = {"azure": {"client_secret": "sp-secret-for-the-test-0003", "client_id": SP_CLIENT,
                    "tenant_id": "contoso.onmicrosoft.com", "refreshed": "x",
                    "kind": "service-principal"}}
    graph = 'scope = "https://graph.microsoft.com/.default"\n'
    try:
        for form, ent, changed in (
                (AZ, ENTRA, AZ.replace("contoso.onmicrosoft.com", "fabrikam.onmicrosoft.com")),
                (AZ, ENTRA, AZ.replace("04b07795-8ddb-461a-bbee-02f9e1bf7b46",
                                       "22222222-2222-2222-2222-222222222222")),
                (AZ, ENTRA, AZ + graph),
                (AZ_SPC, sp, AZ_SPC.replace(SP_CLIENT, "77777777-7777-7777-7777-777777777777")),
                (AZ_SPC, sp, AZ_SPC.replace("contoso.onmicrosoft.com", "fabrikam.onmicrosoft.com"))):
            with H.gateway_env() as env:
                env.o.extra["entra_authority"] = srv.authority
                HA.build_vault(env, form, entra=ent)
                assert entra.access_token("azure", "arm").startswith("ACCESS-"), "it fits: used"
                with vault.locked():     # an ACR token minted with the old settings
                    vault.cache_put("azure", "acr:127.0.0.1", "ACR-OLD-SETTINGS", time.time() + 3600)
                env.write_form(changed)
                assert consent.compute(env.form(), vault.load()).pending_for("azure"), changed
                assert entra.access_token("azure", "graph").startswith("ACCESS-"), \
                    "waiting for the OK: the approved settings apply"
                consent.approve("azure", form=env.form(), keep_credentials=True)
                n = len(srv.calls)
                for scope in ("arm", "graph"):
                    try:
                        entra.access_token("azure", scope)
                        raise AssertionError(f"a token for the old settings was used: {changed}")
                    except entra.EntraError as e:
                        assert "made for other settings" in str(e) and "gate check azure" in str(e), e
                try:
                    entra.acr_token("127.0.0.1:9", "azure")
                    raise AssertionError(f"an ACR token for the old settings was used: {changed}")
                except entra.EntraError as e:
                    assert "made for other settings" in str(e), e
                assert len(srv.calls) == n, "nothing went to Entra"
    finally:
        srv.close()


def test_an_account_that_isnt_approved_never_uses_its_stored_sign_in():
    """A stored Entra credential (a browser sign-in's refresh token or a
    service principal's secret) is refused while its account has no approval
    at all (a refresh token because no approved browser sign-in exists, a
    secret because nothing approves it); nothing goes to Entra."""
    srv = HA.EntraServer(secret="sp-secret-for-the-test-0004")
    sp = {"azure": {"client_secret": "sp-secret-for-the-test-0004", "client_id": SP_CLIENT,
                    "tenant_id": "contoso.onmicrosoft.com", "refreshed": "x",
                    "kind": "service-principal"}}
    try:
        for form, ent, why in ((AZ, ENTRA, "no Entra credential"), (AZ_SPC, sp, "isn't approved")):
            with H.gateway_env() as env:
                env.o.extra["entra_authority"] = srv.authority
                HA.build_vault(env, form, entra=ent, approve=False)
                assert entra.approved_account(vault.load(), "azure") is None
                try:
                    entra.access_token("azure", "arm")
                    raise AssertionError(f"an unapproved account's sign-in was used: {form}")
                except entra.EntraError as e:
                    assert why in str(e) and "gate check azure" in str(e), e
                assert srv.calls == [], "nothing went to Entra"
    finally:
        srv.close()


def test_the_account_check_never_sends_a_credential_that_doesnt_fit():
    """§19.5 (WS-6 review should-fix 2): the account check sent a service
    principal's secret to its old tenant after an approved tenant change and
    said "connected", though the credential is refused at use. Now it says
    the account needs a new sign-in and contacts nobody; while the change
    waits for the OK (the approved settings apply) it is checked as before."""
    from gateway import adapters
    srv = HA.EntraServer(secret="sp-secret-for-the-test-0005")
    sp = {"azure": {"client_secret": "sp-secret-for-the-test-0005", "client_id": SP_CLIENT,
                    "tenant_id": "contoso.onmicrosoft.com", "refreshed": "x",
                    "kind": "service-principal"}}
    try:
        with H.gateway_env() as env:
            env.o.extra["entra_authority"] = srv.authority
            HA.build_vault(env, AZ_SPC, entra=sp)
            assert adapters.check_and_record("azure").state == "connected"
            env.write_form(AZ_SPC.replace("contoso.onmicrosoft.com", "fabrikam.onmicrosoft.com"))
            assert adapters.check_and_record("azure").state == "connected", "waiting for the OK"
            consent.approve("azure", form=env.form(), keep_credentials=True)
            n = len(srv.calls)
            c = adapters.check_and_record("azure")
            assert c.state == "reauthentication_required" and "needs a new sign-in" in c.detail, c
            assert "gate check azure" in c.detail, c.detail
            assert len(srv.calls) == n, "nothing went to Entra"
    finally:
        srv.close()


# ---------------------------------------------------------------------------
# The form keys and consent (PLAN-0.11 §7.4)
# ---------------------------------------------------------------------------

CLIENT = "11111111-1111-1111-1111-111111111111"
AZB = ('[accounts.work-azure]\nkind = "azure"\ntenant = "contoso.onmicrosoft.com"\n'
       f'client_id = "{CLIENT}"\nsign_in = "browser"\n')
AZB_SCOPE = "https://management.azure.com/.default offline_access"


def _problems(text: str) -> list[str]:
    return [p.render() for p in formmod.parse_text(text, Path("gateway.toml")).problems
            if p.level == "error"]


def test_sign_in_keys_parse_and_are_checked():
    f = formmod.parse_text(AZB + 'scope = "https://graph.microsoft.com/.default offline_access"\n',
                           Path("gateway.toml"))
    a = f.accounts["work-azure"]
    assert a.sign_in == "browser" and a.scope == "https://graph.microsoft.com/.default"
    assert acctmod.request_scope(a) == "https://graph.microsoft.com/.default offline_access"
    assert acctmod.request_scope(formmod.parse_text(AZB, Path("g")).accounts["work-azure"]) == AZB_SCOPE
    sp = formmod.parse_text(AZ_SP + 'sign_in = "service-principal"\n', Path("g")).accounts["azure"]
    assert sp.sign_in == "", "a service principal is the default, written or not"
    base = AZB.replace('sign_in = "browser"\n', "")
    for bad, word in (('sign_in = "device-code"\n', "sign_in"), ('sign_in = true\n', "sign_in"),
                      ('sign_in = "browser"\nscope = ""\n', "scope"),
                      ('sign_in = "browser"\nscope = "a b c d e f g h i"\n', "scope"),
                      ('sign_in = "browser"\nscope = "x\\"y"\n', "scope"),
                      ('sign_in = "browser"\nscope = "offline_access"\n', "scope")):
        assert any(word in p for p in _problems(base + bad)), (bad, _problems(base + bad))
    assert _problems(base + 'sign_in = "browser"\nscope = "api://x/.default"\n') == []
    warn = [p.render() for p in formmod.parse_text(base + 'scope = "api://x/.default"\n', Path("g")).problems
            if p.level == "warning"]
    assert any("only with sign_in" in w for w in warn), warn
    nocl = '[accounts.az]\nkind = "azure"\ntenant = "contoso.com"\nsign_in = "browser"\n'
    assert any("needs client_id" in p for p in _problems(nocl)), _problems(nocl)
    cat = '[accounts.models]\nkind = "ml-catalog"\nhost = "catalog.example.com"\n'
    assert formmod.parse_text(cat, Path("g")).accounts["models"].tenant == ""
    t = formmod.parse_text(cat + 'tenant = "Contoso.onmicrosoft.com"\n', Path("g"))
    assert t.accounts["models"].tenant == "contoso.onmicrosoft.com"
    assert any("tenant" in p for p in _problems(cat + 'tenant = "not a tenant"\n'))


def test_changing_a_sign_in_key_is_a_widening_and_an_older_approval_reads_the_same():
    with H.gateway_env() as env:
        HA.build_vault(env, AZ_SP)
        for same in (AZ_SP, AZ_SP + 'sign_in = "service-principal"\n'):
            env.write_form(same)
            assert consent.compute(env.form(), vault.load()).pending_for("azure") == [], same
        env.write_form(AZ_SP + 'sign_in = "browser"\nclient_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"\n')
        eff = consent.compute(env.form(), vault.load())
        lines = [c.what for c in eff.pending_for("azure")]
        assert "sign_in service-principal -> browser (needs a new sign-in)" in lines, lines
        assert eff.accounts["azure"].sign_in is None, "the approved way applies meanwhile"
    with H.gateway_env() as env:
        HA.build_vault(env, AZB)
        env.write_form(AZB + 'scope = "https://graph.microsoft.com/.default"\n')
        lines = [c.what for c in consent.compute(env.form(), vault.load()).pending_for("work-azure")]
        assert any(x.startswith("scope unset -> https://graph") and "new sign-in" in x for x in lines), lines


def test_gate_check_plans_the_browser_sign_in_and_names_a_service_principals_client():
    with H.gateway_env() as env:
        data = HA.build_vault(env, AZB)
        form = env.form()
        p = gate_setup.plan_for("work-azure", form, consent.compute(form, data), data)
        assert p.needs_signin and p.browser and p.error is None
        good = {"refresh_token": "rt-0123456789", "client_id": CLIENT, "kind": "browser",
                "tenant_id": "contoso.onmicrosoft.com", "scope": AZB_SCOPE, "refreshed": "x"}
        for rec, needed in ((good, False), ({**good, "kind": ""}, True),
                            ({**good, "client_id": "22222222-2222-2222-2222-222222222222"}, True),
                            ({**good, "scope": "https://graph.microsoft.com/.default offline_access"}, True),
                            ({"client_secret": "s", "client_id": CLIENT,
                              "tenant_id": "contoso.onmicrosoft.com"}, True)):
            data["accounts"]["work-azure"]["entra"] = rec
            p = gate_setup.plan_for("work-azure", form, consent.compute(form, data), data)
            assert p.needs_signin is needed and p.browser is needed, rec
    with H.gateway_env() as env:
        data = HA.build_vault(env, AZ_SP)
        form = env.form()
        p = gate_setup.plan_for("azure", form, consent.compute(form, data), data)
        assert p.error and "own client_id" in p.error and "sign_in = \"browser\"" in p.error, p.error
        assert not p.browser


def test_the_status_says_signed_in_only_for_a_credential_gate_check_would_use():
    """gate status, the status line and Claude's context follow gate check's
    rule: an older gateway's refresh token, or a sign-in made for another
    client or scope, needs a new sign-in; a service principal's certificate
    counts as its credential."""
    good = {"refresh_token": "rt-0123456789", "client_id": CLIENT, "kind": "browser",
            "tenant_id": "contoso.onmicrosoft.com", "scope": AZB_SCOPE, "refreshed": "x"}
    other = "22222222-2222-2222-2222-222222222222"
    graph = "https://graph.microsoft.com/.default offline_access"
    sp_form = AZB.replace('sign_in = "browser"\n', "")
    cert = {"client_certificate": "PEM", "client_id": CLIENT, "tenant_id": "contoso.onmicrosoft.com",
            "kind": "service-principal"}
    with H.gateway_env() as env:
        for form_text, rec, fits in ((AZB, good, True), (AZB, {**good, "kind": ""}, False),
                                     (AZB, {**good, "client_id": other}, False),
                                     (AZB, {**good, "scope": graph}, False),
                                     (sp_form, cert, True), (sp_form, {**cert, "client_id": other}, False)):
            HA.build_vault(env, form_text)
            with vault.edit() as d:
                d["accounts"]["work-azure"]["entra"] = dict(rec)
            form, data = env.form(), vault.load()
            eff = consent.compute(form, data)
            line = gate_setup.status_line("work-azure", form, eff, data)
            status = gate.render_status(form, eff, data)
            ctx = hooks_session.context_text(form, eff, vault.meta(data))
            needs = gate_setup.plan_for("work-azure", form, eff, data).needs_signin
            if fits:
                assert "work-azure ready: signed in" in line and not needs, (rec, line)
                assert "needs a new sign-in" not in status + ctx, (rec, status, ctx)
            else:
                assert "work-azure ready: needs a new sign-in" in line and needs, (rec, line)
                assert "needs a new sign-in (gate check work-azure)" in status, (rec, status)
                assert "needs a new sign-in: `gate check work-azure`" in ctx, (rec, ctx)
            assert "rt-0123456789" not in line + status + ctx


def test_a_browser_sign_in_is_checked_with_its_own_scope():
    """The account check (adapters) mints with the scope the sign-in was made
    for, not always ARM's (an account signed in for Graph alone)."""
    from gateway import adapters
    graph = "https://graph.microsoft.com/.default"
    srv = HA.EntraServer()
    try:
        for scope, sent in ((graph, f"{graph} offline_access"),
                            (None, f"{acctmod.ARM_SCOPE} offline_access")):
            with H.gateway_env() as env:
                env.o.extra["entra_authority"] = srv.authority
                text = AZB + (f'scope = "{scope}"\n' if scope else "")
                rec = {"refresh_token": "SEED-RT-0123456789", "client_id": CLIENT, "kind": "browser",
                       "tenant_id": "contoso.onmicrosoft.com", "refreshed": "x",
                       "scope": f"{scope or acctmod.ARM_SCOPE} offline_access"}
                HA.build_vault(env, text, entra={"work-azure": rec})
                a, data = env.form().accounts["work-azure"], vault.load()
                c = adapters.check_azure(a, data["accounts"]["work-azure"], data)
                assert c.state == "connected", (c.state, c.detail)
                assert srv.calls[-1]["grant_type"] == "refresh_token" and srv.calls[-1]["scope"] == sent, \
                    srv.calls[-1].get("scope")
                assert ("Resource Manager" in c.detail) is (scope is None), c.detail
    finally:
        srv.close()


def test_a_browser_sign_ins_refresh_token_is_never_exported_and_a_file_with_one_is_refused():
    """PLAN-0.11 §19.12 (WS-8): a browser sign-in's refresh token is the
    machine's session state, which an import could never use: no export
    item offers it, an export never carries it (even when its item is
    named), and a file holding one, or a sign-in's scope, is refused. A
    service principal's secret still travels."""
    import harness_ux as U
    from gateway import transfer
    rt = "RT-" + secrets.token_hex(10)
    rec = {"refresh_token": rt, "client_id": CLIENT, "tenant_id": "contoso.onmicrosoft.com",
           "refreshed": "2026-01-01T00:00:00Z", "kind": "browser",
           "scope": "https://graph.microsoft.com/.default api://x/y offline_access"}
    sp = AZ_SPC.replace("[accounts.azure]", "[accounts.sp-azure]")
    sp_secret = "sp-secret-" + secrets.token_hex(8)
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        U.setup(env, AZB + sp)
        with vault.edit() as d:
            vault.account_record(d, "work-azure", "azure")["entra"] = dict(rec)
            vault.account_record(d, "sp-azure", "azure")["entra"] = {
                "client_secret": sp_secret, "client_id": SP_CLIENT,
                "tenant_id": "contoso.onmicrosoft.com", "refreshed": "x", "kind": "service-principal",
                "refresh_token": "STRAY-" + rt}
        form, _e, data = transfer._load()
        keys = {it.key for it in transfer.export_items(form, data)}
        assert "account:work-azure" in keys and "account-secrets:work-azure" not in keys, keys
        assert "account-secrets:sp-azure" in keys, keys
        content = json.loads(json.dumps(transfer.export_content(
            form, data, {"account:work-azure", "account-secrets:work-azure", "account:sp-azure",
                         "account-secrets:sp-azure"})))
        assert rt not in json.dumps(content), "no refresh token in the file, a stray one neither"
        assert "entra" not in content["vault"]["accounts"]["work-azure"]
        inc = transfer.parse_incoming(content)
        assert "entra" not in inc.vault["accounts"]["work-azure"]
        got = inc.vault["accounts"]["sp-azure"]["entra"]
        assert got["client_secret"] == sp_secret and got["kind"] == "service-principal", sorted(got)
        for field, value in (("refresh_token", rt), ("scope", rec["scope"])):
            c = json.loads(json.dumps(content))
            c["vault"]["accounts"]["sp-azure"]["entra"][field] = value
            c["digest"] = transfer._digest(c)
            try:
                transfer.parse_incoming(c)
                raise AssertionError(f"a file with a sign-in's {field} was imported")
            except transfer.TransferError as e:
                assert "unknown fields" in str(e) and rt not in str(e), e
        c = json.loads(json.dumps(content))
        c["vault"]["accounts"]["work-azure"]["entra"] = {"refresh_token": rt, "kind": "browser",
                                                         "client_id": CLIENT}
        c["digest"] = transfer._digest(c)
        try:
            transfer.parse_incoming(c)
            raise AssertionError("a file with a browser sign-in was imported")
        except transfer.TransferError as e:
            assert "nothing was imported" in str(e), e


# ---------------------------------------------------------------------------
# Pieces of daemon/oauth.py
# ---------------------------------------------------------------------------


def test_pkce_is_s256():
    # RFC 7636, appendix B
    assert oauth.pkce_challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk") == \
        "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def _raw(port: int, data: bytes, timeout: float = 5) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as c:
        c.sendall(data)
        out = b""
        while True:
            chunk = c.recv(65536)
            if not chunk:
                return out
            out += chunk


def test_the_listener_is_on_127_0_0_1_serves_only_get_cb_and_caps_each_request():
    seen: list[dict] = []
    lis = oauth.Listener(30, lambda q: (seen.append(q), (200, oauth.PAGE_OK))[1])
    old = oauth.CONN_TIMEOUT
    try:
        assert lis.sock.getsockname()[0] == "127.0.0.1", "never 0.0.0.0 or another interface"
        assert re.fullmatch(r"http://127\.0\.0\.1:\d+/cb", lis.redirect_uri)
        lis.start()
        r = _raw(lis.port, b"GET /cb?state=s1&code=c1 HTTP/1.1\r\nHost: x\r\n\r\n")
        assert r.startswith(b"HTTP/1.1 200 ") and b"Cache-Control: no-store" in r
        assert seen == [{"state": ["s1"], "code": ["c1"]}]
        big = b"GET /cb?state=s HTTP/1.1\r\nX-Big: " + b"a" * 20000 + b"\r\n\r\n"
        assert _raw(lis.port, big).startswith(b"HTTP/1.1 431 ")
        assert _raw(lis.port, b"POST /cb HTTP/1.1\r\nContent-Length: 0\r\n\r\n").startswith(b"HTTP/1.1 405 ")
        assert _raw(lis.port, b"GET /other?state=s HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 404 ")
        assert len(seen) == 1, "only GET /cb with a request under the cap reaches the sign-in"
        # a connection that sends nothing is closed after the per-connection timeout
        oauth.CONN_TIMEOUT = 0.5
        with socket.create_connection(("127.0.0.1", lis.port), timeout=5) as c:
            t0 = time.time()
            assert c.recv(100) == b"" and time.time() - t0 < 4
    finally:
        oauth.CONN_TIMEOUT = old
        lis.close()


def test_the_listeners_deadline_is_the_whole_connections_and_its_handlers_are_capped():
    """A client sending a byte at a time is cut off at the connection's
    deadline (not one per byte), and only MAX_CONNS connections are handled
    at once: one more is closed unanswered, so no local process can pile up
    gated's threads during a sign-in."""
    old = oauth.CONN_TIMEOUT, oauth.MAX_CONNS
    oauth.CONN_TIMEOUT, oauth.MAX_CONNS = 1.0, 2
    seen: list[dict] = []
    lis = oauth.Listener(60, lambda q: (seen.append(q), (200, oauth.PAGE_OK))[1])
    held: list[socket.socket] = []
    try:
        lis.start()
        with socket.create_connection(("127.0.0.1", lis.port), timeout=5) as c:
            t0, cut = time.time(), None
            for b in b"GET /cb?state=x HTTP/1.1\r\nX-Pad: " + b"a" * 100:
                time.sleep(0.15)
                if select.select([c], [], [], 0)[0]:
                    try:
                        got = c.recv(100)
                    except OSError:
                        got = b""
                    assert got == b"", got
                    cut = time.time() - t0
                    break
                try:
                    c.sendall(bytes([b]))
                except OSError:
                    cut = time.time() - t0
                    break
                if time.time() - t0 > 4:
                    break
            assert cut is not None and cut < 2.5, f"a slow sender kept its connection ({cut})"
        assert seen == []
        # MAX_CONNS connections that send nothing hold every slot; one more is
        # closed at once, unanswered
        held = [socket.create_connection(("127.0.0.1", lis.port), timeout=5) for _ in range(2)]
        time.sleep(0.3)
        with socket.create_connection(("127.0.0.1", lis.port), timeout=5) as c:
            t0 = time.time()
            try:
                c.sendall(b"GET /cb?state=s HTTP/1.1\r\n\r\n")
                got = c.recv(100)
            except OSError:
                got = b""
            assert got == b"" and time.time() - t0 < 0.8, (got, time.time() - t0)
        for h in held:
            h.close()
        held = []
        time.sleep(0.3)
        # the slots are free again: a request is answered
        assert _raw(lis.port, b"GET /cb?state=s HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 200 ")
        assert seen == [{"state": ["s"]}]
    finally:
        for h in held:
            h.close()
        oauth.CONN_TIMEOUT, oauth.MAX_CONNS = old
        lis.close()


def test_closing_the_listener_stops_it_at_once_and_serves_nothing_accepted_after():
    """verify012: on Linux close() alone left the socket in LISTEN, taking
    connections, while the serve thread waited in accept(). close() shuts
    the socket down before it closes it and waits for the serve thread; a
    connection accepted as the sign-in ends is closed unanswered."""
    calls: list[str] = []

    class Rec:
        """The listening socket, recording shutdown and close."""
        def __init__(self, s: socket.socket):
            self.s = s

        def __getattr__(self, name: str):
            return getattr(self.s, name)

        def accept(self) -> tuple[socket.socket, object]:
            try:
                return self.s.accept()
            except OSError:
                time.sleep(0.3)          # a serve thread slow to leave: close() still waits
                raise

        def shutdown(self, how: int) -> None:
            calls.append("shutdown")
            self.s.shutdown(how)

        def close(self) -> None:
            calls.append("close")
            self.s.close()

    seen: list[dict] = []
    lis = oauth.Listener(30, lambda q: (seen.append(q), (200, oauth.PAGE_OK))[1])
    lis.sock = Rec(lis.sock)
    try:
        lis.start()
        assert _raw(lis.port, b"GET /cb?state=s HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 200 ")
    finally:
        lis.close()
    assert calls[:1] == ["shutdown"], f"shutdown() first (on Linux close() alone keeps it listening): {calls}"
    assert lis.thread is not None and not lis.thread.is_alive(), "close() waits for the serve thread"
    for _ in range(3):
        try:
            socket.create_connection(("127.0.0.1", lis.port), timeout=1).close()
        except OSError:
            continue
        raise AssertionError("the listener took a connection after close()")
    assert seen == [{"state": ["s"]}]

    # accept() returns a connection just after close() began: never served
    a, b = socket.socketpair()
    late: list[dict] = []
    lis2 = oauth.Listener(30, lambda q: (late.append(q), (200, oauth.PAGE_OK))[1])

    class Late:
        n = 0

        def accept(self) -> tuple[socket.socket, None]:
            Late.n += 1
            if Late.n > 1:
                raise OSError("closed")
            lis2.closed.wait(5)
            return a, None

        def shutdown(self, how: int) -> None:
            pass

        def close(self) -> None:
            pass

    real = lis2.sock
    lis2.sock = Late()
    try:
        b.sendall(b"GET /cb?state=late HTTP/1.1\r\n\r\n")
        lis2.start()
        time.sleep(0.1)
        lis2.close()
        b.settimeout(3)
        try:
            got = b.recv(100)
        except OSError:
            got = b""
        assert got == b"" and late == [], (got, late)
    finally:
        real.close()
        a.close()
        b.close()


def test_the_listener_stops_by_itself_at_its_deadline():
    """verify013: the listener's own timer ends it at its life (the accept no
    longer polls a deadline). Once a callback was accepted the sign-in's own
    timer does nothing, so this one is what stops the listener then."""
    lis = oauth.Listener(0.3, lambda q: (200, oauth.PAGE_OK))
    try:
        lis.start()
        assert _raw(lis.port, b"GET /cb?state=s HTTP/1.1\r\n\r\n").startswith(b"HTTP/1.1 200 ")
        assert lis.thread is not None
        end = time.monotonic() + 3
        while lis.thread.is_alive() and time.monotonic() < end:
            time.sleep(0.05)
        assert not lis.thread.is_alive(), "the listener outlived its deadline"
        try:
            socket.create_connection(("127.0.0.1", lis.port), timeout=1).close()
        except OSError:
            pass
        else:
            raise AssertionError("the listener took a connection after its deadline")
    finally:
        lis.close()


def test_the_system_browser_is_opened_by_absolute_path_only():
    """Outside any test override: /usr/bin/open on macOS, xdg-open from the
    fixed folders on Linux; never $BROWSER, never a PATH lookup."""
    url = "https://login.example.com/t/oauth2/v2.0/authorize?x=1"
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as d:
        planted = Path(d) / "xdg-open"
        planted.write_text("#!/bin/sh\nexit 0\n")
        os.chmod(planted, 0o755)
        with HA.env_vars(BROWSER=str(planted), PATH=f"{d}:/usr/bin:/bin"):
            try:
                argv, env = oauth.browser_command(url, {"DISPLAY": ":0"}, "darwin")
            except oauth.BrowserError as e:          # a system without /usr/bin/open
                assert "/usr/bin/open" in str(e) and not os.path.exists("/usr/bin/open"), e
                argv = []
            if argv:
                assert argv == ["/usr/bin/open", url] and "BROWSER" not in env, (argv, env)
            try:
                argv, env = oauth.browser_command(url, {"DISPLAY": ":0"}, "linux")
            except oauth.BrowserError:
                argv, env = [], {}
            if argv:
                assert argv[0] != str(planted) and os.path.dirname(argv[0]) in oauth.LINUX_DIRS
                assert argv[1:] == [url] and env.get("DISPLAY") == ":0" and "BROWSER" not in env
    assert oauth.display_problem({}, "darwin") == "" and oauth.display_problem({}, "linux") == oauth.NO_DISPLAY
    assert oauth.display_problem({"WAYLAND_DISPLAY": "wayland-0"}, "linux") == ""
    # over ssh a Mac's browser would open on its own screen (a forwarded X
    # display doesn't change where `open` shows it); Linux's xdg-open uses
    # the forwarded display
    ssh = {"SSH_CONNECTION": "192.0.2.1 50000 192.0.2.2 22"}
    assert oauth.display_problem(ssh, "darwin") == oauth.OVER_SSH
    assert oauth.display_problem({**ssh, "DISPLAY": "localhost:10.0"}, "darwin") == oauth.OVER_SSH
    assert oauth.display_problem({**ssh, "DISPLAY": "localhost:10.0"}, "linux") == ""
    assert oauth.clean_env({"DISPLAY": ":0", "BROWSER": "x", "WAYLAND_DISPLAY": "w;rm"}) == {"DISPLAY": ":0"}
    # the opener's environment: a fixed PATH, LANG, gated's HOME and (Linux)
    # the answer's display and desktop variables; nothing else of gated's own
    desk = {"DISPLAY": ":0", "XDG_CURRENT_DESKTOP": "ubuntu:GNOME",
            "XDG_DATA_DIRS": "/usr/share/ubuntu:/usr/local/share/:/usr/share/:/var/lib/snapd/desktop",
            "XDG_RUNTIME_DIR": "/run/user/1000", **ssh}
    given = oauth.clean_env({**desk, "BROWSER": "/x/evil", "XDG_DATA_DIRS2": "/x"})
    assert given == desk, given
    assert oauth.clean_env({"XDG_CURRENT_DESKTOP": "GNOME;x", "XDG_DATA_DIRS": "rel:/usr/share",
                            "SSH_CONNECTION": "1.2.3.4 22 $(x) 1"}) == {}
    with HA.env_vars(GW_CANARY_ENV="canary-value-0123456789", CLAUDE_CODE_OAUTH_TOKEN="tok-0123456789",
                     BROWSER="/x/evil"):
        lin = oauth.browser_env(given, "linux")
        assert set(lin) <= {"PATH", "LANG", "HOME", *oauth.BROWSER_ENV}, lin
        assert lin["PATH"] == "/usr/bin:/bin" and lin["XDG_DATA_DIRS"] == desk["XDG_DATA_DIRS"]
        assert lin["XDG_CURRENT_DESKTOP"] == "ubuntu:GNOME" and "SSH_CONNECTION" not in lin
        assert set(oauth.browser_env(given, "darwin")) <= {"PATH", "LANG", "HOME"}
    with H.gateway_env() as env:
        try:
            oauth.browser_command(url, {}, "darwin")
            raise AssertionError("under a test override only the knob's program runs")
        except oauth.BrowserError:
            pass
        env.o.extra["browser"] = "/x/fake-browser"
        assert oauth.browser_command(url, {}, "darwin")[0] == ["/x/fake-browser", url]


class _Sess:
    def __init__(self) -> None:
        from gateway.daemon import peers
        self.pid, self.start, self.session_id, self.ui = os.getpid(), peers.started(os.getpid()), "s-1", True
        self.surfaces, self.surface = ["terminal"], "terminal"


class _Daemon:
    def __init__(self, s: _Sess) -> None:
        self.registry = SimpleNamespace(live=lambda pid: s if pid == s.pid else None)
        self.events = SimpleNamespace(emit=lambda *a, **k: None)

    def effective(self):
        return None


def test_only_gateds_own_confirm_carries_sign_in_fields_and_open_keeps_only_display_names():
    """A dialog a program opens with its lease never carries `signin` (the
    mod would draw the sign-in template for it); gated's own confirm does,
    and its Open keeps only the display variables' names."""
    from gateway.daemon import dialogs as dmod
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as d:
        s = _Sess()
        dl = dmod.Dialogs(_Daemon(s), Path(d) / "dialogs.json")
        view = {"account": "work-azure", "kind": "azure", "tenant": "t.example.com", "client": CLIENT,
                "scope": AZB_SCOPE, "host": "", "previous_client": ""}
        lease = dl.lease(s, os.getpid())["lease"]
        rid = dl.open(lease, os.getpid(), {"kind": "confirm", "signin": view, "lines": ["x"]})["id"]
        assert "signin" not in dl.view(s)["dialog"]
        dl.close(lease, os.getpid(), rid, "cancelled")
        seen: list = []
        r = dl.open_owned(s, {"signin": view, "entry": "work-azure", "what": oauth.WHAT},
                          lambda req, _v: (seen.append(dict(req.env)), (True, "ok"))[1], kind="confirm")
        got = dl.view(s)["dialog"]
        assert got["id"] == r["id"] and got["signin"] == view
        ssh = "192.0.2.1 50000 192.0.2.2 22"
        dl.answer(s, {"id": r["id"], "button": "ok",
                      "env": {"DISPLAY": ":0", "BROWSER": "/x/evil", "GW_X": "1", "SSH_CONNECTION": ssh}})
        deadline = time.time() + 5
        while (not seen or dl.view(s)["dialog"] is not None) and time.time() < deadline:
            time.sleep(0.02)
        assert seen == [{"DISPLAY": ":0", "SSH_CONNECTION": ssh}], seen
        with dl.lock:                                   # its close (and the file's write) done
            assert dl.view(s)["dialog"] is None, "closed once its handler answered"


# ---------------------------------------------------------------------------
# hooks/tool_guard.sh and hooks.json
# ---------------------------------------------------------------------------

GUARD = H.PLUGIN / "hooks" / "tool_guard.sh"


def _guard(root: Path, run: Path, payload: object, compact: bool = False) -> str:
    text = json.dumps(payload, separators=(",", ":")) if compact else json.dumps(payload)
    r = subprocess.run(["sh", str(GUARD), "--test"], input=text, capture_output=True, text=True,
                       timeout=15, env={"PATH": "/usr/bin:/bin", "GATEWAY_TEST_ROOT": str(root),
                                        "GATEWAY_TEST_RUN": str(run)})
    assert r.returncode == 0 and not r.stderr, r.stderr
    return r.stdout.strip()


def _tool(name: str, **inp: object) -> dict:
    return {"session_id": "s1", "hook_event_name": "PreToolUse", "tool_name": name, "tool_input": inp}


def test_tool_guard_denies_browser_tools_only_while_a_sign_in_runs():
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as d:
        root, run = Path(d), Path(d) / "run"
        run.mkdir()
        chrome = _tool("mcp__claude-in-chrome__navigate", url="https://example.com")
        pane = _tool("mcp__Claude_Browser__computer", action="screenshot")
        read = _tool("Read", file_path="/x", note='"tool_name": "mcp__Claude_Browser__computer"')
        for p in (chrome, pane, read):
            assert _guard(root, run, p) == "", "no sign-in: no decision"
        (run / "signin-active").touch()
        for p in (chrome, pane):
            for compact in (False, True):
                out = json.loads(_guard(root, run, p, compact))["hookSpecificOutput"]
                assert out["permissionDecision"] == "deny" and "sign-in" in out["permissionDecisionReason"]
        assert _guard(root, run, read) == "", "another tool (a quoted name inside its input) passes"
        (run / "signin-active").unlink()
        assert _guard(root, run, chrome) == ""


def test_hooks_json_runs_tool_guard_for_the_browser_tools():
    spec = json.loads((H.PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]
    groups = [g for g in spec["PreToolUse"] if g.get("matcher") != "AskUserQuestion"    # (WS-6's)
              and any("tool_guard.sh" in " ".join(h.get("args", [])) for h in g["hooks"])]
    assert len(groups) == 1, groups
    m = groups[0]["matcher"]
    for t in ("mcp__Claude_Browser__computer", "mcp__Claude_Browser__navigate",
              "mcp__claude-in-chrome__navigate", "mcp__claude-in-chrome__read_page"):
        assert re.search(m, t), (m, t)
    assert not re.fullmatch(m, "Read") and not re.fullmatch(m, "Bash")
    assert GUARD.exists() and os.access(GUARD, os.X_OK)


def test_the_mod_sends_the_variables_gated_takes_with_the_open_answer():
    """dialog.ts's SIGNIN_ENV, register.tsx's reads (each by its literal name,
    in that order) and gated's lists name the same variables; SSH_CONNECTION
    only tells a session over ssh and never reaches the browser."""
    ts = (H.PLUGIN / "hooks" / "mod" / "dialog.ts").read_text()
    m = re.search(r"export const SIGNIN_ENV: readonly string\[\] = \[([^\]]*)\]", ts)
    assert m, "dialog.ts's SIGNIN_ENV"
    names = re.findall(r"'([A-Z_]+)'", m.group(1))
    reg = (H.PLUGIN / "hooks" / "mod" / "register.tsx").read_text()
    body = reg.split("async function signinEnv(", 1)[1].split("\n}\n", 1)[0]
    reads = re.findall(r"\$\.env\.get\('([A-Z_]+)'\)", body)
    assert names == reads == list(dmod.SIGNIN_ENV), (names, reads, dmod.SIGNIN_ENV)
    assert set(oauth.ENV_PATTERNS) == set(dmod.SIGNIN_ENV)
    assert set(oauth.BROWSER_ENV) < set(oauth.ENV_PATTERNS) and "SSH_CONNECTION" not in oauth.BROWSER_ENV


# ---------------------------------------------------------------------------
# The browser sign-in through a real gated
# ---------------------------------------------------------------------------


is_signin, _gate, _result, _active = HO.is_signin, HO.gate, HO.result, HO.active


def sso(form_text: str = AZB, **kw):
    return HO.sso(form_text, **kw)


def test_browser_sign_in_asks_first_and_only_gated_sees_the_code_and_the_tokens():
    with sso() as s:
        pid = _gate(s, "check", "work-azure")
        d = s.mod.dialog(is_signin)
        assert d["kind"] == "confirm" and d["ok_label"] == "Open" and d["cancel_label"] == "Cancel"
        assert d["default_cancel"] is True and d["entry"] == "work-azure" and d["lines"] == []
        assert d["signin"] == {"account": "work-azure", "kind": "azure",
                               "tenant": "contoso.onmicrosoft.com", "client": CLIENT,
                               "scope": AZB_SCOPE, "host": "", "previous_client": ""}, d["signin"]
        # nothing happens before Open: no browser, no authorization request, no marker
        time.sleep(0.6)
        assert HO.opened(s.log) == [] and s.srv.authorize == [] and not _active(s)
        s.mod.open(d, {"DISPLAY": ":0", "BROWSER": "/x/evil"})
        rc, out, err = _result(s, pid)
        assert rc == 0 and "work-azure ready: signed in" in out, (rc, out, err)
        assert "waiting for the user's browser sign-in for work-azure" in err
        # the system browser got the authorize URL (by the knob), and only the
        # display variables the mod sent beside a fixed PATH and LANG
        rec = HO.opened(s.log)
        assert len([x for x in rec if "url" in x]) == 1, rec
        assert rec[0]["url"].startswith(f"{s.srv.authority}/contoso.onmicrosoft.com/oauth2/v2.0/authorize?")
        assert "DISPLAY" in rec[0]["env"] and "BROWSER" not in rec[0]["env"], rec[0]["env"]
        assert not any(n.startswith(("GATEWAY", "CLAUDE", "GW_")) for n in rec[0]["env"])
        az = s.srv.authorize[0]
        assert az["client_id"] == CLIENT and az["scope"] == AZB_SCOPE and az["response_mode"] == "query"
        assert re.fullmatch(r"http://127\.0\.0\.1:\d+/cb", az["redirect_uri"]), az["redirect_uri"]
        assert az["code_challenge_method"] == "S256" and len(az["state"]) >= 32
        tok = s.srv.tokens[0]
        assert tok["grant_type"] == "authorization_code" and tok["redirect_uri"] == az["redirect_uri"]
        assert HO.s256(tok["code_verifier"]) == az["code_challenge"] and len(tok["code_verifier"]) >= 43
        # the tokens went straight into the vault, and nowhere Claude reads
        e = vault.load()["accounts"]["work-azure"]["entra"]
        assert e == {**e, "refresh_token": "SSO-REFRESH-1", "kind": "browser", "client_id": CLIENT,
                     "tenant_id": "contoso.onmicrosoft.com", "scope": AZB_SCOPE}, e
        blob = out + err + s.de.log()
        for v in ("SSO-REFRESH-1", "SSO-ACCESS-1", tok["code"], tok["code_verifier"], az["state"]):
            assert v not in blob
        # the sign-in is over: no marker, no listener
        assert not _active(s)
        port = int(az["redirect_uri"].rsplit(":", 1)[1].split("/")[0])
        try:
            socket.create_connection(("127.0.0.1", port), timeout=2).close()
            raise AssertionError("the listener stayed open")
        except OSError:
            pass
        # its access token is cached, then the refresh token mints the next (§7.5)
        assert entra.access_token("work-azure", "arm") == "SSO-ACCESS-1"
        with vault.locked():
            vault.cache_clear("work-azure")
        assert entra.access_token("work-azure", "arm").startswith("ACCESS-2-for-https://management")
        assert vault.load()["accounts"]["work-azure"]["entra"]["refresh_token"] == "ROT-REFRESH-2"
        # set up now: a second gate check asks nothing
        rc, out, err = _result(s, _gate(s, "check", "work-azure"))
        assert rc == 0 and len([x for x in HO.opened(s.log) if "url" in x]) == 1, (out, err)


def test_cancel_opens_nothing_and_isnt_asked_again_in_the_session():
    with sso() as s:
        pid = _gate(s, "check", "work-azure")
        d = s.mod.dialog(is_signin)
        st, _ = s.mod.post("/ui/dialog/cancel", {"id": d["id"]})
        assert st == 200
        rc, out, err = _result(s, pid)
        assert rc == 1 and "cancelled the browser sign-in for work-azure" in err, err
        assert HO.opened(s.log) == [] and s.srv.authorize == [] and not _active(s)
        assert not (vault.load()["accounts"]["work-azure"].get("entra") or {})
        rc, out, err = _result(s, _gate(s, "check", "work-azure"))
        assert rc == 1 and "cancelled the gateway dialog for work-azure" in err, err
        assert s.mod.view()["dialog"] is None


def test_a_wrong_state_gets_400_and_the_listener_keeps_waiting():
    with sso(mode="wrong_state_first") as s:
        pid = _gate(s, "check", "work-azure")
        s.mod.open(s.mod.dialog(is_signin))
        rc, out, err = _result(s, pid)
        assert rc == 0, (out, err)
        steps = [x for x in HO.opened(s.log) if "step" in x]
        assert [x["step"] for x in steps] == ["wrong_state", "follow"], steps
        assert steps[0]["status"] == 400 and steps[1]["status"] == 200, steps
        assert [t.get("code") for t in s.srv.tokens if t.get("grant_type") == "authorization_code"] \
            != ["CODE-WRONG"], "the wrong state's code was never exchanged"
        assert all(t.get("code") != "CODE-WRONG" for t in s.srv.tokens)


def test_an_error_from_the_browser_is_a_fixed_failure_and_its_description_goes_nowhere():
    srv = HO.OAuthServer(mode="error")
    try:
        with sso(server=srv) as s:
            pid = _gate(s, "check", "work-azure")
            d = s.mod.dialog(is_signin)
            s.mod.open(d)
            rc, out, err = _result(s, pid)
            assert rc == 1 and "the sign-in was declined or failed" in err, err
            blob = out + err + s.de.log() + json.dumps(s.mod.view())
            if (s.de.run / "gated-dialogs.json").exists():
                blob += (s.de.run / "gated-dialogs.json").read_text()
            assert "CANARY-ERRDESC" not in blob and "AADSTS65004" not in blob
            assert srv.tokens == [] and not (vault.load()["accounts"]["work-azure"].get("entra") or {})
            assert not _active(s)
    finally:
        srv.close()


def test_a_redirect_at_the_token_endpoint_is_never_followed():
    evil = HA.RecorderServer(reply={"access_token": "EVIL-AT", "refresh_token": "EVIL-RT",
                                    "expires_in": 3600})
    srv = HO.OAuthServer(token_mode="redirect", redirect_to=evil.url)
    try:
        with sso(server=srv) as s:
            pid = _gate(s, "check", "work-azure")
            s.mod.open(s.mod.dialog(is_signin))
            rc, out, err = _result(s, pid)
            assert rc == 1 and "redirect" in err, err
            assert not evil.calls, "nothing went on to the redirect's target"
            assert not (vault.load()["accounts"]["work-azure"].get("entra") or {})
    finally:
        srv.close()
        evil.close()


def test_the_timeout_names_the_redirect_cause_and_browser_tools_are_denied_meanwhile():
    with sso(mode="none", knobs={"signin_timeout": 4}) as s:
        pid = _gate(s, "check", "work-azure")
        d = s.mod.dialog(is_signin)
        chrome = _tool("mcp__claude-in-chrome__get_page_text")
        assert _guard(s.de.root, s.de.run, chrome) == "", "not before Open"
        s.mod.open(d)
        assert s.de.wait_for(lambda: _active(s), timeout=10), "the marker is written on Open"
        out = json.loads(_guard(s.de.root, s.de.run, chrome))["hookSpecificOutput"]
        assert out["permissionDecision"] == "deny"
        assert _guard(s.de.root, s.de.run, _tool("Read", file_path="/x")) == ""
        rc, out, err = _result(s, pid)
        assert rc == 1 and "didn't finish in time" in err and "127.0.0.1" in err, err
        assert not _active(s) and _guard(s.de.root, s.de.run, chrome) == ""
        assert s.srv.tokens == []


def test_one_sign_in_at_a_time_and_only_its_lease_waits_for_it():
    two = AZB + AZB.replace("work-azure", "other-azure")
    with sso(two) as s:
        pid = _gate(s, "check", "work-azure")
        d = s.mod.dialog(is_signin)
        gate = D.probe_root(s.de.root)
        st, body = s.de.probe(s.fc, gate / "run.py", ["gate", "check", "other-azure"],
                              "/agent/signin/start", body={"account": "other-azure"})
        assert st == 409 and body["error"] == "busy", (st, body)
        rc, out, err = _result(s, _gate(s, "check", "other-azure"))
        assert rc == 1 and "another browser sign-in is open" in err, err
        st, joined = s.de.probe(s.fc, gate / "run.py", ["gate", "check", "work-azure"],
                                "/agent/signin/start", body={"account": "work-azure"})
        assert st == 200 and joined.get("joined") is True, joined
        st, body = s.de.probe(s.fc, gate / "run.py", ["gate", "status"], "/agent/signin/wait",
                              body={"lease": "0" * 64, "wait": 0})
        assert st == 403 and body["error"] == "lease", body
        st, body = s.de.probe(s.fc, gate / "run.py", ["gate", "status"], "/agent/signin/wait",
                              body={"lease": joined["lease"], "wait": 0})
        assert st == 200 and body["state"] == "asking", body
        s.mod.post("/ui/dialog/cancel", {"id": d["id"]})
        rc, out, err = _result(s, pid)
        assert rc == 1
        st, body = s.de.probe(s.fc, gate / "run.py", ["gate", "status"], "/agent/signin/wait",
                              body={"lease": joined["lease"], "wait": 0})
        assert st == 200 and body["state"] == "done" and body["outcome"] == "cancelled", body


def test_without_a_display_nothing_opens_and_the_fixed_text_says_so():
    with sso(knobs={"browser_platform": "linux"}) as s:
        pid = _gate(s, "check", "work-azure")
        s.mod.open(s.mod.dialog(is_signin), env={})
        rc, out, err = _result(s, pid)
        assert rc == 1 and popup.signin_unavailable() in err, err
        assert HO.opened(s.log) == [] and not _active(s)
        # with Claude Code's display it opens, and the browser gets that display
        pid = _gate(s, "check", "work-azure")
        s.mod.open(s.mod.dialog(is_signin), env={"WAYLAND_DISPLAY": "wayland-0"})
        rc, out, err = _result(s, pid)
        assert rc == 0, (out, err)
        assert "WAYLAND_DISPLAY" in HO.opened(s.log)[0]["env"]


def test_on_a_mac_a_session_over_ssh_opens_no_browser_and_says_why():
    """The mod sends SSH_CONNECTION with Open: a Mac's browser would open on
    its own screen, which the person working over ssh may not see."""
    with sso(knobs={"browser_platform": "darwin"}) as s:
        pid = _gate(s, "check", "work-azure")
        s.mod.open(s.mod.dialog(is_signin), env={"SSH_CONNECTION": "192.0.2.1 50000 192.0.2.2 22",
                                                 "DISPLAY": "localhost:10.0"})
        rc, out, err = _result(s, pid)
        assert rc == 1 and popup.signin_unavailable(oauth.OVER_SSH) in err, err
        assert "ssh session" in err and HO.opened(s.log) == [] and not _active(s)
        # at the Mac itself (no ssh) it opens
        pid = _gate(s, "check", "work-azure")
        s.mod.open(s.mod.dialog(is_signin), env={})
        rc, out, err = _result(s, pid)
        assert rc == 0, (out, err)
        assert "SSH_CONNECTION" not in HO.opened(s.log)[0]["env"]


def test_the_confirm_dialog_rechecks_the_account_before_anything_opens():
    """Its `check`: an account that left gateway.toml (or changed kind) while
    the confirm dialog waited gets no sign-in on Open."""
    with sso() as s:
        for changed in (AZB.replace("work-azure", "other-azure"),
                        '[accounts.work-azure]\nkind = "github"\nlogin = "octocat"\n'):
            s.de.env.write_form(AZB)
            pid = _gate(s, "check", "work-azure")
            d = s.mod.dialog(is_signin)
            s.de.env.write_form(changed)
            st, body = s.mod.post("/ui/dialog/answer", {"id": d["id"], "button": "ok",
                                                        "env": {"DISPLAY": ":0"}})
            assert st == 200 and body.get("ok") is False, body
            rc, out, err = _result(s, pid)
            assert rc == 1 and "didn't complete" in err, (out, err)
            assert HO.opened(s.log) == [] and s.srv.authorize == [] and not _active(s)
            assert not (vault.load()["accounts"]["work-azure"].get("entra") or {})


def test_a_session_without_the_dialog_gets_the_fixed_text_and_nothing_else():
    with sso(surface=None) as s:
        rc, out, err = _result(s, _gate(s, "check", "work-azure"))
        assert rc == 1 and "browser sign-in isn't available here (" in err, err
        assert "claude -p" in err and "use a service principal (azure)" in err, err
        assert HO.opened(s.log) == [] and s.srv.authorize == []


def test_the_sign_in_waits_for_the_users_ok_and_uses_only_approved_settings():
    with sso(approve=False) as s:
        gate = D.probe_root(s.de.root)
        st, body = s.de.probe(s.fc, gate / "run.py", ["gate", "check", "work-azure"],
                              "/agent/signin/start", body={"account": "work-azure"})
        assert st == 409 and body["error"] == "pending", body
        pid = _gate(s, "check", "work-azure")
        c = s.mod.dialog(lambda d: d.get("what") == "consent" or d.get("ok_label") == "Approve")
        assert not is_signin(c)
        s.mod.post("/ui/dialog/answer", {"id": c["id"], "button": "ok"})
        s.mod.open(s.mod.dialog(is_signin))
        rc, out, err = _result(s, pid)
        assert rc == 0 and "signed in" in out, (out, err)
        # (the vault passphrase offer after the first stored secret, PLAN-0.11 §8: dismissed)
        s.mod.post("/ui/dialog/cancel", {"id": s.mod.dialog(lambda d: d.get("offer") == "passphrase")["id"]})
        # the form now asks for another client: until the user's OK the approved one is used
        s.de.env.write_form(AZB.replace(CLIENT, "33333333-3333-3333-3333-333333333333"))
        st, body = s.de.probe(s.fc, gate / "run.py", ["gate", "check", "work-azure"],
                              "/agent/signin/start", body={"account": "work-azure"})
        assert st == 200 and body.get("available"), body
        d = s.mod.dialog(is_signin)
        assert d["signin"]["client"] == CLIENT, d["signin"]
        s.mod.post("/ui/dialog/cancel", {"id": d["id"]})


def test_a_sign_in_that_cant_start_now_says_when_to_retry():
    """Too many dialogs open, or the task paused: the text says to retry
    later, never to find a session with a display."""
    real = entra.signin_start
    with H.gateway_env() as env:
        HA.build_vault(env, AZB)
        try:
            for reason, want in (("busy", "once the user has answered them"),
                                 ("paused", "after the user resumes it")):
                entra.signin_start = lambda name, r=reason: {
                    "ok": True, "available": False, "reason": r, "message": dmod.UNAVAILABLE[r]}
                err = io.StringIO()
                with contextlib.redirect_stderr(err):
                    rc = gate_setup._browser_signin("work-azure", "key", "digest")
                assert rc == 1 and want in err.getvalue(), err.getvalue()
                assert "can't start now" in err.getvalue() and "display" not in err.getvalue()
            entra.signin_start = lambda name: {"ok": True, "available": False, "reason": "print",
                                               "message": dmod.UNAVAILABLE["print"]}
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                assert gate_setup._browser_signin("work-azure", "key", "digest") == 1
            assert "isn't available here (this is claude -p" in err.getvalue(), err.getvalue()
        finally:
            entra.signin_start = real


# ---------------------------------------------------------------------------
# The sign-ins' steps in process: a fake daemon around the real vault
# ---------------------------------------------------------------------------

STATE = "S" * 43


class _Broker:
    """The daemon's broker over the test vault; `hold` blocks a write."""

    def __init__(self) -> None:
        self.writes = 0
        self.hold: threading.Event | None = None
        self.entered = threading.Event()

    def read(self, touch: bool = True) -> dict:
        return vault.load()

    def write(self, data: dict) -> None:
        self.entered.set()
        if self.hold is not None:
            self.hold.wait(20)
        vault.save(data)
        self.writes += 1


class _Dialogs:
    def __init__(self) -> None:
        self.opened: list[dict] = []

    def open_owned(self, session, spec, handler, on_close=None, terminal="", kind="secret"):
        self.opened.append({"spec": spec, "kind": kind})
        return {"ok": True, "available": True, "id": f"d_{len(self.opened):016x}"}

    def close_owned(self, rid, outcome, note=""):
        pass


def _fake_daemon() -> SimpleNamespace:
    return SimpleNamespace(broker=_Broker(), vault_mutex=threading.Lock(), dialogs=_Dialogs())


@contextlib.contextmanager
def _signins(form_text: str = AZB):
    with H.gateway_env() as env:
        HA.build_vault(env, form_text)
        d = _fake_daemon()
        yield SimpleNamespace(env=env, d=d, sis=oauth.SignIns(d))


def _past_open(t: SimpleNamespace, name: str = "work-azure") -> oauth.SignIn:
    """A sign-in past the person's Open (state and verifier made; no
    listener, no browser)."""
    si = oauth.SignIn(oauth.params_for(t.d, name), _Sess())
    si.state, si.oauth_state, si.verifier = "open", STATE, "V" * 86
    si.redirect = "http://127.0.0.1:9/cb"
    t.sis.active = si
    return si


@contextlib.contextmanager
def _exchange(gate: threading.Event | None = None):
    """oauth.exchange answering canned tokens, after `gate` when given."""
    calls: list[str] = []
    entered = threading.Event()
    real = oauth.exchange

    def fake(p, code, verifier, redirect):
        calls.append(code)
        entered.set()
        if gate is not None:
            gate.wait(20)
        return {"refresh_token": f"UNIT-REFRESH-{len(calls)}", "access_token": f"UNIT-ACCESS-{len(calls)}",
                "expires_in": 3600}
    oauth.exchange = fake
    try:
        yield SimpleNamespace(calls=calls, entered=entered)
    finally:
        oauth.exchange = real


def _in_thread(fn, *args) -> tuple[threading.Thread, list]:
    out: list = []
    th = threading.Thread(target=lambda: out.append(fn(*args)), daemon=True)
    th.start()
    return th, out


def _stored(name: str = "work-azure") -> str:
    return str((vault.load()["accounts"][name].get("entra") or {}).get("refresh_token") or "")


def test_the_timer_or_gated_stopping_during_the_exchange_never_contradicts_the_vault():
    q = {"state": [STATE], "code": ["CODE-1"]}
    # the timer fires while the code is exchanged: the exchange decides, and
    # the tokens it brings are stored and reported
    with _signins() as t:
        si = _past_open(t)
        gate = threading.Event()
        with _exchange(gate) as ex:
            th, res = _in_thread(t.sis._callback, si, q)
            assert ex.entered.wait(10)
            t.sis._expire(si)
            assert si.state == "open", "an accepted callback is never timed out"
            gate.set()
            th.join(20)
        assert res == [(200, oauth.PAGE_OK)] and si.outcome == "ok", (res, si.outcome, si.message)
        assert _stored() == "UNIT-REFRESH-1"
    # gated stops while the code is exchanged: its outcome says nothing was
    # stored, and nothing is
    with _signins() as t:
        si = _past_open(t)
        gate = threading.Event()
        with _exchange(gate) as ex:
            th, res = _in_thread(t.sis._callback, si, q)
            assert ex.entered.wait(10)
            t.sis.stop_all()
            assert si.state == "done" and si.outcome == "failed" and "nothing was stored" in si.message
            gate.set()
            th.join(20)
        assert res == [(200, oauth.PAGE_FAIL)] and si.outcome == "failed", res
        assert t.d.broker.writes == 0 and _stored() == ""
    # gated stops while the tokens are written: it waits, and the store's
    # outcome stands
    with _signins() as t:
        si = _past_open(t)
        t.d.broker.hold = threading.Event()
        with _exchange():
            th, res = _in_thread(t.sis._callback, si, q)
            assert t.d.broker.entered.wait(10)
            stopper, _ = _in_thread(t.sis.stop_all)
            time.sleep(0.4)
            assert stopper.is_alive() and si.state == "open", "the stop waits for the store"
            t.d.broker.hold.set()
            th.join(20)
            stopper.join(20)
        assert res == [(200, oauth.PAGE_OK)] and si.outcome == "ok", (res, si.outcome, si.message)
        assert t.d.broker.writes == 1 and _stored() == "UNIT-REFRESH-1"


def test_one_valid_callback_only_and_an_error_needs_the_state_too():
    # a second valid callback while the first is exchanged: 409, never a second exchange
    with _signins() as t:
        si = _past_open(t)
        gate = threading.Event()
        with _exchange(gate) as ex:
            th, res = _in_thread(t.sis._callback, si, {"state": [STATE], "code": ["CODE-1"]})
            assert ex.entered.wait(10)
            assert t.sis._callback(si, {"state": [STATE], "code": ["CODE-2"]}) == (409, oauth.PAGE_BAD)
            gate.set()
            th.join(20)
        assert ex.calls == ["CODE-1"] and res == [(200, oauth.PAGE_OK)], (ex.calls, res)
    # an error with a wrong or no state is a bad request like any other: the
    # sign-in waits on (one bad request is no denial of service)
    with _signins() as t:
        si = _past_open(t)
        with _exchange() as ex:
            for q in ({"error": ["access_denied"], "state": ["not-the-state"]}, {"error": ["access_denied"]}):
                assert t.sis._callback(si, q) == (400, oauth.PAGE_BAD), q
                assert si.state == "open" and not si.accepted
            assert t.sis._callback(si, {"error": ["access_denied"], "state": [STATE]}) == (200, oauth.PAGE_FAIL)
        assert si.outcome == "declined" and ex.calls == []


def test_the_store_rechecks_the_account_in_gateway_toml():
    """An account that left gateway.toml, or changed kind, while the browser
    was open gets nothing stored."""
    for changed in (AZB.replace("work-azure", "other-azure"),
                    '[accounts.work-azure]\nkind = "github"\nlogin = "octocat"\n'):
        with _signins() as t:
            si = _past_open(t)
            t.env.write_form(changed)
            with _exchange():
                assert t.sis._callback(si, {"state": [STATE], "code": ["CODE-1"]}) == (200, oauth.PAGE_FAIL)
            assert si.outcome == "changed" and "changed in gateway.toml" in si.message, si.message
            assert t.d.broker.writes == 0 and _stored() == ""


def test_the_end_of_a_sign_in_is_announced_only_after_its_listener_stopped():
    """verify013: _finish stops the listener and removes the marker before it
    wakes the waiters. Before, a connection made as the end was announced
    still reached the listener (a 410 page), and the marker outlived it."""
    with _signins() as t:
        si = _past_open(t)
        lis = oauth.Listener(30, lambda q: t.sis._callback(si, q))
        si.listener = lis
        lis.start()
        t.sis._write_active_file()
        assert oauth.active_path().exists()
        seen: list[tuple[bool, bool]] = []

        class Spy(threading.Condition):
            """Records, as the end is announced, whether the listener still
            takes a connection and whether the marker is still there."""
            def notify_all(self) -> None:
                if si.state == "done":
                    try:
                        socket.create_connection(("127.0.0.1", lis.port), timeout=1).close()
                        took = True
                    except OSError:
                        took = False
                    seen.append((took, oauth.active_path().exists()))
                super().notify_all()

        t.sis.cond = Spy()
        try:
            t.sis._finish(si, "failed", "gateway: test")
        finally:
            lis.close()
        assert seen == [(False, False)], f"(listener took it, marker there) as the end was announced: {seen}"
        assert lis.thread is not None and not lis.thread.is_alive()


def test_only_the_same_session_joins_a_sign_in_and_a_killed_gateds_marker_goes():
    with H.gateway_env() as env:
        HA.build_vault(env, AZB)
        oauth.active_path().touch()
        sis = oauth.SignIns(_fake_daemon())
        assert not oauth.active_path().exists(), "a killed gated's leftover marker is removed"
        s1, s2 = _Sess(), _Sess()
        s2.pid = os.getppid()
        r = sis.start(s1, "work-azure")
        assert r["available"] and not r.get("joined"), r
        assert sis.start(s1, "work-azure").get("joined") is True
        try:
            sis.start(s2, "work-azure")
            raise AssertionError("another session joined the sign-in")
        except oauth.SignInError as e:
            assert e.code == "busy", e.code


def test_gated_runs_a_browser_sign_in_only_for_an_account_approved_for_it():
    """A service principal (its own client) gets no browser sign-in from
    gated, also while the form asks for one and the user hasn't approved it."""
    sp = AZB.replace('sign_in = "browser"\n', "")
    with _signins(sp) as t:
        for form_text in (sp, AZB):
            t.env.write_form(form_text)
            try:
                oauth.params_for(t.d, "work-azure")
                raise AssertionError("gated would sign in an account approved as a service principal")
            except oauth.SignInError as e:
                assert e.code == "sign_in" and e.status == 409, (e.code, e.message)
    with _signins(AZB) as t:
        p = oauth.params_for(t.d, "work-azure")
        assert p.client_id == CLIENT and p.scope == AZB_SCOPE
