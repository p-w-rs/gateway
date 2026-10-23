"""entra.py (SPEC 9.5, 14): access tokens with cache.age, refresh-token
rotation under the lock, scope mapping and the ACR exchange."""
from __future__ import annotations

import http.server
import json
import threading
import time
import urllib.parse
from pathlib import Path

import harness as H
import harness_accounts as HA
from gateway import entra, vault
from gateway import form as formmod

AZ = ('[accounts.azure]\nkind = "azure"\ntenant = "contoso.onmicrosoft.com"\n'
      'databricks = ["adb-123.7.azuredatabricks.net"]\nstorage = ["examplestore"]\n'
      'sites = ["custom.example.com"]\n')
ENTRA = {"azure": {"refresh_token": "SEED-REFRESH-0", "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
                   "tenant_id": "11111111-2222-3333-4444-555555555555", "refreshed": "x"}}


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
                            "client_id": "99999999-8888-7777-6666-555555555555",
                            "tenant_id": "11111111-2222-3333-4444-555555555555", "refreshed": "x",
                            "kind": "service-principal"}}
            HA.build_vault(env, AZ, entra=sp)
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
            rt = entra.acr_token(host, "azure")
            assert rt == "ACR-REFRESH-1"
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
