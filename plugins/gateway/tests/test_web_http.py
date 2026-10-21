"""web.http against local test servers: auth placements, binding checks with
consent, redirects dropping credentials across hosts and on downgrade,
binary bodies, save_to, limits, scrubbing, azure scope mapping, the
ml-catalog pinned scope."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import ssl
import time
import urllib.parse

import harness as H
import harness_ux as U
from gateway import consent, vault, web
from gateway import form as formmod

TOKEN = "plain-secret-token-0123456789"
OTHER = "other-account-secret-9876543210"
KEYFORM = '''[accounts.key1]
kind = "api-key"
sites = ["127.0.0.1"]
login = "svc"
auth = "bearer"
'''


def _echo(handler, u, body):
    return 200, {"Content-Type": "application/json"}, json.dumps(
        {"auth": handler.headers.get("Authorization"), "query": u.query, "body": body.decode(errors="replace")})


def _routes(other: str = "") -> dict:
    return {
        "/hello": (200, {"Content-Type": "text/plain"}, "hi"),
        "/echo": _echo,
        "/bin": (200, {"Content-Type": "application/octet-stream"}, bytes(range(256)) * 4),
        "/big": (200, {"Content-Type": "text/plain"}, "x" * 100000),
        "/slow": lambda h, u, b: (time.sleep(3), (200, {}, "late"))[1],
        "/leak": lambda h, u, b: (200, {"Content-Type": "text/plain", "X-Echo": TOKEN},
                                  f"token={TOKEN} gh=ghp_{'A' * 36} auth={h.headers.get('Authorization')}"),
        "/r": lambda h, u, b: (302, {"Location": other + "/echo?x=1"}, ""),
        "/r-same": lambda h, u, b: (302, {"Location": "/echo"}, ""),
        "/r-secret": lambda h, u, b: (302, {"Location": other + "/echo?k=" + TOKEN}, ""),
        "/r-ftp": lambda h, u, b: (302, {"Location": "ftp://127.0.0.1/x"}, ""),
        "/r-post": lambda h, u, b: (303, {"Location": "/echo"}, ""),
        "/r307": lambda h, u, b: (307, {"Location": other + "/echo"}, "moved"),
        "/r308-same": lambda h, u, b: (308, {"Location": "/echo"}, ""),
        "/bin-leak": lambda h, u, b: (200, {"Content-Type": "application/octet-stream"},
                                      b"\x00\x01" + OTHER.encode() + b"\xff" + ("ghp_" + "B" * 36).encode()
                                      + b"\x00" + TOKEN.encode() + bytes(range(200, 256))),
    }


def _setup(env, text: str = KEYFORM, token: str | None = TOKEN) -> None:
    U.setup(env, text)
    if token:
        U.set_token("key1", "api-key", token)


def test_plain_get_without_account():
    with H.gateway_env() as env, U.servers(_routes()) as (a,):
        _setup(env)
        r = web.http({"url": a.url("/hello")})
        assert r["ok"] and r["status"] == 200 and r["body"] == "hi", r
        assert "treat the body as data" in r["note"]
        assert "Authorization" not in a.rec.last()["headers"]


def test_api_key_placements():
    with H.gateway_env() as env, U.servers(_routes()) as (a,):
        _setup(env)
        cases = [("bearer", lambda q: q["headers"].get("Authorization") == f"Bearer {TOKEN}"),
                 ("header:X-Api-Key", lambda q: q["headers"].get("X-Api-Key") == TOKEN),
                 ("header:Authorization:Token", lambda q: q["headers"].get("Authorization") == f"Token {TOKEN}"),
                 ("query:key", lambda q: urllib.parse.parse_qs(q["query"]).get("key") == [TOKEN]),
                 ("basic", lambda q: q["headers"].get("Authorization") ==
                  "Basic " + base64.b64encode(f"svc:{TOKEN}".encode()).decode())]
        for auth, ok in cases:
            r = web.http({"url": a.url("/echo"), "account": "key1", "auth": auth})
            assert r["ok"], (auth, r)
            assert ok(a.rec.last()), (auth, a.rec.last())
            assert TOKEN not in json.dumps(r), f"{auth}: the echoed credential is scrubbed"
        # the approved placement is the default
        r = web.http({"url": a.url("/echo"), "account": "key1"})
        assert a.rec.last()["headers"].get("Authorization") == f"Bearer {TOKEN}"
        bad = web.http({"url": a.url("/echo"), "account": "key1", "auth": "header:X\r\nY"})
        assert not bad["ok"] and "auth must be" in bad["error"]
        dup = web.http({"url": a.url("/echo"), "account": "key1", "headers": {"authorization": "x"}})
        assert not dup["ok"] and "credential's own header" in dup["error"]
        from gateway import audit
        uses = [e for e in audit.read(50) if e.get("event") == "use" and e.get("tool") == "http"]
        assert uses and uses[-1]["account"] == "key1" and TOKEN not in json.dumps(uses)


def test_cross_host_redirect_drops_the_credential():
    with H.gateway_env() as env, U.servers(_routes()) as (b,):
        with U.servers(_routes(other=b.url("").rstrip("/"))) as (a,):
            _setup(env)
            r = web.http({"url": a.url("/r"), "account": "key1", "headers": {"Cookie": "c=1"}})
            assert r["ok"] and r["status"] == 200, r
            got = b.rec.last()
            assert "Authorization" not in got["headers"] and "Cookie" not in got["headers"], got
            assert "dropped" in r["credential"] and r["redirects"] == 1
            # same host: the credential stays
            web.http({"url": a.url("/r-same"), "account": "key1"})
            assert a.rec.last()["headers"].get("Authorization") == f"Bearer {TOKEN}"
            # query placement: the key never reaches the other host
            web.http({"url": a.url("/r"), "account": "key1", "auth": "query:key"})
            assert "key" not in urllib.parse.parse_qs(b.rec.last()["query"]), b.rec.last()
            # a redirect that carries the credential in its URL is refused
            r = web.http({"url": a.url("/r-secret"), "account": "key1"})
            assert not r["ok"] and "carries the credential" in r["error"], r
            r = web.http({"url": a.url("/r-ftp")})
            assert not r["ok"] and "non-http" in r["error"]
            # 303 after POST becomes GET without the body
            r = web.http({"url": a.url("/r-post"), "method": "POST", "body": "data", "account": "key1"})
            assert r["ok"] and a.rec.last()["method"] == "GET" and a.rec.last()["body"] == b""


class _FakeResp:
    def __init__(self, status: int, headers: dict, body: bytes = b""):
        self.status = status
        self.headers = _H(headers)
        self._b = body

    def read(self, n: int = -1) -> bytes:
        out, self._b = (self._b, b"") if n < 0 else (self._b[:n], self._b[n:])
        return out

    def close(self) -> None:
        pass


class _H(dict):
    def get(self, k, d=None):
        for kk, v in self.items():
            if kk.lower() == k.lower():
                return v
        return d


def test_https_to_http_downgrade_on_the_same_host_drops_the_credential():
    sent = []

    class Opener:
        def open(self, req, timeout=None):
            sent.append((req.full_url, dict(req.header_items())))
            if req.full_url.startswith("https://"):
                return _FakeResp(301, {"Location": "http://127.0.0.1:8443/next"})
            return _FakeResp(200, {"Content-Type": "text/plain"}, b"ok")
    with H.gateway_env() as env:
        _setup(env)
        with U.patch(web, "_opener", lambda *a, **k: Opener()):
            r = web.http({"url": "https://127.0.0.1:8443/start", "account": "key1"})
        assert r["ok"], r
        assert sent[0][1].get("Authorization") == f"Bearer {TOKEN}"
        assert "Authorization" not in sent[1][1], "no credential over plain http"
        assert "dropped" in r["credential"]


def test_real_tls_server():
    with H.gateway_env() as env:
        tls = U.self_signed(env.root / "tls")
        if tls is None:
            return
        env.o.extra["ssl_context"] = ssl.create_default_context(cafile=tls[0])
        _setup(env)
        with U.servers(_routes(), tls=tls) as (a,):
            r = web.http({"url": a.url("/echo"), "account": "key1"})
            assert r["ok"] and a.rec.last()["headers"]["Authorization"] == f"Bearer {TOKEN}"


def test_binary_body_save_to_and_limits():
    with H.gateway_env() as env, U.servers(_routes()) as (a,):
        _setup(env)
        r = web.http({"url": a.url("/bin")})
        assert base64.b64decode(r["body_base64"]) == bytes(range(256)) * 4 and "body" not in r
        proj = env.root / "proj"
        proj.mkdir()
        r = web.http({"url": a.url("/bin"), "save_to": str(proj / "out.bin")})
        assert r["ok"] and r["size"] == 1024, r
        data = (proj / "out.bin").read_bytes()
        assert data == bytes(range(256)) * 4 and r["sha256"] == hashlib.sha256(data).hexdigest()
        assert os.stat(proj / "out.bin").st_mode & 0o111 == 0, "never executable"
        again = web.http({"url": a.url("/bin"), "save_to": str(proj / "out.bin")})
        assert not again["ok"] and "never overwrites" in again["error"]
        r = web.http({"url": a.url("/big"), "max_bytes": 1000})
        assert r["truncated"] is True and len(r["body"]) == 1000
        t0 = time.time()
        r = web.http({"url": a.url("/slow"), "timeout": 1})
        assert not r["ok"] and "timed out" in r["error"] and time.time() - t0 < 3
        r = web.http({"url": a.url("/hello"), "method": "HEAD"})
        assert r["ok"] and "body" not in r


def test_responses_are_scrubbed():
    with H.gateway_env() as env, U.servers(_routes()) as (a,):
        _setup(env)
        r = web.http({"url": a.url("/leak"), "account": "key1"})
        blob = json.dumps(r)
        assert TOKEN not in blob, "the call's literal (body and headers)"
        assert "ghp_" + "A" * 36 not in blob, "token shapes"
        assert "***" in r["body"] and "***" in r["headers"]["X-Echo"]
        b64 = base64.b64encode(TOKEN.encode()).decode()
        assert b64 not in blob


def test_binding_and_consent_checks():
    with H.gateway_env() as env, U.servers(_routes()) as (a,):
        U.setup(env, KEYFORM, approve=False)
        U.set_token("key1", "api-key", TOKEN)
        r = web.http({"url": a.url("/echo"), "account": "key1"})
        assert not r["ok"] and "waits for the user's OK" in r["error"] and "gate check key1" in r["error"]
        assert not a.rec.requests, "nothing was sent"
        consent.approve_all(env.form())
        assert web.http({"url": a.url("/echo"), "account": "key1"})["ok"]
        # a widened site: pending until gate check
        env.write_form(KEYFORM.replace('["127.0.0.1"]', '["127.0.0.1", "api.example.com"]'))
        r = web.http({"url": "https://api.example.com/x", "account": "key1"})
        assert not r["ok"] and "waits for the user's OK" in r["error"], r
        r = web.http({"url": "https://example.org/x", "account": "key1"})
        assert not r["ok"] and "goes only to" in r["error"], r
        # the vault binding is checked too (approved but not bound)
        env.write_form(KEYFORM)
        with vault.edit() as d:
            d["accounts"]["key1"]["bound"]["hosts"] = []
        r = web.http({"url": a.url("/echo"), "account": "key1"})
        assert not r["ok"] and "waits for the user's OK" in r["error"], r
        n = len(a.rec.requests)
        assert web.http({"url": a.url("/echo"), "account": "nope"})["error"].startswith(
            "gateway: there is no account nope")
        assert len(a.rec.requests) == n


def test_refusals_for_off_unsigned_and_stale():
    with H.gateway_env() as env, U.servers(_routes()) as (a,):
        _setup(env, token=None)
        r = web.http({"url": a.url("/echo"), "account": "key1"})
        assert "no saved key" in r["error"]
        U.set_token("key1", "api-key", TOKEN)
        with vault.edit() as d:
            d["accounts"]["key1"]["token"]["stale"] = True
        assert "rejected" in web.http({"url": a.url("/echo"), "account": "key1"})["error"]
        env.write_form(KEYFORM + "use = false\n")
        assert "off" in web.http({"url": a.url("/echo"), "account": "key1"})["error"]
        assert not a.rec.requests


def test_url_and_argument_rules():
    with H.gateway_env() as env:
        _setup(env)
        for args, frag in [({"url": "ftp://x.example.com/f"}, "only http"),
                           ({"url": "https://u:p@x.example.com/"}, "user or password"),
                           ({"url": "https://x.example.com:99999/"}, "invalid port"),
                           ({"url": "https://x.example.com/", "method": "G E T"}, "method"),
                           ({"url": "https://x.example.com/", "headers": {"X": "a\nb"}}, "line breaks"),
                           ({"url": "https://x.example.com/", "auth": "bearer"}, "only applies with account"),
                           ({"url": "https://x.example.com/", "body": "a", "json": {}}, "not both"),
                           ({"url": "http://x.example.com/‮"}, "plain")]:
            r = web.http(args)
            assert not r["ok"] and frag in r["error"] and r["error"].startswith("gateway:"), (args, r)


AZFORM = '''[accounts.az]
kind = "azure"
tenant = "asirobots.com"
databricks = ["adb-1.7.azuredatabricks.net"]
storage = ["asistore"]
registries = ["asicr.azurecr.io"]
sites = ["127.0.0.1", "custom.example.com"]
'''


def test_azure_scope_mapping():
    with H.gateway_env():
        _azure_scope_mapping()


def _azure_scope_mapping():
    a = formmod.parse_text(AZFORM).accounts["az"]
    s = web.azure_scope
    assert s(a, "management.azure.com", None) == "https://management.azure.com/.default"
    assert s(a, "graph.microsoft.com", None) == "https://graph.microsoft.com/.default"
    assert s(a, "adb-1.7.azuredatabricks.net", None) == "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d/.default"
    assert s(a, "asistore.blob.core.windows.net", None) == "https://storage.azure.com/.default"
    assert s(a, "asistore.dfs.core.windows.net", None) == "https://storage.azure.com/.default"
    assert s(a, "custom.example.com", "https://custom.example.com/.default") == "https://custom.example.com/.default"
    for host, scope, frag in [("asicr.azurecr.io", None, "crane"), ("custom.example.com", None, "pass scope="),
                              ("custom.example.com", "javascript:x", "scope must"),
                              ("other.blob.core.windows.net", None, "no Entra scope")]:
        try:
            s(a, host, scope)
            raise AssertionError(host)
        except web.Refused as e:
            assert frag in e.message, (host, e.message)


def test_azure_end_to_end_with_a_minted_token():
    minted = []
    tok = "eyJhbGciOiJub25lIn0.eyJhdWQiOiJ4In0.sig-azure-access"

    def fake(name, scope):
        minted.append((name, scope))
        return tok
    with H.gateway_env() as env, U.servers(_routes()) as (a,):
        U.setup(env, AZFORM)
        with vault.edit() as d:
            vault.account_record(d, "az", "azure")["entra"] = {"refresh_token": "rt-123456789",
                                                               "client_id": formmod.AZURE_CLI_CLIENT_ID,
                                                               "tenant_id": "t"}
        with U.patch(web, "entra_token", fake):
            r = web.http({"url": a.url("/echo"), "account": "az"})
            assert not r["ok"] and "scope=" in r["error"]
            r = web.http({"url": a.url("/echo"), "account": "az", "scope": "https://x.example.com/.default"})
        assert r["ok"], r
        assert minted == [("az", "https://x.example.com/.default")]
        assert a.rec.last()["headers"]["Authorization"] == f"Bearer {tok}"
        assert tok not in json.dumps(r)


def test_ml_catalog_uses_the_pinned_scope():
    seen = []
    with H.gateway_env() as env, U.servers(_routes()) as (a,):
        form = f'[accounts.cat]\nkind = "ml-catalog"\nhost = "127.0.0.1:{a.port}"\n'
        U.setup(env, form)
        with vault.edit() as d:
            rec = vault.account_record(d, "cat", "ml-catalog")
            rec["entra"] = {"refresh_token": "rt-abcdefghi", "client_id": formmod.AZURE_CLI_CLIENT_ID,
                            "tenant_id": "t"}
        with U.patch(web, "entra_token", lambda n, s: seen.append(s) or "catalog-access-token-1"):
            r = web.http({"url": a.url("/echo"), "account": "cat"})
            assert not r["ok"] and "gate login cat" in r["error"], "no pinned scope: sign in again"
            with vault.edit() as d:
                d["accounts"]["cat"]["bound"]["scope"] = "api://11111111-2222-3333-4444-555555555555/access_as_user"
            r = web.http({"url": a.url("/echo"), "account": "cat"})
        assert r["ok"] and seen == ["api://11111111-2222-3333-4444-555555555555/access_as_user"]


def test_gateway_owned_headers_are_refused():
    with H.gateway_env() as env:
        _setup(env)
        for h in ("Host", "content-length", "Transfer-Encoding"):
            r = web.http({"url": "https://x.example.com/", "headers": {h: "evil.example.com"}})
            assert not r["ok"] and "set by the gateway" in r["error"], (h, r)


def test_binary_bodies_are_scrubbed_like_text():
    """A binary body goes to Claude as base64: every vault value (not only the
    call's own credential) and the token shapes are masked in the bytes first."""
    with H.gateway_env() as env, U.servers(_routes()) as (a,):
        _setup(env)
        U.set_token("key2", "api-key", OTHER)
        r = web.http({"url": a.url("/bin-leak"), "account": "key1"})
        raw = base64.b64decode(r["body_base64"])
        assert OTHER.encode() not in raw, "another vault value"
        assert ("ghp_" + "B" * 36).encode() not in raw, "a token shape"
        assert TOKEN.encode() not in raw, "the call's own credential"
        assert raw.startswith(b"\x00\x01***\xff***\x00***") and raw.endswith(bytes(range(200, 256))), raw[:40]
        r = web.http({"url": a.url("/bin")})
        assert base64.b64decode(r["body_base64"]) == bytes(range(256)) * 4, "other bytes pass unchanged"


def test_a_body_is_never_resent_to_another_host_on_307_308():
    with H.gateway_env() as env, U.servers(_routes()) as (b,):
        with U.servers(_routes(other=b.url("").rstrip("/"))) as (a,):
            _setup(env)
            r = web.http({"url": a.url("/r307"), "method": "POST", "body": "private-data-123",
                          "account": "key1"})
            assert r["ok"] and r["status"] == 307 and "not followed" in r["redirect"], r
            assert r["headers"]["Location"].endswith("/echo") and r["body"] == "moved"
            assert not b.rec.requests, "nothing went to the other host"
            r = web.http({"url": a.url("/r307"), "method": "PUT", "json": {"x": 1}})
            assert r["status"] == 307 and not b.rec.requests, "json bodies too, with or without account"
            # same host: followed with the body
            r = web.http({"url": a.url("/r308-same"), "method": "POST", "body": "same-host-data",
                          "account": "key1"})
            assert r["ok"] and r["status"] == 200 and a.rec.last()["body"] == b"same-host-data", r
            assert a.rec.last()["headers"].get("Authorization") == f"Bearer {TOKEN}"
            # no body: a cross-host 307 is followed (credential dropped)
            r = web.http({"url": a.url("/r307"), "account": "key1"})
            assert r["ok"] and r["status"] == 200 and "dropped" in r["credential"], r
            assert "Authorization" not in b.rec.last()["headers"]


def test_credentials_go_only_over_https():
    """A credential never goes over plain http (except to this machine's loopback
    address): http://api.example.com with an account is refused before anything
    is sent, whatever the account's sites say."""
    sent = []

    def no_network(*a, **k):
        sent.append(a[0])
        raise web.Refused("gateway: test: nothing may be sent")
    with H.gateway_env() as env, U.servers(_routes()) as (a,):
        _setup(env, KEYFORM.replace('["127.0.0.1"]', '["127.0.0.1", "api.example.com"]'))
        with U.patch(web, "_send", no_network):
            for url in ("http://api.example.com/v1/x", "http://API.example.com:8080/v1/x"):
                for tool in (web.http, web.download):
                    args = {"url": url, "account": "key1"}
                    r = tool(args) if tool is web.http else tool(args, cwd=str(env.root))
                    assert not r["ok"] and "only over https" in r["error"], (url, r)
                    assert TOKEN not in json.dumps(r)
        assert sent == [], "nothing was sent"
        # plain http to the loopback address is this machine: allowed (tests, local services)
        assert web.credential_scheme_ok("http://127.0.0.1:8080/x") and web.credential_scheme_ok("http://[::1]/x")
        assert web.credential_scheme_ok("http://localhost:3000/") and web.credential_scheme_ok("https://x.example.com/")
        assert not web.credential_scheme_ok("http://127.0.0.1.example.com/")
        assert not web.credential_scheme_ok("http://10.0.0.5/")
        r = web.http({"url": a.url("/echo"), "account": "key1"})
        assert r["ok"] and a.rec.last()["headers"]["Authorization"] == f"Bearer {TOKEN}"
        # without an account plain http is fine
        assert web.http({"url": a.url("/hello")})["ok"]


def test_azure_listed_sites_never_get_first_party_scopes():
    """scope= for a listed site may not name ARM, Graph, Storage or Databricks
    (the per-host audience mapping), in any spelling."""
    with H.gateway_env():
        a = formmod.parse_text(AZFORM).accounts["az"]
        bad = ["https://management.azure.com/.default", "https://management.azure.com//.default",
               "https://MANAGEMENT.azure.com/.default", "https://management.core.windows.net/.default",
               "https://graph.microsoft.com/.default", "https://graph.windows.net/.default",
               "https://storage.azure.com/.default", "https://asistore.blob.core.windows.net/.default",
               "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d/.default",
               "api://797f4846-ba00-4fd7-ba43-dac1f8f63013/.default",
               "00000003-0000-0000-c000-000000000000/.default", "https://graph.microsoft.us/.default",
               "https://adb-1.7.azuredatabricks.net/.default"]
        for s in bad:
            try:
                web.azure_scope(a, "custom.example.com", s)
                raise AssertionError(s)
            except web.Refused as e:
                assert "maps by host" in e.message, (s, e.message)
        for s in ("https://custom.example.com/.default", "api://11111111-2222-3333-4444-555555555555/.default",
                  "https://cognitiveservices.azure.com/.default"):
            assert web.azure_scope(a, "custom.example.com", s) == s
        # the first-party hosts themselves still get their own audience
        assert web.azure_scope(a, "management.azure.com", None) == "https://management.azure.com/.default"


def test_a_trickling_server_cannot_hold_the_call_past_its_timeout():
    """Bytes arriving one at a time (each within the socket timeout) in the
    status line and headers, or in the body: the call ends at `timeout`."""
    with H.gateway_env() as env:
        _setup(env)
        for mode in ("headers", "body"):
            with U.trickle_server(mode) as base:
                t0 = time.time()
                r = web.http({"url": base + "/slow", "timeout": 2})
                took = time.time() - t0
            assert not r["ok"] and ("timed out" in r["error"] or "took too long" in r["error"]), (mode, r)
            assert took < 6, (mode, took)
        proj = env.root / "proj"
        proj.mkdir()
        with U.trickle_server("headers") as base:
            t0 = time.time()
            r = web.http({"url": base + "/f.txt", "timeout": 2, "save_to": str(proj / "f.txt")})
            took = time.time() - t0
        assert not r["ok"] and took < 6 and not (proj / "f.txt").exists(), (r, took)


def test_proxy_variables_are_ignored():
    """phase B request (accounts): like entra's client, the http tool never
    routes a request (and its credential) through a proxy named in the
    environment."""
    import harness_accounts as HA
    evil = HA.RecorderServer(reply={"proxied": True})
    try:
        with H.gateway_env() as env, U.servers(_routes()) as (a,):
            _setup(env)
            with U.env_vars(http_proxy=evil.url, HTTP_PROXY=evil.url, https_proxy=evil.url,
                            HTTPS_PROXY=evil.url, ALL_PROXY=evil.url, no_proxy=None, NO_PROXY=None):
                r = web.http({"url": a.url("/echo"), "account": "key1"})
            assert r["ok"] and json.loads(r["body"])["auth"] == "Bearer ***", r
            assert not evil.calls and not evil.saw(TOKEN), "the proxy must never see the request"
    finally:
        evil.close()


def test_ssl_cert_file_is_ignored():
    with H.gateway_env() as env:
        tls = U.self_signed(env.root / "tls")
        assert tls is not None, "this test needs an openssl binary for a throwaway certificate"
        _setup(env)
        with U.servers(_routes(), tls=tls) as (a,):
            with U.env_vars(SSL_CERT_FILE=tls[0], SSL_CERT_DIR=str(env.root / "tls")):
                r = web.http({"url": a.url("/echo"), "account": "key1"})
            assert not r["ok"], "SSL_CERT_FILE must not make the http tool trust a certificate"
