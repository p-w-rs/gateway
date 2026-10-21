"""Account adapters and their states (PLAN-v4 phase 7, adapters.py): GitHub
(fine-grained or classic PAT), Hugging Face (token), Azure (service
principal secret or certificate, an existing refresh token), each checked
with one cheap API call to the account's bound host and its state told
apart from the service's answers: configured, connected, expired, revoked,
reauthentication_required, unknown, missing. A browser login (a `gh auth`
of the user's own) is never API authorization. Canaries are generated here
and never printed."""
from __future__ import annotations

import http.server
import json
import secrets
import subprocess
import threading
from pathlib import Path
from typing import Any

import harness as H
import harness_accounts as HA
from gateway import adapters, consent, testing, vault
from gateway import form as F


class Api:
    """A local API answering GET with a configured (status, headers, body)."""

    def __init__(self) -> None:
        self.answer: tuple[int, dict[str, str], Any] = (200, {}, {})
        self.seen: list[dict[str, Any]] = []
        api = self

        class Hd(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a: Any) -> None:
                pass

            def do_GET(self) -> None:
                api.seen.append({"path": self.path, "auth": bool(self.headers.get("Authorization"))})
                st, hd, body = api.answer
                data = json.dumps(body).encode()
                self.send_response(st)
                for k, v in hd.items():
                    self.send_header(k, v)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hd)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self) -> None:
        self.httpd.shutdown()
        self.httpd.server_close()


GH = '[accounts.gh]\nkind = "github"\nlogin = "octo"\n'
HF = '[accounts.hf]\nkind = "huggingface"\n'
AZ = ('[accounts.az]\nkind = "azure"\ntenant = "11111111-2222-3333-4444-555555555555"\n'
      'client_id = "99999999-8888-7777-6666-555555555555"\n')


def _setup(env: Any, form: str, name: str, kind: str, token: str | None = None,
           entra: dict[str, Any] | None = None) -> None:
    env.write_form(form)
    vault.save(vault.empty())
    consent.approve_all(env.form())
    with vault.edit() as d:
        r = vault.account_record(d, name, kind)
        if token is not None:
            r["token"] = {"value": token, "source": "pasted", "updated": vault.now(), "stale": False}
        if entra is not None:
            r["entra"] = entra


def _check(name: str) -> adapters.Check:
    return adapters.check_and_record(name)


def test_github_states_come_from_githubs_answers():
    api = Api()
    try:
        with H.gateway_env() as env:
            env.o.extra["github_api"] = api.url
            tok = "github_pat_" + secrets.token_hex(20)
            _setup(env, GH, "gh", "github", tok)
            a = env.form().accounts["gh"]
            assert adapters.stored_state(a, vault.load()["accounts"]["gh"]).state == "configured"
            api.answer = (200, {"github-authentication-token-expiration": "2099-01-01 00:00:00 UTC"},
                          {"login": "octo"})
            c = _check("gh")
            assert c.state == "connected" and c.meta["credential"] == "fine-grained personal access token"
            assert c.meta["expires_at"] == "2099-01-01T00:00:00Z" and c.meta["login"] == "octo"
            assert api.seen[-1]["auth"] is True
            st = adapters.stored_state(a, vault.load()["accounts"]["gh"])
            assert st.state == "connected" and st.checked_at
            # refused after a reported expiry that has passed: expired
            with vault.edit() as d:
                d["accounts"]["gh"]["status"]["meta"]["expires_at"] = "2001-01-01T00:00:00Z"
            api.answer = (401, {}, {"message": "Bad credentials"})
            assert _check("gh").state == "expired"
            # refused with no expiry passed: revoked
            with vault.edit() as d:
                d["accounts"]["gh"]["status"]["meta"]["expires_at"] = "2099-01-01T00:00:00Z"
            assert _check("gh").state == "revoked"
            api.answer = (403, {"X-GitHub-SSO": "required; url=https://x"}, {})
            assert _check("gh").state == "reauthentication_required"
            api.answer = (500, {}, {})
            assert _check("gh").state == "unknown"
            api.answer = (200, {}, {"login": "someone-else"})
            assert _check("gh").state == "revoked"          # another login's token
            # nothing of the token in what the check keeps
            assert tok not in json.dumps(vault.load()["accounts"]["gh"]["status"])
            # a classic token is named as one
            with vault.edit() as d:
                d["accounts"]["gh"]["token"]["value"] = "ghp_" + "a" * 36
            assert adapters.credential_of("github", vault.load()["accounts"]["gh"]) == \
                "classic personal access token"
    finally:
        api.close()


def test_huggingface_states_and_the_binding():
    api = Api()
    try:
        with H.gateway_env() as env:
            env.o.extra["hf_api"] = api.url
            _setup(env, HF, "hf", "huggingface", "hf_" + secrets.token_hex(16))
            api.answer = (200, {}, {"name": "hugger", "auth": {"accessToken": {"role": "read"}}})
            c = _check("hf")
            assert c.state == "connected" and c.meta["login"] == "hugger" and c.meta["role"] == "read"
            api.answer = (401, {}, {"error": "Invalid credentials in Authorization header"})
            assert _check("hf").state == "revoked"
            # an unbound credential is never sent for a check
            n = len(api.seen)
            with vault.edit() as d:
                d["accounts"]["hf"]["bound"]["hosts"] = []
            c = _check("hf")
            assert c.state == "unknown" and "isn't bound" in c.detail and len(api.seen) == n
    finally:
        api.close()


def _cert(tmp: Path) -> tuple[str, Path]:
    key, crt, pub = tmp / "k.pem", tmp / "c.pem", tmp / "pub.pem"
    o = str(HA.ENV_BIN / "openssl")
    subprocess.run([o, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=gw-test",
                    "-keyout", str(key), "-out", str(crt), "-days", "1"], check=True,
                   capture_output=True, env={"OPENSSL_CONF": "/dev/null", "PATH": "/usr/bin:/bin"})
    subprocess.run([o, "x509", "-in", str(crt), "-pubkey", "-noout", "-out", str(pub)], check=True,
                   capture_output=True, env={"OPENSSL_CONF": "/dev/null", "PATH": "/usr/bin:/bin"})
    return crt.read_text() + key.read_text(), pub


def test_azure_states_for_a_secret_a_certificate_and_a_refresh_token():
    with H.gateway_env() as env:
        tmp = env.root / "cert"
        tmp.mkdir()
        pem, pub = _cert(tmp)
        srv = HA.EntraServer(secret="sp-secret-good-0123456789", cert_pub=pub)
        try:
            env.o.extra["entra_authority"] = srv.authority
            base = {"client_id": "99999999-8888-7777-6666-555555555555",
                    "tenant_id": "11111111-2222-3333-4444-555555555555", "kind": "service-principal"}
            _setup(env, AZ, "az", "azure", entra={**base, "client_secret": "sp-secret-good-0123456789"})
            assert _check("az").state == "connected"
            for codes, state in (([7000222], "expired"), ([7000215], "revoked"),
                                 ([50076], "reauthentication_required"), ([700082], "expired")):
                srv.refuse = {"status": 400, "error": "invalid_client", "codes": codes,
                              "description": f"AADSTS{codes[0]}: refused"}
                assert _check("az").state == state, (codes, state)
            srv.refuse = None
            # a certificate: a client assertion signed here, verified by the server
            with vault.edit() as d:
                d["accounts"]["az"]["entra"] = {**base, "client_certificate": pem}
            c = _check("az")
            assert c.state == "connected" and c.meta["credential"] == "service principal certificate", c
            assert srv.assertions and srv.assertions[-1]["verified"] is True
            assert srv.calls[-1].get("client_assertion_type", "").endswith("jwt-bearer")
            assert "client_secret" not in srv.calls[-1]
            # the key is never on a command line or in the assertion's text
            key_body = pem.split("-----BEGIN PRIVATE KEY-----")[1][:40]
            assert key_body not in json.dumps(srv.calls)
            # another key than the certificate's: Entra refuses it
            other, _p = _cert(env.root / "cert2") if (env.root / "cert2").mkdir() is None else ("", None)
            mixed = pem.split("-----BEGIN PRIVATE KEY-----")[0] + "-----BEGIN PRIVATE KEY-----" + \
                other.split("-----BEGIN PRIVATE KEY-----")[1]
            with vault.edit() as d:
                d["accounts"]["az"]["entra"] = {**base, "client_certificate": mixed}
            assert _check("az").state == "revoked"
            # a refresh token stored before: rotated and saved by the check
            with vault.edit() as d:
                d["accounts"]["az"]["entra"] = {**base, "refresh_token": "RT-OLD-0123456789"}
                d["accounts"]["az"]["entra"].pop("kind")
            assert _check("az").state == "connected"
            assert vault.load()["accounts"]["az"]["entra"]["refresh_token"].startswith("ROT-REFRESH-")
        finally:
            srv.close()


def test_a_pem_must_hold_one_certificate_and_one_unencrypted_key():
    for bad in ("not pem", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"
                "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n",
                "junk -----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----"):
        try:
            adapters.cert_parts(bad)
            raise AssertionError(bad)
        except ValueError:
            pass


def test_a_browser_login_is_never_api_authorization():
    """The user's own `gh auth login` (a token in ~/.config/gh/hosts.yml) or
    a Hugging Face login in ~/.cache/huggingface leave a gateway account
    without a stored credential "missing": the gateway's states come only
    from its own credential and the service's API."""
    with H.gateway_env() as env:
        home = env.o.user_home
        (home / ".config" / "gh").mkdir(parents=True)
        (home / ".config" / "gh" / "hosts.yml").write_text(
            "github.com:\n    oauth_token: gho_" + "b" * 36 + "\n    user: octo\n")
        (home / ".cache" / "huggingface").mkdir(parents=True)
        (home / ".cache" / "huggingface" / "token").write_text("hf_" + "c" * 30)
        _setup(env, GH + HF, "gh", "github")
        rows = {r["account"]: r for r in adapters.summary(env.form(), vault.load())}
        assert rows["gh"]["state"] == "missing" and rows["hf"]["state"] == "missing", rows
        assert _check("gh").state == "missing"


def test_gate_accounts_lists_and_checks_states_without_values():
    import io
    import sys
    from gateway import manage
    api = Api()
    try:
        with H.gateway_env() as env:
            env.o.extra["github_api"] = api.url
            tok = "ghp_" + secrets.token_hex(18)
            _setup(env, GH + HF, "gh", "github", tok)
            api.answer = (200, {}, {"login": "octo"})
            out = io.StringIO()
            so = sys.stdout
            sys.stdout = out
            try:
                rc = manage.main("accounts", ["--check", "gh", "--json"])
            finally:
                sys.stdout = so
            assert rc == 0
            doc = json.loads(out.getvalue())
            rows = {r["account"]: r for r in doc["accounts"]}
            assert rows["gh"]["state"] == "connected" and rows["hf"]["state"] == "missing"
            assert tok not in out.getvalue()
            # a new token starts over as configured (gate login stores through _store_token)
            from gateway import gate_setup
            gate_setup._store_token("gh", "github", "ghp_" + "d" * 36, "pasted")
            rows = {r["account"]: r for r in adapters.summary(env.form(), vault.load())}
            assert rows["gh"]["state"] == "configured"
    finally:
        api.close()


def test_no_adapter_needs_a_cookie_or_session_store():
    """GitHub, Hugging Face and Azure take API credentials; the only
    session-like state is an Entra refresh token, kept in the vault's entra
    record (docs: DECISIONS "PLAN-v4 phase 7")."""
    assert set(adapters.CHECKED_KINDS) == {"github", "huggingface", "azure"}
    for kind in adapters.CHECKED_KINDS:
        assert not any("cookie" in m.lower() for m in adapters.METHODS[kind])
    assert "unavailable" in adapters.METHODS["ml-catalog"][0]
    _ = (F, testing)


def test_a_pem_paste_may_hold_line_breaks_only_when_the_dialog_asks_for_a_pem():
    from gateway.daemon import clipboard
    pem = b"-----BEGIN CERTIFICATE-----\r\nAAAA\r\n-----END CERTIFICATE-----\n"
    try:
        clipboard.accept(pem)
        raise AssertionError("a one-line field took several lines")
    except clipboard.ClipboardError:
        pass
    assert clipboard.accept(pem, multiline=True) == pem.decode().replace("\r\n", "\n").rstrip("\n")
    for bad in (b"a\x07b", b"a\x1b[31mb", b"a\x00b"):
        try:
            clipboard.accept(bad, multiline=True)
            raise AssertionError(bad)
        except clipboard.ClipboardError:
            pass
