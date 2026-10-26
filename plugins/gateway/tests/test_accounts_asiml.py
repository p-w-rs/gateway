"""asiml (SPEC 9.5): init/clone/pull/push/status/search/show/files against a
fake catalog API and a fake dvc, plus the dvc delegation. The storage pass
(SAS) must never reach the output. The catalog's browser sign-in (PLAN-0.11
§7.4, run by gated): a fixed authority, tenant and scope whatever the
catalog's /api/config names, the client id pinned, and a changed client id
refused until a new sign-in."""
from __future__ import annotations

import os
import time
from pathlib import Path

import harness as H
import harness_accounts as HA
import harness_oauth as HO
from gateway import consent, entra, gate_setup, vault

SCOPE = "api://99999999-8888-7777-6666-555555555555/access_as_user"
APITOK = "CATAPI-TOKEN-0123456789abcdef"

FAKE_DVC = '''#!{py}
import os, sys
args = sys.argv[1:]
# echo the storage pass so the test can prove it is scrubbed
sas = os.environ.get("AZURE_STORAGE_SAS_TOKEN")
if sas:
    sys.stdout.write("DVC-SAS:" + sas + "\\n")
if args and args[0] == "add":
    payload = args[-1]
    open(payload + ".dvc", "w").write(
        "outs:\\n- md5: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.dir\\n  size: 3\\n"
        "  nfiles: 1\\n  hash: md5\\n  path: '" + payload + "'\\n")
sys.stdout.write("dvc " + (args[0] if args else "?") + " ok\\n")
sys.exit(0)
'''


def _fake_dvc(env) -> str:
    d = Path(env.root) / "fakebin"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "dvc"
    p.write_text(FAKE_DVC.format(py=HA.PY))
    os.chmod(p, 0o755)
    return str(p)


CID = "99999999-8888-7777-6666-555555555555"
# the browser sign-in's record (PLAN-0.11 §7): its refresh token, the client
# id it pinned (the catalog's), the tenant
SIGNED_IN = {"refresh_token": "CAT-REFRESH-0", "client_id": CID, "tenant_id": "organizations",
             "kind": "browser", "refreshed": "x", "scope": f"api://{CID}/access_as_user offline_access"}


def _setup(env, cat, form: str | None = None):
    form = form or f'[accounts.catalog]\nkind = "ml-catalog"\nhost = "{cat.host}"\n'
    HA.build_vault(env, form, bound_scope={"catalog": SCOPE}, entra={"catalog": dict(SIGNED_IN)})
    with vault.locked():
        vault.cache_put("catalog", SCOPE, APITOK, time.time() + 3600)
    HA.install_fakes(env, dvc=_fake_dvc(env))
    HA.set_direct((True, ""))


def test_asiml_init_then_push():
    cat = HA.CatalogServer()
    try:
        with H.gateway_env() as env:
            _setup(env, cat)
            wd = Path(env.root) / "ws"
            wd.mkdir()
            rc, out, err = HA.run_asiml(["init", "datasets/demo"], str(wd))
            assert rc == 0, err
            assert (wd / ".asiml" / "workspace.json").exists()
            (wd / "data" / "x.bin").write_text("abc")
            rc, out, err = HA.run_asiml(["push"], str(wd))
            assert rc == 0, err
            assert "published datasets/demo@bbbbbbbb" in out
            # the catalog was asked for a push pass and a complete
            paths = [c["path"] for c in cat.calls]
            assert any(p.endswith("/push") for p in paths)
            assert any(p.endswith("/complete") for p in paths)
            assert "SECRETSAS" not in out
    finally:
        cat.close()


def test_run_dvc_scrubs_the_storage_pass():
    from gateway import asiml
    cat = HA.CatalogServer()
    try:
        with H.gateway_env() as env:
            _setup(env, cat)
            wd = Path(env.root) / "sas"
            wd.mkdir()
            access = {"sasToken": "sig=SECRETSAS123456", "account": "acct"}
            rc, out, err = asiml._run_dvc(wd, ["push"], access)
            assert rc == 0
            assert "SECRETSAS" not in out and "***" in out
    finally:
        cat.close()


def test_asiml_clone_and_pull():
    cat = HA.CatalogServer()
    try:
        with H.gateway_env() as env:
            _setup(env, cat)
            wd = Path(env.root) / "c"
            wd.mkdir()
            rc, out, err = HA.run_asiml(["clone", "datasets/demo", "here"], str(wd))
            assert rc == 0, err
            root = wd / "here"
            assert (root / ".asiml" / "workspace.json").exists()
            assert "retrieved datasets/demo@aaaa" in out
            rc, out, err = HA.run_asiml(["pull"], str(root))
            assert rc == 0, err
            assert "SECRETSAS" not in out
    finally:
        cat.close()


def test_asiml_status():
    cat = HA.CatalogServer()
    try:
        with H.gateway_env() as env:
            _setup(env, cat)
            wd = Path(env.root) / "s"
            wd.mkdir()
            HA.run_asiml(["init", "models/m"], str(wd))
            rc, out, err = HA.run_asiml(["status"], str(wd))
            assert rc == 0, err
            assert "models/m" in out
    finally:
        cat.close()


def test_asiml_search_show_files():
    cat = HA.CatalogServer()
    try:
        with H.gateway_env() as env:
            _setup(env, cat)
            wd = Path(env.root) / "r"
            wd.mkdir()
            rc, out, err = HA.run_asiml(["search", "demo"], str(wd))
            assert rc == 0 and "demo" in out, err
            rc, out, err = HA.run_asiml(["show", "datasets/demo"], str(wd))
            assert rc == 0, err
            rc, out, err = HA.run_asiml(["files", "datasets/demo@" + "a" * 32], str(wd))
            assert rc == 0 and "f.bin" in out, err
            # every call carried a bearer token, and it never leaked to stdout
            assert all("Bearer" in c.get("auth", "") for c in cat.calls if c["path"].startswith("/api/")
                       and c["path"] != "/api/config")
            assert APITOK not in out
    finally:
        cat.close()


def test_asiml_refuses_unknown_command():
    cat = HA.CatalogServer()
    try:
        with H.gateway_env() as env:
            _setup(env, cat)
            wd = Path(env.root) / "u"
            wd.mkdir()
            rc, out, err = HA.run_asiml(["destroy", "everything"], str(wd))
            assert rc == 2 and "no 'destroy' command" in err
    finally:
        cat.close()


def test_asiml_refuses_without_account():
    with H.gateway_env() as env:
        HA.build_vault(env, '[hosts.localhost]\nsudo = true\n')  # no catalog account
        HA.set_direct((True, ""))
        wd = Path(env.root) / "n"
        wd.mkdir()
        rc, out, err = HA.run_asiml(["search", "x"], str(wd))
        assert rc == 2 and "no ml-catalog account" in err, err


def test_dvc_delegates_only_pull_push_in_workspace():
    from gateway import asiml
    cat = HA.CatalogServer()
    try:
        with H.gateway_env() as env:
            _setup(env, cat)
            wd = Path(env.root) / "d"
            wd.mkdir()
            HA.run_asiml(["init", "datasets/demo"], str(wd))
            old = os.getcwd()
            os.chdir(str(wd))
            try:
                with HA._patched_direct(), HA.capture_fds() as box:
                    rc = asiml.dvc_main(["pull"])
                assert rc == 0, box["err"].decode()
                # every other dvc command is the user's own dvc (PLAN-0.11 §1.4;
                # none on this machine: 127)
                with HA.capture_fds() as box2:
                    rc2 = asiml.dvc_main(["repro"])
                assert rc2 == 127 and "dvc isn't installed here" in box2["err"].decode()
            finally:
                os.chdir(old)
    finally:
        cat.close()


def test_dvc_outside_a_workspace_is_the_users_own():
    from gateway import asiml
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        wd = Path(env.root) / "o"
        wd.mkdir()
        old = os.getcwd()
        os.chdir(str(wd))
        try:
            with HA.capture_fds() as box:
                rc = asiml.dvc_main(["pull"])
            assert rc == 127 and "dvc isn't installed here" in box["err"].decode()
        finally:
            os.chdir(old)


# ---------------------------------------------------------------------------
# Direct vs scripts (SPEC 9, 10), redirects and proxies (invariant: a token
# goes only to its bound host)
# ---------------------------------------------------------------------------

CAT_SCRIPTS_FORM = '[accounts.catalog]\nkind = "ml-catalog"\nhost = "{host}"\nscripts = true\n'


def _api_calls(cat) -> list:
    return [c for c in cat.calls if c["path"].startswith("/api/") and c["path"] != "/api/config"]


def test_asiml_not_direct_refused_unless_scripts():
    cat = HA.CatalogServer()
    try:
        with H.gateway_env() as env:
            _setup(env, cat)
            wd = Path(env.root) / "nd"
            wd.mkdir()
            HA.set_direct((False, "make"))
            rc, out, err = HA.run_asiml(["search", "demo"], str(wd))
            assert rc == 2 and "got no credential" in err and "make" in err, err
            assert "scripts = true for catalog" in err
            from gateway import ancestry
            HA.set_direct((False, "?"))
            rc, out, err = HA.run_asiml(["search", "demo"], str(wd))
            assert rc == 2 and f"started by {ancestry.UNTRACED_WHO} got no credential" in err, err
            HA.set_direct((False, "make"))
            assert not _api_calls(cat), "a non-direct caller must not reach the catalog with a token"
            # init and status use no credential: not gated
            rc, out, err = HA.run_asiml(["init", "datasets/demo"], str(wd))
            assert rc == 0, err
            rc, out, err = HA.run_asiml(["status"], str(wd))
            assert rc == 0, err
            # push and pull would hand the storage pass to dvc: gated
            (wd / "data" / "x.bin").write_text("abc")
            for argv in (["push"], ["pull", "latest"]):
                rc, out, err = HA.run_asiml(argv, str(wd))
                assert rc == 2 and "got no credential" in err, (argv, err)
            assert not _api_calls(cat)
            # scripts = true on the account: allowed even when not direct
            _setup(env, cat, CAT_SCRIPTS_FORM.format(host=cat.host))
            HA.set_direct(lambda tool, entry_scripts=False:
                          (True, "make") if entry_scripts else (False, "make"))
            rc, out, err = HA.run_asiml(["search", "demo"], str(wd))
            assert rc == 0 and "demo" in out, err
            assert _api_calls(cat)
    finally:
        cat.close()


def test_dvc_delegation_not_direct_is_refused():
    from gateway import asiml
    cat = HA.CatalogServer()
    try:
        with H.gateway_env() as env:
            _setup(env, cat)
            wd = Path(env.root) / "dd"
            wd.mkdir()
            HA.run_asiml(["init", "datasets/demo"], str(wd))
            HA.set_direct((False, "npm"))
            old = os.getcwd()
            os.chdir(str(wd))
            try:
                with HA._patched_direct(), HA.capture_fds() as box:
                    rc = asiml.dvc_main(["pull"])
            finally:
                os.chdir(old)
            err = box["err"].decode()
            assert rc == 2 and "dvc started by npm got no credential" in err, err
            assert not _api_calls(cat)
    finally:
        cat.close()


def test_asiml_does_not_follow_a_redirect_with_the_token():
    evil = HA.RecorderServer(reply={"items": [{"name": "stolen"}]})
    cat = HA.CatalogServer(redirect_to=evil.url)
    try:
        with H.gateway_env() as env:
            _setup(env, cat)
            wd = Path(env.root) / "rd"
            wd.mkdir()
            rc, out, err = HA.run_asiml(["search", "demo"], str(wd))
            assert rc == 2 and "redirect" in err, (rc, err)
            rc2, out2, err2 = HA.run_asiml(["clone", "datasets/demo", "c"], str(wd))
            assert rc2 == 2 and "redirect" in err2, (rc2, err2)
            assert not evil.calls, "a redirect must not be followed (it would carry the token)"
            assert not evil.saw(APITOK)
            # the catalog itself did see the token (so the redirect, not a missing
            # token, is what was refused)
            assert any(APITOK in c["auth"] for c in cat.calls if c.get("redirected"))
    finally:
        cat.close()
        evil.close()


def test_asiml_ignores_proxy_variables():
    evil = HA.RecorderServer(reply={"items": [{"name": "via-proxy"}]})
    cat = HA.CatalogServer()
    try:
        with H.gateway_env() as env:
            _setup(env, cat)
            wd = Path(env.root) / "px"
            wd.mkdir()
            with HA.env_vars(http_proxy=evil.url, HTTP_PROXY=evil.url, https_proxy=evil.url,
                             HTTPS_PROXY=evil.url, no_proxy=None, NO_PROXY=None):
                rc, out, err = HA.run_asiml(["search", "demo"], str(wd))
            assert rc == 0 and "demo" in out and "via-proxy" not in out, (rc, out, err)
            assert not evil.calls and not evil.saw(APITOK), \
                "a proxy variable in Claude's environment must not see the catalog token"
    finally:
        cat.close()
        evil.close()


def test_asiml_names_a_catalog_account_that_is_off_instead_of_saying_there_is_none():
    """A catalog account that is off because of a mistake (a converted 0.6
    catalog without host) is named with its problem, so Claude fixes it
    instead of adding a second catalog account; with none at all the message
    says what to add (kind and host)."""
    with H.gateway_env() as env:
        HA.build_vault(env, '[accounts.catalog]\nkind = "ml-catalog"\nlogin = "w@example.com"\n')
        HA.set_direct((True, ""))
        wd = Path(env.root) / "off"
        wd.mkdir()
        rc, out, err = HA.run_asiml(["search", "x"], str(wd))
        assert rc == 2, err
        assert "the ml-catalog account catalog is off" in err and "host is required" in err, err
        assert "ask the user to fix [accounts.catalog]" in err, err
        assert "rather than adding another" in err and "no ml-catalog account" not in err, err
    with H.gateway_env() as env:
        HA.build_vault(env, '[hosts.localhost]\nsudo = true\n')
        HA.set_direct((True, ""))
        wd = Path(env.root) / "none"
        wd.mkdir()
        rc, out, err = HA.run_asiml(["search", "x"], str(wd))
        assert rc == 2 and "no ml-catalog account" in err, err
        assert 'kind = "ml-catalog" with host = the catalog\'s address' in err, err


SITE_DVC = '''#!{py}
import os, sys
sys.stdout.write("SITE=" + os.environ.get("DVC_SITE_CACHE_DIR", "") + "\\n")
sys.exit(0)
'''


def test_dvc_runs_with_a_site_cache_in_a_folder_of_its_own():
    """dvc's site cache (its repo index and locks) is the user's
    ~/.local/share/asiml/site-cache, a folder of the gateway's asiml's own."""
    from gateway import asiml, paths
    with H.gateway_env() as env:
        d = Path(env.root) / "fakebin"
        d.mkdir(parents=True, exist_ok=True)
        p = d / "dvc"
        p.write_text(SITE_DVC.format(py=HA.PY))
        os.chmod(p, 0o755)
        HA.build_vault(env, '[hosts.localhost]\nsudo = true\n')
        HA.install_fakes(env, dvc=str(p))
        wd = Path(env.root) / "site"
        wd.mkdir()
        rc, out, err = asiml._run_dvc(wd, ["status"], None)
        want = paths.user_home() / ".local" / "share" / "asiml" / "site-cache"
        assert rc == 0 and f"SITE={want}" in out, (out, err)


# ---------------------------------------------------------------------------
# The catalog's browser sign-in (PLAN-0.11 §7.4)
# ---------------------------------------------------------------------------

OTHER = "77777777-6666-5555-4444-333333333333"


def test_a_catalog_naming_another_client_id_is_refused_until_a_new_sign_in():
    from gateway import asiml
    cat = HA.CatalogServer()
    try:
        with H.gateway_env() as env:
            _setup(env, cat)
            wd = Path(env.root) / "cid"
            wd.mkdir()
            asiml._CFG.clear()
            rc, out, err = HA.run_asiml(["search", "demo"], str(wd))
            assert rc == 0, err
            cat.client_id = OTHER                    # the catalog names another app now
            asiml._CFG.clear()
            n = len(_api_calls(cat))
            rc, out, err = HA.run_asiml(["search", "demo"], str(wd))
            assert rc == 2 and "changed since catalog signed in" in err and "gate check catalog" in err, err
            assert len(_api_calls(cat)) == n, "no token went out"
            # gate check sees it too: a new sign-in (whose dialog shows the change)
            data = vault.load()
            form = env.form()
            p = gate_setup.plan_for("catalog", form, consent.compute(form, data), data)
            assert p.needs_signin and p.browser and any("another client id" in x for x in p.notes)
    finally:
        cat.close()


def test_a_catalog_sign_in_from_an_older_gateway_is_refused():
    from gateway import asiml
    cat = HA.CatalogServer()
    try:
        with H.gateway_env() as env:
            _setup(env, cat)
            from gateway import adapters
            rec = vault.load()["accounts"]["catalog"]
            assert adapters.credential_of("ml-catalog", rec) == "browser sign-in"
            with vault.edit() as d:
                d["accounts"]["catalog"]["entra"].pop("kind")
            assert adapters.credential_of("ml-catalog", vault.load()["accounts"]["catalog"]) == "refresh token"
            asiml._CFG.clear()
            wd = Path(env.root) / "old"
            wd.mkdir()
            rc, out, err = HA.run_asiml(["search", "demo"], str(wd))
            assert rc == 2 and "isn't signed in" in err and "browser sign-in" in err, err
            assert not _api_calls(cat)
    finally:
        cat.close()


def test_the_catalog_sign_in_has_a_fixed_authority_tenant_and_scope_and_pins_the_client():
    """The catalog's /api/config names an authority, a tenant and a Graph
    scope: none is used. The authority is the gateway's, the tenant the
    account's own ("organizations" by default), the scope fixed around the
    catalog's client id, which the vault pins."""
    from gateway import asiml
    evil = HA.RecorderServer(reply={"ok": True})
    cat = HA.CatalogServer(extra_config={"authority": evil.url, "tenantId": "22222222-2222-2222-2222-222222222222",
                                         "scope": "https://graph.microsoft.com/.default"})
    try:
        form = f'[accounts.models]\nkind = "ml-catalog"\nhost = "{cat.host}"\n'
        with HO.sso(form) as s:
            pid = HO.gate(s, "check", "models")
            d = s.mod.dialog(HO.is_signin)
            want = f"api://{CID}/access_as_user offline_access"
            assert d["signin"] == {"account": "models", "kind": "ml-catalog", "tenant": "organizations",
                                   "client": CID, "scope": want, "host": cat.host,
                                   "previous_client": ""}, d["signin"]
            s.mod.open(d)
            rc, out, err = HO.result(s, pid)
            assert rc == 0 and "models ready: signed in" in out, (out, err)
            # (the vault passphrase offer after the first stored secret, PLAN-0.11 §8: dismissed)
            s.mod.post("/ui/dialog/cancel",
                       {"id": s.mod.dialog(lambda d: d.get("offer") == "passphrase")["id"]})
            az = s.srv.authorize[0]
            assert az["tenant"] == "organizations" and az["scope"] == want and az["client_id"] == CID
            assert HO.opened(s.log)[0]["url"].startswith(f"{s.srv.authority}/organizations/")
            assert not evil.calls, "nothing went to an authority the catalog named"
            rec = vault.load()["accounts"]["models"]
            assert rec["entra"]["client_id"] == CID and rec["entra"]["kind"] == "browser"
            assert rec["entra"]["tenant_id"] == "organizations"
            assert rec["bound"]["scope"] == f"api://{CID}/access_as_user"
            # asiml uses the sign-in (its refresh token mints the API token)
            HA.install_fakes(s.de.env, dvc=_fake_dvc(s.de.env))
            HA.set_direct((True, ""))
            asiml._CFG.clear()
            wd = Path(s.de.root) / "ws"
            wd.mkdir()
            rc, out, err = HA.run_asiml(["search", "demo"], str(wd))
            assert rc == 0 and "demo" in out, err
            # (gated cached the sign-in's access token under the pinned API scope)
            assert [c["auth"] for c in _api_calls(cat)] == ["Bearer SSO-ACCESS-1"], cat.calls
            # the catalog names another client now: gate check signs in again, and the
            # dialog shows the change (cancelled here: nothing changes)
            cat.client_id = OTHER
            pid = HO.gate(s, "check", "models")
            d = s.mod.dialog(HO.is_signin)
            assert d["signin"]["client"] == OTHER and d["signin"]["previous_client"] == CID, d["signin"]
            assert d["signin"]["scope"] == f"api://{OTHER}/access_as_user offline_access"
            s.mod.post("/ui/dialog/cancel", {"id": d["id"]})
            rc, out, err = HO.result(s, pid)
            assert rc == 1 and "another client id" in err, err
            assert vault.load()["accounts"]["models"]["entra"]["client_id"] == CID
    finally:
        cat.close()
        evil.close()


def test_gated_signs_in_only_a_catalog_that_is_bound():
    """§7.4: the host must be approved (bound) before gated reads its
    /api/config or asks for a sign-in to it."""
    from types import SimpleNamespace

    from gateway import asiml
    from gateway.daemon import oauth
    cat = HA.CatalogServer()
    try:
        with H.gateway_env() as env:
            _setup(env, cat)
            d = SimpleNamespace(broker=SimpleNamespace(read=lambda touch=True: vault.load()))
            asiml._CFG.clear()
            p = oauth.params_for(d, "catalog")
            assert p.client_id == CID and p.host == cat.host and p.kind == "ml-catalog"
            with vault.edit() as data:
                data["accounts"]["catalog"]["bound"]["hosts"] = []
            try:
                oauth.params_for(d, "catalog")
                raise AssertionError("gated would sign in to a catalog that isn't bound")
            except oauth.SignInError as e:
                assert e.code == "unbound" and e.status == 409, (e.code, e.message)
    finally:
        cat.close()


def test_a_catalogs_changed_tenant_needs_a_new_sign_in():
    """A sign-in made for another tenant than the approved one's isn't used:
    gate check asks for a new one, and the status says so."""
    from gateway import asiml
    cat = HA.CatalogServer()
    try:
        with H.gateway_env() as env:
            form_text = (f'[accounts.catalog]\nkind = "ml-catalog"\nhost = "{cat.host}"\n'
                         'tenant = "contoso.onmicrosoft.com"\n')
            _setup(env, cat, form_text)          # signed in for "organizations"
            asiml._CFG.clear()
            form, data = env.form(), vault.load()
            eff = consent.compute(form, data)
            p = gate_setup.plan_for("catalog", form, eff, data)
            assert p.needs_signin and p.browser and not p.changes, p
            assert "catalog ready: needs a new sign-in" in gate_setup.status_line("catalog", form, eff, data)
            with vault.edit() as d:
                d["accounts"]["catalog"]["entra"]["tenant_id"] = "contoso.onmicrosoft.com"
            data = vault.load()
            p = gate_setup.plan_for("catalog", form, consent.compute(form, data), data)
            assert not p.needs_signin, p
            assert "catalog ready: signed in" in gate_setup.status_line("catalog", form, eff, data)
    finally:
        cat.close()
