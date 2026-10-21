"""asiml (SPEC 9.5): init/clone/pull/push/status/search/show/files against a
fake catalog API and a fake dvc, plus the dvc delegation. The storage pass
(SAS) must never reach the output."""
from __future__ import annotations

import os
import time
from pathlib import Path

import harness as H
import harness_accounts as HA
from gateway import entra, vault

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


def _setup(env, cat):
    form = f'[accounts.catalog]\nkind = "ml-catalog"\nhost = "{cat.host}"\n'
    HA.build_vault(env, form, bound_scope={"catalog": SCOPE})
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
                with HA.capture_fds() as box2:
                    rc2 = asiml.dvc_main(["repro"])
                assert rc2 == 2 and "only 'dvc pull'" in box2["err"].decode()
            finally:
                os.chdir(old)
    finally:
        cat.close()


def test_dvc_outside_workspace_refused():
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
            assert rc == 2 and "inside an asiml workspace" in box["err"].decode()
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
            HA.build_vault(env, CAT_SCRIPTS_FORM.format(host=cat.host),
                           bound_scope={"catalog": SCOPE})
            with vault.locked():
                vault.cache_put("catalog", SCOPE, APITOK, time.time() + 3600)
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
