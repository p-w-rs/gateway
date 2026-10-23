"""The account CLI stand-ins (SPEC 9.5, 9.6, 9.7): gh, hf, databricks, crane,
az and `gate with`, against fake binaries that print their env/args. Tokens
must reach the child only in its environment, endpoints are forced, the listed
subcommands are refused, and output is scrubbed even when the fake prints the
token."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import harness as H
import harness_accounts as HA
from gateway import entra, vault

GHTOK = "ghp_WORKtoken0123456789abcdefg"
PTOK = "gho_PERSONALtoken0123456789abc"
HFTOK = "hf_TESTtoken0123456789abcdefgh"

TWO_GH = ('[accounts.github-personal]\nkind = "github"\nlogin = "octocat"\ndefault = true\n'
          '[accounts.github-work]\nkind = "github"\nlogin = "octo-work"\nowners = ["example-org"]\n')


def _fakes(env, **names):
    d = Path(env.root) / "fakebin"
    tools = {n: HA.fake_cli(d, n) for n in names}
    HA.install_fakes(env, **tools)


def _first_json(out: str) -> dict:
    return json.loads(out.splitlines()[0])


# ---------------------------------------------------------------------------
# gh
# ---------------------------------------------------------------------------


def test_gh_routes_by_owner_and_hides_token():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, gh="gh")
        HA.build_vault(env, TWO_GH, tokens={"github-personal": PTOK, "github-work": GHTOK})
        rc, out, err = HA.run_cli("gh", ["pr", "list", "-R", "example-org/thing"])
        assert rc == 0, err
        j = _first_json(out)
        assert j["env"].get("GH_HOST") == "github.com"
        assert j["env"].get("GH_PROMPT_DISABLED") == "1"
        assert "GH_TOKEN" in j["env"]                    # the work token is in the env
        assert GHTOK not in out and PTOK not in out       # never printed in the clear
        assert "TOKEN-SEEN:***" in out                    # the fake printed it; scrubber masked it
        assert GHTOK not in json.dumps(j["argv"])         # never on the command line


def test_gh_enterprise_uses_enterprise_token():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, gh="gh")
        form = '[accounts.ghe]\nkind = "github"\nhost = "github.acme.com"\nlogin = "me"\n'
        HA.build_vault(env, form, tokens={"ghe": GHTOK})
        rc, out, err = HA.run_cli("gh", ["repo", "list", "acme/x"])
        assert rc == 0, err
        j = _first_json(out)
        assert j["env"].get("GH_HOST") == "github.acme.com"
        assert "GH_ENTERPRISE_TOKEN" in j["env"] and "GH_TOKEN" not in j["env"]


def test_gh_refusals():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, gh="gh")
        HA.build_vault(env, TWO_GH, tokens={"github-personal": PTOK, "github-work": GHTOK})
        for argv, needle in [
            (["auth", "token"], "would print the token"),
            (["auth", "login"], "sign-in"),
            (["auth", "status", "--show-token"], "--show-token"),
            (["extension", "list"], "isn't run through the gateway"),
            (["config", "set", "x", "y"], "isn't run through the gateway"),
            (["!shell"], "aliases that run"),
        ]:
            rc, out, err = HA.run_cli("gh", argv)
            assert rc == 2 and needle in err, (argv, err)


def test_gh_token_printing_refusals_cover_flag_spellings():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, gh="gh")
        HA.build_vault(env, TWO_GH, tokens={"github-personal": PTOK, "github-work": GHTOK})
        for argv in (["auth", "status", "--show-token=true"], ["auth", "status", "--show-token=1"],
                     ["auth", "status", "-t"], ["auth", "status", "-t=true"],
                     ["auth", "status", "-at"], ["auth", "status", "-h", "github.com", "-t"]):
            rc, out, err = HA.run_cli("gh", argv)
            assert rc == 2 and "--show-token" in err, (argv, err)
            assert "TOKEN-SEEN" not in out, argv
        # cobra finds the subcommand after flags: `gh auth -h HOST token` is `auth token`
        for argv in (["auth", "--hostname", "github.com", "token"], ["auth", "-h", "github.com", "token"]):
            rc, out, err = HA.run_cli("gh", argv)
            assert rc == 2 and "would print the token" in err, (argv, err)
        # gh's hidden credential-helper mode prints password=<token>
        rc, out, err = HA.run_cli("gh", ["auth", "git-credential", "get"])
        assert rc == 2 and "isn't run here" in err, err
        # controls: a host value or another flag is not mistaken for -t
        for argv in (["auth", "status"], ["auth", "status", "-h", "github.com"],
                     ["auth", "status", "-hgithub.com"], ["auth", "status", "-a"]):
            rc, out, err = HA.run_cli("gh", argv)
            assert rc == 0, (argv, err)


def test_gh_never_sends_the_token_to_another_host():
    """Round 1 (MEDIUM): for a GHES account gh holds GH_ENTERPRISE_TOKEN, which
    gh attaches to every host but github.com (GH_TOKEN goes to any *.ghe.com);
    --hostname, a full-URL `gh api` endpoint, -R HOST/OWNER/REPO and URL
    arguments named another host. Only the account's host (and its api. host,
    when bound) may be named."""
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, gh="gh")
        form = '[accounts.ghe]\nkind = "github"\nhost = "github.acme.com"\nlogin = "me"\n'
        HA.build_vault(env, form, tokens={"ghe": GHTOK})
        for argv in (["api", "--hostname", "evil.example", "/user"],
                     ["api", "--hostname=evil.example", "/user"],
                     ["api", "https://evil.example/api/v3/user"],
                     ["api", "http://evil.example/user"],
                     ["auth", "status", "-h", "evil.example"],
                     ["auth", "status", "-hevil.example"],
                     ["pr", "list", "-R", "evil.example/acme/x"],
                     ["pr", "list", "--repo=https://evil.example/acme/x"],
                     ["pr", "view", "https://evil.example/acme/x/pull/1"],
                     ["repo", "clone", "evil.example/acme/x"],
                     ["repo", "view", "git@evil.example:acme/x.git"],
                     ["api", "--hostname", "github.com", "/user"],
                     ["api", "--hostname", "api.github.acme.com", "/user"]):
            rc, out, err = HA.run_cli("gh", argv)
            assert rc == 2 and "isn't its host (github.acme.com)" in err, (argv, rc, err)
            assert "TOKEN-SEEN" not in out, argv
        for argv in (["api", "--hostname", "github.acme.com", "/user"],
                     ["api", "https://github.acme.com/api/v3/user"],
                     ["pr", "list", "-R", "github.acme.com/acme/x"],
                     ["pr", "list", "-R", "acme/x"],
                     ["release", "upload", "v1", "dist/a/b.tar.gz"]):
            rc, out, err = HA.run_cli("gh", argv)
            assert rc == 0, (argv, err)
        # a github.com account: GH_TOKEN would go to any *.ghe.com host
        HA.build_vault(env, TWO_GH, tokens={"github-personal": PTOK, "github-work": GHTOK})
        rc, out, err = HA.run_cli("gh", ["api", "--hostname", "acme.ghe.com", "/user"])
        assert rc == 2 and "isn't its host (github.com)" in err, err
        rc, out, err = HA.run_cli("gh", ["api", "https://api.github.com/user"])
        assert rc == 0, err


def test_gh_ambiguous_accounts_refuse():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, gh="gh")
        form = ('[accounts.a]\nkind = "github"\nowners = ["dup"]\n'
                '[accounts.b]\nkind = "github"\nlogin = "dup"\n')
        HA.build_vault(env, form, tokens={"a": GHTOK, "b": PTOK})
        rc, out, err = HA.run_cli("gh", ["repo", "view", "dup/x"])
        assert rc == 2 and "fit; set GATE_ACCOUNT" in err


def test_gh_not_direct_refused_unless_scripts():
    with H.gateway_env() as env:
        _fakes(env, gh="gh")
        HA.build_vault(env, TWO_GH, tokens={"github-personal": PTOK, "github-work": GHTOK})
        HA.set_direct((False, "make"))
        rc, out, err = HA.run_cli("gh", ["pr", "list"])
        assert rc == 2 and "got no credential" in err and "make" in err
        # a caller the gateway can't trace back to Claude (ancestry's "?")
        from gateway import ancestry
        HA.set_direct((False, "?"))
        rc, out, err = HA.run_cli("gh", ["pr", "list"])
        assert rc == 2 and (f"gh started by {ancestry.UNTRACED_WHO} got no credential"
                            in err), err
        # scripts = true on the account -> allowed even when not direct
        form = TWO_GH.replace('default = true\n', 'default = true\nscripts = true\n')
        HA.build_vault(env, form, tokens={"github-personal": PTOK, "github-work": GHTOK})
        HA.set_direct(lambda tool, entry_scripts=False: (True, "make") if entry_scripts else (False, "make"))
        rc, out, err = HA.run_cli("gh", ["pr", "list"])
        assert rc == 0, err


# ---------------------------------------------------------------------------
# hf
# ---------------------------------------------------------------------------


def test_hf_forces_endpoint_and_token():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, hf="hf")
        HA.build_vault(env, '[accounts.hf]\nkind = "huggingface"\nlogin = "octocat"\n',
                       tokens={"hf": HFTOK})
        rc, out, err = HA.run_cli("hf", ["download", "org/model"])
        assert rc == 0, err
        j = _first_json(out)
        assert j["env"].get("HF_ENDPOINT") == "https://huggingface.co"
        assert HFTOK not in out and "TOKEN-SEEN:***" in out
        # Round 3: the token is in a 0600 file (HF_TOKEN_PATH), not in the
        # environment, which `ps eww` shows to every process of the user.
        assert "HF_TOKEN" not in j["env"], "the token isn't in hf's environment"
        assert "TOKEN-FILE-MODE:0o600" in out
        assert not os.path.exists(j["env"]["HF_TOKEN_PATH"]), "the token file is gone afterwards"


def test_hf_refusals():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, hf="hf")
        HA.build_vault(env, '[accounts.hf]\nkind = "huggingface"\nlogin = "octocat"\n',
                       tokens={"hf": HFTOK})
        for argv, needle in [(["auth", "login"], "sign-in"), (["auth", "token"], "sign-in"),
                             (["download", "x/y", "--token", "z"], "--token"), (["env"], "env")]:
            rc, out, err = HA.run_cli("hf", argv)
            assert rc == 2 and needle in err, (argv, err)


# ---------------------------------------------------------------------------
# databricks
# ---------------------------------------------------------------------------

AZ = ('[accounts.azure]\nkind = "azure"\ntenant = "contoso.onmicrosoft.com"\n'
      'databricks = ["adb-123.7.azuredatabricks.net"]\n')
ENTRA = {"azure": {"refresh_token": "SEED", "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
                   "tenant_id": "11111111-2222-3333-4444-555555555555", "refreshed": "x"}}


def test_databricks_uses_entra_token_and_forces_host():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, databricks="databricks")
        HA.build_vault(env, AZ, entra=ENTRA)
        with vault.locked():
            vault.cache_put("azure", entra.SCOPES["databricks"], "DBX-TOKEN-ABCDEF123456",
                            time.time() + 3600)
        rc, out, err = HA.run_cli("databricks", ["clusters", "list"])
        assert rc == 0, err
        j = _first_json(out)
        assert j["env"].get("DATABRICKS_HOST") == "https://adb-123.7.azuredatabricks.net"
        assert j["env"].get("DATABRICKS_AUTH_TYPE") == "pat"
        assert "DATABRICKS_TOKEN" in j["env"] and "DBX-TOKEN-ABCDEF123456" not in out


def test_databricks_unlisted_workspace_refused():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, databricks="databricks")
        HA.build_vault(env, AZ, entra=ENTRA)
        import os
        os.environ["DATABRICKS_HOST"] = "https://adb-999.9.azuredatabricks.net"
        try:
            rc, out, err = HA.run_cli("databricks", ["clusters", "list"])
            assert rc == 2 and ("name the workspace" in err or "no azure account" in err or
                                "isn't bound" in err), err
        finally:
            os.environ.pop("DATABRICKS_HOST", None)


def test_databricks_refuses_configure():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, databricks="databricks")
        HA.build_vault(env, AZ, entra=ENTRA)
        rc, out, err = HA.run_cli("databricks", ["configure"])
        assert rc == 2 and "isn't run through the gateway" in err


# ---------------------------------------------------------------------------
# crane
# ---------------------------------------------------------------------------


def test_crane_ghcr_uses_github_token():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, crane="crane")
        HA.build_vault(env, TWO_GH, tokens={"github-personal": PTOK, "github-work": GHTOK})
        rc, out, err = HA.run_cli("crane", ["ls", "ghcr.io/example-org/img"])
        assert rc == 0, err
        j = _first_json(out)
        assert "DOCKER_CONFIG" in j["env"]
        assert GHTOK not in out                       # token not printed
        assert "DOCKER-AUTH:***" in out               # the fake read config.json; scrubbed


def test_crane_azure_uses_cached_acr_token():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, crane="crane")
        form = AZ + 'registries = ["myreg.azurecr.io"]\n'
        HA.build_vault(env, form, entra=ENTRA)
        with vault.locked():
            vault.cache_put("azure", "acr:myreg.azurecr.io", "ACR-REFRESH-TOKEN-123456",
                            time.time() + 3600)
        rc, out, err = HA.run_cli("crane", ["ls", "myreg.azurecr.io/team/img"])
        assert rc == 0, err
        assert "ACR-REFRESH-TOKEN-123456" not in out


def test_crane_refuses_auth():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, crane="crane")
        HA.build_vault(env, TWO_GH, tokens={"github-personal": PTOK, "github-work": GHTOK})
        rc, out, err = HA.run_cli("crane", ["auth", "login", "ghcr.io"])
        assert rc == 2 and "isn't run through the gateway" in err


# ---------------------------------------------------------------------------
# pijul
# ---------------------------------------------------------------------------

PIJUL = '[accounts.pijul]\nkind = "pijul"\nlogin = "octocat"\nname = "P"\nemail = "p@x.io"\n'


def test_pijul_runs_with_identity_and_agent():
    from gateway import vault
    k_priv, _ = H.ssh_keypair("pijul")
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, pijul="pijul")
        HA.build_vault(env, PIJUL, ssh_keys={"pijul": k_priv},
                       host_keys={"pijul": vault.NEST_HOST_KEYS})
        rc, out, err = HA.run_cli("pijul", ["log"])
        assert rc == 0, err
        j = _first_json(out)
        # identity wiring: the account's public key signs changes, a private
        # PIJUL_CONFIG_DIR holds its identity.toml, and the key reaches pijul
        # only through a private agent (its socket is in the run dir; under the
        # long test path the AF_UNIX limit may stop it, so don't require it).
        assert "--config" in j["argv"] and any("signing_key=" in a for a in j["argv"])
        assert j["env"].get("PIJUL_CONFIG_DIR")


def test_pijul_refuses_identity_and_config():
    from gateway import vault
    k_priv, _ = H.ssh_keypair("pijul")
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, pijul="pijul")
        HA.build_vault(env, PIJUL, ssh_keys={"pijul": k_priv},
                       host_keys={"pijul": vault.NEST_HOST_KEYS})
        for argv in (["key", "generate"], ["log", "--config", "x=y"]):
            rc, out, err = HA.run_cli("pijul", argv)
            assert rc == 2, (argv, out)


def test_pijul_is_built_on_first_use_once():
    """conda-forge has no pijul: the first use starts one background build
    (pixi.toml's install-pijul into <data>/pijul) and exits 75; a second call
    while it runs doesn't start another."""
    from gateway import paths, vault
    k_priv, _ = H.ssh_keypair("pijul")
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        HA.build_vault(env, PIJUL, ssh_keys={"pijul": k_priv},
                       host_keys={"pijul": vault.NEST_HOST_KEYS})
        builds = []

        def build(root):
            builds.append(root)
            (paths.data_dir() / "pijul.building").mkdir(parents=True)
        env.o.extra["pijul_build"] = build
        rc, out, err = HA.run_cli("pijul", ["log"])
        assert rc == 75 and "building it in the background" in err, (rc, err)
        assert builds == [paths.data_dir() / "pijul"]
        rc, out, err = HA.run_cli("pijul", ["log"])
        assert rc == 75 and "still being built" in err and len(builds) == 1, err
        del env.o.extra["pijul_build"]
        (paths.data_dir() / "pijul.building").rmdir()
        rc, out, err = HA.run_cli("pijul", ["log"])
        assert rc == 75 and "tests never build it" in err


# ---------------------------------------------------------------------------
# az (minimal)
# ---------------------------------------------------------------------------

AZ_ENV = AZ + 'env = "AZ_TOKEN"\n'


def test_az_only_with_env_set():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        HA.build_vault(env, AZ, entra=ENTRA)   # no env -> az not available
        rc, out, err = HA.run_cli("az", ["account", "show"])
        assert rc == 2 and "env set" in err


def test_az_account_show_and_get_token():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        HA.build_vault(env, AZ_ENV + "scripts = true\n", entra=ENTRA)
        with vault.locked():
            vault.cache_put("azure", entra.SCOPES["arm"], "ARM-TOKEN-ABCDEF123456",
                            time.time() + 3600)
        rc, out, err = HA.run_cli("az", ["account", "show"])
        assert rc == 0, err
        who = json.loads(out)
        assert who["user"]["name"] == "octo-work" or who["tenantId"]
        HA.set_direct((False, "python3.12"))     # an Azure SDK Claude's command started
        rc, out, err = HA.run_cli("az", ["account", "get-access-token", "-o", "json"])
        assert rc == 0, err
        # env opted in + scripts = true + a program: the token itself (an SDK parses it)
        assert json.loads(out)["accessToken"] == "ARM-TOKEN-ABCDEF123456"
        assert '"tokenType": "Bearer"' in out


def test_az_never_gives_claudes_own_command_a_raw_token():
    """Review round 2: a direct caller (Claude's command shell, a wrapper, a
    Monitor command) got the raw Entra token on stdout, which Claude reads;
    Monitor's streamed lines never pass PostToolUse. Now only a program that
    Claude's command started gets it, and only with scripts = true."""
    tok = "ARM-TOKEN-ABCDEF123456"
    with H.gateway_env() as env:
        for extra in ("", "scripts = true\n"):
            HA.build_vault(env, AZ_ENV + extra, entra=ENTRA)
            with vault.locked():
                vault.cache_put("azure", entra.SCOPES["arm"], tok, time.time() + 3600)
            HA.set_direct((True, ""))           # Claude's own command (shells only up to Claude)
            rc, out, err = HA.run_cli("az", ["account", "get-access-token"])
            assert rc == 2 and tok not in out + err and out.strip() == "", (extra, rc, out, err)
            assert "never to a command's own output" in err and 'account "azure"' in err, err
            HA.set_direct((False, "?"))         # ancestry unknown: not a program we can name
            rc, out, err = HA.run_cli("az", ["account", "get-access-token"])
            assert rc == 2 and tok not in out + err, (extra, rc, out, err)
        HA.set_direct((False, "node"))          # a program, scripts = true: the SDK case
        rc, out, err = HA.run_cli("az", ["account", "get-access-token"])
        assert rc == 0 and json.loads(out)["accessToken"] == tok, (rc, err)


def test_az_mints_only_scopes_of_approved_destinations():
    """Round 1 (MEDIUM): az passed any --resource/--scope to Entra and printed
    the token; it now mints only what the http tool would use for one of the
    account's approved, bound destinations (web.azure_scope)."""
    with H.gateway_env() as env:
        HA.set_direct((False, "python3"))      # an SDK (the only caller that gets a token)
        form = AZ_ENV + 'scripts = true\nstorage = ["acmedata"]\nsites = ["api.acme.example"]\n'
        HA.build_vault(env, form, entra=ENTRA)
        minted: list[str] = []
        real = entra.access_token

        def fake(account, scope):
            minted.append(entra.resolve_scope(scope))
            return "TOKEN-FOR-" + entra.resolve_scope(scope).replace("/", "_")
        entra.access_token = fake
        try:
            for args, want in (
                    ([], entra.SCOPES["arm"]),
                    (["--resource", "https://management.azure.com/"], entra.SCOPES["arm"]),
                    (["--resource", "https://management.core.windows.net/"], entra.SCOPES["arm"]),
                    (["--scope", "https://graph.microsoft.com/.default"], entra.SCOPES["graph"]),
                    (["--resource", "https://storage.azure.com"], entra.SCOPES["storage"]),
                    (["--scope", "https://acmedata.blob.core.windows.net/.default"],
                     entra.SCOPES["storage"]),
                    (["--resource", entra.DATABRICKS_RESOURCE], entra.SCOPES["databricks"]),
                    (["--scope", "https://api.acme.example/.default"],
                     "https://api.acme.example/.default")):
                minted.clear()
                rc, out, err = HA.run_cli("az", ["account", "get-access-token", *args])
                assert rc == 0 and minted == [want], (args, rc, err, minted)
            for args in (["--resource", "https://vault.azure.net"],
                         ["--scope", "api://11111111-2222-3333-4444-555555555555/.default"],
                         ["--scope", "https://evil.example/.default"],
                         ["--scope", "https://other.blob.core.windows.net/.default"],
                         ["--resource", "00000003-0000-0000-c000-000000000000"],
                         ["--scope", "https://api.acme.example.evil/.default"]):
                minted.clear()
                rc, out, err = HA.run_cli("az", ["account", "get-access-token", *args])
                assert rc == 2 and minted == [] and "approved destinations" in err, (args, rc, err)
                assert out.strip() == ""
            # a storage account added in the form but not OK'd yet: not minted
            HA.build_vault(env, AZ_ENV + "scripts = true\n", entra=ENTRA)
            env.write_form(AZ_ENV + 'scripts = true\nstorage = ["acmedata"]\n')
            minted.clear()
            rc, out, err = HA.run_cli("az", ["account", "get-access-token", "--resource",
                                             "https://storage.azure.com"])
            assert rc == 2 and minted == [] and "approved destinations" in err, (rc, err)
            # no storage or workspace listed: those scopes aren't minted either
            HA.build_vault(env, AZ.replace('databricks = ["adb-123.7.azuredatabricks.net"]\n', "")
                           + 'env = "AZ_TOKEN"\nscripts = true\n', entra=ENTRA)
            for args in (["--resource", "https://storage.azure.com"],
                         ["--resource", entra.DATABRICKS_RESOURCE]):
                minted.clear()
                rc, out, err = HA.run_cli("az", ["account", "get-access-token", *args])
                assert rc == 2 and minted == [], (args, rc, err)
        finally:
            entra.access_token = real


def test_az_token_only_for_direct_callers_or_scripts():
    """A program Claude started (not its own shell) gets no token unless the
    azure account has scripts = true; then it gets the real token."""
    with H.gateway_env() as env:
        HA.set_direct((False, "make"))
        HA.build_vault(env, AZ_ENV, entra=ENTRA)
        with vault.locked():
            vault.cache_put("azure", entra.SCOPES["arm"], "ARM-TOKEN-ABCDEF123456",
                            time.time() + 3600)
        rc, out, err = HA.run_cli("az", ["account", "get-access-token"])
        assert rc == 2 and out.strip() == "" and "ARM-TOKEN-ABCDEF123456" not in err, (rc, out, err)
        assert "az started by make got no credential" in err and "scripts = true" in err
        HA.set_direct((False, "make"))         # strict ancestry: a program in between
        HA.build_vault(env, AZ_ENV + "scripts = true\n", entra=ENTRA)
        with vault.locked():
            vault.cache_put("azure", entra.SCOPES["arm"], "ARM-TOKEN-ABCDEF123456",
                            time.time() + 3600)
        rc, out, err = HA.run_cli("az", ["account", "get-access-token"])
        assert rc == 0 and json.loads(out)["accessToken"] == "ARM-TOKEN-ABCDEF123456", (rc, err)


def test_direct_check_fails_closed_when_ancestry_errors():
    """clis has no walker of its own any more (ancestry.py is the single
    source); an error there counts as not direct."""
    def boom(tool, entry_scripts=False):
        raise RuntimeError("process table unreadable")
    with H.gateway_env() as env:
        HA.set_direct(boom)
        HA.build_vault(env, AZ_ENV, entra=ENTRA)
        with vault.locked():
            vault.cache_put("azure", entra.SCOPES["arm"], "ARM-TOKEN-ABCDEF123456",
                            time.time() + 3600)
        rc, out, err = HA.run_cli("az", ["account", "get-access-token"])
        assert rc == 2 and "ARM-TOKEN-ABCDEF123456" not in out + err, (rc, out, err)
        assert "got no credential" in err


def test_az_refuses_other_subcommands():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        HA.build_vault(env, AZ_ENV, entra=ENTRA)
        rc, out, err = HA.run_cli("az", ["vm", "list"])
        assert rc == 2 and "only 'account get-access-token'" in err


# ---------------------------------------------------------------------------
# gate with NAME -- CMD
# ---------------------------------------------------------------------------

OPENAI = ('[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n'
          'env = "OPENAI_API_KEY"\n')
OPENKEY = "sk-openaikeyvalue0123456789abcd"


def test_with_sets_env_var_and_scrubs():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        HA.build_vault(env, OPENAI, tokens={"openai": OPENKEY})
        import sys
        prog = ("import os,sys;sys.stdout.write('KEY='+os.environ.get('OPENAI_API_KEY','none')+'\\n')")
        rc, out, err = HA.run_with(["openai", "--", sys.executable, "-c", prog])
        assert rc == 0, err
        assert "KEY=" in out and OPENKEY not in out       # the program saw it; output scrubbed


def test_with_refuses_without_env():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        HA.build_vault(env, '[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n',
                       tokens={"openai": OPENKEY})
        rc, out, err = HA.run_with(["openai", "--", "echo", "hi"])
        assert rc == 2 and "has no env variable" in err, err


def test_with_refuses_azure():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        HA.build_vault(env, AZ_ENV, entra=ENTRA)
        rc, out, err = HA.run_with(["azure", "--", "echo", "hi"])
        assert rc == 2 and "don't expose a raw token" in err


def test_with_not_direct_refused():
    with H.gateway_env() as env:
        HA.build_vault(env, OPENAI, tokens={"openai": OPENKEY})
        HA.set_direct((False, "make"))
        rc, out, err = HA.run_with(["openai", "--", "echo", "hi"])
        assert rc == 2 and "scripts = true" in err


def test_pijul_binary_whose_build_env_is_gone_is_rebuilt():
    from gateway import clis, paths
    with H.gateway_env() as env:
        root = paths.data_dir() / "pijul"
        (root / "bin").mkdir(parents=True)
        b = root / "bin" / "pijul"
        b.write_text("#!/bin/sh\n")
        os.chmod(b, 0o755)
        assert clis._pijul_bin() == str(b), "no record: trusted (a hand-made build)"
        libs = env.root / "envs-pijul-lib"
        libs.mkdir()
        (root / ".built-with").write_text(str(libs) + "\n")
        assert clis._pijul_bin() == str(b)
        libs.rmdir()                     # the env it links against was cleaned up
        assert clis._pijul_bin() is None


def test_gh_with_a_stale_token_names_gate_check_not_a_pop_up():
    """Review round 4: the gh stand-in said a pop-up was open for a rejected
    token, but none is opened; it says to run gate check NAME (as hf does)."""
    from gateway import popup
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        _fakes(env, gh="gh")
        HA.build_vault(env, TWO_GH, tokens={"github-personal": PTOK, "github-work": GHTOK})
        with vault.edit() as d:
            vault.mark_stale(d, "github-work", "token")
        rc, out, err = HA.run_cli("gh", ["pr", "list", "-R", "example-org/thing"])
        assert rc != 0 and popup.pending() == []
        assert "pop-up" not in err, err
        assert ("github-work's token was rejected; don't retry. Run gate check github-work while "
                "the user is here") in err, err
