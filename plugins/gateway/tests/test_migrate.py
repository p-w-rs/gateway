"""Migration from v2 (SPEC 4): a synthetic vault shaped like the user's,
naming, the full mapping, idempotency and failure paths (store.age is never
touched before success)."""
from __future__ import annotations

import hashlib
import json
import os
import re

import harness as H
from gateway import consent, migrate, paths, vault, vault_v2
from gateway import form as F


def _setup_v2(env, data=None):
    user = paths.local_user()
    data = data if data is not None else H.users_v2_vault(user)
    paths.ensure_home()
    H.write_v2_vault(paths.home(), data)
    return data


def _sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()


_CACHE: dict = {}


def _users_data():
    if "d" not in _CACHE:
        with H.gateway_env():
            _CACHE["d"] = H.users_v2_vault(paths.local_user())
    return json.loads(json.dumps(_CACHE["d"]))


def test_a_converted_06_vault_keeps_sudo_true_on_this_computer():
    """New installs start with sudo = "ask" on this computer; a 0.6 vault
    converted now still gets [hosts.localhost] sudo = true, approved by the
    migration (SPEC 4), with or without a stored sudo password, and keeps it
    through the next session start."""
    from gateway import hooks_bash, hooks_session
    for v2 in ({"version": 2, "secrets": {}, "sudo": {}, "accounts": {}}, None):
        with H.gateway_env() as env:
            _setup_v2(env, v2 if v2 is not None else _users_data())
            r = migrate.run("test")
            assert r.ok and r.status == "migrated", r.message
            text = paths.form_path().read_text()
            loc = text.split("[hosts.localhost]", 1)[1].split("\n[", 1)[0]
            assert "\nsudo = true" in loc, text
            f = env.form()
            assert f.hosts["localhost"].explicit and f.hosts["localhost"].sudo is True
            data = vault.load()
            assert data["approved"]["rights"]["hosts"]["localhost"]["sudo"] is True
            hooks_session.session_main({"session_id": "after-06", "source": "startup"})
            eff = consent.compute(env.form(), vault.load())
            assert eff.hosts["localhost"].sudo is True and "localhost" not in eff.pending_names()
            out = hooks_bash.main({"tool_name": "Bash", "permission_mode": "auto",
                                   "tool_input": {"command": "sudo ls"}})
            assert out["hookSpecificOutput"]["permissionDecision"] == "allow", out
            assert paths.form_path().read_text() == text


def test_a_06_catalog_account_gets_its_host_written_out():
    """The gateway has no default catalog host: a 0.6 catalog account gets
    0.6's host (else the one host it was bound to, also when its list names
    it twice) as `host`; with neither (no host, or several), a commented
    `host` line and a note naming what 0.6 had, its sign-in kept in the vault
    and an approval snapshot with no destination kept for it (m.hostless)."""
    rt = "0.CCCC-catalog-refresh-token-xyz"

    def v2(acct):
        acct = {"kind": "mlcat", "login": "work@example.com", "tenant_id": "t.example.com",
                "client_id": "99999999-8888-7777-6666-555555555555",
                "secrets": {"refresh_token": rt}, **acct}
        return {"version": 2, "secrets": {}, "sudo": {}, "accounts": {"mlcat:work": acct}}

    with H.gateway_env():
        for acct, host in (({"host": "Catalog.Example.com"}, "catalog.example.com"),
                           ({"hosts": ["models.example.org"]}, "models.example.org"),
                           ({"hosts": ["models.example.org", "Models.Example.org "]},
                            "models.example.org")):
            m = migrate.map_v2(v2(acct), local_user="me")
            f = F.parse_text(m.form_text)
            assert f.accounts["catalog"].host == host, m.form_text
            assert m.vault["accounts"]["catalog"]["bound"]["hosts"] == [host]
        m = migrate.map_v2(v2({"hosts": []}), local_user="me")
        f = F.parse_text(m.form_text)
        assert "catalog" in f.disabled and "# host = \"\"" in m.form_text, m.form_text
        assert any("catalog: set host" in a for a in m.attention), m.attention
        assert m.vault["accounts"]["catalog"]["entra"]["refresh_token"] == rt, "the sign-in is kept"
        assert not any("catalog" in d for d in m.dropped), m.dropped
        assert m.hostless["catalog"]["kind"] == "ml-catalog" and m.hostless["catalog"]["destinations"] == []
        # several different hosts: none is picked (the user names it)
        m = migrate.map_v2(v2({"hosts": ["a.example.com", "b.example.com"]}), local_user="me")
        assert "catalog" in F.parse_text(m.form_text).disabled, m.form_text
        assert "0.6 listed 2: a.example.com, b.example.com" in m.form_text, m.form_text
        assert m.vault["accounts"]["catalog"]["bound"]["hosts"] == [] and "catalog" in m.hostless


def test_a_06_conversion_beside_the_users_own_form_keeps_its_sudo():
    """A 0.6 store converted while a gateway.toml already exists approves
    nothing of the user's form (approved {}), and is an existing install: its
    vault has no baseline mark, so the user's own `sudo = true` stays true
    (no OK waiting, the hook allowing it in auto mode), and a form that never
    said sudo keeps the old implicit true; never narrowed by a session start."""
    from gateway import hooks_bash, hooks_session
    for mine in ("[hosts.localhost]\nsudo = true\n", '[hosts.box]\naddress = "u@box.example.com"\n'):
        with H.gateway_env() as env:
            env.write_form(mine)
            _setup_v2(env, _users_data())
            r = migrate.run("test")
            assert r.ok and r.status == "migrated", r.message
            assert paths.form_path().read_text() == mine and paths.from_v2_form_path().exists()
            data = vault.load()
            assert data["approved"] == {} and vault.older_install(data), "an existing install"
            hooks_session.session_main({"session_id": "conv", "source": "startup"})
            eff = consent.compute(consent.load_form(), vault.load())
            assert eff.hosts["localhost"].sudo is True, mine
            assert "localhost" not in eff.pending_names(), [c.render() for c in eff.pending]
            out = hooks_bash.main({"tool_name": "Bash", "permission_mode": "auto",
                                   "tool_input": {"command": "sudo ls"}})
            assert out["hookSpecificOutput"]["permissionDecision"] == "allow", out
            ap = (vault.load().get("approved") or {}).get("rights")
            assert ap is None or ap["hosts"]["localhost"]["sudo"] is True, ap
    with H.gateway_env() as env:                   # no form of the user's: the converted one
        _setup_v2(env, _users_data())
        assert migrate.run("test").ok
        assert vault.older_install(vault.load()), "a converted 0.6 store is an existing install"


RT = "0.CCCC-catalog-refresh-token-xyz"


def _v2_catalog(acct):
    acct = {"kind": "mlcat", "login": "work@example.com", "tenant_id": "t.example.com",
            "client_id": "99999999-8888-7777-6666-555555555555",
            "secrets": {"refresh_token": RT}, **acct}
    return {"version": 2, "secrets": {}, "sudo": {}, "accounts": {"mlcat:work": acct}}


def test_a_hostless_06_catalog_keeps_its_sign_in_when_the_user_adds_the_host():
    """A 0.6 catalog account with no single host (none, or two different
    ones) is converted off, with a commented host line naming what 0.6 had;
    the conversion's approval records it as an approved account with no
    destination yet, so the user adding `host` later is one new destination
    of that account: `gate check` approves it and the sign-in (Entra refresh
    token) is still there, now bound to that host. Also when the conversion
    went to gateway.from-v2.toml (the user's form existed) and the entry is
    copied in with its host."""
    from gateway import hooks_session
    cases = (({"hosts": []}, "0.6 had none", "catalog.example.com"),
             ({"hosts": ["a.example.com", "B.example.com"]}, "0.6 listed 2: a.example.com, "
              "b.example.com", "b.example.com"))
    for acct, why, pick in cases:
        with H.gateway_env() as env:
            _setup_v2(env, _v2_catalog(acct))
            r = migrate.run("test")
            assert r.ok and r.status == "migrated", r.message
            text = paths.form_path().read_text()
            assert f'# host = ""' in text and why in text, text
            assert f"catalog: set host" in r.report and why in r.report, r.report
            f = env.form()
            assert "catalog" in f.disabled and "catalog" not in f.accounts
            data = vault.load()
            snap = data["approved"]["rights"]["accounts"]["catalog"]
            assert snap["kind"] == "ml-catalog" and snap["destinations"] == [], snap
            assert data["accounts"]["catalog"]["entra"]["refresh_token"] == RT
            hooks_session.session_main({"session_id": "hl1", "source": "startup"})
            assert vault.load()["approved"]["rights"]["accounts"]["catalog"] == snap, \
                "a session start keeps the approval of the entry that is off"
            env.write_form(text.replace('# host = ""', f'host = "{pick}"', 1))
            f = env.form()
            eff = consent.compute(f, vault.load())
            pend = [c.render() for c in eff.pending_for("catalog")]
            assert pend == [f"catalog: may now send to {pick}"], pend
            assert not consent.drops_credential(vault.load(), f.accounts["catalog"])
            consent.approve("catalog", eff.pending_for("catalog"), form=f)
            rec = vault.load()["accounts"]["catalog"]
            assert rec["entra"]["refresh_token"] == RT, "the sign-in is kept"
            assert rec["bound"]["hosts"] == [pick]
            assert consent.compute(env.form(), vault.load()).accounts["catalog"].may_send_to(pick)
    with H.gateway_env() as env:                    # converted beside the user's own form
        env.write_form("[hosts.localhost]\nsudo = true\n")
        _setup_v2(env, _v2_catalog({"hosts": []}))
        assert migrate.run("test").ok
        conv = paths.from_v2_form_path().read_text()
        block = conv[conv.index("[accounts.catalog]"):]
        assert vault.load()["imported"]["rights"]["accounts"]["catalog"]["destinations"] == []
        env.write_form("[hosts.localhost]\nsudo = true\n\n"
                       + block.replace('# host = ""', 'host = "catalog.example.com"', 1))
        f = env.form()
        assert not consent.drops_credential(vault.load(), f.accounts["catalog"])
        consent.approve("catalog", consent.compute(f, vault.load()).pending_for("catalog"), form=f)
        rec = vault.load()["accounts"]["catalog"]
        assert rec["entra"]["refresh_token"] == RT and rec["bound"]["hosts"] == ["catalog.example.com"]


def test_full_migration_of_users_vault():
    with H.gateway_env() as env:
        v2data = _setup_v2(env, _users_data())
        store_bytes = paths.v2_store_path().read_bytes()
        key_bytes = paths.v2_key_path().read_bytes()
        assert migrate.needed()
        r = migrate.run("test")
        assert r.ok and r.status == "migrated", r.message
        # v2 files moved out of the home folder, byte-identical backups kept
        assert not paths.v2_store_path().exists() and not paths.v2_key_path().exists()
        backups = {p.name: p.read_bytes() for p in paths.backups_dir().iterdir()}
        assert store_bytes in backups.values() and key_bytes in backups.values()
        assert any(n.startswith("store-v2-") and n.endswith(".age") for n in backups)
        assert "key-v2.txt" in backups
        assert paths.key_path().read_bytes() == key_bytes, "same identity"
        assert oct(paths.private_dir().stat().st_mode & 0o777) == "0o700"
        assert not migrate.needed()
        text = paths.form_path().read_text()
        assert text.startswith(migrate.HEADER)
        f = env.form()
        assert f.syntax_error is None and not f.errors, f.report_lines()
        data = vault.load()
        # --- names -------------------------------------------------------
        assert set(f.hosts) == {"localhost", "example", "builder", "db"}
        assert set(f.accounts) == {"github-personal", "github-work", "hf", "azure", "catalog",
                                   "pijul", "openai-api-key", "legacy-token"}
        al = data["aliases"]
        assert al["github:work"] == "github-work" and al["ssh:example"] == "example"
        assert al["registry:ghcr"] == "github-work" and al["OPENAI_API_KEY"] == "openai-api-key"
        assert al["hf:me"] == "hf" and al["mlcat:work"] == "catalog" and al["pijul:nest"] == "pijul"
        # --- hosts -------------------------------------------------------
        p = f.hosts["example"]
        assert p.address.render() == "octo@10.0.0.5" and p.address.when == "10.0.0.0/24"
        assert [a.render() for a in p.also] == ["octo@lab.example.com:2222"]
        assert p.ssh is True and p.sudo is True and p.note == "the lab box"
        assert f.hosts["builder"].via == "example" and f.hosts["builder"].address.render() == "ci@builder.internal"
        assert f.hosts["db"].address.render() == "admin@db.internal"
        vp = data["hosts"]["example"]
        assert len(vp["keys"]) == 2 and all(k["retired"] is None for k in vp["keys"])
        assert vp["keys"][0]["public"] == " ".join(v2data["accounts"]["ssh:example"]["public_key"].split()[:2]) or \
            vp["keys"][0]["public"] == v2data["accounts"]["ssh:example"]["public_key"]
        assert len(vp["host_keys"]) == 1 and vp["host_keys"][0].startswith("ssh-ed25519 ")
        assert vp["sudo"]["octo"]["password"] == "lab-sudo-pw-22"
        assert data["localhost"]["sudo"][paths.local_user()]["password"] == "mac-login-pw-1"
        assert data["hosts"]["db"]["sudo"]["admin"]["password"] == "db-admin-pw-44"
        assert "bob" not in json.dumps(data["localhost"])
        # --- accounts ----------------------------------------------------
        gw = f.accounts["github-work"]
        assert gw.login == "octo-work" and gw.owners == ["example-org"] and gw.email == "work@example.com"
        assert gw.commit_name == "Octo Cat" and gw.packages is True
        assert f.accounts["github-personal"].packages is False
        rw = data["accounts"]["github-work"]
        assert rw["token"]["value"] == "ghp_workTOKEN0123456789abcdefghij" and rw["token"]["source"] == "pasted"
        assert "ghcr.io" in rw["bound"]["hosts"] and rw["ssh_key"]["fingerprint"].startswith("SHA256:")
        assert data["accounts"]["github-personal"]["token"]["source"] == "gh-oauth"
        az = f.accounts["azure"]
        assert az.tenant == "example.com" and az.client_id == F.AZURE_CLI_CLIENT_ID
        assert az.databricks == ["adb-1234567890.7.azuredatabricks.net"] and az.storage == ["examplestore"]
        assert az.registries == ["examplecr.azurecr.io"] and az.sites == ["custom.example.com"]
        assert "client_id" not in text.split("[accounts.azure]")[1].split("[accounts.")[0]
        ea = data["accounts"]["azure"]["entra"]
        assert ea["refresh_token"] == "0.AAAA-azure-refresh-token-xyz"
        assert ea["tenant_id"] == "11111111-2222-3333-4444-555555555555"
        assert f.accounts["catalog"].kind == "ml-catalog"
        assert f.accounts["catalog"].host == "catalog.example.com"
        assert re.search(r'^host\s*= "catalog\.example\.com"$',
                         text.split("[accounts.catalog]")[1].split("[accounts.")[0], re.M), \
            "the catalog's address is written out (no default catalog)"
        cb = data["accounts"]["catalog"]["bound"]
        assert cb["hosts"] == ["catalog.example.com"] and cb["client_id"] == "99999999-8888-7777-6666-555555555555"
        pj = f.accounts["pijul"]
        assert pj.login == "octocat" and pj.remote_pijul == "/usr/local/bin/pijul" and pj.email == "j@example.com"
        assert data["accounts"]["pijul"]["host_keys"] == vault.NEST_HOST_KEYS
        ok = f.accounts["openai-api-key"]
        assert ok.sites == ["api.openai.com"] and ok.auth == "bearer" and ok.note == "OpenAI for experiments"
        assert "0.6 didn't record how this key was sent" in text
        lt = f.accounts["legacy-token"]
        assert lt.use is False and lt.sites == []
        assert data["accounts"]["legacy-token"]["token"]["value"] == "legacy-token-value-123456"
        assert "0.6 refused delete calls" in text
        # --- consent: the migrated rights are approved; nothing pending ----
        eff = consent.compute(f, data)
        assert not eff.pending, [c.render() for c in eff.pending]
        assert eff.accounts["github-work"].destinations == ["github.com", "api.github.com", "ghcr.io"]
        # --- every credential landed or is listed as dropped --------------
        landed = set(vault.all_values(data))
        for ref, value in vault_v2.credentials(v2data):
            assert value in landed or ref == "sudo bob@localhost", ref
        # --- report and record ---------------------------------------------
        rep = data["migrated"]["report"]
        assert data["migrated"]["store_sha256"] == hashlib.sha256(store_bytes).hexdigest()
        assert data["migrated"]["shown"] is False and r.report == rep
        for s in ("github:work -> github-work", "ssh:example -> example", "sudo on localhost",
                  "sudo on example", "ssh on example", "registry:ghcr -> github-work",
                  "sudo bob@localhost", "db: new host", "per-session sudo switches",
                  "open setup grants", "connection-reuse", "route names (home, away)",
                  "host-key policy accept-new"):
            assert s in rep, (s, rep)
        assert "octocat" in rep, "owner differences of the folded registry are reported"
        for secret in [v for _, v in vault_v2.credentials(v2data)]:
            assert secret not in rep and secret not in text
        assert [e["what"] for e in data["events"]] == ["migrate"]
        assert data["machine"]["id"] == "TEST-MACHINE-0001"
        assert data["form_last_good"] == text
        # v2's catch-all (no owners) next to github:work becomes the default
        assert f.accounts["github-personal"].default is True and not f.accounts["github-work"].default
        assert "Default accounts: github-personal" in rep
        # every migrated host gets sudo = true, and the report says so
        for h in ("builder", "db"):
            assert f"sudo on {h}" in rep, (h, rep)
        assert data["migrated"]["form"] == "gateway.toml"


def test_naming_rules_and_clashes():
    with H.gateway_env():
        d = {"version": 2, "secrets": {"EXAMPLE": {"value": "secret-value-1234", "hosts": ["a.example.com"]},
                                       "_weird": {"value": "secret-value-5678", "hosts": ["b.example.com"]}},
             "sudo": {}, "accounts": {
                 "ssh:example": {"kind": "ssh", "user": "j", "host": "p.example.com"},
                 "ssh:hf": {"kind": "ssh", "user": "j", "host": "hfbox.example.com"},
                 "ssh:gateway": {"kind": "ssh", "user": "j", "host": "gw.example.com"},
                 "hf:me": {"kind": "hf", "hosts": ["huggingface.co", "hf.co"], "secrets": {"token": "hf_token_123456789"}},
                 "github:a": {"kind": "github", "secrets": {"token": "ghp_aaaaaaaaaaaaaaaa"}},
                 "github:b.c": {"kind": "github", "secrets": {"token": "ghp_bbbbbbbbbbbbbbbb"}},
             }}
        m = migrate.map_v2(d, local_user="me")
        al = m.aliases
        assert al["ssh:hf"] == "hf" and al["hf:me"] == "hf-acct", al
        assert al["ssh:gateway"] == "gateway-host"
        assert al["EXAMPLE"] == "example-acct" and al["_weird"] == "weird"
        assert al["github:a"] == "github-a" and al["github:b.c"] == "github-b-c"
        f = F.parse_text(m.form_text)
        assert not f.errors, f.report_lines()


def test_all_refuse_prompts_turn_entries_off():
    with H.gateway_env():
        refuse = {k: "refuse" for k in ("read", "write", "delete", "exec")}
        d = {"version": 2, "secrets": {}, "sudo": {}, "accounts": {
            "github:x": {"kind": "github", "prompts": refuse, "secrets": {"token": "ghp_xxxxxxxxxxxxxxxx"}},
            "ssh:box": {"kind": "ssh", "user": "u", "host": "box.example.com", "prompts": refuse}}}
        m = migrate.map_v2(d, local_user="me")
        f = F.parse_text(m.form_text)
        assert f.accounts["github"].use is False and f.hosts["box"].ssh is False
        assert "ssh on box" not in m.now_true


def test_v1_vault_and_sudo_for_other_local_user_dropped():
    with H.gateway_env():
        d = {"version": 1, "secrets": {"K": {"value": "v" * 12, "hosts": ["k.example.com"]}},
             "sudo": {"me@localhost": {"user": "me", "host": "localhost", "password": "pw-me-1234"},
                      "other@127.0.0.1": {"user": "other", "host": "127.0.0.1", "password": "pw-other-1"}}}
        m = migrate.map_v2(d, local_user="me")
        assert m.vault["localhost"]["sudo"]["me"]["password"] == "pw-me-1234"
        assert any("other@127.0.0.1" in x for x in m.dropped)
        migrate.check(m, vault_v2.normalize(d))


def test_export_v1_mapper_keeps_source_localhost_apart():
    with H.gateway_env():
        obj = {"gateway_export": 1, "from_host": "macbook",
               "secrets": {}, "accounts": {},
               "sudo": {"octo@localhost": {"user": "octo", "host": "localhost", "password": "mac-pw-9999"}}}
        m = migrate.map_export_v1(obj, local_user="octo")
        assert m.vault["localhost"]["sudo"] == {}
        assert m.source_localhost["sudo"]["octo"]["password"] == "mac-pw-9999"
        migrate.check(m, vault_v2.normalize({"version": 2, "sudo": obj["sudo"]}))
        try:
            migrate.map_export_v1({"gateway_export": 2})
        except migrate.MigrationError:
            pass
        else:
            raise AssertionError("format 2 isn't a v1 export")


def test_check_catches_a_credential_that_did_not_land():
    with H.gateway_env():
        d = vault_v2.normalize({"version": 2, "secrets": {"K": {"value": "keep-me-12345", "hosts": ["k.example.com"]}}})
        m = migrate.map_v2(d, local_user="me")
        m.vault["accounts"]["k"]["token"]["value"] = "something else"
        try:
            migrate.check(m, d)
        except migrate.MigrationError as e:
            assert "keep-me" not in str(e)
        else:
            raise AssertionError("a lost credential must fail the check")


def test_form_present_writes_from_v2_and_keeps_form():
    with H.gateway_env() as env:
        mine = '[hosts.localhost]\nsudo = false\n'
        env.write_form(mine)
        _setup_v2(env, _users_data())
        r = migrate.run("test")
        assert r.ok and r.form_path == paths.from_v2_form_path()
        assert paths.form_path().read_text() == mine
        assert paths.from_v2_form_path().read_text().startswith(migrate.HEADER)


def _assert_untouched(store_before: bytes, key_before: bytes, form_existed: bool = False):
    assert paths.v2_store_path().read_bytes() == store_before, "store.age must never change"
    assert paths.v2_key_path().read_bytes() == key_before
    assert not paths.vault_path().exists(), "no vault.age after a failure"
    assert not paths.key_path().exists(), "no private/key.txt after a failure"
    assert paths.form_path().exists() == form_existed


def test_failure_paths_write_nothing_and_keep_store():
    small = {"version": 2, "secrets": {"K": {"value": "value-123456789", "hosts": ["k.example.com"]}},
             "sudo": {}, "accounts": {}}
    for stage in ("map", "check", "write", "form"):
        with H.gateway_env() as env:
            _setup_v2(env, json.loads(json.dumps(small)))
            sb, kb = paths.v2_store_path().read_bytes(), paths.v2_key_path().read_bytes()
            r = migrate.run("test", _fail_at=stage)
            assert not r.ok and r.status == "failed" and r.message.startswith("migration failed: ")
            assert r.message.endswith("; run gate migrate")
            _assert_untouched(sb, kb)
            assert migrate.needed() and migrate.last_failure()["reason"]
            # a later run succeeds and clears the failure
            r2 = migrate.run("test")
            assert r2.ok, r2.message
            assert migrate.last_failure() is None


def test_corrupt_store_and_missing_key_fail_cleanly():
    with H.gateway_env():
        paths.ensure_home()
        paths.v2_store_path().write_bytes(b"not age at all")
        paths.v2_key_path().write_text("AGE-SECRET-KEY-1NOTAREALKEY\n")
        sb, kb = paths.v2_store_path().read_bytes(), paths.v2_key_path().read_bytes()
        r = migrate.run("test")
        assert not r.ok and "decrypt" in r.message
        _assert_untouched(sb, kb)
        try:
            vault.save(vault.empty())
        except vault.VaultError:
            pass
        else:
            raise AssertionError("v3 must not create a vault while migration is pending")
    with H.gateway_env() as env:
        _setup_v2(env, {"version": 2, "secrets": {}, "sudo": {}, "accounts": {}})
        os.unlink(paths.v2_key_path())
        sb = paths.v2_store_path().read_bytes()
        r = migrate.run("test")
        assert not r.ok and "key" in r.message
        assert paths.v2_store_path().read_bytes() == sb and not paths.vault_path().exists()


def test_idempotency_and_leftover_store():
    with H.gateway_env() as env:
        _setup_v2(env, {"version": 2, "secrets": {"K": {"value": "value-abcdefgh", "hosts": ["k.example.com"]}},
                        "sudo": {}, "accounts": {}})
        store_bytes = paths.v2_store_path().read_bytes()
        key_bytes = paths.v2_key_path().read_bytes()
        assert migrate.run("test").status == "migrated"
        before = paths.vault_path().read_bytes()
        assert migrate.ensure("again") is None
        r = migrate.run("again")
        assert r.ok and r.status == "already"
        # the same v2 file reappears (rollback then upgrade): moved away, vault unchanged
        paths.v2_store_path().write_bytes(store_bytes)
        paths.v2_key_path().write_bytes(key_bytes)
        assert migrate.leftover_v2()
        r = migrate.run("again")
        assert r.status == "already" and not paths.v2_store_path().exists() and not paths.v2_key_path().exists()
        assert paths.vault_path().read_bytes() == before
        # a different v2 file (an old session wrote again): moved into the backups as a
        # stray copy, the v3 vault keeps every entry (never "move vault.age aside")
        paths.v2_store_path().write_bytes(b"different")
        r = migrate.run("again")
        assert r.ok and r.status == "stray", r.message
        assert "aside" not in r.message and "something unreadable" in r.message
        assert not paths.v2_store_path().exists()
        assert any(p.name.startswith("store-v2-stray-") for p in paths.backups_dir().iterdir())
        assert set(vault.load()["accounts"]) == {"k"}


def test_not_needed_without_v2():
    with H.gateway_env():
        r = migrate.run("x")
        assert r.ok and r.status == "not-needed"
        assert migrate.ensure("x") is None


def test_keys_with_crlf_and_odd_whitespace_still_land():
    with H.gateway_env():
        priv, pub = H.ssh_keypair("crlf")
        messy = "  " + priv.replace("\n", "\r\n") + "\r\n  "
        d = vault_v2.normalize({"version": 2, "accounts": {
            "ssh:box": {"kind": "ssh", "user": "u", "host": "box.example.com",
                        "secrets": {"ssh_key": messy}, "public_key": pub}}})
        m = migrate.map_v2(d, local_user="me")
        migrate.check(m, d)
        k = m.vault["hosts"]["box"]["keys"][0]
        assert "\r" not in k["private"] and k["fingerprint"] == vault.fingerprint_of(pub)



# ---------------------------------------------------------------------------
# robustness: odd v2 data never fails the migration permanently
# ---------------------------------------------------------------------------


def test_sudo_collision_keeps_the_newer_password_and_lists_the_other():
    with H.gateway_env():
        d = vault_v2.normalize({"version": 2, "accounts": {
            "ssh:lab": {"kind": "ssh", "user": "octo", "host": "lab.example.com",
                        "routes": [{"name": "home", "host": "10.0.0.5", "when": ""},
                                   {"name": "away", "host": "lab.example.com", "when": ""}]}},
            "sudo": {"octo@10.0.0.5": {"user": "octo", "host": "10.0.0.5", "password": "old-pw-1111",
                                         "updated": "2026-01-01T00:00:00+0000"},
                     "octo@lab.example.com": {"user": "octo", "host": "lab.example.com",
                                                "password": "new-pw-2222", "updated": "2026-09-01T00:00:00+0000"},
                     "me@localhost": {"user": "me", "host": "localhost", "password": "a-pw-3333"},
                     "me@127.0.0.1": {"user": "me", "host": "127.0.0.1", "password": "a-pw-3333"}}})
        m = migrate.map_v2(d, local_user="me")
        migrate.check(m, d)
        assert m.vault["hosts"]["lab"]["sudo"]["octo"]["password"] == "new-pw-2222"
        assert any("octo@10.0.0.5" in x and "newer one was kept" in x for x in m.dropped)
        assert "sudo octo@10.0.0.5" in m.dropped_refs
        assert m.vault["localhost"]["sudo"]["me"]["password"] == "a-pw-3333", "identical values both land"


def test_rotated_keys_without_public_keys_and_unknown_kinds():
    with H.gateway_env():
        k1, p1 = H.ssh_keypair("cur")
        k2, _ = H.ssh_keypair("old1")
        k3, _ = H.ssh_keypair("old2")
        d = vault_v2.normalize({"version": 2, "accounts": {
            "ssh:box": {"kind": "ssh", "user": "u", "host": "box.example.com",
                        "secrets": {"ssh_key": k1, "old_ssh_keys": [k2, k3]},
                        "public_key": p1, "old_public_keys": []},
            "gitlab:me": {"kind": "gitlab", "secrets": {"token": "glpat-abcdefghijklmnop"}},
            "weird": {"kind": "github"}}})
        m = migrate.map_v2(d, local_user="me")
        migrate.check(m, d)
        keys = m.vault["hosts"]["box"]["keys"]
        assert len(keys) == 3 and all(k["fingerprint"].startswith("SHA256:") for k in keys), keys
        assert any("gitlab:me" in x and "isn't known to v3" in x for x in m.dropped)
        assert "gitlab:me token" in m.dropped_refs


def test_control_characters_in_hosts_are_reported_not_fatal():
    with H.gateway_env():
        d = vault_v2.normalize({"version": 2, "accounts": {
            "ssh:box": {"kind": "ssh", "user": "u", "host": "box.example.com",
                        "routes": [{"name": "bad", "host": "evil\x07.example.com", "when": ""},
                                   {"name": "ok", "host": "box.example.com", "when": "10.0.0.0/8"},
                                   {"name": "badnet", "host": "x.example.com", "when": "not-a-net"}]},
            "ssh:nohost": {"kind": "ssh", "user": "u", "host": "bad\nhost"},
            "registry:r": {"kind": "registry", "host": "reg‮.example.com",
                           "secrets": {"token": "reg-token-123456789"}},
            "github:g": {"kind": "github", "host": "gh\x00.example.com",
                         "secrets": {"token": "ghp_ggggggggggggggggg"}}}})
        m = migrate.map_v2(d, local_user="me")
        f = migrate.check(m, d)
        assert f.hosts["box"].address.render() == "u@box.example.com" and f.hosts["box"].address.when == "10.0.0.0/8"
        assert "nohost" not in f.hosts and "# [hosts.nohost]" in m.form_text, "commented out, not fatal"
        assert "registry:r token" in m.dropped_refs and "github:g token" in m.dropped_refs
        assert "\x07" not in m.form_text and "‮" not in m.form_text and "\x00" not in m.form_text
        assert any("route bad" in x for x in m.attention) and any("route badnet" in x for x in m.attention)


def test_failure_reason_names_the_full_ref():
    d = vault_v2.normalize({"version": 2, "sudo": {"octo@lab.example.com": {
        "user": "octo", "host": "lab.example.com", "password": "pw-123456789"}}})
    with H.gateway_env():
        m = migrate.map_v2(d, local_user="me")
        m.vault["hosts"]["lab"]["sudo"]["octo"]["password"] = "other"
        try:
            migrate.check(m, d)
        except migrate.MigrationError as e:
            assert "sudo octo@lab.example.com didn't map" in str(e) and "pw-123" not in str(e)
        else:
            raise AssertionError("expected a failure")


def test_invalid_v2_user_is_reported():
    with H.gateway_env():
        d = vault_v2.normalize({"version": 2, "accounts": {
            "ssh:long": {"kind": "ssh", "user": "u" * 40, "host": "long.example.com"},
            "ssh:evil": {"kind": "ssh", "user": "a b", "host": "evil.example.com"}}})
        m = migrate.map_v2(d, local_user="me")
        f = migrate.check(m, d)
        assert "long" in f.disabled, "written as is, so the form reports it and keeps it off"
        assert any(x.startswith("long: the 0.6 user name isn't valid") for x in m.attention)
        assert "evil" not in f.hosts and "# [hosts.evil]" in m.form_text
        assert 'address = "evil.example.com"' not in m.form_text.replace("# address", "")


def test_catch_all_ambiguity_and_single_accounts():
    with H.gateway_env():
        d = vault_v2.normalize({"version": 2, "accounts": {
            "hf:a": {"kind": "hf", "owners": []}, "hf:b": {"kind": "hf"},
            "github:only": {"kind": "github"}}})
        m = migrate.map_v2(d, local_user="me")
        f = F.parse_text(m.form_text)
        assert not f.accounts["hf-a"].default and not f.accounts["hf-b"].default
        assert any("hf-a, hf-b all covered every owner" in x for x in m.attention)
        assert not f.accounts["github"].default, "a single account needs no default"


def test_alias_never_shadows_an_entry_and_identity_aliases_are_skipped():
    with H.gateway_env():
        d = vault_v2.normalize({"version": 2, "secrets": {
            "hf": {"value": "secret-value-1234", "hosts": ["api.x.com"]},
            "openai": {"value": "secret-value-5678", "hosts": ["api.openai.com"]}},
            "accounts": {"hf:me": {"kind": "hf", "secrets": {"token": "hf_abcdefghijklmnop"}}}})
        m = migrate.map_v2(d, local_user="me")
        assert "hf" not in m.aliases, m.aliases
        assert "openai" not in m.aliases, "identity aliases aren't stored"
        assert m.aliases["hf:me"] == "hf" and any("old name hf" in x for x in m.attention)


def test_v2_subdomain_semantics_and_wildcards():
    with H.gateway_env():
        d = vault_v2.normalize({"version": 2, "secrets": {
            "A": {"value": "secret-value-aaaa1", "hosts": ["openai.com", "api.anthropic.com", "*.example.org",
                                                         "10.1.2.3", "*"]}},
            "accounts": {"azure:w": {"kind": "azure", "tenant": "t.example.com",
                                     "hosts": ["*.azuredatabricks.net", "adb-1.2.azuredatabricks.net",
                                               "bad host"],
                                     "secrets": {"refresh_token": "rt-abcdefghijkl"}}}})
        m = migrate.map_v2(d, local_user="me")
        f = migrate.check(m, d)
        assert f.accounts["a"].sites == ["openai.com", ".openai.com", "api.anthropic.com", ".example.org",
                                         "10.1.2.3"], f.accounts["a"].sites
        assert any("api.anthropic.com" in x for x in m.lost)
        assert any("every site" in x for x in m.attention)
        az = f.accounts["azure"]
        assert az.databricks == ["adb-1.2.azuredatabricks.net"] and "azure" not in f.disabled
        assert sum("dropped the 0.6 host" in x for x in m.attention) == 2


def test_backups_are_reused_across_days():
    with H.gateway_env():
        paths.ensure_private()
        src = paths.home() / "store.age"
        src.write_bytes(b"same bytes")
        a = migrate._backup_copy(src, paths.backups_dir(), "store-v2-20261017.age", migrate.STORE_FAMILY)
        b = migrate._backup_copy(src, paths.backups_dir(), "store-v2-20261018.age", migrate.STORE_FAMILY)
        assert a == b and len(list(paths.backups_dir().iterdir())) == 1
        src.write_bytes(b"other bytes")
        c = migrate._backup_copy(src, paths.backups_dir(), "store-v2-20261018.age", migrate.STORE_FAMILY)
        assert c != a and len(list(paths.backups_dir().iterdir())) == 2


def test_existing_form_keeps_approvals_and_imports_converted_entries():
    from gateway import hooks_session
    with H.gateway_env() as env:
        mine = '[hosts.localhost]\nsudo = false\n'
        env.write_form(mine)
        _setup_v2(env, _users_data())
        r = migrate.run("test")
        assert r.ok and r.form_path == paths.from_v2_form_path() and "gateway.from-v2.toml" in r.report
        data = vault.load()
        assert data["form_last_good"] == mine, "the user's form is the fallback, not the from-v2 text"
        assert "example" in data["imported"]["rights"]["hosts"]
        before_bound = data["accounts"]["github-work"]["bound"]["hosts"]
        hooks_session.prepare([], write=True)                      # the first session
        data = vault.load()
        assert data["accounts"]["github-work"]["bound"]["hosts"] == before_bound, "bindings kept"
        assert data["approved"]["rights"]["hosts"]["localhost"]["sudo"] is False
        import contextlib as _cl
        import io as _io
        from gateway import gate
        buf = _io.StringIO()
        with _cl.redirect_stdout(buf):
            gate.main(["status"])
        assert "Converted from 0.6, not in the form yet:" in buf.getvalue() and "example" in buf.getvalue()
        # copy two converted entries in: no pop-up, keys and bindings intact
        conv = paths.from_v2_form_path().read_text()
        ps = conv.split("\n[hosts.example]")[1].split("\n[")[0]
        gw = conv.split("\n[accounts.github-work]")[1].split("\n[")[0]
        env.write_form(mine + "\n[hosts.example]" + ps + "\n[accounts.github-work]" + gw + "\n")
        form, eff, data = hooks_session.prepare([], write=True)
        assert not eff.pending, [c.render() for c in eff.pending]
        assert eff.hosts["example"].ssh is True and eff.hosts["localhost"].sudo is False
        assert "ghcr.io" in eff.accounts["github-work"].destinations
        assert "example" in data["approved"]["rights"]["hosts"], "moved into approved"


def test_existing_form_with_syntax_error_never_falls_back_to_from_v2():
    from gateway import hooks_session
    with H.gateway_env() as env:
        env.write_form('[hosts.localhost\nsudo = false\n')
        _setup_v2(env, _users_data())
        assert migrate.run("test").ok
        assert vault.load()["form_last_good"] is None
        form, eff, _ = hooks_session.prepare([], write=True)
        assert form.syntax_error is not None and not form.from_last_good
        assert set(eff.hosts) == {"localhost"} and not eff.accounts, "no v2 entries become active"


def test_form_missing_after_a_kill_is_restored():
    from gateway import hooks_session
    with H.gateway_env() as env:
        _setup_v2(env, {"version": 2, "secrets": {"K": {"value": "value-abcdefgh", "hosts": ["k.example.com"]}},
                        "sudo": {}, "accounts": {}})
        assert migrate.run("test").status == "migrated"
        text = paths.form_path().read_text()
        before = vault.load()["approved"]["rights"]
        paths.form_path().unlink()          # killed between vault.save and the rename
        msgs: list = []
        hooks_session.prepare(msgs, write=True)
        assert paths.form_path().read_text() == text and any("restored" in x for x in msgs)
        assert vault.load()["approved"]["rights"] == before


_RACE = """
import sys, json
sys.path.insert(0, {src!r})
from gateway import testing, migrate
with testing.override({root!r}, machine_id="TEST-MACHINE-0001"):
    r = migrate.ensure({who!r})
    print(json.dumps(None if r is None else [r.ok, r.status, r.message]))
"""


def test_two_processes_racing_to_migrate():
    # SessionStart and the MCP server (or a stand-in) start together: both pass
    # needed() and queue on the v2 lock. The loser must see "already", not fail.
    import subprocess
    import time as _t
    from gateway import migrate as mig
    for order in range(2):
        with H.gateway_env() as env:
            _setup_v2(env, {"version": 2, "secrets": {"K": {"value": "value-abcdefgh", "hosts": ["k.example.com"]}},
                            "sudo": {}, "accounts": {}})
            procs = []
            with mig._flock(paths.v2_lock_path()):
                for who in (("session", "mcp") if order == 0 else ("mcp", "session")):
                    code = _RACE.format(src=str(H.PLUGIN / "src"), root=str(env.root), who=who)
                    procs.append(subprocess.Popen([H.PY, "-I", "-S", *H.PYX, "-c", code],
                                                  stdout=subprocess.PIPE,
                                                  stderr=subprocess.PIPE, text=True,
                                                  env={"PATH": f"{H.ENV_BIN}:/usr/bin:/bin",
                                                       "HOME": str(env.user_home)}))
                _t.sleep(1.5)                       # both are now waiting on the lock
            outs = [p.communicate(timeout=60) for p in procs]
            results = [json.loads(o.strip().splitlines()[-1]) for o, _e in outs]
            assert results.count(None) == 1, results
            statuses = [r[1] for r in results if r is not None]
            assert statuses == ["migrated"], (results, [e for _o, e in outs])
            assert all("FileNotFoundError" not in o + e for o, e in outs)
            assert mig.last_failure() is None
            from gateway import audit
            assert not [x for x in audit.read(50) if x.get("outcome") == "failed"]


def test_a_host_known_only_from_a_sudo_entry_says_how_its_key_gets_there():
    """Review round 2: the comment promised "Claude will install its key on
    first use", but the ssh stand-in never installs a key (gate check does);
    the report called 0.6 "v2" and didn't say how to get a prompt back."""
    with H.gateway_env():
        d = {"version": 2, "secrets": {}, "accounts": {},
             "sudo": {"octo@db.example.com": {"password": "db-sudo-pw-123"}}}
        m = migrate.map_v2(d, local_user="me")
        assert "run gate check db while you're here to install Claude's key" in m.form_text, m.form_text
        assert "first use" not in m.form_text
        assert m.report.startswith("gateway: converted your 0.6 vault"), m.report
        assert "where you want the prompt back" in m.report and "v2" not in m.report, m.report


def test_a_mid_session_conversion_reports_at_the_next_prompt_once():
    """Review round 4: an upgrader's first v3 session runs without an env, so
    the conversion happens when a stand-in or gate first runs; hooks_prompt
    never showed an unshown report, so it came a session later. Now the next
    prompt shows it, once, and SessionStart doesn't repeat it."""
    from gateway import hooks_prompt, hooks_session, migrate
    import harness_ux as U
    with U.ux_env() as env:
        paths.ensure_home()
        H.write_v2_vault(paths.home(), {"version": 2, "secrets": {
            "OPENAI_API_KEY": {"value": "v" * 16, "hosts": ["api.openai.com"]}},
            "sudo": {}, "accounts": {}})
        r = migrate.ensure("shim")
        assert r is not None and r.ok and migrate.report_flag().exists()
        assert "0.6" in r.report and " v2 " not in r.report, r.report
        # prompt.sh starts Python for it (nothing else would)
        rr = U.run_sh(env, "prompt.sh", {"prompt": "hi", "session_id": "s9"},
                      extra_env={"PATH": "/usr/bin:/bin"})
        assert rr.returncode == 0
        out = hooks_prompt.main({"prompt": "hi", "session_id": "s9"})
        assert out.get("systemMessage", "").startswith(r.report.splitlines()[0]), out
        assert not migrate.report_flag().exists() and vault.load()["migrated"]["shown"] is True
        out = hooks_prompt.main({"prompt": "again", "session_id": "s9"})
        assert r.report.splitlines()[0] not in out.get("systemMessage", "")
        out = hooks_session.session_main({"session_id": "s10"})
        assert r.report.splitlines()[0] not in out.get("systemMessage", "")


def test_prompt_sh_starts_python_for_an_unshown_report():
    import harness_ux as U
    with U.ux_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n')
        marker = env.root / "launched"
        # a launch.sh stand-in next to a copy of prompt.sh records the call
        d = env.root / "rig"
        (d / "hooks").mkdir(parents=True)
        (d / "hooks" / "prompt.sh").write_text((U.SH_SCRIPTS / "prompt.sh").read_text())
        (d / "hooks" / "launch.sh").write_text(f"#!/bin/sh\n: > {str(marker)!r}\ncat > /dev/null\n")
        import subprocess
        e = env.subprocess_env()
        run = lambda: subprocess.run(["/bin/sh", str(d / "hooks" / "prompt.sh"), "--test"],
                                     input=json.dumps({"prompt": "hi"}), capture_output=True,
                                     text=True, env=e, timeout=30)
        run()
        assert not marker.exists()
        from gateway import migrate
        migrate.report_flag().write_text("")
        run()
        assert marker.exists()
