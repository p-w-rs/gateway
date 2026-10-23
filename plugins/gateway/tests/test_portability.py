"""Encrypted export and import (PLAN-v4 phase 7, transfer.py format 3): the
per-item selection (hosts, accounts, their secrets, settings, this machine's
sudo password), schema version and digest, a wrong passphrase asked again
and a changed file told apart, conflicts decided per item (keep, replace,
add under another name, keep or trust a pinned host key), a staged import
that restores the form and the vault when it fails (with a backup), local
or remote by stable machine identity (an exported localhost never becomes
this machine), imported credentials checked where practical and session
state marked as needing a fresh sign-in, and nothing of a live process
(pids, sockets, terminal or job ids, task references) in the file.
Canaries are generated here and never printed."""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Any

import harness as H
import harness_ux as U
from gateway import consent, paths, transfer, vault

PASS = "correct horse battery staple"
A_FORM = '''[policy]
exec = "ask"

[hosts.localhost]
sudo = true

[hosts.localhost.workspaces.notes]
root = "~/notes"

[hosts.lab]
address = "octo@10.0.0.5"

[hosts.lab.workspaces.app]
root = "/srv/app"

[accounts.gh]
kind = "github"
login = "octo"
'''


def _run(fn, *args):
    out, err = io.StringIO(), io.StringIO()
    so, se = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        rc = fn(*args)
    finally:
        sys.stdout, sys.stderr = so, se
    return rc, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def _xdir():
    d = Path(tempfile.mkdtemp(prefix="gwp-", dir=H.tmp_base()))
    try:
        yield d
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def _machine_a(env, tok: str) -> None:
    env.o.extra["etc_ssh"] = str(env.root / "no-etc-ssh")
    U.setup(env, A_FORM)
    k, pub = H.ssh_keypair("lab")
    with vault.edit() as d:
        d["machine"] = {"id": "MACHINE-A", "name": "macbook", "hostname": "macbook.local"}
        lab = vault.host_record(d, "lab")
        lab["keys"] = [vault.key_record(k, pub)]
        lab["host_keys"] = [vault.norm_host_key(H.fake_host_key("labkey"))]
        vault.set_sudo(d, "lab", "octo", "lab-sudo-" + secrets.token_hex(6))
        vault.set_sudo(d, "localhost", "alice", "mac-sudo-" + secrets.token_hex(6))
    U.set_token("gh", "github", tok)


def test_export_items_pick_entries_secrets_and_settings_one_by_one():
    tok = "ghp_" + secrets.token_hex(18)
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        _machine_a(env, tok)
        f, _e, data = transfer._load()
        items = {it.key: it for it in transfer.export_items(f, data)}
        assert set(items) == {"settings", "host:lab", "host-secrets:lab", "account:gh",
                              "account-secrets:gh", "localhost-sudo"}, items
        assert items["localhost-sudo"].checked is False and items["host-secrets:lab"].checked
        assert items["host-secrets:lab"].label == "lab: its SSH key and sudo password"
        # entries without their secrets
        c = transfer.export_content(f, data, {"host:lab", "account:gh"})
        assert c["gateway_export"] == 3 and c["schema"] == 3 and re.fullmatch(r"[0-9a-f]{64}", c["digest"])
        assert c["vault"]["hosts"]["lab"]["keys"] == [] and c["vault"]["hosts"]["lab"]["sudo"] == {}
        assert c["vault"]["hosts"]["lab"]["host_keys"], "the pin isn't a secret"
        assert "token" not in c["vault"]["accounts"]["gh"] and tok not in json.dumps(c)
        assert "[policy]" not in c["form"] and "[hosts.lab]" in c["form"]
        assert "[hosts.lab.workspaces.app]" in c["form"], "a workspace is its own table"
        # with secrets and the settings
        c = transfer.export_content(f, data, {"host:lab", "host-secrets:lab", "account:gh",
                                              "account-secrets:gh", "settings"})
        assert c["vault"]["accounts"]["gh"]["token"]["value"] == tok
        assert c["vault"]["hosts"]["lab"]["keys"] and c["vault"]["hosts"]["lab"]["sudo"]
        assert "[policy]" in c["form"] and c["vault"]["localhost"]["sudo"] == {}
        assert sorted(c["items"]) == sorted(["host:lab", "host-secrets:lab", "account:gh",
                                             "account-secrets:gh", "settings"])


def test_nothing_of_a_live_process_or_a_task_is_in_the_file():
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        _machine_a(env, "ghp_" + "x" * 36)
        paths.gated_dir().mkdir(parents=True, exist_ok=True)
        paths.gated_terminals().write_text(json.dumps({"version": 1, "panes": [
            {"id": "t_01M5E75E6T10DC7D1W1EEQ9B43", "kind": "terminal", "host": "lab",
             "session_pid": 4242, "task_ref": "task-secret-ref", "cwd": "/srv/app"}]}))
        with vault.edit() as d:
            d["accounts"]["gh"]["status"] = {"state": "connected", "checked_at": vault.now(), "meta": {}}
        f, _e, data = transfer._load()
        text = json.dumps(transfer.export_content(f, data, {"hosts", "accounts", "sudo", "settings"}))
        for frag in ("t_01M5E75E6T10DC7D1W1EEQ9B43", "task-secret-ref", "4242", "gated.sock",
                     "session_pid", '"status"', "task_ref", "pid"):
            assert frag not in text, frag


def _export(env, f: Path, picked: set[str]) -> None:
    form, _e, data = transfer._load()
    f.write_bytes(transfer.encrypt_passphrase(
        json.dumps(transfer.export_content(form, data, picked)).encode(), PASS))


def test_a_wrong_passphrase_is_asked_again_and_a_changed_file_is_told_apart():
    with _xdir() as x:
        f = x / "a.age"
        with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
            _machine_a(env, "ghp_" + secrets.token_hex(18))
            _export(env, f, {"account:gh", "account-secrets:gh"})
        ans = U.answers(("ok", "not the passphrase at all"), ("ok", PASS), ("ok",))
        with U.ux_env(ans, local_user="bob", machine_id="MACHINE-B") as env:
            U.setup(env, "")
            rc, out, err = _run(transfer.import_cmd, str(f))
            assert rc == 0, (out, err)
            c = env.dialog.calls()
            assert [x["kind"] for x in c] == ["secret", "secret", "confirm"], c
            assert "That didn't work: that passphrase doesn't open the file" in c[1]["message"]
            assert "gh" in env.form().accounts
        # a byte changed in the encrypted body: age's authentication fails
        blob = bytearray(f.read_bytes())
        blob[-20] ^= 0x01
        bad = x / "changed.age"
        bad.write_bytes(bytes(blob))
        with U.ux_env(U.answers(("ok", PASS)), local_user="bob", machine_id="MACHINE-B") as env:
            U.setup(env, "")
            rc, out, err = _run(transfer.import_cmd, str(bad))
            assert rc != 0 and "changed or damaged" in err, (out, err)
            assert "gh" not in env.form().accounts
        cut = x / "cut.age"
        cut.write_bytes(f.read_bytes()[:-40])
        with U.ux_env(U.answers(("ok", PASS)), local_user="bob", machine_id="MACHINE-B") as env:
            U.setup(env, "")
            rc, out, err = _run(transfer.import_cmd, str(cut))
            assert rc != 0 and "changed or damaged" in err, (out, err)


def test_a_changed_file_whose_requester_stopped_waiting_is_reported_to_the_retry():
    """The person typed the passphrase after the import's wait ran out: the
    job found the file changed. The retry Claude was told to make reports that
    refusal (no new passphrase dialog), and the dialog itself closed failed
    at once (no "try again": asking again can't help)."""
    with _xdir() as x:
        f = x / "a.age"
        with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
            _machine_a(env, "ghp_" + secrets.token_hex(18))
            _export(env, f, {"account:gh", "account-secrets:gh"})
        blob = bytearray(f.read_bytes())
        blob[-20] ^= 0x01
        bad = x / "changed.age"
        bad.write_bytes(bytes(blob))
        with U.ux_env(U.answers(("ok", PASS, 1.5), ("ok", PASS)), wait=0.5, local_user="bob",
                      machine_id="MACHINE-B") as env:
            U.setup(env, "")
            rc, out, err = _run(transfer.import_cmd, str(bad))
            assert rc == 75 and "still open" in err, (rc, out, err)
            U.wait_helpers()
            rc, out, err = _run(transfer.import_cmd, str(bad))
            assert rc == 1 and "changed or damaged" in err, (rc, out, err)
            assert "finished after the last try stopped waiting" in err, err
            assert [c["kind"] for c in env.dialog.calls()] == ["secret"], env.dialog.calls()
            assert "gh" not in env.form().accounts


def _incoming(env, picked: set[str]) -> transfer.Incoming:
    form, _e, data = transfer._load()
    return transfer.parse_incoming(json.loads(json.dumps(transfer.export_content(form, data, picked))))


def test_a_failed_import_restores_the_form_and_the_vault_and_keeps_a_backup():
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        _machine_a(env, "ghp_" + secrets.token_hex(18))
        inc = _incoming(env, {"host:lab", "host-secrets:lab", "account:gh", "account-secrets:gh"})
    with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
        U.setup(env, '[hosts.other]\naddress = "o@other.example.com"\n')
        before_form = paths.form_path().read_text()
        before_vault = paths.vault_path().read_bytes()
        form, _e, data = transfer._load()
        this, how = transfer.find_this_machine(inc, data)
        p = transfer.plan_import(inc, form, data, this, how)
        env.o.extra["import_fail_after_vault"] = True
        try:
            transfer.apply_import(inc, p, "the file", peer=False)
            raise AssertionError("the import didn't fail")
        except transfer.TransferError as e:
            assert "nothing was changed (restored from the backup" in str(e), e
        assert paths.form_path().read_text() == before_form
        assert paths.vault_path().read_bytes() == before_vault
        bks = list(paths.backups_dir().glob("import-*"))
        assert bks and all(paths.private_dir() in b.parents for b in bks)   # the file guard covers it
        assert len(bks) == 1 and (bks[0] / "gateway.toml").read_text() == before_form
        assert (bks[0] / "vault.age").read_bytes() == before_vault
        assert os.stat(bks[0]).st_mode & 0o777 == 0o700
        assert os.stat(bks[0] / "vault.age").st_mode & 0o777 == 0o600
        # without the failure: imported, and the backup named
        env.o.extra.pop("import_fail_after_vault")
        line = transfer.apply_import(inc, p, "the file", peer=False)
        assert "added" in line and "backup of the form and vault before it" in line, line
        f2 = env.form()
        assert "lab" in f2.hosts and "gh" in f2.accounts and "other" in f2.hosts
        assert f2.hosts["lab"].workspaces["app"].root == "/srv/app"


def test_conflicts_are_decided_per_item():
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        _machine_a(env, "ghp_" + secrets.token_hex(18))
        inc = _incoming(env, {"host:lab", "host-secrets:lab", "account:gh", "account-secrets:gh"})
    mine = ('[hosts.lab]\naddress = "octo@10.9.9.9"\n'
            '[accounts.gh]\nkind = "github"\nlogin = "octo"\n')
    with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
        U.setup(env, mine)
        U.set_token("gh", "github", "ghp_" + "m" * 36)
        form, _e, data = transfer._load()
        p = transfer.plan_import(inc, form, data, None, "")
        names = {c.name: c for c in p.conflicts}
        assert set(names) == {"lab", "gh"}, names
        assert any("address octo@10.0.0.5 (yours octo@10.9.9.9)" in d for d in names["lab"].diffs)
        assert [o for o, _l in names["lab"].options] == ["keep", "replace", "rename"]
        assert "lab" in p.keep and "gh" in p.keep and not p.replace
        # decided: lab replaced by the file's, gh added under another name
        p = transfer.plan_import(inc, form, data, None, "", {"lab": "replace", "gh": "rename"})
        assert p.replace == ["lab"] and p.renames == {"gh": "gh-2"}, (p.replace, p.renames)
        transfer.apply_import(inc, p, "the file", peer=False)
        f2 = env.form()
        assert f2.hosts["lab"].address.host == "10.0.0.5" and "gh-2" in f2.accounts and "gh" in f2.accounts
        d2 = vault.load()
        assert d2["accounts"]["gh"]["token"]["value"] == "ghp_" + "m" * 36, "mine kept"
        assert d2["accounts"]["gh-2"]["token"]["value"].startswith("ghp_") and \
            d2["accounts"]["gh-2"]["token"]["value"] != "ghp_" + "m" * 36
        assert vault.live_keys(d2["hosts"]["lab"]), "the file's key came with the replaced host"
        assert f2.text.count("[hosts.lab]") == 1


def test_a_changed_host_key_is_kept_unless_the_person_trusts_the_files():
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        _machine_a(env, "ghp_" + secrets.token_hex(18))
        inc = _incoming(env, {"host:lab"})
    with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
        U.setup(env, '[hosts.lab]\naddress = "octo@10.0.0.5"\n')
        mypin = vault.norm_host_key(H.fake_host_key("my-own-pin"))
        with vault.edit() as d:
            vault.host_record(d, "lab")["host_keys"] = [mypin]
        form, _e, data = transfer._load()
        p = transfer.plan_import(inc, form, data, None, "")
        assert [c.options[0][0] for c in p.conflicts] == ["keep-pin"] and p.hostkey_diff == ["lab"]
        p = transfer.plan_import(inc, form, data, None, "", {"lab": "keep-pin"})
        assert not p.take_pins and "lab" not in p.replace and "lab" in p.hostkey_diff
        p = transfer.plan_import(inc, form, data, None, "", {"lab": "take-pin"})
        transfer.apply_import(inc, p, "the file", peer=False)
        rec = vault.load()["hosts"]["lab"]
        assert rec["host_keys"] == [vault.norm_host_key(H.fake_host_key("labkey"))]
        assert rec["host_keys_previous"] == [mypin]


def test_an_exported_localhost_never_becomes_this_machine_and_identity_decides():
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        _machine_a(env, "ghp_" + secrets.token_hex(18))
        inc = _incoming(env, {"hosts", "accounts", "sudo", "settings"})
    # the same login name on the other machine: still not this machine's sudo password
    with U.ux_env(local_user="alice", machine_id="MACHINE-B") as env:
        env.o.extra["etc_ssh"] = str(env.root / "no-etc-ssh")
        U.setup(env, "")
        form, _e, data = transfer._load()
        this, how = transfer.find_this_machine(inc, data)
        assert (this, how) == (None, "")
        p = transfer.plan_import(inc, form, data, this, how)
        transfer.apply_import(inc, p, "the file", peer=False)
        f2 = env.form()
        assert f2.hosts["localhost"].workspaces == {}, "A's localhost workspace isn't B's"
        assert not vault.load()["localhost"]["sudo"], "A's sudo password isn't B's"
        src = next(n for n, h in f2.hosts.items() if n not in ("localhost", "lab"))
        assert f2.hosts[src].ssh is False, "the machine the file came from is a host, ssh off"
    # a host the other machine met, whose machine token is this machine's: it is localhost here
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        _machine_a(env, "ghp_" + secrets.token_hex(18))
        from gateway.daemon import machine_token
        with vault.edit() as d:
            d["hosts"]["lab"]["machine_id"] = machine_token("MACHINE-LAB")
        inc = _incoming(env, {"hosts", "accounts"})
    with U.ux_env(local_user="octo", machine_id="MACHINE-LAB") as env:
        env.o.extra["etc_ssh"] = str(env.root / "no-etc-ssh")
        U.setup(env, "")
        form, _e, data = transfer._load()
        this, how = transfer.find_this_machine(inc, data)
        assert (this, how) == ("lab", "machine identity"), (this, how)
        p = transfer.plan_import(inc, form, data, this, how)
        assert "lab" not in p.add_hosts and p.localhost_sudo is True
        transfer.apply_import(inc, p, "the file", peer=False)
        assert "lab" not in env.form().hosts
        assert vault.load()["localhost"]["sudo"]["octo"]["password"].startswith("lab-sudo-")


def test_imported_credentials_are_checked_and_session_state_needs_a_fresh_sign_in():
    import harness_accounts as HA
    from test_accounts_states import Api
    api = Api()
    srv = HA.EntraServer(refuse={"status": 400, "error": "invalid_grant", "codes": [50173],
                                 "description": "AADSTS50173: the grant was revoked"})
    try:
        form_a = ('[accounts.gh]\nkind = "github"\nlogin = "octo"\n'
                  '[accounts.az]\nkind = "azure"\ntenant = "contoso.example.com"\n')
        with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
            U.setup(env, form_a)
            U.set_token("gh", "github", "ghp_" + secrets.token_hex(18))
            with vault.edit() as d:
                vault.account_record(d, "az", "azure")["entra"] = {
                    "refresh_token": "RT-" + secrets.token_hex(10), "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
                    "tenant_id": "contoso.example.com", "refreshed": vault.now()}
            inc = _incoming(env, {"accounts"})
        with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
            U.setup(env, "")
            env.o.extra.update(verify_imports=True, github_api=api.url, entra_authority=srv.authority)
            api.answer = (200, {}, {"login": "octo"})
            form, _e, data = transfer._load()
            p = transfer.plan_import(inc, form, data, None, "")
            line = transfer.apply_import(inc, p, "the file", peer=False)
            assert "checked: " in line and "gh connected" in line and "az needs a fresh sign-in" in line, line
            st = vault.load()["accounts"]
            assert st["gh"]["status"]["state"] == "connected"
            assert st["az"]["status"]["state"] == "reauthentication_required"
            assert "fresh sign-in" in st["az"]["status"]["detail"]
    finally:
        api.close()
        srv.close()


def test_the_source_machines_unsaid_sudo_comes_over_as_ask_and_the_mark_stays_this_machines():
    """The machine a file came from becomes a host here (ssh off) with its
    sudo as the file's form says it for localhost, else "ask" (this
    computer's default; a remote host's own default, true, would widen it).
    An export of this version never carries its localhost table, so that is
    "ask" whatever the source's form says (a 0.6 export's explicit true:
    test_transfer_roundtrip::test_import_of_a_v2_export). The file carries no
    baseline mark (export_view), and the importing vault keeps its own: an
    older one stays older, a new one new."""
    for said in ("sudo = true\n", ""):
        with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
            _machine_a(env, "ghp_" + secrets.token_hex(18))
            env.write_form(A_FORM.replace("sudo = true\n", said, 1))
            form, _e, data = transfer._load()
            c = transfer.export_content(form, data, {"hosts", "accounts"})
            assert vault.BASELINE_KEY not in c["vault"], "the mark is this machine's"
            inc = transfer.parse_incoming(json.loads(json.dumps(c)))
        for older in (False, True):
            with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
                env.o.extra["etc_ssh"] = str(env.root / "no-etc-ssh")
                U.setup(env, "")
                if older:
                    with vault.edit() as d:
                        del d[vault.BASELINE_KEY]
                form, _e, data = transfer._load()
                this, how = transfer.find_this_machine(inc, data)
                p = transfer.plan_import(inc, form, data, this, how)
                transfer.apply_import(inc, p, "the file", peer=False)
                f2 = env.form()
                assert p.source_host and f2.hosts[p.source_host].sudo == "ask", (said, p.source_host)
                assert f2.hosts[p.source_host].ssh is False
                assert vault.older_install(vault.load()) is older
