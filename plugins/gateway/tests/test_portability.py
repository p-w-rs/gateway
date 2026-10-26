"""Encrypted export and import (PLAN-v4 phase 7, transfer.py format 3): the
per-item selection (hosts, accounts, their secrets, settings, this machine's
sudo password), schema version and digest, a wrong passphrase asked again
and a changed file told apart, conflicts decided per item (keep, replace,
add under another name, keep or trust a pinned host key), a staged import
that restores the form and the vault when it fails (with a backup), local
or remote by stable machine identity (an exported localhost never becomes
this machine), imported credentials checked where practical, a browser
sign-in (session state) never exported and its account named as needing a
new sign-in, and nothing of a live process
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
from gateway import consent, paths, popup, transfer, vault

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
        assert set(items) == {"settings", "localhost-settings", "host:lab", "host-secrets:lab",
                              "account:gh", "account-secrets:gh", "localhost-sudo"}, items
        assert items["localhost-sudo"].checked is False and items["host-secrets:lab"].checked
        assert items["localhost-settings"].checked is False, "this machine's settings: opt-in"
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
        assert "[hosts.localhost]" not in c["form"], "unticked: this machine's settings stay"
        # this machine's settings: [hosts.localhost]'s sudo, scripts, policy and workspaces
        c = transfer.export_content(f, data, {"localhost-settings"})
        assert "[hosts.localhost]" in c["form"] and "sudo = true" in c["form"]
        assert "[hosts.localhost.workspaces.notes]" in c["form"]
        assert c["vault"]["hosts"] == {} and c["vault"]["localhost"]["sudo"] == {}, \
            "its settings, not its sudo password (an item of its own)"


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


def test_imported_credentials_are_checked_and_a_browser_sign_in_needs_a_new_one():
    """The imported token is checked through its adapter; a browser
    sign-in's account comes without its refresh token (PLAN-0.11 §19.12) and
    the result names it with `gate login NAME` to run in a session."""
    from test_accounts_states import Api
    api = Api()
    try:
        form_a = ('[accounts.gh]\nkind = "github"\nlogin = "octo"\n'
                  '[accounts.az]\nkind = "azure"\ntenant = "contoso.example.com"\n'
                  'client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"\nsign_in = "browser"\n')
        rt = "RT-" + secrets.token_hex(10)
        with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
            U.setup(env, form_a)
            U.set_token("gh", "github", "ghp_" + secrets.token_hex(18))
            with vault.edit() as d:
                vault.account_record(d, "az", "azure")["entra"] = {
                    "refresh_token": rt, "client_id": "04b07795-8ddb-461a-bbee-02f9e1bf7b46",
                    "tenant_id": "contoso.example.com", "refreshed": vault.now(), "kind": "browser"}
            inc = _incoming(env, {"accounts"})
        with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
            U.setup(env, "")
            env.o.extra.update(verify_imports=True, github_api=api.url)
            api.answer = (200, {}, {"login": "octo"})
            form, _e, data = transfer._load()
            p = transfer.plan_import(inc, form, data, None, "")
            line = transfer.apply_import(inc, p, "the file", peer=False)
            assert "checked: gh connected" in line and "az" not in line.split("checked: ")[1].split(";")[0], line
            assert ("needs a new sign-in on this machine (a browser sign-in never travels in a file): "
                    "az; run gate login az in a Claude Code session") in line, line
            st = vault.load()["accounts"]
            assert st["gh"]["status"]["state"] == "connected"
            assert "entra" not in st["az"] and rt not in json.dumps(vault.load())
    finally:
        api.close()


def test_the_source_machines_unsaid_sudo_comes_over_as_ask():
    """The machine a file came from becomes a host here (ssh off) with its
    sudo as the file's form says it for localhost, else "ask" (this
    computer's default; a remote host's own default, true, would widen it).
    An export of this version never carries its localhost table, so that is
    "ask" whatever the source's form says. The file's vault part holds only
    the secrets and what they belong to (vault.EXPORT_KEYS), also from a
    vault an older gateway wrote fields into (an install mark, a 0.6
    conversion record), so it imports."""
    for said in ("sudo = true\n", ""):
        with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
            _machine_a(env, "ghp_" + secrets.token_hex(18))
            env.write_form(A_FORM.replace("sudo = true\n", said, 1))
            with vault.edit() as d:
                d["baseline"], d["migrated"] = 2, {"from": "v2", "at": "2026-10-01T00:00:00+0000"}
                d["imported"] = {"rights": {"hosts": {}, "accounts": {}}}
            form, _e, data = transfer._load()
            c = transfer.export_content(form, data, {"hosts", "accounts"})
            assert set(c["vault"]) <= set(vault.EXPORT_KEYS), sorted(c["vault"])
            inc = transfer.parse_incoming(json.loads(json.dumps(c)))
        with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
            env.o.extra["etc_ssh"] = str(env.root / "no-etc-ssh")
            U.setup(env, "")
            form, _e, data = transfer._load()
            this, how = transfer.find_this_machine(inc, data)
            p = transfer.plan_import(inc, form, data, this, how)
            transfer.apply_import(inc, p, "the file", peer=False)
            f2 = env.form()
            assert p.source_host and f2.hosts[p.source_host].sudo == "ask", (said, p.source_host)
            assert f2.hosts[p.source_host].ssh is False


# ---------------------------------------------------------------------------
# PLAN-0.11 §9.3 (WS-6): everything 0.11 configures travels; imported
# settings are approved in the one dialog; this machine's settings; the
# message points at a Claude Code session
# ---------------------------------------------------------------------------

AZ_CLIENT = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
AZ_SCOPE = "https://management.azure.com/.default offline_access"
FULL_FORM = f'''[policy]
exec = "ask"
write = {{ default = "ask", bypass = "deny" }}

[network]
commands = {{ default = "ask", auto = "cc" }}
extra = ["dig"]

[shell]
import_env = ["HF_HOME"]
import_path = ["~/tools-not-on-b/bin"]

[vault]
lock_after = "4h"

[hosts.localhost]
sudo = {{ default = "ask", auto = true }}

[hosts.localhost.policy]
elevation = "ask"

[hosts.localhost.workspaces.notes]
root = "~/notes"

[hosts.lab]
address = "octo@10.0.0.5"
ssh = {{ default = "ask", auto = true, plan = false }}
sudo = "ask"

[hosts.lab.policy]
write = {{ default = "ask", bypass = "deny" }}
forward_agent = true
env_import = true

[hosts.lab.shell]
import_env = ["CONDA_PREFIX"]

[hosts.lab.workspaces.app]
root = "/srv/app"
local = "~/src/app"

[accounts.gh]
kind = "github"
login = "octo"
use = {{ default = "ask", auto = true }}

[accounts.az]
kind = "azure"
tenant = "contoso.onmicrosoft.com"
client_id = "{AZ_CLIENT}"
sign_in = "browser"
'''
NONE_OF_THEM = "None of them (this machine isn't in the file)"


def _full_machine_a(env, tok: str, rt: str) -> None:
    env.o.extra["etc_ssh"] = str(env.root / "no-etc-ssh")
    U.setup(env, FULL_FORM)
    k, pub = H.ssh_keypair("lab")
    with vault.edit() as d:
        d["machine"] = {"id": "MACHINE-A", "name": "macbook", "hostname": "macbook.local"}
        lab = vault.host_record(d, "lab")
        lab["keys"] = [vault.key_record(k, pub)]
        lab["host_keys"] = [vault.norm_host_key(H.fake_host_key("labkey"))]
        vault.set_sudo(d, "lab", "octo", "lab-sudo-" + secrets.token_hex(6))
        vault.set_sudo(d, "localhost", "alice", "mac-sudo-" + secrets.token_hex(6))
        vault.account_record(d, "az", "azure")["entra"] = {
            "refresh_token": rt, "client_id": AZ_CLIENT, "tenant_id": "contoso.onmicrosoft.com",
            "refreshed": vault.now(), "kind": "browser", "scope": AZ_SCOPE}
    U.set_token("gh", "github", tok)


def test_a_round_trip_carries_everything_0_11_configures_and_every_change_goes_through_the_dialog():
    """The user's requirement (PLAN-0.11 §9.3): configuration and environment
    move between Claude Code sessions with the plugin. Everything 0.11
    configures (hosts with per-mode tables, accounts with a browser sign-in,
    workspaces, [policy], [network], [shell] imports, this machine's
    settings) goes out in one file and comes back through the gateway's own
    dialogs: the passphrase, which host is this machine, keep or replace this
    machine's settings, and one consent dialog listing every change the
    approval then makes (each entry's consent lines and the settings', a new
    host's grants, imports and workspaces too). After it nothing waits for a
    second OK, the credentials are where they belong (a browser sign-in's
    refresh token never travels: the account needs a new sign-in here, and
    the result says so, PLAN-0.11 §19.12), and a cancel there changes
    nothing."""
    tok, rt = "ghp_" + secrets.token_hex(18), "RT-" + secrets.token_hex(12)
    with _xdir() as x:
        f = x / "everything.age"
        with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
            _full_machine_a(env, tok, rt)
            form_a = env.form()
            assert not consent.compute(form_a, vault.load()).pending
            fa, _e, data_a = transfer._load()
            everything = {it.key for it in transfer.export_items(fa, data_a)}
            assert {"settings", "localhost-settings", "localhost-sudo", "host:lab",
                    "host-secrets:lab", "account:gh", "account-secrets:gh", "account:az"} <= everything, \
                everything
            # a browser sign-in's refresh token is never exported (PLAN-0.11 §19.12)
            assert "account-secrets:az" not in everything, everything
            assert rt not in json.dumps(transfer.export_content(fa, data_a, everything | {"account-secrets:az"}))
            _export(env, f, everything)
        # a cancel at the consent dialog: nothing changes
        ans = U.answers(("ok", PASS), ("ok", NONE_OF_THEM),
                        ("ok", "Use the file's settings for this machine"), ("cancelled",))
        with U.ux_env(ans, local_user="bob", machine_id="MACHINE-B") as env:
            env.o.extra["etc_ssh"] = str(env.root / "no-etc-ssh")
            U.setup(env, "")
            before_form = paths.form_path().read_text()
            rc, out, err = _run(transfer.import_cmd, str(f))
            assert rc == 1 and paths.form_path().read_text() == before_form, (out, err)
            assert not vault.load()["accounts"], "nothing of the file was stored"
        ans = U.answers(("ok", PASS), ("ok", NONE_OF_THEM),
                        ("ok", "Use the file's settings for this machine"), ("ok",))
        with U.ux_env(ans, local_user="bob", machine_id="MACHINE-B") as env:
            env.o.extra["etc_ssh"] = str(env.root / "no-etc-ssh")
            U.setup(env, "")
            before = vault.load()
            rc, out, err = _run(transfer.import_cmd, str(f))
            assert rc == 0, (out, err)
            calls = env.dialog.calls()
            assert [c["kind"] for c in calls] == ["secret", "choice", "choice", "confirm"], calls
            assert "settings for this machine" in calls[2]["message"], calls[2]["message"]
            shown = calls[-1]["message"]
            fb = env.form()
            # everything arrived, as written
            assert set(fb.hosts) >= {"localhost", "lab"} and set(fb.accounts) == {"gh", "az"}
            for n in ("lab",):
                for k in ("ssh", "sudo"):
                    assert fb.hosts[n].mode_value(k) == form_a.hosts[n].mode_value(k), (n, k)
                assert fb.hosts[n].policy_modes == form_a.hosts[n].policy_modes
                assert fb.hosts[n].shell.import_env == ["CONDA_PREFIX"]
                assert fb.hosts[n].workspaces["app"].root == "/srv/app"
            lh = fb.hosts["localhost"]
            assert lh.sudo_configured and lh.mode_value("sudo") == form_a.hosts["localhost"].mode_value("sudo")
            assert lh.policy_modes == form_a.hosts["localhost"].policy_modes
            assert lh.workspaces["notes"].root == "~/notes"
            assert fb.accounts["gh"].mode_value() == form_a.accounts["gh"].mode_value()
            az = fb.accounts["az"]
            assert (az.sign_in, az.client_id, az.tenant) == ("browser", AZ_CLIENT, "contoso.onmicrosoft.com")
            assert fb.network.commands == form_a.network.commands and fb.network.extra == ["dig"]
            assert fb.shell.import_env == ["HF_HOME"] and len(fb.shell.import_path) == 1
            assert fb.shell.import_path[0] == str(paths.user_home() / "tools-not-on-b" / "bin")
            assert fb.policy_modes == form_a.policy_modes and fb.vault.lock_after == form_a.vault.lock_after
            # every change the approval made was in the consent dialog, whole
            # (a long line goes on in a continuation line, never cut), and
            # nothing waits
            flat = " ".join(shown.split())
            for c in consent.compute(fb, before).pending:
                assert " ".join(c.what.split()) in flat, (c.entry, c.what, shown)
            assert all(len(ln) <= popup.CONFIRM_LINE for ln in shown.split("\n")), shown
            assert consent.compute(fb, vault.load()).pending == [], "nothing left for a second OK"
            for frag in ("forward_agent = true (a forwarding grant)",
                         "imports on the host: environment CONDA_PREFIX",
                         "workspace app: /srv/app (here ~/src/app)", "workspace notes: ~/notes",
                         "PATH import ~/tools-not-on-b/bin isn't a folder on this machine",
                         "this machine's settings ([hosts.localhost])"):
                assert frag in shown, (frag, shown)
            assert "waiting for the user's OK" not in out, out
            # the credentials: where they belong; the browser sign-in never
            # travels (PLAN-0.11 §19.12): its settings are approved with the
            # account, which needs a new sign-in here, and the result says so
            d = vault.load()
            assert d["accounts"]["gh"]["token"]["value"] == tok
            assert vault.live_keys(d["hosts"]["lab"]) and d["hosts"]["lab"]["sudo"]["octo"]
            assert "entra" not in d["accounts"]["az"], sorted(d["accounts"]["az"])
            from gateway import adapters, entra
            ap = entra.approved_account(d, "az")
            assert (ap.sign_in, ap.client_id, ap.tenant) == ("browser", AZ_CLIENT, "contoso.onmicrosoft.com")
            assert adapters.credential_of("azure", d["accounts"]["az"]) == ""
            assert "needs a new sign-in on this machine" in out and "run gate login az in a Claude " \
                "Code session" in out, out
            try:
                entra.access_token("az", "arm")
                raise AssertionError("a sign-in was used")
            except entra.EntraError as ee:
                assert "has no Entra credential" in str(ee) and "gate check az " in str(ee), ee
            assert not d["localhost"]["sudo"], "the other machine's sudo password isn't this one's"
            src = next(n for n in fb.hosts if n not in ("localhost", "lab"))
            assert fb.hosts[src].ssh is False and d["hosts"][src]["sudo"].get("alice"), src
            assert "gateway: imported" in out and tok not in out and rt not in out, out


def test_imported_settings_are_approved_in_the_import_dialog_not_left_waiting():
    """reqcheck 34a: plan_import never named the settings' changes, so their
    approval failed quietly and they waited for a second OK nobody was told
    about. Now the consent dialog lists them and the import approves them;
    a change made while the dialog was open waits, and the line says so."""
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        U.setup(env, '[network]\ncommands = "allow"\n\n[shell]\nimport_env = ["HF_HOME"]\n')
        inc = _incoming(env, {"settings"})
    with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
        U.setup(env, "")
        form, _e, data = transfer._load()
        p = transfer.plan_import(inc, form, data, None, "")
        assert p.settings_add == ["shell", "network"], p.settings_add
        assert any("HF_HOME" in c for c in p.changes["settings"]), p.changes
        assert any("network commands" in c for c in p.changes["settings"]), p.changes
        text = "\n".join(p.lines(inc, "f"))
        for c in p.changes["settings"]:
            assert c in text, (c, text)
        line = transfer.apply_import(inc, p, "the file", peer=False)
        assert "added the settings [shell], [network]" in line, line
        eff = consent.compute(env.form(), vault.load())
        assert eff.pending_for("settings") == [] and eff.shell.import_env == ["HF_HOME"]
    # the form changed while the dialog was open: nothing approved, and said so
    with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
        U.setup(env, "")
        form, _e, data = transfer._load()
        p = transfer.plan_import(inc, form, data, None, "")
        p.changes["settings"] = p.changes["settings"][:-1]
        line = transfer.apply_import(inc, p, "the file", peer=False)
        assert "waiting for the user's OK: the settings" in line and "gate check" in line, line
        assert consent.compute(env.form(), vault.load()).pending_for("settings")


def test_this_machines_settings_are_kept_or_replaced_and_a_dropped_sudo_is_a_widening():
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        U.setup(env, '[hosts.localhost]\nscripts = true\n\n[hosts.localhost.workspaces.notes]\n'
                     'root = "~/notes"\n')
        inc = _incoming(env, {"localhost-settings"})
    mine = '[hosts.localhost]\nsudo = "ask"\n'
    with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
        U.setup(env, mine)
        form, _e, data = transfer._load()
        p = transfer.plan_import(inc, form, data, None, "")
        c = [x for x in p.conflicts if x.name == "localhost"]
        assert c and [o for o, _l in c[0].options] == ["keep", "replace"], p.conflicts
        assert "this machine ([hosts.localhost])" in c[0].question()
        assert any(d.startswith("sudo not set (yours") for d in c[0].diffs), c[0].diffs
        assert "localhost" in p.keep and "localhost" not in p.replace
        # keep: this machine's own stays
        if p.tables:
            transfer.apply_import(inc, p, "the file", peer=False)
        assert env.form().hosts["localhost"].sudo_configured
        # replace: the file's, and the dropped sudo key is a widening the dialog shows
        form, _e, data = transfer._load()
        p = transfer.plan_import(inc, form, data, None, "", {"localhost": "replace"})
        assert p.replace == ["localhost"]
        assert any("sudo stops going through the gateway" in x for x in p.changes["localhost"]), p.changes
        text = "\n".join(p.lines(inc, "f"))
        assert "this machine: sudo stops going through the gateway" in text, text
        assert "this machine's settings ([hosts.localhost])" in text
        assert "workspace notes: ~/notes" in text
        transfer.apply_import(inc, p, "the file", peer=False)
        lh = env.form().hosts["localhost"]
        assert not lh.sudo_configured and lh.scripts and lh.workspaces["notes"].root == "~/notes"
        assert "address" not in (env.form().text.split("[hosts.localhost]")[1].split("[")[0])
        assert consent.compute(env.form(), vault.load()).pending_for("localhost") == []


def test_the_export_message_points_at_importing_in_a_claude_code_session():
    """reqcheck 34b: the message sent the user to run gate import in their own
    terminal, where no gateway dialog can open."""
    with _xdir() as x:
        dest = x / "out.age"
        ans = U.answers(("ok", "\n".join(["Host lab (octo@10.0.0.5)"])), ("ok", PASS), ("ok", PASS))
        with U.ux_env(ans, local_user="alice", machine_id="MACHINE-A") as env:
            _machine_a(env, "ghp_" + secrets.token_hex(18))
            rc, out, err = _run(transfer.export_cmd, str(dest))
            assert rc == 0, (out, err)
            assert "~/.config/gateway/gate import" not in out
            assert "in a Claude Code session there to run gate import FILE" in out, out
            assert "never in a plain terminal" in out


def _rows(lines: list[str], width: int = 72) -> int:
    """The rows lines take in a dialog pane `width` columns wide, wrapped at
    spaces, counted in characters (here, not with popup's helper): never
    more rows than the pane's own wrap."""
    import textwrap
    return sum(max(1, len(textwrap.wrap(ln, width, break_on_hyphens=False))) for ln in lines)


def test_an_import_too_long_for_one_dialog_is_shown_in_parts_and_never_cut_short():
    """Every change an approval makes must be on screen, whole (WS-6
    review): a line longer than popup.confirm keeps goes on in continuation
    lines, and a list taller than a gateway dialog shows (dialogs.MAX_LINES
    rows of a 72-column pane: mac-tui D) comes in parts, each naming itself
    in its heading and in the question beside its buttons, that the user
    goes through before anything is imported; a cancel at any part changes
    nothing. More parts than MAX_CONFIRM_PAGES are refused, never cut
    short."""
    from gateway.daemon.dialogs import MAX_LINES
    names = [f"lab-machine-{i:02d}" for i in range(45)]
    with _xdir() as x:
        f = x / "many.age"
        with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
            U.setup(env, "".join(f'[hosts.{n}]\naddress = "u@{n}.example.com"\n' for n in names))
            form, _e, data = transfer._load()
            f.write_bytes(transfer.encrypt_passphrase(json.dumps(transfer.export_content(
                form, data, {"hosts"})).encode(), PASS))
        with U.ux_env(U.answers(("ok", PASS), *[("ok",)] * transfer.MAX_CONFIRM_PAGES), local_user="bob",
                      machine_id="MACHINE-B") as env2:
            U.setup(env2, "")
            before = vault.load()
            rc, out, err = _run(transfer.import_cmd, str(f))
            assert rc == 0, (out, err)
            confirms = [c for c in env2.dialog.calls() if c["kind"] == "confirm"]
            n = len(confirms)
            assert n >= 2, confirms
            assert [c["title"].split(": ", 1)[-1] for c in confirms] == \
                [f"import, part {i} of {n}" for i in range(1, n + 1)], confirms
            pages = [c["message"].split("\n") for c in confirms]
            assert [pg[0] for pg in pages] == [f"Part {i} of {n}:" for i in range(1, n + 1)]
            for i, pg in enumerate(pages, 1):     # the question beside the buttons names the part
                assert pg[-1].startswith(f"Part {i} of {n}. "), pg[-1]
                assert ("Nothing is imported before the last part" in pg[-1]) is (i < n), pg[-1]
            assert pages[-1][-1].startswith(f"Part {n} of {n}. Import all of this (parts 1 to {n})?"), \
                pages[-1][-1]
            for pg in pages:                      # each part fits the pane's rows, not only gated's lines
                assert _rows(pg) <= MAX_LINES and all(len(ln) <= popup.CONFIRM_LINE for ln in pg), pg
            adds = next(i for i, ln in enumerate(pages[0]) if ln.startswith("Adds: "))
            assert pages[0][adds + 1].startswith(transfer._CONT), "a long line goes on, not cut"
            flat = " ".join(" ".join(pg) for pg in pages).split()
            flat = " ".join(flat)
            fb = env2.form()
            assert set(names) <= set(fb.hosts), fb.hosts.keys()
            for c in consent.compute(fb, before).pending:
                assert " ".join(c.what.split()) in flat, (c.entry, c.what)
            for nm in names:
                assert f"{nm}," in flat or f"{nm}." in flat, nm
                assert f"- {nm}: new host" in flat, nm
            assert consent.compute(fb, vault.load()).pending == [], "nothing waits"
        for cancel_at in (1, n):
            ans = [("ok", PASS)] + [("ok",)] * (cancel_at - 1) + [("cancelled",)]
            with U.ux_env(U.answers(*ans), local_user="bob", machine_id="MACHINE-B") as env2:
                U.setup(env2, "")
                rc, out, err = _run(transfer.import_cmd, str(f))
                assert rc == 1, (cancel_at, out, err)
                assert [c["kind"] for c in env2.dialog.calls()] == ["secret"] + ["confirm"] * cancel_at
                assert not env2.form().hosts.keys() - {"localhost"}, "a cancel changes nothing"
    # more parts than a confirm may have: refused
    lines = [f"  - lab-machine-{i:03d}: new host" for i in range(MAX_LINES * transfer.MAX_CONFIRM_PAGES)]
    try:
        transfer.confirm_pages(lines, popup.CONFIRM_LINE, MAX_LINES)
        raise AssertionError("an import longer than every part together was shown cut short")
    except transfer.TransferError as e:
        assert "nothing was imported" in str(e), e
    assert len(transfer.confirm_pages(lines[:30], popup.CONFIRM_LINE, MAX_LINES)) == 1


def test_an_import_confirm_is_sized_by_the_rows_the_pane_shows():
    """mac-tui D, for the import confirm: 30 lines of ~100 characters fit
    gated's 40 lines but take ~60 rows of a docked pane, which then opened
    scrolled past its heading. Now it comes in parts of at most 40 rows at
    72 columns, the question beside the buttons naming the part, and a long
    line stays with its continuation lines where they fit."""
    from gateway.daemon.dialogs import MAX_LINES
    lines = [f"  - box-{i:02d}: policy read = {{ default = \"ask\", auto = \"allow\" }} (the gateway "
             "decides it per mode)" for i in range(30)]
    assert all(90 <= len(ln) <= 110 for ln in lines), [len(ln) for ln in lines]
    assert len(lines) + 2 <= MAX_LINES < _rows(lines), "its lines fit one dialog, its rows don't"
    pages = transfer.confirm_pages(lines, popup.CONFIRM_LINE, MAX_LINES)
    n = len(pages)
    assert n >= 2, pages
    for i, pg in enumerate(pages, 1):
        assert _rows(pg) <= MAX_LINES, (i, _rows(pg))
        assert pg[0] == f"Part {i} of {n}:" and pg[-1].startswith(f"Part {i} of {n}. "), (pg[0], pg[-1])
    assert [ln for pg in pages for ln in pg[1:-2]] == lines, "every line, in order, none cut"
    long = "Adds: " + ", ".join(f"name-{i:03d}" for i in range(60)) + "."
    body = [f"line {i}" for i in range(30)] + [long]
    pages = transfer.confirm_pages(body, popup.CONFIRM_LINE, MAX_LINES)
    cont = transfer.fit_lines([long], popup.CONFIRM_LINE)
    assert len(cont) > 1 and any(pg[1:-2][-len(cont):] == cont for pg in pages), \
        "a long line and its continuation lines stay on one part"
    assert len(transfer.confirm_pages(["short"] * 10, popup.CONFIRM_LINE, MAX_LINES)) == 1


def test_an_import_confirm_sits_exactly_on_its_limits_and_counts_wide_characters():
    """WS-11b review: an off-by-one in each limit survived. Exactly 40 rows
    (38 lines, a blank line, the question) are one dialog and one more line
    comes in parts (gated keeps 40 lines: a 41st, the question, was
    dropped); the longest import shown takes exactly MAX_CONFIRM_PAGES
    parts, and one line more is refused. A Chinese, Japanese or Korean
    character takes two columns of the pane: lines that fit one dialog
    counted in characters come in parts."""
    from gateway.daemon.dialogs import MAX_LINES
    from test_ux_popup import _wide_rows

    def pages(k: int) -> list[list[str]] | None:
        try:
            return transfer.confirm_pages([f"  - lab-machine-{i:03d}: new host" for i in range(k)],
                                          popup.CONFIRM_LINE, MAX_LINES)
        except transfer.TransferError:
            return None
    one, more = pages(MAX_LINES - 2), pages(MAX_LINES - 1)
    assert one is not None and len(one) == 1 and len(one[0]) == MAX_LINES, one
    assert more is not None and len(more) == 2 and all(len(p) <= MAX_LINES for p in more), more
    lo, hi = 1, MAX_LINES * (transfer.MAX_CONFIRM_PAGES + 1)    # lo is shown, hi is refused
    assert pages(lo) is not None and pages(hi) is None
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if pages(mid) is None:
            hi = mid
        else:
            lo = mid
    assert len(pages(lo)) == transfer.MAX_CONFIRM_PAGES, lo
    wide = [f"  - PATH import /data/{i:02d}/" + "文" * 40 for i in range(30)]
    assert _rows(wide) + 2 <= MAX_LINES < _wide_rows(wide), "in characters one dialog, in columns not"
    got = transfer.confirm_pages(wide, popup.CONFIRM_LINE, MAX_LINES)
    assert len(got) >= 2 and all(_wide_rows(pg) <= MAX_LINES for pg in got), [len(pg) for pg in got]
    assert [ln for pg in got for ln in pg[1:-2]] == wide


def test_a_long_line_goes_on_in_continuation_lines():
    words = ", ".join(f"name-{i:03d}" for i in range(80))
    for ln in ("Adds: " + words + ".", "x" * 700, "word " * 150):
        out = transfer.fit_lines([ln], 300)
        assert len(out) > 1 and all(len(o) <= 300 for o in out), out
        assert out[1].startswith(transfer._CONT)
        assert "".join(o.removeprefix(transfer._CONT) for o in out).replace(" ", "").replace(",", "") \
            == ln.replace(" ", "").replace(",", ""), "nothing lost"
    assert transfer.fit_lines(["short", ""], 300) == ["short", ""]


def test_every_grant_a_new_host_brings_is_on_its_own_line_in_the_import_confirm():
    """§9.3 and invariant 3 (WS-6 review): a new host with long per-mode
    policy values had its forwarding grants cut off the confirm (its whole
    policy on one line, cut at popup.confirm's 300 characters) while the
    approval added them. Now each policy key, grant, import and workspace key
    is a line of its own that names its entry, and every line of the confirm
    survives popup.confirm whole."""
    from gateway.daemon.dialogs import MAX_LINES
    keys = ("read", "write", "exec", "network", "elevation", "credential")
    pm = '{ default = "ask", auto = "allow", bypass = "allow", plan = "deny" }'

    def host(n: str) -> str:
        return (f'[hosts.{n}]\naddress = "octo@{n}.example.com"\n\n[hosts.{n}.policy]\n'
                + "".join(f"{k} = {pm}\n" for k in keys) + "forward_agent = true\nforward_x11 = true\n"
                + f'\n[hosts.{n}.workspaces.app]\nroot = "/srv/app"\nread = {pm}\nwrite = {pm}\n'
                  f'exec = {pm}\n')
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        U.setup(env, host("lab") + "\n" + host("box"))
        assert not env.form().errors, env.form().errors
        inc = _incoming(env, {"host:lab", "host:box"})
    with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
        U.setup(env, "")
        form, _e, data = transfer._load()
        p = transfer.plan_import(inc, form, data, None, "")
        lines = p.lines(inc, "f")
        for n in ("lab", "box"):
            assert any(ln.startswith(f"  - {n}: new host") for ln in lines), lines
            for g in ("forward_agent", "forward_x11"):
                assert f"  - {n}: policy {g} = true (a forwarding grant)" in lines, (n, g, lines)
            for k in keys:
                assert any(ln.startswith(f"  - {n}: policy {k} = {{") and 'plan = "deny"' in ln
                           for ln in lines), (n, k, lines)
            assert f"  - {n}: workspace app: /srv/app" in lines, lines
            for k in ("read", "write", "exec"):
                assert any(ln.startswith(f"  - {n}: workspace app {k} = {{") for ln in lines), (n, k)
        pages = transfer.confirm_pages(lines, popup.CONFIRM_LINE, MAX_LINES)
        for pg in pages:
            assert len(pg) <= MAX_LINES, pg
            for ln in pg:
                assert popup.clean_line(ln, popup.CONFIRM_LINE) == ln, ln
        shown = "\n".join(popup.clean_line(ln, popup.CONFIRM_LINE) for pg in pages for ln in pg)
        assert shown.count("(a forwarding grant)") == 4, shown


def test_settings_already_waiting_here_are_never_shown_as_the_files():
    """WS-6 review: the settings are approved as a whole, so changes Claude
    had written into this machine's own settings (waiting for the user's OK)
    rode along under "Adds settings: [network]" as if they came from the
    file. Now they have their own heading and are approved only where the
    dialog lists them so; a peer import (no dialog on this machine) leaves
    the settings waiting and says so; settings of the file's that need no OK
    approve nothing."""
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        U.setup(env, '[network]\ncommands = "allow"\n')
        inc = _incoming(env, {"settings"})
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        U.setup(env, '[network]\nextra = ["dig"]\n')
        inc_narrow = _incoming(env, {"settings"})
    mine = '[shell]\nimport_env = ["HF_HOME"]\n'
    edited = '[shell]\nimport_env = ["HF_HOME", "AWS_PROFILE"]\nmanaged = "off"\n'
    for peer in (False, True):
        with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
            U.setup(env, mine)
            env.write_form(edited)                   # Claude's edit: it waits for the OK
            waiting = [c.what for c in consent.compute(env.form(), vault.load()).pending_for("settings")]
            assert len(waiting) == 2, waiting
            form, _e, data = transfer._load()
            p = transfer.plan_import(inc, form, data, None, "")
            assert sorted(p.waiting_settings) == sorted(waiting), p.waiting_settings
            assert p.changes["settings"] and not set(p.changes["settings"]) & set(waiting), p.changes
            text = p.lines(inc, "f")
            head = next(i for i, ln in enumerate(text)
                        if ln.startswith("Also approves changes already waiting for your OK"))
            adds = text.index("Adds settings: [network].")
            for c in p.changes["settings"]:
                assert adds < text.index(f"  - settings: {c}") < head, (c, text)
            for w in waiting:
                assert text.index(f"  - settings: {w}") > head, (w, text)
            line = transfer.apply_import(inc, p, "the file", peer=peer)
            eff = consent.compute(env.form(), vault.load())
            if peer:
                assert "the settings wait for the user's OK" in line and "gate check settings" in line, line
                assert set(waiting) <= {c.what for c in eff.pending_for("settings")}
                assert eff.shell.managed == "on", "nothing approved without a dialog here"
            else:
                assert eff.pending_for("settings") == [] and eff.shell.managed == "off", \
                    "approved as the dialog listed them"
    # the file's settings need no OK: the settings aren't approved, yours keep waiting
    with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
        U.setup(env, mine)
        env.write_form(edited)
        form, _e, data = transfer._load()
        p = transfer.plan_import(inc_narrow, form, data, None, "")
        assert p.settings_add == ["network"] and p.changes["settings"] == [], p.changes
        text = "\n".join(p.lines(inc_narrow, "f"))
        assert "Also approves" not in text and "AWS_PROFILE" not in text, text
        transfer.apply_import(inc_narrow, p, "the file", peer=False)
        eff = consent.compute(env.form(), vault.load())
        assert len(eff.pending_for("settings")) == 2 and eff.shell.managed == "on"
        assert env.form().network.extra == ["dig"]


def test_replaced_settings_are_approved_in_the_import_dialog_and_listed_once():
    """Settings the file replaces (the person picked the file's) are approved
    by the import's dialog like added ones (WS-6 review R10); when the file
    both adds and replaces settings tables, their lines are listed once."""
    for extra, adds in (("", []), ('\n[vault]\nlock_after = "4h"\n', ["vault"])):
        with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
            U.setup(env, '[network]\ncommands = "allow"\n' + extra)
            inc = _incoming(env, {"settings"})
        with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
            U.setup(env, '[network]\ncommands = "ask"\n')
            form, _e, data = transfer._load()
            p = transfer.plan_import(inc, form, data, None, "")
            assert any(c.section == "settings" for c in p.conflicts), "a conflict first"
            p = transfer.plan_import(inc, form, data, None, "", {"settings": "replace"})
            assert p.replace == ["settings"] and p.settings_add == adds, (p.replace, p.settings_add)
            assert any("network commands" in c for c in p.changes["settings"]), p.changes
            text = "\n".join(p.lines(inc, "f"))
            assert "Replaces yours with the file's: the settings." in text, text
            for c in p.changes["settings"]:
                assert text.count(f"  - settings: {c}") == 1, (c, text)
            line = transfer.apply_import(inc, p, "the file", peer=False)
            assert "replaced the settings" in line and "waiting" not in line, line
            eff = consent.compute(env.form(), vault.load())
            assert eff.pending_for("settings") == [], [c.what for c in eff.pending_for("settings")]
            assert env.form().network.commands == inc.form.network.commands
            assert env.form().vault.lock_after == inc.form.vault.lock_after


def test_a_path_import_is_named_missing_only_when_it_isnt_a_folder_here():
    """reqcheck 35 (WS-6 review R8): the import confirm names a [shell]
    PATH import that isn't a folder on this machine, and only that one."""
    with U.ux_env(local_user="bob", machine_id="MACHINE-B"):
        home = paths.user_home()
        (home / "tools" / "bin").mkdir(parents=True)
        raw = {"shell": {"import_path": ["~/tools/bin", "~/not-here/bin", str(home / "tools" / "bin")]}}
        got = transfer.settings_details(raw, ["shell"])
        assert got == ["PATH import ~/not-here/bin isn't a folder on this machine"], got
        assert transfer.settings_details(raw, ["network"]) == [], "only the [shell] the import brings"


def test_a_host_that_differs_only_per_mode_is_a_conflict():
    """PLAN-0.11 §2: two forms whose modeless words agree can still differ
    mode by mode (an explicit allow in default mode, a policy table): the
    person decides, the file's never slips in or out unnoticed."""
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        U.setup(env, '[hosts.lab]\naddress = "octo@10.0.0.5"\nssh = { default = true, auto = true }\n'
                     '[hosts.lab.policy]\nwrite = { default = "ask", bypass = "deny" }\n')
        inc = _incoming(env, {"host:lab"})
    with U.ux_env(local_user="bob", machine_id="MACHINE-B") as env:
        U.setup(env, '[hosts.lab]\naddress = "octo@10.0.0.5"\nssh = true\n'
                     '[hosts.lab.policy]\nwrite = "ask"\n')
        form, _e, data = transfer._load()
        p = transfer.plan_import(inc, form, data, None, "")
        c = [x for x in p.conflicts if x.name == "lab"]
        assert c, p.conflicts
        assert any(d.startswith("ssh ") for d in c[0].diffs) and "policy differs" in c[0].diffs, c[0].diffs


def test_the_grouped_selection_offers_the_settings_and_this_machines_settings():
    """With more items than a pane holds, the groups stand in for them; the
    settings and this machine's settings (unticked) are among them too."""
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        _machine_a(env, "ghp_" + secrets.token_hex(18))
        form, _e, data = transfer._load()
        opts, key, checked = transfer._groups_options(form, data)
        assert key[transfer.SETTINGS_LABEL] == "settings" and transfer.SETTINGS_LABEL in checked
        assert key[transfer.LOCALHOST_LABEL] == "localhost-settings"
        assert transfer.LOCALHOST_LABEL not in checked, "this machine's settings: opt-in"
        keys = transfer._picked_keys(form, data, {key[o] for o in opts})
        assert {"settings", "localhost-settings", "localhost-sudo", "host:lab"} <= keys, keys


def test_the_docs_say_plainly_how_to_export_import_and_copy():
    """The README's everyday use says that the configuration, its secrets and
    the settings can be exported, imported and copied to another machine,
    and links CONFIG.md's section, which names the three commands and every
    settings table the export offers (transfer.SETTINGS_TABLES)."""
    readme, config = H.REPO / "README.md", H.REPO / "docs" / "CONFIG.md"
    if not readme.exists():                    # a scratch copy of the plugin alone (mutations)
        print("    note: no repo docs next to this plugin folder; skipped")
        return
    everyday = readme.read_text().split("\n## Everyday use\n", 1)[1].split("\n## ", 1)[0]
    for said in ("gate export", '"Import FILE"', "gate copy-to", "(docs/CONFIG.md#export-and-import)"):
        assert said in everyday, said
    section = config.read_text().split("\n## Export and import\n", 1)[1].split("\n## ", 1)[0]
    for said in ("gate export", "gate import FILE", "gate copy-to HOST",
                 *(f"`[{t}]`" for t in transfer.SETTINGS_TABLES)):
        assert said in section, said
