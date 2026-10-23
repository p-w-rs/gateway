"""gate_setup: gate check end to end against mocks of ssh/sudo/logins/entra,
idempotency, cancel handling, approve-exactly-shown, accounts (token paste
with login check, browser sign-in, Entra), forget/rotate, and gate secret
(TTY-only; refuses with CLAUDECODE=1 or without /dev/tty; terminal flow)."""
from __future__ import annotations

import contextlib
import io
import json
import os
import select
import stat
import subprocess
import sys
import threading
import time

import harness as H
import harness_ux as U
from gateway import consent, gate_setup, hooks_prompt, hooks_session, paths, popup, vault
from gateway import form as formmod

HOSTFORM = '[hosts.box]\naddress = "octo@box.example.com"\n'
HKEY = H.fake_host_key("boxkey")
GOOD_SUDO = "pw-right-123"


@contextlib.contextmanager
def ssh_mocks(env, *, installed_after: str | None = "my-login", nopasswd: bool = False,
              keys: list[str] | None = None):
    from gateway import ssh
    log = env.root / "ssh-mock.jsonl"
    state = {"installed": False}

    def rec(*a):
        with open(log, "a") as f:
            f.write(json.dumps(a) + "\n")

    def keyscan(name):
        rec("keyscan", name)
        return list(keys if keys is not None else [HKEY])

    def test_login(name):
        rec("test_login", name)
        return (True, "ok") if state["installed"] else (False, "Permission denied")

    def install(name, method, password=None):
        rec("install", name, method)
        if installed_after == method:
            state["installed"] = True
        return f"gateway: installed via {method}"

    def verify(name, user, pw):
        rec("verify", name, user)
        return (pw == GOOD_SUDO, "sudo said no")

    def probe(name, user):
        return nopasswd
    with U.patch(ssh, "keyscan_host", keyscan), U.patch(ssh, "test_login", test_login), \
            U.patch(ssh, "install_key", install), U.patch(ssh, "verify_remote_sudo", verify), \
            U.patch(ssh, "probe_remote_nopasswd", probe):
        yield lambda: [json.loads(l) for l in log.read_text().splitlines()] if log.exists() else []


def _run(fn, *args):
    out, err = io.StringIO(), io.StringIO()
    so, se = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        rc = fn(*args)
    finally:
        sys.stdout, sys.stderr = so, se
    return rc, out.getvalue(), err.getvalue()


def test_check_new_host_end_to_end_then_idempotent():
    ans = U.answers(("ok",), ("ok", "Use my own SSH login once (recommended)"),
                    ("ok", gate_setup.SUDO_STORE), ("ok", GOOD_SUDO))
    with U.ux_env(ans) as env, ssh_mocks(env) as calls:
        U.setup(env, HOSTFORM, approve=False)
        rc, out, err = _run(gate_setup.check, "box")
        assert rc == 0, (out, err)
        # review round 4: what the setup did follows the status, without a
        # second "gateway: " prefix inside its parentheses
        assert out.strip() == ("gateway: box ready: ssh ✓ (octo@box.example.com, key installed), "
                               "sudo ✓ (password saved); installed via my-login"), out
        assert out.count("gateway: ") == 1
        d = env.dialog.calls()
        assert [c["kind"] for c in d] == ["confirm", "choice", "choice", "secret"], d
        assert d[0]["default"] == "Decline" and "new host" in d[0]["message"] and "SHA256:" in d[0]["message"]
        # the sudo choice: store the password or be asked each time (never a sudoers rule)
        assert d[2]["default"].splitlines() == [gate_setup.SUDO_STORE, gate_setup.SUDO_ASK], d[2]
        assert "octo@box.example.com" in d[3]["message"] and popup.NEVER_SEES in d[3]["message"]
        data = vault.load()
        assert "box" in data["approved"]["rights"]["hosts"]
        h = data["hosts"]["box"]
        assert h["host_keys"] == [vault.norm_host_key(HKEY)] and h.get("pinned_at")
        assert len(vault.live_keys(h)) == 1 and h.get("installed")
        assert h["sudo"]["octo"]["password"] == GOOD_SUDO
        assert [c[0] for c in calls()] == ["keyscan", "test_login", "install", "test_login", "verify"]
        assert ["install", "box", "my-login"] in calls()
        # idempotent: nothing to do, no pop-up
        rc, out, err = _run(gate_setup.check, "box")
        assert rc == 0 and out.startswith("gateway: box ready") and len(env.dialog.calls()) == 4, (out, err)
        assert GOOD_SUDO not in out + err


def test_check_cancel_is_not_reopened_until_the_user_writes():
    with U.ux_env(U.answers(("cancelled",), ("cancelled",))) as env, ssh_mocks(env):
        U.setup(env, HOSTFORM, approve=False)
        rc, out, err = _run(gate_setup.check, "box")
        assert rc == 1 and "cancelled" in err, err
        assert "box" not in (vault.load()["approved"].get("rights") or {}).get("hosts", {})
        rc, out, err = _run(gate_setup.check, "box")
        assert rc == 1 and "ask them before running gate check box again" in err
        assert len(env.dialog.calls()) == 1
        hooks_prompt.main({"prompt": "yes, add it", "session_id": "sess-ux"})
        rc, out, err = _run(gate_setup.check, "box")
        assert len(env.dialog.calls()) == 2, "after the user wrote again, the pop-up opens again"


def test_check_approves_exactly_what_was_shown():
    with U.ux_env(U.answers(("ok", None, 1.5), ("cancelled",))) as env, ssh_mocks(env):
        U.setup(env, HOSTFORM, approve=False)

        def widen():
            time.sleep(0.6)
            env.write_form(HOSTFORM + 'also = ["octo@203.0.113.9"]\n')
        t = threading.Thread(target=widen)
        t.start()
        rc, out, err = _run(gate_setup.check, "box")
        t.join()
        assert rc == 1, (out, err)
        rights = (vault.load()["approved"].get("rights") or {}).get("hosts", {})
        assert "box" not in rights, "nothing approved: the form changed while the pop-up was open"
        d = env.dialog.calls()
        assert len(d) == 2 and "203.0.113.9" not in d[0]["message"] and "203.0.113.9" in d[1]["message"]


def test_check_install_choice_show_and_password_paths():
    ans = U.answers(("ok",), ("ok", "Show me the public key (I'll add it myself)"), ("ok", "ssh-ed25519 AAAA"))
    with U.ux_env(ans) as env, ssh_mocks(env, installed_after="show", nopasswd=True) as calls:
        U.setup(env, HOSTFORM, approve=False)
        rc, out, err = _run(gate_setup.check, "box")
        assert rc == 0, (out, err)
        d = env.dialog.calls()
        assert d[2]["kind"] == "text" and "authorized_keys" in d[2]["message"]
        pub = vault.live_keys(vault.load()["hosts"]["box"])[0]["public"]
        assert d[2]["default"] == pub, "the public key is shown, copyable"
        assert not any(c[0] == "verify" for c in calls()), "NOPASSWD: no sudo password asked"
    with U.ux_env(U.answers(("ok",), ("ok", "Type the account's password once"))) as env, \
            ssh_mocks(env, installed_after=None):
        U.setup(env, HOSTFORM, approve=False)
        rc, out, err = _run(gate_setup.check, "box")
        assert rc == 1 and "still refuses Claude's key" in err, err
        assert "box" in vault.load()["approved"]["rights"]["hosts"], "the consent itself stands"


def test_check_unreachable_host_and_no_screen():
    # Review round 4: no host key could be read for a host that needs its first
    # pin: stop before any pop-up (the consent would approve a host nobody
    # reached, and the pin would be asked again later)
    with U.ux_env(U.answers(("ok",))) as env, ssh_mocks(env, keys=[]):
        U.setup(env, HOSTFORM, approve=False)
        rc, out, err = _run(gate_setup.check, "box")
        assert rc == 1 and "couldn't read box's host key" in err and "reachable" in err, err
        assert "nothing was asked" in err and env.dialog.calls() == [], err
        assert "box" not in (vault.load().get("approved") or {}).get("rights", {}).get("hosts", {})
    # a new address of a pinned host likewise; a rights-only change of a pinned
    # host that is off right now still goes ahead
    with U.ux_env(U.answers(("ok",))) as env, ssh_mocks(env, keys=[]):
        U.setup(env, HOSTFORM)
        with vault.edit() as d:
            vault.host_record(d, "box")["host_keys"] = [vault.norm_host_key(HKEY)]
        env.write_form(HOSTFORM + 'also = ["octo@10.0.0.7"]\n')
        rc, out, err = _run(gate_setup.check, "box")
        assert rc == 1 and "nothing was asked" in err and env.dialog.calls() == [], err
        env.write_form(HOSTFORM.replace("box.example.com\"", "box.example.com\"\nsudo = false"))
        consent.approve_all(env.form())
        env.write_form(HOSTFORM)
        rc, out, err = _run(gate_setup.check, "box")
        assert "nothing was asked" not in err and env.dialog.calls(), (rc, err)
    with U.ux_env(dialog="none") as env, ssh_mocks(env):
        U.setup(env, HOSTFORM, approve=False)
        rc, out, err = _run(gate_setup.check, "box")
        assert rc == 1 and "nothing was asked" in err and "terminal or the desktop app" in err, err
        assert "gate secret" not in err and popup.pending("box") == []


def test_check_localhost_sudo_with_verification():
    from gateway import sudo
    with U.ux_env(U.answers(("ok", gate_setup.SUDO_STORE), ("ok", "wrong-one"),
                            ("ok", "mac-pw-correct"))) as env:
        U.setup(env, "[hosts.localhost]\nsudo = true\n")
        with U.patch(sudo, "probe_nopasswd", lambda user=None: False), \
                U.patch(sudo, "verify_local", lambda pw: (pw == "mac-pw-correct", "Sorry, try again")):
            rc, out, err = _run(gate_setup.check, "localhost")
        assert rc == 0 and out.startswith("gateway: localhost ready: sudo ✓"), (out, err)
        d = env.dialog.calls()
        assert len(d) == 3 and d[0]["kind"] == "choice" and "Try again (2 of 3)" in d[2]["message"]
        assert "Remember it box keeps it" in d[0]["message"] and "sudoers" not in d[0]["message"]
        assert vault.load()["localhost"]["sudo"][paths.local_user()]["password"] == "mac-pw-correct"
    with U.ux_env() as env:
        U.setup(env, "[hosts.localhost]\nsudo = true\n")
        with U.patch(sudo, "probe_nopasswd", lambda user=None: True):
            rc, out, err = _run(gate_setup.check, "localhost")
        assert rc == 0 and env.dialog.calls() == [], "NOPASSWD: nothing asked"


def test_check_localhost_on_a_new_install_asks_nothing_to_approve_and_keeps_ask():
    """A new install's starter (sudo = "ask"): gate check localhost has
    nothing to approve (no consent dialog), sets up the password choice as
    for any sudo right, and reports sudo as "ask"; the form is untouched."""
    from gateway import hooks_session, migrate, sudo
    with U.ux_env(U.answers(("ok", gate_setup.SUDO_ASK))) as env:
        hooks_session.session_main({"session_id": "new", "source": "startup"})
        assert paths.form_path().read_text() == migrate.STARTER
        with U.patch(sudo, "probe_nopasswd", lambda user=None: False):
            rc, out, err = _run(gate_setup.check, "localhost")
        assert rc == 0 and out.startswith("gateway: localhost ready: sudo ask"), (out, err)
        d = env.dialog.calls()
        assert len(d) == 1 and d[0]["kind"] == "choice", d
        assert not any("Approve" in c.get("title", "") or "->" in c["message"] for c in d), d
        assert paths.form_path().read_text() == migrate.STARTER
        eff = consent.compute(env.form(), vault.load() if vault.exists() else None)
        assert eff.hosts["localhost"].sudo == "ask" and not eff.pending


def test_check_localhost_approves_an_old_starters_sudo_true_without_a_vault():
    """An install from before the "ask" default with no vault (nothing ever
    stored): its form's sudo = true waits for the OK; one gate check
    localhost (the consent dialog) makes it true, with no form change."""
    from gateway import migrate, sudo
    old = migrate.HEADER + "\n[hosts.localhost]\nsudo = true\n"
    with U.ux_env(U.answers(("ok",))) as env:
        env.write_form(old)
        assert not vault.exists()
        eff = consent.compute(env.form(), None)
        assert eff.hosts["localhost"].sudo == "ask" and eff.pending_names() == ["localhost"]
        with U.patch(sudo, "probe_nopasswd", lambda user=None: True):
            rc, out, err = _run(gate_setup.check, "localhost")
        assert rc == 0 and out.startswith("gateway: localhost ready: sudo ✓"), (out, err)
        d = env.dialog.calls()
        assert len(d) == 1 and 'sudo "ask" -> true' in d[0]["message"], d
        eff = consent.compute(env.form(), vault.load())
        assert eff.hosts["localhost"].sudo is True and not eff.pending
        assert paths.form_path().read_text() == old


def _github_api():
    def user(h, u, b):
        auth = h.headers.get("Authorization", "")
        logins = {"Bearer good-token-123456789": "octocat", "Bearer other-person-token-1": "someone-else",
                  "Bearer gho_browserTOKEN1234567890": "octocat"}
        if auth in logins:
            return 200, {"Content-Type": "application/json"}, json.dumps({"login": logins[auth]})
        return 401, {}, "{}"

    def org(h, u, b):
        return 403, {"X-GitHub-SSO": "required; url=https://github.com/orgs/acme/sso"}, "{}"
    return {"/user": user, "/orgs/acme": org}


def test_github_token_paste_with_login_check():
    form = '[accounts.gh]\nkind = "github"\nlogin = "octocat"\nowners = ["acme"]\n'
    ans = U.answers(("ok",), ("ok", "other-person-token-1"), ("ok", "good-token-123456789"))
    with U.ux_env(ans) as env, U.servers(_github_api()) as (api,):
        env.o.extra["github_api"] = api.url("").rstrip("/")
        U.setup(env, form, approve=False)
        rc, out, err = _run(gate_setup.check, "gh")
        assert rc == 0, (out, err)
        assert "token saved as octocat" in out and "acme uses SSO" in out, out
        d = env.dialog.calls()
        assert [c["kind"] for c in d] == ["confirm", "secret", "secret"], d
        assert "personal access token" in d[1]["message"]
        assert "belongs to someone-else, not octocat" in d[2]["message"]
        rec = vault.load()["accounts"]["gh"]
        assert rec["token"]["value"] == "good-token-123456789" and rec["token"]["source"] == "pasted"
        assert "github.com" in rec["bound"]["hosts"]
        assert "good-token" not in out + err


def test_browser_and_device_code_signins_are_unavailable_and_say_what_works():
    """Brief section 11: no authorization web page, browser or device code.
    Every entry point says so and names what works instead; nothing is asked."""
    from gateway import logins
    assert not hasattr(logins, "github_login") and not hasattr(gate_setup, "github_login")
    assert not hasattr(gate_setup, "open_browser") and not hasattr(gate_setup, "entra_login")
    from gateway import entra
    assert not hasattr(entra, "login_browser") and not hasattr(entra, "login_device")
    for form, kind, instead in (
            ('[accounts.az]\nkind = "azure"\ntenant = "example.com"\n', "azure", "service principal"),
            ('[accounts.cat]\nkind = "ml-catalog"\nhost = "catalog.example.com"\n', "ml-catalog",
             "keeps working")):
        with U.ux_env(U.answers(("ok",))) as env:
            U.setup(env, form, approve=False)
            name = "az" if kind == "azure" else "cat"
            rc, out, err = _run(gate_setup.check, name)
            assert rc == 1 and "browser or a device code isn't available" in err, err
            assert instead in err and "existing sign-in keeps working" in err, err
            assert env.dialog.calls() == [], "nothing is asked (not even the consent)"
            rc, out, err = _run(gate_setup.login, name)
            assert rc == 1 and "isn't available" in err, err
    # an existing refresh token keeps working: no sign-in asked
    with U.ux_env() as env:
        U.setup(env, '[accounts.az]\nkind = "azure"\ntenant = "example.com"\n')
        with vault.edit() as d:
            vault.account_record(d, "az", "azure")["entra"] = {
                "refresh_token": "rt-existing-123456", "client_id": formmod.AZURE_CLI_CLIENT_ID,
                "tenant_id": "tid-1", "refreshed": "x"}
        rc, out, err = _run(gate_setup.check, "az")
        assert rc == 0 and env.dialog.calls() == [], (out, err)
    popup_text = popup.signin_unavailable("github", "gh")
    assert "personal access token" in popup_text and "gate check gh" in popup_text
    # the azure guidance names only what the form takes (tenant, client_id), and that form is valid
    az_text = popup.signin_unavailable("azure", "az")
    assert "tenant" in az_text and "client_id" in az_text and "auth =" not in az_text, az_text
    with U.ux_env():
        f = formmod.parse_text('[accounts.az]\nkind = "azure"\ntenant = "contoso.com"\n'
                               'client_id = "11111111-2222-3333-4444-555555555555"\n')
        assert f.ok and "az" in f.accounts, [p.render() for p in f.problems]


def test_an_azure_service_principal_secret_is_checked_with_entra_then_stored():
    import harness_accounts as HA
    from gateway import entra
    good = "sp-secret-value-good-0123456789"
    form = ('[accounts.az]\nkind = "azure"\ntenant = "11111111-2222-3333-4444-555555555555"\n'
            'client_id = "99999999-8888-7777-6666-555555555555"\n')
    srv = HA.EntraServer(secret=good)
    try:
        with U.ux_env(U.answers(("ok",), ("ok", gate_setup.SP_SECRET),
                                ("ok", "sp-secret-value-wrong"), ("ok", good))) as env:
            env.o.extra["entra_authority"] = srv.authority
            U.setup(env, form, approve=False)
            rc, out, err = _run(gate_setup.check, "az")
            assert rc == 0, (out, err)
            d = env.dialog.calls()
            assert [c["kind"] for c in d] == ["confirm", "choice", "secret", "secret"], d
            assert "client secret" in d[2]["message"] and "99999999-8888" in d[2]["message"]
            assert "Entra didn't accept it" in d[3]["message"] and "Invalid client secret" in d[3]["message"]
            e = vault.load()["accounts"]["az"]["entra"]
            assert e["client_secret"] == good and "refresh_token" not in e
            assert e["client_id"] == "99999999-8888-7777-6666-555555555555"
            assert good not in out + err
            # tokens now come from the client-credentials grant
            tok = entra.access_token("az", "arm")
            assert tok.startswith("ACCESS-") and srv.calls[-1]["grant_type"] == "client_credentials"
            from gateway import vault as v
            assert good in v.all_values(v.load()), "masked in output like every stored value"
    finally:
        srv.close()


def test_names_disabled_entries_and_all():
    with U.ux_env() as env:
        U.setup(env, '[hosts.ok]\naddress = "ok.example.com"\nssh = false\nsudo = false\n'
                     '[hosts.bad]\nadress = "x"\n')
        rc, out, err = _run(gate_setup.check, "nope")
        assert rc == 2 and "isn't in gateway.toml" in err
        rc, out, err = _run(gate_setup.check, "bad")
        assert rc == 1 and "off because of a mistake" in err
        rc, out, err = _run(gate_setup.check, "Bad Name!")
        assert rc == 2 and "valid" in err
        from gateway import sudo
        with U.patch(sudo, "probe_nopasswd", lambda user=None: True):
            rc, out, err = _run(gate_setup.check, "all")
        assert rc == 0 and "ok ready" in out and "localhost ready" in out, (out, err)
        rc, out, err = _run(gate_setup.login, "ok")
        assert rc == 2 and "isn't an account" in err


def test_forget_and_rotate():
    from gateway import ssh
    with U.ux_env() as env:
        U.setup(env, HOSTFORM + '[accounts.k]\nkind = "api-key"\nsites = ["api.x.com"]\n')
        with vault.edit() as d:
            vault.set_sudo(d, "box", "octo", "box-sudo-pw-1")
            vault.host_record(d, "box")["host_keys"] = [vault.norm_host_key(HKEY)]
        U.set_token("k", "api-key", "api-key-value-123")
        rc, out, _ = _run(gate_setup.forget, "box", "sudo")
        assert rc == 0 and "sudo passwords" in out and not vault.load()["hosts"]["box"]["sudo"]
        rc, out, _ = _run(gate_setup.forget, "k", "token")
        assert rc == 0 and "token" not in vault.load()["accounts"]["k"]
        assert vault.load()["accounts"]["k"]["bound"]["hosts"] == ["api.x.com"], "bindings stay"
        rc, out, _ = _run(gate_setup.forget, "box", None)
        rec = vault.load()["hosts"]["box"]
        assert rc == 0 and not rec["keys"] and not rec["host_keys"] and not rec["sudo"], rec
        assert rec["host_keys_previous"] == [vault.norm_host_key(HKEY)], "the old pin is remembered"
        rc, out, err = _run(gate_setup.forget, "box", "everything")
        assert rc == 2
        assert any(e["what"] == "forget" for e in vault.load()["events"])
        with U.patch(ssh, "rotate", lambda n, before_change=None: f"gateway: {n} has a new key (old one retired)"):
            rc, out, err = _run(gate_setup.rotate, "box")
        assert rc == 0 and "new key" in out
        rc, out, err = _run(gate_setup.rotate, "k")
        assert rc == 2


def test_forget_keeps_no_copy_and_names_older_ones_rotate_keeps_one_when_it_changes_the_vault():
    """GW-DUR-1's copies, as the lead decided (review round 2): `gate forget`
    keeps no copy of the vault (forgetting means gone) and says when older
    copies in private/backups (gate rotate's, an import's backup, the 0.6
    conversion's) may still hold what it forgot, and how to delete them.
    `gate rotate` keeps the vault from just before it changes it (0600, the
    folder 0700, still encrypted), names the file, keeps the newest 5, and
    keeps nothing when it fails before changing the vault."""
    from gateway import ssh
    with U.ux_env() as env:
        U.setup(env, HOSTFORM + '[accounts.k]\nkind = "api-key"\nsites = ["api.x.com"]\n')
        U.set_token("k", "api-key", "api-key-value-123")
        bk = paths.backups_dir()

        def copies() -> list[str]:
            return sorted(f.name for f in bk.iterdir()) if bk.is_dir() else []
        rc, out, _ = _run(gate_setup.forget, "k", "token")
        assert rc == 0 and "token" not in vault.load()["accounts"]["k"], out
        assert copies() == [], "forget keeps no copy"
        assert out.strip() == "gateway: forgot its token for k", out
        # rotate failing before it changes the vault: nothing kept, its own words
        def fails(n, before_change=None):
            raise ssh.SshError(f"gateway: {n} has no key of the gateway's yet; run gate check {n}", 2)
        with U.patch(ssh, "rotate", fails):
            rc, out, err = _run(gate_setup.rotate, "box")
        assert rc == 2 and "has no key of the gateway's yet" in err and "failed (SshError)" not in err, err
        assert copies() == [], "a rotation that failed first keeps no copy"

        def rotates(n, before_change=None):
            before_change()
            with vault.edit() as d:
                vault.add_event(d, "rotate", f"{n}: a new key")
            return f"gateway: {n} has a new key (old one retired)"
        before = paths.vault_path().read_bytes()
        with U.patch(ssh, "rotate", rotates):
            rc, out, err = _run(gate_setup.rotate, "box")
        snaps = sorted(bk.glob("rotate-*.vault.age"))
        assert rc == 0 and len(snaps) == 1 and snaps[0].read_bytes() == before, (out, err)
        assert paths.vault_path().read_bytes() != before
        assert f"the vault from before is kept in {paths.describe(snaps[0])}" in out, out
        assert oct(snaps[0].stat().st_mode & 0o777) == oct(0o600)
        assert oct(bk.stat().st_mode & 0o777) == oct(0o700)
        assert json.loads(vault._decrypt(snaps[0]).decode())["accounts"]["k"].get("token") is None
        # forget now names the older copies that may still hold the entry
        imp = bk / "import-20260101-000000-abcdef"
        imp.mkdir()
        (imp / "vault.age").write_bytes(b"an import's backup")
        (bk / "store-v2-20260101.age").write_bytes(b"the 0.6 store")
        U.set_token("k", "api-key", "api-key-value-456")
        have = copies()
        rc, out, _ = _run(gate_setup.forget, "k", "token")
        assert rc == 0 and copies() == have, "still no copy of its own"
        d = paths.describe(bk)
        assert d == "~/.config/gateway/private/backups", d
        assert f"Older copies of the vault in {d} (" in out and snaps[0].name in out \
            and imp.name in out and "store-v2-20260101.age" in out and "may still hold it" in out, out
        assert f"the user deletes them in their own terminal: cd {d} && rm -r *.vault.age import-* " \
            "store-v2-*.age" in out, out
        # rotate's copies: the newest 5
        for i in range(6):
            time.sleep(0.01)
            with U.patch(ssh, "rotate", rotates):
                rc, out, _ = _run(gate_setup.rotate, "box")
            assert rc == 0, out
        left = sorted(bk.glob("rotate-*.vault.age"))
        assert len(left) == vault.SNAPSHOT_KEEP == 5 and snaps[0] not in left, left
        assert imp.is_dir() and (bk / "store-v2-20260101.age").exists(), "others' copies stay"


def test_vault_writes_are_durable_temp_file_fsync_rename_fsync_folder():
    """GW-DUR-1: vault.age and cache.age were renamed into place without an
    fsync, so a power loss soon after a write could leave the vault empty.
    The file is flushed before the rename, and its folder after. On macOS
    the flush is F_FULLFSYNC (fsync there leaves the data in the drive's
    cache), with fsync when the file system refuses it (review round 2)."""
    import fcntl
    with U.ux_env() as env:
        U.setup(env, HOSTFORM)
        seen: list[tuple[str, int, bool]] = []
        real_fsync, real_replace, real_fcntl = os.fsync, os.replace, fcntl.fcntl
        refuse_full = [False]

        def fsync(fd):
            st = os.fstat(fd)
            seen.append(("fsync", st.st_ino, stat.S_ISDIR(st.st_mode)))
            return real_fsync(fd)

        def fcntl_(fd, cmd, *a):
            if cmd == getattr(fcntl, "F_FULLFSYNC", object()):
                st = os.fstat(fd)
                seen.append(("full", st.st_ino, stat.S_ISDIR(st.st_mode)))
                if refuse_full[0]:
                    raise OSError(45, "Operation not supported")
            return real_fcntl(fd, cmd, *a)

        def replace(a, b):
            seen.append(("replace", os.stat(a).st_ino, False))
            return real_replace(a, b)
        darwin = sys.platform == "darwin"
        assert vault._DARWIN == darwin
        flush = "full" if darwin else "fsync"
        for refuse in ((False, True) if darwin else (False,)):
            refuse_full[0] = refuse
            for write, target in ((lambda: vault.save(vault.load()), paths.vault_path()),
                                  (lambda: vault.cache_save({"tokens": {"a|b": {"value": "x" * 12,
                                                                                 "expires": time.time() + 600}}}),
                                   paths.cache_path())):
                seen.clear()
                with U.patch(os, "fsync", fsync), U.patch(os, "replace", replace), \
                        U.patch(fcntl, "fcntl", fcntl_):
                    write()
                ino = target.stat().st_ino
                folder = target.parent.stat().st_ino
                rep = seen.index(("replace", ino, False))
                assert (flush, ino, False) in seen[:rep], (refuse, seen)
                assert (flush, folder, True) in seen[rep:], (refuse, seen)
                if darwin and not refuse:
                    assert ("fsync", ino, False) not in seen, ("F_FULLFSYNC, not fsync", seen)
                if refuse:      # F_FULLFSYNC refused: fsync instead, file and folder
                    assert ("fsync", ino, False) in seen[:rep] and ("fsync", folder, True) in seen[rep:], seen
                assert oct(target.stat().st_mode & 0o777) == oct(0o600)
                assert not list(target.parent.glob(f".{target.name}.*.tmp")), "no temp file left"


# ---------------------------------------------------------------------------
# gate secret (removed)
# ---------------------------------------------------------------------------


def test_gate_secret_is_removed_and_says_where_credentials_are_entered():
    with U.ux_env(session=None) as env:
        U.setup(env, HOSTFORM)
        for name in ("box", "../box", "nosuch"):
            rc, out, err = _run(gate_setup.secret_removed, name)
            assert rc == 2 and "gate secret was removed" in err and "dialog inside Claude Code" in err
            assert "../box" not in err
        assert env.dialog.calls() == [] and popup.pending() == []
        from gateway import gate
        rc, out, err = _run(gate.main, ["secret", "box"])
        assert rc == 2 and "gate check box" in err


class _Pty:
    """A pseudo-terminal pair the code under test sees as its terminal; what
    it writes is collected (nothing may be)."""

    def __init__(self, steps: list, linger: float = 0.0):
        import pty as ptymod
        self.master, self.slave = ptymod.openpty()
        self.fin = os.fdopen(os.dup(self.slave), "r")
        self.fout = os.fdopen(os.dup(self.slave), "w")
        self.all = b""

    def close(self) -> None:
        for f in (self.fin, self.fout):
            with contextlib.suppress(OSError):
                f.close()
        os.set_blocking(self.master, False)
        with contextlib.suppress(OSError):
            self.all += os.read(self.master, 65536)
        for fd in (self.master, self.slave):
            with contextlib.suppress(OSError):
                os.close(fd)


def test_check_without_a_dialog_never_prompts_in_a_terminal():
    """No native dialog, no Claude Code markers, a terminal that would answer
    "yes": gate check asks nothing anywhere and leaves nothing pending."""
    with U.ux_env(dialog="none", session=None) as env, ssh_mocks(env, nopasswd=True):
        U.setup(env, HOSTFORM, approve=False)
        from gateway import ssh
        pty = _Pty([], linger=0.5)
        env.o.extra["tty"] = (pty.fin, pty.fout)
        try:
            with U.patch(ssh, "test_login", lambda n: (True, "ok")):
                rc, out, err = _run(gate_setup.check, "box")
        finally:
            pty.close()
        assert rc == 1 and "nothing was asked" in err, (out, err)
        assert pty.all == b"", "nothing was written to the terminal"
        assert "box" not in (vault.load()["approved"].get("rights") or {}).get("hosts", {})
        assert popup.pending("box") == []


def test_token_checks_ignore_proxy_and_ca_settings_from_the_environment():
    """`gate` runs with the environment of Claude's Bash: a pasted token is
    verified without HTTPS_PROXY/HTTP_PROXY/ALL_PROXY and without
    SSL_CERT_FILE/SSL_CERT_DIR (entra.urlopen: no proxies, the build's own CA
    bundle, no redirects)."""
    proxy_routes = {"/user": (200, {"Content-Type": "application/json"}, json.dumps({"login": "proxy"}))}
    guid = "11111111-2222-3333-4444-555555555555"
    api_routes = dict(_github_api())
    api_routes["/api/config"] = (200, {"Content-Type": "application/json"},
                                 json.dumps({"tenantId": guid, "clientId": guid, "cliClientId": guid}))
    with U.ux_env() as env, U.servers(api_routes, proxy_routes) as (api, proxy):
        U.setup(env, "")
        purl = proxy.url("").rstrip("/")
        with U.env_vars(HTTP_PROXY=purl, http_proxy=purl, HTTPS_PROXY=purl, https_proxy=purl,
                        ALL_PROXY=purl, all_proxy=purl, NO_PROXY=None, no_proxy=None):
            code, body, _h = gate_setup.http_json(api.url("/user"), "good-token-123456789")
            assert (code, body) == (200, {"login": "octocat"}), (code, body)
            assert proxy.rec.requests == [], "the token never went to the proxy"
            assert api.rec.last()["headers"]["Authorization"] == "Bearer good-token-123456789"
            a = __import__("gateway.form", fromlist=["x"]).parse_text(
                '[accounts.gh]\nkind = "github"\nlogin = "octocat"\n').accounts["gh"]
            env.o.extra["github_api"] = api.url("").rstrip("/")
            found: dict = {}
            assert gate_setup.github_verify(a, found)("good-token-123456789") == (True, "")
            assert proxy.rec.requests == []
            # the catalog's sign-in settings (they pick the tenant and client) too
            cfg = gate_setup.catalog_config(f"127.0.0.1:{api.port}")
            assert cfg["tenantId"] == guid and proxy.rec.requests == [], proxy.rec.requests
        tls = U.self_signed(env.root / "tls")
        if tls is None:
            return
        empty = env.root / "no-certs"
        empty.mkdir()
        with U.servers(_github_api(), tls=tls) as (sapi,), \
                U.env_vars(SSL_CERT_FILE=tls[0], SSL_CERT_DIR=str(empty)):
            code, body, _h = gate_setup.http_json(sapi.url("/user"), "good-token-123456789")
            assert code == 0 and body is None, "a CA named by SSL_CERT_FILE isn't trusted"
            assert sapi.rec.requests == [], "nothing was sent over the untrusted connection"


def test_an_entry_named_settings_is_refused():
    form = '[hosts.settings]\naddress = "octo@settings.example.com"\nsudo = false\n'
    with U.ux_env(session=None) as env, ssh_mocks(env):
        U.setup(env, form, approve=False)
        rc, out, err = _run(gate_setup.check, "settings")
        assert rc == 2 and "reserved" in err and "rename [hosts.settings]" in err, (out, err)
        from gateway import sudo
        with U.patch(sudo, "probe_nopasswd", lambda user=None: True):
            rc, out, err = _run(gate_setup.check, "all")
        assert rc == 2 and "reserved" in err and "localhost ready" in out, (out, err)
        assert env.dialog.calls() == [], "no dialog for the clashing entry"
        from gateway import hooks_post
        assert "settings is reserved" in hooks_post.form_report(env.form(), None)


def test_forgetting_host_keys_doesnt_turn_a_changed_key_into_a_first_pin():
    """`gate forget box host-keys` (no longer hook-allowed: GW-DATA-1) then
    `gate check box` with a different key: still a host-key change pop-up
    (old and new), not a plain first pin. The same key as before pins
    quietly in the consent pop-up."""
    form = '[hosts.box]\naddress = "octo@box.example.com"\nsudo = false\n'
    other = H.fake_host_key("attacker-key")
    k, pub = H.ssh_keypair("box")
    with U.ux_env(U.answers(("cancelled",), ("ok",))) as env:
        U.setup(env, form)
        with vault.edit() as d:
            rec = vault.host_record(d, "box")
            rec["keys"] = [vault.key_record(k, pub)]
            rec["installed"] = vault.now()
            rec["host_keys"] = [vault.norm_host_key(HKEY)]
        rc, out, _ = _run(gate_setup.forget, "box", "host-keys")
        assert rc == 0 and vault.load()["hosts"]["box"]["host_keys"] == []
        with ssh_mocks(env, keys=[other]):
            rc, out, err = _run(gate_setup.check, "box")
        assert rc == 1, (out, err)
        d = env.dialog.calls()
        old_fp = vault.host_key_fingerprints([HKEY])[0]
        new_fp = vault.host_key_fingerprints([other])[0]
        assert len(d) == 1 and d[0]["default"] == "Cancel", d
        assert "not the one the gateway pinned" in d[0]["message"], d[0]["message"]
        assert old_fp.split()[-1] in d[0]["message"] and new_fp.split()[-1] in d[0]["message"]
        assert vault.load()["hosts"]["box"]["host_keys"] == [], "nothing pinned after Cancel"
        hooks_prompt.main({"prompt": "go on", "session_id": "sess-ux"})
        with ssh_mocks(env, keys=[HKEY], installed_after=None) as calls, \
                U.patch(__import__("gateway.ssh", fromlist=["x"]), "test_login", lambda n: (True, "ok")):
            rc, out, err = _run(gate_setup.check, "box")
        assert rc == 0, (out, err)
        d = env.dialog.calls()
        assert len(d) == 2 and "Host key of box" in d[1]["message"], d
        assert "differs" not in d[1]["message"] and "not the one" not in d[1]["message"]
        rec = vault.load()["hosts"]["box"]
        assert rec["host_keys"] == [vault.norm_host_key(HKEY)] and "host_keys_previous" not in rec


def test_a_syntax_error_falls_back_to_the_last_valid_form_of_this_session():
    """Review round 2: the last good form was saved only at session start, so
    a syntax error dropped a host added and approved in this session, and gate
    check then said to add it again (a duplicate table TOML rejects). The last
    valid form is kept now, and messages point at the syntax error instead."""
    from gateway import gate, hooks_post, hooks_session, ssh, ssh_args
    ans = U.answers(("ok",), ("ok", "Use my own SSH login once (recommended)"),
                    ("ok", gate_setup.SUDO_STORE), ("ok", GOOD_SUDO))
    with U.ux_env(ans) as env, ssh_mocks(env):
        hooks_session.session_main({"session_id": "sess-ux"})

        def edited():
            return hooks_post.main({"tool_name": "Edit", "session_id": "sess-ux",
                                    "tool_input": {"file_path": str(paths.form_path())},
                                    "tool_response": {}})["hookSpecificOutput"]["additionalContext"]

        env.write_form(paths.form_path().read_text()
                       + '\n[hosts.homelab]\naddress = "alex@192.168.1.20"\nsudo = true\n')
        edited()
        rc, out, err = _run(gate_setup.check, "homelab")
        assert rc == 0, (out, err)
        env.write_form(paths.form_path().read_text()
                       + '\n[hosts.builder]\naddress = "ci@builder.internal"\nsudo = maybe\n')
        ctx = edited()
        assert 'sudo takes true, "ask" or false' in ctx and "last good version" in ctx, ctx
        assert "text values need quotes" not in ctx
        form = consent.load_form()
        assert form.syntax_error is not None and "homelab" in form.hosts, "this session's host stays"
        rc, out, err = _run(gate_setup.check, "homelab")
        assert rc == 0 and "isn't in gateway.toml" not in err, (out, err)
        rc, out, err = _run(gate_setup.check, "builder")
        assert rc != 0 and "syntax error on line" in err and "add it there first" not in err, err
        assert "don't add builder again" in err
        rc, out, err = _run(gate.main, ["status", "nosuch"])
        assert "syntax error on line" in out + err, (out, err)
        dest = ssh_args.parse_destination("builder")
        assert "syntax error on line" in ssh._unknown_message(dest, "uptime", form)
        # a plain invalid value still gets the quoting hint
        f2 = formmod.parse_text('[hosts.x]\naddress = "u@h"\nnote = lab box\n')
        assert "text values need quotes" in f2.syntax_error.message
        f3 = formmod.parse_text('[hosts.x]\naddress = "u@h"\nscripts = maybe\n')
        assert "scripts takes true or false" in f3.syntax_error.message


def test_keys_gate_check_makes_say_which_entry_and_machine():
    """Review round 2: gate check labelled its keys `gateway-NAME`, rotate and
    the ssh stand-in `gateway-NAME@MACHINE`; README's Uninstall tells users to
    look for the latter in authorized_keys."""
    with U.ux_env() as env:
        U.setup(env, '[hosts.homelab]\naddress = "alex@192.168.1.20"\n')
        with vault.edit() as d:
            vault.ensure_machine(d)
            d["machine"]["name"] = "MacBook Air"
        gate_setup._ensure_key("homelab")
        pub = vault.live_keys(vault.load()["hosts"]["homelab"])[0]["public"]
        assert pub.split()[-1] == "gateway-homelab@macbook-air", pub
        assert vault.key_comment("homelab", vault.load()) == "gateway-homelab@macbook-air"


def test_gate_check_prints_its_line_before_claude_codes_bash_timeout():
    """Review round 4: each pop-up wait counted its own 90 s, so a slow scan
    plus an unanswered pop-up ran past Claude Code's 2-minute Bash timeout
    before gate check printed its exit-75 line. The waits now end at the
    command's overall budget; gate check all starts no new entry after its
    own."""
    with U.ux_env(U.answers(("ok", "", 6)), wait=20) as env, ssh_mocks(env):
        U.setup(env, HOSTFORM, approve=False)
        env.o.extra["gate_check_budget"] = 1.5
        t0 = time.time()
        rc, out, err = _run(gate_setup.check, "box")
        took = time.time() - t0
        assert rc == popup.EX_TEMPFAIL and "still open" in err, (rc, err)
        assert took < 5, f"took {took:.1f} s; the 20 s pop-up wait wasn't capped"
        assert popup._DEADLINE is None, "the cap ends with the command"
    with U.ux_env() as env, ssh_mocks(env):
        U.setup(env, '[hosts.localhost]\nsudo = true\n[accounts.a]\nkind = "api-key"\n'
                     'sites = ["api.a.com"]\n[accounts.b]\nkind = "api-key"\nsites = ["api.b.com"]\n')
        U.set_token("a", "api-key", "api-key-value-aaaa")
        U.set_token("b", "api-key", "api-key-value-bbbb")
        env.o.extra["gate_check_all_budget"] = 0
        from gateway import sudo
        with U.patch(sudo, "probe_nopasswd", lambda user=None: True):
            rc, out, err = _run(gate_setup.check, "all")
        assert rc == popup.EX_TEMPFAIL, (rc, out, err)
        assert "2 entries are still to check (a, b); run gate check all again" in err, err
        assert "localhost ready" in out



def test_status_notes_follow_the_line_without_nested_prefixes():
    line = "gateway: homelab ready: ssh ✓ (alex@h, key installed), sudo ✓ (no password needed)"
    out = gate_setup.with_notes(line, [
        "gateway: Claude's key is installed on homelab (SHA256:abc)",
        "gateway: passwordless sudo is set up for alex on homelab.",
        "gateway: passwordless sudo is set up for alex on homelab."])
    assert out == (line + "; Claude's key is installed on homelab (SHA256:abc); passwordless sudo "
                   "is set up for alex on homelab"), out
    assert gate_setup.with_notes(line, []) == line


def test_session_start_says_where_a_waiting_ok_is_given():
    """A widening waiting for the user's OK: SessionStart says Claude opens the
    gateway's dialog with gate check, where it can be answered (no terminal
    command, no code)."""
    with U.ux_env(dialog="none") as env, ssh_mocks(env):
        U.setup(env, '[hosts.homelab]\naddress = "alex@192.168.1.20"\n', approve=False)
        res = hooks_session.session_main({"session_id": "sess-3"})
        msg = res["systemMessage"]
        assert "gateway's dialog for it with `gate check homelab`" in msg, msg
        assert "terminal session or the desktop app" in msg and "gate secret" not in msg, msg


def test_an_unreadable_vault_says_what_to_do():
    with U.ux_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n')
        paths.key_path().write_text("AGE-SECRET-KEY-1NOTAKEY\n")
        res = hooks_session.session_main({"session_id": "s"})
        msg = res["systemMessage"]
        assert "the vault can't be read" in msg and "put back" in msg and "gate import" in msg, msg


@contextlib.contextmanager
def _recorded_secrets(env, after=None):
    """popup.secret wrapped: each call's entry, what, check and remember go
    to a file (the dialogs run in the forked helper); `after(entry, what)`
    runs once the dialog answered (the form edited while it was open)."""
    rec = env.root / "secret-calls.jsonl"
    real = popup.secret

    def recording(entry, what, prompt, verify=None, **kw):
        with open(rec, "a") as f:
            f.write(json.dumps({"entry": entry, "what": what, "check": kw.get("check"),
                                "remember": kw.get("remember")}) + "\n")
        out = real(entry, what, prompt, verify, **kw)
        if after is not None:
            after(entry, what)
        return out
    with U.patch(popup, "secret", recording):
        yield lambda: [json.loads(x) for x in rec.read_text().splitlines()] if rec.exists() else []


def test_check_sudo_dialogs_name_the_rights_gated_rechecks():
    """Phase 3 review: gate check's sudo password dialogs name the host and
    the rights gated rechecks before it hands the password over (sudo; and
    ssh for a remote host, whose sudo runs over it)."""
    from gateway import sudo
    ans = U.answers(("ok",), ("ok", "Use my own SSH login once (recommended)"),
                    ("ok", gate_setup.SUDO_STORE), ("ok", GOOD_SUDO))
    with U.ux_env(ans) as env, ssh_mocks(env), _recorded_secrets(env) as calls:
        U.setup(env, HOSTFORM, approve=False)
        rc, out, err = _run(gate_setup.check, "box")
        assert rc == 0, (out, err)
        assert calls() == [{"entry": "box", "what": "sudo password", "remember": None,
                            "check": {"section": "hosts", "entry": "box", "right": ["ssh", "sudo"]}}]
    with U.ux_env(U.answers(("ok", gate_setup.SUDO_STORE), ("ok", "mac-pw-correct"))) as env, \
            _recorded_secrets(env) as calls:
        U.setup(env, "[hosts.localhost]\nsudo = true\n")
        with U.patch(sudo, "probe_nopasswd", lambda user=None: False), \
                U.patch(sudo, "verify_local", lambda pw: (pw == "mac-pw-correct", "no")):
            rc, out, err = _run(gate_setup.check, "localhost")
        assert rc == 0, (out, err)
        assert [c["check"] for c in calls()] == [{"section": "hosts", "entry": "localhost",
                                                  "right": "sudo"}]
