"""Messages whose next step was wrong or missing (review round 2): each names
the real fix, the real entry name, every "ask" right, and a command where one
helps. One test per message."""
from __future__ import annotations

import contextlib
import io

import harness as H
import harness_accounts as HA
import harness_ux as U
from gateway import accounts, consent, gate, gate_setup, hooks_bash, hooks_session, popup, sudo, vault


def _out(fn, *args):
    o, e = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(o), contextlib.redirect_stderr(e):
        rc = fn(*args)
    return rc, o.getvalue(), e.getvalue()


def test_gate_with_an_env_waiting_for_the_ok_says_run_gate_check():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        HA.build_vault(env, '[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n',
                       tokens={"openai": "sk-openaikeyvalue0123456789abcd"})
        env.write_form('[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n'
                       'env = "OPENAI_API_KEY"\n')
        rc, _out_, err = HA.run_with(["openai", "--", "true"])
        assert rc == 2 and "waits for the user's OK; run gate check openai" in err, err
        assert "add `env" not in err
        env.write_form('[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n')
        rc, _out_, err = HA.run_with(["openai", "--", "true"])
        assert rc == 2 and "ask the user whether to add" in err and "gate check openai" in err, err


def test_waiting_ok_message_names_the_gateway_dialog_and_where_it_works():
    msg = hooks_session.ok_how("homelab", ["homelab"])
    assert "gateway's dialog for it with `gate check homelab`" in msg, msg
    assert "gate secret" not in msg and "pop-up" not in msg and "not claude -p" in msg, msg


def test_the_ask_reason_lists_every_ask_right():
    form = ('[hosts.askhost]\naddress = "u@ask.example.com"\nssh = "ask"\nsudo = "ask"\n')
    with H.gateway_env() as env:
        env.write_form(form)
        vault.save(vault.empty())
        consent.approve_all(env.form())
        out = hooks_bash.main({"tool_name": "Bash", "permission_mode": "auto",
                               "tool_input": {"command": "ssh askhost 'sudo systemctl restart nginx'"}})
        r = out["hookSpecificOutput"]
        assert r["permissionDecision"] == "ask"
        assert "ssh on askhost and sudo (root) on askhost are set to" in r["permissionDecisionReason"], r


def test_an_unknown_git_server_isnt_sent_after_an_account_kind_that_doesnt_exist():
    m = accounts.no_git_account("gitlab.com")
    assert "the user's own ssh and git" in m and "others" not in m and "ask the user to add one" not in m, m
    assert "kind github" in accounts.no_git_account("github.com")


def test_a_cancelled_consent_reads_as_the_users_ok():
    m = popup.message(popup.Outcome.CANCELLED, "openai", "consent")
    assert m.startswith("gateway: the user cancelled the consent dialog for openai;"), m
    assert "your OK" not in m and "the user's OK for" not in m, m


def test_status_says_how_to_add_an_api_key():
    with U.ux_env() as env:
        U.setup(env, '[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n')
        rc, out, _e = _out(gate.main, ["status"])
        assert "no key yet (gate check openai)" in out, out


def test_sudo_without_a_password_or_a_screen_names_the_next_step():
    assert "gate check localhost" in sudo.NO_PW and "own terminal" in sudo.NO_PW


def test_a_rejected_credential_without_a_screen_doesnt_claim_a_pop_up_is_open():
    m = popup.stale_message("box", "sudo password", popup.Outcome.UNAVAILABLE)
    assert "is open" not in m and "gate check box" in m and "Don't retry" in m, m
    assert "cancelled" in popup.stale_message("box", "sudo password", popup.Outcome.CANCELLED)
    assert "a gateway dialog to enter it again is open" in popup.stale_message("box", "sudo password")
    with U.ux_env(dialog="none"):
        msg = popup.reenter("box", "sudo password", "Type it.")
        assert "is open" not in msg and "nothing was asked" in msg, msg


def test_an_unrelated_ip_suggests_no_host_and_an_account_endpoint_asks_for_an_account():
    """Round 3: `ssh 10.0.0.99 x` suggested a host at 10.0.0.9; `ssh github.com
    x` without a GitHub account said Claude could import it from ~/.ssh/config."""
    from pathlib import Path
    from gateway import form as F, ssh, ssh_args
    f = F.parse_text('[hosts.example]\naddress = "u@10.0.0.9"\nalso = ["u@lab.example.com"]\n',
                     Path("/x"))
    assert ssh._suggest("10.0.0.99", f) is None
    assert ssh._suggest("10.0.0.9", f) == "example", "an IP that is one of its addresses"
    assert ssh._suggest("exmple", f) == "example"
    assert ssh._suggest("lab.exampel.com", f) == "example"
    m = ssh._unknown_message(ssh_args.parse_destination("10.0.0.99"), "uptime", f)
    assert "Did you mean" not in m, m
    m = ssh._unknown_message(ssh_args.parse_destination("github.com"), "x", f)
    assert "kind github" in m and "~/.ssh/config" not in m, m


def test_gate_check_all_sets_jump_hosts_up_first():
    from pathlib import Path
    from gateway import form as F, gate_setup
    f = F.parse_text('[hosts.a]\naddress = "u@a.example.com"\nvia = "b"\n'
                     '[hosts.b]\naddress = "u@b.example.com"\nvia = "c"\n'
                     '[hosts.c]\naddress = "u@c.example.com"\n[hosts.d]\naddress = "u@d.example.com"\n',
                     Path("/x"))
    order = gate_setup.hosts_jumps_first(f)
    assert order.index("c") < order.index("b") < order.index("a") and "d" in order, order
    assert len(order) == len(set(order)) == len(f.hosts)


def test_status_line_never_says_ready_with_ssh_waiting():
    with U.ux_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\nssh = false\n')
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\n')
        form, eff, data = gate_setup._reload()
        line = gate_setup.status_line("box", form, eff, data)
        assert line.startswith("gateway: box isn't ready: ssh waits for the user's OK"), line


def test_a_rejected_token_and_an_unreadable_vault_name_the_next_step():
    from gateway import clis
    with U.ux_env() as env:
        U.setup(env, '[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n'
                     'env = "OPENAI_API_KEY"\n')
        U.set_token("openai", "api-key", "sk-planted-0123456789abcdef")
        with vault.edit() as d:
            d["accounts"]["openai"]["token"]["stale"] = True
        err = io.StringIO()
        with U.patch(clis, "is_direct", lambda *a, **k: (True, "")), contextlib.redirect_stderr(err):
            rc = clis.with_main(["openai", "--", "true"])
        assert rc == 2 and "openai's token was rejected; don't retry. Run gate check openai" in \
            err.getvalue(), err.getvalue()
        # the vault can't be read: say what to do
        paths_key = vault.paths.key_path()
        paths_key.write_text("AGE-SECRET-KEY-1NOTAKEY\n")
        try:
            gate_setup._load()
        except SystemExit as e:
            msg = str(e)
        else:
            raise AssertionError("loaded an unreadable vault")
        assert "the vault can't be read, so nothing was changed; tell the user" in msg, msg
