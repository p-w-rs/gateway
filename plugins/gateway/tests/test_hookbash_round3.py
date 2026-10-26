"""Review round 3 fixes in the approval hook (SPEC 8):

- deny and ask go by the stricter of the form's and the effective right: an
  approved "ask" edited to `true` (the change waits for the user's OK) is
  still asked about, and a widening still waiting is denied with the next
  step, because the stand-ins give an effective "ask" right to a command
  Claude typed, trusting the hook asked;
- `gate scrub`, the optional line filter Claude may pipe output through
  (round 3 also required it for Monitor commands; rolled back, see
  test_hookbash_round4).
"""
from __future__ import annotations

import io
import sys

import harness as H
from gateway import consent, gate, hooks_bash, vault

ASKS = """
[hosts.localhost]
sudo = "ask"

[hosts.box]
address = "u@box.example.com"
ssh  = "ask"
sudo = "ask"
"""


def _decide(command, mode="auto", tool="Bash", cwd=None):
    payload = {"tool_name": tool, "tool_input": {"command": command}, "permission_mode": mode,
               "cwd": cwd or "/tmp"}
    out = hooks_bash.main(payload)
    if out is None:
        return None, ""
    r = out["hookSpecificOutput"]
    return r["permissionDecision"], r["permissionDecisionReason"]


def _approve(env, text):
    env.write_form(text)
    vault.save(vault.empty())
    consent.approve_all(env.form())


def test_an_approved_ask_edited_to_true_is_still_asked_about():
    """Round 3: with ssh/sudo = "ask" approved and the form edited to true,
    the effective right stays "ask" (the change waits for the user's OK); the
    hook went by the form (true), gave no decision, and the stand-in, trusting
    a prompt, ran the typed command with Claude's key or the sudo password."""
    with H.gateway_env() as env:
        _approve(env, ASKS)
        env.write_form(ASKS.replace('"ask"', "true"))
        eff = consent.compute(env.form(), vault.load())
        assert eff.hosts["box"].ssh == "ask" and eff.hosts["localhost"].sudo == "ask"
        assert any("box" == c.entry for c in eff.pending)
        for mode in ("auto", "default"):
            for cmd in ("ssh box id", "sudo apt update", "ssh box 'sudo id'", "ssh box sudo id",
                        "env bash -c 'ssh box id'", "gate check box"):
                d, why = _decide(cmd, mode)
                assert d == "ask", (mode, cmd, d, why)
                assert '"ask"' in why
            # words the hook can't spell out get no record: the stand-in would
            # refuse after the prompt (lead decision 19.14), so refused here
            d, why = _decide('ssh box "$(cat cmd.txt)"', mode)
            assert d == "deny" and 'is set to "ask"' in why and "spell out" in why, (mode, d, why)
            # a target in a variable hides the host (PLAN-0.11 §1.7): refused
            d, why = _decide("for h in box; do ssh $h id; done", mode)
            assert d == "deny" and "hides the program or host" in why, (mode, d, why)
            # scp / sftp / rsync start ssh themselves: the stand-in would refuse
            for cmd in ("scp ./f box:/srv/f", "rsync -a ./x box:/srv/x", "sftp box:/srv/f",
                        "rsync -a --rsync-path='sudo rsync' ./x box:/srv/x"):
                d, why = _decide(cmd, mode)
                assert d == "deny" and 'is set to "ask"' in why, (mode, cmd, d, why)


def test_a_widening_waiting_for_the_users_ok_is_denied_with_the_next_step():
    with H.gateway_env() as env:
        off = ASKS.replace('"ask"', "false")
        _approve(env, off)
        env.write_form(ASKS.replace('"ask"', "true"))          # false -> true: waits
        for mode in ("auto", "default"):
            d, why = _decide("ssh box id", mode)
            assert d == "deny" and why == ("gateway: ssh on box waits for the user's OK; run gate "
                                           "check box while the user is here."), why
            d, why = _decide("sudo ls", mode)
            assert d == "deny" and why == ("gateway: sudo on this machine waits for the user's "
                                           "OK; run gate check localhost while the user is "
                                           "here."), why
            d, why = _decide("scp ./f box:/srv/f", mode)
            assert d == "deny" and "waits for the user's OK" in why, why
        # gate check is how the user approves it: allowed, never denied for that
        assert _decide("gate check box", "auto")[0] == "allow"
        # an approved ssh with the host's sudo still waiting
        _approve(env, ASKS.replace('ssh  = "ask"', "ssh = true").replace('"ask"', "false"))
        env.write_form(ASKS.replace('ssh  = "ask"', "ssh = true").replace('"ask"', "true"))
        d, why = _decide("ssh box sudo id")
        assert d == "deny" and why.startswith("gateway: sudo on box waits for the user's OK"), why
        assert _decide("ssh box uptime")[0] == "allow"


def test_a_host_behind_a_jump_host_that_waits_names_the_jump_host():
    with H.gateway_env() as env:
        _approve(env, "[hosts.localhost]\nsudo = true\n")
        env.write_form('[hosts.gw1]\naddress = "u@gw1.example.com"\n\n'
                       '[hosts.inner]\naddress = "u@10.1.2.3"\nvia = "gw1"\n')
        d, why = _decide("ssh inner id")
        assert d == "deny" and "it goes through gw1, which isn't set up yet" in why and \
            "run gate check gw1, then gate check inner" in why, why


def test_an_off_right_still_says_off():
    with H.gateway_env() as env:
        _approve(env, ASKS.replace('"ask"', "false"))
        d, why = _decide("ssh box id")
        assert d == "deny" and why == ("gateway: ssh is off for box (gateway.toml); ask the user "
                                       "if it should be on."), why


# ---------------------------------------------------------------------------
# gate scrub
# ---------------------------------------------------------------------------

PLAIN = '[hosts.localhost]\nsudo = true\n[hosts.box]\naddress = "u@box.example.com"\n'


def test_gate_scrub_masks_vault_values_and_token_shapes():
    secret = "plain-sudo-password-xyz"
    with H.gateway_env() as env:
        env.write_form(PLAIN)
        data = vault.empty()
        vault.set_sudo(data, "box", "u", secret)
        vault.save(data)
        lines = (f"line one {secret}\n"
                 "line two ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345\n"
                 "line three plain\n"
                 f"no newline at the end {secret}")
        old_in, old_out = sys.stdin, sys.stdout
        sys.stdin = io.TextIOWrapper(io.BytesIO(lines.encode()))
        buf = io.BytesIO()
        sys.stdout = io.TextIOWrapper(buf)
        try:
            rc = gate.main(["scrub"])
            sys.stdout.flush()
            out = buf.getvalue().decode()
        finally:
            sys.stdin, sys.stdout = old_in, old_out
        assert rc == 0
        assert secret not in out and "ghp_ABCDEF" not in out, out
        assert out.count("***") == 3 and "line three plain\n" in out, out
        assert out.endswith("no newline at the end ***"), out


def test_gate_scrub_passes_nothing_when_the_vault_cant_be_read():
    with H.gateway_env() as env:
        env.write_form(PLAIN)
        vault.save(vault.empty())
        paths_key = vault.paths.key_path()
        paths_key.write_text("AGE-SECRET-KEY-1NOTAKEY\n")          # a broken identity
        old_in, old_out = sys.stdin, sys.stdout
        sys.stdin = io.TextIOWrapper(io.BytesIO(b"maybe a secret\n"))
        buf = io.StringIO()
        sys.stdout = buf
        try:
            rc = gate.main(["scrub"])
        finally:
            sys.stdin, sys.stdout = old_in, old_out
        assert rc == 1 and "maybe a secret" not in buf.getvalue()
        assert "can't read the vault" in buf.getvalue()
