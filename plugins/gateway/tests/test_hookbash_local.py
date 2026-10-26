"""Local sudo right (false / ask / true) at the Bash hook, consent-pending
hosts, the ratchet on form-editing commands, and `gate why` recording."""
from __future__ import annotations

import harness as H
from gateway import audit, consent, hooks_bash, vault


def _decide(command, mode="auto", cwd=None):
    payload = {"tool_name": "Bash", "tool_input": {"command": command}, "permission_mode": mode}
    if cwd:
        payload["cwd"] = cwd
    out = hooks_bash.main(payload)
    return None if out is None else out["hookSpecificOutput"]["permissionDecision"]


def _reason(command, mode="auto"):
    out = hooks_bash.main({"tool_name": "Bash", "tool_input": {"command": command},
                           "permission_mode": mode})
    return out["hookSpecificOutput"]["permissionDecisionReason"] if out else None


def _approved(env, text):
    env.write_form(text)
    vault.save(vault.empty())
    consent.approve_all(env.form())


def test_local_sudo_off_denies_in_every_mode():
    with H.gateway_env() as env:
        _approved(env, "[hosts.localhost]\nsudo = false\n")
        for mode in ("auto", "default", "plan"):
            assert _decide("sudo ls", mode) == "deny", mode
        assert "sudo is off on this machine" in _reason("sudo ls")


def test_local_sudo_ask():
    with H.gateway_env() as env:
        _approved(env, "[hosts.localhost]\nsudo = ask\n")
        assert _decide("sudo ls", "auto") == "ask"
        assert _decide("sudo ls", "default") == "ask"
        assert '"ask"' in _reason("sudo ls")


def test_local_sudo_true_allows_only_in_auto():
    with H.gateway_env() as env:
        _approved(env, "[hosts.localhost]\nsudo = true\n")
        assert _decide("sudo ls", "auto") == "allow"
        assert _decide("sudo ls", "default") is None


def test_implicit_localhost_sudo_is_the_users_own():
    # No [hosts.localhost] at all (PLAN-0.11 §1.5): this computer's sudo is
    # the user's own: no decision (Claude Code's own permissions), in auto
    # mode too; never allowed.
    with H.gateway_env() as env:
        _approved(env, '[hosts.box]\naddress = "u@box.example.com"\nssh = true\n')
        assert _decide("sudo ls", "auto") is None
        assert _decide("sudo ls", "bypassPermissions") is None


def test_pending_new_host_is_denied_with_the_next_step():
    # A host added but not yet approved: ssh right true in the form, but
    # effective is False (pending). The stand-in would refuse it, so the hook
    # denies with the next step (round 3), in every mode.
    with H.gateway_env() as env:
        env.write_form("[hosts.localhost]\nsudo = true\n")
        vault.save(vault.empty())
        consent.approve_all(env.form())
        env.write_form('[hosts.localhost]\nsudo = true\n\n[hosts.newbox]\n'
                       'address = "u@new.example.com"\nssh = true\n')
        assert "newbox" in consent.compute(env.form(), vault.load()).pending_names()
        for mode in ("auto", "default"):
            out = hooks_bash.main({"tool_input": {"command": "ssh newbox uptime"},
                                   "permission_mode": mode})
            r = out["hookSpecificOutput"]
            assert r["permissionDecision"] == "deny", (mode, r)
            assert r["permissionDecisionReason"] == ("gateway: ssh on newbox waits for the user's "
                                                     "OK; run gate check newbox while the user is "
                                                     "here."), r
        # gate check is how the user approves it: never denied for that reason
        assert _decide("gate check newbox", "auto") == "allow"


def test_narrowed_then_raised_host_is_denied_until_reapproved():
    # Approve ssh true, then the form lowers it to false (narrowing applies at
    # once). ssh is then denied.
    with H.gateway_env() as env:
        _approved(env, '[hosts.localhost]\nsudo=true\n\n[hosts.b]\n'
                  'address="u@b.example.com"\nssh=true\n')
        env.write_form('[hosts.localhost]\nsudo=true\n\n[hosts.b]\n'
                       'address="u@b.example.com"\nssh=false\n')
        assert _decide("ssh b uptime", "auto") == "deny"


def test_sed_edit_of_form_ratchets_first():
    # A sed -i that would be followed by a raise must find the narrowing
    # persisted. We check that naming gateway.toml triggers the ratchet.
    with H.gateway_env() as env:
        _approved(env, '[hosts.localhost]\nsudo=true\n\n[hosts.b]\n'
                  'address="u@b.example.com"\nssh="ask"\n')
        # the form is edited on disk to lower b to false (a narrowing)
        env.write_form('[hosts.localhost]\nsudo=true\n\n[hosts.b]\n'
                       'address="u@b.example.com"\nssh=false\n')
        # a Bash command that names gateway.toml triggers the ratchet
        _decide("sed -n 1p ~/.config/gateway/gateway.toml", "auto")
        ap = vault.load()["approved"]["rights"]["hosts"]["b"]
        assert ap["ssh"] is False, "the narrowing was persisted by the ratchet"


def test_refusal_recorded_for_gate_why():
    with H.gateway_env() as env:
        _approved(env, "[hosts.localhost]\nsudo = false\n")
        import os
        os.environ["CLAUDE_CODE_SESSION_ID"] = "sess-bash-1"
        try:
            assert _decide("sudo ls", "auto") == "deny"
            last = audit.last_refusal("sess-bash-1")
            assert last and "sudo is off" in last["reason"]
        finally:
            os.environ.pop("CLAUDE_CODE_SESSION_ID", None)


def test_reasons_start_with_gateway():
    with H.gateway_env() as env:
        _approved(env, "[hosts.localhost]\nsudo = false\n")
        for cmd in ("curl http://x", "sudo ls", "cat ~/.config/gateway/private/key.txt",
                    "git credential fill"):
            r = _reason(cmd)
            assert r and r.startswith("gateway:"), (cmd, r)


def test_missing_vault_and_form_no_crash():
    with H.gateway_env():
        # no form, no vault: this computer's sudo is the user's own: no decision
        assert _decide("sudo ls", "auto") is None
        assert _decide("curl http://x", "auto") == "ask"     # a network command (PLAN-0.11 §3)



def test_user_terminal_tool_gets_denies_and_asks_but_never_allow():
    """PreToolUse also covers mcp__terminal__run_in_terminal (the user's own
    Terminal panel): there sudo/ssh aren't the stand-ins, so nothing is
    allowed by the gateway; denies (private paths, rights false) and asks
    (a network command, PLAN-0.11 §3) still apply."""
    with H.gateway_env() as env:
        env.write_form('[hosts.localhost]\nsudo = true\n[hosts.off]\naddress = "u@off.example.com"\n'
                       'ssh = false\n')
        vault.save(vault.empty())
        consent.approve_all(env.form())

        def decide(cmd, tool):
            out = hooks_bash.main({"tool_name": tool, "tool_input": {"command": cmd},
                                   "permission_mode": "auto"})
            return None if out is None else out["hookSpecificOutput"]["permissionDecision"]
        assert decide("sudo ls", "Bash") == "allow"
        assert decide("sudo ls | gate scrub", "Monitor") == "allow"
        assert decide("sudo ls", "Monitor") == "allow", "Monitor is judged like Bash (no scrub rule)"
        assert decide("sudo ls", "mcp__terminal__run_in_terminal") is None
        assert decide("gate status", "mcp__terminal__run_in_terminal") is None
        assert decide("curl https://x.example", "mcp__terminal__run_in_terminal") == "ask"
        assert decide("cat ~/.config/gateway/private/key.txt",
                      "mcp__terminal__run_in_terminal") == "deny"
        assert decide("ssh off true", "mcp__terminal__run_in_terminal") == "deny"


def test_gate_dialog_commands_are_denied_in_the_terminal_panel():
    """gate export / import / copy-to ask the user in the gateway's dialog,
    which only a command Claude runs with the Bash tool can open: typed into
    the desktop app's Terminal panel (mcp__terminal__run_in_terminal) they
    are denied, also behind a wrapper; in Bash they aren't. The removed `gate
    secret` has no rule of its own any more (gate itself says it doesn't
    know the command)."""
    with H.gateway_env() as env:
        _approved(env, '[hosts.box]\naddress = "u@box.example.com"\nssh = true\n')

        def out(cmd, tool):
            o = hooks_bash.main({"tool_name": tool, "tool_input": {"command": cmd},
                                 "permission_mode": "auto", "cwd": str(env.root)})
            return o["hookSpecificOutput"] if o else {}
        for cmd in ("gate export", "gate export /tmp/x.age", "~/.config/gateway/gate import f.age",
                    "gate copy-to box", "env gate copy-to box", "timeout 60 gate export /tmp/x.age"):
            d = out(cmd, "mcp__terminal__run_in_terminal")
            assert d.get("permissionDecision") == "deny", (cmd, d)
            assert "Terminal panel" in d["permissionDecisionReason"], (cmd, d)
            assert out(cmd, "Bash").get("permissionDecision") != "deny", cmd
        last = audit.last_refusal(None)
        assert last and last["tool"] == "gate", last
        assert out("gate check box", "mcp__terminal__run_in_terminal").get("permissionDecision") is None
        for tool in ("Bash", "Monitor", "mcp__terminal__run_in_terminal"):
            assert out("gate secret box", tool).get("permissionDecision") != "deny", tool


def test_allow_needs_the_effective_right_even_without_the_deny():
    """Defence in depth: the deny of a right waiting for the user's OK (round
    3) runs first, but the allow shapes still check the effective right on
    their own."""
    from gateway import bashparse
    with H.gateway_env() as env:
        env.write_form("[hosts.localhost]\nsudo = true\n")
        vault.save(vault.empty())
        consent.approve_all(env.form())
        env.write_form('[hosts.localhost]\nsudo = true\n\n[hosts.newbox]\n'
                       'address = "u@new.example.com"\nssh = true\n')
        form = env.form()
        eff = consent.compute(form, vault.load())
        st = bashparse.parse("ssh newbox uptime")[0][0]
        assert hooks_bash._stage_allowed(st, form, eff, ["/tmp"], mode="auto") is False
        st = bashparse.parse("sudo ls")[0][0]
        roots = hooks_bash._read_roots("/tmp")       # ls reads /tmp, a temp folder
        assert hooks_bash._stage_allowed(st, form, eff, ["/tmp"], roots=roots, mode="auto") is True
        # PLAN-0.11 §2: no mode (the modeless rule) never allows
        assert hooks_bash._stage_allowed(st, form, eff, ["/tmp"], roots=roots) is False
