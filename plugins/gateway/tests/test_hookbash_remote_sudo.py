"""The approval hook and remote sudo (SPEC 8 steps 3-5 with SPEC 9.3), found
by the e2e suite (tests/e2e): `ssh HOST sudo CMD` was allowed in auto mode
whatever the host's sudo right, so

- sudo = false: the hook allowed it and only the stand-in refused it (SPEC 8
  step 3 says the hook denies: `gateway: sudo is off for builder`);
- sudo = "ask": the hook allowed it, and the ssh stand-in gives a direct
  caller the password for "ask" (relying on Claude Code having asked), so the
  user was never asked before a root command ran on that host.
"""
from __future__ import annotations

import harness as H
from gateway import consent, hooks_bash, vault

FORM = """
[hosts.localhost]
sudo = true

[hosts.box]
address = "u@box.example.com"
ssh  = true
sudo = true

[hosts.builder]
address = "ci@builder.internal"
ssh  = true
sudo = false

[hosts.sudoask]
address = "u@sa.example.com"
ssh  = true
sudo = "ask"
"""


def _out(command: str, mode: str = "auto") -> dict | None:
    return hooks_bash.main({"tool_name": "Bash", "tool_input": {"command": command},
                            "permission_mode": mode, "cwd": "/tmp"})


def _decide(command: str, mode: str = "auto") -> str | None:
    o = _out(command, mode)
    return None if o is None else o["hookSpecificOutput"]["permissionDecision"]


def _setup(env: H.GatewayEnv, form: str = FORM) -> None:
    env.write_form(form)
    vault.save(vault.empty())
    consent.approve_all(env.form())


def test_remote_sudo_on_a_host_with_sudo_off_is_denied_in_every_mode():
    with H.gateway_env() as env:
        _setup(env)
        for mode in ("auto", "default", "bypassPermissions", "plan"):
            for cmd in ("ssh builder sudo systemctl restart nginx", "ssh builder 'sudo -n true'",
                        "ssh builder 'cd /srv && sudo make install'",
                        "ssh -q builder /usr/bin/sudo id",
                        "rsync -a --rsync-path='sudo rsync' ./x builder:/srv/x",
                        "rsync -a --rsync-path 'sudo rsync' ./x builder:/srv/x"):
                o = _out(cmd, mode)
                assert o is not None and o["hookSpecificOutput"]["permissionDecision"] == "deny", \
                    (mode, cmd, o)
                assert o["hookSpecificOutput"]["permissionDecisionReason"].startswith(
                    "gateway: sudo is off for builder (gateway.toml)"), o
        # ssh itself is still fine there, and a `sudo` word that isn't a
        # command is not refused (the stand-in gives it no password)
        assert _decide("ssh builder uptime") == "allow"
        assert _decide("ssh builder echo sudo") is None
        assert _decide("ssh builder echo sudo", "default") is None


def test_remote_sudo_on_a_host_with_sudo_ask_asks():
    with H.gateway_env() as env:
        _setup(env)
        for mode in ("auto", "default", "bypassPermissions"):
            for cmd in ("ssh sudoask sudo apt update", "ssh sudoask 'cd /x && sudo make install'",
                        "ssh sudoask 'sudo -n true'", "ssh sudoask echo sudo"):
                o = _out(cmd, mode)
                assert o is not None and o["hookSpecificOutput"]["permissionDecision"] == "ask", \
                    (mode, cmd, o)
                assert 'sudo (root) on sudoask is set to "ask"' in \
                    o["hookSpecificOutput"]["permissionDecisionReason"], o
        assert _decide("ssh sudoask uptime") == "allow"
        assert _decide("rsync -a ./x sudoask:/srv/x") == "allow"


def test_remote_sudo_started_by_rsync_on_a_sudo_ask_host_is_refused():
    """Round 1 (HIGH): the ssh stand-in gives an "ask" right only to a command
    Claude typed (rsync, scp, sftp and git start their own ssh, which Claude
    Code can't ask about), so remote sudo through rsync on a sudo = "ask" host
    is refused at once in Claude's Bash, with the way to do it instead. The
    user's own Terminal panel (no stand-ins) still gets the prompt."""
    with H.gateway_env() as env:
        _setup(env)
        for mode in ("auto", "default", "bypassPermissions"):
            for cmd in ("rsync -a --rsync-path='sudo rsync' ./x sudoask:/srv/x",
                        'rsync -a ./x "sudoask:/x; sudo id"',
                        'scp -O "sudoask:/x; sudo id" .'):
                o = _out(cmd, mode)
                assert o is not None and o["hookSpecificOutput"]["permissionDecision"] == "deny", \
                    (mode, cmd, o)
                r = o["hookSpecificOutput"]["permissionDecisionReason"]
                assert 'sudo on sudoask is set to "ask"' in r and "ssh sudoask 'sudo CMD'" in r, r
        o = hooks_bash.main({"tool_name": "mcp__terminal__run_in_terminal", "permission_mode": "auto",
                             "tool_input": {"command": "rsync -a --rsync-path='sudo rsync' ./x "
                                                       "sudoask:/srv/x"}, "cwd": "/tmp"})
        assert o["hookSpecificOutput"]["permissionDecision"] == "ask", o
        # a sudo in a remote path on a sudo = false host is denied like ssh's
        assert _decide('rsync -a ./x "builder:/x; sudo id"') == "deny"
        assert _decide('rsync -a ./x "box:/x; sudo id"') is None     # sudo true: no allow either


def test_remote_sudo_with_sudo_true_is_allowed_and_pending_sudo_is_not():
    with H.gateway_env() as env:
        _setup(env)
        assert _decide("ssh box sudo systemctl restart nginx") == "allow"
        assert _decide("rsync -a --rsync-path='sudo rsync' ./x box:/srv/x") == "allow"
        assert _decide("ssh box sudo systemctl restart nginx", "default") is None
        # builder's sudo raised in the form but not approved yet: the stand-in
        # would refuse it, so the hook denies with the next step (round 3)
        env.write_form(FORM.replace('ci@builder.internal"\nssh  = true\nsudo = false',
                                    'ci@builder.internal"\nssh  = true\nsudo = true'))
        assert _decide("ssh builder sudo id") == "deny"
        assert _decide("ssh builder uptime") == "allow"
        # a sudo word that isn't in command position isn't denied, and the
        # remote command isn't vouched for while builder's sudo isn't effective
        assert _decide("ssh builder 'bash -c \"sudo id\"'") is None
