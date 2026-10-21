"""Rolled back (DECISIONS, "Rolled back"): review round 4 denied a Bash call
with `run_in_background: true` unless it ended in `2>&1 | gate scrub`, and
round 3 a Monitor command unless it ended in `| gate scrub`. The gateway no
longer changes how Claude's ordinary commands run: both are judged like any
Bash command (the same denies, asks and allows), `gate scrub` stays an
allowed, optional filter, and pre_bash.sh treats them by the same word list.
Their raw output (a background task's notice, Monitor's lines) is a known
limit; the prompt hook still holds back a task notification that quotes a
stored value or a token shape (test_ux_hooks).
"""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path

import harness as H
from gateway import consent, hooks_bash, vault

PLAIN = '[hosts.localhost]\nsudo = true\n[hosts.box]\naddress = "u@box.example.com"\n'


def _decide(command, background=None, mode="auto", tool="Bash"):
    ti = {"command": command}
    if background is not None:
        ti["run_in_background"] = background
    out = hooks_bash.main({"tool_name": tool, "tool_input": ti, "permission_mode": mode,
                           "cwd": "/tmp"})
    if out is None:
        return None, ""
    r = out["hookSpecificOutput"]
    return r["permissionDecision"], r["permissionDecisionReason"]


def _approve(env):
    env.write_form(PLAIN)
    vault.save(vault.empty())
    consent.approve_all(env.form())


CASES = (
    # (command, decision for Bash in the foreground, in the background and as Monitor)
    ("cat notes.txt; printf 'Continue? [y/N] '; sleep 70", None),
    ("ssh box tail -f /var/log/syslog", "allow"),
    ("ssh box uptime", "allow"),
    ("tail -f app.log", "allow"),
    ("tail -f app.log | grep --line-buffered ERROR", "allow"),
    ("rsync -a dist/ box:/srv/app/", "allow"),
    ("while true; do cat x; sleep 1; done", None),
    ("make 2>&1 | tee build.log", None),
    ("tail -f app.log | gate scrub", "allow"),                 # the optional filter, still allowed
    ("ssh box tail -f /var/log/syslog 2>&1 | gate scrub", "allow"),
)


def test_background_and_monitor_commands_are_judged_like_any_bash_command():
    with H.gateway_env() as env:
        _approve(env)
        assert vault.exists()
        for cmd, want in CASES:
            got = {(bg, tool): _decide(cmd, background=bg, tool=tool)
                   for bg, tool in ((None, "Bash"), (False, "Bash"), (True, "Bash"), (None, "Monitor"))}
            for k, (d, why) in got.items():
                assert d == want, (cmd, k, d, why)
                assert "gate scrub`" not in why, (cmd, k, why)
        # the denies still apply, with their own reasons
        for bg, tool in ((True, "Bash"), (None, "Monitor")):
            d, why = _decide("curl http://x", background=bg, tool=tool)
            assert d == "deny" and "http tool" in why, (tool, why)
            d, why = _decide("cat ~/.config/gateway/private/key.txt", background=bg, tool=tool)
            assert d == "deny" and "private keys" in why, (tool, why)
        # outside auto mode: no allow, and no deny either
        assert _decide("tail -f app.log", background=True, mode="default")[0] is None
        assert _decide("tail -f app.log", mode="default", tool="Monitor")[0] is None


def test_pre_bash_judges_background_and_monitor_calls_by_the_word_list():
    pre = H.PLUGIN / "hooks" / "pre_bash.sh"
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as td:
        d = Path(td)
        (d / "pre_bash.sh").write_text(pre.read_text())
        marker = d / "launched"
        (d / "launch.sh").write_text(f"#!/bin/sh\n: > {str(marker)!r}\ncat > /dev/null\n")
        for tool, ti, want in (
                ("Bash", {"command": "cat notes.txt", "run_in_background": True}, False),
                ("Bash", {"command": "cat notes.txt", "run_in_background": False}, False),
                ("Bash", {"command": "cat notes.txt"}, False),
                ("Monitor", {"command": "tail -f app.log", "description": "log"}, False),
                ("Bash", {"command": "ssh box uptime", "run_in_background": True}, True),
                ("Monitor", {"command": "tail -f app.log | gate scrub"}, True),
                ("Monitor", {"command": "curl -s http://x"}, True)):
            for sep in ((",", ":"), (", ", ": ")):
                marker.unlink(missing_ok=True)
                payload = json.dumps({"tool_name": tool, "tool_input": ti}, separators=sep)
                # the managed prefix is active (the mod's session): the word list decides
                env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CODE_SHELL_PREFIX"}
                env["CLAUDE_CODE_SHELL_PREFIX"] = str(d / "gate-sh")
                r = subprocess.run(["/bin/sh", str(d / "pre_bash.sh")], input=payload,
                                   capture_output=True, text=True, timeout=15, env=env)
                assert r.returncode == 0 and marker.exists() == want, (tool, ti, sep, r.stderr)
