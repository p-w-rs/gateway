"""The Bash hook's private-folder deny with a working directory (SPEC 8 step 2):
bare names resolved from cwd, `cd` chains, globs, recursive readers, option
values and redirect targets. Regressions for the 2026-10 verification."""
from __future__ import annotations

import os

import harness as H
from gateway import consent, hooks_bash, paths, vault

FORM = """
[hosts.localhost]
sudo = true

[hosts.powerslabs]
address = "joshua@10.0.0.5"
ssh  = true
"""


def _decide(command, mode="auto", cwd=None):
    payload = {"tool_name": "Bash", "tool_input": {"command": command}, "permission_mode": mode}
    if cwd:
        payload["cwd"] = str(cwd)
    out = hooks_bash.main(payload)
    return None if out is None else out["hookSpecificOutput"]["permissionDecision"]


def _setup(env):
    env.write_form(FORM)
    vault.save(vault.empty())
    consent.approve_all(env.form())
    priv = paths.private_dir()
    assert (priv / "vault.age").exists()
    if not (priv / "key.txt").exists():
        (priv / "key.txt").write_text("test identity\n")
    return priv


def test_bare_names_inside_the_private_folder_are_denied():
    # The age identity and the vault named by their bare names, with the
    # shell's working directory inside private/: denied in every mode.
    with H.gateway_env() as env:
        priv = _setup(env)
        for cmd in ("cat key.txt", "cat vault.age", "head key.txt", "tail -n 1 key.txt",
                    "grep x key.txt", "wc -c vault.age", "sort key.txt", "cat ./key.txt",
                    "ls", "grep -r x", "cat k*", "echo junk > vault.age",
                    "sudo cat key.txt"):
            for mode in ("auto", "default"):
                assert _decide(cmd, mode, cwd=priv) == "deny", (cmd, mode)


def test_leaving_the_private_folder_is_not_blocked():
    with H.gateway_env() as env:
        priv = _setup(env)
        assert _decide("cd ~", "auto", cwd=priv) == "allow"
        assert _decide("pwd", "auto", cwd=priv) == "allow"


def test_from_the_gateway_folder():
    with H.gateway_env() as env:
        _setup(env)
        gw = paths.home()
        assert _decide("cat private/key.txt", cwd=gw) == "deny"
        assert _decide("cat private/*", cwd=gw) == "deny"
        assert _decide("grep -r x .", cwd=gw) == "deny"
        assert _decide("grep -r x", cwd=gw) == "deny"
        assert _decide("rsync -a . powerslabs:/tmp/x", cwd=gw) == "deny"
        assert _decide("cat key.txt", cwd=gw) == "deny"         # the v2 key's place
        assert _decide("cat gateway.toml", cwd=gw) == "allow"
        assert _decide("ls", cwd=gw) == "allow"                 # names only


def test_bare_names_elsewhere_are_fine():
    with H.gateway_env() as env:
        _setup(env)
        proj = env.root / "proj"
        proj.mkdir()
        assert _decide("cat key.txt", cwd=proj) == "allow"
        assert _decide("grep -r x", cwd=proj) == "allow"
        assert _decide("grep -r x .", cwd=proj) == "allow"
        assert _decide("rsync -a . powerslabs:/srv/", cwd=proj) == "allow"


def test_cd_chains_are_followed():
    with H.gateway_env() as env:
        _setup(env)
        proj = env.root / "proj"
        proj.mkdir()
        for cmd in ("cd ~/.config/gateway && cat private/key.txt",
                    "cd ~/.config/gateway; cd private; cat key.txt",
                    "cd ~/.config && cd gateway/private && head vault.age",
                    "cd ~/.config/gateway/private && ls",
                    "cd && cat .config/gateway/private/key.txt",
                    "cd ~/.config && grep -r x ."):
            assert _decide(cmd, cwd=proj) == "deny", cmd
        # an unknown target: nothing after it can be vouched for (no allow)
        for cmd in ("cd - && cat key.txt", "cd $D && cat key.txt", "popd && cat key.txt",
                    "pushd +1 && cat key.txt"):
            assert _decide(cmd, cwd=proj) is None, cmd


def test_globs_option_values_and_redirect_targets():
    with H.gateway_env() as env:
        _setup(env)
        proj = env.root / "proj"
        proj.mkdir()
        for cmd in ("cat ~/.config/gateway/*/key.txt", "cat ~/.config/gateway/priv?te/vault.age",
                    "cat ~/.config/gateway/[p]rivate/key.txt", "head ~/.config/*/private/key.txt",
                    "grep --file=~/.config/gateway/private/key.txt x f",
                    "echo x > ~/.config/gateway/private/vault.age",
                    "ssh powerslabs true > ~/.config/gateway/private/x",
                    "rsync -a ~/.config/gateway/ powerslabs:/tmp/g/",
                    "scp -r ~/.conf* powerslabs:"):
            assert _decide(cmd, cwd=proj) == "deny", cmd
        # case variants of the folder (macOS volumes ignore case)
        assert _decide("cat ~/.config/GATEWAY/*/key.txt", cwd=proj) == "deny"


def test_parameter_expansion_defaults_are_checked():
    # verifier 2026-10 (LOW): `${x:-PATH}` expands to PATH when x is unset,
    # so the literal default is checked like any other word.
    with H.gateway_env() as env:
        _setup(env)
        proj = env.root / "proj"
        proj.mkdir()
        for cmd in ("cat ${x:-~/.config/gateway/private/key.txt}",
                    'cat "${x-$HOME/.config/gateway/private/vault.age}"',
                    "cat ${x:=~/.config/gateway/private/key.txt}",
                    "cat ${x:+~/.config/gateway/private/key.txt}",
                    "head ${D:-~/.config/gateway}/private/key.txt"):
            for mode in ("auto", "default"):
                assert _decide(cmd, mode, cwd=proj) == "deny", (cmd, mode)
        # an unrelated default is no decision (an expansion is never vouched for)
        assert _decide("cat ${x:-notes.txt}", cwd=proj) is None


def test_symlinked_alias_of_the_gateway_folder():
    # verifier 2026-10 (LOW): `ln -s ~/.config A; ln -s A/gateway B; cat
    # B/private/key.txt` spells no gateway path. The hook resolves the link and
    # denies; the sh prefilter forwards it because of the `key.txt` trigger
    # (test_hookbash_prefilter). Reads that spell no trigger at all can't be
    # caught by a text prefilter (documented in docs/modules/sudo.md).
    with H.gateway_env() as env:
        priv = _setup(env)
        a = env.root / "a"
        b = env.root / "b"
        a.symlink_to(priv.parent.parent)          # ~/.config
        b.symlink_to(a / "gateway")
        for cmd in (f"cat {b}/private/key.txt", f"cp {b}/private/key.txt /tmp/stolen",
                    f"head -c 100 {b}/private/key.txt", f"cat {b}/private/vault.age",
                    f"cat {a}/gateway/private/key.txt", f"tar c {a}"):
            for mode in ("auto", "default"):
                assert _decide(cmd, mode) == "deny", (cmd, mode)


def test_session_transcripts_are_denied():
    """phase B request (ux): Claude Code's session transcripts can hold the
    one-time codes the gateway shows the user; reading them (or searching a
    folder that holds them) is denied, tool-results/ next to them isn't."""
    with H.gateway_env():
        _setup_transcripts = paths.user_home() / ".claude" / "projects" / "-p"
        (_setup_transcripts / "s1" / "tool-results").mkdir(parents=True)
        (_setup_transcripts / "s1.jsonl").write_text("{}\n")
        (_setup_transcripts / "s1" / "tool-results" / "o.txt").write_text("out\n")
        for cmd in ("cat ~/.claude/projects/-p/s1.jsonl", "tail -n 5 ~/.claude/projects/-p/*",
                    "grep -r code ~/.claude", "grep code ~/.claude/projects/-p/s1.jsonl",
                    "rg 12345678 ~/.claude/projects"):
            for mode in ("auto", "default"):
                assert _decide(cmd, mode) == "deny", (cmd, mode)
        assert _decide("cat s1.jsonl", cwd=_setup_transcripts) == "deny"
        assert _decide("cat ~/.claude/projects/-p/s1/tool-results/o.txt") != "deny"
        assert _decide("ls ~/.claude/projects/-p") != "deny", "names only"


def test_subagent_transcripts_are_denied_too():
    """Round 3: a subagent's hook systemMessages (the one-time code among
    them) go to <project>/<session>/subagents/agent-<id>.jsonl, which the
    `<projects>/<project>/<name>.jsonl` rule missed."""
    with H.gateway_env():
        proj = paths.user_home() / ".claude" / "projects" / "-p"
        sub = proj / "s1" / "subagents"
        sub.mkdir(parents=True)
        (proj / "s1" / "tool-results").mkdir()
        (sub / "agent-a4b0.jsonl").write_text('{"systemMessage":"code 1234-5678"}\n')
        (proj / "s1" / "tool-results" / "o.txt").write_text("out\n")
        for cmd in ("cat ~/.claude/projects/-p/s1/subagents/agent-a4b0.jsonl",
                    "tail -n 3 ~/.claude/projects/-p/s1/subagents/*",
                    "grep -r code ~/.claude/projects/-p/s1",
                    "grep -r code ~/.claude/projects/-p/s1/subagents",
                    "rg 1234 ~/.claude/projects/-p/s1"):
            for mode in ("auto", "default"):
                assert _decide(cmd, mode) == "deny", (cmd, mode)
        assert _decide("cat agent-a4b0.jsonl", cwd=sub) == "deny"
        assert _decide("cat ~/.claude/projects/-p/s1/tool-results/o.txt") != "deny"
        assert _decide("grep -r out ~/.claude/projects/-p/s1/tool-results") != "deny"
        # the payload's own transcript_path may be a subagent's: its config dir counts
        other = paths.user_home() / "cfg" / "projects" / "q" / "s9" / "subagents"
        other.mkdir(parents=True)
        (other / "agent-x.jsonl").write_text("{}\n")
        out = hooks_bash.main({"tool_name": "Bash", "permission_mode": "auto",
                               "tool_input": {"command": f"cat {other / 'agent-x.jsonl'}"},
                               "transcript_path": str(other / "agent-x.jsonl")})
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_workflow_journals_are_readable_from_bash_too():
    """A Workflow run's journal.jsonl (agent results) is readable by Bash
    like any file; the run's agent transcripts, a glob or recursive reader
    that reaches them, and journal-named links to a transcript are not."""
    with H.gateway_env():
        proj = paths.user_home() / ".claude" / "projects" / "-p"
        run_dir = proj / "s1" / "subagents" / "workflows" / "wf_c8cc9141-9d8"
        run_dir.mkdir(parents=True)
        (proj / "s1.jsonl").write_text('{"systemMessage":"code 1234-5678"}\n')
        (run_dir / "journal.jsonl").write_text('{"result":"done"}\n')
        (run_dir / "agent-a1.jsonl").write_text('{"systemMessage":"code 1234-5678"}\n')
        j = "~/.claude/projects/-p/s1/subagents/workflows/wf_c8cc9141-9d8/journal.jsonl"
        for cmd in (f"cat {j}", f"tail -n 20 {j}", f"grep result {j}", f"wc -l {j}",
                    "cat ~/.claude/projects/-p/s1/subagents/workflows/*/journal.jsonl"):
            for mode in ("auto", "default"):
                assert _decide(cmd, mode) != "deny", (cmd, mode)
        assert _decide(f"tail -n 20 {j}") == "allow"
        assert _decide("cat journal.jsonl", cwd=run_dir) != "deny"
        for cmd in ("cat ~/.claude/projects/-p/s1/subagents/workflows/wf_c8cc9141-9d8/agent-a1.jsonl",
                    "cat ~/.claude/projects/-p/s1/subagents/workflows/wf_c8cc9141-9d8/*.jsonl",
                    "grep -r code ~/.claude/projects/-p/s1/subagents/workflows/wf_c8cc9141-9d8",
                    "grep -r code ~/.claude/projects/-p/s1/subagents/workflows",
                    "cat ~/.claude/projects/-p/s1/journal.jsonl"):
            assert _decide(cmd) == "deny", cmd
        assert _decide("grep -r code .", cwd=run_dir) == "deny"
        other = run_dir.parent / "wf_link"
        other.mkdir()
        os.link(proj / "s1.jsonl", other / "journal.jsonl")
        assert _decide("cat ~/.claude/projects/-p/s1/subagents/workflows/wf_link/journal.jsonl") == "deny"
