"""The test fakes themselves (fake sudo, fake dialog, v2 builder) and run.py's
dispatch and failure policies."""
from __future__ import annotations

import io
import json
import os
import sys

import harness as H
from gateway import paths

sys.path.insert(0, str(H.PLUGIN))
import run  # noqa: E402


# ---------------------------------------------------------------------------
# fake sudo
# ---------------------------------------------------------------------------


def test_fake_sudo_password_paths():
    with H.gateway_env() as env:
        s = H.make_fake_sudo(env.root / "sudo", password="pw-right")
        r = s.run("-n", "true")
        assert r.returncode == 1 and "a password is required" in r.stderr
        r = s.run("-S", "-p", "", "echo", "hi", input="pw-right\n")
        assert r.returncode == 0 and r.stdout == "hi\n"
        r = s.run("-n", "echo", "cached")
        assert r.returncode == 0 and r.stdout == "cached\n", "the timestamp is cached"
        assert s.run("-k").returncode == 0
        assert s.run("-n", "true").returncode == 1, "-k forgets it"
        r = s.run("-S", "-v", input="wrong\npw-right\n")
        assert r.returncode == 0 and r.stderr.count("Sorry, try again.") == 1
        s.run("-K")
        r = s.run("-S", "true", input="a\nb\nc\n")
        assert r.returncode == 1 and r.stderr.count("Sorry, try again.") == 3
        assert "3 incorrect password attempts" in r.stderr
        s.run("-K")
        r = s.run("-kS", "-u", "root", "env", input="pw-right\n")
        assert r.returncode == 0 and "FAKE_SUDO_AS=root" in r.stdout and "SUDO_COMMAND=env" in r.stdout
        log = s.log()
        assert log[1]["how"] == "S" and log[-1]["code"] == 0


def test_fake_sudo_askpass_and_nopasswd():
    with H.gateway_env() as env:
        s = H.make_fake_sudo(env.root / "sudo", password="pw-ask")
        ap = env.root / "askpass"
        ap.write_text("#!/bin/sh\necho pw-ask\n")
        os.chmod(ap, 0o755)
        base = {"PATH": "/usr/bin:/bin"}
        r = s.run("-A", "true", env=base)
        assert r.returncode == 1 and "no askpass program" in r.stderr
        r = s.run("-A", "echo", "ok", env={**base, "SUDO_ASKPASS": str(ap)})
        assert r.returncode == 0 and r.stdout == "ok\n" and s.log()[-1]["how"] == "A"
        r = s.run("true", env=base)
        assert r.returncode == 0, "cached"
        s.run("-K")
        r = s.run("true", env=base)
        assert r.returncode == 1 and "terminal is required" in r.stderr
        n = H.make_fake_sudo(env.root / "sudo2", nopasswd=True)
        assert n.run("-n", "true").returncode == 0


def test_fake_dialog_outcomes():
    with H.gateway_env() as env:
        d = H.FakeDialog(env.root / "dlg", [{"outcome": "ok", "value": "s3cret"}])
        d.add("cancelled")
        d.add("unavailable")
        d.add("timeout", sleep=0.05)
        import subprocess
        r = [subprocess.run([str(d.script), "secret", "Gateway", "msg", ""], capture_output=True, text=True)
             for _ in range(5)]
        assert (r[0].returncode, r[0].stdout) == (0, "s3cret\n")
        assert [x.returncode for x in r[1:]] == [1, 3, 1, 1]
        calls = d.calls()
        assert [c["outcome"] for c in calls] == ["ok", "cancelled", "unavailable", "timeout", "cancelled"]
        assert calls[0]["kind"] == "secret" and calls[0]["message"] == "msg"
        env.o.dialog = str(d.script)  # how popup.py (phase B) finds it


def test_v2_builder_round_trip():
    with H.gateway_env():
        paths.ensure_home()
        data = {"version": 2, "secrets": {"A": {"value": "x" * 10, "hosts": ["a.example.com"]}},
                "sudo": {}, "accounts": {}}
        H.write_v2_vault(paths.home(), data)
        assert paths.v2_store_path().exists() and paths.v2_key_path().exists()
        back = H.read_v2_vault(paths.home())
        assert back["secrets"] == data["secrets"] and back["version"] == 2
        assert b"xxxxxxxxxx" not in paths.v2_store_path().read_bytes()


# ---------------------------------------------------------------------------
# run.py
# ---------------------------------------------------------------------------


def _hook(mode: str, payload: dict) -> tuple[int, str, str]:
    old_in, old_out, old_err = sys.stdin, sys.stdout, sys.stderr
    sys.stdin = io.StringIO(json.dumps(payload))
    sys.stdout, sys.stderr = io.StringIO(), io.StringIO()
    try:
        code = run.run_hook(mode)
        return code, sys.stdout.getvalue(), sys.stderr.getvalue()
    finally:
        sys.stdin, sys.stdout, sys.stderr = old_in, old_out, old_err


def _decision(out: str) -> str | None:
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out.strip() else None


def _files(payload: dict) -> str | None:
    code, out, _ = _hook("hook-files", payload)
    assert code == 0
    return _decision(out)


def _setup_private():
    from gateway import vault
    paths.ensure_private()
    vault.save(vault.empty())         # private/key.txt and vault.age exist
    (paths.private_dir() / "backups").mkdir(exist_ok=True)
    (paths.private_dir() / "backups" / "key-v2.txt").write_text("AGE-SECRET-KEY-1TEST\n")


def test_hook_files_placeholder_guard():
    with H.gateway_env():
        assert _files({"tool_name": "Read", "tool_input": {"file_path": str(paths.key_path())}}) == "deny"
        assert _files({"tool_name": "Glob",
                       "tool_input": {"pattern": str(paths.private_dir()) + "/*"}}) == "deny"
        assert _files({"tool_name": "Edit", "tool_input": {"file_path": str(paths.form_path())}}) is None


def test_hook_files_case_variants_on_case_insensitive_volumes():
    with H.gateway_env() as env:
        _setup_private()
        home = paths.home()
        variants = [str(home).replace(".config/gateway", ".config/GATEWAY") + "/private/key.txt",
                    str(home) + "/PRIVATE/key.txt", str(home) + "/Private/vault.AGE",
                    str(home) + "/KEY.txt", str(home) + "/./private/../private/key.txt"]
        for v in variants:
            assert _files({"tool_name": "Read", "tool_input": {"file_path": v}}) == "deny", v
        assert _files({"tool_name": "Write", "tool_input": {"file_path": str(home) + "/PRIVATE/new.txt"}}) == "deny"
        del env


def test_hook_files_case_variant_before_private_exists():
    # Fresh install: private/ doesn't exist yet. Writing a planted key there in
    # any spelling is still refused (only the case-insensitive spelling check
    # can tell; there is no file to compare).
    with H.gateway_env():
        paths.ensure_home()
        assert not paths.private_dir().exists()
        p = str(paths.home()).replace(".config/gateway", ".config/GATEWAY") + "/PRIVATE/key.txt"
        assert _files({"tool_name": "Write", "tool_input": {"file_path": p}}) == "deny"


def test_hook_files_hard_link_to_a_private_file():
    with H.gateway_env() as env:
        _setup_private()
        other = env.root / "elsewhere"
        other.mkdir()
        os.link(paths.key_path(), other / "innocent.txt")
        assert _files({"tool_name": "Read", "tool_input": {"file_path": str(other / "innocent.txt")}}) == "deny"
        assert _files({"tool_name": "Read", "tool_input": {"file_path": str(other)}}) is None


def test_hook_files_grep_from_a_parent_is_refused():
    with H.gateway_env() as env:
        _setup_private()
        home = paths.home()
        for root in (str(home), str(home.parent), str(env.user_home), "/", str(home) + "/",
                     str(home).replace(".config/gateway", ".CONFIG/Gateway")):
            assert _files({"tool_name": "Grep", "tool_input": {"pattern": "AGE-SECRET", "path": root}}) == "deny", root
        # no path: the session's cwd is the search root
        assert _files({"tool_name": "Grep", "tool_input": {"pattern": "x"}, "cwd": str(env.user_home)}) == "deny"
        proj = env.user_home / "project"
        proj.mkdir()
        assert _files({"tool_name": "Grep", "tool_input": {"pattern": "x"}, "cwd": str(proj)}) is None
        assert _files({"tool_name": "Grep", "tool_input": {"pattern": "x", "path": str(proj)}}) is None
        assert _files({"tool_name": "Read", "tool_input": {"file_path": str(home / "gateway.toml")}}) is None


def test_hook_files_glob_patterns_reaching_private():
    with H.gateway_env() as env:
        _setup_private()
        home = paths.home()
        deny = [(str(env.user_home), "**/key.txt"), (str(env.user_home), ".config/gateway/*/*"),
                (str(home), "**/*.txt"), (str(home), "private/**"), (str(home), "{private,x}/*"),
                (str(home), "*/vault.age")]
        for base, pat in deny:
            assert _files({"tool_name": "Glob", "tool_input": {"pattern": pat, "path": base}}) == "deny", (base, pat)
        allow = [(str(env.user_home), "**/*.py"), (str(home), "*"), (str(home), "*.toml"),
                 (str(env.user_home / "project"), "**/*")]
        for base, pat in allow:
            assert _files({"tool_name": "Glob", "tool_input": {"pattern": pat, "path": base}}) is None, (base, pat)


def test_hook_files_ratchets_before_a_form_edit():
    # Narrow, then raise again in the same session: the second edit's file
    # guard persists the first narrowing, so the raise needs the user's OK.
    from gateway import consent, vault
    with H.gateway_env() as env:
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\nsudo = "ask"\n')
        vault.save(vault.empty())
        consent.approve_all(env.form())
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\nsudo = false\n')
        assert _files({"tool_name": "Edit", "tool_input": {"file_path": str(paths.form_path())}}) is None
        assert vault.load()["approved"]["rights"]["hosts"]["box"]["sudo"] is False
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\nsudo = "ask"\n')
        eff = consent.compute(env.form(), vault.load())
        assert eff.hosts["box"].sudo is False and "box" in eff.pending_names()


def test_hook_failure_policies():
    from gateway import hooks_files, hooks_prompt, hooks_bash
    with H.gateway_env():
        saved = (hooks_files.main, hooks_prompt.main, hooks_bash.main)

        def boom(payload):
            raise RuntimeError("x")
        hooks_files.main = hooks_prompt.main = hooks_bash.main = boom
        try:
            code, out, err = _hook("hook-files", {})
            assert code == 2 and "blocked to be safe" in err, "the file guard fails closed"
            code, out, _ = _hook("hook-prompt", {})
            assert json.loads(out)["decision"] == "block", "the prompt hook fails closed"
            code, out, _ = _hook("hook-bash", {})
            assert code == 0 and out == "", "the approval hook fails open"
        finally:
            hooks_files.main, hooks_prompt.main, hooks_bash.main = saved
        for mode in ("hook-bash", "hook-post", "hook-prompt", "hook-filechanged"):
            code, out, _ = _hook(mode, {"tool_name": "Bash", "tool_input": {"command": "ls"}})
            assert code == 0 and out == "", mode


def test_shims_refuse_and_never_run_the_system_tool():
    """A stand-in that can't serve (unknown host, no account, no fake sudo)
    refuses; the user's own ssh/gh/sudo found on PATH never runs instead."""
    with H.gateway_env() as env:
        fake = env.root / "sysbin"
        fake.mkdir()
        marker = env.root / "ran"
        for tool in ("ssh", "gh", "sudo", "hf", "asiml"):
            (fake / tool).write_text(f"#!/bin/sh\necho {tool} >> '{marker}'\n")
            os.chmod(fake / tool, 0o755)
        old = os.environ.get("PATH")
        os.environ["PATH"] = f"{fake}:/usr/bin:/bin"
        err = io.StringIO()
        saved = sys.stderr
        sys.stderr = err
        try:
            for tool in ("ssh", "sudo", "asiml"):
                assert run.run_shim(tool, ["x"]) != 0, tool
            assert run.run_shim("nonsense", []) == 2
        finally:
            sys.stderr = saved
            os.environ["PATH"] = old or ""
        assert "isn't available in this build yet" not in err.getvalue()
        assert "x isn't in gateway.toml" in err.getvalue(), err.getvalue()
        assert not marker.exists(), "the user's own ssh/gh/sudo must never run in their place"


def test_mcp_serves_http_and_download():
    with H.gateway_env() as env:
        msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": "2025-06-18", "capabilities": {}}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                 "params": {"name": "run_privileged", "arguments": {"argv": ["id"]}}},
                {"jsonrpc": "2.0", "id": 4, "method": "nope"}]
        r = H.run_py(env, "--test", "mcp", timeout=30,
                     input_text="\n".join(json.dumps(m) for m in msgs) + "\n")
        assert r.returncode == 0, r.stderr
        # tools/call runs on worker threads: answers are matched by id
        out = {o["id"]: o for o in (json.loads(l) for l in r.stdout.splitlines())}
        assert sorted(out) == [1, 2, 3, 4], out
        assert "tools" in out[1]["result"]["capabilities"]
        tools = out[2]["result"]["tools"]
        assert [t["name"] for t in tools] == ["http", "download", "host_inspect", "terminal_open", "terminal_read", "terminal_send", "terminal_resize", "terminal_signal", "terminal_close", "terminal_list", "job_start", "job_status", "job_tail", "job_signal", "job_list", "host_runtime"], \
        "no v2 tools (run_privileged, ...)"
        assert all(t.get("_meta", {}).get("anthropic/alwaysLoad") is True for t in tools)
        assert out[3]["result"]["isError"] is True and out[4]["error"]["code"] == -32601


def test_dispatch_unknown_mode_and_subprocess_hooks():
    with H.gateway_env() as env:
        saved, sys.stderr = sys.stderr, io.StringIO()
        try:
            assert run.main(["bogus"]) == 2
        finally:
            sys.stderr = saved
        r = H.run_py(env, "--test", "hook-files", payload={"tool_name": "Read",
                                                           "tool_input": {"file_path": str(paths.vault_path())}})
        assert r.returncode == 0 and json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
        r = H.run_py(env, "--test", "hook-bash", payload={"tool_input": {"command": "sudo ls"}})
        # no form yet: sudo on this computer is "ask" by default, so Claude Code asks
        assert r.returncode == 0 and \
            json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask", r.stdout
        env.write_form("[hosts.localhost]\nsudo = false\n")
        r = H.run_py(env, "--test", "hook-bash", payload={"tool_input": {"command": "sudo ls"}})
        assert r.returncode == 0 and \
            json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny", r.stdout


def test_stand_in_triggers_migration():
    with H.gateway_env() as env:
        paths.ensure_home()
        H.write_v2_vault(paths.home(), {"version": 2, "secrets": {"K": {"value": "v" * 16, "hosts": ["k.example.com"]}},
                                        "sudo": {}, "accounts": {}})
        old = os.environ.get("PATH")
        os.environ["PATH"] = str(env.root / "empty")
        saved, sys.stderr = sys.stderr, io.StringIO()
        try:
            assert run.run_shim("asiml", ["status"]) != 0
            msg = sys.stderr.getvalue()
        finally:
            sys.stderr = saved
            os.environ["PATH"] = old or ""
        assert "migrated your 0.6 vault" in msg and paths.vault_path().exists()
        assert not paths.v2_store_path().exists()


def test_gate_entry_drops_proxy_and_ca_variables():
    """phase B request (ux): `gate` (in Claude's Bash) checks tokens the user
    just typed; a proxy or CA from the environment never gets to see them.
    `gate with` keeps the environment for its child (SPEC 9.7)."""
    keys = run.GATE_ENV_DROP
    saved = {k: os.environ.get(k) for k in keys}
    try:
        for k in keys:
            os.environ[k] = "http://127.0.0.1:9/evil"
        run._gate_env(["with", "openai", "--", "env"])
        assert all(os.environ.get(k) for k in keys), "gate with keeps them"
        run._gate_env(["check", "box"])
        assert not [k for k in keys if k in os.environ]
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _transcripts():
    proj = paths.user_home() / ".claude" / "projects" / "-Users-me-proj"
    (proj / "sess1" / "tool-results").mkdir(parents=True)
    (proj / "sess1.jsonl").write_text('{"type":"attachment","stdout":"code 12345678"}\n')
    (proj / "sess1" / "tool-results" / "big.txt").write_text("a large tool output\n")
    return proj


def test_hook_files_session_transcripts_are_not_read():
    """phase B request (ux): transcripts can hold the one-time codes the
    gateway shows the user (hook systemMessages are recorded there)."""
    with H.gateway_env() as env:
        proj = _transcripts()
        t = str(proj / "sess1.jsonl")
        assert _files({"tool_name": "Read", "tool_input": {"file_path": t}}) == "deny"
        assert _files({"tool_name": "Read", "tool_input": {
            "file_path": "~/.claude/projects/-Users-me-proj/sess1.jsonl"}}) == "deny"
        assert _files({"tool_name": "Read", "tool_input": {"file_path": "sess1.jsonl"},
                       "cwd": str(proj)}) == "deny"
        if os.path.exists(t.swapcase()):      # a case-insensitive volume (macOS)
            assert _files({"tool_name": "Read", "tool_input": {"file_path": t.swapcase()}}) == "deny"
        for root in (proj, proj.parent, paths.user_home() / ".claude"):
            assert _files({"tool_name": "Grep", "tool_input": {"pattern": "x", "path": str(root)}}) \
                == "deny", root
        # persisted tool outputs stay readable; listing names is fine
        big = proj / "sess1" / "tool-results" / "big.txt"
        assert _files({"tool_name": "Read", "tool_input": {"file_path": str(big)}}) is None
        assert _files({"tool_name": "Grep", "tool_input": {
            "pattern": "x", "path": str(proj / "sess1" / "tool-results")}}) is None
        # round 3: a session folder holds its subagents' transcripts
        assert _files({"tool_name": "Grep", "tool_input": {
            "pattern": "x", "path": str(proj / "sess1")}}) == "deny"
        assert _files({"tool_name": "Glob", "tool_input": {
            "pattern": "**/*.jsonl", "path": str(proj.parent)}}) is None
        # another config dir, named by the payload's own transcript_path
        other = env.root / "cfg" / "projects" / "p"
        other.mkdir(parents=True)
        (other / "s.jsonl").write_text("{}\n")
        assert _files({"tool_name": "Read", "tool_input": {"file_path": str(other / "s.jsonl")},
                       "transcript_path": str(other / "s.jsonl")}) == "deny"
        assert _files({"tool_name": "Read", "tool_input": {
            "file_path": str(env.root / "cfg" / "notes.jsonl")}}) is None


def test_hook_files_subagent_transcripts_are_not_read():
    """Round 3: a subagent's transcript (<session>/subagents/agent-<id>.jsonl)
    holds the hook systemMessages of its tool calls, a one-time code among
    them; Read, Grep from the session or subagents folder, and Glob-then-Read
    are refused, tool-results/ stays readable."""
    with H.gateway_env():
        proj = _transcripts()
        sub = proj / "sess1" / "subagents"
        sub.mkdir()
        (sub / "agent-a1.jsonl").write_text('{"systemMessage":"code 1234-5678"}\n')
        t = str(sub / "agent-a1.jsonl")
        assert _files({"tool_name": "Read", "tool_input": {"file_path": t}}) == "deny"
        assert _files({"tool_name": "Read", "tool_input": {"file_path": "agent-a1.jsonl"},
                       "cwd": str(sub)}) == "deny"
        for root in (sub, proj / "sess1"):
            assert _files({"tool_name": "Grep", "tool_input": {"pattern": "x", "path": str(root)}}) \
                == "deny", root
        assert _files({"tool_name": "Grep", "tool_input": {"pattern": "x"}, "cwd": str(sub)}) == "deny"
        assert _files({"tool_name": "Read", "tool_input": {
            "file_path": str(proj / "sess1" / "tool-results" / "big.txt")}}) is None
        assert paths.is_transcript(t) and not paths.is_transcript(
            str(proj / "sess1" / "tool-results" / "x.jsonl"))
        assert paths.holds_transcripts(str(proj / "sess1"))
        assert not paths.holds_transcripts(str(proj / "sess1" / "tool-results"))


def _workflow_run():
    """<projects>/<project>/<session>/subagents/workflows/<run>/ with the run's
    journal (agent results) and an agent transcript next to it."""
    proj = _transcripts()
    run_dir = proj / "sess1" / "subagents" / "workflows" / "wf_1b365f24-3a3"
    run_dir.mkdir(parents=True)
    (run_dir / "journal.jsonl").write_text('{"type":"result","agent":"a1","result":"done"}\n')
    (run_dir / "agent-a1.jsonl").write_text('{"systemMessage":"code 1234-5678"}\n')
    return proj, run_dir


def test_hook_files_workflow_journals_are_readable():
    """Claude Code's Workflow tool tells Claude to read a run's journal.jsonl
    (agent results, no hook messages) to diagnose the run: it is readable,
    by its exact name at its exact place; the run's agent transcripts next
    to it, a Grep over the run folder and anything that only looks like a
    journal stay refused."""
    with H.gateway_env():
        proj, run_dir = _workflow_run()
        j = run_dir / "journal.jsonl"
        tilde = "~/.claude/projects/-Users-me-proj/sess1/subagents/workflows/wf_1b365f24-3a3/journal.jsonl"
        for ti, cwd in (({"file_path": str(j)}, None), ({"file_path": tilde}, None),
                        ({"file_path": "journal.jsonl"}, str(run_dir))):
            pl = {"tool_name": "Read", "tool_input": ti}
            if cwd:
                pl["cwd"] = cwd
            assert _files(pl) is None, ti
        assert _files({"tool_name": "Grep", "tool_input": {"pattern": "result", "path": str(j)}}) is None
        assert not paths.is_transcript(j) and not paths.holds_transcripts(j)
        # the run's agent transcripts and searches over the folder: refused
        assert _files({"tool_name": "Read", "tool_input": {
            "file_path": str(run_dir / "agent-a1.jsonl")}}) == "deny"
        for root in (run_dir, run_dir.parent, proj / "sess1" / "subagents"):
            assert _files({"tool_name": "Grep", "tool_input": {"pattern": "x", "path": str(root)}}) \
                == "deny", root
        assert _files({"tool_name": "Grep", "tool_input": {"pattern": "x"}, "cwd": str(run_dir)}) == "deny"
        # only the exact name at the exact place
        fakes = [proj / "sess1" / "journal.jsonl", proj / "journal.jsonl",
                 proj / "sess1" / "subagents" / "journal.jsonl",
                 proj / "sess1" / "subagents" / "workflows" / "journal.jsonl",
                 run_dir / "deeper" / "journal.jsonl", run_dir / "journal2.jsonl",
                 proj / "sess1" / "subagents" / "other" / "wf_x" / "journal.jsonl",
                 # the right last four names, one level too deep or too shallow
                 proj / "sess1" / "x" / "subagents" / "workflows" / "wf_y" / "journal.jsonl",
                 proj / "subagents" / "workflows" / "wf_z" / "journal.jsonl"]
        for f in fakes:
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text('{"systemMessage":"code 1234-5678"}\n')
            assert _files({"tool_name": "Read", "tool_input": {"file_path": str(f)}}) == "deny", f
        assert _files({"tool_name": "Read", "tool_input": {
            "file_path": str(run_dir / "Journal.jsonl")}}) == "deny", "exact case"
        # a journal.jsonl that is a link to a transcript (symbolic or hard)
        for k, how in enumerate(("symlink", "hardlink")):
            other = run_dir.parent / f"wf_link{k}"
            other.mkdir()
            target = proj / "sess1.jsonl"
            (os.symlink if how == "symlink" else os.link)(target, other / "journal.jsonl")
            assert _files({"tool_name": "Read", "tool_input": {
                "file_path": str(other / "journal.jsonl")}}) == "deny", how
            assert _files({"tool_name": "Grep", "tool_input": {
                "pattern": "x", "path": str(other / "journal.jsonl")}}) == "deny", how


def test_stand_ins_and_gate_print_one_line_never_a_traceback():
    """Round 3: clis, asiml, gate and the shim entry had no catch-all, so an
    unexpected error printed a Python traceback (whose text can carry a value
    or a path) to output Claude reads, and with a non-zero exit."""
    import contextlib
    import run
    from gateway import clis, gate as gatemod

    def boom(*a, **k):
        raise RuntimeError("PLANTED-VALUE-IN-MESSAGE")
    with H.gateway_env():
        for tool, mod, attr, call in (("gh", clis, "main", lambda: run.run_shim("gh", ["pr", "list"])),
                                      ("gate", gatemod, "main", lambda: run.dispatch("gate", ["status"]))):
            saved = getattr(mod, attr)
            setattr(mod, attr, boom)
            err = io.StringIO()
            try:
                with contextlib.redirect_stderr(err):
                    rc = call()
            finally:
                setattr(mod, attr, saved)
            text = err.getvalue()
            assert rc == 1 and text.startswith(f"gateway: {tool} failed unexpectedly (RuntimeError)"), text
            assert "Traceback" not in text and "PLANTED" not in text, text
        # gate's own dispatch catches it too (e.g. gate check's helpers)
        from gateway import gate_setup
        saved = gate_setup.check
        gate_setup.check = boom
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                rc = gatemod.main(["check", "box"])
        finally:
            gate_setup.check = saved
        assert rc == 1 and "gate check failed (RuntimeError)" in err.getvalue(), err.getvalue()
        assert "PLANTED" not in err.getvalue()
