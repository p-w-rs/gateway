"""hooks_post (PostToolUse scrub + form validation), hooks_prompt (paste guard,
transcript/history scrubbing, form-change context), hooks_filechanged, and
the sh prefilters post.sh and prompt.sh."""
from __future__ import annotations

import json
import os
import re
import shutil
import time
from pathlib import Path

import harness as H
import harness_ux as U
from gateway import audit, consent, hooks_filechanged, hooks_post, hooks_prompt, hooks_session, paths, vault

GHP = "ghp_" + "Ab1" * 12
PEM = ("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
       "QyNTUxOQAAACB0ZXN0dGVzdHRlc3R0ZXN0dGVzdHRlc3R0ZXN0dGVzdAAAAJgAAAAAAAAAAA\n"
       "-----END OPENSSH PRIVATE KEY-----")

# checkpoint (plugin "check", MCP server "jobs"): the tools that return a
# job's log (job_tail; job_stop its last lines) or its record (job_status).
JOB_RESULT_TOOLS = ("mcp__plugin_check_jobs__job_tail", "mcp__plugin_check_jobs__job_status",
                    "mcp__plugin_check_jobs__job_stop")


# ---------------------------------------------------------------------------
# PostToolUse
# ---------------------------------------------------------------------------


def test_post_scrubs_tool_output_keeping_its_shape():
    with H.gateway_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n')
        resp = {"stdout": f"token: {GHP}\nok", "stderr": "", "interrupted": False, "isImage": False}
        out = hooks_post.main({"tool_name": "Bash", "tool_input": {"command": "x"}, "tool_response": resp})
        new = out["hookSpecificOutput"]["updatedToolOutput"]
        assert out["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
        assert set(new) == set(resp) and new["interrupted"] is False and new["isImage"] is False
        assert GHP not in new["stdout"] and "***" in new["stdout"] and new["stdout"].endswith("ok")
        read = {"type": "text", "file": {"filePath": "/x/y", "content": PEM + "\nrest"}}
        out = hooks_post.main({"tool_name": "Read", "tool_response": read})
        newr = out["hookSpecificOutput"]["updatedToolOutput"]
        assert "PRIVATE KEY-----\nb3Bl" not in newr["file"]["content"] and newr["file"]["filePath"] == "/x/y"
        out = hooks_post.main({"tool_name": "mcp__plugin_gate_gw__http", "tool_response": [
            {"type": "text", "text": f"Authorization: Bearer {'z' * 30}"}]})
        assert isinstance(out["hookSpecificOutput"]["updatedToolOutput"], list)
        assert "z" * 30 not in json.dumps(out)
        assert hooks_post.main({"tool_name": "Bash", "tool_response": {"stdout": "a3f9c2e" * 6}}) is None
        # a vault value without a token shape (the scrubber knows the vault)
        with vault.edit() as d:
            vault.set_sudo(d, "box", "u", "correct-horse-battery")
        out = hooks_post.main({"tool_name": "Bash", "tool_response": {"stdout": "pw correct-horse-battery"}})
        assert "correct-horse-battery" not in json.dumps(out)


def test_post_validates_edits_of_the_form():
    with H.gateway_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\nsudo = "ask"\n')
        fp = str(paths.form_path())
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\nsudo = true\nalso = ["u@10.0.0.9"]\n')
        out = hooks_post.main({"tool_name": "Edit", "tool_input": {"file_path": fp}, "tool_response": {}})
        ctx = out["hookSpecificOutput"]["additionalContext"]
        assert ctx.startswith("gateway: form OK") and "run gate check box" in ctx and "10.0.0.9" in ctx, ctx
        env.write_form('[hosts.box]\nadress = "u@box.example.com"\n[hosts.ok]\naddress = "ok.example.com"\n')
        out = hooks_post.main({"tool_name": "Write", "tool_input": {"file_path": fp}, "tool_response": {}})
        ctx = out["hookSpecificOutput"]["additionalContext"]
        assert "problems" in ctx and "Fix them now" in ctx, ctx
        env.write_form('[hosts.box\naddress = 1\n')
        out = hooks_post.main({"tool_name": "Edit", "tool_input": {"file_path": fp}, "tool_response": {}})
        assert "syntax" in out["hookSpecificOutput"]["additionalContext"].lower() or \
            "line" in out["hookSpecificOutput"]["additionalContext"]
        # a narrowing edit is persisted (ratchet)
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\nsudo = false\n')
        hooks_post.main({"tool_name": "Edit", "tool_input": {"file_path": fp}, "tool_response": {}})
        assert vault.load()["approved"]["rights"]["hosts"]["box"]["sudo"] is False
        other = hooks_post.main({"tool_name": "Edit", "tool_input": {"file_path": str(env.root / "x.toml")},
                                 "tool_response": {}})
        assert other is None


# ---------------------------------------------------------------------------
# UserPromptSubmit
# ---------------------------------------------------------------------------

BLOCKED = [GHP, "gho_" + "x" * 36, "github_pat_11ABCDEFG0" + "a" * 60, "hf_" + "Q" * 34,
           "glpat-" + "a" * 20, "sk-proj-" + "a1B2" * 10, "sk-ant-api03-" + "x" * 40, "xoxb-1234567890-abcdef",
           "AKIA" + "ABCDEFGHIJKLMNOP", "AGE-SECRET-KEY-1" + "Q" * 58, PEM,
           "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
           "-----BEGIN PRIVATE KEY-----\nMIIEvQ"]
PASSED = ["3f786850e387550fdab836ed7e6dc881de23001b",              # git SHA
          "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",   # sha256
          "aGVsbG8gd29ybGQgdGhpcyBpcyBhIGxvbmcgYmFzZTY0IGJsb2IgZm9yIHRlc3Rpbmc=",
          "123e4567-e89b-12d3-a456-426614174000", "use the ghp_ prefix for GitHub tokens",
          "sk-short", "my disk-sk-2 thing", "-----BEGIN PUBLIC KEY-----\nMIIBIj",
          "sha512-" + "a" * 80, "hf_hub_download is a function"]


def test_paste_guard_blocks_known_prefixes_and_pem_keys_only():
    for b in BLOCKED:
        assert hooks_prompt.find_secrets(f"here: {b} thanks"), b
    for p in PASSED:
        assert not hooks_prompt.find_secrets(p), p


def test_paste_guard_blocks_and_scrubs_transcript_and_history():
    with U.ux_env() as env:
        tr = env.root / "transcript.jsonl"
        tr.write_text(json.dumps({"type": "user", "message": f"my token {GHP}"}) + "\n"
                      + json.dumps({"type": "user", "message": "other"}) + "\n")
        hist = env.root / "history.jsonl"
        hist.write_text(json.dumps({"display": f"my token {GHP}"}) + "\n")
        size = tr.stat().st_size
        out = hooks_prompt.main({"prompt": f"my token {GHP}", "session_id": "s1",
                                 "transcript_path": str(tr)})
        assert out["decision"] == "block" and out["hookSpecificOutput"]["suppressOriginalPrompt"] is True
        assert out["reason"] == ("gateway: that looked like a secret, so it wasn't sent; Claude can open "
                                 "the gateway's dialog for it (gate check NAME), where it is typed "
                                 "privately")
        assert GHP not in tr.read_text() and tr.stat().st_size == size, "same-length overwrite"
        assert GHP not in hist.read_text() and "*" * len(GHP) in hist.read_text()
        json.loads(tr.read_text().splitlines()[0])
        out = hooks_prompt.main({"prompt": "show me the 3f786850e387550fdab836ed7e6dc881de23001b commit",
                                 "session_id": "s1"})
        assert "decision" not in out


def test_prompt_adds_context_when_the_form_changed():
    with U.ux_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n')
        form = env.form()
        hooks_session.record_context("s2", form)
        assert hooks_prompt.main({"prompt": "hi", "session_id": "s2"}) == {"continue": True}
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\n[hosts.lab]\naddress = "lab.example.com"\n')
        out = hooks_prompt.main({"prompt": "hi", "session_id": "s2"})
        ctx = out["hookSpecificOutput"]["additionalContext"]
        assert "gateway.toml changed" in ctx and "lab" in ctx and ctx.count("Gateway (plugin)") == 1
        assert hooks_prompt.main({"prompt": "again", "session_id": "s2"}) == {"continue": True}
        assert hooks_prompt.main({"tool_name": "Bash"}) is None, "no prompt: no output"


# ---------------------------------------------------------------------------
# FileChanged
# ---------------------------------------------------------------------------


def test_filechanged_reports_what_changed_and_errors():
    with H.gateway_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n')
        fp = str(paths.form_path())
        assert hooks_filechanged.main({"file_path": fp}) is None, "nothing changed vs approved"
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\nsudo = "ask"\n')
        out = hooks_filechanged.main({"hook_event_name": "FileChanged", "file_path": fp})
        assert "box: sudo now ask" in out["systemMessage"], out
        assert vault.load()["approved"]["rights"]["hosts"]["box"]["sudo"] == "ask", "narrowing persisted"
        assert hooks_filechanged.main({"file_path": fp}) is None, "same content: no message"
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\nsudo = true\n'
                       '[accounts.k]\nkind = "api-key"\nsites = ["api.x.com"]\n')
        msg = hooks_filechanged.main({"file_path": fp})["systemMessage"]
        assert "box: sudo now on" in msg and "k: new api-key account" in msg and "waiting for your OK" in msg
        env.write_form('[hosts.box]\nadress = "x"\n')
        msg = hooks_filechanged.main({"file_path": fp})["systemMessage"]
        assert "gateway.toml line" in msg and "box" in msg
        assert hooks_filechanged.main({"file_path": str(env.root / "other.toml")}) is None


def test_a_narrowing_claude_makes_is_reported_whatever_hook_runs_first():
    """Review round 2: Claude narrowed homelab's sudo to "ask"; PostToolUse
    persisted it and said only "form OK", and FileChanged, comparing with the
    (already lowered) approved rights for want of a session-start snapshot,
    said nothing. PostToolUse names the narrowing now, and SessionStart
    records the form it loaded for FileChanged."""
    with U.ux_env() as env:
        U.setup(env, '[hosts.homelab]\naddress = "u@lab.example.com"\nsudo = true\n')
        hooks_session.session_main({"session_id": "sess-ux"})
        fp = str(paths.form_path())
        env.write_form('[hosts.homelab]\naddress = "u@lab.example.com"\nsudo = "ask"\n')
        out = hooks_post.main({"tool_name": "Edit", "tool_input": {"file_path": fp}, "tool_response": {},
                               "session_id": "sess-ux"})
        ctx = out["hookSpecificOutput"]["additionalContext"]
        assert ctx.startswith("gateway: form OK") and "homelab: sudo" in ctx and "applied at once" in ctx, ctx
        assert vault.load()["approved"]["rights"]["hosts"]["homelab"]["sudo"] == "ask"
        msg = hooks_filechanged.main({"hook_event_name": "FileChanged", "file_path": fp})
        assert msg and "homelab: sudo now ask" in msg["systemMessage"], msg


def test_describe_changes():
    old = {"hosts": {"a": {"ssh": True, "sudo": True, "addresses": [{"user": "u", "host": "a.x", "port": 22}]}},
           "accounts": {"k": {"kind": "api-key", "use": True, "destinations": ["a.x"]}}}
    new = {"hosts": {"a": {"ssh": "ask", "sudo": False, "addresses": [{"user": "u", "host": "b.x", "port": 2222}],
                           "via": "j"}},
           "accounts": {"k": {"kind": "api-key", "use": False, "destinations": ["b.x"], "env": "K"}}}
    lines = hooks_filechanged.describe_changes(old, new)
    for frag in ("a: ssh now ask", "a: sudo now off", "a: new address u@b.x:2222", "a: address u@a.x removed",
                 "a: via j", "k: use now false", "k: env K", "k: may now send to b.x", "k: no longer sends to a.x"):
        assert frag in lines, (frag, lines)


# ---------------------------------------------------------------------------
# The sh prefilters
# ---------------------------------------------------------------------------


def test_prompt_sh_patterns_match_python():
    text = (H.PLUGIN / "hooks" / "prompt.sh").read_text()
    m = re.search(r"TOKENS='(.*)'", text)
    assert m
    for pat in hooks_prompt.TOKEN_PATTERNS:
        assert pat in m.group(1), pat


def test_prompt_sh_fails_closed_and_passes_ordinary_prompts():
    with U.ux_env() as env:
        # no env built: a paste-guard hit is blocked by sh alone
        r = U.run_sh(env, "prompt.sh", {"prompt": f"x {GHP}", "session_id": "s"})
        assert json.loads(r.stdout)["decision"] == "block", r.stdout
        r = U.run_sh(env, "prompt.sh", {"prompt": "hello 3f786850e387550fdab836ed7e6dc881de23001b",
                                        "session_id": "s"})
        assert r.stdout == "", "ordinary prompts don't start Python"
        # with the env: Python decides (the precise check)
        U.fake_ready_env(env)
        tr = env.root / "t.jsonl"
        tr.write_text(json.dumps({"m": GHP}) + "\n")
        r = U.run_sh(env, "prompt.sh", {"prompt": f"x {GHP}", "session_id": "s", "transcript_path": str(tr)})
        out = json.loads(r.stdout)
        assert out["decision"] == "block" and "wasn't sent" in out["reason"], r.stdout + r.stderr
        # the cancelled-pop-up markers are cleared by every prompt (they are global and
        # live in private/, so a changed session id doesn't dodge them)
        from gateway import popup
        popup.mark_cancelled("box--sudo-password", "d1")
        assert popup.was_cancelled("box--sudo-password", "d1")
        assert paths.private_dir() in popup.cancel_path("box--sudo-password").parents
        with U.env_vars(CLAUDE_CODE_SESSION_ID="another-id"):
            assert popup.was_cancelled("box--sudo-password", "d1")
        with U.env_vars(CLAUDE_CODE_SESSION_ID=None):
            assert popup.was_cancelled("box--sudo-password", "d1")
        U.run_sh(env, "prompt.sh", {"prompt": "please retry", "session_id": "s"})
        assert not popup.was_cancelled("box--sudo-password", "d1")


def test_post_sh_prefilter():
    with U.ux_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n')
        r = U.run_sh(env, "post.sh", {"tool_name": "Bash", "session_id": "s",
                                      "tool_response": {"stdout": "nothing to see"}})
        assert r.stdout == "" and r.returncode == 0
        U.fake_ready_env(env)
        r = U.run_sh(env, "post.sh", {"tool_name": "Bash", "session_id": "s",
                                      "tool_response": {"stdout": f"leak {GHP}"}})
        out = json.loads(r.stdout)
        assert GHP not in r.stdout and "***" in out["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        r = U.run_sh(env, "post.sh", {"tool_name": "Edit", "session_id": "s",
                                      "tool_input": {"file_path": str(paths.form_path())}, "tool_response": {}})
        assert "form OK" in json.loads(r.stdout)["hookSpecificOutput"]["additionalContext"]
        # a pending dialog request starts no Python here (the gate mod shows the
        # dialog; SessionStart and the prompt hook say it waits)
        pend = paths.ensure_private() / "pending"
        pend.mkdir(mode=0o700, exist_ok=True)
        (pend / "box--sudo-password.json").write_text(json.dumps(
            {"entry": "box", "what": "sudo password", "state": "open", "pid": os.getpid()}))
        r = U.run_sh(env, "post.sh", {"tool_name": "Bash", "session_id": "s", "tool_response": {"stdout": "x"}})
        assert r.stdout == ""


def test_post_sh_masks_vault_values_without_a_token_shape():
    """Review round 2: post.sh started Python only on a token shape, so a
    prefix-less API key in a Read, a sudo password in Bash output or a refresh
    token in a Grep result reached Claude unmasked. With a vault, every
    response goes to Python, which knows every value in every form."""
    key = "PlantedApiKeyNoPrefix7Q9Z2X4V6B8N0M"
    pw = "correct horse battery staple"
    rt = "0.AXoAplantedRefreshTokenNoShape0123456789"
    with U.ux_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n'
                     '[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n')
        U.set_token("openai", "api-key", key)
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), pw)
            d["accounts"]["openai"]["entra"] = {"refresh_token": rt}
        py = U.fake_ready_env(env)
        age = py.parent / "age"          # the hook decrypts the vault with the env's age
        if not age.exists():
            os.symlink(Path(H.PY).parent / "age", age)
        cases = [
            ("Read", {"type": "text", "file": {"filePath": "/p/.env",
                                               "content": f"OPENAI_API_KEY={key}\nX=1"}}),
            ("Bash", {"stdout": f"the password is {pw}\n", "stderr": ""}),
            ("Grep", {"mode": "content", "content": f"cfg.json:3: \"rt\": \"{rt}\""}),
            ("mcp__terminal__read_terminal", {"text": f"$ echo {key}\n{key}\n"}),
        ]
        for tool, resp in cases:
            r = U.run_sh(env, "post.sh", {"tool_name": tool, "session_id": "s",
                                          "tool_input": {}, "tool_response": resp})
            assert r.returncode == 0 and r.stdout, (tool, r.stderr)
            assert key not in r.stdout and pw not in r.stdout and rt not in r.stdout, (tool, r.stdout)
            new = json.loads(r.stdout)["hookSpecificOutput"]["updatedToolOutput"]
            assert "***" in json.dumps(new), (tool, new)


def test_sh_hooks_run_under_every_shell():
    shells = [s for s in ("/bin/sh", "/bin/dash", "/bin/bash", "/bin/zsh", shutil.which("dash"))
              if s and os.path.exists(s)]
    with H.gateway_env() as env:
        for sh in dict.fromkeys(shells):
            import subprocess
            p = {"tool_name": "mcp__plugin_gate_gw__http", "tool_input": {"url": "u", "method": "POST",
                                                                         "account": "a"}}
            r = subprocess.run([sh, str(H.PLUGIN / "hooks" / "mcp_perm.sh")], input=json.dumps(p),
                               capture_output=True, text=True, env=env.subprocess_env(), timeout=30)
            assert '"allow"' in r.stdout, (sh, r.stderr)
            r = subprocess.run([sh, str(H.PLUGIN / "hooks" / "prompt.sh"), "--test"],
                               input=json.dumps({"prompt": f"t {GHP}", "session_id": "s"}),
                               capture_output=True, text=True, env=env.subprocess_env(), timeout=30)
            assert '"block"' in r.stdout, (sh, r.stderr)
            r = subprocess.run([sh, str(H.PLUGIN / "hooks" / "post.sh"), "--test"],
                               input=json.dumps({"tool_name": "Bash", "tool_response": {"stdout": "ok"}}),
                               capture_output=True, text=True, env=env.subprocess_env(), timeout=30)
            assert r.returncode == 0 and r.stdout == "", (sh, r.stderr)


def test_prompt_sh_catches_tokens_at_the_start_of_a_line():
    """In the JSON payload a pasted line break is the two characters \\n, so the
    character before a token on its own line is the letter n: the sh prefilter
    must still see it (Python decides precisely on the decoded prompt)."""
    aws = "AKIA" + "ABCDEFGHIJKLMNOP"
    prompts = [f"here it is:\n{GHP}", f"line1\n\n{GHP}", f"tab\t{GHP}", f"key:\n{aws}",
               f"cr\r\n{GHP}", f"x {GHP}", GHP, f"note\u2028{GHP}",
               "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----"]
    passes = ["hello 3f786850e387550fdab836ed7e6dc881de23001b", "a\nb\nc",
              "build sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
              f"x{GHP}", "base64 aGVsbG8gd29ybGQgdGhpcyBpcyBub3QgYSB0b2tlbg=="]
    with U.ux_env() as env:
        for p in prompts:
            assert hooks_prompt.find_secrets(p), p
            r = U.run_sh(env, "prompt.sh", {"prompt": p, "session_id": "s"})
            assert r.stdout and json.loads(r.stdout)["decision"] == "block", (p, r.stdout, r.stderr)
        for p in passes:
            r = U.run_sh(env, "prompt.sh", {"prompt": p, "session_id": "s"})
            assert r.stdout == "", (p, r.stdout)
        U.fake_ready_env(env)
        for p in prompts:
            r = U.run_sh(env, "prompt.sh", {"prompt": p, "session_id": "s"})
            assert json.loads(r.stdout)["decision"] == "block", (p, r.stdout, r.stderr)


def test_prompt_sh_records_the_session_once():
    """The first prompt writes private/sessions/<sid>.env (start time, Claude
    Code's display variables); later prompts and other environments don't
    change it."""
    from gateway import popup
    with U.ux_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n')
        r = U.run_sh(env, "prompt.sh", {"prompt": "hi", "session_id": "sess/1"},
                     extra_env={"DISPLAY": ":0", "SSH_CONNECTION": "10.0.0.2 5555 10.0.0.1 22",
                                "XAUTHORITY": "/x;rm -rf /"})
        rec = popup.state_dir() / "sess_1.env"
        assert rec.exists(), (r.stdout, r.stderr)
        text = rec.read_text()
        assert "DISPLAY=:0\n" in text and "SSH_CONNECTION=10.0.0.2 5555 10.0.0.1 22\n" in text
        assert "XAUTHORITY=\n" in text, "unsafe values are not recorded"
        assert oct(rec.stat().st_mode & 0o777) == "0o600"
        t0 = rec.stat().st_mtime
        os.utime(rec, (t0 - 100, t0 - 100))
        U.run_sh(env, "prompt.sh", {"prompt": "again", "session_id": "sess/1"},
                 extra_env={"DISPLAY": ":99"})
        assert rec.read_text() == text and abs(rec.stat().st_mtime - (t0 - 100)) < 1, "written once"


def test_a_deleted_form_is_described_as_it_is():
    """Review round 2: deleting gateway.toml was announced as "nothing is
    turned off meanwhile", yet every host was refused until the next session
    restored it, and gate status didn't say the file was missing."""
    from gateway import consent, gate
    with U.ux_env() as env:
        U.setup(env, '[hosts.homelab]\naddress = "u@lab.example.com"\n')
        hooks_session.session_main({"session_id": "sess-ux"})
        fp = paths.form_path()
        fp.unlink()
        msg = hooks_filechanged.main({"file_path": str(fp)})["systemMessage"]
        assert "nothing is turned off" not in msg
        assert "only this computer's defaults apply" in msg and "restores the last good" in msg, msg
        eff = consent.compute(consent.load_form(), vault.load())
        assert "homelab" not in eff.hosts, "what the message says is what happens"
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            gate.main(["status"])
        assert buf.getvalue().startswith("gateway.toml is missing"), buf.getvalue()


# ---------------------------------------------------------------------------
# Round 3: PostToolUseFailure (Claude Code shows a failed call's output
# unmasked; no hook can change it)
# ---------------------------------------------------------------------------


def test_hooks_json_registers_post_tool_use_failure_like_post_tool_use():
    spec = json.loads((H.PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]
    post, fail = spec["PostToolUse"], spec.get("PostToolUseFailure")
    assert fail, "PostToolUseFailure is registered"
    assert fail[0]["matcher"] == post[0]["matcher"]
    assert fail[0]["hooks"][0]["args"] == post[0]["hooks"][0]["args"], "post.sh, like PostToolUse"


def test_a_failed_call_holding_a_vault_value_warns_claude_and_the_user():
    key = "PlantedApiKeyNoPrefix7Q9Z2X4V6B8N0M"
    pw = "correct horse battery staple"
    with U.ux_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n'
                     '[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n')
        U.set_token("openai", "api-key", key)
        with vault.edit() as d:
            vault.set_sudo(d, "box", "u", pw)
        out = hooks_post.main({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                               "session_id": "s", "tool_input": {"command": "cat .env; exit 1"},
                               "error": f"Exit code 1\nOPENAI_API_KEY={key}\nsudo={pw}"})
        dump = json.dumps(out)
        assert key not in dump and pw not in dump, dump
        spec = out["hookSpecificOutput"]
        assert spec["hookEventName"] == "PostToolUseFailure" and "updatedToolOutput" not in spec
        assert "never repeat, store or use it" in spec["additionalContext"]
        msg = out["systemMessage"]
        assert "openai's token" in msg and "box's sudo password" in msg, msg
        assert "gate login openai" in msg and "gate forget box sudo and gate check box" in msg, msg
        leaks = [a for a in audit.read(50) if a.get("event") == "leak"]
        assert leaks and "openai token" in leaks[-1]["entries"], leaks
        assert key not in json.dumps(leaks)
        # a token shape that isn't a stored value
        out = hooks_post.main({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                               "session_id": "s", "error": f"Exit code 2\n{GHP}"})
        assert "shaped like a token" in out["hookSpecificOutput"]["additionalContext"]
        assert GHP not in json.dumps(out)
        # nothing of either kind: no output
        assert hooks_post.main({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                                "session_id": "s", "error": "Exit code 1\nNo such file"}) is None


def test_a_failed_call_shows_no_terminal_command_or_code():
    """The terminal path and its one-time codes are gone (PLAN-v4 phase 3): a
    failed call's PostToolUseFailure hook adds nothing about a pending dialog."""
    with U.ux_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n')
        out = hooks_post.main({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                               "session_id": "s", "error": "Exit code 1\ngateway: nothing was asked"})
        assert out is None or "gate secret" not in json.dumps(out)


def test_post_sh_passes_a_failure_payload_to_python():
    with U.ux_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n')
        U.fake_ready_env(env)
        r = U.run_sh(env, "post.sh", {"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                                      "session_id": "s", "error": f"Exit code 1\n{GHP}"})
        out = json.loads(r.stdout)
        assert out["hookSpecificOutput"]["hookEventName"] == "PostToolUseFailure"
        assert GHP not in r.stdout


def test_each_leak_warning_names_commands_that_really_replace_the_secret():
    """Review round 4: the PostToolUseFailure warning told the user to run gate
    check (a no-op for a stored credential) or gate rotate for an account's
    key (refused). Each kind now gets its own advice, and running the advised
    commands opens a pop-up for the new secret (or, for a host key, gate rotate
    on a remote host)."""
    from gateway import gate_setup, ssh, sudo
    import test_ux_gate_setup as G
    key = "PlantedApiKeyNoPrefix7Q9Z2X4V6B8N0M"
    pw = "local sudo password 1"
    form = ('[hosts.localhost]\nsudo = true\n[hosts.box]\naddress = "u@box.example.com"\n'
            '[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n'
            '[accounts.pijul]\nkind = "pijul"\nlogin = "me"\n')
    with U.ux_env() as env:
        U.setup(env, form)
        U.set_token("openai", "api-key", key)
        hpriv, hpub = vault.generate_ssh_key("gateway-box@test")
        apriv, apub = vault.generate_ssh_key("gateway-pijul@test")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), pw)
            vault.host_record(d, "box")["keys"] = [vault.key_record(hpriv, hpub)]
            vault.account_record(d, "pijul", "pijul")["ssh_key"] = {
                "private": apriv, "public": apub, "fingerprint": vault.fingerprint_of(apub)}

        def advice(value: str) -> list[list[str]]:
            out = hooks_post.main({"hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
                                   "session_id": "s", "error": f"Exit code 1\n{value}"})
            msg = out["systemMessage"]
            assert value not in msg
            return [m.split() for m in re.findall(r"gate (?:rotate|forget|check|login) [a-z][a-z0-9-]*"
                                                  r"(?: (?:sudo|key|token|signin))?", msg)]

        cmds = advice(hpriv.strip().splitlines()[-2])
        assert cmds == [["gate", "rotate", "box"]], cmds
        assert not env.form().hosts["box"].is_local, "gate rotate works on a remote host"
        with U.patch(ssh, "rotate", lambda n: f"gateway: {n} has a new key"):
            rc, out, err = G._run(gate_setup.rotate, "box")
        assert rc == 0 and "new key" in out, err

        def runs_to_a_popup(cmds: list[list[str]]) -> None:
            before = len(env.dialog.calls())
            for c in cmds:
                verb, name, *what = c[1:]
                if verb == "forget":
                    rc, out, err = G._run(gate_setup.forget, name, what[0] if what else None)
                    assert rc == 0, err
                elif verb == "check":
                    G._run(gate_setup.check, name)
                elif verb == "login":
                    G._run(gate_setup.login, name)
                else:
                    raise AssertionError(c)
            assert len(env.dialog.calls()) > before, (cmds, "no pop-up opened")

        with U.patch(sudo, "probe_nopasswd", lambda user=None: False):
            cmds = advice(pw)
            assert cmds == [["gate", "forget", "localhost", "sudo"], ["gate", "check", "localhost"]], cmds
            runs_to_a_popup(cmds)
        cmds = advice(key)
        assert cmds == [["gate", "login", "openai"]], cmds
        runs_to_a_popup(cmds)
        cmds = advice(apriv.strip().splitlines()[-2])
        assert cmds == [["gate", "forget", "pijul", "key"], ["gate", "check", "pijul"]], cmds
        runs_to_a_popup(cmds)
        new = (vault.load()["accounts"]["pijul"].get("ssh_key") or {}).get("public")
        assert new and new != apub, "a new account key was made"


# ---------------------------------------------------------------------------
# Round 4: task notifications (a background command's raw output tail),
# the desktop app's session tools, the passwd home in the sh hooks
# ---------------------------------------------------------------------------

STALL = ("<task-notification>\n<task-id>b8c58w3rc</task-id>\n<tool-use-id>toolu_01X</tool-use-id>\n"
         "<output-file>/private/tmp/claude-501/x/tasks/b8c58w3rc.output</output-file>\n"
         "<status>running</status>\n<summary>Background command \"cat notes.txt\" appears to be "
         "waiting for interactive input</summary>\n</task-notification>\nLast output:\n{tail}\n"
         "Continue? [y/N]")
DONE = ("<task-notification>\n<task-id>b1</task-id>\n<status>completed</status>\n<summary>Background "
        "command \"make\" completed (exit code 0)</summary>\n</task-notification>")


def _vault_with(env, key: str, pw: str) -> None:
    U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n'
                 '[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n')
    U.set_token("openai", "api-key", key)
    with vault.edit() as d:
        vault.set_sudo(d, "box", "u", pw)


def test_a_task_notice_quoting_a_stored_value_is_held_back_and_masked_in_the_transcript():
    """Claude Code's 'waiting for interactive input' notice quotes the raw end
    of a background command's output file to Claude (as a prompt when idle, a
    queued attachment mid-turn; both pass UserPromptSubmit). A stored value
    with no token shape blocked nothing before (review round 4)."""
    key = "PlantedApiKeyNoPrefix7Q9Z2X4V6B8N0M"
    pw = 'Pl4nted"Sudo\\Pw!42'                 # JSON-escaped in the transcript
    with U.ux_env() as env:
        _vault_with(env, key, pw)
        notice = STALL.format(tail=f"api_key={key}\nsudo_pw={pw}")
        tr = env.root / "transcript.jsonl"
        rec = {"type": "queue-operation", "operation": "enqueue", "content": notice}
        tr.write_text(json.dumps(rec) + "\n" + json.dumps({"type": "user", "message": notice}) + "\n")
        size = tr.stat().st_size
        from gateway import popup
        popup.mark_cancelled("box--sudo-password", "d1")
        out = hooks_prompt.main({"prompt": notice, "session_id": "s", "transcript_path": str(tr)})
        dump = json.dumps(out)
        assert key not in dump and pw not in dump and json.dumps(pw)[1:-1] not in dump, dump
        assert out["decision"] == "block" and out["hookSpecificOutput"]["suppressOriginalPrompt"]
        assert "background command" in out["reason"]
        assert "openai's token" in out["systemMessage"] and "box's sudo password" in out["systemMessage"]
        text = tr.read_text()
        assert key not in text and json.dumps(pw)[1:-1] not in text, text
        assert tr.stat().st_size == size, "same-length overwrite"
        for line in text.splitlines():
            json.loads(line)
        assert any(a.get("event") == "leak" and a.get("where") == "task-notification"
                   for a in audit.read(20))
        # a task notice isn't the user speaking: a cancelled pop-up stays cancelled
        assert popup.was_cancelled("box--sudo-password", "d1")
        # a notice with nothing stored or shaped passes (completion notices carry no output)
        out = hooks_prompt.main({"prompt": DONE, "session_id": "s"})
        assert "decision" not in out, out
        out = hooks_prompt.main({"prompt": STALL.format(tail="Downloading 40%"), "session_id": "s"})
        assert "decision" not in out, out


def test_a_task_notice_with_a_token_shape_says_it_was_a_notice():
    with U.ux_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n')
        out = hooks_prompt.main({"prompt": STALL.format(tail=f"GITHUB_TOKEN={GHP}"), "session_id": "s"})
        assert out["decision"] == "block" and "background command" in out["reason"], out
        assert GHP not in json.dumps(out) and "shaped like a token" in out["systemMessage"]


def test_prompt_sh_sends_every_task_notice_to_python_once_a_vault_exists_and_fails_closed():
    key = "PlantedApiKeyNoPrefix7Q9Z2X4V6B8N0M"
    with U.ux_env() as env:
        notice = STALL.format(tail=f"api_key={key}")
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n', approve=False)
        paths.vault_path().unlink()                 # no vault yet: nothing to look for
        r = U.run_sh(env, "prompt.sh", {"prompt": notice, "session_id": "s"})
        assert r.returncode == 0 and r.stdout == "", r.stdout
        _vault_with(env, key, "correct horse battery staple")
        # no env built: Python can't answer, so the notice is blocked (fail closed)
        r = U.run_sh(env, "prompt.sh", {"prompt": notice, "session_id": "s"})
        out = json.loads(r.stdout)
        assert out["decision"] == "block" and "background command notice" in out["reason"], r.stdout
        assert out["hookSpecificOutput"]["suppressOriginalPrompt"] is True
        # with the env: Python decides
        py = U.fake_ready_env(env)
        age = py.parent / "age"
        if not age.exists():
            os.symlink(Path(H.PY).parent / "age", age)
        r = U.run_sh(env, "prompt.sh", {"prompt": notice, "session_id": "s"})
        out = json.loads(r.stdout)
        assert out["decision"] == "block" and key not in r.stdout and "openai's token" in r.stdout
        r = U.run_sh(env, "prompt.sh", {"prompt": DONE, "session_id": "s"})
        assert "decision" not in r.stdout, r.stdout
        # the cancelled markers survive a notice, not a prompt of the user's
        from gateway import popup
        popup.mark_cancelled("box--sudo-password", "d1")
        U.run_sh(env, "prompt.sh", {"prompt": DONE, "session_id": "s"})
        assert popup.was_cancelled("box--sudo-password", "d1")
        U.run_sh(env, "prompt.sh", {"prompt": "please retry", "session_id": "s"})
        assert not popup.was_cancelled("box--sudo-password", "d1")


def test_scrub_masks_json_escaped_values():
    """A transcript, an export or a JSON tool output holds a value with `"`,
    `\\` or non-ASCII text JSON-escaped (review round 4)."""
    from gateway import scrub
    with H.gateway_env() as env:
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\n')
        d = vault.empty()
        for i, pw in enumerate(('Pl4nted"Sudo\\Pw!42', "Plänted-Pässwort-42")):
            vault.set_sudo(d, "box", f"u{i}", pw)
        vault.save(d)
        for pw in ('Pl4nted"Sudo\\Pw!42', "Plänted-Pässwort-42"):
            for form in (json.dumps(pw), json.dumps(pw, ensure_ascii=False)):
                text = f'{{"content": {form}}}'
                assert form[1:-1] not in scrub.scrub_text(text), (pw, form)


def test_session_tools_export_is_denied_and_search_is_masked():
    """The desktop app's transcript export stays denied; its search and event
    listing are allowed (no one-time code exists any more) and their results
    are masked by PostToolUse like any output. The sh guard of a cold start
    does the same."""
    from gateway import hooks_files
    with U.ux_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n')

        def decide(tool):
            out = hooks_files.main({"tool_name": tool, "tool_input": {"session_id": "self"}})
            return None if out is None else out["hookSpecificOutput"]["permissionDecision"]
        exp, search, events = ("mcp__ccd_session_mgmt__export_transcript",
                               "mcp__ccd_session_mgmt__search_session_transcripts",
                               "mcp__ccd_session_mgmt__list_events")
        assert decide(exp) == "deny"
        assert decide(search) is None and decide(events) is None
        spec = json.loads((H.PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]
        pre = [g for g in spec["PreToolUse"] if "ccd_session_mgmt" in g.get("matcher", "")]
        assert pre and all(re.fullmatch(pre[0]["matcher"], t) for t in (exp, search, events))
        assert pre[0]["hooks"][0]["args"][-1] == "hook-files" and pre[0]["hooks"][0]["onFailure"] == "block"
        for ev in ("PostToolUse", "PostToolUseFailure"):
            m = spec[ev][0]["matcher"]
            assert re.fullmatch(m, search) and re.fullmatch(m, events), (ev, m)
        assert not H.any_env_ready()

        def guard(tool):
            r = H.run_launch(env, "hook-files", payload={"tool_name": tool, "tool_input": {}})
            assert r.returncode == 0, r.stderr
            return _deny_of(r)
        assert guard(exp) == "deny" and guard(search) is None and guard(events) is None


def _deny_of(r):
    return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] if r.stdout.strip() else None


def test_post_masks_stored_values_in_session_search_results():
    key = "PlantedApiKeyNoPrefix7Q9Z2X4V6B8N0M"
    with U.ux_env() as env:
        _vault_with(env, key, "correct horse battery staple")
        resp = {"results": [{"session": "a", "snippet": f"OPENAI_API_KEY={key}"}]}
        out = hooks_post.main({"tool_name": "mcp__ccd_session_mgmt__search_session_transcripts",
                               "session_id": "s", "tool_input": {"query": "key"},
                               "tool_response": resp})
        new = json.dumps(out["hookSpecificOutput"]["updatedToolOutput"])
        assert key not in new and "***" in new, new


def test_post_sh_sends_session_readers_to_python_without_a_vault():
    with U.ux_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n', approve=False)
        paths.vault_path().unlink()
        U.fake_ready_env(env)
        r = U.run_sh(env, "post.sh", {"tool_name": "mcp__ccd_session_mgmt__list_events",
                                      "session_id": "s", "tool_response": {"events": ["x"]}})
        assert r.returncode == 0, r.stderr
        r2 = U.run_sh(env, "post.sh", {"tool_name": "Bash", "session_id": "s",
                                       "tool_response": {"stdout": "x"}})
        assert r2.stdout == ""


def test_sh_hooks_take_the_gateway_home_from_the_password_database_not_HOME():
    """Review round 4: post.sh decided 'a vault exists' from $HOME while every
    gateway process uses the passwd home; with HOME set elsewhere, stored
    values without a token shape went unmasked. hooks/home.sh gives the
    passwd home (the e2e marker and --test still redirect)."""
    import pwd
    import subprocess
    want = pwd.getpwuid(os.getuid()).pw_dir
    home_sh = U.SH_SCRIPTS / "home.sh"
    for sh in dict.fromkeys(s for s in ("/bin/sh", "/bin/bash", "/bin/zsh", shutil.which("dash"))
                            if s and os.path.exists(s)):
        for home in ("/tmp/somewhere-else", ""):
            env = {"PATH": "/usr/bin:/bin", "HOME": home}
            r = subprocess.run([sh, "-c", '. "$1"; gw_user_home', "sh", str(home_sh)],
                               capture_output=True, text=True, timeout=10, env=env)
            assert r.stdout == want, (sh, home, r.stdout, r.stderr)
    for name in ("post.sh", "prompt.sh", "launch.sh"):
        text = (U.SH_SCRIPTS / name).read_text()
        assert "gw_user_home" in text and "home.sh" in text, name
        assert '"${HOME:-/nonexistent}/.config/gateway"' not in text, name
        assert '${HOME:-}/.claude}/plugins/data' not in text, name


def _hooks_copy(d: Path, fake_home: Path, names=("post.sh", "prompt.sh", "launch.sh")) -> Path:
    """A plugin copy whose hooks/home.sh names `fake_home` as the passwd home
    (the real one is never resolved), with a launch.sh stub for post.sh and
    prompt.sh that records each call."""
    root = d / "plugin"
    (root / "hooks").mkdir(parents=True)
    for n in names:
        (root / "hooks" / n).write_text((U.SH_SCRIPTS / n).read_text())
    (root / "hooks" / "home.sh").write_text(f"gw_user_home() {{ printf '%s' {str(fake_home)!r}; }}\n")
    (root / "pixi.lock").write_text("")
    return root


def test_post_sh_finds_the_vault_in_the_passwd_home_when_HOME_points_elsewhere():
    """The reviewer's case: HOME is another folder; the vault lives in the
    passwd home (hooks/home.sh). A response holding a stored value with no
    token shape must still reach Python."""
    import subprocess
    with H.gateway_env() as env:
        d = env.root / "rig"
        fake = d / "pwhome"
        (fake / ".config" / "gateway" / "private").mkdir(parents=True)
        (fake / ".config" / "gateway" / "private" / "vault.age").write_text("x")
        root = _hooks_copy(d, fake, names=("post.sh",))
        marker = d / "launched"
        (root / "hooks" / "launch.sh").write_text(f"#!/bin/sh\n: > {str(marker)!r}\ncat > /dev/null\n")
        other = d / "otherhome"
        other.mkdir()
        payload = json.dumps({"tool_name": "Bash", "session_id": "s",
                              "tool_response": {"stdout": "sudo_pw=Pl4ntedSudoPw42xyz"}})
        e = {"PATH": "/usr/bin:/bin", "HOME": str(other)}
        r = subprocess.run(["/bin/sh", str(root / "hooks" / "post.sh")], input=payload,
                           capture_output=True, text=True, env=e, timeout=30)
        assert r.returncode == 0 and marker.exists(), r.stderr
        # a test root without --test resolves no home at all
        marker.unlink()
        r = subprocess.run(["/bin/sh", str(root / "hooks" / "post.sh")], input=payload,
                           capture_output=True, text=True, timeout=30,
                           env={**e, "GATEWAY_TEST_ROOT": str(env.root)})
        assert r.returncode == 0 and not marker.exists()


def test_launch_sh_writes_the_launcher_in_the_passwd_home():
    import subprocess
    with H.gateway_env() as env:
        d = env.root / "rig"
        fake = d / "pwhome"
        fake.mkdir(parents=True)
        root = _hooks_copy(d, fake, names=("launch.sh",))
        other = d / "otherhome"
        other.mkdir()
        e = {"PATH": "/usr/bin:/bin", "HOME": str(other), "CLAUDE_PLUGIN_DATA": str(d / "data")}
        r = subprocess.run(["/bin/sh", str(root / "hooks" / "launch.sh"), "hook-session"],
                           input="{}", capture_output=True, text=True, env=e, timeout=30)
        assert r.returncode == 0, r.stderr
        assert (fake / ".config" / "gateway" / "gate").is_file()
        assert not (other / ".config").exists()
        # GATEWAY_TEST_ROOT without --test: no home is resolved, nothing written
        (fake / ".config" / "gateway" / "gate").unlink()
        r = subprocess.run(["/bin/sh", str(root / "hooks" / "launch.sh"), "hook-session"],
                           input="{}", capture_output=True, text=True, timeout=30,
                           env={**e, "GATEWAY_TEST_ROOT": str(env.root)})
        assert r.returncode == 0 and not (fake / ".config" / "gateway" / "gate").exists()


def test_form_report_separates_every_item():
    """Review round 4: with errors the items were joined with a space, so a
    waiting item ran into the error text ("... while they're here b: new
    github account ...")."""
    with H.gateway_env() as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n')
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\n'
                       '[accounts.a]\nkind = "github"\nlogin = "x"\ndefault = true\n'
                       '[accounts.b]\nkind = "github"\nlogin = "y"\ndefault = true\n')
        form = env.form()
        txt = hooks_post.form_report(form, consent.compute(form, vault.load()))
        assert "problems" in txt and "default = true is set on a, b" in txt, txt
        assert "Fix them now; a: " in txt and "here; b: " in txt, txt
        assert ".;" not in txt and "  " not in txt


# ---------------------------------------------------------------------------
# Review round 5: what every tool call costs (post.sh, the file guard)
# ---------------------------------------------------------------------------


def _post_rig(env):
    """A plugin copy whose home.sh names a fake passwd home holding a vault
    file, and whose launch.sh only records each payload post.sh hands on (its
    way to Python): nothing of the gateway runs."""
    d = env.root / "rig"
    fake = d / "pwhome"
    (fake / ".config" / "gateway" / "private").mkdir(parents=True)
    (fake / ".config" / "gateway" / "private" / "vault.age").write_text("x")
    root = _hooks_copy(d, fake, names=("post.sh",))
    log = d / "launched"
    (root / "hooks" / "launch.sh").write_text(f"#!/bin/sh\ncat >> {str(log)!r}\necho >> {str(log)!r}\n")
    return root, fake, log


def test_post_sh_with_a_vault_skips_python_for_edit_tools_only():
    """Review round 5: with a vault every response went to Python and age
    (about 0.1 s per call), an Edit's or Write's too, though Claude Code shows
    Claude no file content for them ("The file X has been updated
    successfully"). They skip Python now unless a token shape, gateway.toml
    or a pending notice calls for it. Every other tool still goes, and so does
    a payload whose tool can't be told for sure (two tool_name keys, a nested
    one first, an odd layout)."""
    import subprocess
    with H.gateway_env() as env:
        root, fake, log = _post_rig(env)
        e = {"PATH": "/usr/bin:/bin", "HOME": str(fake)}

        def went(payload):
            if log.exists():
                log.unlink()
            data = payload if isinstance(payload, str) else json.dumps(payload)
            r = subprocess.run(["/bin/sh", str(root / "hooks" / "post.sh")], input=data,
                               capture_output=True, text=True, env=e, timeout=30)
            assert r.returncode == 0, r.stderr
            return log.exists()
        resp = {"filePath": "/p/a.py", "oldString": "a", "newString": "b",
                "originalFile": "sudo_pw=Pl4ntedSudoPw42xyz"}
        for tool in ("Edit", "Write", "MultiEdit"):
            p = {"session_id": "s", "hook_event_name": "PostToolUse", "tool_name": tool,
                 "tool_input": {"file_path": "/p/a.py"}, "tool_response": resp}
            assert not went(p), tool
            assert not went(json.dumps(p, separators=(",", ":"))), tool
            assert not went({"session_id": "s", "hook_event_name": "PostToolUseFailure",
                             "tool_name": tool, "tool_input": {"file_path": "/p/a.py"},
                             "error": "String to replace not found in file."}), tool
            assert went(dict(p, tool_response={**resp, "originalFile": f"t={GHP}"})), tool
            assert went(dict(p, tool_input={"file_path": str(fake / ".config/gateway/gateway.toml")})), tool
        for tool in ("Bash", "BashOutput", "Monitor", "Read", "Grep", "mcp__terminal__read_terminal",
                     "mcp__plugin_gate_gw__http", *JOB_RESULT_TOOLS):
            assert went({"session_id": "s", "tool_name": tool, "tool_response": {"stdout": "x"}}), tool
        for tool in JOB_RESULT_TOOLS:     # checkpoint's job tools (MCP content lists)
            assert went({"session_id": "s", "tool_name": tool,
                         "tool_response": [{"type": "text", "text": "{\"ok\": true}"}]}), tool
            assert went({"session_id": "s", "hook_event_name": "PostToolUseFailure",
                         "tool_name": tool, "error": "{\"ok\": false}"}), tool
        assert went('{"session_id":"s","tool_response":{"tool_name":"Edit","stdout":"pw"},'
                    '"tool_name":"Bash"}')
        assert went('{"session_id":"s","tool_name":"Edit","tool_response":{"tool_name":"Bash"}}')
        assert went('{"session_id":"s","tool_name":\n"Edit","tool_response":{}}')
        assert went('{"session_id":"s","tool_response":{"stdout":"pw"}}')
        pend = fake / ".config" / "gateway" / "private" / "pending"
        pend.mkdir()
        (pend / "box--sudo-password.json").write_text("{}")
        assert not went({"session_id": "s", "tool_name": "Edit", "tool_input": {"file_path": "/p/a.py"},
                         "tool_response": resp}), "a pending dialog is the mod's to show"


def test_post_with_a_vault_still_masks_what_claude_reads_and_leaves_edits_alone():
    """The same through the real hook (harness: post.sh --test, a ready env):
    a Bash response is masked, an Edit's response gets no output at all."""
    pw = "correct horse battery staple"
    with U.ux_env() as env:
        _vault_with(env, "PlantedApiKeyNoPrefix7Q9Z2X4V6B8N0M", pw)
        py = U.fake_ready_env(env)
        age = py.parent / "age"
        if not age.exists():
            os.symlink(Path(H.PY).parent / "age", age)
        r = U.run_sh(env, "post.sh", {"tool_name": "Bash", "session_id": "s",
                                      "tool_response": {"stdout": f"pw {pw}", "stderr": ""}})
        assert pw not in r.stdout and "***" in r.stdout, r.stdout
        r = U.run_sh(env, "post.sh", {"tool_name": "Edit", "session_id": "s",
                                      "tool_input": {"file_path": "/p/a.py"},
                                      "tool_response": {"filePath": "/p/a.py", "originalFile": "x"}})
        assert r.returncode == 0 and r.stdout == "", (r.stdout, r.stderr)


def test_post_hook_without_pending_files_imports_no_popup():
    """The PostToolUse hook's common case (a vault, nothing pending) loads no
    pop-up, dialog or form code: a fresh Python pays for every import."""
    import subprocess
    with U.ux_env() as env:
        _vault_with(env, "PlantedApiKeyNoPrefix7Q9Z2X4V6B8N0M", "correct horse battery staple")
        assert hooks_post.nothing_pending()
        code = ("import json, sys; sys.argv = ['run.py', '--test', 'hook-post']; "
                f"sys.path.insert(0, {str(H.PLUGIN)!r}); import run; "
                "sys.stdin = __import__('io').StringIO(json.dumps({'tool_name': 'Bash', "
                "'session_id': 's', 'tool_response': {'stdout': 'x'}})); rc = run.main(); "
                "print(json.dumps(sorted(m for m in sys.modules if m.startswith('gateway.'))))")
        H._require_test_flag(("--test", "hook-post"), "run.py")
        r = subprocess.run([H.PY, "-I", "-S", *H.PYX, "-c", code], capture_output=True, text=True,
                           timeout=60,
                           env=env.subprocess_env(), cwd=str(env.root))
        mods = json.loads(r.stdout.strip().splitlines()[-1])
        assert "gateway.scrub" in mods and "gateway.vault" in mods, mods
        for m in ("gateway.popup", "gateway.dialog", "gateway.form", "gateway.consent"):
            assert m not in mods, mods
        pend = paths.ensure_private() / "pending"
        pend.mkdir(mode=0o700, exist_ok=True)
        (pend / "box--token.json").write_text("{}")
        assert not hooks_post.nothing_pending()


def _recording_python(env) -> Path:
    """A ready env whose python records each start, then runs the real one
    (launch.sh passes --test, which harness.run_launch checks)."""
    py = paths.env_python()
    py.parent.mkdir(parents=True, exist_ok=True)
    log = env.root / "python-started"
    py.write_text(f"#!/bin/sh\necho x >> '{log}'\nexec '{H.PY}' \"$@\"\n")
    py.chmod(0o755)
    (paths.env_dir() / ".ready").write_text("")
    return log


def _count(log: Path) -> int:
    return len(log.read_text().splitlines()) if log.exists() else 0


def test_file_guard_fast_path_passes_only_what_python_passes():
    """Review round 5: the file guard started Python for every Read, Edit,
    Write, MultiEdit and NotebookEdit (about 66 ms). launch.sh now passes a
    plain path inside the session's folder by itself, and leaves everything
    else to Python. For every case here, the decision launch.sh gives is
    Python's own (hooks_files.main on the same payload), and the plain
    cases never start Python."""
    from gateway import hooks_files
    with U.ux_env(dialog="none", session=None) as env:
        U.setup(env, '[hosts.box]\naddress = "u@box.example.com"\n')
        log = _recording_python(env)
        root = env.root.resolve()          # physical (macOS /var is a symlink: all to Python)
        proj = root / "proj"
        proj.mkdir()
        (proj / "README.md").write_text("hello\n")
        (proj / "sub dir").mkdir()
        (proj / "sub dir" / "a+b@c,d=e.py").write_text("x\n")
        home = root / "home"
        tp = home / ".claude" / "projects" / "p" / "s.jsonl"
        tp.parent.mkdir(parents=True)
        tp.write_text("{}\n")
        priv = paths.private_dir().resolve()

        def guard(fp, tool="Read", cwd=proj, raw=None, shell="/bin/sh", ti=None):
            key = "notebook_path" if tool == "NotebookEdit" else "file_path"
            p = {"session_id": "s", "transcript_path": str(tp), "cwd": str(cwd),
                 "permission_mode": "auto", "hook_event_name": "PreToolUse", "tool_name": tool,
                 "tool_input": ti if ti is not None else {key: str(fp)}}
            text = raw if raw is not None else json.dumps(p)
            n = _count(log)
            r = H.run_launch(env, "hook-files", input_text=text, shell=shell)
            assert r.returncode == 0, (fp, r.stderr)
            got = json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] if r.stdout.strip() else None
            want = hooks_files.main(json.loads(text))
            assert got == (want and "deny"), (fp, raw, got, want)
            if _count(log) == n:
                return "fast"
            return got or "python"

        fast = [("Read", proj / "README.md"), ("Edit", proj / "README.md"), ("Write", proj / "new.txt"),
                ("Write", proj / "new dir" / "deeper" / "x.txt"), ("MultiEdit", proj / "README.md"),
                ("NotebookEdit", proj / "n.ipynb"), ("Read", proj / "sub dir" / "a+b@c,d=e.py")]
        for tool, fp in fast:
            assert guard(fp, tool) == "fast", (tool, fp)
        compact = json.dumps({"cwd": str(proj), "tool_name": "Read",
                              "tool_input": {"file_path": str(proj / "README.md")}}, separators=(",", ":"))
        assert guard(None, raw=compact) == "fast"
        # left to Python, which has nothing to say
        os.symlink(proj / "README.md", proj / "ln.md")
        os.mkfifo(proj / "fifo")
        for fp, cwd in ((proj / "ln.md", proj), (proj / "x.jsonl", proj), (proj / "fifo", proj),
                        (f"{proj}/../proj/README.md", proj), (f"{proj}/./README.md", proj),
                        ("README.md", proj), ("~/x.txt", proj), (root / "elsewhere.txt", proj),
                        (proj / "é.txt", proj), (proj / "README.md", f"{proj}/"),
                        (home / ".config" / "gateway" / "gateway.toml", home)):
            assert guard(fp, cwd=cwd) == "python", fp
        assert guard(None, tool="Grep", ti={"pattern": "x", "path": str(proj)}) == "python"
        assert guard(None, tool="Glob", ti={"pattern": "*.md"}) == "python"
        assert guard(None, raw=json.dumps({"cwd": str(proj), "tool_name": "Read", "tool_input":
                                           {"file_path": str(proj / "README.md")}}, indent=1)) == "fast"
        assert guard(None, raw=(f'{{"cwd": "{proj}", "tool_name":\n"Read", "tool_input": '
                                f'{{"file_path": "{proj}/README.md"}}}}')) == "python"
        assert guard(None, raw=(f'{{"cwd": "{proj}", "tool_name": "Read", "tool_input": '
                                f'{{"file_path": "{proj}/a\\".txt"}}}}')) == "python"
        # denied by Python, never passed here
        os.link(paths.key_path(), proj / "hard.txt")
        os.symlink(paths.key_path(), proj / "soft.txt")
        (root / "run" / "sock.txt").write_text("x")
        cases = [(proj / "hard.txt", proj), (proj / "soft.txt", proj),
                 (priv / "vault.age", home), (home / ".CONFIG" / "GATEWAY" / "private" / "vault.age", home),
                 (tp.with_name("other.jsonl"), home), (tp, home), (root / "run" / "sock.txt", root)]
        cases += [(proj / "hard.txt" / "x", proj), (proj / "hard.txt" / "x" / "y.txt", proj)]
        for fp, cwd in cases:
            assert guard(fp, cwd=cwd) == "deny", fp
        plain = str(proj / "README.md")
        key = str(paths.key_path())
        raws = [  # payloads whose words could mislead a text reader
            f'{{"cwd": "{proj}", "tool_name": "Read", "tool_input": {{"file_path": "{plain}", '
            f'"file_path": "{key}"}}}}',
            f'{{"cwd": "{proj}", "tool_name": "Read", "tool_input": {{"file_path": "{plain}", '
            f'"path": "{priv}"}}}}',
            f'{{"cwd": "{proj}", "tool_name": "Read", "tool_input": {{"file_path": "{plain}", '
            f'"notebook_path": "{key}"}}}}',
            f'{{"cwd": "{proj}", "tool_name": "Read", "tool_input": {{"file_path": "{plain}"}}, '
            '"tool_name": "mcp__ccd_session_mgmt__export_transcript"}',
            f'{{"cwd": "{proj}", "tool_name": "Read", "tool_input": {{"file_path": '
            f'"{proj}/\\u002e\\u002e/home/\\u002econfig/gateway/private/key.txt"}}}}',
        ]
        for raw in raws:
            assert guard(None, raw=raw) == "deny", raw
        # every shell runs it alike
        for sh in dict.fromkeys(s for s in ("/bin/sh", "/bin/dash", "/bin/bash", shutil.which("dash"))
                                if s and os.path.exists(s)):
            assert guard(proj / "README.md", shell=sh) == "fast", sh
            assert guard(proj / "hard.txt", shell=sh) == "deny", sh
        # a symlink inside private/ protects its target; private/ moved into the
        # project behind a symlink is protected where it really is
        (proj / "extra.txt").write_text("x")
        os.symlink(proj / "extra.txt", priv / "extra")
        assert guard(proj / "extra.txt") == "deny"
        (priv / "extra").unlink()
        assert guard(proj / "extra.txt") == "fast"
        (proj / "v2key.txt").write_text("AGE-SECRET-KEY-1X\n")
        os.symlink(proj / "v2key.txt", paths.v2_key_path())
        assert guard(proj / "v2key.txt") == "deny"
        paths.v2_key_path().unlink()
        shutil.move(str(priv), str(proj / "realpriv"))
        os.symlink(proj / "realpriv", priv)
        assert guard(proj / "realpriv" / "vault.age") == "deny"
        assert guard(proj / "realpriv" / "new.txt", tool="Write") == "deny"
        priv.unlink()
        shutil.move(str(proj / "realpriv"), str(priv))
        # a fresh install (no gateway home yet): writing into it is still Python's to deny
        shutil.rmtree(paths.home())
        assert guard(priv / "key.txt", tool="Write", cwd=home) == "deny"


def test_file_guard_fast_path_in_production_mode_leaves_run_dirs_and_test_roots_to_python():
    """The production spelling of the run dir (/tmp/gw-UID, /private/tmp on
    macOS) is decided as text, and GATEWAY_TEST_ROOT without --test gives no
    home at all (run.py refuses then): neither is passed by the fast path. A
    copy whose home.sh names a fake home, and whose env 'python' only records
    that it was started: no gateway code runs."""
    import hashlib
    import subprocess
    with H.gateway_env() as env:
        d = env.root.resolve() / "rig"
        fake = d / "pwhome"
        (fake / ".config" / "gateway" / "private").mkdir(parents=True)
        root = _hooks_copy(d, fake, names=("launch.sh",))
        data = d / "data"
        envd = data / "envs" / hashlib.sha256(b"").hexdigest()[:12]
        py = envd / ".pixi" / "envs" / "default" / "bin" / "python3"
        py.parent.mkdir(parents=True)
        log = d / "started"
        py.write_text(f"#!/bin/sh\ncat > /dev/null\necho x >> '{log}'\nexit 3\n")
        py.chmod(0o755)
        (envd / ".ready").write_text("")
        proj = d / "proj"
        proj.mkdir()
        (proj / "a.txt").write_text("x")
        e = {"PATH": "/usr/bin:/bin", "HOME": str(fake), "CLAUDE_PLUGIN_DATA": str(data)}

        def run(fp, cwd, extra=None):
            if log.exists():
                log.unlink()
            p = {"session_id": "s", "cwd": str(cwd), "tool_name": "Read",
                 "tool_input": {"file_path": str(fp)}}
            r = subprocess.run(["/bin/sh", str(root / "hooks" / "launch.sh"), "hook-files"],
                               input=json.dumps(p), capture_output=True, text=True,
                               env={**e, **(extra or {})}, timeout=30)
            return r.returncode, log.exists()
        assert run(proj / "a.txt", proj) == (0, False)
        tmp = Path("/private/tmp")
        if tmp.is_symlink() or not tmp.is_dir():
            tmp = Path("/tmp")
        assert run(tmp / "gw-0-no-such-run-dir" / "f.txt", tmp) == (3, True)
        assert run(tmp / "GW-0-no-such-run-dir" / "f.txt", tmp) == (3, True)
        assert run(proj / "a.txt", proj, {"GATEWAY_TEST_ROOT": str(env.root)}) == (3, True)


# ---------------------------------------------------------------------------
# Checkpoint's job tools through the output hooks (integration review): the
# results of job_tail, job_status and job_stop are masked like Bash output
# ---------------------------------------------------------------------------

def _post_sh_matcher(event: str) -> str:
    spec = json.loads((H.PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]
    groups = [g for g in spec[event]
              if any(h.get("args", [""])[0].endswith("/hooks/post.sh") for h in g["hooks"])]
    assert len(groups) == 1, (event, groups)
    return groups[0]["matcher"]


def _checkpoint_result(out: dict) -> list:
    """What Claude Code hands PostToolUse for a checkpoint tool: the MCP
    content list, whose one text block is checkpoint's result dict as
    indented JSON (its mcp_server.py; the tool_response shape seen in the
    integration run's job_tail and in a probe, Claude Code 2.1.301)."""
    return [{"type": "text", "text": json.dumps(out, indent=2)}]


def _ready_vault_env(env, key: str, pw: str) -> None:
    _vault_with(env, key, pw)
    py = U.fake_ready_env(env)
    age = py.parent / "age"          # the hook decrypts the vault with the env's age
    if not age.exists():
        os.symlink(Path(H.PY).parent / "age", age)


_JOB = {"id": "leak-20261019-120504", "name": "leak", "state": "exited", "exit_code": 0,
        "command": "cat notes.txt", "cwd": "/p", "log": "/s/jobs/leak-20261019-120504.log",
        "gateway_env": True}


def test_hooks_json_sends_checkpoint_job_results_to_the_output_hooks():
    """Integration review: a job ran `cat notes.txt` (the planted API key and
    the remote sudo password) and job_tail returned both raw to Claude, the
    stream-json and the transcript: PostToolUse's matcher didn't name the job
    tools. Both output events name them now, by their exact names (anchored:
    nothing else matches, and nothing changes when checkpoint isn't loaded).
    Claude Code: a matcher with characters beyond letters, digits, _ and | is
    a regular expression, searched in the tool name."""
    for ev in ("PostToolUse", "PostToolUseFailure"):
        m = _post_sh_matcher(ev)
        assert not re.fullmatch(r"[A-Za-z0-9_|]+", m), m
        for tool in JOB_RESULT_TOOLS:
            assert re.search(m, tool), (ev, tool, m)
        for tool in ("mcp__plugin_check_jobs__job_tail_all", "xmcp__plugin_check_jobs__job_tail",
                     "mcp__plugin_check_jobs__job_", "mcp__plugin_check_jobs__job_stopx",
                     "mcp__plugin_other_jobs__job_tail"):
            assert not re.search(m, tool), (ev, tool, m)


def test_post_sh_masks_stored_values_in_checkpoint_job_results():
    """job_tail and job_stop return a job's log, job_status its record:
    through post.sh and hook-post (the harness's --test) a stored value comes
    back as *** in every form (the sudo password here is JSON-escaped in
    checkpoint's text), a token shape too, and the rest of checkpoint's JSON
    is kept as it was (still valid JSON, the other lines intact)."""
    key = "PlantedApiKeyNoPrefix7Q9Z2X4V6B8N0M"
    pw = 'Pl4nted"Sudo\\Pw!42'
    with U.ux_env() as env:
        _ready_vault_env(env, key, pw)
        tail = f"epoch 3 loss 0.12\nOPENAI_API_KEY={key}\nsudo_pw={pw}\ndone"
        assert json.dumps(pw)[1:-1] != pw    # so checkpoint's text holds its escaped form
        cases = [
            ("mcp__plugin_check_jobs__job_tail", {"name": "leak", "lines": 40},
             {"ok": True, "job": _JOB, "tail": tail}),
            ("mcp__plugin_check_jobs__job_stop", {"name": "leak", "reason": "enough"},
             {"ok": True, "job": dict(_JOB, state="killed"), "tail": tail, "stopped": True}),
            ("mcp__plugin_check_jobs__job_status", {"name": "leak"},
             {"ok": True, "job": dict(_JOB, command=f"GH_TOKEN={GHP} sh -c 'echo {key}'")}),
        ]
        for tool, ti, res in cases:
            r = U.run_sh(env, "post.sh", {"session_id": "s", "hook_event_name": "PostToolUse",
                                          "tool_name": tool, "tool_input": ti,
                                          "tool_response": _checkpoint_result(res)})
            assert r.returncode == 0 and r.stdout, (tool, r.stderr)
            for frag in ("PlantedApiKey", "Pl4nted", GHP[:12]):
                assert frag not in r.stdout, (tool, frag, r.stdout)
            spec = json.loads(r.stdout)["hookSpecificOutput"]
            assert spec["hookEventName"] == "PostToolUse", spec
            new = spec["updatedToolOutput"]
            assert isinstance(new, list) and len(new) == 1 and set(new[0]) == {"type", "text"}, new
            body = json.loads(new[0]["text"])
            assert body["ok"] is True and body["job"]["id"] == _JOB["id"], body
            if "tail" in body:
                lines = body["tail"].splitlines()
                assert lines[0] == "epoch 3 loss 0.12" and lines[-1] == "done", lines
                assert lines[1] == "OPENAI_API_KEY=***" and lines[2] == "sudo_pw=***", lines
            else:
                assert body["job"]["command"].count("***") == 2, body
        # nothing stored and no token shape in the log: no output at all
        r = U.run_sh(env, "post.sh", {"session_id": "s", "hook_event_name": "PostToolUse",
                                      "tool_name": "mcp__plugin_check_jobs__job_tail",
                                      "tool_input": {"name": "leak"},
                                      "tool_response": _checkpoint_result(
                                          {"ok": True, "job": _JOB, "tail": "epoch 3 loss 0.12"})})
        assert r.returncode == 0 and r.stdout == "", (r.stdout, r.stderr)


def test_post_sh_warns_when_a_failed_job_stop_returns_a_stored_value():
    """An MCP error result (job_stop's stop_failed, which carries the job's
    last log lines; isError) goes to PostToolUseFailure with the text in
    `error`, where no hook can rewrite it (probe, Claude Code 2.1.301: an
    updatedToolOutput there is ignored, additionalContext reaches Claude).
    Like a failed Bash command: Claude is told not to use it, the user which
    secret to replace, and a leak is audited; no value in any of it."""
    key = "PlantedApiKeyNoPrefix7Q9Z2X4V6B8N0M"
    pw = 'Pl4nted"Sudo\\Pw!42'
    with U.ux_env() as env:
        _ready_vault_env(env, key, pw)
        res = {"ok": False, "job": dict(_JOB, state="stop_failed"), "stopped": False,
               "tail": f"OPENAI_API_KEY={key}\nsudo_pw={pw}",
               "reason": f"stop_failed: processes of job {_JOB['id']} (process group 4242) are "
                         "still running after SIGKILL"}
        r = U.run_sh(env, "post.sh", {"session_id": "s", "hook_event_name": "PostToolUseFailure",
                                      "tool_name": "mcp__plugin_check_jobs__job_stop",
                                      "tool_input": {"name": "leak", "reason": "enough"},
                                      "error": json.dumps(res, indent=2)})
        assert r.returncode == 0 and r.stdout, r.stderr
        assert "PlantedApiKey" not in r.stdout and "Pl4nted" not in r.stdout, r.stdout
        out = json.loads(r.stdout)
        spec = out["hookSpecificOutput"]
        assert spec["hookEventName"] == "PostToolUseFailure" and "updatedToolOutput" not in spec
        assert "never repeat, store or use it" in spec["additionalContext"], spec
        msg = out["systemMessage"]
        assert "openai's token" in msg and "box's sudo password" in msg, msg
        leaks = [a for a in audit.read(50) if a.get("event") == "leak"]
        assert leaks and leaks[-1]["tool"] == "mcp__plugin_check_jobs__job_stop", leaks
        assert "PlantedApiKey" not in json.dumps(leaks) and "Pl4nted" not in json.dumps(leaks)
