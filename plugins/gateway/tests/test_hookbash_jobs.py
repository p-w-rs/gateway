"""checkpoint's job_start (mcp__plugin_check_jobs__job_start) through the
approval hook (SPEC 8, "Checkpoint jobs"): its `command`, or its `argv`
shlex-joined, gets Bash's denies; an "ask" right is denied (nobody can be
asked while a job runs); gate export/import/copy-to are denied as in the
Terminal panel; the hook never answers allow or ask for it. Also the
wiring (hooks.json) and the sh prefilter (pre_bash.sh) for its payloads."""
from __future__ import annotations

import contextlib
import json
import os
import re
import shlex
import subprocess
import tempfile
import time
from pathlib import Path

import harness as H
import test_hookbash_prefilter as P
import test_hookbash_table as T
from gateway import audit, bashparse, consent, hooks_bash, vault

JOB = "mcp__plugin_check_jobs__job_start"
ASK, DENY, NONE = "ask", "deny", None
JOB_ASK = "a job can't use the \"ask\" right"


@contextlib.contextmanager
def _project_dir(path):
    """CLAUDE_PROJECT_DIR (where checkpoint starts a job without a cwd) set to
    the test's project folder: the tests themselves run under Claude Code."""
    old = os.environ.get("CLAUDE_PROJECT_DIR")
    os.environ["CLAUDE_PROJECT_DIR"] = str(path)
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("CLAUDE_PROJECT_DIR", None)
        else:
            os.environ["CLAUDE_PROJECT_DIR"] = old


@contextlib.contextmanager
def _rig():
    with H.gateway_env() as env:
        proj = T._project(env)
        env.write_form(T.FORM)
        vault.save(vault.empty())
        consent.approve_all(env.form())
        with _project_dir(proj):
            yield env, proj


def _job(ti, mode, cwd=None):
    payload = {"tool_name": JOB, "permission_mode": mode,
               "tool_input": {"name": "j", "redo_hint": "rerun", **ti}}
    if cwd is not None:
        payload["cwd"] = cwd
    return hooks_bash.main(payload)


def _decision(out):
    return None if out is None else out["hookSpecificOutput"]["permissionDecision"]


def _forms(cmd):
    """The command form, and the argv form when the command is one simple
    command (checkpoint runs shlex.join(argv) through /bin/sh -c)."""
    yield {"command": cmd}
    try:
        words = shlex.split(cmd)
    except ValueError:
        return
    if words and shlex.join(words) == cmd:
        yield {"argv": words}


# (command, decision for a job in every mode). Bash's deny rows stay deny;
# Bash's "ask" rows become deny; Bash's allow rows get no decision.
JOB_TABLE = [
    # curl/wget, private folder, transcripts, git credential, redaction
    ("curl http://example.com", DENY),
    ("wget http://example.com/file", DENY),
    ("env curl http://x", DENY),
    ("sudo curl http://x", DENY),
    ("cat ~/.config/gateway/private/key.txt", DENY),
    ("grep -r AGE-SECRET ~/.config/gateway", DENY),
    ("tar c ~/.config", DENY),
    ("cat ~/.claude/projects/p/s.jsonl", DENY),
    ("git credential fill", DENY),
    ("GIT_TRACE_REDACT=0 git push", DENY),
    ("az account get-access-token", DENY),
    # the user's gate commands
    ("gate secret box", DENY),
    ("bash -c 'gate secret box'", DENY),
    ("gate export /tmp/x.age", DENY),
    ("gate import f.age", DENY),
    ("gate copy-to example", DENY),
    ("env gate copy-to example", DENY),
    # rights set to false (and remote sudo on a sudo = false host)
    ("ssh offhost uptime", DENY),
    ("scp offhost:/x .", DENY),
    ("ssh builder sudo id", DENY),
    ("gate check offhost", DENY),
    # "ask" rights: denied (nobody can be asked while a job runs)
    ("ssh askhost uptime", DENY),
    ("ssh askhost sudo id", DENY),
    ("scp askhost:/x .", DENY),
    ("rsync -a ./x askhost:/y", DENY),
    ("env ssh askhost uptime", DENY),
    ("bash -c 'ssh askhost uptime'", DENY),
    ("for h in askhost; do ssh $h x; done", DENY),
    ("gate check askhost", DENY),
    ("echo $(gate rotate askhost)", DENY),
    # what Bash would allow (or leave alone) gets no decision: Claude Code's
    # own permission check decides (a prompt, or the classifier in auto mode)
    ("sudo apt install htop", NONE),
    ("ssh example df -h", NONE),
    ("rsync -a dist/ example:/srv/app/", NONE),
    ("gate status", NONE),
    ("gate check example", NONE),
    ("pixi run train", NONE),
    ("make test", NONE),
    ("python train.py --epochs 10", NONE),
    ("echo 'curl http://x'", NONE),
    ("gate with openai -- python deploy.py", NONE),
]


def test_job_start_decision_table_command_and_argv_in_every_mode():
    with _rig() as (_, proj):
        failures = []
        for cmd, want in JOB_TABLE:
            for ti in _forms(cmd):
                for mode in ("auto", "default", "bypassPermissions", "plan", "acceptEdits"):
                    got = _decision(_job(ti, mode, cwd=str(proj)))
                    if got != want:
                        failures.append(f"{mode:18} {ti}: got {got} want {want}")
        assert not failures, "\n".join(failures)
        # both forms are really exercised
        assert sum(1 for c, _ in JOB_TABLE for f in _forms(c) if "argv" in f) >= 20


def test_every_bash_row_is_a_deny_or_no_decision_for_a_job():
    """The whole Bash decision table through job_start: deny stays deny, ask
    becomes deny, gate export/import/copy-to are denied (as in the Terminal
    panel), allow and no-decision become no decision; never allow or ask, in
    auto and default modes."""
    with _rig() as (_, proj):
        failures = []
        for cmd, auto in T.TABLE:
            terminal = re.search(r"\bgate (export|import|copy-to)\b", cmd)
            want = DENY if auto in (DENY, ASK) or terminal else NONE
            for mode in ("auto", "default"):
                out = _job({"command": cmd}, mode, cwd=str(proj))
                got = _decision(out)
                if got != want:
                    failures.append(f"{mode:8} {cmd!r}: got {got} want {want}")
                elif auto == ASK and not terminal and JOB_ASK not in out["hookSpecificOutput"][
                        "permissionDecisionReason"]:
                    failures.append(f"{mode:8} {cmd!r}: reason {out}")
        assert not failures, "\n".join(failures)


def test_the_ask_deny_names_the_rights_and_the_next_step_and_is_audited():
    with _rig() as (_, proj):
        out = _job({"argv": ["ssh", "askhost", "sudo", "id"]}, "default", cwd=str(proj))
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        assert reason == ('gateway: a job can\'t use the "ask" rights for ssh on askhost and '
                          "sudo (root) on askhost (nobody can be asked while it runs); run it "
                          "with the Bash tool as its own command, or ask the user to set them "
                          "to true."), reason
        last = audit.last_refusal(None)
        assert last and last["target"] == "askhost" and last["reason"] == reason, last
        out = _job({"command": "sudo -n true"}, "auto", cwd=str(proj))
        assert out is None                                   # localhost sudo = true
        out = _job({"command": "scp askhost:/x ."}, "auto", cwd=str(proj))
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        assert reason.startswith('gateway: a job can\'t use the "ask" right for ssh on askhost '
                                 "(nobody can be asked"), reason
        out = _job({"command": "gate copy-to example"}, "auto", cwd=str(proj))
        assert "as a job" in out["hookSpecificOutput"]["permissionDecisionReason"]
        # the same commands in Claude's Bash: asked about / allowed as before
        assert T._decide("ssh askhost sudo id", "default") == ASK
        assert T._decide("gate copy-to example", "auto") == "allow"


def test_localhost_sudo_ask_in_a_job_is_denied():
    with H.gateway_env() as env:
        proj = T._project(env)
        env.write_form("[hosts.localhost]\nsudo = \"ask\"\n")
        vault.save(vault.empty())
        consent.approve_all(env.form())
        with _project_dir(proj):
            out = _job({"command": "sudo make install"}, "auto", cwd=str(proj))
            assert _decision(out) == DENY
            assert "for sudo on this machine" in out["hookSpecificOutput"]["permissionDecisionReason"]
            assert T._decide("sudo make install", "auto") == ASK


def test_the_jobs_own_folder_counts_for_the_private_path_deny():
    """A relative word is protected from the job's cwd (absolute, or relative
    to the project), or from the project folder / the session's cwd when the
    job names none."""
    with _rig() as (env, proj):
        priv = env.home / "private"
        priv.mkdir(parents=True, exist_ok=True)
        assert _decision(_job({"command": "cat key.txt", "cwd": str(priv)}, "auto",
                              cwd=str(proj))) == DENY
        assert _decision(_job({"command": "cat key.txt"}, "auto", cwd=str(proj))) is None
        assert _decision(_job({"command": "cat key.txt"}, "auto", cwd=str(priv))) == DENY
        with _project_dir(priv):
            assert _decision(_job({"command": "cat key.txt"}, "auto", cwd=str(proj))) == DENY
        rel = os.path.relpath(priv, proj)
        assert _decision(_job({"argv": ["cat", "key.txt"], "cwd": rel}, "auto",
                              cwd=str(proj))) == DENY
        assert _decision(_job({"command": "cat notes.txt", "cwd": str(proj)}, "auto",
                              cwd=str(priv))) is None   # the job's own cwd wins


def test_a_job_never_gets_allow_or_ask():
    """Two layers: _judge returns no allow for a job, and the job path passes
    only a deny, whatever the decision below it says."""
    with _rig() as (_, proj):
        payload = {"tool_name": JOB, "permission_mode": "auto", "cwd": str(proj)}
        for cmd in ("ssh example df", "sudo ls", "gate status", "cat README.md"):
            assert T._decide(cmd, "auto") == "allow", cmd
            got = hooks_bash._judge(bashparse.parse(cmd), cmd, payload, "auto", str(proj),
                                    False, in_job=True)
            assert got is None, (cmd, got)
        real = hooks_bash._decide
        try:
            for dec in ("allow", "ask"):
                hooks_bash._decide = lambda *a, _d=dec, **k: hooks_bash._out(_d, "gateway: x")
                assert _job({"command": "sudo ls"}, "auto", cwd=str(proj)) is None, dec
            hooks_bash._decide = lambda *a, **k: hooks_bash._out("deny", "gateway: x")
            assert _decision(_job({"command": "sudo ls"}, "auto", cwd=str(proj))) == DENY
            # an allow for `command` doesn't end the check: `argv` is judged too
            outs = iter([hooks_bash._out("allow", "gateway: x"), hooks_bash._out("deny", "gateway: y")])
            hooks_bash._decide = lambda *a, **k: next(outs)
            out = _job({"command": "sudo ls", "argv": ["sudo", "ls"]}, "auto", cwd=str(proj))
            assert out["hookSpecificOutput"]["permissionDecisionReason"] == "gateway: y", out
        finally:
            hooks_bash._decide = real


def test_job_input_shapes():
    with _rig() as (_, proj):
        for ti in ({}, {"command": ""}, {"command": "   "}, {"argv": []}, {"argv": "curl x"},
                   {"argv": ["curl", 3]}, {"command": None}):
            assert _job(ti, "auto", cwd=str(proj)) is None, ti
        # both given (checkpoint refuses that): either one denies
        assert _decision(_job({"command": "ls", "argv": ["curl", "http://x"]}, "auto",
                              cwd=str(proj))) == DENY
        assert _decision(_job({"command": "curl http://x", "argv": ["ls"]}, "auto",
                              cwd=str(proj))) == DENY
        # the other job tools aren't judged as commands
        out = hooks_bash.main({"tool_name": "mcp__plugin_check_jobs__job_status",
                               "tool_input": {"name": "curl http://x"}, "permission_mode": "auto"})
        assert out is None


def test_run_py_hook_bash_judges_a_job_payload():
    with _rig() as (env, proj):
        r = H.run_py(env, "--test", "hook-bash",
                     payload={"tool_name": JOB, "permission_mode": "auto", "cwd": str(proj),
                              "tool_input": {"name": "x", "redo_hint": "r",
                                             "argv": ["ssh", "askhost", "uptime"]}})
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)["hookSpecificOutput"]
        assert out["permissionDecision"] == "deny" and JOB_ASK in out["permissionDecisionReason"]
        r = H.run_py(env, "--test", "hook-bash",
                     payload={"tool_name": JOB, "permission_mode": "auto", "cwd": str(proj),
                              "tool_input": {"name": "x", "redo_hint": "r",
                                             "command": "ssh example df"}})
        assert r.returncode == 0 and r.stdout.strip() == "", (r.stdout, r.stderr)


# ---------------------------------------------------------------------------
# Wiring and the sh prefilter
# ---------------------------------------------------------------------------


def _bash_group():
    spec = json.loads((H.PLUGIN / "hooks" / "hooks.json").read_text())["hooks"]
    groups = [g for g in spec["PreToolUse"]
              if any(h.get("args", [""])[-1].endswith("/pre_bash.sh") for h in g["hooks"])]
    assert len(groups) == 1, groups
    return groups[0]


def _matches(matcher, tool):
    # Claude Code: a matcher of letters, digits, _ and | is a list of exact
    # names; anything else is a regular expression.
    if re.fullmatch(r"[A-Za-z0-9_|]+", matcher):
        return tool in matcher.split("|")
    return re.search(matcher, tool) is not None


def test_hooks_json_sends_job_start_to_the_bash_prefilter():
    g = _bash_group()
    for tool in ("Bash", "Monitor", "mcp__terminal__run_in_terminal", JOB):
        assert _matches(g["matcher"], tool), (g["matcher"], tool)
    for tool in ("mcp__plugin_check_jobs__job_status", "mcp__plugin_check_jobs__job_tail",
                 "mcp__plugin_check_jobs__job_stop", "Read"):
        assert not _matches(g["matcher"], tool), (g["matcher"], tool)
    assert g["hooks"][0]["command"] == "sh" and "onFailure" not in g["hooks"][0], g


def _run_job(pre, ti):
    payload = json.dumps({"session_id": "s", "tool_name": JOB, "permission_mode": "auto",
                          "transcript_path": "/Users/x/.claude/projects/-p/0b5c.jsonl",
                          "cwd": "/Users/x/proj",
                          "tool_input": {"name": "train", "redo_hint": "rerun; resumes", **ti}})
    t0 = time.monotonic()
    r = subprocess.run(["/bin/sh", str(pre)], input=payload, capture_output=True, text=True,
                       timeout=15)
    return r, time.monotonic() - t0


def test_prefilter_lets_ordinary_jobs_through_without_python_quickly():
    with tempfile.TemporaryDirectory(dir=Path(H.tmp_base())) as td:
        pre, marker = P._rig(Path(td) / "rig")
        times = []
        for cmd in ("pixi run train", "make -j8 test", "python train.py --epochs 10",
                    "npm run build", "cargo build --release", "echo storage passage"):
            for ti in _forms(cmd):
                marker.unlink(missing_ok=True)
                r, dt = _run_job(pre, ti)
                assert r.returncode == 0 and r.stdout == "", (ti, r.stdout, r.stderr)
                assert not marker.exists(), f"python was started for {ti}"
                times.append(dt)
        times.sort()
        # a shell, sed and grep: milliseconds (generous for a loaded test machine)
        assert times[len(times) // 2] < 0.5, times


def test_prefilter_sends_jobs_with_trigger_words_to_python():
    with tempfile.TemporaryDirectory(dir=Path(H.tmp_base())) as td:
        pre, marker = P._rig(Path(td) / "rig")
        for cmd in ("ssh askhost uptime", "sudo make install", "curl http://x",
                    "gate secret box", "rsync -a x h:/y", "cat ~/.config/gateway/private/key.txt"):
            for ti in _forms(cmd):
                marker.unlink(missing_ok=True)
                r, _ = _run_job(pre, ti)
                assert marker.exists() and "sentinel" in r.stdout, f"no trigger on {ti}"
        # the job's own folder can name the gateway folder too
        marker.unlink(missing_ok=True)
        r, _ = _run_job(pre, {"command": "cat key.txt", "cwd": "/Users/x/.config/gateway/private"})
        assert marker.exists(), r
