"""hooks/pre_bash.sh: the POSIX sh prefilter (SPEC 8). It must stay silent and
never start Python for a command with no trigger word, fire on trigger words
only as whole words, and hand the payload to the Python hook on a hit."""
from __future__ import annotations

import json
import os
import subprocess

import harness as H

PRE = H.PLUGIN / "hooks" / "pre_bash.sh"


def _managed_env(pre) -> dict:
    """The environment of a Bash call in a session whose mod set the managed
    prefix (PLAN-v4 phase 4): the word list then decides alone. Without it,
    every Bash call goes to Python (tests/test_managed.py)."""
    env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CODE_SHELL_PREFIX"}
    env["CLAUDE_CODE_SHELL_PREFIX"] = str(pre.parent / "gate-sh")
    return env


def _rig(tmp):
    """A copy of pre_bash.sh next to a fake launch.sh that records invocation
    and echoes a sentinel decision. Returns (pre_path, marker_path)."""
    d = tmp
    d.mkdir(parents=True, exist_ok=True)
    (d / "pre_bash.sh").write_text(PRE.read_text())
    os.chmod(d / "pre_bash.sh", 0o755)
    marker = d / "launched"
    fake = d / "launch.sh"
    fake.write_text(
        "#!/bin/sh\n"
        f": > {str(marker)!r}\n"
        'cat > /dev/null 2>&1\n'
        'printf \'%s\\n\' \'{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
        '"permissionDecision":"allow","permissionDecisionReason":"sentinel"}}\'\n')
    os.chmod(fake, 0o755)
    return d / "pre_bash.sh", marker


def _run(pre, command):
    payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": command},
                          "permission_mode": "auto"})
    return subprocess.run(["/bin/sh", str(pre)], input=payload, capture_output=True,
                          text=True, timeout=15, env=_managed_env(pre))


def test_non_trigger_commands_do_not_start_python():
    import tempfile
    from pathlib import Path
    base = Path(H.tmp_base())
    with tempfile.TemporaryDirectory(dir=base) as td:
        pre, marker = _rig(Path(td) / "rig")
        for cmd in ("ls -la /tmp", "echo hello world", "git status",
                    "python manage.py runserver", "make test", "grep foo bar.txt",
                    "cat README.md", "npm run build", "cargo build"):
            marker.unlink(missing_ok=True)
            r = _run(pre, cmd)
            assert r.returncode == 0 and r.stdout == "", (cmd, r.stdout, r.stderr)
            assert not marker.exists(), f"python was started for {cmd!r}"


def test_trigger_words_only_as_whole_words():
    import tempfile
    from pathlib import Path
    base = Path(H.tmp_base())
    with tempfile.TemporaryDirectory(dir=base) as td:
        pre, marker = _rig(Path(td) / "rig")
        # these contain a trigger substring but not as a word -> no trigger
        for cmd in ("echo storage is managed", "echo passage", "echo sabotage",
                    "echo encourage the team", "echo curling tournament",
                    "echo massage", "ls packages/", "echo hazard lazy"):
            marker.unlink(missing_ok=True)
            r = _run(pre, cmd)
            assert r.stdout == "" and not marker.exists(), f"false trigger on {cmd!r}"


def test_trigger_words_fire_and_reach_python():
    import tempfile
    from pathlib import Path
    base = Path(H.tmp_base())
    with tempfile.TemporaryDirectory(dir=base) as td:
        pre, marker = _rig(Path(td) / "rig")
        for cmd in ("sudo apt install x", "ssh example df", "scp a b:/c",
                    "sftp h:/x", "rsync -a a h:/b", "curl http://x", "wget http://x",
                    "gate status", "age -d f", "git credential fill",
                    "GIT_TRACE_REDACT=0 git push", "cat ~/.config/gateway/private/key.txt",
                    "sed -i s/a/b/ ~/.config/gateway/gateway.toml",
                    "az account get-access-token"):
            marker.unlink(missing_ok=True)
            r = _run(pre, cmd)
            assert marker.exists(), f"no trigger on {cmd!r}"
            assert "sentinel" in r.stdout, (cmd, r.stdout)


def test_prefilter_passes_payload_through_to_python():
    # End to end: the real launch.sh path isn't used; we just confirm the
    # prefilter forwards the raw payload (the fake launch echoes a decision).
    import tempfile
    from pathlib import Path
    base = Path(H.tmp_base())
    with tempfile.TemporaryDirectory(dir=base) as td:
        pre, _ = _rig(Path(td) / "rig")
        r = _run(pre, "sudo ls")
        assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_prefilter_fails_open_on_empty_input():
    import tempfile
    from pathlib import Path
    base = Path(H.tmp_base())
    with tempfile.TemporaryDirectory(dir=base) as td:
        pre, marker = _rig(Path(td) / "rig")
        r = subprocess.run(["/bin/sh", str(pre)], input="", capture_output=True, env=_managed_env(pre),
                           text=True, timeout=10)
        assert r.returncode == 0 and r.stdout == ""
        assert not marker.exists()


def test_a_working_directory_under_the_gateway_folder_reaches_python():
    # `cat key.txt` has no trigger word, but the payload's cwd names the
    # gateway folder, so the Python hook still sees it (and denies it).
    import tempfile
    from pathlib import Path
    base = Path(H.tmp_base())
    with tempfile.TemporaryDirectory(dir=base) as td:
        pre, marker = _rig(Path(td) / "rig")
        for cwd in ("/home/u/.config/gateway/private", "/home/u/.config/gateway"):
            marker.unlink(missing_ok=True)
            payload = json.dumps({"tool_name": "Bash", "cwd": cwd, "permission_mode": "auto",
                                  "tool_input": {"command": "cat key.txt"}})
            r = subprocess.run(["/bin/sh", str(pre)], input=payload, capture_output=True, env=_managed_env(pre),
                               text=True, timeout=15)
            assert marker.exists() and "sentinel" in r.stdout, (cwd, r.stdout, r.stderr)


def test_the_age_identity_by_name_reaches_python():
    # verifier 2026-10 (LOW): a read of the identity through a symlinked
    # alias (`ln -s ~/.config /tmp/a; ln -s /tmp/a/gateway /tmp/b`) spells no
    # gateway path; `key.txt` is a trigger word so the Python hook still sees
    # it (vault.age / cache.age already fire on `age`).
    import tempfile
    from pathlib import Path
    base = Path(H.tmp_base())
    with tempfile.TemporaryDirectory(dir=base) as td:
        pre, marker = _rig(Path(td) / "rig")
        for cmd in ("cat /tmp/b/private/key.txt", "cp /tmp/b/private/key.txt /tmp/stolen",
                    "head -c 100 /tmp/b/private/key.txt", "cat key.txt",
                    "cat /tmp/b/private/vault.age", "cat /tmp/b/private/cache.age"):
            marker.unlink(missing_ok=True)
            r = _run(pre, cmd)
            assert marker.exists() and "sentinel" in r.stdout, f"no trigger on {cmd!r}"
        for cmd in ("cat mykey.txt", "cat key.txtx", "echo monkey"):
            marker.unlink(missing_ok=True)
            r = _run(pre, cmd)
            assert r.stdout == "" and not marker.exists(), f"false trigger on {cmd!r}"


def test_transcripts_reach_python_but_the_payloads_own_transcript_path_does_not():
    """phase B request (ux): reading Claude Code's session transcripts is
    denied by the Python hook, so `claude`/`jsonl` are triggers; the payload's
    own transcript_path field (always a .jsonl under .../claude/projects)
    must not make every command start Python."""
    import tempfile
    from pathlib import Path
    base = Path(H.tmp_base())
    with tempfile.TemporaryDirectory(dir=base) as td:
        pre, marker = _rig(Path(td) / "rig")
        tp = "/Users/x/.claude/projects/-Users-x-proj/0b5c.jsonl"
        for cmd, fires in (("ls -la", False), ("cat ~/.claude/projects/p/s.jsonl", True),
                           ("grep -r code ~/.config/claude/projects", True),
                           ("head s.jsonl", True), ("git status", False)):
            marker.unlink(missing_ok=True)
            payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd},
                                  "transcript_path": tp, "permission_mode": "auto"})
            subprocess.run(["/bin/sh", str(pre)], input=payload, capture_output=True, env=_managed_env(pre),
                           text=True, timeout=15)
            assert marker.exists() == fires, (cmd, fires)
