"""An "ask" right (ssh or remote sudo) at the ssh stand-in (group 'ssh').

Round 1 (HIGH): the stand-in counted git, rsync, scp and sftp as direct
callers and, for "ask", relied on the approval hook having asked; but the
hook only reads the command line Claude typed. `rsync -a f "box:/x; sudo id"`
ran root on a sudo = "ask" host, `git clone --upload-pack="sudo ..."` too, and
git over ssh skipped ssh = "ask". Now an "ask" right needs the ssh to be
started by Claude's own command shell (or a fork of it) with nothing in
between (ancestry.typed_by_claude); these tests use the real process tree
(`typed="real"`, CLAUDE_PID = this test) with the real rsync and git."""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess

import harness  # noqa: F401
import harness_ssh as H

PW = "correct horse battery"


def _rsync() -> str | None:
    for p in ("/usr/bin/rsync", "/opt/local/bin/rsync", "/usr/local/bin/rsync",
              "/opt/homebrew/bin/rsync"):
        if os.access(p, os.X_OK):
            return p
    return shutil.which("rsync")


def _git() -> str:
    for p in ("/opt/local/bin/git", "/usr/local/bin/git", "/opt/homebrew/bin/git", "/usr/bin/git"):
        if os.access(p, os.X_OK):
            return p
    return str(H.ENV_BIN / "git")


def _box(s: H.SshEnv, extra: str) -> H.Sshd:
    t = s.sshd("target")
    s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n{extra}')
    s.approve()
    s.host("box", t)
    return t


def _sh(s: H.SshEnv, script: str, extra: dict[str, str] | None = None
        ) -> subprocess.CompletedProcess:
    """Run a shell command line the way Claude's Bash does: this test is
    "Claude" (CLAUDE_PID), the shell its command shell."""
    env = s.proc_env({"CLAUDE_PID": str(os.getpid()), **(extra or {})})
    return subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, env=env,
                          cwd=str(s.root), timeout=90)


def _asked(s: H.SshEnv, cmd: str) -> str | None:
    """The approval hook on the command line Claude typed, in the folder _sh
    runs it in: its decision; when it is "ask" the hook records the command
    (asks.py), which the stand-in needs to pass an "ask" (lead decision
    19.14)."""
    from gateway import hooks_bash
    out = hooks_bash.main({"tool_name": "Bash", "tool_input": {"command": cmd},
                           "permission_mode": "default", "cwd": str(s.root)})
    return out["hookSpecificOutput"]["permissionDecision"] if out else None


def test_ssh_ask_refuses_ssh_started_by_another_program() -> None:
    with H.ssh_env() as s:
        t = _box(s, 'ssh = "ask"\n')
        s.set(typed=False, culprit="rsync")     # direct for credentials, not typed by Claude
        r = s.run("ssh", "box", "echo hi")
        assert r.returncode == 2 and "not the ssh that rsync starts" in r.stderr, r
        assert "ssh box CMD" in r.stderr and t.accepted() == 0
        s.set(typed=False, culprit="bash")      # a script / sh -c of its own
        r = s.run("ssh", "box", "echo hi")
        assert r.returncode == 2 and "run it as its own command so Claude Code can ask you" \
            in r.stderr, r
        s.set(typed="raise")                    # an ancestry error fails closed
        r = s.run("ssh", "box", "echo hi")
        assert r.returncode == 2 and t.accepted() == 0, r
        s.set(typed=True)
        r = s.run("ssh", "box", "echo hi")
        assert r.returncode == 0 and r.stdout == "hi\n", r


def test_a_typed_command_needs_the_hooks_record_for_every_ask_it_meets() -> None:
    """The reviewer's should-fix 5: typed by Claude is not enough for any
    "ask" the ssh stand-in meets; each needs the approval hook's record (the
    harness's `asked` knob: False is a typed command with no record). An
    "ask" policy restriction (exec) and a remote elevation "ask" (the host's
    sudo true) are refused without it and pass with it; nothing connects or
    runs root before."""
    with H.ssh_env() as s:
        t = _box(s, '[hosts.box.policy]\nexec = "ask"\n')
        s.set(typed=True, asked=False)
        r = s.run("ssh", "box", "echo hi")
        assert r.returncode != 0 and "didn't ask you about this command" in r.stderr, r
        assert "run `ssh box ...` as its own command" in r.stderr and t.accepted() == 0, r
        s.set(asked=True)
        r = s.run("ssh", "box", "echo hi")
        assert r.returncode == 0 and r.stdout == "hi\n", r
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n[hosts.box.policy]\nelevation = "ask"\n')
        s.approve()
        s.set_sudo("box", H.real_user(), PW)
        s.set(asked=False)
        r = s.run("ssh", "box", "sudo echo root")
        assert r.returncode != 0 and "didn't ask you about this command" in r.stderr, r
        assert "root" not in r.stdout and t.sudo.log() == [], r
        s.set(asked=True)
        r = s.run("ssh", "box", "sudo echo root")
        assert r.returncode == 0 and r.stdout == "root\n", r


def test_the_ssh_stand_ins_refusals_are_audited_with_their_mode() -> None:
    """Lead decision 19.8 (verify012): the ssh stand-in audits each refusal
    with the mode it decided in: the session's mode the hook recorded for a
    command Claude typed, else "modeless". The ask refusal and "no pinned
    host key" were audited with none."""
    with H.ssh_env() as s:
        t = s.sshd("target")
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nssh = "ask"\n')
        s.approve()
        s.set(typed=True, asked=False, mode="acceptEdits")
        r = s.run("ssh", "box", "true")
        assert r.returncode != 0 and "didn't ask you about this command" in r.stderr, r
        last = s.audit("refusal")[-1]
        assert last["tool"] == "ssh" and last.get("mode") == "acceptEdits", last
        s.set(asked=True, mode="auto")              # asked: on to the host key, none pinned
        r = s.run("ssh", "box", "true")
        assert r.returncode != 0 and "box has no pinned host key yet" in r.stderr, r
        last = s.audit("refusal")[-1]
        assert "no pinned host key" in last["reason"] and last.get("mode") == "auto", last
        s.set(typed=False, culprit="make")          # a script's ssh: the modeless rule
        r = s.run("ssh", "box", "true")
        assert r.returncode != 0 and "run it as its own command" in r.stderr, r
        assert s.audit("refusal")[-1].get("mode") == "modeless", s.audit("refusal")[-1]
        assert t.accepted() == 0


def test_ssh_ask_with_the_real_process_tree() -> None:
    with H.ssh_env() as s:
        t = _box(s, 'ssh = "ask"\n')
        s.set(typed="real")
        stub = str(s.stub("ssh"))
        r = _sh(s, f"{stub} box echo typed")          # typed, but the hook didn't ask: no record
        assert r.returncode != 0 and "didn't ask you about this command" in r.stderr, r
        assert "run `ssh box ...` as its own command" in r.stderr and t.accepted() == 0, r
        assert _asked(s, f"{stub} box echo typed") == "ask"
        r = _sh(s, f"{stub} box echo typed")          # Claude's shell runs it: asked by the hook
        assert r.returncode == 0 and r.stdout == "typed\n", r
        r = _sh(s, f"{stub} box echo typed")          # the record is used once
        assert r.returncode != 0 and "didn't ask you" in r.stderr, r
        assert _asked(s, f"{stub} box echo piped | cat") == "ask"
        r = _sh(s, f"{stub} box echo piped | cat")    # a pipeline stage is a fork of that shell
        assert r.returncode == 0 and r.stdout == "piped\n", r
        # a script sourced into Claude's shell: its ssh looks typed, but the hook
        # gave the `source` no decision and nothing was recorded (no prompt)
        src = s.root / "env.sh"
        src.write_text(f"{stub} box echo sourced\n")
        assert _asked(s, f". {src}") is None
        r = _sh(s, f". {src}")
        assert r.stdout == "" and "didn't ask you about this command" in r.stderr, r
        r = _sh(s, f"/bin/sh -c '{stub} box echo inner; true'; true")   # an sh -c of its own
        assert r.stdout == "" and "asks the user each time" in r.stderr, r
        script = s.root / "deploy.sh"
        script.write_text(f"#!/bin/sh\n{stub} box echo script\necho done\n")
        os.chmod(script, 0o755)
        r = _sh(s, f"{script}; true")                 # a script Claude runs
        assert r.returncode == 0 and "script" not in r.stdout, r
        assert "asks the user each time" in r.stderr
        n = t.accepted()
        rs = _rsync()
        if rs:                                        # rsync starts the ssh itself
            (s.root / "f").write_text("x")
            r = _sh(s, f"{rs} -a -e {stub} f box:{t.dir}/f")
            assert r.returncode != 0 and "asks the user each time" in r.stderr, r
            assert not (t.dir / "f").exists()
        r = subprocess.run([_git(), "ls-remote", f"box:{t.dir}/none.git"], capture_output=True,
                           text=True, timeout=90,
                           env=s.proc_env({"CLAUDE_PID": str(os.getpid()),
                                           "GIT_SSH_COMMAND": stub, "HOME": str(s.env.user_home),
                                           "GIT_CONFIG_NOSYSTEM": "1",
                                           "GIT_CONFIG_GLOBAL": "/dev/null"}))
        assert r.returncode != 0 and "not the ssh that git starts" in r.stderr, r
        assert t.accepted() == n


def test_the_whole_chain_under_one_claude_code() -> None:
    """The reviewer's should-fix 6: one stand-in for Claude Code (a python
    named `claude`) runs the real pre_bash.sh -> launch.sh -> run.py
    hook-bash on `ssh box echo chained`, then the command itself in a shell
    of its own, as Claude Code does: the record names that Claude Code and
    folder, the ssh stand-in finds it (once) and runs. A prompt the user
    declines leaves a record; the next call through the same chain (a
    sourced script, no trigger word) drops it, and the script's ssh is
    refused."""
    import json
    import types
    import harness_daemon as HD
    import test_ask_records as AR
    from gateway import ancestry, asks
    with H.ssh_env() as s:
        t = _box(s, 'ssh = "ask"\n')
        s.set(typed="real", asked="real")
        rig, pre, log = AR._real_rig(s.env)
        fc = HD.FakeClaude(types.SimpleNamespace(claudes=[]), register=False)
        try:
            from gateway import paths
            hook_env = s.env.subprocess_env({"CLAUDE_PLUGIN_DATA": str(s.env.data),
                                             "CLAUDE_PROJECT_DIR": str(s.root),
                                             "GATEWAY_TEST_RUN": str(paths.run_dir())})
            shell_env = s.proc_env({"CLAUDE_PID": str(fc.pid)})

            def hook(cmd: str) -> str | None:
                p = {"tool_name": "Bash", "tool_input": {"command": cmd},
                     "permission_mode": "default", "cwd": str(s.root), "session_id": "s-test"}
                r = fc.run(["/bin/sh", str(pre)], env=hook_env, input=json.dumps(p),
                           cwd=str(s.root))
                assert r.returncode == 0, r.stderr[-300:]
                return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] \
                    if r.stdout.strip() else None

            def shell(cmd: str) -> subprocess.CompletedProcess:
                return fc.run(["/bin/sh", "-c", cmd], env=shell_env, cwd=str(s.root))

            start = ancestry.started_at(fc.pid)
            me = f"{fc.pid}@{int(start) if start else 0}"
            assert hook("ssh box echo chained") == "ask"
            recs = [json.loads(p.read_text()) for p in asks._dir().iterdir()
                    if not p.name.startswith(".")]
            assert [r["s"] for r in recs] == [me], (recs, me)
            r = shell("ssh box echo chained")
            assert r.returncode == 0 and r.stdout == "chained\n", r
            r = shell("ssh box echo chained")
            assert r.returncode != 0 and "didn't ask you" in r.stderr, r
            n = t.accepted()
            # declined: the record stays until the next call, which drops it
            assert hook("ssh box echo declined") == "ask"
            src = s.root / "x.sh"
            src.write_text("ssh box echo declined\n")
            log.unlink(missing_ok=True)
            assert hook(f". {src}") is None
            assert log.read_text().splitlines() == ["hook-bash"]
            r = shell(f". {src}")
            assert r.stdout == "" and "didn't ask you about this command" in r.stderr, r
            assert t.accepted() == n
        finally:
            fc.close()
            shutil.rmtree(rig, ignore_errors=True)


def test_remote_sudo_ask_refused_through_rsync_and_git() -> None:
    """The reviewer's reproductions: a sudo in rsync's remote path (old rsync
    and openrsync hand it to the remote shell) and git's --upload-pack, on a
    host with ssh = true and sudo = "ask"."""
    with H.ssh_env() as s:
        t = _box(s, 'sudo = "ask"\n')
        s.set_sudo("box", H.real_user(), PW)
        s.set(typed="real")
        stub = str(s.stub("ssh"))
        rs = _rsync()
        if rs:
            (s.root / "f").write_text("x")
            r = _sh(s, f"{rs} -a -e {stub} f 'box:{t.dir}/x; sudo id'")
            assert r.returncode != 0 and "sudo on box asks the user each time" in r.stderr, r
            r = _sh(s, f"{rs} -a -e {stub} --rsync-path='sudo rsync' f box:{t.dir}/y")
            assert r.returncode != 0 and "sudo on box asks the user each time" in r.stderr, r
            # no sudo word: ssh = true, so rsync works as before
            r = _sh(s, f"{rs} -a -e {stub} f box:{t.dir}/z")
            assert r.returncode == 0 and (t.dir / "z").read_text() == "x", r
        r = subprocess.run([_git(), "clone", "-q", "--upload-pack=sudo git-upload-pack",
                            f"box:{t.dir}/none.git", str(s.root / "clone")],
                           capture_output=True, text=True, timeout=90,
                           env=s.proc_env({"CLAUDE_PID": str(os.getpid()),
                                           "GIT_SSH_COMMAND": stub, "HOME": str(s.env.user_home),
                                           "GIT_CONFIG_NOSYSTEM": "1",
                                           "GIT_CONFIG_GLOBAL": "/dev/null"}))
        assert r.returncode != 0 and "sudo on box asks the user each time" in r.stderr, r
        assert t.sudo.log() == []                      # sudo never ran on the remote
        assert not [c for c in t.commands() if "mktemp -d" in c]     # nothing staged
        # Claude's own `ssh box sudo CMD` (which the hook asks about) still works
        assert _asked(s, f"{stub} box sudo echo root") == "ask"
        r = _sh(s, f"{stub} box sudo echo root")
        assert r.returncode == 0 and r.stdout == "root\n", r


def test_ask_inside_a_gateway_terminal_or_job_is_refused_in_the_panes_wording() -> None:
    """gated's panes export CLAUDE_PID=$$ (the pane's own shell) for the direct
    rule. The ssh stand-in run by that shell, or by a script it runs, passed
    typed_by_claude, so ssh = "ask" (and an "ask" policy) went through with
    nobody asked. Now refused in the pane's wording; nothing connects."""
    import harness_sudo as HS
    from gateway import audit, consent
    with H.ssh_env() as s:
        t = _box(s, 'ssh = "ask"\n')
        s.set(typed="real")
        stub = shlex.quote(str(s.stub("ssh")))
        pane = consent.pane_ask_message(["ssh on box"])
        assert pane == ('gateway: a gateway terminal or job can\'t use the "ask" right for ssh on '
                        "box (nobody can be asked about what runs there); run it with the Bash "
                        "tool as its own command, or ask the user to set it to true.")
        sc = s.root / "pane-script.sh"
        sc.write_text(f"#!/bin/sh\n{stub} box echo hi\nexit $?\n")
        for inner in (f"{stub} box echo hi", f"/bin/sh {shlex.quote(str(sc))}"):
            r = subprocess.run(HS.pane_shell(f"{inner}; exit $?"), capture_output=True, text=True,
                               env=s.proc_env(), cwd=str(s.root), timeout=90)
            assert r.returncode == 2 and r.stderr.strip().splitlines()[-1:] == [pane], \
                (inner, r.stdout, r.stderr)
        assert audit.newest_refusal()["reason"] == pane
        assert t.accepted() == 0
        # an "ask" exec policy on a host whose ssh is true: the same in a pane
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n[hosts.box.policy]\nexec = "ask"\n')
        s.approve()
        r = subprocess.run(HS.pane_shell(f"{stub} box echo hi; exit $?"), capture_output=True,
                           text=True, env=s.proc_env(), cwd=str(s.root), timeout=90)
        assert r.returncode != 0 and "hi\n" not in r.stdout and '"ask"' in r.stderr, \
            (r.stdout, r.stderr)
        assert t.accepted() == 0


def test_ask_inside_a_checkpoint_job_gets_the_job_wording() -> None:
    """An "ask" right reached inside a checkpoint job (harness_sudo's job tree:
    checkpoint's runner -> its wrapper sh -> sh -c CMD -> the ssh stand-in) is
    refused in the approval hook's job wording: run it with the Bash tool, or
    set the right to true. "run it as its own command so Claude Code can ask
    you" led Claude to start another job (which the hook denies). With or
    without CLAUDE_PID in the job's environment, ssh = "ask" and remote
    sudo = "ask" alike; nothing connects."""
    import harness_sudo as HS
    from gateway import audit, consent
    with H.ssh_env() as s:
        t = _box(s, 'ssh = "ask"\n')
        s.set(typed="real")
        stub = str(s.stub("ssh"))
        job = consent.job_ask_message(["ssh on box"])
        assert job == ('gateway: a job can\'t use the "ask" right for ssh on box (nobody can be '
                       "asked while it runs); run it with the Bash tool as its own command, or "
                       "ask the user to set it to true.")
        for pid in ("", "parent", "self"):
            for cmd in (f"{stub} box echo hi", f"true; {stub} box echo hi; true"):
                r = HS.checkpoint_job(s.env, cmd, claude_pid=pid, extra_env=s.proc_env(),
                                      timeout=90)
                assert r.stdout.splitlines() == [job], (pid, cmd, r.stdout, r.stderr)
        assert audit.newest_refusal()["reason"] == job
        assert t.accepted() == 0
        # remote sudo = "ask" on a host whose ssh is true
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nsudo = "ask"\n')
        s.approve()
        s.set_sudo("box", H.real_user(), PW)
        r = HS.checkpoint_job(s.env, f"{stub} box sudo id", extra_env=s.proc_env(), timeout=90)
        assert r.returncode == 2 and r.stdout.splitlines() == [
            consent.job_ask_message(["sudo (root) on box"])], (r.stdout, r.stderr)
        assert t.sudo.log() == [] and t.accepted() == 0
        # outside a job the same refusal keeps the Bash wording
        r = _sh(s, f"/bin/sh -c '{stub} box sudo id; true'; true")
        assert "sudo on box asks the user each time; run it as its own command" in r.stderr, r
        assert "a job can't" not in r.stderr
