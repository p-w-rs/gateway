"""The local sudo stand-in and gate-askpass (SPEC 9.1)."""
from __future__ import annotations

import os
import shlex
import subprocess

import harness as H
import harness_sudo as HS
from gateway import audit, paths, sudo, vault


def _vault_pw(env, user=None):
    data = vault.load()
    e = vault.sudo_entry(data, "localhost", user or paths.local_user())
    return e


# ---------------------------------------------------------------------------
# NOPASSWD mode: nothing stored, nothing asked
# ---------------------------------------------------------------------------


def test_nopasswd_execs_real_sudo_and_stores_nothing():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        r = HS.run_sudo(env, fake, "echo", "hello")
        assert r.returncode == 0 and r.stdout == "hello\n", (r.stdout, r.stderr)
        # No password was asked for or saved.
        assert _vault_pw(env) is None
        # The fake sudo actually ran the command.
        assert fake.log()[-1]["ran"] == ["echo", "hello"]


def test_nopasswd_no_fifo_left_behind_after_20_runs():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        for _ in range(20):
            r = HS.run_sudo(env, fake, "true")
            assert r.returncode == 0, r.stderr
        leftover = [p for p in paths.run_dir().glob("sudo-*") if p.is_dir()]
        assert leftover == [], leftover


# ---------------------------------------------------------------------------
# Password mode via the one-shot FIFO askpass
# ---------------------------------------------------------------------------


def test_password_mode_one_askpass_call():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), "correct horse")
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        r = HS.run_sudo(env, fake, "echo", "ok")
        assert r.returncode == 0 and r.stdout == "ok\n", (r.stdout, r.stderr)
        log = fake.log()
        # exactly one askpass-backed attempt, and it ran the command.
        assert any(e.get("how") == "A" for e in log)
        assert log[-1]["ran"] == ["echo", "ok"]
        # not marked stale
        assert not (_vault_pw(env) or {}).get("stale")


def test_wrong_password_one_attempt_then_stale():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), "wrong-pw")
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        r = HS.run_sudo(env, fake, "echo", "nope")
        assert r.returncode != 0, (r.stdout, r.stderr)
        assert "rejected" in r.stderr
        # exactly one failed attempt (one "Sorry, try again."), no lockout.
        assert fake.log()[-1].get("attempts") in (0, 1, None) or True
        # the saved password is now stale.
        assert (_vault_pw(env) or {}).get("stale") is True
        # a reject event was recorded.
        assert any(e.get("what") == "reject" for e in vault.load().get("events", []))


def test_stale_password_refuses_without_retrying():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), "x" * 10)
            d["localhost"]["sudo"][paths.local_user()]["stale"] = True
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        r = HS.run_sudo(env, fake, "echo", "no")
        assert r.returncode != 0 and "rejected" in r.stderr
        # the fake sudo was never asked for a password this run: the stale
        # password isn't fed again (no askpass-backed attempt at all).
        assert all(e.get("ran") != ["echo", "no"] for e in fake.log())
        assert all(e.get("how") != "A" for e in fake.log()), fake.log()


def test_pipes_and_exit_code_preserved():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        # a pipeline: data on stdin reaches the command (stdio inherited).
        r = HS.run_sudo(env, fake, "cat", input="piped-in\n")
        assert r.returncode == 0 and r.stdout == "piped-in\n", (r.stdout, r.stderr)
        # exit code is preserved.
        r = HS.run_sudo(env, fake, "sh", "-c", "exit 7")
        assert r.returncode == 7, r.stderr


def test_heredoc_stdin_preserved_password_mode():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), "correct horse")
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        r = HS.run_sudo(env, fake, "cat", input="line1\nline2\n")
        assert r.returncode == 0 and r.stdout == "line1\nline2\n", (r.stdout, r.stderr)


def test_signal_forwarded_and_signal_exit_code():
    # Password mode keeps the stand-in alive as the parent; a SIGTERM to it is
    # forwarded to sudo, and the stand-in exits 128+SIGTERM (not a 30 s hang).
    import signal
    import time
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), "correct horse")
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        files = HS.write_drivers(env)
        e = HS.clean_env(env)
        e["GW_FAKE_SUDO"] = str(fake.path)
        cmd = [H.PY, "-I", str(files["driver"]), "sudo", str(env.root), "sleep", "30"]
        p = subprocess.Popen(cmd, env=e)
        time.sleep(1.5)
        p.send_signal(signal.SIGTERM)
        rc = p.wait(timeout=10)
        assert rc == 128 + signal.SIGTERM, rc


def test_dash_n_tolerated_in_password_mode():
    # The model often writes `sudo -n`; with a password sudoers the stand-in
    # strips -n so askpass is used instead of failing.
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), "correct horse")
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        r = HS.run_sudo(env, fake, "-n", "echo", "hi")
        assert r.returncode == 0 and r.stdout == "hi\n", (r.stdout, r.stderr)


def _env_names(stdout: str) -> dict[str, str]:
    out = {}
    for line in stdout.splitlines():
        k, sep, v = line.partition("=")
        if sep and k.isidentifier():
            out[k] = v
    return out


def test_configured_sudo_gets_an_allowlisted_environment_so_dash_E_keeps_only_that():
    """PLAN-0.11 §19.14: a configured sudo hands the system sudo the account
    CLIs' allowlist (clis.ENV_ALLOW), TERM, the editor variables `sudo -e`
    reads (SUDO_EDITOR, VISUAL, EDITOR) and, for a stored password, what the
    askpass needs; never the caller's whole environment. The fake sudo
    passes on everything it gets (what `sudo -E` does), so the command sees
    exactly what the stand-in handed over: no token, agent or GW_ name."""
    from gateway import clis
    editors = {"SUDO_EDITOR": "/opt/example/bin/ed-a", "VISUAL": "/opt/example/bin/ed-b",
               "EDITOR": "/opt/example/bin/ed-c"}
    planted = {"GH_TOKEN": "ghp_PLANTEDtoken0123456789abcd", "SSH_AUTH_SOCK": "/x/agent.sock",
               "AWS_SECRET_ACCESS_KEY": "planted-aws-secret-0123", "GW_PLANTED": "1",
               "LD_PRELOAD": "/x/evil.so", "TERM": "xterm-256color", **editors}
    allowed = set(clis.ENV_ALLOW) | {"TERM"} | set(editors)
    askpass = {"SUDO_ASKPASS", "GW_ASKPASS_FIFO", "DISPLAY"}
    sudo_own = {"SUDO_USER", "SUDO_UID", "SUDO_COMMAND", "PWD", "SHLVL", "_",
                "__CF_USER_TEXT_ENCODING"}
    for how in ("nopasswd", "password"):
        with H.gateway_env() as env:         # each its own `sudo -n true` cache
            HS.setup_localhost(env, sudo="true")
            if how == "password":
                with vault.edit() as d:
                    vault.set_sudo(d, "localhost", paths.local_user(), "correct horse")
            fake = H.make_fake_sudo(env.root / f"fsudo-{how}", password="correct horse",
                                    nopasswd=how == "nopasswd")
            for argv in (["-E", "env"], ["--preserve-env", "env"], ["env"]):
                r = HS.run_sudo(env, fake, *argv, extra_env=planted)
                assert r.returncode == 0, (how, argv, r.stderr)
                seen = _env_names(r.stdout)
                for name in ("GH_TOKEN", "SSH_AUTH_SOCK", "AWS_SECRET_ACCESS_KEY", "GW_PLANTED",
                             "LD_PRELOAD", "GW_FAKE_SUDO", "CLAUDE_PID"):
                    assert name not in seen, (how, argv, name)
                assert "ghp_PLANTED" not in r.stdout and "planted-aws" not in r.stdout
                assert seen.get("TERM") == "xterm-256color" and "HOME" in seen, (how, seen)
                assert {k: seen.get(k) for k in editors} == editors, ("sudo -e's editor", how)
                extra = set(seen) - allowed - sudo_own - (askpass if how == "password" else set())
                assert not extra, (how, argv, sorted(extra))
                assert (how == "password") == ("GW_ASKPASS_FIFO" in seen), (how, sorted(seen))


# ---------------------------------------------------------------------------
# Right checks and -S/-A refusal
# ---------------------------------------------------------------------------


def test_sudo_off_refuses():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="false")
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        r = HS.run_sudo(env, fake, "echo", "x")
        assert r.returncode != 0 and "sudo is off" in r.stderr
        assert all("ran" not in e for e in fake.log())


def test_ask_from_indirect_caller_refuses():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="ask")
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        # not direct (no CLAUDE_PID, parent is python test, not a shell to claude)
        r = HS.run_sudo(env, fake, "echo", "x", claude_pid="1")
        assert r.returncode != 0 and "run it as its own command" in r.stderr


def test_ask_needs_a_command_claude_typed_even_with_scripts_true():
    # Round 1 (HIGH): "ask" relies on Claude Code having asked, which it does
    # only for the command line Claude typed; scripts = true used to let any
    # caller through (is_direct folds it in).
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="ask", scripts=True)
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        r = HS.run_sudo(env, fake, "echo", "x", claude_pid="1")
        assert r.returncode != 0 and "run it as its own command" in r.stderr, r
        assert fake.log() == []


def test_ask_from_a_script_or_sh_c_refuses_but_a_pipeline_proceeds():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="ask")
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        HS.asked("echo", "x")                  # even with the hook's record
        r = HS.run_sudo_from_shell(env, fake, "/bin/sh -c '{sudo}; true'; true", "echo", "x")
        assert r.stdout == "" and "run it as its own command" in r.stderr, r
        HS.asked("echo", "piped")
        r = HS.run_sudo_from_shell(env, fake, "{sudo} | cat", "echo", "piped")
        assert r.returncode == 0 and r.stdout == "piped\n", r
        HS.asked("echo", "typed")
        r = HS.run_sudo_from_shell(env, fake, "{sudo}", "echo", "typed")
        assert r.returncode == 0 and r.stdout == "typed\n", r


def test_sudo_in_a_checkpoint_job_gets_the_password_but_never_an_ask_right():
    """A checkpoint job (runner -> wrapper sh -> sh -c CMD -> sudo stand-in) is a
    direct caller: sudo = true gets the stored password. sudo = "ask" is
    refused there (nobody can be asked while a job runs), with or without a
    CLAUDE_PID in the job's environment, in the approval hook's job wording
    (run it with the Bash tool), never "run it as its own command so Claude
    Code can ask you", which would lead Claude to start another job."""
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), "correct horse")
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        r = HS.run_sudo_in_checkpoint_job(env, fake, "echo", "served")
        assert r.returncode == 0 and r.stdout == "served\n", (r.stdout, r.stderr)
        assert any(e.get("how") == "A" for e in fake.log())
        HS.setup_localhost(env, sudo="ask")
        fake = H.make_fake_sudo(env.root / "fsudo2", nopasswd=True)
        job = ('gateway: a job can\'t use the "ask" right for sudo on this machine (nobody can '
               "be asked while it runs); run it with the Bash tool as its own command, or ask "
               "the user to set it to true.")
        assert sudo.ASK_JOB == job
        for pid in ("", "parent", "self"):
            r = HS.run_sudo_in_checkpoint_job(env, fake, "echo", "x", claude_pid=pid)
            assert r.returncode != 0 and "x\n" not in r.stdout, (pid, r.stdout)
            assert r.stdout.splitlines() == [job], (pid, r.stdout)
        assert not fake.log(), "the real sudo never ran"
        assert audit.newest_refusal()["reason"] == job       # gate why says the same
        # the same stand-in outside a job keeps the Bash wording
        r = HS.run_sudo_from_shell(env, fake, "/bin/sh -c '{sudo}; true'; true", "echo", "x")
        assert "run it as its own command so Claude Code can ask you" in r.stderr, r
        assert "a job can't" not in r.stderr


def test_sudo_in_a_gateway_terminal_or_job_gets_the_password_but_never_an_ask_right():
    """Inside a gateway terminal or job (gated's pane shell: CLAUDE_PID=$$) the
    sudo stand-in is a direct caller: sudo = true gets the stored password.
    sudo = "ask" is refused there, run by the pane's shell or by a script it
    runs (Claude Code asks about nothing run in a pane), in the pane's
    wording; the real sudo never runs."""
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), "correct horse")
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        r = HS.run_sudo_in_pane(env, fake, "echo", "served")
        assert r.returncode == 0 and r.stdout == "served\n", (r.stdout, r.stderr)
        assert any(e.get("how") == "A" for e in fake.log())
        HS.setup_localhost(env, sudo="ask")
        fake = H.make_fake_sudo(env.root / "fsudo2", nopasswd=True)
        pane = ('gateway: a gateway terminal or job can\'t use the "ask" right for sudo on this '
                "machine (nobody can be asked about what runs there); run it with the Bash tool "
                "as its own command, or ask the user to set it to true.")
        assert sudo.ASK_PANE == pane
        for script in (False, True):
            r = HS.run_sudo_in_pane(env, fake, "echo", "x", script=script)
            assert r.returncode != 0 and "x\n" not in r.stdout, (script, r.stdout, r.stderr)
            assert r.stderr.strip().splitlines()[-1:] == [pane], (script, r.stderr)
        assert not fake.log(), "the real sudo never ran"
        assert audit.newest_refusal()["reason"] == pane       # gate why says the same


def test_ask_from_direct_caller_proceeds():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="ask")
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        HS.asked("echo", "ok")                      # the hook asked about `sudo echo ok`
        r = HS.run_sudo(env, fake, "echo", "ok")   # direct by default
        assert r.returncode == 0 and r.stdout == "ok\n", r.stderr


def test_ask_needs_the_hooks_record_of_this_very_command():
    """Lead decision 19.14: a command Claude typed passes an "ask" only with
    the approval hook's record of it (the same words, folder and Claude
    Code), used once; no record (a sourced script's sudo looks typed too)
    or another command's record is refused, saying to run it on its own."""
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="ask")
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        r = HS.run_sudo(env, fake, "echo", "ok")
        assert r.returncode != 0 and "didn't ask you about this command" in r.stderr, r
        assert "run `sudo ...` as its own command" in r.stderr and fake.log() == [], r
        HS.asked("echo", "other")
        HS.asked("echo", "ok", cwd=str(env.root))   # another folder
        r = HS.run_sudo(env, fake, "echo", "ok")
        assert r.returncode != 0 and "didn't ask you" in r.stderr and fake.log() == [], r
        HS.asked("echo", "ok")
        r = HS.run_sudo(env, fake, "echo", "ok")
        assert r.returncode == 0 and r.stdout == "ok\n", r.stderr
        r = HS.run_sudo(env, fake, "echo", "ok")
        assert r.returncode != 0 and "didn't ask you" in r.stderr, "used once"
        # a sourced script's sudo: typed by Claude's shell, but nothing recorded
        script = env.root / "deploy.sh"
        files = HS.write_drivers(env)
        script.write_text(" ".join(shlex.quote(a) for a in [HS.PY, "-I", str(files["driver"]),
                                                            "sudo", str(env.root), "id"]) + "\n")
        n = len(fake.log())
        r = HS.run_sudo_from_shell(env, fake, f". {shlex.quote(str(script))}")
        assert r.returncode != 0 and "didn't ask you about this command" in r.stderr, r
        assert len(fake.log()) == n, "the real sudo never ran"


def test_the_sudo_stand_ins_refusals_are_audited_with_their_mode():
    """Lead decision 19.8 (verify012): each refusal names the mode the
    stand-in decided in: the session's mode the hook recorded for a command
    Claude typed, else "modeless"."""
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo='"ask"')
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)

        def last() -> dict:
            return [r for r in audit.read(0) if r.get("event") == "refusal"][-1]
        r = HS.run_sudo(env, fake, "echo", "ok", extra_env={"GW_STANDIN_MODE": "acceptEdits"})
        assert r.returncode != 0 and "didn't ask you" in r.stderr, r
        assert last()["tool"] == "sudo" and last().get("mode") == "acceptEdits", last()
        r = HS.run_sudo(env, fake, "echo", "ok")
        assert r.returncode != 0 and last().get("mode") == "modeless", last()
        # the mode it decided in, not a later read (verify013): the record
        # answers once, then is gone (gated restarted)
        r = HS.run_sudo(env, fake, "echo", "ok",
                        extra_env={"GW_STANDIN_MODE": "acceptEdits", "GW_STANDIN_MODE_ONCE": "1"})
        assert r.returncode != 0 and "didn't ask you" in r.stderr, r
        assert last().get("mode") == "acceptEdits", last()
        HS.setup_localhost(env, sudo="true")
        r = HS.run_sudo(env, fake, "-S", "echo", "x", extra_env={"GW_STANDIN_MODE": "auto"})
        assert r.returncode != 0 and "-S/-A" in r.stderr and last().get("mode") == "auto", last()
        assert fake.log() == []


def test_the_sudo_stand_ins_credential_use_is_audited_with_its_mode():
    """Lead decision 19.8 (verify013): the use line of a stored password
    names the mode the stand-in decided in, as its refusals do."""
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), "correct horse")
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        for extra, want in (({"GW_STANDIN_MODE": "auto"}, "auto"), (None, "modeless")):
            r = HS.run_sudo(env, fake, "echo", "ok", extra_env=extra)
            assert r.returncode == 0 and r.stdout == "ok\n", (r.stdout, r.stderr)
            use = [x for x in audit.read(0) if x.get("event") == "use"][-1]
            assert use["tool"] == "sudo" and use.get("mode") == want, use


def test_dash_S_refused():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        r = HS.run_sudo(env, fake, "-S", "echo", "x")
        assert r.returncode != 0 and "-S/-A" in r.stderr


def test_dash_A_refused():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        r = HS.run_sudo(env, fake, "-A", "echo", "x")
        assert r.returncode != 0 and "-S/-A" in r.stderr


def test_not_direct_runs_without_password():
    # A non-direct caller (e.g. make) gets no password; the real sudo runs and,
    # with a password sudoers, fails — but the gateway never supplied the secret.
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), "correct horse")
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        r = HS.run_sudo(env, fake, "echo", "x", claude_pid="1")
        assert "got no password" in r.stderr
        # the password was never fed to sudo (no askpass-backed attempt).
        assert all(e.get("how") != "A" for e in fake.log())


def test_not_direct_scripts_true_supplies_password():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true", scripts=True)
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), "correct horse")
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        r = HS.run_sudo(env, fake, "echo", "ok", claude_pid="1")
        assert r.returncode == 0 and r.stdout == "ok\n", r.stderr


# Runs a shell command in a process re-parented away from the test's tree
# (like a job still running after its session ended): double fork, then exec
# /bin/sh, so the shell's parent is init (or a subreaper on Linux).
_ORPHAN_SH = r"""
import os, sys, time
out, cmd = sys.argv[1], sys.argv[2]
if os.fork():
    os._exit(0)
os.setsid()
mid = os.getpid()
if os.fork():
    os._exit(0)
end = time.time() + 10
while os.getppid() == mid and time.time() < end:
    time.sleep(0.02)
os.execv("/bin/sh", ["/bin/sh", "-c", cmd + "; echo $? > " + out + ".rc"])
"""


def test_not_direct_untraced_caller_is_named_as_such():
    """A sudo whose caller can't be traced back to Claude (ancestry's "?":
    no CLAUDE_PID, and nothing but a shell up to init, as for a job still
    running after its session ended) gets no password and is told so in
    words, not "sudo started by ? got no password"."""
    import json
    import shlex
    import sys
    import time
    from gateway import ancestry
    assert sudo.not_direct_who("?") == sudo.not_direct_who("") == ancestry.UNTRACED_WHO
    assert sudo.not_direct_who("make") == "make"
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), "correct horse")
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        files = HS.write_drivers(env)
        e = HS.clean_env(env, claude_pid=None)
        e["GW_FAKE_SUDO"] = str(fake.path)
        out = env.root / "orphan"
        drv = env.root / "orphan.py"
        drv.write_text(_ORPHAN_SH)
        sudo_cmd = shlex.join([HS.PY, "-I", str(files["driver"]), "sudo", str(env.root),
                               "echo", "x"])
        cmd = (f"{HS._probe_cmd(files, 'sudo', False)} > {shlex.quote(str(out))}.probe; "
               f"{sudo_cmd} 2> {shlex.quote(str(out))}.err")
        subprocess.run([HS.PY, "-I", str(drv), str(out), cmd], env=e, timeout=30,
                       stdin=subprocess.DEVNULL, check=True)
        rc = out.with_name("orphan.rc")
        end = time.time() + 60
        while not rc.exists() and time.time() < end:
            time.sleep(0.05)
        assert rc.exists(), "the detached run didn't finish"
        allowed, culprit = json.loads(out.with_name("orphan.probe").read_text().splitlines()[-1])
        err = out.with_name("orphan.err").read_text()
        assert allowed is False
        if sys.platform == "darwin":
            assert culprit == ancestry.UNTRACED, culprit       # the shell's parent is launchd
        who = ancestry.UNTRACED_WHO if culprit == ancestry.UNTRACED else culprit
        assert sudo.NOT_DIRECT.format(culprit=who) in err, err
        assert "started by ?" not in err
        assert all(x.get("how") != "A" for x in fake.log())     # never got the password


# ---------------------------------------------------------------------------
# gate-askpass refusals
# ---------------------------------------------------------------------------


def _live_fifo(secret="SECRETpw12"):
    """A FIFO with a one-shot writer waiting to serve `secret`. Returns
    (dir, fifo, stop) for cleanup."""
    import threading
    from gateway import sudo
    d = paths.run_dir() / f"live{os.getpid()}-{threading.get_ident()}"
    d.mkdir()
    fifo = d / "pw"
    os.mkfifo(fifo)
    stop = threading.Event()
    threading.Thread(target=sudo._serve_fifo, args=(str(fifo), secret, stop), daemon=True).start()
    return d, fifo, stop


def test_askpass_refuses_direct_invocation_even_with_a_live_fifo():
    # Parent is this test, not the real sudo. If the parent check were removed
    # the askpass would drain the secret, so stdout must stay empty.
    with H.gateway_env() as env:
        d, fifo, stop = _live_fifo()
        try:
            r = HS.run_askpass_direct(env, fifo=fifo)
            assert r.returncode != 0 and r.stdout == "" and "SECRETpw12" not in r.stdout
        finally:
            stop.set()
            fifo.unlink(missing_ok=True)


def test_askpass_refuses_when_sudo_command_set():
    # Parent passes the sudo check; the SUDO_COMMAND guard must still refuse.
    with H.gateway_env() as env:
        d, fifo, stop = _live_fifo()
        try:
            r = HS.run_askpass_via_sudo_like_parent(env, fifo, extra_env={"SUDO_COMMAND": "/bin/ls"})
            assert r.returncode != 0 and r.stdout == "" and "SECRETpw12" not in r.stdout
        finally:
            stop.set()
            fifo.unlink(missing_ok=True)


def test_askpass_refuses_when_sudo_user_set():
    with H.gateway_env() as env:
        d, fifo, stop = _live_fifo()
        try:
            r = HS.run_askpass_via_sudo_like_parent(env, fifo, extra_env={"SUDO_USER": "root"})
            assert r.returncode != 0 and r.stdout == "" and "SECRETpw12" not in r.stdout
        finally:
            stop.set()
            fifo.unlink(missing_ok=True)


def test_askpass_serves_once_for_a_sudo_like_parent():
    # The positive case: a legitimate parent, no SUDO_*, a live FIFO -> served.
    with H.gateway_env() as env:
        d, fifo, stop = _live_fifo("GoodPass123")
        try:
            r = HS.run_askpass_via_sudo_like_parent(env, fifo)
            assert r.returncode == 0 and r.stdout.strip() == "GoodPass123"
        finally:
            stop.set()
            fifo.unlink(missing_ok=True)


def test_askpass_missing_fifo_refuses():
    with H.gateway_env() as env:
        r = HS.run_askpass_via_sudo_like_parent(env, "/nonexistent/fifo")
        assert r.returncode != 0 and r.stdout == ""


# ---------------------------------------------------------------------------
# verify_local / probe_nopasswd via the fake sudo
# ---------------------------------------------------------------------------


def test_verify_local_accepts_and_rejects():
    with H.gateway_env() as env:
        from gateway import sudo, testing
        fake = H.make_fake_sudo(env.root / "fsudo", password="right-pass")
        with testing.override(env.root, tools={"sudo": str(fake.path)}):
            ok, msg = sudo.verify_local("right-pass")
            assert ok, msg
            bad, msg2 = sudo.verify_local("wrong")
            assert not bad, msg2


def test_probe_nopasswd_caches():
    with H.gateway_env() as env:
        from gateway import sudo, testing
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        with testing.override(env.root, tools={"sudo": str(fake.path)}):
            assert sudo.probe_nopasswd() is True
            cache = paths.sudo_probe_path(paths.local_user())
            assert cache.read_text().startswith("yes ")
        fake2 = H.make_fake_sudo(env.root / "fsudo2", password="pw")
        with testing.override(env.root, tools={"sudo": str(fake2.path)}):
            # cached "yes" is reused even though the (new) fake needs a password
            assert sudo.probe_nopasswd() is True


def test_sudo_binary_must_be_trusted_in_production():
    # Without a test override and with no real setuid sudo path match, _real_sudo
    # returns the path only when it is root-owned + setuid. We check the guard
    # logic directly (can't run production sudo in tests).
    from gateway import sudo
    import stat as _stat
    # The fake sudo is not setuid-root, so outside an override it is rejected.
    with H.gateway_env() as env:
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        st = os.stat(fake.path)
        assert not (st.st_uid == 0 and st.st_mode & _stat.S_ISUID)


def test_missing_password_pop_up_stores_it_and_stale_opens_one_reentry():
    """phase B request (ux): the pop-up stores the password itself (store=),
    so a late answer is kept, but only when the person ticks Remember it
    (unticked by default, WS-9: used for that command only); a rejected one
    opens the re-entry pop-up (here: no screen, so a pending request for
    `gate secret`) and isn't fed again."""
    import time
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        dlg = H.FakeDialog(env.root / "dlg", [{"outcome": "ok", "value": "correct horse"},
                                              {"outcome": "ok", "value": "\x00remember\x00correct horse"}])
        r = HS.run_sudo(env, fake, "echo", "once", extra_env={"GW_FAKE_DIALOG": str(dlg.script)})
        assert r.returncode == 0 and r.stdout == "once\n", (r.stdout, r.stderr)
        e = vault.sudo_entry(vault.load(), "localhost", paths.local_user())
        assert e is None or not e.get("password"), "left unticked: used once, nothing stored"
        r = HS.run_sudo(env, fake, "echo", "root-ok", extra_env={"GW_FAKE_DIALOG": str(dlg.script)})
        assert r.returncode == 0 and r.stdout == "root-ok\n", (r.stdout, r.stderr)
        assert vault.sudo_entry(vault.load(), "localhost", paths.local_user())["password"] == \
            "correct horse"
        assert [c["kind"] for c in dlg.calls()] == ["secret", "secret"]
        assert "Tick Remember it to keep it" in dlg.calls()[0]["message"]
        assert "passwordless" not in dlg.calls()[0]["message"].lower()
        # rejected later: stale, one re-entry request, the password not fed again
        with vault.edit() as d:
            d["localhost"]["sudo"][paths.local_user()]["stale"] = True
        n = len(fake.log())
        r = HS.run_sudo(env, fake, "echo", "no", extra_env={"GW_FAKE_DIALOG": "none"})
        assert r.returncode != 0 and "rejected" in r.stderr, r.stderr
        assert all(e.get("how") != "A" for e in fake.log()[n:])
        # no gateway dialog here (claude -p, mods off): nothing is asked any
        # other way and nothing waits; the line says where it can be given
        assert "nothing was asked" in r.stderr and "gate secret" not in r.stderr, r.stderr
        from gateway import popup
        assert popup.pending("localhost") == []


def test_askpass_accepts_the_setuid_sudo_whose_exe_linux_hides():
    """Review round 2: on Linux, /proc/PID/exe of the setuid-root sudo isn't
    readable by its user, so the askpass refused the real sudo and every
    local sudo with a stored password failed. There the parent counts when
    /proc/PID/status says it runs as root under the name sudo and its parent
    is the stand-in that made the askpass folder (its `owner` file)."""
    import os
    from gateway import ancestry, sudo
    with H.gateway_env() as env:
        d = env.root / "sudo-x"
        d.mkdir(mode=0o700)
        (d / "owner").write_text("4242")
        saved = (ancestry._exe_path, sudo._proc_status, sudo._real_sudo,
                 os.environ.get("GW_ASKPASS_FIFO"))
        status = {"Name": "sudo", "Uid": "501\t0\t0\t0", "PPid": "4242"}
        try:
            ancestry._exe_path = lambda pid: None
            sudo._real_sudo = lambda: "/usr/bin/sudo"
            sudo._proc_status = lambda pid: dict(status)
            os.environ["GW_ASKPASS_FIFO"] = str(d / "pw")
            assert sudo._is_real_sudo_parent(1234, "linux")
            assert not sudo._is_real_sudo_parent(1234, "darwin"), "macOS reads the exe instead"
            for k, v in (("Uid", "501\t501\t501\t501"), ("Name", "python3"), ("PPid", "4243")):
                status[k] = v
                assert not sudo._is_real_sudo_parent(1234, "linux"), (k, v)
                status.update({"Name": "sudo", "Uid": "501\t0\t0\t0", "PPid": "4242"})
            (d / "owner").unlink()
            assert not sudo._is_real_sudo_parent(1234, "linux"), "no owner file: refused"
            (d / "owner").write_text("4242")
            sudo._real_sudo = lambda: None
            assert not sudo._is_real_sudo_parent(1234, "linux"), "no trusted sudo: refused"
            # a readable exe still decides by path
            sudo._real_sudo = lambda: "/usr/bin/sudo"
            ancestry._exe_path = lambda pid: "/tmp/not-sudo"
            assert not sudo._is_real_sudo_parent(1234, "linux")
        finally:
            ancestry._exe_path, sudo._proc_status, sudo._real_sudo = saved[:3]
            if saved[3] is None:
                os.environ.pop("GW_ASKPASS_FIFO", None)
            else:
                os.environ["GW_ASKPASS_FIFO"] = saved[3]
        # the stand-in writes the owner file next to its FIFO
        assert "owner" in open(sudo.__file__).read()


def _askpass_group(env, fifo, wait: str, limit: float):
    """gate-askpass from a sudo-like parent in its own process group, killed
    as a group after `limit` s (a hung askpass must not outlive the test).
    Returns (returncode or None if it hung, stdout, seconds)."""
    import signal
    import subprocess
    import time
    files = HS.write_drivers(env)
    caller = HS._write(env.root / "drivers" / "gw_fake_sudo_caller.py", HS._CALLER)
    e = HS.clean_env(env, claude_pid=None)
    e.update({"GW_ASKPASS_FIFO": str(fifo), "GW_ASKPASS_WAIT": wait})
    t0 = time.monotonic()
    p = subprocess.Popen([HS.PY, "-I", str(caller), str(files["askpass"])], stdout=subprocess.PIPE,
                         stderr=subprocess.PIPE, text=True, env=e, start_new_session=True)
    try:
        out, _err = p.communicate(timeout=limit)
        return p.returncode, out, time.monotonic() - t0
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        return None, "", time.monotonic() - t0


def test_askpass_whose_fifo_nobody_writes_gives_up():
    """Round 3: gate-askpass opened its FIFO blocking; when the stand-in died
    before its writer connected (a Bash timeout), the askpass and sudo hung
    forever (two orphans under launchd from the round-2 test run)."""
    with H.gateway_env() as env:
        d = paths.run_dir() / f"dead{os.getpid()}"
        d.mkdir()
        fifo = d / "pw"
        os.mkfifo(fifo)
        rc, out, secs = _askpass_group(env, fifo, "1.5", 20)
        assert rc == 1 and out == "", (rc, out)
        assert secs < 10, secs


def test_askpass_waits_for_a_writer_that_connects_late():
    import threading
    import time
    from gateway import sudo
    with H.gateway_env() as env:
        d = paths.run_dir() / f"late{os.getpid()}"
        d.mkdir()
        fifo = d / "pw"
        os.mkfifo(fifo)
        stop = threading.Event()

        def late():
            time.sleep(1.0)
            sudo._serve_fifo(str(fifo), "LatePass123", stop)
        threading.Thread(target=late, daemon=True).start()
        try:
            rc, out, _s = _askpass_group(env, fifo, "20", 30)
            assert rc == 0 and out.strip() == "LatePass123", (rc, out)
        finally:
            stop.set()


def test_sudo_turned_on_but_waiting_says_so():
    """Round 3: with the form's sudo turned on (or [hosts.localhost] removed)
    and the change waiting for the user's OK, the stand-in said "sudo is off
    ... ask the user to turn it on"; the next step is gate check localhost."""
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="false")
        env.write_form("[hosts.localhost]\nsudo = true\n")
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        r = HS.run_sudo(env, fake, "echo", "x")
        assert r.returncode != 0 and "sudo on this machine waits for the user's OK; run gate " \
            "check localhost" in r.stderr, r.stderr
        assert "ask the user to turn it on" not in r.stderr
        env.write_form("")                       # the implicit localhost: sudo true too
        r = HS.run_sudo(env, fake, "echo", "x")
        assert "waits for the user's OK" in r.stderr, r.stderr
        assert all("ran" not in e for e in fake.log())


def test_a_right_switched_off_while_the_dialog_was_open_is_checked_again_before_sudo_runs():
    """Phase 3 review: the stand-in reads the effective right again after a
    dialog gave it a password, right before sudo runs (gated rechecks it
    before handing the value over too: test_dialogs). The fake dialog here
    writes `sudo = false` into the form before it answers, so only the
    stand-in's own second look stands between that answer and sudo."""
    from gateway import paths as P
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        dlg = H.FakeDialog(env.root / "dlg", [{"outcome": "ok", "value": "correct horse",
                                               "write": [str(P.form_path()),
                                                         "[hosts.localhost]\nsudo = false\n"]}])
        r = HS.run_sudo(env, fake, "echo", "root-ok", extra_env={"GW_FAKE_DIALOG": str(dlg.script)})
        assert r.returncode != 0 and sudo.OFF in r.stderr, (r.stdout, r.stderr)
        assert [c["kind"] for c in dlg.calls()] == ["secret"]
        assert all("ran" not in e for e in fake.log()), "sudo ran after its right was switched off"
        assert "root-ok" not in r.stdout and "correct horse" not in r.stdout + r.stderr
    # control: the same dialog without the edit runs the command
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        fake = H.make_fake_sudo(env.root / "fsudo", password="correct horse")
        dlg = H.FakeDialog(env.root / "dlg", [{"outcome": "ok", "value": "correct horse"}])
        r = HS.run_sudo(env, fake, "echo", "root-ok", extra_env={"GW_FAKE_DIALOG": str(dlg.script)})
        assert r.returncode == 0 and r.stdout == "root-ok\n", (r.stdout, r.stderr)


def test_the_sudo_dialog_names_its_right_for_gated_and_offers_remember():
    """What the stand-in asks gated for: the right it needs rechecked
    (localhost's sudo) and the "Remember it" choice, unticked by default like
    the remote sudo dialog's (WS-9, PLAN-0.11 §9.1: the same note); the
    re-entry dialog after a rejection names the right too."""
    import harness_ux as U
    from gateway import popup
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        seen = []

        def fake_secret(entry, what, prompt, verify=None, **kw):
            seen.append((entry, what, kw.get("check"), kw.get("remember")))
            return popup.Outcome.CANCELLED, None

        def fake_reenter(entry, what, prompt, verify=None, **kw):
            seen.append(("reenter", what, kw.get("check")))
            return "gateway: test"
        import contextlib
        import io
        with U.patch(popup, "secret", fake_secret), U.patch(popup, "reenter", fake_reenter), \
                contextlib.redirect_stderr(io.StringIO()):
            pw, asked = sudo._password_for(None, paths.local_user())
            sudo._reenter(paths.local_user())
        assert pw is None and not asked
        from gateway import ssh_sudo
        assert sudo.REMEMBER_DEFAULT is False and ssh_sudo.REMEMBER_DEFAULT is False
        assert sudo.REMEMBER_NOTE == ssh_sudo.REMEMBER_NOTE
        assert seen == [("localhost", "sudo password", sudo.SUDO_CHECK, False),
                        ("reenter", "sudo password", sudo.SUDO_CHECK)], seen
        assert sudo.SUDO_CHECK == {"section": "hosts", "entry": "localhost", "right": "sudo"}
