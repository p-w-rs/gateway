"""Rejected-password detection from sudo's stderr (SPEC 9.1 step 5), the
stderr relay, and the -S/-A long-option refusal (SPEC 9.1 step 2).
Regressions for the 2026-10 verification."""
from __future__ import annotations

import harness as H
import harness_sudo as HS


# ---------------------------------------------------------------------------
# passwd_tries=1: sudo never calls askpass twice
# ---------------------------------------------------------------------------


def test_wrong_password_under_passwd_tries_1_is_marked_stale():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        HS.save_local_password("wrong-password-1")
        fake = HS.OneTryFakeSudo(env.root / "f1", password="correct horse")
        r = HS.run_sudo(env, fake, "echo", "nope")
        assert r.returncode == 1, (r.stdout, r.stderr)
        assert "incorrect password attempt" in r.stderr     # sudo's own line, relayed
        assert "rejected" in r.stderr                        # the gateway's line
        assert (HS.local_entry() or {}).get("stale") is True
        # exactly one askpass-backed attempt
        attempts = [e for e in fake.log() if e.get("how") == "A"]
        assert len(attempts) == 1 and attempts[0]["ok"] is False
        # and the stale password is not fed again on the next run
        r2 = HS.run_sudo(env, fake, "echo", "again")
        assert r2.returncode != 0 and "rejected" in r2.stderr
        assert len([e for e in fake.log() if e.get("how") == "A"]) == 1


def test_sorry_try_again_alone_is_also_a_rejection():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        HS.save_local_password("wrong-password-2")
        fake = HS.OneTryFakeSudo(env.root / "f2", password="correct horse",
                                 message="Sorry, try again.")
        r = HS.run_sudo(env, fake, "echo", "nope")
        assert r.returncode == 1
        assert (HS.local_entry() or {}).get("stale") is True


def test_right_password_under_passwd_tries_1_runs_and_stays_fresh():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        HS.save_local_password("correct horse")
        fake = HS.OneTryFakeSudo(env.root / "f3", password="correct horse")
        r = HS.run_sudo(env, fake, "echo", "ok")
        assert r.returncode == 0 and r.stdout == "ok\n", (r.stdout, r.stderr)
        assert not (HS.local_entry() or {}).get("stale")


def test_command_printing_the_message_but_succeeding_is_not_a_rejection():
    # Only a failing sudo whose password was served counts; a command that
    # prints the words itself and exits 0 doesn't mark the password stale.
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        HS.save_local_password("correct horse")
        fake = H.make_fake_sudo(env.root / "f4", password="correct horse")
        r = HS.run_sudo(env, fake, "sh", "-c", "echo 'Sorry, try again.' >&2; exit 0")
        assert r.returncode == 0 and "Sorry, try again." in r.stderr
        assert not (HS.local_entry() or {}).get("stale")


# ---------------------------------------------------------------------------
# The stderr relay: output still arrives, stdio otherwise inherited
# ---------------------------------------------------------------------------


def test_stderr_and_stdout_and_stdin_still_flow_in_password_mode():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        HS.save_local_password("correct horse")
        fake = H.make_fake_sudo(env.root / "f5", password="correct horse")
        r = HS.run_sudo(env, fake, "sh", "-c", "cat; echo to-err >&2; echo to-out; exit 3",
                        input="from-stdin\n")
        assert r.returncode == 3, r.stderr
        assert r.stdout == "from-stdin\nto-out\n"
        assert "to-err" in r.stderr


def test_password_never_appears_on_relayed_stderr():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        pw = "correct horse battery"
        HS.save_local_password(pw)
        fake = H.make_fake_sudo(env.root / "f6", password=pw)
        r = HS.run_sudo(env, fake, "sh", "-c", f"echo 'x {pw} y' >&2")
        assert r.returncode == 0, r.stderr
        assert pw not in r.stderr and "***" in r.stderr


# ---------------------------------------------------------------------------
# -S / -A: long forms and abbreviations are refused too; a command's own
# options are not sudo's
# ---------------------------------------------------------------------------


def test_long_stdin_and_askpass_are_refused():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        fake = H.make_fake_sudo(env.root / "f7", nopasswd=True)
        for opt in ("--stdin", "--askpass", "--std", "--ask", "--askpass=x"):
            r = HS.run_sudo(env, fake, opt, "echo", "x")
            assert r.returncode != 0 and "-S/-A" in r.stderr, (opt, r.stderr)
        # after a value-taking option, too
        r = HS.run_sudo(env, fake, "-u", "root", "--stdin", "echo", "x")
        assert r.returncode != 0 and "-S/-A" in r.stderr
        r = HS.run_sudo(env, fake, "--user", "root", "-S", "echo", "x")
        assert r.returncode != 0 and "-S/-A" in r.stderr
        assert all("ran" not in e for e in fake.log())


def test_command_options_after_the_command_are_not_sudo_options():
    # `sudo ls -A` is ls's -A; sudo stops at the first non-option word.
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        fake = H.make_fake_sudo(env.root / "f8", nopasswd=True)
        r = HS.run_sudo(env, fake, "printf", "%s\n", "-A")
        assert r.returncode == 0 and r.stdout == "-A\n", r.stderr
        r = HS.run_sudo(env, fake, "-u", "root", "printf", "%s\n", "-S")
        assert r.returncode == 0 and r.stdout == "-S\n", r.stderr


def test_long_non_interactive_is_stripped_in_password_mode():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        HS.save_local_password("correct horse")
        fake = H.make_fake_sudo(env.root / "f9", password="correct horse")
        r = HS.run_sudo(env, fake, "--non-interactive", "echo", "hi")
        assert r.returncode == 0 and r.stdout == "hi\n", (r.stdout, r.stderr)


def test_option_scanner_units():
    from gateway import sudo as S
    yes = [["--stdin", "cat"], ["--askpass", "cat"], ["--std", "cat"], ["-nS", "x"],
           ["-E", "-A", "x"], ["--user", "root", "-S", "x"], ["-C", "3", "-S", "x"],
           ["--preserve-env=PATH", "-A", "x"]]
    no = [["ls", "-A"], ["-u", "root", "ls", "-S"], ["-uS", "ls"], ["--user", "-S"],
          ["--", "-S"], ["-hS"], ["printf", "--stdin"]]
    for a in yes:
        assert S._has_S_or_A(a), a
    for a in no:
        assert not S._has_S_or_A(a), a
    assert S._strip_n(["-n", "ls", "-n"]) == ["ls", "-n"]
    assert S._strip_n(["-nH", "ls"]) == ["-H", "ls"]
    assert S._strip_n(["-nu", "root", "ls"]) == ["-u", "root", "ls"]
    assert S._strip_n(["-unobody", "ls"]) == ["-unobody", "ls"]
    assert S._strip_n(["--non-interactive", "ls"]) == ["ls"]
    assert S._strip_n(["--", "-n"]) == ["--", "-n"]


def test_relayed_stderr_releases_a_held_prefix_after_a_quiet_moment():
    """Review round 2: the relay's scrubber held back bytes that could still
    become the password until sudo exited, so a prompt on stderr that starts
    like the password ("c" for "correct horse battery") waited for EOF."""
    import os
    import select
    import subprocess
    import time
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        pw = "correct horse battery"
        HS.save_local_password(pw)
        fake = H.make_fake_sudo(env.root / "f7", password=pw)
        files = HS.write_drivers(env)
        e = HS.clean_env(env, None, claude_pid="self")
        e["GW_FAKE_SUDO"] = str(fake.path)
        p = subprocess.Popen([HS.PY, "-I", str(files["driver"]), "sudo", str(env.root), "sh", "-c",
                              "printf c >&2; sleep 4; printf X >&2"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e)
        try:
            t0 = time.monotonic()
            got = b""
            while b"c" not in got and time.monotonic() - t0 < 10:
                r, _, _ = select.select([p.stderr], [], [], 10)
                if not r:
                    break
                chunk = os.read(p.stderr.fileno(), 100)
                if not chunk:
                    break
                got += chunk
            waited = time.monotonic() - t0
            assert got.endswith(b"c") and waited < 3.5, (got, waited)
            rest = p.communicate(timeout=20)[1]
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
        assert rest.endswith(b"X") and pw.encode() not in got + rest, rest
