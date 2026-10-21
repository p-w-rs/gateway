"""Remote sudo over the ssh stand-in (group 'ssh', SPEC 9.3 hardened: see
ssh_sudo's docstring) against a real sshd whose PATH has the fake password
sudo. The remote askpass answers only a root parent; the harness's
`ssh_remote_euid` override reports the fake sudo as root."""
from __future__ import annotations

import codecs
import json
import os
import subprocess
from pathlib import Path

import harness  # noqa: F401
import harness_ssh as H
from gateway import ssh, ssh_sudo, vault

PW = "correct horse battery"


def _box(s: H.SshEnv, extra: str = "", **kw: object) -> H.Sshd:
    t = s.sshd("target", **kw)
    s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n{extra}')
    s.approve()
    s.host("box", t)
    return t


def _runs(t: H.Sshd, word: str) -> list[dict]:
    return [e for e in t.sudo.log() if word in e.get("argv", [])]


def _staged(t: H.Sshd) -> list[str]:
    return [c for c in t.commands() if "mktemp -d" in c]


def _verifies(t: H.Sshd) -> list[str]:
    return [c for c in t.commands() if c.endswith("sudo -k -A -v")]


def _attempts(t: H.Sshd) -> int:
    """Password attempts the remote sudo saw (wrong answers)."""
    return sum(int(e.get("attempts") or 0) for e in t.sudo.log())


def _set_remote_password(t: H.Sshd, pw: str) -> None:
    cfg = json.loads((t.sudo.dir / "config.json").read_text())
    cfg["password"] = pw
    (t.sudo.dir / "config.json").write_text(json.dumps(cfg))


def test_ssh_sudo_direct_with_password() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        s.set_sudo("box", H.real_user(), PW)
        r = s.run("ssh", "box", "sudo", "echo", "root-ok")
        assert r.returncode == 0 and r.stdout == "root-ok\n", r
        run = _runs(t, "root-ok")
        assert len(run) == 1 and run[0]["how"] == "A" and run[0]["code"] == 0
        assert run[0]["askpass"].startswith(str(t.xdg) + "/gw.")
        cmds = t.commands()
        assert cmds[0] == "sudo -n true"                    # the probe
        assert "mktemp -d" in cmds[1]                       # staging
        assert cmds[2].startswith("SUDO_ASKPASS=") and cmds[2].endswith("sudo -k -A -v")  # verify
        # scripts = false: the askpass is a shell function for this command only
        assert cmds[3].startswith("sudo() { SUDO_ASKPASS=") and cmds[3].endswith(
            "command sudo \"$@\"; }; sudo echo root-ok"), cmds
        assert "export" not in cmds[3]
        assert cmds[4].startswith("d=") and "rm -rf --" in cmds[4]     # cleanup
        assert list(t.xdg.iterdir()) == []                  # nothing left on the remote
        use = s.audit("use")[-1]
        assert use["remote_sudo"] is True and PW not in str(s.audit())
        # probe and verification are cached for 10 minutes
        r = s.run("ssh", "box", "sudo true")
        assert r.returncode == 0 and t.commands().count("sudo -n true") == 1
        assert len(_verifies(t)) == 1 and len(_staged(t)) == 2


def test_ssh_sudo_nested_with_scripts_and_piped_stdin() -> None:
    with H.ssh_env() as s:
        t = _box(s, extra="scripts = true\n")
        s.set_sudo("box", H.real_user(), PW)
        r = s.run("ssh", "box", "sh -c 'sudo echo nested; sudo echo twice'")
        assert r.returncode == 0 and r.stdout == "nested\ntwice\n", r
        assert all(e["how"] == "A" for e in _runs(t, "nested") + _runs(t, "twice"))
        assert [c for c in t.commands() if "sudo echo nested" in c][0].startswith(
            "export SUDO_ASKPASS=")                       # scripts = true: SPEC 9.3 step 3
        out = t.dir / "tee-out.txt"
        r = s.run("ssh", "box", f"sudo tee {out}", input="payload line\n")
        assert r.returncode == 0 and r.stdout == "payload line\n", r
        assert out.read_text() == "payload line\n"          # the password never reached stdin
        assert PW not in out.read_text()
        assert list(t.xdg.iterdir()) == []


def test_ssh_sudo_scripts_false_only_command_position() -> None:
    """scripts = false: sudo in a nested shell or after a wrapper gets no
    password (with a hint); a sudo word that isn't a command stages nothing."""
    with H.ssh_env() as s:
        t = _box(s)
        s.set_sudo("box", H.real_user(), PW)
        r = s.run("ssh", "box", "sh -c 'sudo echo nested; sudo echo twice'")
        assert r.returncode != 0 and "nested" not in r.stdout, r
        assert "only `sudo` as a command of its own gets the password" in r.stderr, r.stderr
        assert "scripts = true for box" in r.stderr
        assert not [e for e in t.sudo.log() if e.get("how") == "A" and e["code"] == 0
                    and "-v" not in e["argv"]]
        r = s.run("ssh", "box", "env sudo echo wrapped")
        assert r.returncode != 0 and "only `sudo` as a command of its own" in r.stderr, r
        # a sudo word that isn't a command: no probe, no staging, no password
        n = len(t.commands())
        r = s.run("ssh", "box", "echo sudo is just a word; grep -c sudo /dev/null")
        assert r.stdout.startswith("sudo is just a word\n"), r
        assert t.commands()[n:] == ["echo sudo is just a word; grep -c sudo /dev/null"]
        assert list(t.xdg.iterdir()) == []


def test_ssh_sudo_askpass_answers_only_sudo() -> None:
    """The staged password isn't handed to Claude's command: the askpass
    refuses a parent that isn't root, and under scripts = false nothing
    points at it from the environment."""
    with H.ssh_env() as s:
        t = _box(s)
        s.set_sudo("box", H.real_user(), PW)
        r = s.run("ssh", "box", 'sudo true; echo "[${SUDO_ASKPASS-unset}]"; '
                                'for a in "$XDG_RUNTIME_DIR"/gw.*/a; do "$a" | rev; done; echo end')
        assert r.returncode == 0 and r.stdout == "[unset]\nend\n", r
        assert PW[::-1] not in r.stdout + r.stderr
        # scripts = true exports SUDO_ASKPASS; calling it still gets nothing
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nscripts = true\n')
        s.approve()
        r = s.run("ssh", "box", 'sudo true; "$SUDO_ASKPASS" | rev; echo "rc=$?"; '
                                "sh -c '\"$SUDO_ASKPASS\"' | tr a-z n-za-m")
        assert PW[::-1] not in r.stdout and codecs.encode(PW, "rot13") not in r.stdout, r
        assert "rc=0" in r.stdout                        # (rev's status) and no password text
        assert r.stdout.strip() == "rc=0", r
        assert list(t.xdg.iterdir()) == []


def test_ssh_sudo_askpass_production_lookup() -> None:
    """The askpass's own euid lookup (no test override): root parent -> 0;
    called from a user's shell it answers nothing and leaves no marker."""
    me = subprocess.run(["/bin/sh", "-c", ssh_sudo.EUID_LOOKUP.replace("$PPID", str(os.getpid()))
                         + '; echo "[$u]"'], capture_output=True, text=True)
    assert me.stdout.strip().replace(" ", "") == f"[{os.getuid()}]", me
    root = subprocess.run(["/bin/sh", "-c", ssh_sudo.EUID_LOOKUP.replace("$PPID", "1")
                           + '; set -- $u; echo "[$1]"'], capture_output=True, text=True)
    assert root.stdout.strip() == "[0]", root
    with H.ssh_env() as s:
        d = s.root / "gw.TESTxx"
        d.mkdir(mode=0o700)
        (d / "p").write_text(PW + "\n")
        (d / "a").write_text(ssh_sudo.askpass_script())
        os.chmod(d / "a", 0o700)
        r = subprocess.run(["/bin/sh", "-c", f"{H.sq(d / 'a')}; echo rc=$?"],
                           capture_output=True, text=True)
        assert r.stdout == "rc=1\n" and PW not in r.stdout + r.stderr, r
        assert sorted(p.name for p in d.iterdir()) == ["a", "p"]       # no answer recorded
        # the test override is only a lookup: a non-root parent is still refused
        (d / "a").write_text(ssh_sudo.askpass_script(str(s.root / "remote-euid.sh")))
        r = subprocess.run(["/bin/sh", "-c", f"{H.sq(d / 'a')}; echo rc=$?"],
                           capture_output=True, text=True)
        assert r.stdout == "rc=1\n", r


def test_ssh_sudo_nopasswd_runs_untouched() -> None:
    with H.ssh_env() as s:
        t = _box(s, nopasswd=True)
        r = s.run("ssh", "box", "sudo echo free")
        assert r.returncode == 0 and r.stdout == "free\n", r
        assert _staged(t) == [] and t.commands() == ["sudo -n true", "sudo echo free"]
        assert ssh_sudo.probe_cached("box", H.real_user()) is True
        assert H.real_user() in s.vault()["hosts"]["box"]["probe"]["nopasswd"]
        assert s.popup_calls() == []                        # nothing asked, nothing stored
        assert vault.sudo_entry(s.vault(), "box", H.real_user()) is None


def test_ssh_sudo_wrong_saved_password_verified_before_use() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        s.set_sudo("box", H.real_user(), "not the password")
        r = s.run("ssh", "box", "for i in 1 2 3 4 5; do sudo true 2>/dev/null; done; echo ran")
        assert r.returncode == 1 and "ran" not in r.stdout, r     # the command never ran
        assert ("gateway: the saved sudo password for box was rejected; a gateway dialog to "
                "enter it again is open in Claude Code; don't retry") in r.stderr
        assert _attempts(t) == 1                                  # one failed attempt in all
        assert len(_verifies(t)) == 1 and not [c for c in t.commands() if "echo ran" in c]
        e = vault.sudo_entry(s.vault(), "box", H.real_user())
        assert e["stale"] is True
        assert any(ev["what"] == "reject" for ev in s.vault()["events"])
        assert list(t.xdg.iterdir()) == []
        # stale: refused at once (the re-entry pop-up again), sudo isn't tried again
        n = len(t.sudo.log())
        r = s.run("ssh", "box", "sudo echo again")
        assert r.returncode == 1 and "was rejected; a gateway dialog to enter it again is open in Claude Code; don't retry" in r.stderr
        assert len(t.sudo.log()) == n and _runs(t, "again") == []
        assert [c["kind"] for c in s.popup_calls()].count("reenter") == 2


def test_ssh_sudo_rejected_inside_command_one_attempt() -> None:
    """The password changes after it was verified: the askpass sees sudo ask
    twice (rejected), answers nobody after that, the password is stale, and
    the command's own exit code stays."""
    with H.ssh_env() as s:
        t = _box(s)
        s.set_sudo("box", H.real_user(), PW)
        assert s.run("ssh", "box", "sudo true").returncode == 0      # verified, cached
        _set_remote_password(t, "changed on the server")
        before = _attempts(t)
        r = s.run("ssh", "box", "for i in 1 2 3 4 5; do sudo true 2>/dev/null; done; echo done")
        assert r.returncode == 0 and r.stdout == "done\n", r
        assert _attempts(t) - before == 1, t.sudo.log()             # one failed attempt only
        assert vault.sudo_entry(s.vault(), "box", H.real_user())["stale"] is True
        assert "was rejected; a gateway dialog to enter it again is open in Claude Code; don't retry" in r.stderr
        assert list(t.xdg.iterdir()) == []


def test_ssh_sudo_command_text_never_marks_stale() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        s.set_sudo("box", H.real_user(), PW)
        r = s.run("ssh", "box", 'sudo echo root-ok && echo "  skipping: f.txt  incorrect '
                                'password" >&2 && echo "Sorry, try again." >&2')
        assert r.returncode == 0 and r.stdout == "root-ok\n", r
        e = vault.sudo_entry(s.vault(), "box", H.real_user())
        assert e["stale"] is False and not [c for c in s.popup_calls() if c["kind"] == "reenter"]
        assert "was rejected" not in r.stderr
        # sudo's own wording on a line of its own only makes the next call verify again
        assert len(_verifies(t)) == 1
        assert s.run("ssh", "box", "sudo true").returncode == 0 and len(_verifies(t)) == 2
        assert s.run("ssh", "box", "sudo true").returncode == 0 and len(_verifies(t)) == 2


def test_ssh_sudo_answer_limit_per_call() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        s.set_sudo("box", H.real_user(), PW)
        assert s.run("ssh", "box", "sudo true").returncode == 0      # verified, cached
        n = len(t.sudo.log())
        r = s.run("ssh", "box", "for i in 1 2 3 4 5 6 7 8; do sudo echo x$i; done")
        assert r.stdout.split() == [f"x{i}" for i in range(1, ssh_sudo.ASK_LIMIT + 1)], r
        new = t.sudo.log()[n:]
        assert sum(e["code"] == 0 for e in new) == ssh_sudo.ASK_LIMIT
        assert _attempts(t) == 0                                   # refusals aren't attempts
        assert vault.sudo_entry(s.vault(), "box", H.real_user())["stale"] is False


def test_ssh_sudo_missing_password_asks_with_verification() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        s.set(popup={"secret": [["ok", "wrong guess 123"], ["ok", PW]]})
        r = s.run("ssh", "box", "sudo echo asked")
        assert r.returncode == 0 and r.stdout == "asked\n", r
        calls = s.popup_calls()
        assert [c["verified"] for c in calls] == [False, True]
        assert calls[0]["what"] == "sudo password"
        assert f"{H.real_user()}@127.0.0.1:{t.port}" in calls[0]["prompt"]
        assert "SHA256:" in calls[0]["prompt"] and "never sees what you type" in calls[0]["prompt"]
        assert "commands Claude runs on box could read it" in calls[0]["prompt"]   # the caveat
        assert "Untick Remember it to use it for this command only" in calls[0]["prompt"]
        assert "NOPASSWD" not in calls[0]["prompt"]
        assert vault.sudo_entry(s.vault(), "box", H.real_user())["password"] == PW
        assert len(_verifies(t)) == 2         # in the pop-up only; a fresh value isn't re-verified
        # cancelled / no screen / still open
        with vault.edit() as d:
            d["hosts"]["box"]["sudo"] = {}
        s.set(popup={"secret": [["cancelled", None]]})
        r = s.run("ssh", "box", "sudo echo x")
        assert r.returncode == 1 and "the user cancelled" in r.stderr
        s.set(popup={"secret": [["stillopen", None]]})
        r = s.run("ssh", "box", "sudo echo x")
        assert r.returncode == 75 and r.stderr.count("the gateway dialog for box is still open") == 1, r
        s.set(popup={"secret": [["failed", None]]})
        r = s.run("ssh", "box", "sudo echo x")
        assert r.returncode == 1 and "didn't work after 3 tries" in r.stderr, r
        s.set(popup={})
        r = s.run("ssh", "box", "sudo echo x")
        assert r.returncode == 75 and r.stderr.count("nothing was asked") == 1 and "gate secret" not in r.stderr, r
        assert list(t.xdg.iterdir()) == []


def test_ssh_sudo_joined_popup_loads_the_value() -> None:
    """A request that joined another process's pop-up gets the stored value
    (load=), and a clear line when there is none."""
    with H.ssh_env() as s:
        _box(s)
        s.set(popup={"secret": [["ok", None]]})
        try:
            ssh._ask_secret("box", "sudo password", "p", load=ssh._sudo_load("box", H.real_user()))
        except ssh.SshError as e:
            assert e.code == 1 and "entered in another call's dialog; run the command again" in e.message
            assert ": ok" not in e.message
        else:
            raise AssertionError("a joined pop-up without a value passed")
        s.set_sudo("box", H.real_user(), PW)
        s.set(popup={"secret": [["ok", None]]})
        assert ssh._ask_secret("box", "sudo password", "p",
                               load=ssh._sudo_load("box", H.real_user())) == PW


def test_ssh_sudo_output_scrubbed() -> None:
    """Residual risk (documented): a program running as the login user can
    still read the staged file; what it prints is scrubbed."""
    with H.ssh_env() as s:
        t = _box(s, extra="scripts = true\n")
        s.set_sudo("box", H.real_user(), PW)
        r = s.run("ssh", "box", 'sudo true; cat "$(dirname "$SUDO_ASKPASS")/p"; '
                                'cat "$(dirname "$SUDO_ASKPASS")/p" >&2')
        assert r.returncode == 0, r
        assert PW not in r.stdout and PW not in r.stderr
        assert r.stdout == "***\n" and "***" in r.stderr, r


def test_ssh_sudo_scrubbed_output_and_closed_reader() -> None:
    """`ssh box 'sudo yes' | head -1`: the scrubbing pump closes its side when
    the reader goes away, so ssh and the remote command end (no hang)."""
    with H.ssh_env() as s:
        t = _box(s)
        s.set_sudo("box", H.real_user(), PW)
        r = subprocess.run(["/bin/sh", "-c", f"{H.sq(s.stub('ssh'))} box 'sudo yes' | head -1"],
                           capture_output=True, text=True, env=s.proc_env(), timeout=60)
        assert r.stdout == "y\n", r
        assert s.wait_for(lambda: list(t.xdg.iterdir()) == [], timeout=10)


def test_ssh_sudo_rights() -> None:
    with H.ssh_env() as s:
        t = _box(s, extra="sudo = false\n")
        s.set_sudo("box", H.real_user(), PW)
        r = s.run("ssh", "box", "sudo id")
        assert r.returncode == 2 and "sudo is off for box (gateway.toml)" in r.stderr, r
        r = s.run("ssh", "box", "cd /tmp && sudo id")
        assert r.returncode == 2 and "sudo is off" in r.stderr
        assert t.commands() == []
        # a sudo word that isn't a command runs, without any password
        r = s.run("ssh", "box", "echo sudo is just a word")
        assert r.returncode == 0 and r.stdout == "sudo is just a word\n"
        assert _staged(t) == [] and "sudo -n true" not in t.commands()
        # "ask": direct callers only
        s.set(direct=False)
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nsudo = "ask"\nscripts = true\n')
        s.approve()
        r = s.run("ssh", "box", "sudo echo x")
        assert r.returncode == 2 and "sudo on box asks the user each time" in r.stderr, r
        s.set(direct=True)
        r = s.run("ssh", "box", "sudo echo direct")
        assert r.returncode == 0 and r.stdout == "direct\n", r


def test_ssh_sudo_short_password_refused_and_helpers() -> None:
    with H.ssh_env() as s:
        t = _box(s, sudo_password="pw12345")
        s.set_sudo("box", H.real_user(), "pw12345")
        r = s.run("ssh", "box", 'sudo true; cat "$XDG_RUNTIME_DIR"/gw.*/p')
        assert r.returncode == 2 and "pw12345" not in r.stdout + r.stderr, r
        assert "shorter than 8 characters" in r.stderr and "longer password" in r.stderr
        assert "NOPASSWD" not in r.stderr
        assert _staged(t) == []                               # never staged
        ok, msg = ssh.verify_remote_sudo("box", H.real_user(), "pw12345")
        assert ok is False and "shorter than 8 characters" in msg
        assert _staged(t) == []
        _set_remote_password(t, PW)
        assert ssh.verify_remote_sudo("box", H.real_user(), PW)[0] is True
        ok, msg = ssh.verify_remote_sudo("box", H.real_user(), "not it at all")
        assert ok is False and "didn't accept" in msg
        assert list(t.xdg.iterdir()) == []
        assert ssh.probe_remote_nopasswd("box", H.real_user()) is False
        t.sudo.dir.joinpath("config.json").write_text(
            json.dumps({"password": PW, "nopasswd": True, "timeout": 0}))
        assert ssh.probe_remote_nopasswd("box", H.real_user()) is False   # cached 10 min
        ssh_sudo.probe_clear("box")
        assert ssh.probe_remote_nopasswd("box", H.real_user()) is True
        assert ssh_sudo.prefix("/d/gw.x", scripts=True).startswith("export SUDO_ASKPASS=/d/gw.x/a; ")
        assert 'export DISPLAY=gw:0' in ssh_sudo.prefix("/d", scripts=True)
        assert ssh_sudo.prefix("/d/gw.x").startswith("sudo() { SUDO_ASKPASS=/d/gw.x/a ")
        # the probe caches are per host: closing box doesn't touch box-2
        ssh_sudo.probe_store("box-2", H.real_user(), True)
        ssh_sudo.probe_clear("box")
        assert ssh_sudo.probe_cached("box-2", H.real_user()) is True


def test_ssh_sudo_wrong_password_without_retry_is_stale() -> None:
    """A sudo that doesn't ask again after a wrong password (passwd_tries=1):
    the verification took the answer and failed, so the password is stale at
    once (no failed attempt on every call)."""
    with H.ssh_env() as s:
        t = _box(s)
        log = t.dir / "tries1.log"
        # the name holds "fake_sudo.py": remote-euid.sh reports it as root
        one = t.dir / "tries1-fake_sudo.py.sh"
        one.write_text("#!/bin/sh\n"
                       "case \" $* \" in *\" -n \"*) echo 'sudo: a password is required' >&2; "
                       "exit 1;; esac\n"
                       "[ -n \"${SUDO_ASKPASS-}\" ] || { echo 'sudo: a terminal is required' >&2; "
                       "exit 1; }\n"
                       "\"$SUDO_ASKPASS\" 'pw: ' >/dev/null || { echo 'sudo: no password was "
                       "provided' >&2; exit 1; }\n"
                       f"echo attempt >> {H.sq(log)}\n"
                       "echo 'sudo: 1 incorrect password attempt' >&2; exit 1\n")
        os.chmod(one, 0o755)
        (t.sudo_bin / "sudo").write_text(f"#!/bin/sh\nexec /bin/sh {H.sq(one)} \"$@\"\n")
        s.set_sudo("box", H.real_user(), PW)
        r = s.run("ssh", "box", "sudo echo never")
        assert r.returncode == 1 and "never" not in r.stdout, r
        assert "was rejected; a gateway dialog to enter it again is open in Claude Code; don't retry" in r.stderr, r.stderr
        assert vault.sudo_entry(s.vault(), "box", H.real_user())["stale"] is True
        assert log.read_text() == "attempt\n"
        r = s.run("ssh", "box", "sudo echo again")
        assert r.returncode == 1 and log.read_text() == "attempt\n", r
        assert list(t.xdg.iterdir()) == []


def test_ssh_sudo_by_path_and_sudoedit() -> None:
    """scripts = true: a sudo called by its path gets the askpass too
    (SUDO_ASKPASS exported). scripts = false: sudoedit in command position
    gets its own shell function; a sudo called by its path skips shell
    functions, so it gets no password and a hint. sudo = false refuses
    sudoedit, a path-qualified sudo and one after a redirection."""
    with H.ssh_env() as s:
        t = _box(s, extra="scripts = true\n")
        s.set_sudo("box", H.real_user(), PW)
        sudo_path = H.sq(t.sudo_bin / "sudo")
        r = s.run("ssh", "box", f"{sudo_path} echo by-path")
        assert r.returncode == 0 and r.stdout == "by-path\n", r
        assert [e.get("how") for e in _runs(t, "by-path")] == ["A"], t.sudo.log()
        # sudoedit, emulated as the fake sudo running cat on the file
        (t.sudo_bin / "sudoedit").write_text(f'#!/bin/sh\nexec {sudo_path} cat "$@"\n')
        os.chmod(t.sudo_bin / "sudoedit", 0o755)
        f = t.dir / "edit-me.txt"
        f.write_text("edited\n")
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n')          # scripts = false
        s.approve()
        r = s.run("ssh", "box", f"sudoedit {H.sq(f)}")
        assert r.returncode == 0 and r.stdout == "edited\n", r
        cmd = [c for c in t.commands() if "edit-me.txt" in c][-1]
        assert cmd.startswith("sudoedit() { SUDO_ASKPASS=") and "export" not in cmd, cmd
        assert "command sudoedit \"$@\"; }; sudoedit " in cmd and "sudo() {" not in cmd
        r = s.run("ssh", "box", f"{sudo_path} echo path-nopw")
        assert r.returncode != 0 and "path-nopw" not in r.stdout, r
        assert "called by its path (/usr/bin/sudo) gets none" in r.stderr, r.stderr
        assert list(t.xdg.iterdir()) == []
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nsudo = false\n')
        s.approve()
        n = len(t.commands())
        for c in (f"sudoedit {H.sq(f)}", f"{sudo_path} id", "</dev/null sudo id",
                  "SUDO_EDITOR='sed -i s/a/b/' sudoedit /etc/hosts"):
            r = s.run("ssh", "box", c)
            assert r.returncode == 2 and "sudo is off for box" in r.stderr, (c, r)
        assert len(t.commands()) == n


def _rsync() -> str | None:
    import shutil
    for p in ("/usr/bin/rsync", "/opt/local/bin/rsync", "/usr/local/bin/rsync",
              "/opt/homebrew/bin/rsync"):
        if os.access(p, os.X_OK):
            return p
    return shutil.which("rsync")


def test_ssh_sudo_prompt_that_starts_the_password_is_not_held_back() -> None:
    """Review round 2: the output scrubber held back the longest tail that
    could still become the password's forms until EOF. `printf c` (the first
    letter of "correct horse battery") then `read` deadlocked: the prompt
    never arrived, so nobody answered it. Held bytes go out after a moment
    of quiet now, and the password is still masked."""
    import select
    import time
    with H.ssh_env() as s:
        _box(s)
        s.set_sudo("box", H.real_user(), PW)
        assert s.run("ssh", "box", "sudo true").returncode == 0      # verified once
        for redir, stream in (("", "stdout"), (" >&2", "stderr")):   # both pumps
            p = subprocess.Popen([str(s.stub("ssh")), "box",
                                  f"sudo sh -c 'printf c{redir}; read x; echo got-$x'"],
                                 stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=s.proc_env(), cwd=str(s.root))
            try:
                t0 = time.monotonic()
                f = getattr(p, stream)
                got = b""
                while not got.endswith(b"c") and time.monotonic() - t0 < 15:
                    r, _, _ = select.select([f], [], [], 15)
                    if not r:
                        break
                    chunk = os.read(f.fileno(), 100)
                    if not chunk:
                        break
                    got += chunk
                assert got.endswith(b"c"), (stream, got, "the prompt never arrived")
                assert time.monotonic() - t0 < 10
                p.stdin.write(b"yes\n")
                p.stdin.flush()
                out, _err = p.communicate(timeout=30)
            finally:
                if p.poll() is None:
                    p.kill()
                    p.wait()
            assert out == b"got-yes\n", (stream, out)
        # a printed password is still masked, a pause in the middle or not
        r = s.run("ssh", "box", f"sudo sh -c 'printf corr; sleep 1; printf \"ect horse battery\\n\"'")
        assert PW not in r.stdout and r.stdout == "corr***\n", r.stdout


def test_ssh_rsync_with_sudo_rsync_and_a_stored_password_completes() -> None:
    """Review round 2: `rsync --rsync-path='sudo rsync'` with the stored
    password "correct horse battery" hung: the rsync server's checksum seed
    ended in a byte that starts the password's base64 form, the scrubber held
    it back, and server and client each waited for the other."""
    rsync = _rsync()
    if rsync is None:
        return
    with H.ssh_env() as s:
        t = _box(s)
        s.set_sudo("box", H.real_user(), PW)
        src = s.root / "site"
        src.mkdir()
        for i in range(30):
            (src / f"f{i}.txt").write_text("hello %d\n" % i * 50)
        env = s.proc_env({"RSYNC_RSH": str(s.stub("ssh"))})
        r = subprocess.run([rsync, "-a", "--rsync-path=sudo rsync", f"{src}/", f"box:{t.dir}/www/"],
                           capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0, r.stderr[-400:]
        assert len(list((t.dir / "www").glob("f*.txt"))) == 30
        assert PW not in r.stdout + r.stderr


def test_ssh_sudo_dialog_names_its_rights_offers_remember_and_rechecks_before_use() -> None:
    """Phase 3 review: the remote sudo dialog names box's ssh and sudo rights
    for gated's recheck and offers "Remember it" (ticked by default:
    stored; unticked: used for this command only); and a right switched off
    while the dialog was open is read again before the password is placed
    on the host (nothing staged, nothing run)."""
    from gateway import paths
    with H.ssh_env() as s:
        t = _box(s)
        form = paths.form_path().read_text()
        s.set(popup={"secret": [["ok", PW]]})
        r = s.run("ssh", "box", "sudo echo kept")
        assert r.returncode == 0 and r.stdout == "kept\n", r
        c = s.popup_calls()[-1]
        assert c["check"] == {"section": "hosts", "entry": "box", "right": ["ssh", "sudo"]}, c
        assert c["remember"] is True
        assert vault.sudo_entry(s.vault(), "box", H.real_user())["password"] == PW
        # unticked: the command runs, nothing is stored
        with vault.edit() as d:
            d["hosts"]["box"]["sudo"] = {}
        s.set(popup={"secret": [["ok", PW, "forget"]]})
        r = s.run("ssh", "box", "sudo echo once")
        assert r.returncode == 0 and r.stdout == "once\n", r
        assert not (vault.sudo_entry(s.vault(), "box", H.real_user()) or {}).get("password")
        # sudo switched off while the dialog was open (here, without gated, the
        # dialog's own check still runs: one staging for its sudo -v): refused
        # before the command's staging
        staged = len(_staged(t)) - len(_verifies(t))
        s.set(popup={"secret": [["ok", PW, {"write": [str(paths.form_path()),
                                                      form + "sudo = false\n"]}]]})
        r = s.run("ssh", "box", "sudo echo late")
        assert r.returncode != 0 and "sudo is off for box" in r.stderr, r
        assert "late" not in r.stdout, r.stdout
        assert len(_staged(t)) - len(_verifies(t)) == staged, "the command's password was staged"
        assert not _runs(t, "late")
