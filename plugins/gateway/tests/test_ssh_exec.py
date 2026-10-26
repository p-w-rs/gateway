"""The ssh stand-in against a real local sshd (group 'ssh'): exec, stdin,
exit codes, shared connections, the private agent, rights, ancestry,
unknown hosts, refused options and the generated config."""
from __future__ import annotations

import contextlib
import os
import json
import subprocess
from pathlib import Path
from typing import Any

import harness  # noqa: F401
import harness_ssh as H
import harness_posture as HP
from gateway import paths, ssh, ssh_conf, vault


def _box(s: H.SshEnv, extra: str = "", name: str = "box") -> H.Sshd:
    t = s.sshd("target")
    s.write_form(f'[hosts.{name}]\naddress = "{t.addr()}"\n{extra}')
    s.approve()
    s.host(name, t)
    return t


def test_ssh_exec_stdin_and_exit_codes() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        r = s.run("ssh", "box", "echo out; echo err >&2; exit 7")
        assert (r.returncode, r.stdout, r.stderr) == (7, "out\n", "err\n"), r
        r = s.run("ssh", "box", "tr a-z A-Z", input="piped data\nline two\n")
        assert r.returncode == 0 and r.stdout == "PIPED DATA\nLINE TWO\n", r
        # words are joined like ssh does; quoting is the remote shell's
        r = s.run("ssh", "box", "printf", "'%s|'", "a", "b")
        assert r.stdout == "a|b|", r
        # binary-safe stdout
        r = subprocess.run([str(s.stub("ssh")), "box", "head -c 4096 /dev/zero"],
                           capture_output=True, env=s.proc_env(), timeout=60)
        assert r.returncode == 0 and r.stdout == b"\0" * 4096
        # by address, user@address, ssh:// and -p naming the same address
        for dest in ([t.addr().rsplit(":", 1)[0], "-p", str(t.port)],
                     ["127.0.0.1", "-p", str(t.port)],
                     [f"ssh://{H.real_user()}@127.0.0.1:{t.port}"], ["-l", H.real_user(), "box"]):
            r = s.run("ssh", *dest, "echo ok")
            assert r.returncode == 0 and r.stdout == "ok\n", (dest, r)
        uses = s.audit("use")
        assert uses and all(u["tool"] == "ssh" and u["target"] == "box" for u in uses)
        assert uses[0]["address"] == t.addr() and uses[0]["argv"].startswith("ssh box echo out")


def test_ssh_exec_master_reused_across_invocations() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        assert s.run("ssh", "box", "true").returncode == 0
        assert t.accepted() == 1 and len(s.masters()) == 1
        for _ in range(3):
            assert s.run("ssh", "box", "echo again").stdout == "again\n"
        assert t.accepted() == 1          # no new authentication: the master was reused
        reuse = [u["reuse"] for u in s.audit("use")]
        assert reuse == [False, True, True, True], reuse
        # the master socket is recorded for close_masters, and closing works
        assert ssh.close_masters("box") == 1
        assert not s.masters()
        assert s.run("ssh", "box", "true").returncode == 0 and t.accepted() == 2
        # no per-call dirs and no agents are left behind
        assert not list(s.run_dir.glob("c-*"))
        assert not [l for l in s.leftovers() if "ssh-agent" in l]


def test_ssh_exec_agent_never_exported() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        log = s.root / "ssh-env.log"
        wrap = s.root / "ssh-wrap"
        wrap.write_text(f"#!/bin/sh\n{{ echo ARGS \"$*\"; env; }} >> {H.sq(log)}\n"
                        f"exec {H.sq(H.ENV_BIN / 'ssh')} \"$@\"\n")
        os.chmod(wrap, 0o755)
        s.set(tools={"ssh": str(wrap)})
        r = s.run("ssh", "box", 'echo "${SSH_AUTH_SOCK-unset}"',
                  extra_env={"SSH_AUTH_SOCK": "/tmp/users-own-agent.sock", "SSH_AGENT_PID": "1"})
        assert r.returncode == 0 and r.stdout == "unset\n", r     # not forwarded
        lines = log.read_text().splitlines()
        assert sum(l.startswith("ARGS") for l in lines) >= 3       # -G, -O check, the command
        env = [l for l in lines if not l.startswith("ARGS")]
        assert not [l for l in env if l.startswith(("SSH_AUTH_SOCK=", "SSH_AGENT_PID="))], env
        assert not [l for l in env if "agent.sock" in l or "users-own-agent" in l]
        assert not [l for l in s.leftovers() if "ssh-agent" in l]


def test_ssh_exec_generated_config() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        st = ssh._load()
        link = ssh._build_link("box", st)
        with ssh_conf.Conn(link) as conn:
            cfg = conn.prepare().read_text()
            kh = (conn.dir / "known_hosts").read_text()
            for line in ("Host gw-box", "HostName 127.0.0.1", f"Port {t.port}",
                         f"User {H.real_user()}", "HostKeyAlias gw-box",
                         "StrictHostKeyChecking yes", "CheckHostIP no", "UpdateHostKeys no",
                         "BatchMode yes", "PasswordAuthentication no", "IdentitiesOnly yes",
                         f"IdentityAgent {conn.dir / 'agent.sock'}", "ForwardAgent no",
                         "ForwardX11 no", "PermitLocalCommand no", "ControlMaster auto",
                         f"ControlPath {paths.run_dir() / 'cm-%C'}", "ControlPersist 120",
                         "ServerAliveInterval 30", "ConnectTimeout 10", "Host *"):
                assert line in cfg, line
            assert kh.strip() == f"gw-box {t.host_key}"
            star = cfg.split("Host *", 1)[1]
            assert "IdentityAgent none" in star and "UserKnownHostsFile /dev/null" in star
            assert "IdentityFile" not in star
            assert oct(os.stat(conn.dir).st_mode & 0o777) == "0o700"
            # ssh -G on the final command line must agree; a smuggled option is caught
            ssh._verify_cmdline(conn, ["-v", "-o", "SendEnv=GIT_PROTOCOL"])
            for bad in (["-o", "ProxyCommand=nc %h %p"], ["-o", "HostName=evil.example"],
                        ["-o", "UserKnownHostsFile=/dev/null"], ["-o", "IdentityAgent=/tmp/x"],
                        ["-o", "ForwardAgent=yes"], ["-o", "StrictHostKeyChecking=no"],
                        ["-F", "/dev/null"]):
                try:
                    ssh._verify_cmdline(conn, bad)
                except ssh.SshError as e:
                    assert "couldn't verify" in e.message
                else:
                    raise AssertionError(f"-G check missed {bad}")


def test_ssh_exec_host_key_pinned_by_ssh_itself() -> None:
    """Even if the address check were fooled, ssh refuses a host key that
    isn't the pinned one (HostKeyAlias + StrictHostKeyChecking yes)."""
    with H.ssh_env() as s:
        t = s.sshd("target")
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n')
        s.approve()
        other = harness.fake_host_key("someone-else")
        s.host("box", t, pins=[other])
        # a lying scan says the server shows the pinned key
        s.set(keyscan={f"127.0.0.1:{t.port}": [other]})
        r = s.run("ssh", "box", "echo should-not-run")
        assert r.returncode == 255 and "should-not-run" not in r.stdout, r
        assert "box's host key isn't the pinned one" in r.stderr, r.stderr
        assert t.commands() == []


def test_ssh_exec_refused_options_never_connect() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        cases = {("-F", "/dev/null"): "-F isn't allowed", ("-i", "/tmp/k"): "-i isn't allowed",
                 # forwarding: off unless the host's own policy turns it on (PLAN-v4 phase 7)
                 ("-A",): "ssh agent forwarding (-A) on box is denied by [hosts.box.policy] has "
                          "no forward_agent", ("-J", "x"): "use via",
                 ("-o", "ProxyCommand=sh -c id"): "ProxyCommand isn't allowed",
                 ("-o", "LocalCommand=id"): "LocalCommand isn't allowed",
                 ("-o", "KnownHostsCommand=id"): "KnownHostsCommand isn't allowed",
                 ("-o", "ForwardAgent=yes"): "ssh agent forwarding (-A) on box is denied",
                 ("-o", "BatchMode=no"): "BatchMode=no isn't allowed",
                 ("-S", "/tmp/sock"): "-S isn't allowed",
                 ("-R", "1:a:2"): "remote port forwarding (-R) on box is denied",
                 ("-X",): "X11 forwarding (-X/-Y) on box is denied",
                 ("-W", "a:22"): "stdio forwarding (-W) on box is denied"}
        for opts, want in cases.items():
            r = s.run("ssh", *opts, "box", "echo hi")
            assert r.returncode == 2 and want in r.stderr and r.stdout == "", (opts, r)
        assert t.accepted() == 0 and not s.masters()
        refusals = s.audit("refusal")
        assert len(refusals) == len(cases)


def test_ssh_exec_no_command_refused_at_once() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        r = s.run("ssh", "box")
        assert r.returncode == 2 and "pass a command; interactive ssh can't work here" in r.stderr
        r = s.run("ssh", "-t", "box")
        assert r.returncode == 2
        assert t.accepted() == 0
        # no destination at all: the user's own ssh (none here: 127)
        r = s.run("ssh")
        assert r.returncode == 127 and "ssh isn't installed here" in r.stderr, r


def test_ssh_exec_unknown_host_is_the_users_own_ssh() -> None:
    """PLAN-0.11 §1.4: a host nothing configures runs the user's own ssh
    (the user_tools fake; never the system_ssh knob), with the full argv;
    git servers no account covers and this computer too; a configured host
    keeps the gateway's key."""
    with H.ssh_env() as s:
        t = _box(s, name="example")
        fake = s.root / "system-ssh"
        fake.write_text("#!/bin/sh\necho \"SYSTEM-SSH $*\"\n")
        os.chmod(fake, 0o755)
        d = HP.user_tools(s.env, "ssh")
        s.set(system_ssh=str(fake), user_tools=str(d))
        for argv in (["exmple", "uptime"], ["elsewhere.invalid", "-v", "uptime"],
                     ["git@gitlab.invalid", "git-upload-pack 'a/b.git'"], ["localhost", "id"]):
            r = s.run("ssh", *argv)
            assert r.returncode == 0 and r.stdout == "fake ssh ran\n", (argv, r)
            assert HP.runs(d, "ssh")[-1]["argv"] == argv
        r = s.run("ssh", "bad\u202ename", "x")
        assert r.returncode == 0
        assert "SYSTEM-SSH" not in json.dumps(HP.runs(d, with_g=True))
        assert t.accepted() == 0
        r = s.run("ssh", "example", "echo mine")   # a configured host: the gateway's key
        assert r.stdout == "mine\n" and t.accepted() == 1, r


def test_ssh_exec_rights_false_and_ask() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nssh = false\n')
        r = s.run("ssh", "box", "echo hi")
        assert r.returncode == 2 and "ssh is off for box (gateway.toml)" in r.stderr, r
        assert t.accepted() == 0
        # raising it back is a widening: it stays off until the user's OK
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nssh = "ask"\n')
        r = s.run("ssh", "box", "echo hi")
        # round 3: the form turns it on, so the next step is the user's OK
        assert r.returncode == 2 and "ssh on box waits for the user's OK; run gate check box" \
            in r.stderr, r.stderr
        s.approve()
        r = s.run("ssh", "box", "echo hi")       # direct caller: the hook already asked
        assert r.returncode == 0 and r.stdout == "hi\n"
        s.set(direct=False, culprit="make")
        r = s.run("ssh", "box", "echo hi")
        assert r.returncode == 2 and "run it as its own command so Claude Code can ask you" in r.stderr
        assert t.accepted() == 1


def test_ssh_exec_scripts_and_ancestry() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        s.set(direct=False, culprit="make")
        r = s.run("ssh", "box", "echo hi")
        assert r.returncode == 2 and r.stdout == ""
        assert ("gateway: ssh started by make got no key (only Claude's own commands do); run it "
                "as its own command, or set scripts = true for box") in r.stderr, r.stderr
        assert t.accepted() == 0
        # a caller the gateway can't trace back to Claude (ancestry's "?": a job
        # still running after its session ended), for ssh and remote sudo alike
        from gateway import ancestry
        s.set(culprit="?")
        for cmd in ("echo hi", "sudo whoami"):
            r = s.run("ssh", "box", cmd)
            assert r.returncode == 2 and r.stdout == ""
            assert (f"gateway: ssh started by {ancestry.UNTRACED_WHO} got no key (only Claude's "
                    "own commands do); run it as its own command, or set scripts = true for "
                    "box") in r.stderr, r.stderr
            assert "a script" not in r.stderr and "started by ?" not in r.stderr
        assert t.accepted() == 0
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nscripts = true\n')
        s.approve()
        r = s.run("ssh", "box", "echo hi")
        assert r.returncode == 0 and r.stdout == "hi\n"


def test_ssh_exec_new_host_and_wrong_user() -> None:
    with H.ssh_env() as s:
        t = s.sshd("target")
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n')
        r = s.run("ssh", "box", "true")
        assert r.returncode == 2 and "box waits for the user's OK; run gate check box" in r.stderr
        s.approve()
        r = s.run("ssh", "box", "true")
        assert "box has no pinned host key yet; run gate check box" in r.stderr
        with vault.edit() as d:
            vault.host_record(d, "box")["host_keys"] = [t.host_key]
        r = s.run("ssh", "box", "true")
        assert "box has no key yet; run gate check box" in r.stderr
        s.host("box", t)
        r = s.run("ssh", "root@box", "true")
        assert r.returncode == 2 and f"box is reached as {H.real_user()}" in r.stderr
        r = s.run("ssh", "-p", "1", "box", "true")
        assert "isn't reached on port 1" in r.stderr
        # a new address is a widening: the old one keeps working, the new one waits
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nalso = ["127.0.0.1:1"]\n')
        r = s.run("ssh", "-p", "1", "box", "true")
        assert r.returncode == 2 and "isn't reached on port 1" in r.stderr
        assert s.run("ssh", "box", "echo ok").stdout == "ok\n"


def test_ssh_exec_auth_failure_message() -> None:
    with H.ssh_env() as s:
        t = s.sshd("target")
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n')
        s.approve()
        s.host("box", None, pins=[t.host_key])        # key in the vault, not authorized there
        r = s.run("ssh", "box", "true")
        assert r.returncode == 255, r
        assert "gateway: box refused Claude's key (installed? run gate check box)" in r.stderr
        assert ssh_conf.recent_authfail("box")
        # a reset right after a failed login is rate limiting, not a reason to fail over
        msg = ssh_conf.explain_failure("box", 255, "kex_exchange_identification: read: "
                                                   "Connection reset by peer")
        assert msg == "gateway: box is rate-limiting after failed logins; wait a minute"
        ssh_conf.clear_authfail("box")
        assert ssh_conf.explain_failure("box", 255, "Connection reset by peer") is None
        assert ssh_conf.explain_failure("box", 1, "Permission denied (publickey)") is None


def test_ssh_exec_forwarding_and_misc_options() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        r = s.run("ssh", "-q", "-T", "-o", "ConnectTimeout=5", "-o", "ServerAliveInterval=10",
                  "-C", "-4", "box", "echo fine")
        assert r.returncode == 0 and r.stdout == "fine\n", r
        r = s.run("ssh", "-n", "box", "cat")     # -n: stdin from /dev/null
        assert r.returncode == 0 and r.stdout == ""
        # no destination: the user's own ssh (PLAN-0.11 §1.4)
        d = HP.user_tools(s.env, "ssh")
        s.set(user_tools=str(d))
        r = s.run("ssh", "-V")
        assert r.returncode == 0 and r.stdout == "fake ssh ran\n" and \
            HP.runs(d, "ssh")[-1]["argv"] == ["-V"], r
        # a reader that goes away ends the command (stdout isn't held by the stand-in)
        r = subprocess.run(["/bin/sh", "-c", f"{H.sq(s.stub('ssh'))} box yes | head -2"],
                           capture_output=True, text=True, env=s.proc_env(), timeout=60)
        assert r.stdout == "y\ny\n", r


def test_ssh_exec_signals_are_forwarded() -> None:
    import signal
    import time
    with H.ssh_env() as s:
        t = _box(s)
        p = subprocess.Popen([str(s.stub("ssh")), "box", "echo started; sleep 30; echo late"],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=s.proc_env())
        assert p.stdout is not None and p.stdout.readline() == b"started\n"
        t0 = time.time()
        p.send_signal(signal.SIGTERM)
        # the stand-in and its ssh end at once (a shared master may finish the remote
        # command; ssh's own mux clients behave the same way)
        assert p.wait(timeout=15) != 0 and time.time() - t0 < 10
        assert not [l for l in s.leftovers() if "ssh-agent" in l]
        assert not list(s.run_dir.glob("c-*"))
        p.stdout.close()
        assert p.stderr is not None
        p.stderr.close()


def test_ssh_exec_leaves_nothing_running() -> None:
    with H.ssh_env() as s:
        _box(s)
        assert s.run("ssh", "box", "true").returncode == 0
        run, root = s.run_dir, s.root
        assert [l for l in s.leftovers() if "[mux]" in l]       # the master persists (120 s)
        s.cleanup()
        assert s.leftovers() == []
    out = subprocess.run(["ps", "-ax", "-o", "command="], capture_output=True, text=True).stdout
    assert str(run) not in out and str(root) not in out
    assert not Path(run).exists()


def test_ssh_exec_remote_sudo_turned_on_but_waiting_says_so() -> None:
    """Round 3: with the form's sudo turned on for a host but the change
    waiting for the user's OK, the stand-in said "sudo is off for box ... ask
    the user if it should be on"; the next step is gate check box."""
    with H.ssh_env() as s:
        t = _box(s, "sudo = false\n")
        r = s.run("ssh", "box", "sudo id")
        assert r.returncode == 2 and "sudo is off for box (gateway.toml)" in r.stderr, r
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nsudo = true\n')
        r = s.run("ssh", "box", "sudo id")
        assert r.returncode == 2 and ("gateway: sudo on box waits for the user's OK; run gate check "
                                      "box while the user is here") in r.stderr, r
        assert "ask the user if it should be on" not in r.stderr
        assert t.accepted() == 0


def _concurrent(s: H.SshEnv, n: int, cmd: str) -> list[subprocess.CompletedProcess]:
    """n ssh stand-ins started at the same moment; their results in order."""
    procs = [subprocess.Popen([str(s.stub("ssh")), "box", cmd], stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              env=s.proc_env(), cwd=str(s.root)) for _ in range(n)]
    out = []
    for p in procs:
        o, e = p.communicate(timeout=60)
        out.append(subprocess.CompletedProcess(p.args, p.returncode, o.decode(), e.decode()))
    return out


def test_ssh_exec_parallel_calls_share_one_master() -> None:
    """Two stand-ins to one host at once (checkpoint jobs run in parallel):
    the second waits on the ControlPath lock while the first starts the
    master, then reuses it; OpenSSH's "ControlSocket ... already exists,
    disabling multiplexing" never reaches the output."""
    with H.ssh_env() as s:
        t = _box(s)
        for round_ in range(3):
            rs = _concurrent(s, 2, "echo ok")
            for r in rs:
                assert r.returncode == 0 and r.stdout == "ok\n", (round_, r)
                assert "already exists" not in r.stderr and "multiplexing" not in r.stderr, \
                    (round_, r.stderr)
            assert len(s.masters()) == 1, (round_, s.masters())
            assert t.accepted() == round_ + 1, (round_, t.accepted())   # one login per round
            assert ssh.close_masters("box") == 1
        # the lock files stay next to the sockets (never unlinked: a waiter
        # could lock a deleted inode); they aren't masters
        assert [p.name.endswith(".lock") for p in s.run_dir.glob("cm-*")
                if not p.name.endswith(".list")] == [True]
        assert not list(s.run_dir.glob("c-*"))
        assert not [l for l in s.leftovers() if "ssh-agent" in l]


def test_ssh_exec_master_lock_wait_is_bounded() -> None:
    """A call that can't get the ControlPath lock (a stuck holder) goes on
    after a bounded wait, on its own (no master); a call that never starts a
    master (scp/sftp pass ControlMaster=no) doesn't keep the lock, and
    reaches the host on its own too."""
    import fcntl
    import threading
    import time
    from gateway import form as formmod
    with H.ssh_env() as s:
        t = _box(s)
        link = ssh_conf.Link(name="box", addr=formmod.Address(host="127.0.0.1", port=t.port,
                                                               user=H.real_user()),
                             host_keys=[t.host_key], pubkeys=[], master=True)
        with ssh_conf.Conn(link) as a, ssh_conf.Conn(link) as b:
            files = a._lock_files()
            assert len(files) == 1 and files[0].startswith(str(s.run_dir) + "/cm-"), files
            assert files[0].endswith(".lock") and files == b._lock_files()
            held = os.open(files[0], os.O_RDWR | os.O_CREAT, 0o600)
            fcntl.flock(held, fcntl.LOCK_EX)
            try:
                got: list[bool] = []
                th = threading.Thread(target=lambda: got.append(a.lock_masters(wait=0.3)),
                                      daemon=True)
                t0 = time.monotonic()
                th.start()
                th.join(timeout=3)
                assert not th.is_alive(), "the lock wait isn't bounded"
                assert got == [False] and not a._locks and time.monotonic() - t0 >= 0.25
                # the stand-in goes on after its own wait (MASTER_LOCK_WAIT) and works,
                # on its own: without the lock it starts no master
                t0 = time.monotonic()
                r = s.run("ssh", "box", "echo ok")
                took = time.monotonic() - t0
                assert r.returncode == 0 and r.stdout == "ok\n", r
                assert ssh_conf.MASTER_LOCK_WAIT - 0.5 <= took < ssh_conf.MASTER_LOCK_WAIT + 10, took
                assert not s.masters() and t.accepted() == 1
            finally:
                os.close(held)
            assert ssh.close_masters("box") == 0
            assert a.lock_masters(wait=0.3) is True and len(a._locks) == 1
            assert b.lock_masters(wait=0.2) is False          # a holds it
            a.unlock_masters()
            a.unlock_masters()                                # twice is harmless
            assert b.lock_masters(wait=0.2) is True
            b.unlock_masters()
            # a call that only reuses masters waits for the lock but doesn't keep it,
            # so it reaches the host on its own (never a master, never multiplexed)
            b.starts_master = False
            b.ensure_agent()
            assert b.agent is not None and not b._locks and b.solo == {"gw-box"}
            g = ssh_conf.ssh_g(b.prepare(), ["gw-box"])
            assert g["controlmaster"] == ["false"] and "controlpath" not in g, g
            assert not b.owns_target()
            assert a.lock_masters(wait=0.2) is True
            a.unlock_masters()


LONG = "sleep 4; echo A"


def _held_master(s: H.SshEnv) -> Path:
    """The gateway's ssh, except that the connection running LONG (not its
    `ssh -G` or `-O check`) waits until the returned file exists (20 s at
    most): the test lets the first call start its master only once a
    parallel call is waiting for it."""
    go = s.root / "go"
    real = H.sq(H.ENV_BIN / "ssh")
    wrap = s.root / "ssh-held"
    wrap.write_text("#!/bin/sh\n"
                    f'for a in "$@"; do case "$a" in -G|-O) exec {real} "$@";; esac; done\n'
                    f'case "$*" in *{H.sq(LONG)}*)\n'
                    f'  n=0; while [ ! -e {H.sq(go)} ] && [ "$n" -lt 400 ]; do sleep 0.05; '
                    'n=$((n+1)); done;;\nesac\n'
                    f'exec {real} "$@"\n')
    os.chmod(wrap, 0o755)
    s.set(tools={"ssh": str(wrap)})
    return go


def _second_call_frees_early(s: H.SshEnv, t: H.Sshd, go: Path, first_running: Any,
                             n_ssh_uses: int) -> None:
    """With the first call holding the ControlPath lock and its ssh held
    back: start a short call, let it reach the lock (it audits `reuse`
    False, then waits), let the first call's ssh go, and time the short call.
    It must end long before LONG does: the lock goes when the master answers."""
    import time
    assert s.wait_for(lambda: list(s.run_dir.glob("c-*/agent.sock")), 20), "no first call"
    b = subprocess.Popen([str(s.stub("ssh")), "box", "echo B"], stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=s.proc_env(),
                         cwd=str(s.root))
    assert s.wait_for(lambda: len([u for u in s.audit("use") if u["tool"] == "ssh"])
                      >= n_ssh_uses, 20), "the short call didn't start"
    assert s.audit("use")[-1]["reuse"] is False      # no master yet: it waits on the lock
    time.sleep(0.3)
    t0 = time.monotonic()
    go.touch()
    o, e = b.communicate(timeout=60)
    took = time.monotonic() - t0
    assert (b.returncode, o, e) == (0, b"B\n", b""), (b.returncode, o, e)
    # LONG takes 4 s after the go; without the early release the short call
    # waits for its end (or MASTER_LOCK_WAIT): about 4.4 s (0.3-0.6 s with it)
    assert took < 2.5 and first_running(), took
    assert t.accepted() == 1


def test_ssh_exec_long_call_frees_the_lock_once_its_master_answers() -> None:
    """Two stand-ins at once, the first running a long command: the first
    call's ControlPath lock goes as soon as its master answers (the agent
    watcher), so the second reuses that master at once instead of waiting
    for the long command to end."""
    with H.ssh_env() as s:
        t = _box(s)
        go = _held_master(s)
        a = subprocess.Popen([str(s.stub("ssh")), "box", LONG], stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=s.proc_env(),
                             cwd=str(s.root))
        _second_call_frees_early(s, t, go, lambda: a.poll() is None, 2)
        o, e = a.communicate(timeout=60)
        assert (a.returncode, o, e) == (0, b"A\n", b""), (a.returncode, o, e)
        assert len(s.masters()) == 1 and t.accepted() == 1
        assert [u["reuse"] for u in s.audit("use")] == [False, False]
        assert not [l for l in s.leftovers() if "ssh-agent" in l]


def test_ssh_exec_gate_capture_frees_the_lock_once_its_master_answers() -> None:
    """The gate process's own calls (Conn.capture: copy-to's ssh.run,
    passwordless sudo setup, rotate, the sudo probe) release the ControlPath
    lock when their master answers, like the stand-in: a parallel stand-in
    call doesn't wait for the remote command (nor MASTER_LOCK_WAIT)."""
    import threading
    with H.ssh_env() as s:
        t = _box(s)
        go = _held_master(s)
        got: list[Any] = []
        th = threading.Thread(target=lambda: got.append(ssh.run("box", LONG)), daemon=True)
        th.start()
        _second_call_frees_early(s, t, go, th.is_alive, 1)
        th.join(timeout=60)
        assert got == [(0, b"A\n", b"")], got
        assert len(s.masters()) == 1 and t.accepted() == 1
        assert [u["tool"] for u in s.audit("use")] == ["gate", "ssh"]
        assert not list(s.run_dir.glob("c-*"))
        assert not [l for l in s.leftovers() if "ssh-agent" in l]


# A call that gives up on the ControlPath lock (the holder's login takes
# longer than the lock wait) connects on its own: it can neither lose its
# agent to the holder's master nor start a master the holder would take for
# its own (verifier, after the integration lows: B failed 4 of 4 with
# "Permission denied", and gate check then said the key was refused).


class _Call:
    """`ssh box echo WORD` as a stand-in (subprocess) or as the gate
    process's own call (ssh.run, Conn.capture, in a thread)."""

    def __init__(self, s: H.SshEnv, kind: str, word: str):
        import threading
        self.kind, self.word = kind, word
        if kind == "standin":
            self.p = subprocess.Popen([str(s.stub("ssh")), "box", f"echo {word}"],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE, env=s.proc_env(), cwd=str(s.root))
            return
        self.got: list[tuple[int, str, str]] = []

        def run() -> None:
            try:
                rc, out, err = ssh.run("box", f"echo {word}")
                self.got.append((rc, out.decode(), err.decode()))
            except ssh_conf.SshError as e:
                self.got.append((e.code, "", e.message))

        self.th = threading.Thread(target=run, daemon=True)
        self.th.start()

    def result(self) -> tuple[int, str, str]:
        if self.kind == "standin":
            o, e = self.p.communicate(timeout=60)
            return self.p.returncode, o.decode(), e.decode()
        self.th.join(timeout=60)
        return self.got[0] if self.got else (-1, "", "no result")


def _why_not_held(t: H.Sshd, px: H.HoldProxy, call: _Call, n0: int) -> str:
    """What became of a call whose login the proxy never held (the failure
    message says it, instead of only that it didn't arrive)."""
    bits = [f"{len(px.held)} held (wanted more than {n0})", f"{px.accepted} connections accepted",
            "sshd " + ("running" if t.proc is not None and t.proc.poll() is None else "gone")]
    if call.kind == "standin":
        if call.p.poll() is None:
            call.p.kill()
        _o, e = call.p.communicate(timeout=10)
        bits.append(f"the stand-in exited {call.p.returncode}: {e.decode('utf-8', 'replace')[-800:]!r}")
    else:
        bits.append(f"the gate call {'still runs' if call.th.is_alive() else 'ended'}: {call.got!r}")
    bits.append(f"the proxy ({px.state()}): " + " | ".join(px.trace[-24:]))
    with contextlib.suppress(OSError):
        bits.append(f"sshd log: {t.log.read_text()[-1500:]!r}")
    return "; ".join(bits)


def _proxied_box(s: H.SshEnv) -> tuple[H.Sshd, H.HoldProxy]:
    t = s.sshd("target")
    px = s.proxy(t.port)
    s.write_form(f'[hosts.box]\naddress = "{H.real_user()}@127.0.0.1:{px.port}"\n')
    s.approve()
    s.host("box", t)
    s.set(master_lock_wait=1.0)        # MASTER_LOCK_WAIT, shortened for the test
    return t, px


def _giver_up(s: H.SshEnv, t: H.Sshd, px: H.HoldProxy, a_kind: str, b_kind: str,
              first: str) -> None:
    """A holds the lock while the proxy holds its login; B gives up on the
    lock and connects, and the proxy holds B's login too. first="A": A's
    master answers while B is still logging in, and B must keep its agent.
    first="B": B finishes first and must leave no master behind, so A's
    watcher doesn't take one for A's own (killing A's agent mid-login)."""
    def agents() -> list[Path]:
        return list(s.run_dir.glob("c-*/agent.sock"))

    n0, logins = len(px.held), t.accepted()
    px.hold = True
    a = _Call(s, a_kind, "A")
    assert px.wait_held(n0 + 1), "A's login didn't reach the proxy: " + _why_not_held(t, px, a, n0)
    b = _Call(s, b_kind, "B")
    assert px.wait_held(n0 + 2), "B didn't connect after its lock wait: " + _why_not_held(t, px, b, n0 + 1)
    assert len(agents()) == 2, agents()
    if first == "A":
        px.release(n0)
        ra = a.result()
        assert len(s.masters()) == 1
        s.wait_for(lambda: not agents(), 1.5)    # time for a wrong watcher to kill B's agent
        px.release(n0 + 1)
        rb = b.result()
    else:
        px.release(n0 + 1)
        rb = b.result()
        assert not s.masters(), s.masters()      # B logged in on its own
        s.wait_for(lambda: not agents(), 1.5)    # time for A's watcher to be fooled
        px.release(n0)
        ra = a.result()
    px.hold = False
    assert ra == (0, "A\n", "") and rb == (0, "B\n", ""), (a_kind, b_kind, first, ra, rb)
    assert len(s.masters()) == 1 and t.accepted() == logins + 2, (s.masters(), t.accepted())
    assert ssh_conf.close_recorded("box") == 1     # keeps the address cache (no new keyscan)
    assert not agents()


def test_a_closed_hold_proxy_takes_no_connection_meant_for_a_later_one() -> None:
    """The lock tests' flake in the Linux VM's full suite ("A's login didn't
    reach the proxy", "B didn't connect ... Connection reset by peer"): on
    Linux close() doesn't wake a thread blocked in accept(), so an earlier
    test's proxy left its accept thread behind, which took a connection meant
    for a later proxy whose listener got the same file descriptor number and
    reset it (its own sshd was gone). close() now wakes it with shutdown()
    and closes the socket only once it is gone."""
    import socket
    import threading

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(64)
    served = [0]

    def serve() -> None:
        with contextlib.suppress(OSError):
            while True:
                c, _ = srv.accept()
                served[0] += 1
                c.sendall(b"SSH-2.0-fake\r\n")
                c.close()
    threading.Thread(target=serve, daemon=True).start()
    old = H.HoldProxy(1)                 # its upstream (port 1) is never there
    fd = old.sock.fileno()
    old.close()
    assert not old._acceptor.is_alive(), "close() left the accept thread behind"
    new = H.HoldProxy(srv.getsockname()[1])
    try:
        for _ in range(20):
            with socket.create_connection(("127.0.0.1", new.port), timeout=10) as c:
                c.settimeout(10)
                assert c.recv(64).startswith(b"SSH-2.0-"), "a connection went to the closed proxy"
        assert new.accepted == 20 and served[0] == 20, (new.accepted, served[0], fd, new.sock.fileno())
    finally:
        new.close()
        with contextlib.suppress(OSError):
            srv.shutdown(socket.SHUT_RDWR)
        srv.close()


def test_the_hold_proxy_keeps_serving_after_a_thread_it_cannot_start_and_a_late_upstream() -> None:
    """The lock tests' proxy (harness): its accept loop used to end at the
    first accept error and to die on a thread it couldn't start, after which
    every later login waited in its listen queue. It now keeps accepting,
    waits for a thread, and retries the upstream connect."""
    import socket
    import threading
    import time

    def upstream(port: int | None = None) -> socket.socket:
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", port or 0))
        srv.listen(4)

        def serve() -> None:
            with contextlib.suppress(OSError):
                while True:
                    c, _ = srv.accept()
                    c.sendall(b"SSH-2.0-fake\r\n" + c.recv(64))
                    c.close()
        threading.Thread(target=serve, daemon=True).start()
        return srv

    def through(px: H.HoldProxy) -> bytes:
        with socket.create_connection(("127.0.0.1", px.port), timeout=10) as c:
            c.settimeout(10)
            c.sendall(b"ping")
            out = b""
            while not out.endswith(b"ping"):
                chunk = c.recv(64)
                if not chunk:
                    break
                out += chunk
            return out

    srv = upstream()
    px = H.HoldProxy(srv.getsockname()[1])
    orig = threading.Thread.start
    fails = [3]

    def flaky(self: threading.Thread) -> None:
        if getattr(self, "_target", None) == px._pipe and fails[0] > 0:
            fails[0] -= 1
            raise RuntimeError("can't start new thread")
        orig(self)
    threading.Thread.start = flaky                      # type: ignore[method-assign]
    try:
        assert through(px) == b"SSH-2.0-fake\r\nping"
    finally:
        threading.Thread.start = orig                   # type: ignore[method-assign]
    assert fails[0] == 0 and through(px) == b"SSH-2.0-fake\r\nping"
    # an upstream that isn't listening yet when the connection arrives
    port = srv.getsockname()[1]
    with contextlib.suppress(OSError):
        srv.shutdown(socket.SHUT_RDWR)
    srv.close()
    late: list[socket.socket] = []
    threading.Timer(0.15, lambda: late.append(upstream(port))).start()
    assert through(px) == b"SSH-2.0-fake\r\nping"
    assert px.accepted == 3
    px.close()
    for s_ in late:
        with contextlib.suppress(OSError):
            s_.shutdown(socket.SHUT_RDWR)
        s_.close()


def test_ssh_exec_a_call_that_gives_up_on_the_lock_keeps_its_agent_and_starts_no_master() -> None:
    """Two stand-ins, the first one's login held longer than the lock wait:
    the second connects on its own (ControlPath none), keeps its agent while
    the first one's master comes up, and starts no master the first one
    could take for its own; both work, no "ControlSocket ... already exists"."""
    with H.ssh_env() as s:
        t, px = _proxied_box(s)
        assert s.run("ssh", "box", "true").returncode == 0      # address and keyscan cached
        assert ssh_conf.close_recorded("box") == 1
        _giver_up(s, t, px, "standin", "standin", "A")
        _giver_up(s, t, px, "standin", "standin", "B")
        assert not list(s.run_dir.glob("c-*"))


def test_ssh_exec_gate_capture_that_gives_up_on_the_lock_keeps_its_agent_and_starts_no_master(
        ) -> None:
    """The same for the gate process's own calls (Conn.capture): as the
    call that gives up, and as the lock holder whose watcher must not take
    another call's master for its own."""
    with H.ssh_env() as s:
        t, px = _proxied_box(s)
        assert s.run("ssh", "box", "true").returncode == 0
        assert ssh_conf.close_recorded("box") == 1
        _giver_up(s, t, px, "standin", "capture", "A")
        _giver_up(s, t, px, "capture", "capture", "B")
        _giver_up(s, t, px, "capture", "standin", "B")
        assert not list(s.run_dir.glob("c-*"))


def test_ssh_exec_hops_without_their_lock_are_reached_on_their_own() -> None:
    """Per hop: a call through a jump host that gets one ControlPath lock
    but not the other reaches the unlocked hop without multiplexing and
    holds the other; it kills its agent early only when it holds the
    target's lock. A later ssh run on the same connection (its earlier run
    released the locks, no master came up) takes again only the locks that
    are free, without waiting."""
    import fcntl
    import time
    from gateway import form as formmod
    with H.ssh_env() as s:
        s.set(master_lock_wait=1.0)
        u = H.real_user()
        jump = ssh_conf.Link(name="gate1", addr=formmod.Address(host="127.0.0.1", port=1, user=u),
                             host_keys=[], pubkeys=[], master=True)
        inner = ssh_conf.Link(name="inner", addr=formmod.Address(host="10.9.9.9", port=22, user=u),
                              host_keys=[], pubkeys=[], master=True, jump=jump)
        for busy, solo, owns in (("gw-inner", {"gw-inner"}, False),
                                 ("gw-gate1", {"gw-gate1"}, True)):
            with ssh_conf.Conn(inner) as c:
                lm = {aliases[0]: p for p, aliases in c._lock_map().items()}
                assert set(lm) == {"gw-inner", "gw-gate1"}, lm
                fd = os.open(lm[busy], os.O_RDWR | os.O_CREAT, 0o600)
                fcntl.flock(fd, fcntl.LOCK_EX)
                fd2 = -1
                try:
                    c.ensure_agent()
                    assert c.agent is not None and c.solo == solo and c.owns_target() is owns
                    assert list(c._locks) == [p for a, p in lm.items() if a != busy]
                    for alias in ("gw-inner", "gw-gate1"):
                        g = ssh_conf.ssh_g(c.prepare(), [alias])
                        if alias in solo:
                            assert g["controlmaster"] == ["false"] and "controlpath" not in g
                        else:
                            assert g["controlmaster"] == ["auto"]
                            assert g["controlpath"] == [lm[alias][:-len(".lock")]]
                    agent = c.agent
                    # its ssh ended without a master (the locks went): the next
                    # run takes the free lock again at once, keeps its agent
                    c.unlock_masters()
                    t0 = time.monotonic()
                    c.ensure_agent()
                    assert time.monotonic() - t0 < 0.8 and c.agent is agent
                    assert c.solo == solo and c.owns_target() is owns
                    # ... and with no lock free, it reaches both hops on its own
                    c.unlock_masters()
                    fd2 = os.open(lm["gw-gate1" if busy == "gw-inner" else "gw-inner"],
                                  os.O_RDWR | os.O_CREAT, 0o600)
                    fcntl.flock(fd2, fcntl.LOCK_EX)
                    c.ensure_agent()
                    assert c.solo == {"gw-inner", "gw-gate1"} and not c.owns_target()
                    assert not c._locks and c.agent is agent
                finally:
                    os.close(fd)
                    if fd2 >= 0:
                        os.close(fd2)
