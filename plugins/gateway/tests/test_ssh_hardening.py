"""Regression tests for the ssh group's verification findings (group 'ssh'):
exact host names before the gw- alias, failures classified from ssh's own
log only, `ssh -v` on a first connection, ancestry errors failing closed,
agent key lifetime and the agent dying with the stand-in, the `ssh -G`
backstops, forwarded ports open to other machines, others = "mine" reaching
a form host under another name, safe strings from resolve(), no tracebacks,
and the probe deadline covering slow name resolution."""
from __future__ import annotations

import contextlib
import io
import os
import signal
import subprocess
import sys
import time

import harness  # noqa: F401
import harness_ssh as H
import harness_posture as HP
from gateway import form as formmod
from gateway import ssh, ssh_args, ssh_conf


def _box(s: H.SshEnv, extra: str = "", name: str = "box") -> H.Sshd:
    t = s.sshd("target")
    s.write_form(f'[hosts.{name}]\naddress = "{t.addr()}"\n{extra}')
    s.approve()
    s.host(name, t)
    return t


def test_ssh_hard_exact_name_before_gw_alias() -> None:
    with H.ssh_env() as s:
        a = s.sshd("a")
        b = s.sshd("b")
        c = s.sshd("c")
        s.write_form(f'[hosts.foo]\naddress = "{a.addr()}"\n\n[hosts.gw-foo]\naddress = "{b.addr()}"\n'
                     f'\n[hosts.bar]\naddress = "{c.addr()}"\n')
        s.approve()
        s.host("foo", a)
        s.host("gw-foo", b)
        s.host("bar", c)
        r = s.run("ssh", "gw-foo", "echo which")
        assert r.returncode == 0 and r.stdout == "which\n", r
        assert b.commands() == ["echo which"] and a.commands() == []
        assert s.audit("use")[-1]["target"] == "gw-foo"
        assert ssh.resolve(["gw-foo", "x"])["name"] == "gw-foo"
        # gw-NAME still names NAME when there is no host called gw-NAME
        r = s.run("ssh", "gw-bar", "echo bar")
        assert r.stdout == "bar\n" and s.audit("use")[-1]["target"] == "bar"


def test_ssh_hard_remote_stderr_isnt_an_ssh_failure() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        assert s.run("ssh", "box", "true").returncode == 0
        assert (s.run_dir / "addr-box.json").exists()
        r = s.run("ssh", "box", 'echo "Permission denied (publickey)." >&2; '
                                f'echo "{H.real_user()}@box: Permission denied (publickey)." >&2; '
                                'echo "kex_exchange_identification: read: Connection reset" >&2; '
                                'echo "ssh: connect to host 10.0.0.9 port 22: Connection refused" >&2; '
                                "exit 255")
        assert r.returncode == 255, r
        assert "Permission denied (publickey)." in r.stderr          # the remote's text, passed on
        assert "refused Claude's key" not in r.stderr and "rate-limiting" not in r.stderr, r.stderr
        assert not ssh_conf.recent_authfail("box")
        assert (s.run_dir / "addr-box.json").exists()                # the address cache stays
        # ssh's own messages still reach stderr (from its -E log)
        r = s.run("ssh", "-t", "box", "echo tty")
        assert r.returncode == 0 and "Pseudo-terminal will not be allocated" in r.stderr, r


def test_ssh_hard_verbose_first_call_returns() -> None:
    with H.ssh_env() as s:
        _box(s)
        t0 = time.time()
        r = s.run("ssh", "-v", "box", "echo hi", timeout=60)
        took = time.time() - t0
        assert r.returncode == 0 and r.stdout == "hi\n", r
        assert "debug1:" in r.stderr
        assert took < 15, took                          # not ControlPersist's 120 s
        assert len(s.masters()) == 1                     # the master was started and persists
        t0 = time.time()
        assert s.run("ssh", "-v", "box", "echo again").stdout == "again\n"
        assert time.time() - t0 < 15


def test_ssh_hard_run_child_stops_draining_after_exit() -> None:
    """Something else holding ssh's stderr after ssh exits can't keep the
    stand-in waiting."""
    with H.ssh_env() as s:
        link = ssh_conf.Link(name="x", addr=formmod.Address(host="127.0.0.1", port=1, user="u"),
                             host_keys=[], pubkeys=[], master=False)
        conn = ssh_conf.Conn(link)
        t0 = time.time()
        saved = os.dup(2)                      # run_child echoes stderr to fd 2: keep it quiet
        null = os.open(os.devnull, os.O_WRONLY)
        os.dup2(null, 2)
        try:
            rc, err, log = ssh_conf.run_child(
                ["/bin/sh", "-c", "sleep 7.31 >/dev/null & echo started >&2; exit 3"], conn)
        finally:
            os.dup2(saved, 2)
            os.close(saved)
            os.close(null)
            subprocess.run(["pkill", "-f", "sleep 7.31"], capture_output=True)
        assert rc == 3 and err == "started\n" and log == ""
        assert time.time() - t0 < ssh_conf.DRAIN_MAX, time.time() - t0


def test_ssh_hard_ancestry_error_fails_closed() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        s.set(direct="raise")
        r = s.run("ssh", "box", "echo hi")
        assert r.returncode == 2 and r.stdout == "", r
        assert "got no key (only Claude's own commands do)" in r.stderr, r.stderr
        assert t.accepted() == 0


def test_ssh_hard_agent_keys_have_a_lifetime() -> None:
    with H.ssh_env() as s:
        _box(s)
        log = s.root / "ssh-add.log"
        wrap = s.root / "ssh-add-wrap"
        wrap.write_text(f"#!/bin/sh\necho \"$*\" >> {H.sq(log)}\n"
                        f"exec {H.sq(H.ENV_BIN / 'ssh-add')} \"$@\"\n")
        os.chmod(wrap, 0o755)
        s.set(tools={"ssh-add": str(wrap)})
        assert s.run("ssh", "box", "true").returncode == 0
        calls = log.read_text().splitlines()
        assert calls and all(c.split()[:3] == ["-q", "-t", "300"] and c.endswith(" -")
                             for c in calls), calls


def test_ssh_hard_agent_dies_with_the_stand_in() -> None:
    with H.ssh_env() as s:
        _box(s)
        p = subprocess.Popen([str(s.stub("ssh")), "-o", "ControlMaster=no", "box",
                              "echo started; sleep 20"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, env=s.proc_env())
        try:
            assert p.stdout is not None and p.stdout.readline() == b"started\n"
            assert [l for l in s.leftovers() if "ssh-agent" in l]      # alive while it runs
            p.send_signal(signal.SIGKILL)
            p.wait()
            assert s.wait_for(lambda: not [l for l in s.leftovers() if "ssh-agent" in l],
                              timeout=10), s.leftovers()
        finally:
            if p.poll() is None:
                p.kill()
                p.wait()
            if p.stdout is not None:
                p.stdout.close()


def test_ssh_hard_cmdline_backstops() -> None:
    """The `ssh -G` check catches what the parser would have refused first."""
    with H.ssh_env() as s:
        _box(s)
        st = ssh._load()
        link = ssh._build_link("box", st)
        with ssh_conf.Conn(link) as conn:
            cfg = conn.prepare().read_text()
            assert "GlobalKnownHostsFile /dev/null" in cfg.split("Host *")[0]
            for ok in (["-L", "8080:127.0.0.1:22"], ["-D", "1080"], ["-L", "localhost:8080:h:22"],
                       ["-L", "[::1]:8080:h:22"]):
                ssh._verify_cmdline(conn, ok)
            other_key = s.root / "other-key"          # ssh drops an -i file that doesn't exist
            other_key.write_text("x\n")
            for bad, what in ((["-i", str(other_key)], "identityfile"),
                              (["-o", f"IdentityFile={other_key}"], "identityfile"),
                              (["-J", "x"], "proxyjump"),
                              (["-o", "GlobalKnownHostsFile=/tmp/x"], "globalknownhostsfile"),
                              (["-L", "*:2222:127.0.0.1:22"], "open to other machines"),
                              (["-D", "0.0.0.0:1080"], "open to other machines"),
                              (["-L", "192.0.2.7:2222:/tmp/rs"], "open to other machines"),
                              (["-R", "2222:127.0.0.1:22"], "remoteforward")):
                try:
                    ssh._verify_cmdline(conn, bad)
                except ssh.SshError as e:
                    assert "couldn't verify" in e.message and what in e.message, (bad, e.message)
                else:
                    raise AssertionError(f"-G check missed {bad}")


def test_ssh_hard_wildcard_forwards_refused() -> None:
    cases = {"8080:127.0.0.1:22": None, "*:2222:h:22": "*", ":2222:h:22": "",
             "0.0.0.0:1:h:2": "0.0.0.0", "localhost:2222:h:22": "localhost",
             "[::1]:2222:h:22": "::1", "[::]:2222:h:22": "::", "/tmp/s:h:22": None,
             "2222:/tmp/rs": None, "10.0.0.1:2222:/tmp/rs": "10.0.0.1"}
    for spec, host in cases.items():
        assert ssh_args.forward_listen_host(spec, False) == host, spec
    assert ssh_args.forward_listen_host("1080", True) is None
    assert ssh_args.forward_listen_host("0.0.0.0:1080", True) == "0.0.0.0"
    for good in (["-L", "8080:h:22"], ["-L", "127.0.0.1:8080:h:22"], ["-D", "localhost:1080"],
                 ["-o", "LocalForward=8080 h:22"], ["-o", "DynamicForward=1080"]):
        ssh_args.parse_ssh([*good, "box", "true"])
    with H.ssh_env() as s:
        t = _box(s)
        for opts in (["-L", "*:2222:127.0.0.1:22"], ["-L", ":2222:h:22"], ["-D", "0.0.0.0:1080"],
                     ["-o", "LocalForward=*:9 h:22"], ["-o", "DynamicForward=192.0.2.5:7"],
                     ["-L", "192.0.2.5:2222:h:22"]):
            r = s.run("ssh", *opts, "box", "echo hi")
            assert r.returncode == 2 and "would open a port to other machines" in r.stderr, (opts, r)
        assert t.accepted() == 0 and not s.masters()
        r = s.run("ssh", "-L", f"{H.free_port()}:127.0.0.1:{t.port}", "box", "echo fwd")
        assert r.returncode == 0 and r.stdout == "fwd\n", r


def test_ssh_hard_an_alias_of_a_configured_host_is_refused_with_a_hint() -> None:
    """PLAN-0.11 §1.4: a name the user's ssh config sends to a configured
    host's address (by HostName, or by resolving to it on the same port) is
    refused with a hint, never routed; another one is the user's own ssh."""
    with H.ssh_env() as s:
        t = s.sshd("target")
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nssh = false\n')
        s.approve()
        d = HP.user_tools(s.env, "ssh", ssh_g={
            "myalias": {"hostname": "127.0.0.1", "port": str(t.port)},
            "byname": {"hostname": "localhost", "port": str(t.port)},
            "other": {"hostname": "192.0.2.10"}})
        s.set(user_tools=str(d))
        for alias in ("myalias", "byname"):
            r = s.run("ssh", alias, "uptime")
            assert r.returncode == 2 and "fake ssh ran" not in r.stdout, (alias, r)
            assert f"gateway: {alias} reaches box, which goes through the gateway" in r.stderr, r
            assert "use `ssh box` so its rights apply" in r.stderr, r.stderr
        r = s.run("ssh", "other", "uptime")
        assert r.returncode == 0 and r.stdout == "fake ssh ran\n", r
        assert t.accepted() == 0 and t.commands() == []


def test_ssh_hard_resolve_strings_are_safe() -> None:
    with H.ssh_env() as s:
        t = s.sshd("target")
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n\n'
                     '[accounts.gh]\nkind = "github"\nlogin = "me"\n')
        r = ssh.resolve(["evil‮name", "x"])
        assert r["kind"] == "unknown" and r["name"] is None
        r = ssh.resolve(["-l", "bob‮", "box", "x"])
        assert r["kind"] == "host" and r["name"] == "box" and r["user"] is None
        r = ssh.resolve(["bad‮user@github.com", "git-upload-pack 'a/b'"])
        assert r["kind"] == "endpoint" and r["user"] is None and r["addr"] is None
        assert ssh.resolve(["box", "x"])["user"] == H.real_user()
        assert not list(s.run_dir.glob("ssh-resolve*"))       # a private config per call


def test_ssh_hard_main_never_prints_a_traceback() -> None:
    with H.ssh_env() as s:
        _box(s)
        orig = ssh._ssh

        def boom(argv: list[str]) -> int:
            raise KeyError("some value")

        ssh._ssh = boom
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                rc = ssh.main("ssh", ["box", "true"])
        finally:
            ssh._ssh = orig
        assert rc == 1
        assert err.getvalue() == ("gateway: ssh failed unexpectedly (KeyError); try again, or run "
                                  "gate status\n"), err.getvalue()
        assert "some value" not in str(s.audit())


def test_ssh_hard_probe_deadline_covers_slow_resolution() -> None:
    with H.ssh_env() as s:
        t = s.sshd("target")
        orig = ssh_conf.when_ok

        def slow_when(a: formmod.Address) -> bool:
            if a.host == "slow.invalid":      # a resolver that hangs (never asked: no network)
                time.sleep(8)
                return False
            return orig(a)

        ssh_conf.when_ok = slow_when
        try:
            cands = [formmod.Address(host="slow.invalid", port=22, user="u", when="10.0.0.0/8"),
                     formmod.Address(host="127.0.0.1", port=t.port, user=H.real_user())]
            t0 = time.time()
            c = ssh_conf.choose("box", cands, [], verify=False, use_cache=False)
            took = time.time() - t0
        finally:
            ssh_conf.when_ok = orig
        assert c.addr.port == t.port and took < 4, (c, took)
        assert "slow.invalid:22 didn't answer" in c.why or "didn't answer" in c.why, c.why


def test_ssh_hard_crypto_only_narrowed() -> None:
    """-c, -m and -o Ciphers/MACs/KexAlgorithms/HostKeyAlgorithms may narrow
    or reorder ssh's defaults, never add a weaker algorithm."""
    with H.ssh_env() as s:
        t = _box(s)
        st = ssh._load()
        link = ssh._build_link("box", st)
        with ssh_conf.Conn(link) as conn:
            for ok in (["-c", "aes256-ctr"], ["-o", "Ciphers=-aes128-ctr"],
                       ["-o", "MACs=^hmac-sha2-512"], ["-o", "KexAlgorithms=curve25519-sha256"],
                       ["-o", "HostKeyAlgorithms=ssh-ed25519"], ["-m", "hmac-sha2-256"]):
                ssh._verify_cmdline(conn, ok)
            for bad, what in ((["-c", "3des-cbc"], "ciphers: 3des-cbc"),
                              (["-o", "Ciphers=+aes128-cbc"], "ciphers: aes128-cbc"),
                              (["-m", "hmac-md5"], "macs: hmac-md5"),
                              (["-o", "MACs=hmac-sha2-256,hmac-md5"], "macs: hmac-md5"),
                              (["-o", "KexAlgorithms=+diffie-hellman-group1-sha1"],
                               "kexalgorithms: diffie-hellman-group1-sha1"),
                              (["-o", "HostKeyAlgorithms=+ssh-rsa"], "hostkeyalgorithms: ssh-rsa")):
                try:
                    ssh._verify_cmdline(conn, bad)
                except ssh.SshError as e:
                    assert "only use its default algorithms" in e.message and what in e.message, (
                        bad, e.message)
                else:
                    raise AssertionError(f"downgrade accepted: {bad}")
        for opts in (["-c", "3des-cbc"], ["-o", "KexAlgorithms=+diffie-hellman-group1-sha1"]):
            r = s.run("ssh", *opts, "box", "echo hi")
            assert r.returncode == 2 and "default algorithms" in r.stderr and r.stdout == "", r
        assert t.commands() == [] and t.accepted() == 0 and not s.masters()
        r = s.run("ssh", "-c", "aes256-ctr", "-o", "MACs=hmac-sha2-512-etm@openssh.com", "box",
                  "echo narrowed")
        assert r.returncode == 0 and r.stdout == "narrowed\n", r
