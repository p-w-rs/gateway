"""Address choice, jump hosts and host-key pinning across candidates
(group 'ssh')."""
from __future__ import annotations

import json
import time

import harness  # noqa: F401
import harness_ssh as H
from gateway import paths, ssh, ssh_conf


def test_ssh_route_via_chain() -> None:
    with H.ssh_env() as s:
        j1 = s.sshd("jump1")
        j2 = s.sshd("jump2")
        t = s.sshd("target")
        u = H.real_user()
        s.write_form(f'[hosts.gate1]\naddress = "{j1.addr()}"\n\n'
                     f'[hosts.gate2]\naddress = "{j2.addr()}"\nvia = "gate1"\n\n'
                     f'[hosts.inner]\naddress = "{u}@127.0.0.1:{t.port}"\nvia = "gate2"\n')
        s.approve()
        s.host("gate1", j1)
        s.host("gate2", j2)
        s.host("inner", t)
        r = s.run("ssh", "inner", "echo deep inside")
        assert r.returncode == 0 and r.stdout == "deep inside\n", r
        # each hop authenticated once with its own key, through the one before
        assert (j1.accepted(), j2.accepted(), t.accepted()) == (1, 1, 1)
        assert t.commands() == ["echo deep inside"] and j1.commands() == []
        use = s.audit("use")[-1]
        assert use["via"] == "gate2" and "behind its jump host" in use["why"]
        # the next call reuses the masters
        assert s.run("ssh", "inner", "echo again").stdout == "again\n"
        assert (j1.accepted(), j2.accepted(), t.accepted()) == (1, 1, 1)
        # scp through the chain
        f = s.root / "f.txt"
        f.write_text("through two jumps\n")
        assert s.run("scp", str(f), f"inner:{t.dir}/f.txt").returncode == 0
        assert (t.dir / "f.txt").read_text() == "through two jumps\n"
        # a jump host lowered to "ask" caps the hosts behind it
        s.write_form(f'[hosts.gate1]\naddress = "{j1.addr()}"\nssh = "ask"\n\n'
                     f'[hosts.gate2]\naddress = "{j2.addr()}"\nvia = "gate1"\n\n'
                     f'[hosts.inner]\naddress = "{u}@127.0.0.1:{t.port}"\nvia = "gate2"\n')
        s.set(direct=False)
        r = s.run("ssh", "inner", "echo no")
        assert r.returncode == 2 and "ssh on inner asks the user each time" in r.stderr, r
        # the narrowing closed the masters of gate1 and of the hosts behind it
        assert not s.masters()
        s.set(direct=True)
        assert s.run("ssh", "inner", "echo yes").stdout == "yes\n"
        assert (j1.accepted(), j2.accepted(), t.accepted()) == (2, 2, 2)


def test_ssh_route_failover_blackhole_closed_then_working() -> None:
    with H.ssh_env() as s:
        t = s.sshd("target")
        hole = s.blackhole()
        closed = H.free_port()
        u = H.real_user()
        s.write_form(f'[hosts.box]\naddress = "{u}@127.0.0.1:{hole.port}"\n'
                     f'also = ["127.0.0.1:{closed}", "127.0.0.1:{t.port}"]\n')
        s.approve()
        s.host("box", t)
        t0 = time.time()
        r = s.run("ssh", "box", "echo reached")
        took = time.time() - t0
        assert r.returncode == 0 and r.stdout == "reached\n", r
        assert took < 6, took                    # probes are parallel, 1 s each
        use = s.audit("use")[-1]
        assert use["address"] == f"{u}@127.0.0.1:{t.port}"
        assert f"127.0.0.1:{hole.port} didn't answer" in use["why"]
        assert f"127.0.0.1:{closed} didn't answer" in use["why"]
        # the choice is cached for this network (5 min): no probing next time
        cache = json.loads((paths.run_dir() / "addr-box.json").read_text())
        assert list(cache.values())[0]["index"] == 2
        r = s.run("ssh", "box", "echo cached")
        assert r.stdout == "cached\n" and "(cached)" in s.audit("use")[-1]["why"]
        # nothing answers: a clear message, no ssh attempt
        t.stop()
        ssh_conf.cache_clear("box")
        ssh.close_masters("box")
        r = s.run("ssh", "box", "echo x")
        assert r.returncode == 255 and "box didn't answer on any address" in r.stderr, r


def test_ssh_route_when_cidr() -> None:
    with H.ssh_env() as s:
        t = s.sshd("target")
        hole = s.blackhole()
        u = H.real_user()
        # the first address is only for another network: skipped without a probe
        s.write_form(f'[hosts.box]\naddress = "{u}@127.0.0.1:{hole.port}"\n'
                     f'when = "10.250.0.0/16"\nalso = ["127.0.0.1:{t.port}"]\n')
        s.approve()
        s.host("box", t)
        t0 = time.time()
        r = s.run("ssh", "box", "echo here")
        assert r.returncode == 0 and r.stdout == "here\n", r
        why = s.audit("use")[-1]["why"]
        assert "didn't answer" not in why and why == f"{u}@127.0.0.1:{t.port} answered", why
        # a `when` that matches this machine's source address toward it is used
        s.write_form(f'[hosts.box]\naddress = "{u}@127.0.0.1:{t.port}"\nwhen = "127.0.0.0/8"\n'
                     f'also = ["127.0.0.1:{hole.port}"]\n')
        s.approve()
        r = s.run("ssh", "box", "echo lan")
        assert r.stdout == "lan\n" and s.audit("use")[-1]["address"].endswith(f":{t.port}")
        # only addresses for other networks: refused with a hint
        s.write_form(f'[hosts.box]\naddress = "{u}@127.0.0.1:{t.port}"\nwhen = "10.250.0.0/16"\n')
        s.approve()
        r = s.run("ssh", "box", "echo x")
        assert r.returncode == 255 and "none of box's addresses is for this network" in r.stderr
        assert ssh_conf.when_ok(ssh_conf.formmod.Address("127.0.0.1", 22, when="127.0.0.0/8"))
        assert not ssh_conf.when_ok(ssh_conf.formmod.Address("127.0.0.1", 22, when="10.0.0.0/8"))


def test_ssh_route_hostkey_mismatch_non_last_skipped() -> None:
    with H.ssh_env() as s:
        impostor = s.sshd("impostor")       # another machine answering on the first address
        t = s.sshd("target")
        u = H.real_user()
        s.write_form(f'[hosts.box]\naddress = "{u}@127.0.0.1:{impostor.port}"\n'
                     f'also = ["127.0.0.1:{t.port}"]\n')
        s.approve()
        priv, pub = s.host("box", t, authorize=[impostor])
        r = s.run("ssh", "box", "echo real")
        assert r.returncode == 0 and r.stdout == "real\n", r
        assert impostor.accepted() == 0 and impostor.commands() == []
        assert s.popup_calls() == []                    # silent
        skip = s.audit("hostkey_skip")
        assert skip and skip[0]["address"] == f"{u}@127.0.0.1:{impostor.port}"
        assert "showed another host key (skipped)" in s.audit("use")[-1]["why"]
        # if the last candidate doesn't answer, there is nothing to use
        t.stop()
        ssh.close_masters("box")
        r = s.run("ssh", "box", "echo x")
        assert r.returncode == 255 and "showed another host key (skipped)" in r.stderr, r
        assert s.popup_calls() == [] and impostor.accepted() == 0


def test_ssh_route_hostkey_mismatch_last_asks() -> None:
    with H.ssh_env() as s:
        t = s.sshd("target")
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n')
        s.approve()
        old = harness.fake_host_key("reinstalled")
        s.host("box", t, pins=[old])
        s.set(popup={"hostkey": ["cancelled"]})
        r = s.run("ssh", "box", "echo x")
        assert r.returncode == 1 and "the user didn't accept box's new host key" in r.stderr, r
        calls = s.popup_calls()
        assert len(calls) == 1 and calls[0]["kind"] == "hostkey" and calls[0]["entry"] == "box"
        assert calls[0]["old"][0].startswith("ssh-ed25519 SHA256:")
        assert t.commands() == [] and t.accepted() == 0
        assert s.vault()["hosts"]["box"]["host_keys"] == [old]
        # no screen: refused too, nothing changes
        s.set(popup={"hostkey": ["unavailable"]})
        r = s.run("ssh", "box", "echo x")
        assert r.returncode == 75 and "no gateway dialog could ask the user; don't connect" in r.stderr, r
        s.set(popup={"hostkey": ["stillopen"]})
        r = s.run("ssh", "box", "echo x")
        assert r.returncode == 75 and r.stderr.count("the gateway dialog for box is still open") == 1, r
        s.set(popup={"hostkey": ["timeout"]})
        r = s.run("ssh", "box", "echo x")
        assert r.returncode == 75 and "nobody answered the dialog for the box host key" in r.stderr
        # the user accepts: the new key is pinned and the command runs
        s.set(popup={"hostkey": ["ok"]})
        r = s.run("ssh", "box", "echo accepted")
        assert r.returncode == 0 and r.stdout == "accepted\n", r
        assert s.vault()["hosts"]["box"]["host_keys"] == [t.host_key]
        assert any(e["what"] == "hostkey" for e in s.vault()["events"])
        assert [a["outcome"] for a in s.audit("hostkey")] == ["cancelled", "unavailable",
                                                             "timeout", "ok"]
        assert s.popup_calls()[-1]["address"] == t.addr()
