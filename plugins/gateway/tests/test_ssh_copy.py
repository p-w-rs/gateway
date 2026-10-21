"""scp, sftp and rsync through the stand-ins (group 'ssh')."""
from __future__ import annotations

import shutil
import subprocess

import harness  # noqa: F401
import harness_ssh as H


def _box(s: H.SshEnv) -> H.Sshd:
    t = s.sshd("target")
    s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n')
    s.approve()
    s.host("box", t)
    return t


def test_ssh_copy_scp_both_ways() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        src = s.root / "local.txt"
        src.write_text("hello over scp\n")
        remote = t.dir / "remote-dir"
        remote.mkdir()
        r = s.run("scp", str(src), f"box:{remote}/up.txt")
        assert r.returncode == 0, r
        assert (remote / "up.txt").read_text() == "hello over scp\n"
        r = s.run("scp", f"box:{remote}/up.txt", str(s.root / "down.txt"))
        assert r.returncode == 0 and (s.root / "down.txt").read_text() == "hello over scp\n", r
        # recursive, legacy protocol, and by address with -P
        (s.root / "tree" / "sub").mkdir(parents=True)
        (s.root / "tree" / "sub" / "f").write_text("deep\n")
        r = s.run("scp", "-r", "-O", "-P", str(t.port), str(s.root / "tree"),
                  f"{H.real_user()}@127.0.0.1:{remote}/")
        assert r.returncode == 0, r
        assert (remote / "tree" / "sub" / "f").read_text() == "deep\n"
        uses = s.audit("use")
        assert uses and all(u["target"] == "box" for u in uses)
        # scp passes -oControlMaster=no: it reuses a master but never starts one
        assert not s.masters()


def test_ssh_copy_scp_reuses_master_and_refuses() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        assert s.run("ssh", "box", "true").returncode == 0
        n = t.accepted()
        f = s.root / "a.txt"
        f.write_text("x")
        assert s.run("scp", str(f), f"box:{t.dir}/b.txt").returncode == 0
        assert t.accepted() == n          # through the existing master
        for opts, want in ((("-S", "/bin/sh"), "-S isn't allowed"),
                           (("-F", "/dev/null"), "-F isn't allowed"),
                           (("-i", "/tmp/k"), "-i isn't allowed"),
                           (("-o", "ProxyCommand=id"), "ProxyCommand isn't allowed")):
            r = s.run("scp", *opts, str(f), f"box:{t.dir}/c.txt")
            assert r.returncode == 2 and want in r.stderr, (opts, r)
        r = s.run("scp", str(f), f"nowhere:{t.dir}/c.txt")
        assert r.returncode != 0 and "nowhere isn't in gateway.toml" in r.stderr, r
        assert not (t.dir / "c.txt").exists()


def test_ssh_copy_sftp_batch() -> None:
    with H.ssh_env() as s:
        t = _box(s)
        (t.dir / "srv").mkdir()
        (t.dir / "srv" / "data.bin").write_bytes(b"\x00\x01binary\xff")
        batch = f"cd {t.dir}/srv\nls\nget data.bin {s.root}/got.bin\nput {s.root}/ssh-entry.json\n"
        r = s.run("sftp", "-b", "-", "box", input=batch)
        assert r.returncode == 0, r
        assert (s.root / "got.bin").read_bytes() == b"\x00\x01binary\xff"
        assert (t.dir / "srv" / "ssh-entry.json").exists()
        r = s.run("sftp", "-b", "-", "-P", str(t.port), f"{H.real_user()}@127.0.0.1",
                  input=f"ls {t.dir}/srv\n")
        assert r.returncode == 0 and "data.bin" in r.stdout, r
        r = s.run("sftp", "-D", "/usr/libexec/sftp-server", "box")
        assert r.returncode == 2 and "-D isn't allowed" in r.stderr
        # round 1: -s with a path runs that command on the host (sudo included)
        n = t.accepted()
        for args in (("-s", "/usr/bin/sudo /usr/libexec/sftp-server"), ("-ssftp",)):
            r = s.run("sftp", "-b", "-", *args, "box", input="ls\n")
            assert r.returncode == 2 and "-s isn't allowed" in r.stderr, (args, r)
        assert t.accepted() == n


def test_ssh_copy_rsync_via_rsync_rsh() -> None:
    rsync = shutil.which("rsync") or ("/opt/local/bin/rsync" if shutil.which(
        "/opt/local/bin/rsync") else None)
    if not rsync:
        print("       (skipped: no rsync on this machine)")
        return
    with H.ssh_env() as s:
        t = _box(s)
        src = s.root / "site"
        (src / "css").mkdir(parents=True)
        (src / "index.html").write_text("<p>hi</p>\n")
        (src / "css" / "a.css").write_text("p{}\n")
        dst = t.dir / "www"
        env = s.proc_env({"RSYNC_RSH": str(s.stub("ssh"))})
        r = subprocess.run([rsync, "-a", f"{src}/", f"box:{dst}/"], capture_output=True, text=True,
                           env=env, timeout=60)
        assert r.returncode == 0, r
        assert (dst / "index.html").read_text() == "<p>hi</p>\n"
        assert (dst / "css" / "a.css").exists()
        r = subprocess.run([rsync, "-a", f"box:{dst}/index.html", str(s.root / "back.html")],
                           capture_output=True, text=True, env=env, timeout=60)
        assert r.returncode == 0 and (s.root / "back.html").read_text() == "<p>hi</p>\n", r
        # rsync's own -e with a refused option is refused by the stand-in
        r = subprocess.run([rsync, "-a", "-e", f"{s.stub('ssh')} -o ProxyCommand=id",
                            f"{src}/", f"box:{dst}/x/"], capture_output=True, text=True, env=env,
                           timeout=60)
        assert r.returncode != 0 and "ProxyCommand isn't allowed" in r.stderr, r
        assert any("rsync --server" in c for c in t.commands())
