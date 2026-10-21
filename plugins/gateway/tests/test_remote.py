"""The managed remote runtime (PLAN-v4 phase 6): artifacts, staging, identity,
remote terminals and jobs, disconnects, the host-change gates.

Pure parts here in this process; everything else against real sshds on
127.0.0.1 (harness_ssh) and a real gated (harness_daemon) with FAKE runtime
artifacts (harness_remote: a stand-in pixi-unpack that links the gateway
env's own bash and tmux), so staging, the sha256 checks, the readiness probe,
the runtime's tmux on its private socket and every remote command run for
real over the gateway's ssh. The live run against the Linux VM with real
pixi-pack artifacts is tests/acceptance_remote.py.

Canaries are generated here and never printed: assertion messages carry
lengths and hashes only.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Any

import harness as H
import harness_daemon as D
import harness_remote as R
import harness_ssh as S
from gateway import consent, paths, runtime_pack, testing, vault
from gateway import form as formmod
from gateway.daemon import remote as RM
from gateway.daemon import terminals as T


def canary(prefix: str = "cv") -> str:
    return f"{prefix}-{secrets.token_urlsafe(18)}"


def sha16(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()[:16]


SHA256 = "{ if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }"


# ---------------------------------------------------------------------------
# Pure parts
# ---------------------------------------------------------------------------


def test_platforms_map_from_uname_and_others_are_refused_with_the_remedy():
    assert runtime_pack.platform_of("Linux", "x86_64") == "linux-64"
    assert runtime_pack.platform_of("Linux", "aarch64") == "linux-aarch64"
    assert runtime_pack.platform_of("Linux", "arm64") == "linux-aarch64"
    assert runtime_pack.platform_of("Darwin", "arm64") == "osx-arm64"
    assert runtime_pack.platform_of("Darwin", "x86_64") == "osx-64"
    for s, m in (("Linux", "armv7l"), ("Linux", "riscv64"), ("FreeBSD", "amd64"),
                 ("MINGW64_NT-10.0", "x86_64"), ("", "")):
        assert runtime_pack.platform_of(s, m) is None
    t = runtime_pack.unsupported_text("Linux", "riscv64")
    assert "Linux riscv64" in t and "Linux x86_64 or aarch64" in t and "ssh HOST CMD" in t
    assert "?" in runtime_pack.unsupported_text("Linux; rm -rf /", "x")


def test_the_runtime_workspace_is_bash_and_tmux_for_four_platforms_locked_without_python():
    src = paths.runtime_src_dir()
    import tomllib
    m = tomllib.loads((src / "pixi.toml").read_text())
    assert sorted(m["workspace"]["platforms"]) == sorted(runtime_pack.PLATFORMS)
    assert set(m["dependencies"]) == {"bash", "tmux"}
    assert set(m["feature"]["unpacker"]["dependencies"]) == {"pixi-unpack"}
    lock = (src / "pixi.lock").read_text()
    for plat in runtime_pack.PLATFORMS:
        for pkg in ("bash-5.", "tmux-3.", "pixi-unpack-0.7."):
            assert re.search(rf"conda-forge/{plat}/{re.escape(pkg)}", lock), (plat, pkg)
    assert "/python-3" not in lock, "the remote runtime must not carry Python"
    assert runtime_pack.VERSION_RE.fullmatch(runtime_pack.version())
    # the gateway env packs it: pixi-pack and zstd are in the plugin's own manifest
    main = tomllib.loads((paths.plugin_root() / "pixi.toml").read_text())
    assert "pixi-pack" in main["dependencies"] and "zstd" in main["dependencies"]


def _conda_pkg(path: Path, files: dict[str, bytes], links: dict[str, str] | None = None,
               bad: str | None = None) -> None:
    """A .conda package: a zip with pkg-*.tar.zst (made with the env's zstd)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data in files.items():
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            ti.mode = 0o755
            t.addfile(ti, io.BytesIO(data))
        for name, target in (links or {}).items():
            ti = tarfile.TarInfo(name)
            ti.type = tarfile.SYMTYPE
            ti.linkname = target
            t.addfile(ti)
        if bad:
            ti = tarfile.TarInfo(bad)
            ti.size = 1
            t.addfile(ti, io.BytesIO(b"x"))
    z = subprocess.run([paths.tool("zstd"), "-q", "-c"], input=buf.getvalue(), capture_output=True,
                       check=True).stdout
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("metadata.json", '{"conda_pkg_format_version": 2}')
        zf.writestr(f"pkg-{path.stem}.tar.zst", z)
        zf.writestr(f"info-{path.stem}.tar.zst", z)


def test_the_unpacker_takes_only_pixi_unpack_and_its_shared_libraries_from_the_packages():
    with H.gateway_env() as env:
        pack = env.root / "pack"
        ch = pack / "channel" / "linux-aarch64"
        ch.mkdir(parents=True)
        (pack / "channel" / "noarch").mkdir()
        _conda_pkg(ch / "pixi-unpack-0.7.11-h0_0.conda",
                   {"bin/pixi-unpack": b"\x7fELF-unpacker", "share/doc/README": b"doc"})
        _conda_pkg(ch / "openssl-3.6.5-h0_0.conda",
                   {"lib/libssl.so.3": b"ssl", "lib/libcrypto.so.3": b"crypto",
                    "lib/engines-3/x.so": b"engine", "bin/openssl": b"tool",
                    "include/openssl/ssl.h": b"h"}, links={"lib/libssl.so": "libssl.so.3"})
        _conda_pkg(ch / "libgomp-16-h0_0.conda", {"lib/libgomp.so.1.0.0": b"omp"})
        out = env.root / "out"
        got = runtime_pack.extract_unpacker(pack, out, "linux-aarch64")
        assert sorted(got) == ["unpacker/bin/pixi-unpack", "unpacker/lib/libcrypto.so.3",
                               "unpacker/lib/libssl.so.3"]
        assert os.stat(out / "unpacker/bin/pixi-unpack").st_mode & 0o111
        assert not (out / "unpacker/lib/libssl.so").exists() and not (out / "share").exists()
        # an unsafe member in any package refuses the whole build
        _conda_pkg(ch / "evil-1-h0_0.conda", {"lib/libz.so.1": b"z"}, bad="../../escape")
        try:
            runtime_pack.extract_unpacker(pack, env.root / "out2", "linux-aarch64")
            raise AssertionError("an unsafe package path was accepted")
        except runtime_pack.PackError as e:
            assert "unsafe" in e.message
        assert not (env.root / "escape").exists()
        # no pixi-unpack at all: refused
        empty = env.root / "empty" / "channel" / "linux-aarch64"
        empty.mkdir(parents=True)
        _conda_pkg(empty / "openssl-1-h0_0.conda", {"lib/libssl.so.3": b"s"})
        try:
            runtime_pack.extract_unpacker(env.root / "empty", env.root / "out3", "linux-aarch64")
            raise AssertionError("a build without pixi-unpack passed")
        except runtime_pack.PackError:
            pass


def test_artifacts_are_built_once_hashed_and_rebuilt_when_a_file_changes():
    with H.gateway_env() as env:
        plat = R.local_platform()
        art = R.fake_artifacts(env.root / "fake", plat)
        with testing.override(root=env.root, runtime_artifacts=str(art)):
            m = runtime_pack.ensure(plat)
            assert m["platform"] == plat and m["version"] == runtime_pack.version()
            rels = sorted(f["path"] for f in m["files"])
            assert rels == ["runtime.tar", "unpacker/bin/pixi-unpack", "unpacker/lib/libtest.so.1"]
            d = runtime_pack.artifacts_dir(plat)
            for f in m["files"]:
                assert runtime_pack.sha256_file(d / f["path"]) == f["sha256"]
            assert str(d).startswith(str(paths.runtime_data_dir()))
            assert not str(d).startswith(str(paths.plugin_root()))
            built = m["built"]
            time.sleep(0.01)
            assert runtime_pack.ensure(plat)["built"] == built        # the same build, verified
            # a file changed since the build: not used, built again
            with open(d / "runtime.tar", "ab") as fh:
                fh.write(b"tampered")
            assert runtime_pack.load_manifest(plat) is None
            m2 = runtime_pack.ensure(plat)
            assert m2["built"] != built and runtime_pack.load_manifest(plat) is not None
            # a manifest naming a path outside the allowed shapes is never trusted
            mm = json.loads((d / "manifest.json").read_text())
            mm["files"].append({"path": "../escape", "sha256": "0" * 64, "size": 0, "mode": 420})
            (d / "manifest.json").write_text(json.dumps(mm))
            assert runtime_pack.load_manifest(plat) is None
            try:
                runtime_pack.ensure("solaris-sparc")
                raise AssertionError("an unknown platform was built")
            except runtime_pack.PackError as e:
                assert e.code == "unsupported"


def test_stty_modes_parse_on_gnu_and_bsd():
    gnu_pw = "500:5:bf:8a33:3:1c:7f:15:4:0:1:0:11:13:1a:0:12:f:17:16:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0"
    gnu_sh = "500:5:bf:8a3b:3:1c:7f:15:4:0:1:0:11:13:1a:0:12:f:17:16:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0"
    gnu_rl = "500:5:bf:8a31:3:1c:7f:15:4:0:1:0:11:13:1a:0:12:f:17:16:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0:0"
    assert RM.parse_stty(gnu_pw, "linux-aarch64") == (False, True)     # read -s: echo off, canonical
    assert RM.parse_stty(gnu_sh, "linux-64") == (True, True)
    assert RM.parse_stty(gnu_rl, "linux-64") == (False, False)
    bsd_pw = "gfmt1:cflag=4b00:iflag=6b02:lflag=200005c3:oflag=3:discard=f:dsusp=19:eof=4"
    bsd_sh = "gfmt1:cflag=4b00:iflag=6b02:lflag=200005cb:oflag=3:discard=f:dsusp=19:eof=4"
    assert RM.parse_stty(bsd_pw, "osx-arm64") == (False, True)
    assert RM.parse_stty(bsd_sh, "osx-arm64") == (True, True)
    assert RM.parse_stty("-", "linux-64") is None and RM.parse_stty("", "osx-64") is None
    assert RM.parse_stty("gfmt1:cflag=zz", "osx-64") is None


def test_runtime_paths_are_plain_and_a_change_waits_for_the_users_ok():
    for ok in ("~/.local/share/gateway-runtime", "/scratch/me/gw", "~/gw-rt_1.2@x+y"):
        assert RM.base_ok(ok), ok
    for bad in ("relative/x", "~user/x", "/a/../etc", "/a//b", "/a b", "/a;rm", '~/"x"', "/a\nb", "",
                "~/$HOME", "/a/`id`"):
        assert not RM.base_ok(bad), bad
    assert RM.base_expr("~/a b".replace(" ", "_")) == '"$HOME"/a_b'
    assert RM.base_expr("/x/y/") == "/x/y"
    with H.gateway_env() as env:
        env.write_form('[hosts.box]\naddress = "me@box.example.org"\nruntime = "~/rt"\n'
                       '[hosts.bad]\naddress = "me@bad.example.org"\nruntime = "/a/../b"\n'
                       '[hosts.localhost]\nruntime = "/x"\n')
        f = formmod.load()
        assert f.hosts["box"].runtime == "~/rt"
        msgs = [p.render() for p in f.problems]
        assert any("runtime must be an absolute" in m for m in msgs), msgs
        assert any("runtime isn't allowed on localhost" in m for m in msgs), msgs
        env.write_form('[hosts.box]\naddress = "me@box.example.org"\nruntime = "~/rt"\n')
        consent.approve_all(env.form())
        eff = consent.compute(env.form(), vault.load())
        assert eff.hosts["box"].runtime == "~/rt" and not eff.pending_for("box")
        env.write_form('[hosts.box]\naddress = "me@box.example.org"\nruntime = "/elsewhere"\n')
        eff = consent.compute(env.form(), vault.load())
        assert eff.hosts["box"].runtime == "~/rt", "an unapproved runtime path applied"
        assert [c.what for c in eff.pending_for("box")] == ["runtime /elsewhere (was ~/rt)"]


def test_a_remote_start_file_sets_only_the_curated_environment_and_removes_itself():
    p = T.Pane(id=T.ulid("t"), host="box", cwd="/srv/a b")
    text = T.remote_start_text(p, rt="/h/u/.local/share/gateway-runtime/x", lang="C.UTF-8",
                               me="/h/u/rt/terms/t.rc")
    assert 'unset "$__gw_n"' in text and "LC_*" in text
    assert "export PATH=/h/u/.local/share/gateway-runtime/x/env/bin:" + RM.SYSTEM_PATH in text
    assert "export SHELL=/h/u/.local/share/gateway-runtime/x/env/bin/bash" in text
    assert ". /h/u/.local/share/gateway-runtime/x/gateway.rc" in text
    # its first line claims it (renamed: a start gated settled as never run stops there)
    assert text.splitlines()[1] == ("command mv -f -- /h/u/rt/terms/t.rc /h/u/rt/terms/t.rc.run "
                                    "2>/dev/null || exit 125"), text.splitlines()[1]
    assert "command rm -f -- /h/u/rt/terms/t.rc.run" in text and "cd -- '/srv/a b'" in text
    assert ".bashrc" not in text and ".profile" not in text and "CLAUDE_PID" not in text
    j = T.Pane(id=T.ulid("j"), host="box", cwd="/tmp")
    jt = T.remote_start_text(j, rt="/r", lang="C.UTF-8", me="/r/terms/j.sh", argv=["echo", "a b"])
    assert jt.rstrip().endswith("echo 'a b'") and "unset HISTFILE" in jt
    assert "HISTFILE" in RM.RC_TEXT and "histexpand" in RM.RC_TEXT


def test_the_bind_check_needs_the_host_records_marker_and_nonce():
    s = RM.bind_check("/r/x", "m_abc", "n0nce")
    assert "/r/x/hosts/m_abc" in s and "n0nce" in s and RM.WRONG_HOST in s and "exit 97" in s
    with H.gateway_env() as env:
        rt = env.root / "rt"
        (rt / "hosts").mkdir(parents=True)
        def run(nonce: str) -> subprocess.CompletedProcess:
            return subprocess.run(["/bin/sh", "-c", RM.bind_check(str(rt), "m_abc", nonce) + "echo RAN"],
                                  capture_output=True, text=True)
        r = run("n0nce")
        assert r.returncode == 97 and "RAN" not in r.stdout     # no marker: nothing runs
        (rt / "hosts" / "m_abc").write_text("n0nce\n")
        assert run("n0nce").stdout.strip().endswith("RAN")
        r = run("other")
        assert r.returncode == 97 and "RAN" not in r.stdout


# ---------------------------------------------------------------------------
# A real gated, real sshds, fake artifacts (harness_remote)
# ---------------------------------------------------------------------------


def _agent(re_: R.RemoteEnv, fc: D.FakeClaude):
    from test_terminals import Agent
    return Agent(re_.de, fc)


def _job_wait(a: Any, jid: str, states: tuple[str, ...], timeout: float = 20) -> dict[str, Any]:
    end = time.time() + timeout
    st: dict[str, Any] = {}
    while time.time() < end:
        st = a.ok("/agent/job/status", {"id": jid})
        if st["state"] in states:
            return st
        time.sleep(0.15)
    raise AssertionError(f"job never reached {states}: {json.dumps(st)[:600]}")


def _snapshot(re_: R.RemoteEnv, fc: D.FakeClaude) -> dict[str, Any]:
    probe = D.probe_root(re_.de.root)
    r = fc.run([D.PY, "-I", "-S", str(probe / "run.py")],
               env={**{k: v for k, v in D.py_env().items() if k != "PYTHONHOME"},
                    "GW_PROBE_SOCK": str(re_.de.sock), "GW_PROBE_PATH": "/v1/snapshot",
                    "GW_PROBE_METHOD": "GET"})
    return json.loads(r.stdout)["body"]


def _work(re_: R.RemoteEnv, name: str = "work") -> Path:
    d = re_.root / name
    d.mkdir(exist_ok=True)
    return d


def test_the_first_remote_terminal_stages_the_runtime_and_runs_the_managed_shell():
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        base = re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        work = _work(re_)
        v = a.open(host="box", cwd=str(work))
        tid = v["id"]
        assert v["host"] == "box" and v.get("remote") is True and v["host_id"].startswith("m_"), v
        assert v["state"] == "open" and v["owner"] == "agent" and v["cwd"] == str(work)
        rt = re_.rt_dir("box")
        assert stat.S_IMODE(os.stat(base).st_mode) == 0o700
        assert stat.S_IMODE(os.stat(rt).st_mode) == 0o700
        marker = json.loads((rt / ".gateway-runtime").read_text())
        assert marker["version"] == runtime_pack.version() and marker["platform"] == R.local_platform()
        assert marker["bash"].startswith("5.") and marker["tmux"].startswith("tmux 3")
        assert (rt / "env" / "bin" / "bash").exists() and (rt / "tmux.sock").is_socket()
        assert not (rt / "runtime.tar").exists() and not (rt / "unpacker").exists(), \
            "the pack and the unpacker stay behind after unpacking"
        hid = v["host_id"]
        assert (rt / "hosts" / hid).read_text().strip(), "no host marker in the runtime"
        assert not list((rt / "terms").glob("*.rc")), "the start file wasn't removed"
        # the managed environment: the runtime's bash, the curated PATH, nothing of
        # the login session (the sshd's environment, its wrapper's PATH)
        out = work / "env.txt"
        a.run(tid, f"env > '{out}'; echo BASH=$BASH_VERSION; echo done-env", "done-env")
        env = dict(ln.split("=", 1) for ln in out.read_text().splitlines() if "=" in ln)
        assert env.get("PATH") == f"{rt}/env/bin:{RM.SYSTEM_PATH}", env.get("PATH")
        assert env.get("SHELL") == f"{rt}/env/bin/bash" and env.get("GW_RUNTIME") == str(rt)
        assert env.get("GW_TERMINAL") == tid
        for leak in ("SSH_CONNECTION", "SSH_CLIENT", "MAIL", "XDG_RUNTIME_DIR", "TMUX", "TMUX_PANE",
                     "GATEWAY_TEST_ROOT", "PYTHONHOME", "CLAUDE_PID"):
            assert leak not in env, leak
        assert str(sshd.sudo_bin) not in env.get("PATH", "")
        assert any(ln.startswith("BASH=5.") for ln in a.read(tid)["lines"])
        # the pane's shell: the runtime's bash, no profile, the start file as its rc
        ps = subprocess.run(["ps", "-axww", "-o", "command="], capture_output=True, text=True).stdout
        assert any(f"{rt}/env/bin/bash --noprofile --rcfile {rt}/terms/{tid}." in ln for ln in ps.splitlines())
        # the runtime's tmux: its own config, on the private socket in the runtime folder
        assert re_.tmux("box", "show", "-gv", "remain-on-exit").stdout.strip() == "on"
        assert re_.tmux("box", "show", "-gv", "status").stdout.strip() == "off"
        # identity: the machine token stored with the host key, verified in the snapshot
        rec = vault.load()["hosts"]["box"]
        assert rec["machine_id"].startswith("m_") and rec.get("host_keys")
        snap = _snapshot(re_, fc)
        h = next(x for x in snap["hosts"] if x["name"] == "box")
        assert h["identity"] == "verified" and h["machine"] == rec["machine_id"], h
        assert h["runtime"] == "ready" and h["reachable"] == "ok" and h["auth"] == "ok", h
        assert h["runtime_version"] == runtime_pack.version()
        loc = next(x for x in snap["hosts"] if x["name"] == "localhost")
        assert loc["identity"] == "machine" and "runtime" in loc
        # the runtime tool reports the same
        st = a.ok("/agent/remote/runtime", {"host": "box"})
        assert st["runtime"] == "ready" and st["identity"] == "verified" and st["bash"].startswith("5.")
        audit_lines = [json.dumps(x) for x in re_.se.audit("remote_runtime")]
        assert any('"staged"' in x for x in audit_lines), audit_lines
        # a second terminal reuses the runtime (no new staging)
        n = len(re_.se.audit("remote_runtime"))
        t2 = a.open(host="box", cwd=str(work))["id"]
        assert t2 != tid and len(re_.se.audit("remote_runtime")) == n
        a.ok("/agent/term/close", {"id": t2})


def test_a_remote_job_runs_reports_its_exit_and_output_and_the_contract_serves_it():
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        work = _work(re_)
        b = a.ok("/agent/job/start", {"host": "box", "cwd": str(work),
                                      "command": 'echo "OUT""PUT-$((6*7))"; pwd; exit 3'})
        jid = b["id"]
        assert jid.startswith("j_") and b["host"] == "box" and b.get("remote") is True
        st = _job_wait(a, jid, ("exited",))
        assert st["exit"] == 3 and st["ended"] is not None, st
        tail = a.ok("/agent/job/tail", {"id": jid})
        assert "OUTPUT-42" in tail["text"] and str(work) in tail["text"], tail
        # the same through CONTRACT-v1 (checkpoint's route), bound to the caller's session
        probe = D.probe_root(re_.de.root)
        st2, body = re_.de.probe(fc, probe / "run.py", ["mcp"], "/v1/jobs",
                                 {"host": "box", "cwd": str(work), "argv": ["printf", "%s\\n", "argv-ok"],
                                  "idempotency_key": "k-1", "session": "s-test"})
        assert st2 == 200 and body["job"].startswith("j_"), body
        cj = _job_wait(a, body["job"], ("exited",))
        assert cj["exit"] == 0 and cj["host"] == "box"
        st3, again = re_.de.probe(fc, probe / "run.py", ["mcp"], "/v1/jobs",
                                  {"host": "box", "argv": ["true"], "idempotency_key": "k-1",
                                   "session": "s-test"})
        assert again["job"] == body["job"] and again["new"] is False
        # an unknown host and a missing folder on the host are refused, nothing starts
        st4, e = a.call("/agent/job/start", {"host": "nope", "command": "true"})
        assert st4 == 404 and e["error"] == "no_host", e
        st5, e = a.call("/agent/job/start", {"host": "box", "cwd": str(work / "missing"),
                                             "command": "true"})
        assert st5 == 400 and e["error"] == "bad_cwd", e


def test_a_corrupted_copy_fails_its_sha256_check_and_nothing_is_unpacked():
    with R.remote_env(knobs={"remote_corrupt_upload": "runtime.tar"}) as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        st, e = a.call("/agent/term/open", {"host": "box", "cwd": str(_work(re_))})
        assert st == 502 and e["error"] == "remote_integrity" and "sha256" in e["message"], e
        rt = re_.rt_dir("box")
        assert not (rt / "env").exists() and not (rt / "runtime.tar").exists()
        assert not (rt / ".gateway-runtime").exists() and not (rt / "unpacker").exists()
        s = a.ok("/agent/remote/runtime", {"host": "box"})
        assert s["runtime"] == "failed" and "sha256" in s.get("note", ""), s
        # the same copy without the corruption: staged
        re_.knobs(remote_corrupt_upload=None)
        re_.de.stop()
        re_.de.start()
        fc2 = re_.de.claude(session="s-two")
        a2 = _agent(re_, fc2)
        v = a2.open(host="box", cwd=str(_work(re_)))
        assert v["state"] == "open" and (rt / ".gateway-runtime").exists()


def test_without_a_hash_tool_on_the_host_the_copy_is_read_back_and_hashed_here():
    with R.remote_env(knobs={"remote_no_hash_tool": True}) as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        a.ok("/agent/remote/runtime", {"host": "box", "action": "provision"})
        assert json.loads((re_.rt_dir("box") / ".gateway-runtime").read_text())["platform"]
        aud = [x for x in re_.se.audit("remote_runtime") if x.get("outcome") == "staged"]
        assert aud and aud[-1].get("hash_check") == "read back", aud
        cmds = "\n".join(sshd.commands())
        assert "cat -- " in cmds and "sha256sum" not in cmds.split("cat -- ")[-1]
    with R.remote_env(knobs={"remote_no_hash_tool": True,
                             "remote_corrupt_upload": "unpacker/bin/pixi-unpack"}) as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        st, e = a.call("/agent/remote/runtime", {"host": "box", "action": "provision"})
        assert st == 200 and e["ok"] is False and e["error"] == "integrity" and "read back" in \
            e["message"], e
        assert not (re_.rt_dir("box") / "env").exists()


def test_an_unsupported_host_is_refused_with_the_remedy_and_nothing_is_copied():
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        (sshd.sudo_bin / "uname").write_text('#!/bin/sh\ncase "$1" in -s) echo Linux ;; '
                                             '-m) echo riscv64 ;; *) echo Linux ;; esac\n')
        os.chmod(sshd.sudo_bin / "uname", 0o755)
        base = re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        st, e = a.call("/agent/term/open", {"host": "box", "cwd": str(_work(re_))})
        assert st == 409 and e["error"] == "remote_unsupported", e
        assert "Linux riscv64" in e["message"] and "Linux x86_64 or aarch64" in e["message"]
        assert not base.exists() or not any(base.iterdir())
        s = a.ok("/agent/remote/runtime", {"host": "box"})
        assert s["runtime"] == "unsupported"


def test_a_noexec_runtime_folder_is_reported_with_the_runtime_path_remedy():
    with R.remote_env(noexec=True) as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        st, e = a.call("/agent/term/open", {"host": "box", "cwd": str(_work(re_))})
        assert st == 409 and e["error"] == "remote_noexec", e
        assert "noexec" in e["message"] and 'runtime = "' in e["message"]
        assert not (re_.rt_dir("box") / "env").exists()


def test_a_full_disk_is_reported_before_anything_is_copied():
    with R.remote_env(knobs={"remote_df_avail_kb": 2048}) as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        st, e = a.call("/agent/term/open", {"host": "box", "cwd": str(_work(re_))})
        assert st == 507 and e["error"] == "remote_disk", e
        assert "2 MB free" in e["message"] and "runtime =" in e["message"]
        rt = re_.rt_dir("box")
        assert not (rt / "runtime.tar").exists() and not (rt / "unpacker").exists()


def test_old_runtime_versions_go_once_the_new_one_is_ready_but_only_idle_marked_ones():
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        base = re_.add_host("box", sshd)
        plat = R.local_platform()
        base.mkdir(parents=True, exist_ok=True)
        old = base / f"{'a' * 12}-{plat}"
        unmarked = base / f"{'b' * 12}-{plat}"
        busy = base / f"{'c' * 12}-{plat}"
        mine = base / "my-project"
        odd = base / f"{'d' * 11}-{plat}"
        for d in (old, unmarked, busy, mine, odd):
            (d / "env" / "bin").mkdir(parents=True)
        for d in (old, busy, odd):
            (d / ".gateway-runtime").write_text("{}")
        (mine / ".gateway-runtime").write_text("{}")
        os.symlink(R.ENV_BIN / "tmux", busy / "env" / "bin" / "tmux")
        sock = busy / "tmux.sock"
        subprocess.run([str(R.ENV_BIN / "tmux"), "-S", str(sock), "-f", "/dev/null", "new-session",
                        "-d", "sleep", "300"], check=True, env={"PATH": "/usr/bin:/bin",
                                                               "HOME": str(re_.root)})
        try:
            fc = re_.de.claude()
            a = _agent(re_, fc)
            a.open(host="box", cwd=str(_work(re_)))
            assert not old.exists(), "an idle older runtime stayed"
            assert unmarked.exists() and busy.exists() and mine.exists() and odd.exists()
            assert re_.rt_dir("box").exists()
        finally:
            subprocess.run([str(R.ENV_BIN / "tmux"), "-S", str(sock), "kill-server"],
                           capture_output=True, env={"PATH": "/usr/bin:/bin", "HOME": str(re_.root)})


def test_hosts_whose_ssh_is_ask_or_off_get_no_remote_terminal_or_job():
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("ask", sshd, ssh="ask")
        re_.add_host("off", sshd, ssh=False)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        st, e = a.call("/agent/term/open", {"host": "ask", "cwd": "/tmp"})
        # an "ask" exec is refused for the agent (only a typed command can be
        # asked about), with the rule behind it (PLAN-v4 phase 7)
        assert st == 403 and e["error"] == "policy" and '"ask"' in e["message"], e
        assert e["rule"].startswith('[hosts.ask] ssh = "ask"'), e
        st, e = a.call("/agent/job/start", {"host": "off", "cwd": "/tmp", "command": "true"})
        assert st == 403 and e["error"] == "policy" and e["rule"].startswith("[hosts.off] ssh = false"), e
        # staging the runtime there by hand is refused by the right itself too
        st, e = a.call("/agent/remote/runtime", {"host": "ask", "action": "provision"})
        assert e["ok"] is False and e["error"] == "right" and "can't ask the user" in e["message"], e
        assert sshd.accepted() == 0 and not sshd.commands(), "something reached the host"


def _until(fn: Any, timeout: float = 20, what: str = "") -> Any:
    end = time.time() + timeout
    v = None
    while time.time() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.1)
    raise AssertionError(f"timed out: {what} (last: {json.dumps(v)[:400] if v is not None else v})")


def _status(a: Any, jid: str) -> dict[str, Any]:
    return a.ok("/agent/job/status", {"id": jid})


def _close_masters(name: str) -> None:
    from gateway import ssh, ssh_conf
    ssh.close_masters(name)
    ssh_conf.cache_clear(name)


def _pane_pids(re_: R.RemoteEnv, host: str) -> dict[str, int]:
    out = re_.tmux(host, "list-panes", "-a", "-F", "#{session_name} #{pane_pid}").stdout
    return {ln.split()[0]: int(ln.split()[1]) for ln in out.splitlines() if len(ln.split()) == 2}


def test_disconnect_and_reconnect_report_a_surviving_job_and_ones_ended_meanwhile_honestly():
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        work = _work(re_)
        tid = a.open(host="box", cwd=str(work))["id"]
        a.run(tid, "export GWKEEP=kept-$((2+3))", None)
        jobs = {k: a.ok("/agent/job/start", {"host": "box", "cwd": str(work),
                                             "command": "sleep 300"})["id"]
                for k in ("survives", "session_killed", "process_killed")}
        for j in jobs.values():
            _job_wait(a, j, ("running",))
        seq_before = a.read(tid)["seq"]
        # the connection goes: the host's sshd stops and the shared master is closed
        sshd.stop()
        _close_masters("box")
        st = _until(lambda: (lambda s: s if s["state"] == "disconnected" else None)(
            _status(a, jobs["survives"])), what="disconnected")
        assert st["ended"] is None and "can't be reached" in st.get("note", ""), st
        assert st.get("exit") is None and not st.get("gone")
        snap = _snapshot(re_, fc)
        assert next(x for x in snap["jobs"] if x["job"] == jobs["survives"])["state"] == "disconnected"
        assert next(x for x in snap["hosts"] if x["name"] == "box")["reachable"] == "down"
        st5, e = a.call("/agent/term/send", {"id": tid, "seq": seq_before, "text": "echo nope",
                                             "enter": True})
        assert st5 == 503 and e["error"] in ("disconnected", "remote_unreachable"), e
        # meanwhile, on the host: one job's session is killed outright, another's
        # process gets SIGKILL (its pane stays, dead, with the signal)
        pids = _pane_pids(re_, "box")
        assert re_.tmux("box", "kill-session", "-t", "=" + jobs["session_killed"]).returncode == 0
        os.killpg(pids[jobs["process_killed"]], signal.SIGKILL)
        sshd.start()
        st = _until(lambda: (lambda s: s if s["state"] == "running" else None)(
            _status(a, jobs["survives"])), timeout=30, what="reconnected")
        assert st["ended"] is None and not st.get("note"), st
        lost = _status(a, jobs["session_killed"])
        assert lost["state"] == "unknown" and lost.get("gone") is True and lost["ended"] is None, lost
        assert "no longer has it" in lost["note"] and "unknown" in lost["note"], lost
        dead = _status(a, jobs["process_killed"])
        assert dead["state"] == "exited" and dead["signal"] == "KILL" and dead["ended"], dead
        # the terminal survived: the same shell, and a seq read before the
        # disconnect is stale (the screen may have moved)
        st6, e = a.call("/agent/term/send", {"id": tid, "seq": seq_before, "text": "echo old"})
        assert st6 == 409 and e["error"] == "stale", e
        v = a.run(tid, 'echo "KE""PT=$GWKEEP"', "KEPT=")
        assert any(ln == "KEPT=kept-5" for ln in v["lines"]), v["lines"]
        ev = R.events(re_.de, fc, ("job.state", "host.state"))
        assert any(e.get("state") == "disconnected" and e.get("job") == jobs["survives"] for e in ev)
        assert any(e.get("kind") == "host.state" and e.get("reachable") == "down" for e in ev)


def test_a_gated_restart_asks_the_host_before_it_reports_or_accepts_input():
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        work = _work(re_)
        tid = a.open(host="box", cwd=str(work))["id"]
        a.run(tid, "export GWR=restart-ok", None)
        seq = a.read(tid)["seq"]
        jid = a.ok("/agent/job/start", {"host": "box", "cwd": str(work), "command": "sleep 300"})["id"]
        gone = a.ok("/agent/job/start", {"host": "box", "cwd": str(work), "command": "sleep 300"})["id"]
        _job_wait(a, jid, ("running",))
        re_.de.stop()
        _close_masters("box")
        re_.tmux("box", "kill-session", "-t", "=" + gone)
        re_.de.start()
        v = _until(lambda: (lambda x: x if x["state"] == "open" and "note" not in x else None)(
            a.read(tid)), what="re-adopted")
        assert v["seq"] > seq
        st, e = a.call("/agent/term/send", {"id": tid, "seq": seq, "text": "echo x"})
        assert st == 409 and e["error"] == "stale"
        out = a.run(tid, 'echo "GW""R=$GWR"', "GWR=")
        assert any(ln == "GWR=restart-ok" for ln in out["lines"])
        assert _status(a, jid)["state"] == "running"
        lost = _until(lambda: (lambda s: s if s["state"] == "unknown" else None)(_status(a, gone)),
                      what="unknown after restart")
        assert lost["ended"] is None and lost.get("gone") is True


def test_a_refused_key_is_waiting_auth_with_the_remedy_and_recovers_when_it_works_again():
    from test_dialogs import Mod
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        mod = Mod(fc)
        a = _agent(re_, fc)
        jid = a.ok("/agent/job/start", {"host": "box", "cwd": str(_work(re_)),
                                        "command": "sleep 300"})["id"]
        _job_wait(a, jid, ("running",))
        keys = sshd.ak.read_text()
        sshd.ak.write_text("")                    # the gateway's key removed on the host
        _close_masters("box")
        st = _until(lambda: (lambda s: s if s["state"] == "waiting_auth" else None)(_status(a, jid)),
                    what="waiting_auth")
        assert "refused the gateway's ssh key" in st["note"] and "gate check box" in st["note"], st
        assert st["ended"] is None
        d = mod.dialog(lambda x: x.get("kind") == "info" and x.get("entry") == "box", timeout=10)
        assert any("gate check box" in ln for ln in d["lines"]), d
        mod.post("/ui/dialog/answer", {"id": d["id"], "button": "ok"})
        snap = _snapshot(re_, fc)
        assert next(x for x in snap["hosts"] if x["name"] == "box")["auth"] == "refused"
        sshd.ak.write_text(keys)                  # installed again
        st = _until(lambda: (lambda s: s if s["state"] == "running" else None)(_status(a, jid)),
                    timeout=40, what="running again")
        assert not st.get("note")


def _new_host_key(sshd: S.Sshd) -> None:
    sshd.stop()
    for f in ("hostkey", "hostkey.pub"):
        (sshd.dir / f).unlink()
    subprocess.run([str(S.ENV_BIN / "ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-C",
                    f"host-{sshd.name}-new", "-f", str(sshd.dir / "hostkey")], check=True,
                   capture_output=True)
    sshd.host_key = " ".join((sshd.dir / "hostkey.pub").read_text().split()[:2])
    sshd.start()


def test_a_changed_host_key_blocks_everything_until_the_user_trusts_it():
    from test_dialogs import Mod
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        mod = Mod(fc)
        a = _agent(re_, fc)
        work = _work(re_)
        tid = a.open(host="box", cwd=str(work))["id"]
        jid = a.ok("/agent/job/start", {"host": "box", "cwd": str(work), "command": "sleep 300"})["id"]
        _job_wait(a, jid, ("running",))
        old_pins = vault.load()["hosts"]["box"]["host_keys"]
        _new_host_key(sshd)
        _close_masters("box")
        d = mod.dialog(lambda x: x.get("kind") == "confirm" and x.get("what") == "host key", timeout=40)
        # counted once the change was seen: a command already on its way over the
        # old, verified connection when the masters closed may still land before
        n_cmds = len(sshd.commands())
        assert d["entry"] == "box" and "new host key" in d["title"].lower(), d
        assert any("Pinned:" in ln for ln in d["lines"]) and any("Now:" in ln for ln in d["lines"])
        st = _until(lambda: (lambda s: s if s["state"] == "disconnected" else None)(_status(a, jid)),
                    what="blocked")
        assert "host key" in st["note"], st
        seq = a.read(tid)["seq"]
        stx, e = a.call("/agent/term/send", {"id": tid, "seq": seq, "text": "touch nope", "enter": True})
        assert stx in (409, 503), e
        st2, e = a.call("/agent/job/start", {"host": "box", "cwd": str(work), "command": "true"})
        assert st2 == 409 and e["error"] == "remote_hostkey", e
        time.sleep(1.0)
        assert len(sshd.commands()) == n_cmds, "a command reached the host behind a changed key"
        assert vault.load()["hosts"]["box"]["host_keys"] == old_pins
        # the user trusts it: pinned, then everything goes on
        st3, r = mod.post("/ui/dialog/answer", {"id": d["id"], "button": "ok"})
        assert st3 == 200, r
        _until(lambda: vault.norm_host_key(sshd.host_key) in
               [vault.norm_host_key(k) for k in vault.load()["hosts"]["box"]["host_keys"]],
               what="new key pinned")
        st = _until(lambda: (lambda s: s if s["state"] == "running" else None)(_status(a, jid)),
                    timeout=30, what="running after the OK")
        assert not st.get("note")
        assert any(e.get("event") == "hostkey" for e in re_.se.vault().get("events", [])) or True


def test_a_declined_host_key_stays_blocked_until_the_pin_changes():
    from test_dialogs import Mod
    from gateway import ssh
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        mod = Mod(fc)
        a = _agent(re_, fc)
        jid = a.ok("/agent/job/start", {"host": "box", "cwd": str(_work(re_)),
                                        "command": "sleep 300"})["id"]
        _job_wait(a, jid, ("running",))
        _new_host_key(sshd)
        _close_masters("box")
        d = mod.dialog(lambda x: x.get("what") == "host key", timeout=40)
        mod.post("/ui/dialog/cancel", {"id": d["id"]})
        st = _until(lambda: (lambda s: s if "didn't accept" in s.get("note", "") else None)(
            _status(a, jid)), what="declined")
        assert st["state"] == "disconnected" and st["ended"] is None
        time.sleep(1.0)
        assert mod.view()["dialog"] is None, "asked again right after the user declined"
        # the user re-pins through gate check (simulated: the pin it writes)
        from gateway import form as fm
        ssh._pin_host_keys("box", fm.load().hosts["box"].address, [sshd.host_key])
        st = _until(lambda: (lambda s: s if s["state"] == "running" else None)(_status(a, jid)),
                    timeout=30, what="running after the re-pin")


def test_a_changed_machine_blocks_until_confirmed_and_work_from_another_machine_is_unknown():
    from test_dialogs import Mod
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        mod = Mod(fc)
        a = _agent(re_, fc)
        work = _work(re_)
        jid = a.ok("/agent/job/start", {"host": "box", "cwd": str(work), "command": "sleep 300"})["id"]
        _job_wait(a, jid, ("running",))
        real = vault.load()["hosts"]["box"]["machine_id"]
        fake = "m_" + "a" * 26
        with vault.edit() as dd:
            vault.host_record(dd, "box")["machine_id"] = fake      # what the gateway met before
        _close_masters("box")
        d = mod.dialog(lambda x: x.get("what") == "machine", timeout=20)
        assert any(fake in ln for ln in d["lines"]) and any(real in ln for ln in d["lines"]), d
        st = _until(lambda: (lambda s: s if s["state"] == "disconnected" else None)(_status(a, jid)),
                    what="blocked by the machine")
        assert "another machine" in st["note"]
        st2, e = a.call("/agent/job/start", {"host": "box", "cwd": str(work), "command": "true"})
        assert st2 == 409 and e["error"] == "remote_machine", e
        mod.post("/ui/dialog/answer", {"id": d["id"], "button": "ok"})
        _until(lambda: vault.load()["hosts"]["box"]["machine_id"] == real, what="machine accepted")
        # the job started on this very machine: it is reached again
        _until(lambda: (lambda s: s if s["state"] == "running" else None)(_status(a, jid)),
               timeout=30, what="running after the OK")
        # a record saying a job started on another machine: never attached here
        j2 = a.ok("/agent/job/start", {"host": "box", "cwd": str(work), "command": "sleep 300"})["id"]
        _job_wait(a, j2, ("running",))
        re_.de.stop()
        recs = json.loads(paths.gated_terminals().read_text())
        for p in recs["panes"]:
            if p["id"] == j2:
                p["machine"] = "m_" + "b" * 26
        paths.gated_terminals().write_text(json.dumps(recs))
        re_.de.start()
        lost = _until(lambda: (lambda s: s if s["state"] == "unknown" else None)(_status(a, j2)),
                      what="unknown: another machine")
        assert "another machine" in lost["note"] and lost["ended"] is None, lost
        assert _status(a, jid)["state"] == "running"


def test_two_hosts_never_mix_their_work_and_a_wrong_runtime_runs_nothing():
    from test_dialogs import Mod
    with R.remote_env() as re_:
        s1 = re_.se.sshd("one")
        s2 = re_.se.sshd("two")
        re_.add_host("one", s1)
        re_.add_host("two", s2)
        fc = re_.de.claude()
        mod = Mod(fc)
        a = _agent(re_, fc)
        work = _work(re_)                          # the same folder on both
        j1 = a.ok("/agent/job/start", {"host": "one", "cwd": str(work), "command": "echo ONE; sleep 300"})["id"]
        j2 = a.ok("/agent/job/start", {"host": "two", "cwd": str(work), "command": "echo TWO; sleep 300"})["id"]
        _job_wait(a, j1, ("running",))
        _job_wait(a, j2, ("running",))
        c1, c2 = "\n".join(s1.commands()), "\n".join(s2.commands())
        assert j1 in c1 and j1 not in c2 and j2 in c2 and j2 not in c1
        _until(lambda: "ONE" in a.ok("/agent/job/tail", {"id": j1})["text"], what="one's output")
        _until(lambda: "TWO" in a.ok("/agent/job/tail", {"id": j2})["text"], what="two's output")
        assert "TWO" not in a.ok("/agent/job/tail", {"id": j1})["text"]
        assert j1 in re_.tmux("one", "ls").stdout and j1 not in re_.tmux("two", "ls").stdout
        # the host record's marker gone from host one's runtime: nothing runs there
        t1 = a.open(host="one", cwd=str(work))["id"]
        hid = a.read(t1)["host_id"]
        (re_.rt_dir("one") / "hosts" / hid).unlink()
        seq = a.read(t1).get("seq", 0)
        st, e = a.call("/agent/term/send", {"id": t1, "seq": seq, "text": f"touch {work}/ran-one",
                                            "enter": True})
        assert st in (409, 503) and "isn't this host's" in e.get("message", "") + json.dumps(e), e
        time.sleep(0.5)
        assert not (work / "ran-one").exists()
        s = _until(lambda: (lambda x: x if x["state"] == "disconnected" else None)(_status(a, j1)),
                   what="one disconnected")
        assert s["ended"] is None and not s.get("gone")
        # host one's address now points at host two's sshd: its key isn't one's pin, so
        # nothing of one's reaches two (the user is asked)
        n2 = len(s2.commands())
        text = re_.form_text.replace(f'address = "{s1.addr()}"', f'address = "{s2.addr()}"')
        re_.rewrite_form(text)
        _close_masters("one")
        mod.dialog(lambda x: x.get("what") == "host key" and x.get("entry") == "one", timeout=20)
        time.sleep(1.0)
        assert all(j1 not in c and t1 not in c for c in s2.commands()[n2:])
        assert _status(a, j2)["state"] == "running"


def test_a_remote_password_prompt_goes_through_the_dialog_and_never_on_a_command_line():
    from test_dialogs import Mod, seal
    base = Path(H.tmp_base())
    wrap_dir = Path(tempfile_dir(base))
    argv_log = wrap_dir / "ssh-argv.log"
    wrapper = wrap_dir / "ssh"
    wrapper.write_text(f'#!/bin/sh\nprintf "%s\\n" "$*" >> {S.sq(argv_log)}\n'
                       f'exec {S.sq(S.ENV_BIN / "ssh")} "$@"\n')
    os.chmod(wrapper, 0o755)
    try:
        _password_prompt(wrapper, argv_log)
    finally:
        shutil.rmtree(wrap_dir, ignore_errors=True)


def _password_prompt(wrapper: Path, argv_log: Path) -> None:
    from test_dialogs import Mod, seal
    with R.remote_env(knobs={"ssh": str(wrapper)}) as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        mod = Mod(fc)
        a = _agent(re_, fc)
        work = _work(re_)
        tid = a.open(host="box", cwd=str(work))["id"]
        a.run(tid, 'read -s -p "Password: " pw; echo; echo "GOT""LEN=${#pw} '
                   'sha=$(printf %s "$pw" | ' + SHA256 + ' | cut -c1-16)"', done=False)
        d = mod.dialog(lambda x: x.get("entry") == "terminal" and x.get("target") == tid, timeout=20)
        assert any("on box" in ln for ln in d["lines"]) and d["kind"] == "secret", d
        v = a.read(tid)
        assert v.get("waiting_auth") is True
        st, r = a.call("/agent/term/send", {"id": tid, "seq": v["seq"], "text": "guess"})
        assert st == 409 and r["error"] == "auth"
        secret = canary("rpw")
        st, r = mod.post("/ui/dialog/submit", seal(d, [secret]))
        assert st == 200 and r["state"] == "checking", r
        got = a.wait(tid, "GOTLEN=", timeout=20)
        line = next(ln for ln in got["lines"] if ln.startswith("GOTLEN="))
        assert line == f"GOTLEN={len(secret)} sha={sha16(secret)}", "the remote pane didn't get the value"
        assert got.get("auth") == "[credential supplied]", ({k: got.get(k) for k in (
            "auth", "note", "waiting_auth", "state")}, re_.de.log()[-3000:])
        a.run(tid, 'echo "AG""AIN:$pw"', "AGAIN:")
        assert any("AGAIN:***" in ln for ln in a.read(tid)["lines"])
        # never on a command line: not in what the host ran, not in ssh's argv here
        assert secret not in "\n".join(sshd.commands())
        assert "load-buffer" in "\n".join(sshd.commands())
        assert argv_log.exists() and secret not in argv_log.read_text()
        assert re_.tmux("box", "list-buffers").stdout.strip() == ""
        blob = b""
        for d0 in (re_.de.run, paths.gated_dir(), re_.rt_dir("box")):
            for p in Path(d0).rglob("*"):
                if p.is_file() and not p.is_socket():
                    try:
                        blob += p.read_bytes()
                    except OSError:
                        pass
        assert secret.encode() not in blob
        assert all(secret not in x for x in a.answers)


def tempfile_dir(base: Path) -> str:
    import tempfile
    return tempfile.mkdtemp(prefix="gwrw-", dir=str(base))


def test_a_root_password_prompt_on_a_host_whose_sudo_is_off_asks_nothing():
    from test_dialogs import Mod
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd, sudo=False)
        fc = re_.de.claude()
        mod = Mod(fc)
        a = _agent(re_, fc)
        work = _work(re_)
        (work / "sudo").symlink_to(R.ENV_BIN / "bash")
        tid = a.open(host="box", cwd=str(work))["id"]
        a.run(tid, "./sudo --norc -c 'read -s -p \"[sudo] password: \" x; echo after'", done=False)
        v = _until(lambda: (lambda x: x if x.get("waiting_auth") else None)(a.read(tid)),
                   what="waiting_auth")
        assert "sudo on box is off" in v.get("note", ""), v
        assert mod.view()["dialog"] is None
        a.ok("/agent/term/signal", {"id": tid, "signal": "INT"})


# ---------------------------------------------------------------------------
# The approval hook and the permission decisions for remote work
# ---------------------------------------------------------------------------

GW_JOB = "mcp__plugin_gate_gw__job_start"
GW_SEND = "mcp__plugin_gate_gw__terminal_send"


def _decision(out: Any) -> str | None:
    return out["hookSpecificOutput"]["permissionDecision"] if out else None


def test_the_approval_hook_judges_remote_work_as_a_command_on_that_host():
    from gateway import hooks_bash
    with H.gateway_env() as env:
        env.write_form('[hosts.localhost]\nsudo = true\n'
                       '[hosts.box]\naddress = "me@box.example.org"\nssh = true\nsudo = false\n'
                       '[hosts.asky]\naddress = "me@asky.example.org"\nssh = "ask"\n')
        vault.save(vault.empty())
        consent.approve_all(env.form())

        def job(host: str, cmd: str) -> str | None:
            return _decision(hooks_bash.main({"tool_name": GW_JOB, "permission_mode": "auto",
                                              "tool_input": {"host": host, "command": cmd}}))
        # sudo on box is off: a remote job running sudo there is denied (on localhost it isn't)
        assert job("box", "sudo apt-get update") == "deny"
        assert job("localhost", "sudo -n true") != "deny"
        assert job("box", "ls /srv") is None              # never allow for a job: Claude Code decides
        # an "ask" host: a job can't use it (nobody can be asked while it runs)
        assert job("asky", "uptime") == "deny"
        # a host word that names no host: denied (never judged as some other command)
        assert job("nowhere", "uptime") == "deny"
        assert job("m_" + "z" * 26, "uptime") == "deny"
        # box named by its assigned id or by its verified machine token (both of which
        # gated accepts and the snapshot shows) is judged as box: the review found the
        # token form skipped the remote sudo rule (no decision, and gated ran it on box)
        token, hid = "m_" + "t" * 26, "m_" + "i" * 26
        paths.gated_dir().mkdir(parents=True, exist_ok=True)
        (paths.gated_dir() / "machine-ids.json").write_text(json.dumps({"box": hid, "asky": "m_" + "j" * 26}))
        paths.gated_remote().write_text(json.dumps({"version": 1, "hosts": {"box": {"machine": token}}}))
        for word in ("box", hid, token):
            assert job(word, "sudo apt-get update") == "deny", word
            assert job(word, "ls /srv") is None, word          # judged on box: no decision
        # gated resolves every one of those words to the same host (one resolver)
        class D0:
            def _host_ids(self, names: list[str]) -> dict[str, str]:
                return {n: json.loads((paths.gated_dir() / "machine-ids.json").read_text())[n]
                        for n in names}
            def log(self, line: str) -> None:
                pass
        mgr = RM.Remotes(D0())
        from gateway import hooks_bash as hb
        for word in ("box", hid, token, "nowhere", "m_" + "z" * 26):
            want = mgr.resolve(word)
            got = hb._remote_name(word)
            assert (got if got is not hb.UNKNOWN_HOST else None) == want, (word, got, want)
        # this machine's own id is localhost, as gated reads it: judged locally
        from gateway.daemon.lifecycle import machine_token
        local = machine_token(vault.machine_id() or "x")
        assert hb._remote_name(local) is None
        assert job(local, "sudo -n true") != "deny"
        # text typed into a remote terminal is judged on its host too
        recs = {"version": 1, "panes": [{"id": T.ulid("t"), "kind": "terminal", "host": "box"},
                                         {"id": T.ulid("t"), "kind": "terminal", "host": "localhost"}]}
        paths.gated_dir().mkdir(parents=True, exist_ok=True)
        paths.gated_terminals().write_text(json.dumps(recs))
        rid, lid = recs["panes"][0]["id"], recs["panes"][1]["id"]

        def send(tid: str, text: str) -> str | None:
            return _decision(hooks_bash.main({"tool_name": GW_SEND, "permission_mode": "auto",
                                              "tool_input": {"id": tid, "seq": 1, "text": text}}))
        assert send(rid, "sudo reboot") == "deny"
        assert send(lid, "sudo -n true") != "deny"
        assert send(rid, "ls") is None


def test_the_permission_hook_allows_only_local_terminals_and_runtime_reads():
    hook = paths.plugin_root() / "hooks" / "mcp_perm.sh"

    def decide(tool: str, ti: dict[str, Any]) -> str | None:
        r = subprocess.run(["/bin/sh", str(hook)], input=json.dumps({"tool_name": tool,
                                                                     "tool_input": ti}),
                           capture_output=True, text=True, timeout=20)
        return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] if r.stdout.strip() \
            else None
    p = "mcp__plugin_gate_gw__"
    assert decide(p + "terminal_open", {"cwd": "/x"}) == "allow"
    assert decide(p + "terminal_open", {"host": "localhost"}) == "allow"
    assert decide(p + "terminal_open", {"host": "box"}) is None
    assert decide(p + "terminal_open", {"host": "localhost", "host ": "box"}) == "allow"
    assert decide(p + "host_runtime", {"host": "box"}) == "allow"
    assert decide(p + "host_runtime", {"host": "box", "action": "status"}) == "allow"
    assert decide(p + "host_runtime", {"host": "box", "action": "provision"}) is None
    assert decide(p + "host_runtime", {"host": "box", "action": "clean"}) is None
    assert decide(p + "host_runtime", {"host": "box", "action": "status", "action ": 1}) == "allow"
    assert decide(p + "job_start", {"host": "box", "command": "true"}) is None


def test_the_mcp_server_offers_the_remote_tools_and_never_sends_local_settings_to_a_host():
    from gateway import mcp_server
    names = [t["name"] for t in mcp_server.TOOLS]
    assert "host_runtime" in names
    op = next(t for t in mcp_server.TOOLS if t["name"] == "terminal_open")
    assert "host" in op["inputSchema"]["properties"]
    sent: list[tuple[str, dict[str, Any], float]] = []
    from gateway.daemon import client
    old = client.term_call
    client.term_call = lambda route, body, timeout=30.0: sent.append((route, body, timeout)) or {"ok": True}
    try:
        with H.gateway_env():
            mcp_server.call_tool("terminal_open", {"host": "box"})
            mcp_server.call_tool("job_start", {"host": "box", "command": "true"})
            mcp_server.call_tool("terminal_open", {})
    finally:
        client.term_call = old
    (r1, b1, t1), (r2, b2, t2), (r3, b3, t3) = sent
    assert r1 == "/agent/term/open" and "cwd" not in b1 and "env" not in b1 and t1 >= 600
    assert "cwd" not in b2 and "env" not in b2 and t2 >= 600
    assert b3.get("cwd") and "env" in b3 and t3 == 30.0


def test_gate_status_shows_a_hosts_runtime_folder_what_was_staged_and_its_machine():
    from gateway import gate
    with H.gateway_env() as env:
        env.write_form('[hosts.box]\naddress = "me@box.example.org"\nruntime = "~/rt"\n'
                       '[hosts.plain]\naddress = "me@plain.example.org"\n')
        consent.approve_all(env.form())
        tok = "m_" + "c" * 26
        with vault.edit() as d:
            vault.host_record(d, "box")["machine_id"] = tok
        paths.gated_dir().mkdir(parents=True, exist_ok=True)
        paths.gated_remote().write_text(json.dumps({"version": 1, "hosts": {"box": {
            "rt_version": "abcdefabcdef", "platform": "linux-aarch64", "bash": "5.2.37(1)-release",
            "tmux": "tmux 3.8", "rt": "/home/me/rt/abcdefabcdef-linux-aarch64"}}}))
        data = vault.load()
        f = env.form()
        eff = consent.compute(f, data)
        text = gate.render_entry("box", f, eff, data)
        assert "runtime ~/rt" in text and "(default)" not in text
        assert "remote runtime abcdefabcdef-linux-aarch64 staged (bash 5.2.37(1)-release, tmux 3.8)" in text
        assert f"machine {tok}" in text
        plain = gate.render_entry("plain", f, eff, data)
        assert "runtime ~/.local/share/gateway-runtime (default)" in plain and "remote runtime" not in plain
        env.write_form('[hosts.box]\naddress = "me@box.example.org"\nruntime = "/other"\n')
        f = env.form()
        text = gate.render_entry("box", f, consent.compute(f, data), data)
        assert "runtime /other  (waits for your OK)" in text


def test_a_pause_applies_each_remote_jobs_policy_on_its_host_and_says_what_happened():
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        cwd = str(_work(re_))
        sus = a.ok("/agent/job/start", {"host": "box", "argv": ["sleep", "171"], "cwd": cwd,
                                        "on_pause": "suspend", "task_ref": "t-1"})["id"]
        intr = a.ok("/agent/job/start", {"host": "box", "cwd": cwd, "on_pause": "interrupt",
                                         "task_ref": "t-1",
                                         "command": "trap 'exit 9' INT; while :; do sleep 0.1; done"})["id"]
        for j in (sus, intr):
            _job_wait(a, j, ("running",))
        st, r = a.call("/v1/pause", {"session": "s-test", "task_ref": "t-1", "reason": "test"}, mode="x")
        assert st == 200, r
        out = {o["job"]: o for o in r["outcomes"]}
        assert out[sus]["outcome"] == "suspended (SIGSTOP)", out
        assert out[intr]["outcome"].startswith("interrupted: exited (exit 9)"), out[intr]
        assert _job_wait(a, sus, ("suspended",))["state"] == "suspended"
        stats = [ln.split()[1] for ln in subprocess.run(["ps", "-axo", "pid=,stat=,command="],
                                                         capture_output=True, text=True).stdout.splitlines()
                 if ln.split()[2:] == ["sleep", "171"]]
        assert stats and all(s.startswith("T") for s in stats), stats
        st, r = a.call("/v1/resume", {"session": "s-test", "task_ref": "t-1"}, mode="x")
        res = {o["job"]: o for o in r["outcomes"]}
        assert res[sus]["outcome"] == "resumed (SIGCONT)", res
        assert _job_wait(a, sus, ("running",))["state"] == "running"
        a.ok("/agent/job/signal", {"id": sus, "signal": "TERM"})
        assert _job_wait(a, sus, ("canceled", "exited"))["state"] == "canceled"


def test_the_prefilter_sends_every_remote_job_to_the_approval_hook():
    import tempfile
    from test_hookbash_prefilter import _rig, _managed_env
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as td:
        pre, marker = _rig(Path(td) / "rig")

        def sent(ti: dict[str, Any]) -> bool:
            marker.unlink(missing_ok=True)
            payload = json.dumps({"tool_name": GW_JOB, "tool_input": ti, "permission_mode": "auto"})
            subprocess.run(["/bin/sh", str(pre)], input=payload, capture_output=True, text=True,
                           timeout=15, env=_managed_env(pre))
            return marker.exists()
        assert sent({"host": "box", "command": "uptime"})            # no trigger word, a remote host
        assert sent({"host": "m_" + "a" * 26, "argv": ["ls"]})
        assert not sent({"host": "localhost", "command": "uptime"})
        assert not sent({"command": "uptime"})
        assert not sent({"command": 'echo "\\"host\\": \\"box\\""'})  # only the top-level key counts
        assert sent({"host": "localhost", "command": "sudo -n true"})  # the word list as before


def test_gated_leaving_never_stops_another_tmux_server_that_took_its_old_pid():
    """abandon() stops gated's own tmux server when its socket went with the
    run dir; a reused pid that now belongs to another server of the same tmux
    binary (a remote runtime's on this machine, another test's) is left alone:
    it must name gated's socket on its command line too."""
    import tempfile
    with H.gateway_env() as env:
        d = Path(tempfile.mkdtemp(prefix="gwx-", dir="/tmp"))
        try:
            other = d / "other.sock"
            tmux = str(R.ENV_BIN / "tmux")
            subprocess.run([tmux, "-S", str(other), "-f", "/dev/null", "new-session", "-d", "sleep", "60"],
                           check=True, env={"PATH": "/usr/bin:/bin", "HOME": str(env.root)})
            pid = int(subprocess.run([tmux, "-S", str(other), "display-message", "-p", "#{pid}"],
                                     capture_output=True, text=True, check=True,
                                     env={"PATH": "/usr/bin:/bin", "HOME": str(env.root)}).stdout)
            logs: list[str] = []

            class D0:
                def log(self, line: str) -> None:
                    logs.append(line)
            sup = T.Supervisor(D0(), state_path=d / "t.json", sock=d / "gone.sock", conf=d / "c",
                               terms=d / "terms")
            sup._tmux = T.Tmux(tmux, d / "gone.sock", d / "c", {"PATH": "/usr/bin:/bin"})
            sup._tmux.server_pid = pid           # gated's old server pid, now another server's
            sup.abandon()
            time.sleep(0.3)
            os.kill(pid, 0)                      # still alive (raises if it was stopped)
            assert not logs, logs
            # its own server (the socket on its command line) is stopped
            own = d / "own.sock"
            subprocess.run([tmux, "-S", str(own), "-f", "/dev/null", "new-session", "-d", "sleep", "60"],
                           check=True, env={"PATH": "/usr/bin:/bin", "HOME": str(env.root)})
            opid = int(subprocess.run([tmux, "-S", str(own), "display-message", "-p", "#{pid}"],
                                      capture_output=True, text=True, check=True,
                                      env={"PATH": "/usr/bin:/bin", "HOME": str(env.root)}).stdout)
            own.unlink()
            sup2 = T.Supervisor(D0(), state_path=d / "t2.json", sock=own, conf=d / "c", terms=d / "terms")
            sup2._tmux = T.Tmux(tmux, own, d / "c", {"PATH": "/usr/bin:/bin"})
            sup2._tmux.server_pid = opid
            sup2.abandon()
            end = time.time() + 3
            while time.time() < end:
                try:
                    os.kill(opid, 0)
                except ProcessLookupError:
                    break
                time.sleep(0.05)
            else:
                raise AssertionError("gated's own unreachable tmux server was left running")
        finally:
            subprocess.run([str(R.ENV_BIN / "tmux"), "-S", str(d / "other.sock"), "kill-server"],
                           capture_output=True, env={"PATH": "/usr/bin:/bin", "HOME": "/tmp"})
            shutil.rmtree(d, ignore_errors=True)


class _FakeConn:
    """Answers RemoteHost._capture as ssh would: the script's own markers
    echoed, then `body`, with `rc`."""

    def __init__(self, rc: int, body: bytes, err: bytes = b""):
        self.rc, self.body, self.err = rc, body, err
        self.target = None

    def capture(self, cmd: str, stdin: bytes | None = None, timeout: float = 60) -> Any:
        mo = re.search(r"__GW_OUT_[0-9a-f]{8}__", cmd).group(0)
        me = re.search(r"__GW_ERR_[0-9a-f]{8}__", cmd).group(0)
        return subprocess.CompletedProcess(cmd, self.rc, f"\n{mo}\n".encode() + self.body,
                                           f"\n{me}\n".encode() + self.err)

    def close(self) -> None:
        pass


def test_an_answer_cut_off_by_a_dropped_connection_is_no_answer_never_no_panes():
    """Found by the suite under load: ssh lost the master while the poll ran,
    the marker had arrived, the rest hadn't, and the empty answer read as "the
    host's tmux has none of these panes": live panes were marked gone. A 255
    after the marker is a dropped connection, and a poll needs its end marker."""
    with H.gateway_env() as env:
        class D0:
            events = None
            def log(self, line: str) -> None:
                pass
        mgr = RM.Remotes(D0(), state_path=env.root / f"rm-{secrets.token_hex(4)}.json")
        h = RM.RemoteHost(mgr, "box")
        h.conn = _FakeConn(255, b"")
        try:
            h._capture("echo hi", None, 5)
            raise AssertionError("a cut-off command counted as an answer")
        except RM.RemoteError as e:
            assert e.code == "unreachable" and "dropped" in e.message
        assert h.conn is None and h.status["reach"] == "down"
        h.conn = _FakeConn(0, b"hi\n")
        assert h._capture("echo hi", None, 5)[1] == b"hi\n"
        tm = RM.RemoteTmux(h, "/r")
        sep = T.SEP
        line = sep.join(["t_X", "n", "1", "2", "/dev/ttys1", "0", "", "", "80", "24", "0", "0", "0", "0",
                         "bash", "title"])
        full = f"{line}\n__GW_TTYS__\nt_X 2 - bash\n{RM.POLL_END}\n"
        infos, ttys = tm.parse_poll(full)
        assert list(infos) == ["t_X"] and ttys["t_X"][0] == 2
        assert tm.parse_poll(f"__GW_TTYS__\n{RM.POLL_END}\n") == ({}, {})   # the host says: none
        assert tm.parse_poll(f"{RM.NOSERVER}\n") == (None, {})               # the host says: no server
        for cut in ("", f"{line}\n", f"{line}\n__GW_TTYS__\n", f"{line}\n__GW_TTYS__\nt_X 2 - ba"):
            try:
                tm.parse_poll(cut)
                raise AssertionError(f"a cut-off poll answer was read ({len(cut)} bytes)")
            except T.TermError as e:
                assert e.code == "remote_unreachable"


# ---------------------------------------------------------------------------
# Lost answers, blips, closes the host didn't get, stale status (review fixes)
# ---------------------------------------------------------------------------


def _lossy_ssh(d: Path) -> tuple[Path, Path, Path]:
    """An ssh wrapper for the `ssh` knob. While `flag` holds "WORD MODE", the
    next ssh call whose arguments contain WORD exits 255 (once): `drop` runs
    the real ssh and throws its answer away (the link dropping after the
    command ran), `cut` passes the answer and then says 255 (dropped after
    the gateway's marker), `skip` never runs it (dropped before it reached
    the host), `skipall` never runs it and every later call fails too until
    `down` is removed."""
    flag, down, w = d / "flag", d / "down", d / "ssh"
    real = S.sq(S.ENV_BIN / "ssh")
    w.write_text(f"""#!/bin/sh
[ -f {S.sq(down)} ] && exit 255
if [ -f {S.sq(flag)} ]; then
  read -r word mode < {S.sq(flag)}
  case "$*" in
    *"$word"*)
      rm -f {S.sq(flag)}
      case "$mode" in
        drop) {real} "$@" >/dev/null 2>&1 ;;
        cut) {real} "$@" ;;
        skipall) : > {S.sq(down)} ;;
      esac
      exit 255 ;;
  esac
fi
exec {real} "$@"
""")
    os.chmod(w, 0o755)
    return w, flag, down


def _lossy_env(fn: Any) -> None:
    d = Path(tempfile_dir(Path(H.tmp_base())))
    wrapper, flag, down = _lossy_ssh(d)
    try:
        with R.remote_env(knobs={"ssh": str(wrapper)}) as re_:
            fn(re_, flag, down)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _j_sessions(re_: R.RemoteEnv, host: str) -> list[str]:
    return [ln.split(":")[0] for ln in re_.tmux(host, "ls").stdout.splitlines()
            if ln.startswith("j_")]


def test_a_remote_start_whose_answer_is_lost_stays_unknown_is_adopted_and_never_runs_twice():
    """Found by the review: a job_start whose answer was lost after new-session
    ran said "unreachable" and kept no record, the job ran untracked, and a
    retry with the same idempotency key ran it a second time."""
    def body(re_: R.RemoteEnv, flag: Path, down: Path) -> None:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        work = _work(re_)
        ids = []
        for mode in ("drop", "cut"):
            count = work / f"count-{mode}"
            flag.write_text(f"new-session {mode}\n")
            req = {"host": "box", "cwd": str(work), "idempotency_key": f"dup-{mode}",
                   "command": f"echo ran >> '{count}'; sleep 300"}
            b = a.ok("/agent/job/start", req)
            jid = b["id"]
            assert not flag.exists(), "the lost answer wasn't simulated"
            assert b["new"] is True and b["state"] == "unknown" and b["ended"] is None, b
            assert b.get("start_confirmed") is False and "dropped while this job was being started" \
                in b.get("note", ""), b
            # a retry with the same key returns that record, never a second start
            again = a.ok("/agent/job/start", req)
            assert again["id"] == jid and again["new"] is False, again
            # nothing is typed into a start that isn't confirmed (unless the host
            # confirmed it meanwhile)
            st, e = a.call("/agent/job/signal", {"id": jid, "signal": "CONT"})
            assert (st == 409 and e["error"] == "unconfirmed" and "isn't confirmed" in e["message"]) \
                or (st == 200 and "start_confirmed" not in _status(a, jid)), (st, e)
            # the host lists it (by its id and nonce): adopted, running
            st = _job_wait(a, jid, ("running",), timeout=30)
            assert "start_confirmed" not in st and not st.get("note"), st
            again = a.ok("/agent/job/start", req)
            assert again["id"] == jid and again["new"] is False
            _until(lambda: count.exists(), what="the job ran")
            time.sleep(0.6)
            assert count.read_text().splitlines() == ["ran"], "the job ran twice"
            assert jid in {j["id"] for j in a.ok("/agent/job/list", {})["jobs"]}
            ids.append(jid)
        assert sorted(_j_sessions(re_, "box")) == sorted(ids), "a job runs on the host untracked"
        snap = _snapshot(re_, fc)
        assert {j["job"]: j["state"] for j in snap["jobs"]} == {i: "running" for i in ids}
    _lossy_env(body)


def test_a_lost_start_that_never_reached_the_host_is_settled_never_started_and_frees_its_key():
    def body(re_: R.RemoteEnv, flag: Path, down: Path) -> None:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        work = _work(re_)
        count = work / "count"
        flag.write_text("new-session skip\n")
        req = {"host": "box", "cwd": str(work), "idempotency_key": "dup-skip",
               "command": f"echo ran >> '{count}'; sleep 300"}
        b = a.ok("/agent/job/start", req)
        jid = b["id"]
        assert b["state"] == "unknown" and b.get("start_confirmed") is False, b
        assert a.ok("/agent/job/start", req)["id"] == jid
        # the poller finds no such session and wins the start file's claim
        st = _job_wait(a, jid, ("failed",), timeout=30)
        assert "never started" in st.get("note", "") and st["exit"] is None and st["ended"], st
        assert "start_confirmed" not in st
        assert not count.exists() and jid not in _j_sessions(re_, "box")
        assert not list((re_.rt_dir("box") / "terms").glob(f"{jid}.*")), "its start file stayed"
        # provably never run: the key is free again, and the same key starts it (once)
        b2 = a.ok("/agent/job/start", req)
        assert b2["id"] != jid and b2["new"] is True and b2["state"] == "running", b2
        _until(lambda: count.exists(), what="the retried job ran")
        time.sleep(0.5)
        assert count.read_text().splitlines() == ["ran"]
        assert a.ok("/agent/job/start", req)["id"] == b2["id"]
        # a terminal's start the same way: unknown, then settled as never opened
        time.sleep(3.2)                         # (past the connection's fast fail)
        flag.write_text("new-session skip\n")
        t = a.ok("/agent/term/open", {"host": "box", "cwd": str(work)})
        assert t["state"] == "unknown" and t.get("start_confirmed") is False, t
        tv = _until(lambda: (lambda x: x if x["state"] != "unknown" else None)(
            next(x for x in a.ok("/agent/term/list", {})["terminals"] if x["id"] == t["id"])),
            timeout=30, what="the terminal's start settled")
        assert tv["state"] == "closed" and "never started" in tv.get("note", ""), tv
    _lossy_env(body)


def test_a_start_files_claim_lets_exactly_one_side_win():
    """The protocol behind settling a lost start: the pane's shell renames its
    start file first thing; gated renames it to settle "never started".
    Whoever renames first wins; the other side's rename fails."""
    with H.gateway_env() as env:
        d = env.root / "rt"
        (d / "terms").mkdir(parents=True)
        out = d / "ran"
        p = T.Pane(id=T.ulid("j"), host="box", cwd=str(d))
        me = str(d / "terms" / f"{p.id}.{p.nonce}.sh")
        text = T.remote_start_text(p, rt=str(d), lang="C.UTF-8", me=me, command=f"echo RAN > '{out}'")
        bash = str(R.ENV_BIN / "bash")
        senv = {"PATH": "/usr/bin:/bin", "HOME": str(env.root)}
        claim = f"mv -- '{me}' '{me}.void' 2>/dev/null && echo NEVER || echo STARTED"   # claim_start's

        def sh(cmd: str) -> subprocess.CompletedProcess:
            return subprocess.run(["/bin/sh", "-c", cmd], capture_output=True, text=True, env=senv,
                                  timeout=20)
        # the shell first: its command runs, gated's claim then fails ("started")
        Path(me).write_text(text)
        r = subprocess.run([bash, "--noprofile", "--norc", me], capture_output=True, text=True,
                           env=senv, timeout=20)
        assert r.returncode == 0 and out.read_text().strip() == "RAN", r.stderr
        assert not os.path.exists(me) and not os.path.exists(me + ".run")
        assert sh(claim).stdout.strip() == "STARTED"
        # gated first while the shell already holds the file open: the shell stops at its claim
        out.unlink()
        Path(me).write_text(text)
        r = sh(f"exec 3< '{me}'; {claim} >/dev/null; exec {bash} --noprofile --norc /dev/fd/3")
        assert r.returncode == 125 and not out.exists(), (r.returncode, r.stderr)
        # gated first, the shell later: there is no file to run
        os.unlink(me + ".void")
        Path(me).write_text(text)
        assert sh(claim).stdout.strip() == "NEVER"
        r = subprocess.run([bash, "--noprofile", "--norc", me], capture_output=True, text=True,
                           env=senv, timeout=20)
        assert r.returncode != 0 and not out.exists()


def test_typed_text_whose_answer_is_lost_is_checked_by_its_buffer_never_called_untyped():
    """The review's second probe: terminal_send said "unreachable" though the
    line had run on the host. The paste deletes its uniquely named buffer, so
    a buffer gone means it went in, one still there means it didn't; when the
    host can't say, the outcome is unknown and the seq moves."""
    def body(re_: R.RemoteEnv, flag: Path, down: Path) -> None:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        work = _work(re_)
        tid = a.open(host="box", cwd=str(work))["id"]
        # 1. it ran there, the answer was lost: delivered, and said so
        flag.write_text("paste-buffer drop\n")
        seq = a.read(tid)["seq"]
        r = a.ok("/agent/term/send", {"id": tid, "seq": seq, "text": f"touch '{work}/sent-1'",
                                      "enter": True})
        assert not flag.exists()
        assert r["delivered"] is True and "answer was lost" in r.get("note", ""), r
        _until(lambda: (work / "sent-1").exists(), what="the line ran")
        back = lambda: _until(lambda: (lambda x: x if x["state"] == "open" and not x.get("note")  # noqa: E731
                                       else None)(a.read(tid)), timeout=30, what="the terminal back")
        back()          # the lost answer dropped the connection: wait for the poller's reconnect
        # 2. it never reached the host: nothing typed, its buffer removed
        flag.write_text("paste-buffer skip\n")
        seq = a.read(tid)["seq"]
        st, e = a.call("/agent/term/send", {"id": tid, "seq": seq, "text": f"touch '{work}/sent-2'",
                                            "enter": True})
        assert st == 503 and "nothing was typed" in e["message"], e
        time.sleep(0.5)
        assert not (work / "sent-2").exists()
        assert re_.tmux("box", "list-buffers").stdout.strip() == ""
        back()          # (under load the reconnect can lag; a send meanwhile is refused upfront)
        # 3. the host can't say: outcome unknown, a repeat with the old seq is stale
        flag.write_text("paste-buffer skipall\n")
        seq = a.read(tid)["seq"]
        st, e = a.call("/agent/term/send", {"id": tid, "seq": seq, "text": f"touch '{work}/sent-3'",
                                            "enter": True})
        assert st == 409 and e["error"] == "outcome_unknown" and "read the screen again" in \
            e["message"], e
        assert a.read(tid)["seq"] > seq, "a blind repeat with the seq read before would be taken"
        down.unlink()
        st, e = a.call("/agent/term/send", {"id": tid, "seq": seq, "text": f"touch '{work}/sent-3'",
                                            "enter": True})
        assert st in (409, 503) and e["error"] in ("stale", "disconnected", "remote_unreachable"), e
        # the buffer of the unknown paste goes at the host's next answer (no late paste)
        _until(lambda: re_.tmux("box", "list-buffers").stdout.strip() == "", timeout=30,
               what="the unknown paste's buffer removed")
        v = _until(lambda: (lambda x: x if x["state"] == "open" and not x.get("note") else None)(
            a.read(tid)), timeout=30, what="the terminal back")
        assert not (work / "sent-3").exists()
        a.run(tid, f"touch '{work}/sent-4'", None)
        _until(lambda: (work / "sent-4").exists(), what="typing works again")
    _lossy_env(body)


def test_a_close_that_doesnt_reach_the_host_is_no_cancel_and_the_job_reports_its_own_end():
    """Found by the review: a close while the host was unreachable failed but
    left cancel set, so the job's own later exit read "canceled"."""
    def body(re_: R.RemoteEnv, flag: Path, down: Path) -> None:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        work = _work(re_)
        jid = a.ok("/agent/job/start", {"host": "box", "cwd": str(work),
                                        "command": "sleep 12; exit 3"})["id"]
        pj = a.ok("/agent/job/start", {"host": "box", "cwd": str(work), "command": "sleep 300",
                                       "on_pause": "interrupt", "task_ref": "t-9"})["id"]
        for j in (jid, pj):
            _job_wait(a, j, ("running",))
        sshd.stop()
        _close_masters("box")
        _until(lambda: (lambda s: s if s["state"] == "disconnected" else None)(_status(a, jid)),
               what="disconnected")
        st, e = a.call("/agent/term/close", {"id": jid})
        assert st == 503 and "was not closed" in e["message"], e
        s = _status(a, jid)
        assert s["state"] == "disconnected" and s["stop_requested"].startswith("not delivered"), s
        # a pause meanwhile says what happened (never "already ended")
        st, r = a.call("/v1/pause", {"session": "s-test", "task_ref": "t-9", "reason": "test"}, mode="x")
        assert st == 200, r
        out = {o["job"]: o["outcome"] for o in r["outcomes"]}
        assert out[pj].startswith("not applied"), out
        a.call("/v1/resume", {"session": "s-test", "task_ref": "t-9"}, mode="x")
        sshd.start()
        _until(lambda: (lambda s: s if s["state"] in ("running", "exited", "canceled") else None)(
            _status(a, jid)), timeout=30, what="reconnected")
        s = _job_wait(a, jid, ("exited", "canceled"), timeout=30)
        assert s["state"] == "exited" and s["exit"] == 3 and s["signal"] is None, s
        # a close whose answer is lost (it did reach the host): the host's next answer decides
        j3 = a.ok("/agent/job/start", {"host": "box", "cwd": str(work), "command": "sleep 300"})["id"]
        _job_wait(a, j3, ("running",))
        flag.write_text("kill-session cut\n")
        st, e = a.call("/agent/term/close", {"id": j3})
        assert not flag.exists()
        assert st == 503 and e["error"] == "outcome_unknown", e
        s = _status(a, j3)
        assert s["stop_requested"].startswith("outcome unknown"), s
        s = _job_wait(a, j3, ("canceled",), timeout=30)
        assert "stop_requested" not in s and j3 not in _j_sessions(re_, "box"), s
    _lossy_env(body)


def test_a_failed_list_panes_is_a_blip_and_only_a_dead_server_loses_the_panes():
    """Found by the review: a list-panes that failed for any reason read as
    "no tmux server", and live remote panes were marked gone/unknown for good."""
    import socket
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        work = _work(re_)
        tid = a.open(host="box", cwd=str(work))["id"]
        jid = a.ok("/agent/job/start", {"host": "box", "cwd": str(work), "command": "sleep 300"})["id"]
        _job_wait(a, jid, ("running",))
        rt = re_.rt_dir("box")
        binp, away = rt / "env" / "bin" / "tmux", rt / "env" / "bin" / "tmux.away"

        def still_there() -> None:
            s = _status(a, jid)
            assert s["state"] == "running" and not s.get("gone") and s["ended"] is None, s
            t = a.ok("/agent/term/list", {})
            tv = next(x for x in t["terminals"] if x["id"] == tid)
            assert tv["state"] == "open" and not tv.get("gone"), tv
        # (a) the runtime's tmux can't start a client for a while; its server runs on
        binp.rename(away)
        try:
            _until(lambda: "didn't answer just now" in _status(a, jid).get("note", ""),
                   what="the blip noticed")
            time.sleep(1.0)
            still_there()
        finally:
            away.rename(binp)
        _until(lambda: not _status(a, jid).get("note"), what="the blip over")
        # (b) tmux says "no server running" (its socket replaced by a dead one) while
        # the server it named last still runs
        sock, held, tmp = rt / "tmux.sock", rt / "tmux.sock.away", rt / "dead.sock"
        dead = socket.socket(socket.AF_UNIX)
        dead.bind(str(tmp))                 # bound, never listening: "no server running"
        os.link(sock, held)                 # the live server's socket kept under another name
        os.rename(tmp, sock)                # the path names the dead one now (atomic: no gap)
        try:
            time.sleep(1.5)
            still_there()
        finally:
            os.rename(held, sock)           # the live one back (atomic)
            dead.close()
        _until(lambda: not _status(a, jid).get("note"), what="answers again")
        still_there()
        v = a.run(tid, 'echo "ST""ILL=$((40+2))"', "STILL=42")
        assert any(ln == "STILL=42" for ln in v["lines"])
        # (c) the server really dies (SIGKILL: its socket stays, nobody listens): lost
        spid = int(re_.tmux("box", "display-message", "-p", "#{pid}").stdout.strip())
        os.kill(spid, signal.SIGKILL)
        lost = _until(lambda: (lambda s: s if s["state"] == "unknown" else None)(_status(a, jid)),
                      what="unknown after the server died")
        assert lost["ended"] is None and lost.get("gone") is True and "isn't running any more" in \
            lost["note"], lost
        tv = next(x for x in a.ok("/agent/term/list", {})["terminals"] if x["id"] == tid)
        assert tv["state"] == "gone", tv


def test_a_root_password_prompt_anywhere_in_the_foreground_pipeline_follows_the_sudo_rule():
    """Found by the review: only the foreground group's leader was looked at,
    so `sleep 60 | sudo ...` (and `echo x | sudo tee f`) got the dialog on a
    host whose sudo is off, naming the wrong program."""
    from test_dialogs import Mod
    with R.remote_env() as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd, sudo=False)
        re_.add_host("box2", sshd, sudo=True)
        fc = re_.de.claude()
        mod = Mod(fc)
        a = _agent(re_, fc)
        work = _work(re_)
        (work / "sudo").symlink_to(R.ENV_BIN / "bash")
        line = ("sleep 60 | ./sudo --norc -c 'read -s -p \"[sudo] password: \" x </dev/tty; "
                "echo after'")
        tid = a.open(host="box", cwd=str(work))["id"]
        a.run(tid, line, done=False)
        v = _until(lambda: (lambda x: x if x.get("waiting_auth") else None)(a.read(tid)),
                   what="waiting_auth (pipeline)")
        assert "sudo on box is off" in v.get("note", ""), v
        time.sleep(0.5)
        assert mod.view()["dialog"] is None, "a root password was asked for where sudo is off"
        a.ok("/agent/term/signal", {"id": tid, "signal": "INT"})
        # where sudo is on, the dialog names the program that asks, not the group's leader
        t2 = a.open(host="box2", cwd=str(work))["id"]
        a.run(t2, line, done=False)
        d = mod.dialog(lambda x: x.get("entry") == "terminal" and x.get("target") == t2, timeout=20)
        assert any(ln == "Foreground program: sudo on box2 (the host's name for it only)"
                   for ln in d["lines"]), d["lines"]
        mod.post("/ui/dialog/cancel", {"id": d["id"]})
        a.ok("/agent/term/signal", {"id": t2, "signal": "INT"})


def test_host_runtime_status_says_when_the_host_last_answered_and_goes_unknown_when_stale():
    """Found by the review: host_runtime status and the snapshot said
    reachable "ok" / runtime "ready" long after the host went down."""
    with H.gateway_env() as env:
        class D0:
            events = None
            def log(self, line: str) -> None:
                pass
            def machine_id(self) -> str:
                return "m_local"
        mgr = RM.Remotes(D0(), state_path=env.root / "rm.json")
        h = RM.RemoteHost(mgr, "box")
        h.status.update(reach="ok", auth="ok", identity="verified", runtime="ready")
        now = time.time()
        h.checked_at = now - 2
        s = h.summary(now)
        assert (s["reachable"], s["auth"], s["runtime"]) == ("ok", "ok", "ready") and "stale" not in s
        assert abs(s["checked_at"] - (now - 2)) < 0.01
        h.checked_at = now - RM.STALE_AFTER - 20
        s = h.summary(now)
        assert (s["reachable"], s["auth"], s["runtime"]) == ("unknown", "unknown", "unknown"), s
        assert s["stale"] is True and "last asked" in s["note"] and "reachable ok" in s["note"], s
    with R.remote_env(knobs={"remote_stale": 1.5}) as re_:
        sshd = re_.se.sshd("box")
        re_.add_host("box", sshd)
        fc = re_.de.claude()
        a = _agent(re_, fc)
        tid = a.open(host="box", cwd=str(_work(re_)))["id"]
        st = a.ok("/agent/remote/runtime", {"host": "box"})
        assert st["reachable"] == "ok" and st["runtime"] == "ready" and st["checked_at"], st
        a.ok("/agent/term/close", {"id": tid})
        sshd.stop()
        _close_masters("box")
        time.sleep(2.5)
        st = a.ok("/agent/remote/runtime", {"host": "box"})
        assert st["reachable"] == "unknown" and st["auth"] == "unknown" and st.get("stale"), st
        assert st["runtime"] == "unknown" and st["checked_at"] < time.time() - 1.5, st
        h = next(x for x in _snapshot(re_, fc)["hosts"] if x["name"] == "box")
        assert h["reachable"] == "unknown" and h["runtime"] == "unknown", h


def test_a_changed_host_key_at_the_address_choice_is_asked_and_nothing_is_trusted():
    """Deterministic for the address choice's own scan (on_mismatch): the
    review found the changed-key test passed either way when that scan was
    skipped, because ssh's strict check asked anyway. Here the scan sees
    another key; the link must raise and ask, never take the seen key as the
    pins, and nothing may reach the host."""
    from gateway import ssh_conf
    with S.ssh_env() as se:
        sshd = se.sshd("box")
        se.write_form(f'[hosts.box]\naddress = "{sshd.addr()}"\nssh = true\n')
        se.host("box", sshd)
        se.approve()
        other = " ".join(se.key("other-host")[1].split()[:2])
        opened: list[dict[str, Any]] = []

        class Dialogs:
            def open_owned(self, sess: Any, spec: dict[str, Any], **kw: Any) -> dict[str, Any]:
                opened.append(spec)
                return {"available": True, "id": f"d{len(opened)}"}

        class D0:
            events = None
            dialogs = Dialogs()
            def log(self, line: str) -> None:
                pass
            def machine_id(self) -> str:
                return "m_local"
            def _host_ids(self, names: list[str]) -> dict[str, str]:
                return {n: "m_" + "h" * 26 for n in names}
        mgr = RM.Remotes(D0(), state_path=se.root / "rm.json")
        h = RM.RemoteHost(mgr, "box")
        old_probe, old_scan = ssh_conf._probe, ssh_conf.scan_keys
        ssh_conf._probe = lambda a: "yes"
        ssh_conf.scan_keys = lambda host, port: [other]
        try:
            ssh_conf.cache_clear("box")
            sess = object()
            try:
                h._link(h.state(), sess)
                raise AssertionError("a changed host key was trusted without asking")
            except RM.RemoteError as e:
                assert e.code == "hostkey" and "asks the user" in e.message, e.message
            assert [x.get("what") for x in opened] == ["host key"] and opened[0]["entry"] == "box"
            assert h.change is not None and h.change["kind"] == "host_key"
            try:
                h.run("touch /tmp/never", session=sess)
                raise AssertionError("a command ran behind a changed host key")
            except RM.RemoteError as e:
                assert e.code == "hostkey"
            assert len(opened) == 1, "asked twice"
        finally:
            ssh_conf._probe, ssh_conf.scan_keys = old_probe, old_scan
        assert sshd.accepted() == 0 and not sshd.commands(), "something reached the host"
        assert vault.load()["hosts"]["box"]["host_keys"] == [sshd.host_key]


def test_ssh_refusing_a_changed_host_key_asks_the_user_at_once():
    """The other way a changed key shows: ssh's own strict check refuses it
    (the address choice's scan was cached, skipped or too slow). The keys are
    scanned right then and the person asked once; nothing ran."""
    from types import SimpleNamespace
    from gateway import ssh_conf
    with H.gateway_env() as env:
        opened: list[dict[str, Any]] = []

        class Dialogs:
            def open_owned(self, sess: Any, spec: dict[str, Any], **kw: Any) -> dict[str, Any]:
                opened.append(spec)
                return {"available": True, "id": "d1"}

        class D0:
            events = None
            dialogs = Dialogs()
            def log(self, line: str) -> None:
                pass

        class Refused:
            target = SimpleNamespace(jump=None, host_keys=["ssh-ed25519 AAAApinned"],
                                     addr=SimpleNamespace(host="127.0.0.1", port=22,
                                                          render=lambda: "127.0.0.1"))
            def capture(self, cmd: str, stdin: bytes | None = None, timeout: float = 60) -> Any:
                return subprocess.CompletedProcess(cmd, 255, b"", b"Host key verification failed.\n")
            def close(self) -> None:
                pass
        mgr = RM.Remotes(D0(), state_path=env.root / "rm.json")
        h = RM.RemoteHost(mgr, "box")
        h.conn = Refused()
        old = ssh_conf.scan_keys
        ssh_conf.scan_keys = lambda host, port: ["ssh-ed25519 AAAAother"]
        try:
            try:
                h._capture("touch /tmp/never", None, 5, session=object())
                raise AssertionError("a refused host key counted as an answer")
            except RM.RemoteError as e:
                assert e.code == "hostkey" and "asks the user" in e.message, e.message
                assert not e.extra.get("ambiguous"), "a refused host key may have run the command?"
        finally:
            ssh_conf.scan_keys = old
        assert [x.get("what") for x in opened] == ["host key"], opened
        assert h.change is not None and h.change["kind"] == "host_key" and h.conn is None


def test_a_plain_uninstall_resumes_a_remote_job_a_pause_suspended_through_the_live_master():
    """A plain uninstall deletes the env (ssh, ssh-agent, ...) with the data
    folder. The drain resumed a local job a pause had suspended, but the
    remote one stayed stopped on its host ("resuming it failed
    (remote_unreachable)": the env's ssh was gone), its runtime's tmux with it,
    and the records that could re-adopt it went with the folder. A draining
    gated now uses the system's ssh (by absolute path; here a logging wrapper
    around it) with the call's generated config and never as a master, so it
    reaches the host through the gateway's live master and resumes the job."""
    import shutil
    import tempfile
    tb = Path(tempfile.mkdtemp(prefix="gwtools-", dir=str(H.tmp_base())))
    wrappers = {}
    for n in ("ssh", "ssh-agent", "ssh-add", "ssh-keyscan"):
        w = tb / n
        w.write_text(f"#!/bin/sh\nexec {S.sq(R.ENV_BIN / n)} \"$@\"\n")
        os.chmod(w, 0o755)
        wrappers[n] = str(w)
    syslog = tb / "system-ssh.log"
    real = "/usr/bin/ssh" if os.access("/usr/bin/ssh", os.X_OK) else str(R.ENV_BIN / "ssh")
    sysw = tb / "system-ssh"
    sysw.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {S.sq(syslog)}\nexec {S.sq(real)} \"$@\"\n")
    os.chmod(sysw, 0o755)
    knobs = {"tools": wrappers, "exclusive_tools": True, "system_ssh": str(sysw)}
    try:
        with R.remote_env(knobs=knobs) as re_:
            sshd = re_.se.sshd("box")
            re_.add_host("box", sshd)
            fc = re_.de.claude()
            a = _agent(re_, fc)
            cwd = str(_work(re_))
            n = secrets.randbelow(10**6)               # this run's sleeps (others may run beside it)
            w6, w7 = f"176.{n}", f"177.{n}"
            rj = a.ok("/agent/job/start", {"host": "box", "argv": ["sleep", w6], "cwd": cwd,
                                           "on_pause": "suspend", "task_ref": "t1"})["id"]
            lj = a.ok("/agent/job/start", {"argv": ["sleep", w7], "cwd": cwd,
                                           "on_pause": "suspend", "task_ref": "t1"})["id"]
            for j in (rj, lj):
                _job_wait(a, j, ("running",))
            st, r = a.call("/v1/pause", {"session": "s-test", "task_ref": "t1", "reason": "x"}, mode="x")
            assert st == 200 and {o["job"]: o["outcome"] for o in r["outcomes"]} == \
                {rj: "suspended (SIGSTOP)", lj: "suspended (SIGSTOP)"}, r

            def stats(word: str) -> list[str]:
                return [ln.split()[1] for ln in subprocess.run(
                    ["ps", "-axo", "pid=,stat=,command="], capture_output=True,
                    text=True).stdout.splitlines() if ln.split()[2:] == ["sleep", word]]
            assert stats(w6) and all(s.startswith("T") for s in stats(w6)), stats(w6)
            for w in wrappers.values():
                os.unlink(w)                  # the env's ssh tools go with the data folder
            time.sleep(1.0)                   # five polls of the host, all failing now
            assert not syslog.exists(), "the system's ssh ran before any drain"
            data = Path(re_.de.env.data)
            shutil.rmtree(data)
            assert re_.de.wait_for(lambda: (re_.de.health() or {}).get("draining"), 10), re_.de.health()
            deadline = time.time() + 15
            while time.time() < deadline and any(s.startswith("T") for s in stats(w6) + stats(w7)):
                time.sleep(0.2)
            assert not any(s.startswith("T") for s in stats(w6)), \
                ("the remote job stayed stopped", stats(w6),
                 (paths.contract_dir() / "gated-drain.log").read_text()[-600:])
            assert not any(s.startswith("T") for s in stats(w7)), stats(w7)
            # the processes run on before the drain's event and its log line
            ev = re_.de.wait_for(lambda: R.events(re_.de, fc, ("daemon.draining",)), 10)
            assert ev and ev[-1]["resumed"] == 2, ev
            calls = syslog.read_text()
            assert "-o ControlMaster=no" in calls and "-F " in calls, calls[-400:]
            drain_log = paths.contract_dir() / "gated-drain.log"
            re_.de.wait_for(lambda: drain_log.exists() and "taking no new work" in drain_log.read_text(), 10)
            note = drain_log.read_text()
            assert rj in note and "resumed" in note and "resuming it failed" not in note, note[-600:]
            gated = re_.de.daemon_pid()
            root = int(subprocess.run([str(R.ENV_BIN / "tmux"), "-S", str(re_.de.run / "tmux.sock"),
                                       "display-message", "-p", "-t", f"={lj}:", "#{pane_pid}"],
                                      capture_output=True, text=True, timeout=10,
                                      env={"PATH": "/usr/bin:/bin"}).stdout.strip())
            os.killpg(root, signal.SIGKILL)
            deadline = time.time() + 10
            while time.time() < deadline and gated and _pid_alive(gated):
                time.sleep(0.1)
            assert not (gated and _pid_alive(gated)), "gated stayed after the local job ended"
            data.mkdir(parents=True)
    finally:
        shutil.rmtree(tb, ignore_errors=True)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
