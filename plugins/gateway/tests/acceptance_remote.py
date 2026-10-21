#!/usr/bin/env python3
"""Brief 14.6 and 14.8 live: the managed remote runtime (PLAN-v4 phase 6).

    pixi run --locked python tests/acceptance_remote.py --vm DIR [--tmp DIR] [--only a,b] [--keep]
        [--vm-dir NAME] [--vm-sshd-port N]

Against real hosts, with real artifacts: a real gated in a test root (the
suite's harness: harness_daemon, a FakeClaude as the Claude Code session that
draws dialogs, answered here as the gate mod would: harness test_dialogs.Mod
and its sealed boxes), the runtime packed for real with pixi-pack (the
gateway env's; packages from conda-forge into the test root's data folder)
and the target's own pixi-unpack, staged over the gateway's own ssh:

  vm    the disposable Debian 13 arm64 VM (DIR/vm.sh) through 127.0.0.1:2222,
        user tester, the gateway's own throwaway key appended to tester's
        authorized_keys for the run (marked, removed afterwards), the VM's
        host key pinned from DIR/known_hosts. Runtime path ~/gw-remote/rt
        (the run works only under ~/gw-remote in the VM; --vm-dir NAME puts it
        under ~/NAME, so runs of several agents sharing the VM don't meet).
  vm2   the same VM through a PRIVATE sshd the run starts inside it as tester
        (127.0.0.1:22022 there, --vm-sshd-port; its own host key and
        authorized_keys under ~/gw-remote/sshd), reached through a local port forward: the
        disruptive steps (stopping sshd, removing the key, a new host key)
        never touch the VM's own sshd, which other agents use.
  mac   a local sshd on this machine (tests/harness_ssh.Sshd, 127.0.0.1), runtime
        under a short /tmp folder: a second platform (osx-arm64 here).

Sections: stage (first remote terminal provisions the runtime: no tmux on
the VM), env (the managed environment: no remote ~/.bashrc effect, only the
curated PATH), jobs, disconnect (a job running while vm2's sshd and the
master go; reconnect; a surviving job, one killed meanwhile, one whose tmux
session went), auth (vm2's key removed then restored: waiting_auth, the
notice, recovery), hostkey (vm2's host key regenerated: blocked until the
user trusts it), wronghost (vm and mac with the same path; vm's address
moved to mac's sshd: blocked, nothing of vm's reaches mac), prompt (a
password prompt in a VM terminal through the dialog; the canary nowhere on a
command line), mac (the second platform). Prints one line per check and a
JSON summary to --tmp/acceptance-remote.json; exits non-zero on any failure.
Canaries are generated here and never printed.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))

import harness as H  # noqa: E402
import harness_daemon as D  # noqa: E402
import harness_ssh as S  # noqa: E402

RESULTS: list[dict[str, Any]] = []
MARK = "gw-remote-acceptance"
# The run's folder under tester's home in the VM (--vm-dir); every path the run
# names there is written with ~/gw-remote, /home/tester/gw-remote or
# $HOME/gw-remote in this file and goes through vmp() on its way out.
VMDIR = "gw-remote"


def vmp(text: str) -> str:
    """The run's own VM folder in a command, a file or a path (VMDIR)."""
    if VMDIR == "gw-remote":
        return text
    for pre in ("~/", "/home/tester/", "$HOME/"):
        text = text.replace(pre + "gw-remote", pre + VMDIR)
    return text
SECTIONS = ("stage", "env", "jobs", "disconnect", "auth", "hostkey", "wronghost", "prompt", "mac")


def check(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append({"check": name, "ok": bool(ok), "detail": detail[:300]})
    print(f"{'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail[:200]})" if detail else ""), flush=True)
    return bool(ok)


def sha16(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()[:16]


class VM:
    def __init__(self, d: Path):
        self.d = d

    def ssh(self, cmd: str, input: str | None = None, timeout: float = 120) -> subprocess.CompletedProcess:
        return subprocess.run([str(self.d / "vm.sh"), "ssh", "tester", vmp(cmd)], input=input,
                              capture_output=True, text=True, timeout=timeout)

    def host_key(self) -> str:
        for ln in (self.d / "known_hosts").read_text().splitlines():
            if ln.startswith("[127.0.0.1]:2222 "):
                return " ".join(ln.split()[1:3])
        raise SystemExit("no pinned VM host key in known_hosts")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class PrivateSshd:
    """A non-root sshd inside the VM, as tester, under ~/gw-remote/sshd,
    reached through a local forward over the VM's own sshd."""

    PORT = 22022

    def __init__(self, vm: VM, work: Path):
        self.vm, self.work = vm, work
        self.lport = free_port()
        self.fwd: subprocess.Popen | None = None
        self.host_key = ""

    def setup(self, pub: str) -> None:
        cfg = "\n".join([f"Port {self.PORT}", "ListenAddress 127.0.0.1",
                         "HostKey /home/tester/gw-remote/sshd/hostkey",
                         "PidFile /home/tester/gw-remote/sshd/sshd.pid",
                         "AuthorizedKeysFile /home/tester/gw-remote/sshd/authorized_keys",
                         "PasswordAuthentication no", "KbdInteractiveAuthentication no",
                         "UsePAM no", "StrictModes no", "PermitUserEnvironment no",
                         "LogLevel VERBOSE", "ClientAliveInterval 5", "ClientAliveCountMax 2", ""])
        r = self.vm.ssh("mkdir -p ~/gw-remote/sshd && chmod 700 ~/gw-remote ~/gw-remote/sshd && "
                        "cat > ~/gw-remote/sshd/sshd_config && "
                        "rm -f ~/gw-remote/sshd/hostkey ~/gw-remote/sshd/hostkey.pub && "
                        "ssh-keygen -q -t ed25519 -N '' -f ~/gw-remote/sshd/hostkey && "
                        "cat ~/gw-remote/sshd/hostkey.pub", input=vmp(cfg))
        assert r.returncode == 0, r.stderr
        self.host_key = " ".join(r.stdout.split()[:2])
        self.set_key(pub)

    def set_key(self, pub: str | None) -> None:
        r = self.vm.ssh("cat > ~/gw-remote/sshd/authorized_keys", input=(pub + "\n") if pub else "")
        assert r.returncode == 0, r.stderr

    def new_host_key(self) -> None:
        r = self.vm.ssh("rm -f ~/gw-remote/sshd/hostkey ~/gw-remote/sshd/hostkey.pub && "
                        "ssh-keygen -q -t ed25519 -N '' -f ~/gw-remote/sshd/hostkey && "
                        "cat ~/gw-remote/sshd/hostkey.pub")
        assert r.returncode == 0, r.stderr
        self.host_key = " ".join(r.stdout.split()[:2])

    def start(self) -> None:
        r = self.vm.ssh("/usr/sbin/sshd -f /home/tester/gw-remote/sshd/sshd_config -E "
                        "/home/tester/gw-remote/sshd/sshd.log; sleep 0.5; "
                        "cat /home/tester/gw-remote/sshd/sshd.pid")
        assert r.returncode == 0 and r.stdout.strip().isdigit(), (r.stdout, r.stderr)
        if self.fwd is None or self.fwd.poll() is not None:
            self.fwd = subprocess.Popen(
                ["ssh", "-N", "-o", "BatchMode=yes", "-o", "ExitOnForwardFailure=yes",
                 "-o", "StrictHostKeyChecking=yes", "-o", f"UserKnownHostsFile={self.vm.d}/known_hosts",
                 "-i", str(self.vm.d / "keys" / "vm_ed25519"), "-p", "2222",
                 "-L", f"127.0.0.1:{self.lport}:127.0.0.1:{self.PORT}", "tester@127.0.0.1"],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            end = time.time() + 15
            while time.time() < end:
                try:
                    with socket.create_connection(("127.0.0.1", self.lport), timeout=1) as s:
                        s.settimeout(2)
                        if s.recv(4) == b"SSH-":
                            return
                except OSError:
                    time.sleep(0.2)
            raise RuntimeError("the forward to the private sshd didn't come up")

    def stop(self) -> None:
        """The listener and every session it serves (sshd-session children)."""
        self.vm.ssh("p=$(cat ~/gw-remote/sshd/sshd.pid 2>/dev/null); "
                    "[ -n \"$p\" ] && { pkill -TERM -P \"$p\"; kill \"$p\"; }; "
                    "rm -f ~/gw-remote/sshd/sshd.pid; true")

    def close(self) -> None:
        self.stop()
        if self.fwd is not None and self.fwd.poll() is None:
            self.fwd.terminate()
            with contextlib.suppress(subprocess.TimeoutExpired):
                self.fwd.wait(timeout=5)

    def addr(self) -> str:
        return f"tester@127.0.0.1:{self.lport}"


def until(fn: Any, timeout: float = 30) -> Any:
    end = time.time() + timeout
    v = None
    while time.time() < end:
        try:
            v = fn()
        except Exception:  # noqa: BLE001
            v = None
        if v:
            return v
        time.sleep(0.2)
    return v


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--vm", required=True, help="the VM folder (vm.sh, known_hosts, keys/)")
    ap.add_argument("--tmp", default=tempfile.gettempdir())
    ap.add_argument("--only", default="")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--vm-dir", default="gw-remote",
                    help="the run's folder under tester's home in the VM (default gw-remote)")
    ap.add_argument("--vm-sshd-port", type=int, default=PrivateSshd.PORT,
                    help="the private sshd's port inside the VM (default 22022)")
    args = ap.parse_args(argv)
    global VMDIR
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,40}", args.vm_dir) or args.vm_dir in (".", ".."):
        print("--vm-dir takes a plain folder name", file=sys.stderr)
        return 2
    VMDIR = args.vm_dir
    PrivateSshd.PORT = args.vm_sshd_port
    only = set(x for x in args.only.split(",") if x) or set(SECTIONS)
    vm = VM(Path(args.vm).resolve())
    out_dir = Path(args.tmp).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    os.environ["GW_TEST_TMP"] = str(out_dir)
    t0 = time.time()
    if vm.ssh("true").returncode != 0:
        print("the VM doesn't answer (DIR/vm.sh start)", file=sys.stderr)
        return 2
    base = Path(tempfile.mkdtemp(prefix="gwra-", dir="/tmp"))
    os.chmod(base, 0o700)
    pvt = None
    bashrc_backup = False
    try:
        with S.ssh_env() as se, D.attach(se.env, se.run_dir, knobs={"remote_tick": 0.5}) as de:
            from gateway import paths, runtime_pack, ssh, ssh_conf, vault
            from test_dialogs import Mod, seal
            from test_terminals import Agent
            # the gateway's own key for the VM (throwaway, the run's only), marked
            priv, pub = se.key("vm")
            pub_line = f"{pub.split()[0]} {pub.split()[1]} {MARK}"
            r = vm.ssh(f"mkdir -p ~/gw-remote && chmod 700 ~/gw-remote && "
                       f"grep -v '{MARK}' ~/.ssh/authorized_keys > ~/gw-remote/ak.new; "
                       f"cat >> ~/gw-remote/ak.new && cat ~/gw-remote/ak.new > ~/.ssh/authorized_keys && "
                       "rm -f ~/gw-remote/ak.new", input=pub_line + "\n")
            check("setup: the gateway's throwaway key is authorized for tester in the VM",
                  r.returncode == 0, r.stderr)
            mac = se.sshd("mac")
            mac_base = base / "mac"
            pvt = PrivateSshd(vm, out_dir)
            pvt.setup(pub_line)
            pvt.start()
            form = vmp(f'[hosts.vm]\naddress = "tester@127.0.0.1:2222"\nssh = true\nsudo = false\n'
                    f'runtime = "~/gw-remote/rt"\n\n'
                    f'[hosts.vm2]\naddress = "{pvt.addr()}"\nssh = true\nsudo = false\n'
                    f'runtime = "~/gw-remote/rt2"\n\n'
                    f'[hosts.mac]\naddress = "{mac.addr()}"\nssh = true\nsudo = false\n'
                    f'runtime = "{mac_base}"\n')
            se.write_form(form)
            se.approve()
            se.host("mac", mac)
            with vault.edit() as d:
                for name, hk in (("vm", vm.host_key()), ("vm2", pvt.host_key)):
                    rec = vault.host_record(d, name)
                    if not any(k.get("public") == pub for k in rec["keys"]):
                        rec["keys"].append(vault.key_record(priv, pub))
                    rec["host_keys"] = [hk]
            fc = de.claude()
            mod = Mod(fc)
            a = Agent(de, fc)

            def status(j: str) -> dict[str, Any]:
                return a.ok("/agent/job/status", {"id": j})

            def wait_state(j: str, states: tuple[str, ...], timeout: float = 60) -> dict[str, Any]:
                return until(lambda: (lambda s: s if s["state"] in states else None)(status(j)),
                             timeout) or status(j)

            ver = runtime_pack.version()
            rtv = vmp(f"/home/tester/gw-remote/rt/{ver}-linux-aarch64")
            vm_tid = None
            # -- stage ----------------------------------------------------------
            if "stage" in only or "env" in only or "prompt" in only:
                before = vm.ssh("command -v tmux || echo no-tmux").stdout.strip()
                check("stage: the VM has no tmux of its own", before == "no-tmux", before)
                t1 = time.time()
                st, v = a.call("/agent/term/open", {"host": "vm", "cols": 100, "rows": 24})
                took = time.time() - t1
                check("stage: the first remote terminal provisions the runtime and opens",
                      st == 200 and v.get("state") == "open", f"{st} {json.dumps(v)[:200]} {took:.1f}s")
                vm_tid = v.get("id")
                m = runtime_pack.load_manifest("linux-aarch64")
                check("stage: the pack was built with pixi-pack for linux-aarch64, sha256 recorded",
                      m is not None and m["pixi_pack"] not in ("test", "?") and
                      all(len(f["sha256"]) == 64 for f in m["files"]),
                      f"files={len(m['files']) if m else 0} total={runtime_pack.total_size(m) if m else 0}")
                ls = vm.ssh(f"stat -c '%a %n' ~/gw-remote/rt {rtv}; ls -A {rtv}; "
                            f"cat {rtv}/.gateway-runtime; du -sk {rtv} | cut -f1").stdout
                check("stage: the runtime folder is private, versioned, unpacked, the pack and "
                      "unpacker removed", vmp("700 /home/tester/gw-remote/rt") in ls and f"700 {rtv}" in ls
                      and "env" in ls.split() and "runtime.tar" not in ls and "unpacker" not in ls
                      and '"platform": "linux-aarch64"' in ls, " ".join(ls.split())[:240])
                aud = [x for x in se.audit("remote_runtime") if x.get("outcome") == "staged"]
                check("stage: sha256 verified on the host", bool(aud) and aud[-1].get("hash_check")
                      == "on the host", json.dumps(aud[-1:])[:200])
                rec = vault.load()["hosts"]["vm"]
                mid = vm.ssh("cat /etc/machine-id").stdout.strip()
                from gateway.daemon.lifecycle import machine_token
                check("stage: the VM's machine id is stored with its host key (as a token)",
                      rec.get("machine_id") == machine_token(mid) and bool(rec.get("host_keys")),
                      rec.get("machine_id", ""))
                srt = a.ok("/agent/remote/runtime", {"host": "vm"})
                check("stage: host_runtime reports ready, verified, bash and tmux versions",
                      srt.get("runtime") == "ready" and srt.get("identity") == "verified" and
                      srt.get("bash", "").startswith("5.") and srt.get("tmux", "").startswith("tmux 3"),
                      json.dumps({k: srt.get(k) for k in ("runtime", "identity", "bash", "tmux",
                                                          "platform")}))
                tm = vm.ssh(f"ps -eo user,args | grep '[g]w-remote/rt/{ver}' | head -3").stdout
                check("stage: the runtime's tmux runs on its private socket in the runtime folder",
                      f"{rtv}/tmux.sock" in tm, " ".join(tm.split())[:200])
                print(f"   (staging + first terminal took {took:.1f} s)")
            # -- env --------------------------------------------------------------
            if "env" in only and vm_tid:
                vm.ssh("cp ~/.bashrc ~/gw-remote/bashrc.orig")
                bashrc_backup = True
                probe = ('[ -f "$HOME/gw-remote/bashrc-probe" ] && { export GW_BASHRC_RAN=1; '
                         'PATH="/gw-bashrc-probe:$PATH"; : > "$HOME/gw-remote/bashrc-ran"; }  # ' + MARK)
                r = vm.ssh(f"{{ printf '%s\\n' '{probe}'; cat ~/gw-remote/bashrc.orig; }} > ~/.bashrc && "
                           ": > ~/gw-remote/bashrc-probe && rm -f ~/gw-remote/bashrc-ran")
                ssh.close_masters("vm")
                check("env: a guarded probe line put first in the VM user's ~/.bashrc", r.returncode == 0)
                st, v = a.call("/agent/term/open", {"host": "vm", "cols": 120, "rows": 30})
                tid = v.get("id")
                a.run(tid, vmp("env > ~/gw-remote/pane-env.txt; echo env-done"), "env-done", timeout=30)
                env_txt = vm.ssh("cat ~/gw-remote/pane-env.txt").stdout
                env = dict(ln.split("=", 1) for ln in env_txt.splitlines() if "=" in ln)
                ran = vm.ssh("[ -f ~/gw-remote/bashrc-ran ] && echo ran || echo not").stdout.strip()
                check("env: the managed shell got nothing from ~/.bashrc", "GW_BASHRC_RAN" not in env
                      and "/gw-bashrc-probe" not in env.get("PATH", ""),
                      f"login shell's own rc ran for the ssh command: {ran}")
                check("env: PATH is exactly the curated one (the runtime's bin, then system folders)",
                      env.get("PATH") == f"{rtv}/env/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:"
                      "/usr/sbin:/sbin", env.get("PATH", ""))
                check("env: nothing of the ssh login session reached it", not any(
                    k in env for k in ("SSH_CONNECTION", "SSH_CLIENT", "MAIL", "XDG_SESSION_ID",
                                       "DBUS_SESSION_BUS_ADDRESS")), " ".join(sorted(env))[:240])
                check("env: SHELL is the runtime's bash", env.get("SHELL") == f"{rtv}/env/bin/bash")
                vm.ssh("cat ~/gw-remote/bashrc.orig > ~/.bashrc && rm -f ~/gw-remote/bashrc-probe "
                       "~/gw-remote/bashrc-ran ~/gw-remote/pane-env.txt")
                same = vm.ssh("cmp -s ~/.bashrc ~/gw-remote/bashrc.orig && echo same").stdout.strip()
                bashrc_backup = same != "same"
                check("env: ~/.bashrc restored byte for byte", same == "same")
                a.ok("/agent/term/close", {"id": tid})
            # -- jobs -------------------------------------------------------------
            if "jobs" in only:
                b = a.ok("/agent/job/start", {"host": "vm", "cwd": "/tmp", "command":
                         'printf "PATH=%s\\n" "$PATH"; command -v tmux bash; tmux -V; exit 4'})
                s = wait_state(b["id"], ("exited",))
                tail = a.ok("/agent/job/tail", {"id": b["id"]})["text"]
                check("jobs: a remote job runs in the managed env and reports its exit",
                      s.get("exit") == 4 and f"PATH={rtv}/env/bin:" in tail and
                      f"{rtv}/env/bin/tmux" in tail and "tmux 3" in tail, " ".join(tail.split())[:240])
            # -- disconnect -------------------------------------------------------
            if "disconnect" in only:
                jobs = {k: a.ok("/agent/job/start", {"host": "vm2", "cwd": "/tmp",
                                                     "command": "sleep 900"})["id"]
                        for k in ("survives", "killed", "session_gone")}
                ok = all(wait_state(j, ("running",)).get("state") == "running" for j in jobs.values())
                check("disconnect: three jobs run on vm2 (the private sshd)", ok)
                pvt.stop()
                ssh.close_masters("vm2")
                ssh_conf.cache_clear("vm2")
                s = wait_state(jobs["survives"], ("disconnected",), 40)
                check("disconnect: with sshd and the master gone the job is disconnected, never ended",
                      s.get("state") == "disconnected" and s.get("ended") is None,
                      f"{s.get('state')}: {s.get('note', '')[:120]}")
                rt2 = vmp(f"/home/tester/gw-remote/rt2/{ver}-linux-aarch64")
                tmx = (f"env -i PATH=/usr/bin:/bin HOME=$HOME {rt2}/env/bin/tmux -S {rt2}/tmux.sock")
                pids = vm.ssh(f"{tmx} list-panes -a -F '#{{session_name}} #{{pane_pid}}'").stdout
                pmap = {ln.split()[0]: ln.split()[1] for ln in pids.splitlines() if len(ln.split()) == 2}
                vm.ssh(f"kill -9 -- -{pmap.get(jobs['killed'], '0')}; "
                       f"{tmx} kill-session -t ={jobs['session_gone']}")
                check("disconnect: the runtime's tmux on the VM survived the disconnect",
                      jobs["survives"] in pmap, ",".join(pmap)[:200])
                pvt.start()
                s = wait_state(jobs["survives"], ("running",), 60)
                check("disconnect: after reconnecting the surviving job is running", s.get("state") ==
                      "running" and not s.get("note"), s.get("state", ""))
                k = status(jobs["killed"])
                check("disconnect: a job killed meanwhile is exited with its signal",
                      k.get("state") == "exited" and k.get("signal") == "KILL", json.dumps(k)[:200])
                g = status(jobs["session_gone"])
                check("disconnect: a job whose tmux session went is unknown (no end time)",
                      g.get("state") == "unknown" and g.get("ended") is None and g.get("gone"),
                      f"{g.get('state')}: {g.get('note', '')[:120]}")
                a.ok("/agent/job/signal", {"id": jobs["survives"], "signal": "TERM"})
            # -- auth ---------------------------------------------------------------
            if "auth" in only:
                j = a.ok("/agent/job/start", {"host": "vm2", "cwd": "/tmp", "command": "sleep 900"})["id"]
                wait_state(j, ("running",))
                pvt.set_key(None)
                ssh.close_masters("vm2")
                s = wait_state(j, ("waiting_auth",), 40)
                check("auth: the key removed on the host gives waiting_auth with the remedy",
                      s.get("state") == "waiting_auth" and "gate check vm2" in s.get("note", ""),
                      s.get("note", "")[:160])
                d = until(lambda: (lambda x: x if x and x.get("kind") == "info" and
                                   x.get("entry") == "vm2" else None)(mod.view().get("dialog")), 20)
                check("auth: the user is told in a gateway dialog", bool(d),
                      (d or {}).get("title", ""))
                if d:
                    mod.post("/ui/dialog/answer", {"id": d["id"], "button": "ok"})
                pvt.set_key(pub_line)
                s = wait_state(j, ("running",), 60)
                check("auth: the key restored, the job is running again", s.get("state") == "running")
                a.ok("/agent/job/signal", {"id": j, "signal": "TERM"})
            # -- hostkey ----------------------------------------------------------
            if "hostkey" in only:
                j = a.ok("/agent/job/start", {"host": "vm2", "cwd": "/tmp", "command": "sleep 900"})["id"]
                wait_state(j, ("running",))
                old = vault.load()["hosts"]["vm2"]["host_keys"]
                pvt.stop()
                pvt.new_host_key()
                pvt.start()
                ssh.close_masters("vm2")
                ssh_conf.cache_clear("vm2")
                log0 = vm.ssh("grep -c 'Accepted publickey' ~/gw-remote/sshd/sshd.log").stdout.strip()
                d = until(lambda: (lambda x: x if x and x.get("what") == "host key" and
                                   x.get("entry") == "vm2" else None)(mod.view().get("dialog")), 40)
                check("hostkey: a regenerated host key opens the gateway's confirmation", bool(d),
                      (d or {}).get("title", ""))
                s = status(j)
                st2, e = a.call("/agent/job/start", {"host": "vm2", "cwd": "/tmp", "command": "true"})
                time.sleep(2)
                log1 = vm.ssh("grep -c 'Accepted publickey' ~/gw-remote/sshd/sshd.log").stdout.strip()
                check("hostkey: blocked until the user answers: nothing logs in, nothing starts",
                      s.get("state") == "disconnected" and st2 == 409 and log0 == log1,
                      f"{s.get('state')} {st2} logins {log0}->{log1}")
                if d:
                    mod.post("/ui/dialog/answer", {"id": d["id"], "button": "ok"})
                new = until(lambda: vault.load()["hosts"]["vm2"]["host_keys"] != old and
                            vault.load()["hosts"]["vm2"]["host_keys"], 20)
                s = wait_state(j, ("running",), 60)
                check("hostkey: trusted, pinned, the job is reached again",
                      bool(new) and s.get("state") == "running", s.get("state", ""))
                a.ok("/agent/job/signal", {"id": j, "signal": "TERM"})
            # -- wronghost --------------------------------------------------------
            if "wronghost" in only:
                cmd = 'uname -s; cat /etc/machine-id 2>/dev/null | cut -c1-6 || echo no-id; sleep 900'
                jv = a.ok("/agent/job/start", {"host": "vm", "cwd": "/tmp", "command": cmd})["id"]
                jm = a.ok("/agent/job/start", {"host": "mac", "cwd": "/tmp", "command": cmd})["id"]
                wait_state(jv, ("running",))
                wait_state(jm, ("running",), 120)
                tv = a.ok("/agent/job/tail", {"id": jv})["text"]
                tmac = a.ok("/agent/job/tail", {"id": jm})["text"]
                check("wronghost: the same command and path run on each host's own machine",
                      "Linux" in tv and "Darwin" in tmac and "Linux" not in tmac,
                      f"vm: {' '.join(tv.split())[:40]} / mac: {' '.join(tmac.split())[:40]}")
                n_mac = len(mac.commands())
                moved = form.replace('address = "tester@127.0.0.1:2222"', f'address = "{mac.addr()}"')
                se.write_form(moved)
                se.approve()
                ssh.close_masters("vm")
                ssh_conf.cache_clear("vm")
                d = until(lambda: (lambda x: x if x and x.get("what") == "host key" and
                                   x.get("entry") == "vm" else None)(mod.view().get("dialog")), 40)
                check("wronghost: vm's address moved to mac's sshd asks before anything runs",
                      bool(d), (d or {}).get("title", ""))
                if d:
                    mod.post("/ui/dialog/cancel", {"id": d["id"]})
                time.sleep(3)
                leaked = [c for c in mac.commands()[n_mac:] if jv in c]
                s = status(jv)
                check("wronghost: nothing of vm's reached mac; vm's job is disconnected, not ended",
                      not leaked and s.get("state") == "disconnected" and s.get("ended") is None,
                      f"{s.get('state')}: {s.get('note', '')[:100]}")
                se.write_form(form)
                se.approve()
                ssh_conf.cache_clear("vm")
                s = wait_state(jv, ("running",), 60)
                check("wronghost: vm's address back: its job is reached again on the VM",
                      s.get("state") == "running")
                for j in (jv, jm):
                    a.ok("/agent/job/signal", {"id": j, "signal": "TERM"})
            # -- prompt -----------------------------------------------------------
            if "prompt" in only and vm_tid:
                a.run(vm_tid, 'read -s -p "Password: " pw; echo; echo "GOT""LEN=${#pw} '
                              'sha=$(printf %s "$pw" | sha256sum | cut -c1-16)"', done=False)
                d = until(lambda: (lambda x: x if x and x.get("entry") == "terminal" and
                                   x.get("target") == vm_tid else None)(mod.view().get("dialog")), 30)
                check("prompt: a password prompt in a VM terminal opens the credential dialog",
                      bool(d) and any("on vm" in ln for ln in (d or {}).get("lines", [])))
                secret = f"rcv-{secrets.token_urlsafe(18)}"
                if d:
                    mod.post("/ui/dialog/submit", seal(d, [secret]))
                got = until(lambda: (lambda v: v if any(ln.startswith("GOTLEN=") for ln in v["lines"])
                                     else None)(a.read(vm_tid)), 30) or {"lines": []}
                line = next((ln for ln in got["lines"] if ln.startswith("GOTLEN=")), "")
                check("prompt: the value reached the remote program only",
                      line == f"GOTLEN={len(secret)} sha={sha16(secret)}", line[:40])
                procs = vm.ssh("ps -eo args").stdout
                logs = vm.ssh("cat ~/gw-remote/sshd/sshd.log 2>/dev/null; "
                              f"grep -rl -- '{secret[:12]}' ~/gw-remote 2>/dev/null | head -1").stdout
                blob = b""
                for d0 in (de.run, paths.gated_dir(), paths.data_dir() / "audit.jsonl"):
                    p0 = Path(d0)
                    for p in ([p0] if p0.is_file() else p0.rglob("*")):
                        if p.is_file() and not p.is_socket():
                            with contextlib.suppress(OSError):
                                blob += p.read_bytes()
                check("prompt: the canary is in no process argv, file or log on either side",
                      secret not in procs and secret not in logs and secret.encode() not in blob and
                      all(secret not in x for x in a.answers))
            # -- mac --------------------------------------------------------------
            if "mac" in only:
                st, v = a.call("/agent/term/open", {"host": "mac", "cwd": "/tmp"})
                plat = runtime_pack.platform_of(os.uname().sysname, os.uname().machine)
                mm = runtime_pack.load_manifest(plat or "")
                check(f"mac: a second platform ({plat}) staged with its real pixi-unpack and opened",
                      st == 200 and v.get("state") == "open" and mm is not None and
                      mm["pixi_pack"] != "test", f"{st} {json.dumps(v)[:120]}")
                if st == 200:
                    out = a.run(v["id"], 'echo "BA""SH=$BASH_VERSION P=$PATH"', "BASH=", timeout=30)
                    ln = next((x for x in out["lines"] if x.startswith("BASH=")), "")
                    check("mac: the runtime's bash 5 with the curated PATH",
                          ln.startswith("BASH=5.") and f"P={mac_base}/" in ln, ln[:160])
            snap = a.ok("/agent/term/list", {})
            check("summary: terminals and jobs listed", isinstance(snap.get("jobs"), list))
    finally:
        if bashrc_backup:
            vm.ssh("[ -f ~/gw-remote/bashrc.orig ] && cat ~/gw-remote/bashrc.orig > ~/.bashrc")
        if pvt is not None:
            pvt.close()
        # the run's own things in the VM: its key line, its runtime tmux servers, ~/gw-remote
        vm.ssh(f"grep -v '{MARK}' ~/.ssh/authorized_keys > ~/gw-remote-ak.new && "
               "cat ~/gw-remote-ak.new > ~/.ssh/authorized_keys; rm -f ~/gw-remote-ak.new; "
               "for s in ~/gw-remote/rt/*/tmux.sock ~/gw-remote/rt2/*/tmux.sock; do "
               "[ -S \"$s\" ] && env -i PATH=/usr/bin:/bin \"${s%/tmux.sock}/env/bin/tmux\" -S \"$s\" "
               "kill-server; done; " + ("" if args.keep else "rm -rf ~/gw-remote") + "; true")
        left = vm.ssh(f"grep -c '{MARK}' ~/.ssh/authorized_keys || true").stdout.strip()
        check("cleanup: the run's key is gone from the VM", left == "0", left)
        # the local host's runtime tmux (mac) and anything else naming the run's base
        for _ in range(2):
            ps = subprocess.run(["ps", "-ax", "-o", "pid=,command="], capture_output=True,
                                text=True).stdout
            for ln in ps.splitlines():
                pid, _, cmd = ln.strip().partition(" ")
                if pid.isdigit() and str(base) in cmd and int(pid) != os.getpid():
                    with contextlib.suppress(OSError):
                        os.kill(int(pid), signal.SIGTERM)
            time.sleep(0.5)
        shutil.rmtree(base, ignore_errors=True)
    passed = sum(1 for r in RESULTS if r["ok"])
    failed = [r for r in RESULTS if not r["ok"]]
    summary = {"passed": passed, "failed": len(failed), "seconds": round(time.time() - t0, 1),
               "results": RESULTS}
    (out_dir / "acceptance-remote.json").write_text(json.dumps(summary, indent=1))
    print(f"\n{passed} passed, {len(failed)} failed ({summary['seconds']} s)")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
