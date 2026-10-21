"""Fixtures for the remote runtime tests (PLAN-v4 phase 6). Pure stdlib.

- remote_env(): an ssh test env (harness_ssh: real sshds on 127.0.0.1, short
  run dir) with a real gated attached (harness_daemon.attach) whose knobs
  point at FAKE runtime artifacts: a small runtime.tar and a stand-in
  pixi-unpack (a POSIX sh script that "unpacks" by linking the gateway env's
  own bash and tmux into <out>/env/bin), so staging, sha256 checks,
  unpacking, the readiness probe and the runtime's tmux all run for real over
  ssh, with no pixi-pack and no network. The runtime base is a SHORT folder
  under /tmp (tmux's socket path must stay under 104 bytes); its tmux servers
  and anything naming it are killed in cleanup.
- RemoteEnv.add_host(name, sshd, ...): the form entry (address, runtime
  path, rights), the vault's key and pinned host key, approved.
- local_platform(): this machine's runtime platform (the harness sshds run
  here, so the "remote" platform is this one).

Remote commands run as this user with its real HOME (the harness sshd's own
behaviour): the tests give every terminal and job an explicit cwd under the
test's folders and a runtime base under /tmp, so nothing is written to the
real home.
"""
from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path
from typing import Any, Iterator

import harness as H
import harness_daemon as D
import harness_ssh as S

ENV_BIN = Path(H.PY).parent


def local_platform() -> str:
    from gateway import runtime_pack
    u = os.uname()
    p = runtime_pack.platform_of(u.sysname, u.machine)
    assert p is not None, u
    return p


FAKE_UNPACK = """#!/bin/sh
# a stand-in for pixi-unpack in the remote runtime tests (never a real one)
case "$1" in --version) echo "pixi-unpack 0.0.0-test"; exit 0 ;; esac
pack=$1; shift; out=; env=env
while [ $# -gt 0 ]; do
  case $1 in -o) out=$2; shift 2 ;; -e) env=$2; shift 2 ;; *) shift ;; esac
done
[ -f "$pack" ] && [ -n "$out" ] || {{ echo "pixi-unpack (test): no pack or no -o" >&2; exit 2; }}
mkdir -p "$out/$env/bin" || exit 3
ln -sf {bash} "$out/$env/bin/bash" && ln -sf {tmux} "$out/$env/bin/tmux" && : > "$out/activate.sh"
"""
NOEXEC = ('echo "$0: Permission denied" >&2; exit 126' + "\n")


def fake_artifacts(base: Path, platform: str, *, noexec: bool = False) -> Path:
    """<base>/<platform>/{runtime.tar, unpacker/bin/pixi-unpack, unpacker/lib/libtest.so.1}."""
    d = base / platform
    (d / "unpacker" / "bin").mkdir(parents=True, exist_ok=True)
    (d / "unpacker" / "lib").mkdir(parents=True, exist_ok=True)
    src = base / "tar-src"
    src.mkdir(exist_ok=True)
    (src / "info.txt").write_text("gateway remote runtime (test pack)\n")
    with tarfile.open(d / "runtime.tar", "w") as t:
        t.add(src / "info.txt", arcname="info.txt")
    unpack = d / "unpacker" / "bin" / "pixi-unpack"
    if noexec:
        # what a shell says when the file system doesn't let the file run
        text = "#!/bin/sh\n" + NOEXEC
    else:
        text = FAKE_UNPACK.format(bash=S.sq(ENV_BIN / "bash"), tmux=S.sq(ENV_BIN / "tmux"))
    unpack.write_text(text)
    os.chmod(unpack, 0o755)
    (d / "unpacker" / "lib" / "libtest.so.1").write_bytes(os.urandom(4096))
    return base


class RemoteEnv:
    def __init__(self, se: S.SshEnv, de: D.DaemonEnv, base: Path, art: Path):
        self.se, self.de, self.base, self.art = se, de, base, art
        self.root = se.root
        self.hosts: dict[str, dict[str, Any]] = {}
        self.form_text = ""

    def add_host(self, name: str, sshd: S.Sshd, *, ssh: Any = True, sudo: Any = True,
                 runtime: str | None = None, extra: str = "") -> Path:
        """A form host on `sshd` with its own runtime base (default
        <base>/<name>); the key authorized there, the host key pinned,
        everything approved. Returns the runtime base."""
        rt = Path(runtime) if runtime else self.base / name
        def word(v: Any) -> str:
            return "true" if v is True else "false" if v is False else f'"{v}"'
        self.form_text += (f'[hosts.{name}]\naddress = "{sshd.addr()}"\nssh = {word(ssh)}\n'
                           f'sudo = {word(sudo)}\nruntime = "{rt}"\n{extra}\n')
        self.se.write_form(self.form_text)
        self.se.host(name, sshd)
        self.se.approve()
        self.hosts[name] = {"sshd": sshd, "base": rt}
        return rt

    def rewrite_form(self, text: str, approve: bool = True) -> None:
        self.form_text = text
        self.se.write_form(text)
        if approve:
            self.se.approve()

    def rt_dir(self, name: str) -> Path:
        from gateway import runtime_pack
        return Path(self.hosts[name]["base"]) / f"{runtime_pack.version()}-{local_platform()}"

    def tmux(self, name: str, *args: str) -> subprocess.CompletedProcess:
        """The host runtime's tmux, asked directly (as something on the host would)."""
        rt = self.rt_dir(name)
        return subprocess.run([str(ENV_BIN / "tmux"), "-S", str(rt / "tmux.sock"), *args],
                              capture_output=True, text=True, timeout=10,
                              env={"PATH": "/usr/bin:/bin", "HOME": str(self.se.env.o.user_home)})

    def knobs(self, **k: Any) -> None:
        self.de.knobs(**k)

    def leftovers(self) -> list[tuple[int, str]]:
        out = subprocess.run(["ps", "-ax", "-o", "pid=,command="], capture_output=True,
                             text=True).stdout
        res = []
        for line in out.splitlines():
            pid, _, cmd = line.strip().partition(" ")
            if pid.isdigit() and int(pid) != os.getpid() and str(self.base) in cmd \
                    and "ps -ax" not in cmd:
                res.append((int(pid), cmd))
        return res

    def cleanup(self) -> None:
        for pid, _cmd in self.leftovers():
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGTERM)
        deadline = time.time() + 3
        while self.leftovers() and time.time() < deadline:
            time.sleep(0.05)
        for pid, _cmd in self.leftovers():
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGKILL)


@contextlib.contextmanager
def remote_env(knobs: dict[str, Any] | None = None, noexec: bool = False) -> Iterator[RemoteEnv]:
    base = Path(tempfile.mkdtemp(prefix="gwr-", dir="/tmp"))
    os.chmod(base, 0o700)
    art = fake_artifacts(Path(tempfile.mkdtemp(prefix="gwa-", dir=str(H.tmp_base()))),
                         local_platform(), noexec=noexec)
    try:
        with S.ssh_env() as se:
            k = {"runtime_artifacts": str(art), "remote_tick": 0.2, **(knobs or {})}
            with D.attach(se.env, se.run_dir, knobs=k) as de:
                re_ = RemoteEnv(se, de, base, art)
                try:
                    yield re_
                finally:
                    re_.cleanup()
    finally:
        shutil.rmtree(base, ignore_errors=True)
        shutil.rmtree(art, ignore_errors=True)


def events(de: D.DaemonEnv, fc: D.FakeClaude, kinds: tuple[str, ...]) -> list[dict[str, Any]]:
    probe = D.probe_root(de.root)
    r = fc.run([D.PY, "-I", "-S", str(probe / "run.py")],
               env={**{k: v for k, v in D.py_env().items() if k != "PYTHONHOME"},
                    "GW_PROBE_SOCK": str(de.sock), "GW_PROBE_PATH": "/v1/events?since=0&wait=0",
                    "GW_PROBE_METHOD": "GET"})
    body = json.loads(r.stdout)["body"]
    return [e for e in body["events"] if e["kind"] in kinds]
