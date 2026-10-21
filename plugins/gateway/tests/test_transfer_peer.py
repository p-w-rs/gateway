"""transfer --from-peer: who may start it. The first non-shell ancestor must be
the system sshd's session child (root-owned binary, by executable path) whose
monitor runs as root. Real process trees: a renamed shell, a symlink named
sshd, and an sshd this user runs (the system binary when there is one) must
all fail; a scripted process table covers the real (root) sshd shapes."""
from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import harness as H
import harness_ux as U
from gateway import transfer

SRC = H.PLUGIN / "src"
PROBE = ("import sys; sys.path.insert(0, %r); from gateway import transfer; "
         "print('PEER', transfer.started_by_sshd())" % str(SRC))


def _probe_argv() -> list[str]:
    return [H.PY, "-I", "-S", *H.PYX, "-c", PROBE]


def _peer_result(out: str) -> str:
    for line in out.splitlines():
        if line.startswith("PEER "):
            return line.split()[1]
    return "missing: " + out[-300:]


def test_renamed_shells_and_symlinks_are_not_sshd():
    with H.gateway_env() as env:
        d = env.root / "fake"
        d.mkdir()
        # a copy of a shell named sshd (macOS kills copies of its own /bin
        # binaries, so prefer a shell from a package manager)
        fakes = ["sshd-session", "sshd-link"]
        for cand in ("/opt/local/bin/bash", "/opt/homebrew/bin/bash", "/usr/local/bin/bash", "/bin/bash",
                     "/usr/bin/bash", "/bin/dash", "/usr/bin/dash"):
            if not os.path.exists(cand):
                continue
            shutil.copyfile(cand, d / "sshd")
            os.chmod(d / "sshd", 0o755)
            if subprocess.run([str(d / "sshd"), "-c", "exit 0"], capture_output=True, timeout=30).returncode == 0:
                fakes.insert(0, "sshd")
                break
        else:
            print("  (no copyable shell here; the renamed-copy case is skipped)")
        (d / "sshd-session").symlink_to("/bin/sh")       # a symlink named sshd-session
        os.symlink("/bin/sh", d / "sshd-link")
        cmd = shlex.join(_probe_argv())
        for fake in fakes:
            r = subprocess.run([str(d / fake), "-c", cmd + "; true"], capture_output=True, text=True,
                               timeout=60, env={"PATH": "/usr/bin:/bin"})
            assert _peer_result(r.stdout) == "False", (fake, r.stdout, r.stderr)
        # plain shells, as Claude's Bash would run it
        r = subprocess.run(["/bin/sh", "-c", cmd + "; true"], capture_output=True, text=True, timeout=60)
        assert _peer_result(r.stdout) == "False", r.stdout


def test_an_sshd_this_user_runs_is_not_the_system_sshd():
    """The exact attack: start sshd as this user (the system binary if there
    is one: root-owned, so only the monitor's uid tells it apart) and run the
    import through it."""
    binaries = [b for b in ("/usr/sbin/sshd", str(H.ENV_BIN / "sshd")) if os.path.exists(b)]
    assert binaries, "no sshd binary to test with"
    tried = 0
    with H.gateway_env() as env:
        for i, b in enumerate(binaries):
            try:
                with U.user_sshd(env.root / f"sshd{i}", b) as sd:
                    r = subprocess.run(sd["ssh"] + [shlex.join(_probe_argv()) + "; true"],
                                       capture_output=True, text=True, timeout=60,
                                       stdin=subprocess.DEVNULL)
            except RuntimeError as e:          # this platform's sshd won't run unprivileged
                print(f"  (skipped {b}: {str(e)[:120]})")
                continue
            tried += 1
            assert _peer_result(r.stdout) == "False", (b, r.returncode, r.stdout, r.stderr)
    assert tried, "no user sshd could be started"


ROOT_BINS = {"/usr/libexec/sshd-session", "/usr/sbin/sshd", "/bin/zsh", "/bin/sh", "/bin/bash"}


def _table(rows: dict[int, tuple[int, str | None, int | None, str]]):
    def info(pid: int):
        return rows.get(pid, (0, None, None, ""))
    return info


def test_process_table_shapes():
    rootbin = lambda p: p in ROOT_BINS  # noqa: E731
    me = os.getuid() or 501
    real = {  # macOS 15 / OpenSSH >= 9.8: shell <- user child <- root monitor
        100: (90, "/bin/zsh", me, "zsh"),
        90: (80, "/usr/libexec/sshd-session", me, "sshd-session"),
        80: (1, "/usr/libexec/sshd-session", 0, "sshd-session"),
    }
    with U.patch(transfer, "_proc_info", _table(real)), U.patch(transfer, "_root_owned_binary", rootbin):
        assert transfer.sshd_ancestor(100) is True
        assert transfer.sshd_ancestor(90) is True
    linux = {  # Linux: the root monitor's exe can't be read; the user child is non-dumpable
        100: (90, "/bin/bash", me, "bash"),
        90: (80, None, me, "sshd"),
        80: (70, None, 0, "sshd"),
    }
    with U.patch(transfer, "_proc_info", _table(linux)), U.patch(transfer, "_root_owned_binary", rootbin):
        assert transfer.sshd_ancestor(100) is True
    cases = {
        "monitor runs as the user (an sshd the user started)": {
            100: (90, "/bin/zsh", me, "zsh"), 90: (80, "/usr/libexec/sshd-session", me, "sshd-session"),
            80: (70, "/usr/libexec/sshd-session", me, "sshd-session")},
        "user-owned sshd binary": {
            100: (90, "/bin/zsh", me, "zsh"), 90: (80, "/opt/x/bin/sshd", me, "sshd"),
            80: (1, "/usr/sbin/sshd", 0, "sshd")},
        "root parent that isn't sshd (sudo -u)": {
            100: (90, "/bin/zsh", me, "zsh"), 90: (80, "/usr/sbin/sshd", me, "sshd"),
            80: (1, "/usr/bin/sudo", 0, "sudo")},
        "first non-shell is something else": {
            100: (90, "/usr/bin/python3", me, "python3"), 90: (80, "/usr/sbin/sshd", me, "sshd"),
            80: (1, "/usr/sbin/sshd", 0, "sshd")},
        "unreadable process": {100: (0, None, None, "")},
        "comm says sshd but the exe is a shell copy": {
            100: (90, "/tmp/x/sshd", me, "sshd"), 90: (1, "/usr/sbin/sshd", 0, "sshd")},
    }
    for why, rows in cases.items():
        with U.patch(transfer, "_proc_info", _table(rows)), U.patch(transfer, "_root_owned_binary", rootbin):
            assert transfer.sshd_ancestor(100) is False, why


def test_root_owned_binary():
    assert transfer._root_owned_binary("/bin/sh") is True
    assert transfer._root_owned_binary(sys.executable) is False or os.getuid() == 0
    with H.gateway_env() as env:
        f = env.root / "sshd"
        f.write_text("#!/bin/sh\n")
        os.chmod(f, 0o755)
        assert transfer._root_owned_binary(str(f)) is False
