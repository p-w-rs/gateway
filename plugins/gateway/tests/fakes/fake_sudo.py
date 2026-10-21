#!/usr/bin/env python3
"""A fake password sudo for tests (never root; runs the command as you).

    fake_sudo.py --state DIR [sudo options] [--] [CMD ...]

DIR/config.json: {"password": "...", "nopasswd": false, "timeout": 300,
                  "sudoers_dir": null}
DIR/log.jsonl: one line per invocation (argv, how the password came, result).

With "sudoers_dir", a file there (sudo's #includedir rules: no dot in the
name, not ending in ~) holding `USER ALL=(ALL) NOPASSWD: ALL` for the
calling user makes it passwordless, like a real sudoers.d rule. Real sudo's
no-tty rule is emulated too: without -S/-A, with SUDO_ASKPASS and DISPLAY set
and no terminal, the askpass is used (SPEC 9.3 relies on it for nested sudo).

Supports -A (SUDO_ASKPASS), -S (stdin, one line per attempt), -v, -n, -k, -K,
-u USER, -g GROUP, -p PROMPT, -H, -E, combined flags (-kv), and "Sorry, try
again." after a wrong password (3 attempts, like sudo). A cached timestamp
(DIR/timestamp) lasts `timeout` seconds; -k/-K remove it. NOPASSWD mode runs
everything without asking.
"""
from __future__ import annotations

import json
import os
import pwd
import re
import subprocess
import sys
import time
from pathlib import Path


def _sudoers_nopasswd(cfg: dict) -> bool:
    d = cfg.get("sudoers_dir")
    if not d or not os.path.isdir(d):
        return False
    me = pwd.getpwuid(os.getuid()).pw_name
    rule = re.compile(r"^\s*" + re.escape(me) + r"\s+ALL\s*=\s*\(ALL(?::ALL)?\)\s+NOPASSWD:\s*ALL\s*$")
    for name in sorted(os.listdir(d)):
        if "." in name or name.endswith("~"):
            continue
        try:
            text = Path(d, name).read_text()
        except OSError:
            continue
        if any(rule.match(line) for line in text.splitlines()):
            return True
    return False


def _no_tty() -> bool:
    try:
        os.close(os.open("/dev/tty", os.O_RDWR))
        return False
    except OSError:
        return True


def _read_tty(prompt: str) -> str | None:
    """Real sudo's way without -S/-A: the prompt and the password on the
    controlling terminal with echo off (a gateway terminal's pane: gated sees
    the prompt and answers it through its dialog). None without a terminal."""
    import termios
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError:
        return None
    try:
        old = termios.tcgetattr(fd)
        new = list(old)
        new[3] &= ~termios.ECHO
        new[3] |= termios.ICANON
        termios.tcsetattr(fd, termios.TCSAFLUSH, new)
        try:
            os.write(fd, prompt.encode())
            buf = b""
            while not buf.endswith(b"\n"):
                ch = os.read(fd, 1)
                if not ch:
                    break
                buf += ch
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, old)
            os.write(fd, b"\n")
        return buf.decode(errors="replace").rstrip("\r\n")
    except (OSError, termios.error):
        return None
    finally:
        os.close(fd)


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[0] != "--state":
        print("fake_sudo: --state DIR required", file=sys.stderr)
        return 1
    state = Path(argv[1])
    args = argv[2:]
    cfg = json.loads((state / "config.json").read_text())
    log = {"argv": args, "ppid": os.getppid(), "askpass": os.environ.get("SUDO_ASKPASS")}
    flags: set[str] = set()
    prompt = None
    user = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if not a.startswith("-") or a == "-":
            break
        if a in ("-u", "-g", "-p", "-C", "-h", "-U"):
            if i + 1 >= len(args):
                print(f"sudo: option requires an argument -- '{a[1]}'", file=sys.stderr)
                return 1
            if a == "-p":
                prompt = args[i + 1]
            if a == "-u":
                user = args[i + 1]
            i += 2
            continue
        if a.startswith("--"):
            flags.add(a)
            i += 1
            continue
        for ch in a[1:]:
            flags.add("-" + ch)
        i += 1
    cmd = args[i:]
    ts = state / "timestamp"

    def finish(code: int, **kw: object) -> int:
        log.update(kw)
        log["code"] = code
        with open(state / "log.jsonl", "a") as f:
            f.write(json.dumps(log) + "\n")
        return code

    if "-K" in flags:
        ts.unlink(missing_ok=True)
        return finish(0)
    if "-k" in flags:
        ts.unlink(missing_ok=True)
        if not cmd and "-v" not in flags:
            return finish(0)
    valid = ts.exists() and time.time() - ts.stat().st_mtime < float(cfg.get("timeout", 300))
    need = not cfg.get("nopasswd") and not valid and not _sudoers_nopasswd(cfg)
    if ("-S" not in flags and "-A" not in flags and os.environ.get("SUDO_ASKPASS")
            and os.environ.get("DISPLAY") and _no_tty()):
        flags.add("-A")                  # real sudo's own rule (no terminal, askpass + DISPLAY)
    if need and ("-v" in flags or cmd):
        if "-n" in flags:
            print("sudo: a password is required", file=sys.stderr)
            return finish(1, how="n")
        attempts = 0
        while attempts < 3:
            if "-S" in flags:
                if prompt != "":
                    sys.stderr.write(prompt if prompt is not None else "[sudo] password for you: ")
                    sys.stderr.flush()
                line = sys.stdin.buffer.readline()
                if not line:
                    print("sudo: no password was provided", file=sys.stderr)
                    return finish(1, how="S", attempts=attempts)
                pw = line.decode().rstrip("\n")
                how = "S"
            elif "-A" in flags:
                ap = os.environ.get("SUDO_ASKPASS")
                if not ap:
                    print("sudo: no askpass program specified, try setting SUDO_ASKPASS",
                          file=sys.stderr)
                    return finish(1, how="A")
                r = subprocess.run([ap, prompt or "[sudo] password: "], capture_output=True)
                if r.returncode != 0:
                    print("sudo: no password was provided", file=sys.stderr)
                    return finish(1, how="A", attempts=attempts)
                pw = r.stdout.decode().splitlines()[0] if r.stdout else ""
                how = "A"
            else:
                pw = _read_tty(prompt if prompt is not None else
                               f"[sudo] password for {pwd.getpwuid(os.getuid()).pw_name}: ")
                if pw is None:
                    print("sudo: a terminal is required to read the password; either use the -S "
                          "option to read from standard input or configure an askpass helper",
                          file=sys.stderr)
                    return finish(1, how="tty")
                how = "tty"
            if pw == cfg["password"]:
                if "-k" not in flags or not cmd:
                    ts.write_text("ok")   # real sudo: `-k CMD` never updates the timestamp
                log["how"] = how
                break
            print("Sorry, try again.", file=sys.stderr)
            attempts += 1
        else:
            print("sudo: 3 incorrect password attempts", file=sys.stderr)
            return finish(1, how=how, attempts=3)
    if not cmd:
        if "-v" in flags:
            return finish(0)
        print("usage: sudo -h | -K | -k | -V", file=sys.stderr)
        return finish(1)
    env = dict(os.environ)
    env.update({"SUDO_USER": os.environ.get("USER", "you"), "SUDO_UID": str(os.getuid()),
                "SUDO_COMMAND": " ".join(cmd)})
    if user:
        env["FAKE_SUDO_AS"] = user
    try:
        r = subprocess.run(cmd, env=env)
    except FileNotFoundError:
        print(f"sudo: {cmd[0]}: command not found", file=sys.stderr)
        return finish(1)
    return finish(r.returncode, ran=cmd)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
