#!/usr/bin/env python3
"""A recording stand-in for one of the user's own tools (PLAN-0.11 §13: the
pass-through tests never run a real ssh, sudo, gh, ...).

    fake_user_tool.py TOOL [ARGS ...]

The harness writes one tiny sh script per tool name into a folder (the
`user_tools` test knob, honoured only under testing.override), each running
this file with its own name. Every run appends one JSON line to the folder's
`log.jsonl`: the tool, its argv (argv[0] as it was exec'd included), the
working directory and the few environment variables the tests look at
(GW_PASSTHRU, SSH_AUTH_SOCK, GH_TOKEN, HF_TOKEN, PATH). It prints
"fake TOOL ran" on stdout and exits with the folder's `exit` file's number
(0 when there is none).

`ssh -G ...` answers like OpenSSH's -G from the folder's `ssh_g.json` (or,
with `-F FILE`, from FILE, a table of the same shape: the user's own config):
{"DESTWORD": {"hostname": "...", "user": "...", "port": "22",
"proxyjump": "...", "proxycommand": "..."}}; a destination not listed gets
hostname = the word itself (user@ and :port taken off), port 22,
proxyjump none, proxycommand none. Never reads ~/.ssh/config.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# the folder of fakes (its wrapper scripts name it); never this file's folder
HERE = Path(os.environ.get("GW_FAKE_USER_DIR") or "/nonexistent-fake-user-tools")
ENV_KEYS = ("GW_PASSTHRU", "SSH_AUTH_SOCK", "GH_TOKEN", "HF_TOKEN", "PATH")
SSH_ARGOPTS = set("BDEFIJLOPQRSWbceilmopw")


def _dest(argv: list[str]) -> str | None:
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            return argv[i + 1] if i + 1 < len(argv) else None
        if not a.startswith("-") or a == "-":
            return a
        body = a[1:]
        for k, c in enumerate(body):
            if c in SSH_ARGOPTS:
                if k == len(body) - 1:
                    i += 1
                break
        i += 1
    return None


def _config(argv: list[str]) -> Path:
    """The table `ssh -G` answers from: a `-F FILE` given (the user's own
    config, as a JSON table of the same shape), else the folder's
    ssh_g.json."""
    for j, a in enumerate(argv):
        if a == "-F" and j + 1 < len(argv):
            return Path(argv[j + 1])
        if a.startswith("-F") and len(a) > 2:
            return Path(a[2:])
    return HERE / "ssh_g.json"


def _ssh_g(argv: list[str]) -> int:
    word = _dest([a for a in argv if a != "-G"]) or ""
    try:
        table = json.loads(_config(argv).read_text())
    except (OSError, ValueError):
        table = {}
    host = word.rsplit("@", 1)[-1]
    if host.startswith("ssh://"):
        host = host[6:]
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    row = {"hostname": host.strip("[]").lower(), "user": os.environ.get("USER", "u"),
           "port": "22", "proxyjump": "none", "proxycommand": "none"}
    row.update(table.get(word) or table.get(host) or {})
    for k in ("user", "hostname", "port", "proxyjump", "proxycommand"):
        print(f"{k} {row[k]}")
    return 0


def main() -> int:
    tool = sys.argv[1] if len(sys.argv) > 1 else "?"
    args = sys.argv[2:]
    rec = {"tool": tool, "argv0": os.environ.get("GW_FAKE_ARGV0", ""), "argv": args,
           "cwd": os.getcwd(), "env": {k: os.environ.get(k) for k in ENV_KEYS}}
    with open(HERE / "log.jsonl", "a", encoding="utf-8") as f:
        f.write(json.dumps(rec) + "\n")
    if tool == "ssh" and "-G" in args:
        return _ssh_g(args)
    print(f"fake {tool} ran")
    try:
        return int((HERE / "exit").read_text().strip() or 0)
    except (OSError, ValueError):
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
