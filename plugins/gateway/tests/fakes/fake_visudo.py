#!/usr/bin/env python3
"""A fake visudo for tests (checks syntax only; never touches /etc).

    fake_visudo.py --state DIR -cf FILE     check one sudoers fragment
    fake_visudo.py --state DIR -c           check every file in DIR/config.json's
                                            "sudoers_dir" (like visudo -c on the
                                            whole configuration)

Accepted lines: blank, comments, `Defaults...`, and user specifications of the
form `USER ALL=(ALL) NOPASSWD: ALL` (also `(ALL:ALL)`). Anything else is a
"syntax error" (exit 1), the way visudo refuses a broken file. A fragment that
isn't mode 0440 is refused too ("bad permissions"), like visudo -c does for
files with wrong modes. DIR/config.json may set "fail": true to refuse every
check. DIR/log.jsonl gets one line per call.
"""
from __future__ import annotations

import json
import re
import stat
import sys
from pathlib import Path

SPEC = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*\s+ALL\s*=\s*\(ALL(?::ALL)?\)\s+NOPASSWD:\s*ALL$")


def check(path: Path, cfg: dict) -> str | None:
    try:
        text = path.read_text()
    except OSError as e:
        return f"visudo: unable to open {path}: {e.strerror}"
    if cfg.get("fail"):
        return f"visudo: {path}: syntax error near line 1"
    if stat.S_IMODE(path.stat().st_mode) != 0o440:
        return f"visudo: {path}: bad permissions, should be mode 0440"
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not s or s.startswith("#") or s.startswith("Defaults"):
            continue
        if not SPEC.match(s):
            return f"visudo: {path}: syntax error near line {n}"
    return None


def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[0] != "--state":
        print("fake_visudo: --state DIR required", file=sys.stderr)
        return 1
    state = Path(argv[1])
    args = argv[2:]
    cfg = json.loads((state / "config.json").read_text())
    with open(state / "log.jsonl", "a") as f:
        f.write(json.dumps({"argv": args, "euid_ok": True}) + "\n")
    if args[:1] == ["-cf"] and len(args) == 2:
        err = check(Path(args[1]), cfg)
    elif args[:2] == ["-c", "-f"] and len(args) == 3:
        err = check(Path(args[2]), cfg)
    elif args == ["-c"]:
        err = None
        d = Path(cfg.get("sudoers_dir") or "/nonexistent")
        for p in sorted(d.iterdir()) if d.is_dir() else []:
            if "." in p.name or p.name.endswith("~") or not p.is_file():
                continue            # sudo's #includedir skips these
            err = err or check(p, cfg)
    else:
        print("usage: visudo -c [-f sudoers]", file=sys.stderr)
        return 1
    if err:
        print(err, file=sys.stderr)
        return 1
    print("parsed OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
