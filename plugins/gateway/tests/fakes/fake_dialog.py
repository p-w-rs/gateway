#!/usr/bin/env python3
"""A scripted dialog backend for tests (popup.py's fake, via testing.override(dialog=...)).

    fake_dialog.py QUEUE LOG KIND TITLE MESSAGE [DEFAULT]

QUEUE is a JSON list of answers consumed in order, each
    {"outcome": "ok" | "cancelled" | "unavailable" | "timeout", "value": "...", "sleep": 0,
     "write": [PATH, TEXT]}
("write": the file is written before the answer: the person, or Claude, changing
the form while the dialog is open.)
ok prints value and exits 0; cancelled exits 1 (zenity's Cancel);
unavailable exits 3 (any other non-zero = no screen); timeout sleeps `sleep`
seconds (default 5) and exits 1. An empty queue counts as cancelled.
Every call is appended to LOG as JSON (kind, title, message, default, outcome).
"""
from __future__ import annotations

import fcntl
import json
import sys
import time


def main(argv: list[str]) -> int:
    queue, log = argv[0], argv[1]
    kind, title, message = (argv[2:5] + ["", "", ""])[:3]
    default = argv[5] if len(argv) > 5 else ""
    with open(queue, "r+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        items = json.loads(f.read() or "[]")
        ans = items.pop(0) if items else {"outcome": "cancelled"}
        f.seek(0)
        f.truncate()
        f.write(json.dumps(items))
    with open(log, "a") as f:
        f.write(json.dumps({"kind": kind, "title": title, "message": message,
                            "default": default, "outcome": ans.get("outcome")}) + "\n")
    w = ans.get("write")
    if isinstance(w, list) and len(w) == 2:
        with open(w[0], "w") as f:
            f.write(w[1])
    out = ans.get("outcome", "cancelled")
    if out == "ok":
        sys.stdout.write(str(ans.get("value", "")) + "\n")
        return 0
    if out == "unavailable":
        return 3
    if out == "timeout":
        time.sleep(float(ans.get("sleep", 5)))
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
