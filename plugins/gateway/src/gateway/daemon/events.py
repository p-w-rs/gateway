"""The daemon's event log (CONTRACT-v1 events).

Every event has `seq` (strictly increasing within one daemon epoch), `epoch`
(the daemon's start counter, persisted in <data>/gated/epoch), `ts` and
`kind`, plus a few ids and enums. They live in a bounded ring in memory
(what /v1/events serves) and in a bounded JSONL file per epoch,
<data>/gated/events/epoch-<n>.jsonl (one older segment kept as .1; the files
of the last KEEP_EPOCHS epochs, this one included, are kept).

Nothing secret ever goes in: an event is built from an allowlist of keys per
kind, each value a bool, a number, None or a short string of safe characters
(ids, names the form validated, enums); anything else is dropped before the
event exists (clean()). Credential values, passphrases, vault data, command
lines and free text never fit.
"""
from __future__ import annotations

import collections
import json
import os
import re
import threading
import time
from pathlib import Path
from typing import Any

# kind -> the keys an event of that kind may carry (besides seq, epoch, ts, kind)
KINDS: dict[str, tuple[str, ...]] = {
    "daemon.started": ("version", "pid"),
    "daemon.stopping": ("reason",),
    # the plugin was uninstalled while terminals or jobs still ran: no new work,
    # the contract withdrawn, the daemon leaves once they have ended (lifecycle.drain)
    "daemon.draining": ("reason", "terminals", "jobs"),
    "session.registered": ("session", "via", "ui"),
    "session.ended": ("session",),
    "vault.unlocked": ("how",),
    "vault.locked": ("reason",),
    "vault.wrapped": (),
    "host.state": ("host", "name", "state", "reachable", "auth", "runtime", "identity"),
    "auth.waiting": ("request", "session", "dialog", "terminal"),
    "auth.supplied": ("request", "outcome"),
    "pause.applied": ("session", "paused", "task", "replayed"),
    # PLAN-v4 phase 7: an entry's effective rights changed (widened after the
    # person's OK, narrowed, removed), an account's adapter state, and a
    # refusal by the gateway's policy (what and where, never the command)
    "rights.changed": ("entry", "change"),
    "account.state": ("account", "state"),
    "policy.denied": ("host", "account", "workspace", "action", "entry"),
    # terminals and jobs (PLAN-v4 phase 5, daemon/terminals.py): ids, enums,
    # counts; never a command, a screen or input
    "job.started": ("job", "host", "session", "task", "agent"),
    "job.state": ("job", "state"),
    "job.exited": ("job", "exit", "signal", "state"),
    "job.output": ("job", "bytes"),
    "terminal.opened": ("terminal", "host", "session", "agent", "by"),
    "terminal.owner": ("terminal", "owner", "agent", "by"),
    "terminal.closed": ("terminal", "reason"),
}
SAFE = re.compile(r"[A-Za-z0-9_.:@/+-]{0,120}")
KEEP_EPOCHS = 5


def clean(kind: str, fields: dict[str, Any]) -> dict[str, Any] | None:
    """The event's allowed fields, each value checked; None for an unknown kind."""
    allowed = KINDS.get(kind)
    if allowed is None:
        return None
    out: dict[str, Any] = {}
    for k in allowed:
        if k not in fields:
            continue
        v = fields[k]
        if v is None or isinstance(v, bool) or (isinstance(v, (int, float)) and abs(v) < 1e15):
            out[k] = v
        elif isinstance(v, str) and SAFE.fullmatch(v):
            out[k] = v
    return out


class EventLog:
    def __init__(self, directory: Path, epoch: int, ring: int = 2000,
                 disk_max: int = 2_000_000):
        self.dir = directory
        self.epoch = epoch
        self.ring: collections.deque[dict[str, Any]] = collections.deque(maxlen=max(10, ring))
        self.disk_max = max(4096, disk_max)
        self.seq = 0
        self.cond = threading.Condition()
        self.closed = False
        self.path = directory / f"epoch-{epoch}.jsonl"
        try:
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
        except OSError:
            pass
        self._prune_epochs()

    def _prune_epochs(self) -> None:
        try:
            files = sorted(self.dir.glob("epoch-*.jsonl*"))
        except OSError:
            return
        def num(p: Path) -> int:
            m = re.match(r"epoch-(\d+)\.jsonl", p.name)
            return int(m.group(1)) if m else -1
        keep = sorted({num(p) for p in files if num(p) >= 0} - {self.epoch})[-(KEEP_EPOCHS - 1):]
        for p in files:
            if num(p) not in keep and num(p) != self.epoch:
                try:
                    p.unlink()
                except OSError:
                    pass

    def emit(self, kind: str, **fields: Any) -> dict[str, Any] | None:
        body = clean(kind, fields)
        if body is None:
            return None
        with self.cond:
            if self.closed:
                return None
            self.seq += 1
            ev = {"seq": self.seq, "epoch": self.epoch, "ts": round(time.time(), 3),
                  "kind": kind, **body}
            self.ring.append(ev)
            self._write(ev)
            self.cond.notify_all()
            return ev

    def _write(self, ev: dict[str, Any]) -> None:
        line = json.dumps(ev, sort_keys=True) + "\n"
        try:
            try:
                if self.path.stat().st_size + len(line) > self.disk_max:
                    os.replace(self.path, self.path.with_name(self.path.name + ".1"))
            except FileNotFoundError:
                pass
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.write(fd, line.encode("utf-8"))
            finally:
                os.close(fd)
        except OSError:
            pass                       # the ring still has it; disk is best effort

    def since(self, seq: int, wait: float = 0.0, epoch: int | None = None) -> dict[str, Any]:
        """Events after `seq`: {events, next, epoch, truncated, reset}. Waits
        up to `wait` seconds for one when there is none yet (long poll). A
        `seq` from another epoch (named, or past this epoch's last) starts
        over from the beginning of this one (`reset`): the consumer re-reads
        the snapshot."""
        deadline = time.monotonic() + max(0.0, wait)
        with self.cond:
            reset = (epoch is not None and epoch != self.epoch) or seq > self.seq
            if reset:
                seq = 0
            while self.seq <= seq and not self.closed:
                left = deadline - time.monotonic()
                if left <= 0:
                    break
                self.cond.wait(left)
            evs = [e for e in self.ring if e["seq"] > seq]
            first = self.ring[0]["seq"] if self.ring else self.seq + 1
            truncated = seq + 1 < first and self.seq > seq
            return {"events": evs, "next": self.seq, "epoch": self.epoch, "truncated": truncated,
                    "reset": reset}

    def close(self) -> None:
        with self.cond:
            self.closed = True
            self.cond.notify_all()


def next_epoch(path: Path) -> int:
    """Increment and return the persisted epoch counter (call under the
    daemon's single-instance lock)."""
    try:
        n = int(path.read_text().strip() or "0")
    except (OSError, ValueError):
        n = 0
    n += 1
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(f"{n}\n")
        os.replace(tmp, path)
    except OSError:
        pass
    return n
