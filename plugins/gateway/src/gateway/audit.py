"""The audit log: $CLAUDE_PLUGIN_DATA/audit.jsonl (SPEC 17).

One JSON line per credential use, pop-up outcome, consent, widening, refusal,
export/import/copy and migration. Values are redacted: through
scrub.scrub_text when phase B's scrubber is available, else by replacing the
literal secrets the caller passes plus a few well-known token shapes.

Refusals are also kept per session in the run dir so `gate why` can explain
the last one with its fix.
"""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path
from typing import Any, Iterable

from . import paths

MAX_BYTES = 5_000_000
# Literal values shorter than this are not scrubbed (SPEC 11): replacing a
# short password wherever it occurs would reveal it. The gateway never puts
# such values into output it controls.
MIN_LITERAL = 8
_SHAPES = [
    re.compile(r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{10,}"),
    re.compile(r"\bhf_[A-Za-z0-9]{10,}"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{10,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
    re.compile(r"AGE-SECRET-KEY-1[0-9A-Z]+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
    re.compile(r"(?i)\b(authorization:\s*(?:bearer|basic|token)\s+)\S+"),
]


def _fallback_scrub(text: str, secrets: Iterable[str]) -> str:
    for s in sorted({x for x in secrets if x and len(x) >= MIN_LITERAL}, key=len, reverse=True):
        text = text.replace(s, "***")
    for rx in _SHAPES:
        text = rx.sub(lambda m: (m.group(1) if m.groups() and m.group(1) else "") + "***", text)
    return text


def redact_text(text: str, secrets: Iterable[str] = ()) -> str:
    secrets = list(secrets)
    try:
        from . import scrub
        return scrub.scrub_text(_fallback_scrub(text, secrets), extra=secrets)
    except NotImplementedError:
        return _fallback_scrub(text, secrets)
    except Exception:  # noqa: BLE001 - never fail to log because of the scrubber
        return _fallback_scrub(text, secrets)


def _redact(obj: Any, secrets: list[str]) -> Any:
    if isinstance(obj, str):
        return redact_text(obj, secrets)
    if isinstance(obj, dict):
        return {str(k): _redact(v, secrets) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_redact(v, secrets) for v in obj]
    return obj


def log(event: str, *, secrets: Iterable[str] = (), **detail: Any) -> None:
    """Append one record. Never raises."""
    try:
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event,
               "session": os.environ.get("CLAUDE_CODE_SESSION_ID") or None,
               "cwd": os.getcwd() if os.path.isdir(os.getcwd()) else None}
        rec.update(detail)
        rec = _redact(rec, list(secrets))
        p = paths.audit_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        try:
            if p.stat().st_size > MAX_BYTES:
                os.replace(p, p.with_name(p.name + ".1"))
        except FileNotFoundError:
            pass
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode("utf-8"))
        finally:
            os.close(fd)
    except Exception:  # noqa: BLE001
        pass


def use(tool: str, target: str, account: str | None, argv: list[str] | None = None,
        secrets: Iterable[str] = (), **extra: Any) -> None:
    """A credential use by a stand-in (one line per use)."""
    summary = " ".join(argv[:12])[:300] if argv else None
    log("use", secrets=secrets, tool=tool, target=target, account=account, argv=summary, **extra)


def refusal(tool: str, target: str | None, reason: str, fix: str | None = None,
            secrets: Iterable[str] = ()) -> None:
    """A refusal: audited, and remembered for `gate why` (per session)."""
    log("refusal", secrets=secrets, tool=tool, target=target, reason=reason, fix=fix)
    try:
        sid = os.environ.get("CLAUDE_CODE_SESSION_ID") or "nosession"
        sid = re.sub(r"[^A-Za-z0-9_-]", "_", sid)[:80]
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "tool": tool, "target": target,
               "reason": redact_text(reason, secrets),
               "fix": redact_text(fix, secrets) if fix else None}
        p = paths.refusals_dir() / f"{sid}.json"
        tmp = p.with_name(p.name + f".{os.getpid()}")
        tmp.write_text(json.dumps(rec))
        os.replace(tmp, p)
    except Exception:  # noqa: BLE001
        pass


def last_refusal(session_id: str | None = None) -> dict[str, Any] | None:
    """The last refusal of this session (session_id, else CLAUDE_CODE_SESSION_ID):
    the run dir's copy, else the audit log's last refusal recorded with the
    same session id (no session id: only refusals recorded without one)."""
    raw = session_id if session_id is not None else (os.environ.get("CLAUDE_CODE_SESSION_ID") or None)
    sid = re.sub(r"[^A-Za-z0-9_-]", "_", raw or "nosession")[:80]
    try:
        p = paths.refusals_dir() / f"{sid}.json"
        return json.loads(p.read_text())
    except (OSError, ValueError, paths.PathError):
        pass
    for rec in reversed(read(500)):
        if rec.get("event") == "refusal" and rec.get("session") == raw:
            return rec
    return None


def newest_refusal() -> dict[str, Any] | None:
    """The newest refusal in the audit log, of any session (for `gate why` in
    the user's own terminal, which has no session id)."""
    for rec in reversed(read(500)):
        if rec.get("event") == "refusal":
            return rec
    return None


def read(n: int = 40, path: Path | None = None) -> list[dict[str, Any]]:
    p = path or paths.audit_path()
    try:
        with open(p, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - 400 * max(n, 1) - 65536))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []
    out = []
    for line in lines[-n:] if n > 0 else lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out[-n:] if n > 0 else out


def render(entries: list[dict[str, Any]]) -> str:
    if not entries:
        return "gateway: the audit log is empty"
    rows = []
    for e in entries:
        bits = [e.get("ts", "?"), e.get("event", "?")]
        for k in ("tool", "target", "account", "outcome", "entry", "what"):
            if e.get(k):
                bits.append(f"{k}={e[k]}")
        for k in ("argv", "reason", "detail"):
            if e.get(k):
                v = e[k] if isinstance(e[k], str) else json.dumps(e[k])
                bits.append(f"{k}: {v[:160]}")
        rows.append("  ".join(str(b) for b in bits))
    return "\n".join(rows)
