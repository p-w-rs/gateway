"""UserPromptSubmit: paste guard, form-change context, pending pop-ups (SPEC 12, 6).

hooks/prompt.sh runs this only when the prompt matches a known token prefix
or a PEM private-key header, when the form is newer than this session's last
context, or when a pending pop-up request is newer than what this session was
shown. (prompt.sh itself clears the "cancelled" markers on every prompt: the
user has spoken again, so a cancelled pop-up may be asked again; and it writes
this session's record into private/sessions/ at the first prompt.)

(a) Paste guard: only known token prefixes (GitHub ghp_/gho_/ghu_/ghs_/ghr_/
    github_pat_, Hugging Face hf_, GitLab glpat-, OpenAI/Anthropic-style sk-,
    Slack xox?-, AWS AKIA, age AGE-SECRET-KEY-1) and PEM private key blocks.
    Git SHAs, base64 blobs, digests and UUIDs pass. A hit blocks the prompt
    (suppressOriginalPrompt) and scrubs the values from the transcript and
    the prompt history (same-length overwrite, every line that holds them, a
    first pass at once and a detached helper for a few seconds while Claude
    Code writes the blocked prompt), then tells the user BLOCK_REASON (`gateway:
    that looked like a secret, so it wasn't sent; Claude can open the gateway's
    dialog for it (gate check NAME), where it is typed privately`).
(b) Form changed since the session's last context (mtime and sha256):
    additionalContext with the new summary (hooks_session.context_text).
(c) Pending requests: a systemMessage with the fixed terminal command and
    its one-time code for no-screen requests (once per request per session).
(d) Task notifications (review round 4): Claude Code hands Claude a
    background task's notice as a prompt (when idle) or a queued attachment
    (mid-turn), and both pass this hook. Its "waiting for interactive input"
    notice quotes the raw last 1 KB of the task's output file, past every
    output hook. prompt.sh sends every prompt holding `<task-notification>` here
    once a vault exists (and any with a token shape); a notice holding a stored
    value in any form, or a token shape, is blocked (suppressOriginalPrompt),
    its matched forms are masked in the transcript and history (same-length,
    JSON-escaped forms too), and the user is told which entry it was (never the
    value). prompt.sh fails closed for these, as for the paste guard.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import signal
import sys
import time
from pathlib import Path
from typing import Any

from . import audit, paths, testing

# Same alternatives as hooks/prompt.sh's prefilter (kept in sync by a test).
TOKEN_PATTERNS = [
    r"gh[pousr]_[A-Za-z0-9]{30,}",
    r"github_pat_[A-Za-z0-9_]{30,}",
    r"hf_[A-Za-z0-9]{30,}",
    r"glpat-[A-Za-z0-9_-]{20,}",
    r"sk-[A-Za-z0-9_-]{20,}",
    r"xox[abprs]-[A-Za-z0-9-]{10,}",
    r"AKIA[0-9A-Z]{16}",
    r"AGE-SECRET-KEY-1[0-9A-Z]{50,}",
]
TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])(?:" + "|".join(TOKEN_PATTERNS) + r")")
PEM_RE = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|\Z)",
                    re.S)
BLOCK_REASON = ("gateway: that looked like a secret, so it wasn't sent; Claude can open the "
                "gateway's dialog for it (gate check NAME), where it is typed privately")
NOTICE_RE = re.compile(r"<\\?/?task-notification>")
NOTICE_REASON = ("gateway: a background command's notice quoted its raw output, which held a "
                 "stored secret or a token, so it wasn't passed to Claude (and it was masked in the "
                 "transcript)")
SCRUB_SECONDS = 10.0


def find_secrets(text: str) -> list[str]:
    """Values in a prompt that look like a credential (known prefixes, PEM keys)."""
    if not isinstance(text, str):
        return []
    out = [m.group(0) for m in TOKEN_RE.finditer(text)]
    for m in PEM_RE.finditer(text):
        block = m.group(0)
        out.append(block)
        # also each base64 line of the key, so a line-wrapped copy is scrubbed too
        out += [ln.strip() for ln in block.splitlines()[1:-1] if len(ln.strip()) >= 16]
    return list(dict.fromkeys(x for x in out if x))


# ---------------------------------------------------------------------------
# Transcript / history scrubbing (v2 common.scrub_file, without the gate: marker)
# ---------------------------------------------------------------------------


def _needles(value: str) -> list[bytes]:
    out = {value.encode("utf-8"),
           json.dumps(value)[1:-1].encode("utf-8"),
           json.dumps(value, ensure_ascii=False)[1:-1].encode("utf-8")}
    return sorted((n for n in out if n), key=len, reverse=True)


def scrub_file(path: Path, values: list[str]) -> int:
    """Overwrite every occurrence with '*' in place (same length, so the file
    stays valid while Claude Code keeps appending to it)."""
    try:
        data = path.read_bytes()
    except OSError:
        return 0
    needles = [n for v in values for n in _needles(v)]
    hits: list[tuple[int, int]] = []
    for n in needles:
        start = 0
        while (i := data.find(n, start)) != -1:
            hits.append((i, len(n)))
            start = i + len(n)
    if hits:
        try:
            with open(path, "r+b") as f:
                for off, ln in hits:
                    f.seek(off)
                    f.write(b"*" * ln)
        except OSError:
            return 0
    return len(hits)


def history_path() -> Path | None:
    o = testing.get("history_path")
    if o is not None:
        return Path(o)
    if testing.active() is not None:
        return None     # tests never touch a real history file
    base = os.environ.get("CLAUDE_CONFIG_DIR", "")
    if base and os.path.isabs(base):
        return Path(base) / "history.jsonl"
    return paths.user_home() / ".claude" / "history.jsonl"


def scrub_files(files: list[Path], values: list[str]) -> int:
    return sum(scrub_file(p, values) for p in files)


def _spawn_scrubber(files: list[Path], values: list[str]) -> None:
    """A first pass now, then a detached helper keeps scrubbing for a few
    seconds (Claude Code writes the blocked prompt around the time the hook
    returns). Values stay in memory (fork), never in argv or a file."""
    scrub_files(files, values)
    duration = float(testing.get("scrub_seconds", SCRUB_SECONDS))
    if duration <= 0:
        return
    try:
        sys.stdout.flush()
        pid = os.fork()
    except OSError:
        return
    if pid:
        with contextlib.suppress(ChildProcessError):
            os.waitpid(pid, 0)
        return
    try:
        os.setsid()
        if os.fork() > 0:
            os._exit(0)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        nul = os.open(os.devnull, os.O_RDWR)
        for fd in (0, 1, 2):
            os.dup2(nul, fd)
        end = time.time() + duration
        while time.time() < end:
            time.sleep(0.25)
            scrub_files(files, values)
    except BaseException:  # noqa: BLE001
        pass
    os._exit(0)


def block() -> dict[str, Any]:
    return {"decision": "block", "reason": BLOCK_REASON,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                   "suppressOriginalPrompt": True}}


def is_task_notice(text: str) -> bool:
    """A Claude Code task notification (a background task finished, or seems
    to wait for input), handed to Claude as a prompt or a queued attachment."""
    return isinstance(text, str) and NOTICE_RE.search(text) is not None


def notice_leaks(text: str) -> tuple[list[str], list[str]]:
    """(entry labels, matched values) for a task notification: every stored
    value in any form the scrubber masks (JSON-escaped included), and token
    shapes (the paste guard's and the scrubber's). Labels never hold a value."""
    from . import hooks_post, scrub
    labels: list[str] = []
    values: list[str] = []
    for name, what, _sec, forms in hooks_post.secret_matches(text):
        labels.append(f"{name}'s {what}")
        values += forms
    shaped = list(find_secrets(text))
    for rx in scrub.SHAPES:
        shaped += [m.group(0) for m in rx.finditer(text)]
    shaped += [text[m.end(1):m.end()] for m in scrub.AUTH_HEADER.finditer(text)]
    values += [v for v in shaped if len(v) >= scrub.MIN_LITERAL]
    return list(dict.fromkeys(labels)), list(dict.fromkeys(v for v in values if v))


def block_notice(labels: list[str]) -> dict[str, Any]:
    what = ("; ".join(labels[:4]) if labels else "something shaped like a token")
    msg = (f"gateway: a background command's notice held {what} (Claude Code quotes the raw end of "
           "a background command's output there, past the gateway's masking), so it was held back "
           "from Claude and masked in the transcript. Claude can still read that command's output "
           "file, masked, with its own tools.")
    return {"decision": "block", "reason": NOTICE_REASON, "systemMessage": msg,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                   "suppressOriginalPrompt": True}}


def _scrub_copies(payload: dict, values: list[str]) -> None:
    files: list[Path] = []
    tp = payload.get("transcript_path")
    if isinstance(tp, str) and os.path.isabs(tp):
        files.append(Path(tp))
    hp = history_path()
    if hp is not None:
        files.append(hp)
    try:
        _spawn_scrubber(files, values)
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# The hook
# ---------------------------------------------------------------------------


def _context_refresh(sid: str) -> str | None:
    from . import hooks_session, vault
    msgs: list[str] = []
    form, eff, data = hooks_session.prepare(msgs, write=False)
    if not form.exists:
        return None
    st = hooks_session.context_state(sid)
    if st is not None and st.get("form_sha256") == form.sha256:
        if st.get("form_mtime_ns") != form.mtime_ns:
            hooks_session.record_context(sid, form)   # touched, same content
        return None
    meta = vault.meta(data) if data else {}
    text = hooks_session.context_text(form, eff, meta)
    hooks_session.record_context(sid, form)
    head = ("Gateway update: gateway.toml changed; this replaces the earlier summary.\n"
            if st is not None else "")
    return head + text


def main(payload: dict) -> dict | None:
    """Block a pasted secret / add context when the form changed / show
    pending requests; None for payloads without a prompt (SPEC 12)."""
    if not isinstance(payload, dict) or not isinstance(payload.get("prompt"), str):
        return None
    prompt = payload["prompt"]
    sid = str(payload.get("session_id") or os.environ.get("CLAUDE_CODE_SESSION_ID") or "")
    notice = is_task_notice(prompt)
    if notice:
        labels, values = notice_leaks(prompt)
        if values:
            _scrub_copies(payload, values)
            audit.log("leak", where="task-notification", entries=labels,
                      shaped=not labels, session_id=sid or None)
            return block_notice(labels)
    found = [] if notice else find_secrets(prompt)
    if found:
        _scrub_copies(payload, found)
        audit.log("paste_guard", count=len(found), session_id=sid or None)
        return block()
    out: dict[str, Any] = {}
    from . import popup
    if not notice:
        popup.clear_cancelled()     # the user spoke again (a task notice isn't the user)
    if sid:
        try:
            ctx = _context_refresh(sid)
        except Exception:  # noqa: BLE001 - context is a convenience
            ctx = None
        if ctx:
            out["hookSpecificOutput"] = {"hookEventName": "UserPromptSubmit",
                                         "additionalContext": ctx}
        from . import hooks_post
        lines = hooks_post.pending_notice(sid, include_open=True)
        if lines:
            out["systemMessage"] = "\n".join(lines)
    return out or {"continue": True}
