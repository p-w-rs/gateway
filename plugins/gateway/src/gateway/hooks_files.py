"""PreToolUse file guard (Read|Grep|Glob|Edit|Write|MultiEdit|NotebookEdit) (SPEC 12).

- deny any path inside ~/.config/gateway/private, the v2 key.txt/store.age or
  the run dir, however it is spelled (paths.Protected: case variants on
  case-insensitive volumes, symlinks, hard links, `..`);
- deny a Grep whose search root (its `path`, else the session's cwd) is one of
  those locations or a folder above one (a recursive search from ~ or from the
  gateway home would read the key), and a Glob whose pattern can reach into one;
- deny reading Claude Code's session transcripts (any .jsonl at any depth
  under <config>/projects: <project>/<session>.jsonl and a subagent's
  <project>/<session>/subagents/agent-<id>.jsonl, which can hold the one-time
  codes the gateway shows the user) and a Grep from a folder holding them
  (a session folder or a Workflow run's folder too); tool-results/ stays
  readable, and so does a Workflow run's journal
  (<project>/<session>/subagents/workflows/<run>/journal.jsonl: agent results,
  which Claude Code's Workflow tool tells Claude to read; paths.is_transcript);
- the desktop app's session tools (review round 4), which read and export
  transcripts with no file path to judge: deny
  mcp__ccd_session_mgmt__export_transcript always (it writes a zip of raw
  transcripts, beyond any masking hook), and search_session_transcripts /
  list_events while a one-time code the gateway showed the user is still
  live (PostToolUse masks stored values and codes in what they return);
- before an Edit/Write/MultiEdit of gateway.toml, persist any narrowing the
  current form shows (consent.ratchet), so a right lowered by one edit can't
  be raised again by the next without the user's OK.

No decision otherwise. run.py runs this with "fail closed" (exit 2).
"""
from __future__ import annotations

import fnmatch
import os
import re
from pathlib import Path
from typing import Any

from . import paths

DENY_INSIDE = ("gateway: that path holds the gateway's private keys and vault; Claude never "
               "needs it (gate status shows what is stored).")
DENY_PARENT = ("gateway: that search would also read the gateway's private keys and vault "
               "(under ~/.config/gateway); search a narrower folder, such as the project, instead.")
DENY_GLOB = ("gateway: that pattern would list the gateway's private files (under "
             "~/.config/gateway); use a narrower folder or pattern.")
DENY_TRANSCRIPT = ("gateway: that is a Claude Code session transcript; it can hold output Claude "
                   "Code showed unmasked (a failed command's, a background command's notice), so "
                   "Claude doesn't read it (the tool-results folder next to it, and a Workflow "
                   "run's journal.jsonl, are fine).")
DENY_TRANSCRIPT_SEARCH = ("gateway: that search would read Claude Code's session transcripts "
                          "(they can hold output Claude Code showed unmasked); search a narrower "
                          "folder, or a Workflow run's journal.jsonl itself, instead.")
DENY_EXPORT = ("gateway: exporting a session transcript is off while the gateway is installed: "
               "transcripts can hold output Claude Code shows unmasked (a failed command's, a "
               "background command's notice), and the exported file is beyond the gateway's "
               "masking. If the user wants an export, they can make it themselves.")
SESSION_EXPORT = "mcp__ccd_session_mgmt__export_transcript"
FORM_EDITS = ("Edit", "Write", "MultiEdit")
_WILD = re.compile(r"[*?\[{]")


def _deny(reason: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def _fold(s: str) -> str:
    return paths._fold(s)


def _braces(pat: str) -> list[str]:
    """Expand {a,b} alternatives (no nesting) for matching."""
    m = re.search(r"\{([^{}]*)\}", pat)
    if not m:
        return [pat]
    out: list[str] = []
    for alt in m.group(1).split(",")[:32]:
        out += _braces(pat[:m.start()] + alt + pat[m.end():])
    return out[:256]


def _glob_match(pattern: list[str], rel: list[str]) -> bool:
    """Does a glob (components, `**` = any depth) match the path components `rel`?"""
    if not pattern:
        return not rel
    head = pattern[0]
    if head == "**":
        return _glob_match(pattern[1:], rel) or (bool(rel) and _glob_match(pattern, rel[1:]))
    if not rel:
        return False
    if not any(fnmatch.fnmatchcase(rel[0], h) for h in _braces(head)):
        return False
    return _glob_match(pattern[1:], rel[1:])


def _glob_hits(prot: paths.Protected, base: str, pattern: str, cwd: str | None) -> bool:
    """A Glob is refused when its folder is protected, or when its pattern
    matches a file that exists in a protected location (folder names alone,
    such as `private` from ~/.config/gateway/*, are only names)."""
    full = pattern if os.path.isabs(pattern) or pattern.startswith("~") else (
        os.path.join(base, pattern) if base else pattern)
    m = _WILD.search(full)
    literal = full[:m.start()] if m else full
    lit_dir = literal if (literal.endswith("/") or not m) else os.path.dirname(literal)
    if prot.contains(lit_dir or "/", cwd):
        return True
    if not m:
        return prot.contains(full, cwd)
    rest = full[len(lit_dir):].lstrip("/")
    parts = [_fold(x) for x in rest.split("/") if x]
    for cand in prot.candidates(lit_dir or "/", cwd):
        root = _fold(str(paths._resolved(cand))).rstrip("/")
        for q in prot.entries:
            if q.startswith(root + "/"):
                rel = [x for x in q[len(root):].split("/") if x]
                if _glob_match(parts, rel):
                    return True
    return False


def _ratchet_before_form_edit(prot_path: str, cwd: str | None) -> None:
    """An Edit/Write of gateway.toml: persist narrowings of the current form
    first (best effort; never blocks the edit)."""
    try:
        target = Path(paths.Protected.candidates(prot_path, cwd)[0])
        if paths._fold(paths._resolved(target)) != paths._fold(paths._resolved(paths.form_path())):
            return
        from . import consent
        consent.ratchet()
    except Exception:  # noqa: BLE001 - a failed ratchet must not block the edit
        pass


def main(payload: dict) -> dict | None:
    """Hook output (deny) or None (SPEC 12)."""
    tool = payload.get("tool_name") or ""
    if tool == SESSION_EXPORT:
        return _deny(DENY_EXPORT)
    ti = payload.get("tool_input") or {}
    if not isinstance(ti, dict):
        return None
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
    prot = paths.Protected()
    files = [ti.get(k) for k in ("file_path", "notebook_path") if isinstance(ti.get(k), str)]
    for c in files:
        if c and prot.contains(c, cwd):
            return _deny(DENY_INSIDE)
    path = ti.get("path") if isinstance(ti.get("path"), str) and ti.get("path") else None
    if path and prot.contains(path, cwd):
        return _deny(DENY_INSIDE)
    if tool == "Grep":
        root = path or cwd
        if root and prot.is_parent(root, cwd):
            return _deny(DENY_PARENT)
    if tool == "Glob" and isinstance(ti.get("pattern"), str):
        if _glob_hits(prot, path or cwd or "", ti["pattern"], cwd):
            return _deny(DENY_GLOB)
    # Session transcripts (contents only: a Glob listing their names is fine).
    roots = paths.transcript_roots(payload.get("transcript_path"))
    for c in [*files, path]:
        if c and paths.is_transcript(c, cwd, roots):
            return _deny(DENY_TRANSCRIPT)
    if tool == "Grep":
        root = path or cwd
        if root and paths.holds_transcripts(root, cwd, roots):
            return _deny(DENY_TRANSCRIPT_SEARCH)
    if tool in FORM_EDITS and files:
        _ratchet_before_form_edit(files[0], cwd)
    return None
