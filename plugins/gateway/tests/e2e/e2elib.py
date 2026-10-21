"""Helpers for the headless e2e suite (tests/e2e/run_e2e.py). Stdlib only.

- Session / parse_stream(): a `claude -p --output-format stream-json
  --verbose --include-hook-events` transcript turned into tool calls (input,
  result text, error flag, denied flag, the PreToolUse hook decisions seen for
  it) and hook events.
- secret_forms(): the spellings of a planted fake secret to grep for (the
  value, its base64 forms, base64 of `user:value`, URL-encoded).
- Checks: a list of named assertions with details, printed as a table and
  saved as JSON.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# stream-json
# ---------------------------------------------------------------------------


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict[str, Any]
    result: str = ""
    is_error: bool = False
    denied: bool = False
    parent: str | None = None          # parent_tool_use_id (a subagent's call)
    hook_outputs: list[str] = field(default_factory=list)

    @property
    def command(self) -> str:
        return str(self.input.get("command", ""))


@dataclass
class Session:
    name: str
    sid: str
    mode: str
    rc: int | None
    timed_out: bool
    seconds: float
    events: list[dict[str, Any]]
    stream_path: Path
    debug_path: Path
    stderr_path: Path
    calls: list[ToolCall] = field(default_factory=list)
    hooks: list[dict[str, Any]] = field(default_factory=list)
    init: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] = field(default_factory=dict)
    # every result event: a session with background events (a Monitor) can
    # finish more than one turn, each with its own permission_denials
    results: list[dict[str, Any]] = field(default_factory=list)
    limit: float = 90.0                # the session's time limit (s)

    # -- lookups ----------------------------------------------------------
    def find(self, needle: str, tool: str = "Bash") -> ToolCall | None:
        """The first call of `tool` whose command (or JSON input) contains needle."""
        for c in self.calls:
            if c.name != tool:
                continue
            hay = c.command if tool == "Bash" else json.dumps(c.input)
            if needle in hay:
                return c
        return None

    def hook_events(self, event: str) -> list[dict[str, Any]]:
        return [h for h in self.hooks if str(h.get("hook_event") or h.get("hook_name") or
                                             "").startswith(event)]

    def hook_text(self, event: str) -> str:
        out = []
        for h in self.hook_events(event):
            for k in ("output", "stdout", "stderr"):
                v = h.get(k)
                if isinstance(v, str):
                    out.append(v)
        return "\n".join(out)

    @property
    def denials(self) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for r in self.results or [self.result]:
            out += [d for d in (r.get("permission_denials") or []) if d not in out]
        return out

    @property
    def debug(self) -> str:
        try:
            return self.debug_path.read_text(errors="replace")
        except OSError:
            return ""


def _text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for c in content:
            if isinstance(c, dict):
                if c.get("type") == "text":
                    parts.append(str(c.get("text", "")))
                elif "content" in c:
                    parts.append(_text(c["content"]))
                else:
                    parts.append(json.dumps(c))
            else:
                parts.append(str(c))
        return "\n".join(parts)
    if content is None:
        return ""
    return json.dumps(content)


def load_events(path: Path) -> list[dict[str, Any]]:
    out = []
    try:
        lines = path.read_text(errors="replace").splitlines()
    except OSError:
        return out
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except ValueError:
            continue
        if isinstance(d, dict):
            out.append(d)
    return out


def parse_stream(s: Session) -> Session:
    calls: dict[str, ToolCall] = {}
    order: list[str] = []
    pending: list[str] = []      # tool_use ids still waiting for their PreToolUse hooks
    for ev in s.events:
        t = ev.get("type")
        if t == "system" and ev.get("subtype") == "init":
            s.init = ev
        elif t == "system" and str(ev.get("subtype", "")).startswith("hook"):
            s.hooks.append(ev)
            # stream hook events carry no tool_use_id: a PreToolUse response
            # belongs to the oldest tool_use not answered yet
            if (ev.get("subtype") == "hook_response" and ev.get("hook_event") == "PreToolUse"
                    and pending):
                tc = calls[pending[0]]
                if tc.name and str(ev.get("hook_name", "")).endswith(":" + tc.name):
                    out = ev.get("output") or ev.get("stdout") or ""
                    if out:
                        tc.hook_outputs.append(str(out))
        elif t == "assistant":
            for c in (ev.get("message") or {}).get("content") or []:
                if isinstance(c, dict) and c.get("type") == "tool_use":
                    tc = ToolCall(str(c.get("id")), str(c.get("name")), dict(c.get("input") or {}),
                                  parent=ev.get("parent_tool_use_id"))
                    calls[tc.id] = tc
                    order.append(tc.id)
                    pending.append(tc.id)
        elif t == "user":
            for c in (ev.get("message") or {}).get("content") or []:
                if isinstance(c, dict) and c.get("type") == "tool_result":
                    tc = calls.get(str(c.get("tool_use_id")))
                    if tc is not None and tc.id in pending:
                        pending.remove(tc.id)
                    if tc is not None:
                        tc.result = _text(c.get("content"))
                        tc.is_error = bool(c.get("is_error"))
        elif t == "result":
            s.result = ev
            s.results.append(ev)
    for d in s.denials:
        tc = calls.get(str(d.get("tool_use_id")))
        if tc is not None:
            tc.denied = True
    s.calls = [calls[i] for i in order]
    return s


def dispatch_info(debug: str, tool_use_id: str) -> dict[str, Any]:
    """What Claude Code's debug log says about one tool call's permission
    step: the `tool_dispatch_start ... toolUseId=ID permissionDecisionMs=N`
    line, whether `Hook approved tool use` came right before it, and whether
    a classifier line appeared in that stretch."""
    lines = debug.splitlines()
    for i, line in enumerate(lines):
        if "tool_dispatch_start" in line and f"toolUseId={tool_use_id}" in line:
            m = re.search(r"permissionDecisionMs=(\d+)", line)
            j = i - 1
            while j >= 0 and "tool_dispatch_start" not in lines[j]:
                j -= 1
            seg = lines[j + 1:i]
            # Without a hook allow, Claude Code's own permission step runs (auto
            # mode: the classifier; it logs "Permission suggestions for TOOL"
            # and takes hundreds of ms); a hook allow skips it.
            return {"found": True,
                    "decision_ms": int(m.group(1)) if m else None,
                    "hook_approved": any("Hook approved tool use" in x for x in seg),
                    "permission_step": [x[:160] for x in seg if "Permission suggestions" in x
                                        or "classif" in x.lower()][:2]}
    return {"found": False}


# ---------------------------------------------------------------------------
# Planted secrets
# ---------------------------------------------------------------------------


def _b64s(b: bytes) -> list[str]:
    std = base64.b64encode(b).decode()
    url = base64.urlsafe_b64encode(b).decode()
    return list(dict.fromkeys([std, std.rstrip("="), url.rstrip("=")]))


def secret_forms(value: str, users: tuple[str, ...] = ()) -> list[str]:
    """Spellings of one fake secret in output (each at least 8 characters)."""
    v = value.encode()
    forms = [value, *_b64s(v), urllib.parse.quote(value, safe=""),
             urllib.parse.quote_plus(value)]
    for u in users:
        forms += _b64s(f"{u}:{value}".encode())
    # a multi-line value (an ssh private key): each long line on its own
    if "\n" in value:
        forms += [ln.strip() for ln in value.splitlines()
                  if len(ln.strip()) >= 16 and "PRIVATE KEY" not in ln]
    return [f for f in dict.fromkeys(forms) if len(f) >= 8]


def scan(paths: list[Path], forms: dict[str, list[str]]) -> list[tuple[str, str]]:
    """(file, secret name) for every planted form found."""
    hits = []
    for p in paths:
        try:
            data = p.read_bytes().decode("utf-8", "replace")
        except OSError:
            continue
        # JSON escaping can split a value: look at the raw text and at the
        # text with \n escapes turned into real newlines.
        variants = [data, data.replace("\\n", "\n").replace("\\/", "/")]
        for name, fs in forms.items():
            if any(f in t for f in fs for t in variants):
                hits.append((str(p), name))
    return hits


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


CLASSIFIER_SKIP = "not reached (classifier)"


@dataclass
class Check:
    group: str
    name: str
    ok: bool | None          # None: not reached / not checked
    detail: str = ""


class Checks:
    def __init__(self) -> None:
        self.items: list[Check] = []

    def add(self, group: str, name: str, ok: bool | None, detail: Any = "") -> bool:
        d = detail if isinstance(detail, str) else json.dumps(detail, default=str)[:600]
        self.items.append(Check(group, name, None if ok is None else bool(ok), d[:600]))
        return bool(ok)

    @property
    def failed(self) -> list[Check]:
        return [c for c in self.items if c.ok is False]

    def table(self) -> str:
        rows = []
        for c in self.items:
            mark = {True: "PASS", False: "FAIL", None: "SKIP"}[c.ok]
            rows.append(f"{mark}  {c.group:8} {c.name}" + (f"\n          {c.detail}" if c.detail
                                                           and c.ok is not True else ""))
        n_ok = sum(1 for c in self.items if c.ok is True)
        n_bad = len(self.failed)
        n_skip = sum(1 for c in self.items if c.ok is None)
        n_cls = len(self.classifier)
        rows.append(f"\n{n_ok} passed, {n_bad} failed, {n_skip} not reached"
                    + (f" ({n_cls} because Claude Code's auto-mode classifier denied the call)"
                       if n_cls else ""))
        return "\n".join(rows)

    @property
    def classifier(self) -> list[Check]:
        """Not reached because Claude Code's auto-mode classifier denied the
        call (scenarios.NOT_REACHED_CLASSIFIER): no pass, no failure."""
        return [c for c in self.items if c.ok is None and c.detail.startswith(CLASSIFIER_SKIP)]

    def save(self, path: Path) -> None:
        path.write_text(json.dumps([c.__dict__ for c in self.items], indent=1))


def first_line(s: str, n: int = 200) -> str:
    s = re.sub(r"\s+", " ", s or "").strip()
    return s[:n]
