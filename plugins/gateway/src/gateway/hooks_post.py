"""PostToolUse: scrub tool output and validate edits of the form (SPEC 12).

hooks.json sends every tool's response to hooks/post.sh (matcher ".*",
PLAN-0.11 §9.1), which skips the tools whose response is fixed text or
Claude's own input (SKIP_TOOLS) and runs this for every other response once
a vault exists (its values have no shape the sh prefilter could match), and
otherwise only when the tool response matches a token shape, holds the
value of one of the credential variables (envfile.MASK_ENV_NAMES), or when
an Edit/Write/MultiEdit touched gateway.toml.

- Scrub: `updatedToolOutput` = the tool response with every string passed
  through scrub.scrub_text (token shapes, vault values, and the values of
  the user's credential variables in this hook's environment, which is
  Claude Code's: env_secrets); same shape as the response (dict stays dict,
  list stays list, string stays string). With a passphrase-protected vault
  the values come from gated (vault.load is brokered: the hooks' scope is
  every secret class); a locked vault masks shapes and variables only.
- Form edits: validate, persist narrowings (consent.ratchet) and return
  `additionalContext` with the result, so Claude fixes its own mistake in the
  same turn: `gateway: form OK; example: new address needs the user's OK
  - run gate check example`.
- `pending_notice` (not called here): the fixed line SessionStart and the
  prompt hook show once per session for an open gateway dialog ("waiting in
  Claude Code (/gate-dialog shows it)"); the mod draws the dialog itself.

PostToolUseFailure (round 3): Claude Code sends a failed tool call (a Bash
command that exited non-zero, timed out or was killed) there, with the
output in `error`, and no hook can change what Claude reads (known limit:
the gateway doesn't change how Claude's commands exit, DECISIONS "Rolled
back"). So when the text holds a stored secret or a token shape, Claude is
told never to repeat or use it (additionalContext), the user is told which
entry to replace (systemMessage, never the value), and an audit event is
written.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

from . import paths

# `form`, `popup`, `vault` and `scrub` are imported where they are needed:
# this hook runs after almost every tool call once a vault exists, and a fresh
# Python pays for every import (review round 5).

FORM_TOOLS = ("Edit", "Write", "MultiEdit")
# Tools whose response is fixed text or Claude's own input: hooks/post.sh
# never starts Python for them (its SKIP_TOOLS; tests compare the two). Not
# TaskOutput or Task/Agent: their responses carry output.
SKIP_TOOLS = ("TodoWrite", "TaskCreate", "TaskGet", "TaskList", "TaskUpdate", "EnterPlanMode",
              "ExitPlanMode")
# The credential variables whose values are masked in what Claude reads
# (PLAN-0.11 §1.6: Claude's shell keeps the user's environment): the one
# list, envfile.MASK_ENV_NAMES, which hooks/post.sh writes out (a test
# compares); here every variable named like a credential is masked too
# (env_secrets).
_CRED_NAME = re.compile(r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|PASSWD|PASSPHRASE|API_?KEY|ACCESS_KEY|"
                        r"PRIVATE_KEY|CONNECTION_STRING)$")
MIN_ENV_VALUE = 8      # scrub.MIN_LITERAL: a shorter value masked by literal would be revealed


def env_secrets(environ: Any = None) -> list[tuple[str, str]]:
    """(name, value) of each credential variable in this hook's environment
    (Claude Code's): MASK_ENV_NAMES, and every name ending like a credential
    (_TOKEN, _SECRET, _PASSWORD, _API_KEY, ...), with a value of 8 or more
    characters. A value that starts with "/" counts too: a base64 secret
    (AWS_SECRET_ACCESS_KEY, AZURE_STORAGE_KEY) does about one time in 64.
    Values only the shell snapshot exports aren't here (a stated limit)."""
    from .envfile import MASK_ENV_NAMES
    env = os.environ if environ is None else environ
    out: list[tuple[str, str]] = []
    for n, v in env.items():
        if not isinstance(n, str) or not isinstance(v, str):
            continue
        if n not in MASK_ENV_NAMES and not _CRED_NAME.search(n.upper()):
            continue
        if len(v) < MIN_ENV_VALUE or not v.strip():
            continue
        out.append((n, v))
    return out


def env_values() -> list[str]:
    return [v for _n, v in env_secrets()]


def env_hits(text: str) -> list[str]:
    """The names of the credential variables whose value, in any form the
    scrubber masks, appears in `text` (names only; never the value)."""
    try:
        from . import scrub
    except Exception:  # noqa: BLE001
        return []
    raw = text.encode("utf-8", "surrogatepass")
    return [n for n, v in env_secrets() if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", n)
            and any(f and f in raw for f in scrub.expand([v]))]


# ---------------------------------------------------------------------------
# Scrubbing
# ---------------------------------------------------------------------------


def _vault_values() -> list[str]:
    try:
        from . import vault
        if not vault.exists():
            return []
        return vault.all_values(vault.load())
    except Exception:  # noqa: BLE001
        return []


def scrub_text(text: str, env: list[str] | None = None) -> str:
    """Token shapes, vault values and the credential variables' values
    (`env`: env_values(), read here when not given) masked."""
    env = env_values() if env is None else env
    try:
        from . import scrub
        return scrub.scrub_text(text, extra=env)
    except NotImplementedError:
        from . import audit
        return audit._fallback_scrub(text, _vault_values() + env)


def scrub_obj(obj: Any, env: list[str] | None = None) -> tuple[Any, bool]:
    """(scrubbed copy, changed?) for a tool response of any JSON shape."""
    env = env_values() if env is None else env
    if isinstance(obj, str):
        new = scrub_text(obj, env)
        return new, new != obj
    if isinstance(obj, dict):
        out, changed = {}, False
        for k, v in obj.items():
            nv, c = scrub_obj(v, env)
            out[k] = nv
            changed = changed or c
        return out, changed
    if isinstance(obj, list):
        items = [scrub_obj(v, env) for v in obj]
        return [v for v, _ in items], any(c for _, c in items)
    return obj, False


# ---------------------------------------------------------------------------
# The form
# ---------------------------------------------------------------------------


def is_form_path(p: Any, cwd: str | None = None) -> bool:
    if not isinstance(p, str) or not p:
        return False
    s = p
    if s == "~" or s.startswith("~/"):
        s = str(paths.user_home()) + s[1:]
    q = Path(s)
    if not q.is_absolute():
        q = Path(cwd if cwd and os.path.isabs(cwd) else os.getcwd()) / q
    target = paths.form_path()
    try:
        if q.exists() and target.exists() and os.path.samefile(q, target):
            return True
    except OSError:
        pass
    try:
        return os.path.normcase(str(q.resolve())).casefold() == \
            os.path.normcase(str(target.resolve())).casefold()
    except OSError:
        return False


def form_report(form: Any, eff: Any, narrowed: list[Any] | None = None) -> str:
    """One paragraph for Claude about the form it just edited (`narrowed`:
    the narrowings this edit made, which apply at once)."""
    if form.syntax_error is not None:
        tail = ("; the gateway keeps using the last good version until it's fixed"
                if form.from_last_good else "; until it's fixed only the defaults apply")
        return f"gateway: gateway.toml {form.syntax_error.render()}{tail}. Fix it now."
    bits: list[str] = []
    errs = form.errors
    if errs:
        shown = "; ".join(p.render() for p in errs[:6])
        more = f" (+{len(errs) - 6} more)" if len(errs) > 6 else ""
        off = [n for n in form.disabled]
        bits.append(f"gateway: gateway.toml has problems: {shown}{more}"
                    + (f". Off until fixed: {', '.join(off[:8])}" if off else "")
                    + ". Fix them now")
    else:
        bits.append("gateway: form OK")
    if narrowed:
        shown = "; ".join(c.render() for c in narrowed[:6])
        more = f" (+{len(narrowed) - 6} more)" if len(narrowed) > 6 else ""
        bits.append(f"{shown}{more} (applied at once)")
    for w in form.warnings[:3]:
        bits.append(f"warning: {w.render()}")
    for sect, table in (("hosts", form.hosts), ("accounts", form.accounts)):
        if "settings" in table or form.is_disabled("settings", sect):
            bits.append(f"warning: the name settings is reserved for the [settings] table; rename "
                        f"[{sect}.settings] (gate check can't set it up under that name)")
    pend = eff.pending if eff is not None else []
    seen: list[str] = []
    for c in pend:
        if c.entry in seen:
            continue
        seen.append(c.entry)
        whats = "; ".join(x.what for x in pend if x.entry == c.entry)[:300]
        bits.append(f"{c.entry}: {whats} needs the user's OK - run gate check {c.entry} while "
                    "they're here")
    return "; ".join(bits)


def _form_context() -> str | None:
    from . import consent, vault
    from . import form as formmod
    try:
        data = vault.load() if vault.exists() else None
    except vault.VaultError:
        data = None
    formmod.clear_cache()
    form = formmod.load(last_good=(data or {}).get("form_last_good"), use_cache=False)
    narrowed: list[Any] = []
    try:
        narrowed = consent.ratchet(form)
        if narrowed and vault.exists():
            data = vault.load()
    except Exception:  # noqa: BLE001
        pass
    eff = consent.compute(form, data)
    # the stand-ins on PATH follow the configured set (PLAN-0.11 §1.2; WS-1)
    from . import envfile
    envfile.sync_standins(form, eff)
    consent.sync_network_words(eff)          # pre_bash.sh's extra trigger words (WS-3)
    return form_report(form, eff, narrowed)


# ---------------------------------------------------------------------------
# Pending dialogs
# ---------------------------------------------------------------------------


def _sid(session_id: str | None) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", session_id or "nosession")[:80]


def shown_path(session_id: str | None) -> Path:
    """What this session was shown already (private/sessions: Claude's commands
    can't fake it to hide a notice)."""
    from . import popup
    return popup.state_dir() / f"{_sid(session_id)}.shown.json"


_WHAT_RE = re.compile(r"[a-z][a-z0-9 ._-]{0,47}")


def _needs(what: Any) -> str:
    if what in ("setup", "consent"):
        return "your OK"
    if isinstance(what, str) and _WHAT_RE.fullmatch(what):
        return f"the {what}"
    return "a secret"


def nothing_pending() -> bool:
    """private/pending holds no request (.json): pending_notice has nothing to
    show, and popup (urllib, the dialogs, the form) isn't imported (session
    start and every dialog clean the folder)."""
    try:
        with os.scandir(paths.pending_dir()) as it:
            return not any(e.name.endswith(".json") for e in it)
    except FileNotFoundError:
        return True
    except (OSError, paths.PathError):
        return False


def pending_notice(session_id: str | None, *, include_open: bool = False) -> list[str]:
    """Fixed lines for open dialogs this session hasn't been told about yet
    (with include_open; the gate mod shows the dialog itself, this is the
    line in the conversation's system message). Marks them shown."""
    if nothing_pending() or not include_open:
        return []
    from . import popup
    try:
        popup.cleanup_stale()
        reqs = popup.pending()
        p = shown_path(session_id)
    except (OSError, paths.PathError):
        return []
    try:
        seen = set(json.loads(p.read_text()).get("ids", []))
    except (OSError, ValueError, AttributeError):
        seen = set()
    lines = []
    for d in reqs:
        if d.get("state") != "open":
            continue
        n = d["entry"]
        rid = f"{d.get('_key')}:{d.get('since')}:{d.get('state')}"
        if rid in seen:
            continue
        what = d.get("what")
        what = what if isinstance(what, str) and _WHAT_RE.fullmatch(what) else "a secret"
        lines.append(f"gateway: the gateway dialog for {n} ({what}) is waiting in Claude Code "
                     "(/gate-dialog shows it)")
        seen.add(rid)
    try:
        tmp = p.with_name(p.name + f".{os.getpid()}")
        tmp.write_text(json.dumps({"ids": sorted(seen)[-200:]}))
        os.replace(tmp, p)
    except OSError:
        pass
    return lines


# ---------------------------------------------------------------------------
# The hook
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# PostToolUseFailure: warn, since nothing can be masked there
# ---------------------------------------------------------------------------


def secret_matches(text: str) -> list[tuple[str, str, str, list[str]]]:
    """(entry, what, section, matched forms) for each stored secret whose
    value, in any form the scrubber masks (JSON-escaped included), appears in
    `text`. The entry is shown only after validation ("an entry" otherwise);
    the forms are for masking copies (a transcript), never for showing."""
    try:
        from . import scrub, vault
        from . import form as formmod
        if not vault.exists():
            return []
        data = vault.load()
    except Exception:  # noqa: BLE001
        return []
    raw = text.encode("utf-8", "surrogatepass")
    out: dict[tuple[str, str, str], list[str]] = {}
    for section, entry, what, value in vault.labeled_secrets(data):
        if len(value) < scrub.MIN_LITERAL:
            continue
        name = entry if formmod.safe(entry) and formmod.NAME_RE.fullmatch(entry) else "an entry"
        found = [f for f in scrub.expand([value], ("x-access-token",)) if f and f in raw]
        if found:
            forms = out.setdefault((name, what, section), [])
            forms += [f.decode("utf-8", "surrogatepass") for f in found if
                      f.decode("utf-8", "surrogatepass") not in forms]
    return [(n, w, sec, forms) for (n, w, sec), forms in out.items()]


def secret_entries(text: str) -> list[tuple[str, str]]:
    """(entry, what) of each stored secret whose value, in any form the
    scrubber masks, appears in `text` (names only; never the value)."""
    return [(n, w) for n, w, _sec, _f in secret_matches(text)]


def _fix_for(entry: str, what: str, section: str = "") -> str:
    """The commands that really replace a leaked secret, by entry and kind
    (review round 4: gate check alone keeps a stored credential, and gate
    rotate is for hosts only)."""
    if entry == "an entry":
        return "replace it where it comes from"
    if section == "hosts" and what == "ssh key":
        return f"gate rotate {entry} gives the host a new key"
    if what == "sudo password":
        where = "this computer" if section == "localhost" else "that machine"
        return f"change it on {where}, then gate forget {entry} sudo and gate check {entry}"
    if what == "ssh key":
        return (f"remove its public key from the account on the server, then gate forget {entry} "
                f"key and gate check {entry}")
    return f"replace it where it comes from (revoke the old one), then gate login {entry}"


def failure_notice(payload: dict) -> tuple[str | None, str | None]:
    """(additionalContext for Claude, systemMessage for the user) when a
    failed call's output holds a stored secret or a token shape."""
    err = payload.get("error")
    text = err if isinstance(err, str) else (json.dumps(err) if err else "")
    if not text:
        return None, None
    matches = secret_matches(text)
    hits = [(n, w) for n, w, _sec, _f in matches]
    envs = env_hits(text)
    shaped = scrub_text(text, []) != text
    if not hits and not shaped and not envs:
        return None, None
    tool = payload.get("tool_name") if isinstance(payload.get("tool_name"), str) else ""
    try:
        from . import audit
        from . import form as formmod
        audit.log("leak", tool=formmod.safe(tool) or "a tool", entries=[f"{e} {w}" for e, w in hits],
                  variables=envs, shaped=shaped and not hits, where="PostToolUseFailure")
    except Exception:  # noqa: BLE001
        pass
    if envs and not hits:
        names = ", ".join(envs[:4])
        ctx = ("gateway: the output of that failed command held the value of one of the user's "
               "credential variables, which Claude Code shows unmasked for failed commands; never "
               "repeat, store or use it.")
        msg = (f"gateway: the output of a failed command held the value of your {names} "
               "variable. Claude Code doesn't let the gateway mask a failed command's output, so "
               "Claude saw it; consider replacing it.")
        return ctx, msg
    if hits:
        names = "; ".join(f"{e}'s {w}" for e, w in hits[:4])
        ctx = ("gateway: the output of that failed command held a stored secret, which Claude Code "
               "shows unmasked for failed commands; never repeat, store or use it, and don't run "
               "that command again.")
        fixes = "; ".join(dict.fromkeys(_fix_for(e, w, sec) for e, w, sec, _f in matches[:4]))
        msg = (f"gateway: the output of a failed command held a stored secret ({names}). Claude "
               "Code doesn't let the gateway mask a failed command's output, so Claude saw it; "
               f"consider replacing it ({fixes}).")
    else:
        ctx = ("gateway: the output of that failed command held something shaped like a token "
               "(Claude Code shows a failed command's output unmasked); never repeat, store or use "
               "it.")
        msg = ("gateway: the output of a failed command held something shaped like a token, which "
               "Claude saw unmasked; if it is a real one, consider replacing it.")
    return ctx, msg


def main(payload: dict) -> dict | None:
    """updatedToolOutput / additionalContext / systemMessage, or None (SPEC 12)."""
    if not isinstance(payload, dict):
        return None
    if payload.get("hook_event_name") == "PostToolUseFailure" or (
            "error" in payload and "tool_response" not in payload):
        return _failure_main(payload)
    tool = payload.get("tool_name")
    tin = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    spec: dict[str, Any] = {}
    out: dict[str, Any] = {}
    if "tool_response" in payload:
        new, changed = scrub_obj(payload.get("tool_response"))
        if changed:
            spec["updatedToolOutput"] = new
    if tool in FORM_TOOLS and is_form_path(tin.get("file_path"), payload.get("cwd")):
        ctx = _form_context()
        if ctx:
            spec["additionalContext"] = ctx
    if spec:
        out["hookSpecificOutput"] = {"hookEventName": "PostToolUse", **spec}
    return out or None


def _failure_main(payload: dict) -> dict | None:
    out: dict[str, Any] = {}
    ctx, msg = failure_notice(payload)
    lines = [msg] if msg else []
    if lines:
        out["systemMessage"] = "\n".join(lines)
    if ctx:
        out["hookSpecificOutput"] = {"hookEventName": "PostToolUseFailure", "additionalContext": ctx}
    return out or None
