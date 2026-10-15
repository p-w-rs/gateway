"""Hook entry points, invoked via run.py from Claude Code.

route_main   -> PreToolUse(Bash): redirect blocked network/credential/cert CLIs.
session_main -> SessionStart: inject the network policy and the vault catalog
                (names, descriptions, hosts; never values) so Claude uses the
                gateway on the first try.
prompt_main  -> UserPromptSubmit (via hooks/prompt.sh): handle
                /net-gateway:secret and /net-gateway:sudo, then let the prompt
                through with the result (or block it if it may hold a value).
"""
from __future__ import annotations

import json
import sys

from . import commands, policy, vault

SESSION_NOTE = (
    "Network policy for this session: do NOT run curl, wget, nmap, masscan, "
    "certutil, cmdkey, the macOS `security` keychain tool, or PowerShell "
    "Invoke-WebRequest / Invoke-RestMethod directly. Instead:\n"
    "- Read a web page: built-in WebFetch tool.\n"
    "- Call an API (any method/headers/body): net-gateway http_request tool.\n"
    "- Download a file: net-gateway download tool (saves to quarantine).\n"
    "- Check host/port reachability: net-gateway port_check tool.\n"
    "- Credentials live in the net-gateway vault; values never reach you. Pass "
    "the secret's NAME as auth_ref to http_request. Allowed hosts go through "
    "silently; any other host is refused. Never try to read the vault files.\n"
    "- Commands needing root (the sudo password, stored in the vault, is "
    "injected for you): where sudo is ENABLED (see below), use run_privileged "
    "(no prompt; use it only for what the task needs); elsewhere use "
    "run_privileged_confirm (Claude Code asks the user for each call).\n"
    "- TLS certs / file hashes: net-gateway cert_inspect / file_hash.\n"
    "- The user manages the vault with slash commands; you can't run them. When "
    "something is missing or not allowed, tell the user the exact command:\n"
    "  /net-gateway:secret add NAME <description>   (a browser form asks the value)\n"
    "  /net-gateway:secret allow NAME HOST\n"
    "  /net-gateway:sudo add USER HOST               (a browser form asks the password)\n"
    "  /net-gateway:sudo enable HOST [always]        (this session, or every session)\n"
    "  /net-gateway:sudo disable HOST\n"
    "  (/net-gateway:secret help and /net-gateway:sudo help list the rest.)\n"
    "When a <net-gateway-result> block is attached to the user's message, the "
    "gateway already handled their command: just relay the result in a line.\n"
    "NEVER ask the user to paste a secret or password into the chat; if they do "
    "anyway, don't repeat it and tell them to replace it.\n"
    "Every gateway call is logged; run /net-log to review this session."
)


def route_main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0  # fail open: never block on our own error

    if payload.get("tool_name") != "Bash":
        return 0
    command = payload.get("tool_input", {}).get("command", "")
    if not command:
        return 0

    hit = policy.match_blocked(command)
    if not hit:
        return 0

    name, route = hit
    policy.audit("hook_redirect", {"tool": name, "command": command[:500]})
    reason = (
        f"'{name}' is routed through the net-gateway instead of running "
        f"directly. Use {route}. Credentials stay hidden and every call is "
        f"logged (see /net-log)."
    )
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    return 0


def _catalog_note(session_id: str = "") -> str:
    try:
        data = vault.load()
        cat = vault.catalog(data)
    except Exception as e:
        return f"\n(The net-gateway vault could not be read: {e})"
    lines = []
    if cat["secrets"]:
        lines.append("Secrets in the net-gateway vault (use the NAME as auth_ref):")
        for n, s in cat["secrets"].items():
            hosts = (", ".join(s["hosts"])
                     or f"none yet: ask the user to run /net-gateway:secret allow {n} HOST")
            lines.append(f"- {n}: {s['description'] or '(no description)'} [hosts: {hosts}]")
    if cat["sudo"]:
        lines.append("Stored sudo passwords:")
        for key in cat["sudo"]:
            host = key.split("@", 1)[1]
            lines.append(f"- {key}: sudo {vault.sudo_state(host, session_id, data)}")
    return ("\n" + "\n".join(lines)) if lines else ""


def _enabled_warning(session_id: str = "") -> str | None:
    """Shown to the USER at session start while any host runs sudo unasked."""
    try:
        data = vault.load()
    except Exception:
        return None
    hosts = sorted({e["host"] for e in data["sudo"].values()
                    if vault.sudo_enabled(e["host"], session_id, data)})
    if not hosts:
        return None
    return ("net-gateway: sudo is ENABLED (root commands run without asking) on: "
            + ", ".join(hosts) + ". Turn off with /net-gateway:sudo disable HOST.")


def session_main() -> int:
    try:
        session_id = json.load(sys.stdin).get("session_id") or ""
    except Exception:
        session_id = ""
    out: dict = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": SESSION_NOTE + _catalog_note(session_id),
        }
    }
    warning = _enabled_warning(session_id)
    if warning:
        out["systemMessage"] = warning
    print(json.dumps(out))
    return 0


def prompt_main() -> int:
    """Output for a /secret or /sudo prompt. On an unexpected error it blocks,
    so a typed value can never fall through to Claude."""
    try:
        payload = json.load(sys.stdin)
        out = commands.handle(payload)
    except Exception as e:  # noqa: BLE001
        out = commands.block(
            f"net-gateway: could not process the command ({type(e).__name__}); "
            "nothing was saved and it was not sent to Claude.")
    if out is not None:
        print(json.dumps(out))
    return 0
