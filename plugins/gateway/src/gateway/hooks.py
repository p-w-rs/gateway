"""Hook entry points, invoked via run.py from Claude Code.

route_main   -> PreToolUse(Bash): redirect blocked network/credential/cert CLIs.
session_main -> SessionStart: inject the network policy and the vault catalog
                (names, descriptions, hosts; never values) so Claude uses the
                gateway on the first try.
prompt_main  -> UserPromptSubmit (via hooks/prompt.sh): handle
                /gate:secret, /gate:sudo and /gate:account, then let the prompt
                through with the result (or block it if it may hold a value).
"""
from __future__ import annotations

import json
import os
import re
import sys

from . import commands, policy, vault

SESSION_NOTE = (
    "Network policy for this session: do NOT run curl, wget, nmap, masscan, "
    "certutil, cmdkey, the macOS `security` keychain tool, or PowerShell "
    "Invoke-WebRequest / Invoke-RestMethod directly. Instead:\n"
    "- Read a web page: built-in WebFetch tool.\n"
    "- Call an API (any method/headers/body): gateway http_request tool.\n"
    "- Download a file: gateway download tool (saves to quarantine).\n"
    "- Check host/port reachability: gateway port_check tool.\n"
    "- Credentials live in the gateway vault; values never reach you. Pass "
    "the secret's NAME as auth_ref to http_request. Allowed hosts go through "
    "silently; any other host is refused. Never try to read the vault files.\n"
    "- Commands needing root (the sudo password, stored in the vault, is "
    "injected for you): where sudo is ENABLED (see below), use run_privileged "
    "(no prompt; use it only for what the task needs); elsewhere use "
    "run_privileged_confirm (Claude Code asks the user for each call).\n"
    "- TLS certs / file hashes: gateway cert_inspect / file_hash.\n"
    "- The user manages the vault with short slash commands; you can't run them. "
    "When something is missing or not allowed, tell the user which one to type:\n"
    "  /gate:add account | secret | sudo | ssh   (or /gate:add github, hf, azure, ...)\n"
    "  /gate:update NAME      (e.g. to allow another host or org, or a new token)\n"
    "  /gate:delete NAME\n"
    "  /gate:enable sudo HOST [always]   /gate:disable sudo HOST\n"
    "  /gate:list\n"
    "  After /gate:add or /gate:update, the gateway's note opens a setup: follow the "
    "gate:setup skill (ask with question pop-ups, then call gate_setup). A native "
    "dialog takes any value; you never see it.\n"
    "- Accounts (KIND:NAME, e.g. github:work) are the user's separate identities. "
    "One with a token works as auth_ref on http_request, for its hosts only. Never "
    "fall back to the user's own environment credentials for a service that has an "
    "account here.\n"
    "When a <gateway-result> block is attached to the user's message, the "
    "gateway already handled their command: just relay the result in a line.\n"
    "NEVER ask the user to paste a secret or password into the chat; if they do "
    "anyway, don't repeat it and tell them to replace it.\n"
    "Every gateway call is logged; run /gate:log to review this session."
)

ACCOUNTS_NOTE = (
    "\nAccount tools (the user's own credentials are never used for these; read the "
    "gate:accounts skill before git/gh/hf/pijul/mirror work): git (EVERY git command, "
    "local ones too), git_mirror, git_identity, gh, hf, pijul, ssh_exec, ssh_copy, "
    "databricks, mlcat, mlcat_workspace, registry, account_list. When a tool answers "
    "use: <tool>_confirm, call that tool with the same arguments (Claude Code asks the "
    "user)."
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

    hit = policy.match_blocked(command) or policy.match_takeover(command)
    if not hit:
        return 0

    name, route = hit
    policy.audit("hook_redirect", {"tool": name, "command": command[:500]})
    reason = (
        f"'{name}' is routed through the gateway instead of running "
        f"directly. Use {route}. Credentials stay hidden and every call is "
        f"logged (see /gate:log)."
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
        return f"\n(The gateway vault could not be read: {e})"
    lines = []
    if cat["secrets"]:
        lines.append("Secrets in the gateway vault (use the NAME as auth_ref):")
        for n, s in cat["secrets"].items():
            hosts = (", ".join(s["hosts"])
                     or f"none yet: ask the user to run /gate:secret allow {n} HOST")
            lines.append(f"- {n}: {s['description'] or '(no description)'} [hosts: {hosts}]")
    if cat["accounts"]:
        lines.append("Accounts in the gateway vault (KIND:NAME; never values):")
        for ref in cat["accounts"]:
            lines.append("- " + commands._describe_account(ref, data["accounts"][ref], data))
    if cat["sudo"]:
        lines.append("Stored sudo passwords:")
        for key in cat["sudo"]:
            host = key.split("@", 1)[1]
            lines.append(f"- {key}: sudo {vault.sudo_state(host, session_id, data)}")
    return ("\n" + "\n".join(lines)) if lines else ""


TAKEOVER_NOTE = (
    "\nThe gateway is the only way to these: git, gh, hf, pijul, asiml/dvc, az, "
    "databricks, ssh/scp/rsync-to-host and registry commands in Bash are refused; use "
    "the tools above. The user's own credential variables and ssh-agent are not "
    "available in Bash, and credential files can't be read."
)


def write_env_file() -> bool:
    """Unset the user's credential variables for every Bash command this
    session (Claude Code sources CLAUDE_ENV_FILE before each one)."""
    path = os.environ.get("CLAUDE_ENV_FILE")
    if not path:
        return False
    try:
        with open(path, "a") as f:
            f.write("unset " + " ".join(policy.ENV_UNSET) + "\n")
        return True
    except OSError:
        return False


def files_main() -> int:
    """PreToolUse for file tools (perm.sh sends only calls that mention a
    credential location). Denies reads of secrets and keys, and writes to the
    gateway's own config; says nothing otherwise."""
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return 0
    tool = payload.get("tool_name", "")
    ti = payload.get("tool_input") or {}
    write = tool in ("Edit", "Write", "MultiEdit", "NotebookEdit")
    paths = [ti.get(k) for k in ("file_path", "path", "notebook_path") if isinstance(ti.get(k), str)]
    if tool == "Glob" and isinstance(ti.get("pattern"), str):
        base = ti.get("path") or ""
        paths.append(os.path.join(base, ti["pattern"]) if base else ti["pattern"])
    root = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    for path in paths:
        # A glob pattern: check its fixed leading part and the whole thing.
        cands = [path]
        if any(c in path for c in "*?["):
            cands.append(re.split(r"[*?\[]", path, maxsplit=1)[0])
        for c in cands:
            why = policy.protected_path(c, write=write, plugin_root=root,
                                        contents=(tool == "Grep"))
            if why and tool == "Glob" and why.startswith("an SSH"):
                continue  # Glob only lists names; listing ~/.ssh is fine
            if why:
                policy.audit("hook_file_denied", {"tool": tool, "path": str(path)[:300], "why": why})
                print(json.dumps({"hookSpecificOutput": {
                    "hookEventName": "PreToolUse", "permissionDecision": "deny",
                    "permissionDecisionReason": f"gateway: {path} is {why}; Claude doesn't need it."}}))
                return 0
    return 0


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
    return ("gateway: sudo is ENABLED (root commands run without asking) on: "
            + ", ".join(hosts) + ". Turn off with /gate:sudo disable HOST.")


def session_main() -> int:
    try:
        session_id = json.load(sys.stdin).get("session_id") or ""
    except Exception:
        session_id = ""
    write_env_file()
    out: dict = {
        "hookSpecificOutput": {
            "hookEventName": "SessionStart",
            "additionalContext": SESSION_NOTE + ACCOUNTS_NOTE + TAKEOVER_NOTE
                                 + _catalog_note(session_id),
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
        from . import setup
        out = setup.handle(payload)
        if out is None:
            out = commands.handle(payload)
    except Exception as e:  # noqa: BLE001
        out = commands.block(
            f"gateway: could not process the command ({type(e).__name__}); "
            "nothing was saved and it was not sent to Claude.")
    if out is not None:
        print(json.dumps(out))
    return 0
