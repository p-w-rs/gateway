"""PreToolUse decision for the gw MCP server's http and download tools
(PLAN-0.11 §2.10, lead decision 19.1). hooks/mcp_perm.sh (sh and awk, no
Python) decides every other gw tool itself and hands these two here
(`launch.sh hook-mcp`): they are rare and wait on the network anyway, so a
Python start is affordable.

The network policy in the payload's `permission_mode` (modes.from_payload):
this computer's ([hosts.localhost.policy] network, [policy] network;
policy.decide(eff, "network", mode=...)), and for a call with an account
(`account` given and not null, as web.py reads it) that account's too
(policy.decide(eff, "network", account=..., mode=...): its
[accounts.NAME.policy] network and [policy] network):

    deny   -> deny, with the rule and what to do (audited, with the mode)
    ask    -> ask (web.py then lets the call through: it was asked about)
    cc     -> no decision: Claude Code's own mode decides (a bare word, or no
              policy at all: nothing is approved by default)
    allow  -> allow, only without an account, only where the user's explicit
              per-mode allow says so (a policy table's, approved in the
              consent dialog like any widening: Decision.explicit_allow), in
              a mode the payload names (empty, missing or unknown reads as
              default and never allows)

A call with an account is never approved here: an account's use has no allow
shape (§2.5). Its `use` and its credential and write policy stay web.py's
(a decision whose rule is the account's `use` itself is left to it, so the
refusal names what to do). A vault alias is followed as web.py follows it;
a name the form doesn't know gets this computer's network policy only
(web.py refuses the name).

Like the Bash hook it records the session's mode in gated when the
effective form makes it matter (hooks_bash.record_mode): web.py reads it
back for the gw MCP server. [network] commands is the Bash hook's class and
never read here (§3.6). Fails open (no output): Claude Code's mode decides.
"""
from __future__ import annotations

from typing import Any

from . import modes

GW = "mcp__plugin_gate_gw__"
TOOLS = {GW + "http": "the http tool", GW + "download": "the download tool"}


def _out(decision: str, reason: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": decision,
                                   "permissionDecisionReason": reason}}


def _explicit_rule(eff: Any, mode: str) -> str:
    """The table that holds the explicit allow, for the reason text."""
    lh = eff.hosts.get("localhost")
    for where, mv in (("[hosts.localhost.policy]", lh.policy_modes.get("network") if lh else None),
                      ("[policy]", eff.policy_modes.get("network"))):
        if mv is not None and mv.explicit_in(mode):
            return f"{where} network"
    return "the network policy"


def _account_name(form: Any, account: Any) -> str | None:
    """The form's name for a call's `account`, as web.py resolves it (a vault
    alias followed; the vault is read only for a name the form doesn't
    know)."""
    if not isinstance(account, str) or not account:
        return None
    if account in form.accounts:
        return account
    from . import accounts as acctmod
    from . import vault
    try:
        aliases = (vault.load().get("aliases") or {}) if vault.exists() else {}
    except Exception:  # noqa: BLE001 - no aliases: this computer's policy only
        aliases = {}
    return acctmod.resolve_name(account, aliases, form)


def _decisions(eff: Any, account: str | None, mode: str) -> list[Any]:
    """The network decisions that apply: this computer's, and with an account
    the form names, the account's (whose base, the account's `use`, is
    web.py's to judge: such a decision is left out)."""
    from . import hooks_bash, policy
    out = [policy.decide(eff, "network", mode=mode)]
    if account is not None and account in eff.accounts:
        d = policy.decide(eff, "network", account=account, mode=mode)
        if hooks_bash._POLICY_RULE.match(d.rule):
            out.append(d)
    return out


def main(payload: dict) -> dict | None:
    """The hook's answer (deny / ask / allow) or None (no decision)."""
    tool = payload.get("tool_name")
    if tool not in TOOLS:
        return None
    ti = payload.get("tool_input")
    if not isinstance(ti, dict):
        return None
    from . import hooks_bash, policy
    mode, known = modes.from_payload(payload.get("permission_mode"))
    form, eff = hooks_bash._load_rights()
    hooks_bash.record_mode(payload.get("permission_mode"), eff)
    what = TOOLS[tool]
    account = ti.get("account")
    ds = _decisions(eff, _account_name(form, account), mode)
    for d in ds:
        if d.value == "deny":
            return _out("deny", policy.refuse(d, tool.removeprefix(GW), f"{what}'s requests"))
    for d in ds:
        if d.value == "ask":
            where = f"with {d.account}" if d.account else "on this machine"
            return _out("ask", f"gateway: {what}'s requests {where} are \"ask\" in "
                               f"{modes.DISPLAY[mode]} mode ({d.rule}); approve it to run.")
    if account is not None:
        return None                  # an account's use has no allow shape: never approved here
    if ds[0].explicit_allow and known:
        return _out("allow", f"gateway: allowed ({_explicit_rule(eff, mode)} allows {what} in "
                             f"{modes.DISPLAY[mode]} mode).")
    return None
