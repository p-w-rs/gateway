"""Policy decisions (PLAN-v4 phase 7, docs/dev/modules/policy.md).

Every gateway action on a host or with an account is decided here, at the
boundary that performs it (the ssh and sudo stand-ins, gated's terminals,
jobs and remote runtime, host inspection, the managed shell's imports, the
http tool, the approval hook), as allow / ask / deny with the concrete rule
behind it:

    decide(eff, action, host=..., workspace=..., account=...) -> Decision

Actions (form.py): restrictions read, exec, write, network, elevation,
credential, env_import, provision; grants forward_agent, forward_x11,
forward_remote, forward_stdio.

How a decision is made (strictest wins, nothing above the rights):

1. the base right: on a remote host every restriction starts at its `ssh`
   right (elevation at the stricter of `sudo` and exec; a grant at `ssh`
   only once the host's own policy table turns it on); on this machine
   read, exec, network, credential and env_import start at allow (Claude
   Code's own permission modes govern Claude's local commands; the gateway
   doesn't add a competing mode) and elevation at localhost's `sudo`; an
   account's credential, write and network start at its `use`;
2. then every restriction that applies lowers it: the host's
   [hosts.NAME.policy], the workspace's own keys, the account's
   [accounts.NAME.policy], and [policy] for everything.

All of these are effective values (consent.compute): a raised key waits for
the user's OK and the approved one applies meanwhile, a lowered one applies
at once. A read grant never implies any other action: each action is
decided on its own, and nothing here derives one action from another except
elevation, which needs exec too (sudo runs a command).

"ask" can only be honoured where Claude Code asks the person: a command
Claude typed, judged by the approval hook. Every other caller (a script, a
job, gated's terminals) treats "ask" as "not now" and says how to get it
asked (`Decision.needs_typed`).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import consent
from . import form as formmod

RANK = consent.RANK
ACTIONS = formmod.POLICY_RESTRICT + formmod.POLICY_GRANT
HOST_ACTIONS = formmod.HOST_POLICY_KEYS
LOCAL_ACTIONS = formmod.LOCALHOST_POLICY_KEYS
ACCOUNT_ACTIONS = formmod.ACCOUNT_POLICY_KEYS
# What each action covers, for messages and docs.
WHAT = {
    "read": "reading files and settings on the host (host_inspect, downloads from it)",
    "exec": "running commands on the host (ssh HOST CMD, terminals, jobs)",
    "write": "writing outside this machine (uploads to the host; pushes and http writes with "
             "an account)",
    "network": "network paths (ssh -L/-D tunnels through the host; the http and download tools)",
    "elevation": "sudo (root) on the host",
    "credential": "the gateway handing a stored credential to a command",
    "env_import": "importing host folders and variables into the managed shell",
    "provision": "staging the gateway's managed runtime on the host",
    "forward_agent": "ssh agent forwarding",
    "forward_x11": "X11 forwarding",
    "forward_remote": "remote port forwarding (ssh -R)",
    "forward_stdio": "stdio forwarding (ssh -W)",
}


@dataclass
class Decision:
    word: Any                 # True | "ask" | False
    rule: str                 # the concrete rule behind it (safe text, from the form's own words)
    entry: str = ""           # the entry that holds that rule ("settings" for [policy])
    action: str = ""
    host: str = ""
    workspace: str = ""
    account: str = ""
    pending: str = ""         # a wider value waiting for the user's OK, said as such
    note: str = ""            # why this rule applies when that isn't plain (a path that may
                              # reach a workspace: ssh_args.decide_path)

    @property
    def allowed(self) -> bool:
        return self.word is True

    @property
    def text(self) -> str:
        return formmod.policy_text(self.word)

    def message(self, what: str | None = None) -> str:
        """The refusal ("gateway: ..."), naming the rule and what to do."""
        target = self.host or self.account or "this machine"
        act = what or WHAT.get(self.action, self.action)
        if self.word == "ask":
            head = (f"gateway: {act} on {target} is \"ask\" ({self.rule}); only a command "
                    "Claude typed can be asked about")
            tail = ("; run it as its own command with the Bash tool so Claude Code asks the "
                    "user, or ask the user to change the rule")
        else:
            head = f"gateway: {act} on {target} is denied by {self.rule}"
            tail = "; ask the user if it should be allowed (they change gateway.toml, then " \
                   f"approve it with gate check {self.entry or target})"
        if self.pending:
            tail = f"; {self.pending}"
        if self.note:
            head += f"; {self.note}"
        return head + tail + "."

    def public(self) -> dict[str, Any]:
        return {"decision": self.text, "rule": self.rule, "action": self.action,
                **({"host": self.host} if self.host else {}),
                **({"workspace": self.workspace} if self.workspace else {}),
                **({"account": self.account} if self.account else {})}


def _line(n: int | None) -> str:
    return f" (gateway.toml line {n})" if n else ""


def _q(r: Any) -> str:
    return f'"{formmod.policy_text(r)}"'


def _right_word(r: Any) -> str:
    return consent.word(r)


def _lower(cur: tuple[Any, str, str], r: Any, rule: str, entry: str) -> tuple[Any, str, str]:
    """The stricter of the current (word, rule, entry) and a new candidate
    (ties keep the earlier, more basic rule)."""
    if r is None:
        return cur
    if RANK.get(r, 0) < RANK.get(cur[0], 0):
        return (r, rule, entry)
    return cur


def _form_value(eff: consent.Effective, scope: str, key: str, host: str = "", ws: str = "",
                account: str = "") -> Any:
    """What the form itself says for a policy key (to tell a pending widening)."""
    f = eff.form
    if scope == "host":
        h = f.hosts.get(host)
        return (h.policy or {}).get(key) if h else None
    if scope == "ws":
        h = f.hosts.get(host)
        w = h.workspaces.get(ws) if h else None
        return w.policy.get(key) if w else None
    if scope == "account":
        a = f.accounts.get(account)
        return (a.policy or {}).get(key) if a else None
    return f.policy.get(key)


def decide(eff: consent.Effective, action: str, host: str | None = None,
           workspace: str | None = None, account: str | None = None) -> Decision:
    """The decision for one action (see the module docstring). `host` None
    or "localhost" is this machine; `account` decides credential, write and
    network with that account."""
    if action not in ACTIONS:
        raise ValueError(f"unknown policy action {action!r}")
    local = host in (None, "", "localhost")
    hname = "localhost" if local else str(host)
    d = Decision(word=False, rule="", action=action, host="" if local and not account else hname,
                 workspace=workspace or "", account=account or "")
    if account and action not in ACCOUNT_ACTIONS and host is None:
        raise ValueError(f"{action} isn't an account action")
    cur: tuple[Any, str, str]
    # 1. the base right
    if account and host is None:
        ea = eff.accounts.get(account)
        if ea is None:
            d.rule = (f"no account {account} in gateway.toml" if account not in eff.form.disabled
                      else f"[accounts.{account}] is off (a mistake in it: gate status)")
            d.entry = account
            return d
        a = eff.form.accounts.get(account)
        cur = (True if ea.use else False,
               f"[accounts.{account}] use = {'true' if ea.use else 'false'}"
               + _line(a.line if a else None), account)
        if ea.new:
            cur = (False, f"[accounts.{account}] waits for the user's OK (gate check {account})",
                   account)
    else:
        eh = eff.hosts.get(hname)
        h = eff.form.hosts.get(hname)
        if eh is None:
            d.rule = (f"no host {hname} in gateway.toml" if hname not in eff.form.disabled
                      else f"[hosts.{hname}] is off (a mistake in it: gate status)")
            d.entry = hname
            return d
        if not local and action not in HOST_ACTIONS:
            raise ValueError(f"{action} isn't a host action")
        if local and action not in LOCAL_ACTIONS:
            # write, provision and the forwarding grants don't apply to this machine
            return Decision(word=True, rule="not a localhost action", action=action,
                            entry="localhost")
        if eh.new:
            cur = (False, f"[hosts.{hname}] waits for the user's OK (gate check {hname})", hname)
        elif local:
            if action == "elevation":
                cur = (eh.sudo, f"[hosts.localhost] sudo = {_right_word(eh.sudo)}"
                       + _line(h.line if h else None), "localhost")
            else:
                cur = (True, "this machine (Claude Code's own permissions apply)", "localhost")
        else:
            cur = (eh.ssh, f"[hosts.{hname}] ssh = {_right_word(eh.ssh)}"
                   + _line(h.line if h else None), hname)
            if action == "elevation":
                cur = _lower(cur, eh.sudo, f"[hosts.{hname}] sudo = {_right_word(eh.sudo)}"
                             + _line(h.line if h else None), hname)
            if action in formmod.POLICY_GRANT:
                g = eh.policy.get(action)
                if g is None:
                    cur = _lower(cur, False, f"[hosts.{hname}.policy] has no {action} = \"allow\" "
                                 f"({WHAT[action]} is off unless that host's own policy turns it "
                                 "on)", hname)
                else:
                    cur = _lower(cur, g, f"[hosts.{hname}.policy] {action} = {_q(g)}"
                                 + _line(h.policy_lines.get(action) if h else None), hname)
        # 2a. the host's own restrictions (elevation also obeys exec's)
        keys = [action] + (["exec"] if action == "elevation" and not local else [])
        for k in keys:
            if k in formmod.POLICY_GRANT:
                continue
            v = eh.policy.get(k)
            cur = _lower(cur, v, f"[hosts.{hname}.policy] {k} = {_q(v)}"
                         + _line(h.policy_lines.get(k) if h else None), hname)
        # 2b. the workspace's
        if workspace:
            ew = eh.workspaces.get(workspace)
            if ew is None:
                fw = h.workspaces.get(workspace) if h else None
                d.rule = (f"workspace {workspace} on {hname} waits for the user's OK (gate check "
                          f"{hname})" if fw is not None else
                          f"no workspace {workspace} on {hname} in gateway.toml")
                d.entry = hname
                return d
            w = ew.workspace
            for k in keys:
                v = ew.policy.get(k)
                cur = _lower(cur, v, f"[hosts.{hname}.workspaces.{workspace}] {k} = {_q(v)}"
                             + _line(w.lines.get(k) if w else None), hname)
        # 2c. the account's, when one is used on the host
        if account:
            ea = eff.accounts.get(account)
            if ea is None or ea.new:
                cur = _lower(cur, False, f"[accounts.{account}] isn't approved (gate check "
                             f"{account})", account)
            elif action in ACCOUNT_ACTIONS:
                a = eff.form.accounts.get(account)
                cur = _lower(cur, True if ea.use else False,
                             f"[accounts.{account}] use = {'true' if ea.use else 'false'}", account)
                v = ea.policy.get(action)
                cur = _lower(cur, v, f"[accounts.{account}.policy] {action} = {_q(v)}"
                             + _line(a.policy_lines.get(action) if a else None), account)
    if account and host is None:
        ea = eff.accounts[account]
        a = eff.form.accounts.get(account)
        v = ea.policy.get(action)
        cur = _lower(cur, v, f"[accounts.{account}.policy] {action} = {_q(v)}"
                     + _line(a.policy_lines.get(action) if a else None), account)
    # 2d. [policy], for everything
    keys = [action] + (["exec"] if action == "elevation" and not local else [])
    for k in keys:
        v = eff.policy.get(k)
        cur = _lower(cur, v, f"[policy] {k} = {_q(v)}" + _line(eff.form.policy_lines.get(k)),
                     "settings")
    d.word, d.rule, d.entry = cur
    d.pending = _pending(eff, d, hname if not (account and host is None) else "", workspace or "",
                         account or "")
    return d


def _pending(eff: consent.Effective, d: Decision, host: str, ws: str, account: str) -> str:
    """When the form itself is wider than what applies (a raised key waiting
    for the OK), say so: the user approves it, Claude never can."""
    if d.word is True:
        return ""
    names = [c.entry for c in eff.pending if d.action in c.what or "new " in c.what]
    want = None
    if d.rule.startswith("[policy]"):
        want = _form_value(eff, "global", d.action)
    elif d.rule.startswith(f"[hosts.{host}.workspaces.{ws}]") and ws:
        want = _form_value(eff, "ws", d.action, host=host, ws=ws)
    elif d.rule.startswith(f"[hosts.{host}.policy]"):
        want = _form_value(eff, "host", d.action, host=host)
    elif d.rule.startswith(f"[accounts.{account}.policy]") and account:
        want = _form_value(eff, "account", d.action, account=account)
    else:
        return ""
    wr = RANK[want] if want is not None else (0 if d.action in formmod.POLICY_GRANT else 2)
    if wr > RANK.get(d.word, 0) and (d.entry in names or not names):
        return (f"gateway.toml already says more, which waits for the user's OK (the user runs "
                f"gate check {d.entry})")
    return ""


def rights(eff: consent.Effective, host: str) -> dict[str, str]:
    """Every action's effective decision on a host, as allow / ask / deny
    (CONTRACT-v1 snapshots, /gate-hosts)."""
    local = host in ("", "localhost")
    acts = LOCAL_ACTIONS if local else HOST_ACTIONS
    out = {}
    for a in acts:
        try:
            out[a] = decide(eff, a, host=host).text
        except ValueError:
            continue
    return out


def account_rights(eff: consent.Effective, account: str) -> dict[str, str]:
    out = {}
    for a in ACCOUNT_ACTIONS:
        out[a] = decide(eff, a, account=account).text
    return out


def refuse(d: Decision, tool: str, what: str | None = None) -> str:
    """Audit a refusal (gate why shows it) and return its message."""
    from . import audit
    msg = d.message(what)
    try:
        audit.refusal(tool=tool, reason=msg, target=d.host or d.account or "localhost")
    except Exception:  # noqa: BLE001 - an audit line is never worth a crash
        pass
    return msg
