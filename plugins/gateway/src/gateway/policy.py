"""Policy decisions (PLAN-v4 phase 7, docs/dev/modules/policy.md).

Every gateway action on a host or with an account is decided here, at the
boundary that performs it (the ssh and sudo stand-ins, gated's terminals,
jobs and remote runtime, host inspection, the managed shell's imports, the
http tool, the approval hook), as allow / ask / deny with the concrete rule
behind it:

    decide(eff, action, host=..., workspace=..., account=..., mode=None) -> Decision

Actions (form.py): restrictions read, exec, write, network, elevation,
credential, env_import, provision; grants forward_agent, forward_x11,
forward_remote, forward_stdio.

Per mode (PLAN-0.11 §2): every right and the restrictions read, exec,
write, network, elevation and credential may hold a word per mode. `mode`
is the mode to decide in (the hook's payload mode, or the session's recorded
mode for a command Claude typed: modes.current_for); None is the modeless
rule (the strictest word over every mode but plan, allow capped at cc), for
jobs, terminals, scripts and gated. The decision's `value` is the word
(deny, ask, cc, allow, or "unconfigured" for this computer's sudo when
nothing configures it), `word` today's vocabulary (cc and allow are True,
"unconfigured" "ask" for a reader that doesn't know it), `mode` the mode it
used.

How a decision is made (strictest wins, nothing above the rights):

1. the base right: on a remote host every restriction starts at its `ssh`
   right (elevation at the stricter of `sudo` and exec; a grant at `ssh`
   only once the host's own policy table turns it on); on this machine
   read, exec, network, credential and env_import start at cc (Claude
   Code's own permission modes govern Claude's local commands; the gateway
   doesn't add a competing mode) and elevation at localhost's `sudo`; an
   account's credential, write and network start at its `use`;
2. then every restriction that applies lowers it, in the same mode: the
   host's [hosts.NAME.policy], the workspace's own keys, the account's
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
from . import modes

RANK = modes.RANK
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
    word: Any                 # True | "ask" | False (today's vocabulary: cc and allow are True)
    rule: str                 # the concrete rule behind it (safe text, from the form's own words)
    entry: str = ""           # the entry that holds that rule ("settings" for [policy])
    action: str = ""
    host: str = ""
    workspace: str = ""
    account: str = ""
    pending: str = ""         # a wider value waiting for the user's OK, said as such
    note: str = ""            # why this rule applies when that isn't plain (a path that may
                              # reach a workspace: ssh_args.decide_path)
    value: str = "deny"       # the word in `mode`: deny | ask | cc | allow | unconfigured
    mode: str | None = None   # the mode decided in (None: the modeless rule)
    # an action on this machine whose base is Claude Code's own permissions
    # (cc) and that a policy table explicitly allows in this mode, with
    # nothing lower: PLAN-0.11 §19.1 (a bare word never counts, nor a table
    # the user hasn't approved yet: consent keeps it plain until the OK)
    explicit_allow: bool = False

    @property
    def allowed(self) -> bool:
        return self.word is True

    @property
    def mode_label(self) -> str:
        """The mode for an audit line: the mode key, or "modeless"."""
        return self.mode or "modeless"

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


def _q(mv: Any) -> str:
    """A policy value in a rule: "allow" / "ask" / "deny" / "cc" for a bare
    word, the table's rendering otherwise."""
    if isinstance(mv, modes.ModeValue):
        snap = mv.snapshot()
        if isinstance(snap, dict):
            return f"{{{mv.render()}}}"
        mv = snap
    if mv in ("cc", "allow", "deny"):
        return f'"{mv}"'
    return f'"{formmod.policy_text(mv)}"'


def _right_word(mv: Any) -> str:
    return consent.word(mv)


def _lower(cur: tuple[str, str, str], r: str | None, rule: str, entry: str) -> tuple[str, str, str]:
    """The stricter of the current (word, rule, entry) and a new candidate
    word (ties keep the earlier, more basic rule; RANK indexed: an unknown
    word raises)."""
    if r is None:
        return cur
    if RANK[r] < RANK[cur[0]]:
        return (r, rule, entry)
    return cur


def _w(mv: Any, mode: str | None) -> str | None:
    """A restriction's word in `mode`; None when absent or "allow" (a
    restriction's allow restricts nothing: it never lowers this computer's
    unconfigured sudo to an approval)."""
    w = mv.word(mode) if mv is not None else None
    return None if w == "allow" else w


def _new_rule(eff: consent.Effective, sect: str, name: str) -> str:
    """Why an entry with no approval is denied: its approval can't be read
    (the vault locked or broken: consent's note), else it waits for the OK."""
    if eff.unreadable:
        return eff.refusal(name) or f"[{sect}.{name}] isn't approved"
    return f"[{sect}.{name}] waits for the user's OK (gate check {name})"


def _form_value(eff: consent.Effective, scope: str, key: str, host: str = "", ws: str = "",
                account: str = "") -> Any:
    """What the form itself says for a policy key, per mode (to tell a
    pending widening)."""
    f = eff.form
    if scope == "host":
        h = f.hosts.get(host)
        return h.policy_mode(key) if h else None
    if scope == "ws":
        h = f.hosts.get(host)
        w = h.workspaces.get(ws) if h else None
        return w.policy_mode(key) if w else None
    if scope == "account":
        a = f.accounts.get(account)
        return a.policy_mode(key) if a else None
    return f.policy_mode(key)


def decide(eff: consent.Effective, action: str, host: str | None = None,
           workspace: str | None = None, account: str | None = None,
           mode: str | None = None) -> Decision:
    """The decision for one action in `mode` (None: the modeless rule; see
    the module docstring). `host` None or "localhost" is this machine;
    `account` decides credential, write and network with that account."""
    if action not in ACTIONS:
        raise ValueError(f"unknown policy action {action!r}")
    if mode is not None:
        mode = modes.normalize(mode)
    local = host in (None, "", "localhost")
    hname = "localhost" if local else str(host)
    d = Decision(word=False, rule="", action=action, host="" if local and not account else hname,
                 workspace=workspace or "", account=account or "", mode=mode)
    if account and action not in ACCOUNT_ACTIONS and host is None:
        raise ValueError(f"{action} isn't an account action")
    cur: tuple[str, str, str]
    local_cc = False           # the base is Claude Code's own permissions (this machine)
    layers: list[Any] = []     # the policy values that applied (for explicit_allow)
    # 1. the base right
    if account and host is None:
        ea = eff.accounts.get(account)
        if ea is None:
            d.rule = (eff.refused.get(account) or f"no account {account} in gateway.toml")
            d.entry = account
            return d
        a = eff.form.accounts.get(account)
        u = ea.modes.get("use") or modes.uniform("deny")
        cur = (u.word(mode), f"[accounts.{account}] use = {_right_word(u)}"
               + _line(a.line if a else None), account)
        if ea.new:
            cur = ("deny", _new_rule(eff, "accounts", account), account)
    else:
        eh = eff.hosts.get(hname)
        h = eff.form.hosts.get(hname)
        if eh is None:
            d.rule = (eff.refused.get(hname) or f"no host {hname} in gateway.toml")
            d.entry = hname
            return d
        if not local and action not in HOST_ACTIONS:
            raise ValueError(f"{action} isn't a host action")
        if local and action not in LOCAL_ACTIONS:
            # write, provision and the forwarding grants don't apply to this machine
            return Decision(word=True, rule="not a localhost action", action=action,
                            entry="localhost", value="cc", mode=mode)
        if eh.new:
            cur = ("deny", _new_rule(eff, "hosts", hname), hname)
        elif local:
            if action == "elevation":
                s = eh.modes.get("sudo")
                cur = ((s.word(mode), f"[hosts.localhost] sudo = {_right_word(s)}"
                        + _line(h.line if h else None), "localhost") if s is not None else
                       (modes.UNCONFIGURED, "this computer's sudo isn't configured in "
                        "gateway.toml (your own sudo)", "localhost"))
                if "localhost" in eff.refused:
                    # configured by the list or the approval while neither can
                    # be checked (consent._listed_localhost): refused
                    cur = ("deny", eff.refused["localhost"], "localhost")
            else:
                cur = ("cc", "this machine (Claude Code's own permissions apply)", "localhost")
                local_cc = True
        else:
            s = eh.modes.get("ssh") or modes.uniform("deny")
            cur = (s.word(mode), f"[hosts.{hname}] ssh = {_right_word(s)}"
                   + _line(h.line if h else None), hname)
            if action == "elevation":
                su = eh.modes.get("sudo") or modes.uniform("deny")
                cur = _lower(cur, su.word(mode), f"[hosts.{hname}] sudo = {_right_word(su)}"
                             + _line(h.line if h else None), hname)
            if action in formmod.POLICY_GRANT:
                g = eh.policy_modes.get(action)
                if g is None:
                    cur = _lower(cur, "deny", f"[hosts.{hname}.policy] has no {action} = \"allow\" "
                                 f"({WHAT[action]} is off unless that host's own policy turns it "
                                 "on)", hname)
                else:
                    cur = _lower(cur, g.word(mode), f"[hosts.{hname}.policy] {action} = {_q(g)}"
                                 + _line(h.policy_lines.get(action) if h else None), hname)
        # 2a. the host's own restrictions (elevation also obeys exec's)
        keys = [action] + (["exec"] if action == "elevation" and not local else [])
        for k in keys:
            if k in formmod.POLICY_GRANT:
                continue
            v = eh.policy_modes.get(k)
            if v is not None and k == action:
                layers.append(v)
            cur = _lower(cur, _w(v, mode), f"[hosts.{hname}.policy] {k} = {_q(v)}"
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
                v = ew.policy_modes.get(k)
                cur = _lower(cur, _w(v, mode), f"[hosts.{hname}.workspaces.{workspace}] {k} = "
                             f"{_q(v)}" + _line(w.lines.get(k) if w else None), hname)
        # 2c. the account's, when one is used on the host
        if account:
            ea = eff.accounts.get(account)
            if ea is None or ea.new:
                cur = _lower(cur, "deny", f"[accounts.{account}] isn't approved (gate check "
                             f"{account})", account)
            elif action in ACCOUNT_ACTIONS:
                a = eff.form.accounts.get(account)
                u = ea.modes.get("use") or modes.uniform("deny")
                cur = _lower(cur, u.word(mode), f"[accounts.{account}] use = {_right_word(u)}",
                             account)
                v = ea.policy_modes.get(action)
                cur = _lower(cur, _w(v, mode), f"[accounts.{account}.policy] {action} = {_q(v)}"
                             + _line(a.policy_lines.get(action) if a else None), account)
    if account and host is None:
        ea = eff.accounts[account]
        a = eff.form.accounts.get(account)
        v = ea.policy_modes.get(action)
        cur = _lower(cur, _w(v, mode), f"[accounts.{account}.policy] {action} = {_q(v)}"
                     + _line(a.policy_lines.get(action) if a else None), account)
    # 2d. [policy], for everything
    keys = [action] + (["exec"] if action == "elevation" and not local else [])
    for k in keys:
        v = eff.policy_modes.get(k)
        if v is not None and k == action:
            layers.append(v)
        cur = _lower(cur, _w(v, mode), f"[policy] {k} = {_q(v)}"
                     + _line(eff.form.policy_lines.get(k)), "settings")
    d.value, d.rule, d.entry = cur
    d.word = modes.legacy(d.value)
    # the user's explicit allow for this mode, approved like any widening
    # (an effective value is explicit only where the approval is too)
    d.explicit_allow = (local_cc and d.value == "cc" and bool(layers)
                        and all(v.word(mode) == "allow" for v in layers)
                        and any(v.explicit_in(mode) for v in layers))
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
    ww = want.word(d.mode) if want is not None else (
        "deny" if d.action in formmod.POLICY_GRANT else "allow")
    if RANK[ww] > RANK[d.value] and (d.entry in names or not names):
        return (f"gateway.toml already says more, which waits for the user's OK (the user runs "
                f"gate check {d.entry})")
    return ""


def refuse(d: Decision, tool: str, what: str | None = None) -> str:
    """Audit a refusal (gate why shows it), with the mode it was decided in
    (PLAN-0.11 §2.4: the mode key, or "modeless"), and return its message.
    (Every action's decision in CONTRACT-v1's words, for snapshots and the
    panes, is daemon/lifecycle.contract_rights.)"""
    from . import audit
    msg = d.message(what)
    try:
        audit.refusal(tool=tool, reason=msg, target=d.host or d.account or "localhost",
                      mode=d.mode_label)
    except Exception:  # noqa: BLE001 - an audit line is never worth a crash
        pass
    return msg
