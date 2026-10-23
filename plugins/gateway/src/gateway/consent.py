"""Consent: effective rights from the approved snapshot vs the form (SPEC 5).

The vault's `approved.rights` holds what the user last OK'd. On every form
load the gateway computes the effective rights:

- narrowing (true -> ask -> false, removing hosts, addresses, owners, sites,
  `use = false`, ...) applies at once; sync_narrowing() also lowers the
  approved snapshot, so raising it again later needs the user's OK;
- widening (a new host or account; a right raised; scripts false -> true; a
  new address/also/via; a new destination such as an api-key site, azure
  workspace/storage/registry/site or account host; an account `env` added or
  changed; a changed api-key `auth` placement or azure tenant/client;
  `others = "mine"`; [shell] `managed` lowered from "on" to "warn" or "off",
  a new import_path folder or import_env name) stays inactive until approve()
  records the user's OK.
  Meanwhile the entry runs with its last approved rights (a brand-new entry:
  nothing).

Bindings: an account credential goes only to destinations in the vault's
`bound.hosts`; approve() adds the approved destinations there.

Without any approved snapshot, the baseline is an empty form under the
install's defaults (others = "refuse"; this computer's sudo where the form
doesn't say: form.apply_install_defaults). A new install (no vault yet, or a
vault with the baseline mark, vault.older_install) gets sudo = "ask", the
documented default its starter form says too. A vault an older gateway made
(0.9.1 and before: no mark) keeps that gateway's baseline, sudo = true, which
was already the effective right there: its old starter's `sudo = true`, a form
without [hosts.localhost] or without its `sudo` key, and a 0.6 conversion
next to the user's own gateway.toml stay true, with or without an approval
stored. With no vault at all, an old starter's `sudo = true` can't be told
from an edit of the new starter: it waits for the user's OK like any widening
(`gate check localhost`) and runs as "ask" meanwhile. A vault that can't be
read now gets the new defaults (the stricter ones) until it can.

Ratchet contract: a narrowing is persisted (the approved snapshot lowered)
by ratchet(), which every process that loads the form should call: SessionStart,
SubagentStart and `gate` (through hooks_session.prepare), the file guard
before an Edit/Write of gateway.toml, and in phase B FileChanged, PostToolUse
(form edits), the Bash hook (commands naming config/gateway) and the
stand-ins. It is cheap when nothing narrowed. A missing form, a syntax error,
a pending v2 store and disabled entries never ratchet.

Imported rights: when migration had to write gateway.from-v2.toml (the user
already had a gateway.toml), the converted entries' rights are kept in
`imported` instead of `approved`. An entry copied from there into
gateway.toml counts as approved up to those rights (no pop-up, bindings kept);
ratchet() moves it into `approved`.
"""
from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any

from . import accounts as acctmod
from . import form as formmod

RANK = {False: 0, "ask": 1, True: 2}
# [shell] managed (PLAN-v4 phase 4): "on" is the strictest; lowering it widens.
SHELL_RANK = {"off": 0, "warn": 1, "on": 2}
SHELL_DEFAULT = {"managed": "on", "import_path": [], "import_env": []}


def ask_phrase(name: str, verb: str) -> str:
    """How a message names one right: "ssh on box", "sudo (root) on box",
    "sudo on this machine"."""
    if name == "localhost" and verb == "sudo":
        return "sudo on this machine"
    if verb == "sudo":
        return f"sudo (root) on {name}"
    return f"{verb} on {name}"


def job_ask_message(phrases: list[str]) -> str:
    """The refusal for "ask" rights inside a checkpoint job: nobody can be
    asked while a job runs. The approval hook's job_start deny and the
    stand-ins (an "ask" right reached under checkpoint's job runner) say the
    same, so Claude runs it with the Bash tool instead of starting another
    job. `phrases` come from ask_phrase."""
    what = phrases[0] if len(phrases) == 1 else ", ".join(phrases[:-1]) + " and " + phrases[-1]
    s, it = ("", "it") if len(phrases) == 1 else ("s", "them")
    return (f'gateway: a job can\'t use the "ask" right{s} for {what} (nobody can be asked while '
            "it runs); run it with the Bash tool as its own command, or ask the user to set "
            f"{it} to true.")


# Said after an "ask" for sudo on this machine (the approval hook's prompt and
# job refusal, the sudo stand-in's refusals) while the vault can't be read
# because it is locked: the rights then come from the new install's defaults
# (sudo "ask"), whatever the vault approved or an older install's default was.
LOCKED_SUDO_NOTE = (' (The gateway vault is locked, so the gateway can\'t tell whether sudo here '
                    'is approved and uses "ask" until the user unlocks it with /gate-unlock in '
                    "Claude Code.)")


def locked_sudo_note(form: formmod.Form) -> str:
    """LOCKED_SUDO_NOTE when the form's sudo on this machine may be more than
    "ask" once the vault is readable (true, or not said: an older install's
    default is true); "" when it says "ask" or off itself."""
    h = form.hosts.get("localhost")
    return LOCKED_SUDO_NOTE if h is not None and (h.sudo_default or h.sudo is True) else ""


def pane_ask_message(phrases: list[str]) -> str:
    """The refusal for "ask" rights reached inside a gateway terminal or job
    (ancestry.TERMINAL): Claude Code asks about nothing run there, whoever
    typed it. The approval hook's terminal_send / job_start deny says the
    same in its job wording; this one names the pane."""
    what = phrases[0] if len(phrases) == 1 else ", ".join(phrases[:-1]) + " and " + phrases[-1]
    s, it = ("", "it") if len(phrases) == 1 else ("s", "them")
    return (f'gateway: a gateway terminal or job can\'t use the "ask" right{s} for {what} (nobody '
            "can be asked about what runs there); run it with the Bash tool as its own command, "
            f"or ask the user to set {it} to true.")


def rmin(a: Any, b: Any) -> Any:
    return a if RANK.get(a, 0) <= RANK.get(b, 0) else b


def word(r: Any) -> str:
    return "true" if r is True else ("false" if r is False else '"ask"')


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------


def _phase7_snapshot(h: formmod.Host, snap: dict[str, Any]) -> dict[str, Any]:
    """PLAN-v4 phase 7's parts of a host's snapshot, each only when present
    (an older approval has none of them): its policy table, its workspaces,
    a remote host's [hosts.NAME.shell] imports."""
    if h.policy is not None:
        snap["policy"] = dict(h.policy)
    if h.workspaces:
        snap["workspaces"] = {n: w.snapshot() for n, w in h.workspaces.items()}
    if not h.is_local and (h.shell.import_path or h.shell.import_env):
        snap["shell"] = {"import_path": list(h.shell.import_path),
                         "import_env": list(h.shell.import_env)}
    return snap


def host_snapshot(h: formmod.Host) -> dict[str, Any]:
    if h.is_local:
        return _phase7_snapshot(h, {"sudo": h.sudo, "scripts": h.scripts})
    snap = {"ssh": h.ssh, "sudo": h.sudo, "scripts": h.scripts, "via": h.via,
            "addresses": [a.snapshot() for a in h.addresses()]}
    if h.runtime:
        snap["runtime"] = h.runtime      # (absent: the default folder; an older approval has none)
    return _phase7_snapshot(h, snap)


def account_snapshot(a: formmod.Account) -> dict[str, Any]:
    snap = {"kind": a.kind, "use": a.use, "scripts": a.scripts, "env": a.env or None,
            "destinations": a.destinations(), "auth": a.auth or None,
            "tenant": a.tenant or None, "client_id": a.client_id or None}
    if a.policy is not None:
        snap["policy"] = dict(a.policy)
    return snap


def shell_snapshot(form: formmod.Form) -> dict[str, Any]:
    sh = form.shell
    return {"managed": sh.managed, "import_path": list(sh.import_path),
            "import_env": list(sh.import_env)}


def approved_shell(ap: dict[str, Any]) -> dict[str, Any]:
    """The approved [shell] settings (an approval from before PLAN-v4 phase
    4 has none: the defaults, managed "on" and no imports)."""
    sh = (ap.get("settings") or {}).get("shell")
    if not isinstance(sh, dict):
        return copy.deepcopy(SHELL_DEFAULT)
    m = sh.get("managed")
    return {"managed": m if m in SHELL_RANK else "on",
            "import_path": [x for x in sh.get("import_path") or [] if isinstance(x, str)],
            "import_env": [x for x in sh.get("import_env") or [] if isinstance(x, str)]}


def snapshot(form: formmod.Form) -> dict[str, Any]:
    return {"settings": {"others": form.settings.others, "shell": shell_snapshot(form),
                         "policy": dict(form.policy)},
            "hosts": {n: host_snapshot(h) for n, h in form.hosts.items()},
            "accounts": {n: account_snapshot(a) for n, a in form.accounts.items()}}


def older_install(data: dict[str, Any] | None) -> bool:
    """Was the vault made by an older gateway (vault.older_install: no
    baseline mark)? Its install keeps the old defaults (sudo true here)."""
    from . import vault
    return vault.older_install(data)


def baseline(older: bool = False) -> dict[str, Any]:
    """The rights of an empty form under the install's defaults (older: a
    vault an older gateway made, whose default was sudo = true here)."""
    from pathlib import Path
    f = formmod.parse_text("", Path("gateway.toml"))
    formmod.apply_install_defaults(f, older)
    return snapshot(f)


def imported_rights(data: dict[str, Any] | None) -> dict[str, Any]:
    """Rights of entries converted into gateway.from-v2.toml, not yet copied
    into the form ({"hosts": {...}, "accounts": {...}})."""
    imp = ((data or {}).get("imported") or {}).get("rights")
    if not isinstance(imp, dict):
        return {"hosts": {}, "accounts": {}}
    return {"hosts": dict(imp.get("hosts") or {}), "accounts": dict(imp.get("accounts") or {})}


def approved_rights(data: dict[str, Any] | None) -> dict[str, Any]:
    ap = ((data or {}).get("approved") or {}).get("rights")
    if not isinstance(ap, dict):
        return baseline(older_install(data))
    ap = copy.deepcopy(ap)
    ap.setdefault("settings", {"others": "refuse"})
    ap.setdefault("hosts", {})
    ap.setdefault("accounts", {})
    return ap


# ---------------------------------------------------------------------------
# Effective rights
# ---------------------------------------------------------------------------


@dataclass
class Change:
    entry: str
    kind: str        # "widen" | "narrow"
    what: str        # safe text, e.g. "sudo \"ask\" -> true"
    line: int | None = None

    def render(self) -> str:
        return f"{self.entry}: {self.what}"


@dataclass
class EffectiveHost:
    name: str
    ssh: Any = False
    sudo: Any = False
    scripts: bool = False
    addresses: list[formmod.Address] = field(default_factory=list)
    via: str | None = None
    runtime: str | None = None        # the approved runtime folder (None: the default)
    new: bool = False                 # not approved at all yet
    pending: list[Change] = field(default_factory=list)
    host: formmod.Host | None = None  # the form entry
    # PLAN-v4 phase 7: the effective policy keys (a restriction absent: none;
    # a grant absent: off), the approved workspaces, a remote host's imports
    policy: dict[str, Any] = field(default_factory=dict)
    workspaces: dict[str, "EffectiveWorkspace"] = field(default_factory=dict)
    import_path: list[str] = field(default_factory=list)
    import_env: list[str] = field(default_factory=list)

    @property
    def is_local(self) -> bool:
        return self.name == "localhost"


@dataclass
class EffectiveAccount:
    name: str
    kind: str
    use: bool = False
    scripts: bool = False
    env: str | None = None
    destinations: list[str] = field(default_factory=list)
    owners: list[str] = field(default_factory=list)
    auth: str | None = None
    tenant: str | None = None
    client_id: str | None = None
    new: bool = False
    pending: list[Change] = field(default_factory=list)
    account: formmod.Account | None = None
    policy: dict[str, Any] = field(default_factory=dict)     # PLAN-v4 phase 7

    def may_send_to(self, host: str) -> bool:
        return self.use and acctmod.covers(self.destinations, host)


@dataclass
class EffectiveWorkspace:
    """An approved workspace as it applies now (PLAN-v4 phase 7): the
    approved root and mapping (a changed one waits for the OK), and its
    effective restrictions."""
    name: str
    host: str
    root: str
    local: str = ""
    policy: dict[str, Any] = field(default_factory=dict)
    workspace: formmod.Workspace | None = None


@dataclass
class EffectiveShell:
    """The managed shell as it applies now: the stricter mode of form and
    approval, and the imports that are in both."""
    managed: str = "on"
    import_path: list[str] = field(default_factory=list)
    import_env: list[str] = field(default_factory=list)


@dataclass
class Effective:
    form: formmod.Form
    others: str = "refuse"
    shell: EffectiveShell = field(default_factory=EffectiveShell)
    hosts: dict[str, EffectiveHost] = field(default_factory=dict)
    accounts: dict[str, EffectiveAccount] = field(default_factory=dict)
    pending: list[Change] = field(default_factory=list)     # widenings waiting for OK
    narrowed: list[Change] = field(default_factory=list)    # narrowings vs approved
    approved: dict[str, Any] = field(default_factory=dict)
    policy: dict[str, Any] = field(default_factory=dict)    # [policy] as it applies (phase 7)

    @property
    def disabled(self) -> dict[str, str]:
        return self.form.disabled

    def host(self, name: str) -> EffectiveHost | None:
        return self.hosts.get(name)

    def account(self, name: str) -> EffectiveAccount | None:
        return self.accounts.get(name)

    def right(self, host: str, what: str) -> Any:
        """True | "ask" | False for ssh/sudo/scripts on a host (False if unknown)."""
        h = self.hosts.get(host)
        return getattr(h, what) if h is not None else False

    def pending_for(self, name: str) -> list[Change]:
        return [c for c in self.pending if c.entry == name]

    def pending_names(self) -> list[str]:
        return list(dict.fromkeys(c.entry for c in self.pending))


def _addr_key(d: dict[str, Any]) -> tuple[str, str, int]:
    return (str(d.get("user")), str(d.get("host")), int(d.get("port") or 22))


def _covered(fa: formmod.Address, approved: list[dict[str, Any]]) -> bool:
    for ap in approved:
        if _addr_key(ap) == fa.key() and (ap.get("when") in (None, "") or ap.get("when") == fa.when):
            return True
    return False


def _render_addr(d: dict[str, Any]) -> str:
    a = formmod.Address(host=d["host"], port=int(d.get("port") or 22), user=d.get("user"))
    return a.render()


GRANT_WORDS = {
    "forward_agent": "ssh agent forwarding (programs on the host can use the keys of the agent "
                     "the gateway gives that connection)",
    "forward_x11": "X11 forwarding (programs on the host can draw on and read this machine's "
                   "display)",
    "forward_remote": "remote port forwarding (ports opened on the host lead to this machine)",
    "forward_stdio": "stdio forwarding (ssh -W: the host connects onward on this machine's "
                     "behalf)",
}


def _ptext(v: Any, grant: bool) -> str:
    if v is None:
        return "off" if grant else "unrestricted"
    return f'"{formmod.policy_text(v)}"'


def policy_compare(f: dict[str, Any] | None, a: dict[str, Any] | None, keys: tuple[str, ...],
                   grants: tuple[str, ...], label: str, W: Any, N: Any) -> dict[str, Any]:
    """One policy table against its approval (PLAN-v4 phase 7): a key raised
    (or a restriction removed, or a grant turned on) waits for the user's OK
    and the approved value applies meanwhile; a key lowered applies at once.
    A restriction absent means none (as permissive as "allow"); a grant
    absent means off ("deny"). Returns the effective keys (absent
    restrictions and grants that are off are left out)."""
    f = f or {}
    a = a or {}
    out: dict[str, Any] = {}
    for k in keys:
        grant = k in grants
        fv, av = f.get(k), a.get(k)
        rf = RANK[fv] if fv is not None else (0 if grant else 2)
        ra = RANK[av] if av is not None else (0 if grant else 2)
        if rf > ra:
            what = f"{label}{k} {_ptext(av, grant)} -> {_ptext(fv, grant)}"
            if grant:
                what += f" ({GRANT_WORDS.get(k, k)})"
            W(what)
            ev = av
        else:
            if rf < ra:
                N(f"{label}{k} {_ptext(av, grant)} -> {_ptext(fv, grant)}")
            ev = fv
        if ev is not None and not (grant and ev is False):
            out[k] = ev
    return out


def _policy_narrowed(f: dict[str, Any] | None, a: dict[str, Any] | None, keys: tuple[str, ...],
                     grants: tuple[str, ...]) -> dict[str, Any] | None:
    """The approved table lowered to the form where the form is stricter
    (sync_narrowing); None when neither has anything to keep."""
    if f is None and a is None:
        return None
    f = f or {}
    a = a or {}
    out: dict[str, Any] = {}
    for k in keys:
        grant = k in grants
        fv, av = f.get(k), a.get(k)
        rf = RANK[fv] if fv is not None else (0 if grant else 2)
        ra = RANK[av] if av is not None else (0 if grant else 2)
        v = fv if rf < ra else av
        if v is not None:
            out[k] = v
    return out


def _ws_restrictions(a: Any) -> dict[str, Any]:
    """An approved workspace's restrictions: its read/exec/write keys below
    "allow" ("ask" or deny); {} when it restricts nothing."""
    pol = a.get("policy") if isinstance(a, dict) and isinstance(a.get("policy"), dict) else {}
    return {k: pol[k] for k in formmod.WORKSPACE_POLICY_KEYS
            if k in pol and RANK.get(pol[k], 0) < 2}


def _phase7_host(e: EffectiveHost, name: str, h: formmod.Host, ap: dict[str, Any],
                 W: Any, N: Any) -> None:
    """The host's policy table, workspaces and remote imports against their
    approval (PLAN-v4 phase 7)."""
    keys = formmod.LOCALHOST_POLICY_KEYS if h.is_local else formmod.HOST_POLICY_KEYS
    e.policy = policy_compare(h.policy, ap.get("policy"), keys, formmod.POLICY_GRANT,
                              "policy ", W, N)
    aws = ap.get("workspaces") if isinstance(ap.get("workspaces"), dict) else {}
    for wn, w in h.workspaces.items():
        a = aws.get(wn)
        if not isinstance(a, dict):
            W(f"new workspace {wn} (root {w.root}" + (f", local {w.local}" if w.local else "")
              + ")")
            continue
        ew = EffectiveWorkspace(name=wn, host=name, root=str(a.get("root") or ""),
                                local=str(a.get("local") or ""), workspace=w)
        if w.root != ew.root:
            W(f"workspace {wn} root {w.root} (was {ew.root})")
        if (w.local or "") != ew.local:
            W(f"workspace {wn} local {w.local or 'none'} (was {ew.local or 'none'})")
        ew.policy = policy_compare(w.policy, a.get("policy"), formmod.WORKSPACE_POLICY_KEYS, (),
                                   f"workspace {wn} ", W, N)
        if ew.root:
            e.workspaces[wn] = ew
    for wn, a in aws.items():
        if wn in h.workspaces:
            continue
        # a workspace taken out of the form (deleted, or renamed: the new name
        # is a new workspace above): one that restricts anything keeps its
        # root and restrictions until the user's OK (removing a restriction
        # is a widening); one that restricts nothing goes at once
        held = _ws_restrictions(a)
        if held and isinstance(a, dict) and a.get("root"):
            W(f"workspace {wn} removed (root {a.get('root')}; its "
              + ", ".join(f"{k} {_ptext(v, False)}" for k, v in held.items())
              + " would no longer apply)")
            e.workspaces[wn] = EffectiveWorkspace(name=wn, host=name, root=str(a.get("root")),
                                                  local=str(a.get("local") or ""), policy=held)
        else:
            N(f"workspace {wn} removed")
    if not h.is_local:
        ash = ap.get("shell") if isinstance(ap.get("shell"), dict) else {}
        for k, label in (("import_path", "PATH import"), ("import_env", "environment import")):
            have = [x for x in ash.get(k) or [] if isinstance(x, str)]
            want = getattr(h.shell, k)
            for x in want:
                if x in have:
                    getattr(e, k).append(x)
                else:
                    W(f"{label} {x} on {name} (the managed shell there "
                      + ("finds the programs in that folder)" if k == "import_path" else
                         "gets that variable from the host's login environment)"))
            for x in have:
                if x not in want:
                    N(f"{label} {x} removed")


def _host(name: str, h: formmod.Host, ap: dict[str, Any] | None,
          widen: list[Change], narrow: list[Change]) -> EffectiveHost:
    e = EffectiveHost(name=name, host=h)
    line = h.line

    def W(what: str) -> None:
        widen.append(Change(name, "widen", what, line))

    def N(what: str) -> None:
        narrow.append(Change(name, "narrow", what, line))

    if ap is None:
        e.new = True
        if h.is_local:
            W(f"localhost: sudo {word(h.sudo)}")
        else:
            bits = [f"address {h.address.render() if h.address else '?'}"]
            if h.also:
                bits.append("also " + ", ".join(a.render() for a in h.also))
            if h.via:
                bits.append(f"via {h.via}")
            bits.append(f"ssh {word(h.ssh)}, sudo {word(h.sudo)}")
            if h.scripts:
                bits.append("scripts true")
            W("new host (" + "; ".join(bits) + ")")
        return e
    keys = ("sudo",) if h.is_local else ("ssh", "sudo")
    for k in keys:
        a, f = ap.get(k, False), getattr(h, k)
        if RANK.get(f, 0) > RANK.get(a, 0):
            W(f"{k} {word(a)} -> {word(f)}")
        elif RANK.get(f, 0) < RANK.get(a, 0):
            N(f"{k} {word(a)} -> {word(f)}")
        setattr(e, k, rmin(a, f))
    a_s, f_s = bool(ap.get("scripts")), h.scripts
    if f_s and not a_s:
        W("scripts false -> true (programs Claude starts get credentials too)")
    elif a_s and not f_s:
        N("scripts true -> false")
    e.scripts = a_s and f_s
    _phase7_host(e, name, h, ap, W, N)
    if h.is_local:
        return e
    approved_addrs = list(ap.get("addresses") or [])
    for fa in h.addresses():
        if _covered(fa, approved_addrs):
            e.addresses.append(fa)
            prev = [x for x in approved_addrs if _addr_key(x) == fa.key()]
            if fa.when and prev and not prev[0].get("when"):
                N(f"address {fa.render()} only on {fa.when} now")
        else:
            same = [x for x in approved_addrs if _addr_key(x) == fa.key()]
            if same:
                W(f"address {fa.render()} on {fa.when or 'any network'} (was {same[0].get('when')})")
            else:
                W(f"new address {fa.render()}" + (f" (on {fa.when})" if fa.when else ""))
    form_keys = {fa.key() for fa in h.addresses()}
    for x in approved_addrs:
        if _addr_key(x) not in form_keys:
            N(f"address {_render_addr(x)} removed")
    a_via, f_via = ap.get("via"), h.via
    if f_via != a_via:
        if f_via:
            W(f"via {f_via} (was {a_via or 'direct'})")
            e.via = a_via
        else:
            N(f"via {a_via} removed (direct now)")
            e.via = None
    else:
        e.via = f_via
    # where the gateway stages its remote runtime (PLAN-v4 phase 6): any
    # change waits for the user's OK (the gateway would write and run
    # programs in another folder); until then the approved folder applies
    a_rt, f_rt = ap.get("runtime") or None, h.runtime or None
    if f_rt != a_rt:
        W(f"runtime {f_rt or 'default'} (was {a_rt or 'default'})")
    e.runtime = a_rt
    if not e.addresses:
        e.ssh = False
    return e


def _account(name: str, a: formmod.Account, ap: dict[str, Any] | None,
             rec: dict[str, Any] | None, widen: list[Change], narrow: list[Change]) -> EffectiveAccount:
    e = EffectiveAccount(name=name, kind=a.kind, owners=list(a.owners), account=a)
    line = a.line
    dests = a.destinations()

    def W(what: str) -> None:
        widen.append(Change(name, "widen", what, line))

    def N(what: str) -> None:
        narrow.append(Change(name, "narrow", what, line))

    if ap is None or ap.get("kind") != a.kind:
        e.new = True
        what = f"new {a.kind} account" if ap is None else f"kind changed to {a.kind}"
        extra = []
        if dests:
            extra.append("sends to " + ", ".join(dests))
        if a.env:
            extra.append(f"env {a.env}")
        if a.scripts:
            extra.append("scripts true")
        if not a.use:
            extra.append("use false")
        W(what + (" (" + "; ".join(extra) + ")" if extra else ""))
        return e
    approved = list(ap.get("destinations") or [])
    bound = None
    if rec is not None:
        bound = list(((rec.get("bound") or {}).get("hosts")) or [])
    for d in dests:
        ok = d in approved and (bound is None or d in bound)
        if ok:
            e.destinations.append(d)
        elif d in approved:
            W(f"credential not yet bound to {d}")
        else:
            W(f"may now send to {d}")
    for d in approved:
        if d not in dests:
            N(f"no longer sends to {d}")
    if a.use and not ap.get("use", True):
        W("use false -> true")
    elif not a.use and ap.get("use", True):
        N("use true -> false")
    e.use = a.use and bool(ap.get("use", True))
    if a.scripts and not ap.get("scripts"):
        W("scripts false -> true (programs Claude starts get the credential too)")
    elif ap.get("scripts") and not a.scripts:
        N("scripts true -> false")
    e.scripts = a.scripts and bool(ap.get("scripts"))
    a_env, f_env = ap.get("env"), a.env or None
    if f_env and f_env != a_env:
        W(f"env {f_env} (programs Claude runs with `gate with` may read the key)"
          + (f"; was {a_env}" if a_env else ""))
        e.env = None
    elif a_env and not f_env:
        N(f"env {a_env} removed")
        e.env = None
    else:
        e.env = f_env
    for k, label in (("auth", "auth placement"), ("tenant", "tenant"), ("client_id", "client_id")):
        av, fv = ap.get(k), getattr(a, k) or None
        if (av or fv) and av != fv:
            hint = " (needs a new sign-in)" if k in ("tenant", "client_id") else ""
            W(f"{label} {av or 'unset'} -> {fv or 'unset'}{hint}")
            setattr(e, k, av)
        else:
            setattr(e, k, fv)
    e.policy = policy_compare(a.policy, ap.get("policy"), formmod.ACCOUNT_POLICY_KEYS, (),
                              "policy ", W, N)
    return e


def compute(form: formmod.Form, data: dict[str, Any] | None = None) -> Effective:
    """Effective rights for a validated form against the vault's approvals.
    First sets the form's install-dependent defaults from the vault
    (form.apply_install_defaults), so the form's own rights read after this
    (the approval hook's stricter-of rule, snapshots, approve) agree."""
    formmod.apply_install_defaults(form, older_install(data))
    ap = approved_rights(data)
    eff = Effective(form=form, approved=ap)
    widen: list[Change] = []
    narrow: list[Change] = []
    f_oth, a_oth = form.settings.others, (ap.get("settings") or {}).get("others", "refuse")
    if form.settings.others_invalid:
        eff.others = "refuse"   # a bad value: nothing extra, and the approval is kept
    elif f_oth == "mine" and a_oth != "mine":
        widen.append(Change("settings", "widen", "others = \"mine\" (your own ssh/git setup for "
                            "machines and git servers not in the form)"))
        eff.others = "refuse"
    else:
        if a_oth == "mine" and f_oth == "refuse":
            narrow.append(Change("settings", "narrow", "others = \"refuse\""))
        eff.others = f_oth
    eff.shell = _shell(form, approved_shell(ap), widen, narrow)
    ap_pol = (ap.get("settings") or {}).get("policy")
    eff.policy = policy_compare(
        form.policy, ap_pol if isinstance(ap_pol, dict) else {}, formmod.GLOBAL_POLICY_KEYS, (),
        "policy ", lambda w: widen.append(Change("settings", "widen", w, form.policy_line)),
        lambda w: narrow.append(Change("settings", "narrow", w)))
    imp = imported_rights(data)
    ap_hosts, ap_accts = ap.get("hosts") or {}, ap.get("accounts") or {}
    for name, h in form.hosts.items():
        eff.hosts[name] = _host(name, h, ap_hosts.get(name, imp["hosts"].get(name)), widen, narrow)
    for name in ap_hosts:
        if name not in form.hosts and not form.is_disabled(name, "hosts"):
            narrow.append(Change(name, "narrow", "host removed"))
    vrecs = (data or {}).get("accounts") or {}
    for name, a in form.accounts.items():
        eff.accounts[name] = _account(name, a, ap_accts.get(name, imp["accounts"].get(name)),
                                      vrecs.get(name), widen, narrow)
    for name in ap_accts:
        if name not in form.accounts and not form.is_disabled(name, "accounts"):
            narrow.append(Change(name, "narrow", "account removed"))
    # A jump host that is off makes the hosts behind it unreachable.
    for _ in range(formmod.MAX_CHAIN + 1):
        for e in eff.hosts.values():
            if e.via:
                j = eff.hosts.get(e.via)
                e.ssh = rmin(e.ssh, j.ssh if j is not None else False)
    for c in widen:
        target = eff.hosts.get(c.entry) or eff.accounts.get(c.entry)
        if target is not None:
            target.pending.append(c)
    eff.pending = widen
    eff.narrowed = narrow
    return eff


def _shell(form: formmod.Form, ap: dict[str, Any], widen: list[Change],
           narrow: list[Change]) -> EffectiveShell:
    """[shell] against its approval (PLAN-v4 phase 4): a lower `managed` and
    a new import wait for the user's OK (the approved ones apply meanwhile);
    a higher `managed` and a removed import apply at once."""
    fs = form.shell
    e = EffectiveShell()

    def W(what: str, line: int | None) -> None:
        widen.append(Change("settings", "widen", what, line))

    def N(what: str) -> None:
        narrow.append(Change("settings", "narrow", what))

    a_m = ap["managed"]
    if fs.managed_invalid:
        e.managed = a_m           # a bad value: the approval stays, nothing ratchets
    elif SHELL_RANK[fs.managed] < SHELL_RANK[a_m]:
        W(f'managed shell "{a_m}" -> "{fs.managed}" ('
          + ("Claude's commands run in Claude Code's own shell, with your login setup"
             if fs.managed == "off" else
             "without Claude Code's mods, Claude's commands run in your own shell")
          + ")", fs.line)
        e.managed = a_m
    else:
        if SHELL_RANK[fs.managed] > SHELL_RANK[a_m]:
            N(f'managed shell "{a_m}" -> "{fs.managed}"')
        e.managed = fs.managed
    for p in fs.import_path:
        if p in ap["import_path"]:
            e.import_path.append(p)
        else:
            W(f"PATH import {p} (Claude's commands find the programs in that folder)",
              fs.path_line)
    for p in ap["import_path"]:
        if p not in fs.import_path:
            N(f"PATH import {p} removed")
    for n in fs.import_env:
        if n in ap["import_env"]:
            e.import_env.append(n)
        else:
            W(f"environment import {n} (its value in Claude Code's environment reaches "
              "Claude's commands)", fs.env_line)
    for n in ap["import_env"]:
        if n not in fs.import_env:
            N(f"environment import {n} removed")
    return e


def _narrow_shell(ap: dict[str, Any], form: formmod.Form) -> dict[str, Any]:
    fs = form.shell
    m = ap["managed"]
    if not fs.managed_invalid and SHELL_RANK[fs.managed] > SHELL_RANK[m]:
        m = fs.managed
    return {"managed": m,
            "import_path": [p for p in ap["import_path"] if p in fs.import_path],
            "import_env": [n for n in ap["import_env"] if n in fs.import_env]}


# ---------------------------------------------------------------------------
# Writing approvals
# ---------------------------------------------------------------------------


def _narrow_phase7(out: dict[str, Any], ap: dict[str, Any], h: formmod.Host) -> None:
    keys = formmod.LOCALHOST_POLICY_KEYS if h.is_local else formmod.HOST_POLICY_KEYS
    pol = _policy_narrowed(h.policy, ap.get("policy"), keys, formmod.POLICY_GRANT)
    if pol is not None:
        out["policy"] = pol
    aws = ap.get("workspaces") if isinstance(ap.get("workspaces"), dict) else None
    if aws is not None:
        kept = {}
        for wn, a in aws.items():
            w = h.workspaces.get(wn)
            if not isinstance(a, dict):
                continue
            if w is None:
                # taken out of the form: one that restricts anything stays
                # approved (its removal waits for the user's OK)
                if _ws_restrictions(a) and a.get("root"):
                    kept[wn] = dict(a)
                continue
            y = dict(a)
            p = _policy_narrowed(w.policy, a.get("policy"), formmod.WORKSPACE_POLICY_KEYS, ())
            if p:
                y["policy"] = p
            kept[wn] = y
        out["workspaces"] = kept
    ash = ap.get("shell") if isinstance(ap.get("shell"), dict) else None
    if ash is not None:
        out["shell"] = {k: [x for x in ash.get(k) or [] if x in getattr(h.shell, k)]
                        for k in ("import_path", "import_env")}


def _narrow_host(ap: dict[str, Any], h: formmod.Host) -> dict[str, Any]:
    out = dict(ap)
    for k in ("ssh", "sudo"):
        if k in ap:
            out[k] = rmin(ap.get(k, False), getattr(h, k))
    out["scripts"] = bool(ap.get("scripts")) and h.scripts
    _narrow_phase7(out, ap, h)
    if not h.is_local:
        form_addrs = {a.key(): a for a in h.addresses()}
        kept = []
        for x in ap.get("addresses") or []:
            fa = form_addrs.get(_addr_key(x))
            if fa is None:
                continue
            y = dict(x)
            if fa.when and not x.get("when"):
                y["when"] = fa.when
            kept.append(y)
        out["addresses"] = kept
        if h.via is None and ap.get("via"):
            out["via"] = None
    return out


def _narrow_account(ap: dict[str, Any], a: formmod.Account) -> dict[str, Any]:
    out = dict(ap)
    dests = a.destinations()
    out["destinations"] = [d for d in ap.get("destinations") or [] if d in dests]
    out["use"] = bool(ap.get("use", True)) and a.use
    out["scripts"] = bool(ap.get("scripts")) and a.scripts
    if not a.env:
        out["env"] = None
    pol = _policy_narrowed(a.policy, ap.get("policy"), formmod.ACCOUNT_POLICY_KEYS, ())
    if pol is not None:
        out["policy"] = pol
    return out


def _promotable(data: dict[str, Any], form: formmod.Form) -> tuple[list[str], list[str]]:
    """Imported (from-v2) entries that are now in the form but not approved."""
    imp = imported_rights(data)
    ap = approved_rights(data)
    hosts = [n for n in form.hosts if n in imp["hosts"] and n not in ap["hosts"]]
    accts = [n for n in form.accounts if n in imp["accounts"] and n not in ap["accounts"]]
    return hosts, accts


def needs_sync(data: dict[str, Any] | None, form: formmod.Form) -> bool:
    """Would sync_narrowing change anything?"""
    if data is None or form.syntax_error is not None or not form.exists:
        return False
    h, a = _promotable(data, form)
    return bool(compute(form, data).narrowed or h or a)


def sync_narrowing(data: dict[str, Any], form: formmod.Form) -> list[Change]:
    """Lower the approved snapshot to the form where the form is narrower
    (and drop removed entries and their bindings); move imported (from-v2)
    entries that were copied into the form into the approved snapshot. Never
    widens anything. Disabled entries, a missing form and a form with a
    syntax error are left alone. Returns the narrowings (so callers can close
    ssh masters); the caller saves."""
    if form.syntax_error is not None or not form.exists:
        return []
    eff = compute(form, data)
    p_hosts, p_accts = _promotable(data, form)
    if not eff.narrowed and not p_hosts and not p_accts:
        return []
    ap = approved_rights(data)
    imp_rec = data.get("imported") or {}
    imp = imp_rec.get("rights") if isinstance(imp_rec.get("rights"), dict) else {}
    for name in p_hosts:
        ap["hosts"][name] = copy.deepcopy(imp["hosts"][name])
        del imp["hosts"][name]
    for name in p_accts:
        ap["accounts"][name] = copy.deepcopy(imp["accounts"][name])
        del imp["accounts"][name]
    for name in list(ap.get("hosts", {})):
        if form.is_disabled(name, "hosts"):
            continue
        h = form.hosts.get(name)
        if h is None:
            del ap["hosts"][name]
        else:
            ap["hosts"][name] = _narrow_host(ap["hosts"][name], h)
    for name in list(ap.get("accounts", {})):
        if form.is_disabled(name, "accounts"):
            continue
        a = form.accounts.get(name)
        rec = (data.get("accounts") or {}).get(name)
        if a is None:
            del ap["accounts"][name]
            if rec and rec.get("bound"):
                rec["bound"]["hosts"] = []
        elif ap["accounts"][name].get("kind") == a.kind:
            ap["accounts"][name] = _narrow_account(ap["accounts"][name], a)
            if rec and rec.get("bound"):
                keep = set(ap["accounts"][name]["destinations"])
                rec["bound"]["hosts"] = [d for d in rec["bound"].get("hosts", []) if d in keep]
    settings = dict(ap.get("settings") or {})
    if form.settings.others == "refuse" and not form.settings.others_invalid:
        settings["others"] = "refuse"
    settings["shell"] = _narrow_shell(approved_shell(ap), form)
    ap_pol = settings.get("policy") if isinstance(settings.get("policy"), dict) else {}
    settings["policy"] = _policy_narrowed(form.policy, ap_pol, formmod.GLOBAL_POLICY_KEYS, ()) or {}
    ap["settings"] = settings
    old = (data.get("approved") or {})
    data["approved"] = {"form_sha256": old.get("form_sha256"), "at": old.get("at"), "rights": ap}
    return eff.narrowed


def last_good_ok(form: formmod.Form) -> bool:
    """May this form become the vault's `form_last_good` (the fallback for a
    later syntax error and the copy a deleted form is restored from)? A form
    read from the file that parses (entry problems are fine)."""
    return form.exists and form.syntax_error is None and not form.from_last_good


def ratchet(form: formmod.Form | None = None) -> list[Change]:
    """Persist the narrowings the current form shows (see the module
    docstring for who calls it), and keep the vault's `form_last_good` the
    last valid form seen (review round 2: it was refreshed only at session
    start, so a syntax error dropped this session's entries). Writes only when
    the form is narrower than the approval, an imported entry was copied in,
    or the valid form differs from the stored copy. With no vault yet, a
    narrowing (say `[hosts.localhost] sudo = false` in the starter form)
    creates one, so it outlives a later syntax error or a deleted form.
    Never raises for an unreadable vault (nothing is persisted then)."""
    from . import audit, paths, vault
    if paths.v2_store_path().exists():
        return []
    if not vault.exists():
        if form is None:
            form = formmod.load()
        if not needs_sync(vault.empty(), form):
            return []
        try:
            with vault.locked():
                if not vault.exists():
                    vault.save(vault.empty())
        except vault.VaultError:
            return []
    try:
        data = vault.load()
    except vault.VaultError:
        return []
    if form is None:
        form = formmod.load(last_good=data.get("form_last_good"))
    keep = last_good_ok(form) and data.get("form_last_good") != form.used_text
    if not keep and not needs_sync(data, form):
        return []
    with vault.locked():
        cur = vault.load()
        changes = sync_narrowing(cur, form)
        if changes:
            vault.add_event(cur, "narrow", "; ".join(c.render() for c in changes)[:400])
        if last_good_ok(form):
            cur["form_last_good"] = form.used_text
        vault.save(cur)
    if changes:
        close_masters_for(changes, form)
        audit.log("narrow", changes=[c.render() for c in changes])
    return changes


def close_masters_for(changes: list[Change], form: formmod.Form | None = None) -> list[str]:
    """Close ssh masters for hosts whose address, via or ssh right narrowed
    (or that were removed). Phase B's ssh.close_masters may be a stub."""
    names = []
    for c in changes:
        if c.kind != "narrow" or c.entry in ("localhost", "settings"):
            continue
        if any(w in c.what for w in ("address", "via", "ssh", "host removed")):
            if form is None or c.entry in form.hosts or "removed" in c.what:
                names.append(c.entry)
    closed = []
    for n in dict.fromkeys(names):
        try:
            from . import ssh
            ssh.close_masters(n)
            closed.append(n)
        except NotImplementedError:
            pass
        except Exception:  # noqa: BLE001 - closing is best effort
            pass
    return closed


class ConsentChanged(Exception):
    """The entry's pending changes differ from what the pop-up showed."""


CREDENTIAL_FIELDS = ("token", "ssh_key", "entra", "host_keys")


def drops_credential(data: dict[str, Any] | None, a: formmod.Account) -> bool:
    """Would approving account `a` now drop a credential stored earlier?

    A stored credential belongs to the identity the user approved: the name
    and the kind. An account approved with no earlier approval of that name
    (brand new, or added back after its entry was removed) and no imported 0.6
    snapshot, or one whose kind changed, starts without a credential: the user
    is asked for a fresh secret instead of an old key silently going to the
    new destinations under a "new account" pop-up (review round 2)."""
    rec = ((data or {}).get("accounts") or {}).get(a.name) or {}
    if not any(rec.get(k) for k in CREDENTIAL_FIELDS):
        return False
    snap = (approved_rights(data)["accounts"].get(a.name)
            or imported_rights(data)["accounts"].get(a.name))
    if not isinstance(snap, dict):
        return True
    return snap.get("kind") != a.kind or rec.get("kind") not in (None, a.kind)


def approve(entry: str, changes: list[Change] | list[str] | None = None,
            form: formmod.Form | None = None, *, keep_credentials: bool = False) -> list[str]:
    """Record the user's OK for `entry` (a host, an account, or "settings"):
    its form rights become the approved ones, an account's destinations are
    bound, and a `widen` event is logged. Returns the approved change lines.
    Call only after the consent pop-up (or `gate secret`) said yes, passing the
    changes it showed: if the entry's pending changes are different now (the
    form changed while the pop-up was open), nothing is approved and
    ConsentChanged is raised, so the user is asked again.

    An account that `drops_credential` names loses the credential stored
    earlier (token, ssh key, Entra sign-in, pinned host keys, cached tokens,
    bindings), so the next step asks for a fresh one. `keep_credentials=True`
    only for an import, whose credentials came with the entry the pop-up
    listed."""
    from . import audit, vault
    if isinstance(changes, formmod.Form):  # approve(entry, form) (positional form)
        form, changes = changes, None
    if form is None:
        form = load_form()
    with vault.locked():
        data = vault.load()
        eff = compute(form, data)
        pending = eff.pending_for(entry)
        if changes is not None:
            shown = sorted(c.render() if isinstance(c, Change) else str(c) for c in changes)
            if shown != sorted(c.render() for c in pending):
                raise ConsentChanged(f"gateway: {entry} changed while the dialog was open; "
                                     "nothing was approved (ask again)")
        changes = pending
        ap = approved_rights(data)
        if entry == "settings":
            sh = shell_snapshot(form)
            if form.shell.managed_invalid:      # a bad mode: the approved one stays
                sh["managed"] = approved_shell(ap)["managed"]
            ap["settings"] = {"others": form.settings.others, "shell": sh,
                              "policy": dict(form.policy)}
        elif entry in form.hosts:
            ap["hosts"][entry] = host_snapshot(form.hosts[entry])
        elif entry in form.accounts:
            a = form.accounts[entry]
            if not keep_credentials and drops_credential(data, a):
                old = data["accounts"][entry]
                for k in CREDENTIAL_FIELDS:
                    old.pop(k, None)
                old["bound"] = {"hosts": []}
                vault.cache_clear(entry)
                vault.add_event(data, "forget", f"{entry}: the credential stored before it was "
                                                "approved as a new account was dropped")
            ap["accounts"][entry] = account_snapshot(a)
            rec = vault.account_record(data, entry, a.kind)
            rec["kind"] = a.kind
            b = rec["bound"]
            b["hosts"] = list(dict.fromkeys(list(b.get("hosts") or []) + a.destinations()))
            if a.kind == "api-key":
                b["auth"] = a.auth
            if a.kind == "azure":
                b["tenant"], b["client_id"] = a.tenant, a.client_id
        else:
            raise KeyError(f"{entry} isn't a valid entry in the form")
        data["approved"] = {"form_sha256": form.sha256, "at": vault.now(), "rights": ap}
        if last_good_ok(form):
            data["form_last_good"] = form.used_text
        imp = (data.get("imported") or {}).get("rights")
        if isinstance(imp, dict):
            for sect in ("hosts", "accounts"):
                (imp.get(sect) or {}).pop(entry, None)
        lines = [c.render() for c in changes]
        if changes:
            vault.add_event(data, "widen", "; ".join(lines))
        vault.save(data)
    audit.log("consent", entry=entry, outcome="approved", changes=lines)
    if entry == "settings":
        # the managed shell's files follow at once (an approved import, or a
        # lower mode, applies to the next command)
        try:
            from . import managed
            managed.sync_now()
        except Exception:  # noqa: BLE001 - the next session start writes them anyway
            pass
    return lines


def approve_all(form: formmod.Form | None = None) -> list[str]:
    """Approve every entry as it stands (tests), keeping stored credentials."""
    form = form or load_form()
    out: list[str] = []
    for name in ["settings", *form.hosts, *form.accounts]:
        out += approve(name, form=form, keep_credentials=True)
    return out


def load_form(data: dict[str, Any] | None = None) -> formmod.Form:
    """The form with the vault's last good text as the syntax-error fallback."""
    last = (data or {}).get("form_last_good") if data is not None else None
    if data is None:
        try:
            from . import vault
            if vault.exists():
                last = vault.load().get("form_last_good")
        except Exception:  # noqa: BLE001
            last = None
    return formmod.load(last_good=last)


# ---------------------------------------------------------------------------
# Bindings
# ---------------------------------------------------------------------------


def bound_hosts(data: dict[str, Any], account: str) -> list[str]:
    rec = (data.get("accounts") or {}).get(account) or {}
    return list((rec.get("bound") or {}).get("hosts") or [])


def bound_ok(data: dict[str, Any], account: str, host: str) -> bool:
    """True only if `host` is in the account's vault bound set."""
    return acctmod.covers(bound_hosts(data, account), host)


def unbound(form_account: formmod.Account, data: dict[str, Any]) -> list[str]:
    """Destinations the form computes that the credential isn't bound to."""
    b = bound_hosts(data, form_account.name)
    return [d for d in form_account.destinations() if d not in b]
