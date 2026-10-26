"""Consent: effective rights from the approved snapshot vs the form (SPEC 5,
PLAN-0.11 §1.1 and §2.7).

The vault's `approved.rights` holds what the user last OK'd. On every form
load the gateway computes the effective rights:

- values compare mode by mode in one order, deny < ask < cc < allow <
  unconfigured (modes.RANK): a change is a widening if any mode rises and a
  narrowing if none rises and one falls, and the effective value is the
  per-mode minimum of the form and the approval (a fall applies at once, a
  rise waits for the user's OK, in the same change);
- narrowing (true -> ask -> false, `use = false`, an owner added, a network
  name added to the class, this computer's sudo configured where it wasn't,
  ...) applies at once; sync_narrowing() also lowers the approved snapshot,
  so raising it again later needs the user's OK;
- widening (a new host or account; a right raised in any mode; scripts
  false -> true; a new address/also/via; a new destination such as an
  api-key site, azure workspace/storage/registry/site or account host; an
  account `env` added or changed; a changed api-key `auth` placement, azure
  tenant/client/sign-in/scope; [shell] `managed` lowered
  to "off", a new import_path folder or import_env name; [network] commands
  raised or a name taken out of the class) stays inactive until approve()
  records the user's OK. Meanwhile the entry runs with its last approved
  rights (a brand-new entry: nothing).
- taking a configured target out of the gateway is a widening too (PLAN-0.11
  §1.1): deleting or renaming a [hosts.X] or [accounts.X] table, dropping an
  address, `also` entry or `via` hop, adding or changing `when`, dropping an
  account's owner, host or destination, deleting [hosts.localhost]'s `sudo`
  key. Until the OK the approved entry keeps classifying and gating: a
  removed entry stays in `Effective.hosts` / `accounts` with its approved
  rights (`removed`), a dropped address, destination or owner stays in the
  entry's `held_*` lists and in the configured set.

The configured set (`Effective.configured`, PLAN-0.11 §1.1) is the union of
the form's entries (disabled ones included: a host by the addresses and an
account by the destinations that still parse), the approved snapshot's and
the configured list `private/configured.json`, a non-secret mirror of the
approved snapshot's reach that approve() and ratchet() rewrite whole (under
the vault's lock) and that compute() reads itself when no approval could be
read (load_listed(); a list that can't be read or has the wrong shape
counts as naming this computer's sudo). A configured entry the form doesn't
name while gateway.toml is missing or unreadable (and has no last good
copy), or one only the list names, is refused (`Effective.refused`), never
passed through; so is this computer's sudo where the list says it is
configured or restricted and the form doesn't say so.

A policy table's allow is the user's explicit per-mode allow (lead decision
19.1: on this machine the gateway then approves in that mode), above "no
restriction" (a bare "allow" or no key): gaining it is a widening like any
other (modes.ModeValue.explicit).

Bindings: an account credential goes only to destinations in the vault's
`bound.hosts`; approve() adds the approved destinations there.

Nothing recorded means nothing approved: the approval is an empty form's
(baseline()): no host or account, this computer's sudo not configured.
Writing [hosts.localhost] `sudo` where the approval has none configures it
at once up to "ask" (a narrowing from unconfigured: the gateway's dialog
asks for the password); anything above "ask" waits for the user's OK (`gate
check localhost`) and runs as "ask" meanwhile (a stored password never
reaches a new `true` unasked). While the vault can't be read nothing
approved applies (`compute(..., locked=True)` for a caller that got
vault.VaultLocked: the form's entries are refused with LOCKED_ENTRY); while
it is locked the Bash hook and the sudo stand-in refuse this computer's
configured sudo too, with the vault's own message (PLAN-0.11 §19.16).

Ratchet contract: a narrowing is persisted (the approved snapshot lowered)
by ratchet(), which every process that loads the form should call: SessionStart,
SubagentStart and `gate` (through hooks_session.prepare), the file guard
before an Edit/Write of gateway.toml, and in phase B FileChanged, PostToolUse
(form edits), the Bash hook (commands naming config/gateway) and the
stand-ins. It is cheap when nothing narrowed. A missing form, a syntax error,
a gateway 0.6 vault waiting for its conversion (vault.v06_waiting) and
disabled entries never ratchet.
"""
from __future__ import annotations

import copy
import json
import os
from dataclasses import dataclass, field
from typing import Any

from . import accounts as acctmod
from . import form as formmod
from . import modes
from .modes import ModeValue


class _Rank(dict):
    """RANK: today's vocabulary (False < "ask" < True) and the per-mode words
    (deny < ask < cc < allow < unconfigured) on one scale; True is cc (the
    legacy attributes hold the modeless resolution, allow capped at cc).
    Every lookup, `.get` included, raises KeyError for anything else (an int,
    a table, an unknown word) instead of ranking it as anything."""

    def __getitem__(self, k: Any) -> int:
        if type(k) not in (bool, str) or not dict.__contains__(self, k):
            raise KeyError(f"not a right or a mode word: {k!r}")
        return dict.__getitem__(self, k)

    def get(self, k: Any, default: Any = None) -> int:  # noqa: ARG002 - strict on purpose
        return self[k]


RANK = _Rank({False: 0, "deny": 0, "ask": 1, True: 2, "cc": 2, "allow": 3,
              modes.UNCONFIGURED: 4})
# [shell] managed (PLAN-v4 phase 4, PLAN-0.11 §1.6): "on" is the stricter;
# lowering it widens.
SHELL_RANK = {"off": 0, "on": 1}
SHELL_DEFAULT = {"managed": "on", "import_path": [], "import_env": []}
# A restriction that isn't written restricts nothing (a policy "allow"); a
# grant that isn't written is off.
NO_RESTRICTION = modes.bare("allow", "policy")
GRANT_OFF = modes.bare("deny", "policy")
DENY = modes.bare(False, "right")
ASK = modes.bare("ask", "right")
# The approved snapshot's record that [hosts.localhost] `sudo` was written
# (PLAN-0.11 §1.1); a snapshot from before 0.11 has none: not configured.
SUDO_CONFIGURED = "sudo_configured"


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


# Why a configured entry the form doesn't name is refused while gateway.toml
# is missing or can't be read (PLAN-0.11 §1.1), and why one only the
# configured list names is refused (the vault can't be read).
FORM_GONE = ("gateway.toml is missing or has a mistake; the hosts and accounts it named stay "
             "gated (gate status)")
LISTED_ONLY = ("the gateway's list of configured entries names it, and the vault that holds its "
               "approval can't be read now (locked: /gate-unlock)")
LISTED_SUDO = ("the gateway's list of configured entries says sudo on this computer goes through "
               "the gateway, and the vault that holds its approval can't be read now (locked: "
               "/gate-unlock)")
# Why an entry the form names is refused while the vault can't be read: its
# approval is in the vault ("{name}" is the entry's validated name).
LOCKED_ENTRY = ("{name}'s approval is in the gateway vault, which is locked (the user unlocks it "
                "with /gate-unlock in Claude Code)")
UNREADABLE_ENTRY = ("{name}'s approval is in the gateway vault, which can't be read now "
                    "(gate status)")


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
    return a if RANK[a] <= RANK[b] else b


def word(r: Any) -> str:
    """How a right is written in a message: true, false, "ask" (today's
    vocabulary), "cc" / "allow" / "deny", or a per-mode value's rendering."""
    if isinstance(r, ModeValue):
        return _text(r)
    if r is True or r is False:
        return "true" if r is True else "false"
    RANK[r]
    return f'"{r}"'


def _text(mv: ModeValue | None, none: str = "not configured") -> str:
    """A value in a change line: a bare one as written (true, "allow",
    "ask", ...; an approved one in its kind's words: true / false for a
    right, "allow" / "deny" otherwise), a table as its rendering."""
    if mv is None:
        return none
    snap = mv.snapshot()
    if isinstance(snap, dict):
        return mv.render()
    w = snap
    if isinstance(mv.written, (bool, str)):
        try:
            if modes.bare(mv.written, mv.kind) == mv:
                w = mv.written.strip() if isinstance(mv.written, str) else mv.written
        except modes.ModeError:
            pass
    if mv.kind != "right" and isinstance(w, bool):
        w = "allow" if w else "deny"
    return modes.text_word(w)


# How a per-mode word reads in the consent dialog (PLAN-0.11 §2.8, lead
# decision 4): plain words, never the raw ones, for bare words and tables
# alike. NOW_SAYS is what a mode does after the change, WAS_SAYS what it did
# before. A key with no allow shape of the gateway's (an account's use)
# reads its allow as "Claude Code decides": the dialog never promises an
# approval there.
NOW_SAYS = {"deny": "it is refused", "ask": "you are asked", "cc": "Claude Code decides",
            "allow": "the gateway now approves without asking you",
            modes.UNCONFIGURED: "it doesn't go through the gateway"}
WAS_SAYS = {"deny": "refused", "ask": "asks you", "cc": "Claude Code decides",
            "allow": "the gateway approves", modes.UNCONFIGURED: "not through the gateway"}


def _names(ms: list[str]) -> str:
    """Claude Code's names for some modes: "Auto mode", "Auto and Plan
    modes", "Manual, Plan and Auto modes", "every mode but Plan"."""
    if len(ms) == len(modes.KEYS) - 1:
        return "every mode but " + modes.DISPLAY[next(m for m in modes.KEYS if m not in ms)]
    d = [modes.DISPLAY[m] for m in ms]
    return (d[0] if len(d) == 1 else ", ".join(d[:-1]) + " and " + d[-1]) + \
        (" mode" if len(d) == 1 else " modes")


def _groups(pairs: list[tuple[str, str]]) -> list[tuple[str, list[str]]]:
    """(phrase, modes) for (mode, phrase) pairs, modes alike together, the
    biggest group last (ties in Claude Code's mode order)."""
    g: dict[str, list[str]] = {}
    for m, p in pairs:
        g.setdefault(p, []).append(m)
    return sorted(g.items(), key=lambda kv: (len(kv[1]), modes.KEYS.index(kv[1][0])))


def _mode_clauses(moves: list[tuple[str, str, str]]) -> str:
    """The modes that moved (PLAN-0.11 §2.8, lead decision 4), each (mode,
    what it does now, what it did): modes that moved alike in one clause,
    the biggest group last ("elsewhere" once every mode moved), then what
    they did, once when it was the same everywhere: "in Auto and Bypass
    permissions modes the gateway now approves without asking you;
    elsewhere Claude Code decides (was: asks you in every mode)"."""
    every = {m for m, _n, _w in moves} == set(modes.KEYS)
    now = _groups([(m, n) for m, n, _w in moves])
    was = {m: w for m, _n, w in moves}

    def was_text(ms: list[str]) -> str:
        g = _groups([(m, was[m]) for m in ms])
        all6 = every and len(ms) == len(modes.KEYS)
        if len(g) == 1:
            return g[0][0] + (" in every mode" if all6 else "")
        return ", ".join(f"{w} elsewhere" if all6 and i == len(g) - 1 else f"{w} in {_names(gm)}"
                         for i, (w, gm) in enumerate(g))
    out = []
    for i, (phrase, ms) in enumerate(now):
        if every and len(now) == 1:
            where = "in every mode"
        elif every and i == len(now) - 1:
            where = "elsewhere"
        else:
            where = "in " + _names(ms)
        out.append(f"{where} {phrase}")
    if len({was[m] for m in was}) == 1:
        return "; ".join(out) + f" (was: {was_text(list(was))})"
    return "; ".join(f"{c} (was: {was_text(ms)})" for c, (_p, ms) in zip(out, now))


def _change_text(label: str, f: ModeValue | None, a: ModeValue | None, which: list[str],
                 none: str = "not configured", what: str | None = None,
                 approves: bool = True) -> str:
    """A right's change line (PLAN-0.11 §2.8, lead decision 4), bare words
    and tables alike: WHAT (else the label), then what each mode in `which`
    (the modes that moved) now does, in plain words with Claude Code's mode
    names: `sudo on box: in Auto and Bypass permissions modes the gateway
    now approves without asking you; elsewhere Claude Code decides (was:
    asks you in every mode)`. `approves`: the key has an allow shape
    (rights' ssh and sudo, [network] commands: lead decision 19.1); an
    account's use hasn't (its allow reads as Claude Code decides)."""
    subject = what or label
    if f is None or a is None:
        return f"{subject}: {_text(a, none)} -> {_text(f, none)}"

    def says(w: str, table: dict[str, str]) -> str:
        return table["cc"] if (w == "allow" and not approves) else table[w]

    def now(m: str) -> str:
        fs, as_ = says(f.word(m), NOW_SAYS), says(a.word(m), NOW_SAYS)
        if fs == as_ and f.word(m) != a.word(m):
            # cc -> allow on a key with no allow shape: the same in effect, said so
            return f"{fs}, as an explicit allow (the gateway approves nothing more for it)"
        return fs
    return f"{subject}: " + _mode_clauses(
        [(m, now(m), says(a.word(m), WAS_SAYS)) for m in modes.KEYS if m in which])


def _ap_mode(ap: dict[str, Any], key: str, kind: str, default: ModeValue | None) -> ModeValue | None:
    """An approved value (ModeValue.snapshot's encoding) back; `default` when
    absent; an unreadable value is the strictest reading (deny)."""
    if key not in ap or ap.get(key) is None:
        return default
    mv = modes.from_snapshot(ap[key], kind)
    return mv if mv is not None else modes.uniform("deny", kind)


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------


def _phase7_snapshot(h: formmod.Host, snap: dict[str, Any]) -> dict[str, Any]:
    """PLAN-v4 phase 7's parts of a host's snapshot, each only when present
    (an older approval has none of them): its policy table, its workspaces,
    a remote host's [hosts.NAME.shell] imports."""
    if h.policy is not None:
        snap["policy"] = formmod.policy_snapshot(h.policy, h.policy_modes)
    if h.workspaces:
        snap["workspaces"] = {n: w.snapshot() for n, w in h.workspaces.items()}
    if not h.is_local and (h.shell.import_path or h.shell.import_env):
        snap["shell"] = {"import_path": list(h.shell.import_path),
                         "import_env": list(h.shell.import_env)}
    return snap


def host_snapshot(h: formmod.Host) -> dict[str, Any]:
    if h.is_local:
        sudo = h.mode_value("sudo")
        return _phase7_snapshot(h, {"sudo": sudo.snapshot() if sudo is not None else
                                    formmod.LOCALHOST_SUDO, SUDO_CONFIGURED: sudo is not None,
                                    "scripts": h.scripts})
    snap = {"ssh": h.mode_value("ssh").snapshot(), "sudo": h.mode_value("sudo").snapshot(),
            "scripts": h.scripts, "via": h.via,
            "addresses": [a.snapshot() for a in h.addresses()]}
    if h.runtime:
        snap["runtime"] = h.runtime      # (absent: the default folder; an older approval has none)
    return _phase7_snapshot(h, snap)


def account_snapshot(a: formmod.Account) -> dict[str, Any]:
    snap = {"kind": a.kind, "use": a.mode_value().snapshot(), "scripts": a.scripts,
            "env": a.env or None, "destinations": a.destinations(), "auth": a.auth or None,
            "tenant": a.tenant or None, "client_id": a.client_id or None,
            "sign_in": a.sign_in if a.sign_in == "browser" else None, "scope": a.scope or None,
            "login": a.login or None, "owners": list(a.owners), "default": bool(a.default),
            "any_owner": not a.owners}
    if a.policy is not None:
        snap["policy"] = formmod.policy_snapshot(a.policy, a.policy_modes)
    return snap


def approved_any_owner(ap: dict[str, Any]) -> bool:
    """Does an approved (or listed) account list no `owners`, so that as the
    only account of its kind for a host it covers every owner? Its
    `any_owner`; an approval without one (0.10's records no owners at all):
    whether it lists none, read as account_snapshot reads the form (an
    owner that is its own login still counts as listed)."""
    v = ap.get("any_owner")
    if isinstance(v, bool):
        return v
    return not [o for o in ap.get("owners") or [] if isinstance(o, str)]


SIGN_IN_KEYS = ("kind", "tenant", "client_id", "sign_in", "scope")


def _sign_in_keys(snap: Any) -> tuple[Any, ...] | None:
    """What an approved account's cached tokens were minted for (an
    approval that changes any of these drops them: PLAN-0.11 §19.5)."""
    if not isinstance(snap, dict):
        return None
    return tuple(snap.get(k) or None for k in SIGN_IN_KEYS)


def shell_snapshot(form: formmod.Form) -> dict[str, Any]:
    sh = form.shell
    return {"managed": sh.managed, "import_path": list(sh.import_path),
            "import_env": list(sh.import_env)}


def network_snapshot(form: formmod.Form) -> dict[str, Any]:
    n = form.network
    return {"commands": n.commands.snapshot(), "extra": list(n.extra), "drop": list(n.drop)}


def approved_shell(ap: dict[str, Any]) -> dict[str, Any]:
    """The approved [shell] settings (approved_rights reads only records
    that hold them; anything unreadable is the strict default, managed "on"
    and no imports; an approved "warn" from 0.9 or 0.10 is "on")."""
    sh = (ap.get("settings") or {}).get("shell")
    if not isinstance(sh, dict):
        return copy.deepcopy(SHELL_DEFAULT)
    m = sh.get("managed")
    return {"managed": m if m in SHELL_RANK else "on",
            "import_path": [x for x in sh.get("import_path") or [] if isinstance(x, str)],
            "import_env": [x for x in sh.get("import_env") or [] if isinstance(x, str)]}


def approved_network(ap: dict[str, Any]) -> tuple[ModeValue, list[str], list[str]]:
    """The approved [network] (commands, extra, drop): "ask" and no names
    when none was approved; an unreadable commands value reads as deny."""
    nt = (ap.get("settings") or {}).get("network")
    if not isinstance(nt, dict):
        return modes.bare(formmod.NETWORK_DEFAULT, "network"), [], []
    cmd = _ap_mode(nt, "commands", "network", modes.bare(formmod.NETWORK_DEFAULT, "network"))
    assert cmd is not None

    def names(k: str) -> list[str]:
        v = nt.get(k)
        return [x for x in v if formmod.network_name(x) == x] if isinstance(v, list) else []
    return cmd, names("extra"), names("drop")


def network_words(eff: "Effective") -> str:
    """$DATA/network-words' text: the class's names beyond the built-in ones
    (pre_bash.sh has those; reserved names are shapes, not words), one per
    line, sorted."""
    names = sorted(n for n in eff.network.names()
                   if n not in formmod.NETWORK_BUILTIN and n not in formmod.NETWORK_RESERVED
                   and formmod.network_name(n) == n)
    return "".join(f"{n}\n" for n in names)


# The account kinds each account CLI stand-in serves (clis.py's tools)
CLI_KINDS = {"gh": ("github",), "hf": ("huggingface",), "databricks": ("azure",),
             "crane": ("github", "azure", "registry"), "pijul": ("pijul",), "az": ("azure",)}
ASK_CLIS = ("gh", "hf", "databricks", "crane", "pijul")


def account_ask_verb(eff: Any, name: str, mode: str | None) -> str | None:
    """"use" or "credential" when account `name` is "ask" in `mode` (its
    use, else its credential policy: policy.decide), else None."""
    from . import policy
    try:
        if eff.word(name, "use", mode) == "ask":
            return "use"
        if policy.decide(eff, "credential", account=name, mode=mode).word == "ask":
            return "credential"
    except (AttributeError, KeyError, ValueError):
        return None
    return None


def ask_clis(eff: "Effective") -> str:
    """$DATA/ask-clis' text: the account CLIs (ASK_CLIS) whose kinds have an
    account that is "ask" (its use, or its credential policy) in some mode,
    one per line. pre_bash.sh sends a plain call of only those to the Bash
    hook, which asks about the account and records the command (lead
    decision 19.14); the others cost no Python start."""
    out = []
    for tool in ASK_CLIS:
        kinds = CLI_KINDS.get(tool, ())
        if any(ea.kind in kinds and account_ask_verb(eff, n, m)
               for n, ea in eff.accounts.items() for m in modes.KEYS):
            out.append(tool)
    return "".join(f"{n}\n" for n in out)


def _write_whole(p: "os.PathLike[str]", text: str) -> None:
    from pathlib import Path
    p = Path(p)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, p)


def sync_network_words(eff: "Effective") -> bool:
    """Keep $DATA/network-words (PLAN-0.11 §3.4; WS-3's named edit) for
    pre_bash.sh's prefilter, which adds its names to its trigger words:
    written whole (a temp file, then a rename) whenever its text changes or
    gateway.toml is newer than it. pre_bash.sh sends every call to Python
    while gateway.toml is newer (a hand edit's new names reach the hook
    before anything rewrote the file), so the file's time is brought up to
    the form's even when the text is the same. pre_bash.sh compares the two
    through $DATA/network-form, a symlink to gateway.toml kept here (no
    home lookup in sh). $DATA/ask-clis (ask_clis) is kept the same way,
    written first, so it is current whenever network-words is. Called
    wherever the stand-ins are synced (every process that loads the form:
    SessionStart, the Bash hook, FileChanged, PostToolUse after an edit,
    approve). Never raises; True when it wrote network-words."""
    from . import paths
    try:
        if not eff.unreadable:         # (a locked vault keeps the last list)
            ap = paths.ask_clis_path()
            at = ask_clis(eff)
            try:
                acur: str | None = ap.read_text(encoding="utf-8")
            except OSError:
                acur = None
            if acur != at:
                _write_whole(ap, at)
    except Exception:  # noqa: BLE001 - the next form load writes it
        pass
    try:
        text = network_words(eff)
        p = paths.network_words_path()
        form = str(paths.form_path())
        link = paths.network_form_link()
        try:
            cur, have = p.read_text(encoding="utf-8"), p.stat().st_mtime_ns
        except OSError:
            cur, have = None, None
        try:
            form_ns: int | None = os.stat(form).st_mtime_ns
        except OSError:
            form_ns = None
        try:
            linked = os.readlink(link) == form
        except OSError:
            linked = False
        if cur == text and have is not None and linked and (form_ns is None or form_ns <= have):
            return False
        p.parent.mkdir(parents=True, exist_ok=True)
        if not linked:
            tl = link.with_name(f".network-form.{os.getpid()}.tmp")
            if os.path.lexists(tl):
                tl.unlink()
            os.symlink(form, tl)
            os.replace(tl, link)
        tmp = p.with_name(f".network-words.{os.getpid()}.tmp")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, p)
        if form_ns is not None and p.stat().st_mtime_ns < form_ns:
            os.utime(p, ns=(form_ns, form_ns))     # a form dated ahead: never newer again
        return True
    except Exception:  # noqa: BLE001 - the next form load writes it; pre_bash.sh forwards meanwhile
        return False


def snapshot(form: formmod.Form) -> dict[str, Any]:
    return {"settings": {"shell": shell_snapshot(form),
                         "policy": formmod.policy_snapshot(form.policy, form.policy_modes),
                         "network": network_snapshot(form)},
            "hosts": {n: host_snapshot(h) for n, h in form.hosts.items()},
            "accounts": {n: account_snapshot(a) for n, a in form.accounts.items()}}


def baseline() -> dict[str, Any]:
    """The rights of an empty form: what counts as approved when nothing is
    recorded (no entry; this computer's sudo not configured)."""
    from pathlib import Path
    return snapshot(formmod.parse_text("", Path("gateway.toml")))


def approved_rights(data: dict[str, Any] | None) -> dict[str, Any]:
    """The approved snapshot, or baseline() (nothing approved). Approvals
    recorded by gateway 0.9 and 0.10 are read (they have the same shape, so
    an upgrade from the last release keeps them: no [network], no
    `sudo_configured`, no `any_owner`; see approved_network,
    SUDO_CONFIGURED, approved_any_owner); nothing older: a record without
    `settings.shell`, which every snapshot since PLAN-v4 phase 4 (0.9.0)
    holds, counts as nothing approved (its entries wait for the user's OK
    again)."""
    ap = ((data or {}).get("approved") or {}).get("rights")
    if not isinstance(ap, dict) or not isinstance(ap.get("settings"), dict) \
            or not isinstance(ap["settings"].get("shell"), dict):
        return baseline()
    ap = copy.deepcopy(ap)
    ap.setdefault("settings", {})
    ap.setdefault("hosts", {})
    ap.setdefault("accounts", {})
    return ap


# ---------------------------------------------------------------------------
# The configured set (PLAN-0.11 §1.1)
# ---------------------------------------------------------------------------


@dataclass
class ConfiguredAccount:
    """What one configured account reaches (the union over its sources):
    destinations (the account's `host` included), its ssh endpoints' hosts,
    who it routes for (login and owners, lowercased), whether it is the
    default for its hosts (a disabled or list-only one counts as default:
    every owner there stays gated), and whether some source lists no
    `owners` for it (any_owner: only then does the only account of its kind
    for a host cover every owner, accounts.owner_covered)."""
    name: str
    kind: str
    destinations: list[str] = field(default_factory=list)
    ssh_hosts: list[str] = field(default_factory=list)
    owners: list[str] = field(default_factory=list)
    default: bool = False
    any_owner: bool = False


@dataclass
class Configured:
    """The configured set: hosts (name -> every address that classifies),
    accounts (name -> its reach under the first kind seen: the form's, else
    the approval's, else the list's; `other_kinds` holds the same name's
    reach under another kind, as after a kind change waiting for the OK),
    whether this computer's sudo is configured, whether an elevation
    restriction ("deny" or "ask" in any mode) applies to this computer, the
    disabled entries, and where each entry comes from ("form", "approved",
    "list")."""
    hosts: dict[str, list[formmod.Address]] = field(default_factory=dict)
    accounts: dict[str, ConfiguredAccount] = field(default_factory=dict)
    localhost_sudo: bool = False
    local_elevation: bool = False
    disabled: set[str] = field(default_factory=set)
    sources: dict[str, set[str]] = field(default_factory=dict)
    other_kinds: list[ConfiguredAccount] = field(default_factory=list)

    def __contains__(self, name: object) -> bool:
        return name in self.hosts or name in self.accounts or name in self.disabled

    def names(self) -> list[str]:
        return list(dict.fromkeys([*self.hosts, *self.accounts, *sorted(self.disabled)]))

    def reaches(self) -> list[ConfiguredAccount]:
        """Every account reach: one per name and kind."""
        return [*self.accounts.values(), *self.other_kinds]

    def host_words(self) -> dict[str, str]:
        """Lowercased host words (name, gw-NAME, every address and also host)
        -> the configured host's name."""
        out: dict[str, str] = {}
        for n in self.hosts:              # a host's own name first: [hosts.gw-foo] beats foo's alias
            out.setdefault(_norm_host(n), n)
        for n, addrs in self.hosts.items():
            for w in [f"gw-{n}", *(a.host for a in addrs)]:
                out.setdefault(_norm_host(w), n)
        return out

    def host_named(self, word: str) -> str | None:
        """The configured host a destination word names (its name, gw-NAME,
        an address or `also` host), else None."""
        if not isinstance(word, str) or not word:
            return None
        return self.host_words().get(_norm_host(word))

    def accounts_for(self, host: str) -> list[ConfiguredAccount]:
        """The configured accounts whose destinations or ssh endpoints cover
        `host`."""
        h = _norm_host(host)
        return [a for a in self.reaches()
                if h in a.ssh_hosts or acctmod.covers(a.destinations, host)]

    def git_targets(self) -> Any:
        """The configured set as gitroute sees it (one reach per entry and
        kind)."""
        from . import gitroute
        return gitroute.Targets(
            hosts=self.host_words(),
            accounts=tuple(gitroute.AccountReach(
                name=a.name, kind=a.kind, dests=tuple(d.lower() for d in a.destinations),
                ssh_hosts=tuple(a.ssh_hosts), owners=tuple(a.owners), default=a.default,
                any_owner=a.any_owner)
                for a in self.reaches()))


def _norm_host(h: str) -> str:
    h = h.strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h


def _snap_addresses(ap: dict[str, Any]) -> list[formmod.Address]:
    out = []
    for x in ap.get("addresses") or []:
        if isinstance(x, dict) and isinstance(x.get("host"), str):
            try:
                out.append(formmod.Address(host=x["host"].lower(), port=int(x.get("port") or 22),
                                           user=x.get("user") if isinstance(x.get("user"), str)
                                           else None, when=x.get("when") or None))
            except (TypeError, ValueError):
                continue
    return out


def _reach_account(name: str, kind: str, dests: list[str], login: str = "",
                   owners: list[str] | None = None, default: bool = False) -> formmod.Account:
    """An Account standing for an approved or listed entry: one whose
    destinations() and ssh_endpoints() give back what was recorded (the
    destinations decide its `host`, `packages` and `sites`)."""
    a = formmod.Account(name=name, kind=kind, login=login or "", owners=list(owners or []),
                        default=default)
    if kind == "github":
        a.host = dests[0] if dests else "github.com"
        a.packages = "ghcr.io" in dests
    elif kind in ("ml-catalog", "pijul", "registry"):
        a.host = dests[0] if dests else ""
    elif kind == "azure":
        a.sites = [d for d in dests if d not in acctmod.FIXED_AZURE]
    elif kind == "api-key":
        a.sites = list(dests)
    return a


def _add_account(c: Configured, name: str, kind: str, dests: list[str], ssh_hosts: list[str],
                 owners: list[str], default: bool, source: str, any_owner: bool = True) -> None:
    ca = c.accounts.get(name)
    if ca is None:
        ca = c.accounts[name] = ConfiguredAccount(name=name, kind=kind)
    elif ca.kind != kind:
        # another kind under the same name (a kind change waiting for the
        # OK): a reach of its own, never one account sending to both kinds'
        # destinations
        ca = next((x for x in c.other_kinds if x.name == name and x.kind == kind), None)
        if ca is None:
            ca = ConfiguredAccount(name=name, kind=kind)
            c.other_kinds.append(ca)
    for d in dests:
        if d not in ca.destinations:
            ca.destinations.append(d)
    for h in ssh_hosts:
        if h.lower() not in ca.ssh_hosts:
            ca.ssh_hosts.append(h.lower())
    for o in owners:
        if o and o.lower() not in ca.owners:
            ca.owners.append(o.lower())
    ca.default = ca.default or default
    ca.any_owner = ca.any_owner or any_owner      # the union: covered while any source covers it
    c.sources.setdefault(name, set()).add(source)


def _add_host(c: Configured, name: str, addrs: list[formmod.Address], source: str) -> None:
    have = c.hosts.setdefault(name, [])
    keys = {(a.key(), a.when) for a in have}
    for a in addrs:
        if (a.key(), a.when) not in keys:
            have.append(a)
            keys.add((a.key(), a.when))
    c.sources.setdefault(name, set()).add(source)


def _elevation_restricted(*pols: Any) -> bool:
    """Does any of these policy tables (snapshot encodings, legacy words or
    ModeValues) restrict elevation ("deny" or "ask" in some mode)?"""
    for p in pols:
        if not isinstance(p, dict) or p.get("elevation") is None:
            continue
        v = p["elevation"]
        mv = v if isinstance(v, ModeValue) else modes.from_snapshot(v, "policy")
        if mv is None or any(modes.RANK[w] <= modes.RANK["ask"] for w in mv.words):
            return True
    return False


def _items(v: Any) -> Any:
    return v.items() if isinstance(v, dict) else ()


def _add_rights(c: Configured, rights: dict[str, Any], source: str) -> None:
    """The approved snapshot's (or the configured list's) entries."""
    for name, h in _items(rights.get("hosts")):
        if not isinstance(h, dict) or not isinstance(name, str):
            continue
        if name == "localhost":
            c.localhost_sudo = c.localhost_sudo or h.get(SUDO_CONFIGURED) is True
            c.local_elevation = c.local_elevation or _elevation_restricted(h.get("policy"))
            continue
        _add_host(c, name, _snap_addresses(h), source)
    for name, a in _items(rights.get("accounts")):
        if not isinstance(a, dict) or not isinstance(name, str) or a.get("kind") not in formmod.KINDS:
            continue
        dests = [d for d in a.get("destinations") or [] if isinstance(d, str)]
        owners = [o for o in a.get("owners") or [] if isinstance(o, str)]
        login = a.get("login") if isinstance(a.get("login"), str) else ""
        acct = _reach_account(name, a["kind"], dests, login, owners)
        ssh_hosts = [x for x in a.get("ssh_hosts") or [] if isinstance(x, str)] or \
            [h for _u, h in acctmod.ssh_endpoints(acct)]
        # an older approval doesn't say who the account routes for: every owner
        _add_account(c, name, a["kind"], dests, ssh_hosts, ([login] if login else []) + owners,
                     bool(a.get("default")) or "owners" not in a, source,
                     any_owner=approved_any_owner(a))
    st = rights.get("settings") if isinstance(rights.get("settings"), dict) else {}
    c.local_elevation = c.local_elevation or _elevation_restricted(st.get("policy"))
    if rights.get("localhost_sudo") is True:
        c.localhost_sudo = True
    if rights.get("local_elevation") is True:
        c.local_elevation = True


def _configured(form: formmod.Form, ap: dict[str, Any] | None,
                listed: dict[str, Any] | None) -> Configured:
    c = Configured()
    for name, h in form.hosts.items():
        if h.is_local:
            c.localhost_sudo = c.localhost_sudo or h.sudo_configured
            c.local_elevation = c.local_elevation or _elevation_restricted(h.policy_modes)
            continue
        _add_host(c, name, h.addresses(), "form")
    for name, a in form.accounts.items():
        _add_account(c, name, a.kind, a.destinations(), [x for _u, x in a.ssh_endpoints()],
                     a.owner_names(), bool(a.default), "form", any_owner=not a.owners)
    c.local_elevation = c.local_elevation or _elevation_restricted(form.policy_modes)
    # a disabled entry (a mistake in it) stays configured and is refused: a
    # host by its name and the addresses that still parse; an account whose
    # kind could be read by its own destinations and endpoints as far as they
    # still parse (form._lenient_account), for every owner
    for name in form.disabled:
        if name == "localhost":
            c.localhost_sudo = True
            continue
        c.disabled.add(name)
        kind = form.disabled_kinds.get(name)
        if kind and form.is_disabled(name, "accounts"):
            acct = form.disabled_accounts.get(name) or formmod.Account(name=name, kind=kind)
            _add_account(c, name, kind, acct.destinations(), [x for _u, x in acct.ssh_endpoints()],
                         [], True, "form")
        elif form.is_disabled(name, "hosts") and name not in form.hosts:
            _add_host(c, name, form.disabled_addresses.get(name, []), "form")
    if ap is not None:
        _add_rights(c, ap, "approved")
    if listed is not None:
        _add_rights(c, listed, "list")
    return c


def configured_list(rights: dict[str, Any]) -> dict[str, Any]:
    """The configured list (private/configured.json) for an approved
    snapshot: entry names, addresses, via, account kinds, destinations, ssh
    hosts, owners, whether this computer's sudo is configured and whether an
    elevation restriction applies here. Nothing secret."""
    c = Configured()
    _add_rights(c, rights, "approved")
    hosts = {}
    for name, h in _items(rights.get("hosts")):
        if name == "localhost" or not isinstance(h, dict):
            continue
        hosts[name] = {"addresses": [a.snapshot() for a in _snap_addresses(h)],
                       "via": h.get("via") if isinstance(h.get("via"), str) else None}
    accts = {}
    for name, ca in c.accounts.items():
        accts[name] = {"kind": ca.kind, "destinations": list(ca.destinations),
                       "ssh_hosts": list(ca.ssh_hosts), "owners": list(ca.owners),
                       "default": ca.default, "any_owner": ca.any_owner}
    return {"version": 1, "hosts": hosts, "accounts": accts, "localhost_sudo": c.localhost_sudo,
            "local_elevation": c.local_elevation}


# A configured list that is there but can't be read or has the wrong shape:
# what it named can't be known, so this computer's sudo and elevation count as
# configured (refused while the vault can't be read); the next ratchet with a
# readable vault writes it again.
BROKEN_LIST = {"version": 1, "hosts": {}, "accounts": {}, "localhost_sudo": True,
               "local_elevation": True, "broken": True}


def clean_listed(d: Any) -> dict[str, Any]:
    """A configured list in its own shape: entries that don't fit are
    dropped, and a list that isn't one at all (not a version-1 table) is
    BROKEN_LIST. Never raises."""
    if not isinstance(d, dict) or d.get("version") != 1:
        return copy.deepcopy(BROKEN_LIST)
    hosts: dict[str, Any] = {}
    raw_h = d.get("hosts")
    for n, h in (raw_h.items() if isinstance(raw_h, dict) else ()):
        if isinstance(n, str) and formmod.NAME_RE.fullmatch(n) and isinstance(h, dict):
            addrs = h.get("addresses")
            hosts[n] = {"addresses": [x for x in addrs if isinstance(x, dict)]
                        if isinstance(addrs, list) else [],
                        "via": h.get("via") if isinstance(h.get("via"), str) else None}
    accts: dict[str, Any] = {}
    raw_a = d.get("accounts")
    for n, a in (raw_a.items() if isinstance(raw_a, dict) else ()):
        if not (isinstance(n, str) and formmod.NAME_RE.fullmatch(n) and isinstance(a, dict)
                and a.get("kind") in formmod.KINDS):
            continue

        def strs(k: str, a: dict[str, Any] = a) -> list[str]:
            v = a.get(k)
            return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []
        accts[n] = {"kind": a["kind"], "destinations": strs("destinations"),
                    "ssh_hosts": strs("ssh_hosts"), "owners": strs("owners"),
                    "default": a.get("default") is True,
                    # (an older list doesn't say: it covers every owner)
                    "any_owner": a.get("any_owner") is not False}
    out = {"version": 1, "hosts": hosts, "accounts": accts,
           "localhost_sudo": d.get("localhost_sudo") is True,
           "local_elevation": d.get("local_elevation") is True}
    if (not isinstance(raw_h, (dict, type(None))) or not isinstance(raw_a, (dict, type(None)))
            or d.get("broken") is True):
        out.update(localhost_sudo=True, local_elevation=True, broken=True)
    return out


def load_listed() -> dict[str, Any] | None:
    """The configured list (clean_listed), or None when there is none.
    compute() reads it itself when the vault can't be read."""
    from . import paths
    try:
        raw = paths.configured_path().read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except (OSError, ValueError, paths.PathError):
        return copy.deepcopy(BROKEN_LIST)
    try:
        return clean_listed(json.loads(raw))
    except ValueError:
        return copy.deepcopy(BROKEN_LIST)


def write_listed(rights: dict[str, Any]) -> bool:
    """Rewrite private/configured.json whole for this approved snapshot (temp
    file, then rename; 0600). False when nothing was written (unchanged, or
    the folder can't be written: the list is a fallback, never a reason to
    fail an approval)."""
    from . import paths
    want = configured_list(rights)
    if load_listed() == want:
        return False
    try:
        p = paths.configured_path()
        paths.ensure_private()
        tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(want, f, sort_keys=True)
            os.replace(tmp, p)
        finally:
            if tmp.exists():
                tmp.unlink()
    except (OSError, paths.PathError):
        return False
    return True


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
    ssh: Any = False                  # today's vocabulary, for compute()'s mode
    sudo: Any = False
    scripts: bool = False
    addresses: list[formmod.Address] = field(default_factory=list)
    via: str | None = None
    runtime: str | None = None        # the approved runtime folder (None: the default)
    new: bool = False                 # not approved at all yet
    pending: list[Change] = field(default_factory=list)
    host: formmod.Host | None = None  # the form entry (a removed one: rebuilt from its approval)
    # PLAN-v4 phase 7: the effective policy keys (a restriction absent: none;
    # a grant absent: off), the approved workspaces, a remote host's imports
    policy: dict[str, Any] = field(default_factory=dict)
    workspaces: dict[str, "EffectiveWorkspace"] = field(default_factory=dict)
    import_path: list[str] = field(default_factory=list)
    import_env: list[str] = field(default_factory=list)
    # PLAN-0.11: ssh and sudo per mode (no "sudo" for this computer's
    # unconfigured sudo), the policy per mode, a host the form no longer
    # names whose approval keeps gating until the OK, and approved addresses
    # the form dropped (they still classify)
    modes: dict[str, ModeValue] = field(default_factory=dict)
    policy_modes: dict[str, ModeValue] = field(default_factory=dict)
    removed: bool = False
    held_addresses: list[formmod.Address] = field(default_factory=list)

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
    sign_in: str | None = None       # PLAN-0.11 §7: "browser", or None (a service principal)
    scope: str | None = None
    new: bool = False
    pending: list[Change] = field(default_factory=list)
    account: formmod.Account | None = None
    policy: dict[str, Any] = field(default_factory=dict)     # PLAN-v4 phase 7
    # PLAN-0.11: use per mode, the policy per mode, an account the form no
    # longer names (its approval keeps gating until the OK), and approved
    # destinations and owners the form dropped (they still classify)
    modes: dict[str, ModeValue] = field(default_factory=dict)
    policy_modes: dict[str, ModeValue] = field(default_factory=dict)
    removed: bool = False
    held_destinations: list[str] = field(default_factory=list)
    held_owners: list[str] = field(default_factory=list)

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
    policy_modes: dict[str, ModeValue] = field(default_factory=dict)


@dataclass
class EffectiveShell:
    """The managed shell as it applies now: the stricter mode of form and
    approval, and the imports that are in both."""
    managed: str = "on"
    import_path: list[str] = field(default_factory=list)
    import_env: list[str] = field(default_factory=list)


@dataclass
class EffectiveNetwork:
    """[network] as it applies now (PLAN-0.11 §3.2): commands per mode (the
    per-mode minimum of form and approval), the names added to the class
    (approved or written: a name joins at once) and the names taken out
    (only those both approved and written)."""
    commands: ModeValue = field(default_factory=lambda: modes.bare(formmod.NETWORK_DEFAULT,
                                                                     "network"))
    extra: list[str] = field(default_factory=list)
    drop: list[str] = field(default_factory=list)

    def names(self) -> set[str]:
        """The class's names: the built-ins and reserved names plus extra,
        minus drop, without letter case (a program name runs in any case
        where the file system ignores it)."""
        return (set(formmod.NETWORK_BUILTIN) | set(formmod.NETWORK_RESERVED)
                | {x.lower() for x in self.extra}) - {x.lower() for x in self.drop}

    def word(self, mode: str | None = None) -> str:
        return self.commands.word(mode)


@dataclass
class Effective:
    form: formmod.Form
    shell: EffectiveShell = field(default_factory=EffectiveShell)
    hosts: dict[str, EffectiveHost] = field(default_factory=dict)
    accounts: dict[str, EffectiveAccount] = field(default_factory=dict)
    pending: list[Change] = field(default_factory=list)     # widenings waiting for OK
    narrowed: list[Change] = field(default_factory=list)    # narrowings vs approved
    approved: dict[str, Any] = field(default_factory=dict)
    policy: dict[str, Any] = field(default_factory=dict)    # [policy] as it applies (phase 7)
    # PLAN-0.11: the mode the legacy attributes were resolved for (None: the
    # modeless rule), [policy] per mode, [network], the configured set, the
    # configured entries refused outright (name -> why), and whether
    # gateway.toml is missing or unreadable with no last good copy
    mode: str | None = None
    policy_modes: dict[str, ModeValue] = field(default_factory=dict)
    network: EffectiveNetwork = field(default_factory=EffectiveNetwork)
    configured: Configured = field(default_factory=Configured)
    refused: dict[str, str] = field(default_factory=dict)
    form_gone: bool = False
    # the vault exists (or the caller says it is locked) but its approval
    # couldn't be read, and whether that is because it is locked
    unreadable: bool = False
    locked: bool = False

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

    def word(self, entry: str, key: str, mode: str | None = None) -> str:
        """The per-mode word of a right (PLAN-0.11 §2.6): a host's "ssh" or
        "sudo", an account's "use", in `mode` (None: the modeless rule):
        deny, ask, cc or allow; "unconfigured" for a target the configured
        set doesn't name (this computer's sudo when it isn't configured).
        A configured entry that is new, disabled or refused is deny."""
        if key in ("ssh", "sudo"):
            e = self.hosts.get(entry)
            if e is None:
                return "deny" if (entry in self.configured or entry in self.refused) \
                    else modes.UNCONFIGURED
            if e.new:
                return "deny"
            mv = e.modes.get(key)
            if mv is None:
                return modes.UNCONFIGURED if (e.is_local and key == "sudo") else "deny"
            return mv.word(mode)
        if key == "use":
            a = self.accounts.get(entry)
            if a is None:
                return "deny" if (entry in self.configured or entry in self.refused) \
                    else modes.UNCONFIGURED
            if a.new:
                return "deny"
            mv = a.modes.get("use")
            return mv.word(mode) if mv is not None else "deny"
        raise KeyError(key)

    def refusal(self, name: str) -> str | None:
        """Why a configured entry is refused outright, or None: off because
        of a mistake in it, gateway.toml missing or unreadable, only the
        configured list names it while the vault can't be read, its approval
        unreadable (the vault locked or broken), or waiting for the user's
        OK as a new entry."""
        if name in self.refused:
            return self.refused[name]
        e = self.hosts.get(name) or self.accounts.get(name)
        if e is not None and e.new:
            if self.unreadable:
                return (LOCKED_ENTRY if self.locked else UNREADABLE_ENTRY).format(name=name)
            return f"{name} waits for the user's OK (gate check {name})"
        return None

    def pending_for(self, name: str) -> list[Change]:
        return [c for c in self.pending if c.entry == name]

    def pending_names(self) -> list[str]:
        return list(dict.fromkeys(c.entry for c in self.pending))


def _addr_key(d: dict[str, Any]) -> tuple[str, str, int]:
    return (str(d.get("user")), str(d.get("host")), int(d.get("port") or 22))


def _covered(fa: formmod.Address, approved: list[dict[str, Any]]) -> bool:
    """The form's address is approved as written, its `when` included (a
    `when` added, changed or removed waits for the OK)."""
    for ap in approved:
        if _addr_key(ap) == fa.key() and (ap.get("when") or None) == fa.when:
            return True
    return False


def _snap_address(d: dict[str, Any]) -> formmod.Address:
    return formmod.Address(host=d["host"], port=int(d.get("port") or 22), user=d.get("user"),
                           when=d.get("when") or None)


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


def _ptext(v: ModeValue | None, grant: bool) -> str:
    if v is None:
        return "off" if grant else "unrestricted"
    snap = v.snapshot()
    if not isinstance(snap, dict):
        return f'"{formmod.policy_text(snap) if snap in (True, False) else snap}"'
    return v.render()


# The policy keys whose explicit per-mode allow on this machine (its own
# table or [policy]) the gateway approves with (lead decision 19.1): network,
# for the http and download tools (hooks_mcp; network commands need
# [network] commands' own allow too). For the others an explicit allow
# restricts nothing and approves nothing, and the dialog says so.
POLICY_APPROVES = ("network",)
POLICY_SAYS = {"network": "the http and download tools"}


def _pword(v: ModeValue, m: str, grant: bool, approves: bool = False, now: bool = True,
           what: str = "") -> str:
    """A policy value's word in one mode for a change line, in plain words
    (§2.8, lead decision 4): what the mode does now (`now`) or did before. A
    restriction's plain allow is "no restriction", an explicit one (a
    table's) the gateway's approval of WHAT where it approves (`approves`:
    this machine's keys and [policy]), else no restriction too; a grant's
    allow is on, its deny off."""
    w = v.word(m)
    if grant and w in ("allow", "deny"):
        return ("it is " if now else "") + ("on" if w == "allow" else "off")
    if w == "allow":
        if m in v.explicit:
            if approves:
                return (f"the gateway now approves {what} without asking you" if now
                        else f"the gateway approves {what}")
            return "no restriction, as an explicit allow"
        return "no restriction"
    return (NOW_SAYS if now else WAS_SAYS)[w]


def _policy_change(label: str, fv: ModeValue | None, av: ModeValue | None, fm: ModeValue,
                   am: ModeValue, which: list[str], grant: bool, approves: bool = False,
                   what: str = "") -> str:
    """A policy key's change line (§2.8, lead decision 4), bare words and
    tables alike (an absent key: no restriction, or a grant off): the label,
    then what each mode in `which` now does, in plain words. With `approves`
    (this machine's keys and [policy]), a mode gaining the user's explicit
    allow says that the gateway will then approve WHAT without asking."""
    what = what or label
    return f"{label}: " + _mode_clauses(
        [(m, _pword(fm, m, grant, approves, True, what), _pword(am, m, grant, approves, False, what))
         for m in modes.KEYS if m in which])


def _ap_policy(a: dict[str, Any], k: str) -> ModeValue | None:
    return _ap_mode(a, k, "policy", None)


def policy_compare(f: dict[str, ModeValue] | None, a: dict[str, Any] | None,
                   keys: tuple[str, ...], grants: tuple[str, ...], label: str, W: Any,
                   N: Any, approves: bool = False) -> dict[str, ModeValue]:
    """One policy table (the form's per-mode values) against its approval
    (snapshot encodings), mode by mode (PLAN-v4 phase 7, PLAN-0.11 §2.7): a
    key raised in any mode (or a restriction removed, or a grant turned on)
    waits for the user's OK and the approved value applies there meanwhile;
    a key lowered applies at once. A restriction absent means none (as
    permissive as a bare "allow"); a grant absent means off ("deny"). A
    table's allow is the user's explicit one (lead decision 19.1: on this
    machine the gateway approves there), above "no restriction": gaining it
    in a mode is a widening, and until the OK the effective value's allow
    there is a plain one (ModeValue.rises / minimum). `approves`: this
    machine's keys and [policy], whose change lines say so. Returns the
    effective keys per mode (absent restrictions and grants that are off are
    left out)."""
    f = f or {}
    a = a or {}
    out: dict[str, ModeValue] = {}
    for k in keys:
        grant = k in grants
        base = GRANT_OFF if grant else NO_RESTRICTION
        fv, av = f.get(k), _ap_policy(a, k)
        fm, am = fv or base, av or base
        up, down = fm.rises(am), fm.falls(am)
        appr = approves and k in POLICY_APPROVES
        about = f"{POLICY_SAYS.get(k, k)} on this computer"
        if up:
            what = _policy_change(f"{label}{k}", fv, av, fm, am, up, grant, appr, about)
            if grant:
                what += f" ({GRANT_WORDS.get(k, k)})"
            W(what)
        if down:
            N(_policy_change(f"{label}{k}", fv, av, fm, am, down, grant, appr, about))
        ev = fm.minimum(am)
        if ev != base:          # (equality counts explicitness: an explicit table stays)
            out[k] = ev
    return out


def _legacy_policy(pm: dict[str, ModeValue], mode: str | None) -> dict[str, Any]:
    """The legacy policy dict (True / "ask" / False) for `mode`."""
    return {k: v.legacy(mode) for k, v in pm.items()}


def _restricts(mv: ModeValue | None) -> bool:
    """A workspace restriction that lowers something ("ask", "deny" or "cc"
    in a mode where no restriction would be "allow")."""
    return mv is not None and bool(mv.falls(NO_RESTRICTION))


def _ws_restrictions(a: Any) -> dict[str, Any]:
    """An approved workspace's restrictions: its read/exec/write keys that
    lower anything (snapshot encodings); {} when it restricts nothing."""
    pol = a.get("policy") if isinstance(a, dict) and isinstance(a.get("policy"), dict) else {}
    return {k: pol[k] for k in formmod.WORKSPACE_POLICY_KEYS
            if k in pol and _restricts(_ap_policy(pol, k))}


def _phase7_host(e: EffectiveHost, name: str, h: formmod.Host, ap: dict[str, Any],
                 W: Any, N: Any, mode: str | None) -> None:
    """The host's policy table, workspaces and remote imports against their
    approval (PLAN-v4 phase 7)."""
    keys = formmod.LOCALHOST_POLICY_KEYS if h.is_local else formmod.HOST_POLICY_KEYS
    fpm = {k: mv for k in keys if (mv := h.policy_mode(k)) is not None}
    e.policy_modes = policy_compare(fpm, ap.get("policy"), keys, formmod.POLICY_GRANT,
                                    "policy ", W, N, approves=h.is_local)
    e.policy = _legacy_policy(e.policy_modes, mode)
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
        wpm = {k: mv for k in formmod.WORKSPACE_POLICY_KEYS if (mv := w.policy_mode(k)) is not None}
        ew.policy_modes = policy_compare(wpm, a.get("policy"), formmod.WORKSPACE_POLICY_KEYS, (),
                                         f"workspace {wn} ", W, N)
        ew.policy = _legacy_policy(ew.policy_modes, mode)
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
              + ", ".join(f"{k} {_ptext(_ap_policy(held, k), False)}" for k in held)
              + " would no longer apply)")
            e.workspaces[wn] = EffectiveWorkspace(name=wn, host=name, root=str(a.get("root")),
                                                  local=str(a.get("local") or ""), policy=held)
            hw = e.workspaces[wn]
            hw.policy_modes = {k: mv for k in held if (mv := _ap_policy(held, k)) is not None}
            hw.policy = _legacy_policy(hw.policy_modes, mode)
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


def _cmp_right(k: str, f: ModeValue, a: ModeValue, W: Any, N: Any, what: str | None = None,
               approves: bool = True) -> ModeValue:
    """A right compared mode by mode; the effective value is the per-mode
    minimum (a rise waits for the OK, a fall applies at once). `what` and
    `approves`: how the change line names it (_change_text)."""
    up, down = f.rises(a), f.falls(a)
    if up:
        W(_change_text(k, f, a, up, what=what, approves=approves))
    if down:
        N(_change_text(k, f, a, down, what=what, approves=approves))
    return f.minimum(a)


def _localhost_sudo(e: EffectiveHost, h: formmod.Host, ap: dict[str, Any], W: Any, N: Any,
                    form_gone: bool) -> None:
    """This computer's sudo (PLAN-0.11 §1.1, §1.5): configured or not in the
    form and in the approval."""
    f = h.mode_value("sudo")
    a = _ap_mode(ap, "sudo", "right", DENY) if ap.get(SUDO_CONFIGURED) is True else None
    if a is not None and form_gone:
        e.modes["sudo"] = DENY                  # the form can't say: configured, refused
    elif f is None and a is None:
        return                                  # the user's own sudo
    elif f is None:
        assert a is not None
        W("sudo stops going through the gateway (the key is gone from [hosts.localhost]: from "
          "then on Claude uses your own sudo on this computer)")
        e.modes["sudo"] = a
    elif a is None:
        # configured where it wasn't: a narrowing from unconfigured, up to
        # "ask"; above "ask" waits for the OK
        N(f"sudo {_text(f)} (this computer's sudo now goes through the gateway)")
        up = f.rises(ASK)
        if up:
            W(_change_text("sudo", f, ASK, up, what="sudo on this computer"))
        e.modes["sudo"] = f.minimum(ASK)
    else:
        e.modes["sudo"] = _cmp_right("sudo", f, a, W, N, what="sudo on this computer")


def _host(name: str, h: formmod.Host, ap: dict[str, Any] | None,
          widen: list[Change], narrow: list[Change], mode: str | None = None,
          form_gone: bool = False) -> EffectiveHost:
    e = EffectiveHost(name=name, host=h)
    line = h.line

    def W(what: str) -> None:
        widen.append(Change(name, "widen", what, line))

    def N(what: str) -> None:
        narrow.append(Change(name, "narrow", what, line))

    if ap is None and h.is_local:
        ap = {}                         # an approval without localhost: nothing configured here
    if ap is None:
        e.new = True
        bits = [f"address {h.address.render() if h.address else '?'}"]
        if h.also:
            bits.append("also " + ", ".join(a.render() for a in h.also))
        if h.via:
            bits.append(f"via {h.via}")
        bits.append(f"ssh {word(h.mode_value('ssh'))}, sudo {word(h.mode_value('sudo'))}")
        if h.scripts:
            bits.append("scripts true")
        W("new host (" + "; ".join(bits) + ")")
        e.modes = {"ssh": DENY, "sudo": DENY}
        e.ssh = e.sudo = False
        return e
    if h.is_local:
        _localhost_sudo(e, h, ap, W, N, form_gone)
    else:
        for k in ("ssh", "sudo"):
            a = _ap_mode(ap, k, "right", DENY)
            assert a is not None
            e.modes[k] = _cmp_right(k, h.mode_value(k), a, W, N,
                                    what=f"ssh to {name}" if k == "ssh" else f"sudo on {name}")
    a_s, f_s = bool(ap.get("scripts")), h.scripts
    if f_s and not a_s:
        W("scripts false -> true (programs Claude starts get credentials too)")
    elif a_s and not f_s:
        N("scripts true -> false")
    e.scripts = a_s and f_s
    _phase7_host(e, name, h, ap, W, N, mode)
    if h.is_local:
        _legacy_rights(e, mode)
        return e
    approved_addrs = [x for x in ap.get("addresses") or [] if isinstance(x, dict)]
    for fa in h.addresses():
        if _covered(fa, approved_addrs):
            e.addresses.append(fa)
            continue
        same = [x for x in approved_addrs if _addr_key(x) == fa.key()]
        if same:
            aw = same[0].get("when") or None
            W(f"address {fa.render()} on {fa.when or 'any network'} (was {aw or 'any network'}"
              + ("; outside that network it would stop going through the gateway)"
                 if fa.when and not aw else ")"))
            e.addresses.append(_snap_address(same[0]))    # the approved one applies meanwhile
        else:
            W(f"new address {fa.render()}" + (f" (on {fa.when})" if fa.when else ""))
    form_keys = {fa.key() for fa in h.addresses()}
    for x in approved_addrs:
        if _addr_key(x) not in form_keys:
            W(f"address {_render_addr(x)} dropped (at that address {name} would stop going "
              "through the gateway: from then on Claude uses your own ssh, agent and keys there)")
            e.held_addresses.append(_snap_address(x))
    a_via, f_via = ap.get("via"), h.via
    if f_via != a_via:
        if f_via:
            W(f"via {f_via} (was {a_via or 'direct'})")
        else:
            W(f"via {a_via} dropped (direct now)")
        e.via = a_via
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
        e.modes["ssh"] = DENY
    _legacy_rights(e, mode)
    return e


def _legacy_rights(e: EffectiveHost, mode: str | None) -> None:
    e.ssh = e.modes["ssh"].legacy(mode) if "ssh" in e.modes else False
    e.sudo = e.modes["sudo"].legacy(mode) if "sudo" in e.modes else (
        formmod.LOCALHOST_SUDO if e.is_local else False)


def _removed_host(name: str, ap: dict[str, Any], W: Any, mode: str | None) -> EffectiveHost:
    """A host the form no longer names (deleted or renamed): its approval
    keeps classifying and gating until the user's OK (PLAN-0.11 §1.1)."""
    addrs = _snap_addresses(ap)
    h = formmod.Host(name=name, address=addrs[0] if addrs else None, also=addrs[1:],
                     via=ap.get("via") if isinstance(ap.get("via"), str) else None,
                     scripts=bool(ap.get("scripts")), runtime=str(ap.get("runtime") or ""))
    e = EffectiveHost(name=name, host=h, removed=True, addresses=addrs, via=h.via,
                      runtime=ap.get("runtime") or None, scripts=bool(ap.get("scripts")))
    for k in ("ssh", "sudo"):
        mv = _ap_mode(ap, k, "right", DENY)
        assert mv is not None
        e.modes[k] = mv if addrs or k == "sudo" else DENY
        h.modes[k] = mv
        setattr(h, k, mv.legacy())
    pol = ap.get("policy") if isinstance(ap.get("policy"), dict) else {}
    e.policy_modes = {k: mv for k in formmod.HOST_POLICY_KEYS
                      if k in pol and (mv := _ap_policy(pol, k)) is not None
                      and mv != (GRANT_OFF if k in formmod.POLICY_GRANT else NO_RESTRICTION)}
    e.policy = _legacy_policy(e.policy_modes, mode)
    for wn, a in (ap.get("workspaces") or {}).items():
        if isinstance(a, dict) and a.get("root"):
            wp = a.get("policy") if isinstance(a.get("policy"), dict) else {}
            ew = EffectiveWorkspace(name=wn, host=name, root=str(a["root"]),
                                    local=str(a.get("local") or ""))
            ew.policy_modes = {k: mv for k in formmod.WORKSPACE_POLICY_KEYS
                               if k in wp and (mv := _ap_policy(wp, k)) is not None
                               and mv != NO_RESTRICTION}
            ew.policy = _legacy_policy(ew.policy_modes, mode)
            e.workspaces[wn] = ew
    sh = ap.get("shell") if isinstance(ap.get("shell"), dict) else {}
    e.import_path = [x for x in sh.get("import_path") or [] if isinstance(x, str)]
    e.import_env = [x for x in sh.get("import_env") or [] if isinstance(x, str)]
    W(f"{name} will stop going through the gateway (its [hosts.{name}] is gone from "
      "gateway.toml): from then on Claude uses your own ssh, agent and keys for it")
    _legacy_rights(e, mode)
    return e


def _only_of_kind(form: formmod.Form, name: str) -> bool:
    """Is account `name` the only one of its kind in the form for at least
    one of its destinations (accounts.owner_covered's `only`, as select
    counts it)?"""
    a = form.accounts[name]
    others = [b for n, b in form.accounts.items() if n != name and b.kind == a.kind]
    return any(not any(acctmod.covers(acctmod.destinations(b), d) for b in others)
               for d in acctmod.destinations(a))


def _account(name: str, a: formmod.Account, ap: dict[str, Any] | None,
             rec: dict[str, Any] | None, widen: list[Change], narrow: list[Change],
             mode: str | None = None, only: bool = True) -> EffectiveAccount:
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
        if not a.mode_value().any_above("deny"):
            extra.append("use false")
        elif a.mode_value().snapshot() is not True:
            extra.append(f"use {word(a.mode_value())}")
        W(what + (" (" + "; ".join(extra) + ")" if extra else ""))
        e.modes = {"use": DENY}
        return e
    approved = [d for d in ap.get("destinations") or [] if isinstance(d, str)]
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
            W(f"no longer sends to {d} (it would stop going through the gateway: from then on "
              "Claude uses your own tools and tokens there)")
            e.held_destinations.append(d)
    # who it routes for (login and owners): one added goes through the gateway
    # at once, one dropped waits for the OK (an older approval names none)
    a_own = [o.lower() for o in ([ap.get("login")] if isinstance(ap.get("login"), str) else [])
             + [o for o in ap.get("owners") or [] if isinstance(o, str)]]
    f_own = [o.lower() for o in a.owner_names() if o]
    for o in f_own:
        if o not in a_own:
            N(f"owner {o} now goes through the gateway")
    for o in a_own:
        if o not in f_own:
            W(f"owner {o} dropped (its repositories would stop going through the gateway: from "
              "then on Claude uses your own git and tokens for them)")
            e.held_owners.append(o)
    # the only account of its kind covers every owner only while it lists
    # none (accounts.owner_covered): listing the first one takes the rest out
    # (beside another account of its kind it covers no other owner anyway)
    if a.owners and approved_any_owner(ap) and only:
        W(f"owners listed (as the only {a.kind} account it went for every owner; other owners' "
          "repositories would stop going through the gateway: from then on Claude uses your own "
          "git and tokens for them)")
    a_use = _ap_mode(ap, "use", "right", modes.bare(True, "right"))
    assert a_use is not None
    e.modes["use"] = _cmp_right("use", a.mode_value(), a_use, W, N, approves=False)
    e.use = e.modes["use"].legacy(mode) is True
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
    f_sign = a.sign_in if a.sign_in == "browser" else None
    for k, label, fv in (("auth", "auth placement", a.auth or None),
                         ("tenant", "tenant", a.tenant or None),
                         ("client_id", "client_id", a.client_id or None),
                         ("sign_in", "sign_in", f_sign), ("scope", "scope", a.scope or None)):
        av = ap.get(k)
        if (av or fv) and av != fv:
            hint = " (needs a new sign-in)" if k in ("tenant", "client_id", "sign_in", "scope") \
                else ""
            unset = "service-principal" if k == "sign_in" else "unset"
            W(f"{label} {av or unset} -> {fv or unset}{hint}")
            setattr(e, k, av)
        else:
            setattr(e, k, fv)
    fpm = {k: mv for k in formmod.ACCOUNT_POLICY_KEYS if (mv := a.policy_mode(k)) is not None}
    e.policy_modes = policy_compare(fpm, ap.get("policy"), formmod.ACCOUNT_POLICY_KEYS, (),
                                    "policy ", W, N)
    e.policy = _legacy_policy(e.policy_modes, mode)
    return e


def _removed_account(name: str, ap: dict[str, Any], rec: dict[str, Any] | None, W: Any,
                     mode: str | None) -> EffectiveAccount:
    """An account the form no longer names: its approval keeps gating until
    the user's OK (PLAN-0.11 §1.1)."""
    kind = ap["kind"]
    dests = [d for d in ap.get("destinations") or [] if isinstance(d, str)]
    bound = None if rec is None else list(((rec.get("bound") or {}).get("hosts")) or [])
    login = ap.get("login") if isinstance(ap.get("login"), str) else ""
    owners = [o for o in ap.get("owners") or [] if isinstance(o, str)]
    acct = _reach_account(name, kind, dests, login, owners, bool(ap.get("default")))
    e = EffectiveAccount(name=name, kind=kind, account=acct, removed=True, owners=owners,
                         destinations=[d for d in dests if bound is None or d in bound],
                         scripts=bool(ap.get("scripts")), env=ap.get("env") or None,
                         auth=ap.get("auth"), tenant=ap.get("tenant"),
                         client_id=ap.get("client_id"), sign_in=ap.get("sign_in"),
                         scope=ap.get("scope"))
    use = _ap_mode(ap, "use", "right", modes.bare(True, "right"))
    assert use is not None
    e.modes["use"] = use
    acct.modes["use"] = use
    e.use = use.legacy(mode) is True
    acct.use = use.modeless() == "cc"
    pol = ap.get("policy") if isinstance(ap.get("policy"), dict) else {}
    e.policy_modes = {k: mv for k in formmod.ACCOUNT_POLICY_KEYS
                      if k in pol and (mv := _ap_policy(pol, k)) is not None and mv != NO_RESTRICTION}
    e.policy = _legacy_policy(e.policy_modes, mode)
    W(f"{name} will stop going through the gateway (its [accounts.{name}] is gone from "
      "gateway.toml): from then on Claude uses your own tools and tokens for it")
    return e


_READ = object()      # compute(listed=...) not given: read the list itself when needed


def compute(form: formmod.Form, data: dict[str, Any] | None = None, mode: str | None = None,
            *, listed: Any = _READ, locked: bool = False) -> Effective:
    """Effective rights for a validated form against the vault's approvals.
    `mode` (a mode key or a payload spelling) resolves the legacy attributes
    (EffectiveHost.ssh/sudo, EffectiveAccount.use, the policy dicts): the
    recorded mode for a command Claude typed, None (the default) for the
    modeless rule; Effective.word and policy.decide take a mode of their own.

    `data` None: no approval could be read. compute then reads the configured
    list itself (load_listed(); `listed` given instead: that list,
    clean_listed applied; None: no list). A list there (it exists only next
    to a vault: approve() and ratchet() write it, ratchet() removes it when
    no vault is left) or `locked` (the caller got vault.VaultLocked) means a
    vault holds approvals that can't be read now (Effective.unreadable):
    entries only the list names are refused, this computer's sudo is
    refused where the list says it is configured (or restricted) and the
    form doesn't say so, and the form's own entries are refused with the
    locked (or unreadable) note (Effective.refusal)."""
    if mode is not None:
        mode = modes.normalize(mode)
    if listed is _READ:
        listed = load_listed() if data is None else None
    elif listed is not None:
        listed = clean_listed(listed)
    ap = approved_rights(data)
    form_gone = not form.from_last_good and (not form.exists or form.syntax_error is not None)
    eff = Effective(form=form, approved=ap, mode=mode, form_gone=form_gone, locked=locked,
                    unreadable=data is None and (locked or listed is not None))
    widen: list[Change] = []
    narrow: list[Change] = []
    eff.shell = _shell(form, approved_shell(ap), widen, narrow)
    eff.network = _network(form, ap, widen, narrow)
    ap_pol = (ap.get("settings") or {}).get("policy")
    eff.policy_modes = policy_compare(
        {k: mv for k in formmod.GLOBAL_POLICY_KEYS if (mv := form.policy_mode(k)) is not None},
        ap_pol if isinstance(ap_pol, dict) else {}, formmod.GLOBAL_POLICY_KEYS, (),
        "policy ", lambda w: widen.append(Change("settings", "widen", w, form.policy_line)),
        lambda w: narrow.append(Change("settings", "narrow", w)), approves=True)
    eff.policy = _legacy_policy(eff.policy_modes, mode)
    ap_hosts, ap_accts = ap.get("hosts") or {}, ap.get("accounts") or {}
    for name, h in form.hosts.items():
        eff.hosts[name] = _host(name, h, ap_hosts.get(name), widen, narrow, mode, form_gone)
    vrecs = (data or {}).get("accounts") or {}
    for name in ap_hosts:
        if name in form.hosts or name == "localhost" or not isinstance(ap_hosts[name], dict):
            continue
        if form.is_disabled(name, "hosts"):
            eff.refused[name] = f"[hosts.{name}] is off (a mistake in it: gate status)"
        elif form_gone:
            eff.refused[name] = FORM_GONE
        else:
            eff.hosts[name] = _removed_host(
                name, ap_hosts[name], lambda w, n=name: widen.append(Change(n, "widen", w)), mode)
    for name, a in form.accounts.items():
        eff.accounts[name] = _account(name, a, ap_accts.get(name), vrecs.get(name), widen, narrow,
                                      mode, only=_only_of_kind(form, name))
    for name in ap_accts:
        if name in form.accounts or not isinstance(ap_accts[name], dict) \
                or ap_accts[name].get("kind") not in formmod.KINDS:
            continue
        if form.is_disabled(name, "accounts"):
            eff.refused[name] = f"[accounts.{name}] is off (a mistake in it: gate status)"
        elif form_gone:
            eff.refused[name] = FORM_GONE
        else:
            eff.accounts[name] = _removed_account(
                name, ap_accts[name], vrecs.get(name),
                lambda w, n=name: widen.append(Change(n, "widen", w)), mode)
    for name in form.disabled:
        sect = "hosts" if form.is_disabled(name, "hosts") else "accounts"
        eff.refused.setdefault(name, f"[{sect}.{name}] is off (a mistake in it: gate status)")
    eff.configured = _configured(form, ap if data is not None else None, listed)
    for name in (listed or {}).get("hosts") or {}:
        if name not in eff.hosts and name != "localhost":
            eff.refused.setdefault(name, LISTED_ONLY if not form_gone else FORM_GONE)
    for name in (listed or {}).get("accounts") or {}:
        if name not in eff.accounts:
            eff.refused.setdefault(name, LISTED_ONLY if not form_gone else FORM_GONE)
    _listed_localhost(eff, listed, mode)
    # A jump host that is off makes the hosts behind it unreachable.
    for _ in range(formmod.MAX_CHAIN + 1):
        for e in eff.hosts.values():
            if e.via:
                j = eff.hosts.get(e.via)
                e.modes["ssh"] = e.modes.get("ssh", DENY).minimum(
                    j.modes.get("ssh", DENY) if j is not None and not j.new else DENY)
                e.ssh = e.modes["ssh"].legacy(mode)
    if form_gone:
        # the form can't say what changed: nothing waits for an OK (the
        # stricter of the empty form and the approval applies; needs_sync and
        # sync_narrowing never ratchet a missing or unreadable form)
        widen = []
    for c in widen:
        target = eff.hosts.get(c.entry) or eff.accounts.get(c.entry)
        if target is not None:
            target.pending.append(c)
    eff.pending = widen
    eff.narrowed = narrow
    return eff


def _listed_localhost(eff: Effective, listed: dict[str, Any] | None, mode: str | None) -> None:
    """While the approval can't be read (or gateway.toml is gone), the
    configured list's word on this computer (PLAN-0.11 §1.1, §11.3): where
    it says sudo here goes through the gateway, or that an elevation
    restriction applies, and neither the form nor a readable approval says
    so now, sudo here is refused (never the user's own sudo passing
    through)."""
    lh = eff.hosts.get("localhost")
    if not listed or lh is None or not (eff.unreadable or eff.form_gone):
        return
    gap_sudo = listed.get("localhost_sudo") is True and "sudo" not in lh.modes
    gap_elev = listed.get("local_elevation") is True and not _elevation_restricted(
        lh.policy_modes, eff.policy_modes)
    if gap_sudo or gap_elev:
        lh.modes["sudo"] = DENY
        _legacy_rights(lh, mode)
        eff.refused["localhost"] = FORM_GONE if eff.form_gone else LISTED_SUDO


def _network(form: formmod.Form, ap: dict[str, Any], widen: list[Change],
             narrow: list[Change]) -> EffectiveNetwork:
    """[network] against its approval (PLAN-0.11 §3.2): commands mode by
    mode; a name entering the class (added to extra, taken out of drop)
    applies at once; one leaving it (taken out of extra, added to drop)
    waits for the OK. A mistake in the table keeps the approved [network]."""
    fn = form.network
    a_cmd, a_extra, a_drop = approved_network(ap)
    if fn.invalid:
        return EffectiveNetwork(commands=a_cmd, extra=list(a_extra), drop=list(a_drop))

    def W(what: str) -> None:
        widen.append(Change("settings", "widen", what, fn.line))

    def N(what: str) -> None:
        narrow.append(Change("settings", "narrow", what))

    out = EffectiveNetwork()
    out.commands = _cmp_right("network commands", fn.commands, a_cmd, W, N, what="network commands")
    for x in fn.extra:
        if x not in a_extra:
            N(f"network: {x} joins the network commands")
    for x in a_extra:
        if x not in fn.extra:
            W(f"network: {x} leaves the network commands (the gateway would stop judging it)")
    for x in fn.drop:
        if x not in a_drop:
            W(f"network: {x} dropped from the network commands (the gateway would stop judging it)")
    for x in a_drop:
        if x not in fn.drop:
            N(f"network: {x} back among the network commands")
    out.extra = list(dict.fromkeys([*a_extra, *fn.extra]))
    out.drop = [x for x in a_drop if x in fn.drop]
    return out


def _shell(form: formmod.Form, ap: dict[str, Any], widen: list[Change],
           narrow: list[Change]) -> EffectiveShell:
    """[shell] against its approval (PLAN-v4 phase 4): a lower `managed` and
    a new import wait for the user's OK (the approved ones apply meanwhile);
    a higher `managed` and a removed import apply at once. A bad `managed`
    (the removed "warn" included) counts as "on" and changes nothing."""
    fs = form.shell
    e = EffectiveShell()

    def W(what: str, line: int | None) -> None:
        widen.append(Change("settings", "widen", what, line))

    def N(what: str) -> None:
        narrow.append(Change("settings", "narrow", what))

    a_m = ap["managed"]
    if fs.managed_invalid:
        e.managed = "on"          # a bad value: the strict mode, nothing ratchets
    elif SHELL_RANK[fs.managed] < SHELL_RANK[a_m]:
        W(f'managed shell "{a_m}" -> "{fs.managed}" (Claude\'s commands run in Claude Code\'s '
          "own shell, with your login setup)", fs.line)
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


def _narrow_network(ap: dict[str, Any], form: formmod.Form) -> dict[str, Any]:
    """The approved [network] lowered to the form where the form is
    stricter: commands per mode, names joining the class kept."""
    a_cmd, a_extra, a_drop = approved_network(ap)
    fn = form.network
    if fn.invalid:
        return {"commands": a_cmd.snapshot(), "extra": a_extra, "drop": a_drop}
    return {"commands": fn.commands.minimum(a_cmd).snapshot(),
            "extra": list(dict.fromkeys([*a_extra, *fn.extra])),
            "drop": [x for x in a_drop if x in fn.drop]}


# ---------------------------------------------------------------------------
# Writing approvals
# ---------------------------------------------------------------------------


def _policy_narrowed(f: dict[str, ModeValue], a: dict[str, Any] | None, keys: tuple[str, ...],
                     grants: tuple[str, ...]) -> dict[str, Any] | None:
    """The approved table lowered to the form where the form is stricter,
    mode by mode (sync_narrowing); None when neither has anything to keep."""
    if not f and a is None:
        return None
    a = a or {}
    out: dict[str, Any] = {}
    for k in keys:
        base = GRANT_OFF if k in grants else NO_RESTRICTION
        fv, av = f.get(k), _ap_policy(a, k)
        if fv is None and av is None:
            continue
        v = (fv or base).minimum(av or base)
        if v == base and av is None:
            continue                     # still nothing approved to keep
        out[k] = v.snapshot() if v != av else a[k]
    return out


def _form_policy(pol_owner: Any, keys: tuple[str, ...]) -> dict[str, ModeValue]:
    return {k: mv for k in keys if (mv := pol_owner.policy_mode(k)) is not None}


def _narrow_phase7(out: dict[str, Any], ap: dict[str, Any], h: formmod.Host) -> None:
    keys = formmod.LOCALHOST_POLICY_KEYS if h.is_local else formmod.HOST_POLICY_KEYS
    pol = _policy_narrowed(_form_policy(h, keys), ap.get("policy"), keys, formmod.POLICY_GRANT)
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
            p = _policy_narrowed(_form_policy(w, formmod.WORKSPACE_POLICY_KEYS), a.get("policy"),
                                 formmod.WORKSPACE_POLICY_KEYS, ())
            if p:
                y["policy"] = p
            kept[wn] = y
        out["workspaces"] = kept
    ash = ap.get("shell") if isinstance(ap.get("shell"), dict) else None
    if ash is not None:
        out["shell"] = {k: [x for x in ash.get(k) or [] if x in getattr(h.shell, k)]
                        for k in ("import_path", "import_env")}


def _narrow_host(ap: dict[str, Any], h: formmod.Host) -> dict[str, Any]:
    """The approved host lowered to the form where the form is stricter.
    Addresses, `when` and `via` never narrow any more: dropping or changing
    them takes the host (or an address of it) out of the gateway, a
    widening (PLAN-0.11 §1.1)."""
    out = dict(ap)
    if h.is_local:
        f = h.mode_value("sudo")
        if f is not None:
            if ap.get(SUDO_CONFIGURED) is True:
                a = _ap_mode(ap, "sudo", "right", DENY)
                assert a is not None
                out["sudo"] = f.minimum(a).snapshot()
            else:
                out["sudo"] = f.minimum(ASK).snapshot()
                out[SUDO_CONFIGURED] = True
    else:
        for k in ("ssh", "sudo"):
            if k in ap:
                a = _ap_mode(ap, k, "right", DENY)
                assert a is not None
                v = h.mode_value(k).minimum(a)
                out[k] = ap[k] if v == a else v.snapshot()
    out["scripts"] = bool(ap.get("scripts")) and h.scripts
    _narrow_phase7(out, ap, h)
    return out


def _narrow_account(ap: dict[str, Any], a: formmod.Account) -> dict[str, Any]:
    """The approved account lowered to the form where the form is stricter;
    owners the form adds are recorded (dropping one later is a widening);
    destinations never narrow (dropping one is a widening)."""
    out = dict(ap)
    a_use = _ap_mode(ap, "use", "right", modes.bare(True, "right"))
    assert a_use is not None
    v = a.mode_value().minimum(a_use)
    out["use"] = ap.get("use", True) if v == a_use else v.snapshot()
    out["scripts"] = bool(ap.get("scripts")) and a.scripts
    if not a.env:
        out["env"] = None
    a_login = ap.get("login") if isinstance(ap.get("login"), str) else None
    owners = [o for o in ap.get("owners") or [] if isinstance(o, str)]
    have = {o.lower() for o in owners + ([a_login] if a_login else [])}
    any_owner = approved_any_owner(ap)            # (read before owners grows)
    for o in ([a.login] if a.login else []) + list(a.owners):
        if o.lower() not in have:
            owners.append(o)
            have.add(o.lower())
    out["owners"] = owners
    # covering every owner (no owners listed) can come at once, never go
    # without the OK (listing the first owner is a widening)
    out["any_owner"] = any_owner or not a.owners
    pol = _policy_narrowed(_form_policy(a, formmod.ACCOUNT_POLICY_KEYS), ap.get("policy"),
                           formmod.ACCOUNT_POLICY_KEYS, ())
    if pol is not None:
        out["policy"] = pol
    return out


def needs_sync(data: dict[str, Any] | None, form: formmod.Form) -> bool:
    """Would sync_narrowing change anything?"""
    if data is None or form.syntax_error is not None or not form.exists:
        return False
    return bool(compute(form, data).narrowed)


def sync_narrowing(data: dict[str, Any], form: formmod.Form) -> list[Change]:
    """Lower the approved snapshot to the form where the form is narrower.
    Never widens anything: an entry the form no longer names, a dropped
    address, destination or owner stay approved (taking them out is a
    widening). Disabled entries, a missing form and a form with a syntax
    error are left alone. Returns the narrowings (so callers can close ssh
    masters); the caller saves."""
    if form.syntax_error is not None or not form.exists:
        return []
    eff = compute(form, data)
    if not eff.narrowed:
        return []
    ap = approved_rights(data)
    for name in list(ap.get("hosts", {})):
        if form.is_disabled(name, "hosts"):
            continue
        h = form.hosts.get(name)
        if h is not None:
            ap["hosts"][name] = _narrow_host(ap["hosts"][name], h)
    lh = form.hosts.get("localhost")
    if lh is not None and "localhost" not in ap["hosts"] and lh.sudo_configured:
        ap["hosts"]["localhost"] = _narrow_host({"scripts": False}, lh)
    for name in list(ap.get("accounts", {})):
        if form.is_disabled(name, "accounts"):
            continue
        a = form.accounts.get(name)
        if a is not None and ap["accounts"][name].get("kind") == a.kind:
            ap["accounts"][name] = _narrow_account(ap["accounts"][name], a)
    settings = dict(ap.get("settings") or {})
    settings["shell"] = _narrow_shell(approved_shell(ap), form)
    settings["network"] = _narrow_network(ap, form)
    ap_pol = settings.get("policy") if isinstance(settings.get("policy"), dict) else {}
    settings["policy"] = _policy_narrowed(_form_policy(form, formmod.GLOBAL_POLICY_KEYS), ap_pol,
                                          formmod.GLOBAL_POLICY_KEYS, ()) or {}
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
    the form is narrower than the approval or the valid form differs from
    the stored copy. With no vault yet, a narrowing (say `[hosts.localhost]
    sudo = false` in the starter form) creates one, so it outlives a later
    syntax error or a deleted form; never next to a gateway 0.6 vault
    (vault.v06_waiting). Never raises for an unreadable vault (nothing is
    persisted then). Keeps the configured list in step with the approval."""
    from . import audit, paths, vault
    if vault.v06_waiting():
        return []
    if not vault.exists():
        _drop_stale_list()
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
        if load_listed() != configured_list(approved_rights(data)):
            # out of step: rewritten under the lock from the vault as it is
            # then (never this process's older copy over a newer approval)
            try:
                with vault.locked():
                    write_listed(approved_rights(vault.load()))
            except (vault.VaultError, OSError, paths.PathError):
                pass
        return []
    with vault.locked():
        cur = vault.load()
        changes = sync_narrowing(cur, form)
        if changes:
            vault.add_event(cur, "narrow", "; ".join(c.render() for c in changes)[:400])
        if last_good_ok(form):
            cur["form_last_good"] = form.used_text
        vault.save(cur)
        write_listed(approved_rights(cur))
    if changes:
        close_masters_for(changes, form)
        audit.log("narrow", changes=[c.render() for c in changes])
    return changes


def _drop_stale_list() -> None:
    """No vault, no approval: a configured list left behind (the vault
    deleted by hand) would keep refusing what it names. Removed under the
    vault's lock, only while there is still no vault."""
    from . import paths, vault
    try:
        if not paths.configured_path().exists():
            return
        with vault.locked():
            if not vault.exists():
                paths.configured_path().unlink(missing_ok=True)
    except (OSError, paths.PathError):
        pass


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
    (brand new, or added back after its entry was removed), or one whose kind
    changed, starts without a credential: the user
    is asked for a fresh secret instead of an old key silently going to the
    new destinations under a "new account" pop-up (review round 2)."""
    rec = ((data or {}).get("accounts") or {}).get(a.name) or {}
    if not any(rec.get(k) for k in CREDENTIAL_FIELDS):
        return False
    snap = approved_rights(data)["accounts"].get(a.name)
    if not isinstance(snap, dict):
        return True
    return snap.get("kind") != a.kind or rec.get("kind") not in (None, a.kind)


def approve(entry: str, changes: list[Change] | list[str] | None = None,
            form: formmod.Form | None = None, *, keep_credentials: bool = False) -> list[str]:
    """Record the user's OK for `entry` (a host, an account, or "settings"):
    its form rights become the approved ones, an account's destinations are
    bound, and a `widen` event is logged. An entry the form no longer names
    leaves the approval (and an account its bindings): from then on it is
    the user's own. Returns the approved change lines. Call only after the
    consent dialog said yes, passing the changes it showed: if the entry's
    pending changes are different now (the form changed while the dialog
    was open), nothing is approved and
    ConsentChanged is raised, so the user is asked again. Nothing is
    approved while gateway.toml is missing or unreadable.

    An account that `drops_credential` names loses the credential stored
    earlier (token, ssh key, Entra sign-in, pinned host keys, cached tokens,
    bindings), so the next step asks for a fresh one. `keep_credentials=True`
    only for an import, whose credentials came with the entry the pop-up
    listed."""
    from . import audit, paths, vault
    if isinstance(changes, formmod.Form):  # approve(entry, form) (positional form)
        form, changes = changes, None
    if form is None:
        form = load_form()
    removed_host = False
    with vault.locked():
        data = vault.load()
        eff = compute(form, data)
        if eff.form_gone:
            raise ConsentChanged("gateway: gateway.toml is missing or has a mistake; nothing was "
                                 "approved (fix it first: gate status)")
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
            net = network_snapshot(form)
            if form.network.invalid:            # a mistake: the approved [network] stays
                a_cmd, a_extra, a_drop = approved_network(ap)
                net = {"commands": a_cmd.snapshot(), "extra": a_extra, "drop": a_drop}
            ap["settings"] = {"shell": sh,
                              "policy": formmod.policy_snapshot(form.policy, form.policy_modes),
                              "network": net}
        else:
            # one name, both sections (one namespace): the form's entry is
            # approved, and an approval of the same name in the other section
            # that the form no longer names leaves (its removal was among the
            # lines the dialog showed for this name)
            done = False
            if entry in form.hosts:
                ap["hosts"][entry] = host_snapshot(form.hosts[entry])
                done = True
            elif entry in ap["hosts"] and entry != "localhost" \
                    and not form.is_disabled(entry, "hosts"):
                del ap["hosts"][entry]           # its removal: the user's own from now on
                removed_host = done = True
            if entry in form.accounts:
                a = form.accounts[entry]
                if not keep_credentials and drops_credential(data, a):
                    old = data["accounts"][entry]
                    for k in CREDENTIAL_FIELDS:
                        old.pop(k, None)
                    old["bound"] = {"hosts": []}
                    vault.cache_clear(entry)
                    vault.add_event(data, "forget", f"{entry}: the credential stored before it "
                                                    "was approved as a new account was dropped")
                snap = account_snapshot(a)
                if _sign_in_keys(ap["accounts"].get(entry)) != _sign_in_keys(snap) \
                        and paths.cache_path().exists():
                    # tokens minted with the old tenant, client_id, sign_in
                    # or scope go with them (PLAN-0.11 §19.5, WS-6)
                    vault.cache_clear(entry)
                ap["accounts"][entry] = snap
                rec = vault.account_record(data, entry, a.kind)
                rec["kind"] = a.kind
                b = rec["bound"]
                b["hosts"] = list(dict.fromkeys(list(b.get("hosts") or []) + a.destinations()))
                if a.kind == "api-key":
                    b["auth"] = a.auth
                if a.kind == "azure":
                    b["tenant"], b["client_id"] = a.tenant, a.client_id
                done = True
            elif entry in ap["accounts"] and not form.is_disabled(entry, "accounts"):
                del ap["accounts"][entry]
                rec = (data.get("accounts") or {}).get(entry)
                if rec and rec.get("bound"):
                    rec["bound"]["hosts"] = []
                vault.cache_clear(entry)
                done = True
            if not done:
                raise KeyError(f"{entry} isn't a valid entry in the form")
        data["approved"] = {"form_sha256": form.sha256, "at": vault.now(), "rights": ap}
        if last_good_ok(form):
            data["form_last_good"] = form.used_text
        lines = [c.render() for c in changes]
        if changes:
            vault.add_event(data, "widen", "; ".join(lines))
        vault.save(data)
        write_listed(ap)                         # under the lock: never an older list over it
    if removed_host:
        close_masters_for([Change(entry, "narrow", "host removed")])
    audit.log("consent", entry=entry, outcome="approved", changes=lines)
    # the stand-ins on PATH follow the configured set (PLAN-0.11 §1.2: an
    # approved removal can take a stand-in away; WS-1's named edit)
    try:
        from . import envfile
        eff_now = compute(form, data)
        envfile.sync_standins(form, eff_now)
        sync_network_words(eff_now)          # (WS-3: the prefilter's extra names)
    except Exception:  # noqa: BLE001 - the next session start writes them anyway
        pass
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
