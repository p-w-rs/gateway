"""Managing hosts, workspaces, policy and accounts from the native panes
(PLAN-v4 phase 7; /gate-hosts and /gate-accounts in hooks/mod, docs/dev/modules/ux.md).

    gate host add NAME USER@ADDRESS[:PORT] [ssh=..] [sudo=..]
    gate host set NAME KEY VALUE        address, ssh, sudo, scripts, note, runtime, via
    gate host set NAME ssh|sudo MODE=WORD [MODE=WORD...]     a per-mode table
    gate account set NAME use WORD | MODE=WORD [MODE=WORD...]  an account's use
    gate workspace add HOST NAME ROOT [LOCAL]
    gate workspace remove HOST NAME     (applies at once, unless the workspace restricts
                                        anything: then it waits for the person's OK)
    gate policy set SCOPE KEY VALUE     SCOPE: all (the [policy] table), a host, or an account
    gate policy set SCOPE KEY MODE=WORD [MODE=WORD...]       read, exec, write, network,
                                        elevation, credential per mode
    gate network commands VALUE | MODE=WORD [MODE=WORD...]   [network] commands
    gate network extra|drop add|remove NAME                  [network] extra / drop
    gate accounts [--check NAME|all] [--json]

Per mode (PLAN-0.11 §2.9): a right (ssh, sudo, an account's use), a moded
policy key or [network] commands takes one word or MODE=WORD tokens, written
as an inline table (`{ default = "ask", auto = true }`). MODE is one of
default, manual, plan, acceptEdits, auto, bypass, bypassPermissions, dontAsk
(default is required: it gives every mode not named); WORD is true, false,
allow, deny, ask or cc. A mode named twice (also as default and manual) is
refused.

Every change goes through the form writer (form.append_table / set_key: the
form is never re-serialized; a write that would change anything else, or
break another entry, is refused and nothing is written), with only
non-secret values (a credential is typed into the gateway's dialog,
`gate login NAME`). Nothing here approves anything: a widening (a new host, a
raised right, a new workspace, a raised policy key) waits for the person's OK
in the gateway's consent dialog, which `gate check NAME` opens (the panes run
it next); a narrowing applies at once (consent.ratchet). So a command Claude
runs can propose but never widen.

A workspace removal is the one edit that takes text out of the form; it
removes exactly that workspace's table (its header and key lines), checks the
result parses to the same document minus that table, and is refused
otherwise.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import sys
import tomllib
from typing import Any

from . import consent, modes, paths, vault
from . import form as formmod

HOST_SET_KEYS = ("address", "ssh", "sudo", "scripts", "note", "runtime", "via")
# One per-mode token (PLAN-0.11 §2.9; manage.ts's MODE_TOKEN says the same).
MODE_TOKEN = re.compile(r"(default|manual|plan|acceptEdits|auto|bypass|bypassPermissions|dontAsk)="
                        r"(true|false|allow|deny|ask|cc)")
MODE_HELP = ("MODE=WORD tokens (MODE: default, manual, plan, acceptEdits, auto, bypass, "
             "bypassPermissions, dontAsk, with default required; WORD: true, false, allow, deny, "
             "ask, cc)")


class ManageError(Exception):
    """Refused; nothing was written (the message is safe to show)."""


def _out(s: str) -> None:
    print(s, flush=True)


def _err(s: str) -> None:
    print(s, file=sys.stderr, flush=True)


def _name(n: str, what: str) -> str:
    if not isinstance(n, str) or not formmod.NAME_RE.fullmatch(n) or n in formmod.RESERVED:
        raise ManageError(f"gateway: {what} names are lowercase letters, digits and -, starting "
                          "with a letter (at most 32), and not a reserved word")
    return n


def _host(n: str) -> str:
    """A host an edit names: a host name, or `localhost` (this machine, which
    is in every form; reserved only as the name of a new host)."""
    return n if n == "localhost" else _name(n, "host")


_WORD_VALUE = {"right": {"allow": True, "deny": False, "ask": "ask", "cc": "cc"},
               "policy": {"allow": "allow", "deny": "deny", "ask": "ask", "cc": "cc"},
               "network": {"allow": "allow", "deny": "deny", "ask": "ask", "cc": "cc"}}


def _word(raw: str, kind: str, what: str, tables: bool = True) -> Any:
    """One word as gateway.toml writes it for `kind`: a right true / false /
    "ask" / "cc", a policy or [network] value "allow" / "deny" / "ask" /
    "cc" (true, yes, on and allow, false, no, off and deny are the same)."""
    t = modes._token(raw)
    if t is None:
        raise ManageError(f"gateway: {what} takes " + ("true, ask, cc or false" if kind == "right"
                                                       else "allow, ask, cc or deny")
                          + (f", or {MODE_HELP}" if tables else ""))
    return _WORD_VALUE[kind][t]


def _is_table(values: list[str]) -> bool:
    """MODE=WORD tokens rather than one word (anything with "=" counts, so a
    misspelt token is refused, never taken as a word)."""
    return len(values) > 1 or any("=" in v for v in values)


def _mode_table(values: list[str], kind: str, what: str) -> modes.ModeValue:
    """MODE=WORD tokens -> a per-mode value written as an inline table
    (`default` required, each mode once)."""
    pairs: list[tuple[str, Any]] = []
    seen: set[str] = set()
    for v in values:
        m = MODE_TOKEN.fullmatch(v)
        if m is None:
            raise ManageError(f"gateway: {what} per mode takes {MODE_HELP}")
        spelling, tok = m.groups()
        key = modes.SPELLINGS[spelling]
        if key in seen:
            raise ManageError(f"gateway: {what} names {modes.DISPLAY[key]} mode twice")
        seen.add(key)
        pairs.append((spelling, _word(tok, kind, what)))
    try:
        return modes.parse(dict(pairs), kind)
    except modes.ModeError as e:
        raise ManageError(f"gateway: {what} {e}") from None


def _moded_value(values: list[str], kind: str, what: str) -> Any:
    """One word, or a per-mode table from MODE=WORD tokens."""
    if _is_table(values):
        return _mode_table(values, kind, what)
    return _word(values[0], kind, what)


def _shown(v: Any) -> str:
    """A written value for a confirmation line: the table's TOML, a word as
    written."""
    return formmod.toml_value(v)


def _value(key: str, raw: str) -> Any:
    """A key's value from its command-line word: rights words for the rights,
    true/false for scripts, text otherwise."""
    if key in ("ssh", "sudo"):
        return _word(raw, "right", key, tables=False)
    if key == "scripts":
        b = {"true": True, "false": False}.get(raw.strip().lower())
        if b is None:
            raise ManageError("gateway: scripts takes true or false")
        return b
    if formmod.unsafe_text(raw) or len(raw) > 1000:
        raise ManageError("gateway: that value holds control characters or is too long")
    return raw


def _today() -> str:
    return datetime.date.today().isoformat()


def _form() -> formmod.Form:
    formmod.clear_cache()
    f = formmod.load(use_cache=False)
    if f.syntax_error is not None:
        raise ManageError("gateway: gateway.toml has a syntax error; fix it first (gate status "
                          "shows the line)")
    return f


def _ensure_form() -> None:
    p = paths.form_path()
    if not p.exists():
        paths.ensure_home()
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)


def _check_entry(table: str, entry: str) -> None:
    """After a write: the entry must still be valid (the writer refuses a
    write that breaks another entry; this one's own new errors are rolled
    back here by the caller's snapshot)."""
    f = _form()
    probs = [p.render() for p in f.problems_for(entry) if p.level == "error"]
    if probs:
        raise ManageError(f"gateway: {table}: {probs[0]}")


def _write(fn: Any, *args: Any, entry: str, table: str, **kw: Any) -> None:
    p = paths.form_path()
    before = p.read_text(encoding="utf-8") if p.exists() else None
    try:
        fn(*args, **kw)
    except formmod.FormWriteError as e:
        raise ManageError(f"gateway: {e}; nothing was written") from None
    try:
        _check_entry(table, entry)
    except ManageError:
        if before is not None:
            formmod._atomic_write(p, before)
        formmod.clear_cache()
        raise
    try:
        consent.ratchet()          # a narrowing applies (and is kept) at once
    except Exception:  # noqa: BLE001
        pass


def _pending_line(entry: str) -> str:
    try:
        data = vault.load() if vault.exists() else vault.empty()
        eff = consent.compute(_form(), data)
    except Exception:  # noqa: BLE001
        return ""
    n = len(eff.pending_for(entry))
    if not n:
        return f"gateway: {entry} is up to date (nothing waits for the user's OK)"
    return (f"gateway: {n} change{'s' if n != 1 else ''} for {entry} wait{'s' if n == 1 else ''} "
            f"for the user's OK in the gateway dialog: gate check {entry}")


# ---------------------------------------------------------------------------
# hosts and workspaces
# ---------------------------------------------------------------------------


def host_add(name: str, address: str, extra: list[str]) -> int:
    _name(name, "host")
    try:
        formmod.parse_address(address)
    except ValueError as e:
        raise ManageError(f"gateway: {e}") from None
    f = _form()
    if name in f.hosts or name in f.accounts or name in f.disabled:
        raise ManageError(f"gateway: {name} is already in gateway.toml (gate host set changes it)")
    items: list[tuple[str, Any]] = [("address", address)]
    for kv in extra:
        k, sep, v = kv.partition("=")
        if not sep or k not in ("ssh", "sudo", "scripts", "note", "runtime", "via"):
            raise ManageError("gateway: extra settings are KEY=VALUE with KEY ssh, sudo, scripts, "
                              "note, runtime or via")
        items.append((k, _value(k, v)))
    _ensure_form()
    _write(formmod.append_table, f"hosts.{name}", items, comment=f"added in /gate-hosts on {_today()}",
           entry=name, table=f"[hosts.{name}]")
    _out(f"gateway: added host {name}")
    _out(_pending_line(name))
    return 0


def host_set(name: str, key: str, values: list[str]) -> int:
    """`gate host set NAME KEY VALUE`, or for ssh and sudo also `KEY
    MODE=WORD...` (a per-mode table)."""
    _host(name)
    if key not in HOST_SET_KEYS:
        raise ManageError(f"gateway: gate host set changes {', '.join(HOST_SET_KEYS)} (credentials "
                          "go through gate login / gate check, workspaces through gate workspace)")
    if not values:
        raise ManageError(f"gateway: gate host set {name} {key} needs a value")
    if key in ("ssh", "sudo"):
        value = _moded_value(values, "right", key)
    elif len(values) != 1:
        raise ManageError(f"gateway: {key} takes one value (only ssh and sudo take MODE=WORD)")
    else:
        value = _value(key, values[0])
    f = _form()
    h = f.hosts.get(name)
    if h is None:
        raise ManageError(f"gateway: no host {name} in gateway.toml")
    if h.is_local and key in ("address", "runtime", "via"):
        raise ManageError(f"gateway: {key} isn't a localhost setting")
    if h.is_local and key == "ssh":
        raise ManageError("gateway: ssh isn't a localhost setting")
    if not h.explicit:
        _ensure_form()
        _write(formmod.append_table, "hosts.localhost", [(key, value)],
               comment=f"added in /gate-hosts on {_today()}", entry=name, table="[hosts.localhost]")
    else:
        _write(formmod.set_key, f"hosts.{name}", key, value, entry=name,
               table=f"[hosts.{name}]")
    _out(f"gateway: {name}: {key} set" + (f" ({_shown(value)})"
                                          if isinstance(value, modes.ModeValue) else ""))
    _out(_pending_line(name))
    return 0


def workspace_add(host: str, ws: str, root: str, local: str | None) -> int:
    _host(host)
    _name(ws, "workspace")
    f = _form()
    h = f.hosts.get(host)
    if h is None:
        raise ManageError(f"gateway: no host {host} in gateway.toml")
    if ws in h.workspaces:
        raise ManageError(f"gateway: {host} has a workspace {ws} already")
    try:
        r = formmod.workspace_path(root, "root")
        loc = formmod.workspace_path(local, "local") if local else None
    except ValueError as e:
        raise ManageError(f"gateway: {e}") from None
    if loc and h.is_local:
        raise ManageError("gateway: a localhost workspace is on this machine already (no local)")
    items: list[tuple[str, Any]] = [("root", r)] + ([("local", loc)] if loc else [])
    _ensure_form()
    if not h.explicit:
        _write(formmod.append_table, "hosts.localhost", [], comment=f"added in /gate-hosts on {_today()}",
               entry=host, table="[hosts.localhost]")
    _write(formmod.append_table, f"hosts.{host}.workspaces.{ws}", items,
           comment=f"added in /gate-hosts on {_today()}", entry=host,
           table=f"[hosts.{host}.workspaces.{ws}]")
    _out(f"gateway: added workspace {ws} on {host} ({r})")
    _out(_pending_line(host))
    return 0


def _remove_table(table: tuple[str, ...]) -> None:
    """Take exactly one [table] (header, its key lines, its comment block
    right above) out of the form, verified: the new text parses to the old
    document without that table, and no other entry gains an error."""
    p = paths.form_path()
    old = p.read_text(encoding="utf-8")
    lines = old.split("\n")
    start = None
    for i, line in enumerate(lines):
        m = formmod._HEADER.match(line)
        if m and not formmod._KEYLINE.match(line) and not m.group(1) and \
                formmod._split_dotted(m.group(2)) == table:
            start = i
            break
    if start is None:
        raise ManageError("gateway: that table isn't written as its own table; edit it by hand")
    end = len(lines)
    for i in range(start + 1, len(lines)):
        m = formmod._HEADER.match(lines[i])
        if m and not formmod._KEYLINE.match(lines[i]):
            end = i
            break
    while end > start + 1 and lines[end - 1].strip().startswith("#"):
        end -= 1                    # the next table's comment block stays with it
    first = start
    while first > 0 and lines[first - 1].strip().startswith("#"):
        first -= 1
    new_lines = lines[:first] + lines[end:]
    new = "\n".join(new_lines)
    try:
        want = tomllib.loads(formmod.normalize_lenient(old))
        got = tomllib.loads(formmod.normalize_lenient(new))
    except tomllib.TOMLDecodeError:
        raise ManageError("gateway: removing it would break the form; edit it by hand") from None
    cur: Any = want
    for part in table[:-1]:
        cur = cur.get(part, {})
    if not isinstance(cur, dict) or table[-1] not in cur:
        raise ManageError("gateway: that table isn't in the form")
    del cur[table[-1]]
    # a dotted header made its parents implicitly (`[hosts.box.workspaces.app]`
    # alone makes `workspaces`): the last one taken out takes the empty parent too
    for k in range(len(table) - 1, 0, -1):
        parent: Any = want
        for part in table[:k - 1]:
            parent = parent.get(part, {})
        node = parent.get(table[k - 1]) if isinstance(parent, dict) else None
        if isinstance(node, dict) and not node and got != want:
            del parent[table[k - 1]]
        else:
            break
    if got != want:
        raise ManageError("gateway: removing it would change other parts of the form; edit it by "
                          "hand")
    formmod._atomic_write(p, new)
    formmod.clear_cache()


def workspace_remove(host: str, ws: str) -> int:
    _host(host)
    _name(ws, "workspace")
    f = _form()
    h = f.hosts.get(host)
    if h is None or ws not in h.workspaces:
        raise ManageError(f"gateway: no workspace {ws} on {host}")
    _remove_table(("hosts", host, "workspaces", ws))
    try:
        consent.ratchet()
    except Exception:  # noqa: BLE001
        pass
    # a workspace that restricted anything keeps binding until the person's OK
    # (taking a restriction away is a widening: consent._phase7_host)
    try:
        eff = consent.compute(_form(), _vault_data())
        waiting = any(c.what.startswith(f"workspace {ws} removed")
                      for c in eff.pending_for(host))
    except Exception:  # noqa: BLE001 - say the cautious thing
        waiting = True
    if waiting:
        _out(f"gateway: removed workspace {ws} from {host} in gateway.toml; it restricted "
             f"what Claude may do there, so it keeps applying until the user approves the "
             f"change (the user runs gate check {host})")
    else:
        _out(f"gateway: removed workspace {ws} from {host} (a narrowing: it applies at once)")
    return 0


def _vault_data() -> dict[str, Any] | None:
    return vault.load() if vault.exists() else None


# ---------------------------------------------------------------------------
# policy
# ---------------------------------------------------------------------------


def policy_set(scope: str, key: str, values: list[str]) -> int:
    """`gate policy set SCOPE KEY VALUE`, or for read, exec, write, network,
    elevation and credential also `KEY MODE=WORD...` (a per-mode table)."""
    if not values:
        raise ManageError("gateway: a policy value is allow, ask or deny")
    w: Any = None                    # (a grant's word: grants take one word)
    if key in formmod.POLICY_MODED:
        value: Any = _moded_value(values, "policy", key)
    elif _is_table(values):
        raise ManageError(f"gateway: {key} takes one word (allow, ask or deny); per mode only "
                          "read, exec, write, network, elevation and credential")
    else:
        w = formmod.policy_word(values[0])
        if w is formmod._BAD:
            raise ManageError("gateway: a policy value is allow, ask or deny")
        value = formmod.policy_text(w)
    f = _form()
    if scope == "all":
        table, keys, entry = "policy", formmod.GLOBAL_POLICY_KEYS, "settings"
        if key in formmod.POLICY_GRANT and w is True:
            raise ManageError(f"gateway: {key} is turned on per host (gate policy set HOST {key} "
                              "allow); [policy] can only keep it off")
        exists = "policy" in formmod._doc(f.used_text)
    elif scope in f.hosts:
        h = f.hosts[scope]
        table = f"hosts.{scope}.policy"
        keys = formmod.LOCALHOST_POLICY_KEYS if h.is_local else formmod.HOST_POLICY_KEYS
        entry = scope
        exists = h.policy is not None
    elif scope in f.accounts:
        table, keys, entry = f"accounts.{scope}.policy", formmod.ACCOUNT_POLICY_KEYS, scope
        exists = f.accounts[scope].policy is not None
    else:
        raise ManageError("gateway: the scope is all, a host or an account in gateway.toml")
    if key not in keys:
        raise ManageError(f"gateway: {scope if scope != 'all' else '[policy]'} takes "
                          + ", ".join(keys))
    _ensure_form()
    if exists:
        _write(formmod.set_key, table, key, value, entry=entry, table=f"[{table}]")
    else:
        _write(formmod.append_table, table, [(key, value)],
               comment=f"added in /gate-hosts on {_today()}", entry=entry, table=f"[{table}]")
    _out(f"gateway: [{table}] {key} = {_shown(value)}")
    _out(_pending_line(entry))
    return 0


# ---------------------------------------------------------------------------
# [network] (PLAN-0.11 §2.9, §3.2)
# ---------------------------------------------------------------------------


def _network_write(key: str, value: Any) -> None:
    """Write [network] KEY = VALUE (the table appended when the form has
    none). A value that gives [network] a mistake is refused by the writer
    (a new form-level error): nothing is written."""
    f = _form()
    _ensure_form()
    if "network" in formmod._doc(f.used_text):
        _write(formmod.set_key, "network", key, value, entry="settings", table="[network]")
    else:
        _write(formmod.append_table, "network", [(key, value)],
               comment=f"added in /gate-hosts on {_today()}", entry="settings", table="[network]")


def network_commands(values: list[str]) -> int:
    """`gate network commands VALUE | MODE=WORD...`."""
    if not values:
        raise ManageError("gateway: gate network commands takes allow, ask, cc or deny, or "
                          + MODE_HELP)
    value = _moded_value(values, "network", "network commands")
    _network_write("commands", value)
    _out(f"gateway: [network] commands = {_shown(value)}")
    _out(_pending_line("settings"))
    return 0


def network_list(which: str, op: str, name: str) -> int:
    """`gate network extra|drop add|remove NAME`: a program name (or a
    reserved name) into or out of [network] extra or drop."""
    if formmod.network_name(name) != name:
        raise ManageError("gateway: a network name is a program name (letters, digits, . _ -; at "
                          "most 32) or a reserved name (" + ", ".join(formmod.NETWORK_RESERVED) + ")")
    doc = formmod._doc(_form().used_text)
    nt = doc.get("network") if isinstance(doc.get("network"), dict) else {}
    cur = nt.get(which, [])
    if not isinstance(cur, list) or not all(isinstance(x, str) for x in cur):
        raise ManageError(f"gateway: [network] {which} isn't a list of names; fix it by hand")
    if op == "add":
        if name in cur:
            raise ManageError(f"gateway: [network] {which} has {name} already")
        new = [*cur, name]
    else:
        if name not in cur:
            raise ManageError(f"gateway: [network] {which} doesn't have {name}")
        new = [x for x in cur if x != name]
    _network_write(which, new)
    _out(f"gateway: [network] {which} = {_shown(new)}")
    _out(_pending_line("settings"))
    return 0


def network_cmd(rest: list[str]) -> int:
    if rest[:1] == ["commands"]:
        return network_commands(rest[1:])
    if len(rest) == 3 and rest[0] in ("extra", "drop") and rest[1] in ("add", "remove"):
        return network_list(rest[0], rest[1], rest[2])
    raise ManageError("gateway: usage: gate network commands VALUE|MODE=WORD... | gate network "
                      "extra|drop add|remove NAME")


# ---------------------------------------------------------------------------
# accounts
# ---------------------------------------------------------------------------

ACCOUNT_SET_KEYS = ("use",)


def account_set(name: str, key: str, values: list[str]) -> int:
    """`gate account set NAME use WORD`, or `use MODE=WORD...` (a per-mode
    table), like a host's ssh and sudo. A raised use waits for the person's
    OK in the consent dialog (gate check NAME); a lowered one applies at
    once."""
    _name(name, "account")
    if key not in ACCOUNT_SET_KEYS:
        raise ManageError("gateway: gate account set changes use (an account's policy goes through "
                          "gate policy set NAME, its credential through gate login NAME)")
    if not values:
        raise ManageError(f"gateway: gate account set {name} use needs a value")
    value = _moded_value(values, "right", key)
    f = _form()
    if name not in f.accounts:
        why = ("is disabled (gate status says why); fix it first"
               if f.is_disabled(name, "accounts") else "isn't an account in gateway.toml")
        raise ManageError(f"gateway: {name} {why}")
    _write(formmod.set_key, f"accounts.{name}", key, value, entry=name, table=f"[accounts.{name}]")
    _out(f"gateway: {name}: {key} set" + (f" ({_shown(value)})"
                                          if isinstance(value, modes.ModeValue) else ""))
    _out(_pending_line(name))
    return 0


def accounts_cmd(args: list[str]) -> int:
    from . import adapters
    as_json = "--json" in args
    rest = [a for a in args if a != "--json"]
    check: list[str] = []
    if rest[:1] == ["--check"]:
        if len(rest) != 2:
            raise ManageError("gateway: usage: gate accounts [--check NAME|all] [--json]")
        data = vault.load() if vault.exists() else vault.empty()
        form = consent.load_form(data)
        check = list(form.accounts) if rest[1] == "all" else [rest[1]]
        for n in check:
            if n not in form.accounts:
                raise ManageError(f"gateway: no account {n} in gateway.toml")
    elif rest:
        raise ManageError("gateway: usage: gate accounts [--check NAME|all] [--json]")
    results = {}
    for n in check:
        results[n] = adapters.check_and_record(n).public()
    data = vault.load() if vault.exists() else vault.empty()
    form = consent.load_form(data)
    rows = adapters.summary(form, data)
    if as_json:
        _out(json.dumps({"accounts": rows, "checked": sorted(results)}))
        return 0
    if not rows:
        _out("gateway: no accounts in gateway.toml")
        return 0
    for r in rows:
        extra = ", ".join(f"{k} {r[k]}" for k in ("login", "credential", "expires_at") if r.get(k))
        _out(f"{r['account']} ({r['kind']}): {r['state']}" + (f" ({extra})" if extra else "")
             + (f": {r['detail']}" if r.get("detail") else ""))
    return 0


def main(cmd: str, rest: list[str]) -> int:
    try:
        if cmd == "host" and rest[:1] == ["add"] and len(rest) >= 3:
            return host_add(rest[1], rest[2], rest[3:])
        # host set and policy set: one value, or MODE=WORD tokens (PLAN-0.11 §2.9)
        if cmd == "host" and rest[:1] == ["set"] and len(rest) >= 4:
            return host_set(rest[1], rest[2], rest[3:])
        if cmd == "account" and rest[:1] == ["set"] and len(rest) >= 4:
            return account_set(rest[1], rest[2], rest[3:])
        if cmd == "workspace" and rest[:1] == ["add"] and len(rest) in (4, 5):
            return workspace_add(rest[1], rest[2], rest[3], rest[4] if len(rest) == 5 else None)
        if cmd == "workspace" and rest[:1] == ["remove"] and len(rest) == 3:
            return workspace_remove(rest[1], rest[2])
        if cmd == "policy" and rest[:1] == ["set"] and len(rest) >= 4:
            return policy_set(rest[1], rest[2], rest[3:])
        if cmd == "network":
            return network_cmd(rest)
        if cmd == "accounts":
            return accounts_cmd(rest)
    except ManageError as e:
        _err(str(e))
        return 2
    _err("gateway: usage: gate host add NAME ADDRESS [KEY=VALUE...] | gate host set NAME KEY "
         "VALUE|MODE=WORD... | gate account set NAME use WORD|MODE=WORD... | gate workspace "
         "add HOST NAME ROOT [LOCAL] | gate workspace remove HOST NAME | gate policy set "
         "all|HOST|ACCOUNT KEY allow|ask|deny|MODE=WORD... | gate network commands "
         "VALUE|MODE=WORD... | gate network extra|drop add|remove NAME | gate accounts "
         "[--check NAME|all] [--json]")
    return 2
