"""Managing hosts, workspaces, policy and accounts from the native panes
(PLAN-v4 phase 7; /gate-hosts and /gate-accounts in hooks/mod, docs/modules/ux.md).

    gate host add NAME USER@ADDRESS[:PORT] [ssh=..] [sudo=..]
    gate host set NAME KEY VALUE        address, ssh, sudo, scripts, note, runtime, via
    gate workspace add HOST NAME ROOT [LOCAL]
    gate workspace remove HOST NAME     (applies at once, unless the workspace restricts
                                        anything: then it waits for the person's OK)
    gate policy set SCOPE KEY VALUE     SCOPE: all (the [policy] table), a host, or an account
    gate accounts [--check NAME|all] [--json]

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
import sys
import tomllib
from typing import Any

from . import consent, paths, vault
from . import form as formmod

HOST_SET_KEYS = ("address", "ssh", "sudo", "scripts", "note", "runtime", "via")


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


def _value(key: str, raw: str) -> Any:
    """A key's value from its command-line word: rights words for the rights,
    true/false for scripts, text otherwise."""
    if key in ("ssh", "sudo"):
        r = formmod.RIGHT_WORDS.get(raw.strip().lower()) if raw.strip().lower() != "ask" else "ask"
        if r is None:
            raise ManageError(f"gateway: {key} takes true, ask or false")
        return r
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


def host_set(name: str, key: str, raw: str) -> int:
    _host(name)
    if key not in HOST_SET_KEYS:
        raise ManageError(f"gateway: gate host set changes {', '.join(HOST_SET_KEYS)} (credentials "
                          "go through gate login / gate check, workspaces through gate workspace)")
    f = _form()
    h = f.hosts.get(name)
    if h is None:
        raise ManageError(f"gateway: no host {name} in gateway.toml")
    if h.is_local and key in ("address", "runtime", "via"):
        raise ManageError(f"gateway: {key} isn't a localhost setting")
    if not h.explicit:
        _ensure_form()
        _write(formmod.append_table, "hosts.localhost", [(key, _value(key, raw))],
               comment=f"added in /gate-hosts on {_today()}", entry=name, table="[hosts.localhost]")
    else:
        _write(formmod.set_key, f"hosts.{name}", key, _value(key, raw), entry=name,
               table=f"[hosts.{name}]")
    _out(f"gateway: {name}: {key} set")
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


def policy_set(scope: str, key: str, raw: str) -> int:
    w = formmod.policy_word(raw)
    if w is formmod._BAD:
        raise ManageError("gateway: a policy value is allow, ask or deny")
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
    text = formmod.policy_text(w)
    _ensure_form()
    if exists:
        _write(formmod.set_key, table, key, text, entry=entry, table=f"[{table}]")
    else:
        _write(formmod.append_table, table, [(key, text)],
               comment=f"added in /gate-hosts on {_today()}", entry=entry, table=f"[{table}]")
    _out(f"gateway: [{table}] {key} = \"{text}\"")
    _out(_pending_line(entry))
    return 0


# ---------------------------------------------------------------------------
# accounts
# ---------------------------------------------------------------------------


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
        if cmd == "host" and rest[:1] == ["set"] and len(rest) == 4:
            return host_set(rest[1], rest[2], rest[3])
        if cmd == "workspace" and rest[:1] == ["add"] and len(rest) in (4, 5):
            return workspace_add(rest[1], rest[2], rest[3], rest[4] if len(rest) == 5 else None)
        if cmd == "workspace" and rest[:1] == ["remove"] and len(rest) == 3:
            return workspace_remove(rest[1], rest[2])
        if cmd == "policy" and rest[:1] == ["set"] and len(rest) == 4:
            return policy_set(rest[1], rest[2], rest[3])
        if cmd == "accounts":
            return accounts_cmd(rest)
    except ManageError as e:
        _err(str(e))
        return 2
    _err("gateway: usage: gate host add NAME ADDRESS [KEY=VALUE...] | gate host set NAME KEY VALUE "
         "| gate workspace add HOST NAME ROOT [LOCAL] | gate workspace remove HOST NAME | gate "
         "policy set all|HOST|ACCOUNT KEY allow|ask|deny | gate accounts [--check NAME|all] [--json]")
    return 2
