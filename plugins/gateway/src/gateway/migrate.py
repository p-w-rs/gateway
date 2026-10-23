"""Migration from gateway v2 (SPEC 4).

Trigger: the first v3 process (SessionStart, a shim, the MCP server or
`gate migrate`) that finds ~/.config/gateway/store.age and no
private/vault.age. Offline: no keyscan, no network, no dialog.

1. Take the v2 lock (home/.lock, so v2 writers wait) and private/.lock;
   re-check under both locks (another process may have migrated meanwhile);
   create private/ (0700); copy store.age and key.txt to private/backups/
   (store-v2-YYYYMMDD.age, key-v2.txt; a byte-identical earlier copy is
   reused, whatever its date).
2. Decrypt with the v2 rules (vault v1 and v2), map, validate: the generated
   form must parse with the v3 parser and every v2 credential must either land
   in the new vault or be listed as dropped. Any failure writes nothing new
   (no key, vault or form) and leaves store.age where it was; status and a
   systemMessage say `migration failed: REASON; run gate migrate`. One odd v2
   entry never fails the whole migration: it is dropped and reported.
3. Write private/key.txt (the same identity), private/vault.age, and
   gateway.toml only if absent (else gateway.from-v2.toml, whose entries are
   kept as `imported` rights: copying one into gateway.toml needs no new OK).
4. Only then move the v2 store.age and key.txt into private/backups/, so
   `cat ~/.config/gateway/*` can never print the key. Rollback (manual): move
   private/backups/store-v2-*.age back to store.age and key-v2.txt to key.txt.
5. Record `migrated` (with the store's sha256, for idempotency) and a report,
   shown once to the user and kept for `gate status --report`.

A v2 store.age that shows up again after migration (an old v2 session wrote
to it) is moved into private/backups/ as store-v2-stray-*.age with its key,
and the user is told what it held (tidy_leftover; SessionStart does it).

map_v2() is also the mapper for v2 export files (gateway_export: 1), via
map_export_v1(), which keeps the source machine's localhost sudo apart.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import ipaddress
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from . import audit, consent, paths, vault, vault_v2
from . import form as formmod

HEADER = (
    "# The machines and accounts Claude may use. Edit freely, or ask Claude.\n"
    "# Secrets never go here; the gateway asks for them in its dialog in Claude Code.\n"
    "#   true = Claude may do it without asking   \"ask\" = ask me each time   false = no\n"
)
# A new install's form: sudo on this computer starts as "ask" (Claude Code asks
# each time). Forms written before (sudo = true) and converted 0.6 vaults
# keep what they say. STARTER_OLDER is what older gateways wrote: an install
# whose vault one of them made (vault.older_install) gets it back if its form
# goes missing with no copy to restore (starter()), so its sudo stays true.
_STARTER_HEAD = HEADER + "\n[hosts.localhost]                  # this computer, whichever one you're on\n"
STARTER = _STARTER_HEAD + "sudo = \"ask\"\n"
STARTER_OLDER = _STARTER_HEAD + "sudo = true\n"


def starter(data: dict[str, Any] | None) -> str:
    """The starter form for this install (data: its vault, None if none)."""
    return STARTER_OLDER if vault.older_install(data) else STARTER


SHORT = {"github": "github", "hf": "hf", "azure": "azure", "mlcat": "catalog", "pijul": "pijul"}
V3_KIND = {"github": "github", "hf": "huggingface", "azure": "azure", "mlcat": "ml-catalog",
           "pijul": "pijul", "registry": "registry"}
OWNER_ROUTED = ("github", "hf", "pijul")   # v2 chose these by owner (empty owners = catch-all)
STORAGE_HOST = re.compile(r"([a-z0-9]{3,24})\.(?:blob|dfs|file|queue|table)\.core\.windows\.net")
FIXED_AZURE = ("management.azure.com", "graph.microsoft.com")
STORE_FAMILY = "store-v2-*.age"
KEY_FAMILY = "key-v2*.txt"


class MigrationError(Exception):
    """Migration refused; the message holds no secret."""


class _Skip(Exception):
    """One v2 entry can't be carried over (the message is safe to show)."""


@dataclass
class Mapped:
    form_text: str
    vault: dict[str, Any]
    renames: list[tuple[str, str]] = field(default_factory=list)
    now_true: list[str] = field(default_factory=list)
    folded: list[str] = field(default_factory=list)
    defaults: list[str] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)
    dropped_refs: set[str] = field(default_factory=set)
    attention: list[str] = field(default_factory=list)
    lost: list[str] = field(default_factory=list)
    switches: list[str] = field(default_factory=list)
    aliases: dict[str, str] = field(default_factory=dict)
    source_localhost: dict[str, Any] = field(default_factory=lambda: {"sudo": {}})
    # catalog accounts 0.6 named no single host for (off until the user sets
    # `host`): name -> the approval snapshot the conversion records for them
    hostless: dict[str, dict[str, Any]] = field(default_factory=dict)
    report: str = ""


@dataclass
class Result:
    ok: bool
    status: str              # migrated | failed | not-needed | already | stray | conflict
    message: str = ""
    report: str = ""
    form_path: Path | None = None


# ---------------------------------------------------------------------------
# Form text generation
# ---------------------------------------------------------------------------


class _Block:
    def __init__(self, table: str, comments: list[str] | None = None, tail: str = ""):
        self.table = table
        self.comments = comments or []
        self.tail = tail
        self.items: list[tuple[str, Any, str]] = []
        self.commented: list[str] = []
        self.off = False          # render the whole table commented out

    def add(self, key: str, value: Any, comment: str = "") -> None:
        formmod.toml_value(value)  # raises FormWriteError now, not while assembling
        self.items.append((key, value, comment))

    def render(self) -> str:
        out = [f"# {c}" for c in self.comments]
        head = f"[{self.table}]"
        body = [head + (" " * max(1, 35 - len(head)) + f"# {self.tail}" if self.tail else "")]
        width = max((len(k) for k, _, _ in self.items), default=0)
        for k, v, c in self.items:
            line = f"{k.ljust(width)} = {formmod.toml_value(v)}"
            if c:
                line += " " * max(1, 35 - len(line)) + f"# {c}"
            body.append(line)
        body += self.commented
        if self.off:
            body = ["# " + b if not b.startswith("#") else b for b in body]
        return "\n".join(out + body) + "\n"


def _clean_note(s: Any) -> str:
    if not isinstance(s, str):
        return ""
    s = formmod.strip_unsafe(s)
    s = " ".join(s.split())
    return s[:formmod.NOTE_MAX]


def _sanitize(s: str, prefix: str) -> str:
    n = re.sub(r"[^a-z0-9-]+", "-", s.lower())
    n = re.sub(r"-+", "-", n).strip("-")
    if not n or not n[0].isalpha():
        n = f"{prefix}-{n}" if n else prefix
    return n[:32].rstrip("-")


class _Names:
    def __init__(self) -> None:
        self.hosts: set[str] = {"localhost"}
        self.accounts: set[str] = set()

    def _free(self, n: str) -> bool:
        return n not in self.hosts and n not in self.accounts and n not in formmod.RESERVED

    def host(self, want: str) -> str:
        n = _sanitize(want, "host")
        if n in formmod.RESERVED and n != "localhost":
            n = _sanitize(n + "-host", "host")
        base, i = n, 2
        while not self._free(n):
            n = f"{base[:29]}-{i}"
            i += 1
        self.hosts.add(n)
        return n

    def account(self, want: str) -> str:
        n = _sanitize(want, "acct")
        if n in self.hosts or n in formmod.RESERVED:
            n = _sanitize(n + "-acct", "acct")
        base, i = n, 2
        while not self._free(n):
            n = f"{base[:29]}-{i}"
            i += 1
        self.accounts.add(n)
        return n


def _fmt_host(h: str) -> str:
    h = h.strip().lower()
    if h.startswith("[") and h.endswith("]"):
        return h
    return f"[{h}]" if ":" in h else h


def _fmt_addr(user: str | None, host: str, port: str | int | None) -> str:
    p = str(port or "").strip()
    s = (f"{user}@" if user else "") + _fmt_host(host)
    if p and p != "22":
        s += f":{p}"
    return s


def _addr_ok(host: str, port: str) -> bool:
    try:
        formmod.parse_address(_fmt_addr(None, host, port))
        return True
    except ValueError:
        return False


def _host_name_from(h: str) -> str:
    h = h.strip("[]").lower()
    try:
        ipaddress.ip_address(h)
        return "h-" + re.sub(r"[^0-9a-f]+", "-", h)
    except ValueError:
        return h.split(".")[0] or h


def _host_keys(known_hosts: Any) -> list[str]:
    if not isinstance(known_hosts, str):
        return []
    out = []
    for line in known_hosts.splitlines():
        if line.strip().startswith("#"):
            continue
        k = vault.norm_host_key(line)
        if k:
            out.append(k)
    return list(dict.fromkeys(out))


def _safe_field(rx: re.Pattern[str] | None, v: Any, maxlen: int = 200) -> str:
    if not isinstance(v, str) or not v.strip() or len(v) > maxlen or formmod.unsafe_text(v):
        return ""
    v = v.strip()
    return v if rx is None or rx.fullmatch(v) else ""


def _show(ref: str) -> str:
    """A v2 ref for messages: each word only if it is plain."""
    return " ".join(formmod.safe(w) or "(a name)" for w in str(ref).split()) or "(a name)"


def _str_list(v: Any) -> list[str]:
    return [x for x in v if isinstance(x, str)] if isinstance(v, list) else []


def _site_for(h: str) -> tuple[list[str], str | None]:
    """v3 api-key sites for one v2 secret host, and a report note. v2 matched a
    bare domain's subdomains too and accepted *.x globs."""
    h = h.strip().lower()
    if h.startswith("*."):
        base = h[2:]
        if formmod.valid_hostname(base) and not formmod.too_broad_site(base):
            return ["." + base], None
        return [], f"dropped site {formmod.safe(h) or '(unreadable)'} (too broad or not a host name)"
    if not formmod.valid_hostname(h):
        return [], f"dropped site {formmod.safe(h) or '(unreadable)'} (not a host name)"
    try:
        ipaddress.ip_address(h)
        return [h], None
    except ValueError:
        pass
    labels = h.split(".")
    if len(labels) == 2 and not formmod.too_broad_site(h):
        return [h, "." + h], None    # v2 also sent it to every subdomain of this domain
    if len(labels) > 2:
        return [h], f"0.6 also allowed subdomains of {h}; add \".{h}\" to sites if you need them"
    return [h], None


# ---------------------------------------------------------------------------
# The mapper
# ---------------------------------------------------------------------------


def map_v2(v2: dict[str, Any], *, local_user: str | None = None, mode: str = "migrate",
           today: str | None = None) -> Mapped:
    """Map a v2 vault (or v2 export) to (form text, v3 vault dict, report).
    mode="export": localhost sudo goes to source_localhost (another machine's)."""
    v2 = vault_v2.normalize(v2)
    local_user = local_user or paths.local_user()
    today = today or time.strftime("%Y-%m-%d")
    names = _Names()
    out = vault.empty()
    out["form_last_good"] = None
    m = Mapped(form_text="", vault=out)
    accts: dict[str, Any] = v2.get("accounts") or {}
    host_blocks: list[_Block] = []
    acct_blocks: list[_Block] = []
    blocks_by_name: dict[str, _Block] = {}
    ref_name: dict[str, str] = {}
    gone_hosts: set[str] = set()          # hosts whose v2 entry couldn't be carried over

    def alias(old: str, new: str) -> None:
        if old == new:
            return
        m.aliases[old] = new
        m.renames.append((old, new))

    def drop_account(ref: str, why: str) -> None:
        m.dropped.append(f"{_show(ref)}: {why}")
        for r in vault_v2.account_credentials(ref, accts.get(ref)):
            m.dropped_refs.add(r)

    def kind_of(ref: str) -> str:
        a = accts.get(ref)
        return str(a.get("kind") or "") if isinstance(a, dict) else ""

    # --- unknown kinds and malformed entries ----------------------------------
    for ref in sorted(accts):
        k = kind_of(ref)
        if not isinstance(accts[ref], dict) or ":" not in ref:
            drop_account(ref, "not a readable 0.6 account")
        elif k not in V3_KIND and k != "ssh":
            drop_account(ref, f"kind {formmod.safe(k) or '(unreadable)'} isn't known to v3")

    # --- ssh accounts -> hosts -------------------------------------------
    ssh_refs = sorted(r for r in accts if kind_of(r) == "ssh" and ":" in r)
    for ref in ssh_refs:
        ref_name[ref] = names.host(ref.split(":", 1)[1])
    for ref in ssh_refs:
        a = accts[ref]
        n = ref_name[ref]
        try:
            b = _map_ssh_host(m, a, ref, n, ref_name, out, v2)
        except Exception as e:  # noqa: BLE001 - one odd entry never fails the migration
            out["hosts"].pop(n, None)
            gone_hosts.add(n)
            why = str(e) if isinstance(e, _Skip) else f"couldn't be read ({type(e).__name__})"
            drop_account(ref, why)
            continue
        alias(ref, n)
        host_blocks.append(b)
        blocks_by_name[n] = b

    # --- sudo -------------------------------------------------------------
    sudo_hosts: dict[str, set[str]] = {}
    extra_hosts: dict[tuple[str, str], str] = {}
    slots: dict[tuple[str, str], tuple[str, dict[str, Any]]] = {}

    def put_sudo(target: str, user: str, key: str, rec_v: dict[str, Any]) -> None:
        slot = (target, user)
        if slot in slots:
            okey, orec = slots[slot]
            if orec["password"] == rec_v["password"]:
                return
            if str(rec_v.get("updated") or "") >= str(orec.get("updated") or ""):
                keep, lose_key = rec_v, okey
                slots[slot] = (key, rec_v)
            else:
                keep, lose_key = orec, key
            m.dropped.append(f"sudo {_show(lose_key)}: another 0.6 entry for {user} on {target} had a "
                             "different password (the newer one was kept)")
            m.dropped_refs.add(f"sudo {lose_key}")
            rec_v = keep
        else:
            slots[slot] = (key, rec_v)
        if target == "localhost":
            out["localhost"]["sudo"][user] = rec_v
        else:
            vault.host_record(out, target)["sudo"][user] = rec_v

    for key in sorted(v2.get("sudo") or {}):
        e = v2["sudo"][key]
        if not isinstance(e, dict):
            continue
        user = str(e.get("user") or key.split("@", 1)[0])
        host = vault_v2.norm_host(str(e.get("host") or key.rsplit("@", 1)[-1]))
        pw = e.get("password")
        pw = pw if isinstance(pw, str) and pw else None
        rec_v = {"password": pw, "updated": e.get("updated") or vault.now(), "stale": False}
        if not formmod.USER_RE.fullmatch(user):
            m.dropped.append(f"sudo {_show(key)}: the user name isn't valid")
            if pw:
                m.dropped_refs.add(f"sudo {key}")
            continue
        if host == "localhost":
            if mode == "export":
                if pw:
                    m.source_localhost["sudo"][user] = rec_v
                continue
            if user != local_user:
                m.dropped.append(f"sudo {_show(key)}: sudo on this machine is for your own user "
                                 f"({local_user}) only")
                if pw:
                    m.dropped_refs.add(f"sudo {key}")
                continue
            if pw:
                put_sudo("localhost", user, key, rec_v)
            sudo_hosts.setdefault("localhost", set()).add(host)
            continue
        found = vault_v2.account_for_sudo(host, user, v2)
        if found and ref_name.get(found[0]) in gone_hosts:
            m.dropped.append(f"sudo {_show(key)}: its host {ref_name[found[0]]} wasn't carried over")
            if pw:
                m.dropped_refs.add(f"sudo {key}")
            continue
        if found and found[0] in ref_name:
            n = ref_name[found[0]]
        else:
            k2 = (host, user)
            if k2 not in extra_hosts:
                if not _addr_ok(host, ""):
                    m.dropped.append(f"sudo {_show(key)}: its host isn't a host name or address")
                    if pw:
                        m.dropped_refs.add(f"sudo {key}")
                    continue
                n = names.host(_host_name_from(host))
                extra_hosts[k2] = n
                b = _Block(f"hosts.{n}", ["0.6 reached this host with your own keys; run gate "
                                          f"check {n} while you're here to install Claude's key"])
                b.add("address", _fmt_addr(user, host, ""))
                b.add("ssh", True)
                b.add("sudo", True)
                host_blocks.append(b)
                blocks_by_name[n] = b
                vault.host_record(out, n)
                m.attention.append(f"{n}: new host from sudo {_show(key)}; run gate check {n} to "
                                   "install Claude's key")
            n = extra_hosts[k2]
        alias(f"sudo:{key}", n)
        if pw:
            put_sudo(n, user, key, rec_v)
        sudo_hosts.setdefault(n, set()).add(host)
    # Every host gets sudo = true (SPEC 4) and migration approves it: report each
    # one where v2 didn't already allow sudo without asking.
    enabled = {vault_v2.norm_host(h) for h in _str_list(v2.get("sudo_enabled"))}
    if mode != "export" and "localhost" not in enabled:
        m.now_true.append("sudo on localhost")
    for b in host_blocks:
        hn = b.table.split(".", 1)[1]
        if b.off or not any(k == "sudo" and v is True for k, v, _ in b.items):
            continue
        if not (sudo_hosts.get(hn, set()) & enabled):
            m.now_true.append(f"sudo on {hn}")

    # --- accounts -----------------------------------------------------------
    regs = sorted(r for r in accts if kind_of(r) == "registry" and ":" in r)
    reg_via_github: dict[str, list[str]] = {}
    reg_via_azure: dict[str, list[str]] = {}
    own_regs: list[str] = []
    for r in regs:
        via = str(accts[r].get("via") or "")
        if via.startswith("github:"):
            reg_via_github.setdefault(via, []).append(r)
        elif via.startswith("azure:"):
            reg_via_azure.setdefault(via, []).append(r)
        else:
            own_regs.append(r)
    counts: dict[str, int] = {}
    for r in accts:
        k = kind_of(r)
        if k in SHORT and ":" in r:
            counts[k] = counts.get(k, 0) + 1
    order = ["github", "hf", "azure", "mlcat", "pijul"]
    acct_refs = sorted((r for r in accts if kind_of(r) in SHORT and ":" in r),
                       key=lambda r: (order.index(kind_of(r)), r))
    for ref in acct_refs:
        k = kind_of(ref)
        want = SHORT[k] if counts[k] == 1 else f"{SHORT[k]}-{ref.split(':', 1)[1]}"
        ref_name[ref] = names.account(want)
    for r in own_regs:
        ref_name[r] = names.account(r.split(":", 1)[1])

    groups: dict[tuple[str, str], list[tuple[str, str, list[str]]]] = {}
    for ref in acct_refs + own_regs:
        n = ref_name[ref]
        try:
            b, host, owners = _map_account(m, accts, ref, n, out, v2, reg_via_github,
                                           reg_via_azure, alias)
        except Exception as e:  # noqa: BLE001 - one odd entry never fails the migration
            out["accounts"].pop(n, None)
            for old in [o for o, new in m.aliases.items() if new == n]:
                del m.aliases[old]
            m.renames = [(o, new) for o, new in m.renames if new != n]
            why = str(e) if isinstance(e, _Skip) else f"couldn't be read ({type(e).__name__})"
            drop_account(ref, why)
            for r in reg_via_github.get(ref, []) + reg_via_azure.get(ref, []):
                drop_account(r, f"signs in through {_show(ref)}, which wasn't carried over")
            continue
        alias(ref, n)
        acct_blocks.append(b)
        blocks_by_name[n] = b
        k = kind_of(ref)
        if k in OWNER_ROUTED:
            groups.setdefault((k, host), []).append((ref, n, owners))

    # v2 used an account with no owners for every owner no other account
    # listed; in v3 that is `default = true` (login always counts as an owner).
    for (k, host), members in sorted(groups.items()):
        if len(members) < 2:
            continue
        catch_all = [(ref, n) for ref, n, owners in members if not owners]
        if len(catch_all) == 1:
            ref, n = catch_all[0]
            blocks_by_name[n].add("default", True, "0.6 used it for owners no other account lists")
            m.defaults.append(f"{n} (for {host} owners no other account lists)")
        elif len(catch_all) > 1:
            m.attention.append(f"{', '.join(n for _, n in catch_all)} all covered every owner on "
                               f"{host} in 0.6; set default = true on the one to use")

    for via, rs in list(reg_via_github.items()) + list(reg_via_azure.items()):
        if via not in accts:
            for r in rs:
                drop_account(r, f"signs in through {_show(via)}, which doesn't exist")

    # --- secrets -> api-key accounts ----------------------------------------
    subdomain_notes: list[str] = []
    for sname in sorted(v2.get("secrets") or {}):
        s = v2["secrets"][sname]
        if not isinstance(s, dict):
            continue
        n = names.account(sname.replace("_", "-"))
        try:
            sites: list[str] = []
            raw_hosts = s.get("hosts") or []
            if "*" in _str_list(raw_hosts):
                m.attention.append(f"{n}: 0.6 allowed this key on every site; list where it may go "
                                   "in sites")
            for h in _str_list(raw_hosts):
                if h == "*":
                    continue
                got, note = _site_for(h)
                sites += got
                if note and note.startswith("0.6 also"):
                    subdomain_notes.append(note)
                elif note:
                    m.attention.append(f"{n}: {note}")
            sites = list(dict.fromkeys(sites))
            b = _Block(f"accounts.{n}")
            b.add("kind", "api-key")
            b.add("sites", sites)
            b.add("auth", "bearer", "0.6 didn't record how this key was sent; change if needed")
            if not sites:
                b.add("use", False, "0.6 allowed this key on no site; add sites, then use = true")
                m.attention.append(f"{n}: no sites (it is off until you add some)")
            note = _clean_note(s.get("description"))
            if note:
                b.add("note", note)
        except Exception as e:  # noqa: BLE001
            m.dropped.append(f"{_show(sname)}: couldn't be read ({type(e).__name__})")
            m.dropped_refs.add(sname)
            continue
        alias(sname, n)
        acct_blocks.append(b)
        blocks_by_name[n] = b
        rec = vault.account_record(out, n, "api-key")
        if isinstance(s.get("value"), str) and s["value"]:
            rec["token"] = {"value": s["value"], "source": "pasted",
                            "updated": s.get("updated") or vault.now(), "stale": False}
        rec["bound"] = {"hosts": list(sites), "auth": "bearer"}
    if subdomain_notes:
        m.lost.append("subdomain matching of three-part API key sites ("
                      + "; ".join(subdomain_notes[:5]) + ")")

    # --- report-only switches -------------------------------------------------
    if v2.get("sudo_enabled"):
        m.switches.append("sudo always-on switches (" + ", ".join(
            sorted(formmod.safe(str(x)) or "?" for x in v2["sudo_enabled"])) + ")")
    if any(v2.get("sudo_session", {}).values()):
        m.switches.append("per-session sudo switches")
    if v2.get("account_prompts"):
        m.switches.append("vault-wide prompt classes")
    if any(isinstance(a, dict) and (a.get("prompts") or a.get("session_prompts"))
           for a in accts.values()):
        m.switches.append("per-account prompt classes")
    if v2.get("grants"):
        m.switches.append("open setup grants")
    if any(v2.get("ssh_reuse", {}).values()):
        m.switches.append("ssh connection-reuse switches (v3 reuses connections for 2 minutes)")

    # --- assemble the form ------------------------------------------------------
    blocks = []
    loc = _Block("hosts.localhost", tail="this computer, whichever one you're on")
    loc.add("sudo", True)
    blocks.append(loc)
    blocks += host_blocks + acct_blocks
    text = HEADER + f"# Converted from gateway 0.6 on {today}; `gate status --report` shows what changed.\n"
    text += "".join("\n" + bl.render() for bl in blocks)
    m.form_text = text
    parsed = formmod.parse_text(text)
    # bound sets for the mapped accounts (v2 hosts + what the entry computes)
    for n, rec in out["accounts"].items():
        v2hosts = rec.pop("_v2hosts", None)
        fa = parsed.accounts.get(n)
        dests = fa.destinations() if fa else []
        if rec.get("kind") in ("github", "huggingface"):
            hosts = list(v2hosts or []) + dests
        elif rec.get("kind") == "api-key":
            hosts = list(rec["bound"].get("hosts") or [])
        else:
            hosts = dests
        rec["bound"]["hosts"] = list(dict.fromkeys(hosts))
        if rec.get("kind") == "azure" and fa:
            rec["bound"]["tenant"], rec["bound"]["client_id"] = fa.tenant, fa.client_id
        if rec.get("kind") == "ml-catalog" and rec.get("entra"):
            rec["bound"]["tenant"] = rec["entra"].get("tenant_id")
            rec["bound"]["client_id"] = rec["entra"].get("client_id")
            rec["bound"]["scope"] = None  # pinned at the first token (the catalog's /api/config)
    # A hostless catalog account is off (host is required) but keeps its
    # sign-in: the conversion's approval records it as an approved account
    # with no destination yet, so the user adding `host` later is a new
    # destination of that account (one OK, the sign-in kept:
    # consent.drops_credential), not a new account whose OK drops it.
    for n in list(m.hostless):
        if n in parsed.accounts or n not in blocks_by_name:
            del m.hostless[n]
            continue
        use = not any(k == "use" and v is False for k, v, _ in blocks_by_name[n].items)
        snap = consent.account_snapshot(formmod.Account(name=n, kind="ml-catalog", use=use))
        snap["destinations"] = []
        m.hostless[n] = snap
    for p in parsed.errors:
        m.attention.append(f"gateway.toml {p.render()}")
    # An old name that is now itself an entry name would hide that entry.
    entry_names = set(parsed.hosts) | set(parsed.accounts) | set(parsed.disabled)
    for old in list(m.aliases):
        if old in entry_names:
            m.attention.append(f"the old name {_show(old)} is now the name of an entry, so it no "
                               f"longer points to {m.aliases[old]}")
            del m.aliases[old]
    out["aliases"] = dict(m.aliases)
    m.lost.append("per-class prompts, grants and session switches (rights are now true, \"ask\" "
                  "or false per host)")
    m.report = _report(m)
    return m


def _map_ssh_host(m: Mapped, a: dict[str, Any], ref: str, n: str, ref_name: dict[str, str],
                  out: dict[str, Any], v2: dict[str, Any]) -> _Block:
    """[hosts.n] for one v2 ssh account, plus its vault record."""
    b = _Block(f"hosts.{n}")
    raw_user = a.get("user")
    user = _safe_field(formmod.USER_RE, raw_user, 32) or None
    if raw_user and not user:
        if (isinstance(raw_user, str) and raw_user.strip() and len(raw_user) <= 200
                and not formmod.unsafe_text(raw_user)
                and not any(c.isspace() or c in "@:[]\"\\" for c in raw_user)):
            user = raw_user.strip()   # written as is: the form reports it and keeps the entry off
            m.attention.append(f"{n}: the 0.6 user name isn't valid in v3; fix its address (the "
                               "entry is off until then)")
        else:
            b.off = True
            m.attention.append(f"{n}: the 0.6 user name couldn't be carried over; the entry is "
                               "commented out in gateway.toml until you fix its address")
    routes = []
    for r in vault_v2.routes(a):
        host, port, when = r["host"].strip(), r["port"].strip(), r["when"].strip()
        if not host or not _addr_ok(host, port):
            m.attention.append(f"{n}: dropped the 0.6 route {formmod.safe(r['name']) or '(unnamed)'} "
                               "(not a host name or address)")
            continue
        if when:
            try:
                when = formmod.parse_cidr(when)
            except ValueError:
                m.attention.append(f"{n}: dropped the 0.6 route {formmod.safe(r['name']) or '(unnamed)'} "
                                   "(its network isn't readable)")
                continue
        routes.append((host, port, when))
    if not routes:
        b.off = True
        m.attention.append(f"{n}: no usable address in 0.6; the entry is commented out in "
                           "gateway.toml until you add one")
        routes = [("host.invalid", "", "")]
    host, port, when = routes[0]
    b.add("address", _fmt_addr(user, host, port))
    if when:
        b.add("when", when)
    also: list[Any] = []
    for host, port, when in routes[1:]:
        at = _fmt_addr(user, host, port)
        also.append({"at": at, "when": when} if when else at)
    if also:
        b.add("also", also)
    jump = a.get("jump") or ""
    if jump:
        if isinstance(jump, str) and jump in ref_name:
            b.add("via", ref_name[jump])
        else:
            m.attention.append(f"{n}: its 0.6 jump host {_show(str(jump))} wasn't found; add "
                               "via = HOST")
    pr = vault_v2.effective_prompts(a, v2)
    # ssh_exec used the exec class, ssh_copy read/write; delete never applied to hosts
    refuses = [k for k in ("read", "write", "exec") if pr.get(k) == "refuse"]
    if len(refuses) == 3:
        b.add("ssh", False, "0.6 refused every call to this host")
    else:
        b.add("ssh", True)
        if refuses:
            b.comments.append(f"0.6 refused {', '.join(refuses)} calls here; v3 has no "
                              "per-class switch (ssh = false turns it off)")
        if not b.off and (pr.get("exec") != "auto" or pr.get("write") != "auto"):
            m.now_true.append(f"ssh on {n}")
    b.add("sudo", True)
    note = _clean_note(a.get("description"))
    if note:
        b.add("note", note)
    rec = vault.host_record(out, n)
    for i, (priv, pub) in enumerate(vault_v2.keys(a)):
        if not isinstance(priv, str) or not priv.strip():
            continue
        try:
            rec["keys"].append(vault.key_record(priv, pub or None, a.get("updated")))
        except ValueError:
            rec["keys"].append({"private": vault.normalize_key(priv), "public": pub or "",
                                "fingerprint": vault.fingerprint_of(pub or ""),
                                "created": a.get("updated") or vault.now(), "retired": None})
            m.attention.append(f"{n}: key {i + 1} couldn't be read as an OpenSSH key; kept "
                               "as is (gate rotate replaces it)")
    rec["host_keys"] = _host_keys(a.get("known_hosts"))
    if not rec["keys"]:
        m.attention.append(f"{n}: no SSH key yet; run gate check {n}")
    if not rec["host_keys"]:
        m.attention.append(f"{n}: no pinned host key yet; gate check {n} reads it")
    if a.get("host_key_policy") in ("accept-new", "ask"):
        m.lost.append(f"{n}: host-key policy {a['host_key_policy']} (v3 pins and asks in a "
                      "dialog)")
    rn = [formmod.safe(r.get("name")) for r in (a.get("routes") or []) if isinstance(r, dict)
          and r.get("name")]
    if rn:
        m.lost.append(f"{n}: route names ({', '.join(x or '?' for x in rn)})")
    if a.get("comfort"):
        m.lost.append(f"{n}: ssh comfort settings")
    sec = a.get("secrets") if isinstance(a.get("secrets"), dict) else {}
    for k, v in sec.items():
        if k not in ("ssh_key", "old_ssh_keys") and v:
            m.dropped.append(f"{_show(ref)}: {formmod.safe(k) or 'a secret'} (not used for ssh hosts)")
            for r, _ in vault_v2.credentials({"accounts": {ref: {"secrets": {k: v}}}}):
                m.dropped_refs.add(r)
    return b


def _map_account(m: Mapped, accts: dict[str, Any], ref: str, n: str, out: dict[str, Any],
                 v2: dict[str, Any], reg_via_github: dict[str, list[str]],
                 reg_via_azure: dict[str, list[str]], alias: Any
                 ) -> tuple[_Block, str, list[str]]:
    """[accounts.n] for one v2 account and its vault record. Returns (block,
    the account's host, its valid owners)."""
    a = accts[ref]
    k = a["kind"]
    kind3 = V3_KIND[k]
    b = _Block(f"accounts.{n}")
    b.add("kind", kind3)
    sec = a.get("secrets") if isinstance(a.get("secrets"), dict) else {}
    login = _safe_field(formmod.LOGIN_RE, a.get("login"), 100)
    host = str(a.get("host") or "").strip().lower()

    def host_ok(h: str) -> str:
        try:
            return formmod.parse_hostport(h)
        except ValueError:
            raise _Skip("its host isn't a host name") from None

    if k == "github":
        host = host_ok(host or "github.com")
        if login:
            b.add("login", login)
        if host != "github.com":
            b.add("host", host)
    elif k == "hf":
        host = "huggingface.co"
        if login:
            b.add("login", login)
    elif k == "azure":
        tenant = _safe_field(None, a.get("tenant") or a.get("tenant_id"), 200)
        if tenant and (formmod.GUID_RE.fullmatch(tenant) or ("." in tenant and formmod.DNS_RE.fullmatch(tenant.lower()))):
            b.add("tenant", tenant)
        else:
            b.commented.append("# tenant = \"\"                     # 0.6 had no tenant; set it")
            m.attention.append(f"{n}: set tenant = \"...\" (0.6 had none)")
        if login:
            b.add("login", login)
        cid = _safe_field(formmod.GUID_RE, a.get("client_id"), 64)
        if cid and cid != vault_v2.AZURE_CLI_CLIENT_ID:
            b.add("client_id", cid)
    elif k == "mlcat":
        # The catalog's address is written out (the gateway has no default
        # catalog): 0.6's host, else the one host 0.6 bound the account to (a
        # list naming it twice still names one host).
        bound: list[str] = []
        if not host:
            bound = list(dict.fromkeys(h.strip().lower() for h in _str_list(a.get("hosts"))
                                       if formmod.valid_hostname(h.strip().lower())))
            host = bound[0] if len(bound) == 1 else ""
        if host:
            host = host_ok(host)
            b.add("host", host)
        else:
            why = ("0.6 had none" if not bound else f"0.6 listed {len(bound)}: "
                   + ", ".join(bound[:3]) + (", ..." if len(bound) > 3 else ""))
            b.commented.append(f"# host = \"\"                       # {why}; set the catalog's address")
            m.attention.append(f"{n}: set host = \"...\" (the catalog's address; {why})")
            m.hostless[n] = {}
        if login:
            b.add("login", login)
    elif k == "pijul":
        host = host_ok(host or "nest.pijul.com")
        if host != "nest.pijul.com":
            b.add("host", host)
        if login:
            b.add("login", login)
    elif k == "registry":
        if not host:
            raise _Skip("0.6 registry had no host")
        host = host_ok(host)
        b.add("host", host)
        if login:
            b.add("login", login)
    owners = [o for o in _str_list(a.get("owners")) if formmod.OWNER_RE.fullmatch(o)]
    if owners and k in ("github", "hf", "pijul", "registry"):
        b.add("owners", owners)
    if k in ("github", "hf", "pijul"):
        nm = _safe_field(None, a.get("name"), 100)
        em = _safe_field(formmod.EMAIL_RE, a.get("email"), 254)
        if nm:
            b.add("name", nm)
        if em:
            b.add("email", em)
    if k == "pijul":
        rp = _safe_field(formmod.PATH_RE, a.get("remote_pijul"), 256)
        if rp:
            b.add("remote_pijul", rp)
    v2hosts = []
    for h in _str_list(a.get("hosts")):
        h = h.strip().lower()
        if h.startswith("*.") and formmod.valid_hostname(h[2:]):
            v2hosts.append("." + h[2:])
        elif h != "*" and formmod.valid_hostname(h):
            v2hosts.append(h)
    rec = vault.account_record(out, n, kind3)
    # credentials
    if isinstance(sec.get("token"), str) and sec["token"] and k in ("github", "hf", "registry"):
        src = a.get("token_source")
        rec["token"] = {"value": sec["token"], "source": src if src == "gh-oauth" else "pasted",
                        "updated": a.get("updated") or vault.now(), "stale": False}
    if isinstance(sec.get("ssh_key"), str) and sec["ssh_key"] and k in ("github", "hf", "pijul"):
        priv = sec["ssh_key"]
        pub = a.get("public_key") if isinstance(a.get("public_key"), str) else ""
        try:
            pub = pub or vault.public_key_of(priv)
        except ValueError:
            m.attention.append(f"{n}: its SSH key couldn't be read as an OpenSSH key; kept")
        rec["ssh_key"] = {"private": vault.normalize_key(priv), "public": pub,
                          "fingerprint": vault.fingerprint_of(pub)}
    if isinstance(sec.get("refresh_token"), str) and sec["refresh_token"] and k in ("azure", "mlcat"):
        rec["entra"] = {"refresh_token": sec["refresh_token"],
                        "client_id": a.get("client_id") or (vault_v2.AZURE_CLI_CLIENT_ID if k == "azure" else None),
                        "tenant_id": a.get("tenant_id") or a.get("tenant"),
                        "refreshed": a.get("token_refreshed") or a.get("updated")}
    used = {"github": ("token", "ssh_key"), "hf": ("token", "ssh_key"),
            "pijul": ("ssh_key",), "azure": ("refresh_token",), "mlcat": ("refresh_token",),
            "registry": ("token",)}[k]
    for sk, sv in sec.items():
        if sv and sk not in used:
            m.dropped.append(f"{_show(ref)}: {formmod.safe(sk) or 'a secret'} (not used by {kind3} accounts)")
            for r, _ in vault_v2.credentials({"accounts": {ref: {"secrets": {sk: sv}}}}):
                m.dropped_refs.add(r)
    # destinations and bindings
    if k == "github":
        regs_here = reg_via_github.get(ref, [])
        ghcr = [r for r in regs_here if str(accts[r].get("host") or "").lower() == "ghcr.io"]
        for r in regs_here:
            rh = str(accts[r].get("host") or "").lower()
            if rh != "ghcr.io":
                m.dropped.append(f"{_show(r)}: registry {formmod.safe(rh) or '?'} through "
                                 f"{_show(ref)} (only ghcr.io is supported for GitHub accounts)")
                for x in vault_v2.account_credentials(r, accts[r]):
                    m.dropped_refs.add(x)
                continue
            alias(r, n)
            m.folded.append(f"{_show(r)} -> {n} (packages, ghcr.io)")
            extra = sorted(set(o.lower() for o in _str_list(accts[r].get("owners"))
                               if formmod.OWNER_RE.fullmatch(o))
                           - set(o.lower() for o in owners + ([login] if login else [])))
            if extra:
                m.attention.append(f"{n}: {_show(r)} also covered {', '.join(extra)}, which aren't "
                                   f"owners of {n}; add them or use GATE_ACCOUNT={n}")
            for x in vault_v2.account_credentials(r, accts[r]):
                m.dropped.append(f"{_show(r)}: its own {x.split()[-1]} (it signs in through {n})")
                m.dropped_refs.add(x)
        if host == "github.com":
            if ghcr:
                b.add("packages", True)
            else:
                b.add("packages", False, "0.6 didn't use it for ghcr.io; true needs your OK")
        elif ghcr:
            b.add("packages", True)
    if k == "azure":
        dbx, sto, reg, sites = [], [], [], []
        for h in _str_list(a.get("hosts")):
            h = h.strip().lower()
            if h in FIXED_AZURE:
                continue
            if not formmod.valid_hostname(h):
                m.attention.append(f"{n}: dropped the 0.6 host {formmod.safe(h) or '(unreadable)'} "
                                   "(v3 lists each Azure host by name)")
                continue
            sm = STORAGE_HOST.fullmatch(h)
            if h.endswith(".azuredatabricks.net"):
                dbx.append(h)
            elif sm:
                sto.append(sm.group(1))
            elif h.endswith(".azurecr.io"):
                reg.append(h)
            else:
                sites.append(h)
        for r in reg_via_azure.get(ref, []):
            rh = str(accts[r].get("host") or "").lower()
            if rh and formmod.valid_hostname(rh):
                reg.append(rh)
                alias(r, n)
                m.folded.append(f"{_show(r)} -> {n} (registries)")
            else:
                m.dropped.append(f"{_show(r)}: its registry host isn't a host name")
            for x in vault_v2.account_credentials(r, accts[r]):
                m.dropped.append(f"{_show(r)}: its own {x.split()[-1]} (it signs in through {n})")
                m.dropped_refs.add(x)
        for key, vals in (("databricks", dbx), ("storage", sto), ("registries", reg),
                          ("sites", sites)):
            vals = list(dict.fromkeys(vals))
            if vals:
                b.add(key, vals)
    pr = vault_v2.effective_prompts(a, v2)
    refuses = [c for c in vault_v2.PROMPT_CLASSES if pr.get(c) == "refuse"]
    if len(refuses) == 4:
        b.add("use", False, "0.6 refused every call for this account")
    elif refuses:
        b.comments.append(f"0.6 refused {', '.join(refuses)} calls for this account; v3 has no "
                          "per-class switch (use = false turns it off)")
    note = _clean_note(a.get("description"))
    if note:
        b.add("note", note)
    if a.get("known_hosts") and k == "pijul":
        rec["host_keys"] = _host_keys(a.get("known_hosts"))
    # bound: computed after the form is assembled (destinations from the parsed entry)
    rec["_v2hosts"] = v2hosts
    return b, host, owners


def map_export_v1(obj: dict[str, Any], local_user: str | None = None) -> Mapped:
    """A v2 export file's content (gateway_export: 1) through the same mapper.
    Its localhost sudo belongs to the source machine: see source_localhost."""
    if not isinstance(obj, dict) or obj.get("gateway_export") != 1:
        raise MigrationError("this isn't a gateway 0.6 export")
    v2 = {"version": 2, "secrets": obj.get("secrets") or {}, "sudo": obj.get("sudo") or {},
          "accounts": obj.get("accounts") or {}, "account_prompts": obj.get("account_prompts") or {}}
    try:
        return map_v2(v2, local_user=local_user, mode="export")
    except vault_v2.V2Error as e:
        raise MigrationError(str(e)) from None


def _report(m: Mapped) -> str:
    lines = ["gateway: converted your 0.6 vault (a backup is in ~/.config/gateway/private/backups/)."]
    renames = [f"{_show(a)} -> {b}" for a, b in m.renames if not a.startswith("sudo:")]
    if renames:
        lines.append("Renamed (old names keep working): " + ", ".join(renames))
    if m.now_true:
        lines.append("Now without asking (0.6 asked each time, or didn't do it): "
                     + ", ".join(m.now_true) + "; set \"ask\" in gateway.toml (or ask Claude) "
                     "where you want the prompt back.")
    if m.defaults:
        lines.append("Default accounts: " + "; ".join(m.defaults) + ".")
    if m.folded:
        lines.append("Folded: " + "; ".join(m.folded) + ".")
    if m.dropped:
        lines.append("Dropped: " + "; ".join(m.dropped) + ".")
    if m.attention:
        lines.append("Needs attention: " + "; ".join(m.attention) + ".")
    if m.switches:
        lines.append("Not carried over: " + "; ".join(m.switches) + ".")
    if m.lost:
        lines.append("Also gone: " + "; ".join(m.lost) + ".")
    return "\n".join(lines)


def check(m: Mapped, v2: dict[str, Any]) -> formmod.Form:
    """Validate a mapping: the form parses with the v3 parser and every v2
    credential landed in the vault or is listed as dropped."""
    parsed = formmod.parse_text(m.form_text)
    if parsed.syntax_error is not None:
        raise MigrationError(f"the generated form doesn't parse ({parsed.syntax_error.message})")

    def norm(v: Any) -> Any:  # keys are stored normalized (LF, stripped lines)
        return vault.normalize_key(v) if isinstance(v, str) and "PRIVATE KEY-----" in v else v

    landed = {norm(v) for v in vault.all_values(m.vault)}
    landed |= {e.get("password") for e in m.source_localhost.get("sudo", {}).values()}
    for ref, value in vault_v2.credentials(v2):
        if norm(value) in landed or ref in m.dropped_refs:
            continue
        raise MigrationError(f"{_show(ref)} didn't map to the new vault")
    return parsed


# ---------------------------------------------------------------------------
# The procedure
# ---------------------------------------------------------------------------


def needed() -> bool:
    return paths.v2_store_path().is_file() and not paths.vault_path().exists()


def leftover_v2() -> bool:
    """A v2 store.age next to a v3 vault (an old v2 session wrote again)."""
    return paths.v2_store_path().is_file() and paths.vault_path().exists()


def _sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


@contextlib.contextmanager
def _flock(p: Path) -> Iterator[None]:
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "a+") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def _backup_copy(src: Path, dest_dir: Path, name: str, family: str | None = None) -> Path:
    """Copy src into dest_dir/name (0600). A byte-identical copy anywhere in the
    family (e.g. store-v2-*.age, whatever its date) is reused; a different file
    under the same name gets a -2, -3 ... suffix."""
    dest_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(dest_dir, 0o700)
    data = src.read_bytes()
    for old in sorted(dest_dir.glob(family or name)):
        with contextlib.suppress(OSError):
            if old.is_file() and old.read_bytes() == data:
                return old
    stem, dot, ext = name.partition(".")
    cand, i = dest_dir / name, 2
    while cand.exists():
        cand = dest_dir / f"{stem}-{i}{dot}{ext}"
        i += 1
    tmp = cand.with_name(cand.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, cand)
    return cand


def _backup_move(src: Path, dest_dir: Path, name: str, family: str) -> Path:
    """Move src into the backups (as an identical copy), then remove it."""
    dest = _backup_copy(src, dest_dir, name, family)
    src.unlink()
    return dest


def _fail_file() -> Path | None:
    try:
        return paths.run_dir() / "migration-failed.json"
    except (OSError, paths.PathError):
        return None


def last_failure() -> dict[str, Any] | None:
    p = _fail_file()
    try:
        return json.loads(p.read_text()) if p else None
    except (OSError, ValueError):
        return None


def _record_failure(reason: str) -> None:
    p = _fail_file()
    if p:
        with contextlib.suppress(OSError):
            p.write_text(json.dumps({"at": vault.now(), "reason": reason}))


def ensure(trigger: str) -> Result | None:
    """Run the migration if it is needed. None when there was nothing to do
    (including when another process migrated first)."""
    if not needed():
        return None
    r = run(trigger)
    return None if r.status in ("already", "not-needed") else r


def _no_store() -> Result:
    if paths.vault_path().exists():
        try:
            rec = vault.load().get("migrated")
        except vault.VaultError:
            rec = None
        if rec:
            return Result(True, "already", "gateway: already migrated from 0.6",
                          rec.get("report", ""))
    return Result(True, "not-needed", "gateway: there is no 0.6 vault to migrate")


def run(trigger: str = "gate migrate", *, _fail_at: str | None = None) -> Result:
    store, key = paths.v2_store_path(), paths.v2_key_path()
    if not store.is_file():
        return _no_store()
    try:
        with _flock(paths.v2_lock_path()):
            paths.ensure_private()
            with vault.locked():
                # Decide again under both locks: another process may have migrated meanwhile.
                if not store.is_file() or paths.vault_path().exists():
                    return _leftover_locked(store, key)
                return _migrate_locked(store, key, trigger, _fail_at)
    except MigrationError as e:
        reason = str(e)
    except Exception as e:  # noqa: BLE001 - never leak a value; name the type
        reason = f"{type(e).__name__}: {formmod.safe(str(e)[:40]) or 'unexpected error'}"
    _record_failure(reason)
    audit.log("migrate", outcome="failed", trigger=trigger, reason=reason)
    return Result(False, "failed", f"migration failed: {reason}; run gate migrate")


def tidy_leftover() -> Result | None:
    """Put away a v2 store.age that sits next to the v3 vault (see
    _leftover_locked). None when there is none."""
    if not leftover_v2():
        return None
    store, key = paths.v2_store_path(), paths.v2_key_path()
    with _flock(paths.v2_lock_path()):
        with vault.locked():
            return _leftover_locked(store, key)


def _describe_stray(store: Path, key: Path) -> list[str] | None:
    """The names a stray v2 store holds (never values), or None if unreadable.
    Its own key.txt first (v2 makes a new one when it is missing), then the
    v3 key (the original v2 identity)."""
    for k in (key, paths.key_path()):
        if not k.is_file():
            continue
        try:
            d = vault_v2.decrypt(store, k)
        except vault_v2.V2Error:
            continue
        out = [_show(r) for r in sorted(d.get("accounts") or {})]
        out += [_show(s) for s in sorted(d.get("secrets") or {})]
        out += [f"sudo {_show(s)}" for s in sorted(d.get("sudo") or {})]
        return out
    return None


def _leftover_locked(store: Path, key: Path) -> Result:
    """Both locks held. No store: someone else finished (already). The store
    that was migrated (a rollback, then the upgrade again): moved into the
    backups, and a missing gateway.toml restored from the vault. A different
    store (an old v2 session wrote after the upgrade; v2 then starts from an
    empty vault, so it holds only what was written since): moved into the
    backups as store-v2-stray-*.age with its key, and the user is told what it
    held. The v3 vault is never replaced."""
    if not store.is_file():
        return _no_store()
    try:
        data = vault.load()
    except vault.VaultError as e:
        return Result(False, "conflict", f"gateway: {e}; the leftover 0.6 store.age stays where it is")
    rec = data.get("migrated") or {}
    try:
        sha = _sha(store)
    except FileNotFoundError:
        return _no_store()
    day = time.strftime("%Y%m%d")
    bdir = paths.backups_dir()
    if rec.get("store_sha256") == sha:
        _backup_move(store, bdir, f"store-v2-{day}.age", STORE_FAMILY)
        if key.exists():
            _backup_move(key, bdir, "key-v2.txt", KEY_FAMILY)
        _restore_form(data)
        return Result(True, "already", "gateway: already migrated; the leftover 0.6 files were "
                      "moved into private/backups/", rec.get("report", ""))
    held = _describe_stray(store, key)
    dest = _backup_move(store, bdir, f"store-v2-stray-{day}.age", STORE_FAMILY)
    if key.exists():
        if key.read_bytes() == (paths.key_path().read_bytes() if paths.key_path().exists() else b""):
            key.unlink()   # the same identity is already private/key.txt
        else:
            _backup_move(key, bdir, f"key-v2-stray-{day}.txt", KEY_FAMILY)
    what = (", ".join(held[:20]) + (f" and {len(held) - 20} more" if len(held) > 20 else "")
            if held else ("nothing" if held == [] else "something unreadable"))
    vault.add_event(data, "migrate", f"a 0.6 store.age written after the upgrade was moved into "
                                     f"private/backups/ ({dest.name}); it held: {what}")
    vault.save(data)
    audit.log("migrate", outcome="stray", backup=dest.name)
    msg = (f"gateway: a 0.6 store.age showed up again in ~/.config/gateway (an old 0.6 session "
           f"wrote to it after the upgrade). It was moved into private/backups/{dest.name}; your "
           f"v3 vault is unchanged. It held: {what}.")
    if held:
        msg += " To use one of those, add it to gateway.toml and run gate check NAME (its secret is asked again)."
    return Result(True, "stray", msg)


def _restore_form(data: dict[str, Any]) -> None:
    """gateway.toml missing but the vault has the last good copy: put it back."""
    last = data.get("form_last_good")
    if not last or paths.form_path().exists():
        return
    with contextlib.suppress(FileExistsError, OSError):
        fd = os.open(paths.form_path(), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(last)
        formmod.clear_cache()


FROM_V2_NOTE = ("Your gateway.toml was kept; the converted entries are in gateway.from-v2.toml. "
                "Copy the ones you want into gateway.toml: they keep their keys and need no new OK.")


def _migrate_locked(store: Path, key: Path, trigger: str, fail_at: str | None) -> Result:
    day = time.strftime("%Y%m%d")
    store_sha = _sha(store)
    _backup_copy(store, paths.backups_dir(), f"store-v2-{day}.age", STORE_FAMILY)
    if key.is_file():
        _backup_copy(key, paths.backups_dir(), "key-v2.txt", KEY_FAMILY)
    try:
        v2 = vault_v2.decrypt(store, key)
    except vault_v2.V2Error as e:
        raise MigrationError(str(e)) from None
    if fail_at == "map":
        raise MigrationError("test failure after decrypt")
    m = map_v2(v2)
    parsed = check(m, v2)
    if fail_at == "check":
        raise MigrationError("test failure after check")
    target = paths.form_path() if not paths.form_path().exists() else paths.from_v2_form_path()
    data = m.vault
    # A converted 0.6 store is an existing install: its vault carries no
    # baseline mark (vault.older_install), so it keeps the old defaults, like
    # this computer's sudo true in the user's own gateway.toml below.
    data.pop(vault.BASELINE_KEY, None)
    vault.ensure_machine(data)
    report = m.report
    rights = consent.snapshot(parsed)
    for n, snap in m.hostless.items():
        rights["accounts"].setdefault(n, snap)
    if target == paths.form_path():
        data["approved"] = {"form_sha256": parsed.sha256, "at": vault.now(), "rights": rights}
        data["form_last_good"] = m.form_text
    else:
        # The user's own form stays in charge: nothing of theirs is approved by
        # the migration, and the converted entries wait in `imported` until
        # copied in (consent.compute counts them as approved then).
        mine = formmod.load(use_cache=False)
        data["approved"] = {}
        data["imported"] = {"from": "v2", "at": vault.now(), "rights": rights}
        data["form_last_good"] = mine.used_text if (mine.syntax_error is None and mine.exists) else None
        report += "\n" + FROM_V2_NOTE
    data["migrated"] = {"from": "v2", "store_sha256": store_sha, "at": vault.now(),
                        "report": report, "shown": False, "trigger": trigger, "form": target.name}
    vault.add_event(data, "migrate", f"migrated from 0.6 ({len(m.renames)} renamed, "
                                     f"{len(m.dropped)} dropped)")
    created: list[Path] = []
    tmp = target.with_name(f".{target.name}.{os.getpid()}.tmp")
    try:
        pk = paths.key_path()
        if pk.exists() and pk.read_bytes() != key.read_bytes():
            _backup_copy(pk, paths.backups_dir(), "key-unused.txt", "key-unused*.txt")
            pk.unlink()
        if not pk.exists():
            fd = os.open(pk, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key.read_bytes())
            created.append(pk)
        if fail_at == "write":
            raise MigrationError("test failure while writing")
        # The form's temp file first, so the gap between the vault and the
        # form is a single rename (a missing form is restored from
        # form_last_good at the next session anyway).
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(m.form_text)
        vault.save(data, migrating=True)
        created.append(paths.vault_path())
        if fail_at == "form":
            raise MigrationError("test failure writing the form")
        os.replace(tmp, target)
        created.append(target)
    except BaseException:
        for p in reversed(created):
            with contextlib.suppress(OSError):
                p.unlink()
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    # Success: move the v2 files out of the home folder.
    _backup_move(store, paths.backups_dir(), f"store-v2-{day}.age", STORE_FAMILY)
    if key.exists():
        _backup_move(key, paths.backups_dir(), "key-v2.txt", KEY_FAMILY)
    p = _fail_file()
    if p:
        with contextlib.suppress(OSError):
            p.unlink()
    formmod.clear_cache()
    audit.log("migrate", outcome="ok", trigger=trigger, renamed=len(m.renames),
              dropped=len(m.dropped), form=str(target.name))
    # The report reaches the user at their next prompt (hooks_prompt), not
    # only at the next session start: in the first session after the update
    # the conversion happens mid-session (review round 4).
    with contextlib.suppress(OSError):
        report_flag().write_text("")
    msg = "gateway: migrated your 0.6 vault"
    if target != paths.form_path():
        msg += f" (your gateway.toml was kept; the converted form is {target.name})"
    return Result(True, "migrated", msg, report, target)


def report_flag() -> Path:
    """private/migrated.unshown: a conversion's report hasn't been shown yet
    (no secret in it; prompt.sh only tests that it exists)."""
    return paths.private_dir() / "migrated.unshown"


def mark_report_shown() -> None:
    with vault.edit() as data:
        if data.get("migrated"):
            data["migrated"]["shown"] = True
    with contextlib.suppress(OSError):
        report_flag().unlink()


def take_unshown_report() -> str | None:
    """The conversion report if the user hasn't seen it yet, marked shown
    (once; for the UserPromptSubmit hook). None otherwise."""
    p = report_flag()
    if not p.exists():
        return None
    report = None
    try:
        with vault.edit() as data:
            mig = data.get("migrated")
            if mig and not mig.get("shown"):
                report = mig.get("report") or None
                mig["shown"] = True
    except vault.VaultError:
        return None
    with contextlib.suppress(OSError):
        p.unlink()
    return report
