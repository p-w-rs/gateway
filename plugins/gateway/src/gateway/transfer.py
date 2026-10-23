"""Export, import, copy-to and pubkey (SPEC 16).

Export (format 3, PLAN-v4 phase 7; formats 1 and 2 are still read):
`{gateway_export: 3, schema: 3, created, form: <text>, vault: <the picked
entries' records>, from: {machine_id, name, hostname, user, ssh_host_keys},
items: [...], digest}`, encrypted with an age passphrase (age's scrypt
recipient; age reads passphrases only from a terminal, so it runs under a
private pty; the plaintext goes through a FIFO in a 0700 temp dir, never a
regular file). The selection is per item (`export_items`): each host, its
secrets (keys, sudo passwords), each account, its credentials, the shared
settings ([settings], [shell], [policy], [vault]) and this machine's sudo password
(unticked by default), as a checklist in the native dialog; the passphrase is
typed twice in its private field (at least 12 characters). The digest is a
sha256 over the rest, checked on import beside age's own authentication; the
file never holds a process id, socket, terminal or job id, task reference or
an account's checked state. The file is written 0600, never over an existing
file, never inside a git work tree, a cloud-synced folder or the gateway home
(default ~/Downloads/gateway-YYYYMMDD.age). The form text in the file is
generated from the validated entries that were ticked.

Import (format 1 through migrate.map_export_v1, 2 or 3; a newer format is
refused with "made by a newer gateway"): decrypt (a passphrase dialog: a
wrong passphrase asks again, a damaged or altered file stops with "the file
was changed or damaged"; or this machine's own key for a file encrypted to
it), check the schema and the digest, validate everything as strictly as the
form and vault, find this machine (its /etc/ssh/ssh_host_*_key.pub against
the hosts' pinned keys; else its machine id or the machine token a host
record carries; else ask), remap (that host becomes localhost and its sudo
password moves to localhost; the source machine's localhost becomes a host
named after it with address user@hostname and ssh = false), resolve each
conflicting item in its own dialog (keep this machine's, replace with the
file's, add the file's under a new name; for a host key, keep or take the
pin), show one consent dialog (default Cancel), then apply it staged
(`apply_import`): the new form text and merged vault are built and checked
in memory, both are backed up to ~/.config/gateway/private/backups/import-*, the
vault is written, then the form (each atomically), and any failure restores
both. Then exactly the shown changes are approved and the imported
credentials are checked through their adapters (`verify_imported`): a
refresh token from another machine that doesn't check out is marked as
needing a fresh sign-in.

copy-to HOST: only to a form host whose host key was pinned before this
session; the user ticks the groups and types the host name in the dialog; the
remote must have the plugin (~/.config/gateway/gate); the export is encrypted
to the remote's recipient (`gate pubkey` there) and streamed to `gate import
--from-peer -` there. The dialogs say plainly that Claude can run commands on
that host (ssh is on), so what is copied is within reach of Claude's commands
there, and show the remote's recipient for the user to compare with `gate
pubkey` on that machine. (The recipient comes from the remote itself: a
machine where Claude has a shell can't be made to prove anything about its own
gate; see docs/dev/modules/ux.md.) --from-peer reads only an age stream for this machine's
own key, only when started by the system's sshd (the first non-shell ancestor
is a root-owned sshd/sshd-session binary, by executable path, whose session
monitor runs as root: an sshd a user started, a renamed shell or a symlink
doesn't count), applies without a dialog and records an `import` event the
next session shows.

Every question is a native gateway dialog in Claude Code (PLAN-v4 phase 3:
the passphrases in its private field, the groups as a checklist, the
summary to confirm). Where no dialog can open (claude -p, mods off, the
user's own terminal outside Claude Code) nothing is asked and the command
says why; there is no terminal prompt any more.

pubkey: print this machine's age recipient.
"""
from __future__ import annotations

import contextlib
import datetime
import hashlib
import json
import os
import re
import secrets as _secrets
import socket
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import accounts as acctmod
from . import audit, consent, hooks_session, paths, popup, testing, vault
from . import form as formmod

FORMAT = 3                        # PLAN-v4 phase 7: per-item selection, settings, a digest
FORMATS = (1, 2, 3)
MAX_CONFLICT_DIALOGS = 12           # more conflicting items than that: the rest keep this machine's
MAX_FILE = 5_000_000
AGE_TIMEOUT = 120
LABEL = "gateway"                 # dialog label for export/import (a reserved name, never an entry)
REMOTE_GATE = "~/.config/gateway/gate"
GROUP_HOSTS, GROUP_ACCOUNTS, GROUP_SUDO = "hosts", "accounts", "sudo"
SYNC_NAMES = ("dropbox", "onedrive", "google drive", "googledrive", "icloud drive", "icloud",
              "box", "box sync", "pcloud drive", "nextcloud", "owncloud", "mega", "sync",
              "creative cloud files", "seafile", "tresorit")
SHELLS = ("sh", "bash", "dash", "zsh", "fish", "ksh", "mksh", "tcsh", "csh", "env")
RECIPIENT_RE = re.compile(r"age1[0-9a-z]{58}")


class TransferError(Exception):
    """Refused: nothing was written or merged (the message is safe to show)."""


class WrongPassphrase(TransferError):
    """The passphrase doesn't open the file (the dialog asks again)."""


def _out(s: str) -> None:
    print(s, flush=True)


def _err(s: str) -> None:
    print(s, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# age (passphrase under a pty; recipient through stdin/stdout)
# ---------------------------------------------------------------------------


def _age() -> str:
    try:
        return vault._age("age")
    except vault.VaultError as e:
        raise TransferError(f"gateway: {e}") from None


def _run_age(args: list[str], passphrase: str, answers: int, fifo: Path,
             feed: bytes | None) -> tuple[int, str, bytes]:
    """age with args under a pty (agepass.run_age, shared with the daemon's
    key wrapping)."""
    from . import agepass
    try:
        return agepass.run_age(args, passphrase, answers, fifo, feed, AGE_TIMEOUT)
    except agepass.AgePassError as e:
        raise TransferError(str(e)) from None


def _tmpdir() -> Path:
    from . import agepass
    return agepass.tmpdir()


def encrypt_passphrase(plain: bytes, passphrase: str) -> bytes:
    from . import agepass
    try:
        return agepass.encrypt(plain, passphrase)
    except agepass.PassphraseTooLong as e:
        raise TransferError(f"{e}; nothing was exported") from None
    except agepass.AgePassError as e:
        raise TransferError("gateway: age didn't finish in time" if "in time" in str(e)
                            else "gateway: age could not encrypt the export") from None


def decrypt_passphrase(blob: bytes, passphrase: str) -> bytes:
    from . import agepass
    try:
        return agepass.decrypt(blob, passphrase)
    except agepass.BadPassphrase:
        raise WrongPassphrase("gateway: that passphrase doesn't open the file; nothing was "
                              "imported") from None
    except agepass.Tampered:
        raise TransferError("gateway: the file was changed or damaged after it was written (it "
                            "fails age's authentication check); nothing was imported") from None
    except agepass.PassphraseTooLong as e:
        raise TransferError(f"{e}; nothing was imported") from None
    except agepass.AgePassError as e:
        raise TransferError("gateway: age didn't finish in time" if "in time" in str(e)
                            else "gateway: age could not decrypt the file; nothing was "
                            "imported") from None


def encrypt_to(recipient: str, plain: bytes) -> bytes:
    if not RECIPIENT_RE.fullmatch(recipient):
        raise TransferError("gateway: that isn't an age recipient")
    r = subprocess.run([_age(), "-e", "-r", recipient], input=plain, capture_output=True, timeout=60)
    if r.returncode != 0:
        raise TransferError("gateway: age could not encrypt to the remote's key")
    return r.stdout


def decrypt_own(blob: bytes) -> bytes:
    if vault.brokered():
        # a wrapped vault key: only the gateway daemon holds the identity
        try:
            from .daemon import client
            return client.open_own(blob)
        except vault.VaultLocked as e:
            raise TransferError(str(e)) from None
        except vault.VaultError:
            raise TransferError("gateway: the stream isn't encrypted to this machine's gateway "
                                "key; nothing was imported") from None
    if not paths.key_path().is_file():
        raise TransferError("gateway: this machine has no gateway key yet")
    r = subprocess.run([_age(), "-d", "-i", str(paths.key_path())], input=blob,
                       capture_output=True, timeout=60)
    if r.returncode != 0:
        raise TransferError("gateway: the stream isn't encrypted to this machine's gateway key; "
                            "nothing was imported")
    return r.stdout


def age_kind(blob: bytes) -> str:
    """'passphrase' (scrypt), 'recipient' (X25519) or '' (not an age file)."""
    head = blob[:4096]
    if not head.startswith(b"age-encryption.org/v1\n"):
        return ""
    if b"\n-> scrypt " in head:
        return "passphrase"
    if b"\n-> X25519 " in head:
        return "recipient"
    return "other"


# ---------------------------------------------------------------------------
# This machine
# ---------------------------------------------------------------------------


def local_host_keys() -> list[str]:
    d = Path(testing.get("etc_ssh", "/etc/ssh"))
    out: list[str] = []
    try:
        files = sorted(d.glob("ssh_host_*_key.pub"))
    except OSError:
        return out
    for f in files:
        try:
            k = vault.norm_host_key(f.read_text(errors="replace"))
        except OSError:
            continue
        if k:
            out.append(k)
    return list(dict.fromkeys(out))


def source_info(data: dict[str, Any]) -> dict[str, Any]:
    m = data.get("machine") or {}
    name = m.get("name") or vault.short_hostname()
    return {"machine_id": vault.machine_id() or m.get("id"),
            "name": name if formmod.NAME_RE.fullmatch(str(name)) else vault.short_hostname(),
            "hostname": socket.gethostname(), "user": paths.local_user(),
            "ssh_host_keys": local_host_keys()}


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def default_path(today: datetime.date | None = None) -> Path:
    today = today or datetime.date.today()
    home = paths.user_home()
    base = home / "Downloads"
    if not base.is_dir():
        base = home
    p = base / f"gateway-{today:%Y%m%d}.age"
    n = 2
    while os.path.lexists(p):
        p = base / f"gateway-{today:%Y%m%d}-{n}.age"
        n += 1
    return p


def _in_git(folder: Path) -> bool:
    for d in [folder, *folder.parents]:
        if (d / ".git").exists():
            return True
    return False


def _synced(p: Path) -> bool:
    home = paths.user_home()
    lib = [home / "Library" / "Mobile Documents", home / "Library" / "CloudStorage"]
    spell = {str(p).casefold()}
    with contextlib.suppress(OSError):
        spell.add(str(p.resolve()).casefold())      # a symlinked home or temp folder
    for root in lib:
        rs = {str(root).casefold()}
        with contextlib.suppress(OSError):
            rs.add(str(root.resolve()).casefold())
        if any(s == r or s.startswith(r + "/") for s in spell for r in rs):
            return True
    for part in p.parts:
        low = part.casefold()
        if low in SYNC_NAMES or low.startswith(("dropbox", "onedrive", "google drive", "icloud")):
            return True
    for d in [p.parent, *p.parent.parents]:
        if (d / ".dropbox").exists() or (d / ".dropbox.cache").exists():
            return True
    return False


def check_export_path(raw: str | None) -> Path:
    p = default_path() if not raw else Path(raw)
    if raw:
        s = raw
        if s == "~" or s.startswith("~/"):
            s = str(paths.user_home()) + s[1:]
        p = Path(s)
        if not p.is_absolute():
            p = Path.cwd() / p
    p = Path(os.path.normpath(p))
    if formmod.UNSAFE.search(str(p)):
        raise TransferError("gateway: give a plain file name")
    if p.suffix != ".age":
        raise TransferError("gateway: the export file name must end in .age")
    if not p.parent.is_dir():
        raise TransferError(f"gateway: {paths.describe(p.parent)} isn't a folder")
    real = Path(os.path.realpath(p.parent)) / p.name
    if os.path.lexists(real) or os.path.lexists(p):
        raise TransferError(f"gateway: {paths.describe(p)} already exists; the gateway never "
                            "overwrites a file. Give another name")
    gw = Path(os.path.realpath(paths.home()))
    if real == gw or gw in real.parents:
        raise TransferError("gateway: not inside the gateway's own folder")
    if _in_git(real.parent):
        raise TransferError("gateway: that folder is inside a git work tree; the export must not "
                            "end up in a repository. Pick another folder (default ~/Downloads)")
    if _synced(real):
        raise TransferError("gateway: that folder is synced to a cloud service; pick a local "
                            "folder (default ~/Downloads)")
    return real


def _write_new(final: Path, blob: bytes) -> None:
    """Write blob as a new 0600 file; never replaces an existing one."""
    tmp = final.with_name(f".{final.name}.{os.getpid()}.{_secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
        os.chmod(tmp, 0o600)
        try:
            os.link(tmp, final)
        except FileExistsError:
            raise TransferError(f"gateway: {paths.describe(final)} appeared meanwhile; nothing "
                                "was written") from None
        except OSError:
            fd2 = os.open(final, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd2, "wb") as f:
                f.write(blob)
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# What goes in the file
# ---------------------------------------------------------------------------


def _doc(text: str) -> dict[str, Any]:
    try:
        return tomllib.loads(formmod.normalize_lenient(text))
    except tomllib.TOMLDecodeError:
        return {}


def entry_tables(sect: str, name: str, t: dict[str, Any]) -> list[tuple[str, list[tuple[str, Any]]]]:
    """An entry's tables as the form writes them (PLAN-v4 phase 7): its own
    keys, then each sub-table on its own ([hosts.NAME.policy],
    [hosts.NAME.shell], [hosts.NAME.workspaces.WS]), so a later edit can
    change one key line."""
    own = [(k, v) for k, v in t.items() if not isinstance(v, dict)]
    out: list[tuple[str, list[tuple[str, Any]]]] = [(f"{sect}.{name}", own)]
    for k, v in t.items():
        if not isinstance(v, dict):
            continue
        if k == "workspaces":
            for wn, wt in v.items():
                if isinstance(wt, dict):
                    out.append((f"{sect}.{name}.workspaces.{wn}", list(wt.items())))
        else:
            out.append((f"{sect}.{name}.{k}", list(v.items())))
    return out


def _tables_text(tables: list[tuple[str, list[tuple[str, Any]]]]) -> list[str]:
    out: list[str] = []
    for table, items in tables:
        out.append("")
        out.append(f"[{table}]")
        for k, v in items:
            out.append(f"{formmod._key(k)} = {formmod.toml_value(v)}")
    return out


SETTINGS_TABLES = ("settings", "shell", "policy", "vault")


def entries_text(raw: dict[str, Any], hosts: list[str], accts: list[str],
                 comment: str | None = None, settings: bool = False) -> str:
    """TOML tables for the given entries (and the settings tables), from
    their parsed (validated) tables."""
    out: list[str] = []
    if comment:
        out.append(f"# {comment}")
    if settings:
        for t in SETTINGS_TABLES:
            v = raw.get(t)
            if isinstance(v, dict) and v:
                out += _tables_text([(t, list(v.items()))])
    for sect, names in (("hosts", hosts), ("accounts", accts)):
        for n in names:
            t = (raw.get(sect) or {}).get(n)
            if not isinstance(t, dict):
                continue
            out += _tables_text(entry_tables(sect, n, t))
    return "\n".join(out).strip() + "\n"


@dataclass
class ExportItem:
    key: str              # "host:NAME", "host-secrets:NAME", "account:NAME", "account-secrets:NAME",
                          # "settings", "localhost-sudo"
    label: str            # what the selection pane shows (fixed words and validated names)
    checked: bool = True


def _secret_words(kind: str, rec: dict[str, Any]) -> list[str]:
    words = []
    if (rec.get("token") or {}).get("value"):
        words.append("token")
    if (rec.get("ssh_key") or {}).get("private"):
        words.append("ssh key")
    e = rec.get("entra") or {}
    if e.get("client_certificate"):
        words.append("client certificate")
    elif e.get("client_secret"):
        words.append("client secret")
    elif e.get("refresh_token"):
        words.append("refresh token (session state: needs a fresh sign-in after import)")
    return words


def export_items(form: formmod.Form, data: dict[str, Any]) -> list[ExportItem]:
    """What the selection pane offers, one item each (PLAN-v4 phase 7): every
    host and account entry, its secrets (SSH keys and sudo passwords, a
    token, a client secret or certificate) as their own item, the settings
    tables, and this machine's sudo password (unticked)."""
    items: list[ExportItem] = []
    raw = _doc(form.used_text)
    if any(isinstance(raw.get(t), dict) and raw.get(t) for t in SETTINGS_TABLES):
        items.append(ExportItem("settings", "Settings ([settings], [shell], [policy], [vault])"))
    for n, h in form.hosts.items():
        if not h.explicit or h.is_local:
            continue
        addr = h.address.render() if h.address else ""
        items.append(ExportItem(f"host:{n}", f"Host {n}" + (f" ({addr})" if addr and
                                                               formmod.safe(addr) else "")))
        rec = (data.get("hosts") or {}).get(n) or {}
        what = []
        if vault.live_keys(rec):
            what.append("SSH key")
        if rec.get("sudo"):
            what.append("sudo password")
        if what:
            items.append(ExportItem(f"host-secrets:{n}", f"{n}: its {' and '.join(what)}"))
    for n, a in form.accounts.items():
        items.append(ExportItem(f"account:{n}", f"Account {n} ({a.kind})"))
        words = _secret_words(a.kind, (data.get("accounts") or {}).get(n) or {})
        if words:
            items.append(ExportItem(f"account-secrets:{n}", f"{n}: its {', '.join(words)}"))
    if (data.get("localhost") or {}).get("sudo"):
        items.append(ExportItem("localhost-sudo", "This machine's sudo password", checked=False))
    return items


def _picked_keys(form: formmod.Form, data: dict[str, Any], picked: set[str]) -> set[str]:
    """Item keys from a selection; the old group words (hosts, accounts,
    sudo) expand to their items."""
    out = {p for p in picked if p not in (GROUP_HOSTS, GROUP_ACCOUNTS, GROUP_SUDO)}
    for it in export_items(form, data):
        k = it.key
        if (GROUP_HOSTS in picked and k.startswith(("host:", "host-secrets:"))) or \
                (GROUP_ACCOUNTS in picked and k.startswith(("account:", "account-secrets:"))) or \
                (GROUP_SUDO in picked and k == "localhost-sudo"):
            out.add(k)
    return out


def _digest(c: dict[str, Any]) -> str:
    body = {k: c.get(k) for k in ("schema", "created", "form", "vault", "from", "items")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"))
                          .encode("utf-8")).hexdigest()


def export_content(form: formmod.Form, data: dict[str, Any], picked: set[str]) -> dict[str, Any]:
    """The file's plaintext (format 3, PLAN-v4 phase 7): the picked entries'
    tables, the vault records they need (secrets only where their item was
    picked), where it came from, a schema version and a sha256 digest over
    all of it (checked on import, beside age's own authentication). Never a
    process id, socket, terminal or job id, task reference or account
    status: nothing tied to a live process or this machine's session."""
    keys = _picked_keys(form, data, set(picked))
    raw = _doc(form.used_text)
    hosts = [n for n, h in form.hosts.items() if h.explicit and not h.is_local and f"host:{n}" in keys]
    accts = [n for n in form.accounts if f"account:{n}" in keys]
    v = vault.export_view(data)
    for k in ("machine", "migrated", "imported", "cache"):
        v.pop(k, None)
    vh: dict[str, Any] = {}
    for n in hosts:
        r = dict((v.get("hosts") or {}).get(n) or {})
        r.pop("probe", None)
        r.pop("host_keys_previous", None)      # this machine's history (gate forget), not a pin
        if f"host-secrets:{n}" not in keys:
            r["keys"], r["sudo"] = [], {}
            r.pop("installed", None)
        vh[n] = r
    v["hosts"] = vh
    va: dict[str, Any] = {}
    for n in accts:
        r = dict((v.get("accounts") or {}).get(n) or {})
        r.pop("status", None)                  # re-verified on the machine that imports it
        if f"account-secrets:{n}" not in keys:
            for k in consent.CREDENTIAL_FIELDS:
                if k != "host_keys":
                    r.pop(k, None)
        va[n] = r
    v["accounts"] = va
    if "localhost-sudo" not in keys:
        v["localhost"] = {"sudo": {}}
    keep = set(hosts) | set(accts)
    v["aliases"] = {a: t for a, t in (v.get("aliases") or {}).items() if t in keep}
    c = {"gateway_export": FORMAT, "schema": FORMAT, "created": vault.now(),
         "form": entries_text(raw, hosts, accts, "exported by gateway", settings="settings" in keys),
         "vault": v, "from": source_info(data), "items": sorted(keys)}
    c["digest"] = _digest(c)
    return c


# ---------------------------------------------------------------------------
# Validation of incoming files
# ---------------------------------------------------------------------------

_STR_MAX = 65536


def _s(v: Any, what: str, maxlen: int = _STR_MAX, rx: re.Pattern[str] | None = None,
       optional: bool = True) -> str | None:
    if v is None and optional:
        return None
    if not isinstance(v, str) or len(v) > maxlen or "\x00" in v:
        raise TransferError(f"gateway: the file's {what} isn't valid; nothing was imported")
    if rx is not None and not rx.fullmatch(v):
        raise TransferError(f"gateway: the file's {what} isn't valid; nothing was imported")
    return v


def _keys(d: Any, what: str, allowed: tuple[str, ...]) -> dict[str, Any]:
    if not isinstance(d, dict):
        raise TransferError(f"gateway: the file's {what} isn't valid; nothing was imported")
    extra = [k for k in d if k not in allowed]
    if extra:
        raise TransferError(f"gateway: the file's {what} has unknown fields; nothing was imported")
    return d


def _host_keys(v: Any, what: str) -> list[str]:
    if v is None:
        return []
    if not isinstance(v, list):
        raise TransferError(f"gateway: the file's {what} isn't valid; nothing was imported")
    out = []
    for k in v:
        n = vault.norm_host_key(_s(k, what, 16384, optional=False))
        if not n or not vault.fingerprint_of(n):
            raise TransferError(f"gateway: the file's {what} isn't valid; nothing was imported")
        out.append(n)
    return out


_TS = re.compile(r"[0-9T:+\-. Z]{0,40}")


def _sudo_map(v: Any, what: str) -> dict[str, Any]:
    out = {}
    for u, rec in (v or {}).items():
        _s(u, f"{what} user", 32, formmod.USER_RE, optional=False)
        _keys(rec, what, ("password", "updated", "stale"))
        pw = _s(rec.get("password"), f"{what} password", 4096, optional=False)
        out[u] = {"password": pw, "updated": _s(rec.get("updated"), what, 40) or vault.now(),
                  "stale": bool(rec.get("stale"))}
    return out


def _ssh_key(rec: Any, what: str) -> dict[str, Any]:
    _keys(rec, what, ("private", "public", "fingerprint", "created", "retired"))
    priv = _s(rec.get("private"), what, 32768, optional=False)
    try:
        pub = vault.public_key_of(priv)
    except ValueError:
        raise TransferError(f"gateway: the file's {what} isn't an OpenSSH key; nothing was imported") from None
    given = rec.get("public")
    if given is not None and vault.norm_host_key(str(given)) != vault.norm_host_key(pub):
        raise TransferError(f"gateway: the file's {what} doesn't match its public key; nothing was imported")
    out = vault.key_record(priv, pub, _s(rec.get("created"), what, 40))
    if rec.get("retired"):
        out["retired"] = _s(rec.get("retired"), what, 40)
    return out


def validate_vault(v: Any, form: formmod.Form) -> dict[str, Any]:
    """The file's vault part, checked field by field (unknown fields refused)."""
    _keys(v, "vault", ("version", "localhost", "hosts", "accounts", "aliases", "events_seen"))
    if v.get("version") not in (None, 3):
        raise TransferError("gateway: the file is from another gateway version; nothing was imported")
    out: dict[str, Any] = {"version": 3, "localhost": {"sudo": {}}, "hosts": {}, "accounts": {},
                           "aliases": {}}
    lh = _keys(v.get("localhost") or {}, "localhost", ("sudo",))
    out["localhost"]["sudo"] = _sudo_map(lh.get("sudo") or {}, "localhost sudo")
    for n, rec in (v.get("hosts") or {}).items():
        if n not in form.hosts or form.hosts[n].is_local:
            raise TransferError("gateway: the file's vault has a host that isn't in its form; "
                                "nothing was imported")
        _keys(rec, f"host {n}", ("keys", "host_keys", "sudo", "probe", "installed", "pinned_at",
                                 "host_keys_previous", "machine_id", "machine_id_at"))
        # (host_keys_previous is never imported; machine_id is the host's machine
        # token from the other machine's first contact: checked again from here)
        keys = [_ssh_key(k, f"host {n} key") for k in (rec.get("keys") or [])]
        out["hosts"][n] = {"keys": keys, "host_keys": _host_keys(rec.get("host_keys"), f"host {n} host keys"),
                           "sudo": _sudo_map(rec.get("sudo") or {}, f"host {n} sudo"),
                           "probe": {"nopasswd": {}}}
        for k in ("installed", "pinned_at"):
            if rec.get(k):
                out["hosts"][n][k] = _s(rec.get(k), f"host {n}", 40)
        if rec.get("machine_id"):
            out["hosts"][n]["machine_id"] = _s(rec.get("machine_id"), f"host {n} machine", 40,
                                               re.compile(r"m_[a-z2-7]{26}"))
    for n, rec in (v.get("accounts") or {}).items():
        a = form.accounts.get(n)
        if a is None:
            raise TransferError("gateway: the file's vault has an account that isn't in its form; "
                                "nothing was imported")
        _keys(rec, f"account {n}", ("kind", "token", "ssh_key", "entra", "host_keys", "bound", "login",
                                    "status"))           # (status: never imported; checked here)
        if rec.get("kind") not in (None, a.kind):
            raise TransferError(f"gateway: the file's account {n} has the wrong kind; nothing was imported")
        r: dict[str, Any] = {"kind": a.kind, "bound": {"hosts": []}}
        if rec.get("token") is not None:
            t = _keys(rec["token"], f"account {n} token", ("value", "source", "updated", "stale"))
            r["token"] = {"value": _s(t.get("value"), f"account {n} token", optional=False),
                          "source": _s(t.get("source"), f"account {n} token", 20,
                                       re.compile(r"[a-z0-9-]{1,20}")) or "pasted",
                          "updated": _s(t.get("updated"), f"account {n}", 40) or vault.now(),
                          "stale": bool(t.get("stale"))}
        if rec.get("ssh_key") is not None:
            k = _ssh_key(rec["ssh_key"], f"account {n} ssh key")
            r["ssh_key"] = {"private": k["private"], "public": k["public"], "fingerprint": k["fingerprint"]}
        if rec.get("entra") is not None:
            e = _keys(rec["entra"], f"account {n} sign-in",
                      ("refresh_token", "client_secret", "client_certificate", "client_id",
                       "tenant_id", "refreshed", "scope", "kind"))
            if e.get("client_certificate") and not e.get("refresh_token"):
                from . import adapters
                pem = _s(e.get("client_certificate"), f"account {n} certificate", 16384,
                         optional=False)
                try:
                    adapters.cert_parts(pem)
                except ValueError:
                    raise TransferError(f"gateway: the file's account {n} certificate isn't valid; "
                                        "nothing was imported") from None
                r["entra"] = {"client_certificate": pem, "kind": "service-principal"}
            elif e.get("client_secret") and not e.get("refresh_token"):
                r["entra"] = {"client_secret": _s(e.get("client_secret"),
                                                  f"account {n} client secret", optional=False),
                              "kind": "service-principal"}
            else:
                r["entra"] = {"refresh_token": _s(e.get("refresh_token"), f"account {n} sign-in",
                                                  optional=False)}
            r["entra"] |= {"client_id": _s(e.get("client_id"), f"account {n} client", 64, formmod.GUID_RE),
                          "tenant_id": _s(e.get("tenant_id"), f"account {n} tenant", 100,
                                          re.compile(r"[A-Za-z0-9.-]{1,100}")),
                          "refreshed": _s(e.get("refreshed"), f"account {n}", 40)}
            if e.get("scope"):
                r["entra"]["scope"] = _s(e.get("scope"), f"account {n} scope", 200,
                                         re.compile(r"[A-Za-z0-9:/._~-]{1,200}"))
        if rec.get("host_keys") is not None:
            r["host_keys"] = _host_keys(rec.get("host_keys"), f"account {n} host keys")
        if rec.get("bound") is not None:
            b = _keys(rec["bound"], f"account {n} binding", ("hosts", "tenant", "client_id", "auth", "scope"))
            hs = b.get("hosts") or []
            if not isinstance(hs, list):
                raise TransferError(f"gateway: the file's account {n} binding isn't valid; "
                                    "nothing was imported")
            for h in hs:
                hh = _s(h, f"account {n} binding", 260, optional=False)
                bare = hh[1:] if hh.startswith(".") else hh
                try:
                    formmod.parse_hostport(bare)
                except ValueError:
                    raise TransferError(f"gateway: the file's account {n} binding isn't valid; "
                                        "nothing was imported") from None
            r["bound"] = {"hosts": list(hs)}
            for k in ("tenant", "client_id", "scope"):
                if b.get(k):
                    r["bound"][k] = _s(b.get(k), f"account {n} binding", 200,
                                       re.compile(r"[A-Za-z0-9:/._~-]{1,200}"))
            if b.get("auth"):
                r["bound"]["auth"] = _s(b.get("auth"), f"account {n} auth", 120, formmod.AUTH_RE)
        out["accounts"][n] = r
    for al, target in (v.get("aliases") or {}).items():
        _s(al, "alias", 100, re.compile(r"[A-Za-z0-9_.:@-]{1,100}"), optional=False)
        _s(target, "alias", 32, formmod.NAME_RE, optional=False)
        out["aliases"][al] = target
    return out


@dataclass
class Incoming:
    fmt: int
    form: formmod.Form
    raw: dict[str, Any]
    vault: dict[str, Any]
    source: dict[str, Any]
    source_sudo: dict[str, Any] = field(default_factory=dict)   # the source machine's own sudo
    created: str = ""
    report: str = ""


def _source(v: Any, fallback_host: str = "") -> dict[str, Any]:
    src = v if isinstance(v, dict) else {}
    name = src.get("name") if isinstance(src.get("name"), str) else ""
    if not formmod.NAME_RE.fullmatch(name or "") or name in formmod.RESERVED:
        base = re.sub(r"[^a-z0-9-]", "-", (fallback_host or str(src.get("hostname") or "")).split(".")[0].lower()).strip("-")
        name = base[:32] if base and base[0].isalpha() and base not in formmod.RESERVED else "other-machine"
    host = src.get("hostname") if isinstance(src.get("hostname"), str) else fallback_host
    host = (host or "").lower()
    if not formmod.valid_hostname(host):
        host = ""
    user = src.get("user") if isinstance(src.get("user"), str) and formmod.USER_RE.fullmatch(src.get("user")) else None
    mid = src.get("machine_id") if isinstance(src.get("machine_id"), str) and len(src.get("machine_id")) <= 100 else None
    keys = []
    try:
        keys = _host_keys(src.get("ssh_host_keys"), "source host keys")
    except TransferError:
        keys = []
    return {"name": name, "hostname": host, "user": user, "machine_id": mid, "ssh_host_keys": keys}


def parse_incoming(obj: Any) -> Incoming:
    if not isinstance(obj, dict):
        raise TransferError("gateway: this isn't a gateway export; nothing was imported")
    fmt = obj.get("gateway_export")
    if fmt == 1:
        from . import migrate
        try:
            m = migrate.map_export_v1(obj, local_user=paths.local_user())
        except migrate.MigrationError as e:
            raise TransferError(f"gateway: the 0.6 export couldn't be read ({formmod.strip_unsafe(str(e))[:120]}); "
                                "nothing was imported") from None
        form = formmod.parse_text(m.form_text)
        if form.syntax_error is not None:
            raise TransferError("gateway: the 0.6 export didn't convert cleanly; nothing was imported")
        v = m.vault
        vv = validate_vault({k: v.get(k) for k in ("localhost", "hosts", "accounts", "aliases")
                             if v.get(k) is not None}, form)
        src = _source({}, str(obj.get("from_host") or ""))
        sudo = _sudo_map((m.source_localhost or {}).get("sudo") or {}, "source sudo")
        return Incoming(1, form, _doc(m.form_text), vv, src, sudo, str(obj.get("created", ""))[:40],
                        m.report)
    if isinstance(fmt, int) and not isinstance(fmt, bool) and fmt > FORMAT:
        raise TransferError(f"gateway: the file is from a newer gateway (export format {fmt}; this "
                            f"gateway reads up to {FORMAT}); update the gateway plugin, then import "
                            "it; nothing was imported")
    if fmt not in FORMATS:
        raise TransferError("gateway: this isn't a gateway export; nothing was imported")
    if fmt == 2:
        _keys(obj, "export", ("gateway_export", "created", "form", "vault", "from"))
    else:
        _keys(obj, "export", ("gateway_export", "schema", "created", "form", "vault", "from",
                              "items", "digest"))
        if obj.get("schema") != fmt:
            raise TransferError("gateway: the file's schema version doesn't match its format; "
                                "nothing was imported")
        dg = obj.get("digest")
        if not isinstance(dg, str) or not re.fullmatch(r"[0-9a-f]{64}", dg) or dg != _digest(obj):
            raise TransferError("gateway: the file's contents don't match their checksum (it was "
                                "changed or damaged after it was written); nothing was imported")
    text = _s(obj.get("form"), "form", 1_000_000, optional=False)
    form = formmod.parse_text(text)
    if form.syntax_error is not None:
        raise TransferError("gateway: the file's form doesn't parse; nothing was imported")
    if form.errors or form.disabled:
        first = form.errors[0].render() if form.errors else "an entry is invalid"
        raise TransferError(f"gateway: the file's form has a problem ({first}); nothing was imported")
    vv = validate_vault(obj.get("vault"), form)
    src = _source(obj.get("from"))
    sudo = vv["localhost"]["sudo"]
    vv["localhost"]["sudo"] = {}
    return Incoming(fmt, form, _doc(text), vv, src, sudo, str(obj.get("created", ""))[:40])


# ---------------------------------------------------------------------------
# Planning an import
# ---------------------------------------------------------------------------

KEEP, REPLACE, RENAME = "keep", "replace", "rename"
KEEP_PIN, TAKE_PIN = "keep-pin", "take-pin"


@dataclass
class Conflict:
    """An item of the file that meets one of this machine's (PLAN-v4 phase
    7): what differs, and the choices the person gets for it."""
    name: str
    section: str                       # hosts | accounts | settings
    diffs: list[str]
    options: list[tuple[str, str]]     # (choice, label)

    def question(self) -> str:
        what = "the settings" if self.section == "settings" else f"{self.section[:-1]} {self.name}"
        return (f"The file's {what} differs from yours: " + "; ".join(self.diffs)[:400]
                + ". What should the import do with it?")


@dataclass
class ImportPlan:
    this_host: str | None = None
    how: str = ""                      # "host key", "machine id", "machine identity", "asked", ...
    same_machine: bool = False
    add_hosts: list[str] = field(default_factory=list)
    add_accounts: list[str] = field(default_factory=list)
    replace: list[str] = field(default_factory=list)    # entries (and "settings") the file's replace
    renames: dict[str, str] = field(default_factory=dict)  # the file's name -> its new name here
    settings_add: list[str] = field(default_factory=list)  # settings tables added (none here yet)
    fill: dict[str, list[str]] = field(default_factory=dict)
    keep: list[str] = field(default_factory=list)
    skip: list[str] = field(default_factory=list)       # "name (why)"
    hostkey_diff: list[str] = field(default_factory=list)
    take_pins: list[str] = field(default_factory=list)
    conflicts: list[Conflict] = field(default_factory=list)
    source_host: str | None = None     # the source machine as a new host
    localhost_sudo: bool = False
    tables: list[tuple[str, list[tuple[str, Any]], str]] = field(default_factory=list)
    vault_add: dict[str, Any] = field(default_factory=dict)
    changes: dict[str, list[str]] = field(default_factory=dict)   # consent lines per entry

    def lines(self, inc: Incoming, label: str) -> list[str]:
        out = [f"Import {label}" + (f" (from {inc.source['name']}" + (f", {inc.created[:10]}" if inc.created else "") + ")"
                                     if inc.source.get("name") else "") + ":"]
        if self.same_machine:
            out.append("The file comes from this machine; localhost stays localhost.")
        elif self.this_host:
            out.append(f"This machine is {self.this_host} in the file (found by {self.how}): it isn't "
                       "added as a host" + ("; its sudo password becomes this machine's" if self.localhost_sudo else "") + ".")
        added = self.add_hosts + self.add_accounts
        if added:
            out.append("Adds: " + ", ".join(added) + ".")
        for n in added + self.replace + list(self.renames.values()):
            for c in self.changes.get(n, []):
                out.append(f"  - {n}: {c}" if n not in added else "  - " + c)
        if self.replace:
            out.append("Replaces yours with the file's: " + ", ".join(self.replace) + ".")
        if self.renames:
            out.append("Adds under new names: " + ", ".join(f"{a} as {b}" for a, b in self.renames.items()) + ".")
        if self.settings_add:
            out.append("Adds settings: " + ", ".join(f"[{t}]" for t in self.settings_add) + ".")
        if self.source_host:
            out.append(f"{self.source_host} is the machine the file came from (ssh stays off until you turn it on).")
        if self.fill:
            out.append("Fills in: " + "; ".join(f"{n} ({', '.join(w)})" for n, w in self.fill.items()) + ".")
        if self.keep:
            out.append("Keeps yours: " + ", ".join(self.keep) + ".")
        if self.take_pins:
            out.append("Trusts the file's host key for: " + ", ".join(self.take_pins) + ".")
        if self.skip:
            out.append("Skips: " + "; ".join(self.skip) + ".")
        if self.hostkey_diff:
            out.append("Host key differs from yours (yours kept): " + ", ".join(self.hostkey_diff) + ".")
        if self.nothing():
            out.append("Nothing would change.")
        return out

    def nothing(self) -> bool:
        return not (self.add_hosts or self.add_accounts or self.fill or self.localhost_sudo or
                    self.replace or self.renames or self.settings_add or self.take_pins)


def find_this_machine(inc: Incoming, local_data: dict[str, Any]) -> tuple[str | None, str]:
    """Which host of the file is this machine (it becomes localhost here,
    never a remote host): its ssh host keys, then the machine token the
    gateway recorded for that host (PLAN-v4 phase 6, compared with this
    machine's own), then the file's own machine id (the file came from
    here)."""
    mine = set(local_host_keys())
    if mine:
        for n, rec in inc.vault["hosts"].items():
            if set(rec.get("host_keys") or []) & mine:
                return n, "host key"
        if set(inc.source.get("ssh_host_keys") or []) & mine:
            return None, "same machine"
    try:
        from .daemon import local_host_id
        token = local_host_id()
    except Exception:  # noqa: BLE001
        token = ""
    if token:
        for n, rec in inc.vault["hosts"].items():
            if rec.get("machine_id") == token:
                return n, "machine identity"
    mid = vault.machine_id() or (local_data.get("machine") or {}).get("id")
    if mid and inc.source.get("machine_id") and mid == inc.source["machine_id"]:
        return None, "same machine"
    return None, ""


def _unique(name: str, taken: set[str]) -> str:
    n, i = name, 2
    while n in taken or n in formmod.RESERVED:
        n = f"{name[:28]}-{i}"
        i += 1
    return n


def _host_diffs(fh: formmod.Host, lh: formmod.Host, src: dict[str, Any],
                lrec: dict[str, Any]) -> tuple[list[str], bool]:
    """(differences that matter for an endpoint or a path, host keys differ)."""
    diffs: list[str] = []
    fa = [a.render() for a in fh.addresses()]
    la = [a.render() for a in lh.addresses()]
    if fa != la:
        diffs.append(f"address {', '.join(fa) or 'none'} (yours {', '.join(la) or 'none'})")
    if (fh.via or "") != (lh.via or ""):
        diffs.append(f"via {fh.via or 'direct'} (yours {lh.via or 'direct'})")
    for k in ("ssh", "sudo"):
        if getattr(fh, k) != getattr(lh, k):
            diffs.append(f"{k} {consent.word(getattr(fh, k))} (yours {consent.word(getattr(lh, k))})")
    for wn, w in fh.workspaces.items():
        lw = lh.workspaces.get(wn)
        if lw is not None and (lw.root != w.root or lw.local != w.local):
            diffs.append(f"workspace {wn} root {w.root} (yours {lw.root})")
    if (fh.policy or {}) != (lh.policy or {}):
        diffs.append("policy differs")
    pins = set(src.get("host_keys") or [])
    lpins = set(lrec.get("host_keys") or [])
    return diffs, bool(pins and lpins and not pins & lpins)


def plan_import(inc: Incoming, local_form: formmod.Form, local_data: dict[str, Any],
                this_host: str | None, how: str,
                choices: dict[str, str] | None = None) -> ImportPlan:
    """What an import does. `choices` resolves the conflicts (name ->
    keep / replace / rename, or keep-pin / take-pin): a conflict without a
    choice is listed in `conflicts` and kept as it is here."""
    choices = choices or {}
    p = ImportPlan(this_host=this_host, how=how, same_machine=(how == "same machine"))
    taken = set(local_form.hosts) | set(local_form.accounts) | set(local_form.disabled)
    vadd: dict[str, Any] = {"hosts": {}, "accounts": {}, "aliases": {}, "localhost_sudo": {},
                            "pins": {}}
    raw_hosts = dict(inc.raw.get("hosts") or {})
    raw_accts = dict(inc.raw.get("accounts") or {})
    me = paths.local_user()
    when = datetime.date.today().isoformat()
    src_note = f"imported from {inc.source['name']} on {when}"

    def add_tables(sect: str, name: str, t: dict[str, Any], note: str = src_note) -> None:
        for i, (table, items) in enumerate(entry_tables(sect, name, t)):
            p.tables.append((table, items, note if i == 0 else ""))

    # this machine in the file -> localhost
    if this_host:
        hrec = inc.vault["hosts"].get(this_host) or {}
        pw = (hrec.get("sudo") or {}).get(me)
        if pw and not (local_data.get("localhost") or {}).get("sudo", {}).get(me):
            vadd["localhost_sudo"][me] = pw
            p.localhost_sudo = True
    if p.same_machine:
        pw = inc.source_sudo.get(me)
        if pw and not (local_data.get("localhost") or {}).get("sudo", {}).get(me):
            vadd["localhost_sudo"][me] = pw
            p.localhost_sudo = True
    # settings tables (PLAN-v4 phase 7)
    local_raw = _doc(local_form.used_text)
    sdiff = []
    for t in SETTINGS_TABLES:
        fv = inc.raw.get(t)
        if not isinstance(fv, dict) or not fv:
            continue
        lv = local_raw.get(t)
        if not isinstance(lv, dict) or not lv:
            p.settings_add.append(t)
        elif lv != fv:
            sdiff.append(f"[{t}]")
    if sdiff:
        ch = choices.get("settings")
        if ch == REPLACE:
            p.replace.append("settings")
        else:
            p.conflicts.append(Conflict("settings", "settings", [", ".join(sdiff) + " differ"],
                                        [(KEEP, "Keep my settings"),
                                         (REPLACE, "Use the file's settings")]))
            p.keep.append("settings")
    for t in p.settings_add + ([x.strip("[]") for x in sdiff] if "settings" in p.replace else []):
        p.tables.append((t, list((inc.raw.get(t) or {}).items()), src_note))
    for n, h in inc.form.hosts.items():
        if not h.explicit or n == this_host:
            continue
        if n == "localhost":
            continue          # the source's localhost: handled below as a named host
        src = inc.vault["hosts"].get(n) or {"keys": [], "host_keys": [], "sudo": {}}
        t = dict(raw_hosts.get(n) or {})
        if h.via and h.via == this_host:
            t.pop("via", None)        # reached through this machine: direct from here
        elif h.via and h.via not in local_form.hosts and h.via not in inc.form.hosts:
            p.skip.append(f"{n} (reached through {h.via}, which isn't here)")
            continue
        if n in local_form.hosts:
            lh = local_form.hosts[n]
            lrec = (local_data.get("hosts") or {}).get(n) or {}
            diffs, keydiff = _host_diffs(h, lh, src, lrec)
            ch = choices.get(n)
            if diffs:
                if ch == REPLACE:
                    p.replace.append(n)
                    add_tables("hosts", n, t, src_note + " (replacing this machine's entry)")
                    vadd["hosts"][n] = {"fill": False, "rec": src, "replace": True}
                    continue
                if ch == RENAME:
                    new = _unique(n, taken)
                    taken.add(new)
                    p.renames[n] = new
                    add_tables("hosts", new, t, src_note + f" (its name there: {n})")
                    vadd["hosts"][new] = {"fill": False, "rec": src}
                    continue
                p.conflicts.append(Conflict(n, "hosts", diffs + (["host key differs"] if keydiff else []),
                                            [(KEEP, "Keep mine"), (REPLACE, "Use the file's (replace mine)"),
                                             (RENAME, f"Add the file's as {_unique(n, taken)}")]))
            elif keydiff:
                if ch == TAKE_PIN:
                    p.take_pins.append(n)
                    vadd["pins"][n] = list(src.get("host_keys") or [])
                else:
                    p.conflicts.append(Conflict(n, "hosts", ["the pinned host key differs"],
                                                [(KEEP_PIN, "Keep my pinned host key"),
                                                 (TAKE_PIN, "Trust the file's host key")]))
                    p.hostkey_diff.append(n)
            got = []
            if not vault.live_keys(lrec) and vault.live_keys(src):
                got.append("keys")
            missing_sudo = {u: r for u, r in (src.get("sudo") or {}).items()
                            if u not in (lrec.get("sudo") or {})}
            if missing_sudo:
                got.append("sudo password")
            if got:
                p.fill[n] = got
                vadd["hosts"][n] = {"fill": True, "rec": src, "sudo": missing_sudo}
            if diffs:
                p.keep.append(n)
            continue
        if n in taken or n in local_form.accounts:
            if choices.get(n) == RENAME:
                new = _unique(n, taken)
                taken.add(new)
                p.renames[n] = new
                add_tables("hosts", new, t, src_note + f" (its name there: {n})")
                vadd["hosts"][new] = {"fill": False, "rec": src}
            else:
                p.keep.append(n)
                p.conflicts.append(Conflict(n, "hosts", [f"{n} is a name in use here"],
                                            [(KEEP, "Keep mine (skip the file's)"),
                                             (RENAME, f"Add the file's as {_unique(n, taken)}")]))
            continue
        p.add_hosts.append(n)
        taken.add(n)
        add_tables("hosts", n, t)
        vadd["hosts"][n] = {"fill": False, "rec": src}
    # the source machine's localhost -> a host named after it (never this machine's localhost)
    if not p.same_machine and inc.source.get("hostname"):
        name = _unique(inc.source["name"], taken)
        user = inc.source.get("user")
        addr = (f"{user}@" if user else "") + inc.source["hostname"]
        try:
            formmod.parse_address(addr)
            ok = True
        except ValueError:
            ok = False
        known_by_key = any(set(src.get("host_keys") or []) & set(inc.source.get("ssh_host_keys") or [])
                           for src in inc.vault["hosts"].values()) if inc.source.get("ssh_host_keys") else False
        if ok and not known_by_key:
            src_lh = (inc.raw.get("hosts") or {}).get("localhost") or {}
            # its sudo as the source's form says, else "ask" (this computer's
            # default; a remote host's own default, true, would widen it)
            t: dict[str, Any] = {"address": addr, "ssh": False,
                                 "sudo": src_lh.get("sudo", formmod.LOCALHOST_SUDO)}
            p.source_host = name
            p.add_hosts.append(name)
            taken.add(name)
            p.tables.append((f"hosts.{name}", list(t.items()),
                             src_note + " (the machine the file came from; set ssh = true to use it)"))
            rec = {"keys": [], "host_keys": list(inc.source.get("ssh_host_keys") or []),
                   "sudo": {}, "probe": {"nopasswd": {}}}
            if user and inc.source_sudo.get(user):
                rec["sudo"][user] = inc.source_sudo[user]
            vadd["hosts"][name] = {"fill": False, "rec": rec}
    for n, a in inc.form.accounts.items():
        src = inc.vault["accounts"].get(n) or {"kind": a.kind, "bound": {"hosts": []}}
        t = dict(raw_accts.get(n) or {})
        if n in local_form.accounts:
            la = local_form.accounts[n]
            lrec = (local_data.get("accounts") or {}).get(n) or {}
            differs = la.kind != a.kind or any(src.get(k) and lrec.get(k) and src.get(k) != lrec.get(k)
                                               for k in ("token", "ssh_key", "entra")) or \
                la.destinations() != a.destinations()
            ch = choices.get(n)
            if differs:
                if ch == REPLACE and la.kind == a.kind:
                    p.replace.append(n)
                    add_tables("accounts", n, t, src_note + " (replacing this machine's entry)")
                    vadd["accounts"][n] = {"fill": False, "rec": src, "replace": True}
                    continue
                if ch == RENAME:
                    new = _unique(n, taken)
                    taken.add(new)
                    p.renames[n] = new
                    add_tables("accounts", new, t, src_note + f" (its name there: {n})")
                    vadd["accounts"][new] = {"fill": False, "rec": src}
                    continue
                d = []
                if la.kind != a.kind:
                    d.append(f"kind {a.kind} (yours {la.kind})")
                if la.destinations() != a.destinations():
                    d.append("its sites or hosts differ")
                if any(src.get(k) and lrec.get(k) and src.get(k) != lrec.get(k)
                       for k in ("token", "ssh_key", "entra")):
                    d.append("another credential")
                opts = [(KEEP, "Keep mine")]
                if la.kind == a.kind:
                    opts.append((REPLACE, "Use the file's (replace mine)"))
                opts.append((RENAME, f"Add the file's as {_unique(n, taken)}"))
                p.conflicts.append(Conflict(n, "accounts", d, opts))
                p.keep.append(n)
                continue
            got = [k for k in ("token", "ssh_key", "entra") if src.get(k) and not lrec.get(k)]
            if got:
                p.fill[n] = got
                vadd["accounts"][n] = {"fill": True, "rec": src, "what": got}
            continue
        if n in taken:
            if choices.get(n) == RENAME:
                new = _unique(n, taken)
                taken.add(new)
                p.renames[n] = new
                add_tables("accounts", new, t, src_note + f" (its name there: {n})")
                vadd["accounts"][new] = {"fill": False, "rec": src}
            else:
                p.keep.append(n)
                p.conflicts.append(Conflict(n, "accounts", [f"{n} is a name in use here"],
                                            [(KEEP, "Keep mine (skip the file's)"),
                                             (RENAME, f"Add the file's as {_unique(n, taken)}")]))
            continue
        p.add_accounts.append(n)
        taken.add(n)
        add_tables("accounts", n, t)
        vadd["accounts"][n] = {"fill": False, "rec": src}
    added = set(p.add_hosts + p.add_accounts + list(p.renames.values()))
    for al, target in inc.vault.get("aliases", {}).items():
        tgt = p.renames.get(target, target)
        if tgt in added and al not in (local_data.get("aliases") or {}) and al not in taken:
            vadd["aliases"][al] = tgt
    p.vault_add = vadd
    # consent lines for what the form gains: as it will read after the merge
    if p.tables:
        new_text = stage_form_text(local_form.text, p)
        merged = formmod.parse_text(new_text)
        eff = consent.compute(merged, local_data)
        for n in p.add_hosts + p.add_accounts + p.replace + list(p.renames.values()):
            p.changes[n] = [c.what for c in eff.pending_for(n)]
            if n != "settings" and n not in merged.hosts and n not in merged.accounts:
                raise TransferError(f"gateway: {n} from the file wouldn't be valid here; nothing was imported")
    return p


def _remove_table_text(text: str, table: tuple[str, ...]) -> str:
    """The form text without [table] and its sub-tables (each header, its key
    lines, the comment block right above it); the comment block of the table
    that follows stays with that table."""
    lines = text.split("\n")
    out: list[str] = []
    i, n = 0, len(lines)

    def is_header(ln: str) -> tuple[str, ...] | None:
        m = formmod._HEADER.match(ln)
        if m and not formmod._KEYLINE.match(ln):
            return formmod._split_dotted(m.group(2))
        return None

    while i < n:
        t = is_header(lines[i])
        if t is not None and t[:len(table)] == table:
            while out and out[-1].strip().startswith("#"):
                out.pop()
            i += 1
            skipped: list[str] = []
            while i < n and is_header(lines[i]) is None:
                skipped.append(lines[i])
                i += 1
            keep: list[str] = []
            while skipped and skipped[-1].strip().startswith("#"):
                keep.insert(0, skipped.pop())
            out += keep
            continue
        out.append(lines[i])
        i += 1
    return "\n".join(out)


def stage_form_text(old: str, p: ImportPlan) -> str:
    """The whole new form, in memory (PLAN-v4 phase 7's staged import): the
    tables the file replaces taken out, the plan's tables appended with
    their comment headers. Nothing else of the person's form changes
    (apply_import checks it)."""
    text = old
    for name in p.replace:
        if name == "settings":
            for t in SETTINGS_TABLES:
                if inc_raw_get(p, t) is not None:
                    text = _remove_table_text(text, (t,))
        else:
            sect = "hosts" if any(tb == f"hosts.{name}" for tb, _i, _c in p.tables) else "accounts"
            text = _remove_table_text(text, (sect, name))
    lines: list[str] = []
    for table, items, comment in p.tables:
        lines.append("")
        if comment:
            lines += [f"# {cl}" for cl in comment.split("\n")]
        lines.append(formmod._header(table))
        for k, v in items:
            lines.append(f"{formmod._key(k)} = {formmod.toml_value(v)}")
    if not lines:
        return text
    body = "\n".join(lines).lstrip("\n")
    if not text.strip():
        return body + "\n"
    if not text.endswith("\n"):
        text += "\n"
    return text + "\n" + body + "\n"


def inc_raw_get(p: ImportPlan, table: str) -> Any:
    """Whether the plan carries a settings table of that name."""
    return next((dict(items) for tb, items, _c in p.tables if tb == table), None)


def _merge_vault(data: dict[str, Any], p: ImportPlan, written: list[str]) -> None:
    va = p.vault_add
    for u, rec in (va.get("localhost_sudo") or {}).items():
        data.setdefault("localhost", {}).setdefault("sudo", {}).setdefault(u, dict(rec))
    for n, pins in (va.get("pins") or {}).items():
        lrec = vault.host_record(data, n)
        lrec["host_keys_previous"] = list(lrec.get("host_keys") or [])
        lrec["host_keys"] = list(pins)
        lrec["pinned_at"] = vault.now()
        lrec.pop("machine_id", None)              # the identity is checked again at the next contact
    for n, item in (va.get("hosts") or {}).items():
        src = item["rec"]
        if item.get("fill"):
            lrec = vault.host_record(data, n)
            if not vault.live_keys(lrec) and vault.live_keys(src):
                lrec["keys"] = [dict(k) for k in src.get("keys") or []]
            for u, r in (item.get("sudo") or {}).items():
                lrec["sudo"].setdefault(u, dict(r))
            continue
        if n not in written:
            continue
        if item.get("replace"):
            (data.get("hosts") or {}).pop(n, None)
        rec = vault.host_record(data, n)
        rec["keys"] = [dict(k) for k in src.get("keys") or []]
        rec["host_keys"] = list(src.get("host_keys") or [])
        rec["sudo"] = {u: dict(r) for u, r in (src.get("sudo") or {}).items()}
        if src.get("installed"):
            rec["installed"] = src["installed"]
        if src.get("machine_id"):
            rec["machine_id"] = src["machine_id"]     # checked at the first contact from here
        rec["pinned_at"] = vault.now()     # pinned on this machine now (never the file's date)
    for n, item in (va.get("accounts") or {}).items():
        src = item["rec"]
        if item.get("fill"):
            lrec = vault.account_record(data, n, src.get("kind"))
            for k in item.get("what") or []:
                if src.get(k) and not lrec.get(k):
                    lrec[k] = json.loads(json.dumps(src[k]))
            lrec.pop("status", None)
            continue
        if n not in written:
            continue
        # an added entry: whatever this machine kept under that name (an entry
        # removed earlier) is not what the dialog listed; the file's record wins
        rec = vault.account_record(data, n, src.get("kind"))
        if src.get("kind"):
            rec["kind"] = src["kind"]
        rec["bound"] = {"hosts": []}
        rec.pop("status", None)
        vault.cache_clear(n)
        for k in consent.CREDENTIAL_FIELDS:
            rec.pop(k, None)
            if src.get(k):
                rec[k] = json.loads(json.dumps(src[k]))
        b = src.get("bound") or {}
        for k in ("tenant", "client_id", "scope", "auth"):
            if b.get(k):
                rec["bound"][k] = b[k]
        # bound.hosts is set by consent.approve from the approved destinations
    for al, target in (va.get("aliases") or {}).items():
        if target in written:
            data.setdefault("aliases", {}).setdefault(al, target)


def _backup(old_text: str | None) -> Path:
    """A copy of the form and the (encrypted) vault before an import, in a
    0700 folder under the private folder's backups (which Claude's file
    tools can't read, like the vault itself): what a failed import restores,
    and what the person can go back to."""
    d = paths.backups_dir() / f"import-{time.strftime('%Y%m%d-%H%M%S')}-{_secrets.token_hex(3)}"
    d.mkdir(parents=True, mode=0o700)
    os.chmod(d.parent, 0o700)
    os.chmod(d, 0o700)
    if old_text is not None:
        fd = os.open(d / "gateway.toml", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(old_text)
    for src, name in ((paths.vault_path(), "vault.age"),):
        if src.exists():
            fd = os.open(d / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(src.read_bytes())
    return d


def _restore(bk: Path, had_form: bool) -> None:
    form = paths.form_path()
    if (bk / "gateway.toml").exists():
        formmod._atomic_write(form, (bk / "gateway.toml").read_text(encoding="utf-8"))
    elif not had_form and form.exists():
        form.unlink()
    if (bk / "vault.age").exists():
        vault.write_private(paths.vault_path(), (bk / "vault.age").read_bytes())
    formmod.clear_cache()


def _check_staged(old: str, new: str, p: ImportPlan) -> None:
    """The staged form changes nothing but what the plan says: every table
    the person had is still there (minus the ones the file replaces), the
    new ones parse, and no entry left alone gains an error."""
    try:
        before = _doc(old) if old.strip() else {}
        after = tomllib.loads(formmod.normalize_lenient(new))
    except tomllib.TOMLDecodeError:
        raise TransferError("gateway: the merged form wouldn't parse; nothing was imported") from None
    removed = set(p.replace)
    for sect in ("hosts", "accounts"):
        for n, t in (before.get(sect) or {}).items():
            if n in removed:
                continue
            if (after.get(sect) or {}).get(n) != t:
                raise TransferError(f"gateway: the import would change {n}; nothing was imported")
    for t in SETTINGS_TABLES:
        if "settings" not in removed and t in before and after.get(t) != before[t]:
            raise TransferError("gateway: the import would change your settings; nothing was imported")
    old_f, new_f = formmod.parse_text(old), formmod.parse_text(new)
    touched = set(p.add_hosts + p.add_accounts + list(p.renames.values()) + p.replace)
    for prob in new_f.errors:
        if prob.entry and prob.entry not in touched and prob.render() not in {x.render() for x in old_f.errors}:
            raise TransferError(f"gateway: the import would break {prob.entry}; nothing was imported")


def apply_import(inc: Incoming, p: ImportPlan, label: str, *, peer: bool) -> str:
    """Write the merge as one staged step (PLAN-v4 phase 7): the new form
    and the merged vault are built in memory and checked, the form and the
    encrypted vault are backed up, the vault is written and then the form
    (each atomically); a failure on the way restores both from the backup
    and nothing of the import stays. Then the approvals of exactly the
    changes the dialog showed, and a check of the imported credentials."""
    fp = paths.form_path()
    old_text = fp.read_text(encoding="utf-8") if fp.exists() else ""
    had_form = fp.exists()
    new_text = stage_form_text(old_text, p) if p.tables else old_text
    _check_staged(old_text, new_text, p)
    written = sorted(set(p.add_hosts + p.add_accounts + list(p.renames.values()) +
                         [n for n in p.replace if n != "settings"]))
    paths.ensure_home()
    bk = _backup(old_text if had_form else None)
    try:
        with vault.locked():
            data = vault.load()
            _merge_vault(data, p, written)
            vault.ensure_machine(data)
            vault.add_event(data, "import", f"{'copy from' if peer else 'import of'} {inc.source['name']}: "
                            + (("added " + ", ".join(written)) if written else "nothing added")
                            + (("; filled in " + ", ".join(p.fill)) if p.fill else ""))
            vault.save(data)
        if testing.get("import_fail_after_vault"):
            raise OSError("test: the form write failed")
        if new_text != old_text:
            formmod._atomic_write(fp, new_text)
    except Exception as e:  # noqa: BLE001 - restored, and said so (no value in the text)
        try:
            _restore(bk, had_form)
        except Exception:  # noqa: BLE001
            raise TransferError(f"gateway: the import failed ({type(e).__name__}) and restoring "
                                f"failed too: your form and vault are in {paths.describe(bk)}") from None
        raise TransferError(f"gateway: the import failed ({type(e).__name__}); nothing was changed "
                            f"(restored from the backup in {paths.describe(bk)})") from None
    formmod.clear_cache()
    form = formmod.load(use_cache=False)
    approved = []
    for n in written + (["settings"] if "settings" in p.replace or p.settings_add else []):
        try:
            consent.approve(n, p.changes.get(n, []) and [f"{n}: {c}" for c in p.changes[n]], form=form,
                            keep_credentials=True)
            approved.append(n)
        except consent.ConsentChanged:
            pass
        except KeyError:
            pass
    checks = verify_imported(written + list(p.fill))
    audit.log("import", source=inc.source["name"], peer=peer, added=written, filled=list(p.fill),
              kept=p.keep, hostkey_diff=p.hostkey_diff, replaced=p.replace, renamed=p.renames,
              backup=str(bk))
    bits = [f"gateway: imported {label}"]
    adds = [n for n in written if n not in p.replace]
    if adds:
        bits.append("added " + ", ".join(adds))
    if p.replace:
        bits.append("replaced " + ", ".join(p.replace))
    if p.fill:
        bits.append("filled in " + ", ".join(p.fill))
    if p.localhost_sudo:
        bits.append("this machine's sudo password")
    if p.keep:
        bits.append("kept yours: " + ", ".join(p.keep))
    if p.hostkey_diff:
        bits.append("host key differs (yours kept): " + ", ".join(p.hostkey_diff))
    if p.source_host:
        bits.append(f"{p.source_host} has ssh = false until you turn it on")
    if checks:
        bits.append("checked: " + ", ".join(checks))
    if len([n for n in approved if n != "settings"]) != len(written):
        bits.append("some additions wait for your OK (gate check NAME)")
    bits.append(f"backup of the form and vault before it: {paths.describe(bk)}")
    return "; ".join(bits)


def verify_imported(names: list[str]) -> list[str]:
    """Each imported account with a credential checked through its adapter
    where practical (PLAN-v4 phase 7); a refresh token (session state from
    another machine) that doesn't check out is marked as needing a fresh
    sign-in. Under a test override only when the test asks (no network)."""
    from . import adapters
    if testing.active() is not None and not testing.get("verify_imports"):
        return []
    out = []
    try:
        data = vault.load()
    except vault.VaultError:
        return []
    form = consent.load_form(data)
    for n in names:
        a = form.accounts.get(n)
        rec = (data.get("accounts") or {}).get(n) or {}
        if a is None or not adapters.credential_of(a.kind, rec):
            continue
        try:
            c = adapters.check(a, rec, vault.load())
        except Exception:  # noqa: BLE001
            c = adapters.Check("unknown", "the check failed")
        if (rec.get("entra") or {}).get("refresh_token") and c.state != "connected":
            c = adapters.Check("reauthentication_required", "needs a fresh sign-in on this "
                               "machine (session state from another machine)", c.meta, vault.now())
        c.checked_at = c.checked_at or vault.now()
        try:
            adapters.record(n, a.kind, c)
        except Exception:  # noqa: BLE001
            pass
        out.append(f"{n} {'needs a fresh sign-in' if c.state == 'reauthentication_required' else c.state}")
    return out


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def _load() -> tuple[formmod.Form, consent.Effective, dict[str, Any]]:
    msgs: list[str] = []
    form, eff, data = hooks_session.prepare(msgs, write=False)
    if data is None:
        if vault.exists():
            raise TransferError("gateway: the vault can't be read; nothing was done")
        data = vault.empty()
    return form, eff, data


def _groups_options(form: formmod.Form, data: dict[str, Any]) -> tuple[list[str], dict[str, str], list[str]]:
    hosts = [n for n, h in form.hosts.items() if h.explicit and not h.is_local]
    accts = list(form.accounts)
    opts: list[str] = []
    key: dict[str, str] = {}
    checked: list[str] = []
    if hosts:
        o = f"Hosts ({len(hosts)}): " + ", ".join(hosts[:6]) + (" ..." if len(hosts) > 6 else "")
        opts.append(o)
        key[o] = GROUP_HOSTS
        checked.append(o)
    if accts:
        o = f"Accounts ({len(accts)}): " + ", ".join(accts[:6]) + (" ..." if len(accts) > 6 else "")
        opts.append(o)
        key[o] = GROUP_ACCOUNTS
        checked.append(o)
    if (data.get("localhost") or {}).get("sudo"):
        o = "This machine's sudo password"
        opts.append(o)
        key[o] = GROUP_SUDO
    return opts, key, checked


def _pick_groups(form: formmod.Form, data: dict[str, Any], prompt: str) -> set[str]:
    """The selection pane (PLAN-v4 phase 7): one line per host, account,
    their secrets, the settings and this machine's sudo password (a
    checklist; with more items than a pane holds, the groups instead)."""
    items = export_items(form, data)
    if not items:
        raise popup_stop(popup.Outcome.FAILED, "gateway: there is nothing to export yet")
    from .daemon.dialogs import MAX_OPTIONS
    if len(items) <= MAX_OPTIONS:
        opts = [it.label for it in items]
        key = {it.label: it.key for it in items}
        checked = [it.label for it in items if it.checked]
    else:
        opts, key, checked = _groups_options(form, data)
    oc, picked = popup.checklist(LABEL, prompt, opts, checked, what="contents")
    if oc != popup.Outcome.OK or picked is None:
        raise popup_stop(oc, popup.message(oc, LABEL, "export"))
    groups = {key[x] for x in picked if x in key}
    if not groups:
        raise popup_stop(popup.Outcome.CANCELLED, "gateway: nothing was ticked; nothing was exported")
    return groups


class _Stop(Exception):
    def __init__(self, outcome: str, msg: str):
        super().__init__(msg)
        self.outcome, self.msg = outcome, msg


def popup_stop(outcome: str, msg: str) -> _Stop:
    return _Stop(outcome, msg)


PASSPHRASE_PROMPT = ("Protect the export file with a passphrase of at least 12 characters. You'll "
                     "need it to import the file (or to open it with age -d). It isn't stored "
                     "anywhere.")


def _passphrase() -> str:
    """The export passphrase, typed twice in the gateway dialog's private
    field (at least 12 characters). There is no generated one to show
    (review round 2: a value shown in a dialog is out of the private field)."""
    oc, first = popup.secret(LABEL, "export passphrase", PASSPHRASE_PROMPT,
                             verify=lambda v: (len(v) >= 12, "it needs at least 12 characters"), lazy=False)
    if oc != popup.Outcome.OK or not first:
        raise _Stop(oc, popup.message(oc, LABEL, "export passphrase"))
    oc, second = popup.secret(LABEL, "export passphrase", "Type the passphrase again.",
                              verify=lambda v: (v == first, "the two passphrases differ"), lazy=False)
    if oc != popup.Outcome.OK:
        raise _Stop(oc, popup.message(oc, LABEL, "export passphrase"))
    return first


def _ask(entry: str, what: str, job: Any, *, kind: str, notice: str, cmd: str = "",
         digest: str = "") -> tuple[str, Any]:
    """Run a dialog job through the broker: every step a native gateway
    dialog in Claude Code. Where none can open (claude -p, mods off, mobile,
    VS Code, the user's own terminal outside Claude Code) nothing is asked
    and popup.run prints why; there is no terminal path (PLAN-v4 phase 3).
    The job's answer is the line it prints (never a secret), so it is kept
    for the retry Claude makes when its wait ran out first (`public`; the
    digest names this very request: the file, the destination, the host)."""
    return popup.run(entry, what, job, kind=kind, lazy=False, notice=notice, digest=digest,
                     public=True)


def _shown_cmd(base: str, path: str | None) -> str:
    """The command named in messages (the path only if it is plain)."""
    cmd = f"{base} {path}" if path else base
    return cmd if re.fullmatch(r"~/\.config/gateway/gate [a-z][a-z-]{1,20}(?: [A-Za-z0-9_./~@:+-]{1,200})?",
                               cmd) else base


def export_cmd(path: str | None) -> int:
    """`gate export [FILE]` (SPEC 16)."""
    try:
        form, eff, data = _load()
        dest = check_export_path(path)
    except TransferError as e:
        _err(str(e))
        return 2

    def job() -> tuple[str, str]:
        try:
            f2, _e2, d2 = _load()
            groups = _pick_groups(f2, d2, f"Export the gateway to {paths.describe(dest)}. Tick what "
                                          "goes into the file (passwords, keys and tokens included):")
            pw = _passphrase()
            content = export_content(f2, d2, groups)
            blob = encrypt_passphrase(json.dumps(content, indent=1).encode(), pw)
            _write_new(dest, blob)
            nh, na = len(content["vault"]["hosts"]), len(content["vault"]["accounts"])
            items = content["items"]
            with vault.edit() as d:
                vault.add_event(d, "export", f"to {paths.describe(dest)}: {len(items)} items")
            audit.log("export", path=str(dest), items=items, hosts=nh, accounts=na)
            return popup.Outcome.OK, (
                f"gateway: exported {nh} host{'s' if nh != 1 else ''} and {na} "
                f"account{'s' if na != 1 else ''}"
                + (" with the settings" if "settings" in items else "")
                + (" and this machine's sudo password" if "localhost-sudo" in items else "")
                + f" to {paths.describe(dest)} (passphrase-protected, mode 0600). Import it on the "
                  f"other machine with ~/.config/gateway/gate import FILE")
        except _Stop as s:
            return s.outcome, s.msg
        except TransferError as e:
            return popup.Outcome.FAILED, str(e)
    try:
        oc, line = _ask(LABEL, "export", job, kind="export",
                        notice="gateway: waiting for the user to confirm the export in the gateway dialog in Claude Code",
                        cmd=_shown_cmd("~/.config/gateway/gate export", path),
                        digest=popup._digest(["export", str(dest)]))
    except popup.StillOpen:
        return popup.EX_TEMPFAIL
    if oc == popup.Outcome.OK:
        _out(line)
        return 0
    _err(line if isinstance(line, str) and line else popup.message(oc, LABEL, "export"))
    return 1


def _read_input(path: str, peer: bool) -> bytes:
    if peer:
        if path != "-":
            raise TransferError("gateway: --from-peer reads only standard input (-)")
        data = sys.stdin.buffer.read(MAX_FILE + 1)
    else:
        s = path
        if s == "~" or s.startswith("~/"):
            s = str(paths.user_home()) + s[1:]
        p = Path(s)
        if not p.is_absolute():
            p = Path.cwd() / p
        if not p.is_file():
            raise TransferError(f"gateway: {paths.describe(p)} isn't a file")
        if paths.is_protected(p):
            raise TransferError("gateway: that file is inside the gateway's private folder")
        with open(p, "rb") as f:
            data = f.read(MAX_FILE + 1)
    if len(data) > MAX_FILE:
        raise TransferError("gateway: that file is too large for a gateway export")
    return data


SSHD_NAMES = ("sshd", "sshd-session")


def _mac_short(pid: int) -> tuple[int, int, str] | None:  # pragma: no cover - macOS only
    """(ppid, effective uid, comm) from proc_pidinfo(PROC_PIDT_SHORTBSDINFO),
    which (unlike PROC_PIDTBSDINFO) also answers for root's processes."""
    import ctypes
    import ctypes.util

    class _Short(ctypes.Structure):   # struct proc_bsdshortinfo (sys/proc_info.h)
        _fields_ = [("pid", ctypes.c_uint32), ("ppid", ctypes.c_uint32), ("pgid", ctypes.c_uint32),
                    ("status", ctypes.c_uint32), ("comm", ctypes.c_char * 16),
                    ("flags", ctypes.c_uint32), ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32),
                    ("ruid", ctypes.c_uint32), ("rgid", ctypes.c_uint32), ("svuid", ctypes.c_uint32),
                    ("svgid", ctypes.c_uint32), ("rfu", ctypes.c_uint32)]
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.dylib", use_errno=True)
    s = _Short()
    n = libc.proc_pidinfo(pid, 13, ctypes.c_uint64(0), ctypes.byref(s), ctypes.sizeof(s))
    if n != ctypes.sizeof(s) or s.pid != pid:
        return None
    return int(s.ppid), int(s.uid), s.comm.decode("utf-8", "replace")


def _proc_info(pid: int) -> tuple[int, str | None, int | None, str]:
    """(parent pid, real executable path or None, effective uid or None, comm)
    of a process, from the kernel (proc_pidpath / proc_pidinfo on macOS,
    /proc on Linux), never from a name the process chose for itself."""
    from . import ancestry
    try:
        exe = ancestry.exe_path(pid)
        exe = os.path.realpath(exe) if exe else None
    except Exception:  # noqa: BLE001
        exe = None
    ppid = 0
    uid: int | None = None
    comm = ""
    try:
        if sys.platform == "darwin":
            got = _mac_short(pid)
            if got is None:
                return 0, exe, None, ""
            ppid, uid, comm = got
        else:
            ppid = int(ancestry.parent_pid(pid))
            with open(f"/proc/{pid}/status") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        uid = int(line.split()[2])       # effective uid
                        break
            with open(f"/proc/{pid}/stat", "rb") as fb:
                raw = fb.read()
            comm = raw[raw.find(b"(") + 1:raw.rfind(b")")].decode("utf-8", "replace")
    except (OSError, ValueError, IndexError):
        pass
    return ppid, exe, uid, comm


def _root_owned_binary(path: str) -> bool:
    """A system binary: the file and every folder above it owned by root and
    writable by nobody else (so no user put it there)."""
    try:
        st = os.stat(path)
        if st.st_uid != 0 or st.st_mode & 0o022:
            return False
        d = os.path.dirname(path)
        while True:
            sd = os.stat(d)
            if sd.st_uid != 0 or sd.st_mode & 0o022:
                return False
            if d in ("/", ""):
                return True
            d = os.path.dirname(d)
    except OSError:
        return False


def _is_system_sshd(exe: str | None, comm: str) -> bool:
    if exe:
        return os.path.basename(exe) in SSHD_NAMES and _root_owned_binary(exe)
    return comm in SSHD_NAMES      # exe unreadable (Linux, another user's or a non-dumpable process)


def sshd_ancestor(pid: int) -> bool:
    """Walk up from `pid` through shells (by executable path). The first other
    process must be the system sshd's session child (a root-owned sshd or
    sshd-session binary) whose parent, the session monitor, runs as root and
    is the system sshd too. An sshd a user started (everything runs as the
    user), a renamed shell or a symlink named sshd don't pass."""
    for _ in range(16):
        if pid <= 1:
            return False
        ppid, exe, _uid, comm = _proc_info(pid)
        name = os.path.basename(exe) if exe else ""
        if name in SHELLS:
            pid = ppid
            continue
        if not _is_system_sshd(exe, comm) or ppid <= 1:
            return False
        _pp, pexe, puid, pcomm = _proc_info(ppid)
        return puid == 0 and _is_system_sshd(pexe, pcomm)
    return False


def started_by_sshd() -> bool:
    """True when `gate import --from-peer -` was started over ssh by the
    system's sshd (`ssh HOST gate import --from-peer -`), not by Claude's Bash,
    a local terminal or an sshd a user runs."""
    if testing.get("peer_parent_ok") is not None:
        return bool(testing.get("peer_parent_ok"))
    return sshd_ancestor(os.getppid())


def import_cmd(path: str, from_peer: bool = False) -> int:
    """`gate import FILE` / `--from-peer -` (SPEC 16)."""
    try:
        if from_peer and not started_by_sshd():
            raise TransferError("gateway: --from-peer is only for `gate copy-to` over ssh from "
                                "another machine; to import a file, run gate import FILE")
        blob = _read_input(path, from_peer)
        kind = age_kind(blob)
        if from_peer and kind != "recipient":
            raise TransferError("gateway: --from-peer takes only a stream encrypted to this machine's "
                                "gateway key; nothing was imported")
        form, eff, data = _load()
    except TransferError as e:
        _err(str(e))
        return 2
    label = "the copy" if from_peer else paths.describe(Path(path)) if path != "-" else "the stream"
    if from_peer:
        try:
            inc = parse_incoming(json.loads(decrypt_own(blob).decode("utf-8")))
            this, how = find_this_machine(inc, data)
            p = plan_import(inc, form, data, this, how)
            line = apply_import(inc, p, f"a copy from {inc.source['name']}", peer=True)
        except (TransferError, UnicodeDecodeError, ValueError) as e:
            msg = str(e) if isinstance(e, TransferError) else "gateway: the stream isn't a gateway export"
            _err(msg)
            return 2
        _out(line)
        return 0
    if kind not in ("passphrase", "recipient"):
        _err("gateway: that isn't a gateway export file (age-encrypted); nothing was imported")
        return 2

    def job() -> tuple[str, str]:
        try:
            if kind == "recipient":
                raw = decrypt_own(blob)
            else:
                # the passphrase in the private field; a wrong one asks again
                # ("That didn't work"), a damaged or changed file stops at once
                opened: dict[str, bytes] = {}
                tampered: list[str] = []

                def verify(pw: str) -> tuple[bool, str]:
                    try:
                        opened["raw"] = decrypt_passphrase(blob, pw)
                        return True, ""
                    except WrongPassphrase:
                        return False, "that passphrase doesn't open the file"
                    except TransferError as e:
                        # asking again can't help: the dialog closes saying why
                        tampered.append(str(e))
                        raise popup.StopDialog(str(e)) from None
                oc, _pw = popup.secret(LABEL, "import passphrase",
                                       f"The passphrase of {Path(path).name if formmod.safe(Path(path).name) else 'the file'}.",
                                       verify=verify, lazy=False)
                _pw = None
                if tampered:
                    raise TransferError(tampered[0])
                if oc != popup.Outcome.OK or "raw" not in opened:
                    raise _Stop(oc, popup.message(oc, LABEL, "import passphrase"))
                raw = opened.pop("raw")
            try:
                inc = parse_incoming(json.loads(raw.decode("utf-8")))
            except (UnicodeDecodeError, ValueError):
                raise TransferError("gateway: the file decrypted but isn't a gateway export") from None
            f2, _e2, d2 = _load()
            this, how = find_this_machine(inc, d2)
            if not this and how != "same machine":
                cands = [n for n, h in inc.form.hosts.items() if h.explicit and not h.is_local]
                if cands:
                    none = "None of them (this machine isn't in the file)"
                    oc, picked = popup.choice(LABEL, "Which host in the file is this machine? (The "
                                              "gateway couldn't tell from its host keys.)",
                                              cands + [none], what="this machine")
                    if oc != popup.Outcome.OK or picked is None:
                        raise _Stop(oc, popup.message(oc, LABEL, "import"))
                    if picked in cands:
                        this, how = picked, "your answer"
            plan = plan_import(inc, f2, d2, this, how)
            # each item that meets one of this machine's: the person decides
            # (keep mine, use the file's, add it under another name; a changed
            # host key: keep the pin or trust the file's) (PLAN-v4 phase 7)
            if plan.conflicts:
                choices: dict[str, str] = {}
                for c in plan.conflicts[:MAX_CONFLICT_DIALOGS]:
                    labels = [lb for _ch, lb in c.options]
                    oc, picked = popup.choice(LABEL, c.question(), labels, what="import conflict")
                    if oc != popup.Outcome.OK or picked is None:
                        raise _Stop(oc, popup.message(oc, LABEL, "import"))
                    choices[c.name] = next(ch for ch, lb in c.options if lb == picked)
                plan = plan_import(inc, f2, d2, this, how, choices)
            if plan.nothing():
                return popup.Outcome.OK, "gateway: the file holds nothing new for this machine; nothing changed"
            lines = plan.lines(inc, Path(path).name if formmod.safe(Path(path).name) else "the file")
            oc = popup.confirm(LABEL, lines + ["", "Import this? Cancel changes nothing."],
                               title="import", ok_label="Import", what="import confirmation")
            if oc != popup.Outcome.OK:
                raise _Stop(oc, popup.message(oc, LABEL, "import"))
            return popup.Outcome.OK, apply_import(inc, plan, label, peer=False)
        except _Stop as s:
            return s.outcome, s.msg
        except TransferError as e:
            return popup.Outcome.FAILED, str(e)
    try:
        oc, line = _ask(LABEL, "import", job, kind="import",
                        notice="gateway: waiting for the user to confirm the import in the gateway dialog in Claude Code",
                        cmd=_shown_cmd("~/.config/gateway/gate import", path),
                        digest=popup._digest(["import", str(Path(path).resolve()) if path != "-" else "-",
                                              hashlib.sha256(blob).hexdigest()]))
    except popup.StillOpen:
        return popup.EX_TEMPFAIL
    if oc == popup.Outcome.OK:
        _out(line)
        return 0
    _err(line if isinstance(line, str) and line else popup.message(oc, LABEL, "import"))
    return 1


def remote(name: str, command: str, input: bytes | None = None, timeout: float = 120) -> tuple[int, bytes, bytes]:
    """Run COMMAND on form host NAME over the gateway's ssh (group ssh's
    in-process runner when it exists; tests replace this)."""
    from . import ssh
    runner = getattr(ssh, "run", None)
    if runner is None:
        raise TransferError("gateway: copy-to needs the gateway's ssh, which isn't available in "
                            "this build yet")
    r = runner(name, command, input=input, timeout=timeout)
    if isinstance(r, tuple):
        return int(r[0]), bytes(r[1] or b""), bytes(r[2] or b"")
    return int(r.returncode), bytes(r.stdout or b""), bytes(r.stderr or b"")


MIN_PIN_AGE = 12 * 3600     # copy-to when this session's start can't be told


def _session_start() -> float | None:
    """When this Claude Code session started: the record prompt.sh writes into
    private/sessions/ at the session's first prompt (Claude's commands can't
    write there). None when there is no session id or no record (then copy-to
    falls back to MIN_PIN_AGE, whatever the environment says)."""
    sid = os.environ.get("CLAUDE_CODE_SESSION_ID")
    if not sid:
        return None
    try:
        p = paths.private_dir() / "sessions" / f"{popup.sid_slug(sid)}.env"
        t = p.stat().st_mtime
    except (OSError, paths.PathError):
        return None
    return t if t <= time.time() + 60 else None


def _ts(s: str | None) -> float | None:
    if not isinstance(s, str) or not s:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S"):
        try:
            d = datetime.datetime.strptime(s[:24].replace("Z", "+0000"), fmt)
            return d.timestamp()
        except (ValueError, OverflowError):
            continue
    return None


def pinned_since(data: dict[str, Any], rec: dict[str, Any]) -> float | None:
    """When a host's keys were pinned: hosts[N].pinned_at, else (v2 pins
    carried over by the migration) the migration's time; None if unknown."""
    t = _ts(rec.get("pinned_at"))
    if t is None:
        t = _ts((data.get("migrated") or {}).get("at"))
    return t


def pinned_too_recently(name: str, data: dict[str, Any], rec: dict[str, Any]) -> str | None:
    """Why copy-to must not go to `name` yet (SPEC 16: only to a host pinned
    before this session), or None."""
    pinned = pinned_since(data, rec)
    if pinned is None:
        return (f"gateway: when {name}'s host key was pinned isn't known; copy-to only goes to a "
                f"host pinned before this session. Ask the user to run gate forget {name} host-keys "
                f"and gate check {name}, then copy in a later session")
    start = _session_start()
    if start is not None:
        if pinned >= start - 1:
            return (f"gateway: {name}'s host key was pinned in this session; copy-to only goes to "
                    "a host pinned before this session (start a new session, then try again)")
        return None
    if time.time() - pinned < MIN_PIN_AGE:
        return (f"gateway: {name}'s host key was pinned less than {MIN_PIN_AGE // 3600} hours ago "
                "and this session's start can't be told; copy-to only goes to a host pinned before "
                "this session (try again in a new Claude Code session, or later)")
    return None


def copy_warning(name: str) -> str:
    """Fixed text in the copy-to dialog: copy-to needs ssh on for the host, so
    Claude's commands reach that machine as the user (no gateway hooks run
    there): what is copied is within their reach, including the remote's own
    gateway key and whatever `gate` there prints."""
    return (f"Claude can run commands on {name} (ssh is on for it in gateway.toml), so whatever you "
            f"copy there is within reach of Claude's commands on {name}. Copy only what you'd let "
            f"Claude use on {name}.")


def copy_confirm_prompt(name: str, recipient: str) -> str:
    shown = recipient if RECIPIENT_RE.fullmatch(recipient or "") else "(not shown)"
    return (f"Type the host name ({name}) to confirm the copy. {name}'s gateway key, as its gate "
            f"pubkey printed it: {shown}. If you want to be sure it's the machine you mean, "
            f"~/.config/gateway/gate pubkey in a terminal on {name} prints the same key.")


def copy_to(host: str) -> int:
    """`gate copy-to HOST` (SPEC 16)."""
    try:
        form, eff, data = _load()
        name = acctmod.resolve_name(host, data.get("aliases") or {}, form)
        if not formmod.safe(name) or name not in form.hosts or form.hosts[name].is_local:
            raise TransferError(f"gateway: {formmod.safe(host) or 'that'} isn't a host in gateway.toml; "
                                "copy-to sends to one of your form hosts")
        if eff.hosts[name].ssh is not True:
            raise TransferError(f"gateway: ssh to {name} isn't on (or waits for the user's OK); "
                                f"run gate check {name} first")
        rec = (data.get("hosts") or {}).get(name) or {}
        if not rec.get("host_keys"):
            raise TransferError(f"gateway: {name}'s host key isn't pinned yet; run gate check {name} "
                                "first (and copy in a later session)")
        why = pinned_too_recently(name, data, rec)
        if why:
            raise TransferError(why)
        rc, out, _e = remote(name, f"test -x {REMOTE_GATE} && echo gateway-present")
        if b"gateway-present" not in out:
            _err(f"gateway: {name} doesn't have the gateway yet. The user installs it there: pixi "
                 "(https://pixi.sh) and Claude Code, signing in to Claude Code on "
                 f"{name} themselves (Claude can't do that over ssh), then `/plugin marketplace add "
                 "p-w-rs/gateway` and `/plugin install gate@gateway`, and one Claude Code session "
                 "there whose first-time setup finishes (about a minute). Then run gate copy-to "
                 f"{name} again.")
            return 1
        rc, out, _e = remote(name, f"{REMOTE_GATE} pubkey")
        recip = out.decode(errors="replace").strip().splitlines()[-1:] if out else []
        recipient = recip[0].strip() if recip else ""
        if rc == 75:
            raise TransferError(f"gateway: the gateway on {name} is still setting up (its first "
                                "Claude Code session builds it, about a minute; or the build failed "
                                f"there); try gate copy-to {name} again in a minute")
        if rc != 0 or not RECIPIENT_RE.fullmatch(recipient):
            raise TransferError(f"gateway: {name} didn't give its gateway key (gate pubkey failed "
                                f"there); ask the user to run ~/.config/gateway/gate status on "
                                f"{name}, then try again")
    except TransferError as e:
        _err(str(e))
        return 2

    def job() -> tuple[str, str]:
        try:
            f2, _e2, d2 = _load()
            groups = _pick_groups(f2, d2, f"Copy the gateway to {name} over ssh (encrypted to "
                                          f"{name}'s own gateway key). " + copy_warning(name)
                                  + " Tick what to send:")
            oc, typed = popup.text(name, copy_confirm_prompt(name, recipient), what="copy confirmation")
            if oc != popup.Outcome.OK:
                raise _Stop(oc, popup.message(oc, name, "copy"))
            if (typed or "").strip() != name:
                raise _Stop(popup.Outcome.CANCELLED, f"gateway: the typed name didn't match {name}; "
                                                     "nothing was copied")
            content = export_content(f2, d2, groups)
            blob = encrypt_to(recipient, json.dumps(content).encode())
            rc2, out2, err2 = remote(name, f"{REMOTE_GATE} import --from-peer -", input=blob, timeout=180)
            if rc2 == 75:
                return popup.Outcome.FAILED, (f"gateway: the gateway on {name} is still setting "
                                              f"up; nothing was copied; try again in a minute")
            if rc2 != 0:
                tail = formmod.strip_unsafe((err2 or out2).decode(errors="replace").strip())[-200:]
                return popup.Outcome.FAILED, f"gateway: {name} refused the copy ({tail or 'error'})"
            with vault.edit() as d:
                vault.add_event(d, "copy", f"to {name}: {sorted(groups)}")
            audit.log("copy", host=name, groups=sorted(groups))
            remote_line = formmod.strip_unsafe(out2.decode(errors="replace").strip())[-300:]
            return popup.Outcome.OK, f"gateway: copied to {name}. {name} says: {remote_line}"
        except _Stop as s:
            return s.outcome, s.msg
        except TransferError as e:
            return popup.Outcome.FAILED, str(e)
    try:
        oc, line = _ask(name, "copy", job, kind="copy",
                        notice=f"gateway: waiting for the user to confirm the copy to {name} in "
                               "the gateway dialog in Claude Code",
                        cmd=f"~/.config/gateway/gate copy-to {name}",
                        digest=popup._digest(["copy", name]))
    except popup.StillOpen:
        return popup.EX_TEMPFAIL
    if oc == popup.Outcome.OK:
        _out(line)
        return 0
    _err(line if isinstance(line, str) and line else popup.message(oc, name, "copy"))
    return 1


def pubkey() -> int:
    """`gate pubkey`: print this machine's age recipient (SPEC 16)."""
    try:
        r = vault.ensure_key()
    except vault.VaultError as e:
        _err(f"gateway: {e}")
        return 2
    _out(r)
    return 0
