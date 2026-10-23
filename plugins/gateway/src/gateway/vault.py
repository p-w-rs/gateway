"""Vault v3: ~/.config/gateway/private/vault.age (SPEC 3).

age-encrypted JSON (same crypto and locking as v2): `age -e -r RECIPIENT`
and `age -d -i key.txt` through stdin/stdout only, a durable replace (temp
file, fsync, rename, fsync the folder: write_private; F_FULLFSYNC on
macOS), and a flock on private/.lock around every read-modify-write. `gate
rotate` keeps a copy of vault.age from just before it changes it (snapshot:
private/backups, the newest 5); `gate forget` keeps none, and names the
older copies that may still hold what it forgot (older_copies). age comes
from the
gateway's pixi env by absolute path (never PATH).

    {"version": 3,
     "machine": {"id", "name", "hostname"},
     "localhost": {"sudo": {USER: {"password", "updated", "stale"}}},
     "hosts": {NAME: {"keys": [{"private", "public", "fingerprint", "created", "retired"}],
                      "host_keys": ["ssh-ed25519 AAAA..."],
                      "sudo": {USER: {"password", "updated", "stale"}},
                      "probe": {"nopasswd": {USER: "<when>"}}}},
     "accounts": {NAME: {"kind", "token": {"value", "source", "updated", "stale"},
                         "ssh_key": {"private", "public", "fingerprint"},
                         "entra": {"refresh_token" | "client_secret", "client_id", "tenant_id",
                                   "refreshed", "kind"},     (client_secret: a service principal)
                         "host_keys": [...],
                         "bound": {"hosts": [...], "tenant", "client_id", "auth", "scope"}}},
     "approved": {"form_sha256", "at", "rights": {...}},      (consent.py)
     "form_last_good": "<text>",
     "aliases": {"github:work": "github-work"},
     "events": [{"n", "at", "what", "detail"}], "events_seen": N,
     "migrated": {"from", "store_sha256", "at", "report", "shown"},
     "baseline": 2}           (made by a gateway with "ask" as this computer's sudo default; below)

cache.age holds short-lived tokens (Entra access tokens, ACR refresh tokens)
keyed by account and scope, with their expiry; it is safe to delete.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import fcntl
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterator

from . import paths, testing

# hashlib, shutil, socket, tempfile and uuid are imported where they are used: the
# PostToolUse hook loads this module for every response once a vault exists
# (review round 5).

VERSION = 3
MAX_EVENTS = 100
EVENT_KINDS = ("widen", "narrow", "bind", "export", "copy", "import", "migrate", "reject",
               "hostkey", "forget")

# Built-in SSH host keys (type + base64). GitHub's are its published keys
# (fingerprints SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU ed25519,
# p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM ecdsa, uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s
# rsa); ssh.github.com:443 uses the same keys. hf.co's ed25519 key
# (SHA256:dVjzGIdV7d6cwKIeZiCoRMa2gMvSKfGZAvHf4gMiMao) and the Nest's
# (SHA256:iJjr1ZMOZNRGcEtLSDXFUUH0C4+5t7X9Wmhu4T4vcQI) were read 2026-10-17/18.
GITHUB_HOST_KEYS = [
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
]
HF_HOST_KEYS = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINJjhgtT9FOQrsVSarIoPVI1jFMh3VSHdKfdqp/O776s"]
NEST_HOST_KEYS = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA1a+L9qfvbf1boAGRZ2/HTjM5PaoEvDciJ/asgRgIR6"]
BUILTIN_HOST_KEYS: dict[tuple[str, int], list[str]] = {
    ("github.com", 22): GITHUB_HOST_KEYS,
    ("ssh.github.com", 443): GITHUB_HOST_KEYS,
    ("ssh.github.com", 22): GITHUB_HOST_KEYS,
    ("hf.co", 22): HF_HOST_KEYS,
    ("nest.pijul.com", 22): NEST_HOST_KEYS,
}


class VaultError(Exception):
    """The vault can't be read or written (message holds no secret)."""


class VaultLocked(VaultError):
    """The vault key has a passphrase (key mode "wrapped") and the gateway
    daemon holds it locked, or can't be reached. The message says what to do
    next (the daemon words it for the caller's session: interactive or not)."""


# PLAN-v4 phase 2: the vault key's modes (key_mode()). "unwrapped": the age
# identity in private/key.txt, read by each gateway process as before.
# "wrapped": private/key.wrapped (the identity encrypted to the user's
# passphrase) and private/key.recipient; only the gateway daemon holds the
# unlocked identity, and every other process gets (scoped) vault data from it
# over its socket (daemon/broker.py, daemon/client.py).
#
# In the daemon process, _DAEMON_IDENTITY is the broker's identity(): it
# answers the identity to decrypt with (None in unwrapped mode: key.txt is
# read as before) or raises VaultLocked.
_DAEMON_IDENTITY: Any = None


def key_mode() -> str:
    """'unwrapped' (key.txt), 'wrapped' (key.wrapped, no key.txt) or 'none'."""
    if paths.key_path().is_file():
        return "unwrapped"
    if paths.wrapped_key_path().is_file():
        return "wrapped"
    return "none"


def brokered() -> bool:
    """Does this process get vault data from the gateway daemon? Only for a
    wrapped key, and never in the daemon itself."""
    return _DAEMON_IDENTITY is None and key_mode() == "wrapped"


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


# The defaults a vault was made under (review round 3). A vault this gateway
# makes says `"baseline": 2`: this computer's sudo is "ask" where the form
# doesn't say. A vault without it was made by an older gateway (0.9.1 and
# before), whose default was sudo = true, and that install keeps it
# (older_install; consent's baseline and the form's localhost default). Every
# writer keeps the mark as it is: empty() has it, _fill never adds it to an
# older vault, save() writes what load() gave, the broker's merge keeps the
# vault's own (a writer can neither add nor drop it), export leaves it out
# (export_view: per machine), and a converted 0.6 vault has none (migrate).
BASELINE_KEY = "baseline"
BASELINE = 2


def empty() -> dict[str, Any]:
    """A new vault (a missing one loads as this): it carries the baseline mark."""
    return {"version": VERSION, "machine": {}, "localhost": {"sudo": {}}, "hosts": {},
            "accounts": {}, "approved": {}, "form_last_good": None, "aliases": {},
            "events": [], "events_seen": 0, "migrated": None, BASELINE_KEY: BASELINE}


def older_install(data: dict[str, Any] | None) -> bool:
    """Was this vault made by an older gateway: a vault document (version 3,
    as load() returns it) without the baseline mark? Never for no vault
    (None: a new install, or one that can't be read now), an empty() one, or
    anything that isn't a vault document: those get the stricter new defaults."""
    if not isinstance(data, dict) or data.get("version") != VERSION:
        return False
    mark = data.get(BASELINE_KEY)
    return not (isinstance(mark, int) and not isinstance(mark, bool) and mark >= BASELINE)


def _fill(data: dict[str, Any]) -> dict[str, Any]:
    for k, v in empty().items():
        if k != BASELINE_KEY:         # an older vault stays one (older_install)
            data.setdefault(k, v)
    data["localhost"].setdefault("sudo", {})
    return data


# ---------------------------------------------------------------------------
# age
# ---------------------------------------------------------------------------


def _age(tool: str = "age") -> str:
    try:
        return paths.tool(tool)
    except paths.ToolMissing as e:
        raise VaultError(str(e)) from None


def exists() -> bool:
    return paths.vault_path().is_file()


def ensure_key() -> str:
    """private/ (0700) and key.txt (0600, created if missing). Returns the
    key's recipient. A wrapped key is never replaced by a new key.txt."""
    paths.ensure_private()
    k = paths.key_path()
    if not k.exists() and paths.wrapped_key_path().is_file():
        return recipient()
    if not k.exists():
        old = os.umask(0o077)
        try:
            subprocess.run([_age("age-keygen"), "-o", str(k)], check=True,
                           capture_output=True, timeout=15, stdin=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            raise VaultError("age-keygen could not create the vault key") from None
        finally:
            os.umask(old)
    with contextlib.suppress(OSError):
        os.chmod(k, 0o600)
    return recipient()


def recipient() -> str:
    if not paths.key_path().is_file() and paths.wrapped_key_path().is_file():
        try:
            r = paths.recipient_path().read_text(encoding="ascii").strip()
        except OSError:
            r = ""
        if not re.fullmatch(r"age1[0-9a-z]{58}", r):
            raise VaultError("the vault key's recipient (private/key.recipient) is missing")
        return r
    out = subprocess.run([_age("age-keygen"), "-y", str(paths.key_path())],
                         capture_output=True, text=True, timeout=15, stdin=subprocess.DEVNULL)
    if out.returncode != 0 or not out.stdout.startswith("age1"):
        raise VaultError("the vault key can't be read")
    return out.stdout.strip()


def _decrypt(path: Path) -> bytes:
    if _DAEMON_IDENTITY is not None:
        ident = _DAEMON_IDENTITY()          # the daemon: its unlocked identity (or VaultLocked)
        if ident is not None:
            from .daemon import broker
            return broker.decrypt_file(ident, path)
    if not paths.key_path().is_file():
        if paths.wrapped_key_path().is_file():
            raise VaultLocked("gateway: the gateway vault is locked")
        raise VaultError("the vault key (private/key.txt) is missing")
    out = subprocess.run([_age(), "-d", "-i", str(paths.key_path()), str(path)],
                         stdin=subprocess.DEVNULL, capture_output=True, timeout=30)
    if out.returncode != 0:
        raise VaultError(f"could not decrypt {path.name} with the vault key")
    return out.stdout


_DARWIN = sys.platform == "darwin"


def full_fsync(fd: int) -> None:
    """Flush a file (or folder) to the disk itself. On macOS fsync only hands
    the data to the drive, whose cache a power loss can lose (APFS too):
    F_FULLFSYNC asks the drive to flush it; where that fails (a file system
    that doesn't take it), fsync (review round 2)."""
    if _DARWIN:
        try:
            fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
            return
        except (OSError, AttributeError):
            pass
    os.fsync(fd)


def write_private(path: Path, data: bytes) -> None:
    """Write whole and durably, mode 0600: a temp file beside it, fsync
    (full_fsync: F_FULLFSYNC on macOS), rename, then fsync the folder, so a
    crash or power loss leaves the old file or the new one, never an empty
    or truncated one (GW-DUR-1; the broker's key.recipient uses it too)."""
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        try:
            os.fchmod(fd, 0o600)
            view = memoryview(data)
            while view:
                view = view[os.write(fd, view):]
            full_fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    fsync_dir(path.parent)


def fsync_dir(d: Path) -> None:
    """fsync a folder (full_fsync), so a rename into it is on disk (best
    effort)."""
    try:
        fd = os.open(d, os.O_RDONLY)
    except OSError:
        return
    try:
        full_fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _encrypt_to(path: Path, plaintext: bytes) -> None:
    """age's ciphertext on its stdout, written durably (write_private)."""
    rec = ensure_key()
    r = subprocess.run([_age(), "-e", "-r", rec], input=plaintext, capture_output=True, timeout=30)
    if r.returncode != 0 or not r.stdout:
        raise VaultError(f"age could not encrypt {path.name}")
    try:
        write_private(path, r.stdout)
    except OSError as e:
        raise VaultError(f"{path.name} couldn't be written ({type(e).__name__})") from None


# ---------------------------------------------------------------------------
# A copy before `gate rotate` changes the vault; older copies `gate forget`
# can't reach (the lead's decision, review round 2: forget keeps none)
# ---------------------------------------------------------------------------

SNAPSHOT_KEEP = 5


def _snapshot_re(kind: str) -> re.Pattern[str]:
    return re.compile(rf"^{re.escape(kind)}-\d{{8}}-\d{{6}}-[0-9a-f]{{6}}\.vault\.age$")


def snapshot(kind: str = "rotate") -> Path | None:
    """A copy of vault.age as it is now (still encrypted, its key unchanged)
    in private/backups/<kind>-<time>-<hex>.vault.age (0600, the folder 0700),
    written durably; only the newest SNAPSHOT_KEEP copies of that kind stay
    (import backups and the 0.6 conversion's aren't touched). None when there
    is no vault yet. `gate rotate` takes one just before it first changes the
    vault (ssh.rotate's before_change, under the vault's lock), so the person
    can put it back by hand (SPEC 15: copy it over vault.age with gated
    stopped). `gate forget` takes none: forgetting means gone (GW-DUR-1)."""
    import secrets
    src = paths.vault_path()
    try:
        data = src.read_bytes()
    except FileNotFoundError:
        return None
    d = paths.backups_dir()
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(d, 0o700)
    p = d / f"{kind}-{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}.vault.age"
    write_private(p, data)
    pat = _snapshot_re(kind)
    snaps = sorted((f for f in d.iterdir() if pat.match(f.name) and f.is_file()),
                   key=lambda f: (f.stat().st_mtime, f.name))
    for old in snaps[:-SNAPSHOT_KEEP]:
        with contextlib.suppress(OSError):
            old.unlink()
    return p


# What in private/backups holds an older copy of the vault (or of the 0.6
# store), so a forgotten secret may survive there: rotate's copies (and any
# other *.vault.age), an import's backup folders (their vault.age), the 0.6
# conversion's store-v2-*.age. Globs for the person's own `rm -r`, by kind.
OLDER_COPY_GLOBS = (("*.vault.age", lambda f: f.is_file() and f.name.endswith(".vault.age")),
                    ("import-*", lambda f: f.is_dir() and f.name.startswith("import-")
                     and (f / "vault.age").exists()),
                    ("store-v2-*.age", lambda f: f.is_file() and f.name.startswith("store-v2-")
                     and f.name.endswith(".age")))


def older_copies() -> list[tuple[str, list[str]]]:
    """[(glob, [names])] of the backups that hold an older vault (or 0.6
    store), by kind, only kinds present; [] when there are none. Names only
    (listing a folder, reading nothing)."""
    d = paths.backups_dir()
    try:
        items = sorted(d.iterdir(), key=lambda f: f.name)
    except OSError:
        return []
    out = []
    for glob, test in OLDER_COPY_GLOBS:
        names = [f.name for f in items if not f.is_symlink() and test(f)]
        if names:
            out.append((glob, names))
    return out


# ---------------------------------------------------------------------------
# load / save / lock
# ---------------------------------------------------------------------------


def load() -> dict[str, Any]:
    """Decrypt the vault into memory. A missing vault is an empty one. With a
    wrapped key (brokered()): the daemon's view for this program (secrets it
    may not see are sentinels), asked of the daemon on every call."""
    p = paths.vault_path()
    if not p.exists():
        return empty()
    if brokered():
        from .daemon import client
        return _fill(client.vault_read())
    try:
        data = json.loads(_decrypt(p).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise VaultError("the vault isn't valid JSON") from None
    if not isinstance(data, dict) or data.get("version") != VERSION:
        raise VaultError(f"unexpected vault version {data.get('version') if isinstance(data, dict) else '?'}")
    return _fill(data)


def save(data: dict[str, Any], *, migrating: bool = False) -> None:
    """Encrypt and atomically replace the vault. While a v2 store.age waits
    for migration, a new vault.age is never created (except by migration), so
    a failed migration retries next time instead of being skipped."""
    p = paths.vault_path()
    if not migrating and not p.exists() and paths.v2_store_path().exists():
        raise VaultError("the 0.6 vault hasn't been migrated yet (run gate migrate)")
    data["version"] = VERSION
    data["events"] = list(data.get("events") or [])[-MAX_EVENTS:]
    if brokered():
        from .daemon import client
        client.vault_write(data, migrating=migrating)
        return
    _encrypt_to(p, json.dumps(data, sort_keys=True).encode("utf-8"))


@contextlib.contextmanager
def locked() -> Iterator[None]:
    """Serialize read-modify-write cycles across processes (private/.lock)."""
    paths.ensure_private()
    with open(paths.lock_path(), "a+") as f:
        with contextlib.suppress(OSError):
            os.chmod(paths.lock_path(), 0o600)
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


@contextlib.contextmanager
def edit() -> Iterator[dict[str, Any]]:
    """with vault.edit() as data: ... -- locked load, saved if changed."""
    with locked():
        data = load()
        before = json.dumps(data, sort_keys=True)
        yield data
        if json.dumps(data, sort_keys=True) != before:
            save(data)


# ---------------------------------------------------------------------------
# cache.age (short-lived tokens)
# ---------------------------------------------------------------------------


def cache_load() -> dict[str, Any]:
    p = paths.cache_path()
    if not p.exists():
        return {"tokens": {}}
    if brokered():
        from .daemon import client
        try:
            c = client.cache_read()
        except VaultError:
            return {"tokens": {}}
        return c if isinstance(c.get("tokens"), dict) else {"tokens": {}}
    try:
        c = json.loads(_decrypt(p).decode("utf-8"))
        if isinstance(c, dict) and isinstance(c.get("tokens"), dict):
            return c
    except (VaultError, UnicodeDecodeError, ValueError):
        pass
    return {"tokens": {}}  # unreadable cache: start over (it is safe to lose)


def cache_save(c: dict[str, Any]) -> None:
    t = time.time()
    c["tokens"] = {k: v for k, v in c.get("tokens", {}).items()
                   if isinstance(v, dict) and float(v.get("expires", 0)) > t}
    if brokered():
        from .daemon import client
        client.cache_write(c)
        return
    _encrypt_to(paths.cache_path(), json.dumps(c, sort_keys=True).encode("utf-8"))


def _ckey(account: str, scope: str) -> str:
    return f"{account}|{scope}"


def cache_get(account: str, scope: str, margin: float = 120.0) -> str | None:
    """A cached token valid for at least `margin` more seconds, or None."""
    e = cache_load()["tokens"].get(_ckey(account, scope))
    if e and float(e.get("expires", 0)) - margin > time.time():
        return e.get("value")
    return None


def cache_put(account: str, scope: str, value: str, expires_at: float) -> None:
    """Store a minted token (call under locked())."""
    c = cache_load()
    c["tokens"][_ckey(account, scope)] = {"value": value, "expires": float(expires_at)}
    cache_save(c)


def cache_clear(account: str | None = None) -> None:
    if account is None:
        with contextlib.suppress(FileNotFoundError):
            paths.cache_path().unlink()
        return
    c = cache_load()
    c["tokens"] = {k: v for k, v in c["tokens"].items() if not k.startswith(account + "|")}
    cache_save(c)


def cache_values() -> list[str]:
    return [v["value"] for v in cache_load()["tokens"].values() if v.get("value")]


# ---------------------------------------------------------------------------
# Events (last 100 security events; SessionStart shows the new ones)
# ---------------------------------------------------------------------------


def add_event(data: dict[str, Any], what: str, detail: str) -> dict[str, Any]:
    evs = data.setdefault("events", [])
    n = max([e.get("n", 0) for e in evs] + [data.get("events_seen", 0)]) + 1
    e = {"n": n, "at": now(), "what": what, "detail": str(detail)[:500]}
    evs.append(e)
    del evs[:-MAX_EVENTS]
    return e


def new_events(data: dict[str, Any]) -> list[dict[str, Any]]:
    seen = data.get("events_seen", 0) or 0
    return [e for e in data.get("events", []) if e.get("n", 0) > seen]


def mark_events_seen(data: dict[str, Any]) -> None:
    ns = [e.get("n", 0) for e in data.get("events", [])]
    if ns:
        data["events_seen"] = max(ns + [data.get("events_seen", 0) or 0])


# ---------------------------------------------------------------------------
# Machine identity
# ---------------------------------------------------------------------------


def machine_id() -> str | None:
    """IOPlatformUUID (macOS), /etc/machine-id (Linux), else None."""
    o = testing.get("machine_id")
    if o is not None:
        return o
    if os.path.exists("/usr/sbin/ioreg"):
        try:
            out = subprocess.run(["/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice"],
                                 capture_output=True, text=True, timeout=5,
                                 stdin=subprocess.DEVNULL)
            m = re.search(r'"IOPlatformUUID"\s*=\s*"([0-9A-Fa-f-]{36})"', out.stdout)
            if m:
                return m.group(1).upper()
        except (OSError, subprocess.TimeoutExpired):
            pass
    for f in ("/etc/machine-id", "/var/lib/dbus/machine-id"):
        try:
            v = Path(f).read_text().strip()
            if re.fullmatch(r"[0-9a-f]{32}", v):
                return v
        except OSError:
            continue
    return None


def short_hostname() -> str:
    import socket
    h = socket.gethostname().split(".")[0].lower()
    h = re.sub(r"[^a-z0-9-]", "-", h).strip("-")
    if not h or not h[0].isalpha():
        h = "m-" + h if h else "machine"
    return h[:32]


def ensure_machine(data: dict[str, Any]) -> bool:
    """Fill data['machine'] (id, name, hostname). True if it changed. A
    machine without a stable id keeps a random one stored in the vault."""
    import socket
    import uuid
    m = data.setdefault("machine", {})
    before = dict(m)
    mid = machine_id()
    if mid:
        m["id"] = mid
    elif not str(m.get("id", "")).startswith("random:"):
        m["id"] = "random:" + str(uuid.uuid4())
    m.setdefault("name", short_hostname())
    m["hostname"] = socket.gethostname()
    return m != before


# ---------------------------------------------------------------------------
# Records and lookups (never hand values to anything that prints)
# ---------------------------------------------------------------------------


def resolve(data: dict[str, Any], name: str, entries: Any = ()) -> str:
    """Follow aliases (github:work -> github-work, OPENAI_API_KEY -> ...). A
    name in `entries` (the form's entry names) is never redirected."""
    if name in entries:
        return name
    return (data.get("aliases") or {}).get(name, name)


def host_record(data: dict[str, Any], name: str) -> dict[str, Any]:
    h = data.setdefault("hosts", {}).setdefault(name, {})
    h.setdefault("keys", [])
    h.setdefault("host_keys", [])
    h.setdefault("sudo", {})
    h.setdefault("probe", {"nopasswd": {}})
    return h


def account_record(data: dict[str, Any], name: str, kind: str | None = None) -> dict[str, Any]:
    a = data.setdefault("accounts", {}).setdefault(name, {})
    if kind:
        a.setdefault("kind", kind)
    a.setdefault("bound", {"hosts": []})
    a["bound"].setdefault("hosts", [])
    return a


def sudo_entry(data: dict[str, Any], host: str, user: str) -> dict[str, Any] | None:
    if host == "localhost":
        return (data.get("localhost") or {}).get("sudo", {}).get(user)
    return ((data.get("hosts") or {}).get(host) or {}).get("sudo", {}).get(user)


def set_sudo(data: dict[str, Any], host: str, user: str, password: str) -> None:
    rec = {"password": password, "updated": now(), "stale": False}
    if host == "localhost":
        data.setdefault("localhost", {}).setdefault("sudo", {})[user] = rec
    else:
        host_record(data, host)["sudo"][user] = rec


def forget_sudo(data: dict[str, Any], host: str, user: str) -> bool:
    """Drop one stored sudo password (passwordless sudo replaced it)."""
    m = (data.get("localhost") or {}).get("sudo", {}) if host == "localhost" else \
        ((data.get("hosts") or {}).get(host) or {}).get("sudo", {})
    return m.pop(user, None) is not None


# The user's answer to gate check's "store the sudo password, or set up
# passwordless sudo?" per (host, user): "password" or "nopasswd". Per machine
# (an install on this machine's hosts), so export leaves it out.
def sudo_choice(data: dict[str, Any], host: str, user: str) -> str | None:
    c = ((data.get("sudo_choice") or {}).get(host) or {}).get(user)
    # "ask" (PLAN-v4 phase 7): leave the password to the per-call dialog;
    # "nopasswd" is only kept from earlier versions (the gateway installed a rule then)
    return c if c in ("password", "nopasswd", "ask") else None


def set_sudo_choice(data: dict[str, Any], host: str, user: str, choice: str | None) -> None:
    m = data.setdefault("sudo_choice", {}).setdefault(host, {})
    if choice is None:
        m.pop(user, None)
    else:
        m[user] = choice
    if not m:
        data["sudo_choice"].pop(host, None)


def mark_stale(data: dict[str, Any], entry: str, what: str, user: str | None = None) -> bool:
    """Mark a rejected credential stale (never retried). what: sudo|token."""
    if what == "sudo" and user:
        e = sudo_entry(data, entry, user)
        if e is not None:
            e["stale"] = True
            return True
    if what == "token":
        t = ((data.get("accounts") or {}).get(entry) or {}).get("token")
        if t:
            t["stale"] = True
            return True
    return False


def key_record(private: str, public: str | None = None, created: str | None = None) -> dict[str, Any]:
    pub = public or public_key_of(private)
    return {"private": normalize_key(private), "public": pub.strip(),
            "fingerprint": fingerprint_of(pub), "created": created or now(), "retired": None}


def live_keys(host: dict[str, Any]) -> list[dict[str, Any]]:
    return [k for k in host.get("keys", []) if not k.get("retired")]


def meta(data: dict[str, Any]) -> dict[str, Any]:
    """What is stored, without any value (for status, stubs, git config)."""
    out: dict[str, Any] = {"localhost": {"sudo": {}}, "hosts": {}, "accounts": {}}
    for u, e in (data.get("localhost") or {}).get("sudo", {}).items():
        out["localhost"]["sudo"][u] = {"stale": bool(e.get("stale")), "updated": e.get("updated")}
    for n, h in (data.get("hosts") or {}).items():
        out["hosts"][n] = {
            "keys": [k.get("fingerprint", "") for k in live_keys(h)],
            "host_keys": host_key_fingerprints(h.get("host_keys", [])),
            "sudo": {u: {"stale": bool(e.get("stale")), "updated": e.get("updated")}
                     for u, e in (h.get("sudo") or {}).items()},
            "installed": h.get("installed"),
        }
    for n, a in (data.get("accounts") or {}).items():
        tok = a.get("token") or {}
        out["accounts"][n] = {
            "kind": a.get("kind"),
            "token": bool(tok.get("value")), "token_source": tok.get("source"),
            "stale": bool(tok.get("stale")),
            "ssh_key": bool((a.get("ssh_key") or {}).get("private")),
            "ssh_fingerprint": (a.get("ssh_key") or {}).get("fingerprint"),
            "entra": bool((a.get("entra") or {}).get("refresh_token")
                          or (a.get("entra") or {}).get("client_secret")),
            "bound": list((a.get("bound") or {}).get("hosts") or []),
        }
    return out


def all_values(data: dict[str, Any]) -> list[str]:
    """Every secret value in the vault (for scrubbing)."""
    vals: list[str] = []
    for e in (data.get("localhost") or {}).get("sudo", {}).values():
        vals.append(e.get("password") or "")
    for h in (data.get("hosts") or {}).values():
        vals += [k.get("private") or "" for k in h.get("keys", [])]
        vals += [e.get("password") or "" for e in (h.get("sudo") or {}).values()]
    for a in (data.get("accounts") or {}).values():
        vals.append((a.get("token") or {}).get("value") or "")
        vals.append((a.get("ssh_key") or {}).get("private") or "")
        vals.append((a.get("entra") or {}).get("refresh_token") or "")
        vals.append((a.get("entra") or {}).get("client_secret") or "")
    return [v for v in dict.fromkeys(vals) if v and not is_redacted(v)]


def is_redacted(v: Any) -> bool:
    """A sentinel the gateway daemon put where a value this program may not
    see was (daemon/broker.py); never a credential."""
    return isinstance(v, str) and v.startswith("gw-redacted:") and len(v) == 44


def labeled_secrets(data: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    """(section, entry, what, value) for every secret value in the vault:
    section is "localhost", "hosts" or "accounts"; what is "sudo password",
    "ssh key", "token" or "sign-in". For a warning that names what to replace
    and how (never the value itself)."""
    out: list[tuple[str, str, str, str]] = []
    for e in (data.get("localhost") or {}).get("sudo", {}).values():
        out.append(("localhost", "localhost", "sudo password", e.get("password") or ""))
    for name, h in (data.get("hosts") or {}).items():
        out += [("hosts", name, "ssh key", k.get("private") or "") for k in h.get("keys", [])]
        out += [("hosts", name, "sudo password", e.get("password") or "")
                for e in (h.get("sudo") or {}).values()]
    for name, a in (data.get("accounts") or {}).items():
        out.append(("accounts", name, "token", (a.get("token") or {}).get("value") or ""))
        out.append(("accounts", name, "ssh key", (a.get("ssh_key") or {}).get("private") or ""))
        out.append(("accounts", name, "sign-in", (a.get("entra") or {}).get("refresh_token") or ""))
        out.append(("accounts", name, "client secret",
                    (a.get("entra") or {}).get("client_secret") or ""))
    return [t for t in out if t[3] and not is_redacted(t[3])]


def labeled_values(data: dict[str, Any]) -> list[tuple[str, str, str]]:
    """(entry, what, value) for every secret value in the vault (labeled_secrets
    without the section)."""
    return [(e, w, v) for _s, e, w, v in labeled_secrets(data)]


def export_view(data: dict[str, Any]) -> dict[str, Any]:
    """The vault minus cache-like and per-machine consent state (SPEC 16; the
    baseline mark is this machine's: the importing vault keeps its own)."""
    d = copy.deepcopy(data)
    for k in ("approved", "imported", "form_last_good", "events", "events_seen", "sudo_choice",
              BASELINE_KEY):
        d.pop(k, None)
    return d


# ---------------------------------------------------------------------------
# SSH keys (carried over from v2)
# ---------------------------------------------------------------------------


def normalize_key(private_key: str) -> str:
    """LF line endings, no stray spaces, one trailing newline."""
    return "\n".join(line.strip() for line in private_key.strip().splitlines()) + "\n"


def _ssh_string(buf: bytes, pos: int) -> tuple[bytes, int]:
    n = int.from_bytes(buf[pos:pos + 4], "big")
    if pos + 4 + n > len(buf):
        raise ValueError("truncated")
    return buf[pos + 4:pos + 4 + n], pos + 4 + n


def public_key_of(private_key: str) -> str:
    """The OpenSSH public key line of an unencrypted OpenSSH private key,
    parsed in Python (nothing written to disk). Passphrase keys are refused."""
    text = private_key.strip()
    head, tail = "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----"
    if not (text.startswith(head) and text.endswith(tail)):
        raise ValueError("that is not an OpenSSH private key (convert older PEM keys with "
                         "ssh-keygen -p -f KEYFILE)")
    try:
        raw = base64.b64decode("".join(text[len(head):-len(tail)].split()), validate=True)
        if not raw.startswith(b"openssh-key-v1\0"):
            raise ValueError("bad magic")
        pos = len(b"openssh-key-v1\0")
        cipher, pos = _ssh_string(raw, pos)
        _kdf, pos = _ssh_string(raw, pos)
        _kdfopts, pos = _ssh_string(raw, pos)
        nkeys = int.from_bytes(raw[pos:pos + 4], "big")
        pos += 4
        blob, pos = _ssh_string(raw, pos)
        priv, pos = _ssh_string(raw, pos)
        keytype, _ = _ssh_string(blob, 0)
    except (ValueError, IndexError) as e:
        raise ValueError("that is not an OpenSSH private key") from e
    if cipher != b"none":
        raise ValueError("that key has a passphrase; the gateway needs a key without one")
    if nkeys != 1 or priv[:4] != priv[4:8]:
        raise ValueError("that is not an OpenSSH private key")
    return f"{keytype.decode()} {base64.b64encode(blob).decode()}"


def fingerprint_of(public_key: str) -> str:
    """SHA256:... as ssh-keygen -l prints it ("" if unparsable)."""
    import hashlib
    parts = public_key.split()
    for i, p in enumerate(parts):  # accept "host type key" and "type key"
        if p.startswith(("ssh-", "ecdsa-", "sk-")) and i + 1 < len(parts):
            try:
                blob = base64.b64decode(parts[i + 1], validate=True)
            except ValueError:
                return ""
            return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
    return ""


def key_comment(name: str, data: dict[str, Any]) -> str:
    """The comment on a key the gateway makes for entry NAME:
    `gateway-NAME@MACHINE`, so an authorized_keys line says which entry and
    which machine's gateway it belongs to (README, Uninstall)."""
    m = (data.get("machine") or {}).get("name") or short_hostname()
    m = re.sub(r"[^a-z0-9-]", "-", str(m).lower())[:32] or "machine"
    return f"gateway-{name}@{m}"


def generate_ssh_key(comment: str) -> tuple[str, str]:
    """A new ed25519 key pair (private, public). ssh-keygen writes only files,
    so it writes into a 0700 temp dir inside private/, read and removed at once."""
    import shutil
    import tempfile
    paths.ensure_private()
    tmp = Path(tempfile.mkdtemp(prefix=".keygen-", dir=paths.private_dir()))
    try:
        os.chmod(tmp, 0o700)
        try:
            kg = paths.tool("ssh-keygen")
        except paths.ToolMissing as e:
            raise VaultError(str(e)) from None
        subprocess.run([kg, "-q", "-t", "ed25519", "-N", "", "-C", comment, "-f",
                        str(tmp / "k")], check=True, capture_output=True,
                       stdin=subprocess.DEVNULL, timeout=15)
        return (tmp / "k").read_text().strip() + "\n", (tmp / "k.pub").read_text().strip()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def norm_host_key(line: str) -> str | None:
    """'host type key [comment]' or 'type key' -> 'type key' (None if not a key)."""
    parts = line.split()
    for i, p in enumerate(parts):
        if p.startswith(("ssh-", "ecdsa-", "sk-")) and i + 1 < len(parts):
            return f"{p} {parts[i + 1]}"
    return None


def host_key_fingerprints(keys: list[str] | str) -> list[str]:
    """['ssh-ed25519 SHA256:...'] for host keys (list or known_hosts text)."""
    if isinstance(keys, str):
        keys = keys.splitlines()
    out = []
    for k in keys:
        n = norm_host_key(k)
        if n:
            out.append(f"{n.split()[0]} {fingerprint_of(n)}")
    return out


def builtin_host_keys(host: str, port: int = 22) -> list[str]:
    return list(BUILTIN_HOST_KEYS.get((host.lower(), int(port)), []))


def keyscan(host: str, port: int = 22) -> list[str]:
    """The host's SSH keys ('type key'), built-in for github.com, hf.co and the
    Nest; else ssh-keyscan (from the pixi env). [] if unreachable. Used only by
    setup the user started (gate check); migration never scans."""
    built = builtin_host_keys(host, port)
    if built:
        return built
    fake = testing.get("keyscan")
    if fake is not None:
        if callable(fake):
            return list(fake(host, int(port)))
        return list(fake.get(f"{host}:{port}", fake.get(host, [])))
    try:
        tool = paths.tool("ssh-keyscan")
    except paths.ToolMissing:
        return []
    if host.startswith("-"):
        return []
    cmd = [tool, "-T", "5", "-t", "ed25519,ecdsa,rsa"]
    if int(port) != 22:
        cmd += ["-p", str(int(port))]
    try:
        out = subprocess.run(cmd + ["--", host], capture_output=True, text=True, timeout=20,
                             stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return []
    keys = [norm_host_key(l) for l in out.stdout.splitlines() if l.strip() and not l.startswith("#")]
    return list(dict.fromkeys(k for k in keys if k))
