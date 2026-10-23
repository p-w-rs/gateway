"""The broker: the vault key, its passphrase, and scoped vault data.

Key modes (vault.key_mode()):
  none       no vault key yet
  unwrapped  private/key.txt holds the age identity in plaintext (every vault
             before this phase): the daemon reads it when it needs it, and the
             other gateway processes keep decrypting locally, as before (a
             same-user process can read key.txt anyway, so brokering would add
             nothing). There is nothing to lock.
  wrapped    private/key.wrapped holds the identity encrypted to the user's
             passphrase with age's scrypt recipient (agepass, an established
             construction); private/key.recipient the public recipient. The
             unlocked identity exists only in this process's memory; every
             other gateway process gets vault data from here.

States reported by /health: none | unwrapped | locked | unlocked.

set_passphrase (wrap): key.txt -> key.wrapped, verified by unwrapping the
written file (and checking the recipient) before key.txt is removed; a
failure leaves key.txt as it was. Lock: explicitly (/ui/vault/lock,
/agent/vault/lock, `gate lock`), after lock_after of no vault use (the
form's [vault] lock_after, default 8h), and when the daemon exits.
In this phase the passphrase reaches the daemon only through the test
routes (/test/vault/passphrase, /test/vault/unlock, enabled by a test
override); the native dialog that asks the user comes with PLAN-v4 phase 3.

Scoped data: each entry point mode gets the secret classes it needs; the
others are replaced by sentinels (`gw-redacted:<hmac>`, keyed by a random
per-daemon key, so a sentinel says nothing about the value). A peer that
isn't a direct caller (ancestry.walk_direct up to its session) also gets
sentinels for every entry without an effective `scripts = true`. Writes come
back as whole documents: sentinels are swapped back for the values they
stand for, and a write that would add, change, move or drop a value the
writer couldn't see is refused (Conflict).
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import os
import re
import secrets
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable, Iterator

from .. import agepass, paths, testing, vault

DEFAULT_LOCK_AFTER = 8 * 3600
SENTINEL_PREFIX = "gw-redacted:"
_SENTINEL_RE = re.compile(r"gw-redacted:[0-9a-f]{32}")
MIN_PASSPHRASE = 12                                  # characters
MAX_PASSPHRASE_BYTES = agepass.MAX_PASSPHRASE_BYTES  # UTF-8 bytes: age reads it from a tty line
IDENTITY_RE = re.compile(r"AGE-SECRET-KEY-1[0-9A-Z]{58}")
RECIPIENT_RE = re.compile(r"age1[0-9a-z]{58}")

SECRET_CLASSES = ("sudo_local", "ssh_hosts", "sudo_hosts", "tokens", "account_keys", "signins")
ALL = frozenset(SECRET_CLASSES + ("cache",))
NONE: frozenset[str] = frozenset()
_CLI = frozenset({"tokens", "signins", "account_keys", "cache"})
SCOPES: dict[str, frozenset[str]] = {
    "shim sudo": frozenset({"sudo_local"}),
    "shim ssh": frozenset({"ssh_hosts", "sudo_hosts", "account_keys"}),
    "shim scp": frozenset({"ssh_hosts", "sudo_hosts", "account_keys"}),
    "shim sftp": frozenset({"ssh_hosts", "sudo_hosts", "account_keys"}),
    "git-credential": frozenset({"tokens", "signins", "cache"}),
    "mcp": frozenset({"tokens", "signins", "cache"}),
    "gate": ALL,
    "shim gate": ALL,
    "hook-files": NONE,
    "hook-daemon": NONE,
    "askpass": NONE,
    "gated": NONE,
}
for _t in ("gh", "hf", "databricks", "crane", "pijul", "az", "asiml", "dvc"):
    SCOPES[f"shim {_t}"] = _CLI


def scope_for(mode: str) -> frozenset[str]:
    """The secret classes an entry point mode may see. Hooks see every value
    (PostToolUse and the prompt hook mask them in Claude's output)."""
    if mode in SCOPES:
        return SCOPES[mode]
    if mode.startswith("hook-"):
        return ALL
    return NONE


def direct_tool(mode: str) -> str | None:
    """The tool name ancestry's direct rule judges a mode as (None: no rule:
    hooks, the MCP server and gate run as Claude Code's own children)."""
    if mode.startswith("shim ") and mode != "shim gate":
        return mode[5:]
    if mode == "git-credential":
        return "git-credential"
    return None


class Locked(vault.VaultLocked):
    pass


class Conflict(Exception):
    """A write would change values its writer couldn't see."""


class BrokerError(Exception):
    pass


# ---------------------------------------------------------------------------
# Secret slots, views and merges (pure functions)
# ---------------------------------------------------------------------------

Slot = tuple[str, tuple[str, str], dict, str]     # class, (section, entry), container, field


def slots(data: dict[str, Any]) -> Iterator[Slot]:
    """Every secret value in a vault document: (class, (section, entry),
    the dict holding it, its key)."""
    def ok(d: Any, k: str) -> bool:
        return isinstance(d, dict) and isinstance(d.get(k), str) and bool(d.get(k))
    for user, e in ((data.get("localhost") or {}).get("sudo") or {}).items():
        if ok(e, "password"):
            yield "sudo_local", ("localhost", "localhost"), e, "password"
    for name, h in (data.get("hosts") or {}).items():
        if not isinstance(h, dict):
            continue
        for k in h.get("keys") or []:
            if ok(k, "private"):
                yield "ssh_hosts", ("hosts", name), k, "private"
        for _user, e in (h.get("sudo") or {}).items():
            if ok(e, "password"):
                yield "sudo_hosts", ("hosts", name), e, "password"
    for name, a in (data.get("accounts") or {}).items():
        if not isinstance(a, dict):
            continue
        if ok(a.get("token"), "value"):
            yield "tokens", ("accounts", name), a["token"], "value"
        if ok(a.get("ssh_key"), "private"):
            yield "account_keys", ("accounts", name), a["ssh_key"], "private"
        if ok(a.get("entra"), "refresh_token"):
            yield "signins", ("accounts", name), a["entra"], "refresh_token"
        if ok(a.get("entra"), "client_secret"):
            yield "signins", ("accounts", name), a["entra"], "client_secret"


def sentinel(key: bytes, value: str) -> str:
    return SENTINEL_PREFIX + hmac.new(key, value.encode("utf-8", "surrogatepass"),
                                      hashlib.sha256).hexdigest()[:32]


def is_sentinel(v: Any) -> bool:
    return isinstance(v, str) and bool(_SENTINEL_RE.fullmatch(v))


EntryOk = Callable[[str, str], bool]


def _visible(cls: str, entry: tuple[str, str], scope: frozenset[str], entry_ok: EntryOk) -> bool:
    return cls in scope and entry_ok(*entry)


def make_view(data: dict[str, Any], scope: frozenset[str], key: bytes,
              entry_ok: EntryOk = lambda s, n: True) -> dict[str, Any]:
    """A copy of `data` with every value the peer may not see replaced by its
    sentinel."""
    view = copy.deepcopy(data)
    for cls, entry, d, k in list(slots(view)):
        if not _visible(cls, entry, scope, entry_ok):
            d[k] = sentinel(key, d[k])
    return view


def _hidden(data: dict[str, Any], scope: frozenset[str], entry_ok: EntryOk) -> list[tuple]:
    return sorted((cls, entry, d[k]) for cls, entry, d, k in slots(data)
                  if not _visible(cls, entry, scope, entry_ok))


def merge(new: dict[str, Any], current: dict[str, Any], scope: frozenset[str], key: bytes,
          entry_ok: EntryOk = lambda s, n: True) -> dict[str, Any]:
    """The document to save for a writer that saw make_view(current, ...):
    its sentinels swapped back for their values. Conflict when the result
    adds, changes, moves or drops a value the writer couldn't see. The
    vault's baseline mark (vault.BASELINE_KEY) stays as `current` has it: a
    writer can neither drop it (that would give a new install an older one's
    defaults) nor add it to an older vault. (With no vault yet, `current` is
    empty(), which has it; a 0.6 conversion never writes through here: it
    puts its key.txt in place first.)"""
    by_sentinel = {sentinel(key, d[k]): d[k] for _c, _e, d, k in slots(current)}
    out = copy.deepcopy(new)
    for _cls, _entry, d, k in list(slots(out)):
        v = d[k]
        if is_sentinel(v):
            if v not in by_sentinel:
                raise Conflict("gateway: the vault changed while this program held it; try again")
            d[k] = by_sentinel[v]
    if _hidden(out, scope, entry_ok) != _hidden(current, scope, entry_ok):
        raise Conflict("gateway: refused a vault change that would add, change or drop a "
                       "credential this program can't see")
    out.pop(vault.BASELINE_KEY, None)
    if vault.BASELINE_KEY in current:
        out[vault.BASELINE_KEY] = current[vault.BASELINE_KEY]
    return out


def cache_view(cache: dict[str, Any], scope: frozenset[str],
               account_ok: Callable[[str], bool]) -> dict[str, Any]:
    if "cache" not in scope:
        return {"tokens": {}}
    toks = cache.get("tokens") or {}
    return {"tokens": {k: v for k, v in toks.items() if account_ok(str(k).split("|", 1)[0])}}


def cache_merge(new: dict[str, Any], current: dict[str, Any], scope: frozenset[str],
                account_ok: Callable[[str], bool]) -> dict[str, Any] | None:
    """The cache to save (None: the writer may not write it). Entries the
    writer couldn't see are kept as they are."""
    if "cache" not in scope:
        return None
    cur = current.get("tokens") or {}
    kept = {k: v for k, v in cur.items() if not account_ok(str(k).split("|", 1)[0])}
    mine = {k: v for k, v in (new.get("tokens") or {}).items()
            if isinstance(v, dict) and account_ok(str(k).split("|", 1)[0])}
    return {"tokens": {**kept, **mine}}


# ---------------------------------------------------------------------------
# age with an identity held in memory
# ---------------------------------------------------------------------------


def _age(tool: str = "age") -> str:
    try:
        return paths.tool(tool)
    except paths.ToolMissing as e:
        raise BrokerError(str(e)) from None


def _with_identity(identity: str, argv_tail: Callable[[str], list[str]], *,
                   tool: str = "age", stdin: bytes | None = None, timeout: float = 30
                   ) -> subprocess.CompletedProcess[bytes]:
    """Run age (or age-keygen) with the identity on an inherited pipe
    (/dev/fd/N): it never touches a file or a command line."""
    r, w = os.pipe()
    try:
        os.write(w, identity.encode("ascii") + b"\n")
        os.close(w)
        w = -1
        return subprocess.run([_age(tool), *argv_tail(f"/dev/fd/{r}")], pass_fds=(r,),
                              input=stdin, capture_output=True, timeout=timeout,
                              stdin=None if stdin is not None else subprocess.DEVNULL)
    finally:
        os.close(r)
        if w != -1:
            os.close(w)


def decrypt_file(identity: str, path: Path) -> bytes:
    p = _with_identity(identity, lambda fd: ["-d", "-i", fd, str(path)])
    if p.returncode != 0:
        raise vault.VaultError(f"could not decrypt {path.name} with the vault key")
    return p.stdout


def decrypt_blob(identity: str, blob: bytes) -> bytes:
    p = _with_identity(identity, lambda fd: ["-d", "-i", fd], stdin=blob)
    if p.returncode != 0:
        raise vault.VaultError("that isn't encrypted to this machine's gateway key")
    return p.stdout


def recipient_of(identity: str) -> str:
    p = _with_identity(identity, lambda fd: ["-y", fd], tool="age-keygen")
    out = p.stdout.decode("ascii", "replace").strip()
    if p.returncode != 0 or not RECIPIENT_RE.fullmatch(out):
        raise BrokerError("gateway: the vault key can't be read")
    return out


def read_identity(text: str) -> str:
    """The AGE-SECRET-KEY-1... line of an age identity file."""
    for line in text.splitlines():
        line = line.strip()
        if IDENTITY_RE.fullmatch(line):
            return line
    raise BrokerError("gateway: the vault key file holds no age identity")


# Write whole (temp file, fsync, rename, fsync the folder), mode 0600: the
# vault's own durable write (vault.age and the cache use it too).
_write_private = vault.write_private
_fsync_dir = vault.fsync_dir


# ---------------------------------------------------------------------------
# The broker
# ---------------------------------------------------------------------------


class Broker:
    def __init__(self, emit: Callable[..., Any] = lambda *a, **k: None,
                 lock_after: float | None = None):
        self.mutex = threading.RLock()
        self._identity: str | None = None
        self.key = secrets.token_bytes(32)          # sentinels' HMAC key, this process only
        self.emit = emit
        self._lock_after_override = lock_after
        self.last_use = time.monotonic()
        self.unlocked_at: float | None = None
        # the decrypted vault, kept while vault.age stays the same file and the
        # key unlocked (read); forgotten on lock and on every write
        self._plain: tuple[tuple[int, int, int], dict[str, Any]] | None = None

    # -- state ---------------------------------------------------------------
    @staticmethod
    def mode() -> str:
        return vault.key_mode()

    def state(self) -> str:
        m = self.mode()
        if m == "wrapped":
            return "unlocked" if self._identity else "locked"
        return m

    def identity(self) -> str | None:
        """The identity the daemon's own vault reads use (vault._DAEMON_IDENTITY):
        None in unwrapped mode (vault.py reads key.txt itself); Locked when
        the wrapped key isn't unlocked."""
        if self.mode() != "wrapped":
            return None
        with self.mutex:
            if self._identity is None:
                raise Locked("gateway: the gateway vault is locked")
            return self._identity

    def touch(self) -> None:
        self.last_use = time.monotonic()

    def lock_after(self) -> float:
        if self._lock_after_override is not None:
            return float(self._lock_after_override)
        try:
            from .. import form as formmod
            f = formmod.load()
            return float(f.vault.lock_after)
        except Exception:  # noqa: BLE001 - the default when the form can't say
            return float(DEFAULT_LOCK_AFTER)

    def tick(self) -> None:
        """Lock after lock_after of no vault use."""
        with self.mutex:
            if self._identity is not None and time.monotonic() - self.last_use >= self.lock_after():
                self.lock("idle")

    def lock(self, reason: str) -> bool:
        """Forget the unlocked identity. False when there was nothing to lock."""
        with self.mutex:
            self._plain = None
            if self._identity is None:
                return False
            self._identity = None
            self.unlocked_at = None
        self.emit("vault.locked", reason=reason)
        return True

    # -- passphrase ----------------------------------------------------------
    @staticmethod
    def _check_passphrase(pw: Any) -> str:
        """A new passphrase: at least MIN_PASSPHRASE characters, at most
        MAX_PASSPHRASE_BYTES in UTF-8 (age reads it as one terminal line, and a
        line near the tty's limit, 1024 bytes on macOS, never ends: age would
        wait out its timeout), no control characters (the tty would act on
        them)."""
        size = _utf8_len(pw)
        if size is None or len(pw) < MIN_PASSPHRASE or size > MAX_PASSPHRASE_BYTES:
            raise BrokerError(f"gateway: the vault passphrase must be at least {MIN_PASSPHRASE} "
                              f"characters and at most {MAX_PASSPHRASE_BYTES} bytes (UTF-8)")
        if _has_control(pw):
            raise BrokerError("gateway: the vault passphrase can't hold control characters")
        return pw

    def set_passphrase(self, passphrase: Any) -> None:
        """Wrap the plaintext key with `passphrase`: write key.wrapped and
        key.recipient, unwrap the written file to check it, then remove
        key.txt. The daemon stays unlocked.

        age's scrypt runs (wrap, then the check's unwrap: seconds) without the
        broker's mutex or the vault's flock, so vault writers and the daemon's
        reads go on meanwhile; both are taken only to re-check that key.txt is
        still the key that was wrapped and to put the files in place."""
        pw = self._check_passphrase(passphrase)
        if self.mode() != "unwrapped":
            raise BrokerError("gateway: the vault key already has a passphrase (or there is "
                              "no vault key yet)")
        if paths.v2_store_path().exists() and not paths.vault_path().exists():
            raise BrokerError("gateway: the 0.6 vault hasn't been converted yet")
        try:
            key_text = paths.key_path().read_text(encoding="ascii", errors="replace")
        except OSError:
            raise BrokerError("gateway: the vault key already has a passphrase (or there is "
                              "no vault key yet)") from None
        ident = read_identity(key_text)
        rec = recipient_of(ident)
        try:
            blob = agepass.encrypt((ident + "\n").encode("ascii"), pw)
        except agepass.AgePassError as e:
            raise BrokerError(str(e)) from None
        corrupt = testing.get("gated_wrap_corrupt")        # tests: a bad write
        if corrupt:
            blob = blob[:-8] + bytes(b ^ 0xFF for b in blob[-8:])
        wrapped = paths.wrapped_key_path()
        tmp = wrapped.with_name(f".{wrapped.name}.{secrets.token_hex(6)}.new")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            try:
                os.write(fd, blob)
                os.fsync(fd)
            finally:
                os.close(fd)
            try:
                back = agepass.decrypt(tmp.read_bytes(), pw).decode("ascii", "replace")
                if read_identity(back) != ident or recipient_of(read_identity(back)) != rec:
                    raise BrokerError("gateway: the wrapped key didn't unwrap to the same key")
            except (agepass.AgePassError, BrokerError) as e:
                raise BrokerError("gateway: setting the vault passphrase failed its check "
                                  f"({type(e).__name__}); nothing changed") from None
            # the flock first, then the mutex: a vault writer holds the flock while
            # the daemon merges its write (which needs the mutex), so the mutex is
            # never held while waiting for the flock
            with vault.locked(), self.mutex:
                if self.mode() != "unwrapped":
                    raise BrokerError("gateway: the vault key already has a passphrase (or "
                                      "there is no vault key yet)")
                if paths.v2_store_path().exists() and not paths.vault_path().exists():
                    raise BrokerError("gateway: the 0.6 vault hasn't been converted yet")
                now = read_identity(paths.key_path().read_text(encoding="ascii", errors="replace"))
                if now != ident:
                    raise BrokerError("gateway: the vault key changed while its passphrase was "
                                      "being set; nothing changed (try again)")
                if paths.vault_path().exists():
                    decrypt_file(ident, paths.vault_path())   # the key really opens the vault
                _write_private(paths.recipient_path(), (rec + "\n").encode("ascii"))
                os.replace(tmp, wrapped)
                _fsync_dir(wrapped.parent)
                paths.key_path().unlink()
                _fsync_dir(wrapped.parent)
                self._identity = ident
                self.unlocked_at = time.time()
                self._plain = None
                self.touch()
        finally:
            tmp.unlink(missing_ok=True)
        self.emit("vault.wrapped")

    def unlock(self, passphrase: Any, how: str = "test") -> None:
        """Unwrap key.wrapped with `passphrase` (age's scrypt runs without the
        broker's mutex), check it against key.recipient and keep the identity
        in memory."""
        if not isinstance(passphrase, str) or not passphrase:
            raise BrokerError("gateway: no passphrase given")
        size = _utf8_len(passphrase)
        if size is None or size > MAX_PASSPHRASE_BYTES or _has_control(passphrase):
            # never a passphrase the wrap accepted (and age would hang on it)
            raise BrokerError("gateway: that passphrase doesn't unlock the vault (a vault "
                              f"passphrase is at most {MAX_PASSPHRASE_BYTES} bytes, without "
                              "control characters)")
        if self.mode() != "wrapped":
            raise BrokerError("gateway: the vault key has no passphrase; there is nothing to "
                              "unlock")
        try:
            raw = agepass.decrypt(paths.wrapped_key_path().read_bytes(), passphrase)
        except agepass.BadPassphrase:
            raise BrokerError("gateway: that passphrase doesn't unlock the vault") from None
        except (agepass.AgePassError, OSError) as e:
            raise BrokerError(f"gateway: the vault couldn't be unlocked ({type(e).__name__})") from None
        ident = read_identity(raw.decode("ascii", "replace"))
        want = self.recipient()
        if want and recipient_of(ident) != want:
            raise BrokerError("gateway: the wrapped key doesn't match key.recipient")
        with self.mutex:
            self._identity = ident
            self.unlocked_at = time.time()
            self.touch()
        self.emit("vault.unlocked", how=how)
        # the managed shell's next command renews its settings (hooks/gate-sh:
        # approved imports are in the vault, left out while it was locked)
        try:
            from .. import managed
            managed.unlocked_marker().touch()
        except Exception:  # noqa: BLE001
            pass

    @staticmethod
    def recipient() -> str | None:
        try:
            r = paths.recipient_path().read_text(encoding="ascii").strip()
        except OSError:
            return None
        return r if RECIPIENT_RE.fullmatch(r) else None

    # -- vault data ----------------------------------------------------------
    def _require(self) -> None:
        if self.mode() == "wrapped" and self._identity is None:
            raise Locked("gateway: the gateway vault is locked")

    def read(self, touch: bool = True) -> dict[str, Any]:
        """The whole vault (vault.load in this process uses the identity). The
        decrypted copy is kept while vault.age stays the same file, so the
        other processes, which ask on every read (client.vault_read), cost no
        decryption each; a lock forgets it. touch=False for gated's own looks
        (rights for snapshots, the ticker): they never count as a use, so
        `lock_after` still locks an idle vault (PLAN-v4 phase 7)."""
        with self.mutex:
            self._require()
            key = _vault_stat()
            if key is not None and self._plain is not None and self._plain[0] == key:
                data = copy.deepcopy(self._plain[1])
            else:
                data = vault.load()
                self._plain = (key, copy.deepcopy(data)) \
                    if key is not None and _vault_stat() == key else None
            if touch:
                self.touch()
        return data

    def write(self, data: dict[str, Any], migrating: bool = False) -> None:
        with self.mutex:
            self._require()
            self._plain = None
            try:
                vault.save(data, migrating=migrating)
            finally:
                self._plain = None
            self.touch()

    def read_cache(self) -> dict[str, Any]:
        self._require()
        c = vault.cache_load()
        self.touch()
        return c

    def write_cache(self, c: dict[str, Any]) -> None:
        self._require()
        vault.cache_save(c)
        self.touch()

    def open_own(self, blob: bytes) -> bytes:
        self._require()
        ident = self._identity if self.mode() == "wrapped" else read_identity(
            paths.key_path().read_text(encoding="ascii", errors="replace"))
        out = decrypt_blob(ident, blob)
        self.touch()
        return out


def _vault_stat() -> tuple[int, int, int] | None:
    try:
        st = os.stat(paths.vault_path())
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size, st.st_ino)


def _utf8_len(pw: Any) -> int | None:
    """len(pw.encode("utf-8")), or None for a non-string or one UTF-8 can't
    encode (a lone surrogate from JSON)."""
    if not isinstance(pw, str):
        return None
    try:
        return len(pw.encode("utf-8"))
    except UnicodeEncodeError:
        return None


def _has_control(pw: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 for c in pw)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(s: Any) -> bytes:
    if not isinstance(s, str):
        raise BrokerError("gateway: expected base64 data")
    try:
        return base64.b64decode(s, validate=True)
    except ValueError:
        raise BrokerError("gateway: expected base64 data") from None

