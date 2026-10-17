"""The gateway's own encrypted vault: secrets and sudo passwords.

Separate from any personal secret store. Lives in $GATEWAY_HOME (default
${XDG_CONFIG_HOME:-~/.config}/gateway):

    key.txt     age identity, generated on first write (mode 600)
    store.age   the vault, age-encrypted JSON (mode 600)

The JSON looks like:
    {"version": 1,
     "secrets": {"HF_TOKEN": {"value": "...", "description": "...",
                              "hosts": ["huggingface.co"], "updated": "..."}},
     "sudo": {"alice@localhost": {"user": "alice", "host": "localhost",
                                   "password": "...", "updated": "..."}},
     "accounts": {"github:work": {"kind": "github", "host": "github.com",
                                  "login": "...", "owners": ["asirobots"],
                                  "hosts": ["github.com", "api.github.com"],
                                  "secrets": {"token": "...", "ssh_key": "..."},
                                  "public_key": "ssh-ed25519 ...", "prompts": {},
                                  "updated": "..."}},
     "account_prompts": {"read": "auto", "write": "auto", ...}}

An account is a named identity of a known kind (KINDS). Everything under its
"secrets" is a value; the rest is what Claude may see (catalog()). Version 1
vaults (no accounts) are read as-is and saved as version 2.

Values are only ever decrypted into memory. The `age` binary comes from the
plugin's pixi env, so this works the same on macOS, Linux and Windows.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Iterator

NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# ssh alias, hostname, IPv4 or IPv6 (no leading '-', so never an ssh option).
HOST_RE = re.compile(r"[A-Za-z0-9_\[][A-Za-z0-9._:%\[\]-]*")
USER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9._-]*")
LOCAL_ALIASES = {"localhost", "local", "127.0.0.1", "::1", "this"}


def home() -> Path:
    override = os.environ.get("GATEWAY_HOME")
    if override:
        return Path(override)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "gateway"


def key_path() -> Path:
    return home() / "key.txt"


def store_path() -> Path:
    return home() / "store.age"


def norm_host(host: str) -> str:
    h = host.strip().lower()
    return "localhost" if h in LOCAL_ALIASES else h


def _age(tool: str = "age") -> str:
    path = shutil.which(tool)
    if not path:
        raise RuntimeError(f"the {tool} binary was not found (it ships in the plugin's pixi env)")
    return path


VERSION = 2


def _empty() -> dict[str, Any]:
    # sudo_enabled: hosts enabled in every session (`/sudo enable HOST always`).
    # sudo_session: {host: [session ids]} enabled for those sessions only.
    # run_privileged runs without asking there; elsewhere it needs approval.
    # accounts / account_prompts: see the module docstring and KINDS.
    return {"version": VERSION, "secrets": {}, "sudo": {}, "sudo_enabled": [],
            "sudo_session": {}, "accounts": {}, "account_prompts": {}}


MAX_SESSIONS_PER_HOST = 20  # oldest session grants are dropped beyond this


def load() -> dict[str, Any]:
    """Decrypt the vault into memory. A missing vault is an empty one."""
    if not store_path().exists():
        return _empty()
    if not key_path().is_file():
        raise RuntimeError(f"vault key missing: {key_path()}")
    out = subprocess.run([_age(), "-d", "-i", str(key_path()), str(store_path())],
                         stdin=subprocess.DEVNULL, capture_output=True, timeout=15)
    if out.returncode != 0:
        raise RuntimeError("could not decrypt the vault with its key")
    data = json.loads(out.stdout.decode("utf-8"))
    for k, v in _empty().items():
        data.setdefault(k, v)
    return data


def _ensure_key() -> str:
    """Create the vault dir and key if needed; return the key's recipient."""
    d = home()
    d.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        os.chmod(d, 0o700)
    if not key_path().exists():
        old = os.umask(0o077)
        try:
            subprocess.run([_age("age-keygen"), "-o", str(key_path())],
                           check=True, capture_output=True, timeout=15)
        finally:
            os.umask(old)
    with contextlib.suppress(OSError):
        os.chmod(key_path(), 0o600)
    out = subprocess.run([_age("age-keygen"), "-y", str(key_path())],
                         check=True, capture_output=True, text=True, timeout=15)
    return out.stdout.strip()


def save(data: dict[str, Any]) -> None:
    """Encrypt and atomically replace the vault. Plaintext goes via stdin only."""
    recipient = _ensure_key()
    data["version"] = VERSION
    tmp = store_path().with_name(f"store.age.{os.getpid()}.tmp")
    old = os.umask(0o077)
    try:
        subprocess.run([_age(), "-e", "-r", recipient, "-o", str(tmp)],
                       input=json.dumps(data).encode("utf-8"),
                       check=True, capture_output=True, timeout=15)
        os.replace(tmp, store_path())
    finally:
        os.umask(old)
        with contextlib.suppress(FileNotFoundError):
            tmp.unlink()


@contextlib.contextmanager
def locked() -> Iterator[None]:
    """Serialize read-modify-write cycles across processes."""
    home().mkdir(parents=True, exist_ok=True)
    with open(home() / ".lock", "a+") as f:
        try:
            import fcntl
            fcntl.flock(f, fcntl.LOCK_EX)
        except ImportError:  # Windows
            import msvcrt
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        yield


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


# ---------------------------------------------------------------------------
# Lookups used by the gateway tools
# ---------------------------------------------------------------------------


def secret(name: str) -> dict[str, Any] | None:
    return load()["secrets"].get(name)


def sudo_entries(host: str) -> list[dict[str, Any]]:
    h = norm_host(host)
    return [e for e in load()["sudo"].values() if e.get("host") == h]


def allow_secret_host(name: str, host: str) -> list[str]:
    """Add a host to a secret's allowed list (the user approved it)."""
    with locked():
        data = load()
        s = data["secrets"].get(name)
        if s is None:
            raise RuntimeError(f"no secret named {name}")
        if host not in s.setdefault("hosts", []):
            s["hosts"].append(host)
            save(data)
        return list(s["hosts"])


def sudo_enabled(host: str, session_id: str | None = None,
                 data: dict[str, Any] | None = None) -> bool:
    """Enabled for every session, or for this session (if its id is known)."""
    data = data if data is not None else load()
    h = norm_host(host)
    return h in data["sudo_enabled"] or bool(
        session_id and session_id in data["sudo_session"].get(h, []))


def sudo_state(host: str, session_id: str | None = None,
               data: dict[str, Any] | None = None) -> str:
    data = data if data is not None else load()
    h = norm_host(host)
    if h in data["sudo_enabled"]:
        return "ENABLED in every session: runs without asking"
    if session_id and session_id in data["sudo_session"].get(h, []):
        return "ENABLED for this session: runs without asking"
    return "disabled: each root command asks"


def enable_for_session(data: dict[str, Any], host: str, session_id: str) -> None:
    ids = data["sudo_session"].setdefault(norm_host(host), [])
    if session_id not in ids:
        ids.append(session_id)
        del ids[:-MAX_SESSIONS_PER_HOST]


def clear_sudo(data: dict[str, Any], host: str) -> None:
    """Disable sudo on a host everywhere (all sessions and 'always')."""
    h = norm_host(host)
    if h in data["sudo_enabled"]:
        data["sudo_enabled"].remove(h)
    data["sudo_session"].pop(h, None)


# ---------------------------------------------------------------------------
# Accounts: named identities of a known kind
# ---------------------------------------------------------------------------

# kind:name, e.g. github:work. The name part is lower case so refs are stable.
ACCOUNT_RE = re.compile(r"([a-z]+):([a-z0-9][a-z0-9._-]{0,63})")
# A GitHub/HF owner or org, a Nest user, ... (no '/', never a leading '-').
OWNER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
LOGIN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]{0,99}")
EMAIL_RE = re.compile(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+")
GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")

PROMPT_CLASSES = ("read", "write", "delete", "exec")
PROMPT_VALUES = ("auto", "ask", "refuse")
DEFAULT_PROMPTS = {"read": "auto", "write": "auto", "delete": "ask", "exec": "ask"}

# The Azure CLI's public client: Microsoft's own SDKs default to it for
# interactive sign-in, and it is pre-authorized for ARM, Storage and Databricks.
AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"

# fields: the non-secret settings the form asks for (besides description).
# secrets: which credential kinds the account can hold.
# owners: whether the scope includes owners/orgs (beyond hosts).
KINDS: dict[str, dict[str, Any]] = {
    "github": {"label": "GitHub", "host": "github.com",
               "fields": ("host", "login", "name", "email"),
               "secrets": ("token", "ssh_key"), "owners": True},
    "hf": {"label": "Hugging Face", "host": "huggingface.co",
           "fields": ("login",), "secrets": ("token", "ssh_key"), "owners": True},
    "pijul": {"label": "Pijul (the Nest or a self-hosted server)", "host": "nest.pijul.com",
              "fields": ("host", "login", "name", "email", "remote_pijul"),
              "secrets": ("ssh_key",), "owners": True},
    "azure": {"label": "Azure (Microsoft Entra ID)", "host": "management.azure.com",
              "fields": ("tenant", "client_id", "login"), "secrets": (), "owners": False},
    "mlcat": {"label": "ASI ML Catalog", "host": "app-dev-ai-mlreg.azurewebsites.net",
              "fields": ("host", "login"), "secrets": (), "owners": False},
    "ssh": {"label": "SSH host", "host": "",
            "fields": ("host", "user", "port", "jump"), "secrets": ("ssh_key",), "owners": False},
    "registry": {"label": "Container registry", "host": "",
                 "fields": ("host", "login"), "secrets": ("token",), "owners": True},
}
SECRET_FIELDS = ("token", "ssh_key")


# The Nest's SSH host key (ed25519, SHA256:iJjr1ZMOZNRGcEtLSDXFUUH0C4+5t7X9Wmhu4T4vcQI),
# read 2026-10-17. Pijul can't ask whether to trust a new key without a
# terminal, so pijul and ssh accounts carry pinned keys.
NEST_KNOWN_HOSTS = ("nest.pijul.com ssh-ed25519 "
                    "AAAAC3NzaC1lZDI1NTE5AAAAIA1a+L9qfvbf1boAGRZ2/HTjM5PaoEvDciJ/asgRgIR6")
PINNED_KINDS = ("pijul", "ssh")


def keyscan(host: str, port: str = "") -> str:
    """The host's SSH keys as known_hosts lines (ssh-keyscan), or "".
    Used only from the user's /gate:account add/up (their trust decision);
    GATEWAY_KEYSCAN=none turns it off (tests)."""
    if host == "nest.pijul.com" and port in ("", "22"):
        return NEST_KNOWN_HOSTS
    if os.environ.get("GATEWAY_KEYSCAN") == "none" or not HOST_RE.fullmatch(host):
        return ""
    tool = Path(sys.executable).parent / "ssh-keyscan"
    cmd = [str(tool) if tool.exists() else (shutil.which("ssh-keyscan") or "ssh-keyscan"),
           "-T", "5", "-t", "ed25519,ecdsa,rsa"]
    if port and port != "22":
        cmd += ["-p", port]
    try:
        out = subprocess.run(cmd + ["--", host], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return "\n".join(l for l in out.stdout.splitlines() if l.strip() and not l.startswith("#"))


def host_key_fingerprints(known_hosts: str) -> list[str]:
    out = []
    for line in known_hosts.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            out.append(f"{parts[1]} {fingerprint_of(' '.join(parts[1:3]))}")
    return out


def default_hosts(kind: str, host: str) -> list[str]:
    """Where an account's credentials may go by default."""
    if kind == "github" and (host == "github.com" or host.endswith(".ghe.com")):
        return [host, f"api.{host}"]
    if kind == "hf":
        return [host, "hf.co"] if host == "huggingface.co" else [host]
    return [host] if host else []


def parse_account_ref(ref: str) -> tuple[str, str] | None:
    m = ACCOUNT_RE.fullmatch(ref or "")
    return (m.group(1), m.group(2)) if m and m.group(1) in KINDS else None


def account(ref: str, data: dict[str, Any] | None = None) -> dict[str, Any] | None:
    data = data if data is not None else load()
    return data["accounts"].get(ref)


def effective_prompts(acct: dict[str, Any], data: dict[str, Any]) -> dict[str, str]:
    """Per-class prompt policy: the account's own, then the vault default,
    then DEFAULT_PROMPTS."""
    out = dict(DEFAULT_PROMPTS)
    out.update({k: v for k, v in data.get("account_prompts", {}).items()
                if k in PROMPT_CLASSES and v in PROMPT_VALUES})
    out.update({k: v for k, v in acct.get("prompts", {}).items()
                if k in PROMPT_CLASSES and v in PROMPT_VALUES})
    return out


def methods(acct: dict[str, Any]) -> list[str]:
    return [k for k in SECRET_FIELDS if acct.get("secrets", {}).get(k)]


def _ssh_keygen() -> str:
    path = shutil.which("ssh-keygen")
    if not path:
        raise RuntimeError("ssh-keygen was not found (it ships with OpenSSH)")
    return path


def _ssh_string(buf: bytes, pos: int) -> tuple[bytes, int]:
    n = int.from_bytes(buf[pos:pos + 4], "big")
    if pos + 4 + n > len(buf):
        raise ValueError("truncated")
    return buf[pos + 4:pos + 4 + n], pos + 4 + n


def public_key_of(private_key: str) -> str:
    """The OpenSSH public key line for an OpenSSH private key, parsed here
    (stdlib only; nothing written to disk). Keys with a passphrase are
    refused: the gateway loads keys into a private ssh-agent unattended."""
    import base64
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
        raise ValueError("that key has a passphrase; the gateway needs a key without one "
                         "(it never leaves the vault and a private agent)")
    if nkeys != 1 or priv[:4] != priv[4:8]:
        raise ValueError("that is not an OpenSSH private key")
    return f"{keytype.decode()} {base64.b64encode(blob).decode()}"


def fingerprint_of(public_key: str) -> str:
    """SHA256:… as ssh-keygen -l prints it."""
    import base64
    import hashlib
    try:
        blob = base64.b64decode(public_key.split()[1])
    except (IndexError, ValueError):
        return ""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def generate_ssh_key(comment: str) -> tuple[str, str]:
    """A new ed25519 key pair (private, public). ssh-keygen can only write
    files, so it writes into a private temp dir inside the vault home, which
    is read and removed at once."""
    import tempfile
    home().mkdir(parents=True, exist_ok=True)
    tmp = Path(tempfile.mkdtemp(prefix=".keygen-", dir=home()))
    try:
        os.chmod(tmp, 0o700)
        subprocess.run([_ssh_keygen(), "-q", "-t", "ed25519", "-N", "", "-C", comment,
                        "-f", str(tmp / "k")], check=True, capture_output=True,
                       stdin=subprocess.DEVNULL, timeout=15)
        return (tmp / "k").read_text().strip() + "\n", (tmp / "k.pub").read_text().strip()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def account_view(ref: str, acct: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    """What Claude may know about one account: never a value."""
    kind = acct.get("kind", "")
    view = {"kind": kind, "description": acct.get("description", "")}
    for f in KINDS.get(kind, {}).get("fields", ()):
        if acct.get(f):
            view[f] = acct[f]
    if KINDS.get(kind, {}).get("owners"):
        view["owners"] = list(acct.get("owners", []))
    view["hosts"] = list(acct.get("hosts", []))
    view["methods"] = methods(acct)
    if acct.get("public_key"):
        view["key_fingerprint"] = acct.get("key_fingerprint", "")
    if kind in PINNED_KINDS:
        view["host_keys"] = host_key_fingerprints(acct.get("known_hosts", ""))
    view["prompts"] = effective_prompts(acct, data)
    return view


def catalog(data: dict[str, Any] | None = None) -> dict[str, Any]:
    """Everything Claude may know about the vault: never a value."""
    data = data if data is not None else load()
    return {
        "secrets": {n: {"description": s.get("description", ""),
                        "hosts": list(s.get("hosts", []))}
                    for n, s in sorted(data["secrets"].items())},
        "sudo": sorted(data["sudo"]),
        "sudo_enabled": sorted(data["sudo_enabled"]),
        "sudo_session": {h: list(ids) for h, ids in data["sudo_session"].items() if ids},
        "accounts": {r: account_view(r, a, data) for r, a in sorted(data["accounts"].items())},
    }


def all_values(data: dict[str, Any] | None = None) -> list[str]:
    data = data if data is not None else load()
    vals = [s["value"] for s in data["secrets"].values()]
    vals += [e["password"] for e in data["sudo"].values()]
    vals += [v for a in data["accounts"].values()
             for v in a.get("secrets", {}).values() if isinstance(v, str)]
    return [v for v in vals if v]
