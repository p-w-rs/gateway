"""The gateway's own encrypted vault: secrets and sudo passwords.

Separate from any personal secret store. Lives in $NETGW_HOME (default
${XDG_CONFIG_HOME:-~/.config}/net-gateway):

    key.txt     age identity, generated on first write (mode 600)
    store.age   the vault, age-encrypted JSON (mode 600)

The JSON looks like:
    {"version": 1,
     "secrets": {"HF_TOKEN": {"value": "...", "description": "...",
                              "hosts": ["huggingface.co"], "updated": "..."}},
     "sudo": {"alice@localhost": {"user": "alice", "host": "localhost",
                                   "password": "...", "updated": "..."}}}

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
import time
from pathlib import Path
from typing import Any, Iterator

NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# ssh alias, hostname, IPv4 or IPv6 (no leading '-', so never an ssh option).
HOST_RE = re.compile(r"[A-Za-z0-9_\[][A-Za-z0-9._:%\[\]-]*")
USER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9._-]*")
LOCAL_ALIASES = {"localhost", "local", "127.0.0.1", "::1", "this"}


def home() -> Path:
    override = os.environ.get("NETGW_HOME")
    if override:
        return Path(override)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return Path(base) / "net-gateway"


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


def _empty() -> dict[str, Any]:
    # sudo_enabled: hosts enabled in every session (`/sudo enable HOST always`).
    # sudo_session: {host: [session ids]} enabled for those sessions only.
    # run_privileged runs without asking there; elsewhere it needs approval.
    return {"version": 1, "secrets": {}, "sudo": {}, "sudo_enabled": [],
            "sudo_session": {}}


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
    }


def all_values(data: dict[str, Any] | None = None) -> list[str]:
    data = data if data is not None else load()
    vals = [s["value"] for s in data["secrets"].values()]
    vals += [e["password"] for e in data["sudo"].values()]
    return [v for v in vals if v]
