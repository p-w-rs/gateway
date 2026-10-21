"""Read-only access to a gateway v2 vault, for migration (SPEC 4).

Copied from v2's vault.py / sshconf.py / sshops.py (git main) so that the v3
modules don't depend on v2 code: decryption of store.age with its key.txt
(vault v1 and v2 accepted), the v2 rules that the mapper needs (routes,
rotated keys, the sudo-to-ssh-account rule, effective prompt classes), and a
walk over every credential value. Nothing here writes.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any, Iterator

from . import paths

LOCAL_ALIASES = {"localhost", "local", "127.0.0.1", "::1", "this"}
AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
PROMPT_CLASSES = ("read", "write", "delete", "exec")
DEFAULT_PROMPTS = {"read": "auto", "write": "auto", "delete": "ask", "exec": "ask"}
KINDS = ("github", "hf", "pijul", "azure", "mlcat", "ssh", "registry")
SECRET_FIELDS = ("token", "ssh_key", "refresh_token")


class V2Error(Exception):
    pass


def norm_host(host: str) -> str:
    h = host.strip().lower()
    return "localhost" if h in LOCAL_ALIASES else h


def _empty() -> dict[str, Any]:
    return {"version": 2, "secrets": {}, "sudo": {}, "sudo_enabled": [], "sudo_session": {},
            "accounts": {}, "account_prompts": {}, "grants": {}, "ssh_reuse": {}}


def decrypt(store: Path, key: Path) -> dict[str, Any]:
    """The v2 vault as a dict (v1 and v2 layouts). Plaintext via a pipe only."""
    if not store.is_file():
        raise V2Error(f"{store.name} is missing")
    if not key.is_file():
        raise V2Error(f"the 0.6 key ({key.name}) is missing")
    try:
        age = paths.tool("age")
    except paths.ToolMissing as e:
        raise V2Error(str(e)) from None
    out = subprocess.run([age, "-d", "-i", str(key), str(store)], stdin=subprocess.DEVNULL,
                         capture_output=True, timeout=30)
    if out.returncode != 0:
        raise V2Error("could not decrypt the 0.6 vault with its key")
    try:
        data = json.loads(out.stdout.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise V2Error("the 0.6 vault isn't valid JSON") from None
    return normalize(data)


def normalize(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise V2Error("the 0.6 vault isn't a JSON object")
    v = data.get("version", 1)
    if v not in (1, 2):
        raise V2Error(f"unknown 0.6 vault version {v!r}")
    for k, val in _empty().items():
        data.setdefault(k, val)
    for k in ("secrets", "sudo", "accounts", "account_prompts", "sudo_session", "ssh_reuse"):
        if not isinstance(data.get(k), dict):
            raise V2Error(f"the 0.6 vault's {k} isn't an object")
    return data


# ---------------------------------------------------------------------------
# v2 rules the mapper reuses
# ---------------------------------------------------------------------------


def _s(v: Any) -> str:
    return v if isinstance(v, str) else (str(v) if isinstance(v, int) and not isinstance(v, bool) else "")


def routes(acct: dict[str, Any]) -> list[dict[str, str]]:
    """sshconf.routes: the account's routes in order (one from host/port if none).
    Malformed routes (not objects) are skipped; values are strings."""
    rs = acct.get("routes") or []
    rs = [r for r in rs if isinstance(r, dict)] if isinstance(rs, list) else []
    if not rs:
        return [{"name": "default", "host": _s(acct.get("host")),
                 "port": _s(acct.get("port")), "when": ""}]
    return [{"name": _s(r.get("name")) or f"route{i + 1}", "host": _s(r.get("host")),
             "port": _s(r.get("port")), "when": _s(r.get("when"))}
            for i, r in enumerate(rs)]


def keys(acct: dict[str, Any]) -> list[tuple[str, str]]:
    """sshconf.keys: (private, public) pairs, newest first. Unlike v2's zip,
    every rotated private key is kept even when its public key is missing
    (the caller derives it), so none is lost."""
    s = acct.get("secrets") or {}
    if not isinstance(s, dict):
        return []
    out = []
    if s.get("ssh_key"):
        out.append((s["ssh_key"], _s(acct.get("public_key"))))
    olds = s.get("old_ssh_keys") or []
    pubs = acct.get("old_public_keys") or []
    if isinstance(olds, list):
        for i, priv in enumerate(olds):
            pub = pubs[i] if isinstance(pubs, list) and i < len(pubs) else ""
            out.append((priv, _s(pub)))
    return out


def account_for_sudo(host: str, user: str, data: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """sshops.account_for_sudo: an ssh account with the same user whose host,
    name or a route's host equals the sudo host."""
    for ref, a in sorted(data["accounts"].items()):
        if not isinstance(a, dict) or ":" not in ref:
            continue
        if a.get("kind") == "ssh" and a.get("user") == user and (
                a.get("host") == host or ref.split(":", 1)[1] == host
                or any(r["host"] == host for r in routes(a))):
            return ref, a
    return None


def effective_prompts(acct: dict[str, Any], data: dict[str, Any]) -> dict[str, str]:
    out = dict(DEFAULT_PROMPTS)
    out.update({k: v for k, v in (data.get("account_prompts") or {}).items()
                if k in PROMPT_CLASSES and v in ("auto", "ask", "refuse")})
    pr = acct.get("prompts")
    out.update({k: v for k, v in (pr if isinstance(pr, dict) else {}).items()
                if k in PROMPT_CLASSES and v in ("auto", "ask", "refuse")})
    return out


def account_credentials(ref: str, acct: Any) -> list[str]:
    """The credential refs of one v2 account (for dropping it whole)."""
    return [r for r, _ in credentials({"accounts": {ref: acct}})]


def credentials(data: dict[str, Any]) -> Iterator[tuple[str, str]]:
    """(ref, value) for every credential value in a v2 vault: secrets, sudo
    passwords, account tokens, keys (current and rotated) and refresh tokens."""
    for name, s in (data.get("secrets") or {}).items():
        if isinstance(s, dict) and isinstance(s.get("value"), str) and s["value"]:
            yield name, s["value"]
    for key, e in (data.get("sudo") or {}).items():
        if isinstance(e, dict) and isinstance(e.get("password"), str) and e["password"]:
            yield f"sudo {key}", e["password"]
    for ref, a in (data.get("accounts") or {}).items():
        sec = a.get("secrets") if isinstance(a, dict) else None
        if not isinstance(sec, dict):
            continue
        for k, v in sec.items():
            if isinstance(v, str) and v:
                yield f"{ref} {k}", v
            elif isinstance(v, list):
                for i, x in enumerate(v):
                    if isinstance(x, str) and x:
                        yield f"{ref} {k}[{i}]", x
