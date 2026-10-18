"""/gate:export and /gate:import: the whole gateway in one passphrase-encrypted
age file, to move it to another machine.

Both start from a command the user types, which opens a setup grant
(setup.py); Claude asks one question and calls gate_setup, which runs here
with the native dialogs (or the terminal, through `gateway finish`).

age reads a passphrase only from a terminal, so it runs under a private
pseudo-terminal (stdlib `pty`) whose prompts the gateway answers. The
plaintext goes through a FIFO in a 0700 temp dir, never a regular file. A
file made here opens by hand with plain `age -d FILE`.

Machine- and session-specific state is never exported: setup grants, sudo
session switches, sudo "always" switches (a typed /gate:enable on the new
machine turns them on again) and ssh connection reuse.
"""
from __future__ import annotations

import datetime
import errno
import json
import os
import re
import select
import shutil
import signal
import socket
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

from . import policy, vault

FORMAT = 1
MAX_FILE = 5_000_000
AGE_TIMEOUT = 120


class TransferError(Exception):
    """Refused: nothing was written or merged."""


class Declined(Exception):
    """The person cancelled or didn't finish; nothing was written or merged."""


# ---------------------------------------------------------------------------
# age under a pty
# ---------------------------------------------------------------------------


def _run_age(args: list[str], passphrase: str, answers: int,
             fifo: Path, feed: bytes | None) -> tuple[int, str, bytes]:
    """Run age with args under a pty, answering `answers` passphrase prompts.
    With feed, write it into fifo (age's input); otherwise read fifo (age's
    output). Returns (exit code, what age printed, bytes read)."""
    import pty
    age = vault._age("age")
    got = bytearray()
    done = threading.Event()

    def pump() -> None:
        try:
            if feed is not None:
                with open(fifo, "wb") as f:
                    f.write(feed)
            else:
                with open(fifo, "rb") as f:
                    while chunk := f.read(65536):
                        got.extend(chunk)
                        if len(got) > MAX_FILE * 2:
                            break
        except OSError:
            pass
        finally:
            done.set()

    t = threading.Thread(target=pump, daemon=True)
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TMPDIR")}
    env["TERM"] = "dumb"
    pid, fd = pty.fork()
    if pid == 0:  # child: age, with the pty as its terminal
        try:
            os.execve(age, [age, *args], env)
        finally:
            os._exit(127)
    t.start()  # after the fork: the child is single-threaded until it execs
    out = bytearray()
    sent, mark = 0, 0
    deadline = time.time() + AGE_TIMEOUT
    status = None
    try:
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    chunk = os.read(fd, 4096)
                except OSError as e:  # EIO on Linux once the child is gone
                    if e.errno != errno.EIO:
                        raise
                    chunk = b""
                if not chunk:
                    break
                out.extend(chunk)
                tail = bytes(out[mark:])
                if sent < answers and re.search(rb"(?i)passphrase[^\n]*:\s*$", tail):
                    os.write(fd, passphrase.encode() + b"\r")
                    sent += 1
                    mark = len(out)
            wpid, st = os.waitpid(pid, os.WNOHANG)
            if wpid:
                status = st
                # drain what's left
                while True:
                    r, _, _ = select.select([fd], [], [], 0.05)
                    if not r:
                        break
                    try:
                        chunk = os.read(fd, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    out.extend(chunk)
                break
        # The pty closes a moment before age is reapable: wait for it.
        until = time.time() + 10
        while status is None and time.time() < until:
            wpid, st = os.waitpid(pid, os.WNOHANG)
            if wpid:
                status = st
            else:
                time.sleep(0.02)
        if status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            raise TransferError("age didn't finish in time")
    finally:
        os.close(fd)
        if not done.is_set():  # unblock the pump if age never opened the FIFO
            try:
                flags = os.O_NONBLOCK | (os.O_RDONLY if feed is not None else os.O_WRONLY)
                os.close(os.open(fifo, flags))
            except OSError:
                pass
        t.join(5)
    code = os.waitstatus_to_exitcode(status)
    text = out.decode("utf-8", "replace").replace(passphrase, "***") if passphrase else ""
    return code, text, bytes(got)


def _tmpdir() -> Path:
    d = Path(tempfile.mkdtemp(prefix="gw-xfer-"))
    os.chmod(d, 0o700)
    return d


def encrypt(plain: bytes, passphrase: str, out: Path) -> None:
    d = _tmpdir()
    try:
        fifo = d / "in"
        os.mkfifo(fifo, 0o600)
        tmp_out = d / "out.age"
        code, text, _ = _run_age(["-p", "-o", str(tmp_out), str(fifo)], passphrase, 2,
                                 fifo, plain)
        if code != 0 or not tmp_out.is_file():
            raise TransferError("age could not encrypt: " + _age_error(text))
        os.chmod(tmp_out, 0o600)
        shutil.move(str(tmp_out), out)
        os.chmod(out, 0o600)
    finally:
        shutil.rmtree(d, ignore_errors=True)


def decrypt(src: Path, passphrase: str) -> bytes:
    d = _tmpdir()
    try:
        fifo = d / "out"
        os.mkfifo(fifo, 0o600)
        code, text, got = _run_age(["-d", "-o", str(fifo), str(src)], passphrase, 1, fifo, None)
        if code != 0:
            if "incorrect passphrase" in text.lower() or "no identity matched" in text.lower():
                raise Declined("That passphrase doesn't open the file; nothing was imported.")
            raise TransferError("age could not decrypt the file: " + _age_error(text))
        return got
    finally:
        shutil.rmtree(d, ignore_errors=True)


def _age_error(text: str) -> str:
    lines = [l.strip() for l in text.splitlines() if "age:" in l or "error" in l.lower()]
    return (lines[-1] if lines else "unknown error")[:200]


# ---------------------------------------------------------------------------
# What goes in the file
# ---------------------------------------------------------------------------


def export_data(data: dict[str, Any], without_secrets: bool) -> dict[str, Any]:
    secrets = {n: dict(s) for n, s in data.get("secrets", {}).items()}
    sudo = {k: dict(e) for k, e in data.get("sudo", {}).items()}
    accounts = json.loads(json.dumps(data.get("accounts", {})))
    if without_secrets:
        for s in secrets.values():
            s.pop("value", None)
        for e in sudo.values():
            e.pop("password", None)
        for a in accounts.values():
            a["secrets"] = {}
    return {"gateway_export": FORMAT, "created": vault.now(), "from_host": socket.gethostname(),
            "without_secrets": without_secrets, "secrets": secrets, "sudo": sudo,
            "accounts": accounts, "account_prompts": dict(data.get("account_prompts", {}))}


def default_path(today: datetime.date | None = None) -> Path:
    today = today or datetime.date.today()
    base = Path.home() / "Downloads"
    if not base.is_dir():
        base = Path.home()
    p = base / f"gateway-{today:%Y%m%d}.age"
    n = 2
    while p.exists():
        p = base / f"gateway-{today:%Y%m%d}-{n}.age"
        n += 1
    return p


def check_export_path(raw: str) -> Path:
    p = Path(os.path.expanduser(raw.strip()))
    if not p.is_absolute():
        p = Path.cwd() / p
    if p.suffix != ".age":
        raise TransferError("the export file name must end in .age")
    if not p.parent.is_dir():
        raise TransferError(f"{p.parent} is not a folder")
    if p.exists():
        raise TransferError(f"{p} already exists; give another name")
    if str(vault.home()) in str(p.resolve()):
        raise TransferError("not inside the gateway's own folder")
    return p


# ---------------------------------------------------------------------------
# Import: validate, plan, merge
# ---------------------------------------------------------------------------

_SCALAR = (str, int, float, bool, type(None))
_CHECKED = {"kind", "hosts", "owners", "secrets", "routes", "known_hosts", "prompts",
            "host_key_policy", "comfort", "public_key", "old_public_keys", "description"}


def _str_list(v: Any, what: str) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise TransferError(f"{what} must be a list of strings")
    return v


def _hosts(v: Any, what: str) -> list[str]:
    """Host names; a legacy "*" is dropped (it never sent a credential
    anywhere: actions.py ignores it too)."""
    out = []
    for h in _str_list(v, what):
        if h == "*":
            continue
        if not vault.HOST_RE.fullmatch(h):
            raise TransferError(f"{what}: '{h}' is not a host name")
        out.append(h)
    return out


def validate(obj: Any) -> dict[str, Any]:
    """The file's content, checked as strictly as a setup. Raises
    TransferError for anything wrong (the whole import is refused)."""
    from . import common, sshconf
    if not isinstance(obj, dict) or obj.get("gateway_export") != FORMAT:
        raise TransferError("this isn't a gateway export (or it's from a newer version)")
    out: dict[str, Any] = {"without_secrets": bool(obj.get("without_secrets")),
                           "from_host": str(obj.get("from_host", ""))[:100],
                           "created": str(obj.get("created", ""))[:40],
                           "secrets": {}, "sudo": {}, "accounts": {}, "account_prompts": {},
                           "dropped": 0}
    for name, s in (obj.get("secrets") or {}).items():
        if not vault.NAME_RE.fullmatch(name) or not isinstance(s, dict):
            raise TransferError(f"secret {name!r} is not valid")
        v = s.get("value")
        if v is not None and (not isinstance(v, str) or len(v) > 65536):
            raise TransferError(f"secret {name}: bad value")
        out["secrets"][name] = {"value": v, "description": str(s.get("description", ""))[:300],
                                "hosts": _hosts(s.get("hosts", []), f"secret {name} hosts"),
                                "updated": str(s.get("updated", ""))[:40]}
    for key, e in (obj.get("sudo") or {}).items():
        if not isinstance(e, dict):
            raise TransferError(f"sudo {key!r} is not valid")
        user, host = str(e.get("user", "")), vault.norm_host(str(e.get("host", "")))
        if (not vault.USER_RE.fullmatch(user) or not vault.HOST_RE.fullmatch(host)
                or key != f"{user}@{host}"):
            raise TransferError(f"sudo {key!r} is not valid")
        pw = e.get("password")
        if pw is not None and (not isinstance(pw, str) or len(pw) > 4096):
            raise TransferError(f"sudo {key}: bad password")
        out["sudo"][key] = {"user": user, "host": host, "password": pw,
                            "updated": str(e.get("updated", ""))[:40]}
    for ref, a in (obj.get("accounts") or {}).items():
        parsed = vault.parse_account_ref(ref)
        if not parsed or not isinstance(a, dict) or a.get("kind") != parsed[0]:
            raise TransferError(f"account {ref!r} is not valid")
        kind = parsed[0]
        spec = vault.KINDS[kind]
        rec: dict[str, Any] = {"kind": kind, "description": str(a.get("description", ""))[:300]}
        for f in spec["fields"]:
            v = a.get(f, "")
            if not isinstance(v, str):
                raise TransferError(f"{ref}: {f} must be text")
            try:
                rec[f] = common._clean_setting(kind, f, v)
            except common.CommandError as e:
                raise TransferError(f"{ref}: {e}")
        if "host" in a and "host" not in spec["fields"]:
            if not isinstance(a["host"], str) or not vault.HOST_RE.fullmatch(a["host"]):
                raise TransferError(f"{ref}: bad host")
            rec["host"] = a["host"]
        rec["hosts"] = _hosts(a.get("hosts", []), f"{ref} hosts")
        if spec["owners"]:
            try:
                rec["owners"] = common._owners(_str_list(a.get("owners", []), f"{ref} owners"))
            except common.CommandError as e:
                raise TransferError(f"{ref}: {e}")
        sec = a.get("secrets") or {}
        if not isinstance(sec, dict):
            raise TransferError(f"{ref}: secrets must be an object")
        rec["secrets"] = {}
        for k, v in sec.items():
            if k in vault.SECRET_FIELDS and isinstance(v, str) and len(v) < 65536:
                rec["secrets"][k] = v
            elif k == "old_ssh_keys":
                rec["secrets"][k] = _str_list(v, f"{ref} old keys")[:3]
            else:
                raise TransferError(f"{ref}: unknown credential {k!r}")
        for k in ("public_key", "known_hosts"):
            if k in a:
                if not isinstance(a[k], str) or len(a[k]) > 65536:
                    raise TransferError(f"{ref}: bad {k}")
                rec[k] = a[k]
        if "old_public_keys" in a:
            rec["old_public_keys"] = _str_list(a["old_public_keys"], f"{ref} old keys")[:3]
        if "routes" in a:
            if kind != "ssh":
                raise TransferError(f"{ref}: routes are for ssh accounts")
            try:
                rec["routes"] = sshconf.check_routes(a["routes"])
            except ValueError as e:
                raise TransferError(f"{ref}: {e}")
        if "host_key_policy" in a:
            if a["host_key_policy"] not in sshconf.POLICIES:
                raise TransferError(f"{ref}: bad host_key_policy")
            rec["host_key_policy"] = a["host_key_policy"]
        if "comfort" in a:
            c = a["comfort"]
            if not isinstance(c, dict) or set(c) - set(sshconf.COMFORT) or not all(
                    isinstance(v, (int, bool)) for v in c.values()):
                raise TransferError(f"{ref}: bad connection settings")
            rec["comfort"] = dict(c)
        if "prompts" in a:
            p = a["prompts"]
            if not isinstance(p, dict) or any(k not in vault.PROMPT_CLASSES
                                              or v not in vault.PROMPT_VALUES for k, v in p.items()):
                raise TransferError(f"{ref}: bad prompts")
            rec["prompts"] = dict(p)
        # Anything else: plain values only (e.g. a sign-in's token_source).
        for k, v in a.items():
            if k in rec or k in _CHECKED or k in spec["fields"] or k == "host":
                continue
            if isinstance(v, _SCALAR) and len(str(v)) < 1000 and re.fullmatch(r"[a-z_]{1,40}", k):
                rec[k] = v
            else:
                out["dropped"] += 1
        out["accounts"][ref] = rec
    ap = obj.get("account_prompts") or {}
    if not isinstance(ap, dict) or any(k not in vault.PROMPT_CLASSES or v not in vault.PROMPT_VALUES
                                       for k, v in ap.items()):
        raise TransferError("bad default prompts")
    out["account_prompts"] = dict(ap)
    for ref, a in out["accounts"].items():
        for link in ("jump", "via"):
            if a.get(link) and a[link] not in out["accounts"]:
                out.setdefault("notes", []).append(f"{ref} uses {a[link]}, which isn't in the file")
    return out


def plan_import(local: dict[str, Any], inc: dict[str, Any], keep_existing: bool) -> dict[str, Any]:
    """Who gets added, replaced, kept, skipped. Names only."""
    p: dict[str, list[str]] = {"add": [], "replace": [], "unchanged": [], "skip": [], "hostkey": []}
    for section, label in (("secrets", "secret"), ("sudo", "sudo"), ("accounts", "")):
        for name, item in inc[section].items():
            tag = f"{label} {name}".strip()
            old = local[section].get(name)
            has_value = {"secrets": lambda x: bool(x.get("value")),
                         "sudo": lambda x: bool(x.get("password")),
                         "accounts": lambda x: True}[section](item)
            if old is None:
                (p["add"] if has_value else p["skip"]).append(tag)
            elif keep_existing:
                p["unchanged"].append(tag)
            else:
                p["replace"].append(tag)
                if (section == "accounts" and item.get("known_hosts") and old.get("known_hosts")
                        and vault.host_key_fingerprints(item["known_hosts"])
                        != vault.host_key_fingerprints(old["known_hosts"])):
                    p["hostkey"].append(name)
    return p


def summary(path: Path, inc: dict[str, Any], p: dict[str, list[str]], keep_existing: bool) -> str:
    L = [f"Import {path.name}"
         + (f" (from {inc['from_host']}, {inc['created'][:10]})" if inc["from_host"] else "")
         + (", a shareable copy without secret values" if inc["without_secrets"] else "") + "."]
    for key, words in (("add", "Adds"), ("replace", "Replaces (the file's version wins)"),
                       ("unchanged", "Keeps yours"), ("skip", "Skips (no value in the file)")):
        if p[key]:
            L.append(f"{words}: {', '.join(p[key])}.")
    if p["hostkey"]:
        L.append("Host key differs from yours (the file's key will be pinned): "
                 + ", ".join(p["hostkey"]) + ".")
    for n in inc.get("notes", []):
        L.append(n + ".")
    if not (p["add"] or p["replace"]):
        L.append("Nothing would change.")
    L.append("sudo stays as set on this machine (enable it again with /gate:enable).")
    return "\n".join(L)


def merge(data: dict[str, Any], inc: dict[str, Any], keep_existing: bool) -> None:
    for section, value_of in (("secrets", lambda x: x.get("value")),
                              ("sudo", lambda x: x.get("password"))):
        for name, item in inc[section].items():
            old = data[section].get(name)
            if old is not None and keep_existing:
                continue
            if old is None and not value_of(item):
                continue
            new = dict(item)
            if not value_of(item):  # shareable copy: keep the local value
                key = "value" if section == "secrets" else "password"
                new[key] = old.get(key) if old else ""
            data[section][name] = new
    for ref, a in inc["accounts"].items():
        old = data["accounts"].get(ref)
        if old is not None and keep_existing:
            continue
        new = json.loads(json.dumps(a))
        if old is not None:
            for k, v in old.get("secrets", {}).items():
                new["secrets"].setdefault(k, v)  # values the file doesn't carry stay
        new["updated"] = vault.now()
        data["accounts"][ref] = new
    if not keep_existing:
        data["account_prompts"].update(inc["account_prompts"])


# ---------------------------------------------------------------------------
# Running an export or import (dialogs or terminal)
# ---------------------------------------------------------------------------


def run_export(plan: dict[str, Any], confirm: Callable[[str], bool],
               secret: Callable[[str], str | None]) -> str:
    path: Path = plan["path"]
    if not confirm("\n".join(plan["lines"]) + "\n\nAllow?"):
        raise Declined("The user chose Cancel; nothing was exported.")
    first = secret("Choose a passphrase for the export file.\nYou'll need it to import "
                   "it (or to open it with age -d). It isn't stored anywhere.")
    if not first:
        raise Declined("No passphrase was entered; nothing was exported.")
    if secret("Type the passphrase again.") != first:
        raise Declined("The two passphrases didn't match; nothing was exported.")
    data = vault.load()
    body = json.dumps(export_data(data, plan["without_secrets"]), indent=1).encode()
    if path.exists():
        raise TransferError(f"{path} appeared in the meantime; nothing was exported")
    encrypt(body, first, path)
    policy.audit("export", {"path": str(path), "without_secrets": plan["without_secrets"],
                            "accounts": len(data["accounts"]), "secrets": len(data["secrets"]),
                            "sudo": len(data["sudo"])})
    return (f"Exported {len(data['accounts'])} accounts, {len(data['secrets'])} secrets and "
            f"{len(data['sudo'])} sudo passwords"
            + (" (without their values: a shareable copy)" if plan["without_secrets"] else "")
            + f" to {path}. Import it on another machine with /gate:import {path}; read it by "
              f"hand with: age -d {path}")


def run_import(plan: dict[str, Any], confirm: Callable[[str], bool],
               secret: Callable[[str], str | None]) -> str:
    path: Path = plan["path"]
    pw = secret(f"The passphrase of {path.name}.")
    if not pw:
        raise Declined("No passphrase was entered; nothing was imported.")
    raw = decrypt(path, pw)
    try:
        inc = validate(json.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TransferError("the file decrypted but isn't a gateway export")
    keep = plan["keep_existing"]
    with vault.locked():
        p = plan_import(vault.load(), inc, keep)
    if not confirm(summary(path, inc, p, keep) + "\n\nAllow?"):
        raise Declined("The user chose Cancel; nothing was imported.")
    with vault.locked():
        data = vault.load()
        p = plan_import(data, inc, keep)
        merge(data, inc, keep)
        vault.save(data)
    policy.audit("import", {"path": str(path), "keep_existing": keep,
                            "added": p["add"], "replaced": p["replace"], "skipped": p["skip"]})
    bits = [f"Imported {path.name}."]
    for key, words in (("add", "Added"), ("replace", "Replaced"), ("unchanged", "Kept yours"),
                       ("skip", "Skipped (no value in the file)")):
        if p[key]:
            bits.append(f"{words}: {', '.join(p[key])}.")
    if p["hostkey"]:
        bits.append("Pinned the file's host key for: " + ", ".join(p["hostkey"]) + ".")
    if inc["sudo"]:
        bits.append("sudo is off for imported hosts until enabled with /gate:enable sudo HOST.")
    return " ".join(bits)
