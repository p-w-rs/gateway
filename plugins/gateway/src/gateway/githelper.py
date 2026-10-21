"""git: the credential helper, the include file and commit identities (SPEC 9.4).

Three pieces:

- `include_config(form, meta)`: the URL-scoped part of $DATA/git/config.
  A `[credential "SCHEME://HOST"]` section (helper reset + the gateway helper
  + useHttpPath) for every git account host; `[url]` insteadOf rewrites from
  the ssh forms to https for token-only hosts (every account on the host has
  a token and no ssh key); `[includeIf "hasconfig:remote.*.url:..."]` blocks
  that pull in a per-account identity file for each owner, for accounts that
  carry a commit name/email. It never emits the global `[credential] helper =`
  reset (envfile writes that first).
- `identity_files(form)`: {name: "[user] ..."} for those identity includes.
- `credential_main(argv)`: git-credential-gateway get|store|erase. `get`
  answers only when its parent is git-remote-http(s) (or git-lfs's `git
  credential fill`), the protocol is https (http only for a loopback host
  under a test override), GIT_TRACE_REDACT isn't 0/false, GIT_SSL_NO_VERIFY
  is absent (git turns checking off when it is set at all, even empty) and
  http.sslVerify isn't false for the URL (`git config --get-urlmatch`, so a
  URL-scoped `http.https://host/.sslVerify false` counts; if git can't
  answer, the helper refuses); it picks the account by host and
  path, refuses when the account's bound set lacks the host, and returns the
  token (username x-access-token for GitHub, else the login). `store` is
  ignored; `erase` marks the token stale.

includeIf hasconfig from an env-provided include.path was verified to work
with /opt/local/bin/git 2.55 and /usr/bin/git 2.54 (Apple Git-157): both
chose the per-owner identity for https and ssh remotes under the owner and
the global identity otherwise. No fallback is needed.
"""
from __future__ import annotations

import ctypes
import hmac
import os
import struct
import subprocess
import sys
import urllib.parse
from pathlib import Path
from typing import Any

from . import accounts as acctmod
from . import audit, consent
from . import form as formmod
from . import vault

LOOPBACK = ("127.0.0.1", "localhost", "::1", "[::1]")


def _bare(host: str) -> str:
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _is_loopback(host: str) -> bool:
    return _bare(host).lower() in ("127.0.0.1", "localhost", "::1")


def _scheme(host: str) -> str:
    return "http" if _is_loopback(host) else "https"


# ---------------------------------------------------------------------------
# The include file (git re-reads it when it changes mid-session)
# ---------------------------------------------------------------------------


def _git_hosts(form: formmod.Form) -> dict[str, list[formmod.Account]]:
    """host (as git sees it) -> accounts whose credential goes there over git
    https. github: the host; huggingface: huggingface.co and hf.co."""
    out: dict[str, list[formmod.Account]] = {}
    for a in form.accounts.values():
        hosts: list[str] = []
        if a.kind == "github":
            hosts = [a.host or "github.com"]
        elif a.kind == "huggingface":
            hosts = ["huggingface.co", "hf.co"]
        for h in hosts:
            out.setdefault(h.lower(), []).append(a)
    return out


def _token_only(accts: list[formmod.Account], meta: dict[str, Any]) -> bool:
    """Every account for a host has a token and none has an ssh key: ssh
    remotes must be rewritten to https (SPEC 9.4)."""
    macc = (meta or {}).get("accounts") or {}
    saw = False
    for a in accts:
        m = macc.get(a.name) or {}
        if m.get("ssh_key"):
            return False
        if m.get("token"):
            saw = True
    return saw


def _ssh_rewrites(host: str) -> list[str]:
    """insteadOf source URLs rewritten to https://host/ for a token-only host."""
    bare = _bare(host)
    out = [f"git@{bare}:", f"ssh://git@{bare}/"]
    if bare == "github.com":
        out += ["git@ssh.github.com:", "ssh://git@ssh.github.com/"]
    return out


def _identity_hosts(a: formmod.Account) -> list[str]:
    if a.kind == "github":
        return [a.host or "github.com"]
    if a.kind == "huggingface":
        return ["huggingface.co", "hf.co"]
    return []


def _escape(val: str) -> str:
    """git config double-quoted value (keeps ", \\, ], ; literal)."""
    return val.replace("\\", "\\\\").replace('"', '\\"')


def identity_name(account: str) -> str:
    return "identity-" + account


def include_config(form, vault_meta: dict) -> str:
    """URL-scoped credential sections, insteadOf rewrites and identity
    includeIf blocks (SPEC 9.4); '' when the form has no git account."""
    if form is None or not getattr(form, "accounts", None):
        return ""
    from . import paths
    helper = str(paths.bin_dir() / "git-credential-gateway")
    gitdir = paths.git_dir()
    hosts = _git_hosts(form)
    out: list[str] = []
    for host in sorted(hosts):
        scheme = _scheme(host)
        out.append(f'[credential "{scheme}://{host}"]')
        out.append("\thelper =")
        out.append(f"\thelper = {helper}")
        out.append("\tuseHttpPath = true")
    for host in sorted(hosts):
        if _token_only(hosts[host], vault_meta):
            scheme = _scheme(host)
            srcs = _ssh_rewrites(host)
            out.append(f'[url "{scheme}://{host}/"]')
            for s in srcs:
                out.append(f"\tinsteadOf = {s}")
    # Identity includes, in a stable order.
    for name in sorted(form.accounts):
        a = form.accounts[name]
        if a.kind not in ("github", "huggingface"):
            continue
        if not (a.commit_name or a.email):
            continue
        owners = [o for o in a.owner_names() if o]
        if not owners:
            continue
        path = gitdir / identity_name(name)
        for host in _identity_hosts(a):
            scheme = _scheme(host)
            bare = _bare(host)
            for owner in owners:
                out.append(f'[includeIf "hasconfig:remote.*.url:{scheme}://{host}/{owner}/**"]')
                out.append(f"\tpath = {path}")
                out.append(f'[includeIf "hasconfig:remote.*.url:git@{bare}:{owner}/**"]')
                out.append(f"\tpath = {path}")
                out.append(f'[includeIf "hasconfig:remote.*.url:ssh://git@{bare}/{owner}/**"]')
                out.append(f"\tpath = {path}")
    return ("\n".join(out) + "\n") if out else ""


def identity_files(form) -> dict[str, str]:
    """{filename: content} of [user] identity include files under $DATA/git/."""
    if form is None:
        return {}
    out: dict[str, str] = {}
    for name, a in getattr(form, "accounts", {}).items():
        if a.kind not in ("github", "huggingface"):
            continue
        if not (a.commit_name or a.email) or not [o for o in a.owner_names() if o]:
            continue
        lines = ["[user]"]
        if a.commit_name:
            lines.append(f'\tname = "{_escape(a.commit_name)}"')
        if a.email:
            lines.append(f'\temail = "{_escape(a.email)}"')
        out[identity_name(name)] = "\n".join(lines) + "\n"
    return out


# ---------------------------------------------------------------------------
# The credential helper (git-credential-gateway)
# ---------------------------------------------------------------------------

_TRACE_OFF = ("0", "false", "no", "off")


def _proc_path(pid: int) -> str | None:
    """The executable path of a pid (macOS proc_pidpath, Linux /proc)."""
    if pid <= 0:
        return None
    if sys.platform == "darwin":
        try:
            lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            buf = ctypes.create_string_buffer(4096)
            n = lib.proc_pidpath(ctypes.c_int(pid), buf, ctypes.c_uint32(4096))
            return buf.value.decode() if n > 0 else None
        except (OSError, UnicodeDecodeError):
            return None
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None


def _parent_pid(pid: int) -> int | None:
    if pid <= 0:
        return None
    if sys.platform == "darwin":
        try:
            lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            buf = ctypes.create_string_buffer(640)
            n = lib.proc_pidinfo(ctypes.c_int(pid), ctypes.c_int(3), ctypes.c_uint64(0),
                                 buf, ctypes.c_int(640))
            if n >= 20:
                return struct.unpack_from("I", buf.raw, 16)[0]
            return None
        except OSError:
            return None
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read()
        rparen = data.rfind(b")")
        fields = data[rparen + 2:].split()
        return int(fields[1])            # ppid is field 4 (index 1 after comm)
    except (OSError, ValueError, IndexError):
        return None


def _exe_base(pid: int) -> str:
    p = _proc_path(pid)
    return os.path.basename(p) if p else ""


_GIT_REMOTES = ("git-remote-http", "git-remote-https")
# The shells git's SHELL_PATH (/bin/sh) can be: git runs a helper through
# `sh -c "<helper> <op>"` (its command has a space), and bash (macOS's
# /bin/sh) execs that one command, but dash (Debian's and Ubuntu's /bin/sh)
# forks it, so there the helper's parent is the shell.
_HELPER_SHELLS = ("sh", "dash", "bash", "ash", "busybox")


def _cmdline(pid: int) -> list[str] | None:
    """A process's argv (Linux /proc; None elsewhere or when unreadable)."""
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return None
    return [a.decode("utf-8", "surrogateescape") for a in raw.split(b"\0")[:-1]]


def _shell_ran_only_this_helper(pid: int, op: str) -> bool:
    """`pid` is git's shell running exactly this helper with this operation
    (`sh -c "<bin>/git-credential-gateway get"`, as git builds it), nothing
    else: a shell snippet that wraps the helper (a pipe, a function) is not."""
    from . import paths
    argv = _cmdline(pid)
    if not argv or len(argv) not in (3, 4) or argv[1] != "-c":
        return False
    want = f"{paths.bin_dir() / 'git-credential-gateway'} {op}"
    return argv[2] in (want, want + ' "$@"') and (len(argv) == 3 or argv[3] == argv[2])


def _parent_is_git_remote_http(op: str = "get") -> bool:
    """The helper answers only when run by git-remote-http(s) (directly, or
    through git's own `sh -c` running only this helper, where /bin/sh is dash),
    or by git-lfs's `git credential fill` (parent git whose parent is git-lfs)."""
    ppid = _parent_pid(os.getpid())
    if not ppid:
        return False
    parent = _exe_base(ppid)
    if parent in _GIT_REMOTES:
        return True
    if parent in _HELPER_SHELLS and _shell_ran_only_this_helper(ppid, op):
        gp = _parent_pid(ppid)
        return bool(gp) and _exe_base(gp) in _GIT_REMOTES
    if parent == "git":
        gp = _parent_pid(ppid)
        if gp and _exe_base(gp).startswith("git-lfs"):
            return True
    return False


def _http_ssl_verify_false(url: str) -> str | None:
    """Why certificate checking may be off for `url` (SPEC 9.4), or None.
    Asks git for http.sslVerify as it applies to this URL, so both the plain
    key and URL-scoped `http.<url>.sslVerify` (repo, global, -c, env) count.
    Fails closed: if git can't answer, the token isn't sent."""
    git = _find_git()
    if not git:
        return "gateway: couldn't check git's http.sslVerify setting, so the token isn't sent"
    try:
        r = subprocess.run([git, "config", "--type=bool", "--get-urlmatch", "http.sslVerify", url],
                           capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return "gateway: couldn't check git's http.sslVerify setting, so the token isn't sent"
    if r.returncode == 1 and not r.stdout.strip():
        return None                      # not set anywhere: git checks certificates
    if r.returncode != 0:
        return ("gateway: git couldn't read its http.sslVerify setting, so the token isn't sent; "
                "fix the git config")
    if r.stdout.strip() == "false":
        return ("gateway: http.sslVerify is false for this URL; the token won't be sent until "
                "certificate checking is on again")
    return None


def _find_git() -> str | None:
    from . import envfile, paths
    try:
        g = envfile.system_git()
        if g and os.access(g, os.X_OK):
            return g
    except Exception:  # noqa: BLE001
        pass
    try:
        return paths.tool("git")
    except Exception:  # noqa: BLE001
        return None


def _read_request() -> dict[str, str]:
    req: dict[str, str] = {}
    try:
        data = sys.stdin.buffer.read()
    except OSError:
        return req
    for line in data.decode("utf-8", "replace").splitlines():
        if line == "":
            break
        k, _, v = line.partition("=")
        if k:
            req[k] = v
    return req


def _refuse(host: str | None, reason: str, fix: str | None = None) -> int:
    """No credential: print one stderr line (git carries on unauthenticated)."""
    audit.refusal("git-credential", host, reason, fix)
    print(reason, file=sys.stderr)
    return 0


def credential_main(argv: list[str]) -> int:
    """git-credential-gateway get|store|erase (SPEC 9.4)."""
    op = argv[0] if argv else ""
    req = _read_request()
    host = req.get("host") or ""
    proto = (req.get("protocol") or "").lower()
    path = req.get("path") or ""
    from . import paths
    testing_active = _testing_active()

    if op == "store":
        return 0  # the gateway owns the token; nothing to store
    if op == "erase":
        return _erase(req)
    if op != "get":
        return 0

    # --- refusal gates (before any vault access) ---------------------------
    if not _parent_is_git_remote_http():
        return _refuse(host, "gateway: the git credential helper answers only git itself, not a "
                       "direct `git credential` call", "let git fetch/push/clone run normally")
    trace = os.environ.get("GIT_TRACE_REDACT")
    if trace is not None and trace.strip().lower() in _TRACE_OFF:
        return _refuse(host, "gateway: GIT_TRACE_REDACT is off, which would print the token; "
                       "unset it", "run the command without GIT_TRACE_REDACT=0")
    if proto == "http" and not (testing_active and _is_loopback(host)):
        return _refuse(host, "gateway: the git credential helper serves https only (an http "
                       "remote would send the token in the clear)")
    if proto not in ("https", "http"):
        return _refuse(host, f"gateway: {formmod.safe(proto) or 'that protocol'} is not https")
    if "GIT_SSL_NO_VERIFY" in os.environ:   # git checks presence: even an empty value counts
        return _refuse(host, "gateway: GIT_SSL_NO_VERIFY is set (the server's certificate wouldn't "
                       "be checked); unset it")
    if not host:
        return _refuse(host, "gateway: the credential request named no host")
    url_path = urllib.parse.quote(path.lstrip("/"), safe="/~@!$&'()*+,;=:%")
    ssl_off = _http_ssl_verify_false(f"{proto}://{host}/{url_path}")
    if ssl_off:
        return _refuse(host, ssl_off)

    # --- account selection ------------------------------------------------
    try:
        data = vault.load()
    except vault.VaultLocked as e:
        return _refuse(host, str(e))
    except vault.VaultError:
        return _refuse(host, "gateway: the vault can't be read, so no token was sent; tell the user "
                       "(gate status shows why)", "gate status")
    form = consent.load_form(data)
    eff = consent.compute(form, data)
    owner = acctmod.owner_from_path(path) if path else None
    # GATE_ACCOUNT (the env prefix the user set on the git command) is honoured.
    sel = acctmod.select(("github", "huggingface"), host, owner, form, effective=eff,
                         vault=data, env=os.environ)
    if sel.error:
        return _refuse(host, sel.error)
    if sel.account is None:
        return _refuse(host, acctmod.no_git_account(host))
    name = sel.account.name
    if not consent.bound_ok(data, name, host):
        return _refuse(host, f"gateway: {name}'s credential isn't bound to {formmod.safe(host) or host}; "
                       f"run gate check {name} while the user is here")
    rec = (data.get("accounts") or {}).get(name) or {}
    tok = rec.get("token") or {}
    if tok.get("stale"):
        return _refuse(host, acctmod.stale_token_message(name), f"gate check {name}")
    token = tok.get("value")
    if not token:
        return _refuse(host, f"gateway: {name} has no token; run gate check {name} while the "
                       "user is here")
    username = "x-access-token" if sel.account.kind == "github" else (sel.account.login or "token")
    audit.use("git-credential", host, name, argv=["get", host, path], secrets=[token])
    out = sys.stdout
    out.write(f"protocol={proto}\n")
    out.write(f"host={host}\n")
    out.write(f"username={username}\n")
    out.write(f"password={token}\n")
    out.flush()
    return 0


def _erase(req: dict[str, str]) -> int:
    """git erase after a 401: mark stale the token git was rejected with (one
    re-entry). git sends the whole credential it used: the account whose
    stored token equals the rejected password (among the github/huggingface
    accounts bound to that host) is the one; nothing else is touched, and a
    password that isn't one of the gateway's marks nothing. Without a
    password, the account `get` would choose for that request (owner from the
    path, GATE_ACCOUNT); never one picked by elimination."""
    host = req.get("host") or ""
    if not host:
        return 0
    password = req.get("password") or ""
    path = req.get("path") or ""
    try:
        with vault.edit() as data:
            names = _rejected_accounts(data, host, password, path)
            for name in names:
                if vault.mark_stale(data, name, "token"):
                    vault.add_event(data, "reject", f"{name} token rejected by {host}")
                    audit.log("reject", tool="git-credential", target=host, account=name)
    except vault.VaultError:
        pass
    return 0


def _rejected_accounts(data: dict, host: str, password: str, path: str) -> list[str]:
    form = consent.load_form(data)
    if password:
        pw = password.encode("utf-8", "surrogateescape")
        out = []
        for name, rec in sorted((data.get("accounts") or {}).items()):
            if not isinstance(rec, dict):
                continue
            kind = rec.get("kind") or getattr(form.accounts.get(name), "kind", None)
            if kind not in ("github", "huggingface"):
                continue
            tok = (rec.get("token") or {}).get("value")
            if not isinstance(tok, str) or not tok or not consent.bound_ok(data, name, host):
                continue
            if hmac.compare_digest(tok.encode("utf-8", "surrogateescape"), pw):
                out.append(name)
        return out
    eff = consent.compute(form, data)
    owner = acctmod.owner_from_path(path) if path else None
    s = acctmod.select(("github", "huggingface"), host, owner, form, effective=eff, vault=data,
                       env=os.environ)
    return [s.account.name] if s.account is not None and not s.error else []


def _testing_active() -> bool:
    from . import testing
    return testing.active() is not None
