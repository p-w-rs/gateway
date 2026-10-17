"""The `git` and `git_identity` tools: all of git, as the right account.

Every git command Claude runs comes here (the Bash redirect follows in a
later phase). Local commands run through the hardened runner with no
credentials. Commands that talk to a remote:

1. find the remote's real URL (after insteadOf/pushurl, as git would);
2. pick the account whose scope covers that host and owner (or check the
   one Claude named);
3. classify the call as read, write or delete and apply that account's
   prompt policy: `auto` runs, `ask` refuses here and points at
   git_confirm (whose settings.json rule is `ask`, so Claude Code asks the
   user), `refuse` refuses both;
4. run it with the account's token (https) or SSH key (ssh).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from . import policy, runner, vault

GIT_KINDS = ("github", "hf", "ssh")
LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}

# Options that take a value as the next word (so it isn't the remote/URL).
VALUE_OPTS = {"-b", "--branch", "--depth", "--origin", "-o", "--reference",
              "--reference-if-able", "--shallow-since", "--shallow-exclude", "--filter",
              "-j", "--jobs", "--push-option", "--server-option", "--deepen",
              "--negotiation-tip", "--refmap", "--recurse-submodules-default",
              "--repo", "--sort"}

# git config keys that steer credentials, ssh, hooks or where git talks to.
FORBIDDEN_CONFIG = re.compile(
    r"^(credential\.|core\.(sshcommand|hookspath|fsmonitor|askpass|gitproxy|editor|pager)$|"
    r"url\..*\.(insteadof|pushinsteadof)$|remote\..*\.(uploadpack|receivepack|proxy)$|"
    r"http\..*|https\..*|include\.|includeif\.|alias\.|filter\.|diff\..*\.(textconv|command)$|"
    r"merge\..*\.driver$|gpg\.|sequence\.editor$|core\.alternaterefscommand$|uploadpack\.)",
    re.I)
CONFIG_READ_FLAGS = {"--get", "--get-all", "--get-regexp", "--get-urlmatch", "-l", "--list",
                     "--show-origin", "--show-scope", "--name-only", "get", "list"}


class GitRefused(Exception):
    pass


# ---------------------------------------------------------------------------
# Remote URLs
# ---------------------------------------------------------------------------

_SCP = re.compile(r"^(?:(?P<user>[^@/:]+)@)?(?P<host>[^/:\[\]]+|\[[^\]]+\]):(?!//)(?P<path>.+)$")
_URL = re.compile(r"^(?P<scheme>https?|ssh|git\+ssh|ssh\+git)://(?:(?P<userinfo>[^@/]*)@)?"
                  r"(?P<host>\[[^\]]+\]|[^/:]+)(?::(?P<port>\d+))?(?P<path>/.*)?$", re.I)


def parse_remote(url: str) -> dict[str, Any] | None:
    """{scheme: https|http|ssh, host, port, owner, repo, cred_host} for a
    network URL, None for a local path or file:// URL."""
    url = url.strip()
    if not url or url.startswith(("file://", "/", "./", "../", "~")):
        return None
    m = _URL.match(url)
    if m:
        scheme = m.group("scheme").lower()
        scheme = "ssh" if "ssh" in scheme else scheme
        if m.group("userinfo") and ":" in m.group("userinfo") and scheme != "ssh":
            raise GitRefused("the remote URL has a password in it; use an account instead "
                             "of credentials in URLs")
        host, port, path = m.group("host").lower(), m.group("port"), m.group("path") or "/"
    else:
        m = _SCP.match(url)
        if not m or Path(url).exists():
            return None
        scheme, host, port, path = "ssh", m.group("host").lower(), None, "/" + m.group("path")
    parts = [p for p in path.split("/") if p]
    owner = parts[0] if parts else ""
    repo = re.sub(r"\.git$", "", parts[1]) if len(parts) > 1 else ""
    cred_host = f"{host}:{port}" if port else host
    return {"scheme": scheme, "host": host, "port": port, "owner": owner, "repo": repo,
            "cred_host": cred_host}


def _positionals(args: list[str]) -> list[str]:
    out, skip = [], False
    for a in args:
        if skip:
            skip = False
            continue
        if a == "--":
            continue
        if a.startswith("-"):
            if a in VALUE_OPTS:
                skip = True
            continue
        out.append(a)
    return out


def _local(argv: list[str], cwd: Path) -> str:
    r = runner.run("git", argv, cwd=cwd, timeout=30)
    return r.stdout.strip() if r.ok else ""


def remote_url(sub: str, args: list[str], cwd: Path) -> str | None:
    """The URL a remote command will talk to, as git resolves it."""
    pos = _positionals(args)
    if sub == "clone":
        return pos[0] if pos else None
    if sub == "archive":
        for a in args:
            if a.startswith("--remote="):
                return a.split("=", 1)[1]
        return None
    if sub == "lfs":
        pos = pos[1:]  # lfs push|pull|fetch [remote]
    if sub in ("fetch", "pull") and ("--all" in args or "--multiple" in args):
        raise GitRefused("fetch one remote at a time, so each uses its own account")
    if sub in ("remote", "submodule"):
        return None  # remote update/show and submodule update run without an account
    name = pos[0] if pos else ""
    if not name:
        upstream = _local(["rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}"], cwd)
        name = upstream.split("/", 1)[0] if "/" in upstream else "origin"
    remotes = _local(["remote"], cwd).split()
    if name in remotes:
        if sub == "push":
            urls = set(_local(["remote", "get-url", "--push", "--all", name], cwd).split())
            if len(urls) > 1:
                raise GitRefused(f"remote {name} pushes to several URLs; push to each one by "
                                 "URL so each uses its own account")
            return urls.pop() if urls else None
        return _local(["remote", "get-url", name], cwd) or None
    return _local(["ls-remote", "--get-url", name], cwd) or name


# ---------------------------------------------------------------------------
# Accounts and classes
# ---------------------------------------------------------------------------


def choose_account(remote: dict[str, Any], explicit: str | None,
                   data: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    host, owner = remote["host"], remote["owner"].lower()

    def in_scope(a: dict[str, Any]) -> bool:
        return a.get("kind") in GIT_KINDS and policy.host_allowed(host, a.get("hosts", []))

    def owner_ok(a: dict[str, Any]) -> bool:
        owners = [o.lower() for o in a.get("owners", [])]
        return not owners or owner in owners

    if explicit:
        a = data["accounts"].get(explicit)
        if a is None:
            raise GitRefused(f"no account named {explicit}; see account_list")
        if not (in_scope(a) and owner_ok(a)):
            raise GitRefused(
                f"{explicit} is not for {host}/{remote['owner']}. If it should be, ask the "
                f"user to run: /gate:account allow {explicit} "
                f"{remote['owner'] if in_scope(a) else host}")
        return explicit, a
    cands = [(r, a) for r, a in sorted(data["accounts"].items()) if in_scope(a) and owner_ok(a)]
    specific = [(r, a) for r, a in cands if a.get("owners")]
    pick = specific or cands
    if len(pick) > 1:
        raise GitRefused(f"several accounts fit {host}/{remote['owner']}: "
                         + ", ".join(r for r, _ in pick) + "; pass account= to pick one")
    return pick[0] if pick else None


def classify(sub: str, args: list[str]) -> str:
    """local | read | write | delete | force"""
    if sub not in runner.GIT_REMOTE:
        return "local"
    if sub == "push":
        refs = _positionals(args)[1:]
        if any(a in ("-f", "--force") for a in args) or any(r.startswith("+") for r in refs):
            return "force"
        if any(a in ("-d", "--delete", "--mirror", "--prune") or a.startswith(("--force-with-lease",
               "--force-if-includes", "--mirror")) for a in args) \
                or any(r.startswith(":") for r in refs):
            return "delete"
        return "write"
    if sub == "lfs":
        return "write" if _positionals(args)[:1] == ["push"] else "read"
    return "read"


def _check_paths(cwd: Path, args: list[str]) -> None:
    """Nothing may point into the vault (git diff --no-index, show, ... read files)."""
    home = vault.home().resolve()

    def inside(p: Path) -> bool:
        try:
            return p.resolve() == home or home in p.resolve().parents
        except OSError:
            return False

    if inside(cwd):
        raise GitRefused("git can't run inside the gateway vault")
    for a in args:
        val = a.split("=", 1)[1] if a.startswith("-") and "=" in a else a
        if str(home) in val or ".config/gateway" in val or inside(cwd / val):
            raise GitRefused("git can't read or write the gateway vault")


def _check_config(sub: str, args: list[str]) -> None:
    if sub != "config":
        return
    if any(a in CONFIG_READ_FLAGS for a in args):
        return
    keys = [a for a in args if not a.startswith("-")]
    if keys and keys[0] in ("set", "unset", "rename-section", "remove-section", "edit"):
        keys = keys[1:]
    if keys and FORBIDDEN_CONFIG.match(keys[0]):
        raise GitRefused(f"git config {keys[0]} is managed by the gateway (it steers "
                         "credentials, ssh or what git runs) and can't be set here")
    if "--edit" in args or "-e" in args:
        raise GitRefused("git config --edit opens an editor; set keys one at a time")


def _hint(stderr: str, ref: str | None) -> str:
    low = stderr.lower()
    if "saml" in low or "sso" in low:
        return (f"The organization requires SSO for this token. Ask the user to run "
                f"/gate:account login {ref or 'github:NAME'} (SSO sign-in) and retry.")
    if "editor" in low and "problem" in low:
        return "git wanted an editor; pass the message or option instead (e.g. -m)."
    if ("authentication failed" in low or "could not read username" in low
            or "permission denied (publickey)" in low):
        return (f"The remote refused {ref or 'the call (no account matched)'}. Check the "
                "account has access, or ask the user to add or update it with /gate:account.")
    return ""


def git_tool(args: list[str], cwd: str, account: str | None = None,
             confirmed: bool = False, timeout: float = 300) -> dict[str, Any]:
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args) or not args:
        return {"ok": False, "reason": "args must be a non-empty list of strings, e.g. "
                                       "[\"status\", \"--short\"]"}
    cwdp = Path(cwd).expanduser()
    if not cwdp.is_absolute():
        return {"ok": False, "reason": "cwd must be an absolute path"}
    try:
        sub = runner.check_git_argv(args)
        _check_paths(cwdp, args)
        _check_config(sub, args[1:])
        cls = classify(sub, args[1:])
        if cls == "force":
            raise GitRefused("plain force pushes are refused; use --force-with-lease through "
                             "git_confirm if the user wants to overwrite the remote")
        ref, creds, remote = None, None, None
        allow_http = False
        if cls != "local":
            data = vault.load()
            url = remote_url(sub, args[1:], cwdp)
            remote = parse_remote(url) if url else None
            picked = choose_account(remote, account, data) if remote else None
            if account and not remote:
                raise GitRefused(f"{url or 'that remote'} is local; no account is used")
            if picked:
                ref, acct = picked
                decision = vault.effective_prompts(acct, data)["write" if cls == "write"
                                                                else cls]
                if decision == "refuse":
                    return _refuse(ref, cls, f"{ref} is set to refuse {cls} calls "
                                   f"(/gate:account prompts {ref} {cls}=ask|auto to change).")
                if decision == "ask" and not confirmed:
                    return _refuse(ref, cls, f"{ref} asks before {cls} calls: run the same "
                                   "command with git_confirm (Claude Code asks the user).",
                                   needs_confirm=True)
                creds = _creds(ref, acct, remote)
            allow_http = bool(remote) and remote["scheme"] == "http" and remote["host"] in LOOPBACK
            if remote and remote["scheme"] == "http" and not allow_http:
                raise GitRefused("plain http remotes are refused (credentials would travel "
                                 "unencrypted); use https")
    except (GitRefused, runner.RunnerError) as e:
        policy.audit("refused", {"action": "git", "reason": str(e)[:200]})
        return {"ok": False, "refused": True, "reason": str(e)}
    res = runner.run("git", args, cwd=cwdp, creds=creds, account=ref or "", timeout=timeout,
                     allow_http=allow_http).as_dict()
    res["class"] = cls
    if remote:
        res["remote"] = f"{remote['host']}/{remote['owner']}/{remote['repo']}".rstrip("/")
        res["account"] = ref or "none (no account matched; ran without credentials)"
    hint = _hint(res.get("stderr", ""), ref) if not res["ok"] else ""
    if hint:
        res["hint"] = hint
    if res.get("seen_host_keys"):
        res["note"] = ("New SSH host key accepted for this call only (not pinned): "
                       + "; ".join(k.split(" ", 1)[1][:80] for k in res["seen_host_keys"]))
        res.pop("seen_host_keys")
    return res


def _refuse(ref: str, cls: str, reason: str, needs_confirm: bool = False) -> dict[str, Any]:
    policy.audit("refused", {"action": "git", "account": ref, "class": cls, "reason": reason})
    out = {"ok": False, "refused": True, "reason": reason, "account": ref, "class": cls}
    if needs_confirm:
        out["use"] = "git_confirm"
    return out


def _creds(ref: str, acct: dict[str, Any], remote: dict[str, Any]) -> runner.Creds:
    secrets = acct.get("secrets", {})
    if remote["scheme"] in ("https", "http"):
        if not secrets.get("token"):
            raise GitRefused(f"{ref} has no token for https; ask the user to run "
                             f"/gate:account login {ref} or /gate:account up {ref}, or use "
                             "the ssh URL if it has an SSH key")
        return runner.Creds(host=remote["cred_host"], token=secrets["token"],
                            username="x-access-token" if acct["kind"] == "github"
                            else (acct.get("login") or "user"),
                            protocols=(remote["scheme"],))
    if not secrets.get("ssh_key"):
        raise GitRefused(f"{ref} has no SSH key; use the https URL, or ask the user to add "
                         f"one with /gate:account up {ref}")
    return runner.Creds(host=remote["cred_host"], ssh_key=secrets["ssh_key"],
                        public_key=acct.get("public_key", ""),
                        known_hosts=acct.get("known_hosts", ""))


def git_identity(cwd: str, account: str) -> dict[str, Any]:
    """Commit as an account in this repo: user.name/user.email in the repo's
    own config, plus gateway.account to remember the binding. No secrets."""
    cwdp = Path(cwd).expanduser()
    data = vault.load()
    a = data["accounts"].get(account)
    if a is None:
        return {"ok": False, "reason": f"no account named {account}; see account_list"}
    if not (a.get("name") or a.get("email")):
        return {"ok": False, "reason": f"{account} has no commit name or email; ask the user "
                                       f"to set them with /gate:account up {account}"}
    try:
        _check_paths(cwdp, [])
    except GitRefused as e:
        return {"ok": False, "refused": True, "reason": str(e)}
    done = {}
    for key, val in (("user.name", a.get("name")), ("user.email", a.get("email")),
                     ("gateway.account", account)):
        if val:
            r = runner.run("git", ["config", "--local", key, val], cwd=cwdp, timeout=30)
            if not r.ok:
                return {"ok": False, "reason": r.stderr.strip() or "git config failed"}
            done[key] = val
    policy.audit("git_identity", {"account": account, "cwd": str(cwdp)})
    return {"ok": True, "set": done}
