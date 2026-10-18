"""The `gh` tool: GitHub's CLI as an account.

The plugin's own gh (pixi) runs with GH_TOKEN (or GH_ENTERPRISE_TOKEN) and
GH_HOST for the account and a throwaway GH_CONFIG_DIR, so the user's gh, its
keychain entries and ~/.config/gh are never involved. Subcommands that run
git or other programs, sign in, open a browser or print a token are
refused; `gh api` may only talk to the account's host. Each call is
classified read / write / delete for the account's prompt policy, like git.
"""
from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import Any

from . import gitops, policy, runner, vault

# gh commands that run git or other programs, manage gh's own auth/config,
# or open things: never through the gateway.
REFUSED_TOP = {"auth", "extension", "extensions", "ext", "alias", "codespace", "cs",
               "config", "completion", "browse", "copilot", "attestation"}
REFUSED_PAIRS = {("repo", "clone"), ("pr", "checkout"), ("pr", "co"), ("repo", "sync"),
                 ("gist", "clone"), ("run", "download"), ("release", "download")}
# repo create/fork are fine unless told to clone, push or add a local remote
# (that part runs git outside the gateway).
LOCAL_GIT_FLAGS = ("--clone", "-c", "--source", "-s", "--push", "--remote")
READ_VERBS = {"list", "ls", "view", "status", "diff", "checks", "search", "watch"}
DELETE_VERBS = {"delete", "archive", "unarchive", "rename", "lock", "transfer"}


def _api_method(args: list[str]) -> str:
    for i, a in enumerate(args):
        if a in ("-X", "--method") and i + 1 < len(args):
            return args[i + 1].upper()
        if a.startswith("--method="):
            return a.split("=", 1)[1].upper()
        if a.startswith("-X") and len(a) > 2:
            return a[2:].upper()
    if any(a in ("-f", "-F", "--field", "--raw-field", "--input") or
           a.startswith(("--field=", "--raw-field=", "--input=")) for a in args):
        return "POST"
    return "GET"


def classify(args: list[str]) -> str:
    top = args[0]
    if top == "api":
        m = _api_method(args[1:])
        return "read" if m in ("GET", "HEAD") else ("delete" if m == "DELETE" else "write")
    verb = args[1] if len(args) > 1 else ""
    if top == "search" or verb in READ_VERBS:
        return "read"
    if verb in DELETE_VERBS:
        return "delete"
    return "write"


def _check(args: list[str], acct: dict[str, Any]) -> None:
    if not args or args[0].startswith("-"):
        raise gitops.GitRefused("put the gh command first, e.g. [\"pr\", \"list\"]")
    top = args[0]
    if top in REFUSED_TOP or tuple(args[:2]) in REFUSED_PAIRS:
        raise gitops.GitRefused(
            f"'gh {' '.join(args[:2])}' is not run through the gateway (it runs git or other "
            "programs, or manages gh's own sign-in). Use the git tool for clones and "
            "checkouts, or gh api for the same data.")
    if tuple(args[:2]) in (("repo", "create"), ("repo", "fork")) and any(
            a.split("=", 1)[0] in LOCAL_GIT_FLAGS and not a.endswith("=false") for a in args[2:]):
        raise gitops.GitRefused(f"'gh {' '.join(args[:2])}' with clone/push/remote options runs "
                                "git outside the gateway; create it here, then use the git tool")
    if "--web" in args or "-w" in args:
        raise gitops.GitRefused("gh --web opens a browser; leave it out")
    if any(a in ("--hostname",) or a.startswith("--hostname=") for a in args):
        raise gitops.GitRefused("the account decides the host; leave --hostname out")
    if top == "api":
        hosts = acct.get("hosts", [])
        for a in args[1:]:
            if a.startswith(("http://", "https://")):
                host = policy.url_host(a)
                if not policy.host_allowed(host, hosts):
                    raise gitops.GitRefused(f"gh api may only call {', '.join(hosts)} as this "
                                            f"account, not {host}")


_OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*")


def owner_from_args(args: list[str]) -> str | None:
    """The repo owner a gh command names, if any: -R/--repo OWNER/REPO,
    `repo list|view|create OWNER[/REPO]`, `api repos|orgs|users/OWNER/...`."""
    for i, a in enumerate(args):
        val = None
        if a in ("-R", "--repo") and i + 1 < len(args):
            val = args[i + 1]
        elif a.startswith("--repo="):
            val = a.split("=", 1)[1]
        if val:
            o = val.split("/")[-2] if val.count("/") >= 1 else ""
            if _OWNER.fullmatch(o or ""):
                return o
    if len(args) >= 3 and args[0] == "repo" and args[1] in ("list", "view", "create", "edit",
                                                           "delete", "archive", "rename"):
        cand = args[2]
        if not cand.startswith("-"):
            o = cand.split("/")[0]
            if _OWNER.fullmatch(o):
                return o
    if len(args) >= 2 and args[0] == "api":
        for a in args[1:]:
            parts = a.lstrip("/").split("/")
            if len(parts) >= 2 and parts[0] in ("repos", "orgs", "users") \
                    and _OWNER.fullmatch(parts[1]):
                return parts[1]
    return None


def pick(account: str | None, cwd: str | None, data: dict[str, Any],
         args: list[str] | None = None) -> tuple[str, dict[str, Any]]:
    if account:
        a = data["accounts"].get(account)
        if a is None or a.get("kind") != "github":
            raise gitops.GitRefused(f"{account} is not a GitHub account; see account_list")
        return account, a
    if cwd:
        url = gitops._local(["remote", "get-url", "origin"], Path(cwd))
        remote = gitops.parse_remote(url) if url else None
        if remote:
            got = gitops.choose_account(remote, None, data)
            if got and got[1].get("kind") == "github":
                return got
    owner = owner_from_args(args or [])
    if owner:
        got = gitops.choose_account({"host": "github.com", "owner": owner}, None, data)
        if got and got[1].get("kind") == "github":
            return got
    gh = [(r, a) for r, a in sorted(data["accounts"].items()) if a.get("kind") == "github"]
    if len(gh) == 1:
        return gh[0]
    raise gitops.GitRefused("pass account= (one of: " + (", ".join(r for r, _ in gh) or
                            "none yet; ask the user to type /gate:add github") + ")")


def gh_tool(args: list[str], cwd: str | None = None, account: str | None = None,
            confirmed: bool = False, timeout: float = 300) -> dict[str, Any]:
    if not isinstance(args, list) or not args or not all(isinstance(a, str) for a in args):
        return {"ok": False, "reason": "args must be a non-empty list of strings, e.g. "
                                       "[\"pr\", \"list\"]"}
    try:
        gitops._check_paths(Path(cwd).expanduser() if cwd else Path(tempfile.gettempdir()),
                            args)
        data = vault.load()
        ref, acct = pick(account, cwd, data, args)
        _check(args, acct)
        token = acct.get("secrets", {}).get("token")
        if not token:
            raise gitops.GitRefused(f"{ref} has no token; ask the user to run "
                                    f"/gate:update {ref}")
        cls = classify(args)
        decision = vault.effective_prompts(acct, data)[cls]
        if decision == "refuse":
            return gitops._refuse(ref, cls, f"{ref} is set to refuse {cls} calls.")
        if decision == "ask" and not confirmed:
            out = gitops._refuse(ref, cls, f"{ref} asks before {cls} calls: run the same "
                                 "command with gh_confirm (Claude Code asks the user).")
            out["use"] = "gh_confirm"
            return out
    except (gitops.GitRefused, runner.RunnerError) as e:
        policy.audit("refused", {"action": "gh", "reason": str(e)[:200]})
        return {"ok": False, "refused": True, "reason": str(e)}
    host = acct.get("host", "github.com")
    enterprise = not (host == "github.com" or host.endswith(".ghe.com"))

    def env(tmp: Path) -> dict[str, str]:
        e = {"GH_HOST": host, "GH_CONFIG_DIR": str(tmp / "gh"), "GH_PROMPT_DISABLED": "1",
             "GH_NO_UPDATE_NOTIFIER": "1", "GH_NO_EXTENSION_UPDATE_NOTIFIER": "1",
             "GH_PAGER": "cat", "NO_COLOR": "1", "GH_BROWSER": "false", "BROWSER": "false",
             "GH_SPINNER_DISABLED": "1"}
        e["GH_ENTERPRISE_TOKEN" if enterprise else "GH_TOKEN"] = token
        return e

    try:
        res = runner.run_cli("gh", args, cwd=Path(cwd).expanduser() if cwd else None,
                             secrets=[token], env_fn=env, account=ref, timeout=timeout).as_dict()
    except runner.RunnerError as e:
        return {"ok": False, "reason": str(e)}
    res.update({"account": ref, "class": cls})
    if not res["ok"]:
        hint = gitops._hint(res.get("stderr", ""), ref)
        if hint:
            res["hint"] = hint
    return res
