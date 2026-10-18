"""The `hf` tool: the Hugging Face CLI as an account.

The plugin's `hf` (pixi environment "hf": huggingface_hub + hf_xet) runs
with HF_TOKEN for the account and HF_ENDPOINT pinned to its host. Its token
file and stored tokens point into the call's temp dir, so the user's own
`hf auth login` state is never read or written. Downloads still land in the
user's normal Hugging Face cache (HF_HUB_CACHE), so models aren't fetched
twice. Xet uploads happen inside the hf process: the Hub gives it a
short-lived, per-repo Xet token for the CAS servers, so the account's token
itself only goes to the Hub.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from . import gitops, policy, runner, vault

REFUSED_TOP = {"auth", "login", "logout", "env"}
READ_VERBS = {"download", "ls", "list", "info", "search", "scan", "whoami", "ls-tree",
              "files", "tree", "show", "inspect", "logs", "ps", "status"}
DELETE_VERBS = {"delete", "rm", "remove", "delete-files", "prune", "cancel", "move"}


def classify(args: list[str]) -> str:
    words = [a for a in args if not a.startswith("-")][:3]
    if any(a == "--delete" or a.startswith("--delete=") for a in args):
        return "delete"
    if any(w in DELETE_VERBS for w in words[:2]):
        return "delete"
    if any(w in READ_VERBS for w in words[:2]) or words[:1] == ["cache"]:
        return "read"
    return "write"


def _repo_owner(args: list[str]) -> str:
    """The namespace of the first owner/name argument, if any."""
    for a in args[1:]:
        if not a.startswith("-") and "/" in a and "://" not in a and not a.startswith((".", "/", "~")):
            return a.split("/", 1)[0]
    return ""


def pick(account: str | None, args: list[str], data: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    hfs = [(r, a) for r, a in sorted(data["accounts"].items()) if a.get("kind") == "hf"]
    if account:
        a = data["accounts"].get(account)
        if a is None or a.get("kind") != "hf":
            raise gitops.GitRefused(f"{account} is not a Hugging Face account; see account_list")
        owner = _repo_owner(args)
        owners = [o.lower() for o in a.get("owners", [])]
        if owner and owners and owner.lower() not in owners:
            raise gitops.GitRefused(f"{account} is not for {owner}. If it should be, ask the user "
                                    f"to run: /gate:update {account} {owner}")
        return account, a
    owner = _repo_owner(args)
    if owner and hfs:
        host = hfs[0][1].get("host", "huggingface.co")
        got = gitops.choose_account({"host": host, "owner": owner}, None, data)
        if got and got[1].get("kind") == "hf":
            return got
    if len(hfs) == 1:
        return hfs[0]
    raise gitops.GitRefused("pass account= (one of: " + (", ".join(r for r, _ in hfs) or
                            "none yet; ask the user to type /gate:add hf") + ")")


def hf_tool(args: list[str], cwd: str | None = None, account: str | None = None,
            confirmed: bool = False, timeout: float = 1800) -> dict[str, Any]:
    if not isinstance(args, list) or not args or not all(isinstance(a, str) for a in args):
        return {"ok": False, "reason": "args must be a non-empty list of strings, e.g. "
                                       "[\"download\", \"org/model\"]"}
    import tempfile
    try:
        gitops._check_paths(Path(cwd).expanduser() if cwd else Path(tempfile.gettempdir()), args)
        if args[0].startswith("-") or args[0] in REFUSED_TOP or args[:2] == ["auth", "token"]:
            if args[:2] != ["auth", "whoami"]:
                raise gitops.GitRefused("the gateway manages Hugging Face sign-in; 'hf auth' (except "
                                        "whoami), login, logout and env are not run here")
        if any(a in ("--token",) or a.startswith(("--token=", "--endpoint")) for a in args):
            raise gitops.GitRefused("the account decides the token and endpoint; leave --token "
                                    "and --endpoint out")
        data = vault.load()
        ref, acct = pick(account, args, data)
        token = acct.get("secrets", {}).get("token")
        if not token:
            raise gitops.GitRefused(f"{ref} has no token; ask the user to run /gate:update {ref}")
        cls = classify(args)
        decision = vault.effective_prompts(acct, data)[cls]
        if decision == "refuse":
            return gitops._refuse(ref, cls, f"{ref} is set to refuse {cls} calls.")
        if decision == "ask" and not confirmed:
            out = gitops._refuse(ref, cls, f"{ref} asks before {cls} calls: run the same "
                                 "command with hf_confirm (Claude Code asks the user).")
            out["use"] = "hf_confirm"
            return out
    except (gitops.GitRefused, runner.RunnerError) as e:
        policy.audit("refused", {"action": "hf", "reason": str(e)[:200]})
        return {"ok": False, "refused": True, "reason": str(e)}
    host = acct.get("host") or "huggingface.co"
    cache = os.environ.get("HF_HUB_CACHE") or str(
        Path(os.environ.get("HF_HOME") or Path.home() / ".cache" / "huggingface") / "hub")

    def env(tmp: Path) -> dict[str, str]:
        return {"HF_TOKEN": token, "HF_ENDPOINT": f"https://{host}",
                "HF_HOME": str(tmp / "hf"), "HF_TOKEN_PATH": str(tmp / "hf" / "token"),
                "HF_STORED_TOKENS_PATH": str(tmp / "hf" / "stored_tokens"),
                "HF_HUB_CACHE": cache, "HF_HUB_DISABLE_TELEMETRY": "1",
                "HF_HUB_DISABLE_PROGRESS_BARS": "1", "HF_HUB_DISABLE_UPDATE_CHECK": "1",
                "NO_COLOR": "1"}

    try:
        res = runner.run_cli("hf", args, cwd=Path(cwd).expanduser() if cwd else None,
                             secrets=[token], env_fn=env, account=ref, timeout=timeout).as_dict()
    except runner.RunnerError as e:
        return {"ok": False, "reason": str(e)}
    res.update({"account": ref, "class": cls})
    return res
