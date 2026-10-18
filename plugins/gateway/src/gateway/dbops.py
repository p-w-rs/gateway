"""The `databricks` tool: the Databricks CLI as an azure account.

The CLI (pixi environment "databricks") runs with DATABRICKS_HOST = the
workspace (which must be one of the account's hosts), DATABRICKS_TOKEN = an
Entra access token for the Azure Databricks resource minted in the server,
DATABRICKS_AUTH_TYPE=pat so it uses only that, and DATABRICKS_CONFIG_FILE
pointing at an empty file so ~/.databrickscfg profiles are never read.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from . import entra, gitops, policy, runner, vault

REFUSED_TOP = {"auth", "configure", "completion", "sync"}
READ_VERBS = {"list", "get", "ls", "cat", "export", "export-dir", "describe", "status",
              "current-user", "me", "summary", "history", "logs"}
DELETE_VERBS = {"delete", "rm", "destroy", "purge", "remove", "delete-run", "cancel"}


def classify(args: list[str]) -> str:
    words = [a for a in args if not a.startswith("-")][:3]
    if words[:1] == ["api"]:
        m = words[1].upper() if len(words) > 1 else "GET"
        return "read" if m in ("GET", "HEAD") else ("delete" if m == "DELETE" else "write")
    if any(w in DELETE_VERBS for w in words[1:3]):
        return "delete"
    if any(w in READ_VERBS for w in words[1:3]):
        return "read"
    return "write"


def databricks_tool(args: list[str], account: str, workspace: str, cwd: str | None = None,
                    confirmed: bool = False, timeout: float = 600) -> dict[str, Any]:
    if not isinstance(args, list) or not args or not all(isinstance(a, str) for a in args):
        return {"ok": False, "reason": "args must be a non-empty list of strings, e.g. "
                                       "[\"clusters\", \"list\"]"}
    host = policy.url_host(workspace if "://" in (workspace or "") else f"https://{workspace}")
    try:
        data = vault.load()
        a = data["accounts"].get(account)
        if a is None or a.get("kind") != "azure":
            raise gitops.GitRefused(f"{account} is not an azure account; see account_list")
        if not host or not policy.host_allowed(host, a.get("hosts", [])):
            raise gitops.GitRefused(f"{account} may not be used for {host or 'that workspace'}; "
                                    f"ask the user to run /gate:update {account} {host}")
        if args[0] in REFUSED_TOP or args[0].startswith("-"):
            raise gitops.GitRefused(f"'databricks {args[0]}' is not run through the gateway "
                                    "(it manages sign-in, profiles or local sync)")
        if any(x in ("--profile", "-p", "--host") or x.startswith(("--profile=", "--host="))
               for x in args):
            raise gitops.GitRefused("the account and workspace decide the host and auth; leave "
                                    "--profile and --host out")
        if cwd:
            gitops._check_paths(Path(cwd).expanduser(), args)
        cls = classify(args)
        decision = vault.effective_prompts(a, data)[cls]
        if decision == "refuse":
            return gitops._refuse(account, cls, f"{account} is set to refuse {cls} calls.")
        if decision == "ask" and not confirmed:
            out = gitops._refuse(account, cls, f"{account} asks before {cls} calls: run the "
                                 "same command with databricks_confirm.")
            out["use"] = "databricks_confirm"
            return out
        token = entra.access_token(account, "databricks")
    except (gitops.GitRefused, runner.RunnerError, entra.EntraError) as e:
        policy.audit("refused", {"action": "databricks", "reason": str(e)[:200]})
        return {"ok": False, "refused": True, "reason": str(e)}

    def env(tmp: Path) -> dict[str, str]:
        cfg = tmp / "databrickscfg"
        cfg.write_text("")
        return {"DATABRICKS_HOST": f"https://{host}", "DATABRICKS_TOKEN": token,
                "DATABRICKS_AUTH_TYPE": "pat", "DATABRICKS_CONFIG_FILE": str(cfg),
                "HOME": str(tmp), "NO_COLOR": "1"}

    try:
        res = runner.run_cli("databricks", args, cwd=Path(cwd).expanduser() if cwd else None,
                             secrets=[token], env_fn=env, account=account,
                             timeout=timeout).as_dict()
    except runner.RunnerError as e:
        return {"ok": False, "reason": str(e)}
    res.update({"account": account, "class": cls, "workspace": host})
    return res
