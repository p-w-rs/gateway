"""The `registry` tool: container images as registry accounts, without a
Docker daemon.

crane (pixi environment "registry") runs with a throwaway DOCKER_CONFIG in
the call's private temp dir holding one credential for the account's
registry; the user's ~/.docker/config.json and credential helpers are never
used. Where the credential comes from:
- a token stored on the registry account (Docker Hub, Quay, ...);
- `via: github:NAME`: that GitHub account's login and token (ghcr.io; the gh
  sign-in asks for read:packages/write:packages);
- `via: azure:NAME`: an ARM token from that Entra sign-in, exchanged at the
  registry's /oauth2/exchange for an ACR refresh token (per call).
"""
from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from . import entra, gitops, policy, runner, vault

READ = {"pull", "manifest", "ls", "digest", "config", "catalog", "export", "validate", "blob"}
DELETE = {"delete"}
REFUSED = {"auth"}
ACR_USER = "00000000-0000-0000-0000-000000000000"


def classify(args: list[str]) -> str:
    sub = args[0]
    return "delete" if sub in DELETE else ("read" if sub in READ else "write")


def _acr_token(host: str, via: str, data: dict[str, Any]) -> str:
    a = data["accounts"].get(via)
    if a is None or a.get("kind") != "azure":
        raise gitops.GitRefused(f"{via} is not an azure account")
    arm = entra.access_token(via, "arm")
    scheme = "http" if host.split(":")[0] in ("127.0.0.1", "localhost") else "https"
    form = urllib.parse.urlencode({"grant_type": "access_token", "service": host.split(":")[0],
                                   "tenant": a.get("tenant_id") or a.get("tenant", ""),
                                   "access_token": arm}).encode()
    try:
        with urllib.request.urlopen(urllib.request.Request(
                f"{scheme}://{host}/oauth2/exchange", data=form,
                headers={"Content-Type": "application/x-www-form-urlencoded"}), timeout=30) as r:
            return json.loads(r.read().decode())["refresh_token"]
    except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
        raise gitops.GitRefused(f"the registry's token exchange failed: {e}") from None


def credential(ref: str, acct: dict[str, Any], data: dict[str, Any]) -> tuple[str, str]:
    via = acct.get("via", "")
    host = acct.get("host", "")
    if via.startswith("github:"):
        g = data["accounts"].get(via)
        if g is None or not g.get("secrets", {}).get("token"):
            raise gitops.GitRefused(f"{via} has no token; ask the user to run /gate:account login {via}")
        return g.get("login") or "x-access-token", g["secrets"]["token"]
    if via.startswith("azure:"):
        return ACR_USER, _acr_token(host, via, data)
    tok = acct.get("secrets", {}).get("token")
    if not tok:
        raise gitops.GitRefused(f"{ref} has no token and no via account; ask the user to run "
                                f"/gate:account up {ref}")
    return acct.get("login") or "user", tok


def registry_tool(args: list[str], account: str, confirmed: bool = False,
                  timeout: float = 1800) -> dict[str, Any]:
    if not isinstance(args, list) or not args or not all(isinstance(a, str) for a in args):
        return {"ok": False, "reason": "args must be a non-empty list of strings, e.g. "
                                       "[\"ls\", \"ghcr.io/org/image\"]"}
    try:
        data = vault.load()
        acct = data["accounts"].get(account)
        if acct is None or acct.get("kind") != "registry":
            raise gitops.GitRefused(f"{account} is not a registry account; see account_list")
        if args[0] in REFUSED or args[0].startswith("-"):
            raise gitops.GitRefused("registry sign-in is the gateway's; 'crane auth' isn't run here")
        host = acct.get("host", "")
        owners = [o.lower() for o in acct.get("owners", [])]
        for a in args[1:]:
            if a.startswith(f"{host}/"):
                owner = a[len(host) + 1:].split("/", 1)[0].lower()
                if owners and owner not in owners:
                    raise gitops.GitRefused(f"{account} is not for {host}/{owner}; ask the user to "
                                            f"run /gate:account allow {account} {owner}")
        cls = classify(args)
        decision = vault.effective_prompts(acct, data)[cls]
        if decision == "refuse":
            return gitops._refuse(account, cls, f"{account} is set to refuse {cls} calls.")
        if decision == "ask" and not confirmed:
            out = gitops._refuse(account, cls, f"{account} asks before {cls} calls: run the "
                                 "same command with registry_confirm.")
            out["use"] = "registry_confirm"
            return out
        user, secret = credential(account, acct, data)
    except (gitops.GitRefused, runner.RunnerError, entra.EntraError) as e:
        policy.audit("refused", {"action": "registry", "reason": str(e)[:200]})
        return {"ok": False, "refused": True, "reason": str(e)}
    auth = base64.b64encode(f"{user}:{secret}".encode()).decode()

    def env(tmp: Path) -> dict[str, str]:
        d = tmp / "docker"
        d.mkdir()
        (d / "config.json").write_text(json.dumps({"auths": {host: {"auth": auth}}}))
        (d / "config.json").chmod(0o600)
        return {"DOCKER_CONFIG": str(d), "HOME": str(tmp)}

    try:
        res = runner.run_cli("crane", args, cwd=None, secrets=[secret, auth], env_fn=env,
                             account=account, timeout=timeout).as_dict()
    except runner.RunnerError as e:
        return {"ok": False, "reason": str(e)}
    res.update({"account": account, "class": cls, "registry": host})
    return res
