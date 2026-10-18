"""The ASI ML Catalog (github.com/asirobots/asi-ai-ml-version-control) as
mlcat accounts.

Sign-in: the catalog publishes its Entra tenant, API app and CLI app at
GET /api/config. /gate:update mlcat:NAME signs in with the CLI app
(entra.py), and the API token is minted for api://<API app>/access_as_user.

Tools:
- mlcat: read the catalog (search, an item, its files) over its API.
- mlcat_workspace (+ _confirm): what `asiml` does, natively, in the same
  workspace format (.asiml/workspace.json), so asiml itself keeps working
  on these folders. init/status are local; clone/pull ask the catalog for a
  one-hour, role-limited storage pass (POST /api/transfers/pull), push for a
  write pass (/push) and then registers the revision (/complete). dvc (pixi
  environment "dvc") gets the pass only in its env (AZURE_STORAGE_ACCOUNT,
  AZURE_STORAGE_SAS_TOKEN), with isolated DVC and Azure config dirs; the
  pass is scrubbed from all output.
"""
from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from . import entra, gitops, policy, runner, vault

_CONFIG: dict[str, dict[str, Any]] = {}
FOLDER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")
REV_RE = re.compile(r"^[0-9a-f]{8,32}$")
SAS_QUERY = re.compile(r"(?i)([?&](?:sig|sv|sp|se|st|skoid|sktid|skt|ske|sks|skv|sr|spr)=)[^\s'\"&]+")


class CatalogError(Exception):
    pass


def base_url(host: str) -> str:
    h = host.split(":", 1)[0]
    return f"{'http' if h in ('127.0.0.1', 'localhost') else 'https'}://{host}"


def catalog_config(host: str) -> dict[str, Any]:
    if host not in _CONFIG:
        try:
            with urllib.request.urlopen(base_url(host) + "/api/config", timeout=30) as r:
                cfg = json.loads(r.read().decode())
        except (urllib.error.URLError, OSError, ValueError) as e:
            raise CatalogError(f"could not read the catalog's sign-in configuration: {e}")
        for k in ("tenantId", "clientId", "cliClientId"):
            if not vault.GUID_RE.fullmatch(str(cfg.get(k) or "")):
                raise CatalogError(f"the catalog's /api/config has no valid {k}")
        _CONFIG[host] = cfg
    return _CONFIG[host]


def api_scope(cfg: dict[str, Any]) -> str:
    return f"api://{cfg['clientId']}/access_as_user"


def api_token(ref: str, acct: dict[str, Any]) -> str:
    return entra.access_token(ref, api_scope(catalog_config(acct["host"])))


def _account(account: str | None, data: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    cats = [(r, a) for r, a in sorted(data["accounts"].items()) if a.get("kind") == "mlcat"]
    if account:
        a = data["accounts"].get(account)
        if a is None or a.get("kind") != "mlcat":
            raise gitops.GitRefused(f"{account} is not an ML Catalog account; see account_list")
        return account, a
    if len(cats) == 1:
        return cats[0]
    raise gitops.GitRefused("pass account= (one of: " + (", ".join(r for r, _ in cats) or
                            "none yet; ask the user to type /gate:add catalog") + ")")


def _api(ref: str, acct: dict[str, Any], method: str, path: str,
         body: dict[str, Any] | None = None) -> Any:
    token = api_token(ref, acct)
    req = urllib.request.Request(base_url(acct["host"]) + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}",
                                          "Accept": "application/json",
                                          **({"Content-Type": "application/json"} if body is not None else {})})
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            raw = r.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = {401: "the sign-in was rejected; ask the user to run /gate:update " + ref,
                  403: "the user's catalog role does not allow this (publishing needs "
                       "Catalog.Writer)"}.get(e.code)
        if detail is None:
            try:
                detail = SAS_QUERY.sub(r"\1[redacted]", json.loads(e.read().decode()).get("error", ""))
            except Exception:
                detail = f"HTTP {e.code}"
        raise CatalogError(f"catalog: {detail}") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise CatalogError(f"could not reach the catalog: {e}") from None


# ---------------------------------------------------------------------------
# mlcat: read the catalog
# ---------------------------------------------------------------------------


def mlcat_tool(action: str, account: str | None = None, kind: str = "", name: str = "",
               version: str = "", query: str = "", page: int = 1, page_size: int = 30,
               prefix: str = "", skip: int = 0, take: int = 200) -> dict[str, Any]:
    try:
        ref, acct = _account(account, vault.load())
        if action == "search":
            q = {"kind": kind or "all", "sort": "recent", "page": page, "pageSize": page_size}
            if query:
                q["q"] = query
            out = _api(ref, acct, "GET", "/api/catalog?" + urllib.parse.urlencode(q))
        elif action == "item":
            if kind not in ("dataset", "model") or not FOLDER_RE.match(name or ""):
                raise gitops.GitRefused("item needs kind=dataset|model and name")
            out = _api(ref, acct, "GET", f"/api/items/{kind}/{urllib.parse.quote(name)}"
                       + (f"?v={version}" if version else ""))
            if isinstance(out, dict):
                out.pop("readmeHtml", None)  # the markdown readme is there too
        elif action == "files":
            if not REV_RE.match(version or ""):
                raise gitops.GitRefused("files needs version= (the revision hash)")
            out = _api(ref, acct, "GET", f"/api/versions/{version}/files?" + urllib.parse.urlencode(
                {"prefix": prefix, "skip": skip, "take": min(take, 1000)}))
        else:
            raise gitops.GitRefused("action is search, item or files")
    except (gitops.GitRefused, CatalogError, entra.EntraError) as e:
        return {"ok": False, "reason": str(e)}
    policy.audit("mlcat", {"account": ref, "action": action, "kind": kind, "name": name})
    return {"ok": True, "account": ref, "result": out}


# ---------------------------------------------------------------------------
# mlcat_workspace: asiml's init / clone / pull / push / status
# ---------------------------------------------------------------------------


def _parse_artifact(value: str) -> tuple[str, str, str | None]:
    path, _, rev = value.partition("@")
    parts = path.split("/")
    if len(parts) != 2 or parts[0] not in ("datasets", "models") or not FOLDER_RE.match(parts[1]):
        raise gitops.GitRefused("use datasets/NAME[@revision] or models/NAME[@revision]")
    if rev and not REV_RE.match(rev):
        raise gitops.GitRefused("a revision is 8-32 lowercase hex characters")
    return ("dataset" if parts[0] == "datasets" else "model"), parts[1], rev or None


def _state_path(root: Path) -> Path:
    return root / ".asiml" / "workspace.json"


def _read_state(root: Path) -> dict[str, Any]:
    try:
        st = json.loads(_state_path(root).read_text())
    except (OSError, ValueError):
        raise gitops.GitRefused("this is not an asiml workspace (no .asiml/workspace.json); "
                                "use init or clone first")
    _parse_artifact(st.get("artifactId", ""))
    if not FOLDER_RE.match(st.get("payload", "")):
        raise gitops.GitRefused("the workspace's payload must be a simple folder name")
    return st


def _write_state(root: Path, st: dict[str, Any]) -> None:
    p = _state_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(st, indent=2))
    os.replace(tmp, p)


def _site_cache() -> str:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
    else:
        base = Path.home() / ".local" / "share"
    return str(base / "ASI" / "asiml" / "site-cache")


def _dvc(root: Path, args: list[str], access: dict[str, Any] | None, ref: str,
         timeout: float) -> runner.Result:
    sas = (access or {}).get("sasToken", "")

    def env(tmp: Path) -> dict[str, str]:
        e = {"DVC_NO_ANALYTICS": "1", "DVC_SITE_CACHE_DIR": _site_cache(),
             "DVC_GLOBAL_CONFIG_DIR": str(tmp / "dvc-global"),
             "DVC_SYSTEM_CONFIG_DIR": str(tmp / "dvc-system"),
             "AZURE_CONFIG_DIR": str(tmp / "azure"), "HOME": os.environ.get("HOME", str(tmp))}
        if access:
            e["AZURE_STORAGE_ACCOUNT"] = access.get("account", "")
            e["AZURE_STORAGE_SAS_TOKEN"] = sas
        return e

    res = runner.run_cli("dvc", args, cwd=root, secrets=[sas] if sas else [], env_fn=env,
                         account=ref, timeout=timeout)
    res.stdout, res.stderr = SAS_QUERY.sub(r"\1[redacted]", res.stdout), SAS_QUERY.sub(r"\1[redacted]", res.stderr)
    return res


def _must(res: runner.Result, what: str) -> None:
    if not res.ok:
        raise CatalogError(f"dvc {what} failed: {res.stderr.strip()[-500:] or res.stdout.strip()[-500:]}")


def _in_git(root: Path) -> bool:
    return any((p / ".git").exists() for p in [root, *root.parents])


def _init(root: Path, kind: str, folder: str, host: str, payload: str, ref: str) -> None:
    if _state_path(root).exists() or (root / ".dvc").exists():
        raise gitops.GitRefused("this directory already has an asiml or DVC workspace")
    root.mkdir(parents=True, exist_ok=True)
    _must(_dvc(root, ["init", "--subdir"] if _in_git(root) else ["init", "--no-scm"], None, ref, 120),
          "init")
    (root / payload).mkdir(exist_ok=True)
    gi = root / ".gitignore"
    lines = gi.read_text().splitlines() if gi.exists() else []
    if f"/{payload}" not in lines:
        with open(gi, "a") as f:
            f.write(f"/{payload}\n")
    _write_state(root, {"artifactId": f"{kind}s/{folder}", "catalogUrl": base_url(host) + "/",
                        "payload": payload, "revision": None})


def _configure_remote(root: Path, access: dict[str, Any], ref: str) -> None:
    url = access.get("remoteUrl", "")
    _must(_dvc(root, ["remote", "add", "--force", "asiml", url], None, ref, 60), "remote add")
    if url.startswith("azure://"):
        _must(_dvc(root, ["remote", "modify", "asiml", "account_name", access.get("account", "")],
                   None, ref, 60), "remote modify")


def _pointer_text(access: dict[str, Any], payload: str) -> str:
    md5 = access.get("md5", "")
    if not re.fullmatch(r"[0-9a-f]{32}", md5):
        raise CatalogError("the catalog returned an invalid revision")
    return (f"outs:\n- md5: {md5}.dir\n  size: {int(access.get('size', 0))}\n"
            f"  nfiles: {int(access.get('nFiles', 0))}\n  hash: md5\n  path: '{payload}'\n")


def _read_pointer(path: Path) -> str:
    m = re.search(r"md5:\s*([0-9a-f]{32})\.dir", path.read_text())
    if not m:
        raise CatalogError("expected a DVC directory manifest hash in " + path.name)
    return m.group(1)


def _transfer(root: Path, args: list[str], access: dict[str, Any], renew, ref: str,
              timeout: float) -> None:
    for attempt in range(3):
        res = _dvc(root, args, access, ref, timeout)
        if res.ok:
            return
        if attempt == 2 or not re.search(r"403|AuthenticationFailed|expired|signature",
                                         res.stdout + res.stderr, re.I):
            raise CatalogError("dvc transfer failed (retrying is safe): "
                               + (res.stderr.strip()[-500:] or res.stdout.strip()[-500:]))
        access = renew()


def mlcat_workspace(action: str, cwd: str, artifact: str = "", revision: str = "",
                    data_dir: str = "data", account: str | None = None,
                    confirmed: bool = False, timeout: float = 3600) -> dict[str, Any]:
    root = Path(cwd).expanduser()
    try:
        if not root.is_absolute():
            raise gitops.GitRefused("cwd must be an absolute path")
        gitops._check_paths(root if root.exists() else root.parent, [])
        data = vault.load()
        ref, acct = _account(account, data)
        cls = {"clone": "read", "pull": "read", "push": "write"}.get(action, "local")
        if action not in ("init", "clone", "pull", "push", "status"):
            raise gitops.GitRefused("action is init, clone, pull, push or status")
        if cls != "local":
            decision = vault.effective_prompts(acct, data)[cls]
            if decision == "refuse":
                return gitops._refuse(ref, cls, f"{ref} is set to refuse {cls} calls.")
            if decision == "ask" and not confirmed:
                out = gitops._refuse(ref, cls, f"{ref} asks before {cls} calls: run the same "
                                     "call with mlcat_workspace_confirm.")
                out["use"] = "mlcat_workspace_confirm"
                return out
        if action == "init":
            kind, folder, rev = _parse_artifact(artifact)
            if rev:
                raise gitops.GitRefused("init takes an artifact without a revision")
            if not FOLDER_RE.match(data_dir) or data_dir in (".dvc", ".git", ".asiml"):
                raise gitops.GitRefused("data_dir must be a simple child folder name")
            _init(root, kind, folder, acct["host"], data_dir, ref)
            readme = root / data_dir / "README.md"
            if not readme.exists():
                readme.write_text(f"---\nname: {folder}\n---\n# {folder}\n\nDescribe this {kind} here.\n")
            msg = f"Initialized {kind}s/{folder} in {root}; put files in {data_dir}/, then push."
        elif action == "clone":
            kind, folder, rev = _parse_artifact(artifact)
            if root.exists() and any(root.iterdir()):
                raise gitops.GitRefused("clone needs a new or empty directory")
            access = _api(ref, acct, "POST", "/api/transfers/pull",
                          {"kind": kind, "folder": folder, "revision": rev})
            _init(root, kind, folder, acct["host"], "data", ref)
            msg = _pull(root, ref, acct, access["md5"], access, timeout)
        elif action == "pull":
            st = _read_state(root)
            ptr = root / f"{st['payload']}.dvc"
            rev = None if revision == "latest" else (revision or (_read_pointer(ptr) if ptr.exists()
                                                                   else st.get("revision")))
            if rev and not REV_RE.match(rev):
                raise gitops.GitRefused("a revision is 8-32 lowercase hex characters, or latest")
            msg = _pull(root, ref, acct, rev, None, timeout)
        elif action == "push":
            st = _read_state(root)
            kind, folder, _ = _parse_artifact(st["artifactId"])
            body = {"kind": kind, "folder": folder}
            access = _api(ref, acct, "POST", "/api/transfers/push", body)
            _configure_remote(root, access, ref)
            _must(_dvc(root, ["add", "--", st["payload"]], None, ref, timeout), "add")
            md5 = _read_pointer(root / f"{st['payload']}.dvc")
            _transfer(root, ["push", "-r", "asiml", "--", f"{st['payload']}.dvc"], access,
                      lambda: _api(ref, acct, "POST", "/api/transfers/push", body), ref, timeout)
            _api(ref, acct, "POST", "/api/transfers/complete", {**body, "revision": md5})
            _write_state(root, {**st, "revision": md5})
            msg = (f"Published {st['artifactId']}@{md5}; the catalog indexes it within a minute. "
                   f"Commit {st['payload']}.dvc (git ignores the data itself).")
        else:  # status
            st = _read_state(root)
            ptr = root / f"{st['payload']}.dvc"
            if not ptr.exists():
                msg = f"{st['artifactId']}: no snapshot yet (push to publish)."
            else:
                res = _dvc(root, ["status", "--", ptr.name], None, ref, 300)
                msg = f"{st['artifactId']} ({st.get('revision') or 'not yet published'})\n" + res.stdout
    except (gitops.GitRefused, CatalogError, entra.EntraError, runner.RunnerError) as e:
        policy.audit("refused", {"action": "mlcat_workspace", "reason": str(e)[:200]})
        return {"ok": False, "reason": str(e)}
    policy.audit("mlcat_workspace", {"account": ref, "action": action, "cwd": str(root)})
    return {"ok": True, "account": ref, "class": cls, "result": msg}


def _pull(root: Path, ref: str, acct: dict[str, Any], rev: str | None,
          access: dict[str, Any] | None, timeout: float) -> str:
    st = _read_state(root)
    kind, folder, _ = _parse_artifact(st["artifactId"])
    if access is None:
        access = _api(ref, acct, "POST", "/api/transfers/pull",
                      {"kind": kind, "folder": folder, "revision": rev})
    _configure_remote(root, access, ref)
    ptr = root / f"{st['payload']}.dvc"
    previous = ptr.read_text() if ptr.exists() else None
    ptr.write_text(_pointer_text(access, st["payload"]))
    pinned = access["md5"]
    try:
        _transfer(root, ["pull", "-r", "asiml", "--", ptr.name], access,
                  lambda: _api(ref, acct, "POST", "/api/transfers/pull",
                               {"kind": kind, "folder": folder, "revision": pinned}), ref, timeout)
    except Exception:
        if previous is not None:
            ptr.write_text(previous)
        else:
            ptr.unlink(missing_ok=True)
        raise
    _write_state(root, {**st, "revision": pinned})
    return f"Retrieved {st['artifactId']}@{pinned} into {root / st['payload']}."
