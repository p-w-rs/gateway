"""The gateway's own asiml and the dvc delegation (SPEC 9.5).

The ml-catalog account kind is an ML model catalog behind Microsoft Entra ID,
with its asiml CLI; the account's `host` (required) names the catalog. asiml
here is the gateway's implementation of that CLI: it reads the catalog over
its API (search / show / files) and manages a DVC-backed workspace (init /
clone / pull / push / status) in the same `.asiml` format the catalog's own
asiml uses. Transfers ask the catalog for a short-lived, role-limited
storage pass and hand it to `dvc` (the gateway's dvc feature env) through an
isolated config; the pass is scrubbed from all output.

The API token is an Entra access token for the catalog's API scope, from the
account's browser sign-in (PLAN-0.11 §7, run by gated: daemon/oauth.py): a
fixed authority (the account's own `tenant`, "organizations" by default),
the client id from the bound catalog's /api/config and the fixed scope
`api://{clientId}/access_as_user`, pinned in the vault at sign-in. Each run
checks that the catalog still names the pinned client id; a change refuses
until a new sign-in. The host must be bound (consent), so a changed host
can't redirect the token. Every catalog request
goes through entra.urlopen: redirects are never followed (a 3xx would make
urllib resend the Bearer token to another host), proxy variables and CA
overrides are ignored.

Like every stand-in (SPEC 9, 10), asiml uses the catalog credential only for
a direct caller (Claude's own command), or for any caller when the account
has `scripts = true`; `init` and `status` use no credential and aren't gated.

`dvc_main` is the `dvc` stand-in: inside an `.asiml` workspace, `dvc pull` and
`dvc push` delegate to `asiml pull` / `asiml push`; every other dvc command,
and any outside a workspace, runs the user's own dvc (PLAN-0.11 §1.4).
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

from . import accounts as acctmod
from . import audit, consent, entra, scrub, vault
from . import form as formmod
from . import paths

FOLDER_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$")
REV_RE = re.compile(r"^[0-9a-f]{8,32}$")
SAS_QUERY = re.compile(r"(?i)([?&](?:sig|sv|sp|se|st|skoid|sktid|skt|ske|sks|skv|sr|spr)=)[^\s'\"&]+")


class AsimlError(Exception):
    """A refusal or a catalog error (message starts with gateway:)."""


def _g(msg: str) -> AsimlError:
    return AsimlError(msg if msg.startswith("gateway:") else f"gateway: {msg}")


# ---------------------------------------------------------------------------
# Account and catalog config
# ---------------------------------------------------------------------------


def _load() -> tuple[formmod.Form, Any, dict[str, Any]]:
    try:
        data = vault.load()
    except vault.VaultError:
        data = vault.empty()
    form = consent.load_form(data)
    try:
        consent.ratchet(form)
        data = vault.load()
    except Exception:  # noqa: BLE001
        pass
    eff = consent.compute(form, data)
    try:
        scrub.note_vault(data)
    except Exception:  # noqa: BLE001
        pass
    return form, eff, data


def _account(form: formmod.Form, eff: Any, data: dict[str, Any], *, cred: bool = True,
             tool: str = "asiml") -> formmod.Account:
    """The ml-catalog account to use. cred=True (a call that uses the catalog
    token or a storage pass) also checks ancestry (SPEC 10)."""
    cats = [a for a in form.accounts.values() if a.kind == "ml-catalog"]
    if not cats:
        raise _g(_no_catalog(form))
    host = cats[0].host
    sel = acctmod.select("ml-catalog", host, None, form, effective=eff, vault=data, env=os.environ)
    if sel.error:
        raise _g(sel.error)
    if sel.account is None:
        raise _g(sel.note or _no_catalog(form))
    a = sel.account
    if not consent.bound_ok(data, a.name, a.host or host):
        raise _g(f"gateway: {a.name} isn't bound to {a.host or host}; run gate check {a.name} "
                 "while the user is here")
    if cred:
        _check_direct(tool, a, eff)
    return a


def _no_catalog(form: formmod.Form) -> str:
    """No usable ml-catalog account. One that is off because of a mistake in
    the form (a converted catalog without `host`, say) is named with its
    problem, so Claude fixes that entry instead of adding a second one."""
    off = [n for n, k in form.disabled_kinds.items()
           if k == "ml-catalog" and form.is_disabled(n, "accounts")]
    if off:
        n = off[0]
        errs = [p.render() for p in form.problems_for(n) if p.level == "error"]
        return (f"gateway: the ml-catalog account {n} is off because of a mistake in gateway.toml"
                + (f" ({errs[0]})" if errs else "") + f"; ask the user to fix [accounts.{n}] "
                "(gate status shows it) rather than adding another ml-catalog account")
    return ("gateway: no ml-catalog account; ask the user to add one (kind = \"ml-catalog\" "
            "with host = the catalog's address)")


def _check_direct(tool: str, account: formmod.Account, eff: Any) -> None:
    """Only Claude's own commands get the catalog credential, unless the
    account has scripts = true (SPEC 10)."""
    from . import clis
    ea = eff.accounts.get(account.name)
    scripts = bool(ea and ea.scripts)
    ok, culprit = clis.is_direct(tool, scripts)
    if not ok:
        who = formmod.safe(culprit) or "a program Claude started"
        from . import ancestry
        if culprit in ("", ancestry.UNTRACED):
            who = ancestry.UNTRACED_WHO
        raise _g(f"gateway: {tool} started by {who} got no credential (only Claude's own "
                 f"commands do); run it as its own command, or set scripts = true for "
                 f"{account.name}")


def base_url(host: str) -> str:
    h = host.split(":", 1)[0]
    return f"{'http' if h in ('127.0.0.1', 'localhost') else 'https'}://{host}"


_CFG: dict[str, dict[str, Any]] = {}


def fetch_catalog_config(host: str, timeout: float = 30) -> dict[str, Any]:
    """The catalog's /api/config, read now (gated's sign-in reads it at each
    sign-in), through entra.urlopen. Only its clientId (a GUID) is ever used:
    never an authority, a tenant or a scope it names."""
    try:
        with entra.urlopen(base_url(host) + "/api/config", timeout=timeout) as r:
            cfg = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        why = "it answered with a redirect, which isn't followed" if entra.is_redirect(e) \
            else f"HTTP {e.code}"
        raise _g(f"gateway: could not read the catalog's sign-in configuration ({why})")
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise _g(f"gateway: could not read the catalog's sign-in configuration ({type(e).__name__})")
    if not isinstance(cfg, dict) or not formmod.GUID_RE.fullmatch(str(cfg.get("clientId") or "")):
        raise _g("gateway: the catalog's /api/config has no valid clientId")
    return cfg


def catalog_config(host: str) -> dict[str, Any]:
    """fetch_catalog_config, once per process."""
    if host not in _CFG:
        _CFG[host] = fetch_catalog_config(host)
    return _CFG[host]


def api_scope(account: formmod.Account, data: dict[str, Any]) -> str:
    """The API scope of the account's browser sign-in (PLAN-0.11 §7.4): fixed
    around the client id pinned at the sign-in, and only while the catalog
    still names that client id (a change refuses until a new sign-in, whose
    confirm dialog shows it)."""
    rec = (data.get("accounts") or {}).get(account.name) or {}
    ent = rec.get("entra") or {}
    pinned = str(ent.get("client_id") or "")
    if not ent.get("refresh_token") or ent.get("kind") != "browser" \
            or not formmod.GUID_RE.fullmatch(pinned):
        raise _g(f"gateway: {account.name} isn't signed in; run gate check {account.name} while "
                 "the user is here (a browser sign-in)")
    if str(catalog_config(account.host).get("clientId")) != pinned:
        raise _g(f"gateway: the catalog's sign-in settings changed since {account.name} signed in "
                 f"(its client id); run gate check {account.name} while the user is here: the "
                 "sign-in dialog shows the change")
    return entra.catalog_scopes(pinned)[0]


def api_token(account: formmod.Account, data: dict[str, Any]) -> str:
    return entra.access_token(account.name, api_scope(account, data), mode="modeless")   # asiml: modeless


def _api(account: formmod.Account, data: dict[str, Any], method: str, path: str,
         body: dict[str, Any] | None = None) -> Any:
    token = api_token(account, data)
    host = account.host
    req = urllib.request.Request(base_url(host) + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": f"Bearer {token}",
                                          "Accept": "application/json",
                                          **({"Content-Type": "application/json"} if body is not None else {})})
    try:
        with entra.urlopen(req, timeout=60) as r:
            raw = r.read().decode()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        detail = {401: f"the sign-in was rejected; run gate check {account.name}",
                  403: "the user's catalog role does not allow this (publishing needs Catalog.Writer)"
                  }.get(e.code)
        if entra.is_redirect(e):
            detail = (f"the catalog answered with a redirect, which the gateway doesn't follow "
                      f"with the sign-in token; check {account.name}'s host in gateway.toml")
        if detail is None:
            try:
                detail = SAS_QUERY.sub(r"\1[redacted]", json.loads(e.read().decode()).get("error", ""))
            except Exception:  # noqa: BLE001
                detail = f"HTTP {e.code}"
        raise _g(f"gateway: catalog: {detail}") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise _g(f"gateway: could not reach the catalog ({type(e).__name__})") from None


# ---------------------------------------------------------------------------
# Workspace state
# ---------------------------------------------------------------------------


def _parse_artifact(value: str) -> tuple[str, str, str | None]:
    path, _, rev = value.partition("@")
    parts = path.split("/")
    if len(parts) != 2 or parts[0] not in ("datasets", "models") or not FOLDER_RE.match(parts[1]):
        raise _g("gateway: use datasets/NAME[@revision] or models/NAME[@revision]")
    if rev and not REV_RE.match(rev):
        raise _g("gateway: a revision is 8-32 lowercase hex characters")
    return ("dataset" if parts[0] == "datasets" else "model"), parts[1], rev or None


def _state_path(root: Path) -> Path:
    return root / ".asiml" / "workspace.json"


def find_workspace(start: Path) -> Path | None:
    for p in [start, *start.parents]:
        if (p / ".asiml" / "workspace.json").exists():
            return p
    return None


def _read_state(root: Path) -> dict[str, Any]:
    try:
        st = json.loads(_state_path(root).read_text())
    except (OSError, ValueError):
        raise _g("gateway: this is not an asiml workspace (no .asiml/workspace.json); use init or clone first")
    _parse_artifact(st.get("artifactId", ""))
    if not FOLDER_RE.match(st.get("payload", "")):
        raise _g("gateway: the workspace's payload must be a simple folder name")
    return st


def _write_state(root: Path, st: dict[str, Any]) -> None:
    p = _state_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(st, indent=2))
    os.replace(tmp, p)


def _in_git(root: Path) -> bool:
    return any((p / ".git").exists() for p in [root, *root.parents])


# ---------------------------------------------------------------------------
# dvc
# ---------------------------------------------------------------------------


def _dvc_bin() -> str:
    from . import clis
    return clis.resolve_tool("dvc", feature="dvc")


def _site_cache() -> str:
    """DVC's site cache (its repo index and locks; nothing secret), in a
    folder of the user's own."""
    return str(paths.user_home() / ".local" / "share" / "asiml" / "site-cache")


def _run_dvc(root: Path, args: list[str], access: dict[str, Any] | None) -> tuple[int, str, str]:
    """Run dvc with an isolated config and the storage pass in its env; capture
    and scrub stdout/stderr. Returns (rc, stdout, stderr)."""
    from . import clis
    import subprocess
    sas = (access or {}).get("sasToken", "")
    real = _dvc_bin()
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="gw-dvc-", dir=paths.run_dir()))
    os.chmod(tmp, 0o700)
    try:
        extra = {"DVC_NO_ANALYTICS": "1", "DVC_SITE_CACHE_DIR": _site_cache(),
                 "DVC_GLOBAL_CONFIG_DIR": str(tmp / "dvc-global"),
                 "DVC_SYSTEM_CONFIG_DIR": str(tmp / "dvc-system"),
                 "AZURE_CONFIG_DIR": str(tmp / "azure"), "HOME": str(tmp), "NO_COLOR": "1"}
        if access:
            extra["AZURE_STORAGE_ACCOUNT"] = access.get("account", "")
            extra["AZURE_STORAGE_SAS_TOKEN"] = sas
        env = clis.child_env(extra)
        proc = subprocess.run([real, *args], cwd=str(root), env=env, capture_output=True,
                              timeout=3600)
        out = scrub.scrub_text(SAS_QUERY.sub(r"\1[redacted]",
                                             proc.stdout.decode("utf-8", "replace")), extra=[sas] if sas else [])
        err = scrub.scrub_text(SAS_QUERY.sub(r"\1[redacted]",
                                             proc.stderr.decode("utf-8", "replace")), extra=[sas] if sas else [])
        return proc.returncode, out, err
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def _must(rc: int, out: str, err: str, what: str) -> None:
    if rc != 0:
        raise _g(f"gateway: dvc {what} failed: {(err.strip() or out.strip())[-400:]}")


def _configure_remote(root: Path, access: dict[str, Any]) -> None:
    url = access.get("remoteUrl", "")
    rc, o, e = _run_dvc(root, ["remote", "add", "--force", "asiml", url], None)
    _must(rc, o, e, "remote add")
    if url.startswith("azure://"):
        rc, o, e = _run_dvc(root, ["remote", "modify", "asiml", "account_name",
                                   access.get("account", "")], None)
        _must(rc, o, e, "remote modify")


def _pointer_text(access: dict[str, Any], payload: str) -> str:
    md5 = access.get("md5", "")
    if not re.fullmatch(r"[0-9a-f]{32}", md5):
        raise _g("gateway: the catalog returned an invalid revision")
    return (f"outs:\n- md5: {md5}.dir\n  size: {int(access.get('size', 0))}\n"
            f"  nfiles: {int(access.get('nFiles', 0))}\n  hash: md5\n  path: '{payload}'\n")


def _read_pointer(path: Path) -> str:
    m = re.search(r"md5:\s*([0-9a-f]{32})\.dir", path.read_text())
    if not m:
        raise _g("gateway: expected a DVC directory manifest hash in " + path.name)
    return m.group(1)


def _transfer(root: Path, args: list[str], access: dict[str, Any], renew) -> None:
    for attempt in range(3):
        rc, out, err = _run_dvc(root, args, access)
        if rc == 0:
            return
        if attempt == 2 or not re.search(r"403|AuthenticationFailed|expired|signature",
                                         out + err, re.I):
            raise _g(f"gateway: dvc transfer failed (retrying is safe): {(err.strip() or out.strip())[-400:]}")
        access = renew()


def _init(root: Path, kind: str, folder: str, host: str, payload: str) -> None:
    if _state_path(root).exists() or (root / ".dvc").exists():
        raise _g("gateway: this directory already has an asiml or DVC workspace")
    root.mkdir(parents=True, exist_ok=True)
    rc, o, e = _run_dvc(root, ["init", "--subdir"] if _in_git(root) else ["init", "--no-scm"], None)
    _must(rc, o, e, "init")
    (root / payload).mkdir(exist_ok=True)
    gi = root / ".gitignore"
    lines = gi.read_text().splitlines() if gi.exists() else []
    if f"/{payload}" not in lines:
        with open(gi, "a") as f:
            f.write(f"/{payload}\n")
    _write_state(root, {"artifactId": f"{kind}s/{folder}", "catalogUrl": base_url(host) + "/",
                        "payload": payload, "revision": None})


def _pull(root: Path, account: formmod.Account, data: dict[str, Any], rev: str | None,
          access: dict[str, Any] | None) -> str:
    st = _read_state(root)
    kind, folder, _ = _parse_artifact(st["artifactId"])
    if access is None:
        access = _api(account, data, "POST", "/api/transfers/pull",
                      {"kind": kind, "folder": folder, "revision": rev})
    _configure_remote(root, access)
    ptr = root / f"{st['payload']}.dvc"
    previous = ptr.read_text() if ptr.exists() else None
    ptr.write_text(_pointer_text(access, st["payload"]))
    pinned = access["md5"]
    try:
        _transfer(root, ["pull", "-r", "asiml", "--", ptr.name], access,
                  lambda: _api(account, data, "POST", "/api/transfers/pull",
                               {"kind": kind, "folder": folder, "revision": pinned}))
    except Exception:
        if previous is not None:
            ptr.write_text(previous)
        else:
            ptr.unlink(missing_ok=True)
        raise
    _write_state(root, {**st, "revision": pinned})
    return f"gateway: retrieved {st['artifactId']}@{pinned} into {root / st['payload']}."


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def _opt(argv: list[str], name: str, default: str = "") -> str:
    for i, a in enumerate(argv):
        if a == name and i + 1 < len(argv):
            return argv[i + 1]
        if a.startswith(name + "="):
            return a.split("=", 1)[1]
    return default


def _positionals(argv: list[str]) -> list[str]:
    out, skip = [], False
    for i, a in enumerate(argv):
        if skip:
            skip = False
            continue
        if a.startswith("-"):
            if "=" not in a and a in ("--data-dir", "--kind", "--prefix"):
                skip = True
            continue
        out.append(a)
    return out


def main(argv: list[str], tool: str = "asiml") -> int:
    """asiml init|clone|pull|push|status|search|show|files (SPEC 9.5)."""
    if not argv:
        print("gateway: usage: asiml init|clone|pull|push|status|search|show|files ...",
              file=sys.stderr)
        return 2
    action = argv[0]
    rest = argv[1:]
    cwd = Path(os.getcwd())
    try:
        form, eff, data = _load()
        if action in ("init",):
            return _cmd_init(rest, cwd, form, eff, data)
        if action == "clone":
            return _cmd_clone(rest, cwd, form, eff, data, tool)
        if action in ("pull", "push", "status"):
            return _cmd_workspace(action, rest, cwd, form, eff, data, tool)
        if action in ("search", "show", "files"):
            return _cmd_read(action, rest, form, eff, data, tool)
        print(f"gateway: asiml has no '{formmod.safe(action) or 'that'}' command", file=sys.stderr)
        return 2
    except AsimlError as e:
        audit.refusal(tool, None, str(e), mode="modeless")   # asiml: the modeless rule
        print(str(e), file=sys.stderr)
        return 2
    except entra.EntraError as e:
        msg = str(e) if str(e).startswith("gateway:") else f"gateway: {e}"
        print(msg, file=sys.stderr)
        return 2


def _cmd_init(rest: list[str], cwd: Path, form, eff, data) -> int:
    pos = _positionals(rest)
    if not pos:
        raise _g("gateway: usage: asiml init datasets/NAME|models/NAME [--data-dir D]")
    kind, folder, rev = _parse_artifact(pos[0])
    if rev:
        raise _g("gateway: init takes an artifact without a revision")
    data_dir = _opt(rest, "--data-dir", "data")
    if not FOLDER_RE.match(data_dir) or data_dir in (".dvc", ".git", ".asiml"):
        raise _g("gateway: --data-dir must be a simple child folder name")
    a = _account(form, eff, data, cred=False)
    _init(cwd, kind, folder, a.host, data_dir)
    readme = cwd / data_dir / "README.md"
    if not readme.exists():
        readme.write_text(f"---\nname: {folder}\n---\n# {folder}\n\nDescribe this {kind} here.\n")
    audit.log("asiml", tool="asiml", action="init", account=a.name)
    print(f"gateway: initialized {kind}s/{folder} in {cwd}; put files in {data_dir}/, then push.")
    return 0


def _cmd_clone(rest: list[str], cwd: Path, form, eff, data, tool: str = "asiml") -> int:
    pos = _positionals(rest)
    if not pos:
        raise _g("gateway: usage: asiml clone datasets/NAME[@REV] [DIR]")
    kind, folder, rev = _parse_artifact(pos[0])
    root = (cwd / pos[1]).resolve() if len(pos) > 1 else (cwd / folder)
    if root.exists() and any(root.iterdir()):
        raise _g("gateway: clone needs a new or empty directory")
    a = _account(form, eff, data, tool=tool)
    access = _api(a, data, "POST", "/api/transfers/pull",
                  {"kind": kind, "folder": folder, "revision": rev})
    _init(root, kind, folder, a.host, "data")
    msg = _pull(root, a, data, access["md5"], access)
    audit.log("asiml", tool="asiml", action="clone", account=a.name)
    print(msg)
    return 0


def _cmd_workspace(action: str, rest: list[str], cwd: Path, form, eff, data,
                   tool: str = "asiml") -> int:
    root = find_workspace(cwd)
    if root is None:
        raise _g("gateway: this is not an asiml workspace (no .asiml/workspace.json)")
    a = _account(form, eff, data, cred=(action != "status"), tool=tool)
    st = _read_state(root)
    if action == "status":
        ptr = root / f"{st['payload']}.dvc"
        if not ptr.exists():
            print(f"gateway: {st['artifactId']}: no snapshot yet (push to publish).")
            return 0
        rc, out, err = _run_dvc(root, ["status", "--", ptr.name], None)
        print(f"gateway: {st['artifactId']} ({st.get('revision') or 'not yet published'})\n{out}")
        return 0 if rc == 0 else 1
    if action == "pull":
        pos = _positionals(rest)
        ptr = root / f"{st['payload']}.dvc"
        want = pos[0] if pos else ""
        rev = None if want == "latest" else (want or (_read_pointer(ptr) if ptr.exists()
                                                       else st.get("revision")))
        if rev and not REV_RE.match(rev):
            raise _g("gateway: a revision is 8-32 lowercase hex characters, or latest")
        msg = _pull(root, a, data, rev, None)
        audit.log("asiml", tool="asiml", action="pull", account=a.name)
        print(msg)
        return 0
    # push
    kind, folder, _ = _parse_artifact(st["artifactId"])
    body = {"kind": kind, "folder": folder}
    access = _api(a, data, "POST", "/api/transfers/push", body)
    _configure_remote(root, access)
    rc, o, e = _run_dvc(root, ["add", "--", st["payload"]], None)
    _must(rc, o, e, "add")
    md5 = _read_pointer(root / f"{st['payload']}.dvc")
    _transfer(root, ["push", "-r", "asiml", "--", f"{st['payload']}.dvc"], access,
              lambda: _api(a, data, "POST", "/api/transfers/push", body))
    _api(a, data, "POST", "/api/transfers/complete", {**body, "revision": md5})
    _write_state(root, {**st, "revision": md5})
    audit.log("asiml", tool="asiml", action="push", account=a.name)
    print(f"gateway: published {st['artifactId']}@{md5}; commit {st['payload']}.dvc "
          "(git ignores the data itself).")
    return 0


def _cmd_read(action: str, rest: list[str], form, eff, data, tool: str = "asiml") -> int:
    a = _account(form, eff, data, tool=tool)
    pos = _positionals(rest)
    if action == "search":
        q = {"kind": _opt(rest, "--kind", "all") or "all", "sort": "recent", "page": 1,
             "pageSize": 30}
        if pos:
            q["q"] = pos[0]
        out = _api(a, data, "GET", "/api/catalog?" + urllib.parse.urlencode(q))
    elif action == "show":
        if not pos:
            raise _g("gateway: usage: asiml show datasets/NAME[@VER] or models/NAME[@VER]")
        kind, folder, ver = _parse_artifact(pos[0])
        out = _api(a, data, "GET", f"/api/items/{kind}/{urllib.parse.quote(folder)}"
                   + (f"?v={ver}" if ver else ""))
        if isinstance(out, dict):
            out.pop("readmeHtml", None)
    else:  # files
        if not pos or "@" not in pos[0]:
            raise _g("gateway: usage: asiml files datasets/NAME@VER [--prefix P]")
        _kind, _folder, ver = _parse_artifact(pos[0])
        if not ver or not REV_RE.match(ver):
            raise _g("gateway: files needs a revision, like datasets/NAME@<revision>")
        out = _api(a, data, "GET", f"/api/versions/{ver}/files?" + urllib.parse.urlencode(
            {"prefix": _opt(rest, "--prefix", ""), "skip": 0, "take": 200}))
    audit.log("asiml", tool="asiml", action=action, account=a.name)
    print(scrub.scrub_text(json.dumps(out, indent=2)))
    return 0


def dvc_main(argv: list[str]) -> int:
    """dvc pull|push inside an .asiml workspace -> asiml pull|push (SPEC 9.5).
    Every other dvc command, and any outside an .asiml workspace, is the
    user's own dvc (PLAN-0.11 §1.4: envfile.pass_through; 127 when there is
    none)."""
    from . import envfile
    root = find_workspace(Path(os.getcwd()))
    if root is None or not argv or argv[0] not in ("pull", "push"):
        return envfile.pass_through("dvc", list(argv), None,
                                    entries=["dvc pull and dvc push in an asiml workspace"])
    return main([argv[0]], tool="dvc")
