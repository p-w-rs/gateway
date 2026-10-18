"""The `pijul` tool: Pijul as an account (the Nest or a self-hosted server).

Every call runs with a throwaway PIJUL_CONFIG_DIR (pijul ignores HOME and
XDG for its config, so this is the only way to keep the user's own
~/.config/pijul out of it) and a throwaway HOME whose .ssh/known_hosts holds
the account's pinned host key (pijul can't ask about new keys without a
terminal). When the call needs the account (push, pull, clone, record,
...), its SSH key goes into a private ssh-agent. That one key both
authenticates to the server and signs changes: `--config signing_key=` points
at its public key, and the identity file in the temp config dir carries the
account's name, email and public key (no secret). REMOTE_PIJUL comes from
the account for self-hosted servers whose pijul isn't on PATH.
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Any

from . import gitops, policy, runner, vault

REMOTE_CMDS = {"push": "write", "pull": "read", "clone": "read"}
SIGNING_CMDS = {"record", "rec"}
REFUSED = {"identity", "id", "key", "client", "protocol", "upgrade"}
_URL = re.compile(r"^ssh://(?:(?P<user>[^@/]+)@)?(?P<host>[^/:]+)(?::(?P<port>\d+))?(?P<path>/.*)?$")


def parse_remote(url: str) -> dict[str, Any] | None:
    m = _URL.match(url or "")
    if not m:
        return None
    parts = [p for p in (m.group("path") or "").split("/") if p]
    return {"host": m.group("host").lower(), "port": m.group("port") or "",
            "user": m.group("user") or "", "owner": parts[0] if parts else "",
            "repo": parts[1] if len(parts) > 1 else ""}


def _default_remote(cwd: Path) -> str:
    cfg = cwd / ".pijul" / "config"
    try:
        m = re.search(r'^\s*default_remote\s*=\s*"([^"]+)"', cfg.read_text(), re.M)
    except OSError:
        return ""
    return m.group(1) if m else ""


def _remote_arg(sub: str, args: list[str], cwd: Path) -> str:
    pos = [a for a in args if not a.startswith("-")]
    if sub in REMOTE_CMDS and pos:
        return pos[0]
    return _default_remote(cwd)


def choose(remote: dict[str, Any] | None, explicit: str | None,
           data: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    accts = [(r, a) for r, a in sorted(data["accounts"].items()) if a.get("kind") == "pijul"]
    if explicit:
        a = data["accounts"].get(explicit)
        if a is None or a.get("kind") != "pijul":
            raise gitops.GitRefused(f"{explicit} is not a Pijul account; see account_list")
        if remote and not policy.host_allowed(remote["host"], a.get("hosts", [])):
            raise gitops.GitRefused(f"{explicit} is not for {remote['host']}; ask the user to run "
                                    f"/gate:account allow {explicit} {remote['host']}")
        owners = [o.lower() for o in a.get("owners", [])]
        if remote and owners and remote["owner"].lower() not in owners:
            raise gitops.GitRefused(f"{explicit} is not for {remote['owner']}; ask the user to "
                                    f"run /gate:account allow {explicit} {remote['owner']}")
        return explicit, a
    if remote:
        fit = [(r, a) for r, a in accts if policy.host_allowed(remote["host"], a.get("hosts", []))
               and (not a.get("owners") or remote["owner"].lower()
                    in [o.lower() for o in a["owners"]])]
        specific = [(r, a) for r, a in fit if a.get("owners")] or fit
        if len(specific) > 1:
            raise gitops.GitRefused("several Pijul accounts fit; pass account=")
        return specific[0] if specific else None
    return accts[0] if len(accts) == 1 else None


def classify(sub: str) -> str:
    return REMOTE_CMDS.get(sub, "local")


def pijul_tool(args: list[str], cwd: str, account: str | None = None,
               confirmed: bool = False, timeout: float = 600) -> dict[str, Any]:
    if not isinstance(args, list) or not args or not all(isinstance(a, str) for a in args):
        return {"ok": False, "reason": "args must be a non-empty list of strings, e.g. "
                                       "[\"record\", \"-a\", \"-m\", \"message\"]"}
    cwdp = Path(cwd).expanduser()
    sub = args[0]
    try:
        if not cwdp.is_absolute() or not cwdp.is_dir():
            raise gitops.GitRefused("cwd must be an existing absolute directory")
        gitops._check_paths(cwdp, args)
        if sub.startswith("-"):
            raise gitops.GitRefused("put the pijul command first, e.g. [\"log\"]")
        if sub in REFUSED:
            raise gitops.GitRefused(f"'pijul {sub}' is managed by the gateway (identities and "
                                    "keys come from the account) or not run here")
        if any(a == "--config" or a.startswith("--config=") for a in args):
            raise gitops.GitRefused("the gateway sets pijul's config; leave --config out")
        data = vault.load()
        cls = classify(sub)
        url = _remote_arg(sub, args[1:], cwdp)
        remote = parse_remote(url)
        if sub in REMOTE_CMDS and url and not remote and "://" in url and not url.startswith("ssh://"):
            remote = None  # https: anonymous (read-only) is fine; no account is used
        needs_acct = sub in REMOTE_CMDS or sub in SIGNING_CMDS
        if needs_acct or account:
            picked = choose(remote, account, data)
        else:  # local: the account's identity file only (names in log, ...), no key
            try:
                picked = choose(remote, None, data)
            except gitops.GitRefused:
                picked = None
        if sub in REMOTE_CMDS and remote and not picked:
            raise gitops.GitRefused(f"no Pijul account is for {remote['host']}/{remote['owner']}; "
                                    "ask the user to type /gate:add pijul")
        ref, acct = picked if picked else (None, None)
        if acct is not None and cls != "local":
            decision = vault.effective_prompts(acct, data)[cls]
            if decision == "refuse":
                return gitops._refuse(ref, cls, f"{ref} is set to refuse {cls} calls.")
            if decision == "ask" and not confirmed:
                out = gitops._refuse(ref, cls, f"{ref} asks before {cls} calls: run the same "
                                     "command with pijul_confirm (Claude Code asks the user).")
                out["use"] = "pijul_confirm"
                return out
        key = (acct or {}).get("secrets", {}).get("ssh_key", "") if needs_acct else ""
        if needs_acct and acct is not None and not key:
            raise gitops.GitRefused(f"{ref} has no SSH key; ask the user to add one with "
                                    f"/gate:account up {ref}")
        if remote and acct is not None and not acct.get("known_hosts"):
            raise gitops.GitRefused(f"{ref} has no pinned host key for {remote['host']}; ask the "
                                    f"user to run /gate:account up {ref} (it reads the key)")
    except (gitops.GitRefused, runner.RunnerError) as e:
        policy.audit("refused", {"action": "pijul", "reason": str(e)[:200]})
        return {"ok": False, "refused": True, "reason": str(e)}

    def env(tmp: Path) -> dict[str, str]:
        home = tmp / "home"
        (home / ".ssh").mkdir(parents=True)
        (home / ".ssh" / "known_hosts").write_text((acct or {}).get("known_hosts", "") + "\n")
        conf = tmp / "pijul"
        (conf / "identities").mkdir(parents=True)
        e = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
             "PIJUL_CONFIG_DIR": str(conf), "NO_COLOR": "1"}
        if acct is not None and acct.get("public_key"):
            pub = acct.get("public_key", "")
            (tmp / "id.pub").write_text(pub + "\n")
            name = re.sub(r"[^A-Za-z0-9._-]", "_", acct.get("login") or ref.split(":", 1)[1])
            idd = conf / "identities" / name
            idd.mkdir()
            esc = lambda v: (v or "").replace("\\", "\\\\").replace('"', '\\"')  # noqa: E731
            (idd / "identity.toml").write_text(
                f'username = "{esc(acct.get("login"))}"\n'
                f'display_name = "{esc(acct.get("name") or acct.get("login") or name)}"\n'
                f'origin = "{esc(acct.get("host"))}"\n'
                f'email = "{esc(acct.get("email"))}"\n'
                f'last_modified = "{time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}"\n\n'
                f'[public_key]\nkey = "{pub.split()[1] if len(pub.split()) > 1 else ""}"\n')
        if acct is not None and acct.get("remote_pijul"):
            e["REMOTE_PIJUL"] = acct["remote_pijul"]
        return e

    def argv(tmp: Path) -> list[str]:
        if acct is not None and key:
            return ["--config", f"signing_key={tmp / 'id.pub'}", *args]
        return list(args)

    try:
        res = runner.run_cli("pijul", args, cwd=cwdp, secrets=[], env_fn=env, argv_fn=argv,
                             ssh_key=key, account=ref or "", timeout=timeout).as_dict()
    except runner.RunnerError as e:
        return {"ok": False, "reason": str(e)}
    res["class"] = cls
    if ref:
        res["account"] = ref
    if not res["ok"] and "Unknown key" in res.get("stdout", "") + res.get("stderr", ""):
        res["hint"] = (f"The server's host key isn't the pinned one. If it changed on purpose, "
                       f"ask the user to run /gate:account up {ref} to read it again.")
    return res
