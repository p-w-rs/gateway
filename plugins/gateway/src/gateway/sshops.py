"""The ssh_exec and ssh_copy tools: servers as `ssh` accounts.

Each call starts a private ssh-agent with the account's key (and its jump
host's), and runs OpenSSH with `-F /dev/null` (no user or system config),
BatchMode, IdentitiesOnly with the account's public key, and a known_hosts
file holding only the account's pinned host keys (StrictHostKeyChecking=yes).
A jump host is another ssh account, reached through a ProxyCommand built the
same way. The command runs as an argv list joined once with shell quoting
(no shell strings). Copies use scp in its default SFTP mode, so remote paths
aren't shell-expanded. run_privileged uses the same path when an ssh account
matches its sudo target.
"""
from __future__ import annotations

import shlex
from pathlib import Path
from typing import Any

from . import gitops, policy, runner, vault


def _opts(tmp: Path, acct: dict[str, Any], tag: str) -> list[str]:
    kh = tmp / f"known_hosts-{tag}"
    kh.write_text(acct.get("known_hosts", "") + "\n")
    pub = tmp / f"id-{tag}.pub"
    pub.write_text(acct.get("public_key", "") + "\n")
    opts = ["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
            "-o", f"UserKnownHostsFile={kh}", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=yes", "-o", "IdentitiesOnly=yes",
            "-o", f"IdentityAgent={tmp / 'agent.sock'}", "-o", f"IdentityFile={pub}",
            "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes"]
    if acct.get("port"):
        opts += ["-p", acct["port"]]
    return opts


def _target(acct: dict[str, Any]) -> str:
    return f"{acct.get('user')}@{acct.get('host')}"


def resolve(account: str, data: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
    a = data["accounts"].get(account)
    if a is None or a.get("kind") != "ssh":
        raise gitops.GitRefused(f"{account} is not an ssh account; see account_list")
    if not a.get("secrets", {}).get("ssh_key"):
        raise gitops.GitRefused(f"{account} has no SSH key; ask the user to run "
                                f"/gate:account up {account}")
    if not a.get("known_hosts"):
        raise gitops.GitRefused(f"{account} has no pinned host key; ask the user to run "
                                f"/gate:account up {account} (it reads the key)")
    jump = None
    if a.get("jump"):
        jump = data["accounts"].get(a["jump"])
        if jump is None or jump.get("kind") != "ssh" or not jump.get("secrets", {}).get("ssh_key"):
            raise gitops.GitRefused(f"{account}'s jump host {a['jump']} is missing or has no key")
    return a, jump


def ssh_args(tmp: Path, acct: dict[str, Any], jump: dict[str, Any] | None) -> list[str]:
    """OpenSSH options (and ProxyCommand for a jump host) for this account."""
    opts = _opts(tmp, acct, "t")
    if jump is not None:
        proxy = shlex.join([runner._which("ssh"), *_opts(tmp, jump, "j"), "-W", "%h:%p",
                            "--", _target(jump)])
        opts += ["-o", f"ProxyCommand={proxy}"]
    return opts


def keys_of(acct: dict[str, Any], jump: dict[str, Any] | None) -> list[str]:
    return [x["secrets"]["ssh_key"] for x in (acct, jump) if x is not None]


def _policy(ref: str, acct: dict[str, Any], cls: str, confirmed: bool, data: dict[str, Any],
            tool: str) -> dict[str, Any] | None:
    decision = vault.effective_prompts(acct, data)[cls]
    if decision == "refuse":
        return gitops._refuse(ref, cls, f"{ref} is set to refuse {cls} calls.")
    if decision == "ask" and not confirmed:
        out = gitops._refuse(ref, cls, f"{ref} asks before {cls} calls: run the same "
                             f"command with {tool}_confirm (Claude Code asks the user).")
        out["use"] = f"{tool}_confirm"
        return out
    return None


def ssh_exec(account: str, argv: list[str], confirmed: bool = False,
             timeout: float = 300) -> dict[str, Any]:
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        return {"ok": False, "reason": "argv must be a non-empty list of strings (not a shell "
                                       "string), e.g. [\"uptime\"]"}
    try:
        data = vault.load()
        acct, jump = resolve(account, data)
        hit = policy.match_blocked(shlex.join(argv))
        if hit:
            raise gitops.GitRefused(f"'{hit[0]}' is not run through ssh_exec either; use {hit[1]}")
        refusal = _policy(account, acct, "exec", confirmed, data, "ssh_exec")
        if refusal is not None:
            return refusal
    except (gitops.GitRefused, runner.RunnerError) as e:
        policy.audit("refused", {"action": "ssh_exec", "reason": str(e)[:200]})
        return {"ok": False, "refused": True, "reason": str(e)}
    try:
        res = runner.run_cli(
            "ssh", [], cwd=None, secrets=[], ssh_key=keys_of(acct, jump), account=account,
            timeout=timeout,
            argv_fn=lambda tmp: [*ssh_args(tmp, acct, jump), "-T", "--", _target(acct),
                                 shlex.join(argv)]).as_dict()
    except runner.RunnerError as e:
        return {"ok": False, "reason": str(e)}
    res.update({"account": account, "class": "exec", "host": acct.get("host")})
    if not res["ok"] and "host key verification failed" in res.get("stderr", "").lower():
        res["hint"] = (f"The server's host key isn't the pinned one. If it changed on purpose, "
                       f"ask the user to run /gate:account up {account}.")
    return res


def ssh_copy(account: str, direction: str, local: str, remote: str, recursive: bool = False,
             confirmed: bool = False, timeout: float = 1800) -> dict[str, Any]:
    if direction not in ("up", "down"):
        return {"ok": False, "reason": "direction is up (local -> host) or down (host -> local)"}
    lp = Path(local).expanduser()
    try:
        if not lp.is_absolute():
            raise gitops.GitRefused("local must be an absolute path")
        gitops._check_paths(lp.parent if lp.parent.exists() else Path("/"), [str(lp)])
        if not remote or remote.startswith("-") or "\n" in remote:
            raise gitops.GitRefused("give a remote path (not starting with '-')")
        data = vault.load()
        acct, jump = resolve(account, data)
        cls = "write" if direction == "up" else "read"
        refusal = _policy(account, acct, cls, confirmed, data, "ssh_copy")
        if refusal is not None:
            return refusal
    except (gitops.GitRefused, runner.RunnerError) as e:
        policy.audit("refused", {"action": "ssh_copy", "reason": str(e)[:200]})
        return {"ok": False, "refused": True, "reason": str(e)}
    rspec = f"{_target(acct)}:{remote}"
    src, dst = (str(lp), rspec) if direction == "up" else (rspec, str(lp))

    def argv(tmp: Path) -> list[str]:
        opts = ssh_args(tmp, acct, jump)
        opts = [("-P" if o == "-p" else o) for o in opts]  # scp spells the port -P
        return [*opts, *(["-r"] if recursive else []), "-q", "--", src, dst]

    try:
        res = runner.run_cli("scp", [], cwd=None, secrets=[], ssh_key=keys_of(acct, jump),
                             account=account, timeout=timeout, argv_fn=argv).as_dict()
    except runner.RunnerError as e:
        return {"ok": False, "reason": str(e)}
    res.update({"account": account, "class": cls, "direction": direction})
    return res


def account_for_sudo(host: str, user: str, data: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """An ssh account for a sudo target: same user, and host (or account
    name) equal to the sudo host."""
    for ref, a in sorted(data["accounts"].items()):
        if a.get("kind") == "ssh" and a.get("user") == user and (
                a.get("host") == host or ref.split(":", 1)[1] == host):
            return ref, a
    return None
