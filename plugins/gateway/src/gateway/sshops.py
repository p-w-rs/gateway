"""The ssh_exec, ssh_copy and ssh_hosts tools: servers as `ssh` accounts.

Each call starts a private ssh-agent with the account's keys (and its jump
hosts'), writes the gateway's own ssh_config and known_hosts for that call
(sshconf.py) and runs OpenSSH with `-F` that file only: BatchMode,
IdentitiesOnly, pinned host keys under one alias across routes,
StrictHostKeyChecking=yes, no forwarding. The command runs as an argv list
joined once with shell quoting (no shell strings). Copies use scp in its
default SFTP mode, so remote paths aren't shell-expanded. run_privileged
uses the same path when an ssh account matches its sudo target.

If the chosen route can't be reached or shows a different host key, the
next route is tried (a LAN address may be someone else's machine away from
home). A host key that changed on every route is replaced only for
accounts whose policy allows it (sshconf.refresh_host_keys).
"""
from __future__ import annotations

import os
import shlex
from pathlib import Path
from typing import Any, Callable

from . import gitops, policy, runner, sshconf, vault


def _session() -> str | None:
    return os.environ.get("CLAUDE_CODE_SESSION_ID") or None


def _unreachable(stderr: str) -> bool:
    s = stderr.lower()
    return "ssh: connect to host" in s or "connection timed out during banner" in s


class Conn:
    """One account's chain (target + jump hosts), its chosen routes and keys."""

    def __init__(self, ref: str, data: dict[str, Any]):
        try:
            self.links = sshconf.chain(ref, data)
        except sshconf.SshError as e:
            raise gitops.GitRefused(str(e))
        self.ref, self.acct = ref, self.links[0][1]
        self.reuse = sshconf.reuse_on(ref, data, _session())
        self.skip: tuple[str, ...] = ()
        self.picked: dict[str, dict[str, str]] = {}
        self.why: dict[str, str] = {}
        self._pick()

    def _pick(self, use_cache: bool = True) -> None:
        for r, a in self.links:
            try:
                route, why = sshconf.pick(r, a, self.skip if r == self.ref else (), use_cache)
            except sshconf.SshError as e:
                raise gitops.GitRefused(str(e))
            self.picked[r], self.why[r] = route, why

    @property
    def target(self) -> str:
        return sshconf.alias(self.ref)

    def keys(self) -> list[str]:
        return [priv for _, a in self.links for priv, _ in sshconf.keys(a)]

    def options(self, tmp: Path) -> list[str]:
        return ["-F", str(sshconf.write_config(tmp, self.links, self.picked,
                                               runner._which("ssh"), self.reuse))]

    def _next_route(self) -> bool:
        left = [r for r in sshconf.routes(self.acct)
                if r["name"] not in self.skip and r["name"] != self.picked[self.ref]["name"]]
        if not left:
            return False
        self.skip += (self.picked[self.ref]["name"],)
        self._pick(use_cache=False)
        return True

    def run(self, tool: str, build: Callable[[list[str]], list[str]], *, secrets: list[str],
            timeout: float, stdin: bytes | None = None) -> dict[str, Any]:
        """Run ssh/scp with argv build(options); fail over to the next route
        when one is unreachable or shows a different host key."""
        notes = sshconf.first_pin(self.links, self.picked)
        refreshed = False
        while True:
            res = runner.run_cli(tool, [], cwd=None, secrets=secrets, ssh_key=self.keys(),
                                 account=self.ref, timeout=timeout, stdin=stdin,
                                 argv_fn=lambda tmp: build(self.options(tmp)))
            if res.ok:
                break
            if sshconf.host_key_failed(res.stderr) or _unreachable(res.stderr):
                if self._next_route():
                    continue
            if sshconf.host_key_failed(res.stderr) and not refreshed:
                refreshed = True
                changed = sshconf.refresh_host_keys(self.links, self.picked)
                if changed:
                    notes += changed
                    continue
            break
        out = res.as_dict()
        route = self.picked[self.ref]
        out.update({"account": self.ref, "host": route["host"], "route": route["name"]})
        if len(sshconf.routes(self.acct)) > 1:
            out["route_why"] = self.why[self.ref]
        if self.reuse:
            out["reuse"] = "on for this session"
        if notes:
            out["host_key_notes"] = notes
        if not res.ok and sshconf.host_key_failed(res.stderr):
            out["hint"] = (f"The server's host key isn't the pinned one. If it changed on "
                           f"purpose (reinstalled), ask the user to run /gate:update {self.ref}; "
                           "otherwise don't connect.")
        return out


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
        hit = policy.match_blocked(shlex.join(argv))
        if hit:
            raise gitops.GitRefused(f"'{hit[0]}' is not run through ssh_exec either; use {hit[1]}")
        acct = data["accounts"].get(account)
        if acct is None or acct.get("kind") != "ssh":
            raise gitops.GitRefused(f"{account} is not an ssh account; see account_list")
        refusal = _policy(account, acct, "exec", confirmed, data, "ssh_exec")
        if refusal is not None:
            return refusal
        conn = Conn(account, data)
    except (gitops.GitRefused, runner.RunnerError) as e:
        policy.audit("refused", {"action": "ssh_exec", "reason": str(e)[:200]})
        return {"ok": False, "refused": True, "reason": str(e)}
    try:
        res = conn.run("ssh", lambda o: [*o, "-T", "--", conn.target, shlex.join(argv)],
                       secrets=[], timeout=timeout)
    except (runner.RunnerError, sshconf.SshError) as e:
        return {"ok": False, "reason": str(e)}
    res["class"] = "exec"
    return res


def run_remote(ref: str, command: str, *, secrets: list[str], stdin: bytes | None,
               timeout: float) -> dict[str, Any]:
    """For run_privileged: one shell command line on an ssh account."""
    conn = Conn(ref, vault.load())
    return conn.run("ssh", lambda o: [*o, "-T", "--", conn.target, command],
                    secrets=secrets, timeout=timeout, stdin=stdin)


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
        acct = data["accounts"].get(account)
        if acct is None or acct.get("kind") != "ssh":
            raise gitops.GitRefused(f"{account} is not an ssh account; see account_list")
        cls = "write" if direction == "up" else "read"
        refusal = _policy(account, acct, cls, confirmed, data, "ssh_copy")
        if refusal is not None:
            return refusal
        conn = Conn(account, data)
    except (gitops.GitRefused, runner.RunnerError) as e:
        policy.audit("refused", {"action": "ssh_copy", "reason": str(e)[:200]})
        return {"ok": False, "refused": True, "reason": str(e)}
    rspec = f"{conn.target}:{remote}"
    src, dst = (str(lp), rspec) if direction == "up" else (rspec, str(lp))
    try:
        res = conn.run("scp", lambda o: [*o, *(["-r"] if recursive else []), "-q", "--",
                                         src, dst], secrets=[], timeout=timeout)
    except (runner.RunnerError, sshconf.SshError) as e:
        return {"ok": False, "reason": str(e)}
    res.update({"class": cls, "direction": direction})
    return res


def ssh_hosts(account: str = "", probe: bool = False) -> dict[str, Any]:
    """The ssh accounts as the gateway sees them: routes (and, with probe,
    which one it would use now and why), host-key policy and fingerprints,
    key fingerprints, reuse for this session. Never a value."""
    data = vault.load()
    out = []
    for ref, a in sorted(data["accounts"].items()):
        if a.get("kind") != "ssh" or (account and ref != account):
            continue
        h: dict[str, Any] = {
            "account": ref, "description": a.get("description", ""), "user": a.get("user"),
            "routes": sshconf.routes(a), "jump": a.get("jump") or None,
            "host_key_policy": sshconf.host_key_policy(a),
            "host_keys": vault.host_key_fingerprints(a.get("known_hosts", "")),
            "keys": [vault.fingerprint_of(pub) for _, pub in sshconf.keys(a) if pub],
            "reuse": "on for this session" if sshconf.reuse_on(ref, data, _session())
            else "off (the user can type /gate:enable reuse " + ref + ")",
            "comfort": {**sshconf.COMFORT, **(a.get("comfort") or {})}}
        if a.get("host_key_changed"):
            h["host_key_changed"] = a["host_key_changed"]
        if probe:
            route, why = sshconf.pick(ref, a, use_cache=False)
            h["would_use"] = {"route": route["name"], "why": why}
        out.append(h)
    if account and not out:
        return {"ok": False, "reason": f"{account} is not an ssh account; see account_list"}
    return {"ok": True, "hosts": out}


def account_for_sudo(host: str, user: str, data: dict[str, Any]) -> tuple[str, dict[str, Any]] | None:
    """An ssh account for a sudo target: same user, and host (or account
    name, or a route's host) equal to the sudo host."""
    for ref, a in sorted(data["accounts"].items()):
        if a.get("kind") == "ssh" and a.get("user") == user and (
                a.get("host") == host or ref.split(":", 1)[1] == host
                or any(r["host"] == host for r in sshconf.routes(a))):
            return ref, a
    return None
