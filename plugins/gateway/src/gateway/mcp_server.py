"""Minimal MCP stdio server for gateway — pure standard library.

Implements just enough of the Model Context Protocol to expose tools over
stdio JSON-RPC: initialize, tools/list, tools/call — plus a server-to-client
`elicitation/create` request, used to get the USER's approval for actions whose
policy tier is "ask". The model has no way to approve on the user's behalf.
No third-party dependencies, so it runs anywhere the plugin's pixi Python runs.
"""
from __future__ import annotations

import itertools
import json
import sys
from collections import deque
from typing import Any

from . import __version__, actions, ghops, gitops, hfops, mirrors, pijulops, policy, vault

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")

_PRIV_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "host": {"type": "string",
                 "description": "'localhost', an ssh alias, host name or IP"},
        "user": {"type": "string",
                 "description": "only if several users are stored for the host"},
        "argv": {"type": "array", "items": {"type": "string"},
                 "description": "e.g. [\"systemctl\", \"restart\", \"caddy\"]"},
        "timeout": {"type": "integer", "default": 120,
                    "description": "seconds, max 600"},
    },
    "required": ["host", "argv"],
}

_GIT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "args": {"type": "array", "items": {"type": "string"},
                 "description": "git arguments without 'git', e.g. [\"push\", \"origin\", \"main\"]"},
        "cwd": {"type": "string", "description": "the repository (absolute path); for clone, "
                                                 "the directory to clone into"},
        "account": {"type": "string", "description": "KIND:NAME, only to choose between "
                                                     "several accounts that fit the remote"},
        "timeout": {"type": "integer", "default": 300},
    },
    "required": ["args", "cwd"],
}
_GH_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "args": {"type": "array", "items": {"type": "string"},
                 "description": "gh arguments without 'gh', e.g. [\"pr\", \"list\"]"},
        "cwd": {"type": "string", "description": "a repository (absolute path), so gh knows "
                                                 "the repo and the account"},
        "account": {"type": "string", "description": "github:NAME"},
        "timeout": {"type": "integer", "default": 300},
    },
    "required": ["args"],
}

_HF_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "args": {"type": "array", "items": {"type": "string"},
                 "description": "hf arguments without 'hf', e.g. [\"download\", \"org/model\"]"},
        "cwd": {"type": "string", "description": "working directory (absolute path)"},
        "account": {"type": "string", "description": "hf:NAME"},
        "timeout": {"type": "integer", "default": 1800},
    },
    "required": ["args"],
}

_PIJUL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "args": {"type": "array", "items": {"type": "string"},
                 "description": "pijul arguments without 'pijul', e.g. [\"record\", \"-a\", \"-m\", \"msg\"]"},
        "cwd": {"type": "string", "description": "the repository (absolute path)"},
        "account": {"type": "string", "description": "pijul:NAME"},
        "timeout": {"type": "integer", "default": 600},
    },
    "required": ["args", "cwd"],
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "http_request",
        "description": (
            "Make an HTTP request (any method, custom headers, body). Use this "
            "INSTEAD OF curl, wget, Invoke-WebRequest, or Invoke-RestMethod. For "
            "simply reading a web page, prefer the built-in WebFetch tool. "
            "Only http:// and https:// URLs. If policy requires approval, the "
            "user is prompted directly. Authenticate with auth_ref = the NAME of "
            "a secret the user stored with /secret (see secret_list or the "
            "session's vault catalog); it is sent only to hosts the user allowed "
            "and its value is never shown to you."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "method": {"type": "string", "default": "GET"},
                "url": {"type": "string"},
                "headers": {"type": "object"},
                "body": {"type": "string"},
                "auth_ref": {"type": "string",
                             "description": "Secret NAME from the vault (e.g. HF_TOKEN), or an account with a token (e.g. github:work)"},
                "auth_header": {"type": "string", "default": "Authorization",
                                "description": "Header to put the secret in, e.g. X-Api-Key"},
                "auth_scheme": {"type": "string", "default": "Bearer",
                                "description": "Prefix before the value; \"\" for the raw value"},
            },
            "required": ["url"],
        },
    },
    {
        "name": "download",
        "description": ("Download a file to the quarantine folder (not executed; "
                        "never overwrites; size-capped). Use INSTEAD OF curl -O / wget."),
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
            "required": ["url"],
        },
    },
    {
        "name": "port_check",
        "description": ("Check whether TCP ports are reachable on a host you "
                        "operate. Use INSTEAD OF nmap/masscan for simple up/down "
                        "connectivity checks. The user may be asked to approve."),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "ports": {"type": "array", "items": {"type": "integer"}},
            },
            "required": ["target"],
        },
    },
    {
        "name": "secret_list",
        "description": ("List the vault's secrets (names, descriptions, allowed "
                        "hosts) and stored sudo targets. Never returns values. Use "
                        "INSTEAD OF `security find/dump`, cmdkey, or certutil -store."),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "secret_use",
        "description": ("Check that a vault secret NAME exists and which hosts it "
                        "may be sent to, without revealing its value."),
        "inputSchema": {
            "type": "object",
            "properties": {"ref": {"type": "string"}},
            "required": ["ref"],
        },
    },
    {
        "name": "run_privileged",
        "description": ("Run one command as root (sudo) on 'localhost' or on a "
                        "host with a stored sudo password, where the user has "
                        "ENABLED sudo: it runs without asking. On a host where "
                        "sudo is disabled it is refused: use run_privileged_confirm "
                        "instead. The sudo password is injected by the gateway "
                        "and never shown to you. Remote hosts are reached with "
                        "ssh keys. Pass the command as an argv list, not a shell "
                        "string; it gets no stdin. Network/credential tools "
                        "(curl, wget, ...) are refused here too."),
        "inputSchema": _PRIV_SCHEMA,
    },
    {
        "name": "run_privileged_confirm",
        "description": ("Same as run_privileged, for hosts where sudo is disabled: "
                        "the user approves each call in Claude Code's permission "
                        "prompt, seeing the exact host and argv."),
        "inputSchema": _PRIV_SCHEMA,
    },
    {
        "name": "cert_inspect",
        "description": ("Inspect a server's TLS certificate (subject, issuer, "
                        "expiry, SANs, SHA-256 fingerprint). Works on self-signed or "
                        "expired certs too: `verified` and `verify_error` say whether "
                        "normal validation passed. Use INSTEAD OF certutil / "
                        "openssl s_client."),
        "inputSchema": {
            "type": "object",
            "properties": {"host": {"type": "string"},
                           "port": {"type": "integer", "default": 443}},
            "required": ["host"],
        },
    },
    {
        "name": "file_hash",
        "description": "Hash a local file. Use INSTEAD OF certutil -hashfile.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"},
                           "algo": {"type": "string", "default": "sha256"}},
            "required": ["path"],
        },
    },
    {
        "name": "account_list",
        "description": ("The user's gateway accounts (KIND:NAME, e.g. github:work): kind, "
                        "login, owners/hosts they are for, methods (token, ssh_key), prompt "
                        "policy. Never values. The git and gh tools pick the matching "
                        "account themselves; pass account= only to choose between several."),
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "git",
        "description": ("Run ANY git command (use INSTEAD OF git in Bash). Local commands run "
                        "without credentials. fetch/pull/push/clone/ls-remote use the "
                        "user's account for that remote's host and owner (token for https, "
                        "SSH key for ssh), never the user's own environment. If the "
                        "account's policy asks first, the call is refused with use: "
                        "git_confirm: then call git_confirm with the same arguments. Plain "
                        "force pushes are refused (use --force-with-lease via git_confirm). "
                        "Non-interactive only: pass -m messages, no editors or -i/-p."),
        "inputSchema": _GIT_SCHEMA,
    },
    {
        "name": "git_confirm",
        "description": ("Same as git, after Claude Code asks the user: for calls the account's "
                        "policy marks ask (often deletes or force-with-lease), or that the "
                        "user should see first."),
        "inputSchema": _GIT_SCHEMA,
    },
    {
        "name": "git_identity",
        "description": ("Make this repo commit as an account: sets the repo's own user.name "
                        "and user.email from the account (and gateway.account). No secrets."),
        "inputSchema": {"type": "object",
                        "properties": {"cwd": {"type": "string", "description": "the repo (absolute path)"},
                                       "account": {"type": "string", "description": "KIND:NAME"}},
                        "required": ["cwd", "account"]},
    },
    {
        "name": "gh",
        "description": ("Run GitHub's CLI as a gateway account (use INSTEAD OF gh in Bash): "
                        "pr/issue/run/release/repo view|list|create|..., gh api. The account "
                        "comes from account=, else the repo's origin, else the only GitHub "
                        "account. Refused: auth, extensions, alias, config, browse/--web, "
                        "repo clone/sync, pr checkout, and repo create/fork with clone/push/remote options (use the git tool). If the "
                        "policy asks first, call gh_confirm with the same arguments."),
        "inputSchema": _GH_SCHEMA,
    },
    {
        "name": "git_mirror",
        "description": ("Keep a repo's branches and tags the same on several remotes (e.g. "
                        "personal and work GitHub), each fetched/pushed as its own account. "
                        "action: status (compare), sync (fast-forward the remotes that are "
                        "behind; diverged branches and conflicting tags are left alone, never "
                        "forced), add/remove (the saved set, in the repo's gateway.mirror "
                        "config). See the accounts skill."),
        "inputSchema": {"type": "object", "properties": {
            "cwd": {"type": "string", "description": "the repo (absolute path)"},
            "action": {"type": "string", "enum": ["status", "sync", "add", "remove"]},
            "remotes": {"type": "array", "items": {"type": "string"},
                        "description": "remote names; default: the saved set"},
            "branches": {"type": "array", "items": {"type": "string"},
                         "description": "only these branches (default: all on any remote)"},
            "tags": {"type": "boolean", "default": True}},
            "required": ["cwd", "action"]},
    },
    {
        "name": "hf",
        "description": ("Run the Hugging Face CLI as a gateway account (use INSTEAD OF hf / "
                        "huggingface-cli in Bash): download, upload (Xet), repo create/delete, "
                        "ls, jobs, cache. The account comes from account=, else the repo id's "
                        "owner, else the only HF account. Sign-in (hf auth) is the gateway's. "
                        "Git pushes to the Hub go through the git tool. If the policy asks "
                        "first, call hf_confirm with the same arguments."),
        "inputSchema": _HF_SCHEMA,
    },
    {
        "name": "hf_confirm",
        "description": "Same as hf, after Claude Code asks the user.",
        "inputSchema": _HF_SCHEMA,
    },
    {
        "name": "pijul",
        "description": ("Run ANY pijul command as a gateway Pijul account (use INSTEAD OF pijul "
                        "in Bash): init/add/record/log/diff/channel locally; push/pull/clone "
                        "over ssh://user@host/owner/repo (the Nest is nest.pijul.com). record "
                        "signs with the account's key; push/pull authenticate with it. The "
                        "user's own pijul config and identities are never used. If the "
                        "policy asks first, call pijul_confirm with the same arguments."),
        "inputSchema": _PIJUL_SCHEMA,
    },
    {
        "name": "pijul_confirm",
        "description": "Same as pijul, after Claude Code asks the user.",
        "inputSchema": _PIJUL_SCHEMA,
    },
    {
        "name": "gh_confirm",
        "description": "Same as gh, after Claude Code asks the user.",
        "inputSchema": _GH_SCHEMA,
    },
]


class Server:
    """Stdio JSON-RPC loop. Holds client capabilities so tools can elicit."""

    def __init__(self, stdin=None, stdout=None):
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.client_caps: dict[str, Any] = {}
        self._ids = itertools.count(1)
        self._backlog: deque[dict[str, Any]] = deque()

    # -- transport ---------------------------------------------------------
    def send(self, obj: dict[str, Any]) -> None:
        self.stdout.write(json.dumps(obj) + "\n")
        self.stdout.flush()

    def _read(self) -> dict[str, Any] | None:
        while True:
            line = self.stdin.readline()
            if not line:
                return None
            line = line.strip()
            if not line:
                continue
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue

    def result(self, rid: Any, result: dict[str, Any]) -> None:
        self.send({"jsonrpc": "2.0", "id": rid, "result": result})

    # -- approval via elicitation -----------------------------------------
    def form(self, message: str, properties: dict[str, Any] | None = None,
             required: list[str] | None = None) -> dict[str, Any] | bool | None:
        """Show the USER an in-app form (MCP elicitation). Returns the
        submitted fields (a dict) if accepted, False if declined/cancelled, or
        None if this client can't show forms. The model never sees the answer:
        it goes from the client straight back to this server."""
        if "elicitation" not in self.client_caps:
            return None
        schema: dict[str, Any] = {"type": "object", "properties": properties or {}}
        if required:
            schema["required"] = required
        eid = f"gateway-elicit-{next(self._ids)}"
        self.send({"jsonrpc": "2.0", "id": eid, "method": "elicitation/create",
                   "params": {"message": message, "requestedSchema": schema}})
        while True:
            msg = self._read()
            if msg is None:
                return None
            if msg.get("id") == eid and "method" not in msg:
                res = msg.get("result") or {}
                # Diagnostics only: the client's action/error, never field values.
                policy.audit("elicitation_result", {
                    "action": res.get("action"), "error": msg.get("error"),
                    "fields": sorted(properties or {}),
                    "returned_fields": sorted(res.get("content") or {})})
                if "error" in msg:
                    return None
                if res.get("action") != "accept":
                    return False
                return dict(res.get("content") or {})
            if msg.get("method") == "ping" and msg.get("id") is not None:
                self.result(msg["id"], {})
            else:
                self._backlog.append(msg)  # handle after this call finishes

    def approve(self, message: str, remember: str | None = None) -> bool | str | None:
        """Yes/no question. True, "always" (the `remember` checkbox ticked),
        False (declined), or None if this client can't show a prompt."""
        props = ({"remember": {"type": "boolean", "title": remember, "default": False}}
                 if remember else {})
        answer = self.form(message, props)
        if not isinstance(answer, dict):
            return answer
        return "always" if remember and answer.get("remember") is True else True

    # -- dispatch ----------------------------------------------------------
    def handle(self, msg: dict[str, Any]) -> None:
        method = msg.get("method")
        rid = msg.get("id")
        params = msg.get("params") or {}

        if method == "initialize":
            self.client_caps = params.get("capabilities") or {}
            asked = params.get("protocolVersion")
            self.result(rid, {
                "protocolVersion": asked if asked in SUPPORTED_VERSIONS
                else PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "gateway", "version": __version__},
            })
        elif method == "notifications/initialized":
            pass  # no response to notifications
        elif method == "tools/list":
            self.result(rid, {"tools": TOOLS})
        elif method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments") or {}
            try:
                out = dispatch(name, args, self.approve, self.form)
            except Exception as e:  # noqa: BLE001
                out = {"ok": False, "reason": f"{type(e).__name__}: {e}"}
            self.result(rid, {
                "content": [{"type": "text", "text": json.dumps(out, indent=2)}],
                "isError": not out.get("ok", False),
            })
        elif method == "ping":
            self.result(rid, {})
        elif rid is not None and method is not None:
            self.send({"jsonrpc": "2.0", "id": rid,
                       "error": {"code": -32601,
                                 "message": f"method not found: {method}"}})

    def run(self) -> None:
        while True:
            msg = self._backlog.popleft() if self._backlog else self._read()
            if msg is None:
                return
            self.handle(msg)


def dispatch(name: str, args: dict[str, Any],
             approve: actions.Approver = None, form: Any = None) -> dict[str, Any]:
    if name == "http_request":
        return actions.http_request(
            args.get("method", "GET"), args["url"], args.get("headers"),
            args.get("body"), args.get("auth_ref"), approve=approve,
            auth_header=args.get("auth_header", "Authorization"),
            auth_scheme=args.get("auth_scheme", "Bearer"))
    if name == "download":
        return actions.download(args["url"], approve=approve)
    if name == "port_check":
        return actions.port_check(args["target"], args.get("ports"), approve=approve)
    if name == "secret_list":
        return actions.secret_list(approve=approve)
    if name == "secret_use":
        return actions.secret_use_check(args["ref"], approve=approve)
    if name in ("run_privileged", "run_privileged_confirm"):
        return actions.run_privileged(args["host"], args["argv"], args.get("user"),
                                      args.get("timeout", 120), approve=approve,
                                      confirmed=name == "run_privileged_confirm")
    if name == "cert_inspect":
        return actions.cert_inspect(args["host"], args.get("port", 443))
    if name == "file_hash":
        return actions.file_hash(args["path"], args.get("algo", "sha256"))
    if name == "account_list":
        cat = vault.catalog()
        policy.audit("account_list", {})
        return {"ok": True, "accounts": cat["accounts"],
                "note": "Never values. Missing one? Ask the user to run /gate:account add "
                        "KIND NAME <description> (or /gate:account login KIND:NAME for SSO)."}
    if name in ("git", "git_confirm"):
        return gitops.git_tool(args.get("args"), args.get("cwd", ""), args.get("account"),
                               confirmed=name == "git_confirm",
                               timeout=min(int(args.get("timeout", 300)), 1800))
    if name == "git_identity":
        return gitops.git_identity(args.get("cwd", ""), args.get("account", ""))
    if name == "git_mirror":
        return mirrors.git_mirror(args.get("cwd", ""), args.get("action", "status"),
                                  args.get("remotes"), args.get("branches"),
                                  args.get("tags", True))
    if name in ("hf", "hf_confirm"):
        return hfops.hf_tool(args.get("args"), args.get("cwd"), args.get("account"),
                             confirmed=name == "hf_confirm",
                             timeout=min(int(args.get("timeout", 1800)), 7200))
    if name in ("pijul", "pijul_confirm"):
        return pijulops.pijul_tool(args.get("args"), args.get("cwd", ""), args.get("account"),
                                   confirmed=name == "pijul_confirm",
                                   timeout=min(int(args.get("timeout", 600)), 3600))
    if name in ("gh", "gh_confirm"):
        return ghops.gh_tool(args.get("args"), args.get("cwd"), args.get("account"),
                             confirmed=name == "gh_confirm",
                             timeout=min(int(args.get("timeout", 300)), 1800))
    return {"ok": False, "reason": f"unknown tool {name}"}


def main() -> None:
    Server().run()


if __name__ == "__main__":
    main()
