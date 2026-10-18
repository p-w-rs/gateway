"""Shared policy core for the gateway plugin.

Used by the MCP server, the PreToolUse hook, and the gateway CLI so that every
route into the network / credential / certificate surface applies the same
allowlists, approval tiers, redaction, and audit logging.

Pure standard library only — no third-party imports.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------


def plugin_root() -> Path:
    """Root of the plugin, resolved from env or this file's location.

    The env value is only trusted when it is an absolute, existing directory:
    Claude Code does not expand ${CLAUDE_PLUGIN_ROOT} inside an .mcp.json "env"
    block, and a literal "${CLAUDE_PLUGIN_ROOT}" would otherwise resolve
    relative to the session's cwd (config not found, logs written there).
    """
    env = os.environ.get("CLAUDE_PLUGIN_ROOT", "")
    if env and "${" not in env and Path(env).is_absolute() and Path(env).is_dir():
        return Path(env)
    # src/gateway/policy.py -> plugin root is two parents up from src/
    return Path(__file__).resolve().parents[2]


def config_path() -> Path:
    override = os.environ.get("GATEWAY_CONFIG")
    if override:
        return Path(override)
    return plugin_root() / "config" / "policy.json"


def audit_log_path() -> Path:
    override = os.environ.get("GATEWAY_AUDIT_LOG")
    if override:
        return Path(override)
    return plugin_root() / "logs" / "audit.jsonl"


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

DEFAULT_CONFIG: dict[str, Any] = {
    # Take-over: redirect git, gh, hf, pijul, asiml, dvc, az, databricks, ssh,
    # scp, rsync-to-host, docker/podman login|push|pull, skopeo, oras and
    # crane in Bash to the gateway's account tools (TAKEOVER below).
    "takeover": False,
    # Domains Claude may reach without asking. "*" means all hosts are in
    # scope (the user chose this), but writes still follow approval tiers.
    "allow_domains": ["*"],
    # Hosts/subnets that reachability checks may target. "*" = all.
    "scan_scope": ["*"],
    # Approval tiers: auto (run), ask (prompt the user), refuse (never).
    # These defaults apply only when config/policy.json is missing or invalid,
    # so they err on the side of asking.
    "approvals": {
        "read_request": "auto",      # GET/HEAD to allowed domains
        "write_request": "ask",      # POST/PUT/PATCH/DELETE
        "download": "ask",
        "port_check": "ask",
        "secret_list": "ask",        # names only, never values
        "secret_use": "ask",         # inject by reference, value hidden
        "secret_reveal": "refuse",   # expose a raw secret value
        "secret_write": "ask",       # create/update/delete a secret
        "cert_inspect": "auto",
        "file_hash": "auto",
        "run_privileged": "ask",     # always asks, whatever is set (ALWAYS_ASK)
    },
    "max_response_bytes": 5_000_000,
    "download_dir": "quarantine",
    # Field NAMES whose values are replaced wholesale.
    "redact_patterns": [
        r"(?i)(authorization|x-api-key|api[-_]?key|token|secret|password|bearer)",
    ],
    # Secret-looking VALUES scrubbed from every string in an audit record.
    # Each entry is [regex, replacement].
    "redact_value_patterns": [
        # scheme://user:pass@host
        [r"(?i)\b([a-z][a-z0-9+.-]*://)[^/\s:@]+:[^/\s@]+@", r"\1***:***@"],
        # Authorization: Bearer xyz / Basic xyz / token xyz
        [r"(?i)\b(bearer|basic|token)(\s+)[A-Za-z0-9._~+/=-]{6,}", r"\1\2***REDACTED***"],
        # key=value / key: value for secret-looking names (headers, query, JSON)
        # (not names that end in expiration/expires/expiry: those carry dates)
        [r"(?i)\b([\w-]*(?:api[-_]?key|token|secret|password|passwd|pwd|"
         r"authorization|cookie)[\w-]*)(?<!expiration)(?<!expires)(?<!expiry)"
         r"([\"']?\s*[:=]\s*[\"']?)[^\s&\"',;]+",
         r"\1\2***REDACTED***"],
        # curl -u user:pass / --user user:pass
        [r"(\s(?:-u\s*|--user[=\s]+))\S+", r"\1***REDACTED***"],
        # Well-known token shapes
        [r"\b(?:gh[pousr]|github_pat)_[A-Za-z0-9_]{10,}", "***REDACTED***"],
        [r"\bsk-[A-Za-z0-9_-]{16,}", "***REDACTED***"],
        [r"\bAKIA[0-9A-Z]{16}\b", "***REDACTED***"],
        [r"\bxox[abprs]-[A-Za-z0-9-]{10,}", "***REDACTED***"],
    ],
}

ALLOWED_SCHEMES = ("http", "https")


def load_config() -> dict[str, Any]:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    p = config_path()
    if p.exists():
        try:
            user = json.loads(p.read_text())
            for k, v in user.items():
                if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
        except Exception as e:
            sys.stderr.write(f"gateway: ignoring unreadable {p}: {e}\n")
    # Machine-local switches next to it (gitignored, so `install --strict`
    # leaves the checkout clean). Only "takeover" is read from there.
    lp = p.with_name("local.json")
    if lp.exists():
        try:
            local = json.loads(lp.read_text())
            if isinstance(local.get("takeover"), bool):
                cfg["takeover"] = local["takeover"]
        except Exception as e:
            sys.stderr.write(f"gateway: ignoring unreadable {lp}: {e}\n")
    return cfg


# ---------------------------------------------------------------------------
# Allowlist checks
# ---------------------------------------------------------------------------


def host_allowed(host: str, patterns: list[str]) -> bool:
    if not host:
        return False
    if "*" in patterns:
        return True
    host = host.lower()
    for pat in patterns:
        pat = pat.lower()
        if host == pat or fnmatch.fnmatch(host, pat):
            return True
        # bare-domain pattern also matches subdomains
        if host.endswith("." + pat):
            return True
    return False


def url_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def url_scheme_ok(url: str) -> bool:
    """Only http(s) — urllib would otherwise happily open file://, ftp://, data:."""
    try:
        return urlparse(url).scheme.lower() in ALLOWED_SCHEMES
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------


def scrub(text: str, cfg: dict[str, Any]) -> str:
    """Scrub secret-looking values out of a free-form string."""
    for pat, repl in cfg.get("redact_value_patterns", []):
        text = re.sub(pat, repl, text)
    return text


def redact(obj: Any, cfg: dict[str, Any]) -> Any:
    """Recursively redact secret-named fields and scrub secret-looking values."""
    pats = [re.compile(p) for p in cfg.get("redact_patterns", [])]

    def looks_secret(name: str) -> bool:
        return any(p.search(name) for p in pats)

    def walk(o: Any) -> Any:
        if isinstance(o, dict):
            return {k: "***REDACTED***" if isinstance(k, str) and looks_secret(k)
                    else walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        if isinstance(o, str):
            return scrub(o, cfg)
        return o

    return walk(obj)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------


def audit(event: str, detail: dict[str, Any]) -> None:
    cfg = load_config()
    path = audit_log_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "event": event,
            "detail": redact(detail, cfg),
        }
        with path.open("a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Decision model
# ---------------------------------------------------------------------------


@dataclass
class Decision:
    allowed: bool
    needs_ask: bool
    reason: str = ""
    notes: list[str] = field(default_factory=list)


# Actions that ask the user every time, whatever policy.json says.
ALWAYS_ASK = {"run_privileged"}


def decide(action: str, *, host: str = "", cfg: dict[str, Any] | None = None) -> Decision:
    cfg = cfg or load_config()
    tier = cfg.get("approvals", {}).get(action, "ask")

    if tier == "refuse":
        return Decision(False, False, reason=f"Action '{action}' is refused by policy.")
    if action in ALWAYS_ASK:
        return Decision(True, True, reason="This runs as root and always needs your approval.")

    # Host scope checks for network actions.
    if action in ("read_request", "write_request", "download"):
        if host and not host_allowed(host, cfg.get("allow_domains", [])):
            return Decision(
                True, True,
                reason=f"Host '{host}' is outside allow_domains; user approval required.",
            )
    if action == "port_check":
        if host and not host_allowed(host, cfg.get("scan_scope", [])):
            return Decision(
                True, True,
                reason=f"Target '{host}' is outside scan_scope; user approval required.",
            )

    if tier == "ask":
        return Decision(True, True, reason=f"Action '{action}' requires user approval.")
    return Decision(True, False, reason="auto")


# ---------------------------------------------------------------------------
# Blocked-command detection (used by the hook)
# ---------------------------------------------------------------------------

# Each entry: (compiled regex, short name, suggested gateway route).
_BLOCKED = [
    (r"\bcurl\b", "curl", "WebFetch (to read) or the http_request tool (for APIs)"),
    (r"\bwget\b", "wget", "WebFetch (to read) or the download tool (for files)"),
    (r"\b(nmap|masscan)\b", "nmap/masscan", "the port_check tool"),
    (r"\bcertutil\b", "certutil", "the cert_inspect or file_hash tool"),
    (r"\bcmdkey\b", "cmdkey", "the secret_list / secret_use tools"),
    (r"\bsecurity\b\s+\b(find|add|delete|dump|set|export|import)\b[-\w]*",
     "security (keychain)", "the secret_list / secret_use tools"),
    (r"(?i)\b(invoke-webrequest|invoke-restmethod|iwr|irm)\b",
     "Invoke-WebRequest/RestMethod", "WebFetch or the http_request tool"),
    # Common evasions: absolute paths, env/exec wrappers.
    (r"/(usr/bin|bin|opt/\S+?/bin)/(curl|wget)\b", "curl/wget (full path)",
     "WebFetch or the http_request / download tools"),
    (r"(?i)\bpython3?\b.*-c.*\b(requests|urllib|http\.client|socket)\b",
     "python inline network call", "the http_request tool"),
    (r"(?i)\bnode\b.*-e.*\bfetch\s*\(", "node inline fetch", "the http_request tool"),
    # Secret stores: values must stay inside the gateway. The gateway's own
    # vault, and the user's personal `secret` store, which is not Claude's.
    (r"gateway/(key\.txt|store\.age)|\.config/gateway\b",
     "gateway vault file", "secret_list for names; values are never shown"),
    (r"\bage\b[^|;&]*\s(-d|--decrypt)\b", "age --decrypt",
     "the secret's NAME as auth_ref on http_request (secret_list shows names)"),
    (r"\bsecret\s+(get|run|edit|reload)\b", "the user's personal secret store",
     "only secrets the user added with /secret (secret_list shows names)"),
    (r"age/keys\.txt|secrets\.env\.age", "the user's personal age store",
     "only secrets the user added with /secret (secret_list shows names)"),
]

_BLOCKED_COMPILED = [(re.compile(p), name, route) for p, name, route in _BLOCKED]


# A command word at a command position: the start, after ; & | ( ` $( or a
# newline, after sudo/env/exec/time/nohup/xargs/then/do/else (with their
# options), and after VAR=value assignments. So `echo git`, `ssh-keygen` or
# `cat .gitignore` don't match.
_CMD = (r"(?:^|[;&|(`\n]\s*|\$\(\s*|\b(?:sudo|env|command|exec|time|nohup|xargs|then|do|"
        r"else)\s+(?:-\S+\s+)*)(?:\w+=\S*\s+)*(?:\S*/)?")
TAKEOVER = [
    (_CMD + r"git(?:-lfs|-xet)?(?=\s|$)", "git",
     "the git tool (every git command; remote ones run as the right account), "
     "git_mirror for mirrors"),
    (_CMD + r"gh(?=\s|$)", "gh", "the gh tool (GitHub CLI as an account)"),
    (_CMD + r"(?:hf|huggingface-cli)(?=\s|$)", "hf", "the hf tool (Hugging Face as an account)"),
    (_CMD + r"pijul(?=\s|$)", "pijul", "the pijul tool (Pijul as an account)"),
    (_CMD + r"(?:asiml|dvc)(?=\s|$)", "asiml/dvc",
     "mlcat (catalog search) and mlcat_workspace (init/clone/pull/push/status)"),
    (_CMD + r"az(?=\s|$)", "az",
     "http_request with auth_ref=azure:NAME and auth_scope (arm, storage, graph, ...); "
     "the Azure CLI isn't used"),
    (_CMD + r"(?:databricks|mlflow)(?=\s|$)", "databricks", "the databricks tool"),
    (_CMD + r"(?:ssh|scp|sftp|sshpass)(?=\s|$)", "ssh/scp/sftp",
     "ssh_exec / ssh_copy (an ssh account), or run_privileged for root"),
    (_CMD + r"rsync\b[^;&|\n]*\s(?:\S+@)?[A-Za-z0-9.\-\[\]]+:", "rsync to a host",
     "ssh_copy (an ssh account)"),
    (_CMD + r"(?:docker|podman)\s+(?:\S+\s+)*?(?:login|push|pull|logout)\b",
     "docker/podman registry", "the registry tool (crane as a registry account, no daemon)"),
    (_CMD + r"(?:skopeo|oras|crane)(?=\s|$)", "skopeo/oras/crane", "the registry tool"),
    # Ways back to the user's ssh-agent after the hook unsets SSH_AUTH_SOCK.
    (_CMD + r"ssh-add(?=\s|$)", "ssh-add", "an ssh account's key (ssh_exec / ssh_copy / git)"),
    (r"\blaunchctl\s+getenv\s+SSH_AUTH_SOCK\b|com\.apple\.launchd\.[^/\s]*/Listeners",
     "the user's ssh-agent", "an ssh account's key (ssh_exec / ssh_copy / git)"),
]
_TAKEOVER_COMPILED = [(re.compile(p), name, route) for p, name, route in TAKEOVER]


def match_takeover(command: str, cfg: dict[str, Any] | None = None) -> tuple[str, str] | None:
    """With takeover on, (tool_name, route) for a Bash command an account tool replaces."""
    cfg = cfg if cfg is not None else load_config()
    if not cfg.get("takeover"):
        return None
    for rx, name, route in _TAKEOVER_COMPILED:
        if rx.search(command):
            return name, route
    return None


def match_blocked(command: str) -> tuple[str, str] | None:
    """Return (tool_name, suggested_route) if the command should be redirected."""
    for rx, name, route in _BLOCKED_COMPILED:
        if rx.search(command):
            return name, route
    # The vault's actual folder, wherever GATEWAY_HOME / XDG_CONFIG_HOME put it.
    from . import vault
    if str(vault.home()) in command:
        return "gateway vault file", "secret_list for names; values are never shown"
    return None
