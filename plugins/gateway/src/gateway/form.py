"""The form: ~/.config/gateway/gateway.toml (SPEC 2).

Reading:
- a lenient pre-pass turns bare `sudo = yes|no|on|off|ask|true|false` words
  (keys ssh, sudo, scripts, use, default, packages) into TOML values;
- tomllib parses it; a syntax error keeps the last good form (the caller passes
  it from the vault) and reports the line;
- every entry is validated on its own: a bad entry is disabled and reported
  (with its line and a "did you mean" for unknown keys); the others keep
  working. Unknown keys are warnings. Strings with control characters,
  newlines or bidi overrides are refused, and names or keys that aren't plain
  are never echoed back in a message.

Writing (the gateway never re-serializes the file): append a whole table with
a comment header, or replace one `key = value` line inside a known table; then
re-parse and roll back if anything else changed.
"""
from __future__ import annotations

import difflib
import hashlib
import ipaddress
import os
import re
import tomllib
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import paths

# ---------------------------------------------------------------------------
# Grammar
# ---------------------------------------------------------------------------

NAME_RE = re.compile(r"[a-z][a-z0-9-]{0,31}")
RESERVED = frozenset({"localhost", "local", "this", "all", "gateway", "gate", "settings"})
KINDS = ("github", "huggingface", "azure", "ml-catalog", "pijul", "registry", "api-key")
RIGHT_WORDS = {"true": True, "yes": True, "on": True, "false": False, "no": False,
               "off": False, "ask": "ask"}

USER_RE = re.compile(r"[A-Za-z_][A-Za-z0-9._-]{0,31}")
LABEL = r"[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?"
DNS_RE = re.compile(rf"(?=.{{1,253}}\Z){LABEL}(?:\.{LABEL})*")
OWNER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
LOGIN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@+-]{0,99}")
EMAIL_RE = re.compile(r"[^\s@<>\"]{1,64}@[^\s@<>\"]{1,190}\.[^\s@<>\"]{1,63}")
GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
STORAGE_RE = re.compile(r"[a-z0-9]{3,24}")
ENV_RE = re.compile(r"[A-Z_][A-Z0-9_]{0,63}")
PATH_RE = re.compile(r"/[A-Za-z0-9._/+-]{1,255}")
AUTH_RE = re.compile(r"bearer|basic|header:([A-Za-z0-9-]{1,64})(?::([!#$%&'*+.^_`|~0-9A-Za-z-]{1,32}))?"
                     r"|query:([A-Za-z0-9_.-]{1,64})")
SAFE_ECHO = re.compile(r"[A-Za-z0-9_.@:-]{1,48}")
# Characters refused in any form string: controls (Cc), invisible format
# characters (Cf: bidi overrides, zero-width joiners, soft hyphen, Unicode tag
# characters that hide text from a reader but not from the model), private use
# (Co), surrogates (Cs), line/paragraph separators (Zl, Zp), and the Hangul
# fillers that render as blanks.
UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Co", "Cs", "Zl", "Zp"})
UNSAFE_EXTRA = frozenset("\u115f\u1160\u3164\uffa0")
# A fast pre-check for the common cases (the category test decides).
UNSAFE = re.compile("[\x00-\x1f\x7f-\x9f\xad\u061c\u115f\u1160\u180e\u200b-\u200f"
                    "\u2028-\u202e\u2060-\u206f\u3164\ufeff\uffa0\ufff9-\ufffb]")


def _unsafe_char(c: str) -> bool:
    return c in UNSAFE_EXTRA or unicodedata.category(c) in UNSAFE_CATEGORIES


# Variables an account's `env` may not name (they would change how programs run).
ENV_DENY = re.compile(r"(PATH|HOME|SHELL|USER|LOGNAME|IFS|ENV|BASH_ENV|PS[1-4]|CDPATH|TMPDIR|"
                      r"TERM|LANG|LC_.*|LD_.*|DYLD_.*|PYTHON.*|PERL5.*|RUBY.*|NODE_.*|"
                      r"GIT_.*|SSH_.*|SUDO_.*|GW_.*|GATE_.*|GATEWAY_.*|CLAUDE.*|HISTFILE|"
                      r"PROMPT_COMMAND|ZDOTDIR|.*_PROXY|PROXY|.*_OPTIONS|SSL_.*|CURL_.*|"
                      r"REQUESTS_CA_BUNDLE|.*_CA_BUNDLE|.*_CA_CERTS?|.*CAFILE|.*CAPATH|"
                      r"EDITOR|VISUAL|PAGER|MANPAGER|BROWSER|MAKEFLAGS|.*_PRELOAD)")

# `.domain` api-key patterns that would cover other people's sites: two-label
# public suffixes (co.uk, com.au, ...) and shared hosting where every
# subdomain belongs to a different owner (github.io, azurewebsites.net, ...).
SECOND_LEVEL = frozenset({"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob",
                          "gouv", "nic", "mil", "ltd", "plc", "sch", "nhs", "me", "info", "biz",
                          "int", "web", "gen", "firm", "ind", "res", "nom", "asso", "id", "gr",
                          "lg", "ed", "mobi", "tv", "name", "pro", "police", "kiwi", "school"})
SHARED_SUFFIXES = frozenset({
    "github.io", "githubusercontent.com", "gitlab.io", "azurewebsites.net", "cloudapp.net",
    "azureedge.net", "azurestaticapps.net", "blob.core.windows.net", "core.windows.net",
    "windows.net", "trafficmanager.net", "cloudfront.net", "amazonaws.com",
    "s3.amazonaws.com", "elasticbeanstalk.com", "herokuapp.com", "herokudns.com",
    "appspot.com", "web.app", "firebaseapp.com", "run.app", "cloudfunctions.net",
    "vercel.app", "now.sh", "netlify.app", "pages.dev", "workers.dev",
    "ngrok.io", "ngrok-free.app", "ngrok.app", "fly.dev", "onrender.com", "repl.co",
    "glitch.me", "surge.sh", "readthedocs.io", "hf.space",
    "blogspot.com", "wordpress.com", "duckdns.org", "dyndns.org", "no-ip.org",
    "trycloudflare.com", "loca.lt", "serveo.net", "localtunnel.me", "nip.io", "sslip.io",
    "xip.io"})


def too_broad_site(bare: str) -> bool:
    """True if `.bare` would match subdomains owned by many different people."""
    b = bare.lower().strip(".")
    if b in SHARED_SUFFIXES:
        return True
    labels = b.split(".")
    if len(labels) < 2:
        return True
    return len(labels) == 2 and len(labels[1]) == 2 and labels[0] in SECOND_LEVEL

AZURE_CLI_CLIENT_ID = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
# A kind's host when the account doesn't say. ml-catalog has none: every
# catalog is its own service, so its account names it (`host`, required).
DEFAULT_HOSTS = {"github": "github.com", "pijul": "nest.pijul.com"}

HOST_KEYS = ("address", "when", "also", "via", "ssh", "sudo", "scripts", "note", "runtime",
             "policy", "workspaces", "shell")
# Git servers, not machines (review round 4): a host whose address is one of
# them would take over git's ssh routing to it (the ssh stand-in matches form
# hosts by address before account endpoints). The kind of account to add
# instead, or None when the gateway has none for it.
GIT_SERVERS: dict[str, str | None] = {
    "github.com": "github", "ssh.github.com": "github", "hf.co": "huggingface",
    "huggingface.co": "huggingface", "nest.pijul.com": "pijul", "gitlab.com": None,
    "bitbucket.org": None, "codeberg.org": None}


def git_server_note(host: str) -> str | None:
    """Why a host address that is a git server can't be a machine, or None."""
    h = (host or "").lower().rstrip(".")
    if h not in GIT_SERVERS:
        return None
    kind = GIT_SERVERS[h]
    if kind:
        return (f"{h} is a git server, not a machine: add a {kind} account (kind = \"{kind}\") "
                "instead of a host")
    return (f"{h} is a git server, not a machine, and the gateway has no account kind for it: use "
            "https for a public repository, or ask the user about others = \"mine\" in [settings]")
LOCALHOST_KEYS = ("sudo", "scripts", "note", "policy", "workspaces")
# sudo on this computer when the form doesn't say (no [hosts.localhost], or one
# without sudo): "ask", Claude Code asks each time, on a new install. An
# install whose vault an older gateway made (vault.older_install) keeps that
# gateway's default, true (apply_install_defaults). A remote host's ssh and
# sudo default to true.
LOCALHOST_SUDO = "ask"
LOCALHOST_SUDO_OLDER = True
# a host's `runtime` (PLAN-v4 phase 6): where the gateway stages its managed
# remote runtime on that host (daemon/remote.py base_ok says the same)
RUNTIME_RE = re.compile(r"(?:~/|/)[A-Za-z0-9._/@+-]{0,200}")
COMMON_KEYS = ("kind", "login", "owners", "default", "name", "email", "env", "scripts", "use",
               "note", "policy")
KIND_KEYS: dict[str, tuple[str, ...]] = {
    "github": ("host", "packages"),
    "huggingface": (),
    "azure": ("tenant", "client_id", "databricks", "storage", "registries", "sites"),
    "ml-catalog": ("host",),
    "pijul": ("host", "remote_pijul"),
    "registry": ("host",),
    "api-key": ("sites", "auth"),
}
IDENTITY_KINDS = ("github", "huggingface", "pijul")   # name / email for commits
ENV_KINDS = ("github", "huggingface", "azure", "api-key")
SETTINGS_KEYS = ("others",)
VAULT_KEYS = ("lock_after",)
SHELL_KEYS = ("managed", "import_path", "import_env")
TOP_KEYS = ("settings", "vault", "shell", "policy", "hosts", "accounts")
# Policy (PLAN-v4 phase 7, docs/dev/modules/policy.md): allow / ask / deny per
# action, layered on the rights above (ssh, sudo, an account's use) and never
# above them. Restrictions (the first list) default to what the right gives
# and can only lower it, at every scope: [policy] for every host and account,
# [hosts.NAME.policy], a workspace's own keys, [accounts.NAME.policy]; the
# strictest that applies wins. Grants (the second list: ssh agent, X11,
# remote and stdio forwarding) are off unless a host's own policy table turns
# them on; [policy] can only keep them off. A read grant never implies any
# other action. Raising or removing a restriction, and turning a grant on,
# are widenings (the user's OK in the gateway dialog, `gate check NAME`).
POLICY_WORDS = {"allow": True, "ask": "ask", "deny": False}
POLICY_RESTRICT = ("read", "exec", "write", "network", "elevation", "credential", "env_import",
                   "provision")
POLICY_GRANT = ("forward_agent", "forward_x11", "forward_remote", "forward_stdio")
HOST_POLICY_KEYS = ("read", "exec", "write", "network", "elevation", "credential", "env_import",
                    "provision") + POLICY_GRANT
LOCALHOST_POLICY_KEYS = ("read", "exec", "network", "elevation", "credential", "env_import")
WORKSPACE_POLICY_KEYS = ("read", "exec", "write")
ACCOUNT_POLICY_KEYS = ("credential", "write", "network")
GLOBAL_POLICY_KEYS = POLICY_RESTRICT + POLICY_GRANT
WORKSPACE_KEYS = ("root", "local", "note") + WORKSPACE_POLICY_KEYS
WORKSPACES_MAX = 32
# [hosts.NAME.shell] (PLAN-v4 phase 7): a remote host's imports for the
# managed shell there (the gateway's runtime): folders on that host for its
# PATH, and names whose values come from that host's own login environment.
HOST_SHELL_KEYS = ("import_path", "import_env")
# [shell] (PLAN-v4 phase 4, docs/dev/modules/managed.md): how Claude's Bash runs.
# managed = "on" (the default: the gateway's managed bash, a curated
# environment, never the login shell), "warn" (managed while Claude Code's
# mods run; without them, the user's own shell with a notice each session) or
# "off" (Claude Code's own shell, as before v4). import_path adds host
# folders to the managed PATH (after the stand-ins and runtime tools, before
# the system folders); import_env passes named variables from Claude Code's
# environment. Lowering `managed` and adding an import are widenings (the
# user's OK in the gateway dialog, `gate check settings`).
SHELL_MODES = {"on": "on", "warn": "warn", "off": "off"}
IMPORT_PATH_MAX = 32
IMPORT_ENV_MAX = 32
IMPORT_ENV_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
# Names the managed shell always passes or sets itself (gate-sh's list).
SHELL_PASSED = re.compile(r"(HOME|USER|LOGNAME|LANG|LC_[A-Za-z0-9_]*|TERM|TMPDIR|TZ|PWD|SHELL|"
                          r"XDG_(CONFIG|DATA|CACHE|STATE)_HOME|XDG_RUNTIME_DIR|"
                          r"__CF_USER_TEXT_ENCODING|CLAUDECODE|GIT_EDITOR|AI_AGENT|"
                          r"COREPACK_ENABLE_AUTO_PIN|NoDefaultCurrentDirectoryInExePath)")
# Names import_env refuses: the PATH (import_path is for that), what changes
# how a shell or the loader starts, the gateway's and Claude Code's own
# variables, the ssh/git/sudo plumbing the stand-ins own, and anything that
# looks like a credential (an account holds those).
IMPORT_ENV_DENY = re.compile(r"(PATH|IFS|ENV|BASH_ENV|BASH_FUNC_.*|SHELLOPTS|BASHOPTS|PS[0-4]|"
                             r"PROMPT_COMMAND|CDPATH|GLOBIGNORE|HISTFILE|ZDOTDIR|FPATH|"
                             r"LD_.*|DYLD_.*|GW_.*|GATE_.*|GATEWAY_.*|CLAUDE.*|ANTHROPIC_.*|"
                             r"GIT_SSH|GIT_SSH_COMMAND|GIT_ASKPASS|GIT_CONFIG.*|GIT_EXEC_PATH|"
                             r"SSH_.*|SUDO_.*|RSYNC_RSH)", re.I)
CREDENTIAL_NAME = re.compile(r".*(TOKEN|SECRET|PASSW|PASSPHRASE|CRED|API_?KEY|ACCESS_KEY|PRIVATE_KEY|"
                             r"CLIENT_KEY|CLIENT_CERT|AUTH|COOKIE|SESSION_KEY).*", re.I)
# [vault] lock_after (PLAN-v4 phase 2): how long the gateway daemon keeps a
# passphrase-protected vault unlocked without any use. "8h" by default; from
# one minute to one day ("90s", "30m", "8h", "1d").
LOCK_AFTER_DEFAULT = 8 * 3600
LOCK_AFTER_MIN = 60
LOCK_AFTER_MAX = 24 * 3600
_DURATION_RE = re.compile(r"\s*(\d{1,6})\s*([smhd])\s*")


def parse_duration(v: Any) -> int | None:
    """Seconds for "90s" / "30m" / "8h" / "1d" inside [vault]'s bounds, else None."""
    if not isinstance(v, str):
        return None
    m = _DURATION_RE.fullmatch(v)
    if not m:
        return None
    n = int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    return n if LOCK_AFTER_MIN <= n <= LOCK_AFTER_MAX else None
ALL_ACCOUNT_KEYS = tuple(dict.fromkeys(COMMON_KEYS + sum(KIND_KEYS.values(), ())))
MAX_CHAIN = 3
NOTE_MAX = 200

LENIENT_RE = re.compile(
    r"^(\s*(?:ssh|sudo|scripts|use|default|packages)\s*=\s*)"
    r"((?i:yes|no|on|off|ask|true|false))(\s*(?:#.*)?)$")


# ---------------------------------------------------------------------------
# Data shapes
# ---------------------------------------------------------------------------


@dataclass
class Problem:
    level: str            # "error" | "warning"
    message: str          # already safe to show (no raw unsafe strings)
    line: int | None = None
    entry: str | None = None   # safe entry name, or None

    def render(self) -> str:
        where = f"line {self.line}: " if self.line else ""
        who = f"{self.entry}: " if self.entry else ""
        return f"{where}{who}{self.message}"


@dataclass
class Address:
    host: str
    port: int = 22
    user: str | None = None      # None = the local user
    when: str | None = None      # CIDR: tried only on that network
    raw: str = ""

    def effective_user(self) -> str:
        return self.user or paths.local_user()

    def hostport(self) -> str:
        h = f"[{self.host}]" if ":" in self.host else self.host
        return h if self.port == 22 else f"{h}:{self.port}"

    def render(self, with_user: bool = True) -> str:
        """user@host[:port] (port only if not 22)."""
        return (f"{self.user}@" if with_user and self.user else "") + self.hostport()

    def key(self) -> tuple[str, str, int]:
        return (self.effective_user(), self.host, self.port)

    def snapshot(self) -> dict[str, Any]:
        return {"user": self.effective_user(), "host": self.host, "port": self.port,
                "when": self.when}


@dataclass
class Workspace:
    """A named root on one host (PLAN-v4 phase 7): `root` as written (an
    absolute path, or ~/... for that host's home), `local` the matching folder
    on this machine when there is a path mapping (as written), and its own
    restrictions (read, exec, write)."""
    name: str
    host: str
    root: str
    local: str = ""
    note: str = ""
    policy: dict[str, Any] = field(default_factory=dict)
    line: int | None = None
    lines: dict[str, int] = field(default_factory=dict)

    def snapshot(self) -> dict[str, Any]:
        d: dict[str, Any] = {"root": self.root}
        if self.local:
            d["local"] = self.local
        if self.policy:
            d["policy"] = dict(self.policy)
        return d


@dataclass
class HostShell:
    """[hosts.NAME.shell]: a remote host's imports (PLAN-v4 phase 7)."""
    import_path: list[str] = field(default_factory=list)
    import_env: list[str] = field(default_factory=list)
    line: int | None = None
    path_line: int | None = None
    env_line: int | None = None


@dataclass
class Host:
    name: str
    line: int | None = None
    address: Address | None = None   # None only for localhost
    also: list[Address] = field(default_factory=list)
    via: str | None = None
    ssh: Any = True                  # True | "ask" | False
    sudo: Any = True
    scripts: bool = False
    note: str = ""
    runtime: str = ""                # the managed remote runtime's folder (PLAN-v4 phase 6; "" default)
    explicit: bool = True            # False: the implicit [hosts.localhost]
    # localhost only: the form doesn't say sudo (no table, or no key). Its
    # value then depends on the install (apply_install_defaults).
    sudo_default: bool = False
    # PLAN-v4 phase 7: [hosts.NAME.policy] (key -> True | "ask" | False; None
    # when the host has no policy table), its lines, the workspaces, and a
    # remote host's [hosts.NAME.shell] imports
    policy: dict[str, Any] | None = None
    policy_lines: dict[str, int] = field(default_factory=dict)
    workspaces: dict[str, "Workspace"] = field(default_factory=dict)
    shell: "HostShell" = field(default_factory=HostShell)

    @property
    def is_local(self) -> bool:
        return self.name == "localhost"

    def addresses(self) -> list[Address]:
        """Candidates in order: address (with its `when`), then also."""
        return ([self.address] if self.address else []) + list(self.also)

    def user(self) -> str:
        return self.address.effective_user() if self.address else paths.local_user()


@dataclass
class Account:
    name: str
    kind: str
    line: int | None = None
    login: str = ""
    owners: list[str] = field(default_factory=list)
    default: bool = False
    commit_name: str = ""            # the `name` key (commit identity)
    email: str = ""
    env: str = ""
    scripts: bool = False
    use: bool = True
    note: str = ""
    host: str = ""                   # github, ml-catalog, pijul, registry
    packages: bool = False           # github
    tenant: str = ""                 # azure
    client_id: str = ""              # azure
    databricks: list[str] = field(default_factory=list)
    storage: list[str] = field(default_factory=list)
    registries: list[str] = field(default_factory=list)
    sites: list[str] = field(default_factory=list)   # azure: extra sites; api-key: its sites
    remote_pijul: str = ""
    auth: str = ""                   # api-key placement
    policy: dict[str, Any] | None = None             # [accounts.NAME.policy] (PLAN-v4 phase 7)
    policy_lines: dict[str, int] = field(default_factory=dict)

    def destinations(self) -> list[str]:
        from . import accounts
        return accounts.destinations(self)

    def ssh_endpoints(self) -> list[tuple[str, str]]:
        from . import accounts
        return accounts.ssh_endpoints(self)

    def owner_names(self) -> list[str]:
        """login plus owners: who this account routes for."""
        return ([self.login] if self.login else []) + list(self.owners)


@dataclass
class Settings:
    others: str = "refuse"
    others_invalid: bool = False   # a bad value: refuse for now, but don't ratchet the approval


@dataclass
class VaultSettings:
    lock_after: int = LOCK_AFTER_DEFAULT


@dataclass
class ShellSettings:
    managed: str = "on"
    managed_invalid: bool = False   # a bad value: the approved mode stays, nothing ratchets
    import_path: list[str] = field(default_factory=list)
    import_env: list[str] = field(default_factory=list)
    line: int | None = None              # [shell]
    path_line: int | None = None         # import_path
    env_line: int | None = None          # import_env


@dataclass
class Form:
    path: Path
    exists: bool = False
    text: str = ""                 # the file as read
    used_text: str = ""            # what was parsed (the last good form after a syntax error)
    mtime_ns: int = 0
    sha256: str = ""               # of used_text
    settings: Settings = field(default_factory=Settings)
    vault: VaultSettings = field(default_factory=VaultSettings)
    shell: ShellSettings = field(default_factory=ShellSettings)
    policy: dict[str, Any] = field(default_factory=dict)          # [policy] (PLAN-v4 phase 7)
    policy_lines: dict[str, int] = field(default_factory=dict)
    policy_line: int | None = None
    hosts: dict[str, Host] = field(default_factory=dict)
    accounts: dict[str, Account] = field(default_factory=dict)
    disabled: dict[str, str] = field(default_factory=dict)   # safe name -> first error
    # names whose LATER definition was dropped because the name is also used by
    # the other section: {name: "hosts"|"accounts"} (the section that is off;
    # the earlier entry stays valid in the other section)
    dup_disabled: dict[str, str] = field(default_factory=dict)
    # disabled accounts whose kind could be read: {name: kind} (a stand-in
    # names the entry that is off instead of saying there is none)
    disabled_kinds: dict[str, str] = field(default_factory=dict)
    unnamed_off: int = 0           # entries whose name can't even be shown (unsafe text)
    problems: list[Problem] = field(default_factory=list)
    syntax_error: Problem | None = None
    from_last_good: bool = False

    @property
    def errors(self) -> list[Problem]:
        return [p for p in self.problems if p.level == "error"]

    @property
    def warnings(self) -> list[Problem]:
        return [p for p in self.problems if p.level == "warning"]

    @property
    def ok(self) -> bool:
        return self.syntax_error is None and not self.errors

    def entry(self, name: str) -> Host | Account | None:
        return self.hosts.get(name) or self.accounts.get(name)

    def host(self, name: str) -> Host | None:
        return self.hosts.get(name)

    def account(self, name: str) -> Account | None:
        return self.accounts.get(name)

    @property
    def n_off(self) -> int:
        """How many entries are off because of a mistake."""
        return len(self.disabled) + self.unnamed_off

    def problems_for(self, name: str) -> list[Problem]:
        return [p for p in self.problems if p.entry == name]

    def is_disabled(self, name: str, section: str) -> bool:
        """True if [section.name] is off (bad entry), as opposed to absent.
        section: "hosts" | "accounts"."""
        if name not in self.disabled:
            return False
        dup = self.dup_disabled.get(name)
        return dup is None or dup == section

    def names(self) -> list[str]:
        return list(self.hosts) + list(self.accounts)

    def report_lines(self) -> list[str]:
        out = []
        if self.syntax_error:
            out.append(self.syntax_error.render()
                       + ("; using the last good form" if self.from_last_good else ""))
        out += [p.render() for p in self.errors]
        return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def safe(s: Any) -> str | None:
    """s if it may be echoed in a message, else None."""
    return s if isinstance(s, str) and SAFE_ECHO.fullmatch(s) else None


def unsafe_text(s: str) -> bool:
    """True if s holds a character that may hide or reshape text (see
    UNSAFE_CATEGORIES)."""
    if UNSAFE.search(s):
        return True
    return not s.isascii() and any(_unsafe_char(c) for c in s)


def strip_unsafe(s: str, repl: str = " ") -> str:
    """s with every unsafe character replaced (for migrated notes)."""
    return "".join(repl if _unsafe_char(c) else c for c in s)


def normalize_lenient(text: str) -> str:
    """The pre-pass: bare yes/no/on/off/ask/true/false for the right keys."""
    out = []
    for line in text.split("\n"):
        m = LENIENT_RE.match(line)
        if m:
            word = m.group(2).lower()
            val = RIGHT_WORDS[word]
            rep = '"ask"' if val == "ask" else ("true" if val else "false")
            line = m.group(1) + rep + m.group(3)
        out.append(line)
    return "\n".join(out)


def parse_cidr(v: Any) -> str:
    if not isinstance(v, str) or unsafe_text(v):
        raise ValueError("when must be a network like \"10.0.0.0/24\"")
    try:
        return str(ipaddress.ip_network(v.strip(), strict=False))
    except ValueError:
        raise ValueError(f"when = {_q(v)} is not a network like \"10.0.0.0/24\"") from None


def _q(v: Any) -> str:
    s = safe(v)
    return f'"{s}"' if s else "(that value)"


def valid_hostname(h: str) -> bool:
    """A DNS name or an IP address (IPv6 without brackets)."""
    if not h or h.startswith("-"):
        return False
    try:
        ipaddress.ip_address(h.split("%", 1)[0] if ":" in h else h)
        return True
    except ValueError:
        pass
    if re.fullmatch(r"[0-9.]+", h):
        return False  # looks like an IPv4 address but isn't one
    return bool(DNS_RE.fullmatch(h))


def parse_address(v: Any, what: str = "address") -> Address:
    """`[user@]host[:port]`, IPv6 as `[::1]:22`. Raises ValueError."""
    if not isinstance(v, str):
        raise ValueError(f"{what} must be a string like \"user@host:port\"")
    s = v.strip()
    if not s or unsafe_text(s) or any(c.isspace() for c in s):
        raise ValueError(f"{what} must be a string like \"user@host:port\" (no spaces)")
    if s.startswith("-"):
        raise ValueError(f"{what} can't start with '-'")
    user = None
    if "@" in s:
        user, _, s = s.partition("@")
        if "@" in s or not USER_RE.fullmatch(user):
            raise ValueError(f"{what}: {_q(user)} is not a user name")
    port: int = 22
    if s.startswith("["):
        m = re.fullmatch(r"\[([0-9A-Fa-f:.]+(?:%[A-Za-z0-9_.-]+)?)\](?::([0-9]{1,5}))?", s)
        if not m:
            raise ValueError(f"{what}: write IPv6 addresses like [::1]:22")
        host = m.group(1).lower()
        try:
            ipaddress.IPv6Address(host.split("%", 1)[0])
        except ValueError:
            raise ValueError(f"{what}: {_q(host)} is not an IPv6 address") from None
        if m.group(2):
            port = int(m.group(2))
    else:
        if s.count(":") > 1:
            raise ValueError(f"{what}: write IPv6 addresses in brackets, like [::1]:22")
        host, sep, p = s.partition(":")
        host = host.lower()
        if sep:
            if not re.fullmatch(r"[0-9]{1,5}", p):
                raise ValueError(f"{what}: {_q(p)} is not a port number")
            port = int(p)
        if not valid_hostname(host):
            raise ValueError(f"{what}: {_q(host)} is not a host name or IP address")
    if not 0 < port < 65536:
        raise ValueError(f"{what}: port {port} is out of range")
    return Address(host=host, port=port, user=user, raw=v)


def parse_hostport(v: Any, what: str = "host") -> str:
    """A host name or IP with an optional :port (account `host` keys)."""
    a = parse_address(v, what)
    if a.user:
        raise ValueError(f"{what} takes no user part")
    return a.hostport()


def _bool(v: Any) -> bool | None:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in RIGHT_WORDS and v.strip().lower() != "ask":
        return bool(RIGHT_WORDS[v.strip().lower()])
    return None


def _right(v: Any) -> Any:
    """true | "ask" | false (quoted words accepted); None if invalid."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in RIGHT_WORDS:
        return RIGHT_WORDS[v.strip().lower()]
    return None


def _suggest(key: str, known: Iterable[str]) -> str:
    k = safe(key)
    if not k:
        return "an unknown key (ignored)"
    m = difflib.get_close_matches(k.lower(), list(known), n=1, cutoff=0.6)
    return f"unknown key {k}" + (f" (did you mean {m[0]}?)" if m else "") + " (ignored)"


# ---------------------------------------------------------------------------
# Line numbers (tomllib doesn't report them)
# ---------------------------------------------------------------------------

_HEADER = re.compile(r"^\s*\[(\[)?\s*(.+?)\s*\]\]?\s*(?:#.*)?$")
_BARE = r"[A-Za-z0-9_-]+"
_DQ = r'"(?:[^"\\]|\\.)*"'
_SQ = r"'[^']*'"
_KEYPART = rf"(?:{_DQ}|{_SQ}|{_BARE})"
_KEYLINE = re.compile(rf"^\s*({_KEYPART}(?:\s*\.\s*{_KEYPART})*)\s*=")


def _split_dotted(s: str) -> tuple[str, ...]:
    parts = re.findall(rf"\s*({_KEYPART})\s*(?:\.|$)", s)
    out = []
    for p in parts:
        if p.startswith('"'):
            try:
                p = tomllib.loads(f"k = {p}")["k"]
            except tomllib.TOMLDecodeError:
                p = p[1:-1]
        elif p.startswith("'"):
            p = p[1:-1]
        out.append(p)
    return tuple(out)


def line_index(text: str) -> dict[tuple[str, ...], int]:
    """(table..., key...) -> 1-based line of its header or key line."""
    idx: dict[tuple[str, ...], int] = {}
    table: tuple[str, ...] = ()
    in_multiline = False
    for n, line in enumerate(text.split("\n"), 1):
        if in_multiline:
            if line.count('"""') % 2 == 1 or line.count("'''") % 2 == 1:
                in_multiline = False
            continue
        m = _HEADER.match(line)
        if m and not _KEYLINE.match(line):
            table = _split_dotted(m.group(2))
            idx.setdefault(table, n)
            continue
        m = _KEYLINE.match(line)
        if m:
            key = table + _split_dotted(m.group(1))
            for i in range(len(table) + 1, len(key) + 1):
                idx.setdefault(key[:i], n)
            rest = line[m.end():]
            if rest.count('"""') == 1 or rest.count("'''") == 1:
                in_multiline = True
    return idx


# ---------------------------------------------------------------------------
# Parsing and validation
# ---------------------------------------------------------------------------


class _Ctx:
    def __init__(self, form: Form, idx: dict[tuple[str, ...], int]):
        self.form = form
        self.idx = idx

    def line(self, *path: str) -> int | None:
        for i in range(len(path), 0, -1):
            n = self.idx.get(tuple(path[:i]))
            if n:
                return n
        return None

    def add(self, level: str, msg: str, line: int | None = None, entry: str | None = None) -> None:
        self.form.problems.append(Problem(level, msg, line, entry))


def _check_strings(v: Any) -> bool:
    """False if any string inside v holds unsafe characters."""
    if isinstance(v, str):
        return not unsafe_text(v)
    if isinstance(v, dict):
        return all(isinstance(k, str) and not unsafe_text(k) and _check_strings(x)
                   for k, x in v.items())
    if isinstance(v, list):
        return all(_check_strings(x) for x in v)
    return True


def _str_list(v: Any, what: str) -> list[str]:
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError(f"{what} must be a list of strings")
    return [x.strip() for x in v]


class _EntryErrors(Exception):
    pass


_BAD = object()


def policy_word(v: Any) -> Any:
    """True | "ask" | False for a policy value ("allow" / "ask" / "deny", or
    true / false), else _BAD."""
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in POLICY_WORDS:
        return POLICY_WORDS[v.strip().lower()]
    return _BAD


def policy_text(r: Any) -> str:
    """How a policy decision is written: allow, ask or deny."""
    return "allow" if r is True else ("ask" if r == "ask" else "deny")


def _policy_keys(ctx: _Ctx, raw: Any, sect: tuple[str, ...], allowed: tuple[str, ...],
                 errs: list[tuple[str, str | None]], where: str,
                 lines: dict[str, int]) -> dict[str, Any]:
    """A policy table's keys: each one of `allowed` with allow / ask / deny.
    An unknown key or a bad value is an error (the entry goes off: a
    misspelt restriction must never quietly not apply)."""
    if not isinstance(raw, dict):
        errs.append((f"{where} must be a table like [{'.'.join(sect)}]", sect[-1]))
        return {}
    out: dict[str, Any] = {}
    for k, v in raw.items():
        if not isinstance(k, str) or k not in allowed:
            if isinstance(k, str) and k in GLOBAL_POLICY_KEYS:
                errs.append((f"{where}: {k} doesn't apply here (it takes "
                             f"{', '.join(allowed)})", sect[-1]))
            else:
                errs.append((f"{where}: {_suggest(k, allowed) if safe(k) else 'an unknown key'}",
                             sect[-1]))
            continue
        w = policy_word(v)
        if w is _BAD:
            errs.append((f"{where}: {k} must be \"allow\", \"ask\" or \"deny\"", sect[-1]))
            continue
        out[k] = w
        n = ctx.line(*sect, k)
        if n:
            lines[k] = n
    return out


def workspace_path(v: Any, what: str) -> str:
    """A workspace folder as written, normalized: an absolute path or ~/...
    (that host's home); spaces and non-ASCII letters are fine, control
    characters, '..' and a leading // aren't. ValueError with the reason."""
    if not isinstance(v, str) or not v.strip():
        raise ValueError(f"{what} must be a folder, like \"/srv/app\" or \"~/src/app\"")
    raw = v.strip()
    if unsafe_text(raw) or "\x00" in raw or len(raw) > 1000:
        raise ValueError(f"{what} holds an unsafe character or is too long")
    if ".." in raw.split("/"):
        raise ValueError(f"{what} can't contain '..'")
    if raw == "~" or raw == "~/":
        return "~"
    if raw.startswith("~/"):
        return "~/" + os.path.normpath(raw[2:]).lstrip("/")
    if not raw.startswith("/") or raw.startswith("//"):
        raise ValueError(f"{what} must be an absolute folder (/...) or ~/...")
    return os.path.normpath(raw)


def _workspaces(ctx: _Ctx, host: str, raw: Any, errs: list[tuple[str, str | None]],
                local: bool) -> dict[str, Workspace]:
    """[hosts.NAME.workspaces.WS] tables: root (required), local (a remote
    workspace's folder on this machine), note, and its read / exec / write."""
    if not isinstance(raw, dict):
        errs.append(("workspaces must be tables like [hosts.NAME.workspaces.APP]", "workspaces"))
        return {}
    out: dict[str, Workspace] = {}
    roots: dict[str, str] = {}
    for wn, wt in raw.items():
        sect = ("hosts", host, "workspaces", wn)
        if not isinstance(wn, str) or not NAME_RE.fullmatch(wn):
            errs.append(("workspace names are lowercase letters, digits and -, starting with a "
                         "letter, at most 32", "workspaces"))
            continue
        if not isinstance(wt, dict):
            errs.append((f"workspaces.{wn} must be a table: [hosts.{host}.workspaces.{wn}]",
                         "workspaces"))
            continue
        w = Workspace(name=wn, host=host, root="", line=ctx.line(*sect))
        bad = False
        for k in wt:
            if k not in WORKSPACE_KEYS:
                errs.append((f"workspaces.{wn}: {_suggest(k, WORKSPACE_KEYS) if safe(k) else 'an unknown key'}",
                             "workspaces"))
                bad = True
        if "root" not in wt:
            errs.append((f"workspaces.{wn} needs root = \"/path/on/the/host\"", "workspaces"))
            continue
        try:
            w.root = workspace_path(wt["root"], f"workspaces.{wn}.root")
        except ValueError as e:
            errs.append((str(e), "workspaces"))
            continue
        if "local" in wt:
            if local:
                ctx.add("warning", f"workspaces.{wn}.local: a localhost workspace is already on "
                        "this machine (ignored)", ctx.line(*sect, "local"), host)
            else:
                try:
                    w.local = workspace_path(wt["local"], f"workspaces.{wn}.local")
                except ValueError as e:
                    errs.append((str(e), "workspaces"))
                    continue
        if "note" in wt:
            n = wt["note"]
            if not isinstance(n, str) or len(n) > NOTE_MAX:
                errs.append((f"workspaces.{wn}.note must be one line of at most {NOTE_MAX} "
                             "characters", "workspaces"))
            else:
                w.note = n.strip()
        for k in WORKSPACE_POLICY_KEYS:
            if k in wt:
                r = policy_word(wt[k])
                if r is _BAD:
                    errs.append((f"workspaces.{wn}.{k} must be \"allow\", \"ask\" or \"deny\"",
                                 "workspaces"))
                    bad = True
                else:
                    w.policy[k] = r
                    n = ctx.line(*sect, k)
                    if n:
                        w.lines[k] = n
        if bad:
            continue
        if w.root in roots:
            ctx.add("warning", f"workspaces {roots[w.root]} and {wn} have the same root",
                    w.line, host)
        roots.setdefault(w.root, wn)
        out[wn] = w
    if len(out) > WORKSPACES_MAX:
        errs.append((f"a host takes at most {WORKSPACES_MAX} workspaces", "workspaces"))
    return out


def remote_import_path_entry(v: Any) -> tuple[str | None, str | None]:
    """(folder as written, None) or (None, why) for one [hosts.NAME.shell]
    import_path entry: a folder on that host (absolute or ~/...), no ':'."""
    if not isinstance(v, str) or ":" in v:
        return None, "import_path entries are folders on that host, without ':'"
    try:
        return workspace_path(v, "an import_path entry"), None
    except ValueError as e:
        return None, str(e)


def _host_shell(ctx: _Ctx, host: str, raw: Any, errs: list[tuple[str, str | None]]) -> HostShell:
    out = HostShell(line=ctx.line("hosts", host, "shell"))
    if not isinstance(raw, dict):
        errs.append((f"shell must be a table: [hosts.{host}.shell]", "shell"))
        return out
    for k, v in raw.items():
        line = ctx.line("hosts", host, "shell", k)
        if k not in HOST_SHELL_KEYS:
            errs.append((f"shell: {_suggest(k, HOST_SHELL_KEYS) if safe(k) else 'an unknown key'}",
                         "shell"))
            continue
        if not isinstance(v, list):
            errs.append((f"shell.{k} must be a list, like {k} = [\"...\"]", "shell"))
            continue
        limit = IMPORT_PATH_MAX if k == "import_path" else IMPORT_ENV_MAX
        got: list[str] = []
        for item in v:
            val, why = (remote_import_path_entry if k == "import_path" else import_env_entry)(item)
            if val is None:
                errs.append((f"shell: {why}", "shell"))
            elif val not in got:
                got.append(val)
        if len(got) > limit:
            errs.append((f"shell: {k} takes at most {limit} entries", "shell"))
            got = got[:limit]
        if k == "import_path":
            out.import_path, out.path_line = got, line
        else:
            out.import_env, out.env_line = got, line
    return out


def _host_entry(ctx: _Ctx, name: str, raw: dict[str, Any]) -> Host:
    errs: list[tuple[str, str | None]] = []
    sect = ("hosts", name)
    local = name == "localhost"
    h = Host(name=name, line=ctx.line(*sect))
    if local:
        h.sudo, h.sudo_default = LOCALHOST_SUDO, "sudo" not in raw
    allowed = LOCALHOST_KEYS if local else HOST_KEYS
    for k in raw:
        if k in allowed:
            continue
        if local and k in ("address", "when", "also", "via", "runtime"):
            errs.append((f"{k} isn't allowed on localhost (it is always this computer)", k))
        elif local and k == "shell":
            errs.append(("shell isn't a localhost key: this machine's imports are [shell] "
                         "import_path / import_env", k))
        elif local and k == "ssh":
            ctx.add("warning", "ssh doesn't apply to localhost (ignored)",
                    ctx.line(*sect, k), name)
        else:
            known = HOST_KEYS if not local else LOCALHOST_KEYS
            ctx.add("warning", _suggest(k, known), ctx.line(*sect, k) if safe(k) else h.line,
                    name)
    for key in ("ssh", "sudo"):
        if key in raw and key in allowed:
            r = _right(raw[key])
            if r is None:
                errs.append((f"{key} must be true, \"ask\" or false", key))
            else:
                setattr(h, key, r)
    if local:
        h.ssh = False
    if "scripts" in raw:
        b = _bool(raw["scripts"])
        if b is None:
            errs.append(("scripts must be true or false", "scripts"))
        else:
            h.scripts = b
    if "note" in raw:
        n = raw["note"]
        if not isinstance(n, str) or len(n) > NOTE_MAX:
            errs.append((f"note must be one line of at most {NOTE_MAX} characters", "note"))
        else:
            h.note = n.strip()
    if "policy" in raw:
        h.policy = _policy_keys(ctx, raw["policy"], sect + ("policy",),
                                LOCALHOST_POLICY_KEYS if local else HOST_POLICY_KEYS, errs,
                                "policy", h.policy_lines)
    if "workspaces" in raw:
        h.workspaces = _workspaces(ctx, name, raw["workspaces"], errs, local)
    if "shell" in raw and not local:
        h.shell = _host_shell(ctx, name, raw["shell"], errs)
    if not local and "runtime" in raw:
        rt = raw["runtime"]
        if not isinstance(rt, str) or not RUNTIME_RE.fullmatch(rt) or ".." in rt.split("/") \
                or "//" in rt:
            errs.append(("runtime must be an absolute or ~/ folder of plain characters (letters, "
                         "digits, . _ - + @ /), like runtime = \"~/.local/share/gateway-runtime\"",
                         "runtime"))
        else:
            h.runtime = rt.rstrip("/") if rt not in ("/", "~/") else rt
    if not local:
        if "address" not in raw:
            errs.append(("address is required, like address = \"user@host\"", None))
        else:
            try:
                h.address = parse_address(raw["address"])
            except ValueError as e:
                errs.append((str(e), "address"))
        if "when" in raw:
            try:
                w = parse_cidr(raw["when"])
                if h.address:
                    h.address.when = w
            except ValueError as e:
                errs.append((str(e), "when"))
        if "also" in raw:
            also = raw["also"]
            if isinstance(also, (str, dict)):
                also = [also]
            if not isinstance(also, list):
                errs.append(("also must be a list of addresses", "also"))
            else:
                for i, item in enumerate(also):
                    try:
                        if isinstance(item, dict):
                            extra = [k for k in item if k not in ("at", "when")]
                            for k in extra:
                                ctx.add("warning", f"also: {_suggest(k, ('at', 'when'))}",
                                        ctx.line(*sect, "also"), name)
                            if "at" not in item:
                                raise ValueError("each also table needs at = \"user@host\"")
                            a = parse_address(item["at"], "also")
                            if "when" in item:
                                a.when = parse_cidr(item["when"])
                        else:
                            a = parse_address(item, "also")
                        h.also.append(a)
                    except ValueError as e:
                        errs.append((str(e), "also"))
                if h.address:
                    want = h.address.effective_user()
                    for a in h.also:
                        if a.user is None:
                            a.user = h.address.user
                        elif a.user != want:
                            errs.append((f"also: the user {_q(a.user)} must be the same as "
                                         f"address's user ({_q(want)})", "also"))
                seen = set()
                for a in h.addresses():
                    if a.key() in seen:
                        ctx.add("warning", f"the address {a.render()} is listed twice",
                                ctx.line(*sect, "also"), name)
                    seen.add(a.key())
        if "via" in raw:
            v = raw["via"]
            if not isinstance(v, str) or not NAME_RE.fullmatch(v):
                errs.append(("via must name another host in this form", "via"))
            elif v == name:
                errs.append(("via can't name the host itself", "via"))
            elif v == "localhost":
                errs.append(("via can't be localhost", "via"))
            else:
                h.via = v
        for a in h.addresses():
            why = git_server_note(a.host)
            if why:
                errs.append((why, "address" if a is h.address else "also"))
                break
        if h.address and "." not in h.address.host and ":" not in h.address.host \
                and h.address.host != "localhost":
            ctx.add("warning", f"{h.address.host} has no domain; if it's an alias from "
                    "~/.ssh/config, use its real HostName (gate import-ssh can look it up)",
                    ctx.line(*sect, "address"), name)
    if errs:
        msg, key = errs[0]
        for m, k in errs:
            ctx.add("error", m, ctx.line(*sect, k) if k else h.line, name)
        raise _EntryErrors(msg)
    return h


def _account_entry(ctx: _Ctx, name: str, raw: dict[str, Any]) -> Account:
    errs: list[tuple[str, str | None]] = []
    sect = ("accounts", name)
    line = ctx.line(*sect)
    kind = raw.get("kind")
    if not isinstance(kind, str) or kind not in KINDS:
        if isinstance(kind, str) and safe(kind):
            m = difflib.get_close_matches(kind.lower(), KINDS, n=1, cutoff=0.5)
            hint = f" (did you mean {m[0]}?)" if m else ""
            msg = f"kind {_q(kind)} is not one of {', '.join(KINDS)}{hint}"
        elif kind is None:
            msg = f"kind is required (one of {', '.join(KINDS)})"
        else:
            msg = f"kind must be one of {', '.join(KINDS)}"
        ctx.add("error", msg, ctx.line(*sect, "kind"), name)
        raise _EntryErrors(msg)
    a = Account(name=name, kind=kind, line=line)
    allowed = COMMON_KEYS + KIND_KEYS[kind]
    for k in raw:
        if k in allowed:
            continue
        if k in ALL_ACCOUNT_KEYS:
            ctx.add("warning", f"{k} isn't used by {kind} accounts (ignored)",
                    ctx.line(*sect, k), name)
        else:
            ctx.add("warning", _suggest(k, allowed), ctx.line(*sect, k) if safe(k) else line,
                    name)

    def get_str(key: str, rx: re.Pattern[str] | None = None, maxlen: int = 200,
                what: str = "") -> str:
        if key not in raw:
            return ""
        v = raw[key]
        if not isinstance(v, str) or len(v) > maxlen or (rx is not None and not rx.fullmatch(v.strip())):
            errs.append((f"{key} {what or 'is not valid'}", key))
            return ""
        return v.strip()

    a.login = get_str("login", LOGIN_RE, 100, "is not a user name")
    try:
        if "owners" in raw:
            if isinstance(raw["owners"], str):
                raise ValueError("owners must be a list, like owners = [\"acme\"]")
            a.owners = _str_list(raw["owners"], "owners")
            for o in a.owners:
                if not OWNER_RE.fullmatch(o):
                    raise ValueError(f"owners: {_q(o)} is not an owner or org name")
    except ValueError as e:
        errs.append((str(e), "owners"))
    for key in ("default", "scripts", "use"):
        if key in raw:
            b = _bool(raw[key])
            if b is None:
                errs.append((f"{key} must be true or false", key))
            else:
                setattr(a, key, b)
    if "name" in raw or "email" in raw:
        a.commit_name = get_str("name", None, 100, "must be at most 100 characters")
        a.email = get_str("email", EMAIL_RE, 254, "is not an email address")
        if kind not in IDENTITY_KINDS:
            ctx.add("warning", f"name/email (commit identity) aren't used by {kind} accounts",
                    ctx.line(*sect, "name" if "name" in raw else "email"), name)
    if "env" in raw:
        env = raw["env"]
        if not isinstance(env, str) or not ENV_RE.fullmatch(env) or ENV_DENY.fullmatch(env):
            errs.append(("env must be a variable name like OPENAI_API_KEY (not PATH, HOME, "
                         "GIT_*, SSH_*, LD_* ...)", "env"))
        elif kind not in ENV_KINDS:
            ctx.add("warning", f"env isn't supported for {kind} accounts (ignored)",
                    ctx.line(*sect, "env"), name)
        else:
            a.env = env
    if "note" in raw:
        n = raw["note"]
        if not isinstance(n, str) or len(n) > NOTE_MAX:
            errs.append((f"note must be one line of at most {NOTE_MAX} characters", "note"))
        else:
            a.note = n.strip()
    if "policy" in raw:
        a.policy = _policy_keys(ctx, raw["policy"], sect + ("policy",), ACCOUNT_POLICY_KEYS, errs,
                                "policy", a.policy_lines)

    # kind-specific
    if kind in ("github", "ml-catalog", "pijul", "registry"):
        if "host" in raw:
            try:
                a.host = parse_hostport(raw["host"])
            except ValueError as e:
                errs.append((str(e), "host"))
        elif kind == "registry":
            errs.append(("host is required for registry accounts, like host = \"docker.io\"",
                         None))
        elif kind == "ml-catalog":
            errs.append(("host is required for ml-catalog accounts (the catalog's address), like "
                         "host = \"catalog.example.com\"", None))
        else:
            a.host = DEFAULT_HOSTS[kind]
    if kind == "github":
        a.packages = a.host == "github.com"
        if "packages" in raw:
            b = _bool(raw["packages"])
            if b is None:
                errs.append(("packages must be true or false", "packages"))
            else:
                a.packages = b
    elif kind == "azure":
        t = raw.get("tenant")
        if t is None:
            errs.append(("tenant is required, like tenant = \"contoso.onmicrosoft.com\"", None))
        elif not isinstance(t, str) or not (GUID_RE.fullmatch(t.strip()) or (
                "." in t and DNS_RE.fullmatch(t.strip().lower()))):
            errs.append(("tenant must be a tenant ID (GUID) or a domain", "tenant"))
        else:
            a.tenant = t.strip().lower() if not GUID_RE.fullmatch(t.strip()) else t.strip()
        if "client_id" in raw:
            c = raw["client_id"]
            if not isinstance(c, str) or not GUID_RE.fullmatch(c.strip()):
                errs.append(("client_id must be an application ID (GUID)", "client_id"))
            else:
                a.client_id = c.strip()
        else:
            a.client_id = AZURE_CLI_CLIENT_ID
        for key in ("databricks", "registries", "sites"):
            if key in raw:
                try:
                    vals = [v.lower() for v in _str_list(raw[key], key)]
                    for v in vals:
                        if not valid_hostname(v):
                            raise ValueError(f"{key}: {_q(v)} is not a host name")
                    setattr(a, key, vals)
                except ValueError as e:
                    errs.append((str(e), key))
        for v in a.databricks:
            if not v.endswith(".azuredatabricks.net"):
                ctx.add("warning", f"databricks: {v} doesn't end in .azuredatabricks.net",
                        ctx.line(*sect, "databricks"), name)
        for v in a.registries:
            if not v.endswith(".azurecr.io"):
                ctx.add("warning", f"registries: {v} doesn't end in .azurecr.io",
                        ctx.line(*sect, "registries"), name)
        if "storage" in raw:
            try:
                vals = _str_list(raw["storage"], "storage")
                for v in vals:
                    if not STORAGE_RE.fullmatch(v):
                        raise ValueError(f"storage: {_q(v)} is not a storage account name "
                                         "(3-24 lowercase letters and digits)")
                a.storage = vals
            except ValueError as e:
                errs.append((str(e), "storage"))
    elif kind == "pijul":
        if "remote_pijul" in raw:
            a.remote_pijul = get_str("remote_pijul", PATH_RE, 256, "must be an absolute path")
    elif kind == "api-key":
        if "sites" not in raw:
            errs.append(("sites is required, like sites = [\"api.example.com\"]", None))
        else:
            try:
                vals = [v.lower() for v in _str_list(raw["sites"], "sites")]
                for v in vals:
                    bare = v[1:] if v.startswith(".") else v
                    if not valid_hostname(bare):
                        raise ValueError(f"sites: {_q(v)} is not a host name (api.x.com, or "
                                         ".x.com for any subdomain)")
                    if v.startswith(".") and too_broad_site(bare):
                        raise ValueError(f"sites: {_q(v)} is too broad (its subdomains belong to "
                                         "many owners); name the site, like api.example.com")
                a.sites = vals
            except ValueError as e:
                errs.append((str(e), "sites"))
            if not a.sites and "sites" in raw and not errs:
                if a.use:
                    errs.append(("sites is empty; list where the key may go (or set use = "
                                 "false)", "sites"))
                else:
                    ctx.add("warning", "has no sites, so the key is never sent",
                            ctx.line(*sect, "sites"), name)
        a.auth = "bearer"
        if "auth" in raw:
            v = raw["auth"]
            if not isinstance(v, str) or not AUTH_RE.fullmatch(v.strip()):
                errs.append(("auth must be bearer, basic, header:NAME, header:NAME:PREFIX or "
                             "query:PARAM", "auth"))
            else:
                a.auth = v.strip()
        if a.auth == "basic" and not a.login:
            ctx.add("warning", "auth = \"basic\" needs login = \"USER\" (the key is the "
                    "password)", ctx.line(*sect, "auth"), name)
    if errs:
        for m, k in errs:
            ctx.add("error", m, ctx.line(*sect, k) if k else line, name)
        raise _EntryErrors(errs[0][0])
    return a


def _table_entries(ctx: _Ctx, doc: dict[str, Any], section: str) -> dict[str, tuple[Any, int | None]]:
    """name -> (raw value, line) for [section.NAME] tables; reports bad names."""
    raw = doc.get(section, {})
    out: dict[str, tuple[Any, int | None]] = {}
    if not isinstance(raw, dict):
        ctx.add("error", f"{section} must be tables like [{section}.NAME]", ctx.line(section))
        return out
    for name, val in raw.items():
        line = ctx.line(section, name) or ctx.line(section)
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            s = safe(name)
            hint = ""
            if s and NAME_RE.fullmatch(s.lower()):
                hint = f" (use lowercase: {s.lower()})"
            what = f"the name {s}" if s else f"a {section[:-1]} name"
            ctx.add("error", f"{what} is not valid: names are lowercase letters, digits and -, "
                    f"starting with a letter, at most 32{hint}", line)
            if s:
                ctx.form.disabled[s] = "invalid name"
            else:
                ctx.form.unnamed_off += 1
            continue
        if name in RESERVED and not (section == "hosts" and name == "localhost"):
            ctx.add("error", f"{name} is a reserved word; pick another name", line, name)
            ctx.form.disabled[name] = "reserved name"
            continue
        if not isinstance(val, dict):
            ctx.add("error", f"should be a table: [{section}.{name}]", line, name)
            ctx.form.disabled[name] = "not a table"
            continue
        if not _check_strings(val):
            ctx.add("error", "a value holds control characters, line breaks or bidi overrides",
                    line, name)
            ctx.form.disabled[name] = "unsafe text"
            continue
        out[name] = (val, line)
    return out


def _chain_ok(form: Form, ctx: _Ctx) -> None:
    """via rules: target exists and works, no loops, at most MAX_CHAIN jumps,
    no jump through a host with ssh = false. Repeats until stable."""
    changed = True
    while changed:
        changed = False
        for name, h in list(form.hosts.items()):
            if not h.via:
                continue
            why = None
            seen = [name]
            cur = h.via
            while cur:
                if cur in seen:
                    why = f"via makes a loop ({' -> '.join(seen + [cur])})"
                    break
                if len(seen) > MAX_CHAIN:
                    why = f"via chains more than {MAX_CHAIN} jump hosts"
                    break
                j = form.hosts.get(cur)
                if j is None:
                    why = (f"via {cur}: that host is disabled (fix it first)"
                           if cur in form.disabled else f"via {cur}: no such host in the form")
                    break
                if j.is_local:
                    why = "via can't be localhost"
                    break
                if j.ssh is False:
                    why = f"via {cur}: that host has ssh = false, so it can't be a jump host"
                    break
                seen.append(cur)
                cur = j.via
            if why:
                ctx.add("error", why, ctx.line("hosts", name, "via") or h.line, name)
                form.disabled[name] = why
                del form.hosts[name]
                changed = True


def _endpoint_hosts(form: Form, ctx: _Ctx) -> None:
    """A host whose address is an account's ssh endpoint (a GitHub Enterprise
    or Pijul server of an account in the form): git over ssh to that server
    would go to the host entry, not the account. A warning (the server's
    admin shell can be a machine of its own)."""
    ends: dict[str, str] = {}
    for a in form.accounts.values():
        if a.host and ":" in a.host.rsplit("]", 1)[-1]:
            continue        # host:port is a web port; its ssh endpoint isn't known
        for _u, eh in a.ssh_endpoints():
            ends.setdefault(eh.lower(), a.name)
    for name, h in form.hosts.items():
        if h.is_local:
            continue
        for addr in h.addresses():
            acct = ends.get(addr.host)
            if acct:
                ctx.add("warning", f"{addr.host} is also the ssh endpoint of the account {acct}: git "
                        f"over ssh to it would use this host entry, not {acct}",
                        ctx.line("hosts", name, "address") or h.line, name)
                break


def _primary(a: Account) -> str:
    if a.kind == "huggingface":
        return "huggingface.co"
    if a.kind == "azure":
        return a.tenant
    if a.kind == "api-key":
        return ",".join(sorted(a.sites))
    return a.host


def validate(doc: dict[str, Any], form: Form, idx: dict[tuple[str, ...], int]) -> None:
    ctx = _Ctx(form, idx)
    for k in doc:
        if k not in TOP_KEYS:
            ctx.add("warning", _suggest(k, TOP_KEYS), ctx.line(k) if safe(k) else None)
    st = doc.get("settings", {})
    if not isinstance(st, dict):
        ctx.add("error", "settings must be a table: [settings]", ctx.line("settings"))
    else:
        for k, v in st.items():
            if k == "others":
                if v in ("refuse", "mine"):
                    form.settings.others = v
                else:
                    form.settings.others_invalid = True
                    ctx.add("error", "others must be \"refuse\" or \"mine\" (\"refuse\" until "
                            "it's fixed)", ctx.line("settings", "others"))
            else:
                ctx.add("warning", f"settings: {_suggest(k, SETTINGS_KEYS)}",
                        ctx.line("settings", k) if safe(k) else ctx.line("settings"))
    vt = doc.get("vault", {})
    if not isinstance(vt, dict):
        ctx.add("error", "vault must be a table: [vault]", ctx.line("vault"))
    else:
        for k, v in vt.items():
            if k == "lock_after":
                n = parse_duration(v)
                if n is None:
                    ctx.add("error", "lock_after must be a duration from \"1m\" to \"1d\" such "
                            "as \"30m\" or \"8h\" (8h until it's fixed)",
                            ctx.line("vault", "lock_after"))
                else:
                    form.vault.lock_after = n
            else:
                ctx.add("warning", f"vault: {_suggest(k, VAULT_KEYS)}",
                        ctx.line("vault", k) if safe(k) else ctx.line("vault"))
    _shell_table(ctx, doc.get("shell", {}), form)
    _policy_global(ctx, doc.get("policy", {}), form)
    hosts = _table_entries(ctx, doc, "hosts")
    accts = _table_entries(ctx, doc, "accounts")
    # One namespace: a name used twice keeps the earlier definition.
    for name in sorted(set(hosts) & set(accts)):
        hl, al = hosts[name][1] or 0, accts[name][1] or 0
        later, sect = (accts, "accounts") if al >= hl else (hosts, "hosts")
        ctx.add("error", f"the name {name} is used for both a host and an account; the "
                f"later one ([{sect}.{name}]) is off", later[name][1], name)
        form.disabled[name] = f"the name is also used by an earlier [{'hosts' if sect == 'accounts' else 'accounts'}.{name}]"
        form.dup_disabled[name] = sect
        del later[name]
    for name, (raw, _line) in hosts.items():
        try:
            form.hosts[name] = _host_entry(ctx, name, raw)
        except _EntryErrors as e:
            form.disabled[name] = str(e)
    for name, (raw, _line) in accts.items():
        try:
            form.accounts[name] = _account_entry(ctx, name, raw)
        except _EntryErrors as e:
            form.disabled[name] = str(e)
            if raw.get("kind") in KINDS:
                form.disabled_kinds[name] = raw["kind"]
    _chain_ok(form, ctx)
    _endpoint_hosts(form, ctx)
    if "localhost" not in form.hosts and "localhost" not in form.disabled:
        form.hosts["localhost"] = Host(name="localhost", sudo=LOCALHOST_SUDO, ssh=False,
                                       explicit=False, sudo_default=True)
    # default: at most one per kind+host
    groups: dict[tuple[str, str], list[Account]] = {}
    for a in form.accounts.values():
        if a.default:
            groups.setdefault((a.kind, _primary(a)), []).append(a)
    for (kind, host), accs in groups.items():
        if len(accs) > 1:
            names = ", ".join(x.name for x in accs)
            for x in accs:
                ctx.add("error", f"default = true is set on {names} for {kind} {host}; at most "
                        "one may be the default, so none is used", ctx.line("accounts", x.name,
                                                                           "default"), x.name)
                x.default = False


def import_path_entry(v: Any) -> tuple[str | None, str | None]:
    """(normalized folder, None) or (None, why) for one [shell] import_path
    entry: an absolute folder or ~/..., no ':' (it separates PATH entries),
    nothing unsafe, not inside the gateway's own home."""
    if not isinstance(v, str) or not v.strip():
        return None, "import_path entries must be folder names (text)"
    raw = v.strip()
    if unsafe_text(raw) or ":" in raw or "\n" in raw:
        return None, "an import_path entry holds a ':' or an unsafe character"
    if raw == "~" or raw.startswith("~/"):
        raw = str(paths.user_home()) + raw[1:]
    if not raw.startswith("/"):
        return None, "import_path entries must be absolute folders (/... or ~/...)"
    norm = os.path.normpath(raw)
    if len(norm) > 255:
        return None, "an import_path entry is too long"
    gw = os.path.normpath(str(paths.home()))
    if norm == gw or norm.startswith(gw + "/"):
        return None, "import_path can't name the gateway's own folder (~/.config/gateway)"
    return norm, None


def import_env_entry(v: Any) -> tuple[str | None, str | None]:
    """(name, None) or (None, why) for one [shell] import_env entry."""
    if not isinstance(v, str) or not IMPORT_ENV_RE.fullmatch(v.strip()):
        return None, "import_env entries must be variable names (letters, digits, _)"
    name = v.strip()
    if SHELL_PASSED.fullmatch(name):
        return None, f"{name} always reaches the managed shell (it needn't be imported)"
    if CREDENTIAL_NAME.fullmatch(name) or name.upper() in _ENV_UNSET_NAMES:
        return None, (f"{name} looks like a credential; credentials come from an account "
                      "(accounts.NAME with env = ...), never an import")
    if IMPORT_ENV_DENY.fullmatch(name):
        return None, (f"{name} can't be imported (it would change how the shell or the "
                      "gateway's stand-ins work; import_path is for PATH)")
    return name, None


# The user's credential variables (envfile.ENV_UNSET), never importable.
_ENV_UNSET_NAMES = frozenset({
    "SSH_AUTH_SOCK", "SSH_AGENT_PID", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "GIT_ASKPASS",
    "GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
    "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_TOKEN",
    "AZURE_STORAGE_KEY", "AZURE_STORAGE_SAS_TOKEN", "AZURE_STORAGE_CONNECTION_STRING",
    "AZURE_CLIENT_SECRET", "ARM_CLIENT_SECRET", "ARM_ACCESS_KEY",
    "DATABRICKS_TOKEN", "DATABRICKS_CLIENT_SECRET", "DOCKER_AUTH_CONFIG", "REGISTRY_AUTH_FILE"})


def _shell_table(ctx: _Ctx, sh: Any, form: Form) -> None:
    """[shell]: managed, import_path, import_env (see SHELL_KEYS). A bad
    value is an error: a bad mode keeps the approved one; a bad import entry
    is left out (the others stay)."""
    out = form.shell
    out.line = ctx.line("shell")
    if not isinstance(sh, dict):
        ctx.add("error", "shell must be a table: [shell]", ctx.line("shell"))
        return
    for k, v in sh.items():
        if k == "managed":
            m = {True: "on", False: "off"}.get(v) if isinstance(v, bool) else (
                SHELL_MODES.get(v.strip().lower()) if isinstance(v, str) else None)
            if m is None:
                out.managed_invalid = True
                ctx.add("error", 'managed must be "on", "warn" or "off" (the approved mode '
                        "stays until it's fixed)", ctx.line("shell", "managed"))
            else:
                out.managed = m
        elif k in ("import_path", "import_env"):
            line = ctx.line("shell", k)
            if not isinstance(v, list):
                ctx.add("error", f"{k} must be a list, like {k} = [\"...\"]", line)
                continue
            limit = IMPORT_PATH_MAX if k == "import_path" else IMPORT_ENV_MAX
            got: list[str] = []
            for item in v:
                val, why = (import_path_entry if k == "import_path" else import_env_entry)(item)
                if val is None:
                    ctx.add("error", f"shell: {why}; that entry is left out", line)
                elif val in got:
                    ctx.add("warning", f"shell: {val} is listed twice in {k}", line)
                elif len(got) >= limit:
                    ctx.add("error", f"shell: {k} takes at most {limit} entries; the rest are "
                            "left out", line)
                    break
                else:
                    got.append(val)
            if k == "import_path":
                out.import_path, out.path_line = got, line
            else:
                out.import_env, out.env_line = got, line
        else:
            ctx.add("warning", f"shell: {_suggest(k, SHELL_KEYS)}",
                    ctx.line("shell", k) if safe(k) else ctx.line("shell"))


def _policy_global(ctx: _Ctx, pt: Any, form: Form) -> None:
    """[policy]: restrictions for every host and account (PLAN-v4 phase 7).
    A bad key or value is an error and counts as "deny" until it is fixed
    (a misspelt restriction never quietly doesn't apply); a grant key may
    only keep its grant off here (deny / ask): forwarding is turned on per
    host."""
    form.policy_line = ctx.line("policy")
    if not isinstance(pt, dict):
        ctx.add("error", "policy must be a table: [policy]", ctx.line("policy"))
        return
    for k, v in pt.items():
        line = ctx.line("policy", k) if safe(k) else ctx.line("policy")
        if not isinstance(k, str) or k not in GLOBAL_POLICY_KEYS:
            ctx.add("error", f"policy: {_suggest(k, GLOBAL_POLICY_KEYS) if safe(k) else 'an unknown key'}",
                    line)
            continue
        w = policy_word(v)
        if w is _BAD:
            ctx.add("error", f"policy: {k} must be \"allow\", \"ask\" or \"deny\" (\"deny\" "
                    "until it's fixed)", line)
            w = False
        elif k in POLICY_GRANT and w is True:
            ctx.add("error", f"policy: {k} is turned on per host ([hosts.NAME.policy] {k} = "
                    "\"allow\"); [policy] can only keep it off (\"deny\" until it's fixed)", line)
            w = False
        form.policy[k] = w
        if line:
            form.policy_lines[k] = line


_RIGHTS_LINE = re.compile(r"^\s*(ssh|sudo|scripts|use|default|packages)\s*=")


def _syntax_problem(e: tomllib.TOMLDecodeError, text: str = "") -> Problem:
    msg = str(e)
    m = re.search(r"\(at line (\d+), column (\d+)\)", msg)
    line = int(m.group(1)) if m else None
    base = re.sub(r"\s*\(at line \d+, column \d+\)", "", msg).strip() or "syntax error"
    hint = ""
    if "Invalid value" in base or "invalid value" in base.lower():
        lines = text.splitlines()
        km = _RIGHTS_LINE.match(lines[line - 1]) if line and 0 < line <= len(lines) else None
        if km and km.group(1) in ("ssh", "sudo"):
            hint = f' ({km.group(1)} takes true, "ask" or false)'
        elif km:
            hint = f" ({km.group(1)} takes true or false)"
        else:
            hint = " (text values need quotes, like note = \"lab box\")"
    if unsafe_text(base):
        base = "syntax error"
    return Problem("error", f"the form can't be read: {base}{hint}", line)


def syntax_note(form: "Form") -> str | None:
    """For messages that would otherwise send Claude to add an entry: the
    form has a syntax error, so what the gateway uses now is the last good
    version (or only the defaults). None when it parses."""
    p = form.syntax_error
    if p is None:
        return None
    where = f" on line {p.line}" if p.line else ""
    meanwhile = ("the gateway uses the last good version meanwhile" if form.from_last_good
                 else "only the defaults apply meanwhile")
    return (f"gateway.toml has a syntax error{where} ({meanwhile}); fix that first (gate status "
            "shows it)")


def parse_text(text: str, path: Path | None = None, last_good: str | None = None) -> Form:
    """Parse and validate form text (no caching, no file access)."""
    form = Form(path=path or paths.form_path(), exists=True, text=text)
    used = text
    try:
        doc = tomllib.loads(normalize_lenient(text))
    except tomllib.TOMLDecodeError as e:
        form.syntax_error = _syntax_problem(e, normalize_lenient(text))
        doc = None
        if last_good is not None and last_good != text:
            try:
                doc = tomllib.loads(normalize_lenient(last_good))
                used = last_good
                form.from_last_good = True
            except tomllib.TOMLDecodeError:
                doc = None
        if doc is None:
            doc = {}
            used = ""
    form.used_text = used
    form.sha256 = hashlib.sha256(used.encode()).hexdigest()
    validate(doc, form, line_index(used))
    return form


def _not_utf8(p: Path, raw: bytes, err: UnicodeDecodeError, last_good: str | None) -> Form:
    """A form that isn't UTF-8 is treated like a syntax error: the last good
    form is used (if any) and the problem names the line."""
    line = raw[:err.start].count(b"\n") + 1
    f = parse_text(last_good if last_good is not None else "", p)
    f.text = raw.decode("utf-8", errors="replace")
    f.from_last_good = last_good is not None
    f.syntax_error = Problem("error", "the form can't be read: it isn't UTF-8 text (save it as "
                             "UTF-8)", line)
    return f


def apply_install_defaults(form: Form, older_install: bool) -> None:
    """Set the defaults that depend on the install (review round 3): sudo on
    this computer where the form doesn't say (Host.sudo_default) is "ask" on a
    new install and true on one whose vault an older gateway made (its
    default then, so that install keeps its rights). consent.compute calls
    this with the vault before it reads the form's rights, so every reader
    after it (the approval hook's form right, snapshots, approvals) sees the
    same value; each call sets it again (a cached form follows the vault)."""
    h = form.hosts.get("localhost")
    if h is not None and h.sudo_default:
        h.sudo = LOCALHOST_SUDO_OLDER if older_install else LOCALHOST_SUDO


_CACHE: dict[str, tuple[int, int, str | None, Form]] = {}


def load(path: Path | None = None, last_good: str | None = None, use_cache: bool = True) -> Form:
    """The form at `path` (default ~/.config/gateway/gateway.toml), cached by
    mtime. A missing file is an empty form (localhost implicit)."""
    p = Path(path) if path else paths.form_path()
    try:
        st = p.stat()
    except FileNotFoundError:
        f = parse_text("", p)
        f.exists = False
        return f
    key = str(p)
    hit = _CACHE.get(key)
    if use_cache and hit and hit[0] == st.st_mtime_ns and hit[1] == st.st_size and hit[2] == last_good:
        return hit[3]
    raw = p.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as e:
        f = _not_utf8(p, raw, e, last_good)
        f.mtime_ns = st.st_mtime_ns
        _CACHE[key] = (st.st_mtime_ns, st.st_size, last_good, f)
        return f
    f = parse_text(text, p, last_good)
    f.mtime_ns = st.st_mtime_ns
    _CACHE[key] = (st.st_mtime_ns, st.st_size, last_good, f)
    return f


def clear_cache() -> None:
    _CACHE.clear()


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------


class FormWriteError(Exception):
    """The change was not written (the form is unchanged)."""


def toml_value(v: Any) -> str:
    """A TOML value for the writer (strings, bools, ints, lists, inline tables)."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, int):
        return str(v)
    if isinstance(v, str):
        if unsafe_text(v):
            raise FormWriteError("refusing to write control characters or bidi overrides")
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(v, (list, tuple)):
        return "[" + ", ".join(toml_value(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"{_key(k)} = {toml_value(x)}" for k, x in v.items()) + "}"
    raise FormWriteError(f"can't write a {type(v).__name__}")


def _key(k: str) -> str:
    return k if re.fullmatch(_BARE, k) else toml_value(k)


def _header(table: str) -> str:
    parts = table.split(".")
    if not all(re.fullmatch(_BARE, p) for p in parts):
        raise FormWriteError("table names must be plain words")
    return "[" + ".".join(parts) + "]"


def _doc(text: str) -> dict[str, Any]:
    return tomllib.loads(normalize_lenient(text))


def _entry_errors(text: str) -> dict[str, list[str]]:
    f = parse_text(text)
    out: dict[str, list[str]] = {}
    for p in f.problems:
        if p.level == "error":
            out.setdefault(p.entry or "", []).append(p.message)
    return out


def _atomic_write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    mode = 0o600
    try:
        mode = p.stat().st_mode & 0o777
    except FileNotFoundError:
        pass
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, p)
    finally:
        if tmp.exists():
            tmp.unlink()
    _CACHE.pop(str(p), None)


def _commit(p: Path, old: str, new: str, expect_doc: dict[str, Any], entry: str) -> None:
    try:
        got = _doc(new)
    except tomllib.TOMLDecodeError as e:
        raise FormWriteError(f"the change would break the form ({e})") from None
    if got != expect_doc:
        raise FormWriteError("the change would alter other parts of the form; not written")
    before = _entry_errors(old)
    after = _entry_errors(new)
    for k in set(before) | set(after):
        # Another entry may lose errors (the change fixes it), never gain new ones.
        if k != entry and not set(after.get(k, [])) <= set(before.get(k, [])):
            raise FormWriteError(f"the change would affect {k or 'the form'}; not written")
    _atomic_write(p, new)
    if p.read_text(encoding="utf-8") != new:  # pragma: no cover - paranoia
        _atomic_write(p, old)
        raise FormWriteError("the form changed while writing; restored")


def append_table(table: str, items: dict[str, Any] | list[tuple[str, Any]],
                 comment: str | list[str] = "", path: Path | None = None) -> None:
    """Append [table] with items and a comment header. Refuses if the table
    exists or the form can't be parsed."""
    p = Path(path) if path else paths.form_path()
    old = p.read_text(encoding="utf-8") if p.exists() else ""
    try:
        doc = _doc(old)
    except tomllib.TOMLDecodeError:
        raise FormWriteError("the form has a syntax error; fix it first") from None
    pairs = list(items.items()) if isinstance(items, dict) else list(items)
    parts = table.split(".")
    cur: Any = doc
    for part in parts[:-1]:
        cur = cur.setdefault(part, {})
        if not isinstance(cur, dict):
            raise FormWriteError(f"{table}: its parent isn't a table")
    if parts[-1] in cur:
        raise FormWriteError(f"[{table}] already exists")
    cur[parts[-1]] = {k: v for k, v in pairs}
    lines = []
    if old and not old.endswith("\n"):
        lines.append("")
    if old.strip():
        lines.append("")
    for c in ([comment] if isinstance(comment, str) else comment):
        if c:
            for cl in c.split("\n"):
                if unsafe_text(cl.replace("\n", "")):
                    raise FormWriteError("comment holds control characters")
                lines.append(f"# {cl}" if cl else "#")
    lines.append(_header(table))
    width = max((len(k) for k, _ in pairs), default=0)
    for k, v in pairs:
        lines.append(f"{_key(k).ljust(width)} = {toml_value(v)}")
    new = old + "\n".join(lines) + "\n"
    _commit(p, old, new, doc, parts[-1] if len(parts) > 1 else table)


def _find_comment(s: str) -> int:
    """Index of a trailing # comment in a value tail, or -1."""
    q = None
    i = 0
    while i < len(s):
        c = s[i]
        if q:
            if c == "\\" and q == '"':
                i += 2
                continue
            if c == q:
                q = None
        elif c in ('"', "'"):
            q = c
        elif c == "#":
            return i
        i += 1
    return -1


def _depth(s: str) -> int:
    """Net [ and { nesting of a value fragment (strings and comments skipped)."""
    d, q, i = 0, None, 0
    while i < len(s):
        c = s[i]
        if q:
            if c == "\\" and q == '"':
                i += 2
                continue
            if c == q:
                q = None
        elif c in ('"', "'"):
            q = c
        elif c == "#":
            break
        elif c in "[{":
            d += 1
        elif c in "]}":
            d -= 1
        i += 1
    return d


def _value_end(lines: list[str], i: int, col: int) -> int:
    """The last line of the value that starts on line i at column col."""
    d = _depth(lines[i][col:])
    while d > 0 and i + 1 < len(lines):
        i += 1
        d += _depth(lines[i])
    return i


def set_key(table: str, key: str, value: Any, path: Path | None = None) -> None:
    """Replace the single `key = value` line inside [table] (or add it after
    the table's last key). Multi-line values are refused."""
    p = Path(path) if path else paths.form_path()
    if not p.exists():
        raise FormWriteError("there is no form yet")
    old = p.read_text(encoding="utf-8")
    try:
        doc = _doc(old)
    except tomllib.TOMLDecodeError:
        raise FormWriteError("the form has a syntax error; fix it first") from None
    parts = tuple(table.split("."))
    cur: Any = doc
    for part in parts:
        if not isinstance(cur, dict) or part not in cur:
            raise FormWriteError(f"[{table}] isn't in the form")
        cur = cur[part]
    if not isinstance(cur, dict):
        raise FormWriteError(f"{table} isn't a table")
    cur[key] = value
    if not re.fullmatch(_BARE, key):
        raise FormWriteError("keys must be plain words")
    lines = old.split("\n")
    start = None
    for i, line in enumerate(lines):
        m = _HEADER.match(line)
        if m and not _KEYLINE.match(line) and _split_dotted(m.group(2)) == parts and not m.group(1):
            start = i
            break
    if start is None:
        raise FormWriteError(f"[{table}] isn't written as its own table; edit it by hand")
    end = len(lines)
    for i in range(start + 1, len(lines)):
        m = _HEADER.match(lines[i])
        if m and not _KEYLINE.match(lines[i]):
            end = i
            break
    target = None
    last_key = start
    i = start + 1
    while i < end:
        m = _KEYLINE.match(lines[i])
        if m:
            if _split_dotted(m.group(1)) == (key,):
                target = i
            i = _value_end(lines, i, m.end())
            last_key = i
        i += 1
    newval = toml_value(value)
    if target is not None:
        line = lines[target]
        m = _KEYLINE.match(line)
        assert m
        tail = line[m.end():]
        stripped = tail.strip()
        if stripped.startswith("[") and stripped.count("[") != stripped.count("]"):
            raise FormWriteError(f"{key} spans several lines; edit it by hand")
        if stripped.startswith(('"""', "'''")):
            raise FormWriteError(f"{key} spans several lines; edit it by hand")
        ci = _find_comment(tail)
        comment = tail[ci:] if ci >= 0 else ""
        lead = line[:m.end()]
        if not lead.endswith(" "):
            lead += " "
        pad = ""
        if comment:
            val_part = tail[:ci]
            pad = " " * max(1, len(val_part) - len(val_part.rstrip()))
        lines[target] = lead + newval + (pad + comment if comment else "")
    else:
        lines.insert(last_key + 1, f"{key} = {newval}")
    new = "\n".join(lines)
    _commit(p, old, new, doc, parts[-1])
