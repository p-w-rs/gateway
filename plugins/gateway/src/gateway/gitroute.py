"""The shared git resolver (PLAN-0.11 §6.2): which repository and remotes a
git command reaches, and whether the gateway handles it.

    resolve(argv, cwd=None, *, targets, env=None) -> Route
    Targets.from_forms(*forms) -> Targets         what counts as configured

The git stand-in and the approval hook use this one resolver. `argv` is
git's arguments after the program name (`["push", "origin"]`).

Repository and config. The bundled git (paths.tool("git")) reads the
effective config the way the user's git would: in that repository, with the
command's own repository options (-C, --git-dir, --work-tree, --bare) and
the inherited environment (GIT_DIR, GIT_WORK_TREE, HOME, GIT_CONFIG_*), so
the user's global config and the repository's config come with their
includes and includeIf resolved by git; the command line's -c and
--config-env pairs come on top. Only `rev-parse` and `config` run (with
core.fsmonitor cleared), never a command that touches the index, the hooks
or the network. The work tree's .gitmodules and .lfsconfig are read the same
way (`git config --file`).

Aliases are resolved first (a word that isn't a git command, as git 2.56
does it): `[alias "NAME"] command = ...` (`alias.NAME.command`, its name
matched case by case) before `alias.NAME` (any case); a deprecated command
(`git --list-cmds=deprecated`) can be replaced by an alias. An alias to a git
subcommand is that subcommand (an alias's own -c pairs are read too); a `!`
alias in a repository the gateway handles is refused (SHELL_ALIAS).

Effective URLs: every remote's url (all of its values) and pushurl after
insteadOf and pushInsteadOf (the longest match, git's rules), the operand
URLs of commands that name a repository (clone, fetch, pull, push, ls-remote,
archive --remote, remote add|set-url, submodule add, the remote helpers and
http-fetch|push, ...), branch.*.remote and branch.*.pushRemote and
remote.pushDefault when they name a URL, the submodules' URLs (config and
.gitmodules) and git-lfs's (lfs.url, lfs.pushurl, remote.*.lfsurl and
lfspushurl, also from .lfsconfig). `clone` reads no repository: the
folder's own config (local and worktree scope, .gitmodules, .lfsconfig)
doesn't apply to it, as git clone ignores it; aliases still come from every
scope, as git reads them.

A URL is configured when its host is a configured host (`[hosts.X]` by name,
gw-NAME, address or `also` entry; never localhost) or when a configured
account covers its host and owner (accounts.destinations, ssh endpoints, the
account's own `host`: GHES counts; the owner by login and owners, a default
account, the only account of its kind for that host when it lists no
`owners` (one that lists them covers only those and its login), or an owner
the URL doesn't name: accounts.owner_covered). An `ext::` URL's words are
each checked as a host. A disabled entry (a mistake in it) stays configured
(PLAN-0.11 §1.1): a host by its name, an account whose kind could be read by
that kind's own destinations and ssh endpoints, for every owner (its
stand-in then refuses it).

Rule: gated routing for every git command in a repository where any
effective URL is configured, and for any command whose operand URL is
configured; everything else passes through. `git config --global`,
`--system` and `--file` always pass through (they write the user's own
config): options only, before the first word that isn't one, as git parses
them (`git config set k --global` writes the repository's own config). When
the config can't be read while something is configured, the command is
refused (UNREADABLE): the gateway can't tell what it reaches. A repository
git won't open (another user's, without the user's safe.directory) is no
repository to the bundled git, as to the user's.

The URLs a Route reports carry no user or password (a token in a remote URL
stays out of every message and audit line).
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from . import accounts, paths
from . import form as formmod

SHELL_ALIAS = ("gateway: a shell alias in a repository the gateway handles; run the commands it "
               "stands for.")
UNREADABLE = ("gateway: git couldn't read the settings of this repository (a broken config file, a "
              "folder that isn't there, or git didn't answer), so the gateway can't tell whether it "
              "handles it; nothing ran.")

GIT_TIMEOUT = 5.0
MAX_ALIAS_DEPTH = 16

# git's commands (git --list-cmds=main of git 2.56, and git-lfs) ...
_COMMANDS = frozenset("""
add am annotate apply archimport archive backfill bisect blame branch bugreport bundle cat-file
check-attr check-ignore check-mailmap check-ref-format checkout checkout-index cherry cherry-pick
citool clean clone column commit commit-graph commit-tree config count-objects credential
credential-cache credential-store cvsexportcommit cvsimport cvsserver daemon describe diagnose
diff diff-files diff-index diff-pairs diff-tree difftool fast-export fast-import fetch fetch-pack
filter-branch fmt-merge-msg for-each-ref for-each-repo format-patch format-rev fsck fsck-objects
gc get-tar-commit-id grep gui hash-object help history hook http-backend http-fetch http-push
imap-send index-pack init init-db instaweb interpret-trailers last-modified log ls-files ls-remote
ls-tree mailinfo mailsplit maintenance merge merge-base merge-file merge-index merge-octopus
merge-one-file merge-ours merge-recursive merge-recursive-ours merge-recursive-theirs
merge-resolve merge-subtree merge-tree mergetool mktag mktree multi-pack-index mv name-rev notes
p4 pack-objects pack-redundant pack-refs patch-id pickaxe prune prune-packed pull push
quiltimport range-diff read-tree rebase receive-pack reflog refs remote remote-ext remote-fd
remote-ftp remote-ftps remote-http remote-https repack replace replay repo request-pull rerere
reset restore rev-list rev-parse revert rm send-email send-pack shell shortlog show show-branch
show-index show-ref sparse-checkout stage stash status stripspace submodule subtree svn switch
symbolic-ref tag unpack-file unpack-objects update-index update-ref update-server-info
upload-archive upload-pack url-parse var verify-commit verify-pack verify-tag version
whatchanged worktree write-tree lfs
""".split())
# ... less the deprecated ones (git --list-cmds=deprecated), which an alias
# replaces in git 2.56; an alias named after any other is ignored, as git
# ignores it.
DEPRECATED = frozenset({"whatchanged", "pack-redundant"})
KNOWN = _COMMANDS - DEPRECATED

# git's options before the subcommand (git(1)). These take the next word as
# their value:
_G_VALUE = ("-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env", "--attr-source")
# ... and these change which repository or config a command sees; they are
# passed to the resolver's own git calls, in order.
_G_KEEP = ("-C", "-c", "--git-dir", "--work-tree", "--config-env", "--bare")
_G_ENV_CHANGING = ("-C", "--git-dir", "--work-tree", "--namespace", "--bare")   # git refuses them in an alias
_G_FLAGS = ("-p", "--paginate", "-P", "--no-pager", "--no-replace-objects", "--no-lazy-fetch",
            "--no-optional-locks", "--no-advice", "--literal-pathspecs", "--glob-pathspecs",
            "--noglob-pathspecs", "--icase-pathspecs", "--exec-path", "--html-path", "--man-path",
            "--info-path")

# The plumbing that takes a repository's URL: the remote helpers (`git
# remote-https NAME URL`; remote-ext's URL is what follows `ext::`) and the
# dumb-http transports.
_URL_PLUMBING = frozenset({"remote-http", "remote-https", "remote-ftp", "remote-ftps", "remote-ext",
                           "http-fetch", "http-push"})
# Commands whose arguments may name a repository by URL (their operands are
# checked); for archive only --remote's value.
OPERAND_COMMANDS = frozenset({"clone", "fetch", "pull", "push", "ls-remote", "fetch-pack",
                              "send-pack", "request-pull", "remote", "submodule", "lfs"}) | _URL_PLUMBING
# Commands that touch a remote (for the pass-through audit and the hook's
# up-front judging); `remote`, `submodule`, `lfs` and `archive` by their
# own subcommand or option.
REMOTE_COMMANDS = frozenset({"push", "fetch", "pull", "clone", "ls-remote", "fetch-pack",
                             "send-pack", "request-pull"}) | _URL_PLUMBING
_REMOTE_SUB = {"remote": frozenset({"update", "show", "prune"}),
               "submodule": frozenset({"update", "add"}),
               "lfs": frozenset({"push", "pull", "fetch", "clone"})}

# The scopes `git config --show-scope` gives the repository's own config.
REPO_SCOPES = ("local", "worktree")

_HOST = re.compile(r"[A-Za-z0-9_]([A-Za-z0-9_.-]{0,252})?")
_TRANSPORT = re.compile(r"([A-Za-z][A-Za-z0-9+.-]*)::(.*)", re.S)
_SCHEME = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*")
OWNER_KINDS = ("github", "huggingface")


# ---------------------------------------------------------------------------
# What counts as configured
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AccountReach:
    """What one configured account covers: its destinations (accounts.
    destinations, the account's `host` included), its ssh endpoints' hosts,
    who it routes for (login and owners, lowercased), whether it is the
    default for its hosts, and whether it lists no `owners` (any_owner: only
    then does the only account of its kind for a host cover every owner)."""
    name: str
    kind: str
    dests: tuple[str, ...]
    ssh_hosts: tuple[str, ...] = ()
    owners: tuple[str, ...] = ()
    default: bool = False
    any_owner: bool = False


@dataclass
class Targets:
    """The configured set as git URLs see it: host words (lowercased name,
    gw-NAME, address and `also` hosts) -> the [hosts.X] entry, and the
    accounts' reach. Built from the form, and by the configured set's owner
    (WS-A1) from the approved snapshot and private/configured.json too:
    `merged` unions them."""
    hosts: dict[str, str] = field(default_factory=dict)
    accounts: tuple[AccountReach, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.hosts or self.accounts)

    @classmethod
    def from_forms(cls, *forms: Any) -> "Targets":
        out = cls()
        for f in forms:
            if f is not None:
                out = out.merged(cls._from_form(f))
        return out

    @classmethod
    def _from_form(cls, form: Any) -> "Targets":
        hosts: dict[str, str] = {}
        for name, h in (getattr(form, "hosts", None) or {}).items():
            if name == "localhost":
                continue
            words = [name, f"gw-{name}"]
            words += [a.host for a in h.addresses() if getattr(a, "host", None)]
            for w in words:
                hosts.setdefault(_norm_host(w), name)
        # a disabled entry (a mistake in it) stays configured (PLAN-0.11 §1.1):
        # its name is all that is known of it
        kinds = getattr(form, "disabled_kinds", None) or {}
        for name in (getattr(form, "disabled", None) or {}):
            if name != "localhost" and name not in kinds:
                for w in (name, f"gw-{name}"):
                    hosts.setdefault(_norm_host(w), name)
        reach = []
        for name, a in (getattr(form, "accounts", None) or {}).items():
            reach.append(_reach(name, a, default=bool(a.default)))
        # a disabled account whose kind could be read: its own destinations
        # and ssh endpoints as far as they still parse (form.disabled_accounts;
        # its owners are unknown), for every owner there, so its stand-in
        # finds it off
        lenient = getattr(form, "disabled_accounts", None) or {}
        for name, kind in kinds.items():
            reach.append(_reach(name, lenient.get(name) or formmod.Account(name=name, kind=kind),
                                default=True))
        return cls(hosts=hosts, accounts=tuple(reach))

    def merged(self, other: "Targets") -> "Targets":
        hosts = dict(self.hosts)
        for w, n in other.hosts.items():
            hosts.setdefault(w, n)
        seen = {(a.name, a) for a in self.accounts}
        accts = list(self.accounts) + [a for a in other.accounts if (a.name, a) not in seen]
        return Targets(hosts=hosts, accounts=tuple(accts))

    # -- matching ------------------------------------------------------------
    def hits(self, where: "Where") -> tuple[tuple[str, str], ...]:
        """The configured entries a URL reaches: ("hosts", NAME) and
        ("accounts", NAME) pairs."""
        out: list[tuple[str, str]] = []
        words = where.words if where.scheme == "ext" else ([where.host] if where.host else [])
        for w in words:
            n = self.hosts.get(w)
            if n is not None and ("hosts", n) not in out:
                out.append(("hosts", n))
        for a in self.accounts:
            if any(self._covers_host(a, where, w) for w in words) and self._covers_owner(a, where):
                if ("accounts", a.name) not in out:
                    out.append(("accounts", a.name))
        return tuple(out)

    @staticmethod
    def _covers_host(a: AccountReach, where: "Where", word: str) -> bool:
        if where.scheme in ("http", "https") and where.port and where.port not in ("80", "443"):
            if accounts.covers(a.dests, f"{word}:{where.port}"):
                return True
            return False
        return word in a.ssh_hosts or accounts.covers(a.dests, word)

    def _covers_owner(self, a: AccountReach, where: "Where") -> bool:
        if a.kind not in OWNER_KINDS or where.scheme == "ext":
            return True
        owner = accounts.owner_from_path(where.path, a.kind)
        # the only account of its kind for that host (by name: the merged
        # sets may hold one account twice) covers another owner only when it
        # lists no owners (accounts.owner_covered)
        hosts = [where.host] if where.host else []
        same = {b.name for b in self.accounts if b.kind == a.kind
                and any(self._covers_host(b, where, w) for w in hosts)}
        return accounts.owner_covered(owner, a.owners, default=a.default, any_owner=a.any_owner,
                                      only=len(same) == 1)


def _reach(name: str, a: Any, *, default: bool) -> AccountReach:
    return AccountReach(
        name=name, kind=a.kind, dests=tuple(d.lower() for d in accounts.destinations(a)),
        ssh_hosts=tuple(h.lower() for _u, h in accounts.ssh_endpoints(a)),
        owners=tuple(o.lower() for o in a.owner_names() if o), default=default,
        any_owner=not a.owners)


def _norm_host(h: str) -> str:
    h = h.strip().lower().rstrip(".")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    return h


# ---------------------------------------------------------------------------
# URLs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Where:
    """Where a URL points: scheme ("https", "ssh", "git", "scp" for
    [user@]host:path, "ext", "local", ...), host (lowercased, no brackets, no
    port; "" for a local path), port, path, and for ext:: its words."""
    scheme: str
    host: str = ""
    port: str = ""
    path: str = ""
    words: tuple[str, ...] = ()

    @property
    def remote(self) -> bool:
        return bool(self.host or self.words)


def _valid_host(h: str) -> bool:
    if not h:
        return False
    if ":" in h:                                       # IPv6, from brackets
        return bool(re.fullmatch(r"[0-9A-Fa-f:.%a-zA-Z]+", h))
    return bool(_HOST.fullmatch(h))


def _split_hostport(hp: str) -> tuple[str, str]:
    if hp.startswith("["):
        host, _, rest = hp[1:].partition("]")
        return host, rest[1:] if rest.startswith(":") else ""
    if hp.count(":") == 1:
        host, port = hp.split(":")
        return host, port
    return hp, ""


def parse_url(u: str) -> Where:
    """Where git would go for repository `u` (git's own rules: a URL with
    ://, a transport helper's `<transport>::<address>`, the scp-like
    [user@]host:path when no slash comes before the first colon, else a
    local path)."""
    s = u.strip()
    m = _TRANSPORT.fullmatch(s)
    if m:
        transport, rest = m.group(1).lower(), m.group(2)
        if transport == "ext":
            words = []
            for w in rest.split():
                w = w.rsplit("@", 1)[-1]
                h, _p = _split_hostport(w) if not w.startswith("/") else ("", "")
                h = _norm_host(h)
                if _valid_host(h) and not h.startswith("%"):
                    words.append(h)
            return Where("ext", words=tuple(dict.fromkeys(words)))
        if transport == "fd":
            return Where("local", path=rest)
        inner = parse_url(rest)
        return inner
    if "://" in s and _SCHEME.fullmatch(s.partition("://")[0]):
        scheme, _, rest = s.partition("://")
        scheme = scheme.lower()
        if scheme == "file":
            return Where("local", path=rest)
        authority, slash, path = rest.partition("/")
        authority = authority.split("?", 1)[0].split("#", 1)[0]
        _user, _at, hostport = authority.rpartition("@")
        host, port = _split_hostport(hostport)
        host = _norm_host(host)
        if not _valid_host(host):
            return Where("local", path=s)
        return Where(scheme, host, port, slash + path)
    colon = s.find(":")
    slash = s.find("/")
    if colon > 0 and (slash < 0 or colon < slash) and not re.match(r"[A-Za-z]:[\\/]", s):
        hostpart, path = s[:colon], s[colon + 1:]
        if s.startswith("[") or "@[" in s:                 # [host]:path, user@[::1]:path
            close = s.find("]")
            if close > 0 and s[close + 1:close + 2] == ":":
                hostpart, path = s[:close + 1], s[close + 2:]
        host = _norm_host(hostpart.rsplit("@", 1)[-1])
        host, _port = _split_hostport(host) if host.count(":") == 1 else (host, "")
        if _valid_host(host):
            return Where("scp", host, "", path)
    return Where("local", path=s)


def shown(u: str) -> str:
    """A URL without its user or password (never shown or recorded)."""
    s = u.strip()
    if "://" in s:
        scheme, _, rest = s.partition("://")
        authority, slash, path = rest.partition("/")
        if "@" in authority:
            authority = authority.rpartition("@")[2]
        return f"{scheme}://{authority}{slash}{path}"
    return s


def _rewrite(url: str, rules: Sequence[tuple[str, str]]) -> str | None:
    """git's alias_url: the longest insteadOf prefix (the first of equal
    length) replaced by its base; None when no rule matches."""
    best: tuple[str, str] | None = None
    for base, prefix in rules:
        if url.startswith(prefix) and (best is None or len(prefix) > len(best[1])):
            best = (base, prefix)
    if best is None:
        return None
    return best[0] + url[len(best[1]):]


# ---------------------------------------------------------------------------
# The Route
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Url:
    """One effective URL: where it points, what it is used for ("fetch",
    "push"), where it came from (a config key, "operand", "gitmodules",
    "lfsconfig"), and the configured entries it reaches."""
    url: str
    where: Where
    use: frozenset[str]
    source: str
    hits: tuple[tuple[str, str], ...] = ()

    @property
    def host(self) -> str:
        return self.where.host

    @property
    def owner(self) -> str:
        return accounts.owner_from_path(self.where.path) or ""


@dataclass(frozen=True)
class Route:
    """How one git command is handled.

    command, args   the subcommand and its arguments after alias expansion
                    ("" when there is none: `git --version`, a bad option)
    alias           the alias the command used ("" for none)
    alias_globals   git's own options the alias (and any alias it led to)
                    put before its subcommand (`-c KEY=VALUE`, `--config-env`):
                    git applies them after the command line's (WS-4's
                    guarded_c reads them)
    shell_alias     the alias (or one it led to) is a `!` shell alias
    repo, worktree  the repository's git dir and work tree ("" for none, and
                    for clone, which reads no repository)
    urls            every effective URL found; configured: those that reach
                    a configured entry
    gated           the gateway's git runs it (the rule above)
    remote          the command touches a remote
    refusal         a fixed refusal ("" for none): SHELL_ALIAS or UNREADABLE
    error           why the config couldn't be read ("" when it could)
    """
    command: str
    args: tuple[str, ...]
    alias: str = ""
    alias_globals: tuple[str, ...] = ()
    shell_alias: bool = False
    repo: str = ""
    worktree: str = ""
    urls: tuple[Url, ...] = ()
    gated: bool = False
    remote: bool = False
    refusal: str = ""
    error: str = ""

    @property
    def configured(self) -> tuple[Url, ...]:
        return tuple(u for u in self.urls if u.hits)

    def entries(self) -> tuple[tuple[str, str], ...]:
        """Every configured entry the command may reach, once each."""
        out: list[tuple[str, str]] = []
        for u in self.urls:
            for h in u.hits:
                if h not in out:
                    out.append(h)
        return tuple(out)


# ---------------------------------------------------------------------------
# Parsing the command line
# ---------------------------------------------------------------------------


def split_globals(args: Sequence[str]) -> tuple[list[str], str, list[str], bool]:
    """(the repository and config options to keep, the subcommand, its
    arguments, whether git would refuse the options). -v/--version and
    -h/--help are the version and help commands, as in git."""
    keep: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a in _G_VALUE:
            if i + 1 >= len(args):
                return keep, "", [], True
            if a in _G_KEEP:
                keep += [a, args[i + 1]]
            i += 2
            continue
        if a.startswith(("--git-dir=", "--work-tree=", "--config-env=")):
            keep.append(a)
            i += 1
            continue
        if a == "--bare":
            keep.append(a)
            i += 1
            continue
        if a.startswith(("--namespace=", "--attr-source=", "--exec-path=", "--list-cmds=")) \
                or a in _G_FLAGS:
            i += 1
            continue
        if a in ("-v", "--version"):
            return keep, "version", list(args[i + 1:]), False
        if a in ("-h", "--help"):
            return keep, "help", list(args[i + 1:]), False
        if a.startswith("-"):
            return keep, "", list(args[i:]), True
        return keep, a, list(args[i + 1:]), False
    return keep, "", [], False


def _clone_config(args: Sequence[str]) -> list[tuple[str, str, str]]:
    """clone's own -c/--config key=value pairs: they apply to the new
    repository before anything is fetched (an insteadOf among them rewrites
    the clone's own URL)."""
    out = []
    i = 0
    while i < len(args):
        a, val = args[i], None
        if a == "--":
            break
        if a in ("-c", "--config") and i + 1 < len(args):
            val, i = args[i + 1], i + 2
        elif a.startswith("--config="):
            val, i = a[len("--config="):], i + 1
        elif a.startswith("-c") and len(a) > 2:
            val, i = a[2:], i + 1
        else:
            i += 1
        if val and "=" in val:
            k, _, v = val.partition("=")
            out.append(("command", _norm_key(k), v))
    return out


def _operand_tokens(command: str, args: Sequence[str]) -> list[str]:
    """The words of a command that may name a repository by URL: every
    argument and option value of the commands that take one (archive: only
    --remote's)."""
    if command == "archive":
        out = []
        for i, a in enumerate(args):
            if a.startswith("--remote="):
                out.append(a[len("--remote="):])
            elif a == "--remote" and i + 1 < len(args):
                out.append(args[i + 1])
        return out
    if command not in OPERAND_COMMANDS:
        return []
    out = []
    for a in args:
        if a.startswith("--") and "=" in a:
            out.append(a.split("=", 1)[1])
        elif not a.startswith("-") or a == "-":
            out.append(a)
    if command == "remote-ext":
        out = [f"ext::{a}" for a in out]
    return out


def _is_remote(command: str, args: Sequence[str]) -> bool:
    if command in REMOTE_COMMANDS:
        return True
    if command == "archive":
        return any(a == "--remote" or a.startswith("--remote=") for a in args)
    subs = _REMOTE_SUB.get(command)
    if subs:
        first = next((a for a in args if not a.startswith("-")), "")
        return first in subs
    return False


# git config's subcommands (git 2.56), its options that pick the user's own
# config file, and those that take the next word as their value.
_CONFIG_SUBCOMMANDS = ("list", "get", "set", "unset", "rename-section", "remove-section", "edit")
_CONFIG_OWN = ("global", "system", "file")
_CONFIG_VALUED = ("type", "default", "comment", "value", "url", "blob")


def _config_writes_users_own(command: str, args: Sequence[str]) -> bool:
    """`git config --global|--system|--file`: the user's own config, which the
    gateway's git never reads. Read as git parses it: after an optional
    subcommand, options up to `--` or the first other word (the key; what
    follows it is a value or a value pattern, never an option), a value
    option taking the next word (`--comment --global` is a comment), a
    `--no-` form undoing its option, and a long option by any prefix (git
    takes an unambiguous one and refuses an ambiguous one, which writes
    nothing)."""
    if command != "config":
        return False
    words = list(args)
    if words and words[0] in _CONFIG_SUBCOMMANDS:
        words = words[1:]
    own: dict[str, bool] = {}
    i = 0
    while i < len(words):
        a = words[i]
        i += 1
        if a == "--" or not a.startswith("-") or a == "-":
            break
        if a.startswith("--"):
            name, eq, _val = a[2:].partition("=")
            if name.startswith("no-"):
                for o in _CONFIG_OWN:
                    if name[3:] and o.startswith(name[3:]):
                        own[o] = False
                continue
            hit = next((o for o in _CONFIG_OWN if name and o.startswith(name)), None)
            if hit:
                own[hit] = True
            if not eq and name and (hit == "file" or not hit and
                                    any(o.startswith(name) for o in _CONFIG_VALUED)):
                i += 1                            # its value is the next word
            continue
        for j, ch in enumerate(a[1:], 1):         # short options, maybe clustered
            if ch == "f":
                own["file"] = True
                if j == len(a) - 1:
                    i += 1                        # -f FILE
                break
            if ch == "t":
                if j == len(a) - 1:
                    i += 1                        # -t TYPE
                break
    return any(own.values())


# ---------------------------------------------------------------------------
# Reading the config
# ---------------------------------------------------------------------------


def _norm_key(k: str) -> str:
    """section.subsection.name with the section and name lowercased (as
    git prints keys)."""
    k = k.strip()
    first, last = k.find("."), k.rfind(".")
    if first < 0:
        return k.lower()
    if first == last:
        return k.lower()
    return k[:first].lower() + k[first:last] + k[last:].lower()


def _git_env(env: Mapping[str, str] | None) -> dict[str, str]:
    e = dict(os.environ if env is None else env)
    for k in list(e):
        if k.startswith("GIT_TRACE"):
            e.pop(k)                      # trace output is noise here, never a setting
    e["GIT_OPTIONAL_LOCKS"] = "0"
    e["GIT_TERMINAL_PROMPT"] = "0"
    return e


class _Unreadable(Exception):
    pass


def _parse_list(raw: bytes, scoped: bool) -> list[tuple[str, str, str]]:
    parts = raw.decode("utf-8", "surrogateescape").split("\0")
    out = []
    i = 0
    while i < len(parts):
        scope = "file"
        if scoped:
            scope = parts[i]
            i += 1
            if i >= len(parts):
                break
        kv = parts[i]
        i += 1
        if not kv:
            continue
        key, nl, val = kv.partition("\n")
        out.append((scope, key, val if nl else ""))
    return out


def _start(git: str, argv: list[str], cwd: str, env: dict[str, str]) -> subprocess.Popen:
    try:
        return subprocess.Popen([git, *argv], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as e:
        raise _Unreadable(type(e).__name__) from None


def _finish(p: subprocess.Popen) -> tuple[int, bytes]:
    try:
        out, _err = p.communicate(timeout=GIT_TIMEOUT)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        raise _Unreadable("timeout") from None
    return p.returncode, out


def _read_config(git: str, keep: list[str], cwd: str, env: dict[str, str]
                 ) -> tuple[list[tuple[str, str, str]], str, str]:
    """(config entries, git dir, work tree): `git config --list` and `git
    rev-parse` side by side, with the command's own repository options."""
    rp = _start(git, [*keep, "-c", "core.fsmonitor=", "rev-parse", "--is-bare-repository",
                      "--absolute-git-dir", "--show-toplevel"], cwd, env)
    try:
        cp = _start(git, [*keep, "-c", "core.fsmonitor=", "config", "-z", "--list", "--show-scope"],
                    cwd, env)
    except _Unreadable:
        rp.kill()
        rp.communicate()
        raise
    try:
        rc, out = _finish(cp)
    finally:
        rrc, rout = _finish(rp)
    if rc != 0:
        raise _Unreadable(f"git config exited {rc}")
    lines = rout.decode("utf-8", "surrogateescape").splitlines()
    gitdir = worktree = ""
    if len(lines) >= 2 and lines[0] in ("true", "false"):
        gitdir = lines[1]
        if rrc == 0 and lines[0] == "false" and len(lines) >= 3:
            worktree = lines[2]
    return _parse_list(out, True), gitdir, worktree


def _read_file(git: str, path: str, cwd: str, env: dict[str, str]) -> list[tuple[str, str, str]]:
    if not os.path.isfile(path):
        return []
    rc, out = _finish(_start(git, ["config", "-z", "--file", path, "--list"], cwd, env))
    if rc != 0:
        raise _Unreadable(f"git config --file exited {rc}")
    return _parse_list(out, False)


# ---------------------------------------------------------------------------
# Collecting the URLs
# ---------------------------------------------------------------------------


def _split_key(key: str) -> tuple[str, str, str]:
    first, last = key.find("."), key.rfind(".")
    if first < 0:
        return key, "", ""
    if first == last:
        return key[:first], "", key[last + 1:]
    return key[:first], key[first + 1:last], key[last + 1:]


@dataclass
class _Config:
    entries: list[tuple[str, str, str]]

    def __post_init__(self) -> None:
        self.remotes: dict[str, dict[str, list[str]]] = {}
        self.rewrites: list[tuple[str, str]] = []
        self.push_rewrites: list[tuple[str, str]] = []
        self.aliases: dict[str, str] = {}               # alias.NAME (git prints NAME lowercased)
        self.sub_aliases: dict[str, str] = {}           # alias.NAME.command (NAME as written)
        self.named: list[tuple[str, str, str]] = []     # (key, value, use) that may name a URL
        self.extra: list[tuple[str, str, str]] = []     # (key, value, use): URLs as such
        for _scope, key, val in self.entries:
            sec, sub, name = _split_key(key)
            if sec == "remote" and sub:
                r = self.remotes.setdefault(sub, {})
                if name in ("url", "pushurl", "lfsurl", "lfspushurl") and val:
                    r.setdefault(name, []).append(val)
            elif sec == "remote" and not sub and name == "pushdefault" and val:
                self.named.append((key, val, "push"))
            elif sec == "url" and sub and name == "insteadof":
                self.rewrites.append((sub, val))
            elif sec == "url" and sub and name == "pushinsteadof":
                self.push_rewrites.append((sub, val))
            elif sec == "alias" and not sub and name:
                self.aliases[name] = val
            elif sec == "alias" and sub and name == "command":
                self.sub_aliases[sub] = val
            elif sec == "branch" and sub and name in ("remote", "pushremote") and val:
                self.named.append((key, val, "fetch" if name == "remote" else "push"))
            elif sec == "submodule" and sub and name == "url" and val:
                self.extra.append((key, val, "fetch"))
            elif sec == "lfs" and not sub and name in ("url", "pushurl") and val:
                self.extra.append((key, val, "fetch" if name == "url" else "push"))

    def alias(self, word: str) -> str | None:
        """git 2.56's alias lookup: `[alias "word"] command` (case by case)
        before `alias.word` (any case); the last value of each wins."""
        val = self.sub_aliases.get(word)
        return self.aliases.get(word.lower()) if val is None else val


def _urls(cfg: _Config, operands: list[tuple[str, str]], files: list[tuple[str, list]],
          targets: Targets) -> list[Url]:
    out: list[Url] = []
    seen: set[tuple[str, str, frozenset[str]]] = set()

    def add(raw: str, use: Iterable[str], source: str, rewrite: str = "fetch") -> None:
        if not raw or raw.startswith(("./", "../")):
            return                            # relative (a submodule's): the same host as its remote
        if rewrite == "push":
            eff = _rewrite(raw, cfg.push_rewrites)
            if eff is None:
                eff = _rewrite(raw, cfg.rewrites) or raw
        else:
            eff = _rewrite(raw, cfg.rewrites) or raw
        where = parse_url(eff)
        if not where.remote:
            return
        u = frozenset(use)
        k = (shown(eff), source, u)
        if k in seen:
            return
        seen.add(k)
        out.append(Url(shown(eff), where, u, source, targets.hits(where)))

    for name, r in cfg.remotes.items():
        pushurls = r.get("pushurl", [])
        for v in r.get("url", []):
            add(v, ("fetch",) if pushurls else ("fetch", "push"), f"remote.{name}.url")
            if not pushurls and _rewrite(v, cfg.push_rewrites) is not None:
                add(v, ("push",), f"remote.{name}.url", rewrite="push")
        for v in pushurls:
            add(v, ("push",), f"remote.{name}.pushurl")
        for k, use in (("lfsurl", ("fetch", "push")), ("lfspushurl", ("push",))):
            for v in r.get(k, []):
                add(v, use, f"remote.{name}.{k}")
    for key, val, use in cfg.named:
        if val != "." and val not in cfg.remotes:
            add(val, (use,), key, rewrite=use)
    for key, val, use in cfg.extra:
        add(val, (use,), key, rewrite=use)
    for source, entries in files:
        sub = _Config(entries)
        for key, val, use in sub.extra:
            add(val, (use,), source, rewrite=use)
        for name, r in sub.remotes.items():
            for k, use in (("lfsurl", ("fetch", "push")), ("lfspushurl", ("push",))):
                for v in r.get(k, []):
                    add(v, use, source)
    for tok, use in operands:
        if tok in cfg.remotes:
            continue                          # a remote's name: its URLs are above
        if parse_url(tok).remote or _rewrite(tok, cfg.rewrites) is not None:
            add(tok, (use,), "operand", rewrite=use)
    return out


def _user_has_external(command: str, env: Mapping[str, str]) -> bool:
    """git runs a `git-<command>` program on PATH before it tries an alias."""
    return bool(command) and shutil.which(f"git-{command}", path=env.get("PATH", "")) is not None


# ---------------------------------------------------------------------------
# resolve
# ---------------------------------------------------------------------------


def resolve(argv: Sequence[str], cwd: str | None = None, *, targets: Targets,
            env: Mapping[str, str] | None = None) -> Route:
    """How git command `argv` (the words after `git`), run in `cwd` with
    `env` (default: this process's), is handled: see the module docstring."""
    keep, command, args, bad = split_globals(list(argv))
    if bad:
        command, args = "", list(argv)
    if _config_writes_users_own(command, args):
        return Route(command, tuple(args))
    if not targets:
        return Route(command, tuple(args), remote=_is_remote(command, args))
    e = _git_env(env)
    try:
        here = cwd or os.getcwd()
        git = paths.tool("git")
        entries, gitdir, worktree = _read_config(git, keep, here, e)
        cfg = _Config(entries)
        alias = ""
        alias_opts: list[str] = []
        shell = False
        for _depth in range(MAX_ALIAS_DEPTH):
            if not command or command in KNOWN:
                break
            val = cfg.alias(command)
            if val is None or _user_has_external(command, e):
                break
            alias = alias or command
            if val.startswith("!"):
                shell = True
                break
            try:
                words = shlex.split(val)
            except ValueError:
                command, args = "", []            # git refuses a bad alias
                break
            more, sub, subargs, wrong = split_globals(words)
            if wrong or any(o in _G_ENV_CHANGING for o in more) or \
                    any(o.startswith(("--git-dir=", "--work-tree=")) for o in more):
                command, args = "", []            # git refuses an alias that changes the repository
                break
            command, args = sub, subargs + args
            alias_opts += more
            if more:
                keep = keep + more
                entries, gitdir, worktree = _read_config(git, keep, here, e)
                cfg = _Config(entries)
        if _config_writes_users_own(command, args):
            return Route(command, tuple(args), alias=alias, alias_globals=tuple(alias_opts))
        if command == "clone":
            # git clone reads no repository: the folder's own config doesn't
            # apply (its global, system and command-line config does)
            cfg = _Config([x for x in cfg.entries if x[0] not in REPO_SCOPES] + _clone_config(args))
            gitdir = worktree = ""
        files = []
        if worktree:
            for name in (".gitmodules", ".lfsconfig"):
                files.append((name.lstrip("."), _read_file(git, os.path.join(worktree, name), here, e)))
        use = "push" if command == "push" else "fetch"
        operands = [(t, use) for t in _operand_tokens(command, args)]
        urls = _urls(cfg, operands, files, targets)
    except (_Unreadable, paths.ToolMissing, OSError) as ex:
        why = str(ex) or type(ex).__name__
        return Route(command, tuple(args), remote=_is_remote(command, args),
                     refusal=UNREADABLE, error=why)
    gated = any(u.hits for u in urls)
    refusal = SHELL_ALIAS if (shell and gated) else ""
    return Route(command, tuple(args), alias=alias, alias_globals=tuple(alias_opts),
                 shell_alias=shell, repo=gitdir, worktree=worktree, urls=tuple(urls), gated=gated,
                 remote=_is_remote(command, args), refusal=refusal)
