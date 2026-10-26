"""git: the gated git's settings, the credential helper, the include file and
commit identities (SPEC 9.4; PLAN-0.11 §6.3).

The pieces:

- `include_config(form, meta)`: the URL-scoped part of $DATA/git/config.
  A `[credential "SCHEME://HOST"]` section (helper reset + the gateway helper
  + useHttpPath) for every git account host; `[url]` insteadOf rewrites from
  the ssh forms to https for token-only hosts (every account on the host has
  a token and no ssh key); `[includeIf "hasconfig:remote.*.url:..."]` blocks
  that pull in a per-account identity file for each owner, for accounts that
  carry a commit name/email. No global `[credential] helper =` reset: each
  section clears the helpers only for its own URL, and the gated git reads
  no user or system config anyway (its own global, GIT_CONFIG_NOSYSTEM).
- `identity_files(form)`: {name: "[user] ..."} for those identity includes.
- The gated git (the git stand-in's gated path, clis.git_main): the env's
  git, run with `gated_env`: an environment built from an allowlist
  (GATED_KEEP; nothing else of the caller's: no GIT_CONFIG_*, askpass,
  GIT_SSH*, proxy, CA, trace or exec-path variable), the include at command
  scope (GIT_CONFIG_COUNT: the user's own user.name and user.email as the
  user's git reads them there (`user_identity`), include.path, then
  core.sshCommand = the ssh stand-in), which beats the repository's own
  config, GIT_CONFIG_GLOBAL = $DATA/git/global (`write_global`: GLOBAL_TEXT,
  mode 0444: init defaults a user's older git and IDE can read, git-lfs's
  filters, user.useConfigOnly so git never guesses an identity) and
  GIT_CONFIG_NOSYSTEM=1, so the rest of the user's ~/.gitconfig and
  /etc/gitconfig don't apply. GATED_MARK says, to the ssh stand-in and the helper the gated git
  starts, which mode the git stand-in used and which entries the approval
  hook asked about for the command; `gated_parent()` believes it only for
  the gated git's own process tree (git's programs, git-lfs's filter, git's
  hooks, which make it `hooked`), started by a command Claude typed. A git
  that git or git-lfs itself starts through the stand-in keeps the mark.
- The approval hook's record (asks.py; requirement 24): the hook writes one
  for each git stage it asks about, and the stand-in passes an "ask" on to
  the gated git only for the command, folder, Claude Code process and
  entries of one, at most asks.ASK_TTL old, each used once.
- `config_writes(args)`, `guarded_writes(args)`, `config_refused(args)`: the
  keys a `git config` command line writes, and what of them the gateway
  refuses in a repository it handles (GUARDED: credentials, the ssh
  command, URL rewrites, remote URLs, a remote's proxy and far-side
  programs, includes, hooks and fsmonitor; an alias that carries a guarded
  -c pair: alias_guarded); `config_file_held`: `--file` into a handled
  repository's own config counts as that repository's; `guarded_c(argv)`:
  the -c and --config-env pairs of a gated git command line (or of the
  alias it uses) that would add a credential helper or an include after
  the gateway's, or change its ssh.
- `credential_main(argv)`: git-credential-gateway get|store|erase. `get`
  answers only when its parent is the env's own git-remote-http(s) (or
  git-lfs's `git credential fill`: the env's git below the env's git-lfs),
  by executable path, below the gated git (gated_parent), the protocol is
  https (http only for a loopback host under a test override),
  GIT_TRACE_REDACT isn't 0/false, GIT_SSL_NO_VERIFY is absent (git turns
  checking off when it is set at all, even empty), no proxy or CA variable
  is set, the command line's config (git's GIT_CONFIG_PARAMETERS: -c and an
  alias's -c) adds no credential setting or include after the gateway's,
  git's http settings for the URL (`git config --get-urlmatch http URL`, so
  URL-scoped ones count) neither turn sslVerify off nor set a proxy, a CA
  file or folder or an SSL backend, and no remote has its own proxy; if git
  can't answer, the helper refuses. It picks the account by host and path
  (in the gated git's mode; a use or credential "ask" passes only for an
  account the approval hook asked about: gated_parent), refuses when the
  account's bound set lacks the host, and returns the token (username
  x-access-token for GitHub, else the login). `store` is ignored; `erase`
  marks the token stale.

includeIf hasconfig from an env-provided include.path was verified to work
with /opt/local/bin/git 2.55 and /usr/bin/git 2.54 (Apple Git-157): both
chose the per-owner identity for https and ssh remotes under the owner and
the global identity otherwise. No fallback is needed.
"""
from __future__ import annotations

import hmac
import os
import re
import struct
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from . import accounts as acctmod
from . import audit, consent
from . import form as formmod
from . import vault

LOOPBACK = ("127.0.0.1", "localhost", "::1", "[::1]")


def _bare(host: str) -> str:
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if host.count(":") == 1 else host


def _is_loopback(host: str) -> bool:
    return _bare(host).lower() in ("127.0.0.1", "localhost", "::1")


def _scheme(host: str) -> str:
    return "http" if _is_loopback(host) else "https"


# ---------------------------------------------------------------------------
# The include file (git re-reads it when it changes mid-session)
# ---------------------------------------------------------------------------


def _git_hosts(form: formmod.Form) -> dict[str, list[formmod.Account]]:
    """host (as git sees it) -> accounts whose credential goes there over git
    https. github: the host; huggingface: huggingface.co and hf.co."""
    out: dict[str, list[formmod.Account]] = {}
    for a in form.accounts.values():
        hosts: list[str] = []
        if a.kind == "github":
            hosts = [a.host or "github.com"]
        elif a.kind == "huggingface":
            hosts = ["huggingface.co", "hf.co"]
        for h in hosts:
            out.setdefault(h.lower(), []).append(a)
    return out


def _token_only(accts: list[formmod.Account], meta: dict[str, Any]) -> bool:
    """Every account for a host has a token and none has an ssh key: ssh
    remotes must be rewritten to https (SPEC 9.4)."""
    macc = (meta or {}).get("accounts") or {}
    saw = False
    for a in accts:
        m = macc.get(a.name) or {}
        if m.get("ssh_key"):
            return False
        if m.get("token"):
            saw = True
    return saw


def _ssh_rewrites(host: str) -> list[str]:
    """insteadOf source URLs rewritten to https://host/ for a token-only host."""
    bare = _bare(host)
    out = [f"git@{bare}:", f"ssh://git@{bare}/"]
    if bare == "github.com":
        out += ["git@ssh.github.com:", "ssh://git@ssh.github.com/"]
    return out


def _identity_hosts(a: formmod.Account) -> list[str]:
    if a.kind == "github":
        return [a.host or "github.com"]
    if a.kind == "huggingface":
        return ["huggingface.co", "hf.co"]
    return []


def _escape(val: str) -> str:
    """git config double-quoted value (keeps ", \\, ], ; literal)."""
    return val.replace("\\", "\\\\").replace('"', '\\"')


def identity_name(account: str) -> str:
    return "identity-" + account


def include_config(form, vault_meta: dict) -> str:
    """URL-scoped credential sections, insteadOf rewrites and identity
    includeIf blocks (SPEC 9.4); '' when the form has no git account."""
    if form is None or not getattr(form, "accounts", None):
        return ""
    from . import paths
    helper = str(paths.bin_dir() / "git-credential-gateway")
    gitdir = paths.git_dir()
    hosts = _git_hosts(form)
    out: list[str] = []
    for host in sorted(hosts):
        scheme = _scheme(host)
        out.append(f'[credential "{scheme}://{host}"]')
        out.append("\thelper =")
        out.append(f"\thelper = {helper}")
        out.append("\tuseHttpPath = true")
    for host in sorted(hosts):
        if _token_only(hosts[host], vault_meta):
            scheme = _scheme(host)
            srcs = _ssh_rewrites(host)
            out.append(f'[url "{scheme}://{host}/"]')
            for s in srcs:
                out.append(f"\tinsteadOf = {s}")
    # Identity includes, in a stable order.
    for name in sorted(form.accounts):
        a = form.accounts[name]
        if a.kind not in ("github", "huggingface"):
            continue
        if not (a.commit_name or a.email):
            continue
        owners = [o for o in a.owner_names() if o]
        if not owners:
            continue
        path = gitdir / identity_name(name)
        for host in _identity_hosts(a):
            scheme = _scheme(host)
            bare = _bare(host)
            for owner in owners:
                out.append(f'[includeIf "hasconfig:remote.*.url:{scheme}://{host}/{owner}/**"]')
                out.append(f"\tpath = {path}")
                out.append(f'[includeIf "hasconfig:remote.*.url:git@{bare}:{owner}/**"]')
                out.append(f"\tpath = {path}")
                out.append(f'[includeIf "hasconfig:remote.*.url:ssh://git@{bare}/{owner}/**"]')
                out.append(f"\tpath = {path}")
    return ("\n".join(out) + "\n") if out else ""


def identity_files(form) -> dict[str, str]:
    """{filename: content} of [user] identity include files under $DATA/git/."""
    if form is None:
        return {}
    out: dict[str, str] = {}
    for name, a in getattr(form, "accounts", {}).items():
        if a.kind not in ("github", "huggingface"):
            continue
        if not (a.commit_name or a.email) or not [o for o in a.owner_names() if o]:
            continue
        lines = ["[user]"]
        if a.commit_name:
            lines.append(f'\tname = "{_escape(a.commit_name)}"')
        if a.email:
            lines.append(f'\temail = "{_escape(a.email)}"')
        out[identity_name(name)] = "\n".join(lines) + "\n"
    return out


# ---------------------------------------------------------------------------
# The gated git (PLAN-0.11 §6.3)
# ---------------------------------------------------------------------------

# $DATA/git/global (GIT_CONFIG_GLOBAL of the gated git): init defaults so a
# repository the bundled git makes stays readable by the user's older git
# and IDE (git 3 may change them), and git-lfs's filters (the user's own
# `git lfs install` lines are in ~/.gitconfig, which the gated git doesn't
# read: without them an LFS file would be committed whole).
GLOBAL_TEXT = ("# gateway: the global git settings of Claude's gated git (read-only; rewritten at\n"
               "# every session start). Your own ~/.gitconfig isn't read there.\n"
               "[init]\n"
               "\tdefaultRefFormat = files\n"
               "\tdefaultObjectFormat = sha1\n"
               "[user]\n"
               "\tuseConfigOnly = true\n"
               "[filter \"lfs\"]\n"
               "\tclean = git-lfs clean -- %f\n"
               "\tsmudge = git-lfs smudge -- %f\n"
               "\tprocess = git-lfs filter-process\n"
               "\trequired = true\n")
GLOBAL_MODE = 0o444

# What the gated git keeps of its caller's environment (by name, or an LC_
# prefix); everything else is dropped, in particular GIT_CONFIG_COUNT/KEY/
# VALUE and GIT_CONFIG_PARAMETERS, GIT_ASKPASS, SSH_ASKPASS, GIT_SSH*,
# GIT_PROXY_COMMAND, GIT_EXEC_PATH, GIT_SSL_*, GIT_TRACE*, GIT_CURL_VERBOSE,
# the proxy variables, SSL_CERT_FILE and CURL_CA_BUNDLE, the user's agent
# and tokens. Kept: clis.ENV_ALLOW's (PATH is rebuilt), git's own needs
# (terminal, editor, pager), CLAUDE_PID (the stand-ins and the helper below
# it judge their caller by it), GATE_ACCOUNT (the account chosen on the
# command line), and the variables git itself sets for its hooks and
# subcommands (where the repository, its index and objects are; author and
# committer), so a hook's own git works on the same repository.
GATED_KEEP = frozenset({
    "HOME", "USER", "LOGNAME", "LANG", "TMPDIR", "TZ", "PWD", "TERM", "COLUMNS", "LINES",
    "NO_COLOR", "EDITOR", "VISUAL", "GIT_EDITOR", "GIT_SEQUENCE_EDITOR", "GIT_PAGER", "PAGER",
    "LESS", "CLAUDE_PID", "GATE_ACCOUNT",
    "GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_COMMON_DIR", "GIT_NAMESPACE",
    "GIT_CEILING_DIRECTORIES", "GIT_DISCOVERY_ACROSS_FILESYSTEM",
    "GIT_AUTHOR_NAME", "GIT_AUTHOR_EMAIL", "GIT_AUTHOR_DATE", "GIT_COMMITTER_NAME",
    "GIT_COMMITTER_EMAIL", "GIT_COMMITTER_DATE", "GIT_REFLOG_ACTION", "GIT_MERGE_AUTOEDIT",
    "GIT_LFS_SKIP_SMUDGE", "GIT_OPTIONAL_LOCKS", "GIT_TERMINAL_PROMPT", "GIT_FLUSH",
})
# The gateway's own settings of a gated git (gated_env sets them; a
# pass-through below a gated git takes them out again: strip_gated).
GATED_SET = ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_COUNT")
# "<pid of the gated git>:<mode or ->:<the entries the approval hook asked
# about, `hosts/NAME` and `accounts/NAME` joined by commas, or ->"
# (mark_text writes it, gated_parent reads it).
GATED_MARK = "GW_GATED_GIT"
_MARK_ENTRY = re.compile(r"(hosts|accounts)/[a-z][a-z0-9-]{0,31}")
# git runs a command through `sh -c` when it has a shell character
# (run-command.c's prepare_shell_cmd); a plain path is exec'd directly.
_SHELL_CHARS = set("|&;<>()$`\\\"' \t\n*?[#~=%")


def write_global() -> Path:
    """$DATA/git/global: GLOBAL_TEXT, mode 0444, written whole (temp file,
    then rename) at every session start."""
    from . import envfile, paths
    p = paths.git_global_path()
    envfile._atomic(p, GLOBAL_TEXT, GLOBAL_MODE)
    return p


def ssh_command(path: str) -> str:
    """core.sshCommand for the ssh stand-in at `path`: the plain path (git
    then execs it, no shell between), quoted only when it holds a shell
    character (git then runs it through `sh -c`)."""
    from . import envfile
    return envfile.sq(path) if any(c in _SHELL_CHARS for c in path) else path


def mark_text(pid: int, mode: str | None, asked: Iterable[tuple[str, str]] = ()) -> str:
    """GATED_MARK's value: the gated git's pid, its mode, and the entries
    (("hosts"|"accounts", NAME)) the approval hook asked about."""
    ents = ",".join(sorted({f"{s}/{n}" for s, n in asked}))
    return f"{pid}:{mode or '-'}:{ents or '-'}"


# The user's own commit identity in the gated git (PLAN-0.11 §19.14): the
# user.name and user.email the user's own git would use in that repository
# (user_identity), passed at command scope before the include, so an
# account's name or email there wins and the user's fills in what the
# account doesn't name. GLOBAL_TEXT's user.useConfigOnly makes git refuse to
# commit rather than guess (user@hostname) when neither names one.
IDENTITY_KEYS = ("user.name", "user.email")
# set in the identity read's environment: a stand-in reached again from it
# (the user's `git` is a wrapper that runs `git` from PATH) reads nothing
IDENTITY_GUARD = "GW_GIT_IDENTITY"
IDENTITY_TIMEOUT = 5.0
# git commands that never write a commit, a tag or a note, nor run a git
# command that does (git's own subcommands inherit the gated git's
# environment; a hook's `git` goes through the stand-in again): no identity
# read for them, so `git status`, `git diff` and the like don't also run
# the user's git. Every other command gets the read (git_main).
NO_IDENTITY = frozenset({
    "", "status", "diff", "log", "show", "fetch", "ls-remote", "ls-files", "ls-tree",
    "rev-parse", "rev-list", "describe", "blame", "annotate", "grep", "shortlog", "cat-file",
    "show-ref", "for-each-ref", "show-branch", "name-rev", "check-ignore", "check-attr",
    "diff-tree", "diff-files", "diff-index", "range-diff", "whatchanged", "count-objects",
    "version", "help", "remote", "branch", "checkout", "switch", "restore", "add", "rm", "mv",
    "reset", "clean", "clone", "init", "config", "reflog"})


def user_identity(environ: dict[str, str] | Any, cwd: str | None,
                  git_dir: str = "") -> list[tuple[str, str]]:
    """[(key, value)] of IDENTITY_KEYS as the user's own git reads them in
    the repository the command works on: `git_dir` (gitroute's Route.repo,
    which follows the command's -C, --git-dir and --work-tree) when there is
    one, else whatever `cwd` is in (every scope: the repository's own, the
    user's ~/.gitconfig with its includes and includeIf, the system's), with
    the user's environment (below a gated git, the gateway's settings taken
    out: strip_gated). The user's git is envfile.user_tool's (on macOS
    /usr/bin/git only with the developer tools, so the read never asks to
    install them), else the env's git. Values are returned for the child's
    environment only (gated_env's GIT_CONFIG_KEY_n/VALUE_n), never put on a
    command line. [] when git can't answer, or for a stand-in reached from
    this read itself."""
    from . import envfile, paths
    if environ.get(IDENTITY_GUARD):
        return []
    git = envfile.user_tool("git")
    if git is None:
        try:
            git = paths.tool("git")
        except paths.ToolMissing:
            return []
    env = dict(environ)
    strip_gated(env)
    env[IDENTITY_GUARD] = "1"
    env[envfile.PASSTHRU_VAR] = f"git:{envfile.PASSTHRU_MAX}:-"
    where = [f"--git-dir={git_dir}"] if git_dir else []
    try:
        r = subprocess.run([git, *where, "config", "--get-regexp", r"^user\.(name|email)$"],
                           cwd=cwd or None, env=env, stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=IDENTITY_TIMEOUT)
    except (OSError, subprocess.SubprocessError, ValueError):
        return []
    if r.returncode != 0:
        return []
    found: dict[str, str] = {}
    for line in r.stdout.decode("utf-8", "replace").splitlines():
        key, _, value = line.partition(" ")
        key = key.lower()
        if key in IDENTITY_KEYS and value.strip() and "\0" not in value:
            found[key] = value                 # the last one wins, as in git
    return [(k, found[k]) for k in IDENTITY_KEYS if k in found]


def gated_env(environ: dict[str, str] | Any, *, pid: int, mode: str | None,
              asked: Iterable[tuple[str, str]] = (),
              identity: Iterable[tuple[str, str]] = ()) -> dict[str, str]:
    """The gated git's environment (see GATED_KEEP): the allowlisted
    variables of `environ`, PATH = the stand-ins, the env's bin (git-lfs and
    git's helpers), then the caller's PATH (a hook's own tools; skipping
    those two), at command scope the user's `identity` (user_identity), the
    include and the ssh stand-in, the gateway's global config, no system
    config, and GATED_MARK for `pid` (mark_text: its mode and the entries
    the approval hook asked about)."""
    from . import paths
    env = {k: v for k, v in environ.items()
           if k in GATED_KEEP or (k.startswith("LC_") and k.isidentifier())}
    b, eb = str(paths.bin_dir()), str(paths.env_bin())
    rest = [d for d in str(environ.get("PATH", "")).split(os.pathsep) if d and d not in (b, eb)]
    env["PATH"] = os.pathsep.join(dict.fromkeys([b, eb, *rest]))
    env.setdefault("HOME", str(paths.user_home()))
    pairs = [(k, v) for k, v in identity if k in IDENTITY_KEYS]
    pairs.append(("include.path", str(paths.git_config_path())))
    ssh = paths.bin_dir() / "ssh"
    if ssh.is_file():
        pairs.append(("core.sshCommand", ssh_command(str(ssh))))
    env["GIT_CONFIG_COUNT"] = str(len(pairs))
    for i, (k, v) in enumerate(pairs):
        env[f"GIT_CONFIG_KEY_{i}"] = k
        env[f"GIT_CONFIG_VALUE_{i}"] = v
    env["GIT_CONFIG_GLOBAL"] = str(paths.git_global_path())
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env[GATED_MARK] = mark_text(pid, mode, asked)
    return env


def strip_gated(environ: dict[str, str]) -> bool:
    """Below a gated git (GATED_MARK set: a hook's own git, passed through
    to the user's git), take the gateway's settings out again, so the user's
    git reads the user's own config and writes `git config --global` there,
    never into $DATA/git. True when there was a mark."""
    if GATED_MARK not in environ:
        return False
    for k in list(environ):
        if k in GATED_SET or k == GATED_MARK or k.startswith(("GIT_CONFIG_KEY_",
                                                               "GIT_CONFIG_VALUE_")):
            environ.pop(k, None)
    return True


def _mark() -> tuple[int, str | None, frozenset[tuple[str, str]]] | None:
    v = os.environ.get(GATED_MARK, "")
    parts = v.split(":")
    if len(parts) != 3 or not parts[0].isdigit():
        return None
    from . import modes
    mode = None if parts[1] == "-" else parts[1]
    if mode is not None and mode not in modes.KEYS:
        return None
    asked: set[tuple[str, str]] = set()
    if parts[2] != "-":
        for item in parts[2].split(","):
            if not _MARK_ENTRY.fullmatch(item):
                return None
            sect, _, name = item.partition("/")
            asked.add((sect, name))
    return int(parts[0]), mode, frozenset(asked)


def _git_prefix() -> str | None:
    from . import paths
    try:
        return os.path.realpath(os.path.dirname(os.path.dirname(paths.tool("git"))))
    except Exception:  # noqa: BLE001 - no env git: nothing is the gated git
        return None


def _shell_ran(pid: int) -> bool:
    """`pid` is the shell git starts for one command of its own (`sh -c
    '<cmd> "$@"' <cmd> ARGS...` for a credential helper or an ssh command
    with a shell character) whose command is a gateway stand-in: a path in
    the stand-in folder, nothing else."""
    from . import ancestry, paths
    argv = ancestry._argv(pid)
    if not argv or len(argv) < 3 or argv[1] != "-c" or \
            os.path.basename(ancestry.exe_name(pid) or "") not in _HELPER_SHELLS:
        return False
    import shlex
    try:
        words = shlex.split(argv[2])
    except ValueError:
        return False
    return bool(words) and os.path.dirname(words[0]) == str(paths.bin_dir()) and \
        not any(w in ("|", "&&", "||", ";", "&") for w in words)


@dataclass(frozen=True)
class GatedParent:
    """gated_parent's answer. below: this process descends from the gated git
    the mark names (the env's git, by executable path); typed: that git was
    started by a command Claude typed (the git stand-in exec'd it in
    Claude's own command shell, so the approval hook saw the command);
    hooked: one of git's hooks (a script, which runs whatever it says) is on
    the way; top: that git's pid; mode and asked: its mode and the entries
    (("hosts"|"accounts", NAME)) the approval hook asked about, for a typed
    one only (else None and none)."""
    below: bool = False
    typed: bool = False
    hooked: bool = False
    top: int = 0
    mode: str | None = None
    asked: frozenset[tuple[str, str]] = frozenset()

    def strict(self) -> bool:
        """Typed, with no hook script on the way: what the ssh stand-in and a
        git command that reaches a remote go by (a hook script's own ssh or
        push never takes the approval of the push that ran the hook)."""
        return self.typed and not self.hooked


# git's hooks (githooks(5)): git runs one as `<its shebang's shell> <path>
# ARGS`, a child of git itself
GIT_HOOKS = frozenset({
    "applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
    "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout",
    "post-merge", "pre-push", "pre-receive", "update", "proc-receive", "post-receive",
    "post-update", "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite",
    "sendemail-validate", "fsmonitor-watchman", "p4-changelist", "p4-prepare-changelist",
    "p4-post-changelist", "p4-pre-submit", "post-index-change"})
# git-lfs's long-running filter (GLOBAL_TEXT's filter.lfs.process), as git
# starts it through its shell (a command with a space: `sh -c '<cmd>'`, with
# ' "$@"' when it has arguments)
_LFS_FILTER = "git-lfs filter-process"


def _git_program(exe: str, prefix: str) -> bool:
    """One of the env's own git programs (git, git-remote-*, git-lfs), by
    executable path."""
    return exe.startswith(prefix + os.sep) and os.path.basename(exe).startswith("git")


def _lfs_filter_shell(pid: int, exe: str) -> bool:
    """`pid` is git's shell for git-lfs's filter, exactly as GLOBAL_TEXT
    names it, nothing else."""
    from . import ancestry
    if os.path.basename(exe) not in _HELPER_SHELLS:
        return False
    argv = ancestry._argv(pid) or []
    return len(argv) >= 3 and argv[1] == "-c" and argv[2] in (_LFS_FILTER, _LFS_FILTER + ' "$@"')


def _hook_shell(pid: int, exe: str, parent_exe: str, prefix: str) -> bool:
    """`pid` is a shell running one of git's hooks (`sh [-OPTS] <dir>/pre-push
    origin URL`), and its parent is one of the env's git programs."""
    from . import ancestry
    if os.path.basename(exe) not in _HELPER_SHELLS or not _git_program(parent_exe, prefix):
        return False
    argv = ancestry._argv(pid) or []
    for a in argv[1:]:
        if a == "-c" or (a.startswith("-") and "c" in a[1:] and not a.startswith("--")):
            return False                  # a command string, not a hook file
        if not a.startswith("-"):
            return os.path.basename(a) in GIT_HOOKS
    return False


def gated_parent() -> GatedParent:
    """Where this process stands to the gated git (GatedParent): GATED_MARK
    names a process this one descends from through the env's own git
    programs (git, git-remote-*, git-lfs, by executable path), git's shell
    for git-lfs's filter and git's hooks (hooked; at most one shell of git's
    own running a stand-in just above this process), and that process is
    the env's git (below); the command shell that started it is Claude's own
    (typed: ancestry.typed_from, so the hook saw that command), and only then
    do its mode and asked entries count. Anything else, or anything
    unreadable: GatedParent() (not below). A guardrail, like the typed walk
    itself: code running as the user could build such a tree."""
    from . import ancestry, paths
    m = _mark()
    prefix = _git_prefix()
    if m is None or prefix is None:
        return GatedParent()
    top, mode, asked = m
    try:
        git = os.path.realpath(paths.tool("git"))
        pid = ancestry.parent_pid(os.getpid())
        if pid and _shell_ran(pid):
            pid = ancestry.parent_pid(pid)
        hooked = False
        for _ in range(ancestry.MAX_DEPTH):
            if pid <= 1:
                break
            exe = os.path.realpath(ancestry.exe_path(pid) or "")
            if pid == top:
                if exe != git:
                    break
                ok, _culprit = ancestry.typed_from(ancestry.parent_pid(pid))
                if not ok:
                    return GatedParent(below=True, hooked=hooked, top=top)
                return GatedParent(True, True, hooked, top, mode, asked)
            parent = ancestry.parent_pid(pid)
            if _git_program(exe, prefix) or _lfs_filter_shell(pid, exe):
                pass
            elif _hook_shell(pid, exe, os.path.realpath(ancestry.exe_path(parent) or ""), prefix):
                hooked = True
            else:
                break
            pid = parent
    except Exception:  # noqa: BLE001 - fail closed
        pass
    return GatedParent()


# ---------------------------------------------------------------------------
# A remote git command's rights (PLAN-0.11 §6.5): the approval hook judges
# them before the command runs and the git stand-in again, in the same way
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GitDecision:
    """One configured entry a remote git command reaches and what decides it:
    `refusal` (the entry can't be used at all: off, gateway.toml gone, its
    approval unreadable, waiting for the OK) or a policy.Decision (the
    right and every restriction, in the mode asked for)."""
    sect: str                     # "hosts" | "accounts"
    name: str
    action: str                   # read | write | credential
    decision: Any = None
    refusal: str = ""

    @property
    def value(self) -> str:
        return "deny" if self.refusal else self.decision.value

    @property
    def word(self) -> Any:
        return False if self.refusal else self.decision.word

    def verb(self) -> str:
        """The right this asks about, for the prompt (consent.ask_phrase):
        the entry's own right when that is what decides, else the action."""
        rule = "" if self.decision is None else self.decision.rule
        if rule.startswith(f"[hosts.{self.name}] ssh"):
            return "ssh"
        if rule.startswith(f"[accounts.{self.name}] use"):
            return "use"
        return self.action

    def message(self, what: str) -> str:
        if self.refusal:
            return f"gateway: {self.name} is refused: {self.refusal}"
        return self.decision.message(what)


def git_push(route: Any) -> bool:
    """Does the remote command write (push, lfs push)?"""
    if route.command == "push":
        return True
    first = next((a for a in route.args if not a.startswith("-")), "")
    return route.command == "lfs" and first == "push"


def _remote_path(where: Any) -> str:
    """The path git asks a host's git-upload-pack / git-receive-pack for, as
    the ssh stand-in sees it (`host:x` -> x, ssh://host/~/x -> ~/x,
    ssh://host/srv/x -> /srv/x)."""
    p = where.path or ""
    if where.scheme != "scp" and p.startswith("/~"):
        p = p[1:]
    return p


def _gate_reach(eff: Any, name: str | None) -> Any:
    """The configured reach (gitroute.AccountReach) of the git account
    GATE_ACCOUNT names, or None."""
    if not name:
        return None
    try:
        for a in eff.configured.git_targets().accounts:
            if a.name == name and a.kind in GIT_KINDS:
                return a
    except Exception:  # noqa: BLE001 - nothing to add: the helper decides on its own
        return None
    return None


def git_decisions(route: Any, eff: Any, mode: str | None,
                  gate_account: str | None = None) -> list[GitDecision]:
    """For a remote git command (gitroute.Route.remote), each configured
    entry each configured URL it may use reaches, decided in `mode` (None:
    the modeless rule): a host by its ssh right and its read (fetch) or
    write (push) restrictions for the repository's path, workspaces
    included (ssh_args.decide_path, as the ssh stand-in decides git over
    ssh); an account by its use and its credential restrictions, and write
    for a push (policy.decide, as the credential helper and git over ssh
    decide). The account GATE_ACCOUNT names (`gate_account`) counts too for
    a URL whose host it serves, whatever the owner: the helper and git over
    ssh pick it there. An entry eff refuses outright gets its refusal. Every
    URL of the repository counts, not only the remote the command names (the
    resolver doesn't follow which one git picks)."""
    from . import gitroute, policy, ssh_args
    push = git_push(route)
    use = "push" if push else "fetch"
    out: list[GitDecision] = []
    seen: set[tuple[str, str, str, str]] = set()
    chosen = _gate_reach(eff, gate_account)
    for u in route.configured:
        if use not in u.use:
            continue
        hits = list(u.hits)
        if chosen is not None and ("accounts", chosen.name) not in hits and u.where.host and \
                gitroute.Targets._covers_host(chosen, u.where, u.where.host):
            hits.append(("accounts", chosen.name))
        for sect, name in hits:
            why = eff.refusal(name)
            if why is None and name not in (eff.hosts if sect == "hosts" else eff.accounts):
                why = eff.refused.get(name) or f"[{sect}.{name}] isn't approved (gate check {name})"
            if sect == "hosts":
                acts = [("write" if push else "read", _remote_path(u.where))]
            else:
                acts = [("credential", "")] + ([("write", "")] if push else [])
            for act, path in acts:
                k = (sect, name, act, path)
                if k in seen:
                    continue
                seen.add(k)
                if why is not None:
                    out.append(GitDecision(sect, name, act, refusal=why))
                elif sect == "hosts":
                    out.append(GitDecision(sect, name, act,
                                           ssh_args.decide_path(eff, act, name, path, mode)))
                else:
                    out.append(GitDecision(sect, name, act,
                                           policy.decide(eff, act, account=name, mode=mode)))
    return out


# ---------------------------------------------------------------------------
# The git stand-in (PLAN-0.11 §6.1-§6.5): by repository. A command that
# reaches nothing configured runs the user's own git, untouched; anything
# else the env's git with the gateway's settings (gated_env). Here, not in
# clis.py: every git call where the stand-in exists pays this module's
# imports (§6.6's budget), and clis brings entra's HTTP stack.
# ---------------------------------------------------------------------------

GIT_KINDS = ("github", "huggingface")      # the account kinds git reaches
GIT_C_REFUSED = ("gateway: git -c {key}=... isn't run in a repository the gateway handles: it would "
                 "come after the gateway's own settings (a credential helper there would be handed "
                 "the token, an include could change anything, an ssh command would go around the "
                 "gateway's ssh); run the command without it.")
GIT_CONFIG_REFUSED = ("gateway: `git config` doesn't change {key} in a repository the gateway "
                      "handles (it would take the repository's credentials, ssh, remotes or hooks "
                      "around the gateway); ask the user to make that change in their own "
                      "terminal.")
GIT_ASK_ALIAS = ("gateway: {what} {are} set to \"ask\", and `git {alias}` is an alias, which Claude "
                 "Code can't ask you about by its name; run the git command it stands for "
                 "(git {command} ...) as its own command.")
GIT_ASK_SCRIPT = ("gateway: {what} {are} set to \"ask\", and Claude Code can only ask about a "
                  "command Claude runs itself; run `git {command} ...` as its own command (not "
                  "inside a script, sh -c or a wrapper).")
GIT_ASK_UNASKED = ("gateway: {what} {are} set to \"ask\", and Claude Code didn't ask you about "
                   "this git command as it ran (it was inside a subshell, a group, exec, a "
                   "background job, $(...) or a shell string, came after a `git remote add`, "
                   "`git clone`, `cd -`, `popd` or a `cd` to a folder in a variable in the same "
                   "command, or GATE_ACCOUNT or GIT_DIR changed "
                   "what it reaches); run `git {command} ...` as its own command (`cd DIR && "
                   "git {command} ...` is fine).")
GIT_ASK_EXPIRED = ("gateway: {what} {are} set to \"ask\", and you approved this git command more "
                   "than 15 minutes before it ran, so that approval no longer counts; run "
                   "`git {command} ...` again.")
GIT_MISSING = ("gateway: the gateway's git is missing (its environment is being set up or was "
               "removed); try again in a minute")
# the one exec (tests replace it to run the stand-in in-process)
_execve = os.execve


def _git_classify(argv: list[str], cwd: str | None) -> tuple[Any, Any]:
    """(the route, the configured set) for a git command, without reading
    the vault (§6.6: a form and configured-list read and one git config
    call): the form and private/configured.json (the approved snapshot's
    reach, readable while the vault is locked)."""
    from . import gitroute
    configured = consent.compute(formmod.load(), None).configured
    return gitroute.resolve(argv, cwd, targets=configured.git_targets()), configured


def _git_entries(configured: Any) -> list[str]:
    """The configured entries git goes through the gateway for (the
    not-installed message)."""
    out = list(configured.hosts)
    out += [r.name for r in configured.reaches() if r.kind in GIT_KINDS]
    return list(dict.fromkeys(out))


def _git_load(mode: str | None = None) -> tuple[Any, str | None, str | None]:
    """The effective rights in the session's mode (modes.current_for: a
    command Claude typed; else `mode`, the approved gated git's above this
    one, or the modeless rule), after consent's ratchet; why the vault can't
    be read now (locked or broken; None when it can): a configured target's
    remote command is refused then; and the account GATE_ACCOUNT names
    (the vault's aliases followed), or None."""
    from . import modes
    unreadable = None
    locked = False
    try:
        data: dict[str, Any] | None = vault.load()
    except vault.VaultLocked as e:
        data, unreadable, locked = None, str(e), True
    except vault.VaultError as e:
        data, unreadable = None, f"gateway: the vault can't be read ({e}); run gate status"
    form = consent.load_form(data)
    if data is not None and consent.needs_sync(data, form):
        try:
            consent.ratchet(form)
            data = vault.load()
        except Exception:  # noqa: BLE001
            pass
    try:
        mode = modes.current_for("standin") or mode
    except Exception:  # noqa: BLE001 - the modeless rule
        pass
    chosen = (os.environ.get("GATE_ACCOUNT") or "").strip()
    if chosen:
        chosen = acctmod.resolve_name(chosen, (data or {}).get("aliases") or {}, form)
    return consent.compute(form, data, mode, locked=locked), unreadable, chosen or None


def _audit_mode() -> str:
    """A refusal's mode for the audit (lead decision 19.8) where the stand-in
    hasn't read it: the session's for a command Claude typed, else the
    modeless rule."""
    from . import modes
    try:
        return modes.current_for("standin") or "modeless"
    except Exception:  # noqa: BLE001
        return "modeless"


def _git_refuse(target: str | None, msg: str, mode: str | None = None) -> int:
    audit.refusal("git", target, msg, mode=mode or _audit_mode())
    print(msg, file=sys.stderr)
    return 2


def _cwd() -> str | None:
    try:
        cwd = os.getcwd()
    except OSError:
        return None
    return cwd if os.path.isdir(cwd) else None


def _git_unasked(route: Any, argv: list[str], cwd: str | None,
                 need: frozenset[tuple[str, str]], phrases: list[str],
                 outer: GatedParent) -> str | None:
    """Why a remote command with "ask" entries (`need`, named by `phrases`)
    can't go on, or None: a command Claude typed, spelled out (no alias),
    that the approval hook asked about (asks.take uses up its record), or a
    git the approved gated git started with no hook script between
    (outer.strict()) whose approval covers every entry. Anything else is
    refused: a job's, a gateway terminal's, a script's."""
    from . import ancestry, asks
    shown = phrases[0] if len(phrases) == 1 else ", ".join(phrases[:-1]) + " and " + phrases[-1]
    are = "is" if len(phrases) == 1 else "are"
    try:
        typed, culprit = ancestry.typed_by_claude()
    except Exception:  # noqa: BLE001 - fail closed
        typed, culprit = False, "?"
    if typed:
        if route.alias:
            return GIT_ASK_ALIAS.format(what=shown, are=are,
                                        alias=formmod.safe(route.alias) or "that alias",
                                        command=route.command)
        got = asks.take("git", asks.session(), cwd or "", argv, need) if cwd else "none"
        if got == "ok":
            return None
        return (GIT_ASK_EXPIRED if got == "expired" else GIT_ASK_UNASKED).format(
            what=shown, are=are, command=route.command)
    if outer.strict() and need <= outer.asked:
        return None
    if culprit == ancestry.CHECKPOINT:
        return consent.job_ask_message(phrases)
    if culprit == ancestry.TERMINAL:
        return consent.pane_ask_message(phrases)
    return GIT_ASK_SCRIPT.format(what=shown, are=are, command=route.command)


def git_main(argv: list[str]) -> int:
    """The git stand-in. gitroute decides by repository: a command whose
    repository has no configured URL (and no configured operand) runs the
    user's own git with the full argv and the environment unchanged
    (envfile.pass_through; one audit line only for a command that touches a
    remote; below a gated git the gateway's own settings are taken out
    first: strip_gated). Otherwise the gated path: the resolver's fixed
    refusal (a `!` alias, unreadable settings); a -c pair that would come
    after the gateway's settings (guarded_c); a `git config` write of a
    guarded key in the repository (guarded_writes); and for a command that
    touches a remote, each configured entry's right and restrictions in the
    session's mode (git_decisions, as the approval hook judged them, the
    account GATE_ACCOUNT names included): deny refuses; "ask" goes on only
    for a command Claude typed and spelled out (no alias) that the approval
    hook asked about (asks.take: its record for this command, folder and
    entries), or for a git the approved gated git itself started (git-lfs's
    own `git credential fill`, no hook script on the way: gated_parent's
    strict) whose "ask" entries the approval covers. Then the env's git runs
    in place of this process (exec: the same pid, so the ssh stand-in and
    the helper below it see a git that Claude's shell started) with
    gated_env: below an approved gated git (typed) it keeps that git's mark,
    unless it reaches a remote through a hook script."""
    from . import envfile, paths
    cwd = _cwd()
    try:
        route, configured = _git_classify(list(argv), cwd)
    except Exception as e:  # noqa: BLE001 - can't classify: nothing runs
        return _git_refuse(None, f"gateway: the gateway couldn't tell where this git command goes "
                                 f"({type(e).__name__}); nothing ran; try again, or run gate status")
    if not route.gated and not route.refusal:
        held = config_file_held(list(argv), cwd, configured.git_targets(), route.args) \
            if route.command == "config" else None
        if held is not None:
            return _git_refuse(held[0], GIT_CONFIG_REFUSED.format(key=held[1]))
        strip_gated(os.environ)
        hosts = [u.where.host for u in route.urls if u.where.host]
        return envfile.pass_through("git", list(argv), hosts[0] if hosts else None,
                                    entries=_git_entries(configured), log=route.remote)
    ents = route.entries()
    target = ents[0][1] if ents else None
    if route.refusal:
        return _git_refuse(target, route.refusal)
    bad = guarded_c(argv) or guarded_c(route.alias_globals)
    if bad:
        return _git_refuse(target, GIT_C_REFUSED.format(key=formmod.safe(bad[0]) or "that key"))
    if route.command == "config":
        shown = config_refused(route.args)
        if shown:
            return _git_refuse(target, GIT_CONFIG_REFUSED.format(key=shown))
    outer = gated_parent() if GATED_MARK in os.environ else GatedParent()
    mode: str | None = None
    asked: frozenset[tuple[str, str]] = frozenset()
    if route.remote:
        # the vault and the session's mode only for a command that touches a
        # remote: `git status` or a commit there hands no credential to anyone
        eff, unreadable, chosen = _git_load(outer.mode if outer.strict() else None)
        mode = eff.mode
        if unreadable:
            return _git_refuse(target, unreadable, mode or "modeless")
        need: dict[tuple[str, str], None] = {}
        phrases: list[str] = []
        what = f"git {route.command}"
        for gd in git_decisions(route, eff, mode, chosen):
            if gd.value == "deny" or gd.word is False:
                return _git_refuse(gd.name, gd.message(what), mode or "modeless")
            if gd.word == "ask":
                need[(gd.sect, gd.name)] = None
                phrases.append(consent.ask_phrase(gd.name, gd.verb()))
        if need:
            why = _git_unasked(route, list(argv), cwd, frozenset(need),
                               list(dict.fromkeys(phrases)), outer)
            if why:
                return _git_refuse(target, why, mode or "modeless")
            asked = frozenset(need)
    try:
        git = paths.tool("git")
    except paths.ToolMissing:
        return _git_refuse(target, GIT_MISSING)
    try:
        if not paths.git_global_path().is_file():
            write_global()                 # a stand-in added since the session started
    except Exception:  # noqa: BLE001 - git reads a missing global file as empty
        pass
    # the identity as the user's git reads it in the command's own repository
    # (`git -C other commit` from another repository uses other's), and only
    # for a command that may write a commit, a tag or a note
    identity = [] if route.command in NO_IDENTITY else \
        user_identity(os.environ, route.worktree or cwd, route.repo)
    if outer.typed and (outer.strict() or not route.remote):
        # a git the approved gated git started (git-lfs's own, a hook's
        # `git lfs pre-push`): the helper and the ssh stand-in below it go by
        # that git's approval, through this one
        env = gated_env(os.environ, pid=outer.top, mode=outer.mode, asked=outer.asked,
                        identity=identity)
    else:
        env = gated_env(os.environ, pid=os.getpid(), mode=mode, asked=asked, identity=identity)
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        _execve(git, [git, *argv], env)
    except OSError as e:
        print(f"gateway: couldn't run git ({type(e).__name__})", file=sys.stderr)
        return 126
    return 0  # pragma: no cover - execve doesn't return


# ---------------------------------------------------------------------------
# git config writes and -c pairs the gateway refuses in a repository it handles
# ---------------------------------------------------------------------------

# Keys (section and name lowercased, subsection as written; `*` one
# subsection) a `git config` write is refused for in a repository the
# gateway handles (PLAN-0.11 §1.7, §6.5): the credentials, the ssh git
# runs, URL rewrites, remote URLs, a remote's proxy and the programs it has
# the far side run, includes, hooks and fsmonitor (both run programs).
GUARDED = ("credential.*", "core.sshcommand", "url.*", "remote.*.url", "remote.*.pushurl",
           "remote.*.proxy", "remote.*.uploadpack", "remote.*.receivepack",
           "include.*", "includeif.*", "core.hookspath", "core.fsmonitor")
# The -c / --config-env pairs a gated git command line may not carry: they
# come after the gateway's include (git reads GIT_CONFIG_PARAMETERS after
# GIT_CONFIG_COUNT), so a credential helper there would be handed the token
# to store, an include would read anything after the gateway's settings,
# and an ssh command would go around the ssh stand-in.
GUARDED_C = ("credential.*", "include.*", "includeif.*", "core.sshcommand", "ssh.variant")

_CONFIG_SUBS = ("list", "get", "set", "unset", "rename-section", "remove-section", "edit")
_CONFIG_READS = ("--get", "--get-all", "--get-regexp", "--get-urlmatch", "--get-color",
                 "--get-colorbool", "-l", "--list")
_CONFIG_WRITES = ("--add", "--replace-all", "--unset", "--unset-all", "--rename-section",
                  "--remove-section", "-e", "--edit")
_CONFIG_VALUED = ("--type", "--default", "--comment", "--value", "--url", "--blob", "-f", "--file",
                  "-t")
EDIT = "(the whole file, by an editor)"


def _key_norm(k: str) -> str:
    k = k.strip()
    first, last = k.find("."), k.rfind(".")
    if first < 0 or first == last:
        return k.lower()
    return k[:first].lower() + k[first:last] + k[last:].lower()


def _matches(key: str, patterns: tuple[str, ...]) -> bool:
    k = _key_norm(key)
    sec, _, rest = k.partition(".")
    for p in patterns:
        psec, _, prest = p.partition(".")
        if psec != sec:
            continue
        if prest == "*":
            return True
        if "*." in prest:                         # remote.*.url: any subsection, that name
            name = prest.split(".", 1)[1]
            sub, dot, kname = rest.rpartition(".")
            if dot and sub and kname == name:
                return True
        elif rest == prest:
            return True
    return False


def _section_matches(section: str, patterns: tuple[str, ...]) -> bool:
    """A whole section (rename-section / remove-section) holds a guarded key:
    `credential`, `url.X`, `remote.X` (its url), `include`, `includeIf.X`,
    `core` (sshCommand, hooksPath, fsmonitor)."""
    s = _key_norm(section + ".x")[:-2]
    sec = s.partition(".")[0].lower()
    return any(p.partition(".")[0] == sec for p in patterns)


_CONFIG_W_LONG = ("add", "replace-all", "unset", "unset-all", "rename-section", "remove-section",
                  "edit")
_CONFIG_VALUED_LONG = ("type", "default", "comment", "value", "url", "blob", "file")


def _config_parse(args: list[str] | tuple[str, ...]) -> tuple[str, str, list[str]]:
    """(subcommand, the old-style action option, the positional words) of a
    `git config` command line's arguments after `config`, read as git
    config reads them: options up to `--` or the first other word (the key;
    what follows it is a value or a value pattern, never an option), a long
    option by any prefix (git takes an unambiguous one; one that may name a
    write counts as that write), a value option taking the next word."""
    words = list(args)
    sub = words[0] if words and words[0] in _CONFIG_SUBS else ""
    if sub:
        words = words[1:]
    action = ""
    pos: list[str] = []
    i = 0
    while i < len(words):
        a = words[i]
        i += 1
        if pos or a == "-" or not a.startswith("-"):
            pos.append(a)
            continue
        if a == "--":
            pos += words[i:]
            break
        if a in _CONFIG_READS:
            action = action or "read"
            continue
        if a in _CONFIG_WRITES:
            action = a
            continue
        if a.startswith("--"):
            name, eq, _val = a[2:].partition("=")
            writes = [o for o in _CONFIG_W_LONG if o.startswith(name)] if len(name) >= 2 else []
            if writes and not eq:
                action = "--" + (name if name in writes else writes[0])
            elif not eq and name and any(o.startswith(name) for o in _CONFIG_VALUED_LONG):
                i += 1                            # its value is the next word
            continue
        if a in _CONFIG_VALUED:
            i += 1
    return sub, action, pos


def config_writes(args: list[str] | tuple[str, ...]) -> list[str]:
    """The keys (or sections, or EDIT) a `git config` command line writes,
    from its arguments after `config`: the new subcommands (set, unset,
    rename-section, remove-section, edit) and the old options (a key and a
    value, --add, --replace-all, --unset[-all], --rename-section,
    --remove-section, -e/--edit). [] for a read (get, list, a key alone, a
    --get* option). Scope options don't matter here (the caller decides
    whether the user's own config is meant)."""
    sub, action, pos = _config_parse(args)
    if sub in ("list", "get"):
        return []
    if sub == "edit" or action in ("-e", "--edit"):
        return [EDIT]
    if sub in ("rename-section", "remove-section") or \
            action in ("--rename-section", "--remove-section"):
        return [f"[{p}]" for p in pos[:2 if "rename" in (sub or action) else 1]]
    if sub in ("set", "unset") or action in ("--add", "--replace-all", "--unset", "--unset-all"):
        return pos[:1]
    if action == "read":
        return []
    return pos[:1] if len(pos) >= 2 else []


def guarded_writes(args: list[str] | tuple[str, ...]) -> list[str]:
    """The keys of config_writes(args) the gateway refuses in a repository it
    handles (GUARDED); a section write counts when the section can hold
    one, an editor session always."""
    out = []
    for k in config_writes(args):
        if k == EDIT or (k.startswith("[") and _section_matches(k[1:-1], GUARDED)) or \
                (not k.startswith("[") and _matches(k, GUARDED)):
            out.append(k)
    return out


def _config_sets(args: list[str] | tuple[str, ...]) -> list[tuple[str, str]]:
    """(key, value) pairs a `git config` command line sets (`set KEY VALUE`,
    `KEY VALUE`, --add, --replace-all)."""
    sub, action, pos = _config_parse(args)
    if len(pos) < 2 or sub not in ("", "set") or action not in ("", "--add", "--replace-all"):
        return []
    return [(pos[0], pos[1])]


def alias_guarded(value: str) -> list[str]:
    """The GUARDED_C keys an alias's own git options carry (`-c KEY=VALUE` or
    --config-env before its subcommand: git applies them after the gateway's
    settings, as for the command line's own); an alias value git's shell
    quoting can't read counts as one. A `!` alias runs a shell (refused
    where the gateway handles the repository anyway)."""
    import shlex
    from . import gitroute
    if value.lstrip().startswith("!"):
        return []
    try:
        words = shlex.split(value)
    except ValueError:
        return ["(unreadable)"]
    keep, _cmd, _args, _bad = gitroute.split_globals(words)
    return guarded_c(keep)


def guarded_alias_writes(args: list[str] | tuple[str, ...]) -> list[str]:
    """The alias keys a `git config` command line sets to an alias that
    carries a guarded -c pair (alias_guarded)."""
    return [k for k, v in _config_sets(args) if _matches(k, ("alias.*",)) and alias_guarded(v)]


def config_refused(args: list[str] | tuple[str, ...]) -> str | None:
    """What a `git config` command line (its arguments after `config`) may
    not change in a repository the gateway handles, as shown in the refusal
    (a guarded key, a section that holds one, the whole file by an editor,
    an alias that carries a guarded -c pair), or None."""
    keys = guarded_writes(args)
    if keys:
        return keys[0] if keys[0] == EDIT else (formmod.safe(keys[0].strip("[]")) or "that key")
    ali = guarded_alias_writes(args)
    if ali:
        return formmod.safe(ali[0]) or "that alias"
    return None


_CONFIG_PAIRED = ("-C", "-c", "--git-dir", "--work-tree", "--config-env")


def _config_file_gitdir(keep: list[str], args: list[str], cwd: str | None) -> str | None:
    """The git dir whose own config (`config` or `config.worktree`) a `git
    config --file FILE` command line names, or None. Options are read as
    git config reads them: up to `--` or the first other word, a long
    option by any prefix of two letters or more, -fFILE clustered."""
    words = list(args)
    if words and words[0] in _CONFIG_SUBS:
        words = words[1:]
    path = None
    i = 0
    while i < len(words):
        a = words[i]
        i += 1
        if a == "--" or a == "-" or not a.startswith("-"):
            break
        if a.startswith("--"):
            name, eq, val = a[2:].partition("=")
            if len(name) >= 2 and "file".startswith(name):
                if eq:
                    path = val
                elif i < len(words):
                    path, i = words[i], i + 1
            elif not eq and name and any(o.startswith(name) for o in
                                         ("type", "default", "comment", "value", "url", "blob")):
                i += 1
            continue
        for j, ch in enumerate(a[1:], 1):
            if ch in "ft":
                v = a[j + 1:]
                if not v and i < len(words):
                    v, i = words[i], i + 1
                if ch == "f":
                    path = v
                break
    if not path:
        return None
    base = cwd or os.getcwd()
    k = 0
    while k < len(keep):
        if keep[k] in _CONFIG_PAIRED:
            if keep[k] == "-C" and k + 1 < len(keep):
                base = os.path.join(base, keep[k + 1])
            k += 2
            continue
        k += 1
    p = os.path.realpath(os.path.join(base, path))
    d = os.path.dirname(p)
    if os.path.basename(p) not in ("config", "config.worktree"):
        return None
    if os.path.isfile(os.path.join(d, "HEAD")) and (os.path.isdir(os.path.join(d, "objects")) or
                                                     os.path.isfile(os.path.join(d, "commondir"))):
        return d
    return None


def config_file_held(argv: list[str], cwd: str | None, targets: Any,
                     args: list[str] | tuple[str, ...] | None = None
                     ) -> tuple[str | None, str] | None:
    """(the entry, what is shown) when `git ARGV` is `git config --file FILE`
    (`args`: config's arguments, when an alias stood for it: the route's)
    writing what config_refused names, FILE is a repository's own config
    (<git dir>/config or config.worktree, through any spelling) and the
    gateway handles that repository: that is the repository's config, not
    the user's own (gitroute passes --file through); else None. Fails
    closed when the repository can't be read."""
    from . import gitroute
    keep, command, own, bad = gitroute.split_globals(list(argv))
    if args is None:
        if bad or command != "config":
            return None
        args = own
    args = list(args)
    if not targets:
        return None
    shown = config_refused(args)
    if not shown:
        return None
    try:
        gitdir = _config_file_gitdir(keep, args, cwd)
        if gitdir is None:
            return None
        r = gitroute.resolve(["--git-dir", gitdir, "rev-parse"], cwd, targets=targets)
    except Exception:  # noqa: BLE001 - can't tell: refused
        return None, shown
    if not (r.gated or r.refusal):
        return None
    ents = r.entries()
    return (ents[0][1] if ents else None), shown


def guarded_c(argv: list[str] | tuple[str, ...]) -> list[str]:
    """The keys of the -c KEY=VALUE and --config-env=KEY=ENV pairs among git's
    global options (before the subcommand) that GUARDED_C names."""
    out = []
    i = 0
    while i < len(argv):
        a = argv[i]
        val = None
        if a == "-c" and i + 1 < len(argv):
            val, i = argv[i + 1], i + 2
        elif a.startswith("-c") and len(a) > 2:
            val, i = a[2:], i + 1
        elif a == "--config-env" and i + 1 < len(argv):
            val, i = argv[i + 1], i + 2
        elif a.startswith("--config-env="):
            val, i = a[len("--config-env="):], i + 1
        elif a in ("-C", "--git-dir", "--work-tree", "--namespace", "--attr-source") and \
                i + 1 < len(argv):
            i += 2
            continue
        elif a.startswith("-"):
            i += 1
            continue
        else:
            break
        key = val.partition("=")[0]
        if _matches(key, GUARDED_C):
            out.append(key)
    return out


def _parameters_guarded(raw: str) -> list[str]:
    """The keys among git's GIT_CONFIG_PARAMETERS (the command line's -c and
    an alias's -c, `'key'='value'` shell words) that GUARDED_C names; an
    unreadable value counts as one."""
    import shlex
    try:
        words = shlex.split(raw)
    except ValueError:
        return ["(unreadable)"]
    return [w.partition("=")[0] for w in words if _matches(w.partition("=")[0], GUARDED_C)]


# ---------------------------------------------------------------------------
# The credential helper (git-credential-gateway)
# ---------------------------------------------------------------------------

_TRACE_OFF = ("0", "false", "no", "off")


def _proc_path(pid: int) -> str | None:
    """The executable path of a pid (macOS proc_pidpath, Linux /proc)."""
    if pid <= 0:
        return None
    if sys.platform == "darwin":
        import ctypes                  # here: SessionStart imports this module (write_global)
        try:
            lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            buf = ctypes.create_string_buffer(4096)
            n = lib.proc_pidpath(ctypes.c_int(pid), buf, ctypes.c_uint32(4096))
            return buf.value.decode() if n > 0 else None
        except (OSError, UnicodeDecodeError):
            return None
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except OSError:
        return None


def _parent_pid(pid: int) -> int | None:
    if pid <= 0:
        return None
    if sys.platform == "darwin":
        import ctypes
        try:
            lib = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
            buf = ctypes.create_string_buffer(640)
            n = lib.proc_pidinfo(ctypes.c_int(pid), ctypes.c_int(3), ctypes.c_uint64(0),
                                 buf, ctypes.c_int(640))
            if n >= 20:
                return struct.unpack_from("I", buf.raw, 16)[0]
            return None
        except OSError:
            return None
    try:
        with open(f"/proc/{pid}/stat", "rb") as f:
            data = f.read()
        rparen = data.rfind(b")")
        fields = data[rparen + 2:].split()
        return int(fields[1])            # ppid is field 4 (index 1 after comm)
    except (OSError, ValueError, IndexError):
        return None


def _exe_real(pid: int) -> str:
    """The executable of a pid, every symlink resolved ("" when unknown)."""
    p = _proc_path(pid)
    return os.path.realpath(p) if p else ""


def _env_git_programs() -> tuple[frozenset[str], str, str] | None:
    """The env's own git-remote-http(s) (git's libexec/git-core), git and
    git-lfs, every symlink resolved; None without the env's git."""
    from . import paths
    try:
        git = os.path.realpath(paths.tool("git"))
    except Exception:  # noqa: BLE001
        return None
    core = os.path.join(os.path.dirname(os.path.dirname(git)), "libexec", "git-core")
    remotes = frozenset(os.path.realpath(os.path.join(core, n)) for n in _GIT_REMOTES)
    try:
        lfs = os.path.realpath(paths.tool("git-lfs"))
    except Exception:  # noqa: BLE001
        lfs = ""
    return remotes, git, lfs


_GIT_REMOTES = ("git-remote-http", "git-remote-https")
# The shells git's SHELL_PATH (/bin/sh) can be: git runs a helper through
# `sh -c "<helper> <op>"` (its command has a space), and bash (macOS's
# /bin/sh) execs that one command, but dash (Debian's and Ubuntu's /bin/sh)
# forks it, so there the helper's parent is the shell.
_HELPER_SHELLS = ("sh", "dash", "bash", "ash", "busybox")


def _cmdline(pid: int) -> list[str] | None:
    """A process's argv (Linux /proc; None elsewhere or when unreadable)."""
    try:
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return None
    return [a.decode("utf-8", "surrogateescape") for a in raw.split(b"\0")[:-1]]


def _shell_ran_only_this_helper(pid: int, op: str) -> bool:
    """`pid` is git's shell running exactly this helper with this operation
    (`sh -c "<bin>/git-credential-gateway get"`, as git builds it), nothing
    else: a shell snippet that wraps the helper (a pipe, a function) is not."""
    from . import paths
    argv = _cmdline(pid)
    if not argv or len(argv) not in (3, 4) or argv[1] != "-c":
        return False
    want = f"{paths.bin_dir() / 'git-credential-gateway'} {op}"
    return argv[2] in (want, want + ' "$@"') and (len(argv) == 3 or argv[3] == argv[2])


def _parent_is_git_remote_http(op: str = "get") -> bool:
    """The helper answers only when run by the env's own git-remote-http(s)
    (directly, or through git's own `sh -c` running only this helper, where
    /bin/sh is dash), or by git-lfs's `git credential fill` (the env's git,
    whose parent is the env's git-lfs): by executable path, every symlink
    resolved, never by a name (a copied shell named git-remote-https is
    not)."""
    progs = _env_git_programs()
    ppid = _parent_pid(os.getpid())
    if progs is None or not ppid:
        return False
    remotes, git, lfs = progs
    parent = _exe_real(ppid)
    if parent in remotes:
        return True
    if os.path.basename(parent) in _HELPER_SHELLS and _shell_ran_only_this_helper(ppid, op):
        gp = _parent_pid(ppid)
        return bool(gp) and _exe_real(gp) in remotes
    if parent == git and lfs:
        gp = _parent_pid(ppid)
        return bool(gp) and _exe_real(gp) == lfs
    return False


# git's http settings that send the token somewhere else than the checked
# server (PLAN-0.11 §6.3, invariant 2): a proxy, a CA file or folder of the
# command's choosing, another SSL backend; and sslVerify off.
_HTTP_REFUSED = {"http.proxy": "a proxy (http.proxy)", "http.sslcainfo": "a CA file (http.sslCAInfo)",
                 "http.sslcapath": "a CA folder (http.sslCAPath)",
                 "http.sslbackend": "another SSL backend (http.sslBackend)"}
# The same by environment (the gated git drops them all; a git below it, or
# one started some other way, might carry them).
_ENV_REFUSED = ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY", "all_proxy", "ALL_PROXY",
                "GIT_SSL_CAINFO", "GIT_SSL_CAPATH", "GIT_SSL_CERT", "GIT_SSL_KEY", "GIT_PROXY_COMMAND",
                "SSL_CERT_FILE", "SSL_CERT_DIR", "CURL_CA_BUNDLE", "GIT_HTTP_PROXY_AUTHMETHOD")
_FALSE = ("false", "no", "off", "")
_TRUE = ("true", "yes", "on")


def _git_bool(val: str) -> bool | None:
    """git's boolean (git_parse_maybe_bool, then an integer): None when git
    would refuse the value."""
    v = val.strip().lower()
    if v in _TRUE:
        return True
    if v in _FALSE:
        return False
    try:
        return int(v, 0) != 0
    except ValueError:
        return None


def _http_overrides(url: str) -> str | None:
    """Why the token mustn't go to `url` (SPEC 9.4, PLAN-0.11 §6.3), or None:
    git's http settings as they apply to this URL (`git config -z
    --get-urlmatch http URL`: the plain keys and URL-scoped ones, from the
    repository, the global config, -c and the environment) turn sslVerify
    off, or set a proxy, a CA file or folder or an SSL backend. Fails
    closed: if git can't answer, the token isn't sent."""
    git = _find_git()
    cant = "gateway: couldn't check git's http settings for this URL, so the token isn't sent"
    if not git:
        return cant
    try:
        r = subprocess.run([git, "config", "-z", "--get-urlmatch", "http", url],
                           capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return cant
    if r.returncode == 1 and not r.stdout.strip(b"\0"):
        return None                      # nothing set: git checks certificates, no proxy
    if r.returncode != 0:
        return ("gateway: git couldn't read its http settings, so the token isn't sent; fix the "
                "git config")
    for item in r.stdout.decode("utf-8", "surrogateescape").split("\0"):
        if not item:
            continue
        key, nl, val = item.partition("\n")
        key = key.lower()
        if key == "http.sslverify" and nl:
            b = _git_bool(val)
            if b is None:
                return ("gateway: git couldn't read its http.sslVerify setting, so the token isn't "
                        "sent; fix the git config")
            if not b:
                return ("gateway: http.sslVerify is false for this URL; the token won't be sent "
                        "until certificate checking is on again")
        if key in _HTTP_REFUSED and val.strip():
            return (f"gateway: git's settings give this URL {_HTTP_REFUSED[key]}, so the token "
                    "isn't sent; take the setting out (or run the command without it)")
    return None


def _remote_proxy() -> str | None:
    """Why the token mustn't go out (PLAN-0.11 §6.3), or None: a remote's own
    proxy (remote.NAME.proxy, which git uses for that remote's http(s) URLs
    instead of http.proxy) is set in git's settings here, the command
    line's -c included. Any remote's counts (which remote the URL belongs to
    isn't told to the helper). Fails closed when git can't answer."""
    git = _find_git()
    cant = "gateway: couldn't check git's remote proxy settings, so the token isn't sent"
    if not git:
        return cant
    try:
        r = subprocess.run([git, "config", "-z", "--get-regexp", r"^remote\..*\.proxy$"],
                           capture_output=True, timeout=10, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return cant
    if r.returncode == 1 and not r.stdout.strip(b"\0"):
        return None
    if r.returncode != 0:
        return cant
    for item in r.stdout.decode("utf-8", "surrogateescape").split("\0"):
        key, _nl, val = item.partition("\n")
        if key and val.strip():
            return (f"gateway: {formmod.safe(key) or 'a remote proxy'} is set, which would send "
                    "the token through that proxy, so it isn't sent; ask the user to take the "
                    "setting out (in their own terminal)")
    return None


def _env_refused() -> str | None:
    for k in _ENV_REFUSED:
        if os.environ.get(k):
            return (f"gateway: {k} is set, which would send the token through another proxy or "
                    "trust another certificate; unset it")
    raw = os.environ.get("GIT_CONFIG_PARAMETERS")
    if raw:
        bad = _parameters_guarded(raw)
        if bad:
            return (f"gateway: the command line sets {formmod.safe(bad[0]) or 'a credential setting'} "
                    "after the gateway's settings (-c, or an alias's -c), so the token isn't sent; "
                    "run git without it")
    return None


def _find_git() -> str | None:
    """The env's git: the gated git's own (it reads the same settings the
    gated git does, the inherited GIT_CONFIG_* included)."""
    from . import paths
    try:
        return paths.tool("git")
    except Exception:  # noqa: BLE001
        return None


def _read_request() -> dict[str, str]:
    req: dict[str, str] = {}
    try:
        data = sys.stdin.buffer.read()
    except OSError:
        return req
    for line in data.decode("utf-8", "replace").splitlines():
        if line == "":
            break
        k, _, v = line.partition("=")
        if k:
            req[k] = v
    return req


_CRED_CALL: dict[str, Any] = {}     # the helper's mode for its audit lines (credential_main)


def _refuse(host: str | None, reason: str, fix: str | None = None) -> int:
    """No credential: print one stderr line (git carries on unauthenticated)."""
    from . import modes
    audit.refusal("git-credential", host, reason, fix, mode=modes.standin_audit_mode(_CRED_CALL))
    print(reason, file=sys.stderr)
    return 0


def credential_main(argv: list[str]) -> int:
    """git-credential-gateway get|store|erase (SPEC 9.4)."""
    from . import modes
    _CRED_CALL.clear()
    op = argv[0] if argv else ""
    req = _read_request()
    host = req.get("host") or ""
    proto = (req.get("protocol") or "").lower()
    path = req.get("path") or ""
    from . import paths
    testing_active = _testing_active()

    if op == "store":
        return 0  # the gateway owns the token; nothing to store
    if op == "erase":
        return _erase(req)
    if op != "get":
        return 0

    # --- refusal gates (before any vault access) ---------------------------
    if not _parent_is_git_remote_http():
        return _refuse(host, "gateway: the git credential helper answers only git itself, not a "
                       "direct `git credential` call", "let git fetch/push/clone run normally")
    # below the gated git the git stand-in started (its mark, through the
    # env's git programs): its mode and the entries the hook asked about,
    # when Claude typed it
    gp = gated_parent()
    _CRED_CALL["mode"] = modes.audit_word(gp.mode if gp.typed else None)
    if not gp.below:
        return _refuse(host, "gateway: the git credential helper answers only the gateway's own "
                       "git (the git stand-in's), not another git", "run git as its own command")
    trace = os.environ.get("GIT_TRACE_REDACT")
    if trace is not None and trace.strip().lower() in _TRACE_OFF:
        return _refuse(host, "gateway: GIT_TRACE_REDACT is off, which would print the token; "
                       "unset it", "run the command without GIT_TRACE_REDACT=0")
    if proto == "http" and not (testing_active and _is_loopback(host)):
        return _refuse(host, "gateway: the git credential helper serves https only (an http "
                       "remote would send the token in the clear)")
    if proto not in ("https", "http"):
        return _refuse(host, f"gateway: {formmod.safe(proto) or 'that protocol'} is not https")
    if "GIT_SSL_NO_VERIFY" in os.environ:   # git checks presence: even an empty value counts
        return _refuse(host, "gateway: GIT_SSL_NO_VERIFY is set (the server's certificate wouldn't "
                       "be checked); unset it")
    if not host:
        return _refuse(host, "gateway: the credential request named no host")
    bad_env = _env_refused()
    if bad_env:
        return _refuse(host, bad_env)
    url_path = urllib.parse.quote(path.lstrip("/"), safe="/~@!$&'()*+,;=:%")
    over = _http_overrides(f"{proto}://{host}/{url_path}") or _remote_proxy()
    if over:
        return _refuse(host, over)

    # --- account selection ------------------------------------------------
    try:
        data = vault.load()
    except vault.VaultLocked as e:
        return _refuse(host, str(e))
    except vault.VaultError:
        return _refuse(host, "gateway: the vault can't be read, so no token was sent; tell the user "
                       "(gate status shows why)", "gate status")
    form = consent.load_form(data)
    # the gated git's mode for a command Claude typed (else the modeless
    # rule), and the accounts the approval hook asked about (their "ask"
    # passes)
    mode = gp.mode if gp.typed else None
    asked = {n for s, n in gp.asked if s == "accounts"} if gp.typed else set()
    eff = consent.compute(form, data, mode)
    owner = acctmod.owner_from_path(path) if path else None
    # GATE_ACCOUNT (the env prefix the user set on the git command) is honoured.
    sel = acctmod.select(("github", "huggingface"), host, owner, form, effective=eff,
                         vault=data, env=os.environ, mode=mode, asked=asked)
    if sel.error:
        return _refuse(host, sel.error)
    if sel.account is None:
        return _refuse(host, acctmod.no_git_account(host))
    name = sel.account.name
    if not consent.bound_ok(data, name, host):
        return _refuse(host, f"gateway: {name}'s credential isn't bound to {formmod.safe(host) or host}; "
                       f"run gate check {name} while the user is here")
    rec = (data.get("accounts") or {}).get(name) or {}
    tok = rec.get("token") or {}
    if tok.get("stale"):
        return _refuse(host, acctmod.stale_token_message(name), f"gate check {name}")
    token = tok.get("value")
    if not token:
        return _refuse(host, f"gateway: {name} has no token; run gate check {name} while the "
                       "user is here")
    username = "x-access-token" if sel.account.kind == "github" else (sel.account.login or "token")
    audit.use("git-credential", host, name, argv=["get", host, path], secrets=[token],
              mode=modes.standin_audit_mode(_CRED_CALL))
    out = sys.stdout
    out.write(f"protocol={proto}\n")
    out.write(f"host={host}\n")
    out.write(f"username={username}\n")
    out.write(f"password={token}\n")
    out.flush()
    return 0


def _erase(req: dict[str, str]) -> int:
    """git erase after a 401: mark stale the token git was rejected with (one
    re-entry). git sends the whole credential it used: the account whose
    stored token equals the rejected password (among the github/huggingface
    accounts bound to that host) is the one; nothing else is touched, and a
    password that isn't one of the gateway's marks nothing. Without a
    password, the account `get` would choose for that request (owner from the
    path, GATE_ACCOUNT); never one picked by elimination."""
    host = req.get("host") or ""
    if not host:
        return 0
    password = req.get("password") or ""
    path = req.get("path") or ""
    try:
        with vault.edit() as data:
            names = _rejected_accounts(data, host, password, path)
            for name in names:
                if vault.mark_stale(data, name, "token"):
                    vault.add_event(data, "reject", f"{name} token rejected by {host}")
                    audit.log("reject", tool="git-credential", target=host, account=name)
    except vault.VaultError:
        pass
    return 0


def _rejected_accounts(data: dict, host: str, password: str, path: str) -> list[str]:
    form = consent.load_form(data)
    if password:
        pw = password.encode("utf-8", "surrogateescape")
        out = []
        for name, rec in sorted((data.get("accounts") or {}).items()):
            if not isinstance(rec, dict):
                continue
            kind = rec.get("kind") or getattr(form.accounts.get(name), "kind", None)
            if kind not in ("github", "huggingface"):
                continue
            tok = (rec.get("token") or {}).get("value")
            if not isinstance(tok, str) or not tok or not consent.bound_ok(data, name, host):
                continue
            if hmac.compare_digest(tok.encode("utf-8", "surrogateescape"), pw):
                out.append(name)
        return out
    eff = consent.compute(form, data)
    owner = acctmod.owner_from_path(path) if path else None
    s = acctmod.select(("github", "huggingface"), host, owner, form, effective=eff, vault=data,
                       env=os.environ)
    return [s.account.name] if s.account is not None and not s.error else []


def _testing_active() -> bool:
    from . import testing
    return testing.active() is not None
