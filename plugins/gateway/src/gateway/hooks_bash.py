"""PreToolUse(Bash|Monitor|run_in_terminal|checkpoint's job_start) approval hook (SPEC 8).

Decision order (reasons always start with `gateway:`):

1. **deny** `curl`/`wget` in command position (any segment), also behind a
   wrapper (`command`, `builtin`, `busybox`, `env`, `nohup`, `timeout`,
   `sudo`, `xargs`, ...). Also (review round 5) `gate secret` for every
   tool, Bash, Monitor and the Terminal panel alike (the user's command:
   also behind a wrapper, or named in a shell string, eval, loop or `find
   -exec`), and `gate export|import|copy-to` typed into the user's Terminal
   panel (without a screen they ask there for the user's one-time code; the
   panel's shells run under the desktop app, which `gate secret`'s
   process-tree check doesn't see).
2. **deny** reading/naming `~/.config/gateway/private` (or the v2 key/store),
   `age -d` on them, a direct `git credential` / helper / askpass run, or
   setting `GIT_TRACE_REDACT` to anything but a clear true. Every word is
   checked (a bare `key.txt` is a file in the working directory, which `cd`s
   in the command move), and option values (`--file=P`, `-fP`), redirect
   targets, globs (expanded) and recursive readers (`grep -r`, `rsync`,
   `scp -r`, `cp -r`, `tar`, ... on a folder holding private/). A tilde is
   expanded as the shell does it (`~+` the stage's working directory, an
   unknown user's `~name/x` a relative path); a word starting with `~-` or
   `~N` names a folder the hook can't know and is denied (DENY_TILDE).
3. **deny** a gateway verb whose target right is `false` in the form (looked
   up behind exec-style wrappers: `env`, `nohup`, `nice`, `command`, ...),
   and one the form gives but the user hasn't approved yet (the effective
   right is off: a widening waiting, a new host, a jump host not set up),
   with the next step (`gate check NAME`; round 3).
   Remote sudo counts too: `sudo` in command position in what the remote
   runs (ssh's command, rsync's `--rsync-path`, or a scp / rsync remote path,
   which old rsync and `scp -O` hand to the remote shell) needs the host's
   sudo right (`ssh builder sudo x` with sudo = false: `gateway: sudo is off
   for builder`). Also denied: git's `--upload-pack` / `--receive-pack` /
   `--exec` / `remote.*.uploadpack` with a sudo word, and `sftp -s`.
4. **ask** when a gateway verb's target right is `"ask"` in the form or in
   effect (deny and ask go by the stricter of the two: an approved "ask"
   edited to `true` stays "ask" until the user's OK; round 3) (ssh, local
   sudo, or the remote host's sudo for a remote command with a `sudo` word). The
   stand-ins give an "ask" right only to a command Claude typed
   (ancestry.typed_by_claude), relying on this prompt; so scp, sftp and
   rsync on an "ask" right (they start ssh themselves, which can't be asked
   about) are denied with the way to do it instead (asked in the user's own
   Terminal panel), and a command the parser can't read, or one that hides
   how it calls them (a shell behind a wrapper, a loop, a target in a
   variable), is asked about when its text names a host with an "ask" right
   (or has a sudo word and localhost sudo is "ask"). A script sourced into
   Claude's shell, or a name computed at run time, isn't seen.
5. **allow** (only in auto / bypassPermissions) when every segment is an
   allowed shape run by its bare name (a path such as `./ssh` runs whatever
   file is there, not the stand-in PATH finds; round 3): a gateway verb on a
   host with the right `true` (effective; remote
   sudo also needs the host's effective sudo `true`), a `gate`
   subcommand (never `forget`, which deletes stored secrets: GW-DATA-1), or
   a benign command; one that reads files (cat, grep, ls, ...) only when
   everything it may read is a plain file of the project (CLAUDE_PROJECT_DIR,
   else the cwd; not the home folder or above) or a temp folder (never in
   the home): no hidden or credential-like name (.env*, *.pem, *.key, id_*,
   *credentials*, ...) below it, a recursive grep's whole tree included, and
   with no path operand the cwd in one of them (GW-UX-1; its own reason
   text, READ_ALLOW); the same for such a reader under sudo, unless a wrapper
   changed its directory (env -C / sudo -D). scp / sftp / rsync only with
   options on an allowlist (never rsync's -e in any spelling, --log-file,
   --write-batch, --remove-source-files, --old-args, -M, -K, ...), plain
   remote paths, downloads that name what they copy (no folder contents, no
   hidden part), every local operand in the project, ~/Downloads or a temp
   folder by the download tool's rules (web.plain_local_path), and sftp only
   as the first stage of a pipeline. `gate with` is never allowed;
   nor is anything the words hide: an output redirection other than to
   /dev/null (a write), an expansion the parser can't resolve (`$X`), a glob
   or brace expansion, a `cd` to an unknown place, `sort -o`, `uniq IN OUT`,
   a sudo'd command with a destructive-list command anywhere in it (behind a
   wrapper, in a command string) or one that runs a command its words don't
   show (`sh -c`, a shell reading a pipe, `xargs`, `su`, `find -exec`), or a
   `date` that could set the clock (`-s`, `--set`, `-f`, a BSD operand).
6. otherwise no decision (Claude Code's mode decides).

Monitor and `run_in_background` calls are judged like any Bash command: the
gateway doesn't change how Claude's ordinary commands run (DECISIONS,
"Rolled back"). Their raw output (Monitor's lines, a background task's
notice) reaches no output hook; `gate scrub` is an optional filter Claude
may pipe through, and the prompt hook holds back a task notification that
quotes a stored value or a token shape (hooks_prompt).

checkpoint's job_start (JOB_TOOL) is judged on its `command`, or its `argv`
shlex-joined: steps 1-3 as for Bash (gate export/import/copy-to denied as in
the Terminal panel), an "ask" right of step 4 denied instead (nobody can be
asked while a job runs), and never step 5 (nor any ask): only a deny or no
decision.

Managed mode (PLAN-v4 phase 4, docs/dev/modules/managed.md), before step 1:
pre_bash.sh sends every Bash and Monitor call here with GW_MANAGED_CHECK=1
when CLAUDE_CODE_SHELL_PREFIX isn't this plugin's hooks/gate-sh (the mod
sets it at session start; so mods are off, Claude Code is older than
2.1.287, another prefix replaced it, or the session started before managed
mode was switched on). With the effective `[shell] managed` "on" the call
is denied ("managed shell unavailable", the reason and what to do); "warn"
lets it run in the user's own shell with a notice once per session, then
judges it as below; "off" just judges it.

Steps 1-4 run in every permission mode; only step 5 is gated on auto/bypass.
Refusals are audited (so `gate why` can explain the last one). When a command
could edit `gateway.toml` (e.g. `sed -i`), narrowings are ratcheted first.
"""
from __future__ import annotations

import dataclasses
import fnmatch
import glob as globmod
import itertools
import json
import os
import re
import shlex
import sys
import unicodedata
from typing import Any

from . import audit, bashparse, consent, paths, ssh_args, testing
from . import form as formmod
from . import vault

_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Setting GIT_TRACE_REDACT to anything but a clear "true" (0, false, no, off,
# empty, $X, ...) turns git's credential redaction off. Matched on the command
# with quotes and backslashes removed, so `=""0` and `=fal"se"` are caught too.
# This is defence in depth: the git credential helper's own GIT_TRACE_REDACT
# check (SPEC 9.4) is the real guard; no regex models every shell spelling.
_GIT_TRACE = re.compile(r"GIT_TRACE_REDACT=(?!(?:1|true|yes|on)(?![A-Za-z0-9_]))", re.I)
_QUOTES = re.compile(r"[\"'\\]")
_FORM_NAMES = ("gateway.toml", "config/gateway")
_GLOB_CHARS = re.compile(r"[*?[]")
# Output redirections an allowed command may carry (nothing is written).
SAFE_REDIRECTS = frozenset({("2>&1", ""), (">", "/dev/null"), (">>", "/dev/null"),
                            ("2>", "/dev/null")})
GLOB_MAX = 500           # matches of one glob checked against the protected set

# gate subcommands the hook may allow. Not `forget`: it deletes an entry's
# stored secrets for good (no dialog, no backup), so the reviewer or a prompt
# decides (GW-DATA-1); nor `with` (an account's credential to any program).
GATE_SUBCMDS = frozenset({"status", "check", "login", "rotate", "why", "log",
                          "export", "import", "copy-to", "migrate", "scrub"})
# gate subcommands that log in to a host with Claude's key (the sudo probe,
# the key install, the rotation, copy-to's transfer): judged like ssh to it.
GATE_SSH_SUBCMDS = frozenset({"check", "rotate", "copy-to"})
# Review round 5: `gate secret` is the user's (a secret, a consent or a
# device code typed in their own terminal after the one-time code); denied
# for every tool. Its process-tree check doesn't see the desktop app's
# Terminal panel (its shells run under the app's helper), which Claude can
# type into with mcp__terminal__run_in_terminal, so the subcommands with a
# terminal path behind the code (export, import, copy-to without a screen)
# are denied there too; in Claude's Bash they use pop-ups or say "ask the user".
GATE_USER_SUBCMD = "secret"
GATE_TERMINAL_SUBCMDS = frozenset({"export", "import", "copy-to"})
DENY_GATE_SECRET = ("gateway: gate secret was removed: credentials are typed only into the "
                    "gateway's own dialog in Claude Code, which `gate check NAME` opens. Don't "
                    "ask for a secret any other way.")
# The checkpoint plugin's job tool (plugin "check", MCP server "jobs"): it runs
# `command` (a shell string) or `argv` (shlex-joined) with /bin/sh -c as a
# detached job of checkpoint's MCP server, with the session's environment
# (plus env.sh's stand-ins when checkpoint sources it). The hook judges it
# like a Bash command with three differences: an "ask" right is denied
# (nobody can be asked while a job runs, and the stand-ins refuse "ask" to a
# job anyway: ancestry.typed_by_claude), gate export/import/copy-to are
# denied as in the Terminal panel (a job has no terminal, and one that
# outlives Claude's process tree escapes gate's Claude-ancestor check), and
# it never answers allow (Claude Code's own permission check decides: a
# prompt in default mode, the classifier in auto mode). Only fires when
# checkpoint is installed (the matcher names its tool).
JOB_TOOL = "mcp__plugin_check_jobs__job_start"
# The gateway's own job and terminal tools (PLAN-v4 phase 5): what they run or
# type is judged like a checkpoint job (Bash's denies, an "ask" right denied,
# never allow): job_start's command/argv, terminal_send's text (a terminal
# runs what is typed into its shell; nobody can be asked about it there).
GW_JOB_TOOL = "mcp__plugin_gate_gw__job_start"
GW_SEND_TOOL = "mcp__plugin_gate_gw__terminal_send"
BENIGN = frozenset({"cd", "pwd", "echo", "printf", "true", ":", "test", "[", "ls", "cat",
                    "head", "tail", "wc", "grep", "sort", "uniq", "date", "sleep"})
# The benign commands that read files, a folder's listing or the working
# directory (GW-UX-1): allowed only when everything they may read is a plain
# file of the project or a temp folder (_reads_plain); with no path operand
# they read the working directory (or stdin), which must be in the project.
BENIGN_READERS = frozenset({"pwd", "test", "[", "ls", "cat", "head", "tail", "wc", "grep",
                            "sort", "uniq"})
# Names that hold credentials wherever they are, in any letter case (the
# hidden ones are refused as hidden anyway): never vouched for, in the project
# too. Besides keys and dotfiles: Kerberos ticket caches (krb5cc_UID in
# /tmp), anything named for a secret or a token, key stores, Terraform state
# and variables, kubeconfig files and cloud service-account keys.
_CRED_NAME = re.compile(r"(?i)\A(?:\.env.*|.*\.pem|.*\.key|id_.*|.*credentials.*|\.?netrc|"
                        r"\.?pgpass|\.?npmrc|\.?pypirc|krb5cc.*|.*secret.*|.*token.*|"
                        r".*\.(?:p12|pfx|ppk|jks|keystore|p8|keytab|kdbx|gpg|ovpn|age)|"
                        r".*_(?:rsa|dsa|ed25519|ecdsa)|passwords?.*\.txt|"
                        r".*\.tfstate.*|.*\.tfvars(?:\.json)?|"
                        r"kubeconfig.*|service[-_]?account.*\.json)\Z")
# The user's credential folders (under the home): a project or temp folder in
# one is no place to read from without a prompt.
_CRED_DIRS = (".ssh", ".aws", ".gnupg", ".kube", ".docker", ".config", ".claude")
READ_TREE_MAX = 2000     # entries a recursive grep's folder may hold and still be vouched for
# macOS's file systems ignore letter case: a path compares to the project and
# the temp folders that way there (web._under folds everywhere; the credential
# folders and the home are always compared folded, which only refuses more)
_CASELESS = sys.platform == "darwin"

# ssh options that take a value, the safe no-arg flags, and the safe value-takers.
SSH_ARG_OPTS = set(ssh_args.SSH_ARGOPTS)      # the stand-in's own table (-B, -P too)
SSH_SAFE_FLAG = set("tTqvCN46")
SSH_SAFE_ARG = set("plLD")
SSH_SAFE_O = frozenset({"connecttimeout", "serveraliveinterval", "batchmode"})

DENY_PRIVATE = ("gateway: that path holds the gateway's private keys and vault; Claude never "
                "needs it (gate status shows what is stored).")
DENY_TRANSCRIPT = ("gateway: that reads Claude Code's session transcripts, which can hold output "
                   "Claude Code showed unmasked (a failed command's, a background command's "
                   "notice); Claude doesn't read them (the tool-results folders next to them, and "
                   "a Workflow run's journal.jsonl, are fine).")
DENY_PRIVATE_TREE = ("gateway: that would read the gateway's private folder (its keys and vault) "
                     "recursively; name a narrower path that doesn't contain "
                     "~/.config/gateway/private.")
DENY_TILDE = ("gateway: a path starting with `~-` or `~N` (the shell's previous or stacked "
              "working directory), or `~` when no home folder is known, names a folder the "
              "gateway can't resolve, which could be its private folder; spell the path out.")


# ---------------------------------------------------------------------------
# Hook output
# ---------------------------------------------------------------------------


def _out(decision: str, reason: str) -> dict[str, Any]:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                   "permissionDecision": decision,
                                   "permissionDecisionReason": reason}}


def _deny(reason: str, tool: str = "bash", target: str | None = None,
          fix: str | None = None) -> dict[str, Any]:
    try:
        audit.refusal(tool, target, reason, fix)
    except Exception:  # noqa: BLE001 - never fail the hook because of the audit
        pass
    return _out("deny", reason)


def _deny_curl(tool: str) -> dict[str, Any]:
    return _deny(f"gateway: use the http tool (or download / WebFetch) instead of {tool}; it "
                 "adds account keys (Claude Code's permission mode decides whether it asks, as "
                 "for any tool). If the http tool isn't available in this "
                 "session (the gateway was still setting up when it started), ask the user to "
                 "reconnect gw in /mcp or start a new session.", tool=tool)


def _deny_right(name: str, verb: str) -> dict[str, Any]:
    if name == "localhost" and verb == "sudo":
        r = "gateway: sudo is off on this machine (gateway.toml); ask the user if it should be on."
    else:
        r = (f"gateway: {verb} is off for {name} (gateway.toml); ask the user if it should be on.")
    return _deny(r, tool=verb, target=name)


_ask_phrase = consent.ask_phrase


def _ask(name: str, verb: str, more: list[tuple[str, str]] | None = None,
         in_job: bool = False) -> dict[str, Any]:
    """The prompt's reason names every "ask" right the command uses (the user
    approves all of them at once, root on a host included). For a checkpoint
    job: a deny instead (nobody can be asked while it runs)."""
    rights = list(dict.fromkeys([(name, verb), *(more or [])]))
    shown = [_ask_phrase(n, v) for n, v in rights]
    what = shown[0] if len(shown) == 1 else ", ".join(shown[:-1]) + " and " + shown[-1]
    # a locked vault: sudo here asks until it is unlocked (consent.LOCKED_SUDO_NOTE)
    note = _LOCKED.get("sudo", "") if ("localhost", "sudo") in rights else ""
    if in_job:
        return _deny(consent.job_ask_message(shown) + note, tool=verb, target=name)
    are = "is" if len(shown) == 1 else "are"
    return _out("ask", f'gateway: {what} {are} set to "ask"; approve it to run.{note}')


# ---------------------------------------------------------------------------
# Stage helpers
# ---------------------------------------------------------------------------


def _strip_gate_account(stage: list[str]) -> list[str]:
    return _argv_meta(stage)[0]


def _argv_meta(stage: list[str]) -> tuple[list[str], list[bool], list[bool]]:
    """The stage's words after a GATE_ACCOUNT=NAME prefix, with bashparse's
    per-word flags: (argv, expands, globs)."""
    words = list(stage)
    exp = list(getattr(stage, "expands", None) or [False] * len(words))
    glb = list(getattr(stage, "globs", None) or [False] * len(words))
    k = 0
    while k < len(words) and _ASSIGN.match(words[k]) and words[k].split("=", 1)[0] == "GATE_ACCOUNT":
        k += 1
    return words[k:], exp[k:], glb[k:]


def _home_dirs() -> list[str]:
    """Where `~` and `$HOME` point: $HOME (what the shell uses) and the
    password-database home. Under a test override only the test's home, so a
    test never resolves (let alone globs) the real ~/.config/gateway."""
    try:
        uh = str(paths.user_home())
    except Exception:  # noqa: BLE001
        uh = ""
    if testing.active() is not None:
        return [uh] if uh else []
    h = os.environ.get("HOME", "")
    return [d for d in dict.fromkeys([h, uh]) if d and os.path.isabs(d)]


_URI = re.compile(r"(?i)(rsync|ssh|scp|sftp)://(?:([^@/]*)@)?(\[[^\]]*\]|[^/:]*)(?::[0-9]*)?(/.*)?\Z",
                  re.S)


def _remote_operand(a: str) -> tuple[str, str] | None:
    """(host word for _resolve_host, remote path) of a transfer operand like
    `h:p`, `u@h:p`, `u@[::1]:p`, `h::module`, `scp://u@h:22/p` or
    `rsync://h/m`; None for a local path (`/x`, `./x`, `~/x`, `a/b:c`, no
    colon)."""
    if not a or a.startswith("-") or a[:1] in ("/", "~", "."):
        return None
    m = _URI.match(a)
    if m:
        user, host, path = m.group(2), m.group(3).strip("[]"), m.group(4) or ""
        return ((f"{user}@" if user else "") + host, path)
    at = a.find("@[")
    if a.startswith("[") or (at >= 0 and "/" not in a[:at] and ":" not in a[:at]):
        k = a.find("]:")
        if k < 0:
            return None
        hostpart, path = a[:k + 1], a[k + 2:]
        user, _, host = hostpart.rpartition("@")
        return ((f"{user}@" if user else "") + host.strip("[]"), path)
    if ":" not in a:
        return None
    before, _, path = a.partition(":")
    if "/" in before or not before:
        return None
    if path.startswith(":"):
        path = path[1:]                        # rsync's host::module
    return before, path


def _host_of_arg(a: str) -> str | None:
    """The host named by a transfer argument (see _remote_operand)."""
    r = _remote_operand(a)
    return r[0] if r else None


# ---------------------------------------------------------------------------
# ssh / scp / sftp / rsync option scanning
# ---------------------------------------------------------------------------


def _scan_ssh(argv: list[str]) -> tuple[list[str], bool]:
    safe = True
    i, n = 1, len(argv)
    while i < n:
        a = argv[i]
        if a == "--":
            i += 1
            break
        if a == "-" or not a.startswith("-"):
            break                      # destination
        if a.startswith("--"):
            safe = False
            i += 1
            continue
        body = a[1:]
        k = 0
        while k < len(body):
            c = body[k]
            if c in SSH_ARG_OPTS:
                val = body[k + 1:] if k + 1 < len(body) else (argv[i + 1] if i + 1 < n else "")
                if c == "o":
                    if val.split("=")[0].strip().lower() not in SSH_SAFE_O:
                        safe = False
                elif c not in SSH_SAFE_ARG:
                    safe = False
                if k + 1 >= len(body):
                    i += 1
                break
            if c not in SSH_SAFE_FLAG:
                safe = False
            k += 1
        i += 1
    dest = argv[i] if i < n else None
    return ([dest] if dest else []), safe


@dataclasses.dataclass
class Transfer:
    """What a scp / sftp / rsync stage does, as far as the words show."""
    targets: list[str] = dataclasses.field(default_factory=list)   # host words, for rights
    safe: bool = True              # every option is on the allowlist (and sftp -s absent)
    remote: list[tuple[str, str]] = dataclasses.field(default_factory=list)  # (host, path)
    local: list[str] = dataclasses.field(default_factory=list)     # local operands
    download: bool = False         # a remote source copied to a local destination
    remote_cmd: str = ""           # rsync --rsync-path value
    opts: set[str] = dataclasses.field(default_factory=set)       # short options seen
    subsystem: bool = False        # sftp -s SUBSYSTEM|PATH (a path runs that command there)


# rsync (3.x and openrsync): short flags without a value that can't run a
# program, write outside the operands or follow a planted link on the
# receiving side (-K), and the long options likewise (exact names: popt
# takes no abbreviations, and an abbreviation getopt_long would accept isn't
# on the list). Everything else withholds `allow`, notably -e/--rsh,
# --rsync-path (but `sudo rsync`), -M/--remote-option, --log-file,
# --write-batch, --only-write-batch, --read-batch, --daemon, --config,
# --remove-source-files, --old-args, --temp-dir, --partial-dir,
# --backup-dir, --suffix, --files-from, --filter, --*-dest and -K.
RSYNC_SAFE_SHORT = frozenset("vqcarRbudlLHpEXAogDtUNOJSnWxyzhPim468sIC0")
RSYNC_VALUE_SHORT = frozenset("eBfMT@")
RSYNC_SAFE_LONG = frozenset({
    "archive", "recursive", "verbose", "quiet", "checksum", "update", "dirs", "links",
    "copy-links", "safe-links", "copy-unsafe-links", "munge-links", "hard-links", "perms",
    "executability", "xattrs", "acls", "owner", "group", "devices", "specials", "times",
    "atimes", "open-noatime", "crtimes", "omit-dir-times", "omit-link-times", "sparse",
    "preallocate", "dry-run", "whole-file", "one-file-system", "fuzzy", "compress",
    "human-readable", "progress", "partial", "itemize-changes", "prune-empty-dirs", "ipv4",
    "ipv6", "8-bit-output", "protect-args", "secluded-args", "stats", "delete", "del",
    "delete-before", "delete-during", "delete-delay", "delete-after", "delete-excluded",
    "delete-missing-args", "ignore-missing-args", "force", "ignore-errors", "ignore-existing",
    "existing", "ignore-non-existing", "ignore-times", "size-only", "inplace", "append",
    "append-verify", "mkpath", "numeric-ids", "no-motd", "list-only", "backup", "relative",
    "implied-dirs", "cvs-exclude", "blocking-io", "delay-updates", "fsync", "from0",
    "msgs2stderr"})
RSYNC_SAFE_LONG_VALUE = frozenset({
    "exclude", "include", "chmod", "max-size", "min-size", "bwlimit", "timeout", "contimeout",
    "info", "debug", "compress-level", "zl", "compress-choice", "zc", "checksum-choice", "cc",
    "modify-window", "outbuf", "stderr", "max-delete", "block-size", "skip-compress",
    "out-format", "log-format"})
# Long options that take a value (`--opt VALUE` consumes the next word), safe or not.
RSYNC_VALUE_LONG = RSYNC_SAFE_LONG_VALUE | frozenset({
    "rsh", "rsync-path", "filter", "exclude-from", "include-from", "files-from", "log-file",
    "log-file-format", "write-batch", "only-write-batch", "read-batch", "temp-dir",
    "partial-dir", "backup-dir", "suffix", "compare-dest", "copy-dest", "link-dest", "chown",
    "usermap", "groupmap", "max-alloc", "port", "sockopts", "address", "password-file",
    "config", "dparam", "iconv", "protocol", "checksum-seed", "remote-option", "early-input",
    "copy-as", "stop-after", "stop-at", "time-limit"})
SCP_FLAGS_SAFE = frozenset("rpqCv46B")
SCP_ARGS = frozenset(ssh_args.SCP_ARGOPTS)
SFTP_FLAGS_SAFE = frozenset("afpqrvC46")
SFTP_ARGS = frozenset(ssh_args.SFTP_ARGOPTS)
# Characters a remote path may hold for `allow`: it may reach the remote
# shell unquoted (old rsync, scp -O), so no metacharacter, space or glob.
_REMOTE_PATH_OK = re.compile(r"[A-Za-z0-9._/~@%+=,:^-]*\Z")


def _scan_short_opts(argv: list[str], i: int, safe_flags: frozenset[str],
                     value_opts: frozenset[str], safe_values: dict[str, Any],
                     tr: Transfer) -> int:
    """One `-xyz` cluster of scp/sftp/rsync at argv[i]; returns the next index.
    A value-taking option takes the rest of the cluster or the next word;
    `safe_values[c]` says whether that value is fine for allow (None: any)."""
    body, k = argv[i][1:], 0
    while k < len(body):
        c = body[k]
        tr.opts.add(c)
        if c in value_opts:
            val = body[k + 1:] if k + 1 < len(body) else (argv[i + 1] if i + 1 < len(argv) else "")
            check = safe_values.get(c, False)
            if check is False:
                tr.safe = False
            elif check is not None and not check(val):
                tr.safe = False
            return i + (1 if k + 1 < len(body) else 2)
        if c not in safe_flags:
            tr.safe = False
        k += 1
    return i + 1


def _safe_o(val: str) -> bool:
    return val.split("=")[0].strip().lower() in SSH_SAFE_O


def _scan_transfer(base: str, argv: list[str]) -> Transfer:
    """scp / sftp / rsync: options (allowlist), operands (remote / local)."""
    tr = Transfer()
    ops: list[str] = []
    i, n = 1, len(argv)
    if base == "rsync":
        safe_vals: dict[str, Any] = {}
    elif base == "scp":
        safe_vals = {"P": None, "l": None, "o": _safe_o}
    else:
        safe_vals = {"P": None, "l": None, "o": _safe_o, "B": None, "R": None}
    while i < n:
        a = argv[i]
        if a == "--":
            ops += argv[i + 1:]
            break
        if a == "-" or not a.startswith("-"):
            ops.append(a)
            i += 1
            continue
        if base != "rsync":
            if a.startswith("--"):
                tr.safe = False
                i += 1
                continue
            flags, vals = (SCP_FLAGS_SAFE, SCP_ARGS) if base == "scp" else (SFTP_FLAGS_SAFE, SFTP_ARGS)
            i = _scan_short_opts(argv, i, flags, vals, safe_vals, tr)
            continue
        if a.startswith("--"):
            name, eq, val = a[2:].partition("=")
            takes = name in RSYNC_VALUE_LONG
            if takes and not eq:
                val = argv[i + 1] if i + 1 < n else ""
                i += 1
            i += 1
            if name == "rsync-path":
                tr.remote_cmd = val
                if val.strip() != "sudo rsync":
                    tr.safe = False
            elif takes:
                if name not in RSYNC_SAFE_LONG_VALUE:
                    tr.safe = False
            elif eq or not (name in RSYNC_SAFE_LONG or (
                    name.startswith("no-") and (name[3:] in RSYNC_SAFE_LONG
                                                or (len(name) == 4 and name[3] in RSYNC_SAFE_SHORT)))):
                tr.safe = False
            continue
        i = _scan_short_opts(argv, i, RSYNC_SAFE_SHORT, RSYNC_VALUE_SHORT, safe_vals, tr)
    if base == "sftp":
        tr.subsystem = "s" in tr.opts
        # sftp DESTINATION [LOCAL]: the destination names a host even without a path
        if ops:
            r = _remote_operand(ops[0])
            if r is None and not ops[0].startswith(("/", ".", "~")):
                r = (ops[0], "")
            if r is not None:
                tr.targets.append(r[0])
                tr.remote.append(r)
                tr.download = bool(r[1])
                tr.local = ops[1:2] or (["."] if r[1] else [])
            tr.local += ops[2:]
        return tr
    for k, a in enumerate(ops):
        r = _remote_operand(a)
        if r is None:
            tr.local.append(a)
            continue
        tr.targets.append(r[0])
        tr.remote.append(r)
        if k < len(ops) - 1 and _remote_operand(ops[-1]) is None:
            tr.download = True
    return tr


def _scan_family(base: str, argv: list[str]) -> tuple[list[str], bool]:
    if base == "ssh":
        return _scan_ssh(argv)
    tr = _scan_transfer(base, argv)
    return tr.targets, tr.safe and not tr.subsystem


def _remote_command(base: str, argv: list[str]) -> str:
    """What the remote host runs for an ssh/rsync stage: ssh's remote command
    (as the stand-in parses it), or rsync's --rsync-path (`sudo rsync`); ""
    for scp/sftp and for an ssh line the stand-in refuses anyway."""
    if base == "ssh":
        try:
            # forwards=True: a forwarding option a host may grant (-A, -X, -R, -W)
            # doesn't hide the remote command from these checks
            return ssh_args.parse_ssh(argv[1:], forwards=True).command_text
        except ssh_args.Refused:
            return ""
    if base == "rsync":
        return _scan_transfer(base, argv).remote_cmd
    return ""


def _sudo_in(cmd: str) -> tuple[bool, bool]:
    """(sudo in command position, a sudo word anywhere) in a remote command."""
    if not cmd or not ssh_args.has_sudo_word(cmd):
        return False, False
    return ssh_args.sudo_in_command_position(cmd), True


def _remote_sudo(base: str, argv: list[str]) -> tuple[bool, bool]:
    """(sudo in command position, a sudo word anywhere) in what the remote
    host runs: ssh's command, rsync's --rsync-path, or a remote path of
    scp / rsync, which old rsync and `scp -O` hand to the remote shell
    unquoted (`rsync f "box:/x; sudo id"`). The stand-in refuses the first
    when the host's sudo is off, so the hook denies / asks / withholds allow
    on the remote host's sudo right too."""
    sc, sw = _sudo_in(_remote_command(base, argv))
    if base in ("scp", "rsync", "sftp"):
        for _h, path in _scan_transfer(base, argv).remote:
            c, w = _sudo_in("true " + path)
            sc, sw = sc or c, sw or w
    return sc, sw


# ---------------------------------------------------------------------------
# sudo structure and the destructive list
# ---------------------------------------------------------------------------
#
# The destructive list (SPEC 8 step 5) withholds `allow` from a few
# catastrophic root commands so they reach a human even with localhost sudo
# true. A plugin `allow` skips the auto-mode classifier, so the list must not
# be evadable by the natural ways of writing those commands. Hence
# (verification 2026-10, `sudo timeout 5 rm -rf /` was allowed):
#
# - the list is checked at EVERY word that could be the program a wrapper
#   runs, not just the first (`sudo env rm -rf /`, `sudo nice -n 5 rm …`,
#   `sudo chrt 1 rm …`: wrappers are an open set, so none are enumerated);
# - every word that is itself a command string is split and checked too
#   (`sudo watch 'rm -rf /'`, `sudo script -c 'rm -rf /'`);
# - a sudo'd program that runs a command its words don't show is never
#   vouched for: a shell (`sh -c STRING`, or commands read from a pipe:
#   `echo 'rm -rf /' | sudo bash`), su/runuser/a nested sudo or doas, xargs /
#   parallel (arguments from stdin), at/batch (commands from stdin), `env -S`,
#   and `find -exec/-ok/-delete` (targets substituted by find);
# - `sudo VAR=value CMD` / `sudo env VAR=value CMD` are not vouched for (like a
#   shell assignment prefix, which bashparse refuses: PATH=, LD_PRELOAD=, …);
# - a target counts as dangerous when it is `/`, `~`/`~user`/`$HOME`, a home
#   directory, or any top-level directory (`/usr`, `/Users`, `/private/etc`
#   …), spelled absolutely, relative to the working directory (`cd / && sudo
#   rm -rf usr`), with `//` or `..`, or through a symlink;
# - the list's members in their other spellings: `rm -R`/`--rec`, GNU's
#   g-prefixed tools (`grm`), `init 0|6`, `kill 1`/`kill -9 -1`, macOS's
#   `newfs_*`/`diskutil eraseDisk…`, `shred /dev/…`, `dd of=//dev/…`,
#   `/etc//sudoers`.
#
# These only withhold `allow` (no decision: the classifier or the normal
# prompt decides), so a false positive (`sudo apt install zsh`, `sudo cat
# /bin/sh`) costs a classifier call, never a refusal. It is a guardrail for
# the obvious spellings, not a sandbox: a root script or interpreter
# (`sudo ./x.sh`, `sudo python3 -c …`) can do anything the list names.

_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "yash", "fish",
                     "csh", "tcsh", "rbash", "posh", "oksh", "loksh", "pdksh"})
# Programs whose argument is a command they run, so a stage holding one hides
# how it calls a tool (it can't be vouched for, and under sudo it isn't a
# plain `sudo CMD ARGS`): shells and su, and the job runners, wherever they
# stand as a program word.
_RUNNERS = _SHELLS | frozenset({"su", "runuser", "sudo", "sudoedit", "doas", "pkexec",
                                "xargs", "parallel", "at", "batch"})
# The tracers, sandboxes and wrappers that exec a command (also _TEXT_RUNNER
# below): a runner only as the program itself (the stage's first word, or a
# word by its path), so `sudo apt install tmux` names tmux as data. (macOS's
# `arch -arm64 CMD` isn't one: the hook looks through it like nice.)
_EXEC_RUNNERS = frozenset({"sshpass", "strace", "ltrace", "dtruss", "flock", "script", "unbuffer",
                           "chroot", "tmux", "screen", "ssh-agent", "nsenter", "setarch",
                           "catchsegv", "proot", "fakeroot"})
_FIND_RUN = frozenset({"-exec", "-execdir", "-ok", "-okdir", "-delete"})
_GNU_PREFIXED = {"grm": "rm", "gdd": "dd", "gchmod": "chmod", "gchown": "chown",
                 "gshred": "shred"}
_POWER = frozenset({"shutdown", "reboot", "halt", "poweroff", "passwd", "wipefs"})
# The editors of sudoers and the user/group databases: `visudo` edits
# /etc/sudoers with no path argument (so no word names it), `vipw` /etc/passwd
# (and /etc/shadow with -s), `vigr` /etc/group. Never vouched for, whatever
# their arguments (SPEC 8: "editing /etc/sudoers*").
_PRIV_EDITORS = frozenset({"visudo", "vipw", "vigr"})
_DISKUTIL_ERASE = frozenset({"erasedisk", "erasevolume", "reformat", "zerodisk",
                             "randomdisk", "secureerase", "partitiondisk"})
_STRING_MAX_DEPTH = 3


def _prog_name(word: str) -> str:
    base = os.path.basename(word)
    return _GNU_PREFIXED.get(base, base)


def _names_program(word: str) -> bool:
    """Could this word (past the first) be the program a wrapper runs? A bare
    name, or a path in a bin directory (`/bin/rm`, `…/gnubin/rm`), but not a
    data path like `/etc/passwd`."""
    if not word or word.startswith("-"):
        return False
    if "/" not in word:
        return True
    return os.path.basename(os.path.dirname(word.rstrip("/"))).endswith("bin")


def _has_flag(arg: str, chars: str) -> bool:
    return arg.startswith("-") and not arg.startswith("--") and any(c in arg[1:] for c in chars)


def _recursive_opt(args: list[str], chars: str) -> bool:
    """A recursive short flag (any of `chars`) or `--recursive` or an
    abbreviation getopt accepts (`--rec`, `--r` for rm)."""
    for a in args:
        if a.startswith("--"):
            name = a.split("=", 1)[0]
            if len(name) >= 3 and "--recursive".startswith(name):
                return True
        elif _has_flag(a, chars):
            return True
    return False


def _top_or_home(p: str, homes: set[str]) -> bool:
    if not p.startswith("/"):
        return False
    p = "/" + p.lstrip("/")                 # normpath keeps a leading `//`
    if p == "/" or p.count("/") == 1 or p in homes:
        return True
    parts = p.split("/")
    return len(parts) == 3 and parts[1] == "private"    # macOS /private/etc, /private/var


def _danger_target(a: str, cwds: list[str]) -> bool:
    """`/`, `~`, `~user`, `$HOME`, a home directory or a top-level directory,
    however spelled (relative to the working directories, `//`, `..`,
    symlinks)."""
    if not a or a.startswith("-"):
        return False
    if a in ("~", "$HOME", "${HOME}", "*", "/*"):
        return True
    if a.startswith("~") and "/" not in a.rstrip("/"):
        return True                         # ~ , ~/ , ~user , ~user/
    homes: set[str] = set()
    for h in _home_dirs():
        homes.add(os.path.normpath(h))
        try:
            homes.add(os.path.realpath(h))
        except (OSError, ValueError):
            pass
    for c in _abs_candidates(a, cwds or [os.getcwd()]):
        norm = os.path.normpath(c)
        try:
            real = os.path.realpath(c)
        except (OSError, ValueError):
            real = norm
        if _top_or_home(norm, homes) or _top_or_home(real, homes):
            return True
    return False


def _spellings(a: str, cwds: list[str]) -> list[str]:
    """Normalised absolute spellings of a path word (also of the value in
    `KEY=PATH`): from every working directory, `//` folded, and resolved."""
    vals = [a] + ([a.split("=", 1)[1]] if "=" in a else [])
    out: list[str] = []
    for v in vals:
        if not v:
            continue
        for c in _abs_candidates(v, cwds or [os.getcwd()]):
            out.append("/" + os.path.normpath(c).lstrip("/"))
            try:
                out.append(os.path.realpath(c))
            except (OSError, ValueError):
                pass
    return out


_HARMLESS_DEV = frozenset({"/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty"})


def _is_device(a: str, cwds: list[str]) -> bool:
    """A device node (`dd of=/dev/disk2`), not the null device or a stream."""
    sp = _spellings(a, cwds)
    if any(p in _HARMLESS_DEV or p.startswith("/dev/fd/") for p in sp):
        return False
    return any(p.startswith("/dev/") for p in sp)


def _names_sudoers(a: str, cwds: list[str]) -> bool:
    if "/etc/sudoers" in a:
        return True
    if "sudoers" not in a:
        return False
    return any("/etc/sudoers" in p for p in _spellings(a, cwds))


def _kills_everything(args: list[str]) -> bool:
    """`kill [SIG] 1` (init / launchd: the machine goes down) or `kill … -1`
    (every process). A leading `-SIG` / `-s SIG` / `-n N` is the signal."""
    i = 0
    if i < len(args) and args[i] in ("-s", "-n"):
        i += 2
    elif i < len(args) and args[i].startswith("-") and args[i] != "--":
        i += 1
    ops = [a for a in args[i:] if a != "--"]
    return any(a in ("1", "-1") for a in ops)


def _is_destructive(cmd: list[str], cwds: list[str] | None = None) -> bool:
    """Is CMD (its first word the program) on SPEC 8's destructive list?"""
    cwds = cwds or []
    base = _prog_name(cmd[0]) if cmd else ""
    args = cmd[1:]
    if base in _PRIV_EDITORS:
        return True
    if base in _POWER:
        return True
    if base in ("init", "telinit") and any(a in ("0", "6") for a in args):
        return True                         # halt / reboot
    if base == "kill" and _kills_everything(args):
        return True
    if base in ("killall", "pkill") and any(a in ("launchd", "init", "systemd") for a in args):
        return True
    if base.startswith("mkfs") or base.startswith("newfs"):
        return True
    if base == "diskutil" and any(a.lower() in _DISKUTIL_ERASE for a in args):
        return True
    if base == "rm" and _recursive_opt(args, "rR"):
        if any(_danger_target(a, cwds) for a in args):
            return True
    if base == "dd" and any(a.startswith("of=") and _is_device(a[3:], cwds) for a in args):
        return True
    if base == "shred" and any(not a.startswith("-") and _is_device(a, cwds) for a in args):
        return True
    if base in ("chmod", "chown", "chgrp") and _recursive_opt(args, "R"):
        if any(_danger_target(a, cwds) for a in args):
            return True
    return any(_names_sudoers(a, cwds) for a in args)


def _command_words(word: str) -> list[str] | None:
    """The words of a command string (`'rm -rf /'`, `'cd / && rm -rf *'`), or
    None when it doesn't split."""
    lex = shlex.shlex(word, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    try:
        return list(lex)
    except ValueError:
        return None


def _destructive_anywhere(cmd: list[str], cwds: list[str], depth: int = 0) -> bool:
    """The destructive list at every word that could be the program a wrapper
    runs, and inside every word that is a command string."""
    for j, w in enumerate(cmd):
        if (j == 0 or _names_program(w)) and _is_destructive(cmd[j:], cwds):
            return True
        if any(ch.isspace() or ch in ";&|" for ch in w):
            sub = _command_words(w)
            if sub is None or depth >= _STRING_MAX_DEPTH:
                return True                 # can't tell: don't vouch
            if sub and _destructive_anywhere(sub, cwds, depth + 1):
                return True
    return False


def _env_hides(args: list[str]) -> bool:
    """Does `env ARGS` set variables for its command or split a string into
    one (`-S`/`--split-string`)? Long options are refused outright."""
    i = 0
    while i < len(args):
        a = args[i]
        if _ASSIGN.match(a):
            return True
        if a == "-":
            i += 1
            continue
        if not a.startswith("-"):
            return False
        if a.startswith("--"):
            return True
        body = a[1:]
        if "S" in body:
            return True
        for k, c in enumerate(body):
            if c in "uCP":                  # -u NAME, -C DIR, -P PATH
                if k == len(body) - 1:
                    i += 1                  # the value is the next word
                break
        i += 1
    return False


# macOS's arch (`arch -arm64 CMD`, `arch -arch x86_64 CMD`): its options are
# whole words; these take the next word as their value (-e NAME=VALUE sets a
# variable for the command, -d NAME unsets one).
_ARCH_VALUE = frozenset({"-arch", "-d", "-e"})


def _arch_sets_env(args: list[str]) -> bool:
    """Does `arch ARGS` set a variable for its command (`-e NAME=VALUE`)?"""
    i = 0
    while i < len(args) and args[i].startswith("-") and args[i] not in ("-", "--"):
        if args[i] == "-e":
            return True
        i += 2 if args[i] in _ARCH_VALUE else 1
    return False


def _runs_hidden(cmd: list[str]) -> bool:
    """Does CMD contain a program that runs a command its words don't show
    (a shell, su, xargs, at, `env -S`, `find -exec`, a nested sudo; a tracer
    or sandbox as the program: _EXEC_RUNNERS)?"""
    run = _unwrap(cmd, fork=True)
    if run and _prog_name(run[0]) in _EXEC_RUNNERS:
        return True                         # the program, also behind nice/env/timeout
    for j, w in enumerate(cmd):
        if j and not _names_program(w):
            continue
        name = _prog_name(w)
        if name in _RUNNERS:
            return True
        if name == "env" and _env_hides(cmd[j + 1:]):
            return True
        if name == "arch" and _arch_sets_env(cmd[j + 1:]):
            return True                     # `arch -e VAR=value CMD`, like env's
        if name == "find" and any(a in _FIND_RUN for a in cmd[j + 1:]):
            return True
    return False


def _sudo_structure_ok(argv: list[str], cwds: list[str] | None = None) -> bool:
    """sudo with only -u/-g (value), -H, -n; never -S/-A/-E/long options; and a
    present command, with no unresolved expansion, no assignment, nothing that
    runs a hidden command, and nothing on the destructive list (anywhere)."""
    i, n = 1, len(argv)
    while i < n:
        a = argv[i]
        if a == "--":
            i += 1
            break
        if a == "-" or not a.startswith("-"):
            break
        if a.startswith("--"):
            return False
        body = a[1:]
        k = 0
        while k < len(body):
            c = body[k]
            if c in "Hn":
                k += 1
                continue
            if c in "ug":
                if k + 1 >= len(body):
                    i += 1             # value is the next arg
                break
            return False               # S, A, E, p, ...
        i += 1
    cmd = argv[i:]
    if not cmd:
        return False
    if any("$" in w or "`" in w for w in cmd):
        return False
    if _ASSIGN.match(cmd[0]):
        return False                   # sudo VAR=value CMD
    if _runs_hidden(cmd):
        return False
    if _destructive_anywhere(cmd, list(cwds or [])):
        return False
    return True


# ---------------------------------------------------------------------------
# Wrappers, git's remote programs, commands the parser can't read
# ---------------------------------------------------------------------------

# Wrappers that exec their command in the same process (or are shell
# builtins), so the program they run looks, to the stand-in's ancestry check,
# exactly like one Claude's shell started: the hook looks through them for
# deny and ask. (`command -v X` only looks X up.) Forking wrappers (timeout,
# xargs, sudo) are looked through only for the curl/wget rule: the stand-ins
# see them as an intermediate anyway. macOS's `arch -arm64 CMD` execs its
# command too (its options: _ARCH_VALUE).
_EXEC_WRAPPERS = frozenset({"command", "builtin", "busybox", "env", "nohup", "nice", "stdbuf",
                            "time", "ionice", "chrt", "taskset", "setsid", "arch"})
_FORK_WRAPPERS = frozenset({"timeout", "gtimeout", "xargs", "sudo", "doas", "caffeinate"})
# Shell reserved words bashparse leaves at the start of a stage; the command
# follows them. A loop or case (`for h in a b; do ssh $h x; done`) names its
# targets through variables, so it gets the text scan below.
_RESERVED_PREFIX = frozenset({"if", "then", "else", "elif", "while", "until", "do", "!"})
_LOOP_WORDS = frozenset({"for", "case", "select"})
_WRAPPER_VALUE_OPTS = {"env": "uCPS", "nice": "n", "stdbuf": "ioe", "ionice": "cnp",
                       "timeout": "sk", "gtimeout": "sk", "xargs": "EIJLRSadeiLnPs",
                       "sudo": "ugpChrtTUD", "doas": "uC", "time": "o", "chrt": "",
                       "taskset": "", "caffeinate": "tw"}
_WRAPPER_VALUE_LONG = frozenset({
    "--unset", "--chdir", "--split-string", "--adjustment", "--signal", "--kill-after",
    "--input", "--output", "--error", "--user", "--group", "--prompt", "--close-from",
    "--host", "--chroot", "--other-user", "--role", "--type", "--command-timeout",
    "--max-args", "--max-procs", "--delimiter", "--arg-file", "--max-lines", "--max-chars",
    "--eof", "--class", "--classdata", "--pid", "--cpu-list"})


def _env_split_string(argv: list[str], i: int) -> tuple[str, int] | None:
    """env's `-S STRING` / `--split-string[=]STRING` at argv[i] (also inside a
    cluster, after options without a value: `-iS`; `-uS` is -u's value S):
    (STRING, index after it), else None."""
    a = argv[i]
    nxt = argv[i + 1] if i + 1 < len(argv) else ""
    if a.startswith("--split-string"):
        return (a.split("=", 1)[1], i + 1) if "=" in a else (nxt, i + 2)
    if not a.startswith("-") or a.startswith("--"):
        return None
    body = a[1:]
    for j, c in enumerate(body):
        if c in "uCP":
            return None                    # its value is the rest or the next word
        if c == "S":
            return (body[j + 1:], i + 1) if body[j + 1:] else (nxt, i + 2)
    return None


def _unwrap(argv: list[str], fork: bool = False) -> list[str]:
    """argv from the program the leading wrappers run (`env A=1 nohup ssh h`
    -> `ssh h`; `env -S 'ssh h x'` -> `ssh h x`); [] when nothing runs
    (`command -v curl`, `env` alone)."""
    i, n = 0, len(argv)
    for _ in range(12):
        while i < n and argv[i] in _RESERVED_PREFIX:
            i += 1                         # `if ssh h x; then sudo y; fi`, `do ssh $h x`
        if i >= n:
            return []
        w = os.path.basename(argv[i])
        if w not in _EXEC_WRAPPERS and not (fork and w in _FORK_WRAPPERS):
            break
        vals = _WRAPPER_VALUE_OPTS.get(w, "")
        i += 1
        while i < n:
            a = argv[i]
            if a == "--":
                i += 1
                break
            if w == "command" and a.startswith("-") and any(c in a[1:] for c in "vV"):
                return []
            if w == "env" and _ASSIGN.match(a):
                i += 1
                continue
            if w == "env":
                split = _env_split_string(argv, i)
                if split is not None:          # env -S 'CMD ARGS': the string is the command
                    try:
                        return _unwrap(shlex.split(split[0]) + argv[split[1]:], fork)
                    except ValueError:
                        return ["sh"]
            if w == "arch" and a.startswith("-") and len(a) > 1:
                i += 2 if a in _ARCH_VALUE else 1      # whole-word options (-arm64, -arch x86_64)
                continue
            if a.startswith("-") and len(a) > 1 and not (w == "busybox"):
                if a.startswith("--"):
                    i += 2 if ("=" not in a and a in _WRAPPER_VALUE_LONG) else 1
                    continue
                body = a[1:]
                if w == "nice" and body.lstrip("-").isdigit():
                    i += 1
                    continue
                k = next((j for j, c in enumerate(body) if c in vals), -1)
                i += 2 if k == len(body) - 1 else 1
                continue
            break
        if w == "env":
            while i < n and _ASSIGN.match(argv[i]):
                i += 1                     # `env -- A=1 CMD`: still assignments after --
        if w in ("timeout", "gtimeout") and i < n:
            i += 1                         # the duration
        elif w in ("chrt", "taskset") and i < n:
            i += 1                         # the priority / CPU mask
    return argv[i:] if i < n else []


def _command(stage: list[str], fork: bool = False) -> tuple[list[str], str]:
    """(argv, basename of the program) of a stage, after GATE_ACCOUNT and the
    exec-style wrappers."""
    argv = _unwrap(_strip_gate_account(stage), fork)
    return argv, (os.path.basename(argv[0]) if argv else "")


_GIT_GLOBAL_VALUE = frozenset({"-C", "-c", "--git-dir", "--work-tree", "--namespace",
                               "--super-prefix", "--config-env"})


def _git_subcommand(argv: list[str]) -> str:
    """git's subcommand, past its global options (`git -C d -c k=v credential`)."""
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in _GIT_GLOBAL_VALUE:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        return a
    return ""


_GIT_PROGRAM_OPTS = ("--upload-pack", "--receive-pack", "--exec")
_GIT_PROGRAM_KEYS = re.compile(r"(?i)remote\..*\.(uploadpack|receivepack)\Z")


def _git_remote_programs(argv: list[str]) -> list[str]:
    """The commands a git command line has the remote run in place of
    git-upload-pack / git-receive-pack: --upload-pack, --receive-pack, --exec,
    `clone -u`, and `-c remote.X.uploadpack|receivepack=` (also `--config`)."""
    out: list[str] = []
    sub = _git_subcommand(argv)
    i = 1
    while i < len(argv):
        a = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else ""
        if a in ("-c", "--config") and nxt:
            key, _, val = nxt.partition("=")
            if _GIT_PROGRAM_KEYS.match(key.strip()):
                out.append(val)
            i += 2
            continue
        if a.startswith("--config="):
            key, _, val = a[len("--config="):].partition("=")
            if _GIT_PROGRAM_KEYS.match(key.strip()):
                out.append(val)
        name, eq, val = a.partition("=")
        if name in _GIT_PROGRAM_OPTS:
            if not eq:
                val = nxt
                i += 1
            out.append(val)
        elif a == "-u" and sub in ("clone", "ls-remote"):
            out.append(nxt)
            i += 1
        elif a.startswith("-u") and len(a) > 2 and sub in ("clone", "ls-remote"):
            out.append(a[2:])
        i += 1
    return out


# Words that make a stage run code its words don't show, in Claude's own
# shell or one exec'd in its place (so the stand-ins can't tell it from a
# command Claude typed): a shell, eval, exec, source / `.`.
_HIDDEN_RUNNERS = frozenset({"eval", "exec", "source", "."}) | frozenset(
    {"sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "yash", "fish", "csh", "tcsh"})
_TEXT_SPLIT = re.compile(r"[\s;&|()<>`$={}:@,/\[\]*?!#]+")
_SSH_FAMILY = frozenset({"ssh", "scp", "sftp", "rsync", "git"})
_SUDO_NAMES = frozenset({"sudo", "sudoedit"})
# Words next to which an "ask" host's name in a hidden command is asked about
# for its ssh right: the ssh family, git, and gate (check / rotate / copy-to).
_FB_SSH_WORDS = _SSH_FAMILY | {"gate"}


def _gate_hosts(argv: list[str], form: formmod.Form) -> list[str]:
    """The remote form hosts a `gate check|rotate|copy-to` stage logs in to:
    its operand (any spelling the ssh stand-in accepts), or for `gate check
    all` every remote host whose ssh isn't off."""
    sub = argv[1] if len(argv) > 1 else ""
    if sub not in GATE_SSH_SUBCMDS:
        return []
    ops = [a for a in argv[2:] if not a.startswith("-")]
    if sub == "check" and "all" in ops:
        return [n for n, h in form.hosts.items() if not h.is_local and h.ssh is not False]
    out = []
    for op in ops:
        name = _resolve_host(op, form)
        if name is not None and not form.hosts[name].is_local:
            out.append(name)
    return out


def _fallback_ask(command: str, form: formmod.Form,
                  eff: consent.Effective | None = None) -> tuple[str, str] | None:
    """For a command the parser can't read (or one that runs a shell, eval or
    exec, a loop, or a verb whose target is a variable): an "ask" right it may
    use, as (host, verb). The stand-ins give an "ask" right only to a command
    Claude typed, trusting that Claude Code asked; this keeps that true when
    the command hides how it calls them: a host with an "ask" right named in
    its text (quotes removed) with an ssh-family or git word (or, for sudo =
    "ask", a sudo word), or localhost sudo = "ask" with a sudo word. Text it
    can't see (a script sourced into Claude's shell, a name computed at run
    time) isn't covered: a guardrail, like the prefilter. The right is the
    stricter of the form's and the effective one (_right), so an approved
    "ask" whose widening to true still waits counts as "ask"."""
    text = _QUOTES.sub("", command)
    words = [w for w in _TEXT_SPLIT.split(text) if w]
    low = {w.lower() for w in words}

    def asks(name: str, verb: str) -> bool:
        if eff is None:
            return _form_right(form, name, verb) == "ask"
        return _right(form, eff, name, verb) == "ask"
    if low & _SUDO_NAMES and "localhost" in form.hosts and asks("localhost", "sudo"):
        return "localhost", "sudo"
    for name, h in form.hosts.items():
        if h.is_local:
            continue
        for verb in ("ssh", "sudo"):
            if not asks(name, verb) or not low & (_FB_SSH_WORDS if verb == "ssh"
                                                  else _SUDO_NAMES):
                continue
            names = {name, f"gw-{name}"} | {a.host.lower() for a in h.addresses()}
            if low & names:
                return name, verb
    return None


# ---------------------------------------------------------------------------
# Rights (the stricter of form and effective for deny/ask, effective for
# allow) and host resolution
# ---------------------------------------------------------------------------


def _form_right(form: formmod.Form, host: str, verb: str) -> Any:
    h = form.hosts.get(host)
    return getattr(h, verb) if h is not None else None


def _eff_right(eff: consent.Effective, host: str, verb: str) -> Any:
    h = eff.hosts.get(host)
    return getattr(h, verb) if h is not None else False


WAIT = "wait"


def _right(form: formmod.Form, eff: consent.Effective, host: str, verb: str) -> Any:
    """The right deny and ask go by: the stricter of the form's and the
    effective one (round 3). The stand-ins use the effective right and give
    an "ask" right to a command Claude typed, trusting that this hook asked:
    with `ssh = "ask"` approved and the form edited to `true` (the change
    waits for the user's OK), the effective right is still "ask", so the hook
    must ask too. None: not a form host. False: off in the form. WAIT: the
    form allows more than the user approved and the effective right is off
    (a widening waiting, a brand-new host, a jump host not set up). "ask"
    when either is "ask"; True only when both are true."""
    f = _form_right(form, host, verb)
    if f is None:
        return None
    if f is False:
        return False
    e = _eff_right(eff, host, verb)
    if e is False:
        return WAIT
    if e == "ask" or f == "ask":
        return "ask"
    return True


def _deny_wait(name: str, verb: str, form: formmod.Form, eff: consent.Effective
               ) -> dict[str, Any]:
    """A right the form gives but the user hasn't approved yet: the stand-in
    would refuse it, so say what to do before anything runs."""
    if _LOCKED.get("message"):
        return _deny(_LOCKED["message"], tool=verb, target=name)
    what = "sudo on this machine" if (name == "localhost" and verb == "sudo") else f"{verb} on {name}"
    h = form.hosts.get(name)
    via = h.via if h is not None else None
    if via and verb == "ssh" and _eff_right(eff, via, "ssh") is False:
        r = (f"gateway: {what} waits for the user's OK (it goes through {via}, which isn't set "
             f"up yet); run gate check {via}, then gate check {name}, while the user is here.")
    else:
        r = f"gateway: {what} waits for the user's OK; run gate check {name} while the user is here."
    return _deny(r, tool=verb, target=name, fix=f"gate check {name}")


def _resolve_host(target: str, form: formmod.Form) -> str | None:
    """The form host a destination word names, the way the ssh stand-in maps
    it (ssh._classify): by name in any case, `gw-NAME` (the generated alias),
    or by address (with the user, if given, matching)."""
    if not target:
        return None
    if target in form.hosts:
        return target
    user = None
    host = target
    if "@" in target:
        user, host = target.rsplit("@", 1)
    if host.count(":") == 1 and not host.startswith("["):
        host = host.rsplit(":", 1)[0]
    host = host.strip("[]").lower()
    if host.startswith("gw-") and host not in form.hosts and host[3:] in form.hosts:
        host = host[3:]
    if host in form.hosts and form.hosts[host].explicit and not form.hosts[host].is_local:
        return host
    lo = host.lower()
    for name, h in form.hosts.items():
        if h.is_local:
            continue
        for addr in h.addresses():
            if addr.host.lower() == lo and (user is None or addr.effective_user() == user):
                return name
    return None


# ---------------------------------------------------------------------------
# Deny scans
# ---------------------------------------------------------------------------


def _flag_values(a: str) -> list[str]:
    """Paths an option word can carry: `--file=PATH`, `-fPATH`."""
    out: list[str] = []
    if "=" in a:
        out.append(a.split("=", 1)[1])
    if not a.startswith("--") and len(a) > 2:
        out.append(a[2:])
    return [v for v in out if v]


# A tilde prefix that names the shell's previous working directory (`~-`,
# OLDPWD) or an entry of its directory stack (`~N`, `~+N`, `~-N`): a folder the
# hook can't know.
_TILDE_STACK = re.compile(r"(?:[+-]?[0-9]+|-)\Z")


def _tilde_user(name: str) -> list[str] | None:
    """The home folder `~NAME` expands to (the password database); None for
    no such user, whose word the shell leaves as written. Under a test
    override a user that exists is the test's home: a test never resolves a
    real home folder."""
    try:
        import pwd
        d = pwd.getpwnam(name).pw_dir
    except (KeyError, ValueError, TypeError, OSError, ImportError):
        return None
    if testing.active() is not None:
        return _home_dirs()
    return [d] if os.path.isabs(d) else []


def _tilde(word: str, cwds: list[str], homes: list[str]) -> list[str] | None:
    """The spellings of a word that starts with `~`, as bash and zsh expand
    it: `~` and `~/x` in the home folders, `~+/x` ($PWD) in the working
    directories, `~NAME/x` in that user's home, and an unknown user's word as
    written (a relative path) from the working directories. None when the
    folder can't be known: `~-`, `~N`, `~+N`, `~-N` (_TILDE_STACK), or no home
    folder known for it."""
    prefix, slash, rest = word[1:].partition("/")
    tail = slash + rest
    if prefix == "":
        dirs = homes
    elif prefix == "+":
        dirs = cwds
    elif _TILDE_STACK.match(prefix):
        return None
    else:
        known = _tilde_user(prefix)
        if known is None:
            return [os.path.join(c, word) for c in cwds]
        dirs = known
    if not dirs:
        return None
    return [d + tail for d in dirs]


def _tilde_unknown(word: str) -> bool:
    """Does the word start with a tilde whose folder the hook can't know
    (`~-/x`, `~1/x`, ...; _tilde)?"""
    return word.startswith("~") and _tilde(word, ["/"], _home_dirs()) is None


def _abs_candidates(token: str, cwds: list[str]) -> list[str]:
    """Absolute spellings of a token: `~`, `~+`, `~user` and `$HOME`/`${HOME}`
    expanded (_tilde), relative ones taken from every candidate working
    directory. Only absolute paths, and none for a tilde whose folder can't
    be known (_tilde_unknown: callers refuse those)."""
    homes = _home_dirs()
    variants = [token]
    if "$HOME" in token or "${HOME}" in token:
        variants = [token.replace("${HOME}", h).replace("$HOME", h) for h in homes]
    out: list[str] = []
    for t in variants:
        if t.startswith("~"):
            out += _tilde(t, cwds, homes) or []
        elif os.path.isabs(t):
            out.append(t)
        else:
            out += [os.path.join(c, t) for c in cwds]
    return [p for p in dict.fromkeys(out) if os.path.isabs(p)]


def _chdir_abs(v: str, cwds: list[str]) -> list[str]:
    """The chdir target `v` resolved to absolute spellings; [] when it can't be
    known (`$X`, `~-`), so the caller refuses rather than guessing a cwd."""
    bare = v.replace("${HOME}", "").replace("$HOME", "")
    if not v or "$" in bare or _tilde_unknown(v):
        return []
    return _abs_candidates(v, cwds)


def _wrapper_chdir(words: list[str], cwds: list[str]) -> list[str] | None:
    """The directories a leading `env -C/--chdir DIR` or `sudo -D/--chdir DIR`
    makes the command run in (resolved, absolute), or None. Only the wrapper
    chain is read (env, sudo/doas, nice, nohup, ...), not the command, and an
    unknown target (`$X`, `~-`) gives []. A per-command chdir, not a cd that
    outlives the stage."""
    i, n = 0, len(words)
    for _ in range(12):
        while i < n and words[i] in _RESERVED_PREFIX:
            i += 1
        if i >= n:
            return None
        w = os.path.basename(words[i])
        letter = {"env": "C", "sudo": "D", "sudoedit": "D", "doas": None}.get(w)
        if w not in _EXEC_WRAPPERS and w not in _FORK_WRAPPERS:
            return None
        vals = _WRAPPER_VALUE_OPTS.get(w, "")
        i += 1
        while i < n:
            a = words[i]
            if a == "--":
                i += 1
                break
            if w == "env" and _ASSIGN.match(a):
                i += 1
                continue
            if not a.startswith("-") or a == "-":
                break                      # the command (or env's next wrapper)
            if w == "arch":
                i += 2 if a in _ARCH_VALUE else 1
                continue
            if a.startswith("--"):
                if a.startswith("--chdir") and letter:
                    v = a.split("=", 1)[1] if "=" in a else (words[i + 1] if i + 1 < n else "")
                    return _chdir_abs(v, cwds)
                i += 2 if ("=" not in a and a in _WRAPPER_VALUE_LONG) else 1
                continue
            body = a[1:]
            for k, c in enumerate(body):
                if letter and c == letter:
                    v = body[k + 1:] or (words[i + 1] if i + 1 < n else "")
                    return _chdir_abs(v, cwds)
                if c in vals:
                    if k == len(body) - 1:
                        i += 1
                    break
            i += 1
        if w in ("timeout", "gtimeout", "chrt", "taskset") and i < n:
            i += 1
    return None


def _cd_targets(argv: list[str], cwds: list[str]) -> list[str] | None:
    """The working directories after `cd`/`pushd ARGV` (as candidates), or
    None when the target can't be known (`cd -`, `popd`, `$X`, `pushd +N`)."""
    base = os.path.basename(argv[0])
    args = argv[1:]
    if base == "popd" or "-" in args:
        return None
    ops = [a for a in args if not a.startswith("-")]
    if base == "pushd" and (not ops or ops[0][:1] in "+-"):
        return None
    if not ops:
        return _home_dirs() or None
    tgt = ops[0]
    if "$" in tgt.replace("${HOME}", "").replace("$HOME", "") or _tilde_unknown(tgt):
        return None
    out = _abs_candidates(tgt, cwds)
    if not out:
        return None
    cdpath = os.environ.get("CDPATH", "") if testing.active() is None else ""
    if cdpath and not tgt.startswith(("/", "~", "./", "../")) and tgt not in (".", ".."):
        out += [os.path.join(d or ".", tgt) for d in cdpath.split(":")]
    # Both spellings: `cd` is logical by default (normpath), `cd -P` physical
    # (left to Protected's resolve()).
    return list(dict.fromkeys(out + [os.path.normpath(p) for p in out]))


def _fold(s: str) -> str:
    return unicodedata.normalize("NFC", s).casefold()


def _resolve_glob_prefix(pat: str) -> str:
    """Resolve symlinks in the part of an absolute glob before its first
    wildcard (so it compares with the resolved protected entries)."""
    parts = pat.split("/")
    k = next((i for i, p in enumerate(parts) if _GLOB_CHARS.search(p)), len(parts))
    prefix = "/".join(parts[:k]) or "/"
    try:
        prefix = os.path.realpath(prefix)
    except (OSError, ValueError):
        pass
    rest = "/".join(parts[k:])
    return prefix.rstrip("/") + ("/" + rest if rest else "")


def _glob_hits(prot: paths.Protected, token: str, cwds: list[str], parent: bool) -> bool:
    """Would the shell's expansion of this glob name a protected path (or,
    with `parent`, a folder holding one)? Checks real matches and, component
    by component and ignoring case, the protected entries themselves."""
    for pat in _abs_candidates(token, cwds):
        try:
            for m in itertools.islice(globmod.iglob(pat), GLOB_MAX):
                if prot.contains(m) or (parent and prot.is_parent(m)):
                    return True
        except (OSError, ValueError, RuntimeError):
            return True
        pparts = _fold(_resolve_glob_prefix(pat)).split("/")
        for e in prot.entries + [_fold(str(q)) for q in prot.paths]:
            eparts = e.split("/")
            if parent and len(eparts) > len(pparts):
                eparts = eparts[:len(pparts)]
            if len(eparts) == len(pparts) and all(
                    fnmatch.fnmatchcase(a, b) for a, b in zip(eparts, pparts)):
                return True
    return False


_GREP = frozenset({"grep", "egrep", "fgrep", "ggrep", "zgrep"})
_RECURSIVE_ALWAYS = frozenset({"rsync", "tar", "gtar", "bsdtar", "zip", "ditto", "pax", "cpio",
                               "rgrep", "rg", "ag", "ack"})


def _grep_dirs_recurse(val: str) -> bool:
    """grep's -d / --directories ACTION recurses unless it is read or skip
    (BSD grep takes the word in any letter case; GNU an abbreviation)."""
    return val.lower() not in ("read", "skip")


def _grep_recursive(argv: list[str]) -> bool:
    """Does grep read whole folder trees: -r / -R anywhere in a cluster, any
    abbreviation getopt accepts of --recursive or --dereference-recursive (3+
    letters), and -d / --directories (or an abbreviation: `--dir`, `--di`)
    with an action other than read or skip, glued, in a cluster (`-id
    recurse`, `-nd recurse`) or in the next word?"""
    i, n = 1, len(argv)
    while i < n:
        a = argv[i]
        i += 1
        if a == "--":
            break
        if a.startswith("--"):
            name, eq, val = a[2:].partition("=")
            if len(name) >= 3 and ("recursive".startswith(name)
                                   or "dereference-recursive".startswith(name)):
                return True
            if len(name) >= 2 and "directories".startswith(name):
                if not eq:
                    val, i = (argv[i] if i < n else ""), i + 1
                if _grep_dirs_recurse(val):
                    return True
            continue
        if a.startswith("-") and a != "-":
            body = a[1:]
            for k, c in enumerate(body):
                if c in "rR":
                    return True
                if c in _GREP_VALUE_SHORT:
                    val = body[k + 1:]
                    if not val:
                        val, i = (argv[i] if i < n else ""), i + 1
                    if c == "d" and _grep_dirs_recurse(val):
                        return True
                    break                # the rest of the word (or the next) is the value
    return False


# grep's long options that take a value in the next word when not glued (GNU;
# --context's is optional in BSD grep, so it isn't counted)
_GREP_LONG_NEXT = frozenset({"regexp", "file", "max-count", "after-context", "before-context",
                             "label", "binary-files", "devices", "directories", "exclude",
                             "exclude-from", "exclude-dir", "include", "group-separator"})


def _grep_files(argv: list[str]) -> tuple[list[str], bool]:
    """grep's file operands (option values and the pattern left out) and
    whether they could be told apart (False: a long option that may take the
    next word)."""
    ops: list[str] = []
    given, sure = False, True
    i, n = 1, len(argv)
    while i < n:
        a = argv[i]
        i += 1
        if a == "--":
            ops += argv[i:]
            break
        if a == "-" or not a.startswith("-"):
            ops.append(a)
            continue
        if a.startswith("--"):
            name, eq, _v = a[2:].partition("=")
            if len(name) >= 3 and ("regexp".startswith(name) or "file".startswith(name)):
                given = True
            if not eq and name in _GREP_LONG_NEXT:
                i += 1
            elif not eq and name not in _GREP_LONG_FLAGS:
                sure = False
            continue
        body = a[1:]
        for k, c in enumerate(body):
            if c in _GREP_VALUE_SHORT:
                given = given or c in "ef"
                if not body[k + 1:]:
                    i += 1
                break
    if not given and ops:
        ops = ops[1:]
    return ops, sure


def _recursive(base: str, argv: list[str]) -> bool:
    """Does this command read whole folder trees (so naming a parent of the
    private folder reads it)?"""
    if base in _RECURSIVE_ALWAYS:
        return True
    flags = [a for a in argv[1:] if a.startswith("-") and a != "-"]
    longs = [a.split("=", 1)[0] for a in flags if a.startswith("--")]
    shorts = "".join(a[1:] for a in flags if not a.startswith("--"))
    if base in _GREP:
        return "r" in shorts or "R" in shorts or _grep_recursive(argv)
    if base in ("cp", "gcp", "scp", "sftp"):
        return ("r" in shorts or "R" in shorts or (base in ("cp", "gcp") and "a" in shorts)
                or "--recursive" in longs or "--archive" in longs)
    return False


def _deny_sensitive(stages: list[list[str]], cwd: str | None,
                    transcript_path: str | None = None, more_cwds: tuple[str, ...] = ()
                    ) -> tuple[dict[str, Any] | None, bool, list[list[str]]]:
    """(deny decision or None, cwd_known, stage_cwds). Scans every word, option
    value and redirect target of every stage against the protected paths,
    resolving relative ones from the working directory as `cd`s in the command
    change it. cwd_known is False when a `cd` target can't be known (then
    nothing that follows can be vouched for). stage_cwds[k] are the candidate
    working directories stage k runs in (for the destructive list).
    more_cwds: other places the command may start in (a checkpoint job's
    folder candidates); a word that is protected from any of them denies."""
    stage_cwds: list[list[str]] = []
    try:
        prot = paths.Protected()
    except Exception:  # noqa: BLE001
        return None, False, stage_cwds
    try:
        roots = paths.transcript_roots(transcript_path)
    except Exception:  # noqa: BLE001
        roots = []
    base_cwd = cwd if cwd and os.path.isabs(cwd) else os.getcwd()
    cwds = list(dict.fromkeys([base_cwd, *(c for c in more_cwds if c and os.path.isabs(c))]))
    cwd_known = True

    def transcript(tok: str, tree: bool, globbed: bool = False) -> bool:
        cands = _abs_candidates(tok, cwds)
        check = paths.holds_transcripts if tree else paths.is_transcript
        if any(check(c, None, roots) for c in cands):
            return True
        if globbed:
            try:
                for pat in cands:
                    for m in itertools.islice(globmod.iglob(pat), GLOB_MAX):
                        if check(m, None, roots):
                            return True
            except (OSError, ValueError, RuntimeError):
                return True
        return False

    def hit(tok: str, globbed: bool) -> bool:
        if any(_prot_hit(prot, c) for c in _abs_candidates(tok, cwds)):
            return True
        return globbed and _glob_hits(prot, tok, cwds, parent=False)

    def tree_hit(tok: str, globbed: bool) -> bool:
        if globbed:
            return _glob_hits(prot, tok, cwds, parent=True)
        return any(_prot_parent(prot, c) for c in _abs_candidates(tok, cwds))

    for st in stages:
        argv, exp, glb = _argv_meta(st)
        if not argv:
            stage_cwds.append(list(cwds))
            continue
        base = os.path.basename(argv[0])
        # A wrapper that changes directory (env -C/--chdir, sudo -D) runs this
        # stage's command there: resolve its paths (and the destructive list)
        # from that folder too, so `env -C ~/.config/gateway cat private/x` is
        # denied and `sudo env -C / rm -rf usr` reaches / (SF1).
        chd = _wrapper_chdir(argv, cwds)
        saved_cwds = cwds
        stage_cwds.append(list(dict.fromkeys(cwds + (chd or []))))
        if chd:
            cwds = list(dict.fromkeys(chd))
        uargv, ubase = _command(st)            # behind env / nohup / command ...
        if ubase == "git" and _git_subcommand(uargv) == "credential":
            return _deny("gateway: don't run `git credential` directly; let git call the "
                         "gateway's helper by itself.", tool="git",
                         target="credential"), cwd_known, stage_cwds
        if ubase.startswith("git-credential") or ubase == "gate-askpass":
            return _deny("gateway: that's an internal gateway helper; Claude never runs it "
                         "directly.", tool=ubase), cwd_known, stage_cwds
        is_age = base == "age" and ("-d" in argv or "--decrypt" in argv)
        tool, target = ("age", "vault") if is_age else (base, None)
        # Every word (a bare name is a file in cwd too), option values, and
        # redirect targets (a write into the private folder destroys it).
        toks: list[tuple[str, bool]] = []
        operands: list[tuple[str, bool]] = []
        for i, a in enumerate(argv):
            if i == 0 and "/" not in a:
                continue                         # a command name, looked up on PATH
            if a.startswith("-") and a != "-":
                toks += [(v, bool(_GLOB_CHARS.search(v))) for v in _flag_values(a)]
            else:
                toks.append((a, glb[i]))
                if i:
                    operands.append((a, glb[i]))
            if exp[i] and "${" in a:
                # `${X:-PATH}` and friends: the shell may use the literal default.
                toks += [(v, bool(_GLOB_CHARS.search(v))) for v in _param_defaults(a)]
        toks += [(t, False) for _, t in getattr(st, "redirects", []) if t]
        if base == "ls" and not operands:
            toks.append((".", False))
        for tok, g in toks:
            if _tilde_unknown(tok):
                # `~-/x`, `~1/x`: a folder the hook can't know may be the private one
                return _deny(DENY_TILDE, tool=tool, target="~"), cwd_known, stage_cwds
            if hit(tok, g):
                return _deny(DENY_PRIVATE, tool=tool, target=target), cwd_known, stage_cwds
            if transcript(tok, False, g):
                return _deny(DENY_TRANSCRIPT, tool=base, target="transcript"), cwd_known, \
                    stage_cwds
        if _recursive(base, argv):
            if base in _GREP:
                files, sure = _grep_files(argv)
                if not files or (not sure and len(files) <= 1):
                    operands.append((".", False))    # searches the working directory
            elif len(operands) <= 1 and base in ("rg", "ag", "ack", "rgrep"):
                operands.append((".", False))
            for tok, g in operands:
                if tree_hit(tok, g):
                    return _deny(DENY_PRIVATE_TREE, tool=base), cwd_known, stage_cwds
                if transcript(tok, True, g):
                    return _deny(DENY_TRANSCRIPT, tool=base, target="transcripts"), cwd_known, \
                        stage_cwds
        cwds = saved_cwds                      # env -C is a per-command chdir, not a cd
        if base in ("cd", "pushd", "popd"):
            nxt = _cd_targets(argv, cwds)
            if nxt is None:
                cwd_known = False
            else:
                cwds = list(dict.fromkeys(cwds + nxt))
    return None, cwd_known, stage_cwds


_PARAM_OP = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:?[-=+?]|\}")


def _param_defaults(word: str) -> list[str]:
    """Literal spellings a word with `${NAME:-WORD}` (`-`, `=`, `+`, `?`, with
    or without `:`) can expand to when the default is used: each piece and the
    word with the operators removed. Defence in depth only."""
    pieces = [p for p in _PARAM_OP.split(word) if p]
    joined = "".join(pieces)
    return list(dict.fromkeys(pieces + ([joined] if joined else [])))


def _prot_hit(prot: paths.Protected, path: str) -> bool:
    try:
        return prot.contains(path)
    except Exception:  # noqa: BLE001
        return True


def _prot_parent(prot: paths.Protected, path: str) -> bool:
    try:
        return prot.is_parent(path)
    except Exception:  # noqa: BLE001
        return True


# ---------------------------------------------------------------------------
# Allow
# ---------------------------------------------------------------------------


def _sort_ok(argv: list[str]) -> bool:
    """sort without -o/--output (a write) or --compress-program (runs a
    program). Long options can be abbreviated, so none are accepted."""
    for a in argv[1:]:
        if a == "--":
            break
        if a.startswith("--"):
            return False
        if a.startswith("-") and "o" in a[1:]:
            return False
    return True


def _uniq_ok(argv: list[str]) -> bool:
    """uniq with at most one operand (a second operand is an output file)."""
    ops = 0
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in ("-f", "-s", "-w"):
            i += 2
            continue
        if not a.startswith("-") or a == "-":
            ops += 1
        i += 1
    return ops <= 1


def _grep_follows_links(argv: list[str]) -> bool:
    """grep -R / --dereference-recursive (GNU) and -S (BSD grep, macOS's
    /usr/bin/grep: every link followed while recursing) follow symlinks met
    while recursing, which the path checks can't see (a link planted in a
    project could point into private/), so they are never vouched for; -r
    doesn't follow them. A short option's value (`-e`, `-f`, ...) ends its
    cluster."""
    for a in argv[1:]:
        if a == "--":
            break
        if a.startswith("--"):
            if a.split("=", 1)[0] in ("--dereference-recursive", "--dereference"):
                return True
        elif a.startswith("-"):
            for c in a[1:]:
                if c in "RS":
                    return True
                if c in _GREP_VALUE_SHORT:
                    break                # the rest of the word is that option's value
    return False


def _transfer_paths_ok(tr: Transfer, cwds: list[str] | None) -> bool:
    """scp / sftp / rsync paths for allow. Every remote path is plain (no shell
    metacharacter, space or glob: old rsync and `scp -O` hand it to the remote
    shell unquoted). A download names what it copies: not a folder's contents
    (a trailing `/`, `.`, or no path: the remote home), and nothing hidden
    anywhere in the remote path (`-R` recreates the whole path here). Every
    local operand lies inside the project, ~/Downloads or a temp folder, by
    the download tool's rules (web.plain_local_path: no hidden part, nothing
    in ~/.ssh, ~/.config, ~/.claude, the Claude config folder, ~/Library or
    the gateway's folders, no file Python runs at startup)."""
    for _h, path in tr.remote:
        if not _REMOTE_PATH_OK.match(path):
            return False
        if tr.download:
            parts = [p for p in path.split("/") if p]
            if (not parts or path.endswith("/") or any(p.startswith(".") for p in parts)
                    or (len(parts) == 1 and parts[0].startswith("~"))):
                return False
    from . import web
    for p in tr.local:
        for c in (cwds or [os.getcwd()]):
            if not web.plain_local_path(p, c):
                return False
    return True


def _date_ok(argv: list[str]) -> bool:
    """date that only prints: `+FORMAT` operands and display options. Never
    `-s`/`--set` (GNU: set the clock), `-f`/`--file` (GNU: read dates from a
    file), or another operand (BSD/macOS `date 202001010000` sets the
    clock). Long options are matched exactly (no abbreviations)."""
    i, n = 1, len(argv)
    while i < n:
        a = argv[i]
        if a.startswith("+"):
            i += 1
            continue
        if a.startswith("--"):
            name, eq, _v = a[2:].partition("=")
            if name in ("date", "reference") and not eq:
                i += 2                   # --date STRING / --reference FILE
                continue
            if not (name in ("utc", "universal", "rfc-2822", "rfc-email", "date", "reference")
                    or name.startswith(("iso-8601", "rfc-3339"))):
                return False
            i += 1
            continue
        if not a.startswith("-") or a == "-":
            return False                 # an operand that sets the clock (BSD/macOS)
        body = a[1:]
        for k, c in enumerate(body):
            if c in "drvz":              # -d STRING, -r FILE|SECONDS, -v ADJ, -z TZ: values
                if k == len(body) - 1:
                    i += 1               # the value is the next word
                break
            if c == "I":
                break                    # GNU -I[FMT]: the rest is its value
            if c not in "ujRn":
                return False             # -s (set), -f (file), anything unknown
        i += 1
    return True


# grep's options whose value is the rest of the word or the next one
_GREP_VALUE_SHORT = frozenset("efmABCdD")
# grep's long options that take no value, spelled out: any other long option
# may take the next word, so the pattern can't be told from a file then
_GREP_LONG_FLAGS = frozenset({
    "extended-regexp", "fixed-strings", "basic-regexp", "perl-regexp", "ignore-case",
    "no-ignore-case", "word-regexp", "line-regexp", "null-data", "no-messages", "invert-match",
    "version", "help", "byte-offset", "line-number", "line-buffered", "with-filename",
    "no-filename", "only-matching", "quiet", "silent", "recursive", "files-without-match",
    "files-with-matches", "count", "initial-tab", "null", "text", "binary", "unix-byte-offsets",
    "color", "colour", "no-group-separator"})
# the long options a vouched-for grep may carry, spelled out (getopt also takes
# any unique abbreviation, which can hide --recursive, --dereference-recursive
# or --directories=recurse): the flags above and those with a value
_GREP_LONG_OK = _GREP_LONG_FLAGS | _GREP_LONG_NEXT | frozenset({"context"})


def _grep_longs_known(argv: list[str]) -> bool:
    """Is every long option of this grep one of _GREP_LONG_OK, spelled out?"""
    for a in argv[1:]:
        if a == "--":
            break
        if a.startswith("--") and a[2:].split("=", 1)[0] not in _GREP_LONG_OK:
            return False
    return True
READ_ALLOW = ("gateway: allowed (plain commands that change nothing; any file they read is in "
              "the project or a temp folder).")


def _read_operands(base: str, argv: list[str]) -> list[str] | None:
    """The words a benign reader may read as a file or a folder (GW-UX-1):
    its operands and every option's value (a count or a name lands in the
    working directory, where it passes). grep's pattern is left out only
    when it can be told apart: no -e/-f/--regexp/--file, and no long option
    that may take the next word as its value. None: `wc --files0-from`,
    which reads file names from a file."""
    out: list[str] = []
    ops: list[str] = []
    grep = base in _GREP
    given, sure = False, True        # grep: a pattern from -e/-f; the first operand surely the pattern
    i, n = 1, len(argv)
    while i < n:
        a = argv[i]
        i += 1
        if a == "--":
            ops += argv[i:]
            break
        if a == "-" or not a.startswith("-"):
            ops.append(a)
            continue
        if a.startswith("--"):
            name, eq, val = a[2:].partition("=")
            if base == "wc" and name.startswith("f"):
                return None
            # a vouched grep's long options are all known, full spellings
            # (_grep_longs_known refuses any abbreviation, which could be
            # --recursive), so only the exact names reach here
            if grep and name in ("regexp", "file"):
                given = True
                if not eq:
                    val, i = (argv[i] if i < n else ""), i + 1
                if name == "file":
                    out.append(val)      # patterns read from a file
            elif eq:
                out.append(val)
            elif grep and name not in _GREP_LONG_FLAGS:
                sure = False             # it may take the next word as its value
            continue
        if not grep:
            out += _flag_values(a)
            continue
        body = a[1:]
        for k, c in enumerate(body):
            if c in _GREP_VALUE_SHORT:
                val = body[k + 1:]
                if not val:
                    val, i = (argv[i] if i < n else ""), i + 1
                if c == "e":
                    given = True         # a pattern
                else:
                    given = given or c == "f"
                    out.append(val)      # -f FILE (a count or an action passes as a name)
                break
    if grep and not given and sure and ops:
        ops = ops[1:]                    # the pattern
    return out + ops


def _inside(p: str, root: str, fold: bool = False) -> bool:
    """Is `p` the folder `root` or below it (with `fold`, ignoring letter case
    and Unicode normalization, as macOS's file systems do)?"""
    if fold:
        p, root = _fold(p), _fold(root)
    return p == root or p.startswith(root.rstrip("/") + "/")


def _read_roots(cwd: str | None) -> tuple[list[str], list[str], str, list[str]]:
    """(project roots, temp roots, home, credential folders), resolved, for
    _reads_plain. The project is CLAUDE_PROJECT_DIR, else the working
    directory; the temp folders are the scp rule's (TMPDIR, /tmp, /var/tmp).
    / doesn't count, nor a project that is the home folder or above it, nor
    a temp folder in the home. The credential folders: the user's (_CRED_DIRS),
    the Claude config folder and the gateway's home."""
    home = os.path.realpath(str(paths.user_home()))
    creds = [os.path.realpath(os.path.join(home, d)) for d in _CRED_DIRS]
    for extra in (os.environ.get("CLAUDE_CONFIG_DIR", ""), str(paths.home())):
        if extra and os.path.isabs(extra):
            creds.append(os.path.realpath(extra))

    def ok(r: str) -> str | None:
        try:
            rr = os.path.realpath(r)
        except (OSError, ValueError):
            return None
        return rr if rr != "/" else None

    proj = os.environ.get("CLAUDE_PROJECT_DIR") or ""
    if not os.path.isabs(proj):
        proj = cwd if cwd and os.path.isabs(cwd) else os.getcwd()
    projects = [r for r in [ok(proj)] if r and not _inside(home, r, fold=True)]
    temps = testing.get("download_temp_roots")
    if temps is None:
        import tempfile
        temps = [tempfile.gettempdir(), "/tmp", "/var/tmp"]
    roots = [ok(t) for t in temps if isinstance(t, str) and os.path.isabs(t)]
    return projects, [r for r in roots if r and not _inside(r, home, fold=True)], home, creds


def _plain_read_path(p: str, roots: tuple[list[str], list[str], str, list[str]]) -> bool:
    """Is the absolute path `p` a plain file of the project or a temp folder:
    resolved, not in a credential folder (a project in one included; letter
    case ignored), inside one of them (a temp folder's never in the home
    folder; letter case ignored on macOS), with no hidden or credential-like
    name below it? A Claude Code worktree of the project
    (`.claude/worktrees/NAME/...`) counts as the project when the rest of the
    path is plain (NAME included)."""
    projects, temps, home, creds = roots
    try:
        real = os.path.realpath(os.path.normpath(p))
    except (OSError, ValueError):
        return False
    if any(_inside(real, c, fold=True) for c in creds):
        return False
    for r in projects + [t for t in temps if not _inside(real, home, fold=True)]:
        if _inside(real, r, fold=_CASELESS):
            tail = _fold(real)[len(_fold(r)):] if _CASELESS else real[len(r):]
            parts = [x for x in tail.split("/") if x]
            if r in projects and len(parts) >= 3 and parts[:2] == [".claude", "worktrees"]:
                parts = parts[2:]        # a worktree of the project: its name and the rest
            return not any(x.startswith(".") or _CRED_NAME.match(x) for x in parts)
    return False


def _tree_plain(top: str, roots: tuple[list[str], list[str], str, list[str]]) -> bool:
    """Does the folder hold nothing hidden or credential-like anywhere below
    it (a recursive grep reads it all), in at most READ_TREE_MAX entries?
    Links aren't followed (grep -r doesn't; -R and BSD's -S, which do, are
    never vouched for), but each must point at a plain file of the project or
    a temp folder all the same (_plain_read_path: not out of them, not at a
    hidden or credential-like name)."""
    seen, todo = 0, [top]
    while todo:
        try:
            with os.scandir(todo.pop()) as it:
                for e in it:
                    seen += 1
                    if seen > READ_TREE_MAX or e.name.startswith(".") or _CRED_NAME.match(e.name):
                        return False
                    if e.is_symlink():
                        if not _plain_read_path(e.path, roots):
                            return False
                    elif e.is_dir(follow_symlinks=False):
                        todo.append(e.path)
        except OSError:
            return False
    return True


def _reads_plain(base: str, argv: list[str], cwds: list[str],
                 roots: tuple[list[str], list[str], str, list[str]]) -> bool:
    """Is everything a benign reader may read a plain file of the project or a
    temp folder (GW-UX-1)? With no path operand it reads the working
    directory (or stdin): that must be in the project or a temp folder. A
    recursive grep also reads every operand's whole tree."""
    words = _read_operands(base, argv)
    if words is None:
        return False
    rec = base in _GREP and _recursive(base, argv)
    for w in [x for x in words if x != "-"] or ["."]:
        cands = _abs_candidates(w, cwds)
        if not cands or not all(os.path.isabs(c) for c in cands):
            return False                 # a folder the hook can't know (`~-`, no home)
        for c in cands:
            if not _plain_read_path(c, roots):
                return False
            if rec and os.path.isdir(c) and not _tree_plain(os.path.realpath(c), roots):
                return False
    return True


def _stage_allowed(stage: list[str], form: formmod.Form, eff: consent.Effective,
                   cwds: list[str] | None = None, first: bool = True,
                   roots: tuple[list[str], list[str], str, list[str]] | None = None) -> bool:
    argv, exp, glb = _argv_meta(stage)
    if not argv:
        return False
    # Only bare names: the stand-ins and the benign tools are vouched for as
    # what PATH finds (the env file puts $DATA/bin first). A path (`./ssh`,
    # `/tmp/x/cat`, `bin/gate`) runs whatever file is there instead (round 3:
    # a planted ./ssh was auto-allowed by its basename).
    if "/" in argv[0]:
        return False
    # Never vouch for what the words hide: a write through a redirection, an
    # expansion the parser can't resolve, or a glob the shell expands.
    if any(r not in SAFE_REDIRECTS for r in getattr(stage, "redirects", [])):
        return False
    if any(exp) or any(glb):
        return False
    base = os.path.basename(argv[0])
    if base == "sudo":
        if _eff_right(eff, "localhost", "sudo") is not True or not _sudo_structure_ok(argv, cwds):
            return False
        # a plain reader under sudo reads as root: the same rule as without it
        # (GW-UX-1), but never when a wrapper changed its directory (env -C /
        # sudo -D): the read rule resolves the file from the stage's cwd (SF1)
        cmd = _unwrap(argv, fork=True)
        if cmd and os.path.basename(cmd[0]) in BENIGN_READERS:
            if _wrapper_chdir(argv, cwds or [os.getcwd()]) is not None:
                return False
            return _stage_allowed(cmd, form, eff, cwds, first, roots)
        return True
    if base in ("ssh", "scp", "sftp", "rsync"):
        targets, safe = _scan_family(base, argv)
        if not safe or not targets:
            return False
        if base == "sftp" and not first:
            return False               # sftp reads commands (`!cmd` runs locally) from a pipe
        _, sudo_word = _remote_sudo(base, argv)
        for t in targets:
            name = _resolve_host(t, form)
            if name is None or _eff_right(eff, name, "ssh") is not True:
                return False
            if sudo_word and _eff_right(eff, name, "sudo") is not True:
                return False           # remote sudo needs the host's sudo right too
        return base == "ssh" or _transfer_paths_ok(_scan_transfer(base, argv), cwds)
    if base == "gate":
        sub = argv[1] if len(argv) > 1 else ""
        if sub == "with" or sub not in GATE_SUBCMDS:
            return False
        if sub in ("rotate", "copy-to"):
            # they log in at once: only to a host whose ssh is approved true
            return all(_eff_right(eff, n, "ssh") is True for n in _gate_hosts(argv, form))
        return True
    if base in BENIGN:
        if base == "sleep":
            return len(argv) == 2 and argv[1].isdigit() and int(argv[1]) <= 5
        if base == "sort" and not _sort_ok(argv):
            return False
        if base == "uniq" and not _uniq_ok(argv):
            return False
        if base == "grep" and _grep_follows_links(argv):
            return False
        if base == "grep" and not _grep_longs_known(argv):
            return False                 # an abbreviation may be --recursive (MF1)
        if base == "date":
            return _date_ok(argv)
        if base in BENIGN_READERS:
            return roots is not None and _reads_plain(base, argv, cwds or [os.getcwd()], roots)
        return True
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def _names_form(command: str) -> bool:
    return any(s in command for s in _FORM_NAMES)


# The gateway daemon's refusal when a wrapped vault key is locked (PLAN-v4
# phase 2): the rights are in the vault, so a right the hook can't read is
# denied with this instead of "waits for the user's OK".
_LOCKED: dict[str, str] = {}


def _load_rights() -> tuple[formmod.Form, consent.Effective]:
    _LOCKED.clear()
    try:
        data = vault.load() if vault.exists() else None
    except vault.VaultLocked as e:
        _LOCKED["message"] = str(e)
        data = None
    except Exception:  # noqa: BLE001
        data = None
    form = consent.load_form(data)
    try:
        eff = consent.compute(form, data)
    except Exception:  # noqa: BLE001
        eff = consent.compute(form, None)
    if _LOCKED:
        _LOCKED["sudo"] = consent.locked_sudo_note(form)     # _ask says how to get it back
    return form, eff


def _gate_sub(argv: list[str]) -> str:
    """A `gate` stage's subcommand (the gate CLI takes it as its first word)."""
    return argv[1] if len(argv) > 1 and os.path.basename(argv[0]) == "gate" else ""


def _deny_gate_terminal(sub: str, in_job: bool = False) -> dict[str, Any]:
    if in_job:
        return _deny(f"gateway: don't run gate {sub} as a job: it asks the user in the gateway's "
                     "dialog, which only a command Claude runs with the Bash tool in this "
                     f"session can open. Run gate {sub} with the Bash tool.", tool="gate",
                     target=sub)
    return _deny(f"gateway: don't run gate {sub} in the user's Terminal panel: it asks the user in "
                 "the gateway's dialog, which only a command Claude runs with the Bash tool in "
                 f"this session can open. Run gate {sub} with the Bash tool.", tool="gate",
                 target=sub)


def _names_gate_secret(command: str) -> bool:
    """The command's text (quotes removed) has `gate secret` as two words, for
    commands whose words hide what runs (a shell string, eval, a loop,
    `find -exec`, ...)."""
    words = [w for w in _TEXT_SPLIT.split(_QUOTES.sub("", command)) if w]
    return any(a == "gate" and b == GATE_USER_SUBCMD for a, b in zip(words, words[1:]))


def _deny_gate_user(stages: list, command: str, in_user_terminal: bool,
                    in_job: bool = False) -> dict[str, Any] | None:
    """`gate secret` for any tool (also behind a wrapper, or named in a command
    the words hide), and gate export/import/copy-to in the Terminal panel and
    in a checkpoint job."""
    hidden = False
    for st in stages:
        for fork in (False, True):
            argv, base = _command(st, fork=fork)
            if base != "gate":
                continue
            sub = _gate_sub(argv)
            if sub == GATE_USER_SUBCMD:
                return _deny(DENY_GATE_SECRET, tool="gate", target=GATE_USER_SUBCMD)
            if in_user_terminal and sub in GATE_TERMINAL_SUBCMDS:
                return _deny_gate_terminal(sub)
            if in_job and sub in GATE_TERMINAL_SUBCMDS:
                return _deny_gate_terminal(sub, in_job=True)
        runner = _command(st, fork=True)[1]
        if runner in _HIDDEN_RUNNERS or runner in _LOOP_WORDS or _runs_hidden(list(st)):
            hidden = True
    if hidden and _names_gate_secret(command):
        return _deny(DENY_GATE_SECRET, tool="gate", target=GATE_USER_SUBCMD)
    return None


def _deny_transfer_ask(base: str, name: str, verb: str) -> dict[str, Any]:
    """scp / sftp / rsync on an "ask" right: the stand-in can't be asked
    about the ssh they start (only a command Claude typed), so it would refuse
    after the prompt; say so before anything runs."""
    how = f"ssh {name} 'sudo CMD'" if verb == "sudo" else f"ssh {name} CMD"
    return _deny(f'gateway: {verb} on {name} is set to "ask", and Claude Code can only ask about '
                 f"a command Claude runs itself, not the ssh that {base} starts; use {how} as "
                 f"its own command, or ask the user to set {verb} = true for {name}.",
                 tool=base, target=name)


# ---------------------------------------------------------------------------
# Alternate routes in managed mode (PLAN-v4 phase 7, docs/dev/modules/managed.md):
# a credential tool run by its path (/usr/bin/ssh, /opt/homebrew/bin/gh, ...)
# is the system's binary with the user's own keys, logins and config, around
# the gateway's stand-ins and gateway.toml; so is one run after the PATH was
# taken away (`command -p`, `env -i`, PATH=...), or ssh named as the program
# rsync/git start (-e, --rsh, GIT_SSH_COMMAND, core.sshCommand). git and
# rsync by path are routed (the env file's GIT_SSH_COMMAND, RSYNC_RSH and git
# include reach any git and rsync binary), so they pass. A guardrail on the
# command Claude typed: a script or a program can still exec the binary by
# path (the same-user limit, stated in the docs).
# ---------------------------------------------------------------------------

ROUTE_TOOLS = frozenset({"ssh", "scp", "sftp", "slogin", "ssh-add", "ssh-agent", "ssh-copy-id",
                         "sudo", "sudoedit", "gh", "hf", "huggingface-cli", "az", "databricks",
                         "crane", "pijul", "dvc"})
# Variables that steer which binary a tool name finds (PATH) or what git,
# rsync and sudo start as their transport or askpass; also git's
# configuration from the environment (GIT_CONFIG_COUNT/KEY_n/VALUE_n,
# GIT_CONFIG_PARAMETERS, ...), which can set core.sshCommand.
_ROUTE_VAR = (r"PATH|GIT_SSH|GIT_SSH_COMMAND|GIT_SSH_VARIANT|RSYNC_RSH|SUDO_ASKPASS"
              r"|GIT_CONFIG_(?:COUNT|PARAMETERS|GLOBAL|SYSTEM|NOSYSTEM|KEY_[0-9]+|VALUE_[0-9]+)")
_ROUTE_ASSIGN = re.compile(rf"^({_ROUTE_VAR})\+?=")
_ROUTE_NAME = re.compile(rf"({_ROUTE_VAR})\Z")
# git keys that choose the ssh git runs (setting one reroutes its transport)
_GIT_SSH_KEYS = ("core.sshcommand", "ssh.variant")
# The tools a changed variable reroutes.
_ROUTED_BY = {"PATH": ROUTE_TOOLS, "SUDO_ASKPASS": frozenset({"sudo", "sudoedit"}),
              "RSYNC_RSH": frozenset({"rsync"})}
# Text the parser can't split (a shell string, eval, a function, an
# assignment statement, ...): a credential tool named by a path (the word's
# last part) anywhere but as an operand of a command that never runs its
# operands (GW-UX-4: `sudo cat /etc/ssh/sshd_config`, `sudo cp x
# /etc/pam.d/sudo` and `sudo rm /usr/local/bin/gh` name data), or a
# transport/PATH change together with a tool word.
_TOOL_ALT = "|".join(sorted((re.escape(x) for x in ROUTE_TOOLS), key=len, reverse=True))
_TEXT_TOOL_PATH = re.compile(rf"[~$A-Za-z0-9_.{{}}/+-]*/({_TOOL_ALT})(?![A-Za-z0-9_./-])")
# Programs that run the next word (after their options) as a program, beside
# the wrappers _unwrap looks through; and those whose -c takes a command string.
_TEXT_RUN_NEXT = frozenset({"eval", "exec", "source", ".", "pkexec", "watch", "parallel"})
_TEXT_RUN_C = _SHELLS | frozenset({"su", "runuser"})
# what separates commands in the text: a brace only as a group's own word
# (`{ cmd; }`), not inside one (awk's `{print}`, `${HOME}`)
_TEXT_SEP = re.compile(r"[;&|()`\n]|(?<!\S)[{}](?!\S)")
# Commands that only read, write, list, compare or edit the files their
# operands name and never run them: a tool's path as their operand is data (a
# bin-folder tool path included: GW-UX-4's own `sudo cat /etc/ssh/sshd_config`,
# `sudo cp x /etc/pam.d/sudo`, `sudo rm /usr/local/bin/gh`). `less` isn't here
# (it runs `! CMD`); nor are awk, vi/vim/view/nvim, sed with an `e` command or
# the transfer tools (rsync, scp, tar), which may run their operands or a
# script (handled below). Any other program (an unknown one, a runner such as
# sshpass, strace, flock, script or chroot, a shell's script or its arguments)
# may run it, so a bin-folder tool path there is a program (round 1's rule).
_TEXT_DATA = frozenset({
    "cat", "tac", "more", "nano", "tee", "sed", "gsed", "cp", "gcp", "mv", "gmv", "ls", "gls",
    "grep", "egrep", "fgrep", "chmod", "gchmod", "chown", "gchown", "chgrp", "chflags", "chattr",
    "getfacl", "setfacl", "restorecon", "install", "ginstall", "mkdir", "rm", "grm", "rmdir",
    "touch", "ln", "gln", "stat", "gstat", "file", "diff", "cmp", "head", "tail", "wc", "sort",
    "uniq", "cut", "strings", "xxd", "od", "hexdump", "md5", "md5sum", "shasum", "sha1sum",
    "sha256sum", "sha512sum", "cksum", "readlink", "realpath", "basename", "dirname", "du",
    "test", "[", "[[", "xattr", "codesign", "otool", "nm", "lipo", "truncate", "which", "whereis",
    "type", "cd", "pushd", "base64", "nl", "paste", "join", "comm", "fold", "rev", "unzip",
    "gzip", "gunzip", "zcat", "bzip2", "bunzip2", "xz", "unxz", "echo", "printf", ":", "true"})
# Runners whose command is the next program word, after their own options (a
# value option takes the next word or the rest of its cluster); the tool path
# that follows may be run, bin-folder or not (round 1's non-bin blind spots).
_TEXT_RUNNER: dict[str, str] = {
    "sshpass": "pfdP", "strace": "oApeEzbuGISrx", "ltrace": "oeSpsnuFl", "dtruss": "",
    "unbuffer": "", "ssh-agent": "", "screen": "", "nsenter": "", "setarch": "",
    "catchsegv": "", "proot": "", "fakeroot": ""}
# Runners that take a resource operand (a lock file, a root, a typescript, a
# tmux subcommand) before the command: skip their options and one operand.
_TEXT_RUNNER_SKIP1 = frozenset({"flock", "chroot", "script", "tmux"})
# Commands that copy or archive their operands locally but run their transport
# or compressor option's value as a program (rsync -e, scp/sftp -S, tar -I).
_TEXT_TRANSFER = {"rsync": "e", "scp": "S", "sftp": "S", "tar": "I", "gtar": "I", "bsdtar": "I"}
# an sed address (a line, a step, `$`, or a /regex/[flags]), for its `e COMMAND`
_SED_ADDR = r"(?:[0-9]+(?:~[0-9]+)?|\$|/(?:\\.|[^/])*/[A-Za-z]*)"
# GNU sed's `e COMMAND` (an address or a `0,/re/` range, an optional block `{`,
# an optional `!`, then `e`) runs a command
_TEXT_SED_EXEC = re.compile(
    rf"\A(?:{_SED_ADDR}(?:,(?:{_SED_ADDR}|\+[0-9]+|~[0-9]+))?)? *\{{? *!?e\Z")
# the word before a path that makes it a program even after a command that
# never runs its operands: a long option naming a program (sort's
# --compress-program, --rsh, --to-command, --pager, ...), ssh's ProxyCommand
# and LocalCommand (rsync -e and scp -S need no rule: those commands may run
# their operands anyway)
_TEXT_PROGRAM_OPT = re.compile(
    r"\A(?:--\S*(?:rsh|rsync-path|program|command|shell|exec|pager|editor|askpass|proxy)\S*|"
    r"(?i:proxycommand|localcommand|knownhostscommand))\Z")
# a redirection word (`3</dev/null`, `>x`, `2>&1`) or operator (`>`, `<<<`)
_TEXT_REDIR = re.compile(r"\A(?:[0-9]+|&)?(?:>>?\|?|<<<|<<?-?|<>|>&|<&)")
# a pipe into a shell (`echo '/opt/x/ssh h' | sh`): every word may be a program
_TEXT_PIPE_SHELL = re.compile(
    r"\|&?\s*(?:(?:sudo|doas|env|nohup|command|exec|nice|time|arch)(?:\s+-\S*)*\s+)*"
    r"(?:\S*/)?(?:" + "|".join(sorted(_SHELLS | {"xargs", "parallel"})) + r")(?![A-Za-z0-9_.-])")
_TEXT_TOOL_WORD = re.compile(rf"(?<![A-Za-z0-9_./-])({_TOOL_ALT}|git|rsync)(?![A-Za-z0-9_-])")
# a word in command position (after a separator, a reserved word, or the
# wrappers that exec their command): `_program_word` reads a `$(...)` or
# backtick there as "$" (a computed program managed mode refuses)
_TEXT_CMD_WORD = re.compile(
    r"(?:^|[;&|\n(]|\b(?:then|do|else|elif|if|while|until)\b|!)\s*"
    r"(?:(?:exec|eval|command|builtin|nohup|time|nice|env|xargs|setsid|stdbuf|arch)\s+"
    r"(?:-[^\s;&|]*\s+|[A-Za-z_][A-Za-z0-9_]*=[^\s;&|]*\s+)*)*"
    r"([^\s;&|()<>]+)")
# the first word of a shell's or su's -c string (`bash -c '$(echo /x/ssh) h'`,
# `bash -c "$CMD"`); only theirs: any other program's -c is its own option
# (`gcc -c "$f"`, `psql -c "$Q"`)
_TEXT_SHELL_C = re.compile(
    r"(?<![\w./-])(?:\S*/)?(?:" + "|".join(sorted(_SHELLS | {"su", "runuser"})) +
    r")(?:\s+-\S+)*?\s+-[A-Za-z]*c\b\s*([^\s;&|()<>]+)")
_TEXT_STEER = [
    (re.compile(rf"(?<![A-Za-z0-9_])({_ROUTE_VAR})\+?="), "{0} changed"),
    (re.compile(rf"\bunset\b[^;&|\n]*?(?<![A-Za-z0-9_])({_ROUTE_VAR})(?![A-Za-z0-9_])"),
     "{0} unset"),
    (re.compile(r"\bhash\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*p"), "hash -p"),
    (re.compile(rf"\balias\s+[^;&|\n]*?(?<![A-Za-z0-9_-])({_TOOL_ALT}|git|rsync)="), "alias {0}"),
    (re.compile(rf"(?<![A-Za-z0-9_-])({_TOOL_ALT}|git|rsync)\s*\(\s*\)"), "a function named {0}"),
    (re.compile(rf"\bfunction\s+({_TOOL_ALT}|git|rsync)(?![A-Za-z0-9_-])"), "a function named {0}"),
    (re.compile(rf"\b(?:printf\s+-v|read\b[^;&|\n]*?)\s*(?<![A-Za-z0-9_])({_ROUTE_VAR})"
                r"(?![A-Za-z0-9_])"), "{0} read into"),
    (re.compile(r"\bcommand\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*p"), "command -p"),
    (re.compile(r"\benv\b[^;&|\n]*?\s(?:-[A-Za-z]*[iuS]|--ignore-environment|--unset|"
                r"--split-string)"), "env without the PATH"),
]
# git's ssh setting reroutes git wherever it stands in the text
_TEXT_GIT_SSH = re.compile(r"(?i)core\.sshcommand|ssh\.variant|--config-env")


# the way out for a real need of the system's own tool (a widening: the user's OK)
_ROUTE_OFF = (" If the user really needs the system's own tool, they can set [shell] managed = "
              "\"off\" in gateway.toml (approved in the gateway's dialog; it applies from the "
              "next session); ask them first.")


def _route_deny(word: str, base: str, why: str = "") -> dict[str, Any]:
    return _deny(f"gateway: {why or word} runs the system's {base} around the gateway (with your "
                 "own keys, logins and config, outside gateway.toml's hosts and rights); run "
                 f"`{base}` by its bare name: the gateway's stand-in is first on PATH. (A script "
                 "that runs it by path is a known limit of the gateway with code running as "
                 "you.)" + _ROUTE_OFF, tool=base, target=word)


# the way out of a refused `bash -c "$CMD"`: the command written out
_SHELL_C_RUN = ("write the command itself in the -c string (`bash -c 'make test'`, not `bash -c "
                "\"$CMD\"`), or run it")


def _route_deny_hidden(base: str | None, why: str, run: str = "") -> dict[str, Any]:
    """A command whose use of a credential tool the hook can't follow
    (managed mode): denied, never left to Claude Code's own mode. `base`
    None: the program itself can't be told (a variable). `run`: the way out,
    when it isn't running the tool or the program by its name."""
    tool = base or "credential tool (ssh, sudo, gh, ...)"
    run = run or (f"run `{base}` by its bare name" if base else "name the program itself")
    return _deny(f"gateway: this command may run the system's {tool} around the gateway ({why}; "
                 "the gateway can't follow a shell string, eval or exec, a function, find -exec, "
                 "a variable as the program, or PATH or ssh settings changed earlier in the "
                 "command), which would use your own keys, logins and config outside "
                 f"gateway.toml's hosts and rights; {run} as its own command: the gateway's "
                 "stand-ins are first on PATH. (A script that runs a tool by path is a known "
                 "limit of the gateway with code running as you.)"
                 + _ROUTE_OFF, tool=base or "shell", target=why[:60])


def _is_stand_in(word: str, base: str) -> bool:
    try:
        return os.path.realpath(word) == os.path.realpath(str(paths.bin_dir() / base))
    except (OSError, paths.PathError):
        return False


_HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_HEREDOC_SHELL = re.compile(r"(?<![A-Za-z0-9_./-])(?:sh|bash|zsh|dash|ksh|ash|mksh|yash|fish|"
                            r"csh|tcsh|source|eval|\.)(?![A-Za-z0-9_-])")


def _drop_heredoc_data(command: str) -> str:
    """The command without the bodies of here-documents that are data (a
    file Claude writes with `cat > f <<EOF`); a body a shell reads (`bash
    <<EOF`, `cat <<EOF | sh`, `eval`, `source`) stays: it is a command."""
    lines = command.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        out.append(ln)
        i += 1
        words = [m.group(2) for m in _HEREDOC.finditer(ln) if "<<<" not in ln[m.start():m.start() + 3]]
        if not words or _HEREDOC_SHELL.search(ln):
            continue
        for w in words:                          # each body in turn, up to its end word
            while i < len(lines) and lines[i].strip("\t") != w:
                i += 1
            i += 1
    return "\n".join(out)


def _program_word(text: str, i: int) -> str:
    """The program word at text[i] in command position: assignments before
    it skipped (`X=$(mktemp) cmd`), a `$(...)` or a backquoted part taken
    whole and read as "$" (`$(git rev-parse --show-toplevel)/x.sh` names the
    program x.sh in a folder it computes; `$(which -a ssh)` names none)."""
    while True:
        w, i = _text_word(text, i)
        if not _ASSIGN.match(w):
            return w
        while i < len(text) and text[i] in " \t":
            i += 1


def _text_word(text: str, i: int) -> tuple[str, int]:
    """One word of quote-stripped text from i (a `$(...)` or a backquoted
    part counts as "$") and the index after it."""
    out, n = [], len(text)
    while i < n and not text[i].isspace() and text[i] not in ";&|<>":
        if text.startswith("$(", i) or text[i] == "`":
            close, depth, j = ("`", 0, i + 1) if text[i] == "`" else (")", 1, i + 2)
            while j < n:
                if close == ")" and text[j] == "(":
                    depth += 1
                elif text[j] == close:
                    depth -= 1
                    if depth <= 0:
                        break
                j += 1
            out.append("$")                   # what it computes: unknown
            i = j + 1
            continue
        if text[i] in "()":
            break
        out.append(text[i])
        i += 1
    return "".join(out), i


_TEXT_TARGET = "\x00"       # the tool path's place in _text_program's words
# where a word a shell reads as a script (`-c STRING`, a here-string `<<<`,
# eval/source/`.`'s argument) sits; separators that aren't a word join
_GLUED_STOP = frozenset(" \t\n;&|()`{}")
# a shell command whose stdin is a here-string (`bash <<< 'SCRIPT'`, `sh -s
# <<< ...`): its content is a script. (`bash -c CMD <<< DATA` doesn't match:
# CMD stands between the shell and the here-string, so the content is CMD's.)
_HERESTRING_SHELL = re.compile(
    r"(?:^|[;&|(`\n])\s*"
    r"(?:(?:sudo|doas|env|nohup|command|nice|time|setsid|stdbuf|exec|arch)\s+(?:-\S+\s+)*|"
    r"[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*"
    r"([^\s;&|<>]+)(?:\s+-\S+)*\s*<<<\s*\Z")


def _herestring_into_shell(text: str, i: int) -> bool:
    """Does text[:i] end with a shell command and a `<<<` here-string whose
    content starts at i (`bash <<< '/x/ssh h'`, `sh -s <<< ...`)? The content
    is then a program the shell runs."""
    m = _HERESTRING_SHELL.search(text[:i])
    if not m:
        return False
    sh = os.path.basename(m.group(1))
    return sh in _SHELLS or sh in ("eval", "source", ".")


def _text_unredirect(words: list[str]) -> list[str] | None:
    """The words without their redirections (`3</dev/null`, `> f`, `2>&1`);
    None when _TEXT_TARGET is a redirection's target (a file: data)."""
    out: list[str] = []
    skip = False
    for w in words:
        if skip:
            if w == _TEXT_TARGET:
                return None
            skip = False
            continue
        m = _TEXT_REDIR.match(w)
        if m and w != _TEXT_TARGET:
            skip = m.end() == len(w)       # a lone operator: its target is the next word
            continue
        out.append(w)
    return out


def _skip_runner(argv: list[str], vals: str) -> list[str]:
    """argv past a runner's own options (a value option, in `vals`, takes the
    next word or the rest of its cluster)."""
    argv = argv[1:]
    while argv and argv[0].startswith("-") and argv[0] not in ("-", "--", _TEXT_TARGET):
        body = argv[0][1:]
        argv = argv[2:] if (body and body[-1] in vals) else argv[1:]
    return argv[1:] if argv[:1] == ["--"] else argv


def _text_program(words: list[str]) -> str:
    """How _TEXT_TARGET, the last of these words (one command of quote-stripped
    text, up to the tool path), stands in the command (GW-UX-4):

    - "run": it is the program, reached through assignments, redirections,
      reserved words, the wrappers _unwrap looks through (env, nohup, sudo,
      timeout, xargs, ...), eval/exec/source, a shell's or su's -c string, su's
      -s shell, find's -exec, a runner (sshpass, strace, flock, chroot, ...),
      or a transfer tool's transport option (rsync -e, tar -I);
    - "pure": it is a plain operand of a command that never runs it (_TEXT_DATA
      without GNU sed's `e COMMAND`, a transfer tool's local path): the one case
      where a bin-folder tool path is still data (round 1's own false positives:
      `sudo rm /usr/local/bin/gh`, `sudo cp x /etc/pam.d/sudo`);
    - "data": a redirection's target, a here-string a reader consumes, or find's
      operand without -exec: data for a non-bin path, a program for a bin-folder
      one (round 1 denied a bin-folder path there);
    - "operand": it is an operand of an unknown program (the caller decides by
      the path: a bin-folder tool path is a program, round 1's rule; a non-bin
      path is data)."""
    argv: list[str] | None = words
    for _ in range(12):
        while argv and _ASSIGN.match(argv[0]):
            argv = argv[1:]
        argv = _unwrap(argv, fork=True)
        if not argv:
            return "data"                  # `command -v X`: looked up, not run
        # a here-string into a shell (`bash <<< '/x/ssh'`) is caught in
        # _text_runs by _herestring_into_shell before the walk; here it is left
        # as a redirection's target (data), so a bin-folder path still denies
        argv = _text_unredirect(argv)
        if argv is None:
            return "data"                  # a redirection's target: a file
        if not argv:
            return "data"
        if argv[0] == _TEXT_TARGET:
            return "run"
        b = os.path.basename(argv[0])
        if b in _TEXT_RUN_NEXT:
            argv = argv[1:]
            while argv and argv[0].startswith("-") and argv[0] != _TEXT_TARGET:
                argv = argv[2:] if argv[0] == "-a" else argv[1:]   # exec -a NAME
            continue
        if b in _TEXT_RUNNER:
            argv = _skip_runner(argv, _TEXT_RUNNER[b])
            continue
        if b in _TEXT_RUNNER_SKIP1:
            argv = _skip_runner(argv, "")
            argv = argv[1:]                # the resource operand (lock file, dir, subcommand)
            continue
        if b in _TEXT_RUN_C:
            rest = argv[1:]
            if b in ("su", "runuser") and any(
                    w in ("-s", "--shell") or w.startswith("--shell=") or
                    (w.startswith("-") and not w.startswith("--") and "s" in w[1:])
                    for w in rest):
                return "run"               # su -s SHELL: whatever follows may be that shell
            c = next((j for j, w in enumerate(rest) if w.startswith("-") and not
                      w.startswith("--") and "c" in w[1:]), None)
            if c is None:
                return "run"               # a script and its arguments, runuser's command
            argv = rest[c + 1:]            # the -c string: its first word is a program
            if b in _SHELLS:
                # a shell's string is its first operand after the options (`-c -e`, `-c --`)
                while argv and argv[0].startswith("-"):
                    end = argv[0] in ("-", "--")
                    argv = argv[1:]
                    if end:
                        break
            continue
        if b == "find":
            k = next((j for j, w in enumerate(argv) if w in _FIND_RUN), None)
            if k is None:
                return "pure"              # find's search roots and tests: never run
            argv = argv[k + 1:]
            continue
        if b in _TEXT_TRANSFER:
            j = argv.index(_TEXT_TARGET) if _TEXT_TARGET in argv else len(argv)
            prev = argv[j - 1] if j else ""
            if prev.startswith("--") and _TEXT_PROGRAM_OPT.match(prev.split("=", 1)[0]):
                return "run"               # rsync --rsh PROG, tar --use-compress-program PROG
            if prev.startswith("-") and not prev.startswith("--") and \
                    prev[-1:] == _TEXT_TRANSFER[b]:
                return "run"               # rsync -e PROG, scp -S PROG, tar -I PROG
            return "pure"                  # a local path or a remote path
        if b in _TEXT_DATA:
            # an operand of a command that never runs it (GNU sed's `e CMD` does)
            if b in ("sed", "gsed") and any(_TEXT_SED_EXEC.match(w) for w in argv[1:-1]):
                return "run"
            return "pure"
        return "operand"                   # an unknown program: the caller decides by the path
    return "operand"


def _text_runs(text: str, m: re.Match[str]) -> bool:
    """May the tool path _TEXT_TOOL_PATH matched in the (quote-stripped) text
    be run as a program there (GW-UX-4)? A bin-folder tool path is a program
    anywhere except as an operand of a command that never runs it (round 1's
    rule); a non-bin path only in a program position or after a known runner.
    Yes anywhere in a text piped into a shell or a shell's here-string, glued
    to a value (`--rsh=/x/ssh`, `X=/x/ssh`, `-e/x/ssh`), after a word that
    names a program (_TEXT_PROGRAM_OPT), and wherever _text_program finds it
    runs. Data: a remote path (`box:/x/ssh`), a redirection's target, an
    operand of a command that never runs it (`sudo cat /etc/ssh`, `sudo cp x
    /etc/pam.d/sudo`, `sudo rm /usr/local/bin/gh`)."""
    word = m.group(0)
    if word.startswith("-"):
        return True                      # an option's own value (`-e/x/ssh`)
    path = re.sub(r"^-[A-Za-z]*(?=[/~$.])", "", word)
    pre = path.split("/", 1)[0]
    if pre and _TEXT_SED_EXEC.match(pre) and re.search(r"(?<![\w./-])g?sed\b", text):
        return True                      # sed's `1e/x/ssh`: the e command glued to its path
    is_bin = _names_program(path)
    if _TEXT_PIPE_SHELL.search(text):
        return True
    i = m.start()
    if _herestring_into_shell(text, i):
        return True
    prev = text[i - 1] if i else " "
    if prev not in _GLUED_STOP:
        # glued to the previous word: a value (`--rsh=`, `X=`) runs; a remote
        # path (`box:/x/ssh`) or a redirect target (`>/x/ssh`) is data
        return prev not in ":<>"
    words = _TEXT_SEP.split(text[:i])[-1].split()
    if words and _TEXT_PROGRAM_OPT.match(words[-1]):
        return True                      # --compress-program, --rsh, ProxyCommand, ...: a program
    kind = _text_program(words + [_TEXT_TARGET])
    if kind == "run":
        return True
    if kind == "pure":
        return False                     # a plain operand of a command that never runs it
    # "data" (a redirect target, a reader's here-string, find's operand) or
    # "operand" (an unknown program's operand): a bin-folder tool path is a
    # program (round 1); a non-bin path is data
    return is_bin


def _route_text(command: str) -> dict[str, Any] | None:
    """The text scan for a command the parser can't follow (see _TEXT_*): a
    credential tool by a path that isn't the stand-in, where it can run as a
    program (_text_runs), or a PATH/transport change (or an alias, a
    function, `hash -p`, `command -p`, `env -i`, git's ssh setting) with a
    tool named anywhere. Here-documents that are data aren't read."""
    text = _QUOTES.sub("", _drop_heredoc_data(command))
    for m in _TEXT_TOOL_PATH.finditer(text):
        word = re.sub(r"^-[A-Za-z]*(?=[/~$.])", "", m.group(0))
        if not _text_runs(text, m):
            continue
        if not _is_stand_in(word, m.group(1)):
            return _route_deny_hidden(m.group(1), f"{word[:60]} by its path")
    for m in _TEXT_CMD_WORD.finditer(text):
        w = _program_word(text, m.start(1))
        if "$" in os.path.basename(w) or "`" in os.path.basename(w):
            return _route_deny_hidden(None, f"the program is a variable or a command's output "
                                            f"({w[:40]})")
    for m in _TEXT_SHELL_C.finditer(text):
        w = _program_word(text, m.start(1))
        if "$" in os.path.basename(w) or "`" in os.path.basename(w):
            # `bash -c "$CMD"`: whatever the variable holds runs, unseen
            return _route_deny_hidden(None, f"the shell's -c string is a variable or a command's "
                                            f"output ({w[:40]})", _SHELL_C_RUN)
    if _TEXT_GIT_SSH.search(text) and re.search(r"(?<![A-Za-z0-9_.-])git(?![A-Za-z0-9_-])", text):
        return _route_deny_hidden("ssh", "git's ssh setting")
    # a change steers only the tools after it (`sudo env -i make` is sudo's own business)
    for rx, why in _TEXT_STEER:
        for m in rx.finditer(text):
            named = m.group(1) if m.groups() and m.group(1) in ROUTE_TOOLS | {"git", "rsync"} \
                else None
            tool = _TEXT_TOOL_WORD.search(text, m.end()) if named is None else m
            if tool is not None:
                return _route_deny_hidden(named or tool.group(1),
                                          why.format(*(m.groups() or ("",))))
    return None


def _stage_hidden(st: list, argv: list[str], base: str) -> bool:
    """Does the stage run code its words don't show (a shell, eval, exec,
    source, su, xargs, env -S, find -exec, a nested sudo/runner, a loop; a
    tracer or sandbox as the program, also behind a wrapper)? A
    plain `sudo CMD ARGS` counts (sudo is a runner), and the text scan reads
    the command it elevates: with the corrected data/program classification a
    tool path that CMD only reads (`sudo restorecon /etc/ssh`, `sudo tar ...
    /etc/ssh`) is no longer refused (MF3), while one it runs (`sudo sort
    --compress-program /x/ssh`, `sudo strace /x/ssh`) still is."""
    return base in _HIDDEN_RUNNERS or base in _LOOP_WORDS or _runs_hidden(list(st))


def _route_changes(argv: list[str]) -> dict[str, str]:
    """What a builtin stage changes for the stages after it in the same
    command: {tool: why} for export/declare/typeset/readonly/local of a
    route variable, `unset` of one, `printf -v` / `read` into one, `hash -p`
    of a tool name, an alias of a tool."""
    out: dict[str, str] = {}
    if not argv:
        return out
    b = argv[0]
    args = argv[1:]

    def mark(var: str, why: str) -> None:
        for tool in _ROUTED_BY.get(var, frozenset({"git"})):
            out.setdefault(tool, why)

    if b in ("export", "declare", "typeset", "readonly", "local"):
        for a in args:
            m = _ROUTE_ASSIGN.match(a)
            if m:
                mark(m.group(1), f"{m.group(1)} changed earlier in the command")
    elif b == "unset":
        for a in args:
            if _ROUTE_NAME.match(a):
                mark(a, f"{a} unset earlier in the command")
    elif b in ("printf", "read"):
        for a in args:
            if _ROUTE_NAME.match(a):
                mark(a, f"{a} set by {b} earlier in the command")
    elif b == "hash" and any(a.startswith("-") and "p" in a[1:] for a in args):
        for a in args:
            if a in ROUTE_TOOLS or a in ("git", "rsync"):
                out.setdefault(a, f"hash -p {a} earlier in the command")
    elif b == "alias":
        for a in args:
            name = a.split("=", 1)[0]
            if "=" in a and (name in ROUTE_TOOLS or name in ("git", "rsync")):
                out.setdefault(name, f"an alias for {name} earlier in the command")
    return out


def _route_argv(st: list, raw: list[str], fork: bool) -> dict[str, Any] | None:
    """The per-command checks on one stage (the exec view or, fork=True,
    through sudo, timeout and xargs too)."""
    argv, base = _command(st, fork=fork)
    if not argv:
        return None
    lead = raw[:len(raw) - len(argv)] if len(argv) <= len(raw) else []
    if not fork and ("$" in os.path.basename(argv[0]) or "`" in argv[0]):
        # (behind sudo, timeout or xargs it is that program's argument: SPEC 8's table)
        return _route_deny_hidden(None, f"the program is a variable ({argv[0][:40]})")
    if base in ROUTE_TOOLS:
        if "/" in argv[0] and not _is_stand_in(argv[0], base):
            return _route_deny(argv[0], base)
        for i, w in enumerate(lead):
            b = os.path.basename(w)
            if b == "command" and any(x.startswith("-") and "p" in x[1:] for x in lead[i + 1:]):
                return _route_deny(argv[0], base, f"command -p {base}")
            if b == "env" and any(x == "-i" or x.startswith("-i") or x == "--ignore-environment"
                                  or x in ("-u", "--unset") or x.startswith("--unset")
                                  for x in lead[i + 1:]):
                return _route_deny(argv[0], base, f"env {base} without the PATH")
        if any(_ROUTE_ASSIGN.match(w) for w in lead + list(getattr(st, "assigns", []) or [])):
            return _route_deny(argv[0], base, f"{base} with its PATH replaced")
    if base in ("rsync", "git", "scp", "sftp"):
        names = [w for w in lead if _ROUTE_ASSIGN.match(w)]
        if names:
            return _route_deny(names[0].split("=", 1)[0], base,
                               f"{names[0].split('=', 1)[0]} set for {base}")
        if base == "git" and _git_sets_ssh(argv):
            return _route_deny("core.sshCommand", "ssh", "git config setting git's ssh")
        for j, a in enumerate(argv[1:], 1):
            val = None
            if base == "rsync":
                if a in ("-e", "--rsh") and j + 1 < len(argv):
                    val = argv[j + 1]
                elif a.startswith("--rsh="):
                    val = a.split("=", 1)[1]
                elif a.startswith("-") and not a.startswith("--") and len(a) > 1:
                    # a short cluster: -e takes the rest, or the next word
                    # (`-ae /usr/bin/ssh`, `-aze/usr/bin/ssh`); a value option
                    # before it (B f M T @) takes the rest itself
                    body = a[1:]
                    for k, c in enumerate(body):
                        if c in RSYNC_VALUE_SHORT:
                            if c == "e":
                                val = body[k + 1:] or (argv[j + 1] if j + 1 < len(argv) else "")
                            break
            elif base == "git":
                if a == "-c" and j + 1 < len(argv) and argv[j + 1].lower().startswith(
                        tuple(k + "=" for k in _GIT_SSH_KEYS)):
                    val = argv[j + 1].split("=", 1)[1]
                elif a.startswith("-c") and len(a) > 2 and a[2:].lower().startswith(
                        tuple(k + "=" for k in _GIT_SSH_KEYS)):
                    val = a[2:].split("=", 1)[1]          # `-ccore.sshCommand=...`
                elif a.lower().startswith("--config-env="):
                    val = a
            if val is not None:
                try:
                    first = (shlex.split(val) or [""])[0]
                except ValueError:
                    first = val
                if not (os.path.basename(first) == "ssh" and "/" not in first) and \
                        not _is_stand_in(first, "ssh"):
                    return _route_deny(first or val, "ssh", f"{base} with its own ssh ({first})")
    return None


_GIT_CONFIG_READS = frozenset({"--get", "--get-all", "--get-regexp", "--get-urlmatch", "-l",
                               "--list", "--unset", "--unset-all", "get", "list", "unset",
                               "--show-origin", "--name-only"})


def _git_sets_ssh(argv: list[str]) -> bool:
    """`git config core.sshCommand VALUE` / `ssh.variant` (any scope, the old
    and the new `git config set` forms): a reroute that outlives the command."""
    if _git_subcommand(argv) != "config":
        return False
    words = [w.lower() for w in argv[1:]]
    if not any(w in _GIT_SSH_KEYS or w.startswith(tuple(k + "=" for k in _GIT_SSH_KEYS))
               for w in words):
        return False
    return not any(w in _GIT_CONFIG_READS for w in words)


def _alternate_route(stages: list, eff: consent.Effective,
                     command: str = "") -> dict[str, Any] | None:
    """A deny for a credential tool reached around the stand-ins (above), or
    None. Managed mode only ([shell] managed "on" or "warn"). Besides each
    stage's own words: a tool whose route an earlier stage of the same command
    changed (PATH, a transport variable, hash -p, an alias), a variable as
    the program, and, when a stage runs code its words don't show (a shell
    string, eval, exec, find -exec, xargs, ...), the text scan."""
    if eff.shell.managed == "off":
        return None
    rerouted: dict[str, str] = {}
    hidden = False
    for st in stages:
        raw = list(_strip_gate_account(st))
        for forked in (False, True):
            argv, base = _command(st, fork=forked)
            if not argv:
                continue
            if base in rerouted:
                return _route_deny_hidden(base, rerouted[base])
            d = _route_argv(st, raw, forked)
            if d is not None:
                return d
            # a shell string, eval, exec, find -exec, ...: the text scan below (never
            # for ssh, whose remote command runs on the host and is judged there)
            hidden = hidden or (base != "ssh" and _stage_hidden(st, argv, base))
        for tool, why in _route_changes(_command(st)[0] or raw).items():
            rerouted.setdefault(tool, why)
    if hidden and command:
        return _route_text(command)
    return None


# a decision whose rule is a policy table's (not a right's own: those keep
# their own messages and next steps below)
_POLICY_RULE = re.compile(r"\[(policy|hosts\.[a-z0-9-]+\.policy|hosts\.[a-z0-9-]+\.workspaces\."
                          r"[a-z0-9-]+|accounts\.[a-z0-9-]+\.policy)\]")


def _policy_hits(base: str, argv: list[str], form: formmod.Form,
                 eff: consent.Effective) -> list[tuple[str, str, Any]]:
    """(host, action, policy.Decision) for every action an ssh / scp / sftp /
    rsync stage or a local sudo takes (PLAN-v4 phase 7), as the stand-ins will
    decide them, so a "deny" is refused here with its rule and an "ask" is
    asked (the stand-ins honour "ask" only for a command Claude typed, which
    is this one)."""
    from . import policy
    out: list[tuple[str, str, Any]] = []
    if base in _SUDO_NAMES:
        out.append(("localhost", "elevation", policy.decide(eff, "elevation")))
        return out
    acts: dict[str, list[tuple[str, str]]] = {}
    if base == "ssh":
        try:
            a = ssh_args.parse_ssh(argv[1:], forwards=True)
        except ssh_args.Refused:
            return out
        if a.dest is None:
            return out
        try:
            dest = ssh_args.parse_destination(a.dest)
        except ssh_args.Refused:
            return out
        name = _resolve_host(dest.host, form) or _resolve_host(a.dest, form)
        if name is None:
            return out
        acts[name] = ssh_args.ssh_actions(a)
        if ssh_args.has_sudo_word(a.command_text):
            acts[name].append(("elevation", ""))
    else:
        tr = _scan_transfer(base, argv)
        last = None
        if base != "sftp":
            ops = [x for x in argv[1:] if not x.startswith("-")]
            last = _remote_operand(ops[-1]) if ops else None
        for host, path in tr.remote:
            name = _resolve_host(host, form)
            if name is None:
                continue
            if base == "sftp" or tr.subsystem:
                # sftp may open any file once it is connected, whatever path it starts at
                acts.setdefault(name, []).extend([("read", ssh_args.ANY_PATH),
                                                  ("write", ssh_args.ANY_PATH)])
            elif last is not None and (host, path) == last:
                acts.setdefault(name, []).append(("write", path or "."))
            else:
                acts.setdefault(name, []).append(("read", path or "."))
        if base == "rsync":
            opts = argv[1:argv.index("--")] if "--" in argv else argv[1:]
            if any(x in ("--remove-source-files", "--remove-sent-files") for x in opts):
                for lst in acts.values():          # it deletes the remote sources: a write
                    lst.extend([("write", p) for a_, p in list(lst) if a_ == "read"])
            if "s" in tr.opts or any(x in ("--protect-args", "--secluded-args") for x in opts):
                for lst in acts.values():          # the paths go on stdin: the stand-in sees exec
                    lst.append(("exec", ""))
        rc = tr.remote_cmd
        if rc and ssh_args.has_sudo_word(rc):
            for name in acts:
                acts[name].append(("elevation", ""))
    for name, lst in acts.items():
        for act, path in dict.fromkeys(lst):
            try:
                # a path in its workspace and in every one it may reach (as the stand-in)
                out.append((name, act, ssh_args.decide_path(eff, act, name, path)))
            except ValueError:
                continue
    return out


# sudo's options that take a value (sudo 1.9: -C -D -g -h -p -R -r -t -T -U -u)
_SUDO_ARG_SHORT = frozenset("CDghpRrtTUu")
_SUDO_ARG_LONG = frozenset({"--chdir", "--close-from", "--group", "--host", "--prompt", "--chroot",
                            "--role", "--type", "--command-timeout", "--other-user", "--user"})
_SUDO_TARGET = re.compile(r"[A-Za-z_][A-Za-z0-9_.-]{0,31}|#[0-9]{1,10}")


def _sudo_target(words: list[str]) -> str:
    """Whom `sudo ...` runs the command as: its -u / --user, else root (a
    name that isn't a plain user name or #uid is "another user")."""
    user = "root"
    i = 1
    while i < len(words):
        w = words[i]
        if w == "--" or w == "-" or not w.startswith("-"):
            break
        if w.startswith("--"):
            k, eq, v = w.partition("=")
            if k == "--user":
                if eq:
                    user = v
                elif i + 1 < len(words):
                    i += 1
                    user = words[i]
            elif not eq and k in _SUDO_ARG_LONG:
                i += 1
            i += 1
            continue
        for j in range(1, len(w)):
            if w[j] in _SUDO_ARG_SHORT:
                val = w[j + 1:]
                if not val and i + 1 < len(words):
                    i += 1
                    val = words[i]
                if w[j] == "u":
                    user = val
                break
        i += 1
    return user if _SUDO_TARGET.fullmatch(user or "") else "another user"


def _remote_sudo_targets(text: str) -> list[str]:
    """The users each sudo in a remote command line runs as (best effort:
    the stand-in decides; this only names them)."""
    try:
        words = shlex.split(text)
    except ValueError:
        words = text.split()
    seps = {";", "&&", "||", "|", "&"}
    out = []
    for i, w in enumerate(words):
        if os.path.basename(w) in _SUDO_NAMES:
            rest = []
            for x in words[i:]:
                if x in seps:
                    break
                rest.append(x)
            out.append(_sudo_target(rest))
    return out or ["root"]


def _elevation_notice(command: str) -> str | None:
    """Who sudo will run as, where (PLAN-v4 phase 7: the target's identity
    visible before elevation): a systemMessage the person sees before the
    command runs, never part of its output."""
    segs = bashparse.parse(command)
    if not segs:
        return None
    form = _load_rights()[0]
    out: list[str] = []
    for st in (st for seg in segs for st in seg):
        argv, base = _command(st)
        if base in _SUDO_NAMES:
            out.append(f"{_sudo_target(argv)} on this machine "
                       f"({paths.local_user()}@{_hostname().split('.')[0]})")
        elif base == "ssh":
            targets, _ = _scan_family(base, argv)
            _cmd, word = _remote_sudo(base, argv)
            if word:
                whom = _remote_sudo_targets(_remote_command(base, argv))
                for t in targets:
                    name = _resolve_host(t, form)
                    h = form.hosts.get(name) if name else None
                    if h is not None and h.address is not None:
                        for u in dict.fromkeys(whom):
                            out.append(f"{u} on {name} ({h.address.render()})")
    if not out:
        return None
    return "gateway: sudo runs as " + ", ".join(dict.fromkeys(out))


MANAGED_TOOLS = ("Bash", "Monitor")
MANAGED_DENY = ("gateway: managed shell unavailable: {why}. In managed mode (gateway.toml [shell] "
                "managed = \"on\", the default) Claude's commands run only in the gateway's managed "
                "bash, which the gateway's Claude Code mod starts, so this one was not run. Tell the "
                "user once: turn Claude Code's mods on (or update Claude Code to 2.1.287 or later) "
                "and start a new session; or set [shell] managed = \"warn\" (or \"off\") in "
                "gateway.toml to run commands in their own shell, which needs their OK in the "
                "gateway's dialog (gate check settings; the dialog needs the mod too).")
MANAGED_WARN = ("gateway: the managed shell isn't active in this session ({why}); gateway.toml "
                "says [shell] managed = \"warn\", so Claude's commands run in your own shell "
                "(your login setup, PATH and environment) until it is. Turn Claude Code's mods on "
                "(2.1.287 or later) and start a new session to use the managed shell.")


def _prefix_why() -> str:
    """Why this session's Bash doesn't go through gate-sh, in words."""
    prefix = os.environ.get("CLAUDE_CODE_SHELL_PREFIX", "")
    if prefix:
        return ("another shell prefix is set (CLAUDE_CODE_SHELL_PREFIX names "
                f"{os.path.basename(prefix) or 'something else'}, not the gateway's gate-sh)")
    return ("the gateway's mod didn't start it: Claude Code's mods are off or older than 2.1.287, "
            "or this session started before managed mode was switched on")


def _ours(prefix: str) -> bool:
    if not prefix:
        return False
    from . import managed
    for p in managed.prefix_paths():
        try:
            if os.path.samefile(prefix, p):
                return True
        except OSError:
            continue
    return False


def _managed_gate(payload: dict) -> tuple[dict | None, str | None]:
    """(a final deny, or None; a notice for the user, or None) for a Bash or
    Monitor call that doesn't run through the gateway's gate-sh."""
    if _ours(os.environ.get("CLAUDE_CODE_SHELL_PREFIX", "")):
        return None, None
    _form, eff = _load_rights()
    mode = eff.shell.managed
    if mode == "off":
        return None, None
    why = _prefix_why()
    if mode == "on":
        return _deny(MANAGED_DENY.format(why=why), tool="bash", target="managed-shell"), None
    sid = str(payload.get("session_id") or os.environ.get("CLAUDE_CODE_SESSION_ID") or "")
    mark = None
    try:
        safe_sid = re.sub(r"[^A-Za-z0-9_-]", "_", sid or "nosession")[:80]
        mark = paths.session_dir() / f"{safe_sid}.managed-warned"
        if mark.exists():
            return None, None
        mark.parent.mkdir(parents=True, exist_ok=True)
        mark.write_text("")
    except (OSError, paths.PathError):
        pass
    try:
        audit.log("managed", outcome="warn", why=why[:120])
    except Exception:  # noqa: BLE001
        pass
    return None, MANAGED_WARN.format(why=why)


def main(payload: dict) -> dict | None:
    """Hook output (deny / ask / allow) or None (SPEC 8)."""
    ti = payload.get("tool_input") or {}
    if not isinstance(ti, dict):
        return None
    if payload.get("tool_name") == GW_JOB_TOOL:
        rname = _remote_name(ti.get("host"))
        if rname is UNKNOWN_HOST:
            return _deny("gateway: that job's host isn't a host in gateway.toml (give a host's name "
                         "as gate status lists it, or its id from the snapshot); nothing was "
                         "started", tool="job_start", target="host")
        if rname:
            return _main_job(payload, _as_ssh(rname, ti))
    if payload.get("tool_name") in (JOB_TOOL, GW_JOB_TOOL):
        return _main_job(payload, ti)
    if payload.get("tool_name") == GW_SEND_TOOL:
        text = ti.get("text")
        if not isinstance(text, str) or not text.strip():
            return None
        host = _terminal_host(ti.get("id"))
        if host:
            return _main_job(payload, _as_ssh(host, {"command": text}))
        return _main_job(payload, {"command": text})
    notice = None
    if os.environ.get("GW_MANAGED_CHECK") == "1" and payload.get("tool_name") in MANAGED_TOOLS:
        final, notice = _managed_gate(payload)
        if final is not None:
            return final
    out = _main_command(payload, ti)
    if notice:
        out = dict(out or {})
        out["systemMessage"] = notice
    decision = ((out or {}).get("hookSpecificOutput") or {}).get("permissionDecision")
    # with the gateway's own allow or ask (no decision: Claude Code's prompt
    # shows the command itself), the target of a sudo is named to the person
    if decision in ("allow", "ask") and isinstance(ti.get("command"), str):
        try:
            el = _elevation_notice(ti["command"])
        except Exception:  # noqa: BLE001 - a notice is never worth a failed hook
            el = None
        if el:
            out = dict(out or {})
            out["systemMessage"] = (out["systemMessage"] + "\n" + el) if out.get("systemMessage") \
                else el
    return out


def _main_command(payload: dict, ti: dict) -> dict | None:
    command = ti.get("command")
    if not isinstance(command, str) or not command.strip():
        return None
    mode = payload.get("permission_mode") or ""
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else None
    # The user's own Terminal panel (mcp__terminal__run_in_terminal) runs in
    # their login shell: no stand-ins, the real sudo and their own ssh keys.
    # The denies and asks apply there too, but the gateway never vouches for
    # such a command (its rights don't reach that shell).
    in_user_terminal = payload.get("tool_name") == "mcp__terminal__run_in_terminal"
    return _decide(command, payload, mode, cwd, in_user_terminal)


UNKNOWN_HOST = object()     # a gw job's host word that names no host gated would run it on


def _remote_name(host: object) -> Any:
    """A gw job's `host` (PLAN-v4 phase 6): None for localhost (absent, "",
    "localhost" or this machine's id, as gated's `_host` reads them), the
    form host's name for a remote one, resolved exactly as gated resolves it
    (`daemon.resolve_remote_host` over the same files: a name, its assigned
    id, or its verified machine token), else UNKNOWN_HOST (denied: a word
    the hook can't tie to a host is never judged as some other command)."""
    if host is None or host in ("", "localhost"):
        return None
    if not isinstance(host, str):
        return UNKNOWN_HOST
    from .daemon import read_host_maps, resolve_remote_host
    try:
        f = formmod.load()
        names = [n for n, h in f.hosts.items() if not h.is_local]
        ids, saved = read_host_maps(paths.gated_dir())
        name = resolve_remote_host(host, names, ids, saved)
    except Exception:  # noqa: BLE001 - gated can't resolve it either (no form): no_host
        name = None
    if name is not None:
        return name
    from .daemon import is_local_host
    if is_local_host(host):
        return None                               # this machine's own id: gated runs it here
    return UNKNOWN_HOST


def _hostname() -> str:
    import socket
    return socket.gethostname()


def _terminal_host(tid: object) -> str | None:
    """The remote host of a gateway terminal (gated's records, metadata
    only), None for a local one or one the records don't know."""
    if not isinstance(tid, str) or not re.fullmatch(r"[tj]_[0-9A-HJKMNP-TV-Z]{26}", tid):
        return None
    try:
        raw = json.loads(paths.gated_terminals().read_text(encoding="utf-8"))
        for d in raw.get("panes") or []:
            if isinstance(d, dict) and d.get("id") == tid:
                h = d.get("host")
                return h if isinstance(h, str) and h != "localhost" else None
    except (OSError, ValueError, AttributeError):
        return None
    return None


def _as_ssh(host: str, ti: dict) -> dict:
    """A remote job or a remote terminal's text judged as what it is: a
    command on that host, `ssh HOST CMD` (its ssh and sudo rights, the
    remote sudo rules), never as a local command."""
    out = {}
    for c in _job_commands(ti):
        out.setdefault("commands", []).append(f"ssh {shlex.quote(host)} {shlex.quote(c)}")
    return {"command": "\n".join(out.get("commands", [])) or None}


def _job_commands(ti: dict) -> list[str]:
    """What a checkpoint job runs: `command`, or `argv` shlex-joined (as
    checkpoint's jobs.start does: it refuses both or neither, but both are
    judged if both come)."""
    out = []
    c = ti.get("command")
    if isinstance(c, str) and c.strip():
        out.append(c)
    a = ti.get("argv")
    if isinstance(a, list) and a and all(isinstance(x, str) for x in a):
        out.append(shlex.join(a))
    return out


def _job_cwds(payload: dict, ti: dict) -> list[str]:
    """Where a checkpoint job may start: its `cwd` (checkpoint resolves a
    relative one from its server's folder, the project), else the project
    folder (CLAUDE_PROJECT_DIR); the session's cwd counts as a candidate too.
    Used only for denies (a word protected from any candidate is denied)."""
    bases = [c for c in (payload.get("cwd"), os.environ.get("CLAUDE_PROJECT_DIR"))
             if isinstance(c, str) and os.path.isabs(c)]
    jc = ti.get("cwd")
    if isinstance(jc, str) and jc:
        return [jc] if os.path.isabs(jc) else [os.path.join(b, jc) for b in bases]
    return bases


def _main_job(payload: dict, ti: dict) -> dict | None:
    """A checkpoint job (JOB_TOOL): Bash's denies, an "ask" right denied,
    never allow."""
    mode = payload.get("permission_mode") or ""
    cwds = list(dict.fromkeys(_job_cwds(payload, ti))) or [None]
    for command in _job_commands(ti):
        d = _decide(command, payload, mode, cwds[0], False, in_job=True,
                    more_cwds=tuple(c for c in cwds[1:] if c))
        if d is not None and d["hookSpecificOutput"]["permissionDecision"] == "deny":
            return d               # only a deny: never allow or ask for a job
    return None


def _decide(command: str, payload: dict, mode: str, cwd: str | None, in_user_terminal: bool,
            in_job: bool = False, more_cwds: tuple[str, ...] = ()) -> dict | None:
    """Decide on one command line (a Bash / Monitor / Terminal panel command,
    or what a checkpoint job runs)."""
    if _names_form(command):
        try:
            consent.ratchet()
        except Exception:  # noqa: BLE001
            pass

    # Deny 2 (raw): disabling git's credential redaction. Fires even when the
    # assignment prefix makes the command otherwise unparseable.
    if _GIT_TRACE.search(_QUOTES.sub("", command)):
        return _deny("gateway: don't disable git's credential redaction "
                     "(GIT_TRACE_REDACT); it would print tokens. Run git normally.",
                     tool="git", target="GIT_TRACE_REDACT")

    segs = bashparse.parse(command)
    if in_user_terminal and "#" in command:
        # An interactive zsh without INTERACTIVE_COMMENTS (its default) runs
        # `# …` as words, and the rest of the line too: deny and ask on that
        # reading as well (this tool never gets allow anyway).
        literal = bashparse.parse(command, comments=False)
        if literal != segs:
            d = _judge(literal, command, payload, mode, cwd, in_user_terminal)
            if d is not None:
                return d
    return _judge(segs, command, payload, mode, cwd, in_user_terminal, in_job, more_cwds)


def _judge(segs: list | None, command: str, payload: dict, mode: str, cwd: str | None,
           in_user_terminal: bool, in_job: bool = False,
           more_cwds: tuple[str, ...] = ()) -> dict | None:
    """Decide on one reading of the command (bashparse's segments). in_job: a
    checkpoint job (an "ask" right is denied, never allow)."""
    if segs is None:
        # Too complex to judge: no deny or allow, but an "ask" right the
        # command may use is still asked about (the stand-ins rely on it),
        # and `gate secret` named in it is denied (review round 5).
        if _names_gate_secret(command):
            return _deny(DENY_GATE_SECRET, tool="gate", target=GATE_USER_SUBCMD)
        # a credential tool the parser can't follow (by a path, or after PATH=...,
        # GIT_SSH_COMMAND=..., an alias, a function, inside a shell string or
        # eval): managed mode refuses it (the text scan)
        _form, eff0 = _load_rights()
        if eff0.shell.managed != "off":
            d = _route_text(command)
            if d is not None:
                return d
        fb = _fallback_ask(command, *_load_rights())
        return _ask(*fb, in_job=in_job) if fb else None
    stages = [st for seg in segs for st in seg]
    firsts = [k == 0 for seg in segs for k in range(len(seg))]
    if not stages:
        return None

    # Deny 1: curl/wget in command position, also behind a wrapper
    # (`command curl`, `busybox wget`, `env curl`, `timeout 5 curl`).
    for st in stages:
        argv, base = _command(st, fork=True)
        if base in ("curl", "wget"):
            return _deny_curl(base)
        # The az stand-in gives a token only to a program that parses it; as
        # Claude's own command (Bash, Monitor) it would print it to Claude.
        if base == "az" and "get-access-token" in argv and not in_user_terminal:
            return _deny("gateway: az account get-access-token gives tokens only to programs (an "
                         "Azure SDK, with scripts = true for the azure account), never to your own "
                         "command; use the http tool with the azure account instead.",
                         tool="az", target="get-access-token")

    # Deny 1b (review round 5): `gate secret` is the user's, in every tool;
    # gate export/import/copy-to not in the user's Terminal panel.
    d = _deny_gate_user(stages, command, in_user_terminal, in_job)
    if d is not None:
        return d

    # Deny 2: sensitive paths / helpers.
    tp = payload.get("transcript_path")
    d, cwd_known, stage_cwds = _deny_sensitive(stages, cwd,
                                               tp if isinstance(tp, str) else None, more_cwds)
    if d is not None:
        return d

    form, eff = _load_rights()

    # Alternate routes around the stand-ins (managed mode; PLAN-v4 phase 7)
    d = _alternate_route(stages, eff, command)
    if d is not None:
        return d

    ask: list[tuple[str, str]] = []
    hidden = False                     # the words may hide an "ask" right: scan the text
    for st in stages:
        argv, base = _command(st)
        if not argv:
            continue
        if base in _HIDDEN_RUNNERS or base in _LOOP_WORDS:
            hidden = True
        if base in _FB_SSH_WORDS | _SUDO_NAMES and any(getattr(st, "expands", None) or []):
            hidden = True              # `ssh $H x`: the target is a variable
        if base == "gate":
            # gate check / rotate / copy-to log in to the host with Claude's
            # key: off in the form denies; "ask" in the form or in effect asks
            # (the helpers then honour "ask" only for this typed command or a
            # pop-up job). A widening still waiting is not denied here: gate
            # check is how the user approves it.
            for name in _gate_hosts(argv, form):
                r = _form_right(form, name, "ssh")
                if r is False:
                    return _deny_right(name, "ssh")
                if r == "ask" or _eff_right(eff, name, "ssh") == "ask":
                    ask.append((name, "ssh"))
            continue
        if base == "git":
            if any(ssh_args.has_sudo_word(v) for v in _git_remote_programs(argv)):
                return _deny("gateway: git's --upload-pack / --receive-pack / --exec (or "
                             "remote.*.uploadpack) can't run sudo through the gateway; run the "
                             "root command as `ssh HOST sudo CMD` on its own.", tool="git")
            continue
        if base in ("sudo", "ssh", "scp", "sftp", "rsync"):
            # the policy's decisions, each action on its own (PLAN-v4 phase 7):
            # a deny with its rule, an "ask" asked; the rights below still apply
            for name, act, dec in _policy_hits(base, argv, form, eff):
                if not _POLICY_RULE.match(dec.rule):
                    continue           # a right itself (ssh, sudo, use): judged below
                if dec.word is False:
                    return _deny(dec.message(), tool=base, target=name)
                if dec.word == "ask":
                    if base in ("scp", "sftp", "rsync") and not (in_user_terminal or in_job):
                        return _deny_transfer_ask(base, name, act)
                    ask.append((name, act))
        if base == "sudo":
            r = _right(form, eff, "localhost", "sudo")
            if r is False:
                return _deny_right("localhost", "sudo")
            if r == WAIT:
                return _deny_wait("localhost", "sudo", form, eff)
            if r == "ask":
                ask.append(("localhost", "sudo"))
        elif base in ("ssh", "scp", "sftp", "rsync"):
            targets, _ = _scan_family(base, argv)
            if base == "sftp" and _scan_transfer(base, argv).subsystem:
                return _deny("gateway: sftp -s isn't available here (a path there runs a command "
                             "on the host as its sftp server); use plain sftp HOST:PATH, or "
                             "scp.", tool="sftp")
            sudo_cmd, sudo_word = _remote_sudo(base, argv)
            for t in targets:
                name = _resolve_host(t, form)
                if name is None:
                    continue
                r = _right(form, eff, name, "ssh")
                if r is False:
                    return _deny_right(name, "ssh")
                if r == WAIT:
                    return _deny_wait(name, "ssh", form, eff)
                if r == "ask":
                    if base != "ssh" and not (in_user_terminal or in_job):
                        return _deny_transfer_ask(base, name, "ssh")
                    ask.append((name, "ssh"))
                if sudo_word:          # remote sudo: the host's sudo right decides too
                    rs = _right(form, eff, name, "sudo")
                    if rs is False and sudo_cmd:
                        return _deny_right(name, "sudo")
                    if rs == WAIT and sudo_cmd:
                        return _deny_wait(name, "sudo", form, eff)
                    if rs == "ask":
                        if base != "ssh" and not (in_user_terminal or in_job):
                            return _deny_transfer_ask(base, name, "sudo")
                        ask.append((name, "sudo"))
    if ask:
        return _ask(ask[0][0], ask[0][1], ask[1:], in_job=in_job)
    if hidden:
        # a shell, eval or exec behind a wrapper (`env bash -c 'ssh h x'`), a
        # loop, or a target in a variable
        fb = _fallback_ask(command, form, eff)
        if fb:
            return _ask(*fb, in_job=in_job)

    if in_job:
        return None    # never allow a job: Claude Code's own permission check decides
    if mode in ("auto", "bypassPermissions") and cwd_known and not in_user_terminal:
        try:
            roots = _read_roots(cwd)
        except Exception:  # noqa: BLE001 - no roots: no file read is vouched for
            roots = None
        if len(stage_cwds) == len(stages) and all(
                _stage_allowed(st, form, eff, c, f, roots)
                for st, c, f in zip(stages, stage_cwds, firsts)):
            if all(_argv_meta(st)[0][0] in BENIGN for st in stages):
                return _out("allow", READ_ALLOW)
            return _out("allow", "gateway: allowed (host/account rights in gateway.toml).")
    return None
