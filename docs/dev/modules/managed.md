# Managed execution (gate-sh, managed.py)

PLAN-v4 phase 4 (2026-10-20), reworked by PLAN-0.11 §1.6-§1.8 (0.11.0).
Code: `plugins/gateway/hooks/gate-sh` (the prefix, POSIX sh),
`src/gateway/managed.py` (its settings, rc and state, the host inspection),
`[shell]` in `form.py`, its consent in `consent.py` (`_shell`,
`approved_shell`, `EffectiveShell`), the env file (`envfile.env_text`),
`hooks_bash.py` (`_managed_gate`'s notice, the route checks) and the mod
(`hooks/mod/register.tsx` `managedSetup`/`managedNow`, `hooks/mod/lib.ts`
`managedPlan`/`parseManagedState`/`managedLines`). Tests:
`tests/test_managed.py`, `tests/test_posture.py`, the mod's `register.test.ts`
and `lib.test.ts`; mutations: `tests/mutations_managed.py`,
`tests/mutations_posture.py`; live: `tests/acceptance_managed.py`. Why it is
built this way: [DECISIONS.md](../DECISIONS.md), "PLAN-v4 phase 4: managed
execution" and "0.11.0"; the platform facts:
[FEASIBILITY-v4.md](../FEASIBILITY-v4.md) P2.

## What it does

In managed mode Claude's Bash runs in the gateway's own bash (bash 5 from the
gateway's pixi env) with the user's own environment: the inherited variables
minus Claude Code's own credentials, the variables that make a shell run code
at startup, and the gateway's internal names. The gateway's stand-ins come
first on PATH, only for what gateway.toml configures, and nothing the user's
snapshot defines can shadow them. It covers every route Claude Code runs a
command by: the Bash tool, `run_in_background`, Monitor, the user's `!`
commands, subagents' Bash and skills' `!` injection all go through Claude
Code's one shell function, which honours `CLAUDE_CODE_SHELL_PREFIX`.

Since 0.11.0 the managed shell is a convenience, not a guard: when it isn't
ready, Claude's commands run without its settings in the shell Claude Code
itself uses, and without the mod in the user's own shell, with a notice
either way; the classic Bash hook judges them the same way.

```
Claude Code ── <shell> -c "'<root>/hooks/gate-sh' '<script>'"      (Bash tool, !, subagents, ...)
            ── /bin/sh -c "'<root>/hooks/gate-sh' '<hook string>'"  (classic shell-form hooks)
gate-sh  ├─ a hook string (anything without a Bash-tool script's shape): exec /bin/sh -c STRING
         └─ a Bash-tool script: snapshot `source` replaced by `. rc.bash <bash snapshot>`, the rest
            unchanged, exec env -u NAME... PATH=... SHELL=... <managed bash> --noprofile --norc -c
            ". rc.bash SNAP && <rest>" (the removals by name; no value on argv)
            not ready: exec env -u NAME... <the shell that made the snapshot> -c '<script>'
            (found as Claude Code finds its shell; never /bin/sh), one notice
```

## Settings: `[shell]` in gateway.toml

```toml
[shell]
managed = "on"            # "on" (default) | "off"; true/false mean on/off
import_path = ["/opt/homebrew/bin", "~/.cargo/bin"]   # host folders for the managed PATH
import_env = ["JAVA_HOME"]                            # names listed in gate status
```

- **on**: the mod sets the prefix. Without it (no mod) commands run in the
  user's own shell with a notice once per session, still judged by the hook.
- **off**: no prefix; Claude Code's own shell. The env file still puts the
  present stand-ins first and removes Claude Code's own credential
  variables.
- `"warn"` is gone (0.11.0): written, it is a mistake (`gate status` names
  it) and counts as "on".

Consent (`consent._shell`, the "settings" pseudo-entry, `SHELL_RANK = {"off":
0, "on": 1}`): turning `managed` off, a new `import_path` folder and a new
`import_env` name are widenings, effective only after the user's OK in the
gateway dialog (`gate check settings`); until then the approved values apply.
Turning it on and removing an import are narrowings, effective at once and
ratcheted into the approval. A bad `managed` value counts as "on" and
changes nothing in the approval.

`import_env` no longer changes what reaches Claude's shell (the inherited
environment keeps those names anyway, minus the removals); it is still
validated and listed (`managed.env_plan`). A remote host's runtime has its
own, `[hosts.NAME.shell] import_env`, which still copies values from that
host's login environment (remote.md).

Validation (`form.import_path_entry`, `form.import_env_entry`):
`import_path` takes absolute folders or `~/...` (expanded with the user's
home), no `:`, nothing unsafe, never inside `~/.config/gateway`; at most 32.
`import_env` takes variable names, refuses those always passed (HOME, LANG,
...), credential-looking names (TOKEN, SECRET, PASSW, PASSPHRASE, CRED, API_KEY,
ACCESS_KEY, PRIVATE_KEY, CLIENT_KEY, CLIENT_CERT, AUTH, COOKIE, SESSION_KEY:
an account holds those), and what would change how a shell, the loader or
the stand-ins work (PATH, IFS, ENV, BASH_ENV, BASH_FUNC_*, SHELLOPTS, PS*,
PROMPT_COMMAND, CDPATH, LD_*, DYLD_*, GIT_SSH*, GIT_ASKPASS, GIT_CONFIG*,
SSH_*, SUDO_*, RSYNC_RSH, the gateway's and Claude Code's own); at most 32. A
bad entry is left out with an error.

## The mod (session start)

`managedSetup` runs first in `session.start`, before the daemon or the dialog
loop: it reads `$DATA/managed/state.json` (a missing or garbled file counts as
"on"), then sets `GW_MANAGED_DIR=$DATA/managed`, `CLAUDE_CODE_SHELL_PREFIX=
<root>/hooks/gate-sh` unless the effective mode is "off", and, once the env is
built, `CLAUDE_CODE_SHELL=<the env's bash>` (Claude Code honours it when it is
set before its first shell use, so the shell it starts gate-sh from is the
managed bash, not the login shell: no `~/.zshenv` per command). A plugin path
holding " -" can't be carried by the prefix (Claude Code splits a prefix at
its last " -" to take flags): no prefix then, and the commands run in the
user's own shell with the classic hook's notice.
`state.json` sits in the data folder, which a command can rewrite, so the mod
takes only two things from it: the mode, and whether the data folder's gate-sh
copy is the prefix (only that exact path, and only while the copy's text is
the plugin's gate-sh, which the mod compares). `CLAUDE_CODE_SHELL` comes from
`launch.sh status` (the env it names, `<env>/.pixi/envs/default/bin/bash`, set
only when that env is ready), never from `state.json`'s `bash` (phase 4
review: a rewritten `bash` made Claude Code start every command, gate-sh
included, from another program with the full environment).
Another plugin's or the user's prefix is replaced (named in `/gate-doctor`).
Before the prefix, where Claude Code's own `SHLVL` is missing, empty, 0, not a
number or 999 and up, the mod sets `SHLVL=1` (0.9.1; `lib.ts` `shlvlOk`): bash
started as `-c` with a socket on stdin, which is how Claude Code starts the
shell it runs the prefix from, sources `~/.bashrc` before the command at shell
level 1 (below, "Known limits"). In `-p` and SDK sessions the same happens (the
mod runs there too). The mod writes exactly these four variables (`claude
plugin validate`'s "env writes", pinned by `test_mod`); with the mode "off" it
writes only `GW_MANAGED_DIR`.

`/gate-doctor` prints the mode, whether this session's prefix is active (from
the process environment, so also after `/reload-plugins`), the managed bash
and its version, the PATH and the imported variables with their origins, and
what waits for the user's OK.

## gate-sh

One argument (Claude Code passes exactly one; more or fewer: exit 126).

**Hook strings.** Anything that isn't recognisably a Bash-tool script runs as
`exec /bin/sh -c "$1"`, with builtins only before it, so stdin, stdout,
stderr, the environment and the exit status are Claude Code's. macOS's
`/bin/sh` is bash, which counts itself in `SHLVL`: the shell Claude Code
starts the prefix from and gate-sh's own shell are one level each where
Claude Code's `/bin/sh -c` is one, so gate-sh gives one back (dash leaves
`SHLVL` alone). Verified case by case against `/bin/sh -c` directly
(`test_hook_strings_run_exactly_as_claude_code_runs_them_without_a_prefix`)
and live (a probe plugin's hook wrote the same `$0` and environment as
without the gateway, but for the mod's three variables). Exec-form hooks
(`command` + `args`, like the gateway's own) and an organization's managed
hooks are never prefixed by Claude Code; MCP servers started after session start are
(their quoted argv runs through `/bin/sh -c` here, which is the same command).

**Bash-tool scripts** are recognised by their whole shape: Claude Code's cwd
tracker as the last segment (` && pwd -P >| <file>-cwd`, the file one word,
bare or quoted the way Claude Code quotes it) together with an eval of the
command (`eval ` first or ` && eval `), or a first segment that sources a
shell snapshot (`source <...>/shell-snapshots/snapshot-...`). Anything else
is a hook string, also when it mentions a snapshot or holds the tracker's
text elsewhere (phase 4 review: such hooks were refused with 126; checked by
`HOOK_CASES`). The shape (2.1.301, bash and zsh alike): `source <snapshot> 2>/dev/null || true`
(absent when Claude Code couldn't make a snapshot), the session's env-file
text (every plugin's `CLAUDE_ENV_FILE` output, inline, then `\n:`), Claude
Code's own segments (TMPDIR, the gh stand-in PATH, GIT_CONFIG_PARAMETERS,
`shopt`/`setopt`, `unalias unsetenv`, its credential scrub when enabled),
`eval '<command>' [< /dev/null]`, the cwd tracker. gate-sh refuses (exit 126,
"doesn't recognize", nothing run) a script that starts with the snapshot's
`source` but lacks the rest of the shape (no `eval`, no tracker, or anything
after it), a first `source` of anything but
`.../shell-snapshots/snapshot-*.sh`, or a tool-shaped script that names a
snapshot in another segment (never run anywhere: it has a tool script's
shape, so `/bin/sh -c` would be a fallback).

It then replaces only the snapshot's `source` with `. <rc.bash> <bash
snapshot>`, keeps the rest byte for byte (so other plugins' env files, the
eval'd command, the tracker and the exit status are Claude Code's), and runs
`exec /usr/bin/env -u NAME ... PATH=<managed PATH> SHELL=<bash> <bash> --noprofile --norc -c ". rc SNAP && rest"`:
one process from Claude Code's point of view, so its interrupt and timeout
kill it (verified: Escape and a Bash `timeout` stop the command as without
the gateway).

**The environment** (PLAN-0.11 §1.6): the inherited one, which is Claude
Code's, minus by name:

- Claude Code's own credentials: every `CLAUDE_*` or `ANTHROPIC_*` name that
  holds a credential word (`managed.CREDENTIAL_WORDS`: TOKEN, SECRET, PASSW,
  PASSPHRASE, CRED, API_KEY, APIKEY, ACCESS_KEY, PRIVATE_KEY, CLIENT_KEY,
  CLIENT_CERT, AUTH, COOKIE, SESSION_KEY) and a fixed list
  (`CLAUDE_CRED_NAMES`: `CLAUDE_CODE_OAUTH_TOKEN`,
  `CLAUDE_CODE_MESSAGING_TOKEN`, `CLAUDE_CODE_CLIENT_KEY`,
  `CLAUDE_CODE_CLIENT_KEY_PASSPHRASE`, `CLAUDE_CODE_CLIENT_CERT`,
  `CLAUDE_CODE_HOST_CREDS_FILE`, `ANTHROPIC_API_KEY`,
  `ANTHROPIC_AUTH_TOKEN`);
- the variables that make a shell run code or change its parsing
  (`STARTUP_NAMES`: `BASH_ENV`, `ENV`, `SHELLOPTS`, `BASHOPTS`, `PS4`,
  `PROMPT_COMMAND`, `CDPATH`, `IFS`, `GLOBIGNORE`, `BASH_XTRACEFD`) and every
  `BASH_FUNC_*` (exported functions; the user's functions come from the
  snapshot instead), and any name no shell takes as a variable;
- the gateway's internal `GW_*` names except `GW_MANAGED_DIR`.

Everything else is kept: the user's `SSH_AUTH_SOCK`, `GH_TOKEN`, cloud
credentials, proxies and toolchain variables are theirs, for their own
unconfigured tools (a configured stand-in's child still gets a clean
per-call environment: `clis.child_env`, `ssh_conf`, `githelper.gated_env`).
`managed.py` holds the same lists (`CLAUDE_CRED_NAMES`, `STARTUP_NAMES`,
`DROP_PREFIXES`, `GATEWAY_NAMES`, `CREDENTIAL_WORDS`; `managed.dropped(name)`
is the rule in Python) and `test_managed` compares them.

How: gate-sh lists its own environment (`env`, every line holding a `=`
gives a name) and passes `env` a `-u NAME` for every name it removes, so the
kept variables reach the managed bash through the environment and only names
reach any command line (every local user can read a process's arguments:
`/proc/PID/cmdline` on Linux without `hidepid`, `ps` on macOS;
`test_no_value_reaches_a_command_line` records env's arguments and on Linux
also scans every `/proc/*/cmdline` during 40 runs). When `env` itself fails,
gate-sh exits 126 instead of running the command with nothing removed. It
resets `IFS` to the default after the hook-string branch, so an inherited
one never splits anything there.

`GW_MANAGED_DIR` passes so that a Claude Code started from a command (a
`claude -p`, an Agent SDK script, a scratch-config session) stays managed: it
inherits `CLAUDE_CODE_SHELL_PREFIX` and `CLAUDE_CODE_SHELL` and runs its own
commands through gate-sh with this session's managed settings; with the
gateway loaded, its own mod sets all three again.

**PATH**: `$DATA/bin` (the stand-ins present for the configured set), then
the snapshot's PATH (its `export PATH=` line, read, never sourced; Claude
Code's own PATH when there is no snapshot or no such line), then other
plugins' `bin/` folders from Claude Code's PATH (only `X/bin` whose
`X/.claude-plugin/plugin.json` exists) that it lacks, then the approved
`import_path` folders; each folder once.

**Not ready**: `GW_MANAGED_DIR` missing or relative, no `conf`, no managed
bash yet (the env is building, failed, or pixi is too old), no `rc.bash`, or
settings that can't be renewed. gate-sh then runs the script byte for byte
(the snapshot's `source` included) without the gateway's settings, in the
shell that made the script's snapshot (`gw_fallback_shell`, mirrored by
`managed.fallback_shell`; a test compares). The snapshot's name says which
(`snapshot-zsh-*`, `snapshot-bash-*`), and the binary is found the way
Claude Code 2.1.310 finds its shell: `CLAUDE_CODE_SHELL`, then `SHELL` (as
Claude Code has it, in the environment: bash run as sh, macOS's `/bin/sh`,
sets one of its own, the login shell, when there is none), then the
preferred shell on Claude Code's PATH, in `/bin`, `/usr/bin`,
`/usr/local/bin`, `/opt/homebrew/bin`, the other in those places, the
other on PATH; bash is preferred when `SHELL` holds "bash", else zsh. The
first that is the snapshot's shell is taken (Claude Code's naming: a path
holding "zsh" is a zsh, else one holding "bash" a bash): an executable
file by its absolute path, without `=` (env would read it as an
assignment); PATH lookups take absolute folders only. Without a snapshot,
any bash or zsh in that order. Never `/bin/sh`: dash, Debian's, has no
`source`, so the snapshot was skipped without a word. With no such shell
it refuses (126: the snapshot's shell, or a bash or zsh, is needed). Once
the env is built the mod sets `CLAUDE_CODE_SHELL` to the env's bash, so
that is the shell for a bash snapshot. It keeps Claude Code's own PATH and
the same removals, and says on stderr, naming the shell: "gateway: this
command ran without the gateway's managed settings, in SHELL: the managed
shell isn't ready (WHAT). WHY AND WHAT TO DO". The reason comes from file
tests only (`gw_setup_state`, no process started) on the env the settings
name, or on every env when they name none or one that is gone: the data folder gone
(uninstalled or removed: restart Claude Code, or reinstall), a build
running ("still setting up"), setup failed (an env folder with
`install.log` and no `.ready`, no live `.building` lock: the log and
`/gate-doctor`; a lock whose `owner` names a builder and pixi child that
are gone, read with `read` and tested with `kill -0`, both builtins, is
stale: `gw_lock_live`; a lock with no owner file yet counts as live, and
without ps a reused pid looks alive, so the doubt is always "still setting
up"), an env built (`.ready` and its python3) with no build running: "the
managed shell's settings are missing or couldn't be renewed; a new session
writes them again", pixi missing (launch.sh's `find_pixi` places and Claude
Code's PATH: https://pixi.sh), else still setting up (no build started yet);
the failed and pixi-missing sentences are launch.sh's `not_ready_text` ones
(test_managed compares them). The approval hook has judged the command already, and the stand-ins
in `$DATA/bin` (written by launch.sh's cold path) still say "still setting
up" for configured targets. A script with a tool script's shape that
doesn't parse (126) is still refused. **Stale**: when gateway.toml (or the
vault-unlocked marker) is newer than `conf`, gate-sh first runs
`$DATA/managed/sync` (`run.py managed-sync`) so a narrowing applies to this
command even before FileChanged runs; when that can't renew it, the
not-ready path.

## The rc

`managed.rc_text`: `envfile.env_text()` (the env file: the stand-ins first,
Claude Code's credential names unset, the stand-in names' aliases and
functions removed), Claude Code's own helpers its snapshot carries (`rg`
from Claude Code's embedded copy when none is on PATH, its pkill guard;
never a user file), then the user's snapshot and the tail:

- **The snapshot** (`RC_SNAPSHOT`): gate-sh passes a bash snapshot
  (`snapshot-bash-*.sh`) as the rc's `$1`, and the rc sources it (the
  user's aliases, functions and options), then puts the managed PATH back.
  On the latest Claude Code the snapshot is made by `CLAUDE_CODE_SHELL`,
  the managed bash, so it is normally a bash one. A zsh snapshot (made
  before the prefix applied) gives only its PATH line; its aliases and
  functions don't carry (a stated limit; `[shell] import_path` and the
  session's offer cover a zsh user's PATH).
- **The tail** (`managed.rc_tail`), every line alias-proof (a backslash
  before each command word, no reserved word): POSIX mode by assignment
  (`POSIXLY_CORRECT=y`, so special builtins come before functions); the
  snapshot's `DEBUG`, `RETURN` and `ERR` traps cleared; the functions and
  aliases of `TAIL_BUILTINS` (`command builtin hash type unalias unset exec
  source . test shopt trap readonly`) and of every stand-in present in
  `$DATA/bin` (checked with `test -e` at run time) removed; then it fails
  closed, through a `${VAR:?TEXT}` expansion error that ends the bash
  before the command, when POSIX mode didn't take (a read-only
  `POSIXLY_CORRECT`: `TAIL_NO_POSIX`) or one of those functions survived
  (read-only, found with the special builtin `readonly -f`:
  `TAIL_READONLY`); then POSIX mode off (alias expansion back on where the
  snapshot had it), `hash -r`.

`test_managed` defines hostile aliases and functions with each of these
names, plus `BASH_ENV`, `ENV` and `BASH_FUNC_ssh%%`, and checks that `ssh`
still resolves to the stand-in.

## managed.py: the files

`sync(form, eff)` writes `$DATA/managed/` (0700) whole (temp file, then
rename): `conf` (0600; `bash=`, `rc=`, `standins=`, `imports=`, `form=`,
`sync=`, `unlocked=`, read line by line by gate-sh, never sourced),
`rc.bash` (0600; `rc_text`, above), `state.json` (0600; mode, form mode,
bash and version, readiness, PATH and variables with origins, pending
widenings, whether the vault was readable, the tool folders found), `sync`
(a stub like the stand-ins', `run.py managed-sync`), and a copy of gate-sh
when an install dropped its executable bit. `conf` is written last and
never dated before gateway.toml.

Who writes them: SessionStart (`envfile.sync`), `launch.sh ensure-env` right
after a build and before the env's warm-up, FileChanged on gateway.toml,
`consent.approve("settings")`, gate-sh's renewal (`run.py managed-sync`), and
the first command after a vault unlock (gated's broker touches
`<run>/gated-unlocked`; approved imports are inside the vault, so a session
started with a locked vault has the defaults until then).

`status_lines(eff)` is `gate status`'s section: the mode (and a pending
change), the bash, every PATH folder with its origin ("the gateway's
stand-ins", "gateway.toml [shell] import_path, line 4; Homebrew"), the
listed variables, what waits for the OK.

## Without the prefix (PLAN-0.11 §1.8)

No blanket refusal. Without the mod (switched off, a path holding " -"), or
with another plugin's prefix, Claude's commands run in Claude Code's own
shell: it sources the user's snapshot, then the env files. The gateway's env
file prepends `$DATA/bin` and, inside Claude Code (`CLAUDECODE` set),
`unset`s Claude Code's own credential names and runs `unalias` and `unset
-f` on every stand-in name present in `$GW_BIN` (POSIX, idempotent under
`set -eu` in sh, dash, bash and zsh: `unalias x 2>/dev/null || :`), so a
snapshot alias can't skip a stand-in the hook judged. The classic Bash hook
enforces every right, policy and per-mode value, the network class and the
configured-only route check as usual; `hooks_bash._managed_gate` adds one
notice per session (`MANAGED_NOTICE`, a marker in the session dir) to a
call that reaches Python while the effective mode is "on". The env file no
longer sets `GIT_SSH_COMMAND` or `RSYNC_RSH`, injects a git include, or
unsets the user's own variables.

## Host inspection (the gw tool `host_inspect`)

`managed.inspect(host, project)`: read-only and scoped, for proposing imports.
It reads `/etc/paths`, `/etc/paths.d/*`, `/etc/zprofile`, `/etc/zshenv`,
`/etc/profile`, `/etc/environment` and the user's `.zshenv .zprofile .zshrc
.zlogin .bash_profile .bash_login .profile .bashrc .config/fish/config.fish`
as text (≤ 256 KiB each) and reports only folder names from PATH lines
(`export PATH=...`, zsh `path+=(...)`, fish `fish_add_path`), with `~`,
`$HOME` and `${HOME}` expanded and any word needing more evaluation left out,
plus the folders well-known setup lines add (`brew shellenv`, `pyenv init`,
`~/.cargo/env`, `rbenv init`, `mise activate`, `asdf.sh`); it lists
well-known toolchain folders (Homebrew, MacPorts, pixi global, ~/.local/bin,
pyenv, nvm, rustup/cargo, Go, SDKMAN, asdf, mise, rbenv, conda, Deno, Bun,
Volta, juliaup, Nix, snap, ~/bin) with up to 12 programs each; the project's
toolchain files (`.python-version`, `.nvmrc`, `.tool-versions`,
`rust-toolchain(.toml)`, `go.mod`, `pyproject.toml`'s requires-python,
`package.json` engines, ...) with a version word only, else "present"
(`.envrc` is named and never run); and the names (never values) of Claude
Code's variables `import_env` would take. Nothing is run or sourced, the
gateway's own folders are left out, the answer goes through the scrubber, and
looking imports nothing. Since PLAN-v4 phase 7 it is decided by this
machine's `read` policy, and a remote host is inspected through gated
(remote.md, "Policy, inspection and imports"). `mcp_perm.sh` allows it in
every mode.

**Found but not imported** (GW-UX-2b, `managed.found_not_imported`): the
same reading (the login PATH folders, then the toolchain folders) gives the
folders that hold programs and that the managed PATH lacks (not the system
folders, `/System/`, `/Library/Apple/`, `/usr/libexec/`, what is imported or
the gateway's own; at most 8, plain characters only). While the form has no
`[shell] import_path` key at all (an explicit `import_path = []` says no) and
the mode isn't "off", Claude's session context names them and says to
propose importing them (`hooks_session.IMPORT_OFFER`: one form edit, then
`gate check settings` and the consent dialog; only when it fits the
context's 2500 characters, after the hosts and accounts); `state.json` carries them as
`found`, so `/gate-doctor` lists them, and so does `gate status`. Nothing is
imported by finding them.

Imports (`[shell] import_path` / `import_env`) apply only while this
machine's `env_import` policy is allow (`managed.imports_allowed`;
`path_plan`, `env_plan` and the conf follow it), so `env_import = "deny"`
takes them out at once (a narrowing).

## Alternate routes

The stand-ins are first on PATH, so `ssh`, `scp`, `sudo`, `git`, `gh`, ... by
their bare names reach the gateway. The approval hook also refuses the ways
around them, **only when they reach a configured target** and **in every
mode**, managed shell on or off and mods off included (PLAN-0.11 §1.7;
`hooks_bash._alternate_route`, `_route_argv`, `_reaches`). Nothing
configured: nothing to refuse. The target is resolved with the configured
set (names, `gw-NAME`, addresses, `also` entries, account hosts and owners)
and, for git, the shared resolver (`gitroute`: a repository with a
configured remote). Each refusal names the stand-in route ("goes around the
gateway's ssh stand-in, and homelab goes through the gateway; use `ssh
homelab ...`"), never `managed = "off"`. `gate with NAME --` is unwrapped
first, nested ones however deep (in text, only right after a command start,
and only an entry's name counts as the account). Program names are compared
without letter case (`_prog`; macOS's file systems ignore it, so
`/usr/bin/SSH box`, `ENV -i ssh box` and `COMMAND -p ssh box` are routes
too).

- a tool (`ROUTE_TOOLS`: ssh, scp, sftp, slogin, ssh-add, ssh-agent,
  ssh-copy-id, sudo, sudoedit, gh, hf, huggingface-cli, az, databricks,
  crane, pijul, dvc, rsync, git, su, doas, pkexec, runuser) by a path
  (`/usr/bin/ssh homelab`, `./sudo`), unless the path is the stand-in
  itself; an account CLI by path is refused while an account of its kind
  exists, since its destination can't be told from the words (lead
  decision 19.10: run it by its name and the stand-in passes an
  unconfigured destination to the user's tool); target-less tools by path
  (`/usr/bin/ssh-add -l`) get no decision;
- tools with no stand-in by any name: slogin to a configured host ("use
  `ssh HOST ...`"), and huggingface-cli (hf's older name) while a
  huggingface account exists ("run the same command as `hf ...`": hf's
  stand-in gates it); both are trigger words in pre_bash.sh;
- a login shell or PATH-resetting wrapper running a stand-in name (`bash
  -l`, `zsh -l`, `sh -l`, `su`/`su -`, `sudo` (secure_path), `sudo -i`,
  `doas`, `env -i`, `env -`, `env -u PATH`, macOS's `env -P DIRS`, `command
  -p`): they rebuild PATH, and on macOS path_helper puts `/usr/bin` first, so
  they count as a tool by path; pre_bash.sh forwards an account CLI's plain
  name beside any of these (`test_every_posture_deny_row_reaches_python`);
- a PATH or transport change for a command or in an earlier stage of the
  same command (`PATH=`, `hash -p`, an alias, `GIT_SSH`, `GIT_SSH_COMMAND`,
  `RSYNC_RSH`, `SUDO_ASKPASS`, git's configuration from the environment,
  `rsync -e/--rsh` also inside combined short options, `git -c
  core.sshCommand=`/`ssh.variant=`, `-o ProxyCommand=`, `-o HostName=`), and
  the words of such a transport line itself;
- `ssh -J` or `-o ProxyJump=` naming a configured host, and a ProxyCommand
  naming a configured address;
- in a repository with a configured remote, `git config` writes to the
  guarded keys (`credential.*`, `core.sshCommand`, `url.*`, `remote.*.url`,
  `remote.*.pushurl`, `remote.*.proxy`, `include.*`, `includeIf.*`,
  `core.hooksPath`, `core.fsmonitor`, ...: `githelper.GUARDED`; the git
  stand-in refuses them too), a `!` alias, and `-c` pairs that set
  credentials, includes or the ssh command;
- a written-out command string (a shell's or su's `-c`, trap's action, an
  alias's value, a `-C` callback), parsed and judged like the outer command.

While this computer's sudo is configured, su, doas, pkexec, runuser,
sudoedit (by its bare name: sudo's own binary, but no stand-in supplies its
password) and osascript's `with administrator privileges` are denied ("use
sudo; the gateway supplies its password in its dialog"), also in text the parser can't
follow (`_other_elevation`, `_elevation_tool`, `_text_elevator`); with only
an elevation restriction here its deny denies and its "ask" asks; otherwise
they are the user's own. They are never allowed.

**Commands that hide their program or host** (`_hidden_rule`): a variable,
computed, globbed or brace-expanded program (`{/usr/bin/ssh,box} id`), a
variable `-c` string (also after a value option: `bash -o posix -c
"$CMD"`), `eval` and `source`/`.` (also behind `builtin`, `command`,
`time`, `!`, a reserved word or a case arm), `exec` running a program, a
function definition, a computed trap, alias or `-C` callback, `coproc`, an
osascript script that starts with a variable, an ssh-family, git, gate or
sudo stage whose target is a variable, and what runs below xargs, parallel
or find -exec (`_TEXT_HIDES`, `_TEXT_HIDES_CHILD`, `_text_exec`, `_hides`,
`_alternate_route`). One is refused when its text names a configured name,
address, `also` entry or `gw-NAME` (`HIDDEN_NAMED`, with the spelled-out
form to use); otherwise it gets no decision. What it runs reaches no "ask"
unasked: a stand-in passes an "ask" only for a command Claude typed with
the approval hook's record of that exact command (`asks.py`, invariant 6),
and nothing the hook can't read gets one, so `source ./deploy.sh` needs no
prompt and its `ssh box` is refused by the stand-in ("run `ssh box ...` as
its own command"). git with a variable for its subcommand or remote is
refused while an entry git may reach is "ask" (`GIT_HIDDEN`: no record of
it can be written).

Text the parser can't follow that names an "ask" target with an ssh-family
or sudo word (`_fallback_asks`, every such target named in the prompt), and
a hidden stage of that kind beside a stage the hook asks about, are asked
about, with records for the ssh and sudo commands the hook can read there,
and for the account-CLI and `gate with` commands whose account is "ask"
(`_fallback_records`, never twice for words the structured judge recorded;
and
`_lenient_commands`: quotes and backslashes as the shell reads them,
redirections and here-document bodies dropped, `&`, subshells, `$(...)`
and backquotes split out, eval's words, a shell's `-c` string and trap's
action read too); one whose words hold a variable, `$(...)`, a glob or
`~user`, or whose folder a `cd` hides, is denied instead (`ASK_HIDDEN`).

Known misses of the hidden-command rule (a guardrail): bash's evaluation
of a variable's contents as an arithmetic expression or a prompt (`echo
$((X))`, `[[ $X -gt 1 ]]`, `echo "${X@P}"`, where X holds a `$(...)` in an
array subscript or a prompt), and a command substitution inside a quoted
array subscript (`printf -v 'a[$(...)]' x`, `(( a['$(...)'] ))`): they run
in Claude's shell with no word the rule looks for; a function or alias
from the user's own bash snapshot (below). A configured name in them isn't
refused up front; an "ask" they reach is still refused by its stand-in (no
record). A record lives until the session's next Bash or Monitor call,
whose hook drops it first (a declined prompt's, a stage that never ran):
what else Claude Code runs without a PreToolUse hook (a skill's or slash
command's `!` injection, the user's own `!` commands) isn't covered in
between. The records live in the user's run folder: a process running as
the user could write one (a guardrail, like the typed walk).

For text the parser can't follow (a command substitution, a loop, `sh -c`
strings, `| sh`, a `<<<` here-string into a shell, `find -exec`, `xargs`,
`env -S`), the text scan (`_route_text`) refuses only what reaches a
configured target (`_text_reach`: a configured name in the text, git's
configured repository, this computer's configured sudo, an account of the
tool's kind): a tool named by a path other than the stand-in's where it can
run as a program (`_text_runs`), a stand-in name after a login shell or a
PATH-resetting wrapper or in a plain sudo's own command, and a
PATH/transport change with a tool named after it. Where a tool can run as
a program (`_text_runs`): a path whose
  parent is a `…bin` folder and whose basename is a tool is a program
  **anywhere** except as a plain operand of a command that never runs it (so
  `sudo cat /etc/ssh/sshd_config`, `sudo tee -a /etc/ssh/sshd_config.d/x.conf`,
  `sudo cp x /etc/pam.d/sudo` and `sudo rm /usr/local/bin/gh` pass, but
  `bash -c 'ls -l /usr/bin/ssh'` passes too — `ls` only reads it). A non-bin
  path (`/opt/x/ssh`, `./ssh`, `/etc/ssh`) is a program only in a program
  position — the first word, after a separator, a reserved word, a wrapper
  (env, nohup, sudo, timeout, xargs incl. `-a`, nice, macOS's arch, ...), a
  shell's or su's `-c` string, su's `-s` shell, find's `-exec`, a known
  runner (sshpass, strace, ltrace, dtruss, flock, script, unbuffer, chroot,
  tmux, screen, ssh-agent, watch, ...), or GNU sed's `e` command (also glued to its
  path, `1e/x/ssh`) — or as a transport option's value (rsync `-e`, scp
  `-S`, tar `-I`, `--rsh`, ProxyCommand), glued to `=` (`--rsh=`, `GIT_SSH=`),
  or anywhere in a text piped into a shell or in a shell's `<<<` here-string.
  Only a shell's or su's `-c` (sh, bash, zsh, dash, ..., su, runuser) takes a
  command string; any other program's `-c` is its own option, so `for f in
  *.c; do gcc -c "$f"; done` and `psql -c "$QUERY"` get no decision. The
  runners count as one only as the program itself (after the wrappers, or
  named by a path): `sudo apt install tmux strace` names them as data. awk's,
  vi/vim's and less's script text counts only for a bin-folder path (they
  aren't data commands, so such a path anywhere in their words is a program);
  a non-bin path in it is a limit (below). The commands that never run an
  operand are `_TEXT_DATA` (cat, cp, mv, rm, ls, grep, sed without an `e`,
  chmod, tar/rsync/scp as a local copy, head, tail, wc, echo, printf, test,
  ...; `less` isn't one — it runs `!`). A variable or a command's output as
  the program (`$(which -a ssh) box`; a computed folder with a named
  program, `$(git rev-parse --show-toplevel)/x.sh`, passes; assignments
  before the program are skipped) and a shell's or su's `-c` string that is a
  variable or a command's output (`bash -c "$CMD"`) go to the
  hidden-command rule above. A PATH/transport change, `unset PATH`, `hash
  -p`, `command -p` or `env -i`/`-`/`-u`/`-P`/`-S` with a tool named after it (`sudo
  env -i make` is sudo's own business), an alias or a function named after a
  tool, and git's ssh setting count when that tool reaches a configured
  target.
  Here-documents that are data (`cat > f <<EOF`) aren't read; one a shell
  reads (`bash <<EOF`, `| sh`, `bash <<< '…'`) is. An ssh stage's remote
  command is never scanned (it runs on the host, where remote sudo has its
  own rules). A plain `sudo CMD ARGS` reaches the scan (sudo is a runner),
  but a tool path CMD only reads is data there, so `sudo restorecon /etc/ssh`,
  `sudo tar czf x /etc/ssh` and `sudo make -C ops/ssh install` pass.
  Known misses of the scan (a guardrail's limits; a bin-folder path is still
  refused in each): a non-bin path in awk's, vi/vim's or less's script text
  (`awk 'BEGIN{"/opt/x/ssh h" | getline}'`, vim's `!`); a path after tmux's
  options that follow its subcommand (`tmux new -d /opt/x/ssh`) or after a
  strace option whose value the scan misreads (`strace -s 100 /opt/x/ssh`;
  its table also counts `-A`, `-z`, `-r`, `-x` as taking one); `watch` with
  an option value, `expect`, `entr` and `docker run` running a non-bin path;
  a here-string into a shell nested in another shell string. The other way,
  a bin-folder path as the operand of a program the scan doesn't know is
  refused (`sudo dpkg -S /usr/bin/ssh`, `sudo setcap ... /usr/local/bin/gh`),
  and so is a here-string to a reader (`cat <<< /usr/bin/ssh`) inside hidden
  text. A function or alias from the user's bash snapshot (`deploy`, whose
  body runs `ssh box`) isn't hidden text to the hook: it runs in Claude's
  shell, so an "ask" right it uses passes as typed (the README's Limits).

**The residual limit, stated:** Claude's commands run as the user, with
the user's own agent and token variables (PLAN-0.11 §1.10). A script or
program that runs `/usr/bin/ssh` itself (not typed on the command line the
hook sees), copies a binary, or calls `execve` directly is not seen by any
hook, and a typed command can still be obfuscated past a text scan (a
tool's path decoded at run time inside a string a shell then runs). What it
can't do is get the gateway's credentials: those stay in the vault
(encrypted; with a wrapped key only gated decrypts) and go only to the
stand-ins' children after their checks. What it can do is use the user's
own credentials outside the gateway (their own `~/.ssh` keys and agent, a
`gh` login, a cached sudo timestamp), exactly as any program the user runs
could, and that reaches a configured host whose limits the user's own key
or token also opens. The hook's checks are guardrails against a cooperative
model, not a sandbox (README "Security and privacy").

## Cost

Measured on macOS arm64 for 0.10.0 (2026-10-20): a trivial tool script took
about 23 ms through gate-sh against 4 ms for bash alone (the env listing,
the snapshot's PATH line, `env`, the managed bash and its rc); a hook string
about 12 ms against 5 ms (one more `/bin/sh`). 0.11.0's rc also sources the
user's bash snapshot, whose cost is the user's own. The prefilter starts
Python only for its trigger words, except while the mode epoch marker exists
(a per-mode value makes the mode matter): then every Bash and Monitor call
starts Python once (`hook-mode`). 0.11.0's measurements are in TESTING.md.

## Known limits

- Claude Code starts the prefix through a shell: with `CLAUDE_CODE_SHELL` set
  (the env built before the session's first command) that is the managed
  bash; before that, the user's shell (zsh reads `~/.zshenv`; bash
  `$BASH_ENV`). Claude Code spawns it as `<shell> -c '<prefix> <script>'`
  with stdin a socket (its code adds `-l` when it has no shell snapshot:
  then a bash reads the login files, and Debian's `~/.profile` sources
  `~/.bashrc`; never seen in a run, not prevented), and
  bash with `-c`, not interactive, not a login shell, not `sh`, no
  `--norc`, at shell level 1 (`SHLVL` unset, empty, 0 or garbage before it
  adds one) and a socket on stdin takes itself for an rshd/sshd command and
  sources `~/.bashrc` first (upstream bash's `isnetconn` check in
  `run_startup_files`, on macOS and Linux alike; Debian's build also counts
  `SSH_CLIENT`, under the same shell-level rule). Found on Debian by the
  GitHub install test (0.9.0: a planted rc's line ran with the command's pid,
  its variables and alias didn't reach the command); reproduced with the env's
  bash 5.2 and macOS's bash 3.2 (`test_managed::test_bash_c_with_a_socket_on_
  stdin_sources_bashrc_at_shell_level_1_and_shlvl_1_stops_it`). Claude Code
  offers no way to add `--norc` (`CLAUDE_CODE_SHELL` must be a bash or zsh
  path and gets only `-c`), so the mod makes the shell level 2 instead: it
  sets `SHLVL=1` where it is missing (a Claude Code started from a terminal
  has 1 or more already). gate-sh still discards everything such a shell set
  (removed by name), but not what it did; zsh's `~/.zshenv` (before the env
  is built, a zsh login shell) stays. Claude Code also runs the user's login
  rc once per session to make its snapshot; the gateway never sources the
  snapshot.
- The system prompt still names the user's `$SHELL`; the session context says
  where Claude's commands run.
- Claude Code's snapshot also shadows `find` and `grep` with its embedded bfs
  and ugrep (which skip ignored files); the managed shell runs the system
  `find` and `grep`.
- Without the mod, the user's `!` commands and skills' `!` injection reach no
  hook: they run in Claude Code's own shell (reported, not prevented).
- The generated files live in the plugin data folder; a command could rewrite
  them (a guardrail against a cooperative model, like the gateway's other
  text and ancestry checks, not a sandbox): `conf` names the bash gate-sh
  runs and `rc.bash` what it sources, and the data folder's gate-sh copy (when
  there is one) runs every command. A rewritten `state.json` alone can only
  take the prefix away (the mod takes the managed bash from `launch.sh
  status` and the copy only while it holds the plugin's gate-sh), and then
  the commands run in the user's own shell, still judged by the hook.
- The removals go by name, from the environment's own listing. An entry
  whose name holds a line break (only a
  program calling `execve` directly can make one; bash passes it on, zsh and
  dash drop it) shows up under another name and can't be removed; Claude
  Code never makes one.
- Not managed by design: the desktop app's Terminal panel (the user's own
  shell) and checkpoint's own job runner (its own shell with env.sh), which
  checkpoint uses only when the gateway doesn't serve its session (absent,
  disabled there, an incompatible contract); otherwise checkpoint 0.6+ hands
  each job to gated, which runs it in the managed environment
  (terminals.md).
- A plugin's own background monitors (if any) run through the same shell
  function and so in the managed shell too.
- Other plugins' and tools' variables in Claude Code's environment (for
  example `CHECKPOINT_HOME`, a corporate `HTTPS_PROXY` or `SSL_CERT_FILE`)
  reach Claude's commands (0.11.0). The configured stand-ins' children,
  the gated git included, drop proxy and CA variables.
- The user's own credential variables are in Claude's shell (0.11.0). The
  output masker masks the values of credential-named variables in Claude
  Code's environment; a variable only the shell snapshot exports isn't seen
  by the hook and isn't masked.
- A zsh snapshot gives only its PATH: a zsh user's aliases and functions
  don't reach Claude's commands.
