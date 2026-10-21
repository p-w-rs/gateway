# Managed execution (gate-sh, managed.py)

PLAN-v4 phase 4 (2026-10-20). Code: `plugins/gateway/hooks/gate-sh` (the
prefix, POSIX sh), `src/gateway/managed.py` (its settings, rc and state, the
host inspection), `[shell]` in `form.py`, its consent in `consent.py`
(`_shell`, `approved_shell`, `EffectiveShell`), the "managed shell
unavailable" path in `hooks/pre_bash.sh`, `hooks_bash.py` (`_managed_gate`)
and `hooks/launch.sh` (`degraded_bash`), and the mod
(`hooks/mod/register.tsx` `managedSetup`/`managedNow`, `hooks/mod/lib.ts`
`managedPlan`/`parseManagedState`/`managedLines`). Tests:
`tests/test_managed.py`, the mod's `register.test.ts` and `lib.test.ts`;
mutations: `tests/mutations_managed.py`; live: `tests/acceptance_managed.py`.
Why it is built this way: [DECISIONS.md](../DECISIONS.md), "PLAN-v4 phase 4:
managed execution"; the platform facts: [FEASIBILITY-v4.md](../FEASIBILITY-v4.md) P2.

## What it does

In managed mode Claude's Bash runs in the gateway's own bash (bash 5 from the
gateway's pixi env), with the gateway's rc and a curated environment, never
the user's login shell, its rc files, aliases, functions, PATH or credential
variables. It covers every route Claude Code runs a command by: the Bash tool,
`run_in_background`, Monitor, the user's `!` commands, subagents' Bash and
skills' `!` injection all go through Claude Code's one shell function, which
honours `CLAUDE_CODE_SHELL_PREFIX`.

```
Claude Code ── <shell> -c "'<root>/hooks/gate-sh' '<script>'"      (Bash tool, !, subagents, ...)
            ── /bin/sh -c "'<root>/hooks/gate-sh' '<hook string>'"  (classic shell-form hooks)
gate-sh  ├─ a hook string (anything without a Bash-tool script's shape): exec /bin/sh -c STRING
         └─ a Bash-tool script: snapshot `source` replaced by `. rc.bash`, the rest unchanged,
            exec env -u NAME... PATH=... SHELL=... <managed bash> --noprofile --norc -c ". rc.bash && <rest>"
            (every variable the curated environment doesn't keep removed by name; no value on argv)
```

## Settings: `[shell]` in gateway.toml

```toml
[shell]
managed = "on"            # "on" (default) | "warn" | "off"; true/false mean on/off
import_path = ["/opt/homebrew/bin", "~/.cargo/bin"]   # host folders for the managed PATH
import_env = ["JAVA_HOME"]                            # variables taken from Claude Code's environment
```

- **on**: the mod sets the prefix; without it (no mod) the classic Bash hook
  denies Bash and Monitor with "managed shell unavailable" and the reason.
- **warn**: as on while the mod runs; without it, commands run in the user's
  own shell and the user sees a notice once per session.
- **off**: no prefix; Claude Code's own shell, as before v4.

Consent (`consent._shell`, the "settings" pseudo-entry): lowering `managed`
(on → warn → off), a new `import_path` folder and a new `import_env` name are
widenings, effective only after the user's OK in the gateway dialog (`gate
check settings`, or `gate check all`); until then the approved values apply
(an approval from before phase 4 has none: on, no imports). Raising `managed`
and removing an import are narrowings, effective at once and ratcheted into
the approval. A bad `managed` value keeps the approved mode (an error in `gate
status`, nothing ratchets).

Validation (`form.import_path_entry`, `form.import_env_entry`):
`import_path` takes absolute folders or `~/...` (expanded with the user's
home), no `:`, nothing unsafe, never inside `~/.config/gateway`; at most 32.
`import_env` takes variable names, refuses those always passed (HOME, LANG,
...), credential-looking names (TOKEN, SECRET, PASSW, PASSPHRASE, CRED, API_KEY,
ACCESS_KEY, PRIVATE_KEY, CLIENT_KEY, CLIENT_CERT, AUTH, COOKIE, SESSION_KEY, and the env file's list
of the user's token and agent variables: an account holds those), and what
would change how a shell, the loader or the stand-ins work (PATH, IFS, ENV,
BASH_ENV, BASH_FUNC_*, SHELLOPTS, PS*, PROMPT_COMMAND, CDPATH, LD_*, DYLD_*,
GIT_SSH*, GIT_ASKPASS, GIT_CONFIG*, SSH_*, SUDO_*, RSYNC_RSH, the gateway's
and Claude Code's own); at most 32. A bad entry is left out with an error.

## The mod (session start)

`managedSetup` runs first in `session.start`, before the daemon or the dialog
loop: it reads `$DATA/managed/state.json` (a missing or garbled file counts as
"on"), then sets `GW_MANAGED_DIR=$DATA/managed`, `CLAUDE_CODE_SHELL_PREFIX=
<root>/hooks/gate-sh` unless the effective mode is "off", and, once the env is
built, `CLAUDE_CODE_SHELL=<the env's bash>` (Claude Code honours it when it is
set before its first shell use, so the shell it starts gate-sh from is the
managed bash, not the login shell: no `~/.zshenv` per command). A plugin path
holding " -" can't be carried by the prefix (Claude Code splits a prefix at
its last " -" to take flags): no prefix then, and the classic hook reports it.
`state.json` sits in the data folder, which a command can rewrite, so the mod
takes only two things from it: the mode, and whether the data folder's gate-sh
copy is the prefix (only that exact path, and only while the copy's text is
the plugin's gate-sh, which the mod compares). `CLAUDE_CODE_SHELL` comes from
`launch.sh status` (the env it names, `<env>/.pixi/envs/default/bin/bash`, set
only when that env is ready), never from `state.json`'s `bash` (phase 4
review: a rewritten `bash` made Claude Code start every command, gate-sh
included, from another program with the full environment).
Another plugin's or the user's prefix is replaced (named in `/gate-doctor`).
In `-p` and SDK sessions the same happens (the mod runs there too). The mod
writes exactly these three variables (`claude plugin validate`'s "env writes",
pinned by `test_mod`).

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
(`command` + `args`, like the gateway's own) and the organization's hooks are
never prefixed by Claude Code; MCP servers started after session start are
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

It then replaces only the snapshot's `source` with `. <rc.bash>`, keeps the
rest byte for byte (so other plugins' env files, the eval'd command, the
tracker and the exit status are Claude Code's), and runs
`exec /usr/bin/env -u NAME ... PATH=<managed PATH> SHELL=<bash> <bash> --noprofile --norc -c ". rc && rest"`:
one process from Claude Code's point of view, so its interrupt and timeout
kill it (verified: Escape and a Bash `timeout` stop the command as without
the gateway).

**Not ready** (exit 75, nothing run): `GW_MANAGED_DIR` missing or relative,
no `conf`, no managed bash yet (the env is building), no `rc.bash`. So the
mod's status line says `ready` only once `conf` exists too (`launch.sh
status` reports `"managed"`, by existence; until then `finishing setup…`,
lib.ts `setupReady`): acceptance 2026-10-21 found Bash refused with 75 for
8-10 s after "gate: ready" on a first session and after an interrupted
setup, while the warm-up ran before the settings were written. **Stale**:
when gateway.toml (or the vault-unlocked marker) is newer than `conf`, gate-sh
first runs `$DATA/managed/sync` (`run.py managed-sync`) so a narrowing
applies to this command even before FileChanged runs; when that can't renew
it, exit 75.

**The curated environment**: `HOME USER LOGNAME LANG LC_* TERM
TMPDIR TZ PWD XDG_CONFIG_HOME XDG_DATA_HOME XDG_CACHE_HOME XDG_STATE_HOME
XDG_RUNTIME_DIR __CF_USER_TEXT_ENCODING`, Claude Code's own (`CLAUDECODE`,
`CLAUDE_*`, `GIT_EDITOR`, `AI_AGENT`, `COREPACK_ENABLE_AUTO_PIN`,
`NoDefaultCurrentDirectoryInExePath`), `GW_MANAGED_DIR`, the approved
`import_env` names, `PATH`, `SHELL=<managed bash>`; never a credential-looking
name (the words above; so `CLAUDE_CODE_OAUTH_TOKEN`, Claude Code's peer
`CLAUDE_CODE_MESSAGING_TOKEN`, its mTLS `CLAUDE_CODE_CLIENT_KEY_PASSPHRASE`,
`CLAUDE_CODE_CLIENT_KEY` and `CLAUDE_CODE_CLIENT_CERT` and its
`CLAUDE_CODE_HOST_CREDS_FILE` are dropped; `test_managed` sets every `CLAUDE_*`
name in Claude Code 2.1.301's own credential lists, a sample of the others and
one `CLAUDE_*` probe per word; `ANTHROPIC_*` isn't passed at all), except the user's own agent and token variables (the env file's list)
when `others = "mine"` is approved. The rc then sets what the env file sets
(the stand-ins first, the git include, `GIT_SSH_COMMAND`, `RSYNC_RSH`).
`managed.PLATFORM_NAMES`, `CLAUDE_NAMES`, `GATEWAY_NAMES` and
`CREDENTIAL_WORDS` mirror gate-sh's lists (a test compares them, and that
import_env refuses every credential word).

How: gate-sh lists its own environment (`env`, every line holding a `=`
gives a name) and passes `env` a `-u NAME` for every name it doesn't keep,
so the kept variables reach the managed bash through the environment and
only names reach any command line. It used to pass the kept variables as
`NAME=VALUE` arguments to `env -i` (phase 4 review): every local user can
read a process's arguments (`/proc/PID/cmdline` is world-readable on Linux
without `hidepid`, `ps` shows them on macOS), while its environment is the
owner's, so the user's own tokens under `others = "mine"`, approved imports
and Claude Code's variables were readable by anyone while `env` ran
(`test_no_value_reaches_a_command_line` records env's arguments, and on
Linux also scans every `/proc/*/cmdline` during 40 runs).

`GW_MANAGED_DIR` passes so that a Claude Code started from a command (a
`claude -p`, an Agent SDK script, a scratch-config session) stays managed:
it inherits `CLAUDE_CODE_SHELL_PREFIX` and `CLAUDE_CODE_SHELL` and runs its
own commands through gate-sh with this session's managed settings (phase 4
review: without the folder every one of its commands failed with 75; with
the gateway loaded, its own mod sets all three again). A prefix set by hand
without the folder gets a 75 that says so.

**PATH**: `$DATA/bin` (the stand-ins), `$DATA/managed/bin` (the runtime
tools: `bash` from the env, and `pixi`, the plugin's prerequisite, as found by
launch.sh's rules), the approved `import_path` folders in form order, then
`/usr/bin:/bin:/usr/sbin:/sbin`; last, other plugins' `bin/` folders, read
(never sourced) from the snapshot's `export PATH=` line, keeping only
folders `X/bin` whose `X/.claude-plugin/plugin.json` exists (Claude Code puts
installed plugins' bin/ on PATH through the snapshot). Nothing else of the
login PATH.

## managed.py: the files

`sync(form, eff)` writes `$DATA/managed/` (0700) whole (temp file, then
rename): `conf` (0600; `bash=`, `rc=`, `path=`, `env=`, `mine=`, `form=`,
`sync=`, `unlocked=`, read line by line by gate-sh, never sourced),
`rc.bash` (0600; `envfile.env_text(others)` plus Claude Code's own helpers
its snapshot carries: `rg` from Claude Code's embedded copy when none is on
PATH, its pkill guard; never a user file), `state.json` (0600; mode, form
mode, bash and version, readiness, PATH and variables with origins, pending
widenings, whether the vault was readable), `bin/bash` and `bin/pixi`
(symlinks), `sync` (a stub like the stand-ins', `run.py managed-sync`).
`conf` is written last and never dated before gateway.toml.

Who writes them: SessionStart (`envfile.sync`), `launch.sh ensure-env` right
after a build and before the env's warm-up (a first session's SessionStart
ran before any Python could; the warm-up takes seconds on macOS), and on an
env built by a setup that was interrupted before them (no `conf`), FileChanged
on gateway.toml, `consent.approve("settings")`, gate-sh's renewal
(`run.py managed-sync`), and the first command after a vault unlock (gated's
broker touches `<run>/gated-unlocked`; approved imports are inside the
vault, so a session started with a locked vault has the defaults until then).

`status_lines(eff)` is `gate status`'s section: the mode (and a pending
change), the bash, every PATH folder with its origin ("the gateway's
stand-ins", "gateway.toml [shell] import_path, line 4; Homebrew", "system"),
the variables, what waits for the OK.

## The classic Bash hook without the prefix

`pre_bash.sh` reads the payload's `tool_name`; for Bash and Monitor, when
`CLAUDE_CODE_SHELL_PREFIX` isn't this plugin's `hooks/gate-sh` (by string or
same file), every call goes to Python with `GW_MANAGED_CHECK=1` (the word list
alone decides otherwise). `hooks_bash._managed_gate` reads the effective mode
(vault approval + form): "on" denies with `MANAGED_DENY` (why: no prefix at
all, mods off or Claude Code older than 2.1.287 or the session started before
managed mode was switched on; or another prefix, named), "warn" adds
`MANAGED_WARN` as a `systemMessage` once per session (a marker in the session
dir) and judges the command as usual, "off" judges it as usual. While no env
can run Python, launch.sh's cold guard denies such a call by text
(`degraded_bash_text("managed")`, byte-identical to envfile's). The Terminal
panel (`run_in_terminal`) and checkpoint's `job_start` aren't the managed
shell and get no managed check.

Without the mod there is also no dialog, so an approval of "warn" or "off"
can't be given then; the deny says so (turn mods on or update Claude Code).

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

Imports (`[shell] import_path` / `import_env`) apply only while this
machine's `env_import` policy is allow (`managed.imports_allowed`;
`path_plan`, `env_plan` and the conf follow it), so `env_import = "deny"`
takes them out at once (a narrowing).

## Alternate routes (phase 7)

The stand-ins are first on PATH, so `ssh`, `scp`, `sudo`, `gh`, ... by their
bare names reach the gateway. In managed mode (`[shell] managed` "on" or
"warn") the approval hook also refuses the ordinary ways around them
(`hooks_bash._alternate_route`), each with "runs the system's TOOL around
the gateway":

- a credential tool (`ROUTE_TOOLS`: ssh, scp, sftp, slogin, ssh-add,
  ssh-agent, ssh-copy-id, sudo, sudoedit, gh, hf, huggingface-cli, az,
  databricks, crane, pijul, dvc) by a path (`/usr/bin/ssh`, `./sudo`), unless
  the path is the stand-in itself;
- `command -p TOOL`, `env -i TOOL` / `env -u ... TOOL`, and `PATH=`,
  `GIT_SSH=`, `GIT_SSH_COMMAND=`, `RSYNC_RSH=` or `SUDO_ASKPASS=` assigned for
  a command (also in text the parser can't split);
- `rsync -e/--rsh` (also inside combined short options: `-ae /usr/bin/ssh`,
  `-aze/usr/bin/ssh`) and `git -c core.sshCommand=` / `ssh.variant=` (also
  as one word, `-ccore.sshCommand=...`) / `--config-env=` naming any ssh but
  the bare `ssh`, and `git config core.sshCommand VALUE` / `ssh.variant`
  (any scope: a reroute that outlives the command);
- `GIT_SSH_VARIANT=` and git's configuration from the environment
  (`GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_n`/`VALUE_n`, `GIT_CONFIG_PARAMETERS`,
  ...) assigned for a command, like the variables above.

Forms whose credential tool the parser can't resolve are denied too, with
"may run the system's TOOL around the gateway" (`_route_deny_hidden`), in
every permission mode (never left to Claude Code's own mode):

- PATH, a transport variable (`GIT_SSH*`, `RSYNC_RSH`, `SUDO_ASKPASS`,
  `GIT_CONFIG_*`) changed by an earlier statement of the same command
  (`export`, `declare`/`typeset`/`readonly`/`local`, `unset`, `printf -v`,
  `read`), or `hash -p` / an alias of a tool, before a later stage runs the
  tool it reroutes (`_route_changes`);
- a variable as the program (`$X box uptime`, `"$x/ssh" ...`; behind sudo,
  timeout or xargs it is that program's argument and SPEC 8's table
  applies);
- a command the parser can't split (an assignment statement, a function,
  `eval`, `exec`, a command substitution) or a stage that runs code its words
  don't show (`sh -c`/`bash -c` strings, `| sh`, `find -exec`, `xargs`,
  `env -S`, a loop): the text scan (`_route_text`) refuses a credential
  tool named by any path but the stand-in's, a variable or a command's
  output as the program (`$(which -a ssh) box`; a computed folder with a
  named program, `$(git rev-parse --show-toplevel)/x.sh`, passes; assignments
  before the program are skipped), a PATH/transport change, `unset PATH`,
  `hash -p`, `command -p` or `env -i`/`-u`/`-S` with a tool named after it
  (`sudo env -i make` is sudo's own business), an alias or a function named
  after a tool, and git's ssh setting with git anywhere. Here-documents that
  are data (`cat > f <<EOF`) aren't read; one a shell reads (`bash <<EOF`,
  `| sh`) is. An ssh stage's remote command is never scanned (it runs on the
  host, where remote sudo has its own rules). The scan is deliberately broad
  (`bash -c 'ls -l /usr/bin/ssh'` is refused too: run it without the shell
  string).

git and rsync by a path still pass: the gateway's env file routes their
transport through `GIT_SSH_COMMAND` / `RSYNC_RSH`, which reach the stand-in
either way. With `managed = "off"` none of this applies (the person chose
their own shell).

**The residual limit, stated:** Claude's commands run as the user. A
script or program that runs `/usr/bin/ssh` itself (not typed on the
command line the hook sees), copies a binary, or calls `execve` directly is
not seen by any hook, and a typed command can still be obfuscated past a
text scan (a tool's path decoded at run time inside a string a shell then
runs). What it can't do is get the gateway's credentials: those stay in
the vault (encrypted; with a wrapped key only gated
decrypts) and go only to the stand-ins' children after their checks. What it
can do is use the user's own credentials outside the gateway (their own
`~/.ssh` keys and agent, a `gh` login, a cached sudo timestamp), exactly as
any program the user runs could. The hook's checks are guardrails against a
cooperative model, not a sandbox (README "Security, honestly").

## Cost

Measured on macOS arm64 (2026-10-20): a trivial tool script takes about
23 ms through gate-sh against 4 ms for bash alone (the env listing, the
snapshot's PATH line, `env`, the managed bash and its rc); a hook string
about 12 ms against 5 ms (one more `/bin/sh`). After the review fixes, side
by side on a loaded machine with 117 variables in the environment: 24 ms
per tool script with `env -u` against 25 ms with the earlier `env -i`
form (the names removed are collected in one string, not re-set one by
one). The classic hook's managed
check costs nothing while the prefix is the gateway's (a string compare in
`pre_bash.sh`); without it every Bash and Monitor call starts Python once.

## Known limits

- Claude Code starts the prefix through a shell: with `CLAUDE_CODE_SHELL` set
  (the env built before the session's first command) that is the managed
  bash, which reads no rc (`bash -c`); before that, the user's shell (zsh
  reads `~/.zshenv`; bash `$BASH_ENV`). gate-sh discards everything such a
  shell set (removed by name), but not what it did. Claude Code also runs the user's
  login rc once per session to make its snapshot; the gateway never sources
  the snapshot.
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
  the classic hook denies in managed mode.
- The curated environment removes what it doesn't keep by name, from the
  environment's own listing. An entry whose name holds a line break (only a
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
  don't reach Claude's commands unless imported (`import_env`); other
  plugins' own hooks, MCP servers and env files still get or set them.
