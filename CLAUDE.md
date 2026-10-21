# CLAUDE.md: working on gateway

Guide for agents (and people) changing this repo. The user's view is
[README.md](README.md). How v3 fits together:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md). The contract:
[docs/SPEC-v3.md](docs/SPEC-v3.md) (section numbers are cited everywhere).
Module APIs: [docs/MODULES-v3.md](docs/MODULES-v3.md) and
[docs/modules/](docs/modules/). Why it looks this way, and what was tried and
rejected: [docs/DECISIONS.md](docs/DECISIONS.md). Read DECISIONS before
redesigning anything. The upgrade in progress: [docs/PLAN-v4.md](docs/PLAN-v4.md)
(authoritative where it differs from SPEC-v3; platform evidence in
[docs/FEASIBILITY-v4.md](docs/FEASIBILITY-v4.md), the checkpoint contract in
[docs/CONTRACT-v1.md](docs/CONTRACT-v1.md), per-surface status in
[docs/CAPABILITIES.md](docs/CAPABILITIES.md)).

## What this is

A Claude Code plugin, `gate` (`plugins/gateway/`), in the marketplace
`gateway` (`.claude-plugin/marketplace.json`). Users install it with
`/plugin marketplace add p-w-rs/gateway` and `/plugin install gate@gateway`.
v3 (plugin 0.9.0) gives Claude the user's machines ("hosts") and accounts as
ordinary commands (`sudo`, `ssh`, `git`, `gh`, ...) through stand-ins on
Claude's PATH, keeps every secret in an age vault Claude can't read, and lets
the user (or Claude, when asked) edit what Claude may do in one form,
`~/.config/gateway/gateway.toml`. Users need only Claude Code and pixi, on
macOS or Linux, desktop or headless; keep it that way. Nothing goes into
settings.json. PLAN-v4 phase 1 (2026-10-19) added a mod (`hooks/mod/`, a
TypeScript hooks module: setup status line, provisioning at session start,
the immediate `/gate-doctor`) beside the classic hooks, which keep every guard.
PLAN-v4 phase 2 (2026-10-19) added the per-user daemon `gated`
(`src/gateway/daemon/`, docs/modules/daemon.md): a Unix socket with peer
authentication and planes, CONTRACT-v1 discovery/snapshot/events for
checkpoint, and the broker that holds a passphrase-wrapped vault key.
PLAN-v4 phase 3 (2026-10-20) made every question the gateway asks a native
pane inside Claude Code (the mod draws it from requests gated holds; a secret
is typed into a `Client` field and reaches gated sealed with NaCl's box): no
OS dialogs, no terminal prompts, no browser or device-code sign-ins, and the
vault passphrase is set and unlocked there (`/gate-unlock`, `/gate-lock`).
PLAN-v4 phase 4 (2026-10-20) made the gateway the default execution route:
the mod sets `CLAUDE_CODE_SHELL_PREFIX` to `hooks/gate-sh`, which runs every
command Claude Code starts through its shell (Bash, background, Monitor, `!`,
subagents, skill injection) in the gateway env's bash with the gateway rc and
a curated environment, and passes classic hook strings through exactly
(docs/modules/managed.md); `[shell]` in the form sets the mode and the host
imports (consented), and the gw tool `host_inspect` shows what the host
offers.
PLAN-v4 phase 5 (2026-10-20, plugin 0.8.0) added terminals and jobs
(docs/modules/terminals.md): gated supervises persistent PTYs in its own tmux
(the env's tmux, a private socket and config), the gw tools `terminal_*` and
`job_*` read and type into them (one writer at a time, quoting the screen's
seq), the person watches and takes them over in the `/gate-terminal` pane, a
password prompt in a pane opens the credential dialog, and CONTRACT-v1's job
routes and per-job pause policies are served.
PLAN-v4 phase 6 (2026-10-20) added the managed remote runtime
(docs/modules/remote.md): `terminal_open`/`job_start` (and CONTRACT-v1's jobs)
take a `host`; gated stages the gateway's own bash and tmux there on first need
(`runtime/pixi.toml` packed with pixi-pack per platform, the target's
pixi-unpack from its conda package, sha256 checked on the host), runs the panes
in the runtime's tmux over the gateway's own ssh (ControlMaster), records the
host's machine id with its host keys, blocks on a changed host key or machine
until the person confirms in the native dialog, and asks the host what
survived a disconnect (disconnected, waiting_auth, unknown; never assumed).
PLAN-v4 phase 7 (2026-10-20, plugin 0.9.0) added hosts' workspaces, policy,
account states and portability (docs/modules/policy.md): workspaces are
named roots per host (`w_` ids bound to the host's id and root, a local
folder mapping) that bind every terminal and job; policy is allow/ask/deny
per host, workspace, account and action (read, exec, write, network,
elevation, credential, env_import, provision, and per-host forwarding
grants), layered on the rights and the consent ratchet, decided at each
boundary with the concrete rule shown; account adapters (GitHub,
Hugging Face, Azure secret/certificate/refresh token) tell configured,
connected, expired, revoked and reauthentication-required apart from the
services' answers; `/gate-hosts` and `/gate-accounts` panes; export/import
format 3 (per-item selection, digest, per-item conflicts, staged import with
backup, wrong-passphrase vs tamper); the gateway never installs a sudoers
rule (per-call passwords, the target named before elevation); alternate
routes around the stand-ins refused in managed mode; `/v1/pause` and
`/v1/resume` bound to the caller's session with `pause_id`; remote
`host_inspect` and remote imports.

## Layout

```
.claude-plugin/marketplace.json     marketplace "gateway" -> ./plugins/gateway (plugin "gate")
docs/
  ARCHITECTURE.md                   how v3 fits together
  DECISIONS.md                      why: platform facts, critiques, the user's choices, rejected ideas
  SPEC-v3.md                        the contract
  PLAN-v4.md, FEASIBILITY-v4.md     the v4 upgrade plan (phases, requirements matrix) and its probe evidence
  CONTRACT-v1.md                    gateway <-> checkpoint contract (identical copy in checkpoint;
                                    gated serves discovery, capabilities, snapshot, events)
  CAPABILITIES.md                   features x surfaces x minimum versions; what works without mods
  MODULES-v3.md, modules/*.md       module APIs and wiring, kept current with the code
                                    (modules/daemon.md: gated, the planes, the broker)
  phaseB-requests/                  how the build groups' requests were settled (RESOLUTION.md)
  history/                          earlier plans (REDESIGN-v3.md) and the first build's notes
plugins/gateway/
  .claude-plugin/plugin.json        name "gate", version 0.9.0
  .mcp.json                         MCP server "gw": sh hooks/launch.sh mcp, "alwaysLoad": true
  hooks/hooks.json                  every hook, exec form (table in MODULES-v3.md, "Wiring"; the
                                    async SessionStart `hook-daemon` starts gated and registers the
                                    session), and "modules": ["./mod/register.tsx"]
  hooks/gate-sh                     the managed shell's prefix (POSIX sh; PLAN-v4 phase 4): hook strings
                                    pass through as /bin/sh -c; Bash-tool scripts run in the env's bash
                                    with the gateway rc (never the snapshot) and a curated env (the rest
                                    removed by name, `env -u`: no value on any command line)
  hooks/launch.sh                   finds pixi, builds (`pixi install --locked`, a build lock with a live
                                    owner) and warms the env, runs run.py (-X pycache_prefix=$DATA/pycache);
                                    degraded output while it builds (env file, stubs, file guard, the cold
                                    Bash guard); the safe env file before SessionStart's Python; the file
                                    guard's sh fast path; `status` (one JSON line for the mod)
  hooks/mod/register.tsx, lib.ts    the mod: managed execution first (CLAUDE_CODE_SHELL_PREFIX, GW_MANAGED_DIR,
                                    CLAUDE_CODE_SHELL), status line, provisioning via $.process.spawn, gated
                                    start + UI-plane registration ($.http.fetch over the socket),
                                    /gate-doctor, the dialog pane and loop, the guard, /gate-dialog|unlock|lock
  hooks/mod/dialog.ts               the dialog's pure logic (views, texts, the sealed-post parser)
  hooks/mod/field.tsx, seal.ts      the private field (a Client module) and its sealing (NaCl box)
  hooks/mod/terminal.ts, term.tsx   the terminal pane's pure logic and its screen (a Client module: styled runs,
                                    keys batched with sequence numbers, the click is the takeover, Ctrl-] prefix)
  hooks/mod/manage.ts               the /gate-hosts and /gate-accounts panes' pure logic (gated's /ui/manage, the
                                    edit line -> one fixed `gate host|workspace|policy` argv; PLAN-v4 phase 7)
  hooks/mod/vendor/                 TweetNaCl 1.0.3 (nacl-fast.js, one-line ES-module change; VENDOR.md)
  hooks/mod/*.test.ts               its tests, run by `claude plugin test .`
  hooks/pre_bash.sh                 PreToolUse Bash|Monitor|run_in_terminal|checkpoint's job_start prefilter -> hook-bash
  hooks/mcp_perm.sh                 PreToolUse decisions for the gw tools (sh + awk, no Python)
  hooks/post.sh, hooks/prompt.sh    PostToolUse/PostToolUseFailure and UserPromptSubmit prefilters
  hooks/e2e.sh                      the e2e marker rules for the sh hooks
  commands/status.md, help.md       /gate:status, /gate:help (/gate-doctor is the mod's)
  skills/gateway/SKILL.md           gate:gateway (user-invocable: false): how Claude edits the form, gate check, accounts
  pixi.toml, pixi.lock              Python 3.12, PyNaCl, age, gh, git-lfs, openssh, git, bash 5 (the managed
                                    shell), tmux 3 (gated's terminal supervisor), pixi-pack and zstd (the remote
                                    runtime's packs); features hf, databricks, dvc, registry, pijul
  runtime/pixi.toml, pixi.lock      the managed remote runtime (PLAN-v4 phase 6): bash 5 + tmux 3 for linux-64,
                                    linux-aarch64, osx-arm64, osx-64 (no Python), feature `unpacker` (the target's
                                    pixi-unpack); never installed here, packed by gated (docs/modules/remote.md)
  run.py                            the one entry point: hook-*, mcp, shim TOOL, askpass, git-credential, gate,
                                    gated serve|start|status|stop, managed-sync
  src/gateway/                      the code (stdlib, plus PyNaCl in gated; below); daemon/ is gated
  tests/                            run_tests.py, harness*.py (harness_daemon: a real gated in a test
                                    root, FakeClaude), fakes/ (fake_claude.py: a python named `claude`),
                                    fixtures/, test_*.py, mutation files (mutations_daemon.py,
                                    mutations_dialogs.py), e2e/ (headless claude -p suite;
                                    tests/e2e.py forwards to it), tui/ (the interactive TUI harness,
                                    identical in checkpoint; proxy.py: the record-only telemetry proxy),
                                    acceptance_dialogs.py (the native dialogs, live, through tui/),
                                    test_managed.py, mutations_managed.py, acceptance_managed.py (managed
                                    execution; the last live through tui/, with a baseline session),
                                    test_terminals.py, mutations_terminals.py, acceptance_terminals.py
                                    (terminals and jobs; the last live through tui/),
                                    test_remote.py, harness_remote.py, mutations_remote.py, acceptance_remote.py
                                    (the remote runtime; the last live against the Linux VM and a local sshd),
                                    test_policy.py, test_workspaces.py, test_accounts_states.py,
                                    test_portability.py, mutations_policy.py (PLAN-v4 phase 7),
                                    acceptance_install.py, acceptance_canaries.py, acceptance_native_ui.py
                                    (PLAN-v4 phase 8, brief 14.1, 14.9/14.13, 14.10/14.12: both plugins
                                    installed, live through tui/),
                                    release_check.py (is the git index the tested tree? read-only)
  logs/, quarantine/                the user's old v0.5 data (git-ignored); leave them alone (never move or
                                    delete them; a local folder marketplace would copy them, so installs
                                    come from git only)
  .claude-plugin/types/             written by Claude Code when it loads the mod from this folder
                                    (interactive --plugin-dir); git-ignored
  tsconfig.json                     also written then (extends the types above); git-ignored
                                    (/tsconfig.json), and release_check treats it as engine junk
.work/                              local plans and trackers (not in git)
```

## Modules (`plugins/gateway/src/gateway/`)

| area | modules |
|---|---|
| core | `paths` (every location), `testing` (the test override API), `form` (parse/validate/write the form, its policy/workspace/shell tables), `accounts` (destinations, account choice), `vault` (age vault v3, cache, events), `vault_v2` (reads 0.6 vaults), `consent` (approved vs effective rights and policy, ratchet), `policy` (allow/ask/deny decisions with their rule, PLAN-v4 phase 7), `migrate` (0.6 to v3), `audit`, `envfile` (env file, stubs, git include, launcher), `warm` (loads a new env once), `managed` (the managed shell's conf, rc, state and runtime links for gate-sh; `gate status`'s section; the host inspection behind `host_inspect`), `runtime_pack` (the remote runtime's artifacts: platforms, pixi-pack builds into plugin data, the target's pixi-unpack out of its conda packages, the sha256 manifest) |
| hooks | `hooks_session` (SessionStart/SubagentStart, Claude's context), `hooks_bash` + `bashparse` (approval hook), `hooks_files` (file guard), `hooks_post` (scrub output, form checks, no-screen notices), `hooks_prompt` (paste guard), `hooks_filechanged` |
| sudo / ssh | `sudo` (local stand-in, askpass, the passwordless probe; never a sudoers rule), `ancestry` (direct vs scripts), `ssh`, `ssh_args`, `ssh_conf`, `ssh_sudo` (remote sudo) |
| accounts | `githelper` (credential helper, include file), `clis` (gh, hf, databricks, crane, pijul, az, `gate with`), `asiml`, `entra` (also a certificate's client assertion), `logins`, `scrub`, `adapters` (account states from each service's API, PLAN-v4 phase 7) |
| user | `gate` (CLI, status, lock), `gate_setup` (check, login, forget, rotate; account setup by PAT, API key, service principal secret or certificate), `manage` (`gate host`, `workspace`, `policy`, `accounts`, through the form writer), `popup` + `dialog` (the only way to ask the user: a lease from gated, then the native dialog through gated; a fake under tests), `transfer` (export, import, copy-to; format 3: per-item, digest, staged import), `agepass` (age's passphrase recipient under a private pty: export/import and the vault key's wrap), `web` + `mcp_server` (http, download) |
| daemon | `daemon/`: `peers` (kernel peer credentials, gateway entry points), `planes` (sessions, plane checks), `events` (event log), `broker` (wrapped key, lock, scoped views, merges), `server` (HTTP routes), `lifecycle` (start, detach, single instance, contract.json, idle exit, version skew, the vault's dialogs), `dialogs` (dialog requests: the queue, per-attempt X25519 keys, sealed intake opened with PyNaCl, the recheck, leases, persistence, pause; gated's own terminal-prompt dialogs), `clipboard` (Paste: the OS clipboard by absolute path, or the test override's program), `terminals` (the tmux supervisor: terminals and jobs, ownership, password prompts, survival, pause policies; remote panes and their pollers), `remote` (remote hosts: the verified connection, machine identity, the host-change gates, staging the runtime, the runtime's tmux over ssh), `screen` (capture-pane escapes to plain lines and styled runs, PTY streams, key and signal names), `client` (what the other processes call) |

## Invariants: don't break these

1. **No secret value reaches Claude**: not in tool output, hook output,
   messages, the audit log, Claude's context or the transcript. Values come
   from the vault inside gateway processes and go to one child (its env, its
   stdin, a one-shot askpass FIFO, a credential-helper answer, a private
   agent). Output the gateway controls goes through `scrub.Scrubber` /
   `scrub.scrub_text`; audit lines are redacted; messages never carry raw
   exception text. The daemon's events are built only from an allowlist of
   keys and safe values (`events.clean`), and its log never records a request
   body. Values under 8 characters are never masked by literal (that
   would reveal them) and must not reach an output path.
2. **Credentials go only to bound destinations.** Check `consent.bound_ok`
   (or `EffectiveAccount.may_send_to`) before sending. Host secrets are tied
   to the pinned host keys. Credentialed HTTP goes through `entra.urlopen` or
   `web`'s opener: no automatic redirects with credentials, no proxies, the
   Python build's own CA bundle.
3. **Widening needs the user's OK in the gateway's dialog.** Use effective rights
   (`consent.compute`), never the raw form. Narrowing applies at once and is
   persisted (`consent.ratchet` from every process that loads the form).
   `consent.approve` runs only after the user said yes, with the changes the
   dialog showed. No model-settable "approved" parameter, ever.
4. **The gateway asks only through its native dialog** (PLAN-v4 phase 3):
   `popup.py` -> `dialog.py` -> gated's dialog requests -> the mod's pane.
   No OS dialog (osascript, zenity, kdialog), no terminal prompt, no
   browser or device-code sign-in, never MCP elicitation, and no other way
   on a surface without the private field (mobile, VS Code, `-p`, the SDK,
   mods off): there the request is reported as unavailable (what is needed,
   where it can be given). Fixed templates; names only after validation
   (`form.safe`); text Claude wrote (notes) is never shown in a dialog or
   put into Claude's context. A secret is typed only into the `Client`
   field and leaves it sealed (TweetNaCl box to the attempt's X25519 key,
   whose private half stays in gated); `/ui/dialog/submit` refuses a
   plaintext body. gated opens the box, rechecks the request (open, before
   its deadline, its session alive and not paused, the asking processes
   alive, the form entry unchanged with the rights it needs) and hands the
   value once to the helper that asked; the conversation sees only a fixed
   result. The form recheck runs only for a dialog that names its entry
   (`check`): every dialog for a host's or an account's secret passes one
   (`sudo.SUDO_CHECK`, `gate_setup.sudo_check` / `_account_check`,
   `ssh.host_check`), and the sudo and ssh stand-ins read the rights again
   before they use a value from a dialog. "Not paused" is gated's own pause
   record (`/v1/pause`), which checkpoint (0.6+) sends on every pause while
   gated serves its session. One dialog at a
   time per session, the rest queued by identity; every exit path (cancel,
   timeout, focus moving away, a failed check after 3 tries, gated dying,
   a reload) clears the field and gated's buffers. Paste reads the
   clipboard in gated by absolute path (under any test override only the
   override's program).
5. **`allow` only for SPEC 8 shapes, only in auto/bypass mode.** The Bash
   hook denies and asks in every mode; it allows only when every segment is
   an allowed shape, run by its bare name (never `./ssh` or `/tmp/x/cat`),
   on an effective `true` right. Never `allow` for `gate with`, account
   CLIs, `mcp__terminal__run_in_terminal` or checkpoint's
   `mcp__plugin_check_jobs__job_start` (a job gets Bash's denies, an
   `"ask"` right there is denied, never `allow` or `ask`). Deny/ask use the stricter of
   the form and the effective right (an approved `"ask"` edited to `true`
   stays `"ask"` until the user's OK; a right waiting for the OK is denied
   with "run gate check NAME"), allow the effective right. Never answer
   `ask` except for an `"ask"` right (an `ask` always becomes a human
   prompt). Monitor and `run_in_background` commands are judged like any
   Bash command (no `gate scrub` rule; see 14). Never `allow`
   `sudo visudo|vipw|vigr` (they edit sudoers and the user database with no
   path argument).
6. **Credentials go to direct callers only** (`ancestry.is_direct`, by
   executable path) unless the entry has `scripts = true`; an ancestry error
   counts as not direct. **An `"ask"` right goes only to a command Claude
   typed** (`ancestry.typed_by_claude`: Claude's command shell or a fork of
   it, nothing in between, never checkpoint's job runner, never a gateway
   terminal's or job's shell (its `CLAUDE_PID=$$` names a shell, never Claude
   Code), whatever `scripts` says), because Claude Code can only prompt for
   that command; the approval
   hook denies scp/sftp/rsync on an `"ask"` right and asks about commands
   that hide their verbs.
7. **Production entry points never honour test overrides.** Locations come
   only from `paths.py`; stand-ins, askpass, the git helper and `gate` never
   read `GATEWAY_*` or take the data folder from `CLAUDE_PLUGIN_DATA`;
   binaries come from `paths.tool()`, never PATH. The only redirections:
   `--test` with `GATEWAY_TEST_ROOT` for hook and MCP modes (the test runner
   only; `gated` too, with `GATEWAY_TEST_RUN` for a short run dir), and the
   e2e marker in a scratch copy under a temp folder (decided by the code's
   own location, never a variable). The daemon takes its data folder from its
   python, never from `CLAUDE_PLUGIN_DATA`.
8. **Tests never touch the real home.** Everything goes through
   `gateway.testing.override(...)` and the harness; the harness guard aborts
   the run on any real location.
9. **Fail closed where it guards**: the file guard (`onFailure: "block"`,
   run.py exits 2; it also covers the desktop app's transcript export and
   search; launch.sh's sh fast path passes only plain paths Python would
   pass, and sends everything else to Python), the paste guard and the
   task-notification check (prompt.sh blocks if Python can't answer). The other hooks fail open (no decision), so
   Claude Code's own permissions still apply. A cold start never switches a
   guard off: while no env can run Python, launch.sh's degraded paths deny
   in sh (the file guard, and the Bash hook's `degraded_bash`: private folder
   and `~/.config/gateway` other than gateway.toml, transcripts, credential
   shapes, curl/wget once a vault exists), byte-identical to
   `envfile.degraded_bash_text`.
10. **The form is never re-serialized**: append a table or replace one
    `key = value` line, re-parse, roll back if anything else changed.
11. **Vault read-modify-write only inside `vault.locked()` / `vault.edit()`.**
    With a wrapped key the writer still holds the flock while the daemon
    merges and writes (the daemon itself never takes it for a client's write,
    which would deadlock; `set_passphrase` takes it).
12. **Every credential use and every refusal is audited** (`audit.use`,
    `audit.refusal`; `gate why` reads the last refusal). Messages start with
    `gateway:` and say what to do next.
13. **Stdlib only** in `src/` (Python 3.12). **POSIX sh** in `hooks/` (no
    bashisms; the desktop app gives hooks a minimal PATH), except
    `hooks/mod/` (the mod, TypeScript, run by Claude Code itself). External
    binaries: the pixi env's age, OpenSSH, gh, git-lfs (and git as a
    fallback), the system's sudo, git and sshd. One exception since PLAN-v4
    phase 3: PyNaCl (libsodium), imported only by gated's `daemon/dialogs.py`
    to open the dialog's sealed boxes (`_nacl()` adds the env's
    site-packages for that import, since gated runs with `-I -S`); the mod
    vendors TweetNaCl (`hooks/mod/vendor/VENDOR.md`). Since phase 4 the env
    also has bash 5, the managed shell (`hooks/gate-sh` runs it; nothing in
    `src/` imports anything for it), and since phase 5 tmux 3, gated's
    terminal supervisor (run by path, `paths.tool("tmux")`, always with `-S`
    the private socket and `-f` the gateway's config), and since phase 6
    pixi-pack and zstd (gated packs the remote runtime with them,
    `runtime_pack.py`; by path, never PATH). What goes to a remote host is
    `runtime/pixi.toml`'s lock (bash, tmux) and the target's pixi-unpack; on
    the host only POSIX tools are used (`sh -c`, cat, mv, mkdir, chmod, df, ps,
    stty, kill, uname).
14. **Claude's commands run in the managed shell, never the login shell**
    (PLAN-v4 phase 4, docs/modules/managed.md; replaces "don't change how
    Claude's ordinary commands behave"). In managed mode (`[shell] managed =
    "on"`, the default, or "warn") the mod sets `CLAUDE_CODE_SHELL_PREFIX` to
    `hooks/gate-sh` before anything else at session start. gate-sh runs a
    classic hook string exactly as Claude Code does without it (`exec /bin/sh
    -c "$1"`, builtins only and no variable assigned before it, SHLVL given
    back on macOS; a hook string is anything without a Bash-tool script's
    whole shape: the cwd tracker last plus an eval, or the snapshot's
    `source` first); a Bash-tool script runs with only the snapshot's
    `source` replaced by the gateway rc, the rest byte for byte (other
    plugins' env files, the eval'd command, the cwd tracker, the exit
    status), under the env's bash with only the platform variables, Claude
    Code's own, `GW_MANAGED_DIR` (a Claude Code started from a command stays
    managed) and approved imports, never a credential-looking name (the
    lists are mirrored in `managed.py` and compared by a test; they cover
    Claude Code's own credential variables, `PASSPHRASE`, `CRED`,
    `CLIENT_KEY` and `CLIENT_CERT` included). Every other variable is removed
    by name (`env -u NAME`): no value ever reaches a command line, which
    every local user can read. A script that has a tool script's shape but
    doesn't parse (126) or a managed shell that isn't ready (75) is refused,
    never run in the user's shell; a newer gateway.toml makes gate-sh renew
    its settings before the command (a narrowing applies at once). Without the prefix the
    classic Bash hook decides every Bash and Monitor call (pre_bash.sh sends
    them all to Python): "on" denies "managed shell unavailable", "warn" runs
    with a notice once per session. Lowering `managed` and adding an import
    are widenings; the mod only reads a cache (`state.json`) that can take
    the prefix away, never keep it off where the vault says "on" (it takes
    the managed bash for `CLAUDE_CODE_SHELL` from `launch.sh status`, never
    from `state.json`, and the data folder's gate-sh copy only while its text
    is the plugin's gate-sh). Still kept
    from the rollback: no EXIT trap, no hook requires a command shape for
    output's sake (no mandatory `| gate scrub`); output Claude Code passes to
    no rewriting hook is a documented known limit (PostToolUseFailure warns,
    the prompt hook holds back a task notification quoting a stored value or
    a token shape, `gate scrub` is optional). Host inspection (`host_inspect`)
    reads files and lists folders only, never runs or sources anything, and
    returns folder names, version words and variable names, never values.
15. **Guards live in the classic hooks, never only in the mod** (PLAN-v4):
    Anthropic can switch mods off and older Claude Code has none, so the mod
    adds conveniences (status line, provisioning, `/gate-doctor`) and reads
    no secret location; every security behaviour holds through hooks.json.
    Managed execution follows this: the mod starts the managed shell, and
    without it the classic Bash hook refuses (or, with an approved "warn",
    notices) instead.
16. **Nothing is written into the plugin folder at run time** (versioned,
    maybe read-only content): Python runs with `-X pycache_prefix=$DATA/pycache`
    (launch.sh, the stubs, the launcher and the daemon: `envfile.py_flags`,
    `lifecycle.daemon_argv`), state lives in `$CLAUDE_PLUGIN_DATA`,
    `~/.config/gateway` and the run dir.
17. **With a wrapped vault key only gated decrypts** (PLAN-v4 phase 2):
    `vault.brokered()` sends every read and write to the daemon, with no local
    fallback; never write a key.txt beside key.wrapped; the identity reaches
    age only on an inherited pipe. Every daemon request meets the uid check,
    then its route's plane check, before anything else; a vault route also
    needs a gateway entry point (by executable and argv: this plugin's run.py,
    or a sibling version's in the plugin cache, started with `-I -S`) below a
    registered session and gets only its mode's secret classes
    (`broker.SCOPES`); a write that changes what its writer couldn't see is
    refused. Every vault read asks the daemon (nothing is kept in the calling
    process, so a lock reaches the MCP server at its next read). A session is
    its pid and start time; the executable is checked only when it
    registers (an upgrade deletes a running Claude Code's binary). The test routes
    (`/test/vault/*`) exist only under a test override that enables them.
    Dialog requests come only from a gateway entry point below a session
    with a drawing surface (`/agent/dialog/lease`); the detached helper that
    waits for the answer proves itself with the lease token on the lease
    plane (gated keeps only its sha256), and only the UI plane (the
    registered Claude Code process) sees, answers or cancels a dialog.
    These checks are guardrails against a cooperative model's scripts, not a
    boundary against code running as the user (docs/modules/daemon.md).
    The terminal and job routes are the gw MCP server's (`planes.check_term`:
    a `run.py mcp` entry point below a session) and the mod's (UI plane); a
    process inside a gateway terminal counts as the pane's owner session only
    while that session lives (`Registry.pane_session`).
18. **Terminals: one writer, nothing on a command line, passwords only
    through the dialog** (PLAN-v4 phase 5, docs/modules/terminals.md). The
    owner is the agent or the user; a takeover fails every queued agent write
    ("input taken by the user; re-read the screen"), hand back bumps the seq,
    an agent write quotes the seq it read and is refused when stale (checked
    when queued and again before it goes in), one agent at a time. Typed
    text and a dialog's value go in by `load-buffer -` (stdin) and
    `paste-buffer -d`, a pane's environment by a 0600 start file it removes:
    never a value on any command line. A password prompt (ECHO off with
    ICANON on) is answered only through the credential dialog, after the
    recheck (same prompt, same foreground process group); meanwhile the agent
    can't type and the pane's typed text is refused; the agent sees
    "[credential supplied]". Reads and tails are bounded and scrubbed,
    including the terminal title (OSC 2) and values split across a soft-wrap
    boundary (the agent reads `capture-pane -J` logical lines); the main
    agent's input is held under its empty loop id (unclaimed is `None`, not
    `""`); `terminal_list`/`job_list` to the agent are bounded. A seq handed
    to the agent is persisted, so a restart's bump makes a pre-crash seq
    stale. Survival is always asked of tmux (id and nonce), never inferred
    from a saved pid: a lost pane is gone (terminal) or unknown (job, with no
    `ended` time: the outcome is unproven), never "exited"; a *failed*
    `list-panes` query is a blip (told from a dead server by its pid), not
    death. A paused session can stop or cancel a job but not resume it
    (`job_signal CONT` refused); an interrupt's SIGTERM escalation is
    persisted and re-armed after a restart. The approval hook's per-call
    judging of `terminal_send` is a guardrail (split-bypassable), not the
    boundary: the stand-ins and the encrypted vault are. The user's tmux
    server and `~/.tmux.conf` are never used.
19. **Remote work runs only in the managed runtime, on the right host, after
    its identity checks** (PLAN-v4 phase 6, docs/modules/remote.md). Only a
    host whose effective ssh right is `true`; every remote command line is
    `exec /bin/sh -c '<script>'` (the login shell only execs; output before a
    random marker is dropped) with no value on it: files and the dialog's
    password go on ssh's stdin (the remote tmux's `load-buffer -`). Every
    command for a runtime checks the host record's marker there
    (`<rt>/hosts/<host id>`, a nonce only gated knows; `bind_check`) and every
    pane operation goes through its own host (`Supervisor._tm`: never another
    host's connection, refused when the host's machine token isn't the
    pane's). A new master connection is verified before anything runs on it
    (host keys by ssh's strict checking against the pins, the machine token
    against the one stored with them); a changed host key or machine blocks
    the host until the person confirms in gated's own dialog (OK pins or
    stores; cancel keeps it blocked until the pins or addresses change).
    Staged files are sha256-checked on the host (or read back and hashed
    here) before anything is unpacked; old runtime folders go only by exact
    name, with the gateway's marker, and only when their tmux doesn't answer.
    A host that can't be asked leaves its panes `disconnected` (a refused key:
    `waiting_auth`), never ended; only the host's answer ends a pane (`exited`
    with tmux's status or signal) or loses it (`unknown`, no end time); a
    reconnect bumps every seq. A command whose answer is lost (a timeout, a 255
    after the marker, or one with no answer unless ssh says it never connected)
    is never reported as not run: a start's record and idempotency key are
    saved before it goes out and stay (`unknown`, `start_confirmed: false`)
    until the host lists it (id and nonce) or the start file's claim (a rename
    only one side can win) proves it never ran; typed text is checked by its
    buffer; a close the host didn't get leaves cancel unset (`stop_requested`).
    A failed `list-panes` is "no server" only with the host's proof (socket
    gone, or "no server running" with the last server pid dead), else a blip.
    The approval hook resolves `host` with gated's own resolver
    (`daemon.resolve_remote_host`) and denies a host word that names no host.
    The managed environment: the runtime's tmux
    under `env -i`, a start file unsetting all but the platform's variables,
    the curated PATH, `--noprofile`; no remote rc, profile, PATH or ssh session
    variable reaches it (since phase 7, only the host's approved
    `[hosts.NAME.shell]` imports, while its `env_import` policy allows them,
    copied on the host into 0600 files: never a value on a command line).
20. **Policy only narrows, is decided where the work happens, and names its
    rule** (PLAN-v4 phase 7, docs/modules/policy.md). Every action on a host
    or with an account goes through `policy.decide` at the boundary that
    performs it (the ssh and sudo stand-ins, gated's `_bind` and
    `ensure_runtime` and `RemoteHost.inspect`, `managed.imports_allowed`,
    `web`, `accounts.select`, the approval hook); the strictest of the base
    right, the host's, the workspace's, the account's and `[policy]` wins,
    never above the rights; each action is decided on its own (a read grant
    never implies exec, provision, elevation or credential use). Forwarding
    grants exist only in the host's own `[hosts.NAME.policy]` (a global grant
    is an error that counts as deny). "ask" passes only for a command Claude
    typed. Every refusal shows `Decision.rule` (and is audited); raising a
    key, adding or moving a workspace, adding a grant, or taking out
    (deleting or renaming) a workspace that restricts anything is a
    widening (the consent dialog; the approved workspace keeps binding
    meanwhile), lowering applies at once and is ratcheted. A transfer
    program on a host is a read or a write only by its exact bare name and
    known options (else exec), and every path it names is decided in every
    workspace it may reach (`ssh_args.decide_path`). Policy never writes or reads
    Claude Code's permission rules or modes. Snapshot and ticker reads never
    count as a vault use (`touch=False`), so `lock_after` still locks.
21. **The gateway never changes the system's privilege rules**: no sudoers
    file, no NOPASSWD advice in code, messages or docs
    (`test_no_blanket_passwordless_sudo_advice_anywhere`); passwordless sudo
    only where `sudo -n true` already works; a sudo password is stored or
    asked per call in the dialog ("Remember it" unticked: used once), and the
    approval names whom sudo runs as and where before it runs.

## Commands

```bash
cd plugins/gateway
pixi run --locked test                   # all tests, 4 modules at a time (~3 min); prints "N passed, 0 failed"
GW_TEST_TMP=DIR pixi run --locked test   # put the temp homes in DIR (it reports anything left behind)
pixi run --locked python tests/run_tests.py test_form -k widen -x   # some modules / tests (-j N, -q)
pixi run --locked python tests/run_tests.py test_daemon test_broker   # the daemon and broker (~2 min)
pixi run --locked python tests/run_tests.py test_dialogs   # the native dialogs: gated's requests, leases, sealed intake, clipboard
pixi run --locked mutations              # every mutation file, each on its own scratch copy (-j N, -k SUBSTR)
GW_E2E_TMP=DIR pixi run --locked e2e     # headless claude -p suite on a scratch copy (not part of test; tests/e2e/README.md;
                                         # its `jobs` scenario needs ../checkpoint/plugins/checkpoint next to this repo, else skipped)
pixi run release-check                   # after `git add -A`: does the index hold the tested tree? (read-only)
claude plugin validate .                 # the plugin (and the mod's hooks module)
claude plugin validate ../..             # the marketplace
claude plugin test .                     # the mod's hooks/mod/*.test.ts in Claude Code's test kit
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_dialogs.py --tmp DIR --pixi-cache DIR2
                                         # the native dialogs live: a real interactive claude through tests/tui
                                         # (scratch config, fake API, the e2e install, telemetry on behind the
                                         # record-only proxy, the observer plugin, --debug-file, recording
                                         # shims for open/osascript/... first on PATH); it builds the e2e
                                         # copy's env first, outside the proxy (a cold DIR2 downloads ~400 MB
                                         # then; a build inside the proxied session can't download), ~3 min after
pixi exec --spec python=3.12 --spec pyte python tests/tui/selftest.py [--only t]   # the TUI harness (t: the proxy)
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_managed.py --tmp DIR --pixi-cache DIR2 [--only route,hooks,perms,cancel,print,nomods]
                                         # managed execution live: the gateway's e2e install plus a probe
                                         # plugin (string-form hooks writing env and $0, an env file, bin/,
                                         # a skill with ! injection) against a baseline config without the
                                         # gateway; every route, hooks, permissions, cancel, -p, no mods (~5 min)
pixi run --locked python tests/run_tests.py test_managed   # gate-sh, managed.py, [shell], the no-prefix hook
pixi run --locked python tests/run_tests.py test_terminals # terminals and jobs: a real gated + the env's tmux (~1 min)
pixi run --locked python tests/run_tests.py test_remote    # the remote runtime: real sshds on 127.0.0.1, a real gated,
                                                           # fake artifacts (a stand-in pixi-unpack; no network) (~1.5 min)
pixi run --locked python tests/run_tests.py test_policy test_workspaces test_accounts_states test_portability
                                         # PLAN-v4 phase 7: policy at every boundary (real sshds, a real gated),
                                         # workspaces, account adapters against local API servers, export/import format 3
pixi run --locked python tests/run_mutations.py mutations_policy.py [-k SUBSTR]
                                         # phase 7's mutations on a scratch copy (also in `mutations`;
                                         # the file run by itself without --copy edits this checkout)
pixi run --locked python tests/acceptance_remote.py --vm VMDIR --tmp DIR [--only stage,env,...] [--vm-dir NAME --vm-sshd-port N]
                                         # the remote runtime live: the Linux VM (127.0.0.1:2222 and a private sshd in it
                                         # for the disruptive steps) and a local sshd, real pixi-pack artifacts (~1 min);
                                         # --vm-dir/--vm-sshd-port keep runs of agents sharing the VM apart
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_terminals.py --tmp DIR --pixi-cache DIR2 [--no-proxy]
                                         # terminals live: the pane, a full-screen program, prompt, resize, signals,
                                         # takeover with Claude's input queued, hand back, sudo's prompt through
                                         # the dialog (canary scanned everywhere), jobs, a script in the pane refused
                                         # an "ask" ssh/sudo right (pane wording) while a true one works, a restart,
                                         # the main screen (~2.5 min)
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_install.py --tmp DIR [--checkpoint DIR] [--only prereq,cold,warm,update,uninstall,spaced,firstbash]
                                         # brief 14.1: both plugins from git-source marketplaces with only claude,
                                         # a recording pixi and pixi's git on PATH; cold provisioning, interrupted
                                         # setup, warm/offline start, update after a restart, uninstall, spaced paths
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_canaries.py --tmp DIR [--pixi-cache DIR2] [--checkpoint DIR]
                                         # brief 14.9/14.13: canaries through every input route, both plugins,
                                         # telemetry on behind the record-only proxy, everything scanned
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_native_ui.py --tmp DIR [--pixi-cache DIR2] [--only scan,hosts,accounts,export,import,tamper]
                                         # brief 14.10/14.12: /gate-hosts, /gate-accounts, export/import/tamper,
                                         # nothing opened outside Claude Code (shims, ps sampler; strace on Linux)
```

`test_mod` runs the three `claude plugin` commands itself (scratch
`CLAUDE_CONFIG_DIR` and HOME, a local recording server as
`ANTHROPIC_BASE_URL`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`), and
skips with a note when no claude is found. `test_release` checks that every
file hooks.json, .mcp.json, the sh hooks and the mod start is in the plugin
folder, runs the release check on throwaway repos, and prints this
checkout's release check as a note (never a failure while it's
uncommitted).

pixi: `requires-pixi = ">=0.68.0"`, no upper bound. Tested range 0.68.0 to
0.82.0 (2026-10-19, macOS arm64, the launcher's own `pixi install --locked
--manifest-path` on a copy with a scratch cache: 0.68.0, 0.69.0, 0.70.0,
0.81.0, 0.82.0 install pixi.lock unchanged; 0.61.0-0.67.0 refuse lock format
v7). The bounds live in pixi.toml, `hooks/mod/lib.ts` (`PIXI_TESTED_MIN/MAX`,
`/gate-doctor`'s verdict) and the docs; `test_packaging` keeps them in step.

Last full run (2026-10-21, gw-reruns: the skill's checkpoint-jobs text,
plugin.json's description, SessionStart's job line, and an "ask" right no
longer honoured inside a gateway terminal or job; DECISIONS "Re-runs and
shipped text"): 1217 passed, 0 failed on macOS arm64 (`pixi run --locked
test`, 346.0 s at 4 at a time, pixi 0.81.0, GW_TEST_TMP in scratch; `claude
plugin test .` 108 pass) and 1217 passed, 0 failed on the Debian 13 arm64 VM
(216.7 s; a fresh copy of `git ls-files -co --exclude-standard` without
logs/ and quarantine/, `pixi install --locked`, pixi 0.82.0, Claude Code
2.1.304, dash as /bin/sh, GW_TEST_TMP under /tmp; no rsync there, so its
parts skipped); the same tree before the pane fix: 1214 of 1214 on both.
Mutations: 1024 of 1024 killed (the all-files run, 15 min 51 s at 3 at a
time; 5 new in mutations_sudo.py and mutations_ssh.py). Live:
`tests/acceptance_remote.py` 39 of 39 against the VM (42 s; tester's
~/.bashrc and authorized_keys byte-identical afterwards), and on the VM
`tests/acceptance_install.py` 50 of 50 (its update step included: the
checkpoint update with a changed lock kept recording on the old runtime
while the new one built, no "setting up" shown) and its vmplain part 14 of
14. The other TUI acceptances on that tree (gw-accept, macOS arm64, Claude
Code 2.1.301, scratch configs, the fake API, telemetry on behind the
record-only proxy where the script does it): dialogs 62 of 62, canaries 71
of 71, managed 38 of 38, native UI 41 of 41, terminals 63 of 63; then
terminals 73 of 73 with its new askright section (a script the agent runs in
a gateway terminal: an `"ask"` ssh right and an `"ask"` sudo right refused
with the pane's wording, no connection made and sudo never run, while its
`true` sudo right runs; both refusals audited). On a scratch copy with the
fix reverted (`if _exe_name(claude) in SHELLS:` made `if False:`) that
section failed 5 of its 10 checks (the script's ssh connected, its "ask"
sudo ran). The suite again after the script change: 1217 passed, 0 failed
(359.3 s at 4 at a time; GW_TEST_TMP in scratch). Not re-run: the headless
e2e suite.
Before that (2026-10-21, after the acceptance fixes, plugin 0.9.0, macOS
arm64, pixi 0.81.0, Claude Code 2.1.301; DECISIONS "Acceptance fixes"): 1214
tests passed, 0 failed on the final tree (`pixi run --locked test`, 340.3 s at
4 at a time; GW_TEST_TMP in scratch; `claude plugin test .`: 108 pass, 0 fail
inside test_mod; three earlier full runs while fixing: 1211 of 1211, 1212 of
1212, and 1212 of 1213, whose one failure, `test_jobs_report_exit_codes_...`,
was a job reporting `job.state` before `job.started`: fixed, with a test of
its own). Mutations: 1019 of 1019 killed (mutation_check 76, accounts 58,
daemon 83, dialogs 78, e2e 26, managed 57, packaging 42, policy 99, remote 58,
ssh 97, sudo 157, terminals 55, ux 133): the all-files run (15 min 47 s at 3
at a time) killed every mutation but found one ux snippet the fix had moved;
after updating it the ux and dialogs files ran again whole on the final
popup.py (133 and 78 killed), and the terminals file after the last terminals
change (55 killed). The prompt-box guard's `.catch` has no mutation: the test
kit can't make that hook fail or re-enter (stated in mutations_dialogs.py).
The live acceptance runs (TUI harness, scratch configs, the fake API,
telemetry behind the record-only proxy where the script does it): macOS with
2.1.301 dialogs 62 of 62, canaries 71 of 71, install 50 of 50 (firstbash: the
first Bash after "gate: ready" ran at once; the daemon left 0.7 s after
`claude plugin uninstall`), native UI 41 of 41 (the localhost workspace, its
consent and sudo choice, tamper: the retry reports the damaged file),
terminals 63 of 63, managed 38 of 38, the TUI harness self-test section g 20
of 20 (the e2e install under umask 002); the Debian 13 arm64 VM with Claude
Code 2.1.304 (everything under `~/fix-acc-gw` and `/var/tmp/fix-acc-gw`,
Debian's own umask 002, git from `pixi global install git` in a scratch
PIXI_HOME, beside another agent's runs) dialogs 62 of 62 (twice), canaries 71
of 71, native UI 44 of 44 (with import-remote of the macOS export), managed 38
of 38, install 50 of 50, terminals 63 of 63. Before the fixes the VM had
failed 6 dialogs checks and the canaries' guard check every run, and 4 managed
checks. Not re-run: `tests/acceptance_remote.py` (it edits the shared VM
user's authorized_keys and ~/.bashrc; `--vm-dir` only renames its paths,
checked by hand), the install script's vmplain part (it uses the VM user's own
~/.config/gateway), the headless e2e suite (real model API), checkpoint's
suite (only its tests/tui copy changed, kept identical to this one, which its
suite doesn't import).
Before that (2026-10-21, after the phase 7 review fixes, plugin 0.9.0,
macOS arm64, pixi 0.81.0, Claude Code 2.1.301): 1203 tests passed, 0 failed
on the final tree (`pixi run --locked test`, 340.0 s at 4 at a time;
GW_TEST_TMP in scratch; `claude plugin test .`: 95 pass, 0 fail inside
test_mod; three earlier full runs while fixing, 1203 of 1203 each in the
end). Mutations: the all-files run killed 1000 of 1000 (mutation_check 76,
accounts 58, daemon 76, dialogs 70, e2e 26, managed 57, packaging 42, policy
97, remote 58, ssh 97, sudo 157, terminals 53, ux 133); the policy file's
first run had one survivor (protected args with paths on the line, killed
by test lines of their own). Two later changes (the hook's text scan reads
a `$(...)` program word whole; a transfer path that starts with `-` is exec)
added two policy mutations; the policy (99 of 99) and ssh (97 of 97) files
ran again on the final tree, and sudo (157 of 157) and managed (57 of 57)
after the hook change (the last change touched only ssh_args), all killed
(the final tree has 1002 mutations). The verifier's probes
(workspace removal and rename, `rsync --remove-source-files`, a program
named rsync by path, multi-path rsync and `scp -f`, the hook's alternate
routes in auto, default and bypass modes) all refuse now. On Linux (the
Debian 13 arm64 VM, pixi 0.82.0, the repository's files under
`~/fix-gw-policy`, removed after, `pixi install --locked`; the tree before
the `-` path change): 1203 passed, 0 failed (204.3 s; GW_TEST_TMP under
/tmp; the first try with it under the VM's home failed 9 tests on the known
test-base artifacts: web's save_to rules and the e2e marker's temp rule);
the VM has no rsync, so the rsync parts of the new tests skipped there.
Checkpoint's suite (unchanged by this work; its CONTRACT-v1 copy is still
byte-identical): 915 passed, 0 failed (`pixi run test`, TMPDIR in scratch).
Before that (2026-10-20, after PLAN-v4 phase 7, plugin 0.9.0, macOS arm64,
pixi 0.81.0): 1192 tests passed, 0 failed (`pixi run --locked test`, 337.4 s
at 4 at a time; GW_TEST_TMP in scratch; the run before, under a concurrent VM
run, failed one phase 6 test, `test_typed_text_whose_answer_is_lost_...`, whose
next send raced the poller's reconnect: the test now waits for the terminal
to be back between its lossy steps); 970 of 970 mutations killed
(mutation_check 76, accounts 58, daemon 76, dialogs 70, e2e 26, managed 57,
packaging 42, policy 67, remote 58, ssh 97, sudo 157, terminals 53, ux 133;
the first all-files run found 7 survivors or moved snippets, all fixed: four
snippets the phase moved, a remote "ask" check and the `-o` value check that
the new policy layer now shadows (each got a test of its own), and the stored
sudo password's second layer); `claude plugin test .`: 95 pass, 0 fail, and
`claude plugin validate` (plugin and marketplace) through `test_mod`. On
Linux (the Debian 13 arm64 VM, pixi 0.82.0, Claude Code 2.1.304, the
repository's files under `~/gw-policy`, `pixi install --locked`): the whole
suite 1192 passed, 0 failed (199.2 s; `claude plugin test .` 95 pass there
too); an earlier VM run found the advice scan matching removed function names
in the new module-doc text (reworded). Run under the Mac's mutation load, the
VM's `test_remote` once failed a phase 6 timing test
(`test_a_failed_list_panes_is_a_blip_...`); unloaded it passed. Not re-run:
the e2e and TUI acceptances, `tests/acceptance_remote.py`.
Before that (2026-10-20, after the phase 6 review fixes, plugin 0.8.0, Claude
Code 2.1.301, pixi 0.81.0, macOS arm64): 1143 tests passed, 0 failed (`pixi run
--locked test`, 413.9 s at 4 at a time; GW_TEST_TMP in scratch; the two runs
before found two old test races, fixed: test_broker's long-running reader read
its answer file before the driver had written it, and test_terminals' sudo test
waited for "SUDO-", which its own typed line showed); 910 of 910 mutations
killed (mutation_check 76, accounts 58, daemon 76, dialogs 72, e2e 26, managed
57, packaging 42, remote 58, ssh 97, sudo 162, terminals 53, ux 133; 16.5 min at
3 at a time; two terminals snippets the fixes moved were updated). The phase 6
claim "890 of 890" didn't hold reliably: the remote mutation "a changed host key
is trusted without asking" survived about half the runs (ssh's own strict check
asked whenever the address choice's scan saw no key); it now has a direct test
and was killed 5 of 5 times (with the declined-key and ssh-refusal mutations).
The start-file claim and the foreground-group listing were also run on the
Debian 13 VM (bash 5.2, dash, GNU mv 9.7, procps); `claude plugin validate` and
`claude plugin test .` passed inside test_mod. Not re-run: the e2e and TUI
acceptances, `tests/acceptance_remote.py` (it works under ~/gw-remote in the
shared VM), the whole suite on Linux.
Before that (2026-10-20, after PLAN-v4 phase 6, plugin 0.8.0, Claude Code
2.1.301, pixi 0.81.0, macOS arm64): 1133 tests passed, 0 failed (`pixi run
--locked test`, 260.3 s at 4 at a time; GW_TEST_TMP in scratch); 890 of 890
mutations killed (mutation_check 76, accounts 58, daemon 76, dialogs 72, e2e
26, managed 57, packaging 42, remote 38, ssh 97, sudo 162, terminals 53, ux
133; four terminals snippets the phase moved were updated and rerun);
`claude plugin test .`: 90 pass, 0 fail; `claude plugin validate` (plugin
and marketplace) passed (both through `test_mod`);
`tests/acceptance_remote.py`: 39 of 39 (60 s; the Debian 13 arm64 VM through
127.0.0.1:2222 and a private sshd in it, a local sshd, real pixi-pack
artifacts for linux-aarch64 and osx-arm64; run twice, both 39 of 39). The
host-key tests were also run 4-5 at a time beside a loaded suite (12 of 12
after the cut-off-answer fix; 2 of 4 failed before it). On Linux (the Debian
13.7 arm64 VM, pixi 0.82.0, the repository's files, `pixi install --locked`):
the whole suite 1133 passed, 0 failed (171.4 s; GW_TEST_TMP under /tmp; the
remote tests' local sshd there is a linux-aarch64 host: GNU `stty -g`,
procps); an earlier Linux run found the read-before-capture race (1128 of
1129), fixed and stress-tested (4 parallel runs of the password test, all
passing).
Before that (2026-10-20, after PLAN-v4 phase 5, plugin 0.8.0, Claude Code
2.1.301, pixi 0.81.0, macOS arm64): 1091 tests passed, 0 failed (`pixi run
--locked test`, 200.2 s at 4 at a time; GW_TEST_TMP in scratch); 843 of 843
mutations killed (mutation_check 76, accounts 58, daemon 76, dialogs 72, e2e
26, managed 57, packaging 42, ssh 97, sudo 162, terminals 44, ux 133; four
older snippets the phase moved (planes' ancestor walk, the dialog post's
dedupe, hooks_bash's job tool line, hooks.json's matcher) were updated and
rerun); `claude plugin test .`: 90 pass, 0 fail; `claude plugin validate`
(plugin and marketplace) passed; `tests/acceptance_terminals.py`: 63 of 63
(103 s; telemetry on behind the record-only proxy; the earlier runs found the
space key, the click focus and the header truncation, fixed). On Linux (the
Debian 13.7 arm64 VM, pixi 0.82.0, the repository's files, `pixi install
--locked`; no system tmux, the env's tmux 3.8): the whole suite 1091 passed, 0
failed (with GW_TEST_TMP under /tmp; a test base named /tmp/gw-* is taken for
the run dir by the file guard's tests, and one under $HOME fails the e2e
marker's temp rule: test-base artifacts), and a probe with the real sudo of
the VM's test user, by absolute path in a gateway terminal: the dialog named
"sudo", the sealed test password reached the tty, sudo -v succeeded, the
value in no gated file, tool result or tmux argv.
Before that (2026-10-20, after the phase 4 review fixes, Claude Code
2.1.301, pixi 0.81.0, macOS arm64): 1057 tests passed, 0 failed (`pixi run
--locked test`, 191.9 s at 4 at a time; GW_TEST_TMP in scratch); 799 of 799
mutations killed (mutation_check 76, accounts 58, daemon 76, dialogs 72, e2e
26, managed 57, packaging 42, ssh 97, sudo 162, ux 133; 10 min 43 s);
`claude plugin test .`: 79 pass, 0 fail; `claude plugin validate` (plugin
and marketplace) passed; `tests/acceptance_managed.py`: 38 of 38 (291 s;
`GW_MANAGED_DIR` now in the curated set and `CLAUDE_CODE_CLIENT_KEY_PASSPHRASE`
among the credentials in Claude Code's environment); a real `claude -p`
(scratch config, the harness's fake API, no plugin) started with this
session's three variables ran its Bash in the managed bash, and without
`GW_MANAGED_DIR` got the new 75. On Linux (the Debian 13.7 arm64 VM, pixi
0.82.0, the repository's files, `pixi install --locked`): 8 full runs with
the fixed hold proxy, 7 at 1057 passed, 0 failed, and one with 1055 passed,
2 failed, both from the VM's clock stepping forward 4876 s mid-run (that
run took "5002 s"; `test_packaging`'s 30-minute lock age and a dialog
session's start time; the ssh tests passed), runs 1-5 while the Mac ran the
suite and the mutations, the condition under which the old proxy failed 4
of 16 runs.
Before that (2026-10-20, after PLAN-v4 phase 4 and the Linux fixes, Claude
Code 2.1.301, pixi 0.81.0, macOS arm64): 1052 tests passed, 0 failed (`pixi
run --locked test`, 186 s at 4 at a time; GW_TEST_TMP in scratch); 786 of 786
mutations killed (mutation_check 76, accounts 58, daemon 76, dialogs 72, e2e
26, managed 44, packaging 42, ssh 97, sudo 162, ux 133; the managed file again
after a snippet the code had moved); `claude plugin test .`: 74 pass, 0
fail; `claude plugin validate` (plugin and marketplace) passed;
`tests/acceptance_managed.py`: 38 of 38 (290 s; the scripted session, the
permission and cancel sessions, `-p`, and the gateway without its mod, each
against a baseline config without the gateway); on Linux (the Debian 13
arm64 VM, pixi 0.82.0, Claude Code 2.1.304, the repository's files, `pixi
install --locked`) the whole suite: 1052 passed, 0 failed (also 1051 of 1051
twice before the last test was added), gate-sh's tests with dash as `/bin/sh`
and the VM's bash. Not run: the headless e2e suite (real model API) and the
dialogs acceptance (phase 3's, unchanged code paths).
Before that (2026-10-20, after the phase 3 review fixes, Claude Code
2.1.301, pixi 0.81.0, macOS arm64): 1017 tests passed, 0 failed (`pixi run
--locked test`, 176.8 s at 4 at a time; GW_TEST_TMP in scratch); 739 of
739 mutations killed (mutation_check 76, accounts 56, daemon 76, dialogs
72, e2e 26, packaging 42, ssh 96, sudo 162, ux 133; the all-files run, 8 min
45 s at 4 at a time, found four sudo/ux snippets the refactor had moved,
updated, then the sudo and ux files again whole: 6 min 46 s at 2 at a
time); `claude plugin test .`: 58 pass, 0 fail; `tests/acceptance_dialogs.py`
three times: 61 of 61 from a cold pixi cache (the env, 388 MB, built before
the session, outside the proxy), then 61 of 62 (under a parallel mutation
run the fullscreen guard's composer check saw one character in the prompt
box at its single look 0.6 s after typing; the scans for that canary in
transcripts, requests and telemetry passed; the check now looks again for up
to 3 s, and says whether what it saw is a prefix or the tail of the typed
canary), then 62 of 62 (170 s, under a parallel mutation run; 8 s
prebuild); on Linux (the Debian 13 arm64 VM, pixi 0.82.0, a copy of the
plugin folder without the user's data) `test_dialogs` + `test_sudo_standin`
+ `test_broker` + `test_daemon` + `test_ux_gate_setup` 161 passed, 0 failed.
The TUI harness wasn't changed (not re-run). Before that (2026-10-20, after
PLAN-v4 phase 3): 1007 tests passed, 0 failed (`pixi run --locked test`,
171.7 s at 4 at a time; GW_TEST_TMP in scratch); 720 of 720 mutations killed
(mutation_check 76, accounts 56, daemon 76, dialogs 53, e2e 26, packaging
42, ssh 96, sudo 162, ux 133; 8 min 44 s at 4 at a time); `claude plugin
test .`: 55 pass, 0 fail, and `claude plugin validate` (plugin and
marketplace) through `test_mod`; `tests/acceptance_dialogs.py`: 56 passed,
0 failed (162 s; the run before failed one check, a test bug in reading the
queue line, and the one before that found the stale-key field: DECISIONS
"PLAN-v4 phase 3"); the TUI harness self-test 166 passed (default
sections) and section t 9 passed; on Linux (the Debian 13 arm64 VM, pixi
0.82.0, a copy of the plugin folder without the user's data, `pixi install
--locked`) `test_dialogs` + `test_broker` + `test_daemon` 97 passed, 0
failed. Before that (2026-10-20, after the phase 2 review fixes): 995
tests passed, 0 failed (171.7 s at 4 at a time); 702 of 702
mutations killed (mutation_check 76, accounts 56, daemon 76, e2e 26,
packaging 42, ssh 96, sudo 162, ux 168; 8 min 53 s; the daemon file again
after a last one-line change, 76 of 76); `test_mod` ran `claude plugin
validate` (plugin and marketplace) and `claude plugin test .`; on Linux (the
Debian 13 arm64 VM, pixi 0.82.0, a copy of the plugin folder, `pixi install
--locked`) `test_daemon` + `test_broker` 70 passed, 0 failed. Before that
(2026-10-19, after PLAN-v4 phase 2): 983 tests, 677 of 677 mutations,
`claude plugin test .`: 32 pass, 0 fail. On Linux (the Debian 13 arm64 VM, a
read-only copy of the plugin folder, `pixi install --locked`): `test_daemon`
+ `test_broker` 58 passed, 0 failed; the whole suite 958 passed, 25 failed
(the same 25 fail on the pre-daemon copy; Status, "Not done"). A live
interactive session (TUI harness, scratch config, fake API, e2e install)
checked the mod's registration, `/gate-doctor`'s daemon line, contract.json
and the daemon's exit with the harness's run dir (8 checks passed; the
script's own leftover-process scan matched the script itself). After PLAN-v4
phase 1 (same day): 918 tests, 614 of 614 mutations, `claude plugin test`
21 pass. The e2e suite (`pixi run e2e`) wasn't re-run in phases 1 and 2. Earlier (after the first-SessionStart fixes): `pixi run e2e --only jobs` (with
checkpoint's checkout next to this repo) ran 3 times: 38 passed, 0 failed,
0 not reached each time (no classifier denial; hook-session took 650-740 ms
in each run's first session). The whole ten-scenario `pixi run e2e` last
ran at the integration lows (115 checks passed); the verifier then saw the
`jobs` scenario fail 3 of 3 times on classifier denials, before it got its
project context.

## Testing rules

- Use `harness.gateway_env()` (or `testing.override(root, ...)`): a temp
  home, data, run and user home, plus fakes: `FakeDialog`, the fake sudo
  (`tests/fakes/fake_sudo.py`: password and NOPASSWD modes, sudoers.d, no-tty
  askpass), the fake visudo, a local sshd on 127.0.0.1 (`harness_ssh.py`), a
  local smart-HTTP git + LFS server, local API servers. Under any override
  without a fake dialog (and without the `native_dialogs` knob a daemon
  test sets), no dialog can open: popup reports it as unavailable.
- Never run gateway Python in a subprocess without a valid `--test`
  (`harness.run_py`), `tests/entry.py` or an explicit override in `-c` code.
  The in-process guard can't see child processes.
- A Python subprocess that imports the plugin's code passes `*H.PYX`, and a
  generated script sets `sys.pycache_prefix = H.PYC` (`-I` ignores
  `PYTHONDONTWRITEBYTECODE`); a prefix that doesn't exist (`/x`) makes CPython
  create empty folders relative to the cwd. `run_tests.py` fails the run with
  `LITTER:` if a run leaves anything new in the plugin folder.
- Daemon tests use `harness_daemon.daemon_env()` (a short run dir under
  /tmp, knobs in `ROOT/gated-test.json`, the daemon started with `run.py
  --test gated start`) and run gateway processes below a `FakeClaude` (a copy
  of python named `claude`). A hook started straight from the test runner
  would register the test runner's own Claude Code ancestor with the test
  daemon; keep it under a FakeClaude. Never start a gated without an override
  in a test: `lifecycle.ensure_running` passes `--test` and the test root
  itself. The test guard's mutations (`mutations_daemon.py`) run with
  `GW_TEST_REAL_HOME` (a scratch folder standing in for the person's home),
  because a mutated guard would stat the real one through `run_tests.py`'s
  own `tmp_base()`.
- A test server with an accept thread must `shutdown()` its listener before
  `close()` (and join the thread): on Linux `close()` doesn't wake a blocked
  `accept()`, and the thread left behind takes a later listener's
  connections when that listener reuses the fd number (`HoldProxy.close`,
  DECISIONS "PLAN-v4 phase 4 review fixes").
- Terminal tests (`test_terminals`) run a real gated with the env's tmux on
  the test run dir's private socket (`<run>/tmux.sock`); the daemon_env
  cleanup kills it (its argv names the run dir), and gated stops it when the
  run dir goes (so does the server's own `gw-watch` session once its socket
  is gone, when gated was stopped first; terminals.md). Never reach the user's tmux server. The `tmux` knob points
  gated at a logging wrapper (what reached tmux's argv). A test that waits
  for output must look for text the typed line itself can't show (the
  `Agent.run` marker, `"GOT""LEN"`): the echoed command contains its own
  words. The fake sudo asks on `/dev/tty` with echo off when it has one.
- Remote runtime tests (`test_remote`, `harness_remote.remote_env()`): real
  sshds on 127.0.0.1 (harness_ssh) and a real gated attached to that env, with
  the knob `runtime_artifacts` pointing at fake artifacts (a stand-in
  pixi-unpack that links the env's bash and tmux): staging, sha256, unpacking,
  the probe and the runtime's tmux all run for real over ssh, no network. The
  runtime base is a short folder under /tmp (tmux's socket path < 104 bytes);
  `remote_env` kills whatever names it at the end. Remote commands run as you
  with your real HOME (the harness sshd's behaviour): give every terminal and
  job an explicit cwd under the test's folders. Other knobs:
  `remote_corrupt_upload`, `remote_no_hash_tool`, `remote_df_avail_kb`,
  `remote_tick`, `remote_stale`, `ssh` (an argv-logging wrapper, or
  `test_remote._lossy_ssh`, which drops one answer: after the command ran, after
  the marker, before it reached the host). A test that needs the host's
  connection to drop closes the masters and clears the address cache in
  process (`ssh.close_masters`, `ssh_conf.cache_clear`: same run dir).
- Never ssh or scp to a real machine (the user's `~/.ssh/config` has real
  hosts), never run real sudo except `sudo -n true`, never open a real
  dialog, never touch the person's clipboard (gated runs only the
  `clipboard` knob's program under any test override). The one exception is
  the disposable test VM the user approved (`tests/acceptance_remote.py
  --vm`): a throwaway gateway key appended for the run and removed after,
  everything under `~/gw-remote`, the disruptive steps against a private
  sshd the run starts inside the VM (never the VM's own sshd, which other
  agents use), the user's `~/.bashrc` probe restored byte for byte.
- Every behaviour change gets a test. Every security property gets a
  mutation in `tests/mutation_check.py` or `tests/mutations_*.py` that makes
  a named test fail. Run mutations only through `pixi run mutations` (or one
  mutation file with `--copy DIR`): they edit scratch copies, never the
  checkout.
- The e2e suite runs `claude -p --plugin-dir <scratch copy> --permission-mode
  auto` against the harness servers. The copy carries an `e2e-root` marker
  that redirects every location (`paths.e2e_context`, `hooks/e2e.sh`,
  `tests/e2e/README.md`), and the suite asserts before starting that nothing
  points at the real `~/.config/gateway`. Never point a claude session with
  this plugin at the real home.

## Gotchas

- **Don't run production entry points here.** A run during development left
  a stray `~/.config/gateway/private/` in the user's real home (leave it
  alone; it is the user's to clean up). That is why the
  harness guard, run.py's refusal of `GATEWAY_TEST_ROOT` without a valid
  `--test`, and `testing.override`'s refusal of real locations exist. Never run
  `run.py`, `launch.sh`, the stand-ins in the data folder's `bin/`, the
  `~/.config/gateway/gate` launcher, or a Claude session with this plugin
  against the real home. Never read, list, copy or change the real
  `~/.config/gateway` (live secrets).
- **Hooks load at session start.** A change to `hooks.json` or `.mcp.json`
  needs a new session (the Python behind a hook runs fresh each call). Test
  wiring headless with a scratch copy (see e2e above).
- **The desktop app starts hooks and MCP servers with a minimal PATH.**
  launch.sh finds pixi in fixed places; stubs and hooks use absolute paths;
  nothing may depend on the user's shell profile.
- **launch.sh's file guard fast path** (`gw_fast_files`, review round 5)
  must never pass what `hooks_files` denies: when the file guard learns a
  new protected place, teach the fast path to send it to Python too.
  `test_ux_hooks::test_file_guard_fast_path_passes_only_what_python_passes`
  compares the two case by case (it needs physical paths: on macOS a test
  root under `/var/folders` is behind a symlink, so every case would go to
  Python and prove nothing).
- **env.sh is sourced by other launchers** (checkpoint jobs, the user's
  terminal), also after an uninstall: keep everything after `GW_BIN=` inside
  `if [ -d "$GW_BIN" ]; then … fi`, POSIX, no `return`/`exit`, nothing that
  assumes Claude's Bash (`CLAUDE_PID`), idempotent under `set -eu` in sh,
  dash, bash and zsh (`test_envfile`).
- **SessionStart must survive being cancelled or killed** (Claude Code's
  20 s limit): launch.sh writes the env file, and missing stand-ins and git
  reset, before it starts Python (`pre_session`), and every file
  SessionStart writes is written whole (temp file, then rename or link).
  A new write path follows suit (`test_session::test_a_killed_session_start_
  leaves_nothing_half_written_and_the_next_one_recovers` kills it halfway
  through each write in turn). Keep slow imports (popup,
  urllib, ssl) out of SessionStart: a new env's first loads are paid by
  `ensure-env`'s warm step (`gateway/warm.py`), not by the sync hook.
- **launch.sh's degraded output must stay byte-identical** to
  `envfile.env_text("refuse")`, `stub_text`,
  `launcher_text(state)` in each of its three states (building, pixi
  missing, build failed), the git reset and `degraded_bash_text(kind)`
  (tests compare them). Change both together. Its degraded file guard now
  also denies session transcripts (a `.jsonl` under `*/projects/`, and a
  Grep rooted at or above the `.claude` / `.config/claude` projects folders),
  byte-identical to `hooks_files.DENY_TRANSCRIPT` / `DENY_TRANSCRIPT_SEARCH`.
  The cold Bash guard sees only what `pre_bash.sh` forwards (its trigger
  words), like Python; it strips quotes and backslashes and treats a glob or
  a separated `.config` + gateway/recursive-reader as naming the private
  folder.
- **The build lock** (`$ENVD.building`) holds `owner` (pid, ps start time,
  the machine's stable id from `gw_hostid` — never `uname -n`, which follows
  the DHCP name on macOS; then the pixi child's pid and start time). It is
  live while either process is (a reused pid has another start time; a zombie
  is dead); a lock without an owner file is live for a minute, one from another machine
  for 30. A signal leaves the lock with its dead owner so a waiter takes
  over at once; a normal exit removes it. `status` reports all of it.
- **The mod** (`hooks/mod/`): a command a mod registers can't have a colon
  and isn't prefixed with the plugin name, and `/doctor` is Claude Code's,
  hence `/gate-doctor`. Spell the command name as a literal in
  `$.command.register` and the `command.run` matcher, or `claude plugin
  validate` lists the hook as a gate. A mod isn't given
  `CLAUDE_PLUGIN_DATA`: `lib.locate` derives it from the install path
  (`<config>/plugins/cache/<mkt>/<plugin>/<ver>` -> `<config>/plugins/data/
  <plugin>-<mkt>`; `--plugin-dir` -> `<plugin>-inline`) and passes it to
  `launch.sh status|ensure-env`. Claude Code prefixes status lines and
  command output with the plugin name ("gate: ..."); don't repeat it. In
  `claude plugin test` the kit has no fs, process or clock: the test's
  `on(...)` hooks answer them, `$`-call hooks with `{ value }`, streaming
  `process.spawn` as an async generator returning `{ value: { code, signal } }`.
  `claude plugin test` runs every `*.test.ts(x)` under the plugin folder.
- **The dialog's Client field** (`hooks/mod/field.tsx`): its `onKey` and
  `onPointer` listeners are set once, at the first render, so they must read
  the instance's latest props (`inst.props`), never the first render's
  closure (a gated restart changes the public key under a live field). A
  Client takes keys only after a click, Claude Code 2.1.301 sends plugins
  clicks only in its fullscreen layout (`CLAUDE_CODE_NO_FLICKER=1`; the TUI
  harness with telemetry on starts on the main screen), Escape returns the
  keys without telling the Client, and the pane's `isFocused` stays false
  while a Client holds the keys: don't build on it. In the test kit,
  `$.ui.focus(args)` reaches a `ui.focus` hook with its own arguments
  (`key`, not `element`), and a test must answer `ui.focus` beneath.
  Never let the field's text reach surface state, a post or a log: only
  `{id, attempt, epk, nonce, box}` leaves it.
- **Native dialogs in tests** (`test_dialogs`): a real gated
  (`harness_daemon`), a `FakeClaude` registered as a terminal session by a
  fake mod (`Mod` in the test polls `/ui/dialog/next` and submits sealed
  boxes with PyNaCl, as the Client would), and the requesting program run
  below it (`write_driver(native_dialogs=True, popup_wait=..., dialog_timeout=...)`,
  `GW_ASK`). The mod side (pane, field, guard, sealing) is tested in
  `hooks/mod/dialog.test.ts` under `claude plugin test`; the whole path
  live by `tests/acceptance_dialogs.py`. `ancestry.claude_ancestor` (the old
  `gate secret` check) is no longer used by any flow; its tests stay with
  the ancestry module (`harness_ux` still sets `extra["claude_ancestor"]`).
- **The sh hooks take the home from the password database** (`hooks/home.sh`),
  like `paths.user_home()`, never `$HOME`. In tests, `launch.sh MODE --test`
  (harness.run_launch adds it) and `post.sh|prompt.sh --test` use
  `GATEWAY_TEST_ROOT`; `GATEWAY_TEST_ROOT` without `--test` resolves no home
  at all, so a test can't reach the real `~/.config/gateway`. Never run a sh
  hook in a test without `--test` unless its home.sh is replaced by a stub
  (as `tests/test_ux_hooks.py` does).
- **Managed execution** (`hooks/gate-sh`, `managed.py`): gate-sh's variable
  lists and credential words are mirrored in `managed.PLATFORM_NAMES`,
  `CLAUDE_NAMES`, `GATEWAY_NAMES`, `CREDENTIAL_WORDS`, `form.SHELL_PASSED`
  and `form.CREDENTIAL_NAME` (a test compares them); change both. Before its
  classification gate-sh may use builtins only and assign no variable (the
  hook passthrough must stay exact: an assigned name that is exported would
  reach the hook). Never put a variable's value on a command line (env's or
  any other): names only (`test_no_value_reaches_a_command_line`). A test that runs pre_bash.sh
  as a managed session would must set `CLAUDE_CODE_SHELL_PREFIX` to the copy's
  `hooks/gate-sh`: without it every Bash and Monitor call goes to Python.
  The managed rc is `envfile.env_text` plus Claude Code's helpers: it applies
  only while `$DATA/bin` exists (a test makes it). Tests of the tool path
  link the test env's bash into the override's `paths.env_bin()` (no python3
  there, so no env counts as ready). Claude Code honours `CLAUDE_CODE_SHELL`
  only before its first shell use (the snapshot is made then).
- **The Bash prefilter is a word list** (`pre_bash.sh`). A new command the
  hook must see needs its trigger word there too. (Since phase 6 a gw
  `job_start` with a top-level remote `host` always goes to Python: it is
  judged as `ssh HOST CMD`.) It serves checkpoint's
  `job_start` too (its `command`/`argv` are in the payload's JSON text);
  tests that judge job payloads set `CLAUDE_PROJECT_DIR` (the tests run
  under Claude Code, and a job without `cwd` starts there).
- **Plugins can't ship permission rules or env**; every rule is a hook
  decision. Plugin `bin/` would be appended last on PATH (don't add one); the
  stand-ins live in `$CLAUDE_PLUGIN_DATA/bin`, put first by the env file.
- **`/gate:status` uses `!` injection.** Injected commands run through the
  Bash tool (the env file applies, so `gate` is found), but PreToolUse hooks
  don't see them; outside auto mode they need the command's `allowed-tools`,
  and a non-zero exit aborts the command (hence `gate status || true`).
- **If the gateway is installed in your own session**, its hooks apply to
  you: curl/wget are refused, reading `~/.config/gateway/private` or session
  transcripts is refused (a Workflow run's `journal.jsonl` is fine), and
  your Bash runs the stand-ins first on PATH.
- **pixi**: use `pixi run --locked ...`; another plugin of the user's
  (pixi-guard) may refuse a bare `python3`.
- **tmux under gated** (`daemon/terminals.py`): tmux resumes a pane whose own
  process SIGSTOP stopped (SIGCONT for any stop but SIGTTIN/SIGTTOU), so a
  suspend stops the root with SIGTTOU (`stop_group`); `-t =NAME` works for
  session commands but a pane-scoped command needs `=NAME:`; Linux's tmux
  gives `#{pane_dead_signal}` as a number, macOS's as a name
  (`signal_word`); `#{pid}` is the server's pid. A pane's tty is read with
  `O_NOCTTY` and closed at once (a held slave keeps a dead pane's tty from
  hanging up); `tcgetpgrp` on it fails (not our controlling tty): use ps's
  `tpgid`.
- **The remote runtime** (`daemon/remote.py`, `runtime_pack.py`): the conda
  pixi-unpack is not static (openssl and libgcc_s by rpath: ship `lib/` next to
  `bin/`), and the local pixi-unpack refuses another platform's pack, so the
  unpacker is extracted with zipfile + the env's zstd + tarfile. Debian's bash
  reads `~/.bashrc` for ssh commands (SSH_SOURCE_BASHRC): never rely on the
  login shell, only `exec /bin/sh -c` behind a marker. `stty -g` is
  colon-separated hex on GNU/busybox (lflag 4th: ECHO 0o10, ICANON 0o2) and
  `gfmt1:lflag=...` on macOS (ECHO 0x8, ICANON 0x100). The runtime folder plus
  `/tmux.sock` must stay under 104 bytes. gated can't be its own dialog client
  (popup takes a lease from gated): its own questions are `open_owned(...,
  kind="confirm"|"info")` (owner "gated", never persisted). One ssh command
  at a time per host (`RemoteHost.lock`; the connection's config folder and
  agent are shared); a failure closes the connection. Killing a session's
  sshd doesn't stop the daemonized remote tmux (that is what survives).
- **The terminal pane** (`hooks/mod/term.tsx`): the space bar reaches a
  Client as the key `space`; the engine keeps ^C, ^D, ^Z and Escape (Ctrl-]
  is the prefix); after the person clicks into the screen the Client holds
  the keys until Escape or a click elsewhere (the acceptance clicks the
  prompt row before its next prompt); while a secret dialog waits the
  prompt box takes only the gateway's commands (phase 3's guard), so an
  agent step during a password prompt must be part of the running turn.
- **Headless `claude -p`** auto-cancels anything interactive, and the desktop
  app auto-cancels MCP elicitation (see DECISIONS).
- The audit log (`$CLAUDE_PLUGIN_DATA/audit.jsonl`) is shared by all
  sessions on the machine.

## Status (2026-10-21, v3 / plugin 0.9.0)

On branch `v3-hosts-accounts`, nothing committed yet. Phases A (core), B
(sudo, ssh, accounts, ux groups) and C (integration) are done: every phase B
request is settled in `docs/phaseB-requests/RESOLUTION.md`; hooks, MCP and
manifests are wired; the v2 modules, commands and installer are gone (only
`vault_v2.py` stays, for migration). Review round 1 (2026-10-19) is fixed:
"ask" rights only for a command Claude typed, scp/sftp/rsync option
allowlist and local-path rules, gh hosts, az scopes (`docs/DECISIONS.md`,
`docs/modules/sudo.md`). Review round 2 (2026-10-19) is fixed too
(`docs/DECISIONS.md`, "Review round 2"): `#` comments in bashparse, no
secret on a dialog's command line (no generated export passphrase),
PostToolUse masks vault values in every response once a vault exists, az
gives raw tokens only to programs with `scripts = true`, a credential belongs
to the approved name + kind, the gateway's ssh helpers honour the ssh right,
held-back output released after 0.15 s, the Linux askpass parent check, a
narrowing persisted before any vault exists, `form_last_good` kept current,
hooks on an older env while an update builds, and truthful next steps in
the messages. Review round 3 (2026-10-19) is fixed too (`docs/DECISIONS.md`,
"Review round 3"): allow only for bare command names, deny/ask by the
stricter of form and effective right, a PostToolUseFailure hook warning for
a failed command's output (round 3's env-file EXIT trap and Monitor `| gate
scrub` rule were later rolled back, below), subagent transcripts protected,
gate check re-verifies hosts and stops behind a jump host that isn't set up,
the user's agent for "use my own SSH login once" from the session record,
the launcher from the first session, a non-blocking askpass, hf's token
through a file, and clearer next steps (waiting rights, accounts, copy-to,
gate why, catch-alls).
Review round 4 (2026-10-19) is fixed too (`docs/DECISIONS.md`, "Review round
4"): `sudo visudo|vipw|vigr` never allowed; Claude Code's task
notifications pass the prompt hook, which holds back one quoting a stored
value (idle and mid-turn, verified headless; round 4's background `2>&1 |
gate scrub` rule was later rolled back, below); the desktop app's transcript
export denied and its transcript search held back while a code is live; the
sh hooks use the
passwd home; git's `erase` marks the account whose token was rejected; no
claimed pop-up for a rejected token; leak warnings name commands that really
replace the secret; `gate import-ssh` follows `Include` and never proposes a
git server (the form refuses one); gate check asks nothing for a host it
couldn't reach and keeps inside Claude Code's 2-minute Bash timeout; the
launcher speaks to the user in every degraded state; a mid-session
conversion's report comes at the next prompt and says "0.6"; message polish.
Rolled back afterwards (2026-10-19, the lead's decision; `docs/DECISIONS.md`,
"Rolled back"): the gateway must not change how Claude's ordinary commands
behave, so the env file's EXIT trap and the hook rules requiring `| gate
scrub` for Monitor and background commands are gone (`gate scrub` stays,
optional; the PostToolUseFailure warning and the task-notification check
stay); a Workflow run's `journal.jsonl` is readable (exact name and place;
transcripts and subagent transcripts stay denied); `gate secret` and the
terminal export/import/copy-to path also refuse under any Claude Code
ancestor process or a process tree they can't read (the one-time code
stays).
Review round 5 (2026-10-19) is fixed too (`docs/DECISIONS.md`, "Review
round 5"): a process tree `gate secret` can't read gets its own message
(macOS can't read the path of an executable replaced while it runs: shells
and tmux after `brew upgrade` / `port upgrade`), and the walk goes on above
it; the approval hook denies `gate secret` in every tool (the Terminal panel
included) and `gate export|import|copy-to` in the panel; and the per-call
cost: post.sh no longer starts Python for an edit tool's response, the
PostToolUse hook imports only what it needs, and launch.sh passes plain
file-guard paths in sh.

Checkpoint jobs (2026-10-19; `docs/DECISIONS.md`, "Checkpoint jobs"):
checkpoint's `job_start` goes through the Bash approval hook (same matcher
and prefilter): Bash's denies, `gate export|import|copy-to` denied, an
`"ask"` right denied ("a job can't use the "ask" right ..."), never `allow`
or `ask`; env.sh does nothing once `$DATA/bin` is gone (so checkpoint may
source it, also after an uninstall); `typed_by_claude` refuses the
checkpoint runner explicitly; Claude's context mentions jobs when
checkpoint's state folder exists, and the skill and README say how jobs are
treated. Integration review (2026-10-19): a job's `cat notes.txt` came back
raw through `job_tail`; the PostToolUse and PostToolUseFailure matchers now
name `job_tail`, `job_status` and `job_stop` (exact names; no Python
change), so their results are masked like Bash output (a failed `job_stop`,
an MCP error result, gets the PostToolUseFailure warning; probed headless
with a standalone plugin). The same names, patched into a scratch copy's
matchers, were verified live by the integration run (its `leakfix`
session: `job_tail` came back with `***`); a two-plugin `claude -p` run with
this checkout's hooks.json is the integration phase's.
Integration lows (2026-10-19; `docs/DECISIONS.md`, "Integration lows"):
parallel ssh calls to one host share one master (the stand-in holds a
flock on `<run>/cm-%C.lock` while it checks for and starts a master, at
most 5 s for a waiter), so OpenSSH's "ControlSocket ... already exists,
disabling multiplexing" no longer lands in the output; an `"ask"` right
reached inside a job (checkpoint's runner anywhere above the stand-in) gets
the approval hook's job wording from the ssh and sudo stand-ins too
(`consent.job_ask_message`); the tests pin checkpoint's current job wrapper
(`tests/harness_sudo.py` `CHECKPOINT_WRAPPER`, copied 2026-10-19; update it
when checkpoint's changes) and check env.sh applies silently under it; the
e2e suite has an optional `jobs` scenario (two plugins, CHECKPOINT_HOME and
CHECKPOINT_GATEWAY_ENV inside the e2e root, a kill switch on checkpoint's
server environment).
First SessionStart and the e2e jobs scenario (2026-10-19; `docs/DECISIONS.md`,
same title): a new env's first sync SessionStart took 5-13 s (once past
Claude Code's 20 s limit, which dropped the context), because macOS checks
each new binary and library at its first load; `ensure-env` (async) now
loads a new env once (`gateway/warm.py`, `.warm`) and SessionStart no longer
imports popup, urllib or ssl (harness, fresh env: first hook-session 5.5-6.0
s before, 0.56-0.98 s after). launch.sh writes the safe env file (and
missing stand-ins and git reset) before SessionStart's Python, every
SessionStart file is written whole, and one that finishes past the limit
leaves no context record, so the next prompt's hook gives the context. The
`jobs` scenario's session gets a `CLAUDE.md` with the facts (the user's own
test, local sshds, fake secrets, the task), and a job step Claude Code's
classifier denies is reported as "not reached (classifier)", never a pass
or a gateway failure (the gateway never approves a job). A job that
outlives its session gets credentials only from entries with `scripts =
true` (README, skill, context and DECISIONS "Integration lows" say so).
Follow-ups (2026-10-19; DECISIONS "Integration lows"): a call that gives up
on the ControlPath lock reaches the hops it couldn't lock without
multiplexing and keeps its agent until its ssh exits (the holder's master
killed it mid-login: "refused Claude's key"), and only a lock holder kills
its agent early; background Bash isn't a way around a job outliving its
session (the docs said so; removed); the e2e `jobs` scenario judges a
retried step that ran; an untraced caller (`?`) is named in words by every
stand-in.

PLAN-v4 phase 1, packaging and the mod skeleton (2026-10-19; PLAN-v4
matrix rows for section 2, 3 and 13): shipped installs use `pixi install
--locked` (launcher, feature envs, pijul build) and `requires-pixi =
">=0.68.0"` (tested 0.68.0-0.82.0, no upper bound); the build lock records
its owner and pixi child, so a killed build is stale at once and a waiter
takes over (tests kill a fake build half way); while no env can run Python
the Bash hook denies in sh (private folder, transcripts, credential shapes,
curl/wget with a vault; byte-identical to `envfile.degraded_bash_text`; seen
working in a real interactive session and in `claude -p`); Python's bytecode
goes to `$DATA/pycache`, never the plugin folder; `tests/release_check.py`
(`pixi run release-check`) and `test_release`'s every-referenced-file check;
README lifecycle commands, the git prerequisite with the verified `pixi
global install git` route, supported systems and the Windows/WSL statement;
`docs/CAPABILITIES.md`. The mod (`hooks/mod/`) shows the setup status line,
provisions through `$.process.spawn` at session start and serves the
immediate `/gate-doctor` (verified in a real interactive session: status
line `gate: setting up… 0:00` then `gate: ready`, the doctor's report with 0
model requests; and in `claude -p`). New tests: `test_packaging`,
`test_release`, `test_mod` (runs `claude plugin validate` and `claude plugin
test`), `hooks/mod/*.test.ts`; new mutations: `tests/mutations_packaging.py`.

PLAN-v4 phase 2, the daemon and the broker (2026-10-19; PLAN-v4 matrix rows
for sections 4, 11 and 13; docs/modules/daemon.md; DECISIONS "PLAN-v4 phase
2"): `gated` (`src/gateway/daemon/`) listens on `<run>/gated.sock` (HTTP/1.1,
0600), checks every peer by the kernel's credentials (macOS LOCAL_PEERPID +
LOCAL_PEERCRED, Linux SO_PEERCRED; uid first) and sorts it onto a plane (UI:
the registered Claude Code pid itself; agent: a gateway entry point by
executable and argv below a registered session; contract; local; health);
sessions register through the mod (`/ui/register`, from inside Claude Code)
or a gateway hook (`/agent/register`; the new async SessionStart hook
`hook-daemon`), persisted in the run dir; started on demand (mod, hook,
stand-ins with a wrapped key), detached (double fork), single instance
(flock), contract.json written after listening and removed on exit, stale
state after `kill -9` replaced at the next start, idle exit after 30 min
without a live session, exit when its socket is removed, version skew (a
newer plugin restarts an idle older daemon, else reports it); event log
(seq per epoch, bounded ring and JSONL, allowlisted fields) with
`/v1/capabilities`, `/v1/snapshot` (form hosts with `m_` ids) and
`/v1/events` long poll. The broker wraps the vault key with age's scrypt
recipient (`agepass.py`, moved out of transfer.py; verified by unwrapping
before key.txt goes), holds the unlocked identity in memory only, locks it
explicitly (`/ui/vault/lock`, `gate lock`), after `[vault] lock_after`
(default 8h) and on exit, and gives each entry point mode its scoped view
(sentinels for the rest; non-direct callers only `scripts = true` entries),
merging writes. Unwrapped vaults (all of them until phase 3's dialog) keep
the local path; the passphrase is set and unlocked only through test routes.
A locked vault gives one clear refusal (interactive vs headless) from the
stand-ins, the git helper, the http tool, the Bash hook and SessionStart.
`/gate-doctor` and `gate status` show the daemon (running, version, epoch,
uptime, sessions, vault none/unwrapped/locked/unlocked). Verified live in an
interactive session through the TUI harness (scratch config, fake API, e2e
install): the mod's `$.http.fetch` over the socket came from the claude pid
and registered the session (the first try found the native install's
binary, `versions/2.1.301`, refused under the e2e home: fixed, tested,
mutated), `/gate-doctor` showed the daemon, contract.json was written and
the daemon left when the harness removed its run dir. On Linux (the Debian
13 arm64 VM, SO_PEERCRED): `test_daemon` + `test_broker` 58/58. Phase-1
findings fixed: web's local-path rules compare resolved paths with resolved
roots (a symlinked temp root), and testing's guard never stats the real
gateway home (parents resolved, protected paths compared as written; the
e2e-marker test uses a fake real home). New tests: `test_daemon`,
`test_broker` (+ `harness_daemon.py`, `fakes/fake_claude.py`); new
mutations: `tests/mutations_daemon.py`.

Phase 2 review fixes (2026-10-20; DECISIONS "PLAN-v4 phase 2 review
fixes"): every vault read asks the daemon (the client kept its view for the
process, so the MCP server kept sending the real token after a lock); the
daemon keeps the decrypted vault while vault.age is unchanged and forgets it
on lock and write; a session is its pid + start time and the executable is
checked only at registration (an upgrade that deletes a running Claude
Code's binary dropped the session and let the daemon exit for idleness);
entry points are this plugin's run.py or a sibling version folder's in the
plugin cache, started with exactly `-I -S [-X pycache_prefix=]` (a "gate"
folder anywhere got every secret class); passphrases 12 characters to 512
UTF-8 bytes (age's tty line hung for 130 s at 1024) and the wrap's scrypt
runs outside the vault's flock and the broker's mutex, re-checking key.txt
under the flock; `gated status` (/gate-doctor) and `gate status` report
version skew; the daemon's log is rotated while it runs; tests that kill
pid reuse, foreign data-folder pythons, a hook registering its parent shell
and unlock's key.recipient check.

PLAN-v4 phase 3, native dialogs (2026-10-20; PLAN-v4 matrix rows for
sections 3, 4, 11, 11.1, 12, 13, 14; DECISIONS "PLAN-v4 phase 3";
docs/modules/daemon.md "Dialogs", docs/modules/ux.md): every question the
gateway asks is a pane the mod draws inside Claude Code from requests gated
holds (`daemon/dialogs.py`): popup.py takes a dialog lease on the agent
plane before it forks its helper, the helper opens and waits on the lease
plane, the mod long-polls `/ui/dialog/next`. A secret is typed into a
`Client` field (`hooks/mod/field.tsx`: keys only after a click, bullets,
every click starts it over) and sealed there with vendored TweetNaCl
(`hooks/mod/vendor/`, VENDOR.md) to the attempt's X25519 key; gated opens it
with PyNaCl (pixi.toml), refuses plaintext, rechecks the request (open,
deadline, session alive and not paused, the lease's processes alive, the
form entry unchanged) and hands the value once to the helper, which
verifies (fake sudo, ssh, GitHub/HF/Entra) and stores or reopens it with
"That didn't work" (3 tries, a new key each). Paste from clipboard makes
gated read the clipboard by absolute path (pbpaste; wl-paste, xclip, xsel;
root-owned only; the test override's program under any override). The
`prompt.edit` guard holds composer typing back while a secret dialog can
take keys. One dialog at a time per session, the rest queued by identity;
cancel, timeout, focus moving away, failure, gated dying (requests persisted
as metadata, new keys at restart), `/reload-plugins` and pause all clean up
or resume. The vault passphrase: "set a vault passphrase" (two fields;
wrap, verify, key.txt removed) and unlock in gated's own dialogs,
`/gate-unlock`, `/gate-lock`; the daemon's version-skew notice on the
status line once. Removed: dialog.py's osascript/zenity/kdialog backends,
`gate secret`'s terminal path (it now says where credentials are entered),
the terminal export/import path, the one-time codes, browser and
device-code sign-ins (GitHub: a PAT; Azure: a service principal, its
client secret stored as `entra.client_secret`; ml-catalog: unavailable;
existing refresh tokens keep working). Surfaces without the private field
(VS Code, mobile, Remote Control, `-p`, the SDK, mods off) get
"unavailable" with what to do, never another way to ask. `/v1/pause` and
`/v1/resume` are implemented for dialogs (feature "pause"). Found live:
Claude Code 2.1.301 reports clicks to plugins only in its fullscreen
layout, and with telemetry on (the TUI harness behind the record-only
proxy) it starts on the main screen, so the field is drawn only where it
works and the main screen offers Paste (keyboard: `/gate-dialog`, Tab,
Enter); the pane's `isFocused` stays false while a Client holds the keys,
so focus changes are handled by the click and `ui.focus`. The TUI harness
(both repos, identical) gained `proxy.py`, the record-only telemetry proxy
(mitmproxy through `pixi exec`, answers every request itself), and
`safety.record_proxied`. Acceptance: `tests/acceptance_dialogs.py`
(below, "Last full run").

Phase 3 review fixes (2026-10-20; DECISIONS "PLAN-v4 phase 3 review
fixes"): no sudo or ssh dialog named its entry for gated's recheck, so a
password typed after the right was switched off was still verified, stored
and used; now the sudo stand-in (`SUDO_CHECK`), gate check's sudo steps
(`sudo_check`), remote sudo and the login password (`ssh.host_check`) pass
`check` (a list of rights is allowed; form and effective rights), and the
sudo and ssh stand-ins (and gate check before a passwordless sudo rule)
read the rights again before using a dialog's value; "Remember it"
(ticked) is offered on a sudo password a command asks for, local and
remote, also with Paste on the main screen, and a post without the choice
takes the dialog's default; the `prompt.edit` guard also holds on the
terminal's main screen and while the pane is closed or unplaced (only the
gateway's own commands pass); the acceptance run builds the env before any
session (outside the proxy) and puts recording shims for open, xdg-open,
osascript, zenity, kdialog and the terminal programs first on PATH (the
process sampler is labelled best effort). One claim didn't hold: a form
without `[hosts.localhost]` keeps the implicit localhost with sudo on.

PLAN-v4 phase 4, managed execution (2026-10-20; PLAN-v4 matrix rows for
sections 2, 3 and 8; DECISIONS "PLAN-v4 phase 4: managed execution";
docs/modules/managed.md): Claude's commands run in the gateway env's bash 5.
The mod, first thing at session start (also in `-p`), sets
`CLAUDE_CODE_SHELL_PREFIX` to the shipped `hooks/gate-sh`, `GW_MANAGED_DIR`
and, once the env is built, `CLAUDE_CODE_SHELL` (the managed bash; Claude
Code honours it when set before its first shell use). gate-sh passes a
classic hook string through as `/bin/sh -c` (SHLVL given back on macOS) and
runs a Bash-tool script with the snapshot's `source` replaced by the gateway
rc, the rest byte for byte, with platform variables, Claude Code's own and
approved imports (never a credential-looking name; since the review fixes
below, everything else removed by name, no value on a command line); unknown
shapes 126, an unready runtime 75, never the login shell; a newer
gateway.toml makes it renew its settings first. `managed.py` writes
`$DATA/managed/{conf,rc.bash,state.json,bin/,sync}` (SessionStart, after a
build, FileChanged, an approval, an unlock, gate-sh's renewal), and an
executable copy of gate-sh when an install dropped its exec bit. `[shell]
managed = "on" | "warn" | "off"`, `import_path`, `import_env` are consented
under the "settings" entry (lowering and imports widen). Without the prefix
the classic Bash hook decides every Bash and Monitor call: "on" denies
"managed shell unavailable", "warn" runs with a notice once per session.
`/gate-doctor` and `gate status` show the PATH and imports with origins; the
gw tool `host_inspect` reads (never runs) what the host offers. bash joined
pixi.toml (the lock gained only bash 5.2.37). Verified live in the TUI
harness against a baseline session without the gateway
(`tests/acceptance_managed.py`): every route (Bash, background, a subagent,
`!`, skill injection) in the managed bash, a probe plugin's string-form hooks
with the same `$0` and environment, the permission dialog and "don't ask
again" rule on the original command, Pre/PostToolUse payloads, results and
exit codes identical, Escape and timeouts stop the command, `-p` managed, and
with the mod removed the deny and the warn notice. Linux (Debian 13 VM): the
whole suite passes; its 25 old failures were examined (DECISIONS "The Linux
suite"): the git credential helper refused every request where `/bin/sh` is
dash (git's `sh -c` stays a process there; fixed, tested, mutated); the rest
were test assumptions (a hard-coded `/usr/bin/git`, unflushed in-process
output, a group-writable ssh config under umask 002, a pixi found only in
the real home, the machine's own `/run/user` agent, a plugin-only copy's
marketplace validation), made explicit.

Phase 4 review fixes (2026-10-20; DECISIONS "PLAN-v4 phase 4 review fixes";
docs/modules/managed.md): gate-sh no longer puts the curated variables on
env's command line (`NAME=VALUE` to `env -i` let every local user read the
user's own tokens under `others = "mine"`, approved imports and Claude
Code's variables in `/proc/PID/cmdline` or `ps`): it removes every other
variable by name (`env -u`), and only names reach any command line; the
credential words gained PASSPHRASE, CRED, CLIENT_KEY and CLIENT_CERT, so
Claude Code's own credential variables (2.1.301's lists, the mTLS
`CLAUDE_CODE_CLIENT_KEY_PASSPHRASE` included) never reach commands;
`GW_MANAGED_DIR` passes, so a Claude Code started from a command (`claude
-p`, an Agent SDK script) stays managed instead of failing every command
with 75; a hook string that mentions a snapshot or holds the tracker's
text runs as `/bin/sh -c` (a tool script is recognised by its whole shape);
the mod takes `CLAUDE_CODE_SHELL` from `launch.sh status`, never from
`state.json`, and the data folder's gate-sh copy only while it is the
plugin's, so a rewritten `state.json` can only take the prefix away; and
the Linux-only flake in the ssh lock tests was the test harness's: a closed
hold proxy left its accept thread blocked (Linux's `close()` doesn't wake
it), which took a later proxy's connection on the same fd number and reset
it; `HoldProxy.close()` now shuts the listener down first.

PLAN-v4 phase 5, terminals and jobs (2026-10-20, plugin 0.8.0; PLAN-v4
matrix rows for sections 4, 9, 13 and 14; DECISIONS "PLAN-v4 phase 5";
docs/modules/terminals.md): gated supervises terminals (`t_<ulid>`) and jobs
(`j_<ulid>`) in its own tmux server (the env's tmux 3.8, joined pixi.toml;
`<run>/tmux.sock`, `<run>/tmux.conf`: remain-on-exit, history, no status bar,
no clipboard; the user's tmux and `~/.tmux.conf` never used), each the env's
bash with the managed environment (PATH and rc from the managed shell's
files, platform variables and approved imports from the caller, never a
credential-looking name, `GW_TERMINAL`, `CLAUDE_PID=$$`; values through a
0600 start file, never a command line). Records (ids, host, workspace, cwd,
owner session, agent, task_ref, owner, state, exit; never screen or input)
in `<data>/gated/terminals.json`; a restarted gated re-adopts live panes by
id and nonce, and a pane tmux lost (or a reboot) is gone/unknown, always
asked of tmux. The gw MCP server's tools: `terminal_open`, `terminal_read`
(bounded, scrubbed: lines, cursor, alternate screen, title, seq, truncated,
history), `terminal_send` (quotes the seq; stale or a user-held terminal
refused; `delay_ms` queues), `terminal_resize`, `terminal_signal`,
`terminal_close`, `terminal_list`, `job_start` (argv or command, on_pause,
idempotency_key), `job_status`, `job_tail` (bounded, scrubbed), `job_signal`,
`job_list`. One writer at a time: the person's takeover (a click into the
`/gate-terminal` pane, a key, Take) fails Claude's queued input ("input taken
by the user; re-read the screen"), hand back needs a fresh read, agents take
turns (the agent loop from the mod's `tool.call`, keyed by the tool use id).
The pane draws the screen in a `Client` (styled runs; the click is the
takeover; keys batched with sequence numbers; Ctrl-] then c/d/z/[ for
^C/^D/^Z/Esc; buttons) in the fullscreen layout, and a line field plus
buttons on the main screen (never during a password prompt); the region's
size resizes the terminal. A password prompt in a pane (ECHO off, ICANON
on) opens the credential dialog; the sealed value goes to that tty only
after a recheck, by `load-buffer -`/`paste-buffer -d`; the agent sees
"[credential supplied]"; sudo in a terminal is handed to the real sudo on
the tty by the stand-in. CONTRACT-v1's job routes (`POST /v1/jobs`, `GET
/v1/jobs/<id>`, tail, signal) replace the 501s, `/v1/pause`/`/v1/resume`
apply per-job on_pause policies with truthful outcomes, features add jobs and
terminals, events job.* and terminal.*. The approval hook judges
`job_start`/`terminal_send` like checkpoint's jobs; mcp_perm.sh allows the
reads, an idle open and a resize. `/gate-doctor` shows live terminals and
jobs. Found by the tests and the live runs (DECISIONS): a race where the tick
cancelled a dialog mid-supply, tmux resuming a SIGSTOPped pane, Linux's tmux
naming signals by number, the space bar reaching a Client as `space`, an
unreachable tmux server left behind when the run dir goes (gated now stops
it). New tests: `test_terminals` (34), `hooks/mod/terminal.test.ts` (11),
`tests/acceptance_terminals.py`; new mutations: `tests/mutations_terminals.py`.

PLAN-v4 phase 6, the managed remote runtime (2026-10-20; PLAN-v4 matrix rows
for sections 2, 4, 8, 9, 10 and 14; DECISIONS "PLAN-v4 phase 6";
docs/modules/remote.md): terminals and jobs on remote hosts in the gateway's
own runtime there. `runtime/pixi.toml` + lock (bash 5, tmux 3; 4 platforms;
no Python; version = the lock's sha256 prefix) is packed on first need by the
env's pixi-pack (pixi.toml gained pixi-pack and zstd; the lock gained only
pixi-pack) into `<data>/runtime/<version>/<platform>/`, with the target's
pixi-unpack taken out of its conda packages (`--directory-only`, zipfile +
zstd + tarfile; it needs its openssl and libgcc_s, shipped beside it) and a
sha256 manifest checked before every use. gated (`daemon/remote.py`) connects
with the stand-in's own machinery (`ssh._build_link(..., on_mismatch=...)`,
the shared ControlMaster), only for hosts whose ssh right is true; every
command is `exec /bin/sh -c` behind a marker, values on stdin; at each new
master the host's machine id is read and its token stored with the host keys
(first contact) or compared, a changed key or machine opening a gated-owned
confirm dialog (dialogs.py gained owned `confirm`/`info`, owner "gated") that
blocks the host until answered. Staging: `<base>/<version>-<platform>/`
(base: the host's consented `runtime` path, default
`~/.local/share/gateway-runtime`), uploads on stdin, sha256 on the host or
read back, pixi-unpack with TMPDIR inside, an `env -i` probe of bash and tmux,
the marker, older idle marked versions removed; unsupported platforms, full
disks, noexec folders, unwritable or too-long paths are reported with the
remedy. Remote panes (`terminals.py`): `host` on `terminal_open`, `job_start`,
`POST /v1/jobs`, `/ui/term/open`; a start file written on the host; the
runtime's tmux under `env -i` on a private socket in the runtime folder; every
command checks the host record's marker (`bind_check`) and goes through the
pane's own host (`_tm`, machine-bound); a per-host poller (list-panes, `stty
-g`, foreground groups) keeps states honest: `disconnected` /
`waiting_auth` (a refused key, with an info dialog and recovery) while the
host can't be asked, `exited` or `unknown` only from the host's answer, seq
bumped on reconnect and after a gated restart; password prompts through the
credential dialog naming the host (sudo-off hosts ask nothing), the value on
ssh's stdin into the remote `load-buffer -`. The approval hook judges remote
jobs and remote terminal text as `ssh HOST CMD`; mcp_perm.sh doesn't
auto-allow a remote `terminal_open`; the gw tool `host_runtime`
(status/provision/clean); snapshot hosts gain `identity: "verified"`,
`machine`, `same_machine`, `reachable`, `auth`, `runtime`; `host.state`
events; feature "remote"; `gate status NAME` shows the runtime. Found by the
tests and the live runs: the conda pixi-unpack isn't static, the local
pixi-unpack refuses another platform's pack, Debian's bash reads `~/.bashrc`
for ssh commands (outside the managed shell); and three races the loaded
machines showed: a read's record facts were taken before its (slow, remote)
capture, so a credential supplied meanwhile showed on the screen but not as
"[credential supplied]" (the view now describes the pane after the capture;
seen on the Linux VM); a poll whose connection dropped after the marker read
as an empty answer, so live remote panes were marked gone (a 255 after the
marker is now a dropped connection and a poll answer needs its end marker;
seen in parallel stress runs of the host-key test); and gated's `abandon()`
killed whatever process of the tmux binary took its old server's pid (now it
must name gated's socket on its command line too). New tests: `test_remote`
(34), `harness_remote.py`, `tests/acceptance_remote.py`; new mutations:
`tests/mutations_remote.py` (38).

Phase 5 review fixes (2026-10-20; terminals.py, server.py,
docs/modules/terminals.md): verified-finding fixes to the terminal
supervisor. (1) A value a program puts in the terminal **title** (OSC 2) no
longer reaches the agent: the title is scrubbed where it is stored (`_mask`),
so `terminal_read`/`terminal_list`/`job_status`, the pane view and the records
are all masked. (2) A vault value printed across a **soft-wrap boundary** no
longer reaches the agent as two splice-able halves: the agent's plain lines
(and history) are captured with `capture-pane -J` (`_capture_joined`), so a
wrapped value is one logical string the scrubber catches. (3) The **main
agent** (empty loop id) now counts as a real input holder (`holder is None`
means unclaimed, not `""`), so a subagent can't write into its terminal
without a take, and vice versa. (4) A **transient `list-panes` failure** (one
timeout / non-zero exit) no longer marks every live pane gone for good: a blip
is told from a dead server by the server's own pid (`_blip`/`_server_alive`),
and adopt retries before concluding gone. (5) A **paused** session's
`job_signal CONT` is refused (409 `paused`): it can stop or cancel but not
resume (checkpoint's `/v1/resume` is the way back). (6) The **interrupt
escalation** (SIGTERM after the grace) and its `paused_as` are persisted and
re-armed after a gated restart, not silently dropped. (7) A seq handed to the
agent is persisted at once, so a restart's adopt-bump reliably makes a
pre-crash seq `stale` even when the screen moved on while gated was down. (8)
`terminal_list`/`job_list` to the agent are bounded to `LIST_MAX` (live first,
with the true total and `truncated`); the pane list and the contract snapshot
stay complete. (9) An **unknown** job (tmux lost it) carries `ended: null` (its
outcome and end time are unproven), on `job_status`, the snapshot and
`GET /v1/jobs`. (10) The credential dialog's "can't read the executable"
wording is honest (setuid, or replaced/deleted), not only "setuid". Left as a
documented guardrail limit (not a fix, with evidence): the approval hook judges
each `terminal_send`'s text per call, so an agent that splits a command across
two sends evades the text deny — but a terminal is a real shell running as the
user, and the hard boundaries (the `sudo`/`ssh`/account stand-ins, the
encrypted vault) are not split-bypassable; screen-reconstruction of the line
was rejected as fragile (invariant 17, docs/modules/terminals.md "Known
limits"). Two verifier probes did not reproduce a defect: pane text to a
just-appeared password prompt (the pane refuses it; only a sub-tick,
model-invisible, user's-own-keystrokes window remains) and start files left
behind (the pane removes its start file before `sleep`, so none were left).
New tests (9) and mutations (9) in `test_terminals`/`mutations_terminals`.

PLAN-v4 phase 7, hosts, policy, accounts, portability (2026-10-20, plugin
0.9.0; PLAN-v4 matrix rows for sections 4, 8, 10, 11, 12 and 13; DECISIONS
"PLAN-v4 phase 7"; docs/modules/policy.md): **workspaces**
(`[hosts.NAME.workspaces.W]`: root on the host, `local` folder here, own
read/exec/write; `w_` ids from the host's id and root) bind every terminal
and job through gated's `Supervisor._bind` (cwd defaults to the root and
must lie inside it, local paths map to the root, another host's workspace is
refused); identical paths on two hosts are two resources. **Policy**
(`policy.py`): allow/ask/deny in `[policy]`, `[hosts.NAME.policy]`, the
workspace and `[accounts.NAME.policy]` for read, exec, write, network,
elevation, credential, env_import, provision and the per-host grants
forward_agent/x11/remote/stdio; restrictions start at the rights and only
lower them, the strictest wins, each action on its own; consented per key
(raising waits for the OK, lowering is ratcheted); decided in the ssh stand-in
(remote command, scp/rsync/sftp/git directions and paths, tunnels,
forwarding: the forwarded agent holds only the gateway's key for that host),
the sudo stand-in and remote sudo (elevation), gated (terminals, jobs,
provisioning, remote inspection), the managed shell's imports, web (http
writes and credential-free requests), account selection and the approval
hook (a deny with its rule, an "ask" asked); every refusal names the rule
and its line, audited and carried as `rule` on CONTRACT-v1 refusals and
`policy.denied` events. **Accounts** (`adapters.py`): GitHub (fine-grained
or classic PAT), Hugging Face, Azure (SP secret, SP certificate by an RS256
client assertion through the env's openssl, existing refresh tokens) with
states configured/connected/expired/revoked/reauthentication_required told
apart from the services' answers, kept in the vault, `account.state` events,
`gate accounts`; no cookie or session store is needed. **Panes**:
`/gate-hosts` and `/gate-accounts` (immediate, from gated's `/ui/manage`;
edits as fixed `gate host|workspace|policy` subcommands through the form
writer, then the consent dialog; Check and Enter credential).
**Portability**: export/import format 3 (per-item selection, schema,
digest; per-item conflict dialogs; staged import with a backup under
`private/backups` and restore on failure; wrong passphrase asked again,
tamper refused; machine identity; imported credentials checked; nothing of a
live process in the file). **sudo**: the passwordless installer and all
NOPASSWD advice removed; store or ask per call (Remember it); a
TTY-requiring sudoers pointed to a gateway terminal; the hook names whom sudo
runs as and where. **Alternate routes** (credential tools by path, `command
-p`, `env -i`, PATH/ssh-command reroutes, rsync/git naming another ssh)
refused in managed mode, the same-user limit stated. **Phase 4-6
leftovers**: `/v1/pause`/`/v1/resume` bound to the caller's session,
`pause_id` (24 h replay) and no second signal for a job a pause already hit;
the MCP server takes this machine's own id as localhost; remote
`host_inspect` and `[hosts.NAME.shell]` imports. CONTRACT-v1 stays
`gateway.v1` (additive; checkpoint's copy byte-identical). Found while
building: gated's snapshot and ticker reads counted as vault uses and kept an
idle vault unlocked (now `touch=False`); a target notice on stderr broke
merged-output commands (now a hook `systemMessage`); `managed.inspect` would
have answered a remote host with this machine's files (now refused). New
tests: `test_policy`, `test_workspaces`, `test_accounts_states`,
`test_portability`, `hooks/mod/manage.test.ts` (+ updates across the suite);
new mutations: `tests/mutations_policy.py`.

Phase 7 review fixes (2026-10-21; docs/modules/policy.md, ssh.md,
managed.md): (1) deleting or renaming a workspace that restricts anything
is a widening: the approved workspace keeps its root and restrictions until
the user's OK (`consent._ws_restrictions`; the ratchet keeps it approved);
only one that restricts nothing goes at once. (2) The ssh stand-in reads a
transfer server strictly (`ssh_args._rsync_server`, `_scp_server`): only
the exact bare name as the first word (`/tmp/x/rsync --server` is exec)
and only known options; `rsync --remove-source-files` writes each source;
`--log-file`, `--temp-dir`, `--backup-dir`, `--files-from`, protected args
(`-s`), a path that starts with `-` (rsync reads options after the `.` too)
and anything else are exec. (3) Every path of a transfer is decided
(`decide_path`), in the workspace that holds it and in every workspace it
may reach (a folder above a root; a root written the other way, from / or
from ~, since the stand-in doesn't know the host's home; `~bob/x`, `..`
leaving the home, sftp: every workspace); the strictest wins and the
refusal says why. (4) In managed mode the approval hook also denies what it
can't follow: a shell string, eval/exec, a function, find -exec, a variable
as the program, PATH or a transport variable changed earlier in the same
command, `hash -p`, an alias, `git config core.sshCommand`, rsync `-e` in
combined options, `git -ccore.sshCommand=` (`_route_changes`,
`_route_text`, a deliberately broad text scan that skips data
here-documents). (5) The NOPASSWD advice scan covers all of docs/ (and
CLAUDE.md); historical passages that quote the old advice are marked
superseded, the only exemption. (6) Found on the way: `gate workspace
remove` refused a host's last workspace and called every removal a
narrowing; it now removes it and says when the removal waits for the OK.

Not done or not verified live (as of the 2026-10-21 acceptance; the per-phase
notes below were written when each phase landed, and items the acceptance
runs later covered are marked so; the requirements matrix with each row's
validation is in docs/PLAN-v4.md):
- Blocked, not done here: the desktop app (no way to drive it from the TUI
  harness; a manual checklist exists), x86_64 machines (linux-64, osx-64:
  no such machine or VM), Windows/WSL 2 (no Windows machine; native Windows
  unsupported), the real GitHub, Hugging Face and Azure services (no
  authorized test accounts: local API servers only), the real model API
  (the headless e2e suite; the work's rules forbid it), the real GitHub
  marketplace (the tree is uncommitted; a local smart-HTTP git server served
  it).
- Phase 7: `/gate-hosts`, `/gate-accounts`, export and import were driven
  live since (`tests/acceptance_native_ui.py`, macOS and the VM); a policy
  "ask" prompt and the elevation notice weren't; remote `host_inspect` and remote
  imports ran against the local sshd, not the VM; the account adapters ran
  against local API servers (GitHub, Hugging Face, Entra fakes), not the real
  services; ssh key passphrases aren't stored; the elevation notice shows
  only with an allow or ask decision (with no decision Claude Code's own
  prompt shows the command); checkpoint sends `pause_id` since its 0.7.0;
  `/usr/bin/ssh` run by a script, not typed, isn't seen
  (stated limit), nor a typed command obfuscated past the text scan; a
  sudoers file installed by 0.8 or earlier isn't removed; a write grant on
  a host can reach exec through the host's own files (dotfiles, `~/.ssh/rc`,
  a PATH folder; stated in docs/modules/policy.md); workspace paths are
  compared as written (a symlink on the host isn't followed); the review
  fixes ran in the repo suites (the hook through `hooks_bash.main`, the
  stand-in against local sshds), not in a live Claude Code session.
- Phase 6: the remote acceptance ran at the daemon level (a real gated, a
  FakeClaude drawing and answering the dialogs as the mod would), not through
  a Claude Code session; tested remote platforms: linux-aarch64 (the VM) and
  osx-arm64 (a local sshd); linux-64 and osx-64 hosts untested; a noexec
  mount and a full disk only in the suite (a stand-in pixi-unpack, a `df`
  override: the VM's test user has no writable noexec mount); hosts behind
  `via` untested live; `waiting_input` not
  detected remotely either; remote job output is the remote tmux history
  only (no `job.output` counts); the first pack of a platform needs network
  (no proxy settings passed to pixi-pack); musl, BSD, other architectures
  and csh/fish login shells unsupported. (Remote inspection and imports and
  the version bump to 0.9.0 came with phase 7.)
- Phase 5: `waiting_input` isn't detected; the desktop app's pane untested (a
  manual check), VS Code, mobile and Remote Control draw no pane (the tools
  work); without mods a password prompt in a pane is reported, not asked;
  agents aren't told apart without the mod; (since: checkpoint 0.6+ delegates
  its jobs to the contract routes and calls `/v1/pause`, and the terminals
  acceptance ran on the Debian VM too, 63 of 63); (workspaces, `w_`, came
  with phase 7).
- Phase 4: Monitor isn't offered by Claude Code against the harness's fake
  API (a server-side gate), so its commands' routing is code evidence only
  (`Rue(..., "bash")`); the desktop app, VS Code, mobile and Remote Control
  weren't driven; the headless e2e suite (`pixi run e2e`, real model API)
  wasn't run (the hard rules forbid the real API here), and its scenarios now
  run managed; (since: the managed acceptance ran on the Debian VM too, 38 of
  38 after the acceptance fixes); without the mod the user's `!` and skills'
  injection run unmanaged (reported); the desktop Terminal panel isn't the
  managed shell, nor checkpoint's own job runner (used only when the gateway
  doesn't serve the session; delegated jobs run in gated's managed
  environment); remote managed shells and remote host inspection are phase 6.
- Phase 3: the desktop app's `Client` relay and dialogs are untested (a
  manual check); VS Code, mobile and Remote Control weren't driven live (the
  mod's tests and gated's availability rules cover their "unavailable"
  answer); typing on the terminal's main screen isn't possible (Claude Code
  sends plugins no clicks there: Paste only); keys typed into the prompt box
  before the click reach other plugins' `prompt.edit` hooks and are painted
  for a frame (FEASIBILITY-v4 P1; the guard holds them back from the
  prompt); a JS string in Claude Code's memory and a Python string in gated
  and the helper can't be wiped; the real clipboard programs (pbpaste,
  wl-paste, xclip, xsel) weren't run by the tests (the override only)
  (per-item export selection came with phase 7); (since: checkpoint 0.6+
  calls `/v1/pause` on every pause while the gateway serves the session, so
  the dialogs' recheck sees a task paused in checkpoint).
- Phase 2: remote host ids are assigned (their machine identity is
  verified since phase 6); a detached process outside a registered session (a checkpoint
  job after its session ended) gets nothing from a wrapped vault; an
  npm-installed Claude Code (`node`) isn't recognized as Claude Code;
  `lock_after` isn't under the widening rule yet; `hook-daemon` and the
  locked refusals weren't run in a live `claude -p` session; the desktop
  app's mod registration is untried.
  (The 25 Linux failures noted here since phase 2 were examined and fixed
  with phase 4: DECISIONS "The Linux suite".)
- The headless suite (`pixi run e2e`, `tests/e2e/`) covers ten short
  `claude -p` scenarios on macOS only (`jobs` only with a checkpoint
  checkout next to this repo; its job steps depend on Claude Code's
  classifier, which may deny some: "not reached"); it wasn't run in the v4
  work (real model API). Linux end to end ran since through the TUI
  acceptance on the Debian VM (installed copies, Claude Code 2.1.304). The
  warm step's effect was measured on macOS only.
- Phase 1 not verified: the desktop app, VS Code, mobile and Remote Control
  surfaces for the mod (docs/CAPABILITIES.md "untested"); the `/plugin ...`
  slash forms of the lifecycle commands (the shell forms were run against a
  scratch config); pixi versions not named in pixi.toml's comment (the
  tested range was probed on macOS only). (Linux since: install, update and
  uninstall on the VM, `tests/acceptance_install.py`.)
  The cold window still has no output masking and no rights checks (only the
  sh text guard); `logs/` and `quarantine/` stay in the plugin folder (the
  user's data, git-ignored).
- Not tried on a real machine: the pijul cargo build on Linux and osx-64, real
  `visudo` and sudoers (fakes only), FileChanged with
  the gateway itself loaded (a standalone probe plugin was used), the sudo
  stand-in's askpass path against a sudo that needs a password (the Linux
  askpass check of round 2 is unit-tested with a faked `/proc` status only;
  the VM's real sudo was answered through the dialog in a gateway terminal,
  phase 5), NixOS's sudo path.

Known limits (documented in SPEC and the module docs): output that Claude
Code passes to no
rewriting hook can't be masked: every Bash command that fails (a non-zero
exit, a timeout, a kill; PostToolUseFailure only warns; likewise an MCP
error result, such as checkpoint's `job_stop` reporting `stop_failed` with
the job's last log lines), Monitor's lines and
its `ws` source, and a background command's raw output (its "waiting for
input" notice reaches Claude unless the prompt hook finds a stored value, in
any scrubber form, or a token shape in it: then the notice is held back and
masked in the transcript; its task output file stays raw), and a
checkpoint job's log file on disk (what `job_tail`, `job_status` and
`job_stop` return is masked); `gate scrub` is
an optional filter Claude may pipe such output through; gh, databricks, dvc
and `gate with` hold their token
in their environment while they run, which `ps eww` shows to the user's
processes (hf uses a 0600 file); the http tool can't reach sites that
need a proxy; the pijul binary depends on its env's lib folder (rebuilt when
it's gone); a stored remote sudo password is readable by same-user processes
on that host while a sudo runs (the gateway doesn't install passwordless
sudo to avoid it: choose "ask me each time" with Remember it unticked, or an
`elevation` policy);
text prefilters and ancestry checks are guardrails against a cooperative
model, not a sandbox against code running as the user; keys typed into
Claude Code's prompt box before the gateway dialog's field is clicked reach
other plugins' `prompt.edit` hooks and are painted for a frame (the guard
holds them back from the prompt and says to click first); on the
terminal's main screen a secret can only be pasted (no clicks reach
plugins there); while a secret dialog waits (up to 30 minutes) the prompt
box takes only the gateway's own commands (answer or cancel it first); an
edit tool's response (the file's earlier text) stays
unmasked in the transcript's record of the call (Claude Code shows Claude
only a one-line result); an `"ask"` right
can't be enforced for a script sourced into Claude's own shell (`source
x.sh`), whose commands look like Claude's own to the stand-ins; on a
machine's very first session, until the env is built, the Bash hook and the
file guard run only their reduced sh form (by text: private folder and the
`.config` parent, transcripts via Bash and via Read/Grep, credential shapes,
curl/wget with a vault; none of the rights checks), output masking
is off and the http tool is missing (later updates run on the previous env
meanwhile); a secret
printed with a pause of more than 0.15 s in the middle shows its part before
the pause; with `scripts = true` on an azure account with `env`, a program
Claude writes can print a raw token from `az`; the desktop app's transcript
search and event listing return other sessions' text with stored values
masked, but a failed
command's unmasked output recorded there stays as it is. Users with a stored
sudo password (for example from 0.6) keep it; since 0.9 `gate check` never
offers a passwordless sudoers rule (one installed by 0.8 or earlier stays
until the user removes it). A script that runs `/usr/bin/ssh` (or another
credential tool by path) itself, outside the command line the hook sees,
reaches the system tool with the user's own credentials, never the
gateway's (docs/modules/managed.md, "Alternate routes").
