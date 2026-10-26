# CLAUDE.md: working on gateway

Guide for agents (and people) changing this repo. The user's view is
[README.md](README.md); what each release changed is
[CHANGELOG.md](CHANGELOG.md); how to report a vulnerability is
[SECURITY.md](SECURITY.md). Developer documentation and design history are
under [docs/dev/](docs/dev/):

- [ARCHITECTURE.md](docs/dev/ARCHITECTURE.md): how v3 fits together.
- [SPEC-v3.md](docs/dev/SPEC-v3.md): the contract (section numbers are cited
  everywhere).
- [MODULES-v3.md](docs/dev/MODULES-v3.md) and
  [modules/](docs/dev/modules/): module APIs, kept current with the code.
- [DECISIONS.md](docs/dev/DECISIONS.md): why it looks this way, and what was
  tried and rejected. Read it before redesigning anything.
- [PLAN-v4.md](docs/dev/PLAN-v4.md): the v4 upgrade, authoritative where it
  differs from SPEC-v3; its platform evidence is
  [FEASIBILITY-v4.md](docs/dev/FEASIBILITY-v4.md).
- [PLAN-0.11.md](docs/dev/PLAN-0.11.md): 0.11.0 (ungated unless configured,
  per-mode values, the network class, the git stand-in, browser sign-in),
  authoritative where it differs from the documents above; its section 19
  holds the lead's decisions, which win over its other sections.
- [TESTING.md](docs/dev/TESTING.md): how every kind of test runs;
  [TEST-LOG.md](docs/dev/TEST-LOG.md): past runs and per-phase status.

Two documents stay in docs/ because they are not only for developers:
[docs/CONTRACT-v1.md](docs/CONTRACT-v1.md), the checkpoint contract (an
identical copy lives in checkpoint's docs/), and
[docs/CAPABILITIES.md](docs/CAPABILITIES.md), what works on each Claude Code
surface. [docs/CONFIG.md](docs/CONFIG.md) is the user's reference for every
setting.

## What this is

A Claude Code plugin, `gate` (`plugins/gateway/`), in the marketplace
`gateway` (`.claude-plugin/marketplace.json`). Users install it with
`/plugin marketplace add p-w-rs/gateway` and `/plugin install gate@gateway`.
It gives Claude the machines ("hosts") and accounts the user configures in
one form, `~/.config/gateway/gateway.toml`, as ordinary commands (`sudo`,
`ssh`, `git`, `gh`, ...) through stand-ins on Claude's PATH, keeps every
secret in an age vault Claude can't read, and lets the user (or Claude, when
asked) set what Claude may do, per Claude Code permission mode. Everything
the form doesn't configure is the user's own: a stand-in exists only for a
tool that can reach something configured, and passes anything else to the
user's own tool untouched (PLAN-0.11 §1). Users need only Claude Code and
pixi, on macOS or Linux, desktop or headless; keep it that way. Nothing goes
into settings.json.

The parts (each landed in a PLAN-v4 phase; [TEST-LOG.md](docs/dev/TEST-LOG.md)
has what each one added):

- **The mod** (`hooks/mod/`, a TypeScript hooks module): the setup status
  line, provisioning at session start, `/gate-doctor`, the dialog and
  terminal panes, managed execution. The classic hooks keep every guard.
- **gated** (`src/gateway/daemon/`, docs/dev/modules/daemon.md): one daemon
  per user on a Unix socket with kernel peer checks and planes, CONTRACT-v1
  for checkpoint, and the broker that holds a passphrase-wrapped vault key.
- **Native dialogs**: every question is a pane inside Claude Code, drawn by
  the mod from requests gated holds; a secret is typed into a `Client` field
  and reaches gated sealed with NaCl's box. No OS dialogs, terminal prompts
  or device codes; the system browser only for a browser sign-in (azure,
  ml-catalog), after the user presses Open (gated's `daemon/oauth.py`).
- **The managed shell** (`hooks/gate-sh`, docs/dev/modules/managed.md):
  `CLAUDE_CODE_SHELL_PREFIX` runs every command Claude Code starts through
  its shell in the gateway env's bash, with the user's environment minus
  Claude Code's credentials and the shell's startup variables, the
  stand-ins first and unshadowable.
- **Per-mode values and the network class** (PLAN-0.11 §2, §3;
  `modes.py`, docs/dev/modules/network.md): rights and restrictions resolve
  per Claude Code permission mode; network commands are one configurable
  class the approval hook judges.
- **The git stand-in** (PLAN-0.11 §6; `gitroute.py`, `githelper.py`):
  inside a repository with a configured remote every git command runs the
  env's git with its own config and an allowlisted environment; elsewhere
  the user's git, untouched.
- **Terminals and jobs** (docs/dev/modules/terminals.md): persistent PTYs in
  gated's own tmux, one writer at a time, password prompts through the
  dialog, watched and taken over in `/gate-terminal`.
- **The remote runtime** (docs/dev/modules/remote.md): terminals and jobs on
  other hosts, in a bash and tmux the gateway stages there, after the host's
  identity checks.
- **Hosts, workspaces, policy, accounts, portability**
  (docs/dev/modules/policy.md): allow/ask/deny per host, workspace, account
  and action; account states from each service; `/gate-hosts` and
  `/gate-accounts`; export and import format 3.

## Layout

```
.claude-plugin/marketplace.json     marketplace "gateway" -> ./plugins/gateway (plugin "gate")
CHANGELOG.md, SECURITY.md           what each release changed; how to report a vulnerability
docs/
  CONFIG.md                         every gateway.toml setting (the user's reference)
  CAPABILITIES.md                   features x surfaces; what works without mods
  CONTRACT-v1.md                    gateway <-> checkpoint contract (identical copy in checkpoint's docs/;
                                    gated serves discovery, capabilities, snapshot, events)
  dev/                              developer documentation and design history (README.md lists it)
    ARCHITECTURE.md                 how v3 fits together
    SPEC-v3.md                      the contract
    MODULES-v3.md, modules/*.md     module APIs and wiring, kept current with the code
                                    (modules/daemon.md: gated, the planes, the broker;
                                    modules/network.md: the network class)
    DECISIONS.md                    why: platform facts, critiques, design choices, rejected ideas
    PLAN-v4.md, FEASIBILITY-v4.md   the v4 upgrade plan (phases, requirements matrix) and its probe evidence
    PLAN-0.11.md                    the 0.11.0 plan (section 19: the lead's decisions)
    TESTING.md, TEST-LOG.md         how the tests run; past runs and per-phase status notes
    phaseB-requests/                how the build groups' requests were settled (RESOLUTION.md)
    history/                        the approved v3 plan (REDESIGN-v3.md)
plugins/gateway/
  .claude-plugin/plugin.json        name "gate" and the version (the gw MCP server reports it;
                                    test_release keeps the two in step)
  .mcp.json                         MCP server "gw": sh hooks/launch.sh mcp, "alwaysLoad": true
  hooks/hooks.json                  every hook, exec form (table in docs/dev/MODULES-v3.md, "Wiring"; the
                                    async SessionStart `hook-daemon` starts gated and registers the
                                    session), and "modules": ["./mod/register.tsx"]
  hooks/gate-sh                     the managed shell's prefix (POSIX sh; PLAN-v4 phase 4, PLAN-0.11 §1.6):
                                    hook strings pass through as /bin/sh -c; Bash-tool scripts run in the
                                    env's bash with the gateway rc and the inherited env minus Claude Code's
                                    credentials, the startup variables and GW_* (removed by name, `env -u`:
                                    no value on any command line); not ready: without its settings, in the
                                    shell that made the snapshot (never /bin/sh), a notice
  hooks/launch.sh                   finds pixi, builds (`pixi install --locked`, a build lock with a live
                                    owner) and warms the env, runs run.py (-X pycache_prefix=$DATA/pycache);
                                    degraded output while it builds (env file, stubs, file guard, the cold
                                    Bash guard); the safe env file before SessionStart's Python; the file
                                    guard's sh fast path; `status` (one JSON line for the mod)
  hooks/mod/register.tsx, lib.ts    the mod: managed execution first (CLAUDE_CODE_SHELL_PREFIX, GW_MANAGED_DIR,
                                    CLAUDE_CODE_SHELL), status line, provisioning via $.process.spawn, gated
                                    start + UI-plane registration ($.http.fetch over the socket),
                                    /gate-doctor, the dialog pane and loop, the guard, /gate-dialog|unlock|lock
  hooks/mod/dialog.ts               the dialog's pure logic (views, texts, the sealed-post parser; the
                                    browser sign-in confirm and the passphrase offer templates)
  hooks/mod/field.tsx, seal.ts      the private field (a Client module) and its sealing (NaCl box)
  hooks/mod/terminal.ts, term.tsx   the terminal pane's pure logic and its screen (a Client module: styled runs,
                                    keys batched with sequence numbers, the click is the takeover, Ctrl-] prefix)
  hooks/mod/manage.ts               the /gate-hosts and /gate-accounts panes' pure logic (gated's /ui/manage, the
                                    edit line of either pane -> one fixed `gate host|account|workspace|policy|
                                    network` argv, MODE=WORD tokens included; per-mode values drawn in words)
  hooks/mod/vendor/                 TweetNaCl 1.0.3 (nacl-fast.js, one-line ES-module change; VENDOR.md)
  hooks/mod/*.test.ts               its tests, run by `claude plugin test .`
  hooks/pre_bash.sh                 PreToolUse prefilter -> hook-bash: Bash, Monitor, run_in_terminal,
                                    checkpoint's job_start, the gateway's own job_start and terminal_send
                                    (trigger words in any letter case, $DATA/network-words; a plain account
                                    CLI while its stand-in exists and $DATA/ask-clis names it; every Bash
                                    and Monitor call while a record is pending, $DATA/asks; while
                                    $DATA/mode-epoch exists, the rest to hook-mode)
  hooks/mcp_perm.sh                 PreToolUse decisions for the gw tools (sh + awk, no Python); http and
                                    download go to hook-mcp (hooks_mcp.py)
  hooks/tool_guard.sh               PreToolUse: the browser-automation tools while a sign-in runs, and an
                                    AskUserQuestion that asks for a secret (sh)
  hooks/post.sh, hooks/prompt.sh    PostToolUse/PostToolUseFailure (every tool but a skip list; the user's
                                    credential variables checked with builtins) and UserPromptSubmit prefilters
  hooks/e2e.sh                      the e2e marker rules for the sh hooks
  commands/status.md, help.md       /gate:status, /gate:help (/gate-doctor is the mod's)
  skills/gateway/SKILL.md           gate:gateway (user-invocable: false): how Claude edits the form, gate check, accounts
  pixi.toml, pixi.lock              every dependency "*" (latest only, `pixi run update-deps`): Python, PyNaCl,
                                    age, gh, git-lfs, openssh, git, bash (the managed shell), tmux (gated's
                                    terminal supervisor), pixi-pack and zstd (the remote runtime's packs);
                                    features hf, databricks, dvc, registry, pijul
  runtime/pixi.toml, pixi.lock      the managed remote runtime (PLAN-v4 phase 6): bash + tmux for linux-64,
                                    linux-aarch64, osx-arm64, osx-64 (no Python), feature `unpacker` (the target's
                                    pixi-unpack); never installed here, packed by gated (docs/dev/modules/remote.md)
  run.py                            the one entry point: hook-* (hook-mcp, hook-mode included), mcp, shim TOOL
                                    (git too), askpass, git-credential, gate, gated serve|start|status|stop,
                                    managed-sync
  src/gateway/                      the code (stdlib, plus PyNaCl in gated; below); daemon/ is gated
  tests/                            run_tests.py, harness*.py (harness_daemon: a real gated in a test
                                    root, FakeClaude; harness_posture: the user_tools knob's recording
                                    fakes; harness_oauth: a fake OAuth server and the browser knob),
                                    fakes/ (fake_claude.py: a python named `claude`; fake_user_tool.py),
                                    test_*.py, mutation_check.py and mutations_*.py (one file per area;
                                    PLAN-0.11's: posture, modes, network, git, sso, offer, relock,
                                    integration, final, asks; 0.11.1's: setup),
                                    e2e/ (headless claude -p suite; tests/e2e.py forwards to it), tui/
                                    (the interactive TUI harness, identical in checkpoint; proxy.py: the
                                    record-only telemetry proxy), acceptance_*.py (live through tui/:
                                    dialogs, managed, terminals, install, canaries, native_ui; remote
                                    against the Linux VM and a local sshd), update_deps.py (the per-release
                                    relock), release_check.py (is the git index the tested tree? read-only)
  logs/, quarantine/                old v0.5 data some checkouts keep (git-ignored); never move or delete
                                    them (a local folder marketplace would copy them, so installs come
                                    from git only)
  .claude-plugin/types/             written by Claude Code when it loads the mod from this folder
                                    (interactive --plugin-dir); git-ignored
  tsconfig.json                     also written then (extends the types above); git-ignored
                                    (/tsconfig.json), and release_check treats it as engine junk
.work/                              local plans and trackers; never commit it
```

## Modules (`plugins/gateway/src/gateway/`)

| area | modules |
|---|---|
| core | `paths` (every location), `testing` (the test override API), `form` (parse/validate/write the form, its policy/workspace/shell/network tables, per-mode values in their own attributes), `modes` (permission modes, the four words and their order, `ModeValue`, the modeless rule, the recorded mode and its epoch marker), `accounts` (destinations, account choice, `entra_fits`), `vault` (age vault v3, cache, events, the passphrase offer's state, the older copies and their delete, a start-over's move; refuses a vault beside a 0.6 one), `consent` (approved vs effective rights and policy mode by mode, the configured set and `private/configured.json`, removal as a widening, ratchet, `network-words` and `ask-clis`), `asks` (the approval hook's record that Claude Code asked about a stand-in's exact command: record, take, standin, drop at the session's next call, the gate CLI's own command), `policy` (allow/ask/deny/cc decisions with their rule, per mode), `audit`, `envfile` (env file, which stand-ins exist, `user_tool` and the pass-through, stubs, launcher, the cold-window texts), `warm` (loads a new env once), `managed` (the managed shell's conf, rc and its unshadowing tail, state for gate-sh, the removal lists; `gate status`'s section; the host inspection behind `host_inspect`), `gitroute` (the git resolver the git stand-in and the hook share: repository, effective URLs, configured or not), `runtime_pack` (the remote runtime's artifacts: platforms, pixi-pack builds into plugin data, the target's pixi-unpack out of its conda packages, the sha256 manifest) |
| hooks | `hooks_session` (SessionStart/SubagentStart, Claude's context, the first 0.11 session's notice), `hooks_bash` + `bashparse` (approval hook: rights per mode, the records of what it asks about, the configured-only route checks, the hidden-command rule, the network class, git's up-front judging; program names without letter case), `hooks_mcp` (the http and download decision), `hooks_files` (file guard), `hooks_post` (mask every tool's output, form checks), `hooks_prompt` (paste guard), `hooks_filechanged` |
| sudo / ssh | `sudo` (local stand-in: gated, restriction-only, or pass-through; askpass, the passwordless probe, the system sudo's allowlisted environment; never a sudoers rule), `ancestry` (direct vs scripts, typed by Claude), `ssh` (configured, a hint, or pass-through: `ssh -G`, hops, IPs), `ssh_args`, `ssh_conf`, `ssh_sudo` (remote sudo) |
| accounts | `githelper` (the git stand-in: pass-through or the gated git with its environment, global config and include; the credential helper), `clis` (gh, hf, databricks, crane, pijul, az: each tool's destination, pass-through, the account it chooses, an "ask" account with the hook's record; `gate with` and its account's use and credential policy), `asiml` (also dvc's pass-through), `entra` (also a certificate's client assertion, the browser sign-in's client side), `logins`, `scrub`, `adapters` (account states from each service's API, PLAN-v4 phase 7) |
| user | `gate` (CLI, status, lock, passphrase), `gate_setup` (check, login, forget and forget --backups, rotate; account setup by PAT, API key, service principal secret or certificate, or a browser sign-in), `manage` (`gate host`, `account set`, `workspace`, `policy`, `network`, `accounts`, through the form writer, MODE=WORD tables), `popup` + `dialog` (the only way to ask the user: a lease from gated, then the native dialog through gated; `offer_passphrase`; a fake under tests), `transfer` (export, import, copy-to; format 3: per-item, digest, staged import, the confirm in parts), `agepass` (age's passphrase recipient under a private pty: export/import and the vault key's wrap), `web` + `mcp_server` (http, download) |
| daemon | `daemon/`: `peers` (kernel peer credentials, gateway entry points), `planes` (sessions, plane checks, recorded modes), `events` (event log), `broker` (wrapped key, lock, change and removal of the passphrase, start-over, scoped views, merges), `server` (HTTP routes), `lifecycle` (start, detach, single instance, contract.json, idle exit, version skew, the vault's dialogs and menu, CONTRACT-v1's rights words), `dialogs` (dialog requests: the queue, per-attempt X25519 keys, sealed intake opened with PyNaCl, the recheck, leases, persistence, pause; gated's own terminal-prompt dialogs), `oauth` (the browser sign-in: lease, confirm, the 127.0.0.1 listener, PKCE, the browser by absolute path, the token exchange), `offer` (the vault passphrase offer), `clipboard` (Paste: the OS clipboard by absolute path, or the test override's program), `terminals` (the tmux supervisor: terminals and jobs, ownership, password prompts, survival, pause policies; remote panes and their pollers), `remote` (remote hosts: the verified connection, machine identity, the host-change gates, staging the runtime, the runtime's tmux over ssh), `screen` (capture-pane escapes to plain lines and styled runs, PTY streams, key and signal names), `client` (what the other processes call) |

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
   would reveal them) and must not reach an output path. Under the posture
   the user's own environment (their agent and token variables) reaches
   Claude's shell: it is the user's, not the vault's. Claude Code's own
   credential variables never do (gate-sh and the env file remove them). The
   output masker covers every tool's response but a fixed skip list
   (`hooks_post.SKIP_TOOLS`, mirrored in post.sh) and also masks the values
   (8 characters or more) of credential-named variables in Claude Code's
   environment (one list of names, compared with post.sh by a test). A
   question asking the user for a secret (AskUserQuestion) is denied
   (`hooks/tool_guard.sh`).
2. **Credentials go only to bound destinations.** Check `consent.bound_ok`
   (or `EffectiveAccount.may_send_to`) before sending. Host secrets are tied
   to the pinned host keys. Credentialed HTTP goes through `entra.urlopen` or
   `web`'s opener: no automatic redirects with credentials, no proxies, the
   Python build's own CA bundle. The gated git runs with an allowlisted
   environment (no proxy, CA, askpass, trace or config-injection variables;
   `githelper.gated_env`), the gateway's settings at command-line scope
   (first the user's own `user.name`/`user.email` as the user's git reads
   them in that repository, the one the command works on (`git -C`,
   `--git-dir`), `githelper.user_identity`, so the account's
   identity in the include wins: values only in the child's environment,
   never on a command line) and a read-only global config of its own (with
   `user.useConfigOnly`: git never guesses an identity). The configured
   sudo hands the system sudo an allowlisted environment (`sudo.sudo_env`:
   `clis.ENV_ALLOW`, TERM, `sudo -e`'s editor variables and the askpass's
   variables), so `sudo -E` keeps
   only that. The credential helper refuses a URL
   with an `http.proxy`, `sslCAInfo`, `sslCAPath`, `sslBackend` or
   `sslVerify` override, or a remote with its own proxy.
3. **Widening needs the user's OK in the gateway's dialog.** Use effective rights
   (`consent.compute`), never the raw form. Narrowing applies at once and is
   persisted (`consent.ratchet` from every process that loads the form).
   `consent.approve` runs only after the user said yes, with the changes the
   dialog showed. No model-settable "approved" parameter, ever. Nothing
   recorded means nothing approved (`consent.baseline()`: no entry, this
   computer's sudo not configured), and under the posture a target the
   configured set doesn't name is the user's own. The configured set is the
   form (disabled entries included), the approved snapshot and
   `private/configured.json` (rewritten whole by approve and ratchet).
   Taking a configured target out of the gateway is a widening, and the
   approved entry keeps gating until the user's OK: deleting or renaming its
   table, dropping an address, `also`, `via`, owner, host or destination,
   listing the first `owners` of an account that listed none (the only
   account of its kind covers every owner only while it lists none:
   `accounts.owner_covered`, the approval's `any_owner`), adding or
   changing `when`, deleting localhost's `sudo` key, or an import
   replace that does so. Values compare mode by mode (deny < ask < cc <
   allow < unconfigured; `modes.RANK` raises on an unknown word); the
   effective value is the per-mode minimum of the form and the approved
   value, and a policy table's explicit allow ranks above a plain one.
   Writing localhost's `sudo` where none is approved applies at once up to
   `"ask"`; above it waits. A missing or unparseable form falls back to the
   last good form, else the configured list, whose entries are refused. With
   a locked vault the configured list still classifies and configured entries
   are refused (`LOCKED_ENTRY`); so is this computer's configured sudo, up
   front, by the Bash hook wherever it would ask and by the sudo stand-in,
   with the vault's own message (how to unlock: `/gate-unlock`; PLAN-0.11
   §19.16). A disabled entry is configured and refused. A snapshot from
   before 0.11 counts localhost as implicit (not configured). Remote hosts' `ssh` and `sudo` default to
   `true`.
4. **The gateway asks only through its native dialog** (PLAN-v4 phase 3):
   `popup.py` -> `dialog.py` -> gated's dialog requests -> the mod's pane.
   No OS dialog (osascript, zenity, kdialog), no terminal prompt, no
   device-code sign-in, never MCP elicitation, and no other way on a surface
   without the private field (mobile, VS Code, `-p`, the SDK, mods off):
   there the request is reported as unavailable (what is needed, where it
   can be given). The one browser exception is the authorization code flow
   with PKCE for azure (`sign_in = "browser"`) and ml-catalog accounts
   (`daemon/oauth.py`): gated opens the system browser by absolute path only
   after the user clicks Open in its confirm dialog, the callback lands on a
   127.0.0.1 listener, and the tokens go straight into the vault; never the
   desktop Browser pane, and the browser-automation tools are denied while a
   sign-in runs (`hooks/tool_guard.sh`, `<run>/signin-active`). A consent or
   import confirm longer than one pane comes in parts ("Part i of n", at most
   10; each fits 40 rows of a 72-column pane, a wide character two columns,
   `popup.dialog_parts`, and its question beside the buttons names the
   part); nothing applies until the last part is accepted, and a cancel on
   any part changes nothing. Fixed templates; names only after validation
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
5. **`allow` only for SPEC 8 shapes, and only where the effective per-mode
   word is `allow`.** A bare `true` right is `allow` in auto and
   bypassPermissions and `cc` (no decision) in manual, plan, acceptEdits and
   dontAsk; only an explicit per-mode `allow` approves elsewhere, never in
   plan. The mode is the payload's `permission_mode` (`modes.from_payload`:
   empty, missing or unknown reads as default and never allows). The Bash
   hook denies and asks in every mode; it allows only when every segment is
   an allowed shape, run by its bare name (never `./ssh` or `/tmp/x/cat`),
   on an effective `allow` with every policy decision for it `allow` too;
   the benign commands and `gate`'s subcommands, which have no right of
   their own, only in auto and bypass (`BARE_ALLOW_MODES`). A network-class
   hit (invariant 22) makes the whole command ineligible for allow unless
   `[network] commands` itself is allow in that mode (lead decision 19.1).
   An unconfigured ssh host, account or local sudo gets no decision (the
   user's own tool runs). Never `allow` for `gate with`, account CLIs, git,
   `mcp__terminal__run_in_terminal`, checkpoint's
   `mcp__plugin_check_jobs__job_start` or the gateway's own `job_start` and
   `terminal_send` (a job is judged at the stricter of its payload's mode
   and the modeless rule, the network class at its payload's mode alone,
   gets Bash's denies, an `"ask"` there is denied, never `allow` or `ask`).
   Deny/ask use the stricter of the form and the
   effective value (an approved `"ask"` edited to `true` stays `"ask"` until
   the user's OK; a value waiting for the OK is denied with "run gate check
   NAME"), allow the effective value. Never answer `ask` except for an
   `"ask"` value in the current mode (a right, an account's use, a policy
   restriction, the network class, or text the parser can't follow that
   names an "ask" target: see 6; an `ask` always becomes a human prompt).
   Program names are compared without letter case (macOS's file systems
   ignore it: `CURL`, `/usr/bin/SSH`), in the hook, pre_bash.sh and the cold
   guard; the allow step approves only the plain lower-case name. Monitor and
   `run_in_background` commands are judged like any
   Bash command (no `gate scrub` rule; see 14). Never `allow`
   `sudo visudo|vipw|vigr` (they edit sudoers and the user database with no
   path argument), nor `gate forget` (not in `GATE_SUBCMDS`). The plain
   readers (`BENIGN_READERS`: pwd, test, [, ls, cat, head, tail, wc, grep,
   sort, uniq) get the allow only when everything they may read is a plain
   file of the project (`CLAUDE_PROJECT_DIR`, else the cwd; never /, the home
   or a folder above it; its `.claude/worktrees/NAME` count) or of a temp
   folder: no hidden or credential-like name (`_CRED_NAME`), nothing under a
   credential folder (`_CRED_DIRS`, `CLAUDE_CONFIG_DIR`, the gateway's
   home), never under a wrapper's `env -C` or `sudo -D`, and for a recursive
   grep the whole tree (at most `READ_TREE_MAX` entries, every link pointing
   at such a file); the same rule under sudo (`_reads_plain`). `~-`, `~N`
   and `~` with no known home are denied (`DENY_TILDE`). mcp_perm.sh allows
   only host_inspect, the terminal and job reads, a local `terminal_open`,
   `terminal_resize` and `host_runtime`'s status; `http` and `download` go
   to Python (`hooks_mcp`), which answers deny or ask from the effective
   `network` policy for the payload's mode, allow only where the user wrote
   an explicit per-mode allow in this computer's `network` policy (never for
   a call with an account), otherwise no decision.
6. **Credentials go to direct callers only** (`ancestry.is_direct`, by
   executable path) unless the entry has `scripts = true`; an ancestry error
   counts as not direct. **An `"ask"` right goes only to a command Claude
   typed** (`ancestry.typed_by_claude`: Claude's command shell or a fork of
   it, nothing in between, never checkpoint's job runner, never a gateway
   terminal's or job's shell (its `CLAUDE_PID=$$` names a shell, never Claude
   Code), whatever `scripts` says), because Claude Code can only prompt for
   that command; the approval hook denies scp/sftp/rsync on an `"ask"` right.
   A stand-in resolves a per-mode value with the session mode the hook
   recorded in gated (`modes.current_for`, under the current epoch: lead
   decision 3) for a command Claude typed, and with the modeless rule for
   everything else (the strictest word over every mode but plan, allow
   capped at cc): jobs, terminals, scripts, gated, and any caller gated has
   no record for. There an "ask" is a refusal. **An "ask" is proved by a
   record** (lead decision 19.14, `asks.py`): the Bash hook writes one for
   each stand-in stage it answers "ask" for (ssh, sudo, the account CLIs,
   git, and `gate`: `gate with NAME --` for the account, `gate
   check|rotate|copy-to` for the host; Bash and Monitor only, in every
   mode: Claude Code shows a hook's ask in dontAsk too), with that Claude
   Code, the real folder, the tool and its exact
   words (quotes gone, `$HOME` and a leading `~/` the home) and the
   entries it asked about, and denies a stage whose words or folder it
   can't spell out (a variable, a glob, `~user`, a `cd` it can't follow);
   a stand-in passes an "ask" only for a command Claude typed with a
   matching record, used once, within 15 minutes and before the session's
   next Bash or Monitor call, else "run `ssh box ...` as its own command".
   That next call's hook first drops every record the session's earlier
   calls left (`asks.drop`: a prompt declined or never shown, a stage that
   never ran), and pre_bash.sh sends every Bash and Monitor call to the hook
   while one is pending (`$DATA/asks` links to them). So a sourced file,
   eval, a function or anything else the hook can't read gets no record and
   its stand-in refuses: the hook never asks about a hidden command for an
   "ask" entry (`source .venv/bin/activate && pytest` gets no decision),
   refuses one whose text names a configured target, and for text the
   parser can't follow, or a hidden stage beside an asked one, that names
   an "ask" target asks (naming each) with records for the ssh, sudo,
   account-CLI and `gate with` commands it can read there (a here-document,
   `&`, a subshell, eval's or a shell's written-out string, trap's action),
   else denies. An "ask" reaches the gated git (and the ssh stand-in or
   credential helper below it) only with the hook's record, and never
   through a git hook script. An account's use = "ask" works for its CLI as
   for git (`clis._select`); the hook asks about the account the stand-in
   will choose (`clis.chosen`, GATE_ACCOUNT included). `gate with` hands a
   key over only while the account's use and credential policy allow it
   (`clis._with_refused`).
7. **Production entry points never honour test overrides.** Locations come
   only from `paths.py`; stand-ins, askpass, the git helper and `gate` never
   read `GATEWAY_*` or take the data folder from `CLAUDE_PLUGIN_DATA`;
   binaries come from `paths.tool()`, never PATH. The only redirections:
   `--test` with `GATEWAY_TEST_ROOT` for hook and MCP modes (the test runner
   only; `gated` too, with `GATEWAY_TEST_RUN` for a short run dir), and the
   e2e marker in a scratch copy under a temp folder (decided by the code's
   own location, never a variable). The daemon takes its data folder from its
   python, never from `CLAUDE_PLUGIN_DATA`. Exception: a stand-in's
   pass-through finds the user's own tool on PATH (`envfile.user_tool`),
   skipping every folder with a `.gateway-standins` marker and this plugin's
   own envs, and only for an unconfigured target, with a recursion guard
   (`GW_PASSTHRU`). A configured target always uses `paths.tool()`. gated
   opens the system browser by absolute path (`/usr/bin/open`, or xdg-open
   from fixed folders), never `$BROWSER` or a PATH lookup.
8. **Tests never touch the real home.** Everything goes through
   `gateway.testing.override(...)` and the harness; the harness guard aborts
   the run on any real location.
9. **Fail closed where it guards**: the file guard (`onFailure: "block"`,
   run.py exits 2; it also covers the desktop app's transcript export and
   search; launch.sh's sh fast path passes only plain paths Python would
   pass, and sends everything else to Python), the paste guard and the
   task-notification check (prompt.sh blocks if Python can't answer). The other hooks fail open (no decision), so
   Claude Code's own permissions still apply. A cold start never switches a
   guard off: while no env can run Python, launch.sh's degraded paths decide
   in sh (the file guard, and the Bash hook's `degraded_bash`: deny the
   private folder and `~/.config/gateway` other than gateway.toml,
   transcripts, credential shapes; the network class asks, or denies when
   gateway.toml has a `[network]` table), byte-identical to
   `envfile.degraded_bash_text`. The cold stand-ins exist whenever
   gateway.toml may configure something (or `private/configured.json`
   exists) and say "still setting up" (sudo's execs `/usr/bin/sudo`, which
   gets nothing from the gateway; git's runs the user's git only while
   nothing may be configured), so no credential flows before Python can
   classify the target.
10. **The form is never re-serialized**: append a table or replace one
    `key = value` line, re-parse, roll back if anything else changed.
11. **Vault read-modify-write only inside `vault.locked()` / `vault.edit()`.**
    With a wrapped key the writer still holds the flock while the daemon
    merges and writes (the daemon itself never takes it for a client's write,
    which would deadlock; `set_passphrase` takes it). Vault files are written
    durably (`vault.write_private`: a temp file, `full_fsync` (`F_FULLFSYNC`
    on macOS), rename, the folder synced; the broker uses the same). `gate
    rotate` keeps an encrypted copy just before its first vault write
    (`vault.snapshot`, `private/backups/rotate-*.vault.age`, newest 5);
    `gate forget` keeps none and names the older copies it can't reach
    (`vault.older_copies`: rotate's, an import's backup, a start-over's
    folder, the 0.6 store); `gate forget --backups` lists them in the
    gateway's dialog and deletes exactly those after the user's OK
    (`vault.delete_older_copies`, each still an older copy then). The
    passphrase is changed or removed (unlocked) and a vault whose
    passphrase is lost started over (locked: its files renamed into
    `private/backups/startover-*`, `vault.move_aside`, nothing deleted)
    only in gated's own dialogs (`Broker.change_passphrase`,
    `remove_passphrase`, `start_over`; `/gate-unlock`, `gate passphrase`).
12. **Every credential use and every refusal is audited** (`audit.use`,
    `audit.refusal`, both with the mode they used or `modeless`: lead
    decision 8; `gate why` reads the last refusal). A pass-through writes one
    `passthrough` line (the tool and a validated host or owner name, never
    argv; for git only commands that touch a remote). Messages start with
    `gateway:` and say what to do next.
13. **Stdlib only** in `src/` (the lock's Python, the newest conda-forge has;
    an older env with another Python minor is never used for new code:
    launch.sh's `older_env`, `envfile.older_env_python`). **POSIX sh** in
    `hooks/` (no bashisms; the desktop app gives hooks a minimal PATH), except
    `hooks/mod/` (the mod, TypeScript, run by Claude Code itself). External
    binaries: the pixi env's age, OpenSSH, gh, git-lfs and git (the gated
    git is always the env's); for pass-through only, the user's own tools
    found on PATH (invariant 7's exception), and the user's git for the
    gated git's identity read (`githelper.user_identity`: `git config
    --get-regexp` in the repository the command works on, only for a
    command that may commit, with a recursion guard); the system's
    sudo for a
    configured local sudo; the system's sshd in tests; the system's ssh only
    for "use my own login once" and a draining gated whose env lost its own
    (`ssh_conf.allow_system_ssh`). One exception since PLAN-v4
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
14. **Claude's commands run in the gateway's bash 5 with the user's own
    environment, and with the stand-ins unshadowable** (PLAN-v4 phase 4,
    PLAN-0.11 §1.6, docs/dev/modules/managed.md). In managed mode (`[shell]
    managed = "on"`, the default) the mod sets `CLAUDE_CODE_SHELL_PREFIX` to
    `hooks/gate-sh` before anything else at session start. gate-sh runs a
    classic hook string exactly as Claude Code does without it (`exec /bin/sh
    -c "$1"`, builtins only and no variable assigned before it, SHLVL given
    back on macOS; a hook string is anything without a Bash-tool script's
    whole shape: the cwd tracker last plus an eval, or the snapshot's
    `source` first); a Bash-tool script runs with only the snapshot's
    `source` replaced by the gateway rc, the rest byte for byte (other
    plugins' env files, the eval'd command, the cwd tracker, the exit
    status), under the env's bash with the inherited environment minus, by
    name (`env -u NAME`, never a value on a command line, which every local
    user can read): Claude Code's own credential variables; `BASH_ENV`,
    `ENV`, `BASH_FUNC_*`, `SHELLOPTS`, `BASHOPTS`, `PS4`, `PROMPT_COMMAND`,
    `CDPATH`, `IFS`, `GLOBIGNORE`, `BASH_XTRACEFD`; and `GW_*` except
    `GW_MANAGED_DIR` (a Claude Code started from a command stays managed).
    The lists are mirrored in `managed.py` and compared by a test; gate-sh
    exits 126 when it can't list the environment. PATH is the present
    stand-ins, then the snapshot's PATH, then other plugins' bins, then the
    approved `import_path`. The gateway rc sources a bash snapshot (a zsh
    snapshot gives only its PATH), then, in POSIX mode, clears the snapshot's
    traps and removes every alias and function named after a present
    stand-in or a builtin the tail relies on, and runs `hash -r`; it fails
    closed (the command never runs) where it can't (`managed.rc_tail`). No
    vault secret ever enters the environment. A managed shell that isn't
    ready runs the script without its settings in the shell that made the
    snapshot (zsh or bash, from the snapshot's name), found the way Claude
    Code finds its shell (`CLAUDE_CODE_SHELL`, `SHELL`, then PATH and its
    usual places in its order; absolute, no `=`; never `/bin/sh`; none:
    refused, 126), with a one-line notice naming that shell and why
    (PLAN-0.11 §19.15); a
    script with a tool script's shape that doesn't parse (126) is refused. A
    newer gateway.toml makes gate-sh renew its settings before the command
    (a narrowing applies at once). Turning `managed` off and adding an import
    are widenings; the mod only reads a cache (`state.json`) that can take
    the prefix away, never keep it off where the vault says "on" (it takes
    the managed bash for `CLAUDE_CODE_SHELL` from `launch.sh status`, never
    from `state.json`, and the data folder's gate-sh copy only while its text
    is the plugin's gate-sh). Still kept from the rollback: no EXIT trap, no
    hook requires a command shape for output's sake (no mandatory `| gate
    scrub`); output Claude Code passes to no rewriting hook is a documented
    known limit (PostToolUseFailure warns, the prompt hook holds back a task
    notification quoting a stored value or a token shape, Monitor's lines
    reach no hook, `gate scrub` is optional). Host inspection
    (`host_inspect`) reads files and lists folders only, never runs or
    sources anything, and returns folder names, version words and variable
    names, never values. The approval hook denies a route around a stand-in
    only when it reaches a configured target, in every mode (managed off and
    mods off included): a tool by its path (git, rsync and the elevation
    tools included; an account CLI by path while an account of its kind
    exists, and huggingface-cli, hf's older name with no stand-in, by any
    name while a huggingface account exists: "use `hf ...`"), a login shell or PATH-resetting wrapper (`bash -l`, `su -`,
    `sudo -i`, `env -i`, `command -p`), a PATH or transport change
    (`PATH=`, `GIT_SSH_COMMAND`, `RSYNC_RSH`, `rsync -e`, `-c
    core.sshCommand=`, `-o ProxyCommand=`, `-o HostName=`), a ProxyJump to a
    configured host, a guarded `git config` write in a configured
    repository; `gate with NAME --` is unwrapped first; a program name in
    any letter case (`/usr/bin/SSH`, `ENV -i`). It refuses commands that hide
    their program or host when the text names a configured target (what else
    they run gets no record of an ask: invariant 6; the known misses:
    managed.md). While
    this computer's sudo is configured, su, doas, pkexec, runuser, sudoedit
    (by its bare name: no stand-in supplies its password) and osascript's
    administrator privileges are denied ("use sudo"). Refusals
    name the stand-in route ("use `ssh homelab`"), never `managed = "off"`
    (docs/dev/modules/managed.md, "Alternate routes").
15. **Guards live in the classic hooks, never only in the mod** (PLAN-v4):
    Anthropic can switch mods off and older Claude Code has none, so the mod
    adds conveniences (status line, provisioning, `/gate-doctor`, the managed
    shell) and reads no secret location; every security behaviour holds
    through hooks.json. Without the mod the env file still prepends the
    present stand-ins and, when `CLAUDECODE` is set, unsets Claude Code's own
    credential variables and the stand-in names' aliases and functions; the
    classic Bash hook still enforces every right, policy, per-mode value, the
    network class and the configured-only route check, and gives a notice
    once per session. There is no blanket refusal.
16. **Nothing is written into the plugin folder at run time** (versioned,
    maybe read-only content): Python runs with `-X pycache_prefix=$DATA/pycache`
    (launch.sh, the stubs, the launcher and the daemon: `envfile.py_flags`,
    `lifecycle.daemon_argv`), state lives in `$CLAUDE_PLUGIN_DATA`,
    `~/.config/gateway` and the run dir.
17. **With a wrapped vault key only gated decrypts** (PLAN-v4 phase 2):
    `vault.brokered()` sends every read and write to the daemon, with no local
    fallback; never write a key.txt beside key.wrapped (but
    `remove_passphrase`, after the user's OK: key.txt written whole, then
    key.wrapped removed); the identity reaches
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
    boundary against code running as the user (docs/dev/modules/daemon.md).
    The other side holds too: a client talks only to a `gated.sock` that is
    its own (this user's socket, 0600, in this user's 0700 run folder,
    checked by lstat: `client.foreign_socket`); anything else counts as
    unreachable, and a start replaces it. A gateway program of another
    plugin data folder (a second `CLAUDE_CONFIG_DIR`) is refused with
    `planes.other_config_message`.
    The terminal and job routes are the gw MCP server's (`planes.check_term`:
    a `run.py mcp` entry point below a session) and the mod's (UI plane); a
    process inside a gateway terminal counts as the pane's owner session only
    while that session lives (`Registry.pane_session`).
    `/agent/session/mode` (the Python hooks record the payload's mode with
    the epoch of `$DATA/mode-epoch`; a stand-in Claude typed and the MCP
    server read it back only under the same epoch),
    `/agent/signin/start|wait` (a lease like the dialog's: a gateway entry
    point below a session with a drawing surface, one sign-in per user, the
    wait proved by the lease token in a POST body) and the passphrase offer
    routes (`/agent/vault/offer`, `/lease/vault/offer`) follow the same plane
    rules. The browser sign-in's 127.0.0.1 listener is the one TCP endpoint
    gated opens: it has no peer uid, so `state` and the PKCE verifier bind
    the callback (only `GET /cb`, headers capped, a deadline per connection,
    at most 16 at once). A recorded mode is a guardrail too: a process
    running as the user could post a false one.
18. **Terminals: one writer, nothing on a command line, passwords only
    through the dialog** (PLAN-v4 phase 5, docs/dev/modules/terminals.md). The
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
    boundary (the agent reads the physical rows, `capture-pane -N -T`, with
    what the scrubber finds in each `-J` rejoined line masked in every row it
    spans; never the rejoined lines themselves, which glue a row the line
    editor filled exactly to the output after it, unless the two captures
    don't line up); the main
    agent's input is held under its empty loop id (unclaimed is `None`, not
    `""`); `terminal_list`/`job_list` to the agent are bounded. A seq handed
    to the agent is persisted, so a restart's bump makes a pre-crash seq
    stale. Survival is always asked of tmux (id and nonce), never inferred
    from a saved pid: a lost pane is gone (terminal) or unknown (job, with no
    `ended` time: the outcome is unproven), never "exited"; a *failed*
    `list-panes` query is a blip (told from a dead server by its pid), not
    death. The one exception (0.9.1): when the env's tmux can't be run at all
    (`Tmux.runnable()`: an uninstall deleted the data folder), a pane's own
    process (pid and start time from tmux's last answer) decides only when
    its watch ends (gone/unknown, never "exited"), so a draining gated can
    leave. Uninstalled while work runs, gated drains (never kills it: no new
    work, no new pause and no job STOP/TSTP, contract.json withdrawn at once,
    a job left suspended resumed since nothing else could (counted only when
    ps showed it stopped; a remote one through the live master by the
    system's ssh, the env's being deleted), it leaves with its tmux server
    once no local pane runs; its code folder removed with another version
    beside it is an update's sweep, not an uninstall: it serves on until
    nothing runs), and it stops its tmux server whenever it exits with no
    local pane running (`stop_server`; a live pane keeps it for re-adoption);
    the watchdog stops it when gated is gone, also killed (`gated.pid`: pid
    and start time; a leftover socket file isn't gated). A paused session can stop or cancel a job but not resume it
    (`job_signal CONT` refused); a job is recorded suspended only when ps
    shows the stop held (else it is continued); an interrupt's SIGTERM escalation is
    persisted and re-armed after a restart. The approval hook's per-call
    judging of `terminal_send` is a guardrail (split-bypassable), not the
    boundary: the stand-ins and the encrypted vault are. The user's tmux
    server and `~/.tmux.conf` are never used. A pane's environment keeps the
    user's variables minus the managed shell's removals (invariant 14). A
    password prompt for an unconfigured target (the user's own sudo) is
    answered through the same dialog, once; nothing typed there is stored.
19. **Remote work runs only in the managed runtime, on the right host, after
    its identity checks** (PLAN-v4 phase 6, docs/dev/modules/remote.md). Only a
    host whose modeless ssh right is cc or allow (`true`); every remote command line is
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
    rule** (PLAN-v4 phase 7, docs/dev/modules/policy.md). Every action on a host
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
    workspace it may reach (`ssh_args.decide_path`). Policy never writes
    Claude Code's permission rules, and reads its mode only from the hook
    payload or gated's record. Snapshot and ticker reads never count as a
    vault use (`touch=False`), so `lock_after` still locks. Rights and the
    restrictions read, exec, write, network, elevation and credential may be
    per-mode tables (`{ default = ..., auto = ... }`, `default` required;
    `policy.decide(..., mode=)`): the hook resolves them with
    `permission_mode`, the stand-ins, web.py and gated with the session's
    recorded mode or the modeless rule (mode None). `scripts`, `provision`,
    `env_import`, the grants and `[shell]` take one word. A policy table's
    allow is the user's explicit allow (lead decision 19.1), which approves
    only this computer's `network` for the http and download tools; a bare
    `"allow"` restricts nothing. `[policy]` binds configured hosts and
    accounts plus this computer's elevation and network commands; it doesn't
    reach unconfigured hosts and accounts.
21. **The gateway never changes the system's privilege rules**: no sudoers
    file, no NOPASSWD advice in code, messages or docs
    (`test_no_blanket_passwordless_sudo_advice_anywhere`); passwordless sudo
    only where `sudo -n true` already works; a sudo password is stored or
    asked per call in the dialog ("Remember it" unticked: used once; the
    local and the remote sudo dialog's box starts unticked), and the approval names whom
    sudo runs as and where before it runs.
22. **Network commands are one configurable class** (PLAN-0.11 §3, lead
    decision 19.1, docs/dev/modules/network.md): `[network] commands`
    (default `"ask"` in every mode, per-mode), `extra`/`drop`, reserved names
    for the structural members; names in any letter case. The Bash hook
    judges it for Bash, Monitor, run_in_terminal, the job tools and
    terminal_send (a job at the mode its tool call carries, "ask" refused
    there), configured or not: in
    command position, in subshells, groups, `&`, `$()`, `exec`, `-c`
    strings, behind sudo and wrappers (`gate with` included) and in an `ssh
    HOST CMD` remote command, at the stricter of the class and this
    computer's `network` policy (a policy's allow never raises it). A hit
    makes the whole command ineligible for the gateway's allow unless
    `[network] commands` is allow in that mode; then only the network stage
    of a plain shape is approved, never under `gate with`, in run_in_terminal
    or a job; under `gate with` the value is at least ask. The known misses
    are listed (network.md). curl and wget are members, not a special
    refusal. The http and download tools stay under the `network` policy
    only, and `policy.decide` never reads `[network]`. The ssh family to
    unconfigured hosts is not in the class: it is the user's own.

## Commands

```bash
cd plugins/gateway
pixi run --locked test                   # all tests, 4 modules at a time (~7 min); prints "N passed, 0 failed"
GW_TEST_TMP=DIR pixi run --locked test   # put the temp homes in DIR (it reports anything left behind)
pixi run --locked python tests/run_tests.py test_form -k widen -x   # some modules / tests (-j N, -q)
pixi run --locked python tests/run_tests.py test_daemon test_broker   # the daemon and broker (~2 min)
pixi run --locked python tests/run_tests.py test_dialogs   # the native dialogs: gated's requests, leases, sealed intake, clipboard
pixi run --locked python tests/run_tests.py test_modes test_posture test_network test_git_standin test_offer test_ask_records
                                         # PLAN-0.11: per-mode values, the posture (stand-ins, pass-through),
                                         # the network class, the git stand-in, the passphrase offer, the
                                         # hook's records of what it asked (browser sign-in: test_accounts_entra,
                                         # test_accounts_asiml)
pixi run --locked mutations              # every mutation file, each on its own scratch copy (-j N, -k SUBSTR)
GW_E2E_TMP=DIR pixi run --locked e2e     # headless claude -p suite on a scratch copy (not part of test; tests/e2e/README.md;
                                         # its `jobs` scenario needs ../checkpoint/plugins/checkpoint next to this repo, else skipped)
pixi run release-check                   # after `git add -A`: does the index hold the tested tree? (read-only)
pixi run update-deps                     # the per-release relock (tests/update_deps.py; needs the newest pixi):
                                         # both locks to conda-forge's newest, requires-pixi, lib.ts's PIXI_TESTED and
                                         # the docs' quote of it, pixi-unpack = pixi-pack, pijul's newest (all or
                                         # nothing: a failed step puts every file back); prints what moved, runs the suite
claude plugin validate .                 # the plugin (and the mod's hooks module)
claude plugin validate ../..             # the marketplace
claude plugin test .                     # the mod's hooks/mod/*.test.ts in Claude Code's test kit
pixi exec --spec python --spec pyte python tests/acceptance_dialogs.py --tmp DIR --pixi-cache DIR2
                                         # the native dialogs live: a real interactive claude through tests/tui
                                         # (scratch config, fake API, the e2e install, telemetry on behind the
                                         # record-only proxy, the observer plugin, --debug-file, recording
                                         # shims for open/osascript/... first on PATH); it builds the e2e
                                         # copy's env first, outside the proxy (a cold DIR2 downloads ~400 MB
                                         # then; a build inside the proxied session can't download), ~3 min after
pixi exec --spec python --spec pyte python tests/tui/selftest.py [--only t]   # the TUI harness (t: the proxy)
pixi exec --spec python --spec pyte python tests/acceptance_managed.py --tmp DIR --pixi-cache DIR2 [--only route,passthru,hooks,perms,gitask,cancel,print,notready,nomods]
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
                                         # the remote runtime live: a disposable Linux VM (127.0.0.1:2222 and a private
                                         # sshd in it for the disruptive steps) and a local sshd, real pixi-pack
                                         # artifacts (~1 min); --vm-dir/--vm-sshd-port keep parallel runs on one VM apart
pixi exec --spec python --spec pyte python tests/acceptance_terminals.py --tmp DIR --pixi-cache DIR2 [--no-proxy]
                                         # terminals live: the pane, a full-screen program, prompt, resize, signals,
                                         # takeover with Claude's input queued, hand back, sudo's prompt through
                                         # the dialog (canary scanned everywhere), jobs, a script in the pane refused
                                         # an "ask" ssh/sudo right (pane wording) while a true one works, a restart,
                                         # the main screen (~2.5 min)
pixi exec --spec python --spec pyte python tests/acceptance_install.py --tmp DIR [--checkpoint DIR] [--only prereq,cold,notice,warm,update,uninstall,spaced,firstbash]
                                         # brief 14.1: both plugins from git-source marketplaces with only claude,
                                         # a recording pixi and pixi's git on PATH; cold provisioning, interrupted
                                         # setup, warm/offline start, update after a restart, uninstall, spaced paths;
                                         # on the disposable VM only (ACCEPTANCE_DISPOSABLE_VM=1): vmplain, and vmdrain
                                         # (plain installs, an uninstall while a job and terminal run, with and without
                                         # --keep-data, the ~/.bashrc probe); needs a git on PATH for its git server
pixi exec --spec python --spec pyte python tests/acceptance_canaries.py --tmp DIR [--pixi-cache DIR2] [--checkpoint DIR]
                                         # brief 14.9/14.13: canaries through every input route, both plugins,
                                         # telemetry on behind the record-only proxy, everything scanned
pixi exec --spec python --spec pyte python tests/acceptance_native_ui.py --tmp DIR [--pixi-cache DIR2] [--only scan,hosts,accounts,settings,export,import,tamper,signin,passphrase]
                                         # brief 14.10/14.12: /gate-hosts, /gate-accounts, the settings,
                                         # export/import/tamper, the browser sign-in, the passphrase offer,
                                         # nothing opened outside Claude Code (shims, ps sampler; strace on Linux)
```

More on each kind of test, and what was verified for each release:
[docs/dev/TESTING.md](docs/dev/TESTING.md). Results of past runs:
[docs/dev/TEST-LOG.md](docs/dev/TEST-LOG.md). There is no CI: the suites run
by hand before a release.

`test_mod` runs the three `claude plugin` commands itself (scratch
`CLAUDE_CONFIG_DIR` and HOME, a local recording server as
`ANTHROPIC_BASE_URL`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`), and
skips with a note when no claude is found. `test_release` checks that every
file hooks.json, .mcp.json, the sh hooks and the mod start is in the plugin
folder, runs the release check on throwaway repos, and prints this
checkout's release check as a note (never a failure while it's
uncommitted).

pixi: latest only (PLAN-0.11 section 5). `requires-pixi = ">=0.83.0"`, the
pixi that made the lock (the newest then), no upper bound; `update-deps` sets
it and `hooks/mod/lib.ts`'s `PIXI_TESTED` together (`CLAUDE_TESTED` is the
Claude Code of the last acceptance runs; `/gate-doctor` warns below either,
notes above), and `test_packaging` keeps them, the docs and the pins in step.
An older pixi refuses the manifest ("requires pixi"): launch.sh records it
(`$ENVD/.pixi-too-old`, status `pixi_too_old`), and its texts, gate-sh's
not-ready notice, `gate status` and `/gate-doctor` say to update pixi with
"pixi self-update, or your package manager for a Homebrew or MacPorts pixi"
(`envfile.PIXI_UPDATE` = launch.sh's `GW_PIXI_UPDATE` = lib.ts's
`PIXI_UPDATE`; tests compare them).
The suite needs the pixi `requires-pixi` names too (`pixi self-update`; or,
keeping an older one installed, run the commands above through `pixi exec
--spec pixi==VERSION pixi ...` with requires-pixi's VERSION). The launcher's
own `pixi install --locked --manifest-path` installs pixi.lock unchanged with
it (`test_packaging`'s lock check runs that pixi).

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
  is gone, when gated was stopped first, or once gated is gone, its socket
  removed or its `gated.pid` naming a dead or other process, and no pane runs
  anything; gated itself stops it when it exits with nothing running;
  terminals.md; the knob `watch_tick` shortens the watchdog's 5 s). Removing
  the override's data folder (`de.env.data`) is how a test makes a plain
  uninstall (the daemon log goes with it: open it first and read the open file).
  Never reach the user's tmux server. The `tmux` knob points
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
  the marker, before it reached the host), `tools` (wrappers for env tools by
  name) with `exclusive_tools` (a named tool is only its wrapper, so removing
  the wrapper is the env losing it, as a plain uninstall does) and
  `system_ssh` (the "system" ssh a draining gated falls back to). A test that needs the host's
  connection to drop closes the masters and clears the address cache in
  process (`ssh.close_masters`, `ssh_conf.cache_clear`: same run dir).
- Never ssh or scp to a real machine (your `~/.ssh/config` may name real
  hosts), never run real sudo except `sudo -n true`, never open a real
  dialog, never touch the person's clipboard (gated runs only the
  `clipboard` knob's program under any test override). The one exception is
  a disposable test VM the person approved for it (`tests/acceptance_remote.py
  --vm`, and `acceptance_install.py`'s VM parts): a throwaway gateway key
  appended for the run and removed after, everything under `~/gw-remote`,
  the disruptive steps against a private sshd the run starts inside the VM
  (never the VM's own sshd, which other runs may use), the VM user's
  `~/.bashrc` probe restored byte for byte.
- Sudo defaults in tests: a new install's local sudo is not configured (the
  user's own: no stand-in, no decision), so a test that needs it gated says
  so (`harness_sudo.setup_localhost(env, sudo=...)`, approved).
- The posture in tests: a pass-through runs the `user_tools` knob's
  recording fakes (`harness_posture.user_tools`, `tests/fakes/
  fake_user_tool.py`, which also answers `ssh -G` from an `-F` table), never
  the real ssh, git, gh or sudo; unconfigured targets use `.invalid` names;
  `SSH_AUTH_SOCK`, `GH_TOKEN` and the like carry fake values. The browser
  sign-in runs against `harness_oauth`'s fake server with gated's `browser`
  knob (a program that follows the redirect), never `open` or `xdg-open`.
- The work-identity scan (`test_packaging::test_the_shipped_plugin_names_no_
  work_identity`) holds only sha256 digests of lowercased words and reports
  `file:line: word N`, never the spelling. Use `example.com`, `octocat`,
  `example-org` and the like in tests and fixtures; a new identity to keep
  out needs its digest added by hand.
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

- **Don't run production entry points here.** They act on the real
  `~/.config/gateway`. That is why the harness guard, run.py's refusal of
  `GATEWAY_TEST_ROOT` without a valid `--test`, and `testing.override`'s
  refusal of real locations exist. Never run
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
  `envfile.env_text()`, `stub_text` (the git stub's cold pass-through
  included), `launcher_text(state)` in each of its four states (building,
  pixi missing, pixi too old, build failed), the cold-window stand-in rule
  (`maybe_configured`: a `[hosts`/`[accounts` shape in gateway.toml, or
  `private/configured.json`) and `degraded_bash_text(kind)` (tests compare
  them). Change both together. Its degraded file guard now
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
  gate-sh reads the same lock with builtins only (`gw_lock_live`: `read` the
  owner file, `kill -0` both pids), so it can't compare start times or
  machine ids: a reused pid reads as still setting up, and a build running
  on another machine that shares the data folder as setup failed.
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
  clicks only in its fullscreen layout (`CLAUDE_CODE_NO_FLICKER=1`, or `/tui
  fullscreen`, which the dialog's texts name; the TUI
  harness with telemetry on starts on the main screen), Escape returns the
  keys without telling the Client, and the pane's `isFocused` stays false
  while a Client holds the keys: don't build on it. In the test kit,
  `$.ui.focus(args)` reaches a `ui.focus` hook with its own arguments
  (`key`, not `element`), and a test must answer `ui.focus` beneath.
  Never let the field's text reach surface state, a post or a log: only
  `{id, attempt, epk, nonce, box}` leaves it. On the main screen the only
  key route is `/gate-dialog`, then Tab and Enter (`dialog.MAIN_KEYS`), and
  only Paste works; Paste never clears the clipboard (the pane, a toast and
  `/gate-doctor`'s "Secrets here" line say so). On Linux without `DISPLAY`
  or `WAYLAND_DISPLAY` Paste can't work at all (`NO_DISPLAY_MAIN`,
  SessionStart's `NO_DISPLAY_NOTE`).
- **Native dialogs in tests** (`test_dialogs`): a real gated
  (`harness_daemon`), a `FakeClaude` registered as a terminal session by a
  fake mod (`Mod` in the test polls `/ui/dialog/next` and submits sealed
  boxes with PyNaCl, as the Client would), and the requesting program run
  below it (`write_driver(native_dialogs=True, popup_wait=..., dialog_timeout=...)`,
  `GW_ASK`). The mod side (pane, field, guard, sealing) is tested in
  `hooks/mod/dialog.test.ts` under `claude plugin test`; the whole path
  live by `tests/acceptance_dialogs.py`.
- **The sh hooks take the home from the password database** (`hooks/home.sh`),
  like `paths.user_home()`, never `$HOME`. In tests, `launch.sh MODE --test`
  (harness.run_launch adds it) and `post.sh|prompt.sh --test` use
  `GATEWAY_TEST_ROOT`; `GATEWAY_TEST_ROOT` without `--test` resolves no home
  at all, so a test can't reach the real `~/.config/gateway`. Never run a sh
  hook in a test without `--test` unless its home.sh is replaced by a stub
  (as `tests/test_ux_hooks.py` does).
- **Managed execution** (`hooks/gate-sh`, `managed.py`): gate-sh's removal
  lists and credential words are mirrored in `managed.CLAUDE_CRED_NAMES`
  (= `envfile.CLAUDE_CRED_NAMES`), `STARTUP_NAMES`, `DROP_PREFIXES`,
  `GATEWAY_NAMES`, `CREDENTIAL_WORDS`, `form.SHELL_PASSED` and
  `form.CREDENTIAL_NAME` (a test compares them); change both. Before its
  classification gate-sh may use builtins only and assign no variable (the
  hook passthrough must stay exact: an assigned name that is exported would
  reach the hook). Never put a variable's value on a command line (env's or
  any other): names only (`test_no_value_reaches_a_command_line`). The
  managed rc is `envfile.env_text` plus Claude Code's helpers, the user's
  bash snapshot and the unshadowing tail (`managed.rc_tail`): it applies
  only while `$DATA/bin` exists (a test makes it). Tests of the tool path
  link the test env's bash into the override's `paths.env_bin()` (no python3
  there, so no env counts as ready). Claude Code honours `CLAUDE_CODE_SHELL`
  only before its first shell use (the snapshot is made then).
- **The Bash prefilter is a word list** (`pre_bash.sh`, also for the
  gateway's own `job_start` and `terminal_send`). A new command the hook must
  see needs its trigger word there too: the network class's names are
  compared with `form.NETWORK_BUILTIN` and launch.sh's list by a test, the
  user's `extra` names come from `$DATA/network-words` (every call goes to
  Python while gateway.toml is newer than it), and git counts only with a
  remote or config word after it. Words match in any letter case (`grep
  -i`). A plain account CLI (gh, hf, databricks, crane, pijul) goes to the
  hook while its stand-in exists in `$DATA/bin` and an account of its kinds
  is "ask" in some mode (`$DATA/ask-clis`, written with network-words; all
  of them while that file is missing), so an "ask" account is asked about
  and recorded. Nothing sends every call to the hook for an "ask" entry
  (the 0.11 ask marker is gone: a command without a trigger word gets no
  record, and its stand-in refuses the "ask"), only right after an ask:
  while a record is pending (`$DATA/asks/*`) every Bash and Monitor call
  goes to the hook, which drops the session's earlier records. While
  `$DATA/mode-epoch` exists (a per-mode value makes the mode matter) every
  call goes to Python, the ones without a trigger word to `hook-mode`,
  which only records the mode.
  (Since phase 6 a gw
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
  you: network commands are asked about, reading `~/.config/gateway/private`
  or session transcripts is refused (a Workflow run's `journal.jsonl` is
  fine), an AskUserQuestion asking for a secret is refused, and your Bash
  runs the stand-ins of whatever your gateway.toml configures first on PATH.
- **pixi**: use `pixi run --locked ...`; pixi-guard, if installed, may
  refuse a bare `python3`.
- **The approval hook's read rule and text scan** (`hooks_bash.py`) are
  tuned by tables of probes (`test_hookbash_table`, hundreds of rows in all
  six modes, plus a posture section for configured and unconfigured
  targets). Run the whole table after any change there, and add rows for
  both directions (a new deny, and the everyday commands that must keep
  their result). In the route text scan (every mode) only a shell's or su's `-c`
  takes a command string (`gcc -c`, `psql -c` don't); a tracer or sandbox
  (`_EXEC_RUNNERS`: strace, sshpass, tmux, ...) counts only as the program,
  also behind nice/env/timeout, so `sudo apt install strace` keeps its allow;
  `arch` is a wrapper the hook looks through; a bin-folder path is a program
  anywhere except as an operand of a pure-data command. The scan's known
  misses are listed in docs/dev/modules/managed.md ("Known misses of the
  scan") and the read rule's in docs/dev/modules/sudo.md.
- **tmux under gated** (`daemon/terminals.py`): tmux resumes a pane whose own
  process SIGSTOP stopped (SIGCONT for any stop but SIGTTIN/SIGTTOU), and a
  pane's process group is orphaned (its leader's parent, the tmux server, is
  in another session), so the kernel drops SIGTTOU and SIGTSTP there: a
  suspend SIGSTOPs every member but the root (`stop_group`; the root, a shell
  waiting for its children, runs on, and a job that is only its root can't be
  suspended); a row the line editor filled exactly is marked soft-wrapped,
  so `capture-pane -J` joins it to the next row (read rows, `-N -T`); `-t =NAME` works for
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

## Status

0.11.1 (2026-10-26, tag `v0.11.1`) is the last published release: 0.11.0's
setup messages and doc fixes. 0.11.0 (CHANGELOG.md; PLAN-0.11.md) brought: ungated
unless configured (stand-ins only where something is configured, the user's
own tools for everything else, removal as a widening), per-mode values for
every right and restriction, the network class, the git stand-in, browser
sign-in for azure and ml-catalog, the passphrase offer, masking of every
tool's output, the AskUserQuestion guard, export/import fixes, and the
deletions (no backward compatibility: the 0.6 conversion, export formats 1
and 2, `[settings]`, `managed = "warn"`, the managed refusal, the curl/wget
refusal, the older-install sudo default). The verification of each release
(suite, mutations, TUI acceptances, platforms) is in
[docs/dev/TESTING.md](docs/dev/TESTING.md).

What was never verified live (desktop app, VS Code, mobile, x86_64, Windows,
the real GitHub, Hugging Face and Azure services, the real model API) and the
history of every phase and review round:
[docs/dev/TEST-LOG.md](docs/dev/TEST-LOG.md). Known limits: the README's
"Limits", SPEC-v3 and the module docs.

## User preferences

- Show a plan and stop before installing anything or changing the user's
  settings; never run the plugin against the real `~/.config/gateway`.
- Plain, concise docs. No license file and no license wording (don't call
  the project open source).
- A hobby project: no CI/CD (no GitHub Actions) and no enterprise-style
  release process.
- Docs stay generic: no employer, work logins, emails, internal hosts,
  personal paths, pids or the user's live state.
