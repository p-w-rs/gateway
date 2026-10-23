> Developer documentation: how the plugin's parts fit together, for people changing the code. To use the plugin, read the [README](../../README.md).

# Architecture (v3)

How the gateway's parts fit together. The exact rules are in
[SPEC-v3.md](SPEC-v3.md) (cited as "SPEC n"); the module APIs are in
[MODULES-v3.md](MODULES-v3.md) and [modules/](modules/); the reasons are in
[DECISIONS.md](DECISIONS.md).

The idea: Claude runs ordinary commands. A SessionStart hook puts small
**stand-ins** for `sudo`, `ssh`, `gh`, ... first on PATH in Claude's Bash and
gives git a **credential helper**. The stand-ins read the user's **form**
(what Claude may do) and the **vault** (the secrets), check that the right is
approved and that Claude itself is the caller, then run the real program with
the credential. A **PreToolUse hook** approves the command shapes the form
allows, so they need no prompt in auto mode. Anything that would widen
Claude's rights waits for the user's OK in the **gateway's dialog** (a pane
inside Claude Code), the only place a secret is typed.

## The picture

```
 the user ── edits, or asks Claude to edit ──▶ ~/.config/gateway/gateway.toml (the form)
    ▲                                                 │ validated; compared with the rights
    │ the gateway's dialog (consent, secrets)         │ the user approved (private/vault.age)
    │                                                 ▼
 ┌──┴────────────────────────────── Claude Code session ──────────────────────────────────────────┐
 │ SessionStart ─ launch.sh ─ run.py hook-session                                                 │
 │    ├─▶ $CLAUDE_ENV_FILE: $DATA/bin first on PATH, git include, user's tokens/agent unset       │
 │    ├─▶ $DATA/bin/*: stand-in stubs (sudo ssh scp sftp gh hf databricks crane pijul asiml       │
 │    │                gate git-credential-gateway gate-askpass; az, dvc, git when needed)        │
 │    ├─▶ $DATA/git/config: credential reset, URL-scoped helper, insteadOf, identities            │
 │    ├─▶ ~/.config/gateway/gate (launcher for the user's terminal) and env.sh                    │
 │    └─▶ additionalContext for Claude, systemMessage for the user, watchPaths [gateway.toml]     │
 │                                                                                                │
 │ Claude's Bash: `ssh homelab sudo systemctl restart nginx`                                      │
 │    │ PreToolUse: pre_bash.sh (word prefilter) ─ hook-bash: deny | ask | allow | no decision    │
 │    ▼                                                                                           │
 │  bash (env file sourced) ─▶ $DATA/bin/ssh ─▶ env python -I -S run.py shim ssh ─▶ ssh.py        │
 │       ssh.py: rights (consent), ancestry, vault (age, locked), per-call ssh config,            │
 │       private agent, pinned host keys ─▶ pixi ssh ─▶ homelab; output through the scrubber      │
 │    ▲ PostToolUse: post.sh ─ hook-post: mask vault values + token shapes, form edits, notices   │
 │                                                                                                │
 │ MCP server gw (launch.sh mcp ─ run.py mcp): http, download ─▶ web.py ─▶ sites and APIs         │
 │   terminal_*, job_* ─▶ gated's tmux supervisor (PLAN-v4 phase 5; modules/terminals.md)         │
 │ File guard (PreToolUse Read|Grep|Glob|Edit|Write|...): never private/, run dir, transcripts    │
 │ UserPromptSubmit: paste guard    FileChanged: form re-checked    SubagentStart: same context   │
 └────────────────────────────────────────────────────────────────────────────────────────────────┘
     dialog broker (popup.py) ─▶ lease from gated ─▶ detached helper ─▶ dialog.py ─▶ gated
     (dialog requests, X25519 key per attempt) ◀─ the gate mod's pane in Claude Code: a Client
     field seals the typed secret (TweetNaCl box); gated opens it (PyNaCl), rechecks, hands it
     to the helper once. No OS dialog, terminal prompt or browser; elsewhere: "unavailable".
```

## Where things live (SPEC 1)

| place | what |
|---|---|
| `~/.config/gateway/` (0700) | `gateway.toml` (the form), `gate` (launcher for the user's terminal, rewritten every session), `env.sh` (the env file, for other launchers), `run/contract.json` (CONTRACT-v1 discovery, while gated runs) |
| `~/.config/gateway/private/` (0700) | `key.txt` (age identity) or, once a passphrase is set, `key.wrapped` + `key.recipient` (PLAN-v4 phase 2), `vault.age` (vault v3), `cache.age` (short-lived tokens), `.lock`, `backups/` (from migration and before every import), `pending/` (dialog broker state), `sessions/` (per-session records and "shown" markers). Claude never reads it. |
| `$CLAUDE_PLUGIN_DATA` (`~/.claude/plugins/data/gate-gateway`, or under `$CLAUDE_CONFIG_DIR`) | `envs/<sha12 of pixi.lock>/` (the pixi env), `bin/` (stand-ins), `git/` (include file, identities), `pijul/` (built on first use), `audit.jsonl` (rotated at 5 MB), `pycache/`, `managed/` (the managed shell's settings), `gated/` (the daemon's log, event log, terminal and job records, remote hosts' state), `runtime/` (remote runtime packs). Survives updates, deleted on uninstall. |
| `/tmp/gw-$UID/` (0700, owner-checked) | run dir: `gated.sock`, gated's tmux socket and config, panes' start files, ssh master sockets, per-call ssh configs and agents, askpass FIFOs, probe caches, refusals for `gate why` |

`paths.py` is the only place these are computed. Production code never takes
them from `GATEWAY_*` variables; only the hook and MCP modes take the data
folder from `CLAUDE_PLUGIN_DATA`, which Claude Code sets (SPEC 1).

## One entry point, one environment (SPEC 7, 18)

Everything runs `run.py` with the pixi env's Python (`-I -S`, so neither
PYTHONPATH nor the working directory can inject code). Modes: `hook-session`,
`hook-subagent`, `hook-bash`, `hook-files`, `hook-post`, `hook-prompt`,
`hook-filechanged` (JSON in, JSON out), `mcp`, `shim TOOL ...`, `askpass`,
`git-credential`, `gate`.

`hooks/launch.sh` (POSIX sh) is what Claude Code starts. It finds pixi (PATH,
then fixed places, because the desktop app gives hooks a minimal PATH),
computes the env folder from the sha of `pixi.lock`, and execs the env's
Python. If the env isn't built yet it degrades: SessionStart still writes the
env file, the stubs and the git reset in sh (byte-identical to the Python
output) and tells the user setup is running; the file guard and the Bash
approval hook run simpler sh versions (the Bash one refuses private-folder
and transcript reads, credential helpers and token-bearing commands, and
curl/wget once a vault exists; PLAN-v4 phase 1); stubs print "still setting
up" and exit 75 (except `sudo`, which runs the real sudo). With the env built, launch.sh still writes the env
file (and missing stubs and git reset) before it starts Python for
SessionStart, so a hook Claude Code cancels or kills leaves Claude's
commands on the stand-ins. The async SessionStart hook (`launch.sh
ensure-env`) builds the env with `pixi install --locked` from a copy of
`pixi.toml` and `pixi.lock` (the build lock `<env>.building` records the
builder's and pixi's pids and start times, so a killed build is stale at
once and the next run or a waiter takes over), loads it once (`gateway/warm.py`: on macOS the
first load of each new binary and library is slow, 5-6 s for the env,
which the next session's sync hook would otherwise pay), and removes old
env folders after 7 days unused. Python always runs with `-X
pycache_prefix=$DATA/pycache`, so nothing is written into the plugin folder.
The mod (`hooks/mod/register.tsx`, Claude Code 2.1.287+) starts the same
`ensure-env` through `$.process.spawn` at session start when nothing builds
yet, shows a status line while it runs (it polls `launch.sh status`), and
serves `/gate-doctor`; the guards stay in the classic hooks. Optional tools
(hf, databricks, dvc, crane) install into feature envs on first use; pijul is
built with cargo in the background on first use.

## Session start (SPEC 7, 13)

`hooks_session.session_main`:

1. Migrates a 0.6 vault if there is one (offline; see Migration).
2. Loads the vault and the form (`hooks_session.prepare`): a missing form is
   restored from the vault's last good copy, or the starter form is written
   when nothing is stored; narrowings are persisted (`consent.ratchet`).
3. Writes the env file whole (a temp file renamed over it; it is reused on
   resume and compact), the same text to `~/.config/gateway/env.sh`, the stubs (each replaced
   atomically inside `$DATA/bin`), the git include file and the launcher
   (`envfile.sync`). The env file is static and idempotent: it puts
   `$DATA/bin` first on PATH once, adds the include file through
   `GIT_CONFIG_COUNT`/`include.path` once, sets `GIT_SSH_COMMAND` and
   `RSYNC_RSH` to the ssh stand-in, and (with `others = "refuse"`) unsets
   the user's agent and token variables, all only while `$DATA/bin` exists
   (env.sh is sourced by other launchers, such as checkpoint jobs, also
   after an uninstall; then it does nothing). It never changes how a command ends
   (round 3's EXIT trap is rolled back: a failed command keeps its exit
   code, and Claude Code sends its output to PostToolUseFailure, which no
   hook can mask).
4. Returns `additionalContext` (at most 2,500 characters, built from the
   validated form only: names, kinds, rights, logins, owners, sites; never
   notes), a `systemMessage` for the user (migration report, form errors,
   widenings waiting, gateway dialogs waiting in Claude Code, security
   events since the last session) and `watchPaths: [gateway.toml]`.
5. Writes the session record `private/sessions/<sid>.env` (its mtime is the
   session start; Claude Code's display variables tell the dialogs where the
   screen is).

Every file it writes is written whole, so a killed SessionStart leaves each
one old, new or absent, and the next session writes them all again. One
that finishes past Claude Code's 20 s limit (its output dropped) leaves the
session with no context record, so the next prompt's hook gives Claude the
context.

SubagentStart returns the same context. UserPromptSubmit adds a fresh summary
when the form changed since the last context.

## Approval hook (SPEC 8)

`PreToolUse` for `Bash|Monitor|mcp__terminal__run_in_terminal|mcp__plugin_check_jobs__job_start`:

- `pre_bash.sh` exits silently unless the command contains a trigger word
  (`sudo ssh scp sftp rsync curl wget gate gateway age credential
  GIT_TRACE_REDACT key.txt claude jsonl az`), so ordinary commands never start
  Python (Monitor and background calls alike).
- `hooks_bash.main` parses the command with `bashparse` (gives up on anything
  it can't judge: `$(`, backticks, heredocs, `eval`, subshells, `sh -c`,
  other redirections, assignment prefixes other than `GATE_ACCOUNT=`). Then,
  in order: deny `curl`/`wget` (also behind `command`, `busybox`, `env`, ...);
  deny anything naming the private folder, the run dir, a session
  transcript (a Workflow run's `journal.jsonl` is not one), `git credential`
  or the helpers, or turning off git's
  credential redaction; deny a gateway verb whose form right is `false`, or
  one the form gives that still waits for the user's OK (with "run gate
  check NAME"; rights for deny and ask are the stricter of form and
  effective, so an approved "ask" edited to true is still asked about)
  (remote sudo through ssh, rsync's `--rsync-path` or a remote path counts
  as the host's sudo right; git's `--upload-pack` with sudo and `sftp -s`
  are denied); ask if one is `"ask"` (scp, sftp and rsync on an `"ask"`
  right are denied instead: the stand-in only honours "ask" for a command
  Claude typed; a command that hides its verbs behind a shell, a loop or a
  variable is asked about when its text names an `"ask"` host); in
  auto/bypass mode only, allow when every segment is an allowed shape run by
  its bare name (never `./ssh` or `/tmp/x/cat`) (local
  `sudo` outside the destructive list, ssh-family commands with allowlisted
  options to hosts whose effective right is `true`, copies only to and from
  the project, `~/Downloads` or a temp folder, `gate` subcommands other than
  `with`, a few read-only commands); otherwise no decision, and Claude
  Code's mode decides.
- The user's own Terminal panel (`mcp__terminal__run_in_terminal`) gets the
  denies and asks but never `allow`: it has no stand-ins. `gate secret`
  (removed in PLAN-v4 phase 3) is denied in every tool, and `gate
  export|import|copy-to` in the panel (their dialogs need a command Claude
  runs, below a session that can draw them).
- checkpoint's `job_start` (when checkpoint is installed) is judged on its
  `command`, or its `argv` shlex-joined: Bash's denies apply, `gate
  export|import|copy-to` are denied as in the panel, an `"ask"` right is
  denied (nobody can be asked while a job runs), and the hook never answers
  `allow` or `ask` for it (Claude Code's own check decides). The job's
  stand-ins come from env.sh when checkpoint applies it; `ancestry` treats
  checkpoint's runner like Claude's shell for credentials but never as a
  typed command. What `job_tail`, `job_status` and `job_stop` return passes
  the output hooks like Bash output (below).
- Monitor and background commands are judged like any Bash command; the
  gateway doesn't change how Claude's commands run (rounds 3 and 4 required
  `| gate scrub` for them; rolled back, DECISIONS "Rolled back"). Their raw
  output is a known limit: Monitor's streamed lines reach Claude past every
  hook, and Claude Code quotes the raw end of a background command's output
  file when it seems to wait for input (the prompt hook holds back such a
  notice when it quotes a stored value or a token shape). `gate scrub` is an
  optional masking filter Claude may pipe them through.

`mcp_perm.sh` (sh + awk) allows `host_inspect`, the terminal and job reads, a
local `terminal_open`, `terminal_resize` and `host_runtime`'s status, in every
mode; `http` and `download` get no decision (since 0.10.0), so Claude Code's
mode decides. The
file guard (`hooks_files`, `onFailure: "block"`) denies Read/Grep/Glob/Edit/
Write/NotebookEdit inside the protected places and on session transcripts
(a Workflow run's `journal.jsonl`, which Claude Code's Workflow tool tells
Claude to read, excepted by exact name and place; a Grep over its run folder
stays denied), and the desktop app's transcript export (always; its
transcript search and event listing are allowed, with stored values masked
in what they return).
launch.sh passes a plain path inside the session's folder by itself (an sh
fast path, round 5) and starts Python for everything else.

## Stand-ins (SPEC 9, 10)

Each stub is a short sh script with absolute paths baked in that execs
`run.py shim TOOL`. Every stand-in follows the same steps:

1. Load the form (cached by mtime) and ratchet; compute effective rights.
2. Check the right: `false` refuses; `"ask"` refuses unless Claude's own
   command shell (or a fork of it, such as a pipeline stage) started the
   stand-in with nothing in between (`ancestry.typed_by_claude`): Claude Code
   can only ask about the command Claude typed, so ssh started by git, rsync,
   scp or sftp, or sudo inside a script, is refused ("run it as its own
   command so Claude Code can ask you"; under checkpoint's job runner, the
   approval hook's job wording: run it with the Bash tool).
3. Check the caller (`ancestry.is_direct`): walking up from the stand-in's
   parent to `CLAUDE_PID`, every process must be a shell or a plain wrapper
   (plus the git/ssh family for ssh and git credentials), identified by
   executable path. Otherwise the credential is withheld unless the entry has
   `scripts = true`.
4. Pick the account (`accounts.select`: `GATE_ACCOUNT`, else the owner, else
   `default`, else the only account; an owner-matched account that isn't
   usable yet refuses rather than falling back) and check the destination is
   in its `bound` set.
5. Read the secret from the vault (under the lock, only when needed), run the
   real binary by absolute path with an allowlisted environment and forced
   endpoint variables, stream its output through the scrubber, write one
   audit line.

Per family:

- **sudo** (local): if `sudo -n true` works (cached 10 min), exec the real
  sudo untouched. Otherwise the stored password (or one verified in the
  gateway's dialog) goes to `sudo -A` through a one-shot askpass FIFO that
  is unlinked after the first read; a rejection marks it stale (never
  retried) and opens one re-entry dialog. `gate-askpass` answers only the real, root-owned setuid sudo.
- **ssh, scp, sftp, rsync**: resolve the destination to a form host or an
  account's ssh endpoint (unknown ones are refused, or with `others = "mine"`
  passed to the system ssh). Refuse options that change identity, proxying or
  forwarding. Pick an address (`address`/`also`, `when` networks, parallel
  1 s probes, cached 5 min). Write a per-call ssh config (pinned host keys
  under one alias, `StrictHostKeyChecking yes`, only the gateway's keys in a
  private agent, `ControlMaster` reuse for 2 minutes, `ProxyJump` for `via`)
  and check it with `ssh -G`. A call that finds no master holds a lock next
  to the master socket while it starts one, so parallel calls (checkpoint
  jobs) wait briefly and share it. A changed host key on the last candidate opens a
  host-key dialog. scp and sftp run the pixi binaries with `-S` pointing at the ssh
  stand-in; rsync and git reach it through `RSYNC_RSH` and `GIT_SSH_COMMAND`.
- **remote sudo** (SPEC 9.3): probe `sudo -n true` over the master; if a
  password is needed, a staging call puts it and a guarded askpass in a 0700
  folder on the remote (in memory where possible), the command runs with
  `SUDO_ASKPASS` scoped to its own `sudo` (all sudo with `scripts = true`),
  output is scrubbed, the folder is removed. Same-user processes on the
  remote can read the staged password while it exists (a stated limit; since
  PLAN-v4 phase 7 the gateway never installs a passwordless sudoers rule:
  sudo is passwordless only where the host already allows it, and a
  password can be asked per command and used once).
- **git**: the include file resets git's credential helpers (with `others =
  "refuse"`) and adds `git-credential-gateway` per account host
  (`useHttpPath`), `insteadOf` rewrites from ssh to https for hosts whose
  accounts only have tokens, and `includeIf "hasconfig:remote.*.url:..."`
  identities per owner. The helper answers only `git-remote-http(s)` (or
  git-lfs), over https, with redaction and certificate checks on. git over
  ssh to an account endpoint goes through the ssh stand-in, which picks the
  account from `git-upload-pack 'owner/repo'`.
- **gh, hf, databricks, crane, pijul**: the token in that process only
  (`GH_TOKEN`, `HF_TOKEN`, an Entra token as `DATABRICKS_TOKEN`, a per-call
  `DOCKER_CONFIG`, a private agent for pijul), endpoints forced (a gh
  command line naming another host is refused), temp config dirs,
  subcommands that print or replace tokens refused.
- **asiml** (and `dvc` inside an asiml workspace): the gateway's own client
  for an ML model catalog (the ml-catalog account's `host`, required) with the
  pinned Entra scope; storage passes go to dvc in an isolated config.
- **az** (only when an azure account has an approved `env`): `account
  get-access-token` and `account show`, for Azure SDKs; the token is printed
  as is, only to a program Claude's command started and only with `scripts =
  true` (never to Claude's own command, whose output Claude reads), and only
  for a scope of one of the account's approved destinations (Resource
  Manager, Graph, listed storage, workspaces and sites).
- **`gate with NAME -- CMD`**: the key in the account's `env` variable for
  that one process, output scrubbed; never hook-approved.

## MCP server (SPEC 14)

`mcp_server.py` is a small stdio JSON-RPC server (`alwaysLoad`, so the tools
are visible without a tool search) with two tools. `http` sends a request,
adding an account's credential only for its approved and bound destinations
(api-key placements, GitHub/Hugging Face bearer tokens, Entra tokens chosen
by host for azure and ml-catalog), follows redirects by hand and drops the
credential on a cross-host or downgrading hop, ignores proxy variables and
custom CA bundles, and scrubs the response. `download` streams to a new file
under the working directory, `~/Downloads` or a temp folder, never over a
file, a dotfile or a config folder, with a check-then-write race closed.

## Form, vault and consent (SPEC 2, 3, 5)

- **The form** is TOML with a lenient pre-pass (`yes`/`no`/`ask` words). Each
  entry is validated on its own; a bad entry is off and reported, the rest
  keep working; a syntax error falls back to the last good copy in the vault.
  The gateway never re-serializes it: writers append a table or replace one
  line and roll back if anything else changed.
- **The vault** is age-encrypted JSON: per host its ssh keys, pinned host
  keys and sudo passwords; per account its token, ssh key or Entra refresh
  token and its `bound` destinations; the approved rights; the last good
  form; aliases from migration; the last 100 security events. Every
  read-modify-write holds `private/.lock`.
- **Consent**: `consent.compute(form, vault)` compares the form with the
  approved rights. Narrowing is effective at once and persisted by every
  process that loads the form (`ratchet`), so a narrow-then-raise still needs
  the user. Widening stays inactive until `gate check NAME` (or the first
  command that needs it) shows the consent dialog and the user approves exactly
  those changes; approving an account adds its destinations to `bound`. A
  credential is sent only to a destination in `bound`.

## Pop-ups (SPEC 6)

`popup.py` is the only way to ask the user, and every question is the
gateway's native dialog inside Claude Code (PLAN-v4 phase 3; DECISIONS
"PLAN-v4 phase 3"; docs/dev/modules/daemon.md "Dialogs"). A request is keyed by
entry and subject; `private/pending/` holds its lock and state, so all
processes asking for the same thing share one dialog. The requesting
process takes a dialog lease from gated (it runs below the Claude Code
session, so gated knows which session's mod draws it; no lease in `claude
-p`, the SDK, VS Code, mobile, Remote Control or with mods off: the request
is "unavailable", nothing is asked any other way, and the message says
where it can be given), prints a notice, double-forks a detached helper
that opens the dialog through gated (and runs the verification and storage
callbacks), and waits at most 90 s before exiting 75 with "the gateway
dialog is still open in Claude Code; tell the user once". The helper keeps
the dialog up to 30 minutes. Outcomes: ok, cancelled (not reopened until
the user writes again), timeout, unavailable, paused, failed.

gated holds the requests (one dialog at a time per session, the rest queued
by identity) and makes an X25519 key pair for each attempt of a secret. The
gate mod long-polls them and draws the pane; a secret is typed into a
`Client` field, which takes keys only after a click and shows bullets, and
leaves it sealed with TweetNaCl's box to the attempt's public key. gated
opens the box (PyNaCl), refuses anything in plaintext, rechecks the request
(still open, its session alive and not paused, the asking processes alive,
the form entry the dialog names unchanged, with the rights it needs) and
hands the value once to the helper, which verifies it (sudo, ssh, the
account's API) and stores it (a sudo password a command asks for only when
"Remember it" stays ticked), or asks gated to reopen the dialog with "That
didn't work" (3 tries); the sudo and ssh stand-ins read the rights again
before they use it. While a secret dialog waits, the mod holds back what is
typed into the prompt box (only the gateway's own commands pass). Paste from clipboard
makes gated read the clipboard itself by absolute path. The requests
survive a gated restart (metadata only, new keys) and `/reload-plugins`.
The vault's passphrase (set, unlock) is asked the same way, by gated
itself.

## The gate CLI (SPEC 15)

`gate status [NAME] [--report]`, `check NAME|all`, `login`, `forget`,
`rotate`, `with`, `export`, `import`, `copy-to`, `pubkey`, `log`, `why`,
`lock`, `migrate`, `import-ssh`, `scrub` (`secret` only says where credentials are
entered now). `gate check NAME` is the eager setup: plan
what the entry needs (pending widenings, a keyscan for new hosts, a key to
install, a sudo password or the per-command choice, a sign-in or token), then run
the whole sequence as one broker job in the dialog helper, so it survives the
requester's exit 75. It is idempotent, and it re-checks a host that looks set
up (its host key, a login with Claude's key); a host behind a jump host that
isn't set up stops with "run gate check JUMP first".

## Other hooks (SPEC 12)

- **PostToolUse** (`post.sh` prefilter): once a vault exists, every tool
  response goes to Python (vault values need not look like tokens), except
  an Edit's, Write's or MultiEdit's (round 5: Claude Code shows Claude no
  file content for them); without one, only a response holding a token
  shape. It rewrites the response with
  `updatedToolOutput`, masking token shapes and every vault value in every
  form (checkpoint's `job_tail`, `job_status` and `job_stop` too: a job's
  log); after an Edit/Write of the form,
  validates it and tells Claude what is wrong or what waits for the user's
  OK; shows no-screen notices once per session.
- **PostToolUseFailure** (same prefilter): a failed call's output can't be
  rewritten (known limit: every Bash command that exits non-zero, times out
  or is killed, and an MCP error result such as a failed `job_stop`). When
  it holds a stored secret or a token shape, it warns Claude never to use what it saw, tells the user which entry to replace,
  audits it, and shows pending no-screen codes.
- **UserPromptSubmit** (`prompt.sh`): blocks a pasted token or private key,
  scrubs it from the transcript and history; clears the "cancelled" markers;
  writes the session record on the first prompt if SessionStart didn't;
  shows a migration report that a mid-session conversion left. Claude Code's
  task notifications pass here too (round 4): one quoting a background
  command's raw output that holds a stored value or a token shape is
  blocked and masked in the transcript (fails closed). The sh hooks take the
  home from the password database, like Python.
- **FileChanged** on `gateway.toml` (SessionStart's `watchPaths`, a group
  without a matcher): re-validates, ratchets and tells the user what changed.

## Migration from 0.6 (SPEC 4)

The first v3 process that finds a v2 `store.age` and no `private/vault.age`
takes both locks, copies the store and key into `private/backups/`, decrypts
with the v2 rules (`vault_v2.py`), maps every record (accounts to
`kind`-named entries, `ssh:` accounts to hosts with their keys, routes and
pins, sudo passwords to their hosts, secrets to `api-key` accounts, old names
to aliases), validates that the new form parses and every credential landed
or is listed as dropped, then writes `private/key.txt`, `private/vault.age`
and `gateway.toml` (or `gateway.from-v2.toml` if a form exists) and moves the
v2 files into the backups. Any failure writes nothing. The report is shown
once and kept for `gate status --report`. A v2 store that reappears later is
put away as a stray backup.

## Export, import, copy-to (SPEC 16)

Export format 3 (PLAN-v4 phase 7; formats 1 and 2 still import) holds the
entries picked in a per-item checklist, with a schema version and a sha256
digest, encrypted with an age passphrase typed twice in the native dialog
(age runs under a private pty). Import validates everything strictly, tells
a wrong passphrase from a changed or damaged file, recognizes this machine
by its SSH host keys or the machine token a host record carries (never the
exported `localhost`), turns that host into `localhost` and the source's
`localhost` into a named host with `ssh = false`, asks per conflicting item
(keep, replace, rename; keep or take a host key), and writes form and vault
in one staged step after a backup under `private/backups/`, restoring both
on failure (modules/ux.md, modules/policy.md). `gate copy-to HOST` encrypts the export to the
remote gateway's own age recipient (`gate pubkey` there) and streams it over
ssh to `gate import --from-peer -`, which accepts only an age stream for its
own key, only when started by the system sshd.

## The gateway daemon (PLAN-v4 phase 2)

`gated` is one detached process per user, started on demand (the mod at
session start, the async SessionStart hook `hook-daemon`, and with a
passphrase-protected vault key every gateway program that needs the vault).
It listens on `/tmp/gw-$UID/gated.sock`, identifies every caller by the
kernel's peer credentials and serves four planes: the UI plane for the Claude
Code process itself (the mod), the agent plane for the gateway's own
programs (vault data, scoped per program), the CONTRACT-v1 plane for
checkpoint (discovery file `~/.config/gateway/run/contract.json`, snapshot,
events) and a local plane (stop, restart). With an unwrapped key (the
default; a passphrase is opt-in through `/gate-unlock`) nothing about the
vault changes; with a wrapped one only the daemon decrypts. Details: [modules/daemon.md](modules/daemon.md).

## The managed shell (PLAN-v4 phase 4)

Claude's commands run in the gateway's own bash. The mod sets
`CLAUDE_CODE_SHELL_PREFIX` to `hooks/gate-sh` at session start; Claude Code
then runs every shell command through it: a classic hook string passes
through as `/bin/sh -c`, a Bash-tool script (Bash, background, Monitor, `!`,
subagents, skill injection) runs with Claude Code's shell snapshot replaced
by the gateway rc, in a curated environment of platform variables, Claude
Code's own and approved `[shell]` imports (everything else removed by name, so
no value is ever on a command line), never the login shell. Without the
mod the classic Bash hook denies ("managed shell unavailable") or, with an
approved `managed = "warn"`, lets the command run in the user's shell with a
notice. Details: [modules/managed.md](modules/managed.md).

## Terminals and jobs (PLAN-v4 phase 5)

gated supervises persistent PTYs in its own tmux server (the env's tmux, a
private socket and config in the run dir; never the user's tmux): terminals
(`t_<ulid>`, an interactive managed bash) and jobs (`j_<ulid>`, one command),
each with the managed shell's environment. The gw MCP server's `terminal_*`
and `job_*` tools reach them on gated's agent-term plane (bounded, scrubbed
reads; writes quote the screen's seq), the mod's `/gate-terminal` pane on the
UI plane (the person's click or key takes the input; Claude's queued input
then fails), checkpoint on the contract plane (jobs, pause policies). A
password prompt in a pane opens the gateway's credential dialog, whose value
goes to that tty only. Records survive in the data folder; panes are
re-adopted from tmux after a gated restart and reported gone when tmux lost
them. Details: [modules/terminals.md](modules/terminals.md).

## The managed remote runtime (PLAN-v4 phase 6)

A terminal or job can run on a host from the form (`host` on `terminal_open`,
`job_start`, CONTRACT-v1's jobs). gated packs the plugin's `runtime/`
workspace (bash and tmux, no Python) with the env's pixi-pack for the host's
platform, takes the target's pixi-unpack out of its conda packages, and
stages both into a private, versioned folder on the host over the gateway's
own ssh (the vault's key, the pinned host keys, the shared ControlMaster),
checking every file's sha256 there before unpacking. The panes run in that
runtime's tmux on a private socket in the folder, under `env -i` and a
curated PATH (no remote rc, profile or login PATH). Every command for a
runtime checks the host record's marker in it; the host's machine id is
read at each new connection and stored with its host keys; a changed host
key or machine blocks the host until the person confirms in gated's own
dialog. A per-host poller asks the host what lives: a host that can't be
asked leaves its panes disconnected (waiting_auth for a refused key), never
ended; only the host's tmux ends (exited) or loses (unknown) a pane.
Details: [modules/remote.md](modules/remote.md).

## Hosts, workspaces, policy and accounts (PLAN-v4 phase 7)

Each host can hold workspaces (named roots there, with a matching folder on
this machine; `w_` ids bound to the host's id and the root), and every
terminal and job is bound to host + workspace by gated. Policy is
allow/ask/deny per host, workspace, account and action (read, exec, write,
network, elevation, credential, env_import, provision, and per-host
forwarding grants), a layer of restrictions on the rights: `policy.decide`
at each boundary (the stand-ins, gated, the managed shell's imports, web,
account selection, the approval hook) takes the strictest rule and names it
in every refusal; raising one waits for the person's OK in the consent
dialog, lowering applies at once. Account adapters check stored credentials
with one cheap API call to the bound host and tell connected, expired,
revoked and reauthentication-required apart. `/gate-hosts` and
`/gate-accounts` show all of it; edits go through the form writer and the
consent dialog. Details: [modules/policy.md](modules/policy.md).

## Threat model, briefly

Meant to stop: a cooperative or prompt-injected Claude seeing a secret,
sending one to the wrong place, giving itself more rights, or getting root
or a token for code it didn't run directly; secrets ending up in output,
logs or the transcript. Not a sandbox: Claude's commands run as the user, so
a determined program can read the vault key; the Bash checks are text checks
and the ancestry check trusts executable names. Commands the form sets to
`true` skip auto mode's reviewer by design. README's "Security and privacy"
and "Limits" list the limits as the user sees them.
