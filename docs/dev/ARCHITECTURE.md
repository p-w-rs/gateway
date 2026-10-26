> Developer documentation: how the plugin's parts fit together, for people changing the code. To use the plugin, read the [README](../../README.md).

# Architecture

How the gateway's parts fit together. The exact rules are in
[SPEC-v3.md](SPEC-v3.md) (cited as "SPEC n"), [PLAN-v4.md](PLAN-v4.md) and,
where they differ, [PLAN-0.11.md](PLAN-0.11.md); the module APIs are in
[MODULES-v3.md](MODULES-v3.md) and [modules/](modules/); the reasons are in
[DECISIONS.md](DECISIONS.md).

The idea: Claude runs ordinary commands. For the hosts and accounts the
user's **form** configures, small **stand-ins** for `sudo`, `ssh`, `git`,
`gh`, ... sit first on PATH in Claude's shell. A stand-in classifies its
target: a configured one goes through the gateway (the right is approved for
the current permission mode, Claude itself is the caller, the credential
comes from the **vault** and goes to one child), anything else runs the
user's own tool untouched. A **PreToolUse hook** judges commands before they
run: it denies, has Claude Code ask, approves the shapes the form allows in
that mode, or stays out of it. Anything that widens Claude's rights, or
takes a configured target out of the gateway, waits for the user's OK in the
**gateway's dialog** (a pane inside Claude Code), the only place a secret is
typed.

## The picture

```
 the user ── edits, asks Claude, or /gate-hosts ──▶ ~/.config/gateway/gateway.toml (the form)
    ▲                                                 │ validated; compared mode by mode with what
    │ the gateway's dialog (consent, secrets,         │ the user approved (private/vault.age), plus
    │ sign-in confirm, passphrase offer)              ▼ private/configured.json (the configured set)
 ┌──┴────────────────────────────── Claude Code session ──────────────────────────────────────────┐
 │ SessionStart ─ launch.sh ─ run.py hook-session                                                 │
 │    ├─▶ $CLAUDE_ENV_FILE: $DATA/bin first on PATH; in Claude's shell, Claude Code's own         │
 │    │   credential variables and the stand-in names' aliases and functions removed              │
 │    ├─▶ $DATA/bin/*: gate, git-credential-gateway, gate-askpass, and only the stand-ins that    │
 │    │   can reach something configured (ssh scp sftp git sudo gh hf databricks crane pijul az   │
 │    │   asiml dvc); .gateway-standins marks the folder                                          │
 │    ├─▶ $DATA/git/: the gated git's include file and read-only global config                    │
 │    ├─▶ $DATA/network-words: the user's [network] extra names for the prefilter                 │
 │    ├─▶ ~/.config/gateway/gate (launcher for the user's terminal) and env.sh                    │
 │    └─▶ additionalContext for Claude, systemMessage for the user, watchPaths [gateway.toml]     │
 │                                                                                                │
 │ Claude's Bash: `ssh homelab sudo systemctl restart nginx`                                      │
 │    │ PreToolUse: pre_bash.sh (word prefilter) ─ hook-bash: deny | ask | allow | no decision,   │
 │    │ in the payload's permission_mode; it records the mode in gated when the mode matters      │
 │    ▼                                                                                           │
 │  gate-sh ─ the env's bash ─▶ $DATA/bin/ssh ─▶ run.py shim ssh ─▶ ssh.py                        │
 │       ssh.py: configured? (the name, ssh -G, hops, IPs) ─ no: exec the user's own ssh          │
 │       yes: rights in the recorded mode, ancestry, vault, per-call ssh config, private agent,   │
 │       pinned host keys ─▶ the env's ssh ─▶ homelab; output through the scrubber                │
 │    ▲ PostToolUse (every tool): post.sh ─ hook-post: mask vault values, token shapes and the    │
 │      user's credential variables; form edits; notices                                          │
 │                                                                                                │
 │ MCP server gw (launch.sh mcp ─ run.py mcp): http, download ─▶ web.py ─▶ sites and APIs         │
 │   (PreToolUse: mcp_perm.sh; http and download ─ hook-mcp: the network policy, per mode)        │
 │   terminal_*, job_* ─▶ gated's tmux supervisor (modules/terminals.md)                          │
 │ File guard (PreToolUse Read|Grep|Glob|Edit|Write|...): never private/, run dir, transcripts    │
 │ tool_guard.sh: AskUserQuestion asking for a secret; browser tools while a sign-in runs         │
 │ UserPromptSubmit: paste guard    FileChanged: form re-checked    SubagentStart: same context   │
 └────────────────────────────────────────────────────────────────────────────────────────────────┘
     dialog broker (popup.py) ─▶ lease from gated ─▶ detached helper ─▶ dialog.py ─▶ gated
     (dialog requests, X25519 key per attempt) ◀─ the gate mod's pane in Claude Code: a Client
     field seals the typed secret (TweetNaCl box); gated opens it (PyNaCl), rechecks, hands it
     to the helper once. No OS dialog or terminal prompt; the system browser only for a browser
     sign-in after Open (daemon/oauth.py); elsewhere: "unavailable".
```

## Where things live (SPEC 1)

| place | what |
|---|---|
| `~/.config/gateway/` (0700) | `gateway.toml` (the form), `gate` (launcher for the user's terminal, rewritten every session), `env.sh` (the env file, for other launchers), `run/contract.json` (CONTRACT-v1 discovery, while gated runs) |
| `~/.config/gateway/private/` (0700) | `key.txt` (age identity) or, once a passphrase is set, `key.wrapped` + `key.recipient` (PLAN-v4 phase 2), `vault.age` (vault v3), `cache.age` (short-lived tokens), `configured.json` (the configured set's non-secret mirror), `.lock`, `backups/` (before every import, `gate rotate`'s), `pending/` (dialog broker state), `sessions/` (per-session records and "shown" markers). Claude never reads it. |
| `$CLAUDE_PLUGIN_DATA` (`~/.claude/plugins/data/gate-gateway`, or under `$CLAUDE_CONFIG_DIR`) | `envs/<sha12 of pixi.lock>/` (the pixi env), `bin/` (stand-ins), `git/` (the gated git's include file and global config), `network-words` and `network-form`, `mode-epoch` (while the mode matters), `pijul/` (built on first use), `audit.jsonl` (rotated at 5 MB), `pycache/`, `managed/` (the managed shell's settings), `gated/` (the daemon's log, event log, terminal and job records, remote hosts' state), `runtime/` (remote runtime packs). Survives updates, deleted on uninstall. |
| `/tmp/gw-$UID/` (0700, owner-checked) | run dir: `gated.sock`, gated's tmux socket and config, panes' start files, ssh master sockets, per-call ssh configs and agents, askpass FIFOs, probe caches, refusals for `gate why`, the approval hook's "ask" records (`asks/`), `signin-active`, `checkpoint-seen` |

`paths.py` is the only place these are computed. Production code never takes
them from `GATEWAY_*` variables; only the hook and MCP modes take the data
folder from `CLAUDE_PLUGIN_DATA`, which Claude Code sets (SPEC 1).

## One entry point, one environment (SPEC 7, 18)

Everything runs `run.py` with the pixi env's Python (`-I -S`, so neither
PYTHONPATH nor the working directory can inject code). Modes: `hook-session`,
`hook-subagent`, `hook-daemon`, `hook-bash`, `hook-mcp`, `hook-mode`,
`hook-files`, `hook-post`, `hook-prompt`, `hook-filechanged` (JSON in, JSON
out), `mcp`, `shim TOOL ...`, `askpass`, `git-credential`, `gate`, `gated`,
`managed-sync`.

`hooks/launch.sh` (POSIX sh) is what Claude Code starts. It finds pixi (PATH,
then fixed places, because the desktop app gives hooks a minimal PATH),
computes the env folder from the sha of `pixi.lock`, and execs the env's
Python (an older env only with the lock's Python minor). If the env isn't
built yet it degrades: SessionStart still writes the env file and, while
gateway.toml may configure something, the full set of stubs in sh
(byte-identical to the Python output) and tells the user setup is running;
the file guard and the Bash approval hook run simpler sh versions (the Bash
one refuses private-folder and transcript reads, credential helpers and
token-bearing commands, and asks about network commands; PLAN-v4 phase 1,
PLAN-0.11 §3.4); stubs print "still setting up" and exit 75 (except `sudo`,
which runs the real sudo, and `git`, which runs the user's own git while
nothing may be configured). A pixi older than
`requires-pixi` is recorded (`pixi_too_old`) and named in every not-ready
text. With the env built, launch.sh still writes the env file (and missing
stubs) before it starts Python for SessionStart, so a hook Claude Code
cancels or kills leaves Claude's commands on the stand-ins. The async
SessionStart hook (`launch.sh ensure-env`) builds the env with `pixi install
--locked` from a copy of `pixi.toml` and `pixi.lock` (the build lock
`<env>.building` records the builder's and pixi's pids and start times, so a
killed build is stale at once and the next run or a waiter takes over),
loads it once (`gateway/warm.py`), and removes old env folders after 7 days
unused. Python always runs with `-X pycache_prefix=$DATA/pycache`, so
nothing is written into the plugin folder. The mod (`hooks/mod/register.tsx`)
starts the same `ensure-env` through `$.process.spawn` at session start when
nothing builds yet, shows a status line while it runs, and serves
`/gate-doctor`; the guards stay in the classic hooks. Optional tools (hf,
databricks, dvc, crane) install into feature envs on first use; pijul is
built with cargo in the background on first use.

## Session start (SPEC 7, 13)

`hooks_session.session_main`:

1. Says once that a gateway 0.6 vault waits for its conversion with 0.10.0,
   and writes nothing beside it.
2. Loads the vault and the form (`hooks_session.prepare`): a missing form is
   restored from the vault's last good copy, or the starter form (three
   comment lines) is written when nothing is stored; narrowings are
   persisted (`consent.ratchet`). It records the payload's permission mode
   in gated where the payload carries one.
3. Writes the env file whole, the same text to `~/.config/gateway/env.sh`,
   the stand-ins the configured set needs (each replaced atomically inside
   `$DATA/bin`, unneeded ones removed), the gated git's include, the
   network words and the launcher (`envfile.sync`). The env file is static
   and idempotent: it puts `$DATA/bin` first on PATH once and, inside Claude
   Code (`CLAUDECODE`), unsets Claude Code's own credential variables and
   removes aliases and functions named after a present stand-in, all only
   while `$DATA/bin` exists (env.sh is sourced by other launchers, such as
   checkpoint jobs, also after an uninstall; then it does nothing). It never
   changes how a command ends.
4. Returns `additionalContext` (at most 2,500 characters, built from the
   validated form only: names, kinds, rights, logins, owners, sites; never
   notes; it says that anything not in gateway.toml uses the user's own
   tools), a `systemMessage` for the user (form errors, widenings waiting,
   gateway dialogs waiting in Claude Code, security events since the last
   session, the first 0.11 session's notice) and `watchPaths:
   [gateway.toml]`.
5. Writes the session record `private/sessions/<sid>.env`.

Every file it writes is written whole, so a killed SessionStart leaves each
one old, new or absent, and the next session writes them all again.

SubagentStart returns the same context. UserPromptSubmit adds a fresh summary
when the form changed since the last context.

## The configured set and the posture (PLAN-0.11 §1)

A target is configured when the form (disabled entries included), the
vault's approved snapshot or `private/configured.json` names it
(`consent.Effective.configured`). Only configured targets go through the
gateway. Taking one out (deleting or renaming its table, dropping an
address, owner or destination, adding `when`, deleting localhost's `sudo`)
is a widening: the approved entry keeps gating until the user's OK. A
missing or broken form falls back to the last good copy, else the
configured list, whose entries are refused; a locked vault still classifies
through the list.

`envfile.standins_for` decides which stand-ins exist; a new install has
none. A stand-in that meets an unconfigured target execs the user's own tool
(`envfile.user_tool`: the caller's PATH minus every folder with a
`.gateway-standins` marker and this plugin's envs, then fixed folders) with
the full argv and the environment unchanged, guarded against loops
(`GW_PASSTHRU`), and writes one `passthrough` audit line without argv.

## Per-mode values (PLAN-0.11 §2)

Rights and the policy restrictions are a word or a table by Claude Code
permission mode (`modes.ModeValue`; words deny < ask < cc < allow, and
"unconfigured" above them). The hooks read the payload's
`permission_mode`. A stand-in for a command Claude typed and the MCP server
read the session's mode that the hooks recorded in gated
(`/agent/session/mode`, kept fresh by the `$DATA/mode-epoch` marker, which
sends every Bash call to Python while it exists); everything else (jobs,
terminals, scripts, gated) uses the modeless rule: the strictest word over
every mode but plan, allow capped at cc. Consent compares values mode by
mode, and the effective value is the per-mode minimum of the form and the
approval.

## Approval hook (SPEC 8, PLAN-0.11)

`PreToolUse` for `Bash|Monitor|mcp__terminal__run_in_terminal|mcp__plugin_check_jobs__job_start|`
the gateway's own `job_start` and `terminal_send`:

- `pre_bash.sh` exits silently unless the command contains a trigger word
  (`sudo ssh scp sftp rsync gate gateway age credential GIT_TRACE_REDACT
  key.txt claude jsonl az su doas pkexec runuser osascript`, git with a
  remote or config word, the network class and the user's `extra` names),
  so ordinary commands never start Python, except while the mode epoch
  marker exists (then a call without a trigger word only records the mode).
- `hooks_bash.main` parses the command with `bashparse` and judges it in the
  payload's mode: deny anything naming the private folder, the run dir, a
  session transcript, `git credential` or the helpers, or turning off git's
  credential redaction; deny a route around a stand-in that reaches a
  configured target (a tool by path, a login shell, `env -i`, a PATH or
  transport change, a ProxyJump), in every mode; deny a command that hides
  its program or host while a configured entry is "ask" in that mode; deny
  the other elevation tools while this computer's sudo is configured; judge
  the network class (deny, ask, or no decision; an explicit allow approves);
  judge git's remote commands in a configured repository up front; deny a
  value that is `false` in that mode or waits for the user's OK; ask for an
  "ask" (scp, sftp and rsync on an "ask" right are denied instead); allow
  when every segment is an allowed shape run by its bare name and its value
  is allow in that mode; otherwise no decision, and Claude Code decides. An
  unconfigured target gets no decision.
- The user's own Terminal panel (`mcp__terminal__run_in_terminal`) gets the
  denies and asks but never `allow`. checkpoint's `job_start` and the
  gateway's job tools are judged at the stricter of their payload's mode and
  the modeless rule; an "ask" there is denied, and the hook never answers
  `allow` or `ask` for them.
- Monitor and background commands are judged like any Bash command. Their raw
  output is a known limit: Monitor's streamed lines reach Claude past every
  hook, and the prompt hook holds back a background command's notice when it
  quotes a stored value or a token shape. `gate scrub` is an optional
  masking filter.

`mcp_perm.sh` (sh + awk) allows `host_inspect`, the terminal and job reads, a
local `terminal_open`, `terminal_resize` and `host_runtime`'s status, in every
mode; `http` and `download` go to `hooks_mcp`, which answers from the
`network` policy in the payload's mode (deny, ask, allow only for the user's
explicit per-mode allow, else nothing). `tool_guard.sh` denies an
AskUserQuestion that asks for a secret and the browser-automation tools while
`<run>/signin-active` exists. The file guard (`hooks_files`, `onFailure:
"block"`) denies Read/Grep/Glob/Edit/Write/NotebookEdit inside the protected
places and on session transcripts, and the desktop app's transcript export.
launch.sh passes a plain path inside the session's folder by itself (an sh
fast path) and starts Python for everything else.

## Stand-ins (SPEC 9, 10)

Each stub is a short sh script with absolute paths baked in that execs
`run.py shim TOOL`. Every stand-in follows the same steps:

1. Load the form and ratchet; compute effective rights for the recorded mode
   (a command Claude typed) or the modeless rule.
2. Classify the target. Unconfigured: pass it through to the user's own
   tool. Configured but disabled, removed-and-held, or behind a locked vault:
   refuse with the reason.
3. Check the right: deny refuses; "ask" refuses unless Claude's own command
   shell (or a fork of it) started the stand-in with nothing in between
   (`ancestry.typed_by_claude`), since Claude Code can only ask about the
   command Claude typed, and only with the approval hook's record of that
   very command, which lives until the session's next Bash or Monitor call
   (`asks.py`; the gated git's children pass an "ask" only with the hook's
   record of that command).
4. Check the caller (`ancestry.is_direct`): every process up to `CLAUDE_PID`
   must be a shell or a plain wrapper (plus the git/ssh family for ssh and
   git credentials), identified by executable path. Otherwise the credential
   is withheld unless the entry has `scripts = true`.
5. Pick the account (`accounts.select`) and check the destination is in its
   `bound` set.
6. Read the secret from the vault, run the real binary by absolute path with
   an allowlisted environment and forced endpoint variables, stream its
   output through the scrubber, write one audit line.

Per family:

- **sudo** (local, only while `[hosts.localhost] sudo` or an elevation
  restriction configures it): with only a restriction, deny refuses, "ask"
  needs a typed command, otherwise the user's sudo runs. Gated: if `sudo -n
  true` works (cached 10 min), exec the real sudo untouched; otherwise the
  stored password (or one verified in the gateway's dialog) goes to `sudo
  -A` through a one-shot askpass FIFO.
- **ssh, scp, sftp**: a lenient parse finds the destination; a direct hit
  (the form's name, `gw-NAME`, an address or `also` entry) takes the gated
  path; a hit found only through the user's `ssh -G`, a ProxyJump hop, a
  ProxyCommand or a resolved IP is refused with the name to use; no hit
  passes through. The gated path refuses options that change identity,
  proxying or forwarding, picks an address, writes a per-call ssh config
  (pinned host keys, only the gateway's keys in a private agent,
  `ControlMaster` reuse, `ProxyJump` for `via`). A copy that mixes a
  configured and an unconfigured remote is refused. rsync is no stand-in:
  it starts `ssh` through PATH.
- **remote sudo** (SPEC 9.3): probe `sudo -n true` over the master; if a
  password is needed, a staging call puts it and a guarded askpass in a 0700
  folder on the remote, the command runs, output is scrubbed, the folder is
  removed ("Remember it" starts unticked).
- **git** (PLAN-0.11 §6, `githelper.git_main` with `gitroute`): in a
  repository with any configured effective URL, and for a command whose
  operand URL is configured, the env's git runs with an allowlisted
  environment, the include file at command-line scope (credential reset,
  URL-scoped `git-credential-gateway`, `insteadOf`, identities,
  `core.sshCommand` = the ssh stand-in) and `GIT_CONFIG_GLOBAL` = the
  gateway's read-only file; a `!` alias, guarded `-c` pairs and guarded
  config writes are refused. Everything else execs the user's git.
- **gh, hf, databricks, crane, pijul, az**: each resolves the destination as
  the tool would; a covered one gets the token in that process only (`GH_TOKEN`,
  `HF_TOKEN`, an Entra token as `DATABRICKS_TOKEN`, a per-call
  `DOCKER_CONFIG`, a private agent for pijul) with endpoints forced and
  token-printing subcommands refused; an undeterminable one uses the
  account; an uncovered one passes through.
- **asiml** (and `dvc pull|push` inside an asiml workspace; other dvc passes
  through): the gateway's own client for an ML model catalog.
- **`gate with NAME -- CMD`**: the key in the account's `env` variable for
  that one process, output scrubbed; never hook-approved.

## MCP server (SPEC 14)

`mcp_server.py` is a small stdio JSON-RPC server (`alwaysLoad`) with the
`http`, `download`, `host_inspect`, terminal and job tools. `http` sends a
request, adding an account's credential only for its approved and bound
destinations, follows redirects by hand and drops the credential on a
cross-host or downgrading hop, ignores proxy variables and custom CA bundles,
and scrubs the response; the `network` policy is read in the session's
recorded mode (an "ask" passes: the hook asked up front). `download` streams
to a new file under the working directory, `~/Downloads` or a temp folder.

## Form, vault and consent (SPEC 2, 3, 5)

- **The form** is TOML with a lenient pre-pass (`yes`/`no`/`ask`/`cc`
  words). Each entry is validated on its own; a bad entry is off (still
  configured, refused) and reported; a syntax error falls back to the last
  good copy in the vault. The gateway never re-serializes it: writers append
  a table or replace one line and roll back if anything else changed.
- **The vault** is age-encrypted JSON: per host its ssh keys, pinned host
  keys and sudo passwords; per account its token, ssh key or Entra
  credential and its `bound` destinations; the approved snapshot (per-mode
  maps where the form has a table); the last good form; the last 100
  security events; the passphrase offer's state. Every read-modify-write
  holds `private/.lock`.
- **Consent**: `consent.compute(form, vault, mode)` compares the form with
  the approved snapshot mode by mode. Narrowing is effective at once and
  persisted by every process that loads the form (`ratchet`). Widening
  (removal included) stays inactive until `gate check NAME` shows the
  consent dialog, which names what changes in each mode, and the user
  approves exactly those changes; approving an account adds its
  destinations to `bound`.

## Dialogs (SPEC 6, PLAN-v4 phase 3)

`popup.py` is the only way to ask the user, and every question is the
gateway's native dialog inside Claude Code (docs/dev/modules/daemon.md
"Dialogs"). The requesting process takes a dialog lease from gated (it runs
below the Claude Code session, so gated knows which session's mod draws it;
no lease in `claude -p`, the SDK, VS Code, mobile, Remote Control or with
mods off: the request is "unavailable"), double-forks a detached helper that
opens the dialog through gated, and waits at most 90 s before exiting 75
with "the gateway dialog is still open in Claude Code; tell the user once".

gated holds the requests (one dialog at a time per session) and makes an
X25519 key pair for each attempt of a secret. The gate mod long-polls them
and draws the pane; a secret is typed into a `Client` field and leaves it
sealed with TweetNaCl's box. gated opens the box (PyNaCl), rechecks the
request and hands the value once to the helper. A consent or import confirm
longer than one pane comes in parts. gated's own dialogs: the vault
passphrase (set, unlock), the passphrase offer after a stored secret
(`daemon/offer.py`), the host-change gates, terminal password prompts, and
the browser sign-in's confirm (`daemon/oauth.py`: Open starts a 127.0.0.1
listener with state and PKCE, opens the system browser by absolute path, and
stores the tokens in the vault).

## The gate CLI (SPEC 15)

`gate status [NAME]`, `check NAME|all`, `login`, `forget`, `rotate`, `with`,
`export`, `import`, `copy-to`, `pubkey`, `log`, `why`, `lock`, `import-ssh`,
`scrub`, `host`, `workspace`, `policy`, `network`, `accounts`. `gate check
NAME` is the eager setup: plan what the entry needs (pending widenings and
removals, a keyscan for new hosts, a key to install, a sudo password or the
per-command choice, a token or a browser sign-in), then run the whole
sequence as one broker job in the dialog helper, so it survives the
requester's exit 75.

## Other hooks (SPEC 12)

- **PostToolUse** (`post.sh` prefilter, every tool but a skip list): once a
  vault exists, every response goes to Python; without one, only a response
  holding a token shape or the value of one of the user's credential
  variables. It rewrites the response with `updatedToolOutput`; after an
  Edit/Write of the form it validates it and tells Claude what is wrong or
  what waits for the user's OK.
- **PostToolUseFailure**: a failed call's output can't be rewritten. When it
  holds a stored secret or a token shape, Claude is told never to use what
  it saw, the user which entry to replace, and it is audited.
- **UserPromptSubmit** (`prompt.sh`): blocks a pasted token or private key;
  holds back a task notification quoting a stored value or a token shape
  (fails closed).
- **FileChanged** on `gateway.toml`: re-validates, ratchets, syncs the
  stand-ins and the network words, and tells the user what changed.

## Export, import, copy-to (SPEC 16)

Export format 3 holds the items picked in a checklist (hosts, accounts,
their secrets, the settings `[shell]`/`[policy]`/`[network]`/`[vault]`, this
machine's `[hosts.localhost]` settings, unticked by default; never a browser
sign-in's refresh token), with a schema version and a sha256 digest,
encrypted with an age passphrase typed twice in the native dialog. Import
validates everything strictly, tells a wrong passphrase from a changed or
damaged file, recognizes this machine, asks per conflicting item, shows one
confirm (in parts when long) whose acceptance approves what it lists, and
writes form and vault in one staged step after a backup. `gate copy-to
HOST` encrypts the export to the remote gateway's own age recipient and
streams it over ssh to `gate import --from-peer -`.

## The gateway daemon (PLAN-v4 phase 2)

`gated` is one detached process per user, started on demand. It listens on
`/tmp/gw-$UID/gated.sock`, identifies every caller by the kernel's peer
credentials and serves its planes: the UI plane for the Claude Code process
itself (the mod), the agent plane for the gateway's own programs (vault
data, scoped per program; recorded modes; sign-in and offer routes), the
CONTRACT-v1 plane for checkpoint and a local plane. With a wrapped vault key
only the daemon decrypts. Details: [modules/daemon.md](modules/daemon.md).

## The managed shell (PLAN-v4 phase 4, PLAN-0.11 §1.6)

The mod sets `CLAUDE_CODE_SHELL_PREFIX` to `hooks/gate-sh`; a classic hook
string passes through as `/bin/sh -c`, a Bash-tool script runs in the env's
bash with Claude Code's snapshot `source` replaced by the gateway rc and the
inherited environment minus Claude Code's credentials, the shell's startup
variables and `GW_*` (removed by name). The rc sources a bash snapshot, then
removes aliases and functions that could shadow the stand-ins. Not ready:
the script runs without the gateway's settings in the shell that made its
snapshot (never `/bin/sh`), with a notice naming that shell. Without the
mod the commands run in the user's shell, still judged by the hook. Details:
[modules/managed.md](modules/managed.md).

## Terminals and jobs (PLAN-v4 phase 5)

gated supervises persistent PTYs in its own tmux server: terminals and jobs,
each with the managed shell's environment. The gw tools reach them on the
agent-term plane, the mod's `/gate-terminal` pane on the UI plane,
checkpoint on the contract plane. A password prompt in a pane opens the
gateway's credential dialog, whose value goes to that tty only. Details:
[modules/terminals.md](modules/terminals.md).

## The managed remote runtime (PLAN-v4 phase 6)

A terminal or job can run on a configured host. gated packs the plugin's
`runtime/` workspace (bash and tmux) with pixi-pack for the host's platform,
stages it over the gateway's own ssh after sha256 checks, and runs the panes
in that runtime's tmux under `env -i` and a curated PATH. A changed host key
or machine blocks the host until the person confirms in gated's own dialog.
Details: [modules/remote.md](modules/remote.md).

## Hosts, workspaces, policy and accounts (PLAN-v4 phase 7)

Each host can hold workspaces, and every terminal and job is bound to host +
workspace by gated. Policy is a per-mode value per host, workspace, account
and action, a layer of restrictions on the rights: `policy.decide` at each
boundary takes the strictest rule and names it in every refusal. Account
adapters check stored credentials with one cheap API call. `/gate-hosts` and
`/gate-accounts` show all of it and edit it (per-mode values included)
through the form writer and the consent dialog. Details:
[modules/policy.md](modules/policy.md), [modules/network.md](modules/network.md)
for the network class.

## Threat model, briefly

Meant to stop: a cooperative or prompt-injected Claude seeing a stored
secret, sending one to the wrong place, giving itself more rights, or
getting root or a token for code it didn't run directly, for what the form
configures; secrets ending up in output, logs or the transcript. Not a
sandbox: Claude's commands run as the user, so a determined program can read
the vault key; the Bash checks are text checks and the ancestry check trusts
executable names. Under the posture the user's own credentials are in
Claude's shell and unconfigured targets are the user's own; a configured
host's limits bind only if the user's own key or token doesn't also open it.
Values the user sets to allow skip Claude Code's prompt by design. README's
"Security and privacy" and "Limits" list the limits as the user sees them.
