> Design history: the v3 build contract, kept for its section numbers (code comments cite them) and its reasoning. Not a user guide: see the [README](../../README.md), and [CONFIG.md](../CONFIG.md) for every setting.

# Gateway v3 build spec

The contract for building v3 (plugin version 0.7.0). **[PLAN-v4.md](PLAN-v4.md)
supersedes it where they differ** (plugin 0.9.0): every question is the
native dialog inside Claude Code (section 6's OS dialogs, `gate secret`'s
terminal path and the browser and device-code sign-ins are removed),
Claude's commands run in the managed shell, the vault key can be
passphrase-wrapped and held by the daemon, sudo never gets a sudoers rule,
export is format 3, and policy and workspaces narrow the rights.
**[PLAN-0.11.md](PLAN-0.11.md) supersedes both where they differ** (plugin
0.11.0): only what gateway.toml configures goes through the gateway, and
everything else uses the user's own tools (reversing the 2026-10-18 choice
below that unlisted machines are refused); stand-ins exist only where
something configured can be reached; rights and restrictions are per
permission mode; network commands are one configurable class (curl and wget
are no longer refused); git is a stand-in with its own config for configured
repositories; azure and ml-catalog accounts can sign in through the browser;
the 0.6 conversion, export formats 1 and 2 and `[settings]` are gone. The
sections below carry short "0.11.0" notes where that changes them; the
module docs ([modules/](modules/)) describe the code as it is. User guide:
[../README.md](../../README.md); the plan this came from:
[history/REDESIGN-v3.md](history/REDESIGN-v3.md). Decisions taken by the user on 2026-10-18:
unlisted machines and git servers are **refused** (with an offer to add);
credentials go to **direct** commands only (opt-in `scripts = true`);
**widening needs one pop-up**; API keys reach programs only **opt-in**
(`env =`).

Research behind this (platform probes, critiques, prototypes) is summarized
in [DECISIONS.md](DECISIONS.md); how the parts fit is in
[ARCHITECTURE.md](ARCHITECTURE.md). Platform facts relied on:

- A plugin PreToolUse `allow` skips the auto-mode classifier (Bash and MCP).
  `ask` always becomes a human prompt. Settings ask/deny rules (such as an
  organization's managed `Bash(curl *)` or `Bash(wget *)`) still win.
- SessionStart may write `$CLAUDE_ENV_FILE`; its content runs before every
  Bash command, including background commands and subagents. The same file
  is reused on resume/compact/clear: replace its whole content (a temp file
  renamed over it; Claude Code sources only `sessionstart-hook-N.sh`),
  idempotently.
- `CLAUDE_PLUGIN_ROOT`/`CLAUDE_PLUGIN_DATA` reach hooks and MCP servers, not
  the Bash tool. `CLAUDE_PID` and `CLAUDE_CODE_SESSION_ID` are in the Bash
  env. Plugin `bin/` is appended last on PATH (don't ship one).
- MCP tools are deferred unless `.mcp.json` sets `"alwaysLoad": true`
  (connect then blocks startup up to ~5 s).
- Hook options: exec form (`command` + `args`), `timeout`, `async`,
  `onFailure: "block"`, `if` filters. Events used: SessionStart,
  SubagentStart, UserPromptSubmit, PreToolUse, PostToolUse (with
  `updatedToolOutput`), PostToolUseFailure, FileChanged.
- A Bash command that exits non-zero (or times out, or is killed) goes to
  PostToolUseFailure, with its output in `error`; that event's hooks can add
  `additionalContext` (and a `systemMessage`) but can't change what Claude
  reads. Claude Code runs a Bash command as `<env file lines> && ... && eval
  CMD && pwd -P >| cwd-file` in one shell (2.1.301). Monitor's PostToolUse
  gets only `{taskId, timeoutMs, persistent}`: each stdout line reaches Claude
  as an event no hook sees. A subagent's hook systemMessages are recorded in
  `<project>/<session>/subagents/agent-<id>.jsonl` (round 3 probes).
- Round 4 probes (2.1.301): every background Bash task (`run_in_background`,
  or a foreground command moved to the background by its timeout, a message
  or ctrl+b; not Monitor) writes stdout and stderr raw to
  `<TMPDIR>/claude-<uid>/<project>/<session>/tasks/<id>.output`. After 45 s
  without new output Claude Code reads its last 1 KB, and if the last line
  looks like a prompt (`[y/N]`, `Continue?`, `Press Enter`, ...) it hands
  Claude a `<task-notification>` with `Last output:` and that raw tail: as a
  new prompt when Claude is idle, as a queued attachment mid-turn. Both pass
  UserPromptSubmit (which can block them); no output hook sees them. The
  desktop app gives Claude session tools (`mcp__ccd_session_mgmt__*`):
  `export_transcript` writes a zip of raw transcripts to `~/Downloads`,
  `search_session_transcripts` and `list_events` return other sessions'
  text; PreToolUse and PostToolUse hooks match them like any MCP tool.
- An MCP tool's result reaches PostToolUse as its content list
  (`[{"type": "text", "text": ...}]`), and an `updatedToolOutput` list
  replaces what Claude reads; an error result (`isError: true`) goes to
  PostToolUseFailure instead, with its text in `error`, where an
  `updatedToolOutput` is ignored and `additionalContext` reaches Claude
  (probe with a standalone plugin, 2.1.301; the integration run saw the same
  for checkpoint's `job_tail`).

## 1. Layout

```
~/.config/gateway/                 GATEWAY home (0700)
  gateway.toml                     the form (Claude may read and edit)
  gate                             stable launcher for the user's terminal (sh, regenerated each session; launch.sh writes it in the first session too)
  env.sh                           stable env file other launchers may source (same content as CLAUDE_ENV_FILE; a no-op once $DATA/bin is gone)
  private/                         0700; Claude must never read it
    key.txt                        age identity (moved here from ../key.txt)
    vault.age                      vault v3
    cache.age                      short-lived tokens (safe to delete)
    .lock                          flock for every read-modify-write
    backups/                       store-v2-YYYYMMDD.age (+ its key) from migration; import-<time>-<hex>/
                                   (the form and vault before an import); rotate-<time>-<hex>.vault.age
                                   (the vault just before a gate rotate changed it, the newest 5; section 15)
    pending/                       pop-up broker state (one file per pending secret; one-time codes, cancel markers)
    sessions/                      per-session records (<sid>.env: start, display variables) and shown markers
$CLAUDE_PLUGIN_DATA/               survives plugin updates, deleted on uninstall
  envs/<lock-sha12>/               pixi env built from a copy of pixi.toml+pixi.lock (immutable once built)
  bin/                             generated stand-ins (atomic: bin.new -> rename)
  git/config                       generated git include file
  ssh/                             generated per-call configs live in run dir, not here
  audit.jsonl                      audit log
/tmp/gw-$UID/                      run dir, 0700, owner-checked (sockets: mux, agent, askpass FIFOs,
                                   gated.sock); refused with a remedy otherwise: one others could write
                                   to is removed and made again, never chmod'ed back (what they put
                                   there would stay); clients connect only to a gated.sock that is the
                                   user's own, 0600, in that folder (modules/daemon.md)
```

`paths.py` is the only place these are computed. The Python code never
reads `GATEWAY_*` from the environment in production entry points (shims,
askpass, git helper, hooks, MCP). Tests use `gateway.testing.override(...)`
(an explicit API), never env vars a Claude-controlled process could set.
Two redirections exist, both for tests: (1) hooks and the MCP server may
honour `GATEWAY_TEST_ROOT` only when `run.py` was started with `--test` by
the test runner (Claude's Bash never invokes hook entry points with `--test`;
and it would only redirect to an empty test vault anyway); (2) the e2e
marker: a file `e2e-root` in a scratch copy of the plugin redirects every
location of every mode (hooks, MCP, stand-ins, askpass, git helper, `gate`;
`paths.e2e_marker`, `hooks/e2e.sh`) to folders it names, and counts only
when the code's own location (never a variable), the marker and those
folders are the user's, private and under a temp folder; the checkout and
an installed plugin never are (`tests/e2e/README.md`).

## 2. The form (`gateway.toml`)

> **0.11.0** ([PLAN-0.11.md](PLAN-0.11.md) §1, §2, §3): only what the form configures goes through the gateway; anything else is the user's own. `[settings]` is removed (a written one is a warning). Rights, the moded policy keys and `[network] commands` take a word (`true`/`"allow"`, `"cc"`, `"ask"`, `false`/`"deny"`) or a per-mode table with `default` required. `[network]` (`commands`, `extra`, `drop`) is new; `[hosts.localhost]` is optional (no `sudo` key: the user's own sudo). The user's reference is [CONFIG.md](../CONFIG.md).

Parsed with `tomllib` after a lenient pre-pass: on lines matching
`^\s*(ssh|sudo|scripts|use|default|packages)\s*=\s*(yes|no|on|off|ask|true|false)\s*(#.*)?$`
bare words are normalized (`yes|on|true` → `true`, `no|off|false` →
`false`, `ask` → `"ask"`). A TOML syntax error keeps the last good form
(the last valid form any gateway process loaded, stored in the vault as
`form_last_good`) and reports the line, with a hint for the key on it (`sudo
takes true, "ask" or false`); `gate check`, `gate status NAME` and the ssh
stand-in then point at the syntax error instead of asking to add an entry
that may be in the unreadable part.

Names: `[a-z][a-z0-9-]{0,31}`, one namespace across hosts and accounts.
Reserved: `localhost` (host only), `local`, `this`, `all`, `gateway`, `gate`,
`settings` (the `[settings]` pseudo-entry of consent and `gate check`).
Unknown keys: warning, ignored. Each entry is validated on its own; a bad
entry is disabled and reported; others keep working. Strings are rendered
anywhere (context, pop-ups, status) only after validation, with control
characters, newlines and bidi overrides refused.

### `[settings]` (optional)

> Removed in 0.11.0: there is no `others` key; unlisted machines and git servers use the user's own tools.

| key | type | default | meaning |
|---|---|---|---|
| `others` | `"refuse"` \| `"mine"` | `"refuse"` | machines/git servers not in the form: refuse, or use the user's own ssh/git setup |

### `[hosts.NAME]`

| key | type | default | meaning |
|---|---|---|---|
| `address` | `"[user@]host[:port]"` | required (forbidden on localhost) | DNS name or IP (IPv6 as `[::1]:22`), not an ssh_config alias; user defaults to the local user, port 22. A git server (`github.com`, `ssh.github.com`, `hf.co`, `huggingface.co`, `nest.pijul.com`, `gitlab.com`, `bitbucket.org`, `codeberg.org`) is an error here and in `also` (round 4: the ssh stand-in matches hosts by address before account endpoints, so it would take over git's ssh routing); an ssh endpoint of an account in the form (a GHES or Pijul server whose `host` has no port) is a warning |
| `when` | CIDR string | none | try `address` only when this machine's source address toward it is in that network |
| `also` | list of `"[user@]host[:port]"` or `{at = "...", when = "CIDR"}` | `[]` | further addresses, tried after `address`; a user part must equal `address`'s user |
| `via` | host name | none | jump host (form host only; chain ≤ 3; no loops; jump host must not have `ssh = false`) |
| `ssh` | `true`\|`"ask"`\|`false` | `true` | ssh, scp, sftp, rsync to this host, and use as a jump host |
| `sudo` | `true`\|`"ask"`\|`false` | `true` (localhost: below) | root commands (local for localhost; remote over ssh otherwise) |
| `scripts` | bool | `false` | credentials also reach programs started by Claude's commands (make, npm, …) |
| `note` | string ≤ 200 | | shown in status |

`[hosts.localhost]` takes only `sudo`, `scripts`, `note` (and, since
PLAN-v4 phase 7, `policy` and `workspaces`); it is implicit when absent.
Where the form doesn't say this computer's `sudo` (no table, or a table
without the key) it is `"ask"` on a new install and `true` on an older one
(0.10.0: the vault's baseline mark decides, section 3;
`form.apply_install_defaults`). The starter a new install writes says
`sudo = "ask"`.

### `[accounts.NAME]`, common keys

| key | type | default | meaning |
|---|---|---|---|
| `kind` | see below | required | |
| `login` | string | filled in by sign-in | the account's user name; always counts as an owner |
| `owners` | list | `[]` | owners (orgs/users) whose repos use this account; routes, never restricts an explicit choice |
| `default` | bool | `false` | used for this kind+host when no owner matches; at most one per kind+host |
| `name`, `email` | strings | | commit identity in repos under `login`/`owners` (github, huggingface, pijul) |
| `env` | var name | | opt-in: `gate with NAME -- cmd` puts the key in that variable for that one process |
| `scripts` | bool | `false` | as for hosts |
| `use` | bool | `true` | `false` keeps the credential but never sends it |
| `note` | string ≤ 200 | | |

### Kinds

| kind | extra keys | destinations (where its credential may go) |
|---|---|---|
| `github` | `host` (default `github.com`), `packages` (bool, default true on github.com) | `host`, `api.<host>` (github.com and `*.ghe.com`), `ghcr.io` if packages; ssh endpoint `git@host` |
| `huggingface` | | `huggingface.co`, `hf.co`; ssh endpoint `git@hf.co` |
| `azure` | `tenant` (required), `client_id` (default Azure CLI public client), `databricks` [workspace hosts], `storage` [account names], `registries` [`x.azurecr.io`], `sites` [hosts needing an explicit scope] | `management.azure.com`, `graph.microsoft.com`, listed workspaces, `<storage>.{blob,dfs,file,queue,table}.core.windows.net`, listed registries, listed sites |
| `ml-catalog` | `host` (required: the catalog's address; no default, an account without it is off) | `host` (tenant/client/scope pinned at sign-in, never re-read from a changed host) |
| `pijul` | `host` (default `nest.pijul.com`), `remote_pijul` (abs path) | `host` over ssh (Nest host key built in; others pinned) |
| `registry` | `host` (required) | `host` |
| `api-key` | `sites` (required list; `api.x.com` exact, `.x.com` any subdomain), `auth` (`bearer` default \| `header:NAME` \| `header:NAME:PREFIX` \| `query:PARAM` \| `basic`) | `sites` |

### Writer

The gateway never re-serializes the form. It (a) appends whole tables with
a comment header, or (b) replaces one `key = value` line inside a known
table; then re-parses and rolls back if the parse or validation changed
anything else. Writers: migration (only when the form is absent; else it
writes `gateway.from-v2.toml`), import, `gate` commands that the user asks
for. Claude edits the form with its own Edit tool.

## 3. Vault v3 (`private/vault.age`)

age-encrypted JSON, same crypto/locking as v2 (`age -r`, stdin/stdout only,
atomic replace, `.lock` flock). The replace is durable (GW-DUR-1): a temp
file beside it, flushed (on macOS `F_FULLFSYNC`, else fsync), renamed, then
the folder flushed (`vault.write_private`); cache.age and key.recipient
likewise.

```json
{"version": 3,
 "machine": {"id": "<IOPlatformUUID | /etc/machine-id | random>", "name": "macbook", "hostname": "macbook.local"},
 "localhost": {"sudo": {"USER": {"password": "...", "updated": "...", "stale": false}}},
 "hosts": {"NAME": {
    "keys": [{"private": "...", "public": "ssh-ed25519 ...", "fingerprint": "SHA256:...", "created": "...", "retired": null}],
    "host_keys": ["ssh-ed25519 AAAA..."],
    "sudo": {"USER": {"password": "...", "updated": "...", "stale": false}},
    "probe": {"nopasswd": {"USER": "2026-10-18T..."}}}},
 "accounts": {"NAME": {
    "kind": "github",
    "token": {"value": "...", "source": "gh-oauth|pasted", "updated": "...", "stale": false},
    "ssh_key": {"private": "...", "public": "...", "fingerprint": "..."},
    "entra": {"refresh_token": "...", "client_id": "...", "tenant_id": "...", "refreshed": "..."},
    "host_keys": ["..."],
    "bound": {"hosts": ["github.com", "api.github.com"], "tenant": "...", "client_id": "...", "auth": "bearer"}}},
 "approved": {"form_sha256": "...", "rights": {"hosts": {...}, "accounts": {...}}},
 "form_last_good": "<text>",
 "aliases": {"github:work": "github-work", "OPENAI_API_KEY": "openai-api-key"},
 "events": [{"at": "...", "what": "widen|bind|export|copy|import|migrate|reject", "detail": "..."}],
 "migrated": {"from": "v2", "store_sha256": "...", "at": "...", "report": "..."},
 "sudo_choice": {"localhost": {"USER": "ask"}, "NAME": {"USER": "password"}},
 "baseline": 2}
```

- `baseline` (0.10.0): the mark of a vault made by 0.10.0 or later
  (`vault.BASELINE_KEY`). A vault without it is an older install
  (`vault.older_install`), which keeps the old default `sudo = true` for
  this computer where the form doesn't say it (section 2). The broker's
  merge keeps the mark as the vault has it, a 0.6 conversion writes none,
  and an export leaves it out (it describes this machine). While the vault
  can't be read the new defaults apply.

- Host secrets are tied to the host's pinned host keys, so a rename or an
  address change with the same key needs nothing.
- Account credentials are tied to `bound` (destination set + auth placement
  + Entra tenant/client). A destination computed from the form that is not
  in `bound.hosts` is a widening (section 5). They also belong to the
  approved identity, name + kind: approving an account with no earlier
  approval of that name (new, or added back after removal; an imported 0.6
  snapshot counts as one) or with another kind drops what was stored under
  that name (token, ssh key, Entra sign-in, pinned host keys, cached tokens,
  bindings), so `gate check` asks for a fresh secret (`consent.drops_credential`).
- `events` keeps the last 100 security events; SessionStart shows the user
  new ones since their last session (systemMessage).
- `sudo_choice`: the user's answer to `gate check`'s sudo choice per (host,
  user) (section 15); per machine, never exported.
- `cache.age`: Entra access tokens, ACR refresh tokens, keyed by
  account+scope, with expiry. Minted under the lock; a shim reuses a cached
  token until 2 minutes before expiry.

## 4. Migration from v2

> Removed in 0.11.0: a 0.6 vault is converted with the published 0.10.0 first, and 0.11.0 refuses to create a vault beside one (`vault.v06_waiting`, `V06_MESSAGE`). This section is history.

Trigger: the first v3 process (SessionStart, a shim, the MCP server or
`gate migrate`) that finds `~/.config/gateway/store.age` and no
`private/vault.age`. Offline: no keyscan, no network, no dialog.

1. Take `.lock`. Create `private/` (0700). Copy `store.age` and `key.txt`
   to `private/backups/` (as `store-v2-YYYYMMDD.age`, `key-v2.txt`).
2. Decrypt with v2 code paths (vault v1 and v2 accepted). Map (below). Write
   `private/key.txt` (same identity) and `private/vault.age`.
3. Write `gateway.toml` only if absent (else `gateway.from-v2.toml`).
4. Validate: parse the generated form with the v3 parser; every v2
   credential either landed in the vault or is listed as dropped. On any
   failure write nothing new; v3 runs with an empty vault; status and a
   systemMessage say `migration failed: REASON; run gate migrate`.
5. On success, move the v2 `store.age` and `key.txt` out of the home folder
   into `private/backups/` (so `cat ~/.config/gateway/*` can never print the
   key). Rollback is a documented manual move.
6. Record `migrated` and a report (`gateway: converted your 0.6 vault …`,
   with what is now allowed without asking and how to get the prompt back);
   show it once to the user (systemMessage) and keep it in `gate status
   --report`. A conversion that a stand-in, the MCP server or `gate` ran
   mid-session (an upgrader's first session runs without an env, so it
   usually is) leaves `private/migrated.unshown`, and the next
   UserPromptSubmit shows the report (round 4); otherwise SessionStart does.
   User-facing text calls the old version "0.6", never "v2" (the internal
   name of its vault format).

Naming: `ssh:NAME` → host `NAME`. A kind with exactly one account takes the
short name (`hf`, `azure`, `catalog`, `pijul`); several take `KIND-NAME`
(`github-personal`, `github-work`). Secrets: lowercase, `_` → `-`. A clash
with a host appends `-acct`. Every old ref goes into `aliases`.

Mapping:

- `github:X` → `[accounts.github-X]` kind github; login, owners, name,
  email; host only if not github.com. Vault: token (+source), ssh_key,
  `bound.hosts` = v2 hosts (+ ghcr.io if a `registry` account used it via).
- `hf:X` → `[accounts.hf]` (or hf-X); token, ssh_key.
- `ssh:X` → `[hosts.X]`: `address` = `user@routes[0].host:port` (or
  host/port), `when` = routes[0].when, `also` = routes[1:] (tables where a
  route has `when`), `via` = jump account's name, ssh/sudo `true`. Vault:
  keys = current key + `old_ssh_keys`/`old_public_keys` (not retired),
  `host_keys` from `known_hosts`. Lost: route names, comfort knobs,
  `accept-new`/`pinned` policy (now: pinned + pop-up), exec prompts, reuse.
- `azure:X` → `[accounts.azure]`: tenant, login, client_id (only if not the
  CLI client), `databricks` = `*.azuredatabricks.net` hosts, `storage` =
  account names from `*.{blob,dfs,file,queue,table}.core.windows.net`,
  `registries` = `*.azurecr.io` (+ registries that used it via), `sites` =
  the rest. Vault: entra {refresh_token, client_id, tenant_id, refreshed}.
- `mlcat:X` → `[accounts.catalog]` kind ml-catalog (host only if not
  default); entra credential; `bound` gets the pinned tenant/client/scope.
- `pijul:X` → `[accounts.pijul]`: login, name, email, remote_pijul, owners;
  ssh_key; host_keys (Nest built in).
- `registry:X via github:Y` → no entry; github-Y gets packages and ghcr.io
  bound; report owner differences. `via azure:Y` → azure `registries`. With
  its own token → `[accounts.X]` kind registry.
- secret `NAME` → `[accounts.<name>]` kind api-key, `sites` = hosts,
  `auth = "bearer"` with a comment that v2 didn't record placement, note =
  description; alias. Empty hosts → entry disabled with a note.
- sudo `user@localhost` → `localhost.sudo[user]` (only if user is the
  current user; else dropped with a note). `U@H` → the host found by v2's
  rule (sshops.account_for_sudo) under `hosts[X].sudo[U]`; if none matches,
  add `[hosts.<from H>] address = "U@H"` with a comment ("0.6 reached this
  host with your own keys; run gate check NAME while you're here to install
  Claude's key": the ssh stand-in never installs a key itself, and Claude's
  context lists the host as having no key yet, without "reach as").
- `sudo_enabled`, `sudo_session`, prompts, `account_prompts`, grants,
  `ssh_reuse`: report only. A class set to `refuse` becomes a comment; four
  refuses → `use = false`. Every host where v2 asked now gets `true`; the
  report says so.
- v2 descriptions → `note`.

Import of a v2 export file (`gateway_export: 1`) runs the same mapper.

## 5. Consent: widening and bindings

`approved` in the vault holds the rights the user last OK'd. On every form
load the gateway computes the effective rights:

- **Narrowing** applies at once, silently (true→ask→false, removing hosts,
  addresses, owners, sites, `use = false`), and is persisted (`approved`),
  also before anything is stored: a narrowing creates the vault, so neither
  a later syntax error nor a deleted form brings the right back. Closing ssh
  masters and agents for affected hosts is part of applying it.
- **Widening** — a new host; a right raised (false→ask→true, false→true,
  scripts false→true); a new `address`/`also`/`via`; a new api-key site,
  azure workspace/storage/registry/site, account `host`; an account `env`
  added; `others = "mine"` — stays inactive until confirmed. The entry runs
  with its last approved rights meanwhile (a brand-new entry: nothing).
- Confirmation: one pop-up listing exactly what changed, default button
  Cancel, opened by `gate check NAME` (Claude runs it right after a change
  the user asked for) or lazily by the first command that needs it. The same
  pop-up continues into any secret entry the entry needs.
- Bindings: a credential is sent only to a destination in its `bound`
  set. An address change for a host is not a binding change (host keys
  bind). A new host key is a pop-up showing old and new fingerprints (and
  whether the user's own `~/.ssh/known_hosts` knows the new one); except
  that a non-last candidate address showing another key is skipped silently
  (another machine on that network) and only logged.

The `others = "refuse"` rule also means: SessionStart unsets the user's
`SSH_AUTH_SOCK`, `SSH_AGENT_PID`, `SSH_ASKPASS*`, `GIT_ASKPASS` and token
variables (v2's `ENV_UNSET` list) in Claude's env file, and git gets a
global `credential.helper=` reset in the include file before the gateway's
URL-scoped helpers. With `others = "mine"` neither happens and the ssh
stand-in delegates unknown hosts to the system ssh with the user's config.

## 6. Pop-ups

(Superseded by PLAN-v4 phase 3: the requests below are shown only as the
native dialog the gateway's mod draws inside Claude Code, through gated;
the osascript/zenity/kdialog backends, the `unavailable` → `gate secret`
terminal route and `signin` by browser or device code are gone. What still
holds: one dialog per (entry, what), the 90 s wait and exit 75, the 30 min
helper, the outcomes, fixed templates and verification on save; see
modules/ux.md and modules/daemon.md "Dialogs".)

`popup.py` is the only way to ask the user anything.

- Kinds: `consent(entry, changes)`, `secret(entry, what, verify)`,
  `choice(entry, question, options)`, `signin(entry)` (opens browser /
  device code page), `hostkey(entry, old, new)`.
- One pop-up per (entry, what) across all processes: `private/pending/`
  holds a lock + state file. A second requester waits on the same one.
- The requesting process prints to stderr, when the helper opens a dialog
  (a job that needs none prints nothing), e.g. `gateway: waiting
  for the example sudo password in a pop-up on your screen`, waits at
  most 90 s, then exits with code 75 (EX_TEMPFAIL) and the message
  `gateway: the pop-up for example is still open; tell the user once and
  carry on with other work. Retry after they answer.` A detached helper
  (double fork, own session) keeps the pop-up open up to 30 min and stores
  the answer when given.
- Outcomes are distinct: `ok`, `cancelled` (user pressed Cancel; don't ask
  again for the same change in this session unless the user asks), `timeout`
  (nobody answered), `unavailable` (no screen). dialog.py maps exit codes:
  osascript `-128` / zenity `1` = cancelled, other non-zero = unavailable.
  GUI detection: macOS needs a console user session and no `SSH_CONNECTION`;
  Linux needs `DISPLAY`/`WAYLAND_DISPLAY` and a working `xset q`/`zenity
  --version`.
- Templates are fixed; entry names and addresses are validated before
  rendering; Claude-written free text (notes) is never shown in a pop-up.
- Secret pop-ups say what the secret is, for which user@address:port, the
  host-key fingerprint, and that Claude never sees it. Consent pop-ups list
  each widening line. Default button: Cancel for consent and hostkey;
  "Save" for a secret.
- `unavailable`: the gateway writes a pending request and the hook layer
  shows the user (systemMessage, which the model can't alter) the fixed
  command `~/.config/gateway/gate secret NAME` with its one-time code, from
  PostToolUse, PostToolUseFailure (a failing `gate check` shows it with the
  failure), UserPromptSubmit and SessionStart; Claude is told the gateway
  shows it (not that it was shown). `gate secret` refuses to run
  without a real TTY, when `CLAUDECODE=1` (or another Claude Code session
  variable) is set, or when its process tree says it was started from
  Claude Code (section 15: any ancestor whose executable is Claude Code's,
  or `CLAUDE_PID`, or a tree it can't read), reads with getpass, and handles
  consent and device-code sign-in in the terminal too. The terminal path of
  export, import and copy-to (section 16) counts the same things as "inside
  Claude Code".
- Verification on save: sudo `sudo -k; sudo -S -v` (local) or the remote
  staging test; ssh test login; GitHub `GET /user` login match and SSO
  check for owners; Entra refresh. Failure re-asks in the same pop-up
  (max 3), never stores a failing value.
- A credential rejected later is marked `stale`, never retried, and one
  re-entry pop-up opens; the command fails with `gateway: the saved sudo
  password for example was rejected; a pop-up is open; don't retry` (or,
  when no pop-up can open, the terminal command the user was shown; or that
  the user cancelled the re-entry pop-up earlier). A rejected account token
  (git's `erase` after a 401, the http tool, gh, hf, `gate with`) opens no
  pop-up by itself: the command says `gateway: NAME's token was rejected;
  don't retry. Run gate check NAME while the user is here to enter a new one`
  (round 4: the old text claimed an open pop-up), and `gate check` asks for a
  new token since a stale one counts as missing.

## 7. Claude's environment (SessionStart)

> **0.11.0** (PLAN-0.11 §1.2, §1.8): the env file puts `$DATA/bin` first and, in Claude's shell, unsets Claude Code's own credential variables and the stand-in names' aliases and functions; it no longer sets `GIT_SSH_COMMAND` or `RSYNC_RSH`, injects the git include, or unsets the user's own variables. Only the stand-ins that can reach something configured are written.

`hooks/hooks.json` SessionStart runs two hooks:

1. **sync** (exec form, timeout 20): `launch.sh hook-session`. Must finish
   fast with system Python if the env isn't built: it is the sh launcher
   that writes the env file (no Python needed) and, if the pixi env is
   ready, the Python part that adds context. Before starting Python,
   launch.sh writes the env file (`others = "refuse"`) and, when missing,
   the stand-ins and the git reset, so a hook Claude Code cancels or kills
   still leaves Claude's commands on the stand-ins without the user's agent
   and tokens. Steps: migrate if needed
   (offline), validate the form, write `$CLAUDE_ENV_FILE` (replaced whole) and
   `~/.config/gateway/env.sh`, regenerate `$DATA/bin` and `$DATA/git/config`,
   write `~/.config/gateway/gate` (launch.sh writes the same bytes while the
   env builds, so no-screen messages work from the first session), print
   `additionalContext` (section 13) and
   a `systemMessage` for anything the user must know (migration report, form
   errors, pending pop-ups with the one-time code of a no-screen request,
   security events, pixi missing, env building). It also returns
   `watchPaths: [gateway.toml]` (section 12, FileChanged) and writes the
   session record `private/sessions/<session>.env` once (its mtime is the
   session start; Claude Code's display variables for pop-ups). Every file
   it writes is written whole (a temp file renamed or linked in place), so a
   killed hook leaves each file old, new or absent, and the next session
   writes them all again. When it finishes past the timeout (less a second,
   timed from the hook process's start) it leaves the session with no
   context record, so the next prompt's hook gives the context (section
   12).
2. **async** (`async: true`, timeout 900): `launch.sh ensure-env` builds the
   pixi env if needed (copies pixi.toml + pixi.lock into
   `$DATA/envs/<sha12>/`, `pixi install --locked`; PLAN-v4 phase 1: the
   build lock records its owner and goes stale as soon as the owner dies),
   loads a new env once
   (`gateway/warm.py`: every gateway module, `age --version`, `ssh -V`;
   marked `.warm`: on macOS the first load of each new binary and library
   is slow, 5-6 s for the whole env, which the sync hook would pay
   otherwise), then removes env dirs older than the current one and unused
   for 7 days.

Env file content (static, idempotent, `set -u` and `set -e` safe, POSIX;
three comment lines first):

```sh
GW_BIN='/…/plugins/data/gate-gateway/bin'
if [ -d "$GW_BIN" ]; then
  case ":${PATH-}:" in *":$GW_BIN:"*) ;; *) PATH="$GW_BIN${PATH:+:$PATH}"; export PATH;; esac
  if [ "${GW_GITCFG_SET-}" != 1 ]; then
    GW_GITCFG_SET=1; export GW_GITCFG_SET
    _n=${GIT_CONFIG_COUNT:-0}
    export GIT_CONFIG_KEY_$_n=include.path GIT_CONFIG_VALUE_$_n='/…/git/config'
    GIT_CONFIG_COUNT=$((_n+1)); export GIT_CONFIG_COUNT; unset _n
  fi
  GIT_SSH_COMMAND='/…/bin/ssh'; RSYNC_RSH='/…/bin/ssh'; export GIT_SSH_COMMAND RSYNC_RSH
  unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS SSH_ASKPASS_REQUIRE GIT_ASKPASS GITHUB_TOKEN GH_TOKEN … # others = refuse only
fi
```

`~/.config/gateway/env.sh` holds the same text for other launchers: the
user's terminal, and checkpoint jobs (a launcher that sources it before the
job's command gives the job the stand-ins, the git include and the gateway's
ssh, and drops the user's agent and token variables). Everything after
`GW_BIN=` runs only while the stand-in folder exists, so after an uninstall
(or with the data folder deleted) env.sh changes nothing: no PATH entry to a
missing folder, no `GIT_SSH_COMMAND` to a missing ssh, the user's agent and
tokens left alone. Nothing in it assumes Claude's Bash (no `CLAUDE_PID`, no
`return` or `exit`); sourced twice it changes nothing more (bash, zsh, dash,
sh).

The env file changes where commands are found and which credential
variables they see, never how they end: no EXIT trap (round 3 added one
that made every failed command exit 0 with `Exit code N` printed; rolled
back, DECISIONS "Rolled back"). A failed command exits with its own code,
so Claude Code hands its output to PostToolUseFailure, which no hook can
mask; the gateway warns there (section 12; known limit).

`$DATA/bin` holds tiny POSIX sh stubs, regenerated every session with
absolute paths baked in:

```sh
#!/bin/sh
exec '/…/envs/<sha>/.pixi/envs/default/bin/python3' -I -S '/…/run.py' shim ssh "$@"
```

(`run.py` inserts its own `src/` path; `-I` ignores PYTHONPATH and cwd.)
Stand-ins: `sudo ssh scp sftp gh hf databricks crane pijul asiml az gate`
plus `git-credential-gateway` and `gate-askpass`. `git` is added only if the
system has no git (then pixi's git, with git-lfs). If the env isn't built
yet, stubs print what is going on and exit 75, except `sudo`, which then
execs the real sudo: `gateway: still setting up (first run); try again in a
minute` while it builds; that pixi isn't installed (with https://pixi.sh and
"start a new session") or that the build failed (with its log; retried at
the next session start) otherwise; Claude's context says the same. The
launcher (`~/.config/gateway/gate`, the user's own helper) says it to the
user instead, by the same three states (`envfile.launcher_text(state)`:
"pixi isn't installed ... start a new Claude Code session", "setup failed
(log: ...); start a new Claude Code session to retry"; round 4). While an
update's env builds (a new `pixi.lock`), the newest older finished env runs
everything meanwhile: launch.sh runs the hooks and the MCP server on it, and
the stubs Python writes then fall back to it until the new one is ready.

## 8. Approval hook (PreToolUse, Bash|Monitor|mcp__terminal__run_in_terminal|mcp__plugin_check_jobs__job_start)

> **0.11.0** (PLAN-0.11 §1.7, §2, §3, §6.5; lead decisions 1, 3, 10): every value is read in the payload's `permission_mode`, and the allow step needs the effective word `allow` in that mode (a bare `true`: auto and bypassPermissions). A target the configured set doesn't name gets no decision. The curl/wget refusal is gone: network commands are one class ([modules/network.md](modules/network.md)), asked about by default, and any hit keeps the allow off the whole command unless `[network] commands` allows in that mode. The route checks refuse only what reaches a configured target, in every mode, and the hidden-command rule refuses a hidden command that names one ([modules/managed.md](modules/managed.md#alternate-routes)); an "ask" holds only with the hook's record of the exact command (lead decision 14, `asks.py`); program names are compared without letter case; su, doas, pkexec, runuser, sudoedit and osascript's admin form are denied while this computer's sudo is configured; git's remote commands in a configured repository are judged up front. The gateway's own job_start and terminal_send are judged here too. The current rules: [modules/sudo.md](modules/sudo.md).

`hooks/pre_bash.sh` (sh): if the payload (without its own `transcript_path`
field) contains none of `sudo ssh scp sftp rsync curl wget gate gateway age
credential GIT_TRACE_REDACT key.txt claude jsonl az` as words, exit 0 with no
output (Monitor calls and `run_in_background` calls too: the same list).
Otherwise run the env python on `hook-bash` (fail open: errors = no
output). `bashparse.py` is conservative: it splits a command into list
segments (`;`, `&&`, `||`, newline) and pipeline stages (a newline right
after `|`, `&&` or `||` continues, as in bash; an unquoted `#` starting a word
starts a comment to the end of the line, as in bash and zsh `-c`, so the words
judged are the words the shell runs), and gives up
(no decision) on `$(`, backticks, `<(`, `>(`, heredocs, `eval`, `exec`,
`source`/`.`, functions, subshells, `sh|bash|zsh -c`, backgrounding `&`,
redirections other than `>`/`>>`/`2>&1`/`2>/dev/null` to plain files, and
any assignment prefix other than `GATE_ACCOUNT=NAME`.

Rights for deny and ask are the stricter of the form's and the effective
one (round 3): `false` in the form denies (`... is off for NAME`); a right
the form gives but the user hasn't approved yet (the effective right is off:
a widening waiting, a brand-new host, a jump host not set up) is denied with
`gateway: ssh on NAME waits for the user's OK; run gate check NAME while the
user is here` (or `... it goes through JUMP, which isn't set up yet; run gate
check JUMP, then gate check NAME`); `"ask"` in the form or in effect asks.
The stand-ins give an effective `"ask"` right to a command Claude typed,
trusting this hook asked, so an approved `"ask"` edited to `true` must keep
asking until the user's OK. `gate check|rotate|copy-to` go by the form's
`false` (gate check is how a waiting widening gets approved) and ask on
either `"ask"`.

Decision, in order:

1. **deny** `curl`/`wget` in command position (any segment), also behind a
   wrapper (`command`, `builtin`, `busybox`, `env`, `nohup`, `nice`,
   `timeout`, `xargs`, `sudo`, ...): reason `gateway: use the http tool (or
   download / WebFetch) instead of curl; it adds account keys and needs no
   prompt`. Never rewrite. Also **deny** `az … get-access-token` as Claude's
   own Bash or Monitor command (the az stand-in gives tokens only to
   programs, section 9.5; not in the user's Terminal panel, whose az is the
   user's own). Also **deny** `gate export|import|copy-to` in the user's
   Terminal panel and in a job (section 15). (The `gate secret` rule went
   with its stub in 0.11.0.)
2. **deny** any segment that reads or names `~/.config/gateway/private`
   (resolved), `key.txt`/`vault.age` there, or runs `age -d` on them, or
   runs `git credential`, the helper or askpass directly, or sets
   `GIT_TRACE_REDACT=0|false`; also any segment naming a Claude Code session
   transcript (any `.jsonl` under `<config>/projects/`, subagents' included, which can hold the one-time
   codes of section 6) or running a recursive reader on a folder that holds
   them. A Workflow run's journal is not a transcript (section 12, file
   guard): `cat`/`tail`/`grep` of it go on; a recursive reader on its run
   folder (which holds the run's agent transcripts) is denied.
3. **deny** a gateway verb whose target right is `false`: `gateway: sudo is
   off for builder (gateway.toml); ask the user if it should be on` (or
   waits for the user's OK, above). The verb
   is found behind exec-style wrappers (`env`, `nohup`, `nice`, `command`,
   ...) and shell reserved words (`if`, `then`, `do`, ...); a host word
   resolves as the ssh stand-in resolves it (name in any case, `gw-NAME`,
   address). Remote sudo counts as the remote host's sudo right: `sudo` in
   command position in what the remote runs (ssh's command, rsync's
   `--rsync-path`, or a scp / rsync remote path, which old rsync and `scp -O`
   hand to the remote shell) is denied when that host's sudo is `false`.
   Also denied: git's `--upload-pack` / `--receive-pack` / `--exec` /
   `clone -u` / `-c remote.*.uploadpack|receivepack=` with a sudo word (run
   `ssh HOST sudo CMD` instead), and `sftp -s` (a server path runs that
   command on the host).
4. **ask** if any gateway verb's target right is `"ask"` (ssh, local sudo,
   or the remote host's sudo for a remote command with a sudo word; the
   reason names the host and right). The stand-ins give an `"ask"` right
   only to a command Claude typed (sections 9 and 10), relying on this prompt. So:
   - scp, sftp and rsync on an `"ask"` right (ssh to the host, or remote sudo
     they would start there) are **denied**, with the way to do it (`ssh HOST
     CMD` as its own command, or ask the user to set the right to `true`):
     they start ssh themselves, which Claude Code can't ask about, and the
     stand-in would refuse after the prompt. In the user's Terminal panel (no
     stand-ins) they are asked about.
   - A command that hides how it calls the stand-ins (bashparse gives up; a
     stage runs a shell, `eval` or `exec` behind a wrapper; a loop or `case`;
     a verb with a target in a variable) is asked about when its text, quotes
     removed, names a host with an `"ask"` right next to an ssh-family or
     git word (or a sudo word for sudo `"ask"`), or has a sudo word while
     localhost sudo is `"ask"`. Known limit: a script sourced or exec'd into
     Claude's own shell (`source x.sh`) runs as Claude's shell, and its text
     isn't read.
5. **allow** (only when `permission_mode` is `auto` or `bypassPermissions`)
   if every segment runs its program by a bare name (round 3: `./ssh`,
   `/tmp/x/cat` or `bin/gate` run whatever file is there, not the stand-in
   or tool PATH finds, so a path-qualified command is never vouched for; the
   denies still go by the basename) and is either
   - `sudo [opts] CMD…` with right true for localhost, where opts are only
     `-u USER`, `-g GROUP`, `-H`, `-E` is refused, `-S`/`-A` refused, `-n`
     tolerated, and CMD is not in the small destructive list (`rm` with `-r`
     and a target of `/`, `~`, `$HOME` or a top-level system dir; `mkfs*`;
     `dd … of=/dev/*`; `chmod -R`/`chown -R` on `/`; `shutdown`, `reboot`,
     `halt`, `poweroff`; `passwd`; editing `/etc/sudoers*`, by a path or
     with the editors that take none: `visudo`, and `vipw`/`vigr` for the
     user and group databases);
   - `ssh [safe opts] TARGET [CMD…]` / `scp` / `sftp` / `rsync` where every
     remote target resolves to a form host with the right true (and, for
     remote sudo, the host's sudo right true), and no option outside the safe
     set (`-p PORT`, `-l USER`, `-t`, `-T`, `-q`, `-v`, `-C`, `-N`, `-L`,
     `-D`, `-4`, `-6`, `-o ConnectTimeout=`, `-o ServerAliveInterval=`,
     `-o BatchMode=`, `-r`, `-P` for scp). `-R`, `-w`, `-A`, `-J`, `-F`,
     `-i`, `-S`, `-W`, `-o ProxyCommand|LocalCommand|PermitLocalCommand|
     KnownHostsCommand|IdentityAgent|IdentityFile|ForwardAgent|RemoteForward|
     Include|Match` → no decision (and the stand-in refuses most of them
     anyway). scp, sftp and rsync, in addition:
     - rsync options only from an allowlist of ordinary flags (`-a -v -z -h
       -P -n -c -u -r -l -t -p -o -g -D -H -x -s -R -b -i -m`, `--delete*`,
       `--exclude`, `--include`, `--progress`, `--partial`, `--no-*`, ...),
       with a value-taking short option taking the rest of its cluster or the
       next word (so `-ave CMD` is `-e`); never `-e`/`--rsh`, `--rsync-path`
       other than `sudo rsync`, `-M`/`--remote-option`, `--log-file`,
       `--write-batch`, `--only-write-batch`, `--read-batch`, `--daemon`,
       `--config`, `--remove-source-files`, `--old-args`, `--temp-dir`,
       `--partial-dir`, `--backup-dir`, `--suffix`, `--files-from`,
       `--filter`, `--*-dest`, `-K`, or an unknown option;
     - every remote path plain (letters, digits, `._/~@%+=,:^-`: no shell
       metacharacter, space or glob);
     - a download names what it copies: not a folder's contents (a trailing
       `/`, `.`, no path, a bare `~`) and nothing hidden in the remote path;
     - every local operand (source or destination; sftp's implicit `.`) in
       the project (the working directory, not the home folder or above),
       `~/Downloads` or a temp folder, by the download tool's rules (section
       14): no hidden part as written or resolved, nothing in `~/.ssh`,
       `~/.config`, `~/.claude`, the Claude config folder, `~/Library` or the
       gateway's folders, no file Python runs at startup;
     - sftp only as the first stage of its pipeline (it would read commands,
       `!cmd` among them, from a pipe);
   - `gate status|check|login|rotate|why|log|export|import|copy-to|migrate …`
     (never `gate forget`, 0.10.0: it deletes stored secrets)
     (`rotate` and `copy-to` only to a host whose effective ssh right is
     `true`; `gate check|rotate|copy-to HOST` log in with Claude's key, so
     they are denied when the host's ssh is `false` and asked about when it
     is `"ask"`, like ssh; the helpers behind them refuse an `"ask"` host
     unless the user is present: a pop-up job or this typed command);
   - `gate scrub` (a filter that only masks; optional, section 11);
   - a plain command from the read-only/benign set: `cd`, `pwd`, `echo`,
     `printf`, `true`, `test`/`[`, `ls`, `cat FILE`, `head`, `tail`, `wc`,
     `grep`, `sort`, `uniq`, `date` (only `+FORMAT` and display options:
     never `-s`/`--set`, `-f`/`--file` or a BSD clock-setting operand),
     `sleep N` (N ≤ 5). Since 0.10.0 the ones that read (`pwd`, `test`/`[`,
     `ls`, `cat`, `head`, `tail`, `wc`, `grep`, `sort`, `uniq`) qualify only
     when everything they may read is a plain file of the project or a temp
     folder: no hidden or credential-like name, nothing in a credential
     folder, not under a wrapper's `env -C` or `sudo -D`, a recursive grep's
     whole tree included; the same under sudo (docs/dev/modules/sudo.md,
     hooks_bash.py, step 5).
6. Otherwise no decision: Claude Code's mode decides (auto mode's
   classifier, or the normal prompt).

In default/acceptEdits/plan modes the hook still denies and asks as above
but never allows. For `mcp__terminal__run_in_terminal` (the user's own
Terminal panel: their login shell, the real sudo and their own ssh keys, no
stand-ins) it denies and asks the same way and never allows; since an
interactive zsh without `INTERACTIVE_COMMENTS` runs `#…` as words, a command
there with a `#` is also judged with `#` read as an ordinary character.

`gate with NAME -- CMD` never gets `allow` (it runs arbitrary code with a
key); the classifier judges it.

**Checkpoint jobs.** The checkpoint plugin's `job_start`
(`mcp__plugin_check_jobs__job_start`: input `command`, a shell string, or
`argv`, a list; checkpoint runs `/bin/sh -c WRAPPER checkpoint-job-ID CMD
EXITFILE ENVFILE STATUSFILE` with `CMD` = `command` or `shlex.join(argv)`,
detached, from its MCP server; the wrapper sources ENVFILE, the gateway's
env.sh, first and applies it only if that is silent on stderr, so env.sh
never writes to stderr) is in the same matcher and goes through `pre_bash.sh` (the
payload's JSON text holds the command or the argv words; the tool name holds
no trigger word). The hook judges `command`, or `argv` shlex-joined (both,
if both come), like a Bash command, with these differences:

- an `"ask"` right (in any of the forms above: a verb, scp/sftp/rsync, a
  hidden verb, gate check/rotate) is **denied**: `gateway: a job can't use
  the "ask" right for ssh on HOST (nobody can be asked while it runs); run
  it with the Bash tool as its own command, or ask the user to set it to
  true.` (the stand-ins refuse `"ask"` to a job anyway, section 10, in the
  same words);
- `gate export|import|copy-to` are denied as in the Terminal panel (without
  a screen they ask for the user's one-time code in a terminal, which a job
  doesn't have; a job that outlives Claude's process tree escapes `gate`'s
  Claude-ancestor check);
- it **never answers `allow` or `ask`**: Claude Code's own permission check
  decides (a prompt in default mode, the classifier in auto mode);
- relative paths are resolved from the job's `cwd` (absolute, or relative
  to the session's cwd and `CLAUDE_PROJECT_DIR`), or, without one, from the
  session's cwd and `CLAUDE_PROJECT_DIR` (checkpoint's default); a word
  protected from any candidate is denied.

The matcher only fires when checkpoint is installed; the other job tools
(`job_status`, `job_tail`, `job_stop`) aren't judged. What they return (a
job's log from `job_tail`, its last lines from `job_stop`, its record from
`job_status`) passes the output hooks like Bash output (section 12;
integration review: a job's `cat notes.txt` came back raw through
`job_tail` before). Known limit: a `job_stop` that fails (`stop_failed`, an
MCP error result carrying the last log lines) goes to PostToolUseFailure,
which only warns, like a failed Bash command; the log file itself stays raw
on disk (a Read of it is masked).

**Monitor and background commands** are judged like any other Bash command
(the same denies, asks and allows; nothing more). Round 3 denied a Monitor
command unless it ended in `| gate scrub`, and round 4 a `run_in_background`
command unless it ended in `2>&1 | gate scrub`; both are rolled back
(DECISIONS, "Rolled back"): the gateway doesn't change how Claude's
ordinary commands run. Known limits: each stdout line of a Monitor command
reaches Claude as an event no hook sees (PostToolUse gets only the task id;
Monitor's `ws` source too), and Claude Code may quote the raw last 1 KB of a
background task's output file (stdout and stderr) to Claude in a
`<task-notification>` (section 1), which no output hook sees; the task file
itself stays raw. `gate scrub` (section 11) is an optional filter Claude
may pipe such output through (the SKILL says when); the prompt hook holds
back a task notification that quotes a stored value or a token shape
(section 12, UserPromptSubmit (d)).

Every decision reason starts with `gateway:` and says what to do next.

## 9. Stand-ins

> **0.11.0** (PLAN-0.11 §1.2-§1.5, §6): a stand-in exists only for a tool that can reach something configured (`envfile.standins_for`), and git and az are stand-ins too. A stand-in classifies its target first: configured goes through the gateway; unconfigured execs the user's own tool (`envfile.user_tool`: PATH minus every stand-in folder) with the full argv and environment unchanged, guarded against loops; a configured host reached by another name (`ssh -G`, a hop, a ProxyCommand, an IP) is refused with the name to use. Per-mode values use the session's recorded mode for a command Claude typed, else the modeless rule. Current behaviour: the module docs.

All stand-ins: read the form (cached by mtime) and vault under the lock
only when they need a secret; check the target right (`false` → refuse,
`"ask"` unless the stand-in was started by a command Claude typed (section
10: `typed_by_claude`; Claude Code can only prompt for that command, so a
program starting ssh or sudo itself, such as git, rsync, scp, sftp, make, a
script or `sh -c`, is refused) → refuse with `run it as its own command so
Claude Code can ask you`, or, under checkpoint's job runner (section 10),
with the approval hook's job wording `gateway: a job can't use the "ask"
right for ssh on HOST (nobody can be asked while it runs); run it with the
Bash tool as its own command, or ask the user to set it to true.`); check
ancestry (section 10); write one audit
line per credential use (tool, target, account, argv summary, session id
from `CLAUDE_CODE_SESSION_ID`, cwd); resolve real binaries by absolute path
(pixi env for ssh/scp/sftp/ssh-agent/ssh-add/gh/git-lfs/age; `/usr/bin/sudo`
checked root-owned + setuid; system git); build the child env from an
allowlist plus what the tool needs (v2 `runner.ENV_ALLOW`), forcing endpoint
variables and dropping proxy/CA overrides unless the form allows them
(it doesn't, in v3.0).

### 9.1 sudo (localhost)

> **0.11.0**: present only while `[hosts.localhost] sudo` or an elevation restriction configures this computer's sudo; with a restriction only, its deny refuses, its ask needs a typed command, otherwise the user's sudo runs. [modules/sudo.md](modules/sudo.md).

1. Right false → `gateway: sudo is off on this machine`, or, when the form
   turns it on and the change waits for the user's OK, `gateway: sudo on this
   machine waits for the user's OK; run gate check localhost while the user is
   here` (the ssh stand-in says the same for ssh and remote sudo). `"ask"`
   handled by the hook; not typed by Claude (section 10) → refuse, whatever
   `scripts` says.
2. `-S` or `-A` given → refuse. Strip `-n` only if a password can be given.
3. Probe `/usr/bin/sudo -n true` (cached 10 min per user in the run dir):
   success → `exec /usr/bin/sudo "$@"` (nothing stored, nothing asked).
4. Password from `localhost.sudo[USER]` (vault); none → `secret` pop-up
   (with verification); stale → refuse with the rejection message.
5. One-shot askpass: a 0700 dir in the run dir with a FIFO; a writer thread
   opens it non-blocking (retry loop up to the command's lifetime), writes
   the password once, **unlinks the FIFO immediately after the first
   write**; `gate-askpass` reads the FIFO path from `GW_ASKPASS_FIFO` and
   exits 1 if it's gone; it opens it non-blocking and gives up (exit 1) when
   no writer has sent the password within 60 s (round 3: a stand-in killed by
   a Bash timeout left the askpass and sudo hanging forever). Run `/usr/bin/sudo -A "$@"` with `SUDO_ASKPASS`
   and `GW_ASKPASS_FIFO` set, inherited stdio, forward signals, wait, clean
   up, exit with sudo's code. If sudo printed `Sorry, try again` /
   `incorrect password`, mark the password stale (no retries).
6. `gate-askpass` refuses when its parent is not the real sudo, when euid
   is 0, or when `SUDO_COMMAND`/`SUDO_USER` is set. The real sudo is
   `/usr/bin/sudo`, or NixOS's `/run/wrappers/bin/sudo`, root-owned and
   setuid; the parent is matched by its resolved executable path. On Linux a
   setuid-root process's `/proc/PID/exe` can't be read by its user, so there
   the parent counts when `/proc/PID/status` shows effective uid 0 and the
   name `sudo`, and its own parent is the stand-in that made the askpass
   folder (its pid in the folder's `owner` file).

### 9.2 ssh family

> **0.11.0**: a lenient parse and the user's own `ssh -G`, hops, ProxyCommand and resolved IPs classify the target before anything below; an unknown host passes through instead of being refused; scp and sftp classify each operand (a mix is refused); rsync is no stand-in (it starts `ssh` through PATH). [modules/ssh.md](modules/ssh.md).

Target resolution: `ssh -G -F <generated config> "$@"` (8 ms) gives the
host name ssh would use; the stand-in maps it to (a) a form host (by name,
`address`, `also`, or `user@address`), (b) an account ssh endpoint (`git@
github.com`, `git@hf.co`, a GHES host, `nest.pijul.com`), or (c) unknown →
`others = refuse`: `gateway: X isn't in gateway.toml. Did you mean
example? To add it, ask the user (Claude can import it from
~/.ssh/config)` (the suggestion is a close spelling of a host's name or DNS
address; an IP address only when it is one of a host's addresses; for
github.com, hf.co and nest.pijul.com the message asks for an account of that
kind instead); `others = mine`: exec the system ssh unchanged.

- Refused options (the stand-in exits 2 with a reason): `-F`, `-i`, `-S`,
  `-A`, `-o` keys that change identity, known hosts, proxying, agent or
  local commands (same list as section 8). `-J` → use `via` in the form.
  sftp `-s` (a subsystem or server path: a path runs that command on the
  host) is refused too.
- Generated config per call in the run dir (reuse `sshconf.write_config`):
  `Host gw-NAME` blocks for the chain, `HostName`/`Port`/`User` from the
  chosen address, `HostKeyAlias gw-NAME`, `UserKnownHostsFile` with the
  pinned keys, `StrictHostKeyChecking yes`, `CheckHostIP no`,
  `UpdateHostKeys no`, `BatchMode yes`, `PasswordAuthentication no`,
  `KbdInteractiveAuthentication no`, `IdentitiesOnly yes`, `IdentityAgent`
  (private agent socket), `IdentityFile` = each non-retired public key,
  `ForwardAgent no`, `ForwardX11 no`, `PermitLocalCommand no`,
  `ControlMaster auto`, `ControlPath /tmp/gw-$UID/cm-%C`,
  `ControlPersist 120`, `ServerAliveInterval 30`, `ConnectTimeout 10`;
  `via` as `ProxyJump gw-JUMP` resolved with the same `-F`; final
  `Host *` with no identity and an empty known_hosts.
- Address choice: probe `address` (if its `when` matches) and `also`
  candidates in parallel with a 1 s TCP connect + SSH banner check; pick the
  first in list order that answered; cache per (host, network fingerprint
  = default route interface addresses) for 5 min in the run dir. A
  non-last candidate whose host key mismatches the pin is skipped silently
  (logged); the last candidate's mismatch → hostkey pop-up.
- Agent: started per invocation only when no live master exists
  (`ssh -O check`); keys loaded with `ssh-add -` from stdin and lifetime
  `-t 300`; killed once the call's own master is up (only a call holding
  the target's lock, below), else when its ssh ends. Never exported to
  Claude's env, never forwarded.
- One master per ControlPath: with no live master, the stand-in (and the
  gate process's own ssh calls, such as copy-to's) takes an `fcntl.flock`
  on `<run>/cm-%C.lock` (each master of the chain, sorted), checks again,
  and holds the lock until its master answers or ssh exits, so a parallel
  call to the same host (checkpoint jobs) waits and reuses that master
  instead of racing it (OpenSSH's `ControlSocket ... already exists,
  disabling multiplexing` in the output). The wait is bounded (5 s in
  all); then the call goes on without the lock, reaching each hop it
  couldn't lock without multiplexing (`ControlMaster no`, `ControlPath
  none` for that hop), so only a lock holder ever starts a master there
  and the master a holder sees is its own. scp/sftp (`ControlMaster=no`)
  wait but don't keep the lock, and then reach every hop on their own.
- Failures: auth failure → `gateway: example refused Claude's key
  (installed? run gate check example)`, and the host's `installed` mark is
  dropped (status stops saying "key installed"; the next `gate check`
  installs the key again); never retry auth; a
  `kex_exchange_identification`/reset right after an auth failure →
  `gateway: example is rate-limiting after failed logins; wait a minute`
  (not a failover trigger). No command and no `-N` → refuse at once: `pass
  a command; interactive ssh can't work here`.
- `scp`/`sftp` stand-ins exec the pixi scp/sftp with `-S <bin/ssh>` (they
  ignore PATH ssh); `rsync` picks up the ssh stand-in via `RSYNC_RSH`.
- Masters are closed (`-O exit`) when a host's address, via, ssh right,
  keys or host keys change (the form loader and `gate` do this).

### 9.3 Remote sudo

Applies when the host's sudo right is true (or `"ask"` for a command Claude
typed, section 10) and the remote command has `sudo` (or `sudoedit`, also by path) in command
position (scripts = false) or anywhere (scripts = true). `sudo` in command
position with sudo `false` is refused; a `sudo` word elsewhere just gets no
password.

1. Probe once per (host, user) per 10 min over the master:
   `sudo -n true`; success → run the command untouched.
2. Else take `hosts[X].sudo[USER]` (pop-up if missing, verified with the
   staging test; passwords under 8 characters are refused, the scrubber
   couldn't hide them). Staging call over the master, password on stdin:
   ```sh
   umask 077; d=$(mktemp -d "${XDG_RUNTIME_DIR:-/dev/shm}/gw.XXXXXX" 2>/dev/null || mktemp -d /tmp/gw.XXXXXX)
   IFS= read -r p; printf '%s\n' "$p" > "$d/p"; unset p
   cat > "$d/a" <<'EOF'
   ... the askpass: absolute paths only; answers only a parent that runs as
   root (real sudo is setuid), once per sudo process ($PPID marker), at most
   6 times per call, never again after a sudo process asked twice (the
   `rejected` marker); then `exec /bin/cat "$d/p"`
   EOF
   chmod 700 "$d/a"; (sleep 900; rm -rf "$d") >/dev/null 2>&1 &
   echo "$d"
   ```
3. A saved password not verified in the last 10 minutes is verified first
   (`sudo -k -A -v`, one attempt); a rejection marks it stale and the
   command doesn't run.
4. Run the user's command with the askpass scoped to it: scripts = false →
   a shell function `sudo() { SUDO_ASKPASS="$d/a" DISPLAY="${DISPLAY:-gw:0}"
   command sudo "$@"; }; <command>` (nothing exported to the programs the
   command starts); scripts = true → `export SUDO_ASKPASS="$d/a"; [ -n
   "${DISPLAY-}" ] || export DISPLAY=gw:0; <command>` (sudo uses the askpass
   by itself with no tty when SUDO_ASKPASS and DISPLAY are set, so nested
   sudo in scripts works).
5. Afterwards `rm -rf "$d"` over the master; ssh output for this call is
   piped through the scrubber (the password is in the scrub set).
6. Stale only on the askpass's `rejected` marker or a failed verification,
   never on text in the command's own stderr (the command controls it).
7. Setup checks the remote login shell is POSIX (`sh -c 'echo ok'`).

Residual risk (accepted, and said in the sudo pop-ups): while a call runs,
anything running as the login user on the remote, including Claude's own
command, can read the staged password (`$d/p`) and print it transformed past
the scrubber. A stored remote sudo password is therefore within reach of
Claude's commands on that host. (`gate check` used to offer a passwordless
sudoers rule instead; PLAN-v4 phase 7 removed it, since such a rule gives
root to every program running as that user. The user can choose "ask me each
time" with Remember it unticked, so a password is staged only for the call
it was typed for, or an `elevation` policy; section 15.)

### 9.4 git

> **0.11.0** (PLAN-0.11 §6): `git` is a stand-in. In a repository with a configured remote (`gitroute`), and for a configured operand URL, the env's git runs with an allowlisted environment, this include file and `core.sshCommand` at command-line scope, and a read-only `GIT_CONFIG_GLOBAL`; everything else runs the user's git untouched. The include no longer comes from the env file. [modules/accounts.md](modules/accounts.md).

`$DATA/git/config` (regenerated when the form changes; git re-reads it):

```ini
[credential]                        # others = refuse only
	helper =
[credential "https://github.com"]
	helper =
	helper = !'/…/bin/git-credential-gateway'
	useHttpPath = true
[url "https://github.com/"]         # when every account for the host has a token and no ssh key
	insteadOf = git@github.com:
	insteadOf = ssh://git@github.com/
[includeIf "hasconfig:remote.*.url:https://github.com/example-org/**"]
	path = /…/git/identity-github-work
[includeIf "hasconfig:remote.*.url:git@github.com:example-org/**"]
	path = /…/git/identity-github-work
```

(identity files hold `[user] name/email`; verify that `includeIf
hasconfig` works from an env-provided include on the pinned git versions;
if not, fall back to a pre-commit-free approach: the git helper is not
involved in commits, so document the limitation.)

`git-credential-gateway get` answers only when: its parent executable is
`git-remote-http(s)` (or git-lfs's `git credential fill`, i.e. parent `git`
whose parent is `git-lfs`); `protocol=https` (http only for loopback in
tests); `GIT_TRACE_REDACT` isn't `0`/`false`; `GIT_SSL_NO_VERIFY` unset
and `http.sslVerify` not false. It picks the account (section 9.6) from
host + path, refuses if the account's `bound.hosts` lacks the host, and
returns `username` (`x-access-token` for GitHub, else the login) and the
token. `store` is ignored; `erase` marks stale the account whose stored
token equals the rejected password git sends (compared in constant time,
among the github/huggingface accounts bound to that host; round 4: it used to
mark the default account, whatever was rejected), or without a password the
account `get` would choose for that path and `GATE_ACCOUNT`; never one found
by elimination, and an unknown password marks nothing. Unknown host: no answer, stderr naming what exists (`gateway: no
account for gitlab.com. The gateway has accounts for GitHub (also GitHub
Enterprise …), Hugging Face and Pijul; for another git server, use https for
a public repository, or ask the user whether to set others = "mine" …`);
for github.com, hf.co or nest.pijul.com it asks for an account of that kind.

git over ssh to an account endpoint goes through the ssh stand-in
(`GIT_SSH_COMMAND`), which takes the owner from `git-upload-pack
'owner/repo'` and uses that account's ssh key with the endpoint's known
host keys (github.com/hf.co keys built in).

### 9.5 Account CLIs

> **0.11.0** (PLAN-0.11 §1.4): each resolves the destination as the tool would; a covered one takes the gated path below, an uncovered one passes through, one that can't be told uses the account while one of its kind exists. dvc goes to asiml only for pull and push in an asiml workspace.

| stand-in | real binary | credential | refused subcommands |
|---|---|---|---|
| `gh` | pixi gh | `GH_TOKEN` (or `GH_ENTERPRISE_TOKEN`), `GH_HOST`, temp `GH_CONFIG_DIR`, `GH_PROMPT_DISABLED=1`, `GH_BROWSER=false` | `auth token`, `auth status --show-token`, `auth login|logout|refresh|setup-git`, `extension`, aliases starting with `!`, `config set`; a command line naming a host other than the account's (or its bound `api.` host): `--hostname`, `auth -h`, `-R HOST/OWNER/REPO` or a URL, a full-URL `gh api` endpoint, URL or `HOST/OWNER/REPO` arguments (gh sends `GH_ENTERPRISE_TOKEN` to any host but github.com, `GH_TOKEN` to any `*.ghe.com`) |
| `hf` | pixi env `hf` (installed on first use) | `HF_TOKEN`, `HF_ENDPOINT` forced, temp `HF_HOME` token paths, real hub cache | `auth token`, `auth login|logout`, `--token` |
| `databricks` | pixi env `databricks` | Entra token for the workspace as `DATABRICKS_TOKEN`, `DATABRICKS_HOST` = the one listed workspace or the one named by `DATABRICKS_HOST`/`--profile`/`databricks.yml` (must be listed), `DATABRICKS_AUTH_TYPE=pat`, empty config file | `auth token`, `auth login`, `configure` |
| `crane` | pixi env `registry` | per-call `DOCKER_CONFIG` with one auths entry chosen by image owner (ghcr → github account; `*.azurecr.io` → azure exchange, cached; else registry account) | `auth get`, `auth login` |
| `pijul` | `$DATA/pijul/bin/pijul` (conda-forge has none: built on first use in the background with the `pijul` env's Rust, `pixi run -e pijul install-pijul` with `CARGO_INSTALL_ROOT=$DATA/pijul`; the stand-in exits 75 meanwhile) | v2 pijulops: temp HOME with known_hosts, `PIJUL_CONFIG_DIR` with identity.toml, `--config signing_key`, private agent | `identity`, `key`, `client`, `--config` |
| `asiml` | gateway's own implementation (mlcat.py) | catalog API token; SAS passes for dvc | anything outside the surface below |
| `az` | gateway's own minimal az | Entra token, printed as is (an SDK's AzureCliCredential parses it), but only to a program started by Claude's command (not direct) with `scripts = true`: never to Claude's own command (a shell/wrapper chain up to `CLAUDE_PID`, also under Monitor, whose streamed lines PostToolUse never sees; the Bash hook denies it there too), nor when the ancestry can't be read; only for a scope the http tool would use for one of the account's approved, bound destinations (`web.azure_scope`): Resource Manager (default; the legacy `management.core.windows.net` audience gets the ARM scope), Graph, Storage when a storage account is listed (also a listed account's own URL), Databricks when a workspace is listed, `https://SITE/.default` for a listed site | everything except `account get-access-token [--resource R \| --scope S] [--tenant T] [-o json]` and `account show`; any other resource or scope (Key Vault, an `api://` app, an unlisted or not yet approved destination); available only when the azure account has `env` set (opt-in), since tokens then reach programs |

All of them stream output through the scrubber (section 11). hf gets its
token in a 0600 file of the call's 0700 folder (`HF_TOKEN_PATH`), not in
`HF_TOKEN`. Residual (round 3): gh (`GH_TOKEN`/`GH_ENTERPRISE_TOKEN`),
databricks (`DATABRICKS_TOKEN`), dvc under asiml (`AZURE_STORAGE_SAS_TOKEN`)
and `gate with` (its variable) hold the credential in their environment
while they run, and `ps eww` shows a process's environment to every process
of the same user (macOS hides it only for platform binaries); output that
prints it is masked by PostToolUse. Optional pixi
envs are installed on first use with one stderr line (`gateway: first use
of hf: installing (about 54 MB)`), into the current `$DATA/envs/<sha>`.

`asiml` surface: `init datasets/NAME|models/NAME [--data-dir D]`, `clone
NAME[@REV] [DIR]`, `pull [REV]`, `push`, `status`, `search [--kind K]
QUERY`, `show NAME[@VER]`, `files NAME@VER [--prefix P]`. Inside an
`.asiml` workspace, `dvc pull|push` (through a `dvc` stand-in added only
when an ml-catalog account exists) delegate to `asiml pull|push`.

### 9.6 Choosing an account (one algorithm everywhere)

1. `GATE_ACCOUNT=NAME` (or an alias) in the environment: must be the right
   kind and the destination must be in its `bound.hosts`; owners don't
   restrict it.
2. The target owner: git helper path / ssh `owner/repo`; gh `-R/--repo`,
   URL args, `OWNER/NAME` positionals, `api repos|orgs|users/OWNER`, else
   the cwd's upstream remote, else origin; hf first `owner/name`; crane the
   image owner; pijul the remote or `.pijul` default.
3. Candidates: accounts of that kind and host with `use = true` whose
   `login` or `owners` include the owner; else the one with `default =
   true`; else, if exactly one account of that kind+host exists, that one.
4. Exactly one → use it. Several → `gateway: both github-personal and
   github-work fit; set GATE_ACCOUNT=github-work`. None → run without a
   credential and print `gateway: no account for github.com/acme`; when
   usable accounts of that kind and host exist but none fits, name them:
   `gateway: no account is chosen for github.com/acme (github-personal and
   github-work exist; neither lists acme or is the default); set
   GATE_ACCOUNT=NAME, or ask the user to add default = true or owners in
   gateway.toml`.
5. An account whose `login`/`owners` match but that isn't usable (waiting for
   the user's OK, credential not bound, `use = false`) owns those repos: the
   command is refused naming it (`gateway: github-work is the account for
   acme but can't be used yet (it waits for the user's OK); run gate check
   github-work while the user is here`), never handed to the default or the
   only other account. The same for a default account that isn't usable.

### 9.7 `gate with NAME -- CMD`

Only for accounts with `env` set (else refuse). Runs CMD with that variable
set (api-key: the key; huggingface: `HF_TOKEN`; github: `GH_TOKEN`; azure:
not a raw token, see `az`), child env otherwise inherited, output
scrubbed, audit logged. Never hook-allowed. The variable is visible to `ps
eww` of the user's processes while CMD runs (section 9.5's residual). A
rejected token: `gateway: NAME's token was rejected; don't retry. Run gate
check NAME while the user is here to enter a new one`.

## 10. Direct vs scripts (ancestry)

A stand-in supplies a credential only if the caller is direct: walking up
from the stand-in's parent, every process until `CLAUDE_PID` is a shell
(sh, bash, dash, zsh, fish) or one of `env nohup time timeout nice ionice
stdbuf xargs sudo`, or, for ssh/git credentials, `git git-remote-*
git-lfs rsync scp sftp ssh gh`. Executables are identified by path
(`proc_pidpath` via ctypes on macOS, `/proc/PID/exe` on Linux), never by
name. No `CLAUDE_PID` in the env (a user's terminal sourcing env.sh, a
checkpoint job): not direct, except that a process tree rooted at the
checkpoint plugin's job runner counts like Claude's shell (it is
recognized by its command line `…/checkpoint/…/run.py server`).

Not direct and the entry has `scripts = true` → allowed. Otherwise the
stand-in runs the real program without the credential and prints one line:
`gateway: sudo started by make got no password (only Claude's own commands
do); run it as its own command, or set scripts = true for localhost`. When
there is no program to name (no `CLAUDE_PID`, or the walk reached init, as
for a job still running after its session ended; culprit `?`), every
stand-in says `started by a program the gateway can't trace back to Claude
(such as a job still running after its session ended)` instead.

An `"ask"` right is stricter (`ancestry.typed_by_claude`): Claude Code can
only prompt for the command line Claude typed, which is all the approval
hook reads. So the stand-in must have been started by Claude's command shell
(the direct child of `CLAUDE_PID`) or a fork of it (a pipeline stage or
subshell: same executable path and same argv as its parent), with nothing
in between: no wrapper, no git, git-lfs, rsync, scp, sftp or gh, no script
and no `sh -c` shell of its own, never the checkpoint runner (a job runs
`sh -c WRAPPER …` and then `sh -c CMD`, which already fails the fork test;
a `CLAUDE_PID` naming the runner itself is refused explicitly), whatever
`scripts` says. A refusal with checkpoint's runner as the stand-in's parent
or above it has the culprit `checkpoint`, and the stand-ins then give the
job wording (section 8), not "run it as its own command". Exec-style wrappers (`env`, `nohup`) and `bash -c 'simple
command'` leave no trace in the process tree; the approval hook looks
through them (section 8).

## 11. Scrubbing

`scrub.py` provides:

- `Scrubber(secrets)`: a streaming byte filter holding back only the
  longest suffix that is a proper prefix of a secret; masks with `***`. The
  pumps release held-back bytes after 0.15 s without new output (an
  interactive prompt or a protocol byte that happens to start a secret's
  form must never stall the stream); a secret completed after such a release
  is masked from there on, so a value printed with a pause in the middle
  shows only its part before the pause (within the residual risk of 9.3).
  The set: every credential value used by the call (≥ 8 chars), its
  base64, base64 of `user:value`, URL-encoded and JSON-escaped forms (round
  4: a value with `"`, `\`, a control character or non-ASCII text, or a
  multi-line key, differs in a transcript or a JSON output); minted tokens
  too.
  EPIPE closes the read side; signals and exit codes pass through.
- `scrub_text(text)`: the above for all vault values (≥ 8 chars, cached
  set) plus shape patterns (`ghp_`, `gho_`, `ghs_`, `ghu_`, `github_pat_`,
  `hf_`, `glpat-`, `sk-`, `xox[abprs]-`, `AKIA`, JWT `eyJ…\.eyJ…\.`,
  `AGE-SECRET-KEY-1`, `-----BEGIN … PRIVATE KEY-----` blocks,
  `Authorization: (Bearer|Basic) …`).

- `gate scrub` (round 3): a line filter over `scrub_text` (vault values
  in every form, plus the shapes), optional: Claude may pipe output that
  reaches no output hook through it (Monitor's lines, a background
  command's output); no hook requires it (rolled back, section 8). It fails
  closed (a vault it can't read passes nothing through).

Used by every stand-in that passes a token, by remote sudo calls, by the
MCP tools, by the PostToolUse hook (section 12) and by `gate scrub`.

Short sudo passwords (< 8 chars) are not scrubbed by literal (that would
reveal them); they never pass through output paths the gateway controls.

## 12. Other hooks

> **0.11.0** (PLAN-0.11 §9.1, §9.2, §7.2): PostToolUse and PostToolUseFailure match every tool (`.*`), post.sh skipping only tools whose response is fixed text or Claude's own input, and the values of the user's credential variables are masked too; `hooks/tool_guard.sh` denies an AskUserQuestion asking for a secret and the browser-automation tools while a browser sign-in runs.

- **PostToolUse** (matcher `^(Bash|BashOutput|Monitor|Read|Grep|Edit|Write|MultiEdit|mcp__terminal__read_terminal|mcp__plugin_gate_gw__.*|mcp__ccd_session_mgmt__search_session_transcripts|mcp__ccd_session_mgmt__list_events|mcp__plugin_check_jobs__job_tail|mcp__plugin_check_jobs__job_status|mcp__plugin_check_jobs__job_stop)$`):
  `hooks/post.sh` prefilter: once a vault exists, every response runs
  Python (vault values without a token shape, such as sudo passwords,
  prefix-less API keys and refresh tokens, can be in any output, file or
  terminal Claude reads), except an Edit's, Write's or MultiEdit's (round
  5): Claude Code gives Claude no file content for them ("The file X has
  been updated successfully", "File created successfully at: X"; checked in
  Claude Code 2.1.301), so they go by the rules for no vault. An edit tool
  counts only when the payload names `"tool_name"` exactly once (anything
  else goes to Python). Without a vault, only a response matching the shape
  patterns (or, for Edit/Write of `gateway.toml`, the path, or a pending
  notice, or the desktop app's session readers, always). Python imports
  only what the response needs (no pop-up, dialog or form code while
  nothing is pending: about 45 ms instead of 110 ms per call, round 5).
  The sh hooks take the gateway home from the password database (`hooks/home.sh`, as
  `paths.user_home()`), never `$HOME` (round 4: Claude Code started with
  another HOME left stored values unmasked). The session readers' results
  also have one-time codes masked (every live code, and `code NNNN-NNNN`).
  checkpoint's job tools that return a job's log or record (`job_tail`,
  `job_status`, `job_stop`; exact names, so nothing changes without
  checkpoint) are matched too: their result is an MCP content list whose
  text is checkpoint's JSON, and the log in it is masked like Bash output
  (integration review). Python returns `updatedToolOutput` with `scrub_text` applied
  (every vault value in every form, plus the shapes). Known limits: a
  failed Bash command goes to PostToolUseFailure instead (below; the
  gateway doesn't change exit codes, section 7), Monitor's lines and a
  background command's notice reach no output hook (section 8), and an
  edit tool's response (which carries the file's earlier text) stays
  unmasked in the transcript's record of the call (round 5; Claude reads
  neither: Claude Code shows it the one-line result, the file guard denies
  transcripts, and the session readers' results are masked). For Edit/Write of
  the form: validate and return `additionalContext` with the result
  (`gateway: form OK; example: new address needs the user's OK — run gate
  check example`; a narrowing it persisted is named too: `homelab: sudo
  true -> "ask" (applied at once)`), so Claude fixes mistakes in the same
  turn.
- **PostToolUseFailure** (same matcher, same `post.sh`; round 3): a failed
  call's output (`error`) can't be masked (known limit: every Bash command
  that exits non-zero, times out or is killed, and an MCP error result such
  as checkpoint's `job_stop` reporting `stop_failed` with the job's last log
  lines). When it holds a stored secret (in
  any form) or a token shape, `additionalContext` tells Claude never to
  repeat, store or use it; a `systemMessage` tells the user which entry's
  secret it was (never the value) and how to replace it, by kind (round 4):
  a host's ssh key `gate rotate NAME`; a sudo password "change it on that
  machine, then gate forget NAME sudo and gate check NAME"; an account's ssh
  key "remove its public key from the account, then gate forget NAME key and
  gate check NAME"; a token, API key or sign-in "replace it where it comes
  from, then gate login NAME" (gate check alone keeps a stored credential).
  `gate forget` keeps no copy, but older copies of the vault in
  `private/backups` (`gate rotate`'s, an import's backup, the 0.6
  conversion's) may still hold the old secret, encrypted; its output names
  them and how the user deletes them (section 15).
  An audit `leak` event is written. Pending no-screen notices (section 6) are shown here
  too.
- **PreToolUse file guard** (Read|Grep|Glob|Edit|Write|MultiEdit|NotebookEdit),
  `onFailure: "block"`: deny when the resolved path is inside
  `~/.config/gateway/private`, or is the v2 `key.txt`/`store.age`, or the
  run dir, or is a Claude Code session transcript (any `.jsonl` at any depth
  under `<config>/projects/` for the payload's config dir, also when its
  `transcript_path` is a subagent's, `CLAUDE_CONFIG_DIR`, `~/.claude` and
  `~/.config/claude`: hook systemMessages, the one-time codes among them,
  are recorded in `<project>/<session>.jsonl` and, for a subagent's tool
  calls, `<project>/<session>/subagents/agent-<id>.jsonl`), and a Grep from a
  folder that holds any of them (a `projects` folder, a folder above it, or
  any folder inside it but `tool-results/`, which stays readable). One
  exception: a Workflow run's journal, exactly
  `<project>/<session>/subagents/workflows/<run>/journal.jsonl` (that name in
  that case, at that depth; a regular file with one link, so no hard link
  to a transcript; a symlink counts by its target), is readable, also by
  Grep naming the file: Claude Code's Workflow tool tells Claude to read it
  to diagnose a run, and it holds the agents' results, not hook messages. A
  Grep over the run folder stays denied (it holds the run's
  `agent-<id>.jsonl` transcripts). The same
  hook (matcher `^mcp__ccd_session_mgmt__(export_transcript|search_session_transcripts|list_events)$`,
  round 4) denies the desktop app's transcript export always (a zip of raw
  transcripts no hook can mask) and its transcript search and event listing
  while a one-time code is live; launch.sh's degraded guard does the same.
  Nothing else is decided (edits of `gateway.toml` go through
  Claude Code's normal permission flow; in auto mode the classifier's
  self-modification rule applies). Fast path (round 5): launch.sh gives
  no decision without starting Python (about 10 ms instead of 40-60 ms)
  only for a call it can settle in sh, and sends everything else to
  Python: a Read, Edit, Write, MultiEdit or NotebookEdit whose payload names
  `"tool_name"`, `"cwd"` and the path key exactly once each (and neither the
  other path key nor `"path"`), with an absolute path inside cwd made only of
  ASCII letters, digits, space and `. _ / + @ , = -` (no JSON escape), no
  `.` or `..` part, not ending in `.jsonl`, not naming `/.config/gateway`
  or `/tmp/gw-*` / `/private/tmp/gw-*` in any letter case, no symlink, no
  file with more path below it, and nothing that is the same file (`test -ef`) as the gateway home, its
  `private/`, `key.txt`, `store.age` or the test/e2e run dir anywhere along
  it, no symlink inside `private/`, and an existing target a regular file
  with one link. A unit test compares its answer with Python's case by case.
- **UserPromptSubmit** `hooks/prompt.sh`: (a) paste guard: block only
  known token prefixes or a PEM private key block (sh regex; Python only on
  a hit), scrub the transcript/history (v2 scrubber minus the `gate:`
  marker), and tell the user `gateway: that looked like a secret, so it
  wasn't sent; Claude can open a pop-up for it`; (b) if the form's mtime
  changed since the session's last context, add `additionalContext` with
  the new summary (the whole context when the session has no context
  record: its SessionStart was cancelled, section 7); (c) a migration report not shown yet
  (`private/migrated.unshown`): a systemMessage, once; (d) round 4: a
  `<task-notification>` (section 1), sent to Python on every prompt once a
  vault exists (prompt.sh fails closed for it, like the paste guard): one
  holding a stored value in any form (JSON-escaped too) or a token shape is
  blocked (`suppressOriginalPrompt`), its matched forms are overwritten
  (same length) in the transcript and history, and a systemMessage names the
  entry, never the value; an audit `leak` event is written. A notice is not
  the user speaking: it leaves the cancelled pop-up markers alone.
- **SubagentStart**: the same `additionalContext` as SessionStart.
- **FileChanged** on `gateway.toml`: SessionStart returns `watchPaths`
  with the form's absolute path; the FileChanged group has no matcher (a
  matcher would add a watch on a same-named file in the working directory)
  and the hook ignores any other `file_path`. Verified headless on Claude
  Code 2.1.301. Validate; `systemMessage` to the user with errors or with what
  changed (`example: sudo now ask`) since the version the user last saw
  (SessionStart records the form it loaded, so a narrowing PostToolUse
  persisted first is still reported). A deleted form: until it's back only
  this computer's defaults apply (approvals are kept; the next session
  restores the last good version), and the message and `gate status` say so.

## 13. What Claude is told

> **0.11.0** (PLAN-0.11 §1.9): the context says that anything not in gateway.toml uses Claude's own ssh, git, gh and sudo, that network commands are asked about, and (while it isn't configured) that the user's own sudo works only without a password; the checkpoint line appears only while checkpoint is live.

SessionStart/SubagentStart `additionalContext` (≤ 2,500 chars), facts
plus how-to:

```
Gateway (plugin): you have these machines and accounts. Use normal commands; the gateway supplies passwords, keys and tokens. Never ask the user for a password, token or key in chat.
Hosts: localhost (sudo: yes, no password needed); example (ssh, sudo; reach as `ssh example CMD`); builder (ssh via example; sudo: off).
Accounts: github-personal (octocat, default), github-work (octo-work; example-org/*), hf, azure (use the http tool with account "azure"), catalog (asiml CLI), openai (api-key for api.openai.com; http tool account "openai"; `gate with openai -- CMD` for programs).
- sudo/ssh/scp/rsync work as usual. Run them as their own command (optionally after cd) so the gateway can approve them without a prompt.
- Web: the gateway's http and download tools (curl/wget are refused). WebFetch reads pages.
- Choose an account with GATE_ACCOUNT=NAME before the command if the gateway says two fit.
- To add or change a host or account, edit ~/.config/gateway/gateway.toml (only when the user asks), then run `gate check NAME` while the user is here. Adding or widening needs the user's OK in a pop-up; secrets are typed only there.
- If the gateway says a pop-up is waiting, tell the user once and continue with other work.
- `gate status` shows everything; `gate why` explains the last refusal.
```

When checkpoint has called gated in the last 24 hours (`<run>/checkpoint-seen`,
PLAN-0.11 §9.4), one more how-to line follows (it survives truncation like the others):
`- checkpoint jobs (job_start) get these stand-ins when checkpoint applies
the gateway's env.sh, and are judged like Bash: curl is refused, and an
"ask" right can't be used in a job (nobody can be asked while it runs), so
run such a command with Bash. job_tail and job_stop mask stored secrets as
*** like Bash output.`

Generated from the validated form only (names, kinds, rights, logins,
owners, sites); notes and other free text are never included.

## 14. MCP server

> **0.11.0** (PLAN-0.11 §2.10, lead decision 19.1): `http` and `download` get deny or ask from the `network` policy in the payload's mode (`hooks_mcp`), allow only for the user's explicit per-mode allow, else no decision; web.py lets a network "ask" through.

`.mcp.json`: server `gw`, `command: sh`, `args: [${CLAUDE_PLUGIN_ROOT}/hooks/launch.sh, mcp]`,
`"alwaysLoad": true`. Hand-rolled stdio JSON-RPC (keep v2's), with
`tools/call` dispatched on worker threads and a locked stdout writer. If
the env isn't built and no older finished env exists, the launcher waits up
to 4 s and then exits; the SessionStart systemMessage says `gateway:
first-time setup is running; restart the session (or reconnect gw in /mcp)
for the http tool`. This only happens on a machine's very first session
(after an update, the older env runs the server meanwhile). The curl/wget
deny says to ask the user to reconnect gw if the http tool is missing.

Tools (each with `_meta: {"anthropic/alwaysLoad": true}`):

- `http`: `{url, method="GET", headers={}, body?, json?, account?, auth?
  (placement override for api-key), save_to?, timeout=30 (≤ 300),
  max_bytes=5e6}`. http/https only. Proxy variables and `SSL_CERT_FILE` /
  `SSL_CERT_DIR` are ignored (certificates are checked against the Python
  build's own CA bundle), like every credentialed client of the gateway
  (`entra.urlopen`): nothing in the environment may route a credential
  through an interceptor. A site reachable only through a proxy can't be
  used with the http tool in v3.0. With `account`: the URL host must be
  in the account's `bound.hosts` (after consent); the credential goes in the
  stored placement (bearer header, named header, query param, basic with
  login). Azure: scope from the host (management → arm, graph →
  graph, listed workspace → databricks resource, listed storage → storage,
  listed site → requires `scope`). ml-catalog: the pinned API scope.
  Redirects: credentials and query keys dropped on cross-host or https→http
  redirects. Response: status, headers (scrubbed), body text (binary →
  base64 or `save_to`), all through `scrub_text` and the call's literals.
- `download`: `{url, account?, save_to?}`: binary-safe stream to `save_to`
  (default the project's working directory + URL basename); refuses
  existing files, dotfiles, paths inside `~/.config`, `~/.ssh`, the Claude
  config dir, the gateway home or the plugin; never sets the exec bit;
  returns path, size, sha256.

Hook decisions for these tools (`mcp_perm.sh`, sh only): since 0.10.0
`download` and `http` get no decision in any mode, for any method, with or
without an account (Claude Code's mode decides). Until 0.9.1 GET/HEAD, a
download and an `http` call naming an account were allowed.

## 15. `gate` CLI

`gate status [NAME] [--report]`, `gate check NAME|all`, `gate login NAME`,
`gate forget NAME [sudo|token|key|signin|host-keys]`, `gate rotate HOST`, `gate with NAME -- CMD`,
`gate export [FILE]`, `gate import FILE`, `gate copy-to HOST`, `gate log
[N]`, `gate why`, `gate secret NAME` (terminal only, below), `gate migrate`,
`CMD | gate scrub` (section 11, optional),
`gate import-ssh [ALIAS…]` (read `~/.ssh/config` and the files it `Include`s,
relative to `~/.ssh`, with globs; each alias resolved via `ssh -G`; propose
form entries; prints TOML for Claude to add — it never writes the form
itself; an alias whose HostName is a git server or an account's ssh endpoint
gets a comment instead of a table, round 4).

`gate check NAME` (the eager setup): validate the entry; compute
widening; pin host keys (keyscan through the chosen address/jump, shown in
the consent pop-up); one consent pop-up; then what the entry needs: install
the host key (choice: "use my own SSH login once" — the gateway process runs
the system ssh with the user's agent to append the key to
`authorized_keys` — or "type the password once" via `SSH_ASKPASS` with
`SSH_ASKPASS_REQUIRE=force`, or "show me the public key"), sudo password
(after a `sudo -n true` probe: see below), sign-in or token for accounts
(GitHub device flow with login check; Entra browser/device), then verify and
print one status line. It is idempotent: an entry already set up prints its
status and exits 0. Round 3: for a remote host it always reads the host key
(a change goes to the host-key pop-up, also through `gate secret NAME`,
which answers a host-key request the stand-in left), and for a host that
looks set up it tries a login with Claude's key (refused: the key is
installed again, and `installed` is dropped); a host behind a jump host that
isn't approved, pinned and holding an installed key stops before any pop-up
with `gateway: inner goes through gw1, which isn't set up yet; run gate check
gw1 first, then gate check inner` (exit 1); `gate check all` sets jump hosts
up before the hosts behind them; the status line never says "ready" while
ssh waits for the user's OK. A keyscan failure shows the ssh module's own
reason; when no host key could be read for a host that needs its first pin
or a new address (or jump), gate check stops before any pop-up (exit 1,
"...; nothing was asked", round 4). Through a jump host the scan tries the
next key type only after a connection that offered no matching key. Time
budget (round 4): Claude Code kills a Bash command after 2 minutes by
default, so every pop-up wait of `gate check` / `gate login` ends 100 s after
the command started (it then prints its exit-75 line), and `gate check all`
starts no new entry after 60 s (exit 75, `N entries are still to check (...);
run gate check all again`). What the setup did follows the status line
(`..., sudo ✓ (no password needed); Claude's key is installed (...)`),
without nested `gateway: ` prefixes.

Sudo, when `sudo -n true` fails (a remote host or localhost) and no
password is stored (since PLAN-v4 phase 7, which replaced this paragraph's
earlier passwordless-setup choice; the gateway never writes a sudoers rule):
one choice pop-up, "Store the sudo password" or "Ask me each time a command
needs it". The text says, for a remote host, that a stored password is staged
there for each sudo, where Claude's commands could read it. Store verifies
the password (3 tries, one sudo attempt each) and keeps it in the vault; ask
stores nothing, and each command's sudo dialog then asks with "Remember it"
(unticked: used for that command only). Sudo that already works without a
password (`sudo -n true`) is used as it is and nothing is asked. A stored
password is kept as it is. The answer is remembered per (host, user) in the
vault (`sudo_choice`, not exported); `gate forget NAME sudo` forgets it.

`gate forget` and `gate rotate` and the vault's copies (GW-DUR-1; the
lead's decision, review round 2): `gate forget` keeps no copy of the vault
(forgetting means gone). When older copies in `private/backups` may still
hold the entry (`rotate-*.vault.age`, `import-*/vault.age`,
`store-v2-*.age`), its output names them and how to delete them: in the
user's own terminal (Claude's tools can't reach that folder), `cd
~/.config/gateway/private/backups && rm -r` with the globs of the kinds
there. `gate rotate HOST` keeps a copy of vault.age taken just before the
rotation first changes the vault (under the vault's lock; a rotation that
fails before that, the host not set up for it (no gateway key, not
approved), keeps none and prints the ssh module's own message; one that
fails later, at the server, has its copy and puts the vault back itself), as
`private/backups/rotate-<YYYYmmdd-HHMMSS>-<hex>.vault.age` (0600, folder
0700, encrypted with the same key; the newest 5 kept), and its output names
the file. There is no restore command. To go back to such a copy by hand:
stop the gateway daemon first (quit every Claude Code session, or `pkill -f
"run.py gated serve"`), then `cp
~/.config/gateway/private/backups/rotate-….vault.age
~/.config/gateway/private/vault.age`. That undoes everything stored since
the copy, and for that host it brings back the old key, which the rotation
already removed from the server's `authorized_keys` when it said so: run
`gate check HOST` afterwards to install a key again.

`gate secret NAME` is the user's: it refuses (exit 2) when a Claude Code
session variable is set (`CLAUDECODE=1`, `CLAUDE_CODE_SESSION_ID`,
`CLAUDE_PID`), and, as defence in depth since a command can drop variables,
when its process tree says Claude Code started it: walking the whole parent
chain (ancestry helpers, by executable path), an ancestor whose executable
is the claude binary (basename `claude`, under `~/.local/share/claude/versions/`,
or the desktop app's bundled copy under `~/Library/Application
Support/Claude/claude-code/`) or whose pid is `CLAUDE_PID` refuses with
`gateway: run gate secret in your own terminal, not from Claude Code`
(audited). A chain it can't read (a parent pid it can't read, a loop, more
than 64 levels, a process of the user's own whose executable it can't read,
except OpenSSH's session process under a root sshd, which Linux makes
unreadable) refuses too, with its own message (round 5): `gateway: can't
tell which programs started this terminal (one of them was updated or
deleted while it ran, or this is a container), so this is refused here;
open a new terminal window and run ~/.config/gateway/gate secret NAME
there` (audited). macOS can't read the path of an executable deleted or
replaced while it runs, so a login shell or tmux running since a `brew
upgrade` or `port upgrade` lands here, in the user's own terminal. The walk
goes on above an unreadable process of the user's own, so a Claude Code
process further up still gets the first message. Another user's process
whose executable can't be read (root's sshd, login or sudo on Linux) isn't
Claude Code, which runs as the user; the walk goes on above it. The
one-time code stays the guard: a process detached from Claude's tree (a
double fork, a terminal window Claude opens), an npm install of Claude Code
(its executable was `node`; since 0.10.0 npm installs are recognized, by
`bin/claude.exe` or node running the package's `cli.js`) without
`CLAUDE_PID`, and the desktop app's
Terminal panel (its shells run under the app's helper) aren't seen by this
check. A shell whose parent is outside its PID namespace (`docker exec`)
can't be read, so `gate secret` refuses there. The terminal path of `gate
export|import|copy-to` (section 16) uses the same test; in the user's own
terminal with a tree it can't read it prints the round 5 message with its
own command, not the words for Claude.

Because Claude can type into the Terminal panel (`mcp__terminal__run_in_terminal`),
which this check doesn't see, the approval hook (section 8) denies `gate
secret` for every tool, Bash, Monitor and the panel alike, also behind a
wrapper or named inside a shell string, `eval`, a loop or `find -exec`
(`gateway: gate secret is for the user; ask them to run it in a terminal of
their own (~/.config/gateway/gate secret NAME, with the code the gateway
shows them). Don't run it or type into it for them.`), and denies `gate
export|import|copy-to` typed into the panel (without a screen they ask
there for the user's code); in Claude's Bash those use pop-ups or say what
to ask the user. A command that only names it (`grep 'gate secret'`) is
judged as before. The user's own typing in the panel passes no hook (round
5).

`gate why` prints the last refusal for this session with its full reason
and the fix; without a session id (the user's own terminal) the newest
refusal of any session, with its time and session. `gate status` without a
form tells a fresh install ("No gateway.toml yet: created at the next
session start") from a removed form, and its "Just ask" examples use the
form's own hosts.

## 16. Export, import, copy-to

> **0.11.0** (PLAN-0.11 §9.3, lead decisions 11, 12): format 3 only (PLAN-v4 phase 7; formats 1 and 2 are refused). Settings (`[shell]`, `[policy]`, `[network]`, `[vault]`) are approved in the import's one confirm; this machine's settings (`[hosts.localhost]`: sudo, scripts, policy, workspaces) are an item, unticked by default, kept or replaced on import; the confirm comes in parts when long; a browser sign-in's refresh token isn't exported; import runs inside a Claude Code session. [modules/ux.md](modules/ux.md).

- Export format 2: age passphrase file (v2's pty runner), mode 0600,
  written outside any git work tree or cloud-synced folder (default
  `~/Downloads/gateway-YYYYMMDD.age`, never overwritten). Content:
  `{gateway_export: 2, form: <text>, vault: <vault minus cache, approved,
  form_last_good, events>, from: {machine_id, name, hostname, ssh_host_keys}}`.
  The consent pop-up lists the contents with checkboxes per group (hosts,
  accounts, this machine's sudo password — unticked by default). The
  passphrase is typed twice in hidden pop-up fields, ≥ 12 characters. No
  generated passphrase is offered: a dialog's visible text is on its command
  line (osascript argv, zenity `--entry-text`, kdialog `--inputbox`), which
  any process of the user's can read with `ps` while it is open, so nothing
  secret is ever shown in a pop-up (`dialog.argv_for` refuses it).
- Import (format 1 via the migration mapper, or 2): decrypt → validate
  everything as strictly as the form/vault → identify this machine by
  matching `/etc/ssh/ssh_host_*_key.pub` against hosts' pinned keys (else
  machine id; else ask) → the matching host becomes localhost (its sudo
  moves to `localhost.sudo`), the source machine's localhost becomes a host
  named after its `name` with `address = user@hostname` and `ssh = false`
  until the user turns it on (its sudo as the file's form says, else
  `"ask"`, 0.10.0) → consent pop-up (adds, replaces, keeps, host
  key differences) → merge under the lock (append tables to the form).
- `gate copy-to HOST`: only to a form host whose host key was pinned
  before this session; the user types the host name in the consent pop-up;
  the remote must have the plugin (`~/.config/gateway/gate` exists, else
  the gateway prints the steps to install it: the user signs in to Claude
  Code there and lets one session's first-time setup finish; a remote `gate`
  that exits 75 is "still setting up; try again in a minute"); encrypt the export to the
  remote's age recipient (`ssh HOST ~/.config/gateway/gate pubkey`) and
  stream it to `ssh HOST ~/.config/gateway/gate import --from-peer -`. The
  remote applies it without a pop-up of its own (it usually has no screen,
  and the user consented on the source; phase C kept this, with pop-up
  wording that Claude can run commands on that host, so whatever is copied
  is within its reach there); `--from-peer` reads only an
  age-encrypted stream for its own recipient, so nothing else can be fed
  in that way, and records an `import` event the remote's next session
  shows to the user. Per-host keys travel; `gate rotate` gives a host a new
  key.

## 17. Audit

`$DATA/audit.jsonl`: one line per credential use, pop-up outcome,
consent, widening, refusal, export/import/copy, migration. Values redacted.
`gate log [N]` renders it. Security events also go into the vault's
`events` (section 3).

## 18. pixi and the launcher

`hooks/launch.sh` (POSIX sh): the user's home from the password database
(`hooks/home.sh`; tests only: `launch.sh MODE --test` with an absolute
`GATEWAY_TEST_ROOT` puts it in the test root, and `GATEWAY_TEST_ROOT` without
that resolves no home at all); find pixi (`command -v`, then
`${PIXI_HOME:-$HOME/.pixi}/bin`, `~/.local/bin`, `/opt/homebrew/bin`,
`/usr/local/bin`, `/opt/local/bin`, `/home/linuxbrew/.linuxbrew/bin`);
compute `sha12` of `pixi.lock`; if `$DATA/envs/$sha12/.pixi/envs/default/bin/python3`
exists, exec it with `-I -S run.py "$@"` (for `hook-session` after writing
the safe env file, section 7); else for `ensure-env` build it (and warm it);
for hooks and `mcp`, exec the newest other env under `$DATA/envs` that has
`.ready` (touching its `.used`), if any; else for hooks print the documented
degraded output (session: env file, stubs while something may be
configured, a systemMessage and context by state: building, pixi missing,
pixi too old, build failed), for `mcp` wait up
to 4 s then exit 1.

pixi.toml (0.11.0, PLAN-0.11 §5: latest only): every dependency `"*"`
(Python, PyNaCl, age, gh, git-lfs, openssh, git, bash, tmux, pixi-pack,
zstd), relocked each release by `pixi run update-deps`; features `hf`
(huggingface_hub, hf-xet), `databricks` (databricks-cli), `dvc` (+
dvc-azure), `registry` (crane only), `pijul` (no conda-forge package: a
cargo build of the newest pijul release, pre-releases included, into
`$DATA/pijul`, against the env's own libraries only). Platforms:
osx-arm64, osx-64, linux-64, linux-aarch64 (no win-64). `requires-pixi` is
the pixi that made the lock, with no upper bound; an older pixi refuses the
manifest, which launch.sh reports as pixi too old (`pixi self-update`).
An older env is used only on the lock's Python minor. Tasks: `test`, `mutations` (every mutation file
on scratch copies), `e2e`, `release-check`.

## 19. Files removed

`install.py`, `legacy-settings.json`, `config/policy.json`, the empty
`bin/`, `commands/` for add/update/delete/enable/disable/block/list/export/
import/log, `skills/accounts` and `skills/setup`, `hooks/perm.sh`, and the v2
modules `actions cli common dbops ghops gitops hfops hooks mirrors mlcat
pijulops policy regops runner setup sshconf sshops web_form` (with them the
elicitation code, the argv policing and hardening, the grants, the
`*_confirm` tools, port_check/cert_inspect/file_hash and the regex
blocklist; only curl/wget remain, as parsed commands; asiml.py replaces
mlcat; entra.py has its own sign-in pages). `vault_v2.py` stays: migration
reads v2 vaults with it.
Commands kept: `/gate:status` (renders `gate status` with the form path and
"just ask me to…" footer) and `/gate:help`. Skill `gate:gateway` (not
user-invocable): how Claude adds/edits entries, the `gate check` flow,
error handling, account selection, Azure/asiml usage.

## 20. Tests

`tests/run_tests.py` discovers `tests/test_*.py` (no pytest; `pixi run
test` runs the modules 4 at a time, each in its own process), with a
shared `tests/harness.py`: temp gateway home/data/run dirs through
`gateway.testing.override`; fake dialog backend (scripted answers and
outcomes); fake password sudo (`-A`/`-S`/`-v`/`-n`/`-k`, `Sorry, try again`
after a wrong password, NOPASSWD mode); a local unprivileged sshd on a free
port with throwaway keys (target + jump; killed in `finally`/atexit, `-D`
with tracked pid) whose PATH has the fake sudo; a local smart-HTTP git +
LFS server with Basic auth; a local HTTP API server; fake GitHub/Entra
endpoints for sign-in tests. Required coverage: every row of section 8's
decision table (≥ 60 commands, must-allow and must-not-allow), every
widening/narrowing case, migration of a synthetic vault shaped like the
user's (8 accounts, secrets, sudo entries, routes, rotated keys), each
stand-in's happy path and refusals, ancestry (direct vs make/npm vs
scripts=true), scrubber streaming edge cases, pop-up outcomes, export →
import round trip including localhost remap, env-file idempotency (sourced
twice, `set -u`, bash/zsh/sh; a no-op without the stand-in folder),
checkpoint's job_start (section 8's table through it, command and argv
forms; real checkpoint-shaped process trees: direct, never typed). Security properties are mutation-checked
(the test fails with the guard removed; `pixi run mutations` runs every
mutation file on scratch copies of the plugin). A headless suite (`pixi run e2e`,
not part of `test`) drives `claude -p --plugin-dir … --permission-mode auto`
against the local sshd and git server and asserts no permission denials for
allowed commands and the expected refusals otherwise.
