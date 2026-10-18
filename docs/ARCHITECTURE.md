# Architecture

gateway has three moving parts inside Claude Code (hooks, an MCP server,
slash commands) and one store outside it (the vault). They all share
`src/gateway/` through a single entry point, `run.py`, run with pixi's
Python.

```
                 ┌───────────────────────── Claude Code session ─────────────────────────┐
 user prompt ──▶ │ UserPromptSubmit hook ── /gate:secret|sudo ──▶ commands.py ─┐   │
                 │   (prompt.sh pre-filter)                                          │   │
                 │                              browser form (web_form.py) ◀─────────┤   │
                 │                                                                   ▼   │
                 │ SessionStart hook ── policy note + vault catalog ──▶ Claude     vault │
                 │                                                                (age) │
 Claude's Bash ─▶│ PreToolUse(Bash) hook ── blocklist match ──▶ deny + "use X"        ▲   │
                 │                                                                   │   │
 Claude's tools ▶│ MCP server "gw" (mcp_server.py → actions.py) ── reads secrets ────┘   │
                 │     http_request / download / port_check / cert_inspect / file_hash   │
                 │     secret_list / secret_use / run_privileged(_confirm)               │
                 └───────────────────────────────────────────────────────────────────────┘
                   everything above appends to logs/audit.jsonl (values redacted)
```

## Hooks (`hooks/hooks.json`)

| Event | Runs | Does |
|---|---|---|
| SessionStart | `run.py hook-session` | Injects the network policy plus a **catalog**: secret names, descriptions, allowed hosts, sudo targets and their state for *this* session. Never values. If sudo is enabled for the session, it also shows the user a `systemMessage` warning. |
| UserPromptSubmit | `hooks/prompt.sh` → `run.py hook-prompt` | The shell pre-filter passes ordinary prompts through without starting Python. For `/gate:secret`, `/gate:sudo` or `/gate:account` (or bare `/secret`, `/sudo`, `/account`) it calls `commands.handle`. |
| PreToolUse(Bash) | `run.py hook-route` | `policy.match_blocked(command)`; on a hit, it returns `permissionDecision: deny` with the gateway equivalent. It fails open on its own errors. |

### The slash commands and the prompt hook

`commands.handle(payload)` returns hook JSON:

- **Normal case: pass through.** It runs the command (add, up, allow, enable,
  …), then returns `additionalContext` holding a `<gateway-result>`
  block. The prompt still reaches Claude, expanded from
  `commands/secret.md`/`sudo.md`, whose body tells Claude to relay the result
  in a line and call no tools. There's no "blocked by hook" popup, and the
  input box isn't refilled.
- **Values** (`secret add/up`, `sudo add/up`, `account add/up`) come from
  `web_form.ask(…)` (one masked field) or `web_form.ask_form(…)` (an
  account's settings plus masked token and key fields), a
  one-time page on 127.0.0.1 the hook opens in the browser and waits on (up to
  300 s; the hook timeout is 330 s). The typed command never contains a value.
- **No browser** (`web_form.gui_available()` is false: Linux without
  `DISPLAY`/`WAYLAND_DISPLAY`, or macOS over ssh): nothing is saved, and the
  passed-through result gives the exact terminal fallback, `pixi run
  --manifest-path …/pixi.toml vault secret|sudo …` (`cli.cmd_vault`). That runs
  the same `run_secret`/`run_sudo` code with `commands.VALUE_PROVIDER` set to a
  hidden `getpass` prompt, and refuses to read from a non-terminal. Python's
  `webbrowser` is never used on a headless machine, because it can fall back to
  console browsers (lynx) that would hang the hook.
- **Safety net: block.** If the text looks like it holds a value
  (`_TOKEN_LIKE`, or extra words after `sudo add USER HOST`), it returns
  `decision: block` with `suppressOriginalPrompt`, saves nothing, and starts a
  detached scrubber (`run.py scrub`). The scrubber overwrites the typed words
  with `*` in the session transcript and prompt history for ~10 s, only on
  lines containing a command marker, keeping the file the same length.
- Unexpected exception → block (fail closed). `prompt.sh` also blocks if
  Python can't run.

## MCP server (`.mcp.json`, `mcp_server.py`)

A hand-rolled JSON-RPC loop over stdio (initialize, tools/list, tools/call,
ping; it negotiates the client's protocol version). `dispatch` maps tools onto
`actions.py`. Claude Code passes `CLAUDE_CODE_SESSION_ID` in the server's
environment, and that's how per-session sudo works.

| Tool | settings.json | Notes |
|---|---|---|
| http_request | allow | http(s) only; `auth_ref=NAME` puts the vault value in `auth_header` (default `Authorization: Bearer …`); refused unless the request's host is in the secret's `hosts`; the value is scrubbed from the response; credentials are dropped on cross-host or downgrade redirects; redirects must stay in `allow_domains` |
| download | allow | to `quarantine/`, never overwrites, streams the sha256, `max_download_bytes` |
| port_check | **ask** | TCP connect to ≤64 ports; not a scanner |
| cert_inspect / file_hash | allow | cert_inspect falls back to an unverified fetch and sets `verified:false` + `verify_error` |
| secret_list / secret_use | allow | names, descriptions, hosts, sudo targets; never values |
| run_privileged | allow | only where sudo is **enabled** (always, or for this session); otherwise refused with a pointer to the next tool |
| run_privileged_confirm | **ask** | the same command, for disabled hosts; Claude Code's prompt shows the host and argv |
| account_list | allow | the accounts catalog (never values) |
| git | allow | any git command (`gitops.py`): local ones without credentials; remote ones as the account for the remote's host+owner, under its prompt policy |
| git_confirm | **ask** | the same, for calls the policy says to ask about (deletes, force-with-lease by default) |
| git_identity | allow | the repo's own user.name/user.email (and gateway.account) from an account |
| gh | allow | the plugin's own gh as an account (`ghops.py`): GH_TOKEN or GH_ENTERPRISE_TOKEN, GH_HOST, a temp GH_CONFIG_DIR |
| gh_confirm | **ask** | the same, when the policy asks |
| git_mirror | allow | `mirrors.py`: status/sync/add/remove of a remote set (repo config `gateway.mirror`); fetch and push through the git tool, fast-forward only |
| hf / hf_confirm | allow / **ask** | `hfops.py`: the `hf` CLI (pixi env hf) with HF_TOKEN, HF_ENDPOINT pinned, token files in the temp dir |
| pijul / pijul_confirm | allow / **ask** | `pijulops.py`: temp PIJUL_CONFIG_DIR + identity.toml, temp HOME with the pinned known_hosts, the key in a private agent, `--config signing_key=` |
| ssh_exec(+_confirm), ssh_copy(+_confirm) | allow / **ask** | `sshops.py` + `sshconf.py`: private agent, `-F` the gateway's own per-call ssh_config, routes, pinned host keys under one alias, jump hosts, argv joined once; exec asks by default (see "SSH hosts") |
| ssh_hosts | allow | read-only: routes, the route it would use (probe), host-key policy and fingerprints, key fingerprints, reuse state |
| databricks / databricks_confirm | allow / **ask** | `dbops.py`: an Entra token for the workspace as DATABRICKS_TOKEN, auth type pat, empty config file |
| mlcat, mlcat_workspace(+_confirm) | allow / **ask** | `mlcat.py`: the catalog API; asiml's workspace commands natively, dvc with the one-hour pass only in its env |
| registry / registry_confirm | allow / **ask** | `regops.py`: crane with a throwaway DOCKER_CONFIG; ghcr via a GitHub account, ACR via token exchange |

`_gate` applies the `policy.json` tiers. An `ask` tier there would use MCP
elicitation (`Server.approve`/`form`), but the desktop app auto-cancels those,
so the real prompts are the settings.json `ask` rules. `refuse` is a hard
off-switch, including for run_privileged.

### SSH hosts (`sshconf.py`)

Each ssh_exec / ssh_copy / run_privileged-over-ssh call writes a private
`ssh_config` and `known_hosts` in the call's 0700 temp dir and runs
`ssh -F <that file> gw-NAME`; `~/.ssh` is never read at runtime.

- **Blocks:** one `Host gw-NAME` per account in the chain (target, then its
  jump hosts, at most 3, no loops): HostName/Port from the chosen route,
  `HostKeyAlias gw-NAME`, `StrictHostKeyChecking yes`, `CheckHostIP no`,
  `UpdateHostKeys no`, BatchMode, no password or keyboard-interactive,
  `IdentitiesOnly` with one `IdentityFile <pub>` per key and the private
  agent, no agent/X11/port forwarding, no LocalCommand or tunnel. A jump is
  `ProxyCommand ssh -F <same file> -W [%h]:%p gw-JUMP`. A final `Host *`
  gives any other name no agent, no key and an empty known_hosts.
- **Routes:** an ordered list `{name, host, port, when}`; none means one
  route from host/port. Python picks: a route with `when` (CIDR) applies only
  if the local source address toward it is in that network (UDP connect, no
  packet); a non-last route must answer an `SSH-` banner within 2 s; the
  last route is the fallback. Cached 5 minutes per account. If the chosen
  route is unreachable or shows another host key, the next route is tried
  (a LAN address elsewhere may be someone else's machine).
- **Host keys:** stored known_hosts lines are rewritten under the alias, so
  every route checks the same keys. Policy per account: `pinned` (default;
  a mismatch is refused with a hint to `/gate:update`), `accept-new`
  (rescan, store, audit `host_key`, report `host_key_notes`; also pins on
  first use) or `ask` (the native dialog shows both fingerprints; Cancel
  keeps the pin). ssh itself always runs strict; replacing is the gateway's
  decision, made only after every route failed. At setup, every route must
  show the same host key, or the proposal is refused.
- **Keys:** `secrets.ssh_key` (newest) plus `secrets.old_ssh_keys` /
  `old_public_keys` (at most 3) during a rotation; all are loaded into the
  private agent and offered newest first.
- **Reuse:** off unless the user typed `/gate:enable reuse ssh:NAME` in this
  session (`ssh_reuse` in the vault: account to session ids). Then the
  target block gets `ControlMaster auto`, `ControlPersist <reuse_minutes>m`
  and a socket `<data>/ssh-mux/NAME-<hash of route and chain>` (or
  `/tmp/gw-mux-UID` when the data path is too long for a socket). While a
  master is open, any process running as the user could use that socket:
  that is why it's opt-in per session. `/gate:disable reuse` sends
  `-O exit` and removes the sockets.
- Pijul uses its own SSH client, and git over ssh uses the runner's
  `GIT_SSH_COMMAND` (below); neither goes through this config.

### Root commands

`run_privileged` runs, locally or as `ssh -o BatchMode=yes -T -- user@host`:

```sh
sudo -S -p "" -v || exit 1; sudo -n -- "$@" </dev/null; rc=$?; sudo -k; exit $rc
```

The password goes to stdin, which only `sudo -v` reads. The command gets
/dev/null, so the password can't leak into it, even under a NOPASSWD rule. The
argv is `shlex.join`-ed once for the remote login shell, which must be a POSIX
sh. The password is scrubbed from stdout and stderr.

## Vault (`vault.py`)

`$GATEWAY_HOME` (default `${XDG_CONFIG_HOME:-~/.config}/gateway`):

```
key.txt     age X25519 identity, generated on first write, mode 600
store.age   age-encrypted JSON, mode 600, replaced atomically; plaintext only via stdin/stdout pipes
.lock       flock for read-modify-write
```

```json
{"version": 2,
 "secrets": {"HF_TOKEN": {"value": "…", "description": "…", "hosts": ["huggingface.co"], "updated": "…"}},
 "sudo": {"admin@myserver": {"user": "admin", "host": "myserver", "password": "…", "updated": "…"}},
 "sudo_enabled": ["…hosts enabled in every session…"],
 "sudo_session": {"myserver": ["<session ids>"]},
 "accounts": {"github:work": {"kind": "github", "description": "…", "host": "github.com",
                              "login": "…", "name": "…", "email": "…", "owners": ["asirobots"],
                              "hosts": ["github.com", "api.github.com"],
                              "secrets": {"token": "…", "ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----…"},
                              "public_key": "ssh-ed25519 …", "key_fingerprint": "SHA256:…",
                              "prompts": {"write": "ask"}, "updated": "…"}},
 "account_prompts": {"delete": "ask"}}
```

A version 1 vault (no accounts) loads as-is and is written back as version 2.

**Accounts** (`/gate:account`, `KINDS` in vault.py): `github`, `hf`, `pijul`,
`azure`, `mlcat`, `ssh`, `registry`.

- **Values vs. catalog.** Everything under `secrets` is a value; the rest is
  what `account_view()` shows Claude.
- **Scope.** `hosts` (defaults from the kind and host, e.g. github.com +
  api.github.com), plus `owners` for kinds that have them.
- **Prompt policy.** `read`/`write`/`delete`/`exec` = `auto`/`ask`/`refuse`,
  per account over a vault-wide default (`account_prompts`). It's kept in
  the vault because Claude can edit `policy.json` from Bash.
- **SSH keys.**
  - A pasted OpenSSH key is parsed in Python: the public key is in its
    unencrypted header, and a passphrase-protected key is refused.
  - A generated key comes from `ssh-keygen` (pixi's OpenSSH), which can only
    write files. It writes into a 0700 temp dir in the vault home that is
    read and removed immediately.
- **As `auth_ref`.** An account with a token works as `auth_ref` on
  `http_request`, under the same host check as a secret.

The host is normalized (`127.0.0.1`, `::1`, `local` → `localhost`). Host
names must match `HOST_RE`, so a leading `-` (an ssh option) is impossible.
`catalog()` is the only view Claude ever gets.

## Runner (`runner.py`)

How the tools that act as an account will run a CLI (git so far; nothing
calls it yet, the `git` MCP tool comes next). Per call:

- **Environment:** an allowlist (`ENV_ALLOW`: PATH, HOME, locale, TMPDIR, …),
  so the user's own `GITHUB_TOKEN`, `HF_TOKEN`, `SSH_AUTH_SOCK`, proxies and
  the like never reach the child.
- **Temp dir:** a private 0700 temp dir holds the agent socket, the
  credential helper and FIFO, `known_hosts` and the public key file. It's
  removed afterwards.
- **SSH key:**
  - `ssh-agent -D -a SOCK` (pixi's OpenSSH) plus `ssh-add -` from stdin.
  - `GIT_SSH_COMMAND` = `ssh -F /dev/null -o BatchMode=yes
    -o IdentitiesOnly=yes -o IdentityAgent=SOCK -o IdentityFile=<the .pub>`
    with its own `UserKnownHostsFile`. Verified to offer only that key,
    never `~/.ssh/id_*`.
  - `StrictHostKeyChecking=yes` against pinned keys, or `accept-new` with
    the keys it saw returned as `seen_host_keys`.
  - Without a key: `IdentityAgent=none`, `IdentityFile=none`.
- **Token:** `credential.helper=` resets the repo's and user's helpers.
  `credential.<proto>://<host>.helper` points at a one-call script that
  checks `host=` and `protocol=` and `cat`s a FIFO the runner writes
  `username=`/`password=` into. The token is never in env, argv or a file.
- **Git config overrides** (`-c`, which beat repo config): `core.hooksPath=/dev/null`,
  `core.fsmonitor=false`, `core.askPass=`, `core.gitProxy=`,
  `http(s).proxy=`, `http.sslVerify=true`, `http.extraHeader=`,
  `protocol.allow=never` (https/ssh/file allowed; ext/git never), and
  `safe.bareRepository=explicit`. Also `GIT_CONFIG_GLOBAL=/dev/null`,
  `GIT_CONFIG_NOSYSTEM=1`, `GIT_TERMINAL_PROMPT=0`, and editors set to
  `false`. Explicit `--upload-pack`/`--receive-pack` beat a repo's
  `remote.*.uploadpack`.
- **Refused before anything runs:** caller `-c`/`--git-dir`/`-C`,
  `--upload-pack`/`--exec`/`--tool`, `credential`, `daemon`, `filter-branch`,
  `difftool`/`mergetool`, `submodule foreach`, `bisect run`, and the like.
- **Local subcommands** (not fetch/push/clone/…) never get the credentials.
- **Output** is capped at 1 MB per stream, and the account's values (and
  each line of a key) plus `policy.scrub` patterns are replaced. The process
  group is killed on timeout, and each call is audited as `run`.

## git and gh as an account (`gitops.py`, `ghops.py`)

- **Which remote:** the URL git will really use (`remote get-url [--push]`,
  or `ls-remote --get-url`, so insteadOf/pushurl apply). Several push URLs
  and `fetch --all` are refused, so each URL uses its own account. A
  password in a URL is refused.
- **Which account:** kinds github/hf/ssh whose `hosts` cover the host.
  - One that lists the owner wins over one with no owners (a catch-all).
  - Two candidates at the same level are ambiguous: pass `account=`.
  - A named account outside its owners is refused, with the
    `/gate:account allow` command to fix it.
  - No match: the command runs without credentials (public repos).
- **Class and policy:**
  - Classes: `read` (fetch, pull, clone, ls-remote, lfs fetch) and `write`
    (push, lfs push).
  - `delete`: `--delete`, `:ref`, `--mirror`, `--prune`,
    `--force-with-lease`, `gh … delete|archive|rename|transfer`,
    `gh api -X DELETE`.
  - Plain `--force` / `+ref` is always refused.
  - The policy's answer: `auto` runs; `ask` refuses with `use: git_confirm`
    (or `gh_confirm`), whose settings rule is `ask`; `refuse` refuses both.
- **Guards:**
  - Nothing may point into the vault (cwd or any path argument).
  - `git config` can't set credential/ssh/hook/url/http/include/alias/filter
    keys.
  - Plain http only to loopback.
  - gh refuses `auth`, extensions, alias, config, browse/`--web`,
    `--hostname`, repo clone/sync, pr checkout, and repo create/fork with clone/push/remote options. `gh api` only
    to the account's hosts.
- **`/gate:account login github:NAME`** (`logins.py`):
  - The hook runs the plugin's gh `auth login --web --insecure-storage` in
    a 0700 temp `GH_CONFIG_DIR` and shows gh's one-time code on a local
    page (`web_form.Notice`, with Cancel) or in the terminal.
  - When gh exits it reads `oauth_token` from that dir into the vault and
    removes the dir.
  - Scopes: gh's defaults plus workflow, read:packages and write:packages.

## Entra (`entra.py`) and the catalog (`mlcat.py`)

- **Sign-in:** `/gate:account login` for azure and mlcat accounts runs
  auth code + PKCE with a one-time `http://localhost:PORT` redirect in your
  browser, or device code in the terminal. The refresh token goes into the
  vault.
- **Tokens:** the MCP server mints access tokens per scope (`arm`,
  `storage`, `graph`, `databricks`, `api://…`), caches them in memory, and
  stores Entra's rotated refresh token in place of the old one. That is the
  only vault write the server makes, and it grants nothing new.
- **The catalog:** mlcat accounts take the tenant, API app and CLI app from
  the catalog's `/api/config`. Storage passes come from
  `/api/transfers/{push,pull,complete}` and live only in dvc's environment.

## One mode: the plugin's own rules

Plugins can't ship permission rules or `env` (only `agent` settings are
honored), so everything the plugin enforces is a hook decision. It's always
on while the plugin is enabled.

- **Redirects (Bash, `hooks.route_main`):** `policy.TAKEOVER` matches git,
  gh, hf/huggingface-cli, pijul, asiml/dvc, az, databricks/mlflow,
  ssh/scp/sftp, rsync to a host, docker/podman login/push/pull, skopeo, oras,
  crane, `ssh-add`, `launchctl getenv SSH_AUTH_SOCK` and the launchd agent
  socket path, at a command position only (not `echo git` or `ssh-keygen`).
  `_BLOCKED` adds curl, wget, nmap, the keychain tool, inline python/node
  network calls and the vault path.
- **Credentials out of Bash (SessionStart):** `hooks.write_env_file` appends
  `unset SSH_AUTH_SOCK SSH_AGENT_PID GITHUB_TOKEN …` (`policy.ENV_UNSET`) to
  `CLAUDE_ENV_FILE`, which Claude Code sources before every Bash command.
  Settings `env` couldn't do this: plugins can't ship it, and the desktop
  app's `SSH_AUTH_SOCK` survived both `""` and `/dev/null` there.
- **Gateway tools (`hooks/perm.sh`):** `*_confirm` and `port_check` return
  `ask`, so Claude Code shows its prompt with the exact arguments. Every other
  gateway tool returns `allow`, because each enforces its own accounts and
  policy.
- **File tools (`perm.sh` → `hooks.files_main`):** Read/Grep/Glob/Edit/Write
  calls that mention a credential location get a precise check
  (`policy.protected_path`): the vault, age and secret stores, credential
  files (gh `hosts.yml`, docker, HF, Azure, Databricks, pijul identities,
  asiml), private keys in `~/.ssh` (`config`, `known_hosts` and `*.pub` stay
  readable; Glob may list names; Grep over `~/.ssh` is refused), the plugin's
  data dir, and writes to the plugin's `config/`. Everything else passes
  without starting Python.

## Policy and logging (`policy.py`)

- `load_config()` merges `config/policy.json` over `DEFAULT_CONFIG`. An
  unreadable file falls back to defaults and prints a warning on stderr.
- `plugin_root()` ignores an unexpanded or relative `CLAUDE_PLUGIN_ROOT`.
  Claude Code doesn't expand `${…}` inside `.mcp.json` `env`, which caused a
  real bug once.
- `audit(event, detail)` appends JSONL to `logs/audit.jsonl` after
  `redact()`: secret-named keys are replaced, and secret-looking values (Bearer
  tokens, `user:pass@`, `?token=`, `-u user:pass`, known token prefixes) are
  scrubbed.
- `_BLOCKED` is the Bash blocklist used by the PreToolUse hook and by
  run_privileged.

## Short commands and guided setup (`setup.py`)

- **Typed commands:** `/gate:add|update|delete|enable|disable|list|export|import`
  go through the UserPromptSubmit hook (`prompt.sh` → `hooks.prompt_main` →
  `setup.handle`, then `commands.handle` for the v0.5 commands). `delete`,
  `enable`, `disable` and `list` act at once: the typed command is the consent.
- **Grants:** `add` and `update` open a **grant**
  `{op, what, target, session, expires (+15 min), used, pending}` in
  `vault["grants"]`, inside the encrypted vault, so Claude's Bash can't
  forge one the way it could a plain file. The note passed to Claude names
  the grant id and the `gate:setup` skill.
- **Guiding:** Claude asks with its question pop-ups (the skill says what to
  ask, per kind), then calls the `gate_setup` MCP tool with the grant and a
  proposal.
- **`gate_setup`:**
  1. Checks the grant: it exists and is unused and unexpired, its session is
     the MCP server's `CLAUDE_CODE_SESSION_ID`, and its kind matches.
  2. Validates the proposal (`_plan`). A refusal leaves the grant open, so
     Claude can fix the proposal and retry.
  3. Shows `dialog.confirm` with a plain-language summary, then
     `dialog.secret` for a token or password, or opens a browser sign-in.
  4. Saves through the same code as the v0.5 commands
     (`commands._apply_form`, the sudo and secret records), and marks the
     grant used.
- **No dialog:** the proposal is kept with the grant, and the user runs
  `pixi run … gateway finish GRANT` in a terminal. It shows the summary,
  asks y/N and reads the value at a hidden prompt.
- **v0.5 commands:** `/gate:secret` and `/gate:sudo` take their value from
  the same dialog; `/gate:account add|up` point to `/gate:add` and
  `/gate:update`.

## Native dialogs (`dialog.py`)

The one place a person types a secret or approves a change. The dialog is
opened by the gateway's own process, and the answer comes straight back to
it; Claude Code's question pop-ups aren't used for values, because their
answers go to the model.
- **macOS:** `osascript` (`display dialog`, `with hidden answer` for
  secrets, giving up after 5 minutes).
- **Linux desktop:** `zenity`, else `kdialog`.
- **Elsewhere (ssh, headless):** `Unavailable`, so the caller points to the
  terminal.

Text is passed as arguments to a fixed script, never spliced into it.
AppleScript variables carry a `gw` prefix: `kind` is a reserved word and
broke the first live run.

## Plugin data folder

`policy.data_dir()`: `CLAUDE_PLUGIN_DATA`, or `<config dir>/plugins/data/gate-gateway`
outside Claude Code. It holds the audit log (moved there once from the v0.5
`logs/`) and `quarantine/` (a relative `download_dir`). It survives plugin
updates. Claude's file tools may read it but not write to it.

## Install

Users install with `/plugin marketplace add p-w-rs/gateway` and
`/plugin install gate@gateway`; nothing else. `install.py` (`pixi run
install`) is a developer helper: it registers a local checkout as the
`gateway` marketplace and removes what gateway 0.5 wrote into settings.json
(rules and strict-mode env, listed in `legacy-settings.json`). An env entry
goes only while it still has a value 0.5 set. It shows the changes, asks,
backs up, and writes atomically.

## Threat model, briefly

Meant to stop: a cooperative or prompt-injected Claude leaking credentials,
sending them to the wrong host, or getting root without the user's say-so;
and secrets ending up in transcripts or logs.

Not a sandbox: Claude still has Bash, so a determined bypass of the regex
blocklist is possible (`c''url`, `nc`, a written script), and Bash can edit
`policy.json`.

Accounts add one more limit. `http_request` enforces a secret's hosts
itself, but once a token is inside a CLI's environment (`gh`, `hf`, `dvc`,
`databricks`, `crane`), the CLI could send it anywhere. The gateway narrows
this:
- endpoints are pinned (`GH_HOST`, `HF_ENDPOINT`, `DATABRICKS_HOST`);
- subcommands that print tokens, sign in or run other programs are refused;
- proxies and endpoint variables are blanked;
- exact-value scrubbing catches echoes.

It is a guardrail, not a guarantee. The Read/Edit deny rules protect the vault files from Claude's
file tools; the vault key itself is the user's file. Enabling sudo with
`always` deliberately trades the prompt away.
