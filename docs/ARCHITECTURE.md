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

`_gate` applies the `policy.json` tiers. An `ask` tier there would use MCP
elicitation (`Server.approve`/`form`), but the desktop app auto-cancels those,
so the real prompts are the settings.json `ask` rules. `refuse` is a hard
off-switch, including for run_privileged.

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

## Install (`install.py`, `pixi run install`)

1. `claude plugin marketplace add <repo>` (skipped if `gateway` is
   already registered), then `claude plugin install gate@gateway`.
2. Reads `settings.rules.json`, replaces `{PLUGIN_DIR}` with a rule path (`~/…`
   under home, `//abs/…` otherwise; a single `/` would be relative to the
   settings file), and merges into `$CLAUDE_CONFIG_DIR/settings.json` or
   `~/.claude/settings.json`. It removes a rule from a weaker list when the
   plugin needs it stricter, so a stray `allow` can't silence an `ask`. It
   shows the changes, asks, backs up, and writes atomically. Re-running is
   idempotent.

## Threat model, briefly

Meant to stop: a cooperative or prompt-injected Claude leaking credentials,
sending them to the wrong host, or getting root without the user's say-so;
and secrets ending up in transcripts or logs.

Not a sandbox: Claude still has Bash, so a determined bypass of the regex
blocklist is possible (`c''url`, `nc`, a written script), and Bash can edit
`policy.json`. The Read/Edit deny rules protect the vault files from Claude's
file tools; the vault key itself is the user's file. Enabling sudo with
`always` deliberately trades the prompt away.
