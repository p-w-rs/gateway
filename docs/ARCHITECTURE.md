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
| UserPromptSubmit | `hooks/prompt.sh` → `run.py hook-prompt` | The shell pre-filter passes ordinary prompts through without starting Python. For `/gate:secret` or `/gate:sudo` (or bare `/secret`, `/sudo`) it calls `commands.handle`. |
| PreToolUse(Bash) | `run.py hook-route` | `policy.match_blocked(command)`; on a hit, it returns `permissionDecision: deny` with the gateway equivalent. It fails open on its own errors. |

### The slash commands and the prompt hook

`commands.handle(payload)` returns hook JSON:

- **Normal case: pass through.** It runs the command (add, up, allow, enable,
  …), then returns `additionalContext` holding a `<gateway-result>`
  block. The prompt still reaches Claude, expanded from
  `commands/secret.md`/`sudo.md`, whose body tells Claude to relay the result
  in a line and call no tools. There's no "blocked by hook" popup, and the
  input box isn't refilled.
- **Values** (`secret add/up`, `sudo add/up`) come from `web_form.ask(…)`, a
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
{"version": 1,
 "secrets": {"HF_TOKEN": {"value": "…", "description": "…", "hosts": ["huggingface.co"], "updated": "…"}},
 "sudo": {"admin@myserver": {"user": "admin", "host": "myserver", "password": "…", "updated": "…"}},
 "sudo_enabled": ["…hosts enabled in every session…"],
 "sudo_session": {"myserver": ["<session ids>"]}}
```

The host is normalized (`127.0.0.1`, `::1`, `local` → `localhost`). Host
names must match `HOST_RE`, so a leading `-` (an ssh option) is impossible.
`catalog()` is the only view Claude ever gets.

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
