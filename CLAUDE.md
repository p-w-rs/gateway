# CLAUDE.md: working on gateway

Guide for agents (and people) changing this repo. User-facing docs are in
[README.md](README.md); how it fits together is in
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); why it looks this way (and what
was tried and rejected) is in [docs/DECISIONS.md](docs/DECISIONS.md).

## What this is

A Claude Code plugin (`plugins/gateway/`) published through a local
directory marketplace (`.claude-plugin/marketplace.json`, name `gateway`).
Users install it **straight from their checkout** (`pixi run install`), so any
edit here is live in their next Claude Code session. Be careful, and run the
tests before you stop. The only requirements are Claude Code and pixi; keep it
that way, and keep it working on macOS and Linux (desktop and headless).

## Layout

```
.claude-plugin/marketplace.json   marketplace "gateway" -> ./plugins/gateway
docs/                             ARCHITECTURE, DECISIONS, history/
plugins/gateway/
  .claude-plugin/plugin.json      name, version
  .mcp.json                       MCP server "gw" (stdio, via pixi)
  hooks/hooks.json                SessionStart, UserPromptSubmit, PreToolUse (Bash; gateway tools + file tools)
  hooks/perm.sh                   the plugin's permission rules: allow/ask gateway tools, credential-path prefilter
  hooks/prompt.sh                 fast pre-filter for UserPromptSubmit
  commands/*.md                   slash commands: add, update, delete, enable, disable, block,
                                  list, export, import, help, log
  install.py                      dev only: register this checkout + remove v0.5's settings.json entries (legacy-settings.json)
  config/policy.json              tunables (domains, tiers, size limits)
  pixi.toml / pixi.lock           Python 3.12 + age, all platforms
  run.py                          single entry: server | hook-* | log | check | scrub | gateway finish
  src/gateway/
    policy.py      config, allowlists, redaction/scrubbing, audit log, Bash blocklist
    actions.py     the MCP tools' logic (http, download, port, certs, hash, sudo)
    runner.py      run a CLI as an account: env allowlist, private ssh-agent, one-call
                   credential helper, hardened git config, scrubbed output
    gitops.py      the git / git_confirm / git_identity tools (account by remote URL)
    ghops.py       the gh / gh_confirm tools (the plugin's own gh)
    logins.py      GitHub browser sign-in (gh's web flow), from a setup
    entra.py       Entra sign-in (PKCE / device code) and per-scope tokens
    mirrors.py     git_mirror
    hfops.py, pijulops.py, sshops.py, dbops.py, mlcat.py, regops.py
                   the hf, pijul, ssh_exec/ssh_copy/ssh_hosts, databricks, mlcat*, registry tools
    sshconf.py     the gateway's own ssh_config per call: routes, host-key policy, keys, reuse
    transfer.py    /gate:export and /gate:import: age -p under a private pty, validate, merge
  skills/accounts/SKILL.md        how Claude uses accounts and mirrors (gate:accounts)
  skills/setup/SKILL.md           how Claude guides /gate:add and /gate:update (gate:setup)
    mcp_server.py  hand-rolled stdio JSON-RPC MCP server + tool schemas
    hooks.py       SessionStart note + vault catalog, PreToolUse redirect, prompt hook
    common.py      shared by the commands and gate_setup: validation, account records,
                   list/delete, sudo switches, sign-in, hook output, transcript scrubber
    vault.py       age-encrypted JSON vault (~/.config/gateway), sudo switches, accounts (KINDS)
    setup.py       /gate:add|update|delete|enable|disable|list, setup grants, gate_setup, `gateway finish`
    web_form.py    browser opener + pages for GitHub/Entra sign-ins (no value form any more)
    dialog.py      native dialogs (osascript / zenity / kdialog): confirm a change, type a secret hidden
    cli.py         `run.py log` (the /gate:log viewer), `check`, and `gateway finish GRANT`
                   (a setup, export or import where no dialog can open)
  tests/run_tests.py              single offline test script (no pytest)
```

## Commands

```bash
cd plugins/gateway
pixi run test                    # must stay green; prints "N passed, 0 failed"
claude plugin validate .         # plugin manifest
claude plugin validate ../..     # marketplace manifest
pixi run --frozen python run.py check 'some bash command'   # would the hook redirect it?
pixi run --frozen python run.py log 40                      # audit log viewer
pixi run install --dry-run       # what the dev installer would register / remove
```

The tests are hermetic. They set `GATEWAY_HOME`, `GATEWAY_CONFIG` and
`GATEWAY_AUDIT_LOG` to temp paths, use a fake `sudo`/`ssh` on `PATH`, a fake
browser (`GATEWAY_BROWSER`), and local HTTP servers on 127.0.0.1. They never
touch the real vault, log or network. Add a check for every behavior change,
and when it's a security property, confirm the new check **fails** without
your change (mutation-check it).

## Invariants: don't break these

1. **No secret value ever reaches Claude**: not in tool results, errors,
   hook output, logs or the transcript. Values come from the vault inside the
   server process, are injected into the request or stdin, and are scrubbed
   from responses (`_hide`) and logs (`policy.redact`/`scrub`).
2. **Secrets go only to their allowed hosts.** Redirects drop credentials when
   they cross hosts or downgrade to http (`_GatewayRedirect`). There are no
   `keychain:`/`env:` refs; the vault is the only source.
3. **Claude can't grant itself anything.** Every vault change starts with a
   command the user types (UserPromptSubmit hook; the slash commands are
   `disable-model-invocation: true`). `/gate:add`/`update` open a one-time
   setup grant (in the vault, this session, 15 min); `gate_setup` acts only
   on a live grant and only after the user approves the native dialog, where
   any value is typed. No MCP tool opens a grant, enables sudo, or adds a
   secret or host without one.
4. **Approvals come from Claude Code's permission prompt**, i.e. the plugin's
   own PreToolUse hook answering `ask` (`hooks/perm.sh`: the `*_confirm` tools,
   `port_check`). Switches that skip a prompt (`/gate:enable sudo|reuse|CLASS`)
   exist only as typed commands, stored in the vault. Never rely on MCP
   elicitation forms: the desktop app auto-cancels them without showing them
   (see DECISIONS). Never add a model-settable "approved" parameter.
5. **Root commands**: argv lists only (no shell strings); the password goes
   only to `sudo -v` and the command gets stdin from /dev/null; `sudo -k`
   afterwards; commands the Bash blocklist matches are refused here too;
   `run_privileged` runs only where sudo is enabled (persistently, or for this
   session via `CLAUDE_CODE_SESSION_ID`).
6. **The prompt hook fails closed.** If it can't run, a typed /gate: command
   is blocked, never passed through (`prompt.sh`).
7. **Stdlib only** in `src/`. The only external binaries are `age`/`age-keygen`
   and OpenSSH's `ssh-keygen` (from pixi), the system `sudo`/`ssh`, and the browser.

## Gotchas when working here

- **The plugin is active in your own session.** Its PreToolUse hook blocks any
  Bash command whose text matches the blocklist: `curl`, `wget`, `nmap`,
  `security find…`, `age -d`, `secret get`, the vault path, and so on. That
  includes heredocs, commit messages, `grep` patterns and scripts written
  inline (even `run.py check '…curl…'` gets blocked). Write the content to a file (in your scratchpad) and run that, or
  use `git commit -F file`. Check with `run.py check '…'`.
- **Take-over is always on** while the plugin is enabled: the hook refuses git, gh, hf, pijul, ssh,
  dvc, … in Bash in every session, including yours, and your Bash has no SSH_AUTH_SOCK or
  token variables (SessionStart writes `unset …` to CLAUDE_ENV_FILE). Use the `git` tool then,
  even for local commits (`git commit -F` works through it too). In a session
  whose MCP server predates a tool change, use `git -C` from your own terminal.
- **Plugins can't ship permission rules or env** (only `agent` settings are
  honored); every rule is a hook decision (perm.sh, hooks.py). Hook config
  (hooks.json) loads at session start; the Python behind it runs fresh each call.
- **pixi-guard** (another plugin) refuses `python3` outside pixi here: use
  `pixi run python …`.
- **You can't read the vault** (`Read(~/.config/gateway/**)` is denied) and
  must not try. Use the `secret_list` tool for names.
- **Tool and hook changes need a new session** to be picked up (the MCP server
  and hooks load at session start). Test headless with `claude -p`, or ask the
  user to open a new session.
- **Headless `claude -p` auto-cancels anything interactive**, and so does the
  desktop app for MCP elicitation. Use fakes (`GATEWAY_BROWSER`, `GATEWAY_HOME`)
  for end-to-end checks.
- The `Edit(...config/**)` deny rule only stops the Edit tool. Bash can still
  change `policy.json`, so the rules are a guardrail, not a boundary (see
  ARCHITECTURE, threat model). Don't widen `allow_domains` or tiers without the
  user asking.
- The audit log is shared by all sessions on the machine; entries from other
  sessions are normal.

## Status (2026-10-17, v0.6.0: the v2 rework)

v2 (plan and trackers in `.work/v2/`, local): one strict mode always on,
standard plugin install (rules in the plugin's hooks), short typed commands
(`/gate:add|update|delete|enable|disable|block|list|export|import`, plus
help and log) with guided setup and native dialogs, the gateway's own SSH
config (routes, host-key policy, key rotation, opt-in connection reuse),
export / import, per-account switches. The skills are for Claude only
(`user-invocable: false`). About 790 tests pass; each phase's security
properties are mutation-checked.

Live-tried on macOS (desktop app): every account kind, push/PR/mirror,
setup through dialogs, ssh exec/copy/sudo and reuse, export / import, the
switches. Not yet live: ssh routes (no LAN route here), Linux end to end,
the ACR exchange.

Known limitations:
- The audit log and quarantine live in the plugin data folder
  (`CLAUDE_PLUGIN_DATA`, `~/.claude/plugins/data/gate-gateway`): Claude may
  read them, not edit them. Tests set `GATEWAY_DATA` and `GATEWAY_DIALOG=none`.
- The Bash blocklist is regex-based: false positives (e.g. `git commit -m
  "...curl..."`) and easy bypasses (`c''url`, base64, `nc`). It steers a
  cooperative model; it isn't a sandbox.
- Plain `sudo` in Bash isn't redirected. It can't prompt for a password
  from Claude's Bash, so it only works for NOPASSWD rules; password-based root
  goes through run_privileged.
- The `/gate:` prefix is required (plugin commands can't register a bare
  name).
- Windows isn't supported (no sudo; export needs a pty).
