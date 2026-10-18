# Decisions (and what was tried and rejected)

Read this before redesigning anything. Most "obvious" alternatives were tried
on 2026-10-15 and failed for reasons that aren't visible in the code.

## Approvals: Claude Code permission prompts, not MCP elicitation

- **Tried:** the MCP server sent `elicitation/create` forms for yes/no
  approvals and for entering secret values in-app.
- **Failed:** the Claude desktop app (Code tab) **auto-cancels elicitation
  without showing anything**; headless `claude -p` does the same. Claude
  Code's docs only say it "displays an interactive dialog". The logged
  response was `{"action": "cancel"}` every time.
- **Chosen:** separate tools whose settings.json rule is `ask`
  (`run_privileged_confirm`, `port_check`). Claude Code's own prompt appears,
  even in auto mode (verified live). The elicitation code remains for
  policy-tier `ask` and is effectively a refusal in the app.
- **Also rejected:** a model-settable `approved: true` argument, because the
  model could approve itself.

## Entering values: a local browser form

Each of these was tried in order:

1. **Inline in a slash command** (`/secret add NAME VALUE`) with a
   UserPromptSubmit hook that **blocks** the prompt. The model never saw the
   value, but Claude Code showed an error-style "blocked by hook" popup, put
   the typed text (including the value) back in the input box, and wrote it to
   the transcript and history (the docs say a blocking hook "isn't a way to
   keep a secret off disk"). `suppressOriginalPrompt` and a transcript
   scrubber mitigated this but didn't fix the UX.
2. **A native dialog** (osascript/zenity/kdialog) opened by the hook. It
   worked, but the user found it clunky, and the blocking popup remained.
3. **In-app MCP forms**: auto-cancelled (above).
4. **Chosen:** the hook opens a one-time **127.0.0.1 browser page** with a
   masked field, and the command text never contains a value, so the hook
   **passes the prompt through** with the result instead of blocking. No
   popup, nothing refilled, nothing on disk. Blocking plus scrubbing is kept
   only as a safety net for pasted tokens.

## Who manages the vault: the user, via slash commands only

- **Tried:** `vault_*` MCP tools Claude could call ("add my token" → tool →
  form). That needed in-app forms (which fail) or permission prompts per
  change, and it made Claude the actor for security changes.
- **Chosen:** only user-typed `/gate:secret` and `/gate:sudo`
  change the vault. Claude can read the catalog and tells the user which
  command to run.

## Credential sources: the gateway's own vault only

- The gateway started with `keychain:NAME` and `env:VAR` refs, then added
  `age:NAME` reading the user's personal `secret` store
  (`~/.config/secrets/secrets.env.age`).
- **Rejected:**
  - It mixed the user's personal shell secrets with what Claude may use.
  - `env:` could read any variable.
  - `secret_list` exposed every keychain item name.
- **Chosen:** a separate age key and store at `~/.config/gateway`, with
  per-secret allowed hosts. The personal store is blocked from Claude
  (`Bash(secret:*)`, `Read(~/.config/secrets/**)`, …).

## Sudo: a per-host switch, per session or always

- **Tried:** "always allow exactly this command" remembered approvals.
- **Rejected by the user:** they wanted a simple on/off.
- **Chosen:**
  - **Disabled (default):** every root command needs Claude Code's prompt via
    `run_privileged_confirm`.
  - **`/sudo enable HOST`:** no prompts for this session only, keyed on
    `CLAUDE_CODE_SESSION_ID`, which Claude Code gives each MCP server.
  - **`enable HOST always`:** no prompts in every session.
  - **`disable`:** clears both.
- The user accepts the risk while sudo is enabled. A session-start warning
  reminds them.

## Other choices

- **Stdlib Python plus pixi:** the only dependency for users is pixi, which
  pins Python and `age` for every platform. The MCP server is hand-rolled to
  avoid the `mcp` package.
- **`write_request: auto` with `allow_domains: ["*"]`:** the user wants
  `http_request` frictionless. Tightening writes alone wouldn't stop leaks,
  since a GET can carry data too. The real control is per-secret hosts.
- **Regex Bash blocklist:** steers a cooperative model. The user declined
  OS-level sandboxing.

## Accounts (v0.4, 2026-10-17)

The full research and plan are in `.work/accounts/PLAN.md` (local, not in
git). The parts that shape the code:

- **Separate identities, not more secrets.** A secret is one value with
  hosts. An account is an identity of a known kind with settings, a scope
  (hosts + owners), one or more credentials and a prompt policy, so several
  per service can be used side by side.
- **The prompt policy lives in the vault**, per account. `policy.json` can be
  edited from Claude's Bash, so it can't hold the setting that decides
  whether Claude gets asked. Approvals still come only from Claude Code's
  permission prompt (`*_confirm` tools, in later phases).
- **Pasted SSH keys are parsed in Python.** `ssh-keygen -y -f /dev/stdin`
  works from a shell redirect but not from a pipe, and writing the key to a
  file to read it back is what we avoid. Passphrase keys are refused because
  the key goes into a private ssh-agent unattended. Only key generation
  touches a (private, immediately removed) temp file, since ssh-keygen can
  only write files.
- **SSO sign-in waits for its own phase.** For SSO-only GitHub orgs
  (asirobots), gh's own OAuth web flow works, verified 2026-10-17. The
  gateway will run its own pixi `gh` in a temp config dir and move the token
  into the vault, rather than copy gh's client id into our code.

## git, gh and GitHub sign-in (v0.4, phase 3)

- **One `git` tool for all of git.** The user asked for literally every git
  command to go through the gateway. Local commands carry no credentials;
  the cost is one MCP call per command.
- **Accounts are picked by the remote's real URL**, not by what Claude says,
  and a named account must fit the remote's scope. So Claude can't send the
  work token to a personal repo by asking.
- **gh's own web login, run by the hook.** asirobots allows only SSO, and
  gh's OAuth app works there (verified 2026-10-17). gh can only save a
  token in the keychain or a file, so it saves to a file in a 0700 temp dir
  for the few seconds before the hook moves the token into the vault: the
  one place a token touches disk, by gh's design.
- **GHES vs github.com:** any GitHub host other than github.com and
  `*.ghe.com` gets `GH_ENTERPRISE_TOKEN`, as gh expects.
- **Not yet:** pinned host keys per account (ssh accepts new keys per call
  and reports them), commit signing, submodules with credentials, and the
  Bash redirect (phase 9).

## The rest of the accounts plan (v0.5)

- **Optional tools in their own pixi environments** (hf, databricks, dvc,
  registry, pijul), installed on first use. The default environment stays
  small. pijul isn't packaged, so the `pijul` environment builds it with
  conda-forge's Rust (on macOS it links the SDK's iconv).
- **Pijul needs pinned host keys and PIJUL_CONFIG_DIR.** It can't ask about
  a new host key without a terminal, and it ignores HOME/XDG for its config.
  So ssh and pijul accounts pin keys when the user adds them (ssh-keyscan
  in their own command, fingerprints shown; the Nest's key is built in), and
  each call gets a temp config dir with a generated identity.toml. That file
  needs `last_modified`, or pijul skips it silently.
- **No `az` CLI (D3 a).** az can't take an injected token and keeps its own
  plaintext login, so Azure work goes through REST with tokens the gateway
  mints. Databricks takes an Entra token as DATABRICKS_TOKEN.
- **The ML Catalog natively, in asiml's format (D1 c).** asiml keeps its
  login in the keychain and can't be given a token, and has no macOS build.
  The gateway does what asiml does (same `.asiml/workspace.json`), so asiml
  still works on those folders. An upstream PR for `--token-stdin` and
  macOS builds is still to do.
- **Refresh-token rotation is the server's one vault write.** Entra rotates
  refresh tokens; keeping the spent one would break the next sign-in. This
  replaces a value the user already put there and grants nothing new.
- *(v0.5, superseded in v0.6 below: take-over as a switch, strict mode
  through settings `env` and installer-merged rules, a per-command `unset`
  prefix with its allow rule, `config/local.json`.)*
- **Host names aren't tokens.** The paste guard exempts host names
  (`adb-1234567890.7.azuredatabricks.net`) unless they start with a known
  token prefix.

## One mode, rules in the plugin (v0.6)

- **No modes.** The user wants the gateway to be the only way Claude uses
  what it manages. Take-over and the lockdown are always on while the plugin
  is enabled; disabling the plugin is the off switch.
- **Rules are hook decisions, not settings.** Plugins can't ship permission
  rules or `env`: from a plugin's settings, only `agent` and
  `subagentStatusLine` are honored (Claude Code docs, plugin components). So
  the `ask` and `deny` rules became PreToolUse decisions in `hooks/perm.sh`
  and `hooks.files_main`. The installer no longer edits settings.json, and
  install is the standard `/plugin install`.
- **Credential variables are unset through `CLAUDE_ENV_FILE`.** A
  SessionStart hook may append shell lines to it, and Claude Code sources it
  before every Bash command. An `unset` there removed `SSH_AUTH_SOCK` and
  `GITHUB_TOKEN` with no prompt, probed headless with a fake value in the
  parent env. This replaces both settings `env` and the per-command prefix.
- **A sh prefilter keeps file tools fast.** Every Read/Grep/Glob/Edit now
  passes through the hook. `perm.sh` decides gateway tools by name and sends
  only calls that mention a credential location to Python. If Python can't
  run, those calls are denied (fail closed).
- **`~/.ssh/config`, `known_hosts` and `*.pub` stay readable.** Claude needs
  them to help import hosts; private keys, agent sockets and Grep over the
  folder don't.
- **`python -c "import requests"` is fine.** The inline-python rule now looks
  for a call (`requests.get(`, `urlopen(`, `socket.create_connection(`, …),
  not an import.
- **`-u`/`-x` are refused only where they run a program** (`clone`/`ls-remote
  -u`, `rebase -x`), including attached and grouped forms. `add -u`, `push
  -u` and `cherry-pick -x` work.

