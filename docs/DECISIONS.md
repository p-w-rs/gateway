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
- **Chosen:** only user-typed `/net-gateway:secret` and `/net-gateway:sudo`
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
- **Chosen:** a separate age key and store at `~/.config/net-gateway`, with
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
