---
description: Quick guide to the gateway - what it does and how to ask for hosts and accounts
argument-hint: "[question]"
disable-model-invocation: true
---

Give the user a short, friendly guide to the gateway plugin (about one
screen) from the reference below. If they asked a question after the command
($ARGUMENTS), answer that instead. Never ask for a password, token or key in
chat, and don't run commands for this.

Reference:

- **What it is.** Claude uses the machines and accounts the user names in
  the gateway's form (this computer's sudo, other machines over ssh, GitHub,
  Hugging Face, Azure / Databricks, an ML model catalog behind Microsoft
  Entra ID with its `asiml` CLI, Pijul, container registries, API keys) with
  ordinary commands. The gateway puts the password, key or token into that
  one command, sends it only where the user allowed, and keeps the values in
  an encrypted vault Claude can't read. Anything the form doesn't name uses
  the user's own ssh, git, gh, sudo and account tools, untouched. Out of the
  box the only thing the gateway asks about is network commands (below).
- **The form.** `~/.config/gateway/gateway.toml`. Each right (`ssh`, `sudo`,
  an account's `use`), policy key and `[network] commands` is a word or a
  table by Claude Code permission mode (default/manual, plan, acceptEdits,
  auto, bypass, dontAsk): `true` (the gateway approves; on a policy key, no
  restriction), `"cc"` (Claude Code decides), `"ask"` (Claude Code asks
  each time) or `false` (refused). A plain `true` approves in auto and
  bypass mode only. Example: `sudo = { default = "ask", auto = true }`.
  The user edits it, asks Claude, or uses
  `/gate-hosts`. Taking rights away works at once; adding, widening or
  removing an entry waits for their OK in the gateway's dialog, a pane
  inside Claude Code (Approve / Decline), which says what changes in each
  mode. Secrets are typed only in that dialog (click its field, then type;
  or Paste from clipboard), never in chat. In `claude -p`, VS Code or the
  mobile app no dialog can open: the gateway says so and asks nothing.
  `/gate-dialog` shows a dialog that is waiting; `/gate-unlock` unlocks the
  vault (or sets, changes or removes its passphrase) and `/gate-lock` locks
  it.
- **What Claude runs.** `sudo ...`, `ssh HOST CMD`, `scp`, `rsync`, `git`,
  `gh`, `hf`, `databricks`, `crane`, `pijul`, `asiml`; the `http` and
  `download` tools for the web. Network commands (curl, wget, nmap, nc, ...)
  are asked about in every mode unless `[network]` in the form says
  otherwise (`gate network commands default=ask bypass=cc`). Azure and the
  ML catalog can sign in through the system browser: the gateway's dialog
  asks first (Open), and the tokens go straight into the vault.
- **Where Claude's commands run.** In the gateway's bash 5 with the user's
  own environment and PATH, the gateway's stand-ins first for what the form
  names, and Claude Code's own credentials removed. `[shell] managed =
  "off"` gives Claude Code's own shell back. `/gate-doctor` shows the
  managed shell.
- **Policy and workspaces.** Finer rules than the rights, also per mode:
  `"allow"`, `"cc"`, `"ask"` or `"deny"` per host, workspace, account and
  action (read, exec, write, network, elevation, credential use, imports,
  provisioning, forwarding) in `[policy]`, `[hosts.NAME.policy]`,
  `[hosts.NAME.workspaces.W]` and `[accounts.NAME.policy]`. The strictest
  rule wins, every refusal names the rule, and loosening one waits for the
  user's OK. This is the gateway's own policy, separate from Claude Code's
  permission rules. `/gate-hosts` and `/gate-accounts` show hosts,
  workspaces, accounts and their state, and edit them.
- **sudo.** On this computer sudo is the user's own unless the form sets
  `[hosts.localhost] sudo`; the user's own sudo works for Claude only where
  it needs no password. With it set (`gate host set localhost sudo ask`),
  the gateway stores the password or asks for it each time in its dialog
  ("Remember it" starts unticked: it is used once; tick it to keep it).
  The gateway never changes the machine's sudo rules. `"ask"` can't be used
  in a gateway terminal, a job or a script, since nobody can be asked there.
  While `[hosts.localhost] sudo` is set, `su`, `doas`, `pkexec`, `runuser`
  and `sudoedit` are refused: use sudo.
- **Examples to ask for.** "Add my server homelab at 192.168.1.20, user alex,
  with sudo." "Ask me before sudo on homelab, except in auto mode." "Have
  the gateway handle sudo here." "Add my work GitHub for the example-org
  repos." "Add my OpenAI key." "Let curl run without asking in bypass mode."
  "Import my servers from ~/.ssh/config." "Add a workspace app on homelab
  at /srv/app." "Don't let Claude write to homelab." "Export my gateway
  (only the GitHub account)." "Copy my gateway to homelab."
- **When something goes wrong.** `gate status` (or `/gate:status`) shows
  everything, `gate why` explains the last refusal, `gate log` shows what the
  gateway did, `/gate-doctor` checks the setup. In the user's own terminal:
  `~/.config/gateway/gate status`.

End with: `/gate:status` shows what the gateway holds now.
