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

- **What it is.** Claude uses this computer's sudo, the user's other machines
  over ssh, and their accounts (GitHub, Hugging Face, Azure / Databricks, the
  ML Catalog, Pijul, container registries, API keys) with ordinary commands.
  The gateway puts the password, key or token into that one command, sends it
  only where the user allowed, and keeps the values in an encrypted vault
  Claude can't read.
- **The form.** `~/.config/gateway/gateway.toml` lists hosts and accounts and
  what Claude may do: `true` (no prompt), `"ask"` (Claude Code asks each time
  Claude runs that ssh or sudo itself; scp, rsync, git and scripts are then
  refused for it) or `false` (refused). The user can edit it or ask Claude to. Taking
  rights away works at once; adding a host or widening a right waits for their
  OK in the gateway's dialog, a pane inside Claude Code (Approve / Decline).
  Secrets are typed only in that dialog (click its field, then type; or
  Paste from clipboard), never in chat. In `claude -p`, VS Code or the
  mobile app no dialog can open: the gateway says so and asks nothing.
  `/gate-dialog` shows a dialog that is waiting; `/gate-unlock` and
  `/gate-lock` unlock and lock the vault.
- **What Claude runs.** `sudo ...`, `ssh HOST CMD`, `scp`, `rsync`, `git`,
  `gh`, `hf`, `databricks`, `crane`, `pijul`, `asiml`; the `http` and
  `download` tools for the web (curl and wget are refused). In auto mode,
  sudo, ssh and the gateway's own commands for what the form allows run with
  no prompt; everything else goes through auto mode as usual.
- **Where Claude's commands run.** In the gateway's own bash (no login
  profile, aliases or tokens; PATH: the gateway's stand-ins, bash, pixi, the
  system folders). The user's own tools come in only as imports they approve:
  `[shell] import_path` / `import_env` in the form ("give Claude my Homebrew
  tools"); `[shell] managed = "off"` gives Claude Code's own shell back.
  `/gate-doctor` shows the managed shell's PATH and imports.
- **Policy and workspaces.** Finer rules than the rights: `"allow"`,
  `"ask"` or `"deny"` per host, workspace, account and action (read, exec,
  write, network, elevation, credential use, imports, provisioning,
  forwarding) in `[policy]`, `[hosts.NAME.policy]`,
  `[hosts.NAME.workspaces.W]` (a named folder on a host, with the matching
  folder here) and `[accounts.NAME.policy]`. The strictest rule wins, every
  refusal names the rule, and loosening one waits for the user's OK like any
  widening. ssh agent, X11 and -R/-W forwarding only where a host's own
  policy turns it on. This is the gateway's own policy, separate from Claude
  Code's permission modes. `/gate-hosts` and `/gate-accounts` show hosts,
  workspaces, accounts and their state, and edit them.
- **sudo.** The gateway never changes the machine's sudo rules: sudo that is
  already passwordless is used as it is; otherwise the password is stored or
  asked for each time in the gateway's dialog ("Remember it" unticked: used
  once). The approval shows whom sudo runs as, and where.
- **Examples to ask for.** "Add my server homelab at 192.168.1.20, user alex,
  with sudo." "Ask me before sudo on homelab." "Add my work GitHub for the
  acme-corp repos." "Add my OpenAI key." "Import my servers from
  ~/.ssh/config." "Add a workspace app on homelab at /srv/app." "Don't let
  Claude write to homelab." "Export my gateway (only the GitHub account)."
  "Copy my gateway to homelab."
- **When something goes wrong.** `gate status` (or `/gate:status`) shows
  everything, `gate why` explains the last refusal, `gate log` shows what the
  gateway did. In the user's own terminal: `~/.config/gateway/gate status`.

End with: `/gate:status` shows what the gateway holds now.
