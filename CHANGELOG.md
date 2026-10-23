# Changelog

What changed in each release of the gateway plugin (`gate@gateway`), newest
first. Versions before 0.9.0 are summarized. How to update:
[README.md](README.md), "Update, disable, uninstall".

## 0.10.0 (unreleased)

Upgrading from 0.9.x: update as usual. Nothing is converted, and your sudo
rights on this computer stay as they are.

### New defaults

- **Sudo on this computer starts as "ask" on new installs.** Claude Code
  asks you each time Claude runs `sudo` here, in every permission mode.
  Sudo from a gateway terminal, a job, `make` or a script is refused,
  because Claude Code can only ask about a command Claude typed. To let
  Claude use sudo here without asking, set `sudo = true` under
  `[hosts.localhost]` and approve it in the gateway's dialog (`gate check
  localhost`). Remote hosts are unchanged.
  - Existing installs keep the old default (`true`). The vault records which
    kind of install it is.
  - A machine that never stored anything in the gateway's vault counts as a
    new install: a `sudo = true` an older version wrote there waits for one
    `gate check localhost`.
  - While the vault is locked, sudo here asks until you unlock it with
    `/gate-unlock`.
  - An import from another machine adds a host for the machine the file came
    from; its sudo is now "ask" unless the file says otherwise.
- **ML catalog accounts need `host`.** The `ml-catalog` kind has no default
  host any more. An account without `host` is off until you add one; an
  account converted from 0.6 keeps its sign-in once you do. Its DVC site
  cache moved to `~/.local/share/asiml/site-cache`.

### What the gateway approves on its own

When the gateway approves a call, Claude Code doesn't ask. Its approvals of
Bash commands apply in auto and bypass mode only. Anything it no longer
approves goes to Claude Code's prompt or reviewer; it is not refused.

- The gateway's `http` and `download` tools are no longer approved by the
  gateway, in any mode. Claude Code's permission mode decides, as for any
  tool: you're asked in default and plan mode, the reviewer decides in auto
  mode.
- Plain reads (`cat`, `head`, `tail`, `grep`, `ls`, `wc`, `sort`, `uniq`,
  `test`, `pwd`) are approved only when every file they read is a plain file
  in the project or a temp folder. Not approved: hidden files,
  credential-like names (`.env`, `*.pem`, `id_*`, `*token*`, `*.tfstate`,
  ...), anything under `~/.ssh`, `~/.aws`, `~/.config`, `~/.claude` and the
  like, and reads under `env -C` or `sudo -D`. The same rule applies under
  sudo. Examples: `cat README.md` in the project is approved; `cat
  ~/.aws/credentials`, and `grep -rn password .` in a folder that holds a
  `.env`, go to Claude Code.
- `gate forget` is no longer approved without a prompt.
- Refused now, in every mode: a path starting with `~-` or `~2` (the
  shell's directory stack), since the gateway can't tell where it points.

### Managed shell

- The check for routes around the gateway's stand-ins is more precise. A
  tool's path counts only where it would run, so `sudo rm
  /usr/local/bin/gh` and `sudo cat /etc/ssh/sshd_config` are no longer
  refused.
- A shell string whose command is a variable (`bash -c "$CMD"`) is refused.
  The message says to write the command out (`bash -c 'make test'`).
- `sudo arch -arm64 make install` is judged as `make install`.
- These refusals now say how to turn managed mode off if you really need the
  system's own tool (`[shell] managed = "off"`, with your OK in the dialog).
- Claude is told which tool folders (on your login PATH, or where common
  toolchains install) aren't imported into the managed shell, and proposes
  importing one when the work needs it (never without your OK).
  `import_path = []` under `[shell]` stops the offer. `/gate-doctor` and
  `gate status` list them.
- When Claude's commands can't run yet, the message says why: still setting
  up, setup failed (with the log's path), pixi not installed, or the data
  folder gone after an uninstall (restart Claude Code).

### Secrets and the vault

- `gate rotate` keeps an encrypted copy of the vault before it changes it,
  in `~/.config/gateway/private/backups/rotate-*.vault.age` (the newest 5).
- `gate forget` keeps no copy. It names older copies that may still hold the
  secret (rotate's, imports', the 0.6 conversion's) and gives the command to
  delete them.
- Vault writes are flushed to disk before they replace the old file.
- On Claude Code's main screen (not fullscreen, or inside tmux) the dialog
  says its field can't take keys there, and gives one way in: Paste from
  clipboard (`/gate-dialog`, then Tab and Enter). Paste leaves the value on
  your clipboard; a toast reminds you to clear it.
- On Linux without a display, the dialog says Paste can't work, and how to
  type the secret instead (start Claude Code with `CLAUDE_CODE_NO_FLICKER=1`).
- `/gate-doctor` has a "Secrets here" line: what works in this terminal.

### Fixes

- Claude Code installed with npm (`@anthropic-ai/claude-code`) is
  recognized. `/gate-doctor` shows which install it found.
- A run folder (`/tmp/gw-<uid>`) the gateway can't use is reported with the
  reason and the fix, also by the ssh, scp and sftp stand-ins. One that
  other users could write to must be removed (`rm -rf`), not chmod'ed. The
  gateway never talks to a daemon socket that isn't yours.
- A second Claude Code configuration (`CLAUDE_CONFIG_DIR`) on the same
  account gets a message saying the gateway's daemon serves the other one;
  `/gate-doctor` and `gate status` there say so too.
- On a Linux machine without a display, the note about Paste no longer
  pushes the hosts' and accounts' details out of Claude's session context.
- Refusal texts no longer mention one-time codes or a pop-up, and plain
  reads get their own reason.
- The marketplace description no longer calls it internal.

### Docs

- Developer documentation and design history moved to `docs/dev/`.
- New: this changelog, [SECURITY.md](SECURITY.md), and
  [docs/CONFIG.md](docs/CONFIG.md) with every setting.

## 0.9.1 (2026-10-21)

- Uninstalling while gateway terminals or jobs run no longer kills them. The
  gateway's helper (gated) stops taking new work and lets them finish. It
  resumes jobs a pause had suspended (on other hosts too, through the
  system's ssh), then exits with its tmux server. Its log lines go to
  `~/.config/gateway/run/gated-drain.log`, which an uninstall keeps.
- gated stops its tmux server and watchdog when it exits with nothing
  running. The watchdog stops the server once gated is gone, also after a
  crash.
- A job's stop or suspend is recorded only when it held. A job the helper
  resumed after an uninstall shows as running.
- Claude Code removing an old version folder after an update is no longer
  taken for an uninstall.
- "ready" shows as a toast instead of a status line with a warning sign.
- The managed shell no longer runs `~/.bashrc` when Claude Code was started
  without `SHLVL` (seen on Debian).
- Claude reads a terminal's rows as drawn, so a command line that exactly
  fills its rows isn't glued to its output. A secret split across a wrapped
  row is still masked.

## 0.9.0 (2026-10-21)

The first published version since 0.6.0. The first session converts a 0.6
vault automatically, with a backup first (README.md, "Update, disable,
uninstall").

- **Hosts and accounts in one form**, `~/.config/gateway/gateway.toml`.
  Claude runs `sudo`, `ssh`, `scp`, `rsync`, `git`, `gh`, `hf` and the like
  as usual; stand-ins supply the credential from an age-encrypted vault
  Claude can't read. Giving Claude more needs your OK in the gateway's
  dialog; taking away applies at once.
- **gated**, a helper daemon per user, holds the vault key. You can protect
  the key with a passphrase (`/gate-unlock`, `/gate-lock`).
- **Every question is a dialog inside Claude Code.** Secrets are typed into
  a private field. OS dialogs, `gate secret`, and browser or device-code
  sign-ins are gone: GitHub takes a personal access token, Azure a service
  principal.
- **The managed shell**: Claude's commands run in the gateway's own bash with
  a clean environment, not your login shell. `[shell]` imports the tools you
  want.
- **Terminals and jobs** you can watch and take over (`/gate-terminal`),
  also on other hosts, in a small runtime the gateway sets up there.
- **Workspaces and policy**: allow, ask or deny per host, workspace, account
  and action. Account states for GitHub, Hugging Face and Azure.
  `/gate-hosts` and `/gate-accounts`.
- **Export and import** format 3: pick items, a digest, a staged import with
  a backup. Older files still import.
- **No sudoers rule.** The gateway no longer sets up sudo without a password.
  A rule an older build installed stays until you remove it.
- Needs Claude Code 2.1.287 or newer (terminal) or 2.1.286 (desktop), and
  pixi 0.68.0 or newer. Installs use `pixi install --locked`.

## 0.8.0 (development build, not published, 2026-10-20)

Built from a checkout only; everything here shipped in 0.9.0. Since 0.7.0:
the mod (status line, setup at session start, `/gate-doctor`), gated and
the vault broker, native dialogs and the managed shell; new in this version:
terminals and jobs under the gateway's own tmux, and the runtime on other
hosts.

## 0.7.0 (development build, not published, 2026-10-18 to 2026-10-19)

v3, "hosts and accounts": one form, stand-ins on Claude's PATH, an age
vault, consent that never widens without your OK. Shipped in 0.9.0.

## Earlier versions

- **0.6.0** (2026-10-17, tag `v0.6.0`): one mode with every rule in the
  plugin; short commands (`/gate:add`, `/gate:update`, `/gate:delete`,
  `/gate:enable`, `/gate:list`) with guided setup in OS dialogs; the
  gateway's own SSH setup (routes, pinned host keys, key rotation);
  encrypted export and import.
- **0.5.0** (2026-10-17): accounts: git and gh with GitHub sign-in, Hugging
  Face, Pijul, SSH hosts with sudo, Azure (Entra) and Databricks, an ML model
  catalog, container registries.
- **0.4.0** (2026-10-17): vault v2 and `/gate:account`.
- **0.3.0** (2026-10-15): the first version, as net-gateway: one audited
  path for Claude Code's network, credential and sudo work. Renamed to
  gateway (plugin `gate`, commands `/gate:*`) the same day.
