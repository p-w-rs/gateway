# Changelog

What changed in each release of the gateway plugin (`gate@gateway`), newest
first. Versions before 0.9.0 are summarized. How to update:
[README.md](README.md), "Update, disable, uninstall".

## 0.11.1 (2026-10-26)

Fixes from installing 0.11.0 from GitHub on macOS and Linux.

- **gateway.toml is written when the first setup finishes**, as the README
  says. It used to appear only when the next session started, and
  `/gate-doctor` said "not written yet" until then.
- **A pixi that is too old**: what Claude is told at session start, and what
  the gateway's commands and `~/.config/gateway/gate` say, now give both ways
  to update it: `pixi self-update`, or your package manager for a Homebrew or
  MacPorts pixi (where `pixi self-update` refuses). The notice for a command
  that runs without the managed shell's settings now says pixi is too old
  and how to update it, instead of "setup failed; it is retried at the next
  session start".
- **"found here but not imported"** (`gate status`, `/gate-doctor`, Claude's
  session context) no longer lists folders already on Claude Code's own
  PATH, such as `~/.local/bin`.
- **0.11.0's "Before you update" corrected**: removing the marketplace also
  uninstalls the gateway and deletes its data folder, so the 0.6-vault steps
  now end by installing the gateway again (`claude plugin install
  gate@gateway`).

## 0.11.0 (2026-10-26)

The gateway now stands only between Claude and the machines and accounts in
your gateway.toml. Everything else uses your own tools, untouched; network
commands are still asked about by default. Only the latest release is
supported: nothing older is converted (a 0.6 vault, export formats 1 and 2),
and approvals recorded before 0.9 aren't read (those of 0.9 and 0.10 are
kept).

### Before you update

- **Still on a gateway 0.6 vault (`~/.config/gateway/store.age`)?** Convert
  it with the published 0.10.0 first. 0.11.0 refuses to create a vault beside
  a 0.6 one: it says so at session start and in `gate status`, and every
  `gate` command but `status`, `log`, `why`, `import-ssh`, `lock` and `scrub`
  refuses. To convert: `claude plugin marketplace remove gateway`, `claude
  plugin marketplace add p-w-rs/gateway#v0.10.0`, `claude plugin install
  gate@gateway`, and start one session (it converts the vault and keeps the
  old one in `private/backups/`). Removing the marketplace also uninstalls
  the gateway and deletes its data folder (the built tools and the audit
  log; the next session builds the tools again); `~/.config/gateway`, with
  the vault, stays. If 0.10.0 put converted entries in
  `gateway.from-v2.toml`, copy the ones you want into gateway.toml while
  0.10.0 runs: 0.11.0 treats an entry copied in later as new (`gate check
  NAME`, and an account's credential is asked for again). Then remove the
  marketplace again, add it without the tag (`claude plugin marketplace add
  p-w-rs/gateway`) and install the gateway again (`claude plugin install
  gate@gateway`).
- **pixi 0.83 or newer** (`pixi self-update`, or your package manager for a
  Homebrew or MacPorts pixi) and **the latest Claude Code**
  are required. With an older pixi the gateway says "pixi self-update"
  (status line, `/gate-doctor`, `gate status`).

### Only what you configure goes through the gateway

- **ssh, scp, sftp, sudo, git, gh, hf, databricks, crane, pijul, az, asiml
  and dvc** reach only the hosts and accounts in gateway.toml through the
  gateway. A stand-in is on Claude's PATH only for a tool that can reach
  something configured, so a new install shadows nothing. Anything else
  (another server, a GitHub owner no account serves, your own sudo) runs
  your own tool with your own keys, agent and tokens, and the gateway makes
  no decision.
- **ssh by another name is refused, not routed**: an alias, IP address,
  ProxyJump or ProxyCommand that reaches a configured host gets "use `ssh
  homelab`". A copy between a configured and an unconfigured host is refused
  ("copy in two steps").
- **This computer's sudo is your own** unless gateway.toml sets
  `[hosts.localhost] sudo`. Your own sudo works for Claude only where it
  needs no password (Claude has no terminal to type one). To have the gateway
  ask for the password in its dialog: `gate host set localhost sudo ask`.
  - A form that 0.10.0 wrote with `sudo = "ask"` keeps going through the
    gateway as before.
  - An approved `sudo = true` runs as `"ask"` until you approve it again
    (`gate check localhost`).
  - No `sudo` key: your own sudo. A sudo password the vault still holds stays
    unused (the first session says so once); `gate forget localhost` removes
    it.
  - While this computer's sudo goes through the gateway, `su`, `doas`,
    `pkexec`, `runuser`, `sudoedit` and `osascript ... with administrator
    privileges` are refused ("use sudo").
  - While the vault is locked, that sudo is refused until you unlock it with
    `/gate-unlock`, like the hosts and accounts in gateway.toml. It used to
    ask first and then fail.
- **A global `[policy]` deny binds only what gateway.toml configures.**
  `read`, `exec`, `write` or `credential` set to deny in `[policy]` now
  reaches only its hosts and accounts; anything else is your own. The first
  session says so once.
- **Removing a host or account, or part of one, waits for your OK.**
  Deleting or renaming an entry, dropping an address, owner or jump host,
  adding `when`, or deleting localhost's `sudo` key would take it out of the
  gateway, so the approved entry keeps going through the gateway until you
  approve (`gate check NAME`). A removed account keeps using its approved
  sites until then. Narrowing a right still applies at once. A missing or
  broken gateway.toml never lets a configured entry through: the last good
  version applies, else those entries are refused.
- **Account CLIs** decide by destination as the tool would (gh's `-R`,
  `GH_REPO`, `GH_HOST` or the repository's remote; hf's repo owner; the
  Databricks workspace; the registry). One the gateway can't place (`gh api
  /user`, `hf whoami`) uses the account when one exists. Run by its path
  (`/usr/local/bin/gh`), a tool is refused while an account of that kind
  exists: run it by its name. `huggingface-cli`, hf's older name, is refused
  by any name while a Hugging Face account exists: use `hf`. `dvc` goes to
  asiml only for `pull` and `push` in an asiml workspace.
- **An account that lists `owners` serves only those and its `login`.** The
  only account of its kind serves every owner only while it lists none (or
  with `default = true`), so with one work account for `example-org` your
  personal repositories use your own git and gh, never its key. Listing the
  first owner of such an account waits for your OK.
- **An `"ask"` holds only for the command Claude Code asked you about.**
  For each ssh, sudo, git, account-tool or `gate` command it asks about,
  the gateway notes the exact words, folder and Claude Code session; the
  stand-in honours your OK only for that command, once, within 15 minutes
  and before Claude's next command (a note left by a prompt you declined,
  or by a part of the command that never ran, is dropped then). What a
  sourced file, `eval`, a function or `bash -c "$CMD"` runs is refused
  ("run `ssh homelab ...` as its own command"), and such commands get no
  prompt of their own any more (`source .venv/bin/activate && pytest` runs
  as usual). A command the gateway would ask about but whose words it can't
  spell out (a variable or glob in them, a `cd` it can't follow) is
  refused before it runs. An account's `use = "ask"` now works for its
  tool too: `gh pr list` asks about the account gh will use, then uses it.
- **Commands that hide their program or host** are refused when they name a
  configured host or account. `xargs`, `parallel` and `find -exec` are
  judged the same way. Otherwise they are yours; the rarer spellings the
  gateway misses are listed in docs/dev/modules/managed.md.
- **Program names in any letter case** count as the tool (macOS's file
  systems ignore case): `CURL`, `SSH homelab`, `/usr/bin/SSH homelab`,
  `Sudo` and `GH` are judged like `curl`, `ssh`, `sudo` and `gh`.

### Settings for each Claude Code mode

- **Every right and restriction can differ by permission mode**: `ssh`,
  `sudo`, an account's `use`, the policy keys `read`, `exec`, `write`,
  `network`, `elevation` and `credential`, and `[network] commands`. Write
  a table, for example `sudo = { default = "ask", auto = true, plan = false
  }`, or from chat, `/gate-hosts` or `/gate-accounts`: `gate host set
  homelab sudo default=ask auto=true`, `gate account set github-work use
  default=ask auto=true`, `gate policy set all write default=ask
  bypass=deny`, `gate network commands default=ask auto=cc`. The modes are
  `default` (also `manual`), `plan`, `acceptEdits`, `auto`, `bypass` (also
  `bypassPermissions`) and `dontAsk`.
- **The words**: `true`/`"allow"` (the gateway approves; on a policy key,
  no restriction), `"cc"` (Claude Code decides), `"ask"` and
  `false`/`"deny"`. A plain `true` on a right keeps its meaning: the gateway
  approves in auto and bypass mode only. Approving in another mode takes an
  explicit table entry; plan mode never approves.
- **The consent dialog says, mode by mode, what changes** ("sudo on this
  computer: in Auto and Bypass permissions modes the gateway now approves
  without asking you; elsewhere Claude Code decides (was: asks you in every
  mode)"). A dialog longer than one screen comes in parts, like the import
  confirm: each part fits about 40 rows of a docked pane, and the question
  beside its buttons says which part it is ("Part 1 of 3").
- **Jobs, gateway terminals and scripts** have no mode: they get the
  strictest value of every mode but plan, so an `"ask"` in any of those
  modes is refused there. A job's network commands are judged in the mode
  you started it from (an `"ask"` there is refused).
- **dontAsk**: Claude Code refuses what it decides itself unless your
  permission rules allow it (a plain `true` is `"cc"` there), a table's
  `dontAsk = "allow"` is approved by the gateway, and `"ask"` still asks you
  (Claude Code 2.1.310 shows the gateway's question there too) and runs
  after your OK.

### Network commands

- **curl, wget, nmap, masscan, nc, socat, telnet, certutil, tcpdump, tshark,
  nikto, sqlmap, hydra, gobuster, ffuf, nuclei, arp-scan, iperf3 and the
  rest** (and shapes such as `openssl s_client`, `python -m http.server`,
  `/dev/tcp`, `rsync://`) are one class, asked about by default in every
  mode, including behind sudo, in subshells, `bash -c` strings and `ssh HOST
  CMD`. curl and wget are no longer refused. `[network]` sets it per mode
  and adds or drops names; an explicit `allow` lets the gateway approve
  them in that mode. In bypass mode, where "ask" still prompts: `gate
  network commands default=ask bypass=cc auto=cc`.
- The `http` and `download` tools follow the `network` policy: refused or
  asked where it says so, approved only where you wrote an explicit per-mode
  allow, else Claude Code decides.

### git

- **git is a stand-in when a host or a git account is configured.** In a
  repository with a remote the gateway handles, and for a clone of one,
  every git command runs the gateway's git with its own read-only global
  config (your `~/.gitconfig` and `/etc/gitconfig` don't apply there), an
  allowlisted environment (no proxy, CA or askpass variables) and the
  account's identity. Everywhere else your own git runs untouched.
- **Commits there carry your own identity** when the account names no
  `name` or `email`: your `user.name` and `user.email` as your own git reads
  them in the repository the command works on (`git -C other commit` uses
  `other`'s), passed in git's environment (never on a command line). With
  neither, git refuses to commit instead of guessing `you@hostname`
  (`user.useConfigOnly`). Commands that never commit (`status`, `diff`,
  `log`, `fetch`, ...) don't run your git for it.
- Pushes and fetches to a configured remote are judged before they run, so
  one you approved in Claude Code's prompt no longer fails afterwards.
- In such a repository, a `!` alias, a `-c` that sets credentials or the ssh
  command, and `git config` writes to `credential.*`, `url.*`,
  `remote.*.url`, `include*`, `core.sshCommand`, `core.hooksPath` and the
  like are refused. Local commands (status, log, commit) still run while the
  vault is locked or the entry has a mistake; anything that contacts the
  remote is refused then.
- `GIT_SSH_COMMAND`, `RSYNC_RSH` and the git include no longer go into
  Claude's shell.

### Claude's shell

- **The managed shell keeps your environment**: bash 5 with your variables
  and PATH (and your aliases and functions from a bash snapshot), minus
  Claude Code's own credentials and the variables that make a shell run
  code at start. The stand-ins can't be shadowed by an alias or function.
- **Your own credentials now reach Claude's shell** (`SSH_AUTH_SOCK`,
  `GH_TOKEN`, cloud tokens): they are yours, for your own tools. Their values
  are masked in output. For a configured host's limits to bind, your own key
  or token must not also open it (README, "Security and privacy").
- **Not ready yet** (first setup, pixi too old, its settings missing):
  commands run without the gateway's settings in the shell that made
  Claude Code's shell snapshot (zsh or bash, found the way Claude Code
  finds its shell: `CLAUDE_CODE_SHELL`, your `SHELL`, then PATH and the
  usual places; never `/bin/sh`) with a one-line notice naming that shell
  and why, instead of being refused. With no such shell the command isn't
  run.
- **Mods off**: no blanket refusal. Commands run in your own shell with a
  notice once per session, and the hooks still judge every command.

### checkpoint jobs

- **A checkpoint job the gateway runs gets the environment checkpoint sends**
  (CONTRACT-v1's `POST /v1/jobs` takes `env`, feature `job_env`), minus
  Claude Code's credentials and the shell's startup variables, with the
  stand-ins first on its PATH. Before, it got only the gateway's PATH,
  so a tool such as `pixi` outside the system folders wasn't found.
  Variables a job can't take (an exported shell function, a value over
  8192 characters) are skipped; the job still starts.

### Browser sign-in (SSO)

- **Azure accounts with `sign_in = "browser"`** (and a public client's
  `client_id`) and **ML catalog accounts** sign in through your system
  browser. The gateway's dialog asks first (Open or Cancel); the browser
  opens only after Open, the answer comes back to a listener on 127.0.0.1,
  and the tokens go straight into the vault. Browser-automation tools are
  refused while a sign-in runs. There is no device-code sign-in, and none
  without a display.
- A changed `sign_in`, `tenant`, `client_id` or `scope` waits for your OK
  and needs a new sign-in; the old credential isn't used meanwhile.

### Secrets

- **The vault passphrase is offered** after you store a secret, until you
  answer: Set passphrase, or Not now (never asked again; `/gate-unlock` sets
  one later).
- **Output of every tool is masked**: WebFetch, Read, Grep, the Browser
  pane, Claude in Chrome, the Terminal panel, every MCP server, besides Bash.
  The values of credential-named variables in Claude Code's environment are
  masked too.
- **AskUserQuestion is refused when it asks for a secret** (a password,
  token, API key, PIN, ...): secrets go only into the gateway's dialog.
- **A sudo password typed in the dialog**, for this computer or a remote
  host, is used once unless you tick Remember it (the box starts unticked).
- **`gate with NAME -- CMD` follows the account's `use` and credential
  policy** in the current mode: off refuses, `"ask"` asks first (it used
  to hand the key over whatever they said).
- **This computer's sudo, when the gateway runs it, gets a short allowlist
  of your environment** (PATH, HOME, USER, LANG, TMPDIR, TZ, TERM, the
  editor `sudo -e` runs and the like), never all of it: `sudo -E` keeps
  only that, not your tokens.
- **Vault care from chat, each after your OK in the gateway's dialog**:
  `gate forget --backups` deletes the older vault copies that `gate
  forget`, `gate rotate` and an import leave in `private/backups` (it lists
  them first); `/gate-unlock` on an unlocked vault, or `gate passphrase`,
  changes or removes the passphrase; `gate passphrase --start-over` starts
  a vault whose passphrase is lost over (the old vault and key move into
  `private/backups`, nothing is deleted), so your last export can be
  imported; the unlock dialog and the "vault is locked" messages name it.
- **Typing a secret**: the dialog says to type `/tui fullscreen` (Claude
  Code's own command, which restarts and resumes the session) instead of
  quitting and restarting with an environment variable.

### Export and import

- **Settings** (`[shell]`, `[policy]`, `[network]`, `[vault]`) are approved
  in the import's one dialog instead of being left waiting.
- **This machine's settings** (`[hosts.localhost]`: sudo, scripts, policy,
  workspaces) are an export item, unticked by default; on import you keep or
  replace them.
- The import confirm lists every grant, import and workspace a new host
  brings, and comes in parts when it is longer than one dialog. Nothing is
  imported until you accept the last part.
- **Import inside a Claude Code session** (Claude runs `gate import FILE`):
  the dialog can't open in a plain terminal, and the messages now say so.
- A browser sign-in isn't exported: after an import the account needs a new
  sign-in (`gate login NAME`).

### Removed (no backward compatibility)

- `[settings]` and its `others` key (a written one is a warning).
- `[shell] managed = "warn"` (a written one is a mistake and counts as
  `"on"`).
- The refusal of every Bash command without the managed shell ("managed
  shell unavailable"), and the "set `[shell] managed = off`" escape in
  refusals.
- The refusal of curl and wget.
- The 0.6 conversion, `gate migrate`, `gate status --report`, and approvals
  of 0.6 entries never copied into gateway.toml.
- Export formats 1 and 2 (0.10.0 imports them).
- The older-install sudo default (`true` for installs 0.9.1 set up).
- Claude Code installed with npm before 2.1.113 (node running `cli.js`).
- The minimum Claude Code and pixi versions: only the latest is supported
  (docs/CAPABILITIES.md's "minimum" column is gone too).
- Reading approvals recorded before 0.9 (they lack the managed shell's
  settings): such a record approves nothing, so its entries wait for your OK
  (`gate check NAME`). Approvals from 0.9 and 0.10 are read.
- The leftovers of `gate secret` (removed in 0.9.0): `gate secret NAME` is
  now an unknown command, with no rule of its own in the approval hook.

## 0.10.0 (2026-10-23)

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
