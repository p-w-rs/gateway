# gateway

A Claude Code plugin that lets Claude use the machines and accounts you name
(`sudo`, `ssh`, `rsync`, `git push`, `gh`, `hf`, API calls) without ever
seeing a password, key or token. The gateway hands each credential to the one
command that needs it, only where you allowed, and keeps the values in an
encrypted vault. What Claude may do is written in one small file, can differ
for each Claude Code permission mode, and anything that gives Claude more
waits for your OK in a dialog inside Claude Code. Whatever the file doesn't
name stays yours: there Claude runs your own ssh, git, gh, sudo and account
tools, unchanged. Out of the box the gateway asks about one kind of command
only: network commands such as `curl`.

```
You:    Add my server homelab at 192.168.1.20, user alex.
Claude: (adds [hosts.homelab] to gateway.toml and runs gate check homelab)
        The gateway's dialog shows the address, the host key and the rights.
        You press Approve, then "use my own SSH login once" to install Claude's key.
You:    How full is homelab's disk?
Claude: $ ssh homelab 'df -h'
        /dev/sda1   916G  402G  468G  47% /
```

Plugin `gate` in the marketplace `gateway`, version 0.11.1. Sister plugins:
[checkpoint](https://github.com/p-w-rs/checkpoint) and
[pixi-guard](https://github.com/p-w-rs/pixi-guard).

## What changes when you install it

- **Claude's ssh, git, gh, sudo and account tools stay your own until you
  add a machine or account.** A new install's
  `~/.config/gateway/gateway.toml` names nothing. Once you add a host or an
  account, the gateway puts a stand-in for that tool first on Claude's PATH.
  It handles only what gateway.toml names and runs your own tool, unchanged,
  for everything else.
- **Network commands ask first** (`curl`, `wget`, `nmap`, `nc`, `tcpdump`,
  ...), in every permission mode and with nothing configured, also inside
  `ssh HOST CMD` and in any letter case (`CURL`), until you set otherwise in
  `[network]`.
- **Claude's commands run in the gateway's bash 5** (Bash, background
  commands, Monitor, subagents, your `!` commands) with your environment
  and PATH, minus Claude Code's own credentials. Your aliases can't shadow
  the stand-ins.
- **Your own credentials are in Claude's shell** (your ssh agent,
  `GH_TOKEN`, cloud tokens), for your own tools; their values are masked in
  what Claude reads. For a configured host see
  [Security and privacy](#security-and-privacy).
- **Your own sudo works for Claude only where it needs no password**:
  Claude has no terminal to type one. To have the gateway ask you for the
  password in its dialog, ask Claude for it, or run `gate host set localhost
  sudo ask`. The dialog's **Remember it** starts unticked: the password is
  used once unless you tick it.
- **Secrets go only into the gateway's dialog**, a pane inside Claude Code.
  A token pasted into the chat is blocked, a question asking you for a
  secret is refused, and secrets in a tool's output are masked (except a
  failed command's output and Monitor's lines: see
  [Limits](#limits)).
- **The first session sets up for about a minute** (about 400 MB of tools,
  installed into the plugin's data folder; pixi downloads them once into its
  own package cache). Meanwhile Claude's
  commands run in your own shell with a notice, and your configured machines
  and accounts wait for the `ready` notice.

## Requirements

- **The latest Claude Code** (only the latest is supported), in the terminal
  or the desktop app: the dialogs, panes, status line and managed shell are
  a Claude Code mod. Any install works, npm's (`@anthropic-ai/claude-code`)
  included. `/gate-doctor` names the versions this release was tested with.
- **Without mods** (mods switched off for your account), Claude's commands
  run in your own shell with a notice and every check still holds, but no
  dialog can open: nothing can be approved and no secret entered there. Each
  feature per Claude Code surface: [docs/CAPABILITIES.md](docs/CAPABILITIES.md).
- **The latest pixi** (from pixi.sh; `pixi self-update`, or your package
  manager for a Homebrew or MacPorts pixi). `pixi.toml` says
  `requires-pixi = ">=0.83.0"`, the pixi it was locked with, and no upper bound.
  The plugin installs everything else (Python, bash, OpenSSH, git, tmux, age)
  into its own data folder (downloads go through pixi's package cache, as for
  any pixi project). Nothing is installed system-wide, and nothing goes into
  your `settings.json`.
- **macOS or Linux.** Windows only through WSL 2, untested.

## Install

In Claude Code:

```
/plugin marketplace add p-w-rs/gateway
/plugin install gate@gateway
```

Or from a shell: `claude plugin marketplace add p-w-rs/gateway`, then
`claude plugin install gate@gateway`. In the desktop app, add the
marketplace from a terminal, then **+** → **Plugins** → **Add plugin** →
**gate**.

Claude Code needs a git to add a marketplace from GitHub. Without one, pixi
provides it: `pixi global install git` (with `~/.pixi/bin` on your PATH).

### First five minutes

1. Start a new session (type `/tui fullscreen` there if you want to type
   secrets). The line under the prompt shows `⚠ gate: setting up…`
   (Claude Code draws every plugin's status line with ⚠), then a `ready`
   notice appears. The gateway creates `~/.config/gateway/gateway.toml`.
2. Type `/gate-doctor`: versions, setup, the vault, the managed shell, and
   whether this terminal can type into the dialog's field.
3. Ask Claude to add something: *"Add my GitHub account alex"*. Approve in
   the dialog, then enter the token. The gateway then offers to protect the
   vault with a passphrase (Set passphrase, or Not now). Then ask for real
   work.

## Everyday use

You manage the gateway by talking to Claude:

- *"Add my work GitHub (octo-work) for the example-org repos."* The dialog
  takes octo-work's token; example-org's repos use it (every github.com repo
  while it is your only GitHub account).
- *"Add my OpenAI key for api.openai.com, and let my scripts use it as
  OPENAI_API_KEY."* Claude calls the API with the `http` tool, or runs
  `gate with openai -- pixi run python train.py`.
- *"Ask me before sudo on homelab, except in auto mode."* or *"Let curl run
  without asking in bypass mode."* Each right can differ by Claude Code
  permission mode (see [Per-mode values](#per-mode-values)).
- *"Import my servers from ~/.ssh/config."* Adding a host, a right or a
  mode's approval waits for your OK.
- *"Export my gateway."* `gate export` writes one passphrase-protected file
  with what you tick: hosts, accounts, their stored secrets, the settings
  and (unticked by default) this machine's settings. *"Import FILE"* brings
  it into another computer, or back after a reinstall, once you approve
  what it adds. *"Copy my gateway to homelab"* (`gate copy-to homelab`)
  sends it over ssh to a server that has the gateway too.
  [Export and import](docs/CONFIG.md#export-and-import).
- *"Open a terminal on homelab and start the training run there."* A
  terminal (or a job) that outlives Claude's turn, which you can watch; the
  first time, the gateway copies its bash and tmux there (about 50 MB, no sudo).

| You type | What it does (the `/gate-...` commands answer at once, with no model turn) |
|---|---|
| `/gate:status`, `/gate:help` | What Claude has: hosts, accounts, rights, changes waiting; a short guide |
| `/gate-doctor` | Setup, versions, the vault, the managed shell, this surface |
| `/gate-hosts`, `/gate-accounts` | Hosts, workspaces and accounts with their state; edit them (per mode too), check, enter a credential |
| `/gate-terminal [ID\|new]` | Watch or take over a terminal or job (Ctrl-] then c, d, z or [ for ^C, ^D, ^Z, Esc) |
| `/gate-dialog` | Show a waiting dialog again and give it the keyboard |
| `/gate-unlock`, `/gate-lock` | Unlock the vault, or set, change or remove its passphrase; lock now |

In your own terminal, `~/.config/gateway/gate` answers `status`, `why` (the
last refusal and its fix) and `log` (`gate help` lists every command).
Whatever needs your answer (`check NAME`, `login NAME`, `export`, `import
FILE`) runs in a Claude Code session, where the gateway's dialog can open:
ask Claude.

## Configuration

Everything lives in `~/.config/gateway/gateway.toml`. It never holds a
secret.

```toml
[hosts.localhost]       # optional: only to have the gateway handle sudo here
sudo = "ask"            # Claude Code asks me each time; the gateway supplies the password

[hosts.homelab]
address = "alex@192.168.1.20"
sudo    = { default = "ask", auto = true }   # ask, but approve in auto mode

[accounts.github-work]
kind   = "github"
owners = ["example-org"]

[network]
commands = { default = "ask", bypass = "cc" }
```

- Hosts have `ssh` and `sudo` rights, addresses, a jump host (`via`), and
  `scripts = true` to give credentials to programs Claude's commands start.
- Accounts are `github`, `huggingface`, `azure`, `ml-catalog`, `pijul`,
  `registry` or `api-key`. A credential goes only to its account's sites.
  A git account serves its `login` and `owners` (an account that lists
  `owners` serves only those; with none listed, the only account of its kind
  serves every repository there). Azure and the ML catalog can sign in
  through your browser.
- `[policy]`, `[hosts.NAME.policy]`, accounts' policies and workspaces
  narrow further per action (`read`, `exec`, `write`, `network`,
  `elevation`, ...). `[network]` sets the network commands, `[shell]` the
  managed shell.
- **Taking away applies at once; adding, widening or removing an entry waits
  for your OK.** Until then the approved entry keeps going through the
  gateway. A mistake turns off only that entry (`gate status` names the
  line).

Every key, its default and which changes need your OK:
[docs/CONFIG.md](docs/CONFIG.md).

### Per-mode values

Every gated command can behave differently in each Claude Code permission
mode. A right (`ssh`, `sudo`, an account's `use`), a policy key (`read`,
`exec`, `write`, `network`, `elevation`, `credential`) or `[network]
commands` takes one word or a table of words by mode:

| Word | In that mode |
|---|---|
| `true` or `"allow"` | the gateway approves, so Claude Code doesn't ask (for the commands it can judge, below); on a policy key, no restriction |
| `"cc"` | Claude Code decides, as for any command (its mode and your permission rules) |
| `"ask"` | Claude Code asks you each time |
| `false` or `"deny"` | refused |

The modes are `default` (also `manual`), `plan`, `acceptEdits`, `auto`,
`bypass` (also `bypassPermissions`) and `dontAsk`. A table must name
`default`; a mode it leaves out takes `default`'s word. A plain `true` on a
right approves in `auto` and `bypass` only (Claude Code decides elsewhere);
approving in another mode takes that mode in a table. A plain `"allow"` on
`[network] commands` approves in every mode but plan. Plan mode never
approves anything. In `dontAsk` Claude Code refuses what it decides itself
unless your permission rules allow it, so a plain `true` (`"cc"` there) is
refused; a table's `dontAsk = "allow"` is approved by the gateway, and
`"ask"` still asks you (Claude Code shows a hook's question in that mode
too; tried with Claude Code 2.1.310).

Set them from the chat (*"approve sudo on homelab in auto mode, ask
otherwise"*), in `/gate-hosts` or `/gate-accounts`, or with `gate host set
NAME ssh|sudo MODE=WORD...`, `gate account set NAME use MODE=WORD...`,
`gate policy set all|HOST|ACCOUNT ACTION MODE=WORD...` and `gate network
commands MODE=WORD...`. A wider value in any mode waits for
your OK, and the dialog says what changes in each mode.

## Permissions: what asks and what doesn't

The gateway answers as a hook on top of Claude Code's permission modes. It
adds no modes and writes no permission rules.

- **A machine, account or repository gateway.toml doesn't name** gets no
  decision from the gateway: Claude Code decides, as without it.
- **Always refused**: reading the gateway's private folder
  (`~/.config/gateway/private`) or session transcripts; anything set to
  `false` in the current mode; a value that waits for your OK; a way around
  a stand-in to a configured target (`/usr/bin/ssh homelab`, `env -i ssh
  homelab`, `/usr/bin/SSH homelab`, a changed `PATH`, an alias or IP of
  homelab); while this
  computer's sudo goes through the gateway, `su`, `doas`, `pkexec` and
  `sudoedit`; while a Hugging Face account is set up, `huggingface-cli` (use
  `hf`); a command that hides its program or host (`source x.sh`, `eval`,
  `bash -c "$CMD"`, `xargs`, ...) and names a configured host or account.
- **`"ask"`** gives you Claude Code's prompt, for `ssh`, `sudo`, `git`,
  the account tools (`gh pr list` with an account's `use = "ask"`) and
  `gate with`. The gateway notes the exact command it asked about, and the
  stand-in honours your OK only for that command, once, within 15 minutes
  and before Claude's next command (so a prompt you declined serves
  nothing later). So a job, a gateway terminal, a script, or what a sourced
  file, `eval` or `bash -c "$CMD"` runs is refused ("run `ssh homelab
  ...` as its own command"), and those commands get no prompt of their own
  (`source .venv/bin/activate && pytest` runs as usual). A command whose
  words the gateway can't spell out (a variable, a glob) is refused before
  it runs.
- **What the gateway approves itself**, where the value is allow in the
  current mode: `sudo CMD` here (except a short list of destructive
  commands); `ssh`, `scp`, `sftp` and `rsync` to a host, copying only to or
  from the project, `~/Downloads` or a temp folder; a network command
  `[network] commands` allows. In auto and bypass mode also `gate status`,
  `check`, `login`, `why`, `log`, `export`, `import` and `scrub` (`rotate`
  and `copy-to` only where the host's `ssh` is allow; no other `gate`
  command) and plain reads (`cat`, `grep`, `ls`, ...) of ordinary files in
  the project or a temp folder. Never: git, gh and the other account tools,
  `gate with`, scripts, jobs, and commands in your Terminal panel.
- **The `http` and `download` tools** follow the `network` policy: refused or
  asked where it says so, approved where you wrote an explicit per-mode
  allow (never for a call with an account), otherwise Claude Code decides.
- **No prompt in any mode**: reading the gateway's terminals and jobs,
  opening a local terminal, `host_inspect`, the runtime status.

## With checkpoint

With [checkpoint](https://github.com/p-w-rs/checkpoint) installed too,
Claude can start long work with checkpoint's `job_start`.

- **Who runs the job.** While the gateway serves the session, it runs the
  job in its managed shell and tmux (with the environment checkpoint sends,
  minus Claude Code's credentials, the stand-ins first on PATH) and applies
  the job's pause policy;
  checkpoint keeps the record. Otherwise (the gateway not installed,
  disabled, an incompatible version) checkpoint runs the job itself;
  `/check:status` says which.
- **The same checks as Bash**, but nobody can be asked while a job runs: by
  default a network command is refused in a job (judged in the mode you
  started it from), and so is an `"ask"` right. The gateway never approves a job by itself: Claude Code asks you or
  its reviewer decides.
- **Masking.** What `job_tail`, `job_status` and `job_stop` show Claude is
  masked, except a failed `job_stop`'s error text; the gateway warns then.
- **Credentials** reach a job only while the session that started it is
  open, unless the entry says `scripts = true`.

The gateway's helper, `gated`, runs one per user and exits 30 minutes after
the last session ends (never while a terminal or job runs). checkpoint finds
it through `~/.config/gateway/run/contract.json`
([docs/CONTRACT-v1.md](docs/CONTRACT-v1.md)).

## Security and privacy

What the gateway guarantees for what gateway.toml names:

- **Claude never gets a stored secret.** Secrets are typed or pasted only in
  the gateway's dialog, sealed inside its field, and stored encrypted with
  age. A credential goes to one process, never on a command line. Every
  tool's output Claude reads is masked (but a few whose output is fixed text
  or Claude's own input): each stored secret, anything shaped like a token,
  and the values of credential-named variables. So a stored secret doesn't
  go to the model or land in the chat history, except in output no hook can
  mask: a failed command's output and Monitor's lines (see Limits).
- **Each credential goes only where you approved it.** SSH keys and sudo
  passwords belong to a host's pinned host key; an account's token only to
  its sites.
- **Claude can't give itself more.** A wider value, in any mode, or the
  removal of an entry applies only after you approve it in a dialog with
  fixed wording; Decline is the default.
- **The gateway asks only inside Claude Code**: its own dialogs and Claude
  Code's permission prompts. The one exception is a browser sign-in, where
  your system browser opens after you press Open.
- **Everything is logged**, values redacted: `gate log`.

What it doesn't guarantee: **the gateway is a guardrail, not a sandbox.**
Claude's commands run as you, and the gateway's text and process-tree
checks keep a cooperative model on track: code that sets out to get around
them can read whatever you can, including the vault's key file unless you
set a passphrase (`/gate-unlock`). What you set to allow skips Claude Code's
prompt or auto mode's reviewer, and some output can't be masked (see
Limits).

**Your own credentials and a configured host.** A route around a stand-in
(a script, a Makefile, a command the hook can't read) signs in with your own
agent and tokens. So a host's limits (`sudo = false`, `write = "deny"`,
workspaces) bind only if your own key or token doesn't also open it: let
Claude reach that host with the gateway's own key (it installs one per
host), keep your personal key out of the agent for it, and scope your
tokens.

| Your data | Where | Kept |
|---|---|---|
| The form, the vault and its key; backups (every import, `gate rotate`'s newest 5, a start-over, an old 0.6 conversion) | `~/.config/gateway/` (secrets and backups in `private/`) | until you delete them (`gate forget --backups` for the backups) |
| Built tools, the gated git's config, audit log (values redacted), the helper's logs, terminal and job records | the plugin's data folder: `~/.claude/plugins/data/gate-gateway`, or under `$CLAUDE_CONFIG_DIR` | audit log 5 MB plus one older copy; records 24 h after a terminal or job ends; a job's last 256 KiB of output; all deleted on uninstall |
| Sockets, the terminals' tmux | `/tmp/gw-<uid>/` | until the machine restarts |
| An ML catalog's DVC cache | `~/.local/share/asiml/site-cache` | until you delete it |
| Claude's keys and runtime on your servers | `~/.ssh/authorized_keys` (lines ending in `gateway-NAME@...`), `~/.local/share/gateway-runtime/` | until you remove them |

`gate forget NAME` deletes what is stored for an entry and keeps no copy;
older vault copies in `private/backups/` (from `gate rotate`, an import or
a start-over) may still hold it. `gate forget --backups` lists them in the
gateway's dialog and deletes them after your OK. The vault's passphrase is
set, changed or removed in the dialog too (`/gate-unlock`, or ask Claude:
`gate passphrase`, `gate passphrase --remove`).

## Limits

- **Desktop app untested**: try its dialogs with a throwaway value first.
- **No dialogs in VS Code, the mobile app, Remote Control, `claude -p` or
  the SDK.** Enter a credential once in a terminal; it then works everywhere.
- **Typing a secret needs the fullscreen view**: type `/tui fullscreen`
  (Claude Code's own command; it restarts and resumes the session).
  Otherwise use Paste from clipboard (`/gate-dialog`, then Tab and Enter)
  and clear your clipboard after; on Linux without a display, only typing works.
- **Keys typed before clicking the dialog's field** reach other plugins'
  prompt hooks: click the field first.
- **Paste from clipboard reads your clipboard**; macOS may show its own
  clipboard-privacy alert the first time (not verified).
- **A sudo that uses Touch ID** (`pam_tid` in your sudo setup) shows macOS's
  own Touch ID sheet when the gateway runs this computer's sudo.
- **Output that can't be masked**: a failed command's output (Claude Code
  shows it as is; the gateway warns after), Monitor's lines (they reach no
  hook), and the values of variables only your shell snapshot exports. A
  background command's notice that quotes a secret is held back.
- **A configured host by another name**: an alias or IP address is matched
  through your own `ssh -G` and a DNS lookup, 1.5 s each. When they time
  out, an alias or an unusual IP spelling isn't recognised and runs your own
  ssh.
- **Network commands are a guardrail**: networking inside an interpreter
  (`python -c`, `node -e`), a script on disk, a scheduled job, git hooks or
  ssh's `ProxyCommand` isn't seen
  ([docs/dev/modules/network.md](docs/dev/modules/network.md#known-misses-guardrail-not-sandbox)).
- **The question guard reads words**: a rephrased request for a secret can
  pass, and a question like "What's the token budget?" can be refused.
- **Per-mode values cost a little**: while some value differs between
  modes, every Bash call starts a short Python check so the gateway knows
  the current mode (about 0.08 s; macOS arm64,
  [TESTING.md](docs/dev/TESTING.md#budgets)). A subagent in another mode
  changes the mode for the whole session.
- **`"ask"` costs a little too**: while an account is `"ask"` in some
  mode, each plain call of its tool (`gh`, `hf`, ...) starts the Python
  check, and so does Claude's next command after a prompt (about 0.15 to
  0.35 s with the vault read; [TESTING.md](docs/dev/TESTING.md#budgets)).
  Two commands Claude runs at once, one of them asked about, may make the
  asked one refused after your OK; it says to run it again by itself.
- **`gh`, `databricks`, `dvc` and `gate with` hold their token in their
  environment** while they run, visible to your own processes.
- **A sudo password for another machine** sits in a private file there
  while sudo runs, where Claude's own command can read it. It is used once
  unless you tick **Remember it**; `elevation = "ask"` in that host's policy
  asks you each time.
- **An `"ask"` is only as good as the gateway's note of what you
  approved**: the note sits in the gateway's run folder, which a process
  running as you could write. Set what must never run unasked to `false`.
- **With the managed shell, a zsh user's aliases and functions don't reach
  Claude's commands** (they run in the gateway's bash; your PATH and
  variables do). `[shell] managed = "off"` keeps your own shell.
- **In a configured repository the gated git uses its own config**, not
  your `~/.gitconfig` (your aliases, signing and hooks settings don't
  apply there). Commits carry the account's `name` and `email`, else your
  own `user.name` and `user.email` as your git reads them; with neither, git
  refuses to commit rather than guess.
- **One Claude Code configuration at a time**: sessions of a second
  `CLAUDE_CONFIG_DIR` get no dialogs, terminals or jobs, and are told so.
- **A disabled (not uninstalled) gateway's helper** keeps running until it
  has been idle for 30 minutes.
- **Browser sign-in needs a display** and has never been tried against
  Microsoft's real service; the catalog's app registration must allow a
  redirect to `http://127.0.0.1`. No device-code sign-in, no stored SSH key
  passphrases. The `http` tool, the account tools, the gated git and the
  first remote host's download (about 20 MB from conda-forge per system)
  ignore proxy settings.
- **Untested**: Intel Macs, Linux x86-64, WSL 2, remote hosts behind `via`.

The guard's rarer gaps, both ways, are listed in
[docs/dev/modules/managed.md](docs/dev/modules/managed.md#alternate-routes)
and [docs/dev/modules/sudo.md](docs/dev/modules/sudo.md#hooks_bashpy-spec-8).

## Update, disable, uninstall

| What | Command (in Claude Code, `/plugin` has the same actions) |
|---|---|
| Update | `claude plugin marketplace update gateway`, then `claude plugin update gate@gateway`, then a new session (or `/reload-plugins`) |
| Turn off for now | `claude plugin disable gate@gateway` (back on: `claude plugin enable gate@gateway`) |
| Uninstall | `claude plugin uninstall gate@gateway` (`--keep-data` keeps the built tools) |
| Forget the marketplace | `claude plugin marketplace remove gateway` (also uninstalls the plugin and deletes its data folder) |

An update keeps working on the old tools while new ones build. Uninstalling
deletes the plugin's data folder and lets running terminals and jobs finish
(notes in `~/.config/gateway/run/gated-drain.log`). **Then restart every
open Claude Code session**: their commands still go to the gateway's shell.

What stays behind: `~/.config/gateway` (a reinstall picks up from it;
export first if you like, then delete it), and on each server the
`gateway-NAME@...` lines in `~/.ssh/authorized_keys` and
`~/.local/share/gateway-runtime/`.

Only the latest release is supported; what each one changed, and what to do
before updating, is in [CHANGELOG.md](CHANGELOG.md).

## Troubleshooting

- **Start with `/gate-doctor`**; `gate why` explains the last refusal.
  Gateway messages start with `gateway:` and say what to do next.
- **"this command ran without the gateway's managed settings, in ...: the
  managed shell isn't ready (...)"** names the shell it ran in and says why:
  still setting up, setup failed (with its log), pixi missing or too old,
  its settings missing (a new session writes them), or the data folder gone
  (restart Claude Code). It runs in the shell that made Claude Code's shell
  snapshot; without that shell the command isn't run.
- **"pixi … is too old"**: `pixi self-update` (or your package manager:
  Homebrew, MacPorts), then start a new session.
- **`Executable not found in $PATH: "git"`** when adding the marketplace:
  see [Install](#install).
- **sudo says a password or a terminal is required**: your own sudo can't
  ask Claude. `gate host set localhost sudo ask` has the gateway ask you in
  its dialog.
- **"X reaches homelab, which goes through the gateway; use `ssh
  homelab`"**: Claude used another name for a configured host. The gateway
  supplies the key only under the form's name.
- **"... waits for the user's OK"**, or **a form change doesn't take
  effect**: it waits for your OK (Claude runs `gate check NAME` while you're
  there) or has a mistake; `gate status` shows which.
- **"no account is chosen for github.com/OWNER"** or **"both ... fit"**: add
  `owners` or `default = true` to one account, or Claude sets
  `GATE_ACCOUNT=NAME` for that command.
- **"the gateway vault is locked"**: `/gate-unlock`. Until then the hosts
  and accounts in gateway.toml, and sudo here when gateway.toml sets it, are
  refused; everything else is your own. A forgotten passphrase can't be
  recovered: ask Claude to start over (`gate passphrase
  --start-over`: after your OK in the dialog the old vault and key move into
  `private/backups/`, nothing is deleted), then import your last export.
- **No `http` tool in the first session**: start a new session, or
  reconnect `gw` in `/mcp`.
- **A long transfer stops midway**: the Bash tool's 2-minute timeout ended
  it. Ask Claude to run it as a job.

## Status

0.11.1 (2026-10-26) is the latest release; what was verified for each release is in
[docs/dev/TESTING.md](docs/dev/TESTING.md). Never tested: the desktop app,
real x86-64 hardware, real GitHub, Hugging Face or Azure services (the
browser sign-in included), a run with the real model. To work on the
gateway, start with [CLAUDE.md](CLAUDE.md).

## Reporting security issues

Please don't open a public issue. See [SECURITY.md](SECURITY.md).
