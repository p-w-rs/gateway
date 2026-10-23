# gateway

A Claude Code plugin that lets Claude use your machines and accounts the way
you would (`sudo`, `ssh`, `rsync`, `git push`, `gh`, `hf`, API calls) without
ever seeing a password, key or token. The gateway hands each credential to
the one command that needs it, only where you allowed, and keeps the values
in an encrypted vault. What Claude may do is written in one small file, and
anything that gives Claude more waits for your OK in a dialog inside Claude
Code.

```
You:    Add my server homelab at 192.168.1.20, user alex.
Claude: (adds [hosts.homelab] to gateway.toml and runs gate check homelab)
        The gateway's dialog shows the address, the host key and the rights.
        You press Approve, then "use my own SSH login once" to install Claude's key.
You:    How full is homelab's disk?
Claude: $ ssh homelab 'df -h'
        /dev/sda1   916G  402G  468G  47% /
```

Plugin `gate` in the marketplace `gateway`, version 0.10.0. Sister plugins:
[checkpoint](https://github.com/p-w-rs/checkpoint) and
[pixi-guard](https://github.com/p-w-rs/pixi-guard).

## What changes when you install it

- **Claude's commands run in the gateway's own shell** (Bash, background
  commands, Monitor, subagents, your `!` commands): a bash 5 without your
  profile, aliases or tokens. Your Homebrew, nvm or cargo tools join its
  PATH only when you approve importing them; Claude offers.
- **`curl` and `wget` are refused.** Claude uses the gateway's `http` and
  `download` tools instead, which Claude Code asks about like any tool.
- **sudo on this computer asks every time.** A new install starts with
  `sudo = "ask"`: Claude Code asks you each time Claude runs `sudo`, in every
  mode. sudo inside a gateway terminal, a job or a script is refused, since
  nobody can be asked there. Set `sudo = true` if Claude should use those.
- **Secrets go only into the gateway's dialog**, a pane inside Claude Code.
  A token pasted into the chat is blocked and scrubbed.
- **The first session sets up for about a minute** (about 400 MB of tools,
  downloaded once). Claude's commands are refused until the `ready` notice.

## Requirements

- **Claude Code 2.1.287 or newer** in the terminal, **2.1.286 or newer** in
  the desktop app: the dialogs, panes, status line and managed shell are a
  Claude Code mod. Tested on 2.1.301 (macOS) and 2.1.304 (Linux). Any
  install works, npm's (`@anthropic-ai/claude-code`) included.
- **Without mods** (an older Claude Code, or mods switched off for your
  account), every Bash and Monitor call is refused ("managed shell
  unavailable") and no dialog can open; the other checks still hold. Update
  Claude Code, or `claude plugin disable gate@gateway` until mods are back.
  Each feature per Claude Code surface: [docs/CAPABILITIES.md](docs/CAPABILITIES.md).
- **pixi 0.68.0 or newer** (from pixi.sh). `pixi.toml` says
  `requires-pixi = ">=0.68.0"` with no upper bound; tested up to 0.82.0.
  The plugin brings everything else (Python, OpenSSH, git, tmux, age).
- **git**, which Claude Code needs to add a marketplace from GitHub. If you
  have none: `pixi global install git` (with `~/.pixi/bin` on your PATH).
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
**gate**. The gateway adds nothing to your `settings.json`.

### First five minutes

1. Start a new session (`CLAUDE_CODE_NO_FLICKER=1 claude` if you want to
   type secrets). The line under the prompt shows `⚠ gate: setting up…`
   (Claude Code draws every plugin's status line with ⚠), then a `ready`
   notice appears. The gateway creates `~/.config/gateway/gateway.toml`.
2. Type `/gate-doctor`: versions, setup, the vault, the managed shell, and
   whether this terminal can type into the dialog's field.
3. Ask Claude to add something: *"Add my GitHub account alex"*. Approve in
   the dialog, then enter the token. Then ask for real work.

## Everyday use

You manage the gateway by talking to Claude:

- *"Add my work GitHub (octo-work) for the example-org repos."* The dialog
  takes a token that GitHub says is octo-work's; example-org's repos use it.
- *"Add my OpenAI key for api.openai.com, and let my scripts use it as
  OPENAI_API_KEY."* Claude calls the API with the `http` tool, or runs
  `gate with openai -- pixi run python train.py`.
- *"Let Claude use sudo here without asking."* or *"Import my servers from
  ~/.ssh/config."* Adding a right or a host waits for your OK.
- *"Open a terminal on homelab and start the training run there."* A
  terminal (or a job) that outlives Claude's turn, which you can watch; the
  first time, the gateway copies its bash and tmux there (about 50 MB, no sudo).

| You type | What it does (the `/gate-...` commands answer at once, with no model turn) |
|---|---|
| `/gate:status`, `/gate:help` | What Claude has: hosts, accounts, rights, changes waiting; a short guide |
| `/gate-doctor` | Setup, versions, the vault, the managed shell, this surface |
| `/gate-hosts`, `/gate-accounts` | Hosts, workspaces and accounts with their state; edit, check, enter a credential |
| `/gate-terminal [ID\|new]` | Watch or take over a terminal or job (Ctrl-] then c, d, z or [ for ^C, ^D, ^Z, Esc) |
| `/gate-dialog` | Show a waiting dialog again and give it the keyboard |
| `/gate-unlock`, `/gate-lock` | Set a vault passphrase or unlock; lock now |

In your own terminal, `~/.config/gateway/gate` does the same: `status`,
`check NAME`, `why` (the last refusal and its fix), `log`, `export` and
`import FILE` (an encrypted file for another machine), `forget NAME`,
`rotate HOST`, and more (`gate help`).

## Configuration

Everything lives in `~/.config/gateway/gateway.toml`. It never holds a
secret.

```toml
[hosts.localhost]       # this computer
sudo = "ask"            # true = Claude may do it without asking, "ask" = ask me each time, false = no

[hosts.homelab]
address = "alex@192.168.1.20"
```

- Hosts have `ssh` and `sudo` rights, addresses, a jump host (`via`), and
  `scripts = true` to give credentials to programs Claude's commands start.
- Accounts are `github`, `huggingface`, `azure`, `ml-catalog`, `pijul`,
  `registry` or `api-key`. A credential goes only to its account's sites.
- `[policy]`, `[hosts.NAME.policy]` and workspaces narrow further:
  `"allow"`, `"ask"` or `"deny"` per action (`read`, `exec`, `write`,
  `elevation`, ...). `[shell]` sets the managed shell and its imports.
- **Taking away applies at once; adding or widening waits for your OK.** A
  mistake turns off only that entry (`gate status` names the line).

Every key, its default and which changes need your OK:
[docs/CONFIG.md](docs/CONFIG.md).

## Permissions: what asks and what doesn't

The gateway answers as a hook on top of Claude Code's permission modes. It
adds no modes and no settings rules; in default and plan mode you're asked
as usual.

- **Always refused**: `curl` and `wget`; reading the gateway's private folder
  (`~/.config/gateway/private`) or session transcripts; anything set to
  `false`; a right that waits for your OK; and in the managed shell the
  usual ways around the gateway (`/usr/bin/ssh` by its path, `command -p`,
  `env -i`, a changed `PATH`, `bash -c "$CMD"`, ...).
- **`"ask"`** gives you Claude Code's prompt each time, in every mode.
- **Auto mode.** The gateway approves a few shapes itself, so they skip the
  reviewer: `sudo CMD` here when its sudo is `true` (except a short list of
  destructive commands); `ssh`, `scp`, `sftp` and `rsync` to a host whose
  `ssh` is `true`, copying only to or from the project, `~/Downloads` or a
  temp folder; `gate status`, `check` and `why`; plain reads (`cat`, `grep`,
  `ls`, ...) of ordinary files in the project or a temp folder. Everything
  else goes to the reviewer, including git, gh, scripts, `gate forget` and
  the `http` and `download` tools.
- **No prompt in any mode**: reading the gateway's terminals and jobs,
  opening a local terminal, `host_inspect`, the runtime status.

## With checkpoint

With [checkpoint](https://github.com/p-w-rs/checkpoint) installed too,
Claude can start long work with checkpoint's `job_start`.

- **Who runs the job.** While the gateway serves the session, it runs the
  job in its managed shell and tmux and applies the job's pause policy;
  checkpoint keeps the record. Otherwise (the gateway not installed,
  disabled, an incompatible version) checkpoint runs the job itself;
  `/check:status` says which.
- **The same checks as Bash.** `curl`, `wget`, the private folder, session
  transcripts and anything set to `false` are refused; an `"ask"` right
  (sudo here, on a new install) can't be used in a job, since nobody can be
  asked while it runs. The gateway never approves a job by itself: Claude
  Code asks you or its reviewer decides.
- **Masking.** What `job_tail`, `job_status` and `job_stop` show Claude is
  masked, except a failed `job_stop`'s error text; the gateway warns then.
- **Credentials** reach a job only while the session that started it is
  open, unless the entry says `scripts = true`.

The gateway's helper, `gated`, runs one per user and exits 30 minutes after
the last session ends (never while a terminal or job runs). checkpoint finds
it through `~/.config/gateway/run/contract.json`
([docs/CONTRACT-v1.md](docs/CONTRACT-v1.md)).

## Security and privacy

What the gateway guarantees:

- **Claude never gets a secret value.** Secrets are typed or pasted only in
  the dialog, sealed inside its field, and stored encrypted with age. A
  credential goes to one process, never on a command line. Output Claude
  sees is masked (every stored secret and anything shaped like a token).
- **Each credential goes only where you approved it.** SSH keys and sudo
  passwords belong to a host's pinned host key.
- **Claude can't give itself more.** Nothing wider applies until you approve
  it in a dialog with fixed wording; Decline is the default.
- **Your own credentials stay out** of Claude's shell (your ssh agent, token
  variables). Only Claude's own commands get credentials, unless `scripts = true`.
- **Everything is logged**, values redacted: `gate log`.

What it doesn't guarantee: **the gateway is a guardrail, not a sandbox.**
Claude's commands run as you, and the gateway's text and process-tree
checks keep a cooperative model on track: code that sets out to get around
them can read whatever you can, including the vault's key file unless you
set a passphrase (`/gate-unlock`). What you set to `true` skips auto mode's
reviewer, and some output can't be masked (see Limits).

| Your data | Where | Kept |
|---|---|---|
| The form, the vault and its key; backups (the 0.6 conversion, every import, `gate rotate`'s newest 5) | `~/.config/gateway/` (secrets and backups in `private/`) | until you delete them |
| Built tools, audit log (values redacted), the helper's logs, terminal and job records | the plugin's data folder: `~/.claude/plugins/data/gate-gateway`, or under `$CLAUDE_CONFIG_DIR` | audit log 5 MB plus one older copy; records 24 h after a terminal or job ends; a job's last 256 KiB of output; all deleted on uninstall |
| Sockets, the terminals' tmux | `/tmp/gw-<uid>/` | until the machine restarts |
| Claude's keys and runtime on your servers | `~/.ssh/authorized_keys` (lines ending in `gateway-NAME@...`), `~/.local/share/gateway-runtime/` | until you remove them |

`gate forget NAME` deletes what is stored for an entry and keeps no copy;
older vault copies in `private/backups/` may still hold it, and the command
names them and how to delete them.

## Limits

- **Desktop app untested**: try its dialogs with a throwaway value first.
- **No dialogs in VS Code, the mobile app, Remote Control, `claude -p` or
  the SDK.** Enter a credential once in a terminal; it then works everywhere.
- **Typing a secret needs the fullscreen view** (`CLAUDE_CODE_NO_FLICKER=1`).
  Otherwise use Paste from clipboard (`/gate-dialog`, then Tab and Enter)
  and clear your clipboard after; on Linux without a display, only typing works.
- **Keys typed before clicking the dialog's field** reach other plugins'
  prompt hooks: click the field first.
- **Output that can't be masked** (a failed command, Monitor's lines, a
  background command's output): the gateway warns and names the secret.
- **`gh`, `databricks`, `dvc` and `gate with` hold their token in their
  environment** while they run, visible to your own processes.
- **A sudo password for another machine** sits in a private file there
  while sudo runs, where Claude's own command can read it. Untick
  **Remember it** to be asked for it each time, or set `elevation = "ask"`
  in that host's policy.
- **`"ask"` can't reach inside a script sourced into Claude's shell**
  (`source x.sh`): set what must never run unasked to `false`.
- **One Claude Code configuration at a time**: sessions of a second
  `CLAUDE_CONFIG_DIR` get no dialogs, terminals or jobs, and are told so.
- **A disabled (not uninstalled) gateway's helper** keeps running until it
  has been idle for 30 minutes.
- **No browser or device-code sign-ins** (use a personal access token, an
  Azure service principal, API keys); no stored SSH key passphrases. The
  `http` tool, the account tools and the first remote host's download (about
  20 MB from conda-forge per system) ignore proxy settings.
- **Untested**: Intel Macs, Linux x86-64, WSL 2, remote hosts behind `via`.

The guard's rarer gaps, both ways, are listed in
[docs/dev/modules/managed.md](docs/dev/modules/managed.md#alternate-routes-phase-7)
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
`~/.local/share/gateway-runtime/`. Gateway 0.8 and older could add a sudoers
file named after the gateway in `/etc/sudoers.d`: delete it, then `sudo visudo -c`.

**Upgrading from 0.9.x.** Nothing is converted, and your rights stay as they
were (an existing install keeps `sudo = true` here). The `http` and
`download` tools now ask like any tool, auto mode sends more reads to its
reviewer, an `ml-catalog` account needs `host`, and sudo here asks while a
passphrase-protected vault is locked. **From 0.6**, the first session
converts the vault and keeps the old one in `private/backups/`. All
changes: [CHANGELOG.md](CHANGELOG.md).

**Rolling back.** Releases are tagged. To go back to 0.9.1: `claude plugin
marketplace remove gateway`, `claude plugin marketplace add
p-w-rs/gateway#v0.9.1`, `claude plugin install gate@gateway`. To return,
do the same without the tag. Removing the marketplace also uninstalls the
plugin and deletes its data folder (the built tools, the audit log and the
terminal and job records); `~/.config/gateway` stays. While the marketplace
is pinned to a tag, updates keep that version.

## Troubleshooting

- **Start with `/gate-doctor`**; `gate why` explains the last refusal.
  Gateway messages start with `gateway:` and say what to do next.
- **"the managed shell isn't ready"** says why: still setting up, setup
  failed (with its log), pixi missing, or the data folder gone (restart
  Claude Code).
- **pixi too old** ("requires pixi '>=0.68.0'"): `pixi self-update`.
- **`Executable not found in $PATH: "git"`** when adding the marketplace:
  see [Requirements](#requirements).
- **"... waits for the user's OK"**, or **a form change doesn't take
  effect**: it waits for your OK (Claude runs `gate check NAME` while you're
  there) or has a mistake; `gate status` shows which.
- **"no account is chosen for github.com/OWNER"** or **"both ... fit"**: add
  `owners` or `default = true` to one account, or Claude sets
  `GATE_ACCOUNT=NAME` for that command.
- **"the gateway vault is locked"**: `/gate-unlock`. A forgotten passphrase
  can't be recovered: import your last export.
- **No `http` tool in the first session**: start a new session, or
  reconnect `gw` in `/mcp`.
- **A long transfer stops midway**: the Bash tool's 2-minute timeout ended
  it. Ask Claude to run it as a job.

## Status

0.10.0 was tested on macOS (Apple silicon, Claude Code 2.1.301) and Debian 13
(ARM64, Claude Code 2.1.304): the repository's test suite with its mutation
checks, and live Claude Code sessions driven against a stand-in model; the
suite also on Intel macOS packages through Rosetta. Not tested: the desktop
app, real x86-64 hardware, real GitHub, Hugging Face or Azure accounts, a
run with the real model. Details: [docs/dev/TESTING.md](docs/dev/TESTING.md). To work on the gateway, start
with [CLAUDE.md](CLAUDE.md).

## Reporting security issues

Please don't open a public issue. See [SECURITY.md](SECURITY.md).
