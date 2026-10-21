# gateway

A Claude Code plugin that lets Claude use your machines and accounts the way
you would, without ever seeing a password, key or token.

Claude runs ordinary commands: `sudo apt install htop`, `ssh homelab 'df -h'`,
`rsync -a dist/ homelab:/srv/app/`, `git push`, `gh pr create`, `hf upload`,
in the gateway's own shell (a bash of its own, without your login setup or
your tokens; [the managed shell](#the-managed-shell)). The gateway supplies
the password, SSH key or token to that one command, sends each credential
only where you allowed it, and keeps the values in an encrypted vault that
Claude can't read. What Claude may do is written in one small file that you
(or Claude, when you ask) can edit. Anything that gives Claude more than
before waits for your OK in the gateway's own dialog inside Claude Code.

It also gives Claude real terminals and long-running jobs, here and on your
other machines, that you can watch and take over in a pane.

Plugin `gate` (version 0.9.1) in the marketplace `gateway`
(`github.com/p-w-rs/gateway`). Sister plugin:
[checkpoint](https://github.com/p-w-rs/checkpoint).

> Developing on this repo, or an agent picking it up? Start with
> [CLAUDE.md](CLAUDE.md), then [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Status: built and tested

"Tested live" means a real Claude Code session in a terminal, driven
automatically against a stand-in model, with the plugin installed from a git
marketplace into a throwaway configuration, on macOS arm64 (Claude Code
2.1.301) and a Debian 13 arm64 VM (Claude Code 2.1.304), 2026-10-21. The
repository's own test suite (1222 tests) and its mutation checks (1041) pass
on macOS, and the suite on the Linux VM too (plugin 0.9.1). The fixes after
the install test from GitHub (an uninstall while a job runs, the status line's
warning sign, `~/.bashrc` on Debian) were checked live on the VM; the other
live checks ran on 0.9.0.

| Area | Built | Tested |
|---|---|---|
| Install, first-use setup, update, disable, uninstall | yes | live (macOS, Linux VM), from a local git server rather than GitHub |
| The managed shell (Bash, background, subagents, `!`, skills) | yes | live (macOS, Linux VM) |
| Dialogs: sudo passwords, tokens, consent, host keys, vault passphrase | yes | live in the terminal (macOS, Linux VM); desktop app **untested** |
| Secrets kept out of transcripts, logs, process lists and telemetry | yes | live in the terminal, with test secrets and telemetry captured before encryption; desktop app untested |
| Terminals and jobs, takeover and hand back | yes | live (macOS, Linux VM) |
| Remote terminals and jobs (the gateway's runtime on another host) | yes | against the Linux VM with a simulated Claude Code, not from a real session |
| Hosts, workspaces, policy; `/gate-hosts`, `/gate-accounts` | yes | live (macOS, Linux VM); a policy "ask" prompt not driven |
| GitHub, Hugging Face, Azure account checks | yes | against local stand-in services only (no real accounts) |
| Encrypted export and import between machines | yes | live, including a macOS export imported on Linux |
| Working with checkpoint | yes | live, both plugins installed |
| Storing SSH key passphrases, a cookie store, native Windows | no | |
| Browser or device-code sign-ins | removed on purpose (no web pages) | |

Details per requirement: [docs/PLAN-v4.md](docs/PLAN-v4.md); per Claude Code
surface: [docs/CAPABILITIES.md](docs/CAPABILITIES.md).

## Before you install

- **Claude Code 2.1.287 or newer** in the terminal, **2.1.286 or newer** in
  the desktop app. The dialogs, the status line, the panes and the managed
  shell are a Claude Code mod, which older versions don't have (see
  [Known limitations](#known-limitations)).
- **pixi 0.68.0 or newer** ([pixi.sh](https://pixi.sh)). pixi.toml says
  `requires-pixi = ">=0.68.0"` with no upper bound; tested: 0.68.0, 0.69.0,
  0.70.0, 0.81.0 and 0.82.0 install the lock unchanged; 0.67 and older can't
  read it (lock format v7).
- **git**, which Claude Code itself needs to add or update a marketplace
  from GitHub. Most machines have it. If yours doesn't, pixi installs it:

  ```
  pixi global install git
  git --version
  ```

  That puts `git` in `~/.pixi/bin`. pixi's installer normally puts that
  folder on your PATH; if `git --version` still says "not found", add it
  (`export PATH="$HOME/.pixi/bin:$PATH"` in your shell profile, or in front
  of the one `claude plugin marketplace ...` command). Without git, adding
  the marketplace fails with `Executable not found in $PATH: "git"`.

Nothing else: no Python, Node, OpenSSH, tmux or daemon to install. The
plugin brings its own through pixi ([What it installs](#what-it-installs)).

## Install

In Claude Code (terminal):

```
/plugin marketplace add p-w-rs/gateway
/plugin install gate@gateway
```

From a shell (the same thing):

```
claude plugin marketplace add p-w-rs/gateway
claude plugin install gate@gateway
```

In the desktop app, add the marketplace once from a terminal (above), then in
the Code tab click **+** → **Plugins** → **Add plugin** and choose **gate**
(the app and the terminal share their plugins).

Then **start a new session**: the gateway's hooks load when a session starts.

Install from the git marketplace only. A local folder added as a marketplace
is read in place, and its install copies the whole folder, ignored files
included (old data some checkouts keep in `plugins/gateway/logs/` and
`plugins/gateway/quarantine/`, which git never ships).

The gateway adds no permission rules or environment variables to your
`settings.json`; everything it does is in the plugin's own hooks. (Claude Code
records the install itself, as for any plugin.)

## Update, disable, uninstall

From a shell (in Claude Code, `/plugin` opens the same actions as a menu):

| What | Command |
|---|---|
| Update | `claude plugin marketplace update gateway`, then `claude plugin update gate@gateway`; then `/reload-plugins` in a running session, or start a new one |
| Turn off for now | `claude plugin disable gate@gateway` (back on: `claude plugin enable gate@gateway`) |
| Uninstall | `claude plugin uninstall gate@gateway` |
| Uninstall, keep the built tools | `claude plugin uninstall --keep-data gate@gateway` |
| Forget the marketplace | `claude plugin marketplace remove gateway` |

An update installs the new version next to the old one. When it didn't change
the tools (`pixi.lock`), nothing is downloaded or built; when it did, the
gateway keeps working on its previous tools while the new set builds.
Updating works from any later shell or Claude Code session; no special PATH
or wrapper is needed beyond git for `marketplace update`. `uninstall` deletes
the plugin's data folder (`~/.claude/plugins/data/gate-gateway`, or under
`$CLAUDE_CONFIG_DIR`); `--keep-data` keeps it, so a reinstall needn't build
again. Either way your form and vault in `~/.config/gateway` stay
([Uninstall](#uninstall)).

**Development.** Try a checkout for one session with
`claude --plugin-dir plugins/gateway` (Claude Code then writes
`.claude-plugin/types/` and a `tsconfig.json` into that folder; both are
git-ignored). To test an install the way users get it, use a scratch Claude
Code configuration and a git source:

```
export CLAUDE_CONFIG_DIR=$(mktemp -d)
claude plugin marketplace add <git URL or path to a git clone>
claude plugin install gate@gateway
```

Either way the plugin uses your real `~/.config/gateway`; the repository's
own tests never do ([Develop](#develop)).

## Supported systems

| | |
|---|---|
| macOS, Apple silicon | tested (macOS 26): everything above |
| Linux, ARM64 (glibc) | tested in a Debian 13 VM: the test suite and live sessions |
| macOS Intel, Linux x86-64 | in the lock (osx-64, linux-64), expected to work, untested (no such machine was available) |
| Windows | native Windows isn't supported (the hooks need a POSIX `sh`, the lock has no win-64, the code uses POSIX-only modules). Use WSL 2: install Claude Code and pixi inside it, and the Linux rules apply (untested) |
| Claude Code surfaces | the terminal: tested. The desktop app: built for (the same mod), untested. VS Code, the mobile app, Remote Control, `claude -p` and the Agent SDK: everything works except the dialogs and panes; a request that needs you says so and asks nothing ([docs/CAPABILITIES.md](docs/CAPABILITIES.md)) |
| Remote hosts (terminals and jobs there) | Linux x86-64 or ARM64 (glibc 2.17 or newer) and macOS Apple silicon or Intel (11 or newer). Nothing to install on the host. Tested: Debian 13 ARM64 (a VM without tmux) and macOS arm64; Linux x86-64 and Intel Macs untested. Not supported: musl (Alpine), the BSDs, other architectures, Windows hosts, csh or fish as the login shell |
| pixi | 0.68.0 or newer (see above). `/gate-doctor` warns, nothing more, about a pixi newer than 0.82.0 |

## What it installs

Everything comes from conda-forge through pixi, at the exact versions in the
plugin's `pixi.lock` (`pixi install --locked`), into the plugin's data folder.
Nothing goes system-wide and nothing changes your shell setup.

| What | Why |
|---|---|
| Python 3.12, PyNaCl | the gateway's code (standard library) and the helper's sealed boxes |
| age 1.3 | the vault's encryption |
| OpenSSH, git (used only when the system has none), git-lfs, gh | the stand-ins' real programs, one version everywhere |
| bash 5 | the managed shell |
| tmux 3 | the terminals' and jobs' supervisor (its own server and settings; never yours) |
| pixi-pack, zstd | packing the remote runtime |
| On first use: huggingface_hub + hf-xet, databricks-cli, dvc + dvc-azure, crane; pijul (built with conda-forge's Rust) | only when you have such an account |
| Shipped in the plugin: TweetNaCl 1.0.3 | the dialog's field seals what you type (hooks/mod/vendor) |
| On a remote host, on first need: bash 5 + tmux 3 for its platform and its `pixi-unpack` | the remote runtime (about 50 MB in your home there) |

The main environment is about 400 MB on a cold pixi cache. From the system
the gateway uses only what every macOS and Linux has: POSIX `sh`, `ps`, the
real `sudo`, the clipboard tools for **Paste from clipboard** (`pbpaste`;
`wl-paste`, `xclip` or `xsel`), and an ssh server on a machine you copy the
gateway to.

## Your first session

- The gateway builds its tools with pixi in the background. The line under
  the prompt shows `⚠ gate: setting up… 0:12`, a few seconds of `⚠ gate:
  finishing setup… 0:41` while the managed shell's settings are written
  (Claude's commands wait meanwhile, hence Claude Code's warning sign), then
  the line goes and a small `gate` / `ready` notice shows for a few seconds
  in the top right corner. It takes about a minute (longer on a slow
  network). If Claude Code quits or the machine sleeps meanwhile, the next
  session takes the setup over and finishes it.
- Until then Claude's commands are refused with "gateway: the managed shell
  isn't ready" (they run only in the gateway's own bash, never in your login
  shell instead), other gateway commands say `gateway: still setting up
  (first run); try again in a minute`, and a reduced form of the gateway's
  checks runs without Python: it refuses anything naming
  `~/.config/gateway` (other than `gateway.toml`), session transcripts,
  credential helpers, token-bearing commands and, once a vault exists,
  `curl` and `wget`. Start a new session (or reconnect `gw` in `/mcp`)
  afterwards to get its `http` tool.
- It finds pixi even when the desktop app starts it with a short PATH
  (`~/.pixi/bin`, `~/.local/bin`, Homebrew, MacPorts, Linuxbrew). If pixi
  is missing it says so.
- Once the tools are ready, a 0.6 vault is converted
  ([Upgrading](#upgrading)); otherwise the gateway creates
  `~/.config/gateway/gateway.toml` with just this computer and sudo on.
- `/gate-doctor` answers at once, without asking Claude: versions, pixi and
  its tested range, whether the tools are built, the helper, the vault, the
  managed shell and what works on this surface.

## Everyday use

You manage the gateway by talking to Claude. A few examples:

**"Add my server homelab at 192.168.1.20, user alex, with sudo."**
Claude adds a few lines to the form and runs `gate check homelab` while you're
there. The gateway's dialog shows exactly what is being added (the address,
the server's host-key fingerprint, ssh and sudo) with **Approve** and
**Decline** (Decline is the default). Then it asks how to install Claude's
own SSH key on the server: *use my own SSH login once* (recommended), *type
the account's password once*, or *show me the public key* (you add it
yourself). If sudo there asks for a password, it offers *Store the sudo
password* or *Ask me each time a command needs it* (then each command's
dialog has a **Remember it** box you can untick so the password is used
once). The gateway never changes a machine's sudo rules: sudo without a
password is used only where you already configured it.

**"Add my personal GitHub (alex) as the default, and my work GitHub
(alex-acme) for the acme-corp repos."**
For each, the dialog asks for a personal access token (GitHub: Settings >
Developer settings > Personal access tokens), typed into its private field or
pasted from the clipboard, and checks with GitHub that it belongs to the
expected login before saving it. Repositories under `acme-corp` then use the
work account; everything else the default.

**"Add my Azure service principal (tenant contoso.com, app 1234...)."**
Claude adds `tenant` and `client_id`; the dialog asks for the client secret
(or certificate) and checks it with Entra before saving it.

**"Add my OpenAI API key for api.openai.com."**
You type or paste the key into the dialog; Claude uses it through the
gateway's `http` tool. Add "and let my scripts use it as OPENAI_API_KEY" and
Claude can run `gate with openai -- python train.py`, which gives the key to
that one program.

**"Turn off sudo on builder."** or **"Ask me before ssh to homelab."**
One word changes in the form. Taking rights away works at once, with no
dialog.

**"Import my servers from ~/.ssh/config."** `gate import-ssh` reads it (and
its `Include`s) and proposes entries; each new host gets its dialog. Git
servers in it aren't machines: for GitHub or Hugging Face, add an account.

**"Open a terminal on homelab and run the training job there."** See
[Terminals and jobs](#terminals-and-jobs).

Claude never asks for a secret in chat. If you paste something that looks like
a token or a private key into the chat, the gateway blocks the message, scrubs
it from the transcript and says Claude can open the gateway's dialog for it.

**Commands you can type** (the `/gate-...` ones answer at once, without a
model turn; they need Claude Code 2.1.287+):

| Command | What |
|---|---|
| `/gate:status` | what Claude has (hosts, accounts, rights, waiting changes); `/gate:help` a short guide |
| `/gate-doctor` | versions, setup, the helper, the vault, the managed shell, this surface |
| `/gate-hosts`, `/gate-accounts` | panes listing hosts, workspaces and accounts with their state, with an edit line, Check and Enter credential |
| `/gate-terminal [ID\|new]` | watch or take over a terminal or job |
| `/gate-dialog` | show a waiting dialog again |
| `/gate-unlock`, `/gate-lock` | set the vault passphrase or unlock; lock now |

In your own terminal, `~/.config/gateway/gate` does the same: `status
[NAME]`, `check NAME|all`, `why`, `log [N]`, `lock`, `accounts [--check
NAME]`, `host ...`, `workspace ...`, `policy set ...`, `export [FILE]`,
`import FILE`, `copy-to HOST`, `pubkey`, `forget NAME`, `rotate HOST`,
`import-ssh`, `migrate`, `scrub`, `with NAME -- CMD`.

Claude's tools from the gateway (`gw`): `http` and `download` (instead of
curl and wget), `host_inspect`, `host_runtime`, `terminal_open`, `_read`,
`_send`, `_resize`, `_signal`, `_close`, `_list`, and `job_start`, `_status`,
`_tail`, `_signal`, `_list`.

## The form

`~/.config/gateway/gateway.toml` lists the hosts and accounts Claude may use.
It never holds a secret. You can open and edit it any time.

```toml
# The machines and accounts Claude may use. Edit freely, or ask Claude.
# Secrets never go here; the gateway asks for them in its dialog in Claude Code.
#   true = Claude may do it without asking   "ask" = ask me each time   false = no

[hosts.localhost]                  # this computer, whichever one you're on
sudo = true

[hosts.homelab]
address = "alex@192.168.1.20"
also    = ["alex@homelab.example.org:2222"]   # tried when the first doesn't answer
sudo    = "ask"

[hosts.builder]
address = "ci@builder.internal"
via     = "homelab"                # reached through homelab
sudo    = false

[accounts.github-work]
kind   = "github"
login  = "alex-acme"
owners = ["acme-corp"]             # repos under acme-corp use this account
```

- `true`: Claude may do it without asking. `false`: refused; Claude is told
  to ask you. (`yes`, `no`, `on` and `off` work too.)
- `"ask"`: Claude Code asks you each time Claude runs it, in every mode. It
  can only ask about a command Claude runs itself (`ssh homelab CMD`, `sudo
  CMD`), so what starts ssh or sudo on its own is refused instead: with `ssh
  = "ask"`, `scp`, `sftp`, `rsync` and `git` to that host; with `sudo =
  "ask"`, a sudo they start; and for either, ssh or sudo inside a script,
  `sh -c`, a wrapper, or a gateway terminal or job (what you type there
  too). Set it to `true` if Claude should use those.

Hosts have `ssh` and `sudo` (both `true` unless you say otherwise), `address`,
`also`, `when` (try an address only on a given network), `via` (a jump host),
`scripts` and `runtime` (where the gateway keeps its runtime on that host).
Accounts have a `kind` (`github`, `huggingface`, `azure`, `ml-catalog`,
`pijul`, `registry`, `api-key`), `login`, `owners`, `default`, `name` and
`email` for commits, `env`, `scripts`, `use` (`false` keeps the credential but
never sends it) and `note`. The full list is in
[docs/SPEC-v3.md](docs/SPEC-v3.md) section 2.

- **Taking away** (lowering a right, removing an address, owner, site or a
  whole entry) applies at once.
- **Adding or widening** (a new host or account, `false` → `true`, a new
  address, site or owner, `scripts = true`, `env`) waits until you OK it in
  the gateway's dialog; until then the entry keeps its old rights (a new one
  has none). Claude can write the change; only you can approve it.
- **A mistake** turns off only that entry (`gate status` shows the line). A
  file that can't be read at all keeps the last version that could, until
  it's fixed.
- **Machines and git servers not in the form** are refused, with a hint to
  add them. `[settings]` `others = "mine"` makes them use your own ssh and git
  setup instead (a widening too).
- **`scripts = true`** on a host or account also gives its credentials to
  programs Claude's commands start (make, npm, a deploy script). Without it
  only Claude's own commands get them.
- **`[vault]` `lock_after = "8h"`** (from "1m" to "1d"): how long a
  passphrase-protected vault stays unlocked without use.
- **`[shell]`** `managed = "on"` (the default), `"warn"` or `"off"`, and
  `import_path` / `import_env` ([the managed shell](#the-managed-shell)).
- Removing an entry keeps its stored secrets until `gate forget NAME`.

### Policy and workspaces

Finer rules than the rights above, each `"allow"`, `"ask"` or `"deny"`, for
a host, a workspace, an account, or everything:

```toml
[policy]                         # everything (it can only narrow)
provision = "ask"                # staging the gateway's runtime on a host

[hosts.homelab.policy]
write = "deny"                   # no uploads to homelab
elevation = "ask"                # sudo there: ask me
forward_agent = "allow"          # ssh -A to homelab (only Claude's key for it)

[hosts.homelab.workspaces.app]   # a named folder on homelab
root  = "/srv/app"
local = "~/src/app"              # the same project on this computer
exec  = "deny"                   # no commands in it

[accounts.github-work.policy]
write = "deny"                   # fetch, never push
```

Actions: `read`, `exec`, `write`, `network`, `elevation` (sudo),
`credential`, `env_import`, `provision`, and per host only `forward_agent`,
`forward_x11`, `forward_remote` (`ssh -R`) and `forward_stdio` (`ssh -W`).
The strictest rule wins and nothing goes above the host's or account's
rights; a read permission never implies running commands, installing, sudo
or credentials. Forwarding is off unless that host's own policy turns it on.
Every refusal names the exact rule and its line. Loosening, a new or moved
workspace, a forwarding grant, or removing a workspace that restricts
anything waits for your OK like any widening.

A workspace is a folder on one host; terminals and jobs in it are bound to
that host and workspace, the same path on two hosts is two different
workspaces, and a folder under `local` here maps to the host's `root`. For
copies (`scp`, `rsync`, git over ssh) every remote path is checked against
every workspace it may reach, by the path as written: write remote paths the
way the workspace's root is written (from `/`, or from `~/`).

`/gate-hosts` lists every host (where it is, whether it answers and takes
Claude's key, its runtime, what isn't simply allowed, changes waiting for
your OK) and its workspaces; its edit line takes `host add NAME USER@HOST`,
`host set NAME KEY VALUE`, `workspace add HOST NAME ROOT [LOCAL]`,
`workspace remove HOST NAME` or `policy set all|HOST|ACCOUNT ACTION
allow|ask|deny` (`localhost` is this machine: `workspace add localhost proj
~/src/proj`) and opens the dialog for anything that widens. `/gate-accounts`
shows each account as connected, stored but not checked, expired, revoked or
needing a fresh sign-in (from GitHub's, Hugging Face's and Microsoft's own
answers; a browser login never counts as API access), with Check and Enter
credential.

## Permissions: what asks and what doesn't

The gateway adds no rules to Claude Code's settings and has no modes of its
own; its decisions are hook answers on top of Claude Code's permission
modes, and its policy never changes them.

- **Always refused**, in every mode: `curl` and `wget` in Claude's terminal
  (the `http` tool does the job), reading `~/.config/gateway/private` or
  session transcripts, a host or right set to `false`, and the usual ways
  around the stand-ins (`/usr/bin/ssh` by path, `command -p`, `env -i`, a
  changed `PATH` or `GIT_SSH_COMMAND`, `bash -c '...'`, `eval`, and more:
  [Security, honestly](#security-honestly)).
- **`"ask"`** gives you Claude Code's prompt each time Claude runs that ssh
  or sudo, even in auto mode.
- **Auto mode.** For a few command shapes the gateway answers "allowed"
  itself, so they run without auto mode's reviewer: `sudo CMD` on this
  computer when its sudo is `true` (except a short destructive list: `rm -rf
  /`, `mkfs`, `dd` to a disk, `shutdown`, `visudo`, `vipw`, a shell, ...);
  `ssh`, `scp`, `sftp` and `rsync` to a host whose `ssh` is `true`, with
  ordinary options and copies only to and from the project, `~/Downloads`
  or a temp folder; the `gate` helper's own commands; these chained with
  simple read-only commands; only when each program is run by its bare name.
  Everything else (git, gh, hf, scripts, `gate with`) goes to the reviewer.
- **Default mode.** You're asked as usual; the gateway approves only its own
  `http` and `download` tools (an `http` write only with an account).
- **Terminals and jobs.** Reading them, opening an empty local terminal and
  resizing need no prompt. What `terminal_send` types and what `job_start`
  runs is checked like a command Claude types (an `"ask"` right is refused
  there, by the stand-ins too and also for what you type in one: nobody can
  be asked inside a terminal), then Claude Code asks or its
  reviewer decides. Signals, closing and remote terminals follow your mode.
- **Widening needs your OK in the gateway's dialog** (default button
  Decline); narrowing applies at once.

## The managed shell

Claude's commands run in the gateway's own shell, not yours: the Bash tool,
background commands, Monitor, subagents, the `!` commands you type and
commands a skill injects. It is bash 5 from the gateway's pixi environment,
started without your profile, rc files, aliases or functions, with:

- **PATH**: the gateway's stand-ins (sudo, ssh, git helper, gh, ...), its
  runtime tools, the folders you import (below), then
  `/usr/bin:/bin:/usr/sbin:/sbin`, and other plugins' `bin/` folders last.
- **Environment**: `HOME`, `USER`, `LOGNAME`, `LANG`/`LC_*`, `TERM`,
  `TMPDIR`, `TZ`, `PWD`, the XDG folders, `SHELL` (the gateway's bash),
  Claude Code's own variables, `GW_MANAGED_DIR` (so a `claude -p` Claude
  starts is managed too), and the variables you import. Never a variable
  that looks like a credential (`*TOKEN*`, `*SECRET*`, `*PASSWORD*`,
  `*PASSPHRASE*`, `*CRED*`, `*API_KEY*`, `*AUTH*`, ...). Every other variable
  is removed by name, so no value ever shows in a process listing.
- Other plugins' session setup still applies and their hooks run exactly as
  before. Claude Code's permission prompts, "don't ask again" rules, hooks,
  results, exit codes, Escape and timeouts are unchanged; the prompt shows
  the command Claude wrote.
- **Your `~/.bashrc` doesn't run per command either.** Claude Code hands each
  command to the gateway through a short `bash -c` with a socket on stdin,
  and bash reads `~/.bashrc` first in that case when `SHLVL` is unset or 0
  (it takes itself for an ssh command; Debian's bash also when `SSH_CLIENT`
  is set). A Claude Code started from a terminal has `SHLVL` 1 or more; for
  one started without it (a launcher, a service) the gateway sets `SHLVL=1`
  in its session (0.9.1; before, the rc's lines ran, though its variables
  never reached a command). Once per session Claude Code still runs your
  login rc for its own snapshot, which the gateway never uses.

**Using your own tools.** Say "Claude, I want my Homebrew tools" (or `cargo`,
`node` from nvm, a `JAVA_HOME`): Claude can look at what this machine has with
`host_inspect` (it reads your rc files and tool folders as text and runs
nothing), then adds them and runs `gate check settings`:

```toml
[shell]
import_path = ["/opt/homebrew/bin", "~/.cargo/bin"]   # folders put on the managed PATH
import_env = ["JAVA_HOME"]                            # variables passed from Claude Code's environment
```

Each new import waits for your OK. `/gate-doctor` and `gate status` list every
PATH folder and variable with where it comes from.

**Switching it off.** `[shell] managed = "off"` gives Claude Code's own shell
back; `"warn"` keeps the managed shell while mods run and falls back to your
shell, with a notice each session, when they don't. Either needs your OK in
the dialog and applies from the next session.

Not the managed shell: the desktop app's Terminal panel (your own terminal),
and checkpoint's jobs when checkpoint runs them itself because the gateway
isn't serving that session ([With checkpoint](#with-checkpoint)).

## Terminals and jobs

Claude can open real terminals and start long jobs that outlive its turn and
the session. They run in the gateway's own tmux (its own server on a private
socket and its own settings; never your tmux or `~/.tmux.conf`) with the
managed shell's environment, and keep running when Claude Code restarts, a
plugin reloads or the gateway's helper restarts. After a computer restart
they are reported gone, never pretended alive.

**Watching and typing.** `/gate-terminal` shows the newest terminal of this
session in a pane (`/gate-terminal ID` a given one, `/gate-terminal new` opens
one for you). The header says who holds the input: Claude or you.

- In Claude Code's fullscreen layout (`CLAUDE_CODE_NO_FLICKER=1`, and the
  desktop app), click into the screen: that click takes the input from
  Claude at once (Claude's input waiting to go in is dropped and Claude is
  told to read the screen again). Claude Code keeps ^C, ^D, ^Z and Esc for
  itself, so press **Ctrl-]** then **c**, **d**, **z** or **[** for them,
  or use the Interrupt, EOF and Esc buttons. Esc gives the keys back to
  Claude Code.
- On the main screen (no clicks reach plugins there) the pane has a line
  field (Enter sends the line) and the buttons.
- **Hand back to Claude** gives the input back; Claude reads the screen
  before it types again. The shell, its folder and variables stay as you
  left them.

Claude types only while it holds the input, and only into the screen it last
read. With several agents one types at a time.

**Passwords in a terminal.** When a program in a gateway terminal asks for a
password (`sudo`, `ssh`, anything that turns echo off), the gateway's dialog
opens in Claude Code, naming the terminal and the program. What you type or
paste there goes to that program only; Claude sees "[credential supplied]".

**Jobs.** A job runs one command in its own terminal; Claude polls it with
`job_status` and `job_tail` (output masked, bounded). Watch one with
`/gate-terminal j_...`.

## Remote terminals and jobs

Give a host from `gateway.toml` and a terminal or job runs there:
the gateway's `terminal_open` and `job_start` take `host` (checkpoint's
`job_start` doesn't: its jobs run on this machine). The first one sets up the
gateway's own runtime on that host; later ones reuse it. `host_runtime` says
whether a host is reachable, accepts the gateway's key and has its runtime
ready, as of its last contact.

**What the host needs.** An ssh login the gateway can use (the host in
`gateway.toml` with `ssh = true`, set up with `gate check NAME`), a login
shell that runs POSIX `sh -c` command lines (sh, bash, dash, zsh or ksh), the
usual POSIX tools, and about 80 MB free in your home while the runtime is set
up (about 50 MB stay). No root, no sudo, no pixi, nothing system-wide; your
`~/.bashrc`, `~/.profile` and the host's PATH are never used inside it.

**What the gateway does there.** It packs bash and tmux for the host's system
on your computer (once per system; the first time downloads about 20 MB from
conda-forge), copies them over its own ssh connection into
`~/.local/share/gateway-runtime/<version>-<system>/`, checks every file's
sha256 on the host, unpacks them, checks that bash and tmux start, and removes
older versions it made there once nothing runs in them. Set `runtime =
"/another/folder"` in the host's entry if your home is small, mounted
`noexec`, or the path is too long.

**Who that host is.** The first time, the gateway records the host's machine
id next to its pinned host key. If either changes later, nothing runs there
until you answer the gateway's dialog; work started on the old machine is
reported as unknown, never continued on the new one.

**When the connection drops.** The terminals and jobs keep running on the
host. Meanwhile they show as `disconnected` (or `waiting_auth` when the host
refuses the gateway's key: `gate check NAME` installs it again); when the
host answers again the gateway asks it what survived: still running, finished
with its exit code or signal, or `unknown` (never "done"). A start whose
answer was lost stays `unknown` until the host says whether it started; a
retry with the same idempotency key never runs it twice.

## The gateway's dialog

The gateway asks you only in its own dialog inside Claude Code, a pane its
mod draws, never in the chat, an OS window, a browser or another terminal.

- It opens right after a change you asked for (Claude runs `gate check
  NAME`), or the first time a command needs something, such as a sudo
  password. It names the machine or account, what is asked and why.
- **Typing a secret:** click the field, then type. The field shows dots;
  Enter submits; the value is encrypted inside the field to the gateway's
  helper before it goes anywhere. Until you click, keys go to Claude Code's
  prompt box: while the dialog waits, the gateway holds back what you type
  there and says "click the gateway dialog's field first" (only its own
  commands, such as `/gate-dialog`, can be typed then). Each click starts the
  field empty.
- **Paste from clipboard:** the gateway's helper reads the clipboard itself,
  so the value never passes through Claude Code. A paste into the field
  doesn't work (Claude Code sends pastes to the prompt box): use the button.
- **Typing needs Claude Code's fullscreen view** (`CLAUDE_CODE_NO_FLICKER=1`):
  on the main screen clicks don't reach plugins, so the dialog offers Paste
  from clipboard instead. Buttons also work from the keyboard: `/gate-dialog`
  gives the dialog the keys, then Tab and Enter.
- **One at a time.** Others wait in line, named at the dialog's bottom.
- The command waits up to 90 seconds; if you're away, Claude is told the
  dialog is still open and carries on. The dialog stays up to 30 minutes;
  your answer is used when you give it, and Claude's retry gets the result.
- **Cancel** means no: Claude won't ask the same thing again until you write
  to it.
- Passwords and GitHub, Hugging Face and Azure credentials are checked before
  they're saved: a wrong one reopens the dialog with "That didn't work" (3
  tries) and is never stored. One that stops working later is never retried.
- Before using what you entered, the gateway checks again that the request
  still stands: the program that asked still runs, the session is open and
  not paused (a pause checkpoint 0.6+ reports through the contract counts),
  and the entry still has the rights it needs.

### The vault passphrase

`/gate-unlock` the first time asks for a passphrase twice (at least 12
characters); the gateway encrypts the vault's key with it (age's scrypt),
checks that it opens again and removes the plain key file. From then on only
the gateway's helper holds the key unlocked, in memory: `/gate-lock` locks it
at once, it locks itself after `lock_after` without use (8 hours by default)
and when the helper stops. When a command needs the locked vault, the unlock
dialog opens by itself. A forgotten passphrase can't be recovered: export
first ([Moving to another machine](#moving-to-another-machine)).

## With checkpoint

With [checkpoint](https://github.com/p-w-rs/checkpoint) installed too, Claude
can start long work with checkpoint's `job_start`, and checkpoint records the
task.

- **Who runs the job.** While the gateway serves the session, checkpoint
  hands the job to the gateway: it runs in the gateway's managed shell in
  its tmux, the gateway keeps its output (bounded, masked) and checkpoint
  keeps a record. A checkpoint pause tells the gateway, which applies each
  job's pause policy (continue, interrupt, suspend or detach) and reports
  what it did; the gateway also stops asking for secrets in that session
  while it is paused. When the gateway isn't available to that session
  (not installed, disabled there, an incompatible version), checkpoint runs
  the job itself, with the gateway's stand-ins from `~/.config/gateway/env.sh`
  (which does nothing once the gateway is uninstalled); `/check:status` says
  which.
- **The same checks as a command Claude types.** The gateway judges a job's
  command at `job_start`: `curl`, `wget`, its private folder and session
  transcripts, `gate export`, `import` and `copy-to`, and hosts or rights set
  to `false` are refused; an `"ask"` right can't be used in a job (nobody can
  be asked while it runs); and the gateway never approves a job by itself:
  Claude Code asks you or its reviewer decides.
- **Masking.** What `job_tail`, `job_status` and `job_stop` show Claude is
  masked like Claude's own commands. A job checkpoint ran itself keeps its
  raw log file on disk, and a failed `job_stop`'s error text (its last lines)
  can't be masked (the gateway warns instead).
- **Credentials.** A job gets keys, passwords and tokens only while the
  Claude session that started it is open; after that only entries with
  `scripts = true` still give it theirs. Keep the session open until such a
  job is done, or, where acceptable, set `scripts = true`.

The gateway's helper, `gated`, runs one per user, started on demand; it
exits 30 minutes after the last session ends (not while a terminal or job
runs), and within about half a minute once its plugin is uninstalled and no
session uses it. Uninstalled while a terminal or job still runs, it starts
nothing new and stops offering itself to checkpoint at once, leaves that
work running, and exits (with its private tmux) once it has ended. Its
private tmux also goes whenever it exits with nothing running. Checkpoint finds it
through `~/.config/gateway/run/contract.json`
([docs/CONTRACT-v1.md](docs/CONTRACT-v1.md)); nothing secret is ever on that
channel.

## Moving to another machine

**A file: "Export my gateway."** `gate export` shows a checklist of what to
include, item by item, then asks for a passphrase twice in the dialog (at
least 12 characters). By default the file goes to
`~/Downloads/gateway-YYYYMMDD.age`; it never overwrites a file and refuses
folders inside a git repository or a cloud-synced folder. On the other
machine, ask Claude to "import FILE". A wrong passphrase is asked again; a
changed or damaged file is refused as such. Something that exists on both
machines and differs gets its own choice: keep this one, take the file's, or
add the file's under a new name (for a host key: keep or trust the file's).
The import is written in one step after a backup of your form and vault (in
`~/.config/gateway/private/backups/`); if anything fails, both are put back.
Imported accounts are checked right away; one whose sign-in can't move
between machines is marked "needs a fresh sign-in". The file holds no
process ids, terminals or jobs.

**Over ssh: "Copy my gateway to homelab."** `gate copy-to homelab` needs
homelab in your form with ssh on and its host key pinned, and the gateway
already installed and set up there. The copy is encrypted to that machine's
own gateway key (compare it with `~/.config/gateway/gate pubkey` there).

Either way the machine you import on is recognized (by its SSH host key, or
the machine identity the gateway recorded) and becomes `localhost`; the
machine you came from becomes a named host with `ssh = false` until you turn
it on.

## Data, retention, backup

| What | Where | Kept |
|---|---|---|
| The form | `~/.config/gateway/gateway.toml` | until you delete it; updates and uninstall keep it |
| The vault and its key | `~/.config/gateway/private/`: `vault.age`, `cache.age` (short-lived tokens), and `key.txt` or, with a passphrase, `key.wrapped` + `key.recipient` | as above |
| Backups | `~/.config/gateway/private/backups/` (the 0.6 conversion, before every import) | until you delete them |
| Launcher and env file | `~/.config/gateway/gate`, `env.sh` | rewritten every session; inert after uninstall |
| Discovery file for checkpoint | `~/.config/gateway/run/contract.json` | while the helper runs |
| Built tools, stand-ins, git settings, the managed shell's settings, remote packs | the plugin's data folder: `~/.claude/plugins/data/gate-gateway` (or under `$CLAUDE_CONFIG_DIR`) | updates keep it (an old tool set unused for 7 days is removed); uninstall deletes the folder, `--keep-data` keeps it |
| Audit log (values redacted) | data folder, `audit.jsonl` | rotated at 5 MB, one older copy |
| The helper's log and event log | data folder, `gated/` | log rotated at 1 MB; events of the last 5 helper starts |
| Terminal and job records, job output | data folder, `gated/terminals.json`; output in the helper's memory and tmux's history | records 24 h after a terminal or job ends; a job's last 256 KiB of output |
| Sockets, ssh connections, the terminals' tmux server | `/tmp/gw-<uid>/` (private) | until the helper stops or the machine restarts |
| Remote runtime | `~/.local/share/gateway-runtime/` on each host (or its `runtime`) | older versions removed once idle; uninstalling the plugin leaves them |
| Claude's SSH keys | in the vault; their public halves in `~/.ssh/authorized_keys` on your servers (lines ending in `gateway-NAME@...`) | until `gate forget` or you remove them |

**Backup.** `gate export` (an encrypted file: keep its passphrase safe), or
copy `~/.config/gateway` with Claude Code stopped (it holds the vault's key
unless you set a passphrase: keep that copy private). **Restore**: `gate
import FILE` on any machine, or copy the folder back to the same place.

## Upgrading

**From 0.6** (the version on GitHub before this one). The first session with
this version converts the 0.6 vault automatically, offline:

- **Backup first.** The 0.6 vault and its key are copied to
  `~/.config/gateway/private/backups/` (`store-v2-YYYYMMDD.age`,
  `key-v2.txt`); after a successful conversion the originals move there too.
- **New names.** `github:work` becomes `github-work` (or `github` if you had
  one GitHub account), `ssh:homelab` becomes the host `homelab` with its keys,
  addresses and pinned host keys, sudo passwords join their hosts, secrets
  become `api-key` accounts. The old names keep working.
- **The key** is a plain file (`private/key.txt`) as before; protecting it
  with a passphrase is your choice (`/gate-unlock`).
- **A report** is shown once (later: `gate status --report`): renames, what
  was dropped, and every host where 0.6 asked each time and the new form
  says `true` (set `"ask"` where you want the prompt back).
- **If you already had a `gateway.toml`**, the converted entries go to
  `gateway.from-v2.toml`; copy the ones you want (they need no new OK).
- **If the conversion fails**, nothing is changed and the reason is shown;
  `gate migrate` tries again.

**From 0.7 or 0.8** (development builds from a checkout). Nothing is
converted: the form, the vault and the plain key file stay as they are. What
changes: Claude's commands now run in the managed shell (import the tools you
need with `[shell] import_path`); every question is the dialog inside Claude
Code (OS dialogs and `gate secret` are gone); browser and device-code
sign-ins are gone (refresh tokens already stored keep working until they
expire; then a personal access token or a service principal); the gateway no
longer offers sudo without a password (a sudoers file 0.8 or earlier
installed for it stays: delete it from `/etc/sudoers.d` and check with `sudo
visudo -c`); export files are format 3 (older files still import).

**The helper after an update.** A newer version restarts an idle older
helper; one still running terminals or jobs is kept until they finish
(`/gate-doctor` says so), and they keep running.

**Rolling back to 0.6.** In your own terminal (Claude can't read
`private/`): `claude plugin marketplace remove gateway` (that also
uninstalls the plugin); then `cd
~/.config/gateway && mv private/backups/store-v2-YYYYMMDD.age store.age && mv
private/backups/key-v2.txt key.txt`; then `claude plugin marketplace add
p-w-rs/gateway#accounts-phase1` (0.6.0, commit `c75fa82`) and `claude plugin
install gate@gateway`. Anything you added after the upgrade isn't in the 0.6
vault; upgrading again later keeps the v3 vault.

## Recovery procedures

- **Setup was cut short** (Claude Code quit, the machine slept): start a new
  session; it sees the stale setup and finishes it. **Setup failed**: the
  message names the log; it's retried at every session start; `/gate-doctor`
  shows the reason.
- **"the managed shell isn't ready"**: wait until the `gate: setting up…`
  line under the prompt goes (a `ready` notice shows in the corner).
- **"the gateway vault is locked"**: `/gate-unlock`. **Passphrase
  forgotten**: the vault can't be opened; import your last export (`gate
  import FILE`) or set things up again.
- **A dialog is waiting or was closed**: `/gate-dialog`.
- **"refused Claude's key"**: `gate check NAME` installs it again. **A
  changed host key or machine**: the dialog shows old and new; confirm only
  if you expected it (a reinstalled server), else leave the host blocked.
- **The helper seems stuck** (commands slow, `/gate-doctor` says it isn't
  answering): the hooks give up on it after 5 s and carry on without it;
  `pkill -f "run.py gated serve"` stops it and the next command starts a new
  one, which adopts the running terminals and jobs.
- **Claude Code crashed or was restarted**: gateway terminals and jobs keep
  running; `/gate-terminal` shows them again.
- **A remote host went away**: its terminals show `disconnected`; when it
  answers again they are checked and reported. `host_runtime` with `provision`
  sets a host's runtime up again; `clean` removes old versions.
- **An import went wrong**: the form and vault are put back from the backup
  automatically; the backup stays in `private/backups/import-*`.
- **A bad edit to gateway.toml**: only that entry is off (`gate status` names
  the line); a file that doesn't parse keeps the last good version in use.
- **Why was something refused?** `gate why`; **what did it do?** `gate log`.

## Security, honestly

What the gateway does:

- **Claude never gets a secret value.** Secrets are typed or pasted only in
  the gateway's dialog, encrypted in its field to the gateway's helper (NaCl
  box, a key made for that one request) and stored encrypted with
  [age](https://age-encryption.org) in `~/.config/gateway/private/`, which
  Claude's tools are refused. A credential goes only to the one process that
  needs it, never on a command line. Output Claude sees is masked (every
  stored secret and anything shaped like a token), and tokens pasted into the
  chat are blocked. In the live tests, test secrets typed, pasted or stored
  this way were found in no transcript, history, debug log, model request,
  telemetry payload (captured before encryption), process listing, file of
  either plugin, or export.
- **Each credential goes only where you approved.** An account's token goes
  only to the sites computed from its entry when you OK'd it. SSH keys and
  sudo passwords belong to a host's pinned host key.
- **Claude can't give itself more.** It can edit the form, but nothing wider
  takes effect until you OK it (default button Decline). Dialogs use fixed
  wording; text Claude wrote never appears in them.
- **Your own credentials stay out.** The managed shell drops your ssh agent
  and token variables (`SSH_AUTH_SOCK`, `GITHUB_TOKEN`, `HF_TOKEN`, ...),
  anything that looks like a credential, your rc files, aliases and
  functions, and git's own credential helpers are switched off there, so
  Claude uses only what's in the form (unless `others = "mine"`).
- **Only Claude's own commands get credentials** (a program they start gets
  none unless `scripts = true`), checked by walking the process tree.
- **Everything is logged** (values redacted): `gate log`. Security events are
  also kept in the vault and shown at the next session start.

What it can't do:

- **Claude's commands run as you.** A determined program could read the
  vault's key file, as it could any of your files; the gateway's refusals
  are text checks, not a sandbox. With a passphrase set (`/gate-unlock`)
  there is no key file, and only the helper decrypts.
- **Other routes to ssh, sudo and the account tools.** In the managed shell
  the gateway refuses the usual ways around its stand-ins: `/usr/bin/ssh` or
  `./sudo` by path, `command -p ssh`, `env -i ssh`, a changed `PATH` or
  `GIT_SSH_COMMAND`, `rsync -e` or `git -c core.sshCommand` naming another
  ssh, a shell string (`bash -c '...'`), `eval`, `exec`, a function, `find
  -exec`, a variable as the program. A program that runs the system's ssh
  itself is seen by no hook: it gets only what any program you run would
  get (and in the managed shell, not your agent), never the gateway's stored
  credentials, which only the stand-ins hand out.
- **What you set to `true` skips auto mode's reviewer.** That is the trade.
- **Other plugins run inside Claude Code.** The dialog's field is private
  from other plugins' hooks and from Claude Code's transcript, history and
  telemetry (tested), but keys typed into the prompt box before clicking the
  field reach every plugin's prompt hooks. Install only plugins you trust.
- More, each with what to do about it: [Known limitations](#known-limitations).

## Known limitations

Each with the smallest remedy.

- **Desktop app untested.** It runs the same mod, but its dialogs, panes and
  the private field were never exercised. Remedy: use the terminal, or try
  the desktop app with a throwaway value before trusting it with a real one.
- **No dialogs in VS Code, the mobile app, Remote Control, `claude -p` or the
  SDK** (they have no private field). A request that needs you says so and
  asks nothing. Remedy: give it once from a terminal session (`gate check
  NAME`); stored credentials then work everywhere.
- **Claude Code older than 2.1.287 (terminal) or 2.1.286 (desktop), or mods
  switched off**: no dialogs, and in the default managed mode Claude's Bash
  and Monitor are refused ("managed shell unavailable"); choosing `"warn"`
  or `"off"` needs a dialog too. Remedy: update Claude Code; if mods are off
  for your account, `claude plugin disable gate@gateway` until they're back.
- **The secret field needs the fullscreen view.** On the terminal's main
  screen it can't be clicked. Remedy: start with `CLAUDE_CODE_NO_FLICKER=1`,
  or use Paste from clipboard.
- **Keys typed before clicking the field** are held back from the prompt but
  seen by other plugins' prompt hooks and drawn for a moment. Remedy: click
  the field first.
- **Output the gateway can't mask**: a command that fails (non-zero exit,
  timeout, kill), Monitor's lines, a background command's output and its
  output file, a failed checkpoint `job_stop`. Claude Code passes these to no
  hook that can rewrite them; the gateway warns and names the secret to
  replace. Remedy: replace a secret that showed; Claude can pipe such output
  through `gate scrub`.
- **Tokens in a running tool's environment**: `gh`, `databricks`, `dvc` and
  `gate with` hold their token while they run, visible to your own processes
  (`ps eww`). Remedy: prefer the `http` tool; give `env` and `scripts = true`
  only where needed.
- **A stored sudo password on another machine** sits in a private file there
  while each sudo runs, readable by your processes on that machine. Remedy:
  *Ask me each time* with **Remember it** unticked, or `elevation = "ask"`
  in that host's policy.
- **A job that outlives its session** gets credentials only from entries with
  `scripts = true`. Remedy: keep the session open until it ends.
- **The very first setup** (about a minute after install): Claude's commands
  are refused, and output masking and the rights checks wait for the tools;
  only the reduced checks run. Remedy: wait for the `ready` notice (the
  `gate: setting up…` line goes).
- **git marketplaces need git on PATH** (also for `marketplace update`), and
  some pixi installs don't put `~/.pixi/bin` on PATH. Remedy: `export
  PATH="$HOME/.pixi/bin:$PATH"`.
- **The first remote host of each system** downloads about 20 MB from
  conda-forge without proxy settings. Remedy: set it up once from a network
  with direct access (`host_runtime` provision); later ones use the cache.
- **The `http` tool and the account tools ignore proxies and custom CA
  bundles** (so credentials can't be routed through an interceptor). Remedy:
  a direct network for them; git uses your proxy settings.
- **Status lines carry Claude Code's warning sign** (`⚠ gate: setting up…`):
  Claude Code draws every plugin's status line that way and offers plugins
  no other kind. The gateway uses the line only while something needs you or
  waits (setup, a failed setup, a waiting dialog, a refused key, a daemon
  from another version) and says `ready` in a corner notice instead. Remedy:
  none needed.
- **A disabled (not uninstalled) gateway's helper** keeps running until it
  has been idle 30 minutes; it refuses that session's calls and checkpoint
  says so. Remedy: none needed; `pkill -f "run.py gated serve"` stops it now.
- **SSH key passphrases aren't stored**, so a passphrase-protected key can't
  be imported. Remedy: let `gate check NAME` install Claude's own key.
- **No browser or device-code sign-ins** (they would need a web page).
  Remedy: a GitHub personal access token, an Azure service principal, API
  keys; refresh tokens stored by older versions keep working until they
  expire.
- **`"ask"` can't reach inside a script sourced into Claude's shell**
  (`source x.sh`). Remedy: set what must never run unasked to `false`.
- **Workspace paths are compared as written** (a symlink on the host isn't
  followed). Remedy: write remote paths the way the workspace root is
  written.
- **Terminals don't tell when a program waits for input.** Remedy: Claude
  reads the screen; you can look with `/gate-terminal`.
- **Untested systems**: Intel Macs, Linux x86-64, WSL 2, remote linux-64 and
  osx-64 hosts, hosts behind `via`; native Windows unsupported. Remedy: WSL 2
  on Windows; report what you find elsewhere.

## Uninstall

`claude plugin uninstall gate@gateway` (in Claude Code: `/plugin`; desktop
app: **+** → **Plugins** → **Manage plugins**). That removes the plugin and
its data folder (`--keep-data` keeps it). The background helper notices at
its next check (within about half a minute, once no session uses it) and
exits, with its private tmux. If a gateway terminal or job still runs, it
stops offering itself to checkpoint and refuses new terminals and jobs at
once, leaves the running ones alone (never killed; jobs on remote hosts keep
running there), and exits with its tmux once the local ones have ended. From
the next session Claude's terminal is back to normal.

Your form and vault stay in `~/.config/gateway` (the `gate` launcher then only
says the plugin isn't there, and `env.sh` does nothing), so a reinstall picks
up where you left off. To remove everything, export first if you like, then
delete that folder yourself. On your servers, Claude's public keys stay in
`~/.ssh/authorized_keys` (lines ending in `gateway-NAME@...`), and remote
runtimes in `~/.local/share/gateway-runtime/`; delete them there. (Gateway
0.8 and earlier could add a sudoers file named after the gateway in
`/etc/sudoers.d`; if you made one, delete it and check with `sudo visudo
-c`.)

## Troubleshooting

- **What does Claude have?** `/gate:status`, or `~/.config/gateway/gate
  status [NAME]` in a terminal.
- **Why was something refused?** `gate why` prints the last refusal and the
  fix. Every message from the gateway starts with `gateway:` and says what to
  do next.
- **"... waits for the user's OK; run gate check NAME while the user is
  here"**: you haven't approved that right yet; Claude runs `gate check NAME`
  while you're there. "NAME goes through JUMP, which isn't set up yet": `gate
  check JUMP` first.
- **"no account is chosen for github.com/OWNER"** or **"both ... fit"**: add
  `owners` or `default = true`; Claude can pick one with `GATE_ACCOUNT=NAME`.
- **pixi missing**: the session start says `gateway: pixi isn't installed`;
  install it and start a new session. **pixi too old**: "workspace requires
  pixi '>=0.68.0'"; run `pixi self-update`.
- **"Executable not found in $PATH: git"** when adding the marketplace:
  [Before you install](#before-you-install).
- **No `http` tool in the first session**: start a new session, or reconnect
  `gw` in `/mcp`.
- **The field doesn't take my typing**: click it first; on the main screen
  use Paste from clipboard or start with `CLAUDE_CODE_NO_FLICKER=1`.
- **"X isn't in gateway.toml"**: add it (Claude can import it from
  `~/.ssh/config`).
- **Long transfers and upgrades** should run as a job or with a longer Bash
  timeout; the 2-minute default stops them midway.
- **"gate secret was removed"**: secrets are entered only in the dialog; ask
  Claude to run `gate check NAME`.
- **A change to the form doesn't take effect**: it may wait for your OK
  (`gate status`, "Waiting for your OK") or have a mistake ("Problems in
  gateway.toml").
- **After installing or updating the plugin**, start a new session.

## Develop

```bash
cd plugins/gateway
pixi run --locked test        # offline: throwaway homes, a fake dialog, a real gated with a fake mod, local servers
pixi run --locked mutations   # every guard removed in turn on a scratch copy: a test must fail
claude plugin validate .      # and ../.. for the marketplace
claude plugin test .          # the mod's own tests (hooks/mod/*.test.ts)
pixi run release-check        # after `git add -A`: does the index hold the tested tree?
# live acceptance in a real Claude Code TUI against a fake API (scratch configs; see CLAUDE.md):
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_install.py --tmp DIR
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_dialogs.py --tmp DIR
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_canaries.py --tmp DIR
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_native_ui.py --tmp DIR
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_managed.py --tmp DIR
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_terminals.py --tmp DIR
# the remote runtime, against a disposable Linux VM and a local sshd:
pixi run --locked python tests/acceptance_remote.py --vm VMDIR --tmp DIR
```

More in [CLAUDE.md](CLAUDE.md). How it fits together:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); why it looks this way:
[docs/DECISIONS.md](docs/DECISIONS.md); the plan and requirements matrix:
[docs/PLAN-v4.md](docs/PLAN-v4.md); the checkpoint contract:
[docs/CONTRACT-v1.md](docs/CONTRACT-v1.md).
