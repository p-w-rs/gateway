# Gateway v3: hosts and accounts

> **History.** This is the plan the user approved on 2026-10-18, before v3
> was built. It is kept for the reasoning; some details changed during the
> build (for example passwordless sudo in `gate check`, the `az` stand-in, and
> what the http tool does with proxies). What was built:
> [../SPEC-v3.md](../SPEC-v3.md) (contract), [../MODULES-v3.md](../MODULES-v3.md)
> (code), [../../README.md](../../README.md) (user guide),
> [../DECISIONS.md](../DECISIONS.md) (why).

Plan, 2026-10-18 (revised after four independent critiques and prototypes).
Nothing is built yet. The exact mechanics are in [SPEC-v3.md](../SPEC-v3.md).

## The goal

Claude uses sudo, ssh and your accounts like any other command: reliably,
in auto mode, with no permission prompts and no "I can't". The gateway's
job shrinks to:

1. keep passwords, tokens and keys out of chat and the transcript,
2. send each one only where it belongs,
3. give web access its own route (your org's policy makes `curl` and `wget`
   prompt anyway).

Two ideas cover everything: **hosts** (this machine plus named machines,
and what Claude may do on each) and **accounts** (GitHub, Hugging Face,
Azure, the ML Catalog, Pijul, registries, API keys).

Why it prompts today: the gateway itself answers "ask" for its ten
`*_confirm` tools, and starts with sudo off and ssh set to ask. Claude Code
always shows a prompt for a plugin's "ask", even in auto mode. In tests, a
plugin that answers "allow" instead skips auto mode's checks entirely. So
v3 answers "allow" for what you've allowed and stays out of the way
otherwise.

## The form

`~/.config/gateway/gateway.toml`: small, readable, never holds a secret.
You can open it, edit it, or ask Claude to change it. The vault moves
into `~/.config/gateway/private/`, which Claude can't read.

```toml
# The machines and accounts Claude may use. Edit freely, or ask Claude.
# Secrets never go here; the gateway asks for them in a pop-up.
#   true = Claude may do it without asking   "ask" = ask me each time   false = no

[hosts.localhost]                  # this computer, whichever one you're on
sudo = true

[hosts.powerslabs]
address = "joshua@10.0.0.5"
when    = "10.0.0.0/24"            # only try that address on the home network
also    = ["joshua@lab.example.com:2222"]
ssh  = true
sudo = true

[hosts.builder]
address = "ci@builder.internal"
via  = "powerslabs"                # reached through powerslabs
sudo = false

[accounts.github-personal]
kind  = "github"
login = "p-w-rs"
default = true                     # used when nothing else decides

[accounts.github-work]
kind   = "github"
login  = "jpowers-asi"
owners = ["asirobots"]             # repos under these owners use this account
email  = "jpowers@asirobots.com"   # commits in those repos use this identity

[accounts.hf]
kind = "huggingface"

[accounts.azure]
kind       = "azure"
tenant     = "asirobots.com"
databricks = ["adb-1234567890.7.azuredatabricks.net"]

[accounts.catalog]
kind = "ml-catalog"

[accounts.openai]
kind  = "api-key"
sites = ["api.openai.com"]
auth  = "bearer"                   # or "header:X-Api-Key", "query:key", "basic"
env   = "OPENAI_API_KEY"           # optional: programs Claude runs may use it
```

Anything left out has a sensible default; Claude writes only what you said.
A typo disables just that entry; the rest keep working, and both you and
Claude are told exactly which line is wrong.

`/gate:status` (or "what can you access?") is the form as you see it, with
live state and never a value:

```
Hosts
  localhost    sudo ✓ (no password needed)
  powerslabs   ssh ✓ via 10.0.0.5, key installed   sudo ✓ password saved
  builder      ssh ✓ via powerslabs                sudo ✗
Accounts
  github-personal  p-w-rs (default)       signed in
  github-work      jpowers-asi  asirobots signed in
  openai           api.openai.com         key saved
File: ~/.config/gateway/gateway.toml   Just ask: "add a server", "turn off sudo on builder"
```

## How Claude uses them

Plain commands in its own terminal; the gateway supplies credentials
behind the scenes:

```
sudo apt install htop
ssh powerslabs 'df -h'         ssh powerslabs sudo systemctl restart nginx
rsync -a dist/ powerslabs:/srv/app/       scp powerslabs:/var/log/app.log .
git push       gh pr create       hf upload me/model ./out
databricks jobs list       pijul push       asiml push
```

At session start the gateway puts small stand-ins for `sudo`, `ssh`,
`scp`, `sftp`, `gh`, `hf`, `databricks`, `crane`, `pijul`, `asiml` and a
helper `gate` first on Claude's PATH (only in Claude's terminal; yours is
untouched), and gives git a credential helper for your accounts' hosts only.

- **sudo**: if this machine needs no password (yours doesn't), nothing is
  stored or asked. Otherwise the password reaches sudo through a one-time
  helper, so pipes, here-docs and long installs work.
- **ssh, scp, sftp, rsync**: a per-host key the gateway owns, its own ssh
  config and pinned host keys, the right address for the network you're on,
  and connections reused for a couple of minutes.
- **sudo on another machine**: the password is placed briefly in a private
  in-memory file there for that one command (tested against a real sshd,
  including sudo inside scripts and piped input), then removed.
- **git**: the account is picked by host and owner; `git@github.com:`
  remotes are switched to https inside Claude's terminal so tokens from
  browser sign-in work. Your git config and hooks keep working; commits in
  `asirobots` repos use the work identity if you set one.
- **gh, hf, databricks, crane, pijul, asiml**: the right token in that one
  process, output scrubbed, and commands that would print a token refused.
- **Azure**: no `az` CLI; Claude uses the `http` tool with `account:
  "azure"` and the gateway picks the token for the URL. Optionally a tiny
  `az account get-access-token` stand-in lets Azure SDKs in scripts work.
- **Web**: `http` and `download` tools, always visible to Claude.
- **Choosing an account**: by owner, then `default`. Claude can say which
  with `GATE_ACCOUNT=github-work git push`, and every error says so.

### What gets approved automatically

In auto mode the gateway approves, with no classifier and no prompt:

- `sudo …`, `ssh`/`scp`/`sftp`/`rsync` to a host where that's `true`,
  as their own command or chained with simple ones like `cd`;
- the `gate` helper's own commands, and `http` reads and `download`.

`"ask"` gives you Claude Code's normal prompt; `false` is refused with a
clear reason. Everything else, including git, gh and hf, is left to auto
mode as usual (it already allows ordinary pushes and PRs, and still
catches things like printing a token or force-pushing main). In the
default permission mode you're asked as usual.

Claude learns all of this at session start (and every subagent does too):
which hosts and accounts exist, what it may do, and what to say if a
pop-up is waiting. It refreshes when the form changes.

## How you manage it

You talk to Claude, or edit the form.

- "Add my server powerslabs at 10.0.0.5, user joshua, with sudo." Claude
  adds a few lines and runs `gate check powerslabs` right away, while
  you're there. One pop-up shows what was added (address, host-key
  fingerprint, ssh, sudo) and asks how to install Claude's key: using your
  own SSH login once, or by typing joshua's password once. It then asks
  for the sudo password if that machine needs one, and checks it works.
- "Add my work GitHub": one pop-up to sign in in the browser (SSO works)
  or paste a token; the gateway checks you signed in as the right login.
- "Turn off sudo on builder" or "ask me before sudo on powerslabs": one
  word changes. Taking rights away never needs a pop-up.

When Claude adds a host or gives itself more rights (a new host, false to
true, a new address or site), the change takes effect only after you OK it
in one pop-up showing exactly what changed. That's what stops a web page
or README from talking Claude into widening its own access.

Secrets are only typed in the gateway's pop-up. On a machine with no
screen, the gateway shows you (not Claude) one short command to run in a
terminal there: `~/.config/gateway/gate secret powerslabs`.

If a secret is needed while you're away, Claude says once that a pop-up is
waiting and carries on with other work; the pop-up stays until you answer.
A rejected password is never retried (no account lockouts); you get one
pop-up to re-enter it.

## Moving to another machine

- **"Copy my gateway to powerslabs"**: powerslabs is already a host, so the
  gateway sends it over ssh, encrypted to that machine's own key, after you
  OK the list in a pop-up. Claude can install pixi, Claude Code and the
  plugin there first, since it already has ssh and sudo.
- **Or a file**: "export my gateway" gives one file locked with a
  passphrase (written outside any git repo); "import FILE" on the other
  machine.

This machine's `localhost` arrives as a named host (`macbook`, with its
address); the entry for the machine you import on becomes its
`localhost`, recognized by its own host key. Your Mac's login password is
left out unless you tick it.

## Your existing vault

The first v3 session converts today's vault automatically, offline, with a
backup kept: `github:work` becomes `github-work`, `ssh:powerslabs` becomes
host `powerslabs` with its keys, routes and pins, sudo entries join their
hosts, secrets become `api-key` accounts. Old names keep working as
aliases. You get a one-time report of what changed. Hosts where sudo or
ssh used to ask become `true` (that's the point), and the report says so.

## What goes away

- The typed `/gate:add|update|delete|enable|disable|block` commands,
  KIND:NAME names, `always`, `reuse`, grants and the 15-minute window. Left:
  `/gate:status` and `/gate:help`; everything else is "just ask".
- The 10 `*_confirm` tools, the read/write/delete/exec switches, and 33
  tools down to 2 (`http`, `download`).
- Redirecting git, gh and ssh to special tools; the git hardening that
  ignored your config and hooks; gh's refusal lists; the regex blocklist
  (only `curl`/`wget` are redirected, and only as commands).
- port_check, cert_inspect, file_hash (plain `nc`, `openssl`, `shasum`
  work), git_mirror, `config/policy.json`, `install.py`,
  `legacy-settings.json`, MCP elicitation, and the quarantine folder.

## Security, honestly

The gateway never prints a secret itself, scrubs the output it controls
(and anything that looks like a token in tool output before Claude sees
it), sends each secret only to the destinations you approved, and asks you
before Claude gets new rights or a secret goes somewhere new. It keeps
your own SSH agent and tokens out of Claude's terminal.

What it can't do: Claude's commands run as you, so a determined program
could read the vault. Claude Code also keeps raw copies of some command
output on disk. And for what you set to `true`, auto mode's own reviewer
doesn't look at those commands; that's the trade you're asking for.
Credentials are passed to Claude's own commands and the scripts it runs
directly, not to programs those start (an `npm install` script doesn't get
your sudo password), unless you allow it for that host.

## Install

Needs only Claude Code and pixi:

```
/plugin marketplace add p-w-rs/gateway
/plugin install gate@gateway
```

No settings.json changes. Start a new session; the gateway builds its
environment in the background into the plugin's data folder (it survives
updates), finds pixi even with a minimal PATH, and says so if pixi is
missing. The vault and form live in `~/.config/gateway` and survive an
uninstall.

## Decisions for you

1. **Machines and git servers not in the form** (your `~/.ssh/config`
   hosts, gitlab, internal git). Recommended: refused with a hint to add
   them, so Claude only ever uses its own keys. Or: fall through to your
   own ssh agent, keys and git credentials.
2. **Scripts Claude runs** (make, npm, a deploy script). Recommended:
   credentials go to Claude's own commands and shell scripts it runs
   directly, not to programs those start, unless you set `scripts = true`
   on a host or account. Or: everything Claude starts.
3. **Widening needs your OK.** Recommended: one pop-up whenever Claude adds
   a host or gives itself more rights. Or: Claude's edits apply directly.
4. **API keys in programs.** Recommended: opt-in per account with `env =`
   (the program can then read the key). Or: keys only through `http`.

Later and optional: a live panel in the app with the hosts and accounts
and toggles (Claude Code's plugin panes are still marked early access).

## Build plan

1. Form, vault v3 and migration (with backup), `gate status`, hooks that
   build the environment and tell Claude what it has.
2. sudo and the ssh family with the network-aware addresses, connection
   reuse, remote sudo, host-key pinning; the approval hook.
3. git credential helper and identities; gh, hf, databricks, crane, pijul,
   asiml stand-ins; `http` and `download`; output scrubbing.
4. Pop-ups (consent, secrets, sign-in), the no-screen path, export, import
   and copy-to-host.
5. Docs; hermetic tests (every guard mutation-checked); headless runs with
   `claude -p` against a local sshd; then a live try with you.
