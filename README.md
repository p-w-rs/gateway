# gateway

A Claude Code plugin that holds your passwords, tokens, SSH keys and sign-ins,
and is **the only way Claude uses them**. Claude never sees a value: the
gateway puts it into each request or command itself, sends it only where you
allowed, and logs every use.

> Developing on this repo, or an agent picking it up? Start with
> [CLAUDE.md](CLAUDE.md), then [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Install

You need **[Claude Code](https://code.claude.com)** and
**[pixi](https://pixi.sh)**. In Claude Code:

```
/plugin marketplace add p-w-rs/gateway
/plugin install gate@gateway
```

Start a new session and type **`/gate:help`**. Nothing is added to your
settings; to turn it all off, disable the plugin.

## Add your first account

Type a short command; Claude asks a few questions in its pop-ups and suggests
answers. Then a small **dialog from your system** shows exactly what will
change. A token or password is typed only there, hidden.

```
/gate:add github         (or hf, ssh, azure, catalog, registry, pijul, or just "account")
/gate:add secret         an API key or token for a website
/gate:add sudo           a computer's administrator password
```

For GitHub, Azure and the ML Catalog, the easy choice is to sign in in your
browser; it works with company single sign-on and needs no copying.

## Everyday commands

```
/gate:list                           what the gateway holds (never values)
/gate:update NAME                    change one (sign in again, new token, more orgs, ...)
/gate:delete NAME                    remove one
/gate:enable sudo HOST [always]      admin commands there run without asking
/gate:enable exec ssh:NAME [always]  commands on that server run without asking
                                     (also delete / write / read, for any account)
/gate:disable ...                    back to asking
/gate:block write github:work        make an account read-only for Claude
/gate:enable reuse ssh:NAME          keep a server's connection open (this session)
/gate:export [FILE.age]              everything in one file locked with a passphrase
/gate:import FILE                    bring it in on another computer
/gate:log                            what the gateway did
```

`[always]` keeps a switch on in every session; without it, it ends with this
session.

## What Claude can and can't do

- It works with git, GitHub (`gh`), Hugging Face, Pijul, your servers over
  SSH, Azure / Databricks, the ASI ML Catalog and container registries
  **through the gateway's tools**, each time as the right account. Several
  accounts of one kind (personal and work GitHub) sit side by side.
- Reading and writing (clone, pull, push a branch, open a PR, upload) just
  run. **Deleting and running commands on servers ask you first** in Claude
  Code's permission prompt, unless you switched that off. A plain force-push
  is always refused.
- **Admin (root) commands ask you**, unless you enabled sudo for that machine.
- A secret goes **only to the hosts you allowed**; anywhere else is refused.
- In Claude's own terminal, `curl`, `git`, `gh`, `ssh`, `docker push`, `az`
  and the like are redirected to the gateway. Your own tokens, your
  ssh-agent and your credential files are off limits to Claude. Your own
  terminal is unaffected.
- Claude **can't add or change anything** in the gateway by itself: every
  change starts with a command you type, and you approve it in the dialog.
- If you type something that looks like a token into a command by mistake,
  it's blocked and scrubbed from the transcript.

## No screen? (over ssh, servers)

When a dialog can't open, Claude gives you one command to run in a terminal
on that machine:

```bash
pixi run --manifest-path ~/gateway/plugins/gateway/pixi.toml gateway finish g-1a2b3c4d
```

It shows the same change and asks at a hidden prompt.

## Platforms

macOS and Linux (desktop or headless). The dialogs use macOS's own, or
zenity / kdialog on Linux. pixi supplies Python and `age`; all gateway code is
Python's standard library. Windows isn't supported (no sudo, no pty for the
export passphrase).

## Develop

```bash
cd plugins/gateway
pixi run test            # offline: throwaway vaults, fake dialogs, local servers
claude plugin validate .
```

From a local checkout, `pixi run install` (in `plugins/gateway`) registers the
clone as the `gateway` marketplace. How it works inside:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); why: [docs/DECISIONS.md](docs/DECISIONS.md).
