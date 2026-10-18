# gateway

A Claude Code plugin that gives Claude **one audited path** for network,
credential and root work, instead of letting it run `curl`, `wget`, `nmap`,
`certutil`, `cmdkey`, the macOS `security` tool, PowerShell web cmdlets, or
`sudo` with a password directly.

Claude still gets the work done. It just does it through gateway tools that
keep secret values out of the conversation, only send a credential to the
hosts you allowed, ask before root commands (unless you switch that off for a
host), and log everything.

> Developing on this repo, or an agent picking it up? Start with
> [CLAUDE.md](CLAUDE.md), then [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What you get

| Instead of | Claude uses |
|---|---|
| `curl`/`wget` to read a page | the built-in **WebFetch** |
| `curl`/`Invoke-RestMethod` to an API | **http_request** (any method, headers, body; auth by secret NAME) |
| `curl -O` / `wget` a file | **download** (to a quarantine folder, never executed, size-capped) |
| `nmap` / `masscan` up-or-down checks | **port_check** (plain TCP connect; asks you first) |
| `certutil` / `openssl s_client` | **cert_inspect** (also reports self-signed/expired certs) |
| `certutil -hashfile` | **file_hash** |
| `sudo` with a typed password | **run_privileged** / **run_privileged_confirm** |
| keychain / env tokens | secrets in the gateway's own vault, used by NAME |

## Managing secrets, sudo and accounts (you, in the chat)

```
/gate:secret add HF_TOKEN Hugging Face Hub token   → a browser page asks for the value
/gate:secret allow HF_TOKEN huggingface.co         → where it may be sent
/gate:secret up HF_TOKEN [new description]         → new value (browser page)
/gate:secret desc | disallow | del | list | help

/gate:sudo add $USER localhost                    → a browser page asks for the password
/gate:sudo add admin myserver                   (an ssh alias, host name or IP)
/gate:sudo enable myserver                       → root runs WITHOUT asking, this session only
/gate:sudo enable myserver always                → ...in every session
/gate:sudo disable myserver                      → back to asking (all sessions)
/gate:sudo up | del | list | help

/gate:account add github work Work GitHub (asirobots)  → a browser page asks login, owners,
                                                         token and/or SSH key (paste or generate)
/gate:account allow github:work asirobots           → owners/orgs (or hosts, with a dot) it is for
/gate:account prompts github:work write=ask         → when tools using it must ask you first
/gate:account pubkey github:work                    → the public key to paste on the site
/gate:account import github:work GITHUB_TOKEN       → reuse a /gate:secret value as its token
/gate:account up | desc | disallow | forget | del | list | help
```

**Accounts** are separate identities, kept apart from your own environment:
several GitHub accounts side by side, Hugging Face, Pijul (the Nest or your own
server), Azure, the ASI ML Catalog, SSH hosts and container registries
(`KIND:NAME`, e.g. `github:work`). Each is scoped to its hosts and owners, and
its prompt policy (`read`, `write`, `delete`, `exec` = `auto`, `ask` or
`refuse`) lives in the vault, so Claude can't loosen it. 

`/gate:account login KIND:NAME` signs in with SSO:
- GitHub: through the plugin's own gh web flow, including SSO-only orgs.
- Azure and the ASI ML Catalog: through Microsoft Entra, in your browser,
  or with a device code in a terminal.

Claude then works through the gateway's tools, each picking the right account:

| Tool | For |
|---|---|
| `git` | every git command (local ones without credentials; remote ones as the account for that remote's host and owner) |
| `git_mirror` | keep one repo's branches and tags the same on several remotes, e.g. personal and work (fast-forward only, never forced) |
| `git_identity` | commit as an account in a repo |
| `gh` | GitHub's CLI (the plugin's own copy) |
| `hf` | Hugging Face uploads, downloads, repos (Xet) |
| `pijul` | Pijul, with the Nest or your own server (signs with the account's key) |
| `ssh_exec`, `ssh_copy` | servers as ssh accounts, with jump hosts; `run_privileged` uses them too |
| `databricks` | the Databricks CLI with an Entra token |
| `mlcat`, `mlcat_workspace` | the ASI ML Catalog: search, and asiml's init/clone/pull/push/status |
| `registry` | container images (ghcr.io via GitHub, ACR via Azure, others by token), no Docker needed |
| `http_request` | any API, with `auth_ref=KIND:NAME` (Azure: plus `auth_scope`) |

When an account's policy says `ask`, the tool's `_confirm` twin runs the call
after Claude Code asks you. The optional tools install on first use (the tool
tells Claude the exact `pixi install -e …` command). Ask Claude in plain words
to set up a mirror ("keep this repo in sync on my personal and work GitHub");
the `gate:accounts` skill tells it how.

- **Values never go in the chat.** A one-time page opens in your browser on
  `127.0.0.1` with a masked field; you paste and Save. Claude never sees the
  value, and it isn't written to the transcript.
- **No popups.** The command holds no secret, so it passes through and Claude
  just confirms the result in a line.
- **Safety net.** If you type something that looks like a token anyway, the
  command is blocked, nothing is saved, and your text is scrubbed from the
  transcript.
- **Claude can't run these commands itself.** When something is missing or not
  allowed, it tells you the exact command to run.

## How it behaves in auto mode

| Silent | Asks you (Claude Code's prompt) | Blocked |
|---|---|---|
| web requests, downloads, cert checks, file hashes, listing secret names | `port_check`, and the `_confirm` tools (the plugin's own hook asks) | `curl`, `wget`, `nmap`, `security`, … in Bash (redirected to the gateway) |
| a secret going to one of its allowed hosts | root commands on a host where sudo is **disabled** (`run_privileged_confirm`) | a secret going to any other host (Claude tells you the `/secret allow` command) |
| root commands where sudo is **enabled** for this session or always | | reading the vault or your personal age store; `file://` URLs |

A new session warns you while sudo is enabled for it.

## Requirements and install

You need only **[Claude Code](https://code.claude.com)** and
**[pixi](https://pixi.sh)** (`curl -fsSL https://pixi.sh/install.sh | sh`).
pixi supplies Python 3.12 and `age` (for the vault) from `pixi.lock` for macOS
(Intel and Apple Silicon), Linux (x86-64 and arm64) and Windows. All gateway
code is Python standard library.

In Claude Code:

```
/plugin marketplace add p-w-rs/gateway
/plugin install gate@gateway
```

Then start a new session and run **`/gate:help`**. That's all: nothing is
added to your settings. The gateway's rules live in its own hooks and are
active whenever the plugin is enabled:
- git, gh, hf, pijul, ssh, scp, docker login/push/pull, az and the like in
  Claude's Bash are redirected to the gateway's account tools;
- your own credential variables (`GITHUB_TOKEN`, `HF_TOKEN`, …) and your
  ssh-agent are removed from every command Claude runs (your terminal is
  unaffected);
- Claude can't read your credential files (`~/.ssh` private keys, gh's
  `hosts.yml`, `~/.docker/config.json`, …) or the vault.

To turn all of it off, disable the plugin (`/plugin`).

**From a local checkout** (to work on the gateway): clone it, then in
`plugins/gateway` run `pixi run install`. That registers the clone as the
`gateway` marketplace, and also removes rules that gateway 0.5 wrote into
`settings.json` (it shows them and asks first).

### Linux and headless machines

- **Desktop Linux:** the value form opens in your browser (needs `DISPLAY` or
  `WAYLAND_DISPLAY`).
- **No desktop (ssh, servers):** the slash command can't open a browser, so it
  tells you the exact terminal command, which asks at a hidden prompt:

  ```bash
  pixi run --manifest-path ~/gateway/plugins/gateway/pixi.toml vault secret add NAME description
  pixi run --manifest-path ~/gateway/plugins/gateway/pixi.toml vault account add KIND NAME description
  pixi run --manifest-path ~/gateway/plugins/gateway/pixi.toml vault sudo add USER HOST
  ```

  Sudo enable from the terminal needs `always`, because a terminal has no
  Claude session.
- **Remote sudo** uses your normal ssh keys or agent (`BatchMode`; no
  password prompts). The remote login shell must be a POSIX `sh`, such as bash
  or dash, not fish.

## Configure

`plugins/gateway/config/policy.json`: allowed domains, port-check scope,
approval tiers, response and download size limits. Credentials and their hosts
are **not** configured here; use `/gate:secret`.

## Review what happened

`/gate:log` summarizes the audit log (`plugins/gateway/logs/`):
hosts contacted, credentials used (by name), root commands and how each was
approved, vault changes, refusals. It never shows values.

## Develop / test

```bash
cd plugins/gateway
pixi run test          # ~240 checks, offline, uses throwaway vaults and fakes
claude plugin validate .
```
