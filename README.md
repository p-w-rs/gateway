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
`refuse`) lives in the vault, so Claude can't loosen it. An account with a
token already works as `auth_ref` on `http_request`; the tools that run git,
gh, hf, pijul and the rest as an account, and SSO sign-in
(`/gate:account login`), are coming in later versions.

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
| web requests, downloads, cert checks, file hashes, listing secret names | `port_check` | `curl`, `wget`, `nmap`, `security`, … in Bash (redirected to the gateway) |
| a secret going to one of its allowed hosts | root commands on a host where sudo is **disabled** (`run_privileged_confirm`) | a secret going to any other host (Claude tells you the `/secret allow` command) |
| root commands where sudo is **enabled** for this session or always | | reading the vault or your personal age store; `file://` URLs |

A new session warns you while sudo is enabled for it.

## Requirements and install

You need only **[Claude Code](https://code.claude.com)** and
**[pixi](https://pixi.sh)** (`curl -fsSL https://pixi.sh/install.sh | sh`).
pixi supplies Python 3.12 and `age` (for the vault) from `pixi.lock` for macOS
(Intel and Apple Silicon), Linux (x86-64 and arm64) and Windows. All gateway
code is Python standard library. Put the clone somewhere permanent, because
Claude Code loads the plugin from it.

```bash
git clone https://github.com/p-w-rs/gateway.git ~/gateway
cd ~/gateway/plugins/gateway
pixi run install
```

`pixi run install`:
- registers the repo as the local marketplace `gateway` and installs the
  plugin;
- shows the permission rules from [settings.rules.json](settings.rules.json) it
  will add to your user `settings.json` (in `$CLAUDE_CONFIG_DIR` or
  `~/.claude`), and asks before writing. It makes a backup first.

The `ask` rules are what make Claude Code prompt for `port_check` and for root
commands when sudo is disabled, so keep them. Options: `--dry-run`, `--yes`,
`--skip-plugin`. Then restart Claude Code and run **`/gate:help`**.

Updating later: `git pull` in the clone, then start a new Claude Code session.

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
