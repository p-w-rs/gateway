---
description: Quick guide to gateway - what it does and how to manage secrets, sudo and accounts
---

Give the user a short, friendly guide to the gateway plugin, based on the
reference below. Keep it to about a screen: a one-line summary, then the
commands they type, then what happens in auto mode. Then call the
`secret_list` tool and show what's in their vault now (names, hosts, sudo
state; it never contains values). If their message has a question after the
command, answer that instead of the full guide.

Reference:

- **What it is:** Claude's network, credential and root work goes through one
  audited gateway. `curl`, `wget`, `nmap`, `security`, … in Bash are
  redirected to gateway tools (`http_request`, `download`, `port_check`,
  `cert_inspect`, `file_hash`, `run_privileged`). Secret values never reach
  Claude, a secret is only sent to hosts the user allowed, and everything is
  logged.
- **Secrets** (only the user types these; Claude can't run them):
  - `/gate:secret add NAME description`: a one-time page opens in the
    browser with a masked field for the value. Never paste a value in the chat.
  - `/gate:secret allow NAME HOST` (and `disallow`): where it may be sent.
  - `/gate:secret up NAME`, `desc NAME text`, `del NAME`, `list`, `help`.
  - Claude then uses it by NAME, e.g. "call the GitHub API with GITHUB_TOKEN".
- **Sudo:**
  - `/gate:sudo add USER HOST`: the browser page asks for the password.
    HOST is `localhost` (USER must be you), an ssh alias, a host name or an IP;
    remote hosts need ssh keys.
  - `/gate:sudo enable HOST`: root commands there run without asking,
    for this session only. Add `always` for every session.
  - `/gate:sudo disable HOST`: back to asking before each root command
    (the default). Also `up`, `del`, `list`, `help`.
- **Accounts** (separate identities: GitHub, Hugging Face, Pijul, Azure, ASI ML
  Catalog, SSH hosts, container registries; several per service is fine):
  - `/gate:account add KIND NAME description`: the browser page asks the
    login, owners/orgs, a token and/or an SSH key (paste one or generate one;
    the public key is shown so you can add it on the site).
  - `/gate:account allow KIND:NAME OWNER|HOST`: what it may be used for.
  - `/gate:account prompts KIND:NAME|* write=ask delete=refuse ...`: when
    tools using it ask first (classes read, write, delete, exec).
  - `/gate:account pubkey`, `import KIND:NAME SECRET`, `forget`, `up`,
    `desc`, `disallow`, `del`, `list`, `help`.
  - `/gate:account login github:NAME`: sign in with GitHub's web flow (works
    for SSO-only orgs); a page shows the one-time code.
  - Claude runs git and gh through the gateway's `git` and `gh` tools as the
    right account; an account with a token also works as `auth_ref` on
    `http_request`. hf/pijul/Azure tools come later.
- **No browser here** (ssh, headless Linux)? Run the same command in a
  terminal, which asks at a hidden prompt:
  `pixi run --manifest-path <plugin dir>/pixi.toml vault secret add NAME description`
  (and `vault sudo ...`, `vault account ...`; per-session enable needs a Claude session, so use
  `enable HOST always` there).
- **Auto mode:**
  - **Silent:** web requests, downloads, cert checks, file hashes, secrets to
    their allowed hosts, root where sudo is enabled.
  - **Asks first:** `port_check`, root where sudo is disabled.
  - **Refused:** a secret to any other host (Claude tells you the `allow`
    command), reading the vault, `file://` URLs.
- **Review:** `/gate:log` summarizes the audit log, never values.
- **Docs:** README.md, CLAUDE.md and docs/ in the plugin's repo.
