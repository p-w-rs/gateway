---
description: Quick guide to net-gateway - what it does and how to manage secrets and sudo
---

Give the user a short, friendly guide to the net-gateway plugin, based on the
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
  - `/net-gateway:secret add NAME description`: a one-time page opens in the
    browser with a masked field for the value. Never paste a value in the chat.
  - `/net-gateway:secret allow NAME HOST` (and `disallow`): where it may be sent.
  - `/net-gateway:secret up NAME`, `desc NAME text`, `del NAME`, `list`, `help`.
  - Claude then uses it by NAME, e.g. "call the GitHub API with GITHUB_TOKEN".
- **Sudo:**
  - `/net-gateway:sudo add USER HOST`: the browser page asks for the password.
    HOST is `localhost` (USER must be you), an ssh alias, a host name or an IP;
    remote hosts need ssh keys.
  - `/net-gateway:sudo enable HOST`: root commands there run without asking,
    for this session only. Add `always` for every session.
  - `/net-gateway:sudo disable HOST`: back to asking before each root command
    (the default). Also `up`, `del`, `list`, `help`.
- **No browser here** (ssh, headless Linux)? Run the same command in a
  terminal, which asks at a hidden prompt:
  `pixi run --manifest-path <plugin dir>/pixi.toml vault secret add NAME description`
  (and `vault sudo ...`; per-session enable needs a Claude session, so use
  `enable HOST always` there).
- **Auto mode:**
  - **Silent:** web requests, downloads, cert checks, file hashes, secrets to
    their allowed hosts, root where sudo is enabled.
  - **Asks first:** `port_check`, root where sudo is disabled.
  - **Refused:** a secret to any other host (Claude tells you the `allow`
    command), reading the vault, `file://` URLs.
- **Review:** `/net-gateway:net-log` summarizes the audit log, never values.
- **Docs:** README.md, CLAUDE.md and docs/ in the plugin's repo.
