---
name: setup
description: Guide the user through adding or changing something in the gateway (an account, a secret, a sudo password, an SSH server) after they typed /gate:add or /gate:update. Use when a gateway note says "Setup g-… is open". Ask a few plain-language questions with question pop-ups, then call gate_setup.
---

# Guiding a gateway setup

The user typed a short command (`/gate:add secret`, `/gate:add account`,
`/gate:update github:work`, …), and the gateway opened a **setup** with a
grant id (`g-…`). Your job is to work out the details with them in plain
words, then call **`gate_setup`** with the grant and a proposal. The gateway
then shows them a dialog with exactly what will change. **They type any
password, token or key there, never in the chat.** You never see it.

## How to ask

- Use your **question pop-ups** (AskUserQuestion), up to 4 questions at a
  time, each with 2–4 short options. Put the recommended option first and add
  "(Recommended)".
- Write for someone who has never used git, ssh or tokens. One sentence per
  option, with no jargon. Explain unavoidable terms in passing: "a token (a
  long password a website gives you for programs)".
- **Look things up instead of asking** when you can: the user's git name and
  email (`git config` via the git tool in a repo), their GitHub login (it
  comes back from a browser sign-in), the orgs in their repo remotes, and the
  hosts in `~/.ssh/config`, which you may read. Then just confirm.
- Names, emails, logins, host names and descriptions are fine in chat. Only
  values are secret: passwords, tokens, keys.
- Keep it short. Most setups need 1–2 pop-ups.

## What to ask, per kind

### Secret (an API key or token for a web service)
Ask, or infer from what they said:
1. **What it's for**, which becomes the description: "OpenCode API key".
2. **Which website it may be sent to**, which becomes the hosts:
   `opencode.ai`, `api.openai.com`, … Suggest the obvious one.
3. **A name** in CAPS_WITH_UNDERSCORES: suggest one (`OPENCODE_API_KEY`).

Proposal: `{"what": "secret", "name": "OPENCODE_API_KEY", "description": "OpenCode API key",
"hosts": ["opencode.ai"]}`

### Sudo (the administrator password of a computer)
Ask which computer: this one (`localhost`) or a server, and the user name
there. If it's a server they reach over SSH, suggest also adding it as an
SSH account (`/gate:add ssh`), so root commands there go through the
gateway's own key.
Proposal: `{"what": "sudo", "user": "joshua", "host": "powerslabs"}`.
Afterwards, mention that `/gate:enable sudo HOST` lets root commands there
run without asking, for this session or `always`.

### Account
First, which service (skip this if the command already said it):
- **GitHub** (`github`)
- **Hugging Face** (`hf`)
- **A server over SSH** (`ssh`)
- **Azure / Databricks** (`azure`)
- **ASI ML Catalog** (`mlcat`)
- **Container registry** (`registry`)
- **Pijul Nest** (`pijul`)

Then ask, per kind:

- **GitHub**
  - **Which account**, which gives the name: `personal`, `work`, ….
  - **Which orgs or users it's for**, which become the owners:
    `asirobots`, or their username. Empty means any, which is only fine
    when it's their only GitHub account.
  - **How to sign in.** Recommend **browser sign-in**
    (`credentials.browser: true`): it works with company single sign-on
    (SSO) and needs no copying. The alternatives are a token they paste in
    the dialog (`token: "ask"`) or an SSH key (`ssh_key: "generate"`, a new
    key they then add on github.com; or `"file"` with `ssh_key_file`, an
    existing key file the gateway reads).
  - **The name and email to put on commits:** look these up and confirm.
  - Fields: `host` (default `github.com`), `login`, `name`, `email`.
- **Hugging Face:** the name; owners (their username or orgs); a token
  (`token: "ask"`, from huggingface.co/settings/tokens). Fields: `login`.
- **SSH server:** the real host name or IP and port. Aliases from
  `~/.ssh/config` don't work here, so read the config and use its
  `HostName` and `Port`. Also the user, a jump host if any (`ssh:NAME`), and
  the key: an existing key file (`ssh_key: "file"`, `ssh_key_file`; offer
  the `IdentityFile` from their config) or a new one (`"generate"`, which
  they then add to the server). Fields: `host`, `user`, `port`, `jump`.
  Name it after the server: `powerslabs`. If they also use sudo there, use
  the same name, so it links up.
  - **Several ways in** (e.g. a LAN address at home, a forwarded port when
    away): send `ssh.routes`, tried in order, the last one being the
    fallback. Each route is `{name, host, port, when}`, where `when` is an
    optional network like `192.168.0.0/24`: the route is tried only when this
    computer is on it. In `~/.ssh/config`, look for two `Host` entries for
    the same machine, or `Match exec` / `Match host` blocks, and offer them as
    routes. Every route must reach the same machine (same host key), or the
    gateway refuses.
  - **Host key** (the server's fingerprint): `ssh.host_key_policy` is
    `pinned` (the default and the right choice almost always: a changed key
    is refused), `ask` (a dialog asks you when it changes), or `accept-new`
    (a changed key is trusted and logged; only for test boxes that get
    reinstalled often). Ask only if they mention reinstalling a machine.
  - **Comfort** (only if they ask): `ssh.connect_timeout` (seconds),
    `ssh.keepalive` (seconds), `ssh.compression` (true/false),
    `ssh.reuse_minutes` (how long a reused connection stays open).
    Connection reuse itself is never set here: the user types
    `/gate:enable reuse ssh:NAME` for a session.
  - **Changing the key** (`/gate:update ssh:NAME`): a new key with
    `credentials: {ssh_key: "generate", keep_old_key: true}` keeps the old
    one working until the new one is on the server. Later,
    `credentials: {remove_old_keys: true}` drops the old one.

  ```json
  {"what": "account", "kind": "ssh", "name": "powerslabs",
   "description": "Powers Labs server",
   "fields": {"user": "joshua"},
   "ssh": {"routes": [
       {"name": "home", "host": "192.168.0.80", "port": "22", "when": "192.168.0.0/24"},
       {"name": "away", "host": "ssh.powerslabs.org", "port": "49222"}]},
   "credentials": {"ssh_key": "file", "ssh_key_file": "~/.ssh/id_ed25519"}}
  ```
- **Azure:** the tenant (directory id or domain) and browser sign-in.
  Fields: `tenant`, optional `client_id`, `login`. Databricks workspace hosts
  are allowed later with `/gate:update azure:NAME`.
- **ML Catalog:** browser sign-in; `host` keeps its default.
- **Container registry:** the host (`ghcr.io`, `docker.io`, an ACR); either
  sign in **through** another account (`via: "github:personal"` for ghcr.io,
  `via: "azure:work"` for ACR) or with its own token (`token: "ask"`), not
  both. For ghcr.io, a fine-grained GitHub token can't push packages; a
  classic one with `write:packages` can.
- **Pijul Nest:** `host` `nest.pijul.com`, login, and the SSH key (`file` or
  `generate`).

Account proposal, for example:
```json
{"what": "account", "kind": "github", "name": "work",
 "description": "work GitHub (asirobots, SSO)",
 "fields": {"host": "github.com", "login": "powers0769", "name": "Joshua Powers",
            "email": "joshua.powers@asirobots.com"},
 "owners": ["asirobots"],
 "credentials": {"browser": true}}
```

### Updates (`/gate:update NAME`)
Ask what to change, then send only that. Examples:
- `{"description": "…"}`
- `{"hosts": [...]}` for a secret (the full new list)
- `{"new_value": true}` to type a new secret value
- for an account: `{"fields": {"email": "…"}}`, `{"owners": [...]}`, or
  `{"credentials": {"token": "ask"}}` / `{"credentials": {"browser": true}}`
  to sign in again
- for sudo: `{}`, which asks for the new password

## After gate_setup

- **`ok`:** tell them in one or two lines what was added. Pass on any
  public key verbatim and say where to paste it. For example, for GitHub:
  Settings → SSH and GPG keys → New SSH key.
- **`refused`:** a detail is wrong (the reason says which). Fix it, asking
  if needed, and call again with the **same grant**.
- **`declined`:** they pressed Cancel. Ask what to change.
- **`needs_terminal`:** no screen to show the dialog, e.g. over ssh. Give
  them the exact command from the reason to run in a terminal.
- If the grant expired (15 minutes), ask them to type the command again.
