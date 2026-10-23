# gateway.toml reference

`~/.config/gateway/gateway.toml` says which machines ("hosts") and accounts
Claude may use, and how. It never holds a secret: passwords, keys and tokens
are typed only into the gateway's dialog and kept in the encrypted vault.

You can edit the file yourself or ask Claude to. This page lists every key
the gateway reads (from `plugins/gateway/src/gateway/form.py`). The
[README](../README.md) has the short version.

## Example

```toml
# The machines and accounts Claude may use. Edit freely, or ask Claude.
# Secrets never go here; the gateway asks for them in its dialog in Claude Code.
#   true = Claude may do it without asking   "ask" = ask me each time   false = no

[hosts.localhost]                  # this computer, whichever one you're on
sudo = "ask"

[hosts.homelab]
address = "alex@192.168.1.20"
also    = ["alex@homelab.example.org:2222"]   # tried when the first doesn't answer
sudo    = "ask"

[hosts.homelab.policy]
write = "deny"                     # no uploads to homelab

[hosts.homelab.workspaces.app]
root  = "/srv/app"                 # a folder on homelab
local = "~/src/app"                # the same project on this computer

[hosts.builder]
address = "ci@builder.example.org"
via     = "homelab"                # reached through homelab
sudo    = false

[accounts.github-work]
kind   = "github"
login  = "octo-work"
owners = ["example-org"]           # repos under example-org use this account

[accounts.openai]
kind  = "api-key"
sites = ["api.openai.com"]
env   = "OPENAI_API_KEY"           # gate with openai -- CMD gets it in this variable

[shell]
import_path = ["/opt/homebrew/bin"]

[vault]
lock_after = "8h"
```

A new install's file holds only the three comment lines and
`[hosts.localhost]` with `sudo = "ask"`.

## How the file is read

- **Rights** (`ssh`, `sudo`) take `true`, `"ask"` or `false`. `yes`, `on`,
  `no` and `off` work too, with or without quotes.
- **Switches** (`scripts`, `use`, `default`, `packages`) take `true` or
  `false` (also `yes`/`no`/`on`/`off`).
- **Policy keys** take `"allow"`, `"ask"` or `"deny"` (`true` and `false`
  mean allow and deny).
- **Names** of hosts, accounts and workspaces: lowercase letters, digits and
  `-`, starting with a letter, at most 32 characters. Hosts and accounts
  share one set of names; if a name is used for both, the later entry is
  off. Reserved: `local`, `this`, `all`, `gateway`, `gate`, `settings`, and
  `localhost` except as the host for this computer.
- **Text** may not hold control characters, line breaks or invisible
  formatting characters; such an entry is off. `note` keys take one line of
  at most 200 characters.
- **A mistake turns off only that entry.** `gate status` shows the line and
  the reason. Unknown keys are warnings and are ignored, except inside a
  host's or account's policy table, a workspace or `[hosts.NAME.shell]`,
  where an unknown key turns the entry off (a misspelled restriction must
  never quietly not apply).
- **A file that doesn't parse** (a TOML syntax error, or not UTF-8): the
  last version that parsed stays in use until you fix it. If the gateway
  has no such version on record, only the defaults apply.

## What needs your OK

The gateway compares the file with what you last approved.

- **Taking away** applies at once, with no dialog: lowering a right
  (`true` → `"ask"` → `false`), removing an address, a site or a whole entry,
  `use = false`, a stricter policy. Raising it again later needs your OK.
- **Adding or widening** waits until you approve it in the gateway's
  dialog. Until then the entry keeps its last approved rights; a new entry
  has none. Claude can write the change, but only you can approve it.
- To approve, Claude runs `gate check NAME` while you are there
  (`gate check settings` for `[settings]`, `[shell]` and `[policy]`), or you
  use `/gate-hosts`. `gate status` lists what waits under "Waiting for your
  OK".

The tables below say for each key whether a change needs the dialog.

## `[hosts.NAME]`: another machine

| Key | Type | Default | What it does | Dialog |
|---|---|---|---|---|
| `address` | `"[user@]host[:port]"` | required | Where to reach the host: a DNS name or IP address (IPv6 as `"[::1]:22"`). The user defaults to your local user name, the port to 22. Use the real name, not an `~/.ssh/config` alias (`gate import-ssh` can look it up). A git server (`github.com`, `hf.co`, `gitlab.com`, ...) is refused here: add an account instead. | a new address |
| `when` | `"10.0.0.0/24"` | none | Try `address` only while this machine is on that network. | removing or changing it |
| `also` | list of addresses, or `{at = "...", when = "..."}` tables | `[]` | More addresses, tried in order after `address`. A user part must match `address`'s user. | a new address |
| `via` | host name | none | A jump host from this file. At most 3 jumps, no loops, and a jump host can't have `ssh = false`. | adding or changing it |
| `ssh` | right | `true` | `ssh HOST CMD`, `scp`, `sftp`, `rsync` and git over ssh to this host, and using it as a jump host. Terminals and jobs on the host need `true`. | raising it |
| `sudo` | right | `true` | `sudo` on the host, over ssh. | raising it |
| `scripts` | switch | `false` | Also give this host's credentials to programs that Claude's commands start (make, npm, a deploy script). Without it, only commands Claude runs itself get them. | `false` → `true` |
| `runtime` | `"/path"` or `"~/path"` | `~/.local/share/gateway-runtime` | Where the gateway puts its own bash and tmux on that host for terminals and jobs. Set it if your home is small, mounted `noexec`, or its path too long. Plain characters only. | any change |
| `note` | text | | Shown in `gate status`. | no |
| `policy` | table | | See [Policy](#policy). | see there |
| `workspaces` | tables | | See [Workspaces](#workspaces). | see there |
| `shell` | table | | See [`[hosts.NAME.shell]`](#hostsnameshell-a-remote-hosts-imports). | see there |

`"ask"` means Claude Code asks you each time Claude runs that ssh or sudo
command itself, in every permission mode. Claude Code can only ask about a
command Claude runs, so with `ssh = "ask"`, `scp`, `sftp`, `rsync` and git to
that host are refused, and so are terminals and jobs there. With either
right at `"ask"`, ssh or sudo started by a script, `sh -c`, a wrapper, or
inside a gateway terminal or job is refused too. Set the right to `true` if
Claude should use those.

## `[hosts.localhost]`: this computer

`localhost` is always the machine you are on. It takes only these keys:

| Key | Type | Default | What it does | Dialog |
|---|---|---|---|---|
| `sudo` | right | `"ask"` on a new install; `true` on an install set up by gateway 0.9.1 or older | `sudo` on this computer. | raising it |
| `scripts` | switch | `false` | Also give the sudo password to programs Claude's commands start. | `false` → `true` |
| `note` | text | | Shown in `gate status`. | no |
| `policy` | table | | Only `read`, `exec`, `network`, `elevation`, `credential`, `env_import`. | see [Policy](#policy) |
| `workspaces` | tables | | Named folders on this computer (no `local` key). | see [Workspaces](#workspaces) |

`address`, `when`, `also`, `via`, `runtime` and `shell` are errors here
(this machine's imports go in `[shell]`). `ssh` is ignored with a warning.

Without a `[hosts.localhost]` table, or with one that has no `sudo` key, the
default above applies.

What `sudo = "ask"` means in practice:

- Claude Code asks you every time Claude runs `sudo`, in every permission
  mode, also when sudo needs no password on this machine. The gateway never
  approves it by itself.
- sudo typed into a gateway terminal (by Claude or by you), sudo in a
  gateway or checkpoint job, and sudo started by `make`, a script, `sh -c` or
  a wrapper are refused, because nobody can be asked there.
- Set `sudo = true` (and approve it) to allow those. A stored sudo password
  still reaches only commands Claude runs itself, unless `scripts = true`.
  With `true`, `sudo` is judged like any other command by Claude Code's
  permission mode, and in auto mode a plain `sudo CMD` skips the reviewer
  (see the README's "Permissions").
- While a passphrase-protected vault is locked, the gateway can't read what
  you approved, so sudo here asks until you run `/gate-unlock`.

An install keeps the defaults it was set up with: an update never turns an
older install's `true` into `"ask"`. Two exceptions: on a machine with no
vault yet (nothing was ever stored or approved), an old `sudo = true` waits
for one `gate check localhost`; and a machine whose vault is moved aside and
started fresh counts as a new install.

## Policy

Finer rules than the rights, each `"allow"`, `"ask"` or `"deny"`. They can
only narrow what the rights give, and the strictest rule that applies wins.
Every refusal names the rule and its line in the file.

| Action | Covers |
|---|---|
| `read` | reading files on the host: `host_inspect`, downloads with scp, rsync or sftp, git fetches over ssh |
| `exec` | running commands: `ssh HOST CMD`, terminals, jobs |
| `write` | uploads to the host; with an account: pushes and http writes |
| `network` | ssh tunnels (`-L`, `-D`) through the host; the `http` and `download` tools |
| `elevation` | sudo (it also needs `exec`) |
| `credential` | the gateway handing a stored credential to a command |
| `env_import` | importing folders and variables into the managed shell |
| `provision` | setting up the gateway's runtime on the host |
| `forward_agent` | `ssh -A` (the forwarded agent holds only the gateway's key for that host) |
| `forward_x11` | `ssh -X`, `-Y` |
| `forward_remote` | `ssh -R` |
| `forward_stdio` | `ssh -W` |

Where each table goes and what it takes:

| Table | Keys | Starting point |
|---|---|---|
| `[policy]` | every action; the four `forward_*` only as `"deny"` or `"ask"` | applies to every host and account |
| `[hosts.NAME.policy]` | every action | on a remote host each action starts at its `ssh` right (`elevation` at the stricter of `sudo` and `exec`) |
| `[hosts.localhost.policy]` | `read`, `exec`, `network`, `elevation`, `credential`, `env_import` | on this computer they start at allow (Claude Code's own permission modes govern local commands), `elevation` at `sudo` |
| workspace keys | `read`, `exec`, `write` | see [Workspaces](#workspaces) |
| `[accounts.NAME.policy]` | `credential`, `write`, `network` | start at the account's `use` |

- A missing restriction means no restriction. The four `forward_*` grants
  are off unless that host's own policy sets them to `"allow"`.
- Each action is decided on its own: allowing `read` never allows `exec`,
  sudo, setup or credentials.
- `"ask"` works only for a command Claude runs itself (Claude Code asks).
  A script, a job or a terminal treats `"ask"` as refused.
- A bad value in `[policy]` counts as `"deny"` until fixed; a bad key or
  value in a host's or account's table turns that entry off.
- **Dialog:** raising a key, removing a restriction, or turning a grant on.
  Lowering applies at once.
- Policy is the gateway's own. It never changes Claude Code's permission
  rules or modes, and a gateway `"deny"` holds in every mode.

## Workspaces

`[hosts.NAME.workspaces.W]` names a folder on one host. Terminals and jobs
opened in a workspace are bound to that host and folder. The same path on two
hosts is two workspaces. A host takes at most 32.

| Key | Type | Default | What it does | Dialog |
|---|---|---|---|---|
| `root` | `"/path"` or `"~/path"` | required | The folder on the host, written from `/` or from the host's home. `..` isn't allowed. | a changed root |
| `local` | `"/path"` or `"~/path"` | none | The same project on this computer: a path under it maps to `root`. Not on `localhost`. | a changed mapping |
| `read`, `exec`, `write` | policy word | no restriction | Narrow what Claude may do in this folder. | raising one |
| `note` | text | | Shown in `/gate-hosts`. | no |

Adding a workspace needs the dialog. Removing (or renaming) one that
restricts anything also does, since its restrictions would stop applying;
one that restricts nothing goes at once.

For copies (`scp`, `rsync`, git over ssh), every remote path is checked
against every workspace it may reach, by the path as written: write remote
paths the way the root is written. A symlink on the host isn't followed.

## `[hosts.NAME.shell]`: a remote host's imports

Imports for the gateway's shell on that host (terminals and jobs there).
Not for `localhost`: use `[shell]`.

| Key | Type | Default | What it does | Dialog |
|---|---|---|---|---|
| `import_path` | list of folders on that host (`/...` or `~/...`, no `:`) | `[]` | Added to the PATH there. At most 32. | each new folder |
| `import_env` | list of variable names | `[]` | Copied from that host's login environment. Same name rules as `[shell] import_env`. At most 32. | each new name |

They apply only while the host's `env_import` policy allows them.

## `[accounts.NAME]`: an account

Keys every kind takes:

| Key | Type | Default | What it does | Dialog |
|---|---|---|---|---|
| `kind` | `"github"`, `"huggingface"`, `"azure"`, `"ml-catalog"`, `"pijul"`, `"registry"`, `"api-key"` | required | What the account is. | a changed kind (a new account) |
| `login` | text | filled in when a GitHub or Hugging Face token is stored | The account's user name. Its repositories use this account. A GitHub token of another login is refused. | no |
| `owners` | list | `[]` | Owners (users or organizations) whose repositories use this account. | no |
| `default` | switch | `false` | Use this account for its kind and host when no owner matches. If two accounts of one kind and host say `true`, neither is the default. | no |
| `name`, `email` | text | | The commit identity in repositories under `login` or `owners`. github, huggingface and pijul only. | no |
| `env` | variable name | | github, huggingface, api-key: `gate with NAME -- CMD` gives that one program the credential in this variable. azure: any name turns on the `az` stand-in, which gives tokens only to programs (such as an Azure SDK) that Claude's commands start under `scripts = true`. Not `PATH`, `HOME`, `GIT_*`, `SSH_*`, `LD_*` and similar names. | adding or changing it |
| `scripts` | switch | `false` | Also give the credential to programs Claude's commands start. | `false` → `true` |
| `use` | switch | `true` | `false` keeps the credential but never sends it. | `false` → `true` |
| `note` | text | | Shown in `gate status`. | no |
| `policy` | table | | `credential`, `write`, `network`; see [Policy](#policy). | raising a key |

An account's credential goes only to the sites listed under "Sends to"
below. Any change that adds a site needs the dialog; removing one applies at
once.

### Kinds

| Kind | Its own keys | Sends to |
|---|---|---|
| `github` | `host` (default `github.com`; a GitHub Enterprise server as `host[:port]`), `packages` (switch; default `true` on github.com, else `false`) | `host`; `api.<host>` for github.com and `*.ghe.com`; `ghcr.io` when `packages` is on |
| `huggingface` | none | `huggingface.co`, `hf.co` |
| `azure` | `tenant` (required: a tenant ID or a domain); `client_id` (the service principal's application ID; needed to store a new credential); `databricks` (workspace hosts, `*.azuredatabricks.net`); `storage` (storage account names); `registries` (`*.azurecr.io` hosts); `sites` (other hosts that need an explicit scope) | `management.azure.com`, `graph.microsoft.com`, the listed workspaces, `<storage>.{blob,dfs,file,queue,table}.core.windows.net`, the listed registries and sites |
| `ml-catalog` | `host` (required: the catalog's address) | `host` |
| `pijul` | `host` (default `nest.pijul.com`), `remote_pijul` (absolute path of pijul on that server) | `host`, over ssh |
| `registry` | `host` (required, like `"docker.io"`) | `host` |
| `api-key` | `sites` (required: `"api.example.com"` exactly, or `".example.com"` for any subdomain; patterns shared by many owners, like `".github.io"`, are refused); `auth` (where the key goes: `"bearer"` (default), `"basic"` (with `login` as the user), `"header:NAME"`, `"header:NAME:PREFIX"`, `"query:PARAM"`) | `sites` |

Notes:

- **Changes that need the dialog** besides the table above: a new or changed
  `host`, `sites`, `databricks`, `storage` or `registries` entry, `packages`
  turned on, and a changed `auth`, `tenant` or `client_id` (the last two also
  need the credential entered again).
- **azure** stores a service principal's client secret or certificate.
  Without `client_id`, only a sign-in stored by an older gateway works.
- **ml-catalog** needs `host`; an account without it is off. A new sign-in
  needs a browser, which the gateway doesn't open, so only a sign-in stored
  by an older gateway works (until its refresh token expires).
- **Choosing an account:** `GATE_ACCOUNT=NAME` picks one for a command.
  Otherwise the account whose `login` or `owners` include the repository's
  owner, else the `default`, else the only account of that kind and host.

## `[shell]`: Claude's shell on this computer

| Key | Type | Default | What it does | Dialog |
|---|---|---|---|---|
| `managed` | `"on"`, `"warn"`, `"off"` (`true` = on, `false` = off) | `"on"` | `"on"`: Claude's commands run in the gateway's own bash, never your login shell. `"warn"`: the same while Claude Code's mods run; without mods, your own shell with a notice each session. `"off"`: Claude Code's own shell. Applies from the next session. | `"on"` → `"warn"` → `"off"` |
| `import_path` | list of folders (`/...` or `~/...`, no `:`) | `[]` | Put on the managed PATH, after the gateway's stand-ins and before the system folders. Not inside `~/.config/gateway`. At most 32. `import_path = []` also stops the session's offer to import tool folders it found. | each new folder |
| `import_env` | list of variable names | `[]` | Passed from Claude Code's environment into Claude's commands. At most 32. | each new name |

`import_env` refuses: names the managed shell always passes (`HOME`, `USER`,
`LANG`, `LC_*`, `TERM`, `TMPDIR`, `TZ`, ...); anything that looks like a
credential (`*TOKEN*`, `*SECRET*`, `*PASSW*`, `*API_KEY*`, `*AUTH*`, ...; an
account with `env` is for those); and names that change how the shell or
the stand-ins work (`PATH`, `LD_*`, `DYLD_*`, `BASH_ENV`, `GIT_SSH*`,
`SSH_*`, `SUDO_*`, `CLAUDE*`, ...). A bad `managed` value keeps the approved
mode; a bad import entry is left out.

Imports apply only while this computer's `env_import` policy allows them.

## `[vault]`

| Key | Type | Default | What it does | Dialog |
|---|---|---|---|---|
| `lock_after` | duration: `"90s"`, `"30m"`, `"8h"`, `"1d"` | `"8h"` | How long a passphrase-protected vault stays unlocked without use. From 1 minute to 1 day. A bad value means 8h until fixed. No effect without a passphrase (`/gate-unlock` sets one). | no |

## `[settings]`

| Key | Type | Default | What it does | Dialog |
|---|---|---|---|---|
| `others` | `"refuse"` or `"mine"` | `"refuse"` | Machines and git servers not in this file: refused (with a hint to add them), or reached with your own ssh and git setup. A bad value means `"refuse"` until fixed. | `"refuse"` → `"mine"` |
