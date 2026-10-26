# gateway.toml reference

`~/.config/gateway/gateway.toml` says which machines ("hosts") and accounts
go through the gateway, and what Claude may do with them in each Claude Code
permission mode. Anything the file doesn't name is yours: Claude uses your
own ssh, git, gh and sudo for it, and the gateway makes no decision. The
file never holds a secret: passwords, keys and tokens are typed only into
the gateway's dialog and kept in the encrypted vault.

You can edit the file yourself or ask Claude to; `/gate-hosts` and the `gate
host`, `gate policy` and `gate network` commands make the common edits
without opening it. This page lists every key the gateway reads (from
`plugins/gateway/src/gateway/form.py`). The [README](../README.md) has the
short version.

## Example

```toml
# The machines and accounts Claude may use. Edit freely, or ask Claude.
# Secrets never go here; the gateway asks for them in its dialog in Claude Code.

[hosts.localhost]                  # optional: only to have the gateway handle sudo here
sudo = { default = "ask", auto = true, plan = false }

[hosts.homelab]
address = "alex@192.168.1.20"
also    = ["alex@homelab.example.org:2222"]   # tried when the first doesn't answer
sudo    = "ask"

[hosts.homelab.policy]
write = { default = "ask", bypass = "deny" }

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

[network]
commands = { default = "ask", auto = "cc" }
extra    = ["dig"]

[vault]
lock_after = "8h"
```

A new install's file holds only the three comment lines: nothing goes
through the gateway until you add something.

## How the file is read

- **Rights** (`ssh`, `sudo`, an account's `use`), **policy keys** and
  `[network] commands` take a word or a per-mode table (next section).
- **Switches** (`scripts`, `default`, `packages`) take `true` or `false`
  (also `yes`/`no`/`on`/`off`).
- **Names** of hosts, accounts and workspaces: lowercase letters, digits and
  `-`, starting with a letter, at most 32 characters. Hosts and accounts
  share one set of names; if a name is used for both, the later entry is
  off. Reserved: `local`, `this`, `all`, `gateway`, `gate`, `settings`, and
  `localhost` except as the host for this computer.
- **Text** may not hold control characters, line breaks or invisible
  formatting characters; such an entry is off. `note` keys take one line of
  at most 200 characters.
- **A mistake turns off only that entry**, and an entry that is off still
  goes through the gateway: it is refused, never handed to your own tools.
  `gate status` shows the line and the reason. Unknown keys are warnings and
  are ignored, except inside a host's or account's policy table, a workspace
  or `[hosts.NAME.shell]`, where an unknown key turns the entry off (a
  misspelled restriction must never quietly not apply).
- **A file that doesn't parse** (a TOML syntax error, not UTF-8) or a
  missing file: the last version that parsed stays in use until you fix it.
  Without one, every host and account you approved is refused, never handed
  to your own tools.

## Per-mode values

A right, a policy key (`read`, `exec`, `write`, `network`, `elevation`,
`credential`) or `[network] commands` is one word or an inline table of
words by Claude Code permission mode:

```toml
sudo  = "ask"
sudo  = { default = "ask", auto = true, plan = false }
write = { default = "ask", bypass = "deny" }
```

| Word | Spellings | In that mode |
|---|---|---|
| allow | `true`, `"allow"`, `yes`, `on` | the gateway approves, so Claude Code doesn't ask (only for the commands it can judge: see the README's "Permissions") |
| cc | `"cc"` | Claude Code decides, as for any command |
| ask | `"ask"` | Claude Code asks you each time; your OK holds only for the exact command it asked about, once, within 15 minutes; a job, gateway terminal, script or sourced file can't be asked and is refused |
| deny | `false`, `"deny"`, `no`, `off` | refused |

- **Modes**: `default` (also `manual`), `plan`, `acceptEdits`, `auto`,
  `bypass` (also `bypassPermissions`), `dontAsk`. A table must name
  `default`; a mode it leaves out takes `default`'s word.
- **A plain word on a right**: `true` approves in `auto` and `bypass` only
  and is `"cc"` in the other modes; `"ask"`, `"cc"` and `false` mean the same
  in every mode. **On a policy key** a plain `"allow"` restricts nothing.
  **For `[network] commands`** a plain `"allow"` approves in every mode but
  plan.
- **Inside a table**, `true`/`"allow"` is allow in that mode. Plan mode
  never approves (allow becomes `"cc"` there).
- **dontAsk**: Claude Code refuses what it decides itself unless your
  permission rules allow it, so a plain `true` (`"cc"` there) is refused;
  a table's `dontAsk = "allow"` is approved by the gateway, and `"ask"`
  still asks you (Claude Code shows a hook's question in that mode too;
  tried with Claude Code 2.1.310).
- **Commands with no mode** (a job, a gateway terminal, a script, the
  gateway's own helper) get the strictest word over every mode but plan,
  with allow counted as `"cc"`: a plain `true` is `"cc"` there (the
  credential is used), `{ default = "ask", auto = true }` is `"ask"`, so
  refused.
- **Order**, in every mode: `false` < `"ask"` < `"cc"` < `true` < not in the
  file. A change that raises any mode waits for your OK; one that only
  lowers applies at once.
- **Edit without opening the file**: `gate host set NAME ssh|sudo
  default=ask auto=true`, `gate account set NAME use default=ask auto=true`,
  `gate policy set all|HOST|ACCOUNT ACTION default=ask bypass=deny`, `gate
  network commands default=ask auto=cc` (from the chat, or on the edit line
  of `/gate-hosts` or `/gate-accounts`).
- A bad mode name or word, a table without `default`, or a table on a key
  that takes one word turns the entry off. In `[policy]` it counts as
  `"deny"`; in `[network]` the approved value stays.

Keys that take one word only: `scripts`, `provision`, `env_import`, the
forwarding grants, `[shell]`, `[vault]`, `runtime`, workspace paths and
`sign_in`.

## What needs your OK

The gateway compares the file with what you last approved, mode by mode.

- **Taking away** applies at once, with no dialog: lowering a right or
  restriction in any mode, `use = false`, a stricter policy, adding a name
  to the network commands. Raising it again later needs your OK.
- **Adding or widening** waits until you approve it in the gateway's
  dialog: a new entry, a new address or site, a higher value in any mode, a
  name taken out of the network commands. Until then the entry keeps its
  last approved values; a new entry has none.
- **Taking something out of the gateway** also waits, because it would hand
  it to your own tools: deleting or renaming a `[hosts.X]` or
  `[accounts.X]` table, dropping an address, `also` entry or `via` hop,
  adding or changing `when`, dropping an account's owner, host or site, or
  deleting `[hosts.localhost]`'s `sudo` key. Until you approve, the approved
  entry keeps going through the gateway (a removed account keeps using its
  approved sites).
- To approve, Claude runs `gate check NAME` while you are there (`gate check
  settings` for `[shell]`, `[policy]`, `[network]` and `[vault]`), or you use
  `/gate-hosts`. The dialog says what changes in each mode. `gate status`
  lists what waits under "Waiting for your OK". Claude can write a change,
  but only you can approve it.

The tables below say for each key whether a change needs the dialog.

## `[hosts.NAME]`: another machine

| Key | Type | Default | What it does | Dialog |
|---|---|---|---|---|
| `address` | `"[user@]host[:port]"` | required | Where to reach the host: a DNS name or IP address (IPv6 as `"[::1]:22"`). The user defaults to your local user name, the port to 22. Use the real name, not an `~/.ssh/config` alias (`gate import-ssh` can look it up). A git server (`github.com`, `hf.co`, `gitlab.com`, ...) is refused here: add an account instead, or leave it out (your own ssh and git reach it). | a new address; dropping one |
| `when` | `"10.0.0.0/24"` | none | Try `address` only while this machine is on that network. | adding or changing it |
| `also` | list of addresses, or `{at = "...", when = "..."}` tables | `[]` | More addresses, tried in order after `address`. A user part must match `address`'s user. | a new address; dropping one |
| `via` | host name | none | A jump host from this file. At most 3 jumps, no loops, and a jump host can't have `ssh = false`. | adding, changing or dropping it |
| `ssh` | right | `true` | `ssh HOST CMD`, `scp`, `sftp`, `rsync` and git over ssh to this host, and using it as a jump host. Terminals and jobs on the host need `true` (or `"cc"`). | raising it |
| `sudo` | right | `true` | `sudo` on the host, over ssh. | raising it |
| `scripts` | switch | `false` | Also give this host's credentials to programs that Claude's commands start (make, npm, a deploy script). Without it, only commands Claude runs itself get them. | `false` → `true` |
| `runtime` | `"/path"` or `"~/path"` | `~/.local/share/gateway-runtime` | Where the gateway puts its own bash and tmux on that host for terminals and jobs. Set it if your home is small, mounted `noexec`, or its path too long. Plain characters only. | any change |
| `note` | text | | Shown in `gate status`. | no |
| `policy` | table | | See [Policy](#policy). | see there |
| `workspaces` | tables | | See [Workspaces](#workspaces). | see there |
| `shell` | table | | See [`[hosts.NAME.shell]`](#hostsnameshell-a-remote-hosts-imports). | see there |

The host goes through the gateway under its name, `gw-NAME`, its addresses
and `also` entries. Claude reaching it by another name (an `~/.ssh/config`
alias, an IP, a ProxyJump) is refused with the name to use.

`"ask"` means Claude Code asks you each time Claude runs that ssh or sudo
command itself. Claude Code can only ask about a command Claude runs, so
with `ssh = "ask"`, `scp`, `sftp` and `rsync` to that host are refused, and
so are terminals and jobs there; a git push or fetch is asked about before
it runs. With either right at `"ask"`, ssh or sudo started by a script, a
sourced file, `eval`, `sh -c`, a wrapper, or inside a gateway terminal or job
is refused too ("run `ssh NAME ...` as its own command"): the gateway notes
the exact command Claude Code asked about, and the stand-in honours your OK
only for that one, once, before Claude's next command (a note left by a
prompt you declined is dropped then). A command whose words it can't spell
out (a variable or a glob in them) is refused before it runs. `gate check`,
`gate rotate` and `gate copy-to` log in to the host, so on an `"ask"` host
they are asked about the same way. Set the right to `true` (or
`"cc"`) if Claude should use those.

## `[hosts.localhost]`: this computer

Optional. Without it, or without its `sudo` key, sudo on this computer is
your own: the gateway makes no decision, and Claude's sudo works only where
it needs no password (Claude has no terminal to type one). Add `sudo` to
have the gateway ask you for the password in its dialog (`gate host set
localhost sudo ask`).

| Key | Type | Default | What it does | Dialog |
|---|---|---|---|---|
| `sudo` | right | none: your own sudo | `sudo` on this computer, through the gateway. | raising it above `"ask"`; deleting it |
| `scripts` | switch | `false` | Also give the sudo password to programs Claude's commands start. | `false` → `true` |
| `note` | text | | Shown in `gate status`. | no |
| `policy` | table | | Only `read`, `exec`, `network`, `elevation`, `credential`, `env_import`. | see [Policy](#policy) |
| `workspaces` | tables | | Named folders on this computer (no `local` key). | see [Workspaces](#workspaces) |

`address`, `when`, `also`, `via`, `runtime` and `shell` are errors here
(this machine's settings for Claude's shell go in `[shell]`). `ssh` is
ignored with a warning.

With `sudo` set:

- `"ask"`: Claude Code asks you every time Claude runs `sudo`, in that mode,
  also when sudo needs no password here. sudo typed into a gateway terminal,
  sudo in a gateway or checkpoint job, and sudo started by `make`, a script,
  `sh -c` or a wrapper are refused, because nobody can be asked there.
- `true`: the gateway approves a plain `sudo CMD` in auto and bypass mode
  (except a short list of destructive commands); Claude Code decides
  elsewhere. A stored sudo password still reaches only commands Claude runs
  itself, unless `scripts = true`.
- The password is stored or asked for each time in the gateway's dialog
  ("Remember it" starts unticked: the password is used once; tick it to
  keep it). sudo that already
  needs no password here is used as it is. The gateway never changes the
  machine's sudo rules.
- Writing `sudo` where none was approved applies at once up to `"ask"`;
  anything higher waits for your OK and runs as `"ask"` meanwhile.
- While it is set, `su`, `doas`, `pkexec`, `runuser`, `sudoedit` and
  `osascript ... with administrator privileges` are refused ("use sudo").
- While a passphrase-protected vault is locked, the gateway can't read what
  you approved or a stored password, so `sudo` here is refused, like the
  hosts and accounts in gateway.toml, until you run `/gate-unlock`. Anything
  gateway.toml doesn't configure is your own and keeps working.
- The system's sudo gets a short allowlist of your environment (`PATH`,
  `HOME`, `USER`, `LOGNAME`, `LANG`, `LC_ALL`, `LC_CTYPE`, `LC_MESSAGES`,
  `TMPDIR`, `TZ`, `TERM`, `SUDO_EDITOR`, `VISUAL`, `EDITOR`, and what the
  gateway's password helper needs), never all of it, so `sudo -E` and
  `--preserve-env` keep only that.

An `elevation` restriction (in `[hosts.localhost.policy]` or `[policy]`)
without a `sudo` key also puts this computer's sudo under the gateway for
that restriction only: its `"deny"` refuses, its `"ask"` asks, and otherwise
your own sudo runs.

## Policy

Finer rules than the rights, each a per-mode value (`"allow"`, `"cc"`,
`"ask"` or `"deny"`, or a table). They can only narrow what the rights give,
and the strictest rule that applies wins. Every refusal names the rule and
its line in the file.

| Action | Covers |
|---|---|
| `read` | reading files on the host: `host_inspect`, downloads with scp, rsync or sftp, git fetches over ssh |
| `exec` | running commands: `ssh HOST CMD`, terminals, jobs |
| `write` | uploads to the host; with an account: pushes and http writes |
| `network` | ssh tunnels (`-L`, `-D`) through the host; the `http` and `download` tools; on this computer and in `[policy]` also network commands (with `[network] commands`, the stricter wins) |
| `elevation` | sudo (it also needs `exec`) |
| `credential` | the gateway handing a stored credential to a command |
| `env_import` | importing folders and variables into Claude's shell or a host's runtime (one word) |
| `provision` | setting up the gateway's runtime on the host (one word) |
| `forward_agent` | `ssh -A` (the forwarded agent holds only the gateway's key for that host) |
| `forward_x11` | `ssh -X`, `-Y` |
| `forward_remote` | `ssh -R` |
| `forward_stdio` | `ssh -W` |

Where each table goes and what it takes:

| Table | Keys | Starting point |
|---|---|---|
| `[policy]` | every action; the four `forward_*` only as `"deny"` or `"ask"` | the hosts and accounts in this file, plus this computer's elevation and network commands; it doesn't reach anything the file doesn't name |
| `[hosts.NAME.policy]` | every action | each action starts at the host's `ssh` right (`elevation` at the stricter of `sudo` and `exec`) |
| `[hosts.localhost.policy]` | `read`, `exec`, `network`, `elevation`, `credential`, `env_import` | on this computer they start at `"cc"` (Claude Code's own modes govern local commands), `elevation` at `sudo` |
| workspace keys | `read`, `exec`, `write` | see [Workspaces](#workspaces) |
| `[accounts.NAME.policy]` | `credential`, `write`, `network` | start at the account's `use` |

- A missing restriction means no restriction, and so does a plain
  `"allow"`. The four `forward_*` grants are off unless that host's own
  policy sets them to `"allow"`.
- **An explicit allow**: a table's `"allow"` for a mode (`network = {
  default = "ask", auto = "allow" }`) is your explicit approval. For this
  computer's `network` (`[hosts.localhost.policy]` or `[policy]`) the
  gateway then approves the `http` and `download` tools in that mode; it
  needs your OK like any widening. Elsewhere it restricts nothing.
- Each action is decided on its own: allowing `read` never allows `exec`,
  sudo, setup or credentials.
- `"ask"` works only for a command Claude runs itself (Claude Code asks).
  A script, a job or a terminal treats `"ask"` as refused. The `http` and
  `download` tools ask up front for a `network` `"ask"`; an account's
  `use`, `credential` or `write` at `"ask"` refuses them.
- A bad value in `[policy]` counts as `"deny"` until fixed; a bad key or
  value in a host's or account's table turns that entry off.
- **Dialog:** raising a key in any mode, removing a restriction, or turning
  a grant on. Lowering applies at once.
- Policy is the gateway's own. It never changes Claude Code's permission
  rules or modes, and a gateway `"deny"` holds in every mode it names.

## Workspaces

`[hosts.NAME.workspaces.W]` names a folder on one host. Terminals and jobs
opened in a workspace are bound to that host and folder. The same path on two
hosts is two workspaces. A host takes at most 32.

| Key | Type | Default | What it does | Dialog |
|---|---|---|---|---|
| `root` | `"/path"` or `"~/path"` | required | The folder on the host, written from `/` or from the host's home. `..` isn't allowed. | a changed root |
| `local` | `"/path"` or `"~/path"` | none | The same project on this computer: a path under it maps to `root`. Not on `localhost`. | a changed mapping |
| `read`, `exec`, `write` | policy value | no restriction | Narrow what Claude may do in this folder. | raising one |
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
| `login` | text | filled in when a GitHub or Hugging Face token is stored | The account's user name. Its repositories use this account. A GitHub token of another login is refused. | dropping it |
| `owners` | list | `[]` | Owners (users or organizations) whose repositories use this account. An account that lists owners serves only those and its `login`. | dropping one; listing the first one |
| `default` | switch | `false` | Use this account for its kind and host when no owner matches. If two accounts of one kind and host say `true`, neither is the default. | no |
| `name`, `email` | text | | The commit identity in repositories this account serves. github, huggingface and pijul only. Without them, git commits there with your own `user.name` and `user.email` (as your git reads them in that repository); with neither anywhere, git refuses to commit rather than guess. | no |
| `env` | variable name | | github, huggingface, api-key: `gate with NAME -- CMD` gives that one program the credential in this variable. azure: any name turns on the `az` stand-in's tokens, which go only to programs (such as an Azure SDK) that Claude's commands start under `scripts = true`. Not `PATH`, `HOME`, `GIT_*`, `SSH_*`, `LD_*` and similar names. | adding or changing it |
| `scripts` | switch | `false` | Also give the credential to programs Claude's commands start. | `false` → `true` |
| `use` | right | `true` | Whether the credential is used: `false` keeps it but never sends it; `"ask"` has Claude Code ask before a command Claude runs itself (git, the account's tool: `gh pr list`, and `gate with NAME -- CMD`), and the account is used for that command only; a per-mode table works too. `gate with` follows it, and the account's `credential` policy, like the tools do. The gateway never approves an account's command itself, so `true` and `"cc"` both leave it to Claude Code. | raising it |
| `note` | text | | Shown in `gate status`. | no |
| `policy` | table | | `credential`, `write`, `network`; see [Policy](#policy). | raising a key |

An account's credential goes only to the sites listed under "Sends to"
below. Adding a site needs the dialog, and so does dropping one (until then
the approved site keeps going through the gateway).

**Which repositories an account serves** (git, gh, hf, pijul): those under
its `login` and `owners`; with `default = true`, every other owner on its
host; and while it is the only account of its kind for a host and lists no
`owners`, every repository there. So with one work account that lists
`owners = ["example-org"]`, your personal repositories (`octocat/...`) use
your own git and gh, never the work account's key. A repository no account
serves uses your own git and tools. Listing the first owner of the only
account of its kind for a host, while it listed none, needs the dialog
(until then it keeps serving every owner). A command whose owner can't be told (`gh api /user`, `hf whoami`)
uses the account when one exists.

### Kinds

| Kind | Its own keys | Sends to |
|---|---|---|
| `github` | `host` (default `github.com`; a GitHub Enterprise server as `host[:port]`), `packages` (switch; default `true` on github.com, else `false`) | `host`; `api.<host>` for github.com and `*.ghe.com`; `ghcr.io` when `packages` is on |
| `huggingface` | none | `huggingface.co`, `hf.co` |
| `azure` | `tenant` (required: a tenant ID or a domain); `client_id` (the application ID); `sign_in` (`"service-principal"`, the default, or `"browser"`); `scope` (the browser sign-in's request: up to 8 scopes; `offline_access` is added); `databricks` (workspace hosts, `*.azuredatabricks.net`); `storage` (storage account names); `registries` (`*.azurecr.io` hosts); `sites` (other hosts that need an explicit scope) | `management.azure.com`, `graph.microsoft.com`, the listed workspaces, `<storage>.{blob,dfs,file,queue,table}.core.windows.net`, the listed registries and sites |
| `ml-catalog` | `host` (required: the catalog's address), `tenant` (default `"organizations"`) | `host` |
| `pijul` | `host` (default `nest.pijul.com`), `remote_pijul` (absolute path of pijul on that server) | `host`, over ssh |
| `registry` | `host` (required, like `"docker.io"`) | `host` |
| `api-key` | `sites` (required: `"api.example.com"` exactly, or `".example.com"` for any subdomain; patterns shared by many owners, like `".github.io"`, are refused); `auth` (where the key goes: `"bearer"` (default), `"basic"` (with `login` as the user), `"header:NAME"`, `"header:NAME:PREFIX"`, `"query:PARAM"`) | `sites` |

Notes:

- **Changes that need the dialog** besides the table above: a new, changed
  or dropped `host`, `sites`, `databricks`, `storage` or `registries` entry,
  `packages` turned on, and a changed `auth`, `tenant`, `client_id`,
  `sign_in` or `scope`. The last four also need a new sign-in or credential:
  the old one isn't used meanwhile.
- **azure, service principal** (the default): `client_id` and the client
  secret or certificate, entered in the dialog.
- **azure, `sign_in = "browser"`**: signs in as you through your system
  browser. It needs `client_id`: a public client application registered for
  the redirect `http://127.0.0.1`.
- **ml-catalog** needs `host`; an account without it is off. It always signs
  in through your system browser; the client id comes from the catalog
  (`/api/config`) and is pinned at sign-in, so a change there needs a new
  sign-in.
- **A browser sign-in** asks first in the gateway's dialog (Open or Cancel);
  the browser opens only after Open, and the tokens go straight into the
  vault. It needs a display, and isn't exported.
- **Choosing an account:** `GATE_ACCOUNT=NAME` picks one for a command.
  Otherwise the account whose `login` or `owners` include the repository's
  owner, else the `default`, else the only account of that kind and host
  when it lists no `owners` (or the owner can't be told).

## `[network]`: network commands

Network commands are one class that the gateway judges in Claude's commands
(Bash, Monitor, the Terminal panel, jobs, gateway terminals), behind sudo
and wrappers, in subshells, `bash -c` strings and `ssh HOST CMD`.

| Key | Type | Default | What it does | Dialog |
|---|---|---|---|---|
| `commands` | per-mode value | `"ask"` in every mode | What a network command gets. `"allow"` lets the gateway approve it in that mode (a plain `"allow"`: every mode but plan). | raising it in any mode |
| `extra` | list of program names | `[]` | Added to the class (for example `dig`, `ping`, `host`, `whois`, `traceroute`, `ssh`). At most 32. | removing a name (adding one applies at once) |
| `drop` | list of names or reserved names | `[]` | Taken out of the class. At most 32. | adding a name |

The class: `curl`, `wget`, `wget2`, `aria2c`, `xh`, `http`, `https`,
`lynx`, `w3m`, `links`, `links2`, `nmap`, `nping`, `masscan`, `zmap`,
`rustscan`, `hping3`, `ssh-keyscan`, `nc`, `ncat`, `netcat`, `socat`,
`telnet`, `ftp`, `tftp`, `lftp`, `smbclient`, `certutil`, `tcpdump`,
`tshark`, `nikto`, `sqlmap`, `hydra`, `gobuster`, `ffuf`, `nuclei`,
`arp-scan`, `iperf3` (each in any letter case: `CURL` too), and these shapes,
by their reserved names: `openssl-tls` (`openssl s_client`, `s_server`,
`s_time`), `http-server` (`python -m http.server`, `php -S`, `ruby -run -e
httpd`, `busybox httpd`), `dev-tcp` (`/dev/tcp/...`, `/dev/udp/...`),
`rsync-daemon` (`rsync://...`, `HOST::MODULE`), `busybox` (`busybox wget`
and other members).

- The value used is the stricter of `commands` and this computer's
  `network` policy (`[hosts.localhost.policy]`, `[policy]`), in the
  command's mode; for `ssh HOST CMD` to a host in this file, that host's
  `network` policy too. A policy's `"allow"` never raises it.
- A network command not allowed in that mode keeps the gateway's own
  approval off the whole command (by default `sudo nmap` asks even where
  `sudo` is `true`). Under `gate with` it is at least `"ask"`.
- A job or gateway terminal is judged in the mode its tool call carries
  (the mode you started it from); an `"ask"` there is refused.
- "ask" also prompts in bypass mode. To stop that: `gate network commands
  default=ask bypass=cc auto=cc`.
- A mistake in `[network]` keeps the approved table (`"ask"` and the class
  as above if none); `gate status` names it.
- The `http` and `download` tools aren't network commands: the `network`
  policy alone governs them.

It is a guardrail: networking inside an interpreter (`python -c`, `node
-e`), a script on disk or a scheduled job isn't seen
([network.md](dev/modules/network.md#known-misses-guardrail-not-sandbox)).

## `[shell]`: Claude's shell on this computer

| Key | Type | Default | What it does | Dialog |
|---|---|---|---|---|
| `managed` | `"on"`, `"off"` (`true` = on, `false` = off) | `"on"` | `"on"`: Claude's commands run in the gateway's bash 5 with your environment, Claude Code's own credentials removed and the stand-ins first. `"off"`: Claude Code's own shell, with the stand-ins still first. Applies from the next session. | `"on"` → `"off"` |
| `import_path` | list of folders (`/...` or `~/...`, no `:`) | `[]` | Added to the managed PATH, after the stand-ins and your own PATH. Not inside `~/.config/gateway`. At most 32. `import_path = []` also stops the session's offer to import tool folders it found. | each new folder |
| `import_env` | list of variable names | `[]` | Listed in `gate status`. Claude's shell keeps your environment anyway, so this matters only where Claude Code's environment lacks a variable your login shell sets. At most 32. | each new name |

`import_env` refuses: names the managed shell always passes (`HOME`, `USER`,
`LANG`, `LC_*`, `TERM`, `TMPDIR`, `TZ`, ...); anything that looks like a
credential (`*TOKEN*`, `*SECRET*`, `*PASSW*`, `*API_KEY*`, `*AUTH*`, ...; an
account with `env` is for those); and names that change how the shell or
the stand-ins work (`PATH`, `LD_*`, `DYLD_*`, `BASH_ENV`, `GIT_SSH*`,
`SSH_*`, `SUDO_*`, `CLAUDE*`, ...). A bad `managed` value (`"warn"`
included) counts as `"on"` until fixed; a bad import entry is left out.

Imports apply only while this computer's `env_import` policy allows them.

## `[vault]`

| Key | Type | Default | What it does | Dialog |
|---|---|---|---|---|
| `lock_after` | duration: `"90s"`, `"30m"`, `"8h"`, `"1d"` | `"8h"` | How long a passphrase-protected vault stays unlocked without use. From 1 minute to 1 day. A bad value means 8h until fixed. No effect without a passphrase (`/gate-unlock` sets one). | no |

The passphrase itself is set, changed and removed in the gateway's dialog,
never in this file: `/gate-unlock` (unlocked: Change passphrase or Remove
passphrase), or Claude runs `gate passphrase` (set or change) or `gate
passphrase --remove`. A lost passphrase can't be recovered: `gate
passphrase --start-over` (after your OK) moves the vault, its wrapped key
and cache into `private/backups/startover-...` (nothing is deleted;
gateway.toml stays), and then nothing is stored or approved: import your
last export, or set each entry up again (`gate check NAME`).

Older copies of the vault stay in `private/backups/`: `gate rotate`'s
newest 5, an import's backup, a start-over's folder. `gate forget
--backups` lists them in the gateway's dialog and deletes them after your
OK (they may still hold secrets you forgot or replaced since).

## Export and import

`gate export` (in a Claude Code session) lets you pick what goes into a
passphrase-protected file: hosts, accounts, their stored secrets, the
settings (`[shell]`, `[policy]`, `[network]`, `[vault]`), and this machine's
settings (`[hosts.localhost]`'s `sudo`, `scripts`, policy and workspaces,
never an address; unticked by default). A browser sign-in isn't exported.

`gate import FILE` runs in a Claude Code session too: one dialog (in parts
when it is long) lists everything the file adds or changes, and approving it
approves those changes. An entry that exists here and differs gets its own
choice (keep, replace, add under a new name); this machine's settings are
kept or replaced. A replace that takes something out of the gateway is shown
as a widening.

`gate copy-to HOST` sends what you tick to another of your machines in
gateway.toml over ssh, encrypted to that machine's own gateway key (`gate
pubkey` there, shown in the dialog to compare). You confirm by typing the
host's name. The gateway must be set up there (one finished Claude Code session);
that machine imports it without a dialog and its next session says so.
Claude can run commands there, so what you copy is within its reach.
