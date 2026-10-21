# Policy, workspaces and the panes (PLAN-v4 phase 7)

`src/gateway/policy.py`, the policy tables in `form.py`, their consent in
`consent.py`, and the boundaries that enforce them (the ssh and sudo
stand-ins, gated's terminals, jobs, remote runtime and host inspection, the
managed shell's imports, the http tool, account selection, the approval
hook). The panes are `hooks/mod/manage.ts` + `register.tsx` and
`src/gateway/manage.py` (the `gate host|workspace|policy|accounts` commands
they run).

## What a policy is

The gateway's rights (`ssh`, `sudo`, `scripts`, `use`, ...) say whether a
host or an account may be used at all. Policy narrows them per **action**,
**host**, **workspace** and **account**, with three words: `"allow"`,
`"ask"`, `"deny"` (`true`/`false` are read as allow/deny). It is layered on
the rights and on the consent ratchet; it never gives more than the rights.

| action | covers | base on a remote host | base on this machine | where it is decided |
|---|---|---|---|---|
| `read` | reading files on the host: `host_inspect`, scp/rsync/sftp downloads, `git-upload-pack` | `ssh` | allow | ssh stand-in (`ssh_args.ssh_actions`), gated (`/agent/remote/inspect`), `managed.inspect` |
| `exec` | running commands: `ssh HOST CMD`, terminals, jobs | `ssh` | allow | ssh stand-in, gated (`Supervisor._bind`), approval hook |
| `write` | uploads to the host (scp/rsync/sftp, `git-receive-pack`); with an account: pushes and non-GET http | `ssh` | (not a local action) | ssh stand-in, `web.http`, account selection |
| `network` | `ssh -L/-D/-N` tunnels; the http and download tools | `ssh` | allow | ssh stand-in, `web` |
| `elevation` | sudo | stricter of `sudo` and exec | localhost `sudo` | sudo stand-in, remote sudo (`ssh._host`), approval hook (also names the target) |
| `credential` | the gateway handing a stored credential to a command | `ssh` | allow | `accounts.select`, `web.credential`, ssh endpoints |
| `env_import` | `[hosts.X.shell]` / `[shell]` imports into the managed shell | `ssh` | allow | `managed.imports_allowed`, `RemoteHost.imports` |
| `provision` | staging the managed runtime on the host | `ssh` | (n/a) | `remote.ensure_runtime` (a new or changed runtime only) |
| `forward_agent`, `forward_x11`, `forward_remote`, `forward_stdio` | `ssh -A`, `-X/-Y`, `-R`, `-W` (and their `-o` forms) | **deny** unless the host's own policy says `"allow"` | (n/a) | ssh stand-in (`parse_ssh(forwards=True)`, `_policy_gate`) |

On this machine `read`, `exec`, `network`, `credential` and `env_import`
start at allow: Claude Code's own permission modes govern Claude's local
commands, and the gateway doesn't add a competing mode. Policy stays a
gateway concept: it never writes Claude Code's permission rules or modes,
and Claude Code's mode never changes a gateway decision (an `allow` in
bypass mode is still refused by a gateway `deny`).

An account's `credential`, `write` and `network` start at its `use`.

## Form syntax

```toml
[policy]                          # everything (only narrows)
provision = "ask"

[hosts.build]
address = "u@build.example.com"
ssh = true

[hosts.build.policy]
read = "allow"
exec = "ask"
elevation = "deny"
forward_agent = "allow"           # grants exist only here, per host

[hosts.build.workspaces.app]
root = "/srv/app"                 # the folder on that host
local = "~/src/app"               # the matching folder here (a path mapping)
exec = "deny"                     # a workspace narrows read, exec, write

[hosts.build.shell]               # remote imports (consented)
import_path = ["/opt/tools/bin"]
import_env = ["LANG"]

[accounts.gh.policy]
write = "deny"
```

Unknown keys and bad words are entry errors (`gate status` names them; the
entry is off until fixed). A bad word in `[policy]` counts as `deny`, and so
does a grant set to `"allow"` there (a global grant would open forwarding
everywhere: grants are per host only).

## How a decision is made

`policy.decide(eff, action, host=, workspace=, account=) -> Decision`:

1. the base right (above), from effective rights (`consent.compute`);
2. lowered by each table that applies: the host's policy, the workspace's
   keys, the account's policy, `[policy]`; elevation also obeys exec's
   restrictions (sudo runs a command); the strictest wins.

Nothing derives one action from another: a read grant never implies exec,
install (provision), elevation or credential use (tests:
`test_policy::test_a_read_grant_never_implies_exec_write_elevation_or_credentials`, which covers provision too).
A transfer program on the host counts as a read or a write only by its exact
bare name and its own known options (an `rsync` named by a path, or with an
option that writes logs, temp or backup files elsewhere, is exec; see
docs/modules/ssh.md, phase 7), so a read grant doesn't run other programs.
The stated limit: a write grant on a host can lead to exec there through
the host's own files (an uploaded `~/.ssh/rc`, a shell profile, a program
in a folder on the host's PATH, which the login shell then runs); keep
writes in a workspace away from the home's dotfiles and PATH folders, or
deny write where exec is denied.

`Decision.rule` is the concrete rule, as the person wrote it, with its line:
`[hosts.build.workspaces.app] exec = "deny" (gateway.toml line 14)`. Every
refusal shows it (`Decision.message()`), it is audited (`gate why`), and
CONTRACT-v1 refusals carry it as `rule` (gated's 403 `policy`, the
`policy.denied` event without the command). When the form already says
more than applies (a raised key waiting for the OK), the message says so and
names `gate check ENTRY`: the person approves it, Claude never can.

**"ask"** is honoured only where Claude Code can ask the person: a command
Claude typed, judged by the approval hook (which answers `ask` with the
rule). The stand-ins pass an "ask" only for a typed command
(`ancestry.typed_by_claude`); every other caller (a script, a job, gated's
terminals and jobs, the MCP server's tools) treats it as refused and says
how to get it asked.

## Consent

Policy keys are consented like rights (`consent.policy_compare`): per key,
an absent restriction ranks as allow (2) and an absent grant as deny (0).
Raising a key, adding a workspace, moving one (a new root or local
folder), removing a restriction or adding a grant is a **widening**: it
waits in `pending` until the person approves it in the gateway's consent
dialog (`gate check ENTRY`; `[policy]` belongs to `settings`). That
includes taking out a workspace that restricts anything (any of read, exec,
write at "ask" or "deny"), whether its table is deleted or renamed: the
approved workspace stays in effect, its root and restrictions binding,
until the OK (`consent._ws_restrictions`; renamed, the new name also waits
as a new workspace). Only a workspace that restricts nothing goes at once.
Lowering is a **narrowing**: it applies at once and is ratcheted
(`consent.ratchet`, `_narrow_phase7`, which keeps such a removed
workspace approved), from every process that loads the form. So an agent-assisted edit (Claude editing gateway.toml, or
running `gate policy set`) can propose but never widen without the user's
OK. gated publishes `rights.changed` (`widened` after the OK, `narrowed`,
`removed`) from its ticker (`Daemon.watch_rights`).

## Workspaces

A workspace is a named root on one host: `[hosts.X.workspaces.W]` with
`root` (on that host; `~/...` is under the remote home), optional `local`
(the folder on this machine it maps to) and its own `read`/`exec`/`write`.
Its id is `w_` + 26 base32 characters of sha256 over the host's id and the
root (`daemon.workspace_id`), so the same root on two hosts is two
workspaces, and the same path on two hosts is two resources
(`test_workspaces::test_identical_paths_on_two_hosts_are_two_workspaces_and_never_mix`).

Every terminal and job is bound to host + workspace (+ the account and the
managed environment it runs with) by `Supervisor._bind`: a named workspace
must be the host's (409 `workspace_host` otherwise), `cwd` defaults to its
root and must lie inside it, a path under its `local` folder maps to the
root, a folder inside a workspace binds to it even when unnamed (so its
restriction applies), and exec is decided there. Snapshots and `/gate-hosts`
list them.

In the ssh stand-in (and the approval hook, which decides the same way),
every remote path of a transfer (each scp/rsync operand, each `git-*-pack`
repository) is decided in the workspace that holds it and in every
workspace it may reach, and the strictest decision applies
(`ssh_args.workspaces_for`, `decide_path`; a workspace only narrows, so
counting one too many is never a widening). The stand-in doesn't know the
host's home folder, so it places a path by how it is written: from / against
roots written from /, from the home (`~/x`, or `x`) against roots written
from ~ (the innermost root that holds it binds). A path may also reach:

- a workspace whose root lies below it (`scp -r box:/srv` reaches
  `/srv/prod`);
- a workspace whose root is written the other way (`notes.txt` and
  `/home/u/notes.txt` are the same file to the host, not to the stand-in);
  write the path the way the root is written: on a remote host, roots
  written from / let absolute paths be placed exactly;
- every workspace, for a path that can't be placed at all (`~bob/x`, a
  relative path leaving the home with `..`) and for sftp, which can open any
  file once connected (scp's own operands are read from its command line).

A refusal from a workspace the path only may reach says why. The mapping is
by the path as written: a symlink on the host that leads into a workspace
isn't followed (the host resolves it, not the gateway).

## Forwarding

Agent, X11, remote (`-R`) and stdio (`-W`) forwarding are refused unless the
host's own `[hosts.X.policy]` says `forward_KIND = "allow"` (approved like
any widening), and never for an account endpoint or a host outside the form.
Stated prerequisites, checked or said in the refusal:

- agent: the forwarded agent is the call's own private agent with only the
  gateway's key for that host (never your own agent); the connection skips
  the shared master so the forward belongs to the call;
- X11: an X server here (`DISPLAY`, which the managed shell passes only as
  an approved `[shell] import_env`; XQuartz on macOS) and `X11Forwarding yes`
  in the host's sshd;
- remote: the forwarded port binds only to the host's loopback (`-R` with a
  bind address that isn't loopback is refused, like `-L`/`-D` here);
- stdio: `-W HOST:PORT` only.

## Panes and commands

`/gate-hosts` and `/gate-accounts` (the mod, immediate, no model turn) read
gated's `/ui/manage` (UI plane: hosts with identity, reachability, auth,
runtime and their rights, workspaces, accounts with their adapter states,
pending changes; never a value). The hosts pane has an edit field taking one
of `host add NAME USER@HOST[:PORT] [KEY=VALUE...]`, `host set NAME KEY
VALUE`, `workspace add HOST NAME ROOT [LOCAL]`, `workspace remove HOST
NAME`, `policy set all|HOST|ACCOUNT ACTION allow|ask|deny`
(`manage.ts editArgv`: these shapes only, names checked, an argv, never a
shell string); the pane runs it as `launch.sh gate ...`, then `gate check
ENTRY`, whose consent dialog shows any widening. The accounts pane has Check
(`gate accounts --check NAME --json`) and Enter credential (`gate login
NAME`: the credential dialog's private field). Credentials are never typed
into the panes.

`manage.py` writes through the form writer only (`form.append_table`,
`form.set_key`; the form is never re-serialized); `workspace remove` takes
out exactly that table and verifies the result parses to the same document
minus it (and minus the `workspaces` table its dotted header made, when it
was the host's last), then says whether the removal applies at once or, for
a workspace that restricted anything, waits for the person's OK.

## Tests and mutations

`tests/test_policy.py` (decisions, rules, consent, the stand-ins, the hook,
web, accounts, imports, inspection, provisioning, forwarding; since the
review fixes also a restricted workspace taken out of the form, the transfer
servers' strict recognition, every path in every workspace it may reach,
sftp, and the routes the hook can't follow),
`tests/test_workspaces.py` (gated's binding, ids, path maps, snapshot, the
contract doc), `hooks/mod/manage.test.ts` (the panes), and
`tests/mutations_policy.py` (each enforcement point and each consent rule
mutated: a named test fails).
