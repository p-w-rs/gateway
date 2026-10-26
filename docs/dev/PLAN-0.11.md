# PLAN-0.11: gateway 0.11.0

Working spec for the 0.11.0 release. It implements the eight decisions the
user approved (they supersede DECISIONS.md "The user's four choices" #1 and
the 0.10.0 older-install sudo default), plus the fixes that need no decision.
Read it with [DECISIONS.md](DECISIONS.md), [SPEC-v3.md](SPEC-v3.md),
[PLAN-v4.md](PLAN-v4.md) and the module docs. Where they differ, this file
wins. Section 11 rewrites CLAUDE.md's invariants. This version was revised
after a security, a semantics and an implementation review; section 18 says
what changed.

The defects come from a requirements check of 0.10.0 kept outside the repo
("reqcheck" below). Each section cites the requirement numbers
it closes.

The headline change (decision 1) reverses the gateway's posture:
**ungated unless configured**. Today the default is "prevent unless widened":
unlisted hosts are refused, local sudo asks, curl and wget are refused, and
the managed shell strips the user's environment. From 0.11.0, everything the
gateway's configuration doesn't name uses the user's own tools, untouched.
The gateway stands only between Claude and the hosts and accounts the user
configured. Every other decision follows from that.

---

## 0. Summary of the choices made where the decisions left room

1. **"Configured" is sticky.** A target is configured when it is named in any
   of three places: the form, the vault's approved snapshot, or a non-secret
   list of configured entries (`private/configured.json`). Anything that
   would take a configured target out of the gateway is a **widening**:
   removing or renaming an entry, dropping an address, `also` entry or owner,
   adding a `when`, or deleting localhost's `sudo` key. Until the user
   approves, the approved entry keeps gating. A missing or broken form never
   lets a configured target through. A malformed entry still counts as
   configured, and it is refused.
2. **Stand-ins exist only where they matter.** A stand-in is on PATH only for
   a tool that can reach something configured. A brand-new install shadows
   nothing. When a stand-in gets an unconfigured target, it **execs the
   user's own tool** with the full argv and the inherited environment. The
   tool is found on the user's PATH, skipping every gateway stand-in folder.
   A recursion guard stops loops. `[settings] others` and the whole
   `[settings]` table are removed.
3. **The managed shell keeps the user's environment.** It runs the bundled
   bash with the user's inherited variables and the snapshot's PATH, and it
   loads aliases and functions from a bash snapshot. It drops a fixed list:
   Claude Code's own credential variables, the variables that make the shell
   run code at startup (`BASH_ENV`, `ENV`, `BASH_FUNC_*`, ...), and `GW_*`
   names other than `GW_MANAGED_DIR`. Its rc ends by removing any alias or
   function named after a stand-in, so the stand-ins can't be shadowed.
   When it isn't ready, a command runs in the user's own shell with a notice
   instead of being refused. `"warn"` is removed: `[shell] managed` is
   `"on"` or `"off"`.
4. **Per-mode values.** The mode keys are `default` (also spelled `manual`),
   `plan`, `acceptEdits`, `auto`, `bypass` (also `bypassPermissions`) and
   `dontAsk`. The words are `allow`/`true`, `"cc"` (leave it to Claude Code),
   `"ask"` and `deny`/`false`. A table must name `default`. A bare `true`
   right means `allow` in auto and bypass, and `"cc"` everywhere else,
   dontAsk included. Every mode uses one order:
   deny < ask < cc < allow < unconfigured. A command Claude typed is judged,
   at the stand-ins and in the MCP server, in the session mode the hook
   recorded in gated. Anything else (jobs, terminals, scripts, gated) uses
   the **modeless rule**: the strictest value over every mode except plan,
   with allow capped at cc.
5. **Network class.** Its default is `"ask"`. The gateway never approves a
   network command: `allow` means `"cc"`, and any hit makes the whole command
   ineligible for the gateway's allow. The class is judged only for Claude's
   command tools (Bash, Monitor, run_in_terminal, job_start, terminal_send),
   at the stricter of `[network] commands` and this computer's `network`
   policy. The http and download tools are unchanged. DNS, ping and
   traceroute are not in the built-in list.
6. **Alternate-route refusals apply only to configured targets, and in every
   managed mode.** A by-path tool, a login shell, a PATH-resetting wrapper or
   a transport variable is refused only when it reaches a configured target.
   Commands that hide their program are still refused when some configured
   entry is `"ask"` in the current mode, or when their text names a
   configured target.
7. **git decides by repository.** Inside a repository with any configured
   remote, and for any command whose effective URL is configured, git runs
   the bundled git. It gets an allowlisted environment, the gateway's settings
   at command-line scope (the same include file as today, now only in that
   child), and a read-only gateway-owned global config. Everything else runs
   the user's own git, untouched. `GIT_SSH_COMMAND` and `RSYNC_RSH` leave
   Claude's shell.
8. **SSO** uses the authorization code flow with PKCE, run by gated. A
   confirm dialog with an Open button acts as the gate. The listener runs on
   127.0.0.1, and the system browser is opened by absolute path. For
   ml-catalog the authority and scope are fixed. Changing sign-in keys is a
   widening. Browser-automation tools are denied while a sign-in runs.
9. **The vault passphrase** is offered after a secret is stored, until the
   user answers. The offer's state is kept in the vault, and the offer is
   skipped once the key is wrapped.
10. **Not in 0.11.0 without the user's say:** the stored-value paste check.
    The reqcheck (item 28) left its cost of about 0.1 s per prompt as an open
    question. Section 9.7 lists it as an open question.

---

## 1. Decision 1: posture "ungated unless configured"

Requirements closed: 16, 18, 19, 20, 21, 22 (and the framing of 0, 1, 2, 5, 6).

### 1.1 What "configured" means

The **configured set** is the union of:

- the form's entries: every `[hosts.NAME]` (localhost only when it has a
  `sudo` key) and every `[accounts.NAME]`, **including disabled (malformed)
  ones**;
- the entries in the vault's approved snapshot, when the vault can be read;
- `private/configured.json`. This is a non-secret mirror of the approved
  snapshot's reach: entry names, kinds, addresses, `also` and `via`
  entries, account hosts and owners, and whether localhost's sudo is
  configured. `consent.approve` and `consent.ratchet` rewrite it whole
  (temp file, then rename) whenever the approved snapshot changes. It can be
  read while the vault is locked.

How a configured target is handled:

| situation | what happens |
|---|---|
| the form names it and its approval matches | gated exactly as today, with per-mode values (§2) |
| the form names it, and the approval waits (new entry, or a widening) | refused with "waits for the user's OK (gate check NAME)", as today |
| the form no longer names it, or names less of it (see below) | the **approved** entry keeps classifying and gating until the user approves the removal |
| the entry is disabled (a mistake in it) | configured and refused ("[hosts.X] is off: gate status"). This holds in the ssh, sudo, CLI and git stand-ins alike |
| the vault is locked | the configured list still classifies; every configured entry is refused with the locked note (`consent.LOCKED_NOTE`, renamed from `LOCKED_SUDO_NOTE`) |
| gateway.toml is missing or unparseable | the last good form if there is one, else the configured list. That list's entries are refused ("gateway.toml is missing or has a mistake; the hosts it named stay gated"), never passed through |

These changes are **widenings**: they move a target from the gateway to the
user's own tools. They need the consent dialog, and the approved entry keeps
gating meanwhile:

- deleting or renaming a `[hosts.X]` or `[accounts.X]` table;
- dropping an `address`, an `also` entry or a `via` hop. An added address
  was already a widening;
- adding or changing `when`, since the host leaves the gateway outside that
  network;
- dropping an account's owner, `host` or destination;
- deleting `[hosts.localhost]`'s `sudo` key, or the whole table;
- an import "replace" that does any of the above.

The dialog says it plainly, for example "homelab will stop going through the
gateway: from then on Claude uses your own ssh, agent and keys for it."

**Restrictions the user wrote keep applying where the hook can judge them.**
An `elevation` restriction (deny or ask, in any mode) in
`[hosts.localhost.policy]` or `[policy]` counts as configuring this
computer's elevation. The hook applies it, and on deny the sudo stand-in
refuses. A `network` restriction there applies to the network class (§3.3).
`[policy]` keys `read`, `exec`, `write` and `credential` keep binding
configured hosts and accounts. They don't reach unconfigured ones, which are
the user's own. `gate status`, and the first 0.11 session's notice (§1.5),
name any global deny that no longer reaches everything it used to.

0.11 snapshots record whether localhost's sudo was **written** in the form.
A snapshot from before 0.11 carries no such record, so its localhost entry
counts as implicit and is not configured. The posture change for this
computer's sudo comes from the release (decision 1), not from an edit to
undo.

### 1.2 Which stand-ins are on PATH

`$DATA/bin` holds `gate`, the helpers, and **only the stand-ins that can
reach something in the configured set**:

| stand-in | present when the configured set has |
|---|---|
| ssh, scp, sftp | a host other than localhost, or an account with an ssh endpoint (github, huggingface, pijul) |
| sudo | localhost sudo, or an elevation restriction on this computer (§1.1) |
| git | a host other than localhost, or a git-capable account (github, huggingface) |
| gh | a github account |
| hf, huggingface-cli | a huggingface account |
| databricks, az | an azure account (with `databricks` for databricks) |
| crane | an azure account with `registries`, a github account with `packages`, or a registry account |
| pijul | a pijul account |
| asiml, dvc | an ml-catalog account |

Any process that loads the form and sees the configured set change rewrites
the set of stand-ins: SessionStart, hooks_post after an edit to
gateway.toml, hooks_filechanged, the Bash hook, and consent's approve and
ratchet. Each stub is written whole, by temp file and rename. A tool with no
stand-in runs the user's own binary directly. The hook still judges it
(rights don't apply, because nothing is configured; the network class and
the route checks do).

**Cold window.** launch.sh's `pre_session` runs before any Python, so it
can't compute the set. It writes the **full** base set of degraded stubs
("still setting up", exit 75) whenever gateway.toml has a `[hosts.` or
`[accounts.` header (`grep -q`), or `private/configured.json` exists.
Otherwise it writes none. Python narrows the set on its first run. The text
must be byte-identical to `envfile.stub_text` (an existing test pair).

SessionStart also writes the marker `$DATA/bin/.gateway-standins`, which the
pass-through lookup uses to skip stand-in folders (§1.3).

### 1.3 Pass-through mechanics

When a present stand-in finds that its target is unconfigured (§1.4), it
runs `os.execv(user_tool(name), argv)` with the **full original argv** and
the process's environment unchanged.

- **`user_tool(name)`** searches the calling process's PATH, skipping every
  folder that holds a `.gateway-standins` marker. That covers this install,
  and a second `CLAUDE_CONFIG_DIR`'s stand-ins too. It also skips this
  plugin's `/.pixi/` env folders. After PATH it tries
  `/usr/local/bin /opt/homebrew/bin /opt/local/bin /usr/bin /bin`, keeping
  git's xcode-select check. One rule for every tool, ssh included: the user's
  own Homebrew ssh is theirs to use. This replaces `ssh._system_ssh`'s fixed
  `/usr/bin/ssh` and `envfile.system_git`, which is renamed `user_tool`.
- **Recursion guard.** The exec'd environment carries `GW_PASSTHRU=<tool>:<n>`.
  If a stand-in is reached again for the same tool with n ≥ 1, it refuses:
  "gateway: <tool> on your PATH calls the gateway's stand-in again (a loop);
  run it by its full path." Refusing is always safe. The variable never lets
  a configured target through.
- **Missing tool.** The stand-in exits 127 with "gateway: <tool> isn't
  installed here. The gateway handles <tool> only for <configured entries>."
- **Audit.** Each pass-through writes one `passthrough` line: the tool and a
  validated host or owner name (else `-`), **never argv**. For git, only
  commands that touch a remote are logged; `git status` writes nothing to
  the shared audit log.
- **Tests** use a `user_tools` knob (a folder of recording fakes) that is
  honoured only under the test override. Invariant 7 gains this one
  exception: pass-through reads PATH, and only for an unconfigured target
  (§11).

### 1.4 Per-tool classification

**ssh, scp, sftp** (`ssh.py`, `ssh_args.py`). This closes reqcheck 18.

1. A **lenient parse** finds the destination and options without refusing
   anything. Today's refusals of `-F`, `-o ProxyCommand` and forwarding move
   to step 5, so they apply only to configured hosts.
2. The user's own ssh runs `ssh -G <full argv>` (1.5 s timeout) to get the
   hostname, user, port, ProxyJump and ProxyCommand. `ssh -G` can run a
   config's `Match exec`. That gives no new power, since the same argv is
   about to be exec'd with the same environment, and the stand-in's own
   environment holds no secret.
3. **Configured** when any of these names a configured name, `gw-NAME`,
   address, `also` entry or account ssh endpoint:
   - the destination word;
   - the `-G` hostname;
   - any ProxyJump hop, followed recursively with `-G`;
   - the ProxyCommand text;
   - a resolved IP (`getaddrinfo`, 1.5 s), as `_form_host_behind` does today.
4. A direct hit on the destination word (the form name, `gw-NAME`, an
   address or an `also` entry the form lists) takes the **gated path**.
5. The gated path is today's full parse with its refusals, rights, policy
   and pins.
6. A hit found **only** through `-G`, a hop, ProxyCommand or an IP
   **refuses with a hint**: "gateway: randombox-alias reaches homelab, which
   goes through the gateway; use `ssh homelab`." It is never routed. The hook
   judged the command by its words and couldn't have asked about an "ask"
   right.
7. No hit runs the **pass-through**.
8. scp and sftp: each remote operand is classified this way. If any operand
   is configured, the gated path runs for all of them. A copy that mixes a
   configured and an unconfigured remote is refused ("copy in two steps").
9. Git-over-ssh endpoints (`git@github.com`): the owner comes from the remote
   command (`git-receive-pack 'org/repo.git'`). A covered owner takes the
   gated path (the account's key); any other owner passes through with the
   user's agent.

Known limit: other IP spellings, and DNS aliases when `-G` or `getaddrinfo`
times out, fail open (§16).

**rsync** is not a stand-in. rsync starts `ssh` through PATH by default, so
it reaches the ssh stand-in when one is present. `RSYNC_RSH` leaves the env
file. An explicit `-e PATH` or `RSYNC_RSH=` that reaches a configured host
is refused by the hook (§1.7).

**sudo**: see §1.5.

**Account CLIs** (gh, hf, databricks, crane, pijul, az, asiml; `clis.py`).
Each stand-in resolves the destination the way the tool itself would:

- gh: `-R`/`--repo`, `GH_REPO`, `GH_HOST`, `--hostname`, else the cwd
  repository's remote (through the shared git resolver, §6.2);
- hf: `HF_ENDPOINT`, the repo id's owner;
- databricks: the workspace host;
- crane: the registry;
- az: the subscription and tenant.

A **covered** destination (`accounts.destinations` / `covers`, including
each account's `host`, so GHES counts) takes the gated path. An uncovered
destination that can be determined passes through, and the user's
`GH_TOKEN` and similar variables reach their own tool. An **undeterminable**
destination (`gh api graphql`, `gh api /user`, `gh auth status`,
`hf whoami`), when an account of that kind exists for that host, takes the
gated path with today's selection, or is refused asking for `-R` when the
choice is ambiguous. It never passes through with the user's full-scope
token.

**dvc** (`asiml.dvc_main`): inside an `.asiml` workspace, `dvc pull` and
`dvc push` go to asiml as today. Every other dvc command passes through to
the user's own dvc (exit 127 if there is none).

**git**: section 6.

### 1.5 This computer's sudo

- The starter form, now `form.STARTER` (moved out of migrate.py), is the
  three comment lines. It writes no `[hosts.localhost]`.
- Internally, `form.parse_text` **keeps** the implicit localhost `Host`
  (`explicit=False`), with a new marker `sudo_configured=False`. About 22
  call sites look up `form.hosts["localhost"]` (`policy.decide` for the http
  and download tools and local terminals and jobs, `managed`'s inspection,
  manage.py, the CONTRACT-v1 snapshot). They keep working. Only sudo and
  elevation read the marker. Every `"localhost"` lookup is audited to confirm
  that "not configured" never surfaces as a crash.
- **Unconfigured** (no `sudo` key, no elevation restriction) means no sudo
  stand-in at all: the user's sudo runs directly with no gateway decision.
  **Consequence, said plainly:** Claude's Bash has no terminal, so the user's
  own sudo works only where it needs no password. On macOS with Touch ID for
  sudo (pam_tid) it opens the system's own prompt. Claude's context (§1.9),
  the README and CONFIG.md say: "To have the gateway ask you for the
  password in its dialog, set `[hosts.localhost] sudo` (gate host set
  localhost sudo ask)." Following the user's decision 1, the starter is
  **not** re-seeded with `sudo = "ask"`.
- **An elevation restriction only** (no `sudo` key): the sudo stand-in is
  present. In that mode, deny refuses. Otherwise, once the hook has asked if
  it had to, the stand-in passes through.
- **`[hosts.localhost] sudo = <value>`** gates sudo exactly as today for that
  value, per mode (§2).
- **In a gateway terminal**, an unconfigured sudo prompt is answered through
  gated's prompt dialog **once**, with no "Remember it". Nothing is stored
  for an unconfigured target.
- **The first 0.11 session.** If the vault holds a local sudo password while
  local sudo is unconfigured, SessionStart shows one info dialog: "This
  computer's sudo now uses your own sudo unless gateway.toml sets
  `[hosts.localhost] sudo`. The stored password stays unused; `gate forget
  localhost` removes it." It also names any global `[policy]` deny that no
  longer reaches unconfigured targets (§1.1). The vault records that the
  notice was shown, so it never repeats.
- The 0.10.0 baseline mark and the `older_install` machinery are deleted
  (§4).

### 1.6 The managed shell (invariant 14 rewrite)

Managed mode stays (`[shell] managed`, default `"on"`). Its contract changes
from "curate a clean environment" to "run bash 5 with the user's environment,
with the stand-ins unshadowable, and leak none of Claude Code's or the
gateway's own credentials."

**Environment** (`hooks/gate-sh`, mirrored in `managed.py`, compared by a
test as today). Start from the inherited environment, which is Claude Code's,
and remove these by name with `env -u`, so no value ever reaches a command
line:

- **Claude Code's own credentials:** every `CLAUDE_*` or `ANTHROPIC_*` name
  that contains a credential word (`CREDENTIAL_WORDS`), plus a fixed list:
  `CLAUDE_CODE_OAUTH_TOKEN`, `CLAUDE_CODE_MESSAGING_TOKEN`,
  `CLAUDE_CODE_CLIENT_KEY`, `CLAUDE_CODE_CLIENT_KEY_PASSPHRASE`,
  `CLAUDE_CODE_CLIENT_CERT`, `CLAUDE_CODE_HOST_CREDS_FILE`,
  `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`. These are not the user's
  environment.
- **Variables that make a shell run code or change parsing:** `BASH_ENV`,
  `ENV`, every `BASH_FUNC_*` (exported functions; the user's functions come
  from the snapshot instead), `SHELLOPTS`, `BASHOPTS`, `PS4`,
  `PROMPT_COMMAND`, `CDPATH`, `IFS`, `GLOBIGNORE`, `BASH_XTRACEFD`.
- **The gateway's internal names:** `GW_*` except `GW_MANAGED_DIR` (a nested
  `claude` stays managed; invariant 14).

Everything else is **kept**: the user's `SSH_AUTH_SOCK`, `SSH_AGENT_PID`,
`GH_TOKEN`, `HF_TOKEN`, cloud credentials, proxies, toolchain variables. They
are the user's own credentials for the user's own unconfigured tools. A
configured stand-in's child still gets a clean per-call environment
(`clis.child_env`, `ssh_conf`). The gated git's is built the same way (§6.3).

**PATH** = `$DATA/bin`, then the snapshot's PATH (its `export PATH=` line,
which gate-sh already reads for plugin bins; the inherited PATH when there
is no snapshot), then other plugins' bin folders, then the approved
`import_path`.

**Aliases and functions.** On the latest Claude Code, the snapshot is made
by `CLAUDE_CODE_SHELL`, which is the managed bash in managed mode, so it is
normally a bash snapshot (`snapshot-bash-*.sh`):

- the rc **sources a bash snapshot** (the user's aliases, functions and
  options), then re-asserts PATH;
- a **zsh snapshot** (`snapshot-zsh-*.sh`, e.g. made before the prefix
  applied) gives only its PATH line. Its aliases and functions don't carry,
  a stated limit;
- for settings that live only in another shell's profile (a zsh user's
  `~/.zprofile`), `[shell] import_path`/`import_env` and the session-start
  offer (`found_not_imported`) stay;
- `acceptance_managed` records which shell made the snapshot on the latest
  Claude Code.

**The rc's last lines make the stand-ins unshadowable:**

1. Enter POSIX mode by assignment (`POSIXLY_CORRECT=y`), so special builtins
   are found before functions.
2. Run `unset -f` on every stand-in present in `$DATA/bin` (checked with
   `[ -e ]`), and on `command builtin hash type unalias unset exec source .`.
3. `\unalias` the same names.
4. Leave POSIX mode and run `hash -r`.

A test defines hostile aliases and functions with each of these names, plus
`BASH_ENV`, `ENV` and `BASH_FUNC_ssh%%`, and checks that `ssh` still resolves
to the stand-in.

**Masking the user's own values** (closes the security review's exposure
note). `env` and `printenv` now print the user's tokens. post.sh checks a
fixed list of credential variable names, mirrored as
`envfile.MASK_ENV_NAMES` and compared by a test. The list covers
`ENV_UNSET`'s names, the cloud and service tokens
(`AZURE_CLIENT_SECRET`, `DATABRICKS_TOKEN`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`, `DOCKER_AUTH_CONFIG`, ...) and Claude Code's own names.
post.sh compares them with sh builtins against its own environment, which is
Claude Code's, using `eval "v=\${$n-}"` and a `case` on the response. It
starts Python only when a value of 8 or more characters appears. Python then
masks every credential-named variable's value (8 or more characters) from
its own environment, besides the vault's values. Variables that exist only
in the shell snapshot's exports aren't seen. That is a stated limit, and it
mostly affects the desktop app.

**Not ready.** When the env's bash can't run (building, failed, pixi too old,
§5), gate-sh **runs the script in the user's shell**: byte for byte,
snapshot `source` included, under `/bin/bash` (else `/bin/sh`), with the
environment drops still applied. It adds one stderr line: "gateway: the
managed shell isn't ready (<reason>: <remedy>); this command ran in your own
shell." This used to be refused (exit 75). The posture makes the managed
shell a convenience, and the hook has already judged the command. A script
with a tool script's shape that doesn't parse (126) is still refused.

**`[shell] managed`** is `"on"` (default) or `"off"`. `"warn"` is removed:
a written `"warn"` is malformed, behaves as `"on"`, and `gate status` names
it. `consent.SHELL_RANK = {"off": 0, "on": 1}`. Turning it off is still a
widening, because without it Claude Code's own credential variables reach
Claude's shell unless the env file removes them (§1.8).

### 1.7 Alternate-route refusals (invariant 14 "Alternate routes" rewrite)

`hooks_bash._alternate_route` and `_route_text` stay. They now run **in
every mode, `managed = "off"` and mods off included**: the early
`if eff.shell.managed == "off": return None` goes. They refuse only a route
that reaches a **configured** target. The target is resolved with the
configured set (§1.1) and the shared git resolver (§6.2).

Each of these is refused when its target is configured (names, `gw-NAME`,
addresses, `also` entries, account hosts and owners), and passes otherwise:

- a tool by its path. `ROUTE_TOOLS` gains `git`, `rsync`, `su`, `doas`,
  `pkexec`;
- **login shells and PATH-resetting wrappers** running a stand-in name:
  `bash -l`/`--login`, `zsh -l`, `sh -l`, `su`/`su -`, `sudo` (secure_path),
  `sudo -i`, `doas`, `env -i`, `env -u PATH`, `command -p`. These rebuild
  PATH, and on macOS path_helper puts `/usr/bin` first, so they count as a
  tool by path;
- a PATH or transport change in an earlier stage or as an assignment:
  `PATH=`, `hash -p`, an alias, `GIT_SSH_COMMAND`, `GIT_SSH`, `RSYNC_RSH`,
  `rsync -e`, `-c core.sshCommand=`, `-o ProxyCommand=`;
- `ssh -J` or `-o ProxyJump=` naming a configured host, and a ProxyCommand
  string naming a configured address;
- `git config` writing `credential.*`, `core.sshCommand`, `url.*`,
  `remote.*.url`, `remote.*.pushurl`, `include.*`, `includeIf.*`,
  `core.hooksPath` or `core.fsmonitor` in a repository with a configured
  remote (§6.5);
- a **literal** `-c` string (`bash -c '/usr/bin/ssh homelab x'`), which is
  parsed and judged recursively like the outer command.

**Commands that hide their program or host.** These are a variable or
computed `-c` string, `eval`, a variable as the program, a function, `find
-exec`, `xargs`, and a sourced file. They are **refused** in either case:

- when **any configured entry resolves to `"ask"` in the current mode**: a
  host's ssh or sudo right, localhost sudo, an account's `use`, a
  `write`/`credential`/`elevation` policy;
- when the text names a configured name, address, `also` entry or `gw-NAME`.

The text: "this command hides the program or host it runs, and with <entries>
set to ask the gateway can't tell Claude Code what to ask about; spell the
command out." The stand-ins trust that an "ask" right reached them only
through a command the hook asked about (invariant 6), and this keeps that
trust honest. Otherwise there is no decision. Nothing configured, or nothing
set to ask, means the user's own business. The network class doesn't count
here: a hidden network name is one of the class's known misses (§3.5).

`_fallback_ask` resolves per mode (§2). `gate with NAME -- CMD` is unwrapped
for these checks and for the network class (§3.3). Target-less tools by path
(`/usr/bin/ssh-add -l`, `ssh-agent`) get no decision.

Refusal texts drop the "set [shell] managed = off" escape and name the
stand-in route instead: "use `ssh homelab`; the gateway supplies the key."

### 1.8 Mods off: no blanket Bash refusal (invariant 15 rewrite)

Today, `managed = "on"` with no mod denies every Bash and Monitor call. From
0.11.0 there is **no blanket refusal**. Without the mod, Claude's commands
run in the user's own shell (Claude Code sources the snapshot, then the env
files). The env file:

- prepends `$DATA/bin`, as today;
- when `CLAUDECODE` is set, `unset`s Claude Code's own credential names (the
  fixed list in §1.6; names only);
- when `CLAUDECODE` is set, `unalias`es and `unset -f`s every stand-in name
  present in `$GW_BIN`. This is POSIX and idempotent under `set -eu` in sh,
  dash, bash and zsh (`unalias x 2>/dev/null || :`), so a snapshot alias
  can't skip a stand-in after the hook judged the command;
- **no longer** sets `GIT_SSH_COMMAND` or `RSYNC_RSH`, injects the git
  include, or unsets `ENV_UNSET`.

The classic Bash hook still enforces every right, policy and per-mode value,
the network class, and the configured-only route check.

pre_bash.sh drops the `GW_MANAGED_CHECK` path, which sent every call to
Python. It uses the trigger-word list in every case (§3.4). Also deleted:
`hooks_bash._managed_gate`'s `MANAGED_DENY` branch, `launch.sh`'s
`degraded_bash("managed")`, and `envfile.DEGRADED_BASH_WHAT["managed"]`.
`_managed_gate` keeps only the once-per-session notice ("your commands run
in your own shell; the gateway still judges them").

### 1.9 Claude's context text (hooks_session)

`INTRO`/`HOWTO` are rewritten:

- "Machines and accounts **in gateway.toml** go through the gateway, which
  supplies their passwords, keys and tokens. Anything **not** in gateway.toml
  uses your own ssh, git, gh and sudo directly, with no gateway involvement."
- "Your own sudo works only where it needs no password; Claude has no
  terminal to type one. If sudo says a password or terminal is required,
  tell the user that the gateway can ask in its dialog once
  `[hosts.localhost] sudo` is set."
- "Don't remove or rename a gateway.toml entry, or reach a configured host
  by another name, address or path, to get past a refusal. Ask the user."
- "Network commands (curl, wget, nmap, ...) ask by default; `[network]`
  changes that."
- `MANAGED_HOWTO`: "Your Bash runs in the gateway's bash 5 with your own
  PATH, variables and aliases. The gateway's stand-ins come first for the
  machines and accounts it handles."
- `JOBS_HOWTO` is added only when checkpoint is live (§9.4).

### 1.10 The user's own credentials in Claude's shell

This is said plainly in §16, README "What changes when you install it" and
SECURITY.md:

- Claude's shell now holds the user's agent and token variables.
  `echo $GH_TOKEN` shows the value to the model unless the masker catches it
  (§1.6).
- Any route around a stand-in signs in with them: a script, a Makefile, a
  string the hook can't parse. For a configured host's limits to bind
  (`sudo = false`, `write = "deny"`, workspaces, forwarding grants, an
  account's narrower policy), **the user's own key or token must not also
  open it**. Use a dedicated gateway key for the host, keep the personal key
  out of the agent, and scope the token.

---

## 2. Decision 2: per-mode settings

Requirements closed: 2, 23, 24.

### 2.1 Modes

Claude Code 2.1.301's `--permission-mode` choices are `acceptEdits`, `auto`,
`bypassPermissions`, `manual`, `dontAsk` and `plan`. The hook payload
strings in today's code and tests are `default`, `plan`, `acceptEdits`,
`auto` and `bypassPermissions`. Normalization (`modes.normalize`):

| payload `permission_mode` | key | spellings accepted in gateway.toml |
|---|---|---|
| `default` or `manual` | `default` | `default`, `manual` |
| `plan` | `plan` | `plan` |
| `acceptEdits` | `acceptEdits` | `acceptEdits` |
| `auto` | `auto` | `auto` |
| `bypassPermissions` | `bypass` | `bypass`, `bypassPermissions` |
| `dontAsk` | `dontAsk` | `dontAsk` |
| empty, missing or unknown | `default` (never yields `allow`) | n/a |

The e2e suite gains one probe per `--permission-mode` that records the real
payload string on the latest Claude Code. The table is corrected from those
results before release.

### 2.2 Values, and which keys take a table

The resolved words for one mode are, in order: **`deny` < `ask` < `cc` <
`allow`**. Spellings:

| word | rights (ssh, sudo, use) | policy restrictions | `[network] commands` |
|---|---|---|---|
| deny | `false`, `"deny"`, no, off | `"deny"` | `"deny"`, `false` |
| ask | `"ask"` | `"ask"` | `"ask"` |
| cc | `"cc"` | `"cc"` | `"cc"`, and also `"allow"`/`true` (§3.2) |
| allow | `true`, `"allow"`, yes, on | `"allow"` | n/a |

A value is either **a word** or an **inline table**
`{ default = …, auto = …, … }`:

```toml
sudo = "ask"
sudo = { default = "ask", auto = true, plan = false }
write = { default = "ask", bypass = "deny" }
```

Rules:

- A table **must** have `default`. An unlisted mode takes `default`'s word.
- Inside a table, `true`/`"allow"` means **allow in that mode**: an explicit
  per-mode approval. In plan it degrades to `cc`, since plan never executes.
- A bad mode name, a bad word, a missing `default`, or a table on a key that
  takes one word only disables the entry. It is refused and stays configured
  (§1.1). A malformed key in `[policy]` counts as deny. A malformed
  `[network]` keeps the approved value ("ask" if none).

**Keys that take a table:** host rights `ssh`, `sudo`; account right `use`;
the policy restrictions `read`, `exec`, `write`, `network`, `elevation`,
`credential` at every scope where they exist (global, host, localhost,
workspace, account); `[network] commands`.

**One word only:** `scripts`, `provision`, `env_import`, the forwarding
grants, `[shell]`, `[vault]`, `runtime`, workspace paths and `sign_in`. They
are decided only where no mode exists, or they aren't permissions.

### 2.3 What a bare word expands to (today's meaning kept)

| bare word | default | plan | acceptEdits | auto | bypass | dontAsk |
|---|---|---|---|---|---|---|
| right `true` | cc | cc | cc | allow | allow | cc |
| `"ask"` | ask | ask | ask | ask | ask | ask |
| `false`/`deny` | deny | deny | deny | deny | deny | deny |
| `"cc"` | cc | cc | cc | cc | cc | cc |
| policy `"allow"` (no restriction) | allow | cc | allow | allow | allow | allow |

So `sudo = true` keeps its meaning: the gateway approves only in auto and
bypass, and leaves the other modes to Claude Code. **dontAsk gets "cc"**
(the code's `mode in ("auto", "bypassPermissions")` today; invariant 5).
Approving there takes an explicit `dontAsk = "allow"`, which the consent
dialog shows as a widening.

A policy restriction's `"allow"` means "no restriction": the effective word
is the per-mode minimum of the right and every policy layer, so `allow`
there never raises anything. In dontAsk, Claude Code refuses a "cc" (no
gateway decision) unless a permission rule allows the command. A hook's
"ask" still prompts there (Claude Code 2.1.310, verify012), so the hook
writes its record in dontAsk as in every mode. The docs say so.

### 2.4 Where the mode comes from

- **The Bash hook and the MCP hook** read `payload.permission_mode`. That
  covers Bash, Monitor, run_in_terminal, job_start and terminal_send; the
  last two carry the mode in their payloads too.
- **The session's recorded mode.** When the effective form has a per-mode
  value whose stand-in word (below) differs across modes other than plan,
  the Python hooks record `(session, mode)` in gated with
  `POST /agent/session/mode`. The hook is a gateway entry point below the
  registered session, so the usual plane checks apply. A stand-in or web.py
  reads it with `GET /agent/session/mode` for a caller that is
  **`typed_by_claude`** (the stand-ins) or for the MCP server below that
  session (web.py).
- **The modeless rule** covers every other caller: jobs, terminals, scripts
  (`scripts = true`), gated's own `_bind`/`ensure_runtime`/inspection,
  `managed.imports_allowed`, and any caller when gated has no record. The
  word is the **strictest over default, acceptEdits, auto, bypass and
  dontAsk** (plan excluded), with allow capped at cc. A bare `true` gives cc,
  which is today's `true`. `{default = "ask", auto = true}` gives ask, which
  a non-typed caller treats as a refusal (invariant 6).
  `{default = false, auto = true}` gives deny.
- A job's command is judged up front at the mode in its `job_start` payload
  (as for Bash). At run time, inside the job, it is not typed, so the
  modeless rule applies. "ask" is refused there, unchanged from today.
- Every refusal and credential use audits the mode it used (or `modeless`).
- A recorded mode is a guardrail: a process running as the user could post
  a false one (invariant 17's framing).

### 2.5 What each word does

| word | Bash hook (mode known) | stand-ins, gated, web.py |
|---|---|---|
| deny | deny | refuse |
| ask | ask (a typed command only; a transfer, script or job context denies, as today) | only a command Claude typed (invariant 6); others refused |
| cc | no decision | today's `true`, including the `scripts` rule |
| allow | the allow step (SPEC 8 shapes only; never for account CLIs, `gate with`, git, run_in_terminal, the job tools, or a network-class hit) | today's `true` |

For keys that have no allow shape (an account's `use`, git push, `gate
with`, http and download), allow acts like cc. The dialog never promises
"approves without asking" for them (§2.8).

### 2.6 Implementation shape (fail-safe for every existing reader)

- `form.py` parses a table into a `modes.ModeValue` (a frozen map mode →
  word, with `default` required). Tables are stored in **new attributes**
  (`Host.modes`, `Account.modes`, `Policy.modes`, `Form.network.commands`).
  No existing reader sees them.
- The **legacy attributes** (`Host.ssh`, `Host.sudo`, `Account.use`, policy
  words) keep today's vocabulary (True/"ask"/False). They hold the
  **modeless** resolution, with cc and allow mapped to True. A reader that
  isn't updated therefore gets the strict value.
- `consent.compute(form, data, mode=None)` returns an `Effective` whose
  legacy attributes are resolved for `mode`: the recorded mode for a typed
  caller, or None for the modeless rule. `Effective.word(entry, key, mode)`
  gives the hook the full four-word value.
- `hooks_bash._right`, `_eff_right`, `_policy_hits`, `_fallback_ask` and the
  allow step move to `Effective.word`. A per-mode table can no longer fall
  into `_right`'s `else: return True`.
- `consent.RANK` gets explicit entries for the four words plus
  `unconfigured`. Every lookup indexes it (`RANK[w]`), so an unknown value
  raises instead of ranking 0. The same goes for `rmin`.
- Mutations: a table reaching a legacy reader as True; RANK falling back to
  0; the stand-in ignoring the recorded mode; dontAsk expanding to allow.

### 2.7 Consent ranking

- Values are compared **mode by mode** in one order:
  deny(0) < ask(1) < cc(2) < allow(3) < unconfigured(4). "unconfigured"
  makes a removal (§1.1) a widening.
- A change is a **widening** if any mode rises, and a **narrowing** if no
  mode rises and at least one falls.
- The **effective** value is the per-mode minimum of the form and the
  approved value. Falls apply at once (ratchet), and rises wait for the OK,
  in the same change.
- The approved snapshot stores the six-mode map for a key that has a table,
  and the bare word otherwise.
- For a policy, the minimums are taken per mode too.
- The maximum over modes is used only for display.

### 2.8 Dialog wording

The consent dialog lists each key that rose, mode by mode, in plain words
and with Claude Code's own mode names:

- "In Manual mode, the gateway will approve `sudo` on this computer without
  asking you (was: Claude Code decides)."
- "In Plan mode: refused (was: asks you)."
- "homelab will stop going through the gateway: from then on Claude uses
  your own ssh, agent and keys for it."

For keys with no allow shape, allow is shown as "Claude Code decides".
`/gate-hosts`' Review pane shows a table as `Manual: ask · Auto: allow ·
Plan: deny`. There is no new dialog kind.

### 2.9 Edit syntax (/gate-hosts, gate CLI)

- `gate host set NAME KEY VALUE` keeps the one-word form.
  `gate host set NAME KEY MODE=WORD [MODE=WORD …]` writes a table (`default`
  is required). The same goes for `gate policy set all|HOST|ACCOUNT ACTION …`.
  An account's `use` keeps being edited as today, by chat through the form
  writer; there is no new account command.
- New: `gate network commands VALUE|MODE=WORD…`,
  `gate network extra add|remove NAME`, and
  `gate network drop add|remove NAME`.
- `manage.ts editArgv` accepts a variable number of `MODE=WORD` tokens after
  the key (no longer exactly 5 words for host set and policy set; manage.py's
  `len(rest) == 4` checks become "4, or more `MODE=WORD` tokens"). Each
  token must match
  `^(default|manual|plan|acceptEdits|auto|bypass|bypassPermissions|dontAsk)=(true|false|allow|deny|ask|cc)$`.
  `SAFE_WORD` admits `=` only in that shape. manage.py writes the table with
  `form.set_key` (`form.toml_value` serializes a `ModeValue`).
- The `/gate-hosts` and `/gate-accounts` panes render a table in the style
  of §2.8, never as an object.
- manage.test.ts gains cases for each shape.

### 2.10 The http and download tools

- `mcp_perm.sh` stays sh and awk and never allows from the form. For `http`
  and `download` it hands off to **Python** (`launch.sh hook-mcp`, a new
  `hooks_mcp.py`). These calls are rare and network-bound, so a Python start
  is affordable.
- Python resolves the effective `network` policy
  (`[hosts.localhost.policy]`, `[policy]`) for the payload's mode. It
  answers deny, or ask, or nothing, and **never allow**. A bare word or
  absent policy gives cc, so no decision: invariant 5 is unchanged. Python
  also records the session mode (§2.4).
- `web._network_ok` resolves the same key with the session's recorded mode,
  or the modeless rule without one. "ask" **passes** there: every MCP call is
  Claude's own and was asked about up front. This is the same trust as
  invariant 6, and it closes the "fails after approval" case (reqcheck 24).
- `[network] commands` is **not** folded into web.py or `policy.decide`
  (§3.6).
- git push is a Bash command and is judged by hooks_bash (§6.5), not here.

### 2.11 CONTRACT-v1

The checkpoint snapshot's `rights` keep their words (allow/ask/deny), taken
from the modeless resolution: cc and allow map to allow, ask to ask, deny to
deny. The contract text and checkpoint's copy are unchanged.

---

## 3. Decision 3: network commands

Requirements closed: 0, 1, 2, 3, 4, 6 (and 21's curl/wget point).

### 3.1 The class

Built-in basenames (in command position, after unwrapping):

```
curl wget wget2 aria2c xh http https lynx w3m links links2
nmap nping masscan zmap rustscan hping3 ssh-keyscan
nc ncat netcat socat telnet ftp tftp lftp smbclient certutil
```

httpie's `http` and `https` are included. The gateway's `http` is an MCP
tool, not a command name, so they don't collide.

Structural members, matched by shape, each with a **reserved name** usable
in `drop`:

| reserved name | matches |
|---|---|
| `openssl-tls` | `openssl s_client`, `s_server`, `s_time` (other openssl subcommands such as `rand`, `dgst`, `genrsa` are not network) |
| `http-server` | `python[3] -m http.server`, `-m SimpleHTTPServer`, `-m http`; `php -S`; `ruby -run -e httpd`; `busybox httpd` |
| `dev-tcp` | `/dev/tcp/…` or `/dev/udp/…` as a redirection target or in a shell string |
| `rsync-daemon` | `rsync` with an `rsync://` URL or a `host::module` operand |
| `busybox` | `busybox APPLET` where the applet is a class member |

**Not** in the built-in list (the user adds them with `extra`): `dig`,
`nslookup`, `host`, `whois`, `ping`, `ping6`, `traceroute`, `mtr`. The
ssh-family (`ssh`, `scp`, `sftp`, rsync over ssh) isn't in the class either.
To configured hosts it is gated by rights. To **unconfigured** hosts it is
the widest network route Claude has, and it is the user's own under decision
1. Invariant 22 and the docs say so. `extra = ["ssh", "scp", "rsync"]`
brings them into the class.

### 3.2 Config and consent

```toml
[network]
commands = "ask"            # a word or a per-mode table
extra    = ["dig", "ping"]  # names added to the class
drop     = ["openssl-tls"]  # names (or reserved names) taken out
```

- `commands` defaults to `"ask"` in every mode. Its words are deny, ask and
  cc. `"allow"`/`true` are accepted and mean **cc**: the gateway never
  approves a network command itself. `/gate-hosts` shows them as "Claude
  Code decides".
- `extra` and `drop` are lists of safe basenames (`[A-Za-z0-9._-]{1,32}`) or
  reserved names, at most 32 each.
- `[network]` joins `form.TOP_KEYS`. Its consent entry is `settings`.
- **Consent direction.** A name entering the class (added to `extra`, or
  removed from `drop`) is a narrowing and applies at once. A name leaving
  it (removed from `extra`, or added to `drop`) is a widening. Raising
  `commands` in any mode is a widening. Effective names = built-ins ∪
  approved `extra` ∪ form `extra`, minus (approved `drop` ∩ form `drop`).
- A malformed `[network]` keeps the approved value ("ask" and the built-ins
  if none), and `gate status` names the mistake.
- `transfer.SETTINGS_TABLES` gains `network`.

**Expected friction.** "ask" also prompts in bypassPermissions, a mode chosen
to stop prompts. The README gives the one-liner to change that:
`gate network commands default=ask bypass=cc auto=cc`.

### 3.3 Where it is judged

`hooks_bash._network_hits(stages, command, mode)` runs for Bash, Monitor,
run_in_terminal (Claude's command in the user's Terminal panel), both
job_starts and terminal_send.

1. **Positions.** Command position after unwrapping env, nice, nohup,
   timeout, time, command, exec, xargs, busybox, `sudo`/`doas`, and `gate
   with NAME --`. It also scans:
   - subshells `( … )`, groups `{ …; }` and `&` backgrounding;
   - `$( … )`, backticks and process substitution;
   - `find -exec`/`-execdir`;
   - literal `bash`/`sh`/`zsh -c` strings, recursively;
   - the remote command of `ssh HOST CMD` (configured or not), scanned as
     text.

   The text scan works like `_route_text` and covers what the parser returns
   `None` for.
2. **Value.** For local commands, the stricter of `[network] commands` and
   this computer's `network` policy (`[hosts.localhost.policy]`,
   `[policy]`), both for this mode. For a policy, allow counts as cc here.
   For `ssh HOST CMD` to a configured host, that host's own `network` policy
   is also taken into the minimum. The refusal names the key that decided.
3. **Effect.**
   - Any hit makes **the whole command ineligible for the gateway's allow**,
     in every mode, so `sudo nmap` no longer slips through the sudo
     auto-allow (closes requirement 1's regression).
   - deny gives deny and beats an ask collected from a right.
   - ask joins the asks. It is honoured only for a typed command; a job,
     terminal or script context denies.
   - cc gives no decision from the class (other rules may still deny or
     ask).
   - A network command under `gate with` (a vault secret goes to it) is
     never weaker than ask: cc becomes ask.

### 3.4 Prefilter, word file, cold window

- `pre_bash.sh`'s trigger words gain the class names and the structural
  triggers (`openssl`, `-m http`, `php`, `ruby`, `busybox`, `/dev/tcp`,
  `/dev/udp`, `rsync`). They also gain `su`, `doas`, `pkexec`, `osascript`,
  and git's remote subcommands (§6.6).
- The user's `extra` names reach the prefilter through `$DATA/network-words`.
  Python writes it whole on every form load that changes it, and pre_bash.sh
  reads it with the `read` builtin. A test compares Python's built-in list
  with pre_bash.sh's and launch.sh's.
- **Cold window** (`launch.sh degraded_bash`, byte-identical to
  `envfile.degraded_bash_text("network")`): the class **asks**, unless
  gateway.toml has a `[network]` table (whose value sh can't read), in which
  case it **denies**. This replaces today's rule of refusing curl and wget
  once a vault exists.
- `_deny_curl` and the `("curl", "wget")` branch in `_judge` are removed.
  curl and wget are ordinary members.

### 3.5 Known misses (guardrail, not sandbox)

These are listed in docs/dev/modules/network.md and README Limits:

- inline networking in interpreters: `python -c` with sockets, `node -e`,
  `perl -MIO::Socket`, `ruby -e`;
- `osascript -e 'do shell script …'`;
- ssh's `ProxyCommand`, `LocalCommand`, `KnownHostsCommand` and `Match
  exec`, which run locally even for pass-through ssh;
- git `!` aliases, `core.pager` and hooks;
- scheduled runs: crontab, at, launchctl, systemd-run;
- a name computed at run time, `eval "$x"`, a hidden `-c` string (§1.7), and
  scripts on disk.

### 3.6 What the class doesn't touch

- The http and download tools are governed by the `network` policy only
  (§2.10).
- `ssh -L`/`-D` tunnels through configured hosts stay under the host's
  `network` policy.
- `policy.decide` and `web.py` don't read `[network]`.

---

## 4. Decision 4: no backward compatibility (deletions)

Requirements closed: 12, 36, 37, 38, 39, 40, 41, 42 (the gateway's share; the
lead runs the checkpoint and pixi-guard deletions, 43-50, in their repos).
The user's live 0.6 install is converted with the **published 0.10.0**
first. That goes in a release-notes line (CHANGELOG 0.11.0, with the
tag-pinned `#v0.10.0` install recipe taken from the README section being
deleted), not in the README.

Delete these, with their tests and their mutation anchors:

| what | files | workstream |
|---|---|---|
| the 0.6→v3 conversion | `migrate.py`, `vault_v2.py`, `tests/test_migrate.py`, the migrate-only parts of `harness.py`, `gate migrate`. Remove the calls in `hooks_session.py` (`ensure`, `leftover_v2`, `tidy_leftover`, `report_flag`), `hooks_prompt.py` (`take_unshown_report`), `gate.py` (`needed`, `last_failure`, `run`, `ensure`) and `transfer.py` (`map_export_v1`). **First move** the live helpers: `migrate.starter` becomes `form.STARTER` (three comment lines); `_sanitize` and `_fmt_addr` move to gate.py's `import-ssh`. **Keep a 0.6 detector** in `vault.save`: when `store.age` exists and `vault.age` doesn't, refuse to create a vault with "gateway: a gateway 0.6 vault is here; convert it with gateway 0.10.0 first (see CHANGELOG 0.11.0)" | WS-0 |
| export formats 1 and 2 | `transfer.FORMATS = (3,)`; the `fmt == 1` and `fmt == 2` branches; `test_transfer_*` cases | WS-0 |
| the 0.10.0 baseline mark and the older-install sudo default | `vault.BASELINE`, `BASELINE_KEY`, `older_install`; `consent.older_install`, `baseline(older)`, `apply_install_defaults(older)`; `form.LOCALHOST_SUDO_OLDER`, `Host.sudo_default`'s older branch. `LOCKED_SUDO_NOTE` becomes the general `LOCKED_NOTE` | WS-0 |
| npm cli.js (pre-2.1.113) detection | `ancestry.is_claude_node` and its call sites (`ancestry.is_claude`, `daemon/peers.py`); tests | WS-0 |
| Entra sign-ins only 0.6 could make | refresh-token rotation stays. The "no sign-in here" dead ends (`popup.SIGNIN_UNAVAILABLE`, `signin_unavailable`, gate_setup's `_Stop(signin_unavailable)`) are reworked once §7 lands. A fixed "browser sign-in isn't available here" message stays for headless sessions | **WS-5** |
| `claude_ancestor` | `ancestry.claude_ancestor`, its `test_ancestry_trees` rows, `harness_ux`'s `extra["claude_ancestor"]` | WS-0 |
| `vault.sudo_choice` `"nopasswd"` | the `"nopasswd"` acceptance in `sudo_choice`/`set_sudo_choice` | WS-0 |
| sudoers notes | the README "Gateway 0.8 and older could add a sudoers file" line, and any visudo or sudoers wording in docs (`test_no_blanket_passwordless_sudo_advice_anywhere` stays) | WS-0 |
| `lib.ts` pre-0.9.1 defaults | the "absent counts as written" managed branch, and any 0.9.1 fallback in `parseEnvState` | WS-0 |
| `lib.ts MODS_MIN_*` and stated floors | README "Claude Code 2.1.287/2.1.286" and the `requires-pixi` floor wording become "latest" (§5) | WS-0 |
| README upgrade and rollback recipes | "Upgrading from 0.9.x", "From 0.6", "Rolling back", replaced by one line: "latest only; see CHANGELOG" | WS-0 |
| `[settings]` (`others`, its only key) | `form.SETTINGS_KEYS`, `Settings`, `TOP_KEYS`' `settings`, consent's others compare, `ssh`'s `others == "mine"` branch, `envfile`'s `ENV_UNSET` unset, every `others` mention in the docs. A written `[settings]` becomes an unknown table (a `gate status` note) | **WS-1** |
| `[shell] managed = "warn"` | §1.6 | WS-A1 (form, consent), WS-1 (gate-sh, mod) |
| the managed refusal machinery | `MANAGED_DENY`, `degraded_bash("managed")`, `GW_MANAGED_CHECK`, the managed=off escape texts, `_route_deny_hidden`'s unconditional refusals | WS-1 |
| the env file's git include, `GIT_SSH_COMMAND`, `RSYNC_RSH`, `git_stub_text` and the system-git fallback stub | §6 | WS-4 (git), WS-1 (env file) |
| `_deny_curl`, the curl/wget branch | §3.4 | WS-3 |
| launch.sh `status`'s `vault_v2` field and the cold guard's `store.age` logic | the path stays in the file guard's deny list | WS-0 |

`paths.v2_*` and the file guard's protection of `store.age`/`key.txt` are
**kept**. A leftover 0.6 file must still never be read by Claude.

---

## 5. Decision 5: latest only (pins)

Requirements closed: 5, 8, 9, 13, 53, 54. The relock happens in WS-R, first
(§17), so every later workstream builds and tests on the new interpreter.

- **`plugins/gateway/pixi.toml`**: `python`, `age`, `pynacl`, `bash`,
  `tmux`, `pixi-pack`, `zstd` and the already-`*` CLIs all `"*"`.
  `requires-pixi = ">=<newest>"` (0.83.0 at spec time). `bash = "*"` is
  conda-forge's newest, **whatever its major version**. A future 6.x is
  "latest" by decision 5, and gate-sh and the rc are tested on whatever is
  locked.
- **`plugins/gateway/runtime/pixi.toml`**: `bash = "*"`, `tmux = "*"`.
  `pixi-unpack` is pinned exactly to the main lock's `pixi-pack` version
  (they ship from one repository). update-deps writes it, and
  `test_packaging` asserts they are equal on every platform.
- **pijul**: the cargo task's `--version` is bumped by update-deps to the
  newest release, pre-releases included (pijul has only betas, and a plain
  `cargo install` skips them).
- **`update-deps`** (`pixi run update-deps` → `tests/update_deps.py`, a
  script, not a one-liner). It:
  1. checks that the running pixi is the newest (`pixi search pixi`);
  2. runs `pixi update` on both manifests (`--manifest-path
     runtime/pixi.toml`);
  3. sets `requires-pixi` and `lib.ts PIXI_TESTED` to that pixi;
  4. pins `pixi-unpack` and bumps pijul;
  5. reinstalls (`pixi install --locked`);
  6. prints what moved and runs the suite.

  CLAUDE.md "Commands" documents it as the per-release relock step. There is
  no CI.
- **Tested-version wording.** `lib.ts` keeps one tested pixi and one tested
  Claude Code. `/gate-doctor` says "tested with pixi X and Claude Code Y".
  An older version is a warning ("update: only the latest is supported"),
  and a newer one is an info line. The minimums are deleted.
- **The Python minor version during a rebuild.** `launch.sh` and
  `envfile.older_env_python` never use an older env whose Python minor
  differs from the lock's. New code never runs on the previous Python (a
  3.12 env with 3.15 code). While the new env builds, the cold paths apply
  (file guard, cold Bash guard, degraded stubs). Invariant 13's "Python
  3.12" becomes "the lock's Python".
- **pixi too old.** `launch.sh` recognizes pixi's "requires pixi" refusal,
  and `status` reports `pixi_too_old` with the found and needed versions.
  gate-sh's not-ready notice (§1.6), `gate status` and `/gate-doctor` say
  "update pixi: pixi self-update". `acceptance_install`'s `prereq` step
  covers an old pixi.
- **TUI harness and acceptances**: `pixi exec --spec python=3.12` becomes
  `--spec python` in tests/tui, the acceptance headers and CLAUDE.md. The
  checkpoint repo has an identical tui copy, so the lead changes it in both.
- **age**: a test runs the locked age's passphrase prompt under a pty and
  checks it against `agepass`'s regex, so a reworded prompt fails at relock.

---

## 6. Decision 6: git

Requirements closed: 8, 17, 19, 63, 64, 66.

### 6.1 The stand-in

`git` is a `BASE_STANDINS` entry (`("git", ("shim", "git"))`). It is present
only when the configured set has a host other than localhost or a
git-capable account (§1.2). The env file's `GIT_CONFIG_COUNT` include
injection, `GIT_SSH_COMMAND`, `git_stub_text` and the system-git fallback
are removed. The env always has git.

### 6.2 Classification, per repository (`gitroute.py`, shared)

The stand-in and the hook use one resolver: `gitroute.resolve(argv, cwd)`.

- **Repository and config.** The resolver honours `-C`, `--git-dir`,
  `--work-tree`, `GIT_DIR` and `GIT_WORK_TREE`. It reads the effective
  config **as the user's git would**: the bundled git's `git -c
  core.fsmonitor= config -z --list --show-scope`, in that repository, with
  the user's global and the repository's config (includes and `includeIf`
  resolved by git). It runs config reads only, never a command that touches
  the index, the hooks or the network. `-c` and `--config-env` pairs on the
  command line are applied on top.
- **Aliases** are resolved first (`alias.X`). An alias to a git subcommand
  is classified as that subcommand. A `!` alias in a repository whose
  routing is gated (below) is refused: "gateway: a shell alias in a
  repository the gateway handles; run the commands it stands for."
- **Effective URLs.** The resolver collects every remote's `url`, all of its
  values, and every `pushurl`, after `insteadOf` and `pushInsteadOf`
  rewriting (longest match). It also takes the operand URLs (`clone`,
  `push URL`, `fetch URL`, `ls-remote URL`), `branch.*.pushRemote`,
  `remote.pushDefault`, `.gitmodules` URLs, and `lfs.url`.
- **Configured URL.** A URL is configured if its host and owner are covered
  by a configured account (`accounts.destinations` / `covers`, each
  account's `host` included, so GHES and custom hosts count; not the fixed
  `GIT_ACCOUNT_HOSTS`), or if its host is a configured `[hosts.X]` by name,
  `gw-NAME`, address or `also` entry.
- **Rule: gated routing** for every git command run in a repository where
  **any** effective URL is configured, and for any command whose operand
  URL is configured (a clone, or `ls-remote` from anywhere). Commits, logs
  and status in such a repository use the account's identity. **Everything
  else passes through**.
- `git config --global`, `--system` or `--file` always passes through: it
  writes the user's own config, which the gated git doesn't read.

### 6.3 The gated git

`exec` the env's git (`paths.env_bin()/git`) with an environment built from
an allowlist (`clis.child_env` plus git's own needs: `HOME`, `LANG`, `TERM`,
`TZ`, `GIT_EDITOR`, `GIT_PAGER`, `PAGER`, `LESS`, `TMPDIR`, `PWD`, plus the
gateway's own settings below). Nothing else from the inherited environment
gets through, in particular:

- `GIT_CONFIG_COUNT`/`KEY`/`VALUE`, `GIT_CONFIG_PARAMETERS`;
- `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_SSH*`, `GIT_PROXY_COMMAND`,
  `GIT_EXEC_PATH`;
- `GIT_SSL_*`, `GIT_TRACE*`, `GIT_CURL_VERBOSE`;
- `http(s)_proxy`, `ALL_PROXY`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`.

Settings:

- **Command-line scope**, which beats `.git/config`: `GIT_CONFIG_COUNT`
  injects `include.path=<the gateway include file>`, the same file and
  mechanism the env file uses today, now only in this child. The include
  holds the `credential.helper=` reset, the gateway's URL-scoped helpers,
  the `insteadOf` rewrites, `core.sshCommand=<the ssh stand-in>` and the
  account identities (`includeIf`). A repository-level `credential.helper`,
  `insteadOf` or `user.email` can't come after them. Keeping the identities
  here, as today, means a repository's own `user.email` doesn't replace the
  account's.
- **`GIT_CONFIG_GLOBAL=$DATA/git/global`**: a gateway-owned file, mode 0444,
  which a gated `git config --global` can't change. It holds safe defaults,
  including `init.defaultRefFormat=files` and `init.defaultObjectFormat=sha1`,
  so a clone made by the bundled git (git 3.0 later) stays readable by the
  user's older git and IDE. A test checks that the user's git reads a gated
  clone.
- `GIT_CONFIG_NOSYSTEM=1`.

So the user's `~/.gitconfig` and `/etc/gitconfig` don't affect Claude's
gated git. The direct-caller and ancestry checks and policy apply as today
(write = push, credential = fetch with a token).

The helper's existing `--get-urlmatch http.sslVerify` refusal extends to
`http.proxy`, `http.sslCAInfo`, `http.sslCAPath` and `http.sslBackend` for
the URL.

### 6.4 Pass-through

`exec user_tool("git")` with the inherited environment and the user's
`~/.gitconfig` untouched. With `GIT_SSH_COMMAND` gone from the shell, the
user's own `core.sshCommand` applies. git's default `ssh` is found on PATH:
it reaches the ssh stand-in when one is present, and that stand-in passes an
unconfigured host through.

### 6.5 Up-front judging in the hook (requirement 24)

`hooks_bash` judges `git push|fetch|pull|clone|ls-remote`,
`git remote update` and `git submodule update` with the same resolver
before they run. For each configured URL:

- an account: its `use` right and its `write` (push) or `credential`
  (fetch) policy, per mode;
- a host: its ssh right and `write` policy, per mode.

"ask" asks, deny denies, and allow acts as cc (git has no SPEC 8 shape). A
push can no longer fail after the user approved Claude Code's prompt. The
hook resolver reads config only (§6.2). In a repository with a configured
remote, `git config` writes to the keys listed in §1.7 are refused.

### 6.6 Cost

- In the stand-in, every git call in a shell where the stub exists pays one
  Python start, a form and configured-list read (no vault read for
  classification) and one `git config` subprocess. The budget is ≤ 80 ms on
  macOS arm64, measured in a new perf test and recorded in TESTING.md.
- The prefilter adds `git` only together with the remote subcommands above,
  so `git status` never starts Python in the hook.
- During a cold start, the degraded git stub passes through (`exec` the user
  git that launch.sh finds the way `user_tool` does) when gateway.toml has
  no `[hosts.` or `[accounts.` header, and says "still setting up"
  otherwise. It is byte-identical with `envfile.stub_text("git")`.

### 6.7 git by path

`/usr/bin/git push` to a configured https remote no longer meets a gateway
helper. `ROUTE_TOOLS` gains `git`, so the configured-only route check
refuses it (§1.7).

---

## 7. Decision 7: SSO (authorization code + PKCE)

Requirements closed: 29 (the SSO exception), 30, 39 (ml-catalog revived).

### 7.1 How a sign-in starts

1. `gate check NAME` (or account setup) for an azure account with
   `sign_in = "browser"`, or for an ml-catalog account, that needs a token
   takes a **sign-in lease** from gated with `POST /agent/signin/start`. This
   works like the dialog lease: only a gateway entry point below a session
   that can draw dialogs gets one. **One sign-in per user at a time.**
2. gated validates the values with `form.safe` and opens a **confirm dialog**
   (owner "gated", a fixed template in the mod with dialog.ts tests). It
   shows the account name, the tenant, the client id (or the catalog host)
   and the scope, and has **Open** and **Cancel** buttons. Nothing happens
   before Open.
3. On Open, gated:
   - binds the listener (§7.3);
   - makes `state` and a PKCE verifier and challenge (S256);
   - writes `<run>/signin-active`;
   - opens the system browser (§7.2).
4. `gate check` waits with `GET /agent/signin/wait` (the lease token) for up
   to 5 minutes and prints a fixed result. The code, verifier and tokens
   never leave gated.
5. gated exchanges the code at the token endpoint through `entra.urlopen`
   (no redirects, the build's CA bundle, no proxies). It stores the refresh
   and access tokens straight into the vault under the account's `entra`
   record, removes `signin-active`, and closes the listener.

### 7.2 Opening the browser

- **macOS:** `/usr/bin/open URL`.
- **Linux:** `xdg-open` from fixed folders only (`/usr/bin`,
  `/usr/local/bin`, `/bin`). It gets `DISPLAY`, `WAYLAND_DISPLAY`,
  `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` from the UI plane's
  registration, the way the clipboard does.
- Never `$BROWSER`, never a PATH lookup (invariant 7).
- **No display** (headless, `-p`, SSH without a forward): a fixed "browser
  sign-in isn't available here (no display). Sign in from a session with a
  display, or use a service principal (azure)." The old
  `SIGNIN_UNAVAILABLE` text is replaced by this one.
- **Browser automation** can read the page while the user types a password,
  so "never a pane Claude can read" needs enforcing. While `signin-active`
  exists, a new PreToolUse matcher
  (`mcp__Claude_Browser__.*|mcp__claude-in-chrome__.*`) denies with a fixed
  reason, through an sh `[ -e ]` check. The desktop Browser pane itself is
  never used.

### 7.3 The listener

- Bind `127.0.0.1`, port 0 (ephemeral). The redirect URI is
  `http://127.0.0.1:PORT/cb`.
- Serve only `GET /cb`, with headers capped at 8 KB and a per-connection
  timeout of 10 s.
- A wrong or missing `state` gets a fixed 400 page, and the listener **keeps
  waiting**, so one bad request is not a denial of service. The first valid
  callback is accepted; then the listener closes.
- An `error` parameter gives a fixed failure page and a fixed result ("the
  sign-in was declined or failed"). `error_description` is never shown to
  Claude or in a dialog.
- A TCP connection has no peer uid. `state` and the PKCE verifier bind the
  callback instead: an exception to invariant 17's uid check, noted there.

### 7.4 Config keys

```toml
[accounts.work-azure]
kind      = "azure"
tenant    = "contoso.onmicrosoft.com"
client_id = "11111111-1111-1111-1111-111111111111"   # a public client registered for http://127.0.0.1
sign_in   = "browser"            # "browser" | "service-principal" (the default)
scope     = "https://management.azure.com/.default"  # optional; the authorization request's scope only

[accounts.models]
kind   = "ml-catalog"
host   = "catalog.example.com"
tenant = "contoso.onmicrosoft.com"   # optional; default "organizations"
```

- `sign_in` is explicit. Its default is `"service-principal"`, today's
  behaviour. It never switches by itself because a secret was stored or
  removed.
- **azure `scope`** shapes only the authorization request (`offline_access`
  is added). Token audiences per destination stay with
  `entra.scope_for_host` / `web.azure_scope`.
- **ml-catalog.** The authority is fixed (`entra.authority()` with the
  account's own `tenant`, validated; never from the catalog). The client id
  comes from the bound host's `/api/config` (validated GUID; the host must
  be approved). The scope is fixed: `api://{clientId}/access_as_user
  offline_access`, as asiml derives it today. Tenant and client id are
  **pinned in the vault** at sign-in. A later change in `/api/config`
  refuses until a new sign-in, whose confirm dialog shows the change. A
  catalog host therefore can't get a management or Graph token minted.
- **Consent:** changing `sign_in`, `tenant`, `client_id` or `scope` is a
  widening (switching to browser means acting as the user) and needs a fresh
  sign-in.

### 7.5 Refresh

Unchanged: `entra.access_token` mints from the stored refresh token under
the vault lock and persists the rotated refresh token. The browser flow only
seeds the first refresh token.

### 7.6 Testing, and an unverified assumption

- A **fake OAuth server** (`tests/harness_oauth.py`) provides an authorize
  endpoint that 302s to the registered `redirect_uri` with a canned `code`,
  and a token endpoint. It is wired through `testing.override(oauth_server=…,
  entra_authority=…)`.
- A **`browser` test knob**: gated runs the knob's program instead of `open`
  or `xdg-open`, and only under a test override. The program GETs the
  authorize URL and follows the redirect to `/cb`. There is no PATH shim.
- `test_accounts_entra` and `test_accounts_asiml` gain browser-flow cases:
  confirm then Open, Cancel, a wrong state ignored, an error parameter,
  timeout, one sign-in at a time, a pinned client id that changed, no
  display. `acceptance_native_ui` gains a `signin` step.
- Mutations: binding `0.0.0.0`; skipping the state check; following
  redirects; taking the scope or authority from `/api/config`; opening the
  browser before Open; the browser-tool deny missing.
- **Unverified:** the catalog's app registration must allow a public-client
  loopback redirect, and an SPA registration won't. The project has never
  verified Azure live. If the redirect isn't allowed, Microsoft's page shows
  the error, and `gate check` times out with a fixed message that names this
  cause.

---

## 8. Decision 8: vault passphrase offered, not forced

Requirement closed: 26 (and 25's at-rest half).

- **State lives in the vault:** `passphrase_offer` is `"pending"` or
  `"declined"`. The broker's merge keeps it. It is set to `"pending"` when a
  credential is stored and no `key.wrapped` exists.
- **When.** After a credential store (`gate_setup._store_token`, the sudo
  and ssh secret stores, the SSO store), **once the vault lock is
  released**: `set_passphrase` takes the flock, so asking while it is held
  would deadlock. The offer comes at most once per session (a gated session
  flag), while the state is `"pending"` and no `key.wrapped` exists.
- **The dialog** is a fixed template in the mod (dialog.ts, with tests): "Protect the vault with a
  passphrase? Without one, any program running as you can read the stored
  secrets." with **Set passphrase** and **Not now**.
  - **Set passphrase** opens the existing passphrase dialog (gated's SET
    path, `broker.set_passphrase`).
  - **Not now** sets `"declined"`, and the offer never comes back unasked.
    The user can still set a passphrase later through `/gate-unlock`.
  - **Cancel**, a timeout or no drawing surface leaves it `"pending"`, so it
    is offered after a later store.
- Never forced. `popup.offer_passphrase()` is the one entry point.

---

## 9. Fixes that need no decision

Requirements closed: 24, 27, 28 (in part), 33, 34, 35, 58, plus the reqcheck
defects.

### 9.1 Mask output from every tool (27)

- The `hooks.json` PostToolUse/PostToolUseFailure matcher becomes `.*`.
  `post.sh` gets an **sh skip list** for tools whose response is fixed text
  or Claude's own input: `TodoWrite`, `Task*`, `EnterPlanMode`,
  `ExitPlanMode`, plus today's Edit/Write/MultiEdit special case. A test
  keeps the list in step with the README.
- **What is covered:** WebFetch, WebSearch, Read, Glob, Grep,
  AskUserQuestion's answers, the desktop Browser pane
  (`mcp__Claude_Browser__*`), Claude in Chrome (`mcp__claude-in-chrome__*`),
  `mcp__terminal__read_terminal`, `run_in_terminal`'s own result, and every
  other MCP server.
- **Cost, stated honestly:** without a vault, Python starts only on a token
  shape or an environment-value hit (§1.6). With a vault, Python starts on
  every response not in the skip list, as it already does for the narrower
  matcher. With a wrapped key the values come from gated (brokered reads);
  otherwise age decrypts once per call. Budgets for the sh path and the
  Python path are measured on macOS and Linux and recorded in TESTING.md.
- README Limits' claim that Monitor output "warns and names the secret" is
  **corrected**: Monitor lines reach no hook, a stated limit. It changes
  together with hooks_bash's docstring.
- **Remote sudo:** the remote sudo dialog's "Remember it" starts unticked,
  as the local one does (27g). The `[hosts.NAME.policy] elevation = "ask"`
  note stays.

### 9.2 AskUserQuestion and chat history (28, the parts without a decision)

- A PreToolUse rule on `AskUserQuestion` (a new matcher, an sh case on the
  payload text) denies when the question, a header or an option contains a
  secret word: password, passphrase, token, API key, secret, private key,
  PIN, 2FA code. The fixed reason: "gateway: ask for secrets only through
  the gateway's dialog (gate check NAME, gate login NAME)." Answers are
  masked by §9.1.
- Edit and Write transcript records stay a stated limit (SPEC-v3). The
  desktop app's own store stays "unverified" in TEST-LOG.
- The stored-value paste check is **not** in 0.11.0 (§9.7).

### 9.3 Export and import (33, 34, 35)

- `transfer.plan_import` fills `p.changes["settings"]` for `[shell]`,
  `[policy]`, `[network]` and `[vault]` (`SETTINGS_TABLES` loses `settings`
  and gains `network`). Imported settings are approved in the same consent
  dialog instead of being left pending. The swallowed `ConsentChanged` is
  handled.
- The success message and the README stop pointing at
  `~/.config/gateway/gate import FILE` in the user's own terminal, where no
  dialog can open. They point at importing inside a Claude Code session
  (Claude runs `gate import`, and the dialog opens). Peer import
  (`--from-peer`) is unchanged.
- **This machine's settings** become a checklist item, **unchecked by
  default**. It carries `[hosts.localhost]`'s sudo, scripts, policy and
  workspaces, but no addresses. On import it is a keep/replace conflict
  that applies to this machine's `[hosts.localhost]`. Widenings go through
  consent, including a replace that drops localhost's sudo (§1.1). It is
  separate from today's item that turns the source machine into a named
  host (transfer.py's `is_local` handling), which is unchanged.
- The import confirm lists all of a new host's grants, imports and
  workspaces, not just its rights.

### 9.4 Checkpoint context only when live (58)

gated touches `<run>/checkpoint-seen` whenever a checkpoint client calls a
CONTRACT-v1 route. `hooks_session._howto` adds `JOBS_HOWTO` only when that
file is younger than 24 h. It no longer checks that
`~/.local/state/checkpoint` exists. If checkpoint connects later in a
session, that session lacks the line, and the next one has it. A `ckoff`
assertion goes into the e2e suite and acceptance_install.

### 9.5 Other elevation tools

- **This computer's sudo configured:** `su`, `doas`, `pkexec` and
  `osascript … with administrator privileges` are **denied** with "use sudo;
  the gateway supplies its password in its dialog". No stand-in supplies
  their password, and pkexec and osascript open system dialogs.
- **An elevation restriction only:** its deny or ask applies to them.
- **Otherwise** they get no decision (the user's own).
- They are never allowed. They join `ROUTE_TOOLS`, and the trigger words
  behind the configured check.

### 9.6 rsync daemon and gh api

`rsync://` and `host::module` are in the network class (`rsync-daemon`,
§3.1). `gh api HOST` keeps its account-host binding check.

### 9.7 Open question for the user (not in 0.11.0)

**The stored-value paste check** (reqcheck 28 asked whether about 0.1 s per
prompt is acceptable, and whether to add heuristics for unshaped passwords).
If the user says yes, it lands later with these rules:

- prompt.sh starts Python per prompt, so nothing is cached;
- the 8-character floor stays;
- a locked passphrase vault checks shapes only, read with `touch=False`;
- a UserPromptSubmit hook can block but not rewrite, so it blocks.

---

## 10. gateway.toml: the 0.11.0 shape (worked example)

```toml
# The machines and accounts Claude may use. Anything not named here uses your
# own ssh/git/gh/sudo directly. Secrets never go here; typed in the gateway dialog.

[hosts.localhost]                 # optional: only to gate this computer's sudo
sudo = { default = "ask", auto = true, plan = false }

[hosts.homelab]
address = "alex@192.168.1.20"
ssh     = true                    # auto/bypass: the gateway approves; else Claude Code decides
sudo    = "ask"

[hosts.homelab.policy]
write = { default = "ask", bypass = "deny" }

[hosts.homelab.workspaces.app]
root  = "/srv/app"
local = "~/src/app"

[accounts.gh-work]
kind   = "github"
owners = ["example-org"]

[accounts.models]
kind = "ml-catalog"
host = "catalog.example.com"      # browser sign-in (auth code + PKCE)

[network]
commands = { default = "ask", auto = "cc" }
extra    = ["dig", "ping"]

[shell]
managed = "on"                    # bash 5, your environment, stand-ins first

[vault]
lock_after = "8h"
```

A brand-new install's file is the three comment lines only: no
`[hosts.localhost]`, so local sudo is the user's own until they configure
it.

---

## 11. Invariants that change (CLAUDE.md)

Numbers are from the current CLAUDE.md. Unlisted invariants (8, 10, 16)
don't change. For each, the text to change is quoted and the replacement
given.

**1 (no secret reaches Claude).** Add: "Under the posture the user's own
environment (their agent and token variables) reaches Claude's shell: it is
the user's, not the vault's. Claude Code's own credential variables never do
(gate-sh and the env file remove them). The output masker also masks the
values (8 characters or more) of credential-named variables in Claude Code's
environment (`envfile.MASK_ENV_NAMES`)."

**2 (bound destinations).** Add: "The gated git runs with an allowlisted
environment (no proxy, CA, askpass, trace or config-injection variables), and
the gateway's helper refuses a URL with an http.proxy, sslCAInfo, sslCAPath,
sslBackend or sslVerify override."

**3 (widening needs the OK).** Replace the baseline text ("What counts as
approved when nothing is recorded is `consent.baseline(older)` … Remote hosts
still default to `true`.") with: "Nothing recorded means nothing approved,
and under the posture a target the configured set doesn't name is the user's
own. The configured set is the form, the approved snapshot and
`private/configured.json`. Taking a configured target out of the gateway is a
widening, and the approved entry keeps gating until the user's OK: deleting
or renaming its table, dropping an address, `also`, `via` or owner, adding
`when`, deleting localhost's `sudo` key, or an import replace that does so.
Values compare mode by mode (deny < ask < cc < allow < unconfigured); the
effective value is the per-mode minimum of the form and the approved value. A
missing or unparseable form falls back to the last good form, else the
configured list, whose entries are refused. With a locked vault the
configured list still classifies, and every configured entry is refused with
`consent.LOCKED_NOTE`. A disabled entry is configured and refused. A snapshot
from before 0.11 counts localhost as implicit."

**4 (native dialog only).** Replace "no browser or device-code sign-in" with:
"no device-code sign-in. The one browser exception is the authorization code
flow with PKCE for azure (`sign_in = "browser"`) and ml-catalog accounts:
gated opens the system browser by absolute path only after the user clicks
Open in the gateway's confirm dialog, the callback lands on a 127.0.0.1
listener, and the tokens go straight into the vault. It never uses the
desktop Browser pane, and browser-automation tools are denied while a sign-in
runs."

**5 (allow).** Replace the heading and first sentence with: "**`allow` only
for SPEC 8 shapes, and only where the effective per-mode word is `allow`.** A
bare `true` right is `allow` in auto and bypassPermissions, and `cc` (no
decision) in manual, plan, acceptEdits and dontAsk. Only an explicit per-mode
`allow` approves elsewhere, never in plan." Keep the shape, bare-name, reader
and never-allow lists. Add: "A network-class hit (invariant 22) makes the
whole command ineligible for allow. An unconfigured ssh host, account or
local sudo gets no decision (the user's own tool runs)." Replace the
mcp_perm.sh sentence's end with: "`http` and `download` go to Python
(`hooks_mcp`), which answers deny or ask from the effective `network` policy
for the mode, otherwise no decision, and never allow." Remove the curl/wget
special case.

**6 (direct callers; "ask" only typed).** Add: "A stand-in resolves a
per-mode value with the session mode the hook recorded in gated, for a
command Claude typed, and with the modeless rule for everything else (the
strictest over all modes but plan, allow capped at cc): jobs, terminals,
scripts and gated. There an "ask" is a refusal. The hook refuses commands
that hide their program or host while any configured entry is "ask" in the
current mode." Delete "on a new install sudo here … `gate check localhost`".

**7 (no test overrides; binaries never from PATH).** Add: "Exception: a
stand-in's pass-through finds the user's own tool on PATH, skipping every
folder with a `.gateway-standins` marker, and only for an unconfigured
target. A configured target always uses `paths.tool()`. gated opens the
system browser by absolute path (`/usr/bin/open`, or xdg-open from fixed
folders)."

**9 (fail closed).** Replace "curl/wget once a vault exists" with "the
network class (ask, or deny when gateway.toml has a `[network]` table)".

**12 (audit).** Add: "A pass-through writes one `passthrough` line (tool and
a validated host or owner name, never argv; for git only remote commands)."

**13 (stdlib; external binaries).** Replace "(Python 3.12)" with "(the lock's
Python, the newest conda-forge has; an older env with another Python minor is
never used for new code)". Replace the "system's sudo, git and sshd (and its
ssh, by path, only for `others = "mine"` …)" clause with: "for pass-through
only, the user's own tools found on PATH (§1.3 of PLAN-0.11); the gated paths
use the env's (git always the env's); the system's sudo for a configured
local sudo; the system's ssh only for 'use my own login once' and a draining
gated whose env lost its own."

**14 (managed shell).** Replace the whole text with: "**Claude's commands run
in the gateway's bash 5 with the user's own environment, and with the
stand-ins unshadowable** (docs/dev/modules/managed.md). In managed mode
(`[shell] managed = "on"`, the default) the mod sets
`CLAUDE_CODE_SHELL_PREFIX` to `hooks/gate-sh` first. gate-sh runs a hook
string exactly as Claude Code does without it (unchanged). A Bash-tool
script runs under the env's bash with the inherited environment minus, by
name (`env -u`, never a value on a command line): Claude Code's own
credential variables; `BASH_ENV`, `ENV`, `BASH_FUNC_*`, `SHELLOPTS`,
`BASHOPTS`, `PS4`, `PROMPT_COMMAND`, `CDPATH`, `IFS`, `GLOBIGNORE`,
`BASH_XTRACEFD`; and `GW_*` except `GW_MANAGED_DIR`. The lists are mirrored
in `managed.py` and compared by a test. PATH is the present stand-ins, then
the snapshot's PATH, then plugin bins, then approved imports. The gateway rc
sources a bash snapshot (a zsh snapshot gives only its PATH), then removes
every alias and function named after a present stand-in or a builtin it
relies on (in POSIX mode) and runs `hash -r`. No vault secret ever enters
the environment. A managed shell that isn't ready runs the script in the
user's shell with a one-line notice; a script with a tool script's shape
that doesn't parse (126) is refused. The approval hook denies a route around
a stand-in only when it reaches a configured target, in every mode (managed
off and mods off included): a tool by path, a login shell or PATH-resetting
wrapper, a PATH or transport change, a ProxyJump or ProxyCommand, a git
config write. It refuses commands that hide their program or host while a
configured entry is "ask" in the current mode or the text names a
configured target. Turning `managed` off and adding an import are
widenings." Keep the paragraphs on the hook passthrough's exact form, no
EXIT trap, no mandatory `| gate scrub`, host inspection, and the mod reading
only `state.json`.

**15 (guards in classic hooks).** Replace the last sentence with: "Managed
execution is a convenience (bash 5, unshadowable stand-ins). Without the mod
the env file still prepends the present stand-ins, removes Claude Code's own
credential variables and the stand-in names' aliases and functions, and the
classic Bash hook still enforces every right, policy, per-mode value, the
network class and the configured-only route check. There is no blanket
refusal."

**17 (gated's checks).** Add: "`/agent/session/mode` (the hook records,
stand-ins and the MCP server read) and `/agent/signin/start|wait` (a lease
like the dialog's: a gateway entry point below a session with a drawing
surface, one sign-in per user) follow the same plane rules. The browser
sign-in's 127.0.0.1 listener is the one TCP endpoint gated opens. It has no
peer uid, so `state` and the PKCE verifier bind the callback."

**18 (terminals).** Add: "A pane's environment keeps the user's variables
minus the managed shell's removals. A password prompt for an unconfigured
target (the user's own sudo) is answered once through the dialog and never
remembered."

**19 (remote).** "Only a host whose effective ssh right is `true`" becomes
"… whose modeless ssh right is cc or allow (today's `true`)".

**20 (policy).** Add: "Rights and the restrictions read, exec, write,
network, elevation and credential may be per-mode tables
(`{ default = …, auto = … }`, `default` required). The hook resolves them
with `permission_mode`, and the stand-ins, web.py and gated with the
session's recorded mode or the modeless rule. `scripts`, `provision`,
`env_import`, the grants and `[shell]` take one word. `[policy]` binds
configured hosts and accounts plus this computer's elevation and network
commands. It doesn't reach unconfigured hosts and accounts."

**21 (privilege rules).** Drop the sudoers-history sentence. Keep "never
changes the system's privilege rules".

**New 22 (network).** "Network commands are one configurable class
(`[network] commands`, default `"ask"`, per-mode; `extra`/`drop`, reserved
names for the structural members). It is judged by the Bash hook for Bash,
Monitor, run_in_terminal, the job tools and terminal_send: in command
position, in subshells, groups, `&`, `$()`, `exec`, literal `-c` strings,
behind sudo and wrappers (`gate with` included) and in an `ssh HOST CMD`
remote command. It uses the stricter of the class and this computer's
`network` policy. The gateway never approves a class member, and a hit makes
the whole command ineligible for allow. The known misses are listed
(network.md). curl and wget are members, not a special refusal. The http and
download tools stay under the `network` policy only. The ssh-family to
unconfigured hosts is not in the class: it is the user's own (decision 1)."

Also update **Status** (0.10.0 → 0.11.0), the **Modules** table (`migrate`
and `vault_v2` removed; `gitroute`, `modes`, `hooks_mcp` and `daemon/oauth`
added), **Commands** (`update-deps`, `--spec python`), and **Testing rules**
("Sudo defaults in tests": a new install's local sudo is unconfigured; a test
that needs it gated says `harness_sudo.setup_localhost(env, sudo=…)`;
`OLD_EMPTY` goes).

---

## 12. Module-by-module changes

### src/gateway

- **modes.py** (new): mode normalization, `ModeValue`, the expansion table,
  the per-mode order, the modeless rule, and the recorded-mode client
  (`current_for(caller)`).
- **gitroute.py** (new): the shared git resolver (§6.2).
- **hooks_mcp.py** (new): the http and download decision (§2.10).
- **form.py**:
  - parse a per-mode table into new attributes, with legacy attributes
    holding the modeless resolution (§2.6) and `toml_value` for
    `ModeValue`;
  - `[network]` (`NETWORK_KEYS = ("commands", "extra", "drop")`), and
    azure's `sign_in`/`scope`;
  - ml-catalog's `tenant`;
  - `STARTER`;
  - the implicit localhost **kept**, with `sudo_configured`;
  - delete `SETTINGS_KEYS`/`Settings`, `LOCALHOST_SUDO_OLDER`, the older
    branch, `apply_install_defaults(older)`, and "warn".
- **consent.py**:
  - `compute(form, data, mode)`, `Effective.word`, and explicit `RANK`
    (raises on unknown values);
  - the per-mode compare and per-mode minimum;
  - the configured set and `private/configured.json`;
  - removal as a widening;
  - the `[network]` compare;
  - `SHELL_RANK` on/off, `LOCKED_NOTE`;
  - snapshots record localhost's written sudo;
  - delete the baseline, `older_install` and the others compare.
- **policy.py**: `decide(eff, action, mode=None)` (None means modeless);
  `Decision.mode`. It doesn't read `[network]`.
- **hooks_bash.py**:
  - mode threading through `Effective.word`;
  - `_network_hits` and `_network_text`;
  - the configured-only `_alternate_route`/`_route_text` (in every mode),
    with login shells, PATH-resetting wrappers, ProxyJump and git config
    writes;
  - the hidden-form rule per mode, and `_fallback_ask` per mode;
  - git's up-front judging (through `gitroute`), and `gate with` unwrapping;
  - su/doas/pkexec/osascript (§9.5);
  - recording the session mode;
  - remove `_deny_curl`, the curl/wget branch, `MANAGED_DENY`, the
    managed=off early return and the escape texts.
- **ssh.py / ssh_args.py**: a lenient destination parse; `ssh -G` with hops,
  ProxyCommand and IP; gated path, refusal with a hint, or pass-through
  (§1.4); scp/sftp operands; the owner from git-over-ssh endpoints; the
  recorded mode for typed callers; delete `others`.
- **sudo.py**: present only when configured. With a restriction only:
  restriction, then pass-through. Otherwise today's gated path with per-mode
  values. Remove the `older_install` messages.
- **clis.py**: pass-through with each tool's destination resolution (§1.4)
  and the undeterminable-owner rule; `user_tool`; the git stand-in entry
  point (with WS-4's `gitroute`).
- **asiml.py**: dvc pass-through outside `.asiml` workspaces; the ml-catalog
  browser sign-in with a fixed authority and scope and a pinned client id.
- **envfile.py**:
  - the stand-in presence (`standins_for(configured)`) and the
    `.gateway-standins` marker;
  - `user_tool` (was `system_git`);
  - `env_text`: the PATH prepend, the Claude Code credential unset, the
    unalias block; the git include, `GIT_SSH_COMMAND`, `RSYNC_RSH` and the
    `ENV_UNSET` unset removed;
  - `MASK_ENV_NAMES`;
  - `degraded_bash_text("network")`; delete `"managed"`;
  - the cold-start stub rule; `older_env_python` with the minor check;
    delete `git_stub_text`.
- **githelper.py**: the include injected at command scope into the gated
  child; `$DATA/git/global` (0444, init defaults); the proxy and CA refusals.
- **managed.py / hooks/gate-sh**: the removal lists (§1.6) mirrored; PATH
  from the snapshot; bash-snapshot sourcing; the rc's unshadowing tail;
  the not-ready fallback; `found_not_imported`/`IMPORT_OFFER` stay.
- **hooks_session.py**: `INTRO`/`HOWTO`/`MANAGED_HOWTO`; `JOBS_HOWTO`
  liveness; the first-0.11 notice; `form.STARTER`; remove the migrate calls
  and the others note.
- **hooks_post.py**: mask the environment credential values; take the vault
  values from gated when the key is wrapped.
- **web.py**: `_network_ok` per recorded mode or modeless; "ask" passes
  (§2.10). No `[network]`.
- **transfer.py**: `FORMATS = (3,)`; `plan_import` fills settings;
  `SETTINGS_TABLES`; the localhost checklist item; the message wording.
- **daemon/oauth.py** (new), **daemon/server.py**, **planes.py**,
  **dialogs.py**, **lifecycle.py**:
  - the sign-in lease, listener and browser opening;
  - `/agent/session/mode`;
  - `checkpoint-seen`;
  - the CONTRACT-v1 rights mapping (§2.11).
- **entra.py / gate_setup.py**: the browser entry; the `signin_unavailable`
  dead ends reworked (WS-5).
- **vault.py**: the 0.6 detector; `passphrase_offer`; the
  posture-notice-shown flag; delete `BASELINE*`, `older_install` and
  `"nopasswd"`.
- **ancestry.py / daemon/peers.py**: delete `is_claude_node` and
  `claude_ancestor`.
- **popup.py**: `offer_passphrase()`; the fixed headless sign-in message.
- **gate.py / manage.py**: drop `gate migrate`; take over `_sanitize` and
  `_fmt_addr`; `MODE=WORD` edits; `gate network`.
- **ssh_sudo.py**: "Remember it" starts unticked.
- **paths.py**: keep `v2_*` in the file guard's list; add
  `configured_path()`, `network_words_path()` and `git_global_path()`.

### hooks / mod

- **pre_bash.sh**: trigger words (§3.4); the `network-words` file; drop
  `GW_MANAGED_CHECK`.
- **mcp_perm.sh**: hand `http`/`download` to `launch.sh hook-mcp`; still no
  allow from sh.
- **post.sh**: the skip list; the environment-value check with builtins.
- **A new sh hook (`hooks/tool_guard.sh`)**: the browser-tool deny during a
  sign-in (§7.2), and the AskUserQuestion secret-word deny (§9.2).
- **launch.sh**: cold stubs by the configured rule; degraded network text;
  the git stub's cold pass-through; `pixi_too_old`; the Python minor check;
  remove `degraded_bash("managed")` and the `vault_v2`/`store.age` status
  logic; `hook-mcp`.
- **hooks.json**: PostToolUse/PostToolUseFailure `.*`; PreToolUse matchers
  for the browser tools and AskUserQuestion; `hook-mcp`.
- **mod/lib.ts, register.tsx, manage.ts, dialog.ts**:
  - `editArgv` `MODE=WORD`, and per-mode rendering;
  - `managedPlan` no longer implies a refusal; "warn" removed;
  - remove `MODS_MIN_*` and the pre-0.9.1 defaults;
  - the tested pixi and Claude Code strings;
  - the sign-in confirm and passphrase-offer templates;
  - tests for each.

---

## 13. Tests and mutations

Every behaviour change gets a test, and every security property gets a
mutation that makes a named test fail (CLAUDE.md "Testing rules"). Each
workstream adds its mutations in **its own new file**, to avoid conflicts:
`mutations_posture.py` (WS-1), `mutations_modes.py` (WS-A1/WS-2),
`mutations_network.py` (WS-3), `mutations_git.py` (WS-4),
`mutations_sso.py` (WS-5), `mutations_offer.py` (WS-6).

- **Real tools stay out of the tests.**
  - Pass-through tests use the `user_tools` knob (recording fakes) and
    `.invalid` host names. `ssh -G` runs the fake ssh with an `-F` test
    config, never `~/.ssh/config`.
  - sudo runs only as `sudo -n true`, else fake_sudo, including its no-tty
    mode.
  - `SSH_AUTH_SOCK` and `GH_TOKEN` carry fake values.
  - The e2e `refuse` scenario, `acceptance_managed`'s "unconfigured runs the
    user's ssh" and `acceptance_install`'s "local sudo passes through" use
    the fakes and the e2e marker.
- **Configured set and removal (WS-A1, WS-1):**
  - deleting a host, dropping an address, adding `when`, deleting
    localhost's sudo key, or an import replace each keeps gating until the
    OK;
  - a corrupted or missing gateway.toml refuses configured entries;
  - a locked vault refuses through the configured list;
  - a disabled entry is refused in every stand-in.
  - Mutations: removal ranked as a narrowing; a broken form passing through;
    the configured list ignored.
- **Posture (WS-1):**
  - stand-in presence per configured set, and the cold-window stub rule
    (byte-identical);
  - `user_tool` skips marker folders; the recursion guard; exit 127;
  - the audit line holds no argv;
  - each §1.4 tool: lenient parse, `-G` hits, hop and ProxyCommand hits
    refused with the hint, mixed scp, git-over-ssh owner;
  - the account CLIs' destination resolution and undeterminable owners;
  - dvc;
  - sudo with a restriction only.
  - Mutations: a configured host passing through; a `-G`/hop hit routed or
    passed; the recursion guard off; an undeterminable owner passed through.
- **Managed shell (WS-1):**
  - each removed name (`BASH_ENV`, `ENV`, `BASH_FUNC_ssh%%`, Claude Code's
    credentials, `GW_*`) and `GW_MANAGED_DIR` kept;
  - hostile aliases and functions don't shadow a stand-in;
  - bash and zsh snapshots;
  - the not-ready fallback runs the script with the notice, and 126 is still
    refused;
  - "warn" rejected;
  - `test_no_value_reaches_a_command_line` extended;
  - the mods-off env file's unalias and credential unset in sh, dash, bash
    and zsh under `set -eu`.
  - Mutations: a removal dropped; the rc's unshadowing tail skipped.
- **Per-mode (WS-A1, WS-2):**
  - new `test_modes.py`: the normalization table, the expansion table
    (dontAsk gives cc), "default required", a table's `true` meaning allow,
    plan degrading to cc, the modeless rule, an unknown mode gives default;
  - consent per mode (a rise in any mode is a widening, the per-mode
    minimum, ask → cc is a widening);
  - the hook's decision per mode for each word, across all six modes;
  - the recorded mode: a stand-in for a typed caller uses it, others are
    modeless, gated absent is modeless;
  - `job_start` and `terminal_send` with their payload modes;
  - `hooks_mcp`/web.py per mode, with "ask" passing;
  - manage.test.ts edit shapes; CONTRACT-v1 mapping.
  - Mutations: §2.6's list.
- **Network (WS-3):**
  - new `test_network.py`: the built-ins and structural members (and benign
    rows: `openssl rand`, `brew install nmap`, `man curl`, `grep curl
    file`);
  - `extra`/`drop` and reserved names, and the consent direction;
  - every scan position (`(curl)`, `curl &`, `{ curl; }`, `$(curl)`,
    `bash -c 'curl'`, `exec curl`, `find -exec curl`, `xargs curl`,
    `sudo nmap`, `gate with A -- curl`, `ssh HOST curl`);
  - per mode; whole-command allow ineligibility;
  - the stricter of class and policy, with the key named;
  - run_in_terminal and job payloads;
  - the cold guard byte-identical; the three word lists equal.
  - Mutations: one per scan branch; the class judged after the allow step;
    web.py reading `[network]`.
- **git (WS-4):**
  - new `test_git_standin.py`: per-repository routing (commit and status
    in a configured repository are gated);
  - aliases, `!` aliases, `insteadOf`/`pushInsteadOf`, `pushurl`, multiple
    `url`s, `pushRemote`/`pushDefault`, submodules, `lfs.url`, `-c
    remote.x.url=`, `-C`/`--git-dir`/`GIT_DIR`;
  - GHES via an account's `host`; `config --global` passing through;
  - the gated environment allowlist (one case per name in §6.3);
  - command-scope precedence over a repository `credential.helper`,
    `insteadOf` and `user.email`;
  - global 0444 and init defaults; the user's git reads a gated clone;
  - the helper's proxy and CA refusals;
  - `/usr/bin/git` refused to a configured remote;
  - up-front push judging; git config writes refused;
  - the cold git stub; the cost budget.
  - Mutations: a repository-level helper winning; an inherited variable
    reaching the gated git; an alias skipping classification; a configured
    push skipping the hook.
- **SSO (WS-5):** §7.6.
- **Passphrase offer (WS-6):**
  - offered after a store, after the lock is released, once per session;
  - "Not now" persists; cancel stays pending; skipped once wrapped;
  - headless skips it.
- **Deletions (WS-0):**
  - remove `test_migrate.py`;
  - `test_release`/`test_packaging` assert that `migrate.py` and
    `vault_v2.py` are gone and that none of these exact tokens remain:
    `others =`, `older_install`, `BASELINE_KEY`, `LOCALHOST_SUDO_OLDER`,
    `map_export_v1`, `is_claude_node`, `claude_ancestor`;
  - `test_transfer_*`: formats 1 and 2 refused as unsupported;
  - the 0.6 detector refuses to create a vault next to `store.age`.
- **Export/import (WS-6):** imported settings approved in the one dialog;
  the localhost item (unchecked by default, keep/replace, a dropped sudo is
  a widening); the message points at Claude Code.
- **Masking (WS-6):** the `.*` matcher with the skip list; a WebFetch,
  Browser-pane payload (a recorded payload; the pane exists only in the
  desktop app), read_terminal or run_in_terminal result masked; an
  environment value masked; the budgets.
- **Python fallback window (WS-R):** an older env with another Python minor
  is refused, and the cold paths apply.
- **Packaging (WS-R):** `pixi-pack == pixi-unpack`; requires-pixi equals
  `PIXI_TESTED`; the age prompt regex; pijul's version.
- **Re-baselining:**
  - `test_hookbash_table` covers **all six modes**. The posture flips its
    route rows and the `bash -c "$CMD"` rows; WS-2 re-baselines it, and each
    workstream adds rows in its own section.
  - The e2e `web`, `refuse` and `jobs` scenarios flip: curl is no longer
    denied, and the curljob runs.
- **Mutation audit:** about 115 entries are anchored on removed code
  (`mutations_sudo` 56, `mutation_check` 12, `mutations_policy` 12,
  `mutations_accounts` 10, ...). `mutation_check.py` fails on a missing
  anchor, so WS-0 and WS-1 re-anchor or retire each one in their own files.
  This is budgeted as its own task in each workstream.
- **No-mention tests** name exact tokens (the list above), never the plain
  word "others".

---

## 14. TUI acceptance changes

- **acceptance_managed.py**:
  - the user's `SSH_AUTH_SOCK` and `GH_TOKEN` (fake values) survive into
    Claude's shell, and Claude Code's credential variables don't;
  - present stand-ins are first, and an alias named `ssh` in the snapshot
    doesn't shadow it;
  - a by-path ssh to a configured host is refused, while an unconfigured one
    runs the fake user ssh;
  - the snapshot's shell is recorded;
  - `nomods` now expects normal judging plus the notice, not a refusal;
  - not-ready runs in the user's shell.
- **acceptance_terminals.py**: a pane's environment keeps the user's
  variables; a configured sudo prompts through the dialog; an unconfigured
  one is answered once with no "Remember it".
- **acceptance_native_ui.py**:
  - a `signin` step: confirm then Open, the `browser` knob, the token
    stored, nothing opened outside the knob, the browser tools denied during
    the sign-in;
  - a `passphrase` step;
  - `scan` still finds no secret anywhere.
- **acceptance_install.py**:
  - a fresh `gateway.toml` has no `[hosts.localhost]`, and no stand-ins
    shadow anything;
  - local sudo passes through (fake);
  - the cold window's network class asks;
  - an old pixi in `prereq` gives the "pixi self-update" path;
  - the first-0.11 notice;
  - a `ckoff` assertion.
- **acceptance_canaries.py**: a canary through WebFetch is masked (needs a
  reachable https URL the harness serves). The Browser pane is desktop-only
  and stays unverified live; it is unit-tested with a recorded payload.
- **The relock** changes tmux, bash, pixi-unpack and openssh, so
  **acceptance_remote** (the VM) and **acceptance_terminals** run again.
- **Platform matrix**, as for 0.10.0: macOS arm64, x86_64 through Rosetta,
  and Linux.
- **e2e**: one probe per `--permission-mode` that records the payload string
  (§2.1).

---

## 15. Docs to update

- **README.md**:
  - "What changes when you install it": the posture, the stand-ins only
    where configured, the user's own credentials in Claude's shell and what
    that means for configured hosts (§1.10), and local sudo needing no
    password unless configured;
  - the network class and the bypass one-liner;
  - per-mode values;
  - delete Upgrading and Rolling back (one line: latest only, see
    CHANGELOG);
  - Requirements: latest Claude Code, pixi and Python;
  - Limits: the corrected Monitor line, the browser sign-in exception, the
    network class's misses, `-G` timeouts, and snapshot-only exports not
    masked.
- **SECURITY.md**: the posture and §1.10.
- **docs/CONFIG.md**:
  - `[hosts.localhost]` optional, and sudo ungated when absent;
  - the per-mode grammar, words, required `default` and keys;
  - `[network]`, azure's `sign_in`/`scope`, ml-catalog's `tenant`;
  - `[settings]` and "warn" removed;
  - export carries localhost (opt-in);
  - the precedence of `[network] commands` and `[policy] network`.
- **docs/dev/modules/**:
  - `managed.md`: the new environment, unshadowing, not-ready, the
    configured-only routes, the hidden-form rule;
  - `sudo.md`: presence, restriction-only, no tty;
  - `ssh.md`: lenient parse, `-G`, hops, pass-through;
  - `policy.md`: per mode, the modeless rule, the recorded mode;
  - `accounts.md`: the destination resolution, the git stand-in, browser
    sign-in;
  - new `network.md`;
  - `daemon.md`: oauth, `/agent/session/mode`, `checkpoint-seen`.
- **docs/dev/SPEC-v3.md**: section 8 (network class, per mode, posture),
  section 9 (stand-ins, pass-through, git), section 16 (formats, the
  localhost item).
- **CHANGELOG.md**: a 0.11.0 entry. Its release notes say:
  - a live 0.6 install converts with the published 0.10.0 first (the
    tag-pinned recipe);
  - after 0.10 → 0.11, an implicit localhost sudo becomes ungated, and a
    stored local sudo password stays unused (add `[hosts.localhost] sudo`,
    or `gate forget localhost`).
- **CLAUDE.md**: §11's rewrites, Modules, Status, Commands, Testing rules.

---

## 16. Risks and known limits

- **A weaker guardrail by design.** Claude uses the user's own ssh, sudo,
  git and tokens for everything unconfigured. Worse, any route around a
  stand-in (a script, a Makefile, an unparseable string) can reach a
  **configured** host with the user's own key or token, so a host's limits
  bind only if the user's own credentials don't also open it (§1.10). The
  README and SECURITY say so.
- **Configured-target resolution** is the new correctness risk. These are
  stated limits:
  - IP spellings and DNS aliases fail open when `-G` or `getaddrinfo` times
    out;
  - a configured host reached by path inside a string the hook can't parse
    is missed unless an "ask" entry or the configured name in the text
    triggers the hidden-form rule;
  - a locked vault plus deleting both the form entry and
    `private/configured.json` un-gates until unlock, which is guardrail
    level.

  The probe tables stay large.
- **The network text scan** shares `_route_text`'s class of misses (§3.5).
  It is a guardrail, not a sandbox.
- **Per-mode consent** must rank a rise in any mode as a widening; that is
  covered by mutations. The recorded mode is a guardrail (a process running
  as the user could post a false one).
- **The user's environment in the managed shell**: corporate proxies and CA
  overrides reach Claude's own commands. The configured stand-ins'
  children, the gated git included (§6.3), drop them. A test covers each.
- **Masking the user's own values** covers names in Claude Code's
  environment, not values only the snapshot exports.
- **git cost**: Python on every git call where the stub exists (budget
  §6.6).
- **Browser sign-in**: unverified against the real catalog's app
  registration (§7.6), and impossible without a display (fixed message).
- **Latest pins**: Python 3.15 is relocked first (WS-R) and the suite runs
  on it before any feature work. bash 6 or git 3 at a later relock are
  covered by tests (`init` defaults pinned).
- **Local sudo out of the box** works only where it needs no password; this
  is the user's decision 1, and it is documented.

---

## 17. Implementation order and workstreams

Each workstream lists the files it **owns**. Where a file is shared, the
owner is named and the others make small, named edits in the merge order
below. A byte-identical pair (`envfile.py` and `launch.sh`, and its test) is
always changed in one commit by the workstream that owns the change.

**WS-R: Relock and version plumbing. Lands first, alone.**
Owns:
- both `pixi.toml` files and their locks;
- `tests/update_deps.py` and the `update-deps` task;
- `test_packaging`'s pin checks;
- `lib.ts` `PIXI_TESTED` and the tested Claude Code string, and the doctor
  verdict;
- `envfile.older_env_python`, and `launch.sh`'s env-build, `pixi_too_old`
  and Python minor parts (with their byte-identical tests);
- tests/tui and the acceptance headers' `--spec python` (with the lead, in
  both repos);
- the agepass prompt test.

It runs the full suite and mutations on 3.15 with **today's code**, so
interpreter drift shows up before feature work.

**WS-0: Deletions.**
Owns:
- `migrate.py`, `vault_v2.py`, `test_migrate.py` (delete), after moving
  `starter` to `form.STARTER` and `_sanitize`/`_fmt_addr` to `gate.py`;
- `vault.py` (baseline, `older_install`, `"nopasswd"`, the 0.6 detector);
- `ancestry.py` and `daemon/peers.py`;
- `transfer.py`'s format code;
- `gate.py` (the migrate command, import-ssh helpers);
- `hooks_prompt.py`'s migrate report;
- `hooks_session.py`'s migrate calls only;
- `lib.ts` (pre-0.9.1, `MODS_MIN_*`);
- the README's recipe and floor wording;
- `launch.sh`'s `vault_v2`/`store.age` status logic;
- re-anchoring the mutation entries for removed code in `mutation_check.py`,
  `mutations_sudo.py`, `mutations_policy.py` and `mutations_accounts.py`.

Not `others` (WS-1), not `signin_unavailable` (WS-5).

**WS-A1: Semantic core (form, consent, policy).** After WS-0.
Owns:
- `form.py`: `ModeValue` attributes, `[network]`, `sign_in`/`scope`/`tenant`
  parsing, the implicit localhost's `sudo_configured`, "warn" removed;
- `consent.py`: `compute(mode)`, `Effective.word`, RANK, per-mode
  compare/minimum, the configured set, `private/configured.json`, removal
  widenings, the `[network]` compare, `SHELL_RANK`, `LOCKED_NOTE`, the
  localhost-written record;
- `policy.py`: `decide(mode)`;
- `modes.py` (new);
- `paths.py`'s new paths;
- the audit of `"localhost"` call sites (findings handed to each owner);
- `test_consent`, `test_form`, `test_modes` (core), `mutations_modes.py`
  (core).

**WS-A2: Shared plumbing.** In parallel with WS-A1.
Owns:
- `gitroute.py` (new) and its tests;
- `daemon/server.py` and `planes.py`: `/agent/session/mode`, plus the
  sign-in route stubs that WS-5 fills;
- `modes.current_for`, the client side (it coordinates with WS-A1 on
  `modes.py`; WS-A2 adds only the client function).

**WS-2: Per-mode in the hook, the MCP tools and the UI.** After WS-A1 and
WS-A2.
Owns:
- `hooks_bash.py`'s mode threading: `_right`, `_eff_right`, `_policy_hits`,
  the allow step, `_fallback_ask`, mode recording, the job and terminal
  payload modes;
- `hooks_mcp.py` (new), `mcp_perm.sh`'s hand-off, `web.py`;
- `manage.py` and `gate.py`'s `MODE=WORD` edits and `gate network`;
- `mod/manage.ts` and its tests;
- the consent dialog texts (§2.8) in `consent.py`'s text functions (a named
  edit in WS-A1's file);
- `lifecycle.py`'s CONTRACT-v1 mapping;
- the `test_hookbash_table` re-baseline over six modes;
- `test_ux_mcp`; `mutations_modes.py` (hook part).

**WS-1: Posture.** After WS-2, whose `hooks_bash.py` signatures land first.
Owns:
- `ssh.py`, `ssh_args.py`, `sudo.py`, `clis.py` (pass-through, destination
  resolution), `asiml.py`'s dvc part;
- `envfile.py`: presence, marker, `user_tool`, `env_text`,
  `MASK_ENV_NAMES`, degraded stubs; with `launch.sh`'s matching parts:
  `pre_session` stubs, `degraded_bash("managed")` removed;
- `managed.py`, `hooks/gate-sh`;
- `hooks_session.py` (`INTRO`/`HOWTO`, the first-0.11 notice, `JOBS_HOWTO`
  liveness via `checkpoint-seen`);
- `hooks_bash.py`'s `_alternate_route`, `_route_text`, the hidden-form rule,
  `_managed_gate`, su/doas/pkexec;
- `pre_bash.sh`'s `GW_MANAGED_CHECK` removal;
- `mod/register.tsx` and `lib.ts`'s `managedPlan`;
- `[settings]` removal;
- `test_ssh_route`, `test_sudo_standin`, `test_accounts_clis`,
  `test_envfile`, `test_managed`, `test_session`, `mutations_posture.py`,
  and re-anchoring `mutations_sudo.py`, `mutations_managed.py` and
  `mutations_ssh.py`.

The stand-ins' calls to `modes.current_for` (WS-2's helper) are written
here.

**WS-3: Network class.** After WS-1.
Owns:
- `hooks_bash.py`'s `_network_hits`, `_network_text` and `gate with`
  unwrapping;
- `pre_bash.sh`'s trigger words and the `network-words` reader;
- `launch.sh` and `envfile.py`'s degraded network text (one commit, with the
  byte-identical test);
- the `network-words` writer (in `consent.py`'s form-load hook, a named
  edit);
- `docs/dev/modules/network.md`, `test_network.py`, `mutations_network.py`.

**WS-4: git.** After WS-1, in parallel with WS-3.
Owns:
- the git stand-in body (`clis._git`), `githelper.py`, `$DATA/git/global`;
- `envfile.py` and `launch.sh`'s git stub and cold pass-through (one
  commit), and the removal of the git include and `GIT_SSH_COMMAND`;
- `hooks_bash.py`'s git up-front judge and git config write refusals;
- `test_git_standin.py`, `test_git_helper`, `mutations_git.py`, and the git
  perf test.

**WS-5: SSO.** After WS-0 and WS-A2. It can run alongside WS-2, WS-1 and
WS-3.
Owns:
- `daemon/oauth.py` (new); `daemon/dialogs.py` and `lifecycle.py`'s sign-in
  handlers; the sign-in routes in `server.py` (filling WS-A2's stubs);
- `entra.py`, `asiml.py`'s sign-in, `gate_setup.py`'s browser entry, and
  the `signin_unavailable` rework in `popup.py`;
- `hooks/tool_guard.sh`'s browser-tool part; the `hooks.json` PreToolUse
  matcher (a named edit, merged before WS-6's `hooks.json` change);
- `mod/dialog.ts`'s confirm template;
- `harness_oauth.py`, `test_accounts_entra`/`asiml`, `mutations_sso.py`;
- `acceptance_native_ui`'s `signin` step.

**WS-6: Passphrase offer, masking, export/import and the remaining fixes.**
After WS-1 and WS-5.
Owns:
- `popup.offer_passphrase`, `vault.py`'s `passphrase_offer` and
  posture-notice fields (named edits after WS-0), the offer calls (one line
  each in `gate_setup.py`, `sudo.py`, `ssh.py`, after WS-5 and WS-1);
- `mod/dialog.ts`'s offer template;
- `hooks.json`'s PostToolUse `.*` and AskUserQuestion matcher, `post.sh`,
  `hooks/tool_guard.sh`'s AskUserQuestion part, `hooks_post.py`;
- `transfer.py` (settings changes, the localhost item, messages,
  `SETTINGS_TABLES`), after WS-0;
- `ssh_sudo.py`'s "Remember it" default; gated's `checkpoint-seen` writer;
- `test_portability`, `test_scrub_stream`, `test_ux_hooks`' matcher cases,
  `mutations_offer.py`.

**WS-7: Docs, acceptance and release.** Last.
Owns:
- the doc sweep (§15, §11);
- the CHANGELOG release notes;
- the e2e scenario flips and per-mode probes;
- the TUI acceptance updates and runs (managed, terminals, native_ui,
  install, canaries, remote on the VM) on the platform matrix;
- the final mutation run;
- TESTING.md and TEST-LOG.md.

**Merge order:** WS-R → WS-0 → (WS-A1 ∥ WS-A2) → WS-2 → (WS-1 ∥ WS-5) →
(WS-3 ∥ WS-4) → WS-6 → WS-7.

`hooks_bash.py` is partitioned by function:

| workstream | functions |
|---|---|
| WS-2 | mode threading and the allow step |
| WS-1 | routes and the managed gate |
| WS-3 | network |
| WS-4 | git |

They merge in that order, and each rebases on the previous. The shared test
files have one owner each: `test_hookbash_table` is WS-2's (others append
rows in their own sections), `test_session`, `test_managed` and
`test_envfile` are WS-1's, `test_consent` is WS-A1's, and `mutation_check.py`
is WS-0's. New properties go into each workstream's own mutation file.

---

## 18. Review changes

**Accepted** (the review that raised each is in brackets):

- **"Configured" redefined, and removal made a widening.** Configured is now
  the form, the approved snapshot and the configured list, with disabled
  entries refused and a broken or missing form never passing through
  [security 1, implementation C5]. The implicit localhost is kept internally
  with a "not configured" marker [C5].
- **Managed shell, environment.** It now removes Claude Code's credentials
  and the startup vectors (`BASH_ENV`, `ENV`, `BASH_FUNC_*`, ...), keeps
  `GW_MANAGED_DIR`, and ends the rc with the unshadowing tail [security 2,
  semantics 1, C8].
- **Managed shell, PATH and aliases.** PATH comes from the snapshot,
  aliases from a bash snapshot, and the zsh limit is stated [C9]. The mods-off
  env file unaliases the stand-in names [C10].
- **Route checks.** Login shells and PATH-resetting wrappers are treated as
  by-path [security 2]. Route checks run in every mode [low].
- **The user's credentials.** Their exposure is stated in §1.10, §16, the
  README and SECURITY, and environment values are masked [security 3,
  semantics 10].
- **git, gated path.** The include stays at command scope, the environment
  is allowlisted, the helper refuses proxy and CA overrides, the global
  config is read-only with pinned init defaults, and `GIT_SSH_COMMAND` and
  `RSYNC_RSH` left the shell [security 4, C6, C7, H3, H7].
- **git, classification.** It is per repository: aliases, effective URLs,
  GHES through accounts' hosts, git by path, one shared resolver reading
  config only, and the cost bounded [security 5, semantics 6, H5, H6, H8].
- **ssh.** A lenient parse with `ssh -G`, hops and ProxyCommand; alias and IP
  hits are refused with a hint; mixed scp is refused; the recursion guard
  and marker-based lookup; one lookup rule for every tool [security 6, H1,
  H2, H3, H4, semantics minor].
- **Hidden forms** are still refused when an entry is "ask" in the mode or a
  configured target is named. The PATH and transport refusals are kept for
  configured targets [security 7].
- **Modes at the stand-ins.** The recorded session mode serves typed
  commands and the modeless rule everything else [security 8, C1]. The
  per-mode keys are listed and `default` is required [security 8, H10].
  Fail-safe legacy attributes and a RANK that raises [C2].
- **One order in every mode**, deny < ask < cc < allow < unconfigured
  [security 9, semantics 3, C3]. dontAsk gives cc [security 10, C4].
  Unknown modes resolve to default [security 9].
- **Network class.** It stays out of web.py and `policy.decide` [security
  11, C13]. A hit makes the whole command ineligible for allow, `allow`
  means cc, and `gate with` is unwrapped [security 12, H10].
- **Restrictions.** Elevation and network restrictions on this computer keep
  applying; global keys are documented and flagged [security 13, H13].
- **SSO.** The confirm dialog is a gate, the browser is opened by absolute
  path, the ml-catalog authority and scope are fixed with the client id
  pinned, `scope` shapes only the request, sign-in key changes are
  widenings, the listener is hardened, browser tools are denied during a
  sign-in, and a fixed headless message stays [security 14, S1-S4].
- **MCP tools.** http and download get a Python decision, never allow, and
  git-push was dropped from the MCP sentence [M1, semantics 2, H9].
- **`[network]` consent direction** fixed, and the ssh-family wording
  corrected [M2].
- **Network coverage.** The list is extended (httpie included), the misses
  are listed, run_in_terminal is judged, `ssh HOST CMD` uses the class plus
  the host's policy, and the cold window asks [M3, H12]. openssl is now a
  structural member only [semantics 4].
- **Invariants** 1, 2, 4, 6, 7, 9, 12, 13, 17, 18 and 19 were added to §11,
  and 3's locked-vault text corrected [M4].
- **Masking.** The matcher covers every tool with an sh skip list, the cost
  claim is corrected, and the tool names are right [M6, H19].
- **Other elevation tools** are denied when local sudo is configured, never
  allowed [M7].
- **Account CLIs** resolve the destination as each tool does, with the
  undeterminable-owner rule, and dvc passes through [M8, H4].
- **Dialog wording** is plain and per mode [M9]. Edit syntax and pane
  rendering are specified [semantics 9b, H11]. The CONTRACT-v1 mapping is
  specified [H11].
- **"warn" removed** [low, semantics 8].
- **Passphrase offer** state lives in the vault, comes after the lock is
  released, and its template is in the mod [low, H17].
- **Pass-through audit** logs no argv [low]. The release notes cover 0.10 →
  0.11 local sudo [low].
- **Honest local-sudo messaging** in context, README and CONFIG [semantics
  5, H14]. The mode normalization table is grounded in evidence [semantics
  7]. The network precedence is documented [semantics 9a]. The bypass
  friction one-liner is given [semantics 10].
- **0.6 install safety.** The 0.6 detector is kept and the recipe moves to
  the release notes [C11]. migrate's live helpers move first [C12].
- **pixi and Python.** An old pixi is detected and explained [C14]. An older
  env with another Python minor is refused [C15].
- **Exports and checkpoint.** Export of localhost and its relation to
  today's import [H15]. A real checkpoint liveness signal [H16].
- **Tests:** real tools kept out, e2e flips, six-mode re-baselining, the
  mutation audit, acceptance gaps, missing tests [T1-T6].
- **Pins:** the TUI Python spec, pixi-unpack equal to pixi-pack, pijul, the
  age prompt test, the `bash = "*"` wording, update-deps as a script with
  the relock first, the doctor verdict [P1-P7].
- **Workstreams restructured:** a relock workstream first; `others` moved to
  WS-1 and `signin_unavailable` to WS-5; new foundation workstreams (WS-A1,
  WS-A2) so dependencies run forward; per-workstream mutation files; an
  owner for every shared and test file; the unassigned items placed
  [W1-W6].

**Rejected or changed:**

- **Ranking cc with ask where Claude Code prompts anyway** [semantics 3's
  nuance]: rejected. Claude Code's own allow rules can make cc wider than ask
  in any mode, so one order applies everywhere.
- **Re-seeding `[hosts.localhost] sudo = "ask"` in the starter** [semantics
  5's option]: rejected. Decision 1 says the starter no longer does.
  Messaging was added instead.
- **Dropping `dontAsk`** [semantics 7]: rejected. Claude Code 2.1.301 lists
  it among `--permission-mode`'s choices. It is kept, with a normalization
  table (`manual` too) and an e2e probe of the real payload strings.
- **Putting only identities in `GIT_CONFIG_GLOBAL`** [security 4,
  implementation C6]: changed. The whole include, identities too, stays at
  command scope as today, so a repository's `user.email` can't replace the
  account identity. The global file is the gateway's read-only base.
- **Removing exported functions named after stand-ins only** [security 2]:
  went further. All `BASH_FUNC_*` are removed, since functions come from the
  snapshot, and the rc removes stand-in-named functions in POSIX mode.
- **Global `[policy]` read/exec/write/credential denies reaching
  unconfigured hosts** [security 13, H13]: rejected. The hook can't judge
  them for a host it knows nothing about, and refusing all unconfigured ssh
  would undo decision 1. They are documented and flagged instead.
- **Keeping `src/` importable on the previous lock's Python** [C15's first
  option]: rejected in favour of refusing an older env with another Python
  minor, which fits latest-only.
- **Keeping the pixi floor lower** [C14, implied]: rejected. Decision 5 sets
  it to the newest pixi. Detection and messages were added, and gate-sh no
  longer refuses when not ready.
- **The stored-value paste check** [H18]: taken out of 0.11.0. The reqcheck
  (item 28) left its cost as the user's decision, which isn't among the
  eight, so it is listed as an open question (§9.7). The AskUserQuestion
  rule, which needs no decision, stays.
- **Masking all of the user's environment values** [security 3]: limited to
  credential-named variables in Claude Code's environment. Values only the
  snapshot exports aren't visible to the hook, a stated limit.
- **Stand-ins always on PATH** (the original plan): changed by this revision
  itself, not by a review. A stand-in exists only where something configured
  can be reached. This removes the pass-through cost and the loop risk for
  unconfigured users, and makes a brand-new install shadow nothing.
- **gate-sh's not-ready refusal**: changed to running in the user's shell
  with a notice, since the managed shell is now a convenience (C14 asked for
  a decision).

## 19. Lead decisions (override the sections above where they differ)

1. **An explicit `allow` is honoured.** The user asked that every gated
   command can be set to the behaviour they want in each mode. So where the
   user explicitly writes `allow` (or `true` inside a per-mode table) for a
   mode, the gateway approves in that mode, after the consent dialog like any
   widening:
   - `[network] commands`: `allow` (bare, or for a mode in a table) means the
     gateway approves a network command in that mode (§3.2's "allow means cc"
     no longer holds; `cc` stays its own word). Defaults are unchanged:
     `"ask"` in every mode.
   - The `http` and `download` tools (§2.10): the network policy's explicit
     `allow` for a mode makes `hooks_mcp.py` answer allow in that mode; a
     bare word or absent policy still gives cc (no decision), so nothing is
     approved by default.
   - Rights keep §2's expansion: a bare `true` is allow in auto and bypass
     and cc elsewhere; `{ default = true, ... }` is allow in default mode.
   Defaults stay conservative; only what the user explicitly configured is
   approved. Tests cover both directions (default never allows; an explicit
   per-mode allow does, only in that mode), with mutations.
2. **The shared TUI harness** (`tests/tui`, identical in checkpoint): a
   workstream that changes it edits the gateway's copy only; the lead copies
   it to checkpoint afterwards (checkpoint is being changed in parallel).
3. **The recorded mode carries an epoch** (WS-2's fix, accepted). While
   the effective form makes the mode matter, the Bash hook keeps
   `$DATA/mode-epoch`; `pre_bash.sh` then sends every Bash and Monitor call to
   Python (a call without a trigger word only records the mode, `hook-mode`),
   and gated answers a read only under the current epoch, so a stand-in never
   reads a record older than the last mode it was told. Where the
   SessionStart payload carries `permission_mode`, SessionStart records it
   too (WS-1), so the first stand-in call has a record; until there is one,
   the modeless rule applies (the strict reading). The per-call cost while
   the marker exists is measured on macOS and Linux and stated in TESTING.md
   and the README's Limits (WS-7).
4. **The consent dialog says what changes in each mode, for bare words
   too** (§2.8; WS-2's review should-fix 5). A change line names the modes
   that move and what each now does, in plain words, grouping modes that move
   alike: `sudo "ask" -> true` becomes, e.g., "sudo on this computer: in Auto
   and Bypass the gateway now approves; elsewhere Claude Code decides (was:
   ask in every mode)". A bare `[network] commands = "allow"` is named as an
   approval (decision 1). WS-3 does it (it owns the network class) and
   updates the exact strings in `test_consent` and `test_session`; it lists
   every string the TUI acceptances match, for WS-7.
5. **A stored Entra credential that doesn't fit the effective account is
   refused at use**, not only shown as "needs a new sign-in": after an
   approved change of `tenant`, `client_id`, `sign_in` or `scope`,
   `entra._entra_record` refuses the old credential until a new sign-in
   (`accounts.entra_fits` against the effective account). WS-6; fixtures whose
   tenant doesn't match their form are fixed, not exempted.
6. **The sign-in keys parse as WS-5 wrote them**: `sign_in` is "" for a
   service principal and "browser" otherwise; a browser sign-in needs
   `client_id`; `scope` is stored without `offline_access` (the gateway adds
   it). The change line's label is the key's name (`sign_in`).
7. **§9.4 (checkpoint context only when live) moves to WS-1 entirely**:
   gated's `<run>/checkpoint-seen` writer and `hooks_session`'s reader.
8. **Refusals and credential uses audit their mode** (`audit.refusal(mode=)`,
   done in WS-2's fix); every new refusal path in later workstreams passes it.
9. **git in a configured repository with no usable approval** (WS-4's
   review (e)): local git commands (status, log, commit, diff) still run, in
   the gated git, while the vault is locked, the entry is disabled or the form
   is missing; anything that contacts a configured remote is refused with the
   entry's refusal. The git stand-in's body lives in `githelper.py` (one
   process, for speed), not `clis._git`.
10. **An account CLI run by path** (`/usr/local/bin/gh ...`) is refused
    whenever an account of that kind exists: the hook can't resolve its
    destination from the words. The refusal says to run it by its name, so
    the stand-in passes an unconfigured destination to the user's own tool.
11. **The import confirm comes in parts** (WS-6): a confirm longer than one
    dialog is shown as "Part i of n" (at most 10); nothing is imported until
    the last part is accepted, and a cancel on any part changes nothing. That
    is §9.3's one consent dialog. A consent dialog longer than one dialog
    pages the same way (WS-8).
12. **A browser sign-in's refresh token is not exported**: an imported one
    could never be used. The import brings the account's settings, and the
    account then needs a new sign-in (`gate login NAME` in a session).
13. **The last fixes before the release verification (WS-9)**:
    - While any entry the hidden-command rule counts is "ask" in a mode but
      plan, Python keeps `$DATA/ask-marker` (wherever network-words is kept)
      and `pre_bash.sh` sends every Bash and Monitor call, and the job and
      terminal payloads, to `hook-bash`: a sourced script, `eval "$X"` or
      `bash -c "$CMD"` has no trigger word, and its `ssh box` would reach an
      "ask" as if typed (invariant 6). The cost is in TESTING.md and the
      README's Limits.
    - `sudoedit` joins §9.5's elevation tools, and `huggingface-cli` (hf's
      older name, no stand-in) is refused by any name while a huggingface
      account exists, pointing at `hf`; both are trigger words.
    - An account that lists `owners` covers only those and its login; the
      only account of its kind covers every owner only when it lists none
      (or with `default = true`). Listing the first owner is a widening.
    - The local sudo dialog's "Remember it" starts unticked, like the
      remote one (§9.1).
    - An account's per-mode `use` is set with `gate account set NAME use
      WORD|MODE=WORD...` and on `/gate-accounts`' edit line.
14. **The release-candidate requirements check (WS-10)** overrides 13 where
    they differ:
    - **"ask" is proved by a record, for every stand-in.** The Bash hook
      writes a record for each stand-in stage it answers "ask" for (ssh,
      scp, sftp, sudo, the account CLIs, git: WS-4's record, generalized:
      the Claude Code process, the real folder, the tool and its exact
      words, the entries asked about, used once, 15 minutes), and a
      stand-in passes an "ask" only with a matching record (and only for a
      command Claude typed). A sourced script, eval, a function or any
      other hidden form then reaches no record and is refused by the
      stand-in ("run `ssh box ...` as its own command"). So the hook no
      longer asks about hidden commands for an "ask" entry (only for a
      named configured target), and the forward-everything marker of 13 is
      removed. An account's `use = "ask"` works for its CLI (gh, hf, ...)
      the way it works for git.
    - **Program names are compared without case** (macOS's filesystem
      ignores it: `CURL`, `SSH`, `/usr/bin/SSH` run the real tools), in the
      hook, pre_bash.sh and the cold guard.
    - **The network class adds** tcpdump, tshark, nikto, sqlmap, hydra,
      gobuster, ffuf, nuclei, arp-scan and iperf3. ping, dig and traceroute
      stay out (everyday diagnostics; `extra` adds them). In a job, the
      network class is judged at the mode its job_start carries ("ask"
      still refused there).
    - **Configured sudo gets its own environment** (an allowlist, as the
      account CLIs), so `sudo -E` preserves only that.
    - **The gated git uses the user's own identity** when the account names
      none (`user.name`/`user.email` read with the user's git, passed as
      settings), with `user.useConfigOnly = true` so it never guesses.
    - **Vault care from chat:** a dialog-confirmed delete of the old vault
      copies `gate forget`/`rotate`/import leave; "Change passphrase" while
      unlocked; a dialog-confirmed "Start over" for a vault whose
      passphrase is lost (its files moved to backups).
    - **A checkpoint job run by the gateway gets checkpoint's environment**:
      CONTRACT-v1's `POST /v1/jobs` takes an optional `env` (names to
      string values; feature `job_env` in capabilities); gated starts the
      job with it minus the credential names the managed shell removes,
      the stand-ins first on PATH. checkpoint sends its environment when the
      gateway advertises `job_env`. pixi-guard reads checkpoint's job_start
      as bash too (the gateway may run it), and while the managed shell
      isn't ready gate-sh runs the user's own shell.
    - **Approvals from 0.9 and 0.10 are read (they have the same shape);
      nothing older.** The pre-phase-4 readers go; the first-0.11 notice
      stays (§1.5).
    - Stays as decided: bash is conda-forge's newest (5.2.37 at this
      relock; GNU's 5.3 isn't there yet); browser sign-in tokens aren't
      exported (12); the stored-value paste check waits for the user
      (§9.7).
15. **The not-ready fallback runs the shell that made the snapshot**
    (WS-11), not §1.6's `/bin/bash` (else `/bin/sh`) or 14's "the user's
    own shell". Its name says which (`snapshot-zsh-*`, `snapshot-bash-*`),
    and the binary is found the way Claude Code (2.1.310) finds its shell:
    `CLAUDE_CODE_SHELL`, then `SHELL`, then the preferred shell on PATH,
    in `/bin`, `/usr/bin`, `/usr/local/bin`, `/opt/homebrew/bin`, the other
    in those places, the other on PATH (bash is preferred when `SHELL`
    holds "bash", else zsh); the first that is the snapshot's shell (a
    path holding "zsh" is a zsh, else one holding "bash" a bash), by its
    absolute path, without `=`. Without a snapshot, any bash or zsh in that
    order. (WS-11's first cut took the first bash, then zsh, which ran a
    zsh snapshot in `/bin/bash` wherever SHELL was unset or fish; review
    WS-11a M1.) Never `/bin/sh` for a script that sources its snapshot
    (dash has no `source`: on Debian the snapshot was skipped without a
    word); with no such shell the command is refused (126). The notice says
    what happened: the command ran without the gateway's managed settings,
    in that shell (the env's bash too: for a bash snapshot once the mod's
    `CLAUDE_CODE_SHELL` names it), and why: "still setting up" only while
    the env builds, else the settings are missing or couldn't be renewed (a
    new session writes them). pixi-guard reads a command behind the prefix
    with that shell.
16. While the vault is locked, this computer's configured sudo is refused
    up front, like the configured hosts and accounts (the stand-in needs
    the vault; asking first only led to a refusal after the user's OK).
