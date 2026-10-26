# The managed remote runtime (remote hosts in gated)

PLAN-v4 phase 6 (2026-10-20). Code: `plugins/gateway/runtime/pixi.toml` and `pixi.lock`
(the runtime workspace), `src/gateway/runtime_pack.py` (the artifacts, built locally),
`src/gateway/daemon/remote.py` (connections, identity, staging, the remote tmux),
the remote panes in `daemon/terminals.py`, the route `/agent/remote/runtime` in
`daemon/server.py`, the gw tools' `host` argument and `host_runtime` in `mcp_server.py`,
the approval hook's judging of remote work in `hooks_bash.py`, the permission decisions in
`hooks/mcp_perm.sh`, the form's `runtime` key (`form.py`) and its consent (`consent.py`),
`gate status NAME`'s runtime lines (`gate.py`). Tests: `tests/test_remote.py` (fixtures:
`tests/harness_remote.py`); mutations: `tests/mutations_remote.py`; live:
`tests/acceptance_remote.py` (the Linux VM and a local sshd, real artifacts). Why it is
built this way: [DECISIONS.md](../DECISIONS.md), "PLAN-v4 phase 6: the managed remote
runtime". Terminals and jobs themselves: [terminals.md](terminals.md).

## What it is

Terminals and jobs on a remote host run in the gateway's own runtime there: bash 5 and
tmux 3 from conda-forge, staged by gated into a private folder on the host over the
gateway's own ssh, never the host's login shell, rc files, PATH or tmux. The person and
Claude share them exactly as local ones (one writer, seq, takeover, the credential dialog
for password prompts); gated keeps the ids and owners and asks the host what survived
before it reattaches or reports anything.

```
gated ── RemoteHost(NAME) ── Conn (ssh_conf: the vault's key, pinned host keys,
  │        │                       ControlMaster cm-%C shared with the ssh stand-in)
  │        └── exec /bin/sh -c '<script>'  (the login shell only execs; values on stdin)
  │                    │
  │                    ▼  on the host, under <base>/<version>-<platform>/ (0700)
  │             env/bin/{bash,tmux}   tmux.sock (private)   tmux.conf   gateway.rc
  │             hosts/<host id>  (the host record's marker: a nonce gated keeps)
  │             terms/  (start files, 0600, removed once read)   .gateway-runtime (marker)
  └── Supervisor: remote panes (records in terminals.json with rt, machine), one poller
      thread per host with live panes
```

## The artifacts (runtime_pack.py)

- `runtime/pixi.toml` + `pixi.lock` in the plugin: workspace `gateway-runtime`, platforms
  linux-64, linux-aarch64, osx-arm64, osx-64; `bash = "5.*"`, `tmux = "3.*"`; no Python
  (FEASIBILITY-v4 P5: a pack with Python is ~85 MB); a feature `unpacker` with
  `pixi-unpack = "0.7.*"` (environment `unpacker`, no default feature).
- The runtime **version** is `sha256(runtime/pixi.lock)[:12]`: a new lock is a new folder on
  every host (`feb524284da9` as of this phase).
- `ensure(platform)` builds on first need into `<data>/runtime/<version>/<platform>/`, under
  a flock (`<data>/runtime/<version>/.<platform>.lock`), into a temp folder renamed into
  place:
  1. a copy of the manifest and lock in `<data>/runtime/<version>/ws/` (the plugin folder is
     never written);
  2. `pixi-pack <ws>/pixi.toml -e default -p <platform> -o runtime.tar --use-cache
     <data>/runtime/cache` (the gateway env's pixi-pack, `pixi.toml` gained it and `zstd`);
  3. `pixi-pack ... -e unpacker -p <platform> --directory-only` and, from its conda packages,
     `bin/pixi-unpack` and the shared libraries right under `lib/` (openssl's libssl and
     libcrypto, libgcc_s; libgomp and friends skipped; only regular files): each `.conda`
     opened with `zipfile`, its `pkg-*.tar.zst` decompressed by the env's `zstd`, read with
     `tarfile` (an absolute or `..` member refuses the build). The target's binary is never
     run here; it finds its libraries by its rpath (`$ORIGIN/../lib`, `@loader_path/../lib`);
  4. `manifest.json`: `{version, platform, files: [{path, sha256, size, mode}], built,
     pixi_pack}`; only `runtime.tar` and `unpacker/{bin/pixi-unpack,lib/NAME}` are allowed
     paths.
- Every use re-reads the manifest and hashes every file (`load_manifest`): a file changed
  since its build is built again. `prune_versions()` drops other versions' builds.
- Sizes (linux-aarch64): runtime.tar 9.7 MB, pixi-unpack 13.1 MB + libs 9.6 MB; unpacked
  env 47.5 MB. osx-arm64: 8.0 MB + 10.3 MB + 6.1 MB.
- Test override `runtime_artifacts` (a folder with `<platform>/runtime.tar` and
  `<platform>/unpacker/...`) replaces the two pixi-pack runs; the manifest and every check
  after it are the same code.

## Connecting, rights and identity (RemoteHost)

- **Rights**: the host's modeless ssh right (PLAN-0.11 §2.4: the strictest over every
  mode but plan) must be cc or allow, i.e. `true` (`"ask"` can't be asked per
  command for a terminal or job: refused with the remedy; `false` refused with the form's
  wording; a host waiting for the user's OK refused). The link is `ssh._build_link(...,
  checked=True, on_mismatch=...)`: the same address choice, pins, keys and jump chain as
  the stand-in.
- **Commands**: every remote command line is `exec /bin/sh -c '<script>'`. The login shell
  (which must run POSIX `sh -c` lines: sh, bash, dash, zsh, ksh) only execs; whatever its rc
  prints is cut off at a random marker the script prints first (stdout and stderr). Values
  (files, the dialog's password) travel on ssh's stdin, never on a command line here or
  there. ssh's exit 255 is classified from ssh's own messages: host key (→ the gate below,
  with a scan of the keys right then), refused key (`auth`), anything else `unreachable`; a 255
  after the marker is a connection that dropped during the command (the scripts never exit
  255): no answer, never an empty one. **A lost answer is never "not run"**: a timeout, a 255
  after the marker, and a 255 with no answer at all unless ssh says it never connected
  (`ssh: connect to host ...`, `Could not resolve hostname`, `kex_exchange_identification`:
  `NOT_SENT`) mark the error `ambiguous` (the command may have run); a failure in connecting
  or verifying (before the command was sent) never does. One command at a time per host
  (the connection is shared).
- **Identity** at each new master (the pid `ssh -O check` reports changed): the script
  `IDENTIFY` prints `uname -s`, `uname -m`, the machine id (`/etc/machine-id`,
  `/var/lib/dbus/machine-id`, IOPlatformUUID through `/usr/sbin/ioreg`, else a random id
  kept in `~/.local/share/gateway-runtime/.machine-id`, prefixed `gw:`), `$HOME`. The token is
  `lifecycle.machine_token(raw)`, the same derivation as localhost's id (a remote host that
  is this very machine shows `same_machine: true`). First contact stores it in the vault
  with the host keys (`hosts[NAME].machine_id`, `machine_id_at`, a vault event "machine");
  the raw id is never stored.
- **The gates**: a changed host key (the address probe's keyscan or ssh's own refusal) and a
  changed machine token each open a gated-owned **confirm** dialog in the session that asked
  (or the owner session of work on that host): fingerprints or tokens old and new, "Trust new
  key" / "Accept new machine", default Cancel. Until it is answered every operation on that
  host is refused (`remote_hostkey`, `remote_machine`), its panes are `disconnected` with the
  reason, nothing is sent to it. OK pins the new key (`ssh._pin_host_keys`) or stores the new
  token (panes started on the old machine become unknown: `machine_changed`); Cancel keeps it
  blocked ("the user didn't accept ...") until the pins or the host's addresses change (gate
  check re-pinned, the form fixed) or ten minutes pass; no dialog possible: blocked with the
  remedy (gate check NAME in an interactive session).
- **A refused key** (`Permission denied (publickey)`): the host's auth state is `refused`,
  its panes `waiting_auth` with "NAME refused the gateway's ssh key ...: the user can install
  it again with gate check NAME"; an **info** dialog tells the person once per 15 minutes;
  gated retries (backoff 1-30 s) and the panes come back by themselves when it works again.
- **A locked vault**: the host can't be reached (no key, no pins): `disconnected` with the
  locked wording.

## Staging (ensure_runtime)

On the first remote terminal or job (or `host_runtime provision`), under the host's lock:

1. connect (rights, keys, identity); `platform_of(uname -s, uname -m)`: Linux x86_64 /
   aarch64 (arm64), Darwin arm64 / x86_64; anything else is refused with what is supported
   and the remedy (`ssh HOST CMD` without the runtime), nothing copied.
2. the base: the host's approved `runtime` path (form key, a widening when changed) or
   `~/.local/share/gateway-runtime`; `<base>/<version>-<platform>` made with umask 077 and
   chmod 700 (and `terms/`, `hosts/`); unwritable: refused with the runtime-path remedy; a
   folder too long for tmux's socket (≥ 100 bytes with `/tmux.sock`): refused, ditto.
3. an existing folder whose marker names this version and platform and whose probe passes
   is reused (only the host's marker, conf and rc are written again).
4. free space (`df -Pk`): less than the files plus 64 MB → refused before anything is copied
   ("NAME has N MB free where the runtime goes ... free some space there, or set another
   runtime path ..."); a write failing with "No space left" or a quota says the same.
5. each file copied with `cat > F.part && mv F.part F && chmod` (stdin), the folder cleaned
   first.
6. **sha256 on the host**: `sha256sum`, else `shasum -a 256`, else `openssl dgst -sha256`;
   with none, each file is read back (`cat`) and hashed here. Any mismatch removes the copy
   and refuses (`remote_integrity`); nothing is unpacked.
7. `pixi-unpack --version` first: exit 126 with "Permission denied" is a noexec mount
   (refused with the runtime-path remedy); then `TMPDIR=<dir>/.tmp pixi-unpack runtime.tar -o
   <dir> -e env -q`; the pack, the temp folder and the unpacker are removed afterwards (only
   `env/` stays).
8. readiness: `env -i HOME=$HOME PATH=/usr/bin:/bin <dir>/env/bin/bash --noprofile --norc -c
   'printf %s "$BASH_VERSION"'` (5.x) and `.../tmux -V` (tmux 3.x).
9. `tmux.conf` (the local supervisor's `TMUX_CONF`), `gateway.rc`, `hosts/<host id>` (a
   nonce), then the marker `.gateway-runtime` `{version, platform, bash, tmux, at}`; the state
   in `<data>/gated/remote.json` (`rt`, `rt_version`, `platform`, `base`, `nonce`, `bash`,
   `tmux`, `ready_at`, `machine`, `home`); audited `remote_runtime staged` (and
   `hash_check`).
10. older versions under the base are removed: only folders named `<12 hex>-<platform>` that
   hold the marker (or this host's marker), and only when their tmux server doesn't answer
   (it still runs work otherwise: kept, "busy").

No elevation, no change to any rc or profile, nothing outside the runtime folder (and the
fallback machine id file). A runtime that went missing on the host (deleted) is staged
again by the next start; panes in it are reported, never assumed.

## Remote panes (terminals.py)

- `terminal_open {host}` / `job_start {host}` / `POST /v1/jobs {host}` / `/ui/term/open
  {host}`: `host` is a form host's name, its contract id (`m_...`) or its machine token
  (exactly one host with it); localhost as before (absent, `localhost` or this machine's
  id). One resolver, `daemon.resolve_remote_host`, serves gated and the approval hook. The
  runtime is made ready first (staging on first need; the gw MCP server waits up to 900 s
  for a remote call).
- **A start whose answer is lost.** The pane's record (state `starting`, `unconfirmed`)
  and a job's idempotency key are saved before `new-session` goes to the host; a second
  request with the same key while the first is starting gets 409 `starting`. When the start
  fails `ambiguous`, the record stays: state `unknown`, `start_confirmed: false`, a note
  ("the connection to NAME dropped while this job was being started ..."), and the call
  answers with it (200, `new: true`); a retry with the same key returns it; writes,
  signals and resizes are refused (`unconfirmed`) until it is settled. A failure that
  provably didn't start it leaves no record and raises as before. The poller settles it:
  the host lists it by id and `@gw_nonce` → adopted (running/open, confirmed); not listed →
  the start file's **claim**: the pane's start file begins by renaming itself (`mv -f F
  F.run || exit 125`; the shell already has it open), and gated renames it too (`mv F
  F.void`, `RemoteTmux.claim_start`): exactly one rename succeeds. Gated's → it never ran
  and can't any more (a session that came up meanwhile is killed, the file removed): a job
  `failed` with "never started on NAME ...", a terminal `closed`, and the job's
  idempotency key is freed (a retry with it starts the job). The shell's → it started:
  the next look decides (listed: adopted; not listed: lost, `unknown`). A gated that dies
  while a start is out leaves the same `starting` record, settled the same way. Only a
  look fetched after the start's answer may call it lost.
- The start file is written on the host (`umask 077; set -C; cat >`, its text on stdin) and
  read once by the pane, which claims it first (renamed to `.run`) and removes it. It unsets every variable but the platform's
  (`KEEP_NAMES`), exports the curated `PATH=<rt>/env/bin:/usr/local/bin:/usr/bin:/bin:
  /usr/local/sbin:/usr/sbin:/sbin`, `SHELL` (the runtime's bash), `LANG` (C.UTF-8 on
  Linux, en_US.UTF-8 on macOS), `GW_TERMINAL`, `GW_RUNTIME`, sources `gateway.rc` (no
  history file, `histexpand` off, a plain prompt), `cd`s into the cwd (checked on the host;
  default the remote home). The runtime's tmux server itself starts under `env -i` (HOME,
  USER, LOGNAME, LANG, PATH=/usr/bin:/bin), with the gateway's config and its socket in the
  runtime folder; the pane is `<rt>/env/bin/bash --noprofile --rcfile <start> -i` (a job:
  `--norc <script>`). The user's `~/.bashrc`, `~/.profile`, `~/.tmux.conf`, login PATH and
  ssh session variables never reach it (the VM run planted a probe first in `~/.bashrc`:
  the login shell's `bash -c` read it, the managed shell got nothing).
- Records gain `rt` (the runtime folder), `machine` (the host's token when it started),
  `remote_note` (why the host can't be reached). Every operation goes through `_tm(p)`: the
  pane's own host's `RemoteTmux` (never another's), refused when the host's machine token
  isn't the pane's; every RemoteTmux command checks the host record's marker first
  (`bind_check`: `<rt>/hosts/<host id>` must hold the nonce gated keeps, else exit 97 and
  "isn't this host's runtime; nothing was run").
- Reading, writing and signals are the local code over ssh: `capture-pane` (once, plus the
  joined capture for the agent), `load-buffer -` (stdin) then one line with `paste-buffer
  -d` and the keys, `kill -s SIG -- -PGID`, the foreground group from the host's `ps -o
  tpgid=`, suspend as the local `stop_group` (SIGTTOU to the root, SIGSTOP to the rest,
  checked with `ps`). Typed text whose paste answer is lost (`ambiguous`) is checked by
  its uniquely named buffer (`_buffer_left`, asked at once even right after the failure):
  gone → it went in (delivered, with a note), still there → nothing was typed (the buffer
  removed, the error says so), can't ask → 409 `outcome_unknown` ("read the screen again"),
  the seq bumped (a repeat quoting the old seq is stale) and the buffer removed at the
  host's next answer (no late paste). A remote job's output is its tmux history on the host
  (10000 lines, kept an hour after it ended): no stream leaves the host but what is read;
  `job.output` events are local only.
- **Close** of a remote pane the host doesn't get: `closing`/`cancel` go back to what they
  were (a job that later ends by itself reports `exited` with its own status, never
  `canceled`), and `stop_requested` says "not delivered" (503, "... was not closed") or,
  when the kill went out and its answer was lost, "outcome unknown" (`outcome_unknown`):
  then the session missing from a server that still runs is that close (`canceled`). A
  pause step the host can't take is "not applied: ..." (or "outcome unknown"), never
  "already ended".
- **The poller** (one thread per host with live panes; every second, `remote_tick` in
  tests, backoff 1-30 s after failures): one ssh round trip per runtime folder answers
  `list-panes` (states, exits, dead panes' status and signal) and, for each live pane, `stty
  -g < tty` (GNU and BSD formats, `parse_stty`), the foreground group and its program's name;
  the answer ends with an end marker (`parse_poll`): one cut off is "can't be asked", and only
  the host's proof of "no server" or a complete list without a pane loses it. "No server"
  needs the socket gone, or tmux saying "no server running" while the server pid it last
  gave (`#{pid}`, kept per runtime folder in remote.json as `tmux_pids`) fails `kill -0`
  (or isn't a tmux); any other failed `list-panes` (a fork failure, the binary briefly
  missing, a full listen queue) is a blip (`__GW_NOANSWER__`, `remote_noanswer`): the panes
  keep their state, with a note, and are asked again (the local `_blip`'s rule).
  - The host can't be asked: its panes become `disconnected` (or `waiting_auth` for a
    refused key) with the reason in `note`, never ended, never unknown; agent writes are
    refused (`disconnected`) without touching the host; reads say so.
  - The host answers again: before anything else the connection is verified (host keys by
    ssh's strict checking against the pins, the machine token at the new master), then each
    pane's state is taken from the host: alive → running/open again, its seq bumped (a seq
    read before is stale), a dead pane → `exited` with its status or signal, a pane the
    host's tmux doesn't list → gone/`unknown` (no end time), the runtime's tmux server gone →
    every pane there unknown/gone ("the host restarted, or it was stopped"), a pane from
    another machine → unknown.
  - A gated restart: remote records are left as recorded but marked unconfirmed (`note`)
    until the host's poller answers; then the same rules apply (seq bumped).
- **Password prompts** on a remote pane (ECHO off with ICANON on, from the poll): the same
  credential dialog, saying the host ("... in gateway terminal t_... on NAME", the
  foreground program as the host's `ps` names it); the dialog names the host's ssh right for
  gated's recheck, and a root prompt (`sudo`, `su`, `doas`, `sudoedit`, `pkexec` anywhere in
  the foreground process group: the poll lists its members, leader first, so `echo x | sudo
  tee f` counts, and the dialog names the root program) the ssh and sudo rights; a root
  prompt on a host whose sudo is `false` opens no dialog (the pane says why). The answer is
  rechecked on the host (still waiting, same foreground group) and goes in on ssh's stdin
  into the runtime tmux's `load-buffer -`, pasted with Enter: the value is on no command
  line here or there (a logging ssh wrapper and the sshd's command
  log in the tests, the VM's process table and logs live), and is masked in that pane's
  later reads.

## Agent tools, routes, permissions

- gw tools: `terminal_open {host, ...}`, `job_start {host, ...}`, and `host_runtime {host,
  action: status | provision | clean}` (identity, reachability, authentication, runtime
  readiness and version, the bash and tmux versions; staging now; removing old idle
  versions). Route `POST /agent/remote/runtime` (agent-term plane).
- `hooks/mcp_perm.sh`: `terminal_open` with a remote `host` gets no decision (it may stage the
  runtime: Claude Code's mode decides); `host_runtime` status is allowed, provision and clean
  get no decision.
- The approval hook judges a remote `job_start` as `ssh HOST '<command>'` (the host's ssh and
  sudo rights, the remote sudo rules; "ask" denied for a job) and a `terminal_send` into a
  remote terminal (its host from gated's records) the same way. It resolves `host` exactly
  as gated does (`daemon.resolve_remote_host` over `machine-ids.json` and `remote.json`:
  name, assigned id, machine token; this machine's id is local) and denies a `job_start`
  whose host word names no host. `pre_bash.sh` sends every
  `job_start` with a top-level remote `host` to it, trigger word or not; remote
  `terminal_send` text goes by the word list, as local text does.

## Policy, inspection and imports (phase 7)

- **Policy** (docs/dev/modules/policy.md): terminals and jobs are decided by the host's `exec`
  (and their workspace's) in `Supervisor._bind`; staging a new or changed runtime by
  `provision` (`ensure_runtime`: a refusal is `RemoteError("policy", ..., 403)` with the
  rule; an already staged runtime of the same version is used without asking again);
  inspection by `read`; imports by `env_import`.
- **`host_inspect` on a remote host** (`RemoteHost.inspect`, route `POST
  /agent/remote/inspect`): one read-only script over the verified connection
  (`managed.remote_inspect_script`: the system's and the user's profile files read as text,
  at most `REMOTE_MAX` bytes each, well-known toolchain folders listed with up to 12
  program names, the login environment's variable names; nothing sourced or run), parsed
  here (`managed.parse_remote_inspection`: folder names from PATH lines, never values) and
  scrubbed; it also shows what the remote managed shell's PATH would be
  (`managed.remote_path_plan`) and the approved imports with their origin.
- **Remote imports**: `[hosts.NAME.shell] import_path = [...]` and `import_env = [...]`,
  each a widening of that host's entry (the consent dialog, `gate check NAME`), applied only
  while the host's `env_import` policy is allow (`RemoteHost.imports`). Folders go on the
  remote managed shell's PATH after the runtime's own (`terminals._remote_path_expr`);
  variables are copied on the host from the ssh session's environment into a 0700 folder of
  0600 files, one per name (`RemoteTmux.capture_env`), which the start file reads by name
  and removes: no value on a command line and none sent to this machine. Credential-looking
  names (and `GW_*`) are refused in the form, as for `[shell]`.

## The contract and diagnostics

- `/v1/snapshot` hosts: remote hosts carry `identity: "verified"` and `machine` once their
  machine id is known (else `"assigned"`), `same_machine`, `reachable` (ok, down, unknown),
  `auth` (ok, refused, locked, unknown), `runtime` (ready, checking, failed, unsupported,
  unknown), `runtime_version`, `platform`, `checked_at` (the host's last answer, or the
  failure that said it was down): past `STALE_AFTER` (10 s; the `remote_stale` knob in tests)
  nothing has asked the host since, so reachable and auth read `unknown` and a ready runtime
  `unknown` too, with `stale: true` and what the last contact said in `note` (the same in
  `host_runtime` status, which never contacts the host itself); localhost carries `runtime` (ready or missing:
  the local env). The host `id` stays the assigned one (stable). Jobs carry `remote: true`
  and `note`. Event `host.state {host, name, state, reachable, auth, runtime, identity}` on
  every change. Feature `"remote"`.
- `gate status NAME`: the runtime folder (or the default, and "waits for your OK"), the
  version and platform staged, the machine token.

## Known limits

- Remote targets: Linux x86_64/aarch64 (glibc 2.17+) and macOS arm64/x86_64 (11+) with a
  POSIX `sh -c` login shell, `uname`, `cat`, `mv`, `mkdir`, `chmod`, `df`, `ps`, `stty`, `kill`
  (all POSIX). musl (Alpine), BSDs, other architectures and native Windows have no runtime.
  csh/tcsh/fish login shells aren't supported.
- Space: about 80 MB free while staging (the copy, the unpacker and the unpacked env), about
  50 MB kept (`env/` only).
- The first pack of a platform downloads its packages from conda-forge (no proxy settings
  are passed to pixi-pack); later builds use the cache in the plugin data folder.
- Debian's bash reads `~/.bashrc` for an ssh command (SSH_SOURCE_BASHRC): the login shell's
  `bash -c` that only execs `/bin/sh` runs it; nothing of it reaches the managed shell, but a
  `~/.bashrc` that reads stdin or exits early would break the gateway's commands (reported
  as a shell problem).
- A remote `import_env` value comes from the ssh session's environment on the host (what
  sshd and the login shell's exec give `sh -c`), not from an interactive login: a variable
  set only in an interactive rc isn't there.
- A noexec runtime folder and a full disk were exercised with a stand-in pixi-unpack and a
  `df` override in the suite; the VM has no writable noexec mount for the test user and its
  disk wasn't filled.
- `waiting_input` isn't detected (as locally); a remote job's output older than the tmux
  history (10000 lines) is gone; `job.output` byte counts are local only.
- One ssh command at a time per host (the shared connection); a pane view open in
  `/gate-terminal` looks every 0.5 s (one round trip each).
- An "ask" ssh right gets no remote terminal or job; a host behind `via` works through the
  jump (ssh's ProxyJump), untested live.
- A lost start settled as "never started" while the original start was still executing on
  the host (the client gave up but the host's `sh` went on): a job's shell then finds no
  start file (or loses its claim) and never runs the command; a terminal's shell comes up
  without its start file (an idle shell with no rc, in a session gated doesn't track). Only
  after an ssh timeout on a host slower than 30 s per command.
- A host's status between pollers' looks is only as current as `checked_at`; during a long
  outage the pollers back off to 30 s, so a "down" may read `unknown` between looks.
