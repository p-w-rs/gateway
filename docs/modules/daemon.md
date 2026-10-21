# The gateway daemon (gated) and the broker

PLAN-v4 phase 2 (2026-10-19), with phase 3's native dialogs, phase 5's
terminals and jobs (2026-10-20; their own page: [terminals.md](terminals.md)) and
phase 6's remote runtime ([remote.md](remote.md)).
Code: `plugins/gateway/src/gateway/daemon/` (`__init__`, `peers`, `planes`,
`events`, `broker`, `server`, `lifecycle`, `dialogs`, `clipboard`, `client`,
`terminals`, `screen`) and `agepass.py`. Tests: `tests/test_daemon.py`, `tests/test_broker.py`,
`tests/test_dialogs.py` (fixtures in `tests/harness_daemon.py`,
`tests/fakes/fake_claude.py`); mutations: `tests/mutations_daemon.py`,
`tests/mutations_dialogs.py`. Why it is built this way, and where it departs
from the phase notes: [DECISIONS.md](../DECISIONS.md), "PLAN-v4 phase 2: the
daemon and the broker" and "PLAN-v4 phase 3: native dialogs". The checkpoint side of the socket is [CONTRACT-v1.md](../CONTRACT-v1.md).

## What it is

One process per user (and per test root), started on demand, detached from
every Claude Code session. It holds the unlocked vault key when the key has a
passphrase, keeps the sessions it knows, publishes the CONTRACT-v1 discovery
file and serves the contract's capabilities, snapshot, events, pause and
resume. Since PLAN-v4 phase 3 it also holds every question the gateway asks
the person (the dialog requests, below), which the gate mod draws inside
Claude Code; since phase 5 it supervises the gateway's terminals and jobs in
its own tmux server ([terminals.md](terminals.md)).

```
<run>/gated.sock        the socket (0600; run dir /tmp/gw-$UID, 0700, owner-checked)
<run>/gated.lock        single-instance flock (held by the daemon for its life)
<run>/gated.pid         `<pid> <start time>` (ps lstart, LC_ALL=C TZ=UTC0), written whole
                        before the socket is bound, removed at exit: the tmux watchdog
                        tells a killed daemon (its socket left behind) from a live one
<run>/gated.start.lock  flock that serializes starters
<run>/gated-sessions.json   registered sessions (0600, written whole)
<run>/gated-dialogs.json    dialog requests, leases (token sha256 only) and paused sessions:
                            metadata only, never a key or a value (0600, written whole)
<data>/gated/gated.log  the daemon's stdout/stderr (0600; rotated to one .1 past 1 MB,
                        at start and while it runs)
<data>/gated/epoch      the epoch counter (incremented at each start)
<data>/gated/events/epoch-<n>.jsonl   bounded event files (one .1 segment; 5 epochs kept)
<data>/gated/machine-ids.json         ids assigned to the form's remote hosts
<data>/gated/terminals.json           terminal and job records (metadata only; terminals.md)
<data>/gated/remote.json              remote hosts' runtime and identity state (remote.md, phase 6)
<data>/runtime/<version>/<platform>/  the remote runtime's packs and their manifest; <data>/runtime/cache
<run>/tmux.sock, <run>/tmux.conf      the supervisor's own tmux server and config
<run>/terms/                          panes' start files (removed once read) and job output FIFOs
~/.config/gateway/run/contract.json   CONTRACT-v1 discovery (0600, folder 0700)
private/key.wrapped, private/key.recipient   the vault key with a passphrase (0600)
```

`paths`: `gated_socket()`, `gated_lock()`, `gated_pid()`, `gated_start_lock()`,
`gated_sessions()`, `gated_dir()`, `gated_log()`, `contract_dir()`,
`contract_path()`, `wrapped_key_path()`, `recipient_path()`.

## Starting and stopping (lifecycle.py)

`run.py gated serve [--detach] | start [--register] | status | stop`
(`launch.sh gated ...` passes through to it). `--test` with
`GATEWAY_TEST_ROOT` (and `GATEWAY_TEST_RUN` for a short run dir) works for
`gated` as for hooks and MCP; the daemon takes its data folder from its
python, never from `CLAUDE_PLUGIN_DATA` (run.py trusts that only in hook and
MCP modes).

Who starts it: the mod at `session.start` (`$.process.run(["sh", launch.sh,
"gated", "start"])`), the async SessionStart hook `hook-daemon` (so it also
runs without mods and in `claude -p`), and with a wrapped key every vault read
(`client.py`): stand-ins, the git helper, the MCP server, gate and hooks.

- `ensure_running(wait=10)`: GET /health; the same or a newer version is
  used (a newer daemon serving an older plugin is reported in the answer's
  `skew`). An older version is asked to restart (`/local/restart`): it stops
  when it holds no live terminals or jobs (`Daemon.busy()`) and the new
  version starts; otherwise it stays and the answer's `skew` says "the old
  gateway daemon (X) still runs N". Else, under `gated.start.lock`, `run.py
  gated serve --detach` is spawned (its own session, a fixed small
  environment: no CLAUDE_*, no stand-in PATH) and /health awaited.
  `StartError` when nothing answers (the message names the log). A daemon
  that takes the connection but doesn't answer (stopped, hung) gets
  `UNRESPONSIVE_GRACE` (3 s: it may be finishing its start), then
  `StartError` ("running but isn't answering"): another start would exit at
  once on the instance lock, so waiting 10 s for it only stalled every
  caller. /health
  itself carries no `skew` (it doesn't know who asks): `gated status`
  (never starts or restarts the daemon; what /gate-doctor runs) adds it for
  any version difference with the plugin copy that runs it, newer or older
  (`daemon.skew_text`), and `gate status` adds the same words to its daemon
  line.
- `serve(detach)`: flock `gated.lock` without waiting (a second daemon prints
  "already running" and exits 0), then fork, setsid, fork (the daemon is not a
  session leader, so it can't get a terminal), stdio to the log, umask 077,
  cwd `/`. `gated.pid` is written (its pid and ps start time, for the tmux
  watchdog: terminals.md), a leftover socket is removed (the lock proves its
  daemon is gone, also after `kill -9`), the socket bound (0600), contract.json written,
  `daemon.started` emitted. A consumer that reads a contract.json whose pid
  is dead treats the gateway as unavailable (CONTRACT-v1); the next start
  rewrites it.
- The ticker (every 30 s; tests set `tick`): exits when the socket was
  removed or replaced (the run dir deleted: nobody can reach it; the e2e and
  TUI harnesses delete theirs, so under the e2e marker the tick is 0.25 s),
  locks the vault after `lock_after` without use, prunes dead sessions, and
  exits after `IDLE_EXIT` (30 min) with no live session, terminal or job
  (live panes keep it running; the supervisor has its own 0.25 s tick).
  Leaving because its socket was removed, it also stops its tmux server,
  whose socket went with the run dir (`Supervisor.abandon`). It also exits
  when the plugin folder its code runs from is going away and it holds no
  terminal or job: removed (`paths.code_root()`'s run.py gone; checked first
  in a tick, before anything that might import a module from it; with
  another, not orphaned version beside it that is an update's sweep, below,
  and the daemon serves on until it holds no terminal or job), or marked
  orphaned by Claude Code (`.orphaned_at`, which 2.1.301's `claude plugin
  uninstall` and an update write into the version folder they leave for a
  later sweep) once no live session is registered (a session still running
  that version keeps it). So an uninstalled gateway stops advertising the
  contract at the next tick, not 30 min later (acceptance 2026-10-21; a
  disabled plugin can't be seen from the daemon: a session without the
  gateway isn't registered, and its calls are refused).
- **Draining** (0.9.1; the GitHub install test found a plain uninstall with a
  job running left gated running forever, advertising the contract, its tmux
  server and watchdog running from deleted files: the env's tmux could no
  longer be run, so every pane query failed and counted as a blip). The
  plugin counts as uninstalled (`uninstalled_reason`) when its data folder is
  gone (`data_removed`: a plain `claude plugin uninstall` deletes it, with the
  env this python and the env's tmux run from), or its code folder is gone or
  orphaned (orphaned: with no live session) with no newer, not orphaned
  sibling version beside it (`newer_sibling`: an update marks the old folder
  the same way, and its daemon keeps serving its jobs and the contract until
  it is free; Claude Code 2.1.301 removes that old folder 14 days later unless
  a live session uses it, and a daemon still running a terminal or job from
  it then serves on too, `replaced`: contract.json kept, new terminals and
  jobs taken, no rights watch since that imports from the removed folder, and
  it exits once it holds no terminal or job, as 0.9.0 did; 0.9.1 before
  refix-gw drained it and refused every new terminal as "uninstalled").
  Uninstalled with nothing running, the daemon
  exits as above. With terminals or jobs running it drains (`drain`, one way):
  contract.json is removed at once (checkpoint stops delegating: a missing
  file is "gateway not available" in CONTRACT-v1), `daemon.draining` is
  emitted (`reason: "uninstalled"`, the local terminal and job counts, and
  `resumed`: the jobs it resumed, below),
  `/health` carries `draining` (and `gated start`/`status` a `skew` note, so
  a reinstall's session says why it gets no new work yet), new terminals,
  jobs (`/agent/...`, `/ui/term/open`, `POST /v1/jobs`) and remote runtime
  staging are refused with 503 `draining` (an idempotency key seen before
  still returns its job), and the running ones are left alone, never killed;
  pauses are refused too (`/v1/pause`: 503 `draining`; `pause_begin`, and
  the drain waits for a pause being applied at that moment), and so is a
  job's STOP or TSTP (`job_signal`, the pane, the contract's signal: 503
  `draining`; counted like a pause being applied), and a job left
  suspended (a pause's `suspend`, `job_signal STOP`/`TSTP`) is resumed with
  SIGCONT (`Supervisor.resume_stopped`; the session's pause record stays;
  `resumed` counts only jobs ps showed stopped just before): with
  contract.json gone checkpoint can't send `/v1/resume`, so the stopped job
  kept the daemon, its tmux server and itself there forever (refix-gw;
  keeping contract.json with a `draining` field instead was rejected in
  0.9.1, since checkpoint 0.7.x would go on delegating; a stop after the
  drain began did the same until fix2). A remote job is resumed through the
  host's live master by the system's ssh (`ssh_conf.allow_system_ssh`, from
  the drain on: a plain uninstall deletes the env's ssh; terminals.md,
  "Draining", says when that can't work and the remedy);
  the vault keeps its lock rules (`broker.tick`), the rights watch stops
  (it would import from the removed folders), bytecode writing is switched
  off (a lazy import must not make the deleted data folder again), and no
  record is written into a removed data folder. It exits once no *local*
  terminal or job runs (`busy_here`; remote ones run on in their hosts'
  runtimes, and a reinstall re-adopts them from kept records), with its tmux
  server (terminals.md, "gated exits"). A reinstall meanwhile finds the
  draining daemon answering (no second one can start) until it leaves.
  From the drain on every log line also goes to
  `~/.config/gateway/run/gated-drain.log` (`DRAIN_LOG`, 0600, started over
  at a drain's first line, at most 64 KiB, never a folder made: a gateway
  home deleted too gets nothing): a plain uninstall deleted gated.log with
  the data folder, and this file says what the draining daemon waited for,
  what it resumed (or failed to) and when it left (fix2).
- Exit (idle, SIGTERM/SIGINT, `/local/stop`, restart, drained): `daemon.stopping`,
  the vault locked (`vault.locked` event), contract.json and the socket removed
  when they are still this daemon's, then its tmux server stopped when no local
  pane runs anything (`Supervisor.stop_server`, still under the instance lock).
- The log: a detached daemon's stdout and stderr go to `gated.log`; past 1 MB
  (`LOG_MAX`) it becomes `gated.log.1` (replacing an older one) at start and,
  checked after every line the daemon writes, while it runs (a consumer
  refused on every poll can't grow it without bound).

Test knobs, `<root>/gated-test.json`, read only under a test override:
`idle_exit`, `tick`, `lock_after`, `test_routes`, `test_entries`, `ring`,
`disk_max`, `log_max`, `busy` (stands in for live terminals and jobs),
`clipboard`, `tmux` (a tmux the supervisor runs instead: a test's logging
wrapper), `watch_tick` (the tmux watchdog's seconds between looks, 1-60;
0.9.1), and since phase 6 `runtime_artifacts` (prebuilt fake runtime
artifacts: no pixi-pack, no network), `remote_corrupt_upload`,
`remote_no_hash_tool`, `remote_df_avail_kb`, `remote_tick`, `remote_stale` (the
host status's staleness window), `ssh` (an ssh wrapper that records its argv, or
drops answers) (remote.md).

## Who is calling (peers.py) and the planes (planes.py)

Every connection: the peer's pid and uid from the kernel at connect time
(Linux `SO_PEERCRED`; macOS `LOCAL_PEERPID` + `LOCAL_PEERCRED` at `SOL_LOCAL`),
then the uid must be the daemon's, before any route.

| plane | routes | who |
|---|---|---|
| health | `GET /health` | any process of this user |
| ui | `/ui/register`, `/ui/unregister`, `/ui/vault/lock`, `/ui/vault/unlock`, `GET /ui/dialog/next`, `POST /ui/dialog/{submit,paste,answer,cancel}` | the Claude Code process itself: a registered UI session's pid |
| agent | `/agent/register`, `/agent/vault/{status,read,write,cache-read,cache-write,open-own,lock}`, `/agent/dialog/lease` | a gateway entry point below a registered session |
| lease | `/lease/dialog/{open,wait,retry,close}`, `/lease/release` | a gateway entry point (any session or none: the dialog helper is detached) holding a live lease token |
| agent-term | `/agent/term/{open,read,send,resize,signal,close,list}`, `/agent/job/{start,status,tail,signal,list}`, `/agent/remote/runtime` | the gw MCP server (a `run.py mcp` entry point) below a registered session (`planes.check_term`; terminals.md, remote.md) |
| ui (pane) | `GET /ui/term/{list,screen}`, `POST /ui/term/{keys,take,release,resize,signal,open,close,agent}` | the Claude Code process itself (the mod's terminal pane) |
| contract | `GET /v1/capabilities`, `GET /v1/snapshot`, `GET /v1/events`, `/v1/pause`, `/v1/resume`, `POST /v1/jobs`, `GET /v1/jobs/<id>`, `GET /v1/jobs/<id>/tail`, `POST /v1/jobs/<id>/signal` | any process below a registered session |
| local | `/local/stop`, `/local/restart` | a gateway entry point (any session or none) |
| test | `/test/vault/passphrase`, `/test/vault/unlock` | only when a test override enables them |

"Below" is strict: the UI process is never on the agent or contract plane,
and their peers never on the UI plane. Refusals are 403 with a code (`uid`,
`plane`, `peer`, `not_registered`, `pid`, `exe`) and a message; the daemon's
log records the route and the code, never a body.

A gateway entry point (`peers.entry_of(pid)`): its executable, by path, is
the daemon's own python or a python of the daemon's data folder's envs
(`<data>/envs/<sha12>/.pixi/envs/default/bin`; another data folder's is
refused), and its argv is `<python> -I -S [-X pycache_prefix=...]
<root>/run.py [--test] MODE ...`:

- the options are exactly what every gateway launcher passes (launch.sh,
  `envfile.py_flags`, `lifecycle.daemon_argv`): -I and -S both (no PYTHON*
  variables, no script folder on the path, no site: a planted
  `sitecustomize` or `.pth` never runs), nothing else but `-X
  pycache_prefix=` (`peers.launcher_options_ok`);
- `<root>` is the daemon's own plugin folder (`paths.code_root()`), or, when
  that folder is a version folder of Claude Code's plugin cache
  (`<config>/plugins/cache/<marketplace>/<plugin>/<version>`), a sibling
  version folder whose `.claude-plugin/plugin.json` names "gate": after an
  update the sessions of the old and the new version share one daemon (the
  newer one's `gated start` asks an idle older daemon to restart through
  `/local/restart`). A folder anywhere else with a run.py and a plugin.json
  naming "gate" is not an entry point (`peers.is_run_py`); a `--plugin-dir`
  checkout or an e2e copy has no siblings;
- MODE is one of run.py's (`shim <tool>`, `askpass`, `git-credential`,
  `gate`, `mcp`, `gated`, `hook-*`).

Under a test override that sets `test_entries`, a script in the plugin's
`tests/` or the test root with the root before the mode counts too. **This is
a guardrail, not a boundary**: argv is chosen by whoever starts a process,
and code running as the user can start the env's python on the real run.py
(or write a folder into the plugin cache), or read the daemon's memory. It
keeps a cooperative model's scripts and unrelated programs off the vault
plane.

Sessions: `Registry` keeps `Session(pid, start, exe, session_id, ui, surface,
surfaces, version, via)` (`surfaces`: the drawing surfaces the mod reports at
registration and at `session.attach`/`detach`; only a terminal or the
desktop app has the private field). The executable is checked when a process registers: it must
be Claude Code's (`ancestry.is_claude_exe`: named `claude`, the native
install's versions folder, the desktop app's copy). Afterwards a session is
valid while its pid lives with the start time it registered with (a reused
pid has another), whatever its executable path says then: an upgrade deletes
or replaces the binary of a Claude Code that keeps running (the native
install keeps two versions, Homebrew removes the old one; macOS then reports
no path, Linux `<path> (deleted)`), and it is still the same process. A live
registered process also counts as Claude Code when it registers again
(`Registry.claude_ok`: the mod at /clear or resume, a hook), so such a
session keeps its registration and keeps the daemon from its idle exit.
- `/ui/register` (the mod, from inside Claude Code): the peer must be Claude
  Code (`claude_ok`); `claude_pid`, when given, must equal the kernel's peer
  pid. A UI session; `surface` decides the locked wording.
- `/agent/register` (a `hook-*` or `gated` entry point): the claimed pid (or
  the nearest Claude Code process above the hook) must be above the peer and
  be Claude Code (`claude_ok`): a hook can't register its parent shell.
  The vault client registers by itself when a hook meets `not_registered`.
- A registration needs a readable start time. Persisted in
  `gated-sessions.json`, re-checked (pid and start time) when loaded and on
  each tick.

## Events (events.py) and the contract routes

`EventLog(dir, epoch, ring=2000, disk_max=2_000_000)`: `emit(kind, **fields)`
keeps only the kind's allowlisted keys, each a bool, a number, None or a
short safe-charset string (`clean`); anything else never becomes part of an
event. `since(seq, wait, epoch=None)` long-polls (≤ 25 s on the route); a seq
from another epoch (named, or past this epoch's end) starts over with
`reset: true`; `truncated` says older events left the ring. Kinds now:
`daemon.started`, `daemon.stopping`, `daemon.draining {reason, terminals,
jobs, resumed}` (0.9.1; the plugin uninstalled while work runs; new within v1, which
allows new kinds), `session.registered`, `session.ended`,
`vault.wrapped`, `vault.unlocked`, `vault.locked`, `auth.waiting`,
`auth.supplied`, `pause.applied`, and since phase 5 `job.started`,
`job.state`, `job.exited`, `job.output` (counts), `terminal.opened`,
`terminal.owner`, `terminal.closed`, since phase 6 `host.state {host, name,
state, reachable, auth, runtime, identity}` (remote.md), and since phase 7
`rights.changed {entry, change}` (widened after the OK, narrowed, removed;
`Daemon.watch_rights` in the ticker), `account.state {account, state}` and
`policy.denied {host, account, workspace, action, entry}` (never the
command); `pause.applied` gains `replayed` for a repeated `pause_id`.

- `/v1/capabilities`: `{contract: 1, contract_id, gateway_version, features:
  ["hosts", "events", "pause", "jobs", "terminals", "remote", "workspaces",
  "accounts", "pause_id"], epoch, limits}`.
- `/v1/snapshot`: `{contract: 1, seq, epoch, hosts, workspaces, accounts,
  terminals, jobs}` (since phase 7: hosts carry `rights`, the effective
  allow/ask/deny per action from `policy.rights`; `workspaces` are `{workspace:
  w_..., name, host, host_name, root, local?}`; `accounts` are `{account, kind,
  state, checked_at?, rights}` from the adapters' last checks, docs/modules/policy.md
  and accounts.md; a locked vault gives `state: "unknown"`. Snapshot reads use
  `broker.read(touch=False)` and `Daemon.effective(touch=False)`, so polling
  never keeps an idle vault unlocked) (terminals and jobs: terminals.md, "Routes"); a host is `{host: m_<26 base32>, name, local, address,
  identity}`: localhost's id is derived (sha256, not reversible) from the
  machine id (`identity: "machine"`), a remote host's is assigned on first
  sight and kept in `machine-ids.json` (`identity: "assigned"`; since phase 6
  `identity: "verified"` with the host's `machine` token once the gateway met
  it, `same_machine`, `reachable`, `auth`, `runtime`, `runtime_version`,
  `platform`: remote.md; the id itself stays the assigned one). The address
  is the form's own text.
- `/v1/events?since=N&wait=S[&epoch=E]`: `{contract: 1, events, next, epoch,
  truncated, reset}`.

### Pause and resume binding, pause_id (phase 7)

`/v1/pause` and `/v1/resume` act only on the caller's own session
(`server._pause_session`): its id or pid key, or a session id whose
processes are all the caller's Claude Code pid (a `/clear` or resume started
a new id under the same process). Another live session is refused (403
`session`); a session that has ended may be named only with `task_ref`, and
then only that task's jobs are touched. `pause_id` (at most 64 characters of
`[A-Za-z0-9._:-]`) makes a repeat idempotent: the first answer is kept in
`Dialogs.replays` (24 h, at most 2000, persisted with the dialogs' state) and
returned with `replayed: true`, nothing applied again. Independently, a job a
pause already interrupted or suspended is never signalled again by a later
pause (`Supervisor._pause_one`: "already interrupted ..." / "already
suspended ...").

### Routes added in phase 7

- `GET /ui/manage` (UI plane): the `/gate-hosts` and `/gate-accounts` panes'
  view (`Daemon.ui_manage`: hosts with identity, reachability, auth, runtime,
  rights and pending changes; workspaces; accounts with state, login, the
  credential's kind and pending changes; never a value).
- `POST /agent/remote/inspect` (agent-term plane, the gw MCP server's
  `host_inspect` for a remote host): `RemoteHost.inspect`, read-only, decided
  by the host's `read` policy (remote.md).

## The broker (broker.py, agepass.py)

Key modes (`vault.key_mode()`): `none`, `unwrapped` (key.txt, every vault
made before this phase), `wrapped` (key.wrapped + key.recipient, no key.txt).
`/health`'s `vault`: `none | unwrapped | locked | unlocked`.

- Unwrapped: nothing changes for the other processes (they decrypt locally;
  a same-user process can read key.txt anyway, so brokering adds nothing).
  The daemon reads key.txt when it needs to.
- Wrapped: `vault.brokered()` is true in every gateway process but the
  daemon: `load()`, `save()`, `cache_load()`, `cache_save()` and
  `transfer.decrypt_own()` go to the daemon (`client.py`); the daemon
  decrypts with the identity it holds (`vault._DAEMON_IDENTITY`), passed to age
  on an inherited pipe (`/dev/fd/N`), never a file or a command line. Writes
  encrypt to key.recipient. `ensure_key()` never makes a new key.txt beside a
  wrapped key.
- `Broker.set_passphrase(pw)` (at least 12 characters, at most 512 bytes in
  UTF-8, no control characters: age reads the passphrase as one tty line,
  and a line near macOS's 1024-byte limit never ends, so age waited out its
  130 s timeout; `agepass` refuses a longer one before age starts,
  `PassphraseTooLong`, for export and import too): key.txt's identity
  encrypted with age's scrypt recipient (`agepass.encrypt`, the private-pty
  driver moved out of transfer.py) into a temp file, unwrapped again from
  that file and compared (identity and recipient). That part (seconds of
  scrypt) runs without the vault's flock and the broker's mutex; then, under
  the flock and then the mutex (a vault writer holds the flock while the
  daemon merges its write, so the mutex is never held while waiting for
  it), key.txt is checked to be still the key that was wrapped, the key to
  open the vault, and key.recipient and key.wrapped are put in place and
  key.txt removed (each step fsynced). A failed check removes the temp file
  and changes nothing. Refused while a 0.6 store waits for migration, or when
  the key is already wrapped.
- `unlock(pw)`: refuses a passphrase the wrap never accepts (over 512 bytes,
  control characters), unwraps key.wrapped (`BrokerError` "that passphrase
  doesn't unlock the vault"; scrypt outside the mutex), checks the identity
  against key.recipient (a mismatch leaves it locked), keeps the identity in
  memory, and touches `<run>/gated-unlocked`, after which the managed shell's
  next command renews its settings (approved imports are in the vault;
  docs/modules/managed.md).
  `lock(reason)` forgets it (explicit `/ui/vault/lock`, `/agent/vault/lock`,
  `gate lock`; `idle` after the form's `[vault] lock_after`, default 8h,
  "1m" to "1d"; `exit`). Each vault read or write counts as a use. Python
  can't wipe a string: the identity's memory is freed, not erased.
- `read()` keeps the decrypted vault while `vault.age` stays the same file
  (mtime, size, inode) and the key unlocked; a write and a lock forget it.
  The daemon already holds the identity, so the copy adds no reach; it
  saves the other processes a decryption each, since they ask on every
  read.
- The passphrase reaches the daemon only through its own dialogs
  (`lifecycle.vault_dialog`): "set a vault passphrase" (two fields that must
  match, at least 12 characters) wraps an unwrapped vault (`set_passphrase`:
  wrap, verify by unwrapping, then key.txt goes), and the unlock dialog
  (`unlock`; "That didn't work" up to 3 times). `/ui/vault/unlock`
  (`/gate-unlock`) opens whichever applies; a locked vault read from a
  session that can draw dialogs opens the unlock dialog by itself (once per
  session at a time). `/ui/vault/lock` (`/gate-lock`) locks at once. The
  test routes stay for tests.

Scoped data: `scope_for(mode)` names the secret classes a mode may see:

| mode | classes |
|---|---|
| `shim sudo` | `sudo_local` |
| `shim ssh`, `shim scp`, `shim sftp` | `ssh_hosts`, `sudo_hosts`, `account_keys` |
| `git-credential`, `mcp` | `tokens`, `signins`, `cache` |
| `shim gh/hf/databricks/crane/pijul/az/asiml/dvc` | `tokens`, `signins`, `account_keys`, `cache` |
| `gate`, `shim gate`, `hook-*` (they mask output) | all |
| `hook-files`, `hook-daemon`, `askpass`, `gated`, anything else | none |

`make_view` replaces every value the peer may not see with a sentinel
`gw-redacted:<32 hex>` (HMAC-SHA256 with a per-daemon random key, so it says
nothing about the value); `vault.is_redacted` recognizes one and
`all_values`/`labeled_secrets` skip them. A peer that isn't a direct caller
(`ancestry.walk_direct` from its parent up to its session, with the tool its
mode names) also gets sentinels for every entry without an effective
`scripts = true` (consent, computed by the daemon). `merge` swaps sentinels
back for their values and raises `Conflict` (409) when the written document
adds, changes, moves or drops a value the writer couldn't see. The token
cache: `cache_view`/`cache_merge` (no cache class: empty view, writes
refused; withheld accounts kept as they are). The client (`client.vault_read`)
asks the daemon on every read and keeps nothing between reads, so a lock (or
an ended session, or a narrower scope) applies at a process's next read,
also in one that runs for the whole session (the MCP server's http and
download tools): it gets `VaultLocked` then. (Before, the view was kept for
the process while `vault.age` stayed the same file, and a long-running
process kept sending credentials while /health said locked.)
A daemon that takes a vault request but doesn't answer (`client.Unresponsive`:
stopped, hung) is never started again; a hook gives it `HOOK_TIMEOUT` (5 s;
everyone else 15 s), then marks it (`<run>/gated-unresponsive`, the pid
contract.json names) and the next hooks skip it for `UNRESPONSIVE_TTL` (30 s)
while that daemon lives; its next answer (a refusal too) clears the mark. The
hooks fail open as they always did on an unreachable daemon (no decision;
masking by shapes only, `scrub.vault_values` is empty): a hung daemon now
costs one 5 s wait per 30 s instead of 15-50 s in every hook of every call
(acceptance 2026-10-21: each Bash call stalled about 12 s). The mark is a
convenience in the user's run dir, not a boundary: a command that can write
it could as well stop the daemon.

Refusals: a locked vault is 423 with the daemon's wording for the caller's
session (`server.LOCKED_INTERACTIVE` when the session's mod registered with a
surface, else `LOCKED_HEADLESS`); `vault.VaultLocked` carries it. A daemon
that can't be reached, or that won't give this program data (403), is also
`VaultLocked` (`client.Refused`) for a wrapped key. run.py refuses a stand-in
up front with that message (its rights are in the vault too); githelper, the
http tool and the Bash hook (a right waiting in the locked vault) give it
verbatim; SessionStart says the vault is locked; PostToolUse masks token
shapes only while it is locked (nothing can get a value then).

## Dialogs (dialogs.py, clipboard.py)

The requests behind every question the gateway asks (DECISIONS "PLAN-v4
phase 3"; popup.py and dialog.py are the asking side, `hooks/mod/` the
drawing side).

- **Lease.** `POST /agent/dialog/lease` (agent plane: a gateway entry point
  below a registered session) answers `{available: false, reason, message}`
  when the session can't draw a dialog (`Dialogs.available`: no session,
  mods off (no UI registration), `-p`/SDK (no surface), only mobile or VS
  Code, paused) and otherwise a lease token (32 random bytes, hex; gated
  keeps its sha256 with the session, the asking pid and its start time;
  35 min). The detached helper presents the token on the lease plane; a
  lease ends when it expires, is released, or every process that used it
  has died.
- **Request.** `/lease/dialog/open` with a spec (kind `secret confirm
  choice checklist text info`, fixed lines checked for size and control
  characters, entry and what, options, labels, fields, remember, paste, the
  form entry to recheck): an id `d_<16 hex>`, a deadline (at most 30 min),
  and for a secret an X25519 key pair (PyNaCl) for this attempt. One dialog
  at a time per session (oldest first); the rest are `queue` items (id,
  kind, entry, what). At most 50 open in all.
- **The mod's loop.** `GET /ui/dialog/next?rev=N&wait=S` (long poll, at
  most 25 s) answers `{rev, dialog, queue, recent, available}` for the
  calling session: the dialog's public view (texts, labels, attempt, error,
  state, expires_in, the public key; never a value), the queue by identity,
  the recently closed ones with their outcome (for a toast).
- **Sealed intake.** `POST /ui/dialog/submit` `{id, attempt, epk, nonce,
  box, remember?}`: a body with `value` or `values` is refused (400
  `plaintext`); sizes checked; `Box(attempt key, epk).decrypt` (400 `box`
  when it doesn't open, `stale` for another attempt); the plaintext must be
  JSON `{rid, a, v}` naming this request and attempt, values of at most
  8 KiB without control characters (a two-field passphrase must match); the
  bytes are overwritten once parsed. Then the recheck (`_recheck`: still
  open, before its deadline, its session alive with the same start time and
  not paused, the lease's processes alive, the form entry still there with
  the same section, kind and rights, in the form and in the effective
  rights): a failed recheck closes the request (failed, cancelled, timeout
  or paused) and nothing is handed over. The key pair is dropped and the
  request goes to "checking". The spec's `check` names what is rechecked:
  `{"section": "hosts", "entry", "right": "sudo" | "ssh" | [...]}` (every
  right in a list: a remote sudo names `["ssh", "sudo"]`) or `{"section":
  "accounts", "entry", "kind"}`. The callers that name one: the sudo
  stand-in (`sudo.SUDO_CHECK`), gate check's sudo steps
  (`gate_setup.sudo_check`), remote sudo and the login password
  (`ssh.host_check`), the account setups (`gate_setup._account_check`). A
  dialog without `check` gets no form recheck (the phase 3 review found
  every sudo and ssh dialog in that state). "Paused" is gated's own pause
  record (`/v1/pause`), which checkpoint (0.6+) sends on every pause while
  gated serves its session.
- **Remember it.** A secret dialog whose spec has `remember` (True or
  False: its default) offers the choice; the post's `remember` is the
  person's, and a post without one takes the dialog's default. The helper
  gets it with the value (`answer.remember`) and stores only when it is
  true. Offered by the sudo stand-in and remote sudo (ticked).
- **Hand-over.** `/lease/dialog/wait` (long poll) gives the helper the
  answer once (a secret's value, a choice, the picked items, an outcome)
  and forgets it. The helper verifies and answers `/lease/dialog/retry`
  (reopened with "That didn't work: WHY", a new key pair, attempt + 1; after
  3 the request fails) or `/lease/dialog/close` (ok, failed, cancelled).
- **The person's other answers.** `/ui/dialog/answer` (a choice, the
  checklist, a typed text, OK), `/ui/dialog/cancel`, `/ui/dialog/paste`
  (`{id, env}`: the display variables from Claude Code's own environment,
  checked by pattern; gated runs the clipboard reader outside its lock and
  takes the text as if typed: `clipboard.accept`, one line, at most 8 KiB,
  no control characters).
- **Clipboard** (`clipboard.read(env)`): macOS `/usr/bin/pbpaste -Prefer
  txt`; Linux `wl-paste --no-newline --type text/plain` (Wayland), else
  `xclip -selection clipboard -o`, else `xsel --clipboard --output`, each
  only from a fixed system folder and only when the file (after symlinks)
  is root's, not group/other-writable and executable. Under any test
  override only the `clipboard` knob's program (an absolute path) runs, or
  nothing: a test never reads the person's clipboard.
- **Cleanup.** Closing a request (any outcome, its session ending, its
  lease ending, a pause, the deadline) drops its key pair and any answer
  not yet handed over and records `auth.supplied {request, outcome}`.
- **Survival.** `<run>/gated-dialogs.json` (metadata, lease hashes, paused
  sessions) is written on every change and read at start: a gated killed
  mid-dialog comes back (the helper's next call or the mod's loop starts
  it) with the same requests and new key pairs; `/reload-plugins` loses only
  the mod's memory.
- **Pause.** `/v1/pause {session, task_ref?}` (contract plane) records the
  Claude Code session as paused, closes its open dialogs ("paused") and
  refuses new leases and answers for it until `/v1/resume`; persisted with
  the dialogs. Since phase 5 it also applies each of the session's jobs'
  `on_pause` (only the task's with `task_ref`) and holds that session's agent
  input to terminals and new jobs; the outcomes say what happened
  (terminals.md, "Jobs"). `features` includes "pause".
- **Terminal password prompts** (phase 5): `Dialogs.open_owned` makes a
  secret dialog gated itself owns (owner "terminal") whose answer goes to the
  supervisor's handler (`_supply`), which types it into that pane after its
  recheck; a failed recheck closes the dialog as failed; such dialogs aren't
  persisted (the prompt is asked again if it still waits after a restart).
- **The vault's dialogs** (`lifecycle.vault_dialog`): `passphrase` (two
  fields) and `unlock` kinds, owned by gated itself (no lease): the answer
  goes straight to the broker on a worker thread.
- **gated's own confirmations** (phase 6, remote.md): `open_owned(...,
  kind="confirm" | "info")`, owner "gated", never persisted: a remote host's
  changed host key or machine (default Cancel; the handler pins or stores on
  the OK only, and the host stays blocked until then) and the notice that a
  host refused the gateway's key. gated can't ask through popup.py (that
  takes a lease from gated as a client).

## /gate-doctor, gate status, gate lock

`/gate-doctor` (the mod) runs `launch.sh gated status` and shows "Gateway
daemon: running (VERSION, epoch N, up T, K sessions); vault STATE" or "not
running (it starts when a session or tool needs it)" (`lib.daemonLine`),
followed by the version skew when the daemon's version differs from that
plugin copy's ("a newer gateway daemon (X) answers this plugin (Y); start a
new session ..." or "an older gateway daemon (X) answers this plugin (Y); it
is replaced when a session of this plugin starts and it holds no terminals
or jobs"). `gate status` ends with the same facts (`gate.daemon_line`, never
starts the daemon); `gate lock` locks a wrapped vault (or says there is
nothing to lock).

## Known limits

- Guardrail, not boundary: same-user code can impersonate an entry point
  (run the env's python on the real run.py with any mode, or put a folder
  into the plugin cache beside the installed version), ptrace or read the
  daemon's memory, or connect while a session lives.
- A detached process outside a registered session (a checkpoint job left
  running after its session) gets no vault data from a wrapped key, and no
  dialog (it has no session to draw one). A process inside a gateway
  terminal or job counts as its pane's owner session while that session
  lives (`Registry.pane_session`, terminals.md), and gets nothing after.
- A handed-over secret is a Python string in gated and in the helper for as
  long as they use it (it can't be wiped; the box's plaintext bytes are).
- An npm-installed Claude Code runs as `node`: it isn't recognized as Claude
  Code, so it can't register (nothing changes for an unwrapped vault).
- Remote host ids are assigned (stable); their machine identity is verified
  since phase 6 (remote.md) and shown beside the id.
- `lock_after` isn't under the widening rule yet (bounded to one day).
- The mod's registration from inside Claude Code (`$.http.fetch` with
  `socketPath`) was verified in a live interactive session (TUI harness,
  scratch config, fake API, 2.1.301 on macOS: the kernel's peer pid was the
  claude pid); the desktop app and `claude -p` (the hook route) weren't run
  live. Recognising Claude Code by executable: named `claude`, or under the
  person's own `~/.local/share/claude/versions/` or the desktop app's
  folder, whatever home a test or e2e override gives the gateway (the live
  run found the native install's `versions/2.1.301` refused under the e2e
  home first; fixed).
