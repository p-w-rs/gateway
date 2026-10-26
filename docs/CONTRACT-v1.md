# Gateway ↔ Checkpoint integration contract, version 1

Small, versioned, additive. Gateway is the provider (it owns hosts, accounts, terminals,
jobs and execution state); Checkpoint is a consumer (it owns task history, pause intent and
recovery). Either plugin works without the other. Checkpoint keeps a copy of this file at
`docs/CONTRACT-v1.md`; the two copies must stay identical (each repo's tests check its copy
against the version string below).

Contract id: `gateway.v1`

## Discovery

Gateway's daemon writes `~/.config/gateway/run/contract.json` (0600, directory 0700) when it
starts and removes it when it stops:

```json
{ "contract": "gateway.v1", "versions": [1], "gateway_version": "0.9.0",
  "socket": "/tmp/gw-501/gated.sock", "pid": 12345, "started": 1792450000.0, "epoch": 7,
  "machine_id": "m_...", "features": ["hosts", "events", "pause", "jobs", "terminals",
  "remote", "workspaces", "accounts", "pause_id", "job_env"] }
```

A consumer treats a missing file, a dead `pid`, an unknown `contract`, or a `versions` list
without 1 as "gateway not available" and says so (it never guesses). The socket is reached
with HTTP/1.1 over a Unix stream socket. Peer identity is checked by the daemon
(`getpeereid`/`SO_PEERCRED`): contract calls are accepted from processes of the same user
whose ancestry reaches a Claude Code session; UI-plane calls are refused on this contract.

`features` says what this daemon serves; a consumer uses a feature only when it is listed
(a field of a feature the daemon doesn't list is ignored by that daemon). Added within v1:
`remote` (gateway 0.8: terminals and jobs on remote hosts in the gateway's managed remote
runtime), `workspaces`, `accounts` and `pause_id` (gateway 0.9), `job_env` (gateway 0.11).

## Messages

Every response is JSON with `"contract": 1`. Unknown fields must be ignored. New fields and
new event kinds may appear within v1; removing or changing the meaning of a field needs v2.
Nothing on this contract ever carries a raw credential, unlocked vault data, typed password
input, or a credential-bearing command string: commands are sent through Gateway's scrubber
before they are returned or published.

Refusals are `{ok: false, error: <code>, message}` with an HTTP status; `message` is safe to
show. A policy refusal (gateway 0.9) also carries `rule`: the concrete rule that refused it,
as the person wrote it (for example `[hosts.build.policy] exec = "deny" (gateway.toml line 12)`).

### Identifiers

- `host`: the host record's stable id (`m_<26 base32>`), plus its display `name`. This
  machine's id is derived from its machine identity; a remote host's id is assigned at first
  sight and kept; once the gateway has met the host, its verified machine token is reported
  beside it (`machine`). The same path on two hosts is two resources.
- `workspace`: `w_<26 base32>`, a named root on one host; the id is bound to that host's id
  and the root, so the same root on another host is another workspace.
- `terminal`: `t_<ulid>`; `job`: `j_<ulid>`; `op`: `o_<ulid>`.
- `session`: Claude Code session id; `agent`: subagent id when present; `task`: the
  consumer's opaque task reference (`task_ref`), stored and echoed, never interpreted.
- `account`: an account's name in the gateway's form (never a credential).

### Calls

| Call | Purpose |
|---|---|
| `GET /v1/capabilities` | `{contract, gateway_version, features, limits}` |
| `GET /v1/snapshot` | `{seq, hosts[], workspaces[], accounts[], terminals[], jobs[]}`: sanitized state at `seq` |
| `GET /v1/events?since=<seq>&wait=<s>` | `{events[], next}`; long-poll up to `wait` (≤ 25 s). Events carry `seq` (strictly increasing per daemon epoch), `epoch`, `ts`, `kind`, ids. A consumer that sees a new `epoch` re-reads the snapshot. |
| `POST /v1/jobs` | start a job: `{argv \| command, host, workspace?, cwd?, session, agent?, task_ref?, idempotency_key, on_pause?, env?}` → `{job, op, state}`. The same `idempotency_key` within 24 h returns the original job instead of starting another. |
| `GET /v1/jobs/<job>` | `{job, state, exit?, signal?, started, ended?, host, cwd, command (scrubbed), owner, on_pause}` |
| `GET /v1/jobs/<job>/tail?bytes=<n>` | last ≤ 64 KiB of scrubbed output, `{text, truncated, offset}` |
| `POST /v1/jobs/<job>/signal` | `{signal: "INT"\|"TERM"\|"KILL"\|"STOP"\|"CONT"}` → `{state}` |
| `POST /v1/pause` | `{session, task_ref?, reason, pause_id?}` → per-job outcomes `[{job, policy, outcome}]` |
| `POST /v1/resume` | `{session, task_ref?, pause_id?}` → per-job outcomes |

Job `state`: `starting`, `running`, `waiting_input`, `waiting_auth`, `suspended`,
`disconnected`, `exited`, `failed`, `canceled`, `unknown`. `unknown` is used whenever
Gateway cannot prove the state (for example a remote host it cannot reach); it is never
reported as finished.

`on_pause` policy per job: `continue` (default; keeps running, reported), `interrupt`
(SIGINT, then TERM after 10 s), `suspend` (SIGSTOP; only for local jobs and remote jobs in
the managed runtime; refused otherwise), `detach` (same as continue but the job is released
from the task). The outcome reports what actually happened.

#### Snapshot records

- `hosts[]`: `{host, name, local, address, identity, runtime, rights}`. `identity` is
  `machine` (this machine), `assigned` (a remote host not met yet) or `verified` (met: then
  also `machine`, its machine token, and `same_machine`, true when that token is this
  machine's). A remote host adds `reachable`, `auth` and `runtime` as of the gateway's last
  contact (`true`/`false`/`null` for unknown; `runtime` is `ready`, `missing`, `staging`,
  `failed` or `unknown`; localhost's is `ready` or `missing`), and `runtime_version` and
  `platform` once staged (gateway 0.8). `rights` (gateway 0.9) is the effective decision per
  action, each `allow`, `ask` or `deny`: `read`, `exec`, `write`, `network`, `elevation`,
  `credential`, `env_import`, `provision`, `forward_agent`, `forward_x11`, `forward_remote`,
  `forward_stdio` (this machine: `read`, `exec`, `network`, `elevation`, `credential`,
  `env_import`).
- `workspaces[]` (gateway 0.9): `{workspace, name, host, host_name, root, local?}`: `root`
  is the folder on that host, `local` the matching folder on this machine when a path
  mapping is set.
- `accounts[]` (gateway 0.9): `{account, kind, state, checked_at?, rights}`. `state` is
  `configured` (a credential is stored, not checked yet), `connected` (the last check
  through the account's adapter succeeded), `expired`, `revoked`,
  `reauthentication_required`, `missing` (no credential) or `unknown`; the gateway tells
  them apart from the service's answers and never equates a browser login with API access.
  `rights` holds `credential`, `write` and `network`.
- `terminals[]`: `{terminal, host, host_name, state, owner, session, cwd, created,
  task_ref, workspace?}`.
- `jobs[]`: as `GET /v1/jobs/<job>`, plus `host_name`, `task_ref`, `workspace` and, when
  they apply, `gone`, `detached`, `remote`, `note`, `start_confirmed: false` (a remote start
  whose answer was lost; the gateway asks the host) and `stop_requested`.

#### Binding

- `POST /v1/jobs`: `session`, when given, must be the caller's session. `workspace` (an id
  or the workspace's name on that host) binds the job to that workspace: `cwd` defaults to
  its root and must lie inside it (a path under the workspace's `local` folder is mapped to
  the host's root); a workspace of another host is refused (409 `workspace_host`). The
  gateway's policy for that host, workspace and action applies (403 `policy`, with `rule`).
- `POST /v1/pause` and `/v1/resume` (gateway 0.9): `session` must be the caller's own
  session (by id, or a session of the caller's Claude Code process); naming another session
  that is still alive is refused (403 `session`). A session that has ended (no live Claude
  Code process registered under it) may be named only together with `task_ref`, and then
  only that task's jobs are touched (a task picked up in a later session).
- `env` (feature `job_env`): the job's environment, an object of variable names to string
  values (a session's whole environment will do). A job on this machine gets the first 400
  variables whose name is a shell name (letters, digits and `_`, not starting with a digit, at
  most 64 characters) and whose value is at most 8192 characters of UTF-8 without NUL, minus
  the ones Gateway's managed shell removes (Claude Code's own credentials, the shell's startup
  variables, Gateway's own) and the ones Gateway or its terminal sets itself (`HOME`, `USER`,
  `LOGNAME`, `SHELL`, `TERM`, `PWD`, `OLDPWD`, `SHLVL`, `COLUMNS`, `LINES`, `TMUX`,
  `TMUX_PANE`, `CLAUDE_PID`); anything else is skipped. `PATH` is Gateway's stand-ins, then
  the `PATH` given. Only an `env` that isn't an object of strings, or whose kept variables
  come to more than 256 KiB (UTF-8 bytes), is refused whole (400 `bad_env`), and then
  nothing starts. Without `env` the job gets Gateway's plain managed environment. A job on a
  remote host keeps that host's managed environment (`env` is ignored there).
- `pause_id` (feature `pause_id`): an opaque id of at most 64 characters
  (`[A-Za-z0-9._:-]`). A pause or resume repeated with the same `session` and `pause_id`
  within 24 h returns the first answer with `replayed: true` and applies nothing again (no
  second signal). Independently of `pause_id`, a job a pause already interrupted or
  suspended is never signalled again by a later pause (`outcome` says "already ...").

### Event kinds (v1)

`job.started`, `job.output` (counts only, no text), `job.state`, `job.exited`,
`terminal.opened`, `terminal.owner` (agent/user), `terminal.closed`, `host.state`
(`host`, `name`, `state`, `reachable`, `auth`, `runtime`, `identity`), `auth.waiting`,
`auth.supplied` (no value, only the request id and outcome), `pause.applied` (`session`,
`paused`, `task`, and `replayed` for a repeated `pause_id`), `daemon.started`,
`daemon.stopping`; also `session.registered`, `session.ended`, `vault.wrapped`,
`vault.unlocked`, `vault.locked` (gateway 0.7), and since gateway 0.9 `rights.changed`
(`entry`, `change`: `widened` after the person's OK, `narrowed`, `removed`),
`account.state` (`account`, `state`) and `policy.denied` (`host`, `account`, `workspace`,
`action`, `entry`: what was refused and under which entry, never the command), and since
gateway 0.11 `vault.unwrapped` (the passphrase removed: the vault key is kept without one)
and `vault.started_over` (a locked vault whose passphrase was lost moved aside: there is no
vault until the next store).

## Compatibility

- Checkpoint without Gateway: its own detached job runner and its stated limits.
- Gateway without Checkpoint: Gateway keeps its own job records and works alone.
- Mismatched versions: a consumer that does not find `1` in `versions` reports
  "gateway contract mismatch (has X, needs 1)" in its diagnostics and works alone.
- Older gateways (before 0.9) ignore `pause_id` and accept any well-formed `session` on
  pause and resume; a consumer checks `features` before relying on either.
