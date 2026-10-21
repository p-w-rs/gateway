# Terminals and jobs (gated's supervisor)

PLAN-v4 phase 5 (2026-10-20); remote panes since phase 6 ([remote.md](remote.md)). Code: `plugins/gateway/src/gateway/daemon/terminals.py`
(the supervisor), `daemon/screen.py` (pure screen, stream, key and signal helpers), the
routes in `daemon/server.py`, the agent tools in `mcp_server.py`, the terminal pane in
`hooks/mod/{terminal.ts,term.tsx}` and `register.tsx`, the sudo stand-in's terminal route
in `sudo.py`, the approval hook's judging of `job_start`/`terminal_send` in
`hooks_bash.py`, the permission decisions in `hooks/mcp_perm.sh`. Tests:
`tests/test_terminals.py`, `hooks/mod/terminal.test.ts`; mutations:
`tests/mutations_terminals.py`; live: `tests/acceptance_terminals.py` (the TUI harness).
Why it is built this way: [DECISIONS.md](../DECISIONS.md), "PLAN-v4 phase 5: terminals
and jobs". The contract side is [CONTRACT-v1.md](../CONTRACT-v1.md) ("Calls").

## What it is

Persistent, PTY-backed terminals and jobs that Claude and the person share, owned by
gated (not by a tool call, a session or the MCP server), with one writer at a time and
password prompts answered through the gateway's own credential dialog.

```
Claude Code ── gw MCP server ──(agent plane: /agent/term/*, /agent/job/*)──┐
     │  (terminal_* and job_* tools; JSON-RPC on stdio only)              │
     └─ gate mod: /gate-terminal pane ──(UI plane: /ui/term/*)────────────┤
checkpoint's MCP server ──(contract plane: /v1/jobs..., /v1/pause)────────┤
                                                                          ▼
gated: Supervisor ── tmux -S <run>/tmux.sock -f <run>/tmux.conf ── panes (bash, jobs)
          │            (the env's tmux; its own server and config)
          └─ <data>/gated/terminals.json (records)   <run>/terms/ (start files, FIFOs)
```

PTY traffic never touches the MCP server's stdio: the server only sends JSON requests
to gated and gets bounded JSON back.

## The tmux server

- Binary: the gateway env's tmux (pixi.toml `tmux = "3.*"`, tmux 3.8 in the lock;
  `paths.tool("tmux")`, next to gated's python); a test may name a wrapper (the
  `tmux` knob). Socket `<run>/tmux.sock` (0600 in the 0700 run dir), config
  `<run>/tmux.conf` written by gated at start (`TMUX_CONF`): `remain-on-exit on`,
  `history-limit 10000`, `status off`, `set-clipboard off` (no OSC 52 to the OS
  clipboard), `window-size manual`, `mouse off`, `allow-passthrough off`,
  `update-environment ""`, `default-terminal screen-256color`, `escape-time 0`,
  `exit-empty on`. Every tmux command gets `-u -S <sock> -f <conf>`: the user's
  `~/.tmux.conf` and tmux server are never read or reached (a test plants one).
- The server starts with gated's small fixed environment (PATH, HOME, LANG,
  TMPDIR), never Claude's. It is detached: it outlives a Claude Code restart, a
  plugin reload and gated itself.
- A terminal is a tmux session `t_<ulid>` with one window running
  `<env bash> --noprofile --rcfile <run>/terms/<id>.<nonce>.rc -i`; a job is a session
  `j_<ulid>` running `<env bash> --noprofile --norc <run>/terms/<id>.<nonce>.sh`.
  Each session gets a random nonce as the tmux option `@gw_nonce`; a pane is gated's
  only when its name and nonce match a record.

## The managed environment a pane gets

`terminals.env_plan(caller_env)` and `start_text(...)`:

- The start file (0600, written with O_EXCL) first unsets every variable but the
  platform's (`KEEP_NAMES`: HOME USER LOGNAME LANG LC_* TERM TMPDIR TZ XDG_*
  __CF_USER_TEXT_ENCODING SHLVL PWD OLDPWD COLUMNS LINES; so TMUX and TMUX_PANE go:
  a pane's programs can't drive the gateway's tmux by its variables), then exports
  the plan: PATH from the managed shell's conf (`managed.conf_path()`: stand-ins,
  runtime tools, approved import_path folders, system dirs), HOME, USER, LOGNAME,
  SHELL (the env's bash), LANG, the platform variables and approved imports the caller
  (the gw MCP server, from Claude Code's environment) passed, never a
  credential-looking name unless it is one of the user's own "mine" names under
  `others = "mine"`; `GW_TERMINAL=<id>`; `CLAUDE_PID=$$` (the stand-ins' direct rule:
  what runs there is direct as in Claude's shell, a program between it and the stand-in
  not; never "typed": a `CLAUDE_PID` naming a shell is never Claude Code, so an `"ask"`
  right or policy is refused in a pane, `ancestry.TERMINAL`); then it
  sources the managed rc (`managed.rc_path()`: the env file's stand-ins and git setup,
  never the user's rc), removes itself, `cd`s into the cwd. A terminal also gets no
  history file (`unset HISTFILE`), `histexpand` off and a plain prompt.
- Values never reach a command line (any local user can read those): they go in the
  start file, which the pane removes once read (a test checks `ps` and the run dir).
- A job runs `command` (bash) or `argv` (quoted, as a child of the script's bash, never
  exec'd: the direct rule then treats the program like a command typed in a shell).

## Records, survival and re-adoption

`<data>/gated/terminals.json` (0600, written whole): per pane `id, kind, nonce, host
(localhost), host_id (m_...), workspace, cwd, created, session_pid/start/id (the owner
session), agent, owner (agent | user), holder, task_ref, command (scrubbed, 500 chars),
on_pause, idempotency_key, state, exit, signal, ended, seq, cols, rows, detached,
paused_as, cancel, closing, gone, via (agent | ui | contract | adopted), title`, and the
idempotency keys (24 h). Never screen content, input or a value. It lives in the data
folder, which survives a reboot, while tmux's socket lives in the run dir, which a
reboot empties: so after a reboot every record is reported gone, not forgotten.

- **Claude Code restart, plugin reload**: nothing changes (tmux and gated outlive the
  session). The new session lists the terminals (`terminal_list`); one whose owner
  session ended is adopted by a read with `take: true`.
- **gated crash or restart**: `Supervisor.adopt()` lists tmux's panes and matches each
  live record by id and nonce: matched panes are adopted with their ids, owners and
  states; a job's output pipe is restarted into a new FIFO and its ring seeded from
  tmux's history. A record tmux doesn't list (or lists with another nonce) is marked
  gone: a terminal `gone`, a job `unknown` (its outcome can't be proven; never
  "exited"). A session on the private socket with no record (records lost) is shown as
  an orphan the user can see and close.
- **Every tick** (0.25 s while anything is live, else 1 s) asks tmux again
  (`list-panes -a`): a pane tmux lost while gated runs is gone/unknown at once, a dead
  pane (`remain-on-exit`) gives its exit status or signal (`job.exited`). Nothing is
  ever claimed alive from a saved pid alone (`_lost`). But a *failed* query (a timeout,
  an `OSError`, a non-zero exit) is not proof the panes died: it is told apart from a
  dead server by the server's own pid (`_blip`/`_server_alive`), so while that process is
  alive a transient `list-panes` hiccup is ignored and the panes stay live (never marked
  gone for good); only when the server pid is gone — or unknown past `TMUX_GRACE` with
  the socket gone — are the panes reported gone. adopt retries a failed query a few times
  before concluding a restart found no server.
- **The run dir removed** (a tmp cleaner; the harnesses): gated exits (its socket is
  gone) and stops its tmux server, which nobody could reach again (`abandon`, by the
  pid tmux reported, only while it is still the env's tmux and names this socket on its
  command line: a reused pid, such as a remote runtime's tmux on this machine, is never
  stopped; phase 6). A gated that was stopped first (SIGTERM keeps the server for
  re-adoption) can't do that, so the local server has a watchdog session `gw-watch`
  (started with the first local pane; tmux execs it without a shell, so its parent is
  the server): every 5 s it checks that the socket it started with (by inode) is still
  there, and once it isn't, it sends the server SIGTERM (acceptance 2026-10-21: the TUI
  harness left `new-session -d -s j_...` servers behind). A `session-closed` hook in the
  local config (`LOCAL_TMUX_CONF`) closes the watchdog when it is the last session, so
  the server still ends with its last terminal (`exit-empty`). `gw-watch` is no
  terminal or job (no `t_`/`j_` id): adoption, lists and `busy()` ignore it.
- An exited pane's tmux session is kept an hour for reads (`RETAIN_DEAD`), its record
  24 h (`RECORD_KEEP`). Live panes keep gated from its idle exit and from a version
  restart (`Daemon.busy()`: "2 terminals and 1 job"); at most 64 live (`MAX_LIVE`).

## Reading

`capture-pane -p -e` with `display-message` in one tmux call (`_capture`): cursor,
alternate screen, size, history size, title, dead flag, the visible rows; with
`history` the last N scrollback lines (≤ 2000). `screen.split_escapes` turns each row
into plain text (for the agent) and styled runs (for the pane: SGR colours, bold, dim,
italic, underline, inverse, strike; every other escape and control character dropped).
`seq` counts changes of the plain screen, cursor, alternate flag, size and title, and
every ownership change. The agent's view (`view`) is bounded: lines ≤ 1000 characters,
64 KiB of text in all (visible first, then history from the newest), `truncated` and
`history_truncated` say so; trailing empty rows below the cursor are trimmed. Every
read is scrubbed (`scrub.scrub_text`: vault and cache values in all their forms, token
shapes, plus the values this pane was given through the dialog), the pane's view too
(a line that changed is drawn plain). PostToolUse (post.sh) masks the gw tools' results
again. Two paths that would otherwise slip a value past the per-line scrub are closed:
the **title** a program sets (OSC 2) is scrubbed where it is stored (`_mask` in
`_update`/`_capture`), so it is masked in `terminal_read`/`terminal_list`/`job_status`,
the pane view and the records; and the agent's plain lines are captured with
`capture-pane -J` (`_capture_joined`), which rejoins tmux's soft-wrapped rows into
logical lines so a value printed across a wrap boundary is one string the scrubber
catches, not two halves the agent could splice. `terminal_list`/`job_list` return at
most `LIST_MAX` records to the agent (live first, newest next, with the true total and
`truncated`); the pane's own list and the contract snapshot stay complete.

## Writing: one writer at a time

- `owner` is `agent` or `user`. The person takes the input from the pane: a click into
  the screen (fullscreen), a key, or the Take button (`/ui/term/take`, and every
  `/ui/term/keys` takes it first). That flips the owner at once, bumps `owner_gen` and
  `seq`, wakes every queued agent write, which then fails with "input taken by the user;
  re-read the screen" (409 `taken`), and emits `terminal.owner`. While the user holds
  it, agent writes, resizes and signals are refused (409 `user`).
- Hand back (`/ui/term/release`) makes the owner `agent` again with no holder, and bumps
  `seq`: the agent's next write must quote a seq from a fresh read.
- An agent write (`send`) quotes the seq it read; it is refused (409 `stale`, with the
  current seq) when the screen changed, checked when the write is queued and again
  right before it goes in (`_stale`). `delay_ms` (≤ 30 s) queues it; the pane shows
  "N queued from Claude".
- Among agents (the main loop, subagents) one holds the input: the first agent to write
  becomes the holder; another agent's write is refused (409 `holder`) until it reads
  with `take: true` (never from the user). The holder is `None` until someone writes, and
  the main agent's own loop id from the mod is the empty string, so "unclaimed" is `None`
  (not `""`): the main agent counts as a real holder once it writes, and a subagent can't
  write into the main agent's terminal without taking it over (and vice versa). Which
  loop called is learned from the mod: its `tool.call` hook posts `{tool_use_id, agent}`
  (`/ui/term/agent`, UI plane) and the gw MCP server passes the call's
  `_meta["claudecode/toolUseId"]`, so the mapping can't be claimed by the model. Without
  the mod every agent counts as one.
- The seq a read hands the agent is persisted at once (`_capture(..., persist=True)`), so
  it is never behind what a gated restart restores from the record. On a restart the
  re-adopt bumps every pane's seq, which then reliably lands strictly above any pre-crash
  seq: an agent write quoting a seq read before the crash is refused `stale`, and the
  agent must read again (even if the screen also moved on while gated was down).
- Writes from another Claude Code session are refused (403 `other_session`); a terminal
  whose session ended is adopted by a read with `take: true`. Writes and new jobs from
  a paused session are refused (`PAUSED`).
- Text goes in through `load-buffer -b gw<random> -` (on tmux's stdin) and
  `paste-buffer -d` (the buffer deleted as it is pasted; LF becomes Enter); named keys
  (`screen.tmux_key`: Enter, Tab, BTab, BSpace, Escape, arrows, Home, End, PageUp,
  PageDown, Insert, Delete, Space, F1-F12, C-a..C-z, M-x) through `send-keys`. Text with
  control characters is refused (keys carry those). No typed text is ever on a command
  line.

## Signals

`terminal_signal` sends to the terminal's foreground process group (ps's `tpgid`, as a
key would: INT is ^C); `job_signal` and the contract's signal to the job's process group
(the pane's root). TERM or KILL marks a job `canceled`. STOP suspends with
`stop_group`: tmux resumes a pane's own process when SIGSTOP stops it (its
`server_child_stopped` sends SIGCONT for any stop but SIGTTIN/SIGTTOU), so the root
gets SIGTTOU and the rest SIGSTOP, and the result is checked in `ps` (state T).

## Password prompts

Each tick reads every live pane's tty mode (`tty_mode`: the pane's tty opened
`O_NOCTTY|O_NONBLOCK`, owner-checked, `tcgetattr`, closed at once, since a slave held
open would keep a dead pane's tty from hanging up). ECHO off with canonical input
(ICANON on) means a program waits for a password: sudo, ssh, `read -s`, getpass (a
shell's readline and full-screen programs are ECHO off with ICANON off, so they don't
count).

1. A new prompt (signature: cursor, history size and the last line) opens a gated-owned
   secret dialog (`Dialogs.open_owned`, owner "terminal") in the pane's owner session:
   "Password for a gateway terminal", the terminal id, the foreground program's
   executable path from the kernel (never argv or the prompt's text, which a program
   chooses), Paste allowed. Where no dialog can open (`-p`, mods off, mobile, VS Code,
   no session) the pane is `waiting_auth` with a note saying so; nothing is asked any
   other way.
2. While it waits, the agent's writes are refused (409 `auth`), its reads say
   `waiting_auth` with a note, the pane says so in yellow, the pane's Client keeps typed
   text to itself and gated refuses text from `/ui/term/keys` (named keys such as Enter
   or ^C still go). A job is `waiting_auth`.
3. The sealed answer (phase 3's field and box) reaches the handler (`_supply`) on a
   worker thread, which rechecks: the same dialog token, the pane alive, the tty still
   ECHO off with ICANON on, the same foreground process group as when the dialog
   opened. Then (state `supplying`, so the tick doesn't cancel the dialog meanwhile) the
   job's output pipe is paused, the value goes in by `load-buffer -` and
   `paste-buffer -d` plus Enter, and the pipe resumes. A failed recheck closes the
   dialog as failed (nothing to retry: the terminal moved on). A value of 8 characters
   or more is added to the pane's scrub list (memory only), so a program that prints it
   later is masked.
4. The agent sees `auth: "[credential supplied]"`; `auth.waiting {request, session,
   dialog, terminal}` and `auth.supplied {request, outcome}` are the events. A
   cancelled or timed-out dialog leaves the prompt waiting with a note ("send ^C to
   abort it, or ask the user"); the same prompt isn't asked again. The prompt ending
   (echo back on) cancels an open dialog.

**sudo in a terminal**: the sudo stand-in (first on the pane's PATH) checks the form's
sudo right and refuses `-S`/`-A` as always; then, seeing `GW_TERMINAL` (a well-formed
id) and a terminal on stdin, it execs the real sudo (audited `outcome: "terminal"`),
which asks on the pane's tty: the path above answers it. A forged `GW_TERMINAL` only
skips the askpass path (sudo then asks on its own tty, as anywhere).

## Jobs

`job_start {argv | command, cwd, host, workspace, on_pause, idempotency_key, task_ref}`
(agent plane) and `POST /v1/jobs` (contract plane, `idempotency_key` required, `session`
must be the caller's). The same key within 24 h (per session) returns the job it started
(`new: false`). States: `running`, `waiting_auth`, `suspended`, `exited` (with `exit` or
`signal`), `canceled` (a stop was asked and took effect), `unknown` (tmux lost it; `gone:
true`; or, remote, a start whose answer was lost: `start_confirmed: false`, still asked
of the host, remote.md), `failed` (remote: a lost start that provably never ran).
A remote close the host didn't get leaves the state alone and says `stop_requested`.
`waiting_input` isn't detected (a job blocked reading its tty looks like a busy one).

Output: `pipe-pane -o 'exec cat > <fifo>'` starts in the same tmux command as the
session (so the first bytes aren't missed); gated holds the FIFO's read end and a write
end of its own (reads then wait for data rather than seeing EOF), a reader thread keeps
the last 256 KiB in memory (`RING_MAX`) and the byte count (`job.output`, at most once a
second). Nothing raw is written to disk. `job_tail {bytes ≤ 64 KiB, lines}` cleans the
stream (`screen.clean_stream`: escapes removed, CR LF to LF, a lone CR keeps what was
drawn over), scrubs it and returns `{text, truncated, offset, bytes_total}`.

`on_pause` (CONTRACT-v1 `/v1/pause {session, task_ref?}`; `/v1/resume`): `continue`
(still running, reported), `interrupt` (SIGINT; "interrupted: exited (...)" when it ends
within a second, else "SIGINT sent; still running, SIGTERM follows in 10 s"), `suspend`
(`stop_group`, verified; resume sends SIGCONT), `detach` (released from the task:
`task_ref` cleared, still running). The outcome says what actually happened. The
interrupt escalation and its `paused_as` are persisted, so a gated restart re-arms the
promised SIGTERM (`_arm_term_escalation` from adopt) instead of silently dropping it.
While a session is paused the agent may still stop or cancel a job, but **`job_signal
CONT` is refused** (409 `paused`): resuming suspended work is checkpoint's `/v1/resume`,
not something the paused agent undoes.

## Routes

| plane | route | what |
|---|---|---|
| agent-term (the gw MCP server: a `run.py mcp` entry point below a session, `planes.check_term`) | `POST /agent/term/{open,read,send,resize,signal,close,list}`, `/agent/job/{start,status,tail,signal,list}` | the tools |
| ui (the Claude Code process) | `GET /ui/term/list`, `GET /ui/term/screen?id&seq&wait` (long poll ≤ 25 s: answers on a new seq or rev), `POST /ui/term/{keys,take,release,resize,signal,open,close,agent}` | the pane |
| contract | `POST /v1/jobs`, `GET /v1/jobs/<id>`, `GET /v1/jobs/<id>/tail?bytes=`, `POST /v1/jobs/<id>/signal`, `/v1/pause`, `/v1/resume`; `/v1/snapshot` lists terminals and jobs | checkpoint |

`planes.Registry.ancestor_session` maps a process inside a gateway terminal or job (whose
ancestors are gated's tmux server, not Claude Code) to the pane's owner session while
that session lives, so the stand-ins and other gateway programs in a pane work within
that session (with a wrapped vault too); once the session ends they get nothing.

## The agent tools (gw MCP server)

`terminal_open {cwd, cols, rows, workspace, task_ref}`, `terminal_read {id, history,
take}`, `terminal_send {id, seq, text, keys, enter, delay_ms, read_after}`,
`terminal_resize {id, cols, rows}`, `terminal_signal {id, signal}`, `terminal_close {id}`,
`terminal_list {}`, `job_start {...}`, `job_status {id}`, `job_tail {id, bytes, lines}`,
`job_signal {id, signal}`, `job_list {}`. Each answers JSON: a read is `{id, kind, state,
host, host_id, cwd, owner, holder_agent?, session, mine, seq, cols, rows, cursor {x, y},
alternate_screen, title, lines, truncated, history?, history_truncated?, waiting_auth?,
auth?, note?}`; a send `{ok, delivered, seq, lines, cursor, ...}` (the screen after the
input, `read_after`); a refusal `{ok: false, error, message, seq?, owner?}`. The server
passes Claude Code's platform variables and approved imports for `terminal_open` and
`job_start`, the project folder as the default cwd.

Permission decisions (`hooks/mcp_perm.sh`): terminal_read, terminal_list, job_status,
job_tail and job_list are allowed in every mode (bounded, scrubbed reads);
terminal_open and terminal_resize too (an idle managed shell, a window size). The Bash
approval hook (`pre_bash.sh` -> `hooks_bash`, matcher in hooks.json) judges
`job_start`'s command/argv and `terminal_send`'s text like a checkpoint job: Bash's
denies, an "ask" right denied, never allow; then Claude Code's own mode decides (a
prompt in default mode, the classifier in auto mode). terminal_signal, terminal_close
and job_signal get no decision.

## The terminal pane (the gate mod)

`/gate-terminal [ID|new]` (immediate): no ID shows this session's newest live terminal
(else anyone's), `new` opens one the person holds from the start. The pane (`Pane`
`gate-terminal`) long-polls `/ui/term/screen` (at most 10 redraws a second,
`MIN_FRAME_MS`) and draws: the header (what, state), the owner line ("Input: Claude
holds it (agent X) · N queued from Claude" or "Input: you hold it"), the typing mode,
the password-prompt note, the screen in a `Client` (`term.tsx`: styled runs, the
cursor's cell inverse), and buttons: Take or Hand back to Claude, Interrupt (^C), EOF
(^D), Esc (and Enter on the main screen).

- **Fullscreen** (`CLAUDE_CODE_NO_FLICKER=1`, the desktop app): Claude Code 2.1.301
  reports clicks to plugins only there, and a Client takes keys only after a click. The
  click into the screen is the takeover; then the Client takes the keys, batches them
  with sequence numbers (re-sent until acknowledged; the hooks module forwards each
  batch once), consecutive characters coalesced. The engine keeps ^C, ^D, ^Z and
  Escape, so Ctrl-] is a prefix: c ^C, d ^D, z ^Z, [ Esc, ] a literal ^]. Escape (or a
  click elsewhere) gives the keys back to Claude Code.
- **Main screen** (no clicks reach plugins): the pane says so and offers a one-line
  `Input` (Enter sends the line and Enter) plus the buttons. An Input's text passes
  every plugin's `ui.input` hooks, so it is never offered while a password prompt waits
  (and gated refuses text then): a password always goes through the credential
  dialog, whose Paste works on the main screen.
- The Client's region size goes to gated (`/ui/term/resize`), so the terminal follows the
  pane. Closing the pane changes nothing in gated; `/gate-terminal` shows it again, in
  this or a new session.

## Events (CONTRACT-v1)

`terminal.opened {terminal, host, session, agent, by}`, `terminal.owner {terminal,
owner, agent, by}`, `terminal.closed {terminal, reason}`, `job.started {job, host,
session, task, agent}`, `job.state {job, state}`, `job.exited {job, exit, signal,
state}`, `job.output {job, bytes}`, `auth.waiting {..., terminal}`, `pause.applied
{session, paused, task}`. Ids, enums and counts only (`events.clean`); never a command,
a screen or input. A job's `job.started` is emitted under the supervisor's lock before
any look at its pane, so a job that ends within milliseconds still reports its start
first (2026-10-21: the full suite once saw `job.state` first, a race the watchdog's
extra tmux call had widened; that call now runs beside the start, on a thread).

## Workspaces and policy (phase 7)

Every terminal and job is bound to host + workspace (`Supervisor._bind`,
docs/modules/policy.md): `workspace` (a `w_` id or the workspace's name on
that host) on `terminal_open`, `job_start`, `POST /v1/jobs` and
`/ui/term/open`; `cwd` defaults to its root and must lie inside it (a remote
`~/...` cwd is expanded on the host); a path under its `local` folder maps
to the host's root; a workspace of another host is refused (409
`workspace_host`); an unnamed cwd inside a workspace binds to it. The exec
decision (`policy.decide(eff, "exec", host, workspace)`) is made there for
the agent and for checkpoint (an "ask" is refused: neither is a command
Claude typed); the person's own pane (`via == "ui"`) isn't held to it. A
refusal is 403 `policy` with `rule`, and a `policy.denied` event. Records,
snapshots and `terminal_list`/`job_list` carry `workspace`.

## Known limits

- Remote hosts (PLAN-v4 phase 6): `host` on `terminal_open`, `job_start` and `POST
  /v1/jobs` runs the pane in the host's managed runtime, with the same records, ownership,
  seq, takeover and password-prompt rules over ssh; what differs (the poller, disconnected
  and waiting_auth, the host's marker and machine binding, output from the remote tmux
  history) is in [remote.md](remote.md).
- `waiting_input` isn't detected; a job's raw output older than its 256 KiB ring is only
  in tmux's history (10000 lines) and gone with its session.
- The pane's keys travel the mod's `ui.message` (only the drawing plugin sees it) and
  then `$.http.fetch` to gated, which other plugins' `http.fetch` hooks can observe
  (FEASIBILITY-v4 P1): ordinary typing only, never a password (refused there).
- Text typed by the agent is on the transcript anyway; text the person types into a
  normal (echo on) prompt is theirs to choose; a value echoed by a program before it
  was supplied through the dialog isn't known to the scrubber.
- A value supplied through the dialog is a Python string in gated while the pane lives
  (for masking) and briefly a tmux paste buffer (deleted as it is pasted).
- One tmux server for every session of the user: a pane's processes can reach the
  private socket by its path in the run dir (guardrail, not boundary, like the planes).
- The agent-loop mapping needs the mod; without it agents aren't told apart.
- The approval hook judges each `terminal_send`'s text **per call**, the way it judges a
  Bash command, so an agent that splits a command across two sends (one with no newline,
  the rest with the newline) can keep any single call from looking like the denied
  command while the pane's shell assembles and runs the whole line. This is a guardrail
  against a cooperative model, not a boundary against code running as the user (SPEC/
  DECISIONS, invariant 17): a gateway terminal is a real shell running as the user, which
  can read any file the user can and reach the network, exactly as any shell they start
  can. The *hard* boundaries in a terminal are not evaded by splitting — `sudo`, `ssh`
  and the account CLIs are the real stand-ins first on PATH (they enforce the form's
  rights whatever text typed them), and the vault stays encrypted (only gated decrypts).
  Reconstructing the command from the screen at the newline was rejected: parsing shell
  intent from a rendered prompt line (PS1, wraps, continuations, here-docs) is fragile
  and would both miss and over-deny, against the gateway's no-screen-parsing-for-policy
  stance.
- A single agent write already being delivered to tmux when the user takes over finishes
  delivering: the takeover is acknowledged at once (it never blocks on an in-flight
  keystroke injection, which is normally sub-millisecond) and every *queued* write is
  failed, but the one keystroke in flight lands. The person then holds the input and
  re-reads before anything else runs.
- A password prompt is noticed on the next tty-mode tick; in the sub-tick window before
  that, the person's own keystrokes in the pane could reach a just-appeared prompt (their
  own keystrokes, echo-off, never routed to the model). Once noticed, the pane refuses
  typed text and the credential dialog takes the value.
