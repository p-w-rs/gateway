# Capability matrix

What the gateway (`gate@gateway`) does on each Claude Code surface, and what
still works when mods are off. Mods (hooks modules) are an
early-access Claude Code feature that Anthropic can switch off remotely, so
every security control lives in the classic hooks and holds without them; the
mod adds the status line, provisioning at session start, the session's
registration on the gateway daemon's UI plane, `/gate-doctor`, the
gateway's dialogs (PLAN-v4 phase 3) and the managed shell. Without mods
nothing can be asked: a credential, a consent or a host key that needs the
person is reported as unavailable (what is needed and where it can be
given), never asked another way; Claude's commands then run in the user's
own shell, still judged by the classic hooks (since 0.11.0; before, they
were refused). `/gate-doctor` prints the rows for the surfaces it runs on
(`hooks/mod/lib.ts`, `CAPABILITIES`; a test keeps that table and this one in
step).

Cells: **yes** works, and was exercised on macOS arm64 with Claude Code
2.1.301 (and for 0.11.0 with 2.1.310) (2026-10-19: repo suites, the e2e suite, or a real interactive session
driven in a PTY against a local fake API); **untested** expected to work, not
exercised; **no** not available on that surface; **planned** a later
[PLAN-v4](dev/PLAN-v4.md) phase. "-p / SDK" is `claude -p` and SDK hosts (no
surface draws); "Remote Control" a session driven from another device.
Only the newest Claude Code is supported, so the table names no minimum
versions; `/gate-doctor` names the Claude Code this release was tested with.
The cells are the doctor's own table as shipped in plugin 0.9.0, unchanged
in 0.10.0 and 0.11.0 (they change only with the code; 0.11.0's live runs
are in [TESTING.md](dev/TESTING.md)). The live acceptance of 2026-10-21 (installed copies,
macOS 2.1.301 and the Debian 13 arm64 VM's 2.1.304; PLAN-v4's matrix) later
exercised more on the terminal surface than the cells claim: the stand-ins
and the http tool (`acceptance_canaries.py`), the policy and export/import
flows and `/gate-hosts` / `/gate-accounts` (`acceptance_native_ui.py`); the
notes below say so per row, and such a cell is conservative, never the
other way round. The desktop app, VS Code, mobile and Remote Control were
not driven at all (no way to drive them from the test harness; the desktop
app needs a manual check).

| Feature | terminal | desktop | VS Code | mobile | -p / SDK | Remote Control | without mods |
|---|---|---|---|---|---|---|---|
| Bash approval hook, file guard, output masking, paste guard (classic hooks) | yes | untested | untested | untested | yes | untested | yes |
| Stand-ins on PATH (sudo, ssh, git, gh, ...) and the gw MCP tools (http, download) | untested | untested | untested | untested | yes | untested | yes |
| Cold-start guard while the env builds (sh, no Python) | yes | untested | untested | untested | yes | untested | yes |
| /gate:status and /gate:help (Markdown commands, a model turn) | untested | untested | untested | untested | untested | untested | yes |
| /gate-doctor (immediate, no model turn) | yes | untested | untested | untested | yes | untested | no |
| Setup status line and provisioning at session start (mod) | yes | untested | untested | untested | no | untested | no |
| Gateway daemon (gated): CONTRACT-v1 discovery, snapshot and events; the vault broker | yes | untested | untested | untested | untested | untested | yes |
| Native gateway dialogs: credential field with sealed delivery, consent, host key, vault passphrase; /gate-dialog, /gate-unlock, /gate-lock | yes | untested | no | no | no | no | no |
| Managed shell (CLAUDE_CODE_SHELL_PREFIX -> gate-sh): Bash, background, ! commands, subagents, skill injection | yes | untested | untested | untested | yes | untested | no |
| Terminals and jobs (tmux supervisor in gated): gw terminal_* and job_* tools, CONTRACT-v1 job routes, password prompts through the dialog | yes | untested | untested | untested | untested | untested | yes |
| Remote terminals and jobs (the managed remote runtime over ssh): host on terminal_open, job_start and CONTRACT-v1 jobs, host_runtime, the host key and machine checks | untested | untested | untested | untested | untested | untested | yes |
| Shared terminal pane and takeover (Client): /gate-terminal | yes | untested | no | no | no | no | no |
| Policy (allow, ask, deny per host, workspace, account and action), workspaces, forwarding grants, account states, export and import format 3 | untested | untested | untested | untested | untested | untested | yes |
| Hosts and accounts panes (immediate): /gate-hosts, /gate-accounts | untested | untested | no | no | no | no | no |

## Notes per row

- **Policy, workspaces, forwarding grants, account states, portability
  (PLAN-v4 phase 7).** Enforced where the work happens: the ssh and sudo
  stand-ins, the approval hook, gated's terminals, jobs, remote runtime and
  host inspection, the managed shell's imports, the http tool and account
  selection (docs/dev/modules/policy.md), so it holds without mods. A rule
  waiting for the person's OK, a credential re-entered from `/gate-accounts`
  and an import's passphrase and conflicts need the gateway's dialogs
  (terminal and desktop app). Exercised by the repo suites (`test_policy`,
  `test_workspaces`, `test_accounts_states`, `test_portability`, real sshds on
  127.0.0.1 and a real gated) on macOS arm64 and the Debian VM. Live since
  2026-10-21 on the terminal surface (`tests/acceptance_native_ui.py`, macOS
  and the VM): a workspace added from the `/gate-hosts` edit line and its
  consent, an account's credential entered and checked, export (checklist,
  passphrase twice), import (wrong passphrase, conflict choice, a tampered
  file refused with its reason) and a macOS export imported on the VM with
  this machine told apart; a policy "ask" prompt wasn't driven. The cells
  stay "untested" until the doctor's table changes.
- **/gate-hosts and /gate-accounts (PLAN-v4 phase 7).** Mod commands drawn
  from gated's `/ui/manage`; tested in Claude Code's plugin test kit
  (`hooks/mod/manage.test.ts`: the panes, the edit line becoming one fixed
  `gate` subcommand, Check and Enter credential); driven live on the
  terminal surface since 2026-10-21 (`tests/acceptance_native_ui.py`, macOS
  and the VM). Without mods the same is `gate status`, `gate accounts`, `gate
  host|workspace|policy` and `gate check` in a terminal.

- **Remote terminals and jobs (PLAN-v4 phase 6).** gated and the gw tools do
  the work (docs/dev/modules/remote.md), so the surface matters only for what the
  person is asked: a changed host key or machine, a refused key, a password
  prompt in a remote terminal are the gateway's dialogs (terminal and desktop
  app only; elsewhere, and without mods, they are reported as unavailable and
  the host stays blocked). Exercised live at the daemon level
  (`tests/acceptance_remote.py`, 39 of 39, 2026-10-20: a real gated with a
  FakeClaude drawing the dialogs, the Debian 13 arm64 VM and a local sshd,
  real pixi-pack artifacts), not yet in a Claude Code session on any surface,
  hence "untested" in every cell.

- **Gateway daemon (PLAN-v4 phase 2).** Started on demand by the mod at
  session start, by the async SessionStart hook `hook-daemon` (so also
  without mods and in `-p`) and, for a passphrase-protected vault, by every
  gateway program that needs it; docs/dev/modules/daemon.md. The terminal cell:
  a real interactive session driven by the TUI harness (scratch config, fake
  API, the e2e install; 2026-10-19): the mod's `$.http.fetch` over the
  socket reached the daemon from the Claude Code process itself (the kernel's
  peer pid was the claude pid) and registered the session on the UI plane;
  `/gate-doctor` showed "Gateway daemon: running (...)"; contract.json was
  written; the daemon left once the harness removed its run dir. The `-p`
  cell: the hook route is covered by the repo tests, not a live `-p` run.
  The daemon's own tests also ran on Linux (Debian 13 arm64, SO_PEERCRED).
  The UI plane needs the mod; everything else works without it.
  Since 0.10.0 it recognizes a Claude Code installed with npm
  (`@anthropic-ai/claude-code`: its `bin/claude.exe`) besides the native
  installer and the desktop app; `/gate-doctor`
  names the install it found (the repo tests use a fake npm layout; no real
  npm install was driven). One daemon per user serves one Claude Code
  configuration (`CLAUDE_CONFIG_DIR`) at a time: sessions of another
  configuration get no dialogs, terminals or jobs from it and are told so
  (an unwrapped vault is still read by the stand-ins themselves).

- **Classic hooks.** Exec-form command hooks (`sh` + args) from
  `hooks/hooks.json`. The terminal row was exercised in an interactive
  session (SessionStart and the Bash hook's cold-start denies); `-p` by the
  e2e suite (`pixi run e2e`). They run on the machine that runs Claude Code,
  so a remote surface (mobile, Remote Control) gets the same decisions; that
  is not exercised. Since 0.11.0 they also mask every tool's output (post.sh
  skips only tools whose response is fixed text or Claude's own input),
  refuse an AskUserQuestion that asks for a secret, and refuse the
  browser-automation tools while a browser sign-in runs
  (`hooks/tool_guard.sh`); the Browser pane and Claude in Chrome payloads are
  tested from recorded payloads only (desktop-only tools).
- **Stand-ins and gw tools.** `-p` by the e2e suite (ssh, git, http, sudo
  scenarios against local servers). An interactive session runs the same
  hooks and env file; on the terminal surface the http tool (a stored key
  sent to a local service, `Bearer ***` in the result) and the sudo
  stand-in's dialog were exercised live on 2026-10-21
  (`tests/acceptance_canaries.py`, macOS and the VM). Since 0.11.0 a
  stand-in is on PATH only for a tool that can reach something gateway.toml
  configures, and passes everything else to the user's own tool; the `http`
  and `download` tools get deny or ask from the `network` policy in the
  payload's mode, allow only for the user's explicit per-mode allow, and
  otherwise no decision (Claude Code's mode decides).
- **Cold-start guard.** While no env can run Python, launch.sh's
  `degraded_bash` decides by text: it denies anything naming the gateway's
  private folder or `~/.config/gateway` other than `gateway.toml`, session
  transcripts, credential helpers / `age -d` / access tokens / token-bearing
  command lines ("still setting up" in the reason), and asks about network
  commands (denies them while gateway.toml has a `[network]` table, whose
  value sh can't read). The stand-ins it writes exist only while
  gateway.toml may configure something and say "still setting up" (sudo's
  runs the real sudo, which gets nothing from the gateway). Exercised in an
  interactive session and in `claude -p` with pixi hidden (so the env never
  built), 2026-10-19, before the 0.11.0 network rule.
- **`/gate-doctor`.** A mod command: `$.command.register` takes letters,
  digits, `_` and `-` only, so not `/gate:doctor` (a colon is refused, and
  the engine doesn't prefix a mod's command with the plugin name), and
  `/doctor` is Claude Code's own. Answered by the mod itself, no model turn
  (0 model requests in the interactive run); `claude -p "/gate-doctor"`
  prints it too. Without mods: `/gate:status` (a model turn).
- **Status line and provisioning.** At session start, in an interactive
  session whose env isn't ready, the mod runs `sh hooks/launch.sh
  ensure-env` through `$.process.spawn` (an argv; POSIX sh is the OS's own
  on macOS and Linux) unless a build already runs (the build lock makes a
  second one wait), and shows `gate: setting up… 0:12` on the status line,
  then a `ready` toast for 5 s (0.9.1: Claude Code draws every status line
  with its warning sign and `$.ui.status` takes no level, so the normal state
  has none). `-p` and SDK sessions draw no status line; there the async
  classic SessionStart hook builds the env (it always runs, mods or not).
- **Native gateway dialogs (PLAN-v4 phase 3).** Every question the
  gateway asks is a pane inside Claude Code, drawn by the mod from requests
  the gateway daemon holds (docs/dev/modules/daemon.md, "Dialogs"); no OS
  dialog or terminal prompt opens, and the system browser only for a
  browser sign-in (azure with `sign_in = "browser"`, ml-catalog; 0.11.0),
  after the person presses Open in the gateway's confirm dialog. 0.11.0
  adds that confirm and the vault passphrase offer (repo suites:
  `test_accounts_entra`, `test_accounts_asiml`, `test_offer`; live runs in
  [TESTING.md](dev/TESTING.md)). A secret is typed into a
  `Client` field (keys reach only it, after a click; bullets drawn) and
  leaves it sealed to the request's own key (TweetNaCl box; gated opens it
  with PyNaCl). `Client` exists on the terminal and desktop surfaces only.
  The terminal cell: the acceptance run (`tests/acceptance_dialogs.py`, a
  real interactive session through the TUI harness, telemetry on behind the
  record-only proxy; 56 of 56 checks, 2026-10-20; DECISIONS "PLAN-v4 phase
  3"; 62 of 62 on macOS with 2.1.301 and on the Debian VM with 2.1.304 on
  2026-10-21, after the prompt-box guard stopped trusting the editor's
  painted draft: DECISIONS "Acceptance fixes"). Claude Code 2.1.301
  reports clicks only in its fullscreen layout, so on the terminal's main
  screen (`CLAUDE_CODE_NO_FLICKER=0`, tmux) the field isn't drawn: the
  dialog says to type `/tui fullscreen` (Claude Code's own command; it
  restarts and resumes the session) or to use Paste from clipboard, which
  works from the keyboard (`/gate-dialog`, Tab, Enter).
  Paste leaves the value on the clipboard (the main-screen dialog, a toast
  after each Paste and `/gate-doctor` say so).
  On Linux without `DISPLAY` or `WAYLAND_DISPLAY` Paste can't work, so on the
  main screen neither route does: the dialog, the typing guard and
  `/gate-doctor`'s "Secrets here" line say so (since 0.10.0).
  Desktop: the field should work there (the `Client` relay is local), not
  exercised. VS Code, mobile (and Remote Control, whose clients attach as
  mobile), `-p` and the SDK: credential entry is reported as unavailable,
  never asked another way; consent and host keys likewise need a terminal
  or the desktop app.
- **Managed shell (PLAN-v4 phase 4).** The mod sets
  `CLAUDE_CODE_SHELL_PREFIX` to the shipped `hooks/gate-sh` (and
  `CLAUDE_CODE_SHELL` to the gateway env's bash) at session start
  ([FEASIBILITY-v4](dev/FEASIBILITY-v4.md) P2, docs/dev/modules/managed.md): every
  command Claude Code starts through its shell runs in the gateway's bash 5
  with the gateway rc; since 0.11.0 with the user's own environment (minus
  Claude Code's credentials and the shell's startup variables) and a bash
  snapshot's aliases and functions, the stand-ins unshadowable; classic hook
  strings and MCP server commands pass through gate-sh exactly as `/bin/sh
  -c`. The terminal cell (0.10.0's curated environment):
  `tests/acceptance_managed.py`
  (real interactive sessions through the TUI harness, 2026-10-20, 38 of 38):
  the Bash tool, `run_in_background`, a subagent's Bash, the user's `!`
  command and a skill's `!` injection all ran in the managed bash; a probe
  plugin's string-form hooks saw the same `$0` and environment as without the
  gateway; the permission dialog, "don't ask again" rules, PreToolUse and
  PostToolUse saw the original command; results, exit codes, Escape and Bash
  timeouts as without the gateway. The `-p` cell: `claude -p` in the same
  run. Monitor: Claude Code 2.1.301 doesn't offer it against the harness's
  fake API (a server-side feature gate); its commands go through the same
  shell function as Bash (`Rue(..., "bash")` in 2.1.301), not exercised.
  Desktop, VS Code, mobile and Remote Control: the prefix is set in the
  Claude Code process the mod runs in, so surfaces attached to it should get
  it too; not exercised. Without mods nothing sets the prefix: since 0.11.0
  Bash and Monitor run in the user's own shell with a notice once per
  session, with the env file's stand-ins first and Claude Code's own
  credential variables unset, and the classic Bash hook judges them as
  usual (0.10.0 refused them: "managed shell unavailable"); the user's `!`
  commands and skills' `!` injection reach no hook there (a known limit).
  Not managed by
  design: the desktop app's Terminal panel (the user's own shell) and
  checkpoint's own job runner (its own shell with env.sh), which checkpoint
  uses only when the gateway doesn't serve its session; otherwise checkpoint
  0.6+ hands its jobs to gated, which runs them in the managed environment.
  2026-10-21: the managed acceptance passed 38 of 38 on the Debian VM too.
- **Terminals and jobs (PLAN-v4 phase 5).** gated runs them in its own tmux
  (the env's tmux 3.8, a private socket, its own config) with the managed
  shell's environment; the gw MCP server's `terminal_*` and `job_*` tools and
  checkpoint's contract calls reach them over gated's socket
  (docs/dev/modules/terminals.md). The terminal cell: `tests/acceptance_terminals.py`
  (real interactive sessions through the TUI harness, telemetry on behind the
  record-only proxy, 73 of 73, 2026-10-21): a full-screen program, an input
  prompt, resize, signals, user takeover with Claude's input queued, hand back
  to the same shell, sudo's password prompt answered in the gateway's dialog
  (a canary found nowhere afterwards), jobs, a script in the pane refused an
  `"ask"` ssh or sudo right (the pane's wording; no connection made, sudo
  never ran) while its `true` sudo right still ran, a Claude Code restart. The
  repo suite also ran on Linux (Debian 13 aarch64, the env's tmux; the VM has
  no system tmux) and, there, the real sudo by absolute path in a gateway
  terminal through the dialog. Without mods the tools and the supervisor
  work; a password prompt is then reported (no dialog can open) and the pane
  doesn't exist. `-p`: the tools work (the MCP route is covered by the repo
  tests), not a live `-p` run; a password prompt there is reported as
  unavailable.
- **Shared terminal pane (PLAN-v4 phase 5).** `/gate-terminal` draws the
  terminal in a `Client`: in the fullscreen layout the click into it is the
  takeover and the Client takes the keys (Ctrl-] then c, d, z or [ for ^C,
  ^D, ^Z, Esc); on the main screen no clicks reach plugins, so the pane offers
  a line field (never during a password prompt) and buttons. Both exercised in
  the acceptance run. `Client` exists on the terminal and desktop surfaces
  only: desktop untested; VS Code, mobile, `-p` and Remote Control draw no
  pane (the tools still work there).

## Platforms

| | |
|---|---|
| Local | macOS (arm64, x86-64) and Linux (x86-64, aarch64): the lock covers osx-arm64, osx-64, linux-64, linux-aarch64. Tested: macOS arm64 (repo suites, the TUI acceptance runs); Linux aarch64 (Debian 13 VM: the whole repo suite, gate-sh with dash and bash, and the TUI acceptance runs through Claude Code 2.1.304, installed from a git marketplace with pixi's git: dialogs, canaries, managed, install, native UI, terminals, 2026-10-21; for 0.11.0 the same on Claude Code 2.1.310, 2026-10-25: [TESTING.md](dev/TESTING.md)). x86-64 (Intel Macs, Linux x86-64): untested, no such machine here. Remote hosts: linux-aarch64 (the VM) and osx-arm64 (a local sshd) tested at the daemon level; linux-64 and osx-64 untested. |
| Windows | Native Windows unsupported (POSIX `sh` hooks, no win-64 in the lock, POSIX-only Python modules). Remedy: WSL 2, where the Linux rules apply. |
| pixi | `requires-pixi = ">=0.83.0"`, the pixi the lock was made with (latest only: every dependency is `"*"`, relocked by `pixi run update-deps`), no upper bound. Tested 2026-10-23 with the launcher's own `pixi install --locked --manifest-path` on a copy: 0.83.0 installs the lock (format v7) unchanged; 0.81.0 refuses the manifest ("requires pixi"), which the launcher reports as pixi too old (`pixi self-update`, or the package manager for a Homebrew or MacPorts pixi). `/gate-doctor` warns for a pixi older than the tested one and notes a newer one. |
| git | Claude Code needs `git` to add or update a git/GitHub marketplace. `pixi global install git` provides it (verified on macOS and the VM: marketplace add, install, update, disable, enable, uninstall with only pixi's git on PATH; without git, `Executable not found in $PATH: "git"`). It lands in `~/.pixi/bin`, which pixi's installer normally puts on PATH; the VM's pixi hadn't, so there `PATH="$HOME/.pixi/bin:$PATH"` was needed for `claude plugin marketplace add|update`. The update itself (`claude plugin update` after `marketplace update`, in a new process with the ordinary PATH) made no pixi call and reused the built env (acceptance 2026-10-21). |
