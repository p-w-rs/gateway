# Native-capability probes (Claude Code 2.1.301 CLI, 2.1.299 types; macOS 25.6; 2026-10-19)

All probes ran in a scratch `CLAUDE_CONFIG_DIR` against a local fake Messages API
(`ANTHROPIC_BASE_URL=http://127.0.0.1:<port>`, `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`),
driving the real interactive TUI in a PTY (python pty + pyte). Canaries were generated
locally and never printed. Harness: `plugins/gateway/tests/tui/` (fake API + PTY driver; the probes ran on its first version).

## P1 Private credential input

| Path | Result | Evidence |
|---|---|---|
| `Input` element | Not private. No mask prop; every `ui.input` change runs through every plugin's hooks; field shows plaintext. | types `InputProps`, `'ui.input'` docs |
| Pane opened with `focus: true` and only a `Client` inside | Keys go to the prompt box. Canary typed into the "dialog" landed in the composer and was submitted to the model, history.jsonl and the transcript. | run2 |
| `prompt.edit` capture while a dialog is open (consume edits, show bullets, drop on submit) | Value reached the hook intact (sha match) and no file held it, but each typed character and the paste were painted in plaintext for one frame before the hook's bullets (editor paints optimistically, sync or async hook), and every plugin's `prompt.edit` hook sees raw input. Escape is not an edit, so cancel needs another signal. This is "normal prompt handling": not compliant. | run3, run5 |
| `Client` region after a mouse click (terminal enables SGR mouse 1000/1002/1003/1006) | Typed keys reach only the Client's `onKey`: no plaintext in PTY output, composer empty, 0 hits in transcripts, history, debug log (`--debug-file`), fake-API payloads. A nosy observer plugin hooking prompt.edit/ui.input/ui.message/ui.render/http.fetch/process.run/tool.call/telemetry(collector) saw none of the typed characters. `ui.message` (the Client's `post`) reaches only the drawing plugin's hooks (the test kit's own bottom hook never saw it either). | run6, run8, test kit `probe-client` |
| Paste into a focused Client | Not delivered to the Client: the paste goes to the composer (plaintext paint, visible to `prompt.edit` hooks). | run6, run8 |
| Keyboard focus into a Client without a click | Not available: the focus ring (`$.ui.focus`, `autoFocus`) covers Button/Input/Select only; a Client takes keys only after a click. | types `UiFocusArgs`, `ClientSurface.onKey` |
| Crypto in mods | Hooks modules and Client modules have `crypto.getRandomValues` and `crypto.subtle.digest` only (no importKey/generateKey/encrypt). Asymmetric sealing needs a vendored audited library (TweetNaCl / noble). | probe-crypto, probe-client |
| Delivery from mod to a local process | `$.http.fetch` (unix `socketPath`), `$.process.run/spawn`, `$.fs.write` are all hookable by other plugins (args and results visible), so the value must be sealed to the broker's per-request public key before it leaves the Client. | types `'http.fetch'`, `'process.run'` |
| Telemetry | Third-party mods may hook only the `collector` telemetry stream; the `anthropic` stream is reserved for built-ins, so first-party telemetry payloads are not observable from a mod. Needs a local TLS-terminating capture proxy (records, never forwards). | validate error on probe-observer |
| Surfaces | `Client`: terminal and desktop only. `Input`/`Select`: not on mobile. VS Code attaches no surface yet. | types `Elements` |

Design consequence: credential dialog = Pane with host/account/purpose + a `Client` masked
field (click to focus; typed input private) + a "Paste from clipboard" button whose press makes
the broker read the OS clipboard directly (never through Claude Code) + Cancel. While a dialog
is pending, a `prompt.edit` guard consumes composer edits (stray typing before the click) and
says "click the field"; that guard cannot hide the stray keys from other plugins or the one-frame
paint, which is documented. Mobile and VS Code: credential entry unavailable (reported).

## P2 Managed Bash routing

| Route | Result | Evidence |
|---|---|---|
| `tool.call` rewrite of `command` | Runs, model sees its original tool_use and result, but the permission dialog, "don't ask again" rule text and every classic PreToolUse/PostToolUse hook see the wrapper. Answering `{ result }` instead would skip the permission prompt and classic hooks entirely (core is beneath module hooks). | run9 |
| `$.env.set('CLAUDE_CODE_SHELL_PREFIX', <abs path>)` at `session.start` | Takes effect for the session. Dialog shows the original command; hooks and model see the original. The prefix receives ONE argument: for the Bash tool the full script (`source <cfg>/shell-snapshots/snapshot-<shell>-*.sh 2>/dev/null || true && setopt ... && eval '<cmd>' < /dev/null && pwd -P >| /tmp/claude-XXXX-cwd`), for classic hook commands the hook's command string. Without a prefix, hooks run as `/bin/sh -c <cmd>` and tool/`!` commands as `$SHELL -c <script>`. | run10, run11 |

Design consequence: the gateway sets the prefix to a shipped POSIX `gate-sh`. Hook strings are
run exactly as before (`/bin/sh -c "$1"`). Tool scripts get the snapshot `source` replaced by the
gateway's managed rc and run under the managed bash with a curated environment; the cwd tracker
and other plugins' env files are kept. Unknown shapes or a not-yet-ready runtime are reported,
never silently run in the host login shell.

Phase 4 probes (2026-10-20, 2.1.301, a recording prefix plugin in the TUI harness, scratch
HOME, bash and zsh as `$SHELL`; and 2.1.301's own code):

| Finding | Evidence |
|---|---|
| The Bash tool, `run_in_background`, a subagent's Bash, the user's `!` command and a skill's `!` injection all reach the prefix with the same one-argument shape; `!` and injection fire no PreToolUse hook | recorder: 14 calls, bash and zsh; transcript |
| Monitor, plugin monitors and `!`-mode completion use the same shell function as Bash (`Rue(cmd, signal, "bash", ...)`), so the prefix covers them; Monitor isn't offered against the fake API (server-side gate `tengu_amber_sentinel`; neither `CLAUDE_INTERNAL_FC_OVERRIDES` nor a cached feature value enabled it) | code; probe |
| The script: `source <snap> 2>/dev/null \|\| true && <env-file text>\n: && { shopt -u extglob \|\| setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL; } >/dev/null 2>&1 \|\| true && { \builtin unalias -- 'unsetenv'; ... } ... && eval '<cmd>' [< /dev/null] && pwd -P >\| <tmp>/claude-XXXX-cwd`; heredocs drop `< /dev/null`; paths are quoted `'...'` with `'"'"'` only when needed; every plugin's `CLAUDE_ENV_FILE` text is inline | recorder |
| The prefix is joined as `'<prefix>' '<script>'` (split at the prefix's last `" -"` to allow flags) and run by `<shell> -c` (`-l` only without a snapshot); the shell execs it (its parent pid is Claude Code's) | code (`Xfe`), recorder |
| Exec-form hooks (`command` + `args`) and the organization's hooks are never prefixed; shell-form hooks run as `/bin/sh -c` (spawn shell:true) with the prefix composed into the string; MCP stdio servers started after session start get `prefix "<quoted argv>"` | code; recorder |
| A string-form hook through a `#!/bin/sh` prefix that execs `/bin/sh -c "$1"`: same env and `$0` (`/bin/sh`) except `SHLVL` +1 on macOS (bash as /bin/sh); dash doesn't touch it | recorder diff with and without the prefix |
| `CLAUDE_CODE_SHELL` set by a mod at `session.start` is honoured (the snapshot became `snapshot-bash-*` for a zsh user): Claude Code picks its shell and makes its snapshot at the first shell use; the system prompt still names `$SHELL` | recorder, request log |
| Installed plugins' `bin/` folders are on PATH through the snapshot's `export PATH=` line (bare, or `'...'` quoted); a `--plugin-dir` plugin's `bin/` is not | recorder |
| Claude Code passes `ANTHROPIC_API_KEY` (when set), `CLAUDE_CODE_MESSAGING_TOKEN`, `GIT_EDITOR=true`, `AI_AGENT`, `COREPACK_ENABLE_AUTO_PIN=0`, `CLAUDE_CODE_EXECPATH` to its commands | recorder env |

## P3 Pause while busy

`$.command.register({ name, immediate: true })` runs `command.run` mid-turn; `$.turn.abort({ turnId })`
cancels the main loop's running turn (ids from `turn.start`). Measured (run12): `/halt` typed 2 s into a
`sleep 31.5` Bash call was acknowledged on screen in 0.26 s, `$.turn.abort` resolved in 7 ms, the
`tool.call` gate denied the queued next step (it never ran). The in-flight Bash process was NOT killed:
Claude Code kept it as a background shell ("1 shell" in the footer). So pause needs an explicit,
reported per-command policy (interrupt the process tree, or leave it running and say so).

## P3b Keys a focused Client receives (run13, one key per fresh session)

Delivered to `onKey`: printable characters, arrows, Tab, Home/End/PgUp/PgDn, Ctrl-L, Ctrl-], F-keys
(as the raw escape sequence, e.g. `\x1bOP`), Alt-x (as `{ key: 'x', meta: true }`).
Taken by the engine, never delivered: Ctrl-C (focus leaves the Client), Ctrl-D, Escape (returns focus),
Ctrl-Z (suspends Claude Code itself). Fast typing: posts coalesce per frame (a later post in the same
frame replaces an undelivered one), so a terminal Client must batch keys with sequence numbers.
Design consequence for the terminal pane: Ctrl-] is a telnet-style prefix (Ctrl-] c = ^C, d = ^D,
z = ^Z, [ = Esc, ] = literal ^]) plus Interrupt/EOF/Esc buttons; documented.

## P4 Harness capabilities

Interactive TUI runs headless in a PTY with a fake API: deterministic tool_use scripting, payload
capture in plaintext before any encryption, SGR mouse clicks, bracketed paste, debug log capture.
Desktop surface cannot be driven this way (needs a manual check).

## P5 Remote runtime packaging (pixi-pack 0.7.x, pixi-unpack 0.7.11; run on macOS arm64)

A workspace with `bash` and `tmux` locked for linux-64, linux-aarch64, osx-arm64, osx-64 packs
cross-platform from this Mac in ~2 s each (`pixi-pack --platform <p> -o <tar>`): 9.4 MB
(linux-64), 9.7 MB (linux-aarch64), 7.7 MB (osx-64), 7.9 MB (osx-arm64). With Python added the
linux-64 pack is 85 MB, so the remote runtime leaves Python out. The osx-arm64 pack, unpacked
with conda-forge's `pixi-unpack` into a path with a space and a non-ASCII character, ran
relocated under `env -i`: bash 5.2.37, tmux 3.8, a detached tmux session on a private socket.
`--create-executable` makes a self-extractor with the right `pixi-unpack` embedded, but it needs
`bash` on the remote (`#!/usr/bin/env bash`); staging the target platform's bare `pixi-unpack`
binary next to the tar needs only POSIX sh and a writable directory. Linux targets not yet run
(no Linux machine here); the plan's remote tests use a local sshd, so Linux remote stays
"untested" until a Linux host is available. (Later, phase 6: a linux-aarch64 pack was staged and
run on the Debian 13 arm64 VM, `tests/acceptance_remote.py`; linux-64 and osx-64 hosts remain
untested.)

## P6 Observing first-party telemetry payloads before encryption (mitmproxy 12.2.3)

A record-only mitmproxy addon (answers every request itself with 204, never forwards) on
127.0.0.1, its CA given to Claude Code through `NODE_EXTRA_CA_CERTS`, `HTTPS_PROXY`/`HTTP_PROXY`
pointing at it, `NO_PROXY=127.0.0.1,localhost` so model calls still reach the local fake API, and
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` left unset (telemetry on). One interactive session
(prompt, one turn, /exit) produced 8 decrypted requests, none forwarded: api.anthropic.com
`/api/event_logging/v2/batch` (telemetry), `/api/eval/sdk-*` (feature gates, 2),
`/api/claude_cli/bootstrap`, `/api/claude_code_penguin_mode`, `/mcp-registry/v0/servers`,
raw.githubusercontent.com CHANGELOG.md, downloads.claude.ai plugin catalog. So acceptance 14.13 can
scan every first-party payload (model requests at the fake API, telemetry at the proxy) for a
canary in plaintext, which a mod cannot do (the `anthropic` telemetry stream is closed to it).
