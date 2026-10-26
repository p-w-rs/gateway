> Design history: why the gateway works the way it does, and what was tried and rejected. Developer documentation, not a user guide (see the [README](../../README.md)).

# Decisions (and what was tried and rejected)

Read this before redesigning anything. Most "obvious" alternatives were tried
and failed for reasons that aren't visible in the code. The v3 decisions come
first; the earlier history is condensed at the end.

The research behind v3 (platform probes, four critiques, prototypes) was done
on 2026-10-18 with Claude Code 2.1.301, mostly with throwaway plugins under
headless `claude -p`. The plan that came out of it is
[history/REDESIGN-v3.md](history/REDESIGN-v3.md); what was built is
[SPEC-v3.md](SPEC-v3.md); how the build groups' requests were settled is
[phaseB-requests/RESOLUTION.md](phaseB-requests/RESOLUTION.md).

## Why v3

v2 (0.6) kept prompting, even in auto mode. It answered `ask` for its ten
`*_confirm` tools and `port_check`, started with sudo off and ssh set to ask,
and made Claude use 33 special MCP tools instead of `git`, `ssh` and `sudo`. A
plugin's `ask` always becomes a human prompt (below), so no setting could fix
it. v3's goal: Claude uses sudo, ssh and the user's accounts as ordinary
commands, with no prompt in auto mode for what the user allowed, while
secrets still never reach the chat, each goes only where it belongs, and web
access has its own route.

## Platform facts v3 relies on

| fact | evidence | consequence |
|---|---|---|
| A plugin PreToolUse `allow` skips the auto-mode classifier, for Bash and MCP tools, in subagents too. | Debug log: "Hook approved tool use for Bash, bypassing permission prompt", decided in 4 ms against 331 ms through the classifier; the same for an MCP tool (1 ms against 418 ms). | `allow` is powerful: the gateway answers it only for strictly parsed command shapes (SPEC 8). |
| A hook `ask` always becomes a human prompt, even in auto mode; it never reaches the classifier (headless it is a denial), and PermissionRequest hooks aren't called for it. | Spike runs with a hook answering `ask` for `echo hello`: denied with the hook's reason, no classifier latency. | Never answer `ask` except for an `"ask"` right. This is why v2 prompted. |
| Settings ask/deny rules beat a hook `allow`. An organization's managed settings can ask on `Bash(curl *)`, `Bash(wget *)` or `Bash(security *)`, for example. | `curl --version` with a hook answering allow: "an ask rule ... requires the full permission pipeline", denied. A PermissionRequest hook could allow it, but that would sidestep such a policy. | Web access goes through the gateway's `http` and `download` tools; curl and wget are denied with a pointer to them. |
| Auto mode drops broad allow rules such as `Bash(sudo *)` and `Bash(ssh *)`, and plugins can't ship permission rules or env anyway (only `agent` and `subagentStatusLine` from a plugin's settings). | Binary strings (the dropped-prefix list includes ssh and sudo); Claude Code docs, plugin components. | Every rule is a hook decision. |
| A SessionStart hook may write `$CLAUDE_ENV_FILE`; its content runs before every Bash command, in the foreground, in the background and in subagents, and a PATH entry there shadows system binaries. The file is per hook (`sessionstart-hook-N.sh`) and is reused, not truncated, on resume and compact. `CLAUDE_PLUGIN_ROOT`, `CLAUDE_PLUGIN_DATA` and `CLAUDE_ENV_FILE` are not in the Bash environment; `CLAUDE_PID` and `CLAUDE_CODE_SESSION_ID` are. | Probes: a shim shadowed `/bin/hostname`; a function and an export applied in all three places; one file held four appended blocks after startup, resume, resume, compact. | The env file is written with truncation and is static and idempotent (guarded PATH and `GIT_CONFIG_COUNT` additions, `set -u` safe). Stubs carry absolute paths; stand-ins derive the data folder from the Python running them. |
| A plugin's `bin/` is appended last on PATH, so it can't shadow `sudo`, `ssh` or `git`; claude.ai and Cowork refuse plugins with a top-level `bin/`. | Claude Code docs (plugin manifest, executables); probe. | No `bin/`; the stand-ins live in `$CLAUDE_PLUGIN_DATA/bin`, put first by the env file. |
| Plugin MCP tools are deferred behind ToolSearch unless `.mcp.json` sets `"alwaysLoad": true`, which blocks startup until the server connects (at most about 5 s). | 3 of 3 runs without the field called ToolSearch first; 3 of 3 with it called the tool directly. | `alwaysLoad` plus `_meta: {"anthropic/alwaysLoad": true}` per tool, and only two tools. |
| `userConfig` values live in the user's `settings.json` (`pluginConfigs`; sensitive ones in the keychain), declared defaults don't reach hooks, and `${user_config.*}` in a shell-form hook is refused at run time. | Probe plugin with a declared option and default. | The user wanted nothing in settings.json: the form is a plain file in `~/.config/gateway`. |
| `updatedInput` works, but it replaces the whole tool input, the permission check judges the rewritten command, and the model sees output that doesn't match what it sent. | Four runs rewriting `echo A`. | Stand-ins on PATH instead of rewriting commands. |
| FileChanged fires for a SessionStart `watchPaths` entry when the FileChanged group has no matcher (a matcher would also watch a same-named file in the working directory). | Headless probe with a standalone plugin (phase C). | `watchPaths: [gateway.toml]`; the hook ignores other paths. |
| Hook output, systemMessages included, is recorded in the session transcript (`hook_success` attachments carry the hook's stdout). | Transcripts on this machine. | The one-time codes of the no-screen path could be read there, so the file guard and the Bash hook deny reading `<config>/projects/*/*.jsonl` (phase C). |
| Claude Code's Workflow tool keeps each run in `<project>/<session>/subagents/workflows/<run>/`: `journal.jsonl` (the agents' results) next to the run's `agent-<id>.jsonl` transcripts, and tells Claude to read the journal to diagnose a run. | Names and link counts on this machine (2.1.301; contents not read); the Workflow tool's instructions. | The journal, by exact name and place, is not a transcript; the run folder still holds transcripts (see "Rolled back"). |
| Claude Code keeps raw copies of large or background output (`tool-results/*.txt`, `tasks/*.output`) even when a PostToolUse `updatedToolOutput` scrubs what the model sees and the transcript. | A scrubbed fake secret: 0 copies in the transcript, 1 in each raw file. Round 4 (2.1.301): the `tool-results/` copy holds the masked text; task output files are raw. | Stated in README's "Limits". |
| A command's `!` injection runs through the Bash tool (the env file applies), PreToolUse hooks don't see it, outside auto mode it needs the command's `allowed-tools`, and a non-zero exit aborts the whole command. | Probe plugin, 2026-10-19: with `allowed-tools: Bash(gate status *) Bash(true)` the injected `gate status \|\| true` ran in default mode, found the env-file PATH, and passed "still setting up" (exit 75) through; without `allowed-tools` it failed the permission check; without `\|\| true` exit 75 aborted the command. | `/gate:status` injects `gate status \|\| true` with that `allowed-tools` line, which also covers Claude's own `gate status NAME` in that turn. |
| The desktop app (and `claude -p`) auto-cancels MCP elicitation without showing it. | Live test, 2026-10-15. | Pop-ups are native dialogs from the gateway's own process. |
| `includeIf "hasconfig:remote.*.url:..."` works from an include file supplied through `GIT_CONFIG_COUNT`/`include.path`. | MacPorts git 2.55 and Apple git 2.54, https and ssh remotes. | Per-owner commit identities without touching the user's git config. |
| conda-forge has no pijul package for osx-arm64, osx-64, linux-64 or linux-aarch64. | Searched in phase C. | pijul is built with cargo into the data folder on first use, against the env's own libraries. |
| A Bash command that exits non-zero goes to PostToolUseFailure (output in `error`, no `tool_response`); its hook output takes only `additionalContext` (plus `systemMessage`): an `updatedToolOutput` there is ignored. | Review round 3 probes (standalone plugin, `claude -p`, 2.1.301): `sh -c 'echo out; exit 1'` fired only PostToolUseFailure; a rewrite returned there left `SECRETVALUE123` in what the model got; the e2e suite's `cat notes.txt; exit 1` returned the planted key. | PostToolUseFailure only warns (round 3). Round 3's env-file EXIT trap (exit 0 with `Exit code N` printed) is rolled back: a failed command's output is a known limit (see "Rolled back"). |
| Claude Code runs a Bash command as `<snapshot> && <env file lines> ... && eval CMD < /dev/null && pwd -P >| cwd-file` in one `bash`/`zsh -c -l`. | Binary strings of 2.1.301 (`Ye.push("eval "+..); Ye.push("pwd -P >| "+..); Ye.join(" && ")`); the e2e `leak` scenario. | A trap set by the env file would run at the shell's exit (round 3 used one; rolled back). A failed command skips the cwd record. |
| Monitor's PostToolUse gets only `{taskId, timeoutMs, persistent}`; each stdout line reaches the model as an event no hook sees (stderr goes to the task's output file). | Round 3 probe: `mon PROBESECRET4 1` quoted verbatim by the model; a Read of the output file was masked. | Round 3 required `| gate scrub` for Monitor commands; rolled back: Monitor lines are a known limit, `gate scrub` optional. |
| A subagent's hook systemMessages are recorded in `<project>/<session>/subagents/agent-<id>.jsonl`. | Round 3 probe: a PostToolUse systemMessage during a subagent's Bash call landed only there. | Every `.jsonl` under a projects folder counts as a transcript. |
| A plugin hook's `updatedInput` is refused for calls that don't run in the hook's environment (a remote or forwarded tool). | Binary strings ("A plugin hook changed this tool call's input. That is allowed only for calls that run in the same environment as the hook"). | One more reason not to rewrite commands. |
| Every background Bash task (`run_in_background`, or a foreground command moved there by its timeout, a message or ctrl+b; not Monitor) writes stdout and stderr raw to `<TMPDIR>/claude-<uid>/<project>/<session>/tasks/<id>.output`. After 45 s without new output Claude Code reads its last 1 KB and, if the last line looks like a prompt (`[y/N]`, `Continue?`, `Press Enter`, ...), hands Claude a `<task-notification>` with `Last output:` and the raw tail: a new prompt when Claude is idle, a queued attachment mid-turn. Both pass UserPromptSubmit; no output hook sees them; they land in the transcript (`queue-operation`, `user`, `api-request-blob` records). | Review round 4: binary of 2.1.301 (`tqn`, 5000/45000/1024); reviewer's `claude -p` probes with a planted key and sudo password (idle, foreground timeout, mid-turn); the prompt hook ran each time. | prompt.sh sends every notice to Python, which blocks one holding a stored value or a token shape and masks the transcript (fails closed). Round 4 also denied `run_in_background` without `2>&1 \| gate scrub`; rolled back: raw background output and task files are a known limit. |
| The desktop app gives Claude session tools: `mcp__ccd_session_mgmt__export_transcript` (a zip of the session's and its subagents' transcripts in `~/Downloads`, no approval), `search_session_transcripts` (verbatim snippets of other sessions) and `list_events` (another session's turns and tool calls). Hooks match them like any MCP tool. | Review round 4, from the tools' own descriptions (not run against the user's real transcripts). | The file guard denies the export always and the readers while a one-time code is live; PostToolUse masks stored values and codes in the readers' results. |
| Claude Code gives Claude no file content for an Edit, Write or MultiEdit: "The file X has been updated successfully." / "File created successfully at: X" (plus a note that the file state is current); the tool response (with `originalFile`) goes to PostToolUse and the transcript. | Binary strings of 2.1.301 (`case"update":return{...content:`The file ${e} has been updated successfully.${M}${q}${V}`}`); no `snippet of the edited file` text left. | Round 5: post.sh doesn't start Python for those responses because a vault exists. |
| macOS `proc_pidpath` returns nothing for a process whose executable was deleted or replaced while it runs (`proc_pidinfo` short info still gives uid, comm and parent); Linux's `/proc/PID/exe` gives `PATH (deleted)`. | A copied `sleep`: its path before the unlink, nothing after (review round 5). | `UNREADABLE` from `ancestry.claude_ancestor` is mostly the user's own terminal after an upgrade on macOS: its own message. |
| The checkpoint plugin's `job_start` (`mcp__plugin_check_jobs__job_start`, input `command` or `argv`, `cwd`, `name`, `redo_hint`, `task`) runs `/bin/sh -c WRAPPER checkpoint-job-ID CMD EXITFILE ENVFILE STATUSFILE` (CMD = `command` or `shlex.join(argv)`; ENVFILE the gateway's env.sh when it is safe to source, else ""; checkpoint's earlier wrapper took only CMD and EXITFILE) from its MCP server (`python …/checkpoint/…/run.py server` under pixi), detached (`start_new_session`, stdin /dev/null, output to a log), with the server's environment minus checkpoint's own pixi activation; a job without `cwd` starts in `CLAUDE_PROJECT_DIR`. The wrapper sources ENVFILE in a subshell first and applies it only if that wrote nothing to stderr and the shell survived (STATUSFILE `applied`), else writes `failed`, says so in the job's log and runs the job without it. | checkpoint's `jobs.start`, `jobs.WRAPPER` and `mcp_server.py` (read 2026-10-19; the wrapper is pinned in `tests/harness_sudo.py`). | Such jobs bypassed the Bash approval hook (its matcher) and the env file (Claude's Bash only); see "Checkpoint jobs". |
| An MCP tool's result reaches PostToolUse as its content list (`[{"type": "text", "text": ...}]`), and an `updatedToolOutput` list replaces what the model reads; an error result (`isError: true`) fires PostToolUseFailure instead, with the text in `error`: an `updatedToolOutput` returned there is ignored, its `additionalContext` reaches the model. checkpoint's job tools return their result dict as indented JSON in one text block (`job_stop`'s `stop_failed` is an error result carrying the last 10 log lines). | Probe (standalone plugin, `claude -p`, 2.1.301, integration review): an ok tool's rewrite reached the model, an error tool's rewrite didn't and its context did; the integration run's `job_tail` result was masked once the matcher named it. checkpoint's `mcp_server.py` and `jobs.tail`/`jobs.stop` (read 2026-10-19). | The output hooks name `job_tail`, `job_status` and `job_stop` (see "Checkpoint jobs"); a failed `job_stop` is a known limit with the PostToolUseFailure warning. |
| `mcp__terminal__run_in_terminal` types a command into the user's Terminal panel (input `command`, one line), whose shells run under the desktop app's helper, not Claude Code; `read_terminal` reads it back. | Tool schemas; the round 5 review saw four panel shells under `Claude Helper` (their environment unread). | The approval hook denies `gate secret` there too. |

Facts about the tools themselves that shaped the guards: real sudo with `-S`
doesn't consume the password line when it needs no password
(`printf 'FAKEPASSWORD\nreal-data\n' | sudo -S -p '' cat` printed it); git
prints the Basic auth header with `GIT_TRACE_REDACT=0`, and `git credential
fill` prints a helper's token; sudo's timestamp is keyed to the parent, so
authenticating first and running the command separately fails without a tty.

## The user's four choices (2026-10-18)

The plan offered four decisions with a recommendation each
([history/REDESIGN-v3.md](history/REDESIGN-v3.md), "Decisions for you"). The
user took the recommendation every time:

1. **Machines and git servers not in the form are refused**, with a hint to
   add them (Claude can import from `~/.ssh/config`). Opt-out:
   `[settings] others = "mine"` (itself a widening).
2. **Credentials go to Claude's direct commands only**, not to programs those
   start. Opt-in per host or account: `scripts = true`.
3. **Widening needs one pop-up.** Claude can edit the form; a new host or a
   raised right takes effect only after the user's OK.
4. **API keys reach programs only opt-in**, with `env = "VAR"` and
   `gate with NAME -- CMD`; otherwise only through the `http` tool.

## Design decisions from the critiques

Four independent critiques (security, platform, UX, migration) and their
prototypes reviewed the first plan. What they changed:

- **Strict allow shapes.** A hook `allow` covers the whole Bash call, so
  "starts with a permitted verb" would let `sudo -v; python3 -c '...'` or
  `ssh -o ProxyCommand=... homelab` skip review. The hook parses the full
  command and allows only when every segment is an allowed shape; it gives up
  (no decision) on anything it can't judge; account CLIs (git, gh, hf) are
  never allowed, so the classifier's credential rules still apply to them.
  The decision table (over 100 commands) is mutation-checked. Verification
  later found and fixed two holes: dropped redirections (`echo KEY >>
  ~/.ssh/authorized_keys` was allowed as a plain `echo`) and a destructive
  list that checked only the first word after sudo (`sudo env rm -rf /`).
- **Ancestry.** Stand-ins on PATH would hand root and tokens to every
  descendant: npm postinstall scripts, Makefiles, git hooks. Credentials go
  only to direct callers, checked by walking the process tree to `CLAUDE_PID`
  by executable path (`proc_pidpath`, `/proc/PID/exe`), never by name;
  `scripts = true` opts in. The checkpoint plugin's job runner is recognized
  by its command line, a documented limitation.
- **Remote sudo staging.** An askpass on this machine can't serve a remote
  sudo, `sudo -S` leaks into the command's input, and pre-authenticating fails
  without a tty. The prototype that worked (direct, nested and piped sudo,
  `rsync --rsync-path="sudo rsync"`, NOPASSWD) stages the password and a
  guarded askpass in a 0700 folder on the remote for the one call, answers
  once per sudo process, scrubs the output and removes the folder. Phase C
  accepted the residual risk that a same-user process on the remote can read
  the staged file (`cat $XDG_RUNTIME_DIR/gw.*/p | rev` prints it reversed)
  and added what it then took for the real answer: `gate check` offered
  passwordless sudo (recommended), a `visudo`-checked sudoers file written
  with the password once. Superseded: PLAN-v4 phase 7 removed it (a rule like that gives
  root to every program running as that user; "PLAN-v4 phase 7" below).
- **URL-scoped git helper.** A global `credential.helper=` reset broke the
  user's own keychain helper for every other host. The include file scopes
  the reset and the gateway helper to each account's URL. The global reset is
  added only with `others = "refuse"`, where refusing unlisted git servers is
  the point (choice 1).
- **insteadOf for ssh remotes.** `git@github.com:` remotes never ask the
  https helper. For hosts whose accounts all have a token and no ssh key, the
  include file rewrites ssh URLs to https inside Claude's terminal; otherwise
  the ssh stand-in handles git over ssh to the account endpoint with the
  account's own key and the built-in host keys.
- **Bindings, not just host names.** Tokens could be redirected without
  touching the form: `HF_ENDPOINT`, `GH_HOST`, proxy and CA variables,
  `http.sslVerify=false`, an ML Catalog `host` whose `/api/config` was re-read.
  Each credential is bound in the vault to its destination set, auth
  placement and Entra tenant/client/scope; stand-ins build the child
  environment from an allowlist with endpoints forced and proxy/CA overrides
  dropped; the git helper refuses when certificate checks are off.
- **Widening pop-up.** "The first secret pop-up is consent" fails whenever no
  secret is needed (NOPASSWD sudo, a copied gateway). The vault keeps the
  approved rights; narrowing applies silently and is persisted by every
  process (a narrow-then-raise still needs the user); widening waits for one
  pop-up with Cancel as the default. Edits of the form are left to Claude
  Code's own permission flow (in auto mode, the classifier's rule against
  self-granted permissions).
- **The form outside `private/`.** The first plan put the form in the folder
  the hooks forbid, next to the age identity. The form is
  `~/.config/gateway/gateway.toml` (Claude may read and edit it); the key and
  vault moved into `private/`, which is denied; migration moves the v2 store
  and key out of the home folder, so `cat ~/.config/gateway/*` can't print the
  key.
- **Scrubbing as a backstop.** git and the account CLIs can print tokens. A
  streaming scrubber per call masks each value it sent (and its base64,
  `base64(user:value)` and URL-encoded forms); PostToolUse masks token shapes
  in tool output. Values under 8 characters are never masked by literal (that
  would reveal them); remote sudo refuses such passwords.
- **System git first.** pixi's git reads its own gitconfig and CA bundle and
  has no LFS. The system git stays; pixi's git is used only on machines
  without one.
- **Setup while the user is there.** Lazy pop-ups appear when nobody is
  watching. Claude runs `gate check NAME` right after the change the user
  asked for; a lazy pop-up waits 90 s, then the command exits 75 and Claude
  carries on.

## Phase C decisions (2026-10-19)

Details and tests: [phaseB-requests/RESOLUTION.md](phaseB-requests/RESOLUTION.md).

- **The `az` stand-in prints the raw token.** It exists only for an azure
  account with an approved `env` (the user's opt-in for programs to get its
  tokens), and a caller that is neither direct nor covered by `scripts = true`
  is refused before anything is minted. A masked token would break the SDKs it
  is for.
- **No proxies for credentialed HTTP.** The `http` tool's opener ignores proxy
  variables and `SSL_CERT_FILE`/`SSL_CERT_DIR`, like every other credentialed
  client. A proxy-only site can't be used with it in v3.0.
- **An owner's account that isn't usable yet refuses** (`NAME is the account
  for OWNER but can't be used yet`) rather than handing the repos to the
  default or the only other account.
- **copy-to applies on the remote without its own pop-up** (option a). The
  remote usually has no screen and the user consented on the source; the
  pop-up says that whatever is copied is within reach of Claude's commands on
  that host. Queuing imports for a pop-up there would contradict SPEC 16 and
  doesn't help against a planted `gate`.
- **Session transcripts are protected** like `private/`, because hook
  messages with one-time codes are recorded there.
- **Under a test override with no fake dialog, there is "no screen"**, so a
  test can never open a real dialog.
- **The user's Terminal panel** (`mcp__terminal__run_in_terminal`) gets the
  hook's denies and asks but never `allow` (no stand-ins there).
- **`requires-pixi` stays at `>=0.81.0`**: the lock format is readable since
  0.68.0 per the changelog, but only 0.81.0 was tried. (Superseded by PLAN-v4
  phase 1, 2026-10-19: the launcher's own `pixi install --locked
  --manifest-path` was run with conda-forge's pixi 0.61.0-0.70.0, 0.81.0 and
  0.82.0 on a copy, scratch cache: 0.68.0 and later install the lock
  unchanged, 0.67.0 and older refuse lock format v7. `requires-pixi =
  ">=0.68.0"`, no upper bound; `/gate-doctor` warns above 0.82.0.)

## Review round 1 (2026-10-19)

- **An `"ask"` right goes only to a command Claude typed.** Claude Code can
  prompt only for the command line Claude runs, and that line is all the
  approval hook sees; the stand-ins used to count git, rsync, scp and sftp as
  direct, so ssh or remote sudo they started skipped the prompt
  (`rsync f "box:/x; sudo id"`, `git clone --upload-pack="sudo …"`). Now the
  stand-in must be started by Claude's command shell or a fork of it
  (`ancestry.typed_by_claude`), and the hook denies scp, sftp and rsync on an
  `"ask"` right at once (the stand-in would refuse after the prompt) and asks
  about commands that hide their verbs (a shell behind a wrapper, a loop, a
  target in a variable). A script sourced into Claude's shell stays a known
  limit: asking whenever a command sources anything would prompt for every
  `source .venv/bin/activate`. Rejected: letting the transfer
  tools through when the hook saw them, because the hook can't see every way
  they start ssh (`sftp HOST` with no colon, `scp://`, a bare-host sftp in a
  pipe); and the plain "only shells" rule, because `./deploy.sh` and `sh -c`
  run their commands in a shell too.
- **scp / sftp / rsync are allowed only on an option allowlist and only for
  copies within the project, `~/Downloads` or a temp folder** (the download
  tool's rules), and downloads only of named, non-hidden things. A list of
  bad rsync options missed `-ave CMD`; copies from an allowed host could
  write `~/.ssh/authorized_keys`, dotfiles or `./.claude/settings.json`.
- **gh refuses a command line naming another host**, since gh sends
  `GH_ENTERPRISE_TOKEN` to any host but github.com; **az mints only scopes of
  the account's approved destinations**, like the http tool.

## Review round 2 (2026-10-19)

- **Nothing secret is ever shown in a dialog.** A dialog's text is on its
  command line (osascript argv, zenity `--entry-text`, kdialog `--inputbox`),
  which `ps` shows every process of the user's for as long as it is open, so
  the generated export passphrase was readable by Claude's Bash for up to 30
  minutes. The generated passphrase is gone (the passphrase is typed twice,
  hidden); `dialog.argv_for` refuses a default marked secret. Rejected:
  showing it from a file the dialog reads (osascript `read`, zenity
  `--text-info`), which adds three untested GUI paths and a file of the
  secret, for a convenience a password manager provides.
- **With a vault, PostToolUse runs Python for every response.** Vault values
  (sudo passwords, prefix-less API keys, refresh tokens, base64 forms) have
  no shape a word list can match. The cost is about 0.1 s per tool call,
  mostly the age decryption (round 5 measured it: mostly imports, age about
  8 ms; edit tools are skipped now, see "Review round 5"). Rejected: caching the decrypted values in the
  run dir (secrets outside `private/`), and salted-hash fingerprints for the
  sh prefilter (more moving parts than the problem needs).
- **The az stand-in prints a raw token only to a program, with `scripts =
  true`.** Claude's own command (also under Monitor, whose streamed lines
  PostToolUse never sees) is refused and told to use the http tool; the Bash
  hook denies `az … get-access-token` for Bash and Monitor. With `scripts =
  true`, a program Claude writes can still print the token: that is what the
  option allows.
- **A stored credential belongs to the approved name and kind.** Approving
  an account with no earlier approval of that name, or with another kind,
  drops what was stored under it, so the user is asked for a new secret.
  Removing an entry still keeps its secrets until `gate forget` (README's
  promise); dropping them on removal would let a form edit delete them.
- **The gateway's own ssh helpers honour the ssh right**, like the stand-in:
  off refuses, `"ask"` needs a pop-up job or a typed command (which the hook
  asks about for `gate check|rotate|copy-to`).
- **Held-back output is released after 0.15 s of quiet.** Holding the
  possible start of a secret until EOF deadlocked prompts and rsync's
  protocol under remote sudo. A secret printed with a pause in the middle can
  show its part before the pause; the rest is masked.
- **Linux: the askpass recognizes the setuid sudo by `/proc/PID/status`**
  (effective uid 0, name sudo, parent = the stand-in that wrote the askpass
  folder's `owner` file), since `/proc/PID/exe` of a setuid-root process
  isn't readable by its user. NixOS's `/run/wrappers/bin/sudo` counts as a
  trusted sudo.
- **A narrowing creates the vault when there is none**, and every process
  that loads a valid form keeps it as `form_last_good`, so neither a syntax
  error nor a deleted form undoes a narrowing or drops this session's
  entries. A deleted form is not replaced by the last good one during the
  session (deleting it may be meant as "turn things off"); the messages now
  say that only the defaults apply until it is back.
- **While an update's env builds, the newest older env runs everything**
  (stdlib-only code), instead of hooks without decisions and an MCP server
  that quits; with no env at all, the messages say whether pixi is missing,
  the build failed, or it is still running.
- **bashparse reads `#` comments as bash does** (and a newline after `|`,
  `&&`, `||` continues), so the words judged are the words run; the Terminal
  panel, an interactive shell where zsh may not treat `#` as a comment, is
  also judged with `#` read as a character.

## Review round 3 (2026-10-19)

- **`allow` only for bare names.** The allow shapes went by
  `os.path.basename(argv[0])`, so `./ssh HOST CMD` from a cloned repo ran a
  planted file with no review. Only `ssh`, `cat`, `gate`, ... as PATH finds
  them are vouched for; `/bin/cat` now goes to the classifier (accepted
  cost). The denies still go by the basename.
- **Deny and ask by the stricter of form and effective right.** The
  stand-ins give an effective `"ask"` right to a typed command, trusting the
  hook asked; with `"ask"` approved and the form edited to `true`, the hook
  (form: true) didn't ask. A right the form gives that still waits for the
  user's OK is denied with "run gate check NAME" (the stand-in would refuse
  it anyway). `gate check` is not denied for a waiting widening (it is how
  the user approves it) but asks on an effective `"ask"`.
- **A failed command exits 0 in Claude's shell (EXIT trap in the env
  file).** (Rolled back, see "Rolled back".) Chosen over (a) rewriting every command with `updatedInput`
  (rejected again: the permission check would judge the wrapper, the user's
  allow rules stop matching, and plugin rewrites are refused for remote
  calls) and (c) only documenting the gap (the top invariant). Claude sees
  `Exit code N` at the end of the output instead of an error result; the e2e
  `leak` scenario shows the output masked and cwd tracking unchanged. Only
  where `CLAUDE_PID` is set (Claude's Bash and Monitor), never a user's
  terminal sourcing env.sh. What still fails (timeout, kill, a command that
  replaces the trap) gets the PostToolUseFailure warning: Claude is told not
  to use what it saw, the user which entry to replace.
- **Monitor must end with `| gate scrub`** (a deny with the way to do it)
  rather than a rewrite. (Rolled back, see "Rolled back".) Loops and `if` count as one unit closed by
  `done`/`fi`; anything bashparse can't read goes into a script file.
- **Transcripts at any depth.** Subagents' transcripts hold the codes of
  their tool calls; every `.jsonl` under a projects folder is protected
  (`tool-results/` stays readable). Emitting codes only from the main
  thread was considered and not taken: a subagent's notice may be the only
  one the user gets before the next prompt.
- **gate check re-verifies** a host that looks set up (host key, one test
  login) and stops behind a jump host that isn't set up; the stand-in drops
  `installed` when the host refuses the key.
- **Smaller ones**: the agent socket for "use my own SSH login once" comes
  from the session record (Claude Code's environment) and Linux's usual
  sockets, checked to be the user's socket; the launcher is written from
  the first session and says when the plugin is gone; hf's token goes
  through a 0600 file; gh/databricks/dvc/`gate with` tokens in a running
  tool's environment (`ps eww`) are a documented residual; the waiting
  notice prints only when a dialog opens; gate-askpass gives up after 60 s;
  catch-alls print one gateway line, never a traceback.

## Review round 4 (2026-10-19)

- **Background output and Claude Code's "waiting for input" notice.** (The
  deny is rolled back, the prompt hook stays; see "Rolled back".) Three
  ways were weighed: (a) deny every background command once a vault exists
  (too blunt: long rsyncs and upgrades are what background is for), (b)
  rewrite the command to pipe through `gate scrub` (rejected again for the
  round 3 reasons), (c) a deny unless the command already routes stdout and
  stderr through `gate scrub`, plus the prompt hook as a backstop for what
  can't be held to it (a foreground command moved to the background). (c)
  was taken. The cost: the completion notice then always says exit code 0
  (the pipe's status), so the deny and the SKILL give the `if CMD; then echo
  ok; else echo "Exit code $?"; fi 2>&1 | gate scrub` form. The prompt hook
  blocks a notice holding a stored value in any scrubber form (JSON-escaped
  too: the transcript holds it that way) or a token shape; blocking drops
  it for Claude (it never learns that command seemed to wait), which is
  accepted: it can read the masked output file.
- **Desktop session tools**: the export is denied outright (a file beyond any
  masking, holding one-time codes and unmasked failure output); search and
  event listing stay usable (the user may ask about another session) but
  wait while a code is live, and their results are masked.
- **`sudo visudo|vipw|vigr`**: on the destructive list by name; the path
  check alone missed the editors that take no path.
- **The sh hooks' home**: from the password database (`hooks/home.sh`), as
  Python does; `$HOME` stays for `~` in a path Claude passed (Claude Code's
  own meaning) and for finding pixi. The test redirection is `--test` with
  `GATEWAY_TEST_ROOT` (as run.py); `GATEWAY_TEST_ROOT` alone resolves no home.
- **git `erase`**: the rejected password identifies the account (constant-time
  compare against the tokens bound to that host); falling back to the
  account `get` would choose only without a password; never by elimination.
- **Rejected tokens**: no re-entry pop-up opens by itself (a token needs a
  sign-in or a paste, best started by `gate check` while the user is there);
  the messages say so instead of claiming an open pop-up. Sudo passwords
  keep their re-entry pop-up.
- **gate check's time budget**: every pop-up wait ends 100 s after the
  command started and `gate check all` starts no new entry after 60 s, so
  the exit-75 line always beats Claude Code's 2-minute Bash timeout; telling
  Claude to pass a 10-minute timeout was considered and not taken (the user
  would wait at a pop-up while Claude sat in a tool call).
- **Smaller ones**: no consent pop-up for a host whose key couldn't be read
  (first pin or new address); `_scan_via` stops after a failed connection;
  `gate import-ssh` follows `Include` and never proposes a git server (the
  form refuses a host at one); the leak warning names commands that really
  replace the secret; the launcher speaks to the user in every degraded
  state; a mid-session conversion's report comes at the next prompt; "0.6"
  in user-facing text.

## Rolled back (2026-10-19, after review round 4)

*(Superseded where the brief is explicit by "PLAN-v4 phase 4: managed
execution" below: in managed mode Claude's Bash runs in the gateway's own
bash. What this section keeps still holds: no EXIT trap, no required command
shape, a command's own exit code and output.)*

The lead's decision, final: **the gateway must not change how Claude's
ordinary commands behave.** The late review rounds had added defenses that
did; they are removed, and what remains is listed with its known limits.

- **The env file's EXIT trap (round 3) is gone**, in `envfile.env_text` and
  in launch.sh's byte-identical degraded copy. It made every failed command
  in Claude's shell exit 0 and print `Exit code N`, so that its output went
  through PostToolUse and could be masked. Why removed: it changed the exit
  status of *every* command Claude runs, to guard a narrow risk (a stored
  secret printed by a command that then fails). Claude Code, its UI, its
  `&&` chains, the model's reading of results and any tool built on exit
  codes saw success for failures; background commands always reported exit
  code 0, which needed a workaround taught in the SKILL. What remains: the
  PostToolUseFailure hook still warns Claude never to repeat, store or use a
  stored secret or token shape it saw in a failed command's output, tells
  the user which entry to replace and how, and audits a `leak` event.
  Known limit: that output itself can't be masked (Claude Code ignores
  `updatedToolOutput` there).
- **Mandatory `gate scrub` (rounds 3 and 4) is gone**: the hook rules that
  denied a Monitor command unless it ended in `| gate scrub`
  (`DENY_MONITOR`) and a `run_in_background` Bash command unless it ended in
  `2>&1 | gate scrub` (`DENY_BACKGROUND`), their parser (`_monitor_scrubbed`
  and helpers), pre_bash.sh's "every Monitor/background call goes to Python"
  cases, table rows, tests and mutations. Why removed: they rewrote the
  shape of ordinary commands Claude runs (every Monitor and background
  command needed a pipe, stderr redirections on every stage, loops closed by
  a piped `done`, and a pipe that hid the real exit status), for a narrow
  risk (a stored secret in a line Claude watches or in the tail Claude Code
  quotes). What remains: `gate scrub` as an optional filter Claude may use
  when it expects secrets in such output (the SKILL says so), and the
  UserPromptSubmit check of Claude Code's task notifications, which holds
  back a notice quoting a stored value (any scrubber form) or a token shape
  and masks it in the transcript and history (fails closed). Known limits:
  Monitor's lines and a background task's raw output (its notice when the
  prompt hook finds nothing, its task file) reach Claude or the disk
  unmasked.
- **Transcript deny: Workflow journals allowed.** Session transcripts and
  subagent transcripts stay denied (they hold hook systemMessages, the
  one-time codes among them). A Workflow run's `journal.jsonl`, exactly at
  `<projects>/<project>/<session>/subagents/workflows/<run>/journal.jsonl`
  (exact name and case, exact depth, a regular file with one link, a
  symlink judged by its target), is readable by Read, Grep naming it and
  Bash: Claude Code's Workflow tool tells Claude to read it to diagnose a
  run, and it holds the agents' results, not hook messages. A Grep or a
  recursive reader over the run folder stays denied: it holds the run's
  `agent-<id>.jsonl` transcripts.
- **Defense in depth for the no-screen path.** `gate secret` (and the
  terminal path of export, import and copy-to, through
  `gate_setup.in_claude_code`) also refuses when any ancestor process is
  Claude Code: `ancestry.claude_ancestor` walks the whole parent chain by
  executable path and refuses on the claude binary (basename `claude`, under
  `~/.local/share/claude/versions/`, the desktop app's bundled copy under
  `~/Library/Application Support/Claude/claude-code/`), on `CLAUDE_PID`, and
  when the chain can't be read, with `gateway: run gate secret in your own
  terminal, not from Claude Code`. The one-time code stays. Why: Claude's
  Bash can drop the session variables (`env -i`), not its own process tree.
  One adaptation of "can't be read": Linux hides the executable of other
  users' processes (root's `sshd`, `login`, `sudo`) and of OpenSSH's
  non-dumpable session process; refusing on those would make `gate secret`
  unusable over ssh, the main no-screen case. Another user's process can't
  be the user's Claude Code, so the walk goes on above it; an unreadable
  process of the user's own refuses, except a session process named
  `sshd`/`sshd-session` under a root parent. Limits: a process Claude
  detaches from its tree (a double fork, a terminal window it opens) and an
  npm install (executable `node`) without `CLAUDE_PID` aren't seen; a shell
  whose parent is outside its PID namespace (`docker exec`) can't be read,
  so `gate secret` refuses there. The desktop app's Terminal panel runs
  under the app's helper, not Claude Code, so the user can use it.

## Review round 5 (2026-10-19, after the rollback)

The lead's decision stands: nothing here changes how Claude's ordinary
commands behave (`gate secret` is the gateway's own command, for the user).

- **A process tree that can't be read gets its own message.** macOS's
  `proc_pidpath` returns nothing for a process whose executable was deleted
  or replaced while it runs (the review checked a copied `sleep`: its path
  before the unlink, nothing after; a test now runs `gate secret` under a
  deleted copy of the shell). That is ordinary in the user's own terminal:
  the login shell in every open tab, or a tmux server, after `brew upgrade`
  or `port upgrade` (this user's shells are MacPorts' bash). `gate secret`
  refused there with "not from Claude Code", and the no-screen export,
  import and copy-to told the user to "ask the user ... don't run it
  yourself". It still refuses (the check can't tell the user's replaced
  shell from a copy Claude started and deleted), but says `gateway: can't
  tell which programs started this terminal (one of them was updated or
  deleted while it ran, or this is a container), so this is refused here;
  open a new terminal window and run CMD there`, audited, in `gate secret`
  and in transfer's terminal path. The walk now goes on above an unreadable
  process of the user's own, so a Claude Code process further up still gets
  "not from Claude Code". Rejected: walking past an unreadable process whose
  comm isn't `claude` and passing it (the reviewer's option): the native
  install names its binary by its version (comm `2.1.301`) and auto-update
  can remove old versions while sessions still run on them, so exactly those
  sessions would pass. Linux reads a deleted executable's path (`... (deleted)`),
  so this is macOS only. docs/dev/modules/sudo.md had said every macOS path is
  readable; corrected.
- **`gate secret` is denied in every tool.** The desktop app's Terminal panel
  runs its shells under the app's helper, which the process-tree check
  (rightly) doesn't count as Claude Code, so the user can work there; but
  Claude types into that panel with `mcp__terminal__run_in_terminal` and
  reads it with `read_terminal`, and no hook decided anything about `gate
  secret`. The approval hook now denies it for Bash, Monitor and the panel
  ("gate secret is for the user; ask them to run it ..."), also behind
  wrappers and inside shell strings, eval, loops, `find -exec` and commands
  the parser can't read (a text scan only where the words hide what runs, so
  `grep 'gate secret' README.md` is judged as before), and denies `gate
  export|import|copy-to` typed into the panel (their no-screen path asks
  there for the user's code; in Claude's Bash they use pop-ups or name the
  command for the user). The user's own typing in the panel passes no hook.
  The one-time code stays the guard.
- **What each tool call costs.** The reviewer measured with the harness
  (N=25, medians): with a vault, post.sh 133 ms (small Bash response) and 146
  ms (12 KB Read) against 18 ms without; the file guard 66 ms on every Read,
  Grep, Glob, Edit, Write, MultiEdit and NotebookEdit. Profiling showed age
  at about 8 ms; the rest was starting Python and imports (popup pulls in
  urllib.request and the form; testing pulled in dataclasses and inspect).
  Changes: (1) post.sh no longer starts Python for an Edit's, Write's or
  MultiEdit's response just because a vault exists: Claude Code 2.1.301
  gives Claude only "The file X has been updated successfully" / "File
  created successfully at: X" for them (read in the binary), so masking
  them masked nothing Claude reads; the shape, gateway.toml and notice
  triggers stay, and an edit tool counts only when the payload names
  `"tool_name"` once. (2) hooks_post imports popup only when private/pending
  holds a request or code, and form only for form edits and failures;
  vault, paths and testing load their heavier modules lazily (testing's
  `Override` is a plain class now). (3) launch.sh passes a plain file-guard
  path inside cwd in sh (SPEC 12: key checks, a character allowlist, no
  symlink, an inode comparison with every protected place along the path, no
  symlink inside private/, one link), and sends everything else to Python;
  a test compares the two answers case by case, with a mutation per check.
  (4) launch.sh hashes pixi.lock without a subshell and `cut`, and the sh
  hooks find their folder without `dirname`. After (same machine and harness
  as the reviewer's script, a stray busy loop still on one core): post.sh
  with a vault 65 ms for a small Bash response and 66 ms for a 12 KB Read
  (was 133 and 146), 20 ms for an Edit's or Write's response; the file guard
  20 ms on the sh fast path and 48 ms when it goes to Python (was 66); the
  harness's own process start is 8 ms of each. Another heavy process (a
  local model server) also ran during this measurement, so these are upper
  bounds.
  Rejected: serving scrub requests from the MCP server over a 0600 unix
  socket (the reviewer's suggestion): sh has no portable unix-socket client,
  so each call would still start Python (saving perhaps 20 ms more), for a
  socket every process of the user's could reach, per-session servers to
  find and outlive, and a second masking path; the notice and form duties
  stay in the hook's own process anyway (a notice marked shown through a
  socket would be a way for Claude's Bash to hide it). A compiled matcher on
  disk was rejected in round 2 (secrets outside private/). New known limit:
  an edit tool's response (with the file's earlier text) stays unmasked in
  the transcript's record of the call; Claude doesn't read it (the one-line
  result, the transcript deny, the masked session readers).

## Checkpoint jobs (2026-10-19)

The user asked that checkpoint jobs follow the gateway (and pixi-guard, on
pixi-guard's side). A `job_start` job ran with the user's own session
environment: no stand-ins, the user's agent and token variables, and no
approval hook. Each plugin still works alone: the gateway's part activates
only when checkpoint is there.

- **env.sh is a no-op once the stand-in folder is gone.** Checkpoint sources
  `~/.config/gateway/env.sh` (SPEC 7; the gateway rewrites it at every
  session start) before a job's command. After an uninstall the file stays
  in `~/.config/gateway`, and its PATH entry, `GIT_SSH_COMMAND` to a missing
  ssh and unset agent would break the user's jobs, so everything after
  `GW_BIN=` sits in `if [ -d "$GW_BIN" ]; then … fi` (POSIX, no `return`;
  the same bytes from launch.sh while the env builds). The trade-off: if
  `$DATA/bin` is deleted mid-session, Claude's next commands keep the user's
  agent and token variables (the same class as any code running as the
  user: Claude Code's own environment holds them anyway; text checks are a
  guardrail, not a sandbox).
- **job_start goes through the Bash approval hook**, in the same matcher and
  the same prefilter (one word list; a sibling prefilter would drift): its
  `command`, or `argv` shlex-joined, gets every Bash deny (curl/wget, the
  private folder, transcripts, `gate secret`, rights `false` or waiting,
  `az … get-access-token`, `GIT_TRACE_REDACT`).
- **An "ask" right is denied in a job**, not asked: Claude Code's prompt
  would approve starting the job, while the ssh or sudo runs later, with no
  one watching, from a tree the stand-ins never count as typed
  (`typed_by_claude`), so they would refuse after the prompt anyway. The
  reason says to run it with the Bash tool as its own command.
- **gate export/import/copy-to are denied in a job**, as in the Terminal
  panel: without a screen they ask for the user's one-time code in a
  terminal, which a job doesn't have, and a job that outlives Claude's
  process tree (reparented to init) escapes `gate`'s Claude-ancestor check.
- **Never allow (nor ask) for job_start.** The gateway vouches only for
  shapes it sees run now in Claude's shell; a job runs unattended, after the
  turn, maybe after the session. Claude Code's own check decides (a prompt in
  default mode, the classifier in auto mode). `_main_job` passes only a deny
  whatever the decision below it says (a second layer, tested on its own).
- **`typed_by_claude` refuses the checkpoint runner explicitly** when
  `CLAUDE_PID` names it (a job's environment can't make the wrapper shell
  look like Claude's command shell); before, only the fork test refused it.
- **Claude is told only when checkpoint is around**: one how-to line when
  checkpoint's state folder exists (`${XDG_STATE_HOME:-~/.local/state}/
  checkpoint`); the skill has a section either way.

Rejected: allowing a job whose command Bash would allow (unattended, later);
turning "ask" into a prompt (it would be refused after the prompt); a
separate prefilter script for job_start.

Integration review (2026-10-19): a job's `cat notes.txt` came back raw
through `job_tail` (then a documented known limit), and with the stand-ins
jobs use credentials routinely, so that path is common. **The output hooks
name `job_tail`, `job_status` and `job_stop`** (PostToolUse and
PostToolUseFailure, exact names: nothing changes without checkpoint);
`hooks_post` is generic (`updatedToolOutput` for any tool response), so no
Python changed. Not `job_start`: its result is the record of what Claude
just sent. A `job_stop` that fails (`stop_failed`, an MCP error result with
the last log lines) gets only the PostToolUseFailure warning, like a failed
Bash command. Rejected: a regex such as `mcp__plugin_check_jobs__job_.*`
(it would take in tools checkpoint adds later without anyone looking at
what they return).

## Integration lows (2026-10-19)

Low findings from the integration run and its verification (checkpoint
jobs now run in parallel, and through the gateway):

- **One ssh master per ControlPath, also for parallel calls.** Two ssh
  calls to one host that start before either's master listens race under
  `ControlMaster auto`: the second prints OpenSSH's `ControlSocket ...
  already exists, disabling multiplexing` into the command's output (and
  opens a second login). The stand-in now takes an `fcntl.flock` on
  `<run>/cm-%C.lock` (next to the socket; every master of the chain, in
  sorted order) when no master answers, checks again, and holds it until
  its master answers (polled, as for the agent) or ssh exits; a parallel
  call waits and reuses that master. The wait is bounded (5 s in all,
  `ssh_conf.MASTER_LOCK_WAIT`): a slow first login can't stall others for
  longer, after which they go on without the lock (the line may then still
  appear). scp/sftp (`ControlMaster=no`) wait for the lock but don't keep
  it. The lock files stay (removing one while another call waits on it
  would split the lock). Rejected: `ControlMaster autoask`/a fixed master
  started up front (a second process to manage, and no help when two calls
  start it), retrying after the line (the output is already printed).
- **Follow-ups to the master lock.** (a) The gate process's own calls
  (`Conn.capture`: copy-to's `ssh.run`, passwordless sudo setup, rotate,
  the sudo probe) kept the lock for their whole remote command, so a
  parallel stand-in waited the full 5 s; they now use the same
  `Conn.master_watch` as the stand-in's `run_child`: the locks go and the
  private agent is killed as soon as the target's master answers
  (`test_ssh_exec_long_call_frees_the_lock_once_its_master_answers`,
  `test_ssh_exec_gate_capture_frees_the_lock_once_its_master_answers`; 3
  mutations). (b) The verifier then found that a call that gave up on the
  lock (the holder's login took longer than 5 s) still ran that watcher and
  multiplexed: when the holder's master answered, the watcher killed the
  waiting call's agent while its own ssh was still logging in, the call
  failed with `Permission denied (publickey)` ("refused Claude's key") and
  `gate check` reported the key refused for 90 s (a proxy delaying the
  first login 7 s failed the second call 4 of 4 times). Now only a call
  that holds a hop's lock may start a master there: a hop it couldn't lock
  is reached without multiplexing (`ControlMaster no`, `ControlPath none` in
  that call's config), so it keeps its agent until its ssh exits and runs no
  watcher, and the holder can't be fooled by another call's master either
  (none can appear while it holds the lock). scp/sftp, which drop the lock,
  reach every hop that way too. A call that gave up costs one more login
  and starts no shared master; the "ControlSocket ... already exists" line
  can't appear then. Rejected: keeping the watcher but checking that the
  master answering is the call's own (a master doesn't say who started it),
  and reusing a master that appears later from a call without the lock
  (`ControlMaster no` with the shared path: a stale socket prints an error
  into the output, and a call has its agent anyway). Tests hold each login
  at a proxy until released (`harness_ssh.HoldProxy`, the lock wait cut to
  1 s through `testing.override(master_lock_wait=...)`); 8 mutations.
- **An "ask" right inside a job gets the job wording from the stand-ins
  too.** A job that reached an `"ask"` right indirectly (a script; the hook
  only denies what the command line shows) got `run it as its own command
  so Claude Code can ask you`, and Claude started another job, which the
  hook then denied. `ancestry.typed_by_claude` now names the culprit
  `checkpoint` whenever it refuses and checkpoint's job runner is the
  stand-in's parent or above it, and the ssh and sudo stand-ins then say
  what the hook says for `job_start` (`consent.job_ask_message`: run it with
  the Bash tool as its own command, or ask the user to set it to true). A
  job whose runner has ended (its session closed, the job re-parented to
  init) isn't recognised and keeps the general wording.
- **The tests use checkpoint's current job wrapper.** Gateway tests still
  ran jobs with checkpoint's old two-argument wrapper; the current one
  sources env.sh itself and records `applied` only when that is silent on
  stderr. It is pinned (copied with its source and date, never imported
  across repos) in `tests/harness_sudo.py` (`CHECKPOINT_WRAPPER`, used by the
  job trees) and `test_envfile` checks `applied` and an empty stderr for
  `env_text("refuse")` and `env_text("mine")`, with and without `$DATA/bin`,
  under /bin/sh and dash: env.sh must never write to stderr when sourced.
- **An optional e2e scenario `jobs`.** It runs only when a checkpoint
  checkout sits next to the gateway repo (`../checkpoint/plugins/checkpoint`)
  and is skipped otherwise, so the gateway stays self-contained. One short
  session with both plugins (CHECKPOINT_HOME and CHECKPOINT_GATEWAY_ENV
  inside the e2e root, a watcher that kills the session if checkpoint's
  server shows anything else): an env probe, ssh, remote sudo and argv jobs,
  curl, "ask" and private-folder denials, the stand-in's job wording, and
  `job_tail` masked.
- **A job that outlives its session gets credentials only from entries
  with `scripts = true`.** When the session ends, checkpoint's runner exits
  and the job is re-parented to init: `is_direct` finds neither
  `CLAUDE_PID` nor the runner above the stand-in (`(False, "?")`, or `(True,
  "?")` with `scripts = true`) and `typed_by_claude` refuses with the
  general wording (checked with checkpoint's real `jobs.start` and an ended
  runner). Kept as it is: the user chose credentials for direct callers
  only, and trusting a process that looks like checkpoint's wrapper would
  let any process claim to be one. The README, the skill and Claude's
  context say so: keep the session open for a job that needs credentials,
  or, where acceptable, give that entry `scripts = true`. (They first also
  offered Bash's `run_in_background` as a way around it; wrong, and
  removed: Claude Code 2.1.301 kills background Bash commands when a
  `claude -p` session winds down, and one left running after an interactive
  exit is re-parented and fails `is_direct` the same way.) Such a caller
  (culprit `?`) was named "?" by the sudo stand-in and "a script" by the ssh
  stand-in; every stand-in now says "a program the gateway can't trace back
  to Claude (such as a job still running after its session ended)"
  (`ancestry.UNTRACED_WHO`).

## First SessionStart and the e2e jobs scenario (2026-10-19)

Two findings from the verification of the integration lows:

- **The first SessionStart on a new env was slow.** The verifier's `e2e
  --only jobs` runs (the e2e root's first session) spent 12.6 s and 13.1 s
  in the sync hook, and one run hit Claude Code's 20 s limit, which dropped
  the gateway's context. Earlier e2e runs' first sessions took 5-12 s, later
  ones 0.15-0.4 s. It wasn't gateway work: macOS checks each new executable
  and library at its first load (the env's python, its extension modules,
  libssl, libcrypto, libffi, age), and reading the files first doesn't help.
  Measured in a harness root with a real `pixi install`: the first `launch.sh
  hook-session` took 5.5-6.0 s, the next ones 0.11 s. Now `ensure-env`, the
  async hook, loads a new env once right after building it
  (`gateway/warm.py`: every gateway module, the standard modules they import
  later, `age --version`, `ssh -V`; marked `.warm`), and SessionStart no
  longer imports popup (urllib, http, email, ssl) for a session-id slug.
  After: the first hook-session 0.56-0.98 s (the first session's own writes,
  and the sh stand-ins when `$DATA/bin` is missing), then 0.11 s; the e2e
  jobs session's 0.74 s; ensure-env takes 8.5-11.6 s instead of 0.9 s, in
  the background. A user's first session runs the sh fallback while the env
  builds, so their next session starts warm.
- **A cancelled or killed SessionStart leaves a safe, whole state.** Before
  starting Python, launch.sh writes the env file (`others = "refuse"`) and,
  when missing, the stand-ins and the git reset: a session whose hook dies
  still runs Claude's commands through the stand-ins without the user's
  agent and tokens. Every file SessionStart writes is now written whole: the
  env file (temp file + rename; Claude Code sources only
  `sessionstart-hook-N.sh`), the starter form and the session record (temp
  file + hard link, only if none exists), the context record (rename);
  env.sh, the stand-ins, the git include and the launcher already were. A
  SessionStart that finishes past the limit (timed from its process's
  start) leaves the session with no context record, so the next prompt's
  hook gives the context; the next session writes everything again. A test kills SessionStart halfway
  through each of its 21 file writes in turn.
- **The e2e jobs scenario and the classifier.** It failed in 3 of 3
  verifier runs, each time because Claude Code's auto-mode classifier
  denied a `job_start` (`[Third-Party Attack]`, `[Credential Exploration]`,
  or no reason), never because of gateway code. The gateway still never
  approves a job. The session now gets honest context (a `CLAUDE.md` in the
  work folder for that session, and one line in the prompt: the user's own
  test, local sshds on 127.0.0.1, fake secrets, the task), and a step the
  classifier denies is reported as "not reached (classifier)": no pass, no
  failure, counted in the summary. The gateway's own denials come before
  the classifier and still fail hard, as does every check on a job that
  ran. Rejected: approving job_start in the e2e copy, or wording the prompt
  to get past the classifier.

## PLAN-v4 phase 2: the daemon and the broker (2026-10-19)

The per-user daemon `gated` and its broker (docs/dev/modules/daemon.md). Built
from the phase-2 notes; where the code showed a better way, or the notes left
a choice open, this is what was chosen and why.

- **Unwrapped vaults keep the local path.** With `private/key.txt` on disk
  (every vault before this phase, and every vault until phase 3's dialog
  lets the user set a passphrase), the stand-ins, hooks, git helper, MCP
  server and gate keep decrypting locally, as before: a same-user process can
  read key.txt anyway, so routing through the daemon would add a failure
  mode and no protection. Only a wrapped key (key.wrapped + key.recipient,
  no key.txt) makes `vault.brokered()` true, and then every read and write
  goes through the daemon, with no fallback. No regression for existing
  vaults; the broker path is exercised by the wrapped-mode tests.
- **age's scrypt recipient, not PyNaCl, wraps the key.** The brief asks for
  an established construction; age's passphrase recipient (scrypt +
  ChaCha20-Poly1305) is one, and the env already ships age and the
  private-pty driver export uses. The driver moved from transfer.py to
  `agepass.py` (transfer keeps its wrappers and messages). No new dependency,
  so pixi.lock (and every user's env) is unchanged in this phase; PyNaCl
  comes with phase 3's sealed boxes, where the plan needs it anyway.
  Invariant 13 (stdlib only) still holds. The identity reaches age on an
  inherited pipe (`-i /dev/fd/N`), never a file or argv.
- **Scoped data by entry point mode, with sentinels and merged writes.**
  "Scoped vault data" could have meant one call per operation (sudo password
  for X, token for Y); that would have rewritten every module that reads the
  vault (about 110 call sites). Instead the daemon gives each run.py mode the
  secret classes it needs (`broker.SCOPES`: sudo sees only localhost sudo
  passwords, ssh only host keys, host sudo and account ssh keys, the account
  CLIs and the git helper only tokens, sign-ins and the token cache) and
  replaces the rest with HMAC sentinels keyed per daemon (they say nothing
  about the value). The code that reads `vault.load()` didn't change. Writes
  come back whole; the daemon swaps sentinels back and refuses (409) a write
  that adds, changes, moves or drops a value its writer couldn't see (moving
  a sentinel into another account would otherwise send a token to that
  account's destination). Hooks, `gate` and the MCP server's masking need
  every value: hooks and gate see all classes (`hook-files`, which needs
  none, sees none).
- **The direct rule runs in the daemon too.** A peer that isn't a direct
  caller (ancestry's walk, now `ancestry.walk_direct`, from its parent up to
  its *registered* session instead of `CLAUDE_PID`) gets sentinels for every
  entry without an effective `scripts = true`. The stand-ins keep their own
  check and messages; this is defence in depth that doesn't trust an
  environment variable.
- **Hooks are entry points and register sessions.** The notes list
  stand-ins, askpass, the git helper and the MCP server; with a wrapped key
  the hooks read the vault too (rights, masking), so `hook-*` modes are
  accepted. Registration has two routes: the mod's `/ui/register` (the peer
  pid is the claude pid; `claude_pid`, when sent, must match: the kernel's
  answer is the authority, and the mod can't always know its own pid) and a
  gateway hook's `/agent/register` (the claimed Claude Code process must be
  above the hook), which the new async SessionStart hook `hook-daemon` uses so
  the daemon runs and knows the session without mods and in `claude -p`. The
  client registers by itself when a hook meets "not registered". Sessions are
  persisted in the run dir so a restarted daemon (version skew, crash) still
  knows them; each is re-checked by pid, start time and executable.
- **A local plane for stop and restart.** `/local/stop` and `/local/restart`
  take any gateway entry point, registered session or not: a newer plugin's
  `gated start` runs before its session is registered, and stopping a
  same-user daemon is no more than `kill` already allows.
- **Version skew by version number only.** A daemon restarts for a newer
  plugin version when idle (no terminals or jobs; none before phase 5); an
  equal version never restarts it (two copies of one version, such as an
  installed copy and a `--plugin-dir` checkout, would otherwise restart each
  other, and each restart relocks a wrapped vault).
- **Test-only routes for the passphrase.** `/test/vault/passphrase` and
  `/test/vault/unlock` exist only when a test override's knob enables them
  (production answers 404; a mutation checks it). The OS-dialog and popup
  paths are untouched, as asked: no production vault becomes wrapped before
  phase 3's native dialog.
- **Locked means refused up front.** A stand-in with a wrapped, locked key
  prints the daemon's refusal before it runs (rights live in the vault too,
  so even passwordless sudo is refused rather than run on default rights);
  the daemon words it for the caller's session (a session whose mod
  registered with a surface can unlock there; `-p` and mod-less sessions get
  "unlock it from an interactive Claude Code session"). The Bash hook gives
  the same words instead of "waits for the user's OK"; SessionStart says the
  vault is locked; PostToolUse masks token shapes only while locked (no
  program can get a value then).
- **`[vault] lock_after`** is a duration from "1m" to "1d" (default "8h").
  It isn't under the widening rule yet (phase 3 brings native approvals);
  the one-day cap bounds what an edit of the form can do meanwhile.
- **Machine ids.** contract.json's `machine_id` and localhost's snapshot id
  are a sha256 of the machine id (`m_` + 26 base32; the raw hardware UUID
  isn't published). Remote hosts get an id assigned on first sight and kept
  in `$DATA/gated/machine-ids.json` (`identity: "assigned"`): stable across
  restarts, but not a verified machine identity (phase 7).
- **The daemon exits when its socket is gone.** A removed run dir means
  nobody can reach it; the e2e suite and the TUI harness delete theirs when
  they finish, so a daemon a test session started never outlives the test
  (tick 0.25 s under the e2e marker). The TUI harness itself is unchanged.
- **The test guard never stats the gateway home** (phase-1 finding):
  `testing.forbidden_roots` resolves only parent folders and compares the
  protected paths as written (any case); a candidate is resolved only after
  that, so a symlink into the home is still refused. The e2e-marker test
  that asked `Protected.contains` about the real path uses a fake real home
  now. The guard's mutations would stat the real home through
  `run_tests.py`'s own `tmp_base()` call, so `tests/mutations_daemon.py`
  points `GW_TEST_REAL_HOME` (harness.py) at a scratch folder for its runs.
- **web's local-path rules resolve both sides** (phase-1 finding): the
  allowed roots were resolved and the path as written was compared with
  them, so under a symlinked temp root (macOS `/var/folders`) every project
  path failed; now the resolved path is compared with resolved roots (a
  symlink out of the project is still judged by its target).

## PLAN-v4 phase 2 review fixes (2026-10-20)

A verifier's findings on the daemon and broker, each reproduced by a script
and now covered by a test and a mutation (`tests/mutations_daemon.py`).

- **A lock reaches a process that runs for the whole session.** The vault
  client kept its scoped view for the life of the process, keyed only on
  `vault.age`'s stat, so after a lock (explicit, idle, daemon exit) the MCP
  server's http and download tools kept getting the real token while
  /health said "locked". The client now asks the daemon on every read and
  keeps nothing between reads; the daemon judges each read when it is made
  (lock, session, scope). A lock generation returned by the status route
  was the other option; it would still have needed a round trip per read,
  plus a second rule for scope changes (a narrower `scripts = true`), so the
  simpler rule won. To keep a read cheap the daemon keeps the decrypted
  vault while `vault.age` stays the same file and the key unlocked, and
  forgets it on a write and on lock: the daemon holds the identity anyway,
  so the copy reaches nothing more. A repeated read costs a socket round
  trip, less than the age run every read cost before phase 2 (macOS arm64,
  50 reads of a test vault: 0.8 ms per read through the daemon, 6.9 ms per
  read decrypting locally with key.txt).
- **A session is its pid and start time; the executable is checked only at
  registration.** On macOS a running process whose executable file was
  unlinked has no path, and on Linux it reads `<path> (deleted)`; the
  native install keeps two versions and Homebrew removes the old one, so a
  session running across an upgrade was dropped at the next tick, refused
  on every plane, couldn't register again, and the daemon exited for
  idleness under it. The start time already guards against pid reuse
  (`peers.alive` compares it), and exec keeps the start time but Claude Code
  doesn't exec into other programs; ptrace-level tricks are outside what the
  planes defend anyway. A live registered process counts as Claude Code when
  it registers again (`Registry.claude_ok`), so the mod at /clear and the
  hooks still work; a process that never registered still needs a Claude
  Code executable, and a registration needs a readable start time.
- **Entry points: this plugin's run.py, or a sibling version in the plugin
  cache, started with `-I -S`.** The phase-2 notes said `<root>/run.py`; the
  first build accepted any folder whose `.claude-plugin/plugin.json` said
  "gate" and any interpreter options, so a two-file folder in /tmp run as
  `gate status` got every secret class, and the real run.py started without
  `-I` would load a planted `sitecustomize`. Now `<root>` must be
  `paths.code_root()` or, only when that is a version folder of Claude
  Code's plugin cache (`<config>/plugins/cache/<mkt>/<plugin>/<version>`), a
  sibling version folder naming "gate": the sessions of the old and new
  version share one daemon after an update, and the newer one's `gated
  start` must be able to ask an idle older daemon to restart. A
  `--plugin-dir` checkout and the e2e copy have no siblings. The options
  must be exactly the launchers' (`-I`, `-S`, `-X pycache_prefix=...`). Not
  closed, and not closable here: code running as the user can run the env's
  python on the real run.py with any mode, or write a folder into the plugin
  cache; the checks keep a cooperative model's scripts off the vault plane,
  they are not a boundary (docs/dev/modules/daemon.md "Known limits"). The
  daemon tests that need a production-like entry run the daemon from a
  plugin copy in a cache layout (`harness_daemon.plugin_copy`), and probes
  in the test root are test entries (the test root before the mode) only
  while the `test_entries` knob is on.
- **Passphrases are bounded in UTF-8 bytes, and age runs outside the
  flock.** age reads the passphrase as one line in the tty's canonical mode;
  macOS ends a line at 1024 bytes (MAX_CANON), so a 1024-character or a
  600 x "é" passphrase (both accepted by the 12-1024 character rule) hung
  age for its 130 s timeout, with the broker's mutex and the vault's flock
  held. The bound is 512 bytes (wrap and unlock; control characters refused
  on both), and `agepass` refuses a longer passphrase before age starts
  (`PassphraseTooLong`; export and import report it too). `set_passphrase`
  runs both scrypt passes without locks and takes the flock, then the mutex
  (the order the client's write path uses), only to re-check that key.txt
  is still the key it wrapped and to put the files in place.
- **Version skew reaches the user.** /health doesn't know who asks, so it
  carries no skew; `gated status` (what /gate-doctor runs) now adds it for
  any version difference with the plugin copy that runs it, and `gate
  status`'s daemon line says the same (`daemon.skew_text`). Before, only
  `gated start`'s answer had it, and the mod dropped it.
- **The daemon's log is rotated while it runs.** It was rotated only at
  start; one daemon refusing a consumer's polls all day grew it without
  bound (7 MB in 25 s in the verifier's flood). `Daemon.log` now checks the
  file's size after each line and moves it to `gated.log.1` past 1 MB,
  reopening stdout and stderr on a new file (the same flood afterwards:
  94,508 refused requests, one `.1` and a 0.28 MB `gated.log`).
- **Security checks that had no killing test now have one**: pid reuse (a
  sessions record whose start time differs gives the process holding the
  pid nothing), data-folder env pythons (the daemon's data folder's are
  accepted, another's refused), a hook naming its parent shell (403 `exe`),
  and unlock's key.recipient check.

## PLAN-v4 phase 3: native dialogs (2026-10-20)

Every question the gateway asks is a native pane inside Claude Code
(docs/dev/modules/ux.md "popup.py" and "dialog.py", docs/dev/modules/daemon.md
"Dialogs"). The OS
dialogs (osascript, zenity, kdialog), the `gate secret` terminal path with
its one-time codes, the terminal export/import/copy-to path and the browser
and device-code sign-ins are gone. Built from PLAN-v4 "Credential dialog" and
FEASIBILITY-v4 P1/P3b/P6; where the code or a live run showed something the
plan didn't, this is what was chosen and why.

- **gated owns the requests; popup.py keeps its broker.** popup.py's
  request keying, one dialog per (entry, what) across processes,
  verify-then-store and outcomes stay; only its backend changed
  (`dialog.Dialog`). gated holds each request (id, entry, what, kind, the
  fixed text lines, an X25519 key pair per open attempt), one per session
  on screen at a time and the rest queued by identity.
- **A lease, because the asking helper is detached.** popup.py's helper
  double-forks out of the session's process tree (it outlives the stand-in's
  90 s wait), so it can't pass the agent plane's "below a registered
  session" check. The requester (still in the tree) takes a lease
  (`/agent/dialog/lease`: availability is decided there) before it forks;
  the helper opens and waits on dialogs with the lease token on a new
  "lease" plane (any gateway entry point of this user holding a valid
  token; the token's sha256 is all gated stores). Dialogs of a lease close
  when it expires, is released, or every process that used it has died.
- **The value is opened in gated and handed to the helper once.** The
  Client seals {rid, attempt, values} with TweetNaCl's box to the attempt's
  public key; gated opens it (PyNaCl), rechecks the request (still open, not
  past its deadline, its session alive and not paused, the lease's
  processes alive, the form entry still there with the same section, kind
  and right) and gives the plaintext to the helper on its next wait, then
  drops it. The helper is a gateway process, the same trust as a vault read
  (scoped values already travel gated -> stand-in this way); it verifies
  (sudo -v, ssh-keygen, the GitHub/HF/Entra check) and stores, or asks gated
  to reopen the dialog with "That didn't work" and a new key pair. The
  plaintext never travels between Claude Code and gated: `/ui/dialog/submit`
  refuses a body with a `value`. The vault's own dialogs (unlock, set a
  passphrase) are gated's: the broker checks them itself.
- **The requests survive gated and the mod.** Metadata only (never a key, a
  value or a lease token) is kept in `<run>/gated-dialogs.json`: a gated
  killed mid-dialog restarts (the helper's next call starts it, so does the
  mod's loop after two failed polls), restores its requests with new key
  pairs, and the mod shows them again (verified live: SIGKILL, the dialog
  reopened, a value typed afterwards stored). `/reload-plugins` loses only
  the mod's memory: the request is still in gated and the reloaded mod opens
  it again.
- **Clicks only in the fullscreen layout (found live, not in the plan).** A
  Client takes keys only after a click (P1), and Claude Code 2.1.301 reports
  mouse events only in its fullscreen (alternate-screen) layout. On the main
  screen (`CLAUDE_CODE_NO_FLICKER=0`, tmux's default, and, in the TUI
  harness, the default as soon as Claude Code's online feature settings are
  fetched: telemetry on behind the record-only proxy started Claude Code on
  the main screen with no mouse modes at all) a click does nothing, and the
  focus ring (ctrl+x tab, /gate-dialog) reaches Buttons, never a Client. So
  the field is drawn only where it works (a fullscreen terminal, the desktop
  app); on the main screen the dialog says how to type privately
  (`CLAUDE_CODE_NO_FLICKER=1`) and offers Paste from clipboard, reachable
  from the keyboard; the guard is off there (it would block the prompt box
  with no field to type into). No other private typing path exists on the
  main screen: `Input` is plaintext to every plugin (P1).
- **The guard covers secret dialogs on screen only.** While a secret
  dialog is drawn and its field can take keys, `prompt.edit` edits are held
  back ("click the gateway dialog's field first") and the field is reset
  (another key: nothing typed carries over). Consent and choice dialogs
  don't hold the prompt box (nothing secret is typed there, and the person
  may want to answer Claude). The guard can't hide those keys from other
  plugins' prompt.edit hooks or the editor's one-frame paint (P1): the
  acceptance run records that exposure as a note, never as a pass.
- **Focus moving away resets the field.** A Client gets no "focus lost"
  signal: Escape and a click elsewhere take its keys silently, and the
  pane's `isFocused` stays false the whole time a Client holds the keys
  (seen live with the observer plugin, so the first design, an epoch bumped
  when `isFocused` fell, never fired). Keys reach the field again only
  after a click, so every click on the field starts it over (field.tsx:
  the buffer overwritten, no bullets); the pane's ring moving onto one of
  its buttons (`ui.focus`: Tab, a click on Paste or Cancel) and any guarded
  composer edit bump an epoch in the field's key (a new Client instance,
  the old one's characters overwritten and dropped). What was typed before
  the focus moved away is never sealed together with what is typed after.
- **A new key pair is a new field (found live).** After gated was killed
  mid-dialog it restored the request with a new key pair, but the field
  instance survived (same dialog, attempt and epoch) and its key listener,
  registered at the first render, still sealed to the old public key: gated
  couldn't open the box and the dialog sat at "checking" until the
  requester gave up. Now a new public key for the same dialog and attempt
  bumps the epoch (a new field, nothing typed carries over), the field
  always seals with its latest props and resets when the key changes, and a
  box gated refuses (`box`, `stale`) starts the field over with "type it
  again" on the status line. The acceptance run's kill step and its broker
  receipt (by hash) pin it; mod tests and mutations too.
- **Posts are batched per field instance.** Every post carries the whole
  outbox with sequence numbers and is re-sent until the hooks module
  acknowledges it in the props it returns; the hooks module forwards each
  (field instance, sequence) once. A retry's field is a new instance whose
  numbers start over (the first live run lost the second attempt when the
  dedupe was keyed by dialog id; a mod test and a mutation pin it).
- **Keys without a click.** Consent and choice dialogs take `y`, `n` and a
  digit per option once the pane holds the keyboard; a secret's dialog has
  no hotkeys, so a letter meant for the field never presses Cancel or Paste.
- **"Remember it" only where storing is optional.** A sudo password a
  command asks for may be used once (unticked: not stored); tokens, API keys
  and client secrets are setups (always stored); a password used once by
  design (installing a key, passwordless sudo) isn't stored and offers no
  choice.
- **Pause through the contract.** `/v1/pause` and `/v1/resume` are no longer
  501: gated records the paused Claude Code session (persisted with the
  dialogs), closes its open dialogs ("paused") and refuses new leases and
  answers for it, so a credential never restarts a task the user paused.
  There are no gateway jobs yet, so the per-job outcomes list is empty;
  "pause" joined the contract's features. Checkpoint doesn't call it yet.
- **Paste reads the clipboard in gated, by absolute path.** pbpaste on
  macOS; wl-paste, else xclip or xsel on Linux, only when the file (after
  symlinks) is root's and not writable by others; the display variables come
  with the UI-plane request (Claude Code's own environment; gated's has
  none), checked by pattern. One line of text up to 8 KiB, no control
  characters. Under any test override only the `clipboard` knob's program
  runs; nothing else (no test ever reads the person's clipboard).
- **PyNaCl in the env, imported by gated only.** Invariant 13 now allows it
  (pixi.toml, pynacl 1.6.*; pixi.lock only added pynacl, cffi, libsodium and
  their small deps). gated runs with `-I -S`, so `_nacl()` appends the env's
  own site-packages folder for that import only (no .pth runs).
  TweetNaCl 1.0.3 is vendored (`hooks/mod/vendor/`, VENDOR.md: npm
  integrity, the original sha256, the one-line ES-module change); the PRNG is
  set explicitly from crypto.getRandomValues.
- **Unavailable means unavailable.** No lease for `claude -p` / the SDK (no
  surface), mods off (a hook-only registration), mobile, VS Code: popup
  prints why and how it can be given later; nothing is persisted as
  "unavailable" (that record only fed the terminal command). Remote Control:
  its clients attach as mobile (no Client); a terminal attached at the same
  time still draws the field locally. The desktop app's Client relay is
  local IPC by design but wasn't verified here (manual check).
- **Browser sign-ins removed, with what works named.** GitHub: a personal
  access token in the dialog (checked with GET /user). Azure: a service
  principal (the account's own `client_id` and `tenant`; its client secret
  checked with a client-credentials token, stored as `entra.client_secret`;
  `entra.access_token` mints with it when there is no refresh token; masked,
  scoped and exported like a refresh token). ml-catalog: unavailable (the
  catalog's API expects a user's token); an existing refresh token keeps
  working. `gate check` says so before any dialog, so nothing is approved
  that couldn't be used.
- **The one-time codes went with the terminal path.** The desktop app's
  transcript search and event listing are allowed again (they were held
  back only while a code was live; PostToolUse still masks stored values in
  what they return); the transcript deny reasons now cite unmasked output.
  `gate secret` prints where credentials are entered now; the approval hook
  keeps denying it (with that wording), and gate export/import/copy-to in
  the Terminal panel or a job (their dialogs need a command Claude runs).
- **Wording.** "pop-up" became "the gateway dialog" in every message.

## PLAN-v4 phase 3 review fixes (2026-10-20)

The verifier's findings on the native dialogs, and what changed.

- **Every sudo and ssh dialog names its host and rights for gated's
  recheck (high).** `Dialogs._entry_problem` ran only for a dialog whose
  spec carried `check`, and only the account setups passed one: the sudo
  stand-in, gate check's two sudo steps, remote sudo and the login
  password passed none. A password typed after localhost's sudo right was
  switched off was still handed over, verified, stored and used (the
  verifier's end-to-end test, on macOS and the Debian VM), while the
  mutation "the recheck ignores the form entry" was killed only by a test
  that injected `check` itself. Now `sudo.SUDO_CHECK` (the stand-in and its
  re-entry dialog), `gate_setup.sudo_check(name, local)` (sudo, plus ssh for
  a remote host) and `ssh.host_check(name, ...)` (remote sudo: ssh and
  sudo; the login password: ssh) go with every such dialog, and `check`'s
  `right` may be a list (every right in it is rechecked, in the form and in
  the effective rights: a right switched off and on again waits for the
  user's OK, so it counts as off). Gated's check comes at submission; the
  stand-ins also read the rights again right before they use a value a
  dialog gave them (`sudo._rights_now(fresh=True)`, `ssh._rights_after_dialog`),
  and gate check reads them again before it installs a passwordless sudo
  rule (`_sudo_still_on`). Tests: `test_dialogs::test_daemon_sudo_standin_*`
  (a real gated, the real stand-in and the fake sudo: switched off, a
  disabled localhost entry, off-then-on; a control), the call-site tests in
  `test_sudo_standin`, `test_ux_gate_setup`, `test_ssh_sudo` and
  `test_ssh_setup`; a mutation per call site and per second look.
  One part of the evidence didn't hold: a form without `[hosts.localhost]`
  doesn't remove localhost; it gets the implicit localhost with `sudo =
  true` (form.py), so sudo running after that edit is right (a fresh `sudo`
  runs too). (Since 0.10.0 the implicit localhost's sudo is `"ask"` on a
  new install and `true` only on an older one: "0.10.0 decisions" below.) The test uses an entry with a bad value instead, which
  disables localhost.
- **"Remember it" is offered where the docs said (medium).** No production
  dialog passed `remember`, so the box was never drawn and every sudo
  password a command asked for was stored. The sudo stand-in and remote
  sudo now pass `remember=True` (ticked); unticked, the password is used for
  that command only (a second command that joined the dialog gets a clear
  "run it again" line). The box is drawn with Paste on the main screen too.
  A post without the choice now takes the dialog's default (it counted as
  unticked). Setups keep no box, as decided in phase 3: in `gate check` the
  person has just chosen to store a sudo password, or asked to set up an
  account (a token, an API key, a client secret), so an unticked box would
  make the step do nothing; a password used once by design (installing
  Claude's key, passwordless sudo) is never stored.
- **The guard holds wherever the dialog waits (medium).** While a secret
  dialog was pending, the `prompt.edit` guard let typing through on the
  terminal's main screen (no field there) and while the pane was closed or
  unplaced, where a typed password reaches every plugin's prompt hooks and,
  on Enter, the model. Now it holds composer edits back in all three
  states; only text that is (a prefix of) one of the gateway's own commands
  passes, so `/gate-dialog` can still bring the dialog back, and an emptied
  box. A leading `/` alone isn't enough (a secret may start with one). The
  status line says what to do in each state (click the field; Paste or
  `CLAUDE_CODE_NO_FLICKER=1`; `/gate-dialog`). The price: while a secret
  dialog waits (up to 30 minutes), the prompt box takes nothing else until
  it is answered or cancelled (the brief: the guard swallows composer edits
  while a dialog is pending). Mod tests and mutations (the old mutation that
  pinned the pass-through is inverted), and the acceptance's main-screen
  step types a canary into the prompt box.
- **A checkpoint pause isn't seen (low; documented).** gated's pause record
  is fed only by `/v1/pause`, and checkpoint doesn't call it yet; reading
  checkpoint's own state files would go around the contract. The README,
  PLAN-v4 row 11.1, CLAUDE.md and daemon.md now say so; the fix belongs in
  checkpoint (its pause calling `/v1/pause` through contract.json).
- **The acceptance run builds the env first (low).** From a cold pixi cache
  the gateway's env build started inside the proxied session, and the
  record-only proxy answered the downloads itself ("invalid peer
  certificate: UnknownIssuer"), so the run waited out 900 s. The script now
  builds the installed e2e copy's env with its own `launch.sh ensure-env`
  before any session, outside the proxy, stops at once with the install
  log's tail when that fails, and waits 180 s for the mod's registration.
- **Banned programs are caught by PATH shims (low).** The process sampler
  (`ps` every 0.25 s) misses short-lived processes (a probe caught 5 of 20
  processes of 80 ms), so it couldn't show that `open` or `xdg-open` never
  ran. Recording shims named osascript, zenity, kdialog, open, xdg-open and
  the terminal programs now come first on every session's PATH (the -p run
  included) and log their name when run; the sampler stays, labelled best
  effort; `test_ux_dialog`'s grep also catches an argv naming one
  (`["open", url]`).

## PLAN-v4 phase 4: managed execution (2026-10-20)

Claude's Bash now runs in the gateway's own bash by default
(docs/dev/modules/managed.md). This reverses "Rolled back" (2026-10-19, the
lead's decision that the gateway must not change how Claude's ordinary
commands behave): the brief (sections 3 and 8) makes the gateway the default
execution route with its own environment, and PLAN-v4 says so. What stays
from that decision: no EXIT trap, no required command shape, exit codes and
output exactly the command's. Built from PLAN-v4 "Managed execution" and
FEASIBILITY-v4 P2; where probing 2.1.301 showed more, this is what was chosen.

- **The prefix, not a tool rewrite.** `CLAUDE_CODE_SHELL_PREFIX` (set by the
  mod at session start) leaves the permission dialog, "don't ask again"
  rules, PreToolUse/PostToolUse payloads and the model's view on the original
  command; a `tool.call` rewrite would have shown the wrapper everywhere
  (P2). Proven live in `tests/acceptance_managed.py`.
- **One code path covers every route.** Recorded with a probe prefix: the
  Bash tool, `run_in_background`, a subagent's Bash, the user's `!` command
  and a skill's `!` injection all reach the prefix with the same script
  shape, for bash and zsh snapshots alike; Monitor calls the same shell
  function (`Rue(cmd, signal, "bash", ...)` in 2.1.301's code) but isn't
  offered against the fake API (a server-side gate), so it is code evidence
  only.
- **Replace the snapshot's `source`, keep everything else.** Other plugins'
  env files arrive inline in the script (their `CLAUDE_ENV_FILE` text, then
  `\n:`), followed by Claude Code's own segments; parsing the whole script
  would have had to understand arbitrary env-file shell. gate-sh replaces
  only the leading `source <snapshot> 2>/dev/null || true` with `. rc.bash`,
  checks the ends it can check (an `eval`, the `pwd -P >| ...-cwd` tracker,
  that the sourced file is a shell snapshot), and refuses anything else that
  looks like a tool script (exit 126) rather than run it anywhere.
- **Hooks pass through as `/bin/sh -c`, with SHLVL given back.** Claude Code
  runs a shell-form hook as `/bin/sh -c` (spawn with shell:true) and
  composes the prefix into that string, so gate-sh runs the hook the same
  way. The only measurable difference was `SHLVL` on macOS (bash as
  `/bin/sh` counts the extra shell); gate-sh decrements it when `/bin/sh` is
  bash, and the env, `$0`, stdin, stdout, stderr and status then match case
  by case (and live, through a probe plugin). Exec-form hooks (the
  gateway's own) and an organization's managed hooks are never prefixed by Claude
  Code; MCP servers started later are, and their quoted argv through
  `/bin/sh -c` is the same command.
- **`CLAUDE_CODE_SHELL` too.** Claude Code picks its shell (and makes its
  snapshot) lazily at the first shell use, so a `CLAUDE_CODE_SHELL` set by
  the mod at session start is honoured (probed: a zsh user got a bash
  snapshot). Pointing it at the managed bash means the shell that starts
  gate-sh is no longer the user's zsh, which read `~/.zshenv` before every
  command. It is set only once the env is built (a missing shell would be
  ignored and memoized as the fallback anyway). The snapshot Claude Code still
  makes (by running the user's login rc) is never sourced.
- **A curated environment by allowlist (`env -i`; since the review fixes,
  removal by name, `env -u`, below).** Platform variables,
  Claude Code's own (`CLAUDE_*`, `GIT_EDITOR`, `AI_AGENT`, ...), approved
  imports; credential-looking names dropped by word, also among `CLAUDE_*`
  (so Claude Code's `CLAUDE_CODE_MESSAGING_TOKEN` doesn't reach commands: a
  `claude` started from Bash can't message the session; accepted), and
  `ANTHROPIC_*` never passed (Claude Code passes `ANTHROPIC_API_KEY` to its
  commands when it has one). The XDG base folders are platform variables:
  tools find their config there, and test harnesses keep them scratch.
  `others = "mine"` (an approved widening) keeps passing the user's agent and
  token variables, as the env file did.
- **PATH.** Stand-ins, runtime tools (bash and pixi, the plugin's own
  prerequisite, as launch.sh finds it), approved imports, `/usr/bin:/bin:/usr/
  sbin:/sbin`, other plugins' `bin/` last. Imports go before the system
  folders (a Homebrew git should win over /usr/bin's, as the user expects) and
  after the stand-ins (an import never shadows them). Plugin `bin/` folders
  are read from the snapshot's PATH line, keeping only folders of a plugin
  (with `.claude-plugin/plugin.json`); nothing else of the login PATH.
- **Claude Code's own helpers stay, the user's don't.** The snapshot also
  carries Claude Code's `rg` (its embedded copy), its pkill guard, and
  `find`/`grep` shadows using its embedded bfs and ugrep with ignore files.
  The rc keeps `rg` (when none is on PATH) and the pkill guard (a safety
  feature), and not the find/grep shadows: the managed shell runs the real
  tools with their usual behaviour.
- **Imports and the mode are consented settings.** `[shell]` joins the
  "settings" pseudo-entry: lowering `managed` and adding an import are
  widenings (the gateway dialog, `gate check settings`), raising it and
  removing one are narrowings at once. Effective = the stricter mode and the
  imports in both. A missing approval counts as managed "on" with no imports
  (the v4 default). `sync_narrowing` used to replace the whole approved
  `settings` with `{"others": "refuse"}`; it now keeps the shell part
  (a test and a mutation).
- **A narrowing applies to the next command.** The settings gate-sh reads
  are regenerated at session start, after a build, on FileChanged and after
  an approval; and gate-sh itself renews them (a stub running `run.py
  managed-sync`) when gateway.toml is newer than its `conf`, refusing the
  command if it can't (a test and two mutations).
- **The mode reaches the mod as a cache it can only make stricter.** The
  effective mode needs the vault's approval, which the mod must not read; it
  reads `state.json`, which Python writes. A missing or garbled file counts
  as "on", and a file rewritten to "off" only keeps the prefix away, after
  which the classic hook (which computes the mode itself) denies. Mode
  changes reach the prefix at the next session start; a narrowing to "on"
  in a session started with "off" is enforced at once by the classic hook.
- **Without the mod: deny, or warn.** pre_bash.sh sends every Bash and
  Monitor call to Python when the prefix isn't the gateway's (one Python
  start per call, only in that case); `on` denies ("managed shell
  unavailable", why, what to do), `warn` (approved) lets it run in the
  user's shell with a notice once per session. Approving "warn" or "off"
  needs the gateway dialog, which needs the mod: a user without mods can't
  lower the mode then, and the deny says so (turn mods on, update Claude
  Code). The user's `!` commands and skill injection reach no hook and stay
  unmanaged without the mod (a known limit, observed live).
- **Host inspection reads, never runs.** The gw tool `host_inspect` gathers
  login PATH folders from rc files read as text (only folder names leave it,
  with `~`/`$HOME` expanded and anything needing evaluation dropped),
  well-known toolchain folders by listing them, project toolchain files as
  version words only, and importable variable names (never values), so a
  token in `.zshrc` or a secret in a version file can't come back (a test
  plants both). Remote hosts wait for the managed remote runtime (phase 6).
- **bash joins the env** (`bash = "5.*"`, pixi.lock gained only bash 5.2.37
  for the four platforms); a first session's commands are refused (exit 75,
  "isn't ready") until the env is built, never run in the login shell.
- **Rejected: falling back to the login shell while the env builds** (the
  brief: never silently); **a per-command wrapper the model must type**
  (rolled back once already); **parsing `CLAUDE_ENV_FILE` text** (it is
  arbitrary shell; kept byte for byte instead); **an env var naming the data
  folder for the stand-ins** (they still take it from their python; only
  gate-sh reads `GW_MANAGED_DIR`, set by the mod in Claude Code's own
  environment, which a command can't change for the next command).

## The Linux suite (2026-10-20, with PLAN-v4 phase 4)

The whole suite had 25 failures in the Debian 13 arm64 VM since phase 2,
never examined. Each one, and what it was (the VM: dash as `/bin/sh`, umask
002, no git, pixi only in `~/.pixi/bin`, a systemd user session):

- **The git credential helper refused every request on Debian (a real bug;
  11 of `test_git_helper`, hidden behind "no git").** git runs an
  absolute-path helper as `sh -c "<helper> get"`; macOS's `/bin/sh` (bash)
  execs that one command, dash forks it, so the helper's parent was `sh`, not
  git-remote-http, and the caller check refused ("answers only git itself").
  Every git push or fetch with a gateway account would have failed on Debian
  and Ubuntu. The check now also takes git's own shell when its argv is
  exactly `sh -c "<this data folder's helper> <op>"` and its parent is
  git-remote-http(s); a shell snippet wrapping the helper (a pipe into tee, a
  function), another copy of the helper or a shell Claude started still
  don't count (a unit test of the chain, two mutations). The helper's
  sslVerify lookup also checks that the system git it would ask exists
  before using it (else the env's git).
- **The tests drove git by `/usr/bin/git`** (the override's "the system has
  git" knob names that path): `system_git_path()` now takes a real system
  git where there is one, else the gateway env's git (what the gateway
  itself falls back to on such a machine).
- **In-process stand-ins printed into the test log (9: az 3, asiml 6).**
  `capture_fds` swapped the file descriptors without flushing Python's
  buffers; block-buffered stdout (as in the VM) wrote the stand-in's JSON
  after the descriptors were back. The harness flushes before and after (a
  real stand-in is a process, flushed at exit: no product change).
- **`gate import-ssh`: "ssh -G failed (error)" (1).** The test's ssh config
  files were group-writable (umask 002), which upstream OpenSSH (the env's;
  Debian's own ssh accepts it for a user's private group) refuses with "Bad
  owner or permissions". The test now writes them 0600 as ssh requires, and
  import-ssh keeps ssh's own reason in its comment (the home as `~`) instead
  of a bare "error" (a test checks a refused file's reason).
- **The degraded "setup failed" message (1).** The test's last launcher call
  had no fake pixi on PATH and found none in the fixed places (the VM has it
  only in the real `~/.pixi/bin`), so it said "pixi isn't installed": the
  call now gets the same PATH as the others.
- **The user's-agent lookup read the machine's own `/run/user/<uid>` (1).**
  With nothing recorded, the Linux fallback found the VM's systemd ssh-agent
  socket under a test override. Under an override the fallback now uses only
  the folder a test names (`linux_runtime_dir`), never the machine's (the
  macOS launchctl branch already worked this way; a test and a mutation).
- **Marketplace validation of a copy of the plugin folder alone (1).** The
  VM runs used to get only the plugin folder; the test now skips the
  marketplace half, saying so, when there is no `.claude-plugin/
  marketplace.json` two folders up, and the VM now gets the repository's
  files, where it runs.
- Found while doing this: a `GW_TEST_TMP` under `/tmp/gw-*` makes the file
  guard treat test files as run-dir files (by design: run dirs are
  `/tmp/gw-<uid>`), and one under `~` fails the download tool's "temp folder"
  rule and the e2e marker's temp-folder rule: use a neutral temp path.

Result: `pixi run --locked test` in the VM, 1051 passed, 0 failed, twice.

## PLAN-v4 phase 4 review fixes (2026-10-20)

The verifier's findings on managed execution, each fixed with a test and a
mutation (`tests/test_managed.py`, `tests/mutations_managed.py`, the mod's
`lib.test.ts` and `register.test.ts`):

- **Values on env's command line (medium).** gate-sh passed the curated
  variables to `/usr/bin/env -i` as `NAME=VALUE` arguments: the user's own
  tokens under `others = "mine"`, approved imports and every `CLAUDE_*`
  value. Every local user can read a process's arguments (`/proc/PID/cmdline`
  is world-readable on Linux without `hidepid`; `ps` on macOS), while its
  environment is the owner's; the verifier saw a canary `GITHUB_TOKEN` in
  `/usr/bin/env`'s cmdline on Debian. gate-sh now lists its own environment
  (`env`) and gives `env` a `-u NAME` for every name it doesn't keep: only
  names reach a command line, the kept values go through the environment.
  Considered: values over an inherited descriptor or a here-document (macOS's
  `/bin/sh` is bash 3.2, which writes here-documents to a temp file: a secret
  on disk; a FIFO can deadlock on a full pipe), and unsetting in sh then
  exec'ing bash directly (bash would start with the whole environment:
  `BASH_ENV`, `SHELLOPTS`, exported functions, `LD_*`/`DYLD_*` for its own
  loader). The removal list comes from the environment's own listing, so it
  is exact but for an entry whose name holds a line break (bash passes such
  an entry on, zsh and dash drop it; only `execve` can make one; documented).
  Test: a copy of gate-sh whose `env` records its arguments, plus a scan of
  every `/proc/*/cmdline` during 40 runs on Linux.
- **`CLAUDE_CODE_CLIENT_KEY_PASSPHRASE` reached commands (medium).** `PASSW`
  isn't in `PASSPHRASE`, and `CLAUDE_*` passes. The credential words gain
  `PASSPHRASE`, `CRED` (in place of `CREDENTIAL`: `CLAUDE_CODE_HOST_CREDS_FILE`),
  `CLIENT_KEY` and `CLIENT_CERT` (Claude Code's mTLS key and certificate
  paths; also `VAULT_CLIENT_KEY`, `PIP_CLIENT_CERT`, ... for import_env),
  in gate-sh, `managed.CREDENTIAL_WORDS` and `form.CREDENTIAL_NAME` (a test
  compares the three). The test sets every `CLAUDE_*` name in Claude Code
  2.1.301's own credential lists (read from its binary, next to
  `AZURE_PASSWORD`), a sample of the others, and one `CLAUDE_*` probe per word. Kept: `CLAUDE_*` by prefix minus credential
  words, rather than an allowlist of `CLAUDE_*` names: the stand-ins need
  `CLAUDE_PID` and `CLAUDE_CODE_SESSION_ID`, the rc `CLAUDE_CODE_EXECPATH`, a
  nested Claude Code `CLAUDE_CONFIG_DIR` and the prefix variables, Claude
  Code adds variables release by release, and its own Bash passes all of
  them; the words cover every credential variable it names today.
- **A Claude Code started from a managed command failed every command with
  75 (medium).** It inherits `CLAUDE_CODE_SHELL_PREFIX` and
  `CLAUDE_CODE_SHELL` (both `CLAUDE_*`), but `GW_MANAGED_DIR` was dropped.
  It passes now (`managed.GATEWAY_NAMES`), so a `claude -p`, an Agent SDK
  script or a scratch-config session run through Bash stays managed with
  this session's settings (one with the gateway loaded sets all three again
  itself). Rejected: dropping the prefix variables instead (the nested
  session would run in the login shell, unmanaged and silently). A prefix set
  by hand without the folder gets a 75 that names the variable and both ways
  out instead of pointing at `/gate-doctor` alone.
- **Hook strings that mention a snapshot or hold the tracker's text were
  refused (low).** gate-sh took any string containing ` && pwd -P >| ` or
  `/shell-snapshots/snapshot-` for a tool script and refused it with 126 when
  it didn't parse, so such a hook, MCP argv or status line stopped working.
  A tool script is now recognised by its whole shape: the snapshot's
  `source` as the first segment, or the tracker as the last segment (one
  `-cwd` word) together with an eval; everything else goes to `/bin/sh -c`
  (`HOOK_CASES` has the verifier's three strings and the near misses).
  Kept unlike the finding's wording: a string with the tracker-and-eval
  shape that names a snapshot elsewhere is refused, not run as a hook (it
  has a tool script's shape, so `/bin/sh -c` would be a silent fallback).
  The classification also assigns no variable before the hook's exec (an
  assigned name that happens to be exported would change the hook's
  environment).
- **A rewritten `state.json` could set `CLAUDE_CODE_SHELL` (low).** The mod
  took the managed bash from `state.json`'s `bash`, so a command could make
  Claude Code start every later command (gate-sh included) from another
  program with the whole environment, while `/gate-doctor` said "active".
  The mod now takes it only from `launch.sh status` (the env it names, when
  ready), and the data folder's gate-sh copy only while its text is the
  plugin's gate-sh (the mod compares the two), so `state.json` alone can
  again only take the prefix away. `conf`, `rc.bash` and the copy itself
  stay writable by a command (a guardrail, said so in managed.md).
- **The VM's full suite failed `test_ssh_exec`'s gives-up-on-the-lock test
  (low): a test-harness bug, Linux only.** "A's login didn't reach the
  proxy" twice in the verifier's Debian runs; reproduced here 4 times in 16
  full runs made while the Mac was busy (none in 7 earlier runs and 24 loops
  of the two tests beside VM-side CPU hogs only). The trace the failure message now
  carries showed the cause: the connection that failed ("kex_exchange_
  identification: read: Connection reset by peer") was never accepted by the
  test's proxy, whose listener was healthy and whose accept thread was
  alive. On Linux `close()` doesn't wake a thread blocked in `accept()` on
  that socket: each earlier test's hold proxy left its accept thread behind
  at cleanup, and such a thread took a connection meant for a later proxy
  whose listener had the same file descriptor number, tried its own sshd
  (gone) and reset it. A standalone probe in the VM: an accept thread left on
  a closed listener took 1 of 50 connections meant for a new listener on the
  same fd, 3 runs of 3; with `shutdown()` before `close()`, none (macOS wakes
  the thread on close, which is why only the VM saw it). `HoldProxy.close()`
  now shuts the listener down (on macOS, where that fails, closes it), waits
  for the accept thread and only then closes; an accept that returns after
  close never serves. The accept loop also keeps going after an accept error,
  waits for a thread it can't start and retries the upstream connect, and
  both waits of the test say what became of the call (the stand-in's exit and
  stderr or the gate call's result, the listener and its thread, a trace of
  every proxied connection, the sshd log). Tests: an earlier proxy closed,
  then 20 connections to a new one all reach it (fails on the old close()
  in the VM), and a proxy that keeps serving through failed thread starts and
  a late upstream (fails on the old accept loop). No product change.

## PLAN-v4 phase 5: terminals and jobs (2026-10-20)

Persistent PTYs and jobs owned by gated, shared with the person in a native
pane, one writer at a time, password prompts through the credential dialog
(docs/dev/modules/terminals.md). Built from PLAN-v4 "Terminals and jobs" and
FEASIBILITY-v4 P3/P3b; what probing tmux 3.8 and Claude Code 2.1.301 showed,
and what the tests found, is what was chosen.

- **tmux, from the env, on its own socket with its own config.** A real
  supervisor (brief 9) that outlives tool calls, sessions and gated itself,
  with screen state, history, resize and exit status (`remain-on-exit`) for
  free. pixi.toml gained `tmux = "3.*"` (the lock: tmux 3.8, libevent, and on
  macOS libjemalloc and libutf8proc; nothing else moved). `-f <run>/tmux.conf`
  on every call keeps the user's `~/.tmux.conf` out (a test plants one), `-S`
  the user's server; `-u` forces UTF-8 whatever gated's locale.
  `set-clipboard off` so a pane can't reach the OS clipboard through OSC 52.
  Rejected: our own PTY layer in gated (would die with gated; no history or
  screen model without pyte, which gated can't import); pyte in gated
  (`capture-pane -e` gives the styled screen already).
- **Records in the data folder, the socket in the run dir.** A reboot empties
  the run dir (and with it tmux), not the data folder, so the next gated still
  has the records and reports them gone rather than forgetting them. A pane is
  gated's only when its session name and a per-pane random nonce (a tmux
  option) match a record: a stale or foreign session with the same name is
  not adopted (test + mutation). Survival is always asked of tmux (adoption
  and every tick, `_lost`), never inferred from a saved pid.
- **Jobs are `unknown`, not `exited`, when tmux lost them.** CONTRACT-v1 says
  `unknown` whenever the gateway can't prove the state and never reports it
  as finished; a pane that vanished without tmux reporting its exit is that
  case (`gone: true` says it won't change).
- **Values never on a command line.** The pane's environment goes in a 0600
  start file the pane removes once read; typed text and the dialog's value
  go in through `load-buffer -` (tmux's stdin) and `paste-buffer -d` (the
  buffer deleted as pasted). The task suggested `send-keys -l`, which would
  put the password on tmux's argv where any local user can read it (`ps`);
  a test runs gated with a logging tmux wrapper and checks the value never
  reaches its argv (+ mutation).
- **Password prompts by the tty's mode.** ECHO off with ICANON on (tcgetattr
  of the pane's tty, opened `O_NOCTTY`, closed at once) is a program waiting
  for a password; a shell's readline and full-screen programs are ECHO off
  with ICANON off. Probed: `read -s`, sudo, getpass. The dialog shows the
  terminal and the foreground program's executable path from the kernel
  (for a setuid sudo, unreadable on Linux, its kernel name "sudo", said to be
  a name only), never the prompt's text: a program (or the model) chooses
  that text. The value goes in only after a recheck (same dialog token, tty
  still in that mode, same foreground process group: test + mutation).
- **A race found by the tests: the tick cancelled a dialog mid-supply.**
  Between the paste and the handler marking the prompt answered, the program
  finished reading and echo came back on; the tick saw "the prompt ended"
  and closed the dialog as cancelled, so the answer was used but reported
  cancelled. Now the handler marks the prompt `supplying` (the tick leaves it
  alone) before the value goes in, and notes "[credential supplied]" and the
  value's mask before the paste (Linux printed before the note was set).
- **sudo in a terminal: the real sudo on the pane's tty.** The stand-in still
  checks the form's sudo right and refuses `-S`/`-A`; with `GW_TERMINAL` (a
  well-formed id) and a tty it execs the real sudo, whose prompt the dialog
  answers. Proven in the repo suite with the fake sudo's new tty mode (it now
  asks on `/dev/tty` with echo off, as sudo does), in the TUI acceptance run,
  and on the Linux VM with the real sudo of a test user.
- **One writer, enforced in gated.** Takeover flips the owner and bumps an
  ownership generation that every queued agent write checks before it goes in
  ("input taken by the user; re-read the screen"); hand back bumps `seq`, so
  the agent must read again; each write quotes the seq it read, checked when
  queued and again right before it goes in (`_stale`). Agents (main loop,
  subagents) take turns by an explicit read with `take`. The agent loop is
  learned from the mod (`tool.call`'s `agentId`, keyed by the tool use id
  Claude Code passes every MCP server in `_meta`), so the model can't claim
  another loop's turn; a `__tool_use_id` argument from the model is dropped.
- **tmux resumes a stopped pane.** Its `server_child_stopped` sends SIGCONT
  when the pane's own process stops for any signal but SIGTTIN/SIGTTOU, so a
  plain `killpg(SIGSTOP)` "suspended" nothing (found by the pause test). The
  suspend policy now sends the pane's root SIGTTOU and the rest SIGSTOP and
  checks `ps` for state T before it says "suspended" (+ mutation).
- **Linux's tmux reports a dead pane's signal as a number** ("15"; macOS's
  "term"): normalized to names (found on the VM). Debian has no `shasum`:
  the tests use `sha256sum` where it exists.
- **The click is the takeover; the main screen gets a line field.** Claude
  Code 2.1.301 sends clicks to plugins only in its fullscreen layout and a
  Client takes keys only after one (phase 3), and the engine keeps ^C, ^D,
  ^Z and Escape (P3b), hence Ctrl-] as a prefix plus buttons. The space bar
  arrives as the key name `space` (found live: typed text lost its spaces).
  On the main screen an `Input` (whose text every plugin's `ui.input` hooks
  see) is offered for ordinary lines only, never while a password prompt
  waits, and gated refuses typed text then too.
- **A process inside a terminal belongs to the pane's owner session.** Its
  ancestors are gated's tmux, not Claude Code, so without a mapping the
  stand-ins in a gateway terminal would get nothing from a wrapped vault and
  no dialog. `Registry.ancestor_session` asks the supervisor (by the pane's
  root pid) and gets the owner session while it lives. `CLAUDE_PID=$$` in the
  pane makes the stand-ins' direct rule start at the pane's shell.
- **The approval hook judges what gw tools type or run.** `terminal_send`'s
  text and `job_start`'s command go through hooks_bash like checkpoint's jobs
  (Bash's denies, an "ask" right denied, never allow); reads, an idle open
  and a resize are allowed by mcp_perm.sh; signals and close follow Claude
  Code's mode.
- **gated stops an unreachable tmux server.** When the run dir is removed (a
  tmp cleaner; the test harnesses), gated exits and the tmux socket is gone
  with it; nobody could ever reach that server, so gated sends it SIGTERM (the
  pid tmux reported, only while it is still the env's tmux). Found as a
  leftover after an interrupted acceptance run.
- **No contract change.** The job routes are CONTRACT-v1's as written; the
  answers add fields (`new`, `host_name`, `gone`, `detached`), which v1
  allows.

## PLAN-v4 phase 6: the managed remote runtime (2026-10-20)

Remote terminals and jobs in the gateway's own runtime on the host
(docs/dev/modules/remote.md), from PLAN-v4 "Remote runtime", FEASIBILITY-v4 P5
and the brief (8, 9, 10, 14.6, 14.8). What probing pixi-pack 0.7.11,
pixi-unpack 0.7.11, the Debian 13 arm64 VM and the local sshd showed is what
was chosen.

- **A separate runtime workspace, bash and tmux only.** `runtime/pixi.toml` +
  `pixi.lock` in the plugin (4 platforms), not the gateway's own env: the
  remote side needs neither Python nor age nor gh, and a pack with Python is
  ~85 MB (P5). The runtime's version is the lock's sha256 prefix, so a plugin
  update that changes the lock stages a new folder; one that doesn't reuses
  the hosts' runtimes. pixi-pack runs from the gateway env (pixi.toml gained
  `pixi-pack = "0.7.*"` and `zstd = "1.*"`, which was already in the lock as a
  dependency; the lock gained only pixi-pack, 4 builds). Rejected: a `remote`
  feature env installed on first use (one more pixi install, network and
  failure mode at the moment the user opens a remote terminal, for 4.6 MB).
- **The target's pixi-unpack from its conda package, extracted here.**
  `pixi-pack --directory-only -e unpacker` gives the target platform's
  packages; gated opens each `.conda` (zipfile, the env's zstd, tarfile) and
  keeps `bin/pixi-unpack` and the shared libraries under `lib/`. Found: the
  conda pixi-unpack is not static: it links openssl and libgcc_s by rpath
  (`$ORIGIN/../lib`), so they ship next to it (Linux 13.1 + 9.6 MB, macOS
  10.3 + 6.1 MB); the local pixi-unpack refuses a pack of another platform
  ("The pack was created for a different platform"), so it can't do the
  extraction. Verified in the VM: the extracted linux-aarch64 pixi-unpack
  unpacked the pack into a path with a space in 0.2 s; bash 5.2.37 and tmux
  3.8 ran under `env -i`. Rejected: `--create-executable` (a bash
  self-extractor that downloads pixi-unpack from GitHub releases at build
  time: unpinned, and it needs bash on the host); copying a local env (other
  OS, architecture and prefix).
- **Staging over ssh's stdin, not sftp.** `cat > F.part && mv` on the
  connection the stand-in already uses (ControlMaster): no sftp subsystem
  needed on the host, the same pins and key. The remote side needs only POSIX
  tools (`cat mv mkdir chmod df ps stty kill uname`), no tar or gzip: the
  unpacker goes as plain files.
- **sha256 on the host, else read back.** `sha256sum`, `shasum -a 256`, then
  `openssl dgst`; with none of them the file is read back over ssh and
  hashed here (slower, but never unchecked). A mismatch removes the copy and
  unpacks nothing (test + mutation, both paths). The local build is hashed
  again before every use.
- **`exec /bin/sh -c` behind every command, a marker before the output.**
  sshd always runs the login shell; the gateway's command line only execs
  `/bin/sh` (no rc there) and everything before a random marker is dropped,
  so an rc that prints doesn't corrupt the protocol. Found live: Debian's
  bash reads `~/.bashrc` for ssh commands (SSH_SOURCE_BASHRC), so a probe
  first in `~/.bashrc` did run in that outer `bash -c`; the managed shell got
  nothing of it (env -i for the runtime's tmux, a start file that unsets
  everything but the platform's variables, `--noprofile --rcfile`). That is
  the boundary claimed: no remote rc effect inside the managed environment,
  not "the login shell never starts". A login shell that can't run `sh -c`
  lines (csh, fish) is reported, never worked around.
- **Identity: the machine id, stored with the host keys.** The same token as
  localhost's id (`machine_token`), so a remote host that is this very
  machine shows `same_machine`; first contact stores it in the vault host
  record (TOFU, like the host key pin of gate check), the raw id never. It is
  checked at every new master connection (the pid `ssh -O check` reports
  changed): host keys are checked by ssh itself on every connection
  (`StrictHostKeyChecking yes` against the pins), the machine at every new
  one. The contract's host id stays the assigned one (stable ids for
  checkpoint); `identity: "verified"` and `machine` say what is known.
- **A per-record marker in the runtime folder on every command.** `hosts/<host
  id>` holding a nonce only gated knows; every RemoteTmux command checks it
  first (exit 97 otherwise). It costs a `read` builtin; a command meant for one
  host's runtime can't act on another's even when both have the same path
  (the misrouting mutation is caught by it: test + mutation). Panes are bound
  to their host record and its machine token besides (`_tm`, the poller).
- **The host-change gates are gated's own dialogs.** The ssh stand-in's
  `popup.hostkey` takes a lease from gated as a client; gated can't be its own
  client, so dialogs.py's owned dialogs gained `confirm` and `info` kinds
  (owner "gated", never persisted, the handler runs on the OK only).
  `ssh._build_link` gained `on_mismatch` so the same address choice and pins
  are used without the pop-up path. While a change waits, every operation on
  the host is refused and nothing is sent to it; a declined change stays
  blocked until the pins or the host's addresses change or ten minutes pass
  (not re-asked every second by the poller).
- **Disconnected is not unknown, unknown is not exited.** A host that can't be
  asked leaves its panes `disconnected` (a refused key: `waiting_auth`, as the
  brief asks) with the reason, never ended: the remote tmux may well still
  run them (it does: killing the session's sshd doesn't kill a daemonized
  tmux; verified in the VM). Only the host's own answer ends or loses a pane:
  a dead pane is `exited` with tmux's status or signal, a pane tmux doesn't
  list is `unknown` (no end time), the runtime's tmux server gone means every
  pane there is unknown. A reconnect bumps every seq (the screen may have
  moved). A refused key also gets one info dialog per episode, with the
  remedy (gate check), and recovers by itself.
- **Remote job output is the remote tmux history.** No pipe from the host:
  reads only (bounded by tmux's history-limit). Rejected: `pipe-pane` into a
  file on the host (unbounded growth on someone else's disk) or a stream over
  a long-lived ssh channel (one more thing to lose on a disconnect).
- **Only `ssh = true` hosts.** A terminal or job can't ask per command, the
  same rule as jobs and terminals locally ("ask" denied). The approval hook
  judges a remote job and text sent to a remote terminal as `ssh HOST CMD`
  (the host's ssh and sudo rights, the remote sudo rules), never as local
  commands; a root password prompt on a host whose sudo is false opens no
  dialog. `terminal_open` with a remote host gets no automatic allow (it may
  stage the runtime).
- **The runtime path is a form key under consent.** `runtime = "..."` in
  `[hosts.NAME]` (absolute or `~/`, plain characters): any change is a widening
  (the gateway would write and run programs elsewhere), the approved one
  applies meanwhile. It is also the remedy the noexec, full-disk, unwritable
  and too-long-socket messages give. Old versions are removed only by exact
  name, with the gateway's marker, and only when their tmux doesn't answer
  (tests + 3 mutations: a base of `~` must never lose `~/my-project`).
- **An answer cut off is no answer.** Parallel stress runs found a poll whose
  ssh master died after the script's marker had arrived: the empty rest read
  as "the host's tmux has none of these panes" and live panes were marked
  gone. ssh's 255 after the marker is now a dropped connection (the scripts
  never exit 255) and the poll's answer must end with its end marker; anything
  else is "can't be asked" (disconnected), never "lost" (test + 2 mutations).
  The same runs found phase 5's `abandon()` stopping any process of the tmux
  binary that had taken its old server's pid (a remote runtime's server on
  this machine): it now also needs gated's socket on that process's command
  line (test + mutation). And a read now describes the pane after its capture
  (a credential supplied during a slow remote capture was on the screen but
  not yet "[credential supplied]" in the record: seen on the loaded VM).
- **Tested where it could be.** The suite runs staging and every remote path
  against real sshds on 127.0.0.1 with a stand-in pixi-unpack (no network);
  `tests/acceptance_remote.py` ran 39 of 39 live against the VM (127.0.0.1:2222
  and a private non-root sshd in the VM for the disruptive steps, so the VM's
  own sshd, which other agents use, was never stopped or rekeyed) and the
  local sshd, with real pixi-pack artifacts for linux-aarch64 and osx-arm64.
  Not live: a noexec mount (the VM's test user has none writable), a full
  disk, a jump host, linux-64 and osx-64 hosts.

## PLAN-v4 phase 6 review fixes (2026-10-20)

A review reproduced seven findings against the real harness; all are fixed
with tests and mutations (docs/dev/modules/remote.md).

- **A lost answer is never "not run".** A job_start whose answer was lost
  after `new-session` ran (an ssh wrapper running the real ssh, then exiting
  255) said "unreachable", kept no record, and a retry with the same
  idempotency key started the job a second time: the brief's "never dispatched"
  claimed for a write that happened, and blind repetition. The record and the
  key are now saved before the start leaves; an `ambiguous` failure keeps the
  record `unknown` (`start_confirmed: false`) and the poller settles it.
  Ambiguous covers a 255 with no answer at all, not only one after the marker:
  the reproduction threw the whole answer away, and a link that drops after
  the command ran looks exactly like that; only ssh's own "never connected"
  words (`NOT_SENT`) make a 255 without an answer provably unsent, and errors
  while connecting or verifying (before the command is sent) never count.
- **The start file's claim, not a guess.** A start the host doesn't list may
  have never begun or have begun and vanished. The pane's start file now
  renames itself first thing (the shell already holds it open) and gated, to
  settle, renames it too: one rename wins. Rejected: a noclobber `.claim` file
  (the pane would have to keep it forever, or a later claim could win after
  the pane removed it and kill a running job) and checking the file's
  existence (racy against a start still executing on the host). A start that
  provably never ran frees its idempotency key, so checkpoint's retry with the
  same key simply starts it; one that did start is never started again.
- **Typed text by its buffer.** terminal_send reported "unreachable" for a
  line that had run. The paste deletes its uniquely named buffer, so a lost
  answer is settled by asking whether the buffer is still there (`insist`: right
  after the failure, past the connection's fast fail); when the host can't say
  it is "outcome unknown", the seq moves (a blind repeat is stale) and the
  buffer is removed at the next answer, so a paste still on its way can't type
  late.
- **A failed `list-panes` is a blip.** Any non-zero exit of the remote tmux
  client read as "no server" and marked live panes gone for good (no later poll
  looks at a gone pane). "No server" now needs proof on the host: the socket
  gone, or "no server running" while the last server pid (`#{pid}`, kept in
  remote.json so a gated restart knows it) fails `kill -0` or isn't a tmux.
  Without a known pid, "no server running" is accepted (tmux prints it only for
  ECONNREFUSED/ENOENT).
- **A close the host didn't get is no cancel.** close() set `closing` and
  `cancel` before the remote kill-session raised, so the job's own later exit
  read "canceled". They are restored on failure and the request is recorded
  apart from the state (`stop_requested`: not delivered / outcome unknown);
  after an unsure close, the session missing from a server that still runs is
  that close. Pause outcomes on an unreachable host now say "not applied"
  instead of "already ended".
- **One host resolver.** gated accepted a host's verified machine token (shown
  in host_runtime and the snapshot) but the approval hook didn't map it, so
  `job_start {host: <token>}` skipped the remote sudo denies. The hook and gated
  now call `daemon.resolve_remote_host` over the same files; a host word that
  names no host is denied (gated refuses it anyway), and this machine's own id
  is local in both. Kept accepting tokens in gated: CONTRACT-v1 consumers hold
  them.
- **The whole foreground group for root prompts**: `sleep 60 | sudo ...`
  opened the dialog under "sleep" where sudo is off. The poll lists the group's
  members (leader first); any sudo/su/doas/sudoedit/pkexec applies the rule and
  is the program named.
- **Host status says how old it is.** host_runtime status and the snapshot
  reported reachable "ok" / runtime "ready" long after the host went down.
  `checked_at` is the last answer (or the failure that said it was down); past
  10 s reachable, auth and a ready runtime read `unknown` (`stale`). Rejected
  for now: a probe from status (it would make a read-only, always-allowed tool
  open connections and possibly dialogs).
- **The host-key mutation is deterministic now.** "A changed host key is
  trusted without asking" survived about half the runs: when the address
  choice's scan saw no key, ssh's own strict check opened the dialog anyway, so
  the end-to-end test passed either way. A direct test of `RemoteHost._link`
  with the scan forced to another key (nothing can reach the host, the dialog
  must open once) now carries that mutation, and a direct test of `_capture`
  with ssh's own refusal (the keys scanned right then) carries a new one for
  that path; the end-to-end test stays as the whole flow.

## PLAN-v4 phase 7: hosts, policy, accounts, portability (2026-10-20)

Plugin 0.9.0. docs/dev/modules/policy.md, accounts.md ("adapters.py"), ux.md
(the panes, transfer format 3), sudo.md and managed.md ("Alternate routes").

- **Policy is a layer of restrictions on the rights, not a second rights
  system.** Each restriction (read, exec, write, network, elevation,
  credential, env_import, provision) starts at the base right and can only be
  lowered by the host's, the workspace's, the account's and `[policy]`'s
  tables; the strictest wins. So an existing form means exactly what it meant
  before, and policy can't raise anything the rights don't allow. Rejected: a
  separate allow-list model (two sources of truth for one decision) and
  deriving actions from each other (a read grant implying exec): every action
  is decided on its own; only elevation also obeys exec's restrictions,
  since sudo runs a command.
- **Forwarding grants are per host only.** `forward_agent`, `forward_x11`,
  `forward_remote`, `forward_stdio` are off unless the host's own policy says
  `"allow"` (a widening, approved in the dialog); `[policy]` can only keep
  them off, and a global `"allow"` is an error that counts as deny (one line
  would open forwarding to every host). The forwarded agent is the call's own
  private agent with only the gateway's key for that host, never the user's
  agent: the grant gives the host what the gateway already gave it, nothing
  of the user's. -R still binds only to the host's loopback.
- **On this machine Claude Code's permission modes stay in charge.** Local
  read/exec/network/credential/env_import start at allow: a gateway "ask" on
  every local command would compete with Claude Code's own prompts and modes.
  Policy can still lower them (and elevation follows localhost's sudo). Policy
  never writes Claude Code's permission rules or modes and is never read from
  them.
- **"ask" is honoured only where a person can be asked.** The approval hook
  answers `ask` with the rule for a command Claude typed; the stand-ins pass
  an "ask" only for a typed command (`typed_by_claude`); gated's terminals,
  jobs, checkpoint and the MCP tools treat it as refused and say how to get
  it asked. Same rule as the rights' "ask" (review round 1).
- **Consent per key, by rank.** An absent restriction ranks as allow, an
  absent grant as deny, so removing a restriction or adding a grant is a
  widening, and the ratchet lowers per key at once. A new or moved workspace
  root is a widening (it changes what a cwd binds to); a removed one goes at
  once.
- **Decided where the work happens.** The stand-ins, gated (`_bind`,
  `ensure_runtime`, `RemoteHost.inspect`), the managed shell's imports, web
  and account selection each call `policy.decide`; the approval hook mirrors
  the decisions so a deny is refused before the command starts and an "ask"
  becomes Claude Code's prompt. The hook is a guardrail; the stand-ins and
  gated are the boundary.
- **Workspace ids are content-bound.** `w_` + base32(sha256(host id, root)):
  the same root on two hosts is two workspaces, and a renamed workspace keeps
  its id. Rejected: ULIDs stored in the form (the form isn't the gateway's to
  rewrite) or in the vault (an id that changes on import).
- **Account states come from the service's API answers only.** GitHub's
  token-expiration header tells expired from revoked, `x-github-sso` is
  reauthentication; Entra's AADSTS codes are sorted into expired, revoked and
  reauthentication; Hugging Face has only valid/revoked. A browser login,
  `gh auth status` or a cookie is never taken as API authorization. No
  adapter needs a cookie or session store: all three take API credentials,
  and the one session-like value (an Entra refresh token from before phase 3)
  stays in the vault's `entra` record. An Azure certificate signs its client
  assertion with the env's openssl (the key on an inherited pipe, never a
  file or argv) instead of adding a crypto library to stdlib-only `src/`.
- **A PEM may be pasted with its line breaks, only where the dialog says
  so.** The clipboard intake still refuses every control character, except
  line breaks for a dialog whose spec has `pem` (the certificate's); the
  check sits in gated's paste, not only in the mod.
- **No sudoers rule, ever.** The phase 3 "Set up passwordless sudo" choice (superseded)
  installed `/etc/sudoers.d/claude-gateway-USER`, which gives root without a
  password to every program running as that user, worse than the residual
  risk it addressed (a staged remote password readable by same-user
  processes while sudo runs). Removed with its code and advice; passwordless
  sudo is used only where it already works, and a password can be asked per
  call and used once. A sudoers that wants a terminal (requiretty, use_pty)
  is pointed to a gateway terminal, where sudo has a tty and its prompt opens
  the dialog. The target identity is shown by the approval hook as a
  `systemMessage` ("sudo runs as USER on HOST (user@address)"): putting it on
  the command's stderr broke commands that merge output.
- **Alternate routes are refused only in managed mode, and the limit is
  stated.** A credential tool by path, `command -p`, `env -i`/`-u`, a PATH or
  ssh-command reroute and rsync/git naming another ssh are refused by the
  hook; git and rsync by path pass because their transport is already routed
  through `GIT_SSH_COMMAND`/`RSYNC_RSH`. A script that runs `/usr/bin/ssh`
  itself is not visible to any hook; it reaches the user's own credentials,
  never the gateway's (the vault and the stand-ins' checks are the boundary).
  Rejected: wrapping or hiding system binaries (they aren't the gateway's to
  change) and refusing in unmanaged mode (the person chose their own shell).
- **Export format 3.** Per-item selection (a host and its secrets, an account
  and its credentials, the settings tables, this machine's sudo password),
  a schema number and a sha256 digest beside age's own authentication (a
  newer format is refused by name), never a pid, socket, terminal or job id,
  task reference or checked account state. Import resolves each conflicting
  item in its own dialog (keep, replace, rename; keep or take a host-key
  pin), stages the new form and vault in memory, backs both up under
  `private/backups/import-*` (inside the file guard: the backup holds the
  encrypted vault), writes the vault then the form and restores both on any
  failure. A wrong passphrase is asked again; a damaged or altered file
  (age's MAC/header/chunk errors, a digest mismatch) stops at once with its
  own message. This machine is found by its host keys or machine token,
  never by the exported localhost; imported credentials are checked, and a
  refresh token that doesn't work here is marked "needs a fresh sign-in".
- **Pause and resume are bound to the caller's session** (phase 4's
  leftover). Another live session is refused; an ended one only with a
  task_ref. `pause_id` (for checkpoint's retries, requested by ck-final)
  replays the first answer for 24 h; independently, a job a pause already
  interrupted or suspended is never signalled again.
- **Snapshots never keep the vault unlocked.** The first version of the
  ticker's rights watch read the vault through `broker.read()`, which counts
  as a use, so `lock_after` never fired (test_broker caught it); gated's own
  reads now pass `touch=False`.
- **mcp_server treats this machine's own contract id as localhost**, and
  `managed.inspect` refuses a remote host (it would have answered with this
  machine's files); a remote `host_inspect` goes to gated over the verified
  connection, read-only, decided by the host's `read` policy.
- **CONTRACT-v1 stays `gateway.v1`.** All of it is additive: features
  `workspaces`, `accounts`, `pause_id`; hosts' `rights`; `workspaces[]` and
  `accounts[]` in the snapshot; `rule` on policy refusals; the events
  `rights.changed`, `account.state`, `policy.denied`; `replayed` on
  `pause.applied`. checkpoint's copy is byte-identical (a test compares them
  when its checkout is next to this repo).

## PLAN-v4 phase 7 review fixes (2026-10-21)

Verified findings against phase 7's policy layer, each reproduced against a
real local sshd or the hook before the fix:

- **Taking a restricted workspace out of the form is a widening.** Deleting
  `[hosts.box.workspaces.prod]` (exec and read denied) was reported as a
  narrowing ("workspace prod removed"), applied at once and ratcheted, so an
  agent-assisted edit lifted the restrictions; a rename did the same while the
  new name waited. Now a removed workspace that restricts anything keeps its
  approved root and restrictions in effect (`consent._ws_restrictions`,
  `_phase7_host`) and stays approved (`_narrow_phase7`) until the person's OK;
  one that restricts nothing still goes at once (it can only make a folder
  stricter by letting an outer workspace bind).
- **Transfer servers are recognised strictly.** `ssh_actions` took any
  program whose basename was rsync/scp/git-*-pack, with any options, as a read
  or a write: a script named `rsync` ran with exec denied, and `rsync
  --remove-source-files` deleted remote files on a read grant. Now only the
  exact bare name as the first word counts, with allowlisted options
  (collected from rsync 3.5's and openrsync's real server command lines);
  `--remove-source-files` writes each source; anything else is exec, which is
  where an option that writes a log, temp or backup file elsewhere belongs,
  and so does a path that starts with `-`: rsync's popt reads options after
  the `.` as well (`rsync --server --sender ... . --remove-source-files FILE`
  deleted FILE when tried locally with rsync 3.5).
  A bare `rsync` still resolves through the host's PATH: a write grant into a
  PATH folder or a dotfile can reach exec there; stated in policy.md rather
  than pretended away.
- **Every path is decided, in every workspace it may reach.** Only the last
  path was mapped, so `rsync box:closed/secret box:free/x` read a read-denied
  workspace. Rejected: refusing every path that can't be mapped exactly, as
  the finding suggested, because the stand-in doesn't know the host's home
  folder, so `notes.txt` against a root `/home/u/proj` (or `/home/u/x`
  against `~/proj`) can't be placed, and refusing all of those would refuse
  most home-relative copies on any host with a workspace. Instead a path is
  decided in the workspace that holds it and in every workspace it may reach
  (a root below it, a root written the other way, every workspace for `~bob`,
  a `..` leaving the home and sftp), and the strictest wins: a workspace only
  narrows, so counting one too many is never a widening, and an unrestricted
  workspace costs nothing. The refusal says why and how to write the path.
  Asking the host for its home (an extra probe before policy) and reading
  gated's recorded home (a file the agent could write) were rejected.
- **The managed-mode route guard covers what it can't follow.** Forms the
  parser can't resolve (a shell string, eval/exec, a function, find -exec, a
  variable as the program, PATH or a transport variable changed in an earlier
  statement, `hash -p`, an alias, `git config core.sshCommand`, rsync `-e` in a
  cluster) got no decision, so Claude Code's own mode decided. They are
  denied now (never `ask`: invariant 5), the unparseable ones by a
  deliberately broad text scan that skips data here-documents; a change
  steers only the tools after it (`sudo env -i make` is sudo's business),
  and an ssh remote command is never scanned (it runs on the host). The
  stated limit grew one sentence: a typed command can still be obfuscated
  past a text scan.
- **The NOPASSWD advice scan reads all of docs/.** Historical records
  (phase B requests, their resolution, PLAN-v4's v3 column, DECISIONS) quoted
  the removed advice; each such passage now says it is superseded, which is
  the scan's only exemption (Markdown only, never code), and the scan's own
  test runs on a synthetic tree so a narrowed scan fails anywhere.
- Found while fixing: `gate workspace remove` refused a host's last workspace
  (the dotted header's implicit `workspaces` table counted as "another part
  of the form"), and it called every removal a narrowing.

## Acceptance fixes (2026-10-21)

The live acceptance runs (macOS 2.1.301 and the Debian VM's 2.1.304) found
these gateway defects; each fix has a test and, where it guards something, a
mutation:

- **The prompt-box guard trusted the draft each edit came with.** Its refusal
  answered `{ text: e.text }`, but the editor paints an edit at once and can
  hand the next edit a draft still holding keys whose refusal hadn't come back
  (2.1.304 left three characters from the middle of a typed canary, every run;
  2.1.301 one character once in four). The guard now answers with what it let
  the box hold (`dialog.ts guardEdit`): a draft is trusted only when it is
  that text or itself may stay (emptied, a gateway command); a trusted edit
  passes when its result may stay or it only deletes or moves (the draft from
  before the dialog can be cleared). Three more layers, because the engine's
  timing can't be proven from a mod: a `.catch` that answers the same way if
  the engine skips the hook (a throw, its budget, a re-entry; the test kit
  can't make that hook fail, so this layer has no mutation, stated in
  mutations_dialogs.py); a check of the box itself 300 ms after the typing
  stops (`$.prompt.read`, refilled with the guarded text by `$.prompt.fill`);
  and `prompt.submit`, which drops a prompt the person submits while a secret
  dialog waits unless it is what the guard let the box hold (the VM run had
  sent one stray character as a prompt when `/gate-dialog` was typed after
  it). The guard's status line now lasts 4 s after the last held-back key,
  not the first (the VM's "status line absent" was that timer). Rejected:
  answering an empty box for every refusal (it would delete a draft the person
  wrote before the dialog opened) and keeping the refused keys to subtract
  them later (the mod would hold typed secret characters for no gain).
- **"gate: ready" before Claude's commands could run.** The status line said
  ready once the env's `.ready` existed, while launch.sh warmed the env
  (8-10 s on macOS) before writing the managed shell's settings, and gate-sh
  refuses every command until they exist (75). Now ensure-env writes them
  before the warm-up (and for an env whose setup was interrupted after the
  build), `launch.sh status` reports `"managed"` (by existence) and the mod
  shows `finishing setup…` until both hold in a session that runs commands
  through gate-sh. gate-sh itself still refuses before them: waiting inside
  gate-sh for settings that may never come (pixi missing) would stall every
  command instead.
- **`localhost` refused as a reserved word** by `gate host set` and `gate
  workspace add|remove` (the /gate-hosts edit line): it names this machine
  there; it stays reserved as a new host's name.
- **A dialog job's last word was lost once its requester stopped waiting.**
  `gate import` of a damaged file: the passphrase dialog closed "supplied",
  the job failed, `<key>.result` kept only the outcome, and the retry Claude
  was told to make opened a new passphrase dialog and ran out of time again.
  Now a job whose answer is the line it prints (`public=True`: export,
  import, copy-to; never a secret, a mutation checks that a secret job's value
  never reaches a pending file) keeps that line in a file of its own request
  (`<key>.<digest>.line`: a single `<key>.result` would be replaced by
  another file's import finishing meanwhile, found by a test while fixing)
  until a requester takes it, and the retry of the same request (key and
  digest: the file's sha256, the destination, the host) gets it once instead
  of a new dialog; and a verify
  callback can stop a dialog at once with its reason (`popup.StopDialog`), so
  the person sees "didn't work (the file was changed or damaged ...)" instead
  of "supplied". Rejected: a final info dialog for every finished job (one
  more click for the person after every export) and extending the requester's
  wait (Claude Code's 2-minute Bash timeout bounds it).
- **The daemon outlived its uninstalled plugin** (idle exit after 30 min,
  contract.json still there). 2.1.301's uninstall keeps the version folder
  and writes `.orphaned_at` into it (an update does the same to the old
  version) for a later sweep. The daemon now exits at its next tick when its
  code's folder is gone, or orphaned with no live session registered, and it
  holds no terminal or job (a session still on the old version keeps it: else
  that session's next hook would start it again from there, and it would
  flap). The removal check comes first in a tick: with the folder gone, a
  lazy import in the tick's other work raised and the check was never
  reached (seen while fixing). A
  disabled plugin can't be seen from the daemon; checkpoint's discovery must
  check that the daemon serves its session (its side; done in checkpoint
  0.7.1, `gateway.serves`).
- **A hung daemon cost every hook 15-50 s.** A stopped gated takes
  connections and never answers: each vault read waited 15 s, then
  `ensure_running` spawned a daemon that exited on the instance lock and
  waited 10 s for it, in every hook of every call (the acceptance saw ~12 s
  per Bash call; the probe here 10-76 s per hook). Now an accepted-but-silent
  connection is `Unresponsive`: never started again, `ensure_running` gives it
  3 s, a hook gives a vault read 5 s and then skips that daemon for 30 s
  (`<run>/gated-unresponsive`, cleared by its next answer). The hooks fail open
  exactly as before (they did after the long wait too); only the time changed.
  Rejected: a shorter timeout alone (still one long wait per hook) and a flock
  probe of the instance lock from hooks (it can make a daemon starting at that
  moment exit).
- **A stopped gated's tmux server outlived its run dir.** SIGTERM keeps the
  server for re-adoption; when the run dir then went, nobody could reach it.
  The local server now runs a watchdog session (`gw-watch`, its parent the
  server) that stops it once its socket (by inode) is gone, and a
  `session-closed` hook lets the server end with its last real session as
  before. Rejected: killing the server on every SIGTERM (it would kill the
  jobs a restart re-adopts) and a separate watcher process (a pid it could
  outlive and reuse). Found while fixing: the watchdog's extra tmux call,
  made right after a job's start, widened an old race in which a job that
  ended within milliseconds reported `job.state` before `job.started` (the
  first look at a pane came before the start's event); `job.started` is now
  emitted under the supervisor's lock before any look, and the watchdog
  starts on a thread beside the pane.
- **Harness assumptions on Linux**: acceptance_managed.py told the managed
  bash apart by version (Debian's own bash is 5.2) and expected zsh as the
  login shell: it now reads the executable's path (`$BASH`) and accepts bash
  as the login shell where there is no zsh; its probe plugin's hooks did a
  redirect to `/pre-env.txt` when `PROBE_OUT` was unset (`claude -p`), exit 2
  under dash, a blocking error: they now do nothing then. The e2e install
  runs under umask 022 (Debian's 002 made the installed marker group-writable,
  which the marker rules rightly refuse). acceptance_remote.py takes
  `--vm-dir` and `--vm-sshd-port`, so agents sharing the VM don't meet.

## Re-runs and shipped text (gw-reruns, 2026-10-21)

- **An "ask" right inside a gateway terminal or job.** gated's start file
  exports `CLAUDE_PID=$$` (the pane's own shell) so a command run there is
  direct for credentials. `typed_by_claude` treats `CLAUDE_PID` as Claude Code
  and its child as Claude's command shell, so the stand-in the pane's shell
  starts (parent = `CLAUDE_PID`) and one a script there starts (grandparent =
  `CLAUDE_PID`) both passed: `ssh = "ask"`, remote or local `sudo = "ask"` and
  an `"ask"` policy (`exec = "ask"`) were used with nobody asked, by a script
  in a gateway job (which the approval hook can't read) or a split
  `terminal_send`; delegated checkpoint jobs (0.6+) run there too. Found while
  checking the skill's job text against the code. A `CLAUDE_PID` whose
  executable is a shell is never Claude Code: the walk now refuses at once
  (culprit `TERMINAL`, wording `consent.pane_ask_message`); `is_direct` is
  unchanged. A pane can't recognise the person typing in it either, so an
  "ask" right is refused for them too (the hook already denied it for the
  agent; their own terminal is the way). Tests: test_ancestry_trees,
  test_sudo_standin, test_ssh_ask (the `pane`/`pane-script` trees of
  harness_sudo); mutations in mutations_sudo.py and mutations_ssh.py.
- **Shipped text.** The skill's "Checkpoint jobs" section and SessionStart's
  job line described only checkpoint's own runner and env.sh: they now say
  that checkpoint 0.6+ hands jobs to gated while it serves the session
  (per-job `on_pause`, this machine only: checkpoint's `job_start` takes no
  `host` or `workspace`, a localhost workspace binds by `cwd`), and what the
  approval hook still judges. plugin.json no longer says "one pop-up".
  Found: checkpoint 0.7.1 treats every 403 from `POST /v1/jobs` as "not
  served" and runs the job with its own runner, gated's `403 policy` included
  (probed with checkpoint's fake gateway), so a localhost exec policy doesn't
  hold for checkpoint jobs; the skill tells Claude to treat that answer as a
  refusal until checkpoint is fixed (its `jobs._start_gateway`).
- **Acceptance scripts' checkpoint CLI.** acceptance_install.py ran
  checkpoint's `ingest` from the test process without
  `CHECKPOINT_GATEWAY_CONTRACT`/`_ENV` (checkpoint then falls back to the real
  `~/.config/gateway`), and acceptance_canaries.py's export without
  `CHECKPOINT_GATEWAY_ENV`: both now always name scratch locations
  (`ckpt_cli_env`: the sessions' own, under the harness state root, refused
  unless scratch).

## GitHub install fixes (gw-fix, 0.9.1, 2026-10-21)

Found by the install test from GitHub (both plugins from `p-w-rs/*` on macOS
and the Debian 13 VM, Claude Code 2.1.301/2.1.304).

- **A plain uninstall with a job running left gated running forever** (still
  advertising contract.json, its tmux server and watchdog running from deleted
  files, even after the job and terminal ended). Cause: `claude plugin
  uninstall` deletes the plugin's data folder, which holds the env: gated's
  own python and the env's tmux. gated stayed for its live panes as designed,
  but every `list-panes` then failed (the binary was gone), and a failed query
  while the server's pid lives is a blip by design (phase 5), so the panes
  stayed "live" forever and gated never left. Now (`Daemon.drain`,
  `uninstalled_reason`): the code folder gone (refix-gw: with no other
  version beside it), the data folder gone, or the code folder orphaned with
  no live session and no newer sibling version counts as uninstalled; with nothing running gated exits as before, with
  terminals or jobs running it drains: contract.json removed at once (a
  missing file is "gateway not available" in CONTRACT-v1, so checkpoint stops
  delegating; no CONTRACT change, which must stay identical in both repos),
  `daemon.draining` emitted (a new event kind, which v1 allows), new
  terminals, jobs and remote runtime staging refused with 503 `draining`
  (after the idempotency lookup, so a retry of a job started before gets that
  job instead of being run twice by checkpoint's own runner), `/health`
  carries `draining` and `gated start`/`status` a skew note (a reinstall's
  session can't start a second daemon meanwhile and says why). The running
  work is left alone, never killed (the user's choice to make: they can stop
  it; the plugin going away is no reason to kill a training run). When the
  env's tmux can't be run any more, gated watches each local pane's own
  process (pid and start time from tmux's last answer); an ended one is
  gone/unknown, never "exited" (the phase 5 rule "never claimed alive from a
  saved pid" still holds: a pid only ends a pane's watch, and only when tmux
  can't be asked at all). It exits once no local terminal or job runs (remote
  ones run on in their hosts' runtimes; a reinstall re-adopts them from kept
  records), with its tmux server. While draining: no rights watch (it imports
  from the removed folders), bytecode writing off and records never written
  into a removed data folder (`_save` and `save_host` no longer create
  parents: a lazy import's pycache or a record would have made
  `plugins/data/gate-gateway` again after the uninstall). An update is no
  uninstall: an orphaned folder with a newer sibling keeps serving its jobs
  and the contract until it is free, as before. Rejected: killing the jobs at
  uninstall (silent loss of user work); exiting at once and leaving the
  panes to the watchdog alone (nobody would answer for them meanwhile, and a
  reinstall would adopt them as orphans); marking contract.json "draining"
  instead of removing it (checkpoint 0.7.x would ignore the unknown field and
  go on delegating); a private copy of tmux to keep querying (its libraries
  are in the deleted env too).
- **The tmux server and gw-watch outlived gated** (the `--keep-data` case and
  every idle exit): `remain-on-exit` keeps dead panes for reads, so the server
  never became empty, and the watchdog only reacted to its socket going. Now
  gated stops its server when it exits for good with no local pane running
  anything (`stop_server`: `kill-server`, or with the env's tmux deleted
  SIGTERM to the pid tmux last named, checked by its start time and its
  command line naming this socket); a live pane keeps it for the next gated
  (SIGTERM, an update), as before. And the watchdog now also stops the server
  once gated's socket is gone and no pane runs anything (it counts the
  server's children with a terminal; a listing it can't read stops nothing),
  which covers a gated that left with a pane still running when that pane
  ends later. Rejected: having gw-watch alone do it (a 5 s lag and no way to
  tell a restart from an exit), killing the server on SIGTERM regardless (a
  restart re-adopts live panes).
- **Status lines drew "⚠ gate: ready".** `$.ui.status(text)` takes only the
  text (types 2.1.299; Claude Code 2.1.301 pins it as a notification with no
  color, and the notice renderer draws every such line with its warning
  glyph and color: probed with a throwaway mod in the TUI harness, which also
  showed `$.ui.toast` as a plain box and `$.ui.log` with a neutral bullet).
  There is no level or kind to pass, so the normal state leaves the status
  line: "ready" is a toast (5 s), and the status line is kept for what warrants
  the sign: setting up (commands wait), a failed setup, a waiting dialog, a
  refused key, a daemon of another version (or a draining one). checkpoint's
  "⚠ check: recording" is checkpoint's to change.
- **Debian: the shell that starts the prefix sourced ~/.bashrc.** Not
  Debian-specific: upstream bash, run as `bash -c` (not interactive, not a
  login shell, not `sh`, no `--norc`) with a socket on stdin at shell level 1,
  takes itself for an rshd/sshd command and sources `~/.bashrc` first
  (`isnetconn` in `run_startup_files`; Debian's `SSH_SOURCE_BASHRC` adds
  `SSH_CLIENT` under the same rule). Claude Code starts that shell exactly so,
  and the TUI harness (like any launcher or service) gives Claude Code no
  `SHLVL`. Reproduced on macOS with the env's bash 5.2 and the system's 3.2.
  Claude Code takes no flags for `CLAUDE_CODE_SHELL` (a bash or zsh path,
  given `-c` only), so the mod sets `SHLVL=1` before the prefix where it is
  missing, empty, 0, garbage or 999 and up (bash then runs at level 2); a
  Claude Code started from a terminal has it already and is left alone, and
  "off" mode doesn't touch it. Rejected: a wrapper script as
  `CLAUDE_CODE_SHELL` adding `--norc` (a file Claude Code runs for every
  command and its snapshot, outside the plugin's read-only folder or with an
  env path it would have to find on its own; phase 4 rejected a data-folder
  `CLAUDE_CODE_SHELL`), bash in `sh` mode (posix mode would change Claude
  Code's snapshot and its `-l` fallback reads `~/.profile`). Left documented:
  Claude Code's `-l` when it has no snapshot (never seen).
- **The v2 vault builder read v3.** `harness.v2_module` took
  `git show main:.../vault.py` first; since 0.9.0 is on main that is v3's
  package module, which can't load alone (15 tests failed in 4 modules). The
  fixture, byte for byte the last v2 vault.py on main, is now the one source.

## Re-fix of the GitHub install fixes (refix-gw, 0.9.1, 2026-10-21)

Three lows a verifier found in the fixes above (probes in a scratch copy of
aafaf3d, each compared with the commit before it). 0.9.1 hadn't shipped, so
the version stays.

- **A killed gated left its tmux server and dead panes running forever.**
  The watchdog took gated's socket file for gated: a SIGKILL, a crash or the
  OOM killer leave the file, so with only a dead pane kept for reads the
  server never ended (8 looks later it still held `gw-watch` and the pane),
  and after an uninstall nothing would adopt it again: the original symptom
  by another road (0.9.0 the same). Now gated writes `<run>/gated.pid`
  (`<pid> <start time>`, ps's `lstart` under `LC_ALL=C TZ=UTC0`, so gated and
  the watchdog's ps print the same words) whole before it binds its socket
  (a restarted gated names itself before its socket replaces the old one,
  so a restart isn't taken for a death), and removes it at exit. The
  watchdog counts gated gone when its socket is missing or the pid file names
  a dead pid (`kill -0`), a zombie or another process (another start time);
  a missing or unreadable file, or a ps that can't say, counts as alive (an
  older gated that writes none keeps the old behaviour). Rejected: a lock
  gated holds (no `flock` on macOS; a FIFO's EOF needs a reader that opens
  before the writer goes), restarting the watchdog with gated's pid at each
  adoption (a race with every restart, and a gated killed before it got
  there leaves the old pid), `ps -o command=` naming `gated serve` (another
  test root's gated, or any reused pid running one, would pass).
- **A job a pause suspended couldn't be resumed after an uninstall**, so it,
  gated and the tmux server stayed forever: the drain withdraws
  contract.json at once, checkpoint's `discover()` then says absent and
  never sends `/v1/resume`, and `job_signal CONT` is refused while the
  session is paused (on 0.9.0 the contract stayed, so checkpoint could still
  resume it). Now the drain resumes every job left suspended (a pause's
  `suspend` or `job_signal STOP`; `Supervisor.resume_stopped`: SIGCONT to its
  process group, a local one only while its process is still the one tmux
  named, by pid and start time, since the env's tmux may be deleted; remote
  ones best effort), counts them in `daemon.draining` (`resumed`) and the
  log, keeps the session's pause record (checkpoint still holds the task
  paused; only the stop is lifted, which is what kept everything there), and
  leaves a pending interrupt escalation to happen (it ends the job, as the
  pause asked). A pause reaching a draining gated is refused (503
  `draining`: nothing could resume what it would suspend), and the drain
  waits for a pause being applied at that moment (`pause_begin`/`pause_end`),
  so what it suspends is resumed too. Rejected again: keeping contract.json
  with `draining: true` (checkpoint 0.7.x ignores the field and would go on
  delegating new work, as 0.9.1 found); leaving the job stopped (nothing
  would ever end it); killing it (silent loss of user work).
- **An update's sweep of the old version folder drained the old gated**,
  which then refused every new terminal and job as "uninstalled": Claude
  Code 2.1.301 removes an orphaned version folder 14 days after marking it
  unless a live session uses it, and a persistent terminal or job may still
  run on the old gated then. `newer_sibling()` covered only the orphaned
  check. Now a removed code folder with another, not orphaned version beside
  it is an update (`replaced`): gated serves on (contract.json kept, new
  terminals and jobs taken, no rights watch: it imports from the removed
  folder) and exits once it holds no terminal or job, as 0.9.0 did, so the
  newer version's sessions start their own daemon; removed with no other
  version it still drains. Rejected: only rewording the refusal (an update is
  no reason to stop serving the sessions that use this daemon meanwhile).

## Verifier lows after the re-fix (fix2-gateway, 0.9.1, 2026-10-21)

Four lows a verifier reproduced on 90732f2/de3a357 (k1, k1b, k15a/b, k16 and
the acceptance's PID0 line). 0.9.1 hadn't shipped, so the version stays.

- **A job's STOP during the drain was never resumed.** `resume_stopped` runs
  once, when the drain starts; a STOP the session's agent, the pane
  (`/ui/term/signal`) or a contract caller sent afterwards was taken (200,
  "suspended"), and once the session ended the job, gated and the tmux
  server stayed forever: the refix-gw forever-state by a later road. Now a
  job's STOP or TSTP is refused while gated drains (503 `draining`,
  `STOP_DRAINING`), counted like a pause being applied (`pause_begin`/
  `pause_end`), so the drain also waits for a stop under way and resumes
  what it stopped. Every other signal still works, and a terminal's TSTP or
  STOP (job control in its shell, which keeps the terminal open anyway) is
  not refused. Rejected: resuming at every tick of a draining gated (it
  would undo a stop the person asked for while the session still runs, and
  hide the refusal).
- **A job's TSTP (and a STOP that didn't hold) was recorded "suspended" for
  a running job**, and the drain then said it resumed it. A pane's process
  group is orphaned (its leader's parent is the tmux server, in another
  session), so the kernel drops SIGTSTP and SIGTTOU there, and tmux
  continues the pane's own process after SIGSTOP: TSTP by killpg never
  stopped anything, and `_stop_group`'s answer was ignored for STOP. Now a
  job's STOP and TSTP both use the group stop (SIGSTOP to every member but
  the root, read back in ps), the job is recorded suspended only when that
  holds, and otherwise it is continued (nothing left half stopped without a
  record, which neither `/v1/resume` nor the drain would continue) and the
  answer carries the real state and a note (a job a pause suspended keeps
  that record). The drain counts a job as resumed only when ps showed a
  member stopped just before its SIGCONT (a remote one: the same check in
  the host's ps, `RemoteTmux.cont_group`), and a record that said suspended
  for a running job is corrected and logged as such. Found on the way: a
  job that is only its pane's own process (`exec ...`) can't be suspended at
  all (the root never stops; the pause and the signal say so); left as is.
- **On a plain uninstall a remote job a pause suspended stayed stopped** on
  its host: the env's ssh goes with the data folder, so the drain's SIGCONT
  failed (`remote_unreachable`), and the records that could re-adopt it
  were deleted too. Now a draining gated may use the system's ssh
  (`/usr/bin/ssh` by path, already what `others = "mine"` and "use my own
  login once" run; `ssh_conf.allow_system_ssh`, never in a stand-in or
  `gate`) with the call's generated config and `-o ControlMaster=no`, so it
  only rides the gateway's live master (the run dir keeps its ControlPath;
  `ControlPersist` 120 s, and the drain starts within a 30 s tick of the
  uninstall); with no master the call stops before ssh runs (the agent it
  would need is the env's, gone too), and the drain asks once even right
  after a failed poll (`insist`). When it still can't (no system ssh, the
  host down, the master gone) the job stays stopped there, stated in
  terminals.md, daemon.md and the README with the remedy (resume first,
  `--keep-data`, or `kill -CONT -- -PGID` on the host). Rejected: the remote
  runtime continuing jobs marked paused once gated stops polling (a host
  that merely lost its link would resume work a pause meant to hold);
  resuming remote jobs before the env can go (an uninstall gives no
  warning); a mux client of our own over the master's socket (the system's
  ssh already speaks it).
- **Terminal reads glued a command's first output line onto its command
  line** when prompt and command filled their rows exactly: the line editor
  wraps such a line by writing the next character, so tmux marks the row
  soft-wrapped and `capture-pane -J` (the agent's lines since the phase 5
  review) joined the output to it (`...$ echo "PID""0=$$ START"PID0=76777
  START`; acceptance_terminals failed with a --tmp of exactly that length).
  Now the agent reads the physical rows (`capture-pane -N -T`) and, in the
  same tmux command and region (history and screen together), the rejoined
  lines only to find values across a wrap: each rejoined line is its rows
  end to end (`align_rows`), and what `scrub.text_spans` finds there is
  masked in every row it spans (`mask_rows`) before each row's own scrub.
  If the two don't line up the rejoined lines are used as before. Rejected:
  re-splitting the joined line where the shell wrote a newline (tmux keeps
  no such mark), padding commands in the acceptance script (the agent would
  still misread such lines).
- The draining gated's log went only into the deleted data folder; from
  the drain on its lines also go to `~/.config/gateway/run/gated-drain.log`
  (0600, never a folder made, 64 KiB at most).
- A later verifier low (final-gw): with the env's tmux gone (a plain
  uninstall) a job the drain resumed still said `suspended` in job_status
  and job_list while it ran, since only `_update` (list-panes) maps
  `paused_as` to the state; `resume_stopped` now sets it itself (running, or
  waiting_auth; `_live_job_state`) and emits `job.state`.

## 0.10.0 decisions (2026-10-22)

What the 0.10.0 fix rounds decided, and why (0.11.0 removed the install
mark and its older-install default, and made unconfigured sudo the user's
own: see the next section). The details are in the module
docs (sudo.md, managed.md, daemon.md, accounts.md) and CLAUDE.md's
invariants 3, 5, 11, 14 and 17.

- **This computer's sudo starts as "ask" on new installs; existing installs
  keep `true`.** A new user shouldn't find sudo approved before they chose
  it. An upgrade must change nobody's rights, so the install's kind is
  recorded as a mark inside the encrypted vault (`"baseline": 2`). A vault
  without it is an older install. Rejected: keeping the old `true` baseline
  and creating a vault at every new install's first session. Without a
  stored record, an old starter's `true` can't be told apart from Claude
  editing the new starter. Consequences accepted: a machine
  that never had a vault counts as new, so a `sudo = true` an older starter
  wrote waits for one `gate check localhost`; a locked or damaged vault
  gives the stricter new defaults until it is readable (the refusals say to
  unlock); starting a fresh vault makes an older install a new one;
  exports leave the mark out, and an imported source machine gets "ask".
- **No work-specific defaults in the shipped plugin.** The `ml-catalog`
  kind needs an explicit `host` (no default). A converted 0.6 catalog
  account without one keeps its approval snapshot, so once the host is
  added and approved its sign-in is kept. The identity check in `test_packaging` holds only sha256
  digests of the words it keeps out, so the test never publishes them.
- **The gateway doesn't approve the web tools.** `http` and `download` can
  carry data out or use an account, which is Claude Code's permission
  mode's call, not the gateway's.
- **Plain reads are approved only for plain project or temp files.**
  Approving `cat` anywhere let auto mode read credential files without the
  reviewer. Reads elsewhere go to Claude Code (prompt or reviewer), not to a
  refusal. `gate forget` lost its approval too: it deletes stored secrets.
- **`gate forget` keeps no copy; `gate rotate` keeps one.** Forgetting means
  gone, so forget names the older copies that may still hold the secret and
  how to delete them; rotate's copy lets the person put the old vault back
  by hand (SPEC 15).
- **The managed-mode text scan counts a tool path as run only where it
  would run.** The earlier rule refused ordinary admin commands (`sudo rm
  /usr/local/bin/gh`, `sudo cat /etc/ssh/sshd_config`). Only a shell's or
  su's `-c` takes a command string; tracers and sandboxes count only as the
  program; `arch` is a wrapper. A shell string that is a variable (`bash -c
  "$CMD"`) is refused, since the hook can't see what it runs; the refusal
  says to write the command out. The scan's known misses are listed in
  managed.md; it is a guardrail, the stand-ins and the vault are the
  boundary.

## 0.11.0 decisions (2026-10-23 to 2026-10-24)

The user approved eight decisions for 0.11.0; [PLAN-0.11.md](PLAN-0.11.md)
implements them, its section 18 lists what its reviews changed or rejected,
and its section 19 holds the lead's decisions, which win over the rest. In
short:

- **Ungated unless configured** (decision 1). The gateway stands only
  between Claude and the hosts and accounts gateway.toml configures; anything
  else uses the user's own tools, untouched, with no gateway decision. It
  reverses v3's "unlisted machines are refused". Consequences accepted and
  documented: Claude's shell holds the user's own agent and tokens, and any
  route around a stand-in can reach a configured host with them, so a host's
  limits bind only if the user's own credentials don't also open it; this
  computer's sudo is the user's own until configured, and then works only
  where it needs no password. "Configured" is sticky: the form, the approved
  snapshot and `private/configured.json`; taking a target out is a widening,
  and a broken form never lets a configured target through. Stand-ins exist
  only where something configured can be reached, so a new install shadows
  nothing. Rejected: global `[policy]` read/exec/write/credential denies
  reaching unconfigured hosts (the hook can't judge a host it knows nothing
  about, and refusing all unconfigured ssh would undo the decision);
  re-seeding the starter with `[hosts.localhost] sudo = "ask"`.
- **Per-mode values** (decision 2). Every right and restriction can differ
  per Claude Code permission mode, one order everywhere (deny < ask < cc <
  allow < unconfigured), a table must name `default`, a bare `true` keeps its
  meaning (allow in auto and bypass only), dontAsk gets cc, plan never
  allows. Callers with no mode (jobs, terminals, scripts, gated) use the
  strictest word of every mode but plan. Rejected: ranking cc with ask where
  Claude Code prompts anyway (its allow rules can make cc wider); dropping
  dontAsk. Lead decision 1: an explicit `allow` the user writes for a mode
  is honoured (the network class, the http and download tools); defaults
  never approve. Lead decision 3: the recorded mode carries an epoch, so a
  stand-in never reads a record older than the last mode it was told.
- **Network commands are one class** (decision 3): curl, wget and the rest
  are asked about by default in every mode, behind sudo and wrappers too,
  and a hit not allowed in that mode keeps the gateway's allow off the
  whole command (lead decision 19.1: an explicit allow approves). It is a
  guardrail; the known misses are listed (network.md). curl and wget lost
  their special refusal.
- **No backward compatibility** (decision 4): the 0.6 conversion, export
  formats 1 and 2, the 0.10.0 install mark and its older-install sudo
  default, npm's `cli.js` detection, `[settings]`, `managed = "warn"`, the
  managed refusal and the curl/wget refusal are deleted. A 0.6 vault is
  converted with the published 0.10.0 first; a detector refuses to create a
  vault beside one.
- **Latest only** (decision 5): every dependency `"*"`, `requires-pixi` the
  newest pixi, one tested pixi and Claude Code, `pixi run update-deps` at
  each release; an older env is used only on the lock's Python minor.
- **git decides by repository** (decision 6): in a repository with a
  configured remote every git command runs the env's git with its own
  read-only global config, an allowlisted environment and the gateway's
  settings at command-line scope; everything else runs the user's git. Lead
  decision 9: local commands there still run while the vault is locked or
  the entry is broken; anything that contacts the remote is refused. The
  stand-in's body lives in `githelper.py`, one process, for speed. Rejected:
  putting only the identities in `GIT_CONFIG_GLOBAL` (a repository's
  `user.email` could then replace the account's).
- **Browser sign-in with PKCE** (decision 7) for azure and ml-catalog: the
  gateway's confirm dialog is the gate, the browser opens by absolute path
  only after Open, the callback lands on 127.0.0.1, the tokens go straight
  into the vault, browser-automation tools are refused meanwhile. Lead
  decision 5: a stored credential that doesn't fit the approved account is
  refused at use. Lead decision 12: a browser sign-in's refresh token isn't
  exported (an imported one could never be used).
- **The vault passphrase is offered, not forced** (decision 8): after a
  stored secret, until the user answers Set passphrase or Not now.
- **Lead decision 10**: an account CLI run by its path is refused while an
  account of its kind exists (its destination can't be told from the
  words); by its name, the stand-in passes an unconfigured destination to
  the user's own tool. **Lead decision 11**: a consent or import confirm
  longer than one dialog comes in parts, applied only after the last.
- **Lead decision 13 (WS-9)**: while anything is "ask", every Bash call
  goes to the Bash hook (`$DATA/ask-marker`), about 0.1 s each with a vault:
  the hidden-command rule can't refuse a `source ./deploy.sh` it never
  sees, and the stand-ins can't tell its `ssh box` from a typed one.
  Rejected: more trigger words (any command can hide a program). An
  account that lists `owners` covers only those and its login (before, the
  only account of its kind covered every owner whatever it listed, so a
  personal repository went through a work account's key); listing the
  first owner is a widening. `sudoedit` and `huggingface-cli` are refused
  by their bare names where their configured counterpart exists (no
  stand-in supplies them); the local sudo dialog's Remember it starts
  unticked, like the remote one.
- **WS-9 review fixes**: a command that hides what runs in Claude's shell
  (a sourced file, eval, exec, a variable as the program or `-c` string, a
  function) is asked about while an entry is "ask", not refused: Claude
  Code's prompt is the consent an "ask" needs, and the refusal broke
  `source .venv/bin/activate`, `eval "$(pyenv init -)"` and the like for
  anyone with `sudo = "ask"`. Rejected: refusing them (a venv or pyenv
  can't be used), and allowing them (the gap reopens). xargs, parallel and
  find -exec get no decision for an "ask": what they run has no shell
  parent, so `typed_by_claude` already refuses an "ask" there; nor does a
  job. Every restriction a stand-in passes as "ask" for a typed command
  counts (exec, read, network, the forwarding grants: ssh's
  `_policy_gate`), not only the rights. The lock's cap on this computer's
  sudo is no "ask" the user wrote and counts for nothing, and the marker is
  never removed while the vault can't be read (the unlock brings the
  approved "ask" back with no form load). "owners listed" waits only for
  the only account of its kind for a host: beside another one, listing
  owners takes nothing out.
- **Lead decision 14 (WS-10a): an "ask" is proved by a record** for every
  stand-in, replacing the ask marker and the hidden-command ask above. The
  Bash hook notes each ssh, sudo, account-CLI and git stage it asks about
  (`asks.py`: Claude Code's process, the real folder, the tool and its
  exact words, the entries), and a stand-in passes an "ask" only for a
  typed command with a matching record, once, within 15 minutes. What a
  sourced file, eval or a function runs never has one, so it needs no
  prompt (`source .venv/bin/activate` runs) and its stand-in refuses the
  "ask"; a stage whose words or folder the hook can't spell out is denied
  up front, since the stand-in would refuse after the OK. Rejected: a
  record that matches any words (a hidden ssh could take the typed one's),
  and recording what the hook can't read. The records sit in the user's
  run folder: a guardrail, like the typed walk. Program names are compared
  without letter case (macOS's file systems ignore it); the allow step
  still approves only the plain lower-case name. A job's network class is
  judged at its payload's mode (nothing re-checks it when the job runs).
- **WS-10a review: a record lives until the session's next call.** The hook
  writes its record when it answers "ask", before the user decides, so a
  declined prompt, one Claude Code couldn't show (`-p`), a stage that never
  ran (`false && sudo x`) or an account asked about but not chosen left a
  record a later sourced file could use for 15 minutes. Now the next Bash or
  Monitor call's hook drops the session's earlier records before anything
  of it runs, and pre_bash.sh sends every such call to the hook while one is
  pending (`$DATA/asks`, a link to the run folder's records, so the sh needs
  no process to look): one Python start, right after an ask only. (None
  was written in dontAsk; see the release verification's fixes below.)
  Rejected for now: binding the record to the asked
  tool call through the typed shell's command line, which would follow
  Claude Code's script shape (`eval '<command>'`) and fail closed for every
  "ask" when that changes. The cost of the choice: a command started while
  an asked one runs (two read-only calls at once, a subagent's, a
  background command whose asked stage starts after Claude's next command)
  drops its record, so the asked one is refused after the OK and is run
  again by itself. The hook also asks about the account the CLI stand-in
  will choose (`clis.chosen`, GATE_ACCOUNT included) rather than every
  "ask" account its destination may use; `gate with` follows the account's
  use and credential policy; `gate check|rotate|copy-to` on an "ask" host
  need the record too. scp and sftp on "ask" stay refused: the ssh they
  start would need a proof from the scp process (as git's gated parent
  gives), left for the lead.
- **Release verification fixes (verify012).** (1) On Linux the browser
  sign-in's listener kept listening for up to 0.5 s after the sign-in
  ended: `close()` doesn't wake a thread waiting in `accept()`, so a
  connection then completed its handshake (never served). `Listener.close`
  now shuts the socket down first (macOS can't shut down a listener, but
  wakes a blocked `accept()` on close), waits for the serve thread, and a
  connection accepted after that is closed unanswered; the accept no
  longer polls, and the listener's own timer ends it at its deadline.
  (2) Claude Code 2.1.310 shows a hook's "ask" in dontAsk too, so the
  hook's record is written there as in every mode (without it the
  stand-in refused after the user's Yes). Seen live: in dontAsk a plain
  `true` gets no gateway decision and Claude Code refuses it, an explicit
  `dontAsk = "allow"` is approved, and "ask" prompts. (3) Lead decision 8:
  the stand-ins' refusals (ssh, sudo, the account CLIs, git's credential
  helper, a pass-through loop) and `gate`'s now name their mode: the one
  the stand-in read (`_CALL["mode"]`), else the session's recorded mode,
  else "modeless" (`modes.standin_audit_mode`); `gate` and asiml decide
  modeless. A web tool's refusal before it read the mode still names none.
- **Its review's fixes (verify013).** (1) A sign-in's end stops the
  listener (`Listener.stop`: the socket shut down, nothing that blocks) and
  removes the marker under the sign-ins' lock, before the waiters hear of
  it; the wait for the serve thread comes after. Before, a connection made
  as the end was announced still reached the listener (a 410 page).
  (2) Lead decision 8 for credential uses too: every `audit.use` names the
  mode the use was decided in, as the refusals do (the stand-ins' own
  mode, the http tool's, "modeless" for gated, `gate` and asiml), and so
  does an Entra mint (`entra.access_token(..., mode=)`, its own use line).
  A test scans `src/` for an `audit.refusal`, `audit.use` or mint call
  without a mode.
- **Not in 0.11.0**: the stored-value paste check (about 0.1 s per prompt;
  an open question for the user, PLAN-0.11 §9.7).

## Rejected alternatives

- **MCP tools first** (v2's design): every git, gh, ssh and sudo action
  through a special tool, with `*_confirm` twins answering `ask`. It prompted
  in auto mode, needed tool names Claude doesn't reach for, and its git
  hardening ignored the user's config and hooks. v3 keeps two tools, `http`
  and `download`.
- **Rewriting commands with `updatedInput`**: see the platform table.
- **A PermissionRequest hook to allow curl or wget**: it would get around the
  an organization's managed rules.
- **Settings allow rules** (`Bash(sudo *)`): auto mode drops them, and plugins
  can't ship them.
- **Plugin `bin/` for the stand-ins**: appended last on PATH.
- **`userConfig` for hosts and accounts**: lives in settings.json, defaults
  don't reach hooks.
- **Mods for everything** (v3's view: early access, and the Input element
  has no masked mode): PLAN-v4 adopted a mod for conveniences and, since
  phase 3, for the dialogs (a Client field, not Input); every guard stays in
  the classic hooks.
- **Input, prompt.edit capture or AskUserQuestion for secrets** (phase 3):
  each passes the value through every plugin's hooks or paints it
  (FEASIBILITY-v4 P1).
- **MCP elicitation** for approvals or secrets: auto-cancelled in the desktop
  app, and its answers are tool results.
- **OS dialogs, a browser, a terminal prompt** (v3's popup backends, `gate
  secret`, device-code sign-in): removed in phase 3 (the brief: every
  plugin-owned UI inside Claude Code).
- **Typed commands that open grants** (v0.6's `/gate:add` and friends): the
  form plus one consent pop-up replaces them, and the user can just ask.
- **A shared stand-in test entry convention** (phase B request): the existing
  entries fit; a third convention would add code without a user.

## Before v3 (condensed)

v1 (2026-10-15) routed curl, wget and friends through an MCP server with an
allowlist and a vault. v0.4 to v0.6 (2026-10-17) added accounts, take-over of
git/gh/ssh into MCP tools, typed setup commands with grants, native dialogs
and export/import. Lessons that still hold:

- **MCP elicitation is auto-cancelled** by the desktop app and `claude -p`
  (logged `{"action": "cancel"}` every time). Never rely on it.
- **A blocking UserPromptSubmit hook doesn't keep a secret off disk**: Claude
  Code shows an error, refills the input box and writes the text to the
  transcript and history. Values are never typed in chat; blocking plus
  scrubbing stays only as the paste guard.
- **Values are typed in native dialogs** (in v0.6 and v3: osascript, zenity,
  kdialog opened by the gateway's own process; superseded by PLAN-v4 phase 3,
  which made the dialog a pane inside Claude Code). Claude Code's question
  pop-ups send their answers to the model, so they're never used for values. (AppleScript
  variables carry a `gw` prefix: `kind` is a reserved word and broke the first
  live run.) A local browser form came and went; the native dialog was
  simpler.
- **The gateway's own vault**, separate from the user's personal secret store;
  no `keychain:` or `env:` references.
- **`unset` through `CLAUDE_ENV_FILE`** removes the user's `SSH_AUTH_SOCK` and
  token variables from Claude's Bash; settings `env` couldn't (the desktop
  app's `SSH_AUTH_SOCK` survived `""` and `/dev/null`).
- **Pasted SSH keys are parsed in Python** (`ssh-keygen -y` reads a file, not
  a pipe); passphrase-protected keys are refused because they go into an
  unattended agent.
- **GitHub sign-in works for SSO-only orgs** with gh's public OAuth client
  (v3 used its device flow until PLAN-v4 phase 3 removed browser and
  device-code sign-ins: a personal access token now); GitHub Enterprise hosts
  get `GH_ENTERPRISE_TOKEN`.
- **Pijul needs pinned host keys and its own config dir**: it can't ask about
  a new host key without a terminal, ignores HOME/XDG for its config, and
  silently skips an `identity.toml` without `last_modified`.
- **No full `az` CLI**: it can't take an injected token and keeps its own
  plaintext login. Azure goes through REST with tokens the gateway mints
  (Databricks takes one as `DATABRICKS_TOKEN`); v3 adds only a minimal `az`
  stand-in for SDKs.
- **The ML Catalog is implemented natively** in asiml's workspace format
  (asiml keeps its login in the keychain and has no macOS build).
- **Entra rotates refresh tokens**: the new one must be saved, or the next
  sign-in breaks.
- **Host names aren't tokens**: the paste guard exempts them unless they
  start with a known token prefix.
- **Stdlib Python plus pixi**: the only dependency for users is pixi, which
  pins Python, age and OpenSSH for every platform; the MCP server is
  hand-rolled.

Dropped in v3: the typed commands and grants, per-account prompt policies and
read/write/delete/exec switches, sudo enable per session or always, the regex
Bash blocklist (only curl and wget remain, as parsed commands),
`port_check`/`cert_inspect`/`file_hash`, `git_mirror`, `config/policy.json`,
`install.py`, `legacy-settings.json` and the quarantine folder.
