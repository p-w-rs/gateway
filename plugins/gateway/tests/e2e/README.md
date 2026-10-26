# Headless end-to-end suite

`pixi run e2e` runs a few short, real Claude Code sessions (`claude -p`,
model haiku) against a scratch copy of this plugin and local test servers,
and checks what the gateway does from the outside: what Claude is told,
what its Bash environment looks like, which commands the approval hook lets
through without a prompt, which it refuses, which accounts the stand-ins
pick, and that no secret shows up anywhere. It is not part of
`pixi run test`.

```
pixi run e2e                    # every scenario (about 10 minutes, a few cents)
pixi run e2e --only ssh,git     # some: context ssh git web refuse default modes leak notice midturn jobs
pixi run e2e --keep             # keep the scratch folders and the transcripts
pixi run e2e --save DIR         # copy report.json, stream-json, debug logs, audit log to DIR
```

Needs: `claude` signed in, pixi, a system git, rsync; for the optional
`jobs` scenario also a checkpoint checkout next to the gateway repo
(`../checkpoint/plugins/checkpoint` from the repo root; without one the
scenario is skipped and the gateway needs nothing of checkpoint's). `GW_E2E_TMP` sets
where the scratch folder goes (a temp folder; default the system one) and
`GW_E2E_RUN_BASE` the base of the short run dir for unix sockets (default
`/tmp`).

## How the gateway is pointed at a test vault

Production reads no environment variable for the vault home (SPEC 1): a
command in Claude's Bash can set any variable, so a variable could point the
stand-ins at another vault. The suite instead uses a marker file that only a
copy of the plugin in a temp folder can carry:

1. `run_e2e.py` (run from the checkout) creates the e2e root, a 0700 folder
   under a temp folder, and a short 0700 run dir, copies the plugin into
   `ROOT/plugin` (git-tracked plus untracked, non-ignored files) and writes
   `ROOT/plugin/e2e-root` with two lines: the root and the run dir. The
   checkout never gets a marker (`tests/test_e2e_marker.py` checks).
2. `paths.e2e_marker()` honours the marker only when no test override is
   active, the plugin folder the code runs from (its own location, never a
   variable) is owned by the user and lies under a temp folder (`/tmp`,
   `/var/tmp`, macOS `/var/folders`), the marker is a regular file (not a
   symlink) owned by the user and not writable by group or others, and each
   named folder is a real directory owned by the user with no group/other
   permission bits, spelled and physically under a temp folder. Otherwise it
   is ignored and nothing changes. `hooks/e2e.sh` applies the same rules for
   the sh hooks (`launch.sh` takes the data folder from it, `prompt.sh` and
   `post.sh` the gateway home), and a unit test checks that sh and Python
   agree on every case.
3. With a valid marker, `run.py` runs every mode (hooks, MCP, stand-ins,
   askpass, git helper, `gate`) under `testing.override`: the gateway home is
   `ROOT/home/.config/gateway`, the data folder (pixi env, stubs, git
   include, audit log) `ROOT/data`, the run dir the marker's second line.
   `ROOT/e2e.json` may name the same fakes the unit tests use (a fake
   dialog, the sudo binary, the remote-euid helper of the sshd harness,
   pop-up timings); unknown keys are dropped. Under the e2e override the
   guards also refuse the real `~/.config/gateway/private` (compared as text;
   the e2e code never stats or lists the real home), and SessionStart tells
   the user `gateway: e2e test mode: this session uses the test vault in ...`.

Before anything starts, the inner part (run from the copy) checks that
Python honours the marker, that `launch.sh e2e-root` (sh) names the same
folders, and that every gateway location (home, form, private/, vault, data,
bin, git include, audit log, run dir, env python) lies inside the e2e root
and none under the real `~/.config/gateway` or the real plugin data folder;
any doubt stops the run. The pixi env is then built into `ROOT/data` with
`CLAUDE_PLUGIN_DATA` pointing at a decoy folder, which must stay unused.

### Why this cannot help an attacker

- **It only moves the gateway away from the real vault.** The marker
  changes where the gateway looks; it never reads, copies, decrypts or
  prints `~/.config/gateway`. With the marker honoured, the gateway works
  on whatever vault is in the named folder: an empty one, or one that
  whoever wrote the marker made. Its secrets are that person's own.
- **It cannot reach a real installation.** It counts only for plugin code
  that itself runs from a temp folder. Claude Code loads an installed
  plugin from its plugin cache and a developer from the checkout; neither
  is ever under `/tmp` or `/var/folders`, so a marker written into them is
  ignored. To use the marker, someone must start Claude Code with
  `--plugin-dir` on a copy in a temp folder, which is exactly what the
  suite does.
- **Others can't plant one.** The plugin folder, the marker and the named
  folders must belong to the user, with no write (marker) or any (folders)
  access for group and others, and no symlinks; another account on the
  machine can't prepare them in the shared temp folder.
- **No new power for code already running as the user.** Such code could
  equally edit the plugin's own files, or read `private/key.txt` directly
  (the threat model in SPEC 1 and docs/dev/modules/sudo.md says so). The one
  thing a marker could add is a pop-up asking the user for a secret that
  then lands in a vault the marker's author can read; that needs the user
  to run a session from the planted temp copy, and that session says
  `e2e test mode` at its start.

## What it starts

- sshds from `tests/harness_ssh.py` on 127.0.0.1: `e2ehost` (target),
  `e2enosudo` (sudo = false), `e2ejump` and `e2ebehind` (via the jump),
  each with the fake password sudo first on the remote PATH (remote sudo
  runs through the gateway's staged askpass; `ssh_remote_euid` lets the fake
  pass as root to it). `e2eask` (ssh = "ask") points at a closed port.
- the smart-HTTP git server with Basic auth from `tests/harness_accounts.py`
  (repos `e2eorg/work`, `e2euser/proj`), accounts `e2e-work` (owner
  `e2eorg`, commit identity) and `e2e-personal` (default).
- an HTTP API from `tests/harness_ux.py` (`/data` needs the bearer key,
  `/echo` returns the Authorization header) and the api-key account
  `e2eapi` for `127.0.0.1`.
- the fake dialog of `tests/harness.py`: every pop-up is cancelled and
  logged (the suite expects none).
- local sudo: the real `/usr/bin/sudo`, but through a guard script that
  runs it only as `sudo -n true` (the NOPASSWD probe and the one command
  the suite runs); anything else is refused.
- the user's own tools: recording fakes named ssh, scp, sftp, git, gh, hf
  and sudo (`tests/fakes/fake_user_tool.py`, through e2e.json's
  `user_tools`). A stand-in that passes an unconfigured target through
  runs one of them, never the real tool: each run is logged (argv, cwd,
  `GW_PASSTHRU`) and prints `fake TOOL ran`.
- `work/pushprobe`: a repository with one commit and no remote, pushed to
  the "ask" host's URL in `refuse`.
- for `modes`, a probe plugin (`fixtures/modeprobe`) loaded beside the
  gateway: its SessionStart and Bash PreToolUse hooks log each payload's
  `permission_mode` string and session id, nothing else, and decide
  nothing.

`gateway.toml` and the vault are written through the gateway's own API
(`vault`, `consent.approve_all`) with generated fake secrets: two git
tokens (one shaped like `ghp_…`), an API key, the remote sudo password,
the hosts' ssh keys, a fake `GITHUB_TOKEN` planted in Claude's environment
(the user's own: since 0.11 it stays in Claude's shell, PLAN-0.11 §1.10)
and a fake `CLAUDE_CODE_CLIENT_KEY_PASSPHRASE` (Claude Code's own: it must
never reach Claude's shell).

## The sessions and what is checked

`claude -p --plugin-dir ROOT/plugin --permission-mode auto --model haiku
--output-format stream-json --verbose --include-hook-events --debug-file …`,
each with a fixed list of commands and at most 90 s (210 s for `notice` and
`midturn`, which wait for Claude Code's 45 s "waiting for input" notice; 60 s
for each `modes` session); the account's
claude.ai connectors are switched off (`ENABLE_CLAUDEAI_MCP_SERVERS=false`)
so only the gateway's MCP server loads. `default` runs in Claude Code's
default mode (`manual` on the latest Claude Code, `default` before), and
`modes` once in every mode `claude --help` lists.

| scenario | checks |
|---|---|
| context | SessionStart context lists the hosts and accounts and says e2e mode, and has no checkpoint job lines while gated hasn't seen checkpoint ("ckoff", PLAN-0.11 §9.4); the env file applies in foreground, background and subagent Bash: the stand-ins for the configured hosts and accounts (ssh, sudo, git) first on PATH, no git include, `GIT_SSH_COMMAND` or `RSYNC_RSH`, the user's own `SSH_AUTH_SOCK` and `GITHUB_TOKEN` kept, Claude Code's `CLAUDE_CODE_CLIENT_KEY_PASSPHRASE` gone; SubagentStart context |
| ssh | `ssh e2ehost echo …`, `ssh e2ehost sudo whoami` (staged askpass, fake sudo log), `scp`, `rsync`, `ssh e2ebehind …` (via the jump), `sudo -n true`: no denial, output right, and for each the stream shows the hook's `allow` and the debug log `Hook approved tool use` right before the dispatch, a permission decision of a few ms and no classifier line; audit `use` lines |
| git | clone/push over http through the git stand-in (the gated git): `e2eorg/*` with the work token as `x-access-token`, `e2euser/*` with the default account, the commit email from the account's identity include, audit lines; the clone's own config names no gateway helper or include (command scope); `git status` outside any configured repository and `git ls-remote` of an `.invalid` remote run the user's own git (the fake) with the full argv, and only the remote one writes a `passthrough` audit line (no argv) |
| web | `curl` asked about by the hook (the network class, `[network] commands` "ask" by default), so a permission denial in `-p`, and nothing reaches the API; the http tool listed at start and called without ToolSearch; the key sent as a bearer header; an echoed key comes back as `***`; no hook decision for the http tool |
| refuse | `ssh e2enosudo sudo whoami` denied (`gateway: sudo is off for e2enosudo`); `ssh e2eask …` a permission denial (nobody can answer an `ask` in `-p`); `git -C pushprobe push e2eask:…` asked about up front (the hook names ssh on e2eask), a permission denial; `ssh nosuchhost.invalid …` passed through to the user's own ssh (the fake gets the full argv and `GW_PASSTHRU=ssh:1:…`; one `passthrough` audit line without the argv); refusals in the audit log |
| default | Claude Code's default mode (`--permission-mode manual`): the allowed ssh gets no allow from the gateway (denied in `-p`), curl still asked about |
| modes | one session per `--permission-mode` choice `claude --help` lists, with the probe plugin: the payload's `permission_mode` in PreToolUse (and SessionStart, where it is there) is a string `modes.from_payload` knows, for the key the choice means (PLAN-0.11 §2.1's table; an unknown one fails and names what to add), and the gateway's hook allows `ssh e2ehost` (a bare `ssh = true`) only in auto and bypass; the strings seen are listed for the table |
| leak | `cat notes.txt` (a file holding the API key and the sudo password) comes back masked; a failed `cd sub && false` is an error result with its own exit code (the round 3 EXIT trap is rolled back) and `pwd` then shows the old cwd, `cd sub` then `pwd` the new one (Claude Code's cwd tracking); `cat ../leak.txt; exit 3` (a token shape) keeps `Exit code 3` and gets the gateway's PostToolUseFailure warning; a Monitor command without `| gate scrub` runs (the round 3 rule is rolled back), one with the optional `| gate scrub` runs too; round 5: a Read of `notes.txt` comes back masked, and a Write and an Edit of a plain file in the project pass with no hook output (the file guard's sh fast path; PostToolUse skips edit tools) |
| notice | round 4: a background `cat notes.txt; printf 'Continue? [y/N] '; sleep 70` runs as typed (the `2>&1 \| gate scrub` rule is rolled back) and its "waiting for interactive input" notice (the raw planted values) is held back by the prompt hook while Claude is idle (hook output or audit `leak` event); a failing background `ls ./no-such-e2e-file > bg-fail.txt 2>&1` is reported by Claude Code with its real exit code; the same stall run in the foreground with a 4 s timeout is moved to the background and its notice is held back too (two `leak` events) |
| midturn | round 4: the same notice arriving while a foreground `perl -e 'sleep 60'` runs (a queued attachment) is held back too |
| jobs | optional (skipped without a checkpoint checkout next to the repo): one session with this plugin and a copy of checkpoint's plugin (`ROOT/ck/checkpoint/plugins/checkpoint`, its pixi env built there), `CHECKPOINT_HOME` = the gateway's e2e state folder and `CHECKPOINT_GATEWAY_ENV` = the e2e env.sh (`run_e2e.checkpoint_env`: both inside the root, set explicitly; a watcher reads checkpoint's MCP server's environment with `ps eww` and kills the session at once if either differs, `server_env_verdict`); a `CLAUDE.md` in the work folder for this session only (`scenarios.JOBS_PROJECT`) and the prompt's first line say what the folder, the hosts and the secrets are and what the task is (see below); afterwards checkpoint is live (gated touched `<run>/checkpoint-seen` during the session, so the next session's context has the job lines; this session's own context is reported, since checkpoint may reach gated after SessionStart); job steps through `job_start`: an env probe (env.sh applied: the stand-ins first, no git include, `GIT_SSH_COMMAND` or `RSYNC_RSH`; no hook `allow`), `ssh e2ehost echo` and `ssh e2ehost sudo whoami` (the staged askpass), an `argv` ssh job, curl (the network class asks, and nobody can be asked in a job) / `ssh e2eask` / a cat of the private folder denied with the gateway's messages and no job created, `sh askscript.sh` reaching `ssh e2eask` refused by the stand-in in the job wording (not "run it as its own command"), `job_tail` of a `cat notes.txt` job masked; no job prints OpenSSH's "ControlSocket ... already exists" line; no planted secret in the other job logs or checkpoint's registry |

**The jobs scenario and Claude Code's classifier.** The gateway never
approves a job (DECISIONS, "Checkpoint jobs"), so in auto mode Claude Code's
classifier decides every `job_start` the gateway doesn't deny, and it
sometimes denies one (`[Third-Party Attack]` or `[Credential Exploration]`
for `ssh e2ehost sudo whoami`, `sh askscript.sh` or the env probe: in 3 of
3 runs before the session got its project context, in none of 3 since).
Such a step and
the checks on its job are reported as `not reached (classifier)` (SKIP
lines; the summary counts them): never a pass, never a gateway failure. The
gateway's own denials (curl, the "ask" host, the private folder) come
before the classifier and fail hard when wrong, as does every check on a
job that ran. When the model retries a step, the call that ran is judged
(with the step's last job record); a step is "not reached" only when the
classifier denied every call with its name (`scenarios._job_call`). The
project context states facts only (the user's own test,
local servers, fake secrets, the task); it doesn't try to steer the
classifier, so a run can still have steps not reached.

Then: no planted secret (the leak scenario's token shape aside: it is shown
unmasked on purpose), nor its base64, `user:value` base64 or URL-encoded
form, in the stream-json, the session transcripts (main and subagent) or the
audit log (Claude Code's debug logs are scanned too, for information), and
the fake dialog saw no pop-up.

## Unit tests and mutations

`tests/test_e2e_marker.py` (in `pixi run test`): the checkout has no
marker; the marker is ignored when absent, outside a temp folder (named
folder or the plugin itself), not owned by the user, writable by others,
symlinked, or with group/other bits on a folder; the production call yields
to a test override; e2e.json keeps only known keys (`user_tools` only as an
absolute folder); the e2e override still
guards the real private folder; SessionStart says e2e mode; and
`launch.sh e2e-root` (hooks/e2e.sh) agrees with Python on every case; and
for the jobs scenario, that checkpoint counts only as a whole plugin next to
the gateway repo, that its state folder and env file stay inside the e2e
root, and that the kill switch accepts only those two values; and that a
step Claude Code's classifier denied is "not reached", while a denial by
the gateway's hook or a step that ran never is; and for `modes`, that the
probe's records are read per session and that a payload string the gateway
doesn't know, or one for another mode, fails the check.
`tests/test_acceptance_lib.py` runs the helpers the suite shares with the TUI
acceptances (`tests/acceptance_lib.py`: the recording fakes, the
`--permission-mode` choices, the strings looked for) and keeps each string
in step with the code that prints it.
`tests/test_hookbash_remote_sudo.py` covers the hook fix the suite found
(remote sudo and the host's sudo right). `tests/mutations_e2e.py` (in
`pixi run mutations`) weakens each of these guards in turn.

## Cleanup

The inner part stops the sshds and servers, closes ssh masters and the
remote staging leftovers (and any checkpoint job still running, by its
process group); the outer part kills every process still naming
the scratch folders and removes them. Unless `--keep`, the sessions'
transcripts, `session-env` and `file-history` entries (only those named
after the suite's session ids) and the run's own project folder in the
Claude config dir are removed too. Claude Code still records the scratch
working folder in its `.claude.json` project list. For a `--plugin-dir`
plugin it sets `CLAUDE_PLUGIN_DATA` to `plugins/data/gate-inline` in the
Claude config dir; in e2e mode the gateway ignores it and writes nothing
there (its data folder is `ROOT/data`).
