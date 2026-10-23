# sudo group: local sudo, ancestry, bashparse, the Bash approval hook

Group **sudo**. Modules (all Python 3.12 stdlib):
`src/gateway/sudo.py`, `ancestry.py`, `bashparse.py`, `hooks_bash.py`, and the
sh prefilter `hooks/pre_bash.sh`. Contract: [SPEC-v3.md](../SPEC-v3.md) §8,
§9.1, §10; API conventions: [MODULES-v3.md](../MODULES-v3.md).

## ancestry.py (SPEC 10)

`is_direct(tool, entry_scripts=False) -> (allowed, culprit)`

Walks up from the stand-in's parent, identifying each process **by executable
path** (`proc_pidpath` via ctypes libproc on macOS, `/proc/PID/exe` on Linux)
— never by argv[0] or a caller-set name.

- **direct** when every process between the stand-in and `CLAUDE_PID` is a
  shell (`sh bash dash zsh fish ash`) or a wrapper (`env nohup time timeout nice
  ionice stdbuf xargs sudo doas`), and `CLAUDE_PID` is reached. For ssh and git
  credentials (`tool` in `ssh scp sftp rsync git git-credential`) the git/ssh
  family is also allowed: `git git-remote-* git-lfs rsync scp sftp ssh gh`.
- A process tree rooted at the checkpoint plugin's job runner counts like
  Claude's shell; it is recognised by its command line (`…/checkpoint/…/run.py`
  with a later `server` argument), read as an argv list from KERN_PROCARGS2
  (macOS) or `/proc/PID/cmdline` (Linux). Two extra checks: the process's
  executable (by path) must be a python interpreter, and that run.py must be
  an existing absolute file. **Limitation:** a command line is chosen by
  whoever starts the process, so code already running as the user (say a
  Makefile step that re-execs python with a crafted argv and a run.py it wrote
  under a `checkpoint/` folder) can still pass as the runner and get the
  credential without `scripts = true`. SPEC 10 specifies command-line
  recognition; the direct/scripts rule guards against build scripts using a
  credential *in passing*, not against hostile code with the user's uid
  (which could read the age identity file directly). The checks only stop
  the cheap imitations (a renamed shell via `exec -a`, a made-up path).
- No `CLAUDE_PID` (a user's terminal sourcing env.sh, an unrelated job) → not
  direct, unless the checkpoint runner is found.
- Not direct + `entry_scripts=True` → `allowed=True` (the opt-in). `culprit` is
  the basename of the first non-allowed intermediate (for the audit line and the
  "sudo started by make got no password" message); "" when direct; `?`
  (`ancestry.UNTRACED`) when there is none to name (no `CLAUDE_PID`, or the
  walk reached init: a job still running after its session ended). The
  refusals of the local and remote sudo, ssh, git and the account CLIs then
  name `ancestry.UNTRACED_WHO` ("a program the gateway can't trace back to
  Claude (such as a job still running after its session ended)"; local sudo:
  `sudo.not_direct_who`), never `?` or "a script".

`typed_by_claude() -> (ok, culprit)` is the stricter test for an `"ask"`
right (SPEC 9, 10; round 1, 2026-10-19). Claude Code can only prompt for the
command line Claude typed, and that line is all the approval hook reads; so
the stand-in must have been started by Claude's own command shell (the direct
child of `CLAUDE_PID`) or a fork of it (a pipeline stage or `( … )` subshell:
same executable path and same argv as its parent), with nothing in between.
Not ok: any non-shell intermediate (git, rsync, scp, sftp, make, xargs,
timeout, ...), a shell of its own (`sh -c '…'`, a script: other argv), no
`CLAUDE_PID`, the checkpoint runner (also when `CLAUDE_PID` names the runner
itself: culprit `CHECKPOINT`, "checkpoint"), anything unreadable. `scripts =
true` doesn't relax it. Whenever it refuses and checkpoint's job runner
(`_is_checkpoint_runner`) is the stand-in's parent or any process above it
(`_under_checkpoint_runner`, the whole chain), the culprit is `CHECKPOINT`, so
the stand-ins can give the job wording (integration lows, 2026-10-19); a job
whose runner has ended (re-parented to init) keeps its own culprit, and
`is_direct` then gives `(False, "?")`, or `(True, "?")` with `scripts =
true` (an orphaned job gets credentials only from such entries). Nothing
run in a gateway terminal or job is typed either (gw-reruns, 2026-10-21):
gated's start file exports `CLAUDE_PID=$$`, the pane's own shell, for
`is_direct`, so without a check the stand-in that shell starts (its parent is
`CLAUDE_PID`) or one a script there starts (its grandparent) passed the walk
and an `"ask"` right or policy was used with nobody asked; a `CLAUDE_PID`
whose executable is a shell is never Claude Code, so the walk refuses at once
with the culprit `TERMINAL` ("gateway-terminal"; the stand-ins'
`consent.pane_ask_message`). Exec-style wrappers (`env`, `nohup`, `nice`) and `bash -c
'simple command'` (bash execs it) leave no trace in the tree, so the approval
hook looks through them and asks (see hooks_bash below).

`claude_ancestor(home=None) -> reason | None` (SPEC 6, 15; added with the
rollback, 2026-10-19) backed `gate secret` and the other terminal paths
behind a one-time code; PLAN-v4 phase 3 removed those paths, so no flow
calls it now (it keeps its tests).
It walks the whole parent chain from this process's parent to pid 1 and
returns why the process counts as started from Claude Code:

- an ancestor whose executable (by path) is Claude Code's
  (`is_claude_exe(exe, home)`): basename `claude`, anything under
  `HOME/.local/share/claude/versions/` (the native install names the binary
  by its version), or under `HOME/Library/Application
  Support/Claude/claude-code/` (the desktop app's bundled copy), or npm's
  native binary `.../node_modules/@anthropic-ai/claude-code/bin/claude.exe`;
  or node running npm's `.../@anthropic-ai/claude-code/cli.js` as its first
  argument (`is_claude_node`, by argv: an npm install before 2.1.113;
  together `is_claude_process`); `home` is `paths.user_home()` (also
  compared resolved). The returned reason is that path;
- an ancestor whose pid is `CLAUDE_PID` (`"CLAUDE_PID"`, whatever its
  executable);
- `UNREADABLE` when the chain can't be read: a parent pid of 0 before pid 1
  (also a parent outside the PID namespace, as under `docker exec`), a loop,
  more than `MAX_DEPTH` levels, or a process whose executable can't be read
  and whose owner can't be read either, or which runs as the user (except
  OpenSSH's session process, comm `sshd`/`sshd-session`, under a root-owned
  parent: Linux makes it non-dumpable, so its exe is unreadable even to its
  owner). An unreadable process named `claude` (comm) counts as Claude Code.
  Above an unreadable process of the user's own the walk goes on (review
  round 5), and a Claude Code process further up is returned instead of
  `UNREADABLE`.

Another user's process whose executable can't be read (on Linux root's
`sshd`, `login`, `sudo`) is not the user's Claude Code, which runs as the
user, so the walk goes on above it. On macOS `proc_pidpath` answers for
every process whose executable still exists, root's included, but returns
nothing for one whose executable was deleted or replaced while it runs
(checked with a copied `sleep`: its path before the unlink, nothing after).
That is ordinary in the user's own terminal: the login shell in every open
tab, or a tmux server, after `brew upgrade` (old kegs are cleaned up) or
`port upgrade` (old files go when a port is deactivated). So `UNREADABLE`
mostly means the user's own terminal there, and the callers say so:
`gate_setup.CANT_TELL` ("can't tell which programs started this terminal
...; open a new terminal window and run CMD there"), not `FROM_CLAUDE`.
Passing such a process was rejected: Claude Code's native install names its
binary by its version (comm `2.1.301`), and auto-update can remove old versions
while sessions still run on them, so those sessions would pass. Linux reads
a deleted executable's path (`/proc/PID/exe` gives `... (deleted)`).
`_owner(pid) -> (euid, comm)` reads `proc_bsdshortinfo` on macOS and
`/proc/PID/status` + `/proc/PID/stat` on Linux. **Limitation:** a process
detached from Claude's tree (a double fork re-parents it to init, a terminal
window Claude opens with `open -a Terminal`) isn't seen; this is defence in
depth behind the one-time code (`popup.prove_presence`), which stays the
guard. The desktop app's Terminal panel runs its shells under the app's
helper (`Claude Helper`), not under Claude Code, so the user can run `gate
secret` there; Claude can type into that panel too
(`mcp__terminal__run_in_terminal`), so the approval hook denies `gate
secret` for every tool (hooks_bash below).

Public process helpers (by executable path): `exe_path(pid)`,
`exe_name(pid)`, `parent_pid(pid)` (used by ssh.py and transfer.py). On macOS
the parent pid comes from `proc_pidinfo(PROC_PIDT_SHORTBSDINFO)` (flavor 13),
which answers for root's processes too (`PROC_PIDTBSDINFO` returns nothing
for them when the caller isn't root, so a walk up through setuid sudo used to
stop there); BSDINFO is the fallback. `sudo.py` also uses `_cmdline(pid)`.
`started_at(pid)`: when a process started (BSDINFO's start time on macOS,
`/proc/PID/stat` and `btime` on Linux; exec keeps it), or None; SessionStart
times itself with it (`hooks_session.session_hook`).

## sudo.py (SPEC 9.1)

`main(argv)` — the local sudo stand-in:

1. `/usr/bin/sudo` must be root-owned + setuid (tests use the fake sudo through
   `testing.override(tools={"sudo": …})`); otherwise it refuses.
2. localhost sudo right `false` → refuse; `"ask"` unless
   `ancestry.typed_by_claude()` (whatever `scripts` says) → refuse (`run it as
   its own command so Claude Code can ask you (not inside a script, sh -c,
   xargs or a wrapper)`; inside a checkpoint job, culprit `checkpoint`, the
   approval hook's job wording `ASK_JOB` = `consent.job_ask_message`: `gateway:
   a job can't use the "ask" right for sudo on this machine (nobody can be
   asked while it runs); run it with the Bash tool as its own command, or ask
   the user to set it to true.`; inside a gateway terminal or job, culprit
   `gateway-terminal`, `ASK_PANE` = `consent.pane_ask_message`: `gateway: a
   gateway terminal or job can't use the "ask" right for sudo on this machine
   (nobody can be asked about what runs there); ...`). While a passphrase
   vault is locked (`vault.VaultLocked`) the rights come from the new
   install's defaults, so a `true` or unsaid sudo here is `"ask"` (fails
   closed); each of these refusals then ends with
   `consent.LOCKED_SUDO_NOTE` (unlock it with `/gate-unlock`), as do the
   approval hook's prompt and job refusal for it.
3. `-S`/`-A` → refuse, including the long forms `--stdin`/`--askpass` and any
   getopt abbreviation of them (`--std`, `--ask`, `--a`). sudo's options are
   scanned the way sudo does (getopt `+`: stop at the first non-option word;
   `-u USER`, `--user USER` and the other value-taking options consume their
   value; an ambiguous long option is taken to have one, the safe side), so a
   command's own flags (`sudo ls -A`) are not sudo's. `-n` /
   `--non-interactive` is tolerated and stripped only when a password can be
   supplied.
4. `probe_nopasswd()` (`sudo -n true`, cached 10 min per user in the run dir):
   success → `exec /usr/bin/sudo` untouched — nothing stored, nothing asked,
   for any caller.
5. A password is needed and the caller isn't direct → exec the real sudo with no
   password and print the one-line "got no password" message (NOPASSWD still
   works; `scripts = true` makes a non-direct caller count as direct).
6. Direct caller: password from `localhost.sudo[USER]` (vault), or a verified
   secret pop-up (`popup.secret` with `store=`/`load=`: the helper stores a
   late answer after the requester's exit 75, a sudo that joined the same
   pop-up re-reads the vault; the prompt says that unticking Remember it
   uses the password once). The dialog names localhost's sudo right for gated's
   recheck (`SUDO_CHECK`: switched off while the dialog is open, the value
   is never handed over, stored or used) and offers "Remember it", ticked
   (unticked: used for this command, never stored); once a dialog gave the
   password, the stand-in reads the effective right again (`_rights_now`)
   before sudo runs (PLAN-v4 phase 3 review). A stale password opens the one
   re-entry pop-up (`popup.reenter`, with the same check) and is refused,
   never fed again. Fed to `sudo -A`
   through a **one-shot FIFO** in a 0700 run-dir folder: a writer thread opens
   `O_WRONLY|O_NONBLOCK` (retry), writes the password once, then **unlinks the
   FIFO**, so a wrong password costs exactly one attempt → marked `stale`
   (no pam_faillock lockout, no retry). A rejection is recognised two ways:
   - a second askpass call finds no FIFO, writes a `rejected` marker and exits
     1 (sudo's default `passwd_tries=3`), or
   - sudo's stderr has a line `Sorry, try again.` or `sudo: N incorrect
     password attempt(s)` **and** the password was served **and** sudo failed
     (SPEC 9.1 step 5). This is the only signal under `passwd_tries=1`, where
     sudo never calls askpass a second time.

   stdin and stdout are inherited (pipes/here-docs work); stderr is relayed
   to ours as it arrives, through `scrub.Scrubber([password])` (a password
   of 8+ characters never shows), and scanned line by line. Signals are
   forwarded and the exit code is preserved (128+sig on a signal).
   Trade-offs of the relay: the command under sudo sees a pipe, not a tty, on
   stderr (Claude's Bash has no tty anyway); after sudo exits the relay drains
   for at most `STDERR_GRACE` (2 s), so a daemon the command left holding
   stderr gets EPIPE on later writes; and a command that itself prints one of
   those lines and then fails marks the password stale (the next use asks for
   it again; nothing is retried).
7. A `stale` saved password → refuse without retrying (rejection message).

`askpass_main()` — `gate-askpass` (run.py `askpass`): reads `GW_ASKPASS_FIFO`
once and refuses when euid is 0, when `SUDO_COMMAND`/`SUDO_USER` is set, or when
its parent isn't the real sudo (production, `_is_real_sudo_parent`: resolved
parent exe == the trusted sudo, `/usr/bin/sudo` or NixOS's
`/run/wrappers/bin/sudo`, root-owned + setuid; tests: the parent is the
phase-A fake sudo, identified by its command line). On Linux the parent's
`/proc/PID/exe` can't be read (setuid root: non-dumpable, ptrace read access
needed), so `_linux_setuid_parent` accepts it when `/proc/PID/status` shows
effective uid 0 and `Name: sudo` and its `PPid` is the pid the stand-in
wrote to the askpass folder's `owner` file before starting sudo (review
round 2: without this, every local sudo with a stored password failed on
Linux; not tried on a real Linux machine, unit-tested with a faked
`/proc` status). With no trusted sudo at all the stand-in and `verify_local`
say so with the next step (`UNTRUSTED`: ask the user
to run the root command in their own terminal). Known limit: the stub used
while the env builds execs `/usr/bin/sudo`, which NixOS doesn't have (sudo
works through the gateway once setup finishes).

Also, for `gate check`: `probe_nopasswd(user=None)` and
`verify_local(password) -> (ok, message)` (`sudo -k; sudo -S -v`).

## bashparse.py (SPEC 8)

`parse(command, comments=True) -> [segment][pipeline-stage]` of `Stage`, or
**None** ("too complex to judge"). Honours single/double quotes and
backslashes; splits on `;`, `&&`, `||`, newline (segments) and `|` (stages); a
newline right after `|`, `&&` or `||` continues the pipeline or list, as in
bash. An unquoted `#` starting a word starts a comment to the end of the line
(bash, and zsh `-c`; a quote or `;` inside it opens or splits nothing; `>#x`
is None, as bash reads it as a syntax error); `comments=False` reads `#` as a
character, as an interactive zsh without `INTERACTIVE_COMMENTS` does (round
2: without comments, `ls #'⏎rm -rf ~/x #'` read as one `ls` and was allowed).
Returns None on `$( )`,
backticks, `<( )`, `>( )`, heredocs/here-strings, `eval`/`exec`/`source`/`.`,
subshells/functions, `sh|bash|zsh -c` in command position, backgrounding `&`,
redirections other than `> >> 2>&1 2>FILE` to plain files (a target with `$`
or a glob is not plain; `> f` with no command is a truncation), `${…}` with
anything but a name/operator inside, and any assignment prefix other than
`GATE_ACCOUNT=NAME` (kept as the stage's first word).

A `Stage` is a `list` of argv words (it compares equal to the plain list) with
what the words hide, so the hook never vouches for it unseen:

- `redirects`: `[(op, target)]`, `op` in `>`, `>>`, `2>`, `2>&1`. Recorded,
  never dropped (verification 2026-10: dropping them let
  `echo KEY >> ~/.ssh/authorized_keys` pass as a plain `echo`).
- `expands[i]`: word i has a parameter expansion outside single quotes
  (`$X`, `${X}`, `$1`, `$'…'`, `$"…"`); `$HOME`/`${HOME}` don't count (the hook
  substitutes them).
- `globs[i]`: word i has an unquoted `*`, `?`, `[…]` or `{…}`.

An fd number only starts a word (`abc2>f` is the word `abc2` and `> f`).

## hooks_bash.py (SPEC 8)

`main(payload) -> decision | None`. Decision order (all reasons start with
`gateway:`; every deny is audited via `audit.refusal` for `gate why`):

1. deny `curl`/`wget` in command position (any stage), also behind
   `command` (not `-v`/`-V`), `builtin`, `busybox`, `env` (`-S` strings are
   split), `nohup`, `nice`, `stdbuf`, `time`, `ionice`, `chrt`, `taskset`,
   `setsid`, macOS's `arch` (`-arm64`, `-arch NAME`; `_ARCH_VALUE`),
   `timeout`, `xargs`, `sudo`, `doas`, `caffeinate` and shell
   reserved words (`if`, `then`, `do`, `!`, ...); `_unwrap(argv, fork)`.
   Also `az … get-access-token` for Bash and Monitor (round 2: the az
   stand-in gives tokens only to programs; not for the Terminal panel).
   Also (review round 5, `_deny_gate_user`) `gate secret` for every tool,
   the Terminal panel included (`DENY_GATE_SECRET`, since PLAN-v4 phase 3:
   "gate secret was removed: credentials are typed only into the gateway's
   own dialog in Claude Code ..."): its subcommand read after `_unwrap` with
   and without the forking wrappers, and, when a stage hides what runs (a
   shell, `eval`, `exec`, `source`, a loop, `xargs`, `find -exec`, `su`; see
   `_runs_hidden`) or the parser gives up, the words `gate secret` anywhere
   in the text (quotes removed; `_names_gate_secret`). And `gate
   export|import|copy-to` in the Terminal panel and in a job
   (`GATE_TERMINAL_SUBCMDS`: their dialogs need a command Claude runs with
   the Bash tool in the session). A command
   that only names the words (`grep 'gate secret' README.md`) is judged as
   any other.
2. deny naming `~/.config/gateway/private` / the v2 key+store / the run dir
   (via `paths.Protected`: resolved, case-insensitive, hard links), `age -d` on
   them, a direct `git credential` / helper / askpass run, or setting
   `GIT_TRACE_REDACT` to anything but a clear true. What is checked, per stage:
   - **every word** (not just path-looking ones: a bare `key.txt` is a file in
     the working directory) except a command name without `/`, resolved from
     the payload's `cwd` **and every directory a `cd`/`pushd` earlier in the
     command can move to** (logical and physical spellings, `CDPATH`); a
     wrapper's `env -C`/`--chdir DIR` or `sudo -D DIR` (`_wrapper_chdir`)
     moves its own command only, not the stages after it, and a target the
     hook can't know (`env -C "$X"`) isn't followed, like `cd $X`;
   - option values (`--file=PATH`, `-fPATH`) and redirect targets (a write
     into private/ destroys the vault);
   - globs, expanded (real matches, plus a component-wise, case-insensitive
     match against the protected entries), so `cat ~/.config/gateway/*/key.txt`
     is caught;
   - recursive readers on a folder that *holds* private/ (`paths.Protected.
     is_parent`): `grep -r/-R` (with no path: the working directory), `rg`,
     `ag`, `ack`, `rsync`, `scp -r`, `cp -r/-a`, `tar`, `zip`, `ditto`, `pax`,
     `cpio` → `DENY_PRIVATE_TREE`. `ls` with no operand lists `.`. grep's
     recursion is read in every spelling: `-r`/`-R` in a cluster, any getopt
     abbreviation of `--recursive`/`--dereference-recursive` (`--recur`,
     `--dereference-rec`), and `-d`/`--directories` (or `--dir`) with an action
     other than `read`/`skip`, glued, clustered (`-id recurse`) or in the next
     word; a grep's long options must all be known ones or it isn't vouched for.
   The `GIT_TRACE_REDACT` check is on the raw text with quotes and
   backslashes removed (so `=""0`, `=''0`, `=fal"se"`, `=\0` and an empty
   value are caught) and fires even though the assignment prefix makes the
   command unparseable. It is defence in depth only: no regex models every
   shell spelling (`printf -v`, a computed name, ...); the git credential
   helper's own `GIT_TRACE_REDACT` check (SPEC 9.4, git group) is the guard.
   A word with a `${X:-PATH}` default (`-`, `=`, `+`, `?`, with or without
   `:`) is also checked as its literal default (the shell uses it when X is
   unset), so `cat ${x:-~/.config/gateway/private/key.txt}` is denied.
   Home resolution uses `$HOME` and the password-database home; under a test
   override only the test's home, so tests never stat or glob the real
   `~/.config/gateway`.
3. deny a gateway verb whose **form** right is `false`, the verb looked up
   behind the exec-style wrappers above (`_command`: not timeout/xargs/sudo,
   which the stand-ins see as an intermediate). Remote sudo: `sudo` in command
   position in what the remote runs (ssh's command, rsync's `--rsync-path`,
   or a scp / rsync remote path, which old rsync and `scp -O` hand to the
   remote shell: `rsync f "box:/x; sudo id"`) on a host whose sudo is `false`.
   Also denied: git's `--upload-pack`, `--receive-pack`, `--exec`, `clone -u`
   and `-c|--config remote.*.uploadpack|receivepack=` with a sudo word
   (`_git_remote_programs`), and `sftp -s` (a path runs that command on the
   host). `gate check|rotate|copy-to HOST` (and `gate check all`) count as
   ssh to that host (round 2: they log in with Claude's key): ssh `false`
   denies, `"ask"` asks (and a hidden one is scanned with `gate` as an ssh
   word); `rotate` and `copy-to` are allowed only on an effective `true`.
   Host words resolve like the ssh stand-in's `_classify`: any case,
   `gw-NAME`, addresses; ssh's value-taking options are the stand-in's own
   table (`-B`, `-P` included).
4. ask when a gateway verb's **form** right is `"ask"` (ssh, local sudo, the
   remote host's sudo for a remote command with a sudo word). The stand-ins
   give an "ask" right only to a command Claude typed
   (`ancestry.typed_by_claude`), so:
   - scp, sftp and rsync on an "ask" right (the ssh they start can't be asked
     about) are **denied** at once with the way to do it
     (`_deny_transfer_ask`: `ssh NAME CMD` / `ssh NAME 'sudo CMD'`, or ask the
     user to set the right to `true`); in the user's Terminal panel (no
     stand-ins) they are asked about;
   - a command that hides how it calls the stand-ins gets a text scan
     (`_fallback_ask`): one bashparse can't read, a stage whose command is a
     shell / eval / exec / source (behind a wrapper: `env bash -c '…'`), a
     loop (`for`, `case`, `select`), or a gateway verb with an unresolved
     expansion (`ssh $H x`). It asks when the de-quoted text names a host with
     an "ask" right (name, `gw-NAME` or an address) next to an ssh-family or
     git word (or a sudo word, for sudo = "ask"), when it has a sudo word and
     localhost sudo is "ask". Not seen: a script sourced into Claude's own
     shell (`source x.sh`, `. x.sh`, `exec ./x.sh` run its commands as
     Claude's shell, which the stand-in can't tell from Claude's own
     command), and a name computed at run time (`$(printf ask)host`); a
     guardrail, like the prefilter.
5. allow (only in `auto`/`bypassPermissions`) when every stage is an allowed
   gateway verb on a host with the **effective** right `true`, a `gate`
   subcommand (`status check login rotate why log export import copy-to
   migrate scrub` — never `with`, nor `forget`, which deletes stored secrets
   with no dialog and no backup: the reviewer or a prompt decides), or a
   benign command (`cd pwd echo printf true : test [ ls cat head tail wc grep
   sort uniq date sleep`). The ones that read (`pwd test [ ls cat head tail wc
   grep sort uniq`, `BENIGN_READERS`) only when everything they may read
   (`_read_operands`: every operand and option value; grep's pattern left out
   only when it can be told apart) is a plain file of the project
   (`CLAUDE_PROJECT_DIR`, else the cwd; not `/`, the home folder or above it)
   or a temp folder (the scp rule's; never a path in the home folder):
   resolved inside one, no hidden or credential-like name below it
   (`_CRED_NAME`: `.env*`, `*.pem`, `*.key`, `id_*`, `*credentials*`,
   `.netrc`, `.pgpass`, `.npmrc`, `.pypirc`, `krb5cc*`, `*secret*`, `*token*`,
   `*.p12/.pfx/.ppk/.jks/.keystore/.p8/.keytab/.kdbx/.gpg/.ovpn/.age`,
   `*_rsa/_dsa/_ed25519/_ecdsa`, `passwords*.txt`, `*.tfstate*`, `*.tfvars`,
   `kubeconfig*`, `service-account*.json`), not in a credential folder
   (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.docker`, `~/.config`,
   `~/.claude`, the Claude config folder and the gateway's home; a project in
   one doesn't count, in any letter case); with no path operand the cwd (or
   stdin) must be in the project or a temp folder; a recursive grep's whole
   tree must hold nothing hidden or credential-like, each symlink in it
   pointing at a plain file too (at most `READ_TREE_MAX` entries); `wc
   --files0-from` never; and no allow at all when a wrapper changed the
   command's directory (`env -C`/`--chdir`, `sudo -D`), since the file is read
   from there, not the stage's cwd (`_reads_plain`, GW-UX-1). Such an
   all-benign command gets its own reason
   (`READ_ALLOW`), not "host/account rights". Option/target rules:
   sudo (`-u/-g/-H`, `-n` tolerated, no `-S/-A/-E`/long opts, command not in the
   destructive list — see below); ssh (safe option set only, every target
   resolving to a form host); scp/sftp/rsync (`_scan_transfer`, round 1):
   - options on an **allowlist** (`RSYNC_SAFE_SHORT`, `RSYNC_SAFE_LONG`,
     `RSYNC_SAFE_LONG_VALUE`, `SCP_FLAGS_SAFE`, `SFTP_FLAGS_SAFE`): a
     value-taking short option takes the rest of its cluster or the next word,
     so `-ave CMD`, `-aze sh`, `-essh` are rsync's `-e`; never `-e/--rsh`,
     `--rsync-path` other than `sudo rsync`, `-M/--remote-option`,
     `--log-file`, `--write-batch`, `--only-write-batch`, `--read-batch`,
     `--daemon`, `--config`, `--remove-source-files`, `--old-args`,
     `--temp-dir`, `--partial-dir`, `--backup-dir`, `--suffix`,
     `--files-from`, `--filter`, `--*-dest`, `-K` (follows a planted
     symlink on the receiver), or an unknown option;
   - every remote path plain (`[A-Za-z0-9._/~@%+=,:^-]`: no metacharacter,
     space or glob, since it may reach the remote shell unquoted);
   - a download names what it copies: not a folder's contents (a trailing
     `/`, `.`, no path or a bare `~`), nothing hidden anywhere in the remote
     path (`-R` recreates the whole path here);
   - every local operand (sources and destination, and sftp's implicit `.`)
     passes `web.plain_local_path`: the project (the working directory, not
     the home folder itself or above), `~/Downloads` or a temp folder; no
     hidden part as written or resolved; nothing in `~/.ssh`, `~/.config`,
     `~/.claude`, the Claude config folder, `~/Library`, the gateway's
     folders; no file Python runs at startup;
   - sftp only as the first stage of its pipeline (it reads commands, `!cmd`
     runs here, from a pipe).
   Never allowed, whatever the command (the classifier judges
   these instead): an output redirection other than `2>&1` or to `/dev/null`
   (it is a write: `echo KEY >> ~/.ssh/authorized_keys`, `ls 2> ~/.bashrc`); a
   word with an unresolved expansion or a glob/brace expansion (the shell turns
   it into words the hook never saw); anything after a `cd` whose target can't
   be known (`cd -`, `cd $D`, `popd`); `sort` with `-o` or any long option
   (`--output`, `--compress-program` runs a program; long options abbreviate);
   `uniq` with a second operand (its output file); `grep -R` /
   `--dereference-recursive` / BSD grep's `-S` (follow symlinks met while
   recursing, which the path checks can't see; `grep -r` doesn't), or a grep
   with an unknown long option (an abbreviation could be `--recursive`).
6. otherwise no decision.

For the user's Terminal panel, a command with a `#` is also judged (steps
1-4) with `#` read as a character (`bashparse.parse(comments=False)`): an
interactive zsh without `INTERACTIVE_COMMENTS` runs `ls #; cat
~/.config/gateway/private/key.txt` as two commands.

**The sudo destructive list** (SPEC 8 step 5) withholds `allow` from a few
catastrophic root commands so they reach the classifier or a human even with
localhost sudo `true`. A plugin `allow` skips the auto-mode classifier, so the
list must hold against the natural ways of writing those commands
(verification 2026-10: `sudo timeout 5 rm -rf /`, `sudo env rm -rf /`,
`sudo sh -c 'rm -rf /'`, `sudo FOO=b rm -rf /` were all allowed):

- **Every word that could be a program** is checked, not just the first after
  sudo's options: a bare name, or a path in a `…bin` directory (`/bin/rm`,
  `…/gnubin/rm`; not a data path like `/etc/passwd`). Wrappers are an open set
  (`env`, `timeout`, `nice`, `nohup`, `time`, `stdbuf`, `ionice`, `chrt`,
  `caffeinate`, `script`, …), so none are enumerated.
- **Command strings** — any word with whitespace or `; & |` — are split
  (shlex, shell punctuation) and checked the same way, up to 3 levels
  (`sudo watch 'rm -rf /'`, `sudo flock f -c '…'`); one that doesn't split is
  not vouched for.
- **Programs that run a command their words don't show** are never vouched
  for: shells (`sh bash zsh dash ksh ash mksh yash fish csh tcsh …`) — with
  `-c` the command is a string, and without it they read commands from stdin
  (Claude's Bash has no tty, so `echo 'rm -rf /' | sudo bash` runs the pipe);
  `su`, `runuser`, a nested `sudo`/`sudoedit`/`doas`/`pkexec`; `xargs` and
  `parallel` (arguments from stdin); `at`/`batch` (commands from stdin);
  `env -S`/`--split-string` (and any long `env` option); `find` with
  `-exec/-execdir/-ok/-okdir/-delete`; and the tracers, sandboxes and
  wrappers that exec a command (`_EXEC_RUNNERS`: sshpass, strace, ltrace,
  dtruss, flock, script, unbuffer, chroot, tmux, screen, ssh-agent, nsenter,
  setarch, catchsegv, proot, fakeroot) as the program itself, the command's
  first word or a word by its path (`sudo strace -f make`), never as a plain
  operand (`sudo apt install tmux strace` keeps its allow). macOS's `arch`
  is looked through like `nice` (`sudo arch -arm64 make install` is judged
  as `make install`).
- **Assignments**: `sudo VAR=value CMD`, `sudo env VAR=value CMD` and `sudo
  arch -e VAR=value CMD` are not vouched for, like a shell assignment prefix
  (`PATH=`, `LD_PRELOAD=`).
- **Dangerous targets** (for `rm -r` and `chmod/chown/chgrp -R`): `/`, `~`,
  `~user`, `~+`, `$HOME`, a home directory, or any top-level directory
  (`/usr`, `/Users`, `/tmp`, macOS's `/private/etc|var|tmp`), spelled
  absolutely, relative to the working directory the stage runs in (the
  payload's `cwd` plus earlier `cd`s: `cd / && sudo rm -rf usr`), with `//`
  or `..`, or through a symlink (resolved).
- **Other spellings of the list**: `rm -R`, `--recursive` and its getopt
  abbreviations (`--rec`, `--r`); GNU's g-prefixed tools (`grm`, `gdd`, …);
  `mkfs*` and macOS's `newfs*`/`diskutil eraseDisk|eraseVolume|reformat|
  zeroDisk|randomDisk|secureErase|partitionDisk`; `wipefs`; `dd of=` /
  `shred` on a device (any spelling; `/dev/null`, `/dev/stdout`,
  `/dev/stderr`, `/dev/tty`, `/dev/fd/*` excepted); `shutdown`, `reboot`,
  `halt`, `poweroff` (also as a word: `systemctl reboot`), `init 0|6`,
  `kill 1`, `kill … -1`, `killall/pkill launchd|init|systemd`; `passwd`;
  `/etc/sudoers*` in any spelling (`/etc//sudoers`, relative from `/etc`);
  the editors that change sudoers or the user/group databases without naming
  a path, whatever their arguments: `visudo` (its default target is
  `/etc/sudoers`), `vipw` (`/etc/passwd`, `-s` `/etc/shadow`) and `vigr`
  (review round 4).

These only withhold `allow` — the result is **no decision**, never a deny —
so a false positive (`sudo apt install zsh`, `sudo cat /etc/sudoers`,
`sudo ls /bin/sh`) costs a classifier call or a prompt, never a refusal. The
list is a guardrail for the obvious spellings, **not a sandbox**: a root script
or interpreter (`sudo ./x.sh`, `sudo make install`, `sudo python3 -c …`) can do
anything the list names, and other destructive commands outside SPEC 8's small
list (`sudo rsync -a --delete /empty/ /`, `sudo rm -rf /usr/bin`) are still
allowed, as SPEC 8 specifies. ssh's remote command is not checked against the
list (SPEC 8 applies it to local sudo only).

Steps 1–4 run in every permission mode; step 5 only in auto/bypass. When a
command names `gateway.toml`/`config/gateway` (e.g. `sed -i`), `consent.ratchet`
runs first so a narrow-then-raise within one session still needs the user's OK.

### Design decisions / ambiguities resolved

- **Deny and ask use the stricter of the form and the effective right;
  allow uses the effective right** (round 3; it was the form right before).
  An explicit `false` in the form denies (even mid-approval); a pending
  (widened) right, form `true` or `"ask"` but effective `false`, is denied
  with "waits for the user's OK; run gate check NAME" (the stand-in refuses
  it anyway); an approved `"ask"` whose widening to `true` waits stays
  `"ask"` (the stand-in still gives it to a typed command, trusting the
  prompt). `gate check` is not denied for a waiting widening: it is how the
  user approves it.
- **`sudo` to a shell is never allowed** (no decision). The first build allowed
  `sudo bash` as "not in SPEC 8's destructive list"; but Claude's Bash has no
  tty, so a sudo'd shell either runs a `-c` string or reads commands from a
  pipe (`echo 'rm -rf /' | sudo bash`), both hidden from the list
  (verification 2026-10). The classifier judges them instead.
- **`sudo curl`**, `command curl`, `busybox wget` and other wrapped spellings
  are denied like `curl` (round 1); an organization's managed `Bash(curl *)` ask
  rule, where there is one, still applies to whatever the hook doesn't decide.
- **scp/sftp/rsync on an "ask" right are denied, not asked** (round 1): the
  stand-in would refuse after the prompt (only a command Claude typed gets an
  "ask" right), so the hook says so first. The user's Terminal panel, which
  has no stand-ins, still gets the prompt.
- **`-L`/`-D`** (local and dynamic forwarding) are in the safe ssh option set
  per SPEC 8; only `-R` and the identity/proxy/agent options are unsafe.

## hooks/pre_bash.sh

POSIX-sh prefilter: silent `exit 0` unless the payload (minus its own
`transcript_path` field, which always names a .jsonl under .../claude/projects)
contains a trigger word as a whole word (`sudo ssh scp sftp rsync curl wget
gate gateway age credential GIT_TRACE_REDACT key.txt claude jsonl az`; `az`
since round 2, for the deny of `az … get-access-token`); on a hit
it pipes the payload to `launch.sh hook-bash`. The whole payload is matched, so a `cwd` under `~/.config/gateway`
also routes a trigger-free command such as `cat key.txt` to the Python hook.
`age` also fires on `vault.age`/`cache.age`, and `key.txt` (the age identity)
was added after verification 2026-10 found that `ln -s ~/.config /tmp/a; ln -s
/tmp/a/gateway /tmp/b; cat /tmp/b/private/key.txt` spelled no trigger, so the
Python hook — which resolves the link and denies — never ran. Fails open.
Phase C wires it into `hooks.json` for `PreToolUse: Bash|Monitor` (and the
Terminal panel; checkpoint's `job_start` since 2026-10-19: its `command` or
`argv` words are in the payload's JSON text, and its tool name holds no
trigger word, so an ordinary job starts no Python). Monitor
calls and Bash calls with `"run_in_background": true` go by the same word
list (rounds 3 and 4 sent every one of them to Python for their `gate scrub`
rules; rolled back, see "Rolled back" below).

**Limitation: the private-folder Bash deny is a guardrail, not a boundary.**
The prefilter is text-based, and symlinks and computed names can strip every
trigger word from a command (`tar c /tmp/a` where `/tmp/a` is an alias of
`~/.config`; `cat "$F"` with F set earlier), so such a read never reaches the
Python hook (the classifier / normal prompt still applies). Even when the hook
runs, a word it can't resolve (`$X/private/key.txt`) is only withheld from
`allow`, not denied. This matches the gateway's stated threat model: it does
not defend against code running with the user's uid reading the identity file
directly (see the ancestry section). A real boundary would have to come from
file permissions or a sandbox, not a text prefilter.

## Tests

`tests/test_ancestry_trees.py`, `tests/test_sudo_standin.py`,
`tests/test_hookbash_parse.py`, `tests/test_hookbash_table.py` (≥ 80-command
decision table in auto and default modes, with the critics' attack examples),
`tests/test_hookbash_local.py`, `tests/test_hookbash_prefilter.py`,
`tests/test_hookbash_remote_sudo.py` (remote sudo and the hook, round 1's
transfer rules on "ask" hosts),
`tests/test_hookbash_private.py` (private-folder deny with a working
directory: bare names, `cd` chains, globs, recursive readers, option values,
redirect targets, `${X:-PATH}` defaults, a symlinked alias of the gateway
folder), `tests/test_hookbash_destructive.py` (the sudo destructive list
against wrappers, command strings, hidden-command runners, assignments, other
spellings of flags and targets, relative targets, homes and symlinks),
`tests/test_sudo_rejection.py` (rejection from stderr
under `passwd_tries=1`, the stderr relay and its scrubbing, `--stdin` /
`--askpass` and option scanning); fixtures in `tests/harness_sudo.py`
(including `OneTryFakeSudo`, a fake sudo that gives up after one wrong
password, and the checkpoint-runner imitations). Security properties are
mutation-checked in `tests/mutations_sudo.py` (158 mutations on 2026-10-19, 208 in
0.10.0's working tree; counts per run in [TEST-LOG.md](../TEST-LOG.md);
the hook's remote-sudo ones are in `tests/mutations_e2e.py`); the group's
tests are 111 across 10 modules. The
askpass **euid-0** refusal is not mutation-checked because it can't be
exercised without running as root; it is enforced in `askpass_main` and
covered by code review.

### Verification fixes (2026-10)

| Finding | Fix | Regression test |
|---|---|---|
| Output redirections dropped → `allow` for `echo … >> ~/.ssh/authorized_keys` | `Stage.redirects`; allow only with none but `2>&1`/`/dev/null` | table rows; `test_hookbash_parse::test_redirects_are_recorded_not_dropped` |
| Bare `key.txt`/`vault.age` with cwd in private/ not denied | every word checked from cwd and `cd` targets | `test_hookbash_private` |
| Wrong password never stale under `passwd_tries=1` | stderr relay scans for sudo's rejection lines | `test_sudo_rejection::test_wrong_password_under_passwd_tries_1_is_marked_stale` |
| `--stdin`/`--askpass` bypass -S/-A refusal | getopt-style option scan with long forms/abbreviations | `test_sudo_rejection::test_long_stdin_and_askpass_are_refused` |
| `GIT_TRACE_REDACT=""0` evades the deny | quotes/backslashes removed; any not-true value denied; helper documented as the guard | table rows |
| Checkpoint runner recognised by spoofable argv | python exe + existing run.py required; limitation documented above | `test_ancestry_trees::test_shell_dressed_up_as_checkpoint_runner_is_not_direct`, `…needs_an_existing_run_py` |
| (2nd round, HIGH) Destructive list only checked the first word after sudo: `sudo env/timeout/nice/xargs rm -rf /`, `sudo sh -c '…'`, `sudo VAR=v rm -rf /` got `allow` | list checked at every program-like word and inside command strings; shells/su/xargs/at/`env -S`/`find -exec`/nested sudo never vouched for; `sudo VAR=`/`env VAR=` not vouched for; targets resolved (cwd, `//`, `..`, symlinks, homes, top-level dirs); `rm -R`, `--rec`, `grm`, `init 0`, `kill 1`, … | `test_hookbash_destructive` (8 tests), table rows; 20 mutations |
| (2nd round, LOW) Private-folder deny bypassed by a trigger-free symlink alias / `${x:-PATH}` | `key.txt` prefilter trigger; `${X:-PATH}` defaults checked; limitation documented (text prefilter is not a boundary) | `test_hookbash_prefilter::test_the_age_identity_by_name_reaches_python`, `test_hookbash_private::test_symlinked_alias_of_the_gateway_folder`, `…test_parameter_expansion_defaults_are_checked`; 2 mutations |

Found while fixing these and fixed too: globs, `$X`/brace expansions, option
values, recursive readers (`grep -r ~`, `rsync -a ~/.config/gateway host:`,
`scp -r`) reaching private/; `sort -o`/`uniq IN OUT` writes and `grep -R`
being allowed;
`sudo ls -A` being refused as `-A` (sudo stops at the first non-option).

### Review round 1 (2026-10-19)

| Finding | Fix | Regression test |
|---|---|---|
| (HIGH) rsync's `-e` inside a short-option cluster (`-ave CMD`, `-aze sh`) ran a local command with `allow` | scp/sftp/rsync options are an allowlist; a value-taking short option takes the rest of its cluster or the next word; `--log-file`, `--write-batch`, `--daemon`, `--config`, `--remove-source-files`, `--old-args`, `-M`, `-T`, `-K`, `--files-from`, ... withhold allow | table rows; 5 mutations |
| (HIGH) sudo/ssh = "ask" skipped when ssh was started by rsync, git or sftp | stand-ins: `ancestry.typed_by_claude` for an "ask" right (local sudo too, also with `scripts = true`); hook: sudo in a scp/rsync remote path is remote sudo, metacharacters in a remote path withhold allow, git `--upload-pack`/`--receive-pack`/`--exec` with sudo and `sftp -s` denied, scp/sftp/rsync on an "ask" right denied, verbs found behind exec-style wrappers and reserved words, unparseable / shell-running / looping commands scanned for an "ask" host's name, host words resolved like the stand-in (`gw-NAME`, any case, ssh `-B`/`-P`) | `test_ancestry_trees` (typed shapes), `test_sudo_standin::test_ask_*`, `test_ssh_ask`, `test_hookbash_remote_sudo::test_remote_sudo_started_by_rsync_*`, table rows; mutations in `mutations_sudo.py`, `mutations_ssh.py`, `mutations_e2e.py` |
| (MEDIUM) scp/rsync/sftp from an allowed host allowed whatever the local destination | every local operand through `web.plain_local_path` (project, ~/Downloads, temp; download's rules); downloads only of named, non-hidden remote paths; sftp only first in its pipeline | table rows, `test_web_download::test_plain_local_path_rules`; mutations |
| (LOW) curl/wget behind `command`/`builtin`/`busybox` | `_unwrap` (also env, nohup, timeout, xargs, sudo, ...) | table rows; mutation |

## Phase C additions

- **Session transcripts** (`hooks_bash`, rule 2): a word that names a Claude
  Code session transcript (`paths.is_transcript`: any `.jsonl` under
  `<config>/projects/` but in `tool-results/`, subagents' transcripts included (round 3),
  globs expanded) is denied with `DENY_TRANSCRIPT`, and so is a recursive
  reader (`grep -r`, `rg`, `tar`, ...) on a folder that holds them
  (`paths.holds_transcripts`). Hook systemMessages, the one-time terminal
  codes among them, are recorded there. `tool-results/` and listing names
  stay allowed, and so does a Workflow run's
  `<session>/subagents/workflows/<run>/journal.jsonl` (exact name, case and
  depth; a regular file with one link; rollback, 2026-10-19): `cat`, `tail`,
  `grep` of it go on, while its run folder, which holds the run's
  `agent-<id>.jsonl` transcripts, stays denied to recursive readers.
- **The user's Terminal panel**: the hook also runs for
  `mcp__terminal__run_in_terminal`. Denies and asks apply; it never answers
  `allow` there (the user's login shell has no stand-ins: real sudo, their
  own ssh keys).
- **Passwordless sudo** (PLAN-v4 phase 7): only as the system already has
  it. `probe_nopasswd(user)` (`sudo -n true`, cached) decides; the gateway
  never writes a sudoers rule (the old `gate check` choice that installed
  one, its root script and its test overrides are gone, and no message
  advises one). Tests: `test_sudo_nopasswd.py` (the fake sudo's NOPASSWD
  mode, the per-call dialog, a sudoers that wants a terminal, the advice
  scan over the code and docs).

### Review round 3 (2026-10-19)

| finding | fix | tests / mutations |
|---|---|---|
| (HIGH) `allow` went by `os.path.basename(argv[0])`: `./ssh HOST CMD`, `/tmp/x/cat f`, `bin/gate status` ran a local file with no review | `_stage_allowed` vouches only for bare names (`"/" in argv[0]` → no decision); the denies still go by the basename | table rows, `test_hookbash_table::test_path_qualified_commands_are_never_vouched_for`; mutation |
| (LOW) `date -s` / `date --set` / a BSD clock-setting operand allowed | `_date_ok`: `+FORMAT` and display options only | table rows, `test_date_that_sets_the_clock_is_not_vouched_for`; mutation |
| (HIGH) an approved `"ask"` edited to `true` stopped being asked while the change waited for the user's OK (the stand-ins still saw "ask" and trusted a prompt) | `_right(form, eff, host, verb)`: the stricter of form and effective for deny/ask; a right the form gives but the user hasn't approved (effective off) is denied with `... waits for the user's OK; run gate check NAME` (`_deny_wait`, naming a jump host that isn't set up); the fallback scan uses it too; `gate check|rotate|copy-to` deny on the form's `false` and ask on either `"ask"` | `test_hookbash_round3` (ssh, local sudo, remote sudo, hidden and unparseable commands, scp/rsync denied, gate check); 5 mutations |
| (MEDIUM) Monitor's lines skip PostToolUse | **rolled back (see "Rolled back")**: with a vault, a Monitor command had to route stdout through the bare `gate scrub` (`_monitor_scrubbed`: every top-level segment ends with it, loops and `if` as one unit closed by `done`/`fi`, quiet builtins exempt; unparseable never counts); `pre_bash.sh` passes every Monitor call | `test_hookbash_round3::test_monitor_*`, `test_pre_bash_hands_every_monitor_call_to_python`; 4 mutations |
| (LOW) gate-askpass blocked forever on its FIFO when the stand-in died first | `O_RDONLY|O_NONBLOCK` and `_read_fifo` with a deadline (`ASKPASS_WAIT` 60 s; `testing` key `askpass_wait`): no writer yet → wait, writer connected → read to EOF | `test_sudo_standin::test_askpass_whose_fifo_nobody_writes_gives_up`, `test_askpass_waits_for_a_writer_that_connects_late`; 2 mutations |
| (LOW) local sudo said "off ... ask the user to turn it on" for a right that waits for the OK | `sudo.WAITING` when the form's localhost sudo isn't false | `test_sudo_turned_on_but_waiting_says_so` |

### Review round 4 (2026-10-19)

| finding | fix | tests / mutations |
|---|---|---|
| (MEDIUM) `sudo visudo`, `sudo vipw`, `sudo vigr` were allowed: no word names `/etc/sudoers`, yet SPEC 8 keeps editing sudoers off the allow list | `_PRIV_EDITORS` in `_is_destructive` (by basename, so a path or a wrapper such as `sudo nice visudo` is caught) | `test_hookbash_destructive::test_sudoers_and_user_database_editors_are_never_vouched_for`; 2 mutations |
| (MEDIUM) a background command's raw output tail reached Claude in Claude Code's "waiting for interactive input" notice | **the deny is rolled back (see "Rolled back"; the prompt hook stays)**: with a vault, `run_in_background: true` needed `_monitor_scrubbed(segs, stderr=True)`: every top-level segment ends with the bare `gate scrub` and every stage before it sends stderr along (`2>&1` or `2>FILE`; a loop's closing `done 2>&1 \| gate scrub`); `DENY_BACKGROUND` says how and how to see a failure (`if CMD; then echo ok; else echo "Exit code $?"; fi 2>&1 \| gate scrub`); `pre_bash.sh` passes every such call. A foreground command Claude Code moves to the background is left to the UserPromptSubmit hook (docs/dev/modules/ux.md) | `test_hookbash_round4`; 3 mutations |

### Rolled back (2026-10-19, lead decision)

The gateway must not change how Claude's ordinary commands run (DECISIONS,
"Rolled back"). Removed from this group:

| removed | was | now |
|---|---|---|
| Monitor rule (round 3) | `DENY_MONITOR` unless every top-level segment ended in the bare `gate scrub` (`_monitor_scrubbed`, `_ends_in_scrub`, `_head`, `_OPENERS`, `_MONITOR_QUIET`) | Monitor is judged like Bash; its lines reach no output hook (known limit); `gate scrub` stays an allowed, optional filter |
| background rule (round 4) | `DENY_BACKGROUND` for `run_in_background: true` unless output and errors went through `gate scrub` (`_stderr_handled`) | judged like Bash; Claude Code's raw "waiting for input" notice is left to the prompt hook (docs/dev/modules/ux.md), the task file stays raw (known limit) |
| pre_bash.sh's always-to-Python cases | every Monitor and background call went to Python | the word list decides for every call |

`hooks_bash.main` is the former `_main` (the decision order above, nothing
after it). Tests: `test_hookbash_round4` (background and Monitor commands
judged like any Bash command, in every mode; the word list for them), the
Monitor rows in `test_hookbash_local` and `test_hookbash_table`. Mutations
(`mutations_sudo.py`): a background or Monitor deny put back, and
pre_bash.sh sending every Monitor call to Python again, each make those
tests fail. Added: `ancestry.claude_ancestor` (above), with
`test_ancestry_trees::test_claude_ancestor_*` on faked process tables and
11 mutations; the Workflow journal exception (`paths.is_transcript`), with
`test_hookbash_private::test_workflow_journals_are_readable_from_bash_too`.

### Review round 5 (2026-10-19)

| finding | fix | tests |
|---|---|---|
| (MEDIUM) `gate secret` refused in the user's own terminal after a shell or tmux upgrade on macOS, saying it was "from Claude Code" (`proc_pidpath` reads nothing for a deleted or replaced executable); this doc said every macOS path is readable | `claude_ancestor` keeps walking above an unreadable process of the user's own (still `UNREADABLE` at the top, unless Claude Code is found further up); `gate_setup.CANT_TELL` for `gate secret` and transfer's terminal path, audited | `test_ancestry_trees::test_claude_ancestor_refuses_a_chain_it_cant_read`, `test_ux_gate_setup::test_secret_refuses_under_a_claude_code_ancestor`, `test_ux_gate_setup::test_secret_under_a_shell_whose_executable_was_deleted_says_what_to_do` (a real deleted shell: macOS message, Linux reaches the terminal check), `test_transfer_roundtrip::test_no_screen_terminal_path_with_a_tree_it_cant_read_tells_the_user_what_to_do`; 2 new and 2 updated mutations here, 4 new and 3 updated in `mutations_ux.py` |
| (MEDIUM) Claude could start `gate secret` (or the no-screen export/import/copy-to) in the desktop app's Terminal panel, which the process-tree check doesn't see | `_deny_gate_user`: `gate secret` denied for every tool (wrappers, shell strings, eval, loops, `find -exec`, unparseable commands); `gate export|import|copy-to` denied in the panel | `test_hookbash_local::test_gate_secret_is_denied_in_every_tool_and_terminal_flows_in_the_panel`, table rows; 6 mutations |

### Checkpoint jobs (2026-10-19)

checkpoint's `job_start` (`hooks_bash.JOB_TOOL` =
`mcp__plugin_check_jobs__job_start`) starts `command` (a shell string) or
`argv` (shlex-joined) with `/bin/sh -c` as a detached job of checkpoint's
MCP server, with the session's environment, plus env.sh when checkpoint
applies it (envfile: a no-op once `$DATA/bin` is gone). It used to bypass
the gateway entirely.

| change | how | tests / mutations |
|---|---|---|
| job_start reaches the approval hook | hooks.json: the Bash matcher is `Bash\|Monitor\|mcp__terminal__run_in_terminal\|mcp__plugin_check_jobs__job_start` → `pre_bash.sh` (same word list) → `launch.sh hook-bash` | `test_hookbash_jobs::test_hooks_json_sends_job_start_to_the_bash_prefilter`, `…prefilter_*` (no Python for ordinary jobs, median well under 0.5 s; trigger words in `command` and `argv` reach Python); mutation |
| Bash's denies apply | `main` → `_main_job`: each of `command` and `shlex.join(argv)` (both if both come) through `_decide` (the GIT_TRACE_REDACT raw check, then `_judge` with `in_job=True`); relative words from the job's `cwd` or the session's cwd / `CLAUDE_PROJECT_DIR` candidates (`_job_cwds`, `_deny_sensitive(more_cwds=)`) | `test_hookbash_jobs::test_job_start_decision_table_command_and_argv_in_every_mode`, `…every_bash_row_is_a_deny_or_no_decision_for_a_job` (the whole Bash table), `…the_jobs_own_folder_counts_*`; mutations |
| "ask" denied | `_ask(…, in_job=True)` denies (audited) with `gateway: a job can't use the "ask" right for ssh on HOST (nobody can be asked while it runs); run it with the Bash tool as its own command, or ask the user to set it to true.`; scp/sftp/rsync on "ask" get the same (not `_deny_transfer_ask`) | `…the_ask_deny_names_the_rights_*`, `…localhost_sudo_ask_in_a_job_is_denied`; mutation |
| gate export/import/copy-to denied | `_deny_gate_user(…, in_job)` → `_deny_gate_terminal(sub, in_job=True)` ("as a job": no terminal for the one-time code; a job outliving Claude's tree escapes the Claude-ancestor check) | decision table rows; mutation |
| never allow, never ask | `_judge` returns None before step 5 for a job; `_main_job` passes only a deny, whatever `_decide` says | `…a_job_never_gets_allow_or_ask` (both layers); 2 mutations |
| stand-ins under a job | `ancestry.is_direct` accepts the real tree (runner → `sh -c WRAPPER checkpoint-job-ID CMD EXITFILE ENVFILE STATUSFILE` → `sh -c CMD` → stand-in, with or without `CLAUDE_PID`); `typed_by_claude` refuses it, and now also when `CLAUDE_PID` names the runner itself (culprit "checkpoint") | `test_ancestry_trees::test_a_real_checkpoint_job_tree_is_direct_but_never_typed`, `…refuses_the_checkpoint_runner_even_as_claude_pid`, `test_sudo_standin::test_sudo_in_a_checkpoint_job_gets_the_password_but_never_an_ask_right` (harness_sudo `checkpoint_job`, `run_sudo_in_checkpoint_job`, the `checkpoint-job*` shapes); 2 mutations |

### Integration lows (2026-10-19)

| finding | fix | tests / mutations |
|---|---|---|
| (LOW) an "ask" right reached inside a job (a script the hook can't read) was refused by the ssh/sudo stand-in with "run it as its own command so Claude Code can ask you", which led Claude to start another job (denied by the hook) | `typed_by_claude` names the culprit `checkpoint` when the job runner is anywhere above a refusal (`_under_checkpoint_runner`); `ssh._ask_refusal` and `sudo.main` then use `consent.job_ask_message` (shared with the hook's `_ask(in_job=True)`; `consent.ask_phrase` names the right) | `test_ancestry_trees::test_a_real_checkpoint_job_tree_is_direct_but_never_typed` (every job shape → "checkpoint"; lookalikes, scripts, `sh -c`, no CLAUDE_PID → not), `test_sudo_standin::test_sudo_in_a_checkpoint_job_gets_the_password_but_never_an_ask_right` (exact wording, audit; outside a job the Bash wording), `test_ssh_ask::test_ask_inside_a_checkpoint_job_gets_the_job_wording` (ssh and remote sudo, with and without CLAUDE_PID, `sh -c CMD` kept or exec'd); 4 mutations here, 1 in `mutations_ssh.py` |
| (LOW) the tests ran jobs with checkpoint's old two-argument wrapper | `harness_sudo.CHECKPOINT_WRAPPER`: checkpoint's current `jobs.WRAPPER`, pinned (source and date in a comment; no import across repos); `checkpoint_job(envfile=...)` passes env.sh as checkpoint does and reports the status file | `test_envfile::test_checkpoint_jobs_apply_env_sh_silently` (`applied`, empty stderr: refuse and mine, with and without `$DATA/bin`, /bin/sh and dash; a noisy env file → `failed`), `test_envfile::test_a_checkpoint_job_sourcing_env_sh_finds_the_stand_ins` (through the runner); mutation in `mutation_check.py` (env.sh writing to stderr) |
| (LOW, follow-up) a caller with no culprit to name (`?`: no `CLAUDE_PID`, the walk reached init, as for a job still running after its session ended) was "sudo started by ? got no password" here and "ssh started by a script" in the ssh stand-in | `ancestry.UNTRACED` / `UNTRACED_WHO`: local sudo (`sudo.not_direct_who`), ssh and remote sudo (`ssh._direct`), the account CLIs and asiml all say "a program the gateway can't trace back to Claude (such as a job still running after its session ended)" | `test_sudo_standin::test_not_direct_untraced_caller_is_named_as_such` (a real tree re-parented away from the test, as an orphaned job is), `test_ssh_exec::test_ssh_exec_scripts_and_ancestry` (ssh and remote sudo), `test_accounts_clis::test_gh_not_direct_refused_unless_scripts`, `test_accounts_asiml::test_asiml_not_direct_refused_unless_scripts`; wording, no mutation |

What `job_tail`, `job_status` and `job_stop` return passes the output hooks
like Bash output (integration review; docs/dev/modules/ux.md, "Checkpoint job
results"). Known limit: a `job_stop` that fails (`stop_failed`, an MCP error
result with the last log lines) only gets the PostToolUseFailure warning,
like a failed Bash command.

### PLAN-v4 phase 7: sudo without blanket NOPASSWD (2026-10-20)

| requirement | how | tests / mutations |
|---|---|---|
| no blanket NOPASSWD advice anywhere | the passwordless installer (local and remote, its root script, gate check's choice that offered it, the sudoers test overrides) is removed; every message and doc that recommended a sudoers rule is reworded | `test_sudo_nopasswd::test_no_blanket_passwordless_sudo_advice_anywhere` (scans src, hooks, skills, commands, README, docs/dev/modules, CAPABILITIES); `test_gate_check_offers_to_store_or_ask_and_never_a_sudoers_rule` |
| passwordless sudo only when already configured | `probe_nopasswd` (`sudo -n true`): when it works, nothing is stored or asked; gate check skips the step | `test_passwordless_sudo_already_configured_is_used_and_nothing_is_asked` |
| per-call password via the dialog, remember or not | gate check offers "Store the sudo password" (`SUDO_STORE`) or "Ask me each time a command needs it" (`SUDO_ASK`, `vault.sudo_choice` = `ask`); a command's sudo dialog has Remember it, ticked (unticked: used for that command, never stored); a stored password is kept as it is | `test_gate_check_store_choice_is_remembered`, `test_a_stored_password_is_used_as_it_is_without_a_choice`, `test_gate_check_remote_offers_store_or_ask`; `test_sudo_standin::test_missing_password_pop_up_stores_it_and_stale_opens_one_reentry` |
| a sudoers that wants a terminal (requiretty, use_pty) | sudo's own words (`NEEDS_TTY`) after a relayed password → `NEEDS_TTY_MSG`: run it in a gateway terminal (`terminal_open` + `terminal_send`), where sudo has a tty and its prompt opens the credential dialog (terminals.md) | `test_a_sudoers_that_wants_a_terminal_points_to_a_gateway_terminal` |
| the target identity visible before elevation | the approval hook adds a `systemMessage` to an allow or ask decision: `gateway: sudo runs as USER on this machine (user@host)` / `on NAME (user@address)`, USER from sudo's `-u`/`--user` (else root; anything that isn't a plain name or `#uid` is "another user"); never on the command's own output | `test_policy::test_the_target_of_sudo_is_named_before_it_runs`; mutation "the elevation notice always says root" |
| elevation policy | `_rights_now` applies `policy.decide(eff, "elevation")` (localhost `sudo`, `[hosts.localhost.policy] elevation`, `[policy] elevation`); remote sudo the same in `ssh._host` (with exec's restrictions) | `test_sudo_nopasswd::test_elevation_policy_refuses_sudo_with_its_rule_and_the_target_is_named`, `test_policy::test_remote_sudo_follows_the_elevation_policy`; mutations in `mutations_policy.py` |

Gateway 0.8 and earlier could install `/etc/sudoers.d/` files named after the
gateway; nothing removes them automatically (the README's uninstall section
says to delete such a file and check the rest with `sudo visudo -c`).
