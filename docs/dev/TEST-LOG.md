> Developer documentation: the gateway's run diaries and per-phase status
> notes up to 0.9.1, moved here verbatim from CLAUDE.md (only paths under
> docs/ were updated to docs/dev/). How to run the tests:
> [TESTING.md](TESTING.md). What each release changed:
> [CHANGELOG.md](../../CHANGELOG.md).

# Test and status log

Newest first within each section. "Last full run" and "Before that" are the
notes each change left when it landed; the status notes say what each phase
and review round did and what was left unverified. 0.10.0 isn't in here yet:
its verification is pending ([TESTING.md](TESTING.md), "0.10.0
verification: pending").

## Run diaries (to 0.9.1, 2026-10-21)

Last full run (2026-10-21, final-gw, plugin 0.9.1: a later verifier low, a
job the drain resumed with the env's tmux gone still said suspended;
DECISIONS "Verifier lows after the re-fix", its last line): 1231 passed, 0
failed on macOS arm64 (`pixi run --locked test`, 374.4 s at 4 at a time, pixi
0.81.0, GW_TEST_TMP in scratch; `claude plugin test .` 118 pass inside
test_mod; new: 1 test in test_terminals, failing with the fix removed; the
older drain test's sleeps now carry a per-run word and it waits for
`daemon.draining`). Mutations: 1063 in all (new: 1 in mutations_terminals.py);
`tests/run_mutations.py mutations_terminals.py` killed 83 of 83 (406 s); the
other files weren't re-run (unchanged since 1062 of 1062). Live on macOS
(Claude Code 2.1.301, tests/tui, scratch configs, the fake API):
`tests/acceptance_install.py` default parts 50 of 50 (87 s; gate 0.9.1,
check 0.7.3); its spaced part's wait after a submit, and bare sleeps after a
submit in acceptance_terminals.py and acceptance_managed.py, now pump the
pty (Claude Code writes to it synchronously). Then on macOS
`acceptance_terminals` 73 of 73 (at the --tmp length that once glued an
exactly filled line) and `acceptance_managed` 38 of 38. On the Debian 13
arm64 VM (Claude Code 2.1.304, this tree with check 0.7.3 at dbea426): 1231
passed, 0 failed; `acceptance_install` default parts 50 of 50, `--only
vmplain` 14 of 14, `--only vmdrain` 30 of 30, `acceptance_managed` 38 of 38,
`acceptance_terminals` 73 of 73. Not re-run on this tree: dialogs,
canaries, native UI and remote (last green at 1786e51 or earlier), the
headless e2e suite.
Before that (2026-10-21, fix2-gateway, plugin 0.9.1: a verifier's four lows
after the re-fix; DECISIONS "Verifier lows after the re-fix"): 1230 passed, 0
failed on macOS arm64 (`pixi run --locked test`, 369.7 s at 4 at a time, pixi
0.81.0, GW_TEST_TMP in scratch; `claude plugin test .` 118 pass inside
test_mod; new: 4 tests in test_terminals, 1 in test_remote, each failing on
HEAD's code first). The run before it failed one new test on a race of its
own (it read `daemon.draining` as soon as /health said draining, which comes
first; the tests now wait for the event and the drain log, and their sleeps
carry a per-run word, since parallel runs of the same test saw each other's
processes). Mutations: 1062 in all (new: 7 in mutations_terminals.py, 5 in
mutations_remote.py; the wrap-boundary mutation now removes `mask_rows`; two
older snippets the change moved were updated: the log rotation in
mutations_daemon.py, the pause's suspend in mutations_terminals.py); the
all-files run (17 min 13 s at 3 at a time) killed 1060, the two moved
snippets were fixed and those files re-run whole: 86 of 86 and 82 of 82, so
1062 of 1062. Live on macOS (Claude Code 2.1.301, tests/tui, scratch configs,
the fake API, telemetry behind the record-only proxy):
`tests/acceptance_terminals.py` 73 of 73 (128 s), and 73 of 73 again with a
--tmp 15 characters longer, so that the prompt plus `echo "PID""0=$$ START"`
is exactly 220 characters, twice the 110-column pane: the verifier's case,
which failed 3 checks before. Not re-run: anything on the VM (this task
didn't use it: the suite on Linux, acceptance_install's vmdrain, the remote
acceptance), the other TUI acceptances, the headless e2e suite.
Before that (2026-10-21, refix-gw, plugin 0.9.1: the verifier's three lows
in the GitHub install fixes; DECISIONS "Re-fix of the GitHub install fixes"):
1225 passed, 0 failed on macOS arm64 (`pixi run --locked test`, 357.1 s at 4
at a time, pixi 0.81.0, GW_TEST_TMP in scratch; `claude plugin test .` 118
pass inside test_mod) and 1225 passed, 0 failed on the Debian 13 arm64 VM
(219.3 s; the working tree's `git ls-files -co --exclude-standard` without
logs/ and quarantine/ under `~/gwrefix`, `pixi install --locked`, pixi 0.82.0,
Claude Code 2.1.304, dash as /bin/sh, procps' ps, GW_TEST_TMP under /tmp; the
three new tests included: the watchdog's `kill -0` and `ps -o stat= -o
lstart=` under dash); on macOS again on the final tree (the pid file's
write-failure path, three mutation snippets and docs changed since): 1225
passed, 0 failed (350.6 s). Mutations: 1050 in all (new: 9 in
mutations_terminals.py; three older snippets the change moved were updated:
the watchdog's gated check, the ticker's broker tick, the pause route's
replay); the all-files run (3 at a time) killed 1048, the two it couldn't
place (moved snippets in mutations_daemon.py and mutations_policy.py) were
fixed and those files re-run: 86 of 86 and 99 of 99 killed, so 1050 of 1050. The new mutations were also run on the VM
(mutations_terminals.py `-k` watchdog, time zone, pid file, draining gated,
sweep, swept: 19 of 19 killed). The VM was restored (`./vm.sh clean`,
stopped). Not re-run: the TUI acceptances (acceptance_install's vmdrain
included), the remote acceptance, the headless e2e suite.
Before that (2026-10-21, gw-fix, plugin 0.9.1: the GitHub install test's
findings; DECISIONS "GitHub install fixes"): 1222 passed, 0 failed on macOS
arm64 (`pixi run --locked test`, 392.7 s at 4 at a time, pixi 0.81.0,
GW_TEST_TMP in scratch; `claude plugin test .` 118 pass inside test_mod;
the first run failed 15 tests in test_session, test_migrate, test_harness_run
and test_gate: the harness built v2 vaults from `git show main:` vault.py,
which is v3 since 0.9.0 is on main, so the v2 fixture is now its source) and
1222 passed, 0 failed on the Debian 13 arm64 VM (217.1 s; the working tree's
files under `~/gwfix`, `pixi install --locked`, pixi 0.82.0, Claude Code
2.1.304, GW_TEST_TMP under /tmp; the watchdog's `ps -A -o ppid= -o tty=` and
Debian's bash with SSH_SOURCE_BASHRC included); on macOS again on the final
tree (docs and acceptance scripts changed since): 1222 passed, 0 failed
(357.8 s). Mutations: 1041 of 1041
killed (the all-files run, 18 min 4 s at 3 at a time, beside the VM work;
new: 3 in mutations_daemon.py, 11 in mutations_terminals.py, 3 in
mutations_managed.py; four older snippets the change moved were updated).
Live on the VM (`tests/acceptance_install.py --only vmdrain`, both plugins
installed plainly from git snapshots of the working trees, gateway 0.9.1 and
checkpoint 0.7.3, through tests/tui's install route; `ACCEPTANCE_DISPOSABLE_VM=1`,
a scratch git first on PATH for the harness's git server): 30 of 30 in 137 s.
A warm session started a gateway job and terminal; a plain `claude plugin
uninstall` of both: contract.json gone 24.6 s later (the 30 s tick) while
gated, its tmux server and gw-watch and the job ran on; once the job and the
terminal ended, gated, the tmux server (run from the deleted env: gated
watched the panes' processes and stopped the server by its pid) and gw-watch
were gone 25.0 s later, the data folder not made again. With `--keep-data`:
contract.json gone after 29.1 s, everything gone 25.5 s after the job ended,
the data folder kept. The planted `~/.bashrc` (Claude Code started without
`SHLVL`, as the harness does) didn't run for the Bash command (its shell's
pid not in the rc's log; one line from Claude Code's own snapshot shell at
SHLVL 2), and setup showed `⚠ gate: setting up…`, then the `ready` toast,
never `⚠ gate: ready`. The VM was restored (`./vm.sh clean`, stopped). Not
re-run: the other TUI acceptances (acceptance_install's other parts check the
toast now; acceptance_managed counts SHLVL as the mod's), the remote
acceptance, the headless e2e suite.
Before that (2026-10-21, gw-reruns: the skill's checkpoint-jobs text,
plugin.json's description, SessionStart's job line, and an "ask" right no
longer honoured inside a gateway terminal or job; DECISIONS "Re-runs and
shipped text"): 1217 passed, 0 failed on macOS arm64 (`pixi run --locked
test`, 346.0 s at 4 at a time, pixi 0.81.0, GW_TEST_TMP in scratch; `claude
plugin test .` 108 pass) and 1217 passed, 0 failed on the Debian 13 arm64 VM
(216.7 s; a fresh copy of `git ls-files -co --exclude-standard` without
logs/ and quarantine/, `pixi install --locked`, pixi 0.82.0, Claude Code
2.1.304, dash as /bin/sh, GW_TEST_TMP under /tmp; no rsync there, so its
parts skipped); the same tree before the pane fix: 1214 of 1214 on both.
Mutations: 1024 of 1024 killed (the all-files run, 15 min 51 s at 3 at a
time; 5 new in mutations_sudo.py and mutations_ssh.py). Live:
`tests/acceptance_remote.py` 39 of 39 against the VM (42 s; tester's
~/.bashrc and authorized_keys byte-identical afterwards), and on the VM
`tests/acceptance_install.py` 50 of 50 (its update step included: the
checkpoint update with a changed lock kept recording on the old runtime
while the new one built, no "setting up" shown) and its vmplain part 14 of
14. The other TUI acceptances on that tree (gw-accept, macOS arm64, Claude
Code 2.1.301, scratch configs, the fake API, telemetry on behind the
record-only proxy where the script does it): dialogs 62 of 62, canaries 71
of 71, managed 38 of 38, native UI 41 of 41, terminals 63 of 63; then
terminals 73 of 73 with its new askright section (a script the agent runs in
a gateway terminal: an `"ask"` ssh right and an `"ask"` sudo right refused
with the pane's wording, no connection made and sudo never run, while its
`true` sudo right runs; both refusals audited). On a scratch copy with the
fix reverted (`if _exe_name(claude) in SHELLS:` made `if False:`) that
section failed 5 of its 10 checks (the script's ssh connected, its "ask"
sudo ran). The suite again after the script change: 1217 passed, 0 failed
(359.3 s at 4 at a time; GW_TEST_TMP in scratch). Not re-run: the headless
e2e suite.
Before that (2026-10-21, after the acceptance fixes, plugin 0.9.0, macOS
arm64, pixi 0.81.0, Claude Code 2.1.301; DECISIONS "Acceptance fixes"): 1214
tests passed, 0 failed on the final tree (`pixi run --locked test`, 340.3 s at
4 at a time; GW_TEST_TMP in scratch; `claude plugin test .`: 108 pass, 0 fail
inside test_mod; three earlier full runs while fixing: 1211 of 1211, 1212 of
1212, and 1212 of 1213, whose one failure, `test_jobs_report_exit_codes_...`,
was a job reporting `job.state` before `job.started`: fixed, with a test of
its own). Mutations: 1019 of 1019 killed (mutation_check 76, accounts 58,
daemon 83, dialogs 78, e2e 26, managed 57, packaging 42, policy 99, remote 58,
ssh 97, sudo 157, terminals 55, ux 133): the all-files run (15 min 47 s at 3
at a time) killed every mutation but found one ux snippet the fix had moved;
after updating it the ux and dialogs files ran again whole on the final
popup.py (133 and 78 killed), and the terminals file after the last terminals
change (55 killed). The prompt-box guard's `.catch` has no mutation: the test
kit can't make that hook fail or re-enter (stated in mutations_dialogs.py).
The live acceptance runs (TUI harness, scratch configs, the fake API,
telemetry behind the record-only proxy where the script does it): macOS with
2.1.301 dialogs 62 of 62, canaries 71 of 71, install 50 of 50 (firstbash: the
first Bash after "gate: ready" ran at once; the daemon left 0.7 s after
`claude plugin uninstall`), native UI 41 of 41 (the localhost workspace, its
consent and sudo choice, tamper: the retry reports the damaged file),
terminals 63 of 63, managed 38 of 38, the TUI harness self-test section g 20
of 20 (the e2e install under umask 002); the Debian 13 arm64 VM with Claude
Code 2.1.304 (everything under `~/fix-acc-gw` and `/var/tmp/fix-acc-gw`,
Debian's own umask 002, git from `pixi global install git` in a scratch
PIXI_HOME, beside another agent's runs) dialogs 62 of 62 (twice), canaries 71
of 71, native UI 44 of 44 (with import-remote of the macOS export), managed 38
of 38, install 50 of 50, terminals 63 of 63. Before the fixes the VM had
failed 6 dialogs checks and the canaries' guard check every run, and 4 managed
checks. Not re-run: `tests/acceptance_remote.py` (it edits the shared VM
user's authorized_keys and ~/.bashrc; `--vm-dir` only renames its paths,
checked by hand), the install script's vmplain part (it uses the VM user's own
~/.config/gateway), the headless e2e suite (real model API), checkpoint's
suite (only its tests/tui copy changed, kept identical to this one, which its
suite doesn't import).
Before that (2026-10-21, after the phase 7 review fixes, plugin 0.9.0,
macOS arm64, pixi 0.81.0, Claude Code 2.1.301): 1203 tests passed, 0 failed
on the final tree (`pixi run --locked test`, 340.0 s at 4 at a time;
GW_TEST_TMP in scratch; `claude plugin test .`: 95 pass, 0 fail inside
test_mod; three earlier full runs while fixing, 1203 of 1203 each in the
end). Mutations: the all-files run killed 1000 of 1000 (mutation_check 76,
accounts 58, daemon 76, dialogs 70, e2e 26, managed 57, packaging 42, policy
97, remote 58, ssh 97, sudo 157, terminals 53, ux 133); the policy file's
first run had one survivor (protected args with paths on the line, killed
by test lines of their own). Two later changes (the hook's text scan reads
a `$(...)` program word whole; a transfer path that starts with `-` is exec)
added two policy mutations; the policy (99 of 99) and ssh (97 of 97) files
ran again on the final tree, and sudo (157 of 157) and managed (57 of 57)
after the hook change (the last change touched only ssh_args), all killed
(the final tree has 1002 mutations). The verifier's probes
(workspace removal and rename, `rsync --remove-source-files`, a program
named rsync by path, multi-path rsync and `scp -f`, the hook's alternate
routes in auto, default and bypass modes) all refuse now. On Linux (the
Debian 13 arm64 VM, pixi 0.82.0, the repository's files under
`~/fix-gw-policy`, removed after, `pixi install --locked`; the tree before
the `-` path change): 1203 passed, 0 failed (204.3 s; GW_TEST_TMP under
/tmp; the first try with it under the VM's home failed 9 tests on the known
test-base artifacts: web's save_to rules and the e2e marker's temp rule);
the VM has no rsync, so the rsync parts of the new tests skipped there.
Checkpoint's suite (unchanged by this work; its CONTRACT-v1 copy is still
byte-identical): 915 passed, 0 failed (`pixi run test`, TMPDIR in scratch).
Before that (2026-10-20, after PLAN-v4 phase 7, plugin 0.9.0, macOS arm64,
pixi 0.81.0): 1192 tests passed, 0 failed (`pixi run --locked test`, 337.4 s
at 4 at a time; GW_TEST_TMP in scratch; the run before, under a concurrent VM
run, failed one phase 6 test, `test_typed_text_whose_answer_is_lost_...`, whose
next send raced the poller's reconnect: the test now waits for the terminal
to be back between its lossy steps); 970 of 970 mutations killed
(mutation_check 76, accounts 58, daemon 76, dialogs 70, e2e 26, managed 57,
packaging 42, policy 67, remote 58, ssh 97, sudo 157, terminals 53, ux 133;
the first all-files run found 7 survivors or moved snippets, all fixed: four
snippets the phase moved, a remote "ask" check and the `-o` value check that
the new policy layer now shadows (each got a test of its own), and the stored
sudo password's second layer); `claude plugin test .`: 95 pass, 0 fail, and
`claude plugin validate` (plugin and marketplace) through `test_mod`. On
Linux (the Debian 13 arm64 VM, pixi 0.82.0, Claude Code 2.1.304, the
repository's files under `~/gw-policy`, `pixi install --locked`): the whole
suite 1192 passed, 0 failed (199.2 s; `claude plugin test .` 95 pass there
too); an earlier VM run found the advice scan matching removed function names
in the new module-doc text (reworded). Run under the Mac's mutation load, the
VM's `test_remote` once failed a phase 6 timing test
(`test_a_failed_list_panes_is_a_blip_...`); unloaded it passed. Not re-run:
the e2e and TUI acceptances, `tests/acceptance_remote.py`.
Before that (2026-10-20, after the phase 6 review fixes, plugin 0.8.0, Claude
Code 2.1.301, pixi 0.81.0, macOS arm64): 1143 tests passed, 0 failed (`pixi run
--locked test`, 413.9 s at 4 at a time; GW_TEST_TMP in scratch; the two runs
before found two old test races, fixed: test_broker's long-running reader read
its answer file before the driver had written it, and test_terminals' sudo test
waited for "SUDO-", which its own typed line showed); 910 of 910 mutations
killed (mutation_check 76, accounts 58, daemon 76, dialogs 72, e2e 26, managed
57, packaging 42, remote 58, ssh 97, sudo 162, terminals 53, ux 133; 16.5 min at
3 at a time; two terminals snippets the fixes moved were updated). The phase 6
claim "890 of 890" didn't hold reliably: the remote mutation "a changed host key
is trusted without asking" survived about half the runs (ssh's own strict check
asked whenever the address choice's scan saw no key); it now has a direct test
and was killed 5 of 5 times (with the declined-key and ssh-refusal mutations).
The start-file claim and the foreground-group listing were also run on the
Debian 13 VM (bash 5.2, dash, GNU mv 9.7, procps); `claude plugin validate` and
`claude plugin test .` passed inside test_mod. Not re-run: the e2e and TUI
acceptances, `tests/acceptance_remote.py` (it works under ~/gw-remote in the
shared VM), the whole suite on Linux.
Before that (2026-10-20, after PLAN-v4 phase 6, plugin 0.8.0, Claude Code
2.1.301, pixi 0.81.0, macOS arm64): 1133 tests passed, 0 failed (`pixi run
--locked test`, 260.3 s at 4 at a time; GW_TEST_TMP in scratch); 890 of 890
mutations killed (mutation_check 76, accounts 58, daemon 76, dialogs 72, e2e
26, managed 57, packaging 42, remote 38, ssh 97, sudo 162, terminals 53, ux
133; four terminals snippets the phase moved were updated and rerun);
`claude plugin test .`: 90 pass, 0 fail; `claude plugin validate` (plugin
and marketplace) passed (both through `test_mod`);
`tests/acceptance_remote.py`: 39 of 39 (60 s; the Debian 13 arm64 VM through
127.0.0.1:2222 and a private sshd in it, a local sshd, real pixi-pack
artifacts for linux-aarch64 and osx-arm64; run twice, both 39 of 39). The
host-key tests were also run 4-5 at a time beside a loaded suite (12 of 12
after the cut-off-answer fix; 2 of 4 failed before it). On Linux (the Debian
13.7 arm64 VM, pixi 0.82.0, the repository's files, `pixi install --locked`):
the whole suite 1133 passed, 0 failed (171.4 s; GW_TEST_TMP under /tmp; the
remote tests' local sshd there is a linux-aarch64 host: GNU `stty -g`,
procps); an earlier Linux run found the read-before-capture race (1128 of
1129), fixed and stress-tested (4 parallel runs of the password test, all
passing).
Before that (2026-10-20, after PLAN-v4 phase 5, plugin 0.8.0, Claude Code
2.1.301, pixi 0.81.0, macOS arm64): 1091 tests passed, 0 failed (`pixi run
--locked test`, 200.2 s at 4 at a time; GW_TEST_TMP in scratch); 843 of 843
mutations killed (mutation_check 76, accounts 58, daemon 76, dialogs 72, e2e
26, managed 57, packaging 42, ssh 97, sudo 162, terminals 44, ux 133; four
older snippets the phase moved (planes' ancestor walk, the dialog post's
dedupe, hooks_bash's job tool line, hooks.json's matcher) were updated and
rerun); `claude plugin test .`: 90 pass, 0 fail; `claude plugin validate`
(plugin and marketplace) passed; `tests/acceptance_terminals.py`: 63 of 63
(103 s; telemetry on behind the record-only proxy; the earlier runs found the
space key, the click focus and the header truncation, fixed). On Linux (the
Debian 13.7 arm64 VM, pixi 0.82.0, the repository's files, `pixi install
--locked`; no system tmux, the env's tmux 3.8): the whole suite 1091 passed, 0
failed (with GW_TEST_TMP under /tmp; a test base named /tmp/gw-* is taken for
the run dir by the file guard's tests, and one under $HOME fails the e2e
marker's temp rule: test-base artifacts), and a probe with the real sudo of
the VM's test user, by absolute path in a gateway terminal: the dialog named
"sudo", the sealed test password reached the tty, sudo -v succeeded, the
value in no gated file, tool result or tmux argv.
Before that (2026-10-20, after the phase 4 review fixes, Claude Code
2.1.301, pixi 0.81.0, macOS arm64): 1057 tests passed, 0 failed (`pixi run
--locked test`, 191.9 s at 4 at a time; GW_TEST_TMP in scratch); 799 of 799
mutations killed (mutation_check 76, accounts 58, daemon 76, dialogs 72, e2e
26, managed 57, packaging 42, ssh 97, sudo 162, ux 133; 10 min 43 s);
`claude plugin test .`: 79 pass, 0 fail; `claude plugin validate` (plugin
and marketplace) passed; `tests/acceptance_managed.py`: 38 of 38 (291 s;
`GW_MANAGED_DIR` now in the curated set and `CLAUDE_CODE_CLIENT_KEY_PASSPHRASE`
among the credentials in Claude Code's environment); a real `claude -p`
(scratch config, the harness's fake API, no plugin) started with this
session's three variables ran its Bash in the managed bash, and without
`GW_MANAGED_DIR` got the new 75. On Linux (the Debian 13.7 arm64 VM, pixi
0.82.0, the repository's files, `pixi install --locked`): 8 full runs with
the fixed hold proxy, 7 at 1057 passed, 0 failed, and one with 1055 passed,
2 failed, both from the VM's clock stepping forward 4876 s mid-run (that
run took "5002 s"; `test_packaging`'s 30-minute lock age and a dialog
session's start time; the ssh tests passed), runs 1-5 while the Mac ran the
suite and the mutations, the condition under which the old proxy failed 4
of 16 runs.
Before that (2026-10-20, after PLAN-v4 phase 4 and the Linux fixes, Claude
Code 2.1.301, pixi 0.81.0, macOS arm64): 1052 tests passed, 0 failed (`pixi
run --locked test`, 186 s at 4 at a time; GW_TEST_TMP in scratch); 786 of 786
mutations killed (mutation_check 76, accounts 58, daemon 76, dialogs 72, e2e
26, managed 44, packaging 42, ssh 97, sudo 162, ux 133; the managed file again
after a snippet the code had moved); `claude plugin test .`: 74 pass, 0
fail; `claude plugin validate` (plugin and marketplace) passed;
`tests/acceptance_managed.py`: 38 of 38 (290 s; the scripted session, the
permission and cancel sessions, `-p`, and the gateway without its mod, each
against a baseline config without the gateway); on Linux (the Debian 13
arm64 VM, pixi 0.82.0, Claude Code 2.1.304, the repository's files, `pixi
install --locked`) the whole suite: 1052 passed, 0 failed (also 1051 of 1051
twice before the last test was added), gate-sh's tests with dash as `/bin/sh`
and the VM's bash. Not run: the headless e2e suite (real model API) and the
dialogs acceptance (phase 3's, unchanged code paths).
Before that (2026-10-20, after the phase 3 review fixes, Claude Code
2.1.301, pixi 0.81.0, macOS arm64): 1017 tests passed, 0 failed (`pixi run
--locked test`, 176.8 s at 4 at a time; GW_TEST_TMP in scratch); 739 of
739 mutations killed (mutation_check 76, accounts 56, daemon 76, dialogs
72, e2e 26, packaging 42, ssh 96, sudo 162, ux 133; the all-files run, 8 min
45 s at 4 at a time, found four sudo/ux snippets the refactor had moved,
updated, then the sudo and ux files again whole: 6 min 46 s at 2 at a
time); `claude plugin test .`: 58 pass, 0 fail; `tests/acceptance_dialogs.py`
three times: 61 of 61 from a cold pixi cache (the env, 388 MB, built before
the session, outside the proxy), then 61 of 62 (under a parallel mutation
run the fullscreen guard's composer check saw one character in the prompt
box at its single look 0.6 s after typing; the scans for that canary in
transcripts, requests and telemetry passed; the check now looks again for up
to 3 s, and says whether what it saw is a prefix or the tail of the typed
canary), then 62 of 62 (170 s, under a parallel mutation run; 8 s
prebuild); on Linux (the Debian 13 arm64 VM, pixi 0.82.0, a copy of the
plugin folder without the user's data) `test_dialogs` + `test_sudo_standin`
+ `test_broker` + `test_daemon` + `test_ux_gate_setup` 161 passed, 0 failed.
The TUI harness wasn't changed (not re-run). Before that (2026-10-20, after
PLAN-v4 phase 3): 1007 tests passed, 0 failed (`pixi run --locked test`,
171.7 s at 4 at a time; GW_TEST_TMP in scratch); 720 of 720 mutations killed
(mutation_check 76, accounts 56, daemon 76, dialogs 53, e2e 26, packaging
42, ssh 96, sudo 162, ux 133; 8 min 44 s at 4 at a time); `claude plugin
test .`: 55 pass, 0 fail, and `claude plugin validate` (plugin and
marketplace) through `test_mod`; `tests/acceptance_dialogs.py`: 56 passed,
0 failed (162 s; the run before failed one check, a test bug in reading the
queue line, and the one before that found the stale-key field: DECISIONS
"PLAN-v4 phase 3"); the TUI harness self-test 166 passed (default
sections) and section t 9 passed; on Linux (the Debian 13 arm64 VM, pixi
0.82.0, a copy of the plugin folder without the user's data, `pixi install
--locked`) `test_dialogs` + `test_broker` + `test_daemon` 97 passed, 0
failed. Before that (2026-10-20, after the phase 2 review fixes): 995
tests passed, 0 failed (171.7 s at 4 at a time); 702 of 702
mutations killed (mutation_check 76, accounts 56, daemon 76, e2e 26,
packaging 42, ssh 96, sudo 162, ux 168; 8 min 53 s; the daemon file again
after a last one-line change, 76 of 76); `test_mod` ran `claude plugin
validate` (plugin and marketplace) and `claude plugin test .`; on Linux (the
Debian 13 arm64 VM, pixi 0.82.0, a copy of the plugin folder, `pixi install
--locked`) `test_daemon` + `test_broker` 70 passed, 0 failed. Before that
(2026-10-19, after PLAN-v4 phase 2): 983 tests, 677 of 677 mutations,
`claude plugin test .`: 32 pass, 0 fail. On Linux (the Debian 13 arm64 VM, a
read-only copy of the plugin folder, `pixi install --locked`): `test_daemon`
+ `test_broker` 58 passed, 0 failed; the whole suite 958 passed, 25 failed
(the same 25 fail on the pre-daemon copy; Status, "Not done"). A live
interactive session (TUI harness, scratch config, fake API, e2e install)
checked the mod's registration, `/gate-doctor`'s daemon line, contract.json
and the daemon's exit with the harness's run dir (8 checks passed; the
script's own leftover-process scan matched the script itself). After PLAN-v4
phase 1 (same day): 918 tests, 614 of 614 mutations, `claude plugin test`
21 pass. The e2e suite (`pixi run e2e`) wasn't re-run in phases 1 and 2. Earlier (after the first-SessionStart fixes): `pixi run e2e --only jobs` (with
checkpoint's checkout next to this repo) ran 3 times: 38 passed, 0 failed,
0 not reached each time (no classifier denial; hook-session took 650-740 ms
in each run's first session). The whole ten-scenario `pixi run e2e` last
ran at the integration lows (115 checks passed); the verifier then saw the
`jobs` scenario fail 3 of 3 times on classifier denials, before it got its
project context.

## Status as of 0.9.1 (2026-10-21)

The Status section of CLAUDE.md as it stood at 0.9.1. Two lines in it were
already out of date when it was moved: 0.9.1 was pushed to GitHub and
published, and its install from the GitHub marketplace was tested (the
README's status at 0.9.1 says how; [TESTING.md](TESTING.md) keeps that
table).

0.9.0 is committed on main (a8dd5ec); 0.9.1 (the GitHub install test's
fixes, below) is committed locally on main, not pushed. Phases A (core), B
(sudo, ssh, accounts, ux groups) and C (integration) are done: every phase B
request is settled in `docs/dev/phaseB-requests/RESOLUTION.md`; hooks, MCP and
manifests are wired; the v2 modules, commands and installer are gone (only
`vault_v2.py` stays, for migration). Review round 1 (2026-10-19) is fixed:
"ask" rights only for a command Claude typed, scp/sftp/rsync option
allowlist and local-path rules, gh hosts, az scopes (`docs/dev/DECISIONS.md`,
`docs/dev/modules/sudo.md`). Review round 2 (2026-10-19) is fixed too
(`docs/dev/DECISIONS.md`, "Review round 2"): `#` comments in bashparse, no
secret on a dialog's command line (no generated export passphrase),
PostToolUse masks vault values in every response once a vault exists, az
gives raw tokens only to programs with `scripts = true`, a credential belongs
to the approved name + kind, the gateway's ssh helpers honour the ssh right,
held-back output released after 0.15 s, the Linux askpass parent check, a
narrowing persisted before any vault exists, `form_last_good` kept current,
hooks on an older env while an update builds, and truthful next steps in
the messages. Review round 3 (2026-10-19) is fixed too (`docs/dev/DECISIONS.md`,
"Review round 3"): allow only for bare command names, deny/ask by the
stricter of form and effective right, a PostToolUseFailure hook warning for
a failed command's output (round 3's env-file EXIT trap and Monitor `| gate
scrub` rule were later rolled back, below), subagent transcripts protected,
gate check re-verifies hosts and stops behind a jump host that isn't set up,
the user's agent for "use my own SSH login once" from the session record,
the launcher from the first session, a non-blocking askpass, hf's token
through a file, and clearer next steps (waiting rights, accounts, copy-to,
gate why, catch-alls).
Review round 4 (2026-10-19) is fixed too (`docs/dev/DECISIONS.md`, "Review round
4"): `sudo visudo|vipw|vigr` never allowed; Claude Code's task
notifications pass the prompt hook, which holds back one quoting a stored
value (idle and mid-turn, verified headless; round 4's background `2>&1 |
gate scrub` rule was later rolled back, below); the desktop app's transcript
export denied and its transcript search held back while a code is live; the
sh hooks use the
passwd home; git's `erase` marks the account whose token was rejected; no
claimed pop-up for a rejected token; leak warnings name commands that really
replace the secret; `gate import-ssh` follows `Include` and never proposes a
git server (the form refuses one); gate check asks nothing for a host it
couldn't reach and keeps inside Claude Code's 2-minute Bash timeout; the
launcher speaks to the user in every degraded state; a mid-session
conversion's report comes at the next prompt and says "0.6"; message polish.
Rolled back afterwards (2026-10-19, the lead's decision; `docs/dev/DECISIONS.md`,
"Rolled back"): the gateway must not change how Claude's ordinary commands
behave, so the env file's EXIT trap and the hook rules requiring `| gate
scrub` for Monitor and background commands are gone (`gate scrub` stays,
optional; the PostToolUseFailure warning and the task-notification check
stay); a Workflow run's `journal.jsonl` is readable (exact name and place;
transcripts and subagent transcripts stay denied); `gate secret` and the
terminal export/import/copy-to path also refuse under any Claude Code
ancestor process or a process tree they can't read (the one-time code
stays).
Review round 5 (2026-10-19) is fixed too (`docs/dev/DECISIONS.md`, "Review
round 5"): a process tree `gate secret` can't read gets its own message
(macOS can't read the path of an executable replaced while it runs: shells
and tmux after `brew upgrade` / `port upgrade`), and the walk goes on above
it; the approval hook denies `gate secret` in every tool (the Terminal panel
included) and `gate export|import|copy-to` in the panel; and the per-call
cost: post.sh no longer starts Python for an edit tool's response, the
PostToolUse hook imports only what it needs, and launch.sh passes plain
file-guard paths in sh.

Checkpoint jobs (2026-10-19; `docs/dev/DECISIONS.md`, "Checkpoint jobs"):
checkpoint's `job_start` goes through the Bash approval hook (same matcher
and prefilter): Bash's denies, `gate export|import|copy-to` denied, an
`"ask"` right denied ("a job can't use the "ask" right ..."), never `allow`
or `ask`; env.sh does nothing once `$DATA/bin` is gone (so checkpoint may
source it, also after an uninstall); `typed_by_claude` refuses the
checkpoint runner explicitly; Claude's context mentions jobs when
checkpoint's state folder exists, and the skill and README say how jobs are
treated. Integration review (2026-10-19): a job's `cat notes.txt` came back
raw through `job_tail`; the PostToolUse and PostToolUseFailure matchers now
name `job_tail`, `job_status` and `job_stop` (exact names; no Python
change), so their results are masked like Bash output (a failed `job_stop`,
an MCP error result, gets the PostToolUseFailure warning; probed headless
with a standalone plugin). The same names, patched into a scratch copy's
matchers, were verified live by the integration run (its `leakfix`
session: `job_tail` came back with `***`); a two-plugin `claude -p` run with
this checkout's hooks.json is the integration phase's.
Integration lows (2026-10-19; `docs/dev/DECISIONS.md`, "Integration lows"):
parallel ssh calls to one host share one master (the stand-in holds a
flock on `<run>/cm-%C.lock` while it checks for and starts a master, at
most 5 s for a waiter), so OpenSSH's "ControlSocket ... already exists,
disabling multiplexing" no longer lands in the output; an `"ask"` right
reached inside a job (checkpoint's runner anywhere above the stand-in) gets
the approval hook's job wording from the ssh and sudo stand-ins too
(`consent.job_ask_message`); the tests pin checkpoint's current job wrapper
(`tests/harness_sudo.py` `CHECKPOINT_WRAPPER`, copied 2026-10-19; update it
when checkpoint's changes) and check env.sh applies silently under it; the
e2e suite has an optional `jobs` scenario (two plugins, CHECKPOINT_HOME and
CHECKPOINT_GATEWAY_ENV inside the e2e root, a kill switch on checkpoint's
server environment).
First SessionStart and the e2e jobs scenario (2026-10-19; `docs/dev/DECISIONS.md`,
same title): a new env's first sync SessionStart took 5-13 s (once past
Claude Code's 20 s limit, which dropped the context), because macOS checks
each new binary and library at its first load; `ensure-env` (async) now
loads a new env once (`gateway/warm.py`, `.warm`) and SessionStart no longer
imports popup, urllib or ssl (harness, fresh env: first hook-session 5.5-6.0
s before, 0.56-0.98 s after). launch.sh writes the safe env file (and
missing stand-ins and git reset) before SessionStart's Python, every
SessionStart file is written whole, and one that finishes past the limit
leaves no context record, so the next prompt's hook gives the context. The
`jobs` scenario's session gets a `CLAUDE.md` with the facts (the user's own
test, local sshds, fake secrets, the task), and a job step Claude Code's
classifier denies is reported as "not reached (classifier)", never a pass
or a gateway failure (the gateway never approves a job). A job that
outlives its session gets credentials only from entries with `scripts =
true` (README, skill, context and DECISIONS "Integration lows" say so).
Follow-ups (2026-10-19; DECISIONS "Integration lows"): a call that gives up
on the ControlPath lock reaches the hops it couldn't lock without
multiplexing and keeps its agent until its ssh exits (the holder's master
killed it mid-login: "refused Claude's key"), and only a lock holder kills
its agent early; background Bash isn't a way around a job outliving its
session (the docs said so; removed); the e2e `jobs` scenario judges a
retried step that ran; an untraced caller (`?`) is named in words by every
stand-in.

PLAN-v4 phase 1, packaging and the mod skeleton (2026-10-19; PLAN-v4
matrix rows for section 2, 3 and 13): shipped installs use `pixi install
--locked` (launcher, feature envs, pijul build) and `requires-pixi =
">=0.68.0"` (tested 0.68.0-0.82.0, no upper bound); the build lock records
its owner and pixi child, so a killed build is stale at once and a waiter
takes over (tests kill a fake build half way); while no env can run Python
the Bash hook denies in sh (private folder, transcripts, credential shapes,
curl/wget with a vault; byte-identical to `envfile.degraded_bash_text`; seen
working in a real interactive session and in `claude -p`); Python's bytecode
goes to `$DATA/pycache`, never the plugin folder; `tests/release_check.py`
(`pixi run release-check`) and `test_release`'s every-referenced-file check;
README lifecycle commands, the git prerequisite with the verified `pixi
global install git` route, supported systems and the Windows/WSL statement;
`docs/CAPABILITIES.md`. The mod (`hooks/mod/`) shows the setup status line,
provisions through `$.process.spawn` at session start and serves the
immediate `/gate-doctor` (verified in a real interactive session: status
line `gate: setting up… 0:00` then `gate: ready`, the doctor's report with 0
model requests; and in `claude -p`). New tests: `test_packaging`,
`test_release`, `test_mod` (runs `claude plugin validate` and `claude plugin
test`), `hooks/mod/*.test.ts`; new mutations: `tests/mutations_packaging.py`.

PLAN-v4 phase 2, the daemon and the broker (2026-10-19; PLAN-v4 matrix rows
for sections 4, 11 and 13; docs/dev/modules/daemon.md; DECISIONS "PLAN-v4 phase
2"): `gated` (`src/gateway/daemon/`) listens on `<run>/gated.sock` (HTTP/1.1,
0600), checks every peer by the kernel's credentials (macOS LOCAL_PEERPID +
LOCAL_PEERCRED, Linux SO_PEERCRED; uid first) and sorts it onto a plane (UI:
the registered Claude Code pid itself; agent: a gateway entry point by
executable and argv below a registered session; contract; local; health);
sessions register through the mod (`/ui/register`, from inside Claude Code)
or a gateway hook (`/agent/register`; the new async SessionStart hook
`hook-daemon`), persisted in the run dir; started on demand (mod, hook,
stand-ins with a wrapped key), detached (double fork), single instance
(flock), contract.json written after listening and removed on exit, stale
state after `kill -9` replaced at the next start, idle exit after 30 min
without a live session, exit when its socket is removed, version skew (a
newer plugin restarts an idle older daemon, else reports it); event log
(seq per epoch, bounded ring and JSONL, allowlisted fields) with
`/v1/capabilities`, `/v1/snapshot` (form hosts with `m_` ids) and
`/v1/events` long poll. The broker wraps the vault key with age's scrypt
recipient (`agepass.py`, moved out of transfer.py; verified by unwrapping
before key.txt goes), holds the unlocked identity in memory only, locks it
explicitly (`/ui/vault/lock`, `gate lock`), after `[vault] lock_after`
(default 8h) and on exit, and gives each entry point mode its scoped view
(sentinels for the rest; non-direct callers only `scripts = true` entries),
merging writes. Unwrapped vaults (all of them until phase 3's dialog) keep
the local path; the passphrase is set and unlocked only through test routes.
A locked vault gives one clear refusal (interactive vs headless) from the
stand-ins, the git helper, the http tool, the Bash hook and SessionStart.
`/gate-doctor` and `gate status` show the daemon (running, version, epoch,
uptime, sessions, vault none/unwrapped/locked/unlocked). Verified live in an
interactive session through the TUI harness (scratch config, fake API, e2e
install): the mod's `$.http.fetch` over the socket came from the claude pid
and registered the session (the first try found the native install's
binary, `versions/2.1.301`, refused under the e2e home: fixed, tested,
mutated), `/gate-doctor` showed the daemon, contract.json was written and
the daemon left when the harness removed its run dir. On Linux (the Debian
13 arm64 VM, SO_PEERCRED): `test_daemon` + `test_broker` 58/58. Phase-1
findings fixed: web's local-path rules compare resolved paths with resolved
roots (a symlinked temp root), and testing's guard never stats the real
gateway home (parents resolved, protected paths compared as written; the
e2e-marker test uses a fake real home). New tests: `test_daemon`,
`test_broker` (+ `harness_daemon.py`, `fakes/fake_claude.py`); new
mutations: `tests/mutations_daemon.py`.

Phase 2 review fixes (2026-10-20; DECISIONS "PLAN-v4 phase 2 review
fixes"): every vault read asks the daemon (the client kept its view for the
process, so the MCP server kept sending the real token after a lock); the
daemon keeps the decrypted vault while vault.age is unchanged and forgets it
on lock and write; a session is its pid + start time and the executable is
checked only at registration (an upgrade that deletes a running Claude
Code's binary dropped the session and let the daemon exit for idleness);
entry points are this plugin's run.py or a sibling version folder's in the
plugin cache, started with exactly `-I -S [-X pycache_prefix=]` (a "gate"
folder anywhere got every secret class); passphrases 12 characters to 512
UTF-8 bytes (age's tty line hung for 130 s at 1024) and the wrap's scrypt
runs outside the vault's flock and the broker's mutex, re-checking key.txt
under the flock; `gated status` (/gate-doctor) and `gate status` report
version skew; the daemon's log is rotated while it runs; tests that kill
pid reuse, foreign data-folder pythons, a hook registering its parent shell
and unlock's key.recipient check.

PLAN-v4 phase 3, native dialogs (2026-10-20; PLAN-v4 matrix rows for
sections 3, 4, 11, 11.1, 12, 13, 14; DECISIONS "PLAN-v4 phase 3";
docs/dev/modules/daemon.md "Dialogs", docs/dev/modules/ux.md): every question the
gateway asks is a pane the mod draws inside Claude Code from requests gated
holds (`daemon/dialogs.py`): popup.py takes a dialog lease on the agent
plane before it forks its helper, the helper opens and waits on the lease
plane, the mod long-polls `/ui/dialog/next`. A secret is typed into a
`Client` field (`hooks/mod/field.tsx`: keys only after a click, bullets,
every click starts it over) and sealed there with vendored TweetNaCl
(`hooks/mod/vendor/`, VENDOR.md) to the attempt's X25519 key; gated opens it
with PyNaCl (pixi.toml), refuses plaintext, rechecks the request (open,
deadline, session alive and not paused, the lease's processes alive, the
form entry unchanged) and hands the value once to the helper, which
verifies (fake sudo, ssh, GitHub/HF/Entra) and stores or reopens it with
"That didn't work" (3 tries, a new key each). Paste from clipboard makes
gated read the clipboard by absolute path (pbpaste; wl-paste, xclip, xsel;
root-owned only; the test override's program under any override). The
`prompt.edit` guard holds composer typing back while a secret dialog can
take keys. One dialog at a time per session, the rest queued by identity;
cancel, timeout, focus moving away, failure, gated dying (requests persisted
as metadata, new keys at restart), `/reload-plugins` and pause all clean up
or resume. The vault passphrase: "set a vault passphrase" (two fields;
wrap, verify, key.txt removed) and unlock in gated's own dialogs,
`/gate-unlock`, `/gate-lock`; the daemon's version-skew notice on the
status line once. Removed: dialog.py's osascript/zenity/kdialog backends,
`gate secret`'s terminal path (it now says where credentials are entered),
the terminal export/import path, the one-time codes, browser and
device-code sign-ins (GitHub: a PAT; Azure: a service principal, its
client secret stored as `entra.client_secret`; ml-catalog: unavailable;
existing refresh tokens keep working). Surfaces without the private field
(VS Code, mobile, Remote Control, `-p`, the SDK, mods off) get
"unavailable" with what to do, never another way to ask. `/v1/pause` and
`/v1/resume` are implemented for dialogs (feature "pause"). Found live:
Claude Code 2.1.301 reports clicks to plugins only in its fullscreen
layout, and with telemetry on (the TUI harness behind the record-only
proxy) it starts on the main screen, so the field is drawn only where it
works and the main screen offers Paste (keyboard: `/gate-dialog`, Tab,
Enter); the pane's `isFocused` stays false while a Client holds the keys,
so focus changes are handled by the click and `ui.focus`. The TUI harness
(both repos, identical) gained `proxy.py`, the record-only telemetry proxy
(mitmproxy through `pixi exec`, answers every request itself), and
`safety.record_proxied`. Acceptance: `tests/acceptance_dialogs.py`
(below, "Last full run").

Phase 3 review fixes (2026-10-20; DECISIONS "PLAN-v4 phase 3 review
fixes"): no sudo or ssh dialog named its entry for gated's recheck, so a
password typed after the right was switched off was still verified, stored
and used; now the sudo stand-in (`SUDO_CHECK`), gate check's sudo steps
(`sudo_check`), remote sudo and the login password (`ssh.host_check`) pass
`check` (a list of rights is allowed; form and effective rights), and the
sudo and ssh stand-ins (and gate check before a passwordless sudo rule)
read the rights again before using a dialog's value; "Remember it"
(ticked) is offered on a sudo password a command asks for, local and
remote, also with Paste on the main screen, and a post without the choice
takes the dialog's default; the `prompt.edit` guard also holds on the
terminal's main screen and while the pane is closed or unplaced (only the
gateway's own commands pass); the acceptance run builds the env before any
session (outside the proxy) and puts recording shims for open, xdg-open,
osascript, zenity, kdialog and the terminal programs first on PATH (the
process sampler is labelled best effort). One claim didn't hold: a form
without `[hosts.localhost]` keeps the implicit localhost with sudo on.

PLAN-v4 phase 4, managed execution (2026-10-20; PLAN-v4 matrix rows for
sections 2, 3 and 8; DECISIONS "PLAN-v4 phase 4: managed execution";
docs/dev/modules/managed.md): Claude's commands run in the gateway env's bash 5.
The mod, first thing at session start (also in `-p`), sets
`CLAUDE_CODE_SHELL_PREFIX` to the shipped `hooks/gate-sh`, `GW_MANAGED_DIR`
and, once the env is built, `CLAUDE_CODE_SHELL` (the managed bash; Claude
Code honours it when set before its first shell use). gate-sh passes a
classic hook string through as `/bin/sh -c` (SHLVL given back on macOS) and
runs a Bash-tool script with the snapshot's `source` replaced by the gateway
rc, the rest byte for byte, with platform variables, Claude Code's own and
approved imports (never a credential-looking name; since the review fixes
below, everything else removed by name, no value on a command line); unknown
shapes 126, an unready runtime 75, never the login shell; a newer
gateway.toml makes it renew its settings first. `managed.py` writes
`$DATA/managed/{conf,rc.bash,state.json,bin/,sync}` (SessionStart, after a
build, FileChanged, an approval, an unlock, gate-sh's renewal), and an
executable copy of gate-sh when an install dropped its exec bit. `[shell]
managed = "on" | "warn" | "off"`, `import_path`, `import_env` are consented
under the "settings" entry (lowering and imports widen). Without the prefix
the classic Bash hook decides every Bash and Monitor call: "on" denies
"managed shell unavailable", "warn" runs with a notice once per session.
`/gate-doctor` and `gate status` show the PATH and imports with origins; the
gw tool `host_inspect` reads (never runs) what the host offers. bash joined
pixi.toml (the lock gained only bash 5.2.37). Verified live in the TUI
harness against a baseline session without the gateway
(`tests/acceptance_managed.py`): every route (Bash, background, a subagent,
`!`, skill injection) in the managed bash, a probe plugin's string-form hooks
with the same `$0` and environment, the permission dialog and "don't ask
again" rule on the original command, Pre/PostToolUse payloads, results and
exit codes identical, Escape and timeouts stop the command, `-p` managed, and
with the mod removed the deny and the warn notice. Linux (Debian 13 VM): the
whole suite passes; its 25 old failures were examined (DECISIONS "The Linux
suite"): the git credential helper refused every request where `/bin/sh` is
dash (git's `sh -c` stays a process there; fixed, tested, mutated); the rest
were test assumptions (a hard-coded `/usr/bin/git`, unflushed in-process
output, a group-writable ssh config under umask 002, a pixi found only in
the real home, the machine's own `/run/user` agent, a plugin-only copy's
marketplace validation), made explicit.

Phase 4 review fixes (2026-10-20; DECISIONS "PLAN-v4 phase 4 review fixes";
docs/dev/modules/managed.md): gate-sh no longer puts the curated variables on
env's command line (`NAME=VALUE` to `env -i` let every local user read the
user's own tokens under `others = "mine"`, approved imports and Claude
Code's variables in `/proc/PID/cmdline` or `ps`): it removes every other
variable by name (`env -u`), and only names reach any command line; the
credential words gained PASSPHRASE, CRED, CLIENT_KEY and CLIENT_CERT, so
Claude Code's own credential variables (2.1.301's lists, the mTLS
`CLAUDE_CODE_CLIENT_KEY_PASSPHRASE` included) never reach commands;
`GW_MANAGED_DIR` passes, so a Claude Code started from a command (`claude
-p`, an Agent SDK script) stays managed instead of failing every command
with 75; a hook string that mentions a snapshot or holds the tracker's
text runs as `/bin/sh -c` (a tool script is recognised by its whole shape);
the mod takes `CLAUDE_CODE_SHELL` from `launch.sh status`, never from
`state.json`, and the data folder's gate-sh copy only while it is the
plugin's, so a rewritten `state.json` can only take the prefix away; and
the Linux-only flake in the ssh lock tests was the test harness's: a closed
hold proxy left its accept thread blocked (Linux's `close()` doesn't wake
it), which took a later proxy's connection on the same fd number and reset
it; `HoldProxy.close()` now shuts the listener down first.

PLAN-v4 phase 5, terminals and jobs (2026-10-20, plugin 0.8.0; PLAN-v4
matrix rows for sections 4, 9, 13 and 14; DECISIONS "PLAN-v4 phase 5";
docs/dev/modules/terminals.md): gated supervises terminals (`t_<ulid>`) and jobs
(`j_<ulid>`) in its own tmux server (the env's tmux 3.8, joined pixi.toml;
`<run>/tmux.sock`, `<run>/tmux.conf`: remain-on-exit, history, no status bar,
no clipboard; the user's tmux and `~/.tmux.conf` never used), each the env's
bash with the managed environment (PATH and rc from the managed shell's
files, platform variables and approved imports from the caller, never a
credential-looking name, `GW_TERMINAL`, `CLAUDE_PID=$$`; values through a
0600 start file, never a command line). Records (ids, host, workspace, cwd,
owner session, agent, task_ref, owner, state, exit; never screen or input)
in `<data>/gated/terminals.json`; a restarted gated re-adopts live panes by
id and nonce, and a pane tmux lost (or a reboot) is gone/unknown, always
asked of tmux. The gw MCP server's tools: `terminal_open`, `terminal_read`
(bounded, scrubbed: lines, cursor, alternate screen, title, seq, truncated,
history), `terminal_send` (quotes the seq; stale or a user-held terminal
refused; `delay_ms` queues), `terminal_resize`, `terminal_signal`,
`terminal_close`, `terminal_list`, `job_start` (argv or command, on_pause,
idempotency_key), `job_status`, `job_tail` (bounded, scrubbed), `job_signal`,
`job_list`. One writer at a time: the person's takeover (a click into the
`/gate-terminal` pane, a key, Take) fails Claude's queued input ("input taken
by the user; re-read the screen"), hand back needs a fresh read, agents take
turns (the agent loop from the mod's `tool.call`, keyed by the tool use id).
The pane draws the screen in a `Client` (styled runs; the click is the
takeover; keys batched with sequence numbers; Ctrl-] then c/d/z/[ for
^C/^D/^Z/Esc; buttons) in the fullscreen layout, and a line field plus
buttons on the main screen (never during a password prompt); the region's
size resizes the terminal. A password prompt in a pane (ECHO off, ICANON
on) opens the credential dialog; the sealed value goes to that tty only
after a recheck, by `load-buffer -`/`paste-buffer -d`; the agent sees
"[credential supplied]"; sudo in a terminal is handed to the real sudo on
the tty by the stand-in. CONTRACT-v1's job routes (`POST /v1/jobs`, `GET
/v1/jobs/<id>`, tail, signal) replace the 501s, `/v1/pause`/`/v1/resume`
apply per-job on_pause policies with truthful outcomes, features add jobs and
terminals, events job.* and terminal.*. The approval hook judges
`job_start`/`terminal_send` like checkpoint's jobs; mcp_perm.sh allows the
reads, an idle open and a resize. `/gate-doctor` shows live terminals and
jobs. Found by the tests and the live runs (DECISIONS): a race where the tick
cancelled a dialog mid-supply, tmux resuming a SIGSTOPped pane, Linux's tmux
naming signals by number, the space bar reaching a Client as `space`, an
unreachable tmux server left behind when the run dir goes (gated now stops
it). New tests: `test_terminals` (34), `hooks/mod/terminal.test.ts` (11),
`tests/acceptance_terminals.py`; new mutations: `tests/mutations_terminals.py`.

PLAN-v4 phase 6, the managed remote runtime (2026-10-20; PLAN-v4 matrix rows
for sections 2, 4, 8, 9, 10 and 14; DECISIONS "PLAN-v4 phase 6";
docs/dev/modules/remote.md): terminals and jobs on remote hosts in the gateway's
own runtime there. `runtime/pixi.toml` + lock (bash 5, tmux 3; 4 platforms;
no Python; version = the lock's sha256 prefix) is packed on first need by the
env's pixi-pack (pixi.toml gained pixi-pack and zstd; the lock gained only
pixi-pack) into `<data>/runtime/<version>/<platform>/`, with the target's
pixi-unpack taken out of its conda packages (`--directory-only`, zipfile +
zstd + tarfile; it needs its openssl and libgcc_s, shipped beside it) and a
sha256 manifest checked before every use. gated (`daemon/remote.py`) connects
with the stand-in's own machinery (`ssh._build_link(..., on_mismatch=...)`,
the shared ControlMaster), only for hosts whose ssh right is true; every
command is `exec /bin/sh -c` behind a marker, values on stdin; at each new
master the host's machine id is read and its token stored with the host keys
(first contact) or compared, a changed key or machine opening a gated-owned
confirm dialog (dialogs.py gained owned `confirm`/`info`, owner "gated") that
blocks the host until answered. Staging: `<base>/<version>-<platform>/`
(base: the host's consented `runtime` path, default
`~/.local/share/gateway-runtime`), uploads on stdin, sha256 on the host or
read back, pixi-unpack with TMPDIR inside, an `env -i` probe of bash and tmux,
the marker, older idle marked versions removed; unsupported platforms, full
disks, noexec folders, unwritable or too-long paths are reported with the
remedy. Remote panes (`terminals.py`): `host` on `terminal_open`, `job_start`,
`POST /v1/jobs`, `/ui/term/open`; a start file written on the host; the
runtime's tmux under `env -i` on a private socket in the runtime folder; every
command checks the host record's marker (`bind_check`) and goes through the
pane's own host (`_tm`, machine-bound); a per-host poller (list-panes, `stty
-g`, foreground groups) keeps states honest: `disconnected` /
`waiting_auth` (a refused key, with an info dialog and recovery) while the
host can't be asked, `exited` or `unknown` only from the host's answer, seq
bumped on reconnect and after a gated restart; password prompts through the
credential dialog naming the host (sudo-off hosts ask nothing), the value on
ssh's stdin into the remote `load-buffer -`. The approval hook judges remote
jobs and remote terminal text as `ssh HOST CMD`; mcp_perm.sh doesn't
auto-allow a remote `terminal_open`; the gw tool `host_runtime`
(status/provision/clean); snapshot hosts gain `identity: "verified"`,
`machine`, `same_machine`, `reachable`, `auth`, `runtime`; `host.state`
events; feature "remote"; `gate status NAME` shows the runtime. Found by the
tests and the live runs: the conda pixi-unpack isn't static, the local
pixi-unpack refuses another platform's pack, Debian's bash reads `~/.bashrc`
for ssh commands (outside the managed shell); and three races the loaded
machines showed: a read's record facts were taken before its (slow, remote)
capture, so a credential supplied meanwhile showed on the screen but not as
"[credential supplied]" (the view now describes the pane after the capture;
seen on the Linux VM); a poll whose connection dropped after the marker read
as an empty answer, so live remote panes were marked gone (a 255 after the
marker is now a dropped connection and a poll answer needs its end marker;
seen in parallel stress runs of the host-key test); and gated's `abandon()`
killed whatever process of the tmux binary took its old server's pid (now it
must name gated's socket on its command line too). New tests: `test_remote`
(34), `harness_remote.py`, `tests/acceptance_remote.py`; new mutations:
`tests/mutations_remote.py` (38).

Phase 5 review fixes (2026-10-20; terminals.py, server.py,
docs/dev/modules/terminals.md): verified-finding fixes to the terminal
supervisor. (1) A value a program puts in the terminal **title** (OSC 2) no
longer reaches the agent: the title is scrubbed where it is stored (`_mask`),
so `terminal_read`/`terminal_list`/`job_status`, the pane view and the records
are all masked. (2) A vault value printed across a **soft-wrap boundary** no
longer reaches the agent as two splice-able halves: the agent's plain lines
(and history) are captured with `capture-pane -J` (`_capture_joined`), so a
wrapped value is one logical string the scrubber catches (since fix2 the agent
reads the physical rows and the `-J` line only finds what to mask in them:
`-J` also glued a row the line editor filled exactly to the output). (3) The **main
agent** (empty loop id) now counts as a real input holder (`holder is None`
means unclaimed, not `""`), so a subagent can't write into its terminal
without a take, and vice versa. (4) A **transient `list-panes` failure** (one
timeout / non-zero exit) no longer marks every live pane gone for good: a blip
is told from a dead server by the server's own pid (`_blip`/`_server_alive`),
and adopt retries before concluding gone. (5) A **paused** session's
`job_signal CONT` is refused (409 `paused`): it can stop or cancel but not
resume (checkpoint's `/v1/resume` is the way back). (6) The **interrupt
escalation** (SIGTERM after the grace) and its `paused_as` are persisted and
re-armed after a gated restart, not silently dropped. (7) A seq handed to the
agent is persisted at once, so a restart's adopt-bump reliably makes a
pre-crash seq `stale` even when the screen moved on while gated was down. (8)
`terminal_list`/`job_list` to the agent are bounded to `LIST_MAX` (live first,
with the true total and `truncated`); the pane list and the contract snapshot
stay complete. (9) An **unknown** job (tmux lost it) carries `ended: null` (its
outcome and end time are unproven), on `job_status`, the snapshot and
`GET /v1/jobs`. (10) The credential dialog's "can't read the executable"
wording is honest (setuid, or replaced/deleted), not only "setuid". Left as a
documented guardrail limit (not a fix, with evidence): the approval hook judges
each `terminal_send`'s text per call, so an agent that splits a command across
two sends evades the text deny — but a terminal is a real shell running as the
user, and the hard boundaries (the `sudo`/`ssh`/account stand-ins, the
encrypted vault) are not split-bypassable; screen-reconstruction of the line
was rejected as fragile (invariant 17, docs/dev/modules/terminals.md "Known
limits"). Two verifier probes did not reproduce a defect: pane text to a
just-appeared password prompt (the pane refuses it; only a sub-tick,
model-invisible, user's-own-keystrokes window remains) and start files left
behind (the pane removes its start file before `sleep`, so none were left).
New tests (9) and mutations (9) in `test_terminals`/`mutations_terminals`.

PLAN-v4 phase 7, hosts, policy, accounts, portability (2026-10-20, plugin
0.9.0; PLAN-v4 matrix rows for sections 4, 8, 10, 11, 12 and 13; DECISIONS
"PLAN-v4 phase 7"; docs/dev/modules/policy.md): **workspaces**
(`[hosts.NAME.workspaces.W]`: root on the host, `local` folder here, own
read/exec/write; `w_` ids from the host's id and root) bind every terminal
and job through gated's `Supervisor._bind` (cwd defaults to the root and
must lie inside it, local paths map to the root, another host's workspace is
refused); identical paths on two hosts are two resources. **Policy**
(`policy.py`): allow/ask/deny in `[policy]`, `[hosts.NAME.policy]`, the
workspace and `[accounts.NAME.policy]` for read, exec, write, network,
elevation, credential, env_import, provision and the per-host grants
forward_agent/x11/remote/stdio; restrictions start at the rights and only
lower them, the strictest wins, each action on its own; consented per key
(raising waits for the OK, lowering is ratcheted); decided in the ssh stand-in
(remote command, scp/rsync/sftp/git directions and paths, tunnels,
forwarding: the forwarded agent holds only the gateway's key for that host),
the sudo stand-in and remote sudo (elevation), gated (terminals, jobs,
provisioning, remote inspection), the managed shell's imports, web (http
writes and credential-free requests), account selection and the approval
hook (a deny with its rule, an "ask" asked); every refusal names the rule
and its line, audited and carried as `rule` on CONTRACT-v1 refusals and
`policy.denied` events. **Accounts** (`adapters.py`): GitHub (fine-grained
or classic PAT), Hugging Face, Azure (SP secret, SP certificate by an RS256
client assertion through the env's openssl, existing refresh tokens) with
states configured/connected/expired/revoked/reauthentication_required told
apart from the services' answers, kept in the vault, `account.state` events,
`gate accounts`; no cookie or session store is needed. **Panes**:
`/gate-hosts` and `/gate-accounts` (immediate, from gated's `/ui/manage`;
edits as fixed `gate host|workspace|policy` subcommands through the form
writer, then the consent dialog; Check and Enter credential).
**Portability**: export/import format 3 (per-item selection, schema,
digest; per-item conflict dialogs; staged import with a backup under
`private/backups` and restore on failure; wrong passphrase asked again,
tamper refused; machine identity; imported credentials checked; nothing of a
live process in the file). **sudo**: the passwordless installer and all
NOPASSWD advice removed; store or ask per call (Remember it); a
TTY-requiring sudoers pointed to a gateway terminal; the hook names whom sudo
runs as and where. **Alternate routes** (credential tools by path, `command
-p`, `env -i`, PATH/ssh-command reroutes, rsync/git naming another ssh)
refused in managed mode, the same-user limit stated. **Phase 4-6
leftovers**: `/v1/pause`/`/v1/resume` bound to the caller's session,
`pause_id` (24 h replay) and no second signal for a job a pause already hit;
the MCP server takes this machine's own id as localhost; remote
`host_inspect` and `[hosts.NAME.shell]` imports. CONTRACT-v1 stays
`gateway.v1` (additive; checkpoint's copy byte-identical). Found while
building: gated's snapshot and ticker reads counted as vault uses and kept an
idle vault unlocked (now `touch=False`); a target notice on stderr broke
merged-output commands (now a hook `systemMessage`); `managed.inspect` would
have answered a remote host with this machine's files (now refused). New
tests: `test_policy`, `test_workspaces`, `test_accounts_states`,
`test_portability`, `hooks/mod/manage.test.ts` (+ updates across the suite);
new mutations: `tests/mutations_policy.py`.

Phase 7 review fixes (2026-10-21; docs/dev/modules/policy.md, ssh.md,
managed.md): (1) deleting or renaming a workspace that restricts anything
is a widening: the approved workspace keeps its root and restrictions until
the user's OK (`consent._ws_restrictions`; the ratchet keeps it approved);
only one that restricts nothing goes at once. (2) The ssh stand-in reads a
transfer server strictly (`ssh_args._rsync_server`, `_scp_server`): only
the exact bare name as the first word (`/tmp/x/rsync --server` is exec)
and only known options; `rsync --remove-source-files` writes each source;
`--log-file`, `--temp-dir`, `--backup-dir`, `--files-from`, protected args
(`-s`), a path that starts with `-` (rsync reads options after the `.` too)
and anything else are exec. (3) Every path of a transfer is decided
(`decide_path`), in the workspace that holds it and in every workspace it
may reach (a folder above a root; a root written the other way, from / or
from ~, since the stand-in doesn't know the host's home; `~bob/x`, `..`
leaving the home, sftp: every workspace); the strictest wins and the
refusal says why. (4) In managed mode the approval hook also denies what it
can't follow: a shell string, eval/exec, a function, find -exec, a variable
as the program, PATH or a transport variable changed earlier in the same
command, `hash -p`, an alias, `git config core.sshCommand`, rsync `-e` in
combined options, `git -ccore.sshCommand=` (`_route_changes`,
`_route_text`, a deliberately broad text scan that skips data
here-documents). (5) The NOPASSWD advice scan covers all of docs/ (and
CLAUDE.md); historical passages that quote the old advice are marked
superseded, the only exemption. (6) Found on the way: `gate workspace
remove` refused a host's last workspace and called every removal a
narrowing; it now removes it and says when the removal waits for the OK.

GitHub install fixes (2026-10-21, plugin 0.9.1; DECISIONS "GitHub install
fixes"): (1) an uninstall while terminals or jobs run drains gated
(`Daemon.drain`: contract.json withdrawn at once, `daemon.draining`, new
terminals, jobs and remote runtimes refused with 503 `draining`, the work
left to finish, never killed; it exits with its tmux server once no local
pane runs; with the env's tmux deleted it watches the panes' own processes);
(2) gated stops its tmux server and watchdog when it exits with no local
pane running, and the watchdog also stops the server once gated's socket is
gone and no pane runs; (3) "ready" is a toast (Claude Code draws every status
line with ⚠ and `$.ui.status` takes no level); (4) the mod sets `SHLVL=1`
where it is missing, so the `bash -c` that starts the prefix (stdin a
socket) no longer sources `~/.bashrc` (upstream bash's rule, seen on Debian);
(5) the version is 0.9.1.
Re-fix (refix-gw, 2026-10-21, still 0.9.1: it hadn't shipped; DECISIONS
"Re-fix of the GitHub install fixes"): (1) the watchdog tells a killed gated
(SIGKILL, a crash: the socket file stays) by `<run>/gated.pid` (pid and ps
start time under `LC_ALL=C TZ=UTC0`, written before the socket is bound) and
stops a server of dead panes then; (2) a draining gated resumes the jobs left
suspended (SIGCONT; `daemon.draining` counts them in `resumed`; the session's
pause record kept) and refuses new pauses (503 `draining`), so a job
checkpoint suspended no longer keeps gated, tmux and itself there forever
once contract.json is gone; (3) a removed code folder with another, not
orphaned version beside it (Claude Code's sweep of an update's old folder) is
no uninstall: gated serves on and exits once nothing runs, as 0.9.0 did.
Verifier lows after the re-fix (fix2-gateway, 2026-10-21, still 0.9.1;
DECISIONS "Verifier lows after the re-fix"): (1) a job's STOP or TSTP is
refused while gated drains (503 `draining`; a stop after the drain began kept
everything there forever once its session ended); (2) a job's STOP and TSTP
both use the group stop, read back in ps, and a job is recorded suspended only
when it held (else continued, with a note); the drain counts as resumed only
jobs ps showed stopped; (3) the drain resumes a remote job a pause suspended
through the live master with the system's ssh (`/usr/bin/ssh`, never a
master), since a plain uninstall deletes the env's; when that can't work the
job stays stopped on its host (documented, with the remedy); (4) the agent
reads a terminal's physical rows, with values across a soft wrap masked in
each row from the rejoined line, so a command line that filled its rows
exactly is no longer glued to its output; and the draining gated's log lines
also go to `~/.config/gateway/run/gated-drain.log`, which an uninstall keeps.
Later (final-gw): a job the drain resumed says running (not suspended) even
with the env's tmux gone (`resume_stopped` sets the state and emits
`job.state`).

Not done or not verified live (as of the 2026-10-21 acceptance; the per-phase
notes below were written when each phase landed, and items the acceptance
runs later covered are marked so; the requirements matrix with each row's
validation is in docs/dev/PLAN-v4.md):
- Blocked, not done here: the desktop app (no way to drive it from the TUI
  harness; a manual checklist exists), x86_64 machines (linux-64, osx-64:
  no such machine or VM), Windows/WSL 2 (no Windows machine; native Windows
  unsupported), the real GitHub, Hugging Face and Azure services (no
  authorized test accounts: local API servers only), the real model API
  (the headless e2e suite; the work's rules forbid it), the real GitHub
  marketplace (the tree is uncommitted; a local smart-HTTP git server served
  it).
- Phase 7: `/gate-hosts`, `/gate-accounts`, export and import were driven
  live since (`tests/acceptance_native_ui.py`, macOS and the VM); a policy
  "ask" prompt and the elevation notice weren't; remote `host_inspect` and remote
  imports ran against the local sshd, not the VM; the account adapters ran
  against local API servers (GitHub, Hugging Face, Entra fakes), not the real
  services; ssh key passphrases aren't stored; the elevation notice shows
  only with an allow or ask decision (with no decision Claude Code's own
  prompt shows the command); checkpoint sends `pause_id` since its 0.7.0;
  `/usr/bin/ssh` run by a script, not typed, isn't seen
  (stated limit), nor a typed command obfuscated past the text scan; a
  sudoers file installed by 0.8 or earlier isn't removed; a write grant on
  a host can reach exec through the host's own files (dotfiles, `~/.ssh/rc`,
  a PATH folder; stated in docs/dev/modules/policy.md); workspace paths are
  compared as written (a symlink on the host isn't followed); the review
  fixes ran in the repo suites (the hook through `hooks_bash.main`, the
  stand-in against local sshds), not in a live Claude Code session.
- Phase 6: the remote acceptance ran at the daemon level (a real gated, a
  FakeClaude drawing and answering the dialogs as the mod would), not through
  a Claude Code session; tested remote platforms: linux-aarch64 (the VM) and
  osx-arm64 (a local sshd); linux-64 and osx-64 hosts untested; a noexec
  mount and a full disk only in the suite (a stand-in pixi-unpack, a `df`
  override: the VM's test user has no writable noexec mount); hosts behind
  `via` untested live; `waiting_input` not
  detected remotely either; remote job output is the remote tmux history
  only (no `job.output` counts); the first pack of a platform needs network
  (no proxy settings passed to pixi-pack); musl, BSD, other architectures
  and csh/fish login shells unsupported. (Remote inspection and imports and
  the version bump to 0.9.0 came with phase 7.)
- Phase 5: `waiting_input` isn't detected; the desktop app's pane untested (a
  manual check), VS Code, mobile and Remote Control draw no pane (the tools
  work); without mods a password prompt in a pane is reported, not asked;
  agents aren't told apart without the mod; (since: checkpoint 0.6+ delegates
  its jobs to the contract routes and calls `/v1/pause`, and the terminals
  acceptance ran on the Debian VM too, 63 of 63); (workspaces, `w_`, came
  with phase 7).
- Phase 4: Monitor isn't offered by Claude Code against the harness's fake
  API (a server-side gate), so its commands' routing is code evidence only
  (`Rue(..., "bash")`); the desktop app, VS Code, mobile and Remote Control
  weren't driven; the headless e2e suite (`pixi run e2e`, real model API)
  wasn't run (the hard rules forbid the real API here), and its scenarios now
  run managed; (since: the managed acceptance ran on the Debian VM too, 38 of
  38 after the acceptance fixes); without the mod the user's `!` and skills'
  injection run unmanaged (reported); the desktop Terminal panel isn't the
  managed shell, nor checkpoint's own job runner (used only when the gateway
  doesn't serve the session; delegated jobs run in gated's managed
  environment); remote managed shells and remote host inspection are phase 6.
- Phase 3: the desktop app's `Client` relay and dialogs are untested (a
  manual check); VS Code, mobile and Remote Control weren't driven live (the
  mod's tests and gated's availability rules cover their "unavailable"
  answer); typing on the terminal's main screen isn't possible (Claude Code
  sends plugins no clicks there: Paste only); keys typed into the prompt box
  before the click reach other plugins' `prompt.edit` hooks and are painted
  for a frame (FEASIBILITY-v4 P1; the guard holds them back from the
  prompt); a JS string in Claude Code's memory and a Python string in gated
  and the helper can't be wiped; the real clipboard programs (pbpaste,
  wl-paste, xclip, xsel) weren't run by the tests (the override only)
  (per-item export selection came with phase 7); (since: checkpoint 0.6+
  calls `/v1/pause` on every pause while the gateway serves the session, so
  the dialogs' recheck sees a task paused in checkpoint).
- Phase 2: remote host ids are assigned (their machine identity is
  verified since phase 6); a detached process outside a registered session (a checkpoint
  job after its session ended) gets nothing from a wrapped vault; an
  npm-installed Claude Code (`node`) isn't recognized as Claude Code;
  `lock_after` isn't under the widening rule yet; `hook-daemon` and the
  locked refusals weren't run in a live `claude -p` session; the desktop
  app's mod registration is untried.
  (The 25 Linux failures noted here since phase 2 were examined and fixed
  with phase 4: DECISIONS "The Linux suite".)
- The headless suite (`pixi run e2e`, `tests/e2e/`) covers ten short
  `claude -p` scenarios on macOS only (`jobs` only with a checkpoint
  checkout next to this repo; its job steps depend on Claude Code's
  classifier, which may deny some: "not reached"); it wasn't run in the v4
  work (real model API). Linux end to end ran since through the TUI
  acceptance on the Debian VM (installed copies, Claude Code 2.1.304). The
  warm step's effect was measured on macOS only.
- Phase 1 not verified: the desktop app, VS Code, mobile and Remote Control
  surfaces for the mod (docs/CAPABILITIES.md "untested"); the `/plugin ...`
  slash forms of the lifecycle commands (the shell forms were run against a
  scratch config); pixi versions not named in pixi.toml's comment (the
  tested range was probed on macOS only). (Linux since: install, update and
  uninstall on the VM, `tests/acceptance_install.py`.)
  The cold window still has no output masking and no rights checks (only the
  sh text guard); `logs/` and `quarantine/` stay in the plugin folder (the
  user's data, git-ignored).
- Not tried on a real machine: the pijul cargo build on Linux and osx-64, real
  `visudo` and sudoers (fakes only), FileChanged with
  the gateway itself loaded (a standalone probe plugin was used), the sudo
  stand-in's askpass path against a sudo that needs a password (the Linux
  askpass check of round 2 is unit-tested with a faked `/proc` status only;
  the VM's real sudo was answered through the dialog in a gateway terminal,
  phase 5), NixOS's sudo path.

Known limits (documented in SPEC and the module docs): output that Claude
Code passes to no
rewriting hook can't be masked: every Bash command that fails (a non-zero
exit, a timeout, a kill; PostToolUseFailure only warns; likewise an MCP
error result, such as checkpoint's `job_stop` reporting `stop_failed` with
the job's last log lines), Monitor's lines and
its `ws` source, and a background command's raw output (its "waiting for
input" notice reaches Claude unless the prompt hook finds a stored value, in
any scrubber form, or a token shape in it: then the notice is held back and
masked in the transcript; its task output file stays raw), and a
checkpoint job's log file on disk (what `job_tail`, `job_status` and
`job_stop` return is masked); `gate scrub` is
an optional filter Claude may pipe such output through; gh, databricks, dvc
and `gate with` hold their token
in their environment while they run, which `ps eww` shows to the user's
processes (hf uses a 0600 file); the http tool can't reach sites that
need a proxy; the pijul binary depends on its env's lib folder (rebuilt when
it's gone); a stored remote sudo password is readable by same-user processes
on that host while a sudo runs (the gateway doesn't install passwordless
sudo to avoid it: choose "ask me each time" with Remember it unticked, or an
`elevation` policy);
text prefilters and ancestry checks are guardrails against a cooperative
model, not a sandbox against code running as the user; keys typed into
Claude Code's prompt box before the gateway dialog's field is clicked reach
other plugins' `prompt.edit` hooks and are painted for a frame (the guard
holds them back from the prompt and says to click first); on the
terminal's main screen a secret can only be pasted (no clicks reach
plugins there); while a secret dialog waits (up to 30 minutes) the prompt
box takes only the gateway's own commands (answer or cancel it first); an
edit tool's response (the file's earlier text) stays
unmasked in the transcript's record of the call (Claude Code shows Claude
only a one-line result); an `"ask"` right
can't be enforced for a script sourced into Claude's own shell (`source
x.sh`), whose commands look like Claude's own to the stand-ins; on a
machine's very first session, until the env is built, the Bash hook and the
file guard run only their reduced sh form (by text: private folder and the
`.config` parent, transcripts via Bash and via Read/Grep, credential shapes,
curl/wget with a vault; none of the rights checks), output masking
is off and the http tool is missing (later updates run on the previous env
meanwhile); a secret
printed with a pause of more than 0.15 s in the middle shows its part before
the pause; with `scripts = true` on an azure account with `env`, a program
Claude writes can print a raw token from `az`; the desktop app's transcript
search and event listing return other sessions' text with stored values
masked, but a failed
command's unmasked output recorded there stays as it is. Users with a stored
sudo password (for example from 0.6) keep it; since 0.9 `gate check` never
offers a passwordless sudoers rule (one installed by 0.8 or earlier stays
until the user removes it). A script that runs `/usr/bin/ssh` (or another
credential tool by path) itself, outside the command line the hook sees,
reaches the system tool with the user's own credentials, never the
gateway's (docs/dev/modules/managed.md, "Alternate routes").

## The PLAN-v4 phases in brief

From CLAUDE.md's "What this is" at 0.9.1: what each phase added.

PLAN-v4 phase 1 (2026-10-19) added a mod (`hooks/mod/`, a
TypeScript hooks module: setup status line, provisioning at session start,
the immediate `/gate-doctor`) beside the classic hooks, which keep every guard.
PLAN-v4 phase 2 (2026-10-19) added the per-user daemon `gated`
(`src/gateway/daemon/`, docs/dev/modules/daemon.md): a Unix socket with peer
authentication and planes, CONTRACT-v1 discovery/snapshot/events for
checkpoint, and the broker that holds a passphrase-wrapped vault key.
PLAN-v4 phase 3 (2026-10-20) made every question the gateway asks a native
pane inside Claude Code (the mod draws it from requests gated holds; a secret
is typed into a `Client` field and reaches gated sealed with NaCl's box): no
OS dialogs, no terminal prompts, no browser or device-code sign-ins, and the
vault passphrase is set and unlocked there (`/gate-unlock`, `/gate-lock`).
PLAN-v4 phase 4 (2026-10-20) made the gateway the default execution route:
the mod sets `CLAUDE_CODE_SHELL_PREFIX` to `hooks/gate-sh`, which runs every
command Claude Code starts through its shell (Bash, background, Monitor, `!`,
subagents, skill injection) in the gateway env's bash with the gateway rc and
a curated environment, and passes classic hook strings through exactly
(docs/dev/modules/managed.md); `[shell]` in the form sets the mode and the host
imports (consented), and the gw tool `host_inspect` shows what the host
offers.
PLAN-v4 phase 5 (2026-10-20, plugin 0.8.0) added terminals and jobs
(docs/dev/modules/terminals.md): gated supervises persistent PTYs in its own tmux
(the env's tmux, a private socket and config), the gw tools `terminal_*` and
`job_*` read and type into them (one writer at a time, quoting the screen's
seq), the person watches and takes them over in the `/gate-terminal` pane, a
password prompt in a pane opens the credential dialog, and CONTRACT-v1's job
routes and per-job pause policies are served.
PLAN-v4 phase 6 (2026-10-20) added the managed remote runtime
(docs/dev/modules/remote.md): `terminal_open`/`job_start` (and CONTRACT-v1's jobs)
take a `host`; gated stages the gateway's own bash and tmux there on first need
(`runtime/pixi.toml` packed with pixi-pack per platform, the target's
pixi-unpack from its conda package, sha256 checked on the host), runs the panes
in the runtime's tmux over the gateway's own ssh (ControlMaster), records the
host's machine id with its host keys, blocks on a changed host key or machine
until the person confirms in the native dialog, and asks the host what
survived a disconnect (disconnected, waiting_auth, unknown; never assumed).
PLAN-v4 phase 7 (2026-10-20, plugin 0.9.0) added hosts' workspaces, policy,
account states and portability (docs/dev/modules/policy.md): workspaces are
named roots per host (`w_` ids bound to the host's id and root, a local
folder mapping) that bind every terminal and job; policy is allow/ask/deny
per host, workspace, account and action (read, exec, write, network,
elevation, credential, env_import, provision, and per-host forwarding
grants), layered on the rights and the consent ratchet, decided at each
boundary with the concrete rule shown; account adapters (GitHub,
Hugging Face, Azure secret/certificate/refresh token) tell configured,
connected, expired, revoked and reauthentication-required apart from the
services' answers; `/gate-hosts` and `/gate-accounts` panes; export/import
format 3 (per-item selection, digest, per-item conflicts, staged import with
backup, wrong-passphrase vs tamper); the gateway never installs a sudoers
rule (per-call passwords, the target named before elevation); alternate
routes around the stand-ins refused in managed mode; `/v1/pause` and
`/v1/resume` bound to the caller's session with `pause_id`; remote
`host_inspect` and remote imports.
