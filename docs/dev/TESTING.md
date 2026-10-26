> Developer documentation: how the gateway's tests run, and what was tested for each release. Results of past runs: [TEST-LOG.md](TEST-LOG.md).

# Testing

Run everything from `plugins/gateway`. The tests never touch your real
`~/.config/gateway`, your Claude Code configuration, your clipboard, your
tmux server or a real remote machine. Two parts are exceptions, and say so
below: the remote acceptance (a disposable Linux VM) and the headless e2e
suite (the real model API).

| What | Command | Time |
|---|---|---|
| The suite | `pixi run --locked test` | about 7 minutes, 4 modules at a time |
| Mutations | `pixi run --locked mutations -j 3` | about 40 minutes, 3 files at a time (the unmutated baseline adds about a fifth) |
| The mod's own tests | `claude plugin test .` (also run inside `test_mod`) | seconds |
| TUI acceptances | `tests/acceptance_*.py` (a real interactive `claude`, a fake API) | 1 to 8 minutes each |
| Remote acceptance | `tests/acceptance_remote.py --vm VMDIR` | about 1 minute |
| Headless e2e | `pixi run --locked e2e` (real `claude -p`, real model) | about 10 minutes |
| Release check | `pixi run release-check` | seconds |

The manifest needs at least the pixi its `requires-pixi` names; with an older
one, run `pixi self-update` first.

## The suite

```bash
pixi run --locked test                                   # everything; ends with "N passed, 0 failed"
GW_TEST_TMP=DIR pixi run --locked test                   # temp homes in DIR; anything left behind is reported
pixi run --locked python tests/run_tests.py test_form test_vault -k widen -x   # some modules (-j N, -q)
```

- There is no pytest. `tests/run_tests.py` imports each `tests/test_*.py`
  and runs every module-level `test_*` function. With `-j N` each module
  runs in its own process, heaviest first.
- Every test runs in throwaway homes (`harness.gateway_env()`,
  `testing.override`). A guard aborts the whole run if any code resolves a
  real location, and the run fails with `LITTER:` if it leaves anything new
  in the plugin folder.
- Instead of real services the tests use fakes: a fake dialog, a fake sudo
  and visudo, an sshd on 127.0.0.1, a local git and LFS server, local
  GitHub, Hugging Face and Entra API servers. Daemon tests start a real
  `gated` below a `FakeClaude` (a copy of python named `claude`). Terminal
  tests run the env's tmux on a private socket. Remote tests run real sshds
  on 127.0.0.1 with fake runtime artifacts (no network).
- `test_mod` runs `claude plugin validate .`, `claude plugin validate ../..`
  and `claude plugin test .` with a scratch config and a local recording
  server. Without a `claude` on PATH it skips with a note.
- `test_release` checks that every file the hooks, the MCP server and the mod
  start is in the plugin folder and not git-ignored, and runs the release
  check on throwaway repos.
- Some tests read the docs, so a docs change can fail the suite:
  - the advice scan (`test_sudo_nopasswd`) reads `README.md`, `CLAUDE.md` and
    every `docs/**/*.md`, and fails on advice to make sudo run without a
    password (a passage that quotes old advice must say "superseded");
  - the capability matrix in `docs/CAPABILITIES.md` must equal the one
    `/gate-doctor` prints (`test_mod`);
  - `README.md` plus `docs/CAPABILITIES.md` must state the tested pixi range
    (`test_packaging`);
  - `docs/CONTRACT-v1.md` must carry the daemon's contract id and feature
    list, and must be byte-identical to checkpoint's `docs/CONTRACT-v1.md`
    when a checkpoint checkout sits next to this repo (`test_workspaces`).
- Some tests read the acceptance scripts: `test_acceptance_lib` compiles
  every `tests/acceptance_*.py` and e2e script, checks that every global
  name they read is defined, runs the helpers they share
  (`tests/acceptance_lib.py`: the recording fakes of the user's own tools,
  the `--permission-mode` choices, the scratch-CA page, the guarded sudo
  line, the opener scan, the checks of a session's own snapshots and
  transcripts), and checks that every string they look for on a screen or
  in a result is still what the code prints. Change a dialog's or a hook's
  wording and this test names the acceptance string to change with it.
- Three tests print a cost for the budgets below; their bounds catch only a
  pathological slowdown, since a loaded machine is slower.
- On Linux, put `GW_TEST_TMP` under `/tmp`, and don't name it `/tmp/gw-*`
  (the file guard's tests take that for the run folder). A temp folder under
  `$HOME` fails the e2e marker's temp-folder rule.

### Budgets

| Budget | Measured by | Limit |
|---|---|---|
| The git stand-in's pass-through (a git call where the stub exists: one Python start, the form, the configured list, one `git config`) | `test_git_standin::test_the_git_stand_in_costs_little` (`GW_PERF_STRICT=1` holds it to the limit) | 80 ms on macOS arm64 |
| post.sh on every tool call: the sh path (no vault, no hit) and the Python path (a vault) | `test_ux_hooks::test_the_output_hooks_cost_per_call` (prints both medians) | none set; recorded |
| Every Bash and Monitor call without a trigger word while the mode marker exists (`$DATA/mode-epoch`: pre_bash.sh, then one Python start, `hook-mode`) | `test_mode_record::test_a_call_while_the_marker_exists_costs_one_python_start` (prints the median with and without the marker; gated's answer over its socket isn't in it) | none set; recorded |
| A plain account CLI while an account of its kinds is "ask" (`$DATA/ask-clis`), and a call without a trigger word while an ask record is pending (`$DATA/asks`): pre_bash.sh, then one Python start, `hook-bash` with the vault read | `test_ask_records::test_a_call_the_records_send_to_the_hook_costs_one_python_start` (prints both medians and the sh-only one) | none set; recorded |

During development, under the suite's own load on macOS arm64, the git
stand-in's median was 60 to 73 ms and post.sh's about 30 to 40 ms (sh only)
and 0.36 s (with a vault), and a Bash call without a trigger word 15 to 19 ms
(sh only) and 74 to 87 ms while the mode marker existed (not yet measured on
Linux). WS-9's ask marker (every call to the Bash hook while an entry was
"ask", 91 to 104 ms) is gone: an "ask" is proved by the hook's record of the
command (asks.py), so a call without a trigger word costs no more for it,
except the one call right after an ask (it drops the session's earlier
records). A plain account CLI goes to the hook only while an account of its
kinds is "ask" in some mode. Under other work's load, a plain gh call was
22 to 48 ms (sh only), 0.24 to 0.33 s with an "ask" account and 0.13 to
0.24 s for a call while a record was pending (the vault read included; up
to 0.6 s under the suite's own load). The release numbers come from the
0.11.0 verification below.

## Mutations

```bash
pixi run --locked mutations -j 3                                    # every file, each on its own scratch copy
pixi run --locked python tests/run_mutations.py mutations_policy.py -k SUBSTR   # one file, some mutations
```

Each mutation weakens one guard: it replaces a snippet of the code with a
weaker version and names a test that must then fail ("killed"). The runner
copies the plugin once per file under `GW_TEST_TMP`, so the checkout is never
edited. Before the first mutation each named test runs once unmutated on the
copy (`mutation_check.baseline`, two test modules at a time): a test that
fails then, or names no test, can't tell a kill from its own failure, so its
mutations are reported as ERROR, never killed (each file's output starts with
a `baseline:` line). It exits 1 when a mutation survives or errs (a snippet
not found exactly once is an error too). Never run a mutation file directly without `--copy DIR`: that edits
the checkout.

Every security property needs a mutation. When a change moves a snippet,
update the snippet; the run reports the ones it couldn't place. Since 0.11
each piece of work adds its mutations in a file of its own (PLAN-0.11 §13).

On a loaded machine a named test can still fail for timing alone after its
baseline passed, and the mutation then looks killed: a false kill hides a
survivor. Run a new
mutation by itself (`-k NAME`) and check that its test fails for the
guard's reason. A test that polls something slow (age's scrypt) inside a
wait is a likely cause: wait on a cheap sign first, then check once.

The files in the working tree and how many mutations each holds:

| File | Mutations |
|---|---|
| `mutation_check.py` (core) | 76 |
| `mutations_accounts.py` | 67 |
| `mutations_asks.py` (WS-10a and its review: an "ask" proved by the hook's record for every stand-in and `gate`, the record dropped at the session's next call, `gate with` and an account's use and credential policy, the account the CLI stand-in chooses, program names without letter case, the network class's new members) | 69 |
| `mutations_daemon.py` | 115 |
| `mutations_dialogs.py` | 90 |
| `mutations_e2e.py` (also the acceptances' shared helpers and checks) | 60 |
| `mutations_final.py` (WS-9 and its review: the hidden-command rule's spellings, sudoedit and huggingface-cli, account owners, the local sudo dialog's Remember it, an account's use from the CLI and the pane) | 38 |
| `mutations_git.py` | 102 |
| `mutations_integration.py` | 64 |
| `mutations_managed.py` | 106 |
| `mutations_modes.py` | 185 |
| `mutations_network.py` | 65 |
| `mutations_offer.py` | 75 |
| `mutations_packaging.py` | 39 |
| `mutations_plumbing.py` | 85 |
| `mutations_policy.py` | 126 (4 of them need `test_terminals`) |
| `mutations_posture.py` | 79 |
| `mutations_relock.py` | 41 |
| `mutations_remote.py` | 63 |
| `mutations_setup.py` (0.11.1, the install-from-GitHub test's findings: the first setup's gateway.toml, pixi too old in gate-sh's notice and Claude's context, the tool folders already on the managed PATH) | 6 |
| `mutations_ssh.py` | 97 |
| `mutations_sso.py` | 67 |
| `mutations_sudo.py` | 196 |
| `mutations_terminals.py` | 94 (all need `test_terminals`) |
| `mutations_ux.py` | 148 |

## The mod's tests

`claude plugin test .` runs every `*.test.ts(x)` under the plugin folder
(`hooks/mod/`) in Claude Code's test kit. The kit has no file system,
process or clock: each test answers those calls with `on(...)` hooks.

## TUI acceptances

These drive a real interactive `claude` in a pseudo-terminal against a local
fake Messages API, with scratch configurations. The plugins are installed
the normal way, from a local git marketplace. Where a script turns it on,
telemetry goes to a record-only proxy on loopback, so it can be scanned
before encryption. Everything is scanned for synthetic canaries. The harness
is `tests/tui/`, identical in checkpoint's repo (check with `diff -r -x
__pycache__` between the two folders).

Needs: Python with `pyte` (through `pixi exec`), `claude` on PATH, `git` on
PATH (Claude Code clones git marketplaces with it), and `openssl` for the
canaries' WebFetch page.

```bash
pixi exec --spec python --spec pyte python tests/tui/selftest.py [--only t]   # the harness itself
pixi exec --spec python --spec pyte python tests/acceptance_install.py   --tmp DIR [--checkpoint DIR] \
    [--only prereq,cold,notice,warm,update,uninstall,spaced,firstbash]
pixi exec --spec python --spec pyte python tests/acceptance_dialogs.py   --tmp DIR --pixi-cache DIR2
pixi exec --spec python --spec pyte python tests/acceptance_canaries.py  --tmp DIR [--pixi-cache DIR2] [--checkpoint DIR]
pixi exec --spec python --spec pyte python tests/acceptance_native_ui.py --tmp DIR [--pixi-cache DIR2] \
    [--only scan,hosts,accounts,settings,export,import,tamper,signin,passphrase]
pixi exec --spec python --spec pyte python tests/acceptance_managed.py   --tmp DIR --pixi-cache DIR2 \
    [--only route,passthru,hooks,perms,gitask,cancel,print,notready,nomods]
pixi exec --spec python --spec pyte python tests/acceptance_terminals.py --tmp DIR --pixi-cache DIR2 [--no-proxy]
```

| Script | What it checks |
|---|---|
| `acceptance_install.py` | Both plugins from git marketplaces with only `claude`, pixi and git on PATH: first-use setup, an interrupted setup, a warm and an offline start, an update, both kinds of uninstall, paths with spaces. Since 0.11: a pixi older than `requires-pixi` ("pixi self-update"; in that session, where no env can build, the cold window's network ask), a fresh install that shadows nothing (no `[hosts.localhost]`, the user's own sudo, a recording fake, runs untouched), the first 0.11 session's notice about a stored local sudo password (once: each session's own transcripts are read), and Claude's context with checkpoint's job lines only while checkpoint is live ("ckoff" in `firstbash`: a warm session's full context). Its `vmplain` and `vmdrain` parts run only on a disposable VM (`ACCEPTANCE_DISPOSABLE_VM=1`). |
| `acceptance_dialogs.py` | Every native dialog, live; the consent line says what changes in each mode; the vault passphrase offer after the first stored secret (Not now, kept in the vault). |
| `acceptance_canaries.py` | Canaries through every input route, with both plugins; transcripts, logs, process lists and telemetry scanned. Since 0.11: a WebFetch of a page the harness serves on `https://127.0.0.1` (a scratch CA), whose summary quotes a key stored for that step alone, comes back masked. That key is in WebFetch's raw result, which every plugin's hook gets before the gateway masks it, so it is left out of the observer, debug-log and screen scans (a stated limit). |
| `acceptance_native_ui.py` | `/gate-hosts`, `/gate-accounts`, export, import and a tampered import; nothing opened outside Claude Code (the static scan allows one opener call, gated's browser sign-in, and must find it). Since 0.11: a consent and an import confirm too long for one dialog, in parts; a browser sign-in through gated with the `browser` knob's recording program and a local fake OAuth server (never a real browser), the browser tools refused while it runs; the passphrase offer cancelled, then taken in a new session (the vault key wrapped). |
| `acceptance_managed.py` | The managed shell against a baseline session without the gateway: every route, hooks, permissions, cancel, `-p`. Since 0.11: the user's environment kept and Claude Code's credentials removed, the snapshot's shell recorded in its JSON, the ssh stand-in not shadowed by an rc alias or function (also in a session whose snapshot bash made, the only kind the rc sources), a by-path ssh to a configured host refused while an unconfigured one runs the user's own ssh (a recording fake), a git push to an "ask" host asked about up front (a prompt even in bypassPermissions mode), a not-ready shell running the command without its settings in the shell Claude Code uses (the env's bash once built), its notice naming that shell and why, and no mods: commands run, still judged, with one notice. |
| `acceptance_terminals.py` | The terminal pane: a full-screen program, resize, signals, takeover and hand back, sudo's password prompt through the dialog, jobs, a restart. Since 0.11: the pane keeps the user's variables, and the user's own (unconfigured) sudo is answered once through the dialog with no "Remember it" (only once the pane's `sudo` is the fake; its sudo line runs only for the fake). |

A cold `--pixi-cache` downloads about 400 MB. The scripts build the env
before the session starts, outside the proxy. The pass-through checks use
recording fakes of the user's own tools (e2e.json's `user_tools`, honoured
only under the e2e marker), never the real ssh, git or sudo.

The remote acceptance runs against a disposable Linux VM:

```bash
pixi run --locked python tests/acceptance_remote.py --vm VMDIR --tmp DIR [--only stage,env,...] [--vm-dir NAME --vm-sshd-port N]
```

It reaches the VM at 127.0.0.1:2222, starts a private sshd inside it for the
disruptive steps, and also uses a local sshd. It appends a throwaway key to
the VM user's `authorized_keys` and removes it afterwards, works under
`~/gw-remote` there, and puts the VM user's `~/.bashrc` back byte for byte.
Use only a VM you can throw away.

## The headless e2e suite

```bash
GW_E2E_TMP=DIR pixi run --locked e2e [--only context,ssh,...] [--keep] [--save DIR]
```

Eleven short scenarios, each real `claude -p` sessions (model haiku), mostly
in auto mode, against a scratch copy of the plugin and local test servers.
It uses the **real model API**: a signed-in `claude`, and a few cents per
run. The copy carries an `e2e-root` marker that sends every location into
the scratch folder (see `plugins/gateway/tests/e2e/README.md`). The `jobs`
scenario needs a checkpoint checkout next to this repo, else it is skipped.
`modes` runs one session per `--permission-mode` choice that `claude --help`
lists and records each hook payload's `permission_mode` string: PLAN-0.11
§2.1's table is checked against them. The scenarios were updated for 0.11
(curl asked about, unconfigured hosts and repositories passed to recording
fakes of the user's tools, the checkpoint context only when live); the
whole suite last ran on 2026-10-19, during the v3 build, before the v4
upgrade; not since.

## Before a commit

```bash
git add -A
pixi run release-check          # does the git index hold the tested tree? 0 ready, 1 not, 2 can't tell
claude plugin validate .        # the plugin
claude plugin validate ../..    # the marketplace
```

## Coverage as of 0.9.1

These facts are from the README's status section at 0.9.1 (2026-10-21).
They have not been re-checked for 0.10.0.

"Tested live" means a real Claude Code session in a terminal, driven
automatically against a stand-in model (never the real one), with the plugin
installed from a git marketplace into a throwaway configuration, on macOS
arm64 (Claude Code 2.1.301) and a Debian 13 arm64 VM (Claude Code 2.1.304),
2026-10-21. The live checks ran on 0.9.1, except three on the Linux VM,
which last ran before 0.9.0: the dialogs, the secrets checks and the import
of a macOS export. The repository's own test suite (1231 tests) passed on
both systems, and its mutation checks (1063) on macOS. The install from the
GitHub repository was tested too: on the Linux VM, a fresh install with live
sessions, the `/plugin marketplace add` and `/plugin install` forms, and both
kinds of uninstall while gateway jobs and a terminal run; on macOS, from the
command line, a fresh install, an update from 0.9.0, disable and enable, and
both kinds of uninstall.

| Area | Built | Tested |
|---|---|---|
| Install, first-use setup, update, disable, uninstall | yes | live (macOS, Linux VM) from a local git marketplace; from GitHub as described above |
| The managed shell (Bash, background, subagents, `!`, skills) | yes | live (macOS, Linux VM) |
| Dialogs: sudo passwords, tokens, consent, host keys, vault passphrase | yes | live in the terminal (macOS; the Linux VM before 0.9.0); desktop app **untested** |
| Secrets kept out of transcripts, logs, process lists and telemetry | yes | live in the terminal (macOS; the Linux VM before 0.9.0), with test secrets and telemetry captured before encryption; desktop app untested |
| Terminals and jobs, takeover and hand back | yes | live (macOS, Linux VM) |
| Remote terminals and jobs (the gateway's runtime on another host) | yes | against the Linux VM with a simulated Claude Code, not from a real session |
| Hosts, workspaces, policy; `/gate-hosts`, `/gate-accounts` | yes | live (macOS, Linux VM); a policy "ask" prompt not driven |
| GitHub, Hugging Face, Azure account checks | yes | against local stand-in services only (no real accounts) |
| Encrypted export and import between machines | yes | live, including a macOS export imported on Linux (that import before 0.9.0) |
| Working with checkpoint | yes | live, both plugins installed |
| Storing SSH key passphrases, a cookie store, native Windows | no | |
| Browser or device-code sign-ins | removed on purpose (no web pages) | |

Not tested at 0.9.1: the desktop app, VS Code, mobile and Remote Control
surfaces; x86_64 machines; Windows and WSL; the real GitHub, Hugging Face and
Azure services; the headless e2e suite. The full list, phase by phase, is in
[TEST-LOG.md](TEST-LOG.md) ("Not done or not verified live"). Per Claude Code
surface: [CAPABILITIES.md](../CAPABILITIES.md).

## 0.10.0 verification

Run on 2026-10-22 and 23 (Claude Code 2.1.301 on macOS, 2.1.304 on Linux;
pixi 0.81.0 / 0.82.0; scratch configs and the fake model API throughout).

- The whole suite on macOS arm64: 1275 passed, 0 failed (`claude plugin
  test`: 130 pass; `claude plugin validate` for the plugin and the
  marketplace).
- Every mutation file: 1177 of 1177 killed (mutation_check 76, accounts 72,
  daemon 96, dialogs 78, e2e 26, managed 62, packaging 42, policy 128, remote
  63, ssh 99, sudo 208, terminals 83, ux 144).
- The whole suite on Intel macOS through Rosetta (osx-64 packages): 1275
  passed, 0 failed. Rosetta is not real Intel hardware.
- The whole suite on Linux (Debian 13 arm64 VM): 1275 passed, 0 failed.
- The TUI acceptances on macOS: install 50 of 50, managed 38 of 38,
  terminals 76 of 76, dialogs 63 of 63, canaries 72 of 72, native UI 42 of
  42, remote (against the VM) 39 of 39. On macOS each TUI script's check that
  the real Claude config is unchanged was not performed (the run's rules kept
  it from reading that config). The scripts were updated for 0.10.0's sudo
  default (the consent dialog now comes first); no check was removed.
- The TUI acceptances on Linux: install 50 of 50, its VM-only parts vmplain
  14 of 14 and vmdrain 30 of 30, managed 38 of 38, terminals 76 of 76 (the
  real-config check performed there).
- Not run: the headless e2e suite (it needs the real model API), the desktop
  app (by hand), real GitHub, Hugging Face and Azure accounts, an upgrade
  from an installed 0.9.1 in a live session (unit-tested), an
  install from GitHub of the released version.

## 0.11.1 verification

Run on 2026-10-26 (Claude Code 2.1.310 and pixi 0.83.0 on macOS arm64;
scratch configs and the fake model API): the whole suite, 1695 passed;
the mutation files the patch touched, `mutations_setup.py` 6,
`mutations_relock.py` 41 and `mutations_managed.py` 106, all killed with
no errors; the TUI acceptances `acceptance_install` (non-VM parts) 63 of
63 and `acceptance_managed` 51 of 51, and checkpoint's
`acceptance_independence` 96 of 96. Not rerun for the patch: Linux,
Rosetta and the other mutation files (0.11.0's runs below).

## 0.11.0 verification

Run on 2026-10-24 and 25 (Claude Code 2.1.310, the newest then, on macOS and
Linux; pixi 0.83.0; Python 3.15.1; scratch configs and the fake model API
throughout). Three rounds: each found bugs that were fixed and checked again;
the counts below are the last round's unless a line says otherwise.

- The whole suite on macOS arm64: 1693 passed, 0 failed (`claude plugin
  test`: 146 pass; `claude plugin validate` for the plugin and the
  marketplace).
- Every mutation file: 2147 of 2147 killed, 0 errors, each named test run
  unmutated first (the counts per file are in the table above).
- The whole suite on Intel macOS through Rosetta (osx-64 packages): 1679
  passed (the round before the last fixes; one timing-only rerun). Rosetta is
  not real Intel hardware.
- The whole suite on Linux (Debian 13 arm64 VM, `/bin/sh` dash): 1692 of
  1693 twice; the one failure was a mod test that steps a fake clock through
  20 minutes past the test kit's 5 s limit on 2 CPUs, given `timeoutMs`
  after which `claude plugin test` passed 146 of 146 three times under CPU
  load there. `test_accounts_entra`, which failed every time on Linux before
  the sign-in listener's fix, passed 5 of 5.
- The budgets, as the suite printed them on a loaded Mac (`GW_PERF_STRICT`
  on an idle machine was not run): a Bash call without a trigger word 55 ms
  (sh only), 129 ms while the mode marker exists; a plain account CLI call
  22 ms, 240 ms with an "ask" account, 136 ms while an ask record is
  pending; post.sh 20 ms (sh only), 107 ms with a vault; the git stand-in's
  pass-through median 96 ms against an 80 ms budget.
- The TUI acceptances on macOS: managed 51 of 51, terminals 86 of 86,
  dialogs 67 of 67, canaries 79 of 79 (the WebFetch canary included), native
  UI 71 of 71 (all nine parts, `signin` and `passphrase` included), install
  63 of 63 (the non-VM parts), remote 39 of 39 against the VM. On Linux:
  install 93 of 93 with every part (`vmplain` 7, `vmdrain` 23), managed 51 of
  51, terminals 86 of 86. checkpoint's acceptance_independence (the gateway,
  checkpoint and pixi-guard alone, in pairs and all three) 96 of 96 on both.
  On macOS each TUI script's check that the real Claude config is unchanged
  was not performed (the run's rules kept it from reading that config); on
  Linux it was. The scripts were fixed where the new steps or Claude Code
  2.1.310 needed it (it refuses a foreground `sleep N` with N >= 25 and
  deletes a session's shell snapshot when the session ends); no check was
  removed.
- Permission modes, live: in bypassPermissions an "ask" host's push or ssh
  gets Claude Code's prompt, and declining runs nothing; in dontAsk a bare
  `true` gets no gateway decision and Claude Code refuses it, an explicit
  `dontAsk = "allow"` is approved, and "ask" prompts and runs after Yes.
- Installed from GitHub after the release (Claude Code 2.1.310, pixi 0.83).
  macOS: the untagged and the tag-pinned marketplace installs at the release
  commits and a plain and a `--keep-data` uninstall (all passed), and a live
  session with all three plugins, 27 of 27 (setup ready, checkpoint
  recording, pixi-guard refusing `python3`, curl asked about, the user's own
  ssh untouched, both doctors naming the versions); and a session with pixi
  0.81 saying pixi is too old. Also on macOS: updating gateway 0.10.0,
  checkpoint 0.8.0 and pixi-guard 0.3.0 to these releases. The Debian VM, 31
  of 31: the same live checks, and uninstalling the gateway, with what stays.
  Not covered: the gateway running checkpoint's jobs in a plain install (the
  harness can't point checkpoint at a plain gateway), the drain during an
  uninstall, Claude Code's ssh clone probe.
- Not run: the headless e2e suite (it needs the real model API), the desktop
  app (by hand), a browser sign-in against the real Entra and ML catalog app
  registrations, real GitHub, Hugging Face and Azure accounts, x86-64
  hardware.
