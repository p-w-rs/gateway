> Developer documentation: how the gateway's tests run, and what was tested for each release. Results of past runs: [TEST-LOG.md](TEST-LOG.md).

# Testing

Run everything from `plugins/gateway`. The tests never touch your real
`~/.config/gateway`, your Claude Code configuration, your clipboard, your
tmux server or a real remote machine. Two parts are exceptions, and say so
below: the remote acceptance (a disposable Linux VM) and the headless e2e
suite (the real model API).

| What | Command | Time |
|---|---|---|
| The suite | `pixi run --locked test` | about 6 to 8 minutes, 4 modules at a time |
| Mutations | `pixi run --locked mutations` | about 20 minutes, 3 files at a time |
| The mod's own tests | `claude plugin test .` (also run inside `test_mod`) | seconds |
| TUI acceptances | `tests/acceptance_*.py` (a real interactive `claude`, a fake API) | 1 to 5 minutes each |
| Remote acceptance | `tests/acceptance_remote.py --vm VMDIR` | about 1 minute |
| Headless e2e | `pixi run --locked e2e` (real `claude -p`, real model) | about 7 minutes |
| Release check | `pixi run release-check` | seconds |

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
- On Linux, put `GW_TEST_TMP` under `/tmp`, and don't name it `/tmp/gw-*`
  (the file guard's tests take that for the run folder). A temp folder under
  `$HOME` fails the e2e marker's temp-folder rule.

## Mutations

```bash
pixi run --locked mutations                                         # every file, each on its own scratch copy
pixi run --locked python tests/run_mutations.py mutations_policy.py -k SUBSTR   # one file, some mutations
```

Each mutation weakens one guard: it replaces a snippet of the code with a
weaker version and names a test that must then fail ("killed"). The runner
copies the plugin once per file under `GW_TEST_TMP`, so the checkout is never
edited. It exits 1 when a mutation survives or a snippet isn't found exactly
once. Never run a mutation file directly without `--copy DIR`: that edits
the checkout.

Every security property needs a mutation. When a change moves a snippet,
update the snippet; the run reports the ones it couldn't place.

The files in the working tree (1177 mutations):

| File | Mutations |
|---|---|
| `mutation_check.py` (core) | 76 |
| `mutations_accounts.py` | 72 |
| `mutations_daemon.py` | 96 |
| `mutations_dialogs.py` | 78 |
| `mutations_e2e.py` | 26 |
| `mutations_managed.py` | 62 |
| `mutations_packaging.py` | 42 |
| `mutations_policy.py` | 128 (4 of them need `test_terminals`) |
| `mutations_remote.py` | 63 |
| `mutations_ssh.py` | 99 |
| `mutations_sudo.py` | 208 |
| `mutations_terminals.py` | 83 (all need `test_terminals`) |
| `mutations_ux.py` | 144 |

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

Needs: Python 3.12 with `pyte` (through `pixi exec`), `claude` on PATH, and
`git` on PATH (Claude Code clones git marketplaces with it).

```bash
pixi exec --spec python=3.12 --spec pyte python tests/tui/selftest.py [--only t]   # the harness itself
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_install.py   --tmp DIR [--checkpoint DIR] [--only ...]
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_dialogs.py   --tmp DIR --pixi-cache DIR2
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_canaries.py  --tmp DIR [--pixi-cache DIR2] [--checkpoint DIR]
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_native_ui.py --tmp DIR [--pixi-cache DIR2] [--only ...]
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_managed.py   --tmp DIR --pixi-cache DIR2 [--only ...]
pixi exec --spec python=3.12 --spec pyte python tests/acceptance_terminals.py --tmp DIR --pixi-cache DIR2 [--no-proxy]
```

| Script | What it checks |
|---|---|
| `acceptance_install.py` | Both plugins from git marketplaces with only `claude`, pixi and git on PATH: first-use setup, an interrupted setup, a warm and an offline start, an update, both kinds of uninstall, paths with spaces. Its `vmplain` and `vmdrain` parts run only on a disposable VM (`ACCEPTANCE_DISPOSABLE_VM=1`). |
| `acceptance_dialogs.py` | Every native dialog, live. |
| `acceptance_canaries.py` | Canaries through every input route, with both plugins; transcripts, logs, process lists and telemetry scanned. |
| `acceptance_native_ui.py` | `/gate-hosts`, `/gate-accounts`, export, import and a tampered import; nothing opened outside Claude Code. |
| `acceptance_managed.py` | The managed shell against a baseline session without the gateway: every route, hooks, permissions, cancel, `-p`, no mods. |
| `acceptance_terminals.py` | The terminal pane: a full-screen program, resize, signals, takeover and hand back, sudo's password prompt through the dialog, jobs, a restart. |

A cold `--pixi-cache` downloads about 400 MB. The scripts build the env
before the session starts, outside the proxy.

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

Ten short scenarios, each real `claude -p` sessions (model haiku) in auto
mode against a scratch copy of the plugin and local test servers. It uses the **real model API**: a
signed-in `claude`, and a few cents per run. The copy carries an `e2e-root`
marker that sends every location into the scratch folder (see
`plugins/gateway/tests/e2e/README.md`). The `jobs` scenario needs a
checkpoint checkout next to this repo, else it is skipped. The whole suite
last ran on 2026-10-19, during the v3 build, before the v4 upgrade; not
since.

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

