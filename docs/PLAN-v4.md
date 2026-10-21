# Gateway v4 plan (authoritative from 2026-10-19)

This plan implements the upgrade brief for the gateway (`gate@gateway`) and its side of the
integration with checkpoint (`check@checkpoint`). It supersedes SPEC-v3 where they conflict;
SPEC-v3 stays the reference for everything this plan keeps (form, vault format, consent,
stand-ins, ssh, sudo, scrubbing, transfer). Checkpoint's half is
`../checkpoint/docs/PLAN-v4.md`. The contract between them is [CONTRACT-v1.md](CONTRACT-v1.md).
Evidence for every platform claim below is in [FEASIBILITY-v4.md](FEASIBILITY-v4.md).

Versions this plan was checked against: Claude Code CLI 2.1.301 and desktop 2.1.299
(mods need 2.1.287 terminal / 2.1.286 desktop), pixi 0.81.0, macOS 25.6 arm64. The final
acceptance (2026-10-21) also ran on a Debian 13.7 arm64 VM with Claude Code 2.1.304 and pixi
0.82.0; the desktop app was never driven (no way to from the test harness).

## What changes, and which earlier decisions it reverses

The brief is the newest instruction, so where it is explicit it wins over earlier decisions.
Each reversal is listed so it can be reviewed:

| Earlier | v4 | Why |
|---|---|---|
| Invariant 4: `popup.py` (OS dialogs) is the only way to ask | Native Claude Code panes only (a mod); OS dialogs, the `gate secret` terminal path, browser and device-code sign-ins are removed | Brief §3, §11, §11.1: no OS dialogs, web pages, browsers or separate terminals |
| Invariant 14: don't change how Claude's ordinary commands behave | In managed mode (default on, a form setting turns it off) Claude's Bash runs in the gateway's managed bash (landed in phase 4; invariant 14 replaced) | Brief §3, §8: gateway is the default execution route with its own environment |
| Invariant 13: stdlib only | PyNaCl (libsodium) for the broker's sealed boxes; bash (phase 4), tmux and pixi-pack in the env | Brief §11: established crypto; §9 a real supervisor; §8 relocatable remote runtime |
| `private/key.txt` unencrypted beside the vault | Key wrapped by an age passphrase recipient; a broker holds the unlocked key in memory; lock/unlock | Brief §11: secure unlock, lock controls |
| `gate check` recommends blanket `NOPASSWD: ALL` (superseded) | Removed; passwordless only when already configured; otherwise per-call password through the native dialog | Brief §11 |
| Checkpoint owns jobs | Gateway owns jobs, terminals and execution state; checkpoint delegates through the contract and keeps its runner only when gateway is absent | Brief §4 |
| Device-code / browser sign-in for GitHub and Entra | Unavailable under these constraints (labelled); PATs, API keys, service principals through the native dialog; existing refresh tokens keep working | Brief §11 "do not launch or present an authorization webpage" |

Kept: the two ideas (hosts, accounts), the form at `~/.config/gateway/gateway.toml`, the
age vault, consent ratchet (widening needs the user's OK, now in a native pane), direct-only
credentials with `scripts = true`, refuse-unlisted, destination binding, pinned host keys,
scrubbing, audit, nothing in settings.json, only Claude Code and pixi to install.

## Architecture

```
Claude Code process
 ├─ gate mod (hooks/mod/*.tsx)  native panes, commands, status line, tool.call gate,
 │    │                         CLAUDE_CODE_SHELL_PREFIX, credential dialog (Client + sealed box)
 │    └─ $.http.fetch(socketPath) ─┐
 ├─ classic hooks (hooks.json)     │  fail-safe guards that hold without mods (Anthropic can
 │                                 │  switch mods off): file guard, Bash approval, output masking
 ├─ MCP server "gw"  ──────────────┤  agent tools: hosts, terminals, jobs, http, download, files
 └─ Bash tool → gate-sh (prefix) → managed bash (curated env, gateway rc)
                                   │
gated (per user, detached, survives sessions) ◄┘  Unix socket, peer pid authentication
 ├─ broker: unlocked vault key, sealed-box intake, clipboard intake, stand-in requests
 ├─ supervisor: tmux server (private socket, gateway config) for local PTYs and jobs;
 │              remote tmux in the managed remote runtime over ssh (ControlMaster)
 ├─ input ownership, bounded output, event log (seq/epoch), contract v1 endpoints
 └─ remote runtime manager: pixi-pack artifacts per platform, stage, verify, start, clean
stand-ins on PATH (sudo, ssh, git helper, gh, hf, ...) ask gated instead of reading the vault
```

### Planes on the socket (peer authentication by pid via getpeereid / SO_PEERCRED)

- **UI plane** (credential intake, approvals, takeover, unlock, management writes): only the
  Claude Code process itself (the mod's `$.http.fetch` runs in it), never a descendant. Any
  installed mod runs inside that process too; Gateway cannot defend against a malicious
  plugin (documented boundary).
- **Agent plane** (stand-ins, MCP server): descendants of a Claude Code session, with the
  existing ancestry rules (direct only, `scripts = true` opt-in).
- **Contract plane** (checkpoint): CONTRACT-v1, read state and control jobs by id.

### Credential dialog (brief §11.1), as proven in FEASIBILITY-v4

1. A stand-in or tool needs a secret → `gated` creates a request (id, host, account, purpose,
   kind, an X25519 keypair whose private half never leaves `gated`).
2. The mod opens a pane: host / account / purpose / what is asked, a `Client` masked field
   ("click the field, then type"), **Paste from clipboard**, **Cancel**.
3. Typed keys reach only the Client (no composer, no other plugin's hooks, no transcript). On
   Enter the Client seals the value with vendored TweetNaCl `box` to the request's public key
   and posts `{request, ephemeral_pub, nonce, box}`; the mod forwards that ciphertext.
   **Paste from clipboard** makes `gated` read the OS clipboard itself (pbpaste / wl-paste /
   xclip / xsel), so a pasted token never passes through Claude Code.
4. `gated` opens the box (PyNaCl), rechecks the request (still pending, host/account/rights,
   not cancelled, task not paused), uses it for that exchange or stores it encrypted if the
   user chose "remember", and answers an opaque status. The conversation shows only
   "credential supplied for <account> on <host>".
5. Client state, broker buffers and the request keypair are dropped on success, cancel,
   timeout or error (Python strings can't be wiped; documented).
6. While a dialog is pending, a `prompt.edit` guard swallows composer typing ("click the
   field first"); it cannot hide those stray keys from other plugins or the one-frame paint.
   (2026-10-21: it answers with what it let the box hold, never the draft an edit came
   with; it checks the box after the typing stops; `prompt.submit` drops a stray prompt.)
7. Surfaces: terminal (verified) and desktop app (built for it, untested: a manual check).
   Mobile, VS Code, Remote Control, `-p`: credential entry unavailable, reported as such;
   nothing is asked any other way.

### Managed execution (brief §3, §8)

`gate-sh` is set as `CLAUDE_CODE_SHELL_PREFIX` by the mod at `session.start`. It gets one
argument. A classic hook string runs exactly as Claude Code runs it without a prefix
(`/bin/sh -c "$1"`). A Bash-tool script (Claude's `source <snapshot> ... eval '<cmd>' ...
pwd -P >| <cwd file>` shape) runs under the env's bash with the snapshot `source` replaced by
the gateway rc and a curated environment: minimal platform variables, the gateway PATH
(stand-ins, runtime tools, then system dirs), selected imports from the host (each with its
origin, shown by `/gate-doctor`), no user rc, aliases, functions or credential variables.
Unknown shapes or an unready runtime are reported, never silently run in the login shell.
Without mods (switched off, old Claude Code) the classic Bash hook reports "managed shell
unavailable" in managed mode (deny with the reason, or the form's `managed = "warn"` to run
in the host shell with a visible notice).
As built (phase 4, docs/modules/managed.md): the mod also sets `CLAUDE_CODE_SHELL` to the
managed bash once the env is built (Claude Code then starts gate-sh from it rather than the
login shell); gate-sh replaces only the snapshot's `source` and keeps the rest of the script
byte for byte (other plugins' env files arrive inline in it); its settings (`conf`,
`rc.bash`, `state.json`) are written by managed.py into `$DATA/managed/` and renewed by
gate-sh itself when gateway.toml is newer; imports are `[shell] import_path` /
`import_env`, consented under the "settings" entry; the gw tool `host_inspect` is the
read-only host inspection.

### Terminals and jobs (brief §9)

tmux from the env, on a private socket under the run dir, with a gateway tmux config (no
user tmux.conf). `gated` keeps the ids, owner (agent | user), screen sequence, bounded output
and exit state; `remain-on-exit` keeps exit status. Agent tools read bounded screen state
(`capture-pane`, last N lines, cursor, mode) and send input only as the owner, quoting the
screen sequence they read (stale → refused, re-read). The terminal pane draws the screen in a
`Client` and batches keys with sequence numbers; Ctrl-] is a prefix for ^C/^D/^Z/Esc (the
engine keeps those keys); takeover flips the owner at once and drops queued agent writes.
A password prompt (ECHO off on the PTY) opens the credential dialog and the broker writes the
value to the PTY. Survival: Claude restart and plugin reload yes (tmux and gated outlive the
session); gated crash: tmux sessions survive and are re-adopted; SSH disconnect: remote tmux
survives, reattach on reconnect; reboot: nothing survives, reported as gone.

### Remote runtime (brief §8)

`pixi-pack` builds a relocatable environment (bash, tmux, coreutils-light helpers, python
for the remote helper) per target platform (linux-64, linux-aarch64, osx-arm64, osx-64),
cached under plugin data. Staging over the gateway's own ssh/sftp to
`~/.local/share/gateway-runtime/<version>-<platform>/` (or the host record's path), sha256
checked, unpacked with the static `pixi-unpack`, readiness probe, old versions removed. No
elevation, no remote rc changes, no remote pixi install. Unsupported platforms or a full disk
are reported with the remedy.
As built (phase 6, docs/modules/remote.md): the runtime is its own workspace
(`runtime/pixi.toml` + lock: bash 5 and tmux 3, no Python; version = the lock's sha256
prefix), packed by the gateway env's pixi-pack on first need; the target's pixi-unpack
(not static: it brings openssl and libgcc_s by rpath) comes out of its conda packages
(`--directory-only`, extracted locally with zstd); staging goes on ssh's stdin (no sftp),
sha256 is checked on the host (sha256sum, shasum, openssl, else read back); every command
is `exec /bin/sh -c` behind a marker and checks the host record's marker in the runtime;
the machine id is read at each new master and stored with the host keys; changed host
keys or machines are gated-owned confirmations; remote panes are polled, never assumed
(disconnected, waiting_auth, unknown).

## Requirements matrix (final, 2026-10-21, plugin 0.9.0)

Status: **implemented**, **partial**, **missing**, **blocked** (needs access or a
capability this work doesn't have; named), **deferred** (left out on purpose; why).
Validation, separate from status: **automated** (the repo suite and mutations on
macOS arm64: 1214 tests, 1019 of 1019 mutations, 2026-10-21), **VM Linux** (the same
suite on the Debian 13 arm64 VM: 1203 of 1203 on the tree before the acceptance
fixes), **synthetic e2e** (a real gated driven by a FakeClaude that draws and answers
the dialogs as the mod would, or a one-off probe), **live TUI** (the real Claude Code
TUI in a PTY against the harness's fake Messages API, both plugins installed from
git-source marketplaces into a scratch config: "installed copies"; macOS = Claude Code
2.1.301, VM = the Debian VM's 2.1.304, fresh from `./vm.sh clean`), **untested**.
Paths are relative to `plugins/gateway/` (Python modules in `src/gateway/`, the daemon's in `src/gateway/daemon/`) unless they start with `docs/` or `../`. The acceptance
scenario numbers (14.x) are the brief's; their results are in the completion report.

| § | Requirement | Status | Code evidence | Validation | Gap, or what blocks it |
|---|---|---|---|---|---|
| 2 | Normal marketplace install, update, disable, uninstall; dev route documented | implemented | `../.claude-plugin/marketplace.json` (`gateway` → `gate`), `.claude-plugin/plugin.json`; README "Install", "Update, disable, uninstall" | live TUI (macOS, VM): `tests/acceptance_install.py` 50/50 each after the fixes (add, install, first use, update after a restart, `--keep-data`, uninstall); the VM's plain install (no e2e marker) 13/13 before them | the `/plugin` slash forms weren't driven (shell forms only); blocked: the real GitHub marketplace (the tree is uncommitted; GitHub's `main` is 0.6.0), so a local smart-HTTP git server served the working tree |
| 2 | Pinned deps (committed pixi.toml + pixi.lock), `--locked`, tested pixi range | implemented | `pixi.toml` (`requires-pixi = ">=0.68.0"`, no upper bound), `pixi.lock` (v7), `hooks/launch.sh` (`pixi install --locked --manifest-path`), `hooks/mod/lib.ts` (`PIXI_TESTED_MIN/MAX`) | automated (`test_packaging`: lock vs manifest offline, bounds, no `--frozen`); probe (0.68.0-0.82.0 install the lock unchanged, 0.61-0.67 refuse; macOS only); live TUI with pixi 0.81.0 (macOS), 0.82.0 (VM) | the range was probed on macOS only |
| 2 | Launcher needs only Claude Code + pixi; no undeclared bootstrap shell or interpreter | implemented (macOS, Linux) | `hooks/launch.sh` (POSIX `sh`, the OS's own), `.mcp.json`, `hooks/hooks.json` (exec form), the mod's `$.process.spawn` argv (`hooks/mod/register.tsx`) | live TUI (macOS, VM): recording shims for python3/python/node/npm/npx/uv saw 0 plugin calls; the VM had no git and no system tool beyond the OS | native Windows has no POSIX `sh`: deferred (WSL 2; row "Targets") |
| 2 | Git for git marketplaces: a verified pixi-assisted route | implemented (docs) | README "Before you install" | live (macOS, VM): `pixi global install git` (scratch PIXI_HOME) 2.1 s / 1.2 s; marketplace add/install/update with only that git | it lands in `~/.pixi/bin`; the VM's pixi installer hadn't put that on PATH, so `marketplace add/update` needed it (remedy in README "Known limitations") |
| 2 | Idempotent, concurrency-safe first-use provisioning with progress; interrupted-setup recovery; cold-start timeouts | implemented | `hooks/launch.sh` (`ensure-env`, the build lock `<env>.building` with builder and pixi pids + start times, `status`, managed settings written before the warm step), `src/gateway/warm.py`, `hooks/mod/lib.ts` + `register.tsx` (status line `setting up…`, `finishing setup…`, `ready`) | automated (`test_packaging` kills a build halfway); live TUI (macOS, VM): cold pixi cache (428 MB), `pixi install` SIGKILLed 0.2 s in, the next session took over and finished in 4.6 s / 2.3 s, never two installs; the first Bash after "gate: ready" ran first try (after the fix; before it, exit 75 for 8.5-10.2 s on macOS) | none open |
| 2 | A cold or timed-out bootstrap never disables security controls | partial | `hooks/launch.sh` degraded file guard and `degraded_bash` (byte-identical to `src/gateway/envfile.py`), `hooks/gate-sh` exit 75 until the managed settings exist; SessionStart writes its files first (`pre_session`) | automated (+ mutations); live TUI (macOS: the cold-start denies; `-p` with pixi hidden) | until the very first build finishes, output masking and the rights checks are off; only the sh text guard holds (documented; wait for "gate: ready") |
| 2 | Offline warm start; cwd honoured; spaces and non-ASCII paths; concurrent sessions | implemented | `hooks/launch.sh`, `src/gateway/paths.py`, `hooks/gate-sh` (Claude Code's cwd tracker kept byte for byte) | live TUI (macOS, VM): pixi refusing every call + a dead proxy: 0 pixi calls over 3 sessions; project `proj dir ü/sub dir ö`, config `cfg dir ü`; two concurrent sessions (checkpoint's `acceptance_durability.py`) | none |
| 2 | Versioned content separate from mutable state; uninstall behaviour; retention and backup | implemented | `-X pycache_prefix` (`envfile.py_flags`, `daemon/lifecycle.daemon_argv`), state in `$CLAUDE_PLUGIN_DATA` and `~/.config/gateway`, `audit.py` rotation, `transfer.py` import backups; README "Data, retention, backup" | automated; live TUI (macOS, VM): update kept the env folder (0 pixi calls), uninstall removed the data folder and kept `~/.config/gateway`, `--keep-data` kept the env | none (backup = `gate export` or a copy of `~/.config/gateway`) |
| 2 | Targets: macOS, Linux, Windows; WSL distinct | partial | lock platforms osx-arm64, osx-64, linux-64, linux-aarch64 (`pixi.toml`, `runtime/pixi.toml`) | macOS arm64: everything; Linux arm64: VM Linux + live TUI (VM); x86-64: untested | blocked: no x86-64 machine (Intel Mac, Linux x86-64) here; native Windows deferred (POSIX `sh` hooks, no win-64 in the lock, POSIX-only modules: use WSL 2); WSL 2 blocked: no Windows machine |
| 2 | The gateway provisions its remote runtime | implemented | `runtime/pixi.toml` + lock (bash 5, tmux 3), `src/gateway/runtime_pack.py`, `src/gateway/daemon/remote.py` | automated (`test_remote`: real sshds on 127.0.0.1); synthetic e2e (`tests/acceptance_remote.py` 39/39: staged on the VM, which has no tmux, in 3.1 s) | not driven from a Claude Code session; linux-64 and osx-64 hosts blocked (none available) |
| 3 | Smallest native component set; capability matrix; minimum versions | implemented | `hooks/hooks.json` (classic hooks + `modules`), `hooks/mod/`, `.mcp.json` (`gw`, `alwaysLoad`), `commands/`, `skills/gateway/`; `docs/CAPABILITIES.md` = `hooks/mod/lib.ts` `CAPABILITIES` | automated (`test_mod`: the two tables equal; `claude plugin validate`, `claude plugin test` 108 pass); live TUI | the doctor's cells are conservative after the 2026-10-21 runs (CAPABILITIES notes) |
| 3 | Every plugin UI inside Claude Code; no OS dialog, browser, webview or window | implemented | `src/gateway/daemon/dialogs.py`, `popup.py`/`dialog.py` (no OS backends), `hooks/mod/dialog.ts`, `field.tsx`, `term.tsx`, `manage.ts` | live TUI (macOS, VM): shims for open, osascript, xdg-open, zenity, kdialog, notify-send, wslview, gio, browsers and terminal programs: 0 runs; VM `strace -f` over the native-UI run: 1482 execs, 0 banned; static scan of the shipped files: 0 calls | macOS has no unprivileged exec tracer, so absolute-path execs and API launches there rest on the static scan; desktop app blocked (row 11.1) |
| 3 | Secret entry verified per surface and transport | partial | `hooks/mod/field.tsx` (Client), `seal.ts` (TweetNaCl box), `daemon/dialogs.py` (PyNaCl, recheck), `daemon/clipboard.py`, the guard (`dialog.ts guardEdit`, `register.tsx`) | live TUI terminal (macOS, VM): `acceptance_canaries.py` 71/71, `acceptance_dialogs.py` 62/62 each after the fixes | desktop app blocked: the TUI harness can't drive it (FEASIBILITY-v4 P4); manual checklist in the completion report. VS Code, mobile, Remote Control, `-p`: no `Client` surface (P1), so entry is reported unavailable by design. Terminal main screen: no clicks reach plugins, Paste only |
| 3 | Gateway is the default execution route (Bash, background, subagents, `!`, skills) | implemented | `hooks/gate-sh`, `src/gateway/managed.py`, the mod's `managedSetup` (`CLAUDE_CODE_SHELL_PREFIX`, `CLAUDE_CODE_SHELL`, `GW_MANAGED_DIR`) | automated (`test_managed` + mutations); live TUI (macOS, VM): `acceptance_managed.py` 38/38 each (the VM's 34/38 before were test assumptions) | Monitor: code evidence only (not offered against the fake API: a server-side gate) |
| 3 | Interception keeps permissions, hooks, cancellation, results | implemented | `hooks/gate-sh` (one exec, the script byte for byte but the snapshot's `source`) | live TUI against a baseline session without the gateway (macOS, VM): permission dialog and "don't ask again" on the original command, Pre/PostToolUse payloads, results, exit codes, Escape, timeouts | none |
| 3 | Paths that can't be enforced are reported or restricted | implemented, with stated limits | `src/gateway/hooks_bash.py` (`managed shell unavailable`, `warn`; alternate routes `_route_changes`, `_route_text`), `docs/modules/managed.md` "Alternate routes" | automated (+ mutations); live TUI (macOS): without the mod, the deny and the warn notice | without mods the user's `!` and skills' injection reach no hook (run unmanaged, documented); a script that runs `/usr/bin/ssh` itself gets the user's own credentials, never the gateway's; the desktop Terminal panel is the user's shell |
| 4 | Versioned contract: discovery, sanitized events, snapshots, job control | implemented | `daemon/server.py` (`/v1/*`), `daemon/lifecycle.py` (contract.json), `daemon/events.py`, `daemon/terminals.py`; `docs/CONTRACT-v1.md` (byte-identical in checkpoint, `test_workspaces`) | automated; live TUI (macOS, VM): checkpoint's `acceptance_gateway.py` 27/27, `acceptance_independence.py` 49/49 | none |
| 4 | Stable ids; correlation; duplicates; reconnects; schema evolution | implemented | `m_`/`w_`/`t_`/`j_`/`o_` ids, seq per epoch, idempotency keys (24 h), `pause_id` replay (`daemon/terminals.py`, `server.py`) | automated (`test_daemon`, `test_terminals`, `test_workspaces`); live TUI via checkpoint's delegation | a gateway listing versions [1, 2] wasn't tested (only [2] and [1]) |
| 4 | No secrets on cross-plugin channels | implemented | `events.clean` (allowlisted keys and values), scrubbed commands and tails | automated (canaries in events, snapshot, capabilities, health, contract.json, the registry, the log; + mutations); live TUI: canary scans of checkpoint's state 0 hits | checkpoint's own-runner job logs (used only without the gateway) keep raw output |
| 4 | Works alone, with checkpoint, either disabled, incompatible versions | implemented | the gateway keeps its own job records; `daemon/lifecycle.py` exits when its plugin folder is removed or orphaned and no session uses it | live TUI (macOS, VM): `acceptance_independence.py` 49/49 after the fixes; daemon gone 0.7 s after `claude plugin uninstall` | a merely disabled gateway's daemon lives until its idle exit (30 min) but refuses that session's calls (checkpoint 0.7.1 says so) |
| 4 | Authenticated local control channels bound to user and session | implemented | `daemon/peers.py` (LOCAL_PEERPID + LOCAL_PEERCRED, SO_PEERCRED), `daemon/planes.py` (UI, agent, contract, lease, local) | automated (+ `mutations_daemon.py`); VM Linux | a guardrail against same-user code, not a boundary (`docs/modules/daemon.md`) |
| 8 | Own bash locally and remotely; no login rc, aliases, PATH or credentials | implemented | `hooks/gate-sh` (`env -u`, no value on a command line), `managed.py`; remote: `daemon/remote.py`, `daemon/terminals.py` (`env -i` start file, `--noprofile`) | live TUI local (macOS, VM): a credential canary in Claude Code's environment never reached a command; synthetic e2e remote: a `~/.bashrc` probe on the VM never reached the managed shell | none |
| 8 | Permissioned host inspection; selective imports with origin | implemented | `managed.inspect` (`host_inspect`), `[shell] import_path`/`import_env` (`form.py`, `consent.py`), remote `RemoteHost.inspect`, `[hosts.NAME.shell]` | automated (`test_managed`, `test_workspaces`); live TUI local (macOS, VM) | remote inspection and imports ran against a local sshd only, not the VM |
| 8 | Managed remote runtime: stage, verify, start, update, clean, report | implemented | `daemon/remote.py`, `runtime_pack.py`, the gw tool `host_runtime` | automated; synthetic e2e (VM) | noexec mounts and a full disk only in the suite (no such mount or filled disk on the VM) |
| 9 | Persistent PTYs locally and remotely: screen, resize, signals, exit codes | implemented | `daemon/terminals.py`, `daemon/screen.py`, the env's tmux 3 | automated; VM Linux; live TUI local (macOS, VM): `acceptance_terminals.py` 63/63 each; synthetic e2e remote | remote panes only at the daemon level; `waiting_input` isn't detected (missing) |
| 9 | Shared terminal in the native UI; one writer; takeover; revalidation | implemented | `hooks/mod/terminal.ts`, `term.tsx`, `/gate-terminal`; ownership in `daemon/terminals.py` | automated (+ `mutations_terminals.py`); live TUI (macOS, VM): takeover with Claude's input queued, hand back to the same shell | desktop pane blocked (manual check) |
| 9 | Secure entry for PTY prompts | implemented | tty ECHO/ICANON detection and `load-buffer -`/`paste-buffer -d` (`daemon/terminals.py`), the sudo stand-in's terminal route | live TUI (macOS, VM): sudo's prompt answered in the dialog, canary nowhere; VM Linux: the VM's real sudo through the dialog (phase 5 probe); synthetic e2e remote | none |
| 9 | Supervisor survival; ask before reattaching | implemented | re-adoption by id and nonce, the `gw-watch` watchdog (`daemon/terminals.py`), remote pollers | automated; live TUI (macOS, VM): a Claude Code restart re-adopts the terminal; synthetic e2e: the VM's sshd and master gone, jobs reported running/exited/unknown honestly | a host reboot wasn't exercised (reported gone by design) |
| 10 | Host records: machine identity, endpoints, accounts, keys, workspaces, path maps, runtime | implemented | `form.py`, `vault.py` (host keys, `machine_id`), `<data>/gated/remote.json`, `[hosts.NAME.workspaces.W]` | automated; synthetic e2e (the VM's machine id) | none |
| 10 | Own SSH identities, known hosts, agents; explicit import | implemented | `ssh.py`, `ssh_conf.py`, `gate import-ssh` | automated (local sshds); synthetic e2e | none |
| 10 | Keepalives, jump hosts, reuse, timeouts, forwarding only by explicit config | implemented | `ssh_conf.py` (ControlMaster, ProxyJump), `ssh_args.py`, per-host forwarding grants (`policy.py`) | automated (`test_policy` against a local sshd) | hosts behind `via` untested live |
| 10 | Every operation bound to host, account, workspace; target visible | implemented | `Supervisor._bind`, `_tm`, `bind_check` (`daemon/terminals.py`), `ssh_args.decide_path`, the approval hook's elevation notice | automated; synthetic e2e (the same path on two machines; a moved address blocked) | the elevation notice and a policy "ask" prompt weren't seen in a live session |
| 10 | Local/remote classification after import | implemented | `transfer.py` (format 3 import: host keys or machine token), `migrate.py` | automated (`test_portability`, `test_transfer_roundtrip`); live TUI: a macOS export imported in the VM (this machine asked for, the Mac's localhost became a remote host, the VM's localhost unchanged) | reachability of an imported remote host wasn't checked live |
| 11 | Vault and broker; tools never return raw secrets | implemented | `vault.py` (age), `daemon/broker.py` (scoped views), `agepass.py` | automated; VM Linux; live TUI: the http tool's result shows `Bearer ***` while the local service got the key (sha256) | none |
| 11 | Coverage: API keys, PATs, SSH keys and passphrases, HTTPS, OAuth, SSO/MFA, sudo, cookies | partial | `adapters.py`, `gate_setup.py`, `githelper.py`, `entra.py`, `sudo.py`, `ssh.py` | automated (local API servers) | ssh key passphrases aren't stored (passphrase-protected keys refused; the gateway makes its own keys): missing. No cookie or session store: no adapter needs one. Browser and device-code SSO/MFA: deferred, unavailable under the brief's no-browser rule (existing refresh tokens keep working) |
| 11 | Adapters with configured, connected, expired, revoked, reauthentication states | implemented | `adapters.py` (GitHub, Hugging Face, Azure secret / certificate / refresh token) | automated (local API servers); live TUI: the accounts pane, "stored, not checked yet", Check | blocked: no authorized GitHub, Hugging Face or Azure test accounts, so no real-service run |
| 11 | Native setup and entry; secure unlock; lock, revoke | implemented | `/gate-unlock`, `/gate-lock`, `gate lock`, `[vault] lock_after` (`daemon/lifecycle.py`, `daemon/dialogs.py`) | automated; live TUI (macOS, VM): set a passphrase (two fields), lock, wrong then right unlock | `lock_after` isn't under the widening rule (bounded to a day) |
| 11 | No secrets in args, transcripts, history, logs, checkpoints, argv, exports | implemented, with stated exceptions | `scrub.py`, gate-sh `env -u`, values on stdin/FIFOs, `audit._redact`, the paste guard | live TUI (macOS, VM): canaries (raw, base64, hex, URL, JSON, UTF-16, gzip) in transcripts, history, `--debug-file`, fake-API and proxied telemetry payloads, observer records, gateway and checkpoint state, the export, 648 argv samples, PTY output: 0 hits | gh, databricks, dvc and `gate with` hold their token in their environment (`ps eww`, same user); a failed command's, Monitor's and background output can't be masked (Claude Code passes it to no rewriting hook) |
| 11 | Isolation boundary documented and tested on alternate paths | implemented (a guardrail, documented) | `hooks_files.py`, `hooks_bash.py` routes, the wrapped key (`daemon/broker.py`), `daemon/planes.py` | automated (+ mutations); live TUI: `cat` of the vault refused, Read of `key.wrapped` refused, a probe run by the system python got 403 and only ciphertext | not a sandbox against code running as the user (README "Security, honestly") |
| 11 | Sudo: passwordless, prompts, TTY, expiry; no blanket rule | implemented | `sudo.py`, `ssh_sudo.py`; `test_sudo_nopasswd` scans code and docs | automated (fake sudo); VM Linux (real sudo of a test user in a gateway terminal); live TUI (fake sudo, private field) | the real macOS sudo with a password was never run (only `sudo -n true` allowed here); a sudoers file from 0.8 or earlier isn't removed (README) |
| 11 | No browser fallback; unavailable flows labelled | implemented | `gate_setup.py`, `logins.py` (PAT, API key, service principal only) | automated (+ `mutations_dialogs.py`); live static scan | none |
| 11.1 | Native dialog naming host/account/purpose; masked; private from the first key | implemented | `hooks/mod/field.tsx`, `dialog.ts` (the guard), `register.tsx` | automated (mod tests, mutations); live TUI (macOS, VM): 62/62 and 71/71 each after the guard fix (2.1.304 had kept 1-3 typed characters before it) | stray keys typed before the click reach other plugins' `prompt.edit` hooks and are painted for a frame (FEASIBILITY-v4 P1, documented); the guard's `.catch` layer has no mutation (the test kit can't make that hook fail) |
| 11.1 | Sealed delivery to the broker; opaque result; cleanup; recheck before resume | implemented | `seal.ts`, `daemon/dialogs.py` (per-attempt X25519, recheck: open, deadline, session alive and not paused, asking processes, form entry and rights) | automated (+ mutations); live TUI: broker receipt by sha256; checkpoint's pause reaches the recheck through `/v1/pause` | none |
| 11.1 | Never sent to Anthropic, model or telemetry endpoints; per-surface verification | partial | the above; nothing on a command line or in a transcript | live TUI terminal (macOS, VM): the record-only proxy decrypted 17-23 first-party requests per run plus the fake API's log: 0 hits | unobservable here: Anthropic-side processing, requests outside proxy settings (none seen), Claude Code's memory; desktop relay blocked (manual check) |
| 12 | Allow/ask/deny policy per host, workspace, account and action | implemented | `policy.py`, decided in the stand-ins, `daemon/terminals.py`, `managed.py`, `web.py`, `accounts.py`, `hooks_bash.py` | automated (`test_policy`, `test_workspaces`, `mutations_policy.py` 99); live TUI: a workspace added from `/gate-hosts` and its consent | a policy "ask" prompt wasn't driven live |
| 12 | The rule behind a denial; no self-widening | implemented | `policy.Decision.rule`, `consent.py` (ratchet) | automated (+ mutations) | none |
| 12 | Encrypted export/import: selection, conflicts, tamper, wrong passphrase, migration | implemented | `transfer.py` (format 3; formats 1-2 still read), `agepass.py` | automated; live TUI (macOS, VM): checklist, passphrase twice, wrong passphrase asked again, conflict choice, a tampered file refused with its reason (after the fix: the retry reports it), Mac→VM | host-key changes, path differences and refresh-token reauthentication after import: suite only |
| 13 | Namespaced commands, native controls, visibility, diagnostics | implemented | `/gate-doctor`, `/gate-dialog`, `/gate-unlock`, `/gate-lock`, `/gate-terminal`, `/gate-hosts`, `/gate-accounts` (`hooks/mod/register.tsx`), `/gate:status`, `/gate:help` (`commands/`), the `gate` CLI (`src/gateway/gate.py`, `manage.py`) | automated; live TUI (the doctor, the panes, the dialogs) | `/gate:status` and `/gate:help` (Markdown commands, a model turn) not driven live |
| 13 | Responsive startup and hooks | implemented | the sh prefilters (`hooks/pre_bash.sh`, `post.sh`, `mcp_perm.sh`), env built once, the unresponsive-daemon mark (`daemon/client.py`) | live TUI: to the prompt 0.63 s with both plugins vs 0.51 s with none (macOS), 0.50 vs 0.47 s (VM); per Bash call 0.221 s vs 0.041 s (macOS), 0.090 vs 0.028 s (VM); probe: a stopped daemon costs one 5 s wait, then 0.1 s per hook | none |
| 14 | Acceptance scenarios 14.1-14.13 with labelled evidence | partial | `tests/acceptance_install.py`, `acceptance_dialogs.py`, `acceptance_canaries.py`, `acceptance_native_ui.py`, `acceptance_managed.py`, `acceptance_terminals.py`, `acceptance_remote.py`; checkpoint's acceptance scripts | live TUI for every scenario but 14.8 (synthetic) and the desktop app (untested) | desktop app blocked (manual); 14.8 not through a TUI session; the completion report has the table |

## Phases (dependency order)

1. **Foundations.** TUI harness in `plugins/gateway/tests/tui/` (fake API, PTY driver,
   observer plugin, canary scanner, git-source marketplace install into a scratch config).
   Packaging: `--locked`, tested pixi range, build-lock liveness, cold-window guards that
   deny private reads and credential shapes while the env builds, no `__pycache__` in the
   plugin root, release and referenced-files checks, README lifecycle commands, git route,
   Windows/WSL statement. Mod skeleton: hooks.json `modules`, launcher through `$.process`,
   readiness gate, status line, `/gate-doctor` (a mod command can't carry a colon, and
   `/doctor` is Claude Code's; verified on 2.1.301), capability matrix. Packaging and mod
   skeleton landed 2026-10-19 (uncommitted);
   the TUI harness is another group's.
2. **Daemon and broker.** `gated` (socket, peer auth, lifecycle, health, event log,
   contract v1), passphrase-wrapped vault key and migration, lock/unlock, stand-ins through
   the broker. Landed 2026-10-19 (uncommitted): `src/gateway/daemon/`, `agepass.py`,
   docs/modules/daemon.md, DECISIONS "PLAN-v4 phase 2"; the passphrase was set and the
   vault unlocked only through test routes until phase 3's native dialog (now
   `/gate-unlock`); job/terminal contract calls wait for phase 5.
3. **Native dialogs.** Credential dialog (Client + TweetNaCl + clipboard intake + guard),
   approvals, consent widening, host-key changes, unlock; dialog.py's OS backends, `gate
   secret`'s terminal path and browser/device sign-ins removed and labelled; canary tests.
   Landed 2026-10-20 (uncommitted): `daemon/dialogs.py`, `daemon/clipboard.py`, the lease
   plane, `hooks/mod/{dialog.ts,field.tsx,seal.ts,vendor/}`, `tests/test_dialogs.py`,
   `tests/mutations_dialogs.py`, `tests/acceptance_dialogs.py`; DECISIONS "PLAN-v4 phase 3".
   Found live: Claude Code 2.1.301 reports clicks only in its fullscreen layout, so the
   field needs `CLAUDE_CODE_NO_FLICKER=1` there (else Paste from clipboard).
4. **Managed execution.** `gate-sh`, gateway rc, curated environment, origin-labelled
   imports, host inspection tool, behaviour without mods. Landed 2026-10-20
   (uncommitted): `hooks/gate-sh`, `src/gateway/managed.py`, `[shell]` in the
   form and its consent, the mod's `managedSetup`, the classic hook's
   "managed shell unavailable", the gw tool `host_inspect`, bash in pixi.toml;
   `tests/test_managed.py`, `tests/mutations_managed.py`,
   `tests/acceptance_managed.py`; docs/modules/managed.md, DECISIONS "PLAN-v4
   phase 4". Found live: Claude Code honours a `CLAUDE_CODE_SHELL` set at
   session start, so the managed bash also starts gate-sh; exec-form hooks are
   never prefixed; other plugins' env files arrive inline in the script.
5. **Terminals and jobs.** tmux supervisor, MCP tools, terminal pane, ownership, PTY secret
   entry, contract job calls, checkpoint delegation support. Landed 2026-10-20 (uncommitted;
   plugin 0.8.0): `daemon/terminals.py`, `daemon/screen.py`, the agent-term, pane and job
   routes, the gw `terminal_*`/`job_*` tools, `hooks/mod/{terminal.ts,term.tsx}` and
   `/gate-terminal`, the sudo stand-in's terminal route, the hook's judging of
   `job_start`/`terminal_send`, tmux in pixi.toml; `tests/test_terminals.py`,
   `tests/mutations_terminals.py`, `tests/acceptance_terminals.py`,
   `hooks/mod/terminal.test.ts`; docs/modules/terminals.md, DECISIONS "PLAN-v4 phase 5".
   Found live: the space bar reaches a Client as the key `space`; tmux resumes a pane
   stopped by SIGSTOP; Linux's tmux names a dead pane's signal by number.
6. **Remote runtime.** pixi-pack artifacts, staging, verification, remote terminals and jobs,
   reconnect, host identity and host-key change flow. Landed 2026-10-20 (uncommitted):
   `runtime/pixi.toml` + `pixi.lock`, `src/gateway/runtime_pack.py`, `daemon/remote.py`, remote
   panes in `daemon/terminals.py`, gated-owned confirm/info dialogs, the gw tool
   `host_runtime` and `host` on `terminal_open`, the form's `runtime` key under consent,
   pixi-pack and zstd in pixi.toml; `tests/test_remote.py`, `tests/harness_remote.py`,
   `tests/mutations_remote.py`, `tests/acceptance_remote.py`; docs/modules/remote.md,
   DECISIONS "PLAN-v4 phase 6". Found live: the conda pixi-unpack needs its openssl and libgcc
   libraries next to it; the local pixi-unpack refuses another platform's pack; Debian's bash
   reads `~/.bashrc` for ssh commands (outside the managed shell).
7. **Hosts, policy, accounts, portability.** Workspaces and path maps, policy dimensions,
   adapter states, sudo changes, export/import selection UI. Landed 2026-10-20 (uncommitted;
   plugin 0.9.0): `policy.py`, `adapters.py`, `manage.py`, the policy/workspace/shell tables
   in `form.py` and `consent.py`, gated's `_bind`, `/ui/manage` and remote inspection and
   imports, transfer format 3, the sudo changes, the hook's alternate-route checks and
   elevation notice, `hooks/mod/manage.ts` and `/gate-hosts`/`/gate-accounts`, the pause
   binding and `pause_id`; `tests/test_policy.py`, `test_workspaces.py`,
   `test_accounts_states.py`, `test_portability.py`, `mutations_policy.py`,
   `hooks/mod/manage.test.ts`; docs/modules/policy.md, DECISIONS "PLAN-v4 phase 7",
   CONTRACT-v1 (additive). Found while building: snapshot reads that counted as vault uses
   kept an idle vault unlocked; a stderr target notice broke merged-output commands (now a
   hook systemMessage).
8. **Acceptance and docs.** Brief §14 scenarios on marketplace-installed copies in scratch
   configs, docs, final matrix, completion report. Done 2026-10-21: new acceptance scripts
   `tests/acceptance_install.py`, `acceptance_canaries.py`, `acceptance_native_ui.py` (and
   checkpoint's `acceptance_independence.py`, `acceptance_durability.py`); every scenario ran
   in the live TUI on macOS and the Debian VM except 14.8 (synthetic, daemon level) and the
   desktop app (untested). The defects they found were fixed the same day (DECISIONS
   "Acceptance fixes"; the guard, "gate: ready" before the managed shell, `localhost` as a
   reserved word, a dialog job's lost answer, the daemon after uninstall, the hung-daemon
   stall, tmux after SIGTERM) and the affected scripts re-run green on both machines. The
   matrix above is the final one; the completion report (outside the repo) has the scenario
   table.

Checkpoint's phases run alongside (separate repo); its contract client needs phase 2's
socket and phase 5's job calls.

## Rules for this work

- Never read, list or change the real `~/.config/gateway`, never install into the real
  Claude config (`~/.config/claude`): scratch `CLAUDE_CONFIG_DIR` and test roots only.
- Synthetic canaries are generated inside tests and never printed or put in a prompt.
- Every behaviour change gets a test; every security property gets a mutation.
- No git commits, pushes or installs without the user's say-so.
