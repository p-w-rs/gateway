> Developer documentation: the code's modules and their APIs, for people changing the code. To use the plugin, read the [README](../../README.md).

# Gateway v3 modules

The modules of gateway v3 (written for plugin 0.7.0; the tables and the
per-group docs below are kept current through PLAN-v4 and PLAN-0.11, plugin
0.11.0) and their APIs, as built. The contract is [SPEC-v3.md](SPEC-v3.md);
section numbers below refer to it, and [PLAN-0.11.md](PLAN-0.11.md) wins
where they differ. All code is in `plugins/gateway/src/gateway/`, stdlib
only, on the lock's Python. Import as `from . import paths, form, vault, ...`.

This file covers the core (paths, testing, form, modes, accounts, vault,
consent, gitroute, audit, envfile, warm, hooks_session, gate, run.py,
hooks_files) and how everything is wired. The rest is documented per group, kept current with the
code:

| group | modules | doc |
|---|---|---|
| sudo / approvals | `sudo.py`, `ancestry.py`, `bashparse.py`, `hooks_bash.py`, `hooks/pre_bash.sh`, `hooks/tool_guard.sh` | [modules/sudo.md](modules/sudo.md); the route checks in [modules/managed.md](modules/managed.md#alternate-routes) |
| ssh | `ssh.py`, `ssh_args.py`, `ssh_conf.py`, `ssh_sudo.py` | [modules/ssh.md](modules/ssh.md) |
| accounts (the git stand-in, account CLIs' destinations, browser sign-in: PLAN-0.11 §1.4, §6, §7) | `scrub.py`, `githelper.py`, `clis.py`, `asiml.py`, `entra.py`, `logins.py`, `gitroute.py` (core, below) | [modules/accounts.md](modules/accounts.md) |
| ux | `popup.py`, `dialog.py`, `gate_setup.py`, `transfer.py`, `web.py`, `mcp_server.py`, `hooks_mcp.py`, `hooks_post.py`, `hooks_prompt.py`, `hooks_filechanged.py`, `hooks/post.sh`, `hooks/prompt.sh`, `hooks/mcp_perm.sh` | [modules/ux.md](modules/ux.md) |
| daemon (PLAN-v4 phases 2, 3; PLAN-0.11 §2.4, §7, §8) | `daemon/` (`peers.py`, `planes.py`, `events.py`, `broker.py`, `server.py`, `lifecycle.py`, `dialogs.py`, `oauth.py`, `offer.py`, `clipboard.py`, `client.py`), `agepass.py` | [modules/daemon.md](modules/daemon.md) |
| terminals and jobs (PLAN-v4 phase 5) | `daemon/terminals.py`, `daemon/screen.py`, the gw tools in `mcp_server.py`, `hooks/mod/{terminal.ts,term.tsx}` | [modules/terminals.md](modules/terminals.md) |
| the managed remote runtime (PLAN-v4 phase 6) | `runtime/pixi.toml` + lock, `runtime_pack.py`, `daemon/remote.py`, remote panes in `daemon/terminals.py`, `host_runtime` in `mcp_server.py` | [modules/remote.md](modules/remote.md) |
| hosts, workspaces, policy, accounts' states, portability (PLAN-v4 phase 7) | `policy.py`, `adapters.py`, `manage.py`, the policy/workspace/shell tables in `form.py` and `consent.py`, `transfer.py` format 3, `hooks/mod/manage.ts` | [modules/policy.md](modules/policy.md), [modules/accounts.md](modules/accounts.md), [modules/ux.md](modules/ux.md) |
| managed execution (PLAN-v4 phase 4, PLAN-0.11 §1.6-§1.8) | `managed.py`, `hooks/gate-sh`, `[shell]` in `form.py` and `consent.py`, `hooks_bash._managed_gate` and the route checks, the mod's `managedSetup` | [modules/managed.md](modules/managed.md) |
| the network class (PLAN-0.11 §3) | `hooks_bash._network` and `_net_*`, `[network]` in `form.py` and `consent.py` (`sync_network_words`), `hooks/pre_bash.sh`'s network words, `launch.sh`'s cold network guard | [modules/network.md](modules/network.md) |

How phase B's requests were settled is in
[phaseB-requests/RESOLUTION.md](phaseB-requests/RESOLUTION.md).

## Rules every module follows

- Locations come only from `paths.py`. Never read `GATEWAY_*` variables.
  Tests redirect everything with `testing.override(...)`.
- **The data folder and binaries in stand-ins.** Stand-ins, askpass, the git
  helper and `gate` run inside Claude's Bash, where the caller controls every
  variable. They never take the data folder from `CLAUDE_PLUGIN_DATA` (only
  hook and MCP modes do; run.py sets that per mode). Resolve binaries only
  with `paths.tool(name)` (next to `sys.executable`, then the env of the data
  folder derived from it) and optional envs only under `paths.envs_dir()`.
  Never search PATH for a binary that receives a credential.
- Never print a secret value. Messages start with `gateway:` and say what to
  do next. Names that come from the form appear in a message only after
  validation (`form.safe(s)` returns `s` or `None`). Never put raw exception
  text into a message or a `Problem`.
- Read-modify-write the vault only inside `vault.locked()` or `vault.edit()`.
- Before using a host or account, check the **effective** rights
  (`consent.compute(form, data)`), not the raw form. A widening has no effect
  until the user approves it. `accounts.select()` requires `effective=`.
- **Ratchet.** Every process that loads the form calls `consent.ratchet(form)`
  (or goes through `hooks_session.prepare`, which does). See consent.py below.
- Commit identities (`name`, `email`) are validated text, but they can still
  hold `"`, `\`, `]` or `;`: quote and escape them when writing git config.

## paths.py: every location (SPEC 1)

| function | returns |
|---|---|
| `home()` | `~/.config/gateway`. The home comes from the password database, not `$HOME`. |
| `form_path()`, `launcher_path()`, `env_sh_path()` | `gateway.toml`, `gate`, `env.sh` |
| `private_dir()`, `key_path()`, `vault_path()`, `cache_path()`, `lock_path()`, `backups_dir()`, `pending_dir()` | `private/…` |
| `v2_store_path()`, `v2_key_path()` | a 0.6 `store.age` and `key.txt`: the file guard's list, and the 0.6 detector (`vault.v06_waiting`) |
| `configured_path()` | `private/configured.json`, the configured set's non-secret mirror (PLAN-0.11 §1.1) |
| `ensure_home()`, `ensure_private()` | create them with mode 0700 |
| `data_dir()` | hook/MCP modes: `CLAUDE_PLUGIN_DATA`. Every mode: the folder of the pixi env that `sys.executable` belongs to (`<DATA>/envs/<sha12>/.pixi/envs/default/bin/python3`). Then `GW_DATA` (the stubs set it themselves), then `~/.claude/plugins/data/gate-gateway` (`CLAUDE_CONFIG_DIR` only in hook/MCP modes). |
| `trust_plugin_env(ok)`, `data_from_executable(exe=None)` | run.py's per-mode switch; the env-python rule above |
| `bin_dir()`, `git_dir()`, `git_config_path()`, `git_global_path()`, `envs_dir()`, `audit_path()` | `$DATA/bin`, `$DATA/git`, `$DATA/git/config` (the gated git's include), `$DATA/git/global` (its read-only global config), `$DATA/envs`, `$DATA/audit.jsonl` |
| `mode_epoch_path()`, `network_words_path()`, `network_form_link()` | `$DATA/mode-epoch` (while the mode matters: pre_bash.sh forwards every call), `$DATA/network-words` (the user's `extra` names for the prefilter), `$DATA/network-form` (a symlink to gateway.toml for its `-nt` test) |
| `run_dir()` | `/tmp/gw-$UID`, created with mode 0700. Raises `PathError` if it isn't a directory owned by you with mode 0700; the error's `remedy` says what to do: a link or a file, `rm` it; another user's, only they or an administrator can remove it (a restart empties /tmp); writable by group or others (`mode & 0o022`), remove it (`rm -rf`) once no Claude Code session or gated uses it, never chmod it (what others put there, a `gated.sock` or a ControlMaster socket, would stay); only read/search bits, `chmod 700`. `explain(e)` gives message and remedy as one line (the stand-ins, `gate status`, SessionStart, `gated start|status`, /gate-doctor). |
| `run_file(name)`, `refusals_dir()`, `session_dir()` | paths inside the run dir |
| `sudo_probe_path(user)` | the cache file for the sudo stand-in's `sudo -n true` probe. Write `yes …` or `no …`; status and context read it. |
| `plugin_root()`, `run_py()`, `launch_sh()` | the plugin's own files |
| `lock_sha12()`, `env_dir()`, `env_bin()`, `env_python()`, `env_ready()` | the pixi env in `$DATA/envs/<sha12>/` (`.ready` marks a finished build) |
| `tool(name)` | absolute path of an env binary (`age`, `ssh`, `ssh-keygen`, `gh`, …). Looks next to `sys.executable`, then in `env_bin()`, never on PATH. Raises `ToolMissing`. |
| `protected_paths()` | `private/`, the v2 key and store, the run dir (resolved) |
| `transcript_roots(transcript_path=None)`, `is_transcript(path, cwd=None, roots=None)`, `holds_transcripts(path, cwd=None, roots=None)` | Claude Code's session transcripts (any `.jsonl` at any depth under `<config>/projects/` but inside `tool-results/`: `<project>/<session>.jsonl` and a subagent's `<project>/<session>/subagents/agent-<id>.jsonl`; config dirs: the payload's `transcript_path`, also a subagent's, `CLAUDE_CONFIG_DIR` outside tests, `~/.claude`, `~/.config/claude`), which can hold the one-time codes hook systemMessages show the user; `holds_transcripts` is a `projects` folder, a folder above one, or any folder inside one but `tool-results/` (a recursive search would read them). Not a transcript: a Workflow run's journal, exactly `<project>/<session>/subagents/workflows/<run>/journal.jsonl` in that case, a regular file with one link (`_workflow_journal`; `WORKFLOW_JOURNAL`); the run folder still holds transcripts |
| `is_protected(path, cwd=None)` | inside a protected location, in any spelling: case-insensitive comparison (macOS volumes ignore case), symlinks and `..` resolved, and same-file checks (st_dev, st_ino) against the protected locations and every file inside `private/` (hard links). `~` expands to both the password-database home and `$HOME`; relative paths are taken from `cwd`. |
| `is_protected_parent(path, cwd=None)` | a protected location lies below `path` (a recursive search from there would read it) |
| `Protected()` | the same, computed once (`contains`, `is_parent`, `candidates`, `entries` = existing files in protected places, for Glob) |
| `user_home()`, `local_user()`, `describe(path)` | the user's home and login from the password database; `describe` turns a path into its `~/…` form |
| `wrapped_key_path()`, `recipient_path()` | `private/key.wrapped` (the vault key encrypted to the user's passphrase) and `private/key.recipient` (its public recipient), PLAN-v4 phase 2 |
| `gated_socket()`, `gated_lock()`, `gated_pid()`, `gated_start_lock()`, `gated_sessions()`, `gated_dialogs()` | the daemon's socket, single-instance lock, pid and start time (for its tmux watchdog), starters' lock, session registry and dialog requests (metadata only) in the run dir |
| `gated_dir()`, `gated_log()` | `$DATA/gated` (log, epoch counter, events/, machine-ids.json) and its log |
| `gated_tmux_socket()`, `gated_tmux_conf()`, `gated_terms_dir()`, `gated_terminals()` | the supervisor's tmux socket and config and the panes' start files and FIFOs in the run dir; the terminal and job records in `$DATA/gated/terminals.json` (PLAN-v4 phase 5) |
| `gated_remote()`, `runtime_src_dir()`, `runtime_data_dir()` | the remote hosts' runtime and identity state (`$DATA/gated/remote.json`); the runtime workspace in the plugin (`runtime/`); the packs and pixi-pack's cache (`$DATA/runtime/`) (PLAN-v4 phase 6) |
| `contract_dir()`, `contract_path()` | `~/.config/gateway/run/contract.json` (CONTRACT-v1 discovery) |
| `ENTRY_MODE` | this process's run.py mode (`shim sudo`, `hook-post`, ...), set by run.py's dispatch |
| `checkpoint_seen_path()` | `<run>/checkpoint-seen`: gated touches it on every CONTRACT-v1 route; Claude's context mentions checkpoint jobs while it is younger than a day (PLAN-0.11 §9.4) |

## testing.py: the explicit test API

- `testing.override(root, **kw)` redirects every location under `root`: home
  is `root/home/.config/gateway`, user_home `root/home`, data `root/data`,
  run `root/run`. Keywords: `home=`, `data=`, `run=`, `user_home=`,
  `plugin_root=`, `env_python=`, `entry=[argv]` (stubs exec this instead of
  run.py), `local_user=`, `machine_id=`, `tools={name: path}`, `dialog=`
  (fake dialog backend for popup.py), `keyscan=` (dict or callable),
  `system_git=` (True/False). Any other keyword lands in `.extra` (since
  0.11.0 among them `user_tools`: a folder of recording fakes the
  pass-through runs instead of the user's own tools). It refuses
  (SystemExit) any location under the real `~/.config/gateway` or the real
  plugin data folder (`guard`, `forbidden_roots`: the protected folders are
  compared as written, any case, and with only their parent folders
  resolved, so they are never stat'ed; a candidate path is resolved only
  after it passed the as-written comparison, which still catches a symlink
  into them; PLAN-v4 phase 2).
- `testing.active()` returns the current `Override` or `None`.
  `testing.get(name, default)` reads one field.
- `testing.from_env(has_test_flag)`: run.py calls this. With `--test`, the
  hook, MCP and gated modes honour `GATEWAY_TEST_ROOT` (and
  `GATEWAY_TEST_RUN`, a short run dir). Stand-ins, askpass and the git helper
  never do.
- Overrides read through `testing.get` by other modules (each listed in its
  group doc): `dialog`, `dialog_backend`, `popup_wait`, `popup_lifetime`,
  `keyscan`, `ssl_context`, `entra_authority`, `github_base`,
  `install_feature`, `pijul_build`, `sudoers_dir`, `visudo`,
  `sudoers_chown`, `ssh_remote_euid`, `ssh_endpoint_map`, `ssh_authorized_keys`,
  `master_lock_wait`, `download_temp_roots`, `gated_test_entries`,
  `gated_wrap_corrupt`, `native_dialogs`, `dialog_timeout`, `clipboard`,
  `tmux` (the supervisor's tmux: a test's wrapper), ... Under any override without `dialog` (or `native_dialogs`, which a
  daemon test sets with its own gated and fake mod), no dialog can open
  (dialog.backend): popup reports it as unavailable, so a test can't reach a
  real dialog. gated reads only the `clipboard` knob's program for Paste
  under any override.

## form.py: the form (SPEC 2)

- `load(path=None, last_good=None, use_cache=True) -> Form`: cached by mtime.
  A missing file gives the last good form (`exists=False`, `from_last_good`),
  else an empty form with localhost implicit.
  After a syntax error, and for a file that isn't UTF-8 (reported with its
  line), `last_good` (the vault's `form_last_good`) is used instead.
- `parse_text(text, path=None, last_good=None) -> Form`: no file access, no cache.
- `[vault]` (PLAN-v4 phase 2): `lock_after = "8h"` (`parse_duration`: "1m" to
  "1d"; a bad value is an error and keeps the default) in `Form.vault.lock_after`
  (seconds), how long the daemon keeps a passphrase-protected vault unlocked
  without use.
- Policy, workspaces and remote imports (PLAN-v4 phase 7;
  [modules/policy.md](modules/policy.md)): `[policy]` (`Form.policy`,
  `policy_lines`), `[hosts.NAME.policy]` (`Host.policy`, `policy_lines`),
  `[hosts.NAME.workspaces.W]` (`Host.workspaces`: `Workspace(root, local,
  note, policy, lines)`), `[hosts.NAME.shell]` (`Host.shell`:
  `HostShell(import_path, import_env)`), `[accounts.NAME.policy]`
  (`Account.policy`). Words "allow" / "ask" / "deny" or a bool
  (`policy_word`, `policy_text`); keys per scope `HOST_POLICY_KEYS`,
  `LOCALHOST_POLICY_KEYS`, `WORKSPACE_POLICY_KEYS`, `ACCOUNT_POLICY_KEYS`,
  `GLOBAL_POLICY_KEYS` (grants `POLICY_GRANT` only per host). An unknown key
  or a bad word is an entry error; in `[policy]` it counts as deny.
- Per-mode values (PLAN-0.11 §2): a right (`ssh`, `sudo`, `use`), a moded
  policy key (`POLICY_MODED`: read, exec, write, network, elevation,
  credential) and `[network] commands` parse into a `modes.ModeValue` (a
  table must name `default`) in new attributes (`Host.modes`,
  `Host.policy_modes`, `Workspace.policy_modes`, `Account.modes`,
  `Account.policy_modes`, `Form.policy_modes`, `Form.network.commands`;
  `mode_value()`, `policy_mode()`); the legacy attributes (`Host.ssh`,
  `Host.sudo`, `Account.use`, policy words) hold the modeless resolution, so
  a reader that doesn't know the mode gets the strict value. A bad mode,
  word or missing `default` disables the entry (in `[policy]` it counts as
  deny). The lenient pre-pass also takes `cc`, `allow` and `deny`.
- `[network]` (PLAN-0.11 §3.2): `NETWORK_KEYS` (commands, extra, drop),
  `NETWORK_BUILTIN`, `NETWORK_RESERVED`, `NETWORK_DEFAULT` ("ask"),
  `Form.network` (`NetworkSettings`; any mistake sets `invalid` and the
  approved `[network]` applies).
- This computer's sudo (PLAN-0.11 §1.5): the implicit localhost is kept
  with `sudo_configured=False` (no `modes["sudo"]`; the legacy `sudo` holds
  "ask", the strict value); a `[hosts.localhost]` without `sudo` isn't
  configured either. `STARTER` is the new install's three comment lines.
- Accounts: azure's `sign_in` ("browser" or "service-principal", kept as
  ""; browser needs an explicit `client_id`) and `scope` (up to 8 tokens,
  `offline_access` stripped), ml-catalog's `tenant` (`CATALOG_TENANT`,
  "organizations"). `Form.disabled_accounts` keeps the destinations a
  disabled account still spells, and `disabled_addresses` a disabled
  host's, so they stay configured.
- `[settings]` is gone: a written one is a warning (`SETTINGS_GONE`).
  `[shell] managed` is "on" or "off" (`SHELL_MODES`); a written "warn" is
  an error that counts as "on".
- `clear_cache()`
- Writers: `append_table("hosts.NAME", {key: value}, comment=..., path=None)`
  and `set_key("hosts.NAME", "sudo", False, path=None)`. Both refuse a form
  with a syntax error. They re-parse after writing and roll back (raising
  `FormWriteError`) if the document changed elsewhere or another entry gains
  or changes errors (another entry losing errors, i.e. being fixed, is fine).
  `toml_value(v)` serializes one value (a `ModeValue` as an inline table).
- Helpers: `parse_address(s) -> Address` (raises ValueError; ports are ASCII
  digits only), `parse_hostport`, `parse_cidr`, `valid_hostname`, `safe(s)`,
  `git_server_note(host)` (round 4: why a host address that is a git server
  can't be a machine, or None; `GIT_SERVERS` maps those hosts to the account
  kind to add instead), `unsafe_text(s)` (controls, invisible format characters such as bidi
  overrides, zero-width joiners, soft hyphen and Unicode tag characters,
  private use, surrogates, line/paragraph separators, Hangul fillers),
  `strip_unsafe(s)`, `too_broad_site(domain)` (public suffixes like `co.uk`
  and shared hosting like `github.io`: refused as `.domain` api-key sites),
  `normalize_lenient(text)`, `line_index(text)`.
- Constants: `NAME_RE`, `RESERVED`, `KINDS`, `AZURE_CLI_CLIENT_ID`,
  `DEFAULT_HOSTS`, `UNSAFE` (a fast pre-check only), `ENV_DENY` (PATH, HOME,
  LD_*, GIT_*, SSH_*, *_PROXY, *_OPTIONS, NODE_*, SSL_*, CURL_*, CA bundles,
  EDITOR, VISUAL, PAGER, …), `SHARED_SUFFIXES`.

Data shapes (dataclasses):

```
Form:     path, exists, text, used_text, mtime_ns, sha256 (of used_text),
          vault, shell, network: NetworkSettings, policy, policy_modes,
          hosts: {name: Host}            # valid entries, plus the implicit localhost
          accounts: {name: Account}      # valid entries only
          disabled: {safe name: first error}
          disabled_kinds: {name: kind}   # disabled accounts whose kind could be read
          dup_disabled: {name: "hosts"|"accounts"}   # a name used by both: the later section is off
          unnamed_off (entries whose name can't be shown), n_off (total off)
          problems: [Problem], errors, warnings, syntax_error: Problem|None,
          from_last_good, ok
          entry(name), host(name), account(name), problems_for(name), names(), report_lines(),
          is_disabled(name, "hosts"|"accounts")    # off, as opposed to absent
Problem:  level ("error"|"warning"), message (safe), line, entry; render() -> "line 12: box: …"
Address:  host (lowercase; IPv6 without brackets), port (22), user (None = local user),
          when (CIDR str|None), raw
          effective_user(), hostport(), render(with_user=True) -> "u@h[:p]", key() -> (user, host, port)
Host:     name, line, address: Address|None (None only for localhost), also: [Address],
          via, ssh/sudo: True|"ask"|False (modeless), modes: {key: ModeValue}, scripts, note,
          explicit (False = implicit localhost), sudo_configured (localhost only)
          is_local, addresses() (address first, then also), user()
Account:  name, kind, line, login, owners, default, commit_name (the `name` key), email, env,
          scripts, use, note, host (github/ml-catalog/pijul/registry; may carry :port),
          packages (github), tenant, client_id (default Azure CLI client), databricks,
          storage, registries, sites (azure extra sites / api-key sites), remote_pijul,
          auth (api-key; default "bearer"), sign_in, scope (azure), modes {"use": ModeValue}
          destinations(), ssh_endpoints(), owner_names() (login + owners)
```

Disabled entries are absent from `hosts`/`accounts`. Treat them as having no
rights; the reason is in `disabled[name]`. They stay in the configured set
(`consent.Effective.configured`) and are refused, never passed through. A
broken `[hosts.localhost]` is disabled, which means no localhost sudo (and
configured, so refused), not the implicit default. Use
`is_disabled(name, section)` rather than `name in disabled` when a name may
be valid in the other section.

## accounts.py: destinations and selection (SPEC 2 Kinds, 9.6)

- `destinations(account) -> [str]`: the hosts, or `.domain` patterns, that
  the credential may go to, computed from the form.
- `destination_matches(pattern, host)`, `covers(dests, host)`: matching for
  `api.x.com` (exact), `.x.com` (any subdomain), and `h:port`.
- `ssh_endpoints(account) -> [(user, host)]`: `git@github.com`
  (+ `ssh.github.com`), `git@GHES`, `git@hf.co`, `LOGIN@nest.pijul.com`.
- `endpoint_accounts(user, host, form)`, `is_ssh_endpoint(host, form)`, `kinds_for_host(host, form)`
- Owners: `owner_from_path("owner/repo", kind)`, `owner_from_url(url, kind) -> (host, owner) | None`
  (https, ssh://, scp form; an invalid port gives None), and
  `owner_from_git_command("git-upload-pack 'o/r'") -> (service, owner)`.
- `resolve_name(name, aliases, form=None)`: follows vault aliases, but a name
  that is an entry of the form is never redirected.
- `select` refuses (Selection.error) when the owner matches an account that
  isn't usable (waiting for the user's OK, credential not bound, `use =
  false`): `gateway: NAME is the account for OWNER but can't be used yet (it
  waits for the user's OK); run gate check NAME while the user is here` (or
  `... has use = false ...`); never the default or the only other account.
  Likewise a default that isn't usable, and an owner matched by a usable and
  an unusable account. The "only account" rule counts the form's accounts of
  that kind and host, approved or not (SPEC 9.6 step 5), and picks it for an
  owner it doesn't list only when it lists no `owners` (or no owner is
  named): `owner_covered(owner, names, *, default, any_owner, only)`, the one
  rule gitroute (and through it the account CLIs' destination, the ssh
  stand-in's endpoints and the hook) shares.
- `select(kind | (kinds…), host, owner, form, *, effective, vault=None, env=None, mode=None, asked=()) -> Selection`
  (`effective` is required: `consent.compute(form, vault_data)`; `mode`: the
  account's `use` and credential policy in that mode, None the modeless rule;
  `asked`: accounts the approval hook asked about, for which an "ask" counts
  as usable: the gated git).
- Entra (PLAN-0.11 §7): `browser_sign_in(a)`, `request_scope(a)`,
  `entra_stored`, `entra_fits(a, info)` (the one rule for whether a stored
  Entra credential fits the account; see modules/accounts.md).

```
Selection: account (form.Account|None), name, explicit (GATE_ACCOUNT), reason ("GATE_ACCOUNT"|"owner"|"default"|"only"),
           candidates [names], error (refuse with it: "gateway: both a and b fit; set GATE_ACCOUNT=b"),
           note (run without a credential and print it: "gateway: no account for github.com/acme")
```

Only approved destinations, approved `use` and (through `effective`) bound
credentials count. Pass `vault=` (the vault dict) for alias resolution and the
explicit `GATE_ACCOUNT` bound check; an account with no vault record has an
empty bound set there. The caller still checks `bound` for the account it
picks before sending (`consent.bound_ok`). A test checks that every
`accounts.select(` call in src/ passes `effective=`.

## vault.py: vault v3 (SPEC 3)

- Key modes (PLAN-v4 phase 2; [modules/daemon.md](modules/daemon.md)):
  `key_mode()` (`"unwrapped"`: key.txt; `"wrapped"`: key.wrapped and
  key.recipient, no key.txt; `"none"`), `brokered()` (a wrapped key and not
  the daemon itself: `load`, `save`, `cache_load`, `cache_save` go to the
  daemon over its socket and get a scoped view), `VaultLocked(VaultError)`
  (the daemon holds the key locked, can't be reached, or won't serve this
  program; the message says what to do), `is_redacted(v)` (a sentinel the
  daemon put where a value this program may not see was; `all_values` and
  `labeled_secrets` skip them), `_DAEMON_IDENTITY` (set in the daemon:
  decrypt with the identity it holds). `ensure_key()` never makes a key.txt
  beside a wrapped key; `recipient()` reads key.recipient then.
- `load()` (a missing vault is `empty()`), `save(data)`, `locked(timeout=)`,
  `edit()` (a context manager: locked load, saves only if changed),
  `exists()`, `ensure_key()`, `recipient()`, `empty()`, `now()` (the
  timestamp format used everywhere), `VaultError` (raised for
  unreadable/unwritable vaults; the message holds no secret). The 0.6
  detector (0.11.0): `v06_waiting()` (a `store.age` and no `vault.age`),
  `V06_MESSAGE` ("convert it with gateway 0.10.0 first (see CHANGELOG
  0.11.0)"); `save` refuses to create `vault.age` beside one, and so do the
  broker's wrap and `gate` (every command but the read-only ones).
- The passphrase offer (PLAN-0.11 §8): `passphrase_offer` ("pending" or
  "declined"; `offer_state`, `note_offer`, `decline_offer`): `save` makes it
  "pending" when the vault holds a secret and there is no `key.wrapped`, never
  undoing "declined". One-time notices: `notice_shown`, `mark_notice`,
  `POSTURE_NOTICE`. `entra_info(rec)` describes a stored Entra credential
  with no values (`meta` carries it as `entra_info`; `accounts.entra_fits`
  reads it), `ENTRA_IMPORTED`.
- Cache (short-lived tokens): `cache_get(account, scope, margin=120)`,
  `cache_put(account, scope, value, expires_at)` (call it under
  `locked()`), `cache_clear(account=None)`, `cache_values()`, `cache_load()`,
  `cache_save()`.
- Durable writes: `write_private(path, data)` (temp file beside it, 0600,
  flushed, renamed, then the folder flushed: a crash or power loss leaves
  the old file or the new one; vault.age, cache.age, the broker's
  key.recipient, an import's restore), `fsync_dir(d)` (best
  effort), `full_fsync(fd)` (`fcntl(F_FULLFSYNC)` on macOS, whose fsync
  leaves the data in the drive's cache; fsync where that is refused, and on
  Linux). `_encrypt_to` takes age's stdout and writes it this way.
- Copies: `snapshot(kind="rotate")` copies vault.age as it is (encrypted,
  0600) to `private/backups/<kind>-<YYYYmmdd-HHMMSS>-<hex>.vault.age`
  (folder 0700) and keeps the newest `SNAPSHOT_KEEP` (5) of that kind; None
  without a vault. `gate rotate` takes one through `ssh.rotate`'s
  `before_change` (just before its first vault write, under the vault's
  lock; not when it fails before). `gate forget` takes none (forgetting
  means gone): `older_copies()` lists, by kind, the backups that may still
  hold what it forgot (`*.vault.age`, `import-*` folders with a vault.age,
  `startover-*` folders, an old 0.6 conversion's `store-v2-*.age`); names
  only, nothing read. `delete_older_copies(names)` deletes those of `names`
  that are older copies when it runs (a file unlinked, a folder removed
  whole; a link or anything else stays): `gate forget --backups`, after the
  user's OK in the gateway's dialog. `move_aside(kind)` renames vault.age,
  key.wrapped, key.recipient and cache.age into a new 0700
  `private/backups/<kind>-<time>-<hex>/` (gated's start-over of a vault
  whose passphrase is lost, under the vault's lock; nothing deleted).
- Events: `add_event(data, what, detail)` keeps the last 100, each with
  `n` and `at`. `new_events(data)` and `mark_events_seen(data)` track
  `events_seen`. Kinds: widen, narrow, bind, export, copy, import, reject,
  hostkey, forget.
- Machine: `machine_id()` (IOPlatformUUID, `/etc/machine-id`, else None),
  `ensure_machine(data)` (falls back to a random id stored in the vault),
  `short_hostname()`.
- Records: `resolve(data, name, entries=())` (aliases; a name in `entries`
  is never redirected), `host_record(data, name)`,
  `account_record(data, name, kind)`, `sudo_entry(data, host, user)`,
  `set_sudo(data, host, user, pw)` (host `"localhost"` maps to
  `localhost.sudo`), `forget_sudo(data, host, user)`,
  `sudo_choice(data, host, user)` / `set_sudo_choice(data, host, user,
  "password"|"ask"|None)` (gate check's sudo choice, per machine: not
  exported), `mark_stale(data, entry, "sudo"|"token", user)`,
  `key_record(private, public=None, created=None)`, `live_keys(host_rec)`.
- `meta(data)` holds no values, only what is stored: per host the key
  fingerprints, host-key fingerprints, sudo users with a stale flag and
  `installed`; per account `token`/`token_source`/`stale`/`ssh_key`/`entra`/`bound`.
  envfile and githelper use it.
- `all_values(data)` lists every secret value, for scrubbing.
  `labeled_secrets(data)` gives `(section, entry, what, value)` (section
  `localhost`/`hosts`/`accounts`; the PostToolUseFailure warning names the
  entry and picks the fix by section and kind, never showing the value);
  `labeled_values(data)` is the same without the section.
  `export_view(data)` is the vault's exportable part, an allowlist
  (`EXPORT_KEYS`; no approved, last-good, events or `sudo_choice`); a browser
  sign-in's refresh token isn't exported (lead decision 19.12).
- Keys: `normalize_key`, `public_key_of`, `fingerprint_of`,
  `generate_ssh_key(comment)`, `norm_host_key(line) -> "type key"`,
  `host_key_fingerprints(keys)`, `builtin_host_keys(host, port)`, and
  `keyscan(host, port=22)` (built-in keys for github.com, ssh.github.com,
  hf.co and nest.pijul.com; else `ssh-keyscan`; tests use
  `override(keyscan=…)`).
- Constants: `GITHUB_HOST_KEYS`, `HF_HOST_KEYS`, `NEST_HOST_KEYS`.

The schema is SPEC 3 plus: `events[].n` and `events_seen` (which events
SessionStart has shown); `passphrase_offer`; the posture notice's mark;
`hosts[NAME].installed` (set after a successful key install or test
login; status shows "key installed"), `hosts[NAME].pinned_at`,
`hosts[NAME].host_keys_previous` (gate forget's memory of forgotten pins);
`sudo_choice` (`{host: {user: "password"|"ask"}}`). Host keys are
stored as `"type base64"`. The approved snapshot (`approved.rights`) stores
a six-mode map for a key that has a per-mode table (a policy map lists its
non-explicit allows under `"plain"`), the bare word otherwise, and
localhost's `sudo_configured`.

## consent.py: effective rights (SPEC 5, PLAN-0.11 §1.1, §2.7)

- `compute(form, data=None, mode=None, *, listed=..., locked=False) ->
  Effective`: the form compared with the approved snapshot (`data` is the
  vault dict), **mode by mode** (`modes.ModeValue.rises`/`falls`): a rise in
  any mode is a widening and waits; a fall applies at once; the effective
  value is the per-mode minimum of the form and the approval (a policy
  table's explicit allow ranks above a plain one). `mode` resolves the legacy
  attributes (the recorded mode for a typed caller, None for the modeless
  rule); `Effective.word(entry, key, mode)` gives the four-word value for any
  mode. The same holds per policy key (`policy_compare`), per workspace, per
  remote import, for `[shell]` (`SHELL_RANK`: off < on) and `[network]`
  (`_network`: a name entering the class narrows; one leaving it, or a
  raised `commands`, widens). `RANK` raises on an unknown value (`.get`
  included).
- **Removal is a widening** (§1.1): a removed host or account stays in
  `Effective` with `removed=True` and its approved rights; dropped
  addresses, destinations and owners stay in `held_*` lists; adding or
  changing `when`, dropping `via`, deleting localhost's `sudo` key wait too.
  Until the OK the approved entry keeps classifying and gating.
- **The configured set** (`Effective.configured`, `Configured` /
  `ConfiguredAccount`: `host_named`, `accounts_for`, `reaches()`,
  `git_targets()` for gitroute, `localhost_sudo`, `local_elevation`): the
  form (disabled entries included), the approved snapshot and the configured
  list `private/configured.json` (`configured_list`, `load_listed`,
  `write_listed`: whole, 0600, inside `vault.locked()`; `clean_listed`: a
  broken list keeps its valid parts and counts as naming this computer's
  sudo). `compute` reads the list itself when no approval can be read.
  `Effective.refused` (name → why: `FORM_GONE`, `LISTED_ONLY`,
  `LISTED_SUDO`, a disabled entry's), `Effective.refusal(name)` (also
  `LOCKED_ENTRY` / `UNREADABLE_ENTRY` while the vault is locked or
  unreadable), `form_gone`, `unreadable`, `locked`.
- **This computer's sudo** (§1.5): not configured unless the form says
  `sudo` (or the approval or the list does); writing it where none is
  approved applies at once up to `"ask"`, above it waits and runs as
  `"ask"` meanwhile; a snapshot from before 0.11 counts localhost as
  implicit. With a locked vault the Bash hook and the sudo stand-in refuse
  the configured sudo with the vault's own message (PLAN-0.11 §19.16).
- `ratchet(form=None) -> [Change]`: persists the narrowings the current form
  shows (lowers `approved`, never removes anything: a removal waits), logs a
  `narrow` event, closes ssh masters, keeps `form_last_good`, rewrites the
  configured list when the snapshot changed, syncs the stand-ins and the
  network words. Never on a missing form, a syntax error, or while a 0.6
  vault waits. **Contract:** call it from every process that loads the
  form: SessionStart, SubagentStart and every `gate` command (via
  `hooks_session.prepare`), the file guard before an Edit/Write/MultiEdit of
  gateway.toml, FileChanged, PostToolUse on form edits, the Bash hook when a
  command names `config/gateway`, and each stand-in / the http tool before
  using a right (cheap when unchanged).
- `needs_sync(data, form)`, `sync_narrowing(data, form) -> [Change]`: the
  in-memory part of `ratchet` (never widens).
- `approve(entry, changes=None, form=None, *, keep_credentials=False) ->
  [lines]`: call only after the user said yes, passing the changes the
  dialog showed; differing pending changes raise `ConsentChanged`. It
  writes `approved.rights[entry]` (a removed entry's approval, bindings and
  masters go), adds an account's destinations to `bound.hosts`, clears an
  account's cached tokens when `kind`, `tenant`, `client_id`, `sign_in` or
  `scope` changed (`SIGN_IN_KEYS`), rewrites the configured list, syncs the
  stand-ins and network words, logs a `widen` event and audits the consent.
  An account `drops_credential` names first loses its stored
  `CREDENTIAL_FIELDS`. `entry` may be `"settings"` (`[shell]`, `[policy]`,
  `[network]`, `[vault]`). `approve_all(form)` approves everything (tests).
- `network_words(eff)`, `sync_network_words(eff)`: `$DATA/network-words`
  (the user's `extra` names) and the `network-form` link for pre_bash.sh.
- `EffectiveNetwork.names()`: the class's names without letter case
  (`extra` and `drop` folded).
- `approved_any_owner(ap)`: whether an approved or listed account lists no
  `owners` (its `any_owner`; an approval without one, 0.10's: whether it
  lists none, as `account_snapshot` reads the form). The configured set's
  accounts carry `any_owner` (the union over sources; a list entry without
  it covers every owner), the ratchet only turns it on, and listing the
  first owner of the only account of its kind for a host is a widening
  ("owners listed"; `_only_of_kind`).
- `close_masters_for(changes, form)`, `bound_hosts`, `bound_ok(data, name,
  host)`, `unbound`, `snapshot(form)`, `host_snapshot(h)`,
  `account_snapshot(a)`, `baseline()` (an empty form's approval: nothing
  configured), `approved_rights(data)`, `load_form(data=None)`.
- Text: `ask_phrase`, `job_ask_message`, `pane_ask_message`, and the change
  lines (`_change_text`, `_policy_change`): each key that moves says, mode
  by mode in Claude Code's names, what each mode now does ("sudo on this
  computer: in Auto and Bypass permissions modes the gateway now approves
  without asking you; elsewhere Claude Code decides (was: asks you in every
  mode)"); a key with no allow shape never promises an approval; a removal
  says the target "will stop going through the gateway".

```
Effective:  form, mode, hosts {name: EffectiveHost}, accounts {name: EffectiveAccount}, shell,
            network: EffectiveNetwork (commands, names()), policy, policy_modes, configured,
            refused, form_gone, unreadable, locked, pending [Change], narrowed [Change], approved;
            word(entry, key, mode), refusal(name), host(n), account(n), pending_for(n)
EffectiveHost:    name, ssh, sudo, scripts (legacy, for `mode`), modes {key: ModeValue}, addresses
                  (approved candidates), held_addresses, via, new, removed, pending, host, is_local
EffectiveAccount: name, kind, use (legacy), modes, scripts, env, destinations, held_destinations,
                  owners, held_owners, auth/tenant/client_id/sign_in/scope, new, removed, pending,
                  account; may_send_to(host)
Change:     entry, kind ("widen"|"narrow"), what (safe text), line; render()
```

A jump host's ssh right caps the hosts behind it.

## asks.py: the approval hook's record that Claude Code asked (lead decision 19.14)

`record(tool, session, cwd, argv, entries)`: one record per stand-in stage
the Bash hook answers "ask" for (tool ssh, sudo, gh, hf, databricks, crane,
pijul, az, git or gate; entries `("hosts"|"accounts", NAME)`), named by a
sha256 of the tool, the Claude Code process (`session()`: the first
ancestor whose executable is Claude Code's, `pid@start`), the folder's real
path and the exact words, holding its time, its session and the entries;
0600 in the run folder's 0700 `asks/`, written whole; records older than
twice `ASK_TTL` (15 minutes) go; `$DATA/asks` is kept as a link to the
folder (`_link`, for pre_bash.sh's glob). `drop()`: the session's next Bash
or Monitor call (the hook runs it first) removes every record of this
session, and any no stand-in could take (expired, dated ahead, unreadable,
a stale half-written one); False when one couldn't be removed (the hook
then refuses the call). `take(tool, session, cwd, argv, needed)`: uses up
a matching record that covers `needed` ("ok"), else "expired" or "none".
`standin(tool, argv, entry)`: the stand-in's own call (this folder and
Claude Code), taken once per stand-in call and kept for its other "ask"
decisions (`reset()` at each stand-in's entry point). `begin(tool, argv)`
and `current(entry)`: the gate CLI's own command (`gate.main`), for the
helpers' "ask" deep down (`ssh._user_present`). `refusal(got, what,
example)`: "run `ssh box ...` as its own command" or the 15-minute text.
Callers: `hooks_bash` (`_drop_asks`, `_pend`, `_fallback_records`,
`_record_asks`), `githelper._git_unasked`, `ssh._asked`,
`ssh._user_present`, `sudo._rights_now`, `clis._unasked`,
`clis._with_refused`.

## modes.py: permission modes and per-mode values (PLAN-0.11 §2)

`KEYS` (`default`, `plan`, `acceptEdits`, `auto`, `bypass`, `dontAsk`),
`normalize(spelling)` (gateway.toml's: `manual` is default,
`bypassPermissions` is bypass), `from_payload(value) -> (key, known)` (a hook
payload's `permission_mode`: Claude Code's own strings only; anything else
is default and never allows), `WORDS`/`RANK` (deny < ask < cc < allow <
unconfigured; indexed, never `.get`), `wmin`, `ModeValue` (frozen: `word(mode)`,
`modeless()` (the strictest over every mode but plan, allow capped at cc),
`legacy()`, `rises`, `falls`, `minimum`, `explicit_in(mode)`, `snapshot()`,
`toml()`, `render()`), `parse(value, kind)` (kind `right`, `policy` or
`network`: what a bare word means, and a table's allow, plan degraded to cc),
`from_snapshot`, `DISPLAY` (Claude Code's mode names for the dialogs). The
recorded mode: `record(permission_mode, create=)`, `current_for(caller)`
(gated's record for a stand-in Claude typed or the MCP server, under the
current epoch; None: the modeless rule), `set_marker`/`drop_marker`/
`marker_epoch` (`$DATA/mode-epoch`), `hook_main` (`launch.sh hook-mode`:
records and decides nothing). An audit line's mode (lead decision 19.8):
`audit_word(mode)` (the key, or "modeless") and `standin_audit_mode(call)`
(the mode a stand-in read, noted in its `_CALL`; before it read one, the
recorded mode for a command Claude typed, else "modeless"). Details:
modules/policy.md.

## gitroute.py: the shared git resolver (PLAN-0.11 §6.2)

`resolve(argv, cwd, *, targets) -> Route` for the git stand-in and the hook:
the repository and its effective config read as the user's git would (the
bundled git's `config -z --list --show-scope`, config reads only), aliases,
every effective URL, and the rule (gated in a repository with any
configured URL, or for a configured operand URL; `config
--global|--system|--file` passes through). `Route`: `command`, `args`,
`alias`, `alias_globals`, `shell_alias`, `repo`, `worktree`, `urls` (and
the configured ones), `gated`, `remote`, `refusal` (`SHELL_ALIAS`,
`UNREADABLE`), `error`;
`Targets` from `consent.Configured.git_targets()`. Details:
modules/accounts.md.

## audit.py (SPEC 17)

- `log(event, *, secrets=(), **fields)` appends one JSON line to
  `$DATA/audit.jsonl` with the session and cwd. Values are redacted with
  `scrub.scrub_text` once that exists; until then, the literal `secrets` of
  at least `MIN_LITERAL` (8) characters plus token shapes are replaced
  (shorter values are never scrubbed by literal: that would reveal them).
- `use(tool, target, account, argv, secrets=())` records one credential use.
- `refusal(tool, target, reason, fix=None)` is audited and kept per session
  for `gate why`. Call it for every refusal.
- `last_refusal(session_id=None)`: this session's (the run dir's copy, else
  the audit log's last refusal with the same session id; without a session
  id, only refusals recorded without one). `newest_refusal()`: the newest of
  any session (`gate why` in the user's terminal). `read(n)`,
  `render(entries)`, `redact_text(text, secrets)`.

## envfile.py and hooks/launch.sh (SPEC 7, 18)

- `env_text()` is the env file text: `$DATA/bin` first on PATH and, when
  `CLAUDECODE` is set, Claude Code's own credential names unset
  (`CLAUDE_CRED_NAMES`) and `unalias`/`unset -f` of every stand-in present
  (POSIX, idempotent under `set -eu` in sh, dash, bash and zsh), all inside
  `if [ -d "$GW_BIN" ]` (after `ENV_HEADER` and `GW_BIN=`), so env.sh does
  nothing for a launcher that sources it (a checkpoint job) once the
  stand-in folder is gone. Since 0.11.0 no git include, `GIT_SSH_COMMAND`,
  `RSYNC_RSH` or unset of the user's own variables.
  Nothing that changes how a
  command ends (round 3's `EXIT_TRAP` is rolled back: a failed command exits
  with its own code; DECISIONS, "Rolled back").
  `write_env_file(path, text)`
  replaces the file whole (`_atomic`: `.NAME.PID.tmp` renamed over it, so a
  killed SessionStart never leaves it empty or cut short; Claude Code
  sources only `sessionstart-hook-N.sh`); `write_env_sh(text)` writes
  `env.sh`. `drop_stale_temps(p)` removes a killed writer's `.NAME.*.tmp`
  once it is an hour old (`_atomic` calls it).
- Which stand-ins exist (PLAN-0.11 §1.2): `STANDIN_NAMES` (sudo ssh scp sftp
  git gh hf databricks crane pijul asiml az dvc), `HELPERS` (gate,
  git-credential-gateway, gate-askpass), `standins_for(eff)` (only those that
  can reach something in the configured set: ssh/scp/sftp for a host or an
  account with an ssh endpoint, git for a host or a git account, sudo for
  this computer's configured sudo or an elevation restriction here, gh, hf,
  pijul per kind, az/databricks/crane for azure, crane also for ghcr.io or a
  registry, asiml and dvc for ml-catalog), `present_standins()`,
  `sync_standins(form, eff)` (adds missing, removes unneeded, writes the
  `.gateway-standins` marker; called wherever the form is loaded and
  changes). The pass-through: `user_tool(name)` / `find_on_path` (the
  caller's PATH minus every folder with the marker and this plugin's own
  envs, `own_env_roots`, then `USER_TOOL_DIRS`; the `user_tools` test knob
  first under an override), `pass_through(tool, argv, target, entries=,
  log=)` (`GW_PASSTHRU` recursion guard: exit 2 on a loop; 127 when the
  tool is missing; one `passthrough` audit line, never argv).
  `MASK_ENV_NAMES`: the user's credential variables post.sh checks.
- `stub_text(name, args)`, `stand_ins(form, eff) -> {name: text}` (the
  helpers and `standins_for(eff)`; `eff=None`: the full base set, as the
  cold window writes it), `write_stubs(stubs)`: each stub is written to a
  temp file and renamed over the old one inside `$DATA/bin` (the folder is
  never moved, so a running command never finds no stub). Stubs set `GW_DATA`, unset `CLAUDE_PLUGIN_DATA`, and exec
  `<env python> -I -S run.py shim TOOL "$@"` (gate: `run.py gate`;
  credential helper: `run.py git-credential`; askpass: `run.py askpass`).
  Until the env is ready they print "still setting up" and exit 75; sudo
  then execs `/usr/bin/sudo`, and git runs the user's own git while nothing
  may be configured (`git_cold_lines`, `CONFIGURED_ERE`: no configured list
  and no line of gateway.toml that may start the hosts or accounts table). `older_env_python()`: when this process runs
  from another finished env (launch.sh's fallback while an update builds)
  on the lock's Python minor (`lock_python_minor()`, which launch.sh's
  `lock_py_minor` reads alike; another minor's env is never used), each
  stub gets a second `exec` line for it, before the not-ready text.
  launch.sh's degraded stubs (no env at all) say instead that pixi is
  missing, too old (its `.pixi-too-old` record of pixi's "requires pixi"
  refusal; `pixi_too_old_words()`) or the build failed, when that is the
  case; with a build running they stay byte-identical to `stub_text`.
- `launcher_text(state="building")` and `write_launcher()` write
  `~/.config/gateway/gate` (mode 0700); when the plugin's run.py is gone the
  launcher says so (`LAUNCHER_GONE`, exit 1) instead of "still setting up".
  launch.sh writes the same bytes in its degraded session (round 3: the first
  session had no launcher though no-screen messages name it), in each of its
  states: `launcher_not_ready(state)` is `STILL_SETTING_UP` ("building"),
  `LAUNCHER_NOPIXI` ("nopixi"), the "update pixi (`PIXI_UPDATE`)" text
  ("pixiold", the build failed on pixi's "requires pixi" refusal) or
  `launcher_failed(log)` ("failed"), all written for the user (round 4: the pixi-missing and failed launchers
  repeated the stubs' "tell the user" text for Claude).
- `git_config_text(helper_text)`, `write_git_config(form, meta)`:
  `$DATA/git/config` = `githelper.include_config(form, meta)` (each
  credential section resets the helpers for its own URL only; the gated git
  reads it at command scope), plus `githelper.identity_files(form)` as
  `$DATA/git/<name>`. An empty result removes a stale file.
- `sync(form, eff, meta, env_file)` does all of the above.
  `cleanup_envs(days=7)`. `degraded_bash_text(kind)`: the cold Bash guard's
  answers (private, transcript, cred: deny; network: ask; network_table:
  deny).
- `launch.sh` produces byte-identical env file, stubs and launcher in
  degraded mode (tests compare them, the launcher in all four states). If the code changes, change both. It takes the user's home from
  the password database (`hooks/home.sh`, `gw_user_home`; round 4), never
  `$HOME`; tests pass `MODE --test` with `GATEWAY_TEST_ROOT` (the test root's
  home), and `GATEWAY_TEST_ROOT` without `--test` resolves no home at all. Its
  degraded file guard matches path fields case-insensitively and refuses Grep
  from a folder above a protected location; a failed env build (install.log,
  no `.ready`, no build running) is reported at SessionStart.
- launch.sh `pre_session` (jobs-lows round 2): before it execs Python for
  `hook-session` (current or older env), it writes the env file
  (`write_env_file`: temp file + `mv`) and, while gateway.toml may configure
  something (`maybe_configured`) and a base stand-in is missing, the full set
  of stubs, so a SessionStart that Claude Code cancels or kills still leaves
  Claude's commands on the stand-ins for what is configured. `write_stubs` quotes its paths once
  and chmods all temp files in one call (the first session's sh writes).
- launch.sh `warm_env`: `ensure-env` runs `gateway/warm.py`'s `main()` with
  the env's python right after a build, or once for a ready env without
  `.warm`, and then creates `.warm`; a failing warm step fails nothing and
  is retried at the next ensure-env.

## warm.py (SPEC 7, 18)

- `main()`: imports every gateway module (`pkgutil` over the package) and
  `LATER` (standard modules gateway code imports inside functions), and runs
  `TOOLS` (`age --version`, `ssh -V`) from `sys.executable`'s own folder with
  a minimal environment. On macOS the first load of each new binary and
  library is slow (checked once per file; reading the files doesn't help);
  a new env's first sync SessionStart paid 5-6 s for it (5-13 s in the e2e
  suite's first sessions, once past the 20 s limit). Resolves no gateway
  location, writes nothing (tests run it under the harness guard).

## hooks_session.py (SPEC 7, 12, 13)

- `session_main(payload, started=None)`, `subagent_main(payload)`,
  `async_main(payload)`, `main(payload)`, `degraded_output(exc)`.
  `session_hook(payload)` (run.py hook-session) passes `started`, the hook
  process's start (`ancestry.started_at(os.getpid())`; launch.sh execs Python
  in the process Claude Code started). Past `SESSION_TIMEOUT` (hooks.json's
  20 s, a test keeps them equal) less a second, Claude Code has dropped the
  output, so the session's context record is removed instead of written and
  the next prompt's hook gives the context. Every file it writes is written whole: the starter form and
  the session record through `_link_new` (temp file, then a hard link only if
  nothing is there; O_EXCL where links aren't supported), the context record
  through a rename. It doesn't import popup (`_sid` is `popup.sid_slug`).
- `context_text(form, eff, meta)` builds the additionalContext (at most 2,500
  characters, no notes, no private paths, never a name that failed
  validation: off entries are a count). Truncation keeps the intro and every
  how-to line and lists as many names as fit. The prompt hook may reuse it.
  The intro (`INTRO`) says that anything not in gateway.toml uses Claude's
  own ssh, git, gh and sudo directly. The how-to lines are `HOWTO` (network
  commands are asked about; don't remove or rename an entry, or reach a
  configured host another way, to get past a refusal), plus `OWN_SUDO_HOWTO`
  while this computer's sudo isn't configured, `JOBS_HOWTO` (checkpoint
  jobs: stand-ins through env.sh, a network command or an "ask" right
  refused in a job, job_tail/job_stop masked) while checkpoint is live
  (`checkpoint_live()`: `<run>/checkpoint-seen` younger than a day),
  `MANAGED_HOWTO` in managed mode, and
  `NO_DISPLAY_NOTE` on Linux without `DISPLAY` and `WAYLAND_DISPLAY` (the
  dialog's Paste can't work there, nor typing on the main screen; what to tell
  the user; review round 2). `IMPORT_OFFER` follows only when it fits.
- `prepare(msgs, write=bool) -> (form, eff, vault_data)`: the shared loader.
  Every mode ratchets (consent.ratchet; also with no vault yet, where only a
  narrowing creates one). A missing form is restored from the
  vault's `form_last_good` (write=True), never replaced by the starter when
  the vault holds approvals or can't be read; the starter (`form.STARTER`,
  three comment lines) is written only when nothing is stored and no 0.6
  vault waits. With `write=True` it also keeps `form_last_good`
  (never from a fallback form) and the machine record.
- `record_context(session_id, form)` and `context_state(session_id)`
  hold `{form_mtime_ns, form_sha256}` from the last context (run dir), so
  UserPromptSubmit can tell that the form changed, or (no record) that the
  session never got its context.
- `pending_requests()`: the dialog requests still waiting (state open),
  after `popup.cleanup_stale()` (a dead helper's request isn't waiting).
  SessionStart names them through `hooks_post.pending_notice(session_id,
  include_open=True)` ("the gateway dialog for X is waiting in Claude Code;
  /gate-dialog shows it"), the "shown" markers shared with the prompt and
  PostToolUse hooks. (PLAN-v4 phase 3 removed the one-time codes.)
- `write_session_record(session_id)`: `private/sessions/<sid>.env` (the
  format prompt.sh writes at the first prompt; O_EXCL, 0600, never
  overwritten): `started=` (the mtime is the session start for copy-to),
  Claude Code's display variables (gated's clipboard reader on Linux gets
  them from the mod instead) and `SSH_AUTH_SOCK` (gate check's "use my own
  SSH login once"; round 3).
- SessionStart returns `watchPaths: [gateway.toml]` for FileChanged. It
  records the payload's permission mode in gated where the payload carries
  one (`record_session_mode`, also from `daemon_main`), syncs the stand-ins
  and the network words, and says once per vault what the 0.11 posture
  changed (`posture_notice`: a stored local sudo password left unused, a
  global `[policy]` deny that no longer reaches unconfigured targets; a
  systemMessage, recorded in the vault).
- `form_messages(form)` returns the user-facing problem lines.
  `ok_how(target, names)`: how the user gives an OK that waits: Claude
  opens the gateway's dialog with `gate check NAME`, answered in Claude
  Code (a terminal session or the desktop app; not -p, VS Code, mobile or
  Remote Control). An unreadable vault's
  message names the next step (restore `private/key.txt`, or start from an
  export).

## gate.py (SPEC 15) and run.py

- `gate.main(argv)`: status (`gate status [NAME]`; any flag or a second name
  is a usage error), log, why, import-ssh, scrub and help here; host,
  workspace, policy, network and accounts to `manage` (per-mode `MODE=WORD`
  tokens for ssh, sudo, the moded policy keys and `network commands`);
  check, login, forget, rotate and secret dispatch to `gate_setup`; with to
  `clis.with_main`; export, import, copy-to and pubkey to `transfer`. Beside
  a gateway 0.6 vault (`vault.v06_waiting`) only `BESIDE_V06` (scrub,
  status, log, why, import-ssh, lock) runs; every other command exits 2 with
  `vault.V06_MESSAGE` before it asks anything or writes a vault, key or form.
  `scrub_cmd(args)`: `CMD | gate scrub`, a line filter over
  `scrub.scrub_text`, optional (Claude may pipe Monitor or background output
  through it; no hook requires it); fails closed when the vault can't be
  read. `footer_examples(form)`: the status footer's "just ask" examples
  from the form's own hosts. `_phase_b` turns an unexpected exception into one
  `gateway: gate X failed (TypeName)` line.
  Renderers you can reuse: `render_status(form, eff, data)`,
  `render_entry(name, …)`, `import_ssh(aliases, config, ssh_bin, form) -> str`
  (a host already in the form gets a commented-out note, never a second table;
  round 4: an alias whose HostName is a git server or an account's ssh
  endpoint gets a comment instead of a table), `config_aliases(config)`
  (every concrete Host alias, following `Include` relative to the config's
  folder, with `~` and globs, depth 16).
- `gate lock` (PLAN-v4 phase 2) locks a wrapped vault in the daemon;
  `gate status` ends with `daemon_line()` (the daemon's /health: running,
  version, epoch, uptime, vault state, and, when it serves another Claude
  Code configuration's data folder, `planes.other_config_note`'s words;
  never starts it; a run folder it can't use: "can't start:" with
  `paths.explain`).
- run.py modes: hook-session, hook-session-async, hook-subagent, hook-bash,
  hook-mcp, hook-mode, hook-files, hook-post, hook-prompt, hook-filechanged
  and hook-daemon (JSON on stdin, JSON on stdout); mcp; `shim TOOL …` (git
  too); askpass; git-credential; gate; `gated serve|start|status|stop` (the
  daemon); managed-sync. Only asiml refuses up front when a wrapped vault is
  locked (`_vault_locked`); the other stand-ins still classify through the
  configured list and refuse only a configured target.
  `parse_test_flag(argv)`: `--test` counts only as the first or second
  argument and only for hook, MCP and gated modes; with `GATEWAY_TEST_ROOT` set and
  no valid `--test`, run.py exits 2 before resolving any path. Failure
  policy: hook-files fails closed (exit 2), hook-prompt blocks, the others
  fail open. A stand-in that raised NotImplementedError would be refused
  (exit 75), never replaced by the system tool; no module raises it any
  more. An unexpected exception in a stand-in or `gate` prints one
  `gateway: TOOL failed unexpectedly (TypeName)` line (never a traceback)
  and exits 1 (`_failed`, round 3); a `paths.PathError` (the run folder
  another user's, a link, open to others) isn't unexpected: `gateway: TOOL
  can't run: <paths.explain(e)>. Tell the user.` (GW-ROB-1). The ssh, scp
  and sftp stand-ins (`ssh.main`) print the same for a PathError. `run.py gate` (and `shim gate`) drops `HTTP(S)_PROXY`, `ALL_PROXY`,
  `NO_PROXY` (both cases) and `SSL_CERT_FILE`/`SSL_CERT_DIR` from its
  environment first, except for `gate with` (whose child inherits it).

## hooks_files.py (SPEC 12)

The PreToolUse file guard (Read|Grep|Glob|Edit|Write|MultiEdit|NotebookEdit;
run.py fails closed, hooks.json has `onFailure: "block"`). Denies:
Read/Edit/Write/NotebookEdit paths inside a protected location
(`paths.Protected().contains`), a Grep whose root (`path`, else the payload's
`cwd`) is protected or above a protected location, a Glob whose folder is
protected or whose pattern matches an existing protected file (folder names
alone are allowed); and Claude Code session transcripts
(`paths.is_transcript`: any `.jsonl` under a `projects` folder, a subagent's
`<session>/subagents/agent-<id>.jsonl` included; `holds_transcripts` for a
Grep root, a session folder and a Workflow run folder too; Glob listings of
their names are fine; `tool-results/` and a Workflow run's `journal.jsonl`
stay readable, the journal also to a Grep naming it). Before an
Edit/Write/MultiEdit of gateway.toml it calls `consent.ratchet()` (best
effort). launch.sh's degraded guard (while the env builds) covers the
protected locations only (and the session tools below). Round 4: the desktop
app's session tools, matched by their own hooks.json group: deny
`mcp__ccd_session_mgmt__export_transcript` always (`DENY_EXPORT`: a zip of
raw transcripts); `search_session_transcripts` and `list_events` are allowed
again since PLAN-v4 phase 3 removed the one-time codes they were held back
for; PostToolUse masks stored values in what they return.

launch.sh's fast path (review round 5, `gw_fast_files`; SPEC 12): before it
starts Python for `hook-files`, launch.sh reads the payload and gives no
decision by itself when it can settle the call in sh: a Read, Edit, Write,
MultiEdit or NotebookEdit with `"tool_name"`, `"cwd"` and the path key named
exactly once (`gw_json_str`), no other path key and no `"path"`, an
absolute path inside cwd of plain ASCII characters (no JSON escape), no `.`
or `..` part, not `.jsonl`, not naming `/.config/gateway` or a `/tmp/gw-*`
run dir in any case, no symlink, no file with more path below it, and
nothing `test -ef` the gateway home, its
`private/`, `key.txt`, `store.age` or the test/e2e run dir along the way, no
symlink inside `private/`, and an existing target a regular file with one
link. Anything else goes to Python on stdin (`run_py`), whose exit status
(2: blocked) is launch.sh's. About 10 ms instead of 40-60 ms; a test (
`test_ux_hooks::test_file_guard_fast_path_passes_only_what_python_passes`)
compares its answer with `hooks_files.main` case by case, under sh, dash and
bash.

## Wiring (hooks/hooks.json, .mcp.json)

All hooks run in exec form (`command: sh`, `args: [${CLAUDE_PLUGIN_ROOT}/hooks/...]`)
with explicit timeouts; none passes `--test`.

| event (matcher) | script | timeout | on failure |
|---|---|---|---|
| SessionStart | `launch.sh hook-session` (sync) | 20 | degraded output (env file, stubs while something may be configured, systemMessage); with an env, launch.sh writes the env file (and missing stubs) before Python |
| SessionStart | `launch.sh ensure-env` (`async: true`; builds, then warms a new env once) | 900 | - |
| SessionStart | `launch.sh hook-daemon` (`async: true`; starts the gateway daemon if needed, registers the session and records its mode, so it also runs without mods and in `-p`; prints nothing) | 60 | - |
| SubagentStart | `launch.sh hook-subagent` | 15 | open |
| UserPromptSubmit | `prompt.sh` | 15 | `onFailure: "block"`; prompt.sh blocks a paste-guard hit by itself if Python can't run |
| PreToolUse `Bash\|Monitor\|mcp__terminal__run_in_terminal\|mcp__plugin_check_jobs__job_start\|mcp__plugin_gate_gw__job_start\|mcp__plugin_gate_gw__terminal_send` | `pre_bash.sh` -> `launch.sh hook-bash` on a trigger word in any letter case (the network class and `$DATA/network-words` included; every call while gateway.toml is newer than the words file; a plain account CLI while its stand-in exists in `$DATA/bin` and `$DATA/ask-clis` names it; every Bash and Monitor call while an ask record is pending, `$DATA/asks/*`), or `launch.sh hook-mode` (record the mode only) while `$DATA/mode-epoch` exists; while no env can run, launch.sh's `degraded_bash` denies private-folder and transcript reads and credential shapes, and asks about network commands (denies them with a `[network]` table): `envfile.degraded_bash_text` | 15 | open (no decision) |
| PreToolUse `mcp__plugin_gate_gw__.*` | `mcp_perm.sh` (sh + awk); `http` and `download` -> `launch.sh hook-mcp` (`hooks_mcp`) | 10 | open |
| PreToolUse `mcp__Claude_Browser__.*\|mcp__claude-in-chrome__.*` | `tool_guard.sh`: deny while `<run>/signin-active` exists (a browser sign-in runs) | 10 | open |
| PreToolUse `AskUserQuestion` | `tool_guard.sh`: deny a question that asks for a secret | 10 | open |
| PreToolUse `Read\|Grep\|Glob\|Edit\|Write\|MultiEdit\|NotebookEdit` | `launch.sh hook-files` (sh fast path for plain paths, else Python) | 15 | `onFailure: "block"` (run.py exits 2 on an error) |
| PreToolUse `^mcp__ccd_session_mgmt__(export_transcript\|search_session_transcripts\|list_events)$` (round 4) | `launch.sh hook-files` | 15 | `onFailure: "block"` |
| PostToolUse `.*` | `post.sh` -> `launch.sh hook-post` (every tool but `hooks_post.SKIP_TOOLS`; without a vault only a token shape or a credential variable's value, with one every response; PLAN-0.11 §9.1) | 15 | open |
| PostToolUseFailure `.*` | `post.sh` -> `launch.sh hook-post` (warns; can't mask: a failed Bash command, an MCP error result such as a failed job_stop) | 15 | open |
| FileChanged (no matcher; SessionStart's `watchPaths`) | `launch.sh hook-filechanged` | 15 | open |

`hooks/home.sh` (sourced by launch.sh, post.sh and prompt.sh) defines
`gw_user_home`: the user's home from the password database (`~$(id -un)`),
as `paths.user_home()`; `$HOME` only when that gives nothing usable.

`"modules": ["./mod/register.tsx"]` (PLAN-v4 phase 1; the latest Claude
Code): `session.start` registers `/gate-doctor`
(immediate) and, in an interactive session whose env isn't ready, starts
`sh launch.sh ensure-env` through `$.process.spawn` (an argv, with the
hooks' data folder as `CLAUDE_PLUGIN_DATA`) unless a build already runs, and
shows the status line from `launch.sh status` (polled every 3 s); once the
env is ready (at once, or when the status line says ready; `-p` too) it runs
`sh launch.sh gated start` (`$.process.run`, an argv) and registers the session
on the daemon's UI plane with `$.http.fetch("http://gated/ui/register",
{socketPath})` from inside Claude Code (PLAN-v4 phase 2), with the surfaces
that draw (again at `session.attach`/`detach`);
`command.run` for `gate-doctor` answers with `lib.doctorText`, including the
daemon's line from `launch.sh gated status` (`lib.parseDaemon`, `daemonLine`).
PLAN-v4 phase 4: first in `session.start` (before the daemon and the dialog
loop) the mod reads `$DATA/managed/state.json` and sets `GW_MANAGED_DIR`,
`CLAUDE_CODE_SHELL_PREFIX` (`hooks/gate-sh`, unless the effective mode is
"off") and, once the env is built, `CLAUDE_CODE_SHELL` (the env's bash); the
three are its only env writes (docs/dev/modules/managed.md). `run.py
managed-sync` (the `$DATA/managed/sync` stub; also `launch.sh ensure-env`
after a build, with `--setup`: a missing gateway.toml first, as SessionStart
writes it) rewrites the managed shell's files. The gw MCP server's tools
include `http`, `download` and `host_inspect`; `mcp_perm.sh` allows
`host_inspect` in every mode and hands `http` and `download` to
`hooks_mcp` (the `network` policy per mode; 0.11.0).
PLAN-v4 phase 3: in an interactive session the mod long-polls
`/ui/dialog/next` and draws the session's dialog as the pane `gate-dialog`
(`ui.render` on `{ component: 'Pane', requestId: 'gate-dialog' }`): fixed
lines, buttons (hotkeys only on dialogs without a field), the queue line,
and for a secret the `Client` field (`hooks/mod/field.tsx`: bullets only;
Enter seals the value with `seal.ts`, vendored TweetNaCl, to the attempt's
public key and posts the box; `ui.message` forwards sealed items only to
`/ui/dialog/submit`, once per field instance and sequence number). The
`prompt.edit` guard holds back composer typing while a secret dialog's field
can take keys; `ui.focus` (the ring moving onto a button), a click on the
field and a new key pair start the field over; `ui.close` leaves the dialog
waiting in gated (the status line says `/gate-dialog`). Commands:
`/gate-dialog`, `/gate-unlock`, `/gate-lock` (immediate). Pure logic in
`hooks/mod/lib.ts` and `hooks/mod/dialog.ts`; tests in `hooks/mod/*.test.ts`
(`claude plugin test`).

`.mcp.json`: server `gw`, `sh ${CLAUDE_PLUGIN_ROOT}/hooks/launch.sh mcp`,
`"alwaysLoad": true`. The plugin ships no `bin/` (SPEC 7: its PATH entry
would come last).

## Tests (plugins/gateway/tests)

- `pixi run test` runs `tests/run_tests.py`, which runs every module-level
  `test_*` function in `tests/test_*.py`. Options: `-k SUBSTR`, `-x`, `-q`,
  and module names. Set `GW_TEST_TMP` to put the temp dirs somewhere else.
  It prints the slowest tests and anything left behind in `GW_TEST_TMP`.
- `tests/harness.py`:
  - `gateway_env(**override_kw)` gives a GatewayEnv with `root`, `home`,
    `data`, `run`, `user_home`, `o` (the Override), `write_form()`,
    `form()`, `vault()` and `subprocess_env()`.
  - `run_py(env, *args, payload=None, input_text=None)`: args must be a valid
    test call exactly as run.py parses it (`valid_test_argv`): `--test` as
    the FIRST or SECOND argument, a hook or MCP mode, and no other `--test`
    (`("--test", "hook-session")` or `("hook-session", "--test")`). Anything
    else (e.g. `shim gate --test status`) is refused before it runs.
    `run_launch(env, *args)` applies the same rule once a fake env is ready,
    and always passes a hook or MCP mode `--test` as its second argument (so
    launch.sh's degraded paths use the test root's home, never the real one).
    `run_stub(env, name, *args)`. `entry_cmd(env)` is for `override(entry=…)`.
  - `FakeDialog(dir, answers)`: `.script`, `.add(outcome, value, sleep)`, `.calls()`.
  - `make_fake_sudo(dir, password, nopasswd, sudoers_dir=None)`: `.path`,
    `.run()`, `.log()` (tests/fakes/fake_sudo.py: `-A/-S/-v/-n/-k/-K`,
    "Sorry, try again", NOPASSWD mode, a sudoers.d rule for the caller,
    real sudo's no-tty askpass rule, `-k CMD` never updating the timestamp).
  - `FakeVisudo(dir, sudoers_dir, fail=False)` (tests/fakes/fake_visudo.py:
    `-cf FILE`, `-c`).
  - Group harnesses: `harness_ssh.py` (real sshds on 127.0.0.1, see
    modules/ssh.md), `harness_sudo.py`, `harness_accounts.py`,
    `harness_ux.py` (`ux_env`, fake dialogs, local HTTP servers),
    `harness_posture.py` (the `user_tools` knob: recording fakes from
    `tests/fakes/fake_user_tool.py`, which also answers `ssh -G` from an
    `-F` table; `run_standin`), `harness_oauth.py` (a fake authorize and
    token server that checks PKCE, a recording program for gated's
    `browser` knob).
  - Builders: `ssh_keypair()`, `fake_host_key(seed)`.
  - The guard: `paths.home()`, `data_dir()`, `run_dir()` and `user_home()`
    called without an override abort the whole run (`GuardTripped`), as does
    any path under the real gateway home. `GW_TEST_REAL_HOME` (set by
    `tests/mutations_daemon.py` for its runs only) makes a scratch folder
    stand in for the person's home, so a mutated guard stats a fake
    `~/.config/gateway`.
- `tests/harness_daemon.py` (PLAN-v4 phase 2): `daemon_env(knobs=…)` (a
  real daemon in a test root with a short run dir; `start()`, `stop()`,
  `call()`, `probe()`, `wrap()`, `unlock()`, `log()`), `attach(env, run)`
  (a daemon for another harness's env, such as `ssh_env`), `FakeClaude` (a
  copy of python named `claude` running `tests/fakes/fake_claude.py`:
  registers on the UI plane from its own pid, runs children below itself;
  `exe=` for a private copy a test may delete), `named_python(name,
  folder)`, `python_at(prefix)` (a data folder's env layout),
  `probe_root(base, name, folder)` (a test entry inside the test root while
  the `test_entries` knob is on; `probe(..., options=, through=)`),
  `plugin_copy(root, version)` + `start_from(plugin)` / `gated_from(plugin,
  ...)` (the plugin in Claude Code's plugin cache layout, where sibling
  version folders are entry points), `write_driver(env, run, **override)` (a
  test entry point for stand-ins; `GW_DUMP=1` prints which secret slots a
  mode sees), `full_vault(passphrase)`.
- Mutation checks: `tests/mutation_check.py` (core) and
  `tests/mutations_*.py` (how they run: [TESTING.md](TESTING.md); counts
  per run: [TEST-LOG.md](TEST-LOG.md)) weaken one
  security guard each and expect the named test to fail. `pixi run
  mutations` (`tests/run_mutations.py [-j N] [-k SUBSTR] [FILE...]`) runs
  them all, each file on its own scratch copy of the plugin (`--copy DIR`),
  never on the checkout.
- `pixi run e2e` (`tests/e2e/run_e2e.py`, scenarios in `tests/e2e/scenarios.py`,
  the redirection in `tests/e2e/README.md`; `tests/e2e.py` only forwards to
  it): the headless suite (not part of `test`), real `claude -p` sessions
  against a scratch copy of the plugin carrying the `e2e-root` marker.
- Never run gateway Python in a subprocess without a valid `--test` or
  `tests/entry.py` (or an explicit `testing.override` in `-c` code). The
  in-process guard can't see child processes; run.py also refuses when
  `GATEWAY_TEST_ROOT` is set without a valid `--test`.
