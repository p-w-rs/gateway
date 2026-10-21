# Gateway v3 modules

The modules of gateway v3 (written for plugin 0.7.0; the tables and the
per-group docs below are kept current through plugin 0.9.0 and PLAN-v4) and
their APIs, as built. The
contract is [SPEC-v3.md](SPEC-v3.md); section numbers below refer to it. All
code is in `plugins/gateway/src/gateway/`, Python 3.12 stdlib only. Import as
`from . import paths, form, vault, ...`.

This file covers the core (paths, testing, form, accounts, vault, consent,
migrate, audit, envfile, warm, hooks_session, gate, run.py, hooks_files) and how
everything is wired. The rest is documented per group, kept current with the
code:

| group | modules | doc |
|---|---|---|
| sudo / approvals | `sudo.py`, `ancestry.py`, `bashparse.py`, `hooks_bash.py`, `hooks/pre_bash.sh` | [modules/sudo.md](modules/sudo.md) |
| ssh | `ssh.py`, `ssh_args.py`, `ssh_conf.py`, `ssh_sudo.py` | [modules/ssh.md](modules/ssh.md) |
| accounts | `scrub.py`, `githelper.py`, `clis.py`, `asiml.py`, `entra.py`, `logins.py` | [modules/accounts.md](modules/accounts.md) |
| ux | `popup.py`, `dialog.py`, `gate_setup.py`, `transfer.py`, `web.py`, `mcp_server.py`, `hooks_post.py`, `hooks_prompt.py`, `hooks_filechanged.py`, `hooks/post.sh`, `hooks/prompt.sh`, `hooks/mcp_perm.sh` | [modules/ux.md](modules/ux.md) |
| daemon (PLAN-v4 phases 2, 3) | `daemon/` (`peers.py`, `planes.py`, `events.py`, `broker.py`, `server.py`, `lifecycle.py`, `dialogs.py`, `clipboard.py`, `client.py`), `agepass.py` | [modules/daemon.md](modules/daemon.md) |
| terminals and jobs (PLAN-v4 phase 5) | `daemon/terminals.py`, `daemon/screen.py`, the gw tools in `mcp_server.py`, `hooks/mod/{terminal.ts,term.tsx}` | [modules/terminals.md](modules/terminals.md) |
| the managed remote runtime (PLAN-v4 phase 6) | `runtime/pixi.toml` + lock, `runtime_pack.py`, `daemon/remote.py`, remote panes in `daemon/terminals.py`, `host_runtime` in `mcp_server.py` | [modules/remote.md](modules/remote.md) |
| hosts, workspaces, policy, accounts' states, portability (PLAN-v4 phase 7) | `policy.py`, `adapters.py`, `manage.py`, the policy/workspace/shell tables in `form.py` and `consent.py`, `transfer.py` format 3, `hooks/mod/manage.ts` | [modules/policy.md](modules/policy.md), [modules/accounts.md](modules/accounts.md), [modules/ux.md](modules/ux.md) |
| managed execution (PLAN-v4 phase 4) | `managed.py`, `hooks/gate-sh`, `[shell]` in `form.py` and `consent.py`, `hooks_bash._managed_gate`, the mod's `managedSetup` | [modules/managed.md](modules/managed.md) |

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
| `form_path()`, `from_v2_form_path()`, `launcher_path()`, `env_sh_path()` | `gateway.toml`, `gateway.from-v2.toml`, `gate`, `env.sh` |
| `private_dir()`, `key_path()`, `vault_path()`, `cache_path()`, `lock_path()`, `backups_dir()`, `pending_dir()` | `private/…` |
| `v2_store_path()`, `v2_key_path()`, `v2_lock_path()` | v2 `store.age`, `key.txt`, `.lock` |
| `ensure_home()`, `ensure_private()` | create them with mode 0700 |
| `data_dir()` | hook/MCP modes: `CLAUDE_PLUGIN_DATA`. Every mode: the folder of the pixi env that `sys.executable` belongs to (`<DATA>/envs/<sha12>/.pixi/envs/default/bin/python3`). Then `GW_DATA` (the stubs set it themselves), then `~/.claude/plugins/data/gate-gateway` (`CLAUDE_CONFIG_DIR` only in hook/MCP modes). |
| `trust_plugin_env(ok)`, `data_from_executable(exe=None)` | run.py's per-mode switch; the env-python rule above |
| `bin_dir()`, `git_dir()`, `git_config_path()`, `envs_dir()`, `audit_path()` | `$DATA/bin`, `$DATA/git`, `$DATA/git/config`, `$DATA/envs`, `$DATA/audit.jsonl` |
| `run_dir()` | `/tmp/gw-$UID`, created with mode 0700. Raises `PathError` if it isn't a directory owned by you with mode 0700. |
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
| `checkpoint_state_dir()` | the checkpoint plugin's state folder (`${XDG_STATE_HOME:-~/.local/state}/checkpoint`; under a test override always in the test's home). Only its existence is read: Claude's context then mentions checkpoint jobs (SPEC 13) |

## testing.py: the explicit test API

- `testing.override(root, **kw)` redirects every location under `root`: home
  is `root/home/.config/gateway`, user_home `root/home`, data `root/data`,
  run `root/run`. Keywords: `home=`, `data=`, `run=`, `user_home=`,
  `plugin_root=`, `env_python=`, `entry=[argv]` (stubs exec this instead of
  run.py), `local_user=`, `machine_id=`, `tools={name: path}`, `dialog=`
  (fake dialog backend for popup.py), `keyscan=` (dict or callable),
  `system_git=` (True/False). Any other keyword lands in `.extra`. It refuses
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
  A missing file gives an empty form with localhost implicit (`exists=False`).
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
- `clear_cache()`
- Writers: `append_table("hosts.NAME", {key: value}, comment=..., path=None)`
  and `set_key("hosts.NAME", "sudo", False, path=None)`. Both refuse a form
  with a syntax error. They re-parse after writing and roll back (raising
  `FormWriteError`) if the document changed elsewhere or another entry gains
  or changes errors (another entry losing errors, i.e. being fixed, is fine).
  `toml_value(v)` serializes one value.
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
          settings: Settings(others="refuse"|"mine", others_invalid=False),
          hosts: {name: Host}            # valid entries, plus the implicit localhost
          accounts: {name: Account}      # valid entries only
          disabled: {safe name: first error}
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
          via, ssh/sudo: True|"ask"|False, scripts, note, explicit (False = implicit localhost)
          is_local, addresses() (address first, then also), user()
Account:  name, kind, line, login, owners, default, commit_name (the `name` key), email, env,
          scripts, use, note, host (github/ml-catalog/pijul/registry; may carry :port),
          packages (github), tenant, client_id (default Azure CLI client), databricks,
          storage, registries, sites (azure extra sites / api-key sites), remote_pijul,
          auth (api-key; default "bearer")
          destinations(), ssh_endpoints(), owner_names() (login + owners)
```

Disabled entries are absent from `hosts`/`accounts`. Treat them as having no
rights; the reason is in `disabled[name]`. A broken `[hosts.localhost]` is
disabled, which means no localhost sudo, not the implicit default. Use
`is_disabled(name, section)` rather than `name in disabled` when a name may
be valid in the other section. An invalid `[settings] others` means
"refuse" for now, but keeps the approval (no ratchet).

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
  that kind and host, approved or not (SPEC 9.6 step 5).
- `select(kind | (kinds…), host, owner, form, *, effective, vault=None, env=None) -> Selection`
  (`effective` is required: `consent.compute(form, vault_data)`).

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
- `load()` (a missing vault is `empty()`), `save(data, *, migrating=False)`,
  `locked()`, `edit()` (a context manager: locked load, saves only if
  changed), `exists()`, `ensure_key()`, `recipient()`, `empty()` (a fresh
  vault dict), `now()` (the timestamp format used everywhere), `VaultError`
  (raised for unreadable/unwritable vaults; the message holds no secret).
  `save` refuses to create `vault.age` while a v2 `store.age` waits for
  migration.
- Cache (short-lived tokens): `cache_get(account, scope, margin=120)`,
  `cache_put(account, scope, value, expires_at)` (call it under
  `locked()`), `cache_clear(account=None)`, `cache_values()`, `cache_load()`,
  `cache_save()`.
- Events: `add_event(data, what, detail)` keeps the last 100, each with
  `n` and `at`. `new_events(data)` and `mark_events_seen(data)` track
  `events_seen`. Kinds: widen, narrow, bind, export, copy, import, migrate,
  reject, hostkey, forget.
- Machine: `machine_id()` (IOPlatformUUID, `/etc/machine-id`, else None),
  `ensure_machine(data)` (falls back to a random id stored in the vault),
  `short_hostname()`.
- Records: `resolve(data, name, entries=())` (aliases; a name in `entries`
  is never redirected), `host_record(data, name)`,
  `account_record(data, name, kind)`, `sudo_entry(data, host, user)`,
  `set_sudo(data, host, user, pw)` (host `"localhost"` maps to
  `localhost.sudo`), `forget_sudo(data, host, user)`,
  `sudo_choice(data, host, user)` / `set_sudo_choice(data, host, user,
  "password"|"nopasswd"|None)` (gate check's sudo choice, per machine: not
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
  `export_view(data)` is the vault without approved, imported, last-good and events.
- Keys: `normalize_key`, `public_key_of`, `fingerprint_of`,
  `generate_ssh_key(comment)`, `norm_host_key(line) -> "type key"`,
  `host_key_fingerprints(keys)`, `builtin_host_keys(host, port)`, and
  `keyscan(host, port=22)` (built-in keys for github.com, ssh.github.com,
  hf.co and nest.pijul.com; else `ssh-keyscan`; tests use
  `override(keyscan=…)`).
- Constants: `GITHUB_HOST_KEYS`, `HF_HOST_KEYS`, `NEST_HOST_KEYS`.

The schema is SPEC 3 plus: `events[].n` and `events_seen` (which events
SessionStart has shown); `migrated.shown`, `migrated.trigger` and
`migrated.form` (`gateway.toml` or `gateway.from-v2.toml`); `imported`
(below); `hosts[NAME].installed` (set after a successful key install or test
login; status shows "key installed"), `hosts[NAME].pinned_at`,
`hosts[NAME].host_keys_previous` (gate forget's memory of forgotten pins);
`sudo_choice` (`{host: {user: "password"|"nopasswd"}}`). Host keys are
stored as `"type base64"`.

## consent.py: effective rights (SPEC 5)

- `compute(form, data=None) -> Effective`: approved rights compared with the
  form (`data` is the vault dict). Narrowing applies at once; widening stays
  pending. Since PLAN-v4 phase 7 the same holds per policy key
  (`policy_compare`: an absent restriction ranks as allow, an absent grant as
  deny), per workspace (a new or moved root waits; a removed one goes at once:
  `EffectiveHost.workspaces`, `EffectiveWorkspace`) and per remote import
  (`EffectiveHost.import_path` / `import_env`); `Effective.policy` is
  `[policy]`'s, under the `settings` entry. Decisions: `policy.decide`
  ([modules/policy.md](modules/policy.md)).
- `ratchet(form=None) -> [Change]`: persists the narrowings the current form
  shows (lowers `approved`, drops removed entries' bindings, moves copied-in
  imported entries into `approved`), logs a `narrow` event, closes ssh
  masters, and keeps `form_last_good` = the last valid form seen
  (`last_good_ok(form)`: read from the file, parses). Reads the vault; writes
  only when something narrowed or the valid form differs from the stored
  copy. With no vault yet, a narrowing creates one (review round 2: a fresh
  install's `localhost sudo = false` was lost at the next syntax error).
  Never on a missing form, a syntax error, or while a v2 store.age is
  present. `approve` stores `form_last_good` too.
  **Contract:** call it from every process that loads the form:
  SessionStart, SubagentStart and every `gate` command (via
  `hooks_session.prepare`), the file guard before an Edit/Write/MultiEdit of
  gateway.toml (so narrow-then-raise within one session needs the OK),
  FileChanged, PostToolUse on form edits, the Bash hook when a command names
  `config/gateway` (sed -i edits bypass the file guard), and each stand-in /
  the http tool before using a right (cheap when unchanged).
- `needs_sync(data, form)`: would `sync_narrowing` change anything?
- `sync_narrowing(data, form) -> [Change]`: the in-memory part of `ratchet`
  (the caller saves). Never widens; skips disabled entries (per section),
  a missing form, a syntax error and an invalid `others`.
- `approve(entry, changes=None, form=None, *, keep_credentials=False) -> [lines]`:
  call only after the user said yes, passing the changes the pop-up showed.
  If the entry's pending changes differ, it raises `ConsentChanged` and
  approves nothing. It writes `approved.rights[entry]`, adds an account's
  destinations to `bound.hosts` (plus api-key `auth` and azure
  `tenant`/`client_id`), removes the entry from `imported`, logs a `widen`
  event and audits the consent. An account `drops_credential(data, account)`
  names (no approved or imported snapshot of that name, or another kind)
  first loses its stored `CREDENTIAL_FIELDS` (token, ssh_key, entra,
  host_keys), cached tokens and bindings, with a `forget` event, so `gate
  check` (whose plan sees the same test) asks for a fresh secret (review round
  2); `keep_credentials=True` only for an import, whose credentials came with
  the listed entry. `entry` may be `"settings"`. `approve_all(form)` approves
  everything, keeping credentials (tests).
- `close_masters_for(changes, form)` calls `ssh.close_masters` for hosts
  whose address, via or ssh right narrowed. NotImplementedError is tolerated.
- `bound_hosts(data, name)`, `bound_ok(data, name, host)`, `unbound(form_account, data)`
- `snapshot(form)`, `host_snapshot(h)`, `account_snapshot(a)`, `baseline()`
  (the empty form), `approved_rights(data)`, `imported_rights(data)`
- `load_form(data=None)`: the form, with the vault's last good text as the fallback.
- `ask_phrase(name, verb)` ("ssh on box", "sudo (root) on box", "sudo on
  this machine") and `job_ask_message(phrases)`: the refusal for `"ask"`
  rights inside a checkpoint job, shared by the approval hook (job_start)
  and the ssh and sudo stand-ins (culprit `ancestry.CHECKPOINT`);
  `pane_ask_message(phrases)`: the same inside a gateway terminal or job
  (culprit `ancestry.TERMINAL`).

```
Effective:  form, others ("refuse" unless the user approved "mine"), hosts {name: EffectiveHost},
            accounts {name: EffectiveAccount}, pending [Change] (widenings), narrowed [Change], approved,
            disabled (= form.disabled); host(n), account(n), right(host, "ssh"|"sudo"|"scripts"),
            pending_for(n), pending_names()
EffectiveHost:    name, ssh, sudo, scripts (min of approved and form), addresses [Address] (approved
                  candidates only, in form order; none means ssh False), via, new (never approved:
                  everything False), pending [Change], host (the form Host), is_local
EffectiveAccount: name, kind, use, scripts, env (None until approved), destinations (form ∩ approved ∩ bound),
                  owners, auth/tenant/client_id (the approved values while a change is pending), new,
                  pending, account (the form Account); may_send_to(host)
Change:     entry, kind ("widen"|"narrow"), what (safe text), line; render() -> "box: sudo \"ask\" -> true"
```

Without any approved snapshot, the baseline is an empty form: localhost with
sudo true, others "refuse". A jump host's ssh right caps the hosts behind it.

`imported` = `{"from": "v2", "at", "rights": {"hosts": {...}, "accounts": {...}}}`:
written by migration when the user already had a gateway.toml (the converted
entries go to gateway.from-v2.toml). An entry that is in the form but not in
`approved` counts as approved up to its imported rights (copying it in needs
no pop-up and keeps its keys and bindings); anything beyond them is a widening.
Imported entries that aren't in the form are neither approved nor "removed".

## migrate.py: v2 to v3 (SPEC 4)

- `needed()` is true when a v2 store exists and there is no `vault.age`.
  `leftover_v2()` is true when a v2 store sits next to a v3 vault.
- `ensure(trigger) -> Result | None`: runs `run()` only when needed; None
  when there was nothing to do, including when another process migrated
  first. run.py calls it for stand-ins and the MCP server; SessionStart and
  `gate` call it too.
- `run(trigger) -> Result` with fields `ok`, `status` (migrated, failed,
  not-needed, already, stray, conflict), `message`, `report` and `form_path`.
  It decides again under both locks (home/.lock and private/.lock), so
  concurrent first processes never fail. A failure writes nothing and leaves
  `store.age` in place. `last_failure()` is kept in the run dir. One odd v2
  entry (control characters, an unknown kind, a bad address, colliding sudo
  passwords, more rotated private keys than public keys) is dropped or fixed
  and reported, never a permanent failure; the failure reason names the full
  ref (`sudo joshua@lab.example.com`).
- `tidy_leftover() -> Result | None`: a v2 store.age next to the v3 vault
  (SessionStart calls it; `gate migrate` does the same): the migrated store
  is moved into the backups (and a missing gateway.toml restored from
  `form_last_good`); a different one (an old v2 session wrote after the
  upgrade; it holds only what was written since) is moved into
  `private/backups/store-v2-stray-YYYYMMDD.age` with its key, an event is
  logged, and the user is told what it held (names only). The v3 vault is
  never replaced.
- `map_v2(v2_dict, local_user=None, mode="migrate"|"export") -> Mapped`
  holds `form_text`, `vault`, `renames`, `now_true`, `defaults`, `folded`,
  `dropped`, `dropped_refs`, `attention`, `lost`, `switches`, `aliases`,
  `source_localhost` (`{"sudo": {user: rec}}` in export mode) and `report`.
  It writes `default = true` on a v2 catch-all account (no owners) next to
  owner-specific ones, maps a two-label v2 secret host `x.com` to
  `["x.com", ".x.com"]` (v2 matched subdomains), `*.x` to `.x`, reports
  `sudo on HOST` for every migrated host, and never stores an alias that is
  itself an entry name.
- `map_export_v1(obj)` maps a v2 export file (`gateway_export: 1`) for
  `transfer.import_cmd`. `check(mapped, v2)` re-validates a mapping.
- `HEADER` and `STARTER` are the form's header comment and the starter form.
  `mark_report_shown()`. `report_flag()` is `private/migrated.unshown`, left
  by a successful `run()` (round 4); `take_unshown_report()` gives the report
  once (marking it shown, removing the flag) to the UserPromptSubmit hook, so
  a mid-session conversion reaches the user at the next prompt. User-facing
  text says "0.6" for the old version; "v2" stays the internal name.
- Backups: a byte-identical earlier copy is reused whatever its date
  (`store-v2-*.age`, `key-v2*.txt`).
- The v2 decryption and rules are in `vault_v2.py`: `decrypt(store, key)`,
  `normalize`, `routes`, `keys` (every rotated private key, public or not),
  `account_for_sudo`, `effective_prompts`, `credentials` (text values only),
  `account_credentials(ref, acct)`.

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

- `env_text(others)` is the env file text: PATH, the git include,
  `GIT_SSH_COMMAND`/`RSYNC_RSH`, the unsets, all inside `if [ -d "$GW_BIN" ]`
  (after `ENV_HEADER` and `GW_BIN=`), so env.sh does nothing for a launcher
  that sources it (a checkpoint job) once the stand-in folder is gone.
  Nothing that changes how a
  command ends (round 3's `EXIT_TRAP` is rolled back: a failed command exits
  with its own code; DECISIONS, "Rolled back").
  `write_env_file(path, text)`
  replaces the file whole (`_atomic`: `.NAME.PID.tmp` renamed over it, so a
  killed SessionStart never leaves it empty or cut short; Claude Code
  sources only `sessionstart-hook-N.sh`); `write_env_sh(text)` writes
  `env.sh`. `drop_stale_temps(p)` removes a killed writer's `.NAME.*.tmp`
  once it is an hour old (`_atomic` calls it). `ENV_UNSET`
  lists the variables unset when others is "refuse".
- `stub_text(name, args)`, `stand_ins(form, eff) -> {name: text}`,
  `write_stubs(stubs)`: each stub is written to a temp file and renamed over
  the old one inside `$DATA/bin` (the folder is never moved, so a running
  command never finds no stub); names no longer generated are removed. The
  base stand-ins are sudo, ssh, scp, sftp, gh, hf, databricks, crane, pijul,
  asiml, gate, git-credential-gateway and gate-askpass. Conditional ones:
  `dvc` (when an ml-catalog account exists), `az` (when an azure account has
  an approved `env`), `git` (pixi's git, only when the system has no git).
  Stubs set `GW_DATA`, unset `CLAUDE_PLUGIN_DATA`, and exec
  `<env python> -I -S run.py shim TOOL "$@"` (gate: `run.py gate`;
  credential helper: `run.py git-credential`; askpass: `run.py askpass`).
  Until the env is ready they print "still setting up" and exit 75; sudo
  then execs `/usr/bin/sudo`. `older_env_python()`: when this process runs
  from another finished env (launch.sh's fallback while an update builds),
  each stub gets a second `exec` line for it, before the not-ready text.
  launch.sh's degraded stubs (no env at all) say instead that pixi is
  missing or the build failed, when that is the case; with a build running
  they stay byte-identical to `stub_text`.
- `launcher_text(state="building")` and `write_launcher()` write
  `~/.config/gateway/gate` (mode 0700); when the plugin's run.py is gone the
  launcher says so (`LAUNCHER_GONE`, exit 1) instead of "still setting up".
  launch.sh writes the same bytes in its degraded session (round 3: the first
  session had no launcher though no-screen messages name it), in each of its
  states: `launcher_not_ready(state)` is `STILL_SETTING_UP` ("building"),
  `LAUNCHER_NOPIXI` ("nopixi") or `launcher_failed(log)` ("failed"), all
  written for the user (round 4: the pixi-missing and failed launchers
  repeated the stubs' "tell the user" text for Claude).
- `GIT_RESET`, `git_config_text(others, helper_text)`,
  `write_git_config(form, meta, others="refuse")`: `$DATA/git/config` =
  the global `[credential] helper =` reset when others is "refuse" (always,
  so git never falls back to the user's keychain helper), then
  `githelper.include_config(form, meta)`; plus `githelper.identity_files(form)`
  as `$DATA/git/<name>`. An empty result removes a stale file. **githelper
  must not emit the global reset itself**, only URL-scoped sections.
- `sync(form, eff, meta, env_file)` does all of the above.
  `cleanup_envs(days=7)`. `system_git()`.
- `launch.sh` produces byte-identical env file, stubs, git reset and
  launcher in degraded mode (tests compare them, the launcher in all three
  states). If the code changes, change both. It takes the user's home from
  the password database (`hooks/home.sh`, `gw_user_home`; round 4), never
  `$HOME`; tests pass `MODE --test` with `GATEWAY_TEST_ROOT` (the test root's
  home), and `GATEWAY_TEST_ROOT` without `--test` resolves no home at all. Its
  degraded file guard matches path fields case-insensitively and refuses Grep
  from a folder above a protected location; a failed env build (install.log,
  no `.ready`, no build running) is reported at SessionStart.
- launch.sh `pre_session` (jobs-lows round 2): before it execs Python for
  `hook-session` (current or older env), it writes the env file
  (`write_env_file`: temp file + `mv`, the refuse text) and, when one of the
  base stand-ins (`STUB_NAMES`, `BASE_STANDINS`' names) or the git include
  is missing, the stand-ins and the git reset, so a SessionStart that Claude
  Code cancels or kills still leaves Claude's commands on the stand-ins
  without the user's agent and tokens. `write_stubs` quotes its paths once
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
  The how-to lines are `HOWTO`, plus `JOBS_HOWTO` (checkpoint jobs: stand-ins
  through env.sh, curl refused, no "ask" rights, job_tail/job_stop masked) when
  `paths.checkpoint_state_dir()` exists.
- `prepare(msgs, write=bool) -> (form, eff, vault_data)`: the shared loader.
  Every mode ratchets (consent.ratchet; also with no vault yet, where only a
  narrowing creates one). A missing form is restored from the
  vault's `form_last_good` (write=True), never replaced by the starter when
  the vault holds approvals or can't be read; the starter is written only
  when nothing is stored. With `write=True` it also keeps `form_last_good`
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
- SessionStart returns `watchPaths: [gateway.toml]` for FileChanged.
- `form_messages(form)` returns the user-facing problem lines.
  `ok_how(target, names)`: how the user gives an OK that waits: Claude
  opens the gateway's dialog with `gate check NAME`, answered in Claude
  Code (a terminal session or the desktop app; not -p, VS Code, mobile or
  Remote Control). An unreadable vault's
  message names the next step (restore `private/key.txt`, or start from an
  export).

## gate.py (SPEC 15) and run.py

- `gate.main(argv)`: status, migrate, log, why, import-ssh, scrub and help here;
  check, login, forget, rotate and secret dispatch to `gate_setup`; with to
  `clis.with_main`; export, import, copy-to and pubkey to `transfer`.
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
  version, epoch, uptime, vault state; never starts it).
- run.py modes: hook-session, hook-session-async, hook-subagent, hook-bash,
  hook-files, hook-post, hook-prompt, hook-filechanged and hook-daemon (JSON
  on stdin, JSON on stdout); mcp; `shim TOOL …`; askpass; git-credential;
  gate; `gated serve|start|status|stop` (the daemon). A stand-in refuses up
  front with the daemon's words when a wrapped vault is locked or can't be
  had (`_vault_locked`).
  `parse_test_flag(argv)`: `--test` counts only as the first or second
  argument and only for hook, MCP and gated modes; with `GATEWAY_TEST_ROOT` set and
  no valid `--test`, run.py exits 2 before resolving any path. Failure
  policy: hook-files fails closed (exit 2), hook-prompt blocks, the others
  fail open. A stand-in that raised NotImplementedError would be refused
  (exit 75), never replaced by the system tool; no module raises it any
  more. An unexpected exception in a stand-in or `gate` prints one
  `gateway: TOOL failed unexpectedly (TypeName)` line (never a traceback)
  and exits 1 (`_failed`, round 3). `run.py gate` (and `shim gate`) drops `HTTP(S)_PROXY`, `ALL_PROXY`,
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
| SessionStart | `launch.sh hook-session` (sync) | 20 | degraded output (env file, stubs, systemMessage); with an env, launch.sh writes the env file (and missing stubs, git reset) before Python |
| SessionStart | `launch.sh ensure-env` (`async: true`; builds, then warms a new env once) | 900 | - |
| SessionStart | `launch.sh hook-daemon` (`async: true`; starts the gateway daemon if needed and registers the session with it, so it also runs without mods and in `-p`; prints nothing) | 60 | - |
| SubagentStart | `launch.sh hook-subagent` | 15 | open |
| UserPromptSubmit | `prompt.sh` | 15 | `onFailure: "block"`; prompt.sh blocks a paste-guard hit by itself if Python can't run |
| PreToolUse `Bash\|Monitor\|mcp__terminal__run_in_terminal\|mcp__plugin_check_jobs__job_start` | `pre_bash.sh` -> `launch.sh hook-bash` (job_start: checkpoint's detached jobs, judged by `hooks_bash` with no allow and "ask" denied; Bash and Monitor without the gateway's `CLAUDE_CODE_SHELL_PREFIX`: every call, with `GW_MANAGED_CHECK=1`, for the managed-mode deny or notice (PLAN-v4 phase 4); while no env can run, launch.sh's `degraded_bash` denies private-folder and transcript reads, credential shapes, with a vault curl/wget, and such a managed-check call: `envfile.degraded_bash_text`) | 15 | open (no decision) |
| PreToolUse `mcp__plugin_gate_gw__.*` | `mcp_perm.sh` (sh + awk only) | 10 | open |
| PreToolUse `Read\|Grep\|Glob\|Edit\|Write\|MultiEdit\|NotebookEdit` | `launch.sh hook-files` (sh fast path for plain paths, else Python) | 15 | `onFailure: "block"` (run.py exits 2 on an error) |
| PreToolUse `^mcp__ccd_session_mgmt__(export_transcript\|search_session_transcripts\|list_events)$` (round 4) | `launch.sh hook-files` | 15 | `onFailure: "block"` |
| PostToolUse `^(Bash\|BashOutput\|Monitor\|Read\|Grep\|Edit\|Write\|MultiEdit\|mcp__terminal__read_terminal\|mcp__plugin_gate_gw__.*\|mcp__ccd_session_mgmt__search_session_transcripts\|mcp__ccd_session_mgmt__list_events\|mcp__plugin_check_jobs__job_tail\|mcp__plugin_check_jobs__job_status\|mcp__plugin_check_jobs__job_stop)$` | `post.sh` -> `launch.sh hook-post` (with a vault: every tool but the edit tools; round 5; checkpoint's job_tail/job_status/job_stop since the integration review: a job's log) | 15 | open |
| PostToolUseFailure (same matcher) | `post.sh` -> `launch.sh hook-post` (warns; can't mask: a failed Bash command, an MCP error result such as a failed job_stop) | 15 | open |
| FileChanged (no matcher; SessionStart's `watchPaths`) | `launch.sh hook-filechanged` | 15 | open |

`hooks/home.sh` (sourced by launch.sh, post.sh and prompt.sh) defines
`gw_user_home`: the user's home from the password database (`~$(id -un)`),
as `paths.user_home()`; `$HOME` only when that gives nothing usable.

`"modules": ["./mod/register.tsx"]` (PLAN-v4 phase 1; Claude Code 2.1.287+
terminal, 2.1.286+ desktop): `session.start` registers `/gate-doctor`
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
three are its only env writes (docs/modules/managed.md). `run.py
managed-sync` (the `$DATA/managed/sync` stub; also `launch.sh ensure-env`
after a build) rewrites the managed shell's files. The gw MCP server's tools
are `http`, `download` and `host_inspect` (allowed by `mcp_perm.sh` in every
mode).
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
    `form()`, `vault()` and `subprocess_env()`. Its override starts with
    `extra["claude_ancestor"] = ""` (no Claude Code ancestor; a leftover of
    the removed `gate secret` check, whose `ancestry.claude_ancestor` keeps
    its own tests).
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
    `harness_ux.py` (`ux_env`, fake dialogs, local HTTP servers).
  - v2 builders: `write_v2_vault(home, data)` (v2 code from git main),
    `read_v2_vault`, `users_v2_vault(local_user)`, `ssh_keypair()`,
    `fake_host_key(seed)`.
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
- Mutation checks: `tests/mutation_check.py` (core, 76) and
  `tests/mutations_{sudo,ssh,accounts,ux,e2e,packaging,daemon,dialogs}.py`
  (counts in CLAUDE.md, "Last full run") weaken one
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
