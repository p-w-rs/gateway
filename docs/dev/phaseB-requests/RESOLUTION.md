# Phase B requests: resolution (phase C, 2026-10-19)

> Historical record. Superseded where it concerns sudo: PLAN-v4 phase 7 removed
> the passwordless sudo setup of #7 (the sudoers file, its choice and its
> advice); the gateway never writes or recommends a sudoers rule
> (docs/dev/DECISIONS.md "No sudoers rule, ever", docs/dev/modules/sudo.md). The rows
> that describe it are marked.

Every request in `accounts.md`, `ssh.md`, `sudo.md` and `ux.md`, plus the
phase C task list, with what was done. "Accepted" means implemented as asked,
"adapted" means implemented differently (reason given), "rejected" means not
done (reason given). Tests and mutations named here are in
`plugins/gateway/tests/`.

## Blocking and stale tests

| request | resolution |
|---|---|
| test_consent abort: `close_masters_for` ran the real `ssh.close_masters` outside `testing.override` (accounts, sudo #1, ssh #1, ux) | **Accepted** (ssh #1's fix): the last assertion runs inside `H.gateway_env()` and expects `["box"]`. `close_masters_for` still catches only `Exception`, so the harness guard keeps aborting a run that touches a real path. |
| Stale phase-A placeholder tests (sudo #2, ssh #2, ux, accounts) | **Accepted**. `test_harness_run`: `test_shims_refuse_and_never_run_the_system_tool` (a landed stand-in refuses `x`, the user's own tool never runs), `test_mcp_serves_http_and_download` (answers matched by id, `_meta anthropic/alwaysLoad`), `test_stand_in_triggers_migration` (asiml exits non-zero, migration still happens). `test_gate`: `test_setup_and_transfer_commands_dispatch`. |

## Group accounts (`accounts.md`)

| request | resolution |
|---|---|
| Keep `ancestry.is_direct` stable; CLI tools stay out of `CRED_FAMILY` | Kept (no change needed). |
| Delete clis's fallback ancestry walker | **Accepted**: `clis.is_direct` only calls `ancestry.is_direct`; any error there counts as not direct (allowed only with `scripts = true`). Test `test_direct_check_fails_closed_when_ancestry_errors`, mutation in `mutations_accounts.py`. |
| `web._opener` honours proxy variables and `SSL_CERT_FILE` | **Accepted**: `ProxyHandler({})` and `entra.tls_context()` (the build's CA bundle). Tests `test_proxy_variables_are_ignored`, `test_ssl_cert_file_is_ignored`; two mutations. Consequence (documented in SPEC 14): a user who needs a proxy to reach a site can't use the http tool for it in v3.0. |
| az: raw token for a scripts caller? | **Adapted** (phase C decision): the token is printed as is. The az stand-in exists only for an azure account with an approved `env` (the user's opt-in for programs to get its tokens), and a caller that is neither direct nor covered by `scripts = true` is refused before anything is minted (the standard "got no credential" line, rather than a JSON with `***` that would break the SDK the same way, less clearly). Claude's own Bash output still passes the PostToolUse scrubber (Entra tokens are JWT-shaped). Test `test_az_token_only_for_direct_callers_or_scripts`; the fail-open masking test/mutation was replaced by one for the direct check. SPEC 9.5 updated. **Narrowed in review round 2**: a direct caller (Claude's own command, including under Monitor, whose streamed lines PostToolUse never sees) never gets the raw token any more; only a program Claude's command started, with `scripts = true` (`test_az_never_gives_claudes_own_command_a_raw_token`); the Bash hook denies `az … get-access-token` for Bash and Monitor. |

## Group ssh (`ssh.md`)

| request | resolution |
|---|---|
| #1 test_consent | See above. |
| #2 test_harness_run shim test | See above. |
| #3 `accounts.select` hands a pending owner-matched account's repos to the other account | **Accepted** in accounts.py: an owner-matched account that isn't usable (waiting for the user's OK, credential not bound, `use = false`) refuses with `gateway: NAME is the account for OWNER but can't be used yet (it waits for the user's OK); run gate check NAME while the user is here` (or `has use = false ...`); never falls back to the default or the only other account. The "only account" rule counts the form's accounts of that kind and host, approved or not (SPEC 9.6's "exists"); a pending default is named too; an owner matched by a live and a pending account is ambiguous. ssh.py's `_pending_owner_account` work-around was removed (select is the single source). Tests in `test_accounts.py` (4 new) and `test_ssh_git`; mutations in `mutations_accounts.py` and `mutations_ssh.py`. The phase A row `use_false_never_picked` now expects the refusal (a use = false account's repos don't go to another account either). |
| #4 fake sudo: real sudo's no-tty askpass rule | (Superseded in part: the tests that needed the sudoers rule mode were #7's, removed in PLAN-v4 phase 7; the fake keeps the mode to stand for a rule the user configured.) **Accepted** in `tests/fakes/fake_sudo.py` (without `-S`/`-A`, with `SUDO_ASKPASS` and `DISPLAY` and no terminal: askpass). The fake also learned two real-sudo behaviours the new tests need: a `sudoers_dir` whose `USER ALL=(ALL) NOPASSWD: ALL` rule makes it passwordless (includedir rules: no dot in the name), and `-k CMD` never updating the timestamp. harness_ssh's wrapper is kept (harmless). |
| #5 shared stand-in entry with override keywords | **Rejected**: harness_ssh (`ssh-entry.json`) and harness_ux (`--entry`) already have entries that fit their needs, and every other group's stand-in tests run in-process; a third convention would add code without a user. |
| #6 `scrub.run` closes the stdout fd twice | **Adapted**: `close_src=False` alone would break the EPIPE path (pump must close the read end so the writer gets SIGPIPE). `scrub.run` now creates its own pipes whose read ends only `pump` closes (once), like `ssh_conf.run_child`. |
| #7 remote sudo password exposure (SPEC decision) | (Superseded: PLAN-v4 phase 7 removed the passwordless setup below, its choice and its advice; a password is asked per call and used once.) **Adapted** (option b, made concrete; option a documented): the staged askpass stays (with the ssh group's hardening), and `gate check` offers, for a host with sudo whose `sudo -n true` fails, one choice pop-up: "Set up passwordless sudo for USER on HOST (recommended: no password stored or sent)" or "Store the sudo password". Passwordless uses the stored-or-typed password once through the staged mechanism for `sudo -k -A /bin/sh -c SCRIPT`, which writes `/etc/sudoers.d/claude-gateway-USER` (`USER ALL=(ALL) NOPASSWD: ALL`) to a dot-named temp file (never read by `#includedir` while half-written), checks it with `visudo -cf`, sets 0440 root, moves it into place, checks the whole configuration with `visudo -c` (a failure removes the file again, so sudo never breaks), then requires `sudo -n true` (after `sudo -k`) to work; nothing is stored (a stored password is forgotten). The same choice for localhost (the stand-in's trusted sudo, password on stdin like `verify_local`), with the wording that any program running as that user then gets root without a password. The answer is remembered per (host, user) in the vault (`sudo_choice`, not exported); a password stored without the choice (v2, the stand-in's own pop-up) gets the choice once; `gate forget NAME sudo` forgets the choice. SPEC 9.3, 15 updated, including step 5's stale detection (the askpass's rejection marker or the verification, never the command's stderr). Tests `test_sudo_nopasswd.py` (fake sudo, fake visudo, the local sshd harness); mutations in `mutations_sudo.py`. |
| #8 public ancestry process helpers | **Accepted**: `ancestry.exe_path`, `exe_name`, `parent_pid`; ssh.py and transfer.py use them. |
| For phase C: `ssh.resolve` for hooks, `ssh.run`, install_key password | No change needed. |

## Group sudo (`sudo.md`)

Items 1 and 2: see "Blocking and stale tests". The `_real_sudo()` safety
(None under any override without a fake) is kept.

## Group ux (`ux.md`)

| request | resolution |
|---|---|
| PostToolUse matcher: SPEC 12 plus Edit/Write/MultiEdit | **Accepted** (hooks.json), plus `mcp__terminal__read_terminal` (the user's Terminal panel output can carry a token; the scrub keeps the output's shape). |
| UserPromptSubmit `prompt.sh` without arguments | **Accepted** (`onFailure: "block"` too). |
| FileChanged on gateway.toml | **Accepted**, verified with a headless probe on Claude Code 2.1.301: a SessionStart `watchPaths` entry plus a matcher-less FileChanged group fires with `file_path` and `event`; `hooks_filechanged` ignores other files. |
| PreToolUse `mcp__plugin_gate_gw__.*` -> `mcp_perm.sh`; delete `perm.sh` | **Accepted**. |
| sh hooks honour `GATEWAY_TEST_ROOT` only with `--test` first | Kept; production hooks.json never passes `--test`. |
| `pending_requests()`: `popup.cleanup_stale()` first, states open/unavailable only | **Accepted**. |
| `gate pubkey` in USAGE | **Accepted**. |
| SessionStart shows pending requests through `hooks_post.pending_notice(..., include_open=True)` | **Accepted** (the one-time code at SessionStart; shown markers shared). Test `test_session_start_shows_the_code_and_writes_the_session_record`, mutation. |
| SessionStart writes `private/sessions/<sid>.env` | **Accepted** (`hooks_session.write_session_record`, prompt.sh's format, O_EXCL 0600, never overwritten; the session start is now the real start). |
| ssh: `ssh.run`, hostkey `on_ok`/`address`, `pinned_at` | Already done by the ssh group. |
| ssh: `_pin_host_keys` should drop `host_keys_previous` | **Accepted** (tidiness: the stand-in's pop-up only pins over existing pins, where the field is normally absent). |
| sudo: `_password()` with `store=`/`load=`, `secret_prompt`, `popup.reenter` | **Accepted** (a late answer after exit 75 is stored by the helper; a joined sudo re-reads; a rejected password opens the one re-entry pop-up). The prompt points to `gate check localhost` for passwordless sudo (superseded: PLAN-v4 phase 7 removed that pointer with the setup). Test `test_missing_password_pop_up_stores_it_and_stale_opens_one_reentry` (the sudo test driver can now pass a fake dialog), mutation. |
| accounts: `entra.scope_for_host` vs `web.azure_scope` | **Accepted**: `entra.scope_for_host` delegates to `web.azure_scope` (one rule set: a passed scope only for a listed site, validated, never a first-party audience; registries refused). |
| sign-in code in a forked helper: no CoreFoundation calls | Noted; nothing new calls them. |
| migrated ml-catalog accounts have `bound.scope = None` | Noted (the http tool asks for `gate login catalog`). |
| ancestry: macOS `PROC_PIDTBSDINFO` fails for root processes | **Accepted**: `_mac_ppid` uses `PROC_PIDT_SHORTBSDINFO` (flavor 13), falling back to BSDINFO. Test `test_public_helpers_and_root_processes` (root processes' parents match `ps`), mutation. |
| perms: `gate import --from-peer` allow-listed | Kept (transfer's sshd-ancestry guard). |
| `gate secret` off the allow list | Verified (`GATE_SUBCMDS` has no `secret`); decision-table rows added. |
| Rule 2 covers `private/pending/*.code`, `*.cancelled`, `private/sessions/` | Verified (all of `private/` is protected); table rows added. |
| form.py: reserve `settings` | **Accepted** (`form.RESERVED`); gate_setup and the PostToolUse report still name the clash clearly. |
| run.py: drop proxy and CA variables at `gate` entry | **Accepted** for every `gate` command except `gate with` (its child inherits the environment, SPEC 9.7). Test, mutation. |
| File guard: deny Claude Code session transcripts | **Accepted**: Read/Edit/Write/NotebookEdit of `<config>/projects/*/*.jsonl` (config dirs: the payload's `transcript_path`, `CLAUDE_CONFIG_DIR`, `~/.claude`, `~/.config/claude`) and a Grep from a folder that holds them are denied; the Bash hook denies words naming them and recursive readers of folders holding them (`claude`/`jsonl` are prefilter triggers; the payload's own `transcript_path` field is left out of the prefilter so ordinary commands still skip Python). `tool-results/` next to them and listing names stay allowed. Tests in `test_harness_run`, `test_hookbash_private`, `test_hookbash_prefilter`; mutations. |
| SPEC decision: copy-to trust | **Option (a)** kept (current behaviour with the pop-up wording that Claude can run commands on that host); recorded in SPEC 16. (b) contradicts SPEC 16 and only helps locally; (c) doesn't help against a gate planted earlier. |
| ssh: `close_masters` guard trip | See above. |

## Also done in phase C (found while integrating)

- `dialog.backend()` returns "no screen" under any test override that gave
  no fake dialog, so a test can never open a real dialog on the developer's
  screen (the sudo test driver used to run the stand-in that way). Test,
  mutation.
- The PreToolUse approval hook also covers `mcp__terminal__run_in_terminal`
  (the user's Terminal panel): denies and asks apply, but it never answers
  `allow` there (the user's own shell has no stand-ins: real sudo, their own
  ssh keys). Test, mutation.
- The pijul stand-in starts the first-use build in the background (SPEC
  9.5): `pixi run -e pijul install-pijul` with `CARGO_INSTALL_ROOT` in the
  data folder, one build at a time, exit 75 meanwhile. Test.
- `tests/run_tests.py` prints the slowest tests and anything left behind in
  `GW_TEST_TMP`; `tests/run_mutations.py` (`pixi run mutations`) runs every
  mutation file on scratch copies.

## Status at the end of phase C

- `pixi run --frozen test`: 702 passed, 0 failed, about 2 min 10 s (4
  modules at a time; about 7 min 20 s sequentially), nothing left in
  `GW_TEST_TMP`, no processes left.
- `pixi run --frozen mutations`: 320 mutations, all killed (mutation_check 42,
  accounts 41, ssh 65, sudo 73, ux 99), each file on its own scratch copy.
- `claude plugin validate` passes for the plugin and the marketplace.

## Status after review round 1 (2026-10-19)

The round's findings (rsync options, "ask" rights reached through rsync,
git or sftp, scp/rsync local destinations, gh hosts, az scopes, the session
context for Azure SDKs, `gate rotate`'s cleanup, wrapped curl, out-of-date
docs) are fixed; what changed and why is in [../DECISIONS.md](../DECISIONS.md)
("Review round 1") and [../modules/sudo.md](../modules/sudo.md).

- `pixi run --frozen test`: 727 passed, 0 failed, about 1 min 45 s (4
  modules at a time), nothing left in `GW_TEST_TMP`.
- `pixi run --frozen mutations`: 379 mutations, all killed (mutation_check
  42, accounts 47, e2e 17, ssh 70, sudo 104, ux 99), each file on its own
  scratch copy.
- `pixi run --frozen e2e`: 70 checks passed (six headless `claude -p`
  scenarios on a scratch copy).
- `claude plugin validate` passes for the plugin and the marketplace.
