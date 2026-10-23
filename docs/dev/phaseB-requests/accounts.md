# Requests from the `accounts` group

## For the perms/ssh group (ancestry.py)
- `clis.py` and `with_main` call `ancestry.is_direct(tool, entry_scripts=False)
  -> (allowed, culprit)` (SPEC 10). The landed signature matches and works.
  `clis.py` keeps a small local ancestry walker as a fallback for when
  `ancestry.is_direct` raises `NotImplementedError`; in phase C that fallback
  can be deleted so ancestry.py is the single source of truth. No action needed
  now beyond keeping the signature stable.
- Confirm the CLI tools (`gh`, `hf`, `databricks`, `crane`, `pijul`, `az`,
  `with`) stay OUT of ancestry's `CRED_FAMILY` (they take a token, not an
  ssh/git credential, so only shells + the base wrappers are allowed
  intermediates). The landed ancestry.py does this correctly.

## For phase C (wiring)
- `run.py` already routes `shim gh|hf|databricks|crane|pijul|az -> clis.main`,
  `shim asiml -> asiml.main`, `shim dvc -> asiml.dvc_main`, and
  `git-credential -> githelper.credential_main`. No change requested.
- `envfile.write_git_config` already calls `githelper.include_config` and
  `githelper.identity_files`. No change requested.

## Phase A tests invalidated by phase B landing (NOT edited by me — report only)
These phase A tests assert "phase B is not available yet" and fail now that the
corresponding phase B modules have landed (across several groups). They should
be updated/removed when phase C wires everything:
- `test_gate::test_phase_b_commands_say_not_available` — `gate with` (clis),
  `gate check/login/...` (gate_setup) are now implemented.
- `test_harness_run::test_shim_without_phase_b_refuses_and_never_runs_the_system_tool`
  — ssh (ssh group) and the account stand-ins now run instead of returning 75.
- `test_harness_run::test_mcp_placeholder_serves_no_tools` — mcp_server/web now
  serve `http`/`download`.
- `test_harness_run::test_stand_in_triggers_migration` — `asiml` now runs.

## Blocking: ssh group break that ABORTS the whole test run
- `test_consent::test_close_masters_called_for_narrowed_hosts` (a phase A test)
  calls `consent.close_masters_for(...)` outside a `testing.override`. The ssh
  group's now-real `ssh.close_masters` -> `ssh_conf.control_dir` -> `paths.run_dir()`
  trips the harness guard (`GuardTripped`), which `run_tests.py` re-raises and
  **halts the entire suite**. This is in the ssh group's files + a phase A test,
  not ours. Fix options for that group / phase C: make `ssh.close_masters`
  tolerate the absence of a run dir, or update the phase A test to run inside an
  override. Until then the full suite cannot complete end to end.

## Follow-ups from verification (round 2)
- To the owner of `web.py` (FYI, not blocking): the accounts group's
  credentialed HTTP now goes through `entra.urlopen` (no redirects, proxy
  variables ignored via `ProxyHandler({})`, certificates checked against the
  Python build's own CA bundle, never `SSL_CERT_FILE`/`SSL_CERT_DIR`). `web.py`'s
  `_opener()` already refuses redirects but still uses `build_opener`'s default
  `ProxyHandler` and `ssl.create_default_context()`, which honour
  `HTTPS_PROXY`/`SSL_CERT_FILE` from the process environment. That matters only
  if `web.http` ever runs in a process started from Claude's Bash (the MCP
  server runs from Claude Code's own environment). Consider the same treatment
  (or reuse `entra.opener()`/`entra.tls_context()`), per SPEC 9's "dropping
  proxy/CA overrides".
- To phase C (design question, no code change made): the `az` stand-in prints
  `account get-access-token` output through `scrub_text`, so `accessToken` is
  always `***`, including for a non-direct `scripts = true` caller (e.g. an
  SDK's AzureCliCredential). SPEC 9.5 says az is opt-in "since tokens then
  reach scripts", which suggests a scripts caller should get the raw token.
  If that's intended, print raw only when `is_direct` returned
  `(True, culprit)` with a non-empty culprit (scripts-allowed, not Claude's
  shell) and keep scrubbing for direct callers; the PostToolUse scrubber is the
  backstop if the script echoes it.
