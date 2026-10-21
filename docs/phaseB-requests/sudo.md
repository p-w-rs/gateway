# Phase-B requests from the `sudo` group

## 1. `test_consent::test_close_masters_called_for_narrowed_hosts` aborts the suite now that `ssh.close_masters` is implemented

**Owner:** the `ssh` group (owns `ssh.py`, `sshconf.py`) and/or whoever owns the
phase-A `tests/test_consent.py` assertion. **Not** the `sudo` group — none of
our files are involved.

**Symptom:** `pixi run --frozen test` aborts (hard `SystemExit`, "the test guard
tripped") at:

```
ABORT test_consent::test_close_masters_called_for_narrowed_hosts: the test guard tripped
TEST GUARD: paths.run_dir() was called without testing.override
```

**Cause:** that test ends with

```python
# the phase-B stub raising NotImplementedError is tolerated
assert consent.close_masters_for(e.narrowed) == []
```

run **after** the `run(...)` helper's `testing.override` context has exited. When
`ssh.close_masters` was the phase-A stub it raised `NotImplementedError`
immediately (before touching any path), which `consent.close_masters_for`
catches, so the result was `[]`. Now `ssh.close_masters` is implemented and calls
`sshconf.close_recorded(name)` / `ssh.probe_clear(name)` → `paths.run_dir()` at
once. With no active override, the harness guard raises `GuardTripped`
(a `SystemExit`, i.e. a `BaseException`), which is **not** caught by
`close_masters_for`'s `except Exception`, so it propagates and aborts the run.

**Reproduce:** `pixi run --frozen python tests/run_tests.py -k
test_close_masters_called_for_narrowed_hosts test_consent`.

**Suggested fix (pick one; all outside the `sudo` group's files):**
- In `tests/test_consent.py`, drop or wrap the final
  `consent.close_masters_for(e.narrowed) == []` assertion now that the stub is
  gone (the first half of the test — the monkeypatched `ssh.close_masters` —
  already covers the contract), e.g. run it inside the same `run()` override, or
  monkeypatch `ssh.close_masters` to raise `NotImplementedError` for that line.
- Or make `ssh.close_masters` defer `paths.run_dir()` until it actually needs a
  socket, so a no-op narrowing never resolves the run dir.

We left this untouched per the "own only your files / report, don't edit" rule.

## 2. Phase-A tests that assert phase-B stand-ins are "not available" now fail

**Owner:** the phase-A test authors (`tests/test_gate.py`,
`tests/test_harness_run.py`) and/or phase C. **Not** the `sudo` group.

Now that the phase-B stand-ins are implemented (ssh, clis/gh/hf/databricks,
asiml, mcp_server, gate_setup, transfer, web — and our sudo), the phase-A tests
that assumed the stubs raise `NotImplementedError` / serve no tools fail:

- `test_gate::test_phase_b_commands_say_not_available` — `gate check/login/with/
  export/...` now dispatch to implemented modules instead of printing
  "isn't available in this build yet".
- `test_harness_run::test_shim_without_phase_b_refuses_and_never_runs_the_system_tool`
  — `run_shim("ssh"/"gh"/"sudo"/"hf"/"asiml")` no longer returns 75. (It fails
  at `ssh`, the first tool in the loop, before reaching `sudo`.)
- `test_harness_run::test_mcp_placeholder_serves_no_tools` — `mcp_server` now
  serves `http`/`download`.
- `test_harness_run::test_stand_in_triggers_migration` — `run_shim("asiml")` is
  implemented, so its 75/"isn't available" expectation no longer holds.

- `test_transfer_roundtrip::test_no_screen_inside_claude_code_names_the_terminal_command`
  — the transfer / ux group's own test (no-screen `gate secret` path); unrelated
  to our modules (it only uses `sudo` as form/vault data).

These are expected parallel-development collisions: those tests need updating to
the implemented behaviour (phase C wiring). None are caused by the `sudo`
group's files, and none exercise a bug in our modules.

**Current full-suite status** (`pixi run --frozen test`): the run *aborts* at
`test_consent::test_close_masters_called_for_narrowed_hosts` (item 1 above)
before completing. Excluding `test_consent`, it is **607 passed, 4 failed**
(2026-10-18, after the second verification round), the 4 being the ones listed
here — all in files owned by phase A. Our own nine test modules are green (91
tests) and all 63 mutations in `tests/mutations_sudo.py` are killed.

**Safety note (fixed in our file):** `sudo._real_sudo()` now returns `None`
whenever a `testing.override` is active without an explicit fake sudo
(`tools={"sudo": …}`), so our `sudo.main` can never reach the real
`/usr/bin/sudo` from inside a test that forgot to provide one. Our own tests and
mutations are green; the full suite is green apart from the collisions above
(all in files we don't own).
