# Requests from group "ssh" (files we don't own)

> Historical record (phase B, 2026-10-19). Its sudo advice is superseded: PLAN-v4
> phase 7 removed the passwordless sudo setup and every recommendation of a
> NOPASSWD rule; the gateway never writes or recommends a sudoers rule
> (docs/dev/DECISIONS.md "No sudoers rule, ever", docs/dev/modules/sudo.md).

## 1. tests/test_consent.py (phase A) — blocks the full suite

`test_close_masters_called_for_narrowed_hosts` ends with

```python
    # the phase-B stub raising NotImplementedError is tolerated
    assert consent.close_masters_for(e.narrowed) == []
```

`ssh.close_masters` is real now. Called outside `testing.override`, it
resolves `paths.run_dir()`, the harness guard raises `GuardTripped` (a
SystemExit), and `pixi run test` aborts the whole run at this test.

Change the last two lines to:

```python
    # phase B's ssh.close_masters is real: in a test env it finds no master
    # and the host still counts as handled
    with H.gateway_env():
        assert consent.close_masters_for(e.narrowed) == ["box"]
```

(`H` is already imported there as `harness`.)

## 2. tests/test_harness_run.py (phase A)

`test_shim_without_phase_b_refuses_and_never_runs_the_system_tool` asserts
`run.run_shim("ssh", ["x"]) == 75` ("isn't available in this build yet").
The ssh stand-in is real now: `ssh x` (x is not in the form) is refused with
exit 2 and `gateway: x isn't in gateway.toml...`, and the user's own ssh
still never runs (the property the test is about). The same applies to the
other landed stand-ins (gh, sudo, hf, asiml: other groups). Proposed:

```python
        for tool in ("ssh", "gh", "sudo", "hf", "asiml"):
            assert run.run_shim(tool, ["x"]) != 0, tool
        ...
        assert not marker.exists(), "the user's own ssh/gh/sudo must never run in their place"
```

and drop the `"isn't available in this build yet"` assertion (or keep it
only for a stand-in that is still a stub).

## 3. src/gateway/accounts.py (phase A) — account selection's "only" rule (worked around in ssh.py; still needed for the git helper and the CLIs)

`select()` computes `pool` from the *effective* destinations, so an account
whose approval or binding is pending drops out of the pool. If it was one of
two accounts for the host, the remaining one becomes "the only account" and
gets the pending account's repos: with `github-work` (owners = ["acme"])
waiting for `gate check` and `github-me` approved, `git push` to
`git@github.com:acme/x` is sent with github-me's key (seen in
test_ssh_git while writing the unbound-credential test). The credential still
only goes to its own bound destinations, but it is the wrong account.

SPEC 9.6 step 3 says "if exactly one account of that kind+host *exists*".
Proposed: count the "only" rule over the form's accounts of that kind whose
form destinations cover the host (approved or not), and when the owner
matches an account that is not usable yet, return
`Selection(error="gateway: github-work matches acme but waits for the user's OK; run gate check github-work")`
instead of falling through to the default/only account.

Verification reproduced this through the ssh stand-in. Until accounts.py
changes, `ssh._pending_owner_account` refuses before calling select() when
the owner matches an account of that kind and host that isn't usable
(tested: test_ssh_git_pending_owner_account_not_given_to_another, and a
mutation). The git credential helper and the account CLIs still go through
select() alone.

## 4. tests/fakes/fake_sudo.py (phase A) — nice to have

Real sudo uses the askpass helper by itself when there is no tty and both
`SUDO_ASKPASS` and `DISPLAY` are set (SPEC 9.3 relies on this for nested
sudo). The fake only uses it with `-A`. harness_ssh.py emulates the rule with
a wrapper script (`if [ -n "$SUDO_ASKPASS" ] && [ -n "$DISPLAY" ] && ! (:
</dev/tty); then exec fake_sudo.py -A "$@"`). Adding that rule to
fake_sudo.py itself would let other groups test nested sudo the same way.

## 5. tests/entry.py (phase A) — nice to have

`entry.py` applies only `testing.override(ROOT)`, so stand-in subprocesses
can't get override keywords (`run=`, `tools=`, `keyscan=`, extras) or test
patches. harness_ssh.py has its own entry (`harness_ssh.py --entry ROOT`,
reading ROOT/ssh-entry.json). A shared convention (e.g. entry.py reading
ROOT/entry-override.json) would avoid one entry per group.

## 7. SPEC 9.3 (SPEC owner / phase C) — remote sudo: decision needed

Verification showed that SPEC 9.3 as written hands the staged sudo password
to anything in the remote command (SUDO_ASKPASS exported, the askpass
answering any caller, the password file readable by the login user), and
scrubbing can't hide transformed or short values. ssh_sudo now hardens it
within SPEC 9.3's structure (docs/dev/modules/ssh.md, "Remote sudo"): the
askpass answers only a root parent (real sudo), once per sudo process, at
most 6 times per call, never after a rejection; under scripts = false the
askpass is a shell function for `sudo` in command position only (nothing
exported) and the password is staged only then; passwords under 8
characters are refused; a saved password is verified (one attempt) before
use every 10 minutes; stale only on the askpass's rejection marker.

What remains, and needs a SPEC decision: while a call runs, a program
running as the login user on the remote can still find the staging dir and
read `$d/p`, or run real sudo with its own askpass that execs `$d/a` with
stdout redirected. With only POSIX sh on the remote there is no way to give
the password to sudo and not to the same user.

Independent verification confirmed this is reachable by Claude's own
command in the default scripts = false mode, e.g. `ssh box 'sudo true; cat
"$XDG_RUNTIME_DIR"/gw.*/p | rev'`: the scrubber masks only the literal
password and its base64 / URL-encoded / line-split forms, so a reversed,
hex or spaced-out copy reaches Claude. A host with sudo = true and a stored
password therefore discloses that password (reusable, possibly valid on
other hosts), which is more than "Claude may run root commands there". The
module docs now say this plainly and recommend NOPASSWD rules for hosts
Claude uses sudo on (superseded: PLAN-v4 phase 7 removed that advice; a
password asked per call and used once, or an `elevation` policy, instead).
Options: (a) accept and
document it (current state; SPEC 9.3 should say "scripts = false keeps the
askpass out of the environment; a deliberate same-user reader on the remote
can still get the password"); (b) recommend NOPASSWD rules for the hosts
Claude uses sudo on (setup could offer a scoped sudoers line; this is
the group's recommendation for now, possibly with gate check warning when a
sudo password is stored for a host whose sudo right is true); (c) a
root-owned helper installed on the remote at setup (e.g. a sudoers
`Defaults:USER askpass=` or a PAM module) — larger change. Also SPEC 9.3
step 5 ("`Sorry, try again` / `incorrect password` in stderr → mark stale")
should change to "the askpass saw sudo ask twice, or the verification
failed" (stderr text from the command could fake it).

## 8. src/gateway/ancestry.py (group sudo) — public process helpers

`ssh._started_by_git_lfs` (git-lfs-authenticate prints a token, so it is
allowed only when git-lfs started ssh) walks up through shells with
`ancestry._exe_name(pid)` and `ancestry._ppid(pid)`, which are private.
Please export them (e.g. `exe_name(pid)`, `parent_pid(pid)`, or
`first_non_shell_ancestor()`), so a rename can't break this (it fails
closed: any error refuses git-lfs-authenticate).

## For phase C (wiring), no change needed now

- hooks_bash / bashparse may use `ssh.resolve(argv)` to map ssh targets for
  the SPEC 8 decision table (no network; `kind`, `name`, `by`).
- consent.ratchet already calls `ssh.close_masters(name)`; it never raises.
- ux's copy-to request: `ssh.run(name, command, input=None, timeout=120) ->
  (rc, stdout, stderr)` exists now (in-process, audited, no ancestry check,
  host approved and ssh right not false); `transfer.remote()` picks it up.
- gate_setup calls `ssh.install_key(name, method)` without a password for
  the "password" method; install_key then asks with
  `popup.secret(name, "login password", ..., lazy=False)` (works in popup's
  direct mode inside the gate check helper).

## 6. src/gateway/scrub.py (group accounts) — small race

`scrub.run()` starts `pump(proc.stdout.fileno(), ...)` with the default
`close_src=True` and later calls `proc.stdout.close()`: the same fd number is
closed twice. If anything opens a file or pipe in between (another thread),
the second close hits that unrelated fd. Suggest passing `close_src=False`
from `run()` (the file objects close their fds once). ssh_conf.run_child
does that when it uses `pump`.
