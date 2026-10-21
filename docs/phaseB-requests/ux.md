# Requests from the `ux` group

## Phase C (hooks.json, .mcp.json, launch.sh)
- **PostToolUse**: `command: sh, args: ["${CLAUDE_PLUGIN_ROOT}/hooks/post.sh"]`,
  timeout ~15. The matcher must be SPEC 12's
  `Bash|BashOutput|Monitor|Read|Grep|mcp__plugin_gate_gw__.*` **plus
  `Edit|Write|MultiEdit`**: SPEC 12's form validation (`additionalContext`
  after Claude edits gateway.toml) only fires for those tools.
- **UserPromptSubmit**: `command: sh, args: ["${CLAUDE_PLUGIN_ROOT}/hooks/prompt.sh"]`
  (the v2 hooks.json passed PLUGIN_ROOT as an argument; the new script takes
  no argument except the test runner's `--test`). It fails closed on a
  paste-guard hit by itself; no `onFailure` needed, but `"onFailure": "block"`
  is harmless.
- **FileChanged** on gateway.toml: `launch.sh hook-filechanged` (SessionStart
  already returns `watchPaths`).
- **PreToolUse** `mcp__plugin_gate_gw__.*`: `command: sh, args:
  ["${CLAUDE_PLUGIN_ROOT}/hooks/mcp_perm.sh"]` (MODULES-v3 called it
  `mcp_decide.sh`; the task named it `mcp_perm.sh`). Delete the v2
  `hooks/perm.sh` (SPEC 19).
- The sh hooks honour `GATEWAY_TEST_ROOT` only with `--test` as the first
  argument (the same rule as run.py); production hooks.json must never pass it.

## Phase A tests invalidated by this group's modules (not edited; please update)
- `test_harness_run::test_mcp_placeholder_serves_no_tools`: the server now
  lists `http` and `download` (each with `_meta anthropic/alwaysLoad`), and
  tools/call runs on worker threads, so responses are matched by id, not by
  order (here id 4's error arrives before id 3's tool result). Suggested:
  `out = {o["id"]: o for o in ...}`; assert tool names == `["http",
  "download"]`, `out[3]["result"]["isError"]` (unknown tool `run_privileged`)
  and `out[4]["error"]["code"] == -32601`.
- `test_gate::test_phase_b_commands_say_not_available`: `gate check|login|
  forget|rotate|secret` (gate_setup) and `export|import|copy-to|pubkey`
  (transfer) are implemented now.

## Phase A: hooks_session.py / gate.py
- `hooks_session.pending_requests()`: call `popup.cleanup_stale()` first, so a
  request whose helper died isn't shown as "a pop-up is waiting" forever; and
  treat only `state in ("open", "unavailable")` as pending.
- `gate.py` USAGE: add `gate pubkey` (print this machine's age recipient, used
  by copy-to); dispatch already works.
- (after verification) SessionStart's systemMessage for pending requests:
  please call `hooks_post.pending_notice(session_id, include_open=True)`
  instead of `_pending_messages()`. A no-screen request now comes with a
  one-time code that `gate secret NAME` asks for (a program driving a
  pseudo-terminal could otherwise type "yes" to consent), and the code reaches
  the user only through these systemMessages. Today the user sees the command
  at SessionStart and the code at their first prompt; with the call they see
  both at once, and the "shown" markers (now in `private/sessions/`) are shared
  so nothing is shown twice.
- (after verification, optional) SessionStart may also write the session
  record `private/sessions/<sid>.env` (mode 0600, never overwritten; lines
  `started=EPOCH` and `DISPLAY= WAYLAND_DISPLAY= XAUTHORITY= XDG_RUNTIME_DIR=
  DBUS_SESSION_BUS_ADDRESS= SSH_CONNECTION= SSH_TTY=` from the hook's own
  environment, values restricted to `[A-Za-z0-9_.:/=,@%+ -]`). prompt.sh writes
  it at the first prompt; dialog.py reads the display variables from it and
  copy-to reads the session start from its mtime.

## Group ssh (ssh.py)
- **Needed for copy-to**: an in-process runner `ssh.run(name, command: str,
  input: bytes | None = None, timeout: float = 120) -> (rc, stdout, stderr)`
  (or a CompletedProcess) that runs one remote command on a form host with
  the gateway's key and config, without the stand-in's ancestry check (it is
  called by the gate process itself after the user's typed confirmation).
  `transfer.remote()` uses `ssh.run` when it exists; until then `gate copy-to`
  says "isn't available in this build yet".
- `popup.hostkey(...)`: pass `on_ok=` (pin the new keys) and `address=`. The
  pop-up runs in a detached helper; when the requester's 90 s wait runs out,
  `popup.StillOpen` (a `SystemExit`, code 75, message already printed) ends
  the stand-in, and a later OK only pins if `on_ok` does it. `except
  Exception` won't catch StillOpen (that is intended: exit 75).
- When ssh pins or replaces host keys, also set `hosts[N]["pinned_at"] =
  vault.now()`: copy-to only goes to hosts pinned before the current session.
- `install_key(name, "password")` may ask through `popup.secret` itself: in
  gate check it runs inside the pop-up helper (direct mode), which is fine.
- (Already reported by accounts) `ssh.close_masters` trips the harness guard
  when called outside an override (`test_consent::test_close_masters_called_for_narrowed_hosts`),
  which aborts the whole suite.

## Group sudo (sudo.py)
- `_password()` calls `popup.secret("localhost", "sudo password", prompt,
  verify=verify_local)` and stores the value itself afterwards. Please pass
  `store=` (vault.set_sudo under vault.edit) and `load=` (re-read the vault)
  instead: if the requester's 90 s wait runs out (exit 75) the helper stores
  the late answer, and a second sudo waiting on the same pop-up gets the value.
  Build the text with `popup.secret_prompt("sudo password", "localhost",
  target=f"{user}@localhost")`.
- On a rejected saved password, `popup.reenter("localhost", "sudo password",
  prompt, verify_local, store=...)` opens the one re-entry pop-up without
  waiting and returns the SPEC message to print.

## Group accounts (entra.py, logins.py, scrub.py)
- `entra.scope_for_host` returns a passed `scope` for any host. web.py keeps
  its own stricter mapping (`web.azure_scope`: `scope` only for listed
  `sites`, validated as `…/.default`, registries refused with "use crane");
  consider aligning so clis and web agree.
- gate_setup calls `logins.github_login(host, show)` without `expected` and
  verifies the login itself, so a wrong account re-asks up to 3 times in the
  same pop-up with a clear message.
- Code that runs inside a pop-up job (entra/logins/mlcat sign-in) runs in a
  forked helper: urllib there uses environment proxies only (macOS
  `_scproxy`/CoreFoundation aborts after fork). Avoid other
  CoreFoundation-backed calls in sign-in code.
- Note (phase A migrate): migrated ml-catalog accounts get `bound.scope =
  None`; the http tool then asks for `gate login catalog` (SPEC 14: the
  pinned scope, never re-read from the host). gate_setup's Entra sign-in for
  ml-catalog pins tenant/client/scope in `bound`.

## Group sudo (ancestry.py)
- On macOS `_mac_ppid` uses `proc_pidinfo(PROC_PIDTBSDINFO)`, which returns
  nothing for root's processes when the caller isn't root (checked: launchd,
  logd), so `_ppid` gives 0 for them. A walk up through `sudo` (setuid root,
  in WRAPPERS) therefore stops at sudo and the caller counts as not direct.
  `proc_pidinfo(pid, 13 = PROC_PIDT_SHORTBSDINFO)` answers for every process
  (ppid, uid, comm); `transfer._mac_short` shows the struct.

## Group perms (hooks_bash.py)
- SPEC 8 allow-lists `gate … import …`; that includes `gate import
  --from-peer -`. That is safe only because transfer refuses `--from-peer`
  unless the first non-shell ancestor is the system sshd's session child
  (root-owned sshd/sshd-session binary, by executable path) whose monitor
  runs as root; no change needed, just keep it in mind if that rule changes.
- `gate secret` must stay off the allow list (it is not in SPEC 8's list):
  it asks for a one-time code only the user is shown.
- Rule 2 (deny Bash segments naming `~/.config/gateway/private`) now also
  protects `private/pending/*.code` (the one-time terminal codes),
  `private/pending/*.cancelled` and `private/sessions/` (session records and
  shown markers).

## After the second verification (ux fixes)

### Phase A: form.py
- Add `"settings"` to `form.RESERVED`. A `[hosts.settings]` or
  `[accounts.settings]` parses today, but consent, pop-ups (`popup._name`,
  `consent_text`: "the gateway settings") and `gate check settings` treat the
  name as the `[settings]` pseudo-entry. Until then gate_setup refuses the
  name (`gate check`/`gate secret`, exit 2) and the PostToolUse form report
  warns.

### Phase A: run.py (defence in depth)
- At `run.py gate` entry, drop `HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY`
  (both cases) and `SSL_CERT_FILE SSL_CERT_DIR` from `os.environ` before
  dispatching. `gate check` verifies a token the user just typed (GitHub
  `/user`, Hugging Face whoami); `gate` runs with the environment of Claude's
  Bash. gate_setup now uses `entra.urlopen` (no proxies, the build's CA
  bundle) and the pop-up helper uses no proxies at all, so this is a second
  layer, not a fix.

### Phase A: hooks_files.py / hooks_bash.py (file guard)
- Claude Code records each hook run in the session transcript: `attachment`
  entries of type `hook_success` carry the hook's `stdout` (checked on this
  machine's transcripts, field names only). A systemMessage with a one-time
  terminal code (`hooks_post.pending_notice`) is hook stdout, so it very
  likely lands in `$CLAUDE_CONFIG_DIR/projects/<project>/<session>.jsonl`
  (default `~/.claude/projects/...`). Please deny Read/Grep/Glob (and SPEC 8
  rule 2 for Bash segments naming them) of `*.jsonl` directly under
  `<config>/projects/*/` (and `~/.claude/projects/*/`), the session
  transcripts. Leave `<config>/projects/*/<session>/tool-results/` readable:
  Claude reads persisted large tool outputs there. Without this, the code is
  only as safe as Claude's restraint from reading its own transcript.

### SPEC decision: copy-to trust (verifier's high finding)
- copy-to needs ssh on for the remote, and no gateway hooks run there, so
  Claude's commands reach the remote as the user. They can replace the
  remote `gate` (so it prints a recipient Claude holds and saves stdin), or
  read the remote's `private/key.txt` after a genuine import. Nothing the
  remote prints can prove otherwise; a recipient the user compares in their
  own terminal on the remote comes from the same (possibly planted) gate.
  Done in transfer.py: the copy-to pop-ups say plainly that Claude can run
  commands on that host, so whatever is copied is within reach of Claude's
  commands there, and they show the remote's recipient to compare with `gate
  pubkey` on that machine.
- `--from-peer` doesn't authenticate the sender (encryption to a public key
  proves nothing about who sent it). On a remote, anyone who can run it
  through the system sshd can already rewrite that machine's vault. Locally
  it needs a login through the system sshd (the documented residual risk).
  It only adds new entries (each approved with the lines the source showed)
  and fills missing secrets. It never widens an existing entry's
  destinations, replaces a pin or overrides an alias.
- Open for the SPEC owner, choose one:
  (a) keep SPEC 16 as is, with the pop-up wording above (current behaviour);
  (b) queue `--from-peer` imports as a pending request applied after the
  remote's own pop-up, or a one-time code typed in a terminal there. This
  contradicts SPEC 16's "applies without a pop-up of its own", and it only
  protects the local case, since a remote's codes are readable by Claude's
  shell on that remote;
  (c) restrict copy-to to hosts with `ssh = "ask"`, so every command Claude
  runs there needs the user's OK. This doesn't help against a gate planted
  earlier.

### Group ssh
- `_pin_host_keys`: also `rec.pop("host_keys_previous", None)`. `gate forget
  NAME host-keys` now remembers the old pins there, so the next `gate check`
  shows a changed key as a change. gate_setup consults the field only when
  nothing is pinned, so this is tidiness, not a fix.

### Group accounts
- `entra.scope_for_host`: like `web.azure_scope`, never mint a first-party
  audience for a listed site. That means ARM, Graph, AAD Graph, Storage
  (incl. `https://X.blob.core.windows.net/.default`) and Databricks, as a
  URL, an app id or an `api://` form; see `web.first_party_scope`.
- `mlcat.catalog_config` (v2) still uses plain `urllib.request.urlopen`.
  gate_setup now reads the catalog's sign-in settings through
  `asiml.catalog_config` (`entra.urlopen`).
