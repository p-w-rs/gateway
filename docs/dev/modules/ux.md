# ux group

Public API and behaviour of the modules the `ux` group owns: `popup.py`,
`dialog.py`, `gate_setup.py`, `transfer.py`, `web.py`, `mcp_server.py`,
`hooks_post.py`, `hooks_prompt.py`, `hooks_filechanged.py`, and the sh hooks
`hooks/post.sh`, `hooks/prompt.sh`, `hooks/mcp_perm.sh`. Contract:
[SPEC-v3.md](../SPEC-v3.md) §6, §12, §14, §15, §16 and [PLAN-v4](../PLAN-v4.md)
phase 3 (native dialogs), with [PLAN-0.11](../PLAN-0.11.md) §2.10, §8 and §9
where they differ. Stdlib only, on the lock's Python;
messages start with `gateway:` and say what to do next; every credential use
is audited (`audit.use`), every refusal too (`audit.refusal`), each with the
mode it was decided in.

## 0.11.0 changes in this group (PLAN-0.11)

Where the sections below say otherwise, this holds:

- **http and download** (§2.10, lead decision 19.1): `mcp_perm.sh` hands
  them to `launch.sh hook-mcp` (`hooks_mcp.py`): the `network` policy in the
  payload's mode gives deny or ask; allow only for the user's explicit
  per-mode allow in this computer's `network` policy, never for a call with
  an account; anything else no decision. `web._network_ok` reads the same
  policy in the session's recorded mode (or the modeless rule) and lets an
  "ask" through (the hook asked up front); an account's `use`, `credential`
  and `write` are read in that mode, and an "ask" there still refuses.
  `[network] commands` is never read here (network.md).
- **Masking every tool** (§9.1): hooks.json's PostToolUse and
  PostToolUseFailure matchers are `.*`; `post.sh` skips `TodoWrite`,
  `TaskCreate`, `TaskGet`, `TaskList`, `TaskUpdate`, `EnterPlanMode`,
  `ExitPlanMode` (`hooks_post.SKIP_TOOLS`, compared by a test) and checks
  the user's credential variables with builtins (one list of names,
  compared with Python's), starting Python only for a value of 8 or more
  characters, a token shape, or any response once a vault exists.
  `hooks_post.env_secrets` masks those values and every credential-named
  variable's in Claude Code's environment, besides the vault's.
- **AskUserQuestion** (§9.2): `hooks/tool_guard.sh` denies a question,
  header or option that asks for a secret (a request word before a secret
  word, a line that is only the word, "PIN" in capitals; a heuristic),
  with "gateway: ask for secrets only through the gateway's dialog (gate
  check NAME, gate login NAME)."
- **The passphrase offer** (§8): `popup.offer_passphrase()` after every
  secret store (`popup.secret`'s store, `gate_setup`'s token, key and
  sign-in stores, gated's own sign-in store); gated's `daemon/offer.py`
  shows it.
- **gate_setup**: `gate check NAME` and `gate check all` bring a pending
  removal to the consent dialog (`removed_entries`); a browser sign-in runs
  from the gate process through gated (`_browser_signin`); `status_line`
  and `_account_has_credential` use `accounts.entra_fits`.
- **transfer** (§9.3, lead decisions 11 and 12): `FORMATS = (3,)`;
  `SETTINGS_TABLES = ("shell", "policy", "network", "vault")`, and imported
  settings are approved in the import's own dialog (`plan_import` fills
  `changes["settings"]`; changes already waiting in this machine's own form
  are listed under their own heading and approved only with the file's);
  this machine's settings are their own item (`LOCALHOST_ITEM`, unticked:
  `[hosts.localhost]`'s sudo, scripts, policy and workspaces, never an
  address), a keep/replace choice on import, a replace that drops sudo shown
  as a widening; the confirm lists every grant, import and workspace a new
  host brings, one line each (`entry_details`, `fit_lines`), and comes in
  parts (`confirm_pages` through `popup.dialog_parts`, "Part i of n" in the
  heading and again in the question beside the buttons, at most
  `MAX_CONFIRM_PAGES` = 10: nothing is imported until the last part is
  accepted); a browser sign-in's
  refresh token isn't exported (the account needs a new sign-in on the
  other machine); the success message says to import inside a Claude Code
  session.
- **Sudo**: the local and the remote sudo dialog's Remember it starts
  unticked (`sudo.REMEMBER_DEFAULT`, `ssh_sudo.REMEMBER_DEFAULT`, with the
  same note: a password is used once unless the person ticks the box).

## popup.py (SPEC 6, PLAN-v4 phase 3): the only way to ask the user anything

Every question is a native dialog inside Claude Code: a pane the gate mod
draws from a request gated holds, with a private `Client` field for secrets
(`dialog.py` here, `daemon/dialogs.py` in gated, `hooks/mod/` in Claude
Code). No OS dialog, terminal prompt, web page or device code; no `gate
secret`, no one-time codes (DECISIONS "PLAN-v4 phase 3"). The system browser
opens only for a browser sign-in, from gated after the person presses Open in
its confirm dialog (daemon.md, "Browser sign-in").

Kinds (all take a validated entry name; free text is never shown):

| call | returns | notes |
|---|---|---|
| `consent(entry, changes, *, extra_lines=(), on_ok=None, lazy=False)` | Outcome | one line per change (`Change.what` or text); **Approve** / **Decline**, Decline focused first. A dialog shows at most `DIALOG_LINES` (40, as gated and the pane), counted as the rows its lines take in a `PANE_COLUMNS` (72) column pane, wrapped as the pane wraps them (`pane_rows`: wrap-ansi's hard wrap without trimming, as Claude Code's text does, a character of East Asian width W or F two columns (`cells`); a docked pane at a 170-column terminal is about 75 columns wide); a longer one comes in parts (`consent_pages`, through `dialog_parts`, which the import confirm uses too): "part i of n" in the heading and "Part i of n." again at the start of the question beside the buttons (the pane opens scrolled to its end), every change line whole on one part where it fits, **Next** / **Decline** on each but the last; nothing is approved before the last part's Approve, and a Decline on any part changes nothing. More than `CONSENT_PARTS` (10) parts: `failed` with no dialog, and `gate check` says "nothing was approved for NAME: its changes need more than 10 gateway dialogs, so none was opened; make fewer changes ..." |
| `secret(entry, what, prompt, verify=None, *, store=None, load=None, lazy=True, detail=None, wait=True, remember=None, check=None, target=None)` | (Outcome, value) | the private field; `verify(v) -> (ok, msg)` reopens the same dialog with "That didn't work: MSG" (try N of 3, a new key pair each time) and never stores a failing value; `store(v)` runs in the helper once the value is good and, where `remember` offers the choice (True or False: the box's first state; the sudo stand-in and remote sudo pass False, so it starts unticked), only if the box is ticked when the person submits; `check` names the form entry and rights gated rechecks before handing the value over (`{"section": "hosts", "entry", "right": "sudo" \| "ssh" \| ["ssh", "sudo"]}` or `{"section": "accounts", "entry", "kind"}`; every sudo, ssh and account dialog passes one); a joined request returns `load()` on ok |
| `choice(entry, question, options, *, on_answer=None, what="choice")` | (Outcome, option) | fixed option texts, one button per row (hotkeys 1-9) |
| `text(entry, prompt, *, default="", what=...)` | (Outcome, text) | a public text to copy (a public key: Copy button), or a typed host name (an `Input`: never a secret) |
| `checklist(entry, prompt, options, checked, *, what=...)` | (Outcome, [options]) | export/copy groups |
| `confirm(entry, lines, *, title, ok_label, what=...)` | Outcome | generated lines (import summary); default **Cancel** |
| `info(entry, text)` | Outcome | a fixed notice with OK |
| `hostkey(entry, old, new, *, address=None, known=None, on_ok=None, lazy=True)` | Outcome | old/new fingerprints (a fixed known_hosts note after a fingerprint is kept); **Trust new key** / Cancel, Cancel first |
| `reenter(entry, what, prompt, verify=None, *, store=None, detail=None, check=None)` | message | stale credential: opens one re-entry dialog without waiting, returns `gateway: the saved WHAT for ENTRY was rejected; a gateway dialog to enter it again is open in Claude Code; don't retry` |
| `run(entry, what, job, *, kind, lazy, digest, detail, notice, load, wait)` | (Outcome, value) | broker a multi-step job (gate check "setup", export, import, copy) |
| `signin_unavailable(why)` | text | the fixed "browser sign-in isn't available here" text (no display, or the reason gated gave), with what works instead (a session with a display; a service principal for azure) |
| `offer_passphrase()` | text | the vault passphrase offer's one entry point, called right after a secret was stored, outside the vault lock (in the detached helper, after its job ended, with its lease); gated decides whether to show it (daemon.md) |

Outcomes (`popup.Outcome`): `ok`, `cancelled` (Cancel or Decline),
`timeout` (nobody answered), `unavailable` (no native dialog here: claude -p,
the SDK, mods off, mobile, VS Code, Remote Control; the reason is printed),
`paused` (a pause gated was told about through the contract's `/v1/pause`, which checkpoint 0.6+ sends on every pause), **`failed`** (verification failed
three times, the request changed before the value could be used, or the
helper died; nothing stored). `message(outcome, entry, what, reason)` gives
the standard line for Claude; `unavailable_text` says why and where it can
be given ("in Claude Code, in a terminal or the desktop app ...").

Templates: `secret_prompt(what, entry, *, target, fingerprint, note)` (what
the secret is, for which user@address:port, the host-key fingerprint, that
Claude never sees it), `consent_text`, `hostkey_text`. Entry names must match
`NAME_RE` (or `settings`); `what` must be a lowercase template subject
(`[a-z][a-z0-9 ._-]{0,47}`); targets and fingerprints are shown only if they
match strict patterns; change lines pass `form.strip_unsafe`.

### The broker

- Key `<entry>--<what-slug>`; files in `private/pending/`: `<key>.lock`
  (flock: create or join), `<key>.json` (the open request: `entry, what,
  kind, state "open", since, id, pid, session, detail, digest`; read by
  hooks_session/gate status), `<key>.result` (`id, outcome, at`, never a
  value; kept 10 min for joiners). A job whose answer is the line it prints
  (`run(..., public=True)`: export, import, copy-to; never a secret) also
  keeps that line in `<key>.<digest>.line` (`id, outcome, line, at`; one per
  request, so another request's job finishing meanwhile doesn't replace it;
  removed when a requester takes it, else after 30 min).
- The requester takes a **dialog lease** from gated first
  (`dialog.take_lease()` -> `POST /agent/dialog/lease`: it runs below the
  Claude Code session, so gated knows whose mod draws the dialog). No lease
  -> `unavailable` at once, with gated's reason; nothing is asked another
  way and no request is persisted.
- Then it prints the notice (`gateway: waiting for the example sudo
  password in the gateway dialog in Claude Code`), double-forks a detached
  helper (own session, stdio on /dev/null, every other fd closed, no exec,
  so callbacks run in it; it inherits the lease token and proves itself with
  it on gated's lease plane), and waits at most **90 s**
  (`testing.override(popup_wait=…)`); then prints `gateway: the gateway
  dialog for example is still open in Claude Code; tell the user once and
  carry on with other work. Retry after they answer.` and raises `StillOpen`
  (a `SystemExit`, code **75**). The helper keeps the dialog open up to
  **30 min** (`popup_lifetime`), stores the answer through the job's
  callbacks and releases the lease.
- The helper finalizes (result file, request removed) under the same lock the
  requester holds while writing the request, then answers over a private pipe.
- A second requester for the same key joins when its digest matches: waits
  on the result (same id) and gets `load()` on ok (a public job: its line).
- **A finished job's line for the retry** (public jobs; acceptance 2026-10-21:
  the import of a damaged file reported nothing once the requester's wait ran
  out). The requester that gets `DONE` over the pipe takes the line (removes
  it); when its wait ran out first, the line stays, and the next `run()` for
  the same key and digest (the retry Claude was told to make:
  "Retry after they answer") gets that outcome and line once, with
  `gateway: the gateway dialog for ... finished after the last try stopped
  waiting; this is its result`, instead of a new dialog (ok, failed and
  cancelled only; a timeout or a pause asks anew). A joiner of the same
  request takes it too; a requester only waiting for another request's
  dialog to end leaves that request's line alone. The digests name the very
  request: import the file's path and sha256, export the destination,
  copy-to the host.
- A secret dialog's `verify` may raise `popup.StopDialog(reason)` when asking
  again can't help (a damaged import file, not a wrong passphrase): the
  dialog closes as failed at once, its toast naming the reason (`didn't work
  (the file was changed or damaged ...)`), no "try 2 of 3". A requester with other
  content waits for the open dialog to close and then opens its own. gated
  shows one dialog at a time per session; the others queue, named by
  identity ("Also waiting: token for gh-work").
- `cancelled`: a global marker per request key (`private/pending/<key>.cancelled`,
  the digests the user cancelled), not tied to the caller's session id.
  Lazy requests (stand-ins) and `gate check` don't reopen the same dialog
  until the user writes a new prompt (prompt.sh deletes the markers).
- Stale handling: `cleanup_stale()` drops open requests whose helper is dead
  or older than its lifetime, results older than 10 min, orphaned locks and
  the old `.code` / unavailable records. `pending(entry=None)`,
  `clear(entry, what=None)`, `was_cancelled/mark_cancelled/clear_cancelled`.
- Modes: `broker` (default) and `direct` (inside the helper: dialogs in
  place). There is no terminal mode.
- Callers: don't hold `vault.locked()` while asking; avoid asking from a
  multi-threaded process (fork). In the helper, urllib uses **no proxies**
  (`_no_proxies`: macOS `_scproxy` aborts after fork, and HTTPS_PROXY comes
  from Claude's Bash). Token checks use `entra.urlopen` anyway.

## dialog.py (the native dialog, through gated)

- `show(kind, message, *, title, default, options, checked, ok_label,
  cancel_label, default_cancel, timeout, ...) -> Result(outcome, value,
  remember)`; kinds `confirm secret text choice checklist info` (gated adds
  `passphrase` and `unlock` for the vault's own dialogs). `Dialog(spec)`
  keeps one request across retries: `ask()`, `retry(why, attempt, of)`
  (gated reopens it with a new key pair and "That didn't work"), `close()`.
- `backend() -> ("native" | "fake" | None, reason)`: under any
  `testing.override` without a `dialog` fake (or "none") and without the
  `native_dialogs` / e2e knob, None: a test never reaches a real dialog.
- Native: `POST /lease/dialog/open` (the spec; gated makes the request and
  its X25519 key pair), `POST /lease/dialog/wait` long polls (20 s steps)
  until the person answered: gated opened the sealed box, rechecked the
  request and hands the value over once (a secret), or the choice, or the
  outcome; `/lease/dialog/retry`, `/lease/dialog/close`, `/lease/release`.
  A gated that died is restarted by the next call (`client.lease_call(...,
  restart_for=...)`): it restores its requests with new keys and the mod
  shows them again.
- The fake (`testing.override(dialog=SCRIPT)`, `tests/harness.FakeDialog`,
  `harness_ux.UXDialog`): a script answering each spec; a retry is shown to
  it as "That didn't work: WHY\nTry again (N of 3).", and an answer prefixed
  `\x00forget\x00` unticks "remember".
- `_session_record()`: the session record (`private/sessions/<sid>.env`,
  written from Claude Code's own environment) gives ssh.py the user's
  `SSH_AUTH_SOCK` for "use my own SSH login once".

What gated and the mod add (docs/dev/modules/daemon.md "Dialogs"; hooks/mod/):
the pane (title, fixed lines, the field or buttons, the queue line), the
`Client` field (bullets only; Enter seals the value with TweetNaCl's box to
the attempt's public key and posts `{id, attempt, epk, nonce, box}`, batched
with sequence numbers until acknowledged), Paste from clipboard (gated reads
the clipboard itself), "Remember it" where storing is optional (with the
field, and with Paste on the main screen), the guard (composer typing held
back while a secret dialog waits, wherever it is: drawn with its field
("click the gateway dialog's field first"), on the main screen (it points to
Paste and `CLAUDE_CODE_NO_FLICKER=1`) or closed (`/gate-dialog`); only the
gateway's own commands pass; the box goes back to what the guard let it hold,
never to the draft an edit came with, which can hold keys the editor painted
before an earlier refusal arrived (`dialog.ts guardEdit`; seen on 2.1.304:
characters from the middle of a typed value stayed); the hook's `.catch`
answers the same way if the engine skips the hook; the box is read once the
typing stops and refilled with the guarded text if anything else got in; a
prompt submitted meanwhile goes only as the guard let the box hold it
(`prompt.submit` drops anything else, so stray characters never reach the
model); the guard's status line lasts 4 s after the last held-back key), a
click on the field or the pane's ring
moving onto a button starts the field over, hotkeys (y, n, digits) only on
dialogs without a field, `/gate-dialog` to bring a waiting dialog back. On
the terminal's main screen (no clicks) the field isn't drawn: the dialog
says to start Claude Code with `CLAUDE_CODE_NO_FLICKER=1`, or to use Paste
(`dialog.ts MAIN_SCREEN`, one key route: `/gate-dialog`, then Tab and
Enter). Paste leaves the value on the clipboard: a toast says so whenever
gated read it, also when the value then failed its recheck (not when the
clipboard couldn't be read); `/gate-doctor`'s "Secrets here:" line says
before any dialog which routes work (`lib.ts secretLine`). On Linux without
`DISPLAY` or `WAYLAND_DISPLAY` in Claude Code's environment (the mod learns
the platform from `gated start|status`) Paste can't work: on the main
screen the dialog (`NO_DISPLAY_MAIN`), the guard (`GUARD_NODISPLAY_TEXT`)
and the doctor say neither typing nor Paste works and what to do (start
Claude Code with `CLAUDE_CODE_NO_FLICKER=1`, or set the credential from a
Claude Code session in the machine's desktop); in the fullscreen view the
dialog adds that Paste can't work (`NO_DISPLAY_PASTE`); the Paste button
stays (a test override's clipboard program works anywhere); and
SessionStart's context says it once (`hooks_session.NO_DISPLAY_NOTE`, a
how-to line, so it survives truncation; review round 2).

## gate_setup.py (SPEC 15, 6)

- `check(name|"all") -> int`, `check_one(name, *, force_signin=False)`,
  `login(name)`, `forget(name, what|None)` (`sudo`, `token`, `key`,
  `signin`, `host-keys`, or everything; account bindings stay; it keeps no
  copy of the vault: forgetting means gone. When older copies in
  `private/backups` may still hold the entry, `gate rotate`'s, an import's
  backup, a start-over's folder or the 0.6 conversion's
  (`vault.older_copies`), its output names them and says that `gate forget
  --backups` deletes them), `forget_backups()` (`gate forget --backups`,
  PLAN-0.11 §19.14: the older copies, at most `BACKUPS_PER_DIALOG` (30) at
  a time, listed by name in one confirm dialog run through `popup.run`
  (Cancel the default); on Delete, `vault.delete_older_copies` removes
  those still older copies then and nothing else; Cancel, a timeout or no
  dialog deletes nothing), `rotate(host)` (→ `ssh.rotate(host, before_change=)`:
  just before the rotation first changes the vault, under its lock, a copy
  of vault.age goes to `private/backups/rotate-<time>-<hex>.vault.age`
  (`vault.snapshot`, 0600, the newest 5 kept), and the output names it; a
  rotation that fails before that keeps none and prints the ssh module's
  own message; there is no restore command: SPEC 15 says how to copy it
  back by hand). (`gate secret`, removed in 0.9.0, lost its stub in 0.11.0:
  gate reports it as an unknown command.)
- `plan_for(...)` (requester side, no dialog): pending changes; for hosts a
  keyscan (`ssh.keyscan_host`) when nothing is pinned or an address/via
  changed; whether a key, a sudo password or an account credential is
  needed. Nothing needed → prints the status line, exit 0 (idempotent). An
  account whose credential can't be set up here (ml-catalog without a
  refresh token, azure without its own service principal) gets
  `popup.signin_unavailable(...)` before any dialog, so nothing is approved
  that couldn't be used.
- The job (one broker request `setup`, so it runs in the helper and survives
  exit 75): consent dialog listing exactly the changes + host-key
  fingerprints (in parts when longer than one dialog; more than 10 parts:
  refused with no dialog; a pure host-key change uses `popup.hostkey`, with the
  `~/.ssh/known_hosts` hint); `consent.approve(NAME, changes_shown)` (a
  `ConsentChanged` re-asks with the new changes, up to 3 times); pins the
  scanned keys (`hosts[N].host_keys`, `pinned_at`, a `hostkey` event); key:
  generates one if missing, `ssh.test_login`, else the choice *use my own SSH
  login once / type the account's password once / show me the public key* →
  `ssh.install_key(name, method)`, verified with `ssh.test_login`, marks
  `installed`; sudo after the passwordless probe (`sudo -n true`: sudo the
  system already allows without a password is used as it is; since PLAN-v4
  phase 7 the gateway never installs a sudoers rule): a stored password is
  kept; otherwise the choice "Store the sudo password" (`SUDO_STORE`) /
  "Ask me each time a command needs it" (`SUDO_ASK`: nothing stored, the
  command's own dialog asks with its Remember it box); store verifies with
  `sudo.verify_local` / `ssh.verify_remote_sudo` (3 tries). The answer is
  kept in `vault.sudo_choice` (`password`, `ask`).
  Accounts (`_signin_step`): GitHub, a personal access token checked with
  `GET /user` (the login filled in; SSO notes for owners); Hugging Face
  (whoami check); api-key and registry (the dialog, no check); azure, a
  service principal: the account's own `tenant` and `client_id` (not the
  Azure CLI's) in the form, its client secret checked with a
  client-credentials token (`sp_token`) and stored as
  `entra.client_secret`; ml-catalog: unavailable (an existing refresh token
  keeps working); pijul (key + show public key). One status line at the end.
- Where no dialog can open (`unavailable`): `gate check` prints why and
  where it can be given, and asks nothing; export/import/copy-to likewise
  (there is no terminal path).
- Adapters tests replace: `catalog_config`, `http_json`, `api_base`, `sp_token`
  (`testing.override(github_api=…, hf_api=…, entra_authority=…)`).
  `http_json` and `catalog_config` go through `entra.urlopen`: no proxies,
  the Python build's own CA bundle, no automatic redirects.
- An entry named `settings` collides with the settings pseudo-entry: `gate
  check settings` and `gate check all` refuse it with a "rename
  [hosts.settings]" message (exit 2), and the PostToolUse form report warns.
- `forget NAME host-keys` (and `forget NAME`) remember the old pins in
  `hosts[N].host_keys_previous` (public keys, at most 20). The next `gate
  check` compares a scan with them: a different key is a host-key change
  (the hostkey dialog, or the "differs from the key pinned before" line in
  the consent dialog), not a plain first pin.

## The /gate-hosts and /gate-accounts panes (PLAN-v4 phase 7)

`hooks/mod/manage.ts` (pure: `parseManage`, `hostLine`, `workspaceLine`,
`accountLine`, `editArgv`, `lastLine`) and `register.tsx` (`loadManage`,
`refreshManage`, `gateRun`, ...): immediate commands (no model turn) that
open a pane from gated's `GET /ui/manage`. Hosts: where each is, reachable,
auth, runtime, the actions that aren't simply allowed, granted forwarding,
pending changes (Review runs `gate check NAME`), its workspaces; an edit
field takes one fixed `gate host|workspace|policy` shape (non-secret words
only, an argv, never a shell string) and runs it, then `gate check ENTRY`
for the consent dialog. Accounts: each state in words ("needs you to sign in
again", "stored, not checked yet", ...), Check (`gate accounts --check NAME
--json`) and Enter credential (`gate login NAME`, the credential dialog), and
the note that a browser login is never an API credential. The panes never
take a credential and never approve anything (docs/dev/modules/policy.md).
Tests: `hooks/mod/manage.test.ts`; `register.test.ts` (seven commands).

`gate host add|set`, `gate workspace add|remove`, `gate policy set`, `gate
accounts` (`manage.py`) write through the form writer only and print the
`gate check` step a widening needs. `localhost` names this machine in `host
set` and `workspace add|remove` (its `[hosts.localhost]` table is appended
when the form has none); it stays reserved as the name of a new host (`host
add`), and the other reserved words are refused everywhere (acceptance
2026-10-21: the pane's `workspace add localhost proj ROOT` was refused).

## transfer.py (SPEC 16)

- `export_cmd(path|None)`: path rules (`check_export_path`: `.age`, never an
  existing file, not in a git work tree, a cloud-synced folder or the gateway
  home; default `~/Downloads/gateway-YYYYMMDD.age`); pop-ups (since PLAN-v4
  phase 7 a per-item checklist, `export_items`: each host, its secrets (keys,
  sudo passwords), each account, its credentials, the settings tables
  ([shell], [policy], [network], [vault]), this machine's settings
  ([hosts.localhost]: sudo, scripts, policy, workspaces) and its sudo
  password, the last two unticked by default; passphrase typed twice in the
  private field, ≥ 12 chars; no generated one, since showing it would put
  it on the dialog's command line, round 2); `export_content(form, data, picked)` = format 3
  (`gateway_export: 3`, `schema: 3`, form text generated from the ticked
  validated entries, written per table so policy, workspace and shell
  sub-tables travel with their entry; vault = the picked records, secrets only
  where their item was ticked, no checked account status, probe or host-key
  history; `from` = machine id, name, hostname, user, `/etc/ssh` host keys;
  `items`; `digest` = sha256 over the rest). Never a pid, socket, terminal or
  job id, or task reference (`test_portability::test_nothing_of_a_live_process_or_a_task_is_in_the_file`).
  age `-p` (scrypt) under a pty; written 0600 via link (never replaces);
  `export` event.
- `import_cmd(path, from_peer=False)`: age kind detection (passphrase vs
  this machine's recipient); the passphrase dialog verifies by decrypting: a
  wrong passphrase (`WrongPassphrase`) asks again (3 tries), a damaged or
  altered file (`agepass.Tampered`: age's MAC, header or chunk errors, a
  truncated file; or a format 3 digest that doesn't match) stops at once with
  "the file was changed or damaged"; `parse_incoming` (format 3 strictly;
  formats 1 and 2 are refused as "from an older gateway" since 0.11.0; a newer
  format or schema is refused as "made by a newer gateway": unknown fields refused, vault
  entries must be in the file's form, keys must be OpenSSH keys matching
  their public half, bindings valid hosts, ...); `find_this_machine`
  (`/etc/ssh/ssh_host_*_key.pub` vs pinned keys, then machine id, then a
  choice pop-up); `plan_import` (adds with their consent lines, fills in
  missing secrets, keeps yours, skips unreachable vias, host-key differences;
  this machine's host → localhost (its sudo password for the local user moves
  to localhost; hosts reached through it become direct); the source's
  localhost → a host named after it, `address = user@hostname`, `ssh =
  false`, pinned with the source's host keys); since phase 7 `find_this_machine`
  also matches the machine token a host record carries, and a host that is
  this machine by identity is never kept as a remote host (nor an exported
  localhost taken for this machine); conflicts (`Conflict`: an entry that
  exists here and differs) get one choice dialog each (at most
  `MAX_CONFLICT_DIALOGS`, the rest keep this machine's): keep this machine's,
  replace with the file's, add the file's under a new name; a different host
  key: keep this machine's pin or take the file's; confirm pop-up (default
  Cancel); `apply_import` (staged): the new form text (`stage_form_text`:
  appended tables, a replaced entry's tables taken out exactly) and the merged
  vault are built and checked in memory (`_check_staged`), the form and the
  encrypted vault are backed up to `~/.config/gateway/private/backups/import-<time>/`
  (0700), the vault is saved, then the form written atomically; a failure
  restores both (`_restore`) and says nothing changed; then
  `consent.approve(NAME, the lines shown)`, `verify_imported` (each imported
  account checked through its adapter), `needs_signin` (an account that signs
  in through the browser is named as needing a new sign-in, `gate login NAME`
  in a session: a browser sign-in's refresh token is never exported, and a
  file holding one is refused), the vault passphrase offer
  (`popup.offer_passphrase`, once the import's job has ended; not for
  `--from-peer`), `import` event.
- `--from-peer -`: only when `started_by_sshd()` (test override
  `peer_parent_ok`): walking up through shells (by executable path), the first
  other process must be the system sshd's session child, a root-owned
  `sshd`/`sshd-session` binary (`_root_owned_binary`: file and every folder
  above it owned by root, writable by nobody else; by kernel path:
  `proc_pidpath`, `/proc/PID/exe`; its comm when the exe can't be read), whose
  parent, the session monitor, runs as root and is the system sshd too
  (`_proc_info`: ppid/uid/comm from `proc_pidinfo(PROC_PIDT_SHORTBSDINFO)` on
  macOS, `/proc` on Linux). An sshd a user runs (the system binary included:
  its monitor runs as the user), a renamed shell or a symlink named sshd don't
  pass. Only an age stream for this machine's own key; applies without a
  pop-up; `import` event ("copy from X") for the next session. Residual risk:
  a process that can log in through the real sshd (e.g. after adding its own
  key to authorized_keys) passes.
- Imported host keys get `pinned_at` = the import time (never the file's).
- `copy_to(host)`: form host with ssh on, host keys pinned, pinned before this
  session (`pinned_too_recently`: `pinned_at`, else refused as unknown; compared with the session record in
  `private/sessions/<sid>.env`; with no session id or no record, pinned at
  least `MIN_PIN_AGE` (12 h) ago); remote gate present;
  remote recipient from `gate pubkey`; pop-ups: groups (with
  `copy_warning(name)`: "Claude can run commands on NAME (ssh is on for it in
  gateway.toml), so whatever you copy there is within reach of Claude's
  commands on NAME") + typed host name (with `copy_confirm_prompt`: the
  remote's recipient, to compare with `gate pubkey` in a terminal on that
  machine); encrypted to the remote recipient and streamed to `gate import
  --from-peer -` through `transfer.remote(name, command, input)` (group ssh's
  in-process runner `ssh.run`; see requests).
- Trust model of copy-to (second verification, high finding; SPEC decision
  requested). copy-to needs ssh on for the host, and no gateway hooks run
  there, so Claude's commands reach that machine as the user: they can replace
  its `gate` (a recipient Claude holds), or read its `private/key.txt` after a
  genuine import. Nothing the remote prints can prove otherwise, and the
  recipient check in the pop-up only helps against a wrong machine, not
  against a planted gate. So the pop-ups say so plainly and the user decides
  what to copy. `--from-peer` is not authenticated either (encryption to a
  public key proves nothing about the sender); on a remote, anyone who can
  run it through sshd can already rewrite that machine's vault, and locally
  it needs a login through the system sshd (residual risk above). It adds
  only new entries (each approved with the lines the source showed) and fills
  missing secrets; it never widens an existing entry's destinations, replaces
  a pin or overrides an alias. Queuing `--from-peer` imports for a pop-up or
  code on the remote would contradict SPEC 16 ("applies without a pop-up of
  its own"), so it is left to the SPEC owner.
- `pubkey()`: prints this machine's age recipient.

## web.py (SPEC 14)

- The opener ignores proxy variables (`ProxyHandler({})`) and checks
  certificates with `entra.tls_context()` (the Python build's CA bundle,
  never SSL_CERT_FILE/SSL_CERT_DIR), like every credentialed client.
- `http(args) -> dict`: `{url, method, headers, body|json, account, auth,
  scope, save_to, timeout ≤ 300, max_bytes}`; http/https only, no userinfo, no
  caller-set Host, Content-Length or Transfer-Encoding;
  a credential only over https (`credential_scheme_ok`: plain http only to a
  loopback address, 127.0.0.0/8, ::1, localhost; checked before anything else
  about the account, for http and download);
  credential only for the account's effective destinations (approved ∩ bound,
  `consent.bound_ok` checked again); a pending widening → `run gate check
  NAME`; placements: api-key `bearer | basic (login) | header:NAME[:PREFIX] |
  query:PARAM` (approved placement, or `auth` override), github/huggingface
  bearer, registry basic/bearer, azure Entra token by host
  (`azure_scope`: management→ARM, graph→Graph, workspace→Databricks,
  storage→Storage, listed site→`scope` required and validated, and never a
  first-party audience the gateway maps by host (`first_party_scope`: ARM,
  Graph, AAD Graph, Storage incl. `*.core.windows.net`, Databricks, by URL,
  app id or api:// form, sovereign clouds too), registry→use crane),
  ml-catalog the pinned `bound.scope` (`entra_token` → `entra.access_token`).
- Time limit: `Watchdog(timeout)` covers the whole call (connect, headers,
  body, every redirect hop). Each connection registers its socket once it is
  up; when the deadline passes the sockets are shut down, so a blocked read
  returns. Bodies are read with `read1` (one receive) and the deadline is
  checked between reads. Residual: a TLS handshake that trickles is bounded
  only per receive by the socket timeout (the socket registers after the
  handshake).
  Redirects by hand (≤ 5, http/https): cross-host or https→http drops the
  credential (headers, Cookie, Proxy-Authorization, the query key) for the
  rest of the call; a redirect URL carrying the secret is refused; 303 (and
  301/302 after POST) → GET. Response: status, headers, body (UTF-8 text, or
  `body_base64`), `truncated`, `url`, `redirects`, `credential` note, all
  scrubbed (`scrub.scrub_text` + the call's `secret_forms`; a binary body
  through `scrub_binary`: every vault value, the literals and the token shapes
  masked in the bytes before base64); a cross-host or downgrading 307/308 with
  a request body is not followed (the redirect comes back with `redirect`
  saying so); `save_to` writes a new 0644 file (download rules).
- `download(args, cwd=None) -> dict`: `{url, account, save_to}`;
  `check_destination`: only under the working directory (unless it is `/` or
  a folder above the home), `~/Downloads` or the temp folders (test override
  `download_temp_roots`); never overwrite, no dotfile, no hidden path
  component, no file Python runs at startup (`*.pth`, `sitecustomize.py`,
  `usercustomize.py`, any `site-packages`/`dist-packages` component), nothing
  in `~/Library`, not under ~/.config, ~/.ssh, ~/.claude, CLAUDE_CONFIG_DIR,
  the gateway home, the plugin or its data folder, `paths.is_protected`;
  O_EXCL|O_NOFOLLOW, mode 0644; size limit; an echoed credential is masked in
  the stream; returns path, size, sha256.
- `plain_local_path(raw, cwd) -> bool` (round 1, used by the Bash approval
  hook for scp / sftp / rsync local operands): the same rules minus the
  new-file ones (an existing file is fine: copies overwrite by design), and
  the home folder itself is never a project root (`_allowed_roots(base,
  home_ok=False)`: `~/bin`, `~/Documents` …); the path as written and as
  resolved must both pass (a symlink in the project into `~/.ssh` doesn't).
- No check-then-write race (`Dest`): right after the checks the folder is
  opened by walking its resolved path one component at a time with
  `O_DIRECTORY|O_NOFOLLOW` (`open_dir_nofollow`; `O_PATH`/`O_SEARCH` for a
  folder that can be traversed but not listed), before the request is sent.
  The file is created inside that open folder (`openat`,
  O_EXCL|O_NOFOLLOW, 0644), then the open folder must still be the one at the
  checked path (device and inode), else the file is removed and the call
  refused ("the destination folder changed while the download ran"). A folder
  swapped for a symlink during a slow request can't send the file into
  ~/.ssh or ~/Library/LaunchAgents. (Moving a whole folder into such a place
  is itself a write there, which this doesn't try to stop.) `http`'s
  `save_to` uses the same path.

## mcp_server.py (SPEC 14)

`Server(stdin, stdout, tool=call_tool, workers=8).serve()`: initialize
(negotiates 2025-06-18 / 2025-03-26 / 2024-11-05, `instructions`), ping,
tools/list (`http`, `download`, `host_inspect` (PLAN-v4 phase 4:
`managed.inspect`, the read-only host inspection; docs/dev/modules/managed.md),
each `_meta: {"anthropic/alwaysLoad": true}`),
tools/call on a thread pool with one locked writer, notifications ignored,
unknown methods -32601, a line that isn't JSON -32700 (id null), a JSON value
that isn't a request -32600, batches accepted, errors without exception text.
`handle(msg)` answers one message synchronously.

## Hooks

- `hooks/post.sh [--test]` (PostToolUse and, since round 3,
  PostToolUseFailure prefilter): once a vault exists,
  every response (vault values such as sudo passwords, prefix-less API keys,
  Entra refresh tokens and base64 forms have no shape a word list could
  match; review round 2: they reached Claude unmasked in Read, Grep and Bash
  output) but an Edit's, Write's or MultiEdit's (review round 5: Claude Code
  shows Claude no file content for them; an edit tool counts only when
  `"tool_name"` appears once in the payload), which go by the rules for no
  vault; without a
  vault, token shapes in the payload, Edit/Write/MultiEdit of gateway.toml,
  or an open dialog request newer than this session's marker
  (`private/sessions/<sid>.shown.json`) → `launch.sh hook-post`. The decrypted
  values are not cached on disk between calls (that would put them outside
  `private/`). The cost per call is the interpreter and its imports (age
  takes about 8 ms): `hooks_post` imports `form` only for form edits and
  failures and `popup` only when `nothing_pending()` is false (a `.json`
  in `private/pending`), and `vault`, `paths` and `testing` load
  their heavier modules lazily, so a call with a vault takes about 45 ms
  (110 ms before round 5). `hooks_post.main`:
  `updatedToolOutput` (same JSON shape, every string through `scrub_text`),
  form validation `additionalContext` (`gateway: form OK; box: … needs the
  user's OK - run gate check box while they're here`, or the problems),
  `consent.ratchet`, and a `systemMessage` naming a gateway dialog that is
  waiting in Claude Code ("/gate-dialog shows it"; once per request per
  session; `pending_notice(..., include_open=True)`; the markers live in
  `private/sessions/`, so Claude's commands can't fake them to hide a
  notice). There are no one-time codes any more (PLAN-v4 phase 3). For a PostToolUseFailure
  payload (round 3: `hook_event_name`, or `error` without `tool_response`)
  `_failure_main` (known limit: Claude Code shows a failed command's output
  as it is, and the gateway no longer turns failures into exit 0; DECISIONS,
  "Rolled back"): `failure_notice` (a stored value in any scrubber form,
  found with `vault.labeled_values` and `scrub.expand`, or a token shape) →
  `additionalContext` (never repeat, store or use it), a `systemMessage`
  naming the entry and how to replace it (never the value), an audit `leak`
  event.
- SessionStart (hooks_session) writes the same session record first
  (`write_session_record`), so its mtime is the real session start.
- `hooks/prompt.sh [--test]` (UserPromptSubmit): deletes the cancelled
  markers; at a session's first prompt writes its record (if SessionStart
  didn't)
  `private/sessions/<sid>.env` (`started=`, Claude Code's display variables;
  0600, never overwritten; records older than 30 days removed); paste guard
  regex (same alternatives as `hooks_prompt.TOKEN_PATTERNS`, kept in sync by a
  test; a token counts after any non-word character or after the JSON escapes
  `\n \r \t \b \f \uXXXX`, so a token pasted on its own line is caught)
  → Python, and if Python gives no answer the prompt is **blocked** (fail
  closed); form newer than the session's context record (or no record: a
  SessionStart that Claude Code cancelled leaves none), or a new open
  dialog request → Python; a `<task-notification>` once a vault exists →
  Python, blocked if Python can't answer (round 4). The home comes from the
  password database (`hooks/home.sh`, as launch.sh and post.sh; never
  `$HOME`; the hooks get Claude Code's environment, not Claude's Bash).
  `hooks_prompt.main`: block + transcript/history scrub (same-length `*`
  overwrite of every occurrence, a first pass at once and a detached helper
  for 10 s) with the fixed block reason (a secret belongs in the gateway's
  dialog, which Claude can open with `gate check NAME`); else the new context summary when the form
  changed, or the whole context when there is no record
  (`hooks_session.context_text`), pending notices; returns
  `{"continue": true}` when there is nothing to say, `None` for payloads
  without a prompt.
- `hooks_filechanged.main`: validate, ratchet, `systemMessage` with errors or
  `gateway.toml changed: box: sudo now ask; …` (`describe_changes` against the
  last seen snapshot in `run/form-seen.json`, else the approved rights) and
  the widenings waiting for the user's OK.
- `hooks/mcp_perm.sh` (PreToolUse `mcp__plugin_gate_gw__.*`): `http` and
  `download` get no output in every mode, for any method, with or without an
  account (a request can carry data out or use an account's credential, so
  Claude Code's own mode decides: a prompt in default and plan mode, the
  reviewer in auto; `web.py` still keeps a credential to its account's sites
  and applies the policy). It allows only `host_inspect`, the terminal and
  job reads, a local `terminal_open`, `terminal_resize` and a
  `host_runtime` status read (terminals.md, remote.md); else no output.
  Only top-level keys count (escapes neutralized, then an awk tokenizer
  tracks object depth outside strings), so a `tool_name`, `host` or
  `action` nested in the input never decides.

## Tests and mutations

`tests/test_ux_popup.py`, `test_ux_dialog.py`, `test_ux_gate_setup.py`,
`test_ux_hooks.py`, `test_ux_mcp.py`, `test_web_http.py`,
`test_web_download.py`, `test_transfer_roundtrip.py`, `test_transfer_peer.py`,
fixtures in `tests/harness_ux.py` (`ux_env`, `UXDialog` with per-answer
delays, helper tracking, local HTTP(S) servers, `run_sh`, `user_sshd` (an
sshd this user runs on 127.0.0.1), `ux_entry_cmd` (a test entry that runs
run.py under `testing.override(ROOT, dialog="none")`), `trickle_server` (a
raw HTTP server answering one byte at a time, in the headers or the body)).
The native dialog path (gated's requests, leases, the sealed intake,
clipboard, restart, pause) is `tests/test_dialogs.py`; the mod's pane, field
and guard `hooks/mod/dialog.test.ts`; the whole path live
`tests/acceptance_dialogs.py`. `tests/mutations_ux.py` runs through
`mutation_check.main` (134 mutations: phase 3 removed the terminal,
one-time-code and OS-dialog ones, and since GW-SEC-1 the `mcp_perm.sh`
ones check that `http` and `download` get no decision; `plain_local_path`'s are in
`tests/mutations_sudo.py`, with the hook that uses it), and
`tests/mutations_dialogs.py` covers the native dialogs. Run mutations only through `pixi run --locked mutations` (or one
file with `--copy DIR`), which mutates scratch copies, never the checkout.

## History

The review-round notes below describe the code as it was then. PLAN-v4
phase 3 (2026-10-20) removed the OS dialogs (osascript, zenity, kdialog),
the terminal mode, `gate secret`, the one-time codes and the browser and
device-code sign-ins they mention; what replaced them is described above.

## Review round 3 (2026-10-19)

- **popup**: the requester prints its "waiting for ... in a pop-up" notice
  when the helper writes `SHOWN` on the pipe (`_shown()`, called before every
  dialog and sign-in window), not up front, so a job that opens no dialog
  prints nothing. `message(cancelled, NAME, "consent")` reads "the user
  cancelled the consent pop-up for NAME"; the no-screen messages say the
  gateway *shows* the user the command and code (with this result or the
  next step), not that it was shown.
- **gate_setup**: `plan_for` reads every remote host's key when ssh isn't
  off (a change → the host-key path of `_consent_step`, so `gate secret NAME`
  answers a host-key request the stand-in left), tries a login for a host
  that looks set up (`_relogin`; refused → `needs_key`, `installed` dropped,
  a note; works → nothing to do), and stops behind a jump host that isn't
  approved, pinned and installed (`jump_problem` → `Plan.error`, exit 1,
  before any pop-up). `_keyscan` returns the ssh module's own reason.
  `check all` uses `hosts_jumps_first`. `status_line` never says "ready"
  with ssh waiting. The unreadable-vault message names the next step.
- **gate.py**: `gate scrub` (a line filter, fails closed; required for
  Monitor commands in round 3, optional since the rollback), the
  status footer from the form's own hosts, "No gateway.toml yet" on a fresh
  install, `gate why` without a session id shows the newest refusal of any
  session (`audit.newest_refusal`), `_phase_b` and run.py's shim and gate
  modes print one `gateway: ... failed (TypeName)` line, never a traceback.
- **transfer**: copy-to says the user signs in to Claude Code on the remote
  and lets its first-time setup finish; a remote `gate` exiting 75 is "still
  setting up; try again in a minute".
- **hooks.json**: PostToolUseFailure with PostToolUse's matcher, `post.sh`
  (since the integration review the matcher names checkpoint's job_tail,
  job_status and job_stop too; below).
- Tests: `test_ux_hooks` (failure payloads, hooks.json), `test_ux_popup`
  (notice), `test_ux_gate_setup` (host-key change through `gate secret`),
  `test_ssh_setup` (re-verify, jump host, agent), `test_gate`, `test_messages`,
  `test_transfer_roundtrip`; mutations in `mutations_ux.py`.

## Review round 4 (2026-10-19)

- **Task notifications** (`hooks_prompt`): `is_task_notice(text)`,
  `notice_leaks(text) -> (labels, values)` (stored values in every scrubber
  form through `hooks_post.secret_matches`, token shapes through
  `find_secrets`, `scrub.SHAPES` and `scrub.AUTH_HEADER`), `block_notice(labels)`
  (block, `suppressOriginalPrompt`, a systemMessage naming the entry),
  `_scrub_copies` (transcript and history, the `_spawn_scrubber` of the
  paste guard). A notice never clears the cancelled pop-up markers (prompt.sh
  and `hooks_prompt` skip them for it). `migrate.take_unshown_report()` gives
  a mid-session conversion's report to the next prompt.
- **PostToolUseFailure advice** (`hooks_post._fix_for(entry, what,
  section)`, from `vault.labeled_secrets`): host ssh key → `gate rotate`;
  sudo password → change it there, `gate forget NAME sudo`, `gate check`;
  account ssh key → remove its public key, `gate forget NAME key`, `gate
  check`; token, API key or sign-in → replace it, `gate login NAME`. A test
  runs each advised command and sees a pop-up open.
  `secret_matches(text) -> [(entry, what, section, forms)]` (the forms are
  for masking copies, never shown). `form_report` joins every item with
  "; ".
- **Desktop session tools**: `hooks_post.SESSION_READERS`
  (`search_session_transcripts`, `list_events`) get one-time codes masked
  too (`live_codes()`, `mask_codes()`); post.sh always sends them to Python.
  The PreToolUse side is `hooks_files` (export denied, readers denied while a
  code is live) and launch.sh's degraded guard.
- **gate_setup**: `_changes_reach(changes)`; `plan_for` stops with
  `Plan.error` ("...; nothing was asked") when no host key was read for a
  first pin or a new address/jump. `check()` / `login()` set
  `popup.set_deadline(start + BUDGET)` (100 s; override
  `gate_check_budget`), so every pop-up wait ends in time for the exit-75
  line before Claude Code's 2-minute Bash timeout; `_check_all` starts no new
  entry after `ALL_BUDGET` (60 s; override `gate_check_all_budget`) and exits
  75 naming what is left. `with_notes(line, notes)`: what the setup did,
  after the status line, without nested `gateway: ` prefixes.
- **popup**: `set_deadline(t)` caps every requester wait of this process
  (`_wait_deadline()`).
- **Token rejection**: the git helper, gh, hf and `gate with` say
  `accounts.stale_token_message(NAME)` (`... rejected; don't retry. Run gate
  check NAME while the user is here to enter a new one`); no pop-up opens by
  itself for a token, so none is claimed.
- **gate.py**: `config_aliases` follows `Include` (relative to the config's
  folder, `~`, globs, depth 16); `import_ssh` skips an alias whose HostName
  is a git server (`form.git_server_note`) or an account's ssh endpoint
  (`_account_endpoint_note`), with a comment. USAGE: `gate forget NAME
  [sudo|token|key|signin|host-keys]`.
- **Wording**: user-facing text says "0.6" for the old version (`gate
  migrate`, `gate status`, the report, the converted form's comments).
- **hooks_session**: `ok_how(target, names, coded)` drops "which you get
  when Claude runs gate check" when that entry's code is in the same
  message; the unreadable-vault message says to restore `private/key.txt` or
  start from an export.
- Tests: `test_ux_hooks`, `test_ux_gate_setup`, `test_gate`, `test_migrate`,
  `test_git_helper`, `test_accounts_clis`, `test_envfile`, `test_ssh_setup`,
  `test_hookbash_round4`; mutations in `mutations_ux.py`, `mutations_sudo.py`
  and `mutations_accounts.py`.

## Rolled back (2026-10-19, lead decision)

- The env file's EXIT trap is gone (envfile, launch.sh): a failed command
  keeps its exit code, so its output goes to PostToolUseFailure, where
  `hooks_post._failure_main` warns (unchanged) and nothing can be masked
  (known limit).
- No hook requires `gate scrub` any more (docs/dev/modules/sudo.md); `gate
  scrub` stays, optional. The prompt hook's task-notification check (round
  4, above) stays: a notice quoting a stored value or a token shape is
  held back and masked in the transcript and history; raw background output
  and Monitor lines are known limits.
- `gate secret` (and `user_terminal()`, so transfer's terminal path) refuse
  under a Claude Code ancestor (`gate_setup.claude_ancestor`,
  `ancestry.claude_ancestor`); the one-time code stays. Review round 5: a
  tree it can't read gets `CANT_TELL` (above), and the approval hook denies
  `gate secret` in every tool, the Terminal panel included
  (docs/dev/modules/sudo.md).
- Tests: `test_ux_gate_setup::test_secret_refuses_under_a_claude_code_ancestor`
  (faked process tables through the real walk: secret refused before
  anything is asked, audited, `user_terminal()` None; a user's terminal
  reaches the code prompt; an unreadable tree and an error refuse) and
  `test_secret_refuses_under_a_real_claude_named_process` (real trees
  re-parented to init, away from the test runner's own Claude Code: a copy of
  the shell named `claude`, or in `~/.local/share/claude/versions/`, refuses;
  a plain shell reaches the terminal check); 5 mutations in
  `mutations_ux.py`.

### Review round 5 (2026-10-19)

| finding | fix | tests |
|---|---|---|
| (MEDIUM) a tree it can't read (macOS: a shell or tmux replaced by an upgrade) refused `gate secret` and the terminal transfer path with words about, or for, Claude Code | `gate_setup.CANT_TELL`, `cant_tell()`, `tree_refusal()`; transfer `_ask` prints and audits it | `test_ux_gate_setup::test_secret_refuses_under_a_claude_code_ancestor` (an unreadable tree and an error give `CANT_TELL`; Claude Code above an unreadable process gives `FROM_CLAUDE`), `test_secret_under_a_shell_whose_executable_was_deleted_says_what_to_do`, `test_transfer_roundtrip::test_no_screen_terminal_path_with_a_tree_it_cant_read_tells_the_user_what_to_do`; 4 new mutations (3 updated) |
| (MEDIUM) about 130-145 ms of Python and age per tool call once a vault exists, plus 66 ms of file guard | post.sh skips Python for an edit tool's response (above); hooks_post's lazy imports and `nothing_pending()`; lazy imports in `vault`, `paths`, `testing` (`Override` is a plain class); launch.sh's file guard fast path (docs/dev/MODULES-v3.md, "Hooks"; SPEC 12), its env hash without a subshell, its folder without `dirname` | `test_ux_hooks::test_post_sh_with_a_vault_skips_python_for_edit_tools_only`, `test_post_with_a_vault_still_masks_what_claude_reads_and_leaves_edits_alone`, `test_post_hook_without_pending_files_imports_no_popup`, `test_file_guard_fast_path_passes_only_what_python_passes` (every case compared with `hooks_files.main`; under sh, dash and bash), `test_file_guard_fast_path_in_production_mode_leaves_run_dirs_and_test_roots_to_python`; 21 mutations |

### Checkpoint job results (integration review, 2026-10-19)

checkpoint's `job_tail` (a job's log), `job_stop` (its last log lines) and
`job_status` (its record) return an MCP content list whose one text block is
checkpoint's result as indented JSON. hooks.json's PostToolUse and
PostToolUseFailure matchers now name the three by their exact names (nothing
changes when checkpoint isn't loaded); `post.sh` and `hooks_post` needed no
change (with a vault every non-edit response goes to Python; `scrub_obj`
walks the list and masks the JSON-escaped forms in the text).

| finding | fix | tests |
|---|---|---|
| (HIGH) a job's `cat notes.txt` (the planted API key and remote sudo password) came back raw through `job_tail`, into the model's context, the stream-json and the transcript (a Read of the log, or the same `cat` in Bash, was masked) | `\|mcp__plugin_check_jobs__job_tail\|mcp__plugin_check_jobs__job_status\|mcp__plugin_check_jobs__job_stop` in both output matchers; a `job_stop` that fails (`stop_failed`, an MCP error result) goes to PostToolUseFailure, which warns and audits like a failed Bash command (probe, Claude Code 2.1.301: `error` holds the text, `updatedToolOutput` is ignored there) | `test_ux_hooks::test_hooks_json_sends_checkpoint_job_results_to_the_output_hooks` (both events; lookalike names don't match), `test_post_sh_masks_stored_values_in_checkpoint_job_results` (post.sh → hook-post: tail, stop, status; JSON-escaped sudo password, token shape; checkpoint's JSON kept), `test_post_sh_warns_when_a_failed_job_stop_returns_a_stored_value`, `test_post_sh_with_a_vault_skips_python_for_edit_tools_only` (the job tools go to Python), `test_session::test_context_mentions_checkpoint_jobs_only_when_checkpoint_is_there` (the how-to line says so); 3 mutations in `mutations_ux.py` (the names out of PostToolUse, job_tail alone out, the names out of PostToolUseFailure) |
