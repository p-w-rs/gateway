# TUI acceptance harness

Test infrastructure for the brief's acceptance scenarios (section 14): it
drives the real interactive `claude` TUI in a pseudo-terminal against a local
fake Messages API, installs plugins the normal way (a git-source marketplace)
into scratch Claude configs, records what a nosy third-party mod could
observe, and scans everything for synthetic canaries.

The folder is identical in both repositories:
`gateway/plugins/gateway/tests/tui/` and
`checkpoint/plugins/checkpoint/tests/tui/`. Change one, copy it to the other,
and check with
`diff -r -x __pycache__ gateway/plugins/gateway/tests/tui checkpoint/plugins/checkpoint/tests/tui`.
It imports nothing from either plugin or from the gateway's other test helpers
(gwe2e.py runs the installed gateway's own `launch.sh` and `gateway.paths` in
child processes, as a pre-flight).

Requirements: the newest Python (`--spec python`) with `pyte` (nothing else
outside the stdlib), the `claude` CLI on PATH (checked against 2.1.310; mods
need 2.1.287 terminal), and `git` on PATH (Claude Code clones git marketplaces with it; the git
server runs `git http-backend`). macOS and Linux (pty, termios).

## Self-test

```bash
pixi exec --spec python --spec pyte python tests/tui/selftest.py            # from the plugin folder
pixi exec --spec python --spec pyte python tests/tui/selftest.py --tmp DIR --keep --only a,c
pixi exec --spec python --spec pyte python tests/tui/selftest.py --gateway ../gateway  # from checkpoint
pixi exec --spec python --spec pyte python tests/tui/selftest.py --only t   # the record-only proxy (opt-in)
```

It proves, on this machine, in about 35 seconds (166 checks, 2026-10-20; `--tmp` must be a
plain path, see section g; `--only s,a,b,c,d,e` leaves the gateway out):

| | |
|---|---|
| s | the guards: `check_scratch` refuses the real Claude config, `~/.claude`, the gateway home, checkpoint's real state, the real home, a temp base, a non-temp dir and a symlink escape; `hermetic_env` drops the caller's credentials, proxies, OTEL and CLAUDE_* settings, sets every plugin state root (CHECKPOINT_GATEWAY_CONTRACT included) to scratch, shares them between HOMEs on one config, and refuses unsafe overrides (a real path, an unset or empty CHECKPOINT_GATEWAY_CONTRACT, an unset CHECKPOINT_GATEWAY_ENV, a non-loopback API URL), and lets CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC go only when every proxy variable, TUI_RECORD_PROXY and a scratch NODE_EXTRA_CA_CERTS name the harness's loopback record-only proxy (a non-loopback proxy, one variable left out, another proxy, no CA: refused); `seed_config` writes and removes the bypass acceptance in settings.json; `classify` tells the prompt box from the bypass warning, the trust dialog and other dialogs; Session refuses a gateway (a `--plugin-dir` copy, or enabled in the config) without an e2e proof before starting anything; the e2e marker rules; `kill_tree` stops a helper a dying child started in a session of its own; Session and Installation refuse the real config |
| a | fake API + interactive session: the prompt appears, the scripted reply is drawn, the request log has the prompt and no credential headers, `--debug-file` and the observer record |
| b | a scripted `Bash` tool_use runs under `--permission-mode bypassPermissions` and its result reaches the fake API; paste, resize and click work; with an untrusted cwd, `wait_ready` accepts the trust dialog (moving off its default "No, exit") and reaches the prompt |
| c | a probe plugin made in a temp dir is published to the local git server, added as a marketplace and installed into a scratch config; its hook fires from the installed cache path with the installation's CHECKPOINT_HOME; a bypassPermissions session on that installed config reaches the prompt, and without the settings key the bypass warning shows and `wait_ready` raises `BlockingDialog` at once; update, then a restart keeps the plugin state root and its contents; disable/enable and uninstall (`--keep-data` and not) behave |
| d | planted canaries are found in raw, base64, hex, URL, gzip, JSON-escaped and ANSI-painted forms in a tree, the fake API log and PTY bytes; an absent one is not; no report or location contains a value |
| e | the fake API protocol without claude, in process and thread mode: SSE text and tool_use blocks, delays, errors, hold/release, script/push, count_tokens, classification, `require_tool`, a 0600 log |
| g | the gateway (this repository's checkout, or `../gateway` from checkpoint's, or `--gateway DIR`; skipped with a note when none is found): `install_gateway_e2e` refuses a config dir with a space and a non-ASCII letter before publishing anything; a plain install is refused by Session; the e2e install carries the marker, the sh and Python pre-flight agree and every gateway location is inside the e2e root, the proof is recorded; a missing proof or an ignored (group-writable) marker is refused; a live session runs the gateway redirected (GATEWAY_TEST_ROOT unset, its stand-ins and launcher in the e2e root, a prompt passes its hooks, no refusal in the debug log); `update_gateway_e2e` installs and proves a new version, and the old proof is refused. The session starts the gateway's pixi build (pixi's cache is kept in the scratch root; about 375 MB is downloaded); close() stops it |
| t | opt-in (`--only t`; not in the default run, since `pixi exec` fetches mitmproxy the first time): a session with telemetry on behind the record-only proxy (`proxy.py`): its environment has the proxies and no traffic switch, the model calls still reach the fake API (none goes through the proxy), and every first-party request is recorded with its body on disk and answered by the proxy |

It exits non-zero on any failure, removes its scratch root (unless `--keep`),
checks that no process mentioning the root survives and that nothing was left
in `/tmp/claude-<uid>/`, and compares the sha256 of the real
`~/.config/claude/settings.json` (and the plugin registry files) before and
after.

## Modules

| module | what it gives |
|---|---|
| `safety.py` | `check_scratch(path)` (refuses anything outside a temp base or overlapping `~/.config/claude`, `~/.claude`, `~/.config/gateway`, `~/.local/state/checkpoint`; "real" home from the password database; the protected dirs themselves are never stat'ed, only their parents resolved), `hermetic_env(...)` (allowlisted child environment; plugin state roots `STATE_VARS` from `state_root_for(config)`), `short_runtime_dir()`, `kill_tree(pid, match=...)` (with `match`, also what joined the tree or the children's sessions since), `real_settings_fingerprint()` |
| `fakeapi.py` | `FakeAPI(root, replies).start()`: fake Messages API on 127.0.0.1, port 0, JSONL request log, scripted replies for main-loop requests only; `script()`, `push()`, `release()`, `requests()`, `main_requests()`, `wait_main()`; `tool_results(rec)` |
| `driver.py` | `Session(root, ...)`: `claude` in a PTY with a seeded scratch config; `wait_ready`, `wait_for`/`expect`, `type`, `send`, `submit`, `paste`, `key`, `click`, `click_text`, `resize`, `text`/`all_text`/`find_text`/`composer`/`state`, `raw`/`mark`/`raw_since`, `alive`, `check_gateways`, `close`; `seed_config`, `classify`/`composer_row`, `BlockingDialog` |
| `install.py` | `source_files`, `snapshot_tree`, `GitServer`/`ServedRepo.publish`, `Installation` (`claude plugin ...` in a scratch config, `plugin(id)` -> cache and data paths), `Hermetic` (all three; `install_gateway_e2e`/`update_gateway_e2e`) |
| `gwe2e.py` | the gateway's e2e route: `install(h, src)` (marker, install, pre-flight, proof), `preflight(plugin_dir)`, `check_rules`/`spelled_ok` (the marker's path rules), `session_gateways` + `verify` (what Session runs), `NotProven` |
| `scan.py` | `Canary.new()`, `Report.scan_tree/scan_bytes/scan_api_log`, `Report.clean()/summary()` |
| `observe.py` + `observer/` | the `tui-observer` plugin and `Observer(root)` to load and read it |
| `proxy.py` | `RecordProxy(root)`: the record-only telemetry proxy (mitmproxy `MITM_VERSION` through `pixi exec`, a record addon answering every request with 204, never forwarding); `start()`/`close()` (or `with`), `env()` (the Session/hermetic_env extras: proxies, its CA, telemetry on), `requests()`, `bodies_dir`, `url`, `ca` |
| `gitserve.py` | the smart-HTTP git server process `install.GitServer` starts |

Import it with the plugin's `tests/` folder on `sys.path` (`from tui import
driver, install, scan`), the way `selftest.py` does.

## Driving a session

```python
from tui.driver import Session

replies = [{"tool": "Bash", "input": {"command": "echo hi > f.txt", "description": "x"}},
           "all done"]
with Session(root, replies=replies, permission_mode="bypassPermissions",
             debug_file=True, observer=True) as s:
    s.wait_ready()
    s.submit("go")
    s.expect(r"all done", timeout=60)       # TimeoutError with a (redacted) screen dump
    s.api.main_requests()[-1]["body"]       # what Claude Code sent, in plaintext
```

- `root` must be a fresh directory under a temp base; the session lays out
  `cfg/` (CLAUDE_CONFIG_DIR), `home/` (HOME; `home=` overrides it), `tmp/`
  (TMPDIR and CLAUDE_CODE_TMPDIR, 0700), `work/` (default cwd), `api/`
  (request log), plus a short private `/tmp/tui-*` for XDG_RUNTIME_DIR
  (removed on close).
- The plugin state roots live in one state root per config,
  `<config>.state/` next to the config dir (`safety.state_root_for`;
  `state_root=` overrides it): every Session on that config, a restart
  included, and every `claude plugin` call on it see the same
  CHECKPOINT_HOME, CHECKPOINT_GATEWAY_ENV, CHECKPOINT_GATEWAY_CONTRACT,
  GATEWAY_TEST_ROOT and XDG_STATE/CONFIG/DATA/CACHE_HOME, whatever their HOME.
- `.claude.json` is seeded (onboarding, theme, trusted cwd unless
  `trust_cwd=False`, approved fake key, auto-updates off) and merged into an
  existing one; bypass mode is accepted in both `.claude.json`
  (`bypassPermissionsModeAccepted`) and `settings.json`
  (`skipDangerousModePermissionPrompt`, merged; the only one an installed
  config honours, see Platform facts); `accept_bypass=False` removes both.
- The child environment is an allowlist (PATH, USER, SHELL, locale, TZ) plus
  ANTHROPIC_BASE_URL (the fake API; it must stay a loopback URL), a fake
  ANTHROPIC_API_KEY, CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 (must stay,
  except behind the record-only proxy: next section),
  DISABLE_AUTOUPDATER=1 and the scratch state roots above.
  `inherit_env=("PIXI_CACHE_DIR", ...)` copies more caller variables;
  `extra_env` sets more (None deletes; CHECKPOINT_GATEWAY_CONTRACT must stay
  non-empty and CHECKPOINT_GATEWAY_ENV present, since checkpoint falls back to
  the real home without them).
- `wait_ready()` returns only for the prompt box (a ❯ row right below a rule,
  or "? for shortcuts", with no dialog footer on screen). It accepts the
  folder-trust dialog (moving its pointer to "Yes, I trust this folder"
  first), raises `BlockingDialog` (a TimeoutError) at once for a known
  blocking dialog such as the Bypass Permissions warning, and TimeoutError
  with the screen for anything else still up at the timeout.
- `close()` kills claude, its process group, its descendants and, by session
  id and command line, what its children left behind in sessions of their
  own (a mod's `$.process.spawn` runs in one).
- Coordinates are 0-based cells (col, row), as pyte reports them.
- `s.redact(value)` keeps a value out of every dump and exception message.
- Plugins: `plugin_dirs=[copy]` (`--plugin-dir`), or `config_dir=` a scratch
  config a plugin was installed into (below). A gateway among them needs the
  e2e route (below), or the Session refuses to start.

### Scripted replies

Only main-loop requests (a POST to `/v1/messages` with a non-empty `tools`
list; `require_tool="Bash"` narrows it) consume replies, in order. A
subagent's requests carry tools too, so they take the next replies like the
main loop's. Everything
else (titles, classifier, summaries) gets `default_text`; `count_tokens` gets
`{"input_tokens": 10}`. Reply forms: `"text"`, `{"text": ...}`,
`{"tool": name, "input": {...}, "text"?: preamble}`, `{"blocks": [...]}`, and
the options `delay`, `chunk_delay` (slow streaming, for "pause during model
work"), `hold: "name"` (answer only after `api.release("name")`), `error:
{status, type, message}`, `stop_reason`. Responses stream as SSE when the
request asks for it.

## Normal installation (brief 14.1)

```python
from tui import install
from tui.driver import Session

with install.Hermetic(root / "inst") as h:
    p = h.install_from(repo_checkout, repo="checkpoint", plugin="check")   # -> InstalledPlugin
    p.cache_path    # <cfg>/plugins/cache/checkpoint/check/<version>: what sessions run
    p.data_path     # <cfg>/plugins/data/check-checkpoint: CLAUDE_PLUGIN_DATA
    with Session(root / "s1", config_dir=h.inst.config_dir) as s:
        ...
    h.update_from(repo_checkout, repo="checkpoint", plugin="check")       # new snapshot + updates
    h.inst.disable(p.id); h.inst.enable(p.id); h.inst.uninstall(p.id, keep_data=True)
```

The gateway installs the same way only through `h.install_gateway_e2e` (next
section); a Session refuses a plainly installed one.

The snapshot is what `git add -A` would commit (`git ls-files -co
--exclude-standard`, run read-only with GIT_OPTIONAL_LOCKS=0): the source
repository is never written. Each publish is a new commit on the served
history. Every `claude plugin` call is kept in `h.inst.history` (argv, exit
code, output) for evidence. `Hermetic(root, config_dir=...)` installs into a
config dir of your choosing (a spaced one, say); the gateway is the exception
(next section).

## The gateway plugin (its e2e route)

The gateway takes its home from the password database, never `$HOME`, and
of its two redirections only one works in a session:

- `GATEWAY_TEST_ROOT` (set by default) redirects only `run.py --test` and
  `launch.sh MODE --test`, which hooks.json never passes. In a session every
  Python hook, the MCP server and every stand-in then exit 2 ("GATEWAY_TEST_ROOT
  is set but this isn't a `run.py --test` ...", in the debug log only) while
  the mod shows no warning (setup still ends in its "ready" toast): inert,
  and a test on it can pass falsely.
- The e2e marker (`e2e-root` in the plugin folder, naming a root and a run
  dir) works, but the gateway honours it only when the plugin folder, the
  marker and the named folders follow `hooks/e2e.sh`'s rules (spelled with
  `[A-Za-z0-9/._-]` only, below `/tmp`, `/var/tmp` or `/var/folders`, folders
  0700 and yours, marker not group or other writable), and otherwise silently
  uses the real `~/.config/gateway`; and run.py refuses every mode while
  `GATEWAY_TEST_ROOT` is set.

So the harness has one route, and a guard:

```python
from tui import install
from tui.driver import Session

with install.Hermetic(root / "inst") as h:              # root: a plain path (no spaces)
    gi = h.install_gateway_e2e(gateway_checkout)       # -> gwe2e.GatewayInstall
    gi.root, gi.run, gi.gateway_home                   # e2e root (0700), run dir under /tmp
    with Session(root / "s1", config_dir=h.inst.config_dir) as s:
        s.gateway_mode                                 # "e2e": GATEWAY_TEST_ROOT unset,
        ...                                            # CHECKPOINT_GATEWAY_ENV/CONTRACT -> gi.gateway_home
    h.update_gateway_e2e(gateway_checkout, version="0.7.1000")   # a native update, re-proven
```

`install_gateway_e2e` refuses a config dir the marker rules reject (a space,
a non-ASCII letter: brief 14.1's spaced paths go in the cwd or the project,
not the gateway's config) before publishing anything; publishes a snapshot of
the checkout with the marker (the checkout is never written); installs it;
runs the pre-flight on the installed copy (`sh hooks/launch.sh e2e-root` and
the copy's own `gateway.paths` must both name the marker's folders, and every
gateway location must lie inside them); and records the proof in
`<config>/.tui-harness/gateway-e2e.json` (0600). `e2e_config={...}` writes the
gateway's `e2e.json` test knobs. `Hermetic.close()` removes the run dir.

Only Session enforces this: a test that starts claude itself on that config
uses `gi.env()` (GATEWAY_TEST_ROOT unset, checkpoint pointed at the e2e
gateway home) only after `gwe2e.verify` passes.

`Session.start()` runs `check_gateways()` before anything starts: every
gateway the session would load (enabled in the config's or the cwd's
settings, or a `--plugin-dir` copy) must pass the pre-flight again, and an
installed one must match its recorded proof (same folder, marker and
folders: an update without `update_gateway_e2e` is refused). Otherwise it
raises `gwe2e.NotProven`, unless `allow_inert_gateway=True`, which keeps
`GATEWAY_TEST_ROOT` set (refusing a session that unsets it) for a test that
wants the gateway present but inert. The pre-flight never touches the real
`~/.config/gateway`: launch.sh runs with `GATEWAY_TEST_ROOT` set and no
`--test` (it resolves no home), and the Python side replaces
`gateway.testing.guard` (which realpaths the real gateway home) in its own
process and checks the locations by text instead. The gateway itself, once
running under the marker, enters `testing.override`, whose guard does
realpath it.

## Canaries

```python
from tui.scan import Canary, Report
c = Canary.new("pw")           # repr/str/format never show the value; not picklable
s.redact(c.value)
s.click_text("Password:", dx=3); s.type(c.value)
rep = Report()
rep.scan_tree(s.config_dir, c)                      # transcripts, history, plugin data ...
rep.scan_tree(s.root / "observer" / "observed", c)  # what a nosy mod saw
rep.scan_bytes(bytes(s.raw), "pty", c, ansi=True)
rep.scan_api_log(s.api.log_path, c)
assert rep.clean(), rep.summary()                   # locations only, values masked
```

`scan_tree(..., exclude=[path])` skips a file that may hold the value (a
positive control such as the broker's own record). Never print `c.value`, put
it in a prompt the model sees, or pass it to `Observer.find(contains=...)` in
code that prints the result.

## Telemetry on, through the record-only proxy (brief 14.13)

Claude Code's first-party telemetry (event logging, feature gates,
bootstrap) is HTTPS to Anthropic and the `anthropic` telemetry stream can't
be hooked by a third-party mod, so the harness sees it by being its
endpoint:

```python
from tui import proxy
with proxy.RecordProxy(root / "proxy") as px:
    s = driver.Session(root / "s", extra_env=px.env(), ...)
    ...
    px.requests()        # [{n, method, host, path, len, encoding}]
    px.bodies_dir        # NNNNN.raw and NNNNN.dec (content-encoding decoded): scan these
```

`RecordProxy` runs `pixi exec --spec mitmproxy==12.2.3 mitmdump` on
127.0.0.1 (a free port, its CA and config in the scratch root) with an addon
that writes every request to disk and answers it itself (204, empty body);
nothing is forwarded. `px.env()` sets HTTPS_PROXY/HTTP_PROXY (both
spellings) and TUI_RECORD_PROXY to it, NODE_EXTRA_CA_CERTS to its CA, and
removes CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC, DISABLE_TELEMETRY and
DISABLE_ERROR_REPORTING. `hermetic_env` keeps NO_PROXY at
`127.0.0.1,localhost`, so the fake API stays direct, and refuses the
traffic switch's removal unless `safety.record_proxied(env)` holds. A
request a client sends outside its proxy settings would not be recorded
(none was seen); a report says so. With telemetry on, Claude Code 2.1.301
fetches its online feature settings and starts on the main screen (no mouse
reporting) unless `CLAUDE_CODE_NO_FLICKER=1` is set: a scenario that clicks
sets it.

## The observer plugin

`observer/` is a test-only plugin, `tui-observer`. One `*` hook records the
input and result of every event a third-party mod can hook (plus other
plugins' nouns), generator hooks record the chunks of `turn.step` and
`process.spawn`, and a `telemetry.*` hook records the `collector` stream (the
`anthropic` stream cannot be hooked by a third-party plugin, so first-party
telemetry needs other evidence). `$TUI_OBSERVER_OUT` names a directory; the
records go to `seg-NNNNNN.jsonl` files in it (a mod can only write whole
files, so the log is split into segments of at most 400 records instead of
rewriting one growing file per event); `$TUI_OBSERVER_MAX` caps each
record's data (default 65536 characters, `trunc` marks a cut).
`Session(observer=True)` copies it into the session root and loads it;
`s.observer.records()` / `.events()` read it.

## Platform facts this harness depends on (2.1.301, macOS)

- On close, the PTY master must keep being read while the child exits: a
  process cannot finish exiting while its terminal output is undrained, so
  `kill_tree` takes a `drain` callback. Claude exits with 143 on SIGTERM.
- Claude Code writes `.claude-plugin/types/` into any mod folder it loads with
  `--plugin-dir`: always load copies (`install.snapshot_tree`), never a
  repository folder.
- Claude Code's own temp root is `/tmp/claude-<uid>/` unless
  `CLAUDE_CODE_TMPDIR` names a private directory; the harness sets it.
- Claude Code's peer-messaging socket goes to `$XDG_RUNTIME_DIR/cc-socks/`
  and falls back to the shared `/tmp/cc-socks-<uid>/` when the path passes the
  103-byte socket limit (scratch paths are long), where the person's real
  sessions would see the test session as a peer; the harness gives each
  session and each `claude plugin` call a short private runtime dir.
- Claude spawns short-lived helpers (a `ps | grep` shell) under itself;
  `kill_tree` signals a pid only while it still has the start time it had
  when listed, so a reused pid is never hit.
- The gateway plugin takes its home from the password database, not `$HOME`,
  and in a session only its e2e marker redirects it (`GATEWAY_TEST_ROOT`
  makes it inert): see "The gateway plugin" above; Session enforces it.
- Bypass mode's warning ("WARNING: Claude Code running in Bypass Permissions
  mode ... ❯ No, exit / Yes, I accept") is suppressed by settings.json's
  `skipDangerousModePermissionPrompt`. `.claude.json`'s
  `bypassPermissionsModeAccepted` counts only on a config's first start,
  which migrates it into settings.json (migrationVersion 14); `claude plugin
  install` is such a start, so on an installed config the old key is ignored
  and the warning shows every time unless settings.json has the new one.
- The folder-trust dialog's pointer starts on "No, exit" (Enter quits); it
  takes keys only once it has settled (about a second).
- A mod's `$.process.spawn` child runs in a session of its own (setsid), so
  what it starts is not in claude's process group, and an orphan of it is
  no longer claude's descendant (the gateway's `launch.sh ensure-env` and its
  warm step were the case).
- The desktop app's surface cannot be driven this way (manual check).
