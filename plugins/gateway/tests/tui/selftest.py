#!/usr/bin/env python3
"""End-to-end self-test of the TUI harness on this machine.

    pixi exec --spec python --spec pyte python tests/tui/selftest.py [--tmp DIR] [--keep] [--only a,c]
        [--gateway DIR]

Sections:
  s  safety guards: check_scratch refuses the real Claude config, ~/.claude,
     the gateway home, checkpoint's real state, the real home, a temp base,
     a non-temp dir and a symlink escape (without stat'ing protected dirs);
     hermetic_env drops the caller's credentials/proxies/CLAUDE_* settings,
     sets every plugin state root (CHECKPOINT_GATEWAY_CONTRACT included) to
     scratch paths shared by every HOME on one config, and refuses unsafe
     overrides; seed_config's bypass acceptance in settings.json; the screen
     classifier (prompt box vs dialogs); Session's gateway guard; the e2e
     marker rules; kill_tree's sweep of a setsid'd orphan; Session and
     Installation refuse the real config before starting anything.
  a  fake API + interactive session: the prompt appears, a typed prompt is
     sent, the scripted reply is drawn; the request log has the prompt and no
     credential headers; --debug-file and the observer plugin record.
  b  a scripted Bash tool_use runs under --permission-mode bypassPermissions,
     its result goes back to the fake API; paste and resize work; wait_ready
     accepts the folder-trust dialog of an untrusted cwd.
  c  a tiny probe plugin (made in a temp dir) is published to the local git
     server, added as a git-source marketplace and installed into a scratch
     config; its classic hook fires from the installed cache path in a real
     session; a bypassPermissions session on that installed config reaches
     the prompt, and without settings.json's key wait_ready raises
     BlockingDialog on the warning; update (new snapshot), a restart that
     keeps the plugin state root, disable/enable and uninstall --keep-data
     behave and are reported by install.py.
  d  canary scan: planted canaries are found in raw/base64/hex/url/gzip/ANSI
     forms in a tree, the fake API log and PTY-like bytes, an absent one is
     not, and no report, repr or location holds a canary value.
  e  fake API protocol without claude (process and thread modes): SSE text
     and tool_use blocks, delays, errors, hold/release, script/push,
     count_tokens, classification, require_tool, a 0600 log.
  t  (opt-in, --only t) the record-only telemetry proxy (proxy.py, mitmproxy
     through pixi exec): a session with telemetry on reaches the fake API for
     model calls while every first-party request is recorded and answered by
     the proxy, never forwarded.
  g  the gateway (--gateway, or this repo / ../gateway): install_gateway_e2e
     refuses a spaced config, a plain install is refused by Session, the e2e
     install is proven (sh + Python pre-flight) and recorded, a missing proof
     or an ignored marker is refused, a live session runs the gateway
     redirected, update_gateway_e2e re-proves a new version.

Safety: every root is a fresh dir under --tmp (default: the system temp dir);
each Session and Installation refuses a CLAUDE_CONFIG_DIR outside it (checked
again here before every start); the sha256 of the real
~/.config/claude/settings.json (and plugin registry files) is recorded before
and compared after; at the end the root is removed (unless --keep) and no
process whose command line mentions it may survive.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True  # leave no __pycache__ in the repository
sys.path.insert(0, str(HERE.parent))

from tui import driver, fakeapi, gwe2e, install, safety, scan  # noqa: E402

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append((name, bool(ok), detail))
    print(f"  {'ok  ' if ok else 'FAIL'} {name}{(': ' + detail) if detail and not ok else ''}", flush=True)
    return bool(ok)


def guard_session(s: driver.Session, root: Path) -> None:
    """The selftest's own assertion before any claude starts."""
    assert safety.is_under(s.config_dir, root), f"config dir {s.config_dir} not under {root}"
    assert not safety.overlaps_protected(s.config_dir)


# ---------------------------------------------------------------------------
def section_s(root: Path) -> None:
    print("s) safety guards (no claude)", flush=True)
    home = safety.real_home()
    refused = {"the real Claude config": home / ".config" / "claude",
               "a dir inside it": home / ".config" / "claude" / "plugins",
               "~/.claude": home / ".claude",
               "the gateway home": home / ".config" / "gateway",
               "checkpoint's real state": home / ".local" / "state" / "checkpoint",
               "the real home": home, "/": Path("/"), "a temp base": Path("/tmp"),
               "a non-temp dir": HERE}
    for what, path in refused.items():
        try:
            safety.check_scratch(path)
            check(f"s.check_scratch refuses {what}", False)
        except safety.UnsafePath:
            check(f"s.check_scratch refuses {what}", True)
    ok_dir = root / "s" / "ok"
    ok_dir.mkdir(parents=True)
    check("s.check_scratch accepts a fresh dir under the run root",
          safety.check_scratch(ok_dir) == Path(os.path.realpath(ok_dir)))
    link = root / "s" / "escape"
    link.symlink_to(HERE, target_is_directory=True)
    try:
        safety.check_scratch(link)
        check("s.check_scratch refuses a symlink out of the temp base", False)
    except safety.UnsafePath:
        check("s.check_scratch refuses a symlink out of the temp base", True)
    leaky = {"ANTHROPIC_API_KEY": "sk-real-looking", "ANTHROPIC_AUTH_TOKEN": "t",
             "CLAUDE_CODE_USE_BEDROCK": "1", "CLAUDE_CONFIG_DIR": str(home / ".config" / "claude"),
             "OTEL_EXPORTER_OTLP_ENDPOINT": "http://x", "GH_TOKEN": "t", "SSH_AUTH_SOCK": "/x",
             "HTTPS_PROXY": "http://x", "CHECKPOINT_HOME": str(home / ".local/state/checkpoint")}
    saved = {k: os.environ.get(k) for k in leaky}
    os.environ.update(leaky)
    try:
        dirs = [root / "s" / n for n in ("cfg", "home", "tmp")]
        for d in dirs:
            d.mkdir()
        env = safety.hermetic_env(config_dir=dirs[0], home=dirs[1], tmpdir=dirs[2])
    finally:
        for k, v in saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
    check("s.hermetic_env drops the caller's credentials, proxies, OTEL and CLAUDE_* settings",
          env["ANTHROPIC_API_KEY"] == safety.FAKE_API_KEY and "ANTHROPIC_AUTH_TOKEN" not in env
          and "CLAUDE_CODE_USE_BEDROCK" not in env and "OTEL_EXPORTER_OTLP_ENDPOINT" not in env
          and "GH_TOKEN" not in env and "SSH_AUTH_SOCK" not in env and "HTTPS_PROXY" not in env
          and safety.is_under(env["CLAUDE_CONFIG_DIR"], root)
          and safety.is_under(env["CHECKPOINT_HOME"], root)
          and safety.is_under(env["CLAUDE_CODE_TMPDIR"], root)
          and (os.stat(dirs[2]).st_mode & 0o777) == 0o700)
    # checkpoint's doctor stats ${CHECKPOINT_GATEWAY_CONTRACT:-<passwd home>/.config/gateway/
    # run/contract.json}: unset (or empty) it is a file in the real gateway home
    check("s.hermetic_env sets CHECKPOINT_GATEWAY_CONTRACT and every plugin state root to scratch",
          all(env.get(k) and safety.is_under(env[k], root) and not safety.overlaps_protected(env[k])
              for k in safety.STATE_VARS)
          and env["CHECKPOINT_GATEWAY_CONTRACT"].endswith("/.config/gateway/run/contract.json"),
          str({k: env.get(k) for k in safety.STATE_VARS}))
    real_contract = str(home / ".config" / "gateway" / "run" / "contract.json")
    for what, extra in {"CLAUDE_CONFIG_DIR -> real": {"CLAUDE_CONFIG_DIR": str(home / ".config/claude")},
                        "CLAUDE_CONFIG_DIR removed": {"CLAUDE_CONFIG_DIR": None},
                        "CHECKPOINT_HOME -> real": {"CHECKPOINT_HOME": str(home / ".local/state/checkpoint")},
                        "GATEWAY_TEST_ROOT -> real home": {"GATEWAY_TEST_ROOT": str(home)},
                        "CHECKPOINT_GATEWAY_CONTRACT -> real": {"CHECKPOINT_GATEWAY_CONTRACT": real_contract},
                        "CHECKPOINT_GATEWAY_CONTRACT removed": {"CHECKPOINT_GATEWAY_CONTRACT": None},
                        "CHECKPOINT_GATEWAY_CONTRACT empty": {"CHECKPOINT_GATEWAY_CONTRACT": ""},
                        "CHECKPOINT_GATEWAY_ENV removed": {"CHECKPOINT_GATEWAY_ENV": None},
                        "XDG_STATE_HOME -> real": {"XDG_STATE_HOME": str(home / ".local" / "state")},
                        "ANTHROPIC_BASE_URL -> a real API": {"ANTHROPIC_BASE_URL": "https://api.anthropic.com"},
                        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC removed":
                            {"CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": None}}.items():
        try:
            safety.hermetic_env(config_dir=dirs[0], home=dirs[1], tmpdir=dirs[2], extra=extra)
            check(f"s.hermetic_env refuses extra {what}", False)
        except safety.UnsafePath:
            check(f"s.hermetic_env refuses extra {what}", True)
    # telemetry on only with every request going to the record-only proxy (proxy.py)
    px = "http://127.0.0.1:9"
    ca = root / "s" / "proxy-ca.pem"
    ca.write_text("not a real CA\n")
    proxied = {"TUI_RECORD_PROXY": px, "HTTPS_PROXY": px, "HTTP_PROXY": px, "https_proxy": px,
               "http_proxy": px, "NODE_EXTRA_CA_CERTS": str(ca),
               "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": None, "DISABLE_TELEMETRY": None,
               "DISABLE_ERROR_REPORTING": None}
    env_t = safety.hermetic_env(config_dir=dirs[0], home=dirs[1], tmpdir=dirs[2], extra=proxied)
    check("s.hermetic_env lets telemetry on only through the harness's record-only proxy",
          "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC" not in env_t and "DISABLE_TELEMETRY" not in env_t
          and env_t["HTTPS_PROXY"] == px and env_t["NO_PROXY"] == "127.0.0.1,localhost")
    far = "http://10.0.0.1:8080"
    for what, extra in {"a non-loopback record proxy": {**proxied, "TUI_RECORD_PROXY": far,
                                                         "HTTPS_PROXY": far, "HTTP_PROXY": far,
                                                         "https_proxy": far, "http_proxy": far},
                        "one proxy variable left out": {**proxied, "http_proxy": None},
                        "a proxy other than the recorder": {**proxied, "HTTPS_PROXY": "http://127.0.0.1:8"},
                        "no proxy CA": {**proxied, "NODE_EXTRA_CA_CERTS": None},
                        "a CA in the real home": {**proxied, "NODE_EXTRA_CA_CERTS": str(home / "ca.pem")},
                        "a non-loopback proxy with traffic off": {"HTTPS_PROXY": far}}.items():
        try:
            safety.hermetic_env(config_dir=dirs[0], home=dirs[1], tmpdir=dirs[2], extra=extra)
            check(f"s.hermetic_env refuses telemetry with {what}", False)
        except safety.UnsafePath:
            check(f"s.hermetic_env refuses telemetry with {what}", True)
    ok_empty = safety.hermetic_env(config_dir=dirs[0], home=dirs[1], tmpdir=dirs[2],
                                   extra={"CHECKPOINT_GATEWAY_ENV": ""})
    check("s.hermetic_env allows an empty CHECKPOINT_GATEWAY_ENV (checkpoint: no env file)",
          ok_empty["CHECKPOINT_GATEWAY_ENV"] == "")
    # restarts: plugin state roots come from the config, not the per-Session HOME
    h2 = root / "s" / "home2"
    h2.mkdir()
    env2 = safety.hermetic_env(config_dir=dirs[0], home=h2, tmpdir=dirs[2])
    st = safety.state_root_for(safety.check_scratch(dirs[0]))
    check("s.two HOMEs on one config share CHECKPOINT_HOME, the gateway paths and XDG dirs",
          env2["HOME"] != env["HOME"]
          and all(env2[k] == env[k] and safety.is_under(env[k], st) for k in safety.STATE_VARS),
          str({k: (env[k], env2[k]) for k in safety.STATE_VARS if env[k] != env2[k]}))
    other = root / "s" / "cfg2"
    other.mkdir()
    env3 = safety.hermetic_env(config_dir=other, home=dirs[1], tmpdir=dirs[2])
    pinned = root / "s" / "pinned-state"
    env4 = safety.hermetic_env(config_dir=dirs[0], home=dirs[1], tmpdir=dirs[2], state_root=pinned)
    check("s.another config gets its own state root; state_root= pins one",
          env3["CHECKPOINT_HOME"] != env["CHECKPOINT_HOME"]
          and all(safety.is_under(env4[k], pinned) for k in safety.STATE_VARS))
    s1 = driver.Session(root / "s" / "r1", config_dir=dirs[0], start=False)
    s2 = driver.Session(root / "s" / "r2", config_dir=dirs[0], start=False)
    check("s.Sessions on one config share a state root (a restart keeps checkpoint's state)",
          s1.state_root == s2.state_root == st and s1.home != s2.home)
    s1.close()
    s2.close()
    section_s_seed(root)
    section_s_screens()
    section_s_gateway_guard(root)
    section_s_sweep(root)
    try:
        driver.Session(root / "s" / "sess", config_dir=home / ".config" / "claude")
        check("s.Session refuses the real config before starting anything", False)
    except safety.UnsafePath:
        check("s.Session refuses the real config before starting anything",
              not (root / "s" / "sess" / "api").exists())
    try:
        install.Installation(root / "s" / "inst", config_dir=home / ".config" / "claude")
        check("s.Installation refuses the real config", False)
    except safety.UnsafePath:
        check("s.Installation refuses the real config", True)


def section_s_seed(root: Path) -> None:
    """seed_config writes the bypass acceptance where an installed config reads it."""
    cfg = root / "s" / "seeded"
    cfg.mkdir()
    sp = cfg / "settings.json"
    sp.write_text(json.dumps({"enabledPlugins": {"x@y": True}}))
    os.chmod(sp, 0o600)
    driver.seed_config(cfg, [str(cfg)], safety.FAKE_API_KEY)
    sj = json.loads(sp.read_text())
    cj = json.loads((cfg / ".claude.json").read_text())
    check("s.seed_config merges skipDangerousModePermissionPrompt into settings.json",
          sj.get("skipDangerousModePermissionPrompt") is True and sj.get("enabledPlugins") == {"x@y": True}
          and (sp.stat().st_mode & 0o777) == 0o600 and cj.get("bypassPermissionsModeAccepted") is True,
          str(sj))
    driver.seed_config(cfg, [str(cfg)], safety.FAKE_API_KEY, accept_bypass=False)
    sj = json.loads(sp.read_text())
    cj = json.loads((cfg / ".claude.json").read_text())
    check("s.seed_config(accept_bypass=False) removes both acceptance keys, keeps the rest",
          "skipDangerousModePermissionPrompt" not in sj and sj.get("enabledPlugins") == {"x@y": True}
          and "bypassPermissionsModeAccepted" not in cj and cj.get("hasCompletedOnboarding") is True)
    fresh = root / "s" / "seeded-fresh"
    fresh.mkdir()
    driver.seed_config(fresh, [], safety.FAKE_API_KEY)
    check("s.seed_config creates settings.json (0600) when there is none",
          json.loads((fresh / "settings.json").read_text()) == {"skipDangerousModePermissionPrompt": True}
          and ((fresh / "settings.json").stat().st_mode & 0o777) == 0o600)


RULE = "─" * 60
# Rows as Claude Code 2.1.301 draws them (trimmed).
SCREENS = {
    "ready": ["Claude Code v2.1.301", "", RULE, "❯", RULE,
              "  ⏵⏵ bypass permissions on (shift+tab to cycle) · ← for agents"],
    "ready-typed": [RULE, "❯ /exit", RULE, "  ? for shortcuts"],
    "bypass": [RULE, "  WARNING: Claude Code running in Bypass Permissions mode", "",
               "  By proceeding, you accept all responsibility for actions taken while running in "
               "Bypass Permissions mode.", "", "  ❯ No, exit", "    Yes, I accept", "",
               "  Enter to confirm · Esc to cancel"],
    "trust": [RULE, " Accessing workspace:", "", " Quick safety check: Is this a project you created "
              "or one you trust?", "", " ❯ No, exit", "   Yes, I trust this folder", "",
              " Enter to confirm · Esc to cancel"],
    "other-dialog": [RULE, " Something to choose", "", " ❯ First option", "   Second option", "",
                     " Enter to confirm · Esc to cancel"],
    "pointer-only": ["", "  ❯ No, exit", "    Yes, go on", ""],
    "boxed-pointer": ["Pick one", "  ❯ No, exit", "    Yes, go on", RULE],
    "starting": ["Claude Code v2.1.301", "Opus 5.5 · API Usage Billing", ""],
}


def section_s_screens() -> None:
    """wait_ready's screen reading: a dialog's selection pointer is not the prompt."""
    want = {"ready": "ready", "ready-typed": "ready", "bypass": "blocked", "trust": "trust",
            "other-dialog": "dialog", "pointer-only": "starting", "boxed-pointer": "starting",
            "starting": "starting"}
    got = {name: driver.classify(rows)[0] for name, rows in SCREENS.items()}
    check("s.classify: prompt box ready, bypass warning blocked, trust, other dialogs, pointer not ready",
          got == want, str(got))
    check("s.composer_row: the ❯ under a rule, never a dialog's pointer",
          driver.composer_row(SCREENS["ready"]) == 3 and driver.composer_row(SCREENS["ready-typed"]) == 1
          and all(driver.composer_row(SCREENS[n]) is None
                  for n in ("bypass", "trust", "other-dialog", "pointer-only", "boxed-pointer")))


def _fake_gateway(d: Path, marker: str | None = None, mode: int = 0o644) -> Path:
    """A folder the guard takes for the gateway (it never runs)."""
    for rel in ("hooks/launch.sh", "hooks/e2e.sh", "src/gateway/paths.py"):
        (d / rel).parent.mkdir(parents=True, exist_ok=True)
        (d / rel).write_text("# not run\n")
    (d / ".claude-plugin").mkdir(exist_ok=True)
    (d / ".claude-plugin" / "plugin.json").write_text(json.dumps({"name": "gate", "version": "0.0.1"}))
    if marker is not None:
        (d / "e2e-root").write_text(marker)
        os.chmod(d / "e2e-root", mode)
    return d


def section_s_gateway_guard(root: Path) -> None:
    """Session refuses a gateway without a proven e2e redirection (no claude)."""
    g = root / "s" / "gw"
    fake = _fake_gateway(g / "fake-gate")
    s = driver.Session(g / "pd", plugin_dirs=[fake], start=False)
    try:
        s.start()
        check("s.Session refuses a --plugin-dir gateway without a marker", False)
    except gwe2e.NotProven as e:
        check("s.Session refuses a --plugin-dir gateway without a marker, before starting anything",
              s.api.port is None and s.pid is None and "no e2e-root marker" in str(e), str(e))
    finally:
        s.close()
    s = driver.Session(g / "pd-args", args=["--plugin-dir", str(fake)], start=False)
    try:
        s.start()
        check("s.Session refuses a gateway passed as --plugin-dir in args", False)
    except gwe2e.NotProven:
        check("s.Session refuses a gateway passed as --plugin-dir in args", s.pid is None)
    finally:
        s.close()
    cfg = g / "cfg-enabled"
    cfg.mkdir()
    (cfg / "settings.json").write_text(json.dumps({"enabledPlugins": {"gate@gateway": True}}))
    s = driver.Session(g / "en", config_dir=cfg, start=False)
    try:
        s.start()
        check("s.Session refuses a config with gate@gateway enabled and no proof", False)
    except gwe2e.NotProven as e:
        check("s.Session refuses a config with gate@gateway enabled and no proof",
              s.api.port is None and s.pid is None and "gate@gateway" in str(e), str(e))
    finally:
        s.close()
    s = driver.Session(g / "inert", config_dir=cfg, allow_inert_gateway=True, start=False)
    found = s.check_gateways()
    check("s.allow_inert_gateway=True keeps the gateway inert (GATEWAY_TEST_ROOT stays set)",
          s.gateway_mode == "inert" and [f.plugin_id for f in found] == ["gate@gateway"])
    s.close()
    s = driver.Session(g / "inert2", config_dir=cfg, allow_inert_gateway=True,
                       extra_env={"GATEWAY_TEST_ROOT": None}, start=False)
    try:
        s.start()
        check("s.allow_inert_gateway refuses an unset GATEWAY_TEST_ROOT", False)
    except safety.UnsafePath:
        check("s.allow_inert_gateway refuses an unset GATEWAY_TEST_ROOT", s.pid is None)
    finally:
        s.close()
    (cfg / "settings.json").write_text(json.dumps({"enabledPlugins": {"gate@gateway": False}}))
    s = driver.Session(g / "off", config_dir=cfg, start=False)
    check("s.a disabled gateway needs no proof", s.check_gateways() == [] and s.gateway_mode is None)
    s.close()
    spaced = g / "cfg with space ü"
    spaced.mkdir()
    rules = {"a space": str(spaced), "a non-ASCII letter": "/private/tmp/x-ü",
             "a // in the path": "/private/tmp//x", "a .. component": "/private/tmp/x/../y",
             "a folder outside the temp roots": str(HERE)}
    for what, path in rules.items():
        try:
            gwe2e.check_rules(path, "test")
            check(f"s.the e2e marker rules reject {what}", False)
        except gwe2e.NotProven:
            check(f"s.the e2e marker rules reject {what}", True)
    plain = g / "plain_dir-1.x"
    plain.mkdir()
    try:
        ok = gwe2e.check_rules(plain, "test") == Path(os.path.realpath(plain))
    except gwe2e.NotProven:
        ok = False
    check("s.the e2e marker rules accept a plain scratch path", ok or not gwe2e.spelled_ok(str(plain)),
          str(plain))
    e2e = g / "e2e-ok"
    e2e.mkdir(mode=0o700)
    for what, marker, mode in (("group-writable", f"{os.path.realpath(e2e)}\n", 0o664),
                               ("naming a spaced folder", f"{os.path.realpath(spaced)}\n", 0o644),
                               ("naming a non-private folder", f"{os.path.realpath(plain)}\n", 0o644)):
        d = _fake_gateway(g / f"gate-{len(what)}-{mode:o}", marker, mode)
        try:
            gwe2e.preflight(d)
            check(f"s.preflight refuses a marker {what}", False)
        except gwe2e.NotProven as e:
            check(f"s.preflight refuses a marker {what}", True, str(e))


SWEEP_CHILD = r"""
import os, subprocess, sys, time
tag = sys.argv[1]
# the child: its own session (as Node's detached spawn), starting a helper as it dies
child = ("trap 'sh -c \"sleep 30; true\" helper-%s & exit 0' TERM; "
         "while :; do sleep 0.1; done" % tag)
subprocess.Popen(["sh", "-c", child, "child-" + tag], start_new_session=True)
time.sleep(60)
"""


def section_s_sweep(root: Path) -> None:
    """kill_tree(match=...) finds a helper started after its listing, in a
    session of its own, by a parent that died (what a mod's spawn leaves)."""
    tag = "sweep-" + root.name
    me = lambda c: tag in c  # noqa: E731
    p = subprocess.Popen([sys.executable, "-I", "-c", SWEEP_CHILD, tag], start_new_session=True,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    t0 = time.time()
    while time.time() - t0 < 10 and not safety.descendants(p.pid):
        time.sleep(0.1)
    time.sleep(0.3)
    kids = safety.descendants(p.pid)
    sids = safety.sessions_of(kids) - {p.pid}   # the child's own session
    safety.kill_tree(p.pid, grace=1.0, match=me)
    time.sleep(0.3)
    # the helper (named by the tag) and its `sleep 30` (not named): by session id
    left = safety.session_members(sids, lambda c: True)
    check("s.kill_tree(match=) also stops a helper a dying child started in its own session",
          bool(kids) and len(sids) == 1 and not left and p.poll() is not None,
          f"{len(kids)} kids, sessions {sids}, left {left}")
    for pid in left:   # never leave them running, whatever the check said
        try:
            os.kill(pid, 9)
        except OSError:
            pass


# ---------------------------------------------------------------------------
def section_a(root: Path) -> None:
    print("a) fake API + interactive session", flush=True)
    s = driver.Session(root / "a", replies=["harness reply alpha-7"], observer=True,
                       debug_file=True, start=False)
    guard_session(s, root)
    try:
        s.start()
        check("a.config dir in the child env is the scratch one",
              safety.is_under(s.env["CLAUDE_CONFIG_DIR"], root)
              and s.env["ANTHROPIC_BASE_URL"] == s.api.url
              and s.env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] == "1"
              and s.env["DISABLE_AUTOUPDATER"] == "1"
              and safety.is_under(s.env["CHECKPOINT_GATEWAY_CONTRACT"], root)
              and "GATEWAY_TEST_ROOT" in s.env and s.gateway_mode is None
              and not any(k.startswith("ANTHROPIC_") and k not in ("ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY")
                          for k in s.env))
        try:
            s.wait_ready(90)
            ready = True
        except TimeoutError as e:
            ready = False
            print(str(e))
        check("a.prompt reached", ready, s.dump(12))
        s.submit("hello harness")
        check("a.scripted reply drawn", bool(s.wait_for(r"harness reply alpha-7", 60)), s.dump(15))
        mains = s.api.main_requests()
        check("a.main request recorded with the prompt",
              any("hello harness" in (r.get("body") or "") for r in mains), f"{len(mains)} main requests")
        check("a.no credential headers in the request log",
              all(not ({"x-api-key", "authorization"} & set(r.get("headers", {})))
                  for r in s.api.requests()))
        check("a.request log has one record per request with seq",
              [r["seq"] for r in s.api.requests()] == list(range(1, len(s.api.requests()) + 1)))
        st = s.api.state()
        check("a.reply consumed by the main loop only", st["consumed"] == 1 and st["pending"] == 0, str(st))
        s.pump(1.0)
        check("a.claude still running", s.alive())
        check("a.peer socket lives in the private runtime dir, not /tmp/cc-socks-<uid>",
              os.path.realpath(s.env.get("XDG_RUNTIME_DIR", "")) == os.path.realpath(s.runtime_dir)
              and any((s.runtime_dir / "cc-socks").glob("*.sock")),
              str(list(s.runtime_dir.rglob("*"))))
        pid = s.pid
    finally:
        s.close()
    check("a.close() killed claude", not safety.pid_alive(pid) and not s.alive())
    check("a.close() stopped the fake API", not s.api.alive())
    check("a.close() removed the runtime dir", not s.runtime_dir.exists())
    check("a.--debug-file written", s.debug_path is not None and s.debug_path.exists()
          and s.debug_path.stat().st_size > 0)
    ev = s.observer.events()
    check("a.observer plugin recorded events", sum(ev.values()) > 0, str(dict(ev.most_common(8))))
    check("a.observer saw the submitted prompt",
          bool(s.observer.find(ev="prompt.submit", contains="hello harness")),
          str(sorted(ev)[:40]))
    check("a.transcript written in the scratch config", bool(s.transcripts()))


# ---------------------------------------------------------------------------
def section_b(root: Path) -> None:
    print("b) scripted Bash tool_use under bypassPermissions", flush=True)
    cmd = "printf 'harness-made\\n' > made-by-bash.txt && echo bash-ran-ok"
    replies = [{"tool": "Bash", "input": {"command": cmd, "description": "make a file"}},
               "bash step finished"]
    s = driver.Session(root / "b", replies=replies, permission_mode="bypassPermissions", start=False)
    guard_session(s, root)
    try:
        s.start()
        s.wait_ready(90)
        s.submit("run the step")
        done = s.wait_for(r"bash step finished", 90)
        check("b.final scripted reply drawn", bool(done), s.dump(20))
        made = s.cwd / "made-by-bash.txt"
        check("b.Bash command ran in the session cwd",
              made.exists() and made.read_text() == "harness-made\n")
        mains = s.api.main_requests()
        results = [fakeapi.result_text(b) for r in mains for b in fakeapi.tool_results(r)]
        check("b.tool_result reached the fake API", any("bash-ran-ok" in t for t in results),
              f"{len(mains)} main requests")
        col, row = s.click_text("bash step finished")
        check("b.click_text finds drawn text", "bash step finished" in s.lines()[row][col:])
        s.redact("pasted words here")
        s.paste("pasted words here")
        check("b.bracketed paste lands in the prompt box",
              bool(s.wait_for(r"pasted words here", 10)) and "pasted words here" in s.composer(),
              s.dump(6))
        try:
            s.expect(r"this text never appears", timeout=0.5)
            check("b.expect raises on timeout", False)
        except TimeoutError as e:
            check("b.expect raises on timeout, with redacted values", "pasted words here" not in str(e)
                  and "<redacted>" in str(e))
        for _ in range(len("pasted words here")):
            s.key("backspace", settle=0.01)
        s.resize(100, 30)
        check("b.resize keeps the session alive", s.alive() and s.screen.columns == 100)
        hits = s.find_text("❯")
        if hits:
            s.click(hits[-1][0] + 2, hits[-1][1])
        check("b.SGR click accepted", s.alive())
    finally:
        s.close()
    # an untrusted cwd: wait_ready moves the pointer to "Yes, I trust" (Enter on
    # the default "No, exit" would quit) and reaches the prompt
    s = driver.Session(root / "b-trust", trust_cwd=False, start=False)
    guard_session(s, root)
    try:
        s.start()
        try:
            s.wait_ready(60)
            ready = True
        except TimeoutError as e:
            ready = False
            print(str(e))
        cj = json.loads((s.config_dir / ".claude.json").read_text())
        trusted = [k for k, v in cj.get("projects", {}).items() if v.get("hasTrustDialogAccepted")]
        check("b.wait_ready accepts the folder-trust dialog and reaches the prompt",
              ready and s.alive() and s.dialogs_seen == ["trust"] and s.state()[0] == "ready"
              and any(os.path.realpath(k) == os.path.realpath(s.cwd) for k in trusted),
              f"{s.dialogs_seen} {trusted}\n{s.dump(12)}")
    finally:
        s.close()


# ---------------------------------------------------------------------------
PROBE_HOOK = """#!/bin/sh
# probe hook: record the event, the plugin root and data dir Claude Code gave us,
# and the plugin state root (one line per SessionStart kept in $CHECKPOINT_HOME)
mkdir -p "$CLAUDE_PLUGIN_DATA" 2>/dev/null && echo kept > "$CLAUDE_PLUGIN_DATA/state.txt"
if [ "$1" = SessionStart ]; then
  mkdir -p "$CHECKPOINT_HOME" 2>/dev/null && echo started >> "$CHECKPOINT_HOME/probe-starts"
fi
printf '{"event":"%s","root":"%s","data":"%s","version":"%s","ck":"%s","xdg":"%s"}\\n' "$1" \\
  "$CLAUDE_PLUGIN_ROOT" "$CLAUDE_PLUGIN_DATA" \\
  "$(sed -n 's/.*"version": *"\\([^"]*\\)".*/\\1/p' "$CLAUDE_PLUGIN_ROOT/.claude-plugin/plugin.json")" \\
  "$CHECKPOINT_HOME" "$XDG_STATE_HOME" >> "$PROBE_MARK"
cat > /dev/null
exit 0
"""


def make_probe_repo(src: Path, version: str) -> None:
    (src / ".claude-plugin").mkdir(parents=True, exist_ok=True)
    pdir = src / "plugins" / "probe"
    (pdir / ".claude-plugin").mkdir(parents=True, exist_ok=True)
    (pdir / "hooks").mkdir(parents=True, exist_ok=True)
    (src / ".claude-plugin" / "marketplace.json").write_text(json.dumps({
        "name": "harness-probe", "owner": {"name": "tui harness"},
        "plugins": [{"name": "probe", "source": "./plugins/probe",
                     "description": "selftest probe plugin"}]}, indent=2))
    (pdir / ".claude-plugin" / "plugin.json").write_text(json.dumps({
        "name": "probe", "version": version, "description": "selftest probe plugin",
        "author": {"name": "tui harness"}}, indent=2))
    def hook(ev: str) -> dict:
        return {"hooks": [{"type": "command",
                           "command": f'sh "${{CLAUDE_PLUGIN_ROOT}}/hooks/mark.sh" {ev}'}]}
    (pdir / "hooks" / "hooks.json").write_text(json.dumps({"hooks": {
        "SessionStart": [hook("SessionStart")], "UserPromptSubmit": [hook("UserPromptSubmit")]}},
        indent=2))
    (pdir / "hooks" / "mark.sh").write_text(PROBE_HOOK)
    (src / ".gitignore").write_text("ignored.txt\n")
    (pdir / "ignored.txt").write_text("must not be published\n")


def marks(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def run_probe_session(root: Path, name: str, cfg: Path, mark: Path, **kw) -> bool:
    s = driver.Session(root / name, config_dir=cfg, extra_env={"PROBE_MARK": str(mark)},
                       replies=["probe session reply"], start=False, **kw)
    guard_session(s, root)
    try:
        s.start()
        s.wait_ready(90)
        s.submit("ping probe")
        ok = bool(s.wait_for(r"probe session reply", 60))
        s.pump(0.5)
        return ok
    finally:
        s.close()


def starts(ck: str) -> int:
    p = Path(ck) / "probe-starts"
    return len(p.read_text().splitlines()) if p.exists() else 0


def section_c(root: Path) -> None:
    print("c) git-source marketplace install into a scratch config", flush=True)
    base = root / "c"
    src = base / "probe-src"
    make_probe_repo(src, "0.1.0")
    genv = {"PATH": os.environ.get("PATH", ""), "HOME": str(base), "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull}
    subprocess.run(["git", "init", "-q", str(src)], env=genv, check=True)  # untracked files only
    files = install.source_files(src)
    check("c.snapshot lists untracked-not-ignored files, not ignored ones",
          "plugins/probe/hooks/mark.sh" in files and "plugins/probe/ignored.txt" not in files, str(files))
    mark = base / "mark.jsonl"
    with install.Hermetic(base / "hermetic") as h:
        assert safety.is_under(h.inst.config_dir, root)
        p = h.install_from(src, repo="harness-probe", plugin="probe")
        hist = "\n".join(str(r) for r in h.inst.history)
        check("c.marketplace add + install succeeded", all(r.ok for r in h.inst.history), hist)
        check("c.installed cache path reported", p.cache_path is not None and p.cache_path.is_dir()
              and safety.is_under(p.cache_path, h.inst.config_dir) and p.version == "0.1.0", str(p))
        check("c.cache holds the published files only",
              p.cache_path is not None and (p.cache_path / "hooks" / "mark.sh").exists()
              and not (p.cache_path / "ignored.txt").exists())
        check("c.enabled in the scratch settings", h.inst.enabled(p.id) is True)
        ok = run_probe_session(root, "c-s1", h.inst.config_dir, mark)
        check("c.session on the installed plugin answered", ok)
        m = marks(mark)
        check("c.installed plugin's hooks fired",
              {"SessionStart", "UserPromptSubmit"} <= {x["event"] for x in m}, str([x["event"] for x in m]))
        check("c.hook ran from the reported cache path",
              bool(m) and all(os.path.realpath(x["root"]) == os.path.realpath(p.cache_path) for x in m))
        check("c.CLAUDE_PLUGIN_DATA is the reported data path",
              bool(m) and all(os.path.realpath(x["data"]) == os.path.realpath(p.data_path) for x in m),
              f"{m[0]['data'] if m else None} vs {p.data_path}")
        ck = h.inst.env()["CHECKPOINT_HOME"]
        check("c.the session's plugin state root is the installation's (one per config)",
              bool(m) and all(x["ck"] == ck for x in m) and starts(ck) == 1, f"{m[:1]} vs {ck}")
        # bypass mode on a config `claude plugin install` already started (and
        # migrated): only settings.json's key suppresses the warning
        mark.unlink(missing_ok=True)
        try:
            ok, why = run_probe_session(root, "c-bypass", h.inst.config_dir, mark,
                                        permission_mode="bypassPermissions"), ""
        except TimeoutError as e:   # BlockingDialog included
            ok, why = False, str(e)
        m = marks(mark)
        sj = json.loads((h.inst.config_dir / "settings.json").read_text())
        check("c.bypassPermissions session on the installed config reaches the prompt and runs hooks",
              ok and {"SessionStart", "UserPromptSubmit"} <= {x["event"] for x in m}
              and sj.get("skipDangerousModePermissionPrompt") is True
              and sj.get("enabledPlugins", {}).get(p.id) is True, f"{sj}\n{why}")
        s = driver.Session(root / "c-nobypass", config_dir=h.inst.config_dir,
                           permission_mode="bypassPermissions", accept_bypass=False, start=False)
        guard_session(s, root)
        t0 = time.time()
        try:
            s.start()
            try:
                s.wait_ready(60)
                err = None
            except driver.BlockingDialog as e:
                err = e
            check("c.without the settings key the bypass warning shows, and wait_ready raises "
                  "BlockingDialog at once (not the prompt, not a 60 s timeout)",
                  err is not None and "Bypass Permissions" in str(err) and "No, exit" in str(err)
                  and time.time() - t0 < 30 and s.alive() and s.composer() == "",
                  s.dump(12))
        finally:
            s.close()
        # update: a new snapshot with a bumped version
        make_probe_repo(src, "0.2.0")
        p2 = h.update_from(src, repo="harness-probe", plugin="probe")
        check("c.update installed the new version", p2.version == "0.2.0" and p2.cache_path is not None
              and p2.cache_path != p.cache_path and p2.cache_path.is_dir(),
              "\n".join(str(r) for r in h.inst.history[-2:]))
        mark.unlink(missing_ok=True)
        ok = run_probe_session(root, "c-s2", h.inst.config_dir, mark)
        m = marks(mark)
        check("c.restarted session runs the updated copy",
              ok and bool(m) and all(x["version"] == "0.2.0" and os.path.realpath(x["root"]) ==
                                     os.path.realpath(p2.cache_path) for x in m), str(m[:1]))
        check("c.the restart keeps the plugin state root and what is in it",
              bool(m) and all(x["ck"] == ck and x["xdg"] == h.inst.env()["XDG_STATE_HOME"] for x in m)
              and starts(ck) == 3, f"{starts(ck)} starts; {m[:1]}")
        h.inst.disable(p.id)
        check("c.disable reported", h.inst.enabled(p.id) is False)
        h.inst.enable(p.id)
        check("c.enable reported", h.inst.enabled(p.id) is True)
        h.inst.uninstall(p.id, keep_data=True)
        check("c.uninstall --keep-data keeps the data dir",
              h.inst.record(p.id) is None and (p.data_path / "state.txt").exists())
        h.inst.install(p.id)
        h.inst.uninstall(p.id)
        check("c.uninstall removes the record and the data dir",
              h.inst.record(p.id) is None and not p.data_path.exists())
    check("c.git server stopped", h.server.proc is None)


# ---------------------------------------------------------------------------
def section_d(root: Path) -> None:
    print("d) canary scan", flush=True)
    base = root / "d"
    tree = base / "tree"
    planted = scan.Canary.new("planted")
    special = scan.Canary.new("special", special=True)
    absent = scan.Canary.new("absent")
    secret_values = [planted.value, special.value, absent.value]
    v = planted.value.encode()
    files = {
        "notes/plain.txt": b"before " + v + b" after\n",
        "enc/b64-offset1.txt": base64.b64encode(b"x" + v + b"yz"),
        "enc/b64-offset2.txt": base64.b64encode(b"xy" + v + b"z!"),
        "enc/b64url.txt": base64.urlsafe_b64encode(b"\xfb\xff" + v),
        "enc/hex.txt": b"0x" + v.hex().encode(),
        "enc/url.txt": ("q=" + quote(special.value, safe="")).encode(),
        "blob.gz": gzip.compress(b"zip " + v),
        "json/escaped.json": b'{"k": "' + "".join(f"\\u{b:04x}" for b in v).encode() + b'"}',
    }
    for rel, data in files.items():
        p = tree / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    named = tree / "names" / ("f-" + planted.value + ".txt")
    named.parent.mkdir(parents=True, exist_ok=True)
    named.write_text("nothing inside\n")
    (tree / "clean.txt").write_text("nothing secret here\n")
    rep = scan.Report()
    rep.scan_tree(tree, planted, special, absent, label="tree")
    found = {loc.split(" in ", 1)[1].split(" ")[0]: loc for loc in rep.locations(planted)}
    for rel in ["notes/plain.txt", "enc/b64-offset1.txt", "enc/b64-offset2.txt", "enc/b64url.txt",
                "enc/hex.txt", "blob.gz", "json/escaped.json"]:
        check(f"d.found planted canary in {rel}", f"tree/{rel}" in found, str(sorted(found)))
    check("d.found canary in a file name (reported masked)",
          any("(name)" in loc and "<planted>" in loc for loc in rep.locations(planted)))
    check("d.found url-encoded special canary", any("enc/url.txt" in l for l in rep.locations(special)))
    check("d.absent canary not found", not rep.locations(absent))
    check("d.clean file not reported", not any("clean.txt" in l for l in rep.locations()))
    # fake API log: send a request holding the canary through a real FakeAPI process
    with fakeapi.FakeAPI(base / "api").start() as api:
        body = json.dumps({"model": "m", "messages": [{"role": "user", "content": planted.value}],
                           "tools": [{"name": "Bash"}]}).encode()
        req = urllib.request.Request(api.url + "/v1/messages", data=body, method="POST",
                                     headers={"content-type": "application/json",
                                              "x-api-key": "should-not-be-logged"})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        opener.open(req, timeout=10).read()
        log = api.log_path
    check("d.fake API log omits the api key header", b"should-not-be-logged" not in Path(log).read_bytes())
    rep2 = scan.Report()
    rep2.scan_api_log(log, planted, absent)
    check("d.canary found in the fake API log by record",
          any("seq=1" in l and "kind=main" in l for l in rep2.locations(planted)), str(rep2.locations()))
    check("d.absent canary not in the API log", not rep2.locations(absent))
    # PTY-like bytes: the value painted one character at a time between cursor moves
    painted = b"".join(b"\x1b[1C\x1b[38;5;2m" + bytes([ch]) for ch in v)
    rep3 = scan.Report()
    rep3.scan_bytes(painted, "pty", planted, ansi=True)
    check("d.canary found in PTY bytes only after ANSI stripping",
          rep3.locations(planted) == ["planted [raw] in pty (ansi stripped)"], str(rep3.locations()))
    everything = "\n".join([rep.summary(), rep2.summary(), rep3.summary(), repr(planted), str(planted),
                            f"{planted}", str(rep.hits), str(rep.scanned), str(rep2.scanned)])
    check("d.no canary value in reports, reprs or locations",
          not any(sv in everything for sv in secret_values))
    try:
        import pickle
        pickle.dumps(planted)
        check("d.canary refuses pickling", False)
    except TypeError:
        check("d.canary refuses pickling", True)


# ---------------------------------------------------------------------------
def _post(url: str, body: dict, headers: dict | None = None) -> tuple[int, bytes]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"content-type": "application/json", **(headers or {})})
    try:
        with opener.open(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def _sse(data: bytes) -> list[dict]:
    return [json.loads(l[6:]) for l in data.decode().splitlines() if l.startswith("data: ")]


def section_e(root: Path) -> None:
    print("e) fake API protocol (no claude)", flush=True)
    main = {"model": "m", "stream": True, "messages": [{"role": "user", "content": "x"}],
            "tools": [{"name": "Bash"}, {"name": "Read"}]}
    side = {"model": "m", "messages": [{"role": "user", "content": "title?"}]}
    replies = [{"blocks": [{"type": "text", "text": "pre"},
                           {"type": "tool_use", "name": "Read", "input": {"file_path": "/x"}}]},
               {"text": "slow text here", "chunk_delay": 0.05, "delay": 0.2},
               {"error": {"status": 529, "type": "overloaded_error", "message": "busy"}}]
    for mode in ("process", "thread"):
        api = fakeapi.FakeAPI(root / f"e-{mode}", replies=replies, default_text="side-default",
                              mode=mode).start()
        try:
            code, body = _post(api.url + "/v1/messages", side)
            check(f"e.{mode}: side request gets the default text without consuming",
                  code == 200 and json.loads(body)["content"][0]["text"] == "side-default"
                  and api.state()["consumed"] == 0)
            code, body = _post(api.url + "/v1/messages?beta=true", main)
            ev = _sse(body)
            kinds = [e["type"] for e in ev]
            starts = [e["content_block"] for e in ev if e["type"] == "content_block_start"]
            check(f"e.{mode}: main request streams text + tool_use blocks",
                  kinds[0] == "message_start" and kinds[-1] == "message_stop"
                  and [b["type"] for b in starts] == ["text", "tool_use"]
                  and starts[1]["name"] == "Read" and starts[1]["id"].startswith("toolu_")
                  and any(e.get("delta", {}).get("stop_reason") == "tool_use" for e in ev), str(kinds))
            t = time.time()
            code, body = _post(api.url + "/v1/messages", main)
            text = "".join(e["delta"].get("text", "") for e in _sse(body) if e["type"] == "content_block_delta")
            check(f"e.{mode}: delay and chunk_delay stream the text in pieces",
                  text == "slow text here" and time.time() - t >= 0.3
                  and sum(1 for e in _sse(body) if e["type"] == "content_block_delta") == 2)
            code, body = _post(api.url + "/v1/messages", main)
            check(f"e.{mode}: scripted error status", code == 529 and b"overloaded_error" in body)
            code, body = _post(api.url + "/v1/messages", dict(main, stream=False))
            check(f"e.{mode}: empty queue answers main requests with the default text (JSON)",
                  code == 200 and json.loads(body)["content"][0]["text"] == "side-default")
            code, body = _post(api.url + "/v1/messages/count_tokens", main)
            check(f"e.{mode}: count_tokens answered", code == 200 and json.loads(body) == {"input_tokens": 10})
            code, body = _post(api.url + "/api/other", {"a": 1})
            check(f"e.{mode}: other POST answered with {{}}", code == 200 and json.loads(body) == {})
            api.script([{"text": "held reply", "hold": "gate1"}])
            api.push("after hold")
            import threading
            out = {}
            th = threading.Thread(target=lambda: out.update(r=_post(api.url + "/v1/messages", main)))
            th.start()
            time.sleep(0.4)
            held = th.is_alive()
            api.release("gate1")
            th.join(10)
            check(f"e.{mode}: hold waits for release", held and not th.is_alive()
                  and b"held reply" in out["r"][1])
            code, body = _post(api.url + "/v1/messages", main)
            check(f"e.{mode}: push appends to the queue", b"after hold" in body)
            recs = api.requests()
            check(f"e.{mode}: every request logged and classified",
                  [r["kind"] for r in recs] == ["side", "main", "main", "main", "main", "count_tokens",
                                                "other", "main", "main"]
                  and recs[1]["query"] == "beta=true" and recs[1]["reply"] == 0,
                  str([(r["kind"], r["reply"]) for r in recs]))
            check(f"e.{mode}: wait_main counts main requests", api.wait_main(6, timeout=1))
            check(f"e.{mode}: log is private (0600)", (os.stat(api.log_path).st_mode & 0o777) == 0o600)
        finally:
            api.stop()
        check(f"e.{mode}: stopped", not api.alive())
    strict = fakeapi.FakeAPI(root / "e-req", replies=["for bash only"], require_tool="Bash").start()
    try:
        _post(strict.url + "/v1/messages", dict(main, tools=[{"name": "Read"}], stream=False))
        code, body = _post(strict.url + "/v1/messages", dict(main, stream=False))
        check("e.require_tool: only requests offering that tool are main",
              [r["kind"] for r in strict.requests()] == ["side", "main"] and b"for bash only" in body)
    finally:
        strict.stop()


# ---------------------------------------------------------------------------
GATEWAY_SRC: Path | None = None


def find_gateway_checkout() -> Path | None:
    """The gateway repository: this one (in the gateway repo) or ../gateway
    next to it (in the checkpoint repo)."""
    here = HERE.parents[3]
    for c in (here, here.parent / "gateway"):
        try:
            mk = json.loads((c / ".claude-plugin" / "marketplace.json").read_text())
        except (OSError, ValueError):
            continue
        if (any(e.get("name") == "gate" for e in mk.get("plugins", []))
                and (c / "plugins" / "gateway" / "hooks" / "e2e.sh").is_file()):
            return c
    return None


def _bumped(version: str) -> str:
    parts = (version.split("-")[0].split(".") + ["0", "0", "0"])[:3]
    nums = [int(x) if x.isdigit() else 0 for x in parts]
    return f"{nums[0]}.{nums[1]}.{nums[2] + 1000}"


def section_g(root: Path) -> None:
    print("g) the gateway: the e2e install route and the session guard", flush=True)
    src = GATEWAY_SRC
    if src is None:
        print("  skipped: no gateway checkout found (pass --gateway DIR)", flush=True)
        return
    base = root / "g"
    base.mkdir()
    if not gwe2e.spelled_ok(os.path.realpath(base)):
        check("g.the selftest root follows the e2e marker rules (use a plain --tmp)", False, str(base))
        return
    # Sessions build the gateway's pixi env in the background (killed on close):
    # keep pixi's cache in the scratch root.
    env = {"PIXI_CACHE_DIR": str(base / "pixi-cache")}
    # 1. a config path the marker rules reject: refused before anything is published
    with install.Hermetic(base / "hs", extra_env=env, config_dir=base / "hs" / "Claude cfg ü") as hs:
        try:
            hs.install_gateway_e2e(src)
            check("g.install_gateway_e2e refuses a config dir with a space and a non-ASCII letter", False)
        except gwe2e.NotProven as e:
            check("g.install_gateway_e2e refuses a config dir with a space and a non-ASCII letter, "
                  "before publishing anything",
                  not (hs.server.repos / "gateway.git").exists() and not hs.inst.history
                  and "marker rules" in str(e), str(e))
    with install.Hermetic(base / "h", extra_env=env) as h:
        # 2. installed the plain way (no marker): the Session refuses it
        plain = install.Installation(base / "plain", extra_env=env)
        served = h.publish(src, "gateway")
        plain.marketplace_add(served.url)
        pp = plain.install("gate@gateway")
        check("g.plain install (no marker) succeeded", pp.cache_path is not None
              and not (pp.cache_path / gwe2e.MARKER).exists(),
              "\n".join(str(r) for r in plain.history))
        s = driver.Session(base / "g-plain", config_dir=plain.config_dir, start=False)
        try:
            s.start()
            check("g.Session refuses a plainly installed gate@gateway", False)
        except gwe2e.NotProven as e:
            check("g.Session refuses a plainly installed gate@gateway before starting anything",
                  s.api.port is None and s.pid is None and "gate@gateway" in str(e)
                  and "without an e2e proof" in str(e), str(e))
        finally:
            s.close()
        # 3. the e2e route, here under Debian's default umask 002 (the install runs
        # under 022, so the installed marker isn't group-writable and is honoured)
        old_umask = os.umask(0o002)
        try:
            gi = h.install_gateway_e2e(src)
        finally:
            os.umask(old_umask)
        cp = gi.plugin.cache_path
        check("g.install_gateway_e2e under umask 002: the installed marker isn't group- or world-writable",
              cp is not None and (os.stat(cp / gwe2e.MARKER).st_mode & 0o022) == 0,
              oct(os.stat(cp / gwe2e.MARKER).st_mode) if cp is not None else "no install path")
        pf = gwe2e.proof_path(h.inst.config_dir)
        check("g.install_gateway_e2e: the installed copy carries the marker, 0700 e2e folders",
              cp is not None and (cp / gwe2e.MARKER).read_text().split() == [str(gi.root), str(gi.run)]
              and (os.stat(gi.root).st_mode & 0o777) == 0o700 and (os.stat(gi.run).st_mode & 0o777) == 0o700
              and safety.is_under(gi.root, root) and safety.is_under(cp, h.inst.config_dir), str(gi.proof))
        locs = gi.proof.locations
        check("g.pre-flight: sh and Python read the marker; every gateway location is inside it",
              gi.proof.sh == [str(gi.root), str(gi.run)]
              and all(v.startswith(str(gi.root) + "/") or v.startswith(str(gi.run)) for v in locs.values())
              and locs["home"] == str(gi.root / "home" / ".config" / "gateway")
              and not any(safety.overlaps_protected(v) for v in locs.values()), str(locs))
        check("g.the proof is recorded in the config (0600) and drops GATEWAY_TEST_ROOT",
              pf.exists() and (pf.stat().st_mode & 0o777) == 0o600
              and gi.plugin.id in gwe2e.read_proofs(h.inst.config_dir)
              and gi.env()["GATEWAY_TEST_ROOT"] is None
              and gi.env()["CHECKPOINT_GATEWAY_ENV"] == str(gi.gateway_home / "env.sh"))
        # 4. a missing proof or an ignored marker: refused
        saved = pf.read_bytes()
        pf.unlink()
        s = driver.Session(base / "g-noproof", config_dir=h.inst.config_dir, start=False)
        try:
            s.start()
            check("g.Session refuses the e2e install once its proof is gone", False)
        except gwe2e.NotProven:
            check("g.Session refuses the e2e install once its proof is gone", s.pid is None)
        finally:
            s.close()
        pf.write_bytes(saved)
        os.chmod(pf, 0o600)
        os.chmod(cp / gwe2e.MARKER, 0o664)   # group-writable: the gateway ignores it
        s = driver.Session(base / "g-ignored", config_dir=h.inst.config_dir, start=False)
        try:
            s.start()
            check("g.Session refuses when the installed marker would be ignored", False)
        except gwe2e.NotProven as e:
            check("g.Session refuses when the installed marker would be ignored", s.pid is None, str(e))
        finally:
            s.close()
            os.chmod(cp / gwe2e.MARKER, 0o644)
        # 5. a live session on the proven install
        s = driver.Session(base / "g-s1", config_dir=h.inst.config_dir, extra_env=env,
                           replies=["gateway session reply"], debug_file=True, start=False)
        guard_session(s, root)
        try:
            s.start()
            check("g.the session runs the gateway redirected: GATEWAY_TEST_ROOT unset, checkpoint "
                  "pointed at the e2e gateway home",
                  s.gateway_mode == "e2e" and "GATEWAY_TEST_ROOT" not in s.env
                  and s.env["CHECKPOINT_GATEWAY_ENV"] == str(gi.gateway_home / "env.sh")
                  and s.env["CHECKPOINT_GATEWAY_CONTRACT"] == str(gi.gateway_home / "run" / "contract.json"),
                  str({k: s.env.get(k) for k in safety.STATE_VARS}))
            s.wait_ready(90)
            # Before its env is built, the gateway's SessionStart (launch.sh) writes its
            # stand-ins into its data folder and its launcher into its home, and says so.
            made = [gi.root / "data" / "bin" / "ssh", gi.gateway_home / "gate"]
            t0 = time.time()
            while time.time() - t0 < 30 and not (all(p.exists() for p in made)
                                                 and "says: gateway:" in s.all_text()):
                s.pump(0.3)
            check("g.the gateway's SessionStart ran redirected: stand-ins and launcher in the e2e "
                  "root, its message on screen",
                  all(p.exists() for p in made) and "says: gateway:" in s.all_text(), s.dump(15))
            s.submit("hello gateway")
            check("g.a prompt passes the gateway's hooks", bool(s.wait_for(r"gateway session reply", 60)),
                  s.dump(15))
            s.pump(1.0)
        finally:
            s.close()
        dbg = s.debug_path.read_text(errors="replace") if s.debug_path and s.debug_path.exists() else ""
        check("g.no gateway hook or MCP refused for GATEWAY_TEST_ROOT (debug log)",
              bool(dbg) and "GATEWAY_TEST_ROOT is set" not in dbg)
        # 6. a native update (new version) re-proven; the old proof no longer fits
        old_proof = pf.read_bytes()
        v = json.loads((src / "plugins" / "gateway" / ".claude-plugin" / "plugin.json").read_text())["version"]
        gi2 = h.update_gateway_e2e(src, version=_bumped(v))
        s = driver.Session(base / "g-upd", config_dir=h.inst.config_dir, start=False)
        found = s.check_gateways()
        s.close()
        check("g.update_gateway_e2e: the new version is installed, proven and accepted",
              gi2.plugin.version == _bumped(v) and gi2.plugin.cache_path != cp
              and (gi2.plugin.cache_path / gwe2e.MARKER).exists() and s.gateway_mode == "e2e"
              and [str(f.path) for f in found] == [str(gi2.plugin.cache_path)],
              "\n".join(str(r) for r in h.inst.history[-2:]))
        pf.write_bytes(old_proof)
        s = driver.Session(base / "g-stale", config_dir=h.inst.config_dir, start=False)
        try:
            s.check_gateways()
            check("g.a proof of the previous version is refused", False)
        except gwe2e.NotProven as e:
            check("g.a proof of the previous version is refused", "not the proven" in str(e), str(e))
        finally:
            s.close()
        run_dir = gi.run
    check("g.Hermetic.close removed the gateway's run dir", not run_dir.exists())


# ---------------------------------------------------------------------------
def section_t(root: Path) -> None:
    """Opt-in (--only t; mitmproxy comes through `pixi exec`): a session with
    telemetry on behind the record-only proxy; its first-party requests are
    recorded (decrypted) and answered locally."""
    print("t) record-only telemetry proxy", flush=True)
    from tui import proxy
    with proxy.RecordProxy(root / "t" / "proxy") as px:
        s = driver.Session(root / "t" / "s", replies=["proxied reply t-1"], extra_env=px.env(),
                           start=False)
        guard_session(s, root)
        try:
            s.start()
            check("t.session env: proxies set, telemetry on, NO_PROXY keeps the fake API direct",
                  s.env.get("HTTPS_PROXY") == px.url and "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC" not in s.env
                  and "127.0.0.1" in s.env.get("NO_PROXY", ""))
            s.wait_ready(120)
            s.submit("hello through the proxy")
            check("t.reply drawn (the model calls went to the fake API)",
                  bool(s.wait_for(r"proxied reply t-1", 90)), s.dump(12))
            s.pump(5)
        finally:
            s.close()
        reqs = px.requests()
        hosts = sorted({r["host"] for r in reqs})
        check("t.first-party requests were recorded and answered by the proxy", len(reqs) > 0, str(hosts))
        check("t.no model request went through the proxy (the fake API took them)",
              not any(r["path"].startswith("/v1/messages") for r in reqs), str(hosts))
        check("t.each recorded request has its body on disk",
              all((px.bodies_dir / f"{r['n']:05d}.dec").exists() for r in reqs))


def leftover_processes(root: Path) -> list[str]:
    out = subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True).stdout
    me = str(os.getpid())
    keys = {str(root), os.path.realpath(root)}
    return [l.strip() for l in out.splitlines()
            if any(k in l for k in keys) and l.strip().split()[0] != me and "ps -axo" not in l]


def claude_tmp_leftovers(root: Path) -> list[str]:
    """Entries Claude Code would leave in /tmp/claude-<uid>/ for this run
    (none expected: the harness points CLAUDE_CODE_TMPDIR into the root)."""
    base = Path(f"/tmp/claude-{os.getuid()}")
    try:
        return [e.name for e in base.iterdir() if root.name in e.name]
    except OSError:
        return []


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tmp", default=tempfile.gettempdir(), help="base for the scratch root")
    ap.add_argument("--keep", action="store_true", help="keep the scratch root for inspection")
    ap.add_argument("--only", default="s,a,b,c,d,e,g", help="sections to run (default s,a,b,c,d,e,g)")
    ap.add_argument("--gateway", default=None,
                    help="gateway checkout for section g (default: this repo or ../gateway)")
    a = ap.parse_args(argv)
    global GATEWAY_SRC
    GATEWAY_SRC = Path(a.gateway).resolve() if a.gateway else find_gateway_checkout()
    before = safety.real_settings_fingerprint()
    root = Path(tempfile.mkdtemp(prefix="tui-selftest-", dir=a.tmp))
    safety.check_scratch(root, "selftest root")
    print(f"tui harness selftest: root {root}", flush=True)
    t0 = time.time()
    sections = {"s": section_s, "a": section_a, "b": section_b, "c": section_c, "d": section_d,
                "e": section_e, "g": section_g, "t": section_t}
    try:
        for key in a.only.split(","):
            t = time.time()
            try:
                sections[key.strip()](root)
            except Exception:
                check(f"{key}.section completed without error", False, traceback.format_exc())
            print(f"   ({time.time() - t:.1f}s)", flush=True)
    finally:
        driver._close_all()
        time.sleep(0.5)
        left = leftover_processes(root)
        check("no harness process left running", not left, "\n".join(left))
        stray = claude_tmp_leftovers(root)
        check("nothing left in /tmp/claude-<uid> for this run", not stray, "\n".join(stray))
        if not a.keep:
            shutil.rmtree(root, ignore_errors=True)
            check("scratch root removed", not root.exists())
        after = safety.real_settings_fingerprint()
        check("real ~/.config/claude settings and plugin registry unchanged", before == after,
              f"{before} != {after}")
    failed = [r for r in RESULTS if not r[1]]
    print(f"\n{len(RESULTS) - len(failed)} passed, {len(failed)} failed in {time.time() - t0:.1f}s")
    for name, _, detail in failed:
        print(f"--- FAIL {name}\n{detail}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
