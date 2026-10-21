#!/usr/bin/env python3
"""Brief 11.1, 14.9, 14.12 and 14.13 in the real TUI: the gateway's native
dialogs (PLAN-v4 phase 3), with telemetry on.

    pixi exec --spec python=3.12 --spec pyte python tests/acceptance_dialogs.py \\
        --tmp DIR [--keep] [--pixi-cache DIR]

The gateway is installed the normal way through the TUI harness's e2e route
(tests/tui: a git-source marketplace in a scratch Claude config, the e2e
marker that redirects every gateway location into a scratch root), the
session runs against the harness's fake Messages API with --debug-file, the
observer plugin (a nosy third-party mod) and Claude Code's own telemetry ON
behind the record-only proxy (tests/tui/proxy.py: mitmproxy answers every
first-party request itself, never forwards). The gateway's pixi env is built
before any session starts, outside the proxy (which answers every download
itself: a build inside the proxied session would fail from a cold cache).
Recording shims named osascript, zenity, kdialog, open, xdg-open and the
terminal programs come first on every session's PATH, so a run through PATH
is logged however briefly it lasts; a process watcher also samples the
process table the whole time (best effort: it misses short-lived processes),
and test_ux_dialog's grep covers calls by absolute path.

Scripted, with synthetic canaries generated here (never printed, never in a
prompt; the fake sudo's password and the fake clipboard are canaries too):

  sudo     gate check localhost: the sudo-method choice, then the private
           field. Typing before the click goes to the prompt box (the guard
           holds it back); a wrong canary typed (click, type, Enter) reopens
           the dialog with "That didn't work"; a partial value typed, then
           the focus moved away (Escape): the click that gives the field the
           keys again starts it over, so the partial value is never sealed;
           the right canary is verified by the fake sudo and stored.
  clip     a new api-key account: the consent dialog (Approve), then "Paste
           from clipboard": gated reads the clipboard through its test
           override (a program returning a canary) and stores it.
  queue    two gate checks at once: one dialog at a time, the other queued
           and named; Cancel on one, Decline on the other.
  kill     gated is killed (SIGKILL) while a token dialog is open: it comes
           back, the dialog reopens with a new key, and a canary typed then
           is stored.
  reload   /reload-plugins while a consent dialog waits: the mod reloads,
           the request stays pending in gated, the dialog reopens and is
           answered.
  mainscr  the main-screen layout (no clicks reach plugins): no field; keys
           typed into the prompt box while the secret dialog waits are held
           back (the guard points to Paste and the fullscreen view), and
           /gate-dialog still passes; Paste from the keyboard.
  print    claude -p on the same config: a gate check that needs a secret
           asks nothing and says credential entry is unavailable there.

Broker receipt is proven by hash: the scratch vault (the e2e root's, its key
unwrapped) is decrypted here and the stored values' sha256 compared with the
canaries'. Then every canary is searched for (raw, base64, hex, URL, JSON
escapes, UTF-16, gzip members; ANSI stripped for the PTY) in the transcripts,
history and everything else in the scratch config, the debug log, the fake
API's request log, every proxied telemetry payload, the observer's records,
the gateway's plugin data (gated's log, events, audit log), its home, its run
dir, the process table samples and the PTY output; only pass/fail and
locations are recorded. Prints one line per check and a JSON summary to
--tmp/acceptance-dialogs.json; exits non-zero on any failure.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN = HERE.parent
REPO = PLUGIN.parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
from tui import driver, gwe2e, install, proxy, safety, scan  # noqa: E402
from tui.fakeapi import FakeAPI  # noqa: E402

RESULTS: list[dict] = []
NOTES: list[str] = []
BANNED = {"osascript", "zenity", "kdialog", "open", "xdg-open", "gnome-terminal", "konsole",
          "x-terminal-emulator", "xterm", "Terminal", "iTerm2"}
GUARD = "click the gateway dialog's field first"
MAIN_GUARD = "a gateway dialog waits for a secret, so typing here is held back"
FIELD = "click here, then type"
PREBUILD_TIMEOUT = 1800       # seconds for the env build from a cold pixi cache (~400 MB)


def check(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append({"check": name, "ok": bool(ok), **({"detail": detail[:1500]} if detail and not ok else {})})
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok or not detail else f"\n       {detail[:1500]}"),
          flush=True)
    return bool(ok)


def note(text: str) -> None:
    NOTES.append(text)
    print(f"  note {text}", flush=True)


def sha(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


# ---------------------------------------------------------------------------
# The process watcher (14.12: nothing opens outside Claude Code; argv samples)
# ---------------------------------------------------------------------------


class Watcher(threading.Thread):
    """Best effort: `ps` every 0.25 s sees a process only if it lives across a
    sample (a probe caught 5 of 20 processes of 80 ms each); `open URL` and
    xdg-open usually exit sooner. The PATH shims (path_shims) are the
    stronger evidence for programs run by name."""

    def __init__(self, canaries: list[scan.Canary]):
        super().__init__(daemon=True)
        self.canaries = canaries
        self.stop = threading.Event()
        self.samples = 0
        self.banned: list[str] = []          # "pid basename" of a banned program seen
        self.argv_hits: set[str] = set()     # canary ids found in some process's argv
        self.roots: set[int] = set()

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                out = subprocess.run(["ps", "-A", "-ww", "-o", "pid=,ppid=,command="],
                                     capture_output=True, text=True, timeout=5).stdout
            except (OSError, subprocess.TimeoutExpired):
                out = ""
            self.samples += 1
            for line in out.splitlines():
                parts = line.strip().split(None, 2)
                if len(parts) < 3 or not parts[0].isdigit():
                    continue
                cmd = parts[2]
                base = os.path.basename(cmd.split()[0]) if cmd.split() else ""
                if base in BANNED and "ps -A" not in cmd:
                    self.banned.append(f"{parts[0]} {base}")
                for c in self.canaries:
                    if c.value in cmd:
                        self.argv_hits.add(c.id)
            self.stop.wait(0.25)


def path_shims(root: Path) -> tuple[Path, Path]:
    """A folder of recording shims, one per banned program name, for the
    front of every session's PATH: each appends its name (never its
    arguments, which could hold a URL or a value) to the log and exits 1, so
    nothing opens. Returns (folder, log)."""
    d = root / "shims"
    d.mkdir(mode=0o700)
    log = root / "shims.log"
    log.write_text("")
    for name in sorted(BANNED):
        f = d / name
        f.write_text(f"#!/bin/sh\nprintf '%s\\n' '{name}' >> '{log}'\nexit 1\n")
        os.chmod(f, 0o755)
    return d, log


def shimmed_path(shims: Path) -> str:
    return f"{shims}:{os.environ.get('PATH', '/usr/bin:/bin')}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def wait(s: driver.Session, cond, timeout: float, step: float = 0.3) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if cond():
                return True
        except Exception:  # noqa: BLE001 - a screen read in flight
            pass
        s.pump(step)
    return bool(cond())


def screen(s: driver.Session) -> str:
    return s.text()


def bullets(s: driver.Session) -> int:
    return screen(s).count("•")


def focus_field(s: driver.Session, tries: int = 5) -> bool:
    """Click the private field until it takes keys: a probe key must add a
    bullet (then it is deleted again). A key that went to the prompt box
    instead is held back by the guard."""
    for _ in range(tries):
        try:
            s.click_text(FIELD)
        except LookupError:
            s.pump(1.0)
            continue
        s.pump(0.4)
        n = bullets(s)
        s.send("x")
        if wait(s, lambda: bullets(s) > n, 2.0, 0.1):
            s.key("backspace")
            wait(s, lambda: bullets(s) == n, 2.0, 0.1)
            return True
    return False


def press(s: driver.Session, label: str, done=None, tries: int = 5, settle: float = 2.0) -> bool:
    """Click a pane's button (or field) by its text until `done()` holds
    (default: the text is gone). The layout can move between finding the text
    and the click (a turn ending moves a docked pane inline), so the text is
    found again before each try."""
    done = done or (lambda: label not in screen(s))
    for _ in range(tries):
        if label not in screen(s):
            return bool(done())
        try:
            s.click_text(label)
        except LookupError:
            pass
        if wait(s, done, settle):
            return True
    return bool(done())


def env_python() -> str:
    r = subprocess.run(["pixi", "run", "--locked", "--manifest-path", str(PLUGIN / "pixi.toml"), "python",
                        "-c", "import sys; print(sys.executable)"], capture_output=True, text=True)
    return r.stdout.strip()


def prebuild_env(root: Path, h, gi, env: dict) -> tuple[bool, str]:
    """Build the installed e2e copy's pixi env before any session starts,
    outside the record-only proxy (it answers every request itself, so a
    download through it fails: pixi reported "invalid peer certificate:
    UnknownIssuer" from a cold cache, and the run then sat out its wait for
    the mod). The copy's own `launch.sh ensure-env` builds what the sessions
    use (its marker puts the env in the e2e root); GATEWAY_TEST_ROOT stays set
    (hermetic_env), so launch.sh resolves no home. (ok, detail)."""
    plugin = Path(gi.plugin.cache_path)
    for d in ("b-home", "b-tmp"):
        (root / d).mkdir(exist_ok=True)
    benv = safety.hermetic_env(config_dir=h.inst.config_dir, home=root / "b-home",
                               tmpdir=root / "b-tmp", extra=env)
    for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
        benv.pop(k, None)
    t0 = time.time()
    try:
        r = subprocess.run(["/bin/sh", str(plugin / "hooks" / "launch.sh"), "ensure-env"], env=benv,
                           cwd=root / "b-tmp", capture_output=True, text=True,
                           timeout=PREBUILD_TIMEOUT)
        rc, err = r.returncode, r.stderr[-400:]
    except subprocess.TimeoutExpired:
        rc, err = None, f"no answer in {PREBUILD_TIMEOUT} s"
    ready = sorted(gi.root.glob("data/envs/*/.ready"))
    logs = sorted(gi.root.glob("data/envs/*/install.log"))
    tail = logs[-1].read_text(errors="replace")[-600:] if logs else ""
    return bool(ready) and rc == 0, (f"launch.sh ensure-env: rc={rc} in {time.time() - t0:.0f} s; "
                                     f"{err}\ninstall.log: {tail}")


def age_binary(root: Path) -> str | None:
    for p in sorted(root.glob("data/envs/*/.pixi/envs/default/bin/age")):
        return str(p)
    return None


def read_vault(gi, age: str) -> dict:
    home = gi.gateway_home
    r = subprocess.run([age, "-d", "-i", str(home / "private" / "key.txt"), str(home / "private" / "vault.age")],
                       capture_output=True, timeout=30)
    if r.returncode != 0:
        raise RuntimeError("the scratch vault couldn't be decrypted")
    return json.loads(r.stdout)


def gated_pid(gi) -> int | None:
    try:
        return int(json.loads((gi.gateway_home / "run" / "contract.json").read_text())["pid"])
    except (OSError, ValueError, KeyError):
        return None


FORM = '[hosts.localhost]\nsudo = true\n'
ACCOUNTS = "".join(f'\n[accounts.{n}]\nkind = "api-key"\nsites = ["api.{n}.example"]\n'
                   for n in ("clip", "qa", "qb", "killme", "reload", "headless", "mainscr"))


def bash(cmd: str, desc: str) -> dict:
    return {"tool": "Bash", "input": {"command": cmd, "description": desc, "timeout": 300000}}


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tmp", default=tempfile.gettempdir())
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--pixi-cache", default=None)
    a = ap.parse_args(argv)
    before = safety.real_settings_fingerprint()
    root = Path(tempfile.mkdtemp(prefix="acc-dialogs-", dir=a.tmp))
    safety.check_scratch(root, "acceptance root")
    print(f"acceptance (native dialogs): root {root}", flush=True)
    env = {"PIXI_CACHE_DIR": a.pixi_cache or str(root / "pixi-cache")}
    PY = env_python()
    right, wrong, partial, guard_c = (scan.Canary.new("sudo-right"), scan.Canary.new("sudo-wrong"),
                                      scan.Canary.new("focus-partial"), scan.Canary.new("guard-typed"))
    clip, killv = scan.Canary.new("clipboard"), scan.Canary.new("token-after-kill")
    main_guard = scan.Canary.new("main-guard-typed")
    canaries = [right, wrong, partial, guard_c, clip, killv, main_guard]
    shims, shim_log = path_shims(root)
    env["PATH"] = shimmed_path(shims)
    watcher = Watcher(canaries)
    watcher.start()
    t0 = time.time()
    try:
        run(root, env, PY, canaries, watcher)
    finally:
        watcher.stop.set()
        watcher.join(5)
        driver._close_all()
    ran = [ln for ln in shim_log.read_text().splitlines() if ln.strip()]
    check("no osascript, zenity, kdialog, open, xdg-open or terminal program was run by name in any "
          "session (recording shims first on PATH)", not ran, ", ".join(ran[:10]))
    check("best effort: no such program was seen in the process table either "
          f"({watcher.samples} samples, every 0.25 s; misses short-lived processes)", not watcher.banned,
          ", ".join(watcher.banned[:10]))
    check("no canary appeared in any process's argv (process-table samples)", not watcher.argv_hits,
          ", ".join(sorted(watcher.argv_hits)))
    time.sleep(0.5)
    left = [ln for ln in subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True,
                                        text=True).stdout.splitlines()
            if str(root) in ln and "ps -axo" not in ln]
    check("no process left naming the scratch root", not left, "\n".join(left))
    after = safety.real_settings_fingerprint()
    check("real ~/.config/claude settings and plugin registry unchanged", before == after)
    failed = [r for r in RESULTS if not r["ok"]]
    summary = {"when": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "seconds": round(time.time() - t0),
               "claude": subprocess.run([driver.find_claude(), "--version"], capture_output=True,
                                        text=True).stdout.strip(),
               "passed": len(RESULTS) - len(failed), "failed": len(failed), "checks": RESULTS,
               "notes": NOTES}
    out = Path(a.tmp) / "acceptance-dialogs.json"
    out.write_text(json.dumps(summary, indent=1))
    print(f"\n{summary['passed']} passed, {summary['failed']} failed in {summary['seconds']} s; {out}")
    if not a.keep:
        shutil.rmtree(root, ignore_errors=True)
    return 1 if failed else 0


def run(root: Path, env: dict, PY: str, canaries: list[scan.Canary], watcher: Watcher) -> None:
    right, wrong, partial, guard_c, clip, killv, main_guard = canaries
    build_env = {k: v for k, v in env.items() if k != "PATH"}
    with install.Hermetic(root / "h", extra_env=build_env) as h, proxy.RecordProxy(root / "proxy") as px:
        gi = h.install_gateway_e2e(REPO)
        check("the gateway is installed through the e2e route (marker proven)", gi.proof is not None)
        print("prebuild: the gateway's pixi env, outside the record-only proxy", flush=True)
        ok, detail = prebuild_env(root, h, gi, build_env)
        if not check("the gateway's pixi env is built before any session (outside the record-only proxy, "
                     "which answers downloads itself)", ok, detail):
            return
        note(f"prebuild: {detail.splitlines()[0]}")
        # the fakes the gateway's e2e knobs point at (their files hold canaries: positive controls,
        # outside every scanned folder)
        fs = gi.root / "fake-sudo"
        fs.mkdir()
        (fs / "config.json").write_text(json.dumps({"password": right.value, "nopasswd": False,
                                                     "timeout": 300, "sudoers_dir": None}))
        os.chmod(fs / "config.json", 0o600)
        (fs / "log.jsonl").write_text("")
        (fs / "sudo").write_text(f"#!/bin/sh\nexec '{PY}' -I -S '{PLUGIN}/tests/fakes/fake_sudo.py' "
                                 f"--state '{fs}' \"$@\"\n")
        os.chmod(fs / "sudo", 0o755)
        fc = gi.root / "fake-clip"
        fc.mkdir()
        (fc / "value").write_text(clip.value)
        os.chmod(fc / "value", 0o600)
        (fc / "paste").write_text(f"#!/bin/sh\nexec /bin/cat '{fc / 'value'}'\n")
        os.chmod(fc / "paste", 0o755)
        e2e = {"tools": {"sudo": str(fs / "sudo")}, "clipboard": str(fc / "paste"), "popup_wait": 8}
        (gi.root / "e2e.json").write_text(json.dumps(e2e))
        os.chmod(gi.root / "e2e.json", 0o600)
        gi.gateway_home.mkdir(parents=True, exist_ok=True)
        (gi.gateway_home / "gateway.toml").write_text(FORM)
        replies = [bash("gate check localhost", "set up sudo"), "sudo step answered",
                   bash("gate check clip", "add the clip account"), "clip step answered",
                   bash("gate check qa & gate check qb; wait", "two accounts at once"), "queue step answered",
                   bash("gate check killme", "add killme"), "kill step answered",
                   bash("gate check reload", "add reload"), "reload step answered"]
        # the fullscreen layout: the terminal reports clicks there, so the private field
        # can be focused (with telemetry on, 2.1.301 starts on the main screen unless told)
        s = driver.Session(root / "s1", config_dir=h.inst.config_dir,
                           extra_env={**env, **px.env(), "CLAUDE_CODE_NO_FLICKER": "1"},
                           replies=replies, debug_file=True, observer=True, cols=170, rows=50,
                           permission_mode="bypassPermissions", start=False)
        s.redact(*[c.value for c in canaries])
        try:
            s.start()
            check("telemetry is on behind the record-only proxy (no CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC)",
                  "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC" not in s.env and s.env.get("HTTPS_PROXY") == px.url)
            check("the recording shims come first on the session's PATH",
                  s.env.get("PATH", "").split(":")[0] == env["PATH"].split(":")[0]
                  and (Path(env["PATH"].split(":")[0]) / "open").is_file(), s.env.get("PATH", "")[:300])
            s.wait_ready(180)
            reg = gi.run / "gated-sessions.json"
            # the env is built already: the mod starts gated and registers at once
            ok = wait(s, lambda: any(x.get("via") == "ui" for x in json.loads(reg.read_text())["sessions"]), 180, 1.0)
            check("the mod registered this session on gated's UI plane (terminal surface)", ok)
            watcher.roots.add(s.pid)
            step_sudo(s, gi, right, wrong, partial, guard_c)
            # the accounts arrive as an edit of the form (Claude's, in real use): new
            # accounts are widenings, so each gate check asks for the user's OK first
            (gi.gateway_home / "gateway.toml").write_text(FORM + ACCOUNTS)
            step_clip(s, gi)
            step_queue(s)
            step_kill(s, gi, killv)
            step_reload(s, gi)
            s.pump(2.0)
        finally:
            s.close()
        age = age_binary(gi.root)
        if age is None:
            check("the gateway's age binary is found to read the scratch vault", False)
            data = {}
        else:
            data = read_vault(gi, age)
        user = next(iter(((data.get("localhost") or {}).get("sudo") or {}).keys()), None)
        stored = ((data.get("localhost") or {}).get("sudo") or {}).get(user or "", {}).get("password", "")
        check("broker receipt (typed): the stored sudo password's sha256 is the right canary's",
              bool(stored) and sha(stored) == sha(right.value))
        tok = lambda n: (((data.get("accounts") or {}).get(n) or {}).get("token") or {}).get("value", "")
        check("broker receipt (clipboard): the clip account's stored token's sha256 is the clipboard "
              "canary's", sha(tok("clip")) == sha(clip.value))
        check("broker receipt (after gated was killed): killme's token sha256 is the canary typed "
              "after the restart", sha(tok("killme")) == sha(killv.value))
        check("nothing stored for the cancelled and declined requests (qa, qb, reload)",
              not tok("qa") and not tok("qb") and not tok("reload"))
        s2 = step_main_screen(root, h, gi, env, px, main_guard)
        if age is not None:
            data = read_vault(gi, age)
        check("broker receipt (main screen, keyboard + Paste): mainscr's token sha256 is the clipboard "
              "canary's", sha(tok("mainscr")) == sha(clip.value))
        flog = [json.loads(ln) for ln in (fs / "log.jsonl").read_text().splitlines() if ln.strip()]
        checks = [e for e in flog if e.get("how") == "S"]
        check("the fake sudo saw exactly two password checks: the wrong canary refused, then the "
              "right one (the partial value dropped on the focus change was never submitted)",
              [e.get("code") for e in checks] == [1, 0], json.dumps([e.get("code") for e in checks]))
        step_print(root, h, gi, env)
        scans(root, [x for x in (s, s2) if x is not None], gi, px, canaries, h)


# ---------------------------------------------------------------------------
# The steps
# ---------------------------------------------------------------------------


def step_sudo(s, gi, right, wrong, partial, guard_c) -> None:
    print("sudo: choice, guard, wrong value, focus change, right value", flush=True)
    s.submit("please set up sudo on this machine")
    ok = wait(s, lambda: "Store the sudo password" in screen(s), 120)
    check("sudo: the sudo-method choice opens as a native pane (no OS dialog)", ok, s.dump(30))
    if not ok:
        return
    press(s, "Store the sudo password", lambda: FIELD in screen(s))
    ok = wait(s, lambda: FIELD in screen(s) and "sudo password for localhost" in screen(s), 60)
    check("sudo: the secret dialog names host, account and what is asked, with Paste and Cancel",
          ok and "@localhost)" in screen(s) and "Paste from clipboard" in screen(s)
          and "Cancel" in screen(s), s.dump(30))
    # typing before the click: the guard holds it back
    s.type(guard_c.value)
    s.pump(0.6)
    # a held-back key is painted for a frame (FEASIBILITY-v4 P1); on a loaded
    # machine that frame can outlast the first look, so look again for 3 s
    left = s.composer().strip()
    check("guard: keys typed before the click don't stay in the prompt box",
          wait(s, lambda: s.composer().strip() == "", 3, 0.2),
          f"{len(left)} character(s) at first look, now {len(s.composer().strip())}; a prefix of "
          f"the typed canary: {bool(left) and guard_c.value.startswith(left)}, its tail: "
          f"{bool(left) and guard_c.value.endswith(left)}")
    check("guard: the status line says to click the field first", GUARD in s.all_text(), s.dump(8))
    # a wrong value, typed into the field after the click
    check("field: a click gives the private field the keys", focus_field(s), s.dump(20))
    s.type(wrong.value)
    s.pump(0.4)
    check("field: only bullets are drawn while typing", "•" * 8 in screen(s) and wrong.value not in screen(s))
    s.key("enter")
    ok = wait(s, lambda: "That didn't work" in screen(s), 60)
    check("validation: a wrong value reopens the dialog with \"That didn't work\" (try 2 of 3)",
          ok and "try 2 of 3" in screen(s), s.dump(25))
    # focus change: a partial value, then the keys leave the field (Escape);
    # the click that gives it the keys again starts it over
    focus_field(s)
    s.type(partial.value[:16])
    s.pump(0.4)
    typed = bullets(s)
    s.key("escape")
    s.pump(1.0)
    try:
        s.click_text(FIELD)
    except LookupError:
        pass
    dropped = wait(s, lambda: bullets(s) == 0, 5, 0.1)
    check("focus change: after the keys left the field (Escape), the click that gives them back starts it "
          "over (no bullets left)", typed >= 16 and dropped, f"bullets before {typed}\n" + s.dump(20))
    focus_field(s)
    s.type(right.value)
    s.key("enter")
    ok = wait(s, lambda: "sudo password for localhost: supplied" in s.all_text()
              or FIELD not in screen(s), 90)
    check("sudo: the right value is verified (fake sudo) and the dialog closes", ok, s.dump(25))
    wait(s, lambda: "sudo step answered" in s.all_text(), 60)


def step_clip(s, gi) -> None:
    print("clip: consent, then Paste from clipboard", flush=True)
    s.submit("add the clip account")
    ok = wait(s, lambda: "Approve" in screen(s) and "clip" in screen(s), 120)
    check("consent: the widening is shown with Approve and Decline", ok and "Decline" in screen(s), s.dump(25))
    if not ok:
        return
    press(s, "Approve", lambda: "api key for clip" in screen(s))
    ok = wait(s, lambda: "Paste from clipboard" in screen(s) and "api key for clip" in screen(s), 60)
    check("clip: the api key dialog opens after the OK", ok, s.dump(25))
    if not ok:
        return
    press(s, "Paste from clipboard")
    ok = wait(s, lambda: "Paste from clipboard" not in screen(s), 60)
    check("clipboard: gated read the clipboard itself (override) and the dialog closed", ok, s.dump(25))
    wait(s, lambda: "clip step answered" in s.all_text(), 60)


def step_queue(s) -> None:
    print("queue: two requests, one dialog at a time", flush=True)
    s.submit("add qa and qb")
    ok = wait(s, lambda: "Also waiting:" in screen(s), 120)
    check("queue: one dialog at a time; the other request is shown by identity (Also waiting: ...)", ok,
          s.dump(25))
    sc = screen(s)
    m = re.search(r"Also waiting: consent for (q[ab])\b", sc)
    waiting = m.group(1) if m else None
    current = "qb" if waiting == "qa" else "qa"
    check("queue: the waiting request names its account (the other one than the dialog shown)",
          waiting is not None and f"changes for {current}" in sc, s.dump(15))
    press(s, "Approve", lambda: "Also waiting:" not in screen(s) or "Decline" not in screen(s)
          or "api key for" in screen(s))           # the first account's OK
    ok = wait(s, lambda: "Cancel" in screen(s) and ("api key for qa" in screen(s) or "api key for qb" in screen(s)
                                                   or "rights for" in screen(s)), 60)
    # answer whatever comes until nothing waits: Cancel a secret, Decline a consent
    for _ in range(4):
        sc = screen(s)
        if "api key for" in sc and "Cancel" in sc:
            press(s, "Cancel", settle=3.0)
        elif "Decline" in sc:
            press(s, "Decline", settle=3.0)
        else:
            break
        s.pump(1.5)
    ok = wait(s, lambda: "Also waiting:" not in screen(s) and "Decline" not in screen(s)
              and FIELD not in screen(s), 60)
    check("queue: Cancel and Decline end both requests", ok, s.dump(20))
    wait(s, lambda: "queue step answered" in s.all_text(), 60)


def step_kill(s, gi, killv) -> None:
    print("kill: gated killed mid-dialog", flush=True)
    s.submit("add killme")
    ok = wait(s, lambda: "Approve" in screen(s) and "killme" in screen(s), 120)
    if ok:
        press(s, "Approve", lambda: "api key for killme" in screen(s))
    ok = wait(s, lambda: "api key for killme" in screen(s) and FIELD in screen(s), 60)
    check("kill: the token dialog is open before the kill", ok, s.dump(20))
    if not ok:
        return
    pid = gated_pid(gi)
    check("kill: gated's pid is known (contract.json)", pid is not None)
    if pid:
        os.kill(pid, signal.SIGKILL)
    back = wait(s, lambda: (gated_pid(gi) not in (None, pid)) and FIELD in screen(s), 60, 0.5)
    check("kill: gated comes back and the dialog is shown again", back, s.dump(20))
    s.pump(2.0)
    focus_field(s)
    s.type(killv.value)
    s.key("enter")
    ok = wait(s, lambda: "api key for killme: supplied" in s.all_text() or FIELD not in screen(s), 60)
    check("kill: a value typed after the restart is taken (sealed to the new key)", ok, s.dump(20))
    wait(s, lambda: "kill step answered" in s.all_text(), 60)


def step_reload(s, gi) -> None:
    print("reload: /reload-plugins while a consent dialog waits", flush=True)
    s.submit("add reload")
    ok = wait(s, lambda: "Approve" in screen(s) and "reload" in screen(s), 120)
    check("reload: the consent dialog is open", ok, s.dump(20))
    if not ok:
        return
    wait(s, lambda: "reload step answered" in s.all_text(), 60)    # the turn ends (the dialog stays)
    s.submit("/reload-plugins")
    s.pump(5.0)
    ok = wait(s, lambda: "Approve" in screen(s) and "reload" in screen(s), 90)
    check("reload: after /reload-plugins the request is still pending in gated and the dialog reopens",
          ok, s.dump(25))
    if ok:
        press(s, "Approve", lambda: "api key for reload" in screen(s))
        ok = wait(s, lambda: "api key for reload" in screen(s), 60)
        if ok:
            press(s, "Cancel", lambda: "api key for reload" not in screen(s))
        ok2 = wait(s, lambda: "api key for reload" not in screen(s), 30)
        check("reload: the reopened dialog is answered (Approve, then Cancel)", ok and ok2, s.dump(20))


def step_main_screen(root: Path, h, gi, env: dict, px, main_guard):
    """The main-screen layout (CLAUDE_CODE_NO_FLICKER=0, tmux's default): the
    terminal reports no clicks, so the field isn't drawn; the dialog says how
    to type privately and offers Paste, reachable from the keyboard. Keys
    typed into the prompt box meanwhile (the reflex at a password prompt)
    are held back; /gate-dialog still passes."""
    print("main screen: no field, Paste from the keyboard", flush=True)
    s = driver.Session(root / "s2", config_dir=h.inst.config_dir,
                       extra_env={**env, **px.env(), "CLAUDE_CODE_NO_FLICKER": "0"},
                       replies=[bash("gate check mainscr", "add mainscr"), "main screen answered"],
                       debug_file=True, observer=True, cols=170, rows=50,
                       permission_mode="bypassPermissions", start=False)
    try:
        s.start()
        s.wait_ready(180)
        reg = gi.run / "gated-sessions.json"
        wait(s, lambda: sum(1 for x in json.loads(reg.read_text())["sessions"] if x.get("via") == "ui") >= 1, 120, 1.0)
        s.submit("add the mainscr account")
        ok = wait(s, lambda: "Approve" in screen(s) and "mainscr" in screen(s), 120)
        check("main screen: the consent dialog is drawn inline", ok, s.dump(25))
        wait(s, lambda: "main screen answered" in s.all_text(), 60)
        s.submit("/gate-dialog")                    # the pane takes the keyboard (asked)
        s.pump(1.5)
        s.send("y")                                 # Approve's key
        ok = wait(s, lambda: "api key for mainscr" in screen(s), 30)
        check("main screen: the consent dialog answers its key (y = Approve) once the pane holds the "
              "keyboard (/gate-dialog)", ok, s.dump(25))
        if not ok:
            return s
        check("main screen: the secret dialog draws no field and says how to type privately "
              "(fullscreen) or paste", "CLAUDE_CODE_NO_FLICKER=1" in screen(s) and FIELD not in screen(s),
              s.dump(25))
        s.redact(main_guard.value)
        s.type(main_guard.value)
        s.pump(0.6)
        check("main screen guard: keys typed into the prompt box while the secret dialog waits don't "
              "stay there", wait(s, lambda: s.composer().strip() == "", 3, 0.2), repr(len(s.composer())))
        check("main screen guard: the status line says typing is held back and points to Paste",
              MAIN_GUARD in s.all_text(), s.dump(8))
        s.submit("/gate-dialog")                    # passes the guard (a gateway command)
        s.pump(1.5)
        s.key("tab")
        s.pump(0.5)
        s.key("enter")
        ok = wait(s, lambda: "api key for mainscr" not in screen(s), 30)
        check("main screen: Paste from clipboard pressed from the keyboard (Tab, Enter) ends the dialog",
              ok, s.dump(25))
        s.pump(1.0)
    finally:
        s.close()
    return s


def step_print(root: Path, h, gi, env: dict) -> None:
    """claude -p: no dialog can open; the gateway says so and asks nothing."""
    print("print: claude -p", flush=True)
    found = gwe2e.session_gateways(h.inst.config_dir, root / "p-work", [])
    for f in found:
        gwe2e.verify(f, h.inst.config_dir)
    api = FakeAPI(root / "p-api", replies=[bash("gate check headless", "headless account"), "headless done"])
    api.start()
    try:
        for d in ("p-work", "p-tmp", "p-home"):
            (root / d).mkdir(exist_ok=True)
        rt = safety.short_runtime_dir()
        penv = safety.hermetic_env(config_dir=h.inst.config_dir, home=root / "p-home",
                                   tmpdir=root / "p-tmp", base_url=api.url, runtime_dir=rt,
                                   extra={**env, **gi.env()})
        try:
            r = subprocess.run([driver.find_claude(), "-p", "set up the headless account",
                                "--permission-mode", "bypassPermissions"],
                               cwd=root / "p-work", env=penv, capture_output=True, text=True, timeout=300)
        finally:
            shutil.rmtree(rt, ignore_errors=True)
        mains = api.main_requests()
        text = json.dumps([m.get("body") for m in mains])
        check("print: claude -p ran its scripted gate check", r.returncode == 0 and len(mains) >= 2,
              r.stderr[-400:])
        check("print: the tool result says credential entry is unavailable in claude -p, nothing asked",
              "claude -p or the Agent SDK" in text and "nothing was asked" in text, text[-800:])
    finally:
        api.stop()


def scans(root: Path, sessions, gi, px, canaries, h) -> None:
    print("scans: every canary everywhere it must not be", flush=True)
    right, wrong, partial, guard_c, clip, killv, main_guard = canaries
    secret_values = [right, wrong, partial, clip, killv]
    s = sessions[0]
    places = {
        "the scratch Claude config (transcripts, history, plugin data, caches)": h.inst.config_dir,
        "the gateway's plugin data (gated log, events, audit log)": gi.root / "data",
        "the gateway's home (form, encrypted vault, pending, sessions)": gi.gateway_home,
        "the gateway's run dir (dialog file, sessions)": gi.run,
        "the observer plugin's records (a nosy third-party mod)": s.observer.root if s.observer else None,
        "the main-screen session's observer records": sessions[1].observer.root
        if len(sessions) > 1 and sessions[1].observer else None,
        "the proxied first-party telemetry payloads": px.root,
    }
    for what, where in places.items():
        if where is None or not Path(where).exists():
            check(f"scan: {what} exists to be scanned", False)
            continue
        rep = scan.Report()
        rep.scan_tree(where, *secret_values)
        check(f"scan: no typed, pasted or wrong canary in {what}", rep.clean(), rep.summary())
    for i, x in enumerate(sessions):
        name = "the fullscreen session" if i == 0 else "the main-screen session"
        rep = scan.Report()
        if x.debug_path and x.debug_path.exists():
            rep.scan_tree(x.debug_path.parent, *secret_values)
            check(f"scan: no canary in {name}'s --debug-file log and session folder", rep.clean(), rep.summary())
        rep = scan.Report()
        rep.scan_api_log(x.api.log_path, *canaries)
        check(f"scan: no canary (the guard's included) in any request {name} made to the fake Messages API",
              rep.clean(), rep.summary())
        rep = scan.Report()
        rep.scan_bytes(bytes(x.raw), "pty", *secret_values, ansi=True)
        check(f"scan: no typed, pasted or wrong canary in {name}'s PTY output (bullets only)",
              rep.clean(), rep.summary())
    n = len(px.requests())
    check(f"telemetry: first-party requests were captured before encryption ({n} recorded by the proxy)",
          n > 0)
    hosts = sorted({r["host"] for r in px.requests()})
    note(f"proxied first-party hosts: {', '.join(hosts)}")
    # the guard's canary: typed into the prompt box before the click (documented exposure)
    rep = scan.Report()
    rep.scan_tree(h.inst.config_dir, guard_c)
    rep.scan_api_log(s.api.log_path, guard_c)
    rep.scan_tree(px.root, guard_c)
    rep.scan_tree(gi.root / "data", guard_c)
    check("guard: keys typed before the click reach no transcript, history, model request, telemetry "
          "or gateway file", rep.clean(), rep.summary())
    if len(sessions) > 1:
        rep = scan.Report()
        rep.scan_tree(h.inst.config_dir, main_guard)
        rep.scan_api_log(sessions[1].api.log_path, main_guard)
        rep.scan_tree(px.root, main_guard)
        rep.scan_tree(gi.root / "data", main_guard)
        check("main screen guard: keys typed into the prompt box while the dialog waited reach no "
              "transcript, history, model request, telemetry or gateway file", rep.clean(), rep.summary())
    pty_rep = scan.Report()
    pty_rep.scan_bytes(bytes(s.raw), "pty", guard_c, ansi=True)
    obs = [r for r in (s.observer.records() if s.observer else []) if r.get("ev") == "prompt.edit"]
    note("guard (documented limit, FEASIBILITY-v4 P1): keys typed into the prompt box before the click "
         f"are painted for a frame ({'found' if not pty_rep.clean() else 'not found as a whole'} in the "
         f"PTY output) and reach every plugin's prompt.edit hook one edit at a time ({len(obs)} "
         "prompt.edit records in the observer)")
    note("unobservable here: the desktop app's Client relay (needs a manual check), Anthropic-side "
         "processing of anything sent outside the proxy settings (none was seen), memory of the "
         "Claude Code process (a JS string can't be wiped)")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
