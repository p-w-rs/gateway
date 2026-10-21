#!/usr/bin/env python3
"""Brief 9 and 14.7 in the real TUI: gateway terminals and jobs (PLAN-v4 phase 5).

    pixi exec --spec python=3.12 --spec pyte python tests/acceptance_terminals.py \\
        --tmp DIR [--keep] [--pixi-cache DIR] [--no-proxy]

The gateway is installed the normal way through the TUI harness's e2e route
(tests/tui: a git-source marketplace in a scratch Claude config, the e2e
marker that keeps every gateway location in a scratch root); sessions run
against the harness's fake Messages API with --debug-file, the observer
plugin and (unless --no-proxy) Claude Code's telemetry on behind the
record-only proxy. The gateway's pixi env (with tmux) is built before any
session. "The model" is scripted one step at a time: each step pushes one
tool call to the fake API (the terminal id and the seq it quotes come from
the previous step's tool result, read from the request log), submits a
prompt, and reads the tool's result back.

Sections, in one fullscreen session (CLAUDE_CODE_NO_FLICKER=1: clicks reach
the pane's Client), then a restart, then a main-screen session:

  open      terminal_open: the bounded structured screen (seq, lines, cursor,
            alternate screen, title, owner, truncated); /gate-terminal ID
            shows it in a pane
  fullscr   a full-screen program (less from the system): alternate_screen,
            the pane draws it; q leaves it
  prompt    an input prompt (read -p): seen in a read, answered by the agent
  resize    terminal_resize, and the pane's own size (the TUI resized): the
            terminal follows
  signals   ^C through the agent's terminal_signal, and ^C from the pane
            (a click into it, then Ctrl-] c)
  takeover  the agent's input queued (delay_ms) when the user clicks into the
            pane: the queued write fails ("input taken by the user; re-read
            the screen"); the user types in the same shell (cd, export)
  handback  Hand back: the agent's old seq is refused (stale); after a read it
            types again: the same shell pid, the user's cwd and variable kept
  sudo      sudo typed in the terminal: the stand-in hands it to sudo (the
            e2e fake, which asks on its tty with echo off, as sudo does);
            gated opens the credential dialog; a canary typed into its
            private field reaches that tty only; the agent sees
            "[credential supplied]"
  jobs      job_start, job_status, job_tail (bounded, scrubbed)
  askright  a script the agent runs in the terminal (sh rights.sh: a sudo
            and an ssh it starts itself; the approval hook sees only the sh
            line): with localhost's sudo true its sudo works (the fake's
            cached timestamp); a new host approved in the consent dialog (gate
            check askhost with ssh true; the e2e fake ssh-keyscan gives its
            key, its address only answers with an ssh banner, the key-install
            choice is cancelled), then narrowed to ssh = "ask": the script's
            ssh is refused with the pane's wording (no connection made) while
            its true sudo still runs; localhost's sudo narrowed to "ask":
            refused the same way, sudo never runs; both refusals audited
  restart   Claude Code exits and a new session starts on the same config:
            terminal_list still has the terminal (tmux and gated outlived the
            session), the same shell answers
  mainscr   the main screen (no clicks reach plugins): the pane says so and
            offers a line field; a line typed there reaches the terminal

Then the canary is searched for everywhere (transcripts, history, the debug
log, the fake API's requests, proxied telemetry, the observer's records, the
gateway's data, home and run dir, PTY output, process-table samples).
Prints one line per check and a JSON summary to
--tmp/acceptance-terminals.json; exits non-zero on any failure.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import socket
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
from tui import driver, install, proxy, safety, scan  # noqa: E402
from tui.fakeapi import result_text, tool_results  # noqa: E402

RESULTS: list[dict] = []
STATE: dict = {}
NOTES: list[str] = []
SHOWN: list[dict] = []               # the agent tools' bounded results, for the report
PREBUILD_TIMEOUT = 1800
FIELD = "click here, then type"
TAKEN = "input taken by the user; re-read the screen"
GW = "mcp__plugin_gate_gw__"


def check(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append({"check": name, "ok": bool(ok), **({"detail": detail[:1500]} if detail and not ok else {})})
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok or not detail else f"\n       {detail[:1500]}"),
          flush=True)
    return bool(ok)


def note(text: str) -> None:
    NOTES.append(text)
    print(f"  note {text}", flush=True)


def wait(s: driver.Session, cond, timeout: float, step: float = 0.3) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if cond():
                return True
        except Exception:  # noqa: BLE001 - a screen read in flight
            pass
        s.pump(step)
    try:
        return bool(cond())
    except Exception:  # noqa: BLE001
        return False


def screen(s: driver.Session) -> str:
    return s.text()


class Watcher(threading.Thread):
    """Process-table samples: the canary in no argv; every tmux on the private socket."""

    def __init__(self, canary: scan.Canary):
        super().__init__(daemon=True)
        self.canary = canary
        self.stop = threading.Event()
        self.samples = 0
        self.argv_hit = False
        self.tmux_cmds: set[str] = set()

    def run(self) -> None:
        while not self.stop.is_set():
            try:
                out = subprocess.run(["ps", "-A", "-ww", "-o", "command="], capture_output=True,
                                     text=True, timeout=5).stdout
            except (OSError, subprocess.TimeoutExpired):
                out = ""
            self.samples += 1
            for cmd in out.splitlines():
                if self.canary.value in cmd:
                    self.argv_hit = True
                first = cmd.split()[0] if cmd.split() else ""
                if os.path.basename(first) == "tmux":
                    self.tmux_cmds.add(cmd[:300])
            self.stop.wait(0.25)


# ---------------------------------------------------------------------------
# One scripted agent step
# ---------------------------------------------------------------------------


def focus_prompt(s: driver.Session) -> None:
    """Give the keys back to the prompt box after the person used the pane
    (its Client holds them after a click; a pressed button keeps the pane's
    focus ring): a click on the prompt row (the bottom-most ❯)."""
    hits = s.find_text("❯")
    if hits:
        x, y = hits[-1]
        s.click(x + 2, y)
        s.pump(0.4)


class Agent:
    def __init__(self, s: driver.Session):
        self.s = s
        self.steps = 0
        self.pane_focus = False        # the person used the pane since the last prompt

    def _prompt(self, text: str) -> None:
        if self.pane_focus:
            focus_prompt(self.s)
            self.pane_focus = False
        self.s.submit(text)

    def tool(self, name: str, args: dict, timeout: float = 90, wait_done: bool = True) -> dict | None:
        """Push one tool call and a closing text, submit a prompt, and return
        the tool's result (its JSON text, parsed) from the next request."""
        s = self.s
        self.steps += 1
        n0 = len(s.api.main_requests())
        done = f"step {self.steps} done"
        s.api.push({"tool": GW + name, "input": args}, done)
        self._prompt(f"step {self.steps}: {name}")
        if not wait(s, lambda: len(s.api.main_requests()) >= n0 + 2, timeout, 0.3):
            return None
        rec = s.api.main_requests()[n0 + 1]
        trs = tool_results(rec)
        if not trs:
            return None
        text = result_text(trs[-1])
        if wait_done:
            wait(s, lambda: done in s.all_text(), 30)
        i = text.find("{")
        try:
            out = json.loads(text[i:]) if i >= 0 else {"raw": text}
        except ValueError:
            out = {"raw": text}
        out["_is_error"] = bool(trs[-1].get("is_error"))
        return out

    def turn(self, calls: list[tuple[str, dict, float]], timeout: float = 120) -> list[dict | None]:
        """Several tool calls in one turn (each reply after `delay` seconds):
        the results, in order."""
        s = self.s
        self.steps += 1
        n0 = len(s.api.main_requests())
        done = f"step {self.steps} done"
        s.api.push(*[{"tool": GW + n, "input": a, **({"delay": d} if d else {})} for n, a, d in calls], done)
        self._prompt(f"step {self.steps}: {len(calls)} calls")
        if not wait(s, lambda: len(s.api.main_requests()) >= n0 + len(calls) + 1, timeout, 0.3):
            return [None] * len(calls)
        out: list[dict | None] = []
        for i in range(len(calls)):
            trs = tool_results(s.api.main_requests()[n0 + i + 1])
            text = result_text(trs[-1]) if trs else ""
            j = text.find("{")
            try:
                out.append(json.loads(text[j:]) if j >= 0 else {"raw": text})
            except ValueError:
                out.append({"raw": text})
        return out

    def start_async(self, name: str, args: dict) -> tuple[int, str]:
        s = self.s
        self.steps += 1
        n0 = len(s.api.main_requests())
        done = f"step {self.steps} done"
        s.api.push({"tool": GW + name, "input": args}, done)
        self._prompt(f"step {self.steps}: {name}")
        return n0, done

    def finish_async(self, n0: int, done: str, timeout: float = 90) -> dict | None:
        s = self.s
        if not wait(s, lambda: len(s.api.main_requests()) >= n0 + 2, timeout, 0.3):
            return None
        text = result_text(tool_results(s.api.main_requests()[n0 + 1])[-1])
        wait(s, lambda: done in s.all_text(), 30)
        i = text.find("{")
        try:
            return json.loads(text[i:]) if i >= 0 else {"raw": text}
        except ValueError:
            return {"raw": text}

    def start_bash(self, command: str, desc: str) -> tuple[int, str]:
        """Push one Bash call (not a gw tool) and a closing text, submit a
        prompt; finish_bash reads its result."""
        s = self.s
        self.steps += 1
        n0 = len(s.api.main_requests())
        done = f"step {self.steps} done"
        s.api.push({"tool": "Bash", "input": {"command": command, "description": desc,
                                              "timeout": 300000}}, done)
        self._prompt(f"step {self.steps}: Bash")
        return n0, done

    def finish_bash(self, n0: int, done: str, timeout: float = 150) -> str | None:
        s = self.s
        if not wait(s, lambda: len(s.api.main_requests()) >= n0 + 2, timeout, 0.3):
            return None
        trs = tool_results(s.api.main_requests()[n0 + 1])
        wait(s, lambda: done in s.all_text(), 30)
        return result_text(trs[-1]) if trs else None


def show(label: str, r: dict | None, keep: tuple[str, ...]) -> None:
    if r is None:
        return
    SHOWN.append({"step": label, **{k: r[k] for k in keep if k in r}})


def lines_of(r: dict | None) -> list[str]:
    return list((r or {}).get("lines") or [])


def has_line(r: dict | None, pred) -> bool:
    return any(pred(ln) for ln in lines_of(r))


# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------


def env_python() -> str:
    r = subprocess.run(["pixi", "run", "--locked", "--manifest-path", str(PLUGIN / "pixi.toml"), "python",
                        "-c", "import sys; print(sys.executable)"], capture_output=True, text=True)
    return r.stdout.strip()


def prebuild_env(root: Path, h, gi, env: dict) -> tuple[bool, str]:
    plugin = Path(gi.plugin.cache_path)
    for d in ("b-home", "b-tmp"):
        (root / d).mkdir(exist_ok=True)
    benv = safety.hermetic_env(config_dir=h.inst.config_dir, home=root / "b-home",
                               tmpdir=root / "b-tmp", extra={**env, **gi.env()})
    for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy", "ALL_PROXY", "all_proxy"):
        benv.pop(k, None)
    t0 = time.time()
    try:
        r = subprocess.run(["/bin/sh", str(plugin / "hooks" / "launch.sh"), "ensure-env"], env=benv,
                           cwd=root / "b-tmp", capture_output=True, text=True, timeout=PREBUILD_TIMEOUT)
        rc, err = r.returncode, r.stderr[-400:]
    except subprocess.TimeoutExpired:
        rc, err = None, f"no answer in {PREBUILD_TIMEOUT} s"
    ready = sorted(gi.root.glob("data/envs/*/.ready"))
    tmux = sorted(gi.root.glob("data/envs/*/.pixi/envs/default/bin/tmux"))
    return bool(ready) and bool(tmux) and rc == 0, f"launch.sh ensure-env: rc={rc} in {time.time() - t0:.0f} s; tmux {'in' if tmux else 'NOT in'} the env; {err}"


def gated_pid(gi) -> int | None:
    try:
        return int(json.loads((gi.gateway_home / "run" / "contract.json").read_text())["pid"])
    except (OSError, ValueError, KeyError):
        return None


def focus_field(s: driver.Session, tries: int = 5) -> bool:
    for _ in range(tries):
        try:
            s.click_text(FIELD)
        except LookupError:
            s.pump(1.0)
            continue
        s.pump(0.4)
        n = screen(s).count("•")
        s.send("x")
        if wait(s, lambda: screen(s).count("•") > n, 2.0, 0.1):
            s.key("backspace")
            wait(s, lambda: screen(s).count("•") == n, 2.0, 0.1)
            return True
    return False


def click_screen(s: driver.Session, tid: str) -> bool:
    """Click into the terminal pane's screen (the Client region below its
    header and mode lines): the click is the takeover. The header's text is
    unique to the pane ("terminal t_..."); the transcript shows the id but
    never after the word terminal."""
    hits = s.find_text(f"terminal {tid}")
    if not hits:
        return False
    x, y = hits[-1]
    s.click(x + 2, y + 4)            # below the header, owner and mode lines: the screen
    s.pump(0.6)
    return True


def press(s: driver.Session, label: str, done=None, tries: int = 5, settle: float = 2.0) -> bool:
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


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tmp", default=tempfile.gettempdir())
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--pixi-cache", default=None)
    ap.add_argument("--no-proxy", action="store_true")
    a = ap.parse_args(argv)
    before = safety.real_settings_fingerprint()
    root = Path(tempfile.mkdtemp(prefix="acc-term-", dir=a.tmp))
    safety.check_scratch(root, "acceptance root")
    print(f"acceptance (terminals and jobs): root {root}", flush=True)
    env = {"PIXI_CACHE_DIR": a.pixi_cache or str(root / "pixi-cache")}
    canary = scan.Canary.new("sudo-pw")
    watcher = Watcher(canary)
    watcher.start()
    t0 = time.time()
    try:
        run(root, env, canary, watcher, not a.no_proxy)
    finally:
        watcher.stop.set()
        watcher.join(5)
        driver._close_all()
    check("no canary appeared in any process's argv (process-table samples, "
          f"{watcher.samples} of them)", not watcher.argv_hit)
    mine = [c for c in watcher.tmux_cmds if STATE.get("tmux_sock", "\0") in c]
    default = [c for c in watcher.tmux_cmds if " -S " not in f" {c} "]
    check("the gateway's tmux ran on its private socket in the scratch run dir, and no tmux process "
          "seen used a default (the user's) server", bool(mine) and not default, "\n".join(default[:5]))
    time.sleep(0.5)
    left = [ln for ln in subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True,
                                        text=True).stdout.splitlines()
            if str(root) in ln and "ps -axo" not in ln]
    if left:
        # what outlived the run (gated stops its tmux when the harness removes the run dir)
        note(f"{len(left)} process(es) still named the scratch root at the end; stopped: "
             + "; ".join(ln.strip()[:80] for ln in left[:3]))
        for ln in left:
            with contextlib.suppress(Exception):
                os.kill(int(ln.split()[0]), 15)
        time.sleep(1.0)
        left = [ln for ln in subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True,
                                            text=True).stdout.splitlines()
                if str(root) in ln and "ps -axo" not in ln]
    check("no process left naming the scratch root (after stopping the e2e gated and its tmux)",
          not left, "\n".join(left))
    after = safety.real_settings_fingerprint()
    check("real ~/.config/claude settings and plugin registry unchanged", before == after)
    failed = [r for r in RESULTS if not r["ok"]]
    summary = {"when": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "seconds": round(time.time() - t0),
               "claude": subprocess.run([driver.find_claude(), "--version"], capture_output=True,
                                        text=True).stdout.strip(),
               "passed": len(RESULTS) - len(failed), "failed": len(failed), "checks": RESULTS,
               "notes": NOTES, "tool_results": SHOWN}
    out = Path(a.tmp) / "acceptance-terminals.json"
    out.write_text(json.dumps(summary, indent=1))
    print(f"\n{summary['passed']} passed, {summary['failed']} failed in {summary['seconds']} s; {out}")
    if not a.keep:
        shutil.rmtree(root, ignore_errors=True)
    return 1 if failed else 0


def run(root: Path, env: dict, canary: scan.Canary, watcher: Watcher, use_proxy: bool) -> None:
    PY = env_python()
    with contextlib.ExitStack() as stack:
        h = stack.enter_context(install.Hermetic(root / "h", extra_env=env))
        px = stack.enter_context(proxy.RecordProxy(root / "proxy")) if use_proxy else None
        gi = h.install_gateway_e2e(REPO)
        check("the gateway is installed through the e2e route (marker proven)", gi.proof is not None)
        STATE["tmux_sock"] = f"-S {gi.run}/tmux.sock"
        print("prebuild: the gateway's pixi env (bash, tmux), outside the record-only proxy", flush=True)
        ok, detail = prebuild_env(root, h, gi, env)
        if not check("the gateway's pixi env, with tmux, is built before any session", ok, detail):
            return
        note(detail.splitlines()[0])
        # the e2e fake sudo: asks on its tty with echo off (as sudo does); its password is the canary
        fs = gi.root / "fake-sudo"
        fs.mkdir()
        # its cached timestamp (after the sudo step's password) lasts through the askright section
        (fs / "config.json").write_text(json.dumps({"password": canary.value, "nopasswd": False,
                                                    "timeout": 900, "sudoers_dir": None}))
        os.chmod(fs / "config.json", 0o600)
        (fs / "log.jsonl").write_text("")
        (fs / "sudo").write_text(f"#!/bin/sh\nexec '{PY}' -I -S '{PLUGIN}/tests/fakes/fake_sudo.py' "
                                 f"--state '{fs}' \"$@\"\n")
        os.chmod(fs / "sudo", 0o755)
        state0: dict = {}
        keyscan = setup_ask_rights(root, gi, state0, stack)
        (gi.root / "e2e.json").write_text(json.dumps({"tools": {"sudo": str(fs / "sudo"),
                                                                 "ssh-keyscan": keyscan}}))
        os.chmod(gi.root / "e2e.json", 0o600)
        pages = root / "pages.txt"
        pages.write_text("".join(f"page line {i}\n" for i in range(400)))
        extra = {**env, "CLAUDE_CODE_NO_FLICKER": "1", **(px.env() if px else {})}
        s = driver.Session(root / "s1", config_dir=h.inst.config_dir, extra_env=extra,
                           debug_file=True, observer=True, cols=170, rows=56,
                           permission_mode="bypassPermissions", start=False)
        s.redact(canary.value)
        sessions = [s]
        state: dict = dict(state0)
        try:
            s.start()
            s.wait_ready(180)
            reg = gi.run / "gated-sessions.json"
            ok = wait(s, lambda: any(x.get("via") == "ui" for x in json.loads(reg.read_text())["sessions"]),
                      180, 1.0)
            check("the mod registered this session on gated's UI plane", ok)
            ag = Agent(s)
            steps(s, ag, gi, pages, canary, fs, state)
        finally:
            s.close()
        if state.get("tid"):
            s2 = step_restart(root, h, gi, extra, state, canary)
            if s2 is not None:
                sessions.append(s2)
            s3 = step_main_screen(root, h, gi, {**env, **(px.env() if px else {})}, state, canary)
            if s3 is not None:
                sessions.append(s3)
        scans(root, sessions, gi, px, canary, h)
        # stop the e2e gated (its terminals keep it alive on purpose)
        pid = gated_pid(gi)
        if pid:
            with contextlib.suppress(OSError):
                os.kill(pid, 15)


def steps(s, ag: Agent, gi, pages: Path, canary, fs: Path, state: dict) -> None:
    print("open: terminal_open, then /gate-terminal", flush=True)
    r = ag.tool("terminal_open", {"cols": 110, "rows": 24})
    ok = r is not None and str(r.get("id", "")).startswith("t_")
    check("terminal_open returns a bounded structured screen (id, seq, lines, cursor, alternate_screen, "
          "title, owner, truncated)", ok and all(k in r for k in ("seq", "lines", "cursor", "alternate_screen",
                                                                 "title", "owner", "truncated")),
          json.dumps(r)[:600])
    if not ok:
        return
    show("terminal_open", r, ("id", "state", "owner", "seq", "cols", "rows", "cursor", "alternate_screen",
                              "truncated", "lines"))
    tid = r["id"]
    state["tid"] = tid
    r = ag.tool("terminal_send", {"id": tid, "seq": r["seq"], "text": 'echo "PID""0=$$ START"', "enter": True})
    pid0 = next((ln.split("=")[1].split()[0] for ln in lines_of(r) if ln.startswith("PID0=")), None)
    state["pid0"] = pid0
    check("terminal_send returns the screen after the input (the shell ran it)", pid0 is not None,
          json.dumps(r)[:500])
    s.submit(f"/gate-terminal {tid}")
    ok = wait(s, lambda: f"terminal {tid}" in screen(s) and "PID0=" in screen(s), 30)
    check("/gate-terminal ID opens the pane: header, the screen gated captured", ok, s.dump(20))
    check("the pane says which typing mode is active (fullscreen: click into the screen)",
          "click into the screen" in s.all_text(), s.dump(10))

    print("fullscr: less from the system", flush=True)
    r = ag.tool("terminal_read", {"id": tid})
    r = ag.tool("terminal_send", {"id": tid, "seq": r["seq"], "text": f"/usr/bin/less '{pages}'", "enter": True})
    time.sleep(0.5)
    r = ag.tool("terminal_read", {"id": tid})
    check("a full-screen program: alternate_screen is true and the lines are its screen",
          bool(r) and r.get("alternate_screen") is True and has_line(r, lambda ln: ln.startswith("page line")),
          json.dumps(r)[:500])
    show("terminal_read (less)", r, ("seq", "alternate_screen", "cursor", "truncated", "lines"))
    check("the pane draws the full-screen program", wait(s, lambda: "page line 5" in screen(s), 15), s.dump(15))
    r = ag.tool("terminal_send", {"id": tid, "seq": r["seq"], "text": "q"})
    r = ag.tool("terminal_read", {"id": tid})
    check("q leaves it (alternate_screen false again)", bool(r) and r.get("alternate_screen") is False,
          json.dumps(r)[:300])

    print("prompt: read -p", flush=True)
    r = ag.tool("terminal_send", {"id": tid, "seq": r["seq"], "text": 'read -p "Your name? " nm; echo "HEL""LO-$nm"',
                                  "enter": True})
    check("an input prompt waits on screen", has_line(r, lambda ln: "Your name?" in ln) and not
          has_line(r, lambda ln: ln.startswith("HELLO-")), json.dumps(r)[:400])
    r = ag.tool("terminal_send", {"id": tid, "seq": r["seq"], "text": "gw-agent", "enter": True})
    check("the agent answers it", has_line(r, lambda ln: ln.startswith("HELLO-gw-agent")), json.dumps(r)[:400])

    print("resize: the tool and the pane", flush=True)
    r = ag.tool("terminal_resize", {"id": tid, "cols": 90, "rows": 20})
    check("terminal_resize: the terminal is 90x20", bool(r) and (r.get("cols"), r.get("rows")) == (90, 20),
          json.dumps(r)[:300])
    s.resize(150, 56)
    s.pump(2.0)
    r = ag.tool("terminal_read", {"id": tid})
    check("the pane's size: the terminal follows the Client region (its columns changed with the TUI's)",
          bool(r) and r.get("cols") not in (None, 90), json.dumps({k: r.get(k) for k in ("cols", "rows")}) if r else "")
    note(f"after the TUI's resize the terminal is {r.get('cols')}x{r.get('rows')}" if r else "no read")

    print("signals: the agent's terminal_signal, the pane's Ctrl-] c", flush=True)
    r = ag.tool("terminal_send", {"id": tid, "seq": r["seq"], "text": "sleep 300", "enter": True})
    time.sleep(0.5)
    ag.tool("terminal_signal", {"id": tid, "signal": "INT"})
    r = ag.tool("terminal_read", {"id": tid})
    r = ag.tool("terminal_send", {"id": tid, "seq": r["seq"], "text": 'echo "ST""ATUS=$?"', "enter": True})
    check("terminal_signal INT reaches the foreground program (exit status 130)",
          has_line(r, lambda ln: ln.startswith("STATUS=130")), json.dumps(r)[:400])
    r = ag.tool("terminal_send", {"id": tid, "seq": r["seq"], "text": 'sleep 301; echo "AFTER""-SLEEP"',
                                  "enter": True})
    wait(s, lambda: "sleep 301" in screen(s), 10)
    click_screen(s, tid)
    ag.pane_focus = True
    owner_user = wait(s, lambda: "Input: you hold it" in screen(s), 10)
    check("a click into the pane's screen takes the input (the header says you hold it)", owner_user,
          s.dump(15))
    s.key("ctrl_rbracket")
    s.send("c")
    s.pump(1.0)
    r = ag.tool("terminal_read", {"id": tid})
    gone = not any("sleep 301" in ln for ln in lines_of(r)[-1:])
    check("Ctrl-] c from the pane interrupts the foreground program (the prompt is back)",
          bool(r) and gone and r.get("owner") == "user", json.dumps(r)[:500])
    show("terminal_read (user holds)", r, ("seq", "owner", "lines"))
    press(s, "Hand back to Claude", lambda: "Input: Claude holds it" in screen(s))
    ag.pane_focus = True
    check("Hand back gives the input to Claude again", "Input: Claude holds it" in screen(s), s.dump(10))

    print("takeover: a queued agent write fails when the user clicks in", flush=True)
    r = ag.tool("terminal_read", {"id": tid})
    n0, done = ag.start_async("terminal_send", {"id": tid, "seq": r["seq"], "text": 'echo "QUEUED""-AGENT-WRITE"',
                                                "enter": True, "delay_ms": 9000})
    queued = wait(s, lambda: "1 queued from Claude" in screen(s), 8)
    check("the pane shows the agent's input queued", queued, s.dump(10))
    click_screen(s, tid)
    ag.pane_focus = True
    res = ag.finish_async(n0, done, 60)
    check("user takeover while the agent's input is queued: the queued write fails with \"input taken "
          "by the user; re-read the screen\"", bool(res) and TAKEN in json.dumps(res), json.dumps(res)[:400])
    show("terminal_send (queued, then taken)", res, ("ok", "error", "message", "owner", "seq"))
    s.type("cd /tmp && export GWX=user-was-here")
    s.key("enter")
    s.pump(1.0)
    r = ag.tool("terminal_read", {"id": tid})
    check("the user's keys reach the same shell (cd, export) and the queued write never ran",
          bool(r) and not has_line(r, lambda ln: ln.startswith("QUEUED-AGENT-WRITE")) and
          has_line(r, lambda ln: "/tmp" in ln), json.dumps(r)[:500])
    stale_seq = r["seq"] if r else 0
    press(s, "Hand back to Claude", lambda: "Input: Claude holds it" in screen(s))
    ag.pane_focus = True

    print("handback: a fresh read, then the same live session", flush=True)
    r = ag.tool("terminal_send", {"id": tid, "seq": stale_seq, "text": "echo should-not-run"})
    check("after the hand back the agent's old seq is refused (stale: read the screen again)",
          bool(r) and r.get("error") == "stale", json.dumps(r)[:300])
    r = ag.tool("terminal_read", {"id": tid})
    r = ag.tool("terminal_send", {"id": tid, "seq": r["seq"], "text": 'echo "PID""1=$$ CWD=$PWD GWX=$GWX"',
                                  "enter": True})
    line = next((ln for ln in lines_of(r) if ln.startswith("PID1=")), "")
    check("hand back to the same live session: the same shell pid, the user's cwd and variable kept",
          state.get("pid0") is not None and line.startswith(f"PID1={state['pid0']} CWD=/tmp") and
          "GWX=user-was-here" in line, line or json.dumps(r)[:400])

    print("sudo: the password prompt goes through the credential dialog", flush=True)
    # one turn: the sudo line, then (2 s on) a read, then an attempt to type into the prompt
    # (the prompt box itself takes nothing but the gateway's commands while the secret
    # dialog waits: phase 3's guard)
    _r1, r2, r3 = ag.turn([("terminal_send", {"id": tid, "seq": r["seq"], "enter": True,
                                              "text": 'sudo -v && echo "SU""DO-OK" || echo "SU""DO-FAILED"'}, 0),
                           ("terminal_read", {"id": tid}, 2.5),
                           ("terminal_send", {"id": tid, "seq": 0, "text": "guess"}, 0)])
    ok = wait(s, lambda: FIELD in screen(s) and "Password for a gateway terminal" in screen(s), 30)
    check("sudo in the terminal: gated sees the password prompt (echo off) and opens the credential "
          "dialog in Claude Code", ok, s.dump(25))
    check("while it waits the agent's read says so",
          bool(r2) and r2.get("waiting_auth") is True and "dialog" in str(r2.get("note", "")), json.dumps(r2)[:400])
    show("terminal_read (a password prompt waits)", r2, ("seq", "waiting_auth", "note", "lines"))
    check("the agent can't type into a password prompt", bool(r3) and r3.get("error") == "auth", json.dumps(r3)[:300])
    if ok:
        check("the dialog's private field takes the keys after a click", focus_field(s), s.dump(15))
        s.type(canary.value)
        s.pump(0.3)
        check("only bullets are drawn in the field", canary.value not in screen(s) and "•" * 8 in screen(s))
        s.key("enter")
        wait(s, lambda: "Password for a gateway terminal" not in screen(s), 30)
        ag.pane_focus = True
    s.pump(1.5)
    r = ag.tool("terminal_read", {"id": tid})
    check("the value reached that tty only: sudo (the e2e fake, checking the canary) accepted it",
          has_line(r, lambda ln: ln.startswith("SUDO-OK")), json.dumps(r)[:500])
    check("the agent sees \"[credential supplied]\", never the value",
          bool(r) and r.get("auth") == "[credential supplied]" and canary.value not in json.dumps(r),
          json.dumps({k: (r or {}).get(k) for k in ("auth", "note")}))
    show("terminal_read (after the password)", r, ("seq", "auth", "lines"))
    flog = [json.loads(ln) for ln in (fs / "log.jsonl").read_text().splitlines() if ln.strip()]
    check("the fake sudo read the password on its tty (how: tty) and accepted it (code 0)",
          bool(flog) and flog[-1].get("how") == "tty" and flog[-1].get("code") == 0,
          json.dumps([{k: e.get(k) for k in ("how", "code")} for e in flog]))
    audit = (gi.root / "data" / "audit.jsonl")
    check("the sudo stand-in audited the terminal route (no value in the audit log)",
          audit.exists() and '"outcome": "terminal"' in audit.read_text() and canary.value not in audit.read_text())

    print("jobs: job_start, job_status, job_tail", flush=True)
    j = ag.tool("job_start", {"command": "for i in $(seq 1 3000); do echo job-line-$i; done; exit 3",
                              "on_pause": "interrupt", "idempotency_key": "acc-1"})
    jid = (j or {}).get("id", "")
    check("job_start starts a job (j_..., running, on_pause kept)", jid.startswith("j_") and
          (j or {}).get("on_pause") == "interrupt", json.dumps(j)[:400])
    show("job_start", j, ("id", "state", "command", "on_pause", "host"))
    time.sleep(1.5)
    st = ag.tool("job_status", {"id": jid})
    check("job_status: exited with code 3", bool(st) and st.get("state") == "exited" and st.get("exit") == 3,
          json.dumps(st)[:400])
    show("job_status", st, ("id", "state", "exit", "signal", "started", "ended", "command"))
    t = ag.tool("job_tail", {"id": jid, "bytes": 300})
    check("job_tail is bounded (300 bytes asked) and says truncated", bool(t) and
          len(str(t.get("text", "")).encode()) <= 300 and t.get("truncated") is True and "job-line-3000" in t.get("text", ""),
          json.dumps(t)[:400])
    show("job_tail", t, ("job", "state", "truncated", "offset", "bytes_total", "text"))
    again = ag.tool("job_start", {"command": "true", "idempotency_key": "acc-1"})
    check("the same idempotency_key returns the job it started", bool(again) and again.get("id") == jid and
          again.get("new") is False, json.dumps(again)[:300])

    step_ask_rights(s, ag, gi, fs, state)


# ---------------------------------------------------------------------------
# askright: a script inside a gateway terminal and the "ask" rights
# ---------------------------------------------------------------------------

ASK_HOST = "askhost"
# consent.pane_ask_message's wording (ancestry.TERMINAL), as the stand-ins print it
PANE_ASK = ('gateway: a gateway terminal or job can\'t use the "ask" right for {what} (nobody can be '
            "asked about what runs there); run it with the Bash tool as its own command, or ask the "
            "user to set it to true.")
# The script the agent runs in the terminal: a sudo and an ssh it starts
# itself (their parent is the script's sh, its parent the pane's shell, which
# the pane's start file names as CLAUDE_PID). Its path and arguments hold no
# sudo/ssh word and no host name, so the approval hook (which judges
# terminal_send's text) can't see what it runs: only the stand-ins decide.
PROBE = """#!/bin/sh
# run from a gateway terminal: what a script there may use
out=$1
sudo -n true 2>"$out.sudo"; s=$?
cat "$out.sudo"
ssh {host} true 2>"$out.ssh"; h=$?
cat "$out.ssh"
echo "sudo=$s ssh=$h" > "$out.tmp" && mv "$out.tmp" "$out"
echo "RIGHTS""-$2 sudo=$s ssh=$h"
"""


class BannerHost(threading.Thread):
    """askhost's address: 127.0.0.1, a free port, answering every connection
    with an ssh banner and closing it (gate check's probe wants the banner;
    nobody ever logs in, so Claude's key is never installed). Counts the
    connections."""

    def __init__(self):
        super().__init__(daemon=True)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.3)
        self.port = self.sock.getsockname()[1]
        self.conns = 0
        self.halt = threading.Event()

    def run(self) -> None:
        while not self.halt.is_set():
            try:
                c, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.conns += 1
            with contextlib.suppress(OSError):
                c.sendall(b"SSH-2.0-acc-askhost\r\n")
                time.sleep(0.2)
            c.close()

    def close(self) -> None:
        self.halt.set()
        with contextlib.suppress(OSError):
            self.sock.shutdown(socket.SHUT_RDWR)
        self.sock.close()
        self.join(3)


def setup_ask_rights(root: Path, gi, state: dict, stack: contextlib.ExitStack) -> str:
    """Before any session: the probe script, askhost's banner-only address,
    and the e2e fake ssh-keyscan (`tools` in e2e.json) that gives gate check
    one fixed host key for it (approving a new ssh host reads its key
    first). Returns the fake's path."""
    probe = root / "probe"
    probe.mkdir()
    (probe / "rights.sh").write_text(PROBE.replace("{host}", ASK_HOST))
    host = BannerHost()
    host.start()
    stack.callback(host.close)
    hk = gi.root / "askhost-hostkey"
    subprocess.run([shutil.which("ssh-keygen") or "/usr/bin/ssh-keygen", "-q", "-t", "ed25519",
                    "-N", "", "-C", "acc-askhost", "-f", str(hk)],
                   check=True, capture_output=True, stdin=subprocess.DEVNULL)
    pub = " ".join(Path(f"{hk}.pub").read_text().split()[:2])
    fk = gi.root / "fake-keyscan"
    fk.mkdir()
    (fk / "ssh-keyscan").write_text(f"#!/bin/sh\n# the e2e fake ssh-keyscan: one fixed key\n"
                                    f"printf '%s\\n' '[127.0.0.1]:{host.port} {pub}'\n")
    os.chmod(fk / "ssh-keyscan", 0o755)
    state.update(probe=probe / "rights.sh", askport=host.port, askhost=host)
    return str(fk / "ssh-keyscan")


def ask_form(port: int, ssh: str, local_sudo: str | None = None) -> str:
    text = f'[hosts.{ASK_HOST}]\naddress = "127.0.0.1:{port}"\nssh = {ssh}\nsudo = false\n'
    if local_sudo is not None:
        text += f"\n[hosts.localhost]\nsudo = {local_sudo}\n"
    return text


def step_ask_rights(s, ag: Agent, gi, fs: Path, state: dict) -> None:
    print("askright: a script in the terminal: \"ask\" rights refused there, a true right works",
          flush=True)
    tid, probe, port = state.get("tid"), state.get("probe"), state.get("askport")
    if not (tid and probe and port):
        check("askright: set up (terminal, probe script, port)", False, json.dumps(
            {"tid": tid, "probe": str(probe), "port": port}))
        return
    form = gi.gateway_home / "gateway.toml"
    audit = gi.root / "data" / "audit.jsonl"

    def audit_lines() -> list[str]:
        try:
            return audit.read_text().splitlines()
        except OSError:
            return []

    def fake_calls() -> int:
        return len([ln for ln in (fs / "log.jsonl").read_text().splitlines() if ln.strip()])

    def run_probe(n: int) -> tuple[dict, str, str, dict | None]:
        out = probe.parent / f"run{n}"
        r = ag.tool("terminal_read", {"id": tid})
        ag.tool("terminal_send", {"id": tid, "seq": (r or {}).get("seq", 0),
                                  "text": f"sh '{probe}' '{out}' {n}", "enter": True})
        wait(s, lambda: out.exists(), 90, 0.5)
        codes: dict = {}
        try:
            codes = dict(kv.split("=", 1) for kv in out.read_text().split())
        except (OSError, ValueError):
            pass
        rd = lambda p: p.read_text().strip() if p.exists() else ""   # noqa: E731
        screen_r = None
        for _ in range(10):
            screen_r = ag.tool("terminal_read", {"id": tid})
            if has_line(screen_r, lambda ln: ln.startswith(f"RIGHTS-{n} ")):
                break
            time.sleep(0.5)
        return codes, rd(Path(f"{out}.sudo")), rd(Path(f"{out}.ssh")), screen_r

    # 1. no form: localhost's sudo is true (the default, the sudo step used it)
    a0 = len(audit_lines())
    codes, err_sudo, _err_ssh, r = run_probe(1)
    new = audit_lines()[a0:]
    check("askright: a true right still works from a script in a gateway terminal (sudo -n true, "
          "the e2e fake's cached timestamp: exit 0; the sudo stand-in took the terminal route)",
          codes.get("sudo") == "0" and any('"outcome": "terminal"' in ln for ln in new),
          json.dumps({"codes": codes, "stderr": err_sudo[:300]}))
    check("askright: the pane shows the script's result line",
          has_line(r, lambda ln: ln.startswith("RIGHTS-1 sudo=0")), json.dumps(lines_of(r)[-6:]))

    # 2. a new ssh host, approved in the dialog (ssh true), then narrowed to "ask"
    form.write_text(ask_form(port, "true"))
    n0, done = ag.start_bash(f"gate check {ASK_HOST}", f"set up {ASK_HOST}")
    ok = wait(s, lambda: "Approve" in screen(s) and ASK_HOST in screen(s), 120)
    check(f"askright: gate check {ASK_HOST} opens the consent dialog (new host, its host key)", ok,
          s.dump(25))
    if ok:
        press(s, "Approve", lambda: "Use my own SSH login once" in screen(s), settle=4.0)
        ok = wait(s, lambda: "Use my own SSH login once" in screen(s), 90)
        check("askright: Approve, then the key-install choice (the address only answers with a "
              "banner: Claude's key isn't installed)", ok, s.dump(25))
        if ok:
            press(s, "Cancel", lambda: "Use my own SSH login once" not in screen(s))
    res = ag.finish_bash(n0, done)
    note(f"gate check {ASK_HOST}: {' '.join((res or 'no result').split())[:200]}")
    ag.pane_focus = True
    form.write_text(ask_form(port, '"ask"'))
    host = state["askhost"]
    a0, f0, c0 = len(audit_lines()), fake_calls(), host.conns
    codes, err_sudo, err_ssh, r = run_probe(2)
    want = PANE_ASK.format(what=f"ssh on {ASK_HOST}")
    check(f"askright: a script in a gateway terminal can't use the \"ask\" ssh right for {ASK_HOST} "
          "(refused with the pane's wording, before any connection)",
          codes.get("ssh") not in (None, "0") and err_ssh == want and host.conns == c0,
          json.dumps({"codes": codes, "stderr": err_ssh[:400], "connections": host.conns - c0}))
    check("askright: the same script's true sudo right still works there (exit 0)",
          codes.get("sudo") == "0" and fake_calls() == f0 + 1,
          json.dumps({"codes": codes, "stderr": err_sudo[:300], "fake sudo calls": fake_calls() - f0}))
    new = audit_lines()[a0:]
    check(f"askright: the ssh stand-in audited the refusal (ssh, {ASK_HOST}, the pane's wording)",
          any('"event": "refusal"' in ln and '"tool": "ssh"' in ln and f'"target": "{ASK_HOST}"' in ln
              and "gateway terminal or job" in ln for ln in new), "\n".join(new[-4:])[:600])

    # 3. localhost's sudo narrowed to "ask" (applies at once)
    form.write_text(ask_form(port, '"ask"', '"ask"'))
    a0, f0 = len(audit_lines()), fake_calls()
    codes, err_sudo, _err_ssh, r = run_probe(3)
    want = PANE_ASK.format(what="sudo on this machine")
    check("askright: a script in a gateway terminal can't use the \"ask\" sudo right on this machine "
          "(refused with the pane's wording; sudo itself never ran)",
          codes.get("sudo") not in (None, "0") and err_sudo == want and fake_calls() == f0,
          json.dumps({"codes": codes, "stderr": err_sudo[:400], "fake sudo calls": fake_calls() - f0}))
    check("askright: the pane shows the refusal to whoever watches it",
          has_line(r, lambda ln: ln.startswith("RIGHTS-3 sudo=") and not ln.startswith("RIGHTS-3 sudo=0")) and
          "can't use the" in " ".join(lines_of(r)), json.dumps(lines_of(r)[-8:])[:600])
    new = audit_lines()[a0:]
    check("askright: the sudo stand-in audited the refusal (sudo, localhost, the pane's wording)",
          any('"event": "refusal"' in ln and '"tool": "sudo"' in ln and '"target": "localhost"' in ln
              and "gateway terminal or job" in ln for ln in new), "\n".join(new[-4:])[:600])


def step_restart(root: Path, h, gi, extra: dict, state: dict, canary) -> driver.Session | None:
    print("restart: Claude Code exits; a new session finds the terminal alive", flush=True)
    s = driver.Session(root / "s2", config_dir=h.inst.config_dir, extra_env=extra, debug_file=True,
                       cols=170, rows=56, permission_mode="bypassPermissions", start=False)
    s.redact(canary.value)
    try:
        s.start()
        s.wait_ready(180)
        ag = Agent(s)
        r = ag.tool("terminal_list", {})
        tid = state["tid"]
        entry = next((t for t in (r or {}).get("terminals", []) if t.get("id") == tid), None)
        check("after a Claude Code restart terminal_list still has the terminal, open (tmux and gated "
              "outlived the session)", bool(entry) and entry.get("state") == "open", json.dumps(r)[:500])
        r = ag.tool("terminal_read", {"id": tid, "take": True})
        check("the new session adopts it (take: its old session ended)", bool(r) and r.get("mine") is True,
              json.dumps(r)[:300])
        r = ag.tool("terminal_send", {"id": tid, "seq": (r or {}).get("seq", 0), "text": 'echo "PID""2=$$"', "enter": True})
        check("the same shell answers (its pid unchanged)",
              has_line(r, lambda ln: ln == f"PID2={state.get('pid0')}"), json.dumps(r)[:400])
        s.submit(f"/gate-terminal {tid}")
        check("the pane shows it again in the new session (state lives in gated)",
              wait(s, lambda: f"terminal {tid}" in screen(s), 30), s.dump(15))
        return s
    finally:
        s.close()


def step_main_screen(root: Path, h, gi, extra: dict, state: dict, canary) -> driver.Session | None:
    print("mainscr: no clicks reach the pane; a line field instead", flush=True)
    s = driver.Session(root / "s3", config_dir=h.inst.config_dir,
                       extra_env={**extra, "CLAUDE_CODE_NO_FLICKER": "0"}, debug_file=True,
                       observer=True, cols=170, rows=56, permission_mode="bypassPermissions", start=False)
    s.redact(canary.value)
    try:
        s.start()
        s.wait_ready(180)
        tid = state["tid"]
        s.submit(f"/gate-terminal {tid}")
        ok = wait(s, lambda: "main screen" in s.all_text() and f"terminal {tid}" in screen(s), 30)
        check("main screen: the pane says no clicks reach it and offers a line field", ok, s.dump(15))
        s.type('echo "FROM""-MAIN-SCREEN"')
        s.pump(0.3)
        s.key("enter")
        reached = wait(s, lambda: "FROM-MAIN-SCREEN" in screen(s).replace('FROM""-MAIN', ''), 15)
        check("a line typed into the pane's field reaches the terminal (the pane shows its output)",
              reached, s.dump(15))
        if not reached:
            note("the line field didn't take the keys on the main screen (focus); the buttons remain")
        return s
    finally:
        s.close()


def scans(root: Path, sessions, gi, px, canary, h) -> None:
    print("scans: the sudo canary everywhere it must not be", flush=True)
    places = {
        "the scratch Claude config (transcripts, history, plugin data, caches)": h.inst.config_dir,
        "the gateway's plugin data (gated log, events, terminals.json, audit log)": gi.root / "data",
        "the gateway's home": gi.gateway_home,
        "the gateway's run dir (tmux config, dialogs, sessions)": gi.run,
    }
    if px is not None:
        places["the proxied first-party telemetry payloads"] = px.root
    for i, x in enumerate(sessions):
        if x.observer is not None:
            places[f"session {i + 1}'s observer records (a nosy third-party mod)"] = x.observer.root
    for what, where in places.items():
        if where is None or not Path(where).exists():
            check(f"scan: {what} exists to be scanned", False)
            continue
        rep = scan.Report()
        rep.scan_tree(where, canary)
        check(f"scan: no canary in {what}", rep.clean(), rep.summary())
    for i, x in enumerate(sessions):
        rep = scan.Report()
        if x.debug_path and x.debug_path.exists():
            rep.scan_tree(x.debug_path.parent, canary)
            check(f"scan: no canary in session {i + 1}'s --debug-file log", rep.clean(), rep.summary())
        rep = scan.Report()
        rep.scan_api_log(x.api.log_path, canary)
        check(f"scan: no canary in any request session {i + 1} made to the fake Messages API",
              rep.clean(), rep.summary())
        rep = scan.Report()
        rep.scan_bytes(bytes(x.raw), "pty", canary, ansi=True)
        check(f"scan: no canary in session {i + 1}'s PTY output", rep.clean(), rep.summary())
    if px is not None:
        n = len(px.requests())
        check(f"telemetry: first-party requests were captured before encryption ({n} recorded)", n > 0)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
