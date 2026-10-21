#!/usr/bin/env python3
"""PLAN-v4 phase 4 in the real TUI: managed execution (brief 3, 8, 14.6).

    pixi exec --spec python=3.12 --spec pyte python tests/acceptance_managed.py \\
        --tmp DIR [--keep] [--pixi-cache DIR] [--only a,b,...]

The gateway is installed the normal way through the TUI harness's e2e route
(tests/tui: a git-source marketplace in a scratch Claude config, the e2e
marker that keeps every gateway location in a scratch root), next to a probe
plugin ("probe") whose string-form hooks write their environment, $0 and
payloads, whose SessionStart hook writes an env file, with a bin/ program and
a skill with ! injection. Sessions run against the harness's fake Messages
API; HOME is scratch, with rc files that define a function, an alias and a
variable (the shell snapshot Claude Code makes from them carries them). The
gateway's pixi env is built before any session.

Sections (a baseline config has only the probe plugin, for comparison):

  route    every route Claude Code runs commands by goes through gate-sh into
           the managed bash (bash 5 from the gateway env), never the
           snapshot: the Bash tool, run_in_background, a subagent's Bash, the
           user's ! command, a skill's ! injection; the curated environment
           (names only; a synthetic credential canary in Claude Code's own
           environment never reaches a command), the gateway PATH, the probe
           plugin's bin/ and its env file kept
  hooks    the probe plugin's string-form hooks run through the prefix with
           the same $0 and environment as in the baseline (but the three
           variables the gateway's mod sets); PreToolUse and PostToolUse see
           the original command
  perms    default permission mode: the dialog shows the original command,
           "don't ask again" writes a rule for the original command, and the
           next matching command runs without a prompt; results and exit
           codes as in the baseline
  cancel   an interrupt (Escape) and a Bash timeout stop a long command (the
           file it would write never appears, its process is gone), as in the
           baseline
  print    claude -p: the prefix is set and the command runs in the managed bash
  nomods   the gateway installed with "modules" removed from hooks.json (no
           mod): Bash is denied with "managed shell unavailable"; with an
           approved [shell] managed = "warn", it runs in the user's own shell
           with a notice once per session

Monitor isn't offered by Claude Code 2.1.301 against the fake API (a
server-side feature gate); its commands use the same shell path (code
evidence in docs/modules/managed.md). Prints one line per check and a JSON
summary to --tmp/acceptance-managed.json; exits non-zero on any failure.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN = HERE.parent
REPO = PLUGIN.parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
from tui import driver, gwe2e, install, safety, scan  # noqa: E402
from tui.fakeapi import FakeAPI, tool_results  # noqa: E402

RESULTS: list[dict] = []
NOTES: list[str] = []
PREBUILD_TIMEOUT = 1800
# what differs between a hook's environment with the gateway and without it:
# the gateway mod's own variables, and per-session values
VOLATILE = re.compile(r"^(CLAUDE_CODE_SHELL_PREFIX|CLAUDE_CODE_SHELL|GW_MANAGED_DIR|"
                      r"CLAUDE_CODE_SESSION_ID|CLAUDE_CODE_MESSAGING_SOCKET|CLAUDE_CODE_MESSAGING_TOKEN|"
                      r"CLAUDE_PID|ANTHROPIC_BASE_URL|XDG_RUNTIME_DIR|CLAUDE_CONFIG_DIR|HOME|TMPDIR|"
                      r"CLAUDE_CODE_TMPDIR|CHECKPOINT_[A-Z_]*|GATEWAY_TEST_ROOT|XDG_[A-Z]*_HOME|"
                      r"CLAUDE_PLUGIN_ROOT|CLAUDE_PLUGIN_DATA|CLAUDE_PROJECT_DIR|PWD|PROBE_OUT|"
                      r"CLAUDE_ENV_FILE|COLUMNS|LINES|OLDPWD)=")


def check(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append({"check": name, "ok": bool(ok), **({"detail": detail[:2000]} if detail and not ok else {})})
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok or not detail else f"\n       {detail[:2000]}"),
          flush=True)
    return bool(ok)


def note(text: str) -> None:
    NOTES.append(text)
    print(f"  note {text}", flush=True)


def bash(cmd: str, desc: str = "probe", **kw) -> dict:
    return {"tool": "Bash", "input": {"command": cmd, "description": desc, **kw}}


def wait(s: driver.Session, cond, timeout: float, step: float = 0.3) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if cond():
                return True
        except Exception:  # noqa: BLE001
            pass
        s.pump(step)
    try:
        return bool(cond())
    except Exception:  # noqa: BLE001
        return False


def env_python() -> str:
    r = subprocess.run(["pixi", "run", "--locked", "--manifest-path", str(PLUGIN / "pixi.toml"), "python",
                        "-c", "import sys; print(sys.executable)"], capture_output=True, text=True)
    return r.stdout.strip()


# ---------------------------------------------------------------------------
# The probe plugin and the scratch HOME
# ---------------------------------------------------------------------------

PROBE_HOOK_ENV = '{ echo "ZERO=$0"; env | LC_ALL=C sort; } > "$PROBE_OUT/hook-env-$1.txt"'
# Which bash ran a probe: the managed bash is the gateway env's (its $BASH, the
# executable's path, ends in this); never told apart by version (Debian's own
# bash is 5.2 like the env's; macOS's is 3.2).
MANAGED_BASH = "/.pixi/envs/default/bin/bash"
# The probe plugin's hooks do nothing where PROBE_OUT isn't set (claude -p's
# session): a redirect to "/pre-env.txt" fails, and under dash that is exit
# status 2, a blocking hook error.
PROBE_GUARD = '[ -n "${PROBE_OUT-}" ] || exit 0; '


def make_probe_repo(src: Path) -> None:
    (src / ".claude-plugin").mkdir(parents=True, exist_ok=True)
    p = src / "plugins" / "probe"
    for d in (".claude-plugin", "hooks", "bin", "commands"):
        (p / d).mkdir(parents=True, exist_ok=True)
    (src / ".claude-plugin" / "marketplace.json").write_text(json.dumps({
        "name": "managed-probe", "owner": {"name": "acceptance"},
        "plugins": [{"name": "probe", "source": "./plugins/probe", "description": "managed-shell probe"}]}))
    (p / ".claude-plugin" / "plugin.json").write_text(json.dumps({
        "name": "probe", "version": "0.1.0", "description": "managed-shell probe",
        "author": {"name": "acceptance"}}))

    def h(cmd: str) -> dict:
        return {"hooks": [{"type": "command", "command": cmd}]}
    hooks = {"hooks": {
        "SessionStart": [h("echo 'export PROBE_ENVFILE=from-the-probe-env-file' >> \"$CLAUDE_ENV_FILE\"")],
        "PreToolUse": [{"matcher": "Bash", **h(
            # $0 and the environment (once per call), then the payload
            PROBE_GUARD + '{ echo "ZERO=$0"; env | LC_ALL=C sort; } > "$PROBE_OUT/pre-env.txt"; '
            'cat >> "$PROBE_OUT/pre.jsonl"; echo >> "$PROBE_OUT/pre.jsonl"')}],
        "PostToolUse": [{"matcher": "Bash", **h(PROBE_GUARD + 'cat >> "$PROBE_OUT/post.jsonl"; '
                                                'echo >> "$PROBE_OUT/post.jsonl"')}],
    }}
    (p / "hooks" / "hooks.json").write_text(json.dumps(hooks, indent=1))
    (p / "bin" / "probe-bin-tool").write_text('#!/bin/sh\necho probe-bin-tool-ran\n'
                                              '[ -n "${2-}" ] && : > "probe-bin-tool-$2.ran"\nexit 0\n')
    os.chmod(p / "bin" / "probe-bin-tool", 0o755)
    (p / "commands" / "inj.md").write_text(
        "---\ndescription: managed-shell probe injection\nallowed-tools: Bash(echo:*)\n---\n"
        "Injected: !`echo \"inj:$BASH_VERSION:${PROBE_ENVFILE-}:${BASH-}\" > inj.txt; echo done`\n")


def make_home(home: Path, marker: Path) -> None:
    rc = ("userfunc() { echo user-function; }\nalias ll='ls -l'\nexport RC_VAR=from-the-user-rc\n"
          f": > '{marker}'\n")
    # .zshenv: every zsh reads it (Claude Code's own launcher too, without the gateway)
    for n in (".bashrc", ".bash_profile", ".zshrc", ".zprofile", ".profile", ".zshenv"):
        (home / n).write_text(rc)


# ---------------------------------------------------------------------------
# Setup helpers
# ---------------------------------------------------------------------------


def prebuild_env(root: Path, h, gi, env: dict) -> tuple[bool, str]:
    plugin = Path(gi.plugin.cache_path)
    for d in ("b-home", "b-tmp"):
        (root / d).mkdir(exist_ok=True)
    # the e2e route's environment (GATEWAY_TEST_ROOT unset; the marker, proven at install,
    # keeps every location in the scratch root), as a session's async hook builds it: the
    # build then also writes the managed shell's files (run.py managed-sync)
    benv = safety.hermetic_env(config_dir=h.inst.config_dir, home=root / "b-home",
                               tmpdir=root / "b-tmp", extra={**env, **gi.env()})
    t0 = time.time()
    try:
        r = subprocess.run(["/bin/sh", str(plugin / "hooks" / "launch.sh"), "ensure-env"], env=benv,
                           cwd=root / "b-tmp", capture_output=True, text=True, timeout=PREBUILD_TIMEOUT)
        rc, err = r.returncode, r.stderr[-400:]
    except subprocess.TimeoutExpired:
        rc, err = None, f"no answer in {PREBUILD_TIMEOUT} s"
    ready = sorted(gi.root.glob("data/envs/*/.ready"))
    return bool(ready) and rc == 0, f"launch.sh ensure-env: rc={rc} in {time.time() - t0:.0f} s; {err}"


def e2e_python(gi) -> str | None:
    c = sorted(gi.root.glob("data/envs/*/.pixi/envs/default/bin/python3"))
    return str(c[-1]) if c else None


def seed(gi, code: str) -> subprocess.CompletedProcess[str]:
    """Run gateway Python against the scratch e2e root (its own src, the
    test override naming that root): a test-only way to set an approval
    where no dialog can open (no mod)."""
    py = e2e_python(gi)
    src = Path(gi.plugin.cache_path) / "src"
    prog = ("import sys; sys.path.insert(0, sys.argv[1]); from gateway import testing, consent, managed\n"
            "with testing.override(sys.argv[2], run=sys.argv[3]):\n" +
            "\n".join("    " + ln for ln in code.splitlines()))
    return subprocess.run([py, "-I", "-S", "-c", prog, str(src), str(gi.root), str(gi.run or gi.root / "run")],
                          capture_output=True, text=True, timeout=60)


def files_of(work: Path) -> dict[str, str]:
    out = {}
    for p in work.glob("*.txt"):
        try:
            out[p.name] = p.read_text()
        except OSError:
            pass
    return out


def jl(p: Path) -> list[dict]:
    if not p.exists():
        return []
    out = []
    for ln in p.read_text().splitlines():
        ln = ln.strip()
        if ln:
            try:
                out.append(json.loads(ln))
            except ValueError:
                pass
    return out


def norm_env(text: str) -> list[str]:
    return [ln for ln in text.splitlines() if not VOLATILE.match(ln)]


def results_text(api: FakeAPI) -> list[str]:
    """Every tool_result the model got back, as text (in request order)."""
    out = []
    seen = set()
    for rec in api.main_requests():
        for tr in tool_results(rec):
            tid = tr.get("tool_use_id")
            if tid in seen:
                continue
            seen.add(tid)
            c = tr.get("content")
            if isinstance(c, list):
                c = "".join(x.get("text", "") for x in c if isinstance(x, dict))
            out.append(str(c))
    return out


# ---------------------------------------------------------------------------
# The scripted turn (the same in the baseline and the gateway's session)
# ---------------------------------------------------------------------------

ROUTE_CMD = ('echo "route:bash=${BASH_VERSION-}:zsh=${ZSH_VERSION-}:pe=${PROBE_ENVFILE-}:rc=${RC_VAR-}:bp=${BASH-}"; '
             "type userfunc >/dev/null 2>&1 && echo has-userfunc || echo no-userfunc; "
             "probe-bin-tool; env | sed 's/=.*//' | LC_ALL=C sort > names.txt; env > fullenv.txt; "
             'echo "$PATH" > path.txt; echo "SHELL=$SHELL" > shell.txt')


BG_CMD = 'echo "bg:$BASH_VERSION:${BASH-}" > bg.txt'


def scripted_replies() -> list:
    return [
        bash(ROUTE_CMD, "route probe"),
        bash(BG_CMD, "background probe", run_in_background=True),
        bash("echo result-text-$((6*7)); echo to-stderr >&2", "result probe"),
        bash("echo before-exit; exit 3", "exit probe"),
        {"tool": "Agent", "input": {"description": "sub probe", "prompt": "run it",
                                    "subagent_type": "general-purpose"}},
        bash('echo "sub:$BASH_VERSION:${PROBE_ENVFILE-}:${BASH-}" > sub.txt', "subagent probe"),
        "subagent done",
        "turn done",
    ]


def run_turn(s: driver.Session, work: Path) -> bool:
    s.submit("run the probes")
    ok = wait(s, lambda: (work / "sub.txt").exists() and (work / "bg.txt").exists()
              and (work / "names.txt").exists(), 180, 0.5)
    s.pump(4)
    return ok


def bang_and_inject(s: driver.Session, work: Path) -> tuple[bool, bool]:
    s.send("!")
    s.pump(0.5)
    s.type('echo "bang:${BASH_VERSION-}:${ZSH_VERSION-}:${PROBE_ENVFILE-}:${BASH-}" > bang.txt')
    s.pump(0.3)
    s.enter()
    b = wait(s, lambda: (work / "bang.txt").exists(), 40, 0.5)
    s.pump(2)
    s.submit("/probe:inj")
    i = wait(s, lambda: (work / "inj.txt").exists(), 60, 0.5)
    s.pump(3)
    return b, i


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tmp", default=tempfile.gettempdir())
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--pixi-cache", default=None)
    ap.add_argument("--only", default="")
    a = ap.parse_args(argv)
    only = set(x for x in a.only.split(",") if x)
    before = safety.real_settings_fingerprint()
    root = Path(tempfile.mkdtemp(prefix="acc-managed-", dir=a.tmp))
    safety.check_scratch(root, "acceptance root")
    print(f"acceptance (managed execution): root {root}", flush=True)
    env = {"PIXI_CACHE_DIR": a.pixi_cache or str(root / "pixi-cache")}
    canary = scan.Canary.new("env-credential")
    t0 = time.time()
    try:
        run(root, env, canary, only)
    finally:
        driver._close_all()
    # the last Hermetic just removed its run dir: a gated notices at its next tick (0.25 s
    # under the e2e marker) and then shuts down, which a loaded machine can stretch
    left: list[str] = []
    for _ in range(20):
        time.sleep(0.5)
        left = [ln for ln in subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True,
                                            text=True).stdout.splitlines()
                if str(root) in ln and "ps -axo" not in ln]
        if not left:
            break
    check("no process left naming the scratch root", not left, "\n".join(left))
    after = safety.real_settings_fingerprint()
    check("real ~/.config/claude settings and plugin registry unchanged", before == after)
    failed = [r for r in RESULTS if not r["ok"]]
    summary = {"when": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "seconds": round(time.time() - t0),
               "claude": subprocess.run([driver.find_claude(), "--version"], capture_output=True,
                                        text=True).stdout.strip(),
               "passed": len(RESULTS) - len(failed), "failed": len(failed), "checks": RESULTS,
               "notes": NOTES}
    out = Path(a.tmp) / "acceptance-managed.json"
    out.write_text(json.dumps(summary, indent=1))
    print(f"\n{summary['passed']} passed, {summary['failed']} failed in {summary['seconds']} s; {out}")
    if not a.keep:
        shutil.rmtree(root, ignore_errors=True)
    return 1 if failed else 0


def session(root: Path, name: str, cfg: Path, env: dict, replies, **kw) -> driver.Session:
    home = root / f"{name}-home"
    home.mkdir(parents=True, exist_ok=True)
    make_home(home, root / f"{name}-rc-ran")
    out = root / f"{name}-probe"
    out.mkdir(exist_ok=True)
    s = driver.Session(root / name, config_dir=cfg, home=home,
                       extra_env={**env, "PROBE_OUT": str(out), "SHELL": "/bin/zsh" if os.path.exists("/bin/zsh") else "/bin/bash"},
                       replies=replies, debug_file=True, cols=160, rows=48, start=False, **kw)
    return s


def run(root: Path, env: dict, canary: scan.Canary, only: set[str]) -> None:
    want = (lambda x: not only or x in only)
    src = root / "probe-src"
    make_probe_repo(src)
    # Claude Code's mTLS key passphrase passed the curated environment before the
    # phase 4 review (PASSW isn't in PASSPHRASE); the key itself isn't set, so
    # Claude Code doesn't use it
    cred_env = {"GITHUB_TOKEN": canary.value, "CLAUDE_CODE_CLIENT_KEY_PASSPHRASE": canary.value}
    # the baseline: only the probe plugin
    base = {}
    with install.Hermetic(root / "hb", extra_env=env) as hb:
        hb.install_from(src, repo="managed-probe", plugin="probe")
        if want("route") or want("hooks") or want("perms") or want("cancel"):
            base = baseline(root, hb, {**env, **cred_env}, want)
    with install.Hermetic(root / "h", extra_env=env) as h:
        gi = h.install_gateway_e2e(REPO)
        check("the gateway is installed through the e2e route (marker proven)", gi.proof is not None)
        h.install_from(src, repo="managed-probe", plugin="probe")
        ok, detail = prebuild_env(root, h, gi, env)
        if not check("the gateway's pixi env (with bash) is built before any session", ok, detail):
            return
        note(detail.splitlines()[0])
        check("the env's build wrote the managed shell's files (launch.sh managed_sync)",
              (gi.root / "data" / "managed" / "conf").is_file(), str(sorted(gi.root.glob("data/managed/*"))))
        if want("route") or want("hooks") or want("perms") or want("cancel"):
            managed_session(root, h, gi, {**env, **cred_env}, canary, base, want)
        if want("print"):
            step_print(root, h, gi, env)
    if want("nomods"):
        step_nomods(root, env, src)


def baseline(root: Path, hb, env: dict, want) -> dict:
    """The same scripted turn without the gateway (Claude Code's own shell)."""
    print("baseline: the probe plugin alone", flush=True)
    out: dict = {}
    s = session(root, "b1", hb.inst.config_dir, env, scripted_replies(), permission_mode="bypassPermissions")
    s.start()
    try:
        s.wait_ready(120)
        out["turn"] = run_turn(s, s.cwd)
        out["files"] = files_of(s.cwd)
        out["results"] = results_text(s.api)
        pe = root / "b1-probe" / "pre-env.txt"
        out["hook_env"] = pe.read_text() if pe.exists() else ""
        if want("cancel"):
            out["cancel"] = cancel_steps(s)
    finally:
        s.close()
    if want("perms"):
        out["perm"] = perm_session(root, "b2", hb.inst.config_dir, env)
    check("baseline: the scripted turn ran without the gateway", bool(out.get("turn")))
    text = "\n".join(out.get("results", []))
    check("baseline: Claude Code's own shell carries the user's setup (the snapshot's function, the "
          "login shell's .zshenv variable), so the managed checks below mean something",
          "has-userfunc" in text and "rc=from-the-user-rc" in text
          and ("zsh=5" in text if os.path.exists("/bin/zsh") else re.search(r":bp=/\S*bash\n", text + "\n") is not None)
          and MANAGED_BASH not in text, text[:600])
    return out


# an unknown program (the probe plugin's bin/), so Claude Code offers a rule for the
# command itself; it leaves a file named after its argument
PERM_CMD = "probe-bin-tool rule prompted"
PERM_CMD2 = "probe-bin-tool rule by-the-rule"   # Claude Code's rule keeps the first word after the program
PROMPTED = "probe-bin-tool-prompted.ran"
BY_RULE = "probe-bin-tool-by-the-rule.ran"


def perm_session(root: Path, name: str, cfg: Path, env: dict) -> dict:
    """Default permission mode: the dialog for PERM_CMD; 'don't ask again'
    (option 2); then PERM_CMD2 runs without a prompt."""
    replies = [bash(PERM_CMD, "make a file"), "first done", bash(PERM_CMD2, "make another"), "second done"]
    s = session(root, name, cfg, env, replies, permission_mode="default")
    s.start()
    try:
        s.wait_ready(180)
        return perm_dialog(s)
    finally:
        s.close()


def perm_dialog(s: driver.Session) -> dict:
    out = {"dialog": "", "rule": None, "second_prompted": None, "screens": []}
    s.submit("make the files")
    if wait(s, lambda: "Do you want to proceed?" in s.text(), 40):
        s.pump(1.5)                # the dialog takes keys once it has settled
        out["dialog"] = s.text()
        m = re.search(r"(\d)\. Yes, and don.t ask again", out["dialog"])
        key = m.group(1) if m else "2"
        s.send(key)                # "Yes, and don't ask again for: ..." (a digit selects at once)
        if not wait(s, lambda: "Do you want to proceed?" not in s.text(), 10):
            s.send(key)
    wait(s, lambda: (s.cwd / PROMPTED).exists(), 30)
    out["screens"].append(s.text()[-1200:])
    s.pump(2)
    s.submit("make the second file")
    out["second_prompted"] = bool(wait(s, lambda: "Do you want to proceed?" in s.text()
                                       and "by-the-rule" in s.text(), 15))
    out["screens"].append(s.text()[-1200:])
    if out["second_prompted"]:
        s.pump(1.5)
        s.send("1")
    wait(s, lambda: (s.cwd / BY_RULE).exists(), 30)
    p = s.cwd / ".claude" / "settings.local.json"
    try:
        out["rule"] = json.loads(p.read_text()).get("permissions", {}).get("allow") or None
    except (OSError, ValueError):
        out["rule"] = None
    return out


def cancel_steps(s: driver.Session) -> dict:
    """An interrupt (Escape) of a long command, and a Bash timeout."""
    out = {}
    s.api.push(bash("echo $$ > long.pid; sleep 9; touch after-interrupt.txt", "a long command"),
               "interrupted turn")
    s.submit("run the long command")
    started = wait(s, lambda: (s.cwd / "long.pid").exists(), 40)
    s.pump(1.5)
    s.send("\x1b")          # Escape interrupts the running tool
    s.pump(1.0)
    s.send("\x1b")
    time.sleep(11)
    s.pump(1)
    pid = (s.cwd / "long.pid").read_text().strip() if (s.cwd / "long.pid").exists() else ""
    alive = bool(pid) and subprocess.run(["ps", "-p", pid], capture_output=True).returncode == 0
    out["interrupt"] = {"started": started, "file": (s.cwd / "after-interrupt.txt").exists(), "alive": alive}
    s.api.push(bash("sleep 9; touch after-timeout.txt", "a timed-out command", timeout=2000), "timeout turn")
    s.submit("run the timed command")
    wait(s, lambda: "timeout turn" in s.text(), 60)
    time.sleep(9)
    out["timeout"] = {"file": (s.cwd / "after-timeout.txt").exists()}
    return out


def managed_session(root: Path, h, gi, env: dict, canary: scan.Canary, base: dict, want) -> None:
    print("managed: the gateway and the probe plugin", flush=True)
    s = session(root, "m1", h.inst.config_dir, env, scripted_replies(), permission_mode="bypassPermissions")
    s.redact(canary.value)
    s.start()
    try:
        s.wait_ready(180)
        work = s.cwd
        ok = run_turn(s, work)
        check("route: the scripted turn ran (Bash, background, subagent)", ok, s.dump(30))
        files = files_of(work)
        res = results_text(s.api)
        route = next((r for r in res if "route:bash=" in r), "")
        check("route: the Bash tool ran in the managed bash 5, not the login shell or its snapshot "
              "(no user function, no rc variable), with the probe's env file and its bin/ program",
              re.search(r"route:bash=5\.\d+[^:]*:zsh=:pe=from-the-probe-env-file:rc=:bp=\S*" + re.escape(MANAGED_BASH) + r"\n",
                        route + "\n") is not None
              and "no-userfunc" in route and "probe-bin-tool-ran" in route, route[:400])
        check("route: run_in_background ran in the managed bash",
              re.fullmatch(r"bg:5\.[^:]*:\S*" + re.escape(MANAGED_BASH) + r"\n", files.get("bg.txt", "")) is not None,
              files.get("bg.txt", ""))
        check("route: a subagent's Bash ran in the managed bash with the env file",
              re.fullmatch(r"sub:5\.[^:]*:from-the-probe-env-file:\S*" + re.escape(MANAGED_BASH) + r"\n",
                           files.get("sub.txt", "")) is not None,
              files.get("sub.txt", ""))
        names = set(files.get("names.txt", "").split())
        allowed = re.compile(r"(HOME|USER|LOGNAME|LANG|LC_[A-Z_]*|TERM|TMPDIR|TZ|PWD|OLDPWD|SHLVL|_|PATH|"
                             r"SHELL|XDG_(CONFIG|DATA|CACHE|STATE)_HOME|XDG_RUNTIME_DIR|__CF_USER_TEXT_ENCODING|"
                             r"CLAUDECODE|CLAUDE_[A-Z0-9_]*|GIT_EDITOR|AI_AGENT|COREPACK_ENABLE_AUTO_PIN|"
                             r"NoDefaultCurrentDirectoryInExePath|GW_MANAGED_DIR|GW_GITCFG_SET|GIT_CONFIG_COUNT|"
                             r"GIT_CONFIG_KEY_\d+|GIT_CONFIG_VALUE_\d+|GIT_SSH_COMMAND|RSYNC_RSH|"
                             r"PROBE_ENVFILE|GIT_CONFIG_PARAMETERS)")
        extra = sorted(n for n in names if not allowed.fullmatch(n))
        check("route: the command's environment is the curated one (platform, Claude Code's own, the gateway "
              "env file's, the probe's env file; nothing else)", names and not extra, f"unexpected: {extra}")
        cred = [n for n in names if re.search(r"TOKEN|SECRET|PASSW|PASSPHRASE|CRED|API_KEY|CLIENT_KEY|"
                                              r"CLIENT_CERT|AUTH|ANTHROPIC", n)]
        check("route: no credential-looking variable reached the command (GITHUB_TOKEN, ANTHROPIC_API_KEY, "
              "CLAUDE_CODE_MESSAGING_TOKEN, CLAUDE_CODE_CLIENT_KEY_PASSPHRASE were in Claude Code's "
              "environment)", not cred, str(cred))
        rep = scan.Report()
        rep.scan_tree(work, canary)
        check("route: the credential canary in Claude Code's environment is in no file the commands wrote",
              rep.clean(), rep.summary())
        path = files.get("path.txt", "").strip().split(":")
        check("route: PATH starts with the gateway's stand-ins and runtime tools, then system folders; the "
              "probe plugin's bin/ (if Claude Code put it on PATH) last; none of the login PATH",
              len(path) >= 6 and path[0].endswith("/data/bin") and path[1].endswith("/data/managed/bin")
              and path[2:6] == ["/usr/bin", "/bin", "/usr/sbin", "/sbin"]
              and all(p.endswith("/bin") and "/probe/" in p for p in path[6:]), ":".join(path))
        check("route: SHELL is the managed bash", re.search(r"SHELL=.*/data/envs/[0-9a-f]+/\.pixi/envs/default/bin/bash\n",
                                                           files.get("shell.txt", "")) is not None,
              files.get("shell.txt", ""))
        # tool results and exit codes as in the baseline
        bres = base.get("results", [])
        mine = [r for r in res if "result-text-42" in r or "before-exit" in r]
        theirs = [r for r in bres if "result-text-42" in r or "before-exit" in r]
        check("perms: tool results (stdout, stderr) and the exit-code result are identical to the baseline's",
              len(mine) == 2 and mine == theirs, json.dumps({"managed": mine, "baseline": theirs})[:800])
        # hooks
        pre = jl(root / "m1-probe" / "pre.jsonl")
        post = jl(root / "m1-probe" / "post.jsonl")
        cmds = [p.get("tool_input", {}).get("command") for p in pre]
        check("hooks: PreToolUse saw the original commands", ROUTE_CMD in cmds and
              BG_CMD in cmds, json.dumps(cmds)[:600])
        pcmds = [p.get("tool_input", {}).get("command") for p in post]
        presp = [json.dumps(p.get("tool_response", "")) for p in post]
        check("hooks: PostToolUse saw the original command and the command's own output",
              "echo result-text-$((6*7)); echo to-stderr >&2" in pcmds and any("result-text-42" in x for x in presp),
              json.dumps(pcmds)[:600])
        menv = (root / "m1-probe" / "pre-env.txt").read_text() if (root / "m1-probe" / "pre-env.txt").exists() else ""
        a, b = norm_env(menv), norm_env(base.get("hook_env", ""))
        check("hooks: the probe's string-form hook (through gate-sh) has the baseline's $0 and environment, "
              "but for the gateway mod's three variables and per-session values",
              a == b and "ZERO=/bin/sh" in a, json.dumps({"only_managed": sorted(set(a) - set(b)),
                                                          "only_baseline": sorted(set(b) - set(a))}))
        check("hooks: the gateway mod's prefix is visible to hooks (as Claude Code passes its environment)",
              any(ln.startswith("CLAUDE_CODE_SHELL_PREFIX=") and ln.endswith("/hooks/gate-sh") for ln in menv.splitlines()))
        if want("route"):
            b_ok, i_ok = bang_and_inject(s, work)
            files = files_of(work)
            check("route: the user's ! command ran in the managed bash (not the login shell) with the env file",
                  b_ok and re.fullmatch(r"bang:5\.[^:]*::from-the-probe-env-file:\S*" + re.escape(MANAGED_BASH) + r"\n",
                                        files.get("bang.txt", "")) is not None,
                  files.get("bang.txt", ""))
            check("route: a skill's ! injection ran in the managed bash with the env file",
                  i_ok and re.fullmatch(r"inj:5\.[^:]*:from-the-probe-env-file:\S*" + re.escape(MANAGED_BASH) + r"\n",
                                        files.get("inj.txt", "")) is not None,
                  files.get("inj.txt", ""))
            bb = base.get("files", {})
            note(f"baseline ! and injection are not run (the baseline session doesn't type them); "
                 f"baseline bg.txt: {bb.get('bg.txt', '').strip()!r}")
            # the doctor (immediate, no model turn) and gate status name the managed shell
            s.submit("/gate-doctor")
            ok = wait(s, lambda: "Managed shell: on; this session: active" in re.sub(r"\s+", " ", s.all_text()), 30)
            check("route: /gate-doctor says the managed shell is active in this session, with its PATH",
                  ok and "PATH:" in s.all_text(), s.text()[-1500:])
            s.api.push(bash("gate status", "gateway status"), "status shown",
                       {"tool": "mcp__plugin_gate_gw__host_inspect", "input": {}}, "inspected")
            s.submit("show the gateway status")
            wait(s, lambda: "status shown" in s.text(), 60)
            s.pump(1)
            s.submit("inspect the host")
            wait(s, lambda: "inspected" in s.text(), 60)
            s.pump(1)
            res = results_text(s.api)
            st = next((r for r in res if "Managed shell:" in r), "")
            check("route: gate status (run in the managed bash) lists the managed shell's PATH with origins",
                  "Managed shell: on" in st and "(the gateway's stand-ins)" in st and "(system)" in st, st[-1200:])
            hi = next((r for r in res if '"login_path"' in r), "")
            check("route: the gw host_inspect tool answers read-only (login PATH folders, toolchains, the "
                  "managed PATH), allowed without a prompt", '"how": "read from files' in hi and '"managed"' in hi,
                  hi[:600])
        if want("perms"):
            s.close()
            p = perm_session(root, "m2", h.inst.config_dir, env)
            work = root / "m2" / "work"
            bp = base.get("perm") or {}
            check("perms: the permission dialog shows the original command, never gate-sh",
                  PERM_CMD in p["dialog"] and "gate-sh" not in p["dialog"], p["dialog"][-1200:])
            check("perms: 'don't ask again' wrote a rule for the original command, as in the baseline",
                  bool(p["rule"]) and p["rule"] == bp.get("rule") and not any("gate-sh" in r for r in p["rule"]),
                  json.dumps({"managed": p["rule"], "baseline": bp.get("rule"), "dialog": p["dialog"][-900:]}))
            check("perms: the next matching command ran without a prompt (the rule matched), as in the baseline",
                  p["second_prompted"] is False and bp.get("second_prompted") is False
                  and (work / BY_RULE).exists(), json.dumps({"managed": p["second_prompted"],
                                                                            "baseline": bp.get("second_prompted")}))
        if want("cancel"):
            s.close()
            s = session(root, "m3", h.inst.config_dir, env, [], permission_mode="bypassPermissions")
            s.start()
            s.wait_ready(180)
            c = cancel_steps(s)
            bc = base.get("cancel") or {}
            check("cancel: Escape interrupts a long command: it never finishes and its process is gone, as in "
                  "the baseline", c["interrupt"]["started"] and not c["interrupt"]["file"]
                  and not c["interrupt"]["alive"] and c["interrupt"] == bc.get("interrupt"),
                  json.dumps({"managed": c, "baseline": bc}))
            check("cancel: a Bash timeout stops the command, as in the baseline",
                  not c["timeout"]["file"] and c["timeout"] == bc.get("timeout"),
                  json.dumps({"managed": c, "baseline": bc}))
    finally:
        s.close()


def step_print(root: Path, h, gi, env: dict) -> None:
    print("print: claude -p", flush=True)
    for f in gwe2e.session_gateways(h.inst.config_dir, root / "p-work", []):
        gwe2e.verify(f, h.inst.config_dir)
    api = FakeAPI(root / "p-api", replies=[bash('echo "print:$BASH_VERSION:${BASH-}"', "print probe"), "print done"])
    api.start()
    try:
        for d in ("p-work", "p-tmp", "p-home"):
            (root / d).mkdir(exist_ok=True)
        rt = safety.short_runtime_dir()
        penv = safety.hermetic_env(config_dir=h.inst.config_dir, home=root / "p-home",
                                   tmpdir=root / "p-tmp", base_url=api.url, runtime_dir=rt,
                                   extra={**env, **gi.env()})
        try:
            r = subprocess.run([driver.find_claude(), "-p", "run the probe", "--permission-mode",
                                "bypassPermissions"], cwd=root / "p-work", env=penv, capture_output=True,
                               text=True, timeout=300)
        finally:
            shutil.rmtree(rt, ignore_errors=True)
        res = results_text(api)
        check("print: in claude -p the command ran in the managed bash 5",
              r.returncode == 0 and any(re.search(r"print:5\.\d[^:]*:\S*" + re.escape(MANAGED_BASH), x) for x in res),
              json.dumps(res)[:400])
    finally:
        api.stop()


def step_nomods(root: Path, env: dict, src: Path) -> None:
    """The gateway without its mod (modules removed from hooks.json)."""
    print("nomods: the gateway with no mod", flush=True)
    copy = root / "gateway-nomods"
    install.snapshot_tree(REPO, copy)
    hj = copy / "plugins" / "gateway" / "hooks" / "hooks.json"
    d = json.loads(hj.read_text())
    d.pop("modules", None)
    hj.write_text(json.dumps(d, indent=2))
    with install.Hermetic(root / "hn", extra_env=env) as h:
        gi = h.install_gateway_e2e(copy)
        h.install_from(src, repo="managed-probe", plugin="probe")
        ok, detail = prebuild_env(root, h, gi, env)
        if not check("nomods: the env is built", ok, detail):
            return
        replies = [bash('echo "nm:${BASH_VERSION-}:${ZSH_VERSION-}" > nm.txt', "no-mods probe"), "denied turn"]
        s = session(root, "n1", h.inst.config_dir, env, replies, permission_mode="bypassPermissions")
        s.start()
        try:
            s.wait_ready(180)
            s.submit("run it")
            wait(s, lambda: len(s.api.main_requests()) >= 2, 60)
            s.pump(2)
            res = results_text(s.api)
            check("nomods: managed mode (the default) denies Bash with 'managed shell unavailable', nothing ran",
                  any("managed shell unavailable" in r and "mods" in r for r in res)
                  and not (s.cwd / "nm.txt").exists(), json.dumps(res)[:800])
            s.send("!")
            s.pump(0.5)
            s.type('echo "nmbang:${BASH_VERSION-}:${ZSH_VERSION-}:${BASH-}" > nmbang.txt')
            s.enter()
            wait(s, lambda: (s.cwd / "nmbang.txt").exists(), 30)
            got = (s.cwd / "nmbang.txt").read_text() if (s.cwd / "nmbang.txt").exists() else ""
            check("nomods: a ! command (no hook sees it) runs in Claude Code's own shell: the documented limit",
                  bool(got) and MANAGED_BASH not in got, got)
        finally:
            s.close()
        # an approved "warn" (seeded: no dialog can open without the mod)
        (gi.gateway_home).mkdir(parents=True, exist_ok=True)
        (gi.gateway_home / "gateway.toml").write_text('[shell]\nmanaged = "warn"\n')
        r = seed(gi, "consent.approve('settings', form=consent.load_form())\n"
                     "print(managed.load_state()['mode'])")
        check("nomods: managed = \"warn\" approved in the scratch vault (seeded)", r.stdout.strip() == "warn",
              r.stderr[-400:])
        replies = [bash('echo "w1:${BASH_VERSION-}:${ZSH_VERSION-}:${BASH-}" > w1.txt', "warn probe 1"), "warn 1",
                   bash('echo "w2" > w2.txt', "warn probe 2"), "warn 2"]
        s = session(root, "n2", h.inst.config_dir, env, replies, permission_mode="bypassPermissions")
        s.start()
        try:
            s.wait_ready(180)
            s.submit("run it")
            wait(s, lambda: (s.cwd / "w1.txt").exists(), 60)
            wait(s, lambda: "warn 1" in s.text(), 30)
            s.pump(2)
            s.submit("run the second")
            ok = wait(s, lambda: (s.cwd / "w2.txt").exists(), 60)
            s.pump(3)
            screen = s.all_text() if hasattr(s, "all_text") else s.text()
            w1 = (s.cwd / "w1.txt").read_text() if (s.cwd / "w1.txt").exists() else ""
            check("nomods warn: commands run (in Claude Code's own shell, not the managed bash)",
                  ok and bool(w1) and MANAGED_BASH not in w1, w1)
            flat = re.sub(r"\s+", " ", screen)
            n = flat.count("the managed shell isn't active in this session")
            tn = sum(t.read_text().count("the managed shell isn't active in this session") for t in s.transcripts())
            check("nomods warn: a visible notice, once in the session", n == 1 or (n == 0 and tn == 1),
                  f"{n} on screen, {tn} in the transcript\n{screen[-1500:]}")
        finally:
            s.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
