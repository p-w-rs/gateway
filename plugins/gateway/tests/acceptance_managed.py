#!/usr/bin/env python3
"""PLAN-v4 phase 4 and PLAN-0.11 §1.6-1.8 in the real TUI: managed execution
(brief 3, 8, 14.6).

    pixi exec --spec python --spec pyte python tests/acceptance_managed.py \\
        --tmp DIR [--keep] [--pixi-cache DIR] [--only a,b,...]

The gateway is installed the normal way through the TUI harness's e2e route
(tests/tui: a git-source marketplace in a scratch Claude config, the e2e
marker that keeps every gateway location in a scratch root), next to a probe
plugin ("probe") whose string-form hooks write their environment, $0 and
payloads, whose SessionStart hook writes an env file, with a bin/ program and
a skill with ! injection. Sessions run against the harness's fake Messages
API; HOME is scratch, with rc files that define a function, an alias, a
variable, and a function and an alias named ssh (the shell snapshot Claude
Code makes from them carries them). The sessions' environment holds the
user's own SSH_AUTH_SOCK and GH_TOKEN (fake values), a plain variable,
BASH_ENV, and a synthetic credential canary in one of Claude Code's own
variables (CLAUDE_CODE_CLIENT_KEY_PASSPHRASE). gateway.toml configures one
host (box.invalid, approved here: no dialog), so the ssh stand-in exists;
e2e.json's user_tools names recording fakes for the user's own ssh. The
gateway's pixi env is built before any session.

Sections (a baseline config has only the probe plugin, for comparison):

  route    every route Claude Code runs commands by goes through gate-sh into
           the managed bash (bash 5 from the gateway env): the Bash tool,
           run_in_background, a subagent's Bash, the user's ! command, a
           skill's ! injection; the user's environment kept (SSH_AUTH_SOCK,
           GH_TOKEN, the plain variable) and Claude Code's credential
           variables and BASH_ENV removed (the canary reaches no command);
           the user's function from the snapshot when Claude Code made a bash
           snapshot (which shell made it is recorded); PATH: the stand-ins
           first, then the snapshot's PATH, the probe plugin's bin/ and its
           env file kept; the ssh stand-in is what `ssh` names, whatever the
           rc's ssh alias and function say; and one more session with
           SHELL=/bin/bash, so Claude Code makes a bash snapshot (the rc
           sources only a bash one) holding that alias and function: the
           user's function is there and `ssh` still names the stand-in
  passthru a by-path ssh to the configured host is refused (a route around the
           stand-in), while `ssh` to a host nothing configures runs the user's
           own ssh (the recording fake) with the full argv
  hooks    the probe plugin's string-form hooks run through the prefix with
           the same $0 and environment as in the baseline (but the
           variables the gateway's mod sets); PreToolUse and PostToolUse see
           the original command
  perms    default permission mode: the dialog shows the original command,
           "don't ask again" writes a rule for the original command, and the
           next matching command runs without a prompt; results and exit
           codes as in the baseline
  gitask   bypassPermissions mode, a git push to the URL of a host set to
           ssh = "ask" (PLAN-0.11 §6.5, requirement 24): Claude Code prompts
           (only a hook's ask does in that mode) with the gateway's reason;
           declined, nothing ran
  cancel   an interrupt (Escape) and a Bash timeout stop a long command (the
           file it would write never appears, its process is gone), as in the
           baseline
  print    claude -p: the prefix is set and the command runs in the managed bash
  notready the managed shell not ready (its rc file moved away for one
           command): the command runs without the managed settings (no rc
           in place of the snapshot's source, SHELL not the managed bash),
           in the shell that made the session's snapshot (a bash one:
           CLAUDE_CODE_SHELL, here the env's bash), with the gateway's
           one-line notice naming that shell and why (settings missing, not
           "still setting up"), Claude Code's credential still removed
  nomods   the gateway installed with "modules" removed from hooks.json (no
           mod): Bash runs in Claude Code's own shell with the gateway's notice
           once per session, and the gateway still judges each command (a read
           of its private folder is denied); a ! command runs in Claude Code's
           own shell

Monitor isn't offered by Claude Code 2.1.301 against the fake API (a
server-side feature gate); its commands use the same shell path (code
evidence in docs/dev/modules/managed.md). Prints one line per check and a JSON
summary to --tmp/acceptance-managed.json (with the shells that made the
snapshots); exits non-zero on any failure.
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
import acceptance_lib as L  # noqa: E402
from tui import driver, gwe2e, install, safety, scan  # noqa: E402
from tui.fakeapi import FakeAPI, tool_results  # noqa: E402

RESULTS: list[dict] = []
NOTES: list[str] = []
SUMMARY: dict = {}           # facts for the JSON summary (which shells made the snapshots)
PREBUILD_TIMEOUT = 1800
# what differs between a hook's environment with the gateway and without it:
# the gateway mod's own variables (SHLVL too since 0.9.1, where Claude Code
# runs without it: the harness's allowlisted environment), and per-session values
VOLATILE = re.compile(r"^(CLAUDE_CODE_SHELL_PREFIX|CLAUDE_CODE_SHELL|GW_MANAGED_DIR|SHLVL|"
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
# gate-sh's not-ready reason once the env is built (gw_setup_state)
NOT_READY_SETTINGS = "settings are missing or couldn't be renewed"
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
    # (the ssh function first: defined after the alias, its name would be alias-expanded)
    rc = ("userfunc() { echo user-function; }\nalias ll='ls -l'\nexport RC_VAR=from-the-user-rc\n"
          "ssh() { echo user-function-ssh; }\nalias ssh='echo user-alias-ssh'\n"
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
             'echo "$PATH" > path.txt; echo "SHELL=$SHELL" > shell.txt; '
             "{ command -v ssh; type -t ssh; } > ssh-is.txt 2>&1")
# the sessions' environment: the user's own (kept in Claude's shell since 0.11, PLAN-0.11
# §1.6, §1.10; fake values) and a startup vector (removed by name)
USER_ENV = {"GH_TOKEN": "acc-fake-gh-token-not-a-secret", "ACC_USER_VAR": "from-the-users-environment"}
FAKE_HOST = "box.invalid"          # the configured host (approved here; never reachable)
# gateway.toml: that host, and one set to ssh = "ask" at a closed port (the gitask section)
FORM = (f'[hosts.box]\naddress = "tester@{FAKE_HOST}"\n\n'
        '[hosts.boxask]\naddress = "tester@127.0.0.1:9"\nssh = "ask"\n')
ASK_PUSH = "git -C pushprobe push boxask:repo.git HEAD:refs/heads/main"


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
               "notes": NOTES, **SUMMARY}
    out = Path(a.tmp) / "acceptance-managed.json"
    out.write_text(json.dumps(summary, indent=1))
    print(f"\n{summary['passed']} passed, {summary['failed']} failed in {summary['seconds']} s; {out}")
    if not a.keep:
        shutil.rmtree(root, ignore_errors=True)
    return 1 if failed else 0


def session(root: Path, name: str, cfg: Path, env: dict, replies, shell: str | None = None,
            **kw) -> driver.Session:
    """A session with a scratch HOME (make_home's rc files) and SHELL, which
    picks the shell Claude Code makes its snapshot with: zsh where /bin/zsh
    exists (every macOS), unless `shell` says otherwise."""
    home = root / f"{name}-home"
    home.mkdir(parents=True, exist_ok=True)
    make_home(home, root / f"{name}-rc-ran")
    out = root / f"{name}-probe"
    out.mkdir(exist_ok=True)
    sh = shell or ("/bin/zsh" if os.path.exists("/bin/zsh") else "/bin/bash")
    s = driver.Session(root / name, config_dir=cfg, home=home,
                       extra_env={**env, "PROBE_OUT": str(out), "SHELL": sh},
                       replies=replies, debug_file=True, cols=160, rows=48, start=False, **kw)
    return s


def run(root: Path, env: dict, canary: scan.Canary, only: set[str]) -> None:
    want = (lambda x: not only or x in only)
    src = root / "probe-src"
    make_probe_repo(src)
    # One of Claude Code's own credential variables holds the canary (its mTLS key
    # passphrase; the key itself isn't set, so Claude Code doesn't use it): gate-sh removes
    # it by name. The user's own variables and BASH_ENV (a startup vector, removed) beside it.
    (root / "bash-env.sh").write_text(": the BASH_ENV of the sessions\n")
    cred_env = {"CLAUDE_CODE_CLIENT_KEY_PASSPHRASE": canary.value, **USER_ENV,
                "SSH_AUTH_SOCK": str(root / "fake-agent.sock"), "BASH_ENV": str(root / "bash-env.sh")}
    # the baseline: only the probe plugin
    base = {}
    with install.Hermetic(root / "hb", extra_env=env) as hb:
        hb.install_from(src, repo="managed-probe", plugin="probe")
        if want("route") or want("hooks") or want("perms") or want("cancel"):
            base = baseline(root, hb, {**env, **cred_env}, want)
    with install.Hermetic(root / "h", extra_env=env) as h:
        # the user's own ssh for the pass-through: a recording fake (e2e.json's user_tools)
        fakes = L.write_user_tools(root / "user-tools", ("ssh", "scp", "sftp", "git"), sys.executable)
        gi = h.install_gateway_e2e(REPO, e2e_config={"user_tools": str(fakes)})
        check("the gateway is installed through the e2e route (marker proven)", gi.proof is not None)
        h.install_from(src, repo="managed-probe", plugin="probe")
        ok, detail = prebuild_env(root, h, gi, env)
        if not check("the gateway's pixi env (with bash) is built before any session", ok, detail):
            return
        note(detail.splitlines()[0])
        check("the env's build wrote the managed shell's files (launch.sh managed_sync)",
              (gi.root / "data" / "managed" / "conf").is_file(), str(sorted(gi.root.glob("data/managed/*"))))
        # one configured host, so the ssh stand-in exists (approved here: no dialog opens in a test
        # step that doesn't answer one)
        gi.gateway_home.mkdir(parents=True, exist_ok=True)
        (gi.gateway_home / "gateway.toml").write_text(FORM)
        r = seed(gi, "from gateway import vault\n"
                     "if not vault.exists():\n    vault.ensure_key()\n    vault.save(vault.empty())\n"
                     "consent.approve('box', form=consent.load_form())\n"
                     "consent.approve('boxask', form=consent.load_form())\n"
                     "e = consent.compute(consent.load_form(), vault.load())\n"
                     "print('approved' if not e.pending and 'box' in e.hosts else 'pending')")
        check("the configured host is approved in the scratch vault (seeded)",
              r.stdout.strip().endswith("approved"), (r.stdout + r.stderr)[-400:])
        if want("route") or want("hooks") or want("perms") or want("cancel") or want("passthru"):
            managed_session(root, h, gi, {**env, **cred_env}, canary, base, want, fakes)
        if want("route"):
            step_bash_snapshot(root, h, {**env, **cred_env}, canary)
        if want("print"):
            step_print(root, h, gi, env)
        if want("gitask"):
            step_git_ask(root, h, {**env, **cred_env}, canary, fakes)
        if want("notready"):
            step_notready(root, h, gi, {**env, **cred_env}, canary)
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
    s.pump(12)              # waits read the pty: Claude Code writes to it synchronously
    pid = (s.cwd / "long.pid").read_text().strip() if (s.cwd / "long.pid").exists() else ""
    alive = bool(pid) and subprocess.run(["ps", "-p", pid], capture_output=True).returncode == 0
    out["interrupt"] = {"started": started, "file": (s.cwd / "after-interrupt.txt").exists(), "alive": alive}
    s.api.push(bash("sleep 9; touch after-timeout.txt", "a timed-out command", timeout=2000), "timeout turn")
    s.submit("run the timed command")
    wait(s, lambda: "timeout turn" in s.text(), 60)
    s.pump(9)
    out["timeout"] = {"file": (s.cwd / "after-timeout.txt").exists()}
    return out


def managed_session(root: Path, h, gi, env: dict, canary: scan.Canary, base: dict, want,
                    fakes: Path) -> None:
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
        # PLAN-0.11 §1.6: the rc sources a bash snapshot (the user's functions and aliases);
        # a zsh snapshot gives only its PATH (a stated limit). Which shell made it, on the
        # latest Claude Code, is recorded here.
        shells = L.snapshot_shells(h.inst.config_dir)
        note(f"the shell snapshots in the gateway session's config were made by: {shells or 'none found'}")
        SUMMARY["snapshot_shells"] = shells
        check("route: Claude Code made a shell snapshot (recorded: which shell made it)", bool(shells))
        bash_snap = bool(shells) and shells[-1] == "bash"
        check("route: the Bash tool ran in the managed bash 5 with the probe's env file and its bin/ "
              "program, and the user's function from the snapshot exactly when Claude Code made a bash "
              "snapshot",
              re.search(r"route:bash=5\.\d+[^:]*:zsh=:pe=from-the-probe-env-file:rc=[^:]*:bp=\S*"
                        + re.escape(MANAGED_BASH) + r"\n", route + "\n") is not None
              and ("has-userfunc" in route) == bash_snap and "probe-bin-tool-ran" in route, route[:400])
        note(f"the user rc's exported variable in the command: {'yes' if 'rc=from-the-user-rc' in route else 'no'} "
             "(a snapshot carries functions, aliases and PATH)")
        check("route: run_in_background ran in the managed bash",
              re.fullmatch(r"bg:5\.[^:]*:\S*" + re.escape(MANAGED_BASH) + r"\n", files.get("bg.txt", "")) is not None,
              files.get("bg.txt", ""))
        check("route: a subagent's Bash ran in the managed bash with the env file",
              re.fullmatch(r"sub:5\.[^:]*:from-the-probe-env-file:\S*" + re.escape(MANAGED_BASH) + r"\n",
                           files.get("sub.txt", "")) is not None,
              files.get("sub.txt", ""))
        names = set(files.get("names.txt", "").split())
        kept = ["GH_TOKEN", "ACC_USER_VAR", "SSH_AUTH_SOCK", "GW_MANAGED_DIR"]
        check("route: the user's own environment reaches the command (SSH_AUTH_SOCK, GH_TOKEN, a plain "
              "variable; PLAN-0.11 §1.6), and GW_MANAGED_DIR (a nested claude stays managed)",
              bool(names) and all(n in names for n in kept), f"missing: {[n for n in kept if n not in names]}")
        gone = sorted(n for n in names if n in ("BASH_ENV", "ENV", "ANTHROPIC_API_KEY",
                                                 "CLAUDE_CODE_CLIENT_KEY_PASSPHRASE")
                      or n.startswith("BASH_FUNC_") or (n.startswith("GW_") and n != "GW_MANAGED_DIR")
                      or (re.match(r"(CLAUDE|ANTHROPIC)_", n)
                          and re.search(r"TOKEN|SECRET|PASSW|PASSPHRASE|CRED|API_KEY|CLIENT_KEY|CLIENT_CERT|AUTH", n)))
        check("route: Claude Code's own credential variables (ANTHROPIC_API_KEY, CLAUDE_CODE_CLIENT_KEY_PASSPHRASE, "
              "...), BASH_ENV and the gateway's internal GW_* names never reach the command", not gone, str(gone))
        rep = scan.Report()
        rep.scan_tree(work, canary)
        check("route: the credential canary in Claude Code's environment is in no file the commands wrote",
              rep.clean(), rep.summary())
        path = files.get("path.txt", "").strip().split(":")
        own = [d for d in s.env.get("PATH", "").split(":") if d.startswith("/") and os.path.isdir(d)]
        check("route: PATH starts with the gateway's stand-ins, then the snapshot's PATH (the system "
              "folders in it), no runtime-tools folder (PLAN-0.11 §1.6)",
              bool(path) and path[0].endswith("/data/bin") and "/usr/bin" in path
              and not any(p.endswith("/data/managed/bin") for p in path), ":".join(path))
        note(f"the session's PATH folders in the command's PATH: {sum(d in path for d in own)} of {len(own)} "
             "(the snapshot's PATH is the login shell's)")
        check("route: SHELL is the managed bash", re.search(r"SHELL=.*/data/envs/[0-9a-f]+/\.pixi/envs/default/bin/bash\n",
                                                           files.get("shell.txt", "")) is not None,
              files.get("shell.txt", ""))
        ssh_is = files.get("ssh-is.txt", "").split()
        check("route: `ssh` names the gateway's ssh stand-in (a configured host exists), not the rc's ssh "
              "alias or function (the rc's tail removes them; PLAN-0.11 §1.6)",
              len(ssh_is) >= 2 and ssh_is[0].endswith("/data/bin/ssh") and ssh_is[1] == "file",
              files.get("ssh-is.txt", ""))
        bfiles = base.get("files", {})
        note(f"baseline: `ssh` there is {' '.join(bfiles.get('ssh-is.txt', '').split())[:80]!r} (the snapshot's alias)")
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
              "but for the gateway mod's variables and per-session values",
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
                  "Managed shell: on" in st and "(the gateway's stand-ins)" in st and "(your own PATH" in st, st[-1200:])
            hi = next((r for r in res if '"login_path"' in r), "")
            check("route: the gw host_inspect tool answers read-only (login PATH folders, toolchains, the "
                  "managed PATH), allowed without a prompt", '"how": "read from files' in hi and '"managed"' in hi,
                  hi[:600])
        if want("passthru"):
            passthru_steps(s, work, fakes)
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


BASH_SNAP_CMD = ("type userfunc >/dev/null 2>&1 && echo has-userfunc > bs-func.txt || echo no-userfunc > bs-func.txt; "
                 "{ command -v ssh; type -t ssh; } > bs-ssh.txt 2>&1")


def step_bash_snapshot(root: Path, h, env: dict, canary: scan.Canary) -> None:
    """PLAN-0.11 §1.6, §14 where Claude Code makes a bash snapshot (SHELL=/bin/bash):
    the gateway rc sources it, so the user's function reaches the command, and
    `ssh` still names the stand-in, not the snapshot's ssh alias or function
    (the rc's tail removes them). The route session's SHELL is zsh wherever
    /bin/zsh exists, and the rc sources only a bash snapshot, so only here are
    the alias and the function really in the way."""
    print("route: a session whose shell snapshot bash made (SHELL=/bin/bash)", flush=True)
    if not os.path.exists("/bin/bash"):
        check("route (bash snapshot): /bin/bash exists", False)
        return
    cfg = h.inst.config_dir
    before = L.snapshot_files(cfg)
    s = session(root, "m6", cfg, env, [bash(BASH_SNAP_CMD, "bash snapshot probe"), "bash snapshot done"],
                shell="/bin/bash", permission_mode="bypassPermissions")
    s.redact(canary.value)
    s.start()
    shells: list[str] = []
    new: list[Path] = []
    text = ""
    try:
        s.wait_ready(180)
        s.submit("probe the bash snapshot")
        ran = wait(s, lambda: (s.cwd / "bs-ssh.txt").exists(), 60)
        s.pump(2)
        # read while the session runs: Claude Code 2.1.310 removes a session's snapshot
        # when the session ends ("Cleaned up session snapshot" in its debug log)
        shells = L.snapshot_shells(cfg, skip=before)
        new = [p for p in L.snapshot_files(cfg) if p not in before]
        text = "\n".join(p.read_text(errors="replace") for p in new)
    finally:
        s.close()
    SUMMARY["snapshot_shells_bash_session"] = shells
    check("route (bash snapshot): Claude Code made a bash snapshot for the session (SHELL=/bin/bash), and it "
          "holds the rc's ssh alias or function", shells == ["bash"]
          and ("user-alias-ssh" in text or "user-function-ssh" in text), f"shells {shells}; {len(new)} new file(s)")
    func = (s.cwd / "bs-func.txt").read_text().strip() if (s.cwd / "bs-func.txt").exists() else ""
    check("route (bash snapshot): the managed bash sourced the bash snapshot (the user's function is there)",
          ran and func == "has-userfunc", func)
    got = (s.cwd / "bs-ssh.txt").read_text() if ran else ""
    ssh_is = got.split()
    check("route (bash snapshot): `ssh` still names the gateway's ssh stand-in, not the snapshot's ssh alias or "
          "function (the rc's tail removes them; PLAN-0.11 §1.6)",
          len(ssh_is) >= 2 and ssh_is[0].endswith("/data/bin/ssh") and ssh_is[1] == "file", got)


def passthru_steps(s: driver.Session, work: Path, fakes: Path) -> None:
    """PLAN-0.11 §1.3, §1.7: the configured host by the system's ssh is a route
    around the stand-in (the hook refuses it, in every mode); a host nothing
    configures goes through the ssh stand-in to the user's own ssh (the
    recording fake): the full argv, the recursion guard set."""
    print("passthru: a by-path ssh to the configured host, an unconfigured host", flush=True)
    n0 = len(s.api.main_requests())
    s.api.push(bash(f"/usr/bin/ssh {FAKE_HOST} true; echo by-path-ran > bypath.txt", "the system's ssh"),
               bash("ssh other.invalid echo hi-from-the-fake > pt.txt", "an unconfigured host"),
               "passthru done")
    s.submit("run the ssh checks")
    wait(s, lambda: len(s.api.main_requests()) >= n0 + 3, 120)
    s.pump(2)
    res = results_text(s.api)
    deny = next((r for r in res if L.ROUTE_SSH in r), "")
    check("passthru: the system's ssh to the configured host is refused by the hook (a route around the "
          "stand-in), and nothing ran", bool(deny) and "box" in deny and not (work / "bypath.txt").exists(),
          json.dumps(res[-3:])[:800])
    runs = [r for r in L.user_tool_runs(fakes, "ssh") if r.get("argv") == ["other.invalid", "echo", "hi-from-the-fake"]]
    got = (work / "pt.txt").read_text() if (work / "pt.txt").exists() else ""
    check("passthru: `ssh` to a host nothing configures runs the user's own ssh (the recording fake) with the "
          "full argv, through the stand-in's pass-through (GW_PASSTHRU set)",
          got.strip() == L.FAKE_RAN.format(tool="ssh") and len(runs) == 1
          and str((runs[0].get("env") or {}).get("GW_PASSTHRU", "")).startswith("ssh:1:"),
          json.dumps({"pt.txt": got, "runs": runs[-2:]})[:600])


def step_git_ask(root: Path, h, env: dict, canary: scan.Canary, fakes: Path) -> None:
    """PLAN-0.11 §6.5 (requirement 24): a git push whose URL names a host set to
    ssh = "ask" is asked about by the hook before it runs. In bypassPermissions
    mode Claude Code prompts only for a hook's ask, so the prompt is the
    gateway's; declined, the push never ran (neither the gated git nor the
    user's own git or ssh started)."""
    print("gitask: a git push to an \"ask\" host's URL, bypassPermissions", flush=True)
    work = root / "m5" / "work"
    repo = work / "pushprobe"
    repo.mkdir(parents=True, exist_ok=True)
    git = shutil.which("git") or "/usr/bin/git"
    genv = {"PATH": "/usr/bin:/bin", "HOME": str(root), "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null", "LANG": "C"}
    (repo / "README").write_text("acceptance push probe\n")
    for args in (["init", "-q"], ["add", "README"], ["-c", "user.email=acc@example.com", "-c", "user.name=acc",
                                                     "-c", "commit.gpgsign=false", "commit", "-qm", "probe"]):
        subprocess.run([git, "-C", str(repo), *args], env=genv, capture_output=True, timeout=60)
    n_runs = len(L.user_tool_runs(fakes, with_g=True))
    s = session(root, "m5", h.inst.config_dir, env, [bash(ASK_PUSH, "push the probe"), "push answered"],
                permission_mode="bypassPermissions")
    s.redact(canary.value)
    s.start()
    try:
        s.wait_ready(180)
        s.submit("push it")
        asked = wait(s, lambda: "Do you want to proceed?" in s.text(), 60)
        shown = L.flat(s.text())
        check("gitask: in bypassPermissions mode Claude Code prompts for the push (only a hook's ask does there: "
              "the gateway asked up front)", asked, s.text()[-1200:])
        note(f"gitask: the prompt {'names' if 'boxask' in shown else 'does not name'} boxask (the hook's reason)")
        if asked:
            s.pump(1.0)
            s.send("\x1b")              # declined
            wait(s, lambda: "Do you want to proceed?" not in s.text(), 15)
        s.pump(3.0)
    finally:
        s.close()
    check("gitask: declined, nothing ran (the stand-ins never reached the user's ssh or git: the fakes' log "
          "has no new run)",
          len(L.user_tool_runs(fakes, with_g=True)) == n_runs, json.dumps(L.user_tool_runs(fakes, with_g=True)[n_runs:])[:400])


def step_notready(root: Path, h, gi, env: dict, canary: scan.Canary) -> None:
    """PLAN-0.11 §1.6, §19.15: the managed shell not ready (here its rc file
    moved away for one command): the command runs byte for byte without the
    managed settings, in the shell that made its snapshot (a bash snapshot:
    CLAUDE_CODE_SHELL, which the mod sets to the env's bash once it is
    built; a zsh one: a zsh), with Claude Code's credentials still removed
    and one stderr line naming that shell and why (the rc missing; the env
    is built, so its settings are missing, never "still setting up" or "your
    own shell"); no refusal. Only the managed path sources the rc in place of
    the snapshot (bash's BASH_EXECUTION_STRING then starts with `.`, else
    with the snapshot's `source`): that may not be seen. SHELL tells nothing
    for a bash snapshot: Claude Code (2.1.310) itself gives every Bash-tool
    command SHELL = the shell it runs, CLAUDE_CODE_SHELL here (the env's
    bash, the value the managed path sets too); with a zsh snapshot it must
    not be the env's bash. Nor does PATH: the gateway's session env file,
    which both paths source, puts the stand-ins first."""
    print("notready: the managed shell's rc moved away for one command", flush=True)
    conf = gi.root / "data" / "managed" / "conf"
    rc = next((Path(ln[3:]) for ln in conf.read_text().splitlines() if ln.startswith("rc=")), None) \
        if conf.is_file() else None
    if rc is None or not rc.is_file():
        check("notready: the managed shell's rc is found (managed/conf)", False, str(rc))
        return
    cfg = h.inst.config_dir
    before = L.snapshot_files(cfg)
    s = session(root, "m4", cfg, env, [], permission_mode="bypassPermissions")
    s.redact(canary.value)
    t_start = time.time()
    s.start()
    hidden = rc.with_name(rc.name + ".acc-hidden")
    shells: list[str] = []
    try:
        s.wait_ready(180)
        # the gateway's session start rewrites the managed shell's files (managed.sync: the
        # rc, then conf last); on Claude Code 2.1.310 the prompt is up before it is done, and
        # an rc moved away before then is written again: move it once conf is this session's
        check("notready: this session's start rewrote the managed shell's settings (conf) first",
              wait(s, lambda: conf.is_file() and conf.stat().st_mtime >= t_start, 60))
        s.api.push(bash('echo "nr:${BASH-}:${SHELL-}:${BASH_EXECUTION_STRING%% *}:'
                        '${CLAUDE_CODE_CLIENT_KEY_PASSPHRASE+set}" > nr.txt', "not ready"),
                   "notready done")
        os.rename(rc, hidden)
        s.submit("run it while the shell isn't ready")
        ok = wait(s, lambda: (s.cwd / "nr.txt").exists(), 60)
        wait(s, lambda: "notready done" in s.text(), 30)
        # read while the session runs (2.1.310 removes a session's snapshot when it ends)
        shells = L.snapshot_shells(cfg, skip=before)
    finally:
        if hidden.exists():
            os.rename(hidden, rc)
        s.close()
    got = (s.cwd / "nr.txt").read_text().strip() if ok else ""
    res = results_text(s.api)
    named = next((m.group(1) for r in res for m in [re.search(
        re.escape(L.NOT_READY) + r", in (/.+?): the managed shell isn't ready \(", r)] if m), "")
    bash_snap = shells == ["bash"]
    fields = got.split(":") if got.startswith("nr:") else []
    check("notready: the command ran in the shell that made the session's snapshot, the one the notice names "
          "(a bash snapshot: CLAUDE_CODE_SHELL, the env's bash; a zsh one: a zsh), with Claude Code's "
          "credential still removed",
          ok and len(fields) == 5 and shells in (["bash"], ["zsh"]) and fields[4] == ""
          and ((bash_snap and MANAGED_BASH in named and fields[1] == named)
               or (not bash_snap and "zsh" in named and MANAGED_BASH not in named and fields[1] == "")),
          f"snapshot {shells}; {got!r} / {named!r}")
    check("notready: without the managed settings (the rc wasn't sourced in place of the snapshot: the script "
          "still starts with its own `source`; SHELL is Claude Code's own for its shell: with a bash snapshot "
          "the shell the notice names, with a zsh one not the managed bash)",
          len(fields) == 5 and fields[3] != "." and (fields[3] == "source" or not bash_snap)
          and ((bash_snap and fields[2] == named) or (not bash_snap and MANAGED_BASH not in fields[2])),
          f"{got!r}")
    check("notready: the gateway says so in one line (the command's stderr): its rc missing, and with the env "
          "built its settings missing (not 'still setting up', not 'your own shell')",
          any(L.NOT_READY in r and "its rc file is missing" in r and NOT_READY_SETTINGS in r
              and "still setting up" not in r and "own shell" not in r for r in res), json.dumps(res)[:600])


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


# No mod, so no prefix: pre_bash.sh sends every Bash call to Python. Each probe also has
# a trigger word that runs nothing (`ssh-probe` is an echo's word), so it reaches the hook
# by the word list too, and no real tool ever runs (PLAN-0.11 §13).
NOMODS_FIRST = 'echo ssh-probe > /dev/null; echo "nm:${BASH_VERSION-}:${ZSH_VERSION-}:${BASH-}" > nm.txt'
NOMODS_SECOND = "echo ssh-probe again > nm2.txt"


def step_nomods(root: Path, env: dict, src: Path) -> None:
    """The gateway without its mod (modules removed from hooks.json; PLAN-0.11
    §1.8): no blanket refusal. Bash runs in Claude Code's own shell with the
    gateway's notice once per session, and the classic hook still judges every
    command it sees (a read of the gateway's private folder is denied)."""
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
        priv = gi.gateway_home / "private" / "vault.age"
        # the first command reaches the hook, which tells once; the second reads the private folder
        replies = [bash(NOMODS_FIRST, "no-mods probe"), "probe turn",
                   bash(f"cat '{priv}' > nm-priv.txt", "private read"), "denied turn",
                   bash(NOMODS_SECOND, "second probe"), "second turn"]
        s = session(root, "n1", h.inst.config_dir, env, replies, permission_mode="bypassPermissions")
        s.start()
        try:
            s.wait_ready(180)
            s.submit("run it")
            ran = wait(s, lambda: (s.cwd / "nm.txt").exists(), 60)
            wait(s, lambda: "probe turn" in s.text(), 30)
            s.pump(2)
            got = (s.cwd / "nm.txt").read_text() if ran else ""
            check("nomods: no blanket refusal: the command runs, in Claude Code's own shell (not the managed bash)",
                  ran and MANAGED_BASH not in got, got)
            s.submit("read the vault")
            wait(s, lambda: "denied turn" in s.text(), 60)
            s.pump(2)
            res = results_text(s.api)
            check("nomods: the classic hook still judges: a read of the gateway's private folder is denied",
                  any("private keys and vault" in r for r in res) and not (s.cwd / "nm-priv.txt").exists(),
                  json.dumps(res)[-800:])
            s.submit("run the second")
            wait(s, lambda: (s.cwd / "nm2.txt").exists(), 60)
            wait(s, lambda: "second turn" in s.text(), 30)
            s.pump(3)
            screen = L.flat(s.all_text() if hasattr(s, "all_text") else s.text())
            n = screen.count(L.MANAGED_NOTICE)
            tn = sum(L.flat(t.read_text()).count(L.MANAGED_NOTICE) for t in s.transcripts())
            check("nomods: the gateway's notice (your commands run in your own shell, and the gateway still "
                  "judges them), once in the session", n == 1 or (n == 0 and tn == 1),
                  f"{n} on screen, {tn} in the transcript\n{screen[-1500:]}")
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


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
