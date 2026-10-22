#!/usr/bin/env python3
"""Brief 2 and 14.1 in the real TUI: both plugins installed the normal way,
first-use provisioning, interrupted setup, warm start, later updates after a
restart, uninstall, arbitrary working directories and paths with spaces and
non-ASCII letters.

    pixi exec --spec python=3.12 --spec pyte python tests/acceptance_install.py \\
        --tmp DIR [--keep] [--checkpoint DIR] [--only prereq,cold,warm,update,uninstall,spaced]

Prerequisites as a user has them: a scratch bin folder with only `claude`
and `pixi` (a recording wrapper around the real pixi: every call is logged;
in "fail" mode it refuses every call), `git` from `pixi global install git`
into a scratch PIXI_HOME (the documented route; its bin folder is on PATH as
pixi's installer puts it), and the OS folders (/usr/bin:/bin:/usr/sbin:/sbin).
Recording shims named python3, python, node, npm, npx and uv come first on
PATH: a plugin that ran an undeclared interpreter by name is logged. A cold,
scratch pixi cache (nothing downloaded before), so the first session really
provisions.

The gateway goes through the TUI harness's e2e route (tests/tui: a
git-source marketplace, the marker that keeps every gateway location in a
scratch root; its config dir must be a plain path, so the spaced paths are
the project's here, and the spaced config dir is checkpoint's), checkpoint
the plain way (check@checkpoint). Sessions run against the harness's fake
Messages API.

  prereq    the git route: `pixi global install git` (scratch PIXI_HOME) gives
            the only git on the session PATH besides the OS's; the plugins'
            marketplaces are added and installed with it
  cold      session 1 in a project folder with a space and a non-ASCII letter:
            both plugins start provisioning by themselves and say so (the
            gateway on its status line, checkpoint in the prompt footer;
            sampled); mid-build, every pixi install, its builder
            and claude are SIGKILLed (the interrupted setup); session 2 (a
            restart) takes the stale build locks over, finishes, never runs two
            builds of one env at once, and the plugins work: a Bash command
            runs in the gateway's managed bash in that folder, checkpoint
            journals the session with that folder
  warm      session 3 with pixi refusing every call and every non-loopback
            HTTP(S) request sent to a dead proxy (offline): ready at once, no
            pixi call; startup measured against a session with no plugins
  update    new versions of both are published; after Claude Code exited,
            `claude plugin marketplace update` + `claude plugin update` run
            with the same PATH (no bootstrap environment, no pixi exec
            wrapper); session 4 (pixi still refusing) runs the new versions
            on the existing environments (same lock: no rebuild), the journal
            and the gateway's form kept; then a checkpoint update whose lock
            changed: it keeps recording on the old runtime while the new one
            builds
  uninstall `uninstall --keep-data` keeps checkpoint's data (a reinstall builds
            nothing), `uninstall` removes it while its journal (CHECKPOINT_HOME)
            stays; the gateway's uninstall (its data is in the e2e root here, so
            the plugin-data removal is checked on the Linux VM's plain install)
  spaced    checkpoint alone in a config folder with a space and a non-ASCII
            letter (its cache and data paths have them), first-use provisioning
            there, sessions from two other such folders: each recorded with its
            own folder
  vmdrain   (only on the disposable Linux VM, ACCEPTANCE_DISPOSABLE_VM=1, not in
            the default list) both plugins installed plainly into one config;
            a warm session starts a gateway job and opens a terminal and runs a
            Bash probe under a planted ~/.bashrc (Claude Code without SHLVL, as
            the harness starts it: the rc must not run for the command); then a
            plain `claude plugin uninstall` of both while they run: gated
            drains (contract.json gone, gated and the work still running), and
            once the job and the terminal end gated, its tmux server and
            gw-watch go; the same with `--keep-data` (its data folder kept)

Prints one line per check, keeps evidence (status samples, timings, the pixi
and shim logs, `claude plugin` calls) in --tmp/acceptance-install.json; exits
non-zero on any failure.
"""
from __future__ import annotations

import argparse
import contextlib
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
from tui import driver, install, safety  # noqa: E402

RESULTS: list[dict] = []
NOTES: list[str] = []
SUMMARY: dict = {}
BUILD_TIMEOUT = 1800
SHIMMED = ("python3", "python", "node", "npm", "npx", "uv")


def check(name: str, ok, detail: str = "") -> bool:
    ok = bool(ok)
    RESULTS.append({"check": name, "ok": ok, **({"detail": detail[:1500]} if detail and not ok else {})})
    print(f"  {'ok  ' if ok else 'FAIL'} {name}" + ("" if ok or not detail else f"\n       {detail[:1500]}"),
          flush=True)
    return ok


def note(text: str) -> None:
    NOTES.append(text)
    print(f"  note {text}", flush=True)


def wait(s: driver.Session | None, cond, timeout: float, step: float = 0.5) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            if cond():
                return True
        except Exception:  # noqa: BLE001 - a condition reading files mid-write
            pass
        if s is not None:
            s.pump(step)
        else:
            time.sleep(step)
    try:
        return bool(cond())
    except Exception:  # noqa: BLE001
        return False


def ps_rows() -> list[tuple[int, int, str]]:
    out = subprocess.run(["ps", "-A", "-ww", "-o", "pid=,ppid=,command="], capture_output=True,
                         text=True).stdout
    rows = []
    for ln in out.splitlines():
        parts = ln.strip().split(None, 2)
        if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit():
            rows.append((int(parts[0]), int(parts[1]), parts[2]))
    return rows


# ---------------------------------------------------------------------------
# Prerequisites: claude + pixi (+ pixi's git), nothing else
# ---------------------------------------------------------------------------


class Prereqs:
    def __init__(self, root: Path):
        self.root = root
        self.bin = root / "bin"
        self.shims = root / "shims"
        self.pixi_home = root / "pixi-home"
        self.cache = root / "pixi-cache-cold"
        self.pixi_log = root / "pixi-calls.log"
        self.shim_log = root / "shim-calls.log"
        self.fail_flag = root / "pixi-refuses"
        self.slow_flag = root / "pixi-slow"          # `pixi install` waits 6 s first (a slow network's start)
        for d in (self.bin, self.shims, self.pixi_home, self.cache):
            d.mkdir(parents=True, exist_ok=True)
        self.pixi_log.write_text("")
        self.shim_log.write_text("")
        real_pixi = shutil.which("pixi")
        if not real_pixi:
            raise RuntimeError("pixi is not on PATH")
        self.real_pixi = os.path.realpath(real_pixi)
        os.symlink(os.path.realpath(driver.find_claude()), self.bin / "claude")
        (self.bin / "pixi").write_text(
            "#!/bin/sh\n"
            f"printf '%s\\t%s\\t%s\\n' \"$(date +%s)\" \"$$\" \"$*\" >> '{self.pixi_log}'\n"
            f"if [ -e '{self.fail_flag}' ]; then echo 'pixi (acceptance shim): refused' >&2; exit 1; fi\n"
            f"if [ -e '{self.slow_flag}' ] && [ \"$1\" = install ]; then sleep 6; fi\n"
            f"exec '{self.real_pixi}' \"$@\"\n")
        os.chmod(self.bin / "pixi", 0o755)
        for name in SHIMMED:
            real = shutil.which(name, path="/usr/bin:/bin:/usr/sbin:/sbin") or ""
            body = (f"#!/bin/sh\nprintf '%s\\t%s\\n' '{name}' \"$*\" >> '{self.shim_log}'\n"
                    + (f"exec '{real}' \"$@\"\n" if real else "exit 127\n"))
            (self.shims / name).write_text(body)
            os.chmod(self.shims / name, 0o755)

    @property
    def path(self) -> str:
        return ":".join([str(self.shims), str(self.bin), str(self.pixi_home / "bin"),
                         "/usr/bin", "/bin", "/usr/sbin", "/sbin"])

    def env(self) -> dict:
        return {"PATH": self.path, "PIXI_CACHE_DIR": str(self.cache), "PIXI_HOME": str(self.pixi_home)}

    def pixi_calls(self, since: float = 0.0) -> list[str]:
        out = []
        for ln in self.pixi_log.read_text().splitlines():
            t, _, rest = ln.partition("\t")
            if t.isdigit() and int(t) >= int(since):
                out.append(rest.partition("\t")[2])
        return out

    def install_git(self) -> tuple[bool, str]:
        env = {"PATH": f"{self.bin}:/usr/bin:/bin", "HOME": str(self.root / "pg-home"),
               "PIXI_HOME": str(self.pixi_home), "PIXI_CACHE_DIR": str(self.cache),
               "PIXI_NO_PATH_UPDATE": "1", "LANG": "C.UTF-8", "TMPDIR": str(self.root / "pg-tmp")}
        for d in ("pg-home", "pg-tmp"):
            (self.root / d).mkdir(exist_ok=True)
        t0 = time.time()
        r = subprocess.run([str(self.bin / "pixi"), "global", "install", "git"], env=env,
                           capture_output=True, text=True, timeout=900)
        SUMMARY["pixi_global_git_s"] = round(time.time() - t0, 1)
        return r.returncode == 0 and (self.pixi_home / "bin" / "git").exists(), (r.stdout + r.stderr)[-800:]


# ---------------------------------------------------------------------------
# Environments of both plugins
# ---------------------------------------------------------------------------


def envs(data: Path) -> list[Path]:
    return sorted(p for p in data.glob("envs/*") if p.is_dir() and not p.name.endswith(".building"))


def ready_envs(data: Path) -> list[Path]:
    return [p for p in envs(data) if (p / ".ready").exists()]


def builders(datas: list[Path]) -> list[tuple[int, str]]:
    """Live processes building an env of these data folders (pixi install, launch.sh/env.sh)."""
    out = []
    for pid, _pp, cmd in ps_rows():
        if any(str(d) in cmd for d in datas) and ("install --locked" in cmd or "ensure" in cmd):
            out.append((pid, cmd))
    return out


# The mod's "ready" (0.9.1): a toast, a box headed "gate" over "ready" (before,
# the status line "gate: ready", which Claude Code draws with its warning sign)
READY_TOAST = re.compile(r"│ gate\s*│[^\n]*\n[^\n]*│ ready\s*│")


def gate_ready(text: str) -> bool:
    return "gate: ready" in text or READY_TOAST.search(text) is not None


class StatusSampler(threading.Thread):
    """Samples the session's status rows (the gateway's status line and ready
    toast, checkpoint's footer label) and the concurrent pixi installs per env
    folder."""

    def __init__(self, s: driver.Session, datas: list[Path]):
        super().__init__(daemon=True)
        self.s, self.datas = s, datas
        self.stop = threading.Event()
        self.seen: list[tuple[float, str]] = []
        self.max_parallel = 0
        self.t0 = time.time()

    def run(self) -> None:
        last = None
        while not self.stop.is_set():
            try:
                lines = self.s.lines()
                rows = [ln.strip() for ln in lines if re.search(r"\b(gate|check):", ln)]
                if READY_TOAST.search("\n".join(lines)):
                    rows.append("gate: ready (toast)")
                cur = " | ".join(rows)
                if cur and cur != last:
                    self.seen.append((round(time.time() - self.t0, 1), cur[:300]))
                    last = cur
                per: dict[str, int] = {}
                for _pid, cmd in builders(self.datas):
                    m = re.search(r"install --locked --manifest-path (\S+)", cmd)
                    if m and "pixi" in cmd.split(" install")[0]:
                        per[m.group(1)] = per.get(m.group(1), 0) + 1
                self.max_parallel = max([self.max_parallel, *per.values()])
            except Exception:  # noqa: BLE001
                pass
            self.stop.wait(0.5)


def bash(cmd: str, desc: str = "acceptance") -> dict:
    return {"tool": "Bash", "input": {"command": cmd, "description": desc, "timeout": 120000}}


def session(root: Path, name: str, cfg: Path, cwd: Path, pre: Prereqs, extra: dict | None = None,
            replies=(), **kw) -> driver.Session:
    env = {**pre.env(), **(extra or {})}
    return driver.Session(root / name, cwd, config_dir=cfg, extra_env=env, replies=list(replies),
                          permission_mode="bypassPermissions", debug_file=True, cols=160, rows=45,
                          start=False, **kw)


def journal(home: Path) -> list[dict]:
    out = []
    for seg in sorted(home.glob("journal/*/seg-*.jsonl")):
        for line in seg.read_text(errors="replace").splitlines():
            with contextlib.suppress(ValueError):
                out.append(json.loads(line))
    return out


def ckpt_cli_env(home: Path) -> dict:
    """The gateway locations checkpoint's CLI gets when this script runs it
    from the test process (not under a harness Session): the sessions' own
    scratch ones under the state root that holds `home` (safety.state_env),
    whatever this process's environment says. Unset, checkpoint falls back
    to the real ~/.config/gateway/run/contract.json and env.sh (it would
    stat, read and call them): never."""
    st = safety.state_env(home.parents[2])
    if st["CHECKPOINT_HOME"] != str(home):
        raise safety.UnsafePath(f"checkpoint home {home} isn't a harness state root's")
    out = {k: st[k] for k in ("CHECKPOINT_GATEWAY_CONTRACT", "CHECKPOINT_GATEWAY_ENV")}
    for k, v in out.items():
        safety.check_scratch(v, k)
    return out


def ingest_all(cache: Path, data: Path, home: Path, env_extra: dict) -> None:
    """Journal what the sessions spooled (checkpoint ingests at its own Python moments)."""
    gw = ckpt_cli_env(home)
    for sid_dir in sorted((home / "spool").glob("*")) if (home / "spool").is_dir() else []:
        envd = (home / "rt" / sid_dir.name).read_text().strip() if (home / "rt" / sid_dir.name).exists() else ""
        subprocess.run(["sh", str(cache / "hooks" / "env.sh"), "run", "ingest", sid_dir.name],
                       env={**os.environ, **env_extra, "CHECKPOINT_HOME": str(home), "CLAUDE_PLUGIN_DATA": str(data),
                            **gw, **({"CHECKPOINT_ENVD": envd} if envd else {})},
                       capture_output=True, timeout=120)


def ttr(s: driver.Session, timeout: float = 120) -> float:
    """Seconds from spawn to the prompt box."""
    t0 = time.time()
    s.start()
    s.wait_ready(timeout)
    return round(time.time() - t0, 2)


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tmp", default=tempfile.gettempdir())
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--checkpoint", default=str(REPO.parent / "checkpoint"))
    ap.add_argument("--only", default="prereq,cold,warm,update,uninstall,spaced,firstbash")
    a = ap.parse_args(argv)
    before = safety.real_settings_fingerprint()
    root = Path(tempfile.mkdtemp(prefix="acc-install-", dir=a.tmp))
    safety.check_scratch(root, "acceptance root")
    print(f"acceptance (installation): root {root}", flush=True)
    only = set(a.only.split(","))
    t0 = time.time()
    try:
        run(root, Path(a.checkpoint).resolve(), only)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        check(f"the run went to its end ({type(e).__name__}: {str(e)[:300]})", False)
    finally:
        driver._close_all()
        stop_gated(root)
    time.sleep(1.0)
    left = [f"{pid} {cmd[:160]}" for pid, _pp, cmd in ps_rows() if str(root) in cmd and "ps -A" not in cmd]
    check("no process left naming the scratch root", not left, "\n".join(left))
    check("real ~/.config/claude settings and plugin registry unchanged", before == safety.real_settings_fingerprint())
    failed = [r for r in RESULTS if not r["ok"]]
    summary = {"when": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "seconds": round(time.time() - t0),
               "claude": subprocess.run([driver.find_claude(), "--version"], capture_output=True,
                                        text=True).stdout.strip(),
               "pixi": subprocess.run(["pixi", "--version"], capture_output=True, text=True).stdout.strip(),
               "passed": len(RESULTS) - len(failed), "failed": len(failed), "checks": RESULTS,
               "notes": NOTES, **SUMMARY}
    out = Path(a.tmp) / "acceptance-install.json"
    out.write_text(json.dumps(summary, indent=1))
    print(f"\n{summary['passed']} passed, {summary['failed']} failed in {summary['seconds']} s; {out}")
    if not a.keep:
        shutil.rmtree(root, ignore_errors=True)
    return 1 if failed else 0


def stop_gated(root: Path) -> None:
    for pid, _pp, cmd in ps_rows():
        if str(root) in cmd and "gated" in cmd:
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGTERM)


def kill_builds(datas: list[Path]) -> list[str]:
    killed = []
    for pid, cmd in builders(datas):
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGKILL)
            killed.append(cmd[:120])
    return killed


def patched_checkpoint(src: Path, dest: Path, version: str, lock_comment: str | None = None) -> Path:
    install.snapshot_tree(src, dest)
    pj = dest / "plugins" / "checkpoint" / ".claude-plugin" / "plugin.json"
    d = json.loads(pj.read_text())
    d["version"] = version
    pj.write_text(json.dumps(d, indent=2) + "\n")
    init = dest / "plugins" / "checkpoint" / "src" / "checkpoint" / "__init__.py"
    init.write_text(re.sub(r'__version__ = "[^"]+"', f'__version__ = "{version}"', init.read_text()))
    if lock_comment:
        lk = dest / "plugins" / "checkpoint" / "pixi.lock"
        lk.write_text(lk.read_text() + f"# {lock_comment}\n")
    return dest


def run(root: Path, ck_src: Path, only: set[str]) -> None:
    pre = Prereqs(root / "pre")
    SUMMARY["path"] = pre.path
    # ---- prereq: pixi's git
    print("prereq: pixi global install git (scratch PIXI_HOME, cold cache)", flush=True)
    ok, out = pre.install_git()
    if not check("`pixi global install git` gives a git in the scratch PIXI_HOME/bin", ok, out):
        return
    r = subprocess.run(["sh", "-c", "command -v git; git --version"], env={"PATH": pre.path},
                       capture_output=True, text=True)
    check("with the session PATH, `git` is pixi's (first on PATH before the OS folders)",
          r.stdout.splitlines()[:1] == [str(pre.pixi_home / "bin" / "git")], r.stdout + r.stderr)
    SUMMARY["git"] = r.stdout.strip().splitlines()[-1:] if r.stdout else []
    h = install.Hermetic(root / "h", extra_env=pre.env())
    h.__enter__()
    try:
        gi = h.install_gateway_e2e(REPO)
        check("gate@gateway installs from the git-source marketplace with pixi's git (e2e route, proven)",
              gi.proof is not None)
        p = h.install_from(ck_src, repo="checkpoint", plugin="check")
        check("check@checkpoint installs from its git-source marketplace with pixi's git",
              p.cache_path is not None and (Path(p.cache_path) / "hooks" / "env.sh").is_file())
        SUMMARY["installed"] = {"gate": [gi.plugin.version, str(gi.plugin.cache_path)],
                                "check": [p.version, str(p.cache_path)]}
        cfg = h.inst.config_dir
        gdata, cdata = gi.root / "data", p.data_path
        home = safety.state_root_for(cfg) / ".local" / "state" / "checkpoint"
        proj = root / "proj dir ü" / "sub dir ö"
        proj.mkdir(parents=True)
        if "cold" in only:
            part_cold(root, pre, cfg, gi, p, gdata, cdata, home, proj)
        if "warm" in only:
            part_warm(root, pre, cfg, gdata, cdata, home, proj)
        if "update" in only:
            part_update(root, pre, h, cfg, gi, p, ck_src, gdata, cdata, home, proj)
        if "uninstall" in only:
            part_uninstall(root, pre, h, cfg, gi, p, gdata, cdata, home, proj)
    finally:
        h.close()
        SUMMARY["plugin_calls"] = [{"argv": r.argv[1:], "rc": r.rc} for r in h.inst.history]
    if "spaced" in only:
        part_spaced(root, pre, ck_src)
    if "firstbash" in only:
        part_firstbash(root, pre)
    if "vmplain" in only:
        part_vmplain(root, pre)
    if "vmdrain" in only:
        part_vmdrain(root, pre, ck_src)
    shim = [ln for ln in pre.shim_log.read_text().splitlines() if ln.strip()]
    SUMMARY["undeclared_interpreter_calls"] = shim[:20]
    check("no plugin ran python3, python, node, npm, npx or uv by name (recording shims first on PATH)",
          not shim, "; ".join(shim[:10]))


def part_cold(root, pre, cfg, gi, p, gdata, cdata, home, proj) -> None:
    print("cold: first-use provisioning from a cold pixi cache, killed mid-build, then a restart", flush=True)
    check("nothing is built before the first session (no env in either data folder)",
          not ready_envs(gdata) and not ready_envs(cdata))
    pre.slow_flag.write_text("slow\n")
    s1 = session(root, "s1-cold", cfg, proj, pre)
    samp = StatusSampler(s1, [gdata, cdata])
    t0 = time.time()
    try:
        s1.start()
        samp.start()
        s1.wait_ready(180)
        SUMMARY["cold_prompt_s"] = round(time.time() - t0, 1)
        # both builds start by themselves (the gateway's mod and SessionStart hooks; checkpoint's hook)
        both = wait(s1, lambda: any("install --locked" in c and str(gdata) in c for _p, c in builders([gdata]))
                    and any("install --locked" in c and str(cdata) in c for _p, c in builders([cdata])), 120)
        check("session 1 starts both plugins' first-use builds by itself (pixi install --locked in each data folder)",
              both, "; ".join(c[:150] for _p, c in builders([gdata, cdata])))
        wait(s1, lambda: any("gate: setting up" in t for _t, t in samp.seen)
             and any("check: setting up" in t for _t, t in samp.seen), 5)
        texts = " || ".join(t for _t, t in samp.seen)
        check("the status line shows the gateway's progress (gate: setting up… m:ss)",
              re.search(r"gate: setting up… \d+:\d\d", texts), texts[-600:])
        check("the footer shows checkpoint setting up (check: setting up its runtime)",
              "check: setting up its runtime" in texts, texts[-600:])
        check("...and checkpoint says once that its first-time setup is running (session start message)",
              "first-time setup is running" in s1.all_text().replace("\n", " "), s1.all_text()[-600:])
        # kill mid-build: once the real pixi runs for both envs (downloading), 0.8 s in, SIGKILL everything
        real = lambda d: [c for _p, c in builders([d]) if c.startswith(pre.real_pixi) and "install --locked" in c]  # noqa: E731
        # each build is killed 0.2 s after its real pixi starts (downloading), before either env is ready
        killed, seen, before_kill = [], set(), []
        end = time.time() + 60
        while time.time() < end and len(seen) < 2:
            for d in (gdata, cdata):
                if d not in seen and real(d):
                    s1.pump(0.2)
                    before_kill += [p_.name for p_ in ready_envs(d)]
                    killed += kill_builds([d])
                    seen.add(d)
            s1.pump(0.05)
        SUMMARY["real_pixi_seen_for_both"] = len(seen) == 2
        os.kill(s1.pid, signal.SIGKILL)
        wait(None, lambda: not s1.alive(), 10)
        SUMMARY["killed_mid_build"] = killed
        check("mid-build: the pixi installs and their builders SIGKILLed, then claude (no env ready yet)",
              killed and not before_kill, f"killed={killed} ready_before={before_kill}")
    finally:
        samp.stop.set()
        s1.close()
    SUMMARY["cold_status_samples"] = samp.seen[:40]
    time.sleep(1)
    stale = [d.name for d in gdata.glob("envs/*.building")] + [d.name for d in cdata.glob("envs/*.building")]
    check("the interrupted builds left no ready env (a stale build lock and a partial env remain)",
          not ready_envs(gdata) and not ready_envs(cdata), f"locks={stale}")
    SUMMARY["stale_locks_after_kill"] = stale
    pre.slow_flag.unlink(missing_ok=True)
    # session 2: the restart takes over
    s2 = session(root, "s2-restart", cfg, proj, pre, replies=[
        bash("pwd -P > pwd.txt; printf '%s|%s|%s' \"$BASH_VERSION\" \"${GW_MANAGED_DIR:+managed}\" \"$0\" > shell.txt",
             "where am I"), "done"])
    samp = StatusSampler(s2, [gdata, cdata])
    t0 = time.time()
    try:
        s2.start()
        samp.start()
        s2.wait_ready(180)
        okg = wait(s2, lambda: ready_envs(gdata), BUILD_TIMEOUT, 2.0)
        SUMMARY["restart_gateway_ready_s"] = round(time.time() - t0, 1)
        okc = wait(s2, lambda: ready_envs(cdata), BUILD_TIMEOUT, 2.0)
        SUMMARY["restart_checkpoint_ready_s"] = round(time.time() - t0, 1)
        check(f"session 2 (restart) finishes the gateway's env after the interrupted build "
              f"({SUMMARY['restart_gateway_ready_s']} s from a cold-ish cache)", okg)
        check(f"...and checkpoint's ({SUMMARY['restart_checkpoint_ready_s']} s)", okc)
        check("...never two pixi installs of one env at once (sampled every 0.5 s, both sessions)",
              samp.max_parallel <= 1, f"max {samp.max_parallel}")
        rdy = wait(s2, lambda: gate_ready(" ".join(t for _t, t in samp.seen)) or not re.search(
            r"gate: setting up", s2.text()), 60)
        rec = wait(s2, lambda: "check: recording" in s2.text(), 90)
        texts = " || ".join(t for _t, t in samp.seen)
        check("...setup ends: no gate: setting up any more (the ready toast), and check: recording", rdy and rec,
              texts[-500:])
        logs = [str(x) for x in gdata.glob("envs/*/install.log")]
        SUMMARY["gateway_install_log"] = logs
        n0 = len(s2.api.main_requests())
        s2.submit("Where am I?")
        got = wait(s2, lambda: (proj / "shell.txt").exists(), 120)
        pwd = (proj / "pwd.txt").read_text().strip() if (proj / "pwd.txt").exists() else ""
        sh = (proj / "shell.txt").read_text().strip() if got else ""
        check("a Bash command runs in the project folder with a space and non-ASCII letters (pwd -P)",
              pwd == os.path.realpath(proj), f"pwd={pwd!r}")
        check("...in the gateway's managed bash (bash 5, GW_MANAGED_DIR set)",
              sh.startswith("5.") and "|managed|" in sh, sh)
        wait(s2, lambda: len(s2.api.main_requests()) >= n0 + 2, 60)
    finally:
        samp.stop.set()
        s2.close()
    SUMMARY["restart_status_samples"] = samp.seen[:40]
    ingest_all(Path(p.cache_path), cdata, home, pre.env())
    starts = [r for r in journal(home) if r.get("kind") == "session.start"]
    check("checkpoint journaled the sessions with the spaced, non-ASCII project folder as cwd",
          any((r.get("data") or {}).get("cwd") == str(proj) for r in starts),
          json.dumps([(r.get("data") or {}).get("cwd") for r in starts])[:400])


def part_warm(root, pre, cfg, gdata, cdata, home, proj) -> None:
    print("warm: pixi refusing every call, non-loopback HTTP(S) to a dead proxy; startup measured", flush=True)
    base_cfg = root / "baseline-cfg"
    base_cfg.mkdir()
    times_base, times_both = [], []
    for i in range(3):
        b = session(root, f"base{i}", base_cfg, proj, pre)
        try:
            times_base.append(ttr(b))
        finally:
            b.close()
    pre.fail_flag.write_text("refuse\n")
    dead = {k: "http://127.0.0.1:9" for k in ("HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy",
                                               "ALL_PROXY", "all_proxy")}
    t_mark = time.time()
    try:
        for i in range(3):
            s = session(root, f"s3-warm{i}", cfg, proj, pre, extra=dead,
                        replies=[bash(f"echo warm{i} > warm{i}.txt"), "ok"])
            try:
                times_both.append(ttr(s))
                if i == 0:
                    t_rec = time.time()
                    rec = wait(s, lambda: "check: recording" in s.text(), 60)
                    SUMMARY["warm_recording_after_prompt_s"] = round(time.time() - t_rec, 2)
                    check("warm start: checkpoint is recording without pixi (no rebuild, no download)", rec,
                          s.text()[-400:])
                    s.submit("warm check")
                    ok = wait(s, lambda: (proj / "warm0.txt").exists(), 90)
                    check("warm start offline: a Bash command runs (the gateway's managed bash, no pixi)", ok)
                    gst = "\n".join(ln for ln in s.lines() if "gate:" in ln)
                    check("...and the gateway shows no setup or failure on its status line",
                          "setting up" not in gst and "failed" not in gst and "pixi isn't" not in gst, gst)
            finally:
                s.close()
    finally:
        calls = pre.pixi_calls(t_mark)
        pre.fail_flag.unlink(missing_ok=True)
    check("no pixi call at all during the three warm sessions (no environment solving)", not calls,
          "; ".join(calls[:10]))
    med = lambda xs: sorted(xs)[len(xs) // 2] if xs else None  # noqa: E731
    SUMMARY["startup_to_prompt_s"] = {"no_plugins": times_base, "both_plugins_warm": times_both,
                                      "median_no_plugins": med(times_base), "median_both": med(times_both)}
    note(f"startup to the prompt box (median of 3): no plugins {med(times_base)} s, both plugins warm "
         f"{med(times_both)} s")
    check("warm startup with both plugins stays within 3 s of a session without plugins (median of 3)",
          med(times_both) is not None and med(times_both) - med(times_base) < 3.0,
          json.dumps(SUMMARY["startup_to_prompt_s"]))


def part_update(root, pre, h, cfg, gi, p, ck_src, gdata, cdata, home, proj) -> None:
    print("update: new versions published; after a restart, marketplace update + plugin update", flush=True)
    recs_before = len(journal(home))
    form = gi.gateway_home / "gateway.toml"
    form_before = form.read_bytes() if form.exists() else None
    genvs, cenvs = [e.name for e in ready_envs(gdata)], [e.name for e in ready_envs(cdata)]
    gi2 = h.update_gateway_e2e(REPO, version="0.9.1000")
    ck2 = patched_checkpoint(ck_src, root / "ck-src-0.7.1000", "0.7.1000")
    p2 = h.update_from(ck2, repo="checkpoint", plugin="check")
    hist = h.inst.history[-4:]
    check("`claude plugin marketplace update` + `claude plugin update` for both, with the normal PATH "
          "(pixi's git; no bootstrap environment)", all(r.ok for r in hist),
          "\n".join(str(r)[:300] for r in hist if not r.ok))
    check("the new versions are installed (0.9.1000, 0.7.1000), each in its own cache folder",
          gi2.plugin.version == "0.9.1000" and p2.version == "0.7.1000"
          and str(gi2.plugin.cache_path).endswith("0.9.1000") and str(p2.cache_path).endswith("0.7.1000"),
          f"{gi2.plugin.version} {gi2.plugin.cache_path} {p2.version} {p2.cache_path}")
    SUMMARY["updated"] = {"gate": [gi2.plugin.version, str(gi2.plugin.cache_path)],
                          "check": [p2.version, str(p2.cache_path)],
                          "old_cache_kept": [Path(gi.plugin.cache_path).exists(), Path(p.cache_path).exists()]}
    pre.fail_flag.write_text("refuse\n")
    t_mark = time.time()
    s = session(root, "s4-updated", cfg, proj, pre, replies=[bash("echo updated > updated.txt"), "ok"])
    try:
        s.start()
        s.wait_ready(120)
        rec = wait(s, lambda: "check: recording" in s.text(), 60)
        s.submit("after the update")
        ok = wait(s, lambda: (proj / "updated.txt").exists(), 90)
        check("session 4 runs the updated plugins on the existing environments (pixi refusing: no rebuild)",
              rec and ok, s.text()[-400:])
        dbg = s.debug_path.read_text(errors="replace") if s.debug_path and s.debug_path.exists() else ""
        check("...the session loaded the new cache folders (debug log names 0.9.1000 and 0.7.1000)",
              "gate/0.9.1000" in dbg and "check/0.7.1000" in dbg)
    finally:
        s.close()
        pre.fail_flag.unlink(missing_ok=True)
    check("...no pixi call (same lock, same environments)", not pre.pixi_calls(t_mark),
          "; ".join(pre.pixi_calls(t_mark)[:5]))
    check("...the environments are the same folders as before the update",
          [e.name for e in ready_envs(gdata)] == genvs and [e.name for e in ready_envs(cdata)] == cenvs)
    ingest_all(Path(p2.cache_path), cdata, home, pre.env())
    check("the journal kept every record from before the update and goes on after it",
          len(journal(home)) > recs_before)
    check("the gateway's form is unchanged by the update",
          (form.read_bytes() if form.exists() else None) == form_before)
    # a checkpoint update whose lock changed
    ck3 = patched_checkpoint(ck_src, root / "ck-src-0.7.1001", "0.7.1001", lock_comment="acceptance: lock bump")
    p3 = h.update_from(ck3, repo="checkpoint", plugin="check")
    check("a checkpoint update with a changed lock installs (0.7.1001)", p3.version == "0.7.1001")
    t_mark = time.time()
    s = session(root, "s5-newlock", cfg, proj, pre, replies=[bash("echo newlock > newlock.txt"), "ok"])
    samp = StatusSampler(s, [cdata])
    try:
        s.start()
        samp.start()
        s.wait_ready(120)
        s.submit("after the lock update")
        ok = wait(s, lambda: (proj / "newlock.txt").exists(), 90)
        new_ready = wait(s, lambda: len(ready_envs(cdata)) > len(cenvs), BUILD_TIMEOUT, 2.0)
        texts = " || ".join(t for _t, t in samp.seen)
        check("...it keeps recording on the previous runtime while the new one builds (no 'setting up' shown)",
              ok and "check: setting up" not in texts and "check: recording" in texts, texts[-400:])
        check("...the new runtime is built in the background into a new env folder", new_ready,
              str([e.name for e in envs(cdata)]))
    finally:
        samp.stop.set()
        s.close()
    SUMMARY["newlock_pixi_calls"] = pre.pixi_calls(t_mark)[:5]


def part_uninstall(root, pre, h, cfg, gi, p, gdata, cdata, home, proj) -> None:
    print("uninstall: --keep-data, reinstall, uninstall; the gateway's uninstall", flush=True)
    pid = "check@checkpoint"
    r = h.inst.uninstall(pid, keep_data=True, check=False)
    check("`claude plugin uninstall --keep-data check@checkpoint` keeps its data folder (the built runtime)",
          r.ok and ready_envs(cdata), str(r)[:400])
    r = h.inst.install(pid, check=False)
    pre.fail_flag.write_text("refuse\n")
    t_mark = time.time()
    s = session(root, "s6-reinstalled", cfg, proj, pre, replies=["ok"])
    try:
        s.start()
        s.wait_ready(120)
        rec = wait(s, lambda: "check: recording" in s.text(), 60)
    finally:
        s.close()
        pre.fail_flag.unlink(missing_ok=True)
    check("...a reinstall records at once on the kept runtime (no pixi call)", rec and not pre.pixi_calls(t_mark))
    n_recs = len(journal(home))
    r = h.inst.uninstall(pid, check=False)
    check("`claude plugin uninstall check@checkpoint` removes its data folder", r.ok and not cdata.exists(),
          str(r)[:400])
    check("...while its journal (CHECKPOINT_HOME, outside the plugin) stays", n_recs > 0 and len(journal(home)) == n_recs)
    gpid = gi.plugin.id
    form = gi.gateway_home / "gateway.toml"
    had_form = form.exists()
    r = h.inst.uninstall(gpid, check=False)
    rec = h.inst.record(gpid)
    check("`claude plugin uninstall gate@gateway` removes the plugin (no install record, cache folder gone)",
          r.ok and rec is None, str(r)[:400])
    check("...the gateway's form and vault home stay (outside the plugin)", form.exists() == had_form)
    # the daemon notices its plugin folder is gone at its next tick (30 s; 0.25 s under the e2e marker)
    t0 = time.time()
    gone = wait(None, lambda: not [1 for _p, _pp, cmd in ps_rows() if "gated" in cmd and str(gi.root) in cmd]
                      and not (gi.gateway_home / "run" / "contract.json").exists(), 45)
    gated = [(pid_, cmd) for pid_, _pp, cmd in ps_rows() if "gated" in cmd and str(gi.root) in cmd]
    contract = (gi.gateway_home / "run" / "contract.json").exists()
    runpys = [w for _p, c in gated for w in c.split() if w.endswith("/run.py")]
    SUMMARY["after_gateway_uninstall"] = {"gated_alive": bool(gated), "contract_json": contract,
                                          "seconds": round(time.time() - t0, 1),
                                          "gated_runs_from": [(w, os.path.exists(w)) for w in runpys][:3]}
    check("after `claude plugin uninstall gate@gateway` (no session open) the gateway daemon leaves at its next "
          "tick and contract.json goes (checkpoint no longer finds a gateway)", gone and not gated and not contract,
          json.dumps(SUMMARY["after_gateway_uninstall"]))


def part_spaced(root: Path, pre: Prereqs, ck_src: Path) -> None:
    print("spaced: checkpoint alone in a config folder with a space and a non-ASCII letter", flush=True)
    cfg = root / "cfg dir ü"
    with install.Hermetic(root / "hs", extra_env=pre.env(), config_dir=cfg) as h:
        p = h.install_from(ck_src, repo="checkpoint", plugin="check")
    check("check@checkpoint installs into a config folder with a space and a non-ASCII letter "
          "(its cache and data paths carry them)", p.cache_path is not None and " " in str(p.cache_path)
          and "ü" in str(p.data_path))
    home = safety.state_root_for(cfg) / ".local" / "state" / "checkpoint"
    w1 = root / "wörk dir" / "ü x"
    w2 = root / "élsewhere dir"
    w1.mkdir(parents=True)
    w2.mkdir(parents=True)
    s = session(root, "sp1", cfg, w1, pre, replies=[bash("pwd -P > pwd.txt"), "ok"])
    try:
        s.start()
        s.wait_ready(180)
        okb = wait(s, lambda: ready_envs(p.data_path), BUILD_TIMEOUT, 2.0)
        check("first-use provisioning into the spaced data folder (warm pixi cache)", okb)
        rec = wait(s, lambda: "check: recording" in s.text(), 120)
        s.submit("pwd please")
        ok = wait(s, lambda: (w1 / "pwd.txt").exists(), 90)
        check("...recording, and a Bash command runs in the spaced, non-ASCII cwd",
              rec and ok and (w1 / "pwd.txt").read_text().strip() == os.path.realpath(w1))
    finally:
        s.close()
    s = session(root, "sp2", cfg, w2, pre, replies=["ok"])
    try:
        s.start()
        s.wait_ready(120)
        wait(s, lambda: "check: recording" in s.text(), 60)
        s.submit("hello from elsewhere")
        # pumping: Claude Code writes to its terminal synchronously, so a wait that
        # doesn't read lets the pty fill up and stalls the session
        wait(s, lambda: len(s.api.main_requests()) >= 1, 60)
    finally:
        s.close()
    ingest_all(Path(p.cache_path), p.data_path, home, pre.env())
    cwds = {(r.get("data") or {}).get("cwd") for r in journal(home) if r.get("kind") == "session.start"}
    check("each session is journaled with its own launch folder (both spaced, non-ASCII)",
          str(w1) in cwds and str(w2) in cwds, json.dumps(sorted(c or "" for c in cwds))[:300])


def part_firstbash(root: Path, pre: Prereqs) -> None:
    """A plain first session (nothing interrupted): the gateway builds its env during it; the moment the
    ready toast shows, Claude runs Bash, then again every 2 s until a command runs."""
    print("firstbash: Bash right after the first session's setup says ready", flush=True)
    with install.Hermetic(root / "hf", extra_env=pre.env()) as h:
        gi = h.install_gateway_e2e(REPO)
        proj = root / "fb-proj"
        proj.mkdir()
        gdata = gi.root / "data"
        s = session(root, "fb-s1", h.inst.config_dir, proj, pre)
        try:
            s.start()
            s.wait_ready(180)
            ready = wait(s, lambda: gate_ready(s.text()), BUILD_TIMEOUT, 0.2)
            t_ready = time.time()
            check("firstbash: the first session builds the env and says ready (the toast)", ready)
            tries, ran, first_err = 0, False, ""
            while time.time() - t_ready < 90 and not ran:
                tries += 1
                n0 = len(s.api.main_requests())
                s.api.script([bash(f"echo try{tries} > fb{tries}.txt", "try"), f"try {tries} done"])
                s.submit(f"try {tries}")
                wait(s, lambda: len(s.api.main_requests()) >= n0 + 2, 60, 0.2)
                ran = (proj / f"fb{tries}.txt").exists()
                if not ran and not first_err:
                    from tui.fakeapi import result_text, tool_results
                    reqs = s.api.main_requests()
                    first_err = "\n".join(result_text(b) for b in tool_results(reqs[n0 + 1]))[:300] if len(reqs) > n0 + 1 else ""
                if not ran:
                    s.pump(2.0)
            SUMMARY["firstbash"] = {"tries": tries, "ran": ran, "window_s": round(time.time() - t_ready, 1),
                                    "first_error": first_err}
            check("firstbash: the first Bash command after the ready toast runs (no not-ready window)",
                  ran and tries == 1, json.dumps(SUMMARY["firstbash"]))
        finally:
            s.close()
        stop_gated(h.root)


VM_HOME = "/home/tester"


def part_vmplain(root: Path, pre: Prereqs) -> None:
    """Only on the disposable Linux test VM: the gateway installed the PLAIN way (no e2e marker) into a
    config folder with a space and a non-ASCII letter, so its data folder has them too; it then uses the
    VM test user's own ~/.config/gateway, which exists only on that throwaway machine. Never runs elsewhere."""
    import pwd
    print("vmplain: the gateway installed plainly on the disposable VM (spaced, non-ASCII config)", flush=True)
    if not (sys.platform.startswith("linux") and os.uname().nodename == "gwtest-linux"
            and os.environ.get("ACCEPTANCE_DISPOSABLE_VM") == "1" and pwd.getpwuid(os.getuid()).pw_dir == VM_HOME):
        note("vmplain: skipped (only on the disposable test VM: host gwtest-linux, ACCEPTANCE_DISPOSABLE_VM=1)")
        return
    gwhome = Path(VM_HOME) / ".config" / "gateway"
    if gwhome.exists():
        check("vmplain: the VM's gateway home is fresh (./vm.sh clean first)", False)
        return

    class VMSession(driver.Session):
        def check_gateways(self):          # the VM's own home is the throwaway one: no e2e redirection
            self.gateway_mode = "vm-plain"
            return []

    cfg = root / "plain cfg ü"
    proj = root / "plain proj ö" / "sub dir"
    proj.mkdir(parents=True)
    with install.Hermetic(root / "hp", extra_env=pre.env(), config_dir=cfg) as h:
        p = h.install_from(REPO, repo="gateway", plugin="gate")
    check("vmplain: gate@gateway installs plainly into a config folder with a space and a non-ASCII letter",
          p.cache_path is not None and " " in str(p.cache_path) and "ü" in str(p.data_path))
    s = VMSession(root / "vp-s1", proj, config_dir=cfg, extra_env={**pre.env(), "GATEWAY_TEST_ROOT": None},
                  replies=[bash("pwd -P > pwd.txt; printf '%s|%s' \"$BASH_VERSION\" \"${GW_MANAGED_DIR:+managed}\" > sh.txt"),
                           "ok"], permission_mode="bypassPermissions", debug_file=True, cols=160, rows=45, start=False)
    try:
        t0 = time.time()
        s.start()
        s.wait_ready(180)
        okb = wait(s, lambda: ready_envs(p.data_path), BUILD_TIMEOUT, 2.0)
        SUMMARY["vmplain_build_s"] = round(time.time() - t0, 1)
        check(f"vmplain: first-use provisioning into the spaced, non-ASCII plugin data folder "
              f"({SUMMARY['vmplain_build_s']} s)", okb)
        wait(s, lambda: (p.data_path / "managed" / "state.json").exists(), 60, 1.0)
        s.submit("where am I")
        ok = wait(s, lambda: (proj / "sh.txt").exists(), 120)
        pwdv = (proj / "pwd.txt").read_text().strip() if (proj / "pwd.txt").exists() else ""
        shv = (proj / "sh.txt").read_text() if ok else ""
        check("vmplain: a Bash command runs in the managed bash in the spaced, non-ASCII project folder",
              pwdv == os.path.realpath(proj) and shv.startswith("5.") and "|managed" in shv, f"{pwdv!r} {shv!r}")
        check("vmplain: the gateway's daemon runs for the VM user (its contract.json in ~/.config/gateway/run)",
              wait(s, lambda: (gwhome / "run" / "contract.json").exists(), 60))
    finally:
        s.close()
    with install.Hermetic(root / "hp2", extra_env=pre.env(), config_dir=cfg) as h2:
        r = h2.inst.uninstall(p.id, check=False)
    check("vmplain: `claude plugin uninstall gate@gateway` removes the plugin data folder (env, stand-ins, audit log)",
          r.ok and not p.data_path.exists(), str(r)[:300])
    check("vmplain: ...the form and vault home (~/.config/gateway) stay", gwhome.exists())
    alive = []
    with contextlib.suppress(Exception):
        pid = int(json.loads((gwhome / "run" / "contract.json").read_text())["pid"])
        alive = [pid]

    def daemon_left() -> bool:
        try:
            os.kill(alive[0], 0)
        except (OSError, IndexError):
            return True
        return False
    left = wait(None, lambda: daemon_left() and not (gwhome / "run" / "contract.json").exists(), 45)
    SUMMARY["vmplain_daemon_after_uninstall"] = not left
    check("vmplain: after the uninstall (no session open) the gateway daemon of the removed plugin leaves at its "
          "next tick (30 s) and its contract.json goes", left)
    if not left and alive:
        with contextlib.suppress(OSError):
            os.kill(alive[0], signal.SIGTERM)
        time.sleep(2)
    shutil.rmtree(gwhome, ignore_errors=True)          # the throwaway VM user's gateway home made by this part


def _vm_only(part: str) -> bool:
    import pwd
    if (sys.platform.startswith("linux") and os.uname().nodename == "gwtest-linux"
            and os.environ.get("ACCEPTANCE_DISPOSABLE_VM") == "1" and pwd.getpwuid(os.getuid()).pw_dir == VM_HOME):
        return True
    note(f"{part}: skipped (only on the disposable test VM: host gwtest-linux, ACCEPTANCE_DISPOSABLE_VM=1)")
    return False


def part_vmdrain(root: Path, pre: Prereqs, ck_src: Path) -> None:
    """Only on the disposable Linux test VM (the gateway installed plainly uses the VM test user's own
    ~/.config/gateway and /tmp/gw-<uid>): an uninstall while a gateway job and terminal run (0.9.1; the
    GitHub install test saw 0.9.0's gated run on forever, advertising the contract, its tmux server and
    watchdog running from deleted files), with and without --keep-data, and the ~/.bashrc probe."""
    print("vmdrain: uninstall while a gateway job and terminal run (plain installs, the VM)", flush=True)
    if not _vm_only("vmdrain"):
        return
    gwhome = Path(VM_HOME) / ".config" / "gateway"
    contract = gwhome / "run" / "contract.json"
    run_dir = f"/tmp/gw-{os.getuid()}"
    if gwhome.exists():
        check("vmdrain: the VM's gateway home is fresh (./vm.sh clean first)", False)
        return

    class VMSession(driver.Session):
        def check_gateways(self):          # the VM's own home is the throwaway one: no e2e redirection
            self.gateway_mode = "vm-plain"
            return []

    cfg = root / "drain-cfg"
    proj = root / "drain-proj"
    home = root / "drain-home"             # every session's HOME: the planted rc lives here
    for d in (proj, home):
        d.mkdir(parents=True)
    rclog = root / "drain-rc.log"
    (home / ".bashrc").write_text(f'echo "rc pid=$$ shlvl=${{SHLVL-unset}}" >> {shlex_q(str(rclog))}\n')
    rclog.write_text("")
    gw_tool = "mcp__plugin_gate_gw__"

    def gated_pids() -> list[int]:
        return [pid for pid, _pp, cmd in ps_rows() if "run.py gated serve" in cmd and str(cfg) in cmd]

    def tmux_pids() -> list[int]:
        return [pid for pid, _pp, cmd in ps_rows()
                if "tmux" in cmd and f"-S {run_dir}/tmux.sock" in cmd and "gw-watch" not in cmd]

    def watch_pids() -> list[int]:
        return [pid for pid, _pp, cmd in ps_rows() if "gw-watch" in cmd and f"{run_dir}/tmux.sock" in cmd]

    def job_pids(word: str) -> list[int]:
        return [pid for pid, _pp, cmd in ps_rows() if cmd.strip() == f"sleep {word}"]

    def state() -> dict:
        return {"gated": gated_pids(), "tmux": tmux_pids(), "gw-watch": watch_pids(),
                "contract": contract.exists()}

    # one git server for the part: a reinstall finds the marketplaces where they were added
    h = install.Hermetic(root / "hd", extra_env=pre.env(), config_dir=cfg)
    h.__enter__()

    def install_both() -> tuple:
        if "gateway" in h.repos:
            return h.inst.install("gate@gateway"), h.inst.install("check@checkpoint")
        return (h.install_from(REPO, repo="gateway", plugin="gate"),
                h.install_from(ck_src, repo="checkpoint", plugin="check"))

    def uninstall_both(g, c, keep: bool) -> list:
        return [h.inst.uninstall(x.id, keep_data=keep, check=False) for x in (g, c)]

    def session(name: str, replies=()) -> driver.Session:
        return VMSession(root / name, proj, config_dir=cfg, home=home,
                         extra_env={**pre.env(), "GATEWAY_TEST_ROOT": None}, replies=list(replies),
                         permission_mode="bypassPermissions", debug_file=True, cols=160, rows=45, start=False)

    def provision(name: str, g, first: bool) -> None:
        s = session(name, ["ok"])
        try:
            t0 = time.time()
            s.start()
            s.wait_ready(180)
            if first:
                warned = wait(s, lambda: re.search(r"⚠ gate: (setting up|finishing setup)", s.text()) is not None,
                              60, 0.2)
                check("vmdrain: setting up shows on the status line with Claude Code's warning sign", warned,
                      s.text()[-600:])
            okb = wait(s, lambda: ready_envs(g.data_path) and (g.data_path / "managed" / "state.json").exists(),
                       BUILD_TIMEOUT, 1.0)
            check(f"vmdrain: {name}: first-use provisioning ({round(time.time() - t0)} s)", okb)
            if first:
                toast = wait(s, lambda: gate_ready(s.text()), 60, 0.2)
                check("vmdrain: ready is a toast (gate / ready), never the warning-sign status line `⚠ gate: ready`",
                      toast and "gate: ready" not in s.all_text(), s.text()[-800:])
        finally:
            s.close()

    def run_tools(name: str, job_word: str, with_terminal: bool, probe: bool) -> None:
        s = session(name)
        try:
            s.start()
            s.wait_ready(180)
            if probe:
                rclog.write_text("")
                cmd = ('echo "SELF=$$ SHLVL=${SHLVL-unset} BASH=$BASH"; echo "MARK=${FROM_RC:-none}"')
                s.api.script([bash(cmd, "probe"), "probed"])
                s.submit("probe the shell")
                wait(s, lambda: "probed" in s.all_text(), 120)
                from tui.fakeapi import result_text, tool_results
                reqs = s.api.main_requests()
                out = "\n".join(result_text(b) for b in tool_results(reqs[-1])) if reqs else ""
                me = re.search(r"SELF=(\d+)", out)
                logl = rclog.read_text()
                SUMMARY["vmdrain_rc_probe"] = {"result": out[:400], "rc_log": logl[-600:]}
                check("vmdrain: a Bash command's shell never ran the planted ~/.bashrc (Claude Code started "
                      "without SHLVL; the gateway sets it)",
                      me is not None and f"pid={me.group(1)} " not in logl and "/envs/" in out,
                      json.dumps(SUMMARY["vmdrain_rc_probe"]))
            s.api.script([{"tool": gw_tool + "job_start", "input": {"command": f"sleep {job_word}",
                                                                      "cwd": str(proj)}}, "job started"])
            s.submit("start a gateway job")
            check(f"vmdrain: {name}: a gateway job runs (sleep {job_word})",
                  wait(s, lambda: bool(job_pids(job_word)), 120), s.text()[-600:])
            if with_terminal:
                s.api.script([{"tool": gw_tool + "terminal_open", "input": {"cwd": str(proj)}},
                              "terminal opened"])
                s.submit("open a gateway terminal")
                wait(s, lambda: "terminal opened" in s.all_text(), 120)
        finally:
            s.close()

    def end_work(job_word: str) -> list[str]:
        ended = []
        for pid in job_pids(job_word):
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGKILL)
                ended.append(f"job {pid}")
        for tm in tmux_pids():
            for pid, pp, cmd in ps_rows():
                if pp == tm and "gw-watch" not in cmd:
                    with contextlib.suppress(OSError):
                        os.kill(pid, signal.SIGHUP)
                        ended.append(f"pane {pid}: {cmd[:60]}")
        return ended

    def scenario(label: str, keep: bool, job_word: str, first: bool) -> None:
        g, c = install_both()
        check(f"vmdrain ({label}): gate and check install plainly from git snapshots of the working trees",
              g.cache_path is not None and c.cache_path is not None)
        provision(f"vd-{label}-s1", g, first)
        run_tools(f"vd-{label}-s2", job_word, with_terminal=not keep, probe=first)
        before = state()
        SUMMARY[f"vmdrain_{label}_before"] = before
        check(f"vmdrain ({label}): gated, its tmux server and gw-watch run, contract.json is there",
              before["gated"] and before["tmux"] and before["gw-watch"] and before["contract"], json.dumps(before))
        t0 = time.time()
        rs = uninstall_both(g, c, keep)
        check(f"vmdrain ({label}): `claude plugin uninstall{' --keep-data' if keep else ''}` of both succeeds",
              all(r.ok for r in rs), str(rs)[:400])
        check(f"vmdrain ({label}): ...the gateway's data folder {'stays' if keep else 'goes'}",
              g.data_path.exists() == keep)
        drained = wait(None, lambda: not contract.exists(), 45, 0.5)
        mid = state()
        SUMMARY[f"vmdrain_{label}_drained"] = {**mid, "seconds": round(time.time() - t0, 1),
                                                "job": job_pids(job_word)}
        check(f"vmdrain ({label}): within a tick contract.json goes (checkpoint stops delegating) while gated, "
              "its tmux server and the job keep running", drained and mid["gated"] and mid["tmux"]
              and job_pids(job_word), json.dumps(SUMMARY[f"vmdrain_{label}_drained"]))
        time.sleep(5)
        check(f"vmdrain ({label}): ...gated stays while the work runs (never killed)",
              gated_pids() == mid["gated"] and job_pids(job_word), json.dumps(state()))
        ended = end_work(job_word)
        t1 = time.time()
        gone = wait(None, lambda: not gated_pids() and not tmux_pids() and not watch_pids(), 90, 0.5)
        after = state()
        SUMMARY[f"vmdrain_{label}_after"] = {**after, "seconds": round(time.time() - t1, 1), "ended": ended}
        check(f"vmdrain ({label}): once the work ends gated exits with its tmux server and gw-watch "
              f"({SUMMARY[f'vmdrain_{label}_after']['seconds']} s)",
              gone and not after["contract"], json.dumps(SUMMARY[f"vmdrain_{label}_after"]))
        check(f"vmdrain ({label}): ...and the data folder is {'kept' if keep else 'not made again'}",
              g.data_path.exists() == keep)
        for pid in gated_pids() + tmux_pids() + watch_pids():
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGTERM)

    try:
        scenario("plain", False, "7301", True)
        scenario("keepdata", True, "7302", False)
    finally:
        h.close()
        for pid in job_pids("7301") + job_pids("7302"):
            with contextlib.suppress(OSError):
                os.kill(pid, signal.SIGKILL)
        shutil.rmtree(gwhome, ignore_errors=True)          # the throwaway VM user's gateway home


def shlex_q(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
