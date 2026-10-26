"""The session's recorded mode never goes stale (PLAN-0.11 §2.4, WS-2 review
must-fix 3): while the effective form makes the mode matter the Bash hook
keeps an epoch marker ($DATA/mode-epoch), pre_bash.sh then sends every call
to Python (a call without a trigger word to `launch.sh hook-mode`, which only
records), and a record counts only under the marker's epoch, so one posted
before the marker was taken out and made again (a mode switched while no
call reached Python) is never read back.

The review's case: `[accounts.gh] use = { default = false, auto = true }`
and a host; in auto `ssh h true` records auto; the person switches to
Manual; `gh pr list` has no trigger word, so before this fix gated still said
auto, and a stand-in reading it would hand the credential over in Manual."""
from __future__ import annotations

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import harness as H
import harness_daemon as D
from gateway import modes, paths

PRE = H.PLUGIN / "hooks" / "pre_bash.sh"


# ---------------------------------------------------------------------------
# pre_bash.sh: every call reaches Python while the marker exists
# ---------------------------------------------------------------------------

def _rig(d: Path) -> tuple[Path, Path]:
    """A plugin-shaped copy: hooks/pre_bash.sh (with e2e.sh and home.sh) next
    to a fake launch.sh that logs its arguments and answers with a sentinel
    decision. Returns (pre_bash.sh, the log)."""
    hooks = d / "hooks"
    hooks.mkdir(parents=True)
    for name in ("pre_bash.sh", "e2e.sh", "home.sh"):
        (hooks / name).write_text((H.PLUGIN / "hooks" / name).read_text())
    log = d / "launched"
    (hooks / "launch.sh").write_text(
        "#!/bin/sh\n"
        f"printf '%s\\n' \"$*\" >> {str(log)!r}\n"
        "cat > /dev/null\n"
        "printf '%s\\n' '{\"hookSpecificOutput\": {\"hookEventName\": \"PreToolUse\", "
        "\"permissionDecision\": \"allow\", \"permissionDecisionReason\": \"sentinel\"}}'\n")
    return hooks / "pre_bash.sh", log


def _run(pre: Path, payload: dict[str, Any], data: str | None,
         extra: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items()
           if k not in ("CLAUDE_PLUGIN_DATA", "CLAUDE_CODE_SHELL_PREFIX", "GATEWAY_TEST_ROOT")}
    env["CLAUDE_CODE_SHELL_PREFIX"] = str(pre.parent / "gate-sh")   # a managed session
    env["GATEWAY_TEST_ROOT"] = "/nonexistent-test-root"            # never the real home
    env["CLAUDE_CONFIG_DIR"] = "/nonexistent-config"               # nor the real config
    if data is not None:
        env["CLAUDE_PLUGIN_DATA"] = data
    env.update(extra or {})
    return subprocess.run(["/bin/sh", str(pre)], input=json.dumps(payload), capture_output=True,
                          text=True, timeout=20, env=env)


def _bash(command: str, tool: str = "Bash") -> dict[str, Any]:
    return {"tool_name": tool, "tool_input": {"command": command}, "permission_mode": "default",
            "session_id": "s1"}


def test_pre_bash_sends_every_call_to_python_while_the_epoch_marker_exists():
    """No marker: a call without a trigger word never starts Python (as
    before). With the marker in the data folder (CLAUDE_PLUGIN_DATA): every
    such call goes to `launch.sh hook-mode`, whose output is never passed on
    (it only records the mode); a trigger word still goes to hook-bash and
    its answer is passed on. A relative CLAUDE_PLUGIN_DATA, or none under a
    test root, finds no marker (never the real home's)."""
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as td:
        pre, log = _rig(Path(td) / "rig")
        data = Path(td) / "data"
        data.mkdir()

        def calls() -> list[str]:
            out = log.read_text().splitlines() if log.exists() else []
            log.unlink(missing_ok=True)
            return out
        for p in (_bash("gh pr list"), _bash("ls"), _bash("tail -f x", "Monitor")):
            r = _run(pre, p, str(data))
            assert r.returncode == 0 and r.stdout == "" and calls() == [], p
        (data / "mode-epoch").write_text("0123456789abcdef0123456789abcdef\n")
        for p in (_bash("gh pr list"), _bash("ls"), _bash("tail -f x", "Monitor"),
                  {"tool_name": "mcp__plugin_check_jobs__job_start", "permission_mode": "auto",
                   "tool_input": {"argv": ["make", "test"]}}):
            r = _run(pre, p, str(data))
            assert r.returncode == 0 and r.stdout == "", (p, r.stdout)    # never a decision
            assert calls() == ["hook-mode"], p
        r = _run(pre, _bash("ssh h true"), str(data))
        assert "sentinel" in r.stdout and calls() == ["hook-bash"], r.stdout
        for where in ("relative/data", None):
            r = _run(pre, _bash("gh pr list"), where)
            assert r.stdout == "" and calls() == [], where


def test_pre_bash_finds_the_marker_in_the_e2e_copys_data_folder():
    """The e2e suite's scratch copy (hooks/e2e.sh): its data folder is the
    e2e root's, as launch.sh and Python find it, whatever CLAUDE_PLUGIN_DATA
    says."""
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as td:
        base = Path(td)
        pre, log = _rig(base / "rig")
        root = base / "e2e"
        (root / "data").mkdir(parents=True)
        os.chmod(root, 0o700)
        marker = base / "rig" / "e2e-root"
        marker.write_text(str(root.resolve()) + "\n")
        os.chmod(marker, 0o600)
        other = base / "other-data"
        other.mkdir()
        r = _run(pre, _bash("gh pr list"), str(other))
        assert r.stdout == "" and not log.exists()
        (root / "data" / "mode-epoch").write_text("0123456789abcdef0123456789abcdef\n")
        r = _run(pre, _bash("gh pr list"), str(other))
        assert r.stdout == "" and log.read_text().splitlines() == ["hook-mode"]


# ---------------------------------------------------------------------------
# modes.py: the marker, record and current_for (no gated)
# ---------------------------------------------------------------------------

def test_the_marker_is_made_once_and_an_unreadable_one_is_replaced():
    with H.gateway_env():
        p = paths.mode_epoch_path()
        assert modes.marker_epoch() is None
        e = modes.set_marker()
        assert e is not None and modes.EPOCH_RE.fullmatch(e) and p.read_text().strip() == e
        assert modes.set_marker() == e, "made once: a second call keeps the epoch"
        p.write_text("not an epoch\n")
        assert modes.marker_epoch() is None
        e2 = modes.set_marker()
        assert e2 is not None and e2 != e
        modes.drop_marker()
        assert not p.exists() and modes.marker_epoch() is None
        modes.drop_marker()                                     # gone already: no error


def test_record_posts_the_markers_epoch_and_reads_need_it():
    """record makes the marker (create) and posts the payload's mode under
    its epoch; hook_main never makes one (no marker: nothing posted); a read
    without the marker never even asks gated, and asks with the epoch."""
    calls: list[tuple] = []
    answers: dict[str, Any] = {"POST": {"ok": True}, "GET": {"ok": True, "mode": "auto"}}
    real_call, real_entry = modes._call, paths.ENTRY_MODE

    def fake(method, body=None, route=modes.MODE_ROUTE):
        calls.append((method, body, route))
        return answers[method]
    modes._call = fake
    try:
        with H.gateway_env():
            paths.ENTRY_MODE = "hook-mode"
            assert modes.hook_main({"permission_mode": "auto"}) is None
            assert calls == [] and modes.marker_epoch() is None, "hook-mode never makes the marker"
            paths.ENTRY_MODE = "hook-bash"
            assert modes.record("bypass") is True               # gateway.toml's spelling: default
            e = modes.marker_epoch()
            assert calls == [("POST", {"mode": "default", "epoch": e}, modes.MODE_ROUTE)], calls
            calls.clear()
            paths.ENTRY_MODE = "hook-mode"
            modes.hook_main({"permission_mode": "bypassPermissions"})
            assert calls == [("POST", {"mode": "bypass", "epoch": e}, modes.MODE_ROUTE)], calls
            calls.clear()
            paths.ENTRY_MODE = "mcp"
            assert modes.current_for("mcp") == "auto"
            assert calls == [("GET", None, f"{modes.MODE_ROUTE}?epoch={e}")], calls
            calls.clear()
            modes.drop_marker()
            assert modes.current_for("mcp") is None and calls == [], "no marker: no record counts"
    finally:
        modes._call = real_call
        paths.ENTRY_MODE = real_entry


# ---------------------------------------------------------------------------
# gated: a record counts only under the marker's epoch
# ---------------------------------------------------------------------------

DRIVER = """import json, os, sys
sys.pycache_prefix = {pyc!r}
sys.path.insert(0, {src!r})
from gateway import modes, paths, testing
root, mode, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
with open(os.path.join(root, "entry-knobs.json")) as f:
    kw = json.load(f)
with testing.override(root, **kw):
    paths.ENTRY_MODE = "shim " + rest[0] if mode == "shim" else mode
    op, value = os.environ["GW_OP"], json.loads(os.environ["GW_MODE"])
    if op == "record":
        out = modes.record(value)
    elif op == "hookmode":
        out = modes.hook_main({{"permission_mode": value}})
    elif op == "drop":
        out = modes.drop_marker()
    else:
        out = modes.current_for(op)
    print(json.dumps({{"out": out}}))
"""


def _ask(de: D.DaemonEnv, fc: D.FakeClaude, drv: Path, mode: list[str], op: str,
         value: Any = None) -> Any:
    env = de.env.subprocess_env()
    env.pop("GATEWAY_TEST_ROOT")
    env.update({"GW_OP": op, "GW_MODE": json.dumps(value), "CLAUDE_PID": str(fc.pid)})
    r = fc.run([H.PY, "-I", "-S", *H.PYX, str(drv), str(de.root), *mode], env=env)
    lines = [ln for ln in r.stdout.splitlines() if ln.startswith("{")]
    assert r.returncode == 0 and lines, (r.returncode, r.stdout[-300:], r.stderr[-800:])
    return json.loads(lines[-1])["out"]


def test_a_record_from_before_the_marker_was_made_again_never_counts():
    """The review's case end to end, with a real gated: auto recorded under
    the marker; the marker taken out (the mode stopped mattering) and made
    again later (it matters again) while the session switched to Manual
    without any call reaching Python: the old "auto" never counts (the
    modeless rule) until hook-mode or the Bash hook records under the new
    epoch. hook-mode records under the marker it finds and never makes one;
    a read with no epoch, or another one, gets nothing from gated."""
    with D.daemon_env() as de:
        fc = de.claude()
        D.write_driver(de.env, de.run)
        drv = de.root / "drivers" / "mode_record.py"
        drv.write_text(DRIVER.format(pyc=H.PYC, src=str(H.PLUGIN / "src")))
        standin = ["shim", "gh"]
        assert _ask(de, fc, drv, ["hook-bash"], "record", "auto") is True
        assert _ask(de, fc, drv, standin, "standin") == "auto"
        assert _ask(de, fc, drv, ["mcp"], "mcp") == "auto"
        # the mode stops mattering: the marker goes, no record counts
        _ask(de, fc, drv, ["hook-bash"], "drop")
        assert _ask(de, fc, drv, standin, "standin") is None
        _ask(de, fc, drv, ["hook-mode"], "hookmode", "default")     # no marker: nothing posted
        # it matters again: a new epoch; the stale "auto" doesn't count
        epoch = "fedcba9876543210fedcba9876543210"
        (de.env.data / "mode-epoch").write_text(epoch + "\n")
        assert _ask(de, fc, drv, standin, "standin") is None
        assert _ask(de, fc, drv, ["hook-mode"], "hookmode", "default") is None
        assert _ask(de, fc, drv, standin, "standin") == "default"
        assert _ask(de, fc, drv, ["mcp"], "mcp") == "default"
        # gated itself checks the epoch: none, or another one, reads nothing
        gate = D.probe_root(de.root)
        for path in ("/agent/session/mode", "/agent/session/mode?epoch=" + "0" * 32):
            st, body = de.probe(fc, gate / "run.py", standin, path, method="GET")
            assert st == 200 and body["mode"] is None, (path, body)
        st, body = de.probe(fc, gate / "run.py", standin, f"/agent/session/mode?epoch={epoch}",
                            method="GET")
        assert st == 200 and body["mode"] == "default", body


# ---------------------------------------------------------------------------
# What it costs (PLAN-0.11 §19.3: measured and stated in TESTING.md)
# ---------------------------------------------------------------------------

def test_a_call_while_the_marker_exists_costs_one_python_start():
    """While $DATA/mode-epoch exists, a Bash or Monitor call without a
    trigger word takes the real path: pre_bash.sh (sh, sed, grep), launch.sh
    hook-mode (sh), run.py hook-mode (one Python start: modes and paths, one
    POST to gated; no gated runs here, so that local socket round trip isn't
    in it). Without the marker it is sh only. Both medians are printed for
    TESTING.md; the bound catches only a pathological slowdown (a machine
    under load is slower)."""
    import shutil
    import statistics
    import time
    import harness_ux as U
    with H.gateway_env() as env:
        U.fake_ready_env(env)
        rig = Path(tempfile.mkdtemp(prefix="gwmc-", dir=H.tmp_base()))
        try:
            hooks = rig / "hooks"
            hooks.mkdir()
            for name in ("pre_bash.sh", "e2e.sh", "home.sh"):
                (hooks / name).write_text((H.PLUGIN / "hooks" / name).read_text())
            launch = H.PLUGIN / "hooks" / "launch.sh"
            log = rig / "launched"
            # the real launch.sh, given the --test that pre_bash.sh doesn't pass (a test root
            # needs it); it then runs run.py hook-mode --test with the (fake) ready env's python
            (hooks / "launch.sh").write_text(f"#!/bin/sh\nprintf '%s\\n' \"$1\" >> {str(log)!r}\n"
                                             f"exec /bin/sh {str(launch)!r} \"$1\" --test\n")
            e = env.subprocess_env({"CLAUDE_PLUGIN_DATA": str(env.data),
                                    "CLAUDE_CODE_SHELL_PREFIX": str(hooks / "gate-sh")})
            payload = json.dumps(_bash("ls"))

            def median(n: int = 5) -> float:
                ts = []
                for _ in range(n):
                    t0 = time.perf_counter()
                    r = subprocess.run(["/bin/sh", str(hooks / "pre_bash.sh")], input=payload,
                                       capture_output=True, text=True, timeout=60, env=e)
                    ts.append(time.perf_counter() - t0)
                    assert r.returncode == 0 and r.stdout == "", (r.stdout, r.stderr)
                return statistics.median(ts)
            sh_only = median()
            assert not log.exists(), "no marker: Python never starts"
            (env.data / "mode-epoch").write_text("0123456789abcdef0123456789abcdef\n")
            r = subprocess.run(["/bin/sh", str(launch), "hook-mode", "--test"], input=payload,
                               capture_output=True, text=True, timeout=60, env=e)
            assert r.returncode == 0 and r.stdout == "" and r.stderr == "", (r.returncode, r.stderr[-500:])
            marked = median()
            assert log.read_text().splitlines() == ["hook-mode"] * 5
            print(f"    note: a Bash call without a trigger word: {sh_only * 1000:.0f} ms (sh only), "
                  f"{marked * 1000:.0f} ms while the mode marker exists (one Python start, hook-mode)")
            assert sh_only < 2.0 and marked < 15.0, (sh_only, marked)
        finally:
            shutil.rmtree(rig, ignore_errors=True)
