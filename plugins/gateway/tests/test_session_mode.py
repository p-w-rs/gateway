"""The session's recorded permission mode (PLAN-0.11 §2.4) and the browser
sign-in's route planes (§7.1): gated's /agent/session/mode and
/agent/signin/* routes with their planes, the registry's records, and the
client side (modes.record, modes.current_for). A real daemon runs in a test
root (harness_daemon); Claude Code is a FakeClaude, the gateway programs
probes and a driver below it."""
from __future__ import annotations

import inspect
import io
import json
import os
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import harness as H
import harness_daemon as D
from gateway import modes
from gateway.daemon import peers, planes, server

# A gateway program asking the mode route through modes.py: a test entry
# point (a script in the test root, the root before its mode) that applies
# the override write_driver's knobs name (the test daemon's run dir).
MODE_DRIVER = """import json, os, sys
sys.pycache_prefix = {pyc!r}
sys.path.insert(0, {src!r})
from gateway import modes, paths, testing
root, mode, rest = sys.argv[1], sys.argv[2], sys.argv[3:]
with open(os.path.join(root, "entry-knobs.json")) as f:
    kw = json.load(f)
with testing.override(root, **kw):
    paths.ENTRY_MODE = "shim " + rest[0] if mode == "shim" else mode
    op = os.environ["GW_OP"]
    if op == "record":
        print(json.dumps({{"ok": modes.record(json.loads(os.environ["GW_MODE"]))}}))
    else:
        print(json.dumps({{"mode": modes.current_for(op)}}))
"""

# A program between Claude's command and the stand-in (make, a script): the
# stand-in's command isn't one Claude typed.
WRAPPER = "import subprocess, sys; sys.exit(subprocess.call(sys.argv[1:]))"


def _driver(de: D.DaemonEnv) -> Path:
    D.write_driver(de.env, de.run)
    drv = de.root / "drivers" / "modes_entry.py"
    drv.write_text(MODE_DRIVER.format(pyc=H.PYC, src=str(H.PLUGIN / "src")))
    return drv


def _ask(de: D.DaemonEnv, fc: D.FakeClaude, drv: Path, mode: list[str], op: str,
         value: Any = None, typed: bool = True, through: list[str] | None = None) -> dict[str, Any]:
    """Run the driver below the fake claude as gateway entry point `mode`:
    op "record" posts `value`, any other op is modes.current_for(op).
    typed: CLAUDE_PID names the fake claude (its child is a command Claude
    typed); through: a program between them."""
    env = de.env.subprocess_env()
    env.pop("GATEWAY_TEST_ROOT")
    env["GW_OP"] = op
    env["GW_MODE"] = json.dumps(value)
    if typed:
        env["CLAUDE_PID"] = str(fc.pid)
    r = fc.run([*(through or []), H.PY, "-I", "-S", *H.PYX, str(drv), str(de.root), *mode], env=env)
    lines = [ln for ln in r.stdout.splitlines() if ln.startswith("{")]
    assert r.returncode == 0 and lines, (r.returncode, r.stdout[-300:], r.stderr[-800:])
    return json.loads(lines[-1])


def _post(de: D.DaemonEnv, fc: D.FakeClaude, mode: list[str], value: Any) -> tuple[int, dict]:
    gate = D.probe_root(de.root)
    return de.probe(fc, gate / "run.py", mode, "/agent/session/mode", body={"mode": value})


def _get(de: D.DaemonEnv, fc: D.FakeClaude, mode: list[str]) -> tuple[int, dict]:
    gate = D.probe_root(de.root)
    return de.probe(fc, gate / "run.py", mode, "/agent/session/mode", method="GET")


# ---------------------------------------------------------------------------
# The route and its planes
# ---------------------------------------------------------------------------


def test_only_a_hook_records_the_mode_and_only_a_stand_in_or_the_mcp_server_reads_it():
    with D.daemon_env() as de:
        fc = de.claude()
        st, body = _post(de, fc, ["hook-bash"], "auto")
        assert st == 200 and body == {"ok": True, "mode": "auto"}, body
        for mode in (["shim", "sudo"], ["mcp"]):
            st, body = _get(de, fc, mode)
            assert st == 200 and body["mode"] == "auto", (mode, body)
        # recording: no stand-in, MCP server, gate or other gateway program
        for mode in (["shim", "sudo"], ["shim", "gate"], ["mcp"], ["gate", "status"], ["askpass"],
                     ["git-credential", "get"], ["gated", "status"]):
            st, body = _post(de, fc, mode, "bypassPermissions")
            assert st == 403 and body["error"] == "peer", (mode, body)
        # reading: no hook, gate or other gateway program
        for mode in (["hook-bash"], ["hook-post"], ["gate", "status"], ["askpass"],
                     ["git-credential", "get"]):
            st, body = _get(de, fc, mode)
            assert st == 403 and body["error"] == "peer", (mode, body)
        # a program that isn't a gateway entry point at all: the test process, the
        # Claude Code process itself (the UI plane is never this plane)
        assert de.call("POST", "/agent/session/mode", {"mode": "bypass"})[0] == 403
        assert de.call("GET", "/agent/session/mode")[0] == 403
        st, body = fc.http("POST", "/agent/session/mode", {"mode": "bypass"})
        assert st == 403 and body["error"] == "peer", body
        st, body = fc.http("GET", "/agent/session/mode")
        assert st == 403 and body["error"] == "peer", body
        # outside any registered session
        stranger = de.claude(register=False)
        st, body = _post(de, stranger, ["hook-bash"], "auto")
        assert st == 403 and body["error"] == "not_registered", body
        st, body = _get(de, stranger, ["shim", "sudo"])
        assert st == 403 and body["error"] == "not_registered", body
        # nothing above changed the record
        assert _get(de, fc, ["shim", "sudo"])[1]["mode"] == "auto"
        assert "refused POST /agent/session/mode: peer" in de.log()


def test_a_recorded_mode_is_normalized_and_belongs_to_its_own_session():
    with D.daemon_env() as de:
        a, b = de.claude(session="s-a"), de.claude(session="s-b")
        st, body = _get(de, b, ["shim", "ssh"])
        assert st == 200 and body["mode"] is None, body            # nothing recorded yet
        cases = {"default": "default", "manual": "default", "plan": "plan",
                 "acceptEdits": "acceptEdits", "auto": "auto", "bypassPermissions": "bypass",
                 "bypass": "bypass", "dontAsk": "dontAsk",
                 # empty, missing or unknown: default, which never yields allow
                 "": "default", "Auto": "default", "bypassPermissions ": "default",
                 "yolo": "default", None: "default", 7: "default", True: "default",
                 "x" * 5000: "default"}
        for given, want in cases.items():
            st, body = _post(de, a, ["hook-bash"], given)
            assert st == 200 and body["mode"] == want, (given, body)
            assert _get(de, a, ["mcp"])[1]["mode"] == want, given
        st, body = de.probe(a, D.probe_root(de.root) / "run.py", ["hook-bash"], "/agent/session/mode",
                            body={})
        assert st == 200 and body["mode"] == "default", body       # no mode at all
        _post(de, a, ["hook-bash"], "plan")
        _post(de, b, ["hook-prompt"], "acceptEdits")
        assert _get(de, a, ["shim", "ssh"])[1]["mode"] == "plan"
        assert _get(de, b, ["shim", "ssh"])[1]["mode"] == "acceptEdits"
        # a session that ended takes its record with it; a new one starts with none
        a.close()
        assert de.wait_for(lambda: de.health()["sessions"] == 1), de.health()
        c = de.claude(session="s-c")
        assert _get(de, c, ["shim", "ssh"])[1]["mode"] is None


def test_records_live_in_memory_only_so_a_restarted_daemon_has_none():
    with D.daemon_env() as de:
        fc = de.claude()
        assert _post(de, fc, ["hook-bash"], "bypassPermissions")[1]["mode"] == "bypass"
        de.stop()
        assert de.wait_for(lambda: de.health() is None)
        de.start()
        st, body = _get(de, fc, ["shim", "sudo"])
        assert st == 200 and body["mode"] is None, body            # the session is known, no mode
        raw = (de.run / "gated-sessions.json").read_text()
        assert "bypass" not in raw, raw


# ---------------------------------------------------------------------------
# The registry's records
# ---------------------------------------------------------------------------


def _child() -> subprocess.Popen:
    return subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])


def test_a_record_goes_with_its_session_and_never_to_a_reused_pid():
    with H.gateway_env() as env:
        p = _child()
        try:
            reg = planes.Registry(env.root / "sessions.json")
            s = reg.register(p.pid, ui=False, via="hook", session_id="s1")
            reg.set_mode(s, "auto")
            assert reg.mode_of(s) == "auto" and reg.mode_of(reg.live(p.pid)) == "auto"
            # the same pid, another process (another start time): not its record
            other = replace(s, start=(s.start or 0) - 100.0)
            assert reg.mode_of(other) is None
            # a reused pid registering drops the old process's record
            reg.sessions[p.pid] = other
            s2 = reg.register(p.pid, ui=False, via="hook")
            assert reg.mode_of(s2) is None and p.pid not in reg.modes
            reg.set_mode(s2, "plan")
            assert reg.mode_of(s2) == "plan"
            # the same process registering again keeps it (the mod after a hook)
            assert reg.mode_of(reg.register(p.pid, ui=True, via="ui")) == "plan"
            reg.unregister(p.pid)
            assert p.pid not in reg.modes
            s3 = reg.register(p.pid, ui=False, via="hook")
            reg.set_mode(s3, "dontAsk")
        finally:
            p.kill()
            p.wait()
        assert reg.prune() == 0 and reg.modes == {}, reg.modes   # a dead session's goes too


def test_the_mode_is_never_read_or_recorded_through_a_gateway_pane():
    """A process inside a gateway terminal or job counts as the pane's owner
    session for the terminal routes (Registry.pane_session), but nothing
    started there is a command Claude typed or a hook: the mode route finds
    the session only on the real process chain."""
    with H.gateway_env() as env:
        reg = planes.Registry(env.root / "sessions.json")
        p = _child()
        try:
            s = reg.register(p.pid, ui=False, via="hook", session_id="s1")
            reg.set_mode(s, "bypass")
            reg.pane_session = lambda up: s                  # every process "in a pane" of s
            me = os.getpid()                                 # not below p
            # a pane's process: below gated's tmux server, no Claude Code above it
            # (the test runner's own chain may hold one: it is left out here)
            old_chain, old = peers.chain, peers.entry_of
            try:
                peers.chain = lambda pid: [pid, 1] if pid == me else old_chain(pid)
                assert reg.ancestor_session(me) is s
                assert reg.chain_session(me) is None
                peers.entry_of = lambda pid: peers.Entry("shim sudo", "run.py", sys.executable) \
                    if pid == me else None
                for record in (False, True):
                    if record:
                        peers.entry_of = lambda pid: peers.Entry("hook-bash", "run.py",
                                                                 sys.executable) if pid == me else None
                    try:
                        planes.check_mode(reg, peers.Peer(me, os.getuid(), os.getgid()), record)
                    except planes.Denied as e:
                        assert e.code == "not_registered", e.code
                    else:
                        raise AssertionError(f"the pane's session was used (record={record})")
            finally:
                peers.entry_of = old
                peers.chain = old_chain
        finally:
            p.kill()
            p.wait()


# A Claude Code started inside another one's session (a nested `claude`): a
# copy of python named claude that runs each step below itself and prints
# their outputs as one JSON list.
INNER = """import json, os, subprocess, sys
out = []
for argv, env in json.loads(os.environ["GW_INNER_STEPS"]):
    r = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=60)
    out.append({"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr[-800:]})
print(json.dumps(out))
"""


def _probe_step(de: D.DaemonEnv, mode: list[str], method: str, body: Any = None,
                path: str = "/agent/session/mode") -> list:
    gate = D.probe_root(de.root)
    env = D.py_env({"GW_PROBE_SOCK": str(de.sock), "GW_PROBE_PATH": path,
                    "GW_PROBE_METHOD": method})
    env.pop("PYTHONHOME")
    if body is not None:
        env["GW_PROBE_BODY"] = json.dumps(body)
    return [[H.PY, "-I", "-S", str(gate / "run.py"), str(de.root), *mode], env]


def _driver_step(de: D.DaemonEnv, drv: Path, mode: list[str], op: str, value: Any = None) -> list:
    env = de.env.subprocess_env()
    env.pop("GATEWAY_TEST_ROOT")
    env.update({"GW_OP": op, "GW_MODE": json.dumps(value), "CLAUDE_CODE_SESSION_ID": "s-inner"})
    return [[H.PY, "-I", "-S", *H.PYX, str(drv), str(de.root), *mode], env]


def test_a_claude_code_inside_another_ones_session_is_a_session_of_its_own():
    """The mode route finds the nearest Claude Code on the caller's chain: an
    inner one that isn't registered yet gets not_registered (never the outer
    session's record), so its hook registers it and records its own mode."""
    with D.daemon_env() as de:
        outer = de.claude(session="s-outer")
        drv = _driver(de)
        assert _post(de, outer, ["hook-bash"], "plan")[1]["mode"] == "plan"
        # the driver's record goes under the epoch marker's epoch (modes.set_marker),
        # read back under the same one (WS-2's stale-record fix)
        epoch = "0123456789abcdef0123456789abcdef"
        de.env.data.mkdir(parents=True, exist_ok=True)
        (de.env.data / "mode-epoch").write_text(epoch + "\n")
        read = f"/agent/session/mode?epoch={epoch}"
        steps = [_probe_step(de, ["shim", "ssh"], "GET"),
                 _probe_step(de, ["hook-bash"], "POST", {"mode": "bypassPermissions"}),
                 _driver_step(de, drv, ["hook-bash"], "record", "acceptEdits"),
                 _probe_step(de, ["shim", "ssh"], "GET", path=read),
                 _probe_step(de, ["mcp"], "GET", path=read)]
        env = D.py_env({"GW_INNER_STEPS": json.dumps(steps)})
        r = outer.run([str(D.named_python("claude")), "-I", "-S", "-c", INNER], env=env)
        assert r.returncode == 0, r.stderr[-800:]
        out = json.loads(r.stdout)
        assert all(o["rc"] == 0 for o in out), out
        got = [json.loads(o["stdout"].splitlines()[-1]) for o in out]
        assert got[0] == {"status": 403, "body": got[0]["body"]} and \
            got[0]["body"]["error"] == "not_registered", got[0]
        assert got[1]["status"] == 403 and got[1]["body"]["error"] == "not_registered", got[1]
        assert got[2] == {"ok": True}, got[2]                       # registered, then recorded
        assert got[3] == {"status": 200, "body": {"ok": True, "mode": "acceptEdits"}}, got[3]
        assert got[4]["body"]["mode"] == "acceptEdits", got[4]
        # the outer session's record is its own, untouched
        assert _get(de, outer, ["shim", "ssh"])[1]["mode"] == "plan"


# ---------------------------------------------------------------------------
# The client (modes.py)
# ---------------------------------------------------------------------------


def test_the_mode_client_falls_back_to_the_modeless_rule_on_any_error():
    """An unsafe run folder (paths.PathError, raised on the way to gated's
    socket) or any other error: None and False, never an exception (the
    stand-ins and the MCP server then use the modeless rule)."""
    from gateway import paths
    with H.gateway_env():
        run = paths.run_dir()
        os.chmod(run, 0o777)                     # writable by others: refused
        old = paths.ENTRY_MODE
        try:
            paths.ENTRY_MODE = "mcp"
            assert modes.current_for("mcp") is None
            paths.ENTRY_MODE = "hook-bash"
            assert modes.record("auto") is False
        finally:
            paths.ENTRY_MODE = old
            os.chmod(run, 0o700)


def test_a_hooks_answered_call_clears_a_stale_unresponsive_mark():
    """As client._vault_call: once gated answers a hook, a leftover mark that
    it was unresponsive goes (one naming no live daemon is skipped over, and
    then removed)."""
    with D.daemon_env() as de:
        fc = de.claude()
        drv = _driver(de)
        mark = de.run / "gated-unresponsive"
        mark.write_text("999999\n")
        assert _ask(de, fc, drv, ["shim", "ssh"], "standin") == {"mode": None}
        assert mark.exists()                                 # a stand-in leaves it
        assert _ask(de, fc, drv, ["hook-bash"], "record", "plan") == {"ok": True}
        assert not mark.exists()
        assert _ask(de, fc, drv, ["shim", "ssh"], "standin") == {"mode": "plan"}


def test_a_hook_records_and_a_stand_in_claude_typed_reads_the_mode_back():
    with D.daemon_env() as de:
        fc = de.claude()
        drv = _driver(de)
        assert _ask(de, fc, drv, ["shim", "ssh"], "standin") == {"mode": None}   # none yet
        assert _ask(de, fc, drv, ["hook-bash"], "record", "acceptEdits") == {"ok": True}
        assert _ask(de, fc, drv, ["shim", "ssh"], "standin") == {"mode": "acceptEdits"}
        assert _ask(de, fc, drv, ["shim", "sudo"], "standin") == {"mode": "acceptEdits"}
        assert _ask(de, fc, drv, ["mcp"], "mcp") == {"mode": "acceptEdits"}
        assert _ask(de, fc, drv, ["hook-post"], "record", "bypassPermissions") == {"ok": True}
        assert _ask(de, fc, drv, ["shim", "ssh"], "standin") == {"mode": "bypass"}
        # a stand-in Claude didn't type (a script, make, a job): the modeless rule
        assert _ask(de, fc, drv, ["shim", "ssh"], "standin", typed=False) == {"mode": None}
        assert _ask(de, fc, drv, ["shim", "ssh"], "standin",
                    through=[H.PY, "-I", "-S", "-c", WRAPPER]) == {"mode": None}
        # the wrong caller for the entry point, or no such caller
        assert _ask(de, fc, drv, ["mcp"], "standin") == {"mode": None}
        assert _ask(de, fc, drv, ["shim", "ssh"], "mcp") == {"mode": None}
        assert _ask(de, fc, drv, ["shim", "ssh"], "typed") == {"mode": None}
        assert _ask(de, fc, drv, ["gate", "status"], "standin") == {"mode": None}
        # only a hook records
        assert _ask(de, fc, drv, ["shim", "ssh"], "record", "plan") == {"ok": False}
        assert _ask(de, fc, drv, ["mcp"], "record", "plan") == {"ok": False}
        assert _ask(de, fc, drv, ["shim", "ssh"], "standin") == {"mode": "bypass"}


def test_a_hook_whose_session_gated_doesnt_know_yet_registers_it_and_records():
    with D.daemon_env() as de:
        fc = de.claude(register=False)
        drv = _driver(de)
        assert _ask(de, fc, drv, ["shim", "ssh"], "standin") == {"mode": None}
        assert _ask(de, fc, drv, ["hook-bash"], "record", "dontAsk") == {"ok": True}
        assert de.health()["sessions"] == 1
        assert _ask(de, fc, drv, ["shim", "ssh"], "standin") == {"mode": "dontAsk"}


def test_without_a_running_daemon_there_is_no_record_and_none_is_started():
    with D.daemon_env(start=False) as de:
        fc = de.claude(register=False)
        drv = _driver(de)
        assert _ask(de, fc, drv, ["hook-bash"], "record", "auto") == {"ok": False}
        assert _ask(de, fc, drv, ["shim", "ssh"], "standin") == {"mode": None}
        assert _ask(de, fc, drv, ["mcp"], "mcp") == {"mode": None}
        time.sleep(0.3)
        assert de.health() is None, "the mode client started a daemon"


def test_normalize_follows_the_plans_table():
    assert modes.KEYS == ("default", "plan", "acceptEdits", "auto", "bypass", "dontAsk")
    assert set(modes.SPELLINGS.values()) == set(modes.KEYS)
    for given, want in (("default", "default"), ("manual", "default"), ("plan", "plan"),
                        ("acceptEdits", "acceptEdits"), ("auto", "auto"),
                        ("bypassPermissions", "bypass"), ("bypass", "bypass"),
                        ("dontAsk", "dontAsk"), ("", "default"), (None, "default"),
                        ("AUTO", "default"), ("acceptedits", "default"), ([], "default")):
        assert modes.normalize(given) == want, given


# ---------------------------------------------------------------------------
# The browser sign-in's routes (daemon/oauth.py; the flows: test_accounts_entra)
# ---------------------------------------------------------------------------


def test_only_gate_below_a_session_that_draws_dialogs_reaches_the_sign_in_routes():
    with D.daemon_env() as de:
        fc = de.claude()                                   # a terminal surface
        gate = D.probe_root(de.root)
        for mode in (["gate", "check", "work-azure"], ["shim", "gate"]):
            # past the plane check: the route itself answers (no account named, no lease)
            st, body = de.probe(fc, gate / "run.py", mode, "/agent/signin/start", body={})
            assert st == 400 and body["error"] == "bad_request", (mode, body)
            st, body = de.probe(fc, gate / "run.py", mode, "/agent/signin/wait", body={"lease": "x"})
            assert st == 403 and body["error"] == "lease", (mode, body)
        for mode in (["shim", "sudo"], ["shim", "az"], ["mcp"], ["hook-bash"], ["askpass"],
                     ["git-credential", "get"], ["gated", "status"]):
            for path in ("/agent/signin/start", "/agent/signin/wait"):
                st, body = de.probe(fc, gate / "run.py", mode, path, body={})
                assert st == 403 and body["error"] == "peer", (mode, path, body)
        for path in ("/agent/signin/start", "/agent/signin/wait"):
            assert de.call("POST", path, {})[0] == 403
            st, body = fc.http("POST", path, {})
            assert st == 403 and body["error"] == "peer", body
        stranger = de.claude(register=False)
        st, body = de.probe(stranger, gate / "run.py", ["gate", "status"], "/agent/signin/start", body={})
        assert st == 403 and body["error"] == "not_registered", body
        # a session that can't draw the confirm dialog gets no sign-in (as for the dialog lease)
        headless = de.claude(surface=None, session="s-print")
        st, body = de.probe(headless, gate / "run.py", ["gate", "status"], "/agent/signin/start", body={})
        assert st == 200 and body["available"] is False and body["reason"] == "print", body
        hooked = de.claude(register=False, session="s-hook")
        st, _ = de.probe(hooked, gate / "run.py", ["hook-session"], "/agent/register",
                         body={"session_id": "s-hook"})
        assert st == 200
        st, body = de.probe(hooked, gate / "run.py", ["gate", "status"], "/agent/signin/start", body={})
        assert st == 200 and body["available"] is False and body["reason"] == "no_mod", body


# ---------------------------------------------------------------------------
# The dispatcher
# ---------------------------------------------------------------------------

CHECKED = ("ui", "agent", "contract", "agent-term", "local", "lease", "mode-record", "mode-read",
           "signin")


def test_every_route_names_a_plane_the_dispatcher_checks():
    for (method, path), (plane, _fn) in server.routes(True).items():
        assert plane in CHECKED or plane in server.SELF_CHECKED, (method, path, plane)
    disp = inspect.getsource(server.Handler._dispatch)
    for plane in CHECKED:
        assert f'"{plane}"' in disp, plane
    assert server.ROUTES[("POST", "/agent/session/mode")][0] == "mode-record"
    assert server.ROUTES[("GET", "/agent/session/mode")][0] == "mode-read"
    assert server.ROUTES[("POST", "/agent/signin/start")][0] == "signin"
    assert server.ROUTES[("POST", "/agent/signin/wait")][0] == "signin"


class _Daemon:
    def __init__(self, routes: dict) -> None:
        self.routes = routes
        self.lines: list[str] = []

    def log(self, line: str) -> None:
        self.lines.append(line)


def test_a_route_whose_plane_the_dispatcher_doesnt_know_is_refused():
    """A typo in a route's plane must never mean "no check"."""
    called = []

    def fn(ctx: Any) -> dict:
        called.append(1)
        return {"ok": True}

    h = server.Handler.__new__(server.Handler)
    h.daemon = _Daemon({("GET", "/agent/x"): ("agnet", fn), ("GET", "/health"): ("health", fn)})
    h.peer = peers.Peer(os.getpid(), os.getuid(), os.getgid())
    h.headers = {}
    h.rfile = io.BytesIO()
    sent: list[tuple[int, dict]] = []
    h._send = lambda status, body: sent.append((status, body))
    h.path = "/agent/x"
    h._dispatch("GET")
    assert sent[-1][0] == 500 and sent[-1][1]["error"] == "internal" and not called, sent
    assert any("unknown plane" in ln for ln in h.daemon.lines), h.daemon.lines
    h.path = "/health"
    h._dispatch("GET")
    assert sent[-1][0] == 200 and called == [1], sent
