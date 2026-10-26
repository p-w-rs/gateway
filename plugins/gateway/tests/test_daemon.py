"""The gateway daemon, gated (PLAN-v4 phase 2): lifecycle, peer identity and
planes, the event log and the CONTRACT-v1 routes. A real daemon runs in a
test root (harness_daemon), reached over its real Unix socket; Claude Code is
played by a copy of python named `claude` (FakeClaude), and gateway entry
points by probes and the real run.py."""
from __future__ import annotations

import fcntl
import json
import os
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import harness as H
import harness_daemon as D
from gateway import paths
from gateway.daemon import broker
from gateway.daemon import events as evmod
from gateway.daemon import peers, planes

FORM = """
[hosts.box]
address = "tester@10.1.2.3:2222"
ssh = true

[hosts.build]
address = "build.example.org"
ssh = "ask"
"""


def _gated_procs(de: D.DaemonEnv) -> list[tuple[int, str]]:
    return [(p, c) for p, c in de.leftovers() if "gated serve" in c]


def _wait_dead(pid: int, timeout: float = 5) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        time.sleep(0.03)
    return False


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


def test_start_listens_writes_the_contract_file_and_stops_cleanly():
    with D.daemon_env() as de:
        h = de.health()
        assert h and h["ok"] and h["version"] and h["epoch"] == 1 and h["vault"] == "none", h
        pid = h["pid"]
        st = os.lstat(de.sock)
        assert stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
        assert stat.S_IMODE(os.stat(de.run).st_mode) == 0o700
        cp = paths.contract_path()
        assert stat.S_IMODE(os.stat(cp).st_mode) == 0o600
        assert stat.S_IMODE(os.stat(cp.parent).st_mode) == 0o700
        doc = json.loads(cp.read_text())
        assert doc["contract"] == "gateway.v1" and doc["versions"] == [1], doc
        assert doc["socket"] == str(de.sock) and doc["pid"] == pid and doc["epoch"] == 1
        assert doc["machine_id"].startswith("m_") and len(doc["machine_id"]) == 28
        assert doc["features"] == ["hosts", "events", "pause", "jobs", "terminals", "remote", "workspaces", "accounts", "pause_id", "job_env"] and doc["gateway_version"] == h["version"]
        # detached: a session of its own (double fork: not its leader, so it can never
        # get a terminal), not a child of the starter, stdio to the log
        assert os.getsid(pid) not in (os.getsid(0), pid)
        assert __import__("gateway.ancestry", fromlist=["x"]).parent_pid(pid) != os.getpid()
        assert "started: version" in de.log()
        de.stop()
        assert _wait_dead(pid)
        assert not de.sock.exists() and not cp.exists()
        evs = [json.loads(l) for l in (paths.gated_dir() / "events" / "epoch-1.jsonl")
               .read_text().splitlines()]
        assert [e["kind"] for e in evs][0] == "daemon.started"
        assert evs[-1]["kind"] == "daemon.stopping" and evs[-1]["reason"] == "request"
        assert [e["seq"] for e in evs] == list(range(1, len(evs) + 1))


def test_concurrent_starts_make_one_daemon():
    with D.daemon_env(start=False) as de:
        env = de.env.subprocess_env(de.extra_env())
        args = ["--test", "gated", "start"]
        cmd = [H.PY, "-I", "-S", *H.PYX, str(H.PLUGIN / "run.py"), *args]
        assert H.valid_test_argv(args)
        procs = [subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, cwd=str(de.root)) for _ in range(6)]
        outs = [p.communicate(timeout=60) for p in procs]
        pids = {json.loads(o)["pid"] for o, _e in outs}
        assert len(pids) == 1, outs
        time.sleep(0.3)
        assert len(_gated_procs(de)) == 1, _gated_procs(de)


def test_a_second_daemon_exits_at_once_while_one_runs():
    with D.daemon_env() as de:
        pid = de.daemon_pid()
        r = de.gated("serve", timeout=30)
        assert r.returncode == 0 and "already running" in r.stderr, (r.stdout, r.stderr)
        assert de.daemon_pid() == pid


def test_kill_9_leaves_nothing_that_blocks_the_next_start():
    with D.daemon_env() as de:
        pid = de.daemon_pid()
        os.kill(pid, signal.SIGKILL)
        assert _wait_dead(pid)
        # the stale socket and contract file are still there, naming a dead pid
        assert de.sock.exists() and paths.contract_path().exists()
        stale = json.loads(paths.contract_path().read_text())
        assert stale["pid"] == pid
        assert de.health() is None
        h = de.start()
        assert h["pid"] != pid and h["epoch"] == 2, h
        doc = json.loads(paths.contract_path().read_text())
        assert doc["pid"] == h["pid"] and doc["epoch"] == 2


def test_a_stale_socket_file_without_a_daemon_is_replaced():
    with D.daemon_env(start=False) as de:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(str(de.sock))
        s.close()                       # a socket file nobody listens on
        assert de.sock.exists() and de.health() is None
        h = de.start()
        assert h["ok"] and de.health()["pid"] == h["pid"]


class _Impostor:
    """A listener at a socket path that answers every request like gated
    would, counting the connections it gets."""

    def __init__(self, path: Path):
        self.n = 0
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.bind(str(path))
        self.s.listen(8)
        self.t = threading.Thread(target=self._serve, daemon=True)
        self.t.start()

    def _serve(self) -> None:
        body = b'{"ok": true, "pid": 4242, "version": "0.0.1"}'
        while True:
            try:
                c, _ = self.s.accept()
            except OSError:
                return
            self.n += 1
            with c:
                c.settimeout(2)
                try:
                    c.recv(65536)
                    c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                              b"Content-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
                except OSError:
                    pass

    def close(self) -> None:
        try:
            self.s.shutdown(socket.SHUT_RDWR)       # wakes a blocked accept() on Linux
        except OSError:
            pass
        self.s.close()
        self.t.join(5)


def test_a_daemon_socket_that_isnt_this_users_own_is_never_talked_to():
    """Review round 2 (must-fix): the client connected to whatever gated.sock
    the run folder held. Another user who bound one there while the folder
    was open to them (and it was chmod'ed back) would get the vault data a
    stand-in sends, the values the mod seals and the dialogs' answers. The
    socket and its folder must be this user's own and closed to others
    (gated makes them 0600 and 0700): anything else is never connected to,
    counts as unreachable, and a start replaces it."""
    from gateway.daemon import client
    with D.daemon_env(start=False) as de:
        imp = _Impostor(de.sock)
        real_lstat = os.lstat
        try:
            os.chmod(de.sock, 0o600)
            # this user's own 0600 socket in a 0700 folder is talked to
            assert client.health(sock=de.sock)["pid"] == 4242 and imp.n == 1

            def refused(sock: Path, why: str) -> None:
                try:
                    client.call("GET", "/health", sock=sock)
                except client.ForeignSocket as e:
                    assert e.code == "foreign_socket" and why in e.message \
                        and "didn't connect" in e.message, e.message
                else:
                    raise AssertionError(f"talked to {sock} ({why})")
                assert client.health(sock=sock) is None
            # another user's socket (no other user's can be made here: lstat
            # reports this one's owner as someone else, the folder as it is)

            def lstat(p, *a, **k):
                st = real_lstat(p, *a, **k)
                if os.fspath(p) == str(de.sock):
                    t = list(st)
                    t[4] = st.st_uid + 1
                    return os.stat_result(t)
                return st
            os.lstat = lstat
            try:
                refused(de.sock, "belongs to another user")
            finally:
                os.lstat = real_lstat
            # open to others: the socket, or its folder
            os.chmod(de.sock, 0o666)
            refused(de.sock, "is open to other users (mode 666)")
            os.chmod(de.sock, 0o600)
            os.chmod(de.run, 0o711)
            refused(de.sock, f"{de.run} is open to other users")
            os.chmod(de.run, 0o700)
            # a link to it isn't a socket of its own
            link = de.run / "link.sock"
            link.symlink_to(de.sock)
            refused(link, "isn't a socket of its own")
            assert imp.n == 1, "nothing reached the impostor"
            # a start replaces what isn't this user's own: the daemon binds anew
            os.chmod(de.sock, 0o666)
            h = de.start()
            assert h["ok"] and h["pid"] != 4242 and h["version"] == D.plugin_version(), h
            st = os.lstat(de.sock)
            assert stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
            assert de.health()["pid"] == h["pid"] and imp.n == 1
        finally:
            os.lstat = real_lstat
            imp.close()


def test_idle_exit_without_live_sessions_and_not_while_one_lives():
    # idle_exit leaves room for a loaded machine to register the fake claude
    # after the restart (0.6 s was flaky with the suite at 6 at a time); the
    # fake's binary is made (and run once) before the idle clock starts
    D.named_python("claude")
    with D.daemon_env(knobs={"idle_exit": 1.5}) as de:
        pid = de.daemon_pid()
        assert _wait_dead(pid, 8), "no session: the daemon exits when idle"
        assert not de.sock.exists() and not paths.contract_path().exists()
        de.start()
        fc = de.claude()
        pid = de.daemon_pid()
        time.sleep(2.5)
        assert de.daemon_pid() == pid, "a live registered session keeps it"
        fc.close()
        assert _wait_dead(pid, 9), "the session ended: idle again"
        assert "idle" in de.log()
        evs = [json.loads(l) for l in (paths.gated_dir() / "events" / "epoch-2.jsonl")
               .read_text().splitlines()]
        assert [e["kind"] for e in evs] == ["daemon.started", "session.registered", "session.ended",
                                            "daemon.stopping"], evs
        assert evs[2]["session"] == "s-test" and evs[3]["reason"] == "idle"


REGISTER_UI = {"session_id": "s-late", "surface": "terminal", "version": "2.1.301"}


def test_a_registration_while_gated_stops_is_refused_and_a_new_gated_takes_it():
    """Verifier (0.11, Rosetta): gated answered /ui/register 200 and then exited
    for idleness anyway: the registration landed after its idle decision,
    while it still answered. A registration after the decision to stop is
    refused on both planes (503 "stopping"), /health says it is stopping,
    and a session start (the async hook-daemon: ensure_running, then
    /agent/register) waits for it to go, starts a new gated and registers
    there, which then stays (the stop_linger knob holds the window open)."""
    D.named_python("claude")
    with D.daemon_env(knobs={"idle_exit": 0.5, "stop_linger": 4.0}, start=False) as de:
        fc = de.claude(register=False)
        de.start()
        old = de.daemon_pid()
        assert de.wait_for(lambda: (de.health() or {}).get("stopping") == "idle", 10), de.health()
        st, body = fc.http("POST", "/ui/register", {**REGISTER_UI, "claude_pid": fc.pid})
        assert st == 503 and body["error"] == "stopping" and "stopping (idle)" in body["message"], (st, body)
        st, body = de.probe(fc, D.probe_root(de.root) / "run.py", ["hook-session"], "/agent/register",
                            body={"session_id": "s-late"})
        assert st == 503 and body["error"] == "stopping", (st, body)
        assert de.health()["sessions"] == 0
        de.knobs(stop_linger=0.05)                          # for the next gated
        r = fc.run([H.PY, "-I", "-S", *H.PYX, str(H.PLUGIN / "run.py"), "--test", "hook-daemon"],
                   env=de.env.subprocess_env(de.extra_env()), input=json.dumps({"session_id": "s-late"}))
        assert r.returncode == 0, r.stderr
        assert _wait_dead(old, 10), "the stopping gated left"
        h = de.health()
        assert h and h["pid"] != old and h["sessions"] == 1 and "stopping" not in h, h
        time.sleep(1.5)                                     # well past idle_exit
        h2 = de.health()
        assert h2 and h2["pid"] == h["pid"] and h2["sessions"] == 1, "the new gated serves the session"


def test_the_idle_decision_counts_a_registration_that_came_after_its_prune():
    """The other side of the race: a registration answered between the tick's
    prune (no session) and its idle decision is counted by that decision
    (idle_lock, registry.count()), so the daemon serves on; the idle_gap knob
    holds the window open."""
    D.named_python("claude")
    with D.daemon_env(knobs={"idle_exit": 0.5, "idle_gap": 2.0}, start=False) as de:
        fc = de.claude(register=False)
        de.start()
        pid = de.daemon_pid()
        assert de.wait_for(lambda: "idle: deciding in 2 s" in de.log(), 10), de.log()[-400:]
        st, body = fc.http("POST", "/ui/register", {**REGISTER_UI, "claude_pid": fc.pid})
        assert st == 200, (st, body)
        time.sleep(3.0)                                     # the gap, then a few ticks
        h = de.health()
        assert h and h["pid"] == pid and h["sessions"] == 1 and "stopping" not in h, (h, de.log()[-400:])
        assert _wait_dead(pid, 0.2) is False


def test_a_registration_and_the_idle_decision_never_interleave():
    """A registration holds the idle lock from its stopping check to its
    record: an idle decision that comes meanwhile waits for it and counts
    the session (the register_gap knob holds a registration there past the
    idle deadline)."""
    D.named_python("claude")
    with D.daemon_env(knobs={"idle_exit": 1.5, "register_gap": 2.5, "tick": 0.05}, start=False) as de:
        fc = de.claude(register=False)
        de.start()
        pid = de.daemon_pid()
        st, body = fc.http("POST", "/ui/register", {**REGISTER_UI, "claude_pid": fc.pid})
        assert st == 200, (st, body)
        time.sleep(1.0)
        h = de.health()
        assert h and h["pid"] == pid and h["sessions"] == 1 and "stopping" not in h, (h, de.log()[-400:])


def test_a_registration_waiting_for_the_idle_decision_is_refused_once_it_decided_to_stop():
    """Review (WS-11a) S2: a registration that arrives while the idle
    decision holds the idle lock (the idle_hold knob: it decided to stop and
    hasn't marked the daemon stopping yet) waits for it, then finds the
    daemon stopping: 503 "stopping", never 200 from a daemon about to exit
    (the stopping check is made under the lock, not before it)."""
    D.named_python("claude")
    with D.daemon_env(knobs={"idle_exit": 0.5, "idle_hold": 2.0, "stop_linger": 3.0}, start=False) as de:
        fc = de.claude(register=False)
        de.start()
        pid = de.daemon_pid()
        assert de.wait_for(lambda: "idle: stopping in 2 s" in de.log(), 10), de.log()[-400:]
        st, body = fc.http("POST", "/ui/register", {**REGISTER_UI, "claude_pid": fc.pid})
        assert st == 503 and body["error"] == "stopping" and "stopping (idle)" in body["message"], (st, body)
        assert _wait_dead(pid, 10), "the stopping gated left"


def test_every_stop_says_stopping_and_a_start_waits_for_it():
    """Review (WS-11a) S2: /health says "stopping" for every reason, not only
    the idle exit: after a signal or a stop request (the stop_linger knob
    keeps it answering) a registration is refused (503, "stopping (signal)",
    "stopping (request)"), and a start waits for that gated to go and starts
    a new one instead of using it."""
    D.named_python("claude")
    with D.daemon_env(knobs={"stop_linger": 3.0}, start=False) as de:
        fc = de.claude(register=False)
        for reason in ("signal", "request"):
            de.knobs(stop_linger=3.0)
            old = de.start()["pid"]
            if reason == "signal":
                os.kill(old, signal.SIGTERM)
                stopper = None
            else:
                stopper = threading.Thread(target=de.gated, args=("stop",))
                stopper.start()
            assert de.wait_for(lambda: (de.health() or {}).get("stopping") == reason, 5), (reason, de.health())
            st, body = fc.http("POST", "/ui/register", {**REGISTER_UI, "claude_pid": fc.pid})
            assert st == 503 and f"stopping ({reason})" in body["message"], (reason, st, body)
            de.knobs(stop_linger=0.05)                      # for the next gated
            h = de.start()
            assert h["pid"] != old and "stopping" not in h and not _pid_alive(old), (reason, h)
            if stopper is not None:
                stopper.join(10)
            de.stop()


def test_the_orphaned_plugins_exit_counts_a_registration_that_came_after_its_prune():
    """Review (WS-11a) S3: the plugin folder marked orphaned with no live
    session: the exit is decided under the idle lock with registry.count()
    (the idle_gap knob holds the window after the tick's prune open), so a
    session registered meanwhile (answered 200) keeps the daemon serving it,
    never a 200 and then an exit."""
    D.named_python("claude")
    with D.daemon_env(knobs={"idle_gap": 2.0}, start=False) as de:
        copy = D.plugin_copy(de.root, D.plugin_version())
        h = de.start_from(copy)
        fc = de.claude(register=False)
        (copy / ".orphaned_at").write_text("1792450000000")
        assert de.wait_for(lambda: "orphaned: deciding in 2 s" in de.log(), 10), de.log()[-400:]
        st, body = fc.http("POST", "/ui/register", {**REGISTER_UI, "claude_pid": fc.pid})
        assert st == 200, (st, body)
        time.sleep(3.0)                                     # the gap, then a few ticks
        h2 = de.health()
        assert h2 and h2["pid"] == h["pid"] and h2["sessions"] == 1 and "stopping" not in h2, \
            (h2, de.log()[-400:])
        assert not h2.get("draining"), h2
        fc.close()
        assert _wait_dead(h["pid"], 10), "the orphaned version's daemon leaves with its last session"
    # a registration under way when the decision comes (idle_gap holds the ticker after
    # its prune, register_gap the registration inside the idle lock past that): the
    # decision waits for it and counts the session
    with D.daemon_env(knobs={"idle_gap": 2.0, "register_gap": 3.0}, start=False) as de:
        copy = D.plugin_copy(de.root, D.plugin_version())
        h = de.start_from(copy)
        fc = de.claude(register=False)
        (copy / ".orphaned_at").write_text("1792450000000")
        assert de.wait_for(lambda: "orphaned: deciding in 2 s" in de.log(), 10), de.log()[-400:]
        got: list = []
        t = threading.Thread(target=lambda: got.append(
            fc.http("POST", "/ui/register", {**REGISTER_UI, "claude_pid": fc.pid})))
        t.start()
        t.join(15)
        assert got and got[0][0] == 200, got
        time.sleep(1.0)
        h2 = de.health()
        assert h2 and h2["pid"] == h["pid"] and h2["sessions"] == 1 and "stopping" not in h2, \
            (h2, de.log()[-400:])
        fc.close()
        assert _wait_dead(h["pid"], 10), "the orphaned version's daemon leaves with its last session"


def test_a_start_waits_for_a_gated_that_still_holds_its_instance_lock():
    """A gated that no longer answers may still be finishing its exit (its
    socket gone, its tmux server being stopped) and hold the instance lock:
    a start waits for the lock (else the new daemon exits at once and the
    start fails after its whole wait), then starts the new one."""
    from gateway.daemon import lifecycle
    with D.daemon_env(start=False) as de:
        # in process, so nothing depends on how long a start takes to get going:
        # the spawn records whether the instance lock was free when it came
        seen: list[bool] = []

        def spawn() -> None:
            probe = os.open(paths.gated_lock(), os.O_RDWR)
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                seen.append(True)
            except BlockingIOError:
                seen.append(False)
            finally:
                os.close(probe)
        real = lifecycle._spawn, lifecycle._wait_health
        lifecycle._spawn = spawn
        lifecycle._wait_health = lambda deadline: {"ok": True, "version": D.plugin_version(), "pid": 1}
        fd = os.open(paths.gated_lock(), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        threading.Timer(1.0, os.close, (fd,)).start()
        try:
            t0 = time.monotonic()
            h = lifecycle.ensure_running(wait=5)
        finally:
            lifecycle._spawn, lifecycle._wait_health = real
        assert h["ok"] and seen == [True] and time.monotonic() - t0 >= 0.9, (h, seen)
        # held past the start's wait: refused in words, nothing spawned
        fd = os.open(paths.gated_lock(), os.O_RDWR)
        fcntl.flock(fd, fcntl.LOCK_EX)
        lifecycle._spawn = spawn
        try:
            lifecycle.ensure_running(wait=0.5)
            raise AssertionError("started beside a daemon holding the instance lock")
        except lifecycle.StartError as e:
            assert "still stopping" in e.message, e.message
        finally:
            lifecycle._spawn = real[0]
            os.close(fd)
        assert seen == [True], seen
        # and for real: the lock free, a start starts gated
        h = de.start()
        assert h["ok"] and _pid_alive(h["pid"]), h


class _FakeHealth:
    """A stand-in for a gated that holds the instance lock: a Unix socket
    server at gated.sock answering /health (made 0600, as gated makes it:
    client.foreign_socket), "stopping" when told."""

    def __init__(self, stopping: str = ""):
        import http.server
        import socketserver
        from gateway.daemon import lifecycle
        version, fake = lifecycle.plugin_version(), self

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                h = {"ok": True, "version": version, "pid": os.getpid(), "fake": True,
                     "socket": str(paths.gated_socket())}
                if fake.stopping:
                    h["stopping"] = fake.stopping
                body = json.dumps(h).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

            def address_string(self):
                return "unix"
        self.stopping = stopping
        self.srv = socketserver.ThreadingUnixStreamServer(str(paths.gated_socket()), Handler)
        os.chmod(paths.gated_socket(), 0o600)
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()
        paths.gated_socket().unlink(missing_ok=True)


def test_a_start_uses_a_gated_that_holds_its_instance_lock_once_it_answers():
    """Review (WS-11a) M2: a gated that took its instance lock but doesn't
    listen yet (a slow start whose first starter gave up after START_WAIT)
    and then answers is used by the next start: before the instance-lock
    wait it was (spawn, then /health), and with the wait polling only the
    lock the start failed after its whole wait with "still stopping". One
    that answers "stopping" is not used: the start waits for its lock and
    starts a new gated."""
    from gateway.daemon import lifecycle
    with D.daemon_env(start=False):
        spawned: list[int] = []
        real = lifecycle._spawn, lifecycle._wait_health
        lifecycle._spawn = lambda: spawned.append(1)       # a second gated exits at once on the lock
        lifecycle._wait_health = lambda deadline: {"ok": True, "version": D.plugin_version(), "pid": 1}
        fakes: list[_FakeHealth] = []
        fd = os.open(paths.gated_lock(), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)                     # the starting gated's instance lock
        try:
            threading.Timer(1.0, lambda: fakes.append(_FakeHealth())).start()
            t0 = time.monotonic()
            try:
                h = lifecycle.ensure_running(wait=5)
            except lifecycle.StartError as e:
                raise AssertionError(f"StartError after {time.monotonic() - t0:.1f} s: {e.message}") from None
            assert h.get("fake") and spawned == [], (h, spawned)
            assert time.monotonic() - t0 < 4, "used once it answered, not at the deadline"
            # the holder answers "stopping" (going away): waited for, then a new gated
            fakes.pop().close()
            threading.Timer(1.0, lambda: fakes.append(_FakeHealth(stopping="idle"))).start()
            threading.Timer(2.5, os.close, (fd,)).start()  # its lock goes when it has exited
            fd = -1
            h = lifecycle.ensure_running(wait=8)
            assert not h.get("fake") and h["pid"] == 1 and spawned == [1], (h, spawned)
        finally:
            lifecycle._spawn, lifecycle._wait_health = real
            for f in fakes:
                f.close()
            if fd >= 0:
                os.close(fd)


def test_a_registration_refused_as_stopping_goes_to_a_new_daemon_once():
    """client.call: POST /agent/register refused with 503 "stopping" (the
    daemon decided to stop between the caller's start and its registration)
    starts a new daemon (lifecycle.ensure_running) and is sent there, once;
    any other refusal, route or socket is not retried."""
    from gateway.daemon import client, lifecycle
    stopping = client.DaemonError(503, "stopping", "gateway: the gateway daemon is stopping (idle)")
    calls: list[tuple] = []
    starts: list[int] = []

    def fake(answers):
        def _call(method, path, body=None, *, timeout=15.0, sock=None):
            calls.append((method, path, sock))
            a = answers.pop(0)
            if isinstance(a, Exception):
                raise a
            return a
        return _call
    real_call, real_start = client._call, lifecycle.ensure_running
    lifecycle.ensure_running = lambda *a, **k: starts.append(1) or {"ok": True}
    try:
        client._call = fake([stopping, {"ok": True, "registered": {"pid": 1}}])
        assert client.call("POST", "/agent/register", {})["registered"] == {"pid": 1}
        assert len(calls) == 2 and starts == [1], (calls, starts)
        for method, path, sock, err in (
                ("POST", "/agent/register", None, client.DaemonError(503, "stopping", "x")),
                ("POST", "/agent/register", None, client.DaemonError(403, "pid", "x")),
                ("POST", "/ui/register", None, stopping),
                ("POST", "/agent/register", "/elsewhere.sock", stopping)):
            calls.clear()
            starts.clear()
            client._call = fake([err, err] if err.code == "stopping" and path == "/agent/register"
                                and sock is None else [err])
            try:
                client.call(method, path, {}, sock=sock)
                raise AssertionError("no refusal")
            except client.DaemonError as e:
                assert e.code == err.code
            want = 2 if err.code == "stopping" and path == "/agent/register" and sock is None else 1
            assert len(calls) == want and len(starts) == want - 1, (method, path, sock, calls, starts)
    finally:
        client._call, lifecycle.ensure_running = real_call, real_start


def test_gated_start_register_reports_the_daemon_that_took_the_registration():
    """Review (WS-11a) nit: `gated start --register` whose registration was
    refused as stopping and sent to a new daemon (client.call) prints that
    daemon's health, not the stopping one's."""
    import contextlib
    import io

    from gateway.daemon import client, lifecycle
    mine = D.plugin_version()
    old = {"ok": True, "version": mine, "pid": 101, "stopping": "idle"}
    new = {"ok": True, "version": mine, "pid": 202}
    starts = [old, new]
    answers: list = [client.DaemonError(503, "stopping", "gateway: the gateway daemon is stopping (idle)"),
                     {"ok": True, "registered": {"pid": 7}}]

    def _call(method, path, body=None, *, timeout=15.0, sock=None):
        if path == "/health":
            return new
        a = answers.pop(0)
        if isinstance(a, Exception):
            raise a
        return a
    real = client._call, lifecycle.ensure_running
    client._call = _call
    lifecycle.ensure_running = lambda *a, **k: starts.pop(0)
    buf = io.StringIO()
    try:
        with D.daemon_env(start=False), contextlib.redirect_stdout(buf):
            assert lifecycle.main(["start", "--register"]) == 0
    finally:
        client._call, lifecycle.ensure_running = real
    out = json.loads(buf.getvalue())
    assert out["pid"] == 202 and "stopping" not in out and out["registered"] == {"pid": 7}, out
    assert starts == [] and answers == [], (starts, answers)


def _pid_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def test_version_skew_a_newer_plugin_restarts_an_idle_older_daemon():
    """Copies in Claude Code's plugin cache layout (sibling version folders):
    the newer plugin's run.py may ask the older daemon to restart."""
    from gateway import gate
    with D.daemon_env(start=False) as de:
        base = D.plugin_copy(de.root, D.plugin_version())
        old = de.start_from(base)
        newer = D.plugin_copy(de.root, "99.0.0")
        h = de.start_from(newer)
        assert h["version"] == "99.0.0" and h["pid"] != old["pid"], h
        assert _wait_dead(old["pid"])
        # an older plugin uses the newer daemon and says so: start, status, gate status
        h2 = de.start_from(base)
        mine = D.plugin_version()
        want = f"a newer gateway daemon (99.0.0) answers this plugin ({mine})"
        assert h2["pid"] == h["pid"] and want in h2.get("skew", ""), h2
        assert want in de.gated_from(base, "status").get("skew", "")
        assert want in gate.daemon_line(), gate.daemon_line()
        assert "skew" not in de.gated_from(newer, "status")


def test_version_skew_a_busy_older_daemon_is_kept_and_reported():
    """The report reaches the user: `gated start` says it, and `gated status`
    (what /gate-doctor runs) and gate status say it too (the verifier found
    only start's answer carried it)."""
    from gateway import gate
    with D.daemon_env(knobs={"busy": "1 job"}, start=False) as de:
        mine = D.plugin_version()
        old = de.start_from(D.plugin_copy(de.root, "0.0.1"))
        newer = D.plugin_copy(de.root, "99.0.0")
        h = de.start_from(newer)
        assert h["pid"] == old["pid"] and "still runs 1 job" in h.get("skew", ""), h
        st = de.gated_from(newer, "status")
        assert st["pid"] == old["pid"], st
        assert "an older gateway daemon (0.0.1) answers this plugin (99.0.0)" in st.get("skew", ""), st
        line = gate.daemon_line()                      # this checkout's version
        assert f"an older gateway daemon (0.0.1) answers this plugin ({mine})" in line, line
        assert "skew" not in de.gated_from(D.plugin_copy(de.root, "0.0.1"), "status")


# ---------------------------------------------------------------------------
# Peer identity and planes
# ---------------------------------------------------------------------------


def test_peer_credentials_come_from_the_kernel():
    a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        p = peers.peer_cred(a)
        assert p.pid == os.getpid() and p.uid == os.getuid(), p
    finally:
        a.close()
        b.close()


def test_the_uid_check_refuses_another_users_process():
    planes.check_uid(peers.Peer(os.getpid(), os.getuid(), os.getgid()))
    try:
        planes.check_uid(peers.Peer(os.getpid(), os.getuid() + 1, os.getgid()))
    except planes.Denied as e:
        assert e.status == 403 and e.code == "uid"
    else:
        raise AssertionError("another uid passed")


def test_health_needs_only_the_same_user():
    with D.daemon_env() as de:
        st, body = de.call("GET", "/health")
        assert st == 200 and body["ok"]
        st, body = de.call("POST", "/health")
        assert st == 405


def test_the_ui_plane_is_only_the_registered_claude_process():
    with D.daemon_env() as de:
        st, body = de.call("POST", "/ui/vault/lock")               # this test process
        assert st == 403 and body["error"] == "plane", body
        fc = de.claude()
        st, body = fc.http("POST", "/ui/vault/lock")
        assert st == 200 and body["ok"], body
        gate = D.probe_root(de.root)
        st, body = de.probe(fc, gate / "run.py", ["shim", "sudo"], "/ui/vault/lock")
        assert st == 403 and body["error"] == "plane", body        # a child is never the UI
        other = de.claude(register=False)
        st, body = other.http("POST", "/ui/vault/lock")
        assert st == 403, body


def test_the_contract_plane_refuses_the_ui_and_strangers():
    with D.daemon_env() as de:
        fc = de.claude()
        st, body = fc.http("GET", "/v1/capabilities")              # the UI process itself
        assert st == 403 and body["contract"] == 1 and body["error"] == "plane", body
        gate = D.probe_root(de.root)
        st, body = de.probe(fc, gate / "run.py", ["shim", "sudo"], "/v1/capabilities", method="GET")
        assert st == 200 and body["contract"] == 1 and body["features"] == ["hosts", "events", "pause", "jobs", "terminals", "remote", "workspaces", "accounts", "pause_id", "job_env"], body
        st, body = de.call("GET", "/v1/snapshot")                   # no registered session above
        assert st == 403 and body["contract"] == 1
        stranger = de.claude(register=False)
        st, body = de.probe(stranger, gate / "run.py", ["shim", "sudo"], "/v1/snapshot", method="GET")
        assert st == 403, body
        # any program below the session may use the contract (checkpoint's isn't the gateway's)
        other = D.probe_root(de.root, "check")
        st, body = de.probe(fc, other / "run.py", ["mcp"], "/v1/snapshot", method="GET")
        assert st == 200, body
        # jobs are served since PLAN-v4 phase 5 (an empty request is refused as such)
        st, body = de.probe(fc, gate / "run.py", ["shim", "sudo"], "/v1/jobs", body={})
        assert st == 400 and body["contract"] == 1 and "idempotency_key" in body["message"], body


def test_ui_registration_needs_its_own_pid_and_a_claude_executable():
    with D.daemon_env() as de:
        fc = de.claude(register=False)
        st, body = fc.http("POST", "/ui/register", {"claude_pid": fc.pid + 1})
        assert st == 403 and body["error"] == "pid", body
        st, body = fc.http("POST", "/ui/register", {"claude_pid": True})
        assert st == 403, body
        st, body = de.call("POST", "/ui/register", {"claude_pid": os.getpid()})
        assert st == 403 and body["error"] == "exe", body          # python, not claude
        st, body = fc.http("POST", "/ui/register", {"session_id": "s\u0007x" * 50, "surface": "terminal"})
        assert st == 200 and body["registered"]["pid"] == fc.pid, body
        assert "\u0007" not in body["registered"]["session"] and len(body["registered"]["session"]) <= 120
        assert de.health()["sessions"] == 1


def test_a_gateway_hook_registers_the_claude_process_above_it():
    with D.daemon_env() as de:
        fc = de.claude(register=False)
        gate = D.probe_root(de.root)
        st, body = de.probe(fc, gate / "run.py", ["shim", "sudo"], "/agent/register", body={})
        assert st == 403 and body["error"] == "peer", body          # only hooks register
        st, body = de.probe(fc, gate / "run.py", ["hook-session"], "/agent/register",
                            body={"claude_pid": 1})
        assert st == 403 and body["error"] == "pid", body          # not above the hook
        st, body = de.probe(fc, gate / "run.py", ["hook-session"], "/agent/register",
                            body={"session_id": "s-hook"})
        assert st == 200 and body["registered"]["pid"] == fc.pid and not body["registered"]["ui"]
        st, body = de.probe(fc, gate / "run.py", ["shim", "sudo"], "/agent/vault/status")
        assert st == 200, body                                       # the session is known now
        st, body = fc.http("POST", "/ui/vault/lock")
        assert st == 403, body                                       # a hook's session isn't a UI one


def test_the_agent_plane_needs_a_gateway_entry_point():
    """Test entries off (production's rules): the daemon runs a plugin copy
    in Claude Code's plugin cache layout; its own run.py and a sibling
    version folder's (an update while sessions of the other version run)
    are entry points, nothing else is."""
    with D.daemon_env(knobs={"test_entries": False}, start=False) as de:
        base = D.plugin_copy(de.root, D.plugin_version())
        de.start_from(base)
        fc = de.claude()
        cache = base.parent
        sibling = D.probe_root(cache, folder="99.0.0")          # <cache>/gateway/gate/99.0.0
        st, body = de.probe(fc, sibling / "run.py", ["shim", "sudo"], "/agent/vault/status")
        assert st == 200 and body["scope"] == ["sudo_local"], body
        # (a real, writable prefix: a missing absolute one such as /x makes
        # importlib create its folders relative to the cwd, an empty x/... tree)
        st, body = de.probe(fc, sibling / "run.py", ["gate", "status"], "/agent/vault/status",
                            options=("-IS", *H.PYX))
        assert st == 200 and body["scope"] == sorted(broker.ALL), body
        # the daemon's own run.py (the copy it runs): a real hook registers a session
        other_fc = de.claude(register=False, session="s-own")
        r = other_fc.run([H.PY, "-I", "-S", str(base / "run.py"), "--test", "hook-daemon"],
                         env=de.env.subprocess_env(de.extra_env()),
                         input=json.dumps({"session_id": "s-own"}))
        assert r.returncode == 0, r.stderr
        assert de.wait_for(lambda: de.health()["sessions"] == 2), de.health()
        refusals = {
            # a folder anywhere else whose plugin.json says "gate" (the verifier's forged root:
            # it got every secret class as `gate status`)
            "a gate folder outside the plugin": de.probe(fc, D.probe_root(de.root) / "run.py",
                                                         ["gate", "status"], "/agent/vault/status"),
            "a gate folder outside the plugin, mcp": de.probe(fc, D.probe_root(de.root) / "run.py",
                                                              ["mcp"], "/agent/vault/status"),
            "a gate folder in another plugin's cache folder": de.probe(
                fc, D.probe_root(cache.parent / "other", folder="1.0.0") / "run.py",
                ["shim", "sudo"], "/agent/vault/status"),
            "another plugin's run.py": de.probe(fc, D.probe_root(cache, "other", folder="98.0.0") /
                                                "run.py", ["shim", "sudo"], "/agent/vault/status"),
            "a copied python": de.probe(fc, sibling / "run.py", ["shim", "sudo"], "/agent/vault/status",
                                        python=D.named_python("python3.12")),
            "without -I": de.probe(fc, sibling / "run.py", ["shim", "sudo"], "/agent/vault/status",
                                   options=("-S",)),
            "without -S (a planted sitecustomize would run)": de.probe(
                fc, sibling / "run.py", ["shim", "sudo"], "/agent/vault/status", options=("-I",)),
            "another interpreter option": de.probe(fc, sibling / "run.py", ["shim", "sudo"],
                                                   "/agent/vault/status", options=("-I", "-S", "-u")),
            "another -X option": de.probe(fc, sibling / "run.py", ["shim", "sudo"],
                                          "/agent/vault/status", options=("-I", "-S", "-X", "dev")),
            "an unknown mode": de.probe(fc, sibling / "run.py", ["sneaky"], "/agent/vault/status"),
            "a bare shim": de.probe(fc, sibling / "run.py", ["shim"], "/agent/vault/status"),
            # the local plane takes any entry point, but only one with a real mode
            "an unknown mode on the local plane": de.probe(fc, sibling / "run.py", ["sneaky"],
                                                           "/local/stop"),
            "a forged gate folder on the local plane": de.probe(fc, D.probe_root(de.root) / "run.py",
                                                                ["gate", "status"], "/local/stop"),
        }
        for what, (st, body) in refusals.items():
            assert st == 403 and body["error"] == "peer", (what, body)
        assert de.health() is not None
        # python -c (no script at all) with the same code
        env = D.py_env({"GW_PROBE_SOCK": str(de.sock), "GW_PROBE_PATH": "/agent/vault/status"})
        env.pop("PYTHONHOME")
        r = fc.run([H.PY, "-I", "-S", "-c", D.PROBE, "shim", "sudo"], env=env)
        assert json.loads(r.stdout)["status"] == 403, r
        # a gate plugin's root with the test root where the mode goes: no mode
        r = fc.run([H.PY, "-I", "-S", str(sibling / "run.py"), str(de.root), "shim", "sudo"], env=env)
        assert json.loads(r.stdout)["status"] == 403
        # a test entry point (a script in the test root, the root before the mode) is
        # refused unless the test override turns test entries on (never in production)
        drv = de.root / "drivers" / "entry.py"
        drv.parent.mkdir(exist_ok=True)
        drv.write_text(D.PROBE)
        r = fc.run([H.PY, "-I", "-S", str(drv), str(de.root), "shim", "sudo"], env=env)
        assert json.loads(r.stdout)["status"] == 403
        assert "refused POST /agent/vault/status: peer" in de.log()


def test_outside_the_plugin_cache_only_the_plugins_own_run_py_counts():
    """A daemon run from a checkout (--plugin-dir) or a copy elsewhere has no
    sibling versions: a gate folder next to it isn't an entry point."""
    import shutil
    with D.daemon_env(knobs={"test_entries": False}, start=False) as de:
        base = de.root / "work" / "gateway"
        shutil.copytree(D.plugin_copy(de.root, D.plugin_version()), base)
        de.start_from(base)
        fc = de.claude(register=False)
        r = fc.run([H.PY, "-I", "-S", str(base / "run.py"), "--test", "hook-daemon"],
                   env=de.env.subprocess_env(de.extra_env()), input=json.dumps({"session_id": "s"}))
        assert r.returncode == 0 and de.wait_for(lambda: de.health()["sessions"] == 1), r.stderr
        nxt = D.probe_root(base.parent, folder="gateway-2")      # work/gateway-2: a gate folder beside it
        st, body = de.probe(fc, nxt / "run.py", ["shim", "sudo"], "/agent/vault/status")
        assert st == 403 and body["error"] == "peer", body


def test_test_entry_points_count_only_when_the_test_override_says_so():
    with D.daemon_env(knobs={"test_entries": True}) as de:
        fc = de.claude()
        drv = de.root / "drivers" / "entry.py"
        drv.parent.mkdir(exist_ok=True)
        drv.write_text(D.PROBE)
        env = D.py_env({"GW_PROBE_SOCK": str(de.sock), "GW_PROBE_PATH": "/agent/vault/status"})
        env.pop("PYTHONHOME")
        r = fc.run([H.PY, "-I", "-S", str(drv), str(de.root), "shim", "sudo"], env=env)
        out = json.loads(r.stdout)
        assert out["status"] == 200 and out["body"]["scope"] == ["sudo_local"], out
        # outside the test root and the plugin's tests folder: still refused
        elsewhere = Path(H.tmp_base()) / f"elsewhere-{os.getpid()}.py"
        elsewhere.write_text(D.PROBE)
        try:
            r = fc.run([H.PY, "-I", "-S", str(elsewhere), str(de.root), "shim", "sudo"], env=env)
            assert json.loads(r.stdout)["status"] == 403
        finally:
            elsewhere.unlink()


def test_entry_point_parsing():
    assert peers._script_index(["py", "-I", "-S", "-X", "pycache_prefix=/x", "/r/run.py", "gate"]) == 5
    assert peers._script_index(["py", "-IS", "-Xfoo", "/r/run.py"]) == 3
    assert peers._script_index(["py", "-c", "print(1)", "/r/run.py"]) is None
    assert peers._script_index(["py", "-m", "x"]) is None
    assert peers._script_index(["py", "--", "/r/run.py"]) == 2
    ok = peers.launcher_options_ok
    assert ok(["-I", "-S", "-X", "pycache_prefix=/d/pycache"]) and ok(["-IS"]) and ok(["-SI"])
    assert ok(["-I", "-S"]) and ok(["-I", "-Xpycache_prefix=/p", "-S"])
    for bad in ([], ["-I"], ["-S"], ["-I", "-S", "-u"], ["-ISi"], ["-I", "-S", "-X", "dev"],
                ["-I", "-S", "-X"], ["-I", "-S", "-W", "error"], ["-I", "-S", "--"], ["-E", "-s"]):
        assert not ok(bad), bad
    assert peers.is_run_py(str(H.PLUGIN / "run.py"))
    assert not peers.is_run_py("run.py") and not peers.is_run_py(str(H.PLUGIN / "README.md"))
    assert peers.in_plugin_cache("/h/.claude/plugins/cache/gateway/gate/0.7.0")
    assert not peers.in_plugin_cache("/h/projects/gateway/plugins/gateway")
    assert not peers.in_plugin_cache("/plugins/cache/gate")


def test_sessions_survive_a_daemon_restart_and_dead_ones_are_dropped():
    with D.daemon_env() as de:
        fc = de.claude()
        dead = de.claude()
        dead_pid = dead.pid
        dead.close()
        de.stop()
        assert de.wait_for(lambda: de.health() is None)
        # the registry file is the daemon's private record (0600, in the 0700 run dir)
        reg = de.run / "gated-sessions.json"
        assert stat.S_IMODE(os.stat(reg).st_mode) == 0o600
        de.start()
        assert de.health()["sessions"] == 1
        gate = D.probe_root(de.root)
        st, body = de.probe(fc, gate / "run.py", ["shim", "sudo"], "/v1/snapshot", method="GET")
        assert st == 200, body
        pids = [s["pid"] for s in json.loads(reg.read_text())["sessions"]]
        assert fc.pid in pids and dead_pid not in pids


def test_a_session_whose_claude_binary_an_upgrade_deleted_stays_registered():
    """An upgrade deletes the running Claude Code's binary (the native
    install keeps two versions; Homebrew removes the old one): macOS then
    reports no executable path for the process, Linux "<path> (deleted)".
    The session is still the process that registered (pid and start time),
    so it stays registered, may register again (the mod at /clear, a hook),
    keeps the daemon from its idle exit, and is dropped only when it ends.
    The verifier saw it dropped at the next tick, refused on every plane,
    and the daemon exit for idleness under a live session."""
    exe = D.named_python("claude", folder="claude-upgraded-py")   # before the idle clock starts
    with D.daemon_env(knobs={"idle_exit": 1.0}) as de:
        fc = de.claude(exe=exe, session="s-before")
        gate = D.probe_root(de.root)
        st, body = de.probe(fc, gate / "run.py", ["shim", "gh"], "/v1/snapshot", method="GET")
        assert st == 200, body
        os.unlink(exe)                                 # the upgrade removes the old version
        assert peers.exe(fc.pid) in (None, f"{exe} (deleted)"), peers.exe(fc.pid)
        assert not peers.is_claude(fc.pid)
        time.sleep(0.6)                                # several ticks (0.1 s)
        assert fc.p.poll() is None and de.health()["sessions"] == 1, de.health()
        st, body = de.probe(fc, gate / "run.py", ["shim", "gh"], "/v1/snapshot", method="GET")
        assert st == 200, body
        st, body = fc.http("POST", "/ui/vault/lock")
        assert st == 200, body                         # still the UI plane
        st, body = fc.http("POST", "/ui/register", {"claude_pid": fc.pid, "session_id": "s-after",
                                                     "surface": "terminal"})
        assert st == 200 and body["registered"]["session"] == "s-after", body
        st, body = de.probe(fc, gate / "run.py", ["hook-session"], "/agent/register",
                            body={"session_id": "s-hook"})
        assert st == 200 and body["registered"]["pid"] == fc.pid and body["registered"]["ui"], body
        reg = json.loads((de.run / "gated-sessions.json").read_text())["sessions"]
        assert [s["exe"] for s in reg] == [str(exe)], reg     # the executable it registered with
        pid = de.daemon_pid()
        time.sleep(1.5)
        assert de.daemon_pid() == pid, "a live session keeps the daemon"
        # the executable is still checked when a process first registers: one whose
        # binary is gone (so it can't be shown to be Claude Code) is refused
        exe2 = D.named_python("claude", folder="claude-never-registered-py")
        stranger = de.claude(exe=exe2, register=False)
        os.unlink(exe2)
        st, body = stranger.http("POST", "/ui/register", {"claude_pid": stranger.pid})
        assert st == 403 and body["error"] == "exe", body
        stranger.close()
        fc.close()
        assert _wait_dead(pid, 9), "the session ended: idle again"
        kinds = [json.loads(line)["kind"] for line in
                 (paths.gated_dir() / "events" / "epoch-1.jsonl").read_text().splitlines()]
        assert kinds.count("session.ended") == 1 and kinds[-2:] == ["session.ended", "daemon.stopping"], \
            kinds


def test_a_reused_pid_is_not_the_registered_session():
    """A session is its pid with the start time it registered with: a record
    whose start time differs (an earlier process that had this pid) gives the
    process now holding it nothing, on the UI plane or below it."""
    me = os.getpid()
    st0 = peers.started(me)
    assert st0 is not None and peers.alive(me, st0) and peers.alive(me)
    assert not peers.alive(me, st0 - 5) and not peers.alive(me, st0 + 5)
    with D.daemon_env() as de:
        fc = de.claude()
        assert fc.http("POST", "/ui/vault/lock")[0] == 200
        de.stop()
        assert de.wait_for(lambda: de.health() is None)
        reg = de.run / "gated-sessions.json"
        doc = json.loads(reg.read_text())
        assert [s["pid"] for s in doc["sessions"]] == [fc.pid]
        doc["sessions"][0]["start"] -= 30              # the record of an earlier process with this pid
        reg.write_text(json.dumps(doc))
        de.start()
        assert de.health()["sessions"] == 0, de.health()
        st, body = fc.http("POST", "/ui/vault/lock")
        assert st == 403 and body["error"] == "plane", body
        st, body = de.probe(fc, D.probe_root(de.root) / "run.py", ["shim", "gh"], "/v1/snapshot",
                            method="GET")
        assert st == 403, body


def test_only_the_daemons_own_data_folder_env_pythons_are_gateway_pythons():
    """Besides the daemon's own interpreter, a gateway python is one of the
    daemon's data folder's envs (<data>/envs/<sha12>/.pixi/envs/default/bin):
    the same layout under another data folder is refused."""
    with D.daemon_env() as de:
        fc = de.claude()
        gate = D.probe_root(de.root)
        layout = Path("envs") / "0123456789ab" / ".pixi" / "envs" / "default"
        mine = D.python_at(paths.data_dir() / layout)
        theirs = D.python_at(de.root / "other-data" / layout)
        assert paths.data_from_executable(str(mine)) == paths.data_dir()
        st, body = de.probe(fc, gate / "run.py", ["shim", "sudo"], "/agent/vault/status", python=mine)
        assert st == 200 and body["scope"] == ["sudo_local"], body
        st, body = de.probe(fc, gate / "run.py", ["shim", "sudo"], "/agent/vault/status", python=theirs)
        assert st == 403 and body["error"] == "peer", body
        assert peers.python_ok(str(mine)) and not peers.python_ok(str(theirs))


def test_another_configurations_gateway_is_refused_in_words_that_say_so():
    """GW-ROB-2: one gated per user serves one Claude Code configuration (its
    data folder); a second CLAUDE_CONFIG_DIR's gateway programs were refused
    with "vault data only to the gateway's own programs", which says nothing
    of why. The refusal now names both data folders and what to do; anything
    else is refused as before."""
    with D.daemon_env() as de:
        fc = de.claude()
        gate = D.probe_root(de.root)
        layout = Path("envs") / "0123456789ab" / ".pixi" / "envs" / "default"
        theirs = D.python_at(de.root / "other-cfg" / "plugins" / "data" / "gate-gateway" / layout)
        mine = D.python_at(paths.data_dir() / layout)
        other = de.root / "other-cfg" / "plugins" / "data" / "gate-gateway"
        for mode, path in ((["shim", "gh"], "/agent/vault/read"), (["hook-session"], "/agent/register"),
                           (["mcp"], "/agent/term/list"), (["gate"], "/agent/dialog/lease"),
                           (["gated", "stop"], "/local/stop")):
            st, body = de.probe(fc, gate / "run.py", mode, path, body={}, python=theirs,
                                test_entry=False)             # production argv
            assert st == 403 and body["error"] == "other_config", (mode, body)
            msg = body["message"]
            assert "another Claude Code configuration" in msg and paths.describe(other) in msg \
                and paths.describe(paths.data_dir()) in msg and "one gateway daemon per user" in msg \
                and "quit the other configuration's" in msg, msg
            # review round 2: true for an unwrapped vault (the stand-ins read
            # it themselves) and for terminals and jobs keeping gated there
            assert "gets no vault data" not in msg and "no secrets while the vault has a passphrase" \
                in msg and "still read the vault themselves" in msg, msg
            assert "terminals and jobs end" in msg and "stays while any of them runs" in msg \
                and "leaves 30 minutes after its last session" not in msg, msg
        # /gate-doctor there: `gated status` from the other configuration's
        # data folder (another test root, the same run folder) says the daemon
        # serves another configuration; this one's says nothing of it
        theirs_root = de.root / "other-root"
        theirs_root.mkdir()
        for sub in ("status", "start"):
            r = H.run_py(de.env, "--test", "gated", sub,
                         extra_env={**de.extra_env(), "GATEWAY_TEST_ROOT": str(theirs_root)})
            out = json.loads(r.stdout)
            assert r.returncode == 0 and out["ok"] is True, (r.stdout, r.stderr)
            note = out.get("other_config", "")
            assert note.startswith("the gateway daemon running now serves another Claude Code "
                                   "configuration") and paths.describe(paths.data_dir()) in note \
                and str(theirs_root) in note and "Tell the user" in note, out
        assert de.health()["data"] == str(paths.data_dir())
        out = json.loads(de.gated("status").stdout)
        assert out["ok"] is True and "other_config" not in out, out
        assert planes.other_config_note({"ok": True}) == "", "an older daemon without data: nothing"
        # gate status there says it too
        from gateway import gate as gatecli
        from gateway.daemon import client as cl
        h = {**de.health(), "data": str(theirs_root / "data")}
        old_health = cl.health
        cl.health = lambda *a, **k: h
        try:
            line = gatecli.daemon_line()
        finally:
            cl.health = old_health
        assert line.startswith("Gateway daemon: running (") and \
            "; the gateway daemon running now serves another Claude Code configuration" in line, line
        # not another configuration's gateway: refused as before
        not_run = de.root / "probe-gate" / "other.py"
        not_run.write_text((gate / "run.py").read_text())
        for python, script, mode in ((mine, gate / "run.py", ["shim", "gh"]),       # this folder's python
                                     (theirs, not_run, ["shim", "gh"]),            # not a run.py
                                     (theirs, gate / "run.py", ["nonsense"])):     # not a gateway mode
            st, body = de.probe(fc, script, mode, "/agent/vault/read", body={}, python=python,
                                test_entry=False)
            assert st == 403 and body["error"] == "peer", (python, script, mode, body)
        # not the launchers' options
        st, body = de.probe(fc, gate / "run.py", ["shim", "gh"], "/agent/vault/read", body={},
                            python=theirs, options=("-S",), test_entry=False)
        assert st == 403 and body["error"] == "peer", body
        # the dialog's lease says it in the same words (popup reports it as unavailable)
        from gateway.daemon import client

        def refuse(*_a, **_k):
            raise client.DaemonError(403, "other_config", "gateway: the gateway daemon running now "
                                     "serves another Claude Code configuration (...)")
        old = client.call
        client.call = refuse
        try:
            r = client.dialog_lease()
        finally:
            client.call = old
        assert r["available"] is False and r["reason"] == "other_config" \
            and r["message"].startswith("the gateway daemon running now serves another"), r


def test_a_hook_cannot_register_a_process_that_isnt_claude_code():
    """A gateway hook may register only a Claude Code process above it: one
    that names its parent shell (or any other program between it and
    Claude Code) is refused, so a program can't make its own parent a
    session."""
    with D.daemon_env() as de:
        fc = de.claude(register=False)
        gate = D.probe_root(de.root)
        shell = de.root / "drivers" / "shell.py"
        shell.parent.mkdir(exist_ok=True)
        shell.write_text("import json, os, subprocess, sys\n"
                         "os.environ['GW_PROBE_BODY'] = json.dumps({'claude_pid': os.getpid()})\n"
                         "sys.exit(subprocess.run(sys.argv[1:]).returncode)\n")
        st, body = de.probe(fc, gate / "run.py", ["hook-session"], "/agent/register",
                            through=[H.PY, "-I", "-S", str(shell)])
        assert st == 403 and body["error"] == "exe", body
        assert de.health()["sessions"] == 0
        st, body = de.probe(fc, gate / "run.py", ["hook-session"], "/agent/register",
                            body={"claude_pid": fc.pid})
        assert st == 200 and body["registered"]["pid"] == fc.pid, body


def test_the_daemons_log_is_rotated_while_it_runs():
    """The log was rotated only at start: one daemon refusing requests all
    day grew it without bound (the verifier: 7 MB in 25 s). It now becomes
    gated.log.1 past its limit while the daemon runs."""
    with D.daemon_env(knobs={"log_max": 4000}) as de:
        pid = de.daemon_pid()
        log = paths.gated_log()
        old = log.with_name(log.name + ".1")
        for _ in range(150):                           # refused: no session above the test runner
            assert de.call("GET", "/v1/snapshot")[0] == 403
        assert de.daemon_pid() == pid
        assert old.exists(), "no .1 segment"
        assert log.stat().st_size <= 4000 + 200 and old.stat().st_size <= 4000 + 200, \
            (log.stat().st_size, old.stat().st_size)
        assert not log.with_name(log.name + ".2").exists()
        assert stat.S_IMODE(log.stat().st_mode) == 0o600
        n = len(log.read_text().splitlines())
        assert de.call("GET", "/v1/snapshot")[0] == 403
        assert len(log.read_text().splitlines()) in (n + 1, 1), "the daemon writes the new file"


# ---------------------------------------------------------------------------
# Events and the contract routes
# ---------------------------------------------------------------------------


def _get(de: D.DaemonEnv, fc: D.FakeClaude, path: str) -> dict:
    st, body = de.probe(fc, D.probe_root(de.root) / "run.py", ["shim", "gh"], path, method="GET")
    assert st == 200, body
    return body


def test_events_long_poll_wakes_on_a_new_event_and_times_out_without_one():
    with D.daemon_env() as de:
        fc = de.claude()
        first = _get(de, fc, "/v1/events?since=0")
        kinds = [e["kind"] for e in first["events"]]
        assert kinds == ["daemon.started", "session.registered"], kinds
        assert first["epoch"] == 1 and first["next"] == 2 and not first["reset"]
        nxt = first["next"]
        t0 = time.time()
        quiet = _get(de, fc, f"/v1/events?since={nxt}&wait=0.4")
        assert quiet["events"] == [] and 0.35 <= time.time() - t0 < 5
        res: dict = {}

        def poll() -> None:
            res["r"] = _get(de, fc, f"/v1/events?since={nxt}&wait=20")
            res["t"] = time.time()
        th = threading.Thread(target=poll)
        th.start()
        time.sleep(0.8)
        t1 = time.time()
        de.claude(session="s-second")                         # a new event
        th.join(30)
        assert [e["kind"] for e in res["r"]["events"]] == ["session.registered"], res
        assert res["r"]["events"][0]["session"] == "s-second"
        assert res["t"] - t1 < 5
        # wait is capped at 25 s; numbers only
        st, body = de.probe(fc, D.probe_root(de.root) / "run.py", ["shim", "gh"],
                            "/v1/events?since=x", method="GET")
        assert st == 400 and body["contract"] == 1


def test_a_new_epoch_starts_over_and_says_so():
    with D.daemon_env() as de:
        fc = de.claude()
        before = _get(de, fc, "/v1/events?since=0")
        de.stop()
        assert de.wait_for(lambda: de.health() is None)
        de.start()
        after = _get(de, fc, f"/v1/events?since={before['next']}&epoch={before['epoch']}")
        assert after["epoch"] == before["epoch"] + 1 and after["reset"], after
        assert after["events"][0]["kind"] == "daemon.started" and after["events"][0]["seq"] == 1
        # a seq past this epoch's end (an old consumer that names no epoch) starts over too
        late = _get(de, fc, "/v1/events?since=999")
        assert late["reset"] and late["events"][0]["seq"] == 1


def test_the_event_log_is_bounded_in_memory_and_on_disk():
    with D.daemon_env(knobs={"ring": 12, "disk_max": 4096}) as de:
        fc = de.claude()
        for i in range(40):
            st, _b = fc.http("POST", "/ui/register", {"session_id": f"s-{i:03d}"})
            assert st == 200
        r = _get(de, fc, "/v1/events?since=0")
        assert len(r["events"]) == 12 and r["truncated"] and r["next"] == r["events"][-1]["seq"]
        d = paths.gated_dir() / "events"
        cur = d / "epoch-1.jsonl"
        assert cur.stat().st_size <= 4096 and (d / "epoch-1.jsonl.1").exists()
        assert stat.S_IMODE(cur.stat().st_mode) == 0o600


def test_old_epochs_files_are_pruned(tmp=None):
    base = Path(__import__("tempfile").mkdtemp(dir=H.tmp_base()))
    try:
        for n in range(1, 9):
            (base / f"epoch-{n}.jsonl").write_text("{}\n")
        evmod.EventLog(base, 9)
        left = sorted(int(p.name.split("-")[1].split(".")[0]) for p in base.glob("epoch-*"))
        assert left == [5, 6, 7, 8], left
    finally:
        import shutil
        shutil.rmtree(base, ignore_errors=True)


def test_events_carry_only_allowlisted_safe_fields():
    assert evmod.clean("nope.kind", {"x": 1}) is None
    out = evmod.clean("session.registered", {"session": "abc-123", "via": "ui", "ui": True,
                                              "token": "ghp_" + "x" * 36})
    assert out == {"session": "abc-123", "via": "ui", "ui": True}
    assert evmod.clean("session.registered", {"session": "has space"}) == {}
    assert evmod.clean("vault.locked", {"reason": "x" * 200}) == {}
    assert evmod.clean("daemon.started", {"version": "0.7.0", "pid": 12, "argv": ["a"]}) == \
        {"version": "0.7.0", "pid": 12}


def test_the_snapshot_lists_the_forms_hosts_with_stable_machine_ids():
    with D.daemon_env() as de:
        de.env.write_form(FORM)
        fc = de.claude()
        snap = _get(de, fc, "/v1/snapshot")
        assert snap["contract"] == 1 and snap["workspaces"] == [] and snap["terminals"] == [] \
            and snap["jobs"] == [] and isinstance(snap["seq"], int)
        hosts = {h["name"]: h for h in snap["hosts"]}
        assert set(hosts) == {"localhost", "box", "build"}, hosts
        assert hosts["localhost"]["local"] and hosts["localhost"]["identity"] == "machine"
        assert hosts["localhost"]["host"] == json.loads(paths.contract_path().read_text())["machine_id"]
        assert hosts["box"]["address"] == "tester@10.1.2.3:2222" and not hosts["box"]["local"]
        assert all(h["host"].startswith("m_") and len(h["host"]) == 28 for h in hosts.values())
        assert len({h["host"] for h in hosts.values()}) == 3
        de.stop()
        assert de.wait_for(lambda: de.health() is None)
        de.start()
        again = {h["name"]: h["host"] for h in _get(de, fc, "/v1/snapshot")["hosts"]}
        assert again == {n: h["host"] for n, h in hosts.items()}, "ids are stable across restarts"


def test_the_machine_token_is_stable_and_not_the_raw_id():
    from gateway.daemon import lifecycle
    a = lifecycle.machine_token("1234-ABCD")
    assert a == lifecycle.machine_token("1234-ABCD") != lifecycle.machine_token("1234-ABCE")
    assert a.startswith("m_") and len(a) == 28 and "1234" not in a


def test_the_server_refuses_another_uid_before_any_route():
    """The uid check is the first thing every request meets (a peer of
    another user can't be produced without root, so the kernel's answer is
    replaced here, in a server run in this process)."""
    import shutil
    import tempfile
    from gateway import vault
    from gateway.daemon import client, lifecycle
    run = Path(tempfile.mkdtemp(prefix="gwd-", dir="/tmp"))
    os.chmod(run, 0o700)
    saved = peers.peer_cred
    try:
        with H.gateway_env(run=run):
            d = lifecycle.Daemon(k={"tick": 0.1})
            d.bind()
            th = threading.Thread(target=d.server.serve_forever, kwargs={"poll_interval": 0.05},
                                  daemon=True)
            th.start()
            try:
                assert client.health(sock=run / "gated.sock")["pid"] == os.getpid()
                peers.peer_cred = lambda s: peers.Peer(os.getpid(), os.getuid() + 1, os.getgid())
                for method, path in (("GET", "/health"), ("GET", "/v1/snapshot"),
                                     ("POST", "/ui/register"), ("POST", "/agent/vault/read"),
                                     ("POST", "/local/stop"), ("GET", "/nowhere")):
                    try:
                        client.call(method, path, {} if method == "POST" else None,
                                    sock=run / "gated.sock")
                    except client.DaemonError as e:
                        assert e.status == 403 and e.code == "uid", (path, e.status, e.code)
                    else:
                        raise AssertionError(f"{path} answered another uid")
            finally:
                peers.peer_cred = saved
                d.server.shutdown()
                d.server.server_close()
                d.unbind()
                vault._DAEMON_IDENTITY = None
    finally:
        peers.peer_cred = saved
        shutil.rmtree(run, ignore_errors=True)


def test_a_daemon_whose_socket_is_removed_exits():
    """Nobody can reach it then (the run dir deleted, as the e2e suite and the
    TUI harness do when they finish): it exits at its next tick, and never
    makes the deleted run dir again (the live TUI check found an empty one
    left behind)."""
    import shutil
    with D.daemon_env() as de:
        pid = de.daemon_pid()
        os.unlink(de.sock)
        assert _wait_dead(pid, 5)
        assert "the socket is gone" in de.log()
        assert not paths.contract_path().exists()
        de.start()
        pid = de.daemon_pid()
        shutil.rmtree(de.run)
        assert _wait_dead(pid, 5)
        time.sleep(0.3)
        assert not de.run.exists(), "the daemon made its deleted run dir again"
        de.run.mkdir(mode=0o700)                 # for the fixture's cleanup


def test_a_daemon_whose_plugin_folder_is_removed_exits_and_withdraws_the_contract():
    """`claude plugin uninstall gate@gateway` removes the plugin's cache
    folder or marks it orphaned: the daemon running from it stops at its next
    tick (not 30 min later), removing contract.json, so checkpoint stops
    finding a gateway; one that still holds terminals or jobs keeps running
    for them but drains (contract.json withdrawn at once, no new work:
    test_terminals' uninstall tests), and (orphaned) one that still serves a
    live session keeps serving it."""
    import shutil
    with D.daemon_env(start=False) as de:
        copy = D.plugin_copy(de.root, D.plugin_version())
        h = de.start_from(copy)
        assert paths.contract_path().exists()
        shutil.rmtree(copy)
        assert _wait_dead(h["pid"], 8), "the daemon of a removed plugin stops"
        assert "the plugin folder it runs from is gone" in de.log(), de.log()[-600:]
        assert not paths.contract_path().exists() and not de.sock.exists()
    with D.daemon_env(knobs={"busy": "1 job"}, start=False) as de:
        copy = D.plugin_copy(de.root, D.plugin_version())
        h = de.start_from(copy)
        shutil.rmtree(copy)
        time.sleep(1.0)
        assert de.daemon_pid() == h["pid"], "a daemon holding jobs keeps running for them"
        assert "plugin folder it runs from is gone" in (de.health() or {}).get("draining", ""), de.health()
        assert not paths.contract_path().exists(), "a draining daemon still advertises the contract"
        assert "taking no new work" in de.log(), de.log()[-600:]
    # an update (a newer sibling version folder beside the orphaned one) isn't
    # an uninstall: a daemon holding jobs keeps serving them and the contract
    with D.daemon_env(knobs={"busy": "1 job"}, start=False) as de:
        copy = D.plugin_copy(de.root, D.plugin_version())
        h = de.start_from(copy)
        D.plugin_copy(de.root, "99.0.0")
        (copy / ".orphaned_at").write_text("1792450000000")
        time.sleep(1.0)
        assert de.daemon_pid() == h["pid"] and not (de.health() or {}).get("draining"), de.health()
        assert paths.contract_path().exists()
    # uninstalled with --keep-data (orphaned, no sibling) while it holds jobs: drains
    with D.daemon_env(knobs={"busy": "1 job"}, start=False) as de:
        copy = D.plugin_copy(de.root, D.plugin_version())
        h = de.start_from(copy)
        (copy / ".orphaned_at").write_text("1792450000000")
        assert de.wait_for(lambda: (de.health() or {}).get("draining"), 5), de.health()
        assert de.daemon_pid() == h["pid"] and not paths.contract_path().exists()
    # Claude Code's uninstall (2.1.301) keeps the version folder and marks it
    # orphaned (`.orphaned_at`) for a later sweep; an update marks the old one
    # the same way: a session still running that version keeps the daemon
    with D.daemon_env(start=False) as de:
        copy = D.plugin_copy(de.root, D.plugin_version())
        h = de.start_from(copy)
        fc = de.claude()
        (copy / ".orphaned_at").write_text("1792450000000")
        time.sleep(1.0)
        assert de.daemon_pid() == h["pid"], "a live session of the orphaned version keeps the daemon"
        fc.close()
        assert _wait_dead(h["pid"], 8), "the orphaned version's daemon leaves with its last session"
        assert not paths.contract_path().exists()


def test_a_hung_daemon_costs_a_hook_one_short_wait_and_is_never_started_twice():
    """gated stopped (SIGSTOP, a hang): the socket takes connections but
    nothing answers. A hook's vault read used to wait 15 s, then start another
    daemon (which exits on the instance lock) and wait 10 s more, in every
    hook of every call (acceptance: each Bash call stalled ~12 s). Now the
    first hook waits HOOK_TIMEOUT and marks the daemon unresponsive, later
    hooks skip it at once (failing open as before: no decision, shapes-only
    masking), `gated start` says it hangs instead of starting another, and
    the first answer after it wakes clears the mark."""
    from gateway import vault
    from gateway.daemon import client
    with D.daemon_env() as de:
        de.env.write_form(FORM)
        vault.save(vault.empty())
        de.wrap("a-test-passphrase-123")
        fc = de.claude()
        env = de.env.subprocess_env({**de.extra_env(), "CLAUDE_PLUGIN_DATA": str(de.env.data),
                                     "CLAUDE_CODE_SESSION_ID": "s-test"})

        def hook(mode: str, payload: dict) -> tuple[float, subprocess.CompletedProcess]:
            t0 = time.time()
            r = fc.run([D.PY, "-I", "-S", *H.PYX, str(H.PLUGIN / "run.py"), "--test", mode], env=env,
                       input=json.dumps({"session_id": "s-test", "cwd": str(de.root),
                                         "transcript_path": "", **payload}), timeout=120)
            return time.time() - t0, r

        bash = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "permission_mode": "default",
                "tool_input": {"command": "echo stopped > stopped.txt"}}
        post = {"hook_event_name": "PostToolUse", "tool_name": "Bash",
                "tool_input": {"command": "echo x"}, "tool_response": {"stdout": "x", "stderr": ""}}
        pid = de.daemon_pid()
        marker = de.run / "gated-unresponsive"
        os.kill(pid, signal.SIGSTOP)
        try:
            dt, r = hook("hook-bash", bash)
            assert r.returncode == 0 and dt < client.HOOK_TIMEOUT + 3, (dt, r.stderr)
            assert marker.read_text().split() == [str(pid)]
            for mode, p in (("hook-post", post), ("hook-bash", bash)):
                dt, r = hook(mode, p)
                assert r.returncode == 0 and dt < 2.5, (mode, dt, r.stderr)
            t0 = time.time()
            g = de.gated("start", timeout=60)
            assert time.time() - t0 < 1 + 3 + 3, time.time() - t0
            assert "running but isn't answering" in g.stdout, g.stdout
            assert de.log().count("started: version") == 1, "a second daemon was started"
        finally:
            os.kill(pid, signal.SIGCONT)
        dt, r = hook("hook-post", post)       # the mark is still fresh: skipped once more
        time.sleep(0.1)
        marker.write_text(f"{pid}\n")
        os.utime(marker, (time.time() - client.UNRESPONSIVE_TTL - 1,) * 2)   # stale: asked again
        dt, r = hook("hook-bash", bash)
        assert r.returncode == 0 and dt < 3, (dt, r.stderr)
        assert not marker.exists(), "the answer clears the mark"
        assert de.daemon_pid() == pid


def test_the_contract_file_is_private_whatever_the_umask():
    """contract.json is 0600 in a 0700 folder by its own open mode, not only
    because the detached daemon runs with umask 077; and a daemon removes it
    only while it names that daemon's pid."""
    import shutil
    import tempfile
    from gateway import vault
    from gateway.daemon import lifecycle
    run = Path(tempfile.mkdtemp(prefix="gwd-", dir="/tmp"))
    os.chmod(run, 0o700)
    old = os.umask(0o022)
    try:
        with H.gateway_env(run=run):
            d = lifecycle.Daemon(k={})
            try:
                d.write_contract()
                p = paths.contract_path()
                assert stat.S_IMODE(p.stat().st_mode) == 0o600
                assert stat.S_IMODE(p.parent.stat().st_mode) == 0o700
                doc = json.loads(p.read_text())
                doc["pid"] = doc["pid"] + 1           # another daemon's file now
                p.write_text(json.dumps(doc))
                d.remove_contract()
                assert p.exists()
                d.write_contract()
                d.remove_contract()
                assert not p.exists()
            finally:
                vault._DAEMON_IDENTITY = None
    finally:
        os.umask(old)
        shutil.rmtree(run, ignore_errors=True)


def test_claude_codes_native_install_is_recognised_under_a_test_override():
    """The live e2e check (TUI harness) found the mod's registration refused:
    the native install's binary is ~/.local/share/claude/versions/<v> (not
    named claude), and the e2e override's home isn't where it is installed.
    Claude Code is recognised by the person's own home (password database)."""
    real = __import__("gateway.testing", fromlist=["x"]).real_user_home()
    with H.gateway_env():
        assert peers.exe_is_claude(str(real / ".local" / "share" / "claude" / "versions" / "2.1.301"))
        assert peers.exe_is_claude(str(real / "Library" / "Application Support" / "Claude" /
                                       "claude-code" / "2.1.299" / "x" / "claude.app" / "Contents" /
                                       "MacOS" / "claude"))
        assert peers.exe_is_claude("/opt/anything/bin/claude")
        assert not peers.exe_is_claude(str(real / ".local" / "share" / "other" / "versions" / "2.1.301"))
        assert not peers.exe_is_claude("/usr/bin/python3")


def _npm_layout(base: Path) -> tuple[Path, Path, Path]:
    """npm's global layout under `base` (as `npm i -g @anthropic-ai/claude-code`
    made it before 2.1.113): (the package folder, <prefix>/bin/claude -> the
    package's cli.js, which is a copy of fake_claude.py, and a copy of python
    named node)."""
    pkg = base / "lib" / "node_modules" / "@anthropic-ai" / "claude-code"
    pkg.mkdir(parents=True)
    shutil.copyfile(D.TESTS / "fakes" / "fake_claude.py", pkg / "cli.js")
    (base / "bin").mkdir()
    (base / "bin" / "claude").symlink_to("../lib/node_modules/@anthropic-ai/claude-code/cli.js")
    return pkg, base / "bin" / "claude", D.named_python("node")


def test_an_npm_installed_claude_code_is_recognised_by_its_native_binary_only():
    """npm's package runs its native binary as
    .../@anthropic-ai/claude-code/bin/claude.exe: it registers on the UI plane
    and its gateway programs get the agent plane. Node running the package's
    cli.js (npm installs before 2.1.113) is no longer Claude Code (latest
    only), nor is node running any other script, an option before cli.js, or
    another program running cli.js."""
    with D.daemon_env() as de:
        pkg, shim, node = _npm_layout(de.root / "npm")
        gate = D.probe_root(de.root)
        env = de.env.subprocess_env(de.extra_env())
        native = D.python_at(pkg, "claude.exe")
        fc = de.claude(exe=native, session="s-npm-native")
        st, body = de.probe(fc, gate / "run.py", ["shim", "sudo"], "/agent/vault/status")
        assert st == 200, body
        r = fc.run([H.PY, "-I", "-S", *H.PYX, str(H.PLUGIN / "run.py"), "--test", "gated", "status"], env=env)
        out = json.loads(r.stdout)
        assert out["claude_install"] == "npm (its native binary)" and out["parent_pid"] == fc.pid, out
        other = de.root / "other" / "cli.js"
        other.parent.mkdir()
        shutil.copyfile(D.TESTS / "fakes" / "fake_claude.py", other)
        loose = de.root / "loose" / "node_modules" / "claude-code" / "cli.js"
        loose.parent.mkdir(parents=True)
        shutil.copyfile(D.TESTS / "fakes" / "fake_claude.py", loose)
        for argv in ([node, shim], [node, pkg / "cli.js"], [node, other], [node, "-S", shim],
                     [D.named_python("python3"), shim], [node, loose],
                     [node, os.path.relpath(shim, de.root)]):
            stranger = de.claude(argv=[str(a) for a in argv], register=False, cwd=de.root)
            st, body = stranger.http("POST", "/ui/register", {"claude_pid": stranger.pid})
            assert st == 403 and body["error"] == "exe", (argv, body)
            r = stranger.run([H.PY, "-I", "-S", *H.PYX, str(H.PLUGIN / "run.py"), "--test", "gated",
                              "status"], env=env)
            out = json.loads(r.stdout)
            assert out["claude_install"] == "" and "parent_pid" not in out and out["parent_exe"], (argv, out)
            # (named: a hook that names none takes the first Claude Code above it,
            # which under a test run may be the runner's own)
            st, body = de.probe(stranger, gate / "run.py", ["hook-session"], "/agent/register",
                                body={"claude_pid": stranger.pid})
            assert st == 403 and body["error"] == "exe", (argv, body)
        assert de.health()["sessions"] == 1
