"""Terminals and jobs (PLAN-v4 phase 5): gated's tmux supervisor.

Pure helpers (daemon/screen.py) in this process; everything else against a
real gated in a test root (harness_daemon) with the gateway env's tmux on the
test run dir's private socket: a FakeClaude is the Claude Code session (its
own requests are the UI plane, the gate mod's terminal pane), and a probe in
mode `mcp` below it plays the gw MCP server (the agent's terminal_* and job_*
tools). The MCP server itself (run.py --test mcp) is driven once over stdio.

Canaries are generated here and never printed: assertion messages carry
lengths and hashes only.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

import harness as H
import harness_daemon as D
from gateway import paths, vault
from gateway.daemon import screen
from gateway.daemon import terminals as T


# sha256 of stdin in a pane, on macOS (shasum) and Linux (sha256sum)
SHA256 = "{ if command -v sha256sum >/dev/null; then sha256sum; else shasum -a 256; fi; }"


def canary(prefix: str = "cv") -> str:
    return f"{prefix}-{secrets.token_urlsafe(18)}"


def sha16(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_screen_split_escapes_keeps_styles_and_drops_every_other_sequence():
    plain, runs = screen.split_escapes("\x1b[31mred\x1b[39m plain \x1b[1m\x1b[44mbold\x1b[0m")
    assert plain == "red plain bold"
    assert runs == [{"t": "red", "fg": "red"}, {"t": " plain "}, {"t": "bold", "b": 1, "bg": "blue"}]
    plain, runs = screen.split_escapes("\x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\ \x1b[38;5;196mc\x1b[0m"
                                       "\x1b[38;2;1;2;3mt\x1b[7mr\x1b[27m\x07\x01")
    assert plain == "link ctr", plain
    assert runs[-3] == {"t": "c", "fg": "#ff0000"} and runs[-2] == {"t": "t", "fg": "#010203"}
    assert runs[-1] == {"t": "r", "fg": "#010203", "r": 1}


def test_screen_clean_stream_makes_a_pty_stream_readable():
    assert screen.clean_stream(b"a\r\nprogress 10%\rprogress 100%\r\n\x1b[1mdone\x1b[0m\n") == \
        "a\nprogress 100%\ndone\n"
    assert screen.clean_stream(b"long line here\rshort") == "shortline here"
    assert screen.clean_stream("caf\u00e9\x07\x1b[2J".encode()) == "caf\u00e9"


def test_key_and_signal_names():
    assert [screen.tmux_key(k) for k in ("Enter", "return", "C-c", "^d", "ctrl-z", "esc", "PageUp",
                                         "F12", "M-x", "Delete", "BSpace")] == \
        ["Enter", "Enter", "C-c", "C-d", "C-z", "Escape", "PPage", "F12", "M-x", "DC", "BSpace"]
    for bad in ("bogus", "C-é", "", None, 3, "M- ", "x" * 40, "send-keys"):
        assert screen.tmux_key(bad) is None, bad
    assert screen.signal_name("sigint") == "INT" and screen.signal_name("TERM") == "TERM"
    assert screen.signal_name("SEGV") is None and screen.signal_name(9) is None
    # tmux's #{pane_dead_signal}: "term" on macOS, "15" on Linux
    assert T.signal_word("term") == "TERM" and T.signal_word("15") == "TERM"
    assert T.signal_word("SIGKILL") == "KILL" and T.signal_word("") is None and T.signal_word("a b") is None


def test_ids_are_ulids_with_their_prefix():
    a, b = T.ulid("t"), T.ulid("j")
    assert T.ID_RE.fullmatch(a) and T.ID_RE.fullmatch(b) and a.startswith("t_") and b.startswith("j_")
    assert len({T.ulid("t") for _ in range(200)}) == 200


def test_the_start_file_unsets_everything_but_the_platform_and_never_holds_a_command_line_value():
    p = T.Pane(id=T.ulid("t"), cwd="/tmp/a b")
    text = T.start_text(p, rc="/x/rc.bash", exports={"LC_X": "it's $(rm -rf /)"}, path="/a:/b",
                        me=Path("/run/terms/x.rc"))
    assert "unset \"$__gw_n\"" in text and "LC_*" in text and "TMUX" not in text.split("case")[1].split(")")[0]
    assert "export LC_X='it'\"'\"'s $(rm -rf /)'" in text
    assert "export GW_TERMINAL=" + p.id in text and "export CLAUDE_PID=$$" in text
    assert "command rm -f -- /run/terms/x.rc" in text and "cd -- '/tmp/a b'" in text
    assert "unset HISTFILE" in text
    j = T.Pane(id=T.ulid("j"), cwd="/tmp")
    jt = T.start_text(j, rc="", exports={}, path="/a", me=Path("/x.sh"), argv=["printf", "%s\\n", "a b"])
    assert jt.rstrip().endswith("printf '%s\\n' 'a b'") and "exec " not in jt


# ---------------------------------------------------------------------------
# A real gated with its supervisor
# ---------------------------------------------------------------------------


class Agent:
    """The gw MCP server's side (mode mcp, below the fake claude)."""

    def __init__(self, de: D.DaemonEnv, fc: D.FakeClaude):
        self.de, self.fc = de, fc
        self.probe = D.probe_root(de.root)
        self.answers: list[str] = []

    def call(self, path: str, body: dict[str, Any], mode: str = "mcp") -> tuple[int, dict[str, Any]]:
        st, b = self.de.probe(self.fc, self.probe / "run.py", [mode], path, body)
        self.answers.append(json.dumps(b))
        return st, b

    def ok(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        st, b = self.call(path, body)
        assert st == 200 and b.get("ok") is not False, (path, st, json.dumps(b)[:600])
        return b

    def spawn(self, path: str, body: dict[str, Any]) -> int:
        env = D.py_env({"GW_PROBE_SOCK": str(self.de.sock), "GW_PROBE_PATH": path,
                        "GW_PROBE_METHOD": "POST", "GW_PROBE_BODY": json.dumps(body)})
        env.pop("PYTHONHOME")
        return self.fc.spawn([D.PY, "-I", "-S", str(self.probe / "run.py"), str(self.de.root), "mcp"],
                             env=env)

    def result(self, pid: int) -> tuple[int, dict[str, Any]]:
        r = self.fc.wait(pid)
        out = json.loads(r.stdout)
        self.answers.append(json.dumps(out["body"]))
        return out["status"], out["body"]

    def open(self, **kw: Any) -> dict[str, Any]:
        return self.ok("/agent/term/open", {"cwd": str(self.de.root), "cols": 100, "rows": 24, **kw})

    def read(self, tid: str, **kw: Any) -> dict[str, Any]:
        return self.ok("/agent/term/read", {"id": tid, **kw})

    def run(self, tid: str, text: str, wait_for: str | None = None, timeout: float = 15,
            done: bool = True) -> dict[str, Any]:
        """Type a line (quoting the current seq) and wait until it has run: a
        marker echoed after it (spelled so the typed line itself never shows
        it), then `wait_for`. done=False for a line that waits (less, read)."""
        seq = self.read(tid)["seq"]
        self.n = getattr(self, "n", 0) + 1
        mark = f"__DONE_{self.n}__"
        line = text + (f'; echo "__D""ONE_{self.n}__"' if done else "")
        b = self.ok("/agent/term/send", {"id": tid, "seq": seq, "text": line, "enter": True})
        if done:
            b = self.wait(tid, mark, timeout)
        if wait_for is not None:
            b = self.wait(tid, wait_for, timeout)
        return b

    def wait(self, tid: str, needle: str, timeout: float = 15) -> dict[str, Any]:
        end = time.time() + timeout
        while time.time() < end:
            v = self.read(tid)
            if any(needle in ln for ln in v.get("lines", [])):
                return v
            time.sleep(0.15)
        raise AssertionError(f"{needle!r} never showed: {self.read(tid).get('lines')}")


def _job_wait(a: Agent, jid: str, states: tuple[str, ...], timeout: float = 15) -> dict[str, Any]:
    end = time.time() + timeout
    while time.time() < end:
        st = a.ok("/agent/job/status", {"id": jid})
        if st["state"] in states:
            return st
        time.sleep(0.1)
    raise AssertionError(f"job {jid} never reached {states}: {a.ok('/agent/job/status', {'id': jid})}")


def _events(de: D.DaemonEnv, kinds: tuple[str, ...]) -> list[dict[str, Any]]:
    fc = de.claudes[0]
    a = Agent(de, fc)
    r = fc.run([D.PY, "-I", "-S", str(a.probe / "run.py")],
               env={**{k: v for k, v in D.py_env().items() if k != "PYTHONHOME"},
                    "GW_PROBE_SOCK": str(de.sock), "GW_PROBE_PATH": "/v1/events?since=0&wait=0",
                    "GW_PROBE_METHOD": "GET"})
    body = json.loads(r.stdout)["body"]
    return [e for e in body["events"] if e["kind"] in kinds]


def _tmux(de: D.DaemonEnv, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([paths.tool("tmux"), "-S", str(de.run / "tmux.sock"), *args],
                          capture_output=True, text=True, timeout=10,
                          env={"PATH": "/usr/bin:/bin", "HOME": str(de.env.o.user_home)})


def _gated_files(de: D.DaemonEnv) -> bytes:
    out = b""
    for base in (de.run, paths.gated_dir()):
        for p in Path(base).rglob("*"):
            if p.is_file() and not p.is_socket() and not str(p).endswith(".fifo"):
                try:
                    out += p.read_bytes()
                except OSError:
                    pass
    return out


def test_a_terminal_runs_the_gateway_bash_in_the_managed_environment_never_the_users_setup():
    with D.daemon_env() as de:
        home = de.env.o.user_home
        marker = de.root / "user-rc-ran"
        for n in (".bashrc", ".bash_profile", ".profile"):
            (home / n).write_text(f": > '{marker}'\nexport FROM_USER_RC=1\n")
        (home / ".tmux.conf").write_text("set -g status on\nset -g @gw_user_conf yes\n")
        fc = de.claude()
        a = Agent(de, fc)
        lc = canary("lc")
        tok = canary("ghp")
        v = a.open(env={"LC_GWTEST": lc, "GITHUB_TOKEN": tok, "LANG": "C.UTF-8"})
        tid = v["id"]
        assert T.ID_RE.fullmatch(tid) and tid.startswith("t_")
        assert v["state"] == "open" and v["owner"] == "agent" and v["kind"] == "terminal"
        assert v["host"] == "localhost" and v["host_id"].startswith("m_") and v["mine"] is True
        assert isinstance(v["seq"], int) and v["cols"] == 100 and v["rows"] == 24
        # what the pane's processes and the tmux server have on their command lines
        ps = subprocess.run(["ps", "-axww", "-o", "command="], capture_output=True, text=True).stdout
        assert lc not in ps and tok not in ps
        out = de.root / "env.txt"
        a.run(tid, f"env > '{out}'; echo BASH=$BASH_VERSION; echo done-env", "done-env")
        env = dict(ln.split("=", 1) for ln in out.read_text().splitlines() if "=" in ln)
        assert env.get("LC_GWTEST") == lc, "a platform variable from the caller didn't arrive"
        assert "GITHUB_TOKEN" not in env, "a credential-looking variable reached the pane"
        assert "FROM_USER_RC" not in env and not marker.exists(), "the user's rc ran"
        assert "TMUX" not in env and "TMUX_PANE" not in env
        assert env.get("GW_TERMINAL") == tid and env.get("PATH", "").startswith(str(paths.bin_dir()))
        assert env.get("SHELL", "").endswith("/bash") and env.get("HOME") == str(home)
        assert env.get("CLAUDE_PID", "").isdigit()
        assert any(ln.startswith("BASH=5.") for ln in a.read(tid)["lines"])
        # the start file is gone once read, and nothing in the run dir holds the values
        assert not list((de.run / "terms").glob("*.rc"))
        assert lc.encode() not in _gated_files(de) and tok.encode() not in _gated_files(de)
        # the user's tmux config was never read: the gateway's own is
        assert _tmux(de, "show", "-gv", "@gw_user_conf").stdout.strip() == ""
        assert _tmux(de, "show", "-gv", "status").stdout.strip() == "off"
        assert _tmux(de, "show", "-gv", "remain-on-exit").stdout.strip() == "on"
        assert _tmux(de, "show", "-gv", "history-limit").stdout.strip() == "10000"
        assert _tmux(de, "show", "-gv", "set-clipboard").stdout.strip() == "off"
        assert stat_mode(de.run / "tmux.sock") & 0o077 == 0
        ev = _events(de, ("terminal.opened",))
        assert ev and ev[-1]["terminal"] == tid and ev[-1]["session"] == "s-test"


def stat_mode(p: Path) -> int:
    return os.stat(p).st_mode & 0o777


def test_reads_are_bounded_and_a_send_must_quote_the_current_seq():
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open(cols=80, rows=10)["id"]
        v = a.run(tid, "for i in $(seq 1 60); do echo line-$i; done; echo end-of-lines", "end-of-lines")
        assert len(v["lines"]) <= 10 and v["cursor"]["y"] < 10 and v["alternate_screen"] is False
        h = a.read(tid, history=30)
        assert len(h["history"]) == 30 and h["history"][-1].startswith("line-") and h["history_size"] >= 30
        big = a.read(tid, history=999999)
        assert len(big.get("history", [])) <= T.HISTORY_MAX
        old = v["seq"]
        a.run(tid, "echo moved-on", "moved-on")
        st, b = a.call("/agent/term/send", {"id": tid, "seq": old, "text": "echo should-not-run",
                                            "enter": True})
        assert st == 409 and b["error"] == "stale" and b["seq"] > old, b
        assert not any("should-not-run" in ln for ln in a.read(tid)["lines"])
        st, b = a.call("/agent/term/send", {"id": tid, "text": "echo no-seq"})
        assert st == 400 and b["error"] == "no_seq"
        st, b = a.call("/agent/term/send", {"id": tid, "seq": a.read(tid)["seq"], "text": "a\x03b"})
        assert st == 400 and b["error"] == "bad_text"
        st, b = a.call("/agent/term/send", {"id": tid, "seq": a.read(tid)["seq"], "keys": ["nope"]})
        assert st == 400 and b["error"] == "bad_keys"
        # a long line is cut and said so
        w = a.run(tid, "printf 'x%.0s' $(seq 1 3000); echo; echo wide-done", "wide-done")
        assert all(len(ln) <= T.LINE_MAX for ln in w["lines"])
        st, b = a.call("/agent/term/read", {"id": "t_NOPE"})
        assert st == 400
        st, b = a.call("/agent/term/read", {"id": T.ulid("t")})
        assert st == 404 and "terminal_list" in b["message"]


def test_user_takeover_fails_a_queued_agent_write_and_handing_back_needs_a_fresh_read():
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        v = a.open()
        tid = v["id"]
        pid = a.spawn("/agent/term/send", {"id": tid, "seq": v["seq"], "text": "echo queued-write",
                                           "enter": True, "delay_ms": 4000})
        time.sleep(1.0)
        st, tk = fc.http("POST", "/ui/term/take", {"id": tid})
        assert st == 200 and tk["owner"] == "user", tk
        st, b = a.result(pid)
        assert st == 409 and b["error"] == "taken" and "input taken by the user; re-read the screen" in \
            b["message"], b
        time.sleep(4.0)
        assert not any("queued-write" in ln for ln in a.read(tid)["lines"])
        # while the user holds it: refused at once
        st, b = a.call("/agent/term/send", {"id": tid, "seq": a.read(tid)["seq"], "text": "x"})
        assert st == 409 and b["error"] == "user"
        st, b = a.call("/agent/term/signal", {"id": tid, "signal": "INT"})
        assert st == 409 and b["error"] == "user"
        # the person types (cwd and an exported variable change in the same shell)
        st, k = fc.http("POST", "/ui/term/keys", {"id": tid, "seq": 3, "items": [
            {"k": "text", "v": "cd / && export GWX=from-the-user"}, {"k": "key", "v": "Enter"}]})
        assert st == 200 and k["sent"] == 2 and k["acked"] == 3
        time.sleep(0.4)
        before = a.read(tid)
        st, rl = fc.http("POST", "/ui/term/release", {"id": tid})
        assert st == 200 and rl["owner"] == "agent" and rl["seq"] > before["seq"]
        st, b = a.call("/agent/term/send", {"id": tid, "seq": before["seq"], "text": "echo old-seq"})
        assert st == 409 and b["error"] == "stale"
        after = a.run(tid, 'echo "PI""D=$$ cwd=$PWD gwx=$GWX"', "PID=")
        line = next(ln for ln in after["lines"] if ln.startswith("PID="))
        assert "cwd=/ " in line and "gwx=from-the-user" in line
        ev = _events(de, ("terminal.owner",))
        assert [e["owner"] for e in ev if e["terminal"] == tid][-2:] == ["user", "agent"]
        assert all(e.get("by") in ("user", "agent") for e in ev)


def test_one_agent_holds_the_input_and_another_takes_it_with_a_read():
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        # the mod names the agent loop behind each tool call (the UI plane)
        assert fc.http("POST", "/ui/term/agent", {"tool_use_id": "toolu_sub1", "agent": "a-sub-1"})[0] == 200
        seq = a.read(tid)["seq"]
        b = a.ok("/agent/term/send", {"id": tid, "seq": seq, "text": "echo from-sub", "enter": True,
                                      "tool_use_id": "toolu_sub1"})
        st, r = a.call("/agent/term/send", {"id": tid, "seq": b["seq"], "text": "echo from-main",
                                            "enter": True})
        assert st == 409 and r["error"] == "holder" and "a-sub-1" in r["message"], r
        v = a.ok("/agent/term/read", {"id": tid, "take": True})
        assert v["owner"] == "agent" and "holder_agent" not in v
        a.ok("/agent/term/send", {"id": tid, "seq": v["seq"], "text": "echo from-main", "enter": True})
        # a tool_use_id the mod named for another session counts for nobody
        assert a.ok("/agent/term/list", {})["terminals"][0]["id"] == tid
        st, _ = a.call("/agent/term/read", {"id": tid, "take": True})
        assert st == 200
        # never from the user
        fc.http("POST", "/ui/term/take", {"id": tid})
        st, r = a.call("/agent/term/read", {"id": tid, "take": True})
        assert st == 409 and r["error"] == "user"


def test_another_session_may_read_but_not_write_and_adopts_only_an_orphan():
    with D.daemon_env() as de:
        fc1 = de.claude(session="s-one")
        a1 = Agent(de, fc1)
        tid = a1.open()["id"]
        fc2 = de.claude(session="s-two")
        a2 = Agent(de, fc2)
        v = a2.read(tid)
        assert v["mine"] is False and v["session"] == "s-one"
        st, r = a2.call("/agent/term/send", {"id": tid, "seq": v["seq"], "text": "echo x"})
        assert st == 403 and r["error"] == "other_session"
        st, r = a2.call("/agent/term/read", {"id": tid, "take": True})
        assert st == 403 and "still running" in r["message"]
        fc1.close()
        deadline = time.time() + 5
        while time.time() < deadline:
            st, r = a2.call("/agent/term/read", {"id": tid, "take": True})
            if st == 200:
                break
            time.sleep(0.2)
        assert st == 200 and r["session"] == "s-two" and r["mine"] is True, r
        a2.run(tid, "echo adopted-ok", "adopted-ok")


def _tmux_wrapper(base: Path) -> tuple[Path, Path]:
    """A tmux that logs every command line it gets (one per line), then runs
    the env's tmux: what the supervisor puts on tmux's argv, which any local
    user can read in the process table."""
    log = base / "tmux-argv.log"
    log.write_text("")
    w = base / "tmux-wrapper"
    w.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> '{log}'\nexec '{paths.tool('tmux')}' \"$@\"\n")
    os.chmod(w, 0o755)
    return w, log


def test_a_password_prompt_goes_through_the_dialog_to_that_pane_only_and_is_never_logged():
    from test_dialogs import Mod, seal
    with D.daemon_env(start=False) as de:
        wrapper, argv_log = _tmux_wrapper(de.root)
        de.knobs(tmux=str(wrapper))
        de.start()
        fc = de.claude()
        mod = Mod(fc)
        a = Agent(de, fc)
        tid = a.open()["id"]
        a.run(tid, 'read -s -p "Password: " pw; echo; echo "GOT""LEN=${#pw} '
                   'sha=$(printf %s "$pw" | ' + SHA256 + ' | cut -c1-16)"', done=False)
        d = mod.dialog(lambda x: x.get("entry") == "terminal", timeout=10)
        assert d["kind"] == "secret" and d["target"] == tid and d["paste"] is True
        assert any(tid in ln for ln in d["lines"])
        v = a.read(tid)
        assert v["waiting_auth"] is True and "dialog" in v["note"]
        st, r = a.call("/agent/term/send", {"id": tid, "seq": v["seq"], "text": "guess"})
        assert st == 409 and r["error"] == "auth"
        # typed text from the terminal pane is refused while the prompt waits
        st, k = fc.http("POST", "/ui/term/keys", {"id": tid, "items": [{"k": "text", "v": "typed"}]})
        assert st == 200 and k["sent"] == 0 and "dialog" in k["refused"]
        fc.http("POST", "/ui/term/release", {"id": tid})
        secret = canary("pw")
        st, r = mod.post("/ui/dialog/submit", seal(d, [secret]))
        assert st == 200 and r["state"] == "checking", r
        got = a.wait(tid, "GOTLEN=")
        line = next(ln for ln in got["lines"] if ln.startswith("GOTLEN="))
        assert line == f"GOTLEN={len(secret)} sha={sha16(secret)}", "the pane didn't get the value"
        assert got.get("auth") == "[credential supplied]"
        # the value echoed back by a careless program is masked for this pane
        a.run(tid, 'echo "AG""AIN:$pw"', "AGAIN:")
        assert any("AGAIN:***" in ln for ln in a.read(tid)["lines"])
        # no tmux buffer keeps it; no gated file, event or log line has it; it was
        # never on a tmux command line (it went in on tmux's stdin)
        assert _tmux(de, "list-buffers").stdout.strip() == ""
        logged = argv_log.read_text()
        assert "load-buffer" in logged and "paste-buffer -d" in logged and secret not in logged
        argv_log.unlink()
        assert secret.encode() not in _gated_files(de)
        assert all(secret not in x for x in a.answers)
        ev = _events(de, ("auth.waiting", "auth.supplied"))
        assert any(e.get("terminal") == tid for e in ev if e["kind"] == "auth.waiting")
        assert any(e.get("outcome") == "ok" for e in ev if e["kind"] == "auth.supplied")
        assert secret not in json.dumps(ev)


def test_a_password_prompt_with_nobody_to_ask_is_reported_and_not_asked_any_other_way():
    from test_dialogs import Mod
    with D.daemon_env() as de:
        fc = de.claude(surface=None)                 # claude -p: no drawing surface
        a = Agent(de, fc)
        tid = a.open()["id"]
        a.run(tid, 'read -s -p "Secret: " x; echo got-it', done=False)
        deadline = time.time() + 10
        v = a.read(tid)
        while time.time() < deadline and not v.get("waiting_auth"):
            time.sleep(0.2)
            v = a.read(tid)
        assert v.get("waiting_auth") is True and "no gateway dialog" in v.get("note", ""), v
        assert Mod(fc).view()["dialog"] is None
        a.ok("/agent/term/signal", {"id": tid, "signal": "INT"})


def test_a_cancelled_dialog_leaves_the_prompt_waiting_and_says_so():
    from test_dialogs import Mod
    with D.daemon_env() as de:
        fc = de.claude()
        mod = Mod(fc)
        a = Agent(de, fc)
        tid = a.open()["id"]
        a.run(tid, 'read -s -p "Secret: " x; echo got-it', done=False)
        d = mod.dialog(lambda x: x.get("entry") == "terminal", timeout=10)
        mod.post("/ui/dialog/cancel", {"id": d["id"]})
        deadline = time.time() + 5
        v = a.read(tid)
        while time.time() < deadline and "cancelled" not in v.get("note", ""):
            time.sleep(0.2)
            v = a.read(tid)
        assert "cancelled" in v.get("note", "") and v["waiting_auth"] is True, v
        time.sleep(1.0)
        assert mod.view()["dialog"] is None          # not asked again for the same prompt
        # the program stopped asking: the agent may type again
        a.ok("/agent/term/signal", {"id": tid, "signal": "INT"})
        a.run(tid, "echo back-to-normal", "back-to-normal")


def test_vault_values_are_masked_in_terminal_reads_job_tails_and_the_pane_view():
    with D.daemon_env() as de:
        tok = "ghp_" + secrets.token_hex(18)
        d = vault.empty()
        acct = vault.account_record(d, "gh-me", "github")
        acct["token"] = {"value": tok, "source": "pasted", "updated": "x", "stale": False}
        vault.save(d)
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        f = de.root / "tok.txt"
        f.write_text(tok + "\n")
        v = a.run(tid, f"cat '{f}'; echo cat-done", "cat-done")
        assert all(tok not in ln for ln in v["lines"]) and any("***" in ln for ln in v["lines"])
        st, ui = fc.http("GET", f"/ui/term/screen?id={tid}&seq=0&wait=0")
        assert st == 200 and tok not in json.dumps(ui) and "***" in json.dumps(ui)
        j = a.ok("/agent/job/start", {"command": f"cat '{f}'; echo job-done", "cwd": str(de.root)})
        _job_wait(a, j["id"], ("exited",))
        t = a.ok("/agent/job/tail", {"id": j["id"]})
        assert tok not in t["text"] and "***" in t["text"] and "job-done" in t["text"]
        assert all(tok not in x for x in a.answers)


def test_a_job_that_ends_at_once_is_reported_started_first():
    """job.started is emitted under the supervisor's lock before any look at
    the pane: a job that exits within milliseconds never reports its end
    before its start (the full suite once saw job.state first)."""
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        ids = [a.ok("/agent/job/start", {"command": "exit 3", "cwd": str(de.root)})["id"] for _ in range(5)]
        for j in ids:
            assert _job_wait(a, j, ("exited",))["exit"] == 3
        ev = _events(de, ("job.started", "job.state", "job.exited"))
        for j in ids:
            kinds = [e["kind"] for e in ev if e.get("job") == j]
            assert kinds and kinds[0] == "job.started" and "job.exited" in kinds, (j, kinds)


def test_jobs_report_exit_codes_signals_bounded_tails_and_honour_idempotency_keys():
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        j = a.ok("/agent/job/start", {"command": "for i in $(seq 1 5000); do echo out-$i; done; exit 7",
                                      "cwd": str(de.root)})
        assert j["kind"] == "job" and j["new"] is True and j["id"].startswith("j_")
        st = _job_wait(a, j["id"], ("exited",))
        assert st["exit"] == 7 and st["signal"] is None and st["ended"] >= st["started"]
        t = a.ok("/agent/job/tail", {"id": j["id"], "bytes": 200})
        assert len(t["text"].encode()) <= 200 and t["truncated"] is True and "out-5000" in t["text"]
        assert t["offset"] > 0
        t2 = a.ok("/agent/job/tail", {"id": j["id"], "lines": 3})
        assert t2["text"].strip().splitlines()[-1] == "out-5000" and len(t2["text"].splitlines()) <= 4
        # argv, a signal, the canceled state
        s = a.ok("/agent/job/start", {"argv": ["sleep", "60"], "cwd": str(de.root), "idempotency_key": "k-1"})
        again = a.ok("/agent/job/start", {"argv": ["sleep", "60"], "cwd": str(de.root),
                                          "idempotency_key": "k-1"})
        assert again["id"] == s["id"] and again["new"] is False
        a.ok("/agent/job/signal", {"id": s["id"], "signal": "TERM"})
        st = _job_wait(a, s["id"], ("canceled",))
        assert st["signal"] == "TERM" or st["exit"] is not None, st
        # bad requests
        for body, code in (({"command": "x", "argv": ["y"]}, "bad_command"), ({}, "bad_command"),
                           ({"command": "x", "on_pause": "nap"}, "bad_policy"),
                           ({"command": "x", "cwd": "relative"}, "bad_cwd"),
                           ({"command": "x", "host": "build"}, "no_host")):
            stc, b = a.call("/agent/job/start", body)
            assert stc in (400, 404) and b["error"] == code, (body, b)
        ev = _events(de, ("job.started", "job.state", "job.exited", "job.output"))
        kinds = [e["kind"] for e in ev if e.get("job") == j["id"]]
        assert kinds[0] == "job.started" and "job.exited" in kinds and "job.output" in kinds
        ex = next(e for e in ev if e["kind"] == "job.exited" and e["job"] == j["id"])
        assert ex["exit"] == 7 and ex["state"] == "exited"
        assert all("out-" not in json.dumps(e) for e in ev)


def test_signals_reach_the_foreground_program_of_a_terminal():
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        a.run(tid, "sleep 300", done=False)
        time.sleep(0.5)
        r = a.ok("/agent/term/signal", {"id": tid, "signal": "INT"})
        assert r["signal"] == "INT"
        # bash drops the rest of a list its foreground job was interrupted in (as at ^C)
        v = a.run(tid, "echo status=$?", "status=130")
        assert v["state"] == "open"
        a.ok("/agent/term/signal", {"id": tid, "signal": "KILL"})
        deadline = time.time() + 5
        while time.time() < deadline and a.read(tid)["state"] != "exited":
            time.sleep(0.1)
        assert a.read(tid)["state"] == "exited"
        st, b = a.call("/agent/term/send", {"id": tid, "seq": a.read(tid)["seq"], "text": "x"})
        assert st == 410 and b["error"] == "ended"


def test_a_full_screen_program_uses_the_alternate_screen_and_resize_follows():
    less = "/usr/bin/less"
    if not os.path.exists(less):
        print("    note: no /usr/bin/less here; skipped")
        return
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open(cols=90, rows=20)["id"]
        f = de.root / "pages.txt"
        f.write_text("".join(f"page line {i}\n" for i in range(500)))
        a.run(tid, f"{less} '{f}'", "page line 0", done=False)
        v = a.read(tid)
        assert v["alternate_screen"] is True and len(v["lines"]) <= 20
        r = a.ok("/agent/term/resize", {"id": tid, "cols": 60, "rows": 12})
        assert (r["cols"], r["rows"]) == (60, 12)
        v = a.read(tid)
        assert v["cols"] == 60 and v["rows"] == 12 and len(v["lines"]) <= 12
        a.ok("/agent/term/send", {"id": tid, "seq": v["seq"], "keys": ["Space"]})
        time.sleep(0.3)
        v = a.read(tid)
        a.ok("/agent/term/send", {"id": tid, "seq": v["seq"], "text": "q"})
        deadline = time.time() + 5
        while time.time() < deadline and a.read(tid)["alternate_screen"]:
            time.sleep(0.1)
        assert a.read(tid)["alternate_screen"] is False
        st, ui = fc.http("POST", "/ui/term/resize", {"id": tid, "cols": 70, "rows": 15})
        assert st == 200 and (ui["cols"], ui["rows"]) == (70, 15)


def test_on_pause_policies_report_what_actually_happened_and_resume_undoes_a_suspend():
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        cwd = str(de.root)
        jobs = {}
        jobs["continue"] = a.ok("/agent/job/start", {"argv": ["sleep", "60"], "cwd": cwd, "task_ref": "task-1"})["id"]
        jobs["suspend"] = a.ok("/agent/job/start", {"argv": ["sleep", "61"], "cwd": cwd, "on_pause": "suspend",
                                                    "task_ref": "task-1"})["id"]
        jobs["interrupt"] = a.ok("/agent/job/start", {"command": "trap 'exit 9' INT; while :; do sleep 0.1; done",
                                                      "cwd": cwd, "on_pause": "interrupt", "task_ref": "task-1"})["id"]
        jobs["detach"] = a.ok("/agent/job/start", {"argv": ["sleep", "60"], "cwd": cwd, "on_pause": "detach",
                                                   "task_ref": "task-1"})["id"]
        other = a.ok("/agent/job/start", {"argv": ["sleep", "60"], "cwd": cwd, "on_pause": "suspend",
                                          "task_ref": "task-2"})["id"]
        time.sleep(0.5)
        st, r = a.call("/v1/pause", {"session": "s-test", "task_ref": "task-1", "reason": "test"},
                       mode="x")
        assert st == 200 and r["paused"] is True, r
        out = {o["job"]: o for o in r["outcomes"]}
        assert other not in out
        assert out[jobs["continue"]]["outcome"].startswith("still running")
        assert out[jobs["suspend"]]["outcome"] == "suspended (SIGSTOP)"
        assert out[jobs["interrupt"]]["outcome"].startswith("interrupted: exited (exit 9)"), out[jobs["interrupt"]]
        assert out[jobs["detach"]]["outcome"].startswith("detached")
        assert _job_wait(a, jobs["suspend"], ("suspended",))["state"] == "suspended"
        stats = [ln.split()[1] for ln in subprocess.run(["ps", "-axo", "pid=,stat=,command="],
                                                         capture_output=True, text=True).stdout.splitlines()
                 if ln.split()[2:] == ["sleep", "61"]]
        assert stats and all(st.startswith("T") for st in stats), stats
        # paused: no new job and no typing from this session's agent
        st, b = a.call("/agent/job/start", {"argv": ["true"], "cwd": cwd})
        assert st == 409 and b["error"] == "paused"
        st, r = a.call("/v1/resume", {"session": "s-test", "task_ref": "task-1"}, mode="x")
        res = {o["job"]: o for o in r["outcomes"]}
        assert res[jobs["suspend"]]["outcome"] == "resumed (SIGCONT)"
        assert _job_wait(a, jobs["suspend"], ("running",))["state"] == "running"
        st, b = a.call("/agent/job/status", {"id": jobs["detach"]})
        assert b.get("detached") is True and "task_ref" not in b


def test_gated_restart_readopts_live_panes_and_a_lost_supervisor_is_reported_never_assumed():
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        v = a.run(tid, 'export KEEP=me; echo "PI""D=$$"', "PID=")
        shell_pid = next(ln for ln in v["lines"] if ln.startswith("PID="))
        jid = a.ok("/agent/job/start", {"argv": ["sleep", "120"], "cwd": str(de.root)})["id"]
        fc.http("POST", "/ui/term/take", {"id": tid})
        os.kill(de.daemon_pid(), signal.SIGKILL)
        time.sleep(0.3)
        de.start()
        v = a.read(tid)
        assert v["state"] == "open" and v["owner"] == "user", v
        fc.http("POST", "/ui/term/release", {"id": tid})
        v = a.run(tid, 'echo "PI""D=$$ keep=$KEEP"', "PID=")
        assert any(ln.startswith(shell_pid + " keep=me") for ln in v["lines"]), v["lines"]
        assert _job_wait(a, jid, ("running",))["state"] == "running"
        a.ok("/agent/job/signal", {"id": jid, "signal": "KILL"})
        jid2 = a.ok("/agent/job/start", {"argv": ["sleep", "120"], "cwd": str(de.root)})["id"]
        # a pane killed behind the supervisor's back while gated runs: unknown, never "exited"
        _tmux(de, "kill-session", "-t", f"={jid2}")
        deadline = time.time() + 5
        while time.time() < deadline and a.ok("/agent/job/status", {"id": jid2})["state"] != "unknown":
            time.sleep(0.1)
        s = a.ok("/agent/job/status", {"id": jid2})
        assert s["state"] == "unknown" and s["gone"] is True and "unknown" in s["note"], s
        # an unknown outcome has no proven end time (the process may still run)
        assert s.get("ended") is None, s
        # the supervisor itself gone while gated was down too (a reboot): the restarted
        # gated asks tmux, finds nothing, and reports the terminal gone
        assert a.read(tid)["state"] == "open"
        os.kill(de.daemon_pid(), signal.SIGKILL)
        time.sleep(0.3)
        _tmux(de, "kill-server")
        de.start()
        g = a.read(tid)
        assert g["state"] == "gone" and g.get("gone") is True and "restarted" in g["note"], g


def test_contract_job_routes_events_snapshot_and_their_plane():
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        body = {"command": "echo contract-job; exit 3", "host": "localhost", "cwd": str(de.root),
                "session": "s-test", "task_ref": "ck-task-1", "idempotency_key": "ck-1"}
        st, r = a.call("/v1/jobs", body, mode="x")
        assert st == 200 and r["contract"] == 1 and r["job"].startswith("j_") and r["op"].startswith("o_")
        jid = r["job"]
        st, r2 = a.call("/v1/jobs", body, mode="x")
        assert r2["job"] == jid and r2["new"] is False
        deadline = time.time() + 10
        while time.time() < deadline:
            st, g = a.de.probe(fc, a.probe / "run.py", ["x"], f"/v1/jobs/{jid}", method="GET")
            if g.get("state") == "exited":
                break
            time.sleep(0.1)
        assert g["state"] == "exited" and g["exit"] == 3 and g["task_ref"] == "ck-task-1"
        assert g["host"].startswith("m_") and g["command"].startswith("echo contract-job")
        st, t = a.de.probe(fc, a.probe / "run.py", ["x"], f"/v1/jobs/{jid}/tail?bytes=100", method="GET")
        assert st == 200 and "contract-job" in t["text"] and t["contract"] == 1
        st, s = a.call(f"/v1/jobs/{jid}/signal", {"signal": "TERM"}, mode="x")
        assert st == 200 and s["state"] == "exited"
        st, s = a.call(f"/v1/jobs/{jid}/signal", {"signal": "SEGV"}, mode="x")
        assert st == 400
        st, n = a.de.probe(fc, a.probe / "run.py", ["x"], f"/v1/jobs/{T.ulid('j')}", method="GET")
        assert st == 404
        st, m = a.call("/v1/jobs", {**body, "session": "someone-else", "idempotency_key": "ck-2"}, mode="x")
        assert st == 403
        st, m = a.call("/v1/jobs", {k: v for k, v in body.items() if k != "idempotency_key"}, mode="x")
        assert st == 400
        st, snap = a.de.probe(fc, a.probe / "run.py", ["x"], "/v1/snapshot", method="GET")
        assert any(j["job"] == jid and j["state"] == "exited" for j in snap["jobs"])
        st, cap = a.de.probe(fc, a.probe / "run.py", ["x"], "/v1/capabilities", method="GET")
        assert "jobs" in cap["features"] and "terminals" in cap["features"]
        # the contract plane needs a session: the test process has none
        st, _ = de.call("POST", "/v1/jobs", body)
        assert st == 403


def test_terminal_routes_are_the_mcp_servers_and_the_panes_alone():
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        for mode in ("gate", "hook-post", "shim"):
            st, b = a.call("/agent/term/read", {"id": tid}, mode=mode)
            assert st == 403, (mode, st, b)
        st, b = de.call("POST", "/agent/term/read", {"id": tid})          # no session above
        assert st == 403
        # the pane's routes: only the Claude Code process itself (a child is refused)
        st, b = a.call("/ui/term/take", {"id": tid})
        assert st == 403 and b["error"] == "plane"
        st, b = de.call("GET", f"/ui/term/screen?id={tid}")
        assert st == 403


def test_a_process_inside_a_terminal_belongs_to_its_owner_session_while_that_lives():
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        out = de.root / "cap.json"
        probe = a.probe / "run.py"
        cmd = (f"PYTHONHOME= GW_PROBE_SOCK='{de.sock}' GW_PROBE_PATH=/v1/capabilities GW_PROBE_METHOD=GET "
               f"'{D.PY}' -I -S '{probe}' > '{out}'; echo probe-done")
        a.run(tid, cmd, "probe-done")
        assert json.loads(out.read_text())["status"] == 200
        fc.close()
        time.sleep(0.5)
        out.unlink()
        # the owner session is gone: the pane's processes have no session any more
        _tmux(de, "send-keys", "-t", f"={tid}:", "-l", cmd)
        _tmux(de, "send-keys", "-t", f"={tid}:", "Enter")
        deadline = time.time() + 10
        while time.time() < deadline and not out.exists():
            time.sleep(0.1)
        time.sleep(0.3)
        assert json.loads(out.read_text())["status"] == 403


def test_live_panes_keep_gated_from_idle_exit_and_restart():
    with D.daemon_env(knobs={"idle_exit": 1, "tick": 0.1}) as de:
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        h = de.health()
        assert h["terminals"] == 1 and h["jobs"] == 0
        st, r = a.call("/local/restart", {}, mode="gated")
        assert st == 200 and r["restarting"] is False and r["busy"] == "1 terminal", r
        pid = de.daemon_pid()
        fc.close()
        time.sleep(2.5)
        assert de.daemon_pid() == pid, "gated left while a terminal lives"
        _tmux(de, "kill-session", "-t", f"={tid}")
        deadline = time.time() + 10
        while time.time() < deadline and de.daemon_pid() is not None:
            time.sleep(0.1)
        assert de.daemon_pid() is None, "gated stayed with nothing to keep it"


def test_the_mcp_server_offers_the_tools_and_passes_its_tool_use_id():
    with D.daemon_env() as de:
        fc = de.claude()
        fc.http("POST", "/ui/term/agent", {"tool_use_id": "toolu_mcp_1", "agent": "a-mcp"})
        env = de.env.subprocess_env(de.extra_env())
        msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                 "params": {"name": "terminal_open", "arguments": {"cwd": str(de.root), "cols": 80, "rows": 10,
                                                                   "__tool_use_id": "forged"},
                            "_meta": {"claudecode/toolUseId": "toolu_mcp_1"}}}]
        r = fc.run([D.PY, "-I", "-S", *H.PYX, str(H.PLUGIN / "run.py"), "--test", "mcp"], env=env,
                   input="".join(json.dumps(m) + "\n" for m in msgs), timeout=60)
        outs = {o["id"]: o for o in (json.loads(ln) for ln in r.stdout.splitlines() if ln.strip())}
        names = {t["name"] for t in outs[2]["result"]["tools"]}
        assert {"terminal_open", "terminal_read", "terminal_send", "terminal_resize", "terminal_signal",
                "terminal_close", "terminal_list", "job_start", "job_status", "job_tail", "job_signal",
                "job_list"} <= names
        res = json.loads(outs[3]["result"]["content"][0]["text"])
        assert outs[3]["result"]["isError"] is False and res["id"].startswith("t_"), res
        assert res["agent"] == "a-mcp" and res["holder_agent"] == "a-mcp"


def test_the_sudo_stand_in_hands_a_gateway_terminal_to_the_real_sudo_on_its_tty():
    from gateway import sudo
    calls = []
    old = (sudo._real_sudo, sudo._rights_now, sudo._exec_real, sudo.probe_nopasswd, os.isatty)
    tid = T.ulid("t")
    try:
        sudo._real_sudo = lambda: "/usr/bin/sudo"
        sudo._rights_now = lambda fresh=False: ({}, None, False)
        sudo._exec_real = lambda real, argv: calls.append(("exec", real, list(argv))) or 0
        sudo.probe_nopasswd = lambda *a, **k: calls.append(("probe",)) or False
        old_direct = sudo.ancestry.is_direct
        sudo.ancestry.is_direct = lambda *a, **k: (False, "?")
        os.isatty = lambda fd: True
        import contextlib
        import io
        with H.gateway_env(), contextlib.redirect_stderr(io.StringIO()):
            os.environ["GW_TERMINAL"] = tid
            assert sudo.main(["whoami"]) == 0
            assert calls == [("exec", "/usr/bin/sudo", ["whoami"])]
            calls.clear()
            assert sudo.main(["-S", "whoami"]) == 1 and not calls     # -S/-A still refused
            os.environ["GW_TERMINAL"] = "t_forged"
            sudo.main(["whoami"])
            assert ("probe",) in calls                                # not a terminal: the usual path
            calls.clear()
            os.environ["GW_TERMINAL"] = tid
            sudo._rights_now = lambda fresh=False: ({}, sudo.OFF, False)
            assert sudo.main(["whoami"]) == 1 and not calls          # sudo off: refused there too
    finally:
        os.environ.pop("GW_TERMINAL", None)
        sudo._real_sudo, sudo._rights_now, sudo._exec_real, sudo.probe_nopasswd, os.isatty = old
        sudo.ancestry.is_direct = old_direct


def test_the_approval_hook_judges_what_gw_jobs_run_and_terminals_are_sent():
    from gateway import hooks_bash
    with H.gateway_env() as env:
        env.write_form("[hosts.localhost]\nsudo = \"ask\"\n")
        base = {"session_id": "s", "permission_mode": "auto", "cwd": str(env.root),
                "transcript_path": "/x/projects/p/t.jsonl"}
        priv = str(paths.private_dir() / "key.txt")
        for tool, ti in (("mcp__plugin_gate_gw__job_start", {"command": f"cat {priv}"}),
                         ("mcp__plugin_gate_gw__job_start", {"argv": ["cat", priv]}),
                         ("mcp__plugin_gate_gw__terminal_send", {"id": "t_x", "seq": 1, "text": f"cat {priv}\n"}),
                         ("mcp__plugin_gate_gw__terminal_send", {"id": "t_x", "seq": 1, "text": "curl https://x"})):
            out = hooks_bash.main({**base, "tool_name": tool, "tool_input": ti})
            assert out and out["hookSpecificOutput"]["permissionDecision"] == "deny", (tool, ti, out)
        for tool, ti in (("mcp__plugin_gate_gw__job_start", {"command": "ls -la"}),
                         ("mcp__plugin_gate_gw__terminal_send", {"id": "t_x", "seq": 1, "text": "ls\n"}),
                         ("mcp__plugin_gate_gw__terminal_send", {"id": "t_x", "seq": 1, "keys": ["C-c"]})):
            out = hooks_bash.main({**base, "tool_name": tool, "tool_input": ti})
            assert out is None or out["hookSpecificOutput"]["permissionDecision"] == "deny", (tool, out)
            assert out is None, (tool, ti, out)
        out = hooks_bash.main({**base, "tool_name": "mcp__plugin_gate_gw__terminal_send",
                               "tool_input": {"id": "t_x", "seq": 1, "text": "sudo whoami\n"}})
        assert out and out["hookSpecificOutput"]["permissionDecision"] == "deny", out


def test_mcp_perm_allows_only_reads_and_an_idle_open():
    hook = H.PLUGIN / "hooks" / "mcp_perm.sh"
    for tool, allowed in (("terminal_read", True), ("terminal_list", True), ("job_status", True),
                          ("job_tail", True), ("job_list", True), ("terminal_open", True),
                          ("terminal_resize", True), ("terminal_send", False), ("job_start", False),
                          ("terminal_signal", False), ("terminal_close", False), ("job_signal", False)):
        r = subprocess.run(["/bin/sh", str(hook)], input=json.dumps(
            {"tool_name": f"mcp__plugin_gate_gw__{tool}", "tool_input": {"id": "t_x"}}),
            capture_output=True, text=True, timeout=10)
        assert ('"allow"' in r.stdout) == allowed, (tool, r.stdout)


def test_sudo_typed_in_a_gateway_terminal_asks_on_its_tty_and_the_dialogs_value_reaches_it():
    """The whole path: the sudo stand-in (first on the pane's PATH) sees a
    gateway terminal and execs the real sudo (the test override's fake, which
    asks on its tty with echo off, as sudo does); gated sees the prompt and
    opens the credential dialog; the sealed answer reaches that tty only."""
    from test_dialogs import Mod, seal
    with D.daemon_env() as de:
        right = canary("sudo")
        fs = de.root / "fake-sudo"
        fs.mkdir()
        (fs / "config.json").write_text(json.dumps({"password": right, "nopasswd": False,
                                                    "timeout": 300, "sudoers_dir": None}))
        (fs / "log.jsonl").write_text("")
        fake = fs / "sudo"
        fake.write_text(f"#!/bin/sh\nexec '{D.PY}' -I -S '{H.PLUGIN}/tests/fakes/fake_sudo.py' "
                        f"--state '{fs}' \"$@\"\n")
        os.chmod(fake, 0o755)
        drv = D.write_driver(de.env, de.run, tools={"sudo": str(fake)})
        stub = paths.bin_dir() / "sudo"
        stub.write_text(f"#!/bin/sh\nexec '{D.PY}' -I -S '{drv}' '{de.root}' shim sudo \"$@\"\n")
        os.chmod(stub, 0o755)
        fc = de.claude()
        mod = Mod(fc)
        a = Agent(de, fc)
        tid = a.open()["id"]
        # (quoted for the shell: the typed line itself must not show "SUDO-")
        a.run(tid, "sudo -v && echo SU''DO-OK || echo SU''DO-FAILED", done=False)
        d = mod.dialog(lambda x: x.get("entry") == "terminal", timeout=20)
        assert any("Foreground program:" in ln for ln in d["lines"])
        st, r = mod.post("/ui/dialog/submit", seal(d, [right]))
        assert st == 200, r
        v = a.wait(tid, "SUDO-")
        assert any(ln.startswith("SUDO-OK") for ln in v["lines"]), v["lines"]
        log = [json.loads(ln) for ln in (fs / "log.jsonl").read_text().splitlines() if ln.strip()]
        assert log and log[-1]["how"] == "tty" and log[-1]["code"] == 0, log
        assert right.encode() not in _gated_files(de) and all(right not in x for x in a.answers)
        audit = paths.audit_path().read_text() if paths.audit_path().exists() else ""
        assert '"outcome": "terminal"' in audit and right not in audit


def test_a_value_is_typed_only_into_the_prompt_it_was_asked_for():
    """The recheck before a dialog's value goes in (in this process, on a
    private tmux socket): the pane must still wait for a password (echo off,
    canonical input) from the same foreground process group, else nothing is
    typed."""
    import tempfile
    from gateway.daemon import peers

    class _Reg:
        lock = __import__("threading").RLock()
        sessions: dict = {}

        def live(self, pid):
            return None

    class _Daemon:
        registry = _Reg()

        class dialogs:
            paused: set = set()

        class events:
            @staticmethod
            def emit(*a, **k):
                return None

        @staticmethod
        def log(line):
            pass

        @staticmethod
        def machine_id():
            return "m_test"

    class _S:
        pid = os.getpid()
        start = peers.started(os.getpid())
        session_id = "s-in-process"

    with H.gateway_env() as env:
        run = Path(tempfile.mkdtemp(prefix="gwsup-", dir="/tmp"))
        os.chmod(run, 0o700)
        sup = T.Supervisor(_Daemon(), state_path=env.root / "t.json", sock=run / "tmux.sock",
                           conf=run / "tmux.conf", terms=run / "terms")
        try:
            sup.conf.write_text(T.TMUX_CONF)
            p = sup.open_terminal(_S(), cwd=str(env.root), cols=80, rows=10)
            time.sleep(0.5)
            sup._refresh(p)
            value = canary("not-asked")
            # echo on (the shell at its prompt, or cat waiting): refused, nothing typed
            for setup in ("", "cat"):
                if setup:
                    sup._deliver(p, setup, [], True)
                    time.sleep(0.4)
                tp = T.foreground_pgrp(p.pane_pid)
                p.auth = {"state": "asking", "token": "tok", "tpgid": tp}
                ok, why = sup._supply(p.id, "tok", [value])
                assert ok is False and "isn't waiting" in why, (setup, ok, why)
            time.sleep(0.3)
            assert all(value not in ln for ln in sup.view(p)["lines"]) and value not in "".join(p.secrets)
            sup._deliver(p, None, ["C-c"], False)
            # a real password prompt, but from another process group than the one asked for
            sup._deliver(p, 'read -s -p "pw: " x; echo "GOT""=${#x}"', [], True)
            time.sleep(0.5)
            p.auth = {"state": "asking", "token": "tok", "tpgid": 1}
            ok, _ = sup._supply(p.id, "tok", [value])
            assert ok is False
            # the right one: typed, then masked for this pane
            p.auth = {"state": "asking", "token": "tok", "tpgid": T.foreground_pgrp(p.pane_pid)}
            ok, _ = sup._supply(p.id, "tok", [value])
            assert ok is True and value in p.secrets
            time.sleep(0.4)
            assert any(ln.endswith(f"GOT={len(value)}") for ln in sup.view(p)["lines"]), sup.view(p)["lines"]
            # a wrong token (another dialog) is refused
            p.auth = {"state": "asking", "token": "tok", "tpgid": 1}
            assert sup._supply(p.id, "other", [value])[0] is False
        finally:
            sup.stop()
            subprocess.run([paths.tool("tmux"), "-S", str(run / "tmux.sock"), "kill-server"],
                           capture_output=True, timeout=10)
            import shutil
            shutil.rmtree(run, ignore_errors=True)


def test_closing_a_terminal_ends_its_session_and_says_so():
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        r = a.ok("/agent/term/close", {"id": tid})
        assert r["state"] == "closed"
        assert _tmux(de, "has-session", "-t", f"={tid}").returncode != 0
        assert a.read(tid)["state"] == "closed"
        ev = _events(de, ("terminal.closed",))
        assert any(e["terminal"] == tid and e["reason"] == "agent" for e in ev)
        assert de.health()["terminals"] == 0


def test_the_bash_hook_sees_the_gw_tools_that_type_or_run():
    hooks = json.loads((H.PLUGIN / "hooks" / "hooks.json").read_text())
    pre = [m for m in hooks["hooks"]["PreToolUse"]
           if any("pre_bash.sh" in " ".join(h.get("args", [])) for h in m["hooks"])]
    assert pre, "no pre_bash.sh matcher"
    names = pre[0]["matcher"].split("|")
    assert "mcp__plugin_gate_gw__job_start" in names and "mcp__plugin_gate_gw__terminal_send" in names
    post = [m for m in hooks["hooks"]["PostToolUse"] if "post.sh" in json.dumps(m)]
    assert post and "mcp__plugin_gate_gw__.*" in post[0]["matcher"]      # their output is masked too


def test_a_removed_run_dir_takes_the_unreachable_tmux_server_with_gated():
    import shutil
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        a.open()
        pid = int(_tmux(de, "display-message", "-p", "#{pid}").stdout.strip())
        gated = de.daemon_pid()
        # gated itself stops the server (abandon), not only the server's watchdog
        assert _tmux(de, "kill-session", "-t", f"={T.WATCH_SESSION}").returncode == 0
        shutil.rmtree(de.run)                       # a tmp cleaner; the harnesses do this
        deadline = time.time() + 10
        while time.time() < deadline and _alive(gated):
            time.sleep(0.1)
        while time.time() < deadline and _alive(pid):
            time.sleep(0.1)
        assert not _alive(gated), "gated stayed without its socket"
        assert not _alive(pid), ("the unreachable tmux server was left running", pid, de.log()[-800:])
        de.run.mkdir(mode=0o700)                    # for the harness's cleanup


def test_a_stopped_gateds_tmux_server_goes_with_its_socket_and_ends_with_its_last_session():
    """gated stopped (SIGTERM) keeps its tmux server for re-adoption; when the
    run dir then goes, nobody can reach that server or its panes again: its
    watchdog session stops it (the TUI harness left such servers behind). And
    the watchdog never keeps an empty server alive: closing the last terminal
    ends the server, as before."""
    import shutil
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        jid = a.ok("/agent/job/start", {"argv": ["sleep", "120"], "cwd": str(de.root)})["id"]
        pid = int(_tmux(de, "display-message", "-p", "#{pid}").stdout.strip())
        deadline = time.time() + 5           # the watchdog starts beside the pane, not before it
        while time.time() < deadline:
            names = _tmux(de, "list-sessions", "-F", "#{session_name}").stdout.split()
            if T.WATCH_SESSION in names:
                break
            time.sleep(0.1)
        assert sorted(names) == sorted([tid, jid, T.WATCH_SESSION]), names
        # the watchdog is no terminal or job of anyone's
        assert all(t["id"] != T.WATCH_SESSION for t in a.ok("/agent/term/list", {})["terminals"])
        a.ok("/agent/term/close", {"id": tid})
        gated = de.daemon_pid()
        os.kill(gated, signal.SIGTERM)
        deadline = time.time() + 10
        while time.time() < deadline and _alive(gated):
            time.sleep(0.1)
        assert not _alive(gated)
        assert _alive(pid), "a stopped gated keeps its tmux server (its jobs are re-adopted)"
        shutil.rmtree(de.run)                       # the run dir goes after gated stopped
        deadline = time.time() + 15
        while time.time() < deadline and _alive(pid):
            time.sleep(0.2)
        assert not _alive(pid), "the unreachable tmux server was left running"
        de.run.mkdir(mode=0o700)                    # for the harness's cleanup
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        pid = int(_tmux(de, "display-message", "-p", "#{pid}").stdout.strip())
        a.ok("/agent/term/close", {"id": tid})
        deadline = time.time() + 5
        while time.time() < deadline and _alive(pid):
            time.sleep(0.1)
        assert not _alive(pid), "the watchdog kept an empty tmux server alive"


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def test_a_pane_without_its_nonce_is_never_adopted():
    """A tmux session that has a record's name but not the nonce gated gave
    it is somebody else's: the record is reported gone, never re-adopted."""
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        os.kill(de.daemon_pid(), signal.SIGKILL)
        time.sleep(0.3)
        assert _tmux(de, "set-option", "-t", f"={tid}:", "@gw_nonce", "not-gateds").returncode == 0
        de.start()
        v = a.read(tid)
        assert v["state"] == "gone", v


def test_a_seq_read_before_a_gated_restart_is_stale_after_it():
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        seq = a.read(tid)["seq"]
        os.kill(de.daemon_pid(), signal.SIGKILL)
        time.sleep(0.3)
        de.start()
        st, b = a.call("/agent/term/send", {"id": tid, "seq": seq, "text": "echo after-restart"})
        assert st == 409 and b["error"] == "stale", b
        a.run(tid, "echo fresh-read-works", "fresh-read-works")


def test_a_seq_from_screen_changes_not_yet_persisted_is_stale_after_a_restart():
    """The seq a read hands the agent is persisted at once, so after a crash
    the adopt bump lands strictly above it even when the screen moved on
    (typing, output) between the last ownership save and the crash: a pre-crash
    seq is refused, never accepted because the saved seq lagged behind it."""
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        # bump the in-memory seq past the last ownership-triggered save: an
        # ownership round trip saves, then the agent types (no Enter), then reads
        fc.http("POST", "/ui/term/take", {"id": tid})
        fc.http("POST", "/ui/term/release", {"id": tid})
        s0 = a.read(tid)["seq"]
        b = a.ok("/agent/term/send", {"id": tid, "seq": s0, "text": "echo typed-no-enter"})
        held = a.read(tid)["seq"]
        assert held > s0
        os.kill(de.daemon_pid(), signal.SIGKILL)
        time.sleep(0.3)
        de.start()
        # the pre-crash seq is refused, so the queued (un-entered) line never runs
        st, r = a.call("/agent/term/send", {"id": tid, "seq": held, "keys": ["Enter"]})
        assert st == 409 and r["error"] == "stale", r


def test_a_vault_value_in_the_terminal_title_is_masked_everywhere():
    """A program can put a value in the terminal title (OSC 2); it must not
    reach the agent through terminal_read / terminal_list / job_status / the
    pane view, nor be written raw into the records."""
    with D.daemon_env() as de:
        tok = "ghp_" + secrets.token_hex(18)
        d = vault.empty()
        acct = vault.account_record(d, "gh-me", "github")
        acct["token"] = {"value": tok, "source": "pasted", "updated": "x", "stale": False}
        vault.save(d)
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        f = de.root / "tok.txt"
        f.write_text(tok)
        a.run(tid, f"printf '\\033]2;%s\\007' \"$(cat '{f}')\"; echo title-set", "title-set")
        r = a.read(tid)
        assert tok not in json.dumps(r), "the title leaked the vault value to terminal_read"
        assert tok not in json.dumps(a.ok("/agent/term/list", {}))
        st, ui = fc.http("GET", f"/ui/term/screen?id={tid}&seq=0&wait=0")
        assert st == 200 and tok not in json.dumps(ui)
        j = a.ok("/agent/job/start", {"command": f"printf '\\033]2;%s\\007' \"$(cat '{f}')\"; sleep 3",
                                      "cwd": str(de.root)})
        time.sleep(1.0)
        assert tok not in json.dumps(a.ok("/agent/job/status", {"id": j["id"]}))
        a.ok("/agent/job/signal", {"id": j["id"], "signal": "KILL"})
        assert tok.encode() not in _gated_files(de), "the title leaked into the records"
        assert all(tok not in x for x in a.answers)


def test_a_vault_value_split_across_a_wrap_boundary_is_masked():
    """tmux wraps a long line across two rows; a value printed at the wrap
    boundary must still be masked for the agent (its reads rejoin the rows)
    and never handed over as two halves to splice."""
    with D.daemon_env() as de:
        tok = "ghp_" + secrets.token_hex(18)
        d = vault.empty()
        acct = vault.account_record(d, "gh-me", "github")
        acct["token"] = {"value": tok, "source": "pasted", "updated": "x", "stale": False}
        vault.save(d)
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open(cols=100, rows=24)["id"]
        f = de.root / "tok.txt"
        f.write_text(tok)
        # 90 chars of text then the token: it wraps across the 100-column boundary
        a.run(tid, f"printf 'config: %083d ' 0; cat '{f}'; echo; echo wrap-done", "wrap-done")
        r = a.read(tid, history=50)
        assert tok not in "".join(r["lines"]), "a wrap-split value reached the agent (visible)"
        assert tok not in "".join(r.get("history", [])), "a wrap-split value reached the agent (history)"
        assert any("***" in ln for ln in r["lines"])
        assert all(tok not in x for x in a.answers)


def test_the_main_agent_holds_its_terminal_against_a_subagent():
    """The main agent's loop id is empty, which must count as a real holder (the
    first writer holds the input), so a subagent can't write into the main
    agent's terminal without taking it over, and vice versa."""
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        assert fc.http("POST", "/ui/term/agent", {"tool_use_id": "toolu_main", "agent": ""})[0] == 200
        assert fc.http("POST", "/ui/term/agent", {"tool_use_id": "toolu_sub", "agent": "a-sub"})[0] == 200
        tid = a.ok("/agent/term/open", {"cwd": str(de.root), "tool_use_id": "toolu_main"})["id"]
        seq = a.read(tid)["seq"]
        b = a.ok("/agent/term/send", {"id": tid, "seq": seq, "text": "echo from-main", "enter": True,
                                      "tool_use_id": "toolu_main"})
        st, r = a.call("/agent/term/send", {"id": tid, "seq": b["seq"], "text": "echo from-sub",
                                            "enter": True, "tool_use_id": "toolu_sub"})
        assert st == 409 and r["error"] == "holder", r
        a.ok("/agent/term/send", {"id": tid, "seq": a.read(tid)["seq"], "text": "echo main-again",
                                  "enter": True, "tool_use_id": "toolu_main"})
        # the subagent takes it over with a read, then holds it against the main agent
        v = a.ok("/agent/term/read", {"id": tid, "take": True, "tool_use_id": "toolu_sub"})
        a.ok("/agent/term/send", {"id": tid, "seq": v["seq"], "text": "echo sub-now", "enter": True,
                                  "tool_use_id": "toolu_sub"})
        st, r = a.call("/agent/term/send", {"id": tid, "seq": a.read(tid)["seq"], "text": "echo blocked",
                                            "enter": True, "tool_use_id": "toolu_main"})
        assert st == 409 and r["error"] == "holder", r


def _fail_list_wrapper(base: Path, flag: Path) -> Path:
    w = base / "tmux-faillist"
    w.write_text("#!/bin/sh\n"
                 f"case \"$*\" in *list-panes*) [ -e '{flag}' ] && exit 1 ;; esac\n"
                 f"exec '{paths.tool('tmux')}' \"$@\"\n")
    os.chmod(w, 0o755)
    return w


def test_a_transient_list_panes_failure_doesnt_mark_live_panes_gone():
    """One failed list-panes query (tmux still runs, its server alive) is a
    blip, not proof the panes died: live terminals and jobs stay live and
    writable, never marked gone for good."""
    with D.daemon_env(start=False) as de:
        flag = de.root / "fail-list"
        de.knobs(tmux=str(_fail_list_wrapper(de.root, flag)))
        de.start()
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        jid = a.ok("/agent/job/start", {"argv": ["sleep", "120"], "cwd": str(de.root)})["id"]
        flag.write_text("")                 # list-panes fails for a few ticks
        time.sleep(0.9)
        flag.unlink()
        time.sleep(0.6)
        v = a.read(tid)
        s = a.ok("/agent/job/status", {"id": jid})
        assert v["state"] == "open" and not v.get("gone"), v
        assert s["state"] == "running" and not s.get("gone"), s
        assert _tmux(de, "has-session", "-t", f"={tid}").returncode == 0
        a.run(tid, "echo still-writable", "still-writable")
        a.ok("/agent/job/signal", {"id": jid, "signal": "KILL"})


def test_pause_and_resume_are_bound_to_the_callers_session():
    """PLAN-v4 phase 7: /v1/pause and /v1/resume used to take any well-formed
    session id, so a process of one session could pause (SIGSTOP, SIGINT) or
    resume another session's jobs. Now a caller acts on its own session only;
    another live session is refused (403 session); an ended session's jobs
    only for a task (task_ref), as checkpoint does for a task picked up in a
    later session."""
    with D.daemon_env() as de:
        fc1 = de.claude()
        fc2 = de.claude(session="s-other")
        a1, a2 = Agent(de, fc1), Agent(de, fc2)
        jid = a1.ok("/agent/job/start", {"argv": ["sleep", "60"], "cwd": str(de.root),
                                         "on_pause": "suspend", "task_ref": "t1"})["id"]
        time.sleep(0.3)
        for body in ({"session": "s-test", "reason": "x"},
                     {"session": "s-test", "task_ref": "t1", "reason": "x"}):
            st, r = a2.call("/v1/pause", body, mode="x")
            assert st == 403 and r["error"] == "session", (st, r)
            st, r = a2.call("/v1/resume", body, mode="x")
            assert st == 403 and r["error"] == "session", (st, r)
        assert a1.ok("/agent/job/status", {"id": jid})["state"] == "running"
        # the caller's own session: applied
        st, r = a1.call("/v1/pause", {"session": "s-test", "task_ref": "t1", "reason": "x"}, mode="x")
        assert st == 200 and r["outcomes"][0]["outcome"] == "suspended (SIGSTOP)", r
        st, r = a1.call("/v1/resume", {"session": "s-test", "task_ref": "t1"}, mode="x")
        assert st == 200 and r["outcomes"][0]["outcome"] == "resumed (SIGCONT)", r
        # the first session ends: its task's jobs may be paused from another
        # session, but only with the task named
        fc1.close()
        time.sleep(0.3)
        st, r = a2.call("/v1/pause", {"session": "s-test", "reason": "x"}, mode="x")
        assert st == 403 and r["error"] == "session", (st, r)
        st, r = a2.call("/v1/pause", {"session": "s-test", "task_ref": "other", "reason": "x"},
                        mode="x")
        assert st == 200 and r["outcomes"] == [], r
        st, r = a2.call("/v1/pause", {"session": "s-test", "task_ref": "t1", "reason": "x"}, mode="x")
        assert st == 200 and [o["job"] for o in r["outcomes"]] == [jid], r
        assert _job_wait(a2, jid, ("suspended",))["state"] == "suspended"
        st, r = a2.call("/v1/resume", {"session": "s-test", "task_ref": "t1"}, mode="x")
        assert st == 200 and r["outcomes"][0]["outcome"] == "resumed (SIGCONT)", r
        # (another session still can't signal it directly: job_signal is the owner's)
        st, r = a2.call("/agent/job/signal", {"id": jid, "signal": "KILL"})
        assert st == 403 and r["error"] == "other_session"


def test_a_repeated_pause_never_signals_a_job_twice():
    """checkpoint retries a pause whose delivery was uncertain; an
    on_pause=interrupt job that ignored the first SIGINT must not get a
    second one: the same pause_id replays the first answer (nothing applied),
    and even without one a job a pause already interrupted isn't signalled
    again until a resume."""
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        log = de.root / "ints.log"
        jid = a.ok("/agent/job/start", {"command": f"trap 'echo INT >> \"{log}\"' INT; "
                                                   "while :; do sleep 0.1; done",
                                        "cwd": str(de.root), "on_pause": "interrupt",
                                        "task_ref": "t1"})["id"]
        time.sleep(0.5)

        def ints() -> int:
            return len(log.read_text().splitlines()) if log.exists() else 0

        body = {"session": "s-test", "task_ref": "t1", "reason": "x", "pause_id": "p-1"}
        st, first = a.call("/v1/pause", body, mode="x")
        assert st == 200 and "SIGINT sent" in first["outcomes"][0]["outcome"], first
        time.sleep(0.4)
        assert ints() == 1
        st, again = a.call("/v1/pause", body, mode="x")
        assert st == 200 and again.get("replayed") is True, again
        assert again["outcomes"] == first["outcomes"]
        time.sleep(0.4)
        assert ints() == 1, "the replayed pause signalled the job again"
        # a different pause_id (or none) while still paused: no second SIGINT either
        st, r = a.call("/v1/pause", {**body, "pause_id": "p-2"}, mode="x")
        assert st == 200 and r["outcomes"][0]["outcome"].startswith("already interrupted"), r
        time.sleep(0.4)
        assert ints() == 1
        st, r = a.call("/v1/pause", {**body, "pause_id": "bad id!"}, mode="x")
        assert st == 400
        # resume, then a new pause: that one interrupts again
        st, r = a.call("/v1/resume", {"session": "s-test", "task_ref": "t1", "pause_id": "p-1"},
                       mode="x")
        assert st == 200 and r.get("replayed") is not True
        st, r2 = a.call("/v1/resume", {"session": "s-test", "task_ref": "t1", "pause_id": "p-1"},
                        mode="x")
        assert st == 200 and r2.get("replayed") is True
        st, r = a.call("/v1/pause", {**body, "pause_id": "p-3"}, mode="x")
        assert st == 200 and "SIGINT sent" in r["outcomes"][0]["outcome"], r
        time.sleep(0.4)
        assert ints() == 2
        a.ok("/agent/job/signal", {"id": jid, "signal": "KILL"})
        ev = [e for e in _events(de, ("pause.applied",)) if e.get("replayed")]
        assert ev, "a replayed pause isn't recorded as such"


def test_a_paused_session_cannot_resume_a_suspended_job_with_cont():
    """While the task is paused the agent may stop or cancel work, but it may
    not resume it: job_signal CONT is refused (checkpoint's /v1/resume is the
    way back), so a pause's suspend holds."""
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        jid = a.ok("/agent/job/start", {"argv": ["sleep", "60"], "cwd": str(de.root),
                                        "on_pause": "suspend", "task_ref": "t1"})["id"]
        sess = next(x["session"] for x in a.ok("/agent/job/list", {})["jobs"] if x["id"] == jid)
        st, r = a.call("/v1/pause", {"session": sess, "reason": "test"}, mode="x")
        assert st == 200 and r["paused"] is True
        assert _job_wait(a, jid, ("suspended",))["state"] == "suspended"
        st, b = a.call("/agent/job/signal", {"id": jid, "signal": "CONT"})
        assert st == 409 and b["error"] == "paused", b
        assert a.ok("/agent/job/status", {"id": jid})["state"] == "suspended"
        # cancellation is still allowed while paused
        a.ok("/agent/job/signal", {"id": jid, "signal": "KILL"})
        st, r = a.call("/v1/resume", {"session": sess}, mode="x")
        assert st == 200


def test_the_interrupt_escalation_survives_a_gated_restart():
    """on_pause=interrupt promises SIGTERM after the grace if the job ignores
    SIGINT; a gated restart must re-arm that timer (its promise outlives the
    crash), not silently drop it."""
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        jid = a.ok("/agent/job/start", {"command": "trap '' INT; sleep 60", "cwd": str(de.root),
                                        "on_pause": "interrupt", "task_ref": "t1"})["id"]
        sess = next(x["session"] for x in a.ok("/agent/job/list", {})["jobs"] if x["id"] == jid)
        st, r = a.call("/v1/pause", {"session": sess, "reason": "test"}, mode="x")
        assert st == 200 and "SIGTERM follows" in r["outcomes"][0]["outcome"]
        os.kill(de.daemon_pid(), signal.SIGKILL)
        time.sleep(0.3)
        de.start()
        # within the grace the restarted gated sends the promised SIGTERM
        st = _job_wait(a, jid, ("exited", "canceled", "unknown"), timeout=20)
        assert st["state"] in ("exited", "canceled") and st.get("signal") == "TERM", st


def test_terminal_list_and_job_list_are_bounded_for_the_agent():
    """A session that has run many jobs gets a bounded terminal_list / job_list
    (the newest LIST_MAX, with the true total), so the result the model reads
    stays small; the contract snapshot stays complete."""
    with D.daemon_env() as de:
        fc = de.claude()
        a = Agent(de, fc)
        n = T.LIST_MAX + 20
        for _ in range(n):
            a.ok("/agent/job/start", {"command": "true", "cwd": str(de.root)})
        time.sleep(1.0)
        jl = a.ok("/agent/job/list", {})
        assert len(jl["jobs"]) == T.LIST_MAX and jl["truncated"] is True and jl["total"] == n, \
            (len(jl["jobs"]), jl.get("total"))
        tl = a.ok("/agent/term/list", {})
        assert len(tl["jobs"]) == T.LIST_MAX and tl.get("truncated") is True
        # the contract snapshot keeps every job
        st, snap = a.de.probe(fc, a.probe / "run.py", ["x"], "/v1/snapshot", method="GET")
        assert len([j for j in snap["jobs"]]) == n, len(snap["jobs"])


# ---------------------------------------------------------------------------
# An uninstall while terminals and jobs run; the tmux server after gated
# (0.9.1, the GitHub install test: a plain `claude plugin uninstall` with a job
# running left gated running forever, advertising the contract, its tmux
# server and watchdog running from deleted files)
# ---------------------------------------------------------------------------


def _gone(pid: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _alive(pid):
            return True
        time.sleep(0.05)
    return not _alive(pid)


def _server_pid(de: D.DaemonEnv) -> int:
    return int(_tmux(de, "display-message", "-p", "#{pid}").stdout.strip())


def _wait_watchdog(de: D.DaemonEnv) -> None:
    deadline = time.time() + 5           # the watchdog starts beside the pane, not before it
    while time.time() < deadline:
        if T.WATCH_SESSION in _tmux(de, "list-sessions", "-F", "#{session_name}").stdout.split():
            return
        time.sleep(0.1)
    raise AssertionError("no watchdog session")


def _end_pane(de: D.DaemonEnv, pid_: str) -> None:
    """End a pane's processes behind gated's back (its process group)."""
    root = int(_tmux(de, "display-message", "-p", "-t", f"={pid_}:", "#{pane_pid}").stdout.strip())
    os.killpg(root, signal.SIGKILL)


def test_an_uninstall_while_a_job_runs_drains_gated_and_it_leaves_with_its_tmux_after_the_job():
    """A plain `claude plugin uninstall` deletes the plugin's data folder while
    a job and a terminal run: gated drains at its next tick (contract.json
    withdrawn at once, daemon.draining, new terminals and jobs refused while an
    idempotent retry still gets the job it started), leaves the work running,
    and exits once it has ended, its tmux server and watchdog with it. Nothing
    makes the deleted data folder again."""
    import shutil
    with D.daemon_env(knobs={"watch_tick": 60}) as de:
        fc = de.claude()
        a = Agent(de, fc)
        job = {"argv": ["sleep", "300"], "cwd": str(de.root), "idempotency_key": "k-drain"}
        jid = a.ok("/agent/job/start", job)["id"]
        tid = a.open()["id"]
        _wait_watchdog(de)
        server = _server_pid(de)
        gated = de.daemon_pid()
        assert paths.contract_path().exists()
        log = open(paths.gated_log(), errors="replace")        # the file goes with the folder
        data = Path(de.env.data)
        shutil.rmtree(data)
        assert de.wait_for(lambda: (de.health() or {}).get("draining"), 5), de.health()
        assert "data folder is gone" in de.health()["draining"]
        assert not paths.contract_path().exists(), "a draining gated still advertises the contract"
        for path, body in (("/agent/job/start", {"argv": ["true"], "cwd": str(de.root)}),
                           ("/agent/term/open", {"cwd": str(de.root)})):
            st, r = a.call(path, body)
            assert st == 503 and r.get("error") == "draining" and "uninstalled" in r["message"], (path, st, r)
        st, r = fc.http("POST", "/ui/term/open", {"cwd": str(de.root)})
        assert st == 503 and r.get("error") == "draining", (st, r)
        again = a.ok("/agent/job/start", job)
        assert again["id"] == jid and again["new"] is False, again
        ev = _events(de, ("daemon.draining",))
        assert ev and ev[-1]["reason"] == "uninstalled" and ev[-1]["jobs"] == 1 and ev[-1]["terminals"] == 1, ev
        time.sleep(1.0)
        assert de.daemon_pid() == gated and _alive(server), "gated left (or stopped tmux) while work runs"
        assert _job_wait(a, jid, ("running",))["state"] == "running"
        a.ok("/agent/term/close", {"id": tid})
        time.sleep(0.5)
        assert de.daemon_pid() == gated, "gated left while a job still runs"
        _end_pane(de, jid)
        assert _gone(gated, 10), "gated stayed after the last job ended"
        assert _gone(server, 5), "its tmux server (and watchdog) stayed"
        assert not data.exists(), "the deleted data folder was made again"
        text = log.read()
        log.close()
        assert "taking no new work" in text and "nothing runs any more: exiting" in text, text[-800:]
        assert "the tmux server was stopped" in text, text[-800:]
        data.mkdir(parents=True)                                   # for the harness's cleanup


def test_a_draining_gated_whose_tmux_was_deleted_watches_the_panes_processes():
    """The uninstall deleted the env too (the data folder holds it): tmux
    can't be run, so every query fails while the server runs on from the
    deleted files (0.9.0 called that a blip forever). gated watches the pane's
    own process instead (pid and start time from tmux's last answer): alive,
    the job keeps gated; ended, the job is unknown (never "exited"), gated
    exits and stops the server by its verified pid."""
    import shutil
    with D.daemon_env(start=False, knobs={"watch_tick": 60}) as de:
        wb = de.root / "envbin"
        wb.mkdir()
        wrapper = wb / "tmux"
        wrapper.write_text(f"#!/bin/sh\nexec '{paths.tool('tmux')}' \"$@\"\n")
        os.chmod(wrapper, 0o755)
        de.knobs(tmux=str(wrapper))
        de.start()
        fc = de.claude()
        a = Agent(de, fc)
        jid = a.ok("/agent/job/start", {"argv": ["sleep", "300"], "cwd": str(de.root)})["id"]
        _wait_watchdog(de)
        server = _server_pid(de)
        gated = de.daemon_pid()
        time.sleep(0.5)                                  # a tick has seen the pane's process
        log = open(paths.gated_log(), errors="replace")
        data = Path(de.env.data)
        shutil.rmtree(data)
        wrapper.unlink()                                 # the env's tmux is gone with it
        assert de.wait_for(lambda: (de.health() or {}).get("draining"), 5), de.health()
        time.sleep(1.0)
        s = a.ok("/agent/job/status", {"id": jid})
        assert s["state"] == "running" and not s.get("gone"), s
        assert de.daemon_pid() == gated and _alive(server)
        _end_pane(de, jid)
        assert _gone(gated, 10), ("gated stayed with its tmux unrunnable", log.read()[-800:])
        assert _gone(server, 5), "the tmux server it could no longer run stayed"
        text = log.read()
        log.close()
        assert f"{jid} is gone (the gateway's tmux can't be run any more" in text, text[-800:]
        assert "its server was stopped" in text, text[-800:]
        assert not data.exists(), "the deleted data folder was made again"
        data.mkdir(parents=True)


def test_a_gated_that_exits_with_nothing_running_stops_its_tmux_server():
    """gated exiting for good (here `gated stop`) with only a dead pane left
    for reads: the tmux server and its watchdog go with it at once (the
    watchdog's own look is minutes away here), rather than lingering."""
    with D.daemon_env(knobs={"watch_tick": 60}) as de:
        fc = de.claude()
        a = Agent(de, fc)
        jid = a.ok("/agent/job/start", {"argv": ["true"], "cwd": str(de.root)})["id"]
        _job_wait(a, jid, ("exited",))
        _wait_watchdog(de)
        server = _server_pid(de)
        de.stop()
        assert _gone(server, 3), "the tmux server stayed after gated exited with nothing running"
        assert "the tmux server was stopped" in de.log()


def test_the_watchdog_stops_the_server_once_gated_is_gone_and_no_pane_runs():
    """gated stopped (SIGTERM) while a job runs keeps its tmux server for the
    next gated; if none comes and the job then ends, the watchdog sees gated's
    socket gone and no pane running anything (only itself) and stops the
    server. While the job runs it never does."""
    with D.daemon_env(knobs={"watch_tick": 1}) as de:
        fc = de.claude()
        a = Agent(de, fc)
        jid = a.ok("/agent/job/start", {"argv": ["sleep", "300"], "cwd": str(de.root)})["id"]
        _wait_watchdog(de)
        server = _server_pid(de)
        gated = de.daemon_pid()
        os.kill(gated, signal.SIGTERM)
        assert _gone(gated, 10)
        assert not de.sock.exists()
        time.sleep(3.0)                                  # three of the watchdog's looks
        assert _alive(server), "the watchdog stopped a server whose job still runs"
        _end_pane(de, jid)
        assert _gone(server, 6), "the watchdog left the server with gated gone and nothing running"


# ---------------------------------------------------------------------------
# Re-fix of 0.9.1's verified findings (refix-gw): a killed gated and its
# watchdog, a job left suspended at an uninstall, an update's sweep of the old
# version folder
# ---------------------------------------------------------------------------


def _kept_exited_job(de: D.DaemonEnv, a: Agent) -> tuple[int, int, Path, list[str]]:
    """A job that has exited (its dead pane kept for reads) and nothing else:
    (gated's pid, the tmux server's pid, gated's pid file, its words)."""
    jid = a.ok("/agent/job/start", {"argv": ["true"], "cwd": str(de.root)})["id"]
    _job_wait(a, jid, ("exited",))
    _wait_watchdog(de)
    gated = de.daemon_pid()
    pidf = de.run / "gated.pid"
    return gated, _server_pid(de), pidf, pidf.read_text().split()


def test_the_watchdog_stops_the_server_once_gated_was_killed_and_only_a_dead_pane_is_left():
    """gated killed (SIGKILL, a crash, the OOM killer: no cleanup) leaves its
    socket file behind, so the socket alone made the watchdog take it for
    alive and the server ran on forever with its dead panes (and from deleted
    binaries after an uninstall). gated writes its pid and start time next to
    its socket before it listens; the watchdog reads them: while gated lives it
    never stops a server whose panes are all dead (kept for reads); once that
    pid is dead, or is another process (a reused pid: another start time), it
    stops the server."""
    with D.daemon_env(knobs={"watch_tick": 1}) as de:
        fc = de.claude()
        a = Agent(de, fc)
        gated, server, pidf, words = _kept_exited_job(de, a)
        assert words[:1] == [str(gated)] and len(words) > 1, words
        assert " ".join(words[1:]) == T.ps_start(gated), "the pid file's start time isn't ps's"
        time.sleep(3.0)                                  # three of the watchdog's looks
        assert _alive(server), "the watchdog stopped the server of a live gated (only a dead pane)"
        os.kill(gated, signal.SIGKILL)
        assert _gone(gated, 5)
        assert de.sock.exists() and pidf.exists(), "a killed gated cleaned up after itself?"
        assert _gone(server, 6), "the watchdog left the server of a killed gated running"
    # the pid file names a live process that started at another time (a reused pid)
    with D.daemon_env(knobs={"watch_tick": 1}) as de:
        fc = de.claude()
        a = Agent(de, fc)
        gated, server, pidf, words = _kept_exited_job(de, a)
        os.kill(gated, signal.SIGKILL)
        assert _gone(gated, 5)
        pidf.write_text(f"{os.getpid()} Mon Jan 1 00:00:00 2001\n")
        assert _gone(server, 6), "the watchdog took a reused pid for gated"


def test_a_job_left_suspended_at_an_uninstall_is_resumed_and_gated_leaves_after_it():
    """checkpoint paused the task (on_pause suspend: the job stopped), then a
    plain uninstall: contract.json goes at once, so checkpoint can't find
    gated to send /v1/resume, and the stopped job kept gated, its tmux server
    and itself there forever. The drain resumes it (SIGCONT, counted in
    daemon.draining), refuses a new pause (nothing could resume what it would
    suspend) while it leaves other jobs alone, and gated leaves once the jobs
    have ended."""
    import shutil
    with D.daemon_env(knobs={"watch_tick": 60}) as de:
        fc = de.claude()
        a = Agent(de, fc)
        cwd = str(de.root)
        jid = a.ok("/agent/job/start", {"argv": ["sleep", "172"], "cwd": cwd, "on_pause": "suspend",
                                        "task_ref": "t1"})["id"]
        other = a.ok("/agent/job/start", {"argv": ["sleep", "173"], "cwd": cwd, "on_pause": "suspend",
                                          "task_ref": "t2"})["id"]
        time.sleep(0.5)
        st, r = a.call("/v1/pause", {"session": "s-test", "task_ref": "t1", "reason": "x"}, mode="x")
        assert st == 200 and {o["job"]: o["outcome"] for o in r["outcomes"]} == \
            {jid: "suspended (SIGSTOP)"}, r
        _job_wait(a, jid, ("suspended",))
        gated = de.daemon_pid()
        server = _server_pid(de)

        def stats(word: str) -> list[str]:
            return [ln.split()[1] for ln in subprocess.run(["ps", "-axo", "pid=,stat=,command="],
                                                            capture_output=True, text=True).stdout.splitlines()
                    if ln.split()[2:] == ["sleep", word]]
        assert stats("172") and all(s.startswith("T") for s in stats("172"))
        log = open(paths.gated_log(), errors="replace")        # the file goes with the folder
        data = Path(de.env.data)
        shutil.rmtree(data)
        assert de.wait_for(lambda: (de.health() or {}).get("draining"), 5), de.health()
        assert not paths.contract_path().exists()
        assert _job_wait(a, jid, ("running",))["state"] == "running", "the suspended job stayed stopped"
        assert stats("172") and not any(s.startswith("T") for s in stats("172")), stats("172")
        ev = _events(de, ("daemon.draining",))
        assert ev and ev[-1]["resumed"] == 1 and ev[-1]["jobs"] == 2, ev
        # a pause reaching the draining gated now is refused, and nothing is applied
        st, r = a.call("/v1/pause", {"session": "s-test", "task_ref": "t2", "reason": "x"}, mode="x")
        assert st == 503 and r.get("error") == "draining" and "no new pause" in r["message"], (st, r)
        time.sleep(0.3)
        assert a.ok("/agent/job/status", {"id": other})["state"] == "running"
        assert not any(s.startswith("T") for s in stats("173")), stats("173")
        time.sleep(1.0)
        assert de.daemon_pid() == gated and _alive(server), "gated left while its jobs run"
        _end_pane(de, jid)
        _end_pane(de, other)
        assert _gone(gated, 10), "gated stayed after its last job ended"
        assert _gone(server, 5), "its tmux server stayed"
        text = log.read()
        log.close()
        assert f"terminals: resumed {jid} (SIGCONT)" in text, text[-800:]
        assert "nothing runs any more: exiting" in text, text[-800:]
        assert not data.exists(), "the deleted data folder was made again"
        data.mkdir(parents=True)                                   # for the harness's cleanup


def test_an_updates_sweep_of_the_old_version_folder_is_no_uninstall():
    """An update leaves the old version folder orphaned beside the new one, and
    Claude Code removes it 14 days later unless a live session uses it, while
    the old gated may still run a terminal or job. That is no uninstall (0.9.1
    drained it and refused every new terminal as "uninstalled"): gated serves
    on (no drain, contract.json kept, new terminals taken) and leaves once
    nothing runs, its tmux server with it."""
    import shutil
    with D.daemon_env(start=False, knobs={"watch_tick": 60}) as de:
        copy = D.plugin_copy(de.root, D.plugin_version())
        de.start_from(copy)
        fc = de.claude()
        a = Agent(de, fc)
        tid = a.open()["id"]
        D.plugin_copy(de.root, "99.0.0")                     # the update: a newer version beside it
        (copy / ".orphaned_at").write_text("1792450000000")
        time.sleep(0.5)
        gated = de.daemon_pid()
        shutil.rmtree(copy)                                  # the sweep of the old version folder
        time.sleep(1.0)                                      # ten ticks
        h = de.health() or {}
        assert h.get("pid") == gated and not h.get("draining"), h
        assert paths.contract_path().exists(), "the swept version's gated withdrew the contract"
        t2 = a.open()["id"]
        _wait_watchdog(de)
        server = _server_pid(de)
        time.sleep(0.5)
        assert de.daemon_pid() == gated, "gated left while its terminals run"
        a.ok("/agent/term/close", {"id": tid})
        a.ok("/agent/term/close", {"id": t2})
        assert _gone(gated, 10), "the swept version's gated stayed with nothing running"
        assert _gone(server, 5), "its tmux server stayed"
        assert "replaced by an update" in de.log(), de.log()[-800:]
        assert not paths.contract_path().exists()
