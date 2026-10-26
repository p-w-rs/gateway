"""dialog.py (PLAN-v4 phase 3): native dialogs only. No OS dialog backend is
left (osascript, zenity, kdialog), and nothing in the plugin starts one, a
browser (but the browser sign-in's, PLAN-0.11 §7) or a terminal; the backend
is the gateway daemon's native dialog
(test_dialogs.py drives it end to end), the test fake, or none under a test
override; the fake's protocol and outcomes; the session record ssh.py reads."""
from __future__ import annotations

import os
import re
from pathlib import Path

import harness as H
import harness_ux as U
from gateway import dialog


def _script(path: Path, body: str) -> str:
    path.write_text("#!/bin/sh\n" + body + "\n")
    os.chmod(path, 0o755)
    return str(path)


def _span(path: Path, func: str) -> range:
    """The line numbers of a top-level function in path."""
    lines = path.read_text().splitlines()
    start = next(i for i, ln in enumerate(lines, 1) if ln.startswith(f"def {func}("))
    end = next((i for i, ln in enumerate(lines, 1) if i > start and ln.startswith(("def ", "class "))),
               len(lines) + 1)
    return range(start, end)


def test_no_os_dialog_browser_or_terminal_opener_is_left_in_the_code():
    """Nothing the plugin runs names an OS dialog program, a URL opener or a
    terminal emulator (brief sections 3 and 11.1). The one exception is the
    browser sign-in's system browser (PLAN-0.11 §7.2), opened by gated after
    the person's Open, and named only in daemon/oauth.py's browser_command.
    The approval hook names osascript only to refuse its administrator
    privileges (PLAN-0.11 §9.5: hooks_bash's elevation finders and
    _other_elevation) or a script it can't read (_hides), never runs it."""
    oauth_py = H.PLUGIN / "src" / "gateway" / "daemon" / "oauth.py"
    allowed = {f"src/gateway/daemon/oauth.py:{n}" for n in _span(oauth_py, "browser_command")}
    hb = H.PLUGIN / "src" / "gateway" / "hooks_bash.py"
    judged = {f"src/gateway/hooks_bash.py:{n}"
              for f in ("_text_elevator", "_elevation_tool", "_other_elevation", "_hides")
              for n in _span(hb, f)}
    banned = re.compile(r"""["'/](osascript|zenity|kdialog|xdg-open|gnome-terminal|x-terminal-emulator|xterm)["' ]"""
                        r"""|["']/usr/bin/open["']|webbrowser|display dialog|choose from list"""
                        # an argv naming one: ["open", url], ['xdg-open', ...], ("konsole", ...)
                        r"""|\[\s*["']open["']"""
                        r"""|[\[(,]\s*["'](osascript|zenity|kdialog|xdg-open|konsole|gnome-terminal|xterm"""
                        r"""|x-terminal-emulator|open -a|open -u)["']""")
    for planted in ('subprocess.run(["open", url])', "$.process.run(['xdg-open', u])",
                    'os.execvp("osascript", ("osascript", "-e", s))', 'cmd = ("konsole", "-e")'):
        assert banned.search(planted), planted          # the pattern catches each shape
    hits = []
    roots = [H.PLUGIN / "src", H.PLUGIN / "hooks", H.PLUGIN / "run.py"]
    for root in roots:
        files = [root] if root.is_file() else [p for p in root.rglob("*") if p.is_file()]
        for p in files:
            if p.suffix not in (".py", ".sh", ".ts", ".tsx", ".json") and p.name != "run.py":
                continue
            if "vendor" in p.parts:
                continue
            for n, line in enumerate(p.read_text(errors="replace").splitlines(), 1):
                if banned.search(line) and not line.lstrip().startswith(("#", "//", "*")):
                    hits.append(f"{p.relative_to(H.PLUGIN)}:{n}")
    excepted = [h for h in hits if h in allowed]
    assert [h for h in hits if h not in allowed and h not in judged] == [], hits
    assert 1 <= len(excepted) <= 2, excepted       # /usr/bin/open and xdg-open, nothing else


def test_backend_choice():
    with H.gateway_env() as env:
        be, why = dialog.backend()
        assert be is None and "test override" in why, "a test without a fake never reaches a session"
        env.o.dialog = "none"
        assert dialog.backend()[0] is None
        assert dialog.show("secret", "m").outcome == "unavailable"
        env.o.dialog = "/x/fake"
        assert dialog.backend()[0] == "fake"
        env.o.dialog = None
        env.o.extra["native_dialogs"] = True
        assert dialog.backend()[0] == "native"
    with H.gateway_env(e2e="/tmp/x"):
        assert dialog.backend()[0] == "native", "the e2e and TUI copies use the real dialog"


def test_native_without_a_lease_is_unavailable_and_says_why():
    with H.gateway_env(native_dialogs=True):
        dialog.set_lease(None)
        r = dialog.show("secret", "m")
        assert r.outcome == "unavailable" and r.reason


def test_fake_protocol_and_outcomes():
    with H.gateway_env() as env:
        d = env.root / "bin"
        d.mkdir()
        log = d / "args"
        cases = [("echo 'typed value'; exit 0", "ok", "typed value"),
                 ("exit 1", "cancelled", None), ("exit 5", "timeout", None),
                 ("exit 3", "unavailable", None)]
        for body, outcome, value in cases:
            env.o.dialog = _script(d / "fake", f"printf '%s\\n' \"$@\" > '{log}'\n{body}")
            r = dialog.show("secret", "the message", title="T")
            assert r.outcome == outcome and r.value == value, (body, r)
            assert log.read_text().split("\n")[:3] == ["secret", "T", "the message"]
        env.o.dialog = _script(d / "fake", f"printf '%s\\n' \"$@\" > '{log}'\nexit 0")
        dialog.show("confirm", "m", ok_label="Approve", cancel_label="Decline", default_cancel=True)
        assert log.read_text().split("\n")[3] == "Decline", "a confirm's default button goes to the fake"
        dialog.show("choice", "m", options=["one", "two"])
        assert log.read_text().split("\n")[3:5] == ["one", "two"]


def test_a_retry_shows_the_reason_and_the_attempt_first():
    with H.gateway_env() as env:
        fake = H.FakeDialog(env.root / "fd", [{"outcome": "ok", "value": "a"},
                                              {"outcome": "ok", "value": "b"}])
        env.o.dialog = str(fake.script)
        d = dialog.Dialog(dialog.Spec("secret", "Type it."))
        assert d.ask().value == "a"
        assert d.retry("wrong", 2, 3).value == "b"
        assert fake.calls()[1]["message"] == "That didn't work: wrong\nTry again (2 of 3).\n\nType it."


def test_the_remember_choice_from_the_fake():
    with H.gateway_env() as env:
        fake = H.FakeDialog(env.root / "fd", [{"outcome": "ok", "value": "v"},
                                              {"outcome": "ok", "value": "\x00forget\x00v"}])
        env.o.dialog = str(fake.script)
        assert dialog.show("secret", "m", remember=True).remember is True
        r = dialog.show("secret", "m", remember=True)
        assert r.remember is False and r.value == "v"
        assert dialog.Dialog(dialog.Spec("secret", "m")).spec.remember is None


def test_the_session_record_names_this_sessions_agent_never_the_callers():
    """ssh.py's "use my own SSH login once" reads SSH_AUTH_SOCK from the
    session record (Claude Code's environment), never the caller's."""
    with H.gateway_env():
        from gateway import popup
        d = popup.state_dir()
        assert dialog._session_record() is None
        old = d / "older-session.env"
        old.write_text("started=1\nSSH_AUTH_SOCK=/tmp/old/agent\n")
        os.utime(old, (1_000_000, 1_000_000))
        (d / "real-session.env").write_text("started=2\nSSH_AUTH_SOCK=/tmp/real/agent\n")
        (d / "real-session.shown.json").write_text("{}")        # not a record
        for sid in ("real-session", "some-other-id", "", None):
            with U.env_vars(CLAUDE_CODE_SESSION_ID=sid):
                assert "SSH_AUTH_SOCK=/tmp/real/agent" in (dialog._session_record() or ""), sid
        with U.env_vars(CLAUDE_CODE_SESSION_ID="older-session"):
            assert "/tmp/old/agent" in (dialog._session_record() or ""), "a session's own record wins"
