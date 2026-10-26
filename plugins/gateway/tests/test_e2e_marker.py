"""The e2e redirection (paths.e2e_marker, hooks/e2e.sh, tests/e2e/README.md).

The marker counts only for a plugin copy under a temp folder whose `e2e-root`
file (private, owned by this user) names private folders under a temp
folder; it is ignored otherwise. The checkout never carries one. The sh side
(hooks/e2e.sh through `launch.sh e2e-root`, which exits before any Python
runs) must agree with Python on every case, or a sh hook could use a home
Python doesn't.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import harness as H
from gateway import paths, testing


def _tmp(prefix: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix, dir=H.tmp_base())).resolve()


class Copy:
    """A minimal plugin copy (hooks/launch.sh + hooks/e2e.sh) under the test
    temp folder, an e2e root and a run dir (both 0700)."""

    def __init__(self) -> None:
        self.base = _tmp("gwe2e-")
        self.plugin = self.base / "plugin"
        (self.plugin / "hooks").mkdir(parents=True)
        for f in ("launch.sh", "e2e.sh"):
            shutil.copy2(H.PLUGIN / "hooks" / f, self.plugin / "hooks" / f)
        self.root = self.base / "root"
        self.run = self.base / "run"
        for d in (self.root, self.run):
            d.mkdir(mode=0o700)
            os.chmod(d, 0o700)
        self.marker = self.plugin / paths.E2E_MARKER

    def write(self, text: str, mode: int = 0o600) -> None:
        self.marker.unlink(missing_ok=True)
        self.marker.write_text(text)
        os.chmod(self.marker, mode)

    def py(self, **kw):
        return paths.e2e_marker(self.plugin, **kw)

    def sh(self) -> tuple[Path, Path | None] | None:
        r = subprocess.run(["/bin/sh", str(self.plugin / "hooks" / "launch.sh"), "e2e-root"],
                           capture_output=True, text=True, timeout=30,
                           env={"PATH": "/usr/bin:/bin", "HOME": str(self.base)})
        if r.returncode != 0:
            return None
        lines = r.stdout.split("\n")
        return Path(lines[0]), (Path(lines[1]) if lines[1] else None)

    def agree(self, expect: tuple[Path, Path | None] | None) -> None:
        got_py, got_sh = self.py(), self.sh()
        assert got_py == expect, (got_py, expect)
        assert got_sh == expect, ("sh and Python disagree", got_sh, expect)

    def close(self) -> None:
        shutil.rmtree(self.base, ignore_errors=True)


def test_checkout_has_no_marker():
    assert not (paths.code_root() / paths.E2E_MARKER).exists(), \
        "the checkout must never carry an e2e-root marker (tests/e2e writes it into a copy)"
    assert not (H.PLUGIN / paths.E2E_MARKER).exists()
    assert paths.e2e_marker(paths.code_root()) is None
    # under a test override the production call never looks
    with H.gateway_env():
        assert paths.e2e_marker() is None and paths.e2e_root() is None


def test_valid_marker_is_honoured_by_python_and_sh():
    c = Copy()
    try:
        c.agree(None)                                   # absent: ignored
        c.write(f"{c.root}\n")
        c.agree((c.root, None))
        c.write(f"{c.root}\n{c.run}\n")
        c.agree((c.root, c.run))
        assert paths.e2e_root(c.plugin) == c.root
    finally:
        c.close()


def test_production_call_reads_the_codes_own_folder_and_never_under_a_test_override():
    c = Copy()
    orig = paths.code_root
    try:
        c.write(f"{c.root}\n{c.run}\n")
        paths.code_root = lambda: c.plugin            # as if this code ran from the copy
        assert paths.e2e_marker() == (c.root, c.run)
        with H.gateway_env():
            assert paths.e2e_marker() is None         # unit tests: the override wins
    finally:
        paths.code_root = orig
        c.close()


def test_marker_pointing_outside_temp_is_ignored():
    c = Copy()
    other = _tmp("gwe2e-other-")
    try:
        os.chmod(other, 0o700)
        # a folder outside the temp roots the check is given
        c.write(f"{other}\n")
        assert c.py() == (other, None)
        assert c.py(temp_roots=[str(c.base)]) is None
        # the plugin itself outside the temp roots: ignored even when what it
        # names is inside them
        sub = other / "sub"
        sub.mkdir(mode=0o700)
        os.chmod(sub, 0o700)
        c.write(f"{sub}\n")
        assert c.py(temp_roots=[str(other), str(c.base)]) == (sub, None)
        assert c.py(temp_roots=[str(other)]) is None
        # spellings that leave the temp folder (both sides refuse them)
        for bad in (f"{c.root}/../../../../../../../usr", "/usr", "/", "relative/path",
                    f"{c.root}//x", f"{c.root}/./", f" {c.root}", f"{c.root}\r",
                    str(testing.real_user_home())):
            c.write(bad + "\n")
            c.agree(None)
        # physically outside through a symlinked folder on the way
        (c.base / "lnk").symlink_to("/usr")
        c.write(f"{c.base}/lnk/share\n")
        c.agree(None)
        # three lines, or a bad second line
        c.write(f"{c.root}\n{c.run}\n{c.run}\n")
        c.agree(None)
        c.write(f"{c.root}\n/usr\n")
        c.agree(None)
    finally:
        c.close()
        shutil.rmtree(other, ignore_errors=True)


def test_marker_not_owned_by_the_user_is_ignored():
    c = Copy()
    try:
        c.write(f"{c.root}\n")
        assert c.py() == (c.root, None)
        assert c.py(uid=os.getuid() + 4242) is None     # every file belongs to someone else
    finally:
        c.close()


def test_unsafe_marker_files_and_folders_are_ignored():
    c = Copy()
    try:
        c.write(f"{c.root}\n", mode=0o666)               # writable by others
        c.agree(None)
        c.write(f"{c.root}\n", mode=0o620)               # writable by the group
        c.agree(None)
        real = c.plugin / "marker-target"
        real.write_text(f"{c.root}\n")
        c.marker.unlink()
        c.marker.symlink_to(real)                        # a symlinked marker
        c.agree(None)
        c.write(f"{c.root}\n")
        os.chmod(c.root, 0o750)                          # group bits on the root
        c.agree(None)
        os.chmod(c.root, 0o700)
        alias = c.base / "alias"
        alias.symlink_to(c.root)                         # the root named through a symlink
        c.write(f"{alias}\n")
        c.agree(None)
        f = c.base / "afile"
        f.write_text("")
        c.write(f"{f}\n")                                # not a directory
        c.agree(None)
        c.write(f"{c.root}\n")
        c.agree((c.root, None))
    finally:
        c.close()


def test_e2e_config_keeps_only_known_knobs():
    c = Copy()
    try:
        cfg = c.root / paths.E2E_CONFIG
        cfg.write_text(json.dumps({
            "dialog": "/x/fake-dialog", "tools": {"sudo": "/x/sudo", "ssh": "rel/ssh"},
            "machine_id": "E2E-1", "popup_wait": 5, "system_git": True,
            "home": "/somewhere/else", "data": "/elsewhere", "entry": ["/bin/sh"],
            "popup_lifetime": "30", "dialog_timeout": True, "user_tools": "/x/user-tools"}))
        os.chmod(cfg, 0o600)
        got = paths.e2e_config(c.root)
        assert got == {"dialog": "/x/fake-dialog", "tools": {"sudo": "/x/sudo"},
                       "machine_id": "E2E-1", "popup_wait": 5, "system_git": True,
                       "user_tools": "/x/user-tools"}, got
        # the folder of the user's own tools (recording fakes for a pass-through,
        # PLAN-0.11 §1.3) counts only when absolute, like the tools
        for bad in ("user-tools", "./x", "", ["/x"], True):
            cfg.write_text(json.dumps({"user_tools": bad, "machine_id": "E2E-2"}))
            assert paths.e2e_config(c.root) == {"machine_id": "E2E-2"}, (bad, paths.e2e_config(c.root))
        os.chmod(cfg, 0o666)
        assert paths.e2e_config(c.root) == {}            # a config others could write
        os.chmod(cfg, 0o600)
        assert paths.e2e_config(c.root, uid=os.getuid() + 4242) == {}
    finally:
        c.close()


def test_e2e_override_redirects_and_still_guards_the_real_home():
    """What e2e_context sets up (an override with e2e=ROOT): every location
    inside the root, and the real private folder still refused by the guards,
    compared as text only. A fake "real" home stands in for the person's:
    Protected.contains resolves the path it is asked about, and no test may
    stat the real ~/.config/gateway (PLAN-v4 phase 2)."""
    c = Copy()
    orig_real = testing.real_user_home
    fake_real = c.base / "fake-real-home"
    testing.real_user_home = lambda: fake_real
    try:
        with testing.override(c.root, run=c.run, e2e=str(c.root), machine_id="E2E-1"):
            assert paths.home() == c.root / "home" / ".config" / "gateway"
            assert paths.data_dir() == c.root / "data" and paths.run_dir() == c.run
            assert paths.user_home() == c.root / "home"
            real = testing.real_user_home() / ".config" / "gateway"
            reals = paths.real_protected_paths()
            assert real / "private" in reals
            prot = paths.Protected()
            assert all(not str(p).startswith(str(real)) for p in prot.paths)   # never walked
            assert prot.contains(str(real / "private" / "key.txt"))
            assert prot.contains(str(real / "key.txt"))
            assert prot.is_parent(str(real.parent))
            assert prot.contains(str(paths.private_dir() / "vault.age"))
        with H.gateway_env():
            assert paths.real_protected_paths() == []    # unit tests: test home only
    finally:
        testing.real_user_home = orig_real
        c.close()


def test_session_start_says_e2e_mode():
    from gateway import hooks_session
    with H.gateway_env() as env:
        env.o.extra["e2e"] = str(env.root)
        env.write_form("[hosts.box]\naddress = \"u@127.0.0.1:2222\"\n")
        out = hooks_session.session_main({"session_id": "s-e2e"})
        assert out["systemMessage"].startswith("gateway: e2e test mode: this session uses the "
                                               f"test vault in {env.root}")
        env.o.extra.pop("e2e")
        out = hooks_session.session_main({"session_id": "s-e2e-2"})
        assert "e2e test mode" not in out.get("systemMessage", "")


def _run_e2e():
    import sys
    if str(H.TESTS / "e2e") not in sys.path:
        sys.path.insert(0, str(H.TESTS / "e2e"))
    import run_e2e
    return run_e2e


def test_e2e_jobs_scenario_needs_checkpoint_next_to_the_repo_and_stays_in_the_root():
    """The optional jobs scenario (tests/e2e): a checkpoint checkout counts only
    next to the gateway repo (../checkpoint/plugins/checkpoint, with run.py,
    .mcp.json and pixi.toml), else the scenario is skipped; checkpoint's state
    folder and gateway env file are set inside the e2e root, and a root whose
    folders lead elsewhere (a symlink) is refused; the kill switch accepts a
    checkpoint server only with exactly those two values."""
    R = _run_e2e()
    base = _tmp("gwck-")
    try:
        plugin = base / "gateway" / "plugins" / "gateway"
        plugin.mkdir(parents=True)
        assert R.find_checkpoint(plugin) is None                   # no checkout: skipped
        ck = base / "checkpoint" / "plugins" / "checkpoint"
        ck.mkdir(parents=True)
        for f in ("run.py", ".mcp.json"):
            (ck / f).write_text("")
        assert R.find_checkpoint(plugin) is None                   # not a whole plugin
        (ck / "pixi.toml").write_text("")
        assert R.find_checkpoint(plugin) == ck.resolve()
        root = base / "root"
        root.mkdir()
        env = R.checkpoint_env(root)
        home = str(root / "home" / ".local" / "state" / "checkpoint")
        gw = str(root / "home" / ".config" / "gateway" / "env.sh")
        assert env == {"CHECKPOINT_HOME": home, "CHECKPOINT_GATEWAY_ENV": gw}, env
        evil = base / "evil"
        evil.mkdir()
        (evil / "home").symlink_to(base / "elsewhere")
        try:
            R.checkpoint_env(evil)
            raise AssertionError("a root whose home leads out of it was accepted")
        except SystemExit:
            pass
        line = (f"python {ck}/run.py server PATH=/usr/bin:/bin CHECKPOINT_HOME={home} "
                f"CHECKPOINT_GATEWAY_ENV={gw} TERM=dumb")
        assert R.server_env_verdict(line, gw, home)[0] is True
        real = str(R.real_home() / ".config" / "gateway" / "env.sh")
        for bad in (line.replace(f"CHECKPOINT_GATEWAY_ENV={gw}", ""),
                    line.replace(f"CHECKPOINT_GATEWAY_ENV={gw}", f"CHECKPOINT_GATEWAY_ENV={real}"),
                    line.replace(f"CHECKPOINT_GATEWAY_ENV={gw}", "CHECKPOINT_GATEWAY_ENV="),
                    line.replace(f"CHECKPOINT_GATEWAY_ENV={gw}", f"XCHECKPOINT_GATEWAY_ENV={gw}"),
                    line.replace(f"CHECKPOINT_HOME={home}", ""),
                    line.replace(f"CHECKPOINT_HOME={home}", "CHECKPOINT_HOME=/elsewhere")):
            assert R.server_env_verdict(bad, gw, home)[0] is False, bad
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_e2e_jobs_counts_a_classifier_denial_as_not_reached_never_a_gateway_denial():
    """The jobs scenario: the gateway never approves a job, so Claude Code's
    auto-mode classifier decides each job_start the gateway doesn't deny. A
    step the classifier denied is "not reached (classifier)": no pass, no
    failure. A denial by the gateway's hook (a PreToolUse hook error, before
    any classifier) and a call that ran are never counted so: the gateway's
    assertions decide them."""
    _run_e2e()
    import e2elib as L
    import scenarios as SC

    def call(result: str, denied: bool = True) -> L.ToolCall:
        return L.ToolCall("toolu_x", SC.JOB_TOOL, {"name": "x"}, result=result, denied=denied)

    cls = call("Permission for this action was denied by the Claude Code auto mode classifier. "
               "Reason: [Third-Party Attack]. If you have other tasks that don't depend on this "
               "action, continue working on those.")
    srv = call("Permission for this action was denied by the Claude Code auto mode classifier. "
               "Reason: The server-side auto mode classifier judged this action dangerous (it "
               "gave no explanation). If you have other tasks ...")
    hook = call("PreToolUse:mcp__plugin_check_jobs__job_start hook error: gateway: a job can't "
                "use the \"ask\" right for ssh on e2eask; (not the auto mode classifier)")
    ran = call('{"ok": true, "job": {"command": "echo auto mode classifier"}}', denied=False)
    assert SC.classifier_denial(cls) == "[Third-Party Attack]"
    assert "server-side auto mode classifier" in SC.classifier_denial(srv)
    assert SC.classifier_denial(hook) is None and SC.classifier_denial(ran) is None
    assert SC.classifier_denial(None) is None
    C = L.Checks()
    assert SC._reached(C, "jobs", "job_start x", cls, "a", "b") is False
    assert SC._reached(C, "jobs", "job_start x", None, "c") is False
    assert SC._reached(C, "jobs", "job_start x", hook, "d") is True
    assert SC._reached(C, "jobs", "job_start x", ran, "e") is True
    assert [(c.name, c.ok) for c in C.items] == [("a", None), ("b", None), ("c", None)]
    assert [c.name for c in C.classifier] == ["a", "b"] and not C.failed
    assert C.items[0].detail.startswith("not reached (classifier): job_start x denied by "
                                        "Claude Code's auto-mode classifier ([Third-Party")
    assert C.items[2].detail == "the model never made this call"
    assert C.table().endswith("0 passed, 0 failed, 3 not reached (2 because Claude Code's "
                              "auto-mode classifier denied the call)")


def test_e2e_jobs_judges_the_job_step_that_ran_even_after_a_classifier_denial():
    """The model may retry a job step: the call that ran (not denied) is the
    one judged, like its job record (_ck_job takes the last record with the
    name), and "not reached (classifier)" only when every call with that
    name was denied by the classifier; a gateway (hook) denial is judged
    before a classifier denial."""
    _run_e2e()
    import types
    import e2elib as L
    import scenarios as SC
    cls_text = ("Permission for this action was denied by the Claude Code auto mode classifier. "
                "Reason: [Credential Exploration]. If you have other tasks ...")
    hook_text = "PreToolUse:mcp__plugin_check_jobs__job_start hook error: gateway: use the http tool"

    def call(i: int, name: str, result: str, denied: bool = True) -> L.ToolCall:
        return L.ToolCall(f"toolu_{i}", SC.JOB_TOOL, {"name": name}, result=result, denied=denied)

    cls1, ran, cls2 = (call(1, "jobssh", cls_text), call(2, "jobssh", '{"ok": true}', False),
                       call(3, "jobssh", cls_text))
    bash = L.ToolCall("toolu_4", "Bash", {"name": "jobssh"}, result="x")
    retried = types.SimpleNamespace(calls=[cls1, bash, ran, cls2])
    assert SC._job_call(retried, "jobssh") is ran
    C = L.Checks()
    assert SC._reached(C, "jobs", "job_start jobssh", SC._job_call(retried, "jobssh"), "a")
    only_cls = types.SimpleNamespace(calls=[cls1, cls2])
    assert SC._job_call(only_cls, "jobssh") is cls2
    assert not SC._reached(C, "jobs", "job_start jobssh", SC._job_call(only_cls, "jobssh"), "b")
    hook, cls3 = call(5, "curljob", hook_text), call(6, "curljob", cls_text)
    assert SC._job_call(types.SimpleNamespace(calls=[hook, cls3]), "curljob") is hook
    assert SC._job_call(types.SimpleNamespace(calls=[cls3, hook]), "curljob") is hook
    ran2 = call(7, "jobssh", '{"ok": true, "again": true}', False)
    assert SC._job_call(types.SimpleNamespace(calls=[ran, cls1, ran2]), "jobssh") is ran2
    assert SC._job_call(retried, "leak") is None
    assert [c.name for c in C.classifier] == ["b"] and not C.failed


def test_e2e_modes_reads_each_sessions_payload_strings_and_knows_only_the_gateways_table():
    """The modes scenario (PLAN-0.11 §2.1, §14): the probe plugin's hook
    (run_e2e.MODEPROBE_REC, run by sh here on a recorded payload's shape)
    keeps only the event, the session id and permission_mode; its records
    are read per session; a payload string passes only when
    modes.from_payload knows it and it means the key of the
    --permission-mode choice (an empty or missing mode, another mode's
    string or a choice the table lacks fails)."""
    R = _run_e2e()
    import scenarios as SC
    base = _tmp("gwmp-")
    try:
        log = base / "modeprobe.log"
        rec = base / "rec.sh"
        rec.write_text(R.MODEPROBE_REC.replace("@LOG@", str(log)))
        payloads = [
            ("PreToolUse", {"session_id": "s-1", "hook_event_name": "PreToolUse",
                            "tool_input": {"command": 'echo "permission_mode": "plan"'},
                            "permission_mode": "acceptEdits", "cwd": "/w"}),
            ("SessionStart", {"session_id": "s-1", "source": "startup"}),
            ("PreToolUse", {"permission_mode": "default", "session_id": "s-2"}),
            # the key twice, on lines of their own (a tool input that is an object): still one record
            ("PreToolUse", {"session_id": "s-4", "tool_input": {"permission_mode": "plan"},
                            "permission_mode": "auto"}),
        ]
        for ev, p in payloads:
            r = subprocess.run(["/bin/sh", str(rec), ev], input=json.dumps(p, indent=1), text=True,
                               capture_output=True, timeout=30, env={"PATH": "/usr/bin:/bin"})
            assert r.returncode == 0 and r.stdout == "", r
        text = log.read_text()
        assert text == ("PreToolUse\ts-1\tacceptEdits\nSessionStart\ts-1\t-\n"
                        "PreToolUse\ts-2\tdefault\nPreToolUse\ts-4\tauto\n"), text
        assert "echo" not in text and "/w" not in text
        assert SC.mode_records(text + "a bad line\n", "s-1") == {"PreToolUse": ["acceptEdits"],
                                                                 "SessionStart": [""]}
        assert SC.mode_records(text, "s-3") == {}
    finally:
        shutil.rmtree(base, ignore_errors=True)
    for choice, payload in (("auto", "auto"), ("manual", "default"), ("manual", "manual"),
                            ("default", "default"), ("bypassPermissions", "bypassPermissions"),
                            ("plan", "plan"), ("acceptEdits", "acceptEdits"), ("dontAsk", "dontAsk")):
        assert SC.mode_verdict(choice, [payload, payload])[0] is True, (choice, payload)
    for choice, payload in (("bypassPermissions", "bypass"), ("auto", "default"), ("manual", ""),
                            ("dontAsk", "dontask"), ("auto", "Auto"), ("plan", "manual")):
        ok, why = SC.mode_verdict(choice, [payload])
        assert ok is False and choice in why, (choice, payload, why)
    assert SC.mode_verdict("auto", ["auto", "default"])[0] is False
    ok, why = SC.mode_verdict("newmode", ["newmode"])
    assert ok is False and "isn't in the gateway's table" in why
    assert SC.mode_verdict("auto", []) == (None, "no payload recorded")


def test_e2e_reads_the_hooks_decisions_and_what_the_env_probe_must_print():
    """hook_decisions: each PreToolUse decision a call got, in order (stream
    hook output, spaced or not); probe_want: the stand-ins first on PATH, no
    git include or transport variables, the user's own SSH_AUTH_SOCK and
    GITHUB_TOKEN kept and Claude Code's credential variable gone in Claude's
    Bash; in a job only the gateway's part. Every scenario run_e2e offers
    exists, in the same order."""
    R = _run_e2e()
    import e2elib as L
    import scenarios as SC
    assert list(R.SCENARIOS) == list(SC.SCENARIOS), (R.SCENARIOS, list(SC.SCENARIOS))
    c = L.ToolCall("toolu_1", "Bash", {"command": "curl x"}, hook_outputs=[
        '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask"}}',
        '{"hookSpecificOutput":{"permissionDecision":"allow"}}', "not json", ""])
    assert SC.hook_decisions(c) == ["ask", "allow"]
    assert SC.hook_decisions(None) == []
    w = SC.probe_want(Path("/r/data"))
    assert (w["path_first"], w["ssh"], w["sudo"], w["git"]) == (
        "/r/data/bin", "/r/data/bin/ssh", "/r/data/bin/sudo", "/r/data/bin/git")
    assert w["git_include"] == w["git_ssh_command"] == w["rsync_rsh"] == "" == w["client_key_pass"]
    assert w["ssh_auth_sock"] == w["github_token"] == w["claude_pid"] == "set"
    j = SC.probe_want(Path("/r/data"), job=True)
    assert set(j) == {"path_first", "ssh", "sudo", "git", "git_include", "git_ssh_command", "rsync_rsh"}
