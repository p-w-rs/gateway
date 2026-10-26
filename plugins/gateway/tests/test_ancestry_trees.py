"""ancestry.is_direct with real process trees (SPEC 10)."""
from __future__ import annotations

import os

import harness as H
import harness_sudo as HS
from gateway import ancestry


def test_direct_through_a_shell():
    with H.gateway_env() as env:
        allowed, culprit, r = HS.ancestry_tree(env, "direct", tool="sudo")
        assert allowed is True and culprit == "", r.stderr


def test_make_like_wrapper_is_not_direct():
    with H.gateway_env() as env:
        allowed, culprit, r = HS.ancestry_tree(env, "wrapper", tool="sudo")
        assert allowed is False, (culprit, r.stderr)
        assert "python" in culprit.lower() or culprit == "?"


def test_wrapper_allowed_with_scripts_true():
    with H.gateway_env() as env:
        allowed, culprit, r = HS.ancestry_tree(env, "wrapper", tool="sudo", scripts=True)
        assert allowed is True, (culprit, r.stderr)
        # culprit still names the intermediate (for the audit line).
        assert culprit and culprit != ""


def test_missing_claude_pid_is_not_direct():
    with H.gateway_env() as env:
        allowed, culprit, r = HS.ancestry_tree(env, "no-pid", tool="sudo")
        assert allowed is False, (culprit, r.stderr)


def test_missing_claude_pid_scripts_true_allowed():
    with H.gateway_env() as env:
        allowed, _, r = HS.ancestry_tree(env, "no-pid", tool="sudo", scripts=True)
        assert allowed is True, r.stderr


def test_checkpoint_job_runner_counts_like_claude():
    with H.gateway_env() as env:
        allowed, culprit, r = HS.ancestry_tree(env, "checkpoint", tool="sudo")
        assert allowed is True and culprit == "", r.stderr


def test_shell_dressed_up_as_checkpoint_runner_is_not_direct():
    # argv[0] is the real run.py path and `server` follows, but the process is
    # /bin/sh (identified by executable path), so it isn't the runner.
    with H.gateway_env() as env:
        allowed, culprit, r = HS.ancestry_tree(env, "checkpoint-shell", tool="sudo")
        assert allowed is False, (culprit, r.stderr)


def test_checkpoint_runner_needs_an_existing_run_py():
    with H.gateway_env() as env:
        allowed, culprit, r = HS.ancestry_tree(env, "checkpoint-missing", tool="sudo")
        assert allowed is False, (culprit, r.stderr)


def test_a_real_checkpoint_job_tree_is_direct_but_never_typed():
    """checkpoint starts a job as `python …/checkpoint/…/run.py server` ->
    `/bin/sh -c WRAPPER checkpoint-job-ID CMD EXITFILE ENVFILE STATUSFILE` (checkpoint's
    current wrapper, harness_sudo.CHECKPOINT_WRAPPER) -> `/bin/sh -c CMD` ->
    the stand-in. Credentials: direct (like Claude's shell), with or without a
    CLAUDE_PID in the job's environment. An "ask" right: never (nobody can be
    asked while a job runs; the approval hook denies it for job_start too),
    even with CLAUDE_PID forged to the runner itself. The refusal's culprit
    is "checkpoint" whenever the runner is above the stand-in, so the
    stand-ins give the approval hook's job wording."""
    with H.gateway_env() as env:
        for shape in ("checkpoint-job", "checkpoint-job-list", "checkpoint-job-claude",
                      "checkpoint-job-list-claude", "checkpoint-job-forged",
                      "checkpoint-runner-forged-direct"):
            for tool in ("sudo", "ssh", "gh"):
                ok, culprit, r = HS.ancestry_tree(env, shape, tool=tool)
                assert ok is True and culprit == "", (shape, tool, culprit, r.stderr)
            ok, culprit, r = HS.ancestry_tree(env, shape, tool="typed")
            assert ok is False and culprit == ancestry.CHECKPOINT, (shape, culprit, r.stderr)
        # the runner starting the stand-in through a shell (no CLAUDE_PID)
        ok, culprit, r = HS.ancestry_tree(env, "checkpoint", tool="typed")
        assert ok is False and culprit == ancestry.CHECKPOINT, (culprit, r.stderr)
        # not checkpoint's runner: the same script elsewhere, a shell or a python
        # dressed up as it, or no runner at all keep their own culprit
        for shape in ("job-elsewhere", "checkpoint-shell", "checkpoint-missing", "sh-c",
                      "script", "wrapper", "no-pid"):
            ok, culprit, r = HS.ancestry_tree(env, shape, tool="typed")
            assert ok is False and culprit != ancestry.CHECKPOINT, (shape, culprit, r.stderr)
        # the same runner script anywhere else is just a program (not direct)
        ok, culprit, r = HS.ancestry_tree(env, "job-elsewhere", tool="sudo")
        assert ok is False and "python" in culprit.lower(), (culprit, r.stderr)
        ok, _, r = HS.ancestry_tree(env, "job-elsewhere", tool="sudo", scripts=True)
        assert ok is True, r.stderr


def test_typed_by_claude_refuses_the_checkpoint_runner_even_as_claude_pid():
    """Without the explicit check, a job whose CLAUDE_PID names the runner
    would pass: the wrapper shell's parent is CLAUDE_PID."""
    with H.gateway_env() as env:
        ok, culprit, r = HS.ancestry_tree(env, "checkpoint-job-forged", tool="typed")
        assert ok is False and culprit == "checkpoint", (culprit, r.stderr)
        # the runner itself as CLAUDE_PID, starting the stand-in with no shell
        # in between of its own: still not typed (but direct for credentials)
        ok, culprit, r = HS.ancestry_tree(env, "checkpoint-runner-forged-direct", tool="typed")
        assert ok is False and culprit == "checkpoint", (culprit, r.stderr)
        ok, culprit, r = HS.ancestry_tree(env, "checkpoint-runner-forged-direct", tool="sudo")
        assert ok is True and culprit == "", (culprit, r.stderr)


def test_argv_of_self_is_a_list():
    import sys
    argv = ancestry._argv(os.getpid())
    assert isinstance(argv, list) and argv and any(a.endswith(".py") for a in argv), argv
    assert sys.argv[0] in " ".join(argv) or os.path.basename(sys.argv[0]) in " ".join(argv)


def test_git_family_allows_git_intermediate_but_sudo_does_not():
    # Same tree (sh -> python wrapper -> probe); the wrapper is python either way,
    # so both are non-direct — but the allowed set differs by tool, which we
    # exercise directly here (git credentials accept scp/ssh/git intermediates).
    assert "scp" in ancestry._allowed_names("ssh")
    assert "scp" not in ancestry._allowed_names("sudo")
    assert "git" in ancestry._allowed_names("git-credential")
    assert ancestry._is_allowed_name("git-remote-https", ancestry._allowed_names("ssh"))
    assert not ancestry._is_allowed_name("git-remote-https", ancestry._allowed_names("sudo"))


def test_exe_path_and_ppid_of_self():
    me = os.getpid()
    assert ancestry._ppid(me) == os.getppid()
    exe = ancestry._exe_path(me)
    assert exe and os.path.basename(exe).startswith("python")


def test_public_helpers_and_root_processes():
    """parent_pid answers for root's processes too (macOS: PROC_PIDT_SHORTBSDINFO;
    PROC_PIDTBSDINFO returns nothing for them, so a walk up through setuid sudo
    used to stop at sudo and the caller counted as not direct)."""
    import subprocess
    me = os.getpid()
    assert ancestry.parent_pid(me) == os.getppid()
    assert ancestry.exe_name(me).startswith("python") and ancestry.exe_path(me)
    rows = subprocess.run(["/bin/ps", "-axo", "pid=,ppid=,uid="], capture_output=True,
                          text=True, timeout=10).stdout.split("\n")
    checked = 0
    for row in rows:
        f = row.split()
        if len(f) == 3 and f[2] == "0" and f[0] != "1" and int(f[1]) > 0:
            pid, ppid = int(f[0]), int(f[1])
            got = ancestry.parent_pid(pid)
            if got == 0 and subprocess.run(["/bin/ps", "-p", str(pid)],
                                           capture_output=True).returncode != 0:
                continue          # gone since ps ran: skip
            assert got == ppid, (pid, got, ppid)
            checked += 1
            if checked >= 3:
                break
    assert checked, "no root process found to check"


# ---------------------------------------------------------------------------
# typed_by_claude: the test for an "ask" right (round 1, HIGH)
# ---------------------------------------------------------------------------


def test_typed_by_claude_accepts_claudes_shell_and_its_forks():
    with H.gateway_env() as env:
        for shape in ("direct", "subshell", "pipeline"):
            ok, culprit, r = HS.ancestry_tree(env, shape, tool="typed")
            assert ok is True and culprit == "", (shape, culprit, r.stderr)


def test_typed_by_claude_refuses_wrappers_scripts_and_shells_of_their_own():
    # Claude Code can only ask about the command line Claude typed: a program
    # in between (git, rsync, make, a wrapper), a script, or an `sh -c` shell
    # of its own (which the approval hook can't read) is never "typed".
    with H.gateway_env() as env:
        for shape in ("wrapper", "sh-c", "script", "no-pid", "checkpoint"):
            ok, culprit, r = HS.ancestry_tree(env, shape, tool="typed")
            assert ok is False, (shape, culprit, r.stderr)
        # the same trees are direct for credentials (is_direct): only "ask" is stricter
        for shape in ("sh-c", "script", "checkpoint"):
            ok, _, r = HS.ancestry_tree(env, shape, tool="sudo")
            assert ok is True, (shape, r.stderr)


def test_typed_by_claude_refuses_inside_a_gateway_terminal_or_job():
    """gated's start file exports CLAUDE_PID=$$ (the pane's own shell) for
    is_direct, so the stand-in that shell starts has CLAUDE_PID as its parent,
    and one a script started there starts has it as its grandparent: both
    passed the walk, so an "ask" right (or an "ask" policy) was used with
    nobody asked (gw-reruns, 2026-10-21). A CLAUDE_PID that names a shell is
    never Claude Code: not typed, culprit TERMINAL. Direct for credentials
    they stay (a command typed in a pane gets them like one in Claude's
    shell)."""
    with H.gateway_env() as env:
        for shape in ("pane", "pane-script"):
            ok, culprit, r = HS.ancestry_tree(env, shape, tool="typed")
            assert ok is False and culprit == ancestry.TERMINAL, (shape, culprit, r.stderr)
            ok, culprit, r = HS.ancestry_tree(env, shape, tool="sudo")
            assert ok is True and culprit == "", (shape, culprit, r.stderr)
        # Claude's own shell and its forks stay typed (the check is on CLAUDE_PID only)
        ok, culprit, r = HS.ancestry_tree(env, "direct", tool="typed")
        assert ok is True and culprit == "", (culprit, r.stderr)


# ---------------------------------------------------------------------------
# Claude Code by its executable path (is_claude_exe: gated's sessions;
# claude_install: /gate-doctor)
# ---------------------------------------------------------------------------

HOME = "/Users/u"
VERSIONS_BIN = HOME + "/.local/share/claude/versions/2.1.301"
DESKTOP_BIN = (HOME + "/Library/Application Support/Claude/claude-code/2.1.299/4fa9694b7975/"
               "claude.app/Contents/MacOS/claude")


def test_claude_code_is_recognised_by_its_executable_path():
    """A binary named claude, the native installer's versions folder and the
    desktop app's bundled copy under the person's home: nothing else (the
    desktop app itself and its helper, another home's versions folder,
    node, a shell)."""
    for exe in ("/opt/homebrew/bin/claude", VERSIONS_BIN, DESKTOP_BIN,
                HOME + "/Library/Application Support/Claude/claude-code/2.1.299/x/node"):
        assert ancestry.is_claude_exe(exe, HOME), exe
    assert not ancestry.is_claude_exe(VERSIONS_BIN), "the versions folder counts under the home only"
    for exe in ("/Applications/Claude.app/Contents/MacOS/Claude",
                "/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/"
                "Claude Helper",
                "/Users/other/.local/share/claude/versions/2.1.301", "/opt/x/bin/node", "/bin/zsh"):
        assert not ancestry.is_claude_exe(exe, HOME), exe
    assert ancestry.claude_install(VERSIONS_BIN, HOME).startswith("the native installer")
    assert ancestry.claude_install(DESKTOP_BIN, HOME) == "the desktop app's own copy"
    assert ancestry.claude_install("/opt/homebrew/bin/claude", HOME).startswith(
        "an executable named claude")
    assert ancestry.claude_install("/opt/x/bin/node", HOME) == ""


def test_npms_claude_code_counts_by_its_native_binary_only():
    """npm's @anthropic-ai/claude-code is Claude Code by its native binary
    (bin/claude.exe): a claude.exe anywhere else isn't, and node running the
    package's cli.js (npm installs before 2.1.113) isn't either."""
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as d:
        pre = Path(d) / "npm"
        pkg = pre / "lib" / "node_modules" / "@anthropic-ai" / "claude-code"
        pkg.mkdir(parents=True)
        (pkg / "cli.js").write_text("// cli\n")
        native = str(pkg / "bin" / "claude.exe")
        assert ancestry.is_claude_exe(native)
        assert ancestry.claude_install(native) == "npm (its native binary)"
        for exe in (str(Path(d) / "bin" / "claude.exe"),
                    str(pre / "node_modules" / "claude-code" / "bin" / "claude.exe"),
                    "/opt/x/bin/node", str(pkg / "cli.js")):
            assert not ancestry.is_claude_exe(exe) and ancestry.claude_install(exe) == "", exe
