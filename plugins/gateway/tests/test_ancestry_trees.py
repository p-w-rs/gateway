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
# claude_ancestor: `gate secret` refuses under any Claude Code ancestor
# (defence in depth for the no-screen path; the one-time code stays)
# ---------------------------------------------------------------------------

HOME = "/Users/u"
ME = os.geteuid()
VERSIONS_BIN = HOME + "/.local/share/claude/versions/2.1.301"
DESKTOP_BIN = (HOME + "/Library/Application Support/Claude/claude-code/2.1.299/4fa9694b7975/"
               "claude.app/Contents/MacOS/claude")


def _walk(rows, tail=1, claude_pid=None, home=HOME):
    """ancestry.claude_ancestor() over a faked process table: `rows` are
    (exe or None, uid, comm) from this process's parent upward; the last
    row's parent is `tail` (1: init, readable, root; 0: a parent that can't be
    read; "loop": back to the first row)."""
    base = os.getppid()
    pids = [base] + [910000 + k for k in range(1, len(rows))]
    table = {}
    for k, (exe, uid, comm) in enumerate(rows):
        parent = pids[k + 1] if k + 1 < len(rows) else (pids[0] if tail == "loop" else tail)
        table[pids[k]] = (parent, exe, uid, comm)
    table.setdefault(1, (0, "/sbin/launchd", 0, "launchd"))
    saved = (ancestry._exe_path, ancestry._ppid, ancestry._owner, os.environ.get("CLAUDE_PID"))
    ancestry._exe_path = lambda pid: table.get(pid, (0, None, None, ""))[1]
    ancestry._ppid = lambda pid: table.get(pid, (0, None, None, ""))[0]
    ancestry._owner = lambda pid: (table[pid][2], table[pid][3]) if pid in table else (None, "")
    if claude_pid is None:
        os.environ.pop("CLAUDE_PID", None)
    else:
        os.environ["CLAUDE_PID"] = str(pids[claude_pid])
    try:
        return ancestry.claude_ancestor(home)
    finally:
        ancestry._exe_path, ancestry._ppid, ancestry._owner = saved[:3]
        if saved[3] is None:
            os.environ.pop("CLAUDE_PID", None)
        else:
            os.environ["CLAUDE_PID"] = saved[3]


def test_claude_ancestor_finds_claude_code_anywhere_up_the_chain():
    term = [("/bin/zsh", ME, "zsh"), ("/usr/bin/login", 0, "login"),
            ("/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", ME, "Terminal")]
    assert _walk(term) is None, "the user's own terminal"
    # Claude Code by its binary: a native install (versions folder), the
    # desktop app's bundled copy, anything named claude; directly above or
    # several processes up (env -i, a script, a terminal multiplexer, sudo)
    for claude in ("/opt/homebrew/bin/claude", VERSIONS_BIN, DESKTOP_BIN,
                   HOME + "/Library/Application Support/Claude/claude-code/2.1.299/x/node"):
        assert _walk([("/bin/zsh", ME, "zsh"), (claude, ME, "claude")]) == claude, claude
        deep = [("/bin/sh", ME, "sh"), ("/usr/bin/env", ME, "env"), ("/opt/x/bin/python3", ME, "python3"),
                ("/opt/local/bin/tmux", ME, "tmux"), ("/usr/bin/sudo", 0, "sudo"),
                ("/opt/local/bin/bash", ME, "bash"), (claude, ME, "claude"),
                ("/Applications/Claude.app/Contents/MacOS/Claude", ME, "Claude")]
        assert _walk(deep) == claude, claude
    # CLAUDE_PID names an ancestor whatever its binary (an npm install runs node)
    assert _walk([("/bin/zsh", ME, "zsh"), ("/opt/x/bin/node", ME, "node")], claude_pid=1) == "CLAUDE_PID"
    # the desktop app itself (its Terminal panel's shells run under its helper) isn't Claude Code
    app = [("/bin/zsh", ME, "zsh"),
           ("/Applications/Claude.app/Contents/Frameworks/Claude Helper.app/Contents/MacOS/Claude Helper",
            ME, "Claude Helper"), ("/Applications/Claude.app/Contents/MacOS/Claude", ME, "Claude")]
    assert _walk(app) is None
    # the versions folder of another home isn't this user's Claude Code
    assert _walk([("/bin/zsh", ME, "zsh"), ("/Users/other/.local/share/claude/versions/2.1.301", ME,
                                            "2.1.301")]) is None


def test_claude_ancestor_refuses_a_chain_it_cant_read():
    unread = ancestry.UNREADABLE
    assert _walk([("/bin/zsh", ME, "zsh"), ("/opt/local/bin/tmux", ME, "tmux")], tail=0) == unread
    assert _walk([("/bin/zsh", ME, "zsh"), ("/opt/local/bin/tmux", ME, "tmux")], tail="loop") == unread
    # a process of the user's own whose executable can't be read
    assert _walk([("/bin/zsh", ME, "zsh"), (None, ME, "tmux")]) == unread
    assert _walk([("/bin/zsh", ME, "zsh"), (None, None, "")]) == unread
    # ... also with readable processes above it (review round 5: the walk
    # goes on, so Claude Code further up is named instead; the macOS case of
    # a login shell whose executable an upgrade replaced while it ran)
    term = [("/opt/local/bin/bash", ME, "bash"), (None, ME, "bash"), ("/usr/bin/login", 0, "login"),
            ("/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", ME, "Terminal")]
    assert _walk(term) == unread
    assert _walk([("/bin/zsh", ME, "zsh"), (None, ME, "tmux"), ("/bin/zsh", ME, "zsh"),
                  (VERSIONS_BIN, ME, "2.1.301")]) == VERSIONS_BIN
    assert _walk([("/bin/zsh", ME, "zsh"), (None, ME, "tmux"), ("/opt/x/bin/node", ME, "node")],
                 claude_pid=2) == "CLAUDE_PID"
    assert _walk([("/bin/zsh", ME, "zsh"), (None, ME, "tmux")], tail=0) == unread
    # ... named like sshd but not under a root sshd
    assert _walk([("/bin/bash", ME, "bash"), (None, ME, "sshd"), ("/opt/x/sshd", ME, "sshd")]) == unread
    # an unreadable process named claude is Claude Code
    assert _walk([("/bin/zsh", ME, "zsh"), (None, 0, "claude")]) == "claude"
    # too deep
    assert _walk([("/bin/sh", ME, "sh")] * (ancestry.MAX_DEPTH + 2)) == unread


def test_claude_ancestor_passes_linux_logins_it_can_only_partly_read():
    """Linux hides the executable of root's processes (sshd, login, sudo) and
    of OpenSSH's non-dumpable session process from the user: a login over
    ssh, the console's login and sudo stay usable, and the walk goes on above
    them (Claude Code runs as the user, so it is never one of them)."""
    ssh_login = [("/bin/bash", ME, "bash"), (None, ME, "sshd-session"), (None, 0, "sshd")]
    assert _walk(ssh_login) is None
    assert _walk([("/bin/bash", ME, "bash"), (None, ME, "sshd"), (None, 0, "sshd")]) is None
    assert _walk([("/bin/bash", ME, "bash"), (None, 0, "login")]) is None
    above = [("/bin/bash", ME, "bash"), (None, 0, "sudo"), ("/bin/zsh", ME, "zsh"),
             (VERSIONS_BIN, ME, "claude")]
    assert _walk(above) == VERSIONS_BIN, "sudo in between hides nothing above it"


def test_npms_claude_code_counts_as_claude_code_and_no_other_node_script():
    """GW-COMPAT-1: npm's @anthropic-ai/claude-code is Claude Code: its
    native binary (bin/claude.exe, since 2.1.113) by path, and before that
    node running its cli.js (npm's shim, <prefix>/bin/claude, links to it) by
    argv; node running anything else isn't."""
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as d:
        pre = Path(d) / "npm"
        pkg = pre / "lib" / "node_modules" / "@anthropic-ai" / "claude-code"
        pkg.mkdir(parents=True)
        (pkg / "cli.js").write_text("// cli\n")
        (pre / "bin").mkdir()
        (pre / "bin" / "claude").symlink_to(pkg / "cli.js")
        other = Path(d) / "other.js"
        other.write_text("// other\n")
        native = str(pkg / "bin" / "claude.exe")
        node = "/opt/x/bin/node"
        assert ancestry.is_claude_exe(native)
        assert ancestry.claude_install(native) == "npm (its native binary)"
        # a claude.exe anywhere else isn't (only npm's package folder names it so)
        for exe in (str(Path(d) / "bin" / "claude.exe"), str(pre / "node_modules" / "claude-code" / "bin" / "claude.exe")):
            assert not ancestry.is_claude_exe(exe) and ancestry.claude_install(exe) == "", exe
        for argv in ([node, str(pre / "bin" / "claude"), "--resume"], [node, str(pkg / "cli.js")],
                     ["/usr/bin/nodejs", str(pkg / "cli.js")]):
            assert ancestry.is_claude_node(argv[0], argv), argv
            assert ancestry.claude_install(argv[0], argv).startswith("npm (node"), argv
        for argv in ([node, str(other)], [node, "--require", str(pkg / "cli.js"), str(other)],
                     [node, "-r", str(pkg / "cli.js")], ["/opt/x/bin/python3", str(pkg / "cli.js")],
                     [node, "cli.js"], [node, str(pkg / "nope" / "cli.js")], [node], None):
            assert not ancestry.is_claude_node(argv[0] if argv else node, argv), argv
            assert ancestry.claude_install(argv[0] if argv else node, argv) == "", argv
        # the ancestor walk (gate secret's check) finds it too, by argv
        argvs = {}
        saved = ancestry._argv
        ancestry._argv = lambda pid: argvs.get(pid)
        try:
            argvs[910001] = [node, str(pre / "bin" / "claude")]
            assert _walk([("/bin/zsh", ME, "zsh"), (node, ME, "node")]) == node
            argvs[910001] = [node, str(other)]
            assert _walk([("/bin/zsh", ME, "zsh"), (node, ME, "node")]) is None
            assert _walk([("/bin/zsh", ME, "zsh"), (native, ME, "claude.exe")]) == native
        finally:
            ancestry._argv = saved
