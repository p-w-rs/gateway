"""Managed execution (PLAN-v4 phase 4, PLAN-0.11 §1.6/§1.8,
docs/dev/modules/managed.md): hooks/gate-sh (the CLAUDE_CODE_SHELL_PREFIX
the mod sets: bash 5 with the user's environment minus the removals, the
user's bash snapshot, the stand-ins unshadowable, the not-ready fallback to
the shell that made the snapshot), managed.py (its settings, rc, state and the host
inspection), the [shell] form section and its consent, the classic Bash
hook's once-per-session notice without the prefix, a gateway terminal's
environment, and the session context and `gate status` lines.

gate-sh is driven the way Claude Code 2.1.301 drives a prefix (recorded in
FEASIBILITY-v4 P2 and this phase's probes): `/bin/sh -c "'<prefix>'
'<string>'"` for a classic hook (and an MCP server's quoted argv), and
`<shell> -c "'<prefix>' '<script>'"` for a Bash-tool script of the shape
`source <snapshot> 2>/dev/null || true && <env-file text>\n: && ... && eval
'<command>' [< /dev/null] && pwd -P >| <cwd file>`."""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from pathlib import Path

import harness as H
from gateway import consent, envfile, managed, paths, testing, vault
from gateway import form as F

GATE_SH = H.PLUGIN / "hooks" / "gate-sh"
BASH = H.ENV_BIN / "bash"
SAFE_WORD = re.compile(r"[A-Za-z0-9@%+=:,./_-]+")


def sq(s: str) -> str:
    """Claude Code's quoting of a word (its go()): '...' with '"'"' for a quote."""
    return "'" + s.replace("'", "'\"'\"'") + "'"


def word(s: str) -> str:
    return s if SAFE_WORD.fullmatch(s) else sq(s)


def tool_script(cmd: str, *, snap: str | None, cwdfile: str, envfile_text: str = "",
                heredoc: bool = False) -> str:
    """A Bash-tool script as Claude Code 2.1.301 builds it with a prefix set."""
    parts = []
    if snap is not None:
        parts.append(f"source {word(snap)} 2>/dev/null || true")
    if envfile_text:
        parts.append(envfile_text + "\n:")
    parts.append("{ shopt -u extglob || setopt NO_EXTENDED_GLOB NO_BARE_GLOB_QUAL; } "
                 ">/dev/null 2>&1 || true")
    parts.append("{ \\builtin unalias -- 'unsetenv'; \\builtin unset -f -- 'unsetenv'; } "
                 ">/dev/null 2>&1 || true")
    parts.append(f"eval {sq(cmd)}" + ("" if heredoc else " < /dev/null"))
    parts.append(f"pwd -P >| {word(cwdfile)}")
    return " && ".join(parts)


def through_prefix(script: str, env: dict, cwd: Path, *, launcher: str = "/bin/sh",
                   stdin: str = "", prefix: Path = GATE_SH, timeout: float = 30
                   ) -> subprocess.CompletedProcess[str]:
    """`<launcher> -c "'<prefix>' '<script>'"`, as Claude Code starts it."""
    return subprocess.run([launcher, "-c", f"{sq(str(prefix))} {sq(script)}"], input=stdin,
                          capture_output=True, text=True, env=env, cwd=str(cwd),
                          timeout=timeout)


def base_env(extra: dict | None = None) -> dict:
    """Claude Code's environment; SHELL is the test env's bash, so a not-ready
    fallback never depends on the host's shells (Debian's /bin/sh is dash)."""
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/nonexistent-home",
           "USER": "tester", "LOGNAME": "tester", "LANG": "C.UTF-8", "TERM": "xterm",
           "SHELL": str(BASH), "CLAUDE_CODE_SHELL_PREFIX": str(GATE_SH)}
    env.update(extra or {})
    return env


def ran_without(shell: str | Path) -> str:
    """The start of the not-ready notice (PLAN-0.11 §19.15)."""
    return f"gateway: this command ran without the gateway's managed settings, in {shell}: " \
           "the managed shell isn't ready ("


# ---------------------------------------------------------------------------
# A managed-shell world: a gateway env whose managed bash is the test env's
# own bash (the gateway's pixi env has bash 5 since phase 4)
# ---------------------------------------------------------------------------


class World:
    def __init__(self, env: H.GatewayEnv):
        self.env = env
        self.work = env.root / "work dir é"
        self.work.mkdir(parents=True, exist_ok=True)
        self.tmp = env.root / "cctmp"
        self.tmp.mkdir(exist_ok=True)
        cfg = env.root / "claude cfg"
        self.snapdir = cfg / "shell-snapshots"
        self.snapdir.mkdir(parents=True, exist_ok=True)
        # the managed bash where managed.env_bash() finds it, in this data folder
        # (only bash: no python3, so no env counts as ready)
        eb = paths.env_bin()
        eb.mkdir(parents=True, exist_ok=True)
        (eb / "bash").unlink(missing_ok=True)
        os.symlink(BASH, eb / "bash")
        self.marker = env.root / "snapshot-was-sourced"
        paths.bin_dir().mkdir(parents=True, exist_ok=True)   # the stand-ins (SessionStart writes them)

    def snapshot(self, shell: str = "bash", path_line: str | None = None) -> Path:
        p = self.snapdir / f"snapshot-{shell}-1792496386116-rhykrx.sh"
        lines = ["# Snapshot file", "unalias -a 2>/dev/null || true",
                 f": > {sq(str(self.marker))}",
                 "userfunc () { echo user-function; }",
                 "alias ll='ls -l'", "shopt -s expand_aliases 2>/dev/null || :",
                 "alias userls='echo user-alias-ran'", "export SNAPVAR=from-the-snapshot",
                 path_line if path_line is not None else
                 "export PATH=/opt/user/bin:/usr/local/bin:/usr/bin:/bin"]
        p.write_text("\n".join(lines) + "\n")
        return p

    def sync(self) -> None:
        form, eff, data = self.load()
        r = managed.sync(form, eff)
        assert r["errors"] == [], r

    def load(self):
        data = vault.load() if vault.exists() else None
        form = consent.load_form(data)
        return form, consent.compute(form, data), data

    def launch_env(self, extra: dict | None = None) -> dict:
        return base_env({"GW_MANAGED_DIR": str(managed.managed_dir()), "TMPDIR": str(self.tmp),
                         **(extra or {})})

    def run(self, cmd: str, *, snap: Path | None = None, extra: dict | None = None,
            heredoc: bool = False, envfile_text: str = "", launcher: str = "/bin/sh",
            stdin: str = "") -> tuple[subprocess.CompletedProcess[str], Path]:
        cwdfile = self.tmp / f"claude-{os.urandom(2).hex()}-cwd"
        script = tool_script(cmd, snap=str(snap) if snap else None, cwdfile=str(cwdfile),
                             envfile_text=envfile_text, heredoc=heredoc)
        r = through_prefix(script, self.launch_env(extra), self.work, launcher=launcher,
                           stdin=stdin)
        return r, cwdfile


def world():
    @contextlib.contextmanager
    def cm():
        with H.gateway_env(entry=None, pixi="") as env:
            env.o.entry = H.entry_cmd(env)
            w = World(env)
            w.sync()
            yield w
    return cm()


# ---------------------------------------------------------------------------
# gate-sh: hook strings run exactly as without a prefix
# ---------------------------------------------------------------------------

HOOK_CASES = [
    'printf "%s|" "$0" "$#"; echo',
    "env | LC_ALL=C sort",
    'cat; echo "[$?]"',
    "echo out; echo err >&2; exit 3",
    'n=$(date +%s); { echo "ZERO=$0"; env | LC_ALL=C sort; } ',
    "'printf' '%s\\n' 'an mcp' 'argv'",                 # an MCP server's quoted argv
    "pwd -P > /dev/null && echo tracker-like-but-a-hook",
    "echo \"$SHLVL\"",
    'set -- a b; echo "$@"; trap "echo trapped" EXIT',
    "",
    # hooks that only mention a snapshot or hold the tracker's text (verifier,
    # phase 4 review): /bin/sh -c, not refused as broken tool scripts
    'find "$HOME/.claude/shell-snapshots/snapshot-"* -mtime +7 2>/dev/null; echo cleaned',
    "cd /tmp && pwd -P >| /dev/null; echo ok",
    "echo '{\"a\": 1}' # cleans /shell-snapshots/snapshot-x",
    "eval 'echo evaluated' && pwd -P >| /dev/null",                 # an eval, no -cwd tracker
    "eval 'echo evaluated' && pwd -P >| /dev/null; echo not-a-tracker-cwd",
    "echo no-eval && pwd -P >| ./a-hook-tracker-cwd",                 # a tracker, no eval
    "echo x; source /tmp/shell-snapshots/snapshot-bash-1.sh 2>/dev/null; echo y",
]


def test_hook_strings_run_exactly_as_claude_code_runs_them_without_a_prefix():
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as td:
        cwd = Path(td)
        for shlvl in (None, "0", "1", "3"):
            for extra in ({}, {"GW_MANAGED_DIR": "/nowhere"}, {"SOME_TOKEN": "x"}):
                env = base_env(extra)
                if shlvl is not None:
                    env["SHLVL"] = shlvl
                for hook in HOOK_CASES:
                    plain = subprocess.run(["/bin/sh", "-c", hook], input="from stdin\n",
                                           capture_output=True, text=True, env=env, cwd=td)
                    via = through_prefix(hook, env, cwd, stdin="from stdin\n")
                    assert (via.stdout, via.stderr, via.returncode) == \
                        (plain.stdout, plain.stderr, plain.returncode), (hook, shlvl, extra, plain, via)


def test_a_hook_that_writes_its_environment_and_dollar_zero_sees_the_same_with_gate_sh():
    """The probe plugin's hook (writes env and $0 to a file), plain vs through
    gate-sh, with Claude Code's hook variables."""
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as td:
        out = Path(td)
        hook = '{ echo "ZERO=$0"; env | LC_ALL=C sort; } > "$PROBE_OUT"'
        envs = []
        for via in (False, True):
            f = out / f"env-{via}.txt"
            env = base_env({"PROBE_OUT": str(f), "CLAUDE_PLUGIN_ROOT": "/p", "CLAUDE_PROJECT_DIR": td,
                            "CLAUDE_ENV_FILE": f"{td}/sessionstart-hook-0.sh"})
            if via:
                r = through_prefix(hook, env, out)
            else:
                r = subprocess.run(["/bin/sh", "-c", hook], capture_output=True, text=True,
                                   env=env, cwd=td)
            assert r.returncode == 0, r
            envs.append(f.read_text().replace(str(f), "OUT"))
        assert envs[0] == envs[1], envs
        assert "ZERO=/bin/sh" in envs[1]


def test_hook_strings_need_no_managed_settings_and_never_read_them():
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as td:
        for extra in ({}, {"GW_MANAGED_DIR": "relative"}, {"GW_MANAGED_DIR": td + "/missing"}):
            r = through_prefix("echo hook-ran", base_env(extra), Path(td))
            assert r.returncode == 0 and r.stdout == "hook-ran\n" and r.stderr == "", r


def test_gate_sh_takes_exactly_one_argument():
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as td:
        for args in ([], ["a", "b"]):
            r = subprocess.run([str(GATE_SH), *args], capture_output=True, text=True,
                               env=base_env(), cwd=td)
            assert r.returncode == 126 and "instead of one" in r.stderr, r


def test_gate_sh_is_posix_and_names_what_managed_py_names():
    text = GATE_SH.read_text()
    assert text.startswith("#!/bin/sh\n")
    assert os.access(GATE_SH, os.X_OK)
    for sh in ("/bin/sh", shutil.which("dash")):
        if sh:
            r = subprocess.run([sh, "-n", str(GATE_SH)], capture_output=True, text=True)
            assert r.returncode == 0, (sh, r.stderr)
    # the removals (PLAN-0.11 §1.6): the fixed names, the credential words a
    # CLAUDE_* or ANTHROPIC_* name is dropped for, the prefixes, the GW_* kept
    fixed = re.search(r"^GW_FIXED_DROP=' ([^']*) '$", text, re.M).group(1).split()
    assert fixed == list(managed.CLAUDE_CRED_NAMES) + list(managed.STARTUP_NAMES), fixed
    assert managed.CLAUDE_CRED_NAMES == envfile.CLAUDE_CRED_NAMES
    cred = re.search(r"gw_credlike\(\) \{\n  case \$1 in\n  (.*?)\) return 0", text, re.S).group(1)
    words = [w_.strip().strip("*") for w_ in cred.split("|")]
    assert words == list(managed.CREDENTIAL_WORDS), words
    assert "  GW_MANAGED_DIR) continue ;;\n" in text and managed.GATEWAY_NAMES == ("GW_MANAGED_DIR",)
    assert "  GW_* | BASH_FUNC_* | *[!A-Za-z0-9_]* | [0-9]*) ;;" in text
    assert managed.DROP_PREFIXES == ("GW_", "BASH_FUNC_")
    assert "  CLAUDE_* | ANTHROPIC_*) gw_credlike \"$_n\" ||" in text
    # import_env refuses every name gate-sh would drop as credential-looking
    for w_ in managed.CREDENTIAL_WORDS:
        assert F.CREDENTIAL_NAME.fullmatch(f"MY_{w_}_X") and managed.credential_like(f"MY_{w_}_X"), w_
    # the rule in Python, name by name
    for n, gone in (("CLAUDE_CODE_OAUTH_TOKEN", True), ("CLAUDE_X_SECRET", True),
                    ("ANTHROPIC_AUTH_TOKEN", True), ("BASH_ENV", True), ("BASH_FUNC_ssh%%", True),
                    ("GW_PASSTHRU", True), ("WEIRD-NAME", True), ("1X", True), ("IFS", True),
                    ("GW_MANAGED_DIR", False), ("CLAUDE_CODE_SESSION_ID", False),
                    ("GH_TOKEN", False), ("SSH_AUTH_SOCK", False), ("AWS_SECRET_ACCESS_KEY", False),
                    ("HTTPS_PROXY", False), ("JAVA_HOME", False), ("A NAME", False)):
        assert managed.dropped(n) is gone, n


# ---------------------------------------------------------------------------


def test_tool_scripts_run_in_the_managed_bash_with_the_gateway_rc_and_a_bash_snapshot():
    """PLAN-0.11 §1.6: the snapshot's `source` is replaced by the gateway rc,
    which sources a bash snapshot (the user's aliases, functions, options
    and exports) and then puts the managed PATH back; a zsh snapshot (one
    made before the prefix applied) gives only its PATH line."""
    with world() as w:
        # launchers: Claude Code starts the prefix from the user's shell (bash or zsh) or,
        # once the env is built, from the managed bash (CLAUDE_CODE_SHELL)
        launchers = [("bash", "/bin/sh"), ("bash", str(BASH))]
        launchers += [(sh, f"/bin/{sh}") for sh in ("bash", "zsh") if os.path.exists(f"/bin/{sh}")]
        want = ":".join([str(paths.bin_dir()), "/opt/user/bin", "/usr/local/bin", "/usr/bin", "/bin"])
        for shell, launcher in launchers:
            snap = w.snapshot(shell)
            w.marker.unlink(missing_ok=True)
            r, cwdfile = w.run('echo "B=$BASH_VERSION Z=${ZSH_VERSION-} S=${SNAPVAR-} E=${ENVFILEVAR-}"; '
                               'echo "T=$(type -t userfunc) A=$(alias ll 2>/dev/null) K=$(type -t pkill)"; '
                               'echo "PATH=$PATH"; echo "SHELL=$SHELL"; echo "U=$(userls 2>/dev/null)"; '
                               'cd /; echo moved',
                               snap=snap, envfile_text="export ENVFILEVAR=from-an-env-file",
                               launcher=launcher)
            assert r.returncode == 0, r
            lines = r.stdout.splitlines()
            mine = shell == "bash"
            assert lines[0].startswith("B=5.") and lines[0].endswith(
                " Z= S=" + ("from-the-snapshot" if mine else "") + " E=from-an-env-file"), lines
            # K: the gateway rc ran (Claude Code's pkill guard is its function)
            assert lines[1] == ("T=function A=alias ll='ls -l' K=function" if mine
                                else "T= A= K=function"), (shell, lines)
            assert lines[2] == f"PATH={want}", lines              # the snapshot's PATH, stand-ins first
            assert lines[3] == f"SHELL={paths.env_bin() / 'bash'}", lines
            # the user's aliases expand in the command (leaving the tail's POSIX
            # mode turns expansion off; the rc turns it back on)
            assert lines[4] == ("U=user-alias-ran" if mine else "U="), lines
            assert w.marker.exists() is mine, "only a bash snapshot is sourced"
            assert cwdfile.read_text().strip() == "/", "the cwd tracker ran (pwd -P after cd)"


# the names the rc's tail must take back from the user's snapshot (PLAN-0.11
# §1.6): every stand-in present, and the builtins the tail itself relies on
HOSTILE_NAMES = ("ssh", "sudo", "gh", "command", "builtin", "hash", "type", "unalias", "unset",
                 "trap", "readonly", "exec", "source", "test")


def test_the_users_aliases_and_functions_never_shadow_a_present_stand_in():
    """A snapshot (or the environment) defining aliases and functions named
    after the stand-ins and after the builtins the tail uses, plus BASH_ENV,
    ENV and an exported BASH_FUNC_ssh%%: ssh, sudo and gh still resolve to
    and run the stand-ins; a name with no stand-in present keeps the user's
    own function (the user's environment is theirs)."""
    with world() as w:
        b = paths.bin_dir()
        for n in ("ssh", "sudo", "gh"):
            (b / n).write_text(f'#!/bin/sh\necho "standin-{n} $*"\n')
            os.chmod(b / n, 0o755)
        hostile = w.env.root / "hostile-ran"
        mark = f": > {sq(str(hostile))}"
        lines = ["shopt -s expand_aliases", f"_gw_hostile={sq(str(hostile))}"]
        for n in HOSTILE_NAMES:
            lines.append(f"function {n} {{ {mark}; echo hijacked-function-{n}; }}")
        for n in HOSTILE_NAMES:
            lines.append(f"alias {n}=': > \"$_gw_hostile\"; echo hijacked-alias-{n}'")
        lines += ["scp () { echo user-scp; }", "export PATH=/usr/bin:/bin",
                  "echo snapshot-complete > \"$_gw_hostile.done\""]
        snap = w.snapdir / "snapshot-bash-1792496386117-hostil.sh"
        snap.write_text("\n".join(lines) + "\n")
        startup = w.env.root / "startup.sh"
        startup.write_text(mark + "\n")
        extra = {"BASH_ENV": str(startup), "ENV": str(startup),
                 "BASH_FUNC_ssh%%": "() { " + mark + "; echo hijacked-exported; }"}
        r, _ = w.run('echo "T=$(type -t ssh) $(type -t sudo) $(type -t gh) C=$(command -v ssh)"; '
                     "ssh box ls; sudo id; gh api user; scp a b; "
                     'for n in command builtin hash type unalias unset trap readonly exec source test; do '
                     'printf "%s " "$(type -t $n)"; done; echo', snap=snap, extra=extra)
        assert r.returncode == 0, r
        out = r.stdout.splitlines()
        assert out[0] == f"T=file file file C={b / 'ssh'}", out
        assert out[1:5] == ["standin-ssh box ls", "standin-sudo id", "standin-gh api user",
                            "user-scp"], out
        assert out[5].split() == ["builtin"] * 11, out
        assert "hijacked" not in r.stdout and not hostile.exists(), r.stdout
        assert Path(str(hostile) + ".done").exists(), "the whole hostile snapshot was sourced"
        # a command that turns alias expansion back on (leaving POSIX mode turned
        # it off) still finds no stand-in alias
        r, _ = w.run('shopt -s expand_aliases\necho "T=$(type -t ssh)"\nssh box ls', snap=snap,
                     extra=extra)
        assert r.returncode == 0 and r.stdout.splitlines() == ["T=file", "standin-ssh box ls"], r
        assert not hostile.exists()


def test_the_rc_clears_the_snapshots_traps_and_fails_closed_on_what_it_cant_remove():
    """Review should-fix 10: a snapshot's DEBUG, RETURN and ERR traps (they
    run before each command, when a sourced file returns, after a failure)
    are cleared, so one that defines ssh again can't shadow the stand-in; a
    read-only function named after a present stand-in or after a builtin
    the tail uses, and a read-only POSIXLY_CORRECT, stop the command instead
    of running it; a read-only function with no stand-in present stays the
    user's own."""
    with world() as w:
        b = paths.bin_dir()
        (b / "ssh").write_text('#!/bin/sh\necho "standin-ssh $*"\n')
        os.chmod(b / "ssh", 0o755)
        done = w.env.root / "ran"

        def snap(*lines: str) -> Path:
            p = w.snapdir / f"snapshot-bash-1792496386118-{os.urandom(3).hex()}.sh"
            p.write_text("\n".join(lines) + "\n")
            return p
        s = snap("trap 'ssh() { echo hijack-debug; }' DEBUG",
                 "trap 'ssh() { echo hijack-return; }' RETURN",
                 "trap 'ssh() { echo hijack-err; }' ERR")
        r, _ = w.run('ssh box ls; echo "T=$(type -t ssh) P=$(trap -p DEBUG RETURN ERR)"', snap=s)
        assert r.returncode == 0 and r.stdout.splitlines() == ["standin-ssh box ls", "T=file P="], r
        refused = [
            (snap("ssh() { echo hijack; }", "readonly -f ssh"), "makes a function read-only"),
            (snap("test() { return 1; }", "readonly -f test"), "makes a function read-only"),
            (snap("readonly() { return 1; }", "builtin readonly -f readonly"),
             "makes a function read-only"),
            (snap("readonly POSIXLY_CORRECT"), "could not enter POSIX mode"),
        ]
        for s, why in refused:
            r, _ = w.run(f": > {sq(str(done))}; ssh box ls", snap=s)
            assert r.returncode != 0 and not done.exists(), (why, r)
            assert why in r.stderr and "the command was not run" in r.stderr, (why, r.stderr)
            assert "hijack" not in r.stdout and "standin" not in r.stdout, r
        r, _ = w.run("scp a b", snap=snap("scp() { echo user-scp; }", "readonly -f scp"))
        assert r.returncode == 0 and r.stdout == "user-scp\n", r


def test_tool_script_forms_pipe_heredoc_multiline_and_exit_status():
    with world() as w:
        snap = w.snapshot()
        r, _ = w.run("printf 'a\\nb\\n' | wc -l | tr -d ' '", snap=snap)
        assert (r.returncode, r.stdout) == (0, "2\n"), r
        r, _ = w.run("cat <<'EOF'\nhello heredoc\nEOF", snap=snap, heredoc=True)
        assert (r.returncode, r.stdout) == (0, "hello heredoc\n"), r
        r, _ = w.run("echo 'line1\nline2'", snap=snap)
        assert r.stdout == "line1\nline2\n", r
        r, cwdfile = w.run("echo before; exit 7", snap=snap)
        assert (r.returncode, r.stdout) == (7, "before\n"), r
        assert not cwdfile.exists(), "a failed command doesn't reach the tracker (as without a prefix)"
        r, _ = w.run("echo $(( 6 * 7 )) [[ ok ]] && [[ -n x ]] && echo bashism-ok", snap=snap)
        assert "42" in r.stdout and "bashism-ok" in r.stdout, r
        r, _ = w.run("read x; echo \"[${x-}]\"", snap=snap, stdin="not for the command\n")
        assert r.stdout == "[]\n", "the command's stdin is /dev/null, as without a prefix"
        # without a snapshot (Claude Code couldn't make one): the same, rc first,
        # the inherited PATH after the stand-ins
        r, _ = w.run('echo "K=$(type -t pkill) P=$PATH"', snap=None)
        assert r.returncode == 0 and r.stdout.strip() == \
            f"K=function P={paths.bin_dir()}:/usr/bin:/bin:/usr/sbin:/sbin", r


def test_the_environment_is_the_users_minus_the_removals():
    """PLAN-0.11 §1.6: the command gets the inherited environment (Claude
    Code's, the user's) minus, by name, Claude Code's own credentials, the
    variables that make a shell run code or change its parsing, and the
    gateway's GW_* names but GW_MANAGED_DIR; managed.dropped() is the same
    rule (compared name by name)."""
    with world() as w:
        snap = w.snapshot()
        ran = w.env.root / "startup-ran"
        bash_env = w.env.root / "bash-env.sh"
        bash_env.write_text(f": > {sq(str(ran))}\n")
        host = {
            "PATH": "/opt/user/bin:/usr/local/bin:/usr/bin:/bin", "HOME": "/home/x", "USER": "x",
            "LOGNAME": "x", "LANG": "en_US.UTF-8", "LC_ALL": "C.UTF-8", "TERM": "xterm-256color",
            "TZ": "UTC", "CLAUDECODE": "1", "CLAUDE_PID": "123", "CLAUDE_CODE_SESSION_ID": "s-1",
            "CLAUDE_CODE_ENTRYPOINT": "cli", "AI_AGENT": "claude-code",
            # the user's own: kept
            "SSH_AUTH_SOCK": "/tmp/agent", "SSH_AGENT_PID": "77", "GH_TOKEN": "gho_user",
            "HF_TOKEN": "hf_user", "GITHUB_TOKEN": "ghp", "AWS_SECRET_ACCESS_KEY": "aws",
            "HTTPS_PROXY": "http://u:p@proxy:1", "MY_SETTING": "1", "JAVA_HOME": "/jdk",
            "PYTHONPATH": "/py",
            # Claude Code's own credentials: removed
            "CLAUDE_CODE_OAUTH_TOKEN": "tok", "CLAUDE_CODE_MESSAGING_TOKEN": "tok2",
            "CLAUDE_CODE_CLIENT_CERT": "/c.pem", "ANTHROPIC_API_KEY": "sk",
            "ANTHROPIC_AUTH_TOKEN": "at", "CLAUDE_SOME_NEW_SECRET": "x",
            # what makes a shell run code or changes its parsing: removed
            "BASH_ENV": str(bash_env), "ENV": str(bash_env), "PROMPT_COMMAND": "echo pc",
            "BASHOPTS": "xpg_echo", "PS4": "+TRACE ", "CDPATH": "/", "IFS": "x",
            "GLOBIGNORE": "*", "BASH_XTRACEFD": "2",
            # the gateway's own: removed (GW_MANAGED_DIR, from launch_env, kept)
            "GW_PASSTHRU": "ssh:1:abc", "GW_TERMINAL": "t_x",
            # names no shell variable can have: removed
            "WEIRD-NAME": "x", "BASH_FUNC_userfn%%": "() { echo hijacked; }",
        }
        r, _ = w.run("env | sed 's/=.*//' | LC_ALL=C sort; type -t userfn; echo done", snap=snap,
                     extra=host)
        assert r.returncode == 0, r
        out = r.stdout.splitlines()
        assert out[-1] == "done" and "hijacked" not in r.stdout, out
        names = set(out[:-1])
        given = w.launch_env(host)
        wrong = [n for n in given if n != "PATH" and (n in names) is managed.dropped(n)]
        assert not wrong, wrong
        # (the gateway rc, the env file's text, sets no git variable: PLAN-0.11 §6)
        set_here = {"PATH", "PWD", "SHLVL", "_", "SHELL", "OLDPWD", "SNAPVAR"}
        assert names - set(given) <= set_here, names - set(given)
        for n in ("CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_CLIENT_CERT", "ANTHROPIC_API_KEY",
                  "CLAUDE_SOME_NEW_SECRET", "BASH_ENV", "ENV", "PS4", "IFS", "GW_PASSTHRU",
                  "WEIRD-NAME", "BASH_FUNC_userfn%%"):
            assert n not in names, n
        for n in ("SSH_AUTH_SOCK", "SSH_AGENT_PID", "GH_TOKEN", "HF_TOKEN", "GITHUB_TOKEN",
                  "AWS_SECRET_ACCESS_KEY", "HTTPS_PROXY", "MY_SETTING", "JAVA_HOME", "PYTHONPATH",
                  "GW_MANAGED_DIR", "CLAUDECODE", "CLAUDE_CODE_SESSION_ID"):
            assert n in names, n
        assert not ran.exists(), "BASH_ENV/ENV ran"
        # the values reach the command unchanged
        r, _ = w.run('echo "$SSH_AUTH_SOCK $GH_TOKEN $HTTPS_PROXY $JAVA_HOME"', snap=snap, extra=host)
        assert r.stdout == "/tmp/agent gho_user http://u:p@proxy:1 /jdk\n", r


# Claude Code 2.1.301's own credential variables (its MCP credential lists,
# next to AZURE_PASSWORD in the binary), the CLAUDE_* ones first: CLAUDE_*
# passes the curated environment, so the credential words must catch these.
CC_CREDENTIAL_NAMES = (
    "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_OAUTH_REFRESH_TOKEN", "CLAUDE_CODE_ARTIFACTS_API_TOKEN",
    "CLAUDE_CODE_MEMORY_API_TOKEN", "CLAUDE_CODE_SLACK_TAG_TOKEN", "CLAUDE_SESSION_INGRESS_TOKEN_FILE",
    "CLAUDE_CODE_HOST_CREDS_FILE", "CLAUDE_CODE_MESSAGING_TOKEN", "CLAUDE_CODE_CLIENT_KEY_PASSPHRASE",
    "CLAUDE_CODE_CLIENT_KEY", "CLAUDE_CODE_CLIENT_CERT", "CLAUDE_API_KEY", "CLAUDE_BRIDGE_OAUTH_TOKEN",
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "MCP_CLIENT_SECRET", "AZURE_CLIENT_CERTIFICATE_PASSWORD",
    "AZURE_PASSWORD", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS",
    "HTTPS_PROXY", "NPM_TOKEN", "TWINE_PASSWORD", "VAULT_CLIENT_KEY", "GIT_SSL_KEY", "SSH_SIGNING_KEY",
)


def test_claude_codes_own_credential_variables_never_reach_the_command():
    """Every CLAUDE_* or ANTHROPIC_* name holding a credential word, and the
    fixed list, is removed: Claude Code's, not the user's (PLAN-0.11 §1.6;
    CLAUDE_CODE_CLIENT_KEY_PASSPHRASE passed before PASSPHRASE was a word).
    The same kinds of names outside those prefixes are the user's own and
    reach the command."""
    with world() as w:
        snap = w.snapshot()
        canary = "cc-" + os.urandom(16).hex()
        theirs = tuple(n for n in CC_CREDENTIAL_NAMES if n.startswith(("CLAUDE_", "ANTHROPIC_")))
        users = tuple(n for n in CC_CREDENTIAL_NAMES if n not in theirs)
        # each credential word on its own, in a CLAUDE_* and an ANTHROPIC_* name
        probes = tuple(f"{p_}_GW_{w_}_PROBE" for p_ in ("CLAUDE", "ANTHROPIC")
                       for w_ in managed.CREDENTIAL_WORDS)
        gone = theirs + probes + managed.CLAUDE_CRED_NAMES
        host = {n: f"{canary}-{i}" for i, n in enumerate(gone)}
        host.update({n: f"user-{i}" for i, n in enumerate(users)})
        host["CLAUDE_CODE_SESSION_ID"] = "s-1"       # an ordinary CLAUDE_* name still passes
        r, _ = w.run("env", snap=snap, extra=host)
        assert r.returncode == 0, r.returncode
        names = {ln.split("=", 1)[0] for ln in r.stdout.splitlines() if "=" in ln}
        assert "CLAUDE_CODE_SESSION_ID" in names
        leaked = sorted(n for n in gone if n in names)
        assert not leaked and canary not in r.stdout, leaked
        assert [n for n in users if n not in names] == [], "the user's own variables are kept"
        for n in gone:
            assert managed.dropped(n), n


def _argv_recorder(w: World) -> tuple[Path, Path]:
    """A copy of gate-sh whose env records its arguments, then runs as before."""
    rec = w.env.root / "env-argv"
    fake = w.env.root / "recording-env"
    fake.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" >> {sq(str(rec))}\nexec /usr/bin/env \"$@\"\n")
    os.chmod(fake, 0o755)
    text = GATE_SH.read_text()
    assert text.count("exec /usr/bin/env ") == 2          # the managed bash, the not-ready fallback
    copy = w.env.root / "gate-sh-recording"
    copy.write_text(text.replace("exec /usr/bin/env ", f"exec {sq(str(fake))} "))
    os.chmod(copy, 0o755)
    return copy, rec


def test_no_value_reaches_a_command_line():
    """Every local user can read a process's arguments (ps, /proc/PID/cmdline);
    only the owner its environment. gate-sh once passed variables as
    NAME=VALUE arguments to env -i (verifier, phase 4 review: a canary
    GITHUB_TOKEN seen in /usr/bin/env's /proc cmdline on Debian). Only names
    reach env's arguments: the removals as `-u NAME`, then PATH= and SHELL=;
    the values reach the command through its environment. The not-ready
    fallback too."""
    with world() as w:
        snap = w.snapshot()
        canary = os.urandom(16).hex()
        vals = {"GITHUB_TOKEN": f"ghp_{canary}a", "JAVA_HOME": f"/jdk-{canary}b",
                "CLAUDE_CODE_SESSION_ID": f"s-{canary}c", "TZ": f"tz{canary}d",
                "SSH_AUTH_SOCK": f"/tmp/agent-{canary}e"}
        gone = {"CLAUDE_CODE_OAUTH_TOKEN": f"oat-{canary}f", "GW_SOMETHING": f"gw-{canary}g",
                "BASH_ENV": f"/nowhere/{canary}h"}
        show = "; ".join(f'echo "{n}=${{{n}-}}"' for n in list(vals) + list(gone))
        copy, rec = _argv_recorder(w)
        cwdfile = w.tmp / "claude-ab12-cwd"
        script = tool_script(show, snap=str(snap), cwdfile=str(cwdfile))
        env = w.launch_env({**vals, **gone, "MY_OTHER_VAR": "x"})
        r = through_prefix(script, env, w.work, prefix=copy)
        assert r.returncode == 0, r.returncode
        got = dict(ln.split("=", 1) for ln in r.stdout.splitlines() if "=" in ln)
        assert [n for n in vals if got.get(n) != vals[n]] == [], "a value didn't reach the command"
        assert all(got.get(n) == "" for n in gone), got
        argv = rec.read_text()
        assert canary not in argv, [n for n, v in {**vals, **gone}.items() if v in argv]
        # env's own arguments: `-u NAME` pairs, then only PATH= and SHELL=, then the managed bash
        args = argv.split("\n")
        opts = args[:args.index(str(paths.env_bin() / "bash"))]
        sets = [a for a in opts if "=" in a]
        assert [a.split("=", 1)[0] for a in sets] == ["PATH", "SHELL"], [a.split("=", 1)[0] for a in sets]
        rest = [a for a in opts if "=" not in a]
        assert rest[0::2] == ["-u"] * len(rest[0::2]) and set(gone) <= set(rest[1::2]) \
            and not set(vals) & set(rest[1::2]) and "MY_OTHER_VAR" not in rest[1::2], rest
        # the not-ready fallback: the same removals, names only
        rec.unlink()
        managed.conf_path().unlink()
        r = through_prefix(script, env, w.work, prefix=copy)
        assert r.returncode == 0 and ran_without(BASH) in r.stderr, r
        got = dict(ln.split("=", 1) for ln in r.stdout.splitlines() if "=" in ln)
        assert [n for n in vals if got.get(n) != vals[n]] == [] and \
            all(got.get(n) == "" for n in gone), got
        argv = rec.read_text()
        assert canary not in argv and set(gone) <= set(argv.split("\n")), argv
        w.sync()
        # Linux: the real gate-sh while another thread reads every /proc/*/cmdline
        if Path("/proc/self/cmdline").exists():
            import threading
            seen: set[str] = set()
            stop = threading.Event()

            def scan() -> None:
                needle = canary.encode()
                while not stop.is_set():
                    for pid in os.listdir("/proc"):
                        if pid.isdigit():
                            try:
                                b = Path(f"/proc/{pid}/cmdline").read_bytes()
                            except OSError:
                                continue
                            if needle in b:
                                seen.add(b.split(b"\0")[0].decode(errors="replace"))
            th = threading.Thread(target=scan, daemon=True)
            th.start()
            try:
                for _ in range(40):
                    r = through_prefix(script, w.launch_env({**vals, **gone}), w.work)
                    assert r.returncode == 0, r.returncode
            finally:
                stop.set()
                th.join(timeout=10)
            assert not seen, sorted(seen)


def test_a_claude_code_started_from_a_managed_command_stays_managed():
    """A `claude -p`, an Agent SDK script or a scratch-config Claude Code run
    through Bash inherits CLAUDE_CODE_SHELL_PREFIX and CLAUDE_CODE_SHELL from
    the command's environment and runs its own commands through gate-sh again
    (verifier, phase 4 review: without GW_MANAGED_DIR every one of them failed
    with 75). GW_MANAGED_DIR passes, so they run managed too; without it
    (a prefix set by hand) the command runs without the managed settings in
    the user's shell, with the notice (PLAN-0.11 §1.6, §19.15)."""
    with world() as w:
        snap = w.snapshot()
        canary = "cc-" + os.urandom(16).hex()
        inner = tool_script('echo "inner P=${PATH%%:*} S=${SNAPVAR-} M=${GW_MANAGED_DIR-}"; env',
                            snap=str(snap), cwdfile=str(w.tmp / "claude-1nnr-cwd"))
        f = w.env.root / "inner-script"
        f.write_text(sq(inner))
        # what the nested Claude Code does: <its shell> -c "'<its prefix>' '<script>'"
        outer = f'"$CLAUDE_CODE_SHELL" -c "\'$CLAUDE_CODE_SHELL_PREFIX\' $(cat {sq(str(f))})"'
        r, _ = w.run(outer, snap=snap, extra={"CLAUDE_CODE_SHELL": str(BASH),
                                              "CLAUDE_CODE_OAUTH_TOKEN": canary})
        assert r.returncode == 0 and "isn't ready" not in r.stderr, (r.returncode, r.stderr)
        lines = r.stdout.splitlines()
        assert lines[0] == f"inner P={paths.bin_dir()} S=from-the-snapshot M={managed.managed_dir()}", \
            lines[0]
        names = {ln.split("=", 1)[0] for ln in lines[1:] if "=" in ln}
        assert {"CLAUDE_CODE_SHELL_PREFIX", "CLAUDE_CODE_SHELL", "GW_MANAGED_DIR"} <= names, names
        assert "CLAUDE_CODE_OAUTH_TOKEN" not in names and canary not in r.stdout
        # without GW_MANAGED_DIR (a prefix set by hand): the user's own shell (SHELL),
        # and the notice says why
        r = through_prefix(inner, base_env({"TMPDIR": str(w.tmp)}), w.work)
        assert r.returncode == 0 and "GW_MANAGED_DIR is missing or not an absolute path" in r.stderr \
            and ran_without(BASH) in r.stderr, r
        assert r.stdout.startswith("inner P=/opt/user/bin S=from-the-snapshot M=\n"), r.stdout


def test_approved_import_path_folders_come_last_and_unapproved_ones_never():
    """PLAN-0.11 §1.6: the PATH is the stand-ins, the snapshot's PATH, other
    plugins' bin/ folders, then the approved import_path (each folder once);
    an import waits for the OK. import_env adds nothing the inherited
    environment doesn't already hold."""
    with world() as w:
        snap = w.snapshot()
        imp = w.env.root / "imported dir"
        imp.mkdir()
        w.env.write_form(f'[shell]\nimport_path = ["{imp}", "/opt/homebrew/bin", "/opt/user/bin"]\n'
                         'import_env = ["JAVA_HOME"]\n')
        w.sync()
        base = [str(paths.bin_dir()), "/opt/user/bin", "/usr/local/bin", "/usr/bin", "/bin"]
        r, _ = w.run('echo "J=${JAVA_HOME-}"; echo "$PATH"', snap=snap, extra={"JAVA_HOME": "/jdk"})
        assert r.stdout.splitlines() == ["J=/jdk", ":".join(base)], "not approved yet: no import"
        consent.approve("settings", form=w.env.form())
        r, _ = w.run('echo "J=${JAVA_HOME-}"; echo "$PATH"', snap=snap, extra={"JAVA_HOME": "/jdk"})
        assert r.stdout.splitlines() == ["J=/jdk", ":".join(base + [str(imp), "/opt/homebrew/bin"])], r


def test_other_plugins_bin_folders_come_after_the_snapshots_path():
    """Claude Code's own PATH adds only other plugins' bin/ folders the
    snapshot's PATH lacks, after it; the snapshot's PATH is kept whole."""
    with world() as w:
        plug = w.env.root / "a plugin's dir" / "probe"
        (plug / ".claude-plugin").mkdir(parents=True)
        (plug / ".claude-plugin" / "plugin.json").write_text("{}")
        (plug / "bin").mkdir()
        (plug / "bin" / "probe-tool").write_text("#!/bin/sh\necho probe-tool-ran\n")
        os.chmod(plug / "bin" / "probe-tool", 0o755)
        notplug = w.env.root / "user" / "bin"
        notplug.mkdir(parents=True)
        other = w.env.root / "claude-codes-own" / "bin"
        other.mkdir(parents=True)
        line = ("export PATH=" + sq(f"/opt/user/bin:{notplug}:/usr/bin:/bin"))
        snap = w.snapshot(path_line=line)
        r, _ = w.run('echo "$PATH"; probe-tool', snap=snap,
                     extra={"PATH": f"/usr/bin:/bin:{plug}/bin:{other}"})
        assert r.returncode == 0, r
        path, ran = r.stdout.splitlines()
        assert path == ":".join([str(paths.bin_dir()), "/opt/user/bin", str(notplug), "/usr/bin",
                                 "/bin", f"{plug}/bin"]), path
        assert ran == "probe-tool-ran"


def test_unknown_shapes_are_refused_and_never_run_anywhere():
    with world() as w:
        snap = w.snapshot()
        done = w.env.root / "ran"
        cmd = f": > {sq(str(done))}"
        cwdf = str(w.tmp / "claude-ab12-cwd")
        good = tool_script(cmd, snap=str(snap), cwdfile=cwdf)
        evil = w.env.root / "evil.sh"
        evil.write_text(f": > {sq(str(done))}\n")
        bad = [
            good.replace(f"source {word(str(snap))}", f"source {word(str(evil))}"),   # not a snapshot
            tool_script(cmd, snap=str(snap), cwdfile=cwdf).replace("eval ", "true "),   # no eval
            tool_script(cmd, snap=None, cwdfile=cwdf,                                    # snapshot later
                        envfile_text=f"source {word(str(snap))} 2>/dev/null"),
            good.replace(f" && pwd -P >| {word(cwdf)}", ""),                              # snapshot first, no tracker
            good.replace(" && eval ", " && true "),                                        # snapshot first, no eval
            good + "; echo ran-cwd",                                                      # snapshot first, junk after the tracker
            tool_script(cmd, snap=str(snap), cwdfile=str(w.tmp / "elsewhere")),          # not a tracker
            good.replace(" 2>/dev/null || true && ", " 2>/dev/null && ", 1),              # changed first segment
            f"source {snap} 2>/dev/null || true && {cmd}",                                # snapshot, no tracker
        ]
        for script in bad:
            done.unlink(missing_ok=True)
            r = through_prefix(script, w.launch_env(), w.work)
            assert r.returncode == 126 and "doesn't recognize" in r.stderr \
                and "not run, in the managed shell or your own" in r.stderr, (script, r)
            assert not done.exists(), f"ran: {script}"
            assert not w.marker.exists()
        r = through_prefix(good, w.launch_env(), w.work)
        assert r.returncode == 0 and done.exists(), r


def test_an_unready_managed_shell_runs_the_script_in_the_users_shell_and_says_so():
    """PLAN-0.11 §1.6, §19.15: not ready (no folder named, no settings, no
    bash, no rc), gate-sh runs the script byte for byte (the snapshot's
    source included) without the managed settings, in the shell Claude Code
    would use (here SHELL: the user's bash), with the removals still
    applied, and one stderr line says so, naming that shell; the exit status
    is the script's."""
    with world() as w:
        snap = w.snapshot()
        done = w.env.root / "ran"
        startup = w.env.root / "startup-ran"
        (w.env.root / "be.sh").write_text(f": > {sq(str(startup))}\n")
        canary = "cc-" + os.urandom(8).hex()
        hostile = {"CLAUDE_CODE_OAUTH_TOKEN": canary, "BASH_ENV": str(w.env.root / "be.sh"),
                   "GH_TOKEN": "gho_user"}
        cmd = (f": > {sq(str(done))}; "
               'echo "S=${SNAPVAR-} T=${CLAUDE_CODE_OAUTH_TOKEN-} G=${GH_TOKEN-} P=${PATH%%:*}"')
        script = tool_script(cmd, snap=str(snap), cwdfile=str(w.tmp / "claude-ab12-cwd"))
        conf = managed.conf_path().read_text()

        def check(env, why):
            done.unlink(missing_ok=True)
            w.marker.unlink(missing_ok=True)
            r = through_prefix(script, {**env, **hostile}, w.work)
            assert r.returncode == 0 and done.exists() and w.marker.exists(), (why, r)
            assert r.stdout == "S=from-the-snapshot T= G=gho_user P=/opt/user/bin\n", (why, r.stdout)
            line, = r.stderr.splitlines()
            assert line.startswith(ran_without(BASH)) and why in line and "own shell" not in line \
                and line.endswith("."), (why, r.stderr)
            assert not startup.exists(), "BASH_ENV ran"
        check(base_env({"TMPDIR": str(w.tmp)}), "didn't name its managed-shell folder")
        check(w.launch_env({"GW_MANAGED_DIR": "managed"}), "didn't name its managed-shell folder")
        managed.conf_path().unlink()
        check(w.launch_env(), "haven't been written yet")
        # the exit status is the script's
        r = through_prefix(tool_script("echo before; exit 7", snap=str(snap),
                                       cwdfile=str(w.tmp / "claude-ab13-cwd")),
                           w.launch_env(), w.work)
        assert (r.returncode, r.stdout) == (7, "before\n") and "isn't ready" in r.stderr, r
        managed.conf_path().write_text(re.sub(r"^bash=.*$", "bash=/nowhere", conf, flags=re.M))
        check(w.launch_env(), "environment isn't built")
        managed.conf_path().write_text(conf)
        managed.rc_path().unlink()
        check(w.launch_env(), "its rc file is missing")
        w.sync()
        done.unlink()
        r = through_prefix(script, w.launch_env(hostile), w.work)
        assert r.returncode == 0 and done.exists() and r.stderr == "", r
        assert r.stdout == f"S=from-the-snapshot T= G=gho_user P={paths.bin_dir()}\n", r.stdout


# gate-sh's usual places for a fallback bash or zsh (managed.FALLBACK_DIRS)
FALLBACK_LOOP = "  for _d in /bin /usr/bin /usr/local/bin /opt/homebrew/bin; do\n"


def _gate_sh_with_places(w: World, places: tuple[Path, ...], *, run_by_bash: bool = False) -> Path:
    """A copy of gate-sh whose usual places for a fallback shell are `places`
    (the host's /bin and the like hold whatever shells this machine has);
    run_by_bash: run by the test env's bash instead of /bin/sh (macOS's
    /bin/sh is bash, Debian's dash)."""
    text = GATE_SH.read_text()
    assert text.count(FALLBACK_LOOP) == 1
    text = text.replace(FALLBACK_LOOP, "  for _d in " + " ".join(sq(str(p)) for p in places) + "; do\n")
    if run_by_bash:
        text = f"#!{BASH}\n" + text.split("\n", 1)[1]
    copy = w.env.root / ("gate-sh-places-" + "-".join(p.name for p in places) + ("-bash" if run_by_bash else ""))
    copy.write_text(text)
    os.chmod(copy, 0o755)
    return copy


def test_the_fallback_shell_rule_is_gate_shs_own_in_managed_py():
    text = GATE_SH.read_text()
    assert FALLBACK_LOOP == "  for _d in " + " ".join(managed.FALLBACK_DIRS) + "; do\n", FALLBACK_LOOP
    # Claude Code's order: CLAUDE_CODE_SHELL, SHELL, the preferred shell on PATH, the usual
    # places for it, then for the other, the other on PATH; bash first when SHELL holds "bash"
    assert '  for _c in "${CLAUDE_CODE_SHELL-}" "$_sh"; do\n' in text
    assert "  case $_sh in *bash*) set -- bash zsh ;; *) set -- zsh bash ;; esac\n" in text
    assert '  gw_which "$1" || gw_places "$1" || gw_places "$2" || gw_which "$2"\n' in text
    assert "case ${GW_SNAP##*/} in snapshot-zsh-*) GW_FAMILY=zsh ;; snapshot-bash-*) GW_FAMILY=bash ;; esac\n" \
        in text
    assert managed.FALLBACK_SHELLS == ("bash", "zsh")
    assert [managed.snapshot_family(p) for p in ("/c/shell-snapshots/snapshot-zsh-1-a.sh",
                                                 "/c/shell-snapshots/snapshot-bash-1-a.sh",
                                                 "/c/shell-snapshots/snapshot-sh-1-a.sh", None)] \
        == ["zsh", "bash", "", ""]
    assert [managed.shell_family(p) for p in ("/bin/zsh", "/opt/zsh-5.9/bin/bash", "/bin/bash5", "/bin/fish")] \
        == ["zsh", "zsh", "bash", ""]


def test_an_unready_managed_shell_runs_the_shell_that_made_the_snapshot_never_bin_sh():
    """PLAN-0.11 §19.15: the not-ready path runs the script in the shell that
    made its snapshot (its name says which: snapshot-zsh-*, snapshot-bash-*),
    found the way Claude Code 2.1.310 finds its shell: CLAUDE_CODE_SHELL,
    then SHELL, then the preferred shell on PATH, the usual places for it,
    the usual places for the other, the other on PATH, where bash is
    preferred when SHELL holds "bash" and zsh otherwise; the first that is
    an absolute path to an executable file Claude Code names like the
    snapshot (a path holding "zsh" is a zsh, else one holding "bash" a
    bash), without '=' (env would take it for an assignment). Without a
    snapshot, any bash or zsh in that order. Passed over: fish, a missing
    file, a folder named bash, a relative PATH entry. Never /bin/sh
    (Debian's dash has no `source`, so the snapshot was skipped without a
    word); with no such shell the script is refused (126) and nothing runs.
    The notice names the shell (the env's bash too: never "your own
    shell"). managed.fallback_shell agrees row by row (run from the same
    folder, where the relative entry holds a bash and a zsh)."""
    with world() as w:
        assert "bash" not in str(w.env.root) and "zsh" not in str(w.env.root), \
            f"the test root's name holds a shell's name: {w.env.root}"
        sb, sz = w.snapshot("bash"), w.snapshot("zsh")
        log = w.env.root / "which-shell.log"
        done = w.env.root / "ran"

        def folder(name: str, *shells: str) -> Path:
            d = w.env.root / name
            d.mkdir(parents=True, exist_ok=True)
            for n in shells:
                (d / n).write_text(f"#!/bin/sh\nprintf '%s\\n' \"$0\" >> {sq(str(log))}\n"
                                   f'exec {sq(str(BASH))} "$@"\n')
                os.chmod(d / n, 0o755)
            return d
        shells = folder("user shells", "bash", "zsh", "fish", "zsh-5.9")
        b, z, f, z59 = (str(shells / n) for n in ("bash", "zsh", "fish", "zsh-5.9"))
        more = folder("more shells", "bash", "zsh")
        b2, z2 = str(more / "bash"), str(more / "zsh")
        onlyb, onlyz, both, empty = (folder("only-b", "bash"), folder("only-z", "zsh"),
                                     folder("both", "bash", "zsh"), folder("empty"))
        pathb, pathz = folder("path-b", "bash"), folder("path-z", "zsh")
        pathboth = folder("path both [*]", "bash", "zsh")   # a blank and glob characters
        dirs = folder("dir-sh")
        (dirs / "bash").mkdir()                             # executable, but no program
        (dirs / "zsh").mkdir()
        eq = folder("tools=x", "bash", "zsh")               # '=': env reads it as an assignment
        folder("work dir é/rel", "bash", "zsh")             # a relative PATH entry (the cwd's rel/)
        envbash = str(paths.env_bin() / "bash")             # the gateway env's bash
        managed.conf_path().unlink()                        # not ready: no settings
        rows = [
            # CLAUDE_CODE_SHELL, then SHELL (each the snapshot's shell)
            ((empty,), sb, {"CLAUDE_CODE_SHELL": b, "SHELL": b2, "PATH": str(pathboth)}, b),
            ((empty,), sb, {"SHELL": b2, "PATH": str(pathboth)}, b2),
            ((empty,), sz, {"CLAUDE_CODE_SHELL": z, "SHELL": z2}, z),
            # passed over: a folder named bash, a missing file, fish, a path holding '='
            ((empty,), sb, {"CLAUDE_CODE_SHELL": str(dirs / "bash"), "SHELL": b2}, b2),
            ((empty,), sb, {"CLAUDE_CODE_SHELL": "/nowhere/bash", "SHELL": b2}, b2),
            ((empty,), sb, {"CLAUDE_CODE_SHELL": f, "SHELL": b}, b),
            ((empty,), sb, {"CLAUDE_CODE_SHELL": str(eq / "bash"), "SHELL": b}, b),
            ((empty,), sb, {"SHELL": str(eq / "bash"), "PATH": f"{eq}:{pathb}"}, f"{pathb}/bash"),
            # any path holding the shell's name (Claude Code's own test)
            ((empty,), sz, {"SHELL": z59, "PATH": str(pathboth)}, z59),
            # the snapshot decides: the env's bash (the mod's CLAUDE_CODE_SHELL) runs a bash
            # snapshot only; a zsh snapshot runs in a zsh, whatever is preferred or set
            ((both,), sb, {"CLAUDE_CODE_SHELL": envbash, "SHELL": z}, envbash),
            ((both,), sz, {"CLAUDE_CODE_SHELL": envbash, "SHELL": z}, z),
            ((both,), sz, {"SHELL": f, "PATH": str(pathboth)}, f"{pathboth}/zsh"),
            ((both,), sz, {"PATH": str(pathb)}, f"{both}/zsh"),
            ((both,), sb, {"PATH": str(pathz)}, f"{both}/bash"),
            # PATH before the usual places for the preferred shell, after them for the other
            ((both,), sb, {"SHELL": "/nowhere/bash", "PATH": str(pathboth)}, f"{pathboth}/bash"),
            ((both,), sb, {"SHELL": f, "PATH": str(pathboth)}, f"{both}/bash"),
            # no snapshot: Claude Code's own order (zsh first unless SHELL holds "bash")
            ((both,), None, {"PATH": str(pathboth)}, f"{pathboth}/zsh"),
            ((both,), None, {"SHELL": "/nowhere/bash", "PATH": str(pathz)}, f"{both}/bash"),
            ((onlyb,), None, {"SHELL": f, "PATH": str(pathb)}, f"{onlyb}/bash"),
            # a relative PATH entry and folders named zsh and bash passed over
            ((dirs,), sz, {"PATH": f"rel:{dirs}:{onlyz}"}, f"{onlyz}/zsh"),
            ((dirs,), sb, {"PATH": f"rel:{dirs}:{onlyb}"}, f"{onlyb}/bash"),
            # nothing fits: refused (a zsh snapshot isn't run by a bash)
            ((empty, dirs), sz, {"SHELL": f, "PATH": f"rel:{empty}:{pathb}"}, None),
            ((empty, dirs), None, {"SHELL": f, "PATH": f"rel:{empty}"}, None),
        ]
        for places, snap, extra, want in rows:
            env = {k: v for k, v in w.launch_env().items() if k != "SHELL"}
            env.update(extra)
            with contextlib.chdir(w.work):
                assert managed.fallback_shell(env, tuple(str(p) for p in places),
                                              str(snap) if snap else None) == want, (snap, extra, want)
            log.write_text("")
            done.unlink(missing_ok=True)
            script = tool_script(f"echo ran-it; : > {sq(str(done))}", snap=str(snap) if snap else None,
                                 cwdfile=str(w.tmp / "claude-ab15-cwd"))
            r = through_prefix(script, env, w.work, prefix=_gate_sh_with_places(w, places))
            line, = r.stderr.splitlines()
            if want is None:
                assert r.returncode == 126 and r.stdout == "" and not done.exists(), (extra, r)
                need = "a zsh (the shell that made its snapshot)" if snap == sz else "a bash or zsh"
                assert line.startswith("gateway: this command was not run: the managed shell isn't ready (") \
                    and f"needs {need}, but" in line, line
                assert log.read_text() == "", log.read_text()
                continue
            assert r.returncode == 0 and r.stdout == "ran-it\n" and done.exists(), (snap, extra, r)
            assert line.startswith(ran_without(want)) and "own shell" not in line, (want, line)
            assert log.read_text().splitlines() == ([] if want == envbash else [want]), \
                (snap, extra, log.read_text())
        # SHELL unset: gate-sh run by a bash (macOS's /bin/sh, some Linux's) sees a SHELL
        # bash set itself, the login shell, which isn't Claude Code's: passed over
        env = {k: v for k, v in w.launch_env().items() if k != "SHELL"}
        env["PATH"] = str(pathb)
        log.write_text("")
        script = tool_script("echo ran-it", snap=None, cwdfile=str(w.tmp / "claude-ab16-cwd"))
        r = through_prefix(script, env, w.work, prefix=_gate_sh_with_places(w, (empty,), run_by_bash=True))
        assert r.returncode == 0 and r.stderr.startswith(ran_without(f"{pathb}/bash")), r
        assert log.read_text().splitlines() == [f"{pathb}/bash"], log.read_text()


def test_gate_sh_refuses_when_it_cant_list_the_environment():
    """Review should-fix 9: without env's list gate-sh would remove nothing,
    and Claude Code's credentials would reach the command. It refuses (126)
    and runs nothing, in the managed shell and the not-ready fallback
    alike. (A copy of gate-sh whose helper PATH finds a failing env first.)"""
    with world() as w:
        snap = w.snapshot()
        done = w.env.root / "ran"
        fake = w.env.root / "failing-env"
        fake.mkdir()
        (fake / "env").write_text("#!/bin/sh\nexit 1\n")
        os.chmod(fake / "env", 0o755)
        text = GATE_SH.read_text()
        old = "PATH=/usr/bin:/bin:/usr/sbin:/sbin   #"
        assert text.count(old) == 1
        copy = w.env.root / "gate-sh-copy"
        copy.write_text(text.replace(old, f"PATH={fake}:/usr/bin:/bin:/usr/sbin:/sbin   #"))
        os.chmod(copy, 0o755)
        script = tool_script(f": > {sq(str(done))}", snap=str(snap),
                             cwdfile=str(w.tmp / "claude-ab14-cwd"))
        canary = {"CLAUDE_CODE_OAUTH_TOKEN": "cc-" + os.urandom(8).hex()}
        for env in (w.launch_env(canary), base_env({"TMPDIR": str(w.tmp), **canary})):
            r = through_prefix(script, env, w.work, prefix=copy)
            assert r.returncode == 126 and not done.exists(), r
            assert "couldn't list the environment" in r.stderr and canary["CLAUDE_CODE_OAUTH_TOKEN"] \
                not in r.stdout + r.stderr, r
        (fake / "env").unlink()                   # the same copy with the system's env runs it
        r = through_prefix(script, w.launch_env(canary), w.work, prefix=copy)
        assert r.returncode == 0 and done.exists(), r


def _launch_sh_sentence(name: str) -> str:
    """One of launch.sh's not-ready texts for the stand-ins, without its
    "gateway: " (NOPIXI, or the failed one with LOG for the log's path)."""
    src = (H.PLUGIN / "hooks" / "launch.sh").read_text()
    if name == "nopixi":
        m = re.search(r'^NOPIXI="gateway: ([^"]+)"$', src, re.M)
    elif name == "pixiold":       # WORDS for launch.sh's GW_TOOOLD ("pixi 0.81.0 is too old ...")
        m = re.search(r'''printf '%s' "gateway: (the gateway can't set itself up: \$GW_TOOOLD; '''
                      r'''tell the user [^"]*)"''', src)
        upd = re.search(r'^GW_PIXI_UPDATE="([^"]+)"$', src, re.M)
        assert m and upd and upd.group(1) == envfile.PIXI_UPDATE, name
        return m.group(1).replace("$GW_PIXI_UPDATE", upd.group(1)).replace("$GW_TOOOLD", "WORDS")
    else:
        m = re.search(r'''printf '%s' "gateway: (the gateway's setup failed \(log: \$ENVD/install\.log\)[^"]*)"''', src)
    assert m, name
    return m.group(1).replace("$ENVD/install.log", "LOG")


def test_an_unready_managed_shell_says_what_is_wrong():
    """GW-UX-1b: the not-ready notice once named "a first run, about a
    minute" in every state: also with pixi missing, after a failed build and
    with the data folder gone. gate-sh tells them apart by file tests; the
    failed and pixi-missing sentences are launch.sh's own. "Still setting up"
    only while no env is built (a build running, or none started yet): with
    a built env and no build running, the settings are what is missing or
    wasn't renewed (verifier, 0.11 TUI: a missing rc in a ready env said
    "still setting up"). Each time the command ran without the managed
    settings, in the user's shell (PLAN-0.11 §1.6, §19.15)."""
    with world() as w:
        snap = w.snapshot()
        done = w.env.root / "ran"
        script = tool_script(f": > {sq(str(done))}", snap=str(snap),
                             cwdfile=str(w.tmp / "claude-ab12-cwd"))
        fakepixi = w.env.root / "pixi-bin"
        fakepixi.mkdir()
        (fakepixi / "pixi").write_text("#!/bin/sh\nexit 0\n")
        (fakepixi / "pixi").chmod(0o755)
        withpixi = {"PATH": f"/usr/bin:/bin:/usr/sbin:/sbin:{fakepixi}"}
        conf = managed.conf_path().read_text()
        envs = paths.envs_dir()
        settings = "The managed shell's settings are missing or couldn't be renewed; a new session " \
                   "writes them again (/gate-doctor shows their state)."

        def refused(env, prefix=GATE_SH):
            done.unlink(missing_ok=True)
            r = through_prefix(script, env, w.work, prefix=prefix)
            assert r.returncode == 0 and r.stderr.startswith(ran_without(BASH)), r
            assert done.exists() and len(r.stderr.splitlines()) == 1, r
            return r.stderr
        # still setting up: no settings yet, nothing failed, pixi there
        managed.conf_path().unlink()
        err = refused(w.launch_env(withpixi))
        assert "still setting up" in err and "/gate-doctor" in err, err
        assert "failed" not in err and "pixi isn't installed" not in err, err
        # setup failed: an env folder with its log and no .ready
        bad = envs / "0123456789ab"
        bad.mkdir(parents=True)
        (bad / "install.log").write_text("pixi: lock format v7 is not supported\n")
        err = refused(w.launch_env(withpixi))
        want = _launch_sh_sentence("failed").replace("LOG", str(bad / "install.log"))
        assert want[0].upper() + want[1:] in err and "/gate-doctor" in err, (want, err)
        assert "still setting up" not in err, err
        # pixi too old (the GitHub install test, 0.11.0: this said "setup failed;
        # retried at the next session start"): launch.sh's record beside that log
        # names the versions, and the advice is launch.sh's own (the package
        # manager for a Homebrew or MacPorts pixi)
        record = bad / ".pixi-too-old"
        old = _launch_sh_sentence("pixiold")
        for text, words in (("found=0.81.0\nneeded=>=0.83.0\n",
                             "pixi 0.81.0 is too old (the gateway needs pixi >=0.83.0)"),
                            ("found=\nneeded=\n", "this pixi is too old")):
            record.write_text(text)
            err = refused(w.launch_env(withpixi))
            say = old.replace("WORDS", words)
            assert say[0].upper() + say[1:] + "." in err and envfile.PIXI_UPDATE in err, (say, err)
            assert "failed" not in err and "retried" not in err and "still setting up" not in err, err
        # ... unless a build runs now (its lock; one without an owner file yet
        # counts as live, as in launch.sh)
        lock = envs / "0123456789ab.building"
        lock.mkdir()
        err = refused(w.launch_env(withpixi))
        assert "still setting up" in err and "failed" not in err and "too old" not in err, err
        record.unlink()
        err = refused(w.launch_env(withpixi))
        assert "still setting up" in err and "failed" not in err, err
        # review round 2: a lock whose builder and pixi child are gone (a
        # build killed at ensure-env's timeout) is stale: setup failed, not
        # "still setting up" for the rest of the session
        gone = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
        gone.wait()
        gone2 = subprocess.Popen(["/bin/sh", "-c", "exit 0"])
        gone2.wait()
        (lock / "owner").write_text(f"pid={gone.pid}\nstart=Thu Oct 22 10:00:00 2026\nhost=x\n"
                                    f"child={gone2.pid}\ncstart=Thu Oct 22 10:00:01 2026\n")
        err = refused(w.launch_env(withpixi))
        assert want[0].upper() + want[1:] in err and "still setting up" not in err, (want, err)
        # the builder alive (or only its pixi child): still setting up
        for owner in (f"pid={os.getpid()}\nstart=x\nhost=x\n",
                      f"pid={gone.pid}\nstart=x\nhost=x\nchild={os.getpid()}\ncstart=x\n"):
            (lock / "owner").write_text(owner)
            err = refused(w.launch_env(withpixi))
            assert "still setting up" in err and "failed" not in err, (owner, err)
        shutil.rmtree(lock)
        # the settings name an env that isn't built: that env's log decides
        managed.conf_path().write_text(conf.replace(f"bash={BASH.parent}", f"bash={bad}/.pixi/envs/default/bin")
                                       .replace(f"bash={paths.env_bin()}", f"bash={bad}/.pixi/envs/default/bin"))
        err = refused(w.launch_env(withpixi))
        assert "environment isn't built" in err and str(bad / "install.log") in err, err
        (bad / ".ready").write_text("")
        err = refused(w.launch_env(withpixi))
        assert "still setting up" in err, err
        shutil.rmtree(bad)
        # the env the settings name is built (launch.sh's test: .ready and its
        # python3) and nothing builds: its settings are what is missing
        managed.conf_path().write_text(conf)
        py3 = paths.env_bin() / "python3"
        py3.write_text("#!/bin/sh\nexit 0\n")
        py3.chmod(0o755)
        managed.rc_path().unlink()
        # (its python3 without .ready isn't built yet: still setting up)
        err = refused(w.launch_env(withpixi))
        assert "its rc file is missing" in err and "still setting up" in err and settings not in err, err
        (paths.env_dir() / ".ready").write_text("")
        err = refused(w.launch_env(withpixi))
        assert "its rc file is missing" in err and settings in err and "still setting up" not in err, err
        # the settings name an env that is gone (an update's sweep) and another is built:
        # its settings, not "still setting up"
        managed.conf_path().write_text(re.sub(r"^bash=.*$", f"bash={envs}/gone0000000/.pixi/envs/default/bin/bash",
                                              conf, flags=re.M))
        err = refused(w.launch_env(withpixi))
        assert "environment isn't built" in err and settings in err and "still setting up" not in err, err
        (envs / "gone0000000.building").mkdir()         # ... unless that env is being built again
        err = refused(w.launch_env(withpixi))
        assert "environment isn't built" in err and "still setting up" in err and settings not in err, err
        (envs / "gone0000000.building").rmdir()
        managed.conf_path().unlink()                    # no settings at all, an env built
        err = refused(w.launch_env(withpixi))
        assert "haven't been written yet" in err and settings in err and "still setting up" not in err, err
        # ... but a build running beside it (an update's env) is still setting up
        (envs / "0123456789ab").mkdir()
        lock = envs / "0123456789ab.building"
        lock.mkdir()
        err = refused(w.launch_env(withpixi))
        assert "still setting up" in err and settings not in err, err
        shutil.rmtree(lock)
        shutil.rmtree(envs / "0123456789ab")
        py3.unlink()
        (paths.env_dir() / ".ready").unlink()
        w.sync()
        managed.conf_path().unlink()
        # pixi missing: launch.sh's places (a copy of gate-sh with the system
        # folders this machine may keep a real pixi in renamed away) and PATH
        nopixi = w.env.root / "gate-sh-nopixi"
        txt = GATE_SH.read_text()
        for d in ("/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin", "/home/linuxbrew/.linuxbrew/bin"):
            assert f" {d}" in txt, d
            txt = txt.replace(f" {d}", f" /nonexistent{d}", 1)
        nopixi.write_text(txt)
        nopixi.chmod(0o755)
        err = refused(w.launch_env(), prefix=nopixi)
        want = _launch_sh_sentence("nopixi")
        assert want[0].upper() + want[1:] + "." in err, (want, err)
        err = refused(w.launch_env(withpixi), prefix=nopixi)
        assert "still setting up" in err, err
        # the data folder gone (uninstalled, or removed by hand)
        gone = w.env.root / "gone-data" / "managed"
        err = refused(w.launch_env({**withpixi, "GW_MANAGED_DIR": str(gone)}))
        assert f"data folder ({gone.parent}) is gone" in err and "restart Claude Code" in err \
            and "reinstall" in err, err
        managed.conf_path().write_text(conf)
        done.unlink(missing_ok=True)
        r = through_prefix(script, w.launch_env(), w.work)
        assert r.returncode == 0 and done.exists() and "isn't ready" not in r.stderr, r


def test_a_newer_form_renews_the_settings_before_the_command_so_a_narrowing_applies():
    with world() as w:
        snap = w.snapshot()
        imp = w.env.root / "imp"
        imp.mkdir()
        w.env.write_form(f'[shell]\nimport_path = ["{imp}"]\n')
        w.sync()
        consent.approve("settings", form=w.env.form())
        r, _ = w.run('echo "$PATH"', snap=snap)
        assert r.stdout.strip().endswith(f":{imp}"), r
        # the import removed (a narrowing) and FileChanged not run: gate-sh
        # sees the newer form and renews first (the sync stub, run.py managed-sync)
        time.sleep(0.05)
        w.env.write_form("[shell]\n")
        st = paths.form_path().stat()
        os.utime(paths.form_path(), (st.st_atime, managed.conf_path().stat().st_mtime + 5))
        r, _ = w.run('echo "$PATH"', snap=snap)
        assert r.returncode == 0 and str(imp) not in r.stdout and r.stderr == "", r
        # renewing impossible (no sync stub): without the managed settings, in the
        # user's shell, with the notice
        os.utime(paths.form_path(), (st.st_atime, managed.conf_path().stat().st_mtime + 5))
        managed.sync_path().unlink()
        r, _ = w.run('echo "ran $PATH"', snap=snap)
        assert r.returncode == 0 and "couldn't be renewed" in r.stderr \
            and r.stderr.startswith(ran_without(BASH)), r
        assert r.stdout.startswith("ran /opt/user/bin:") and str(imp) not in r.stdout, r


def test_an_unlock_renews_the_settings():
    with world() as w:
        snap = w.snapshot()
        before = managed.conf_path().stat().st_mtime
        marker = managed.unlocked_marker()
        marker.touch()
        os.utime(marker, (before + 5, before + 5))
        r, _ = w.run("echo ran", snap=snap)
        assert r.stdout == "ran\n", r
        assert managed.conf_path().stat().st_mtime > before, "renewed after the unlock"


def test_an_interrupt_kills_the_running_command_and_the_status_is_kept():
    with world() as w:
        snap = w.snapshot()
        child = w.env.root / "child.pid"
        cwdfile = w.tmp / "claude-ffff-cwd"
        script = tool_script(f"sleep 30 & echo $! > {sq(str(child))}; wait", snap=str(snap),
                             cwdfile=str(cwdfile))
        p = subprocess.Popen(["/bin/sh", "-c", f"{sq(str(GATE_SH))} {sq(script)}"],
                             env=w.launch_env(), cwd=str(w.work), start_new_session=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(100):
            if child.exists() and child.read_text().strip():
                break
            time.sleep(0.05)
        sleeper = int(child.read_text())
        # gate-sh exec'd env, which exec'd the managed bash: no gate-sh or env process is
        # left between (macOS's /bin/sh execs the prefix too; dash keeps itself as parent)
        table = subprocess.run(["ps", "-A", "-o", "pid=,ppid=,command="], capture_output=True,
                               text=True).stdout.splitlines()
        rows = [ln.split(None, 2) for ln in table if len(ln.split(None, 2)) == 3]
        kids, frontier = set(), {p.pid}
        while frontier:
            new = {int(r[0]) for r in rows if int(r[1]) in frontier} - kids
            kids |= new
            frontier = new
        mine = [r[2] for r in rows if int(r[0]) in kids | {p.pid}]
        bashes = [c for c in mine if c.startswith(str(paths.env_bin() / "bash") + " --noprofile --norc -c")]
        assert len(bashes) == 1, mine
        assert not any(c.split()[0].endswith(("/gate-sh", "/env")) for c in mine), mine
        os.killpg(p.pid, signal.SIGINT)            # Claude Code interrupts the process tree
        os.killpg(p.pid, signal.SIGTERM)
        p.wait(timeout=10)
        assert p.returncode != 0
        time.sleep(0.2)
        try:
            os.kill(sleeper, 0)
            alive = True
        except ProcessLookupError:
            alive = False
        assert not alive, "the command kept running"
        assert not cwdfile.exists()


# ---------------------------------------------------------------------------
# managed.py: the files gate-sh reads
# ---------------------------------------------------------------------------


def test_sync_writes_private_conf_rc_state_runtime_links_and_the_sync_stub():
    with world() as w:
        md = managed.managed_dir()
        assert md.stat().st_mode & 0o777 == 0o700
        for p in (managed.conf_path(), managed.rc_path(), managed.state_path()):
            assert p.stat().st_mode & 0o777 == 0o600, p
        conf = dict(l.split("=", 1) for l in managed.conf_path().read_text().splitlines()
                    if "=" in l and not l.startswith("#"))
        assert set(conf) == {"bash", "rc", "standins", "imports", "form", "sync", "unlocked"}, conf
        assert conf["bash"] == str(paths.env_bin() / "bash")
        assert conf["rc"] == str(managed.rc_path()) and conf["standins"] == str(paths.bin_dir())
        assert conf["form"] == str(paths.form_path()) and conf["sync"] == str(managed.sync_path())
        assert conf["imports"] == "" and conf["unlocked"] == str(managed.unlocked_marker())
        assert not (md / "bin").exists(), "no runtime folder: the user's own PATH has their tools"
        stub = managed.sync_path().read_text()
        assert "managed-sync" in stub and os.access(managed.sync_path(), os.X_OK)
        st = json.loads(managed.state_path().read_text())
        assert st["mode"] == "on" and st["bash_version"].startswith("5.") and st["ready"] is True
        assert [p["origin"] for p in st["path"]] == [
            "the gateway's stand-ins", "your own PATH (Claude Code's shell snapshot, else its own PATH)"]
        rc = managed.rc_path().read_text()
        assert envfile.env_text() in rc and rc.rstrip().endswith(":")
        assert rc.endswith(managed.rc_tail())
        # the only file the rc sources is its $1, and only a bash snapshot
        sources = [ln for ln in rc.splitlines() if re.search(r"(^|;|then|&&|\|\|)\s*(source|\.)\s", ln)]
        assert sources == [managed.RC_SNAPSHOT.splitlines()[2]], sources
        assert "*/shell-snapshots/snapshot-bash-*.sh)" in sources[0]
        r = subprocess.run([str(BASH), "-n", str(managed.rc_path())], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        # never older than the form (a form dated in the future)
        future = time.time() + 3600
        os.utime(w.env.write_form(""), (future, future))
        w.sync()
        assert managed.conf_path().stat().st_mtime > future


def test_a_gate_sh_without_its_exec_bit_gets_an_executable_copy_in_the_data_folder():
    """Claude Code runs the prefix as a program; an install that drops file
    modes would break every command, and the plugin folder is never written
    to: managed.sync writes an executable copy into the data folder, the
    state names it (the mod then sets it), and the classic hook counts it as
    the gateway's."""
    from gateway import hooks_bash
    with H.gateway_env() as env:
        root = env.root / "plugin copy"
        (root / "hooks").mkdir(parents=True)
        shutil.copy(H.PLUGIN / "pixi.lock", root / "pixi.lock")
        (root / "hooks" / "gate-sh").write_text(GATE_SH.read_text())
        os.chmod(root / "hooks" / "gate-sh", 0o644)
        with testing.override(env.root, plugin_root=root, managed_bash=str(BASH), pixi="",
                              machine_id="TEST-MACHINE-0001", system_git=True):
            data = None
            form = consent.load_form(data)
            eff = consent.compute(form, data)
            assert managed.sync(form, eff)["errors"] == []
            copy = managed.gate_sh_copy()
            assert copy.read_text() == GATE_SH.read_text() and os.access(copy, os.X_OK)
            assert managed.load_state()["gate_sh"] == str(copy)
            assert hooks_bash._ours(str(copy)) and hooks_bash._ours(str(root / "hooks" / "gate-sh"))
            assert not hooks_bash._ours(str(env.root / "elsewhere" / "gate-sh"))
            r = through_prefix("echo hook-through-the-copy", base_env(), env.root, prefix=copy)
            assert r.stdout == "hook-through-the-copy\n", r
            os.chmod(root / "hooks" / "gate-sh", 0o755)
            assert managed.sync(form, eff)["errors"] == []
            assert not copy.exists() and managed.load_state()["gate_sh"] == str(root / "hooks" / "gate-sh")


def test_the_rc_brings_rg_from_claude_codes_copy_and_its_pkill_guard_only():
    with world() as w:
        fake_cc = w.env.root / "claude-code-bin"
        fake_cc.write_text('#!/bin/sh\necho "argv0-rg $*"\n')
        os.chmod(fake_cc, 0o755)
        r, _ = w.run("type -t rg; rg --version", snap=w.snapshot(),
                     extra={"CLAUDE_CODE_EXECPATH": str(fake_cc)})
        assert r.stdout.splitlines()[0] == "function" and "argv0-rg --version" in r.stdout, r
        r, _ = w.run("type -t pkill; type -t find; type -t grep", snap=w.snapshot())
        assert r.stdout.splitlines() == ["function", "file", "file"], r


# ---------------------------------------------------------------------------
# [shell] in the form, and its consent
# ---------------------------------------------------------------------------


def test_the_shell_section_parses_and_refuses_what_it_must():
    with H.gateway_env() as env:
        f = F.parse_text('[shell]\nmanaged = "WARN"\nimport_path = ["/opt/homebrew/bin", "~/.cargo/bin",'
                         ' "rel/x", "/a:b", "/opt/homebrew/bin", "~/.config/gateway/private"]\n'
                         'import_env = ["JAVA_HOME", "GITHUB_TOKEN", "PATH", "HOME", "LD_PRELOAD",'
                         ' "MY_API_KEY", "SSH_AUTH_SOCK", "CLAUDE_X", "bad-name", "GOPATH"]\nbogus = 1\n')
        # "warn" is gone (PLAN-0.11 §1.6): a mistake that counts as "on"
        assert f.shell.managed == "on" and f.shell.managed_invalid
        assert f.shell.import_path == ["/opt/homebrew/bin", str(env.user_home / ".cargo" / "bin")]
        assert f.shell.import_env == ["JAVA_HOME", "GOPATH"]
        msgs = [p.render() for p in f.problems]
        for needle in ('"warn" is gone', "must be absolute", "holds a ':'", "listed twice",
                       "gateway's own folder",
                       "GITHUB_TOKEN looks like a credential", "PATH can't be imported",
                       "HOME always reaches", "LD_PRELOAD can't be imported",
                       "MY_API_KEY looks like a credential", "SSH_AUTH_SOCK looks like a credential",
                       "CLAUDE_X can't be imported", "must be variable names", "unknown key bogus"):
            assert any(needle in m for m in msgs), (needle, msgs)
        for v, want in ((True, "on"), (False, "off"), ('"on"', "on"), ('"off"', "off")):
            g = F.parse_text(f"[shell]\nmanaged = {str(v).lower() if isinstance(v, bool) else v}\n")
            assert g.shell.managed == want and not g.problems, (v, g.problems)
        g = F.parse_text('[shell]\nmanaged = "sometimes"\n')
        assert g.shell.managed_invalid and g.errors
        assert F.parse_text("").shell.managed == "on"


def test_lowering_managed_and_adding_imports_wait_for_the_ok_and_narrowing_applies_at_once():
    with H.gateway_env():
        _lowering_and_imports()


def _lowering_and_imports():
    def run(old: str, new: str) -> consent.Effective:
        data = {"approved": {"rights": consent.snapshot(F.parse_text(old))}}
        return consent.compute(F.parse_text(new), data)
    e = run("", '[shell]\nmanaged = "off"\n')
    assert e.shell.managed == "on" and [c.what for c in e.pending][0].startswith('managed shell "on" -> "off"')
    # "warn" is gone (PLAN-0.11 §1.6): written, it is a mistake that counts as "on"
    e = run("", '[shell]\nmanaged = "warn"\n')
    assert e.shell.managed == "on" and not e.pending_for("settings")
    e = run('[shell]\nmanaged = "off"\n', '[shell]\nmanaged = "on"\n')
    assert e.shell.managed == "on" and not e.pending and e.narrowed[0].what == 'managed shell "off" -> "on"'
    e = run("", '[shell]\nimport_path = ["/opt/x/bin"]\nimport_env = ["JAVA_HOME"]\n')
    assert e.shell.import_path == [] and e.shell.import_env == []
    assert sorted(c.what.split(" (")[0] for c in e.pending) == ["PATH import /opt/x/bin",
                                                                 "environment import JAVA_HOME"]
    old = '[shell]\nimport_path = ["/opt/x/bin", "/opt/y/bin"]\nimport_env = ["JAVA_HOME"]\n'
    e = run(old, '[shell]\nimport_path = ["/opt/y/bin"]\n')
    assert e.shell.import_path == ["/opt/y/bin"] and e.shell.import_env == [] and not e.pending
    assert {c.what for c in e.narrowed} == {"PATH import /opt/x/bin removed",
                                            "environment import JAVA_HOME removed"}
    # a bad mode counts as "on" (the stricter), nothing ratchets
    e = run('[shell]\nmanaged = "off"\n', '[shell]\nmanaged = "nope"\n')
    assert e.shell.managed == "on" and not e.narrowed and not e.pending
    # approvals older than 0.9 aren't read (PLAN-0.11 §19.14): a record without
    # a shell part (before PLAN-v4 phase 4) approves nothing, not even its
    # hosts; 0.9's and 0.10's records (a shell part, no [network]: the same
    # shape) keep their approvals
    host = '[hosts.box]\naddress = "octo@box.example.com"\n'
    snap = consent.snapshot(F.parse_text(host + '[shell]\nmanaged = "off"\n'))
    old = {"settings": {}, "hosts": snap["hosts"], "accounts": {}}
    e = consent.compute(F.parse_text(host + '[shell]\nmanaged = "off"\n'),
                        {"approved": {"rights": old}})
    assert e.shell.managed == "on" and e.hosts["box"].new and \
        sorted(e.pending_names()) == ["box", "settings"], e.pending_names()
    assert consent.approved_rights({"approved": {"rights": old}}) == consent.baseline()
    v010 = {"settings": {"shell": snap["settings"]["shell"], "policy": snap["settings"]["policy"]},
            "hosts": snap["hosts"], "accounts": {}}
    e = consent.compute(F.parse_text(host + '[shell]\nmanaged = "off"\n'),
                        {"approved": {"rights": v010}})
    assert e.shell.managed == "off" and not e.pending, e.pending_names()


def test_approval_and_the_ratchet_keep_the_shell_settings():
    with H.gateway_env() as env:
        env.write_form('[shell]\nmanaged = "off"\nimport_path = ["/opt/x/bin"]\n')
        consent.approve("settings", form=env.form())
        data = vault.load()
        sh = data["approved"]["rights"]["settings"]["shell"]
        assert sh == {"managed": "off", "import_path": ["/opt/x/bin"], "import_env": []}
        assert managed.load_state()["mode"] == "off", "approve() renewed the managed files"
        # a narrowing (an import removed) keeps the shell part
        env.write_form('[shell]\nmanaged = "off"\n')
        consent.ratchet(env.form())
        sh = vault.load()["approved"]["rights"]["settings"]["shell"]
        assert sh == {"managed": "off", "import_path": [], "import_env": []}, sh
        env.write_form("")
        consent.ratchet(env.form())
        sh = vault.load()["approved"]["rights"]["settings"]["shell"]
        assert sh["managed"] == "on", "raising managed back to on is a narrowing, ratcheted"


# ---------------------------------------------------------------------------
# The classic Bash hook when the prefix isn't the gateway's
# ---------------------------------------------------------------------------


def _hook(payload: dict, prefix: str | None) -> dict | None:
    from gateway import hooks_bash
    keep = os.environ.get("CLAUDE_CODE_SHELL_PREFIX")
    if prefix is None:
        os.environ.pop("CLAUDE_CODE_SHELL_PREFIX", None)
    else:
        os.environ["CLAUDE_CODE_SHELL_PREFIX"] = prefix
    try:
        return hooks_bash.main(payload)
    finally:
        if keep is None:
            os.environ.pop("CLAUDE_CODE_SHELL_PREFIX", None)
        else:
            os.environ["CLAUDE_CODE_SHELL_PREFIX"] = keep


def test_without_the_prefix_commands_run_with_a_notice_once_per_session():
    """PLAN-0.11 §1.8: no blanket refusal. Without the gateway's gate-sh
    (mods off, or another prefix) a Bash or Monitor call is judged as usual
    and the person is told once per session that commands run in their own
    shell; a decision the hook makes stays."""
    with H.gateway_env() as env:
        for i, (tool, ti) in enumerate((("Bash", {"command": "ls"}),
                                        ("Bash", {"command": "ls", "run_in_background": True}),
                                        ("Monitor", {"command": "tail -f x", "description": "x"}))):
            p = {"tool_name": tool, "tool_input": ti, "session_id": f"s{i}",
                 "permission_mode": "default"}
            out = _hook(p, None)
            assert set(out or {}) == {"systemMessage"}, out
            msg = out["systemMessage"]
            assert msg.startswith("gateway: the managed shell isn't active in this session (the "
                                  "gateway's mod didn't start it"), msg
            assert "your commands run in your own shell, and the gateway still judges them" in msg
            assert _hook(p, None) is None, "once per session"
            out = _hook({**p, "session_id": f"o{i}"}, "/usr/local/bin/audit-log")
            assert "another shell prefix is set" in out["systemMessage"] and \
                "audit-log" in out["systemMessage"], out
            # the gateway's own gate-sh (by any spelling): no notice
            assert _hook({**p, "session_id": f"g{i}"}, str(GATE_SH)) is None
            assert _hook({**p, "session_id": f"h{i}"},
                         str(GATE_SH.parent / ".." / "hooks" / "gate-sh")) is None
            # no session id (no session to tell once): nothing
            assert _hook({k: v for k, v in p.items() if k != "session_id"}, None) is None
        # a refusal keeps its decision, with the notice beside it
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\nssh = false\n')
        out = _hook({"tool_name": "Bash", "tool_input": {"command": "ssh box ls"},
                     "session_id": "d1", "permission_mode": "default"}, None)
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny", out
        assert "managed shell isn't active" in out["systemMessage"], out


def test_a_written_warn_counts_as_on_and_off_gives_no_notice():
    """"warn" is gone (PLAN-0.11 §1.6): written, it is a mistake that counts
    as "on" (the notice); "off" (approved) gives none."""
    with H.gateway_env() as env:
        env.write_form('[shell]\nmanaged = "warn"\n')
        consent.approve("settings", form=env.form())
        p = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "session_id": "s1"}
        out = _hook(p, None)
        assert set(out or {}) == {"systemMessage"}, out
        assert vault.load()["approved"]["rights"]["settings"]["shell"]["managed"] == "on"
        env.write_form('[shell]\nmanaged = "off"\n')
        consent.approve("settings", form=env.form())
        assert _hook({**p, "session_id": "s4"}, None) is None
        # a form that says off without the OK: still on
        env.write_form('[shell]\nmanaged = "on"\n')
        consent.ratchet(env.form())
        env.write_form('[shell]\nmanaged = "off"\n')
        out = _hook({**p, "session_id": "s5"}, None)
        assert set(out or {}) == {"systemMessage"}, out


def test_jobs_and_the_terminal_panel_are_not_the_managed_shell():
    with H.gateway_env() as env:
        for tool in ("mcp__terminal__run_in_terminal", "mcp__plugin_check_jobs__job_start"):
            out = _hook({"tool_name": tool, "tool_input": {"command": "ls"}, "session_id": "s"}, None)
            assert out is None, (tool, out)


def _rig(td: Path):
    (td / "pre_bash.sh").write_text((H.PLUGIN / "hooks" / "pre_bash.sh").read_text())
    log = td / "launched"
    (td / "launch.sh").write_text(f'#!/bin/sh\nprintf "%s %s\\n" "$1" "${{GW_MANAGED_CHECK-unset}}" >> {sq(str(log))}\n'
                                  "cat > /dev/null\n")
    return td / "pre_bash.sh", log


def test_pre_bash_sends_only_its_trigger_words_to_python_whatever_the_prefix():
    """PLAN-0.11 §1.8: the GW_MANAGED_CHECK path is gone. Without the
    gateway's prefix a Bash or Monitor call reaches Python only for its
    trigger words, as with it."""
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as d:
        td = Path(d)
        pre, log = _rig(td)
        for tool in ("Bash", "Monitor", "mcp__terminal__run_in_terminal",
                     "mcp__plugin_check_jobs__job_start"):
            for prefix in (None, "/other/prefix", str(td / "gate-sh")):
                env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CODE_SHELL_PREFIX"}
                if prefix:
                    env["CLAUDE_CODE_SHELL_PREFIX"] = prefix
                for command, sent in (('echo "\\"tool_name\\": \\"Bash\\""', False),
                                      ("ssh box ls", True)):
                    log.unlink(missing_ok=True)
                    payload = json.dumps({"session_id": "s", "tool_name": tool,
                                          "tool_input": {"command": command}})
                    r = subprocess.run(["/bin/sh", str(pre)], input=payload, capture_output=True,
                                       text=True, env=env, timeout=15)
                    assert r.returncode == 0
                    if sent:
                        assert log.read_text() == "hook-bash unset\n", (tool, prefix)
                    else:
                        assert not log.exists(), (tool, prefix, command)
    assert "GW_MANAGED_CHECK" not in (H.PLUGIN / "hooks" / "pre_bash.sh").read_text()


def test_the_cold_guard_has_no_managed_refusal():
    """PLAN-0.11 §1.8: launch.sh's degraded_bash("managed") is gone, with
    envfile's text: a cold Bash call without the prefix gets no decision."""
    assert "managed" not in envfile.DEGRADED_BASH_WHAT
    text = (H.PLUGIN / "hooks" / "launch.sh").read_text()
    assert "GW_MANAGED_CHECK" not in text and "managed shell unavailable" not in text
    with H.gateway_env() as env:
        if H.any_env_ready():
            return
        p = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": str(env.root)}
        for extra in ({"GW_MANAGED_CHECK": "1"}, {}):
            r = H.run_launch(env, "hook-bash", payload=p, extra_env=extra)
            assert r.stdout == "", r


# ---------------------------------------------------------------------------


def test_host_inspect_reads_files_and_lists_folders_but_runs_and_imports_nothing():
    with H.gateway_env() as env:
        h = env.user_home
        ran = env.root / "rc-ran"
        canary = "ghp_" + os.urandom(12).hex()
        (h / ".zshrc").write_text(
            f': > {sq(str(ran))}\n'
            'export PATH="$HOME/.cargo/bin:$PATH"\n'
            'eval "$(/opt/homebrew/bin/brew shellenv)"\n'
            f'export GITHUB_TOKEN={canary}\n'
            'path+=(~/tools/bin)\n'
            'export PATH="$(some command):$PATH"\n')
        (h / ".profile").write_text('PATH=/opt/legacy/bin:"$PATH"; export PATH\n')
        (h / ".cargo" / "bin").mkdir(parents=True)
        (h / ".cargo" / "bin" / "cargo").write_text("")
        proj = env.root / "proj"
        proj.mkdir()
        (proj / ".python-version").write_text("3.12.4\n")
        (proj / ".nvmrc").write_text(f"{canary}\n")
        (proj / ".envrc").write_text(f"touch {ran}\n")
        (proj / "pyproject.toml").write_text('[project]\nrequires-python = ">=3.11"\n')
        env.write_form('[shell]\nimport_path = ["~/.cargo/bin"]\n')
        consent.approve("settings", form=env.form())
        os.environ["GW_TEST_VISIBLE"] = "1"
        os.environ["SOME_SECRET_TOKEN"] = "x"
        try:
            out = managed.inspect(None, str(proj))
        finally:
            os.environ.pop("GW_TEST_VISIBLE", None)
            os.environ.pop("SOME_SECRET_TOKEN", None)
        text = json.dumps(out)
        assert out["ok"] and canary not in text and not ran.exists()
        login = {e["dir"]: e for e in out["login_path"]}
        assert login["~/.cargo/bin"]["imported"] is True and "~/.zshrc line 2" in login["~/.cargo/bin"]["source"]
        assert "/opt/homebrew/bin" in login and "brew shellenv" in login["/opt/homebrew/bin"]["source"]
        assert "~/tools/bin" in login and "/opt/legacy/bin" in login
        assert not any("some command" in d for d in login)
        tc = {t["name"]: t for t in out["toolchains"]}
        assert tc["rustup/cargo"]["dirs"][0]["tools"] == ["cargo"]
        files = {f["file"]: f["says"] for f in out["project"]}
        assert files[".python-version"] == "version 3.12.4" and files[".nvmrc"] == "present"
        assert files[".envrc"].startswith("present (direnv") and files["pyproject.toml"] == "requires-python >=3.11"
        assert "GW_TEST_VISIBLE" not in out["env_names"] and "SOME_SECRET_TOKEN" not in out["env_names"]
        assert out["managed"]["path"][2]["dir"] == "~/.cargo/bin"
        bad = managed.inspect("buildbox", None)
        assert not bad["ok"] and "this machine only" in bad["error"]


def test_host_inspect_is_a_gw_tool_allowed_by_its_hook():
    from gateway import mcp_server
    names = [t["name"] for t in mcp_server.TOOLS]
    assert "host_inspect" in names
    payload = json.dumps({"tool_name": "mcp__plugin_gate_gw__host_inspect", "tool_input": {}})
    r = subprocess.run(["/bin/sh", str(H.PLUGIN / "hooks" / "mcp_perm.sh")], input=payload,
                       capture_output=True, text=True, timeout=15)
    assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "allow"


def test_the_session_context_tells_claude_where_its_commands_run():
    from gateway import hooks_session
    with H.gateway_env() as env:
        form, eff, data = hooks_session.prepare([], write=False)
        assert hooks_session.MANAGED_HOWTO in hooks_session.context_text(form, eff, {})
        env.write_form('[shell]\nmanaged = "off"\n')
        consent.approve("settings", form=env.form())
        form, eff, data = hooks_session.prepare([], write=False)
        assert hooks_session.MANAGED_HOWTO not in hooks_session.context_text(form, eff, {})
        assert len(hooks_session.context_text(form, eff, {})) <= hooks_session.CONTEXT_MAX


def test_tool_folders_found_but_not_imported_are_offered_and_listed_never_imported():
    """GW-UX-2b: a fresh install drops Homebrew, cargo, nvm and the like from
    Claude's PATH with no word about it. While the form has no [shell]
    import_path, Claude's context names the tool folders this machine has
    and says to propose importing them (one form edit, then the consent
    dialog); /gate-doctor (state.json) and `gate status` list them. Nothing
    is imported by finding them."""
    from gateway import hooks_session
    with world() as w:
        h = w.env.user_home
        for d, tool in ((".cargo/bin", "cargo"), (".nvm/versions/node/v20.11.1/bin", "npm"),
                        ("tools/bin", "mytool")):
            (h / d).mkdir(parents=True)
            (h / d / tool).write_text("")
        (h / "go" / "bin").mkdir(parents=True)                         # no programs in it
        (h / "evil folder" / "bin").mkdir(parents=True)                # not plain characters
        (h / "evil folder" / "bin" / "x").write_text("")
        (h / ".zshrc").write_text('export PATH="$HOME/tools/bin:$HOME/evil folder/bin:$PATH"\n')
        form, eff, data = hooks_session.prepare([], write=False)
        found = managed.found_not_imported(eff)
        for d in ("~/tools/bin", "~/.cargo/bin", "~/.nvm/versions/node/v20.11.1/bin"):
            assert d in found, (d, found)
        assert found.index("~/tools/bin") < found.index("~/.cargo/bin"), "the login PATH first"
        assert "~/go/bin" not in found and not any("evil" in d for d in found), found
        assert not set(found) & set(managed.SYSTEM_DIRS) and len(found) <= managed.FOUND_MAX
        ctx = hooks_session.context_text(form, eff, {})
        offer = next(ln for ln in ctx.splitlines() if ln.startswith("- Tool folders here"))
        assert "~/.cargo/bin" in offer and "propose importing" in offer and "gate check" in offer \
            and "Never import without that OK" in offer and len(ctx) <= hooks_session.CONTEXT_MAX, offer
        assert eff.shell.import_path == [] and str(h / ".cargo" / "bin") not in \
            [d for d, _ in managed.path_plan(eff)], "finding imports nothing"
        # the hosts and accounts come first: no room, no offer
        w.env.write_form("".join(f'[hosts.h{i:02d}]\naddress = "u@h{i:02d}.example.com"\n'
                                 for i in range(60)))
        form, eff, data = hooks_session.prepare([], write=False)
        ctx = hooks_session.context_text(form, eff, {})
        assert len(ctx) <= hooks_session.CONTEXT_MAX and "- Tool folders here" not in ctx and "h00" in ctx
        w.env.write_form("")
        form, eff, data = hooks_session.prepare([], write=False)
        w.sync()
        st = json.loads(managed.state_path().read_text())
        assert "~/.cargo/bin" in st["found"], st["found"]
        lines = managed.status_lines(eff)
        assert any(ln.startswith("  found here but not imported: ") and "~/.cargo/bin" in ln for ln in lines), lines
        # an import_path in the form (approved or not, even empty): no offer, and
        # what is imported isn't listed as missing
        w.env.write_form('[shell]\nimport_path = ["~/.cargo/bin"]\n')
        consent.approve("settings", form=w.env.form())
        form, eff, data = hooks_session.prepare([], write=False)
        assert "~/.cargo/bin" not in managed.found_not_imported(eff)
        assert "- Tool folders here" not in hooks_session.context_text(form, eff, {})
        w.env.write_form('[shell]\nimport_path = []\n')
        form, eff, data = hooks_session.prepare([], write=False)
        assert "- Tool folders here" not in hooks_session.context_text(form, eff, {})
        # managed "off": no offer either (Claude Code's own shell has the login PATH)
        w.env.write_form('[shell]\nmanaged = "off"\n')
        consent.approve("settings", form=w.env.form())
        form, eff, data = hooks_session.prepare([], write=False)
        assert "- Tool folders here" not in hooks_session.context_text(form, eff, {})


def test_tool_folders_already_on_the_managed_path_are_not_listed_as_found():
    """The GitHub install test of 0.11.0: gate status and /gate-doctor said
    "found here but not imported: ~/.local/bin, ~/.pixi/bin" (Debian) and
    /opt/local/bin (macOS), each needing the user's OK, though the managed
    shell's PATH held them already (Claude Code's own PATH, which the
    snapshot's PATH starts from). A folder on the PATH the process inherited
    is left out; one that isn't stays listed. gate-sh renews the settings
    with Claude Code's PATH, not its own helper PATH, so state.json (what
    /gate-doctor shows) leaves it out too; `gate status` in Claude's shell
    sees the managed PATH itself."""
    with world() as w:
        h = w.env.user_home
        for d in (".local/bin", ".cargo/bin"):
            (h / d).mkdir(parents=True)
            (h / d / "tool").write_text("")
        local = str(h / ".local" / "bin")
        form, eff, data = w.load()
        found = managed.found_not_imported(eff, path="/usr/bin:/bin")
        assert "~/.local/bin" in found and "~/.cargo/bin" in found, found
        found = managed.found_not_imported(eff, path=f"/usr/bin:{local}/:relative/bin:/bin")
        assert "~/.local/bin" not in found and "~/.cargo/bin" in found, found
        old = os.environ.get("PATH", "")
        try:                                    # this process's PATH by default (a hook's)
            os.environ["PATH"] = f"{local}:/usr/bin:/bin"
            found = managed.found_not_imported(eff)
            line = next(ln for ln in managed.status_lines(eff) if "found here but not imported" in ln)
        finally:
            os.environ["PATH"] = old
        assert "~/.local/bin" not in found and "~/.cargo/bin" in found, found
        assert "~/.local/bin" not in line and "~/.cargo/bin" in line, line
        # gate-sh's renewal (a newer gateway.toml) writes state.json with Claude Code's PATH
        snap = w.snapshot()
        for path, listed in ((f"{local}:/usr/bin:/bin:/usr/sbin:/sbin", False),
                             ("/usr/bin:/bin:/usr/sbin:/sbin", True)):
            w.sync()                 # the test's sync stub again (a renewal writes a plain one)
            w.env.write_form("# renewed\n")
            st = paths.form_path().stat()
            os.utime(paths.form_path(), (st.st_atime, managed.conf_path().stat().st_mtime + 5))
            r, _ = w.run("echo ran", snap=snap, extra={"PATH": path})
            assert r.returncode == 0 and r.stdout == "ran\n" and r.stderr == "", r
            assert managed.conf_path().stat().st_mtime > paths.form_path().stat().st_mtime, "renewed"
            got = json.loads(managed.state_path().read_text())["found"]
            assert ("~/.local/bin" in got) is listed and "~/.cargo/bin" in got, (path, got)


def test_gate_status_shows_the_managed_shell_with_every_origin():
    from gateway import gate
    with world() as w:
        w.env.write_form('[shell]\nimport_path = ["/opt/homebrew/bin"]\nimport_env = ["JAVA_HOME"]\n'
                         'managed = "off"\n')
        form, eff, data = w.load()
        text = gate.render_status(form, eff, data)
        assert "Managed shell: on (Claude's Bash runs in the gateway's bash 5 with your own " \
            "environment" in text, text
        assert 'gateway.toml says "off"; that waits for your OK (gate check settings)' in text
        assert "waiting for your OK: settings: managed shell" in text
        consent.approve("settings", form=w.env.form())
        form, eff, data = w.load()
        text = gate.render_status(form, eff, data)
        assert "Managed shell: off" in text
        assert "/opt/homebrew/bin  (gateway.toml [shell] import_path, line 2; Homebrew)" in text
        assert "[shell] import_env: JAVA_HOME (gateway.toml [shell] import_env, line 3)" in text
        assert "(the gateway's stand-ins)" in text and \
            "$PATH  (your own PATH (Claude Code's shell snapshot, else its own PATH))" in text
        assert "minus Claude Code's own credential variables" in text


def test_filechanged_renews_the_managed_settings_at_once():
    from gateway import hooks_filechanged
    with world() as w:
        w.env.write_form('[shell]\nimport_path = ["/opt/x/bin"]\n')
        consent.approve("settings", form=w.env.form())
        hooks_filechanged.record_seen(w.env.form())      # what SessionStart records
        assert "imports=/opt/x/bin\n" in managed.conf_path().read_text()
        w.env.write_form("[shell]\n")
        out = hooks_filechanged.main({"file_path": str(paths.form_path()), "cwd": str(w.env.root)})
        assert "imports=\n" in managed.conf_path().read_text()
        assert "PATH import /opt/x/bin removed" in (out or {}).get("systemMessage", ""), out


def test_session_start_writes_the_managed_files():
    from gateway import hooks_session
    with H.gateway_env() as env:
        assert not managed.conf_path().exists()
        hooks_session.session_main({"session_id": "s1"})
        assert managed.conf_path().exists() and managed.rc_path().exists()
        assert managed.load_state()["mode"] == "on"


def test_launch_sh_writes_the_managed_files_once_a_build_finishes():
    """Right after the build, before the warm-up (seconds on macOS): gate-sh
    refuses every command until they exist. An env whose setup was
    interrupted after the build (no conf) gets them at the next ensure-env,
    and a missing gateway.toml with them (--setup)."""
    text = (H.PLUGIN / "hooks" / "launch.sh").read_text()
    assert '[ "$rc" -eq 0 ] && { managed_sync; warm_env; cleanup_envs; }' in text
    assert 'if ready; then [ -f "$DATA/managed/conf" ] || managed_sync; warm_env; cleanup_envs; return 0; fi' in text
    assert '"$PY" -I -S -X "pycache_prefix=$PYC" "$ROOT/run.py" managed-sync --setup </dev/null' in text


def test_the_first_setup_writes_the_starter_form_when_it_finishes():
    """The first session's SessionStart runs before any env can run Python
    (launch.sh's degraded path), so gateway.toml appeared only when the next
    session started, though the README says the first session creates it
    (the GitHub install test of 0.11.0: /gate-doctor said "not written yet"
    after ready). launch.sh runs `managed-sync --setup` once the build is
    done: a missing form is written as SessionStart writes it (the starter;
    the vault's last good form; nothing over approvals it can't restore,
    nothing beside a 0.6 vault), before conf, so gate-sh doesn't renew at
    the first command. Without --setup (gate-sh's renewal, an approval) a
    missing form stays missing."""
    with H.gateway_env(entry=None, pixi="") as env:
        env.o.entry = H.entry_cmd(env)
        assert managed.sync_now() == 0 and not paths.form_path().exists()
        r = subprocess.run([str(managed.sync_path()), "--setup"], capture_output=True, text=True,
                           env=env.subprocess_env(), timeout=60)     # run.py managed-sync --setup
        assert r.returncode == 0, r
        assert paths.form_path().read_text() == F.STARTER
        assert managed.conf_path().stat().st_mtime > paths.form_path().stat().st_mtime
        # a form there is left as it is
        env.write_form("# mine\n")
        assert managed.sync_now(setup=True) == 0 and paths.form_path().read_text() == "# mine\n"
        # a vault with a last good form: that one, never the starter
        form = '[hosts.box]\naddress = "u@box.example.com"\n'
        env.write_form(form)
        vault.save(vault.empty())
        consent.approve_all(env.form())
        with vault.edit() as d:
            d["form_last_good"] = form
        paths.form_path().unlink()
        assert managed.sync_now() == 0 and not paths.form_path().exists()
        managed.sync_now(setup=True)
        assert paths.form_path().read_text() == form
        # approvals and no copy: left missing (no starter over them)
        with vault.edit() as d:
            d["form_last_good"] = None
        paths.form_path().unlink()
        managed.sync_now(setup=True)
        assert not paths.form_path().exists()
    with H.gateway_env() as env:                     # a 0.6 vault waiting for 0.10.0's conversion
        paths.ensure_private()
        paths.v2_store_path().write_text("age-encrypted 0.6 store\n")
        managed.sync_now(setup=True)
        assert not paths.form_path().exists()


def test_bash_c_with_a_socket_on_stdin_sources_bashrc_at_shell_level_1_and_shlvl_1_stops_it():
    """Claude Code starts the shell that runs the prefix as `<shell> -c ...`
    with stdin a socket. bash then counts itself started by sshd/rshd
    (upstream bash's isnetconn check; Debian's also looks at SSH_CLIENT) and
    sources ~/.bashrc before the command whenever its shell level is 1: SHLVL
    unset, 0 or garbage in Claude Code's environment (a launcher, a service,
    the TUI harness). The rc's variables never reach a command (gate-sh
    removes them), but its lines run (the GitHub install test on Debian,
    0.9.0). From SHLVL 1 on bash doesn't, which is why the mod sets SHLVL=1
    where it is missing (register.tsx managedSetup, lib.ts shlvlOk; the mod's
    tests check that). This pins the platform fact, for the env's bash (the
    managed bash, CLAUDE_CODE_SHELL) and the system's."""
    import socket
    shells = [BASH] + [Path(b) for b in ("/bin/bash", "/usr/bin/bash") if Path(b).is_file()][:1]
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as d:
        home = Path(d) / "home"
        home.mkdir()
        log = Path(d) / "rc.log"
        (home / ".bashrc").write_text(f'echo "rc $$" >> {sq(str(log))}\n')
        for bash in shells:
            for shlvl, stdin_kind, sourced in ((None, "socket", True), ("0", "socket", True),
                                               ("x", "socket", True), ("1", "socket", False),
                                               ("2", "socket", False), (None, "pipe", False)):
                log.write_text("")
                env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LANG": "C"}
                if shlvl is not None:
                    env["SHLVL"] = shlvl
                a, b = socket.socketpair() if stdin_kind == "socket" else os.pipe()
                try:
                    r = subprocess.run([str(bash), "-c", "echo ran"], stdin=a, env=env,
                                       capture_output=True, text=True, timeout=30)
                finally:
                    for x in (a, b):
                        x.close() if hasattr(x, "close") else os.close(x)
                assert r.returncode == 0 and r.stdout.strip() == "ran", (bash, r.stderr)
                assert bool(log.read_text().strip()) is sourced, (str(bash), shlvl, stdin_kind)


def test_a_gateway_terminal_keeps_the_users_variables_minus_the_removals():
    """Invariant 18 (PLAN-0.11 §11): a pane's environment is the caller's
    (the gw MCP server's, Claude Code's) minus the managed shell's removals;
    its PATH is the stand-ins, the caller's PATH, the approved imports. The
    MCP server sends only what gated may take."""
    from gateway import mcp_server
    from gateway.daemon import terminals
    with world() as w:
        imp = w.env.root / "imp"
        imp.mkdir()
        w.env.write_form(f'[shell]\nimport_path = ["{imp}"]\n')
        w.sync()
        consent.approve("settings", form=w.env.form())
        caller = {"PATH": "/opt/user/bin:/usr/bin:/bin", "GH_TOKEN": "gho_user",
                  "SSH_AUTH_SOCK": "/tmp/agent", "JAVA_HOME": "/jdk", "LANG": "C.UTF-8",
                  "CLAUDE_CODE_OAUTH_TOKEN": "tok", "ANTHROPIC_API_KEY": "sk", "BASH_ENV": "/x",
                  "GW_PASSTHRU": "x", "GW_MANAGED_DIR": str(managed.managed_dir()),
                  "HOME": "/elsewhere", "SHELL": "/bin/zsh", "TERM": "dumb", "CLAUDE_PID": "1",
                  "BAD-NAME": "x", "NUL": "a\x00b"}
        bash, rc, exports, path = terminals.env_plan(caller)
        assert bash == str(paths.env_bin() / "bash") and rc == str(managed.rc_path())
        assert {k: exports[k] for k in ("GH_TOKEN", "SSH_AUTH_SOCK", "JAVA_HOME", "LANG",
                                        "GW_MANAGED_DIR")} == {k: caller[k] for k in (
            "GH_TOKEN", "SSH_AUTH_SOCK", "JAVA_HOME", "LANG", "GW_MANAGED_DIR")}, exports
        for n in ("CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "BASH_ENV", "GW_PASSTHRU",
                  "TERM", "CLAUDE_PID", "BAD-NAME", "NUL", "PATH"):
            assert n not in exports, n
        assert exports["HOME"] == str(paths.user_home()) and exports["SHELL"] == bash
        assert path == ":".join([str(paths.bin_dir()), "/opt/user/bin", "/usr/bin", "/bin", str(imp)])
        # no PATH from the caller: the system folders
        assert terminals.env_plan({})[3] == ":".join([str(paths.bin_dir()), *managed.SYSTEM_DIRS,
                                                       str(imp)])
        keep = dict(os.environ)
        try:
            os.environ.update({"GW_TEST_PANE_VAR": "x", "MY_PANE_VAR": "y",
                               "CLAUDE_CODE_OAUTH_TOKEN": "tok"})
            sent = mcp_server.terminal_env()
        finally:
            os.environ.clear()
            os.environ.update(keep)
        assert sent["MY_PANE_VAR"] == "y" and "GW_TEST_PANE_VAR" not in sent \
            and "CLAUDE_CODE_OAUTH_TOKEN" not in sent, sorted(sent)
