"""Managed execution (PLAN-v4 phase 4, docs/modules/managed.md): hooks/gate-sh
(the CLAUDE_CODE_SHELL_PREFIX the mod sets), managed.py (its settings, rc,
state and the host inspection), the [shell] form section and its consent,
the classic Bash hook's "managed shell unavailable" path, and the session
context and `gate status` lines.

gate-sh is driven the way Claude Code 2.1.301 drives a prefix (recorded in
FEASIBILITY-v4 P2 and this phase's probes): `/bin/sh -c "'<prefix>'
'<string>'"` for a classic hook (and an MCP server's quoted argv), and
`<shell> -c "'<prefix>' '<script>'"` for a Bash-tool script of the shape
`source <snapshot> 2>/dev/null || true && <env-file text>\n: && ... && eval
'<command>' [< /dev/null] && pwd -P >| <cwd file>`."""
from __future__ import annotations

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
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/nonexistent-home",
           "USER": "tester", "LOGNAME": "tester", "LANG": "C.UTF-8", "TERM": "xterm",
           "CLAUDE_CODE_SHELL_PREFIX": str(GATE_SH)}
    env.update(extra or {})
    return env


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
                 "alias ll='ls -l'", "export SNAPVAR=from-the-snapshot",
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
    import contextlib

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
    fixed = re.search(r"^GW_PASS='([^']*)'$", text, re.M).group(1).split()
    assert fixed == list(managed.PLATFORM_NAMES) + list(managed.CLAUDE_NAMES) + \
        list(managed.GATEWAY_NAMES), fixed
    cred = re.search(r"gw_credlike\(\) \{\n  case \$1 in\n  (.*?)\) return 0", text, re.S).group(1)
    words = [w.strip().strip("*") for w in cred.split("|")]
    assert words == list(managed.CREDENTIAL_WORDS), words
    # the passed names, in the form's own list too (import_env refuses them)
    for n in managed.PLATFORM_NAMES + managed.CLAUDE_NAMES:
        assert F.SHELL_PASSED.fullmatch(n), n
    # import_env refuses every name gate-sh would drop as credential-looking
    for w_ in managed.CREDENTIAL_WORDS:
        assert F.CREDENTIAL_NAME.fullmatch(f"MY_{w_}_X") and managed.credential_like(f"MY_{w_}_X"), w_


# ---------------------------------------------------------------------------
# gate-sh: Bash-tool scripts run in the managed bash, never the snapshot
# ---------------------------------------------------------------------------


def test_tool_scripts_run_in_the_managed_bash_with_the_gateway_rc_not_the_snapshot():
    with world() as w:
        # launchers: Claude Code starts the prefix from the user's shell (bash or zsh) or,
        # once the env is built, from the managed bash (CLAUDE_CODE_SHELL)
        launchers = [("bash", "/bin/sh"), ("bash", str(BASH))]
        launchers += [(sh, f"/bin/{sh}") for sh in ("bash", "zsh") if os.path.exists(f"/bin/{sh}")]
        for shell, launcher in launchers:
            snap = w.snapshot(shell)
            w.marker.unlink(missing_ok=True)
            r, cwdfile = w.run('echo "B=$BASH_VERSION Z=${ZSH_VERSION-} S=${SNAPVAR-} E=${ENVFILEVAR-}"; '
                               "type userfunc 2>&1 | head -n 1; alias ll 2>&1 | head -n 1; "
                               'echo "G=${GIT_SSH_COMMAND-}"; echo "SHELL=$SHELL"; cd /; echo moved',
                               snap=snap, envfile_text="export ENVFILEVAR=from-an-env-file",
                               launcher=launcher)
            assert r.returncode == 0, r
            lines = r.stdout.splitlines()
            assert lines[0].startswith("B=5.") and " Z= S= E=from-an-env-file" in lines[0], lines
            assert "not found" in lines[1] and "not found" in lines[2], lines
            assert lines[3] == f"G={paths.bin_dir() / 'ssh'}", lines       # the gateway rc ran
            assert lines[4] == f"SHELL={paths.env_bin() / 'bash'}", lines
            assert not w.marker.exists(), "the snapshot was sourced"
            assert cwdfile.read_text().strip() == "/", "the cwd tracker ran (pwd -P after cd)"


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
        # without a snapshot (Claude Code couldn't make one): the same, rc first
        r, _ = w.run('echo "G=${GIT_SSH_COMMAND-}"', snap=None)
        assert r.returncode == 0 and r.stdout.strip() == f"G={paths.bin_dir() / 'ssh'}", r


def test_the_curated_environment_has_only_platform_claude_and_approved_variables():
    with world() as w:
        snap = w.snapshot()
        bash_env = w.env.root / "bash-env.sh"
        bash_env.write_text(f": > {sq(str(w.env.root / 'bash-env-ran'))}\n")
        host = {
            "PATH": "/opt/user/bin:/usr/local/bin:/usr/bin:/bin", "HOME": "/home/x", "USER": "x",
            "LOGNAME": "x", "LANG": "en_US.UTF-8", "LC_CTYPE": "UTF-8", "LC_ALL": "C.UTF-8",
            "TERM": "xterm-256color", "TZ": "UTC", "XDG_CONFIG_HOME": "/home/x/.cfg",
            "XDG_RUNTIME_DIR": "/run/user/1", "CLAUDECODE": "1", "CLAUDE_PID": "123",
            "CLAUDE_CODE_SESSION_ID": "s-1", "CLAUDE_CODE_ENTRYPOINT": "cli", "GIT_EDITOR": "true",
            "AI_AGENT": "claude-code", "COREPACK_ENABLE_AUTO_PIN": "0",
            "CLAUDE_CODE_OAUTH_TOKEN": "tok", "CLAUDE_CODE_MESSAGING_TOKEN": "tok2",
            "ANTHROPIC_API_KEY": "sk", "GITHUB_TOKEN": "ghp", "AWS_SECRET_ACCESS_KEY": "aws",
            "SSH_AUTH_SOCK": "/tmp/agent", "MY_SETTING": "1", "JAVA_HOME": "/jdk",
            "BASH_ENV": str(bash_env), "ENV": str(bash_env), "PROMPT_COMMAND": "echo pc",
            "SHELLOPTS": "xtrace", "CDPATH": "/", "PYTHONPATH": "/py", "SHLVL": "4",
            "HTTPS_PROXY": "http://u:p@proxy:1",
            # names no shell variable can have (bash passes them on, dash drops them): removed too
            "WEIRD-NAME": "x", "BASH_FUNC_userfn%%": "() { echo hijacked; }",
        }
        r, _ = w.run("env | sed 's/=.*//' | LC_ALL=C sort; echo PATH=$PATH", snap=snap, extra=host)
        assert r.returncode == 0, r
        out = r.stdout.splitlines()
        names = set(out[:-1])
        expected = {"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_CTYPE", "LC_ALL", "TERM", "TZ",
                    "XDG_CONFIG_HOME", "XDG_RUNTIME_DIR", "TMPDIR", "PWD", "SHELL", "SHLVL", "_",
                    "CLAUDECODE", "CLAUDE_PID", "CLAUDE_CODE_SESSION_ID", "CLAUDE_CODE_ENTRYPOINT",
                    "CLAUDE_CODE_SHELL_PREFIX", "GIT_EDITOR", "AI_AGENT", "COREPACK_ENABLE_AUTO_PIN",
                    "GW_MANAGED_DIR",
                    # set by the gateway rc (the env file's text)
                    "GW_GITCFG_SET", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
                    "GIT_SSH_COMMAND", "RSYNC_RSH"}
        assert names == expected, (names - expected, expected - names)
        want_path = ":".join([str(paths.bin_dir()), str(managed.runtime_dir()), *managed.SYSTEM_DIRS])
        assert out[-1] == f"PATH={want_path}", out[-1]
        assert not (w.env.root / "bash-env-ran").exists(), "BASH_ENV/ENV ran"


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
    """CLAUDE_CODE_CLIENT_KEY_PASSPHRASE passed (PASSW isn't in PASSPHRASE),
    and the mTLS key and certificate paths and HOST_CREDS_FILE with it."""
    with world() as w:
        snap = w.snapshot()
        canary = "cc-" + os.urandom(16).hex()
        # each credential word on its own, in a CLAUDE_* name (which would pass otherwise)
        probes = tuple(f"CLAUDE_GW_{w_}_PROBE" for w_ in managed.CREDENTIAL_WORDS)
        host = {n: f"{canary}-{i}" for i, n in enumerate(CC_CREDENTIAL_NAMES + probes)}
        host["CLAUDE_CODE_SESSION_ID"] = "s-1"       # an ordinary CLAUDE_* name still passes
        r, _ = w.run("env", snap=snap, extra=host)
        assert r.returncode == 0, r.returncode
        names = {ln.split("=", 1)[0] for ln in r.stdout.splitlines() if "=" in ln}
        assert "CLAUDE_CODE_SESSION_ID" in names
        leaked = sorted(n for n in CC_CREDENTIAL_NAMES + probes if n in names)
        assert not leaked and canary not in r.stdout, leaked
        for n in CC_CREDENTIAL_NAMES:
            assert managed.credential_like(n) or not n.startswith(("CLAUDE_", "LC_")), n


def _argv_recorder(w: World) -> tuple[Path, Path]:
    """A copy of gate-sh whose env records its arguments, then runs as before."""
    rec = w.env.root / "env-argv"
    fake = w.env.root / "recording-env"
    fake.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" >> {sq(str(rec))}\nexec /usr/bin/env \"$@\"\n")
    os.chmod(fake, 0o755)
    text = GATE_SH.read_text()
    assert text.count("exec /usr/bin/env ") == 1
    copy = w.env.root / "gate-sh-recording"
    copy.write_text(text.replace("exec /usr/bin/env ", f"exec {sq(str(fake))} "))
    os.chmod(copy, 0o755)
    return copy, rec


def test_no_value_reaches_a_command_line():
    """Every local user can read a process's arguments (ps, /proc/PID/cmdline);
    only the owner its environment. gate-sh passed the curated variables as
    NAME=VALUE arguments to env -i, so the user's own tokens (others = "mine"),
    approved imports and Claude Code's variables were readable by anyone
    (verifier, phase 4 review: a canary GITHUB_TOKEN seen in /usr/bin/env's
    /proc cmdline on Debian). Only names reach env's arguments now; the values
    still reach the command through its environment."""
    with world() as w:
        snap = w.snapshot()
        w.env.write_form('[settings]\nothers = "mine"\n[shell]\nimport_env = ["JAVA_HOME"]\n')
        w.sync()
        consent.approve("settings", form=w.env.form())
        canary = os.urandom(16).hex()
        vals = {"GITHUB_TOKEN": f"ghp_{canary}a", "JAVA_HOME": f"/jdk-{canary}b",
                "CLAUDE_CODE_SESSION_ID": f"s-{canary}c", "TZ": f"tz{canary}d",
                "SSH_AUTH_SOCK": f"/tmp/agent-{canary}e"}
        show = "; ".join(f'echo "{n}=${{{n}-}}"' for n in vals)
        copy, rec = _argv_recorder(w)
        cwdfile = w.tmp / "claude-ab12-cwd"
        script = tool_script(show, snap=str(snap), cwdfile=str(cwdfile))
        r = through_prefix(script, w.launch_env({**vals, "MY_OTHER_VAR": "x"}), w.work, prefix=copy)
        assert r.returncode == 0, r.returncode
        got = dict(ln.split("=", 1) for ln in r.stdout.splitlines() if "=" in ln)
        assert [n for n in vals if got.get(n) != vals[n]] == [], "a value didn't reach the command"
        argv = rec.read_text()
        assert canary not in argv, [n for n, v in vals.items() if v in argv]
        # env's own arguments: `-u NAME` pairs, then only PATH= and SHELL=, then the managed bash
        args = argv.split("\n")
        opts = args[:args.index(str(paths.env_bin() / "bash"))]
        sets = [a for a in opts if "=" in a]
        assert [a.split("=", 1)[0] for a in sets] == ["PATH", "SHELL"], [a.split("=", 1)[0] for a in sets]
        rest = [a for a in opts if "=" not in a]
        assert rest[0::2] == ["-u"] * len(rest[0::2]) and "GITHUB_TOKEN" not in rest[1::2] \
            and "CLAUDE_CODE_SESSION_ID" not in rest[1::2] and "MY_OTHER_VAR" in rest[1::2], rest
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
                    r = through_prefix(script, w.launch_env(vals), w.work)
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
    with 75). GW_MANAGED_DIR passes now, so they run managed too."""
    with world() as w:
        snap = w.snapshot()
        canary = "cc-" + os.urandom(16).hex()
        inner = tool_script('echo "inner G=${GIT_SSH_COMMAND-} S=${SNAPVAR-} M=${GW_MANAGED_DIR-}"; env',
                            snap=str(snap), cwdfile=str(w.tmp / "claude-1nnr-cwd"))
        f = w.env.root / "inner-script"
        f.write_text(sq(inner))
        # what the nested Claude Code does: <its shell> -c "'<its prefix>' '<script>'"
        outer = f'"$CLAUDE_CODE_SHELL" -c "\'$CLAUDE_CODE_SHELL_PREFIX\' $(cat {sq(str(f))})"'
        r, _ = w.run(outer, snap=snap, extra={"CLAUDE_CODE_SHELL": str(BASH),
                                              "CLAUDE_CODE_OAUTH_TOKEN": canary})
        assert r.returncode == 0 and "isn't ready" not in r.stderr, (r.returncode, r.stderr)
        lines = r.stdout.splitlines()
        assert lines[0] == f"inner G={paths.bin_dir() / 'ssh'} S= M={managed.managed_dir()}", lines[0]
        names = {ln.split("=", 1)[0] for ln in lines[1:] if "=" in ln}
        assert {"CLAUDE_CODE_SHELL_PREFIX", "CLAUDE_CODE_SHELL", "GW_MANAGED_DIR"} <= names, names
        assert "CLAUDE_CODE_OAUTH_TOKEN" not in names and canary not in r.stdout
        # without GW_MANAGED_DIR (a prefix set by hand): refused, and the message says why
        r = through_prefix(inner, base_env({"TMPDIR": str(w.tmp)}), w.work)
        assert r.returncode == 75 and "GW_MANAGED_DIR is missing or not an absolute path" in r.stderr \
            and "unset CLAUDE_CODE_SHELL_PREFIX and CLAUDE_CODE_SHELL" in r.stderr, r


def test_approved_imports_reach_the_command_and_unapproved_ones_do_not():
    with world() as w:
        snap = w.snapshot()
        imp = w.env.root / "imported dir"
        imp.mkdir()
        w.env.write_form(f'[shell]\nimport_path = ["{imp}", "/opt/homebrew/bin"]\n'
                         'import_env = ["JAVA_HOME"]\n')
        w.sync()
        r, _ = w.run('echo "J=${JAVA_HOME-}"; echo "$PATH"', snap=snap, extra={"JAVA_HOME": "/jdk"})
        assert r.stdout.splitlines()[0] == "J=", "not approved yet: no import"
        assert str(imp) not in r.stdout
        consent.approve("settings", form=w.env.form())
        r, _ = w.run('echo "J=${JAVA_HOME-}"; echo "$PATH"', snap=snap, extra={"JAVA_HOME": "/jdk"})
        lines = r.stdout.splitlines()
        assert lines[0] == "J=/jdk", r
        assert lines[1] == ":".join([str(paths.bin_dir()), str(managed.runtime_dir()), str(imp),
                                     "/opt/homebrew/bin", *managed.SYSTEM_DIRS]), lines[1]
        # others = "mine" (approved): the user's own agent variable passes too
        w.env.write_form(f'[settings]\nothers = "mine"\n[shell]\nimport_env = ["JAVA_HOME"]\n')
        w.sync()
        r, _ = w.run('echo "A=${SSH_AUTH_SOCK-}"', snap=snap, extra={"SSH_AUTH_SOCK": "/tmp/ag"})
        assert r.stdout == "A=\n", "others = mine waits for the OK"
        consent.approve("settings", form=w.env.form())
        r, _ = w.run('echo "A=${SSH_AUTH_SOCK-}"', snap=snap, extra={"SSH_AUTH_SOCK": "/tmp/ag"})
        assert r.stdout == "A=/tmp/ag\n", r


def test_other_plugins_bin_folders_from_the_snapshot_come_last_and_nothing_else_of_its_path():
    with world() as w:
        plug = w.env.root / "a plugin's dir" / "probe"
        (plug / ".claude-plugin").mkdir(parents=True)
        (plug / ".claude-plugin" / "plugin.json").write_text("{}")
        (plug / "bin").mkdir()
        (plug / "bin" / "probe-tool").write_text("#!/bin/sh\necho probe-tool-ran\n")
        os.chmod(plug / "bin" / "probe-tool", 0o755)
        notplug = w.env.root / "user" / "bin"
        notplug.mkdir(parents=True)
        line = ("export PATH=" + sq(f"/opt/user/bin:{notplug}:/usr/bin:{plug}/bin:/bin"))
        snap = w.snapshot(path_line=line)
        r, _ = w.run('echo "$PATH"; probe-tool', snap=snap)
        assert r.returncode == 0, r
        path, ran = r.stdout.splitlines()
        assert path.split(":")[-1] == f"{plug}/bin" and str(notplug) not in path \
            and "/opt/user/bin" not in path, path
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
                and "never falls back to your own shell" in r.stderr, (script, r)
            assert not done.exists(), f"ran: {script}"
            assert not w.marker.exists()
        r = through_prefix(good, w.launch_env(), w.work)
        assert r.returncode == 0 and done.exists(), r


def test_an_unready_managed_shell_refuses_and_never_falls_back():
    with world() as w:
        snap = w.snapshot()
        done = w.env.root / "ran"
        script = tool_script(f": > {sq(str(done))}", snap=str(snap),
                             cwdfile=str(w.tmp / "claude-ab12-cwd"))
        conf = managed.conf_path().read_text()

        def check(env, why):
            done.unlink(missing_ok=True)
            r = through_prefix(script, env, w.work)
            assert r.returncode == 75 and "isn't ready" in r.stderr and why in r.stderr, (why, r)
            assert not done.exists() and not w.marker.exists()
        check(base_env({"TMPDIR": str(w.tmp)}), "didn't name its managed-shell folder")
        check(w.launch_env({"GW_MANAGED_DIR": "managed"}), "didn't name its managed-shell folder")
        managed.conf_path().unlink()
        check(w.launch_env(), "haven't been written yet")
        managed.conf_path().write_text(conf.replace(f"bash={BASH.parent}", "bash=/nowhere")
                                       .replace(f"bash={paths.env_bin()}", "bash=/nowhere"))
        check(w.launch_env(), "still being set up")
        managed.conf_path().write_text(conf)
        managed.rc_path().unlink()
        check(w.launch_env(), "its rc file is missing")
        w.sync()
        r = through_prefix(script, w.launch_env(), w.work)
        assert r.returncode == 0 and done.exists(), r


def test_a_newer_form_renews_the_settings_before_the_command_so_a_narrowing_applies():
    with world() as w:
        snap = w.snapshot()
        w.env.write_form('[shell]\nimport_env = ["JAVA_HOME"]\n')
        w.sync()
        consent.approve("settings", form=w.env.form())
        r, _ = w.run('echo "J=${JAVA_HOME-}"', snap=snap, extra={"JAVA_HOME": "/jdk"})
        assert r.stdout == "J=/jdk\n", r
        # the import removed (a narrowing) and FileChanged not run: gate-sh
        # sees the newer form and renews first (the sync stub, run.py managed-sync)
        time.sleep(0.05)
        w.env.write_form("[shell]\n")
        st = paths.form_path().stat()
        os.utime(paths.form_path(), (st.st_atime, managed.conf_path().stat().st_mtime + 5))
        r, _ = w.run('echo "J=${JAVA_HOME-}"', snap=snap, extra={"JAVA_HOME": "/jdk"})
        assert (r.returncode, r.stdout) == (0, "J=\n"), r
        # renewing impossible (no sync stub): refused, not run with stale settings
        os.utime(paths.form_path(), (st.st_atime, managed.conf_path().stat().st_mtime + 5))
        managed.sync_path().unlink()
        r, _ = w.run("echo ran", snap=snap)
        assert r.returncode == 75 and "couldn't be renewed" in r.stderr and r.stdout == "", r


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
        assert conf["bash"] == str(paths.env_bin() / "bash")
        assert conf["rc"] == str(managed.rc_path())
        assert conf["form"] == str(paths.form_path()) and conf["sync"] == str(managed.sync_path())
        assert conf["env"] == "" and conf["mine"] == ""
        assert os.readlink(managed.runtime_dir() / "bash") == str(paths.env_bin() / "bash")
        assert not (managed.runtime_dir() / "pixi").exists()     # the override: no pixi
        stub = managed.sync_path().read_text()
        assert "managed-sync" in stub and os.access(managed.sync_path(), os.X_OK)
        st = json.loads(managed.state_path().read_text())
        assert st["mode"] == "on" and st["bash_version"].startswith("5.") and st["ready"] is True
        assert [p["origin"] for p in st["path"]][:2] == ["the gateway's stand-ins",
                                                         "the gateway's runtime tools (bash, pixi)"]
        rc = managed.rc_path().read_text()
        assert envfile.env_text("refuse") in rc and rc.rstrip().endswith(":")
        assert not re.search(r"(^|\s)(source|\.)\s+[~$]", rc), "the rc sources no user file"
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


def test_pixi_is_a_runtime_tool_when_found():
    with world() as w:
        fake = w.env.root / "pixi-home" / "pixi"
        fake.parent.mkdir()
        fake.write_text("#!/bin/sh\necho pixi 0.0.0\n")
        os.chmod(fake, 0o755)
        with testing.override(w.env.root, pixi=str(fake), entry=w.env.o.entry,
                              machine_id="TEST-MACHINE-0001", system_git=True):
            form, eff, _ = w.load()
            managed.sync(form, eff)
            assert os.readlink(managed.runtime_dir() / "pixi") == str(fake)
            r, _ = w.run("pixi --version", snap=w.snapshot())
            assert r.stdout == "pixi 0.0.0\n", r


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
        assert f.shell.managed == "warn" and not f.shell.managed_invalid
        assert f.shell.import_path == ["/opt/homebrew/bin", str(env.user_home / ".cargo" / "bin")]
        assert f.shell.import_env == ["JAVA_HOME", "GOPATH"]
        msgs = [p.render() for p in f.problems]
        for needle in ("must be absolute", "holds a ':'", "listed twice", "gateway's own folder",
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
    e = run("", '[shell]\nmanaged = "warn"\n')
    assert e.shell.managed == "on" and e.pending_for("settings")
    e = run('[shell]\nmanaged = "off"\n', '[shell]\nmanaged = "warn"\n')
    assert e.shell.managed == "warn" and not e.pending and e.narrowed[0].what == 'managed shell "off" -> "warn"'
    e = run("", '[shell]\nimport_path = ["/opt/x/bin"]\nimport_env = ["JAVA_HOME"]\n')
    assert e.shell.import_path == [] and e.shell.import_env == []
    assert sorted(c.what.split(" (")[0] for c in e.pending) == ["PATH import /opt/x/bin",
                                                                 "environment import JAVA_HOME"]
    old = '[shell]\nimport_path = ["/opt/x/bin", "/opt/y/bin"]\nimport_env = ["JAVA_HOME"]\n'
    e = run(old, '[shell]\nimport_path = ["/opt/y/bin"]\n')
    assert e.shell.import_path == ["/opt/y/bin"] and e.shell.import_env == [] and not e.pending
    assert {c.what for c in e.narrowed} == {"PATH import /opt/x/bin removed",
                                            "environment import JAVA_HOME removed"}
    # a bad mode keeps the approved one, nothing ratchets
    e = run('[shell]\nmanaged = "off"\n', '[shell]\nmanaged = "nope"\n')
    assert e.shell.managed == "off" and not e.narrowed and not e.pending
    # an approval from before phase 4 has no shell part: the defaults
    e = consent.compute(F.parse_text('[shell]\nmanaged = "off"\n'),
                        {"approved": {"rights": {"settings": {"others": "refuse"}, "hosts": {},
                                                 "accounts": {}}}})
    assert e.shell.managed == "on" and e.pending


def test_approval_and_the_ratchet_keep_the_shell_settings():
    with H.gateway_env() as env:
        env.write_form('[shell]\nmanaged = "warn"\nimport_path = ["/opt/x/bin"]\n')
        consent.approve("settings", form=env.form())
        data = vault.load()
        sh = data["approved"]["rights"]["settings"]["shell"]
        assert sh == {"managed": "warn", "import_path": ["/opt/x/bin"], "import_env": []}
        assert managed.load_state()["mode"] == "warn", "approve() renewed the managed files"
        # a narrowing (others stays "refuse", an import removed) keeps the shell part
        env.write_form('[shell]\nmanaged = "warn"\n')
        consent.ratchet(env.form())
        sh = vault.load()["approved"]["rights"]["settings"]["shell"]
        assert sh == {"managed": "warn", "import_path": [], "import_env": []}, sh
        env.write_form("")
        consent.ratchet(env.form())
        sh = vault.load()["approved"]["rights"]["settings"]["shell"]
        assert sh["managed"] == "on", "raising managed back to on is a narrowing, ratcheted"


# ---------------------------------------------------------------------------
# The classic Bash hook when the prefix isn't the gateway's
# ---------------------------------------------------------------------------


def _hook(payload: dict, prefix: str | None) -> dict | None:
    from gateway import hooks_bash
    keep = {k: os.environ.get(k) for k in ("GW_MANAGED_CHECK", "CLAUDE_CODE_SHELL_PREFIX")}
    os.environ["GW_MANAGED_CHECK"] = "1"
    if prefix is None:
        os.environ.pop("CLAUDE_CODE_SHELL_PREFIX", None)
    else:
        os.environ["CLAUDE_CODE_SHELL_PREFIX"] = prefix
    try:
        return hooks_bash.main(payload)
    finally:
        for k, v in keep.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def test_without_the_prefix_managed_mode_denies_bash_and_monitor_with_the_reason():
    with H.gateway_env() as env:
        for tool, ti in (("Bash", {"command": "ls"}), ("Bash", {"command": "ls", "run_in_background": True}),
                         ("Monitor", {"command": "tail -f x", "description": "x"})):
            p = {"tool_name": tool, "tool_input": ti, "session_id": "s1", "permission_mode": "default"}
            out = _hook(p, None)
            hso = out["hookSpecificOutput"]
            assert hso["permissionDecision"] == "deny", out
            assert hso["permissionDecisionReason"].startswith("gateway: managed shell unavailable: the "
                                                              "gateway's mod didn't start it"), out
            assert "Claude Code's mods on" in hso["permissionDecisionReason"]
            out = _hook(p, "/usr/local/bin/audit-log")
            assert "another shell prefix is set" in out["hookSpecificOutput"]["permissionDecisionReason"]
            assert "audit-log" in out["hookSpecificOutput"]["permissionDecisionReason"]
            # the gateway's own gate-sh (by any spelling): judged as usual, no managed deny
            assert _hook(p, str(GATE_SH)) is None
            assert _hook(p, str(GATE_SH.parent / ".." / "hooks" / "gate-sh")) is None


def test_warn_runs_with_a_notice_once_per_session_and_off_judges_as_before():
    with H.gateway_env() as env:
        env.write_form('[shell]\nmanaged = "warn"\n')
        consent.approve("settings", form=env.form())
        p = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "session_id": "s1"}
        out = _hook(p, None)
        assert out == {"systemMessage": out["systemMessage"]} and \
            "[shell] managed = \"warn\", so Claude's commands run in your own shell" in out["systemMessage"]
        assert _hook(p, None) is None, "once per session"
        assert "systemMessage" in _hook({**p, "session_id": "s2"}, None)
        # the usual judgment still applies (and keeps the notice)
        out = _hook({**p, "session_id": "s3", "tool_input": {"command": "curl https://x"}}, None)
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny" and "systemMessage" in out
        env.write_form('[shell]\nmanaged = "off"\n')
        consent.approve("settings", form=env.form())
        assert _hook({**p, "session_id": "s4"}, None) is None
        # a form that says off without the OK: still on
        env.write_form('[shell]\nmanaged = "on"\n')
        consent.ratchet(env.form())
        env.write_form('[shell]\nmanaged = "off"\n')
        out = _hook({**p, "session_id": "s5"}, None)
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_jobs_and_the_terminal_panel_are_not_the_managed_shell():
    with H.gateway_env() as env:
        for tool in ("mcp__terminal__run_in_terminal", "mcp__plugin_check_jobs__job_start"):
            out = _hook({"tool_name": tool, "tool_input": {"command": "ls"}, "session_id": "s"}, None)
            assert out is None, (tool, out)


def _rig(td: Path):
    (td / "pre_bash.sh").write_text((H.PLUGIN / "hooks" / "pre_bash.sh").read_text())
    log = td / "launched"
    (td / "launch.sh").write_text(f'#!/bin/sh\nprintf "%s %s\\n" "$1" "${{GW_MANAGED_CHECK-}}" >> {sq(str(log))}\n'
                                  "cat > /dev/null\n")
    return td / "pre_bash.sh", log


def test_pre_bash_sends_every_bash_and_monitor_call_to_python_without_the_gateways_prefix():
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as d:
        td = Path(d)
        pre, log = _rig(td)
        cases = [("Bash", None, True), ("Monitor", None, True), ("Bash", "/other/prefix", True),
                 ("Bash", str(td / "gate-sh"), False), ("Monitor", str(td / "gate-sh"), False),
                 ("mcp__terminal__run_in_terminal", None, False),
                 ("mcp__plugin_check_jobs__job_start", None, False)]
        for tool, prefix, forced in cases:
            log.unlink(missing_ok=True)
            env = {k: v for k, v in os.environ.items() if k != "CLAUDE_CODE_SHELL_PREFIX"}
            if prefix:
                env["CLAUDE_CODE_SHELL_PREFIX"] = prefix
            # a command with no trigger word, and a fake tool_name inside the command
            payload = json.dumps({"session_id": "s", "tool_name": tool,
                                  "tool_input": {"command": 'echo "\\"tool_name\\": \\"Bash\\""'}})
            r = subprocess.run(["/bin/sh", str(pre)], input=payload, capture_output=True, text=True,
                               env=env, timeout=15)
            assert r.returncode == 0
            assert (log.exists() and log.read_text() == "hook-bash 1\n") == forced, (tool, prefix)
            assert log.exists() == forced, (tool, prefix)


def test_the_cold_guard_denies_bash_without_the_prefix_byte_identically():
    with H.gateway_env() as env:
        if H.any_env_ready():
            return
        p = {"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": str(env.root)}
        r = H.run_launch(env, "hook-bash", payload=p, extra_env={"GW_MANAGED_CHECK": "1"})
        assert r.stdout == envfile.degraded_bash_text("managed"), r
        r = H.run_launch(env, "hook-bash", payload=p)
        assert r.stdout == "", r


# ---------------------------------------------------------------------------
# Host inspection, context, status, FileChanged, SessionStart
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


def test_gate_status_shows_the_managed_shell_with_every_origin():
    from gateway import gate
    with world() as w:
        w.env.write_form('[shell]\nimport_path = ["/opt/homebrew/bin"]\nimport_env = ["JAVA_HOME"]\n'
                         'managed = "warn"\n')
        form, eff, data = w.load()
        text = gate.render_status(form, eff, data)
        assert "Managed shell: on (Claude's Bash runs in the gateway's managed bash)" in text
        assert 'gateway.toml says "warn"; that waits for your OK (gate check settings)' in text
        assert "waiting for your OK: settings: managed shell" in text
        consent.approve("settings", form=w.env.form())
        form, eff, data = w.load()
        text = gate.render_status(form, eff, data)
        assert "Managed shell: warn" in text
        assert "/opt/homebrew/bin  (gateway.toml [shell] import_path, line 2; Homebrew)" in text
        assert "imported: JAVA_HOME (gateway.toml [shell] import_env, line 3)" in text
        assert f"(the gateway's stand-ins)" in text and "/usr/bin  (system)" in text


def test_filechanged_renews_the_managed_settings_at_once():
    from gateway import hooks_filechanged
    with world() as w:
        w.env.write_form('[shell]\nimport_env = ["JAVA_HOME"]\n')
        consent.approve("settings", form=w.env.form())
        hooks_filechanged.record_seen(w.env.form())      # what SessionStart records
        assert "env=JAVA_HOME" in managed.conf_path().read_text()
        w.env.write_form("[shell]\n")
        out = hooks_filechanged.main({"file_path": str(paths.form_path()), "cwd": str(w.env.root)})
        assert "env=\n" in managed.conf_path().read_text()
        assert "environment import JAVA_HOME removed" in (out or {}).get("systemMessage", ""), out


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
    interrupted after the build (no conf) gets them at the next ensure-env."""
    text = (H.PLUGIN / "hooks" / "launch.sh").read_text()
    assert '[ "$rc" -eq 0 ] && { managed_sync; warm_env; cleanup_envs; }' in text
    assert 'if ready; then [ -f "$DATA/managed/conf" ] || managed_sync; warm_env; cleanup_envs; return 0; fi' in text
    assert '"$PY" -I -S -X "pycache_prefix=$PYC" "$ROOT/run.py" managed-sync' in text
