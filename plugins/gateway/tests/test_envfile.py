"""Claude's environment: the env file (idempotent, set -u safe, bash/zsh/sh),
stubs (atomic, baked paths), the launcher, git config, and hooks/launch.sh
(degraded mode parity, ensure-env with a fake pixi, mcp wait) (SPEC 7, 18)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import harness as H
import harness_sudo as HS
from gateway import envfile, githelper, paths
from gateway import form as F

SHELLS = [s for s in ("/bin/sh", "/bin/dash", "/bin/bash", "/opt/local/bin/bash", "/bin/zsh",
                      "/usr/bin/zsh", "/usr/bin/dash") if os.path.exists(s)]


def _source_twice(shell: str, envf: Path, pre: dict[str, str]) -> dict[str, str]:
    script = (f"set -u; . '{envf}'; . '{envf}'; "
              "printf 'PATH=%s\\n' \"$PATH\"; printf 'COUNT=%s\\n' \"${GIT_CONFIG_COUNT-}\"; "
              "printf 'K0=%s\\n' \"${GIT_CONFIG_KEY_0-}\"; printf 'V0=%s\\n' \"${GIT_CONFIG_VALUE_0-}\"; "
              "printf 'K1=%s\\n' \"${GIT_CONFIG_KEY_1-}\"; printf 'V1=%s\\n' \"${GIT_CONFIG_VALUE_1-}\"; "
              "printf 'K2=%s\\n' \"${GIT_CONFIG_KEY_2-}\"; "
              "printf 'GSC=%s\\n' \"${GIT_SSH_COMMAND-}\"; printf 'RSH=%s\\n' \"${RSYNC_RSH-}\"; "
              "printf 'SOCK=%s\\n' \"${SSH_AUTH_SOCK-unset}\"; printf 'GH=%s\\n' \"${GH_TOKEN-unset}\"; "
              "env | grep -c '^GIT_CONFIG_KEY_' | sed 's/^/NKEYS=/'")
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", **pre}
    r = subprocess.run([shell, "-c", script], capture_output=True, text=True, env=env, timeout=20)
    assert r.returncode == 0, (shell, r.stderr)
    return dict(l.split("=", 1) for l in r.stdout.splitlines() if "=" in l)


def test_env_text_content():
    with H.gateway_env():
        t = envfile.env_text("refuse")
        b = paths.bin_dir()
        assert f"GW_BIN='{b}'\n" in t
        assert f"GIT_SSH_COMMAND='{b}/ssh'; RSYNC_RSH='{b}/ssh'; export GIT_SSH_COMMAND RSYNC_RSH" in t
        assert f"GIT_CONFIG_VALUE_$_n='{paths.git_config_path()}'" in t
        lines = t.rstrip().splitlines()
        # everything after GW_BIN= is inside one `if [ -d "$GW_BIN" ]` (env.sh is
        # sourced by other launchers too: a no-op once the stand-ins are gone)
        k = lines.index(f"GW_BIN='{b}'")
        assert lines[k + 1] == 'if [ -d "$GW_BIN" ]; then' and lines[-1] == "fi", lines
        assert all(line.startswith("  ") for line in lines[k + 2:-1]), lines
        assert lines[-2].startswith("  unset SSH_AUTH_SOCK SSH_AGENT_PID SSH_ASKPASS")
        assert "unset SSH_AUTH_SOCK" not in envfile.env_text("mine")
        # nothing in it assumes Claude's Bash, and it is sourced (no return/exit)
        code = "\n".join(line for line in lines if not line.startswith("#"))
        for word in ("CLAUDE_PID", "return", "exit", "trap"):
            assert word not in code, word


def test_env_file_idempotent_under_every_shell():
    assert len(SHELLS) >= 2, SHELLS
    with H.gateway_env() as env:
        paths.bin_dir().mkdir(parents=True, exist_ok=True)   # the stand-ins are there
        envf = env.root / "envfile.sh"
        envfile.write_env_file(envf, envfile.env_text("refuse"))
        envfile.write_env_file(envf, envfile.env_text("refuse"))
        assert envf.read_text() == envfile.env_text("refuse"), "truncate, never append"
        b = str(paths.bin_dir())
        for sh in SHELLS:
            got = _source_twice(sh, envf, {"SSH_AUTH_SOCK": "/tmp/agent", "GH_TOKEN": "tok"})
            assert got["PATH"].split(":").count(b) == 1 and got["PATH"].startswith(b + ":"), (sh, got)
            assert got["COUNT"] == "1" and got["K0"] == "include.path", (sh, got)
            assert got["V0"] == str(paths.git_config_path()) and got["NKEYS"] == "1", (sh, got)
            assert got["GSC"] == b + "/ssh" and got["RSH"] == b + "/ssh"
            assert got["SOCK"] == "unset" and got["GH"] == "unset", (sh, got)
            # an existing GIT_CONFIG_COUNT is respected
            got = _source_twice(sh, envf, {"GIT_CONFIG_COUNT": "2", "GIT_CONFIG_KEY_0": "a.b",
                                           "GIT_CONFIG_VALUE_0": "1", "GIT_CONFIG_KEY_1": "c.d",
                                           "GIT_CONFIG_VALUE_1": "2"})
            assert got["COUNT"] == "3" and got["K2"] == "include.path" and got["K1"] == "c.d", (sh, got)
        envfile.write_env_file(envf, envfile.env_text("mine"))
        for sh in SHELLS:
            got = _source_twice(sh, envf, {"SSH_AUTH_SOCK": "/tmp/agent"})
            assert got["SOCK"] == "/tmp/agent", "others = mine keeps the user's agent"


def test_env_file_with_empty_path_and_set_u():
    with H.gateway_env() as env:
        paths.bin_dir().mkdir(parents=True, exist_ok=True)
        envf = env.root / "e.sh"
        envfile.write_env_file(envf, envfile.env_text())
        for sh in SHELLS:
            r = subprocess.run([sh, "-c", f"set -u; unset PATH; . '{envf}'; echo \"$PATH\""],
                               capture_output=True, text=True, env={}, timeout=10)
            assert r.returncode == 0 and r.stdout.strip() == str(paths.bin_dir()), (sh, r.stderr)


def test_env_file_does_nothing_once_the_stand_in_folder_is_gone():
    """env.sh is sourced by other launchers too (checkpoint jobs, the user's
    terminal), also after the plugin is uninstalled or its data deleted: with
    no $DATA/bin it must change nothing (no PATH entry to a missing folder, no
    GIT_SSH_COMMAND to a missing ssh, the user's agent and tokens kept), under
    every shell, sourced twice, under set -eu."""
    with H.gateway_env() as env:
        envf = env.root / "envfile.sh"
        envfile.write_env_file(envf, envfile.env_text("refuse"))
        assert not paths.bin_dir().exists()
        pre = {"SSH_AUTH_SOCK": "/tmp/agent", "GH_TOKEN": "tok", "GIT_CONFIG_COUNT": "1",
               "GIT_CONFIG_KEY_0": "a.b", "GIT_CONFIG_VALUE_0": "1"}
        for sh in SHELLS:
            got = _source_twice(sh, envf, pre)
            assert got["PATH"] == "/usr/bin:/bin", (sh, got)
            assert got["SOCK"] == "/tmp/agent" and got["GH"] == "tok", (sh, got)
            assert got["GSC"] == "" and got["RSH"] == "", (sh, got)
            assert got["COUNT"] == "1" and got["K0"] == "a.b" and got["K1"] == "", (sh, got)
            assert got["NKEYS"] == "1", (sh, got)
            r = subprocess.run([sh, "-c", f"set -eu; . '{envf}'; . '{envf}'; echo ok "
                                          '"${GW_GITCFG_SET-unset}"'],
                               capture_output=True, text=True, timeout=10,
                               env={"PATH": "/usr/bin:/bin"})
            assert r.returncode == 0 and r.stdout == "ok unset\n" and r.stderr == "", (sh, r)
        # the folder comes back (next session start): the same file applies again
        paths.bin_dir().mkdir(parents=True)
        for sh in SHELLS:
            got = _source_twice(sh, envf, pre)
            assert got["PATH"].startswith(str(paths.bin_dir()) + ":"), (sh, got)
            assert got["SOCK"] == "unset" and got["K1"] == "include.path", (sh, got)


def test_a_checkpoint_job_sourcing_env_sh_finds_the_stand_ins():
    """A checkpoint job runs `/bin/sh -c WRAPPER checkpoint-job-ID CMD EXITFILE
    ENVFILE STATUSFILE` (checkpoint's current wrapper, pinned in
    harness_sudo.CHECKPOINT_WRAPPER) with the MCP server's environment (no
    CLAUDE_PID, no CLAUDE_ENV_FILE); the wrapper sources env.sh first, so the
    job gets the stand-ins first on PATH, the gateway's ssh for git and rsync,
    and no user agent or tokens."""
    with H.gateway_env() as env:
        envfile.write_stubs(envfile.stand_ins())
        p = envfile.write_env_sh(envfile.env_text("refuse"))
        cmd = ('command -v ssh; command -v sudo; '
               'echo "GSC=$GIT_SSH_COMMAND SOCK=${SSH_AUTH_SOCK-unset} GH=${GH_TOKEN-unset}"')
        r = HS.checkpoint_job(env, cmd, envfile=p,
                              extra_env={"SSH_AUTH_SOCK": "/tmp/agent", "GH_TOKEN": "tok"})
        b = paths.bin_dir()
        assert r.returncode == 0 and r.stderr == "gateway_env: applied\n", r
        assert r.stdout.splitlines() == [str(b / "ssh"), str(b / "sudo"),
                                         f"GSC={b / 'ssh'} SOCK=unset GH=unset"], r.stdout


def _ck_wrapper(sh: str, env, cmd: str, envf, pre: dict[str, str]
                ) -> tuple[subprocess.CompletedProcess, str, str]:
    """checkpoint's job wrapper run directly by `sh`: (result, exit file,
    gateway_env status file)."""
    exitf, status = env.root / "exit_code", env.root / "gateway_env"
    for f in (exitf, status):
        f.unlink(missing_ok=True)
    r = subprocess.run([sh, "-c", HS.CHECKPOINT_WRAPPER, "checkpoint-job-x-1", cmd, str(exitf),
                        str(envf), str(status)], capture_output=True, text=True, timeout=10,
                       stdin=subprocess.DEVNULL,
                       env={"PATH": "/usr/bin:/bin", "HOME": str(env.user_home), **pre})
    read = lambda f: f.read_text().strip() if f.exists() else ""   # noqa: E731
    return r, read(exitf), read(status)


def test_checkpoint_jobs_apply_env_sh_silently():
    """checkpoint's wrapper (pinned: harness_sudo.CHECKPOINT_WRAPPER) sources
    env.sh in a subshell first and applies it only if that printed nothing on
    stderr; otherwise the job records "failed" and runs without the
    stand-ins. So env.sh must source silently: "applied" and no stderr for
    others = refuse and mine, with and without $DATA/bin (after an
    uninstall), under /bin/sh and dash."""
    shells = ["/bin/sh"] + [d for d in ("/bin/dash", "/usr/bin/dash") if os.path.exists(d)][:1]
    assert len(shells) == 2 or not os.path.exists("/bin/dash"), shells
    cmd = 'command -v ssh; echo "SOCK=${SSH_AUTH_SOCK-unset}"'
    with H.gateway_env() as env:
        b = paths.bin_dir()
        for others in ("refuse", "mine"):
            p = envfile.write_env_sh(envfile.env_text(others))
            for with_bin in (True, False):
                if with_bin:
                    envfile.write_stubs(envfile.stand_ins())
                else:
                    shutil.rmtree(b)
                for sh in shells:
                    where = (others, with_bin, sh)
                    r, rc, status = _ck_wrapper(sh, env, cmd, p, {"SSH_AUTH_SOCK": "/tmp/agent"})
                    assert r.returncode == 0 and rc == "0", (where, r)
                    assert status == "applied" and r.stderr == "", (where, status, r.stderr)
                    out = r.stdout.splitlines()
                    if with_bin:
                        sock = "SOCK=/tmp/agent" if others == "mine" else "SOCK=unset"
                        assert out == [str(b / "ssh"), sock], (where, out)
                    else:                      # a no-op: the system's ssh, the user's agent
                        assert str(b) not in r.stdout and out[-1] == "SOCK=/tmp/agent", (where, out)
        # what the wrapper does with an env file that writes to stderr: "failed",
        # its text in the job's log, and the job runs without it
        noisy = env.root / "noisy.sh"
        noisy.write_text(envfile.env_text("refuse") + "echo 'a note' >&2\n")
        envfile.write_stubs(envfile.stand_ins())
        for sh in shells:
            r, rc, status = _ck_wrapper(sh, env, cmd, noisy, {})
            assert status == "failed" and rc == "0", (sh, status, r)
            assert "could not apply the gateway environment" in r.stderr and "a note" in r.stderr
            assert str(b) not in r.stdout, (sh, r.stdout)


def test_stub_text_bakes_paths_and_fallbacks():
    with H.gateway_env():
        t = envfile.stub_text("ssh", ("shim", "ssh"))
        py = paths.env_python()
        assert t.startswith("#!/bin/sh\n")
        assert f"GW_DATA='{paths.data_dir()}'; export GW_DATA; unset CLAUDE_PLUGIN_DATA\n" in t
        assert (f"exec '{py}' -I -S -X 'pycache_prefix={paths.pycache_dir()}' '{paths.run_py()}' "
                "'shim' 'ssh' \"$@\"") in t, t
        assert envfile.STILL_SETTING_UP in t and t.rstrip().endswith("exit 75")
        s = envfile.stub_text("sudo", ("shim", "sudo"))
        assert s.rstrip().endswith('exec /usr/bin/sudo "$@"') and "exit 75" not in s


def test_stub_runs_still_setting_up_when_env_missing():
    with H.gateway_env() as env:
        envfile.write_stubs(envfile.stand_ins())
        r = H.run_stub(env, "ssh", "box", "true")
        assert r.returncode == 75 and envfile.STILL_SETTING_UP in r.stderr


def test_stand_ins_conditional():
    with H.gateway_env(system_git=True):
        base = set(envfile.stand_ins())
        assert base == {"sudo", "ssh", "scp", "sftp", "gh", "hf", "databricks", "crane", "pijul",
                        "asiml", "gate", "git-credential-gateway", "gate-askpass"}
        f = F.parse_text('[accounts.cat]\nkind = "ml-catalog"\n[accounts.az]\nkind = "azure"\n'
                         'tenant = "t.example.com"\nenv = "AZ_TOKEN"\n')
        s = envfile.stand_ins(f)
        assert "dvc" in s and "az" in s
        assert "az" not in envfile.stand_ins(F.parse_text('[accounts.az]\nkind = "azure"\ntenant = "t.example.com"\n'))
    with H.gateway_env(system_git=False):
        s = envfile.stand_ins()
        assert "git" in s and str(paths.env_bin() / "git") in s["git"]


def test_write_stubs_replaces_files_and_removes_stale_names():
    with H.gateway_env():
        d = paths.data_dir()
        (d / "bin.new.123").mkdir(parents=True)          # left by the old layout
        envfile.write_stubs({"a": "#!/bin/sh\necho one\n"})
        ino = os.stat(paths.bin_dir()).st_ino
        envfile.write_stubs({"b": "#!/bin/sh\necho two\n"})
        assert sorted(p.name for p in paths.bin_dir().iterdir()) == ["b"]
        assert os.stat(paths.bin_dir()).st_ino == ino, "the folder itself is never swapped"
        assert not list(d.glob("bin.new.*")) and not list(d.glob("bin.old.*"))
        assert oct(os.stat(paths.bin_dir() / "b").st_mode & 0o777) == "0o755"


def test_stubs_never_missing_while_rewritten():
    # A command running while SessionStart rewrites the stubs must always find
    # them (a gap would fall through to the system ssh with the user's keys).
    import threading
    with H.gateway_env():
        stubs = envfile.stand_ins()
        envfile.write_stubs(stubs)
        target = paths.bin_dir() / "ssh"
        misses = 0
        stop = threading.Event()

        def watch():
            nonlocal misses
            while not stop.is_set():
                if not os.path.exists(target):
                    misses += 1
        t = threading.Thread(target=watch)
        t.start()
        try:
            for _ in range(60):
                envfile.write_stubs(stubs)
        finally:
            stop.set()
            t.join()
        assert misses == 0, misses


def test_launch_sh_stubs_never_missing_while_rewritten():
    import threading
    with H.gateway_env() as env:
        envfile.write_stubs(envfile.stand_ins())
        target = paths.bin_dir() / "ssh"
        misses = 0
        stop = threading.Event()

        def watch():
            nonlocal misses
            while not stop.is_set():
                if not os.path.exists(target):
                    misses += 1
        t = threading.Thread(target=watch)
        t.start()
        try:
            for _ in range(4):
                r = H.run_launch(env, "hook-session", extra_env={"PATH": "/usr/bin:/bin"})
                assert r.returncode == 0, r.stderr
        finally:
            stop.set()
            t.join()
        assert misses == 0, misses


def test_launcher_and_env_sh():
    with H.gateway_env():
        p = envfile.write_launcher()
        assert p == paths.launcher_path() and oct(p.stat().st_mode & 0o777) == "0o700"
        t = p.read_text()
        assert "'gate' \"$@\"" in t and f"GW_DATA='{paths.data_dir()}'" in t
        e = envfile.write_env_sh(envfile.env_text())
        assert e.read_text() == envfile.env_text() and oct(e.stat().st_mode & 0o777) == "0o600"


def test_git_config_resets_credential_helpers_under_refuse():
    with H.gateway_env():
        f = F.parse_text("")
        # others = "refuse": the global reset is always written, even with no
        # githelper text, so git never falls back to the user's keychain helper.
        p = envfile.write_git_config(f, {})
        assert p and p.read_text() == "[credential]\n\thelper =\n" == envfile.GIT_RESET
        assert envfile.write_git_config(f, {}, "mine") is None and not paths.git_config_path().exists(), \
            "others = mine: no reset, and a stale include file is removed"
        orig_inc, orig_id = githelper.include_config, githelper.identity_files
        helper = '[credential "https://github.com"]\n\thelper =\n\thelper = !x\n'
        githelper.include_config = lambda form, meta: helper
        githelper.identity_files = lambda form: {"identity-x": "[user]\n\tname = X\n", "../evil": "x"}
        try:
            p = envfile.write_git_config(f, {})
            assert p.read_text() == envfile.GIT_RESET + helper, "the reset comes first"
            assert envfile.write_git_config(f, {}, "mine").read_text() == helper
            assert (paths.git_dir() / "identity-x").exists() and not (paths.data_dir() / "evil").exists()
        finally:
            githelper.include_config, githelper.identity_files = orig_inc, orig_id


def test_session_sync_writes_the_reset_and_git_sees_it():
    import shutil as _sh
    git = _sh.which("git", path="/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin")
    with H.gateway_env() as env:
        f = F.parse_text("")
        envfile.sync(f, None, {}, None)
        assert paths.git_config_path().read_text() == envfile.GIT_RESET
        if git:
            home = env.root / "githome"
            home.mkdir()
            (home / ".gitconfig").write_text("[credential]\n\thelper = osxkeychain\n")
            r = subprocess.run([git, "config", "--get-all", "credential.helper"], capture_output=True,
                               text=True, cwd=str(env.root),
                               env={"HOME": str(home), "PATH": "/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM": "1",
                                    "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "include.path",
                                    "GIT_CONFIG_VALUE_0": str(paths.git_config_path())})
            assert r.stdout.splitlines()[-1:] == [""], ("the empty reset is the last helper value", r.stdout)


def test_stub_through_test_entry_runs_gate_status():
    with H.gateway_env() as env:
        env.o.entry = H.entry_cmd(env)
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\n')
        envfile.write_stubs(envfile.stand_ins())
        r = H.run_stub(env, "gate", "status")
        assert r.returncode == 0, r.stderr
        assert "box" in r.stdout and "waits for your OK" in r.stdout


# ---------------------------------------------------------------------------
# hooks/launch.sh
# ---------------------------------------------------------------------------


def test_launch_degraded_session_matches_python():
    with H.gateway_env() as env:
        envf = env.root / "claude-env.sh"
        fake = _fake_pixi(env.root / "fakebin")     # pixi is there: the env is building
        assert not paths.launcher_path().exists()
        r = H.run_launch(env, "hook-session", "--test", payload={"session_id": "s1"},
                         extra_env={"CLAUDE_ENV_FILE": str(envf),
                                    "PATH": f"{fake.parent}:/usr/bin:/bin"})
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        assert out["systemMessage"].startswith("gateway: ")
        assert out["hookSpecificOutput"]["hookEventName"] == "SessionStart"
        assert envf.read_text() == envfile.env_text("refuse"), "sh and Python write the same env file"
        # round 3: the first session has the terminal launcher too (no-screen
        # messages name it), byte-identical to Python's, mode 0700
        assert paths.launcher_path().read_text() == envfile.launcher_text() \
            == envfile.launcher_text("building")
        assert (paths.launcher_path().stat().st_mode & 0o777) == 0o700
        want = envfile.stand_ins()
        got = {p.name: p.read_text() for p in paths.bin_dir().iterdir()}
        assert got == want, sorted(set(got) ^ set(want)) or [n for n in got if got[n] != want[n]]
        assert paths.git_config_path().read_text() == envfile.git_config_text("refuse"), \
            "sh writes the same credential reset"


FIXED_PIXI_DIRS = ("/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin", "/home/linuxbrew/.linuxbrew/bin")


def _no_pixi_root(env) -> Path:
    """A plugin root whose launch.sh can't find pixi in the fixed places."""
    root = env.root / "plugin"
    (root / "hooks").mkdir(parents=True)
    text = (H.PLUGIN / "hooks" / "launch.sh").read_text()
    for d in FIXED_PIXI_DIRS:
        assert d in text
        text = text.replace(d, str(env.root / "nowhere"))
    (root / "hooks" / "launch.sh").write_text(text)
    for name in ("pixi.lock", "pixi.toml", "run.py", "src"):
        os.symlink(H.PLUGIN / name, root / name)
    return root


def test_launch_degraded_says_pixi_missing():
    with H.gateway_env() as env:
        root = _no_pixi_root(env)
        e = {"PATH": "/usr/bin:/bin", "HOME": str(env.user_home)}
        r = H.run_launch(env, "hook-session", plugin_root=root, extra_env=e)
        out = json.loads(r.stdout)
        msg = out["systemMessage"]
        assert "pixi isn't installed" in msg, msg
        # Review round 2: Claude and the stand-ins said "still setting up, try
        # again in a minute" though nothing was being set up.
        ctx = out["hookSpecificOutput"]["additionalContext"]
        assert "pixi isn't installed" in ctx and "https://pixi.sh" in ctx and "still running" not in ctx
        # Review round 4: the launcher (the user's own helper) speaks to the user,
        # byte-identical to Python's text for this state
        lt = paths.launcher_path().read_text()
        assert "tell the user" not in lt and "install it from https://pixi.sh" in lt, lt
        env.o.plugin_root = root.resolve()          # launch.sh takes its root physically
        try:
            assert lt == envfile.launcher_text("nopixi")
        finally:
            env.o.plugin_root = None
        stub = H.run_stub(env, "gate", "status")
        assert stub.returncode == 75 and "pixi isn't installed" in stub.stderr, stub.stderr
        assert "try again in a minute" not in stub.stderr
        assert "exec /usr/bin/sudo" in (paths.bin_dir() / "sudo").read_text()
        r = H.run_launch(env, "hook-subagent", plugin_root=root, extra_env=e)
        assert "pixi isn't installed" in json.loads(r.stdout)["hookSpecificOutput"]["additionalContext"]
        r = H.run_launch(env, "gate", "status", plugin_root=root, extra_env=e)
        assert r.returncode == 75 and "pixi isn't installed" in r.stderr


def _deny(r) -> str | None:
    return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] if r.stdout.strip() else None


def test_launch_degraded_other_hooks():
    with H.gateway_env() as env:
        r = H.run_launch(env, "hook-bash", payload={"tool_input": {"command": "sudo ls"}})
        assert r.returncode == 0 and r.stdout == ""
        r = H.run_launch(env, "hook-files", payload={"tool_input": {"file_path": "~/.config/gateway/private/key.txt"}})
        assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
        r = H.run_launch(env, "hook-files", payload={"tool_input": {"file_path": "/tmp/x"}})
        assert r.stdout == ""


def test_launch_degraded_file_guard_case_parents_and_dotdot():
    with H.gateway_env() as env:
        home = str(env.user_home)
        e = {"HOME": home}
        deny = [
            {"tool_name": "Read", "tool_input": {"file_path": f"{home}/.config/GATEWAY/PRIVATE/key.txt"}},
            {"tool_name": "Read", "tool_input": {"file_path": f"{home}/.config/gateway/Key.TXT"}},
            {"tool_name": "Read", "tool_input": {"file_path": f"{home}/.config/x/../gateway/private/k"}},
            {"tool_name": "Grep", "tool_input": {"pattern": "AGE-SECRET", "path": f"{home}/.config/gateway"}},
            {"tool_name": "Grep", "tool_input": {"pattern": "x", "path": f"{home}/.config/"}},
            {"tool_name": "Grep", "tool_input": {"pattern": "x", "path": "~"}},
            {"tool_name": "Grep", "tool_input": {"pattern": "x"}, "cwd": home},
            {"tool_name": "Grep", "tool_input": {"pattern": "x", "path": "/"}},
            {"tool_name": "Grep", "tool_input": {"pattern": "x", "path": "/tmp"}},
            {"tool_name": "Glob", "tool_input": {"pattern": "**/gateway/private/*", "path": home}},
            {"tool_name": "Read", "tool_input": {"file_path": "private/key.txt"}, "cwd": f"{home}/.config/gateway"},
        ]
        for p in deny:
            r = H.run_launch(env, "hook-files", payload=p, extra_env=e)
            assert _deny(r) == "deny", (p, r.stdout, r.stderr)
        allow = [
            {"tool_name": "Read", "tool_input": {"file_path": f"{home}/.config/gateway/gateway.toml"}},
            {"tool_name": "Grep", "tool_input": {"pattern": "gateway/private", "path": f"{home}/project"}},
            {"tool_name": "Edit", "tool_input": {"file_path": f"{home}/project/README.md",
                                                 "old_string": "a", "new_string": "see ~/.config/gateway/private"}},
            {"tool_name": "Glob", "tool_input": {"pattern": "**/*.py", "path": f"{home}/project"}},
        ]
        for p in allow:
            r = H.run_launch(env, "hook-files", payload=p, extra_env=e)
            assert _deny(r) is None, (p, r.stdout)


def _reason(r) -> str | None:
    return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecisionReason"] if r.stdout.strip() else None


def test_launch_degraded_file_guard_denies_transcripts():
    """The cold window's Read/Grep route into session transcripts (brief
    section 2: a cold start never switches a guard off). Byte-identical to
    Python's hooks_files.DENY_TRANSCRIPT / DENY_TRANSCRIPT_SEARCH."""
    from gateway import hooks_files
    with H.gateway_env() as env:
        home = str(env.user_home)
        e = {"HOME": home}
        deny_read = [
            {"tool_name": "Read", "tool_input": {"file_path": f"{home}/.claude/projects/p/abc.jsonl"}},
            {"tool_name": "Read", "tool_input": {"file_path": f"{home}/.config/claude/projects/x/s.jsonl"}},
            {"tool_name": "Read", "tool_input": {"file_path": f"{home}/.claude/projects/p/s/subagents/agent-1.jsonl"}},
            {"tool_name": "Grep", "tool_input": {"pattern": "secret", "path": f"{home}/.claude/projects/p/abc.jsonl"}},
        ]
        for p in deny_read:
            r = H.run_launch(env, "hook-files", payload=p, extra_env=e)
            assert _deny(r) == "deny", (p, r.stdout, r.stderr)
            assert _reason(r) == hooks_files.DENY_TRANSCRIPT, (p, _reason(r))
        deny_search = [
            {"tool_name": "Grep", "tool_input": {"pattern": "code", "path": f"{home}/.claude/projects"}},
            {"tool_name": "Grep", "tool_input": {"pattern": "code", "path": f"{home}/.config/claude/projects"}},
            {"tool_name": "Grep", "tool_input": {"pattern": "code", "path": f"{home}/.claude"}},
        ]
        for p in deny_search:
            r = H.run_launch(env, "hook-files", payload=p, extra_env=e)
            assert _deny(r) == "deny", (p, r.stdout, r.stderr)
            assert _reason(r) == hooks_files.DENY_TRANSCRIPT_SEARCH, (p, _reason(r))
        allow = [
            # tool-results and a Workflow run's journal stay readable
            {"tool_name": "Read", "tool_input": {"file_path": f"{home}/.claude/projects/p/s/tool-results/out.jsonl"}},
            {"tool_name": "Read", "tool_input": {"file_path": f"{home}/.claude/projects/p/s/subagents/workflows/w1/journal.jsonl"}},
            # a .jsonl that isn't under a projects folder, and a project search
            {"tool_name": "Read", "tool_input": {"file_path": f"{home}/project/data.jsonl"}},
            {"tool_name": "Grep", "tool_input": {"pattern": "x", "path": f"{home}/project"}},
            {"tool_name": "Read", "tool_input": {"file_path": f"{home}/.claude/settings.json"}},
        ]
        for p in allow:
            r = H.run_launch(env, "hook-files", payload=p, extra_env=e)
            assert _deny(r) is None, (p, r.stdout)


def test_launch_degraded_session_reports_a_failed_build():
    with H.gateway_env() as env:
        envd = paths.env_dir()
        envd.mkdir(parents=True)
        (envd / "install.log").write_text("error: network unreachable\n")
        fake = _fake_pixi(env.root / "fakebin")
        r = H.run_launch(env, "hook-session", extra_env={"PATH": f"{fake.parent}:/usr/bin:/bin"})
        out = json.loads(r.stdout)
        msg = out["systemMessage"]
        assert "setting up failed" in msg and str(envd / "install.log") in msg, msg
        ctx = out["hookSpecificOutput"]["additionalContext"]
        assert "setup failed" in ctx and "next session start" in ctx and "still running" not in ctx
        stub = H.run_stub(env, "ssh", "box", "true")
        assert stub.returncode == 75 and "setup failed" in stub.stderr and \
            str(envd / "install.log") in stub.stderr, stub.stderr
        r = H.run_launch(env, "hook-subagent", extra_env={"PATH": f"{fake.parent}:/usr/bin:/bin"})
        assert "setup failed" in json.loads(r.stdout)["hookSpecificOutput"]["additionalContext"]
        # the launcher, for the user: no "tell the user", byte-identical to Python's
        lt = paths.launcher_path().read_text()
        assert lt == envfile.launcher_text("failed"), lt
        assert "tell the user" not in lt and "start a new Claude Code session to retry" in lt
        lp = paths.launcher_path()
        r = subprocess.run([str(lp), "status"], capture_output=True, text=True, timeout=10,
                           env={"PATH": "/usr/bin:/bin"})
        assert r.returncode == 75 and "tell the user" not in r.stderr, r
        (envd.parent / (envd.name + ".building")).mkdir()
        r = H.run_launch(env, "hook-session", extra_env={"PATH": f"{fake.parent}:/usr/bin:/bin"})
        assert "first-time setup is running" in json.loads(r.stdout)["systemMessage"], "a build is running"
        r = H.run_launch(env, "hook-subagent")
        assert json.loads(r.stdout)["hookSpecificOutput"]["hookEventName"] == "SubagentStart"
        # pixi must be found for "still setting up" (else it says pixi is missing): the fake
        # one, not wherever this machine keeps a real pixi (the Debian VM has it only in ~/.pixi)
        r = H.run_launch(env, "gate", "status", extra_env={"PATH": f"{fake.parent}:/usr/bin:/bin"})
        assert r.returncode == 75 and envfile.STILL_SETTING_UP in r.stderr, r.stderr


def _fake_env(env) -> Path:
    py = paths.env_python()
    py.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(H.PY, py)
    (paths.env_dir() / ".ready").write_text("")
    return py


def test_launch_with_built_env_runs_python_session():
    with H.gateway_env() as env:
        _fake_env(env)
        envf = env.root / "claude-env.sh"
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\n')
        r = H.run_launch(env, "hook-session", "--test", payload={"session_id": "s2"},
                         extra_env={"CLAUDE_ENV_FILE": str(envf)})
        assert r.returncode == 0, r.stderr
        out = json.loads(r.stdout)
        ctx = out["hookSpecificOutput"]["additionalContext"]
        assert ctx.startswith("Gateway (plugin)") and "box" in ctx
        assert out["hookSpecificOutput"]["watchPaths"] == [str(paths.form_path())]
        assert envf.read_text() == envfile.env_text("refuse")
        assert (paths.env_dir() / ".used").exists()


def _run_main_recorded(args: list[str], test_root: str | None) -> tuple[int, list, str]:
    """run.main in-process with dispatch replaced by a recorder (nothing runs)."""
    import io
    import sys
    sys.path.insert(0, str(H.PLUGIN))
    import run
    calls: list = []
    saved_dispatch, saved_err = run.dispatch, sys.stderr
    old = os.environ.get("GATEWAY_TEST_ROOT")
    run.dispatch = lambda mode, rest: calls.append((mode, rest)) or 0
    sys.stderr = io.StringIO()
    try:
        if test_root is None:
            os.environ.pop("GATEWAY_TEST_ROOT", None)
        else:
            os.environ["GATEWAY_TEST_ROOT"] = test_root
        code = run.main(args)
        return code, calls, sys.stderr.getvalue()
    finally:
        run.dispatch, sys.stderr = saved_dispatch, saved_err
        if old is None:
            os.environ.pop("GATEWAY_TEST_ROOT", None)
        else:
            os.environ["GATEWAY_TEST_ROOT"] = old


def test_run_py_refuses_test_flag_for_stand_ins():
    # run.py rejects --test for anything but hook/MCP/gated modes before resolving any path
    with H.gateway_env() as env:
        for args in (["--test", "shim", "gate", "status"], ["shim", "--test", "gate"],
                     ["--test", "askpass"], ["--test", "git-credential", "get"], ["--test", "gate", "status"]):
            code, calls, err = _run_main_recorded(args, str(env.root))
            assert code == 2 and not calls and "only for hook, MCP and gated" in err, (args, err)


def test_run_py_fails_closed_on_a_misplaced_test_flag():
    # The 15:27 incident shape: --test anywhere but first/second is an ordinary
    # argument, so run.py would have run in production mode. With
    # GATEWAY_TEST_ROOT set, it must refuse before dispatching anything.
    with H.gateway_env() as env:
        for args in (["shim", "gate", "--test", "status"], ["gate", "status", "--test"],
                     ["hook-session", "x", "--test"], ["shim", "sudo", "--test", "ls"]):
            code, calls, err = _run_main_recorded(args, str(env.root))
            assert code == 2 and not calls and "GATEWAY_TEST_ROOT is set" in err, (args, calls, err)
        code, calls, _ = _run_main_recorded(["hook-session", "--test"], str(env.root))
        assert code == 0 and calls == [("hook-session", [])], "a valid --test call still runs"


def test_harness_refuses_misplaced_test_flags_without_running_them():
    bad = [("shim", "gate", "--test", "status"), ("gate", "status", "--test"),
           ("hook-session", "x", "--test"), ("--test", "shim", "gate"), ("shim", "--test", "gate"),
           ("hook-session",), ("--test", "--test", "hook-session"), ("hook-session", "--test", "--test"),
           ("--test",), ()]
    for args in bad:
        assert not H.valid_test_argv(args), args
        try:
            H.run_py(None, *args)
        except H.GuardTripped:
            pass
        else:
            raise AssertionError(f"the harness must refuse {args}")
    for args in (("--test", "hook-session"), ("hook-session", "--test"), ("--test", "mcp"),
                 ("hook-files", "--test")):
        assert H.valid_test_argv(args), args


def _fake_pixi(d: Path) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    p = d / "pixi"
    p.write_text(f"""#!/bin/sh
# fake pixi: install --locked --manifest-path M
echo "$@" >> '{d}/calls'
[ "$1" = install ] || exit 1
m=""; while [ $# -gt 0 ]; do [ "$1" = --manifest-path ] && m=$2; shift; done
dir=$(dirname "$m")
mkdir -p "$dir/.pixi/envs/default/bin" && ln -s '{H.PY}' "$dir/.pixi/envs/default/bin/python3"
""")
    os.chmod(p, 0o755)
    return p


def test_ensure_env_builds_with_pixi_and_cleans_old_envs():
    with H.gateway_env() as env:
        fake = _fake_pixi(env.root / "fakebin")
        old = paths.envs_dir() / "aaaaaaaaaaaa"
        recent = paths.envs_dir() / "bbbbbbbbbbbb"
        for d in (old, recent):
            d.mkdir(parents=True)
            (d / ".used").write_text("")
        t = time.time() - 9 * 86400
        os.utime(old / ".used", (t, t))
        r = H.run_launch(env, "ensure-env", extra_env={"PATH": f"{fake.parent}:/usr/bin:/bin"})
        assert r.returncode == 0, r.stderr
        assert paths.env_ready(), "the env is marked ready"
        assert (paths.env_dir() / "pixi.lock").read_bytes() == (H.PLUGIN / "pixi.lock").read_bytes()
        calls = (fake.parent / "calls").read_text()
        # locked resolution (brief section 2): never re-solve or rewrite the lock
        assert "install --locked --manifest-path" in calls and "--frozen" not in calls, calls
        assert not old.exists() and recent.exists()
        # a second run is a no-op build
        r = H.run_launch(env, "ensure-env", extra_env={"PATH": f"{fake.parent}:/usr/bin:/bin"})
        assert r.returncode == 0 and (fake.parent / "calls").read_text().count("install") == 1


def test_ensure_env_without_pixi_fails_cleanly():
    with H.gateway_env() as env:
        r = H.run_launch(env, "ensure-env", plugin_root=_no_pixi_root(env),
                         extra_env={"PATH": "/usr/bin:/bin", "HOME": str(env.user_home)})
        assert r.returncode == 1 and "pixi" in r.stderr and not paths.env_ready(), r.stderr


def test_mcp_waits_then_exits_when_env_missing():
    with H.gateway_env() as env:
        t0 = time.time()
        r = H.run_launch(env, "mcp", timeout=20)
        dt = time.time() - t0
        assert r.returncode == 1 and 3.5 <= dt <= 10, dt


def test_lock_sha_matches_launch_sh():
    with H.gateway_env() as env:
        r = subprocess.run(["/bin/sh", "-c", f"shasum -a 256 '{H.PLUGIN / 'pixi.lock'}' 2>/dev/null || sha256sum '{H.PLUGIN / 'pixi.lock'}'"],
                           capture_output=True, text=True)
        assert r.stdout[:12] == paths.lock_sha12()
        del env


def test_cleanup_envs_python_version():
    with H.gateway_env():
        old = paths.envs_dir() / "cccccccccccc"
        old.mkdir(parents=True)
        (old / ".used").write_text("")
        t = time.time() - 30 * 86400
        os.utime(old / ".used", (t, t))
        cur = paths.env_dir()
        cur.mkdir(parents=True)
        assert envfile.cleanup_envs() == ["cccccccccccc"] and cur.exists()


def test_launch_runs_on_an_older_env_while_an_update_builds():
    """Review round 2: after an update that changes pixi.lock, the hooks gave
    no decisions (curl allowed, no private-folder deny), the MCP server quit
    and the stand-ins said "still setting up" until the new env was built.
    They run on the newest older finished env meanwhile."""
    with H.gateway_env() as env:
        old = paths.envs_dir() / "0123456789ab"
        py = old / ".pixi" / "envs" / "default" / "bin" / "python3"
        py.parent.mkdir(parents=True)
        os.symlink(H.PY, py)
        (old / ".ready").write_text("")
        assert not paths.env_ready()
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\n')
        r = H.run_launch(env, "hook-bash", "--test",
                         payload={"tool_name": "Bash", "tool_input": {"command": "curl http://x"}})
        assert r.returncode == 0 and '"deny"' in r.stdout, (r.stdout, r.stderr)
        assert "reconnect gw in /mcp" in json.loads(r.stdout)["hookSpecificOutput"][
            "permissionDecisionReason"]
        assert (old / ".used").exists(), "an env in use isn't cleaned up"
        t0 = time.time()
        r = H.run_launch(env, "mcp", "--test", timeout=20)
        assert r.returncode == 0 and time.time() - t0 < 3.5, (r.returncode, r.stderr)
        # the stubs Python writes from the older env fall back to it
        import sys
        saved = sys.executable
        try:
            sys.executable = str(py)
            assert envfile.older_env_python() == py
            text = envfile.stub_text("ssh", ("shim", "ssh"))
        finally:
            sys.executable = saved
        cur = text.index(str(paths.env_python()))
        assert str(py) in text and cur < text.index(str(py)) < text.index("exit 75"), text
        assert envfile.older_env_python() is None, "not when running from elsewhere"
        assert "0123456789ab" not in envfile.stub_text("ssh", ("shim", "ssh"))


# ---------------------------------------------------------------------------
# Round 3: a failed command exits 0 in Claude's shell (PostToolUse sees it)
# ---------------------------------------------------------------------------


def _claude_like(shell: str, envf: Path, cmd: str, pre: dict[str, str]) -> subprocess.CompletedProcess:
    """Claude Code's Bash wrapper: the env file's lines, then `eval CMD &&
    pwd -P >| cwd-file` (claude 2.1.301)."""
    cwdf = envf.parent / "cwd.txt"
    cwdf.unlink(missing_ok=True)
    script = (envf.read_text() + ":\n" + f"eval '{cmd}' < /dev/null && pwd -P >| '{cwdf}'")
    env = {"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", **pre}
    return subprocess.run([shell, "-c", script], capture_output=True, text=True, env=env, timeout=20,
                          cwd=str(envf.parent))


def test_a_failed_command_keeps_its_exit_code_in_claudes_shell():
    """The gateway doesn't change how Claude's commands end (DECISIONS,
    "Rolled back"): round 3's EXIT trap made every failed command exit 0 with
    `Exit code N` printed, in Claude's shell only. Now a failed command exits
    with its own code and prints nothing extra, in Claude's shell (CLAUDE_PID
    set) and in the user's terminal sourcing env.sh, and Claude Code's cwd
    record works as without the gateway."""
    with H.gateway_env() as env:
        envf = env.root / "envfile.sh"
        text = envfile.env_text("refuse")
        assert "trap " not in text and "EXIT" not in text, text
        envfile.write_env_file(envf, text)
        sub = env.root / "sub"
        sub.mkdir()
        for sh in SHELLS:
            for pre in ({"CLAUDE_PID": "1"}, {}):
                r = _claude_like(sh, envf, "echo out; exit 3", pre)
                assert r.returncode == 3 and r.stdout == "out\n" and r.stderr == "", (sh, pre, r)
                r = _claude_like(sh, envf, "echo out; false", pre)
                assert r.returncode == 1 and r.stderr == "", (sh, pre, r)
                r = _claude_like(sh, envf, "echo fine", pre)
                assert r.returncode == 0 and r.stderr == "" and r.stdout == "fine\n", (sh, r)
                assert (envf.parent / "cwd.txt").read_text().strip() == str(env.root.resolve()), sh
                # a failed command skips Claude Code's cwd record, as without the gateway
                r = _claude_like(sh, envf, "cd sub && false", pre)
                assert r.returncode == 1 and not (envf.parent / "cwd.txt").exists(), (sh, r)


def test_the_launcher_says_when_the_plugin_is_gone():
    """Round 3: after an uninstall the leftover launcher said "still setting
    up (first run)" forever."""
    with H.gateway_env() as env:
        text = envfile.launcher_text()
        assert envfile.sq(envfile.LAUNCHER_GONE) in text
        gone = text.replace(str(paths.run_py()), str(env.root / "nowhere" / "run.py"))
        lp = env.root / "gate"
        lp.write_text(gone)
        os.chmod(lp, 0o700)
        r = subprocess.run([str(lp), "status"], capture_output=True, text=True, timeout=10,
                           env={"PATH": "/usr/bin:/bin"})
        assert r.returncode == 1 and "isn't there any more" in r.stderr, r
        assert "still setting up" not in r.stderr
        lp.write_text(text)                     # the plugin is there, the env isn't built
        r = subprocess.run([str(lp), "status"], capture_output=True, text=True, timeout=10,
                           env={"PATH": "/usr/bin:/bin"})
        assert r.returncode == 75 and "still setting up" in r.stderr, r


# ---------------------------------------------------------------------------
# The first session on a new env: the warm step, and a SessionStart that is
# cancelled or killed (jobs-lows round 2)
# ---------------------------------------------------------------------------


def _killed_python(env) -> Path:
    """A built env whose python dies at once, as a SessionStart Claude Code
    cancels or kills before Python wrote anything."""
    py = paths.env_python()
    py.parent.mkdir(parents=True, exist_ok=True)
    py.write_text("#!/bin/sh\nkill -9 $$\n")
    os.chmod(py, 0o755)
    (paths.env_dir() / ".ready").write_text("")
    return py


def _temps(*dirs: Path) -> list[str]:
    return [p.name for d in dirs if d.is_dir() for p in d.iterdir() if p.name.endswith(".tmp")
            or ".tmp." in p.name]


def test_launch_writes_the_safe_env_before_python_runs_session_start():
    """The first Python SessionStart on a new env took 5-13 s (once past
    Claude Code's 20 s limit): a session whose hook is cancelled or killed
    before Python writes anything must still run Claude's commands through
    the stand-ins, without the user's agent and tokens. launch.sh writes the
    env file, and the stand-ins and the git reset when missing, before it
    starts Python; the next session (Python) writes everything for the form."""
    with H.gateway_env() as env:
        _killed_python(env)
        envf = env.root / "session-env" / "sid" / "sessionstart-hook-0.sh"
        assert not paths.bin_dir().exists() and not paths.git_config_path().exists()
        r = H.run_launch(env, "hook-session", "--test", payload={"session_id": "s1"},
                         extra_env={"CLAUDE_ENV_FILE": str(envf)})
        assert r.returncode != 0 and r.stdout == "", (r.returncode, r.stdout, r.stderr)
        assert envf.read_text() == envfile.env_text("refuse")
        want = envfile.stand_ins()
        got = {p.name: p.read_text() for p in paths.bin_dir().iterdir()}
        assert got == want, sorted(set(got) ^ set(want)) or [n for n in got if got[n] != want[n]]
        assert all(os.access(paths.bin_dir() / n, os.X_OK) for n in got)
        assert paths.git_config_path().read_text() == envfile.git_config_text("refuse")
        assert not _temps(envf.parent, paths.bin_dir(), paths.git_config_path().parent)
        # a resumed session reuses its env file (replaced whole); a missing
        # stand-in is written again
        envf.write_text("# an older session's text\n")
        (paths.bin_dir() / "scp").unlink()
        r = H.run_launch(env, "hook-session", "--test", payload={"session_id": "s1"},
                         extra_env={"CLAUDE_ENV_FILE": str(envf)})
        assert envf.read_text() == envfile.env_text("refuse")
        assert (paths.bin_dir() / "scp").read_text() == want["scp"], "a missing stand-in is back"
        # the next session (Python runs) writes everything for the form
        paths.env_python().unlink()
        os.symlink(H.PY, paths.env_python())
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\n')
        envf2 = env.root / "session-env" / "sid2" / "sessionstart-hook-0.sh"
        r = H.run_launch(env, "hook-session", "--test", payload={"session_id": "s2"},
                         extra_env={"CLAUDE_ENV_FILE": str(envf2)})
        assert r.returncode == 0, r.stderr
        assert "box" in json.loads(r.stdout)["hookSpecificOutput"]["additionalContext"]
        assert envf2.read_text() == envfile.env_text("refuse")
        assert paths.env_sh_path().read_text() == envfile.env_text("refuse")
        assert paths.launcher_path().read_text() == envfile.launcher_text()


def test_the_env_file_is_never_left_cut_short():
    """write_env_file replaces the file whole: a write cut off midway (the
    hook killed) leaves the old text, never part of the new one, and the
    temp file's name isn't one Claude Code sources."""
    import builtins
    import re

    class Killed(BaseException):
        pass

    class Cut:
        def __init__(self, f):
            self.f = f

        def write(self, s):
            self.f.write(s[: len(s) // 2])
            self.f.flush()
            raise Killed()

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.f.close()
            return False

        def __getattr__(self, a):
            return getattr(self.f, a)

    with H.gateway_env() as env:
        envf = env.root / "session-env" / "sid" / "sessionstart-hook-0.sh"
        envfile.write_env_file(envf, "OLD\n")
        real_fdopen, real_open = os.fdopen, builtins.open
        os.fdopen = lambda *a, **k: Cut(real_fdopen(*a, **k))
        builtins.open = lambda f, m="r", *a, **k: (Cut(real_open(f, m, *a, **k)) if "w" in m
                                                  else real_open(f, m, *a, **k))
        try:
            try:
                envfile.write_env_file(envf, envfile.env_text("refuse"))
            except Killed:
                pass
        finally:
            os.fdopen, builtins.open = real_fdopen, real_open
        claude_reads = re.compile(r"^(setup|sessionstart|cwdchanged|filechanged)-hook-(\d+)\.sh$")
        seen = {p.name: p.read_text() for p in envf.parent.iterdir() if claude_reads.match(p.name)}
        assert seen == {envf.name: "OLD\n"}, seen
        assert [p.name for p in envf.parent.iterdir() if p.name.endswith(".tmp")], \
            "the cut write left only its temp file"
        envfile.write_env_file(envf, envfile.env_text("refuse"))
        assert envf.read_text() == envfile.env_text("refuse")
        # a killed writer's temp file goes once it is an hour old
        stale, fresh = (envf.parent / f".{envf.name}.{n}.tmp" for n in (99998, 99999))
        for p in (stale, fresh):
            p.write_text("# cut")
        os.utime(stale, (time.time() - 7200, time.time() - 7200))
        envfile.write_env_file(envf, envfile.env_text("refuse"))
        assert not stale.exists() and fresh.exists()


def test_launch_sh_base_stand_ins_match_python():
    text = (H.PLUGIN / "hooks" / "launch.sh").read_text()
    line = next(ln for ln in text.splitlines() if ln.startswith("STUB_NAMES="))
    assert line.split("=", 1)[1].strip('"').split() == [n for n, _ in envfile.BASE_STANDINS]


def test_ensure_env_warms_a_new_env_once():
    """ensure-env (the async SessionStart hook) loads a new env once
    (gateway/warm.py) and marks it .warm, so the next session's sync
    SessionStart doesn't pay the first load of every binary and library
    (5-6 s on macOS). An env built before (ready, no .warm) is warmed at the
    next ensure-env; a failing warm step fails nothing and is retried."""
    with H.gateway_env() as env:
        fake = _fake_pixi(env.root / "fakebin")
        e = {"PATH": f"{fake.parent}:/usr/bin:/bin"}
        r = H.run_launch(env, "ensure-env", extra_env=e)
        assert r.returncode == 0 and paths.env_ready(), r.stderr
        warm = paths.env_dir() / ".warm"
        assert warm.exists(), "a new env is warmed right after its build"
        t = time.time() - 3600
        os.utime(warm, (t, t))
        r = H.run_launch(env, "ensure-env", extra_env=e)
        assert r.returncode == 0 and abs(warm.stat().st_mtime - t) < 1, "warmed only once"
        warm.unlink()                       # an env built before the warm step existed
        r = H.run_launch(env, "ensure-env", extra_env=e)
        assert r.returncode == 0 and warm.exists()
        warm.unlink()                       # the warm step fails: nothing else does
        py = paths.env_python()
        py.unlink()
        py.write_text("#!/bin/sh\nexit 3\n")
        os.chmod(py, 0o755)
        r = H.run_launch(env, "ensure-env", extra_env=e)
        assert r.returncode == 0 and not warm.exists(), (r.returncode, r.stderr)


def test_warm_loads_the_gateway_and_resolves_no_location():
    """gateway/warm.py imports every gateway module (and what they import
    later) and runs age --version and ssh -V from its python's own folder,
    with no gateway location resolved (the harness guard is on) and nothing
    written to the working folder or HOME."""
    with H.gateway_env() as env:
        d = env.root / "warmenv"
        d.mkdir()
        os.symlink(H.PY, d / "python3")
        log = env.root / "tools.log"
        for name in ("age", "ssh"):
            (d / name).write_text(f"#!/bin/sh\necho \"{name} $*\" >> '{log}'\n")
            os.chmod(d / name, 0o755)
        cwd, home = env.root / "cwd", env.root / "h"
        cwd.mkdir()
        home.mkdir()
        code = ("import json, sys; sys.path[:0] = [sys.argv[1], sys.argv[2]]; import harness; "
                "from gateway import warm; rc = warm.main(); "
                "print(json.dumps([rc, sorted(m for m in sys.modules if m.startswith('gateway.'))"
                ", [m for m in ('ssl', '_ctypes', 'urllib.request', 'pty', 'uuid') "
                "if m in sys.modules]]))")
        r = subprocess.run([str(d / "python3"), "-I", "-S", *H.PYX, "-c", code, str(H.PLUGIN / "src"),
                            str(H.TESTS)], capture_output=True, text=True, timeout=120, cwd=cwd,
                           env={"PATH": "/usr/bin:/bin", "HOME": str(home)})
        assert r.returncode == 0, r.stderr
        rc, mods, std = json.loads(r.stdout.strip().splitlines()[-1])
        src = H.PLUGIN / "src" / "gateway"
        want = sorted([f"gateway.{p.stem}" for p in src.glob("*.py") if p.stem != "__init__"]
                      + ["gateway.daemon"] + [f"gateway.daemon.{p.stem}"
                                              for p in (src / "daemon").glob("*.py")
                                              if p.stem != "__init__"])
        assert rc == 0 and mods == want, sorted(set(want) - set(mods))
        assert std == ["ssl", "_ctypes", "urllib.request", "pty", "uuid"], std
        assert sorted(log.read_text().splitlines()) == ["age --version", "ssh -V"]
        assert not list(cwd.iterdir()) and not list(home.iterdir())
