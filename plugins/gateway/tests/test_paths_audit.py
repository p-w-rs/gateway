"""paths.py (SPEC 1), testing.override and its guards, audit.py (SPEC 17)."""
from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import harness as H
from gateway import audit, paths, testing


def test_checkpoint_state_dir_follows_xdg_state_home_outside_tests():
    """Claude's context mentions checkpoint jobs when checkpoint's state folder
    exists (`${XDG_STATE_HOME:-~/.local/state}/checkpoint`). Only an absolute
    XDG_STATE_HOME is checked here, so the real home is never resolved."""
    old = os.environ.get("XDG_STATE_HOME")
    base = Path(H.tmp_base()) / "xdg-state-probe"
    try:
        os.environ["XDG_STATE_HOME"] = str(base)
        assert testing.active() is None
        assert paths.checkpoint_state_dir() == base / "checkpoint"
        with H.gateway_env() as env:
            assert paths.checkpoint_state_dir() == env.user_home / ".local" / "state" / "checkpoint"
    finally:
        if old is None:
            os.environ.pop("XDG_STATE_HOME", None)
        else:
            os.environ["XDG_STATE_HOME"] = old


def test_layout_under_override():
    with H.gateway_env() as env:
        h = env.home
        assert paths.home() == h and h == env.user_home / ".config" / "gateway"
        assert paths.form_path() == h / "gateway.toml" and paths.launcher_path() == h / "gate"
        assert paths.env_sh_path() == h / "env.sh" and paths.private_dir() == h / "private"
        assert paths.key_path() == h / "private" / "key.txt"
        assert paths.vault_path() == h / "private" / "vault.age"
        assert paths.cache_path() == h / "private" / "cache.age"
        assert paths.lock_path() == h / "private" / ".lock"
        assert paths.backups_dir() == h / "private" / "backups"
        assert paths.pending_dir() == h / "private" / "pending"
        assert paths.v2_store_path() == h / "store.age" and paths.v2_key_path() == h / "key.txt"
        d = env.data
        assert paths.bin_dir() == d / "bin" and paths.git_config_path() == d / "git" / "config"
        assert paths.audit_path() == d / "audit.jsonl"
        assert paths.env_dir() == d / "envs" / paths.lock_sha12() and len(paths.lock_sha12()) == 12
        assert paths.env_python() == paths.env_dir() / ".pixi" / "envs" / "default" / "bin" / "python3"
        assert paths.run_py() == H.PLUGIN / "run.py"
        assert paths.tool("age").endswith("/age")


def test_run_dir_mode_and_type_checks():
    with H.gateway_env() as env:
        r = paths.run_dir()
        assert stat.S_IMODE(r.stat().st_mode) == 0o700
        os.chmod(r, 0o755)
        try:
            paths.run_dir()
        except paths.PathError as e:
            assert "readable by others" in str(e)
        else:
            raise AssertionError("a 0755 run dir must be refused")
        os.chmod(r, 0o700)
        alt = env.root / "run2"
        os.symlink(r, alt)
        env.o.run = alt
        try:
            paths.run_dir()
        except paths.PathError as e:
            assert "not a directory" in str(e)
        else:
            raise AssertionError("a symlinked run dir must be refused")
        env.o.run = env.root / "fresh-run"
        assert stat.S_IMODE(paths.run_dir().stat().st_mode) == 0o700


def test_data_dir_precedence():
    import sys
    with H.gateway_env() as env:
        orig = H.ORIGINALS["data_dir"]
        saved, saved_exe = env.o.data, sys.executable
        old = {k: os.environ.get(k) for k in ("CLAUDE_PLUGIN_DATA", "GW_DATA", "CLAUDE_CONFIG_DIR")}
        try:
            env.o.data = None
            sys.executable = "/usr/bin/python3"           # not a gateway env python
            # hook and MCP modes: CLAUDE_PLUGIN_DATA (Claude Code sets it there)
            paths.trust_plugin_env(True)
            os.environ["CLAUDE_PLUGIN_DATA"] = str(env.root / "cpd")
            os.environ["GW_DATA"] = str(env.root / "gwd")
            assert orig() == env.root / "cpd"
            os.environ["CLAUDE_PLUGIN_DATA"] = "${CLAUDE_PLUGIN_DATA}"
            assert orig() == env.root / "gwd", "an unexpanded value is ignored"
            del os.environ["CLAUDE_PLUGIN_DATA"]
            del os.environ["GW_DATA"]
            os.environ["CLAUDE_CONFIG_DIR"] = str(env.root / "cfg")
            assert orig() == env.root / "cfg" / "plugins" / "data" / "gate-gateway"
            # stand-in modes: the caller's environment can't redirect the data folder
            paths.trust_plugin_env(False)
            os.environ["CLAUDE_PLUGIN_DATA"] = "/tmp/attacker-data"
            assert orig() == env.user_home / ".claude" / "plugins" / "data" / "gate-gateway", \
                "CLAUDE_PLUGIN_DATA and CLAUDE_CONFIG_DIR are ignored outside hooks/MCP"
            sys.executable = str(env.root / "d" / "envs" / "abcdef123456" / ".pixi" / "envs"
                                 / "default" / "bin" / "python3")
            assert orig() == env.root / "d", "the data folder of the env python that runs it"
            paths.trust_plugin_env(True)
            assert orig() == Path("/tmp/attacker-data"), "(hooks trust Claude Code's variable)"
        finally:
            paths.trust_plugin_env(False)
            env.o.data, sys.executable = saved, saved_exe
            for k, v in old.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


def test_run_dispatch_trusts_the_env_only_in_hook_and_mcp_modes():
    import io
    import sys
    sys.path.insert(0, str(H.PLUGIN))
    import run
    seen = {}
    saved_hook, saved_shim, saved_err = run.run_hook, run.run_shim, sys.stderr
    run.run_hook = lambda mode: seen.__setitem__(mode, paths._TRUST_ENV_DATA) or 0
    run.run_shim = lambda tool, args: seen.__setitem__("shim " + tool, paths._TRUST_ENV_DATA) or 0
    sys.stderr = io.StringIO()
    try:
        with H.gateway_env():
            run.dispatch("hook-session", [])
            run.dispatch("shim", ["gh", "pr", "list"])
            run.dispatch("hook-files", [])
            run.dispatch("shim", ["ssh"])
    finally:
        run.run_hook, run.run_shim, sys.stderr = saved_hook, saved_shim, saved_err
        paths.trust_plugin_env(False)
    assert seen == {"hook-session": True, "shim gh": False, "hook-files": True, "shim ssh": False}, seen


def test_is_protected():
    with H.gateway_env():
        paths.ensure_private()
        assert paths.is_protected(paths.key_path()) and paths.is_protected(paths.vault_path())
        assert paths.is_protected(paths.private_dir() / "backups" / "x")
        assert paths.is_protected(paths.v2_key_path()) and paths.is_protected(paths.v2_store_path())
        assert paths.is_protected(paths.run_dir() / "sock")
        assert not paths.is_protected(paths.form_path()) and not paths.is_protected(paths.home() / "env.sh")
        link = paths.home() / "innocent"
        os.symlink(paths.private_dir(), link)
        assert paths.is_protected(link / "key.txt"), "symlinks are resolved"
        assert paths.is_protected(str(paths.home()).upper() + "/PRIVATE/KEY.TXT") or \
            paths.is_protected(str(paths.home()) + "/PRIVATE/KEY.TXT"), "case variants"
        assert paths.is_protected("private/key.txt", cwd=str(paths.home())), "relative to the cwd"
        assert paths.is_protected_parent(paths.home()) and paths.is_protected_parent("/")
        assert paths.is_protected_parent(paths.home().parent)
        assert not paths.is_protected_parent(paths.home() / "gateway.toml")
        assert not paths.is_protected_parent(paths.user_home() / "project")


def test_override_refuses_real_home_and_guard_trips():
    real = testing.real_user_home() / ".config" / "gateway"
    scratch = H.tmp_base() / "never-created"
    try:
        with testing.override(home=real, data=scratch / "data", run=scratch / "run"):
            pass
    except testing.UnsafeTestPath:
        pass
    else:
        raise AssertionError("an override into the real gateway home must abort")
    try:
        paths.home()
    except H.GuardTripped:
        pass
    else:
        raise AssertionError("paths.home() without an override must trip the guard")
    for args in (("hook-session",), ("shim", "gate", "--test", "status"), ("gate", "status", "--test")):
        try:
            H.run_py(None, *args)
        except H.GuardTripped:
            pass
        else:
            raise AssertionError(f"a subprocess without a valid --test must trip the guard: {args}")


class _FakeRealHome:
    """testing.real_user_home() answering a fake home (with a fake
    .config/gateway/private in it) and every os.stat / os.lstat recorded, so
    a test can prove what the guard stats without ever going near the real
    ~/.config/gateway. CLAUDE_CONFIG_DIR is unset meanwhile (forbidden_roots
    would otherwise resolve the real Claude config's parents)."""

    def __init__(self, base: Path):
        self.home = base / "fake-real-home"
        self.gw = self.home / ".config" / "gateway"
        (self.gw / "private").mkdir(parents=True)
        self.calls: list[str] = []

    def __enter__(self) -> "_FakeRealHome":
        self._orig = (testing.real_user_home, os.stat, os.lstat, os.environ.get("CLAUDE_CONFIG_DIR"))
        testing.real_user_home = lambda: self.home
        os.environ.pop("CLAUDE_CONFIG_DIR", None)

        def rec(f):
            def w(p, *a, **k):
                if isinstance(p, (str, os.PathLike)):
                    self.calls.append(os.fspath(p))
                return f(p, *a, **k)
            return w
        os.stat, os.lstat = rec(self._orig[1]), rec(self._orig[2])
        return self

    def __exit__(self, *exc) -> None:
        testing.real_user_home, os.stat, os.lstat, cfg = self._orig
        if cfg is not None:
            os.environ["CLAUDE_CONFIG_DIR"] = cfg

    def touched_gateway_home(self) -> list[str]:
        g = os.fspath(self.gw).casefold()
        return [c for c in self.calls if c.casefold() == g or c.casefold().startswith(g + "/")]


def _guard_base() -> Path:
    """A scratch folder made without H.tmp_base() (which runs the guard on the
    real home before the fake one is in place: a mutation that makes the
    guard stat again must only ever stat the fake)."""
    import tempfile
    return Path(tempfile.mkdtemp(prefix="guard-", dir=os.environ.get("GW_TEST_TMP") or None))


def test_the_guard_never_stats_the_gateway_home_it_protects():
    """PLAN-v4 phase 2 (a phase-1 finding): testing's guard used to resolve
    (lstat) the real ~/.config/gateway on every test run. Now only parent
    folders are resolved and the protected paths are compared as written:
    forbidden_roots(), an override of a scratch root and a refused spelling
    of the protected folder itself stat nothing inside it. (A fake real home
    stands in for the person's, which no test may touch.)"""
    base = _guard_base()
    try:
        with _FakeRealHome(base) as f:
            roots = testing.forbidden_roots()
            assert f.gw in roots
            scratch = base / "scratch"
            testing.guard(scratch / "x")
            with testing.override(root=scratch):
                pass
            for bad in (f.gw, f.gw / "private" / "key.txt", f.home / ".config" / "GATEWAY" / "private",
                        str(f.gw) + "/../gateway/private"):
                try:
                    testing.guard(bad)
                except testing.UnsafeTestPath:
                    pass
                else:
                    raise AssertionError(f"the guard let {bad} through")
            touched = f.touched_gateway_home()
            assert touched == [], touched
    finally:
        import shutil
        shutil.rmtree(base, ignore_errors=True)


def test_the_guard_still_catches_a_symlink_into_the_gateway_home():
    """The as-written comparison doesn't weaken the guard: a scratch path that
    is a symlink into the (fake) real gateway home, or into its private
    folder, is resolved and refused, and so is an override rooted there."""
    base = _guard_base()
    try:
        with _FakeRealHome(base) as f:
            link = base / "innocent"
            link.symlink_to(f.gw)
            for bad in (link, link / "private", link / "private" / "key.txt"):
                try:
                    testing.guard(bad)
                except testing.UnsafeTestPath:
                    pass
                else:
                    raise AssertionError(f"the guard let the symlinked {bad} through")
            try:
                with testing.override(home=link, data=base / "d", run=base / "r"):
                    pass
            except testing.UnsafeTestPath:
                pass
            else:
                raise AssertionError("an override through a symlink into the gateway home ran")
            testing.guard(base / "innocent-sibling")
    finally:
        import shutil
        shutil.rmtree(base, ignore_errors=True)


def test_from_env_requires_test_flag():
    with testing.from_env(False):
        assert testing.active() is None
    old = os.environ.pop(testing.TEST_ROOT_VAR, None)
    try:
        try:
            testing.from_env(True)
        except testing.UnsafeTestPath:
            pass
        else:
            raise AssertionError("--test without a root must abort")
    finally:
        if old is not None:
            os.environ[testing.TEST_ROOT_VAR] = old


def test_audit_log_redacts_and_records_context():
    with H.gateway_env():
        audit.log("use", secrets=["hunter2-secret-pw"], tool="sudo", target="localhost",
                  argv="sudo -S <<< hunter2-secret-pw",
                  detail="token ghp_abcdefghijklmnopqrstuvwxyz0123 and Authorization: Bearer abc.def "
                         "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----")
        raw = paths.audit_path().read_text()
        for bad in ("hunter2-secret-pw", "ghp_abcdefghijklmnop", "abc.def", "AAAA"):
            assert bad not in raw, bad
        rec = json.loads(raw.splitlines()[-1])
        assert rec["event"] == "use" and rec["tool"] == "sudo" and rec["cwd"]
        assert oct(paths.audit_path().stat().st_mode & 0o777) == "0o600"
        assert audit.read(1)[0]["target"] == "localhost"
        assert "event" not in audit.render([]) and "use" in audit.render(audit.read(5))


def test_audit_fallback_scrubs_only_long_literals():
    with H.gateway_env():
        audit.log("use", secrets=["pw12", "longer-secret-1"], argv="sudo pw12 longer-secret-1")
        rec = audit.read(1)[0]
        assert "pw12" in rec["argv"], "short values aren't scrubbed by literal (that would reveal them)"
        assert "longer-secret-1" not in rec["argv"]


def test_last_refusal_fallback_stays_in_this_session():
    import shutil
    with H.gateway_env():
        old = os.environ.get("CLAUDE_CODE_SESSION_ID")
        try:
            os.environ["CLAUDE_CODE_SESSION_ID"] = "s-b"
            audit.refusal("sudo", "builder", "gateway: sudo is off for builder")
            shutil.rmtree(paths.refusals_dir())          # the run dir was cleaned (reboot)
            os.environ["CLAUDE_CODE_SESSION_ID"] = "s-a"
            assert audit.last_refusal() is None, "another session's refusal is never shown"
            os.environ["CLAUDE_CODE_SESSION_ID"] = "s-b"
            assert audit.last_refusal()["target"] == "builder", "this session's comes from the log"
            os.environ.pop("CLAUDE_CODE_SESSION_ID")
            assert audit.last_refusal() is None
        finally:
            if old is None:
                os.environ.pop("CLAUDE_CODE_SESSION_ID", None)
            else:
                os.environ["CLAUDE_CODE_SESSION_ID"] = old


def test_last_refusal_is_per_session():
    with H.gateway_env():
        old = os.environ.get("CLAUDE_CODE_SESSION_ID")
        try:
            os.environ["CLAUDE_CODE_SESSION_ID"] = "s-a"
            audit.refusal("ssh", "x", "gateway: x isn't in gateway.toml")
            os.environ["CLAUDE_CODE_SESSION_ID"] = "s-b"
            audit.refusal("sudo", "builder", "gateway: sudo is off for builder")
            assert audit.last_refusal("s-a")["target"] == "x"
            assert audit.last_refusal()["target"] == "builder"
            assert audit.last_refusal("nobody") is None
        finally:
            if old is None:
                os.environ.pop("CLAUDE_CODE_SESSION_ID", None)
            else:
                os.environ["CLAUDE_CODE_SESSION_ID"] = old
