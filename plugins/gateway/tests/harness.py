"""Shared test fixtures (SPEC 20). Pure stdlib.

- gateway_env(): temp gateway home, data and run dirs through
  gateway.testing.override; every path the gateway resolves is checked.
- A hard guard: while the tests run, paths.home()/data_dir()/run_dir() abort
  the whole run (SystemExit) if called without an override, or if anything
  resolves under the real ~/.config/gateway (or the real plugin data folder).
- FakeDialog: scripted dialog answers and outcomes (ok, cancelled, timeout,
  unavailable) for popup.py (phase B), via testing.override(dialog=...).
- make_fake_sudo(): a password sudo (-A/-S/-v/-n/-k, "Sorry, try again",
  NOPASSWD mode).
- run_py()/run_launch(): run run.py or hooks/launch.sh as subprocesses with
  --test and GATEWAY_TEST_ROOT.
- PYC/PYX: the test run's bytecode folder (under the test temp root) and the
  `-X pycache_prefix=` flag for every Python a test starts on the plugin's
  code, so no __pycache__ lands in the plugin folder (CLAUDE.md invariant 16).
"""
from __future__ import annotations

import atexit
import base64
import contextlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Iterator

TESTS = Path(__file__).resolve().parent
PLUGIN = TESTS.parent
REPO = PLUGIN.parents[1]


def _bytecode_dir() -> str:
    """Where this process and every Python a test starts write bytecode:
    never beside the plugin's sources (run.py, src/, tests/). run_tests.py
    makes one folder per run under the test temp root, sets sys.pycache_prefix
    and passes it on in GW_TEST_PYCACHE; a process started with `-X
    pycache_prefix=` (PYX) keeps its own; anything else that imports the
    harness gets one of its own, removed at exit. Subprocesses need PYX on
    their argv: -I ignores PYTHONPYCACHEPREFIX and PYTHONDONTWRITEBYTECODE."""
    v = os.environ.get("GW_TEST_PYCACHE") or str(sys._xoptions.get("pycache_prefix") or "")
    if not os.path.isabs(v):
        base = os.environ.get("GW_TEST_TMP") or tempfile.gettempdir()
        os.makedirs(base, exist_ok=True)
        v = tempfile.mkdtemp(prefix="gwpyc-", dir=base)
        atexit.register(shutil.rmtree, v, True)
        os.environ["GW_TEST_PYCACHE"] = v
    os.makedirs(v, exist_ok=True)
    return v


PYC = _bytecode_dir()
sys.pycache_prefix = PYC              # before the first import of the plugin's code
PYX = ("-X", f"pycache_prefix={PYC}")
sys.path.insert(0, str(PLUGIN / "src"))
sys.path.insert(1, str(PLUGIN))   # run.py (its --test parsing is mirrored by the guard)

from gateway import paths, testing  # noqa: E402
from gateway import form as formmod  # noqa: E402

PY = sys.executable
ENV_BIN = Path(sys.executable).parent


def _fake_real_home() -> None:
    """GW_TEST_REAL_HOME (tests/mutations_daemon.py sets it for its runs only):
    a scratch folder that stands in for the person's home in this test
    process, so a mutation that makes testing's guard stat the protected
    folders again stats a fake one, never ~/.config/gateway. Refused unless
    it is an absolute path under a temp folder."""
    v = os.environ.get("GW_TEST_REAL_HOME", "")
    if not v:
        return
    p = Path(v)
    temps = [Path(tempfile.gettempdir()).resolve(), Path("/tmp").resolve(),
             Path("/private/tmp"), Path("/private/var/folders"), Path("/var/folders")]
    if not p.is_absolute() or not any(t in p.parents for t in temps):
        raise SystemExit(f"TEST GUARD: GW_TEST_REAL_HOME={v} isn't under a temp folder")
    testing.real_user_home = lambda: p


_fake_real_home()
REAL_GATEWAY_HOME = testing.real_user_home() / ".config" / "gateway"


class GuardTripped(SystemExit):
    pass


# ---------------------------------------------------------------------------
# The hard guard
# ---------------------------------------------------------------------------

_GUARDED = ("home", "data_dir", "run_dir", "user_home")
ORIGINALS: dict[str, Any] = {}


def _install_guard() -> None:
    if getattr(paths, "_test_guard", False):
        return
    for name in _GUARDED:
        orig = getattr(paths, name)
        ORIGINALS[name] = orig

        def wrapped(*a: Any, __orig=orig, __name=name, **kw: Any) -> Path:
            if testing.active() is None:
                raise GuardTripped(f"TEST GUARD: paths.{__name}() was called without "
                                   "testing.override; aborting so the real gateway is never touched")
            p = __orig(*a, **kw)
            testing.guard(p, f"paths.{__name}()")
            return p
        setattr(paths, name, wrapped)
    paths._test_guard = True


_install_guard()


def guard_all() -> None:
    """Resolve every gateway location and abort if one is real."""
    for fn in ("home", "form_path", "launcher_path", "env_sh_path", "private_dir", "key_path",
               "vault_path", "cache_path", "lock_path", "backups_dir", "pending_dir",
               "v2_store_path", "v2_key_path", "data_dir", "bin_dir", "git_config_path",
               "envs_dir", "audit_path", "run_dir"):
        p = getattr(paths, fn)()
        testing.guard(p, fn)
        if REAL_GATEWAY_HOME == p or REAL_GATEWAY_HOME in Path(p).resolve().parents:
            raise GuardTripped(f"TEST GUARD: {fn} -> {p} is inside the real gateway home")


def tmp_base() -> Path:
    b = Path(os.environ.get("GW_TEST_TMP") or tempfile.gettempdir())
    b.mkdir(parents=True, exist_ok=True)
    testing.guard(b, "GW_TEST_TMP")
    return b


# ---------------------------------------------------------------------------
# Gateway environment
# ---------------------------------------------------------------------------


class GatewayEnv:
    def __init__(self, root: Path, o: testing.Override):
        self.root = root
        self.o = o
        self.user_home = o.user_home
        self.home = o.home
        self.data = o.data
        self.run = o.run

    @property
    def form_path(self) -> Path:
        return paths.form_path()

    def write_form(self, text: str) -> Path:
        p = paths.form_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
        st = p.stat()
        os.utime(p, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))  # defeat mtime caching
        formmod.clear_cache()
        return p

    def form(self, last_good: str | None = None) -> formmod.Form:
        formmod.clear_cache()
        return formmod.load(last_good=last_good, use_cache=False)

    def vault(self) -> dict[str, Any]:
        from gateway import vault
        return vault.load()

    def subprocess_env(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        env = {"PATH": f"{ENV_BIN}:/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(self.user_home),
               "LANG": os.environ.get("LANG", "C.UTF-8"), "TMPDIR": str(self.root / "tmp"),
               "GATEWAY_TEST_ROOT": str(self.root),
               "CLAUDE_CONFIG_DIR": str(self.root / "claude")}
        (self.root / "tmp").mkdir(exist_ok=True)
        if self.o.machine_id:
            env["GATEWAY_TEST_MACHINE_ID"] = self.o.machine_id
        if self.o.system_git is not None:
            env["GATEWAY_TEST_SYSTEM_GIT"] = "1" if self.o.system_git else "0"
        env.update(extra or {})
        return env


@contextlib.contextmanager
def gateway_env(**kw: Any) -> Iterator[GatewayEnv]:
    root = Path(tempfile.mkdtemp(prefix="gwt-", dir=tmp_base()))
    kw.setdefault("machine_id", "TEST-MACHINE-0001")
    kw.setdefault("system_git", True)
    try:
        with testing.override(root, **kw) as o:
            o.user_home.mkdir(parents=True, exist_ok=True)
            guard_all()
            formmod.clear_cache()
            try:
                yield GatewayEnv(root, o)
            finally:
                formmod.clear_cache()
    finally:
        shutil.rmtree(root, ignore_errors=True)


def entry_cmd(env: GatewayEnv) -> list[str]:
    """For testing.override(entry=...): stubs then run tests/entry.py ROOT."""
    return [PY, "-I", "-S", *PYX, str(TESTS / "entry.py"), str(env.root)]


# ---------------------------------------------------------------------------
# Subprocess helpers
# ---------------------------------------------------------------------------


def valid_test_argv(args: tuple[str, ...] | list[str]) -> bool:
    """True only for argv that run.py itself treats as a test call: `--test`
    as the first or second argument (run.parse_test_flag), the mode a hook or
    MCP mode (run.TEST_MODES), and no other `--test` anywhere. A flag in any
    other position is an ordinary argument to run.py, which would then run in
    production mode against the real ~/.config/gateway."""
    import run as runmod
    args = list(args)
    test, rest = runmod.parse_test_flag(args)
    return bool(test and rest and rest[0] in runmod.TEST_MODES and "--test" not in rest)


def _require_test_flag(args: tuple[str, ...], what: str) -> None:
    """A subprocess that runs gateway Python must be a valid --test hook/MCP
    call (which then honours GATEWAY_TEST_ROOT) or go through tests/entry.py.
    Anything else would resolve the REAL ~/.config/gateway (the in-process
    guard can't see child processes), so it is refused here, before anything
    runs. (run.py also fails closed when GATEWAY_TEST_ROOT is set without a
    valid --test.)"""
    if not valid_test_argv(args):
        raise GuardTripped(f"TEST GUARD: {what} {' '.join(args)} isn't a valid --test hook/MCP "
                           "call and would run against the real gateway home")


def run_py(env: GatewayEnv, *args: str, payload: Any = None, extra_env: dict[str, str] | None = None,
           timeout: float = 60, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    """run.py --test ARGS... (hook/MCP modes) with GATEWAY_TEST_ROOT=env.root.
    stdin is json(payload), or input_text as is."""
    _require_test_flag(args, "run.py")
    cmd = [PY, "-I", "-S", *PYX, str(PLUGIN / "run.py"), *args]
    data = input_text if input_text is not None else (json.dumps(payload) if payload is not None else "")
    return subprocess.run(cmd, input=data, capture_output=True, text=True, timeout=timeout,
                          env=env.subprocess_env(extra_env), cwd=str(env.root))


def any_env_ready() -> bool:
    """A (fake) env launch.sh would run Python from: the current one, or an
    older finished one it falls back to while the current one builds."""
    if paths.env_python().exists():
        return True
    try:
        return any((d / ".ready").exists() for d in paths.envs_dir().iterdir())
    except OSError:
        return False


def run_launch(env: GatewayEnv, *args: str, payload: Any = None,
               extra_env: dict[str, str] | None = None, plugin_root: Path | None = None,
               timeout: float = 60, input_text: str | None = None,
               shell: str = "/bin/sh") -> subprocess.CompletedProcess[str]:
    """sh hooks/launch.sh ARGS... with CLAUDE_PLUGIN_DATA=env.data. When the
    (fake) env is ready, launch.sh execs Python, so --test is then required.
    A hook or MCP mode always gets `--test` as its second argument: launch.sh's
    degraded paths (the launcher, the file guard) then use the test root's
    home; without it, GATEWAY_TEST_ROOT makes launch.sh resolve no home at all
    (never the real one, which comes from the password database). stdin is
    json(payload), or input_text as is; `shell` runs the script."""
    root = plugin_root or PLUGIN
    if args and (args[0].startswith("hook-") or args[0] in ("mcp", "status")) and "--test" not in args:
        args = (args[0], "--test", *args[1:])
    # ensure-env and status are launch.sh's own (they never start run.py)
    if any_env_ready() and args and args[0] not in ("ensure-env", "status"):
        _require_test_flag(args, "launch.sh")
    e = env.subprocess_env({"CLAUDE_PLUGIN_DATA": str(env.data), **(extra_env or {})})
    data = input_text if input_text is not None else (json.dumps(payload) if payload is not None else "")
    return subprocess.run([shell, str(root / "hooks" / "launch.sh"), *args], input=data,
                          capture_output=True, text=True, timeout=timeout, env=e,
                          cwd=str(env.root))


def run_stub(env: GatewayEnv, name: str, *args: str, input: str | None = None,
             timeout: float = 30) -> subprocess.CompletedProcess[str]:
    """Run a generated stand-in stub. Allowed only when stubs exec tests/entry.py
    (testing.override(entry=...)) or when no env is ready (the stub then only
    prints 'still setting up'): a production stub would use the real home."""
    if not env.o.entry and paths.env_python().exists():
        raise GuardTripped("TEST GUARD: running a production stub with a ready env")
    return subprocess.run([str(paths.bin_dir() / name), *args], input=input, capture_output=True,
                          text=True, env=env.subprocess_env(), timeout=timeout)


# ---------------------------------------------------------------------------
# Fake dialog and fake sudo
# ---------------------------------------------------------------------------


class FakeDialog:
    """script KIND TITLE MESSAGE [DEFAULT] -> stdout answer; exit 0 ok, 1 cancelled,
    3 unavailable; 'timeout' sleeps then exits 1. Answers are consumed in order."""

    def __init__(self, directory: Path, answers: list[dict[str, Any]] | None = None):
        directory.mkdir(parents=True, exist_ok=True)
        self.queue = directory / "dialog-queue.json"
        self.log = directory / "dialog-log.jsonl"
        self.script = directory / "fake-dialog"
        self.queue.write_text(json.dumps(answers or []))
        self.log.write_text("")
        self.script.write_text(f"#!/bin/sh\nexec {PY!s} -I -S {TESTS / 'fakes' / 'fake_dialog.py'!s} "
                               f"'{self.queue}' '{self.log}' \"$@\"\n")
        os.chmod(self.script, 0o755)

    def add(self, outcome: str, value: str | None = None, sleep: float = 0) -> None:
        q = json.loads(self.queue.read_text())
        q.append({"outcome": outcome, "value": value, "sleep": sleep})
        self.queue.write_text(json.dumps(q))

    def calls(self) -> list[dict[str, Any]]:
        return [json.loads(l) for l in self.log.read_text().splitlines() if l.strip()]


class FakeSudo:
    def __init__(self, directory: Path, password: str = "correct horse", nopasswd: bool = False,
                 timeout: int = 300, sudoers_dir: Path | None = None):
        directory.mkdir(parents=True, exist_ok=True)
        self.dir = directory
        self.path = directory / "sudo"
        (directory / "config.json").write_text(json.dumps(
            {"password": password, "nopasswd": nopasswd, "timeout": timeout,
             "sudoers_dir": str(sudoers_dir) if sudoers_dir else None}))
        (directory / "log.jsonl").write_text("")
        self.path.write_text(f"#!/bin/sh\nexec {PY!s} -I -S {TESTS / 'fakes' / 'fake_sudo.py'!s} "
                             f"--state '{directory}' \"$@\"\n")
        os.chmod(self.path, 0o755)

    def log(self) -> list[dict[str, Any]]:
        return [json.loads(l) for l in (self.dir / "log.jsonl").read_text().splitlines() if l]

    def run(self, *args: str, input: str | None = None, env: dict[str, str] | None = None
            ) -> subprocess.CompletedProcess[str]:
        return subprocess.run([str(self.path), *args], input=input, capture_output=True,
                              text=True, env=env, timeout=30)


def make_fake_sudo(directory: Path, password: str = "correct horse", nopasswd: bool = False,
                   sudoers_dir: Path | None = None) -> FakeSudo:
    return FakeSudo(directory, password, nopasswd, sudoers_dir=sudoers_dir)


class FakeVisudo:
    """tests/fakes/fake_visudo.py behind a script: `-cf FILE` checks one
    fragment, `-c` every file of `sudoers_dir`. `fail=True` refuses all."""

    def __init__(self, directory: Path, sudoers_dir: Path, fail: bool = False):
        directory.mkdir(parents=True, exist_ok=True)
        self.dir = directory
        self.path = directory / "visudo"
        (directory / "config.json").write_text(json.dumps(
            {"sudoers_dir": str(sudoers_dir), "fail": fail}))
        (directory / "log.jsonl").write_text("")
        self.path.write_text(f"#!/bin/sh\nexec {PY!s} -I -S {TESTS / 'fakes' / 'fake_visudo.py'!s} "
                             f"--state '{directory}' \"$@\"\n")
        os.chmod(self.path, 0o755)

    def log(self) -> list[dict[str, Any]]:
        return [json.loads(l) for l in (self.dir / "log.jsonl").read_text().splitlines() if l]


# ---------------------------------------------------------------------------
# keys
# ---------------------------------------------------------------------------


def ssh_keypair(comment: str = "test") -> tuple[str, str]:
    d = Path(tempfile.mkdtemp(prefix="gwkey-", dir=tmp_base()))
    try:
        subprocess.run([str(ENV_BIN / "ssh-keygen"), "-q", "-t", "ed25519", "-N", "", "-C",
                        comment, "-f", str(d / "k")], check=True, capture_output=True)
        return (d / "k").read_text(), (d / "k.pub").read_text().strip()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def fake_host_key(seed: str) -> str:
    """A syntactically valid ssh-ed25519 public key line (not a real key)."""
    blob = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + (seed.encode() * 32)[:32]
    return "ssh-ed25519 " + base64.b64encode(blob).decode()
