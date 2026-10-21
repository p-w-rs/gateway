"""The explicit test API: redirect every gateway location to temp folders.

Production code never reads GATEWAY_* variables; tests call

    with testing.override(root=tmp) as o:
        ...

and every function in paths.py (and the few other knobs below) follows `o`.
The one exception (SPEC 1): hook and MCP entry points started by the test
runner as `run.py --test ...` honour GATEWAY_TEST_ROOT (see from_env()).
Claude's Bash never starts hook entry points with --test, and doing so would
only redirect to an empty test vault anyway.

Every override refuses a location under the user's real ~/.config/gateway
(or the real plugin data folder): a test can never touch live secrets.
"""
from __future__ import annotations

import contextlib
import os
import pwd
from pathlib import Path
from typing import Any, Callable, Iterator

TEST_ROOT_VAR = "GATEWAY_TEST_ROOT"


class Override:
    """Every location and knob a test can redirect (None: not redirected). A
    plain class, not a dataclass: every gateway process imports this module,
    and `dataclasses` (with `inspect`) costs a hook a few milliseconds."""

    def __init__(self) -> None:
        self.root: Path | None = None
        self.home: Path | None = None          # ~/.config/gateway
        self.user_home: Path | None = None     # ~ (for ~/.ssh/config, Downloads, ...)
        self.data: Path | None = None          # $CLAUDE_PLUGIN_DATA
        self.run: Path | None = None           # /tmp/gw-$UID
        self.plugin_root: Path | None = None
        self.env_python: Path | None = None    # python baked into stubs
        self.entry: list[str] | None = None    # replaces "<python> -I -S <run.py>" in stubs
        self.local_user: str | None = None
        self.machine_id: str | None = None
        self.tools: dict[str, str] = {}        # name -> absolute path
        self.dialog: Any = None                # fake dialog backend (popup.py, phase B)
        self.keyscan: Callable[[str, int], list[str]] | dict | None = None
        self.system_git: bool | None = None    # pretend the system has (no) git
        self.extra: dict[str, Any] = {}

    def __repr__(self) -> str:
        return f"Override(root={self.root!r})"


_STACK: list[Override] = []


def active() -> Override | None:
    return _STACK[-1] if _STACK else None


def get(name: str, default: Any = None) -> Any:
    o = active()
    if o is None:
        return default
    if hasattr(o, name):
        v = getattr(o, name)
        return default if v is None else v
    return o.extra.get(name, default)


def real_user_home() -> Path:
    try:
        return Path(pwd.getpwuid(os.getuid()).pw_dir)
    except KeyError:  # pragma: no cover
        return Path(os.path.expanduser("~"))


def forbidden_roots() -> list[Path]:
    """Locations no test may ever resolve into, each spelled twice: as written
    (from the password database's home) and with only its parent folders
    resolved. The locations themselves are never stat'ed: realpath lstats
    every component it walks, and ~/.config/gateway holds live secrets
    (PLAN-v4 phase 2; tests/tui/safety.py protected_paths does the same)."""
    h = real_user_home()
    out = [h / ".config" / "gateway"]
    for base in (h / ".claude", h / ".config" / "claude",
                 Path(os.environ["CLAUDE_CONFIG_DIR"]) if os.path.isabs(
                     os.environ.get("CLAUDE_CONFIG_DIR", "")) else None):
        if base is not None:
            out.append(base / "plugins" / "data")
    res: list[Path] = []
    for p in out:
        for q in (Path(os.path.abspath(p)), _parent_resolved(p)):
            if q not in res:
                res.append(q)
    return res


def _parent_resolved(p: Path) -> Path:
    """`p` with its parent folders resolved and its last name as written (so
    `p` itself is never stat'ed)."""
    try:
        return Path(os.path.realpath(Path(p).parent)) / Path(p).name
    except (OSError, ValueError):
        return Path(p)


def _res(p: Path) -> Path:
    try:
        return Path(p).resolve()
    except (OSError, RuntimeError):
        return Path(p)


def _fold(p: Path) -> str:
    # macOS volumes ignore case: ~/.config/GATEWAY is the real home too
    return os.fspath(p).casefold().rstrip("/") or "/"


def _inside(p: Path, roots: list[Path]) -> Path | None:
    fp = _fold(p)
    for bad in roots:
        fb = _fold(bad)
        if fp == fb or fp.startswith(fb + "/"):
            return bad
    return None


class UnsafeTestPath(SystemExit):
    pass


def guard(path: Path | str | None, what: str = "path") -> None:
    """Abort (SystemExit) if `path` is, or resolves to, the real gateway home
    or the real plugin data folder (or something inside them). The path is
    first compared as written (made absolute, any case), so a protected
    location is refused without a stat; only a path that isn't one as written
    is resolved (a symlink into the real home is still caught)."""
    if path is None:
        return
    roots = forbidden_roots()
    a = Path(os.path.abspath(os.fspath(path)))
    bad = _inside(a, roots)
    if bad is None:
        a = _res(a)
        bad = _inside(a, roots)
    if bad is not None:
        raise UnsafeTestPath(f"testing.override: refusing {what} {a}: it is inside "
                             f"the real {bad}")


@contextlib.contextmanager
def override(root: Path | str | None = None, **kw: Any) -> Iterator[Override]:
    """Redirect the gateway into `root` (home=root/home/.config/gateway,
    user_home=root/home, data=root/data, run=root/run), or set each location
    by keyword. Nested overrides stack."""
    o = Override()
    if root is not None:
        r = Path(root)
        o.root = r
        o.user_home = r / "home"
        o.home = r / "home" / ".config" / "gateway"
        o.data = r / "data"
        o.run = r / "run"
    extra = kw.pop("extra", None) or {}
    for k, v in kw.items():
        if hasattr(o, k):
            setattr(o, k, Path(v) if k in ("home", "user_home", "data", "run", "plugin_root",
                                           "env_python") and v is not None else v)
        else:
            extra[k] = v
    o.extra.update(extra)
    for what in ("home", "user_home", "data", "run"):
        guard(getattr(o, what), what)
    if o.home is None or o.data is None or o.run is None:
        raise UnsafeTestPath("testing.override needs root= or all of home=, data=, run=")
    if o.run is not None:
        o.run.mkdir(parents=True, exist_ok=True)
        os.chmod(o.run, 0o700)
    _STACK.append(o)
    try:
        yield o
    finally:
        _STACK.remove(o)


def from_env(argv_has_test: bool) -> contextlib.AbstractContextManager[Any]:
    """For run.py: with --test, honour GATEWAY_TEST_ROOT (hooks, MCP and the
    daemon only; GATEWAY_TEST_RUN may name a short run dir). Without --test
    (production), a no-op."""
    root = os.environ.get(TEST_ROOT_VAR, "")
    if not argv_has_test:
        return contextlib.nullcontext()
    if not root or not os.path.isabs(root):
        raise UnsafeTestPath("--test needs an absolute GATEWAY_TEST_ROOT")
    kw: dict[str, Any] = {}
    run = os.environ.get("GATEWAY_TEST_RUN", "")
    if run and os.path.isabs(run):
        kw["run"] = run                      # a short run dir (unix socket paths < 104 bytes)
    if os.environ.get("GATEWAY_TEST_MACHINE_ID"):
        kw["machine_id"] = os.environ["GATEWAY_TEST_MACHINE_ID"]
    if os.environ.get("GATEWAY_TEST_SYSTEM_GIT") in ("0", "1"):
        kw["system_git"] = os.environ["GATEWAY_TEST_SYSTEM_GIT"] == "1"
    return override(root, **kw)
