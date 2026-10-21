"""Every location the gateway uses (SPEC 1). The only place they are computed.

    ~/.config/gateway/                 home (0700)
      gateway.toml                     the form (Claude may read and edit it)
      gate                             launcher for the user's terminal
      env.sh                           same content as CLAUDE_ENV_FILE
      private/                         0700; Claude must never read it
        key.txt | key.wrapped key.recipient  vault.age  cache.age  .lock  backups/  pending/
      run/contract.json                0600 (dir 0700): the daemon's CONTRACT-v1 discovery file
    $CLAUDE_PLUGIN_DATA/               survives plugin updates
      envs/<lock-sha12>/  bin/  git/config  audit.jsonl  gated/ (log, epoch, events/)
    /tmp/gw-$UID/                      run dir, 0700, owner-checked (gated.sock, gated.lock, ...)

Production code never reads GATEWAY_* variables. The home folder comes from
the password database (not $HOME), so a process that changes HOME can't point
the gateway at another vault. Tests redirect everything through
`gateway.testing.override(...)`; the data folder follows Claude Code's
CLAUDE_PLUGIN_DATA (hooks, MCP) or GW_DATA (baked into the stand-ins).
"""
from __future__ import annotations

import os
import pwd
import re
import stat
import sys
import unicodedata
from pathlib import Path

from . import testing

PLUGIN_DATA_NAME = "gate-gateway"


class PathError(Exception):
    """A location exists but is unsafe to use (wrong owner or mode)."""


def _override(name: str) -> Path | None:
    o = testing.active()
    if o is None:
        return None
    v = getattr(o, name, None)
    return Path(v) if v is not None else None


def user_home() -> Path:
    """The user's real home (password database), or the test's fake one."""
    o = _override("user_home")
    if o is not None:
        return o
    try:
        return Path(pwd.getpwuid(os.getuid()).pw_dir)
    except KeyError:  # pragma: no cover - no passwd entry
        return Path(os.path.expanduser("~"))


def local_user() -> str:
    o = testing.active()
    if o is not None and o.local_user:
        return o.local_user
    try:
        return pwd.getpwuid(os.getuid()).pw_name
    except KeyError:  # pragma: no cover
        return os.environ.get("USER", "user")


# ---------------------------------------------------------------------------
# The gateway home (~/.config/gateway)
# ---------------------------------------------------------------------------


def home() -> Path:
    o = _override("home")
    if o is not None:
        return o
    return user_home() / ".config" / "gateway"


def form_path() -> Path:
    return home() / "gateway.toml"


def from_v2_form_path() -> Path:
    return home() / "gateway.from-v2.toml"


def launcher_path() -> Path:
    return home() / "gate"


def env_sh_path() -> Path:
    return home() / "env.sh"


def private_dir() -> Path:
    return home() / "private"


def key_path() -> Path:
    return private_dir() / "key.txt"


def vault_path() -> Path:
    return private_dir() / "vault.age"


def cache_path() -> Path:
    return private_dir() / "cache.age"


def lock_path() -> Path:
    return private_dir() / ".lock"


def wrapped_key_path() -> Path:
    """The vault key encrypted to the user's passphrase (PLAN-v4 phase 2)."""
    return private_dir() / "key.wrapped"


def recipient_path() -> Path:
    """The vault key's public recipient (age1...), kept beside key.wrapped."""
    return private_dir() / "key.recipient"


def backups_dir() -> Path:
    return private_dir() / "backups"


def pending_dir() -> Path:
    return private_dir() / "pending"


# v2 files (migration reads them; the file guard protects them)
def v2_store_path() -> Path:
    return home() / "store.age"


def v2_key_path() -> Path:
    return home() / "key.txt"


def v2_lock_path() -> Path:
    return home() / ".lock"


def ensure_home() -> Path:
    d = home()
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    return d


def ensure_private() -> Path:
    """home and private/ (both 0700). Returns private/."""
    ensure_home()
    p = private_dir()
    p.mkdir(mode=0o700, exist_ok=True)
    try:
        os.chmod(p, 0o700)
    except OSError:
        pass
    return p


# ---------------------------------------------------------------------------
# Plugin data ($CLAUDE_PLUGIN_DATA)
# ---------------------------------------------------------------------------


# This process's run.py mode ("shim sudo", "hook-post", "gate", ...), set by
# run.py's dispatch: the daemon client lets a hook register its session.
ENTRY_MODE = ""

# Whether this process may take the data folder from its environment. Only
# run.py's hook and MCP modes set it: Claude Code itself puts
# CLAUDE_PLUGIN_DATA there. Stand-ins, askpass, the git helper and `gate` run
# inside Claude's Bash, where any variable can be set by the caller, so they
# derive the folder from the python that runs them instead.
_TRUST_ENV_DATA = False


def trust_plugin_env(ok: bool = True) -> None:
    """run.py: hook and MCP modes may use CLAUDE_PLUGIN_DATA (set by Claude Code)."""
    global _TRUST_ENV_DATA
    _TRUST_ENV_DATA = bool(ok)


def _env_abs(var: str) -> str | None:
    v = os.environ.get(var, "")
    return v if v and "${" not in v and os.path.isabs(v) else None


def data_from_executable(executable: str | None = None) -> Path | None:
    """<DATA> when this python is <DATA>/envs/<sha12>/.pixi/envs/default/bin/python*
    (how every stub and launch.sh start the gateway), else None."""
    exe = Path(executable or sys.executable or "")
    try:
        p = exe.parents
        if (exe.name.startswith("python") and p[0].name == "bin" and p[1].name == "default"
                and p[2].name == "envs" and p[3].name == ".pixi" and p[5].name == "envs"
                and exe.is_absolute()):
            return p[6]
    except IndexError:
        pass
    return None


def data_dir() -> Path:
    """The plugin data folder.

    Hook and MCP modes (trust_plugin_env): CLAUDE_PLUGIN_DATA, which Claude Code
    sets. Every mode: the folder of the pixi env this python belongs to. Last:
    GW_DATA (the stand-in stubs set it themselves, overriding the caller), then
    ~/.claude/plugins/data/gate-gateway (CLAUDE_CONFIG_DIR is honoured only in
    hook and MCP modes). Stand-ins never follow CLAUDE_PLUGIN_DATA: a command in
    Claude's Bash could set it to redirect the audit log or the binaries."""
    o = _override("data")
    if o is not None:
        return o
    if _TRUST_ENV_DATA:
        v = _env_abs("CLAUDE_PLUGIN_DATA")
        if v:
            return Path(v)
    d = data_from_executable()
    if d is not None:
        return d
    v = _env_abs("GW_DATA")
    if v:
        return Path(v)
    base = _env_abs("CLAUDE_CONFIG_DIR") if _TRUST_ENV_DATA else None
    if not base:
        base = str(user_home() / ".claude")
    return Path(base) / "plugins" / "data" / PLUGIN_DATA_NAME


def bin_dir() -> Path:
    return data_dir() / "bin"


def pycache_dir() -> Path:
    """Python's bytecode cache for the gateway's own processes (`-X
    pycache_prefix=`, set by launch.sh, the stubs and the launcher), so no
    __pycache__ is ever written into the plugin folder (versioned content)."""
    return data_dir() / "pycache"


def git_dir() -> Path:
    return data_dir() / "git"


def git_config_path() -> Path:
    return git_dir() / "config"


def envs_dir() -> Path:
    return data_dir() / "envs"


def audit_path() -> Path:
    return data_dir() / "audit.jsonl"


# ---------------------------------------------------------------------------
# The run dir (/tmp/gw-$UID)
# ---------------------------------------------------------------------------


def run_dir(create: bool = True) -> Path:
    """/tmp/gw-$UID: created 0700; refused if it isn't a directory owned by
    this user with mode 0700 (someone else could read sockets and FIFOs)."""
    d = _override("run") or Path("/tmp") / f"gw-{os.getuid()}"
    if create:
        try:
            os.mkdir(d, 0o700)
        except FileExistsError:
            pass
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        if create:
            raise
        return d
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise PathError(f"{d} is not a directory; the gateway won't use it")
    if st.st_uid != os.getuid():
        raise PathError(f"{d} belongs to another user; the gateway won't use it")
    if st.st_mode & 0o077:
        raise PathError(f"{d} is readable by others (mode {stat.S_IMODE(st.st_mode):o}); "
                        "the gateway won't use it")
    return d


def run_file(name: str) -> Path:
    return run_dir() / name


def sudo_probe_path(user: str) -> Path:
    """Where the sudo stand-in caches its `sudo -n true` probe (SPEC 9.1)."""
    return run_dir() / f"sudo-nopasswd-{user}"


def refusals_dir() -> Path:
    d = run_dir() / "refusals"
    d.mkdir(mode=0o700, exist_ok=True)
    return d


def session_dir() -> Path:
    d = run_dir() / "sessions"
    d.mkdir(mode=0o700, exist_ok=True)
    return d


# The gateway daemon (PLAN-v4 phase 2, daemon/): its socket, single-instance
# lock and session registry in the private run dir; its log, epoch counter and
# event files in the plugin data folder; the contract file for checkpoint in
# the gateway home (CONTRACT-v1 "Discovery").
def gated_socket() -> Path:
    return run_dir() / "gated.sock"


def gated_lock() -> Path:
    return run_dir() / "gated.lock"


def gated_start_lock() -> Path:
    return run_dir() / "gated.start.lock"


def gated_sessions() -> Path:
    return run_dir() / "gated-sessions.json"


def gated_dialogs() -> Path:
    """The native dialogs waiting for an answer (metadata only, never a value
    or a key: daemon/dialogs.py), so a restarted daemon shows them again."""
    return run_dir() / "gated-dialogs.json"


def gated_tmux_socket() -> Path:
    """The terminal supervisor's tmux server (PLAN-v4 phase 5,
    daemon/terminals.py): a private socket in the run dir, never the user's
    tmux server."""
    return run_dir() / "tmux.sock"


def gated_tmux_conf() -> Path:
    """The gateway's own tmux config (written by gated at start; the user's
    ~/.tmux.conf is never read)."""
    return run_dir() / "tmux.conf"


def gated_terms_dir() -> Path:
    """Per-pane start files (rc/script, 0600, removed by the pane once read)
    and job output FIFOs."""
    return run_dir() / "terms"


def gated_terminals() -> Path:
    """The terminals' and jobs' records (ids, owners, states; never screen
    content, input or a value): in the data folder, so a host reboot (which
    empties the run dir) is reported as "gone" rather than forgotten."""
    return gated_dir() / "terminals.json"


def gated_remote() -> Path:
    """The remote hosts' runtime and identity state (PLAN-v4 phase 6,
    daemon/remote.py): runtime folder, version, readiness, the per-host
    marker nonce; never a key or a value."""
    return gated_dir() / "remote.json"


def runtime_src_dir() -> Path:
    """The remote runtime's workspace in the plugin (runtime/pixi.toml and
    pixi.lock, PLAN-v4 phase 6): read only, packed by gated."""
    return plugin_root() / "runtime"


def runtime_data_dir() -> Path:
    """Where gated builds the remote runtime's packs (one folder per runtime
    version and platform) and keeps pixi-pack's package cache."""
    return data_dir() / "runtime"


def gated_dir() -> Path:
    return data_dir() / "gated"


def gated_log() -> Path:
    return gated_dir() / "gated.log"


def contract_dir() -> Path:
    return home() / "run"


def contract_path() -> Path:
    return contract_dir() / "contract.json"


def checkpoint_state_dir() -> Path:
    """The checkpoint plugin's state folder (`${XDG_STATE_HOME:-~/.local/state}/
    checkpoint`, as checkpoint's state.home()). Only its existence is read:
    Claude's context mentions checkpoint jobs when it is there (SPEC 13).
    Under a test override: in the test's home, whatever XDG_STATE_HOME says."""
    if testing.active() is None:
        x = os.environ.get("XDG_STATE_HOME", "")
        if os.path.isabs(x):
            return Path(x) / "checkpoint"
    return user_home() / ".local" / "state" / "checkpoint"


# ---------------------------------------------------------------------------
# The plugin and its pixi env
# ---------------------------------------------------------------------------


def plugin_root() -> Path:
    o = _override("plugin_root")
    if o is not None:
        return o
    return Path(__file__).resolve().parents[2]


def run_py() -> Path:
    return plugin_root() / "run.py"


def launch_sh() -> Path:
    return plugin_root() / "hooks" / "launch.sh"


_SHA_CACHE: dict[str, str] = {}


def lock_sha12() -> str:
    """First 12 hex digits of sha256(pixi.lock); names the env dir."""
    lock = plugin_root() / "pixi.lock"
    key = str(lock)
    if key not in _SHA_CACHE:
        import hashlib  # here, not at the top: the hooks that never need it start faster
        try:
            _SHA_CACHE[key] = hashlib.sha256(lock.read_bytes()).hexdigest()[:12]
        except OSError:
            _SHA_CACHE[key] = "nolock000000"
    return _SHA_CACHE[key]


def env_dir() -> Path:
    return envs_dir() / lock_sha12()


def env_bin() -> Path:
    return env_dir() / ".pixi" / "envs" / "default" / "bin"


def env_python() -> Path:
    """The python the stand-ins and hooks run (baked into the stubs)."""
    o = _override("env_python")
    if o is not None:
        return o
    return env_bin() / "python3"


def env_ready() -> bool:
    return (env_dir() / ".ready").exists() and os.access(env_python(), os.X_OK)


# ---------------------------------------------------------------------------
# The e2e redirection (tests/e2e/README.md): a scratch copy of the plugin only
# ---------------------------------------------------------------------------
# Production reads no environment override for the vault home. The headless
# end-to-end suite runs real Claude Code sessions against a COPY of the plugin
# placed in a temp folder and writes a marker file `e2e-root` into that copy
# (never into the checkout or an installed plugin): line 1 names the e2e root
# folder, an optional line 2 a short run dir (unix socket paths must stay
# under 104 bytes). The marker counts only when all of these hold; otherwise
# it is ignored and nothing changes:
#   - no testing.override is active (unit tests use that API);
#   - the plugin folder this code runs from (this file's location, never a
#     variable) is owned by this user and lies under a system temp folder
#     (/tmp, /var/tmp, macOS /var/folders): a checkout or an installed plugin
#     never does;
#   - the marker is a regular file (not a symlink) owned by this user, not
#     writable by group or others, with one or two non-blank lines, each an
#     absolute path of [A-Za-z0-9/._-] characters;
#   - each named folder is a real directory (not a symlink) owned by this
#     user with no group/other permission bits, spelled and physically under
#     a system temp folder.
# run.py then runs every mode under e2e_context(): testing.override with the
# gateway home, user home, data and run dirs inside the root, plus the fakes
# the unit tests use that the root's e2e.json names (fake dialog, sudo,
# remote euid, ...). hooks/e2e.sh applies the same rules for the sh hooks.
# The marker can only point the gateway at another vault (empty or made by
# whoever wrote the marker); it never reads, copies or reveals the real one.

E2E_MARKER = "e2e-root"
E2E_CONFIG = "e2e.json"
# Spelled exactly like hooks/e2e.sh (gw_e2e_tmp), which checks the same strings.
E2E_TEMP_ROOTS = ("/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders",
                  "/private/var/folders")
_E2E_CHARS = re.compile(r"[A-Za-z0-9/._-]+")
# e2e.json keys passed on to testing.override (anything else is ignored).
E2E_KNOBS = {"dialog": str, "tools": dict, "machine_id": str, "system_git": bool,
             "ssh_remote_euid": str, "popup_wait": (int, float), "popup_lifetime": (int, float),
             "dialog_timeout": (int, float), "clipboard": str}


def code_root() -> Path:
    """The plugin folder this code runs from (never an override)."""
    return Path(__file__).resolve().parents[2]


def _e2e_tmp_ok(s: str, roots: tuple[str, ...] | list[str]) -> bool:
    """hooks/e2e.sh's gw_e2e_tmp: only [A-Za-z0-9/._-], no `.`/`..`
    components or `//`, and strictly below one of `roots`."""
    if not _E2E_CHARS.fullmatch(s or ""):
        return False
    if "/../" in s or s.endswith("/..") or "/./" in s or s.endswith("/.") or "//" in s:
        return False
    t = s + "/"
    return any(t.startswith(r.rstrip("/") + "/") and len(t) > len(r.rstrip("/")) + 1
               for r in roots)


def _read_private_file(path: Path, uid: int, limit: int = 65536) -> str | None:
    """A regular file (no symlink) owned by uid, not group/other-writable."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_mode & 0o022:
            return None
        if st.st_size > limit:
            return None
        return os.read(fd, limit + 1).decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    finally:
        os.close(fd)


def _e2e_dir(raw: str, uid: int, roots: tuple[str, ...] | list[str]) -> Path | None:
    """A folder named by the marker (hooks/e2e.sh's gw_e2e_dir): spelled and
    physically below a temp root, a real directory owned by uid with no
    group/other bits. Returns the physical path."""
    if not _e2e_tmp_ok(raw, roots):
        return None
    try:
        st = os.lstat(raw)
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or stat.S_IMODE(st.st_mode) & 0o077:
            return None
        real = Path(raw).resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        return None
    return real if _e2e_tmp_ok(str(real), roots) else None


def e2e_marker(plugin: Path | str | None = None, *, uid: int | None = None,
               temp_roots: tuple[str, ...] | list[str] | None = None
               ) -> tuple[Path, Path | None] | None:
    """(root, run dir or None) from a valid `e2e-root` marker in the plugin
    folder this code runs from, else None (see the comment above). `plugin`,
    `uid` and `temp_roots` are for tests; a production call (plugin=None)
    returns None while a testing.override is active."""
    if plugin is None:
        if testing.active() is not None:
            return None
        plugin = code_root()
    me = os.getuid() if uid is None else uid
    roots = E2E_TEMP_ROOTS if temp_roots is None else tuple(temp_roots)
    try:
        if not (Path(plugin) / E2E_MARKER).is_file():
            return None              # the common case: no marker
        pr = Path(plugin).resolve(strict=True)
        if os.lstat(pr).st_uid != me or not _e2e_tmp_ok(str(pr), roots):
            return None
    except (OSError, RuntimeError, ValueError):
        return None
    text = _read_private_file(pr / E2E_MARKER, me, limit=4096)
    if text is None:
        return None
    lines = [ln for ln in text.split("\n") if ln.strip()]
    if not 1 <= len(lines) <= 2:
        return None
    root = _e2e_dir(lines[0], me, roots)
    if root is None:
        return None
    run = None
    if len(lines) == 2:
        run = _e2e_dir(lines[1], me, roots)
        if run is None:
            return None
    return root, run


def e2e_root(plugin: Path | str | None = None, *, uid: int | None = None,
             temp_roots: tuple[str, ...] | list[str] | None = None) -> Path | None:
    """The validated e2e root, or None (the marker is absent or ignored)."""
    m = e2e_marker(plugin, uid=uid, temp_roots=temp_roots)
    return m[0] if m else None


def e2e_config(root: Path, uid: int | None = None) -> dict:
    """The testing.override keywords from ROOT/e2e.json (a private file like
    the marker); unknown keys and values of the wrong type are dropped."""
    text = _read_private_file(Path(root) / E2E_CONFIG, os.getuid() if uid is None else uid)
    if text is None:
        return {}
    try:
        import json
        raw = json.loads(text)
    except ValueError:
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict = {}
    for k, typ in E2E_KNOBS.items():
        v = raw.get(k)
        if isinstance(v, typ) and not (typ is not bool and isinstance(v, bool)):
            out[k] = v
    tools = out.get("tools")
    if tools is not None:
        out["tools"] = {str(n): str(p) for n, p in tools.items()
                        if isinstance(p, str) and os.path.isabs(p)}
    return out


def e2e_context():
    """run.py: everything under the e2e redirection when the marker is valid
    (testing.override with the root's folders), else a no-op."""
    import contextlib
    m = e2e_marker()
    if m is None:
        return contextlib.nullcontext()
    root, run = m
    kw = e2e_config(root)
    return testing.override(root, run=run or (root / "run"), e2e=str(root), **kw)


class ToolMissing(Exception):
    pass


def tool(name: str) -> str:
    """Absolute path of a binary shipped in the pixi env (age, ssh, gh, ...):
    next to the running python first, then the data env. Never PATH."""
    cands = [Path(sys.executable).parent / name, env_bin() / name]
    o = testing.active()
    if o is not None and o.tools and name in o.tools:
        cands.insert(0, Path(o.tools[name]))
    for c in cands:
        if c.is_file() and os.access(c, os.X_OK):
            return str(c)
    raise ToolMissing(f"{name} was not found in the gateway's pixi environment")


# ---------------------------------------------------------------------------
# Protected locations (for the file guard and the Bash hook)
# ---------------------------------------------------------------------------


def _resolved(p: Path) -> Path:
    try:
        return p.resolve()
    except (OSError, RuntimeError):
        return p


def protected_paths() -> list[Path]:
    """Locations Claude's tools must never read: private/, the v2 key and
    store, and the run dir."""
    out = [private_dir(), v2_key_path(), v2_store_path()]
    try:
        out.append(run_dir(create=False))
    except PathError:
        out.append(Path("/tmp") / f"gw-{os.getuid()}")
    return [_resolved(p) for p in out]


def real_protected_paths() -> list[Path]:
    """Under the e2e redirection only: the REAL private/, v2 key and store
    and run dir, so the e2e sessions' guards keep Claude away from the real
    vault too. Spelled, never resolved, stat'ed or listed (the e2e code never
    touches the real home)."""
    if not testing.get("e2e"):
        return []
    h = testing.real_user_home() / ".config" / "gateway"
    run = f"gw-{os.getuid()}"
    return [h / "private", h / "key.txt", h / "store.age", Path("/tmp") / run,
            Path("/private/tmp") / run]


def _fold(p: str | os.PathLike[str]) -> str:
    """Case- and normalization-insensitive spelling (macOS volumes ignore case:
    .config/GATEWAY/PRIVATE/key.txt is the real key)."""
    return unicodedata.normalize("NFC", os.fspath(p)).casefold()


def _inode(p: str | os.PathLike[str]) -> tuple[int, int] | None:
    try:
        st = os.stat(p)
    except (OSError, ValueError):
        return None
    return (st.st_dev, st.st_ino)


class Protected:
    """The file guard's view of the protected locations, computed once per hook
    call. A path counts as inside when, spelled case-insensitively after
    resolving symlinks, it is a protected location or below one, or when it (or
    any folder above it) is the same file as a protected one (st_dev, st_ino:
    catches case variants, symlinks and hard links). A path counts as a parent
    when a protected location lies below it (a recursive Grep from there would
    read it)."""

    MAX_WALK = 2000

    def __init__(self) -> None:
        self.paths = protected_paths()
        self.folded = [_fold(p) for p in self.paths]
        # e2e only: the real home's protected spellings, compared as text
        self.folded += [_fold(p) for p in real_protected_paths()]
        self.inside: set[tuple[int, int]] = set()
        self.above: set[tuple[int, int]] = set()
        self._entries: list[str] | None = None
        for q in self.paths:
            i = _inode(q)
            if i:
                self.inside.add(i)
            for a in [q, *q.parents]:
                j = _inode(a)
                if j:
                    self.above.add(j)
        # Every file inside private/ (a hard link to one elsewhere is the same file).
        for full in self._walk(self.paths[0]):
            i = _inode(full)
            if i:
                self.inside.add(i)

    def _walk(self, top: Path) -> list[str]:
        out: list[str] = []
        if not top.is_dir():
            return out
        for dirpath, dirnames, filenames in os.walk(top):
            for name in dirnames + filenames:
                out.append(os.path.join(dirpath, name))
                if len(out) >= self.MAX_WALK:
                    return out
        return out

    @property
    def entries(self) -> list[str]:
        """Concrete existing files (for Glob patterns), spelled folded: the
        protected files and everything inside the protected folders (a
        folder's own name isn't secret). Computed on first use."""
        if self._entries is None:
            ents = [_fold(p) for p in self.paths if p.is_file()]
            for q in self.paths:
                ents += [_fold(x) for x in self._walk(q)]
            self._entries = ents
        return self._entries

    @staticmethod
    def candidates(path: str | os.PathLike[str], cwd: str | None = None) -> list[Path]:
        """Absolute spellings of a tool's path: `~` expands to the home from the
        password database and to $HOME; relative paths are taken from cwd."""
        s = os.fspath(path)
        if s.startswith("~"):
            rest = s[1:]
            if rest and not rest.startswith("/"):
                return [Path(os.path.expanduser(s))]
            out = [Path(str(user_home()) + rest)]
            h = os.environ.get("HOME", "")
            if h and os.path.isabs(h) and Path(h + rest) not in out:
                out.append(Path(h + rest))
            return out
        p = Path(s)
        if not p.is_absolute():
            p = Path(cwd if cwd and os.path.isabs(cwd) else os.getcwd()) / p
        return [p]

    def _one_inside(self, p: Path) -> bool:
        r = _fold(_resolved(p))
        for q in self.folded:
            if r == q or r.startswith(q.rstrip("/") + "/"):
                return True
        for a in [p, *p.parents, _resolved(p)]:
            i = _inode(a)
            if i and i in self.inside:
                return True
        return False

    def _one_parent(self, p: Path) -> bool:
        r = _fold(_resolved(p)).rstrip("/") or "/"
        for q in self.folded:
            if r == "/" or q.startswith(r + "/"):
                return True
        i = _inode(p)
        return bool(i and i in self.above)

    def contains(self, path: str | os.PathLike[str], cwd: str | None = None) -> bool:
        try:
            return any(self._one_inside(c) for c in self.candidates(path, cwd))
        except (OSError, ValueError, RuntimeError):
            return True

    def is_parent(self, path: str | os.PathLike[str], cwd: str | None = None) -> bool:
        try:
            return any(self._one_parent(c) for c in self.candidates(path, cwd))
        except (OSError, ValueError, RuntimeError):
            return True


def is_protected(path: str | os.PathLike, cwd: str | None = None) -> bool:
    """True for paths inside private/, the v2 key and store, or the run dir
    (any spelling: case variants, symlinks, hard links, `..`)."""
    return Protected().contains(path, cwd)


def is_protected_parent(path: str | os.PathLike, cwd: str | None = None) -> bool:
    """True when a protected location lies below `path` (or is `path`)."""
    return Protected().is_parent(path, cwd)


def describe(path: Path) -> str:
    """A path for messages: ~ for the user's home."""
    try:
        return "~/" + str(Path(path).relative_to(user_home()))
    except ValueError:
        return str(path)


# ---------------------------------------------------------------------------
# Claude Code's session transcripts (phase B request, ux)
# ---------------------------------------------------------------------------
# A no-screen pop-up request comes with a one-time code that only the user may
# see; it reaches them as a hook systemMessage, which Claude Code also records
# in the session transcript (<config>/projects/<project>/<session>.jsonl) or,
# for a subagent's tool call, in <project>/<session>/subagents/agent-<id>.jsonl
# (round 3). The file guard and the Bash hook therefore refuse to read any
# .jsonl at any depth under a projects folder (a guardrail for a cooperative
# model, like the private-folder deny), and a recursive search from a folder
# that holds one. The tool-results/ folders (persisted large tool outputs
# Claude reads) stay readable.


def transcript_roots(transcript_path: str | None = None) -> list[Path]:
    """The `projects` folders that hold session transcripts: the one the
    hook payload's transcript_path lives in, CLAUDE_CONFIG_DIR/projects (hook
    modes; not under a test override), ~/.claude/projects and
    ~/.config/claude/projects. Resolved, without duplicates."""
    cands: list[Path] = []
    if isinstance(transcript_path, str) and os.path.isabs(transcript_path):
        tp = Path(transcript_path)
        # <projects>/<project>/<session>.jsonl, or a subagent's
        # <projects>/<project>/<session>/subagents/agent-<id>.jsonl
        for up in list(tp.parents)[1:4]:
            if up.name == "projects":
                cands.append(up)
                break
    if testing.active() is None:
        cfg = os.environ.get("CLAUDE_CONFIG_DIR", "")
        if cfg and os.path.isabs(cfg):
            cands.append(Path(cfg) / "projects")
    home = user_home()
    cands += [home / ".claude" / "projects", home / ".config" / "claude" / "projects"]
    out: list[Path] = []
    for c in cands:
        r = _resolved(c)
        if r not in out:
            out.append(r)
    return out


TOOL_RESULTS = "tool-results"
# Claude Code's Workflow tool keeps a run's journal (agent results, not hook
# messages) at <projects>/<project>/<session>/subagents/workflows/<run>/
# journal.jsonl and tells Claude to read it; next to it are the run's agent
# transcripts (agent-<id>.jsonl), which stay protected.
WORKFLOW_JOURNAL = ("subagents", "workflows", None, "journal.jsonl")


def _under_root(r: str, root: str) -> list[str] | None:
    """The components of folded path `r` below folded `root`, or None."""
    if not r.startswith(root + "/"):
        return None
    return [x for x in r[len(root) + 1:].split("/") if x]


def _workflow_journal(r: Path, below: list[str]) -> bool:
    """`r` (resolved, `below` its components under a projects folder) is a
    Workflow run's journal: exactly `<project>/<session>/subagents/workflows/
    <run>/journal.jsonl`, names in that exact case, and a regular file with
    one link (a hard link to a transcript would have two) or no file yet."""
    if len(below) != 6:
        return False
    tail = r.parts[-4:]
    if len(tail) != 4 or any(w is not None and w != t for w, t in zip(WORKFLOW_JOURNAL, tail)):
        return False
    try:
        st = os.lstat(r)
    except FileNotFoundError:
        return True
    except (OSError, ValueError):
        return False
    return stat.S_ISREG(st.st_mode) and st.st_nlink == 1


def is_transcript(path: str | os.PathLike[str], cwd: str | None = None,
                  roots: list[Path] | None = None) -> bool:
    """A session transcript: a `.jsonl` file anywhere under a `projects`
    folder (`<project>/<session>.jsonl`, a subagent's
    `<project>/<session>/subagents/agent-<id>.jsonl`, a Workflow run's
    `agent-<id>.jsonl`), but not inside a tool-results folder and not a
    Workflow run's `journal.jsonl` (_workflow_journal); in any spelling (case,
    symlinks, `~`, relative to cwd)."""
    roots = transcript_roots() if roots is None else roots
    folded = [_fold(r).rstrip("/") for r in roots]
    try:
        for c in Protected.candidates(path, cwd):
            r = _resolved(c)
            if r.suffix.casefold() != ".jsonl":
                continue
            fr = _fold(r)
            for root in folded:
                below = _under_root(fr, root)
                if below and TOOL_RESULTS not in below[:-1] and not _workflow_journal(r, below):
                    return True
    except (OSError, ValueError, RuntimeError):
        return True
    return False


def holds_transcripts(path: str | os.PathLike[str], cwd: str | None = None,
                      roots: list[Path] | None = None) -> bool:
    """A recursive search from `path` would read transcripts: it is a
    `projects` folder, a folder above one, or any folder inside one (a
    project, a session's folder with its subagents' transcripts, a Workflow
    run's folder, ...) except a tool-results folder and what is below it. A
    Workflow run's journal file itself holds none."""
    roots = transcript_roots() if roots is None else roots
    try:
        for c in Protected.candidates(path, cwd):
            rp = _resolved(c)
            r = _fold(rp).rstrip("/")
            for root in roots:
                f = _fold(root).rstrip("/")
                if f == r or f.startswith(r + "/"):
                    return True
                below = _under_root(r, f)
                if below is not None and TOOL_RESULTS not in below \
                        and not _workflow_journal(rp, below):
                    return True
    except (OSError, ValueError, RuntimeError):
        return True
    return False
