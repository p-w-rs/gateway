"""The gateway plugin under the harness: its one working, safe route (the e2e
marker) and the guard that keeps a Session from loading it any other way.

Why this exists. The gateway takes its home from the password database,
never from $HOME, so a session that loads it has to redirect it, and only one
of its two redirections works in a session:

* GATEWAY_TEST_ROOT (safety.hermetic_env sets it by default) redirects only
  `run.py --test` and `launch.sh MODE --test`, which hooks.json never passes.
  In a session it makes every Python hook, the MCP server and every stand-in
  exit 2 ("GATEWAY_TEST_ROOT is set but this isn't a `run.py --test` ...")
  and the sh hooks resolve no home: safe, but inert, and the screen need not
  say so (the mod shows no warning: setup still ends in its "ready" toast,
  /gate-doctor answers), so a test built on it can pass falsely.
* The e2e marker: a file `e2e-root` in the plugin folder naming a scratch
  root (and a short run dir). The gateway honours it only when the plugin
  folder, the marker and the named folders all follow hooks/e2e.sh's rules
  (paths spelled with [A-Za-z0-9/._-] only, below /tmp, /var/tmp or
  /var/folders, folders 0700 and owned by this user, the marker not group or
  other writable); otherwise it silently ignores the marker and uses the real
  ~/.config/gateway. And run.py refuses every mode while GATEWAY_TEST_ROOT
  is set, so that variable has to go, but only once the marker is proven.

So:

    gi = h.install_gateway_e2e(repo_checkout)     # install.Hermetic; -> GatewayInstall
    with Session(root / "s1", config_dir=h.inst.config_dir) as s:   # proof checked again
        ...                                       # GATEWAY_TEST_ROOT unset, checkpoint
                                                  # pointed at the e2e gateway home

`install()` refuses a config dir the marker rules reject (a space, a non-ASCII
letter, outside a temp folder) before publishing anything, publishes a
snapshot of the checkout with the marker (the checkout is never written),
installs it, runs the pre-flight on the installed copy and records the proof
in `<config>/.tui-harness/gateway-e2e.json`. `preflight()` asks the installed
copy itself: `sh hooks/launch.sh e2e-root` (the sh hooks' reading of the
marker) and its own `gateway.paths` (Python's), both of which must name the
marker's folders, and every gateway location under the marker must lie inside
them. `session_gateways()` + `verify()` are what driver.Session.start runs:
every gateway the session would load (enabled in the config's or the cwd's
settings, or a --plugin-dir) must pass the pre-flight again, and an installed
one must also match its recorded proof, or the Session refuses to start
(unless `allow_inert_gateway=True`, which keeps GATEWAY_TEST_ROOT set).

The pre-flight never touches the real ~/.config/gateway: launch.sh runs with
GATEWAY_TEST_ROOT set and no --test (so it resolves no home at all), and the
Python side replaces gateway.testing.guard (which would realpath, so lstat,
the real gateway home) for its own process; the locations are checked by text
here instead.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from . import safety

MARKER = "e2e-root"
E2E_CONFIG = "e2e.json"
PROOF_DIR = ".tui-harness"
PROOF_FILE = "gateway-e2e.json"
# hooks/e2e.sh's gw_e2e_tmp and gateway.paths.E2E_TEMP_ROOTS, spelled the same.
E2E_TEMP_ROOTS = ("/tmp", "/private/tmp", "/var/tmp", "/private/var/tmp", "/var/folders",
                  "/private/var/folders")
_CHARS = re.compile(r"[A-Za-z0-9/._-]+")
# gateway.paths functions the Python pre-flight reports (missing ones are skipped;
# REQUIRED must be there).
LOCATION_FNS = ("home", "user_home", "form_path", "private_dir", "key_path", "vault_path",
                "pending_dir", "launcher_path", "env_sh_path", "v2_store_path", "v2_key_path",
                "data_dir", "bin_dir", "pycache_dir", "git_config_path", "envs_dir",
                "audit_path", "env_python", "checkpoint_state_dir")
REQUIRED = ("home", "user_home", "data_dir", "env_sh_path", "run_dir")

_PY_PREFLIGHT = r'''
import json, sys
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
from gateway import paths, testing
# The harness checks every location below by text; gateway.testing.guard would
# realpath (lstat) the real ~/.config/gateway, which the harness never touches.
testing.guard = lambda *a, **k: None
fns = json.loads(sys.argv[2])
m = paths.e2e_marker()
out = {"marker": [str(m[0]), str(m[1]) if m[1] else None] if m else None, "locs": {}}
if m:
    with paths.e2e_context():
        for fn in fns:
            f = getattr(paths, fn, None)
            if f is None:
                continue
            try:
                out["locs"][fn] = str(f())
            except Exception as e:
                out["locs"][fn] = "ERR " + type(e).__name__
        try:
            out["locs"]["run_dir"] = str(paths.run_dir(create=False))
        except Exception as e:
            out["locs"]["run_dir"] = "ERR " + type(e).__name__
print(json.dumps(out))
'''


class NotProven(safety.UnsafePath):
    """A gateway would run without a proven e2e redirection."""


# ---------------------------------------------------------------------------
# The marker rules (hooks/e2e.sh), as path arithmetic
# ---------------------------------------------------------------------------


def spelled_ok(s: str) -> bool:
    """hooks/e2e.sh's gw_e2e_tmp: only [A-Za-z0-9/._-], no `.`/`..`
    components or `//`, and strictly below one of E2E_TEMP_ROOTS."""
    if not _CHARS.fullmatch(s or ""):
        return False
    if "/../" in s or s.endswith("/..") or "/./" in s or s.endswith("/.") or "//" in s:
        return False
    t = s + "/"
    return any(t.startswith(r + "/") and len(t) > len(r) + 1 for r in E2E_TEMP_ROOTS)


def check_rules(path: os.PathLike | str, what: str) -> Path:
    """Return the physical `path` if both its spelling and its physical path
    follow the marker rules, else raise NotProven (the gateway would ignore a
    marker there and fall back to the real ~/.config/gateway)."""
    a = os.fspath(path)
    if not os.path.isabs(a):
        a = os.path.abspath(a)   # as written otherwise: `//` and `..` count
    p = os.path.realpath(a)
    for s in (a, p):
        if not spelled_ok(s):
            raise NotProven(
                f"{what} {s!r} breaks the gateway's e2e marker rules (only [A-Za-z0-9/._-], "
                f"below one of {', '.join(E2E_TEMP_ROOTS)}): the gateway would ignore the "
                "marker and use the real ~/.config/gateway; use a plain path")
    return Path(p)


def _private_dir(path: Path, what: str) -> Path:
    """A 0700 directory owned by this user, following the marker rules."""
    safety.check_scratch(path, what)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise NotProven(f"{what} {path} is not a directory of this user")
    return check_rules(path, what)


# ---------------------------------------------------------------------------
# What a session would load
# ---------------------------------------------------------------------------


def looks_like_gateway(d: os.PathLike | str | None) -> bool:
    """A gateway plugin folder (any version): plugin.json names "gate", or it
    has the gateway's launcher and package."""
    if d is None:
        return False
    d = Path(d)
    try:
        if json.loads((d / ".claude-plugin" / "plugin.json").read_text()).get("name") == "gate":
            return True
    except (OSError, ValueError, AttributeError):
        pass
    return ((d / "src" / "gateway" / "paths.py").is_file()
            and ((d / "hooks" / "e2e.sh").is_file() or (d / "hooks" / "launch.sh").is_file()))


@dataclass
class Found:
    source: str               # "config" (enabled in settings) or "plugin-dir"
    plugin_id: str | None     # <plugin>@<marketplace> for "config"
    path: Path | None         # the folder the session would run (None: not installed)
    where: str = ""           # the settings file or the --plugin-dir argument


def _json(p: Path):
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError):
        return None


def enabled_plugins(config_dir: os.PathLike | str, cwd: os.PathLike | str | None = None
                    ) -> dict[str, str]:
    """{plugin id: settings file} for every plugin enabled in the config's
    settings.json or the cwd's .claude/settings{,.local}.json (never a file
    in a protected location)."""
    files = [Path(config_dir) / "settings.json"]
    if cwd is not None:
        files += [Path(cwd) / ".claude" / "settings.json",
                  Path(cwd) / ".claude" / "settings.local.json"]
    out: dict[str, str] = {}
    for f in files:
        if safety.overlaps_protected(f):
            continue
        data = _json(f)
        ep = data.get("enabledPlugins") if isinstance(data, dict) else None
        if isinstance(ep, dict):
            for pid, on in ep.items():
                if on:
                    out.setdefault(str(pid), str(f))
    return out


def install_paths(config_dir: os.PathLike | str, plugin_id: str) -> list[Path]:
    data = _json(Path(config_dir) / "plugins" / "installed_plugins.json")
    recs = (data or {}).get("plugins", {}).get(plugin_id) or [] if isinstance(data, dict) else []
    return [Path(r["installPath"]) for r in recs if isinstance(r, dict) and r.get("installPath")]


def session_gateways(config_dir: os.PathLike | str, cwd: os.PathLike | str | None = None,
                     plugin_dirs=()) -> list[Found]:
    """Every gateway a session on this config (and cwd, and --plugin-dirs)
    would load. An enabled plugin named `gate` that isn't installed counts,
    with path None."""
    found: list[Found] = []
    for pid, where in enabled_plugins(config_dir, cwd).items():
        paths = install_paths(config_dir, pid)
        gw = [p for p in paths if looks_like_gateway(p)]
        if gw:
            found += [Found("config", pid, p, where) for p in gw]
        elif pid.partition("@")[0] == "gate":
            found.append(Found("config", pid, paths[0] if paths else None, where))
    for d in plugin_dirs:
        if looks_like_gateway(d):
            found.append(Found("plugin-dir", None, Path(d), str(d)))
    return found


# ---------------------------------------------------------------------------
# The pre-flight and the proof
# ---------------------------------------------------------------------------


@dataclass
class Proof:
    plugin_dir: str
    root: str
    run: str | None
    marker_sha256: str
    sh: list[str]
    locations: dict[str, str]
    plugin_id: str | None = None
    checked_at: float = field(default_factory=time.time)

    @property
    def gateway_home(self) -> Path:
        return Path(self.locations["home"])

    def env(self) -> dict[str, str | None]:
        """What a Session on this gateway sets: GATEWAY_TEST_ROOT unset (run.py
        refuses every mode while it is set) and checkpoint pointed at the e2e
        gateway home instead of the scratch default."""
        h = self.gateway_home
        return {"GATEWAY_TEST_ROOT": None,
                "CHECKPOINT_GATEWAY_ENV": self.locations.get("env_sh_path", str(h / "env.sh")),
                "CHECKPOINT_GATEWAY_CONTRACT": str(h / "run" / "contract.json")}


def _inside(loc: str, bases: list[str]) -> bool:
    return any(loc == b or loc.startswith(b.rstrip("/") + "/") for b in bases)


def preflight(plugin_dir: os.PathLike | str, expect: tuple[str, str | None] | None = None,
              plugin_id: str | None = None, python: str | None = None,
              timeout: float = 60) -> Proof:
    """Prove that the gateway in `plugin_dir` is redirected by its marker:
    the folder and the marker follow the rules, `sh hooks/launch.sh e2e-root`
    and gateway.paths both report the marker's folders (`expect`, when
    given), and every gateway location lies inside them. Raises NotProven."""
    pd = Path(plugin_dir)
    if not looks_like_gateway(pd) or not (pd / "hooks" / "launch.sh").is_file():
        raise NotProven(f"{pd} is not a gateway plugin folder")
    phys = check_rules(pd, "the gateway plugin folder")
    if os.lstat(phys).st_uid != os.getuid():
        raise NotProven(f"{phys} is not owned by this user")
    mk = phys / MARKER
    try:
        st = os.lstat(mk)
    except FileNotFoundError:
        raise NotProven(f"{phys} has no {MARKER} marker: the gateway would use the real "
                        "~/.config/gateway (install it with install.Hermetic.install_gateway_e2e)")
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o022:
        raise NotProven(f"{mk} is not a regular file of this user that only it can write: "
                        "the gateway would ignore it")
    raw = mk.read_bytes()
    lines = [ln for ln in raw.decode("utf-8", "replace").split("\n") if ln.strip()]
    if not 1 <= len(lines) <= 2:
        raise NotProven(f"{mk} must hold one or two lines")
    root = check_rules(lines[0], "the marker's root")
    run = check_rules(lines[1], "the marker's run dir") if len(lines) == 2 else None
    for d, what in ((root, "the marker's root"), (run, "the marker's run dir")):
        if d is None:
            continue
        safety.check_scratch(d, what)
        s = os.lstat(d)
        if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) & 0o077:
            raise NotProven(f"{what} {d} must be a 0700 directory of this user")
    want = [str(root), str(run) if run else ""]
    if expect is not None and [str(expect[0]), str(expect[1] or "")] != want:
        raise NotProven(f"{mk} names {want}, not the recorded {list(expect)}")
    work = root / ".preflight"
    work.mkdir(mode=0o700, exist_ok=True)
    # The sh hooks' reading. GATEWAY_TEST_ROOT without --test: launch.sh
    # resolves no home at all, and e2e-root mode only validates the marker.
    r = subprocess.run(["/bin/sh", str(phys / "hooks" / "launch.sh"), "e2e-root"],
                       cwd=work, capture_output=True, text=True, timeout=timeout,
                       env={"PATH": "/usr/bin:/bin", "HOME": str(work), "LANG": "C",
                            "GATEWAY_TEST_ROOT": str(work / "unused")})
    sh = r.stdout.split("\n")[:2]
    if r.returncode != 0 or sh != want:
        raise NotProven(f"the gateway's sh hooks ignore the marker in {phys} "
                        f"(launch.sh e2e-root: rc={r.returncode}, {sh!r}, {r.stderr[-300:]!r})")
    # Python's reading, from the installed copy's own gateway.paths.
    r = subprocess.run([python or sys.executable, "-I", "-B", "-c", _PY_PREFLIGHT,
                        str(phys / "src"), json.dumps(LOCATION_FNS)],
                       cwd=work, capture_output=True, text=True, timeout=timeout,
                       env={"PATH": "/usr/bin:/bin", "HOME": str(work), "LANG": "C.UTF-8"})
    try:
        out = json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise NotProven(f"the gateway's Python pre-flight failed in {phys}: {r.stderr[-600:]!r}")
    if out.get("marker") != [str(root), str(run) if run else None]:
        raise NotProven(f"gateway.paths ignores the marker in {phys} (reads {out.get('marker')!r})")
    locs: dict[str, str] = out.get("locs") or {}
    bases = [str(root)] + ([str(run)] if run else [])
    bad = sorted(f"{k}={v}" for k, v in locs.items()
                 if v.startswith("ERR") or not _inside(v, bases) or safety.overlaps_protected(v))
    missing = [k for k in REQUIRED if k not in locs]
    if bad or missing:
        raise NotProven(f"gateway locations outside the e2e root in {phys}: {bad}, missing {missing}")
    return Proof(str(phys), str(root), str(run) if run else None,
                 hashlib.sha256(raw).hexdigest(), sh, locs, plugin_id)


def proof_path(config_dir: os.PathLike | str) -> Path:
    return Path(config_dir) / PROOF_DIR / PROOF_FILE


def read_proofs(config_dir: os.PathLike | str) -> dict[str, dict]:
    data = _json(proof_path(config_dir))
    return data.get("plugins", {}) if isinstance(data, dict) else {}


def write_proof(config_dir: os.PathLike | str, proof: Proof) -> Path:
    p = proof_path(config_dir)
    p.parent.mkdir(mode=0o700, exist_ok=True)
    os.chmod(p.parent, 0o700)
    data = {"version": 1, "plugins": read_proofs(config_dir)}
    data["plugins"][proof.plugin_id or proof.plugin_dir] = asdict(proof)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)
    return p


def verify(found: Found, config_dir: os.PathLike | str, python: str | None = None) -> Proof:
    """The proof a Session needs for one gateway it would load: the
    pre-flight passes now, and an installed gateway matches its recorded
    proof (same folder, marker and e2e folders). Raises NotProven."""
    label = found.plugin_id or found.where
    if found.path is None:
        raise NotProven(f"{label} is enabled ({found.where}) but not installed")
    if found.source == "plugin-dir":
        return preflight(found.path, python=python)
    rec = read_proofs(config_dir).get(found.plugin_id or "")
    if not rec:
        raise NotProven(f"{label} is enabled in {found.where} without an e2e proof: installed "
                        "without the e2e marker it either does nothing (GATEWAY_TEST_ROOT set) "
                        "or uses the real ~/.config/gateway (unset). Install it with "
                        "install.Hermetic.install_gateway_e2e, or pass allow_inert_gateway=True")
    if os.path.realpath(rec.get("plugin_dir", "")) != os.path.realpath(found.path):
        raise NotProven(f"{label} now runs from {found.path}, not the proven "
                        f"{rec.get('plugin_dir')} (updated without update_gateway_e2e?)")
    proof = preflight(found.path, expect=(rec["root"], rec.get("run")),
                      plugin_id=found.plugin_id, python=python)
    if proof.marker_sha256 != rec.get("marker_sha256"):
        raise NotProven(f"{label}'s marker changed since its proof")
    return proof


# ---------------------------------------------------------------------------
# Installing the gateway the safe way
# ---------------------------------------------------------------------------


@dataclass
class GatewayInstall:
    plugin: object            # install.InstalledPlugin
    proof: Proof

    @property
    def root(self) -> Path:
        return Path(self.proof.root)

    @property
    def run(self) -> Path | None:
        return Path(self.proof.run) if self.proof.run else None

    @property
    def gateway_home(self) -> Path:
        return self.proof.gateway_home

    def env(self) -> dict[str, str | None]:
        return self.proof.env()


def _plugin_source(stage: Path, plugin: str) -> Path:
    mk = json.loads((stage / ".claude-plugin" / "marketplace.json").read_text())
    for e in mk.get("plugins", []):
        if e.get("name") == plugin and isinstance(e.get("source"), str):
            return (stage / e["source"]).resolve()
    raise ValueError(f"plugin {plugin!r} not in {stage}/.claude-plugin/marketplace.json")


def install(h, src: os.PathLike | str, repo: str = "gateway", plugin: str = "gate", *,
            update: bool = False, version: str | None = None, e2e_config: dict | None = None,
            root: os.PathLike | str | None = None) -> GatewayInstall:
    """Install (or, with update=True, update) the gateway from `src` into
    h.inst's scratch config with the e2e marker, prove it, record the proof.

    The config dir must follow the marker rules; this is checked before
    anything is published. The e2e root (default h.root/"gw-e2e") and a
    short run dir under /tmp (removed by h.close()) are 0700 folders reused
    by later calls. `version` rewrites the published plugin.json version (for
    update scenarios); `e2e_config` is written to <root>/e2e.json (the
    gateway's test knobs: fake dialog, tools, ...)."""
    from . import install as inst_mod

    check_rules(h.inst.config_dir, "the Claude config dir")
    if getattr(h, "gateway_dirs", None) is None:
        r = _private_dir(Path(root) if root else h.root / "gw-e2e", "the gateway e2e root")
        # Short (unix socket paths stay under 104 bytes); h.close() removes it.
        run = Path(os.path.realpath(tempfile.mkdtemp(prefix="tui-gw-", dir="/tmp")))
        h.gateway_run_tmp = run
        h.gateway_dirs = (r, _private_dir(run, "the gateway run dir"))
    root_p, run_p = h.gateway_dirs
    if e2e_config is not None:
        cfgf = root_p / E2E_CONFIG
        cfgf.write_text(json.dumps(e2e_config))
        os.chmod(cfgf, 0o600)
    stage = h.root / f".gw-stage-{time.time_ns()}"
    try:
        inst_mod.snapshot_tree(src, stage)
        pdir = _plugin_source(stage, plugin)
        if not looks_like_gateway(pdir):
            raise ValueError(f"{plugin} in {src} is not the gateway plugin")
        if version is not None:
            pj = pdir / ".claude-plugin" / "plugin.json"
            data = json.loads(pj.read_text())
            data["version"] = version
            pj.write_text(json.dumps(data, indent=2) + "\n")
        mk = pdir / MARKER
        mk.write_text(f"{root_p}\n{run_p}\n")
        os.chmod(mk, 0o644)
        served = h.publish(stage, repo, message=f"snapshot of {Path(src).name} + e2e marker")
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    pid = f"{plugin}@{served.marketplace_name()}"
    # Claude Code's install checks the copy out with the process's umask: under
    # Debian's default 002 the installed marker would be group-writable, which
    # the marker rules refuse (rightly), so the install runs under 022, as a
    # typical user's would
    old_umask = os.umask(0o022)
    try:
        if update:
            h.inst.marketplace_update(served.marketplace_name())
            h.inst.update(pid)
        else:
            if served.marketplace_name() not in h.inst.marketplaces():
                h.inst.marketplace_add(served.url)
            h.inst.install(pid)
    finally:
        os.umask(old_umask)
    p = h.inst.plugin(pid)
    if p.cache_path is None:
        raise NotProven(f"{pid} reports no install path")
    proof = preflight(p.cache_path, expect=(str(root_p), str(run_p)), plugin_id=pid)
    write_proof(h.inst.config_dir, proof)
    return GatewayInstall(p, proof)
