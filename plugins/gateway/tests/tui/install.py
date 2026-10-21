"""Hermetic NORMAL installation through a git-source marketplace.

Brief section 14.1 wants acceptance tests on plugins installed the way users
install them, not on a `--plugin-dir` checkout. This module reproduces a
GitHub-style install of the CURRENT working tree without network and without
touching the source repository or the real Claude config:

1. `source_files(src)` lists what a `git add -A` would commit: tracked plus
   untracked-but-not-ignored files (`git -C src ls-files -co
   --exclude-standard`, read-only, GIT_OPTIONAL_LOCKS=0), minus files deleted
   in the working tree. A non-git folder is taken whole (minus .git).
2. `GitServer` + `ServedRepo.publish(src)` copy that list into a scratch work
   tree, commit it there and push it to a scratch bare repo served by
   gitserve.py at http://127.0.0.1:PORT/<name>.git. Publishing again makes a
   new commit on top (what a later `git push` to GitHub would do).
3. `Installation` runs `claude plugin marketplace add <url>`, `claude plugin
   install <plugin>@<marketplace>`, `update`, `disable`, `enable`,
   `uninstall [--keep-data]` with CLAUDE_CONFIG_DIR set to a scratch dir
   (safety.hermetic_env refuses anything else) and reports the installed
   cache path (installed_plugins.json `installPath`) and the plugin data dir
   (<config>/plugins/data/<plugin>-<marketplace>).

`Hermetic` bundles the three for the common case:

    with install.Hermetic(root) as h:
        p = h.install_from(src_repo, repo="checkpoint", plugin="check")
        p.cache_path, p.data_path          # what sessions will run / keep
        ... driver.Session(..., config_dir=h.inst.config_dir) ...
        h.update_from(src_repo, repo="checkpoint", plugin="check")   # new snapshot + updates

The gateway plugin goes through `h.install_gateway_e2e(src_repo)` instead
(gwe2e.py): a Session refuses a gateway installed without its proven e2e
marker.

Claude Code needs `git` on PATH to add a git marketplace (it runs `git clone
--depth 1`); the system git is used.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import safety

HERE = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------


def _git_read(src: os.PathLike | str, *args: str) -> subprocess.CompletedProcess:
    """A read-only git command on a source repository (never writes its index)."""
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    return subprocess.run(["git", "-C", os.fspath(src), *args], capture_output=True,
                          env=env, timeout=120)


def source_files(src: os.PathLike | str) -> list[str]:
    """Relative paths (POSIX) under `src` that a commit of its working tree
    would hold: tracked + untracked-not-ignored, minus deleted files."""
    src = Path(src)
    r = _git_read(src, "rev-parse", "--is-inside-work-tree")
    if r.returncode == 0 and r.stdout.strip() == b"true":
        r = _git_read(src, "ls-files", "-z", "-c", "-o", "--exclude-standard")
        if r.returncode != 0:
            raise RuntimeError(f"git ls-files failed in {src}: {r.stderr.decode(errors='replace')}")
        names = sorted({n.decode("utf-8", "surrogateescape") for n in r.stdout.split(b"\0") if n})
        return [n for n in names if os.path.lexists(src / n)]
    out = []
    for dp, dn, fn in os.walk(src):
        dn[:] = [d for d in dn if d != ".git"]
        for f in fn:
            out.append(Path(dp, f).relative_to(src).as_posix())
    return sorted(out)


def snapshot_tree(src: os.PathLike | str, dest: os.PathLike | str,
                  files: list[str] | None = None) -> list[str]:
    """Copy `files` (default source_files(src)) from src into dest, keeping
    modes and symlinks. dest must not exist or be empty. Returns the list.

    Also the way to give `--plugin-dir` a copy: Claude Code writes
    `.claude-plugin/types/` into a mod folder it loads from disk, so a
    session should never load a repository folder directly."""
    src, dest = Path(src), Path(dest)
    if dest.exists() and any(dest.iterdir()):
        raise FileExistsError(f"{dest} is not empty")
    files = source_files(src) if files is None else files
    for rel in files:
        s, d = src / rel, dest / rel
        d.parent.mkdir(parents=True, exist_ok=True)
        if s.is_symlink():
            os.symlink(os.readlink(s), d)
        else:
            shutil.copy2(s, d)
    return files


# ---------------------------------------------------------------------------
# Git server and served repositories
# ---------------------------------------------------------------------------


def _scratch_git_env(home: Path) -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(home),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": "TUI Harness", "GIT_AUTHOR_EMAIL": "harness@example.invalid",
        "GIT_COMMITTER_NAME": "TUI Harness", "GIT_COMMITTER_EMAIL": "harness@example.invalid",
    }


class GitServer:
    """gitserve.py as a child process serving `<root>/repos/*.git`."""

    def __init__(self, root: os.PathLike | str):
        self.root = safety.check_scratch(Path(root), "git server root")
        self.repos = self.root / "repos"
        self.work = self.root / "work"
        self.home = self.root / "home"
        for d in (self.repos, self.work, self.home):
            d.mkdir(parents=True, exist_ok=True)
        self.port: int | None = None
        self.proc: subprocess.Popen | None = None

    def start(self, timeout: float = 15.0) -> "GitServer":
        pf = self.root / "git.port"
        pf.unlink(missing_ok=True)
        err = open(self.root / "git.stderr", "ab")
        self.proc = subprocess.Popen(
            [sys.executable, "-I", str(HERE / "gitserve.py"), "--root", str(self.repos),
             "--port", "0", "--port-file", str(pf), "--log", str(self.root / "git.log")],
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=err,
            start_new_session=True, env=_scratch_git_env(self.home))
        err.close()
        end = time.time() + timeout
        while time.time() < end:
            if pf.exists():
                self.port = int(pf.read_text().strip())
                return self
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        self.stop()
        raise RuntimeError(f"git server did not start (see {self.root / 'git.stderr'})")

    def stop(self) -> None:
        if self.proc is not None:
            if self.proc.poll() is None:
                safety.kill_tree(self.proc.pid, grace=1.0)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            self.proc = None

    def __enter__(self):
        return self.start() if self.port is None else self

    def __exit__(self, *exc):
        self.stop()

    def url(self, name: str) -> str:
        return f"http://127.0.0.1:{self.port}/{name}.git"

    def repo(self, name: str) -> "ServedRepo":
        return ServedRepo(self, name)


class ServedRepo:
    """A bare repo the server serves, fed from a scratch work tree."""

    def __init__(self, server: GitServer, name: str):
        if not re.fullmatch(r"[A-Za-z0-9._-]+", name):
            raise ValueError(f"bad repo name {name!r}")
        self.server, self.name = server, name
        self.bare = server.repos / f"{name}.git"
        self.work = server.work / name
        self.env = _scratch_git_env(server.home)
        if not self.bare.exists():
            self._git(server.repos, "init", "-q", "--bare", "-b", "main", str(self.bare))
        if not self.work.exists():
            self.work.mkdir(parents=True)
            self._git(self.work, "init", "-q", "-b", "main")
            self._git(self.work, "remote", "add", "origin", str(self.bare))

    def _git(self, cwd: Path, *args: str) -> str:
        r = subprocess.run(["git", *args], cwd=cwd, env=self.env, capture_output=True,
                           text=True, timeout=300)
        if r.returncode != 0:
            raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
        return r.stdout

    @property
    def url(self) -> str:
        return self.server.url(self.name)

    def publish(self, src: os.PathLike | str, message: str | None = None,
                files: list[str] | None = None) -> str:
        """Commit a snapshot of `src` (see source_files) on top of the served
        history and push it. Returns the new commit sha."""
        for entry in self.work.iterdir():
            if entry.name == ".git":
                continue
            if entry.is_dir() and not entry.is_symlink():
                shutil.rmtree(entry)
            else:
                entry.unlink()
        tmp = self.server.root / f".snap-{self.name}-{time.time_ns()}"
        snapshot_tree(src, tmp, files)
        for entry in tmp.iterdir():
            shutil.move(str(entry), self.work / entry.name)
        tmp.rmdir()
        self._git(self.work, "add", "-A")
        self._git(self.work, "commit", "-q", "--allow-empty", "-m",
                  message or f"snapshot of {Path(src).name}")
        self._git(self.work, "push", "-q", "origin", "HEAD:main")
        return self.head()

    def head(self) -> str:
        return self._git(self.work, "rev-parse", "HEAD").strip()

    def marketplace_name(self) -> str:
        """`name` from the published .claude-plugin/marketplace.json."""
        return json.loads((self.work / ".claude-plugin" / "marketplace.json").read_text())["name"]


# ---------------------------------------------------------------------------
# Claude Code's plugin CLI in a scratch config
# ---------------------------------------------------------------------------


@dataclass
class Result:
    argv: list[str]
    rc: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.rc == 0

    def json(self):
        """The last line of stdout that parses as JSON (for --json runs)."""
        for line in reversed(self.out.splitlines()):
            line = line.strip()
            if line.startswith(("{", "[")):
                try:
                    return json.loads(line)
                except ValueError:
                    continue
        try:
            return json.loads(self.out)
        except ValueError:
            return None

    def __str__(self) -> str:
        return f"$ {' '.join(self.argv[1:])}\nrc={self.rc}\n{self.out}{self.err}"


@dataclass
class InstalledPlugin:
    id: str
    version: str | None
    cache_path: Path | None
    data_path: Path
    record: dict = field(default_factory=dict)


def data_dir_name(plugin_id: str) -> str:
    """plugins/data/<name> for `<plugin>@<marketplace>` (Claude Code's naming)."""
    plugin, _, market = plugin_id.partition("@")
    return re.sub(r"[^A-Za-z0-9_-]", "-", f"{plugin}-{market}" if market else plugin)


def find_claude() -> str:
    exe = shutil.which("claude") or os.path.expanduser("~/.local/bin/claude")
    if not os.path.exists(exe):
        raise FileNotFoundError("claude CLI not found on PATH")
    return exe


class Installation:
    """A scratch Claude config plus the `claude plugin ...` commands on it.

    root/cfg is CLAUDE_CONFIG_DIR, root/home is HOME, root/tmp is TMPDIR and
    root/cwd the working directory of every CLI call (so no project's
    .claude/settings.json is read)."""

    def __init__(self, root: os.PathLike | str, claude: str | None = None,
                 base_url: str = "http://127.0.0.1:9", extra_env: dict | None = None,
                 config_dir: os.PathLike | str | None = None):
        self.root = safety.check_scratch(Path(root), "installation root")
        self.config_dir = safety.check_scratch(Path(config_dir) if config_dir else self.root / "cfg",
                                               "CLAUDE_CONFIG_DIR")
        self.home = self.root / "home"
        self.tmp = self.root / "tmp"
        self.cwd = self.root / "cwd"
        for d in (self.config_dir, self.home, self.tmp, self.cwd):
            d.mkdir(parents=True, exist_ok=True)
        self.claude = claude or find_claude()
        self.base_url = base_url
        self.extra_env = dict(extra_env or {})
        self.history: list[Result] = []

    def env(self, runtime_dir: os.PathLike | str | None = None) -> dict[str, str]:
        return safety.hermetic_env(config_dir=self.config_dir, home=self.home, tmpdir=self.tmp,
                                   base_url=self.base_url, runtime_dir=runtime_dir,
                                   extra=self.extra_env)

    def run(self, *args: str, timeout: float = 300, check: bool = False) -> Result:
        """`claude plugin <args>` in the scratch config."""
        argv = [self.claude, "plugin", *args]
        rd = safety.short_runtime_dir()
        try:
            env = self.env(rd)  # hermetic_env refuses a non-scratch CLAUDE_CONFIG_DIR
            r = subprocess.run(argv, cwd=self.cwd, env=env, stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=timeout)
        finally:
            shutil.rmtree(rd, ignore_errors=True)
        res = Result(argv, r.returncode, r.stdout, r.stderr)
        self.history.append(res)
        if check and not res.ok:
            raise RuntimeError(f"claude plugin {' '.join(args)} failed:\n{res}")
        return res

    # marketplaces ----------------------------------------------------------
    def marketplace_add(self, source: str, check: bool = True) -> Result:
        return self.run("marketplace", "add", source, check=check)

    def marketplace_update(self, name: str | None = None, check: bool = True) -> Result:
        return self.run("marketplace", "update", *([name] if name else []), check=check)

    def marketplace_remove(self, name: str, check: bool = True) -> Result:
        return self.run("marketplace", "remove", name, check=check)

    def marketplaces(self) -> dict:
        p = self.config_dir / "plugins" / "known_marketplaces.json"
        return json.loads(p.read_text()) if p.exists() else {}

    # plugins -------------------------------------------------------------------
    def install(self, plugin_id: str, scope: str = "user", check: bool = True) -> InstalledPlugin:
        self.run("install", plugin_id, "--scope", scope, check=check)
        return self.plugin(plugin_id)

    def update(self, plugin_id: str, check: bool = True) -> Result:
        return self.run("update", plugin_id, check=check)

    def disable(self, plugin_id: str, check: bool = True) -> Result:
        return self.run("disable", plugin_id, check=check)

    def enable(self, plugin_id: str, check: bool = True) -> Result:
        return self.run("enable", plugin_id, check=check)

    def uninstall(self, plugin_id: str, keep_data: bool = False, check: bool = True) -> Result:
        return self.run("uninstall", *(["--keep-data"] if keep_data else []), plugin_id, check=check)

    def validate(self, path: os.PathLike | str, strict: bool = False) -> Result:
        return self.run("validate", *(["--strict"] if strict else []), os.fspath(path))

    def list(self) -> list | dict | None:
        return self.run("list", "--json", check=True).json()

    def record(self, plugin_id: str, scope: str = "user") -> dict | None:
        """The installed_plugins.json record of `plugin_id` (or None)."""
        p = self.config_dir / "plugins" / "installed_plugins.json"
        if not p.exists():
            return None
        recs = json.loads(p.read_text()).get("plugins", {}).get(plugin_id) or []
        for r in recs:
            if r.get("scope") == scope:
                return r
        return recs[0] if recs else None

    def enabled(self, plugin_id: str) -> bool | None:
        p = self.config_dir / "settings.json"
        if not p.exists():
            return None
        return json.loads(p.read_text()).get("enabledPlugins", {}).get(plugin_id)

    def data_path(self, plugin_id: str) -> Path:
        return self.config_dir / "plugins" / "data" / data_dir_name(plugin_id)

    def plugin(self, plugin_id: str) -> InstalledPlugin:
        rec = self.record(plugin_id) or {}
        cp = Path(rec["installPath"]) if rec.get("installPath") else None
        return InstalledPlugin(plugin_id, rec.get("version"), cp, self.data_path(plugin_id), rec)


class Hermetic:
    """A git server, a served repo per source and a scratch installation."""

    def __init__(self, root: os.PathLike | str, claude: str | None = None,
                 extra_env: dict | None = None, config_dir: os.PathLike | str | None = None):
        self.root = safety.check_scratch(Path(root), "hermetic root")
        self.server = GitServer(self.root / "git")
        self.inst = Installation(self.root / "claude", claude=claude, extra_env=extra_env,
                                 config_dir=config_dir)
        self.repos: dict[str, ServedRepo] = {}
        self.gateway_dirs: tuple[Path, Path] | None = None   # gwe2e: (e2e root, run dir)
        self.gateway_run_tmp: Path | None = None

    def __enter__(self):
        self.server.start()
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self) -> None:
        self.server.stop()
        if self.gateway_run_tmp is not None:   # the gateway's short run dir under /tmp
            shutil.rmtree(self.gateway_run_tmp, ignore_errors=True)
            self.gateway_run_tmp = None

    def publish(self, src: os.PathLike | str, repo: str, message: str | None = None) -> ServedRepo:
        r = self.repos.get(repo) or self.server.repo(repo)
        self.repos[repo] = r
        r.publish(src, message)
        return r

    def install_from(self, src: os.PathLike | str, repo: str, plugin: str) -> InstalledPlugin:
        """Publish src, add it as a marketplace and install `plugin` from it."""
        r = self.publish(src, repo)
        if r.marketplace_name() not in self.inst.marketplaces():
            self.inst.marketplace_add(r.url)
        return self.inst.install(f"{plugin}@{r.marketplace_name()}")

    def update_from(self, src: os.PathLike | str, repo: str, plugin: str) -> InstalledPlugin:
        """Publish a new snapshot, then `marketplace update` + `plugin update`."""
        r = self.publish(src, repo)
        self.inst.marketplace_update(r.marketplace_name())
        self.inst.update(f"{plugin}@{r.marketplace_name()}")
        return self.inst.plugin(f"{plugin}@{r.marketplace_name()}")

    # the gateway (gwe2e.py) ----------------------------------------------------
    def install_gateway_e2e(self, src: os.PathLike | str, repo: str = "gateway",
                            plugin: str = "gate", **kw):
        """The gateway's only safe working route in a Session: publish src with
        an e2e marker naming 0700 scratch folders, install it, prove the
        installed copy honours the marker (sh and Python), record the proof
        in the config. Refuses a config dir the marker rules reject before
        publishing anything. -> gwe2e.GatewayInstall (see gwe2e.install)."""
        from . import gwe2e
        return gwe2e.install(self, src, repo, plugin, **kw)

    def update_gateway_e2e(self, src: os.PathLike | str, repo: str = "gateway",
                           plugin: str = "gate", **kw):
        """install_gateway_e2e's update: a new snapshot (same marker), then
        `marketplace update` + `plugin update`, proven and recorded again."""
        from . import gwe2e
        return gwe2e.install(self, src, repo, plugin, update=True, **kw)
