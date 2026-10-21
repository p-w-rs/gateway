"""What a release ships (PLAN-v4 phase 1; brief section 2): every file the
plugin's configs, hook scripts and mod start is in the plugin folder, and
tests/release_check.py tells whether the git index holds the tested tree
(checked on throwaway repos; for this checkout it prints a note, never a
failure, while the tree is uncommitted). Read-only git only."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import harness as H

RC = H.TESTS / "release_check.py"
GIT_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
GIT_ENV.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1")


# ---------------------------------------------------------------------------
# Every referenced file is in the plugin
# ---------------------------------------------------------------------------


def _refs_from_json(v, out: set[str]) -> None:
    if isinstance(v, str):
        out.update(re.findall(r"\$\{CLAUDE_PLUGIN_ROOT\}/([^\s\"']+)", v))
    elif isinstance(v, dict):
        for x in v.values():
            _refs_from_json(x, out)
    elif isinstance(v, list):
        for x in v:
            _refs_from_json(x, out)


def referenced_files() -> set[str]:
    """Plugin-relative paths the plugin starts or reads at run time."""
    root = H.PLUGIN
    refs: set[str] = set()
    hooks = json.loads((root / "hooks" / "hooks.json").read_text())
    _refs_from_json(hooks.get("hooks", {}), refs)
    for m in hooks.get("modules", []):
        refs.add(os.path.normpath(f"hooks/{m}"))
    _refs_from_json(json.loads((root / ".mcp.json").read_text()), refs)
    # the sh scripts: $ROOT/... (launch.sh), $dir/... and $here/... (siblings)
    for sh in (root / "hooks").glob("*.sh"):
        text = sh.read_text()
        refs.update(re.findall(r'"\$ROOT/([A-Za-z0-9_./-]+)"', text))
        refs.update("hooks/" + x for x in re.findall(r'"\$(?:dir|here)/([A-Za-z0-9_.-]+\.sh)"', text))
    # the managed shell's prefix: named by the mod (lib.ts GATE_SH) and pre_bash.sh
    lib = (root / "hooks" / "mod" / "lib.ts").read_text()
    refs.update(re.findall(r"export const GATE_SH = '([A-Za-z0-9_./-]+)'", lib))
    # the mod's own imports (every file it imports is loaded from the plugin)
    for f in (root / "hooks" / "mod").glob("*.ts*"):
        for imp in re.findall(r"""from\s+['"](\.{1,2}/[^'"]+)['"]""", f.read_text()):
            refs.add(os.path.normpath(str((f.parent / imp).relative_to(root))))
    return refs


def test_every_referenced_file_is_in_the_plugin():
    refs = referenced_files()
    must = {"hooks/launch.sh", "hooks/pre_bash.sh", "hooks/mcp_perm.sh", "hooks/post.sh",
            "hooks/prompt.sh", "hooks/home.sh", "hooks/e2e.sh", "hooks/mod/register.tsx",
            "hooks/mod/lib.ts", "hooks/gate-sh", "run.py", "pixi.toml", "pixi.lock", "src"}
    assert must <= refs, sorted(must - refs)
    # Claude Code runs the prefix as a program (git keeps the mode; managed.py copies it
    # into the data folder when an install dropped it)
    assert os.access(H.PLUGIN / "hooks" / "gate-sh", os.X_OK), "hooks/gate-sh must be executable"
    optional = {"e2e-root"}      # the e2e suite's marker, written into scratch copies only
    missing = sorted(r for r in refs - optional if not (H.PLUGIN / r).exists())
    assert not (H.PLUGIN / "e2e-root").exists(), "the checkout must never carry the e2e marker"
    assert not missing, f"referenced but not in the plugin folder: {missing}"
    outside = sorted(r for r in refs if ".." in Path(r).parts)
    assert not outside, f"the plugin reaches outside its folder: {outside}"
    # Markdown commands and skills ship as files too
    for md in list((H.PLUGIN / "commands").glob("*.md")) + list((H.PLUGIN / "skills").glob("*/SKILL.md")):
        assert md.read_text().startswith("---"), md


def test_referenced_files_are_not_git_ignored():
    git = shutil.which("git")
    if git is None:
        print("    note: git not found; ignore check skipped")
        return
    paths = sorted(r for r in referenced_files() if (H.PLUGIN / r).is_file())
    r = subprocess.run([git, "-C", str(H.PLUGIN), "check-ignore", "--no-index", *paths],
                       capture_output=True, text=True, timeout=30,
                       env=dict(os.environ, GIT_OPTIONAL_LOCKS="0"))
    if r.returncode == 128:
        print(f"    note: not a git work tree; ignore check skipped ({r.stderr.strip()[:80]})")
        return
    assert r.stdout.strip() == "", f"git ignores files the plugin needs: {r.stdout.split()}"


def test_gitignore_covers_engine_types_and_the_users_old_data():
    lines = (H.PLUGIN / ".gitignore").read_text().split()
    for want in (".pixi/", "__pycache__/", "logs/", "quarantine/", ".claude-plugin/types/",
                 "/tsconfig.json"):
        assert want in lines, want


# ---------------------------------------------------------------------------
# The MCP server's version doesn't drift from plugin.json after an update
# ---------------------------------------------------------------------------


def test_the_gw_server_version_tracks_plugin_json():
    """The gw MCP server's serverInfo version is the package __version__, kept
    equal to plugin.json's "version": a release that bumps one must bump both,
    so an updated gateway never reports a stale server version (as checkpoint's
    invariant-10 test does for its own server)."""
    from gateway import __version__
    from gateway.mcp_server import SERVER_INFO

    manifest = json.loads((H.PLUGIN / ".claude-plugin" / "plugin.json").read_text())
    assert SERVER_INFO["version"] == __version__, (SERVER_INFO, __version__)
    assert __version__ == manifest["version"], (__version__, manifest["version"])
    # the hard-coded literal is gone: the constant reads the package version
    src = (H.PLUGIN / "src" / "gateway" / "mcp_server.py").read_text()
    assert '"version": __version__' in src and f'"version": "{__version__}"' not in src


# ---------------------------------------------------------------------------
# The release check, on throwaway repos
# ---------------------------------------------------------------------------


def _rc(where: Path | None, env: dict[str, str]) -> tuple[int, str]:
    r = subprocess.run([sys.executable, str(RC)] + ([str(where)] if where else []),
                       capture_output=True, text=True, timeout=60, env=env)
    return r.returncode, r.stdout + r.stderr


def test_release_check_on_a_throwaway_repo():
    if shutil.which("git") is None:
        print("    note: git not found; release check not tested")
        return
    tmp = Path(tempfile.mkdtemp(prefix="gw-release-", dir=H.tmp_base()))
    env = dict(GIT_ENV, GIT_CEILING_DIRECTORIES=str(tmp.resolve()))

    def tgit(repo: Path, *args: str) -> None:
        subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                       timeout=30, env=env)

    try:
        repo = tmp / "repo"
        rp = repo / "plugins" / "gateway"
        for rel, text in {".claude-plugin/marketplace.json": "{}\n", "README.md": "readme\n",
                          "plugins/gateway/.gitignore": ".pixi/\nlogs/\nquarantine/\n__pycache__/\n"
                                                        "*.pyc\n.claude-plugin/types/\n",
                          "plugins/gateway/hooks/hooks.json": "{}\n",
                          "plugins/gateway/commands/old.md": "old\n",
                          ".gitignore": ".work/\n.DS_Store\n"}.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(text)
        tgit(repo, "init", "-q")
        tgit(repo, "add", "-A")
        code, out = _rc(rp, env)
        assert code == 0 and "ready" in out, out
        assert "logs/ + quarantine/" in out and "leave them alone" in out, out
        # the release this guards: new files the hooks start, old ones dropped
        (rp / "hooks" / "launch.sh").write_text("exit 0\n")
        (rp / "hooks" / "mod").mkdir(parents=True)
        (rp / "hooks" / "mod" / "register.tsx").write_text("export const register = () => {}\n")
        (rp / "commands" / "old.md").unlink()
        (rp / "hooks" / "hooks.json").write_text('{"modules": ["./mod/register.tsx"]}\n')
        code, out = _rc(repo, env)
        assert code == 1 and "untracked" in out and "plugins/gateway/hooks/launch.sh" in out, out
        assert "plugins/gateway/hooks/mod/register.tsx" in out and "git add -A" in out
        assert "deleted, not staged" in out and "plugins/gateway/commands/old.md" in out
        assert "modified, not staged" in out and "plugins/gateway/hooks/hooks.json" in out
        tgit(repo, "add", "-A")
        index = (repo / ".git" / "index").read_bytes()
        # caches, Claude Code's types folder, the tsconfig.json it writes at the
        # plugin root, and the user's old data don't count (untracked here: junk
        # drops them before they can read as "untracked, so installs lack them")
        for junk in (".pixi/envs/default/bin/python", "src/gateway/__pycache__/x.cpython-312.pyc",
                     ".claude-plugin/types/claude-code/index.d.ts", "tsconfig.json",
                     "logs/audit.jsonl", "quarantine/claude.tar.gz", "hooks/.DS_Store"):
            (rp / junk).parent.mkdir(parents=True, exist_ok=True)
            (rp / junk).write_text("x")
        os.utime(rp / "hooks" / "launch.sh", (1, 1))     # stat-dirty only
        code, out = _rc(repo, env)
        assert code == 0, out
        assert (repo / ".git" / "index").read_bytes() == index, "the check never writes the index"
        # a file the plugin needs that a .gitignore hides
        (rp / ".gitignore").write_text((rp / ".gitignore").read_text() + "hooks/local*.sh\n")
        tgit(repo, "add", "-A")
        (rp / "hooks" / "local-pixi.sh").write_text("x")
        code, out = _rc(repo, env)
        assert code == 1 and "plugins/gateway/hooks/local-pixi.sh" in out and ".gitignore" in out, out
        (tmp / "not-a-repo").mkdir()
        code, out = _rc(tmp / "not-a-repo", env)
        assert code == 2 and "ready" not in out.replace("not ready", ""), out
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_release_check_note_for_this_checkout():
    """A note for whoever commits this repo (read-only; never fails)."""
    if shutil.which("git") is None:
        print("    note: git not found; release check skipped")
        return
    code, out = _rc(None, dict(os.environ, GIT_OPTIONAL_LOCKS="0"))
    if code == 1:
        print("    note (release check, not a failure while the tree is uncommitted): "
              + "\n          ".join(out.strip().splitlines()[:6]))
    elif code == 2:
        print("    note: release check can't tell here: " + out.strip()[:200])
    assert code in (0, 1, 2), out
