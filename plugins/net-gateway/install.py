#!/usr/bin/env python3
"""Install net-gateway for the current user (run via `pixi run install`).

1. Registers this repo as the local plugin marketplace "local-tools" and
   installs net-gateway from it (`claude plugin ...`).
2. Merges the plugin's permission rules (settings.rules.json at the repo
   root) into your user settings.json, after showing what changes and asking.
   A backup is written first. Re-running is safe: rules already there are
   left alone.

Options: --yes (don't ask), --dry-run (show only), --skip-plugin (settings only).
Only Claude Code and pixi are needed.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

PLUGIN_DIR = Path(__file__).resolve().parent
REPO_ROOT = PLUGIN_DIR.parents[1]
RULES_FILE = REPO_ROOT / "settings.rules.json"
KINDS = ("allow", "ask", "deny")


def settings_path() -> Path:
    base = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    return Path(base) / "settings.json"


def rule_path(p: Path) -> str:
    """A path as Claude Code permission rules spell it: `~/…` under home,
    `//abs/…` otherwise (a single leading `/` would mean relative to the
    settings file)."""
    p = p.resolve()
    try:
        return "~/" + p.relative_to(Path.home().resolve()).as_posix()
    except ValueError:
        return "/" + p.as_posix()


def load_rules(plugin_dir: Path = PLUGIN_DIR) -> dict[str, list[str]]:
    raw = json.loads(RULES_FILE.read_text())["permissions"]
    where = rule_path(plugin_dir)
    return {k: [r.replace("{PLUGIN_DIR}", where) for r in raw.get(k, [])] for k in KINDS}


def merge(settings: dict, rules: dict[str, list[str]]) -> tuple[dict, list[str]]:
    """Add the plugin's rules to a settings dict. A rule the plugin puts on
    'ask' or 'deny' is removed from a weaker list ('allow', or 'allow'/'ask'),
    so a stray allow can't silence a prompt. Returns (new settings, changes)."""
    out = json.loads(json.dumps(settings))
    perm = out.setdefault("permissions", {})
    changes = []
    weaker = {"ask": ["allow"], "deny": ["allow", "ask"], "allow": []}
    for kind in KINDS:
        for rule in rules[kind]:
            for w in weaker[kind]:
                if rule in perm.get(w, []):
                    perm[w].remove(rule)
                    changes.append(f"- {w}: {rule}")
            cur = perm.setdefault(kind, [])
            if rule not in cur:
                cur.append(rule)
                changes.append(f"+ {kind}: {rule}")
    return out, changes


def _claude(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["claude", *args], capture_output=True, text=True)


def install_plugin() -> bool:
    if not shutil.which("claude"):
        print("! The `claude` command isn't on PATH. Install Claude Code first: "
              "https://code.claude.com", file=sys.stderr)
        return False
    listed = _claude("plugin", "marketplace", "list").stdout
    if "local-tools" not in listed:
        r = _claude("plugin", "marketplace", "add", str(REPO_ROOT))
        print(r.stdout.strip() or r.stderr.strip())
        if r.returncode != 0:
            return False
    else:
        print("✓ marketplace local-tools already registered")
    r = _claude("plugin", "install", "net-gateway@local-tools")
    print(r.stdout.strip() or r.stderr.strip())
    return r.returncode == 0 or "already" in (r.stdout + r.stderr).lower()


def main(argv: list[str]) -> int:
    yes, dry = "--yes" in argv, "--dry-run" in argv
    if not dry and "--skip-plugin" not in argv:
        print("== Registering the plugin")
        if not install_plugin():
            return 1

    path = settings_path()
    current = json.loads(path.read_text()) if path.exists() else {}
    new, changes = merge(current, load_rules())
    print(f"\n== Permission rules for {path}")
    if not changes:
        print("✓ already up to date")
    else:
        print("\n".join(changes))
        if dry:
            print("\n(dry run: nothing written)")
            return 0
        if not yes:
            if not sys.stdin.isatty():
                print("\nNot a terminal; re-run with --yes to apply.", file=sys.stderr)
                return 1
            if input("\nApply these changes? [y/N] ").strip().lower() not in ("y", "yes"):
                print("Nothing changed.")
                return 0
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            backup = path.with_name(f"settings.json.bak.{time.strftime('%Y%m%d%H%M%S')}")
            shutil.copy2(path, backup)
            print(f"backup: {backup}")
        mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
        tmp = path.with_name("settings.json.tmp")
        tmp.write_text(json.dumps(new, indent=2) + "\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        print("✓ settings updated")

    print("\nDone. Restart Claude Code (or /reload-plugins), then try /net-gateway:help")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
