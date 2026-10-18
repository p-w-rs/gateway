#!/usr/bin/env python3
"""Developer helper (`pixi run install`). Users don't need it: the standard
plugin install (/plugin marketplace add p-w-rs/gateway, /plugin install
gate@gateway) is all there is, because the gateway's rules live in its own
hooks.

1. Registers this checkout as the local plugin marketplace "gateway" and
   installs the plugin from it (`claude plugin ...`), so edits here are live.
2. Removes what gateway v0.5 wrote into your settings.json (permission rules
   and the strict-mode `env` entries, listed in legacy-settings.json), after
   showing it and asking. A backup is written first. Settings the gateway
   didn't add are left alone.

Options: --yes (don't ask), --dry-run (show only), --skip-plugin (cleanup only).
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
LEGACY_FILE = PLUGIN_DIR / "legacy-settings.json"
KINDS = ("allow", "ask", "deny")


def settings_path() -> Path:
    base = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    return Path(base) / "settings.json"


def rule_path(p: Path) -> str:
    """A path as Claude Code permission rules spell it: `~/…` under home,
    `//abs/…` otherwise."""
    p = p.resolve()
    try:
        return "~/" + p.relative_to(Path.home().resolve()).as_posix()
    except ValueError:
        return "/" + p.as_posix()


def legacy(plugin_dir: Path = PLUGIN_DIR) -> dict:
    """Everything v0.5's installer could have added: rules per kind (with
    {PLUGIN_DIR} filled in) and env entries with the value it set."""
    raw = json.loads(LEGACY_FILE.read_text())
    where = rule_path(plugin_dir)
    rules = {k: [r.replace("{PLUGIN_DIR}", where) for r in raw["permissions"].get(k, [])]
             for k in KINDS}
    strict = raw.get("strict", {})
    for k in ("allow", "deny"):
        rules[k] += strict.get(k, [])
    env = dict(strict.get("env", {}))
    return {"rules": rules, "env": env}


def cleanup(settings: dict, old: dict) -> tuple[dict, list[str]]:
    """Remove v0.5's rules and env entries. An env entry goes only if it still
    has a value v0.5 set ("" or the template's), so the user's own stays."""
    out = json.loads(json.dumps(settings))
    perm = out.get("permissions", {})
    changes = []
    for kind in KINDS:
        have = perm.get(kind)
        if not isinstance(have, list):
            continue
        for rule in old["rules"][kind]:
            while rule in have:
                have.remove(rule)
                changes.append(f"- {kind}: {rule}")
        if not have:
            perm.pop(kind)
    if "permissions" in out and not out["permissions"]:
        out.pop("permissions")
    env = out.get("env")
    if isinstance(env, dict):
        for k, v in old["env"].items():
            if k in env and env[k] in ("", v):
                del env[k]
                changes.append(f"- env: {k}")
        if not env:
            out.pop("env")
    return out, changes


def _claude(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["claude", *args], capture_output=True, text=True)


def install_plugin() -> bool:
    if not shutil.which("claude"):
        print("! The `claude` command isn't on PATH. Install Claude Code first: "
              "https://code.claude.com", file=sys.stderr)
        return False
    listed = _claude("plugin", "marketplace", "list").stdout
    if "gateway" not in listed:
        r = _claude("plugin", "marketplace", "add", str(REPO_ROOT))
        print(r.stdout.strip() or r.stderr.strip())
        if r.returncode != 0:
            return False
    else:
        print("✓ marketplace gateway already registered")
    r = _claude("plugin", "install", "gate@gateway")
    print(r.stdout.strip() or r.stderr.strip())
    return r.returncode == 0 or "already" in (r.stdout + r.stderr).lower()


def main(argv: list[str]) -> int:
    yes, dry = "--yes" in argv, "--dry-run" in argv
    if not dry and "--skip-plugin" not in argv:
        print("== Registering the plugin from this checkout")
        if not install_plugin():
            return 1

    path = settings_path()
    current = json.loads(path.read_text()) if path.exists() else {}
    new, changes = cleanup(current, legacy())
    print(f"\n== Old gateway entries in {path}")
    if not changes:
        print("✓ none (the gateway keeps its rules in its own hooks)")
    else:
        print("\n".join(changes))
        if dry:
            print("\n(dry run: nothing written)")
            return 0
        if not yes:
            if not sys.stdin.isatty():
                print("\nNot a terminal; re-run with --yes to apply.", file=sys.stderr)
                return 1
            if input("\nRemove these? [y/N] ").strip().lower() not in ("y", "yes"):
                print("Nothing changed.")
                return 0
        backup = path.with_name(f"settings.json.bak.{time.strftime('%Y%m%d%H%M%S')}")
        shutil.copy2(path, backup)
        print(f"backup: {backup}")
        mode = path.stat().st_mode & 0o777
        tmp = path.with_name("settings.json.tmp")
        tmp.write_text(json.dumps(new, indent=2) + "\n")
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        print("✓ settings cleaned")
    stale = PLUGIN_DIR / "config" / "local.json"
    if stale.exists() and not dry:
        stale.unlink()
        print("✓ removed config/local.json (take-over is always on now)")

    print("\nDone. Start a new Claude Code session, then try /gate:help")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
