"""Helpers for the nosy observer plugin in tui/observer/.

The plugin records what any installed third-party mod could observe (see the
header of observer/hooks/observer.ts) into $TUI_OBSERVER_OUT/seg-*.jsonl.
Privacy tests load it next to the plugin under test and then search its
records for a canary with scan.py.

    obs = Observer(root)                  # copies the plugin to root/observer-plugin
    Session(..., plugin_dirs=[obs.plugin_dir], extra_env=obs.env())
    # or simply Session(..., observer=True) and use session.observer
    obs.records()                          # parsed records
    obs.events()                           # Counter of event names seen

The plugin is always loaded from a scratch COPY: Claude Code writes
`.claude-plugin/types/` into a mod folder it loads with --plugin-dir, and the
repository copy must stay untouched.
"""
from __future__ import annotations

import collections
import json
import os
import shutil
from pathlib import Path

from . import safety

PLUGIN_SRC = Path(__file__).resolve().parent / "observer"
PLUGIN_NAME = "tui-observer"


def copy_plugin(dest: os.PathLike | str) -> Path:
    """Copy the observer plugin (manifest + hooks only) to `dest`."""
    dest = Path(dest)
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(PLUGIN_SRC, dest, ignore=shutil.ignore_patterns("types", ".DS_Store"))
    return dest


class Observer:
    def __init__(self, root: os.PathLike | str, max_field: int = 65536):
        self.root = safety.check_scratch(Path(root), "observer root")
        self.plugin_dir = copy_plugin(self.root / "observer-plugin")
        self.out = self.root / "observed"
        self.out.mkdir(parents=True, exist_ok=True)
        self.max_field = max_field

    def env(self) -> dict[str, str]:
        return {"TUI_OBSERVER_OUT": str(self.out), "TUI_OBSERVER_MAX": str(self.max_field)}

    def files(self) -> list[Path]:
        return sorted(self.out.glob("seg-*.jsonl"))

    def records(self) -> list[dict]:
        out = []
        for f in self.files():
            for line in f.read_text(errors="replace").splitlines():
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        out.sort(key=lambda r: r.get("n", 0))
        return out

    def events(self) -> collections.Counter:
        return collections.Counter(r.get("ev") for r in self.records())

    def find(self, ev: str | None = None, phase: str | None = None, contains: str | None = None):
        """Records filtered by event name, phase and a substring of `data`.
        (Never pass a canary as `contains` in code that prints the result.)"""
        return [r for r in self.records()
                if (ev is None or r.get("ev") == ev) and (phase is None or r.get("phase") == phase)
                and (contains is None or contains in (r.get("data") or ""))]
