"""Test-only entry point baked into stubs generated under testing.override(entry=...).

    python -I -S tests/entry.py ROOT RUN.PY-ARGS...

Applies testing.override(ROOT) in-process, then runs run.py's dispatcher.
Production stubs never point here (they run run.py, which ignores test roots
for the stand-ins).
"""
import sys
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN / "src"))
sys.path.insert(0, str(PLUGIN))

from gateway import testing  # noqa: E402
import run  # noqa: E402


def main() -> int:
    root = sys.argv[1]
    with testing.override(root):
        return run.dispatch(sys.argv[2] if len(sys.argv) > 2 else "", sys.argv[3:])


if __name__ == "__main__":
    raise SystemExit(main())
