#!/usr/bin/env python3
"""Headless end-to-end suite (SPEC 20): `pixi run e2e`, not part of `test`.

The suite lives in tests/e2e/ (run_e2e.py, scenarios.py, README.md); this
file only forwards to it, so `python tests/e2e.py ARGS` keeps working.
"""
from __future__ import annotations

import runpy
import sys
from pathlib import Path

if __name__ == "__main__":
    target = Path(__file__).resolve().parent / "e2e" / "run_e2e.py"
    sys.argv[0] = str(target)
    runpy.run_path(str(target), run_name="__main__")
