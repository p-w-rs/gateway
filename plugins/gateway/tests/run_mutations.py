#!/usr/bin/env python3
"""Run every mutation check (tests/mutation_check.py and each
tests/mutations_*.py) on scratch copies of the plugin, never on the checkout.

    pixi run mutations [-j N] [-k SUBSTR] [FILE ...]

Each file gets its own copy (src/, tests/, hooks/, run.py, the pixi files) in
a temporary folder under GW_TEST_TMP (else the system temp dir), so files
can run in parallel (-j, default 3) and nobody's test run ever sees a mutated
source file. Each mutation must make its named test fail ("killed"); before
the first mutation each named test runs once unmutated on the copy
(mutation_check.baseline), and a mutation whose test fails then, or whose
snippet isn't found exactly once, is an ERROR, never a kill. Prints the
baseline's line and one summary line per file and exits 1 if any mutation
survived or erred. The copies are removed afterwards.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

TESTS = Path(__file__).resolve().parent
PLUGIN = TESTS.parent
IGNORE = shutil.ignore_patterns(".pixi", "logs", "quarantine", "__pycache__", "*.pyc", ".git")


def files(names: list[str]) -> list[Path]:
    if names:
        return [TESTS / Path(n).name for n in names]
    return [TESTS / "mutation_check.py"] + sorted(TESTS.glob("mutations_*.py"))


def run_one(f: Path, base: Path, pat: str | None) -> tuple[str, int, int, int, int, str]:
    work = Path(tempfile.mkdtemp(prefix=f"mut-{f.stem}-", dir=base))
    try:
        copy = work / "gateway"
        shutil.copytree(PLUGIN, copy, ignore=IGNORE, symlinks=True)
        tmp = work / "tmp"
        tmp.mkdir()
        env = dict(os.environ, GW_TEST_TMP=str(tmp))
        argv = [sys.executable, str(copy / "tests" / f.name), "--copy", str(copy)]
        if pat:
            argv += ["-k", pat]
        t0 = time.time()
        r = subprocess.run(argv, cwd=copy, env=env, capture_output=True, text=True,
                           timeout=4 * 3600)
        out = r.stdout + r.stderr
        m = re.search(r"(\d+) mutations killed, (\d+) survived, (\d+) errors", out)
        killed, survived, errors = (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else (0, -1, 0)
        return f.name, killed, survived, errors, r.returncode, out + f"\n({time.time() - t0:.0f}s)"
    finally:
        shutil.rmtree(work, ignore_errors=True)


def main(argv: list[str]) -> int:
    jobs, pat, names = 3, None, []
    i = 0
    while i < len(argv):
        if argv[i] == "-j":
            jobs = int(argv[i + 1])
            i += 2
            continue
        if argv[i] == "-k":
            pat = argv[i + 1]
            i += 2
            continue
        names.append(argv[i])
        i += 1
    base = Path(os.environ.get("GW_TEST_TMP") or tempfile.gettempdir())
    base.mkdir(parents=True, exist_ok=True)
    todo = files(names)
    bad = 0
    with ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
        for name, killed, survived, errors, rc, out in ex.map(lambda f: run_one(f, base, pat), todo):
            lines = [l for l in out.splitlines()
                     if "SURVIVED" in l or "ERROR" in l or l.startswith("baseline: ")]
            for l in lines:
                print(f"{name}: {l.strip()}")
            took = out.rsplit("(", 1)[-1].rstrip(")\n")
            if survived < 0:
                print(f"{name}: no summary (exit {rc}); last lines:\n" + "\n".join(out.splitlines()[-15:]))
                bad += 1
            else:
                print(f"{name}: {killed} killed, {survived} survived, {errors} errors ({took})")
                bad += 1 if survived or errors or rc else 0
    print("all mutations killed" if not bad else f"{bad} file(s) with surviving mutations or errors")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
