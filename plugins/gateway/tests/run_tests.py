#!/usr/bin/env python3
"""Discovering test runner (no pytest). Run from plugins/gateway:

    pixi run test
    pixi run --locked python tests/run_tests.py [-j N] [-k SUBSTR] [-x] [-q] [MODULE ...]

Imports every tests/test_*.py (or the named modules) and runs each module-level
function named test_*. Prints one line per test and "N passed, M failed".
With -j N (pixi run test uses 4), each module runs in its own process (its
own GW_TEST_TMP below the given one), N at a time, heaviest first; the
output of each module is printed when it finishes.
A test-harness guard (tests/harness.py) aborts the whole run if any code
resolves a gateway path outside testing.override or under the real
~/.config/gateway.
Bytecode goes to one folder per run under the test temp root (harness.PYC,
passed to the workers in GW_TEST_PYCACHE), and the run fails (one failure,
the paths listed) if it left anything new in the plugin folder: an entry
directly in it (a __pycache__, a stray x/...), or a __pycache__ folder or
.pyc file under src/ or tests/ (CLAUDE.md invariant 16).
"""
from __future__ import annotations

import importlib
import os
import shutil
import sys
import tempfile
import time
import traceback
from pathlib import Path

TESTS = Path(__file__).resolve().parent
PLUGIN = TESTS.parent
sys.path.insert(0, str(TESTS))
sys.path.insert(0, str(PLUGIN / "src"))


def _bytecode_dir() -> tuple[str, bool]:
    """This run's bytecode folder and whether this process made it (and so
    removes it): a worker of a -j run gets its parent's in GW_TEST_PYCACHE."""
    v = os.environ.get("GW_TEST_PYCACHE", "")
    if os.path.isabs(v):
        os.makedirs(v, exist_ok=True)
        return v, False
    base = os.environ.get("GW_TEST_TMP") or tempfile.gettempdir()
    os.makedirs(base, exist_ok=True)
    v = tempfile.mkdtemp(prefix="gwpyc-", dir=base)
    os.environ["GW_TEST_PYCACHE"] = v
    return v, True


def _litter() -> set[str]:
    """What a test run must not leave in the plugin folder, as paths relative
    to it: every entry directly in the plugin folder (compared with the start
    of the run, so only new ones count; Finder's .DS_Store aside), and every
    __pycache__ folder and .pyc file under src/ and tests/."""
    found = {n for n in os.listdir(PLUGIN) if n != ".DS_Store"}
    for sub in ("src", "tests"):
        for dp, dn, fn in os.walk(PLUGIN / sub):
            rel = os.path.relpath(dp, PLUGIN)
            found.update(os.path.join(rel, d) for d in dn if d == "__pycache__")
            found.update(os.path.join(rel, f) for f in fn if f.endswith(".pyc"))
            dn[:] = [d for d in dn if d != "__pycache__"]
    return found


def _litter_report(before: set[str] | None) -> list[str]:
    """The new litter since `before` (None: not checked here), printed."""
    if before is None:
        return []
    new = sorted(_litter() - before)
    if new:
        print(f"\nLITTER: this run left {len(new)} new path(s) in the plugin folder {PLUGIN} "
              "(tests must write only under the test temp root; bytecode goes to "
              "harness.PYC via -X pycache_prefix):\n  " + "\n  ".join(new))
    return new


def main(argv: list[str]) -> int:
    # a -j worker (its parent checks) and a mutation run (a scratch copy, where
    # a litter failure would count as a kill) don't check
    litter0 = None if os.environ.get("GW_TEST_NO_LITTER_CHECK") == "1" else _litter()
    pyc, own = _bytecode_dir()
    sys.pycache_prefix = pyc          # before the harness or any test module is imported
    try:
        return _main(argv, litter0)
    finally:
        if own:
            shutil.rmtree(pyc, ignore_errors=True)


def _main(argv: list[str], litter0: set[str] | None) -> int:
    pattern = None
    stop = False
    quiet = False
    jobs = 1
    mods: list[str] = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-k":
            pattern = argv[i + 1]
            i += 2
            continue
        if a == "-j":
            jobs = int(argv[i + 1])
            i += 2
            continue
        if a == "-x":
            stop = True
        elif a == "-q":
            quiet = True
        else:
            mods.append(Path(a).stem)
        i += 1
    import harness  # noqa: F401  (installs the guard before any test module loads)
    names = mods or sorted(p.stem for p in TESTS.glob("test_*.py"))
    if jobs > 1 and len(names) > 1:
        return run_parallel(names, jobs, pattern, quiet, litter0)
    passed = failed = 0
    failures: list[str] = []
    times: list[tuple[float, str]] = []
    base = Path(harness.tmp_base())
    before = set(os.listdir(base))
    t0 = time.time()
    for name in names:
        try:
            mod = importlib.import_module(name)
        except SystemExit:
            raise
        except Exception:
            failed += 1
            failures.append(f"{name}: import failed")
            print(f"  FAIL {name} (import)\n" + traceback.format_exc())
            if stop:
                break
            continue
        tests = [(n, f) for n, f in vars(mod).items() if n.startswith("test_") and callable(f)]
        for tname, fn in tests:
            full = f"{name}::{tname}"
            if pattern and pattern not in full:
                continue
            t1 = time.time()
            try:
                fn()
            except harness.GuardTripped:
                print(f"  ABORT {full}: the test guard tripped")
                raise
            except Exception as e:  # noqa: BLE001
                failed += 1
                failures.append(full)
                tb = traceback.format_exc().rstrip().splitlines()
                print(f"  FAIL {full}: {type(e).__name__}: {e}")
                print("\n".join("       " + l for l in tb[-12:]))
                if stop:
                    break
            else:
                passed += 1
                took = time.time() - t1
                times.append((took, full))
                if not quiet:
                    print(f"  ok   {full}" + (f"  ({took:.1f}s)" if took >= 2 else ""))
        if stop and failed:
            break
    dt = time.time() - t0
    if not quiet and times:
        slow = sorted(times, reverse=True)[:10]
        print("\nslowest: " + ", ".join(f"{n.split('::')[-1]} {t:.1f}s" for t, n in slow))
    left = sorted(n for n in set(os.listdir(base)) - before
                  if not n.startswith(("gwv2-", "gwbin-")))   # harnesses remove those at exit
    if left and not quiet:
        print(f"\nleft behind in {base}: {', '.join(left[:10])}")
    if _litter_report(litter0):
        failed += 1
        failures.append("litter in the plugin folder (above)")
    if failures:
        print("\nFailed:\n  " + "\n  ".join(failures))
    print(f"\n{passed} passed, {failed} failed ({dt:.1f}s)")
    return 1 if failed else 0


# Rough cost per test function, by module prefix (real sshds, pop-up helpers
# and subprocess trees are the slow ones): only used to start the heaviest
# modules first.
_WEIGHT = (("test_ssh_", 3.0), ("test_transfer", 1.5), ("test_ux_gate", 1.5), ("test_sudo", 1.2),
           ("test_git_helper", 1.2), ("test_ux_", 0.8), ("test_session", 0.8),
           ("test_web", 0.8), ("test_hookbash_table", 3.0))


def _cost(name: str) -> float:
    try:
        n = sum(1 for l in (TESTS / f"{name}.py").read_text().splitlines()
                if l.startswith(("def test_", "@case(")))
    except OSError:
        n = 1
    return n * next((w for pre, w in _WEIGHT if name.startswith(pre)), 0.3)


def run_parallel(names: list[str], jobs: int, pattern: str | None, quiet: bool,
                 litter0: set[str] | None = None) -> int:
    import re
    import subprocess
    from concurrent.futures import ThreadPoolExecutor, as_completed
    import harness
    base = Path(harness.tmp_base())
    t0 = time.time()

    def one(name: str) -> tuple[str, int, str]:
        tmp = tempfile.mkdtemp(prefix=f"w-{name}-", dir=base)
        argv = [sys.executable, str(Path(__file__).resolve()), name]
        argv += ["-k", pattern] if pattern else []
        argv += ["-q"] if quiet else []
        try:
            r = subprocess.run(argv, capture_output=True, text=True,
                               env=dict(os.environ, GW_TEST_TMP=tmp, GW_TEST_NO_LITTER_CHECK="1"),
                               timeout=1800)
            out, code = r.stdout + r.stderr, r.returncode
        except subprocess.TimeoutExpired as e:
            out, code = f"{(e.stdout or b'')!r}\n  FAIL {name}: timed out after 1800 s\n", 1
        left = [x for x in os.listdir(tmp)] if os.path.isdir(tmp) else []
        if left:
            out += f"\nleft behind by {name}: {', '.join(sorted(left)[:10])}\n"
        shutil.rmtree(tmp, ignore_errors=True)
        return name, code, out

    passed = failed = 0
    failures: list[str] = []
    aborted: list[str] = []
    times: list[tuple[float, str]] = []
    with ThreadPoolExecutor(max_workers=jobs) as ex:
        futs = [ex.submit(one, n) for n in sorted(names, key=_cost, reverse=True)]
        for f in as_completed(futs):
            name, code, out = f.result()
            body = [l for l in out.splitlines() if not re.match(r"^\d+ passed, \d+ failed", l)
                    and not l.startswith(("slowest: ", "Failed:"))]
            print("\n".join(l for l in body if l.strip()), flush=True)
            m = re.search(r"(\d+) passed, (\d+) failed", out)
            if m:
                passed += int(m.group(1))
                failed += int(m.group(2))
            else:
                failed += 1
            failures += re.findall(r"^  FAIL (\S+?)[: ]", out, re.M)
            if "ABORT " in out or "TEST GUARD" in out:
                aborted.append(name)
            elif not m:
                failures.append(f"{name} (exit {code}, no summary)")
            times += [(float(t), n) for n, t in re.findall(r"^  ok   (\S+)  \(([0-9.]+)s\)", out, re.M)]
    dt = time.time() - t0
    if not quiet and times:
        slow = sorted(times, reverse=True)[:10]
        print("\nslowest: " + ", ".join(f"{n.split('::')[-1]} {t:.1f}s" for t, n in slow))
    if _litter_report(litter0):
        failed += 1
        failures.append("litter in the plugin folder (above)")
    if failures:
        print("\nFailed:\n  " + "\n  ".join(dict.fromkeys(failures)))
    if aborted:
        print("\nABORTED (the test guard tripped) in: " + ", ".join(aborted))
        return 2
    print(f"\n{passed} passed, {failed} failed ({dt:.1f}s, {jobs} at a time)")
    return 1 if failed else 0


if __name__ == "__main__":
    os.environ.pop("CLAUDE_ENV_FILE", None)
    raise SystemExit(main(sys.argv[1:]))
