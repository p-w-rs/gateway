"""The mutation harness (tests/mutation_check.py, which every mutations_*.py
runs): each named test runs once unmutated before any mutation, and a
mutation whose test fails then (or names no test) is an ERROR, never a kill
(release verification of 0.11, mutations.md finding 2: a test that failed on
every scratch copy counted as a kill). Driven against a scratch "plugin"
whose tests/run_tests.py is a stub that judges one source file."""
from __future__ import annotations

import contextlib
import io
import json
import tempfile
from pathlib import Path

import harness as H

STUB = '''import json, sys
from pathlib import Path
here = Path(__file__).resolve().parents[1]
sub = sys.argv[sys.argv.index("-k") + 1]
src = (here / "src" / "thing.txt").read_text()
with open(here / "calls.jsonl", "a") as f:
    f.write(json.dumps({"sub": sub, "src": src}) + "\\n")
passed, failed = {"good": (1, 0) if "guard on" in src else (0, 1), "broken": (0, 1),
                  "none": (0, 0)}[sub]
print(f"{passed} passed, {failed} failed (0.0s)")
sys.exit(1 if failed else 0)
'''

MUTATIONS = [
    ("kills", "src/thing.txt", "guard on", "guard off", "test_x::good"),
    ("vacuous", "src/thing.txt", "guard on", "guard off", "test_x::broken"),
    ("names nothing", "src/thing.txt", "guard on", "guard off", "test_x::none"),
    ("lost snippet", "src/thing.txt", "absent words", "x", "test_x::good"),
    ("survives", "src/thing.txt", "guard on", "guard on, really", "test_x::good"),
    ("kills too", "src/thing.txt", "guard on", "guard gone", "test_x::good"),
]


def _run(argv: list[str]) -> tuple[int, str, list[dict], str]:
    import mutation_check as M
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as td:
        p = Path(td)
        (p / "src").mkdir()
        (p / "tests").mkdir()
        (p / "src" / "thing.txt").write_text("guard on\n")
        (p / "tests" / "run_tests.py").write_text(STUB)
        keep = (M.PLUGIN, M.MUTATIONS)
        M.MUTATIONS = MUTATIONS
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = M.main([*argv, "--copy", str(p)])
        finally:
            M.PLUGIN, M.MUTATIONS = keep
        calls = [json.loads(ln) for ln in (p / "calls.jsonl").read_text().splitlines()]
        return rc, out.getvalue(), calls, (p / "src" / "thing.txt").read_text()


def test_a_test_that_fails_without_its_mutation_is_an_error_never_a_kill():
    rc, out, calls, src = _run([])
    assert rc == 1 and src == "guard on\n", (rc, src)
    assert "  killed   kills  (test_x::good" in out and "  killed   kills too  (test_x::good" in out, out
    assert "  ERROR vacuous: its test test_x::broken fails without the mutation (0 passed, 1 failed" in out, out
    assert "  ERROR names nothing: its test test_x::none names no test (0 passed, 0 failed" in out, out
    assert "  ERROR lost snippet: the snippet isn't found exactly once in src/thing.txt" in out, out
    assert "  SURVIVED survives  (test_x::good" in out, out
    assert "killed   vacuous" not in out and "killed   names nothing" not in out, out
    assert out.rstrip().endswith("2 mutations killed, 1 survived, 3 errors"), out
    assert "baseline: 3 named tests run unmutated in " in out and ", 2 can't judge a mutation" in out, out
    # each named test once, unmutated, before any mutation; the broken ones never mutated
    base = [c for c in calls if c["src"] == "guard on\n"]
    assert sorted(c["sub"] for c in base) == ["broken", "good", "none"], calls
    assert calls[:3] == base, "the baseline runs before the first mutation"
    assert [c["sub"] for c in calls[3:]] == ["good"] * 3 and all(c["src"] != "guard on\n" for c in calls[3:]), calls


def test_k_picks_the_mutations_and_only_their_tests_run_unmutated():
    rc, out, calls, _src = _run(["-k", "kills"])
    assert rc == 0 and out.rstrip().endswith("2 mutations killed, 0 survived, 0 errors"), out
    assert [(c["sub"], c["src"]) for c in calls] == [("good", "guard on\n"), ("good", "guard off\n"),
                                                     ("good", "guard gone\n")], calls
    rc, out, calls, _src = _run(["-k", "vacuous"])
    assert rc == 1 and out.rstrip().endswith("0 mutations killed, 0 survived, 1 errors"), out
    assert [c["sub"] for c in calls] == ["broken"], calls


def test_every_mutation_file_goes_through_the_harness_main():
    """Each mutations_*.py runs mutation_check.main (so each gets the baseline)."""
    for f in sorted(H.TESTS.glob("mutations_*.py")):
        text = f.read_text()
        assert "mutation_check.MUTATIONS = MUTATIONS" in text and "mutation_check.main(" in text, f.name
