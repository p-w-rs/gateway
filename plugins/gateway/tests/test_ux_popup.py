"""popup.py: the broker (one dialog per (entry, what) across processes, the
90 s wait and exit 75, the detached helper, distinct outcomes, cancelled not
re-asked, unavailable asks nothing and says why), templates, default
buttons, verification re-asks in the same dialog, the remember choice, stale
handling. These run on the test fake (dialog.py's "fake" backend);
test_dialogs.py runs the same broker against a real gated and a fake mod."""
from __future__ import annotations

import io
import json
import os
import sys
import time
from pathlib import Path

import harness as H
import harness_ux as U
from gateway import hooks_post, hooks_prompt, hooks_session, paths, popup


def _capture_stderr():
    buf = io.StringIO()
    return buf


def _store_to(path: Path):
    def store(v: str) -> None:
        path.write_text(v)
    return store


def test_secret_ok_returns_value_and_stores_in_helper():
    with U.ux_env(U.answers(("ok", "s3cret-value-123"))) as env:
        out = env.root / "stored"
        saved, sys.stderr = sys.stderr, io.StringIO()
        try:
            oc, v = popup.secret("box", "sudo password", popup.secret_prompt("sudo password", "box"),
                                 store=_store_to(out))
            notice = sys.stderr.getvalue()
        finally:
            sys.stderr = saved
        assert (oc, v) == ("ok", "s3cret-value-123")
        assert out.read_text() == "s3cret-value-123", "the helper stored the answer"
        assert "gateway: waiting for the box sudo password in the gateway dialog in Claude Code" in notice
        calls = env.dialog.calls()
        assert len(calls) == 1 and calls[0]["kind"] == "secret"
        assert popup.NEVER_SEES in calls[0]["message"]
        assert not list(paths.pending_dir().glob("*.json")), "the request is gone once answered"
        res = json.loads((paths.pending_dir() / "box--sudo-password.result").read_text())
        assert res["outcome"] == "ok" and "s3cret" not in json.dumps(res)


def test_outcomes_are_distinct():
    with U.ux_env(U.answers(("cancelled",), ("unavailable",), ("timeout", None, 4)), lifetime=1) as env:
        quiet, sys.stderr = sys.stderr, io.StringIO()
        try:
            assert popup.secret("box", "sudo password", "p", lazy=False)[0] == popup.Outcome.CANCELLED
            assert popup.secret("box", "token", "p", lazy=False)[0] == popup.Outcome.UNAVAILABLE
            assert not (paths.pending_dir() / "box--token.json").exists(), "nothing stays pending"
            t0 = time.time()
            oc, _ = popup.secret("box", "api key", "p", lazy=False)
            assert oc == popup.Outcome.TIMEOUT and time.time() - t0 < 30, oc
        finally:
            sys.stderr = quiet
        assert [c["outcome"] for c in env.dialog.calls()] == ["cancelled", "unavailable", "timeout"]


def test_verification_reasks_up_to_three_times_and_never_stores_a_failing_value():
    good = "right-password-1"
    verify = lambda v: (v == good, "sudo said no")  # noqa: E731
    with U.ux_env(U.answers(("ok", "wrong-1"), ("ok", "wrong-2"), ("ok", good))) as env:
        out = env.root / "stored"
        oc, v = popup.secret("box", "sudo password", "Type it.", verify=verify, store=_store_to(out))
        assert (oc, v) == ("ok", good) and out.read_text() == good
        msgs = [c["message"] for c in env.dialog.calls()]
        assert "Try again (2 of 3)" in msgs[1] and "sudo said no" in msgs[1] and "(3 of 3)" in msgs[2]
    with U.ux_env(U.answers(("ok", "a"), ("ok", "b"), ("ok", "c"), ("ok", good))) as env:
        out = env.root / "stored"
        oc, v = popup.secret("box", "sudo password", "Type it.", verify=verify, store=_store_to(out))
        assert oc == popup.Outcome.FAILED and v is None
        assert not out.exists(), "a failing value is never stored"
        assert len(env.dialog.calls()) == 3, "at most 3 tries"


def test_default_buttons():
    from gateway import consent
    with U.ux_env(U.answers(("ok",), ("ok", "x"), ("cancelled",))) as env:
        ch = [consent.Change("box", "widen", "sudo on box: in every mode you are asked (was: "
                                                "refused in every mode)")]
        assert popup.consent("box", ch) == "ok"
        popup.secret("box", "token", "Type it.", lazy=False)
        assert popup.hostkey("box", ["ssh-ed25519 SHA256:" + "A" * 43], ["ssh-ed25519 SHA256:" + "B" * 43],
                             lazy=False) == "cancelled"
        c = env.dialog.calls()
        assert c[0]["kind"] == "confirm" and c[0]["default"] == "Decline", "consent defaults to Decline"
        assert "sudo on box: in every mode you are asked" in c[0]["message"] and \
            "Approve?" in c[0]["message"]
        assert c[1]["kind"] == "secret"
        assert c[2]["kind"] == "confirm" and c[2]["default"] == "Cancel", "hostkey defaults to Cancel"


def _rows(lines: list[str], width: int = 72) -> int:
    """The rows lines take in a pane `width` columns wide, wrapped at spaces
    (a longer word broken), counted in characters here on its own, not with
    popup's helper: never more rows than the pane's own wrap, which also
    keeps the spaces and counts a wide character as two columns."""
    import textwrap
    return sum(max(1, len(textwrap.wrap(ln, width, break_on_hyphens=False))) for ln in lines)


def _long_changes(n: int) -> list:
    """n change lines, some long enough to wrap (each ends with its number)."""
    from gateway import consent
    return [consent.Change("box", "widen", f"environment import VAR_{i:03d} (its value reaches "
                           "Claude's commands" + (" and a long tail" * 25 if i % 4 == 0 else "")
                           + f"; end {i:03d})") for i in range(n)]


def test_a_consent_dialog_longer_than_one_dialog_comes_in_parts_never_dropping_a_line():
    """PLAN-0.11 §19.11 (WS-8): gated and the pane show at most 40 lines of a
    dialog (a longer one lost its tail silently, the Approve question
    included). A longer consent dialog comes in parts, "part i of n", each
    within the limit and every change line whole; nothing is approved before
    the last part's Approve (on_ok), and a Decline on any part changes
    nothing; more than 10 parts is refused without a dialog."""
    from gateway.daemon import dialogs as dmod
    assert popup.DIALOG_LINES == dmod.MAX_LINES
    assert f".slice(0, {popup.DIALOG_LINES})" in (H.PLUGIN / "hooks" / "mod" / "dialog.ts").read_text()
    short = _long_changes(3)
    assert popup.consent_pages("box", short) == [popup.consent_text("box", short)], "one dialog as before"
    ch = _long_changes(70)
    pages = popup.consent_pages("box", ch, extra_lines=["Host key of box: SHA256:x"])
    n = len(pages)
    assert 2 < n <= popup.CONSENT_PARTS, n
    for i, page in enumerate(pages, 1):
        lines = page.split("\n")
        assert _rows(lines) <= popup.DIALOG_LINES and all(len(ln) <= dmod.MAX_LINE for ln in lines), i
        assert lines[0].endswith(f"(part {i} of {n}):"), lines[0]
        assert lines[-1].startswith(f"Part {i} of {n}. "), lines[-1]
        assert ("Approve all of this" in lines[-1]) is (i == n), lines[-1]
        assert ("Nothing is approved before the last part" in lines[-1]) is (i < n), lines[-1]
    shown = " ".join(" ".join(p.split()) for p in pages)
    for c in ch:
        assert " ".join(c.what.split()) in shown, c.what
    assert "Host key of box: SHA256:x" in pages[-1]
    for c in ch:            # a change line is never split across two parts
        assert sum(" ".join(c.what.split()) in " ".join(p.split()) for p in pages) == 1, c.what
    for answers, want, approved in (([("ok",)] * n, "ok", True),
                                    ([("cancelled",)], "cancelled", False),
                                    ([("ok",)] * (n - 1) + [("cancelled",)], "cancelled", False)):
        with U.ux_env(U.answers(*answers)) as env:
            mark = env.root / "approved"
            got = popup.consent("box", ch, extra_lines=["Host key of box: SHA256:x"],
                                on_ok=lambda: mark.write_text("approved"))
            calls = env.dialog.calls()
            assert got == want and mark.exists() is approved, (got, want, len(calls))
            assert len(calls) == len(answers), "a Decline ends it at once"
            assert [c["message"] for c in calls] == pages[:len(calls)]
            assert all(c["kind"] == "confirm" and c["default"] == "Decline" for c in calls)
            assert all(c["title"].endswith(f"(part {i} of {n})") for i, c in enumerate(calls, 1))
    many = _long_changes(500)
    assert popup.consent_pages("box", many) is None
    with U.ux_env(U.answers(("ok",))) as env:
        assert popup.consent("box", many, on_ok=lambda: (env.root / "approved").write_text("x")) == "failed"
        assert env.dialog.calls() == [] and not (env.root / "approved").exists()
        assert "more than 10 gateway dialogs, so none was opened" in popup._LAST_REASON, \
            popup._LAST_REASON


def test_a_dialog_part_is_sized_by_the_rows_the_pane_shows_and_its_question_names_the_part():
    """mac-tui D: a part was sized by its lines, so 36 change lines of ~100
    characters took ~78 rows of a docked pane (~75 columns) and the pane
    opened scrolled past "part 1 of 2". Now every dialog of a consent, one
    or a part, fits DIALOG_LINES rows at PANE_COLUMNS (72) columns wrapped
    as the pane wraps them, and the question beside the buttons repeats
    "Part i of n"."""
    from gateway import consent
    assert popup.PANE_COLUMNS == 72
    assert popup.pane_rows("") == 1 and popup.pane_rows("x" * 72) == 1
    assert popup.pane_rows("x" * 73) == 2, "a word longer than a row is broken"
    assert popup.pane_rows(("word " * 15).strip()) == 2, "74 characters wrap at a space"
    wide = [consent.Change("settings", "widen", f"environment import TOOL_HOME_{i:02d} (its value "
                           "reaches Claude's commands, and a little more text)") for i in range(30)]
    assert all(90 <= len(c.what) <= 110 for c in wide), [len(c.what) for c in wide]
    text = popup.consent_text("settings", wide)
    assert text.count("\n") + 1 <= popup.DIALOG_LINES < _rows(text.split("\n")), \
        "its lines fit one dialog, its rows don't"
    pages = popup.consent_pages("settings", wide)
    assert pages is not None and len(pages) >= 2, pages
    n = len(pages)
    for i, page in enumerate(pages, 1):
        lines = page.split("\n")
        assert _rows(lines) <= popup.DIALOG_LINES, (i, _rows(lines))
        assert lines[-1].startswith(f"Part {i} of {n}. "), lines[-1]
    shown = " ".join(" ".join(p.split()) for p in pages)
    assert all(" ".join(c.what.split()) in shown for c in wide)
    short = [consent.Change("box", "widen", f"ssh {i}") for i in range(10)]
    assert popup.consent_pages("box", short) == [popup.consent_text("box", short)]
    # the helper both dialogs use: a group stays together where it fits, a
    # part never starts with a blank line, and n is the real count
    parts = popup.dialog_parts([["a" * 100, "  b"], [""], ["c"] * 30], lambda i, n: [f"H {i}/{n}"],
                               lambda i, n: ["", f"Part {i} of {n}. q"], 10, rows=20)
    assert parts is not None and len(parts) == 3, parts
    assert parts[0][1:] == ["a" * 100, "  b", "", "Part 1 of 3. q"] and parts[1][1] == "c", parts
    assert [p[0] for p in parts] == ["H 1/3", "H 2/3", "H 3/3"]
    assert all(_rows(p) <= 20 for p in parts)
    assert popup.dialog_parts([["c"]] * 100, lambda i, n: [], lambda i, n: [], 3, rows=10) is None


def _wide_rows(lines: list[str], width: int = 72) -> int:
    """The rows lines take in a pane `width` columns wide, a character of
    East Asian width W or F two columns: words kept whole where they fit, a
    wider one broken where the row ends (counted here on its own, not with
    popup's helper; it never counts more rows than the pane's wrap)."""
    import unicodedata
    total = 0
    for ln in lines:
        rows, col = 1, 0
        for k, word in enumerate(ln.split(" ")):
            widths = [2 if unicodedata.east_asian_width(c) in "WF" else 1 for c in word]
            gap = 1 if k else 0
            if col + gap + sum(widths) <= width:
                col += gap + sum(widths)
                continue
            if sum(widths) <= width:
                rows, col = rows + 1, sum(widths)
                continue
            col += gap
            for c in widths:
                if col + c > width:
                    rows, col = rows + 1, 0
                col += c
        total += rows
    return total


def _ssh_changes(k: int) -> list:
    """k one-row change lines."""
    from gateway import consent
    return [consent.Change("box", "widen", f"ssh {i}") for i in range(k)]


def test_a_dialog_in_parts_sits_exactly_on_its_limits():
    """WS-11b review: the limits were tested only from afar, so an
    off-by-one in each survived. Exactly DIALOG_LINES rows are one dialog
    and one row more comes in parts (gated keeps 40 lines: a 41st, the
    question, was dropped); exactly CONSENT_PARTS parts are shown and one
    more is refused; a part never starts with a blank line."""
    for k, n in ((36, 1), (37, 2)):         # heading, blank, k changes, blank, question
        lines = popup.consent_text("box", _ssh_changes(k)).split("\n")
        assert len(lines) == _rows(lines) == k + 4, (k, len(lines))
        pages = popup.consent_pages("box", _ssh_changes(k))
        assert pages is not None and len(pages) == n, (k, pages and len(pages))
        assert all(len(p.split("\n")) <= popup.DIALOG_LINES for p in pages), k
    # dialog_parts: max_parts parts are returned, one more is None
    none: list = []
    assert len(popup.dialog_parts([["c"]] * 30, lambda i, n: none, lambda i, n: none, 3, rows=10)) == 3
    assert popup.dialog_parts([["c"]] * 31, lambda i, n: none, lambda i, n: none, 3, rows=10) is None
    # the longest consent shown takes exactly CONSENT_PARTS parts
    lo, hi = 1, 2000                         # lo is shown, hi is refused
    assert popup.consent_pages("box", _ssh_changes(lo)) is not None
    assert popup.consent_pages("box", _ssh_changes(hi)) is None
    while hi - lo > 1:
        mid = (lo + hi) // 2
        if popup.consent_pages("box", _ssh_changes(mid)) is None:
            hi = mid
        else:
            lo = mid
    assert len(popup.consent_pages("box", _ssh_changes(lo))) == popup.CONSENT_PARTS, lo
    # a blank line that would open a part is left out (and one closing it)
    parts = popup.dialog_parts([["a"] * 10, ["", "b", ""]], lambda i, n: none, lambda i, n: none, 10,
                               rows=10)
    assert parts == [["a"] * 10, ["b"]], parts


def test_a_dialog_part_counts_wide_characters_as_two_columns():
    """WS-11b review: pane_rows counted characters, but the pane counts
    columns, and a Chinese, Japanese or Korean character (East Asian width
    W or F) takes two: 12 PATH imports of folders named with 70 of them came
    out as one dialog that took ~52 rows of the pane. Now such a character
    takes two columns, as the pane's own wrap counts it (wrap-ansi's hard
    wrap without trimming: a space after a row a word filled exactly starts
    the next row)."""
    from gateway import consent
    assert popup.cells("ab") == 2 and popup.cells("文字") == 4 and popup.cells("é") == 1
    assert popup.pane_rows("文" * 36) == 1 and popup.pane_rows("文" * 37) == 2
    assert popup.pane_rows("x" + "文" * 36) == 2 and popup.pane_rows("文" * 70) == 2
    assert popup.pane_rows("a" * 72 + " " + "b" * 10) == 2, "the space starts the next row"
    assert popup.pane_rows("a" * 72 + " " + "b" * 72) == 3, "...where a row-wide word doesn't fit"
    ch = [consent.Change("settings", "widen", f"PATH import /data/{i:02d}/" + "文" * 70
                         + " (Claude's commands find the programs in that folder)") for i in range(12)]
    text = popup.consent_text("settings", ch).split("\n")
    assert _rows(text) <= popup.DIALOG_LINES < _wide_rows(text), \
        "counted in characters it fits one dialog, in columns it doesn't"
    pages = popup.consent_pages("settings", ch)
    assert pages is not None and len(pages) >= 2, pages
    for page in pages:
        assert _wide_rows(page.split("\n")) <= popup.DIALOG_LINES, _wide_rows(page.split("\n"))
    shown = " ".join(" ".join(p.split()) for p in pages)
    assert all(" ".join(c.what.split()) in shown for c in ch)


def test_the_remember_choice_decides_what_is_stored():
    with U.ux_env(U.answers(("ok", "kept-1"), ("ok", "\x00forget\x00once-2"))) as env:
        out = env.root / "stored"
        assert popup.secret("box", "sudo password", "p", store=_store_to(out), remember=True,
                            lazy=False) == ("ok", "kept-1")
        assert out.read_text() == "kept-1"
        out.unlink()
        assert popup.secret("box", "sudo password", "p", store=_store_to(out), remember=True,
                            lazy=False) == ("ok", "once-2"), "used for this exchange"
        assert not out.exists(), "not remembered: nothing stored"


def test_one_popup_per_entry_and_what_across_processes():
    with U.ux_env(U.answers(("ok", "joint-secret-99", 1.5))) as env:
        stored = env.root / "stored"
        child_out = env.root / "child.json"
        quiet, sys.stderr = sys.stderr, io.StringIO()
        pid = os.fork()
        if pid == 0:
            try:
                time.sleep(0.4)        # the parent's helper is up by now
                oc, v = popup.secret("box", "sudo password", "p", store=_store_to(stored),
                                     load=lambda: stored.read_text())
                child_out.write_text(json.dumps([oc, v]))
            finally:
                U.wait_helpers()       # a helper this child started (none when it joined)
                os._exit(0)
        try:
            oc, v = popup.secret("box", "sudo password", "p", store=_store_to(stored),
                                 load=lambda: stored.read_text())
            os.waitpid(pid, 0)
        finally:
            sys.stderr = quiet
        assert (oc, v) == ("ok", "joint-secret-99")
        assert json.loads(child_out.read_text()) == ["ok", "joint-secret-99"], "the second requester joined"
        assert len(env.dialog.calls()) == 1, "one pop-up, not two"


def test_a_different_request_waits_for_the_open_one_and_then_opens_its_own():
    """Same (entry, what) but other content (another user): the second
    requester doesn't take the first one's answer; it waits for that pop-up
    to close and then shows its own."""
    ans = U.answers(("ok", "pw-for-alice-1", 1.2), ("ok", "pw-for-bob-22"))
    with U.ux_env(ans) as env:
        child_out = env.root / "child.json"
        quiet, sys.stderr = sys.stderr, io.StringIO()
        pid = os.fork()
        if pid == 0:
            try:
                time.sleep(0.4)
                oc, v = popup.secret("box", "sudo password", "p", detail={"user": "bob"}, lazy=False)
                child_out.write_text(json.dumps([oc, v]))
            finally:
                U.wait_helpers()       # bob's helper is this child's: it ends before the env goes
                os._exit(0)
        try:
            oc, v = popup.secret("box", "sudo password", "p", detail={"user": "alice"}, lazy=False)
            os.waitpid(pid, 0)
        finally:
            sys.stderr = quiet
        assert (oc, v) == ("ok", "pw-for-alice-1")
        assert json.loads(child_out.read_text()) == ["ok", "pw-for-bob-22"], "bob's request got its own pop-up"
        assert len(env.dialog.calls()) == 2


def test_wait_runs_out_exit_75_then_the_helper_stores_the_late_answer():
    with U.ux_env(U.answers(("ok", "late-answer-777", 2.5)), wait=0.6) as env:
        stored = env.root / "stored"
        err = io.StringIO()
        saved, sys.stderr = sys.stderr, err
        try:
            try:
                popup.secret("example", "sudo password", "p", store=_store_to(stored))
                raise AssertionError("expected StillOpen")
            except popup.StillOpen as e:
                assert e.code == 75 and isinstance(e, SystemExit)
                assert e.message == ("gateway: the gateway dialog for example is still open in "
                                     "Claude Code; tell the user once and carry on with other work. "
                                     "Retry after they answer.")
        finally:
            sys.stderr = saved
        assert "still open" in err.getvalue()
        st = json.loads((paths.pending_dir() / "example--sudo-password.json").read_text())
        assert st["state"] == "open" and popup._pid_alive(st["pid"])
        msgs = hooks_post.pending_notice("sess-start", include_open=True)
        assert any("the gateway dialog for example (sudo password) is waiting in Claude Code"
                   in m for m in msgs), msgs
        assert [d["entry"] for d in hooks_session.pending_requests()] == ["example"]
        U.wait_helpers()
        assert stored.read_text() == "late-answer-777", "the detached helper stored the late answer"
        assert not (paths.pending_dir() / "example--sudo-password.json").exists()


def _public_job(line: str, outcome: str = "failed"):
    """A dialog job like import's: one confirm in the dialog, then its line."""
    def job():
        oc = popup._confirm("Gateway: import", "Import this?", "Import", entry="gateway",
                            what="import confirmation")
        return (outcome if oc == "ok" else oc), line
    return job


def _quiet_run(*a, **kw):
    err = io.StringIO()
    saved, sys.stderr = sys.stderr, err
    try:
        return popup.run(*a, **kw), err.getvalue()
    except popup.StillOpen:
        return "still open", err.getvalue()
    finally:
        sys.stderr = saved


def test_a_finished_jobs_line_reaches_the_retry_after_the_wait_ran_out():
    """gate import's wait ran out before the person answered; the job then
    failed (a damaged file). The retry Claude is told to make gets that
    outcome and line, once, instead of a new dialog; a third try asks anew."""
    line = "gateway: the file was changed or damaged after it was written; nothing was imported"
    ans = U.answers(("ok", "", 1.5), ("cancelled",))
    with U.ux_env(ans, wait=0.5) as env:
        d1 = popup._digest(["import", "/x/tampered.age", "abc"])
        got, err = _quiet_run("gateway", "import", _public_job(line), kind="import", digest=d1, public=True)
        assert got == "still open" and "still open" in err, (got, err)
        U.wait_helpers()
        rec = json.loads((paths.pending_dir() / f"gateway--import.{d1}.line").read_text())
        assert rec["outcome"] == "failed" and rec["line"] == line, rec
        # another request (another file) has no line of its own: it is asked
        other = popup._digest(["import", "/x/other.age", "def"])
        assert popup._take("gateway--import", other) is None
        got, err = _quiet_run("gateway", "import", _public_job(line), kind="import", digest=d1, public=True)
        assert got == ("failed", line), got
        assert "finished after the last try stopped waiting" in err, err
        assert len(env.dialog.calls()) == 1, "the retry opened no dialog"
        # taken: the next try is a new request with its own dialog
        got, _err = _quiet_run("gateway", "import", _public_job(line), kind="import", digest=d1, public=True)
        assert got == ("cancelled", line) and len(env.dialog.calls()) == 2, got


def test_another_request_waiting_for_the_dialog_leaves_its_line_to_its_own_retry():
    """An import of file A ran out of time; an import of file B waits for A's
    dialog to end before it opens its own: B must not take A's line, which
    belongs to A's retry."""
    line_a, line_b = "gateway: imported A", "gateway: imported B"
    with U.ux_env(U.answers(("ok", "", 1.5), ("ok", ""), ("ok", "")), wait=0.5) as env:
        da = popup._digest(["import", "/x/a.age", "aaa"])
        db = popup._digest(["import", "/x/b.age", "bbb"])
        got, _err = _quiet_run("gateway", "import", _public_job(line_a, "ok"), kind="import", digest=da,
                               public=True)
        assert got == "still open", got
        env.o.extra["popup_wait"] = 10
        got, _err = _quiet_run("gateway", "import", _public_job(line_b, "ok"), kind="import", digest=db,
                               public=True)
        assert got == ("ok", line_b), got
        U.wait_helpers()
        got, err = _quiet_run("gateway", "import", _public_job(line_a, "ok"), kind="import", digest=da,
                              public=True)
        assert got == ("ok", line_a) and "finished after the last try" in err, (got, err)
        assert len(env.dialog.calls()) == 2, env.dialog.calls()


def test_a_requester_that_got_its_line_leaves_nothing_for_a_retry():
    line = "gateway: imported 1 host"
    with U.ux_env(U.answers(("ok", ""), ("ok", ""))) as env:
        d1 = popup._digest(["import", "/x/good.age", "abc"])
        got, _err = _quiet_run("gateway", "import", _public_job(line, "ok"), kind="import", digest=d1, public=True)
        assert got == ("ok", line), got
        assert not list(paths.pending_dir().glob("gateway--import.*.line")), "the requester took its line"
        got, _err = _quiet_run("gateway", "import", _public_job(line, "ok"), kind="import", digest=d1, public=True)
        assert got == ("ok", line) and len(env.dialog.calls()) == 2, "a new request, a new dialog"


def test_only_public_jobs_keep_a_line_and_a_secret_never_reaches_the_result_file():
    with U.ux_env(U.answers(("ok", "late-secret-4242", 1.2)), wait=0.4) as env:
        try:
            popup.secret("box", "sudo password", "p", store=_store_to(env.root / "stored"))
        except popup.StillOpen:
            pass
        U.wait_helpers()
        text = (paths.pending_dir() / "box--sudo-password.result").read_text()
        res = json.loads(text)
        assert res["outcome"] == "ok" and "line" not in res, res
        assert not list(paths.pending_dir().glob("*.line")), "a secret job keeps no line"
        for f in paths.pending_dir().iterdir():
            if f.is_file():
                assert b"late-secret-4242" not in f.read_bytes(), f.name


def test_a_verify_that_stops_closes_the_dialog_at_once_with_its_reason():
    """A damaged import file: asking for the passphrase again can't help, so
    the dialog closes as failed (its toast says why), no second try."""
    with U.ux_env(U.answers(("ok", "any-passphrase-123"), ("ok", "x"))) as env:
        def verify(v: str):
            raise popup.StopDialog("gateway: the file was changed or damaged after it was written")
        err = io.StringIO()
        saved, sys.stderr = sys.stderr, err
        try:
            oc, v = popup.secret("gateway", "import passphrase", "p", verify=verify, lazy=False)
        finally:
            sys.stderr = saved
        assert (oc, v) == ("failed", None)
        assert len(env.dialog.calls()) == 1, "no second try"


def test_unavailable_asks_nothing_and_says_why():
    """No native dialog here (the "none" fake stands in for claude -p, mods off,
    mobile...): nothing is asked any other way, nothing stays pending, no
    terminal command and no one-time code; the message names what works."""
    with U.ux_env(dialog="none") as env:
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\n')
        err = io.StringIO()
        saved, sys.stderr = sys.stderr, err
        try:
            oc, v = popup.secret("box", "sudo password", "p", detail={"user": "u"})
        finally:
            sys.stderr = saved
        assert (oc, v) == ("unavailable", None)
        text = err.getvalue()
        assert "nothing was asked" in text and "terminal or the desktop app" in text, text
        assert "gate secret" not in text and "code" not in text
        assert env.dialog.calls() == [], "no dialog was attempted"
        assert popup.pending("box") == [] and not list(paths.pending_dir().glob("*.code"))
        assert hooks_post.pending_notice("sess-ux", include_open=True) == []
        out = hooks_post.main({"tool_name": "Bash", "session_id": "third", "tool_response": {"stdout": "x"}})
        assert out is None or "systemMessage" not in out


def test_cancelled_is_not_reasked_until_the_user_writes_again():
    with U.ux_env(U.answers(("cancelled",), ("ok", "now-ok-123"))) as env:
        quiet, sys.stderr = sys.stderr, io.StringIO()
        try:
            assert popup.secret("box", "sudo password", "p")[0] == "cancelled"
            assert popup.secret("box", "sudo password", "p")[0] == "cancelled"
            assert len(env.dialog.calls()) == 1, "a lazy request after Cancel opens no pop-up"
            assert popup.secret("box", "sudo password", "p", lazy=False)[0] == "ok", \
                "an explicit request (the user asked) may ask again"
        finally:
            sys.stderr = quiet
    with U.ux_env(U.answers(("cancelled",), ("ok", "now-ok-456"))) as env:
        quiet, sys.stderr = sys.stderr, io.StringIO()
        try:
            assert popup.secret("box", "sudo password", "p")[0] == "cancelled"
            hooks_prompt.main({"prompt": "ok, try again", "session_id": "sess-ux"})
            assert popup.secret("box", "sudo password", "p")[0] == "ok", "a new prompt clears it"
        finally:
            sys.stderr = quiet
        assert len(env.dialog.calls()) == 2


def test_templates_validate_names_and_strip_unsafe_text():
    for bad in ("Bad Name", "box\nAllow", "", "a" * 40):
        try:
            popup.secret_prompt("sudo password", bad)
            raise AssertionError(f"{bad!r} accepted")
        except ValueError:
            pass
    t = popup.secret_prompt("sudo password", "box", target="octo@10.0.0.5:2222",
                            fingerprint="ssh-ed25519 SHA256:" + "x" * 43)
    assert "octo@10.0.0.5:2222" in t and "SHA256:" in t and popup.NEVER_SEES in t
    t2 = popup.secret_prompt("sudo password", "box", target="evil‮@host", fingerprint="nope")
    assert "evil" not in t2 and "nope" not in t2, "unsafe targets and fingerprints aren't shown"
    txt = popup.consent_text("box", ["sudo ‮false -> true\nAllow everything"])
    assert "‮" not in txt and "\nAllow everything" not in txt.split("Claude asks")[1].split("\n\n")[0] + "x"
    try:
        popup.secret("box", "Type your PASSWORD", "p")
        raise AssertionError("free-form subjects refused")
    except ValueError:
        pass


def test_stale_open_request_is_replaced_and_old_results_cleaned():
    with U.ux_env(U.answers(("ok", "fresh-value-1"))) as env:
        d = paths.ensure_private() / "pending"
        d.mkdir(mode=0o700, exist_ok=True)
        (d / "box--sudo-password.json").write_text(json.dumps(
            {"entry": "box", "what": "sudo password", "state": "open", "since": "x", "t": time.time() - 10,
             "id": "dead", "pid": 999999}))
        old = d / "box--old.result"
        old.write_text("{}")
        os.utime(old, (time.time() - 4000, time.time() - 4000))
        os.utime(d / "box--sudo-password.json", (time.time() - 30, time.time() - 30))
        oc, v = popup.secret("box", "sudo password", "p", lazy=False)
        assert (oc, v) == ("ok", "fresh-value-1"), "a dead helper's request doesn't block a new one"
        assert not old.exists()


def test_reenter_opens_the_popup_without_waiting():
    with U.ux_env(U.answers(("ok", "re-entered-pw-1", 1.0))) as env:
        stored = env.root / "stored"
        t0 = time.time()
        msg = popup.reenter("example", "sudo password", "p", store=_store_to(stored))
        assert time.time() - t0 < 5
        assert msg == ("gateway: the saved sudo password for example was rejected; a gateway "
                       "dialog to enter it again is open in Claude Code; don't retry")
        U.wait_helpers()
        assert stored.read_text() == "re-entered-pw-1"


def test_the_helper_uses_no_proxies():
    """The pop-up job runs in the helper with Claude's environment: HTTPS_PROXY
    and friends must not route a token being verified there."""
    import urllib.request
    with U.ux_env() as env, U.env_vars(HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9",
                                       ALL_PROXY="http://127.0.0.1:9", https_proxy="http://127.0.0.1:9"):
        assert urllib.request.getproxies(), "the test environment names proxies"
        oc, v = popup.run("box", "proxy probe", lambda: ("ok", json.dumps(urllib.request.getproxies())),
                          kind="setup")
        assert oc == "ok" and json.loads(v) == {}, v
        h = urllib.request.ProxyHandler()
        assert getattr(h, "proxies", None), "only the helper drops them (this process is unchanged)"


def test_session_start_names_a_waiting_dialog_and_writes_the_session_record():
    """SessionStart shows open dialogs through hooks_post.pending_notice (shown
    markers shared with the prompt hook) and writes private/sessions/<sid>.env;
    an old .code file of the removed terminal path is cleaned up."""
    with U.ux_env(U.answers(("ok", "late-1", 3.0)), wait=0.3) as env:
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\n')
        d = paths.ensure_private() / "pending"
        d.mkdir(mode=0o700, exist_ok=True)
        (d / "box--secret.code").write_text('{"code": "1234-5678"}')
        quiet, sys.stderr = sys.stderr, io.StringIO()
        try:
            try:
                popup.secret("box", "sudo password", "p", detail={"user": "u"})
            except popup.StillOpen:
                pass
        finally:
            sys.stderr = quiet
        assert not (d / "box--secret.code").exists()
        with U.env_vars(DISPLAY=":7", SSH_TTY="bad\nvalue"):
            out = hooks_session.session_main({"session_id": "sess-start-1"})
        assert "the gateway dialog for box (sudo password) is waiting in Claude Code" in \
            out["systemMessage"], out["systemMessage"]
        assert hooks_post.pending_notice("sess-start-1", include_open=True) == [], "shown once"
        shown = hooks_post.shown_path("sess-start-1")
        assert paths.private_dir() in shown.parents, "the shown marker lives in private/"
        assert not list(paths.session_dir().glob("*shown*")), "nothing in the run dir"
        rec = paths.private_dir() / "sessions" / "sess-start-1.env"
        text = rec.read_text()
        assert text.startswith("started=") and "DISPLAY=:7\n" in text and "SSH_TTY=\n" in text
        assert (rec.stat().st_mode & 0o777) == 0o600
        before = rec.stat().st_mtime_ns
        time.sleep(0.01)
        hooks_session.session_main({"session_id": "sess-start-1"})   # resume
        assert rec.stat().st_mtime_ns == before, "the record is written once"
        U.wait_helpers()


def test_the_waiting_notice_prints_only_when_a_dialog_opens():
    """Round 3: `gate check inner` printed "waiting for the user in a pop-up for
    inner on your screen" for a job that opened no dialog."""
    with U.ux_env(U.answers(("ok",))) as env:
        saved, sys.stderr = sys.stderr, io.StringIO()
        try:
            oc, _v = popup.run("box", "setup", lambda: (popup.Outcome.OK, None),
                               notice="gateway: waiting for the user in the gateway dialog for box")
            quiet = sys.stderr.getvalue()
            sys.stderr = io.StringIO()
            oc2 = popup.run("box", "notice", lambda: (popup._confirm("t", "x", "OK"), None),
                            notice="gateway: waiting for the user in the gateway dialog for box")[0]
            loud = sys.stderr.getvalue()
        finally:
            sys.stderr = saved
        assert oc == popup.Outcome.OK and "waiting for" not in quiet, quiet
        assert oc2 == popup.Outcome.OK and "waiting for the user in the gateway dialog for box" in loud, loud
        assert len(env.dialog.calls()) == 1
