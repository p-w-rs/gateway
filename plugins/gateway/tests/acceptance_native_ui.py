#!/usr/bin/env python3
"""Brief 12, 13 and 14.12 (and the live half of 14.10) in the real TUI: the
gateway's native management flows on an installed copy, and proof that
nothing opens outside Claude Code.

    pixi exec --spec python --spec pyte python tests/acceptance_native_ui.py \\
        --tmp DIR [--keep] [--pixi-cache DIR] \\
        [--only scan,hosts,accounts,settings,export,import,tamper,signin,passphrase] \\
        [--export-to FILE --pass-file FILE] [--import-from FILE --pass-file FILE]

The gateway is installed through the TUI harness's e2e route (a git-source
marketplace, the marker keeping every gateway location in a scratch root),
its env built before the session; the session runs fullscreen
(CLAUDE_CODE_NO_FLICKER=1) against the fake Messages API with the observer
plugin and --debug-file; recording shims named open, osascript, xdg-open,
zenity, kdialog, notify-send and the terminal programs come first on PATH
(each logs its name and exits 1), a process-table sampler runs beside it, and
on Linux the whole run can be wrapped in `strace -f -e trace=execve` (see
--strace-log): an exec tracer that misses no process, however short-lived.

  scan      a static scan of both plugins' shipped files for programs and APIs
            that open windows or browsers (osascript, zenity, kdialog,
            xdg-open, open -a/URL, webbrowser, NSWorkspace, notify-send,
            terminal programs, $BROWSER): every hit outside docs and tests is
            listed and must be a refusal, a comment or a test fake, but for
            the one expected opener, which the scan must find as a call:
            gated's browser sign-in (daemon/oauth.py open_browser,
            acceptance_lib.EXPECTED_OPENER)
  hosts     /gate-hosts: the pane lists this machine with its runtime state;
            an edit typed into its field (workspace add) is written through
            the form writer, waits for the OK (Review localhost...), the
            consent dialog approves it (with the form's sudo = true, which
            waits for the OK too: configuring this computer's sudo applies
            only up to "ask" at once; its line says what each mode now does),
            the pane lists the workspace
  accounts  /gate-accounts: the accounts with their states; "Enter a
            credential for ..." opens the private dialog (a canary typed), the
            state turns to "stored, not checked yet"; "Check ..." runs; the
            vault passphrase offer that follows the first stored secret is
            cancelled (it stays pending: offered again in a later session)
  settings  `gate check settings` for a [shell] change longer than one dialog
            (42 lines): the consent dialog comes in parts ("part 1 of n",
            each part's question beside its buttons saying which it is,
            Next, then Approve on the last part), and only then is it
            approved (PLAN-0.11 §19.11)
  export    `gate export FILE`: the selection checklist (OK), the passphrase
            typed twice in the private field (a canary), the file written 0600,
            age-encrypted: no stored value in it in any encoding
  import    `gate import FILE` after an account changed here and the [shell]
            table was taken out: a wrong passphrase asks again, the right one
            opens it, the conflict dialog (Use the file's), the summary in
            parts (Part 1 of n, Next, then Import): the account is the
            file's again and the settings are back
  tamper    a byte of the file changed: the import stops ("damaged or
            changed"), nothing changes; a file that isn't an export is refused
  signin    an azure account with sign_in = "browser" (PLAN-0.11 §7): its
            consent, then gated's confirm (account, Open/Cancel: nothing
            before Open); Open runs the `browser` knob's program (gated-test
            .json: a recording program, never a real browser; a local fake
            OAuth server as the authority), which waits while the browser
            tools are refused (the installed copy's tool_guard.sh), then
            follows the authorize URL: the tokens land in the vault, the
            program got one URL (S256, a 127.0.0.1 redirect), and nothing
            else opened
  passphrase a new session: another account's credential stored brings the
            offer again (the cancel kept it pending); Set passphrase opens
            the set-a-passphrase dialog (two private fields): the vault key
            is wrapped (key.wrapped, no key.txt)

--export-to/--import-from with --pass-file carry the export file and its
passphrase (a 0600 file, never printed) between two machines for 14.10: the
export on one, the import on another machine (different host keys and
machine id): local/remote classification checked there.

Prints one line per check and a JSON summary to --tmp/acceptance-native-ui.json;
exits non-zero on any failure.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN = HERE.parent
REPO = PLUGIN.parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
import acceptance_dialogs as AD  # noqa: E402
import acceptance_lib as L  # noqa: E402
import harness_oauth as HO  # noqa: E402  (its server and browser program only: no test harness)
from tui import driver, install, safety, scan  # noqa: E402
from tui.fakeapi import result_text, tool_results  # noqa: E402

note = AD.note
SUMMARY: dict = {}
LIVE: dict = {}          # the running session and a folder for screen dumps of failed checks


def check(name: str, ok, detail: str = "") -> bool:
    if not ok and LIVE.get("s") is not None and LIVE.get("dir") is not None:
        n = len(list(LIVE["dir"].glob("*.txt"))) + 1
        with contextlib.suppress(Exception):
            (LIVE["dir"] / f"{n:02d}.txt").write_text(name + "\n\n" + LIVE["s"].dump())
            detail = (detail[:300] + f" [screen: {LIVE['dir'].name}/{n:02d}.txt]") if detail else f"[screen: {LIVE['dir'].name}/{n:02d}.txt]"
    return AD.check(name, ok, detail)
AD.BANNED |= {"notify-send", "wslview", "gio", "sensible-browser", "x-www-browser", "firefox", "chromium",
              "google-chrome", "safari"}


def sha(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


def wait(s, cond, timeout, step=0.3):
    return AD.wait(s, cond, timeout, step)


def scr(s) -> str:
    return AD.screen(s)


# ---------------------------------------------------------------------------
# The static scan
# ---------------------------------------------------------------------------


def static_scan() -> None:
    print("scan: both plugins' shipped files for window, browser and terminal openers", flush=True)
    roots = {"gate": (REPO, "plugins/gateway/"), "check": (REPO.parent / "checkpoint", "plugins/checkpoint/")}
    hits: list[dict] = []
    for plug, (repo, prefix) in roots.items():
        if not repo.exists():
            check(f"scan: the {plug} checkout is found", False)
            continue
        for rel in install.source_files(repo):
            if not rel.startswith(prefix):
                continue
            p = repo / rel
            if p.is_symlink() or not p.is_file() or p.stat().st_size > 2_000_000:
                continue
            try:
                text = p.read_text(errors="replace")
            except OSError:
                continue
            hits += L.opener_hits(plug, rel[len(prefix):], text)
    code = [h for h in hits if h["kind"] == "code"]
    SUMMARY["static_scan"] = {"hits": len(hits), "in_code": code[:80]}
    note(f"static scan: {len(hits)} mentions, {len(code)} outside docs and tests (listed in the JSON)")
    # A code mention is fine only as a refusal, a guard word list, a comment or a test fake: never a
    # call, but for the one expected opener (gated's browser sign-in, after the person pressed Open)
    expected, calls = L.opener_calls(hits)
    plug, rel, _call = L.EXPECTED_OPENER
    check(f"scan: the one expected opener is found as a call ({plug}'s {rel}: open_browser, the browser "
          "sign-in of PLAN-0.11 §7.2, run only after the person pressed Open)", bool(expected),
          json.dumps([h for h in code if h["file"] == rel][:10]))
    check("scan: no other plugin code calls a window, browser or terminal opener (every other code mention is "
          "a refusal, a word list or a comment)", not calls, json.dumps(calls[:10]))


# ---------------------------------------------------------------------------
# The live flows
# ---------------------------------------------------------------------------


def press_text(s, label: str, done, tries: int = 5, settle: float = 2.5) -> bool:
    return AD.press(s, label, done, tries=tries, settle=settle)


def press_button(s, label: str, done, settle: float = 3.0) -> bool:
    return AD.press_button(s, label, done, settle=settle)


def vault_data(gi) -> dict:
    """The scratch vault, decrypted here (its key unwrapped), or {}."""
    age = AD.age_binary(gi.root)
    if not age or not (gi.gateway_home / "private" / "key.txt").exists():
        return {}
    try:
        return AD.read_vault(gi, age)
    except RuntimeError:
        return {}


def type_secret(s, value: str) -> bool:
    """`value` into the private field and Enter, only once the field took
    the keys and shows one bullet per character (acceptance_lib's
    focus_private_field and type_private); else nothing is submitted."""
    empty = AD.focus_field(s)
    if empty is None or not L.type_private(s, value, lambda: AD.bullets(s), empty):
        return False
    s.key("enter")
    return True


def form_text(gi) -> str:
    f = gi.gateway_home / "gateway.toml"
    return f.read_text() if f.exists() else ""


def to_prompt(s) -> None:
    """Give the keyboard back to the prompt box: a pane's field keeps it after an edit (Escape, then a
    click on the prompt row)."""
    s.key("escape")
    s.pump(0.3)
    row = driver.composer_row(s.lines())
    if row is not None:
        s.click(4, row)
        s.pump(0.3)


def cmd(s, text: str) -> None:
    to_prompt(s)
    s.submit(text)


def show_dialog(s, needle: str, timeout: float = 30) -> bool:
    """The dialog opens as a tab beside other open panes: /gate-dialog brings it to the front."""
    if wait(s, lambda: needle in scr(s), 3):
        return True
    for _ in range(3):
        cmd(s, "/gate-dialog")
        if wait(s, lambda: needle in scr(s), timeout / 3):
            return True
    return needle in scr(s)


def wheel(s, up: bool, n: int) -> None:
    """Mouse-wheel steps over the docked pane (right of its border), which scroll it without
    moving the keyboard focus."""
    cols = [ln.index("│") for ln in s.lines() if "│" in ln]
    if not cols:
        return
    x, y = max(set(cols), key=cols.count) + 10, s.rows // 3
    for _ in range(n):
        s.send(f"\x1b[<{64 if up else 65};{x + 1};{y + 1}M")
        s.pump(0.05)
    s.pump(0.5)


def show_long_dialog(s, top: str, bottom: str, timeout: float = 60) -> bool:
    """A dialog that may be taller than the docked pane: a part is sized to ~40 rows of a
    72-column pane (popup.dialog_parts), and the pane opens scrolled to its end, the buttons (seen
    on Claude Code 2.1.310; the pane scrolls with the wheel). It is open once `bottom` (its
    question, which names the part) shows; `top` (its heading) is read the way a person reads
    it, by scrolling the pane up; then back down to the buttons."""
    if not show_dialog(s, bottom, timeout):
        return False
    seen = top in scr(s)
    for _ in range(10):
        if seen:
            break
        wheel(s, True, 8)
        seen = top in scr(s)
    for _ in range(12):                      # down to the end again (its buttons), until it stops moving
        before = scr(s)
        wheel(s, False, 8)
        if scr(s) == before:
            break
    return seen and bottom in scr(s)


def in_pane(s, text: str) -> bool:
    """`text` drawn right of the docked pane's border (its field), not in the prompt box below
    (whose rows have no border): the screen alone can't tell the two apart otherwise."""
    return any(text in ln.split("│", 1)[1] for ln in s.lines() if "│" in ln)


def pane_text(s) -> str:
    """The docked pane's column alone (right of its border, row by row): a line the pane wrapped
    reads as written, without the conversation's text beside the next row."""
    return "\n".join(ln.split("│", 1)[1] for ln in s.lines() if "│" in ln)


def pane_edit(s, line: str) -> None:
    """Type one edit line into the hosts pane's field (an Input: not private, never for secrets).
    A click that didn't give the field the keys (seen on Claude Code 2.1.310: no ui.focus in the
    debug log, the line then sent to Claude from the prompt box) is taken back and tried again."""
    for i in range(4):
        try:
            s.click_text("edit:", dx=7)
        except LookupError:
            s.pump(1.0)
            continue
        s.pump(0.5)
        s.type(line, 0.01)
        s.pump(0.5)
        if in_pane(s, line[:16]):
            break
        note(f"pane edit: try {i + 1}: the keys didn't reach the pane's field; taken back, clicking again")
        s.key("backspace", len(line), settle=0.02)
        s.key("escape")
        s.pump(1.0)
    s.key("enter")
    s.pump(3.0)


def part_hosts(s, gi, proj: Path) -> None:
    print("hosts: /gate-hosts, edits typed into its field", flush=True)
    cmd(s, "/gate-hosts")
    ok = wait(s, lambda: "localhost: this machine" in scr(s), 60)
    check("hosts: /gate-hosts opens a native pane listing this machine and its runtime state",
          ok and "runtime" in scr(s), s.dump(25))
    if not ok:
        return
    SUMMARY["hosts_pane"] = [ln.split("│")[-1].strip() for ln in s.lines() if "│" in ln and ln.split("│")[-1].strip()][:8]
    root = proj / "ws"
    root.mkdir(exist_ok=True)
    before = form_text(gi)
    pane_edit(s, f"workspace add localhost proj {root}")
    msg = " ".join(ln.split("│")[-1].strip() for ln in s.lines() if "│" in ln)
    SUMMARY["hosts_localhost_workspace_note"] = msg[-300:]
    check("hosts: a workspace on this machine can be added from the pane's edit line (workspace add localhost ...)",
          "[hosts.localhost.workspaces.proj]" in form_text(gi), msg[-300:])
    # a new workspace is a widening: the pane runs gate check localhost, whose consent dialog
    # names it; approved here (it would otherwise wait in front of every later dialog)
    # (its tab opens beside the hosts pane, whose tab row already names it: /gate-dialog
    # brings it to the front, as in the accounts part)
    ok = show_dialog(s, "Approve", 60) and "localhost" in scr(s)
    SUMMARY["hosts_localhost_consent"] = [ln.split("│")[-1].strip() for ln in s.lines()
                                          if "│" in ln and ln.split("│")[-1].strip()][:8]
    check("hosts: the localhost workspace waits for the OK: the consent dialog opens and names it",
          ok and "proj" in scr(s), s.dump(20))
    # PLAN-0.11 §1.5: FORM's sudo = true was written before any vault existed; configuring this
    # computer's sudo applies up to "ask" at once and true waits for the OK, so the same dialog
    # also asks for that change (each mode in plain words, §19.4); Approve answers both
    check("hosts: the same consent dialog asks for the form's sudo = true too, saying what changes in "
          f"each mode (\"... {L.CONSENT_APPROVES}\")", ok and L.shows(scr(s), L.CONSENT_APPROVES),
          s.dump(20))
    if ok:
        press_text(s, "Approve", lambda: "Approve" not in scr(s), settle=4.0)
        check("hosts: approved in the dialog, the localhost workspace no longer waits",
              wait(s, lambda: "allow changes for localhost" not in scr(s) and "Approve" not in scr(s), 30),
              s.dump(15))
        # gate check localhost goes on to this machine's sudo (a choice; nothing secret): asked
        # each time, so nothing is stored and no later dialog waits behind it
        if show_dialog(s, "Ask me each time", 20):
            press_text(s, "Ask me each time", lambda: "Ask me each time" not in scr(s), settle=3.0)
        # the dialog's tab took the front: the hosts pane again, for the next edit
        cmd(s, "/gate-hosts")
        wait(s, lambda: "localhost: this machine" in scr(s) and "edit:" in scr(s), 60)
    pane_edit(s, "workspace add otherbox proj /srv/proj")
    ok = wait(s, lambda: "[hosts.otherbox.workspaces.proj]" in form_text(gi), 30)
    check("hosts: an edit typed into the pane's field (workspace add otherbox ...) is written through the form writer",
          ok, form_text(gi)[-300:])
    ok = wait(s, lambda: "workspace proj: /srv/proj" in scr(s) or "added workspace proj" in scr(s)
              or "otherbox didn't answer" in scr(s), 60)
    SUMMARY["hosts_after_edit"] = [ln.split("│")[-1].strip() for ln in s.lines() if "│" in ln and ln.split("│")[-1].strip()][:10]
    check("hosts: the pane reports the edit's outcome and the widening waits for the OK (its gate check: the "
          "TEST-NET host doesn't answer, so nothing is asked and nothing is approved)",
          ok and "wait for your OK" in scr(s), s.dump(20))
    SUMMARY["form_unchanged_by_refused_edit"] = before in form_text(gi)


def part_accounts(s, gi, cred) -> None:
    print("accounts: /gate-accounts, Review (consent), the credential, Check", flush=True)
    cmd(s, "/gate-accounts")
    ok = wait(s, lambda: "ui1 (api-key)" in scr(s), 60)
    check("accounts: /gate-accounts lists the accounts with their states (ui1: no credential stored)",
          ok and "no credential stored" in scr(s), s.dump(25))
    if not ok:
        return
    press_text(s, "Review ui1", lambda: "allow changes for ui1" in scr(s) or "Approve" in scr(s), settle=4.0)
    ok = show_dialog(s, "Approve")
    check("accounts: Review ui1... opens the consent dialog (a native pane; /gate-dialog brings its tab to the front)",
          ok and "Decline" in scr(s), s.dump(25))
    if not ok:
        return
    press_text(s, "Approve", lambda: "Approve" not in scr(s) or AD.FIELD in scr(s), settle=4.0)
    ok = show_dialog(s, AD.FIELD, 60)
    check("accounts: after the OK the private credential dialog for ui1 opens", ok and "ui1" in scr(s), s.dump(25))
    if not ok:
        return
    type_secret(s, cred.value)
    ok = wait(s, lambda: AD.FIELD not in scr(s), 60)
    check("accounts: the credential typed into the private field is taken", ok, s.dump(20))
    s.pump(2.0)
    # PLAN-0.11 §8: the first stored secret brings the passphrase offer (once a session);
    # Cancel leaves it pending, so the passphrase part's new session gets it again
    ok = show_dialog(s, L.OFFER_TITLE, 60)
    check("accounts: the first stored secret brings the vault passphrase offer (Set passphrase / Not now)",
          ok and L.OFFER_SET in scr(s) and L.OFFER_NOT_NOW in scr(s), s.dump(20))
    if ok:
        press_button(s, "Cancel", lambda: L.OFFER_TITLE not in scr(s))
        check("accounts: the offer is cancelled (it stays pending in the vault)",
              wait(s, lambda: L.OFFER_TITLE not in scr(s), 30)
              and vault_data(gi).get("passphrase_offer") == "pending",
              str(vault_data(gi).get("passphrase_offer")))
    cmd(s, "/gate-accounts")
    ok = wait(s, lambda: re.search(r"ui1 \(api-key\): (stored, not checked yet|connected|unknown)", scr(s)), 30)
    check("accounts: the pane shows ui1's new state (stored, not checked yet)", ok, s.dump(20))
    if "Check ui1" in scr(s):
        press_text(s, "Check ui1", lambda: False, tries=1, settle=4.0)
        SUMMARY["accounts_after_check"] = [ln.split("│")[-1].strip() for ln in s.lines() if "ui1" in ln][:4]
    for _ in range(3):              # close the management panes (their tabs' close mark)
        with contextlib.suppress(LookupError):
            s.click_text("✕")
            s.pump(0.8)


def part_settings(s, gi) -> None:
    """PLAN-0.11 §19.11: a consent dialog longer than one dialog comes in parts;
    nothing is approved before the last part's Approve."""
    print("settings: a consent too long for one dialog, in parts", flush=True)
    (gi.gateway_home / "gateway.toml").write_text(form_text(gi) + "\n" + L.settings_table())
    s.api.script([AD.bash("gate check settings", "approve the settings"), "settings answered"])
    cmd(s, "approve the new settings")
    ok = show_dialog(s, "Go on to part 2 of ", 120)    # part 1's question, beside its buttons
    n = L.parts_of(scr(s)) or 0
    ok = ok and n > 1 and show_long_dialog(s, f"(part 1 of {n}):", L.part_question(1, n), 60)
    check("settings: the consent dialog for 42 [shell] lines comes in parts (part 1 of n, its question "
          "beside Next saying so)", ok and n > 1 and L.NEXT in scr(s) and L.CONSENT_LAST not in L.flat(scr(s)),
          f"n={n}\n" + s.dump(25))
    if not ok or n < 2:
        return
    check("settings: nothing is approved while the first part is open",
          "TOOL_HOME_29" not in json.dumps(vault_data(gi).get("approved") or {}))
    for i in range(2, n + 1):             # the question beside the buttons says which part shows
        press_button(s, L.NEXT, lambda i=i: L.part_question(i, n) in scr(s), settle=4.0)
        ok = show_long_dialog(s, f"(part {i} of {n}):", L.part_question(i, n), 60)
        if not ok:
            break
    check(f"settings: Next goes through the parts to the last ({n} of {n}), which asks to approve all of it",
          ok and L.shows(scr(s), L.CONSENT_LAST) and "Approve" in scr(s), s.dump(25))
    if ok:
        press_button(s, "Approve", lambda: L.part_question(n, n) not in scr(s), settle=4.0)
    approved = wait(s, lambda: "TOOL_HOME_29" in json.dumps(vault_data(gi).get("approved") or {}), 60)
    check("settings: Approve on the last part approves all of it (the vault's approval names the last "
          "import)", approved)
    wait(s, lambda: "settings answered" in s.all_text(), 60)


def part_export(s, gi, dest: Path, xpass) -> bool:
    print("export: the checklist, the passphrase twice", flush=True)
    n0 = len(s.api.main_requests())
    s.api.script([AD.bash(f"gate export '{dest}'", "export the gateway"), "export answered"])
    cmd(s, "export the gateway")
    wait(s, lambda: "Tick what" in scr(s) or "export answered" in s.all_text(), 120)
    ok = show_dialog(s, "Tick what") and "[x]" in scr(s)
    check("export: the selection checklist opens as a native pane (items ticked)", ok, s.dump(30))
    if not ok:
        return False
    SUMMARY["export_items"] = [ln.strip() for ln in scr(s).splitlines() if "[x]" in ln or "[ ]" in ln][:12]
    press_text(s, "[ Continue ]" if "[ Continue ]" in scr(s) else "[ OK ]", lambda: AD.FIELD in scr(s), settle=4.0)
    ok = show_dialog(s, AD.FIELD, 60) and "export passphrase" in scr(s)
    check("export: the passphrase dialog opens with the private field", ok, s.dump(25))
    if not ok:
        return False
    type_secret(s, xpass.value)
    ok = show_dialog(s, "Type the passphrase again", 60) and AD.FIELD in scr(s)
    check("export: it asks again (typed twice)", ok, s.dump(25))
    type_secret(s, xpass.value)
    ok = wait(s, lambda: dest.exists(), 90)
    wait(s, lambda: len(s.api.main_requests()) >= n0 + 2, 60)
    mode = oct(dest.stat().st_mode & 0o777) if ok else None
    head = dest.read_bytes()[:40] if ok else b""
    check("export: the file is written, mode 0600, age-encrypted (passphrase recipient)",
          ok and mode == "0o600" and head.startswith(b"age-encryption.org/v1"), f"mode={mode} head={head[:22]!r}")
    return ok


def part_import(s, gi, src: Path, xpass, wrong) -> None:
    print("import: a wrong passphrase, the right one, a conflict, the summary", flush=True)
    t = form_text(gi)
    # the settings part's [shell] table taken out here (a narrowing: at once), so the
    # import brings it back: 42 widening lines, more than one dialog holds (§19.11)
    paged = L.settings_table() in t
    t = t.replace(L.settings_table(), "")
    (gi.gateway_home / "gateway.toml").write_text(t.replace('sites = ["api.ui1.example"]',
                                                            'sites = ["api.ui1-changed.example"]'))
    n0 = len(s.api.main_requests())
    s.api.script([AD.bash(f"gate import '{src}'", "import the file"), "import answered"])
    cmd(s, "import the export")
    wait(s, lambda: "import passphrase" in scr(s) or "import answered" in s.all_text(), 120)
    ok = show_dialog(s, "import passphrase", 60) and AD.FIELD in scr(s)
    check("import: the passphrase dialog opens with the private field", ok, s.dump(25))
    if not ok:
        return
    type_secret(s, wrong.value)
    ok = wait(s, lambda: "That didn't work" in scr(s) or "doesn't open" in scr(s), 60)
    check("import: a wrong passphrase is refused and asked again", ok, s.dump(25))
    type_secret(s, xpass.value)
    wait(s, lambda: "differs from yours" in scr(s) or "Import this?" in scr(s), 60)
    ok = show_dialog(s, "differs from yours", 30) or "Import this?" in scr(s)
    check("import: the right passphrase opens it; the changed account is a conflict the person decides",
          ok and "differs from yours" in scr(s), s.dump(30))
    if "differs from yours" in scr(s):
        press_text(s, "Use the file's", lambda: "differs from yours" not in scr(s), settle=4.0)
    if paged:
        ok = show_dialog(s, "Go on to part 2 of ", 60)     # part 1's question, beside its buttons
        n = L.parts_of(scr(s)) or 0
        ok = ok and n > 1 and show_long_dialog(s, f"Part 1 of {n}:", L.part_question(1, n), 60)
        check("import: the summary is too long for one dialog (the settings' 42 lines): Part 1 of n, "
              "with Next, and nothing imported yet",
              ok and n > 1 and L.NEXT in scr(s) and not L.shows(scr(s), L.IMPORT_LAST)
              and L.settings_table() not in form_text(gi), f"n={n}\n" + s.dump(30))
        for i in range(2, n + 1 if ok else 2):
            press_button(s, L.NEXT, lambda i=i: L.part_question(i, n) in scr(s), settle=4.0)
            ok = show_long_dialog(s, f"Part {i} of {n}:", L.part_question(i, n), 60)
            if not ok:
                break
        check("import: Next goes through the parts to the last, which asks to import all of it "
              "(Import / Cancel)", ok and n > 1 and L.shows(scr(s), L.IMPORT_LAST), s.dump(30))
        if ok and n > 1:
            press_text(s, "[ Import ]", lambda: L.part_question(n, n) not in scr(s), settle=4.0)
    else:
        ok = show_dialog(s, "Import this?", 60)
        check("import: the summary is shown for confirmation (Import / Cancel)", ok, s.dump(30))
        if ok:
            press_text(s, "[ Import ]", lambda: "Import this?" not in scr(s), settle=4.0)
    wait(s, lambda: len(s.api.main_requests()) >= n0 + 2, 90)
    check("import: the account is the file's again (sites restored)",
          wait(s, lambda: 'sites = ["api.ui1.example"]' in form_text(gi), 30), form_text(gi)[-300:])
    if paged:
        check("import: the settings are back from the file (import_env, import_path) and approved in "
              "the same dialog", wait(s, lambda: "TOOL_HOME_29" in form_text(gi)
                                      and "/opt/tool-11/bin" in form_text(gi), 30)
              and "TOOL_HOME_29" in json.dumps(vault_data(gi).get("approved") or {}),
              form_text(gi)[-400:])


def last_result(s, n0: int) -> str:
    reqs = s.api.main_requests()
    for r in reqs[n0 + 1:]:
        t = "\n".join(result_text(b) for b in tool_results(r))
        if t:
            return t
    return ""


def part_tamper(s, gi, src: Path, xpass, root: Path) -> None:
    print("tamper: a changed byte, a file that isn't an export", flush=True)
    bad = root / "tampered.age"
    b = bytearray(src.read_bytes())
    i = len(b) * 2 // 3
    b[i] ^= 0x01
    bad.write_bytes(bytes(b))
    os.chmod(bad, 0o600)
    before = form_text(gi)
    n0 = len(s.api.main_requests())
    s.api.script([AD.bash(f"gate import '{bad}'", "import the changed file"), "tamper answered"])
    cmd(s, "import the changed file")
    wait(s, lambda: "tamper answered" in s.all_text(), 120)          # the requester's wait (8 s here) ends first
    ok = show_dialog(s, "import passphrase", 60) and AD.FIELD in scr(s)
    if ok:
        type_secret(s, xpass.value)
        wait(s, lambda: "import passphrase" not in scr(s), 60)
    s.pump(2.0)
    # Claude retries as told ("Retry after they answer"): the retry joins the finished job's result
    n1 = len(s.api.main_requests())
    s.api.script([AD.bash(f"gate import '{bad}'", "retry the import"), "tamper retried"])
    cmd(s, "retry the import")
    wait(s, lambda: "tamper retried" in s.all_text(), 120)
    res = last_result(s, n1)
    SUMMARY["tamper_result"] = res[:300]
    SUMMARY["tamper_first_result"] = last_result(s, n0)[:300]
    audit = gi.root / "data" / "audit.jsonl"
    events = [json.loads(ln) for ln in audit.read_text().splitlines() if ln.strip()] if audit.exists() else []
    imports = [e for e in events if e.get("event") == "popup" and e.get("what") == "import"]
    SUMMARY["tamper_audit"] = [e.get("outcome") for e in imports][-3:]
    check("tamper: the import of a changed file changes nothing (form unchanged; the job ends failed in the audit log)",
          form_text(gi) == before and any(e.get("outcome") == "failed" for e in imports[-3:]),
          json.dumps(SUMMARY["tamper_audit"]))
    check("tamper: its refusal (damaged or changed file) reaches Claude or the person: the requester's wait ran out "
          "before the passphrase was typed, and the retry Claude is told to make should report the finished job",
          re.search(r"damaged|changed|tamper|integrity|authenticat|corrupt", res, re.I) is not None, res[-400:])
    if "import passphrase" in scr(s):            # the retry opened a new dialog instead: close it
        press_text(s, "Cancel", lambda: "import passphrase" not in scr(s), settle=3.0)
    notexp = root / "not-an-export.txt"
    notexp.write_text("hello\n")
    n0 = len(s.api.main_requests())
    s.api.script([AD.bash(f"gate import '{notexp}'", "import a text file"), "notexp answered"])
    cmd(s, "import a text file")
    wait(s, lambda: "notexp answered" in s.all_text(), 120)
    res = last_result(s, n0)
    check("tamper: a file that isn't a gateway export is refused before any dialog",
          "isn't a gateway export" in res, res[-300:])


SSO = "sso1"
SSO_TENANT = "contoso.onmicrosoft.com"
SSO_CLIENT = "11111111-2222-4333-8444-555555555555"
SSO_FORM = (f'\n[accounts.{SSO}]\nkind = "azure"\ntenant = "{SSO_TENANT}"\n'
            f'client_id = "{SSO_CLIENT}"\nsign_in = "browser"\n')
BROWSER_PAYLOAD = {"session_id": "acc-signin", "hook_event_name": "PreToolUse",
                   "tool_name": "mcp__claude-in-chrome__navigate",
                   "tool_input": {"url": "https://example.com/"}}


def tool_guard(gi) -> str:
    """The installed copy's hooks/tool_guard.sh on a browser tool's payload (its
    e2e branch reads the marker's run dir, where gated keeps signin-active): its
    output, empty when it lets the call through."""
    script = Path(gi.plugin.cache_path) / "hooks" / "tool_guard.sh"
    r = subprocess.run(["/bin/sh", str(script)], input=json.dumps(BROWSER_PAYLOAD), text=True,
                       capture_output=True, timeout=30, env={"PATH": "/usr/bin:/bin", "LANG": "C"})
    return r.stdout


def part_signin(s, gi, sso: dict) -> None:
    """PLAN-0.11 §7, §14: a browser sign-in through gated, never a real browser.
    gated-test.json names the `browser` knob's program (harness_oauth's
    recording program, here waiting for a go file) and a local fake OAuth
    server as the authority; the display rule follows macOS's (the harness
    passes no DISPLAY)."""
    print("signin: consent, gated's confirm, Open, the browser knob's program, the tokens", flush=True)
    srv, log, modef = sso["server"], sso["log"], sso["mode"]
    run_dir = gi.run
    s.api.script([AD.bash(f"gate check {SSO}", "sign in to azure"), "signin answered"])
    cmd(s, f"set up the {SSO} account")
    ok = show_dialog(s, "Approve", 120) and SSO in scr(s)
    check(f"signin: gate check {SSO} asks for the new account's OK first (its sign_in = browser shown)",
          ok and "Decline" in scr(s), s.dump(25))
    if ok:
        press_text(s, "Approve", lambda: f"allow changes for {SSO}" not in scr(s), settle=4.0)
    want = L.SIGNIN_AZURE.format(name=SSO)
    if not show_dialog(s, want, 20):
        # gate's own wait (popup_wait: 8 s) ran out on the consent: the approval stands, and
        # `gate login` starts the sign-in (gated holds it from there on)
        wait(s, lambda: "signin answered" in s.all_text(), 60)
        s.api.script([AD.bash(f"gate login {SSO}", "sign in to azure"), "login answered"])
        cmd(s, f"sign in to {SSO}")
    ok = show_dialog(s, want, 90)
    check("signin: gated's own confirm names the account and the tenant, says nothing happens before "
          "Open, with Open and Cancel",
          ok and SSO_TENANT in scr(s) and L.shows(pane_text(s), L.SIGNIN_NOTE) and "Cancel" in scr(s),
          s.dump(25))
    if not ok:
        return
    check("signin: nothing opened before Open (the knob's program has no record, no marker file)",
          not HO.opened(log) and not (run_dir / "signin-active").exists())
    press_button(s, "Open", lambda: want not in scr(s), settle=4.0)
    started = wait(s, lambda: bool(HO.opened(log)), 60)
    recs = HO.opened(log)
    url = recs[0].get("url", "") if recs else ""
    q = {k: v[0] for k, v in urllib.parse.parse_qs(urllib.parse.urlsplit(url).query).items()}
    check("signin: Open runs the browser knob's program once with the authorize URL (the fake "
          "authority, the account's tenant and client, S256, a 127.0.0.1 redirect)",
          started and len(recs) == 1
          and url.startswith(f"{srv.authority}/{SSO_TENANT}/oauth2/v2.0/authorize?")
          and q.get("client_id") == SSO_CLIENT and q.get("code_challenge_method") == "S256"
          and q.get("redirect_uri", "").startswith("http://127.0.0.1:"), url[:300])
    active = wait(s, lambda: (run_dir / "signin-active").exists(), 10)
    out = tool_guard(gi)
    check("signin: while it runs the browser tools are refused (gated's signin-active; the installed "
          "copy's tool_guard.sh denies a Claude in Chrome call)",
          active and '"permissionDecision": "deny"' in out and L.BROWSER_PAUSED in out, out[:300])
    Path(str(modef) + ".go").write_text("")
    done = wait(s, lambda: not (run_dir / "signin-active").exists()
                and any(r.get("step") == "follow" for r in HO.opened(log)), 90)
    grants = [t for t in srv.tokens if t.get("grant_type") == "authorization_code"]
    check("signin: the program followed the URL; gated took the code at its 127.0.0.1 listener and "
          "exchanged it once with the PKCE verifier (the fake token endpoint)",
          done and len(grants) == 1 and bool(grants[0].get("code_verifier"))
          and grants[0].get("client_id") == SSO_CLIENT,
          json.dumps({"steps": [r.get("step") for r in HO.opened(log)], "grants": len(grants)}))
    ent = wait(s, lambda: ((vault_data(gi).get("accounts") or {}).get(SSO) or {}).get("entra"), 30)
    rec = ((vault_data(gi).get("accounts") or {}).get(SSO) or {}).get("entra") or {}
    sso["tokens"] = [v for v in (rec.get("refresh_token"), rec.get("access_token")) if v]
    check("signin: the tokens are in the vault (a browser sign-in's record), from the fake server",
          bool(ent) and rec.get("kind") == "browser"
          and str(rec.get("refresh_token", "")).startswith("SSO-REFRESH-"),
          json.dumps(sorted(rec)))
    out = tool_guard(gi)
    check("signin: after it the browser tools pass the guard again", out.strip() == "", out[:200])
    s.pump(2.0)
    if L.OFFER_TITLE in scr(s):              # the session's offer, when no earlier part had it
        press_button(s, "Cancel", lambda: L.OFFER_TITLE not in scr(s))


def part_passphrase(root: Path, h, gi, env: dict, cred2, ppass) -> driver.Session | None:
    """PLAN-0.11 §8 in a new session: the offer the accounts part cancelled is
    still pending, so the next stored secret brings it again; Set passphrase
    opens the set-a-passphrase dialog (two private fields); the vault key is
    then wrapped."""
    print("passphrase: a new session, another credential, the offer, Set passphrase", flush=True)
    priv = gi.gateway_home / "private"
    s = driver.Session(root / "s2", root / "proj", config_dir=h.inst.config_dir,
                       extra_env={**env, "CLAUDE_CODE_NO_FLICKER": "1"},
                       replies=[AD.bash("gate check ui2", "add ui2"), "ui2 answered"],
                       debug_file=True, observer=True, cols=170, rows=50,
                       permission_mode="bypassPermissions", start=False)
    s.redact(cred2.value, ppass.value)
    LIVE["s"] = s
    try:
        s.start()
        s.wait_ready(180)
        reg = gi.run / "gated-sessions.json"
        wait(s, lambda: any(x.get("via") == "ui" for x in json.loads(reg.read_text())["sessions"]), 180, 1.0)
        check("passphrase: the offer is still pending from the earlier session's cancel",
              vault_data(gi).get("passphrase_offer") == "pending",
              str(vault_data(gi).get("passphrase_offer")))
        cmd(s, "add the ui2 account")
        ok = show_dialog(s, "Approve", 120) and "ui2" in scr(s)
        if ok:
            press_text(s, "Approve", lambda: "Approve" not in scr(s) or AD.FIELD in scr(s), settle=4.0)
        ok = show_dialog(s, AD.FIELD, 60) and "ui2" in scr(s)
        check("passphrase: ui2's consent, then its private credential dialog", ok, s.dump(25))
        if not ok:
            return s
        type_secret(s, cred2.value)
        wait(s, lambda: AD.FIELD not in scr(s), 60)
        ok = show_dialog(s, L.OFFER_TITLE, 90)
        check("passphrase: in this new session the stored credential brings the offer again",
              ok and L.OFFER_SET in scr(s), s.dump(25))
        if not ok:
            return s
        press_button(s, L.OFFER_SET, lambda: L.SET_PASSPHRASE_TITLE in scr(s), settle=4.0)
        ok = show_dialog(s, L.SET_PASSPHRASE_TITLE, 60) and AD.FIELD in scr(s)
        check("passphrase: Set passphrase opens the set-a-passphrase dialog (two private fields)", ok,
              s.dump(25))
        if not ok:
            return s
        AD.focus_field(s)
        s.type(ppass.value)
        s.key("tab")
        s.type(ppass.value)
        s.key("enter")
        ok = wait(s, lambda: (priv / "key.wrapped").exists() and not (priv / "key.txt").exists(), 90)
        check("passphrase: the vault key is wrapped with it (key.wrapped, no key.txt left)", ok,
              str(sorted(x.name for x in priv.iterdir())))
        wait(s, lambda: L.SET_PASSPHRASE_TITLE not in scr(s), 30)
        s.pump(2.0)
        return s
    finally:
        s.close()


def part_import_remote(s, gi, src: Path, xpass, wrong) -> None:
    """The import half of 14.10 on another machine (its own host keys and machine id)."""
    print("import-remote: the file of another machine", flush=True)
    before_local = re.findall(r"\[hosts\.localhost\][^\[]*", form_text(gi))
    n0 = len(s.api.main_requests())
    s.api.script([AD.bash(f"gate import '{src}'", "import the other machine's file"), "import answered"])
    cmd(s, "import the other machine's export")
    wait(s, lambda: "import passphrase" in scr(s) or "import answered" in s.all_text(), 120)
    ok = show_dialog(s, "import passphrase", 60) and AD.FIELD in scr(s)
    check("import-remote: the passphrase dialog opens", ok, s.dump(25))
    if not ok:
        return
    type_secret(s, wrong.value)
    check("import-remote: a wrong passphrase is refused", wait(s, lambda: "That didn't work" in scr(s)
                                                                 or "doesn't open" in scr(s), 60), s.dump(20))
    type_secret(s, xpass.value)
    for _ in range(6):
        ok = wait(s, lambda: "Which host in the file is this machine" in scr(s) or "differs from yours" in scr(s)
                  or "Import this?" in scr(s), 90)
        if not ok:
            break
        if "Which host in the file is this machine" in scr(s):
            SUMMARY["import_remote_asked_this_machine"] = True
            press_text(s, "None of them", lambda: "Which host in the file" not in scr(s), settle=4.0)
        elif "differs from yours" in scr(s):
            press_text(s, "Keep mine", lambda: "differs from yours" not in scr(s), settle=4.0)
        else:
            SUMMARY["import_remote_summary"] = [ln.strip() for ln in scr(s).splitlines() if ln.strip()][-14:]
            press_text(s, "[ Import ]", lambda: "Import this?" not in scr(s), settle=4.0)
            break
    wait(s, lambda: len(s.api.main_requests()) >= n0 + 2, 90)
    t = form_text(gi)
    check(f"import-remote: the other machine's account (from-{OTHER}) is here now", f"[accounts.from-{OTHER}]" in t,
          t[-500:])
    check("import-remote: the file's localhost did not become this machine's localhost (this machine's "
          "localhost section unchanged)", re.findall(r"\[hosts\.localhost\][^\[]*", t) == before_local,
          json.dumps([before_local, re.findall(r"\[hosts\.localhost\][^\[]*", t)])[:500])
    SUMMARY["import_remote_hosts"] = re.findall(r"\[hosts\.([a-z0-9-]+)\]", t)


PLAT = "mac" if sys.platform == "darwin" else "linux"
OTHER = "linux" if PLAT == "mac" else "mac"
FORM = ('[hosts.localhost]\nsudo = true\n\n[accounts.ui1]\nkind = "api-key"\nsites = ["api.ui1.example"]\n\n'
        f'[accounts.from-{PLAT}]\nkind = "api-key"\nsites = ["api.{PLAT}.example"]\n\n'
        '[hosts.otherbox]\naddress = "192.0.2.10"\nuser = "tester"\n\n'
        '[accounts.ui2]\nkind = "api-key"\nsites = ["api.ui2.example"]\n' + SSO_FORM)
PARTS = "scan,hosts,accounts,settings,export,import,tamper,signin,passphrase"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tmp", default=tempfile.gettempdir())
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--pixi-cache", default=None)
    ap.add_argument("--only", default=PARTS)
    ap.add_argument("--export-to", default=None)
    ap.add_argument("--import-from", default=None)
    ap.add_argument("--pass-file", default=None)
    a = ap.parse_args(argv)
    before = safety.real_settings_fingerprint()
    root = Path(tempfile.mkdtemp(prefix="acc-ui-", dir=a.tmp))
    safety.check_scratch(root, "acceptance root")
    print(f"acceptance (native UI): root {root}", flush=True)
    only = set(a.only.split(","))
    env = {"PIXI_CACHE_DIR": a.pixi_cache or str(root / "pixi-cache")}
    xpass = scan.Canary.new("export-pass")
    if a.pass_file and Path(a.pass_file).exists():
        xpass = scan.Canary(Path(a.pass_file).read_text().strip(), cid="export-pass")
    cred, wrong = scan.Canary.new("ui1-cred"), scan.Canary.new("wrong-pass")
    cred2, ppass = scan.Canary.new("ui2-cred"), scan.Canary.new("vault-pass")
    canaries = [xpass, cred, wrong, cred2, ppass]
    shims, shim_log = AD.path_shims(root)
    env["PATH"] = AD.shimmed_path(shims)
    watcher = AD.Watcher(canaries)
    watcher.start()
    t0 = time.time()
    try:
        if "scan" in only:
            static_scan()
        if only - {"scan"}:
            run(root, env, only, canaries, a)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        check(f"the run went to its end ({type(e).__name__}: {str(e)[:300]})", False)
    finally:
        watcher.stop.set()
        watcher.join(5)
        driver._close_all()
        for line in subprocess.run(["ps", "-A", "-ww", "-o", "pid=,command="], capture_output=True,
                                   text=True).stdout.splitlines():
            pid, _, cmd = line.strip().partition(" ")
            if str(root) in cmd and "gated" in cmd and pid.isdigit():
                with contextlib.suppress(OSError):
                    os.kill(int(pid), signal.SIGTERM)
    if only - {"scan"}:
        ran = [ln for ln in shim_log.read_text().splitlines() if ln.strip()]
        check("no window, browser or terminal program was run by name (recording shims first on PATH)", not ran,
              ", ".join(ran[:10]))
        check(f"best effort: none in the process table either ({watcher.samples} samples)", not watcher.banned,
              ", ".join(watcher.banned[:10]))
        check("no canary in any process's argv (samples)", not watcher.argv_hits, ", ".join(sorted(watcher.argv_hits)))
    time.sleep(1.0)
    left = [ln for ln in subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True,
                                        text=True).stdout.splitlines() if str(root) in ln and "ps -axo" not in ln]
    check("no process left naming the scratch root", not left, "\n".join(left))
    check("real ~/.config/claude settings and plugin registry unchanged", before == safety.real_settings_fingerprint())
    failed = [r for r in AD.RESULTS if not r["ok"]]
    summary = {"when": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "seconds": round(time.time() - t0),
               "claude": subprocess.run([driver.find_claude(), "--version"], capture_output=True,
                                        text=True).stdout.strip(), "platform": sys.platform,
               "passed": len(AD.RESULTS) - len(failed), "failed": len(failed), "checks": AD.RESULTS,
               "notes": AD.NOTES, **SUMMARY}
    out = Path(a.tmp) / "acceptance-native-ui.json"
    out.write_text(json.dumps(summary, indent=1, default=str))
    print(f"\n{summary['passed']} passed, {summary['failed']} failed in {summary['seconds']} s; {out}")
    if not a.keep:
        shutil.rmtree(root, ignore_errors=True)
    return 1 if failed else 0


def run(root: Path, env: dict, only: set[str], canaries: list, a) -> None:
    xpass, cred, wrong, cred2, ppass = canaries
    build_env = {k: v for k, v in env.items() if k != "PATH"}
    srv = HO.OAuthServer()
    srv.counter = 10 ** 9 + secrets.randbelow(10 ** 9)      # its tokens: SSO-ACCESS-n / SSO-REFRESH-n
    try:
        with install.Hermetic(root / "h", extra_env=build_env) as h:
            _run(root, h, env, build_env, only, canaries, a, srv)
    finally:
        srv.close()


def _run(root: Path, h, env: dict, build_env: dict, only: set[str], canaries: list, a, srv) -> None:
    xpass, cred, wrong, cred2, ppass = canaries
    gi = h.install_gateway_e2e(REPO)
    check("the gateway is installed through the e2e route (marker proven)", gi.proof is not None)
    ok, detail = AD.prebuild_env(root, h, gi, build_env)
    if not check("the gateway's env is built before the session", ok, detail):
        return
    (gi.root / "e2e.json").write_text(json.dumps({"popup_wait": 8}))
    os.chmod(gi.root / "e2e.json", 0o600)
    # the browser sign-in's test knobs, read by gated only under the e2e marker's override
    # (daemon/lifecycle.py): the recording program for the `browser` knob, the fake OAuth
    # server as the authority, the display rule of macOS (the harness passes no DISPLAY)
    prog, blog, bmode = HO.write_browser(root / "browser", "wait_go", py=sys.executable)
    (gi.root / "gated-test.json").write_text(json.dumps({"browser": str(prog), "entra_authority": srv.authority,
                                                         "browser_platform": "darwin"}))
    os.chmod(gi.root / "gated-test.json", 0o600)
    sso = {"server": srv, "log": blog, "mode": bmode, "tokens": []}
    gi.gateway_home.mkdir(parents=True, exist_ok=True)
    (gi.gateway_home / "gateway.toml").write_text(FORM)
    proj = root / "proj"
    proj.mkdir()
    s = driver.Session(root / "s1", proj, config_dir=h.inst.config_dir,
                       extra_env={**env, "CLAUDE_CODE_NO_FLICKER": "1"}, replies=["ok"],
                       debug_file=True, observer=True, cols=170, rows=50,
                       permission_mode="bypassPermissions", start=False)
    s.redact(*[c.value for c in canaries])
    LIVE["s"], LIVE["dir"] = s, root / "screens"
    LIVE["dir"].mkdir(exist_ok=True)
    exp = Path(a.export_to) if a.export_to else root / "export" / "gw-export.age"
    exp.parent.mkdir(parents=True, exist_ok=True)
    try:
        s.start()
        s.wait_ready(180)
        reg = gi.run / "gated-sessions.json"
        wait(s, lambda: any(x.get("via") == "ui" for x in json.loads(reg.read_text())["sessions"]), 180, 1.0)
        if "hosts" in only:
            part_hosts(s, gi, proj)
        if "accounts" in only:
            part_accounts(s, gi, cred)
        if "settings" in only:
            part_settings(s, gi)
        exported = False
        if "export" in only:
            exported = part_export(s, gi, exp, xpass)
            if exported and a.export_to and a.pass_file:
                Path(a.pass_file).write_text(xpass.value)
                os.chmod(a.pass_file, 0o600)
        if exported and "import" in only:
            part_import(s, gi, exp, xpass, wrong)
        if exported and "tamper" in only:
            part_tamper(s, gi, exp, xpass, root)
        if a.import_from and "import-remote" in only:
            part_import_remote(s, gi, Path(a.import_from), xpass, wrong)
        if "signin" in only:
            part_signin(s, gi, sso)
        s.pump(2.0)
    finally:
        s.close()
    secret = [xpass, cred, wrong] + [scan.Canary(v, cid=f"sso-token-{i}") for i, v in enumerate(sso["tokens"])]
    print("scans: the canaries", flush=True)
    for what, where in {"the scratch Claude config": h.inst.config_dir, "the gateway's data": gi.root / "data",
                        "the gateway's home (form, encrypted vault)": gi.gateway_home,
                        "the gateway's run dir": gi.run,
                        "the export file (age-encrypted)": exp if exp.exists() else None,
                        "the observer plugin's records": s.observer.root if s.observer else None,
                        "the browser program's log (the authorize URL only)": blog.parent}.items():
        if where is None or not Path(where).exists():
            continue
        rep = scan.Report()
        if Path(where).is_file():
            rep.scan_bytes(Path(where).read_bytes(), str(where), *secret)
        else:
            rep.scan_tree(where, *secret)
        check(f"scan: no passphrase, credential or sign-in token canary in {what}", rep.clean(), rep.summary())
    rep = scan.Report()
    rep.scan_api_log(s.api.log_path, *secret)
    check("scan: no canary in any fake-API request (the model's inputs)", rep.clean(), rep.summary())
    rep = scan.Report()
    rep.scan_bytes(bytes(s.raw), "pty", *secret, ansi=True)
    check("scan: no canary in the PTY output", rep.clean(), rep.summary())
    data = vault_data(gi)
    if exp.exists():
        v = (((data.get("accounts") or {}).get("ui1") or {}).get("token") or {}).get("value", "")
        if v:
            rep = scan.Report()
            rep.scan_bytes(exp.read_bytes(), "export", scan.Canary(v, cid="stored-ui1"))
            check("scan: the stored credential isn't in the export file in any encoding (encrypted)", rep.clean(),
                  rep.summary())
            check("broker receipt: ui1's stored credential is the typed canary (sha256)", sha(v) == sha(cred.value))
    if "passphrase" not in only:
        return
    s2 = part_passphrase(root, h, gi, env, cred2, ppass)
    if s2 is None:
        return
    print("scans: the passphrase session's canaries", flush=True)
    for what, where in {"the scratch Claude config": h.inst.config_dir, "the gateway's data": gi.root / "data",
                        "the gateway's home (form, encrypted vault, wrapped key)": gi.gateway_home,
                        "the gateway's run dir": gi.run,
                        "the passphrase session's observer records": s2.observer.root if s2.observer else None}.items():
        if where is None or not Path(where).exists():
            continue
        rep = scan.Report()
        rep.scan_tree(where, cred2, ppass)
        check(f"scan: no vault passphrase or ui2 credential canary in {what}", rep.clean(), rep.summary())
    rep = scan.Report()
    rep.scan_api_log(s2.api.log_path, cred2, ppass)
    rep.scan_bytes(bytes(s2.raw), "pty", cred2, ppass, ansi=True)
    check("scan: neither in the passphrase session's fake-API requests or PTY output", rep.clean(), rep.summary())


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
