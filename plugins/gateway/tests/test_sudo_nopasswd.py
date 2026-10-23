"""Sudo without blanket passwordless rules (PLAN-v4 phase 7, brief section 11):
the gateway never installs a sudoers rule or advises one; passwordless sudo is
used only where the system already has it; otherwise gate check offers to
store the password or to leave it to the per-call dialog (with Remember it);
a sudoers that wants a terminal points to the managed terminal path; the
policy's elevation restrictions refuse sudo with their rule; the target is
named before sudo runs."""
from __future__ import annotations

import io
import json
import os
import re
import sys
from pathlib import Path

import harness as H
import harness_sudo as HS
import harness_ux as U
from gateway import gate_setup, paths, vault

PW = "correct horse"


def _local(env):
    fake = H.make_fake_sudo(env.root / "fsudo", password=PW)
    env.o.tools = dict(env.o.tools or {}, sudo=str(fake.path))
    return fake


def _gate(fn, *args):
    out, err = io.StringIO(), io.StringIO()
    so, se = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        rc = fn(*args)
    finally:
        sys.stdout, sys.stderr = so, se
    return rc, out.getvalue(), err.getvalue()


def test_gate_check_offers_to_store_or_ask_and_never_a_sudoers_rule():
    with U.ux_env() as env:
        me = paths.local_user()
        _local(env)
        env.dialog.add("ok", gate_setup.SUDO_ASK)
        U.setup(env, "[hosts.localhost]\nsudo = true\n")
        rc, out, err = _gate(gate_setup.check, "localhost")
        assert rc == 0 and "(password asked each time)" in out, (out, err)
        d = env.dialog.calls()
        assert [c["kind"] for c in d] == ["choice"], d
        assert d[0]["default"].splitlines() == [gate_setup.SUDO_STORE, gate_setup.SUDO_ASK], d[0]
        q = d[0]["message"].lower()
        assert "sudoers" not in q and "passwordless" not in q and "nopasswd" not in q, q
        data = vault.load()
        assert not data["localhost"]["sudo"], "nothing stored"
        assert vault.sudo_choice(data, "localhost", me) == "ask"
        rc, out, _ = _gate(gate_setup.check, "localhost")
        assert rc == 0 and len(env.dialog.calls()) == 1, "asked once"


def test_gate_check_store_choice_is_remembered():
    with U.ux_env() as env:
        me = paths.local_user()
        _local(env)
        env.dialog.add("ok", gate_setup.SUDO_STORE)
        env.dialog.add("ok", PW)
        U.setup(env, "[hosts.localhost]\nsudo = true\n")
        from gateway import sudo as sudomod
        with U.patch(sudomod, "verify_local", lambda pw: (pw == PW, "Sorry, try again")):
            rc, out, err = _gate(gate_setup.check, "localhost")
        assert rc == 0 and "(password saved)" in out, (out, err)
        data = vault.load()
        assert data["localhost"]["sudo"][me]["password"] == PW
        assert vault.sudo_choice(data, "localhost", me) == "password"
        rc, out, _ = _gate(gate_setup.check, "localhost")
        assert rc == 0 and len(env.dialog.calls()) == 2, "asked once"
        rc, out, _ = _gate(gate_setup.forget, "localhost", "sudo")
        assert vault.sudo_choice(vault.load(), "localhost", me) is None


def test_a_stored_password_is_used_as_it_is_without_a_choice():
    """A password stored before (0.6, or the stand-in's own dialog with
    Remember it) is kept: there is no passwordless rule to offer instead."""
    with U.ux_env() as env:
        me = paths.local_user()
        _local(env)
        U.setup(env, "[hosts.localhost]\nsudo = true\n")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", me, PW)
        rc, out, err = _gate(gate_setup.check, "localhost")
        assert rc == 0 and "(password saved)" in out, (out, err)
        assert env.dialog.calls() == []
        data = vault.load()
        assert data["localhost"]["sudo"][me]["password"] == PW
        assert vault.sudo_choice(data, "localhost", me) != "ask"
        # the sudo step itself (whatever gate check's plan says) asks nothing either
        from gateway import sudo as sudomod
        with U.patch(sudomod, "probe_nopasswd", lambda user=None: False):
            assert gate_setup._sudo_step("localhost") == []
        assert env.dialog.calls() == []
        assert vault.sudo_choice(vault.load(), "localhost", me) == "password"


def test_passwordless_sudo_already_configured_is_used_and_nothing_is_asked():
    with U.ux_env() as env:
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        env.o.tools = dict(env.o.tools or {}, sudo=str(fake.path))
        U.setup(env, "[hosts.localhost]\nsudo = true\n")
        rc, out, err = _gate(gate_setup.check, "localhost")
        assert rc == 0 and "no password needed" in out, (out, err)
        assert env.dialog.calls() == []


def test_gate_check_remote_offers_store_or_ask():
    from gateway import ssh as sshmod
    form = '[hosts.box]\naddress = "octo@box.example.com"\n'
    with U.ux_env() as env:
        U.setup(env, form)
        with vault.edit() as d:
            r = vault.host_record(d, "box")
            r["keys"].append(vault.key_record(*vault.generate_ssh_key("t")))
            r["installed"] = vault.now()
            r["host_keys"] = ["ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"]
        env.dialog.add("ok", gate_setup.SUDO_ASK)
        with U.patch(sshmod, "probe_remote_nopasswd", lambda n, u: False), \
                U.patch(sshmod, "test_login", lambda n: (True, "ok")):
            rc, out, err = _gate(gate_setup.check, "box")
        assert rc == 0 and "(password asked each time)" in out, (out, err)
        q = env.dialog.calls()[0]["message"]
        assert "placed briefly on box" in q and "sudoers" not in q.lower()
        assert not hasattr(sshmod, "setup_remote_nopasswd")
        data = vault.load()
        assert not data["hosts"]["box"]["sudo"] and vault.sudo_choice(data, "box", "octo") == "ask"


# what would advise or install blanket passwordless sudo
ADVICE = re.compile(r"(?i)(NOPASSWD:\s*ALL|set up passwordless sudo|sudoers\.d/claude-gateway|"
                    r"passwordless sudo rule for|NOPASSWD sudo rule|nopasswd_script|"
                    r"install_nopasswd|setup_remote_nopasswd|"
                    r"recommend[a-z]* (?:the |a |blanket )?(?:NOPASSWD|passwordless)|"
                    r"passwordless sudo \(recommended|for passwordless sudo)")
# where a Markdown passage starts: a list item, a heading or a table row
_BLOCK_START = re.compile(r"\s*(?:(?:[-*+]|\d+\.)\s|#|\|)")


def _passage(lines: list[str], i: int) -> str:
    """The Markdown passage holding line i: a table row alone, else its list
    item or paragraph (up to a blank line or the next item, heading or row)."""
    if lines[i].lstrip().startswith("|"):
        return lines[i]
    a = i
    while not _BLOCK_START.match(lines[a]) and a > 0 and lines[a - 1].strip() and \
            not lines[a - 1].lstrip().startswith(("|", "#")):
        a -= 1
    b = i
    while b + 1 < len(lines) and lines[b + 1].strip() and not _BLOCK_START.match(lines[b + 1]):
        b += 1
    return "\n".join(lines[a:b + 1])


def advice_hits(files: list[Path], root: Path) -> list[str]:
    """Every advice match in `files`; in Markdown a passage that says it is
    superseded (an old record: the advice it quotes no longer holds) is
    exempt, never code."""
    hits = []
    for f in files:
        if not f.is_file() or "vendor" in f.parts or f.suffix in (".pyc",):
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        lines = text.split("\n")
        for m in ADVICE.finditer(text):
            line = text.count("\n", 0, m.start())
            if f.suffix == ".md" and "superseded" in _passage(lines, line).lower():
                continue
            hits.append(f"{f.relative_to(root)}:{line + 1}: {m.group(0)}")
    return hits


def advice_files(plugin: Path) -> list[Path]:
    repo = plugin.parent.parent
    return [*sorted((plugin / "src").rglob("*.py")), *sorted((plugin / "hooks").rglob("*")),
            *sorted((plugin / "skills").rglob("*.md")), *sorted((plugin / "commands").rglob("*.md")),
            repo / "README.md", repo / "CLAUDE.md", *sorted((repo / "docs").rglob("*.md"))]


def test_no_blanket_passwordless_sudo_advice_anywhere():
    plugin = H.PLUGIN
    repo = plugin.parent.parent
    files = advice_files(plugin)
    if (repo / "docs").is_dir():
        # every Markdown file under docs/ is read, the historical records too
        for want in ("docs/dev/phaseB-requests/ssh.md", "docs/dev/phaseB-requests/RESOLUTION.md",
                     "docs/dev/DECISIONS.md", "docs/dev/history/REDESIGN-v3.md",
                     "docs/dev/modules/sudo.md", "docs/CAPABILITIES.md"):
            assert repo / want in files, want
    else:
        print("       (docs part skipped: a copy of the plugin folder alone)")
    hits = advice_hits(files, repo)
    assert not hits, "blanket passwordless sudo advice: " + "; ".join(hits[:10])


def test_the_advice_scan_reads_every_doc_and_exempts_only_passages_marked_superseded():
    import tempfile
    with tempfile.TemporaryDirectory(dir=str(H.tmp_base())) as d:
        base = Path(d)
        plugin = base / "plugins" / "gateway"
        doc = base / "docs" / "old" / "notes.md"
        doc.parent.mkdir(parents=True)
        doc.write_text(
            "# Notes\n\nThe group would recommend NOPASSWD rules for every host.\n\n"
            "Earlier we said to set up passwordless sudo\n(superseded: removed since).\n\n"
            "- an item: gate check offered passwordless sudo (recommended) then\n"
            "- the next item is superseded but says nothing\n\n"
            "| a | b |\n|---|---|\n| row: NOPASSWD: ALL (superseded) | x |\n"
            "| row: NOPASSWD: ALL | y |\n", encoding="utf-8")
        (base / "docs" / "history").mkdir()
        (base / "docs" / "history" / "plan.md").write_text("Use a NOPASSWD sudo rule.\n",
                                                           encoding="utf-8")
        (base / "CLAUDE.md").write_text("Then set up passwordless sudo.\n", encoding="utf-8")
        code = plugin / "src" / "x.py"
        code.parent.mkdir(parents=True)
        code.write_text("# superseded\nADVICE = 'set up passwordless sudo'\n", encoding="utf-8")
        hits = advice_hits(advice_files(plugin), base)
        got = sorted(":".join(h.split(":")[:2]) for h in hits)
        assert got == sorted(["docs/old/notes.md:3", "docs/old/notes.md:8", "docs/old/notes.md:14",
                              "docs/history/plan.md:1", "CLAUDE.md:1", "plugins/gateway/src/x.py:2"]), hits


def test_a_sudoers_that_wants_a_terminal_points_to_a_gateway_terminal():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), PW)
        fake = H.make_fake_sudo(env.root / "fsudo", password=PW)
        tty = env.root / "tty-sudo"
        tty.mkdir()
        script = tty / "sudo"
        script.write_text('#!/bin/sh\ncase "$*" in *-n*) exit 1 ;; esac\n'
                          'echo "sudo: a terminal is required to read the password" >&2\nexit 1\n')
        os.chmod(script, 0o755)
        fake.path = script
        r = HS.run_sudo(env, fake, "true")
        assert r.returncode != 0 and "gateway terminal" in r.stderr and "terminal_open" in r.stderr, r


def test_elevation_policy_refuses_sudo_with_its_rule_and_the_target_is_named():
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo="true")
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        r = HS.run_sudo(env, fake, "echo", "hi")
        assert r.returncode == 0 and r.stdout == "hi\n", r
        # the target identity is named before elevation by the approval hook's
        # systemMessage (test_policy), never on the command's own output
        assert "sudo runs as root" not in r.stderr, r.stderr
        env.write_form("[hosts.localhost]\nsudo = true\n[hosts.localhost.policy]\nelevation = \"deny\"\n")
        r = HS.run_sudo(env, fake, "echo", "hi")
        assert r.returncode != 0 and r.stdout == "", r
        assert '[hosts.localhost.policy] elevation = "deny"' in r.stderr, r.stderr
        ran = [x.get("ran") for x in fake.log() if x.get("ran")]
        assert ran.count(["echo", "hi"]) == 1, ("the denied sudo never ran", fake.log())
