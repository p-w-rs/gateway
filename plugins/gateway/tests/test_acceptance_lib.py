"""The helpers the TUI acceptances and the headless e2e suite share
(tests/acceptance_lib.py), and the scripts themselves as far as the suite
can check them: they compile, and every string they look for on a screen or
in a result is still what the gateway's code prints (the acceptances run
live only by hand; a string that drifted would fail them there first).
"""
from __future__ import annotations

import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import harness as H
import acceptance_lib as L
from gateway import consent, envfile, hooks_bash, hooks_session, modes, paths, popup, transfer, vault

MOD = H.PLUGIN / "hooks" / "mod"


def _tmp(prefix: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=prefix, dir=H.tmp_base())).resolve()


def test_every_acceptance_and_e2e_script_compiles():
    """compile() only (no bytecode written): a script that no longer parses
    would first fail when the lead runs it live."""
    files = (sorted(H.TESTS.glob("acceptance_*.py")) + sorted((H.TESTS / "e2e").glob("*.py"))
             + [H.TESTS / "harness_oauth.py", H.TESTS / "fakes" / "fake_user_tool.py"])
    assert len(files) >= 12, files
    for f in files:
        compile(f.read_text(), str(f), "exec")


def _scripts() -> list[Path]:
    return (sorted(H.TESTS.glob("acceptance_*.py")) + sorted((H.TESTS / "e2e").glob("*.py"))
            + [H.TESTS / "harness_oauth.py", H.TESTS / "fakes" / "fake_user_tool.py"])


def _undefined_globals(path: Path) -> list[str]:
    """The global names a script reads (at module level or in any function)
    that it never binds and that aren't builtins: what pyflakes reports as an
    undefined name, which only fails a script when that line runs."""
    import builtins
    import symtable
    top = symtable.symtable(path.read_text(), str(path), "exec")
    scopes, todo = [], list(top.get_children())
    while todo:
        t = todo.pop()
        scopes.append(t)
        todo.extend(t.get_children())
    bound = {s.get_name() for s in top.get_symbols() if s.is_assigned() or s.is_imported() or s.is_namespace()}
    bound |= {s.get_name() for t in scopes for s in t.get_symbols() if s.is_declared_global() and s.is_assigned()}
    known = bound | set(dir(builtins))
    out = {f"<module>: {s.get_name()}" for s in top.get_symbols() if s.is_referenced()
           and s.get_name() not in known}
    out |= {f"{t.get_name()}: {s.get_name()}" for t in scopes for s in t.get_symbols()
            if s.is_referenced() and s.is_global() and s.get_name() not in known}
    return sorted(n for n in out if not re.search(r": __\w+__$", n))


def test_every_acceptance_and_e2e_script_names_only_what_exists():
    """Every global a script reads is bound in it (acceptance_managed once
    read a SUMMARY it never defined: the live run stopped at its first route
    check), and every `L.name` is in acceptance_lib."""
    import ast
    for f in _scripts():
        assert _undefined_globals(f) == [], (f.name, _undefined_globals(f))
        tree = ast.parse(f.read_text())
        if any(isinstance(n, ast.Import) and any(a.name == "acceptance_lib" and a.asname == "L" for a in n.names)
               for n in ast.walk(tree)):
            missing = sorted({n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
                              and isinstance(n.value, ast.Name) and n.value.id == "L" and not hasattr(L, n.attr)})
            assert not missing, (f.name, missing)
    probe = _tmp("gwug-")
    try:
        bad = probe / "bad.py"
        bad.write_text("X = 1\n\ndef f():\n    global Y\n    Y = X\n    return SUMMARY, Y, len, __file__\n")
        assert _undefined_globals(bad) == ["f: SUMMARY"], _undefined_globals(bad)
    finally:
        shutil.rmtree(probe, ignore_errors=True)


def _script_src(name: str) -> str:
    return (H.TESTS / name).read_text()


def _function_src(name: str, func: str) -> str:
    """One top-level function's source in an acceptance script."""
    import ast
    text = _script_src(name)
    for node in ast.parse(text).body:
        if isinstance(node, ast.FunctionDef) and node.name == func:
            return ast.get_source_segment(text, node) or ""
    raise AssertionError(f"{name} has no function {func}")


def _script_consts(name: str, *names: str) -> dict[str, Any]:
    """Module-level constants of an acceptance script, without importing it
    (it imports tests/tui, which needs pyte)."""
    import ast
    text = _script_src(name)
    out: dict[str, Any] = {}
    for node in ast.parse(text).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name) \
                and node.targets[0].id in names:
            out[node.targets[0].id] = ast.literal_eval(node.value)
    assert set(out) == set(names), (name, sorted(set(names) - set(out)))
    return out


def test_the_consent_and_import_strings_the_acceptances_look_for_are_the_gateways():
    """A bare `sudo = true` rising from "ask" (the acceptances' first gate
    check of this computer's sudo) says what each mode now does; a consent
    and an import confirm longer than one dialog come in parts with Next on
    each but the last."""
    from gateway import form as F
    data = {"approved": {"rights": consent.snapshot(F.parse_text("", Path("/x")))}}
    e = consent.compute(F.parse_text("[hosts.localhost]\nsudo = true\n", Path("/x")), data)
    lines = [c.render() for c in e.pending]
    assert len(lines) == 1 and L.CONSENT_APPROVES in lines[0], lines
    with H.gateway_env() as env:
        env.write_form(L.settings_table())
        vault.save(vault.empty())
        pend = consent.compute(env.form(), vault.load()).pending_for("settings")
        assert len(pend) == len(L.SETTINGS_ENV) + len(L.SETTINGS_PATH), len(pend)
        pages = popup.consent_pages("settings", pend)
    assert pages is not None and len(pages) >= 2, pages and len(pages)
    n = len(pages)
    # how the native UI acceptance reads the parts: n from part 1's question,
    # each part i by the heading it scrolls up to and its question
    assert L.parts_of(pages[0]) == n and all(L.parts_of(p) is None for p in pages[1:])
    for i, p in enumerate(pages, 1):
        assert f"(part {i} of {n}):" in p and p.split("\n")[-1].startswith(L.part_question(i, n)), p
        assert (L.CONSENT_LAST in p) is (i == n)
        assert ("Go on to part 2 of " in p) is (i == 1)
    pop = (H.PLUGIN / "src" / "gateway" / "popup.py").read_text()
    assert f'"Approve" if last else "{L.NEXT}"' in pop
    imp = transfer.confirm_pages([f"line {i}" for i in range(60)], 300, 40)
    k = len(imp)
    assert k >= 2 and [p[0] for p in imp] == [f"Part {i} of {k}:" for i in range(1, k + 1)]
    assert L.parts_of("\n".join(imp[0])) == k and all(L.parts_of("\n".join(p)) is None for p in imp[1:])
    for i, p in enumerate(imp, 1):
        assert p[-1].startswith(L.part_question(i, k)) and (L.IMPORT_LAST in p[-1]) is (i == k), p[-1]
    tr = (H.PLUGIN / "src" / "gateway" / "transfer.py").read_text()
    assert f'ok_label="Import" if last else "{L.NEXT}"' in tr


def test_the_dialog_and_context_strings_the_acceptances_look_for_are_the_gateways():
    """The passphrase offer, the set-passphrase dialog, the browser sign-in's
    confirm and outcome, the browser-tool guard, Claude's context (job lines,
    the first 0.11 session), the cold window's network ask, the no-mods
    notice and the not-ready line."""
    ts = (MOD / "dialog.ts").read_text()
    assert f"export const OFFER_TITLE = '{L.OFFER_TITLE}'" in ts
    assert f"export const OFFER_OPTIONS: readonly string[] = ['{L.OFFER_SET}', '{L.OFFER_NOT_NOW}']" in ts
    assert L.SIGNIN_AZURE.format(name="${s.account}") in ts
    assert L.SIGNIN_NOTE in re.search(r"export const SIGNIN_NOTE = \"([^\"]+)\"", ts).group(1)
    life = (H.PLUGIN / "src" / "gateway" / "daemon" / "lifecycle.py").read_text()
    assert f'"title": "{L.SET_PASSPHRASE_TITLE}"' in life
    from gateway.daemon import oauth
    assert L.SIGNIN_OK.format(name="sso1") in oauth.OK_TEXT.format(name="sso1")
    assert L.BROWSER_PAUSED in (H.PLUGIN / "hooks" / "tool_guard.sh").read_text()
    assert L.JOBS_MARK in hooks_session.JOBS_HOWTO
    # every request's skill listing carries the skill's description: the mark must not match it
    assert L.JOBS_MARK not in (H.PLUGIN / "skills" / "gateway" / "SKILL.md").read_text()
    lib = (MOD / "lib.ts").read_text()
    assert L.PIXI_OLD_STATUS.replace("/gate-doctor", "/${DOCTOR_COMMAND}") in lib
    assert f"update pixi (${{PIXI_UPDATE}})" in lib and L.PIXI_SELF_UPDATE in lib
    assert L.POSTURE_SUDO in hooks_session.POSTURE_SUDO
    cold = json.loads(envfile.degraded_bash_text("network"))["hookSpecificOutput"]
    assert cold["permissionDecision"] == "ask" and L.COLD_NET in cold["permissionDecisionReason"]
    assert L.MANAGED_NOTICE in hooks_bash.MANAGED_NOTICE
    assert L.NOT_READY in (H.PLUGIN / "hooks" / "gate-sh").read_text()


def _hook(cmd: str, mode: str = "auto", tool: str = "Bash") -> dict:
    payload = {"tool_name": tool, "tool_input": {"command": cmd}, "permission_mode": mode,
               "cwd": str(paths.home().parent.parent / "project")}
    return (hooks_bash.main(payload) or {}).get("hookSpecificOutput") or {}


def test_the_hook_answers_the_acceptances_look_for_are_the_gateways():
    """curl asks (the network class) and is refused in a job; a by-path ssh
    to a configured host is refused as a route around the stand-in, while an
    unconfigured one gets no decision (the pass-through's business)."""
    with H.gateway_env() as env:
        (env.root / "project").mkdir()
        out = _hook("curl -s http://127.0.0.1:9/")
        assert out.get("permissionDecision") == "ask" and L.NET_ASK in out["permissionDecisionReason"], out
        out = _hook("curl -s http://127.0.0.1:9/", tool=hooks_bash.JOB_TOOL)
        assert out.get("permissionDecision") == "deny" and L.NET_JOB in out["permissionDecisionReason"], out
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\n')
        vault.save(vault.empty())
        consent.approve_all(env.form())
        out = _hook("/usr/bin/ssh box true", "bypassPermissions")
        assert out.get("permissionDecision") == "deny" and L.ROUTE_SSH in out["permissionDecisionReason"], out
        assert _hook("/usr/bin/ssh other.invalid true", "bypassPermissions") == {}


def test_the_user_tools_fakes_record_each_run_and_say_so():
    """write_user_tools: one fake per name, standing alone (its own copy of
    fake_user_tool.py); each run prints "fake TOOL ran" and is recorded with
    its argv and cwd; user_tool_runs leaves out ssh -G lookups unless asked."""
    base = _tmp("gwut-")
    try:
        d = L.write_user_tools(base / "user tools", ("ssh", "git"), sys.executable)
        assert sorted(p.name for p in d.iterdir()) == ["fake_user_tool.py", "git", "ssh"]
        assert all(os.access(d / n, os.X_OK) for n in ("ssh", "git"))
        work = base / "w"
        work.mkdir()
        env = {"PATH": "/usr/bin:/bin", "HOME": str(base)}
        r = subprocess.run([str(d / "ssh"), "box.invalid", "echo", "hi there"], cwd=work, env=env,
                           capture_output=True, text=True, timeout=60)
        assert r.returncode == 0 and r.stdout.strip() == L.FAKE_RAN.format(tool="ssh"), r
        r = subprocess.run([str(d / "ssh"), "-G", "box.invalid"], cwd=work, env=env,
                           capture_output=True, text=True, timeout=60)
        assert "hostname box.invalid" in r.stdout, r
        subprocess.run([str(d / "git"), "status"], cwd=work, env=env, capture_output=True, timeout=60)
        runs = L.user_tool_runs(d)
        assert [(x["tool"], x["argv"], x["cwd"]) for x in runs] == [
            ("ssh", ["box.invalid", "echo", "hi there"], str(work)), ("git", ["status"], str(work))], runs
        assert len(L.user_tool_runs(d, "ssh", with_g=True)) == 2
        assert [x["argv"] for x in L.user_tool_runs(d, "git")] == [["status"]]
        assert L.user_tool_runs(base / "none") == []
        for bad in ("../x", "fake_user_tool.py", ""):
            try:
                L.write_user_tools(base / "b", (bad,), sys.executable)
                raise AssertionError(f"{bad!r} was taken as a tool name")
            except ValueError:
                pass
    finally:
        shutil.rmtree(base, ignore_errors=True)


HELP = '''  --input-format <format>               Input format (only works with --print)
                                        (choices: "text", "stream")
  --permission-mode <mode>              Permission mode to use for the session
                                        (choices: "acceptEdits", "auto",
                                        "bypassPermissions", "manual",
                                        "dontAsk", "plan")
  --permission-prompts <target>         Who answers permission prompts with
  --output-format <format>              Output format (choices: "text", "json")
'''


def test_the_permission_modes_and_the_gateways_mode_table():
    """`claude --help`'s --permission-mode choices (Claude Code 2.1.301's
    text), and the key each means: the same table as modes.PAYLOADS; a bare
    `true` right is allow only in BARE_TRUE_ALLOWS (§2.3)."""
    assert L.permission_modes(HELP) == ["acceptEdits", "auto", "bypassPermissions", "manual",
                                         "dontAsk", "plan"]
    assert L.permission_modes("no such option here") == []
    assert L.manual_mode(L.permission_modes(HELP)) == "manual"
    assert L.manual_mode(["acceptEdits", "auto", "default", "plan"]) == "default"
    assert L.MODE_KEYS == modes.PAYLOADS
    assert all(L.mode_key(c) == modes.SPELLINGS[c] for c in L.permission_modes(HELP))
    assert L.mode_key("bypass") is None and L.mode_key("Auto") is None
    bare = modes.parse(True, "right")
    assert L.BARE_TRUE_ALLOWS == tuple(k for k in modes.KEYS if bare.word(k) == "allow")


def test_which_shells_made_the_snapshots():
    """Every session of a config adds its snapshot there: a session's own are
    the ones that weren't there before it (`skip`)."""
    base = _tmp("gwss-")
    try:
        assert L.snapshot_shells(base) == [] and L.snapshot_files(base) == []
        d = base / "shell-snapshots"
        d.mkdir()
        for n in ("snapshot-zsh-1700000000-abc.sh", "notes.txt", "snapshot-.sh"):
            (d / n).write_text("")
        before = L.snapshot_files(base)
        assert [p.name for p in before] == ["snapshot-zsh-1700000000-abc.sh"]
        for n in ("snapshot-bash-1700000001-def.sh", "snapshot-bash-1700000002-ghi.sh"):
            (d / n).write_text("")
        assert L.snapshot_shells(base) == ["bash", "zsh"]
        assert L.snapshot_shells(base, skip=before) == ["bash"]
        assert L.snapshot_shells(base, skip=[p.name for p in L.snapshot_files(base)]) == []
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_a_sessions_own_transcripts_are_the_new_ones():
    """new_files: what a session added to a projects folder every session of
    its config shares (the install acceptance's notice check reads only
    those: an earlier session's transcript holds the notice too)."""
    base = _tmp("gwnf-")
    try:
        first = base / "projects" / "p" / "a.jsonl"
        first.parent.mkdir(parents=True)
        first.write_text('{"said": "the notice"}\n')
        before = sorted((base / "projects").rglob("*.jsonl"))
        second = first.with_name("b.jsonl")
        second.write_text('{"said": "nothing"}\n')
        now = sorted((base / "projects").rglob("*.jsonl"))
        assert L.new_files(now, before) == [second]
        assert L.new_files(now, [str(p) for p in now]) == []
        assert L.new_files(now, []) == now
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_shows_reads_a_wrapped_line_as_written():
    """A line the screen wrapped (at a space, or inside a word) still shows
    the piece; a piece that isn't there doesn't."""
    screen = ("│ sudo on this computer: in Auto and Bypass permissions modes the gateway now │\n"
              "│   approves without asking you; elsewhere                                     │")
    assert L.shows(screen, L.CONSENT_APPROVES)
    assert L.shows("the gateway now appro\nves without asking you", L.CONSENT_APPROVES)
    assert not L.shows(screen, "asks you in every mode")
    assert L.flat(" a \n\t b ") == " a b "


def test_the_tls_site_serves_its_page_to_a_client_that_trusts_its_ca():
    """TlsSite (a WebFetch the harness serves): a CA and a certificate for
    127.0.0.1 made with openssl; a client trusting only that CA fetches the
    page, one that doesn't refuses; the CA bundle carries another CA file."""
    if not (shutil.which("openssl") or os.path.exists("/usr/bin/openssl")):
        print("  note: no openssl here; TlsSite not tried")
        return
    base = _tmp("gwtls-")
    site = None
    try:
        site = L.TlsSite(base, "<p>hello page</p>")
        ctx = ssl.create_default_context(cafile=str(site.ca))
        with urllib.request.urlopen(site.url, context=ctx, timeout=20) as r:
            assert r.status == 200 and r.read() == b"<p>hello page</p>"
        try:
            urllib.request.urlopen(site.url, context=ssl.create_default_context(), timeout=20)
            raise AssertionError("a client without the scratch CA trusted the site")
        except (ssl.SSLError, urllib.error.URLError):
            pass
        assert site.paths == ["/page"], site.paths
        other = base / "other-ca.pem"
        other.write_text("-----BEGIN CERTIFICATE-----\nX\n-----END CERTIFICATE-----\n")
        bundle = site.ca_bundle(str(other)).read_text()
        assert bundle.startswith("-----BEGIN CERTIFICATE-----\nX\n") and site.ca.read_text() in bundle
        assert oct(os.stat(base / "ca.key").st_mode & 0o777) == "0o600"
    finally:
        if site is not None:
            site.close()
        shutil.rmtree(base, ignore_errors=True)


def test_the_browser_program_waits_for_its_go_file_then_follows():
    """harness_oauth.write_browser's "wait_go" mode (the native UI
    acceptance's sign-in step looks at the guard meanwhile): nothing is
    fetched until MODEFILE.go exists, then the URL is followed."""
    import http.server
    import harness_oauth as HO
    hits: list[str] = []

    class Hd(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            hits.append(self.path)
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *a):
            pass
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Hd)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    base = _tmp("gwbr-")
    try:
        prog, log, modef = HO.write_browser(base, "wait_go", py=sys.executable)
        url = f"http://127.0.0.1:{srv.server_address[1]}/authorize?x=1"
        p = subprocess.Popen([str(prog), url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             env={"PATH": "/usr/bin:/bin", "NO_PROXY": "*"})
        time.sleep(1.0)
        assert hits == [] and p.poll() is None, hits
        Path(str(modef) + ".go").write_text("")
        assert p.wait(30) == 0
        steps = HO.opened(log)
        assert hits == ["/authorize?x=1"] and steps[0]["url"] == url, (hits, steps)
        assert [s.get("step") for s in steps[1:]] == ["go", "follow"] and steps[1]["seen"] is True
        assert steps[2]["status"] == 200, steps
    finally:
        srv.shutdown()
        srv.server_close()
        th.join(5)
        shutil.rmtree(base, ignore_errors=True)


def test_ckoff_needs_the_full_context_and_no_job_lines():
    """The install acceptance's "ckoff" (PLAN-0.11 §9.4): Claude's request
    must hold the full context (HOWTO_MARK, a how-to line even the cut
    context keeps) and no checkpoint job lines. A cold session's not-ready
    context (launch.sh) has neither, so it fails: it would prove nothing."""
    assert any(L.HOWTO_MARK in h for h in hooks_session.HOWTO)
    launch = (H.PLUGIN / "hooks" / "launch.sh").read_text()
    m = re.search(r"^not_ready_context\(\) \{\n(.*?)^\}", launch, re.M | re.S)
    assert m and "Gateway (plugin)" in m.group(1) and L.HOWTO_MARK not in m.group(1)
    ok, why = L.ckoff(json.dumps([m.group(1)]))
    assert ok is False and "full context" in why, why
    with H.gateway_env() as env:
        form, eff, _data = hooks_session.prepare([], write=False)
        assert L.ckoff(json.dumps([hooks_session.context_text(form, eff, {})])) == (True, "")
        paths.checkpoint_seen_path().write_text("")          # gated served checkpoint just now
        ok, why = L.ckoff(json.dumps([hooks_session.context_text(form, eff, {})]))
        assert ok is False and "job lines" in why, why
        env.write_form("".join(f'[hosts.host-number-{i:03d}]\naddress = "h{i}.example.com"\n'
                               for i in range(120)))
        vault.save(vault.empty())
        consent.approve_all(env.form())
        form, eff, _data = hooks_session.prepare([], write=False)
        cut = hooks_session.context_text(form, eff, {})
        assert len(cut) <= hooks_session.CONTEXT_MAX and "more" in cut and L.HOWTO_MARK in cut, cut[-400:]


def test_run_if_fake_runs_sudo_only_when_it_is_the_fake():
    """run_if_fake (the terminals acceptance's own-sudo step): the line runs
    its command only where `sudo` resolves to the fake (a path with a
    space too); with another sudo first on PATH, or none, it runs the other
    branch and never that sudo. The line itself, typed into a gateway
    terminal while nothing configures this computer's sudo, gets no
    decision from the approval hook."""
    base = _tmp("gwrf-")
    try:
        fake_dir, other_dir = base / "user bin", base / "other"
        for d, word in ((fake_dir, "FAKE"), (other_dir, "OTHER")):
            d.mkdir()
            (d / "sudo").write_text(f'#!/bin/sh\necho {word}-SUDO-RAN "$@"\n')
            os.chmod(d / "sudo", 0o755)
        line = L.run_if_fake(str(fake_dir / "sudo"), "sudo -v && echo OK", 'echo "NOT""-THE-FAKE"')

        def run(path: str) -> str:
            return subprocess.run(["/bin/sh", "-c", line], env={"PATH": path}, capture_output=True,
                                  text=True, timeout=30).stdout
        assert run(f"{fake_dir}:{other_dir}:/usr/bin:/bin") == "FAKE-SUDO-RAN -v\nOK\n"
        assert run(f"{other_dir}:{fake_dir}:/usr/bin:/bin") == "NOT-THE-FAKE\n"
        assert run("/usr/bin:/bin") == "NOT-THE-FAKE\n"       # the system's sudo (if any) never runs
        try:
            L.run_if_fake("user-bin/sudo", "true", "true")
            raise AssertionError("a relative path was taken")
        except ValueError:
            pass
        with H.gateway_env() as env:
            (env.root / "project").mkdir()
            for text in (line, L.run_if_fake(str(fake_dir / "sudo"), 'echo "SUDO""-IS-FAKE"',
                                             'echo "SUDO""-IS-OTHER $(command -v sudo)"')):
                p = {"tool_name": hooks_bash.GW_SEND_TOOL, "permission_mode": "bypassPermissions",
                     "tool_input": {"id": "t_0123456789", "seq": 1, "text": text, "enter": True},
                     "cwd": str(env.root / "project")}
                out = (hooks_bash.main(p) or {}).get("hookSpecificOutput") or {}
                assert "permissionDecision" not in out, (text, out)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_the_opener_scan_expects_only_gateds_browser_sign_in():
    """The native UI acceptance's static scan (invariant 4): a code line that
    starts a program or calls a browser opener is a call; the one expected is
    gated's own open_browser call in daemon/oauth.py (the browser sign-in,
    after the person pressed Open). The same call in another file or plugin,
    or a line there that starts a program, is not; definitions, comments,
    docs and tests are never calls. Over the shipped gateway code: that one,
    and no other."""
    rel = L.EXPECTED_OPENER[1]
    hits = (L.opener_hits("gate", rel, "def open_browser(url, env):\n    pass\n\n    open_browser(url, env)\n"
                          "    subprocess.run(['xdg-open', url])\n# xdg-open: never run by name\n"
                          "    subprocess.Popen(argv) or open_browser(url, env)\n")
            + L.opener_hits("gate", "src/gateway/other.py", "    oauth.open_browser(url, env)\n"
                            "    launch_browser(url)\n")
            + L.opener_hits("check", rel, "    open_browser(url, env)\n")
            + L.opener_hits("gate", "tests/x.py", "subprocess.run(['xdg-open', u])\n")
            + L.opener_hits("gate", "docs/x.md", "open_browser(url)\n"))
    expected, other = L.opener_calls(hits)
    assert {(h["plugin"], h["file"], h["line"]) for h in expected} == {("gate", rel, 4)}, expected
    assert {(h["plugin"], h["file"], h["line"]) for h in other} == {
        ("gate", rel, 5), ("gate", rel, 7), ("gate", "src/gateway/other.py", 1),
        ("gate", "src/gateway/other.py", 2), ("check", rel, 1)}, other
    shipped = [H.PLUGIN / "run.py", H.PLUGIN / ".mcp.json"] + [
        p for d in ("src", "hooks", "commands", "skills") for p in sorted((H.PLUGIN / d).rglob("*"))
        if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"]
    hits = []
    for p in shipped:
        hits += L.opener_hits("gate", str(p.relative_to(H.PLUGIN)), p.read_text(errors="replace"))
    expected, other = L.opener_calls(hits)
    assert expected and {h["file"] for h in expected} == {rel}, expected
    assert other == [], other


def test_the_no_mods_probes_reach_the_hook_and_run_no_real_tool():
    """acceptance_managed's nomods probes (PLAN-0.11 §1.8, §13): every program
    they run is echo (never the system's ssh); without the prefix each gets
    the gateway's notice once per session, no refusal; and with it (where
    pre_bash.sh's word list decides alone) each still reaches Python."""
    import test_hookbash_prefilter as PF
    from gateway import bashparse
    c = _script_consts("acceptance_managed.py", "NOMODS_FIRST", "NOMODS_SECOND")
    for cmd in c.values():
        progs = [st[0] for seg in (bashparse.parse(cmd) or []) for st in seg if st]
        assert progs and set(progs) == {"echo"}, (cmd, progs)
    assert "ssh -V" not in _script_src("acceptance_managed.py")
    keep = os.environ.pop("CLAUDE_CODE_SHELL_PREFIX", None)
    try:
        with H.gateway_env():
            for i, cmd in enumerate(c.values()):
                p = {"tool_name": "Bash", "tool_input": {"command": cmd}, "session_id": f"nm{i}",
                     "permission_mode": "bypassPermissions"}
                out = hooks_bash.main(p)
                assert set(out or {}) == {"systemMessage"} and L.MANAGED_NOTICE in out["systemMessage"], out
                assert hooks_bash.main(p) is None, "once per session"
    finally:
        if keep is not None:
            os.environ["CLAUDE_CODE_SHELL_PREFIX"] = keep
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as td:
        pre, marker = PF._rig(Path(td) / "rig")
        for cmd in c.values():
            marker.unlink(missing_ok=True)
            PF._run(pre, cmd)
            assert marker.exists(), f"pre_bash.sh kept {cmd!r} from Python"


def test_claude_md_names_each_acceptances_parts_as_the_script_does():
    """CLAUDE.md's Commands block lists the `--only` parts of the install,
    managed and native_ui acceptances: exactly the parts each script runs
    (its default list, or every name its `want(...)` checks), so a part
    added to a script shows up there (WS-9). VM-only and --import-from parts
    are described in prose, not listed."""
    doc = H.PLUGIN.parents[1] / "CLAUDE.md"
    if not doc.is_file():
        print("  note: no CLAUDE.md next to this plugin copy; not checked")
        return
    text = doc.read_text()
    extra = {"vmplain", "vmdrain", "import-remote"}
    for script in ("acceptance_install", "acceptance_managed", "acceptance_native_ui"):
        m = re.search(rf"tests/{script}\.py [^\n]*\[--only ([a-z,_-]+)\]", text)
        assert m, script
        listed = m.group(1).split(",")
        src = (H.PLUGIN / "tests" / f"{script}.py").read_text()
        ran = set(re.findall(r'want\("([a-z_-]+)"\)', src)) | set(re.findall(r'"([a-z_-]+)" (?:not )?in only', src))
        assert ran and set(listed) == ran - extra, (script, sorted(set(listed) ^ (ran - extra)))
        d = re.search(r'add_argument\("--only", default="([a-z,_-]*)"\)', src) or \
            re.search(r'^PARTS = "([a-z,_-]+)"', src, re.M)
        if d and d.group(1):
            assert d.group(1).split(",") == listed, (script, d.group(1))


def test_testing_md_names_no_pixi_version_the_relock_would_leave_behind():
    """`pixi run update-deps` rewrites the requires-pixi quote only in its
    DOCS; TESTING.md isn't one, so it states the requirement without a
    version (a pinned `pixi==X` workaround went stale at the next relock)."""
    import update_deps
    doc = H.PLUGIN.parents[1] / "docs" / "dev" / "TESTING.md"
    if not doc.is_file():
        print("  note: no docs/dev/TESTING.md next to this plugin copy; not checked")
        return
    assert "docs/dev/TESTING.md" not in update_deps.DOCS
    text = doc.read_text()
    bad = re.findall(r"pixi==\d[\w.]*|pixi \d+\.\d+(?:\.\d+)? or newer|requires-pixi = \">=", text)
    assert not bad and "requires-pixi" in text and "pixi self-update" in text, bad


def test_the_acceptances_keep_the_reviews_fixes():
    """Defects a live run would hit, which the suite can't run (WS-7t's
    review): each check reads only what its own session made, can fail, and
    runs nothing real.
    - install: the notice's "once" reads each session's own transcripts; ckoff
      looks at a warm session's full context; the cold network ask runs in
      the old-pixi session (the cold part's slow start stays before its kill);
    - terminals: the user's own sudo line runs only for the fake; the vault
      passphrase offer after askright's stored key is answered;
    - canaries: the webfetch step quotes a key of its own, left out of the
      scans that see a tool's raw result;
    - managed: a bash-snapshot session, and the summary has the shells;
    - native UI: the scan's call rule is acceptance_lib's."""
    notice = _function_src("acceptance_install.py", "part_notice")
    assert "L.new_files(s.transcripts(), before)" in notice and "for t in s.transcripts()" not in notice
    assert "L.ckoff(body)" in _function_src("acceptance_install.py", "part_firstbash")
    assert "cold_network_step(" not in _function_src("acceptance_install.py", "part_cold")
    assert "cold_network_step(s, " in _function_src("acceptance_install.py", "part_oldpixi")
    own = _function_src("acceptance_terminals.py", "step_own_sudo")
    assert own.count("L.run_if_fake(fake, ") == 2 and "\"text\": 'sudo" not in own and "return" in own
    ask = _function_src("acceptance_terminals.py", "step_ask_rights")
    assert "wait(s, lambda: L.OFFER_TITLE in screen(s), 60)" in ask
    assert "press(s, drawn if drawn in screen(s) else L.OFFER_NOT_NOW" in ask
    run = _function_src("acceptance_canaries.py", "run")
    assert 'step_webfetch(s, site, C["webfetch-key"])' in run and 'step_webfetch(s, site, C["service-key"])' not in run
    sc = _function_src("acceptance_canaries.py", "scans")
    assert 'raw = [C["webfetch-key"]]' in sc and sc.count("not_raw(") == 3, sc
    assert '"webfetch-key"' in _function_src("acceptance_canaries.py", "main")
    snap = _function_src("acceptance_managed.py", "step_bash_snapshot")
    assert 'shell="/bin/bash"' in snap and "L.snapshot_shells(cfg, skip=before)" in snap
    assert "step_bash_snapshot(" in _function_src("acceptance_managed.py", "run")
    assert "**SUMMARY}" in _function_src("acceptance_managed.py", "main")
    assert "L.opener_calls(hits)" in _function_src("acceptance_native_ui.py", "static_scan")


class _Clock:
    """acceptance_lib's time while a test runs: pump and sleep move it on,
    so a wait that never holds ends at once."""

    def __init__(self) -> None:
        self.now = 0.0

    def monotonic(self) -> float:
        return self.now

    def sleep(self, t: float) -> None:
        self.now += t


class _Pane:
    """A session typing into a pane's field, as acceptance_lib drives it
    (send, type, key, pump): keys reach the field once `focus_after` clicks
    were made (or, with `focus_at`, from that time on), else the prompt box;
    keystroke numbers in `drop` are lost, those in `double` arrive twice,
    and those in `late` are drawn `delay` seconds after they were pressed
    (the keys after one wait behind it: keys stay in order). With `rate`,
    a slow screen draws at most that many keys per pump. `hint` is drawn
    while the field is empty (an Input's placeholder); the screen also has
    3 bullets of its own."""

    def __init__(self, clock: _Clock, focus_after: int = 1, drop=(), double=(), hint: str = "",
                 focus_at: float | None = None, late=(), delay: float = 0.0,
                 rate: int | None = None) -> None:
        self.clock, self.focus_after, self.hint, self.focus_at = clock, focus_after, hint, focus_at
        self.drop, self.double, self.late = set(drop), set(double), set(late)
        self.delay, self.rate = delay, rate
        self.field = self.prompt = ""
        self.clicks = self.keys = 0
        self.queue: list[tuple[float, str, str]] = []     # (when it is drawn, where, key)

    def click(self) -> None:
        self.clicks += 1

    def _focused(self) -> bool:
        if self.focus_at is not None:
            return self.clock.now >= self.focus_at
        return self.clicks >= self.focus_after

    def _press(self, ch: str) -> None:
        self.keys += 1
        if self.keys in self.drop:
            return
        into = "field" if self._focused() else "prompt"
        due = self.clock.now + (self.delay if self.keys in self.late else 0.0)
        if self.queue:
            due = max(due, self.queue[-1][0])
        self.queue += [(due, into, ch)] * (2 if self.keys in self.double else 1)
        if self.rate is None:
            self._draw()

    def _draw(self, most: int | None = None) -> None:
        drawn = 0
        while self.queue and self.queue[0][0] <= self.clock.now and (most is None or drawn < most):
            _due, into, ch = self.queue.pop(0)
            text = getattr(self, into)
            setattr(self, into, text[:-1] if ch == "\b" else text + ch)
            drawn += 1

    def send(self, data: str) -> None:
        for ch in data:
            self._press(ch)

    def type(self, text: str, delay: float = 0.02) -> None:
        self.send(text)

    def key(self, name: str, repeat: int = 1, settle: float = 0.1) -> None:
        assert name == "backspace", name
        for _ in range(repeat):
            self._press("\b")

    def pump(self, t: float = 0.2) -> int:
        self.clock.now += t
        self._draw(self.rate)
        return 0

    def finish(self) -> None:
        """Draw every key still on its way."""
        while self.queue:
            self.pump(1.0)

    def bullets(self) -> int:
        return 3 + len(self.field)

    def screen(self) -> str:
        return f"line: {self.field or self.hint}"


def _with_clock(fn):
    clock, saved = _Clock(), L.time
    L.time = clock
    try:
        return fn(clock)
    finally:
        L.time = saved


def test_the_private_field_takes_a_value_only_once_it_shows_it_whole():
    """vm-tui 4: focus_field said yes without checking that its Backspace
    took the probe "x" away again, and nothing compared the field's bullets
    with the value before Enter, so a lost or doubled key sent a wrong
    password (three "Sorry, try again" and a cascade). Now the probe must be
    gone, and the value shows one bullet per character before Enter (else
    it is emptied and typed again, or the dialog isn't submitted)."""
    value = "correct-horse-battery"

    def run(clock: _Clock) -> None:
        p = _Pane(clock, drop={2})                  # the first Backspace is lost
        assert L.focus_private_field(p, p.click, p.bullets) == 3 and p.field == ""
        p = _Pane(clock, focus_after=3)             # two clicks before the field has the keys
        assert L.focus_private_field(p, p.click, p.bullets) == 3 and p.field == "" and p.clicks == 3
        assert p.prompt == "", "the probes that missed went to the prompt box and were taken back"
        p = _Pane(clock, drop={2, 3, 4})            # the probe can't be taken back: no
        assert L.focus_private_field(p, p.click, p.bullets) is None and p.field == "x"

        def missing():
            raise LookupError("not drawn")
        assert L.focus_private_field(p, missing, p.bullets) is None
        for drop, double in (({5}, ()), ((), {7}), ((), ())):
            p = _Pane(clock, drop=drop, double=double)
            p.click()
            assert L.type_private(p, value, p.bullets, 3) and p.field == value, (drop, double, p.field)
        p = _Pane(clock, drop=set(range(1, 200, 3)))  # it never shows whole: no
        p.click()
        assert not L.type_private(p, value, p.bullets, 3) and p.field != value
    _with_clock(run)
    src = _function_src("acceptance_terminals.py", "focus_field")
    assert "L.focus_private_field(" in src
    assert "L.type_private(" in _function_src("acceptance_terminals.py", "type_secret")
    for step, canary in (("steps", "canary.value"), ("step_own_sudo", "own_canary.value")):
        body = _function_src("acceptance_terminals.py", step)
        assert f"type_secret(s, {canary}, empty)" in body and f"s.type({canary})" not in body, step
        assert body.index("empty = focus_field(s)") < body.index(f"type_secret(s, {canary}, empty)"), step
        typed = body.index(f"type_secret(s, {canary}, empty)")
        assert body.index('s.key("enter")', typed) < body.index('press(s, "[ Cancel ]"', typed), step
    assert "L.focus_private_field(" in _function_src("acceptance_dialogs.py", "focus_field")
    native = _function_src("acceptance_native_ui.py", "type_secret")
    assert "L.type_private(" in native and "s.type(" not in native
    assert native.index("L.type_private(") < native.index('s.key("enter")')
    assert L.FIELD_HINT in (MOD / "field.tsx").read_text()
    assert _script_consts("acceptance_terminals.py", "FIELD")["FIELD"] == L.FIELD_HINT


def test_a_probe_drawn_late_never_goes_out_with_the_value():
    """WS-11b review: a probe "x" drawn only after focus_private_field's
    2 s wait stayed in the field (the next try counted it in its baseline),
    and type_private, measuring its own baseline, passed "x" + the value,
    so Enter would send a wrong password on a loaded machine. Now a probe
    not seen in time is taken back with a Backspace, the value is checked
    against the field's empty count from before the first probe, and only
    a count that stays put counts (one a slow screen passes through on its
    way to another doesn't)."""
    value = "correct-horse-battery"

    def run(clock: _Clock) -> None:
        for delay in (2.1, 2.5, 3.0):               # the first key drawn after the wait
            p = _Pane(clock, late={1}, delay=delay)
            empty = L.focus_private_field(p, p.click, p.bullets)
            p.finish()
            assert empty == 3 and p.field == "", (delay, empty, p.field)
            assert L.type_private(p, value, p.bullets, empty), delay
            p.finish()
            assert p.field == value, (delay, p.field)
        # the Backspace that takes the late probe back is lost: the probe is
        # still there, so the value is typed again after emptying the field
        p = _Pane(clock, late={1}, delay=2.1, drop={2})
        empty = L.focus_private_field(p, p.click, p.bullets)
        assert empty == 3, empty
        assert L.type_private(p, value, p.bullets, empty)
        p.finish()
        assert p.field == value, p.field
        # a slow screen draws one key per look: with a key left in the field
        # the count passes the value's length on its way to one more
        p = _Pane(clock, rate=1)
        p.click()
        p.send("x")
        p.finish()
        assert L.type_private(p, value, p.bullets, 3)
        p.finish()
        assert p.field == value, p.field
    _with_clock(run)


def test_the_main_screens_line_field_is_typed_into_only_once_it_has_the_keys():
    """vm-tui 5: mainscr typed its line as soon as the pane was drawn, and
    the keys went to the prompt box. Now a probe key must replace the line
    field's placeholder (then Backspace bring it back) before the line is
    typed; a probe that went to the prompt box is taken back."""
    def run(clock: _Clock) -> None:
        p = _Pane(clock, hint=L.LINE_FIELD_HINT, focus_at=2.0)   # drawn now, the keys 2 s later
        assert L.focus_line_field(p, p.screen) and p.field == "" and p.prompt == ""
        assert p.keys > 2, "the first probe went to the prompt box and was taken back"
        p = _Pane(clock, hint=L.LINE_FIELD_HINT, focus_at=1e9)
        assert not L.focus_line_field(p, p.screen) and p.prompt == ""
        assert not L.focus_line_field(_Pane(clock, hint="other"), lambda: "nothing drawn")
    _with_clock(run)
    reg = (MOD / "register.tsx").read_text()
    assert re.search(r'<Input key="line" label="line" placeholder="' + re.escape(L.LINE_FIELD_HINT), reg)
    main = _function_src("acceptance_terminals.py", "step_main_screen")
    assert main.index("L.focus_line_field(s, ") < main.index("s.type('echo \"FROM\"\"-MAIN-SCREEN\"')")
    assert "if keys:" in main
    # Enter only once the field shows the whole typed line (WS-11b review)
    typed = main.index("typed = wait(s, ")
    assert main.index("s.type('echo") < typed < main.index("if typed:") < main.index('s.key("enter")')
    assert main.count('s.key("enter")') == 1 and "reached = typed and " in main


def test_the_uninstall_journal_check_asks_only_that_every_earlier_record_stays():
    """mac-tui F: the journal was counted, the plugin uninstalled, and the
    count compared again, while the session that had just closed still
    flushed a segment (one more record: a false failure). Now the journal is
    read once it stopped changing, and afterwards each of those records must
    still be there (more may come)."""
    def run(clock: _Clock) -> None:
        recs = [{"kind": "session.start", "n": 1}]
        late = [{"kind": "session.end", "n": 2}]

        def read() -> list:            # one more record a second after the first look
            return recs + (late if clock.now >= 1.0 else [])
        got = L.settled(read, quiet=3.0, timeout=30.0)
        assert got == recs + late and clock.now >= 4.0, (got, clock.now)
        clock.now = 0.0
        busy = L.settled(lambda: [{"n": clock.now}], quiet=3.0, timeout=10.0)
        assert clock.now >= 10.0 and busy, "a journal that never settles: what it holds at the timeout"
    _with_clock(run)
    a, b, c = {"n": 1, "x": [1]}, {"x": [1], "n": 1}, {"n": 2}
    assert L.kept([a], [c, b]) and L.kept([a, c], [c, a, {"n": 3}]) and L.kept([], [a])
    assert not L.kept([a, c], [a]) and not L.kept([a, a], [a]), "a record lost (or one of two alike)"
    body = _function_src("acceptance_install.py", "part_uninstall")
    assert "before = L.settled(lambda: journal(home))" in body
    assert "L.kept(before, after)" in body and "len(journal(home)) == n_recs" not in body
    assert body.index("L.settled(") < body.index("h.inst.uninstall(pid, check=False)")
