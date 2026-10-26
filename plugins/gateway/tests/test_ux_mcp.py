"""mcp_server.py (JSON-RPC: initialize, tools/list with alwaysLoad meta,
ping, threaded tools/call with a locked writer) and hooks/mcp_perm.sh."""
from __future__ import annotations

import io
import json
import threading
import time

import harness as H
import harness_ux as U
from gateway import mcp_server


def _run(msgs, tool=None, workers=4) -> list[dict]:
    src = io.StringIO("\n".join(json.dumps(m) if not isinstance(m, str) else m for m in msgs) + "\n")
    out = io.StringIO()
    mcp_server.Server(src, out, tool=tool, workers=workers).serve()
    return [json.loads(l) for l in out.getvalue().splitlines()]


def test_initialize_negotiates_and_lists_the_always_loaded_tools():
    out = _run([{"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": "2025-03-26", "capabilities": {}}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "ping"},
                {"jsonrpc": "2.0", "id": 4, "method": "resources/list"},
                "not json",
                "[]",
                "42",
                {"jsonrpc": "2.0", "id": 5, "method": "initialize",
                 "params": {"protocolVersion": "1999-01-01"}}])
    by = {o["id"]: o for o in out if o.get("id") is not None}
    assert sorted(by) == [1, 2, 3, 4, 5], "notifications get no answer"
    junk = [o["error"]["code"] for o in out if o.get("id") is None]
    assert junk == [-32700, -32600, -32600], "a line that isn't JSON: parse error; not a request: invalid"
    assert by[1]["result"]["protocolVersion"] == "2025-03-26"
    assert by[5]["result"]["protocolVersion"] == mcp_server.PROTOCOL_VERSION
    assert by[1]["result"]["serverInfo"]["name"] == "gw" and "tools" in by[1]["result"]["capabilities"]
    tools = by[2]["result"]["tools"]
    assert [t["name"] for t in tools] == ["http", "download", "host_inspect", "terminal_open", "terminal_read", "terminal_send", "terminal_resize", "terminal_signal", "terminal_close", "terminal_list", "job_start", "job_status", "job_tail", "job_signal", "job_list", "host_runtime"]
    assert all(t["_meta"] == {"anthropic/alwaysLoad": True} for t in tools)
    assert tools[0]["inputSchema"]["required"] == ["url"]
    assert by[3]["result"] == {} and by[4]["error"]["code"] == -32601


def test_tools_run_on_threads_and_lines_never_interleave():
    started = threading.Event()

    def tool(name, args):
        if args.get("slow"):
            started.set()
            time.sleep(0.6)
        return {"ok": True, "name": name, "pad": "x" * 20000, "n": args.get("n")}
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "http", "arguments": {"slow": True, "n": 1}}}]
    msgs += [{"jsonrpc": "2.0", "id": i, "method": "tools/call",
              "params": {"name": "download", "arguments": {"n": i}}} for i in range(2, 12)]
    msgs.append({"jsonrpc": "2.0", "id": 99, "method": "ping"})
    out = _run(msgs, tool=tool, workers=6)
    ids = [o["id"] for o in out]
    assert sorted(ids) == sorted([1, *range(2, 12), 99])
    assert ids.index(99) < ids.index(1) and ids.index(2) < ids.index(1), "a slow call doesn't block others"
    for o in out:
        if o["id"] != 99:
            body = json.loads(o["result"]["content"][0]["text"])
            assert body["ok"] and o["result"]["isError"] is False


def test_tool_errors_carry_no_exception_text():
    def boom(name, args):
        raise RuntimeError("secret detail /Users/x/.config/gateway/private/key.txt")
    out = _run([{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "http", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "nope", "arguments": {}}},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {}}], tool=boom)
    by = {o["id"]: o for o in out}
    text = by[1]["result"]["content"][0]["text"]
    assert by[1]["result"]["isError"] and "RuntimeError" in text and "private" not in text
    assert by[3]["error"]["code"] == -32602
    real = mcp_server.handle({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                              "params": {"name": "nope", "arguments": {}}})
    assert real["result"]["isError"] and "unknown tool" in real["result"]["content"][0]["text"]


def test_mcp_through_run_py_with_a_real_http_call():
    routes = {"/hello": (200, {"Content-Type": "text/plain"}, "hello from test")}
    with H.gateway_env() as env, U.servers(routes) as (a,):
        msgs = [{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18"}},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
                {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                 "params": {"name": "http", "arguments": {"url": a.url("/hello")}}}]
        r = H.run_py(env, "--test", "mcp", timeout=60, input_text="\n".join(json.dumps(m) for m in msgs) + "\n")
        assert r.returncode == 0, r.stderr
        out = {o["id"]: o for o in (json.loads(l) for l in r.stdout.splitlines())}
        assert [t["name"] for t in out[2]["result"]["tools"]] == ["http", "download", "host_inspect", "terminal_open", "terminal_read", "terminal_send", "terminal_resize", "terminal_signal", "terminal_close", "terminal_list", "job_start", "job_status", "job_tail", "job_signal", "job_list", "host_runtime"]
        body = json.loads(out[3]["result"]["content"][0]["text"])
        assert body["ok"] and body["body"] == "hello from test"


# ---------------------------------------------------------------------------
# hooks/mcp_perm.sh
# ---------------------------------------------------------------------------

GW = "mcp__plugin_gate_gw__"
HTTP = GW + "http"
DL = GW + "download"


def _decide(env, payload) -> str | None:
    r = U.run_sh(env, "mcp_perm.sh", payload, test=True)
    assert r.returncode == 0, r.stderr
    if not r.stdout.strip():
        return None
    return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"]


def _p(tool, tin) -> dict:
    return {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tin,
            "cwd": "/x"}


def test_mcp_perm_decisions():
    """GW-SEC-1 / GW-UX-3, PLAN-0.11 §2.10: with no network policy the hook
    gives no decision for the http and download tools, in any mode, for any
    method, with or without an account (a request can carry project data
    out, a download fetches anything, and an account's credential reaches
    its service), so Claude Code's own mode decides: a prompt in default and
    plan mode, the reviewer in auto. mcp_perm.sh hands them to Python
    (hooks_mcp, which runs here: a ready env, --test), never allowing from
    sh. Only top-level keys decide the tools it does allow."""
    with H.gateway_env() as env:
        U.fake_ready_env(env)
        never = [
            _p(DL, {"url": "https://x.example.com/f.tgz"}),
            _p(DL, {"url": "https://x.example.com/payload.sh", "account": "pkg", "save_to": "a/b"}),
            _p(HTTP, {"url": "https://x.example.com/"}),
            _p(HTTP, {"url": "https://x.example.com/?d=PROJECTDATA", "method": "GET"}),
            _p(HTTP, {"url": "https://x.example.com/", "method": "head"}),
            _p(HTTP, {"url": "https://x.example.com/", "method": "get", "account": "openai"}),
            _p(HTTP, {"url": "https://api.openai.com/v1/x", "method": "POST", "account": "openai",
                      "json": {"q": 1}}),
            _p(HTTP, {"url": "https://api.github.com/repos/o/r", "method": "DELETE",
                      "account": "github-work"}),
            _p(HTTP, {"url": "https://x.example.com/", "headers": {"method": "POST"}}),
            _p(HTTP, {"url": "https://x.example.com/", "method": "POST", "body": "data"}),
            _p(HTTP, {"url": "https://x.example.com/", "method": "PUT", "json": {"account": "openai"}}),
            _p(HTTP, {"url": "https://x.example.com/", "method": "POST", "account": ""}),
            _p(HTTP, {"url": "https://x.example.com/", "method": ["GET"]}),
            _p("mcp__plugin_other_gw__http", {"url": "https://x.example.com/"}),
            _p("Bash", {"command": "curl x"}),
            {"tool_name": HTTP, "tool_input": {"method": "POST", "account": "x"},
             "extra": {"tool_name": DL}},
        ]
        for mode in (None, "default", "plan", "acceptEdits", "auto", "bypassPermissions", "dontAsk"):
            for p in never:
                q = dict(p, permission_mode=mode) if mode else p
                assert _decide(env, q) is None, (mode, p)
        # Python did decide (a deny through the same path proves it ran)
        env.write_form('[policy]\nnetwork = "deny"\n')
        assert _decide(env, _p(HTTP, {"url": "https://x.example.com/"})) == "deny"
        env.write_form("")
        # pretty-printed payloads (newlines, spaces) decide the same
        pretty = json.dumps(_p(HTTP, {"url": "u", "method": "POST", "account": "openai"}), indent=2)
        assert _decide(env, pretty) is None
        pretty = json.dumps(_p(GW + "terminal_read", {"id": "t_x"}), indent=2)
        assert _decide(env, pretty) == "allow"
        # only the top-level tool_name counts: one nested in the input (after the
        # real one) or elsewhere (before it) never decides
        send = GW + "terminal_send"
        tricky = json.dumps({"tool_name": send, "tool_input": {
            "id": "t_x", "text": "id\n", "meta": {"tool_name": GW + "terminal_read"}}})
        assert _decide(env, tricky) is None
        tricky = '{"tool_input": {"url": "u"}, "x": {"tool_name": "%s"}, "tool_name": "%s"}' % (
            GW + "host_inspect", HTTP)
        assert _decide(env, tricky) is None
        assert _decide(env, _p(GW + "host_inspect", {})) == "allow"
        assert _decide(env, "garbage {") is None


def test_claude_facing_texts_dont_promise_web_tools_without_a_prompt():
    """GW-SEC-1 / GW-UX-3 round 2: mcp_perm.sh no longer allows http or
    download, so the MCP instructions must not tell Claude they "need no
    prompt": Claude Code's own mode decides. Since PLAN-0.11 §3 curl and wget
    aren't refused (network commands are asked about), and no text Claude
    reads says they are."""
    from gateway import hooks_bash
    assert "no prompt" not in mcp_server.INSTRUCTIONS
    assert "permission mode decides" in mcp_server.INSTRUCTIONS
    with H.gateway_env():
        out = hooks_bash.main({"tool_name": "Bash", "tool_input": {"command": "curl x"},
                               "permission_mode": "auto"})
    why = out["hookSpecificOutput"]["permissionDecisionReason"]
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask", out
    assert "no prompt" not in why and "network command" in why, why


def test_this_machines_own_host_id_is_localhost_for_terminals_and_jobs():
    """PLAN-v4 phase 7 (a phase 4-6 leftover): a terminal_open / job_start
    naming this machine by its contract id (what gated's snapshot calls
    localhost) used to be taken for a remote host by the MCP server, which
    then sent neither the project folder nor the managed imports, so gated ran
    it locally with a remote host's defaults (the home folder, no imports).
    It is localhost now, exactly like "localhost"."""
    import os
    from gateway import daemon
    from gateway.daemon import client
    with H.gateway_env():
        local = daemon.local_host_id()
        assert local.startswith("m_") and daemon.is_local_host(local)
        assert daemon.is_local_host(None) and daemon.is_local_host("") and daemon.is_local_host("localhost")
        assert not daemon.is_local_host("m_" + "a" * 26) and not daemon.is_local_host("box")
        seen: list[tuple[str, dict]] = []
        real = client.term_call
        client.term_call = lambda route, body, timeout=30.0: seen.append((route, dict(body))) or {"ok": True}
        old = os.environ.get("CLAUDE_PROJECT_DIR")
        os.environ["CLAUDE_PROJECT_DIR"] = "/tmp/the-project"
        try:
            for tool in ("terminal_open", "job_start"):
                for host in (local, "localhost"):
                    seen.clear()
                    mcp_server.call_terminal(tool, {"host": host, "argv": ["true"]})
                    route, body = seen[0]
                    assert body["host"] == "localhost", body
                    assert body["cwd"] == "/tmp/the-project", body
                    assert isinstance(body.get("env"), dict), "a local pane gets the managed imports"
            seen.clear()
            mcp_server.call_terminal("terminal_open", {"host": "box"})
            body = seen[0][1]
            assert body["host"] == "box" and "cwd" not in body and "env" not in body
        finally:
            client.term_call = real
            if old is None:
                os.environ.pop("CLAUDE_PROJECT_DIR", None)
            else:
                os.environ["CLAUDE_PROJECT_DIR"] = old


def test_host_inspect_for_a_remote_host_goes_through_gated():
    from gateway.daemon import client
    with H.gateway_env():
        seen = []
        real = client.term_call
        client.term_call = lambda route, body, timeout=30.0: seen.append((route, body)) or {"ok": True}
        try:
            mcp_server.call_tool("host_inspect", {"host": "box"})
            assert seen == [("/agent/remote/inspect", {"host": "box"})], seen
            seen.clear()
            r = mcp_server.call_tool("host_inspect", {"host": "localhost"})
            assert seen == [] and r.get("host") == "localhost", r
        finally:
            client.term_call = real


# ---------------------------------------------------------------------------
# hooks_mcp.py: http and download per mode (PLAN-0.11 §2.10, lead decision 19.1)
# ---------------------------------------------------------------------------

MODES6 = ("default", "plan", "acceptEdits", "auto", "bypassPermissions", "dontAsk")


def _mcp(tool, mode, tin=None):
    from gateway import hooks_mcp
    p = {"tool_name": tool, "tool_input": tin if tin is not None else {"url": "https://x.example.com/"}}
    if mode is not None:
        p["permission_mode"] = mode
    out = hooks_mcp.main(p)
    return (None, "") if out is None else (out["hookSpecificOutput"]["permissionDecision"],
                                           out["hookSpecificOutput"]["permissionDecisionReason"])


def _approved(env, text):
    from gateway import consent, vault
    env.write_form(text)
    vault.save(vault.empty()) if not vault.exists() else None
    consent.approve_all(env.form())


def test_hooks_mcp_never_allows_by_default():
    """Nothing approved by default: no network policy, a bare "allow" (no
    restriction) or a bare "cc" give no decision in every mode, for both tools
    and any spelling of the mode; a bare deny or ask is that word in every
    mode."""
    with H.gateway_env() as env:
        for text in ("", '[policy]\nnetwork = "allow"\n', '[hosts.localhost.policy]\nnetwork = "allow"\n',
                     '[policy]\nnetwork = "cc"\n'):
            _approved(env, text)
            for tool in (HTTP, DL):
                for mode in MODES6 + (None, "manual", "yolo"):
                    assert _mcp(tool, mode)[0] is None, (text, tool, mode)
        _approved(env, '[policy]\nnetwork = "ask"\n')
        for mode in MODES6 + (None,):
            d, why = _mcp(HTTP, mode)
            assert d == "ask" and '"ask"' in why and "[policy] network" in why, (mode, why)
        _approved(env, '[hosts.localhost.policy]\nnetwork = "deny"\n')
        for mode in MODES6:
            d, why = _mcp(DL, mode)
            assert d == "deny" and why.startswith("gateway: the download tool's requests") and \
                "[hosts.localhost.policy] network" in why, (mode, why)
        # other tools are mcp_perm.sh's own; a broken input gets nothing
        assert _mcp(GW + "host_inspect", "auto")[0] is None
        assert _mcp(HTTP, "auto", tin="not a dict")[0] is None


def test_hooks_mcp_honours_an_explicit_per_mode_allow_only_in_its_mode():
    """Lead decision 19.1: the user's explicit per-mode allow of the network
    policy (a table's, approved in the consent dialog) makes the hook allow
    in that mode only; plan never; a table still waiting for the OK, a mode
    the payload doesn't name and a call with an account get no decision."""
    with H.gateway_env() as env:
        for where in ("[policy]", "[hosts.localhost.policy]"):
            _approved(env, f'{where}\nnetwork = {{ default = "ask", auto = "allow", dontAsk = "deny" }}\n')
            got = {m: _mcp(HTTP, m)[0] for m in MODES6}
            assert got == {"default": "ask", "plan": "ask", "acceptEdits": "ask", "auto": "allow",
                           "bypassPermissions": "ask", "dontAsk": "deny"}, (where, got)
            d, why = _mcp(DL, "auto")
            assert d == "allow" and f"{where} network allows the download tool in Auto mode" in why, why
            for mode in (None, "", "yolo", "bypass"):
                assert _mcp(HTTP, mode)[0] == "ask", mode          # default's word, never allow
            # with an account: never approved here (an account's use has no
            # allow shape); the network policy's deny and ask still hold
            assert _mcp(HTTP, "auto", {"url": "https://x.example.com/", "account": "gh"})[0] is None
            assert _mcp(DL, "dontAsk", {"url": "https://x.example.com/", "account": ""})[0] == "deny"
            assert _mcp(DL, "default", {"url": "https://x.example.com/", "account": "gh"})[0] == "ask"
        _approved(env, '[policy]\nnetwork = { default = "allow" }\n')
        assert [_mcp(HTTP, m)[0] for m in MODES6] == ["allow", None, "allow", "allow", "allow", "allow"]
        assert _mcp(HTTP, "manual")[0] == "allow" and _mcp(HTTP, None)[0] is None
        # gateway.toml's own spelling isn't a payload string: never allowed
        assert _mcp(HTTP, "bypass")[0] is None
        # raised again in the form: waits for the OK (the approved word applies)
        from gateway import consent
        _approved(env, '[policy]\nnetwork = "allow"\n')
        env.write_form('[policy]\nnetwork = { default = "allow" }\n')
        assert [_mcp(HTTP, m)[0] for m in MODES6] == [None] * 6
        consent.approve_all(env.form())
        assert _mcp(HTTP, "default")[0] == "allow"


def test_hook_mcp_is_a_hook_mode_gated_knows():
    """hooks_mcp records the session's mode in gated like the Bash hook: gated
    takes a record only from an entry point it knows as a hook (peers'
    HOOK_MODES, planes' "hook-" modes), so every run.py hook mode, hook-mcp
    included, is one."""
    import run as runmod
    from gateway.daemon import peers, planes
    assert runmod.HOOKS["hook-mcp"] == ("hooks_mcp", "main", "open")    # fails open
    assert set(runmod.HOOKS) <= set(peers.HOOK_MODES), set(runmod.HOOKS) - set(peers.HOOK_MODES)
    assert planes.mode_allowed("hook-mcp", planes.MODE_RECORD_MODES)


def test_mcp_perm_hands_http_and_download_to_python_and_passes_its_answer():
    """mcp_perm.sh starts Python (launch.sh hook-mcp) only for the http and
    download tools, by their top-level tool_name, with --test passed on only
    for the test runner (an absolute GATEWAY_TEST_ROOT), and prints Python's
    answer as it is."""
    import os
    import subprocess
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as td:
        d = Path(td)
        (d / "mcp_perm.sh").write_text((H.PLUGIN / "hooks" / "mcp_perm.sh").read_text())
        log = d / "launched"
        (d / "launch.sh").write_text(
            "#!/bin/sh\n"
            f"printf '%s\\n' \"$*\" >> {str(log)!r}\n"
            "cat > /dev/null\n"
            "printf '%s\\n' '{\"hookSpecificOutput\": {\"hookEventName\": \"PreToolUse\", "
            "\"permissionDecision\": \"ask\", \"permissionDecisionReason\": \"sentinel\"}}'\n")
        base = {k: v for k, v in os.environ.items() if k != "GATEWAY_TEST_ROOT"}

        def run(p, *args, root=None):
            env = dict(base, **({"GATEWAY_TEST_ROOT": root} if root else {}))
            return subprocess.run(["/bin/sh", str(d / "mcp_perm.sh"), *args], input=json.dumps(p),
                                  capture_output=True, text=True, timeout=20, env=env)
        for tool in (HTTP, DL):
            r = run(_p(tool, {"url": "u"}), "--test", root=str(d))
            assert r.returncode == 0 and json.loads(r.stdout)["hookSpecificOutput"][
                "permissionDecisionReason"] == "sentinel", r
        r = run(_p(HTTP, {"url": "u"}), "--test", root="relative/root")
        r2 = run(_p(DL, {"url": "u"}))
        # invariant 7: GATEWAY_TEST_ROOT alone (absolute, no --test argument: a
        # production run with the variable set) never passes --test on
        assert run(_p(HTTP, {"url": "u"}), root=str(d)).returncode == 0
        assert log.read_text().splitlines() == ["hook-mcp --test", "hook-mcp --test", "hook-mcp",
                                                "hook-mcp", "hook-mcp"], log.read_text()
        log.unlink()
        for p in (_p(GW + "terminal_send", {"id": "t", "text": "x"}), _p("Bash", {"command": "x"}),
                  {"tool_name": GW + "terminal_send", "tool_input": {"meta": {"tool_name": HTTP}}},
                  _p(GW + "host_inspect", {})):
            r = run(p, "--test", root=str(d))
            assert r.returncode == 0 and "sentinel" not in r.stdout, p
        assert not log.exists(), "Python started for a tool sh decides"


def test_web_network_ok_reads_the_recorded_mode_and_lets_ask_through():
    """§2.10: web.py resolves this machine's network policy in the session's
    recorded mode (the modeless rule without one): only deny refuses; "ask"
    passes (hooks_mcp had Claude Code ask up front)."""
    from gateway import web
    with H.gateway_env() as env:
        _approved(env, '[policy]\nnetwork = { default = "ask", auto = "deny", dontAsk = "cc" }\n')
        web._network_ok("the http tool", "default")                  # ask: passes
        web._network_ok("the http tool", "dontAsk")
        for mode in ("auto", None):                                  # deny; modeless: deny
            try:
                web._network_ok("the http tool", mode)
            except web.Refused as e:
                assert "the http tool's requests" in e.message and "[policy] network" in e.message
            else:
                raise AssertionError(f"{mode}: not refused")
        # the recorded mode is what the tool calls use (modes.current_for("mcp"))
        real = web._mode
        try:
            web._mode = lambda: "default"
            r = web.http({"url": "http://127.0.0.1:9/"})
            assert "tool's requests" not in (r.get("error") or ""), r  # not refused by the policy
            web._mode = lambda: "auto"
            r = web.download({"url": "http://127.0.0.1:9/f.txt"}, cwd=str(env.root))
            assert not r["ok"] and "the download tool's requests" in r["error"], r
        finally:
            web._mode = real


def test_a_credential_use_is_audited_with_the_mode_it_was_decided_in():
    """§2.4: every credential use audits the mode it used (or "modeless")."""
    from gateway import paths, web
    routes = {"/x": (200, {"Content-Type": "text/plain"}, "ok")}
    with H.gateway_env(), U.servers(routes) as (a,):
        assert web.Cred(account="key").mode == "modeless"
        web._http_send(a.url("/x"), "GET", {}, None, web.Cred(account="key", mode="auto"), 10, 1000,
                       None, "127.0.0.1")
        uses = [json.loads(x) for x in paths.audit_path().read_text().splitlines()]
        uses = [u for u in uses if u.get("event") == "use"]
        assert uses and uses[-1]["mode"] == "auto" and uses[-1]["account"] == "key", uses


def test_web_reads_an_accounts_use_in_the_recorded_mode():
    """An account's `use` per mode (§2.4): the credential goes out only where
    the word in the session's recorded mode is cc or allow; an "ask" there
    still refuses (a tool call can't be asked about); the modeless rule
    without a record."""
    from gateway import vault, web
    with H.gateway_env() as env:
        _approved(env, '[accounts.key]\nkind = "api-key"\nsites = ["api.example.com"]\n'
                       'use = { default = false, auto = true, bypass = "ask" }\n')
        data = vault.load()
        data.setdefault("accounts", {})["key"] = {"token": {"value": "tok-0123456789abcdef"},
                                                  "bound": {"hosts": ["api.example.com"]}}
        vault.save(data)
        url = "https://api.example.com/v1"
        c = web.credential("key", url, mode="auto")
        assert c.headers["Authorization"].endswith("tok-0123456789abcdef") and c.mode == "auto"
        for mode, words in (("default", "is off in Manual mode"), ("bypass", '"ask" in Bypass'),
                            (None, "the strictest of its modes applies")):
            try:
                web.credential("key", url, mode=mode)
            except web.Refused as e:
                assert words in e.message, (mode, e.message)
                # the value named is gateway.toml's own, said as such
                assert "gateway.toml says use = Manual: deny" in e.message, e.message
            else:
                raise AssertionError(f"{mode}: the credential went out")
        # gateway.toml raised above what was approved: the approved word applies,
        # and the refusal says it waits for the OK (never "off ... in gateway.toml")
        env.write_form('[accounts.key]\nkind = "api-key"\nsites = ["api.example.com"]\nuse = true\n')
        try:
            web.credential("key", url, mode="default")
        except web.Refused as e:
            assert "waits for the user's OK" in e.message and "gate check key" in e.message, e.message
            assert "is off" not in e.message, e.message
        else:
            raise AssertionError("a raised use went out before the OK")


# ---------------------------------------------------------------------------
# WS-2 review fixes: the mode record from hooks_mcp, the network policy with
# an account, the modes in audit lines
# ---------------------------------------------------------------------------

ACCT = '[accounts.key]\nkind = "api-key"\nsites = ["127.0.0.1"]\nauth = "bearer"\n'


def test_hooks_mcp_records_the_payloads_mode_with_or_without_an_account():
    """§2.4: hooks_mcp records the session's mode (web.py reads it back for
    the credential's `use`) on every call, with an account or without, as
    soon as any per-mode value makes the mode matter: here only an account's
    `use` table does (with `use = { default = false, auto = true }`, a stale
    "auto" after a switch to Manual would hand the credential over). A form
    of bare words records nothing."""
    from gateway import modes
    seen: list = []
    real = modes.record
    modes.record = lambda pm, create=True: seen.append(pm) or True
    try:
        with H.gateway_env() as env:
            for text, want in ((ACCT, False), (ACCT + "use = { default = false, auto = true }\n", True)):
                _approved(env, text)
                for tin in ({"url": "http://127.0.0.1:9/"},
                            {"url": "http://127.0.0.1:9/", "account": "key"}):
                    for pm in ("auto", "default", "dontAsk"):
                        seen.clear()
                        _mcp(HTTP, pm, tin)
                        assert seen == ([pm] if want else []), (text, tin, pm, seen)
    finally:
        modes.record = real


def _key_with_token(env, extra: str = ""):
    U.setup(env, ACCT + extra)
    U.set_token("key", "api-key", "key-secret-token-0123456789")


def test_the_network_policy_holds_for_calls_with_an_account():
    """Review item 10: a network deny (this computer's, [policy]'s or the
    account's own [accounts.NAME.policy]) refuses an http or download call
    with an account too, in hooks_mcp (up front) and in web.py (after the
    credential's own checks, before anything is sent); an "ask" asks up front
    and then passes; an account's call is never approved by the hook; the
    account's own `use` stays web.py's to refuse (hooks_mcp leaves it)."""
    from gateway import web
    routes = {"/x": (200, {"Content-Type": "text/plain"}, "ok")}
    with H.gateway_env() as env, U.servers(routes) as (a,):
        proj = env.root / "proj"
        proj.mkdir()
        tin = {"url": a.url("/x"), "account": "key"}
        _key_with_token(env)
        assert _mcp(HTTP, "auto", tin)[0] is None
        assert web.http(dict(tin))["ok"], "sent without a network policy"
        for policy_text, where in (('[policy]\nnetwork = "deny"\n', "[policy] network"),
                                   ('[hosts.localhost.policy]\nnetwork = "deny"\n',
                                    "[hosts.localhost.policy] network"),
                                   ('[accounts.key.policy]\nnetwork = "deny"\n',
                                    "[accounts.key.policy] network"),
                                   ('[accounts.key.policy]\nnetwork = { default = "allow", auto = "deny" }\n',
                                    "[accounts.key.policy] network")):
            _key_with_token(env, policy_text)
            n = len(a.rec.requests)
            d, why = _mcp(HTTP, "auto", tin)
            assert d == "deny" and where in why, (policy_text, why)
            assert _mcp(DL, "auto", tin)[0] == "deny", policy_text
            old = web._mode
            web._mode = lambda: "auto"
            try:
                r = web.http(dict(tin))
                assert not r["ok"] and "the http tool's requests" in r["error"] and where in r["error"], r
                r = web.download(dict(tin), cwd=str(proj))
                assert not r["ok"] and "the download tool's requests" in r["error"], r
            finally:
                web._mode = old
            assert len(a.rec.requests) == n, "a refused call reached the server"
        # a vault alias of the account is followed, as web.py follows it
        from gateway import vault
        _key_with_token(env, '[accounts.key.policy]\nnetwork = "deny"\n')
        with vault.edit() as data:
            data.setdefault("aliases", {})["svc:main"] = "key"
        assert _mcp(HTTP, "auto", dict(tin, account="svc:main"))[0] == "deny"
        assert _mcp(HTTP, "auto", dict(tin, account="nobody"))[0] is None   # web.py refuses the name
        # an account's "ask": asked up front, then it passes in web.py
        _key_with_token(env, '[accounts.key.policy]\nnetwork = "ask"\n')
        d, why = _mcp(HTTP, "default", tin)
        assert d == "ask" and "with key" in why and "[accounts.key.policy] network" in why, why
        old = web._mode
        web._mode = lambda: "default"
        try:
            assert web.http(dict(tin))["ok"]
        finally:
            web._mode = old
        # an explicit per-mode allow approves only calls without an account
        _key_with_token(env, '[policy]\nnetwork = { default = "allow" }\n')
        assert _mcp(HTTP, "default", {"url": a.url("/x")})[0] == "allow"
        assert _mcp(HTTP, "default", tin)[0] is None
        # the account's own use: web.py refuses it with its own words, not the hook
        _key_with_token(env, "use = false\n")
        assert _mcp(HTTP, "auto", tin)[0] is None
        r = web.http(dict(tin))
        assert not r["ok"] and "key is off" in r["error"], r


def test_a_download_credential_use_and_refusals_are_audited_with_their_mode():
    """§2.4: a download's credential use names the mode it was decided in;
    web.py's refusals (once the mode was read) and hooks_mcp's name theirs
    too ("modeless" without a record)."""
    from gateway import paths, web
    routes = {"/f.txt": (200, {"Content-Type": "text/plain"}, "data")}
    with H.gateway_env() as env, U.servers(routes) as (a,):
        proj = env.root / "proj"
        proj.mkdir()
        _key_with_token(env)

        def lines(event):
            recs = [json.loads(x) for x in paths.audit_path().read_text().splitlines()]
            return [r for r in recs if r.get("event") == event]
        old = web._mode
        try:
            web._mode = lambda: "acceptEdits"
            r = web.download({"url": a.url("/f.txt"), "account": "key"}, cwd=str(proj))
            assert r["ok"], r
            use = lines("use")[-1]
            assert use["tool"] == "download" and use["mode"] == "acceptEdits", use
            _key_with_token(env, '[policy]\nnetwork = "deny"\n')
            (proj / "f.txt").unlink()
            r = web.download({"url": a.url("/f.txt")}, cwd=str(proj))
            assert not r["ok"] and lines("refusal")[-1]["mode"] == "acceptEdits", lines("refusal")[-1]
            web._mode = lambda: None
            r = web.http({"url": a.url("/f.txt")})
            assert not r["ok"] and lines("refusal")[-1]["mode"] == "modeless", lines("refusal")[-1]
            # a refusal before the mode was read names none
            r = web.http({"url": "ftp://x"})
            assert not r["ok"] and "mode" not in lines("refusal")[-1], lines("refusal")[-1]
        finally:
            web._mode = old
        assert _mcp(DL, "dontAsk")[0] == "deny"
        assert lines("refusal")[-1]["mode"] == "dontAsk", lines("refusal")[-1]


def test_hook_mcp_and_hook_mode_see_no_secret_in_the_vault():
    """Review nit: the http and download tools' hook reads rights and policy
    only, and hook-mode never reads the vault: gated's broker gives neither
    a secret class (not the "hook-" prefix's ALL)."""
    from gateway.daemon import broker
    assert broker.scope_for("hook-mcp") == broker.NONE
    assert broker.scope_for("hook-mode") == broker.NONE
    assert broker.scope_for("hook-bash") == broker.ALL
