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
    r = U.run_sh(env, "mcp_perm.sh", payload, test=False)
    assert r.returncode == 0, r.stderr
    if not r.stdout.strip():
        return None
    return json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"]


def _p(tool, tin) -> dict:
    return {"session_id": "s", "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": tin,
            "cwd": "/x"}


def test_mcp_perm_decisions():
    """GW-SEC-1 / GW-UX-3: the hook gives no decision for the http and
    download tools, in any mode, for any method, with or without an account
    (a request can carry project data out, a download fetches anything, and
    an account's credential reaches its service), so Claude Code's own mode
    decides: a prompt in default and plan mode, the reviewer in auto. Only
    top-level keys decide the tools it does allow."""
    with H.gateway_env() as env:
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
        for mode in (None, "default", "plan", "acceptEdits", "auto", "bypassPermissions"):
            for p in never:
                q = dict(p, permission_mode=mode) if mode else p
                assert _decide(env, q) is None, (mode, p)
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
    download, so the MCP instructions and the curl refusal must not tell
    Claude they "need no prompt": Claude Code's own mode decides."""
    from gateway import hooks_bash
    assert "no prompt" not in mcp_server.INSTRUCTIONS
    assert "permission mode decides" in mcp_server.INSTRUCTIONS
    with H.gateway_env():
        why = hooks_bash._deny_curl("curl")["hookSpecificOutput"]["permissionDecisionReason"]
    assert "no prompt" not in why and "permission mode decides" in why, why


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
