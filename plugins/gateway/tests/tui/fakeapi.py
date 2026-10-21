"""Fake Anthropic Messages API for TUI acceptance tests (stdlib only).

It answers Claude Code's requests on 127.0.0.1 and records every request it
receives, so a test can (a) script what "the model" does, deterministically,
and (b) inspect exactly what Claude Code would have sent to Anthropic, in
plaintext, before any TLS (the payload-capture evidence brief section 14.13
asks for).

Two halves live in this file:

* the server (`serve()`, run as `python fakeapi.py --log LOG --port 0
  --port-file F`): a ThreadingHTTPServer; all shared state sits behind one
  lock, so concurrent requests (main loop, classifier, side calls) are safe;
* the client (`FakeAPI`): starts the server as a child process (default) or
  in a thread, learns the port it bound (port 0), scripts replies over a
  small control API, and reads the request log.

Request log (JSONL, mode 0600), one record per request:
    {"seq", "t", "method", "path", "query", "headers" (lower-cased, without
     x-api-key / authorization / cookie / proxy-authorization), "kind"
     ("main" | "side" | "count_tokens" | "other"), "reply" (index of the
     scripted reply consumed, or null), "body" (text) or "body_b64"
     (when not UTF-8), "content_encoding"}

Classification: a POST to .../v1/messages whose JSON body has a non-empty
`tools` list is a main-loop request ("main"; with `require_tool="Bash"` the
list must also hold that tool). Only main requests consume scripted replies;
every other messages request (title, classifier, summaries) gets the default
text, count_tokens gets {"input_tokens": 10}, and any other POST gets {}.

Scripted replies (a list; each item is one model turn):
    "hello"                                   text
    {"text": "hello"}                         text
    {"tool": "Bash", "input": {...}}          one tool_use block
    {"tool": ..., "input": ..., "text": "x"}  text block, then the tool_use
    {"blocks": [{"type": "text", "text": "a"},
                {"type": "tool_use", "name": "Bash", "input": {...}}]}
  options on any reply:
    "delay": 1.5        seconds before the response starts
    "chunk_delay": 0.2  seconds between text deltas (text sent in 8-char pieces)
    "hold": "name"      wait until FakeAPI.release("name") (or 300 s) before answering
    "error": {"status": 529, "type": "overloaded_error", "message": "..."}
    "stop_reason": "end_turn" | "tool_use" | "max_tokens" ...
When the queue is empty, main requests get `default_text` too.

Control API (not logged): POST /_harness/script {"replies": [...],
"default_text"?}, POST /_harness/push {"replies": [...]}, POST
/_harness/release {"name": ...}, GET /_harness/state.
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.request
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

DROP_HEADERS = {"x-api-key", "authorization", "proxy-authorization", "cookie", "set-cookie"}
CONTROL = "/_harness/"


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------


class State:
    """Everything the handlers share; every access goes through `lock`."""

    def __init__(self, log_path: str, replies=(), default_text: str = "ok",
                 require_tool: str | None = None):
        self.lock = threading.Condition()
        self.log_path = log_path
        self.replies = [normalize(r) for r in replies]
        self.consumed = 0
        self.seq = 0
        self.kinds: dict[str, int] = {}
        self.default_text = default_text
        self.require_tool = require_tool
        self.released: set[str] = set()
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        self.log = os.fdopen(fd, "ab", buffering=0)

    def classify(self, path: str, req: dict | None) -> str:
        p = urlsplit(path).path.rstrip("/")
        if p.endswith("/count_tokens"):
            return "count_tokens"
        if not p.endswith("/v1/messages"):
            return "other"
        tools = (req or {}).get("tools") if isinstance(req, dict) else None
        if isinstance(tools, list) and tools:
            if self.require_tool and not any(
                    isinstance(t, dict) and t.get("name") == self.require_tool for t in tools):
                return "side"
            return "main"
        return "side"

    def take(self, kind: str) -> tuple[int | None, dict]:
        with self.lock:
            if kind == "main" and self.replies:
                idx = self.consumed
                self.consumed += 1
                return idx, self.replies.pop(0)
            return None, {"text": self.default_text}

    def record(self, rec: dict) -> int:
        with self.lock:
            self.seq += 1
            rec["seq"] = self.seq
            self.kinds[rec.get("kind", "?")] = self.kinds.get(rec.get("kind", "?"), 0) + 1
            self.log.write(json.dumps(rec, ensure_ascii=False).encode("utf-8") + b"\n")
            self.lock.notify_all()
            return self.seq

    def wait_release(self, name: str, timeout: float = 300.0) -> bool:
        end = time.time() + timeout
        with self.lock:
            while name not in self.released:
                left = end - time.time()
                if left <= 0:
                    return False
                self.lock.wait(left)
            return True


def normalize(r) -> dict:
    """A scripted reply in its dict form (see module doc)."""
    if isinstance(r, str):
        return {"text": r}
    if not isinstance(r, dict):
        raise ValueError(f"reply must be a str or dict, not {type(r).__name__}")
    return dict(r)


def blocks_of(reply: dict) -> list[dict]:
    if "blocks" in reply:
        out = []
        for b in reply["blocks"]:
            b = dict(b)
            if b.get("type") == "tool_use":
                b.setdefault("id", new_tool_id())
            out.append(b)
        return out
    out = []
    if "tool" in reply:
        if reply.get("text"):
            out.append({"type": "text", "text": reply["text"]})
        out.append({"type": "tool_use", "id": reply.get("id") or new_tool_id(),
                    "name": reply["tool"], "input": reply.get("input", {})})
        return out
    return [{"type": "text", "text": str(reply.get("text", "ok"))}]


def new_tool_id() -> str:
    return "toolu_fake" + secrets.token_hex(8)


USAGE = {"input_tokens": 1, "output_tokens": 1, "cache_creation_input_tokens": 0,
         "cache_read_input_tokens": 0}


class Handler(BaseHTTPRequestHandler):
    server_version = "fakeapi/1"
    state: State  # set on the class by make_server

    def log_message(self, *a):  # quiet
        pass

    # -- plumbing -------------------------------------------------------
    def _body(self) -> bytes:
        n = int(self.headers.get("content-length") or 0)
        raw = self.rfile.read(n) if n else b""
        enc = (self.headers.get("content-encoding") or "").lower()
        try:
            if enc in ("gzip", "x-gzip"):
                raw = zlib.decompress(raw, 16 + zlib.MAX_WBITS)
            elif enc == "deflate":
                raw = zlib.decompress(raw)
        except zlib.error:
            pass
        return raw

    def _json(self, obj, status: int = 200):
        b = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.send_header("request-id", "req_fake" + secrets.token_hex(6))
        self.end_headers()
        self.wfile.write(b)

    def _record(self, raw: bytes, kind: str, reply_idx):
        u = urlsplit(self.path)
        rec = {"t": time.time(), "method": self.command, "path": u.path, "query": u.query,
               "headers": {k.lower(): v for k, v in self.headers.items()
                           if k.lower() not in DROP_HEADERS},
               "kind": kind, "reply": reply_idx,
               "content_encoding": self.headers.get("content-encoding")}
        try:
            rec["body"] = raw.decode("utf-8")
        except UnicodeDecodeError:
            rec["body_b64"] = base64.b64encode(raw).decode()
        return self.state.record(rec)

    # -- control --------------------------------------------------------
    def _control(self, raw: bytes):
        st = self.state
        name = urlsplit(self.path).path[len(CONTROL):]
        try:
            data = json.loads(raw or b"{}")
        except ValueError:
            return self._json({"error": "bad json"}, 400)
        with st.lock:
            if name == "script" and self.command == "POST":
                st.replies = [normalize(r) for r in data.get("replies", [])]
                if "default_text" in data:
                    st.default_text = str(data["default_text"])
            elif name == "push" and self.command == "POST":
                st.replies.extend(normalize(r) for r in data.get("replies", []))
            elif name == "release" and self.command == "POST":
                st.released.add(str(data.get("name")))
                st.lock.notify_all()
            elif name != "state":
                return self._json({"error": "unknown control"}, 404)
            out = {"pending": len(st.replies), "consumed": st.consumed, "requests": st.seq,
                   "kinds": dict(st.kinds), "released": sorted(st.released)}
        return self._json(out)

    # -- verbs ----------------------------------------------------------
    def do_GET(self):
        if self.path.startswith(CONTROL):
            return self._control(b"")
        self._record(b"", "other", None)
        self._json({"type": "error", "error": {"type": "not_found_error", "message": "fake"}}, 404)

    def do_HEAD(self):
        self._record(b"", "other", None)
        self.send_response(200)
        self.send_header("content-length", "0")
        self.end_headers()

    def do_POST(self):
        raw = self._body()
        if self.path.startswith(CONTROL):
            return self._control(raw)
        try:
            req = json.loads(raw or b"{}")
        except ValueError:
            req = None
        kind = self.state.classify(self.path, req)
        idx, reply = self.state.take(kind)
        self._record(raw, kind, idx)
        if kind == "count_tokens":
            return self._json({"input_tokens": 10})
        if kind == "other":
            return self._json({})
        if reply.get("hold"):
            self.state.wait_release(str(reply["hold"]))
        if reply.get("delay"):
            time.sleep(float(reply["delay"]))
        if reply.get("error"):
            err = reply["error"]
            return self._json({"type": "error", "error": {"type": err.get("type", "api_error"),
                                                          "message": err.get("message", "fake error")}},
                              int(err.get("status", 500)))
        model = (req or {}).get("model", "claude-fake") if isinstance(req, dict) else "claude-fake"
        blocks = blocks_of(reply)
        stop = reply.get("stop_reason") or (
            "tool_use" if any(b.get("type") == "tool_use" for b in blocks) else "end_turn")
        if isinstance(req, dict) and req.get("stream"):
            return self._stream(model, blocks, stop, float(reply.get("chunk_delay") or 0))
        return self._json({"id": "msg_fake" + secrets.token_hex(6), "type": "message",
                           "role": "assistant", "model": model, "content": blocks,
                           "stop_reason": stop, "stop_sequence": None, "usage": USAGE})

    def _stream(self, model: str, blocks: list[dict], stop: str, chunk_delay: float):
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("cache-control", "no-cache")
        self.send_header("request-id", "req_fake" + secrets.token_hex(6))
        self.end_headers()

        def ev(name, data):
            self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
            self.wfile.flush()

        try:
            ev("message_start", {"type": "message_start", "message": {
                "id": "msg_fake" + secrets.token_hex(6), "type": "message", "role": "assistant",
                "model": model, "content": [], "stop_reason": None, "stop_sequence": None,
                "usage": USAGE}})
            for i, b in enumerate(blocks):
                if b.get("type") == "tool_use":
                    ev("content_block_start", {"type": "content_block_start", "index": i,
                                               "content_block": {"type": "tool_use", "id": b["id"],
                                                                 "name": b["name"], "input": {}}})
                    ev("content_block_delta", {"type": "content_block_delta", "index": i, "delta": {
                        "type": "input_json_delta", "partial_json": json.dumps(b.get("input", {}))}})
                else:
                    text = str(b.get("text", ""))
                    ev("content_block_start", {"type": "content_block_start", "index": i,
                                               "content_block": {"type": "text", "text": ""}})
                    pieces = [text[j:j + 8] for j in range(0, len(text), 8)] if chunk_delay else [text]
                    for p in pieces or [""]:
                        ev("content_block_delta", {"type": "content_block_delta", "index": i,
                                                   "delta": {"type": "text_delta", "text": p}})
                        if chunk_delay:
                            time.sleep(chunk_delay)
                ev("content_block_stop", {"type": "content_block_stop", "index": i})
            ev("message_delta", {"type": "message_delta",
                                 "delta": {"stop_reason": stop, "stop_sequence": None},
                                 "usage": {"output_tokens": 1}})
            ev("message_stop", {"type": "message_stop"})
        except (BrokenPipeError, ConnectionResetError):
            pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(state: State, port: int = 0) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"state": state})
    return _Server(("127.0.0.1", port), handler)


def serve(argv: list[str] | None = None) -> None:
    """Entry point of the server process."""
    ap = argparse.ArgumentParser(description="fake Anthropic Messages API (127.0.0.1)")
    ap.add_argument("--log", required=True, help="request log (JSONL)")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--port-file", help="written with the bound port once listening")
    ap.add_argument("--script", help="JSON file with the initial reply list")
    ap.add_argument("--default-text", default="ok")
    ap.add_argument("--require-tool")
    a = ap.parse_args(argv)
    replies = json.load(open(a.script)) if a.script else []
    st = State(a.log, replies, a.default_text, a.require_tool)
    srv = make_server(st, a.port)
    port = srv.server_address[1]
    if a.port_file:
        tmp = a.port_file + ".tmp"
        with open(tmp, "w") as f:
            f.write(str(port))
        os.replace(tmp, a.port_file)
    print(f"FAKEAPI PORT {port}", flush=True)
    srv.serve_forever()


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

_NO_PROXY = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def _safety():
    """The harness's safety module (imported lazily: the server half of this
    file runs alone with `python -I` and must stay stdlib-only)."""
    try:
        from . import safety
    except ImportError:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import safety  # type: ignore[no-redef]
    return safety


class FakeAPI:
    """Start, script and read a fake API.

        api = FakeAPI(root, replies=[{"tool": "Bash", "input": {...}}, "done"]).start()
        ... ANTHROPIC_BASE_URL=api.url ...
        api.push("another turn")
        api.wait_main(2, timeout=30)
        api.requests(kind="main")[-1]["body"]
        api.stop()

    mode="process" (default) runs the server as a child process, so the
    harness process stays single-threaded for pty.fork; mode="thread" runs
    it in a daemon thread (fine when no fork follows).
    """

    def __init__(self, root: os.PathLike | str, replies=(), default_text: str = "ok",
                 require_tool: str | None = None, mode: str = "process"):
        self.root = os.fspath(root)
        os.makedirs(self.root, exist_ok=True)
        self.log_path = os.path.join(self.root, "api.jsonl")
        self._replies = [normalize(r) for r in replies]
        self.default_text = default_text
        self.require_tool = require_tool
        self.mode = mode
        self.port: int | None = None
        self.proc: subprocess.Popen | None = None
        self._srv = None
        self._thread = None

    # lifecycle -----------------------------------------------------------
    def start(self, timeout: float = 15.0) -> "FakeAPI":
        if self.mode == "thread":
            st = State(self.log_path, self._replies, self.default_text, self.require_tool)
            self._srv = make_server(st)
            self.port = self._srv.server_address[1]
            self._thread = threading.Thread(target=self._srv.serve_forever, daemon=True)
            self._thread.start()
            return self
        script = os.path.join(self.root, "script.json")
        with open(script, "w") as f:
            json.dump(self._replies, f)
        port_file = os.path.join(self.root, "api.port")
        if os.path.exists(port_file):
            os.unlink(port_file)
        argv = [sys.executable, "-I", os.path.abspath(__file__), "--log", self.log_path,
                "--port", "0", "--port-file", port_file, "--script", script,
                "--default-text", self.default_text]
        if self.require_tool:
            argv += ["--require-tool", self.require_tool]
        err = open(os.path.join(self.root, "api.stderr"), "ab")
        self.proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=err, start_new_session=True,
                                     env={"PATH": os.environ.get("PATH", "/usr/bin:/bin")})
        err.close()
        end = time.time() + timeout
        while time.time() < end:
            if os.path.exists(port_file):
                self.port = int(open(port_file).read().strip())
                return self
            if self.proc.poll() is not None:
                break
            time.sleep(0.05)
        self.stop()
        raise RuntimeError("fake API did not start (see api.stderr)")

    def stop(self) -> None:
        if self._srv is not None:
            self._srv.shutdown()
            self._srv.server_close()
            self._srv = None
            if self._thread is not None:
                self._thread.join(5)
                self._thread = None
        if self.proc is not None:
            if self.proc.poll() is None:
                _safety().kill_tree(self.proc.pid, grace=1.0)
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
            self.proc = None

    def alive(self) -> bool:
        if self._srv is not None:
            return True
        return self.proc is not None and self.proc.poll() is None

    def __enter__(self):
        return self.start() if self.port is None else self

    def __exit__(self, *exc):
        self.stop()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    # control ---------------------------------------------------------------
    def _control(self, name: str, data: dict | None = None) -> dict:
        url = f"{self.url}{CONTROL}{name}"
        if data is None:
            req = urllib.request.Request(url, method="GET")
        else:
            req = urllib.request.Request(url, data=json.dumps(data).encode(), method="POST",
                                         headers={"content-type": "application/json"})
        with _NO_PROXY.open(req, timeout=10) as r:
            return json.loads(r.read())

    def script(self, replies, default_text: str | None = None) -> dict:
        """Replace the queue of scripted replies."""
        d = {"replies": [normalize(r) for r in replies]}
        if default_text is not None:
            d["default_text"] = default_text
        return self._control("script", d)

    def push(self, *replies) -> dict:
        """Append replies to the queue."""
        return self._control("push", {"replies": [normalize(r) for r in replies]})

    def release(self, name: str) -> dict:
        """Let replies scripted with {"hold": name} answer."""
        return self._control("release", {"name": name})

    def state(self) -> dict:
        return self._control("state")

    # log -------------------------------------------------------------------
    def requests(self, kind: str | None = None) -> list[dict]:
        """Every recorded request (a partly written last line is skipped)."""
        out = []
        try:
            with open(self.log_path, "rb") as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                    except ValueError:
                        continue
                    if kind is None or rec.get("kind") == kind:
                        out.append(rec)
        except FileNotFoundError:
            pass
        return out

    def main_requests(self) -> list[dict]:
        return self.requests("main")

    def wait_for(self, pred, timeout: float = 30.0, poll: float = 0.1):
        """First recorded request for which pred(record) is true, or None."""
        end = time.time() + timeout
        while True:
            for r in self.requests():
                if pred(r):
                    return r
            if time.time() >= end:
                return None
            time.sleep(poll)

    def wait_main(self, n: int, timeout: float = 30.0) -> bool:
        """True once at least n main-loop requests were received."""
        end = time.time() + timeout
        while time.time() < end:
            if len(self.main_requests()) >= n:
                return True
            time.sleep(0.1)
        return len(self.main_requests()) >= n


def body_json(rec: dict):
    """The parsed JSON body of a log record, or None."""
    try:
        return json.loads(rec.get("body") or "null")
    except ValueError:
        return None


def tool_results(rec: dict) -> list[dict]:
    """tool_result blocks in the last user message of a main request."""
    body = body_json(rec) or {}
    msgs = body.get("messages") or []
    for m in reversed(msgs):
        if m.get("role") == "user" and isinstance(m.get("content"), list):
            res = [b for b in m["content"] if isinstance(b, dict) and b.get("type") == "tool_result"]
            if res:
                return res
    return []


def result_text(block: dict) -> str:
    """Plain text of a tool_result block's content."""
    c = block.get("content")
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return "\n".join(str(x.get("text", "")) for x in c if isinstance(x, dict))
    return ""


if __name__ == "__main__":
    serve()
