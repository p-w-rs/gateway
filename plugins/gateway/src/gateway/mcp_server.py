"""The MCP server `gw` (SPEC 14): hand-rolled stdio JSON-RPC, standard library only.

Tools: `http` and `download` (web.py), `host_inspect` (managed.inspect: a
read-only look at what this machine offers for the managed shell), and the
terminal and job tools (PLAN-v4 phase 5: `terminal_open`, `terminal_read`,
`terminal_send`, `terminal_resize`, `terminal_signal`, `terminal_close`,
`terminal_list`, `job_start`, `job_status`, `job_tail`, `job_signal`,
`job_list`), which ask gated's supervisor over its socket (terminals.py;
the PTYs live in gated's tmux, never on this server's stdio), each
listed with
`_meta: {"anthropic/alwaysLoad": true}` so Claude sees them without a
ToolSearch round trip. initialize negotiates the protocol version (the
client's if supported, else the newest we speak), ping answers {},
notifications get no answer, unknown methods get -32601, a line that isn't
JSON gets -32700 (id null), a JSON value that isn't a request -32600.

tools/call runs on worker threads (a slow download doesn't block a ping or
another call); every message goes out through one locked writer, so lines
never interleave. Errors never carry raw exception text.
"""
from __future__ import annotations

import concurrent.futures
import json
import sys
import threading
from typing import Any, Callable, TextIO

from . import __version__

PROTOCOL_VERSION = "2025-06-18"
SUPPORTED_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
# Version comes from the package (kept equal to plugin.json), so an update
# never leaves the server reporting a stale number (tests/test_release.py).
SERVER_INFO = {"name": "gw", "version": __version__}
MAX_WORKERS = 8
ALWAYS = {"anthropic/alwaysLoad": True}
INSTRUCTIONS = (
    "The gateway's web tools. http: any http(s) request (Claude Code's permission mode "
    "decides whether it asks, as for any tool); with "
    "account=NAME the gateway adds that account's key or token, only for the account's own "
    "sites. download: save a file into the project (never overwrites, never executable). "
    "Prefer these to curl and wget in Bash (network commands there are asked about unless "
    "gateway.toml's [network] says otherwise). host_inspect: what this machine "
    "offers the managed shell (login PATH folders, toolchains, project toolchain files), read "
    "without running anything. Terminals (terminal_*): real PTYs the user can watch and take "
    "over (/gate-terminal); read the screen, then send input quoting the seq you read (a stale "
    "seq or a terminal the user holds is refused: read again). Never type a password into a "
    "terminal: a password prompt opens the gateway's own dialog for the user. Jobs (job_*): a "
    "command run in its own PTY that outlives this turn and session; job_tail shows its output.")

HTTP_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "an http:// or https:// URL"},
        "method": {"type": "string", "default": "GET",
                   "description": "GET, HEAD, POST, PUT, PATCH, DELETE, ..."},
        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
        "body": {"type": "string", "description": "request body (text)"},
        "json": {"description": "a JSON value sent as the body (sets Content-Type)"},
        "account": {"type": "string",
                    "description": "a gateway account (gate status lists them); its key or token "
                                   "is added, only for the account's own sites"},
        "auth": {"type": "string",
                 "description": "api-key accounts only, to override where the key goes: bearer, "
                                "basic, header:NAME, header:NAME:PREFIX or query:PARAM"},
        "scope": {"type": "string",
                  "description": "azure accounts, for a host listed under `sites`: its Entra scope "
                                 "(https://example.com/.default)"},
        "save_to": {"type": "string",
                    "description": "write the response body to this new file instead of returning it"},
        "timeout": {"type": "number", "default": 30, "maximum": 300},
        "max_bytes": {"type": "integer", "default": 5000000},
    },
    "required": ["url"],
}
DOWNLOAD_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "url": {"type": "string", "description": "an http:// or https:// URL"},
        "account": {"type": "string", "description": "a gateway account whose credential the site needs"},
        "save_to": {"type": "string",
                    "description": "a new file (default: the project folder + the URL's file name)"},
    },
    "required": ["url"],
}
INSPECT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "host": {"type": "string", "default": "localhost",
                 "description": "localhost, or a host in gateway.toml (its name or id): read on "
                                "that host through the gateway's own connection (its read "
                                "policy decides)"},
        "project": {"type": "string",
                    "description": "a project folder whose toolchain files to list (default: the "
                                   "session's project)"},
    },
}
ID_PROP = {"type": "string", "description": "a terminal id (t_...) or job id (j_...)"}
SIGNAL_PROP = {"type": "string", "enum": ["INT", "TERM", "KILL", "HUP", "QUIT", "STOP", "CONT",
                                          "TSTP", "USR1", "USR2", "WINCH"]}
HOST_PROP = {"type": "string", "default": "localhost",
             "description": "localhost, or a host in gateway.toml (its name or id): the terminal "
                            "or job then runs there in the gateway's managed remote runtime (bash "
                            "and tmux staged on first use; ssh = true needed)"}
TERM_OPEN_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "host": HOST_PROP,
        "cwd": {"type": "string", "description": "absolute folder to start in (default: the project "
                                                 "on localhost, the home folder on a remote host)"},
        "cols": {"type": "integer", "minimum": 20, "maximum": 400, "default": 120},
        "rows": {"type": "integer", "minimum": 5, "maximum": 150, "default": 32},
        "workspace": {"type": "string", "description": "a workspace of that host (its name or w_ "
                                                       "id): cwd defaults to its root and must be "
                                                       "inside it"},
        "task_ref": {"type": "string", "description": "an opaque task reference to keep with it"},
    },
}
TERM_READ_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": ID_PROP,
        "history": {"type": "integer", "minimum": 0, "maximum": 2000, "default": 0,
                    "description": "also return this many lines of scrollback above the screen"},
        "take": {"type": "boolean", "default": False,
                 "description": "take the input from another agent of this session (or adopt a "
                                "terminal whose session ended); never from the user"},
    },
    "required": ["id"],
}
TERM_SEND_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "id": ID_PROP,
        "seq": {"type": "integer", "description": "the seq of the screen you read (terminal_read, "
                                                  "or the last send's answer)"},
        "text": {"type": "string", "description": "text to type (no control characters; a newline "
                                                  "is Enter)"},
        "keys": {"type": "array", "items": {"type": "string"},
                 "description": "keys after the text: Enter, Tab, Escape, BSpace, Up, Down, Left, "
                                "Right, Home, End, PageUp, PageDown, Delete, F1-F12, C-a..C-z, M-x"},
        "enter": {"type": "boolean", "default": False, "description": "press Enter at the end"},
        "delay_ms": {"type": "integer", "minimum": 0, "maximum": 30000, "default": 0,
                     "description": "wait this long before typing (the input is queued meanwhile; a "
                                    "user takeover cancels it)"},
        "read_after": {"type": "boolean", "default": True,
                       "description": "return the screen after the input"},
    },
    "required": ["id", "seq"],
}
TERM_RESIZE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"id": ID_PROP, "cols": {"type": "integer", "minimum": 20, "maximum": 400},
                   "rows": {"type": "integer", "minimum": 5, "maximum": 150}},
    "required": ["id", "cols", "rows"],
}
TERM_SIGNAL_SCHEMA: dict[str, Any] = {
    "type": "object", "properties": {"id": ID_PROP, "signal": SIGNAL_PROP},
    "required": ["id", "signal"],
}
ID_ONLY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {"id": ID_PROP}, "required": ["id"]}
EMPTY_SCHEMA: dict[str, Any] = {"type": "object", "properties": {}}
JOB_START_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "command": {"type": "string", "description": "a bash command string (or give argv)"},
        "argv": {"type": "array", "items": {"type": "string"},
                 "description": "the program and its arguments (or give command)"},
        "cwd": {"type": "string", "description": "absolute folder to run in (default: the project "
                                                 "on localhost, the home folder on a remote host)"},
        "host": HOST_PROP,
        "workspace": {"type": "string", "description": "a workspace of that host (its name or w_ "
                                                       "id): cwd defaults to its root and must be "
                                                       "inside it"},
        "on_pause": {"type": "string", "enum": ["continue", "interrupt", "suspend", "detach"],
                     "default": "continue",
                     "description": "what a pause of the task does to this job"},
        "idempotency_key": {"type": "string",
                            "description": "the same key within 24 h returns the job it started "
                                           "instead of starting another"},
        "task_ref": {"type": "string"},
    },
}
JOB_TAIL_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {"id": ID_PROP,
                   "bytes": {"type": "integer", "minimum": 1, "maximum": 65536, "default": 8192},
                   "lines": {"type": "integer", "minimum": 1, "description": "at most this many lines"}},
    "required": ["id"],
}

RUNTIME_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "host": {"type": "string", "description": "a remote host in gateway.toml (name or id)"},
        "action": {"type": "string", "enum": ["status", "provision", "clean"], "default": "status",
                   "description": "status: identity, reachability, authentication and runtime "
                                  "readiness; provision: stage the runtime now; clean: remove the "
                                  "host's older runtime versions that run nothing"},
    },
    "required": ["host"],
}

TERM_TOOLS: list[tuple[str, str, dict[str, Any], str]] = [
    ("terminal_open", "/agent/term/open", TERM_OPEN_SCHEMA,
     "Open a persistent terminal (a real PTY in the gateway's managed bash: no user rc, the "
     "gateway's PATH and stand-ins) that survives this turn and a Claude Code restart, and that "
     "the user can watch and take over with /gate-terminal ID. Returns its id and first screen "
     "(seq, lines, cursor)."),
    ("terminal_read", "/agent/term/read", TERM_READ_SCHEMA,
     "Read a terminal's screen, bounded and scrubbed of secrets: visible lines, cursor, whether a "
     "full-screen program uses the alternate screen, the title, owner (agent or user), seq (quote "
     "it in terminal_send), truncated; optionally the last N scrollback lines."),
    ("terminal_send", "/agent/term/send", TERM_SEND_SCHEMA,
     "Type into a terminal you hold: text and/or keys. Quote the seq you read: if the screen "
     "changed since, or the user took the input, it is refused and you read again. Never type a "
     "password: a password prompt opens the gateway's dialog for the user. Returns the screen "
     "after."),
    ("terminal_resize", "/agent/term/resize", TERM_RESIZE_SCHEMA,
     "Resize a terminal you hold (columns, rows)."),
    ("terminal_signal", "/agent/term/signal", TERM_SIGNAL_SCHEMA,
     "Send a signal to a terminal's foreground program (INT is what ^C does)."),
    ("terminal_close", "/agent/term/close", ID_ONLY_SCHEMA,
     "Close a terminal (its programs get a hangup) or a job's pane."),
    ("terminal_list", "/agent/term/list", EMPTY_SCHEMA,
     "List the gateway's terminals and jobs: id, state, owner, cwd, which are this session's."),
    ("job_start", "/agent/job/start", JOB_START_SCHEMA,
     "Start a command as a gateway job in its own PTY (the managed environment): it outlives this "
     "turn and session; poll it with job_status/job_tail. on_pause says what pausing the task "
     "does to it; an idempotency_key makes a retry return the same job. On a remote host a "
     "start whose answer was lost comes back as state unknown (start_confirmed false): the "
     "gateway asks the host; don't start it again before job_status says."),
    ("job_status", "/agent/job/status", ID_ONLY_SCHEMA,
     "A job's state (running, waiting_auth, suspended, disconnected, exited, canceled, failed, "
     "unknown), exit code or signal, command (scrubbed), times; stop_requested when a close "
     "didn't (provably) reach its host."),
    ("job_tail", "/agent/job/tail", JOB_TAIL_SCHEMA,
     "The end of a job's output, scrubbed of secrets and bounded (64 KiB at most), with "
     "truncated and offset."),
    ("job_signal", "/agent/job/signal", TERM_SIGNAL_SCHEMA,
     "Send a signal to a job's process group (TERM or KILL stops it: state canceled)."),
    ("job_list", "/agent/job/list", EMPTY_SCHEMA, "List the gateway's jobs."),
    ("host_runtime", "/agent/remote/runtime", RUNTIME_SCHEMA,
     "A remote host's managed runtime (the gateway's own bash and tmux there, used by terminals and "
     "jobs on that host): its verified machine identity, whether it is reachable and accepts the "
     "gateway's key, and the runtime's readiness and version, as of the last contact "
     "(checked_at; unknown once nothing has asked the host for a while); or stage it now, or "
     "clean old versions. Nothing of the host's own shell setup is used."),
]
TERM_ROUTES = {name: route for name, route, _schema, _desc in TERM_TOOLS}

TOOLS: list[dict[str, Any]] = [
    {"name": "http",
     "description": "HTTP request through the gateway (rather than curl/wget). With account=NAME "
                    "the gateway adds that account's credential for its own sites. The response "
                    "comes back scrubbed of secrets; binary bodies as base64 or save_to.",
     "inputSchema": HTTP_SCHEMA, "_meta": dict(ALWAYS)},
    {"name": "download",
     "description": "Download a file (binary-safe) into the project or save_to; never overwrites, "
                    "never sets the exec bit; returns path, size and sha256.",
     "inputSchema": DOWNLOAD_SCHEMA, "_meta": dict(ALWAYS)},
    {"name": "host_inspect",
     "description": "What this machine offers Claude's managed shell, read-only and scoped: the "
                    "folders a login shell would put on PATH (from /etc/paths and the shell rc "
                    "files, read as text, never run), toolchain folders (Homebrew, MacPorts, "
                    "pyenv, nvm, rustup, pixi, ...) with some of their programs, the project's "
                    "toolchain files and the names of importable variables, plus the managed "
                    "shell's current PATH and imports with their origins. With a remote host "
                    "the same is read on that host (files read, folders listed; nothing run). "
                    "Nothing is imported by looking: an import is a [shell] (or [hosts.NAME."
                    "shell]) entry in gateway.toml the user approves.",
     "inputSchema": INSPECT_SCHEMA, "_meta": dict(ALWAYS)},
] + [{"name": n, "description": d, "inputSchema": sch, "_meta": dict(ALWAYS)}
     for n, _r, sch, d in TERM_TOOLS]
TOOL_NAMES = tuple(t["name"] for t in TOOLS)


def terminal_env() -> dict[str, str]:
    """What a new terminal or job takes from this server's environment
    (Claude Code's, the user's): every variable but the managed shell's
    removals (managed.dropped; PLAN-0.11 §1.6). gated checks them again."""
    import os
    from . import managed
    return {k: v for k, v in os.environ.items() if not managed.dropped(k)}


def call_terminal(name: str, args: dict[str, Any]) -> dict[str, Any]:
    import os
    from .daemon import client
    from .daemon import is_local_host
    body = {k: v for k, v in args.items() if not k.startswith("__")}
    body["tool_use_id"] = args.get("__tool_use_id") or ""
    remote = False
    if name in ("terminal_open", "job_start"):
        # this machine named by its own contract id is localhost (PLAN-v4
        # phase 7): it gets the project folder and the managed imports like
        # "localhost", never a remote host's defaults
        if is_local_host(body.get("host")):
            if body.get("host") not in (None, ""):
                body["host"] = "localhost"
        else:
            remote = True
    if name in ("terminal_open", "job_start"):
        if not body.get("cwd") and not remote:
            body["cwd"] = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
        if not remote:
            body["env"] = terminal_env()
    timeout = 30.0
    if remote or name == "host_runtime":
        timeout = 900.0            # the first use stages the runtime on the host
    if name == "terminal_send":
        try:
            timeout += max(0, min(30000, int(args.get("delay_ms") or 0))) / 1000.0
        except (TypeError, ValueError):
            pass
    return client.term_call(TERM_ROUTES[name], body, timeout=timeout)


def call_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    from . import web
    if not isinstance(args, dict):
        args = {}
    if name in TERM_ROUTES:
        return call_terminal(name, args)
    args = {k: v for k, v in args.items() if not k.startswith("__")}
    if name == "http":
        return web.http(args)
    if name == "download":
        return web.download(args)
    if name == "host_inspect":
        import os
        from . import managed
        from .daemon import is_local_host
        host = args.get("host") if isinstance(args.get("host"), str) else None
        if not is_local_host(host):
            from .daemon import client
            return client.term_call("/agent/remote/inspect", {"host": host}, timeout=120.0)
        project = args.get("project") if isinstance(args.get("project"), str) else None
        if not project:
            project = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
        return managed.inspect(host, project)
    return {"ok": False, "error": "gateway: unknown tool; the tools are " + ", ".join(TOOL_NAMES)}


class Server:
    def __init__(self, stdin: TextIO | None = None, stdout: TextIO | None = None,
                 tool: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
                 workers: int = MAX_WORKERS):
        self.stdin = stdin or sys.stdin
        self.stdout = stdout or sys.stdout
        self.tool = tool or call_tool
        self._lock = threading.Lock()
        self._pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers,
                                                           thread_name_prefix="gw-tool")
        self.protocol = PROTOCOL_VERSION

    def send(self, obj: dict[str, Any]) -> None:
        line = json.dumps(obj) + "\n"
        with self._lock:
            try:
                self.stdout.write(line)
                self.stdout.flush()
            except (OSError, ValueError):
                pass

    def result(self, rid: Any, result: dict[str, Any]) -> None:
        self.send({"jsonrpc": "2.0", "id": rid, "result": result})

    def error(self, rid: Any, code: int, msg: str) -> None:
        self.send({"jsonrpc": "2.0", "id": rid, "error": {"code": code, "message": msg}})

    def _call(self, rid: Any, name: str, args: dict[str, Any]) -> None:
        try:
            out = self.tool(name, args)
        except Exception as e:  # noqa: BLE001
            out = {"ok": False, "error": f"gateway: the {name if name in TOOL_NAMES else ''} "
                                         f"tool failed ({type(e).__name__}); try again or tell the user"}
        if not isinstance(out, dict):
            out = {"ok": False, "error": "gateway: the tool returned nothing"}
        self.result(rid, {"content": [{"type": "text", "text": json.dumps(out, indent=1)}],
                          "isError": not out.get("ok", False)})

    def handle(self, msg: dict[str, Any]) -> None:
        method = msg.get("method")
        rid = msg.get("id")
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        if method is None:
            return                      # a response to something we never sent
        if rid is None:
            return                      # notifications (initialized, cancelled, ...)
        if method == "initialize":
            asked = params.get("protocolVersion")
            self.protocol = asked if asked in SUPPORTED_VERSIONS else PROTOCOL_VERSION
            self.result(rid, {"protocolVersion": self.protocol,
                              "capabilities": {"tools": {"listChanged": False}},
                              "serverInfo": SERVER_INFO, "instructions": INSTRUCTIONS})
        elif method == "ping":
            self.result(rid, {})
        elif method == "tools/list":
            self.result(rid, {"tools": TOOLS})
        elif method == "tools/call":
            name = params.get("name")
            args = params.get("arguments")
            if not isinstance(name, str):
                self.error(rid, -32602, "tools/call needs a tool name")
                return
            args = dict(args) if isinstance(args, dict) else {}
            for k in [k for k in args if k.startswith("__")]:
                args.pop(k)                      # reserved for the server's own notes
            meta = params.get("_meta") if isinstance(params.get("_meta"), dict) else {}
            tid = meta.get("claudecode/toolUseId")
            if isinstance(tid, str):
                args["__tool_use_id"] = tid      # which agent loop called (the mod told gated)
            self._pool.submit(self._call, rid, name, args)
        else:
            self.error(rid, -32601, "method not found")

    def serve(self) -> None:
        try:
            for line in self.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except ValueError:
                    self.error(None, -32700, "parse error")   # JSON-RPC: id null
                    continue
                if isinstance(msg, dict):
                    self.handle(msg)
                elif isinstance(msg, list) and msg:      # a batch (2025-03-26)
                    for m in msg:
                        if isinstance(m, dict):
                            self.handle(m)
                        else:
                            self.error(None, -32600, "invalid request")
                else:
                    self.error(None, -32600, "invalid request")
        finally:
            self._pool.shutdown(wait=True)


def handle(msg: dict[str, Any]) -> dict[str, Any] | None:
    """One message -> its response, synchronously (tests, simple callers)."""
    out: list[dict[str, Any]] = []

    class _Buf:
        def write(self, s: str) -> None:
            out.append(json.loads(s))

        def flush(self) -> None:
            pass
    srv = Server(stdin=None, stdout=_Buf(), workers=1)  # type: ignore[arg-type]
    try:
        srv.handle(msg)
    finally:
        srv._pool.shutdown(wait=True)
    return out[0] if out else None


def serve(stdin: TextIO | None = None, stdout: TextIO | None = None) -> None:
    Server(stdin, stdout).serve()


def main() -> None:
    serve()


if __name__ == "__main__":
    main()
