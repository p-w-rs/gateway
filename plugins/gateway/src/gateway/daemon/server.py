"""The daemon's HTTP/1.1 server on its Unix socket, and the routes.

One thread per connection (socketserver.ThreadingMixIn); every request is
answered with JSON and `Connection: close`. The peer's credentials are read
from the socket when the connection is accepted (peers.peer_cred) and every
request goes through the uid check, then its route's plane check
(planes.py), before anything else happens. Refusals are logged without
their bodies (the daemon's log under the plugin data folder; never a value).

Contract routes (/v1/*) answer with "contract": 1 (CONTRACT-v1): discovery,
snapshot (hosts, terminals, jobs), events, jobs (start, status, tail,
signal), pause and resume (recorded per session; dialogs closed or held;
each job's on_pause policy applied, with the outcome as it happened).

Terminal and job routes (daemon/terminals.py, PLAN-v4 phase 5): /agent/term/*
and /agent/job/* for the gw MCP server's tools (planes.check_term),
/ui/term/* for the gate mod's terminal pane.

Dialog routes (daemon/dialogs.py): /ui/dialog/* on the UI plane (the mod),
/agent/dialog/lease on the agent plane, /lease/* for any gateway entry point
holding a lease token (popup.py's detached helper).
"""
from __future__ import annotations

import json
import re
import socketserver
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler
from typing import Any, Callable

from .. import ancestry, paths, vault
from . import FEATURES, broker, dialogs, peers, planes, terminals

MAX_REQUEST = 8 * 1024 * 1024
EVENTS_WAIT_MAX = 25.0


class Reply(Exception):
    def __init__(self, status: int, body: dict[str, Any]):
        super().__init__(status)
        self.status, self.body = status, body


def _err(status: int, code: str, message: str, **extra: Any) -> Reply:
    return Reply(status, {"ok": False, "error": code, "message": message, **extra})


LOCKED_INTERACTIVE = ("gateway: the gateway vault is locked (it has a passphrase), so nothing "
                      "was sent. The gateway's unlock dialog is open in Claude Code (the user "
                      "can also type /gate-unlock); tell the user once, then retry after they "
                      "unlock it.")
LOCKED_HEADLESS = ("gateway: the gateway vault is locked (it has a passphrase) and this session "
                   "has no screen to unlock it on, so nothing was sent. Tell the user to unlock "
                   "it from an interactive Claude Code session (/gate-doctor shows the vault's "
                   "state), then retry.")


class Handler(BaseHTTPRequestHandler):
    server_version = "gated"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    timeout = 30                         # a request that stalls (reading or writing) ends
    daemon: "Daemon"                     # set on the class by Daemon.bind

    # -- plumbing ------------------------------------------------------------
    def address_string(self) -> str:      # unix sockets have no address
        return "local"

    def log_message(self, fmt: str, *args: Any) -> None:  # requests aren't logged
        pass

    def setup(self) -> None:
        super().setup()
        try:
            self.peer: peers.Peer | None = peers.peer_cred(self.request)
        except OSError:
            self.peer = None

    def _send(self, status: int, body: dict[str, Any]) -> None:
        data = json.dumps(body, sort_keys=True).encode("utf-8")
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            pass
        self.close_connection = True

    def _read_raw(self) -> bytes | None:
        """The request body, read whole before anything is answered (a reply
        sent while the caller's body is still unread can reach it as a reset
        connection); None when its length is unusable."""
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return None
        if n < 0 or n > MAX_REQUEST:
            return None
        return self.rfile.read(n) if n else b""

    def _body(self) -> dict[str, Any]:
        raw = self._raw
        if raw is None:
            raise _err(413, "bad_request", "gateway: bad or too large Content-Length")
        if not raw:
            return {}
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise _err(400, "bad_request", "gateway: the request isn't JSON") from None
        if not isinstance(obj, dict):
            raise _err(400, "bad_request", "gateway: the request isn't a JSON object")
        return obj

    def _dispatch(self, method: str) -> None:
        url = urllib.parse.urlsplit(self.path)
        query = dict(urllib.parse.parse_qsl(url.query))
        d = self.daemon
        self._raw = self._read_raw() if method == "POST" else b""
        try:
            if self.peer is None:
                raise _err(403, "peer", "gateway: the daemon couldn't identify the caller")
            planes.check_uid(self.peer)
            route = d.routes.get((method, url.path))
            path_id = None
            if route is None:
                # /v1/jobs/<job>, /v1/jobs/<job>/tail, /v1/jobs/<job>/signal
                m = JOB_PATH.fullmatch(url.path)
                if m:
                    path_id = m.group(1)
                    route = d.routes.get((method, "/v1/jobs/{id}" + (m.group(2) or "")))
            if route is None:
                known = any(p == url.path for (_m, p) in d.routes) or bool(JOB_PATH.fullmatch(url.path))
                raise _err(405 if known else 404, "no_route",
                           "gateway: no such route on the gateway daemon")
            plane, fn = route
            ctx = Ctx(d, self.peer, query, self._body if method == "POST" else (lambda: {}))
            ctx.path_id = path_id
            if plane == "ui":
                ctx.session = planes.check_ui(d.registry, self.peer)
            elif plane == "agent":
                ctx.session, ctx.entry = planes.check_agent(d.registry, self.peer)
            elif plane == "contract":
                ctx.session = planes.check_contract(d.registry, self.peer)
            elif plane == "agent-term":
                ctx.session, ctx.entry = planes.check_term(d.registry, self.peer)
            elif plane in ("local", "lease"):
                ctx.entry = planes.check_local(self.peer)
            body = fn(ctx)
            status = 200
        except dialogs.DialogError as e:
            status, body = e.status, {"ok": False, "error": e.code, "message": e.message}
        except terminals.TermError as e:
            status, body = e.status, {"ok": False, "error": e.code, "message": e.message, **e.extra}
        except planes.Denied as e:
            d.log(f"refused {method} {url.path}: {e.code} (pid {self.peer.pid if self.peer else '?'})")
            status, body = e.status, {"ok": False, "error": e.code, "message": e.message}
        except Reply as r:
            status, body = r.status, r.body
        except vault.VaultLocked:
            status, body = 423, {"ok": False, "error": "locked", "message": d.locked_message(self.peer)}
        except broker.Conflict as e:
            status, body = 409, {"ok": False, "error": "conflict", "message": str(e)}
        except (broker.BrokerError, vault.VaultError) as e:
            status, body = 400, {"ok": False, "error": "vault", "message": str(e)}
        except Exception as e:  # noqa: BLE001 - one line, never a traceback with values
            d.log(f"error on {method} {url.path}: {type(e).__name__}")
            status, body = 500, {"ok": False, "error": "internal",
                                 "message": f"gateway: the gateway daemon failed ({type(e).__name__})"}
        if url.path.startswith("/v1/"):
            body = {"contract": 1, **body}
        self._send(status, body)

    def do_GET(self) -> None:  # noqa: N802
        self._dispatch("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._dispatch("POST")


class Ctx:
    def __init__(self, daemon: "Daemon", peer: peers.Peer, query: dict[str, str],
                 body: Callable[[], dict[str, Any]]):
        self.daemon, self.peer, self.query = daemon, peer, query
        self._body_fn = body
        self._body: dict[str, Any] | None = None
        self.session: planes.Session | None = None
        self.entry: peers.Entry | None = None
        self.path_id: str | None = None

    @property
    def body(self) -> dict[str, Any]:
        if self._body is None:
            self._body = self._body_fn()
        return self._body


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 64


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


def _scope(ctx: Ctx) -> tuple[frozenset[str], broker.EntryOk, Callable[[str], bool]]:
    """What the peer may see: its mode's classes, and for a caller that isn't
    direct (ancestry's rule, walked up to its session) only the entries with
    an effective `scripts = true`."""
    assert ctx.entry is not None and ctx.session is not None
    scope = broker.scope_for(ctx.entry.mode)
    tool = broker.direct_tool(ctx.entry.mode)
    if tool is None:
        return scope, (lambda s, n: True), (lambda a: True)
    try:
        direct, _culprit = ancestry.walk_direct(peers.parent(ctx.peer.pid), ctx.session.pid, tool)
    except Exception:  # noqa: BLE001 - can't tell: not direct
        direct = False
    if direct:
        return scope, (lambda s, n: True), (lambda a: True)
    eff = ctx.daemon.effective()
    def ok(section: str, name: str) -> bool:
        if section == "accounts":
            a = eff.accounts.get(name) if eff else None
            return bool(a and a.scripts)
        h = eff.hosts.get(name) if eff else None
        return bool(h and h.scripts)
    return scope, ok, (lambda a: ok("accounts", a))


def r_health(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.health()


def r_ui_register(ctx: Ctx) -> dict[str, Any]:
    s = planes.register_ui(ctx.daemon.registry, ctx.peer, ctx.body)
    ctx.daemon.events.emit("session.registered", session=s.session_id or None, via="ui", ui=True)
    return {"ok": True, "registered": s.public(), **ctx.daemon.health()}


def r_ui_unregister(ctx: Ctx) -> dict[str, Any]:
    gone = ctx.daemon.registry.unregister(ctx.peer.pid)
    if gone and ctx.session is not None:
        ctx.daemon.events.emit("session.ended", session=ctx.session.session_id or None)
    return {"ok": True, "removed": gone}


def r_lock(ctx: Ctx) -> dict[str, Any]:
    b = ctx.daemon.broker
    if b.mode() != "wrapped":
        return {"ok": True, "locked": False, "vault": b.state(),
                "message": "gateway: the vault key has no passphrase, so there is nothing to lock"}
    b.lock("explicit")
    return {"ok": True, "locked": True, "vault": b.state(),
            "message": "gateway: the vault is locked"}


def r_agent_register(ctx: Ctx) -> dict[str, Any]:
    s = planes.register_agent(ctx.daemon.registry, ctx.peer, ctx.body)
    ctx.daemon.events.emit("session.registered", session=s.session_id or None, via="hook",
                           ui=s.ui)
    return {"ok": True, "registered": s.public()}


def r_vault_status(ctx: Ctx) -> dict[str, Any]:
    return {"ok": True, "vault": ctx.daemon.broker.state(), "mode": ctx.daemon.broker.mode(),
            "scope": sorted(broker.scope_for(ctx.entry.mode)) if ctx.entry else []}


def r_vault_read(ctx: Ctx) -> dict[str, Any]:
    scope, entry_ok, _acct = _scope(ctx)
    with ctx.daemon.vault_mutex:
        data = ctx.daemon.broker.read()
    return {"ok": True, "data": broker.make_view(data, scope, ctx.daemon.broker.key, entry_ok),
            "scope": sorted(scope)}


def r_vault_write(ctx: Ctx) -> dict[str, Any]:
    new = ctx.body.get("data")
    if not isinstance(new, dict):
        raise _err(400, "bad_request", "gateway: no vault document")
    scope, entry_ok, _acct = _scope(ctx)
    b = ctx.daemon.broker
    with ctx.daemon.vault_mutex:
        current = b.read() if paths.vault_path().exists() else vault.empty()
        merged = broker.merge(new, current, scope, b.key, entry_ok)
        b.write(merged, migrating=bool(ctx.body.get("migrating")))
    return {"ok": True}


def r_cache_read(ctx: Ctx) -> dict[str, Any]:
    scope, _ok, acct = _scope(ctx)
    with ctx.daemon.vault_mutex:
        c = ctx.daemon.broker.read_cache() if "cache" in scope else {"tokens": {}}
    return {"ok": True, "cache": broker.cache_view(c, scope, acct)}


def r_cache_write(ctx: Ctx) -> dict[str, Any]:
    new = ctx.body.get("cache")
    if not isinstance(new, dict):
        raise _err(400, "bad_request", "gateway: no cache document")
    scope, _ok, acct = _scope(ctx)
    b = ctx.daemon.broker
    with ctx.daemon.vault_mutex:
        merged = broker.cache_merge(new, b.read_cache(), scope, acct)
        if merged is None:
            raise _err(403, "scope", "gateway: this program may not write the token cache")
        b.write_cache(merged)
    return {"ok": True}


def r_open_own(ctx: Ctx) -> dict[str, Any]:
    assert ctx.entry is not None
    if ctx.entry.mode not in ("gate", "shim gate"):
        raise _err(403, "scope", "gateway: only gate may open data encrypted to this machine's key")
    blob = broker.unb64(ctx.body.get("blob"))
    return {"ok": True, "data": broker.b64(ctx.daemon.broker.open_own(blob))}


def r_local_stop(ctx: Ctx) -> dict[str, Any]:
    ctx.daemon.stop_soon("request")
    return {"ok": True, "stopping": True}


def r_local_restart(ctx: Ctx) -> dict[str, Any]:
    d = ctx.daemon
    busy = d.busy()
    if busy:
        return {"ok": True, "restarting": False, "busy": busy,
                "message": f"gateway: the old gateway daemon ({d.version}) still runs {busy}; it "
                           "is kept until they finish"}
    d.stop_soon("restart")
    return {"ok": True, "restarting": True}


def r_capabilities(ctx: Ctx) -> dict[str, Any]:
    d = ctx.daemon
    return {"ok": True, "contract_id": "gateway.v1", "gateway_version": d.version,
            "features": list(FEATURES), "epoch": d.epoch,
            "limits": {"events_wait_max": EVENTS_WAIT_MAX, "events_ring": d.events.ring.maxlen}}


def r_snapshot(ctx: Ctx) -> dict[str, Any]:
    d = ctx.daemon
    seq = d.events.seq
    terms, jobs = d.terminals.snapshot()
    return {"ok": True, "seq": seq, "epoch": d.epoch, "hosts": d.hosts(),
            "workspaces": d.workspaces(), "accounts": d.accounts(), "terminals": terms,
            "jobs": jobs}


def r_events(ctx: Ctx) -> dict[str, Any]:
    try:
        since = int(ctx.query.get("since", "0"))
        wait = min(EVENTS_WAIT_MAX, max(0.0, float(ctx.query.get("wait", "0"))))
        epoch = int(ctx.query["epoch"]) if "epoch" in ctx.query else None
    except ValueError:
        raise _err(400, "bad_request", "gateway: since, wait and epoch are numbers") from None
    return {"ok": True, **ctx.daemon.events.since(max(0, since), wait, epoch)}


JOB_PATH = re.compile(r"/v1/jobs/(j_[0-9A-HJKMNP-TV-Z]{26})(/tail|/signal)?")


def _session_arg(ctx: Ctx) -> str:
    sid = ctx.body.get("session")
    if not isinstance(sid, str) or not planes._clean_id(sid) or planes._clean_id(sid) != sid:
        raise _err(400, "bad_request", "gateway: pause and resume name a session id")
    return sid


def _task_arg(ctx: Ctx) -> str | None:
    t = ctx.body.get("task_ref")
    if t in (None, ""):
        return None
    if not isinstance(t, str) or len(t) > 200:
        raise _err(400, "bad_request", "gateway: task_ref is a string")
    return t


PAUSE_ID = re.compile(r"[A-Za-z0-9._:-]{1,64}")


def _pause_id_arg(ctx: Ctx) -> str | None:
    v = ctx.body.get("pause_id")
    if v in (None, ""):
        return None
    if not isinstance(v, str) or not PAUSE_ID.fullmatch(v):
        raise _err(400, "bad_request", "gateway: pause_id is at most 64 characters of letters, "
                   "digits and . _ : -")
    return v


def _session_live(ctx: Ctx, sid: str) -> bool:
    """Is a Claude Code process still alive under that session key: a
    registered session with that id (or pid key), or the process the
    session's terminals and jobs were started from."""
    reg = ctx.daemon.registry
    with reg.lock:
        sessions = list(reg.sessions.values())
    for s in sessions:
        if terminals.session_key(s) == sid or (s.session_id and s.session_id == sid):
            if reg.live(s.pid) is not None:
                return True
    m = re.fullmatch(r"pid:(\d{1,10})", sid)
    if m and reg.live(int(m.group(1))) is not None:
        return True
    return any(peers.alive(pid, start) for pid, start in ctx.daemon.terminals.session_processes(sid))


def _pause_session(ctx: Ctx, task: str | None) -> str:
    """The session a pause or resume may act on (PLAN-v4 phase 7): the
    caller's own (its id or pid key, or an id the caller's Claude Code process
    started work under before a /clear or resume); another session only once
    it has ended, and then only for a task (its jobs of that task). Another
    live session is refused: a caller can't pause or resume someone else's
    work."""
    sid = _session_arg(ctx)
    me = ctx.session
    assert me is not None
    if sid == terminals.session_key(me) or (me.session_id and sid == me.session_id):
        return sid
    procs = ctx.daemon.terminals.session_processes(sid)
    if procs and all(pid == me.pid and (start is None or me.start is None or abs(start - me.start) < 1.0)
                     for pid, start in procs):
        return sid
    if _session_live(ctx, sid):
        raise _err(403, "session", "gateway: that session is another live Claude Code session; a "
                   "session can pause or resume only its own work")
    if not task:
        raise _err(403, "session", "gateway: that session isn't the caller's; an ended session's "
                   "jobs can be paused or resumed only for a task (give task_ref)")
    return sid


def r_pause(ctx: Ctx) -> dict[str, Any]:
    """CONTRACT-v1 pause: recorded per session (its dialogs close, no
    credential is used or asked for, no terminal input or new job from its
    agent until resume) and each of its jobs' on_pause policy applied (only
    the task's jobs when task_ref is given), with what actually happened.
    Bound to the caller's session (_pause_session); a repeated pause_id gets
    the first answer back and changes nothing."""
    task = _task_arg(ctx)
    sid = _pause_session(ctx, task)
    pid_ = _pause_id_arg(ctx)
    if pid_:
        prev = ctx.daemon.dialogs.replay("pause", sid, pid_)
        if prev is not None:
            ctx.daemon.events.emit("pause.applied", session=sid, paused=True, task=task, replayed=True)
            return {**prev, "replayed": True}
    closed = ctx.daemon.dialogs.pause(sid)
    outcomes = ctx.daemon.terminals.pause(sid, task)
    ctx.daemon.events.emit("pause.applied", session=sid, paused=True, task=task)
    out = {"ok": True, "paused": True, "outcomes": outcomes, "dialogs_closed": closed}
    if pid_:
        ctx.daemon.dialogs.remember_replay("pause", sid, pid_, out)
        out["pause_id"] = pid_
    return out


def r_resume(ctx: Ctx) -> dict[str, Any]:
    task = _task_arg(ctx)
    sid = _pause_session(ctx, task)
    pid_ = _pause_id_arg(ctx)
    if pid_:
        prev = ctx.daemon.dialogs.replay("resume", sid, pid_)
        if prev is not None:
            ctx.daemon.events.emit("pause.applied", session=sid, paused=False, task=task, replayed=True)
            return {**prev, "replayed": True}
    was = ctx.daemon.dialogs.resume(sid)
    outcomes = ctx.daemon.terminals.resume(sid, task)
    ctx.daemon.events.emit("pause.applied", session=sid, paused=False, task=task)
    out = {"ok": True, "paused": False, "was_paused": was, "outcomes": outcomes}
    if pid_:
        ctx.daemon.dialogs.remember_replay("resume", sid, pid_, out)
        out["pause_id"] = pid_
    return out


# -- jobs on the contract (CONTRACT-v1 "Calls") ----------------------------------------


def r_v1_job_start(ctx: Ctx) -> dict[str, Any]:
    b = ctx.body
    s = ctx.session
    sid = b.get("session")
    if sid not in (None, "") and s is not None and s.session_id and sid != s.session_id:
        raise _err(403, "session", "gateway: that session isn't the caller's Claude Code session")
    if b.get("idempotency_key") in (None, ""):
        raise _err(400, "bad_request", "gateway: a job needs an idempotency_key (CONTRACT-v1)")
    sup = ctx.daemon.terminals
    p, new = sup.start_job(s, agent=terminals._clean(b.get("agent"), 80), argv=b.get("argv"),
                           command=b.get("command"), cwd=b.get("cwd"), host=b.get("host"),
                           workspace=b.get("workspace") or "", task_ref=b.get("task_ref") or "",
                           on_pause=b.get("on_pause"), idempotency_key=b.get("idempotency_key"),
                           via="contract")
    return {"ok": True, "job": p.id, "op": terminals.ulid("o"), "state": p.state, "new": new}


def r_v1_job_get(ctx: Ctx) -> dict[str, Any]:
    return {"ok": True, **ctx.daemon.terminals.contract_job(ctx.daemon.terminals.job(ctx.path_id))}


def r_v1_job_tail(ctx: Ctx) -> dict[str, Any]:
    try:
        n = int(ctx.query.get("bytes", "8192"))
    except ValueError:
        raise _err(400, "bad_request", "gateway: bytes is a number") from None
    t = ctx.daemon.terminals.tail(ctx.path_id, n)
    return {"ok": True, "job": t["job"], "text": t["text"], "truncated": t["truncated"],
            "offset": t["offset"], "state": t["state"]}


def r_v1_job_signal(ctx: Ctx) -> dict[str, Any]:
    sup = ctx.daemon.terminals
    p = sup.job(ctx.path_id)
    if ctx.body.get("signal") not in ("INT", "TERM", "KILL", "STOP", "CONT"):
        raise _err(400, "bad_request", "gateway: signal is INT, TERM, KILL, STOP or CONT")
    r = sup.signal(p.id, ctx.session, ctx.body.get("signal"), by="contract")
    return {"ok": True, "job": p.id, "state": r.get("state"), "exit": r.get("exit")}


# -- the gw MCP server's terminal and job tools (planes.check_term) --------------------


def _agent(ctx: Ctx) -> str:
    return ctx.daemon.terminals.agent_of(ctx.session, ctx.body.get("tool_use_id"))


def r_term_open(ctx: Ctx) -> dict[str, Any]:
    b = ctx.body
    sup = ctx.daemon.terminals
    p = sup.open_terminal(ctx.session, agent=_agent(ctx), cwd=b.get("cwd"), cols=b.get("cols"),
                          rows=b.get("rows"), env=b.get("env"), workspace=b.get("workspace") or "",
                          task_ref=b.get("task_ref") or "", host=b.get("host"))
    time.sleep(0.3 if not p.remote else 0.8)     # the shell's first prompt
    return {"ok": True, **sup.view(p, me=ctx.session)}


def r_term_read(ctx: Ctx) -> dict[str, Any]:
    b = ctx.body
    return {"ok": True, **ctx.daemon.terminals.read(b.get("id"), ctx.session, history=b.get("history") or 0,
                                                    take=bool(b.get("take")), agent=_agent(ctx))}


def r_term_send(ctx: Ctx) -> dict[str, Any]:
    b = ctx.body
    return ctx.daemon.terminals.send(b.get("id"), ctx.session, agent=_agent(ctx), seq=b.get("seq"),
                                     text=b.get("text"), keys=b.get("keys"), enter=b.get("enter"),
                                     delay_ms=b.get("delay_ms"), read_after=b.get("read_after", True))


def r_term_resize(ctx: Ctx) -> dict[str, Any]:
    b = ctx.body
    return ctx.daemon.terminals.resize(b.get("id"), ctx.session, b.get("cols"), b.get("rows"))


def r_term_signal(ctx: Ctx) -> dict[str, Any]:
    b = ctx.body
    return ctx.daemon.terminals.signal(b.get("id"), ctx.session, b.get("signal"))


def r_term_close(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.terminals.close(ctx.body.get("id"), ctx.session)


def r_term_list(ctx: Ctx) -> dict[str, Any]:
    sup = ctx.daemon.terminals
    t = sup.list_bounded(ctx.session, "terminal")
    j = sup.list_bounded(ctx.session, "job")
    out = {"ok": True, "terminals": t["items"], "jobs": j["items"]}
    if t["truncated"] or j["truncated"]:
        out["truncated"] = True
        out["totals"] = {"terminals": t["total"], "jobs": j["total"]}
    return out


def r_job_start(ctx: Ctx) -> dict[str, Any]:
    b = ctx.body
    sup = ctx.daemon.terminals
    p, new = sup.start_job(ctx.session, agent=_agent(ctx), argv=b.get("argv"), command=b.get("command"),
                           cwd=b.get("cwd"), host=b.get("host"), workspace=b.get("workspace") or "",
                           task_ref=b.get("task_ref") or "", on_pause=b.get("on_pause"),
                           idempotency_key=b.get("idempotency_key"), env=b.get("env"))
    return {"ok": True, "new": new, **sup.describe(p, ctx.session)}


def r_job_status(ctx: Ctx) -> dict[str, Any]:
    sup = ctx.daemon.terminals
    return {"ok": True, **sup.describe(sup.job(ctx.body.get("id")), ctx.session)}


def r_job_tail(ctx: Ctx) -> dict[str, Any]:
    b = ctx.body
    return ctx.daemon.terminals.tail(b.get("id"), b.get("bytes") or 8192, b.get("lines"))


def r_job_signal(ctx: Ctx) -> dict[str, Any]:
    sup = ctx.daemon.terminals
    p = sup.job(ctx.body.get("id"))
    return sup.signal(p.id, ctx.session, ctx.body.get("signal"))


def r_job_list(ctx: Ctx) -> dict[str, Any]:
    j = ctx.daemon.terminals.list_bounded(ctx.session, "job")
    out = {"ok": True, "jobs": j["items"]}
    if j["truncated"]:
        out["truncated"] = True
        out["total"] = j["total"]
    return out


# -- remote hosts' runtime (PLAN-v4 phase 6, daemon/remote.py) --------------------------


def r_remote_runtime(ctx: Ctx) -> dict[str, Any]:
    """{host, action: status | provision | clean}: a remote host's runtime
    readiness, staging it now, or removing its unused older versions."""
    from .remote import RemoteError
    b = ctx.body
    action = b.get("action") or "status"
    if action not in ("status", "provision", "clean"):
        raise _err(400, "bad_request", "gateway: action is status, provision or clean")
    d = ctx.daemon
    name = d.remote.resolve(b.get("host"))
    if name is None:
        raise _err(404, "no_host", "gateway: no such remote host in gateway.toml (gate status lists "
                   "them)")
    rh = d.remote.get(name)
    out: dict[str, Any] = {"ok": True, "host": name, "host_id": rh.host_id}
    try:
        if action == "provision":
            rt = rh.ensure_runtime(ctx.session)
            out["runtime_dir"] = rt
        elif action == "clean":
            rh.ensure_runtime(ctx.session)
            out["removed"] = rh.prune_old(rh.info.get("base") or "", f"{rh.info.get('rt_version')}-"
                                          f"{rh.platform}", ctx.session)
    except RemoteError as e:
        out.update({"ok": False, "error": e.code, "message": e.message})
    out.update(rh.summary())
    for k in ("bash", "tmux", "ready_at"):
        if rh.info.get(k):
            out[k] = rh.info[k]
    return out


def r_remote_inspect(ctx: Ctx) -> dict[str, Any]:
    """host_inspect for a remote host (PLAN-v4 phase 7): read-only, through
    the host's verified connection, by its read policy."""
    from .remote import RemoteError
    d = ctx.daemon
    name = d.remote.resolve(ctx.body.get("host"))
    if name is None:
        raise _err(404, "no_host", "gateway: no such remote host in gateway.toml (gate status lists "
                   "them)")
    try:
        return d.remote.get(name).inspect(ctx.session)
    except RemoteError as e:
        return {"ok": False, "error": e.code, "message": e.message}


# -- the gate mod's terminal pane (UI plane) -------------------------------------------


def r_ui_term_list(ctx: Ctx) -> dict[str, Any]:
    return {"ok": True, "terminals": ctx.daemon.terminals.list(ctx.session, "terminal"),
            "jobs": ctx.daemon.terminals.list(ctx.session, "job")}


def r_ui_term_screen(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.terminals.ui_screen(ctx.query.get("id"), ctx.query.get("seq", "0"),
                                          ctx.query.get("wait", "0"))


def r_ui_term_keys(ctx: Ctx) -> dict[str, Any]:
    b = ctx.body
    r = ctx.daemon.terminals.ui_keys(b.get("id"), ctx.session, b.get("items"))
    return {**r, "acked": b.get("seq") if isinstance(b.get("seq"), int) else None}


def r_ui_term_take(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.terminals.ui_take(ctx.body.get("id"), ctx.session)


def r_ui_term_release(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.terminals.ui_release(ctx.body.get("id"), ctx.session)


def r_ui_term_resize(ctx: Ctx) -> dict[str, Any]:
    b = ctx.body
    return ctx.daemon.terminals.resize(b.get("id"), ctx.session, b.get("cols"), b.get("rows"), by="ui")


def r_ui_term_signal(ctx: Ctx) -> dict[str, Any]:
    b = ctx.body
    sup = ctx.daemon.terminals
    sup.ui_take(b.get("id"), ctx.session)
    return sup.signal(b.get("id"), ctx.session, b.get("signal"), by="ui")


def r_ui_term_open(ctx: Ctx) -> dict[str, Any]:
    b = ctx.body
    sup = ctx.daemon.terminals
    p = sup.open_terminal(ctx.session, cwd=b.get("cwd"), cols=b.get("cols"), rows=b.get("rows"),
                          env=b.get("env"), via="ui", host=b.get("host"))
    return {"ok": True, "id": p.id, "owner": p.owner}


def r_ui_term_close(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.terminals.close(ctx.body.get("id"), ctx.session, by="ui")


def r_ui_term_agent(ctx: Ctx) -> dict[str, Any]:
    ctx.daemon.terminals.note_agent(ctx.session, ctx.body.get("tool_use_id"), ctx.body.get("agent"))
    return {"ok": True}


# -- /gate-hosts and /gate-accounts (PLAN-v4 phase 7) ----------------------------


def r_ui_manage(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.ui_manage()


# -- native dialogs (daemon/dialogs.py) ----------------------------------------


def _num(ctx: Ctx, name: str, default: float) -> float:
    try:
        return float(ctx.query.get(name, default))
    except ValueError:
        raise _err(400, "bad_request", f"gateway: {name} is a number") from None


def r_dialog_next(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.dialogs.next(ctx.session, int(_num(ctx, "rev", 0)), _num(ctx, "wait", 0))


def r_dialog_submit(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.dialogs.submit(ctx.session, ctx.body)


def r_dialog_paste(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.dialogs.paste(ctx.session, ctx.body)


def r_dialog_answer(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.dialogs.answer(ctx.session, ctx.body)


def r_dialog_cancel(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.dialogs.cancel(ctx.session, ctx.body)


def r_ui_unlock(ctx: Ctx) -> dict[str, Any]:
    """/gate-unlock: the unlock dialog (a locked vault), or the first-time
    "set a vault passphrase" dialog (an unwrapped one)."""
    return ctx.daemon.vault_dialog(ctx.session)


def r_dialog_lease(ctx: Ctx) -> dict[str, Any]:
    assert ctx.entry is not None
    return ctx.daemon.dialogs.lease(ctx.session, ctx.peer.pid, ctx.entry.mode)


def r_lease_open(ctx: Ctx) -> dict[str, Any]:
    spec = ctx.body.get("dialog")
    if not isinstance(spec, dict):
        raise _err(400, "bad_request", "gateway: no dialog")
    return ctx.daemon.dialogs.open(ctx.body.get("lease"), ctx.peer.pid, spec)


def r_lease_wait(ctx: Ctx) -> dict[str, Any]:
    try:
        wait = float(ctx.body.get("wait") or 0)
    except (TypeError, ValueError):
        wait = 0.0
    return ctx.daemon.dialogs.wait(ctx.body.get("lease"), ctx.peer.pid, ctx.body.get("id"), wait)


def r_lease_retry(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.dialogs.retry(ctx.body.get("lease"), ctx.peer.pid, ctx.body.get("id"),
                                    ctx.body.get("why"))


def r_lease_close(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.dialogs.close(ctx.body.get("lease"), ctx.peer.pid, ctx.body.get("id"),
                                    ctx.body.get("outcome"), ctx.body.get("note") or "")


def r_lease_release(ctx: Ctx) -> dict[str, Any]:
    return ctx.daemon.dialogs.release(ctx.body.get("lease"), ctx.peer.pid)


def r_test_passphrase(ctx: Ctx) -> dict[str, Any]:
    ctx.daemon.broker.set_passphrase(ctx.body.get("passphrase"))
    return {"ok": True, "vault": ctx.daemon.broker.state()}


def r_test_unlock(ctx: Ctx) -> dict[str, Any]:
    ctx.daemon.broker.unlock(ctx.body.get("passphrase"), how="test")
    return {"ok": True, "vault": ctx.daemon.broker.state()}


ROUTES: dict[tuple[str, str], tuple[str, Callable[[Ctx], dict[str, Any]]]] = {
    ("GET", "/health"): ("health", r_health),
    ("POST", "/ui/register"): ("ui-register", r_ui_register),
    ("POST", "/ui/unregister"): ("ui", r_ui_unregister),
    ("POST", "/ui/vault/lock"): ("ui", r_lock),
    ("POST", "/ui/vault/unlock"): ("ui", r_ui_unlock),
    ("GET", "/ui/dialog/next"): ("ui", r_dialog_next),
    ("POST", "/ui/dialog/submit"): ("ui", r_dialog_submit),
    ("POST", "/ui/dialog/paste"): ("ui", r_dialog_paste),
    ("POST", "/ui/dialog/answer"): ("ui", r_dialog_answer),
    ("POST", "/ui/dialog/cancel"): ("ui", r_dialog_cancel),
    ("POST", "/agent/dialog/lease"): ("agent", r_dialog_lease),
    ("POST", "/lease/dialog/open"): ("lease", r_lease_open),
    ("POST", "/lease/dialog/wait"): ("lease", r_lease_wait),
    ("POST", "/lease/dialog/retry"): ("lease", r_lease_retry),
    ("POST", "/lease/dialog/close"): ("lease", r_lease_close),
    ("POST", "/lease/release"): ("lease", r_lease_release),
    ("POST", "/agent/register"): ("agent-register", r_agent_register),
    ("POST", "/agent/vault/status"): ("agent", r_vault_status),
    ("POST", "/agent/vault/read"): ("agent", r_vault_read),
    ("POST", "/agent/vault/write"): ("agent", r_vault_write),
    ("POST", "/agent/vault/cache-read"): ("agent", r_cache_read),
    ("POST", "/agent/vault/cache-write"): ("agent", r_cache_write),
    ("POST", "/agent/vault/open-own"): ("agent", r_open_own),
    ("POST", "/agent/vault/lock"): ("agent", r_lock),
    ("POST", "/local/stop"): ("local", r_local_stop),
    ("POST", "/local/restart"): ("local", r_local_restart),
    ("GET", "/v1/capabilities"): ("contract", r_capabilities),
    ("GET", "/v1/snapshot"): ("contract", r_snapshot),
    ("GET", "/v1/events"): ("contract", r_events),
    ("POST", "/v1/jobs"): ("contract", r_v1_job_start),
    ("GET", "/v1/jobs/{id}"): ("contract", r_v1_job_get),
    ("GET", "/v1/jobs/{id}/tail"): ("contract", r_v1_job_tail),
    ("POST", "/v1/jobs/{id}/signal"): ("contract", r_v1_job_signal),
    ("POST", "/v1/pause"): ("contract", r_pause),
    ("POST", "/v1/resume"): ("contract", r_resume),
    ("POST", "/agent/term/open"): ("agent-term", r_term_open),
    ("POST", "/agent/term/read"): ("agent-term", r_term_read),
    ("POST", "/agent/term/send"): ("agent-term", r_term_send),
    ("POST", "/agent/term/resize"): ("agent-term", r_term_resize),
    ("POST", "/agent/term/signal"): ("agent-term", r_term_signal),
    ("POST", "/agent/term/close"): ("agent-term", r_term_close),
    ("POST", "/agent/term/list"): ("agent-term", r_term_list),
    ("POST", "/agent/job/start"): ("agent-term", r_job_start),
    ("POST", "/agent/job/status"): ("agent-term", r_job_status),
    ("POST", "/agent/job/tail"): ("agent-term", r_job_tail),
    ("POST", "/agent/job/signal"): ("agent-term", r_job_signal),
    ("POST", "/agent/job/list"): ("agent-term", r_job_list),
    ("POST", "/agent/remote/runtime"): ("agent-term", r_remote_runtime),
    ("POST", "/agent/remote/inspect"): ("agent-term", r_remote_inspect),
    ("GET", "/ui/term/list"): ("ui", r_ui_term_list),
    ("GET", "/ui/term/screen"): ("ui", r_ui_term_screen),
    ("POST", "/ui/term/keys"): ("ui", r_ui_term_keys),
    ("POST", "/ui/term/take"): ("ui", r_ui_term_take),
    ("POST", "/ui/term/release"): ("ui", r_ui_term_release),
    ("POST", "/ui/term/resize"): ("ui", r_ui_term_resize),
    ("POST", "/ui/term/signal"): ("ui", r_ui_term_signal),
    ("POST", "/ui/term/open"): ("ui", r_ui_term_open),
    ("POST", "/ui/term/close"): ("ui", r_ui_term_close),
    ("POST", "/ui/term/agent"): ("ui", r_ui_term_agent),
    ("GET", "/ui/manage"): ("ui", r_ui_manage),
}
TEST_ROUTES = {
    ("POST", "/test/vault/passphrase"): ("test", r_test_passphrase),
    ("POST", "/test/vault/unlock"): ("test", r_test_unlock),
}


def routes(test_routes: bool) -> dict[tuple[str, str], tuple[str, Callable[[Ctx], dict[str, Any]]]]:
    out = dict(ROUTES)
    if test_routes:
        out.update(TEST_ROUTES)
    return out


