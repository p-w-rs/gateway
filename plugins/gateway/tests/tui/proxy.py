"""A record-only telemetry proxy for the TUI harness (brief 14.13).

Claude Code's first-party telemetry (api.anthropic.com event logging, feature
gates, bootstrap) is encrypted on the wire and the `anthropic` telemetry
stream can't be hooked by a third-party mod, so the only way to see what it
would send is to be its HTTPS endpoint: this module runs mitmproxy (`pixi
exec --spec mitmproxy==MITM_VERSION mitmdump`, a scratch environment) on
127.0.0.1 with a record-only addon that answers EVERY request itself (204,
an empty body) and never forwards anything. Its CA (generated in the scratch
`confdir`) reaches Claude Code through NODE_EXTRA_CA_CERTS; HTTPS_PROXY and
HTTP_PROXY point at it; NO_PROXY keeps 127.0.0.1 (the fake API) direct.

    with RecordProxy(root / "proxy") as px:
        s = Session(root / "s", extra_env=px.env(), ...)
        ...
        px.requests()             # [{n, method, host, path, len, encoding}]
        px.bodies_dir             # one file per request body: N.raw and N.dec
                                  # (decoded content-encoding), for scan.Report

px.env() also removes CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC,
DISABLE_TELEMETRY and DISABLE_ERROR_REPORTING (telemetry ON) and sets
TUI_RECORD_PROXY to the proxy URL. safety.hermetic_env lets the
disable flags go only when TUI_RECORD_PROXY, HTTPS_PROXY, HTTP_PROXY (and
their lower-case spellings) all name the same loopback URL: with the
harness's own proxy in the way nothing leaves the machine. (Probe evidence:
gateway docs/dev/FEASIBILITY-v4.md P6, 8 decrypted first-party requests in one
session, none forwarded.) What a client sends outside its proxy settings
(none was seen) would not be recorded here: say so in reports.

Imports nothing from either plugin.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from pathlib import Path

from . import safety

MITM_VERSION = "12.2.3"

ADDON = r'''"""Record-only: every request is written to disk and answered here (204)."""
import json, os, time
from mitmproxy import http

LOG = os.environ["TUI_PROXY_LOG"]
BODIES = os.environ["TUI_PROXY_BODIES"]
_n = [0]


def request(flow: http.HTTPFlow) -> None:
    _n[0] += 1
    n = _n[0]
    raw = flow.request.raw_content or b""
    try:
        dec = flow.request.get_content(strict=False) or b""
    except Exception:
        dec = raw
    with open(os.path.join(BODIES, f"{n:05d}.raw"), "wb") as f:
        f.write(raw)
    with open(os.path.join(BODIES, f"{n:05d}.dec"), "wb") as f:
        f.write(dec)
    rec = {"n": n, "t": time.time(), "method": flow.request.method,
           "host": flow.request.pretty_host, "path": flow.request.path.split("?")[0],
           "len": len(raw), "encoding": flow.request.headers.get("content-encoding", "")}
    with open(LOG, "a") as f:
        f.write(json.dumps(rec) + "\n")
    flow.response = http.Response.make(204, b"", {"content-type": "application/json"})
'''


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class RecordProxy:
    def __init__(self, root: os.PathLike | str):
        self.root = safety.check_scratch(Path(root), "proxy root")
        self.root.mkdir(parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.conf = self.root / "conf"
        self.bodies_dir = self.root / "bodies"
        self.log_path = self.root / "requests.jsonl"
        self.addon = self.root / "record_addon.py"
        self.port: int | None = None
        self.proc: subprocess.Popen | None = None

    @property
    def url(self) -> str:
        assert self.port is not None, "start() first"
        return f"http://127.0.0.1:{self.port}"

    @property
    def ca(self) -> Path:
        return self.conf / "mitmproxy-ca-cert.pem"

    def start(self, timeout: float = 300.0) -> "RecordProxy":
        self.conf.mkdir(exist_ok=True)
        self.bodies_dir.mkdir(exist_ok=True)
        self.addon.write_text(ADDON)
        self.log_path.touch()
        self.port = _free_port()
        env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "TMPDIR") if k in os.environ}
        for k in ("PIXI_CACHE_DIR", "RATTLER_CACHE_DIR"):
            if os.environ.get(k):
                env[k] = os.environ[k]
        env.update({"TUI_PROXY_LOG": str(self.log_path), "TUI_PROXY_BODIES": str(self.bodies_dir)})
        argv = ["pixi", "exec", "--spec", f"mitmproxy=={MITM_VERSION}", "mitmdump", "-q",
                "--listen-host", "127.0.0.1", "-p", str(self.port),
                "--set", f"confdir={self.conf}", "-s", str(self.addon)]
        self.proc = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL,
                                     stdout=open(self.root / "mitmdump.out", "wb"),
                                     stderr=subprocess.STDOUT, start_new_session=True)
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                raise RuntimeError("mitmdump exited: " + (self.root / "mitmdump.out").read_text()[-500:])
            if self.ca.exists() and self._listening():
                return self
            time.sleep(0.25)
        self.close()
        raise TimeoutError("the record-only proxy didn't start")

    def _listening(self) -> bool:
        try:
            with socket.create_connection(("127.0.0.1", self.port), timeout=0.5):
                return True
        except OSError:
            return False

    def env(self) -> dict:
        """Session/hermetic_env extras: everything through this proxy,
        telemetry on (see the module docstring)."""
        u = self.url
        return {"HTTPS_PROXY": u, "HTTP_PROXY": u, "https_proxy": u, "http_proxy": u,
                "TUI_RECORD_PROXY": u, "NODE_EXTRA_CA_CERTS": str(self.ca),
                "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": None, "DISABLE_TELEMETRY": None,
                "DISABLE_ERROR_REPORTING": None}

    def requests(self) -> list[dict]:
        try:
            return [json.loads(ln) for ln in self.log_path.read_text().splitlines() if ln.strip()]
        except OSError:
            return []

    def close(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            safety.kill_tree(self.proc.pid)
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                pass
        self.proc = None

    def __enter__(self) -> "RecordProxy":
        return self.start()

    def __exit__(self, *exc) -> None:
        self.close()
