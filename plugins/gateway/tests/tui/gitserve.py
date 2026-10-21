"""Local smart-HTTP git server for hermetic marketplace installs (stdlib only).

Serves every bare repository under --root at http://127.0.0.1:PORT/<name>.git
by running `git http-backend` as CGI for each request (clone, fetch and
ls-remote over protocol v0/v2; read-only: receive-pack is refused). Claude
Code clones git marketplaces with the system `git clone --depth 1`, so this
is what a GitHub-hosted marketplace looks like to it, without network.

    python gitserve.py --root DIR --port 0 --port-file F [--log FILE]

install.GitServer starts and stops it; it is ported from the packaging
audit's githttp.py (threaded, port 0, isolated git config, push refused).
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def backend_path() -> str:
    exec_path = subprocess.check_output(["git", "--exec-path"], text=True).strip()
    return os.path.join(exec_path, "git-http-backend")


class Handler(BaseHTTPRequestHandler):
    root = ""
    backend = ""
    logf = None

    def _run(self):
        u = urlsplit(self.path)
        if "git-receive-pack" in u.path or "service=git-receive-pack" in u.query:
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": self.root,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_PROJECT_ROOT": self.root,
            "GIT_HTTP_EXPORT_ALL": "1",
            "REQUEST_METHOD": self.command,
            "PATH_INFO": u.path,
            "QUERY_STRING": u.query,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "CONTENT_LENGTH": str(len(body)),
            "REMOTE_ADDR": "127.0.0.1",
            "GIT_PROTOCOL": self.headers.get("Git-Protocol", ""),
        }
        if self.headers.get("Content-Encoding"):
            env["HTTP_CONTENT_ENCODING"] = self.headers["Content-Encoding"]
        p = subprocess.run([self.backend], input=body, env=env, capture_output=True)
        out = p.stdout
        head, sep, rest = out.partition(b"\r\n\r\n")
        if not sep:
            head, sep, rest = out.partition(b"\n\n")
        status = 200
        headers = []
        for line in head.decode("latin-1").splitlines():
            if not line.strip():
                continue
            k, _, v = line.partition(":")
            if k.lower() == "status":
                status = int(v.strip().split()[0])
            else:
                headers.append((k.strip(), v.strip()))
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(rest)))
        self.end_headers()
        self.wfile.write(rest)
        if self.logf:
            self.logf.write(f"{time.time():.3f} {self.command} {self.path} {status}\n")
            self.logf.flush()

    do_GET = _run
    do_POST = _run

    def log_message(self, fmt, *args):
        pass


class _Server(ThreadingHTTPServer):
    daemon_threads = True


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="smart-HTTP git server on 127.0.0.1")
    ap.add_argument("--root", required=True)
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--port-file")
    ap.add_argument("--log")
    a = ap.parse_args(argv)
    handler = type("BoundHandler", (Handler,), {
        "root": os.path.realpath(a.root), "backend": backend_path(),
        "logf": open(a.log, "a") if a.log else None})
    srv = _Server(("127.0.0.1", a.port), handler)
    port = srv.server_address[1]
    if a.port_file:
        tmp = a.port_file + ".tmp"
        with open(tmp, "w") as f:
            f.write(str(port))
        os.replace(tmp, a.port_file)
    print(f"GITSERVE PORT {port}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    sys.exit(main())
