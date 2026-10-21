"""A stand-in for the Claude Code process in the daemon tests.

tests/harness_daemon.py runs this script with a copy of the env's python
named `claude` (so the kernel reports an executable whose name is Claude
Code's, as for the real thing). It answers JSON lines on stdin:

    {"op": "http", "method", "path", "body"?, "sock"}   a request from THIS
        process (the UI plane: the daemon sees the claude pid itself)
    {"op": "run", "argv", "env"?, "input"?, "timeout"?}  a child process (the
        agent and contract planes: a process below the claude pid)
    {"op": "spawn", "argv", "env"?}  /  {"op": "wait", "pid", "timeout"?}
    {"op": "exit"}

and prints one JSON line per request. Stdlib only, nothing of the gateway's.
"""
import http.client
import json
import os
import socket
import subprocess
import sys

KIDS: dict[int, subprocess.Popen] = {}


class _Unix(http.client.HTTPConnection):
    def __init__(self, path: str):
        super().__init__("gated", timeout=30)
        self._p = path

    def connect(self) -> None:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(30)
        s.connect(self._p)
        self.sock = s


def http_req(req: dict) -> dict:
    c = _Unix(req["sock"])
    try:
        body = json.dumps(req["body"]).encode() if req.get("body") is not None else None
        c.request(req["method"], req["path"], body=body, headers={"Connection": "close"})
        r = c.getresponse()
        raw = r.read()
        try:
            obj = json.loads(raw or b"{}")
        except ValueError:
            obj = {"raw": raw.decode("utf-8", "replace")}
        return {"status": r.status, "body": obj}
    except OSError as e:
        return {"status": 0, "body": {"error": type(e).__name__}}
    finally:
        c.close()


def main() -> int:
    print(json.dumps({"pid": os.getpid()}), flush=True)
    for line in sys.stdin:
        try:
            req = json.loads(line)
        except ValueError:
            continue
        op = req.get("op")
        if op == "exit":
            break
        if op == "http":
            out = http_req(req)
        elif op == "run":
            try:
                r = subprocess.run(req["argv"], env=req.get("env"), input=req.get("input"),
                                   capture_output=True, text=True, timeout=req.get("timeout", 60),
                                   cwd=req.get("cwd"))
                out = {"rc": r.returncode, "stdout": r.stdout, "stderr": r.stderr}
            except (OSError, subprocess.TimeoutExpired) as e:
                out = {"rc": -1, "stdout": "", "stderr": type(e).__name__}
        elif op == "spawn":
            p = subprocess.Popen(req["argv"], env=req.get("env"), stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                 cwd=req.get("cwd"))
            KIDS[p.pid] = p
            out = {"pid": p.pid}
        elif op == "wait":
            p = KIDS.pop(int(req["pid"]), None)
            if p is None:
                out = {"rc": -1, "stdout": "", "stderr": "unknown pid"}
            else:
                try:
                    o, e = p.communicate(timeout=req.get("timeout", 60))
                    out = {"rc": p.returncode, "stdout": o, "stderr": e}
                except subprocess.TimeoutExpired:
                    p.kill()
                    o, e = p.communicate()
                    out = {"rc": -9, "stdout": o, "stderr": e}
        else:
            out = {"error": "unknown op"}
        print(json.dumps(out), flush=True)
    for p in KIDS.values():
        try:
            p.kill()
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
