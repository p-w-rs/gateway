"""One-time local browser form for entering a secret value.

The gateway serves a single page on 127.0.0.1 at a random port and a random
128-bit path, opens it in the user's browser, and waits for one submission.
The value goes from the browser straight to this process. Claude never sees
it, and the URL is not shown to Claude until the form is finished, so it
can't submit the form itself.

Guards: loopback only; unguessable one-time path; the Host header must be the
loopback address (blocks DNS rebinding); a POST must carry the page's own
nonce; the server stops after one submission, a cancel, or the timeout.

GATEWAY_BROWSER, if set, is a program run as `PROGRAM URL` instead of the
system browser (the tests use it to fill the form).
"""
from __future__ import annotations

import html
import http.server
import os
import secrets
import subprocess
import sys
import threading
import urllib.parse
import webbrowser
from typing import Any

TIMEOUT = 300  # seconds the user has to submit

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>gateway</title>
<style>
 :root {{ color-scheme: light dark; --bg:#f6f6f4; --card:#fff; --fg:#1d1d1b; --muted:#6b6b66;
         --line:#d9d9d4; --accent:#2f5d50; }}
 @media (prefers-color-scheme: dark) {{ :root {{ --bg:#1b1b1a; --card:#262624; --fg:#ececea;
         --muted:#a3a39e; --line:#3a3a37; --accent:#7fb8a6; }} }}
 body {{ margin:0; background:var(--bg); color:var(--fg);
        font:16px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; }}
 main {{ max-width:440px; margin:12vh auto; padding:0 16px; }}
 .card {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:24px; }}
 h1 {{ font-size:18px; margin:0 0 4px; }}
 p {{ margin:0 0 16px; color:var(--muted); font-size:14px; }}
 dl {{ margin:0 0 18px; font-size:14px; }} dt {{ color:var(--muted); }} dd {{ margin:0 0 8px; }}
 label {{ display:block; font-size:14px; margin-bottom:6px; }}
 input[type=password] {{ width:100%; box-sizing:border-box; padding:10px 12px; font:inherit;
        border:1px solid var(--line); border-radius:8px; background:var(--bg); color:var(--fg); }}
 .row {{ display:flex; gap:8px; justify-content:flex-end; margin-top:18px; }}
 button {{ font:inherit; padding:8px 16px; border-radius:8px; border:1px solid var(--line);
          background:transparent; color:var(--fg); cursor:pointer; }}
 button.primary {{ background:var(--accent); border-color:var(--accent); color:var(--card); }}
</style></head>
<body><main><div class="card">
<h1>{title}</h1>
<p>Claude can't see what you type here. It goes straight to the gateway vault.</p>
<dl>{details}</dl>
<form method="post" autocomplete="off">
<input type="hidden" name="nonce" value="{nonce}">
<label for="v">{label}</label>
<input id="v" name="value" type="password" autocomplete="new-password" autofocus {required}>
<div class="row">
<button type="submit" name="action" value="cancel" formnovalidate>Cancel</button>
<button type="submit" name="action" value="save" class="primary">Save</button>
</div></form>
</div></main></body></html>
"""

DONE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>gateway</title><style>:root{{color-scheme:light dark}}
body{{font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
max-width:440px;margin:20vh auto;padding:0 16px}}</style></head>
<body><p>{msg}</p><p>You can close this tab.</p></body></html>"""


class Unavailable(Exception):
    """The form couldn't be shown (no browser could be opened)."""


def ask(title: str, details: list[tuple[str, str]], label: str,
        optional: bool = False, timeout: float | None = None) -> str | None:
    """Show the form and wait. Returns the submitted value ("" if optional and
    left empty), or None if cancelled or timed out. Raises Unavailable if no
    browser could be opened."""
    if timeout is None:
        timeout = float(os.environ.get("GATEWAY_FORM_TIMEOUT") or TIMEOUT)
    path = "/" + secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    state: dict[str, Any] = {"value": None}
    done = threading.Event()

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):  # keep the console clean
            pass

        def _host_ok(self) -> bool:
            port = self.server.server_address[1]
            return self.headers.get("Host", "") in (f"127.0.0.1:{port}", f"localhost:{port}")

        def _send(self, code: int, body: str) -> None:
            data = body.encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Content-Security-Policy",
                             "default-src 'none'; style-src 'unsafe-inline'; "
                             "form-action 'self'; frame-ancestors 'none'")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):
            if self.path != path or not self._host_ok() or done.is_set():
                self._send(404, "Not found")
                return
            rows = "".join(f"<dt>{html.escape(k)}</dt><dd>{html.escape(v)}</dd>"
                           for k, v in details if v)
            self._send(200, PAGE.format(title=html.escape(title), details=rows,
                                        nonce=nonce, label=html.escape(label),
                                        required="" if optional else "required"))

        def do_POST(self):
            if self.path != path or not self._host_ok() or done.is_set():
                self._send(404, "Not found")
                return
            length = min(int(self.headers.get("Content-Length") or 0), 65536)
            form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"),
                                         keep_blank_values=True)
            if form.get("nonce", [""])[0] != nonce:
                self._send(403, "Forbidden")
                return
            if form.get("action", [""])[0] == "cancel":
                self._send(200, DONE.format(msg="Cancelled. Nothing was saved."))
            else:
                value = form.get("value", [""])[0]
                if not value and not optional:
                    self._send(400, DONE.format(msg="No value entered; nothing was saved."))
                else:
                    state["value"] = value
                    self._send(200, DONE.format(msg="Saved to the gateway vault."))
            done.set()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    url = f"http://127.0.0.1:{server.server_address[1]}{path}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if not _open(url):
            raise Unavailable("no browser could be opened on this machine")
        done.wait(timeout)
    finally:
        server.shutdown()
        server.server_close()
    return state["value"]


def _open(url: str) -> bool:
    prog = os.environ.get("GATEWAY_BROWSER")
    if prog:
        if prog.lower() == "none":
            return False
        subprocess.Popen([prog, url], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    if not gui_available():
        return False
    try:
        return bool(webbrowser.open(url, new=2))
    except Exception:
        return False


def gui_available() -> bool:
    """Is there a desktop to open a browser on? Without one (ssh, a headless
    server), Python's webbrowser may fall back to a console browser such as
    lynx, which would hang the hook, so the caller falls back to the terminal
    instead."""
    if os.environ.get("GATEWAY_BROWSER"):
        return os.environ["GATEWAY_BROWSER"].lower() != "none"
    if sys.platform == "darwin":
        return not os.environ.get("SSH_CONNECTION")
    if sys.platform == "win32":
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
