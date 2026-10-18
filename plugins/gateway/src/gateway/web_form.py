"""Opening the user's browser for sign-ins (GitHub's device code notice,
Entra's redirect page). Secret values are no longer entered in a browser
form: they go in a native dialog (dialog.py).

GATEWAY_BROWSER, if set, is a program run as `PROGRAM URL` instead of the
system browser (the tests use it); `none` means no browser.
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

DONE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>gateway</title><style>:root{{color-scheme:light dark}}
body{{font:16px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
max-width:440px;margin:20vh auto;padding:0 16px}}</style></head>
<body><p>{msg}</p><p>You can close this tab.</p></body></html>"""


class Unavailable(Exception):
    """The form couldn't be shown (no browser could be opened)."""


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


NOTICE = """<!doctype html>
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
 h1 {{ font-size:18px; margin:0 0 4px; }} p {{ margin:0 0 16px; color:var(--muted); font-size:14px; }}
 .code {{ font:600 28px/1.2 ui-monospace, Menlo, monospace; letter-spacing:2px; margin:8px 0 18px; }}
 a.go {{ display:inline-block; padding:8px 16px; border-radius:8px; background:var(--accent);
        color:var(--card); text-decoration:none; }}
 .row {{ display:flex; gap:8px; justify-content:space-between; align-items:center; margin-top:18px; }}
 button {{ font:inherit; padding:8px 16px; border-radius:8px; border:1px solid var(--line);
          background:transparent; color:var(--fg); cursor:pointer; }}
</style></head>
<body><main><div class="card">
<h1>{title}</h1>
<p>{text}</p>
<div class="code">{code}</div>
<form method="post" class="row">
<a class="go" href="{link}" target="_blank" rel="noopener noreferrer">{link_label}</a>
<input type="hidden" name="nonce" value="{nonce}">
<button type="submit" name="action" value="cancel">Cancel</button>
</form>
</div></main></body></html>
"""


class Notice:
    """A one-time page that shows a code and a link (an SSO sign-in) while
    the caller waits on something else. `cancelled` is set if the user
    presses Cancel. Same guards as ask_form."""

    def __init__(self, title: str, text: str, code: str, link: str, link_label: str):
        self.cancelled = threading.Event()
        path = "/" + secrets.token_urlsafe(16)
        nonce = secrets.token_urlsafe(16)
        page = NOTICE.format(title=html.escape(title), text=html.escape(text),
                             code=html.escape(code), link=html.escape(link, quote=True),
                             link_label=html.escape(link_label), nonce=nonce)
        cancelled = self.cancelled

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _ok(self) -> bool:
                port = self.server.server_address[1]
                return self.path == path and self.headers.get("Host", "") in (
                    f"127.0.0.1:{port}", f"localhost:{port}")

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
                self._send(200, page) if self._ok() else self._send(404, "Not found")

            def do_POST(self):
                if not self._ok():
                    self._send(404, "Not found")
                    return
                length = min(int(self.headers.get("Content-Length") or 0), 4096)
                form = urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
                if form.get("nonce", [""])[0] != nonce:
                    self._send(403, "Forbidden")
                    return
                cancelled.set()
                self._send(200, DONE.format(msg="Cancelled. Nothing was saved."))

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}{path}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        if not _open(self.url):
            self.close()
            raise Unavailable("no browser could be opened on this machine")

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
