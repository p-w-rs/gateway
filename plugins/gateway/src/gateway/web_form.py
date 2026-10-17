"""One-time local browser form for entering secret values (and settings).

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
 input, textarea, select {{ width:100%; box-sizing:border-box; padding:10px 12px; font:inherit;
        border:1px solid var(--line); border-radius:8px; background:var(--bg); color:var(--fg); }}
 textarea {{ min-height:96px; font-family:ui-monospace, Menlo, monospace; font-size:13px; }}
 textarea.secret {{ -webkit-text-security:disc; }}
 .field {{ margin-bottom:14px; }} .help {{ color:var(--muted); font-size:13px; margin-top:4px; }}
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
{fields}
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
    """Show a one-field masked form and wait. Returns the submitted value (""
    if optional and left empty), or None if cancelled or timed out. Raises
    Unavailable if no browser could be opened."""
    got = ask_form(title, details, [{"name": "value", "label": label, "type": "password",
                                     "required": not optional}], timeout=timeout)
    return None if got is None else got["value"]


def _field_html(i: int, f: dict[str, Any]) -> str:
    """One form field. type: text | password | textarea (masked) | select."""
    name, kind = f["name"], f.get("type", "text")
    fid = f"f{i}"
    req = " required" if f.get("required") else ""
    auto = " autofocus" if i == 0 else ""
    val = html.escape(f.get("value") or "")
    if kind == "select":
        opts = "".join(f'<option value="{html.escape(v)}"{" selected" if v == f.get("value") else ""}>'
                       f"{html.escape(lbl)}</option>" for v, lbl in f["options"])
        ctl = f'<select id="{fid}" name="{html.escape(name)}"{auto}>{opts}</select>'
    elif kind == "textarea":
        ctl = (f'<textarea id="{fid}" name="{html.escape(name)}" class="secret" spellcheck="false" '
               f'autocomplete="off"{req}{auto}></textarea>')
    else:
        typ = "password" if kind == "password" else "text"
        ac = "new-password" if kind == "password" else "off"
        shown = "" if kind == "password" else f' value="{val}"'
        ctl = (f'<input id="{fid}" name="{html.escape(name)}" type="{typ}" autocomplete="{ac}" '
               f'spellcheck="false"{shown}{req}{auto}>')
    helptext = f'<div class="help">{html.escape(f["help"])}</div>' if f.get("help") else ""
    return (f'<div class="field"><label for="{fid}">{html.escape(f["label"])}</label>'
            f"{ctl}{helptext}</div>")


def ask_form(title: str, details: list[tuple[str, str]], fields: list[dict[str, Any]],
             timeout: float | None = None) -> dict[str, str] | None:
    """Show a form with several fields and wait. Returns {name: value} for
    every field ("" when left empty), or None if cancelled or timed out.
    Masked fields (password, textarea) are never pre-filled. Raises
    Unavailable if no browser could be opened."""
    if timeout is None:
        timeout = float(os.environ.get("GATEWAY_FORM_TIMEOUT") or TIMEOUT)
    path = "/" + secrets.token_urlsafe(16)
    nonce = secrets.token_urlsafe(16)
    state: dict[str, Any] = {"value": None}  # {name: value} once submitted
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
            body = "".join(_field_html(i, f) for i, f in enumerate(fields))
            self._send(200, PAGE.format(title=html.escape(title), details=rows,
                                        nonce=nonce, fields=body))

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
                got = {f["name"]: form.get(f["name"], [""])[0] for f in fields}
                if any(f.get("required") and not got[f["name"]] for f in fields):
                    self._send(400, DONE.format(msg="No value entered; nothing was saved."))
                else:
                    state["value"] = got
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
