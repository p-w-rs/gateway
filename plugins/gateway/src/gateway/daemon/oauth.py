"""The browser sign-in, run by gated (PLAN-0.11 §7): authorization code + PKCE.

`gate check NAME` (or `gate login NAME`) for an azure account with
sign_in = "browser", or for an ml-catalog account, takes a sign-in lease:
POST /agent/signin/start {account} on the signin plane (gate, below a
registered session: planes.check_signin; a session that can't draw the
confirm dialog gets the dialogs' "unavailable" answer). One sign-in per user
at a time. gated reads the account itself (the form and the approved rights,
consent.compute: never a value from the caller), validates what it will
show, and opens its own confirm dialog (owner "gated"; the mod draws it from
a fixed template, hooks/mod/dialog.ts) naming the account, the tenant, the
client id (for a catalog also its host, and the client id pinned before when
the catalog now gives another) and the scope, with Open and Cancel. Nothing
happens before Open.

On Open (the dialog's handler):
  - the display and desktop variables come with the mod's answer (the UI
    plane only: the registered Claude Code process), and SSH_CONNECTION; on
    Linux with neither DISPLAY nor WAYLAND_DISPLAY, or on macOS in an ssh
    session (the browser would open on the Mac's own screen), the outcome is
    the fixed no-display text, nothing opened;
  - a listener on 127.0.0.1, port 0: the one TCP endpoint gated opens. A TCP
    peer has no uid, so `state` and the PKCE verifier bind the callback
    (the exception to the daemon's uid check);
  - `state` and a PKCE verifier with its S256 challenge;
  - <run>/signin-active (hooks/tool_guard.sh denies the browser-automation
    tools while it exists: they could read the page while the person types);
  - the system browser by absolute path (`/usr/bin/open`, or xdg-open from
    fixed folders): never $BROWSER, a PATH lookup or a pane Claude can read.

The listener serves only GET /cb: headers capped at MAX_HEAD, read within
CONN_TIMEOUT of the connection's start (one deadline for the whole
connection, however slowly it sends), a thread each and at most MAX_CONNS
at once (one more is closed unanswered). A wrong or missing state gets a fixed 400
page and the listener keeps waiting (one bad request is no denial of
service); an `error` gives a fixed failure page and outcome (its
error_description is never shown or kept); the first valid code is exchanged
at the token endpoint through entra.urlopen (no redirects, no proxies, the
build's CA bundle), the tokens go straight into the vault under the
account's `entra` record (kind "browser"; an ml-catalog account also pins its
API scope), the access token into cache.age, and the listener closes. It
waits `timeout()` at most (SIGNIN_TIMEOUT) for that callback; once one is
accepted, its exchange and store decide the outcome (never the timer), a
store that finds the sign-in ended (gated stopping) writes nothing, and
gated stopping waits for a store already writing: an outcome that says
nothing was stored is always true. The program that asked waits
with POST /agent/signin/wait (its lease token; gated keeps only its sha256)
and gets a fixed outcome. The code, the verifier and the tokens never leave
this process.

ml-catalog (§7.4): the authority is entra.authority() with the account's
own tenant ("organizations" by default), the client id comes from the bound
catalog's /api/config (a GUID; read at each sign-in, never cached here), and
the scope is fixed (entra.catalog_scopes). A catalog can't name the
authority, the tenant or the scope.

Tests (gated-test.json, only under a test override): `browser` names the
program run instead of the system browser (it gets the URL as its argument);
`browser_platform` the platform the display rule follows; `signin_timeout`
a shorter wait.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

from .. import paths, testing, vault

SIGNIN_TIMEOUT = 300.0          # the confirm dialog's life, and the wait after Open
LOOPBACK = "127.0.0.1"
MAX_HEAD = 8192                  # a callback's request line and headers
CONN_TIMEOUT = 10.0              # a connection's whole life until its request is read
MAX_CONNS = 16                   # connections handled at once (one thread each)
WAIT_MAX = 25.0
DONE_KEEP = 600.0                # a finished sign-in's outcome stays for its waiters
BROWSER_WAIT = 10.0              # how long the opener may take before it counts as started
STORE_WAIT = 15.0                # how long an ending (gated stopping) waits for a store writing
CODE_MAX = 8192
ACTIVE_FILE = "signin-active"
WHAT = "browser sign-in"
LINUX_DIRS = ("/usr/bin", "/usr/local/bin", "/bin")
# The variables of the Open answer, as the mod sends them from Claude Code's
# own environment (dialogs.SIGNIN_ENV), each checked here: the display and
# desktop variables xdg-open needs (BROWSER_ENV: the display, and the desktop
# that picks the opener and the folders of the browser's .desktop file), and
# SSH_CONNECTION, which only tells a session over ssh (display_problem).
_PATH = r"/[A-Za-z0-9._/@+-]{0,300}"
ENV_PATTERNS = {
    "DISPLAY": re.compile(r"[A-Za-z0-9._-]{0,64}:[0-9]{1,5}(?:\.[0-9]{1,3})?"),
    "WAYLAND_DISPLAY": re.compile(r"[A-Za-z0-9._/-]{1,200}"),
    "XAUTHORITY": re.compile(r"/[A-Za-z0-9._/@+-]{1,300}"),
    "XDG_RUNTIME_DIR": re.compile(r"/[A-Za-z0-9._/@+-]{1,300}"),
    "DBUS_SESSION_BUS_ADDRESS": re.compile(r"[A-Za-z0-9._/@+=:,%-]{1,300}"),
    "XDG_CURRENT_DESKTOP": re.compile(r"[A-Za-z0-9_.-]{1,40}(?::[A-Za-z0-9_.-]{1,40}){0,5}"),
    "XDG_DATA_DIRS": re.compile(rf"{_PATH}(?::{_PATH}){{0,15}}"),
    "SSH_CONNECTION": re.compile(r"[0-9A-Fa-f.:%]{1,64} [0-9]{1,5} [0-9A-Fa-f.:%]{1,64} [0-9]{1,5}"),
}
ENV_MAX = 1000                   # any one value's length
BROWSER_ENV = ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR",
               "DBUS_SESSION_BUS_ADDRESS", "XDG_CURRENT_DESKTOP", "XDG_DATA_DIRS")
TENANT_RE = re.compile(r"[A-Za-z0-9.-]{1,100}")
_TOKEN = re.compile(r"[0-9a-f]{64}")
_ERROR_WORD = re.compile(r"[a-z_]{1,40}")

# The outcomes `gate` prints (fixed texts; NAME is a validated entry name).
OK_TEXT = "gateway: {name} is signed in (a browser sign-in); its tokens are in the gateway's vault"
CANCELLED_TEXT = ("gateway: the user cancelled the browser sign-in for {name}; don't ask again "
                  "unless they say so")
DIALOG_TIMEOUT_TEXT = ("gateway: nobody answered the browser sign-in dialog for {name}; ask the "
                       "user when they're back")
PAUSED_TEXT = ("gateway: the task is paused (checkpoint), so the browser sign-in for {name} "
               "wasn't started; it can be after the user resumes the task")
TIMEOUT_TEXT = ("gateway: the browser sign-in for {name} didn't finish in time; nothing was "
                "stored. If the browser showed an error about the redirect address, the app "
                "registration (its client id) may not allow a public client's http://127.0.0.1 "
                "redirect: ask the user, then run gate check {name} again")
DECLINED_TEXT = ("gateway: the sign-in was declined or failed in the browser for {name}; nothing "
                 "was stored. Run gate check {name} again if the user wants to retry")
FAILED_TEXT = ("gateway: the browser sign-in for {name} didn't complete ({why}); nothing was "
               "stored. Run gate check {name} again")
BROWSER_TEXT = ("gateway: the system browser couldn't be opened for the sign-in of {name} "
                "({why}); nothing was stored")
CHANGED_TEXT = ("gateway: {name} changed in gateway.toml while the sign-in ran; nothing was "
                "stored. Run gate check {name} again")
LOCKED_TEXT = ("gateway: the gateway vault is locked, so the sign-in for {name} can't store its "
               "tokens; the user unlocks it (/gate-unlock), then run gate check {name} again")
STOPPED_TEXT = ("gateway: the gateway daemon stopped during the browser sign-in for {name}; "
                "nothing was stored. Run gate check {name} again")
BUSY_TEXT = ("gateway: another browser sign-in is open; it ends when the user finishes or "
             "cancels it (within 5 minutes). Run gate check {name} again after that")

# The pages the browser shows (fixed).
PAGE_OK = "Signed in. You can close this tab and go back to Claude Code."
PAGE_FAIL = "The sign-in didn't complete. You can close this tab; Claude Code says what to do next."
PAGE_BAD = "This isn't the gateway's current sign-in. You can close this tab."
PAGE_NOT_FOUND = "Not found."
_REASONS = {200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
            409: "Conflict", 410: "Gone", 431: "Request Header Fields Too Large"}


class SignInError(Exception):
    """A refused sign-in call or a failed step: (http status, code, message);
    the message is a fixed text."""

    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


class BrowserError(Exception):
    """The system browser couldn't be opened (fixed reason)."""


def no_display_text(why: str = "") -> str:
    from .. import popup
    return popup.signin_unavailable(why)


def timeout() -> float:
    v = testing.get("signin_timeout") if testing.active() is not None else None
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) and v > 0 \
        else SIGNIN_TIMEOUT


def active_path():
    return paths.run_dir() / ACTIVE_FILE


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def pkce_challenge(verifier: str) -> str:
    """S256: base64url(sha256(verifier)), unpadded (RFC 7636)."""
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()) \
        .rstrip(b"=").decode("ascii")


def clean_env(given: Any) -> dict[str, str]:
    """The variables of the Open answer that pass their patterns."""
    out: dict[str, str] = {}
    if not isinstance(given, dict):
        return out
    for k, pat in ENV_PATTERNS.items():
        v = given.get(k)
        if isinstance(v, str) and len(v) <= ENV_MAX and pat.fullmatch(v):
            out[k] = v
    return out


# ---------------------------------------------------------------------------
# What a sign-in asks for (read by gated itself)
# ---------------------------------------------------------------------------


class Params:
    """One sign-in's settings, all validated: what the confirm dialog shows
    and what the authorization and token requests carry."""

    def __init__(self, name: str, kind: str, authority: str, tenant: str, client_id: str,
                 scope: str, *, host: str = "", api_scope: str = "", previous_client: str = ""):
        self.name, self.kind, self.authority = name, kind, authority.rstrip("/")
        self.tenant, self.client_id, self.scope = tenant, client_id, scope
        self.host, self.api_scope, self.previous_client = host, api_scope, previous_client

    @property
    def token_url(self) -> str:
        return f"{self.authority}/{urllib.parse.quote(self.tenant, safe='')}/oauth2/v2.0/token"

    @property
    def cache_scope(self) -> str:
        """The scope its access token is cached under (entra.access_token's
        key), or "" when it asked for more than one."""
        if self.kind == "ml-catalog":
            return self.api_scope
        toks = [t for t in self.scope.split() if t != "offline_access"]
        return toks[0] if len(toks) == 1 else ""

    def view(self) -> dict[str, str]:
        """The confirm dialog's fields (the mod's fixed template)."""
        return {"account": self.name, "kind": self.kind, "tenant": self.tenant,
                "client": self.client_id, "scope": self.scope, "host": self.host,
                "previous_client": self.previous_client}


def _shown(value: str, rx: re.Pattern[str]) -> bool:
    return isinstance(value, str) and bool(rx.fullmatch(value))


def params_for(d: Any, name: Any) -> Params:
    """The sign-in settings of account `name` from gated's own reading of the
    form and the approved rights; SignInError (a fixed text) otherwise."""
    from .. import accounts as acctmod
    from .. import consent, entra
    from .. import form as formmod
    if not isinstance(name, str) or not formmod.NAME_RE.fullmatch(name) or not formmod.safe(name):
        raise SignInError(400, "bad_request", "gateway: name the account to sign in to")
    try:
        data = d.broker.read(touch=False) if paths.vault_path().exists() else vault.empty()
    except vault.VaultLocked:
        raise SignInError(423, "locked", LOCKED_TEXT.format(name=name)) from None
    except vault.VaultError:
        raise SignInError(400, "vault", "gateway: the vault can't be read, so no sign-in can "
                          "start (gate status shows why)") from None
    f = formmod.load(last_good=data.get("form_last_good"))
    eff = consent.compute(f, data)
    a, ea = f.accounts.get(name), eff.accounts.get(name)
    if a is None or ea is None:
        raise SignInError(404, "no_account", f"gateway: {name} isn't an account in gateway.toml")
    if a.kind not in ("azure", "ml-catalog"):
        raise SignInError(400, "kind", f"gateway: {name} is a {a.kind} account, which has no "
                          "browser sign-in")
    if ea.new:
        raise SignInError(409, "pending", f"gateway: {name} waits for the user's OK first; run "
                          f"gate check {name} while they're here")
    rec = (data.get("accounts") or {}).get(name) or {}
    if a.kind == "azure":
        if ea.sign_in != "browser":
            raise SignInError(409, "sign_in", f"gateway: {name} isn't approved to sign in through "
                              f"the browser (sign_in = \"browser\"); run gate check {name} while "
                              "the user is here")
        tenant, client = ea.tenant or "", ea.client_id or ""
        if not _shown(tenant, TENANT_RE) or not formmod.GUID_RE.fullmatch(client):
            raise SignInError(400, "settings", f"gateway: {name} needs a tenant and a client_id "
                              "for a browser sign-in")
        scope = acctmod.request_scope(ea)
        if not all(formmod.SCOPE_TOKEN_RE.fullmatch(t) for t in scope.split()):
            raise SignInError(400, "settings", f"gateway: {name}'s scope isn't valid")
        authority = entra.authority()
        return Params(name, "azure", authority, tenant, client, scope)
    # ml-catalog: the authority and the scope are fixed, the tenant is the
    # account's own; only the client id comes from the (bound) catalog
    host = a.host
    if not host or host not in ea.destinations or not consent.bound_ok(data, name, host):
        raise SignInError(409, "unbound", f"gateway: {name} isn't bound to its catalog yet; run "
                          f"gate check {name} while the user is here")
    if not formmod.safe(host):
        raise SignInError(400, "settings", f"gateway: {name}'s host can't be shown in a dialog")
    tenant = ea.tenant or formmod.CATALOG_TENANT
    if not _shown(tenant, TENANT_RE):
        raise SignInError(400, "settings", f"gateway: {name}'s tenant isn't valid")
    from .. import asiml
    try:
        cfg = asiml.fetch_catalog_config(host, timeout=15)
    except asiml.AsimlError as e:
        raise SignInError(502, "catalog", str(e)) from None
    client = str(cfg.get("clientId") or "")
    if not formmod.GUID_RE.fullmatch(client):
        raise SignInError(502, "catalog", "gateway: the catalog's /api/config has no valid clientId")
    api, scope = entra.catalog_scopes(client)
    authority = entra.authority()
    ent = rec.get("entra") or {}
    before = str(ent.get("client_id") or "") if ent.get("kind") == "browser" else ""
    previous = before if before != client and formmod.GUID_RE.fullmatch(before) else ""
    return Params(name, "ml-catalog", authority, tenant, client, scope, host=host, api_scope=api,
                  previous_client=previous)


def authorize_url(p: Params, redirect: str, state: str, challenge: str) -> str:
    q = {"client_id": p.client_id, "response_type": "code", "redirect_uri": redirect,
         "response_mode": "query", "scope": p.scope, "state": state,
         "code_challenge": challenge, "code_challenge_method": "S256"}
    return (f"{p.authority}/{urllib.parse.quote(p.tenant, safe='')}/oauth2/v2.0/authorize?"
            + urllib.parse.urlencode(q, quote_via=urllib.parse.quote))


def exchange(p: Params, code: str, verifier: str, redirect: str) -> dict[str, Any]:
    """The code and the PKCE verifier for tokens, at the token endpoint,
    through entra.urlopen (no redirects: a 3xx is a failure; no proxies; the
    build's CA bundle). SignInError with a fixed reason otherwise."""
    from .. import entra
    form = {"client_id": p.client_id, "grant_type": "authorization_code", "code": code,
            "redirect_uri": redirect, "code_verifier": verifier, "scope": p.scope}
    req = urllib.request.Request(p.token_url, data=urllib.parse.urlencode(form).encode(),
                                 headers={"Content-Type": "application/x-www-form-urlencoded",
                                          "Accept": "application/json"})
    try:
        with entra.urlopen(req, timeout=30) as r:
            tok = json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if entra.is_redirect(e):
            raise SignInError(502, "failed", "the token endpoint answered with a redirect, which "
                              "the gateway doesn't follow") from None
        word = ""
        try:
            word = json.loads(e.read().decode("utf-8")).get("error") or ""
        except Exception:  # noqa: BLE001
            pass
        word = word if isinstance(word, str) and _ERROR_WORD.fullmatch(word) else f"HTTP {e.code}"
        raise SignInError(502, "failed", f"Entra refused the code: {word}") from None
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise SignInError(502, "failed", f"Entra couldn't be reached: {type(e).__name__}") from None
    if not isinstance(tok, dict) or not isinstance(tok.get("refresh_token"), str) \
            or not tok["refresh_token"]:
        raise SignInError(502, "failed", "Entra gave no refresh token")
    return tok


# ---------------------------------------------------------------------------
# The system browser
# ---------------------------------------------------------------------------


def platform() -> str:
    p = testing.get("browser_platform") if testing.active() is not None else None
    return p if isinstance(p, str) and p else sys.platform


NO_DISPLAY = "no display"
OVER_SSH = ("Claude Code runs in an ssh session, so the browser would open on the Mac's own "
            "screen")


def display_problem(env: dict[str, str], plat: str) -> str:
    """Why the system browser can't be shown to the person, or "": Linux
    needs DISPLAY or WAYLAND_DISPLAY from Claude Code's environment; macOS
    opens the browser of the logged-in desktop, which a person working over
    ssh may not see (and `open` may fail there quietly), so a Claude Code in
    an ssh session (SSH_CONNECTION) counts as having none."""
    if plat.startswith("linux"):
        return "" if env.get("DISPLAY") or env.get("WAYLAND_DISPLAY") else NO_DISPLAY
    return OVER_SSH if env.get("SSH_CONNECTION") else ""


def browser_env(env: dict[str, str], plat: str) -> dict[str, str]:
    """The opener's whole environment: a fixed PATH, LANG, gated's own HOME,
    and on Linux the Open answer's display and desktop variables
    (BROWSER_ENV). Nothing else of gated's environment or of the answer."""
    child = {"PATH": "/usr/bin:/bin", "LANG": os.environ.get("LANG", "C.UTF-8")}
    if os.environ.get("HOME", "").startswith("/"):
        child["HOME"] = os.environ["HOME"]   # gated's own (lifecycle._daemon_env: the passwd home)
    if plat.startswith("linux"):
        child.update({k: v for k, v in env.items() if k in BROWSER_ENV})
    return child


def browser_command(url: str, env: dict[str, str], plat: str | None = None
                    ) -> tuple[list[str], dict[str, str]]:
    """(argv, child environment) that opens `url` in the system browser, by
    absolute path only (never $BROWSER, never a PATH lookup); BrowserError.
    Under a test override only the `browser` knob's program."""
    from . import clipboard
    plat = plat or sys.platform
    if testing.active() is not None:
        prog = testing.get("browser")
        if not isinstance(prog, str) or not os.path.isabs(prog):
            raise BrowserError("no browser is opened under a test override")
        return [prog, url], browser_env(env, "linux")    # (the knob sees what xdg-open would)
    if plat == "darwin":
        exe = "/usr/bin/open"
        if not clipboard._trusted(exe):
            raise BrowserError("this Mac has no usable /usr/bin/open")
        return [exe, url], browser_env(env, plat)
    if plat.startswith("linux"):
        exe = clipboard._find("xdg-open", LINUX_DIRS)
        if not exe:
            raise BrowserError("no xdg-open in " + ", ".join(LINUX_DIRS))
        return [exe, url], browser_env(env, plat)
    raise BrowserError("opening a browser isn't supported on this system")


def open_browser(url: str, env: dict[str, str]) -> None:
    argv, child = browser_command(url, env, platform())
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, env=child, cwd="/", close_fds=True,
                                start_new_session=True)
    except OSError as e:
        raise BrowserError(f"it couldn't be started: {type(e).__name__}") from None
    try:
        rc = proc.wait(timeout=BROWSER_WAIT)
    except subprocess.TimeoutExpired:
        threading.Thread(target=proc.wait, daemon=True).start()   # reaped when it ends
        return
    if rc != 0:
        raise BrowserError(f"it exited with status {rc}")


# ---------------------------------------------------------------------------
# The listener (127.0.0.1, GET /cb only)
# ---------------------------------------------------------------------------


def _page(status: int, text: str) -> bytes:
    body = ("<!doctype html><meta charset=\"utf-8\"><title>Gateway sign-in</title>"
            f"<p>{text}</p>\n").encode("utf-8")
    head = (f"HTTP/1.1 {status} {_REASONS.get(status, 'Error')}\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\n"
            "X-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n")
    return head.encode("ascii") + body


def _close(conn: socket.socket) -> None:
    try:
        conn.close()
    except OSError:
        pass


def _read_head(conn: socket.socket, end: float) -> bytes | None:
    """The request line and headers (at most MAX_HEAD bytes), or None;
    TimeoutError at the connection's deadline `end` (time.monotonic). The
    deadline is the whole connection's: a client sending a byte at a time
    gets no longer than one that sends nothing."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > MAX_HEAD:
            return None
        left = end - time.monotonic()
        if left <= 0:
            raise TimeoutError("the connection's deadline passed")
        conn.settimeout(left)
        chunk = conn.recv(2048)
        if not chunk:
            return None
        buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0]
    return head if len(head) <= MAX_HEAD else None


class Listener:
    """One sign-in's callback listener on 127.0.0.1 (an ephemeral port)."""

    def __init__(self, life: float, on_callback: Callable[[dict[str, list[str]]], tuple[int, str]]):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind((LOOPBACK, 0))
            s.listen(16)
        except OSError:
            s.close()
            raise
        self.sock = s
        self.port = s.getsockname()[1]
        self.life = life
        self.on_callback = on_callback
        self.closed = threading.Event()
        self.thread: threading.Thread | None = None
        self.timer: threading.Timer | None = None
        # at most MAX_CONNS connections are handled at once (a thread each);
        # one beyond them is closed at once, so no local process can pile up
        # gated's threads during a sign-in
        self.slots = threading.BoundedSemaphore(MAX_CONNS)

    @property
    def redirect_uri(self) -> str:
        return f"http://{LOOPBACK}:{self.port}/cb"

    def start(self) -> None:
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.timer = threading.Timer(self.life, self.close)   # it never outlives its life
        self.timer.daemon = True
        self.thread.start()
        self.timer.start()

    def stop(self) -> None:
        """Stop listening now, without waiting (nothing here blocks, so a
        caller may hold a lock). On Linux close() doesn't wake a thread
        blocked in accept(): the socket stayed in LISTEN and completed
        handshakes. shutdown() wakes it (macOS has no shutdown of a listener:
        close() wakes it there). A connection accepted after this is closed
        unanswered (_serve)."""
        self.closed.set()
        if self.timer is not None:
            self.timer.cancel()
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            _close(self.sock)

    def close(self) -> None:
        """stop(), then wait for the serve thread and close the socket."""
        self.stop()
        th = self.thread
        if th is not None and th is not threading.current_thread():
            th.join(5)
        _close(self.sock)

    def _serve(self) -> None:
        while not self.closed.is_set():
            try:
                conn, _addr = self.sock.accept()     # blocks until a connection or close()
            except OSError:
                break
            if self.closed.is_set():
                _close(conn)                     # the sign-in ended: never served
                break
            if not self.slots.acquire(blocking=False):
                _close(conn)                     # too many at once: refused
                continue
            try:
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
            except RuntimeError:                 # no thread to be had
                self.slots.release()
                _close(conn)
        self.close()

    def _handle(self, conn: socket.socket) -> None:
        end = time.monotonic() + CONN_TIMEOUT    # the whole connection's deadline
        try:
            status, text = self._answer(conn, end)
            conn.settimeout(max(0.1, end - time.monotonic()))
            conn.sendall(_page(status, text))
            # a graceful close: what the client still sends is read and dropped
            # (a close with unread data would reset the answer away), until
            # the deadline but for a second at most (0.2 s at least)
            conn.shutdown(socket.SHUT_WR)
            stop = time.monotonic() + max(0.2, min(1.0, end - time.monotonic()))
            for _ in range(16):
                left = stop - time.monotonic()
                if left <= 0:
                    break
                conn.settimeout(left)
                if not conn.recv(65536):
                    break
        except OSError:
            pass
        finally:
            _close(conn)
            self.slots.release()

    def _answer(self, conn: socket.socket, end: float) -> tuple[int, str]:
        head = _read_head(conn, end)
        if head is None:
            return 431, PAGE_BAD
        line = head.split(b"\r\n", 1)[0].decode("latin-1")
        parts = line.split(" ")
        if len(parts) != 3 or not parts[2].startswith("HTTP/"):
            return 400, PAGE_BAD
        if parts[0] != "GET":
            return 405, PAGE_NOT_FOUND
        target = urllib.parse.urlsplit(parts[1])
        if target.path != "/cb":
            return 404, PAGE_NOT_FOUND
        try:
            q = urllib.parse.parse_qs(target.query, keep_blank_values=True, max_num_fields=20)
        except ValueError:
            return 400, PAGE_BAD
        return self.on_callback(q)


# ---------------------------------------------------------------------------
# The sign-ins
# ---------------------------------------------------------------------------


class SignIn:
    def __init__(self, p: Params, session: Any):
        self.p = p
        self.session = session           # the vault passphrase offer goes to it (PLAN-0.11 §8)
        self.session_pid = session.pid
        self.waiters: set[str] = set()
        self.state = "asking"            # asking (the confirm dialog) | open (after Open) | done
        self.outcome = ""
        self.message = ""
        self.dialog = ""
        self.listener: Listener | None = None
        self.timer: threading.Timer | None = None
        self.oauth_state = ""
        self.verifier = ""
        self.redirect = ""
        self.accepted = False            # a valid callback came (one only)
        self.storing = False             # its tokens are being written (that outcome stands)
        self.answered = False            # the person pressed Open (the dialog closes itself)
        self.ended = 0.0


class SignIns:
    """gated's browser sign-ins: at most one at a time (this user's)."""

    def __init__(self, daemon: Any):
        self.d = daemon
        self.cond = threading.Condition()
        self.active: SignIn | None = None
        self.done: list[SignIn] = []
        # resolved once: paths.run_dir() makes a missing run dir, and a daemon
        # whose run dir was deleted must not make it again
        self.marker = active_path()
        self._remove_active_file()            # a killed gated's leftover

    # -- the routes ------------------------------------------------------------
    def start(self, session: Any, account: Any) -> dict[str, Any]:
        p = params_for(self.d, account)
        token = secrets.token_hex(32)
        with self.cond:
            cur = self.active
            if cur is not None and cur.state != "done":
                if cur.p.name == p.name and cur.session_pid == session.pid:
                    cur.waiters.add(_hash(token))         # the same sign-in, asked again
                    return {"ok": True, "available": True, "lease": token, "joined": True}
                raise SignInError(409, "busy", BUSY_TEXT.format(name=p.name))
            si = SignIn(p, session)
            si.waiters.add(_hash(token))
            self.active = si
        life = timeout()
        spec = {"title": f"Browser sign-in for {p.name}", "entry": p.name, "what": WHAT,
                "lines": [], "ok_label": "Open", "cancel_label": "Cancel", "default_cancel": True,
                "timeout": life, "signin": p.view(),
                "check": {"section": "accounts", "entry": p.name, "kind": p.kind}}
        try:
            r = self.d.dialogs.open_owned(session, spec, lambda req, _v: self._open(si, req),
                                          on_close=lambda _rid, oc: self._closed(si, oc),
                                          kind="confirm")
        except Exception:  # noqa: BLE001 - the sign-in ends, never half-open
            self._finish(si, "failed", FAILED_TEXT.format(name=p.name,
                                                          why="its dialog couldn't open"))
            raise
        if not r.get("available"):
            self._finish(si, "unavailable", str(r.get("message") or ""))
            return {"ok": True, "available": False, "reason": r.get("reason"),
                    "message": r.get("message")}
        si.dialog = str(r.get("id") or "")
        return {"ok": True, "available": True, "lease": token, "expires_in": int(2 * life + 60)}

    def wait(self, token: Any, wait: Any) -> dict[str, Any]:
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            raise SignInError(403, "lease", "gateway: no valid sign-in lease")
        h = _hash(token)
        try:
            w = min(WAIT_MAX, max(0.0, float(wait or 0)))
        except (TypeError, ValueError):
            w = 0.0
        end = time.monotonic() + w
        with self.cond:
            while True:
                si = self._find(h)
                if si is None:
                    raise SignInError(403, "lease", "gateway: that sign-in lease isn't valid (any "
                                      "more)")
                if si.state == "done":
                    return {"ok": True, "state": "done", "outcome": si.outcome,
                            "message": si.message, "account": si.p.name}
                left = end - time.monotonic()
                if left <= 0:
                    return {"ok": True, "state": si.state, "account": si.p.name}
                self.cond.wait(min(left, 1.0))

    def stop_all(self) -> None:
        with self.cond:
            si = self.active
        if si is not None:
            self._finish(si, "failed", STOPPED_TEXT.format(name=si.p.name))
        self._remove_active_file()

    # -- the steps ---------------------------------------------------------------
    def _find(self, h: str) -> SignIn | None:
        now = time.time()
        self.done = [s for s in self.done if now - s.ended < DONE_KEEP]
        if self.active is not None and any(hmac.compare_digest(h, w) for w in self.active.waiters):
            return self.active
        for s in reversed(self.done):
            if any(hmac.compare_digest(h, w) for w in s.waiters):
                return s
        return None

    def _open(self, si: SignIn, req: Any) -> tuple[bool, str]:
        """The person pressed Open (a dialog worker thread): the listener,
        state and PKCE, the marker file, then the browser."""
        name = si.p.name
        env = clean_env(getattr(req, "env", None))
        with self.cond:
            if si.state != "asking" or self.active is not si:
                return False, "the sign-in had ended"
            si.answered = True                   # the dialog's own close reports from here on
        why = display_problem(env, platform())
        if why:
            self._finish(si, "no_display", no_display_text(why))
            return False, "no display"
        life = timeout()
        try:
            lis = Listener(life, lambda q: self._callback(si, q))
        except OSError as e:
            self._finish(si, "failed", FAILED_TEXT.format(
                name=name, why=f"no local port to listen on: {type(e).__name__}"))
            return False, "no local port"
        state, verifier = secrets.token_urlsafe(32), secrets.token_urlsafe(64)
        url = authorize_url(si.p, lis.redirect_uri, state, pkce_challenge(verifier))
        with self.cond:
            if si.state != "asking":
                lis.close()
                return False, "the sign-in had ended"
            si.oauth_state, si.verifier, si.redirect = state, verifier, lis.redirect_uri
            si.listener, si.state = lis, "open"
            timer = threading.Timer(life, lambda: self._expire(si))
            timer.daemon = True
            si.timer = timer
            self.cond.notify_all()
        self._write_active_file()
        lis.start()
        timer.start()
        try:
            open_browser(url, env)
        except BrowserError as e:
            self._finish(si, "browser", BROWSER_TEXT.format(name=name, why=str(e)))
            return False, "the browser couldn't be opened"
        return True, "the sign-in is open in the browser"

    def _closed(self, si: SignIn, outcome: str) -> None:
        """The confirm dialog ended (called with the dialog store's lock held:
        nothing here calls back into it). Before Open, that ends the sign-in."""
        with self.cond:
            if si.state != "asking":
                return
        texts = {"cancelled": CANCELLED_TEXT, "timeout": DIALOG_TIMEOUT_TEXT,
                 "paused": PAUSED_TEXT}
        oc = outcome if outcome in texts else "failed"
        text = texts.get(oc) or FAILED_TEXT.format(name=si.p.name, why="its dialog closed")
        self._finish(si, oc, text.format(name=si.p.name))

    def _expire(self, si: SignIn) -> None:
        # once a callback is accepted its exchange (bounded by the token
        # request's own timeout) and the store decide the outcome: a timeout
        # then would say "nothing was stored" while the tokens go in
        self._finish(si, "timeout", TIMEOUT_TEXT.format(name=si.p.name), unless_accepted=True)

    def _callback(self, si: SignIn, q: dict[str, list[str]]) -> tuple[int, str]:
        """A request to /cb (a listener thread). Only the state binds it."""
        with self.cond:
            if si.state != "open":
                return 410, PAGE_BAD
            got = q.get("state") or []
            want = si.oauth_state.encode("ascii")
            if len(got) != 1 or not want or not hmac.compare_digest(
                    got[0].encode("utf-8", "surrogateescape"), want):
                return 400, PAGE_BAD             # and the listener keeps waiting
            if si.accepted:
                return 409, PAGE_BAD
            si.accepted = True
            verifier, redirect = si.verifier, si.redirect
        name = si.p.name
        if "error" in q:                         # error_description is never kept
            self._finish(si, "declined", DECLINED_TEXT.format(name=name))
            return 200, PAGE_FAIL
        codes = q.get("code") or []
        if len(codes) != 1 or not codes[0] or len(codes[0]) > CODE_MAX:
            self._finish(si, "failed", FAILED_TEXT.format(name=name,
                                                          why="the browser brought back no code"))
            return 400, PAGE_FAIL
        try:
            tok = exchange(si.p, codes[0], verifier, redirect)
        except SignInError as e:
            self._finish(si, "failed", FAILED_TEXT.format(name=name, why=e.message))
            return 200, PAGE_FAIL
        try:
            self._store(si, tok)
        except SignInError as e:
            self._finish(si, e.code, e.message, store=True)
            return 200, PAGE_FAIL
        finally:
            tok.clear()
        self._finish(si, "ok", OK_TEXT.format(name=name), store=True)
        self._offer(si)
        return 200, PAGE_OK

    def _offer(self, si: SignIn) -> None:
        """The vault passphrase offer after gated's own store (PLAN-0.11 §8),
        with the vault's lock released (set_passphrase takes it); also when
        no gate check waits for the outcome any more. Once per session
        (daemon/offer.py); it never changes the sign-in's outcome."""
        try:
            self.d.offers.offer(si.session)
        except Exception:  # noqa: BLE001 - a later store offers it
            pass

    def _store(self, si: SignIn, tok: dict[str, Any]) -> None:
        """The tokens straight into the vault (the flock first, then the
        daemon's vault mutex, as set_passphrase takes them)."""
        from .. import audit
        from .. import form as formmod
        p = si.p
        refresh, access = tok.get("refresh_token"), tok.get("access_token")
        try:
            f = formmod.load()
            a = f.accounts.get(p.name)
        except Exception:  # noqa: BLE001
            a = None
        if a is None or a.kind != p.kind:
            raise SignInError(409, "changed", CHANGED_TEXT.format(name=p.name))
        rec_entra = {"refresh_token": refresh, "client_id": p.client_id, "tenant_id": p.tenant,
                     "refreshed": vault.now(), "kind": "browser", "scope": p.scope}
        try:
            with vault.locked(), self.d.vault_mutex:
                with self.cond:
                    if si.state != "open":
                        # it ended meanwhile (gated stopping), and its outcome
                        # already said nothing was stored: nothing is
                        raise SignInError(410, "ended", "")
                    si.storing = True        # from here the store's outcome stands
                b = self.d.broker
                data = b.read() if paths.vault_path().exists() else vault.empty()
                rec = vault.account_record(data, p.name, p.kind)
                rec["kind"] = p.kind
                rec["entra"] = rec_entra
                rec.pop("status", None)              # a new credential: its state starts over
                if p.kind == "ml-catalog":
                    rec["bound"]["scope"] = p.api_scope
                vault.add_event(data, "bind", f"{p.name}: signed in through the browser")
                b.write(data)
                if isinstance(access, str) and access and p.cache_scope:
                    try:
                        expires = time.time() + float(tok.get("expires_in", 3600))
                        vault.cache_clear(p.name)
                        vault.cache_put(p.name, p.cache_scope, access, expires)
                    except (vault.VaultError, OSError, TypeError, ValueError):
                        pass                         # the cache is safe to lose
        except vault.VaultLocked:
            raise SignInError(423, "locked", LOCKED_TEXT.format(name=p.name)) from None
        except (vault.VaultError, OSError) as e:
            raise SignInError(500, "failed", FAILED_TEXT.format(
                name=p.name, why=f"the vault couldn't be written: {type(e).__name__}")) from None
        audit.log("secret_saved", entry=p.name, what="sign-in", source="browser",
                  secrets=[v for v in (refresh, access) if isinstance(v, str) and v])

    def _finish(self, si: SignIn, outcome: str, message: str, *, store: bool = False,
                unless_accepted: bool = False) -> None:
        """Every exit path: the outcome kept for the waiters, the listener and
        the timer stopped, state and verifier forgotten, the marker removed.
        `store`: the store's own outcome. Any other waits for a store that is
        writing (STORE_WAIT at most), whose outcome then stands, so no outcome
        says nothing was stored while the tokens go in. `unless_accepted`:
        nothing happens once a callback was accepted (the timer)."""
        with self.cond:
            if unless_accepted and si.accepted:
                return
            if store:
                si.storing = False
                self.cond.notify_all()
            else:
                end = time.monotonic() + STORE_WAIT
                while si.storing:
                    left = end - time.monotonic()
                    if left <= 0:
                        break
                    self.cond.wait(min(left, 0.5))
            if si.state == "done":
                return
            si.state, si.outcome, si.message, si.ended = "done", outcome, message, time.time()
            lis, si.listener = si.listener, None
            tim, si.timer = si.timer, None
            si.oauth_state = si.verifier = ""
            if self.active is si:
                self.active = None
            self.done.append(si)
            # before anyone hears of the end: the listener stops (nothing is
            # served after it), then the marker goes
            if lis is not None:
                lis.stop()
            if self.active is None:
                self._remove_active_file()
            self.cond.notify_all()
        if tim is not None:
            tim.cancel()
        if lis is not None:
            lis.close()                          # (waits for its serve thread)
        if si.dialog and not si.answered:
            # before Open the dialog may still be open (gated stopping): close
            # it; after Open its handler's answer closes it
            try:
                self.d.dialogs.close_owned(si.dialog, "cancelled", "the sign-in ended")
            except Exception:  # noqa: BLE001
                pass

    # -- the marker hooks/tool_guard.sh checks -------------------------------------
    def _write_active_file(self) -> None:
        try:
            fd = os.open(self.marker, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            os.close(fd)
        except OSError:
            pass

    def _remove_active_file(self) -> None:
        try:
            self.marker.unlink()
        except OSError:
            pass
