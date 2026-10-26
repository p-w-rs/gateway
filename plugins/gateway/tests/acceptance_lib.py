"""Pure helpers the TUI acceptances and the headless e2e suite share (stdlib
only). Nothing here imports tests/tui or the test harness, so an
acceptance's `pixi exec` Python and the e2e suite's scratch copy can import
it; tests/test_acceptance_lib.py runs every helper and keeps each string
below in step with the code that prints it.

- What the scripts look for on a screen or in a result: a short piece of the
  gateway's own text (the screen wraps long lines: flat() joins them first).
- write_user_tools() / user_tool_runs(): a folder of the user's own tools as
  recording fakes (tests/fakes/fake_user_tool.py) for e2e.json's
  `user_tools` knob: a pass-through runs them, never the real ssh, git or
  sudo (PLAN-0.11 §1.3, §13).
- permission_modes() / mode_key(): Claude Code's --permission-mode choices
  (from `claude --help`) and the gateway's key for each (PLAN-0.11 §2.1).
- snapshot_files() / snapshot_shells(): Claude Code's shell snapshots and
  which shells made them (a session's own: leave out the earlier ones).
- new_files(): a session's own transcripts when every session of a config
  shares its projects folder.
- parts_of() / part_question(): a dialog in parts as the screen shows it.
- focus_private_field() / type_private() / focus_line_field(): keys into a
  pane's field only once it has them, and the value checked before Enter.
- settled() / kept(): a journal read once another process stopped writing
  it, and "every earlier record is still there".
- ckoff(): Claude's first request holds the full context without the
  checkpoint job lines (PLAN-0.11 §9.4).
- run_if_fake(): a shell line that runs a sudo command only when `sudo` is
  the acceptance's fake (the real sudo never gets a canary).
- opener_hits() / opener_calls(): the static scan for programs that open
  windows, browsers or terminals, and the one opener plugin code may call.
- TlsSite: a page on https://127.0.0.1 with a certificate from a scratch CA
  (openssl), for a WebFetch the harness serves.
"""
from __future__ import annotations

import http.server
import json
import os
import re
import shutil
import ssl
import subprocess
import threading
import time
from collections import Counter
from collections.abc import Callable, Collection, Iterable
from pathlib import Path
from typing import Any

TESTS = Path(__file__).resolve().parent
FAKE_USER_TOOL = TESTS / "fakes" / "fake_user_tool.py"

# ---------------------------------------------------------------------------
# Pieces of the gateway's text
# ---------------------------------------------------------------------------

# consent: a bare `sudo = true` (or ssh) that rises from "ask" (PLAN-0.11
# §19.4: each change line says what each mode now does)
CONSENT_APPROVES = "now approves without asking you"
# consent in parts (popup.consent_pages, §19.11): the dialog's own button
# and the last part's question
NEXT = "Next"
CONSENT_LAST = "Approve all of this (parts 1 to"
# the import confirm in parts (transfer.confirm_pages)
IMPORT_LAST = "Import all of this (parts 1 to"
# either dialog's question beside its buttons starts with where it is
# (popup.dialog_parts' callers): part 1 of n says "Part 1 of n. Go on to
# part 2 of n? ...", at the start of a pane row however the rest wraps
PARTS_FIRST = re.compile(r"Part 1 of (\d+)\. Go on to part 2 of \1\?")
# the private field's hint (mod/field.tsx) and the terminal pane's line
# field on the main screen (register.tsx, its Input's placeholder)
FIELD_HINT = "click here, then type"
LINE_FIELD_HINT = "type a line; Enter sends it"
# the vault passphrase offer (hooks/mod/dialog.ts OFFER_*; daemon/offer.py)
OFFER_TITLE = "Protect the vault with a passphrase?"
OFFER_SET = "Set passphrase"
OFFER_NOT_NOW = "Not now"
SET_PASSPHRASE_TITLE = "Set a vault passphrase"
# the browser sign-in's confirm (dialog.ts signinLines, SIGNIN_NOTE) and
# outcome (daemon/oauth.py OK_TEXT)
SIGNIN_AZURE = "Claude asks to sign in to Azure as you (account {name})"
SIGNIN_NOTE = "Nothing happens before you press Open."
SIGNIN_OK = "{name} is signed in (a browser sign-in)"
# tool_guard.sh while a sign-in is open
BROWSER_PAUSED = "browser tools are paused while a browser sign-in is open"
# Claude's context while checkpoint is live (hooks_session.JOBS_HOWTO, §9.4): words
# only that line has; "checkpoint jobs (job_start)" alone is also in the gateway
# skill's description, which Claude Code sends in every request's skill listing
JOBS_MARK = "checkpoint jobs (job_start) run on this machine under the gateway's own job supervisor"
# the status line once pixi refused the manifest (lib.ts statusLine) points at the
# doctor, which says how to update pixi (lib.ts pixiTooOldText, PLAN-0.11 §5)
PIXI_OLD_STATUS = "pixi is too old: update it; /gate-doctor says how"
PIXI_SELF_UPDATE = "pixi self-update"
# a how-to line of the full context (hooks_session.HOWTO; the cut form keeps
# every how-to line), which the not-ready context (launch.sh) never has
HOWTO_MARK = "`gate why` explains the last refusal"
# the first 0.11 session (hooks_session.POSTURE_SUDO)
POSTURE_SUDO = "now uses your own sudo unless gateway.toml sets"
# the network class (hooks_bash._network): an ask, and a job's refusal
NET_ASK = "is a network command, and [network] commands asks"
NET_JOB = "a job or gateway terminal can't be asked about this"
# the cold window's network ask (envfile.DEGRADED_BASH_WHAT["network"])
COLD_NET = "running a network command"
# no managed shell (hooks_bash.MANAGED_NOTICE), and one that isn't ready (gate-sh)
MANAGED_NOTICE = "your commands run in your own shell, and the gateway still judges them"
NOT_READY = "this command ran without the gateway's managed settings"
# a route around a stand-in to a configured host (hooks_bash._route_deny)
ROUTE_SSH = "goes around the gateway's ssh stand-in"
# what a recording fake prints (tests/fakes/fake_user_tool.py)
FAKE_RAN = "fake {tool} ran"


# A [shell] change longer than one gateway dialog (30 environment and 12
# PATH imports: 42 consent lines): its consent, and an import that brings it
# back, come in parts (§19.11). No name is a credential's (form.py).
SETTINGS_ENV = tuple(f"TOOL_HOME_{i:02d}" for i in range(30))
SETTINGS_PATH = tuple(f"/opt/tool-{i:02d}/bin" for i in range(12))


def settings_table() -> str:
    """gateway.toml's [shell] table with SETTINGS_ENV and SETTINGS_PATH."""
    return ("[shell]\nimport_env = [" + ", ".join(f'"{n}"' for n in SETTINGS_ENV) + "]\n"
            "import_path = [" + ", ".join(f'"{d}"' for d in SETTINGS_PATH) + "]\n")


def flat(text: str) -> str:
    """The text with a pane's side borders dropped and every run of white
    space as one space: a long line the screen wrapped reads as written."""
    return re.sub(r"\s+", " ", re.sub(r"[│┃║╎]", " ", text or ""))


def shows(text: str, piece: str) -> bool:
    """`piece` is in `text`, however the screen wrapped it (a wrap at a
    space, or in the middle of a word: both are tried)."""
    f = flat(text)
    return flat(piece) in f or piece.replace(" ", "") in f.replace(" ", "")


def parts_of(text: str) -> int | None:
    """n when `text` (a screen) shows the first part of a dialog in n parts
    (its question beside the buttons), else None."""
    m = PARTS_FIRST.search(text or "")
    return int(m.group(1)) if m else None


def part_question(i: int, n: int) -> str:
    """How part i of n's question beside its buttons starts."""
    return f"Part {i} of {n}. "


# ---------------------------------------------------------------------------
# Keys into a pane's field: a session (tests/tui driver.Session) is used only
# through send, key, type and pump; `count` reads what the field shows.
# ---------------------------------------------------------------------------


def until(s: Any, cond: Callable[[], bool], timeout: float, step: float = 0.1) -> bool:
    """Pump the session until cond() holds (True) or the time is up."""
    end = time.monotonic() + timeout
    while True:
        try:
            if cond():
                return True
        except Exception:  # noqa: BLE001 - a screen read in flight
            pass
        if time.monotonic() >= end:
            return False
        s.pump(step)


def steady(s: Any, cond: Callable[[], bool], timeout: float, hold: float = 1.0,
           step: float = 0.1) -> bool:
    """Pump the session until cond() has held for `hold` seconds in a row
    (True) or the time is up: a count a slow screen only passes through on
    its way to another doesn't count."""
    end = time.monotonic() + timeout
    since = None
    while True:
        try:
            ok = bool(cond())
        except Exception:  # noqa: BLE001 - a screen read in flight
            ok = False
        now = time.monotonic()
        if not ok:
            since = None
        elif since is None:
            since = now
        if since is not None and now - since >= hold:
            return True
        if now >= end:
            return False
        s.pump(step)


def focus_private_field(s: Any, click: Callable[[], Any], count: Callable[[], int],
                        tries: int = 5) -> int | None:
    """Click the private field until it takes the keys: a probe "x" must add
    a bullet (count: the bullets on the screen), then Backspace must take it
    away again before this says yes, since a probe left in the field would
    go out with the value (VM run 8: three "Sorry, try again"). A probe not
    seen in time is taken back too (a Backspace, which follows it wherever
    it went, however late it is drawn) before the next click. click()
    raises LookupError while the field isn't drawn. The field is a fresh one
    (empty), so a Backspace too many does nothing.

    Returns the bullets the screen shows with the field empty, counted
    before the first probe (type_private checks the value against it), or
    None when the field never took the keys."""
    empty = None
    for _ in range(tries):
        try:
            click()
        except LookupError:
            s.pump(1.0)
            continue
        s.pump(0.4)
        n = count()
        if empty is None:
            empty = n
        s.send("x")
        if not until(s, lambda: count() > n, 2.0):
            s.key("backspace")                # late, or in the prompt box: take it back
            until(s, lambda: count() == n, 2.0)
            continue                          # click again
        for _ in range(3):
            s.key("backspace")
            if until(s, lambda: count() == n, 2.0):
                return empty
        return None                           # the probe stays: never type a value after it
    return None


def type_private(s: Any, value: str, count: Callable[[], int], empty: int,
                 tries: int = 2) -> bool:
    """Type `value` into the focused private field and see, before Enter,
    one bullet per character: count (the bullets on the screen) must stay
    at `empty` (focus_private_field's count with the field empty) plus the
    value's length, so a dropped or doubled key, or a probe left in the
    field, would never send a wrong value. A field that doesn't show it is
    emptied and typed again; False when it still doesn't (nothing is
    submitted here)."""
    want = empty + len(value)
    for _ in range(tries):
        s.type(value)
        if steady(s, lambda: count() == want, 6.0):
            return True
        s.key("backspace", len(value) + 8, 0.02)
        steady(s, lambda: count() == empty, 6.0)
    return False


def focus_line_field(s: Any, shown: Callable[[], str], hint: str = LINE_FIELD_HINT,
                     tries: int = 6) -> bool:
    """Wait until a pane's line field (an Input drawn with `hint` as its
    placeholder) has the keys: a probe "x" must replace the placeholder,
    then Backspace bring it back. Keys typed before that reach the prompt
    box instead (VM run 10's mainscr); a probe that went there is taken back
    with a Backspace."""
    for _ in range(tries):
        if not until(s, lambda: hint in shown(), 5.0):
            return False                      # no field drawn
        s.send("x")
        if until(s, lambda: hint not in shown(), 1.5):
            s.key("backspace")
            if until(s, lambda: hint in shown(), 2.0):
                return True
            continue
        s.key("backspace")                    # the probe went to the prompt box
        s.pump(1.0)
    return False


# ---------------------------------------------------------------------------
# A journal (or any list of records) that another process still writes
# ---------------------------------------------------------------------------


def settled(read: Callable[[], list], quiet: float = 3.0, timeout: float = 30.0,
            step: float = 0.5) -> list:
    """read() once it has returned the same records for `quiet` seconds (a
    session that just closed may still flush a segment: mac-tui F), or what
    it returns when `timeout` is up."""
    end = time.monotonic() + timeout
    last, since = read(), time.monotonic()
    while time.monotonic() < end:
        time.sleep(step)
        now = read()
        if now != last:
            last, since = now, time.monotonic()
        elif time.monotonic() - since >= quiet:
            break
    return last


def kept(before: Iterable[Any], after: Iterable[Any]) -> bool:
    """Every record of `before` is still in `after` (as many times), in any
    order: what "it stays" means while new records may still come."""
    def key(r: Any) -> str:
        return json.dumps(r, sort_keys=True, default=str)
    return not (Counter(map(key, before)) - Counter(map(key, after)))


def ckoff(body: str) -> tuple[bool, str]:
    """Claude's request `body` holds the gateway's full context (a how-to
    line) and no checkpoint job lines: (True, "") or (False, why). A body
    with only the not-ready context proves nothing about the job lines, so
    it fails too."""
    if HOWTO_MARK not in body:
        return False, "the full context isn't in the request (the not-ready context, or none)"
    if JOBS_MARK in body:
        return False, "the checkpoint job lines are in the context"
    return True, ""


# ---------------------------------------------------------------------------
# A session's own files
# ---------------------------------------------------------------------------


def new_files(now: Iterable[os.PathLike | str], before: Iterable[os.PathLike | str]) -> list[Path]:
    """The files in `now` that weren't in `before`, in `now`'s order: a
    session's own transcripts, when every session of a config shares its
    projects folder (driver.Session.transcripts lists them all)."""
    old = {Path(p) for p in before}
    return [Path(p) for p in now if Path(p) not in old]


def run_if_fake(fake: str, command: str, otherwise: str) -> str:
    """A shell line that runs `command` only when `sudo` resolves to `fake`
    (an absolute path), else `otherwise`: a canary meant for the fake never
    reaches the real sudo, whatever order the PATH ends up in."""
    if not fake.startswith("/"):
        raise ValueError(f"not an absolute path: {fake!r}")
    return f"case $(command -v sudo) in {_sq(fake)}) {command} ;; *) {otherwise} ;; esac"


# ---------------------------------------------------------------------------
# The user's own tools, as recording fakes
# ---------------------------------------------------------------------------


def write_user_tools(folder: Path, names: tuple[str, ...] | list[str], python: str,
                     exit_code: int = 0) -> Path:
    """A folder of recording fakes named `names` for the `user_tools` knob:
    each runs a copy of fake_user_tool.py (copied in, so the folder stands
    alone) with its own name, under `python`. Returns the folder."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    fake = folder / "fake_user_tool.py"
    shutil.copy2(FAKE_USER_TOOL, fake)
    for n in names:
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", n) or n == fake.name:
            raise ValueError(f"not a tool name: {n!r}")
        p = folder / n
        p.write_text("#!/bin/sh\n"
                     f"GW_FAKE_ARGV0=\"$0\"; GW_FAKE_USER_DIR={_sq(str(folder))}; "
                     "export GW_FAKE_ARGV0 GW_FAKE_USER_DIR\n"
                     f"exec {_sq(python)} -I {_sq(str(fake))} {_sq(n)} \"$@\"\n")
        os.chmod(p, 0o755)
    if exit_code:
        (folder / "exit").write_text(str(exit_code))
    return folder


def user_tool_runs(folder: Path, tool: str | None = None, *, with_g: bool = False) -> list[dict[str, Any]]:
    """The fakes' recorded runs, oldest first (an `ssh -G` lookup only with
    `with_g`)."""
    try:
        lines = (Path(folder) / "log.jsonl").read_text().splitlines()
    except OSError:
        return []
    out = []
    for ln in lines:
        try:
            rec = json.loads(ln)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        if not with_g and rec.get("tool") == "ssh" and "-G" in (rec.get("argv") or []):
            continue
        if tool is None or rec.get("tool") == tool:
            out.append(rec)
    return out


def _sq(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


# ---------------------------------------------------------------------------
# Permission modes
# ---------------------------------------------------------------------------

_CHOICES = re.compile(r"--permission-mode\b.*?\(choices:\s*(.*?)\)", re.S)


def permission_modes(help_text: str) -> list[str]:
    """The --permission-mode choices `claude --help` lists, in its order
    ([] when it lists none)."""
    m = _CHOICES.search(help_text or "")
    if not m:
        return []
    return [c for c in re.findall(r'"([A-Za-z]+)"', m.group(1))]


# Claude Code's --permission-mode choices and gateway.toml's spellings ->
# the gateway's mode key (modes.SPELLINGS; a test keeps the two alike)
MODE_KEYS = {"default": "default", "manual": "default", "plan": "plan",
             "acceptEdits": "acceptEdits", "auto": "auto", "bypassPermissions": "bypass",
             "dontAsk": "dontAsk"}
# where a bare `true` right is the gateway's allow (§2.3); cc elsewhere
BARE_TRUE_ALLOWS = ("auto", "bypass")


def mode_key(choice: str) -> str | None:
    """The gateway's mode key for a --permission-mode choice, or None for a
    choice the gateway's table doesn't know (the table needs a look)."""
    return MODE_KEYS.get(choice)


def manual_mode(choices: list[str]) -> str:
    """The choice that is Claude Code's default (asking) mode: "manual" on
    the latest Claude Code, "default" on older ones."""
    return "manual" if "manual" in choices or not choices else "default"


# ---------------------------------------------------------------------------
# Shell snapshots
# ---------------------------------------------------------------------------


_SNAPSHOT = re.compile(r"snapshot-([a-z]+)-.*\.sh")


def snapshot_files(config_dir: Path) -> list[Path]:
    """Claude Code's shell snapshots in `config_dir`
    (shell-snapshots/snapshot-SHELL-*.sh), by name."""
    d = Path(config_dir) / "shell-snapshots"
    try:
        return sorted(p for p in d.iterdir() if _SNAPSHOT.fullmatch(p.name))
    except OSError:
        return []


def snapshot_shells(config_dir: Path, skip: Collection[os.PathLike | str] = ()) -> list[str]:
    """The shells that made Claude Code's shell snapshots in `config_dir`,
    by name, each once, leaving out the snapshots in `skip` (those of earlier
    sessions on the same config)."""
    old = {Path(p).name for p in skip}
    out: list[str] = []
    for p in snapshot_files(config_dir):
        m = _SNAPSHOT.fullmatch(p.name)
        if m and p.name not in old and m.group(1) not in out:
            out.append(m.group(1))
    return out


# ---------------------------------------------------------------------------
# The static scan for window, browser and terminal openers
# ---------------------------------------------------------------------------

# What the native UI acceptance's scan looks for in both plugins' shipped files
OPENER_PATTERNS = {
    "osascript": r"\bosascript\b", "zenity": r"\bzenity\b", "kdialog": r"\bkdialog\b",
    "xdg-open": r"\bxdg-open\b", "notify-send": r"\bnotify-send\b", "webbrowser": r"\bwebbrowser\b",
    "NSWorkspace": r"\bNSWorkspace\b", "open -a / open URL": r"""\bopen\s+(-a\b|-b\b|https?://|"https?://)""",
    "argv 'open'": r"""\[\s*["']open["']""", "terminal programs": r"\b(gnome-terminal|x-terminal-emulator|xterm|konsole|"
    r"Terminal\.app|iTerm)\b", "$BROWSER": r"\$\{?BROWSER\b", "wslview / gio open": r"\b(wslview|gio\s+open)\b",
    "device-code/browser sign-in": r"(device[_ ]code|devicelogin|launch_browser|open_browser)",
}
# A line of plugin code that starts a program: a call, never a mention
OPENER_RUNS = re.compile(r"(subprocess|Popen|run\(|spawn|exec[lv]?p?\(|\$\.process|os\.system|"
                         r"webbrowser\.(open|get))")
# ... or calls a browser opener by name
OPENER_FUNC = re.compile(r"\b(open_browser|launch_browser)\(")
# The one opener plugin code calls (PLAN-0.11 §7.2): gated's browser sign-in,
# run only after the person pressed Open (tests: the `browser` knob's program);
# a call of it anywhere else, or a line that also starts a program, is a call
# like any other
EXPECTED_OPENER = ("gate", "src/gateway/daemon/oauth.py", re.compile(r"\bopen_browser\("))


def opener_kind(rel: str) -> str:
    """"doc/test" for docs, tests and test files, else "code"."""
    if rel.startswith(("tests/", "docs/")) or "/tests/" in rel or rel.endswith((".md", ".test.ts", ".test.tsx")):
        return "doc/test"
    return "code"


def opener_hits(plugin: str, rel: str, text: str) -> list[dict[str, Any]]:
    """Every OPENER_PATTERNS match in one file (`rel`: its path in the plugin
    folder): plugin, file, line, what, kind and the line's text."""
    hits = []
    lines = text.splitlines()
    for name, pat in OPENER_PATTERNS.items():
        for m in re.finditer(pat, text):
            ln = text.count("\n", 0, m.start()) + 1
            line = lines[ln - 1].strip() if lines else ""
            hits.append({"plugin": plugin, "file": rel, "line": ln, "what": name,
                         "kind": opener_kind(rel), "text": line[:160]})
    return hits


def opener_calls(hits: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """The code hits that call something (not a comment, not a definition),
    split into the expected opener's calls (EXPECTED_OPENER: its plugin, its
    file, its call) and every other call."""
    plug, rel, call = EXPECTED_OPENER
    expected, other = [], []
    for h in hits:
        t = h["text"].lstrip()
        if h["kind"] != "code" or t.startswith(("#", "//", "*", "def ")):
            continue
        runs = OPENER_RUNS.search(t)
        if not (runs or OPENER_FUNC.search(t)):
            continue
        ok = h["plugin"] == plug and h["file"] == rel and call.search(t) is not None and not runs
        (expected if ok else other).append(h)
    return expected, other


# ---------------------------------------------------------------------------
# A page on https://127.0.0.1 (a WebFetch the harness serves)
# ---------------------------------------------------------------------------


class TlsSite:
    """One page at https://127.0.0.1:PORT/PATH with a certificate issued by
    a scratch CA (openssl; the CA's file goes to NODE_EXTRA_CA_CERTS, with
    any CA already there). Records each request's path (never a header)."""

    def __init__(self, folder: Path, body: str, path: str = "/page", openssl: str | None = None):
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True)
        self.path = path
        self.paths: list[str] = []
        ossl = openssl or shutil.which("openssl") or "/usr/bin/openssl"
        self.ca, key, crt = self._certs(ossl)
        site = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                site.paths.append(self.path)
                data = body.encode() if self.path == site.path else b"not here\n"
                self.send_response(200 if self.path == site.path else 404)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(crt), str(key))
        self.srv.socket = ctx.wrap_socket(self.srv.socket, server_side=True)
        self.port = self.srv.server_address[1]
        self.thread = threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.2},
                                       daemon=True)
        self.thread.start()

    @property
    def url(self) -> str:
        return f"https://127.0.0.1:{self.port}{self.path}"

    def _certs(self, ossl: str) -> tuple[Path, Path, Path]:
        f = self.folder
        # strict X.509 checks (Python 3.13+, current Node) want key usage on
        # the CA and key identifiers on both
        cnf = f / "ca.cnf"
        cnf.write_text("[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = gateway acceptance CA\n"
                       "[v3_ca]\nbasicConstraints = critical,CA:TRUE\n"
                       "keyUsage = critical,keyCertSign,cRLSign\nsubjectKeyIdentifier = hash\n")
        ext = f / "leaf.ext"
        ext.write_text("basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                       "extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1,DNS:localhost\n"
                       "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
        cmds = [
            [ossl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-config", str(cnf),
             "-extensions", "v3_ca", "-keyout", str(f / "ca.key"), "-out", str(f / "ca.pem")],
            [ossl, "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1",
             "-keyout", str(f / "leaf.key"), "-out", str(f / "leaf.csr")],
            [ossl, "x509", "-req", "-in", str(f / "leaf.csr"), "-CA", str(f / "ca.pem"),
             "-CAkey", str(f / "ca.key"), "-CAcreateserial", "-days", "2", "-extfile", str(ext),
             "-out", str(f / "leaf.pem")],
        ]
        for c in cmds:
            r = subprocess.run(c, capture_output=True, text=True, timeout=60, stdin=subprocess.DEVNULL)
            if r.returncode != 0:
                raise RuntimeError(f"openssl failed: {' '.join(c[:3])}: {r.stderr[-300:]}")
        for k in ("ca.key", "leaf.key"):
            os.chmod(f / k, 0o600)
        return f / "ca.pem", f / "leaf.key", f / "leaf.pem"

    def ca_bundle(self, extra: str | None = None) -> Path:
        """A file with this site's CA and the CA file `extra` names (the
        record-only proxy's), for NODE_EXTRA_CA_CERTS."""
        out = self.folder / "extra-cas.pem"
        text = self.ca.read_text()
        if extra and Path(extra).is_file():
            text = Path(extra).read_text().rstrip("\n") + "\n" + text
        out.write_text(text)
        return out

    def close(self) -> None:
        self.srv.shutdown()
        self.srv.server_close()
        self.thread.join(5)
