"""Drive the real interactive Claude Code TUI in a pseudo-terminal.

    from tui.driver import Session
    with Session(root, replies=["hello from the fake model"]) as s:
        s.wait_ready()                      # the prompt (❯) is on screen
        s.submit("hi")                      # type + Enter
        assert s.wait_for(r"hello from the fake model")

What a Session does:

* checks that `root` is a fresh scratch directory (safety.check_scratch) and
  lays out root/cfg (CLAUDE_CONFIG_DIR, unless `config_dir` names an
  existing scratch config such as an install.Installation's), root/home
  (HOME), root/tmp (TMPDIR and CLAUDE_CODE_TMPDIR), root/work (default
  cwd) and root/api (the fake API's log, unless `api` is given), plus a
  short private /tmp/tui-* dir for XDG_RUNTIME_DIR (Claude Code's peer
  socket; removed on close);
* refuses to start if it would load the gateway plugin without a proven e2e
  redirection (gwe2e.py; check_gateways), before anything starts;
* seeds <config>/.claude.json: onboarding done, theme set, the cwd trusted
  (as given and resolved; trust_cwd=False leaves it untrusted), the fake API
  key approved, auto-updates off; and bypass mode accepted, in
  <config>/settings.json too (accept_bypass=False removes it); existing keys
  (from `claude plugin install`) are kept;
* builds the child environment with safety.hermetic_env: an allowlist of
  the caller's variables (no CLAUDE_*, ANTHROPIC_*, OTEL_*, proxies, tokens,
  ssh agent), then ANTHROPIC_BASE_URL=<fake API>, ANTHROPIC_API_KEY=<fake>,
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1, DISABLE_AUTOUPDATER=1, scratch
  CHECKPOINT_HOME / CHECKPOINT_GATEWAY_ENV / CHECKPOINT_GATEWAY_CONTRACT /
  GATEWAY_TEST_ROOT / XDG dirs under one state root per config (shared by
  every Session on that config, so a restart sees the same plugin state;
  `state_root=` overrides it, `home=` the HOME);
* starts `claude [--plugin-dir D]... [--permission-mode M] [--debug-file F]
  [args]` with pty.fork (the child leads its own session and process group)
  and mirrors the screen with pyte (a HistoryScreen, so scrolled-off lines
  stay searchable with where="all");
* answers the terminal queries Ink waits on (cursor position, device
  attributes), so the TUI never stalls;
* close() (also on __exit__, atexit and errors) kills the child, its process
  group and every descendant it started, plus what those left behind in
  process sessions of their own (recorded while pumping; matched by session
  id and a command line naming this session's scratch places), closes the
  PTY and stops the fake API it owns. It is safe to call twice.

Screen coordinates are 0-based (col, row) as pyte reports them; click()
converts to the 1-based SGR mouse encoding. Wide characters take two cells.

Secrets: register any value a test types with `session.redact(value)` and it
is replaced by <redacted> in every dump this module produces (exceptions,
dump()); raw bytes stay available in `session.raw` for scanning.

Plugins under test should be given as scratch copies (install.snapshot_tree)
or installed through install.Hermetic, never as the repository folder:
Claude Code writes `.claude-plugin/types/` into a mod folder it loads.
A gateway plugin loaded here must run under its e2e marker
(install.Hermetic.install_gateway_e2e, gwe2e.py): it takes its home from the
password database, not from $HOME, and GATEWAY_TEST_ROOT only makes it
inert in a session. start() refuses otherwise.
"""
from __future__ import annotations

import atexit
import fcntl
import json
import os
import pty
import re
import select
import shutil
import signal
import struct
import termios
import time
import weakref
from pathlib import Path

import pyte

from . import safety
from .fakeapi import FakeAPI
from .install import find_claude
from .observe import Observer

PROMPT = "❯"

KEYS = {
    "enter": "\r", "return": "\r", "tab": "\t", "shift_tab": "\x1b[Z", "esc": "\x1b",
    "escape": "\x1b", "backspace": "\x7f", "delete": "\x1b[3~", "space": " ",
    "up": "\x1b[A", "down": "\x1b[B", "right": "\x1b[C", "left": "\x1b[D",
    "home": "\x1b[H", "end": "\x1b[F", "pgup": "\x1b[5~", "pgdn": "\x1b[6~",
    "f1": "\x1bOP", "f2": "\x1bOQ", "f3": "\x1bOR", "f4": "\x1bOS",
    "ctrl_c": "\x03", "ctrl_d": "\x04", "ctrl_z": "\x1a", "ctrl_l": "\x0c",
    "ctrl_r": "\x12", "ctrl_o": "\x0f", "ctrl_rbracket": "\x1d",
}

# Terminal queries Ink/Claude Code sends and waits on, with our answers.
QUERY_DSR = re.compile(rb"\x1b\[\??6n")
QUERY_DA1 = re.compile(rb"\x1b\[0?c")

_LIVE: "weakref.WeakSet[Session]" = weakref.WeakSet()


def ctrl(ch: str) -> str:
    """The control character for a letter: ctrl('c') == '\\x03'."""
    return chr(ord(ch.lower()) & 0x1F)


def alt(ch: str) -> str:
    return "\x1b" + ch


def _write_json(p: Path, data: dict) -> None:
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(data, indent=2))
    os.chmod(tmp, (p.stat().st_mode & 0o777) if p.exists() else 0o600)
    os.replace(tmp, p)


def _read_json(p: Path) -> dict:
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text())
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def seed_config(config_dir: os.PathLike | str, trusted: list[str], api_key: str,
                accept_bypass: bool = True) -> Path:
    """Write/merge <config>/.claude.json (and settings.json) so the TUI
    starts at the prompt.

    Bypass mode's warning: Claude Code reads the acceptance from
    settings.json's skipDangerousModePermissionPrompt. .claude.json's
    bypassPermissionsModeAccepted counts only until its first start migrates
    it there (migrationVersion 14), and `claude plugin install` is such a
    start, so on an installed config only the settings key works; both are
    written. accept_bypass=False removes both, so the warning shows."""
    p = Path(config_dir) / ".claude.json"
    data = _read_json(p)
    data.update({"hasCompletedOnboarding": True, "theme": data.get("theme", "dark"),
                 "numStartups": max(5, int(data.get("numStartups", 0) or 0)),
                 "autoUpdates": False, "hasSeenTasksHint": True})
    if accept_bypass:
        data["bypassPermissionsModeAccepted"] = True
    else:
        data.pop("bypassPermissionsModeAccepted", None)
    resp = data.setdefault("customApiKeyResponses", {"approved": [], "rejected": []})
    if api_key[-20:] not in resp.setdefault("approved", []):
        resp["approved"].append(api_key[-20:])
    resp.setdefault("rejected", [])
    projects = data.setdefault("projects", {})
    for t in trusted:
        e = projects.setdefault(t, {})
        e.update({"hasTrustDialogAccepted": True, "hasCompletedProjectOnboarding": True,
                  "projectOnboardingSeenCount": max(1, int(e.get("projectOnboardingSeenCount", 0) or 0))})
    _write_json(p, data)
    sp = Path(config_dir) / "settings.json"
    settings = _read_json(sp)
    if accept_bypass and settings.get("skipDangerousModePermissionPrompt") is not True:
        settings["skipDangerousModePermissionPrompt"] = True
        _write_json(sp, settings)
    elif not accept_bypass and "skipDangerousModePermissionPrompt" in settings:
        settings.pop("skipDangerousModePermissionPrompt")
        _write_json(sp, settings)
    return p


# ---------------------------------------------------------------------------
# What is on screen: the prompt box, or a dialog in front of it
# ---------------------------------------------------------------------------

class BlockingDialog(TimeoutError):
    """A start-up dialog that waiting cannot clear is on screen (the prompt
    will not appear by itself). A TimeoutError, so callers that handle "the
    prompt did not appear" handle it too."""


# Dialogs wait_ready refuses to answer, by name (the screen must match).
BLOCKING_DIALOGS = {
    "the Bypass Permissions warning (seed_config(accept_bypass=True) writes "
    "settings.json's skipDangerousModePermissionPrompt)":
        re.compile(r"Bypass Permissions mode[\s\S]*(Yes, I accept|No, exit)"),
}
TRUST_DIALOG = re.compile(r"Do you trust the files|Yes, I trust|trust this folder")
TRUST_YES = re.compile(r"Yes, I trust")
# Footers of a selection dialog (case matters: the busy footer says "esc to interrupt").
DIALOG_MARKERS = ("Enter to confirm", "Esc to cancel", "Press Enter to continue")
RULE = re.compile(r"^\s*─{20,}\s*$")


def composer_row(lines: list[str]) -> int | None:
    """The row of the prompt box: a row starting with ❯ directly below a
    horizontal rule, with another rule further down (a dialog's "❯ No, exit"
    selection pointer has no rule above it). The lowest such row, or None."""
    rules = [i for i, ln in enumerate(lines) if RULE.match(ln)]
    for i in range(len(lines) - 1, 0, -1):
        if (lines[i].lstrip().startswith(PROMPT) and RULE.match(lines[i - 1])
                and any(r > i for r in rules)):
            return i
    return None


def classify(lines: list[str]) -> tuple[str, str]:
    """("blocked", name) | ("trust", "") | ("dialog", marker) | ("ready", "")
    | ("starting", "") for a screen (a list of rows)."""
    text = "\n".join(ln.rstrip() for ln in lines)
    for name, rx in BLOCKING_DIALOGS.items():
        if rx.search(text):
            return "blocked", name
    if TRUST_DIALOG.search(text):
        return "trust", ""
    for m in DIALOG_MARKERS:
        if m in text:
            return "dialog", m
    if composer_row(lines) is not None or "? for shortcuts" in text:
        return "ready", ""
    return "starting", ""


class Session:
    """One interactive `claude` in a PTY against a fake API (see module doc)."""

    def __init__(self, root: os.PathLike | str, cwd: os.PathLike | str | None = None, *,
                 plugin_dirs=(), api: FakeAPI | None = None, replies=(), default_text: str = "ok",
                 config_dir: os.PathLike | str | None = None, cols: int = 120, rows: int = 40,
                 args=(), permission_mode: str | None = None, debug_file: bool | str = False,
                 extra_env: dict | None = None, inherit_env=(), observer: bool = False,
                 claude: str | None = None, history: int = 5000, start: bool = True,
                 home: os.PathLike | str | None = None, state_root: os.PathLike | str | None = None,
                 trust_cwd: bool = True, accept_bypass: bool = True,
                 allow_inert_gateway: bool = False):
        self.root = safety.check_scratch(Path(root), "session root")
        self.root.mkdir(parents=True, exist_ok=True)
        self.config_dir = safety.check_scratch(Path(config_dir) if config_dir else self.root / "cfg",
                                               "CLAUDE_CONFIG_DIR")
        self.home = safety.check_scratch(Path(home), "HOME") if home else self.root / "home"
        # Plugin state roots (CHECKPOINT_HOME, XDG_*, ...): shared by every
        # Session on this config unless given (safety.state_root_for).
        self.state_root = safety.check_scratch(
            Path(state_root) if state_root else safety.state_root_for(self.config_dir), "state root")
        self.trust_cwd = trust_cwd
        self.accept_bypass = accept_bypass
        self.allow_inert_gateway = allow_inert_gateway
        self.gateway_mode: str | None = None       # None, "e2e" or "inert" (check_gateways)
        self.gateway_proofs: list = []
        self.dialogs_seen: list[str] = []          # dialogs wait_ready answered ("trust")
        self.sessions: set[int] = set()            # process sessions claude's children opened
        self._sampled = 0.0
        self.tmp = self.root / "tmp"
        self.cwd = Path(cwd) if cwd else self.root / "work"
        for d in (self.config_dir, self.home, self.tmp, self.cwd):
            d.mkdir(parents=True, exist_ok=True)
        self.cols, self.rows = cols, rows
        self.redactions: list[str] = []
        self.pid: int | None = None
        self.fd: int | None = None
        self.exit_status: int | None = None
        self.raw = bytearray()
        self._tail = b""
        self._closed = False
        self.owns_api = api is None
        self.api = api or FakeAPI(self.root / "api", replies=replies, default_text=default_text)
        self.observer = Observer(self.root / "observer") if observer else None
        self.plugin_dirs = [str(Path(d)) for d in plugin_dirs]
        if self.observer:
            self.plugin_dirs.append(str(self.observer.plugin_dir))
        self.debug_path = (Path(debug_file) if isinstance(debug_file, (str, os.PathLike))
                           else self.root / "debug.log") if debug_file else None
        self.claude = claude or find_claude()
        self.extra_env = dict(extra_env or {})
        if self.observer:
            self.extra_env = {**self.observer.env(), **self.extra_env}
        self.inherit_env = tuple(inherit_env)
        self.argv = [self.claude]
        for d in self.plugin_dirs:
            self.argv += ["--plugin-dir", d]
        if permission_mode:
            self.argv += ["--permission-mode", permission_mode]
        if self.debug_path:
            self.argv += ["--debug-file", str(self.debug_path)]
        self.argv += list(args)
        self.screen = pyte.HistoryScreen(cols, rows, history=history, ratio=0.5)
        self.stream = pyte.ByteStream(self.screen)
        self.env: dict[str, str] = {}
        self.runtime_dir: Path | None = None
        if start:
            self.start()

    # ------------------------------------------------------------------ life
    def check_gateways(self) -> list:
        """The gateway guard (gwe2e.py), run by start() before anything starts:
        every gateway this session would load (enabled in the config's or the
        cwd's settings, or a --plugin-dir) must pass the e2e pre-flight now
        (and an installed one match the proof install_gateway_e2e recorded).
        Then the session runs it redirected: GATEWAY_TEST_ROOT unset,
        checkpoint pointed at the e2e gateway home (gateway_mode "e2e").
        Otherwise it refuses (UnsafePath), unless allow_inert_gateway=True:
        then GATEWAY_TEST_ROOT must stay set and every gateway hook, its MCP
        server and its stand-ins exit 2 (gateway_mode "inert")."""
        from . import gwe2e
        argv = self.argv
        dirs = [argv[i + 1] for i, a in enumerate(argv[:-1]) if a == "--plugin-dir"]
        dirs += [a.split("=", 1)[1] for a in argv if a.startswith("--plugin-dir=")]
        found = gwe2e.session_gateways(self.config_dir, self.cwd, dirs)
        proofs, problems = [], []
        for f in found:
            try:
                proofs.append(gwe2e.verify(f, self.config_dir))
            except gwe2e.NotProven as e:
                problems.append(str(e))
        self.gateway_proofs = proofs
        if problems:
            if not self.allow_inert_gateway:
                raise gwe2e.NotProven("refusing to start a session that loads the gateway "
                                      "without a proven e2e redirection:\n  " + "\n  ".join(problems))
            if not self.extra_env.get("GATEWAY_TEST_ROOT", "set"):
                raise gwe2e.NotProven("allow_inert_gateway needs GATEWAY_TEST_ROOT to stay set "
                                      "(unset, an unproven gateway uses the real ~/.config/gateway)")
            self.gateway_mode = "inert"
        elif proofs:
            if self.extra_env.get("GATEWAY_TEST_ROOT"):
                raise ValueError("GATEWAY_TEST_ROOT would make the proven e2e gateway inert "
                                 "(run.py refuses every mode while it is set)")
            self.gateway_mode = "e2e"
        else:
            self.gateway_mode = None
        return found

    def start(self) -> "Session":
        try:
            self.check_gateways()  # raises before anything starts
            extra = dict(self.extra_env)
            if self.gateway_mode == "e2e":
                for k, v in self.gateway_proofs[0].env().items():
                    if k == "GATEWAY_TEST_ROOT" or k not in extra:
                        extra[k] = v
            if self.api.port is None:
                self.api.start()
            trusted = sorted({str(self.cwd), os.path.realpath(self.cwd)}) if self.trust_cwd else []
            seed_config(self.config_dir, trusted, safety.FAKE_API_KEY, accept_bypass=self.accept_bypass)
            self.runtime_dir = safety.short_runtime_dir()
            self.env = safety.hermetic_env(
                config_dir=self.config_dir, home=self.home, tmpdir=self.tmp,
                base_url=self.api.url, runtime_dir=self.runtime_dir, state_root=self.state_root,
                cols=self.cols, rows=self.rows, inherit=self.inherit_env, extra=extra)
            # The checks that matter most, made right before exec.
            safety.check_scratch(self.env["CLAUDE_CONFIG_DIR"], "CLAUDE_CONFIG_DIR")
            if self.gateway_mode == "inert" and not self.env.get("GATEWAY_TEST_ROOT"):
                raise safety.UnsafePath("an unproven gateway needs GATEWAY_TEST_ROOT set")
            if self.gateway_mode == "e2e" and "GATEWAY_TEST_ROOT" in self.env:
                raise safety.UnsafePath("the e2e gateway needs GATEWAY_TEST_ROOT unset")
            winsz = struct.pack("HHHH", self.rows, self.cols, 0, 0)
            pid, fd = pty.fork()
            if pid == 0:  # child: never returns
                try:
                    fcntl.ioctl(1, termios.TIOCSWINSZ, winsz)
                    os.chdir(self.cwd)
                    os.execve(self.claude, self.argv, self.env)
                finally:
                    os._exit(127)
            self.pid, self.fd = pid, fd
            fcntl.ioctl(fd, termios.TIOCSWINSZ, winsz)
            _LIVE.add(self)
        except BaseException:
            self.close()
            raise
        return self

    def alive(self) -> bool:
        """True while the claude child runs (reaps it when it ended)."""
        if self.pid is None or self.exit_status is not None:
            return False
        try:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
        except ChildProcessError:  # reaped by safety.kill_tree
            self.exit_status = safety.EXIT_STATUS.get(self.pid, -1)
            return False
        if pid == 0:
            return True
        self.exit_status = os.waitstatus_to_exitcode(status)
        return False

    def close(self) -> None:
        """Kill claude and everything it started, close the PTY, stop the owned API."""
        if self._closed:
            return
        self._closed = True
        try:
            if self.pid is not None:
                drain = (lambda: self.pump(0.05)) if self.fd is not None else None
                safety.kill_tree(self.pid, grace=3.0, drain=drain, sessions=self.sessions,
                                 match=self._ours)
                self.alive()
        finally:
            if self.fd is not None:
                try:
                    os.close(self.fd)
                except OSError:
                    pass
                self.fd = None
            if self.owns_api:
                self.api.stop()
            if self.runtime_dir is not None:
                shutil.rmtree(self.runtime_dir, ignore_errors=True)
            _LIVE.discard(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _ours(self, command: str) -> bool:
        """A command line naming one of this session's scratch places (its
        root, config, state root, or a proven gateway's e2e folders): what
        close() may sweep up in the sessions claude's children opened."""
        keys = {str(self.root), str(self.config_dir), str(self.state_root)}
        for pr in self.gateway_proofs:
            keys |= {pr.root, pr.run or pr.root}
        return any(k and k in command for k in keys)

    def _sample_sessions(self) -> None:
        """Record the session ids of claude's descendants (every 2 s while
        pumping): a mod's process runs in a session of its own, and what it
        leaves behind when it dies is found again by that id at close()."""
        if self.pid is None or self.exit_status is not None or time.time() - self._sampled < 2.0:
            return
        self._sampled = time.time()
        self.sessions |= safety.sessions_of(safety.descendants(self.pid)) - {self.pid}

    # ------------------------------------------------------------------ I/O
    def pump(self, t: float = 0.2) -> int:
        """Read PTY output for up to t seconds; returns bytes read."""
        if self.fd is None:
            return 0
        if not self._closed:
            self._sample_sessions()
        got = 0
        end = time.time() + t
        while True:
            left = max(0.0, end - time.time())
            try:
                r, _, _ = select.select([self.fd], [], [], left)
            except (OSError, ValueError):
                break
            if not r:
                break
            try:
                b = os.read(self.fd, 65536)
            except OSError:
                break
            if not b:
                break
            got += len(b)
            self.raw += b
            self.stream.feed(b)
            self._answer_queries(b)
            if time.time() >= end:
                break
        return got

    def _answer_queries(self, b: bytes) -> None:
        buf = self._tail + b
        cut = len(self._tail)
        for m in QUERY_DSR.finditer(buf):
            if m.end() > cut:
                y, x = self.screen.cursor.y + 1, self.screen.cursor.x + 1
                self.send(f"\x1b[{y};{x}R")
        for m in QUERY_DA1.finditer(buf):
            if m.end() > cut:
                self.send("\x1b[?62;22c")
        self._tail = buf[-16:]

    def send(self, data: str | bytes) -> None:
        """Write raw bytes (or UTF-8 text) to the PTY."""
        if self.fd is None:
            raise RuntimeError("session is closed")
        b = data.encode() if isinstance(data, str) else bytes(data)
        while b:
            try:
                n = os.write(self.fd, b)
            except BlockingIOError:
                self.pump(0.01)
                continue
            b = b[n:]

    def type(self, text: str, delay: float = 0.02) -> None:
        """Type text one character at a time, pumping output in between."""
        for ch in text:
            self.send(ch)
            self.pump(delay)

    def paste(self, text: str, settle: float = 0.3) -> None:
        """Paste text as a terminal does with bracketed paste on."""
        self.send("\x1b[200~" + text + "\x1b[201~")
        self.pump(settle)

    def key(self, name: str, repeat: int = 1, settle: float = 0.1) -> None:
        """Press a named key (KEYS), e.g. key('down', 2), key('enter')."""
        seq = KEYS[name.lower()]
        for _ in range(repeat):
            self.send(seq)
            self.pump(settle)

    def enter(self) -> None:
        self.key("enter")

    def submit(self, text: str, settle: float = 0.4) -> None:
        """Type text into the prompt box and press Enter (with a pause so a
        slash command's autocomplete settles first)."""
        self.type(text)
        self.pump(settle)
        self.enter()

    def click(self, x: int, y: int, button: int = 0, settle: float = 0.3) -> None:
        """Left (button 0) press+release at 0-based screen cell (x=col, y=row)."""
        self.send(f"\x1b[<{button};{x + 1};{y + 1}M")
        self.pump(0.05)
        self.send(f"\x1b[<{button};{x + 1};{y + 1}m")
        self.pump(settle)

    def click_text(self, needle: str, dx: int = 0, nth: int = -1, settle: float = 0.3) -> tuple[int, int]:
        """Click the nth (default: last) occurrence of `needle` on screen,
        `dx` cells right of its first character. Returns (col, row)."""
        hits = self.find_text(needle)
        if not hits:
            raise LookupError(f"text not on screen: {self._redact(needle)!r}\n{self.dump()}")
        col, row = hits[nth]
        self.click(col + dx, row, settle=settle)
        return col, row

    def resize(self, cols: int, rows: int, settle: float = 0.5) -> None:
        """Change the terminal size (the TUI gets SIGWINCH)."""
        self.cols, self.rows = cols, rows
        self.screen.resize(rows, cols)
        if self.fd is not None:
            fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        if self.pid:
            try:
                os.killpg(os.getpgid(self.pid), signal.SIGWINCH)
            except OSError:
                pass
        self.pump(settle)

    # ------------------------------------------------------------ the screen
    def _row_cells(self, row: int) -> list[tuple[int, str]]:
        line = self.screen.buffer[row]
        out = []
        for x in range(self.screen.columns):
            ch = line[x].data
            if ch == "":
                continue  # second cell of a wide character
            out.append((x, ch))
        return out

    def lines(self) -> list[str]:
        return list(self.screen.display)

    def text(self) -> str:
        """The visible screen as text."""
        return "\n".join(line.rstrip() for line in self.screen.display)

    def all_text(self) -> str:
        """Scrollback (pyte history) plus the visible screen."""
        hist = []
        for line in self.screen.history.top:
            hist.append("".join(line[x].data for x in range(self.screen.columns)).rstrip())
        return "\n".join(hist + [self.text()])

    def find_text(self, needle: str) -> list[tuple[int, int]]:
        """(col, row) cells where `needle` starts on the visible screen."""
        hits = []
        for row in range(self.screen.lines):
            cells = self._row_cells(row)
            s = "".join(ch for _, ch in cells)
            start = s.find(needle)
            while start >= 0:
                hits.append((cells[start][0], row))
                start = s.find(needle, start + 1)
        return hits

    def composer(self) -> str:
        """The prompt box's first line (see composer_row), without the ❯
        marker; "" when no prompt box is on screen (a dialog's selection
        pointer is not one)."""
        lines = list(self.screen.display)
        i = composer_row(lines)
        return lines[i].lstrip()[len(PROMPT):].strip(" \xa0") if i is not None else ""

    def state(self) -> tuple[str, str]:
        """classify() of the visible screen."""
        return classify(list(self.screen.display))

    def mark(self) -> int:
        """A position in the raw output, for raw_since()."""
        return len(self.raw)

    def raw_since(self, mark: int) -> bytes:
        return bytes(self.raw[mark:])

    def wait_for(self, pattern: str, timeout: float = 30.0, where: str = "screen"):
        """Pump until regex `pattern` matches the screen ("screen"), the
        scrollback + screen ("all") or the raw output ("raw", bytes regex
        from the UTF-8 pattern). Returns the match, or None on timeout."""
        rx = re.compile(pattern.encode() if where == "raw" else pattern)
        end = time.time() + timeout
        while True:
            hay = (bytes(self.raw) if where == "raw" else
                   self.all_text() if where == "all" else self.text())
            m = rx.search(hay)
            if m:
                return m
            if time.time() >= end or (not self.alive() and not self.pump(0.05)):
                hay = (bytes(self.raw) if where == "raw" else
                       self.all_text() if where == "all" else self.text())
                return rx.search(hay)
            self.pump(0.1)

    def expect(self, pattern: str, timeout: float = 30.0, where: str = "screen"):
        """wait_for that raises TimeoutError with a (redacted) screen dump."""
        m = self.wait_for(pattern, timeout, where)
        if not m:
            raise TimeoutError(f"no match for {pattern!r} within {timeout}s "
                               f"(claude {'alive' if self.alive() else f'exited {self.exit_status}'})\n"
                               + self.dump())
        return m

    def wait_ready(self, timeout: float = 60.0) -> None:
        """Wait for the prompt box (composer_row, or "? for shortcuts", with
        no dialog footer on screen). A folder-trust dialog is accepted (the
        pointer is moved to "Yes, I trust this folder" first: Enter on its
        default "No, exit" quits). A known blocking dialog (BLOCKING_DIALOGS,
        such as the Bypass Permissions warning) raises BlockingDialog at once,
        any other dialog that is still up at the timeout raises TimeoutError;
        both carry the (redacted) screen."""
        end = time.time() + timeout
        last = ("starting", "")
        while time.time() < end:
            self.pump(0.2)
            last = self.state()
            kind, detail = last
            if kind == "blocked":
                raise BlockingDialog(f"a blocking dialog is up: {detail}\n" + self.dump())
            if kind == "trust":
                self._accept_trust(end)
                continue
            if kind == "ready":
                return
            if not self.alive():
                break
        what = {"dialog": f"a dialog is up ({last[1]!r})", "trust": "the trust dialog stayed up"}
        raise TimeoutError(f"the prompt did not appear: {what.get(last[0], last[0])} "
                           f"(claude {'alive' if self.alive() else f'exited {self.exit_status}'})\n"
                           + self.dump())

    def _accept_trust(self, end: float) -> None:
        """Move the trust dialog's pointer to "Yes, I trust ..." and press Enter
        (never Enter on another option)."""
        self.pump(0.8)  # the dialog takes keys only once it has settled
        for _ in range(4):
            sel = [ln for ln in self.screen.display if PROMPT in ln]
            if any(TRUST_YES.search(ln) for ln in sel):
                self.key("enter", settle=0.5)
                self.dialogs_seen.append("trust")
                return
            if time.time() >= end or not self.alive():
                return
            self.key("down", settle=0.4)

    # ---------------------------------------------------------------- dumps
    def redact(self, *values: str) -> None:
        """Never show these values in dumps or exception messages."""
        self.redactions.extend(v for v in values if v)

    def _redact(self, s: str) -> str:
        for v in self.redactions:
            s = s.replace(v, "<redacted>")
        return s

    def dump(self, last: int | None = None) -> str:
        """The visible screen (redacted), optionally only its last N non-empty lines."""
        lines = [ln.rstrip() for ln in self.screen.display]
        if last:
            lines = [ln for ln in lines if ln.strip()][-last:]
        return self._redact("\n".join(lines))

    # ------------------------------------------------------------- artefacts
    def transcripts(self) -> list[Path]:
        return sorted((self.config_dir / "projects").rglob("*.jsonl"))

    @property
    def history_file(self) -> Path:
        return self.config_dir / "history.jsonl"


@atexit.register
def _close_all() -> None:
    for s in list(_LIVE):
        try:
            s.close()
        except Exception:
            pass
