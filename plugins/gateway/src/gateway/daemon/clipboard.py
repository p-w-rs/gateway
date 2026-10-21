"""The OS clipboard, read by gated for the dialog's "Paste from clipboard".

A paste into Claude Code would go through its prompt box (the composer, where
every plugin's prompt.edit hook sees it and the editor paints it); a
Client region doesn't receive pastes at all (FEASIBILITY-v4 P1). So the
button asks gated, and gated reads the clipboard itself: the value never
passes through Claude Code, the mod or the http hop.

The command is chosen by absolute path, never PATH, and only when the file
(after symlinks) belongs to root and nobody else may write to it:

    macOS   /usr/bin/pbpaste
    Linux   wl-paste --no-newline        (Wayland: WAYLAND_DISPLAY)
            xclip -selection clipboard -o, else xsel --clipboard --output
                                         (X11: DISPLAY)
            looked up in /usr/bin, /bin, /usr/local/bin, /run/current-system/sw/bin

The display variables come with the paste request, from Claude Code's own
environment (the UI plane: only the Claude Code process itself may ask),
checked against the patterns below; the daemon's own environment has none
(it is started with a fixed one). The child gets a small fixed environment.

What is accepted: one line of UTF-8 text (a trailing newline is dropped),
1 to MAX_BYTES bytes, no control characters. Anything else is refused with a
reason that never quotes the clipboard.

Tests: testing.override(clipboard=PROGRAM) runs PROGRAM instead (an
absolute path, no arguments; the TUI harness's e2e.json "clipboard" knob).
Under any other test override nothing is read ("unavailable"): a test never
touches the person's real clipboard.
"""
from __future__ import annotations

import os
import re
import stat
import subprocess
import sys

from .. import testing

MAX_BYTES = 8192
TIMEOUT = 5.0
LINUX_DIRS = ("/usr/bin", "/bin", "/usr/local/bin", "/run/current-system/sw/bin")
ENV_PATTERNS = {
    "DISPLAY": re.compile(r"[A-Za-z0-9._-]{0,64}:[0-9]{1,5}(?:\.[0-9]{1,3})?"),
    "WAYLAND_DISPLAY": re.compile(r"[A-Za-z0-9._/-]{1,200}"),
    "XAUTHORITY": re.compile(r"/[A-Za-z0-9._/@+-]{1,300}"),
    "XDG_RUNTIME_DIR": re.compile(r"/[A-Za-z0-9._/@+-]{1,300}"),
}


class ClipboardError(Exception):
    """The clipboard couldn't be read; the message says why (never what it holds)."""


def clean_env(given: object) -> dict[str, str]:
    """The display variables of a paste request that pass their patterns."""
    out: dict[str, str] = {}
    if not isinstance(given, dict):
        return out
    for k, pat in ENV_PATTERNS.items():
        v = given.get(k)
        if isinstance(v, str) and pat.fullmatch(v):
            out[k] = v
    return out


def _trusted(path: str) -> bool:
    """A regular, executable file owned by root that only root may change
    (after symlinks: /run/current-system/sw/bin links into /nix/store)."""
    try:
        real = os.path.realpath(path)
        st = os.stat(real)
    except OSError:
        return False
    return (stat.S_ISREG(st.st_mode) and st.st_uid == 0 and not st.st_mode & 0o022
            and os.access(real, os.X_OK))


def _find(name: str, dirs: tuple[str, ...]) -> str | None:
    for d in dirs:
        p = os.path.join(d, name)
        if os.path.exists(p) and _trusted(p):
            return p
    return None


def command(env: dict[str, str], platform: str | None = None) -> tuple[list[str], dict[str, str]]:
    """(argv, child env) of the production clipboard reader for this system,
    or ClipboardError when there is none."""
    plat = platform or sys.platform
    base = {"PATH": "/usr/bin:/bin", "LANG": os.environ.get("LANG", "C.UTF-8")}
    if os.environ.get("HOME", "").startswith("/"):
        base["HOME"] = os.environ["HOME"]
    if plat == "darwin":
        exe = "/usr/bin/pbpaste"
        if not _trusted(exe):
            raise ClipboardError("this Mac has no usable /usr/bin/pbpaste")
        return [exe, "-Prefer", "txt"], base
    if plat.startswith("linux"):
        if env.get("WAYLAND_DISPLAY"):
            exe = _find("wl-paste", LINUX_DIRS)
            if exe:
                child = {**base, "WAYLAND_DISPLAY": env["WAYLAND_DISPLAY"]}
                if env.get("XDG_RUNTIME_DIR"):
                    child["XDG_RUNTIME_DIR"] = env["XDG_RUNTIME_DIR"]
                return [exe, "--no-newline", "--type", "text/plain"], child
        if env.get("DISPLAY"):
            child = {**base, "DISPLAY": env["DISPLAY"]}
            if env.get("XAUTHORITY"):
                child["XAUTHORITY"] = env["XAUTHORITY"]
            exe = _find("xclip", LINUX_DIRS)
            if exe:
                return [exe, "-selection", "clipboard", "-o"], child
            exe = _find("xsel", LINUX_DIRS)
            if exe:
                return [exe, "--clipboard", "--output"], child
        if not env.get("WAYLAND_DISPLAY") and not env.get("DISPLAY"):
            raise ClipboardError("this session has no display, so there is no clipboard to read "
                                 "(type the value instead)")
        raise ClipboardError("no clipboard program was found (install wl-clipboard, xclip or "
                             "xsel, or type the value instead)")
    raise ClipboardError("reading the clipboard isn't supported on this system")


def accept(raw: bytes, multiline: bool = False) -> str:
    """The clipboard's bytes as the value, or ClipboardError. multiline (a
    dialog for a PEM certificate and key, PLAN-v4 phase 7): line breaks are
    kept (as \\n); every other control character is still refused."""
    if len(raw) > MAX_BYTES:
        raise ClipboardError(f"the clipboard holds more than {MAX_BYTES} bytes")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ClipboardError("the clipboard doesn't hold text") from None
    if text.endswith("\r\n"):
        text = text[:-2]
    elif text.endswith("\n"):
        text = text[:-1]
    if not text:
        raise ClipboardError("the clipboard is empty")
    if multiline:
        text = text.replace("\r\n", "\n")
    elif "\n" in text or "\r" in text:
        raise ClipboardError("the clipboard holds more than one line")
    if multiline and any((ord(c) < 32 and c != "\n") or ord(c) == 127 for c in text):
        raise ClipboardError("the clipboard holds control characters")
    if not multiline and any(ord(c) < 32 or ord(c) == 127 for c in text):
        raise ClipboardError("the clipboard holds control characters")
    return text


def read(env: object = None, multiline: bool = False) -> str:
    """The clipboard as one line of text (see the module docstring)."""
    o = testing.active()
    if o is not None:
        prog = testing.get("clipboard")
        if not isinstance(prog, str) or not os.path.isabs(prog):
            raise ClipboardError("the clipboard isn't available under a test override")
        argv, child = [prog], {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    else:
        argv, child = command(clean_env(env))
    try:
        p = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, env=child, timeout=TIMEOUT, cwd="/",
                           close_fds=True)
    except subprocess.TimeoutExpired:
        raise ClipboardError("reading the clipboard took too long") from None
    except OSError as e:
        raise ClipboardError(f"the clipboard couldn't be read ({type(e).__name__})") from None
    if p.returncode != 0:
        raise ClipboardError("the clipboard couldn't be read (is anything copied?)")
    out = p.stdout
    try:
        return accept(out, multiline)
    finally:
        out = b""
