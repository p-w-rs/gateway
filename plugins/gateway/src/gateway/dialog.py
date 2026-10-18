"""Native dialogs: the one place a person types a secret or approves a change.

Claude never sees what is typed here: the dialog is opened by the gateway's own
process (a hook or the MCP server) and the answer comes straight back to it.
Claude Code's own question pop-ups are not used for values, because their
answers go to the model.

- macOS: `osascript` (`display dialog`, hidden answer for secrets).
- Linux desktop: `zenity`, else `kdialog` (needs DISPLAY or WAYLAND_DISPLAY).
- Anywhere else (ssh session, headless): `Unavailable`, and the caller tells
  the user the terminal command instead.
- Tests: GATEWAY_DIALOG=/path/to/script, called as
  `script KIND TITLE MESSAGE [DEFAULT]` with KIND confirm|secret|text|file;
  it prints the answer and exits 0, or exits 1 for Cancel.

Text shown in a dialog is passed as arguments, never spliced into a script, so
names and descriptions can't inject AppleScript or shell.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

TITLE = "Gateway"
TIMEOUT = 300  # seconds a dialog waits before it counts as Cancel


class Unavailable(Exception):
    """No way to show a dialog here (headless, ssh, no zenity/kdialog)."""


def _backend() -> str:
    fake = os.environ.get("GATEWAY_DIALOG")
    if fake == "none":
        raise Unavailable("dialogs turned off (GATEWAY_DIALOG=none)")
    if fake:
        return "fake"
    if sys.platform == "darwin":
        if os.environ.get("SSH_CONNECTION") or not shutil.which("osascript"):
            raise Unavailable("no display (ssh session)")
        return "osascript"
    if sys.platform.startswith("linux"):
        if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
            raise Unavailable("no display")
        for tool in ("zenity", "kdialog"):
            if shutil.which(tool):
                return tool
        raise Unavailable("neither zenity nor kdialog is installed")
    raise Unavailable(f"no dialogs on {sys.platform}")


def available() -> bool:
    try:
        _backend()
        return True
    except Unavailable:
        return False


# AppleScript that reads everything from argv: (kind, title, message, default).
_OSA = r'''
on run argv
    set gwKind to item 1 of argv
    set gwTitle to item 2 of argv
    set gwMsg to item 3 of argv
    set gwDefault to item 4 of argv
    if gwKind is "confirm" then
        display dialog gwMsg with title gwTitle buttons {"Cancel", "Allow"} default button "Allow" cancel button "Cancel" with icon caution giving up after %d
        if gave up of result then error number -128
        return "yes"
    else if gwKind is "secret" then
        set r to display dialog gwMsg with title gwTitle default answer "" with hidden answer buttons {"Cancel", "Save"} default button "Save" cancel button "Cancel" with icon caution giving up after %d
        if gave up of r then error number -128
        return text returned of r
    else if gwKind is "file" then
        return POSIX path of (choose file with prompt gwMsg default location (POSIX file gwDefault))
    else
        set r to display dialog gwMsg with title gwTitle default answer gwDefault buttons {"Cancel", "OK"} default button "OK" cancel button "Cancel" giving up after %d
        if gave up of r then error number -128
        return text returned of r
    end if
end run
''' % (TIMEOUT, TIMEOUT, TIMEOUT)


def _run(kind: str, message: str, default: str = "", title: str = TITLE) -> str | None:
    """The answer, or None for Cancel / timeout."""
    backend = _backend()
    if backend == "fake":
        argv = [os.environ["GATEWAY_DIALOG"], kind, title, message, default]
    elif backend == "osascript":
        argv = ["osascript", "-e", _OSA, kind, title, message, default or os.path.expanduser("~")]
    elif backend == "zenity":
        base = ["zenity", f"--title={title}", f"--timeout={TIMEOUT}"]
        argv = base + {
            "confirm": ["--question", f"--text={message}", "--ok-label=Allow"],
            "secret": ["--password"],
            "file": ["--file-selection", f"--filename={default or os.path.expanduser('~')}/"],
        }.get(kind, ["--entry", f"--text={message}", f"--entry-text={default}"])
    else:  # kdialog
        argv = ["kdialog", "--title", title] + {
            "confirm": ["--yesno", message],
            "secret": ["--password", message],
            "file": ["--getopenfilename", default or os.path.expanduser("~")],
        }.get(kind, ["--inputbox", message, default])
    if backend == "zenity" and kind == "secret":
        # zenity's password dialog has no message line; show it as the title.
        argv[1] = f"--title={title}: {message}"
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=TIMEOUT + 30,
                           stdin=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        return None
    if r.returncode != 0:
        return None
    out = r.stdout
    return out[:-1] if out.endswith("\n") else out


def confirm(message: str, title: str = TITLE) -> bool:
    """Show `message` with Allow / Cancel. True only for Allow."""
    return _run("confirm", message, title=title) is not None


def secret(message: str, title: str = TITLE) -> str | None:
    """Hidden input. None for Cancel; "" if the person saved an empty field."""
    return _run("secret", message, title=title)


def text(message: str, default: str = "", title: str = TITLE) -> str | None:
    return _run("text", message, default, title=title)


def choose_file(message: str, start: str = "", title: str = TITLE) -> str | None:
    """A file picker (used for importing an existing key file)."""
    return _run("file", message, start, title=title)
