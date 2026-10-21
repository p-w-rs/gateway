"""Terminal screen helpers for gated's supervisor (PLAN-v4 phase 5).

Pure functions, no tmux and no state: what `tmux capture-pane -e` prints is
turned into plain lines (for the agent's bounded reads) and styled runs (for
the terminal pane's Client); a pane's raw output stream (a job's pipe-pane)
into readable text; key names and signal names checked.

- `split_escapes(text)`: (plain, runs) for one captured line. SGR sequences
  (colours, bold, dim, italic, underline, inverse, strike) become run styles;
  every other escape sequence and control character is dropped.
- `clean_stream(data)`: a PTY byte stream as text: escape sequences removed,
  CR LF made LF, a lone CR (a progress bar redrawing its line) keeps only
  what came after it, other control characters dropped.
- `tmux_key(name)`: an agent's or the pane's key name as tmux spells it
  ("Enter", "C-c", "Up", "F5", "M-x"), or None when it isn't one we send.
- `SIGNALS`: the signals the tools may send, by name.
"""
from __future__ import annotations

import re
import signal

# ---------------------------------------------------------------------------
# SGR -> runs
# ---------------------------------------------------------------------------

_TOKEN = re.compile(
    r"(\x1b\[[0-9;:]*m)"                                   # SGR
    r"|(\x1b(?:\[[0-9;:?<=>]*[ -/]*[@-~]"                  # other CSI
    r"|\][^\x07\x1b]*(?:\x07|\x1b\\)?"                     # OSC (titles, hyperlinks)
    r"|[PX^_][^\x1b]*(?:\x1b\\)?"                          # DCS, SOS, PM, APC
    r"|[()*+][0-9A-Za-z]"                                  # charset designations
    r"|.?))"                                               # anything else after ESC
    , re.S)
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
BASIC = ("black", "red", "green", "yellow", "blue", "magenta", "cyan", "white")
BRIGHT = ("#7f7f7f", "#ff5555", "#55ff55", "#ffff55", "#5c5cff", "#ff55ff", "#55ffff", "#ffffff")


def _c256(n: int) -> str:
    if n < 8:
        return BASIC[n]
    if n < 16:
        return BRIGHT[n - 8]
    if n < 232:
        n -= 16
        lv = (0, 95, 135, 175, 215, 255)
        return "#%02x%02x%02x" % (lv[n // 36], lv[(n // 6) % 6], lv[n % 6])
    g = 8 + 10 * (n - 232)
    return "#%02x%02x%02x" % (g, g, g)


def _apply(style: dict, params: str) -> dict:
    s = dict(style)
    parts = re.split(r"[;:]", params) if params else ["0"]
    nums: list[int] = []
    for p in parts:
        try:
            nums.append(int(p) if p else 0)
        except ValueError:
            nums.append(0)
    i = 0
    while i < len(nums):
        n = nums[i]
        if n == 0:
            s = {}
        elif n == 1:
            s["b"] = 1
        elif n == 2:
            s["d"] = 1
        elif n == 3:
            s["i"] = 1
        elif n == 4:
            s["u"] = 1
        elif n == 7:
            s["r"] = 1
        elif n == 9:
            s["s"] = 1
        elif n in (21, 22):
            s.pop("b", None)
            s.pop("d", None)
        elif n == 23:
            s.pop("i", None)
        elif n == 24:
            s.pop("u", None)
        elif n == 27:
            s.pop("r", None)
        elif n == 29:
            s.pop("s", None)
        elif 30 <= n <= 37:
            s["fg"] = BASIC[n - 30]
        elif 90 <= n <= 97:
            s["fg"] = BRIGHT[n - 90]
        elif 40 <= n <= 47:
            s["bg"] = BASIC[n - 40]
        elif 100 <= n <= 107:
            s["bg"] = BRIGHT[n - 100]
        elif n == 39:
            s.pop("fg", None)
        elif n == 49:
            s.pop("bg", None)
        elif n in (38, 48):
            key = "fg" if n == 38 else "bg"
            if i + 2 < len(nums) and nums[i + 1] == 5:
                s[key] = _c256(max(0, min(255, nums[i + 2])))
                i += 2
            elif i + 1 < len(nums) and nums[i + 1] == 2 and i + 4 < len(nums):
                r, g, b = (max(0, min(255, x)) for x in nums[i + 2:i + 5])
                s[key] = "#%02x%02x%02x" % (r, g, b)
                i += 4
        i += 1
    return s


def split_escapes(text: str) -> tuple[str, list[dict]]:
    """(plain text, styled runs) for one line of `capture-pane -e` output."""
    plain: list[str] = []
    runs: list[dict] = []
    style: dict = {}
    pos = 0

    def add(seg: str) -> None:
        seg = _CTRL.sub("", seg.replace("\t", " "))
        if not seg:
            return
        plain.append(seg)
        if runs and {k: v for k, v in runs[-1].items() if k != "t"} == style:
            runs[-1]["t"] += seg
        else:
            runs.append({"t": seg, **style})

    for m in _TOKEN.finditer(text):
        if m.start() > pos:
            add(text[pos:m.start()])
        if m.group(1):
            style = _apply(style, m.group(1)[2:-1])
        pos = m.end()
    if pos < len(text):
        add(text[pos:])
    return "".join(plain), runs


def strip_escapes(text: str) -> str:
    return split_escapes(text)[0]


# ---------------------------------------------------------------------------
# A raw PTY stream -> text
# ---------------------------------------------------------------------------


def clean_stream(data: bytes) -> str:
    """A job's raw terminal output as readable text (see the module doc)."""
    text = data.decode("utf-8", "replace")
    text = _TOKEN.sub(lambda m: "", text)
    text = text.replace("\r\n", "\n")
    out_lines = []
    for line in text.split("\n"):
        if "\r" in line:
            # what a terminal shows after a carriage return: the last segment
            # written over the earlier ones (longer earlier tails stay)
            shown = ""
            for seg in line.split("\r"):
                shown = seg + shown[len(seg):]
            line = shown
        out_lines.append(_CTRL.sub("", line.replace("\t", "    ")))
    return "\n".join(out_lines)


# ---------------------------------------------------------------------------
# Keys and signals
# ---------------------------------------------------------------------------

NAMED = {
    "enter": "Enter", "return": "Enter", "tab": "Tab", "btab": "BTab", "backtab": "BTab",
    "backspace": "BSpace", "bspace": "BSpace", "escape": "Escape", "esc": "Escape",
    "up": "Up", "down": "Down", "left": "Left", "right": "Right", "home": "Home", "end": "End",
    "pageup": "PPage", "ppage": "PPage", "pgup": "PPage", "pagedown": "NPage", "npage": "NPage",
    "pgdn": "NPage", "insert": "IC", "ic": "IC", "delete": "DC", "dc": "DC", "space": "Space",
}
for _i in range(1, 13):
    NAMED[f"f{_i}"] = f"F{_i}"
_CTRL_KEY = re.compile(r"^(?:c-|ctrl-|ctrl\+|\^)(.)$", re.I)
_META_KEY = re.compile(r"^(?:m-|meta-|alt-|alt\+|meta\+)(.)$", re.I)
CTRL_OK = set("abcdefghijklmnopqrstuvwxyz@[\\]^_ ")


def tmux_key(name: object) -> str | None:
    """tmux's spelling of one key name, or None."""
    if not isinstance(name, str) or not name or len(name) > 16:
        return None
    low = name.strip().lower()
    if low in NAMED:
        return NAMED[low]
    m = _CTRL_KEY.match(name.strip())
    if m:
        c = m.group(1).lower()
        if c in CTRL_OK:
            return "C-Space" if c == " " else f"C-{c}"
        return None
    m = _META_KEY.match(name.strip())
    if m:
        c = m.group(1)
        if c.isprintable() and c != " ":
            return f"M-{c}"
    return None


SIGNALS = {"INT": signal.SIGINT, "TERM": signal.SIGTERM, "KILL": signal.SIGKILL,
           "HUP": signal.SIGHUP, "QUIT": signal.SIGQUIT, "STOP": signal.SIGSTOP,
           "CONT": signal.SIGCONT, "TSTP": signal.SIGTSTP, "USR1": signal.SIGUSR1,
           "USR2": signal.SIGUSR2, "WINCH": signal.SIGWINCH}


def signal_name(v: object) -> str | None:
    if not isinstance(v, str):
        return None
    n = v.strip().upper()
    if n.startswith("SIG"):
        n = n[3:]
    return n if n in SIGNALS else None
