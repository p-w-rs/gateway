"""A conservative Bash command splitter for the approval hook (SPEC 8).

`parse(command)` returns a list of **segments** (split on `;`, `&&`, `||` and
newlines); each segment is a list of **pipeline stages** (split on `|`); each
stage is a `Stage`: a list of argv words. It returns **None** ("too complex to
judge, let Claude Code decide") whenever the command uses anything the hook
cannot reason about safely:

    $( …)   ` … `   <( …)   >( …)   heredocs/here-strings (<< <<<)
    eval    exec    source / .     shell functions / subshells ( … )
    sh|bash|zsh -c (in command position)        backgrounding &
    redirections other than > >> 2>&1 2>FILE to plain files
    any assignment prefix other than GATE_ACCOUNT=NAME

An unquoted `#` at the start of a word starts a comment to the end of the line
(as in bash), and a newline right after `|`, `&&` or `||` continues the
pipeline or list, so the words judged are the words bash runs.

Quoting is honoured, so `echo "curl …"` yields a single word `curl …` (curl is
not in command position), while `curl …` yields a stage whose command word is
`curl`. A leading `GATE_ACCOUNT=NAME` assignment is kept as the stage's first
word (the caller strips it); every other `NAME=value` prefix makes the whole
command unparseable.

A `Stage` compares equal to the plain word list, and also carries what the
words alone hide (the hook must never vouch for what it cannot see):

- `redirects`: the stage's output redirections, in order, as `(op, target)`
  with `op` one of `>`, `>>`, `2>`, `2>&1` (target `""`). They are recorded,
  never silently dropped: `echo x >> ~/.ssh/authorized_keys` is a write.
- `expands[i]`: word i contains a parameter expansion the shell resolves and
  the parser can't: `$NAME`, `${…}`, `$1`, `$'…'`, `$"…"` outside single
  quotes. `$HOME` / `${HOME}` alone don't count (the hook substitutes them).
- `globs[i]`: word i contains an unquoted glob or brace expansion
  (`*`, `?`, `[…]`, `{…}`), which the shell expands to other words.
"""
from __future__ import annotations

import os
import re

_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_FD_REDIR = re.compile(r"(\d+)(>>?|<)")
_HOME_REF = re.compile(r"\$(?:HOME(?![A-Za-z0-9_])|\{HOME\})")
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "fish", "csh", "tcsh", "ash"})
_GIVEUP_WORDS = frozenset({"eval", "exec", "source", ".", "{", "}"})


class _Bail(Exception):
    """The command is too complex to judge; parse() returns None."""


class Stage(list):
    """The argv words of one pipeline stage, plus `redirects`, `expands` and
    `globs` (see the module docstring). Equal to the plain list of words."""

    def __init__(self, words=(), expands=(), globs=(), redirects=()):
        super().__init__(words)
        self.expands: list[bool] = list(expands) or [False] * len(self)
        self.globs: list[bool] = list(globs) or [False] * len(self)
        self.redirects: list[tuple[str, str]] = list(redirects)


def parse(command: str, comments: bool = True) -> list[list[Stage]] | None:
    """`comments=True` reads `#` at the start of an unquoted word as a comment
    to the end of the line, as bash and zsh do for `-c` commands (Claude's
    Bash and Monitor). `comments=False` reads it as an ordinary character, as
    an interactive zsh without INTERACTIVE_COMMENTS does (the user's Terminal
    panel)."""
    if not isinstance(command, str):
        return None
    try:
        return _parse(command, comments)
    except _Bail:
        return None


# ---------------------------------------------------------------------------


class _Word:
    """A word being built: its text plus whether an unknown expansion or an
    unquoted glob/brace character appeared in it."""

    __slots__ = ("buf", "started", "expands", "bare")

    def __init__(self) -> None:
        self.buf: list[str] = []
        self.started = False
        self.expands = False
        self.bare: list[str] = []      # unquoted glob/brace characters, in order

    def add(self, s: str) -> None:
        self.buf.append(s)
        self.started = True

    def globbed(self) -> bool:
        b = self.bare
        if "*" in b or "?" in b:
            return True
        for o, c in (("[", "]"), ("{", "}")):
            if o in b and c in b[b.index(o) + 1:]:
                return True
        return False


def _dollar_expands(cmd: str, i: int, in_dq: bool = False) -> bool:
    """Is the `$` at cmd[i] (outside single quotes) an expansion the parser
    can't resolve? `$` at the end, or before a blank/operator, is literal (and
    before the closing `"` inside double quotes); `$'…'` and `$"…"` outside
    double quotes are expansions; `$HOME`/`${HOME}` are resolved by the hook."""
    if i + 1 >= len(cmd) or cmd[i + 1] in " \t\n;|&<>)":
        return False
    if in_dq and cmd[i + 1] == '"':
        return False
    return not _HOME_REF.match(cmd, i)


def _read_target(cmd: str, i: int) -> tuple[str | None, int]:
    """Read a redirection target (a plain filename) starting at i. Honours
    quotes; stops at whitespace or an operator. (None, i) if there is none.
    A target the shell would expand (`$X`, a glob) is not a plain file."""
    n = len(cmd)
    buf: list[str] = []
    if i < n and cmd[i] == "#":
        raise _Bail()                        # `>#x`: bash reads a comment (a syntax error)
    while i < n:
        c = cmd[i]
        if c in " \t\n" or c in ";|&<>()`":
            break
        if c == "'":
            j = cmd.find("'", i + 1)
            if j < 0:
                raise _Bail()
            buf.append(cmd[i + 1:j])
            i = j + 1
            continue
        if c == '"':
            j = i + 1
            b: list[str] = []
            while j < n and cmd[j] != '"':
                if cmd[j] in "`$":
                    raise _Bail()
                if cmd[j] == "\\" and j + 1 < n and cmd[j + 1] in '"\\$`':
                    b.append(cmd[j + 1])
                    j += 2
                    continue
                b.append(cmd[j])
                j += 1
            if j >= n:
                raise _Bail()
            buf.append("".join(b))
            i = j + 1
            continue
        if c == "\\" and i + 1 < n:
            buf.append(cmd[i + 1])
            i += 2
            continue
        if c == "$" and _dollar_expands(cmd, i):
            raise _Bail()
        if c in "*?[{":
            raise _Bail()
        buf.append(c)
        i += 1
    if not buf:
        return None, i
    return "".join(buf), i


def _tokenize(cmd: str, comments: bool = True) -> list[tuple]:
    """('word', text, expands, globbed) | ('op', 'semi'|'and'|'or'|'pipe'|'newline')
    | ('redir', op, target). Anything unsafe raises _Bail."""
    tokens: list[tuple] = []
    w = _Word()
    i, n = 0, len(cmd)

    def flush() -> None:
        nonlocal w
        if w.started:
            tokens.append(("word", "".join(w.buf), w.expands, w.globbed()))
        w = _Word()

    while i < n:
        c = cmd[i]
        if c == "#" and comments and not w.started:
            # An unquoted `#` starting a word starts a comment: bash drops the
            # rest of the line (a quote or `;` in it is part of the comment).
            # The newline itself still ends the segment.
            j = cmd.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "'":                         # single quotes: literal
            j = cmd.find("'", i + 1)
            if j < 0:
                raise _Bail()
            w.add(cmd[i + 1:j])
            i = j + 1
            continue
        if c == '"':                         # double quotes
            j = i + 1
            buf: list[str] = []
            while j < n and cmd[j] != '"':
                if cmd[j] == "`":
                    raise _Bail()
                if cmd[j] == "$":
                    if j + 1 < n and cmd[j + 1] == "(":
                        raise _Bail()
                    if _dollar_expands(cmd, j, in_dq=True):
                        w.expands = True
                if cmd[j] == "\\" and j + 1 < n and cmd[j + 1] in '"\\$`':
                    buf.append(cmd[j + 1])
                    j += 2
                    continue
                buf.append(cmd[j])
                j += 1
            if j >= n:
                raise _Bail()
            w.add("".join(buf))
            i = j + 1
            continue
        if c == "\\":
            if i + 1 < n:
                if cmd[i + 1] == "\n":       # line continuation
                    i += 2
                    continue
                w.add(cmd[i + 1])
                i += 2
                continue
            i += 1
            continue
        if c == "`":
            raise _Bail()
        if c == "$":
            if i + 1 < n and cmd[i + 1] == "(":
                raise _Bail()
            if _dollar_expands(cmd, i):
                w.expands = True             # $NAME, ${..}, $'..', $"..", $1 ...
            if i + 1 < n and cmd[i + 1] == "{":
                # ${NAME...}: its braces are not a brace expansion. Anything
                # but a plain name/operator inside is too complex to judge.
                j = cmd.find("}", i + 2)
                if j < 0 or any(ch in " \t\n'\"`$(){}<>;|&\\" for ch in cmd[i + 2:j]):
                    raise _Bail()
                w.add(cmd[i:j + 1])
                i = j + 1
                continue
            w.add(c)
            i += 1
            continue
        if c in " \t":
            flush()
            i += 1
            continue
        if c == "\n":
            flush()
            tokens.append(("op", "newline"))
            i += 1
            continue
        if c == ";":
            flush()
            if i + 1 < n and cmd[i + 1] == ";":
                raise _Bail()                # case ';;'
            tokens.append(("op", "semi"))
            i += 1
            continue
        if c == "&":
            flush()
            if i + 1 < n and cmd[i + 1] == "&":
                tokens.append(("op", "and"))
                i += 2
                continue
            raise _Bail()                    # backgrounding '&' or '&>'
        if c == "|":
            flush()
            if i + 1 < n and cmd[i + 1] == "|":
                tokens.append(("op", "or"))
                i += 2
                continue
            tokens.append(("op", "pipe"))
            i += 1
            continue
        if c in "()":
            raise _Bail()                    # subshell / function body
        if c == "<":
            raise _Bail()                    # < , << , <<< , <(
        if c == ">":
            flush()
            op = ">>" if (i + 1 < n and cmd[i + 1] == ">") else ">"
            i += 2 if op == ">>" else 1
            if i < n and cmd[i] == "&":
                raise _Bail()                # >&  (fd dup)
            while i < n and cmd[i] in " \t":
                i += 1
            tgt, i = _read_target(cmd, i)
            if tgt is None:
                raise _Bail()
            tokens.append(("redir", op, tgt))
            continue
        if c.isdigit() and not w.started:    # an fd number only starts a word
            m = _FD_REDIR.match(cmd, i)
            if m:
                fd, redir = m.group(1), m.group(2)
                j = m.end()
                if fd == "2" and redir == ">":
                    if cmd[j:j + 2] == "&1":
                        i = j + 2
                        tokens.append(("redir", "2>&1", ""))
                        continue
                    if j < n and cmd[j] == "&":
                        raise _Bail()        # 2>&N other than 1
                    while j < n and cmd[j] in " \t":
                        j += 1
                    tgt, j = _read_target(cmd, j)
                    if tgt is None:
                        raise _Bail()
                    i = j
                    tokens.append(("redir", "2>", tgt))
                    continue
                raise _Bail()                # 1> , 2>> , n< , ...
        if c in "*?[]{}":
            w.bare.append(c)
        w.add(c)
        i += 1
    flush()
    return tokens


def _command_word(stage: list[str]) -> str:
    for w in stage:
        if _ASSIGN.match(w):
            continue
        return os.path.basename(w)
    return ""


def _finish_stage(words: list[tuple[str, bool, bool]], redirects: list[tuple[str, str]]
                  ) -> Stage | None:
    """Apply the assignment-prefix rule and the give-up words. None for a
    stage with no command (empty, or assignments only)."""
    i = 0
    while i < len(words) and _ASSIGN.match(words[i][0]):
        if words[i][0].split("=", 1)[0] != "GATE_ACCOUNT":
            raise _Bail()                    # any other NAME=value prefix
        i += 1
    if i >= len(words):
        if redirects:
            raise _Bail()                    # `> file` alone truncates a file
        return None
    st = Stage([t for t, _, _ in words], [e for _, e, _ in words],
               [g for _, _, g in words], redirects)
    cw = _command_word(st)
    if cw in _GIVEUP_WORDS:
        raise _Bail()
    if cw in _SHELLS and "-c" in st:
        raise _Bail()
    return st


_CONTINUES = (("op", "pipe"), ("op", "and"), ("op", "or"))


def _parse(cmd: str, comments: bool = True) -> list[list[Stage]]:
    out: list[list[Stage]] = []
    seg: list[Stage] = []
    words: list[tuple[str, bool, bool]] = []
    redirects: list[tuple[str, str]] = []

    def end_stage() -> None:
        nonlocal words, redirects
        st = _finish_stage(words, redirects)
        if st is not None:
            seg.append(st)
        words, redirects = [], []

    def end_segment() -> None:
        nonlocal seg
        end_stage()
        if seg:
            out.append(seg)
        seg = []

    prev: tuple | None = None
    for tok in _tokenize(cmd, comments):
        if tok == ("op", "newline") and prev in _CONTINUES:
            continue                         # bash continues after `|`, `&&` or `||` at a line end
        prev = tok
        if tok[0] == "word":
            words.append((tok[1], tok[2], tok[3]))
        elif tok[0] == "redir":
            redirects.append((tok[1], tok[2]))
        elif tok[1] == "pipe":
            end_stage()
        else:                                # semi / and / or / newline
            end_segment()
    end_segment()
    return out
