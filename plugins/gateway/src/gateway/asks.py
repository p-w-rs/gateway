"""The approval hook's record that Claude Code asked (invariant 6; PLAN-0.11
§6.5, lead decision 19.14).

An "ask" value is honoured only because Claude Code asks the user about the
command first, and Claude Code asks only about the command Claude typed. So
the Bash hook writes a record for each stand-in stage it answers "ask" for
(`record`), and a stand-in passes an "ask" only for a command Claude typed
(ancestry.typed_by_claude) that matches one (`take`, `standin`): the same
Claude Code process (`session`), the same folder (its real path), the same
tool and exact words, every "ask" entry the stand-in finds among those the
hook asked about, written at most ASK_TTL ago; each record is used once. A
sourced file, eval, a function or anything else the hook can't read writes
no record, so a stand-in it starts refuses the "ask" (`refusal`: "run `ssh
box ...` as its own command").

A record lives only until the session's next Bash or Monitor call (`drop`,
which the hook runs first; while any record is pending, pre_bash.sh sends
every such call to the hook, through the `$DATA/asks` link): one left by a
prompt the user declined, by a prompt that couldn't be shown (`-p`), or by
a stage that never ran (`false && sudo x`, an account asked about but not
chosen) is gone before anything else Claude starts can use it. The hook
writes them in dontAsk too: Claude Code shows a hook's "ask" there as well.

The tools: ssh, sudo, the account CLIs (gh, hf, databricks, crane, pijul,
az), git and the gateway's own `gate` (`gate with NAME --` for an account,
`gate check|rotate|copy-to` for a host: `begin`, `current`); scp, sftp and
rsync on an "ask" are refused by the hook: the ssh they start can't be
asked about. Entries are ("hosts"|"accounts", NAME). The run folder is the
user's: a guardrail against a cooperative model, like the typed walk.
"""
from __future__ import annotations

import json
import os
import secrets
import time
from pathlib import Path
from typing import Any, Iterable

ASKS = "asks"                 # the run folder's records
LINK = "asks"                 # $DATA/asks: a link to them, for pre_bash.sh
ASK_TTL = 15 * 60             # seconds a record counts
FUTURE = 60                   # seconds ahead of now a record may be dated (clock steps)

UNASKED = ("gateway: {what} {are} set to \"ask\", and Claude Code didn't ask you about this "
           "command as it ran (it came from a script, a sourced file, eval, a function or "
           "something else the gateway can't read, ran in another folder, or ran after "
           "another of Claude's commands started); run `{example}` as its own command so "
           "Claude Code can ask you.")
EXPIRED = ("gateway: {what} {are} set to \"ask\", and you approved this command more than 15 "
           "minutes before it ran, so that approval no longer counts; run `{example}` again.")


def _dir() -> Path:
    from . import paths
    return paths.run_file(ASKS)


def session() -> str:
    """The Claude Code process above this one, as `pid@start`: the first
    ancestor whose executable is Claude Code's (ancestry.is_claude_exe), or
    "" when none is (a Claude Code that node runs: then the hook and the
    stand-in both find none)."""
    from . import ancestry, paths
    try:
        home = paths.user_home()
        pid = ancestry.parent_pid(os.getpid())
        for _ in range(ancestry.MAX_DEPTH):
            if pid <= 1:
                break
            exe = ancestry.exe_path(pid) or ""
            if exe and ancestry.is_claude_exe(exe, home):
                start = ancestry.started_at(pid)
                return f"{pid}@{int(start) if start else 0}"
            pid = ancestry.parent_pid(pid)
    except Exception:  # noqa: BLE001 - no session: the records still need to match
        pass
    return ""


def _key(tool: str, session: str, cwd: str, argv: Iterable[str]) -> str:
    import hashlib
    h = hashlib.sha256()
    for part in (tool, session, os.path.realpath(cwd) if cwd else "", *argv):
        h.update(str(part).encode("utf-8", "surrogateescape") + b"\0")
    return h.hexdigest()[:40]


def _words(entries: Iterable[tuple[str, str]]) -> set[str]:
    return {f"{s}/{n}" for s, n in entries}


def _link(d: Path) -> None:
    """$DATA/asks names the records folder, so pre_bash.sh sees with a glob
    (no process, no uid) whether a record is pending. Raises OSError when it
    can't be made: the next call would then reach the hook only by its words,
    and a leftover record could outlive it."""
    from . import paths
    ln = paths.data_dir() / LINK
    try:
        if os.readlink(ln) == str(d):
            return
    except OSError:
        pass
    tmp = ln.with_name(f".{LINK}.{secrets.token_hex(4)}")
    ln.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(str(d), tmp)
    try:
        os.replace(tmp, ln)
    except OSError:
        os.unlink(tmp)
        raise


def record(tool: str, session: str, cwd: str, argv: Iterable[str],
           entries: Iterable[tuple[str, str]]) -> None:
    """The approval hook asked about `TOOL ARGV` in `cwd` for `entries`: one
    record, written whole (0600, in the 0700 run folder) with its session
    (for `drop`); records older than twice ASK_TTL go."""
    d = _dir()
    d.mkdir(mode=0o700, exist_ok=True)
    _link(d)
    now = time.time()
    try:
        for p in d.iterdir():
            try:
                if p.stat().st_mtime < now - 2 * ASK_TTL:
                    p.unlink()
            except OSError:
                continue
    except OSError:
        pass
    name = f"{_key(tool, session, cwd, argv)}.{secrets.token_hex(8)}"
    body = json.dumps({"t": now, "s": session, "entries": sorted(_words(entries))})
    tmp = d / f".{name}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, body.encode())
    finally:
        os.close(fd)
    os.replace(tmp, d / name)


def drop(me: str | None = None) -> bool:
    """The session's next Bash or Monitor call, before anything of it runs:
    every record this Claude Code process's earlier hook calls left goes
    (a prompt declined or never shown, a stage that never ran), with any
    record no stand-in could take any more (older than ASK_TTL, dated ahead,
    unreadable) and a stale half-written one. `me` (session()) is worked
    out only when a record is there. False when a record that a
    stand-in could still take couldn't be removed (the hook then refuses the
    call); True otherwise (no folder, or one no stand-in can read either)."""
    from . import paths
    try:
        d = paths.run_dir(create=False) / ASKS
        names = os.listdir(d)
    except (OSError, paths.PathError):
        return True                       # nothing a stand-in could read (_take: "none")
    now = time.time()
    ok = True
    for n in names:
        p = d / n
        try:
            if n.startswith("."):
                if p.lstat().st_mtime < now - FUTURE:
                    p.unlink()            # a write that died halfway
                continue
            try:
                rec = json.loads(p.read_text(encoding="utf-8"))
                t, s = float(rec["t"]), rec.get("s")
            except (ValueError, KeyError, TypeError, AttributeError):
                p.unlink()                # no stand-in takes it (_take skips it)
                continue
            if t < now - ASK_TTL or t > now + FUTURE:
                p.unlink()
                continue
            if me is None:
                me = session()
            if s == me:
                p.unlink()
        except FileNotFoundError:
            continue                      # taken meanwhile
        except OSError:
            ok = False
    return ok


def _take(tool: str, session: str, cwd: str, argv: Iterable[str],
          needed: Iterable[tuple[str, str]]) -> tuple[str, frozenset[str]]:
    """Use up the record for `TOOL ARGV` in `cwd` that covers `needed`:
    ("ok", the entries it holds); ("expired", ∅) when only records older
    than ASK_TTL match the command; ("none", ∅) otherwise."""
    d = _dir()
    key = _key(tool, session, cwd, list(argv))
    want = _words(needed)
    now = time.time()
    old = False
    try:
        names = sorted(n for n in os.listdir(d) if n.startswith(key + "."))
    except OSError:
        return "none", frozenset()
    for n in names:
        p = d / n
        try:
            rec = json.loads(p.read_text(encoding="utf-8"))
            t = float(rec["t"])
            ents = frozenset(str(x) for x in rec["entries"])
        except (OSError, ValueError, KeyError, TypeError):
            continue
        if t > now + FUTURE:
            continue                      # from the future: not this hook's
        if t < now - ASK_TTL:
            old = True
            continue
        if not want <= ents:
            continue
        try:
            os.unlink(p)                  # one use: whoever unlinks it has it
        except OSError:
            continue
        return "ok", ents
    return ("expired" if old else "none"), frozenset()


def take(tool: str, session: str, cwd: str, argv: Iterable[str],
         needed: Iterable[tuple[str, str]]) -> str:
    """_take's answer alone: "ok", "expired" or "none"."""
    return _take(tool, session, cwd, argv, needed)[0]


# What this stand-in call took (one command can meet several "ask"
# decisions, for the entries the hook asked about: the ssh right, a remote
# sudo, a policy restriction; the record is used once, the first time).
# Each stand-in's entry point starts with reset().
_HELD: dict[tuple[str, tuple[str, ...]], frozenset[str]] = {}


def reset() -> None:
    """A new stand-in call: nothing taken yet."""
    _HELD.clear()


# The gate CLI's own command (gate.main: `begin`), for an "ask" its helpers
# meet deep down (ssh._user_present for gate check / rotate / copy-to on an
# "ask" host; `gate with` for an "ask" account).
_CURRENT: dict[str, Any] = {}


def begin(tool: str, argv: Iterable[str]) -> None:
    """A new call of `TOOL ARGV` (the gate CLI): nothing taken yet."""
    reset()
    _CURRENT.clear()
    _CURRENT.update(tool=tool, argv=tuple(argv))


def current(entry: tuple[str, str]) -> str:
    """standin() for the command `begin` named; "none" when none was."""
    if not _CURRENT:
        return "none"
    return standin(str(_CURRENT["tool"]), _CURRENT["argv"], entry)


def standin(tool: str, argv: Iterable[str], entry: tuple[str, str]) -> str:
    """For a stand-in about to pass an "ask" for `entry` to a command Claude
    typed: "ok" when the approval hook's record of this very command (this
    Claude Code, this folder, `TOOL ARGV`) covers it, the record taken on its
    first use and kept for the rest of this process; else "expired" or
    "none". Fails closed (an error is "none")."""
    try:
        argv = tuple(argv)
        held = _HELD.get((tool, argv))
        want = f"{entry[0]}/{entry[1]}"
        if held is not None:
            return "ok" if want in held else "none"
        try:
            cwd = os.getcwd()
        except OSError:
            return "none"
        got, ents = _take(tool, session(), cwd, argv, [entry])
        if got == "ok":
            _HELD[(tool, argv)] = ents
        return got
    except Exception:  # noqa: BLE001 - fail closed
        return "none"


def refusal(got: str, what: list[str], example: str) -> str:
    """The stand-in's refusal for an "ask" with no record ("none") or an old
    one ("expired"): `what` names the "ask" entries (consent.ask_phrase),
    `example` the command to run by itself (`ssh box ...`)."""
    shown = what[0] if len(what) == 1 else ", ".join(what[:-1]) + " and " + what[-1]
    are = "is" if len(what) == 1 else "are"
    return (EXPIRED if got == "expired" else UNASKED).format(what=shown, are=are, example=example)
