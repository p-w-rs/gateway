"""Claude Code's permission modes and per-mode values (PLAN-0.11 §2).

    KEYS, normalize(value) -> key       the mode keys and §2.1's table (gateway.toml spellings)
    from_payload(value) -> (key, known) a hook payload's permission_mode (Claude Code's strings)
    WORDS, RANK, wmin(a, b)             deny < ask < cc < allow < unconfigured (§2.7)
    ModeValue                           a value per mode (a frozen map mode -> word)
    parse(value, kind) -> ModeValue     a gateway.toml word or inline table (§2.2, §2.3)
    from_snapshot(value, kind)          the approved snapshot's encoding back
    legacy(word) -> True | "ask" | False   today's vocabulary (cc and allow are True)
    record(permission_mode) -> bool     a Python hook records its session's mode in gated
    current_for(caller) -> key | None   the recorded mode for a stand-in Claude typed or
                                        the gw MCP server; None means the modeless rule
    audit_word, standin_audit_mode      the mode an audit line names (key or "modeless")
    set_marker / drop_marker / marker_epoch   the epoch marker that keeps records fresh

Words (§2.2). For one mode a value resolves to one of deny < ask < cc <
allow: deny refuses, ask has Claude Code ask (a command Claude typed only),
cc gives no gateway decision (Claude Code decides; today's `true` at the
stand-ins), allow is the gateway's approval (the SPEC 8 shapes only).
"unconfigured" ranks above them all: a target the gateway doesn't handle (the
user's own tool), so taking a configured target out is a widening.

A value is a word or an inline table `{ default = ..., auto = ..., ... }`
(`default` required; an unlisted mode takes default's word). The kind of key
decides what a bare word means (§2.3):

    kind      bare true / "allow"                    used by
    right     allow in auto and bypass, cc elsewhere  ssh, sudo, an account's use
    policy    allow everywhere but plan (cc there)    read, exec, write, network,
                                                      elevation, credential
    network   allow everywhere but plan (cc there)    [network] commands

and inside a table `true` / "allow" is allow in that mode (an explicit
per-mode approval), except in plan, which never executes: cc there. The
other words mean the same in every mode. So `sudo = true` keeps today's
meaning (the gateway approves in auto and bypass only), dontAsk gets cc, and
approving elsewhere takes an explicit `{ default = ..., dontAsk = "allow" }`.

A policy restriction's bare "allow" restricts nothing, while a table's allow
is the user's explicit per-mode allow (lead decision 19.1: on this machine
the gateway then approves in that mode). The two share a word, so a policy
value also records the modes where its allow is explicit (`explicit`): a
table's allows, never a bare word's. Explicit ranks above a plain allow in
that mode: gaining it is a widening (`rises`), the effective value keeps it
only where both sides have it (`minimum`), and the snapshot keeps it (a
six-mode map's allows are explicit unless listed under "plain"). Rights and
[network] commands have no such difference (their bare allow already
approves): `explicit` is always empty there.

The modeless rule (§2.4): a caller with no known mode (a job, a terminal, a
script, gated, a stand-in gated has no record for) gets the strictest word
over every mode but plan, with allow capped at cc: a bare `true` is cc
(today's true), `{ default = "ask", auto = true }` is ask (a refusal for a
caller Claude didn't type), `{ default = false, auto = true }` is deny.

Every lookup indexes RANK (`RANK[w]`): an unknown word raises KeyError
instead of ranking as anything.

The recorded mode (§2.4). A hook payload carries `permission_mode`; a
stand-in or web.py doesn't. So the Python hooks post the payload's mode to
gated (`POST /agent/session/mode`, from a hook-* entry point below the
registered session), and a stand-in reads it back (`GET`, from a `shim`
entry point below that session) only for a command Claude typed
(`ancestry.typed_by_claude`): Claude Code asked about that command in that
mode. web.py reads it for the gw MCP server (every MCP call is Claude's own).
Everything else (jobs, terminals, scripts, gated, a caller gated has no
record for, a gated that can't be reached) gets None: the modeless rule.

A record must never go stale: a mode switched to Manual must reach gated
before the next command Claude typed runs a stand-in, though most commands
have none of pre_bash.sh's trigger words. So while the effective form makes
the mode matter, the Bash hook keeps an epoch marker ($DATA/mode-epoch,
set_marker / drop_marker) and pre_bash.sh sends every call to Python
(`launch.sh hook-mode` records and decides nothing); a record carries the
marker's epoch and is read back only under the same one (current_for), so
one posted before the marker was taken out and made again never counts.

gated keeps the records in memory only, per registered session (pid and
start time), so a restarted daemon or a reused pid has none until the next
hook posts one. A recorded mode is a guardrail, not a boundary: a process
running as the user could post a false one (invariant 17's framing), and
the last post wins, so a subagent running in another mode in the same
session changes the record for both.
"""
from __future__ import annotations

import os
import re
import secrets
from typing import Any

# The mode keys (§2.1): what gateway.toml's per-mode tables name and what
# gated records.
KEYS = ("default", "plan", "acceptEdits", "auto", "bypass", "dontAsk")

# §2.1's table: Claude Code's payload strings and gateway.toml's spellings ->
# the key. Anything else (empty, missing, unknown) is "default", which
# never yields allow.
SPELLINGS = {
    "default": "default",
    "manual": "default",
    "plan": "plan",
    "acceptEdits": "acceptEdits",
    "auto": "auto",
    "bypass": "bypass",
    "bypassPermissions": "bypass",
    "dontAsk": "dontAsk",
}


def normalize(value: Any) -> str:
    """The mode key for a gateway.toml spelling (or a key): exact spellings
    only; anything else is "default". A hook payload's `permission_mode`
    goes through from_payload, which knows only Claude Code's own strings."""
    return SPELLINGS.get(value, "default") if isinstance(value, str) else "default"


# §2.1's payload column: the strings Claude Code puts in a hook payload's
# `permission_mode` (`bypass` is only gateway.toml's spelling).
PAYLOADS = {"default": "default", "manual": "default", "plan": "plan",
            "acceptEdits": "acceptEdits", "auto": "auto", "bypassPermissions": "bypass",
            "dontAsk": "dontAsk"}


def from_payload(value: Any) -> tuple[str, bool]:
    """(the mode key, whether the payload named a mode Claude Code sends) for
    a hook payload's `permission_mode`: empty, missing or unknown (`bypass`,
    a wrong case, a stray space included) is ("default", False), and then
    the hooks never allow."""
    if isinstance(value, str) and value in PAYLOADS:
        return PAYLOADS[value], True
    return "default", False


# ---------------------------------------------------------------------------
# Words and per-mode values (§2.2 - §2.7)
# ---------------------------------------------------------------------------

WORDS = ("deny", "ask", "cc", "allow")
UNCONFIGURED = "unconfigured"
# One order in every mode (§2.7). A dict, indexed (never .get): an unknown
# word raises.
RANK = {"deny": 0, "ask": 1, "cc": 2, "allow": 3, UNCONFIGURED: 4}
# The modes the modeless rule takes the strictest of (plan never executes).
MODELESS = ("default", "acceptEdits", "auto", "bypass", "dontAsk")
# Claude Code's own names for the modes, for messages and the dialog (§2.8).
DISPLAY = {"default": "Manual", "plan": "Plan", "acceptEdits": "Accept edits", "auto": "Auto",
           "bypass": "Bypass permissions", "dontAsk": "Don't ask"}
KINDS = ("right", "policy", "network")
# Spellings of the words in gateway.toml (case ignored for strings).
_TOKENS = {"true": "allow", "yes": "allow", "on": "allow", "allow": "allow",
           "false": "deny", "no": "deny", "off": "deny", "deny": "deny",
           "ask": "ask", "cc": "cc"}


class ModeError(ValueError):
    """A value that isn't a word or a valid per-mode table; the message is
    safe to show (it never echoes what was written unless it is a plain
    mode name or word)."""


def wmin(a: str, b: str) -> str:
    """The stricter of two words (RANK indexed: an unknown word raises)."""
    return a if RANK[a] <= RANK[b] else b


def legacy(word: str) -> Any:
    """Today's vocabulary for a word: allow and cc are True (the gateway's
    `true`), ask is "ask", deny is False. "unconfigured" is "ask": a reader
    that doesn't know the word gets the stricter value (the implicit
    localhost's sudo kept its "ask"). Unknown words raise."""
    RANK[word]
    return {"allow": True, "cc": True, "ask": "ask", "deny": False, UNCONFIGURED: "ask"}[word]


def _token(v: Any) -> str | None:
    """The word a written value spells (true/false/"ask"/"cc"/"allow"/
    "deny", also yes/no/on/off), else None."""
    if isinstance(v, bool):
        return "allow" if v else "deny"
    if isinstance(v, str):
        return _TOKENS.get(v.strip().lower())
    return None


def _bare_words(word: str, kind: str) -> tuple[str, ...]:
    """§2.3: what a bare word means in each mode (KEYS order)."""
    if word != "allow":
        return (word,) * len(KEYS)
    if kind == "right":
        return tuple("allow" if m in ("auto", "bypass") else "cc" for m in KEYS)
    return tuple("cc" if m == "plan" else "allow" for m in KEYS)


class ModeValue:
    """A value per mode: one word for each of KEYS (frozen). `written` is the
    value as gateway.toml spells it (a bare token, or a tuple of (mode
    spelling, token) pairs for a table) and is what the writer puts back.
    `explicit`: the modes where a policy value's allow is the user's
    explicit per-mode allow (a table's; see the module docstring); always
    empty for other kinds and never plan."""

    __slots__ = ("words", "written", "kind", "explicit")

    def __init__(self, words: tuple[str, ...], written: Any = None, kind: str = "right",
                 explicit: Any = ()):
        if len(words) != len(KEYS):
            raise ModeError("a per-mode value needs a word for every mode")
        for w in words:
            RANK[w]
        exp = frozenset(m for m in explicit if m in KEYS and m != "plan"
                        and words[KEYS.index(m)] == "allow") if kind == "policy" else frozenset()
        object.__setattr__(self, "words", tuple(words))
        object.__setattr__(self, "written", written)
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "explicit", exp)

    def __setattr__(self, k: str, v: Any) -> None:  # frozen
        raise AttributeError("ModeValue is read-only")

    def __eq__(self, other: Any) -> bool:
        return (isinstance(other, ModeValue) and self.words == other.words
                and self.explicit == other.explicit)

    def __hash__(self) -> int:
        return hash((self.words, self.explicit))

    def __repr__(self) -> str:
        return f"ModeValue({self.render()})"

    # -- reading -------------------------------------------------------------
    def word(self, mode: str | None = None) -> str:
        """The word in `mode` (a mode key or a payload spelling; None: the
        modeless rule)."""
        if mode is None:
            return self.modeless()
        return self.words[KEYS.index(normalize(mode))]

    def modeless(self) -> str:
        """§2.4: the strictest word over every mode but plan, allow capped
        at cc."""
        w = self.words[KEYS.index(MODELESS[0])]
        for m in MODELESS[1:]:
            w = wmin(w, self.words[KEYS.index(m)])
        return "cc" if w == "allow" else w

    def legacy(self, mode: str | None = None) -> Any:
        return legacy(self.word(mode))

    def map(self) -> dict[str, str]:
        return dict(zip(KEYS, self.words))

    @property
    def uniform(self) -> bool:
        return len(set(self.words)) == 1

    @property
    def is_table(self) -> bool:
        return isinstance(self.written, tuple)

    def any_above(self, word: str) -> bool:
        return any(RANK[w] > RANK[word] for w in self.words)

    def explicit_in(self, mode: str | None) -> bool:
        """Is this value's allow in `mode` the user's explicit per-mode allow
        (a policy table's)? Never for the modeless rule (None)."""
        return mode is not None and normalize(mode) in self.explicit

    # -- comparing -----------------------------------------------------------
    def _above(self, other: "ModeValue", m: str, a: str, b: str) -> bool:
        return RANK[a] > RANK[b] or (a == b == "allow" and m in self.explicit
                                     and m not in other.explicit)

    def rises(self, other: "ModeValue") -> list[str]:
        """The modes where this value is above `other` (a widening there),
        an explicit allow over a plain one included."""
        return [m for m, a, b in zip(KEYS, self.words, other.words) if self._above(other, m, a, b)]

    def falls(self, other: "ModeValue") -> list[str]:
        """The modes where this value is below `other` (a narrowing there)."""
        return [m for m, a, b in zip(KEYS, self.words, other.words) if other._above(self, m, b, a)]

    def minimum(self, other: "ModeValue") -> "ModeValue":
        """The per-mode minimum (the effective value of a form and its
        approval): an allow stays explicit only where both sides say so.
        Equal to one side, that side's spelling is kept."""
        words = tuple(wmin(a, b) for a, b in zip(self.words, other.words))
        exp = frozenset(m for m in self.explicit & other.explicit if words[KEYS.index(m)] == "allow")
        if words == self.words and exp == self.explicit:
            return self
        if words == other.words and exp == other.explicit:
            return other
        return ModeValue(words, None, self.kind, exp)

    # -- writing -------------------------------------------------------------
    def snapshot(self) -> Any:
        """The approved snapshot's encoding (§2.7): a bare value as today's
        vocabulary (true / "ask" / false, or "cc"), a table (or any value
        that isn't one bare word's expansion) as its six-mode map. A policy
        map's allows are explicit except the modes listed under "plain"."""
        if not isinstance(self.written, tuple) and not self.explicit:
            t = _token(self.written)
            if t is None:
                t = next((w for w in WORDS if _bare_words(w, self.kind) == self.words), None)
            if t is not None and _bare_words(t, self.kind) == self.words:
                return {"allow": True, "deny": False}.get(t, t)
        out: dict[str, Any] = self.map()
        plain = [m for m, w in zip(KEYS, self.words)
                 if w == "allow" and m not in self.explicit] if self.kind == "policy" else []
        if plain:
            out["plain"] = plain
        return out

    def toml(self) -> Any:
        """What form.toml_value writes: the bare token, or {spelling: token}."""
        if isinstance(self.written, tuple):
            return dict(self.written)
        if self.written is not None and _token(self.written) is not None:
            return self.written
        return dict(self.map())

    def render(self) -> str:
        """For messages and panes (§2.8): a bare word as written, a table as
        `Manual: ask · Auto: allow · ...` (only the modes that differ from
        Manual after it)."""
        if not isinstance(self.written, tuple) and _token(self.written) is not None:
            return text_word(self.written)
        first = self.words[0]
        parts = [f"{DISPLAY['default']}: {first}"]
        parts += [f"{DISPLAY[m]}: {w}" for m, w in zip(KEYS[1:], self.words[1:]) if w != first]
        return " · ".join(parts)


def text_word(v: Any) -> str:
    """How a bare token is written in a message: true, false, "ask", "cc",
    "allow", "deny"."""
    if isinstance(v, bool):
        return "true" if v else "false"
    return f'"{v}"' if isinstance(v, str) else "?"


def uniform(word: str, kind: str = "right") -> ModeValue:
    """The same word in every mode."""
    return ModeValue((word,) * len(KEYS), None, kind)


def bare(token: Any, kind: str = "right") -> ModeValue:
    """A bare word's expansion (§2.3); ModeError for anything else."""
    t = _token(token)
    if t is None:
        raise ModeError("not a word")
    return ModeValue(_bare_words(t, kind), token, kind)


def parse(value: Any, kind: str = "right") -> ModeValue:
    """A gateway.toml value: a word (true / "ask" / "cc" / false, or
    "allow" / "deny"; yes/no/on/off too) or an inline table naming
    `default` and any other mode (§2.1's spellings). ModeError otherwise:
    a bad mode name, a bad word, a missing `default`, a mode named twice."""
    if kind not in KINDS:
        raise ValueError(f"unknown kind {kind!r}")
    if not isinstance(value, dict):
        try:
            return bare(value, kind)
        except ModeError:
            raise ModeError(('must be true, "ask", "cc" or false' if kind == "right" else
                             'must be "allow", "ask", "cc" or "deny"')
                            + ', or a table like { default = "ask", auto = '
                            + ('true }' if kind == "right" else '"allow" }')) from None
    words: dict[str, str] = {}
    written: list[tuple[str, Any]] = []
    for spelling, v in value.items():
        key = SPELLINGS.get(spelling) if isinstance(spelling, str) else None
        if key is None:
            shown = spelling if isinstance(spelling, str) and spelling.isascii() \
                and spelling.replace("_", "").isalnum() and len(spelling) <= 32 else None
            raise ModeError((f"names {shown}, which isn't a mode" if shown else
                             "names an unknown mode")
                            + " (the modes: default, manual, plan, acceptEdits, auto, bypass, "
                            "bypassPermissions, dontAsk)")
        if key in words:
            raise ModeError(f"names {DISPLAY[key]} mode twice")
        t = _token(v)
        if t is None:
            raise ModeError(f"gives {spelling} a value that isn't "
                            + ('true, "ask", "cc" or false' if kind == "right"
                               else '"allow", "ask", "cc" or "deny"'))
        words[key] = t
        written.append((spelling, v))
    if "default" not in words:
        raise ModeError("needs default = ... in a per-mode table (the word for every mode it "
                        "doesn't name)")
    out = []
    for m in KEYS:
        w = words.get(m, words["default"])
        out.append("cc" if (m == "plan" and w == "allow") else w)
    # a policy table's allows are the user's explicit per-mode allows (19.1)
    return ModeValue(tuple(out), tuple(written), kind, KEYS)


def from_snapshot(value: Any, kind: str = "right") -> ModeValue | None:
    """The approved snapshot's encoding (ModeValue.snapshot) back; None when
    it can't be read (the caller then takes the strictest reading). A policy
    map keeps its allows explicit except the modes under "plain"."""
    if isinstance(value, dict):
        plain = value.get("plain", [])
        if set(value) - {"plain"} != set(KEYS) or any(value[m] not in WORDS for m in KEYS):
            return None
        if "plain" in value and (kind != "policy" or not isinstance(plain, list) or not plain
                                 or any(p not in KEYS or value[p] != "allow" for p in plain)):
            return None
        return ModeValue(tuple(value[m] for m in KEYS), None, kind,
                         [m for m in KEYS if m not in plain])
    try:
        return bare(value, kind)
    except ModeError:
        return None


# ---------------------------------------------------------------------------
# The recorded mode: the client side of gated's /agent/session/mode
# ---------------------------------------------------------------------------

MODE_ROUTE = "/agent/session/mode"
MODE_TIMEOUT = 2.0          # gated answers in milliseconds; a hung one costs this once


def _call(method: str, body: Any = None, route: str = MODE_ROUTE) -> dict[str, Any] | None:
    """One request to gated's mode route; None when gated can't be reached,
    doesn't answer or refuses, and on any other error (an unsafe run folder,
    paths.PathError, included): the caller then uses the modeless rule, the
    safe fallback. Never starts gated: without a running daemon there is no
    record to read, and a hook's record would be lost with it."""
    try:
        return _ask_gated(method, body, route)
    except Exception:  # noqa: BLE001 - whatever went wrong, the modeless rule
        return None


# The epoch marker ($DATA/mode-epoch, paths.mode_epoch_path): a record is
# worth reading only while every call of its session reaches a Python hook
# that refreshes it. pre_bash.sh sends a call without a trigger word to
# Python (`launch.sh hook-mode`, which only records) only while the marker
# exists, and the Bash hook keeps the marker exactly while the effective form
# makes the mode matter (hooks_bash.record_mode). A record carries the epoch
# it was posted under and is read back only with the same one: one posted
# before the marker was taken out and made again (a mode switched while no
# call reached Python) never counts.
EPOCH_RE = re.compile(r"[0-9a-f]{32}")


def marker_epoch() -> str | None:
    """The marker's epoch, or None (no marker, an unreadable one, any error)."""
    from . import paths
    try:
        v = paths.mode_epoch_path().read_text(encoding="ascii").strip()
    except Exception:  # noqa: BLE001 - no usable marker: nothing recorded counts
        return None
    return v if EPOCH_RE.fullmatch(v) else None


def set_marker() -> str | None:
    """Make the marker unless it is there (a new random epoch; one that can't
    be read is replaced); its epoch, or None when it can't be written."""
    from . import paths
    cur = marker_epoch()
    if cur is not None:
        return cur
    try:
        p = paths.mode_epoch_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_name(f".{p.name}.{os.getpid()}")
        tmp.write_text(secrets.token_hex(16) + "\n", encoding="ascii")
        try:
            if p.exists() or p.is_symlink():
                os.replace(tmp, p)            # unreadable: no record counts under it anyway
            else:
                os.link(tmp, p)               # made once: a racing hook's epoch wins, not two
        except FileExistsError:
            pass
        finally:
            tmp.unlink(missing_ok=True)
    except Exception:  # noqa: BLE001 - no marker: no record (the modeless rule)
        return None
    return marker_epoch()


def drop_marker() -> None:
    """Take the marker out (the mode doesn't matter any more: every record
    stops counting, and pre_bash.sh stops sending every call to Python)."""
    from . import paths
    try:
        paths.mode_epoch_path().unlink(missing_ok=True)
    except Exception:  # noqa: BLE001 - best effort; a record still needs its epoch to count
        pass


def _ask_gated(method: str, body: Any, route: str = MODE_ROUTE) -> dict[str, Any] | None:
    """A hook whose session gated doesn't know yet registers it once and
    retries (as client._vault_call does); a daemon that took the request but
    didn't answer is skipped for a while (client.skipping_unresponsive), and
    a hook clears that mark once gated answers."""
    from . import paths
    from .daemon import client
    hook = paths.ENTRY_MODE.startswith("hook-")
    if client.skipping_unresponsive():
        return None
    registered = False
    while True:
        try:
            r = client.call(method, route, body, timeout=MODE_TIMEOUT)
            if hook:
                client._clear_unresponsive()
            return r
        except client.Unresponsive:
            if hook:
                client._mark_unresponsive()
            return None
        except client.Unreachable:
            return None
        except client.DaemonError as e:
            if hook:
                client._clear_unresponsive()      # it answered (a refusal is an answer)
            if e.code == "not_registered" and hook and not registered:
                try:
                    client._register()
                except client.DaemonError:
                    return None
                registered = True
                continue
            return None


def record(permission_mode: Any, create: bool = True) -> bool:
    """A Python hook (a hook-* entry point) records its session's mode, the
    payload's `permission_mode` (from_payload), in gated, under the marker's
    epoch: `create` makes the marker first when it is missing (the Bash hook
    and hooks_mcp, which know the mode matters); hook-mode, which pre_bash.sh
    starts only while the marker exists, never makes one (no marker: nothing
    posted). True once gated holds it. Any other caller is refused by gated
    (and gets False)."""
    from . import paths
    if not paths.ENTRY_MODE.startswith("hook-"):
        return False
    epoch = set_marker() if create else marker_epoch()
    if epoch is None:
        return False
    r = _call("POST", {"mode": from_payload(permission_mode)[0], "epoch": epoch})
    return bool(r and r.get("ok"))


def hook_main(payload: Any) -> None:
    """`run.py hook-mode` (pre_bash.sh, for a call without a trigger word,
    only while the epoch marker exists): record the payload's mode under the
    marker's epoch, never making one, so the record doesn't go stale between
    the calls the Bash hook judges. Never a decision; the vault and the form
    are never read (it stays light: pre_bash.sh starts it for every such
    call)."""
    if isinstance(payload, dict):
        try:
            record(payload.get("permission_mode"), create=False)
        except Exception:  # noqa: BLE001 - the modeless rule applies
            pass
    return None


def current_for(caller: str) -> str | None:
    """The mode the hook recorded for this process's session, for `caller`:

    - "standin": a stand-in (a `shim` entry point) whose command Claude typed
      (ancestry.typed_by_claude, checked here);
    - "mcp": the gw MCP server (web.py's http and download tools).

    None for anything else, for a stand-in that a script, job or terminal
    started, when gated has no record (a new or restarted daemon, a hook that
    never posted), without the epoch marker or for a record posted under
    another epoch (it may be stale: see marker_epoch), and when gated can't
    be reached: the caller then uses the modeless rule."""
    from . import ancestry, paths
    if caller == "standin":
        if not paths.ENTRY_MODE.startswith("shim "):
            return None
        try:
            typed, _culprit = ancestry.typed_by_claude()
        except Exception:  # noqa: BLE001 - can't tell: not typed
            typed = False
        if not typed:
            return None
    elif caller == "mcp":
        if paths.ENTRY_MODE != "mcp":
            return None
    else:
        return None
    epoch = marker_epoch()
    if epoch is None:
        return None
    r = _call("GET", None, f"{MODE_ROUTE}?epoch={epoch}")
    mode = r.get("mode") if r else None
    return mode if isinstance(mode, str) and mode in KEYS else None


def audit_word(mode: str | None) -> str:
    """An audit line's mode (lead decision 19.8): the mode key the values
    were resolved with, or "modeless" (None: the modeless rule)."""
    return mode if isinstance(mode, str) and mode in KEYS else "modeless"


def standin_audit_mode(call: dict[str, Any]) -> str:
    """The mode for a stand-in's audit line: the one it resolved its values
    with (`call["mode"]`, which its load step sets), else, before it read
    one, the session's mode for a command Claude typed, else "modeless"."""
    m = call.get("mode")
    if isinstance(m, str) and m:
        return m
    try:
        return audit_word(current_for("standin"))
    except Exception:  # noqa: BLE001 - the modeless rule
        return "modeless"
