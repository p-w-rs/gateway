"""The local sudo stand-in and its one-shot askpass (SPEC 9.1).

`sudo APT…` in Claude's terminal resolves to this stand-in. It:

1. refuses when localhost sudo is `false`; `"ask"` is refused unless Claude's
   own command shell started it with nothing in between (Claude Code can only
   prompt for a command Claude typed: ancestry.typed_by_claude, which
   `scripts = true` doesn't relax);
2. refuses `-S`/`-A` (a caller must not feed its own password or askpass);
3. probes `sudo -n true` (cached 10 min) and, if passwordless, just execs the
   real sudo — nothing is stored or asked;
4. otherwise, only for a *direct* caller (SPEC 10), takes the password from the
   vault (`localhost.sudo[USER]`), or opens a secret pop-up, and feeds it to
   `sudo -A` through a **one-shot FIFO** askpass: the password is written once,
   the FIFO is unlinked immediately, so a wrong password costs exactly one
   attempt (no pam_faillock lockout) and is then marked stale;
5. inherits stdin and stdout (pipes and here-docs work) and relays stderr
   (scrubbed of the password) so it can tell a rejected password: a second
   askpass call, or sudo's "Sorry, try again" / "N incorrect password
   attempts" (passwd_tries=1 never calls askpass twice); forwards signals and
   exits with sudo's own code.

`gate-askpass` (run.py askpass) reads that FIFO once and refuses unless its
parent is the real sudo, euid is non-root, and `SUDO_COMMAND`/`SUDO_USER` are
unset.
"""
from __future__ import annotations

import contextlib
import errno
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any

from . import ancestry, audit, consent, paths, scrub, testing
from . import vault

PROBE_TTL = 600          # seconds a `sudo -n true` result is cached
_REAL_SUDO = "/usr/bin/sudo"
# NixOS has no /usr/bin/sudo: its setuid wrapper lives in /run/wrappers/bin.
_SUDO_CANDIDATES = (_REAL_SUDO, "/run/wrappers/bin/sudo")
UNTRUSTED = ("gateway: this machine has no trusted sudo (/usr/bin/sudo, or NixOS's "
             "/run/wrappers/bin/sudo, root-owned and setuid), so the gateway can't run sudo here; "
             "ask the user to run the root command in their own terminal.")
STDERR_GRACE = 2.0       # seconds to drain sudo's stderr after it exits
# What sudo prints when the password is wrong: "Sorry, try again." before a
# retry, "sudo: N incorrect password attempt(s)" when it gives up (the only
# message under passwd_tries=1, where no second askpass call ever happens).
REJECTED_LINE = re.compile(rb"^(?:Sorry, try again\.?|sudo: \d+ incorrect password attempts?)\s*$",
                           re.I)

OFF = "gateway: sudo is off on this machine (gateway.toml); ask the user to turn it on."
# The form turns sudo on but the user hasn't approved it yet (round 3).
WAITING = ("gateway: sudo on this machine waits for the user's OK; run gate check localhost while "
           "the user is here.")
ASKPASS_WAIT = 60        # seconds gate-askpass waits for the stand-in's FIFO writer
ASK_INDIRECT = ("gateway: sudo here needs your OK; run it as its own command so Claude Code "
                "can ask you (not inside a script, sh -c, xargs or a wrapper).")
ASK_JOB = consent.job_ask_message([consent.ask_phrase("localhost", "sudo")])
ASK_PANE = consent.pane_ask_message([consent.ask_phrase("localhost", "sudo")])
NO_SA = "gateway: sudo -S/-A isn't allowed here; the gateway supplies the password itself."
STALE = ("gateway: the saved sudo password for this machine was rejected; a gateway dialog to "
         "enter it again is open in Claude Code; don't retry.")
NO_PW = ("gateway: no sudo password is saved for this machine and the gateway's dialog couldn't "
         "ask for one; ask the user to run gate check localhost in an interactive Claude Code "
         "session (it can store the password, or leave it to be asked each time), or to run the "
         "root command in their own terminal.")
# sudo's own words when its sudoers wants a terminal (requiretty, use_pty with
# no tty): the managed terminal path has one (PLAN-v4 phase 7)
NEEDS_TTY = re.compile(rb"(?i)(a terminal is required|you must have a tty|no tty present)")
NEEDS_TTY_MSG = ("gateway: this machine's sudo wants a terminal (its sudoers has requiretty or "
                 "use_pty): run the command in a gateway terminal instead (terminal_open, then "
                 "type it there with terminal_send; its password prompt opens the gateway's "
                 "dialog for the user).")
NOT_DIRECT = ("gateway: sudo started by {culprit} got no password (only Claude's own commands "
              "do); run it as its own command, or set scripts = true for localhost.")
JOINED_NOT_KEPT = ("gateway: the sudo password for this machine was entered in another command's "
                   "gateway dialog and can't be read back here (it isn't kept when Remember it is "
                   "unticked); run the command again.")


def not_direct_who(culprit: str | None) -> str:
    """How NOT_DIRECT names the culprit (ancestry.UNTRACED_WHO for "?")."""
    if not culprit or culprit == ancestry.UNTRACED:
        return ancestry.UNTRACED_WHO
    return culprit


# ---------------------------------------------------------------------------
# The real /usr/bin/sudo (root-owned + setuid), or the test fake via override
# ---------------------------------------------------------------------------


def _real_sudo() -> str | None:
    """The path to a trusted sudo: the test fake under testing.override, else
    the first of /usr/bin/sudo and NixOS's /run/wrappers/bin/sudo that is
    root-owned and setuid. None if none is.

    Under a test override, only the explicit fake is ever returned: a test that
    forgot to provide one never reaches the real /usr/bin/sudo."""
    o = testing.active()
    if o is not None:
        if o.tools and "sudo" in o.tools:
            return o.tools["sudo"]
        return None
    for cand in _SUDO_CANDIDATES:
        try:
            st = os.stat(cand)
        except OSError:
            continue
        if st.st_uid == 0 and (st.st_mode & stat.S_ISUID):
            return cand
    return None


# ---------------------------------------------------------------------------
# NOPASSWD probe and password verification (also used by `gate check`)
# ---------------------------------------------------------------------------


def probe_nopasswd(user: str | None = None) -> bool:
    """`sudo -n true` (optionally `-u user`), cached PROBE_TTL per user."""
    real = _real_sudo()
    key = user or paths.local_user()
    cache = paths.sudo_probe_path(key)
    now = time.time()
    try:
        parts = cache.read_text().split()
        if len(parts) == 2 and now - float(parts[1]) < PROBE_TTL:
            return parts[0] == "yes"
    except (OSError, ValueError, paths.PathError):
        pass
    ok = False
    if real is not None:
        cmd = [real, "-n"] + (["-u", user] if user else []) + ["true"]
        try:
            ok = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=10).returncode == 0
        except (OSError, subprocess.TimeoutExpired):
            ok = False
    try:
        cache.write_text(f"{'yes' if ok else 'no'} {now:.0f}")
        os.chmod(cache, 0o600)
    except (OSError, paths.PathError):
        pass
    return ok


def verify_local(password: str) -> tuple[bool, str]:
    """`sudo -k; sudo -S -v` with the password (SPEC 6). (ok, message)."""
    real = _real_sudo()
    if real is None:
        return False, UNTRUSTED
    try:
        subprocess.run([real, "-k"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        r = subprocess.run([real, "-S", "-p", "", "-v"], input=password + "\n",
                           capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return False, "gateway: couldn't check the sudo password."
    if r.returncode == 0:
        return True, "gateway: sudo password accepted."
    return False, "gateway: that sudo password was not accepted."


# ---------------------------------------------------------------------------
# Passwordless sudo: only as the system already has it
# ---------------------------------------------------------------------------
# PLAN-v4 phase 7: the gateway never installs a sudoers rule (no blanket
# passwordless sudo, no change to the system's privilege rules). Passwordless
# sudo is used only when it is already configured (probe_nopasswd); otherwise
# the password is asked per call in the gateway's dialog ("Remember it" keeps
# it in the vault, unticked it is used once).


# ---------------------------------------------------------------------------
# argv helpers
# ---------------------------------------------------------------------------

# sudo's short options that take a value (getopt "+Aa:BbC:c:D:Eeg:Hh::iKklNnp:PR:r:SsT:t:U:u:Vv"):
# the value is the rest of the cluster or, if that is empty, the next word.
_VALUE_SHORT = set("aCcDgpRrTtUu")
_OPTIONAL_SHORT = set("h")          # -hHOST: an optional value, attached only
# Long options that take a value (`--user root` as well as `--user=root`).
_LONG_WITH_VALUE = ("auth-type", "close-from", "login-class", "chdir", "group", "host",
                    "prompt", "chroot", "role", "type", "command-timeout", "other-user", "user")


def _long_name(a: str) -> str:
    return a[2:].split("=", 1)[0]


def _abbrev_of(name: str, full: str) -> bool:
    """getopt_long accepts any unambiguous prefix: --std is --stdin."""
    return bool(name) and full.startswith(name)


def _scan_opts(argv: list[str]) -> tuple[list[tuple[str, str]], int]:
    """sudo's own options, as [(kind, word)] with kind 'short', 'long', 'val'
    (an option's separate value) or 'end' (`--`), and the index where the
    command starts. sudo stops at the first non-option word, like getopt "+".
    When a long option is ambiguous it is taken to have a value, so a later
    word is read as an option rather than as the command (the safe side)."""
    items: list[tuple[str, str]] = []
    i, n = 0, len(argv)
    while i < n:
        a = argv[i]
        if a == "--":
            items.append(("end", a))
            i += 1
            break
        if a == "-" or not a.startswith("-"):
            break
        if a.startswith("--"):
            items.append(("long", a))
            if "=" not in a and any(_abbrev_of(_long_name(a), f) for f in _LONG_WITH_VALUE):
                if i + 1 < n:
                    items.append(("val", argv[i + 1]))
                i += 2
                continue
            i += 1
            continue
        items.append(("short", a))
        body = a[1:]
        for k, c in enumerate(body):
            if c in _OPTIONAL_SHORT:
                break
            if c in _VALUE_SHORT:
                if k + 1 >= len(body) and i + 1 < n:
                    items.append(("val", argv[i + 1]))
                    i += 1
                break
        i += 1
    return items, i


def _short_flags(word: str) -> str:
    """The flag letters of a short cluster, up to an option that takes a value."""
    out = []
    for c in word[1:]:
        out.append(c)
        if c in _VALUE_SHORT or c in _OPTIONAL_SHORT:
            break
    return "".join(out)


def _has_S_or_A(argv: list[str]) -> bool:
    """-S/--stdin or -A/--askpass (any abbreviation) among sudo's options."""
    items, _ = _scan_opts(argv)
    for kind, w in items:
        if kind == "short" and ("S" in _short_flags(w) or "A" in _short_flags(w)):
            return True
        if kind == "long" and (_abbrev_of(_long_name(w), "stdin")
                               or _abbrev_of(_long_name(w), "askpass")):
            return True
    return False


def _strip_n(argv: list[str]) -> list[str]:
    """Remove -n / --non-interactive (and the n from a short cluster) so sudo
    uses askpass instead of refusing. Option values and the command are kept."""
    items, start = _scan_opts(argv)
    out: list[str] = []
    for kind, w in items:
        if kind == "short":
            body = w[1:]
            flags = _short_flags(w)
            if flags and flags[-1] in (_VALUE_SHORT | _OPTIONAL_SHORT):
                kept = flags[:-1].replace("n", "") + flags[-1]   # keep -u, -p, ...
            else:
                kept = flags.replace("n", "")
            rest = body[len(flags):]
            if kept or rest:
                out.append("-" + kept + rest)
        elif kind == "long" and _abbrev_of(_long_name(w), "non-interactive"):
            continue
        else:
            out.append(w)
    return out + argv[start:]


# ---------------------------------------------------------------------------
# One-shot FIFO writer (the credential never touches argv or a readable file)
# ---------------------------------------------------------------------------


def _serve_fifo(fifo: str, password: str, stop: threading.Event,
                served: threading.Event | None = None) -> None:
    data = password.encode("utf-8") + b"\n"
    while not stop.is_set():
        try:
            fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        except OSError as e:
            if e.errno in (errno.ENXIO, errno.ENOENT):
                time.sleep(0.01)
                continue
            return
        try:
            try:
                os.unlink(fifo)      # one-shot: a second askpass finds no FIFO
            except OSError:
                pass
            os.write(fd, data)
            if served is not None:
                served.set()
        finally:
            os.close(fd)
        return


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


class _StderrRelay:
    """Copies sudo's stderr to ours as it comes (through a Scrubber for the
    password, so even a long one never shows), and notes whether sudo said the
    password was rejected (SPEC 9.1 step 5). Only stderr is relayed: stdin and
    stdout stay inherited, so pipes and here-docs work as before."""

    MAX_LINE = 4096

    def __init__(self, src: int, password: str):
        self.src = src
        self.scrubber = scrub.Scrubber([password])
        self.rejected = False
        self.needs_tty = False
        self._line = b""
        self.thread = threading.Thread(target=self._run, daemon=True)

    def _scan(self, chunk: bytes, final: bool = False) -> None:
        buf = self._line + chunk
        lines = buf.split(b"\n")
        self._line = b"" if final else lines.pop()[-self.MAX_LINE:]
        for ln in lines:
            if REJECTED_LINE.match(ln.rstrip(b"\r")):
                self.rejected = True
            if NEEDS_TTY.search(ln):
                self.needs_tty = True

    def _run(self) -> None:
        import select
        try:
            while True:
                if self.scrubber.holding:
                    # held-back bytes (a possible start of the password's
                    # forms) go out after a moment of quiet: a prompt on
                    # stderr never stalls (review round 2)
                    try:
                        ready = select.select([self.src], [], [], scrub.IDLE)[0]
                    except InterruptedError:
                        continue
                    except (OSError, ValueError):
                        ready = [self.src]
                    if not ready:
                        _write_all(2, self.scrubber.release())
                        continue
                try:
                    chunk = os.read(self.src, 65536)
                except InterruptedError:
                    continue
                except OSError:
                    chunk = b""
                if not chunk:
                    self._scan(b"", final=True)
                    _write_all(2, self.scrubber.flush())
                    return
                self._scan(chunk)
                out = self.scrubber.feed(chunk)
                if out:
                    _write_all(2, out)
        except OSError:
            pass                      # our stderr went away: stop reading (sudo gets EPIPE)
        finally:
            try:
                os.close(self.src)
            except OSError:
                pass


def _run_with_askpass(real: str, argv: list[str], password: str) -> tuple[int, bool]:
    """Run `real -A argv` feeding `password` through a one-shot FIFO askpass.
    Returns (exit_code, rejected).

    Rejected = a second askpass call found the FIFO gone (the `rejected`
    marker), or sudo's stderr says so after the password was served and sudo
    failed. The second covers sudoers with passwd_tries=1, where sudo never
    calls askpass again and only prints "sudo: 1 incorrect password attempt"."""
    rundir = paths.run_dir()
    d = tempfile.mkdtemp(prefix="sudo-", dir=str(rundir))
    os.chmod(d, 0o700)
    fifo = os.path.join(d, "pw")
    rejected_marker = os.path.join(d, "rejected")
    os.mkfifo(fifo, 0o600)
    # the askpass's Linux parent check: sudo's parent must be this process
    fd = os.open(os.path.join(d, "owner"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, str(os.getpid()).encode())
    finally:
        os.close(fd)
    stop = threading.Event()
    served = threading.Event()
    t = threading.Thread(target=_serve_fifo, args=(fifo, password, stop, served), daemon=True)
    t.start()
    env = dict(os.environ)
    env["SUDO_ASKPASS"] = str(paths.bin_dir() / "gate-askpass")
    env["GW_ASKPASS_FIFO"] = fifo
    # DISPLAY lets sudo use askpass with no tty for nested/absolute-path sudo.
    env.setdefault("DISPLAY", "gw:0")
    proc = subprocess.Popen([real, "-A", *_strip_n(argv)], env=env, stderr=subprocess.PIPE)
    assert proc.stderr is not None
    relay = _StderrRelay(os.dup(proc.stderr.fileno()), password)
    proc.stderr.close()
    relay.thread.start()
    _forward_signals(proc)
    try:
        rc = proc.wait()
    finally:
        stop.set()
    # Drain what sudo (and the command) wrote. A daemon the command started
    # may keep stderr open; don't wait for it beyond the grace period.
    relay.thread.join(STDERR_GRACE)
    rejected = os.path.exists(rejected_marker) or (
        served.is_set() and rc != 0 and relay.rejected)
    if rc != 0 and relay.needs_tty:
        print(NEEDS_TTY_MSG, file=sys.stderr, flush=True)
    try:
        if os.path.exists(fifo):
            os.unlink(fifo)
        for name in os.listdir(d):
            os.unlink(os.path.join(d, name))
        os.rmdir(d)
    except OSError:
        pass
    return (rc if rc >= 0 else 128 - rc), rejected


def _forward_signals(proc: subprocess.Popen) -> None:
    for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT):
        try:
            signal.signal(s, lambda n, f: _safe_send(proc, n))
        except (OSError, ValueError):
            pass


def _safe_send(proc: subprocess.Popen, n: int) -> None:
    try:
        proc.send_signal(n)
    except (OSError, ProcessLookupError):
        pass


# ---------------------------------------------------------------------------
# The stand-in
# ---------------------------------------------------------------------------


def _exec_real(real: str, argv: list[str]) -> int:
    """exec the real sudo, inheriting stdio (no password supplied)."""
    try:
        os.execv(real, [real, *argv])
    except OSError:
        return 1
    return 0  # unreachable


def _typed_by_claude() -> tuple[bool, str]:
    """(typed by Claude, culprit); fails closed."""
    try:
        ok, culprit = ancestry.typed_by_claude()
        return bool(ok), str(culprit or "")
    except Exception:  # noqa: BLE001 - fail closed
        return False, ""


# What gated rechecks before it hands a password typed into the gateway's
# dialog to this stand-in: localhost still in the form with sudo not off.
SUDO_CHECK = {"section": "hosts", "entry": "localhost", "right": "sudo"}


def _rights_now(fresh: bool = False) -> tuple[dict[str, Any] | None, str | None, bool]:
    """(vault data, refusal or None, scripts) from the effective localhost
    sudo right as it is now (fresh: the form read again, not from this
    process's cache). Refused: sudo off or waiting for the user's OK; an
    "ask" right for anything but a command Claude typed (Claude Code can only
    prompt for that one, whatever scripts says; inside a checkpoint job the
    approval hook's job wording, since nobody can be asked there)."""
    if fresh:
        from . import form as formmod
        formmod.clear_cache()
    locked = False
    try:
        data = vault.load() if vault.exists() else None
    except vault.VaultLocked:
        data, locked = None, True
    except Exception:  # noqa: BLE001
        data = None
    form = consent.load_form(data)
    eff = consent.compute(form, data)
    eh = eff.hosts.get("localhost")
    right = eh.sudo if eh is not None else False
    scripts = bool(eh.scripts) if eh is not None else False
    if right is False:
        fh = form.hosts.get("localhost")
        return data, (WAITING if (fh is not None and fh.sudo is not False) else OFF), scripts
    # the policy's elevation restrictions ([hosts.localhost.policy] elevation,
    # [policy] elevation; PLAN-v4 phase 7), with the rule behind a refusal
    from . import policy
    d = policy.decide(eff, "elevation")
    if d.word is False:
        return data, d.message("sudo (root)"), scripts
    if right == "ask" or d.word == "ask":
        typed, by = _typed_by_claude()
        if not typed:
            # a locked vault: say how sudo's own right comes back (consent.LOCKED_SUDO_NOTE)
            note = consent.locked_sudo_note(form) if locked and right == "ask" else ""
            return data, (ASK_JOB if by == ancestry.CHECKPOINT else
                          ASK_PANE if by == ancestry.TERMINAL else ASK_INDIRECT) + note, scripts
    return data, None, scripts


def _in_gateway_terminal() -> bool:
    """Run inside a gateway terminal or job (gated's tmux pane, PLAN-v4 phase
    5) with a terminal on stdin: the real sudo asks on the pane's tty, where
    gated sees the password prompt (echo off) and opens the gateway's
    credential dialog, then hands the answer to that tty only. A forged
    GW_TERMINAL only skips the askpass path: sudo then asks on its own tty,
    as it does anywhere."""
    t = os.environ.get("GW_TERMINAL", "")
    if not re.fullmatch(r"[tj]_[0-9A-HJKMNP-TV-Z]{26}", t):
        return False
    try:
        return os.isatty(0)
    except OSError:
        return False


def main(argv: list[str]) -> int:
    real = _real_sudo()
    if real is None:
        print(UNTRUSTED, file=sys.stderr)
        audit.refusal("sudo", "localhost", "sudo binary not trusted")
        return 1

    # Effective localhost sudo right.
    data, msg, scripts = _rights_now()
    if msg is not None:
        print(msg, file=sys.stderr)
        audit.refusal("sudo", "localhost", msg)
        return 1

    direct, culprit = ancestry.is_direct("sudo", entry_scripts=scripts)

    if _has_S_or_A(argv):
        print(NO_SA, file=sys.stderr)
        audit.refusal("sudo", "localhost", NO_SA)
        return 1

    # In a gateway terminal the real sudo asks on the pane's tty: gated's
    # password-prompt path answers it through the gateway's dialog.
    if _in_gateway_terminal():
        audit.log("sudo", outcome="terminal", target="localhost",
                  terminal=os.environ.get("GW_TERMINAL", ""))
        return _exec_real(real, argv)

    # Passwordless sudo, as the system already has it: nothing stored,
    # nothing asked, any caller.
    if probe_nopasswd():
        return _exec_real(real, argv)

    # A password is needed. Only a direct caller gets it.
    if not direct:
        msg = NOT_DIRECT.format(culprit=not_direct_who(culprit))
        print(msg, file=sys.stderr)
        audit.refusal("sudo", "localhost", msg)
        return _exec_real(real, argv)

    user = paths.local_user()
    password, asked = _password_for(data, user)
    if password is None:
        return 1
    if asked:
        # The dialog may have been open for minutes: gated rechecked the right
        # before it handed the password over, and it is checked once more
        # here, right before sudo runs (the form may have changed meanwhile).
        _data, msg, scripts_now = _rights_now(fresh=True)
        if msg is None and scripts_now != scripts:
            direct, culprit = ancestry.is_direct("sudo", entry_scripts=scripts_now)
            if not direct:
                msg = NOT_DIRECT.format(culprit=not_direct_who(culprit))
        if msg is not None:
            password = None
            print(msg, file=sys.stderr)
            audit.refusal("sudo", "localhost", f"{msg} (after the dialog)")
            return 1

    audit.use("sudo", "localhost", None, ["sudo", *argv], secrets=[password])
    rc, rejected = _run_with_askpass(real, argv, password)
    if rejected:
        _mark_stale(user)
        print(_reenter(user), file=sys.stderr)     # SPEC 6: one re-entry pop-up opens
    return rc


def _sudo_prompt(user: str) -> str:
    from . import popup
    try:
        return popup.secret_prompt(
            "sudo password", "localhost", target=f"{user}@localhost",
            note="Untick Remember it to use it for this command only (nothing is stored).")
    except Exception:  # noqa: BLE001
        return "Type the sudo password for this machine."


def _reenter(user: str) -> str:
    """The saved password was rejected: one re-entry pop-up (deduped, a cancel
    remembered), and the line that says what happened to it."""
    from . import popup

    def store(pw: str) -> None:
        with vault.edit() as cur:
            vault.set_sudo(cur, "localhost", user, pw)
    try:
        msg = popup.reenter("localhost", "sudo password", _sudo_prompt(user), verify_local,
                            store=store, check=SUDO_CHECK)
    except Exception:  # noqa: BLE001 - the refusal stands either way
        return STALE
    return msg.replace("for localhost", "for this machine") if isinstance(msg, str) and \
        msg.startswith("gateway: ") else STALE


def _password_for(data: dict[str, Any] | None, user: str) -> tuple[str | None, bool]:
    """(password, asked): the saved sudo password (asked False), or one
    collected through the gateway's dialog (asked True). None (with a printed
    reason) when it is stale or no dialog could open.

    The dialog offers "Remember it" (ticked by default): kept ticked, the
    dialog stores the value itself (store=, run where the dialog runs), so an
    answer that comes after this process gave up waiting (exit 75) is kept,
    and a second sudo that joined the same dialog re-reads it (load=);
    unticked, it is used for this command only and never stored. gated
    rechecks localhost's sudo right before it hands the value over
    (SUDO_CHECK). A rejected saved password opens the one re-entry dialog
    (popup.reenter, which dedupes and remembers a cancel) and is never fed
    again."""
    from . import popup
    entry = vault.sudo_entry(data, "localhost", user) if data is not None else None
    if entry is not None and not entry.get("stale"):
        pw = entry.get("password")
        if pw:
            return pw, False

    def store(pw: str) -> None:
        with vault.edit() as cur:
            vault.set_sudo(cur, "localhost", user, pw)

    def load() -> str | None:
        try:
            return (vault.sudo_entry(vault.load(), "localhost", user) or {}).get("password")
        except vault.VaultError:
            return None

    prompt = _sudo_prompt(user)
    if entry is not None and entry.get("stale"):
        msg = _reenter(user)
        print(msg, file=sys.stderr)
        audit.refusal("sudo", "localhost", msg)
        return None, False
    # No saved password: open a secret dialog (verified; it stores the value
    # when "Remember it" stays ticked).
    try:
        outcome, value = popup.secret("localhost", "sudo password", prompt, verify=verify_local,
                                      store=store, load=load, remember=True, check=SUDO_CHECK)
    except Exception as e:  # noqa: BLE001
        print(NO_PW, file=sys.stderr)
        audit.refusal("sudo", "localhost", f"{NO_PW} ({type(e).__name__})")
        return None, False
    if outcome == popup.Outcome.OK and value:
        return value, True
    if outcome == popup.Outcome.OK:
        # joined another command's dialog whose password wasn't kept
        print(JOINED_NOT_KEPT, file=sys.stderr)
        audit.refusal("sudo", "localhost", JOINED_NOT_KEPT)
        return None, False
    if outcome != popup.Outcome.UNAVAILABLE:     # (unavailable: popup printed why)
        print(popup.message(outcome, "localhost", "sudo password"), file=sys.stderr)
    audit.refusal("sudo", "localhost", f"{NO_PW} ({outcome})")
    return None, False


def _mark_stale(user: str) -> None:
    try:
        with vault.edit() as cur:
            vault.mark_stale(cur, "localhost", "sudo", user)
            vault.add_event(cur, "reject", "localhost sudo password rejected")
    except vault.VaultError:
        pass
    try:
        audit.log("reject", tool="sudo", target="localhost")
    except Exception:  # noqa: BLE001
        pass


# ---------------------------------------------------------------------------
# gate-askpass (run.py askpass)
# ---------------------------------------------------------------------------


def _parent_is_sudo() -> bool:
    """The askpass's parent must be the real sudo: in production the trusted
    root-owned setuid sudo (_is_real_sudo_parent). Under testing.override the
    real sudo is the phase-A fake, which runs as a python process, so the
    parent is identified by its command line (`fake_sudo…`); a direct
    invocation by any other process is refused just as in production."""
    ppid = os.getppid()
    if testing.active() is not None:
        return "fake_sudo" in (ancestry._cmdline(ppid) or "")
    return _is_real_sudo_parent(ppid)


def _is_real_sudo_parent(ppid: int, platform: str | None = None) -> bool:
    """Is process `ppid` the trusted sudo? By resolved executable path where
    it can be read (macOS's proc_pidpath answers for root's processes too). On
    Linux, /proc/PID/exe of a setuid-root process can't be read by its user
    (EACCES: it needs ptrace read access, and setuid processes are
    non-dumpable), so there `_linux_setuid_parent` decides (review round 2:
    without it every local sudo with a stored password failed on Linux)."""
    real = _real_sudo()
    if real is None:
        return False
    exe = ancestry._exe_path(ppid)
    if exe:
        try:
            return os.path.realpath(exe) == os.path.realpath(real)
        except OSError:
            return False
    if (platform or sys.platform).startswith("linux"):
        return _linux_setuid_parent(ppid)
    return False


def _proc_status(pid: int) -> dict[str, str]:
    """/proc/PID/status as {field: value} ({} if unreadable). Readable by
    everyone, also for setuid processes."""
    try:
        with open(f"/proc/{pid}/status", encoding="utf-8", errors="replace") as f:
            text = f.read()
    except OSError:
        return {}
    out: dict[str, str] = {}
    for line in text.splitlines():
        k, sep, v = line.partition(":")
        if sep:
            out[k.strip()] = v.strip()
    return out


def _askpass_owner() -> int | None:
    """The pid of the stand-in that made this askpass's 0700 folder (its
    `owner` file next to the FIFO), or None."""
    fifo = os.environ.get("GW_ASKPASS_FIFO", "")
    if not fifo:
        return None
    try:
        with open(os.path.join(os.path.dirname(fifo), "owner"), encoding="ascii") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def _linux_setuid_parent(ppid: int) -> bool:
    """The parent runs as root (effective uid 0 in /proc/PID/status) under the
    name sudo, and its own parent is the stand-in that started it (the pid in
    the askpass folder's `owner` file): the setuid sudo the stand-in ran."""
    st = _proc_status(ppid)
    uids = st.get("Uid", "").split()
    if len(uids) < 2 or uids[1] != "0":
        return False
    if st.get("Name") != "sudo":
        return False
    owner = _askpass_owner()
    try:
        return owner is not None and owner > 1 and int(st.get("PPid", "")) == owner
    except ValueError:
        return False


def _mark_rejected(fifo: str) -> None:
    try:
        marker = os.path.join(os.path.dirname(fifo), "rejected")
        with open(marker, "w"):
            pass
    except OSError:
        pass


def _read_fifo(fd: int, deadline: float) -> bytes:
    """Everything the writer sends, until it closes; b"" if no writer connects
    and writes before the deadline. A non-blocking read of a FIFO with no
    writer yet returns b"" (EOF): wait and try again; with a writer that
    hasn't written yet it raises BlockingIOError: wait for data."""
    import select
    data = b""
    writer = False
    while True:
        try:
            chunk = os.read(fd, 4096)
        except BlockingIOError:
            writer = True
            left = deadline - time.monotonic()
            if left <= 0:
                return b""
            with contextlib.suppress(InterruptedError, OSError, ValueError):
                select.select([fd], [], [], min(left, 0.5))
            continue
        except InterruptedError:
            continue
        if chunk:
            data += chunk
            writer = True
            continue
        if data or writer:
            return data                      # the writer wrote (or closed) and is gone
        if time.monotonic() >= deadline:
            return b""
        time.sleep(0.02)                     # no writer has connected yet


def askpass_main() -> int:
    if os.geteuid() == 0:
        return 1
    if os.environ.get("SUDO_COMMAND") or os.environ.get("SUDO_USER"):
        return 1
    if not _parent_is_sudo():
        return 1
    fifo = os.environ.get("GW_ASKPASS_FIFO", "")
    if not fifo:
        return 1
    try:
        # Never a blocking open: if the stand-in died before its writer
        # connected (a Bash timeout), a blocking open would hang this askpass
        # and sudo forever (round 3: orphans under launchd).
        fd = os.open(fifo, os.O_RDONLY | os.O_NONBLOCK)
    except OSError:
        _mark_rejected(fifo)                 # second call: FIFO already unlinked
        return 1
    try:
        data = _read_fifo(fd, time.monotonic() + float(testing.get("askpass_wait", ASKPASS_WAIT)))
    finally:
        os.close(fd)
    if not data:
        return 1
    if not data.endswith(b"\n"):
        data += b"\n"
    os.write(1, data)
    return 0
