"""Remote sudo over the ssh stand-in (SPEC 9.3, with the hardening below).

1. Probe `sudo -n true` over the connection, cached per (host, user) for 10
   minutes in the run dir: success -> the command runs untouched.
2. Else the stored password (hosts[X].sudo[USER]) goes, on stdin, to a
   staging call that writes it into a fresh 0700 dir (XDG_RUNTIME_DIR, else
   /dev/shm, else /tmp) next to a tiny askpass. The askpass answers only
   when its parent process runs as root (real sudo is setuid root; a shell
   or a script calling the askpass is not), once per sudo process ($PPID
   marker), at most ASK_LIMIT times per call, and never again once a sudo
   asked twice (a second ask from one sudo process means the answer was
   rejected: the `rejected` marker). Passwords shorter than 8 characters are
   refused (the scrubber can't hide them).
3. Before a saved password is first used (and then every 10 minutes), the
   staged password is verified with `sudo -k -A -v` (one attempt); a
   rejection marks it stale and the command doesn't run.
4. The command runs with the askpass scoped to it:
   - scripts = false (default): a shell function `sudo() { SUDO_ASKPASS=<dir>/a
     DISPLAY=... command sudo "$@"; }` (and `sudoedit() {...}` when the command
     runs sudoedit) before the command: only `sudo` in command position in
     Claude's own command gets the askpass (not `/usr/bin/sudo`: a path skips
     shell functions); nothing is exported to the programs the command starts.
   - scripts = true: `export SUDO_ASKPASS=<dir>/a; [ -n "${DISPLAY-}" ] ||
     export DISPLAY=gw:0;` (SPEC 9.3 step 3), so nested sudo in scripts works.
5. A cleanup call removes the dir and reports the markers (rejected, how
   many answers); the command's output is scrubbed (the password is in the
   scrub set: the scrubber masks the literal value and its base64,
   url-encoded and line-split forms, not a transformed one).
6. Stale only on the askpass's `rejected` marker or a failed verification,
   never on the command's own output. sudo's own `Sorry, try again.` lines
   after an answer only drop the verification cache (the next call verifies).

Residual risk (accepted in phase C, SPEC 9.3 and docs/dev/phaseB-requests/RESOLUTION.md
#7; since PLAN-v4 phase 7 the gateway no longer offers to install a passwordless
sudoers rule: passwordless sudo is used only where the host already has it, and
the dialog's "Remember it" unticked uses a password for one call): while
the call runs, anything running as the login user on the remote, including
Claude's own command under the default scripts = false, can find the staging
dir and read the password file (`sudo true; cat "$XDG_RUNTIME_DIR"/gw.*/p |
rev`). Scrubbing then only catches the untransformed forms: reversed, hex
or spaced-out output gets through. The measures above stop the askpass from
handing the password out and keep it out of the environment; they don't stop
a deliberate same-user reader. Where the host is already set up for passwordless
sudo, nothing is staged at all.
"""
from __future__ import annotations

import contextlib
import os
import re
import shlex
import time
from pathlib import Path

from . import paths, testing
from .scrub import MIN_LITERAL
from .ssh_conf import Conn, SshError

PROBE_TTL = 600
VERIFY_TTL = 600
ASK_LIMIT = 6
MIN_PASSWORD = MIN_LITERAL
PROBE_CMD = "sudo -n true"
# The remote sudo dialog's "Remember it" box starts unticked (PLAN-0.11
# §9.1, 27g): a password typed for a command is used for that call only,
# since while it is staged on the host Claude's own command could read it;
# the person ticks the box to keep it (ssh.py's _sudo_password).
REMEMBER_DEFAULT = False
REMEMBER_NOTE = ("Tick Remember it to keep it for later commands (unticked, it is used for this "
                 "command only).")

# The effective uid of the askpass's parent ($PPID): /proc on Linux (real,
# effective, saved, fs), else /bin/ps (BSD and procps: `uid` is effective).
# Absolute paths and builtins only: whoever calls the askpass controls PATH.
EUID_LOOKUP = ('u=; if [ -r "/proc/$PPID/status" ]; then '
               'while read -r k r e x; do if [ "$k" = Uid: ]; then u=$e; break; fi; done '
               '< "/proc/$PPID/status"; else u=$(/bin/ps -o uid= -p "$PPID" 2>/dev/null); fi')


def askpass_script(euid_cmd: str | None = None) -> str:
    """The remote askpass. `euid_cmd` replaces the euid lookup (tests only:
    the fake sudo isn't root; testing.get("ssh_remote_euid"))."""
    look = EUID_LOOKUP if not euid_cmd else f'u=$({shlex.quote(euid_cmd)} "$PPID" 2>/dev/null)'
    return (
        "#!/bin/sh\n"
        "PATH=/usr/bin:/bin; export PATH\n"
        'd=${0%/*}\n'
        '[ -e "$d/no" ] && exit 1\n'
        f"{look}\n"
        "set -- $u\n"
        '[ "${1-}" = 0 ] || exit 1\n'
        'if [ -e "$d/used.$PPID" ]; then : > "$d/rejected"; : > "$d/no"; exit 1; fi\n'
        'set -- "$d"/used.*\n'
        f'if [ -e "$1" ] && [ $# -ge {ASK_LIMIT} ]; then exit 1; fi\n'
        ': > "$d/used.$PPID"\n'
        'exec /bin/cat "$d/p"\n')


def stage_script(euid_cmd: str | None = None) -> str:
    """SPEC 9.3 step 2's staging call (password on stdin), with the hardened
    askpass."""
    return ('umask 077; d=$(mktemp -d "${XDG_RUNTIME_DIR:-/dev/shm}/gw.XXXXXX" 2>/dev/null '
            "|| mktemp -d /tmp/gw.XXXXXX)\n"
            "IFS= read -r p; printf '%s\\n' \"$p\" > \"$d/p\"; unset p\n"
            "cat > \"$d/a\" <<'EOF'\n" + askpass_script(euid_cmd) + "EOF\n"
            'chmod 700 "$d/a"; (sleep 900; rm -rf "$d") >/dev/null 2>&1 &\n'
            'echo "$d"')


STAGE = stage_script()
STAGE_DIR = re.compile(r"/[A-Za-z0-9._/+-]{0,400}/gw\.[A-Za-z0-9]{6,}")
# sudo's own lines (anchored): the command's output saying "incorrect
# password" somewhere doesn't match.
REJECTED_LINE = re.compile(r"(?m)^(?:Sorry, try again\.?|sudo: [0-9]+ incorrect password "
                           r"attempts?)\r?$")
# sudo found no way to ask (no askpass in its environment: a nested shell or a
# wrapper like env/nohup/xargs under scripts = false).
NO_ASKPASS = re.compile(r"(?m)^sudo: (?:a terminal is required|no askpass program|"
                        r"a password is required)")
_REPORT = re.compile(r"gw-sudo r=([01]) n=([0-9]+)")
POSIX_CHECK = "x=ok; printf '%s\\n' \"$x\""


def prefix(d: str, scripts: bool = False, names: tuple[str, ...] = ("sudo",)) -> str:
    """What goes before the user's command (see the module docstring, 4).
    `names`: the sudo commands in command position (scripts = false): one
    shell function each (`sudo`, `sudoedit`)."""
    a = shlex.quote(d + "/a")
    if scripts:
        return f'export SUDO_ASKPASS={a}; [ -n "${{DISPLAY-}}" ] || export DISPLAY=gw:0; '
    return "".join(f'{n}() {{ SUDO_ASKPASS={a} DISPLAY="${{DISPLAY:-gw:0}}" command {n} "$@"; }}; '
                   for n in names if n in ("sudo", "sudoedit"))


def verify_cmd(d: str) -> str:
    return f"SUDO_ASKPASS={shlex.quote(d + '/a')} DISPLAY=gw:0 sudo -k -A -v"


def cleanup_cmd(d: str) -> str:
    """Remove the staging dir; print the markers (rejected, number of answers)."""
    return (f"d={shlex.quote(d)}; n=0; for f in \"$d\"/used.*; do [ -e \"$f\" ] && n=$((n+1)); "
            "done; r=0; [ -e \"$d/rejected\" ] && r=1; rm -rf -- \"$d\"; "
            "echo \"gw-sudo r=$r n=$n\"")


def too_short(password: str) -> bool:
    return len(password) < MIN_PASSWORD


def short_message(name: str, user: str) -> str:
    return (f"gateway: the sudo password of {user} on {name} is shorter than {MIN_PASSWORD} "
            "characters, so the gateway can't keep it out of command output; remote sudo with it "
            "is off. Ask the user to run the root command themselves, or to use a longer "
            "password")


# ---------------------------------------------------------------------------
# Caches in the run dir: rsudo-NAME@USER (passwordless probe), rsudov-NAME@USER
# (the saved password was verified). '@' never occurs in a host name.
# ---------------------------------------------------------------------------


def _probe_path(name: str, user: str) -> Path:
    return paths.run_dir() / f"rsudo-{name}@{user}"


def _verified_path(name: str, user: str) -> Path:
    return paths.run_dir() / f"rsudov-{name}@{user}"


def _read2(p: Path, ttl: float) -> str | None:
    try:
        txt = p.read_text().split()
        if len(txt) == 2 and time.time() - float(txt[1]) < ttl:
            return txt[0]
    except (OSError, ValueError, paths.PathError):
        pass
    return None


def _write2(p: Path, word: str) -> None:
    with contextlib.suppress(OSError, paths.PathError):
        tmp = p.with_name(p.name + f".{os.getpid()}")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(f"{word} {time.time()}")
        os.replace(tmp, p)


def probe_cached(name: str, user: str) -> bool | None:
    w = _read2(_probe_path(name, user), PROBE_TTL)
    return None if w is None else w == "yes"


def probe_store(name: str, user: str, ok: bool) -> None:
    _write2(_probe_path(name, user), "yes" if ok else "no")


def probe_clear(name: str) -> None:
    with contextlib.suppress(OSError, paths.PathError):
        for pat in (f"rsudo-{name}@*", f"rsudov-{name}@*"):
            for p in paths.run_dir().glob(pat):
                p.unlink()


def _stamp(updated: str | None) -> str:
    return re.sub(r"[^A-Za-z0-9:.+-]", "", str(updated or "-"))[:40] or "-"


def verified_recently(name: str, user: str, updated: str | None) -> bool:
    return _read2(_verified_path(name, user), VERIFY_TTL) == _stamp(updated)


def note_verified(name: str, user: str, updated: str | None) -> None:
    _write2(_verified_path(name, user), _stamp(updated))


def forget_verified(name: str, user: str) -> None:
    with contextlib.suppress(OSError, paths.PathError):
        _verified_path(name, user).unlink()


# ---------------------------------------------------------------------------
# Remote calls
# ---------------------------------------------------------------------------


def probe(conn: Conn, name: str, user: str, use_cache: bool = True) -> bool:
    """`sudo -n true` over the connection (cached 10 min). True: no password."""
    if use_cache:
        c = probe_cached(name, user)
        if c is not None:
            return c
    r = conn.capture(PROBE_CMD, timeout=60)
    if r.returncode == 255:
        from .ssh_conf import explain_failure
        msg = explain_failure(name, 255, r.stderr.decode("utf-8", "replace"))
        raise SshError(msg or f"gateway: couldn't reach {name} to check sudo", 255)
    ok = r.returncode == 0
    probe_store(name, user, ok)
    return ok


def posix_shell(conn: Conn) -> bool:
    r = conn.capture(POSIX_CHECK, timeout=30)
    return r.returncode == 0 and r.stdout.decode("utf-8", "replace").strip() == "ok"


def stage(conn: Conn, name: str, password: str) -> str:
    """Write the password and askpass on the remote; returns the dir."""
    script = stage_script(testing.get("ssh_remote_euid") or None)
    r = conn.capture(script, stdin=(password + "\n").encode("utf-8"), timeout=60)
    out = r.stdout.decode("utf-8", "replace").strip().splitlines()
    d = out[-1].strip() if out else ""
    if r.returncode != 0 or not STAGE_DIR.fullmatch(d):
        raise SshError(f"gateway: couldn't prepare sudo on {name} (its login shell must be "
                       "POSIX sh, bash, dash or zsh, and mktemp must work)", 1)
    return d


def verify_staged(conn: Conn, d: str) -> int:
    """`sudo -k -A -v` with the staged askpass (one attempt); its exit code."""
    return conn.capture(verify_cmd(d), timeout=60).returncode


def cleanup(conn: Conn, d: str) -> tuple[bool, int]:
    """Remove the staging dir. (rejected, answers) from the askpass markers;
    (False, 0) when the report didn't come back."""
    try:
        r = conn.capture(cleanup_cmd(d), timeout=30)
    except (SshError, OSError):
        return False, 0
    m = _REPORT.search(r.stdout.decode("utf-8", "replace"))
    return (m.group(1) == "1", int(m.group(2))) if m else (False, 0)


def rejected(stderr: str) -> bool:
    """sudo's own rejection lines in stderr (a hint only, see the docstring)."""
    return bool(REJECTED_LINE.search(stderr))
