"""age's passphrase (scrypt) recipient, driven under a private pty.

age reads a passphrase only from a terminal, so it runs under a pty this
process owns; the passphrase is typed into it when age asks, and the
plaintext goes through a FIFO in a fresh 0700 temp folder (never a file on
disk, never a command line or an environment variable). Used by export and
import (transfer.py) and by the gateway daemon to wrap the vault key with
the user's passphrase (daemon/broker.py): age's scrypt recipient is the
established construction (scrypt work factor, ChaCha20-Poly1305), nothing
of the gateway's own invention.

    encrypt(plain, passphrase) -> bytes          an age file (scrypt recipient)
    decrypt(blob, passphrase) -> bytes           BadPassphrase for a wrong one

A passphrase is at most MAX_PASSPHRASE_BYTES (512) in UTF-8: age reads it as
one tty line, and macOS's line limit is 1024 bytes (PassphraseTooLong).
"""
from __future__ import annotations

import errno
import os
import re
import select
import shutil
import signal
import tempfile
import threading
import time
from pathlib import Path

from . import paths

MAX_FILE = 5_000_000
AGE_TIMEOUT = 120
# age reads the passphrase as one line in the tty's canonical mode; a line
# near the tty's limit (MAX_CANON, 1024 bytes on macOS) never completes and
# age waits out AGE_TIMEOUT. Passphrases are bounded well below it.
MAX_PASSPHRASE_BYTES = 512
# age's passphrase prompts as they end the pty's output ("Enter passphrase
# (leave empty to autogenerate a secure one): ", "Confirm passphrase: ",
# "Enter passphrase: "). test_packaging runs the locked age under a pty and
# checks its prompts against this, so a reworded prompt fails at the relock.
PROMPT_RE = re.compile(rb"(?i)passphrase[^\n]*:\s*$")


class AgePassError(Exception):
    """age failed (the message holds no secret)."""


class BadPassphrase(AgePassError):
    """The passphrase doesn't open the file."""


class Tampered(AgePassError):
    """The file opened with the passphrase but failed age's authentication:
    changed or damaged after it was written (PLAN-v4 phase 7)."""


class PassphraseTooLong(AgePassError):
    """Longer than MAX_PASSPHRASE_BYTES in UTF-8 (age would hang on it)."""


def _age() -> str:
    try:
        return paths.tool("age")
    except paths.ToolMissing as e:
        raise AgePassError(str(e)) from None


def run_age(args: list[str], passphrase: str, answers: int, fifo: Path,
            feed: bytes | None, timeout: float = AGE_TIMEOUT) -> tuple[int, str, bytes]:
    """age with args under a pty, answering `answers` passphrase prompts. With
    feed, write it into fifo (age's input); else read fifo (age's output).
    PassphraseTooLong, before age starts, for a passphrase over
    MAX_PASSPHRASE_BYTES."""
    import pty
    if len(passphrase.encode("utf-8", "surrogatepass")) > MAX_PASSPHRASE_BYTES:
        raise PassphraseTooLong(f"gateway: a passphrase may be at most {MAX_PASSPHRASE_BYTES} "
                                "bytes (UTF-8)")
    age = _age()
    got = bytearray()
    done = threading.Event()

    def pump() -> None:
        try:
            if feed is not None:
                with open(fifo, "wb") as f:
                    f.write(feed)
            else:
                with open(fifo, "rb") as f:
                    while chunk := f.read(65536):
                        got.extend(chunk)
                        if len(got) > MAX_FILE * 2:
                            break
        except OSError:
            pass
        finally:
            done.set()

    t = threading.Thread(target=pump, daemon=True)
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TMPDIR")}
    env["TERM"] = "dumb"
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.execve(age, [age, *args], env)
        finally:
            os._exit(127)
    t.start()
    out = bytearray()
    sent, mark = 0, 0
    deadline = time.time() + timeout
    status = None
    try:
        while time.time() < deadline:
            r, _, _ = select.select([fd], [], [], 0.2)
            if r:
                try:
                    chunk = os.read(fd, 4096)
                except OSError as e:
                    if e.errno != errno.EIO:
                        raise
                    chunk = b""
                if not chunk:
                    break
                out.extend(chunk)
                tail = bytes(out[mark:])
                if sent < answers and PROMPT_RE.search(tail):
                    os.write(fd, passphrase.encode() + b"\r")
                    sent += 1
                    mark = len(out)
            wpid, st = os.waitpid(pid, os.WNOHANG)
            if wpid:
                status = st
                while True:
                    r, _, _ = select.select([fd], [], [], 0.05)
                    if not r:
                        break
                    try:
                        chunk = os.read(fd, 4096)
                    except OSError:
                        break
                    if not chunk:
                        break
                    out.extend(chunk)
                break
        until = time.time() + 10
        while status is None and time.time() < until:
            wpid, st = os.waitpid(pid, os.WNOHANG)
            if wpid:
                status = st
            else:
                time.sleep(0.02)
        if status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
            raise AgePassError("gateway: age didn't finish in time")
    finally:
        os.close(fd)
        if not done.is_set():
            try:
                flags = os.O_NONBLOCK | (os.O_RDONLY if feed is not None else os.O_WRONLY)
                os.close(os.open(fifo, flags))
            except OSError:
                pass
        t.join(5)
    code = os.waitstatus_to_exitcode(status)
    text = out.decode("utf-8", "replace").replace(passphrase, "***") if passphrase else ""
    return code, text, bytes(got)


def tmpdir() -> Path:
    d = Path(tempfile.mkdtemp(prefix="gw-xfer-"))
    os.chmod(d, 0o700)
    return d


def encrypt(plain: bytes, passphrase: str) -> bytes:
    d = tmpdir()
    try:
        fifo = d / "in"
        os.mkfifo(fifo, 0o600)
        tmp_out = d / "out.age"
        code, _text, _ = run_age(["-p", "-o", str(tmp_out), str(fifo)], passphrase, 2, fifo, plain)
        if code != 0 or not tmp_out.is_file():
            raise AgePassError("gateway: age could not encrypt")
        return tmp_out.read_bytes()
    finally:
        shutil.rmtree(d, ignore_errors=True)


def decrypt(blob: bytes, passphrase: str) -> bytes:
    d = tmpdir()
    try:
        src = d / "in.age"
        fd = os.open(src, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
        fifo = d / "out"
        os.mkfifo(fifo, 0o600)
        code, text, got = run_age(["-d", "-o", str(fifo), str(src)], passphrase, 1, fifo, None)
        if code != 0:
            low = text.lower()
            if "incorrect passphrase" in low or "no identity matched" in low:
                raise BadPassphrase("gateway: that passphrase doesn't open it")
            if any(w in low for w in ("mac", "authenticat", "chunk", "unexpected eof", "truncat",
                                      "malformed", "invalid header", "parse header",
                                      "failed to read header")):
                raise Tampered("gateway: the file failed its authentication check")
            raise AgePassError("gateway: age could not decrypt")
        return got
    finally:
        shutil.rmtree(d, ignore_errors=True)
