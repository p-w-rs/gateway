"""Scrubbing secrets out of output (SPEC 11).

- `secret_forms(value, user=None)`: the literal forms one credential can take
  in output: the value, its base64 (also the part of the base64 that is fixed
  whatever comes before or after it, at each of the three byte alignments, so
  `base64("x-access-token:" + value)` in a Basic header is caught), base64 of
  `user:value`, its URL-encoded forms, and each long line of a multi-line
  value (an SSH key printed line by line). Only forms of at least 8
  characters are returned: masking a short value wherever it occurs would
  reveal it.
- `Scrubber(secrets)`: a streaming byte filter. It holds back only the
  longest suffix of what it has seen that is a proper prefix of a secret
  form, masks every occurrence (overlapping ones too) with `***`, and is
  bytes-safe (binary output passes through unchanged unless it contains a
  secret). `feed(chunk)` returns what is safe to emit now; `flush()` returns
  the rest at end of stream; `release()` emits what is held back after
  `IDLE` seconds of quiet (the pumps call it), and a secret that started in
  released bytes is masked from where its continuation arrives.
- `pump(src_fd, dst_fd, scrubber)` and `run(argv, secrets, ...)`: run a
  child with its stdout/stderr streamed through scrubbers (stdin inherited);
  a closed reader (EPIPE) closes the read side so the child gets SIGPIPE;
  SIGINT/SIGTERM/SIGHUP are forwarded; the child's exit code is returned
  (a signal N gives 128+N).
- `scrub_text(text, extra=None)`: every vault and cache value (>= 8 chars,
  in all their forms; cached per process by the files' mtimes) plus `extra`
  literals plus the token shape patterns.
"""
from __future__ import annotations

import base64
import errno
import json
import os
import re
import signal
import subprocess
import threading
import urllib.parse
from typing import Iterable, Sequence

MASK = b"***"
IDLE = 0.15            # seconds of quiet after which held-back bytes are released
MIN_LITERAL = 8
MIN_LINE = 16          # lines of a multi-line secret masked on their own
CHUNK = 65536


# ---------------------------------------------------------------------------
# Forms of a secret
# ---------------------------------------------------------------------------


def _b64_cores(raw: bytes) -> list[str]:
    """For each byte alignment k (0, 1, 2) the base64 characters that depend
    only on `raw`, whatever bytes precede or follow it in the encoded text."""
    out = []
    n = len(raw)
    for k in range(3):
        enc = base64.b64encode(b"\0" * k + raw + b"\0\0").decode()
        first = -(-8 * k // 6)               # ceil(8k / 6)
        last = (8 * k + 8 * n) // 6          # exclusive
        if last > first:
            out.append(enc[first:last])
    return out


def secret_forms(value: str | bytes, user: str | None = None) -> list[str]:
    """The forms of one credential worth masking (each >= 8 characters)."""
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            value = value.decode("latin-1")
    if not value or len(value) < MIN_LITERAL:
        return []
    raw = value.encode("utf-8")
    forms = [value]
    b64 = base64.b64encode(raw).decode()
    forms += [b64, b64.rstrip("="), base64.urlsafe_b64encode(raw).decode().rstrip("=")]
    forms += _b64_cores(raw)
    if user:
        up = base64.b64encode(f"{user}:{value}".encode("utf-8")).decode()
        forms += [up, up.rstrip("=")]
    for q in (urllib.parse.quote(value, safe=""), urllib.parse.quote_plus(value),
              urllib.parse.quote(value)):
        forms.append(q)
    # JSON-escaped, as a transcript, an export or a tool's JSON output holds
    # it: a value with `"`, `\\`, a control character or non-ASCII text differs
    # there (review round 4), and a multi-line key is one escaped line.
    forms += [json.dumps(value)[1:-1], json.dumps(value, ensure_ascii=False)[1:-1]]
    if "\n" in value:
        forms += [line.strip() for line in value.splitlines() if len(line.strip()) >= MIN_LINE]
        forms.append(value.replace("\n", "\r\n"))
    return [f for f in dict.fromkeys(forms) if len(f) >= MIN_LITERAL]


def expand(secrets: Iterable[str | bytes], users: Iterable[str] = ()) -> list[bytes]:
    """Every form of every secret, as bytes, longest first."""
    us = [u for u in users if u] or [None]
    out: set[bytes] = set()
    for s in secrets:
        if not s or len(s) < MIN_LITERAL:
            continue
        for u in us:
            for f in secret_forms(s, u):
                out.add(f.encode("utf-8"))
    return sorted(out, key=len, reverse=True)


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------


class Scrubber:
    """Streaming byte filter (SPEC 11): holds back only the longest suffix
    that is a proper prefix of a secret; masks matches with ***.

    `secrets` are expanded with secret_forms() (base64, user:value base64,
    URL-encoded, ...) unless expand=False; values under 8 characters are
    ignored. `users` adds base64(user:value) forms for those user names.

    `release()` emits what is held back without waiting for more (the pumps
    call it after IDLE seconds of quiet, so a prompt or a protocol byte that
    happens to start a secret's form never stalls the stream; review round
    2). The released bytes stay in a window: if the next bytes complete a
    secret that started there, the rest of it is masked, so the whole value
    never shows (only the prefix that was released does)."""

    def __init__(self, secrets: Iterable[str | bytes], users: Iterable[str] = (),
                 expand_forms: bool = True):
        if expand_forms:
            pats = expand(secrets, users)
        else:
            pats = sorted({(s.encode("utf-8") if isinstance(s, str) else bytes(s))
                           for s in secrets if s and len(s) >= MIN_LITERAL},
                          key=len, reverse=True)
        self.patterns: list[bytes] = pats
        self.maxlen = max((len(p) for p in pats), default=0)
        self._by_first: dict[int, list[bytes]] = {}
        for p in pats:
            self._by_first.setdefault(p[0], []).append(p)
        # The window: win[:_emit] was handled already (emitted, or covered by
        # a *** emitted earlier: win[:_masked]); win[_emit:] is held back.
        # win starts at the earliest position that may still begin a secret.
        self._win = b""
        self._emit = 0
        self._masked = 0
        self._valid: list[int] = []   # positions p in win where win[p:] is a proper prefix

    @property
    def active(self) -> bool:
        return bool(self.patterns)

    @property
    def holding(self) -> bool:
        """Bytes are held back (release() would emit something)."""
        return self._emit < len(self._win)

    def _spans(self, buf: bytes) -> list[tuple[int, int]]:
        spans = []
        for p in self.patterns:
            i = buf.find(p)
            while i != -1:
                spans.append((i, i + len(p)))
                i = buf.find(p, i + 1)
        if not spans:
            return []
        spans.sort()
        merged = [list(spans[0])]
        for a, b in spans[1:]:
            if a < merged[-1][1]:            # overlapping (not merely adjacent)
                merged[-1][1] = max(merged[-1][1], b)
            else:
                merged.append([a, b])
        return [(a, b) for a, b in merged]

    def _is_prefix_start(self, buf: bytes, p: int) -> bool:
        cands = self._by_first.get(buf[p])
        if not cands:
            return False
        tail = buf[p:]
        lt = len(tail)
        return any(len(c) > lt and c.startswith(tail) for c in cands)

    def _prefix_starts(self, buf: bytes, old_len: int) -> list[int]:
        """Every p where buf[p:] is a proper prefix of a pattern. Positions
        inside the old window can only be ones that were valid there."""
        n = len(buf)
        lo = max(0, n - self.maxlen + 1)
        cands = [p for p in self._valid if p >= lo]
        cands += range(max(lo, old_len), n)
        return [p for p in cands if self._is_prefix_start(buf, p)]

    def _step(self, data: bytes, final: bool) -> bytes:
        """Take `data`, emit what is safe (everything when `final`), keep
        the window. The one routine behind feed, release and flush."""
        old_len = len(self._win)
        buf = self._win + bytes(data)
        n = len(buf)
        e, m0 = self._emit, self._masked
        starts = self._prefix_starts(buf, old_len) if n else []
        cut = n if final else max(starts[0] if starts else n, e)
        m = m0
        out = bytearray()
        pos = e
        # win[:m0] is covered by a *** emitted earlier. A secret that overlaps
        # it continues that ***, unless bytes were released in clear between
        # (m0 < e): then, like any other, it gets its own *** where its
        # unhandled part begins. This also runs when nothing new is emitted:
        # a secret that started in released bytes and completes now is
        # masked at once.
        for a, b in self._spans(buf):
            if b <= pos:
                continue
            if a >= cut:
                break
            st = max(a, pos)
            lo = max(pos, m0)
            if lo < st:
                out += buf[lo:st]
            if not (a < m0 and m0 >= e):
                out += MASK
            m = max(m, b)
            pos = max(st, min(b, cut))
        lo = max(pos, m0)
        if lo < cut:
            out += buf[lo:cut]
        keep = min(starts[0], cut) if starts else cut
        self._win = buf[keep:]
        self._emit = cut - keep
        self._masked = max(0, m - keep)
        self._valid = [p - keep for p in starts if p >= keep]
        return bytes(out)

    def feed(self, data: bytes) -> bytes:
        """Filter a chunk; returns what is safe to emit now."""
        if not self.patterns:
            return bytes(data)
        if not data and not self.holding:
            return b""
        return self._step(data, final=False)

    def release(self) -> bytes:
        """Emit what is held back now (the stream went quiet); a secret that
        started in it is still masked from wherever the next bytes complete
        it (see the class docstring)."""
        if not self.patterns or not self.holding:
            return b""
        return self._step(b"", final=True)

    def flush(self) -> bytes:
        """Emit whatever is held back (end of stream)."""
        if not self.patterns:
            return b""
        out = self._step(b"", final=True) if self.holding else b""
        self._win, self._emit, self._masked, self._valid = b"", 0, 0, []
        return out


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


def pump(src: int, dst: int, scrubber: Scrubber, close_src: bool = True,
         idle: float | None = None) -> bool:
    """Copy src to dst through the scrubber until EOF. Bytes held back (a
    possible start of a secret) are released after `idle` seconds (IDLE by
    default) without new input, so an interactive prompt or a protocol
    exchange never waits for bytes that won't come. On EPIPE/a closed
    reader, close src (the writer then gets SIGPIPE/EPIPE instead of
    blocking on a full pipe) and drain nothing more. Returns False if the
    reader went away."""
    import select
    wait = IDLE if idle is None else idle
    ok = True
    try:
        while True:
            if scrubber.holding:
                try:
                    ready = select.select([src], [], [], wait)[0]
                except InterruptedError:
                    continue
                except (OSError, ValueError):
                    ready = [src]
                if not ready:
                    out = scrubber.release()
                    if out:
                        _write_all(dst, out)
                    continue
            try:
                chunk = os.read(src, CHUNK)
            except InterruptedError:
                continue
            except OSError:
                chunk = b""
            if not chunk:
                tail = scrubber.flush()
                if tail:
                    _write_all(dst, tail)
                break
            out = scrubber.feed(chunk)
            if out:
                _write_all(dst, out)
    except BrokenPipeError:
        ok = False
    except OSError as e:
        if e.errno not in (errno.EPIPE, errno.EBADF):
            raise
        ok = False
    finally:
        if close_src:
            try:
                os.close(src)
            except OSError:
                pass
    return ok


def run(argv: Sequence[str], secrets: Iterable[str | bytes], *, env: dict[str, str] | None = None,
        cwd: str | None = None, users: Iterable[str] = (), stdout_fd: int = 1,
        stderr_fd: int = 2, stdin: int | None = None, pass_fds: Sequence[int] = ()) -> int:
    """Run argv with stdout and stderr streamed through scrubbers (stdin
    inherited unless given). Returns the child's exit code (128+N for a
    signal N). Raises OSError if the program can't be started."""
    secrets = list(secrets)
    users = list(users)
    # Private pipes whose read ends only pump() closes (once: on EOF, or at
    # once when our reader went away so the child gets SIGPIPE). Popen's own
    # PIPE file objects would close the same fd numbers a second time, which
    # can hit an unrelated fd another thread opened in between.
    out_r, out_w = os.pipe()
    err_r, err_w = os.pipe()
    try:
        proc = subprocess.Popen(list(argv), stdin=stdin, stdout=out_w, stderr=err_w, env=env,
                                cwd=cwd, bufsize=0, pass_fds=tuple(pass_fds))
    except BaseException:
        for fd in (out_r, out_w, err_r, err_w):
            os.close(fd)
        raise
    os.close(out_w)
    os.close(err_w)
    old: dict[int, object] = {}

    def fwd(signum: int, _frame: object) -> None:
        try:
            proc.send_signal(signum)
        except OSError:
            pass

    if threading.current_thread() is threading.main_thread():
        for s in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            try:
                old[s] = signal.signal(s, fwd)
            except (OSError, ValueError):
                pass
    started: list[threading.Thread] = []
    try:
        for src, dst in ((out_r, stdout_fd), (err_r, stderr_fd)):
            t = threading.Thread(target=pump, args=(src, dst, Scrubber(secrets, users)),
                                 daemon=True)
            t.start()
            started.append(t)
        rc = proc.wait()
        for t in started:
            t.join()
    finally:
        for s, h in old.items():
            try:
                signal.signal(s, h)  # type: ignore[arg-type]
            except (OSError, ValueError, TypeError):
                pass
        if len(started) < 2:          # a pump never started: its read end is still ours
            for fd in (out_r, err_r)[len(started):]:
                try:
                    os.close(fd)
                except OSError:
                    pass
    return rc if rc >= 0 else 128 - rc


# ---------------------------------------------------------------------------
# Whole texts
# ---------------------------------------------------------------------------

SHAPES = [
    re.compile(r"\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{10,}"),
    re.compile(r"\bhf_[A-Za-z0-9]{10,}"),
    re.compile(r"\bglpat-[A-Za-z0-9_-]{10,}"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"),
    re.compile(r"AGE-SECRET-KEY-1[0-9A-Z]+"),
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
               re.S),
]
AUTH_HEADER = re.compile(r"(?i)\b(authorization:\s*(?:bearer|basic|token)\s+)[^\s\"',;]+")

_VAULT_CACHE: dict[str, object] = {"key": None, "values": []}


def _stat_key() -> tuple:
    from . import paths
    out = []
    for p in (paths.vault_path(), paths.cache_path()):
        try:
            st = p.stat()
            out.append((st.st_mtime_ns, st.st_size, st.st_ino))
        except OSError:
            out.append(None)
    return tuple(out)


def note_vault(data: dict) -> None:
    """A caller that already decrypted the vault hands it over, so
    scrub_text needn't decrypt it again in this process."""
    try:
        from . import vault
        key = _stat_key()
        vals = [v for v in vault.all_values(data) if len(v) >= MIN_LITERAL]
        try:
            vals += [v for v in vault.cache_values() if len(v) >= MIN_LITERAL]
        except Exception:  # noqa: BLE001
            pass
        _VAULT_CACHE["key"] = key
        _VAULT_CACHE["values"] = expand(vals, ("x-access-token",))
    except Exception:  # noqa: BLE001
        pass


def add_values(values: Iterable[str]) -> None:
    """Extra values (minted tokens) scrub_text should mask in this process."""
    vals = [v for v in values if v and len(v) >= MIN_LITERAL]
    if not vals:
        return
    cur = list(_VAULT_CACHE.get("extra") or [])  # type: ignore[arg-type]
    _VAULT_CACHE["extra"] = sorted(set(cur) | set(expand(vals)), key=len, reverse=True)


def vault_values() -> list[bytes]:
    """Every vault and cache value in all its forms (cached per process
    while the files don't change). [] if the vault can't be read."""
    try:
        key = _stat_key()
    except Exception:  # noqa: BLE001
        return list(_VAULT_CACHE.get("extra") or [])  # type: ignore[arg-type]
    if _VAULT_CACHE.get("key") != key:
        vals: list[str] = []
        try:
            from . import vault
            if vault.exists():
                vals += [v for v in vault.all_values(vault.load()) if len(v) >= MIN_LITERAL]
            vals += [v for v in vault.cache_values() if len(v) >= MIN_LITERAL]
        except Exception:  # noqa: BLE001 - scrubbing never fails; shapes still apply
            pass
        _VAULT_CACHE["key"] = key
        _VAULT_CACHE["values"] = expand(vals, ("x-access-token",))
    return list(_VAULT_CACHE["values"]) + list(_VAULT_CACHE.get("extra") or [])  # type: ignore[arg-type]


def _mask_literals(text: str, pats: Iterable[bytes]) -> str:
    raw = text.encode("utf-8", "surrogatepass")
    s = Scrubber(list(pats), expand_forms=False)
    if not s.active:
        return text
    out = s.feed(raw) + s.flush()
    try:
        return out.decode("utf-8", "surrogatepass")
    except UnicodeDecodeError:
        return out.decode("utf-8", "replace")


def scrub_text(text: str, extra: list[str] | None = None) -> str:
    """All vault values (>= 8 chars, cached) plus `extra` literals and the
    token shape patterns, masked (SPEC 11)."""
    if not text:
        return text
    pats = set(vault_values())
    pats |= set(expand(extra or [], ("x-access-token",)))
    text = _mask_literals(text, pats)
    for rx in SHAPES:
        text = rx.sub("***", text)
    return AUTH_HEADER.sub(lambda m: m.group(1) + "***", text)
