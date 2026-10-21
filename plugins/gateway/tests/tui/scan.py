"""Canary helpers: make synthetic secrets in-process and find where they leaked.

A canary is generated here, typed or pasted by the test into the TUI (or fed
to the plugin under test), and then searched for everywhere it must not be:
a directory tree (config dir, transcripts, history, debug log, plugin data,
journals), the raw PTY bytes, the rendered screen, the fake API's request log
and the observer plugin's records. Reports name only WHERE a canary was found
(file, record, encoding), never the value or the text around it.

    c = Canary.new("pw")            # repr/str never show the value
    s.redact(c.value)               # keep it out of driver dumps
    s.type(c.value)                 # the one place the value is used
    rep = Report()
    rep.scan_tree(s.config_dir, c)
    rep.scan_bytes(bytes(s.raw), "pty", c, ansi=True)
    rep.scan_api_log(s.api.log_path, c)
    assert rep.clean(), rep.summary()   # summary lists locations only

Encodings searched for each canary: raw, base64 and url-safe base64 (at all
three byte alignments, so a canary inside a larger encoded blob is found),
hex (lower and upper), URL-encoding (quote, quote_plus, every byte %XX in
both cases), JSON \\u escapes, and UTF-16-LE. Gzip files and gzip/zlib
members are decompressed and searched too. Text from the PTY can also be
searched with ANSI escape sequences removed (a TUI may paint a value one
character at a time between cursor moves).

Canary values are letters and digits by default (safe to type, to put in
JSON, in a shell word and in a URL); `special=True` adds URL-special
characters so the URL-encoded forms differ from the raw one.
"""
from __future__ import annotations

import base64
import gzip
import json
import os
import re
import secrets
import string
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import quote, quote_plus

ANSI = re.compile(rb"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]|[\x00-\x08\x0e-\x1f]")
_ids = iter(range(1, 1 << 30))


class Canary:
    """A synthetic secret whose value never appears in repr/str/format."""

    __slots__ = ("id", "_value", "_needles")

    def __init__(self, value: str, cid: str | None = None):
        if len(value) < 12:
            raise ValueError("a canary needs at least 12 characters")
        self.id = cid or f"canary{next(_ids)}"
        self._value = value
        self._needles: list[tuple[str, bytes]] | None = None

    @classmethod
    def new(cls, label: str = "c", nbytes: int = 16, special: bool = False) -> "Canary":
        """A fresh random canary: `cnry` + random alphanumerics (+ specials)."""
        alphabet = string.ascii_letters + string.digits
        body = "".join(secrets.choice(alphabet) for _ in range(nbytes * 2))
        if special:
            body = body[:8] + "+/=%&? @" + body[8:]
        return cls("cnry" + body, cid=label)

    @property
    def value(self) -> str:
        """The secret itself: pass it to the TUI, never print it."""
        return self._value

    def __len__(self) -> int:
        return len(self._value)

    def __repr__(self) -> str:
        return f"<Canary {self.id} len={len(self._value)}>"

    __str__ = __repr__

    def __format__(self, spec: str) -> str:
        return repr(self)

    def __reduce__(self):  # no pickling of the value into logs
        raise TypeError("canaries are not picklable")

    def part(self, start: int = 0, end: int | None = None, cid: str | None = None) -> "Canary":
        """A canary for a slice (e.g. the half typed before a paste)."""
        return Canary(self._value[start:end], cid or f"{self.id}[{start}:{'' if end is None else end}]")

    def needles(self) -> list[tuple[str, bytes]]:
        """(form name, bytes) for every encoding searched."""
        if self._needles is None:
            self._needles = encodings(self._value.encode("utf-8"))
        return self._needles


def _b64_cores(raw: bytes, enc) -> list[bytes]:
    """Encoded forms of `raw` that stay the same wherever it sits inside a
    larger encoded blob: for each byte alignment, drop the edge characters
    that depend on neighbouring bytes."""
    out = []
    for k in range(3):
        e = enc(b"\0" * k + raw).rstrip(b"=")
        start = 4 if k else 0
        tail = (k + len(raw)) % 3
        stop = len(e) - (1 if tail else 0)
        core = e[start:stop]
        if len(core) >= 8:
            out.append(core)
    return out


def encodings(raw: bytes) -> list[tuple[str, bytes]]:
    text = raw.decode("utf-8", "surrogateescape")
    forms: list[tuple[str, bytes]] = [("raw", raw)]
    forms += [("base64", c) for c in _b64_cores(raw, base64.b64encode)]
    forms += [("base64url", c) for c in _b64_cores(raw, base64.urlsafe_b64encode)]
    forms += [("hex", raw.hex().encode()), ("HEX", raw.hex().upper().encode())]
    forms += [("url", quote(text, safe="").encode()), ("url+", quote_plus(text, safe="").encode()),
              ("url%all", "".join(f"%{b:02x}" for b in raw).encode()),
              ("URL%ALL", "".join(f"%{b:02X}" for b in raw).encode()),
              ("json\\u", "".join(f"\\u{b:04x}" for b in raw).encode()),
              ("json-escaped", json.dumps(text)[1:-1].encode()),
              ("utf16le", text.encode("utf-16-le"))]
    seen, out = set(), []
    for name, b in forms:
        if b and b not in seen:
            seen.add(b)
            out.append((name, b))
    return out


@dataclass
class Hit:
    canary: str      # canary id (never the value)
    form: str        # which encoding matched
    where: str       # file path / label, plus the record or offset kind

    def __str__(self) -> str:
        return f"{self.canary} [{self.form}] in {self.where}"


@dataclass
class Report:
    """Collects hits. Every method returns the hits it added."""

    hits: list[Hit] = field(default_factory=list)
    scanned: dict[str, int] = field(default_factory=dict)

    def _add(self, new: list[Hit], canaries) -> list[Hit]:
        """Record hits with every canary form masked out of their location
        (a path may itself hold a canary)."""
        out = []
        for h in new:
            h = Hit(h.canary, h.form, _mask(h.where, canaries))
            out.append(h)
            if h not in self.hits:
                self.hits.append(h)
        return out

    # -------------------------------------------------------------- bytes
    def scan_bytes(self, data: bytes, where: str, *canaries: Canary, ansi: bool = False) -> list[Hit]:
        """Search one buffer. ansi=True also searches it with escape
        sequences and control characters removed."""
        new: list[Hit] = []
        views = [("", data)]
        if ansi:
            views.append((" (ansi stripped)", ANSI.sub(b"", data)))
        for suffix, buf in views:
            for c in canaries:
                for form, needle in c.needles():
                    if needle in buf:
                        new.append(Hit(c.id, form, where + suffix))
                        break
        for extra_where, extra in _decompressed(data):
            new += self.scan_bytes(extra, f"{where} ({extra_where})", *canaries)
        self.scanned[_mask(where, canaries)] = self.scanned.get(where, 0) + len(data)
        return self._add(new, canaries)

    def scan_text(self, text: str, where: str, *canaries: Canary) -> list[Hit]:
        return self.scan_bytes(text.encode("utf-8", "surrogateescape"), where, *canaries)

    # --------------------------------------------------------------- trees
    def scan_tree(self, root: os.PathLike | str, *canaries: Canary, exclude=(),
                  label: str | None = None, max_bytes: int = 256 << 20) -> list[Hit]:
        """Search every regular file (and every file name) under root.
        Symlinks are not followed. `exclude` holds paths to skip (e.g. the one
        file that is allowed to hold the canary, such as a broker's sealed
        store in a positive control)."""
        root = Path(root)
        label = label or str(root)
        skip = {os.path.realpath(p) for p in exclude}
        new: list[Hit] = []
        for dp, dn, fn in os.walk(root, followlinks=False):
            for name in dn + fn:
                rel = os.path.relpath(os.path.join(dp, name), root)
                for c in canaries:
                    for form, needle in c.needles():
                        if needle in name.encode("utf-8", "surrogateescape"):
                            new.append(Hit(c.id, form, f"{label}/{rel} (name)"))
                            break
            for name in fn:
                p = os.path.join(dp, name)
                if os.path.realpath(p) in skip or os.path.islink(p) or not os.path.isfile(p):
                    continue
                try:
                    size = os.path.getsize(p)
                    if size > max_bytes:
                        new.append(Hit("-", "unscanned", f"{label}/{os.path.relpath(p, root)} "
                                                         f"(too large: {size} bytes)"))
                        continue
                    with open(p, "rb") as f:
                        data = f.read()
                except OSError:
                    continue
                new += self.scan_bytes(data, f"{label}/{os.path.relpath(p, root)}", *canaries)
        return self._add(new, canaries)

    # ---------------------------------------------------------- api log
    def scan_api_log(self, path: os.PathLike | str, *canaries: Canary, label: str = "api") -> list[Hit]:
        """Search the fake API's JSONL request log: the file as stored and,
        per record, the decoded body (JSON strings unescaped) and headers."""
        new = self.scan_bytes(Path(path).read_bytes(), f"{label}:file", *canaries) \
            if os.path.exists(path) else []
        try:
            lines = Path(path).read_bytes().splitlines()
        except OSError:
            lines = []
        for line in lines:
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            tag = f"{label}:seq={rec.get('seq')} {rec.get('method')} {rec.get('path')} kind={rec.get('kind')}"
            if "body_b64" in rec:
                body = base64.b64decode(rec["body_b64"])
            else:
                body = (rec.get("body") or "").encode("utf-8", "surrogateescape")
            new += self.scan_bytes(body, tag + " body", *canaries)
            try:
                strings = list(_json_strings(json.loads(body)))
            except ValueError:
                strings = []
            if strings:
                new += self.scan_text("\n".join(strings), tag + " body (json strings)", *canaries)
            new += self.scan_text(json.dumps(rec.get("headers", {})), tag + " headers", *canaries)
            new += self.scan_text(rec.get("query") or "", tag + " query", *canaries)
        return new

    # ------------------------------------------------------------- results
    def clean(self) -> bool:
        return not [h for h in self.hits if h.form != "unscanned"]

    def locations(self, canary: Canary | None = None) -> list[str]:
        return sorted({str(h) for h in self.hits if canary is None or h.canary == canary.id})

    def summary(self) -> str:
        if self.clean():
            return f"no canary found ({len(self.scanned)} locations scanned)"
        return "canary found in:\n  " + "\n  ".join(self.locations())


def _mask(where: str, canaries) -> str:
    """`where` with every searched form of each canary replaced by <id>."""
    for c in canaries:
        for _form, needle in sorted(c.needles(), key=lambda fn: -len(fn[1])):
            t = needle.decode("utf-8", "replace")
            if t and t in where:
                where = where.replace(t, f"<{c.id}>")
    return where


def _json_strings(v):
    if isinstance(v, str):
        yield v
    elif isinstance(v, dict):
        for k, x in v.items():
            yield k
            yield from _json_strings(x)
    elif isinstance(v, list):
        for x in v:
            yield from _json_strings(x)


def _decompressed(data: bytes):
    """Decompressed views of gzip data or zlib streams inside `data`."""
    out = []
    if data[:2] == b"\x1f\x8b":
        try:
            out.append(("gunzip", gzip.decompress(data)))
        except (OSError, EOFError, zlib.error):
            pass
    elif data[:1] == b"\x78" and len(data) > 2 and (data[0] * 256 + data[1]) % 31 == 0:
        try:
            out.append(("zlib", zlib.decompress(data)))
        except zlib.error:
            pass
    return out


def screen_contains(session, canary: Canary) -> bool:
    """True if the canary (raw) is on the session's screen or scrollback."""
    return canary.value in session.all_text()
