"""The managed remote runtime's artifacts (PLAN-v4 phase 6, docs/modules/remote.md).

The runtime is the workspace in the plugin's `runtime/` folder (bash and
tmux, locked for linux-64, linux-aarch64, osx-arm64 and osx-64; no Python:
FEASIBILITY-v4 P5). For one target platform gated builds, on first need and
into the plugin data folder (never the plugin folder):

    <data>/runtime/<version>/<platform>/
        runtime.tar                 pixi-pack's pack of the default env (the
                                    locked manifest exactly; --use-cache in
                                    <data>/runtime/cache)
        unpacker/bin/pixi-unpack    the TARGET platform's pixi-unpack, taken out
        unpacker/lib/*              of its conda packages here (with openssl's
                                    and libgcc's shared libraries; rpath
                                    ../lib): the `unpacker` env packed with
                                    --directory-only, each .conda opened with
                                    zipfile + the env's zstd + tarfile. A
                                    target's binary is never run here.
        manifest.json               {version, platform, files: [{path, sha256,
                                    size, mode}], built, pixi_pack}

`version` is the first 12 hex digits of sha256(runtime/pixi.lock): a new lock
is a new runtime version (a new remote folder). The sha256 of every file is
recorded at build time and checked again before each use (a file changed
since is rebuilt) and, after staging, on the host (daemon/remote.py).

Stdlib only; external programs by absolute path from the gateway env
(paths.tool): pixi-pack and zstd. A test override (`runtime_artifacts`, a
folder with <platform>/runtime.tar and <platform>/unpacker/...) replaces the
two pixi-pack runs (no network in the suite); everything after them (the
manifest, the hashes, the checks) is the same code.
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import tarfile
import time
import zipfile
from pathlib import Path
from typing import Any

from . import paths, testing

PLATFORMS = ("linux-64", "linux-aarch64", "osx-arm64", "osx-64")
# uname -s, uname -m -> conda subdir
_UNAME = {
    ("Linux", "x86_64"): "linux-64", ("Linux", "amd64"): "linux-64",
    ("Linux", "aarch64"): "linux-aarch64", ("Linux", "arm64"): "linux-aarch64",
    ("Darwin", "arm64"): "osx-arm64", ("Darwin", "x86_64"): "osx-64",
}
SUPPORTED_TEXT = "Linux x86_64 or aarch64 (glibc 2.17 or newer), macOS arm64 or x86_64 (11 or newer)"
BUILD_TIMEOUT = 900.0
LOCK_WAIT = 1200.0
MANIFEST = "manifest.json"
# the shared libraries a pixi-unpack needs sit right under lib/ in its
# packages (openssl, libgcc); only regular files (the SONAME files) are kept
_SHLIB = re.compile(r"lib[A-Za-z0-9_.+-]+\.(?:so(?:\.[0-9]+)*|dylib)")
_SKIP_LIB = re.compile(r"libgomp|libatomic|libitm|libquadmath|libasan|libtsan|liblsan|libubsan")
VERSION_RE = re.compile(r"[0-9a-f]{12}")


class PackError(Exception):
    """The runtime's artifacts can't be built or used: (message, code)."""

    def __init__(self, message: str, code: str = "build"):
        super().__init__(message)
        self.message, self.code = message, code


def platform_of(sysname: str, machine: str) -> str | None:
    """`uname -s` and `uname -m` of a host -> its conda platform, or None
    when the gateway has no runtime for it."""
    return _UNAME.get(((sysname or "").strip(), (machine or "").strip()))


def unsupported_text(sysname: str, machine: str) -> str:
    def safe(s: str) -> str:
        return s if re.fullmatch(r"[A-Za-z0-9_.+-]{1,40}", s or "") else "?"
    return (f"the gateway has no managed runtime for {safe(sysname)} {safe(machine)}: it supports "
            f"{SUPPORTED_TEXT}. Use ssh HOST CMD (no managed terminal or job there), or run the "
            "work on a supported host")


def version() -> str:
    """sha256(runtime/pixi.lock)[:12]; "000000000000" when the lock is missing."""
    try:
        return hashlib.sha256((paths.runtime_src_dir() / "pixi.lock").read_bytes()).hexdigest()[:12]
    except OSError:
        return "0" * 12


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def artifacts_dir(platform: str, ver: str | None = None) -> Path:
    return paths.runtime_data_dir() / (ver or version()) / platform


def _check_platform(platform: str) -> None:
    if platform not in PLATFORMS:
        raise PackError(f"gateway: no runtime for platform {platform!r}", "unsupported")


# ---------------------------------------------------------------------------
# The manifest
# ---------------------------------------------------------------------------


def load_manifest(platform: str, ver: str | None = None) -> dict[str, Any] | None:
    """The manifest of a finished build whose files are all there with the
    recorded size and sha256; None otherwise."""
    d = artifacts_dir(platform, ver)
    try:
        m = json.loads((d / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(m, dict) or m.get("version") != (ver or version()) or \
            m.get("platform") != platform or not isinstance(m.get("files"), list):
        return None
    for f in m["files"]:
        if not isinstance(f, dict) or not _rel_ok(f.get("path")):
            return None
        p = d / f["path"]
        try:
            if p.stat().st_size != f.get("size") or sha256_file(p) != f.get("sha256"):
                return None
        except OSError:
            return None
    return m


def _rel_ok(rel: Any) -> bool:
    """A manifest path: runtime.tar or unpacker/{bin,lib}/NAME, nothing else."""
    return isinstance(rel, str) and (rel == "runtime.tar" or bool(
        re.fullmatch(r"unpacker/(?:bin/pixi-unpack|lib/[A-Za-z0-9_.+-]{1,100})", rel)))


def _write_manifest(d: Path, platform: str, ver: str, tool: str) -> dict[str, Any]:
    files = []
    for p in sorted(d.rglob("*")):
        if p.is_file() and not p.is_symlink() and p.name != MANIFEST:
            rel = p.relative_to(d).as_posix()
            if not _rel_ok(rel):
                raise PackError(f"gateway: an unexpected file in the runtime build ({rel[:80]})")
            mode = 0o755 if rel.startswith("unpacker/bin/") else 0o644
            files.append({"path": rel, "sha256": sha256_file(p), "size": p.stat().st_size,
                          "mode": mode})
    if not any(f["path"] == "runtime.tar" for f in files) or \
            not any(f["path"] == "unpacker/bin/pixi-unpack" for f in files):
        raise PackError("gateway: the runtime build is incomplete (no pack or no pixi-unpack)")
    m = {"version": ver, "platform": platform, "files": files, "built": round(time.time(), 3),
         "pixi_pack": tool}
    tmp = d / f".{MANIFEST}.tmp"
    tmp.write_text(json.dumps(m, indent=1), encoding="utf-8")
    os.replace(tmp, d / MANIFEST)
    return m


def total_size(m: dict[str, Any]) -> int:
    return sum(int(f.get("size") or 0) for f in m.get("files") or [])


# ---------------------------------------------------------------------------
# Building
# ---------------------------------------------------------------------------


def _env() -> dict[str, str]:
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(paths.user_home()),
           "LANG": os.environ.get("LANG") or "C.UTF-8"}
    tmp = os.environ.get("TMPDIR", "")
    if tmp and os.path.isabs(tmp):
        env["TMPDIR"] = tmp
    return env


def _run(argv: list[str], what: str) -> None:
    try:
        r = subprocess.run(argv, capture_output=True, timeout=BUILD_TIMEOUT, env=_env(),
                           stdin=subprocess.DEVNULL, cwd=str(paths.runtime_data_dir()))
    except subprocess.TimeoutExpired:
        raise PackError(f"gateway: {what} took longer than {int(BUILD_TIMEOUT)} s") from None
    except OSError as e:
        raise PackError(f"gateway: {what} couldn't start ({type(e).__name__})") from None
    if r.returncode != 0:
        err = r.stderr.decode("utf-8", "replace")
        net = re.search(r"(?i)error sending request|dns error|connect|timed out|network", err)
        tail = " ".join(err.split())[-240:]
        hint = (" (no network? the first pack of a platform downloads its packages from "
                "conda-forge; later ones use the cache)" if net else "")
        raise PackError(f"gateway: {what} failed{hint}: {tail}")


def _workspace(ver: str) -> Path:
    """A copy of runtime/pixi.toml + pixi.lock in the data folder (pixi-pack
    reads them there: the plugin folder stays untouched)."""
    src = paths.runtime_src_dir()
    ws = paths.runtime_data_dir() / ver / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    for name in ("pixi.toml", "pixi.lock"):
        data = (src / name).read_bytes()
        dst = ws / name
        try:
            if dst.read_bytes() == data:
                continue
        except OSError:
            pass
        tmp = ws / f".{name}.{os.getpid()}"
        tmp.write_bytes(data)
        os.replace(tmp, dst)
    return ws


def extract_unpacker(pack_dir: Path, out: Path, platform: str, zstd: str | None = None) -> list[str]:
    """Take bin/pixi-unpack and the shared libraries next to it (lib/*.so*,
    lib/*.dylib) out of the conda packages of a `--directory-only` pack for
    `platform`. Members are checked (no absolute path, no `..`, regular files
    only). Returns the relative paths written."""
    chans = [pack_dir / "channel" / platform, pack_dir / "channel" / "noarch"]
    pkgs = sorted(p for c in chans if c.is_dir() for p in c.iterdir()
                  if p.name.endswith((".conda", ".tar.bz2")))
    if not pkgs:
        raise PackError("gateway: the unpacker pack holds no packages")
    written: list[str] = []
    for pkg in pkgs:
        for name, data in _package_members(pkg, zstd):
            if name == "bin/pixi-unpack":
                rel, mode = "unpacker/bin/pixi-unpack", 0o755
            elif name.startswith("lib/") and "/" not in name[4:] and _SHLIB.fullmatch(name[4:]) \
                    and not _SKIP_LIB.match(name[4:]):
                rel, mode = "unpacker/" + name, 0o644
            else:
                continue
            dst = out / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
            os.chmod(dst, mode)
            written.append(rel)
    if "unpacker/bin/pixi-unpack" not in written:
        raise PackError("gateway: the target's pixi-unpack wasn't in its package")
    return written


def _package_members(pkg: Path, zstd: str | None) -> list[tuple[str, bytes]]:
    """(name, bytes) of every regular file in a conda package (.conda: a zip
    with pkg-*.tar.zst; .tar.bz2: a tar), checked for unsafe names."""
    if pkg.name.endswith(".tar.bz2"):
        with tarfile.open(pkg, "r:bz2") as t:
            return _tar_files(t)
    with zipfile.ZipFile(pkg) as z:
        inner = [n for n in z.namelist() if n.startswith("pkg-") and n.endswith(".tar.zst")]
        if len(inner) != 1:
            raise PackError(f"gateway: {pkg.name[:80]} isn't a conda package")
        raw = z.read(inner[0])
    tool = zstd or paths.tool("zstd")
    try:
        r = subprocess.run([tool, "-d", "-c", "-q"], input=raw, capture_output=True, timeout=300,
                           env=_env())
    except (OSError, subprocess.TimeoutExpired) as e:
        raise PackError(f"gateway: zstd couldn't open {pkg.name[:80]} ({type(e).__name__})") from None
    if r.returncode != 0:
        raise PackError(f"gateway: zstd couldn't open {pkg.name[:80]}")
    with tarfile.open(fileobj=io.BytesIO(r.stdout), mode="r:") as t:
        return _tar_files(t)


def _tar_files(t: tarfile.TarFile) -> list[tuple[str, bytes]]:
    out = []
    for m in t.getmembers():
        name = m.name
        if name.startswith("/") or ".." in Path(name).parts or "\x00" in name:
            raise PackError("gateway: a package holds an unsafe path")
        if not m.isfile():
            continue
        f = t.extractfile(m)
        if f is not None:
            out.append((name, f.read()))
    return out


def _build(platform: str, ver: str, tmp: Path) -> str:
    """Fill `tmp` with runtime.tar and unpacker/; returns the pixi-pack
    version word."""
    fake = testing.get("runtime_artifacts")
    if isinstance(fake, str) and os.path.isabs(fake) and testing.active() is not None:
        src = Path(fake) / platform
        if not (src / "runtime.tar").is_file():
            raise PackError(f"gateway: no runtime artifacts for {platform} (test)", "unsupported")
        shutil.copyfile(src / "runtime.tar", tmp / "runtime.tar")
        shutil.copytree(src / "unpacker", tmp / "unpacker")
        return "test"
    try:
        pack = paths.tool("pixi-pack")
        zstd = paths.tool("zstd")
    except paths.ToolMissing:
        raise PackError("gateway: the gateway env has no pixi-pack yet (it is still being set up, "
                        "or it predates the remote runtime); a new session sets it up") from None
    ws = _workspace(ver)
    cache = paths.runtime_data_dir() / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    _run([pack, str(ws / "pixi.toml"), "-e", "default", "-p", platform, "-o",
          str(tmp / "runtime.tar"), "--use-cache", str(cache), "-q"],
         f"packing the runtime for {platform}")
    unp = tmp / "unpacker-pack"
    _run([pack, str(ws / "pixi.toml"), "-e", "unpacker", "-p", platform, "--directory-only",
          "-o", str(unp), "--use-cache", str(cache), "-q"], f"packing pixi-unpack for {platform}")
    extract_unpacker(unp, tmp, platform, zstd)
    shutil.rmtree(unp, ignore_errors=True)
    try:
        v = subprocess.run([pack, "--version"], capture_output=True, text=True, timeout=30,
                           env=_env(), stdin=subprocess.DEVNULL).stdout.split()
        return v[-1] if v else "?"
    except (OSError, subprocess.TimeoutExpired):
        return "?"


@contextlib.contextmanager
def _flock(path: Path, wait: float):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    try:
        end = time.monotonic() + wait
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= end:
                    raise PackError("gateway: another build of the runtime is still running; try "
                                    "again in a minute") from None
                time.sleep(0.2)
        yield
    finally:
        os.close(fd)


def ensure(platform: str) -> dict[str, Any]:
    """The finished, verified artifacts for `platform` (built on first need;
    a build whose files changed since is built again). Raises PackError."""
    _check_platform(platform)
    ver = version()
    m = load_manifest(platform, ver)
    if m is not None:
        return m
    root = paths.runtime_data_dir() / ver
    root.mkdir(parents=True, exist_ok=True)
    with _flock(root / f".{platform}.lock", LOCK_WAIT):
        m = load_manifest(platform, ver)
        if m is not None:
            return m
        tmp = root / f".build-{platform}-{os.getpid()}-{secrets.token_hex(3)}"
        tmp.mkdir(mode=0o700)
        try:
            tool = _build(platform, ver, tmp)
            _write_manifest(tmp, platform, ver, tool)
            final = root / platform
            old = None
            if final.exists():
                old = root / f".old-{platform}-{secrets.token_hex(3)}"
                os.replace(final, old)
            os.replace(tmp, final)
            if old is not None:
                shutil.rmtree(old, ignore_errors=True)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        m = load_manifest(platform, ver)
        if m is None:
            raise PackError("gateway: the runtime build didn't verify after it was written")
        return m


def prune_versions(keep: str | None = None) -> list[str]:
    """Remove the data folder's builds of other runtime versions (a plugin
    update brings a new lock); the package cache stays. Returns what went."""
    keep = keep or version()
    gone = []
    base = paths.runtime_data_dir()
    with contextlib.suppress(OSError):
        for d in base.iterdir():
            if d.is_dir() and VERSION_RE.fullmatch(d.name) and d.name != keep:
                shutil.rmtree(d, ignore_errors=True)
                gone.append(d.name)
    return gone
