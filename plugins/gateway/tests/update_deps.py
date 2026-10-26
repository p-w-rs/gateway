#!/usr/bin/env python3
"""Relock to the newest packages: the per-release relock step (PLAN-0.11
section 5, "latest only"; there is no CI). Run from plugins/gateway:

    pixi run update-deps [--no-install] [--no-test]

Every dependency in pixi.toml and runtime/pixi.toml is "*", so a relock is
conda-forge's newest of everything. In order, this script:

1. checks that the running pixi is the newest conda-forge has for this
   platform (`pixi search`), and stops otherwise: requires-pixi follows the
   pixi that made the lock;
2. asks crates.io for pijul's newest release, pre-releases included (pijul
   has only betas, and a plain `cargo install` skips them);
3. sets requires-pixi (pixi.toml), PIXI_TESTED (hooks/mod/lib.ts) and the
   `requires-pixi = ">=..."` the docs quote (DOCS; test_packaging checks
   them against PIXI_TESTED) to that pixi, and the pijul task's `cargo
   install --version` to pijul's newest;
4. runs `pixi update` on pixi.toml;
5. pins runtime/pixi.toml's pixi-unpack to the new lock's pixi-pack (they
   ship from one repository; test_packaging compares them on every
   platform), then runs `pixi update` on runtime/pixi.toml;
6. prints what moved, reinstalls the default env (`pixi install --locked`)
   and runs the suite (`pixi run --locked test`).

All or nothing: when a step fails (a refusal, pixi, the network, a file),
every file it touched gets its old bytes back. The two pixi.lock files and
the edited lines are the whole change; review the printed list and the
suite's result before committing. The pure parts (lock parsing, the diff,
the edits, version order) are tested in tests/test_update_deps.py, and whole
runs against a fake pixi on a scratch copy of the repo.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import urllib.request
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[1]
MANIFEST = PLUGIN / "pixi.toml"
LOCK = PLUGIN / "pixi.lock"
RUNTIME = PLUGIN / "runtime" / "pixi.toml"
RUNTIME_LOCK = PLUGIN / "runtime" / "pixi.lock"
LIB_TS = PLUGIN / "hooks" / "mod" / "lib.ts"
REPO = PLUGIN.parents[1]
# the docs that quote the manifest's requires-pixi, relative to the repo
DOCS = ("README.md", "docs/CAPABILITIES.md", "CLAUDE.md")
# crates.io's list of pijul's versions (tests point it at a file:// URL)
CRATES = os.environ.get("GW_UPDATE_DEPS_CRATES") or "https://crates.io/api/v1/crates/pijul/versions"

REQUIRES_RE = re.compile(r'^requires-pixi = "[^"\n]*"$', re.M)
TESTED_RE = re.compile(r"^export const PIXI_TESTED = '[^'\n]*'$", re.M)
UNPACK_RE = re.compile(r'^pixi-unpack = "[^"\n]*"', re.M)
PIJUL_RE = re.compile(r"(cargo install pijul --version )(\S+)( --locked)")
DOC_RE = re.compile(r'requires-pixi = ">=([^"\n]*)"')


class Stop(Exception):
    """A step can't go on; the message says why and what to do."""


# ---------------------------------------------------------------------------
# Versions
# ---------------------------------------------------------------------------


def version_key(v: str) -> tuple:
    """Order of semver-like versions, pre-releases included: 1.0.0-beta.2 <
    1.0.0-beta.10 < 1.0.0 < 1.0.1. Numeric parts compare as numbers (a
    letter suffix after them, as in conda-forge's tmux 3.5a or 3.8_, orders
    after the bare number), a release sorts after its own pre-releases."""
    core, _, pre = v.strip().lstrip("v").partition("-")
    nums = []
    for x in core.split("+")[0].split("."):
        m = re.match(r"(\d*)(.*)", x)
        nums.append((int(m.group(1)) if m.group(1) else 0, m.group(2)))
    nums += [(0, "")] * (3 - len(nums))
    nums = tuple(nums)
    if not pre:
        return (nums, 1, ())
    parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in pre.split("."))
    return (nums, 0, parts)


def newest(versions: list[str]) -> str:
    if not versions:
        raise Stop("gateway: no versions to choose from")
    return max(versions, key=version_key)


def parse_pixi_version(text: str) -> str:
    """`pixi --version` -> "0.83.0"."""
    m = re.search(r"(\d+\.\d+\.\d+)", text)
    if m is None:
        raise Stop(f"gateway: can't read pixi's version from {text.strip()[:80]!r}")
    return m.group(1)


def conda_platform() -> str:
    s, m = platform.system(), platform.machine()
    table = {("Darwin", "arm64"): "osx-arm64", ("Darwin", "x86_64"): "osx-64",
             ("Linux", "x86_64"): "linux-64", ("Linux", "aarch64"): "linux-aarch64",
             ("Linux", "arm64"): "linux-aarch64"}
    if (s, m) not in table:
        raise Stop(f"gateway: no conda platform for {s} {m}")
    return table[(s, m)]


def newest_from_search(text: str, plat: str) -> str:
    """The newest version in `pixi search --json -p PLATFORM NAME`'s answer."""
    d = json.loads(text)
    recs = d.get(plat, []) if isinstance(d, dict) else d
    return newest([r["version"] for r in recs if isinstance(r, dict) and "version" in r])


def newest_crate(text: str) -> str:
    """The newest non-yanked version in crates.io's versions answer."""
    d = json.loads(text)
    return newest([v["num"] for v in d.get("versions", []) if not v.get("yanked")])


# ---------------------------------------------------------------------------
# Lock files
# ---------------------------------------------------------------------------


def _name_version(kind: str, url: str) -> tuple[str, str]:
    fn = url.rstrip("/").rsplit("/", 1)[-1]
    if kind == "conda":
        for ext in (".conda", ".tar.bz2"):
            if fn.endswith(ext):
                fn = fn[: -len(ext)]
        parts = fn.rsplit("-", 2)
        if len(parts) == 3:
            return parts[0], parts[1]
        return fn, ""
    # pypi: a wheel (name-version-...) or an sdist (name-version.tar.gz)
    m = re.match(r"([A-Za-z0-9_.]+?)-(\d[^-]*?)(?:-|\.tar\.gz$|\.zip$)", fn)
    if m:
        return "pypi:" + m.group(1).lower().replace("_", "-"), m.group(2)
    return "pypi:" + fn, ""


def lock_packages(text: str) -> dict[str, dict[str, dict[str, str]]]:
    """{environment: {platform: {package: version}}} of a pixi.lock (format
    v6/v7: `environments:` -> NAME -> `packages:` -> PLATFORM -> `- conda: URL`)."""
    out: dict[str, dict[str, dict[str, str]]] = {}
    in_envs = False
    env = key = plat = None
    for line in text.splitlines():
        if not line.strip():
            continue
        if not line.startswith(" "):
            in_envs = line.rstrip() == "environments:"
            env = key = plat = None
            continue
        if not in_envs:
            continue
        ind = len(line) - len(line.lstrip(" "))
        s = line.strip()
        if ind == 2 and s.endswith(":"):
            env, key, plat = s[:-1], None, None
            out.setdefault(env, {})
        elif ind == 4 and env is not None and not s.startswith("- "):
            key, plat = s.split(":", 1)[0], None
        elif ind == 6 and env is not None and key == "packages" and s.endswith(":"):
            plat = s[:-1]
            out[env].setdefault(plat, {})
        elif ind == 6 and plat is not None and key == "packages" and s.startswith("- "):
            kind, _, url = s[2:].partition(": ")
            name, ver = _name_version(kind.strip(), url.strip())
            out[env][plat][name] = ver
    return out


def lock_version(pkgs: dict, env: str, name: str) -> str:
    """The one version of NAME in ENV on every platform of the lock (Stop
    when it is missing on one or differs between them)."""
    plats = pkgs.get(env, {})
    found = {p: v.get(name) for p, v in plats.items()}
    vers = set(found.values())
    if not plats or None in vers or len(vers) != 1:
        raise Stop(f"gateway: {name} isn't one version on every platform of {env}: {found}")
    return vers.pop()


def _fmt(by_plat: dict[str, str] | None) -> str:
    if not by_plat:
        return ""
    vers: dict[str, list[str]] = {}
    for p, v in sorted(by_plat.items()):
        vers.setdefault(v, []).append(p)
    if len(vers) == 1:
        return next(iter(vers))
    return " / ".join(f"{v} ({', '.join(ps)})" for v, ps in sorted(vers.items(), key=lambda x: version_key(x[0])))


def moved(old: dict, new: dict, label: str = "") -> list[str]:
    """One line per package whose version moved, appeared or went, by
    environment: `[label ]ENV: NAME OLD -> NEW`."""
    out = []
    for env in sorted(set(old) | set(new)):
        def by_name(pk: dict) -> dict[str, dict[str, str]]:
            d: dict[str, dict[str, str]] = {}
            for plat, names in pk.get(env, {}).items():
                for n, v in names.items():
                    d.setdefault(n, {})[plat] = v
            return d
        o, n = by_name(old), by_name(new)
        for name in sorted(set(o) | set(n)):
            a, b = _fmt(o.get(name)), _fmt(n.get(name))
            if a != b:
                out.append(f"{label}{env}: {name} {a or '(new)'} -> {b or '(gone)'}")
    return out


# ---------------------------------------------------------------------------
# Edits (each replaces exactly one line, or stops)
# ---------------------------------------------------------------------------


def _sub1(rx: re.Pattern, repl, text: str, what: str) -> str:
    new, n = rx.subn(repl, text)
    if n != 1:
        raise Stop(f"gateway: expected one {what} line, found {n}")
    return new


def set_requires_pixi(toml: str, version: str) -> str:
    return _sub1(REQUIRES_RE, f'requires-pixi = ">={version}"', toml, "requires-pixi")


def set_pixi_tested(ts: str, version: str) -> str:
    return _sub1(TESTED_RE, f"export const PIXI_TESTED = '{version}'", ts, "PIXI_TESTED")


def set_doc_pixi(doc: str, version: str) -> str:
    return _sub1(DOC_RE, f'requires-pixi = ">={version}"', doc, 'requires-pixi = ">=..."')


def doc_pixi(doc: str) -> list[str]:
    """Every requires-pixi version a doc quotes (one, when it is right)."""
    return [m.group(1) for m in DOC_RE.finditer(doc)]


def set_pixi_unpack(toml: str, version: str) -> str:
    return _sub1(UNPACK_RE, f'pixi-unpack = "=={version}"', toml, "pixi-unpack")


def set_pijul(toml: str, version: str) -> str:
    return _sub1(PIJUL_RE, lambda m: m.group(1) + version + m.group(3), toml, "pijul cargo install")


def pijul_version(toml: str) -> str:
    m = PIJUL_RE.search(toml)
    if m is None:
        raise Stop("gateway: no pijul cargo install line in pixi.toml")
    return m.group(2)


# ---------------------------------------------------------------------------
# The run
# ---------------------------------------------------------------------------


def _run(argv: list[str]) -> str:
    print("+ " + " ".join(argv), flush=True)
    r = subprocess.run(argv, capture_output=True, text=True, cwd=PLUGIN)
    if r.returncode != 0:
        raise Stop(f"gateway: {argv[1]} failed ({r.returncode}):\n{r.stdout}{r.stderr}")
    return r.stdout


def _fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "gateway update-deps"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return resp.read().decode()


def _write(p: Path, old: str, new: str) -> None:
    if new != old:
        p.write_text(new)


def _restore(saved: dict[Path, bytes]) -> None:
    """Every file the run touched back to the bytes it had before."""
    for p, data in saved.items():
        try:
            if p.read_bytes() == data:
                continue
        except OSError:
            pass
        p.write_bytes(data)


def main(argv: list[str]) -> int:
    install, test = "--no-install" not in argv, "--no-test" not in argv
    pixi = os.environ.get("PIXI_EXE") or shutil.which("pixi")
    if not pixi:
        print("gateway: pixi not found", file=sys.stderr)
        return 1
    docs = [REPO / d for d in DOCS]
    saved: dict[Path, bytes] = {}
    try:
        running = parse_pixi_version(_run([pixi, "--version"]))
        plat = conda_platform()
        top = newest_from_search(_run([pixi, "search", "--json", "-p", plat, "pixi"]), plat)
        if version_key(running) < version_key(top):
            raise Stop(f"gateway: this is pixi {running}, conda-forge has {top}: update pixi first "
                       "(pixi self-update), then run update-deps again")
        pj = newest_crate(_fetch(CRATES))
        saved = {p: p.read_bytes() for p in (MANIFEST, LOCK, RUNTIME, RUNTIME_LOCK, LIB_TS, *docs)}
        old = {p: b.decode() for p, b in saved.items()}
        # every one-line edit in memory first: a line that isn't there stops the run before a write
        new = {MANIFEST: set_pijul(set_requires_pixi(old[MANIFEST], running), pj),
               LIB_TS: set_pixi_tested(old[LIB_TS], running),
               **{d: set_doc_pixi(old[d], running) for d in docs}}
        for p, text in new.items():
            _write(p, old[p], text)
        _run([pixi, "update", "--manifest-path", str(MANIFEST)])
        pack = lock_version(lock_packages(LOCK.read_text()), "default", "pixi-pack")
        _write(RUNTIME, old[RUNTIME], set_pixi_unpack(old[RUNTIME], pack))
        _run([pixi, "update", "--manifest-path", str(RUNTIME)])
    except BaseException as e:
        _restore(saved)
        if not isinstance(e, (Stop, OSError, ValueError, KeyError)):
            raise
        print(str(e) if isinstance(e, Stop) else f"gateway: update-deps stopped: {type(e).__name__}: {e}",
              file=sys.stderr)
        if saved:
            print("gateway: every file update-deps touched has its old bytes back", file=sys.stderr)
        return 1
    lines = moved(lock_packages(old[LOCK]), lock_packages(LOCK.read_text()), "pixi.lock ")
    lines += moved(lock_packages(old[RUNTIME_LOCK]), lock_packages(RUNTIME_LOCK.read_text()), "runtime/pixi.lock ")
    for what, p, rx in (("requires-pixi", MANIFEST, REQUIRES_RE), ("lib.ts PIXI_TESTED", LIB_TS, TESTED_RE),
                        ("runtime pixi-unpack", RUNTIME, UNPACK_RE),
                        *((f"{d.relative_to(REPO)} quotes", d, DOC_RE) for d in docs)):
        ma, mb = rx.search(old[p]), rx.search(p.read_text())
        if ma and mb and ma.group(0) != mb.group(0):
            lines.append(f"{what}: {ma.group(0)} -> {mb.group(0)}")
    if pijul_version(old[MANIFEST]) != pj:
        lines.append(f"pijul (cargo): {pijul_version(old[MANIFEST])} -> {pj}")
    print(f"\nWhat moved ({len(lines)}):" if lines else "\nNothing moved.")
    for line in lines:
        print("  " + line)
    sys.stdout.flush()
    if install:
        try:
            _run([pixi, "install", "--locked", "--manifest-path", str(MANIFEST)])
        except Stop as e:
            print(str(e), file=sys.stderr)
            return 1
    if test:
        # a new process: the env this script started from may have just been replaced
        os.execv(pixi, [pixi, "run", "--locked", "--manifest-path", str(MANIFEST), "test"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
