"""The per-release relock (tests/update_deps.py, PLAN-0.11 section 5): lock
parsing, the "what moved" list, the one-line edits, version order (pijul's
betas included), and whole runs against a fake pixi on a scratch copy of the
repo's files it edits, the docs included (no network: crates.io's answer
comes from a file): a relock, an older pixi, and runs that stop half way
(every file put back)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import harness as H
import update_deps as U


def _lock(envs: dict[str, dict[str, list[str]]]) -> str:
    """A pixi.lock (format v7) with these environments: {env: {platform: [filename]}}."""
    out = ["version: 7", "platforms:", "- name: linux-64", "environments:"]
    for env, plats in envs.items():
        out += [f"  {env}:", "    channels:", "    - url: https://conda.anaconda.org/conda-forge/",
                "    options:", "      pypi-prerelease-mode: if-necessary-or-explicit", "    packages:"]
        for plat, files in plats.items():
            out.append(f"      {plat}:")
            for f in files:
                if f.endswith(".whl"):
                    out.append(f"      - pypi: https://files.pythonhosted.org/packages/xx/{f}")
                else:
                    out.append(f"      - conda: https://conda.anaconda.org/conda-forge/{plat}/{f}")
    out += ["packages:", "- conda: https://conda.anaconda.org/conda-forge/linux-64/python-9.9.9-h_0.conda",
            "  sha256: 00"]
    return "\n".join(out) + "\n"


def test_versions_order_semver_with_prereleases_and_conda_suffixes():
    assert U.newest(["1.0.0-beta.9", "1.0.0-beta.10", "1.0.0-alpha.3", "0.12.2"]) == "1.0.0-beta.10"
    assert U.newest(["1.0.0-beta.24", "1.0.0", "1.0.0-rc.1"]) == "1.0.0", "a release after its pre-releases"
    assert U.newest(["0.82.1", "0.83.0", "0.9.0", "0.83"]) == "0.83.0"
    assert U.newest(["3.5", "3.5a", "3.8_", "3.10"]) == "3.10"
    assert U.version_key("3.8_") > U.version_key("3.5a") > U.version_key("3.5")
    assert U.parse_pixi_version("pixi 0.83.0\n") == "0.83.0"
    crates = json.dumps({"versions": [{"num": "1.0.0-beta.24", "yanked": False},
                                      {"num": "1.0.0-beta.25", "yanked": False},
                                      {"num": "2.0.0", "yanked": True}]})
    assert U.newest_crate(crates) == "1.0.0-beta.25", "yanked versions never count"
    search = json.dumps({"osx-arm64": [{"version": "0.82.1"}, {"version": "0.83.0"}, {"version": "0.9.0"}]})
    assert U.newest_from_search(search, "osx-arm64") == "0.83.0"


def test_lock_packages_reads_each_environment_and_platform():
    text = _lock({
        "default": {"linux-64": ["python-3.15.1-h1_cp315.conda", "git-lfs-3.8.1-h2_0.conda",
                                 "_openmp_mutex-4.5-20_gnu.tar.bz2"],
                    "osx-arm64": ["python-3.15.1-h3_cp315.conda", "git-lfs-3.8.1-h4_0.conda"]},
        "hf": {"linux-64": ["python-3.14.2-h5_cp314.conda", "huggingface_hub-2.3.0-pyhd_0.conda",
                            "hf_xet-1.2.0-py3-none-any.whl"]},
    })
    p = U.lock_packages(text)
    assert p["default"]["linux-64"] == {"python": "3.15.1", "git-lfs": "3.8.1", "_openmp_mutex": "4.5"}
    assert p["default"]["osx-arm64"] == {"python": "3.15.1", "git-lfs": "3.8.1"}
    assert p["hf"]["linux-64"] == {"python": "3.14.2", "huggingface_hub": "2.3.0", "pypi:hf-xet": "1.2.0"}
    assert set(p) == {"default", "hf"}, "the top-level packages: list is not an environment"
    assert U.lock_version(p, "default", "python") == "3.15.1"
    for env_name, name in (("default", "huggingface_hub"), ("nowhere", "python")):
        try:
            U.lock_version(p, env_name, name)
        except U.Stop:
            pass
        else:
            raise AssertionError(f"lock_version accepted {name} missing from {env_name}")
    split = U.lock_packages(_lock({"default": {"linux-64": ["pixi-pack-0.7.12-h_0.conda"],
                                               "osx-64": ["pixi-pack-0.7.11-h_0.conda"]}}))
    try:
        U.lock_version(split, "default", "pixi-pack")
    except U.Stop as e:
        assert "isn't one version on every platform" in str(e)
    else:
        raise AssertionError("two versions across platforms were accepted")


def test_moved_lists_what_changed_appeared_or_went_by_environment():
    old = U.lock_packages(_lock({"default": {"linux-64": ["python-3.12.15-h_0.conda", "libnsl-2.0.1-h_0.conda",
                                                          "age-1.3.2-h_0.conda", "harfbuzz-14.6.0-h_0.conda"],
                                             "osx-64": ["python-3.12.15-h_0.conda", "age-1.3.2-h_0.conda",
                                                        "harfbuzz-14.6.0-h_0.conda"]}}))
    new = U.lock_packages(_lock({"default": {"linux-64": ["python-3.15.1-h_0.conda", "libmpdec-4.0.0-h_0.conda",
                                                          "age-1.3.2-h_0.conda", "harfbuzz-15.0.0-h_0.conda"],
                                             "osx-64": ["python-3.15.1-h_0.conda", "age-1.3.2-h_0.conda",
                                                        "harfbuzz-14.6.0-h_0.conda"]}}))
    assert U.moved(old, new, "pixi.lock ") == [
        "pixi.lock default: harfbuzz 14.6.0 -> 14.6.0 (osx-64) / 15.0.0 (linux-64)",
        "pixi.lock default: libmpdec (new) -> 4.0.0",
        "pixi.lock default: libnsl 2.0.1 -> (gone)",
        "pixi.lock default: python 3.12.15 -> 3.15.1",
    ]
    assert U.moved(new, new) == []


def test_the_edits_replace_exactly_one_line_or_stop():
    toml = (H.PLUGIN / "pixi.toml").read_text()
    ts = (H.PLUGIN / "hooks" / "mod" / "lib.ts").read_text()
    rt = (H.PLUGIN / "runtime" / "pixi.toml").read_text()
    t2 = U.set_requires_pixi(toml, "9.9.9")
    assert 'requires-pixi = ">=9.9.9"' in t2 and len(t2.splitlines()) == len(toml.splitlines())
    assert "export const PIXI_TESTED = '9.9.9'" in U.set_pixi_tested(ts, "9.9.9")
    assert 'pixi-unpack = "==9.9.9"' in U.set_pixi_unpack(rt, "9.9.9")
    t3 = U.set_pijul(toml, "1.0.0-beta.99")
    assert U.pijul_version(t3) == "1.0.0-beta.99" and "--version 1.0.0-beta.99 --locked" in t3
    doc = "The newest pixi. `pixi.toml` says\n  `requires-pixi = \">=0.83.0\"`, the pixi it was locked with.\n"
    d2 = U.set_doc_pixi(doc, "9.9.9")
    assert U.doc_pixi(d2) == ["9.9.9"] and d2 == doc.replace("0.83.0", "9.9.9")
    for fn, text in ((U.set_requires_pixi, "nothing here\n"),
                     (U.set_requires_pixi, 'requires-pixi = ">=1"\nrequires-pixi = ">=2"\n'),
                     (U.set_pixi_tested, "export const PIXI_TESTED_MAX = '1'\n"),
                     (U.set_pixi_unpack, "# pixi-unpack = \"1\"\n"),
                     (U.set_doc_pixi, "the pixi it was locked with, no requires line\n"),
                     (U.set_doc_pixi, doc + doc)):
        try:
            fn(text, "1.2.3")
        except U.Stop as e:
            assert "expected one" in str(e)
        else:
            raise AssertionError(f"{fn.__name__} edited {text!r}")


# ---------------------------------------------------------------------------
# A whole run against a fake pixi
# ---------------------------------------------------------------------------

# The runtime relock records the pixi-unpack pin it saw (it must already be
# the new pixi-pack's), and fails when FAKE_FAIL_RT is set (after the main
# lock was rewritten: a run that stops there must put that back too).
FAKE_PIXI = r"""#!/bin/sh
printf '%s\n' "$*" >> "$FAKE_LOG"
case $1 in
  --version) echo "pixi $FAKE_VERSION" ;;
  search) printf '{"%s": [{"version": "0.82.1"}, {"version": "%s"}, {"version": "0.9.0"}]}\n' "$4" "$FAKE_NEWEST" ;;
  update)
    case $3 in
      */runtime/pixi.toml)
        sed -n 's/^\(pixi-unpack = "[^"]*"\).*/\1/p' "$3" > "$FAKE_LOG.pin"
        [ -z "${FAKE_FAIL_RT-}" ] || { echo "error: the solve failed" >&2; exit 1; }
        cp "$FAKE_RT_LOCK" "${3%/pixi.toml}/pixi.lock" ;;
      *) cp "$FAKE_LOCK" "${3%/pixi.toml}/pixi.lock" ;;
    esac ;;
  install) ;;
  run) echo "the suite ran" ;;
esac
"""


def _scratch(root: Path) -> Path:
    """A scratch repo (root/repo) with the plugin's files update-deps edits,
    at an older relock, and the docs that quote requires-pixi (the real ones
    when this checkout has them; a mutation's scratch copy is the plugin
    alone)."""
    repo = root / "repo"
    plugin = repo / "plugins" / "gateway"
    for rel in ("pixi.toml", "runtime/pixi.toml", "hooks/mod/lib.ts", "tests/update_deps.py"):
        (plugin / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(H.PLUGIN / rel, plugin / rel)
    for rel in U.DOCS:
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        real = H.REPO / rel
        text = real.read_text() if real.is_file() else f'{rel}\n`requires-pixi = ">=0.1.0"`, no upper bound.\n'
        (repo / rel).write_text(U.set_doc_pixi(text, "0.70.0"))
    t = (plugin / "pixi.toml").read_text()
    (plugin / "pixi.toml").write_text(U.set_pijul(U.set_requires_pixi(t, "0.70.0"), "1.0.0-beta.1"))
    ts = (plugin / "hooks/mod/lib.ts").read_text()
    (plugin / "hooks/mod/lib.ts").write_text(U.set_pixi_tested(ts, "0.70.0"))
    rt = (plugin / "runtime/pixi.toml").read_text()
    (plugin / "runtime/pixi.toml").write_text(U.set_pixi_unpack(rt, "0.7.1"))
    plats = ("linux-64", "linux-aarch64", "osx-64", "osx-arm64")
    (plugin / "pixi.lock").write_text(_lock({"default": {p: ["python-3.12.15-h_0.conda",
                                                             "pixi-pack-0.7.1-h_0.conda"] for p in plats}}))
    (plugin / "runtime/pixi.lock").write_text(_lock({"default": {p: ["tmux-3.5a-h_0.conda"] for p in plats},
                                                     "unpacker": {p: ["pixi-unpack-0.7.1-h_0.conda"] for p in plats}}))
    (root / "new.lock").write_text(_lock({"default": {p: ["python-3.15.1-h_0.conda",
                                                          "pixi-pack-0.7.12-h_0.conda"] for p in plats}}))
    (root / "new-rt.lock").write_text(_lock({"default": {p: ["tmux-3.8_-h_0.conda"] for p in plats},
                                             "unpacker": {p: ["pixi-unpack-0.7.12-h_0.conda"] for p in plats}}))
    (root / "crates.json").write_text(json.dumps({"versions": [
        {"num": "1.0.0-beta.10", "yanked": False}, {"num": "1.0.0-beta.9", "yanked": False},
        {"num": "1.0.0", "yanked": True}]}))
    fake = root / "pixi"
    fake.write_text(FAKE_PIXI)
    fake.chmod(0o755)
    return plugin


def _run(root: Path, plugin: Path, version: str, newest: str, **extra: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, PIXI_EXE=str(root / "pixi"), FAKE_LOG=str(root / "log"),
               FAKE_VERSION=version, FAKE_NEWEST=newest, FAKE_LOCK=str(root / "new.lock"),
               FAKE_RT_LOCK=str(root / "new-rt.lock"),
               GW_UPDATE_DEPS_CRATES=(root / "crates.json").as_uri())
    env.update(extra)
    return subprocess.run([sys.executable, *H.PYX, str(plugin / "tests" / "update_deps.py")],
                          capture_output=True, text=True, env=env, timeout=60)


def _files(repo: Path) -> dict[Path, bytes]:
    return {p: p.read_bytes() for p in repo.rglob("*") if p.is_file()}


def _calls(root: Path) -> list[str]:
    return [c.split()[0] for c in (root / "log").read_text().splitlines()]


def test_a_run_relocks_both_manifests_pins_and_prints_what_moved():
    with H.gateway_env() as env:
        root = env.root / "relock"
        plugin = _scratch(root)
        repo = plugin.parents[1]
        r = _run(root, plugin, "0.83.0", "0.83.0")
        assert r.returncode == 0, r.stdout + r.stderr
        calls = (root / "log").read_text().splitlines()
        assert _calls(root) == ["--version", "search", "update", "update", "install", "run"], calls
        assert calls[2] == f"update --manifest-path {plugin / 'pixi.toml'}"
        assert calls[3] == f"update --manifest-path {plugin / 'runtime' / 'pixi.toml'}"
        assert calls[4].startswith("install --locked") and calls[5].endswith(" test"), calls
        assert (root / "log.pin").read_text() == 'pixi-unpack = "==0.7.12"\n', \
            "the runtime is relocked with pixi-unpack already pinned to the new pixi-pack"
        toml = (plugin / "pixi.toml").read_text()
        assert 'requires-pixi = ">=0.83.0"' in toml, "requires-pixi follows the running (newest) pixi"
        assert "export const PIXI_TESTED = '0.83.0'" in (plugin / "hooks/mod/lib.ts").read_text()
        assert 'pixi-unpack = "==0.7.12"' in (plugin / "runtime/pixi.toml").read_text(), \
            "pixi-unpack follows the new lock's pixi-pack"
        assert U.pijul_version(toml) == "1.0.0-beta.10", "pijul's newest beta, the yanked release skipped"
        for rel in U.DOCS:      # test_packaging's docs check holds after every relock
            assert U.doc_pixi((repo / rel).read_text()) == ["0.83.0"], rel
        out = r.stdout
        for line in ("pixi.lock default: python 3.12.15 -> 3.15.1",
                     "pixi.lock default: pixi-pack 0.7.1 -> 0.7.12",
                     "runtime/pixi.lock default: tmux 3.5a -> 3.8_",
                     "runtime/pixi.lock unpacker: pixi-unpack 0.7.1 -> 0.7.12",
                     'requires-pixi: requires-pixi = ">=0.70.0" -> requires-pixi = ">=0.83.0"',
                     "lib.ts PIXI_TESTED: export const PIXI_TESTED = '0.70.0' -> export const PIXI_TESTED = '0.83.0'",
                     'runtime pixi-unpack: pixi-unpack = "==0.7.1" -> pixi-unpack = "==0.7.12"',
                     *(f'{rel} quotes: requires-pixi = ">=0.70.0" -> requires-pixi = ">=0.83.0"' for rel in U.DOCS),
                     "pijul (cargo): 1.0.0-beta.1 -> 1.0.0-beta.10"):
            assert "  " + line + "\n" in out, (line, out)
        assert "the suite ran" in out


def test_a_run_with_an_older_pixi_changes_nothing():
    with H.gateway_env() as env:
        root = env.root / "relock"
        plugin = _scratch(root)
        before = _files(root / "repo")
        r = _run(root, plugin, "0.82.1", "0.83.0")
        assert r.returncode == 1, r.stdout + r.stderr
        assert "this is pixi 0.82.1, conda-forge has 0.83.0: update pixi first (pixi self-update)" in r.stderr
        assert _files(root / "repo") == before
        assert _calls(root) == ["--version", "search"]


def test_a_run_that_stops_half_way_puts_every_file_back():
    """All or nothing: crates.io unreachable, the runtime's relock failing
    after the main lock was rewritten, or a doc that no longer quotes
    requires-pixi each end the run with a message (no traceback) and every
    file as it was."""
    with H.gateway_env() as env:
        root = env.root / "relock"
        plugin = _scratch(root)
        repo = root / "repo"
        before = _files(repo)
        gone = (root / "no-such-answer.json").as_uri()
        r = _run(root, plugin, "0.83.0", "0.83.0", GW_UPDATE_DEPS_CRATES=gone)
        assert r.returncode == 1 and "Traceback" not in r.stderr, r.stderr
        assert "gateway: update-deps stopped: URLError" in r.stderr, r.stderr
        assert _files(repo) == before and _calls(root) == ["--version", "search"]

        (root / "log").unlink()
        r = _run(root, plugin, "0.83.0", "0.83.0", FAKE_FAIL_RT="1")
        assert r.returncode == 1 and "Traceback" not in r.stderr, r.stderr
        assert "gateway: update failed (1)" in r.stderr and "error: the solve failed" in r.stderr, r.stderr
        assert "every file update-deps touched has its old bytes back" in r.stderr, r.stderr
        assert _calls(root) == ["--version", "search", "update", "update"]
        changed = sorted(str(p.relative_to(repo)) for p in before if p.read_bytes() != before[p])
        assert not changed, changed

        (root / "log").unlink()
        doc = repo / U.DOCS[-1]
        doc.write_text(doc.read_text().replace("requires-pixi = ", "requires pixi "))
        before = _files(repo)
        r = _run(root, plugin, "0.83.0", "0.83.0")
        assert r.returncode == 1 and "Traceback" not in r.stderr, r.stderr
        assert "expected one requires-pixi" in r.stderr, r.stderr
        assert _files(repo) == before and _calls(root) == ["--version", "search"], \
            "the one-line edits are checked before anything is written or relocked"
