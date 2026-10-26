"""Fixtures for the posture tests (PLAN-0.11 §1, "ungated unless configured"):
a folder of the user's own tools as recording fakes (tests/fakes/
fake_user_tool.py) for the `user_tools` test knob, a way to run a stand-in
in a child process the way its stub does (so a pass-through really execs),
and a capture of an in-process pass-through.

The fakes never run a real ssh, sudo, gh, ...; `ssh -G` answers from the
folder's ssh_g.json, never from ~/.ssh/config.
"""
from __future__ import annotations

import contextlib
import json
import os
import subprocess
from pathlib import Path
from typing import Any, Iterator

import harness as H

FAKE = H.TESTS / "fakes" / "fake_user_tool.py"


def user_tools(env: H.GatewayEnv, *names: str, ssh_g: dict[str, dict[str, str]] | None = None,
               exit_code: int = 0, folder: str = "user-tools") -> Path:
    """A folder of recording fakes named `names` (each runs fake_user_tool.py
    with its own name), set as the `user_tools` knob of env's override."""
    d = env.root / folder
    d.mkdir(parents=True, exist_ok=True)
    for n in names:
        p = d / n
        p.write_text("#!/bin/sh\n"
                     f'GW_FAKE_ARGV0="$0"; GW_FAKE_USER_DIR={str(d)!r}; '
                     "export GW_FAKE_ARGV0 GW_FAKE_USER_DIR\n"
                     f"exec {H.PY!r} -I {str(FAKE)!r} {n!r} \"$@\"\n")
        os.chmod(p, 0o755)
    if ssh_g is not None:
        (d / "ssh_g.json").write_text(json.dumps(ssh_g))
    if exit_code:
        (d / "exit").write_text(str(exit_code))
    env.o.extra["user_tools"] = str(d)
    return d


def runs(folder: Path, tool: str | None = None, *, with_g: bool = False) -> list[dict[str, Any]]:
    """The fakes' recorded runs (without `ssh -G` lookups unless with_g)."""
    try:
        lines = (folder / "log.jsonl").read_text().splitlines()
    except FileNotFoundError:
        return []
    out = [json.loads(x) for x in lines if x.strip()]
    if not with_g:
        out = [r for r in out if not (r["tool"] == "ssh" and "-G" in r["argv"])]
    return [r for r in out if tool is None or r["tool"] == tool]


class PassedThrough(Exception):
    """envfile._execve was called: the stand-in handed over to the user's own
    tool (path, argv, env)."""

    def __init__(self, path: str, argv: list[str], env: dict[str, str]):
        super().__init__(path)
        self.path, self.argv, self.env = path, list(argv), dict(env)


@contextlib.contextmanager
def capture_passthrough() -> Iterator[list[PassedThrough]]:
    """Run a stand-in in-process: a pass-through raises PassedThrough instead
    of replacing the test process (envfile._execve is the one exec)."""
    from gateway import envfile
    seen: list[PassedThrough] = []

    def fake(path: str, argv: list[str], env: dict[str, str]) -> None:
        e = PassedThrough(path, argv, env)
        seen.append(e)
        raise e
    old = envfile._execve
    envfile._execve = fake
    try:
        yield seen
    finally:
        envfile._execve = old


_DRIVER = (f"import sys\nsys.pycache_prefix = {H.PYC!r}\n"
           f"sys.path.insert(0, {str(H.PLUGIN / 'src')!r})\nsys.path.insert(0, {str(H.PLUGIN)!r})\n"
           """
import json, os
from gateway import testing
import run
root, knobs, tool = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3]
with testing.override(root, **knobs):
    raise SystemExit(run.run_shim(tool, sys.argv[4:]))
""")


def run_standin(env: H.GatewayEnv, tool: str, *args: str, cwd: str | Path | None = None,
                extra_env: dict[str, str] | None = None, knobs: dict[str, Any] | None = None,
                timeout: float = 60) -> subprocess.CompletedProcess[str]:
    """`run.py shim TOOL ARGS` in a child, under env's override (and the
    user_tools knob set by user_tools()), as a stub runs it: a pass-through
    execs the fake. The child's environment: env.subprocess_env without
    GATEWAY_TEST_ROOT (the shim mode refuses it), plus extra_env."""
    d = env.root / "drivers"
    d.mkdir(exist_ok=True)
    drv = d / "posture_driver.py"
    if not drv.exists():
        drv.write_text(_DRIVER)
    k = {"user_tools": env.o.extra.get("user_tools"), "machine_id": env.o.machine_id,
         "local_user": env.o.local_user, **(knobs or {})}
    k = {a: b for a, b in k.items() if b is not None}
    e = env.subprocess_env(extra_env)
    e.pop("GATEWAY_TEST_ROOT", None)
    return subprocess.run([H.PY, "-I", *H.PYX, str(drv), str(env.root), json.dumps(k), tool,
                           *args], capture_output=True, text=True, env=e,
                          cwd=str(cwd or env.root), timeout=timeout)
