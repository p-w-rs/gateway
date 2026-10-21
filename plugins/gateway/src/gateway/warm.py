"""Load a freshly built pixi env once, in the async SessionStart hook (SPEC 7,
18): `launch.sh ensure-env` runs `main()` with the env's python right after
the build (and once for an env built before this existed), then marks the
env with `.warm`.

Why: macOS checks every new executable and library the first time it is
loaded (the env has a few dozen: python, its extension modules, libssl,
libcrypto, libffi, age). Without this, the first sync SessionStart on a new
env paid all of it: 5-6 s on an idle machine, 5-13 s in the e2e suite's
first sessions, and once past Claude Code's 20 s limit for the hook (while
a second plugin's fresh env loaded too). Loaded here, the next session's
hooks start warm (about 0.1 s).

It imports every gateway module (gateway.daemon's too) and the standard modules they import
inside functions, and runs `age --version` and `ssh -V` from this python's
own folder. It resolves no gateway location and starts nothing else, so
production and tests run it alike.
"""
from __future__ import annotations

import importlib
import os
import pkgutil
import subprocess
import sys
from pathlib import Path

# Imported inside functions by gateway modules (not at their top).
LATER = ("hashlib", "pty", "tempfile", "uuid", "ctypes.util", "socket", "select", "threading")
# Binaries the hooks run (the vault's age) and the first ssh command runs.
TOOLS = (("age", "--version"), ("ssh", "-V"))


def main() -> int:
    import gateway
    for m in pkgutil.walk_packages(gateway.__path__, "gateway."):   # the daemon's package too
        try:
            importlib.import_module(m.name)
        except Exception:  # noqa: BLE001 - warming only; the hooks report real errors
            pass
    for name in LATER:
        try:
            importlib.import_module(name)
        except Exception:  # noqa: BLE001
            pass
    here = Path(sys.executable).parent
    for name, arg in TOOLS:
        exe = here / name
        if not (exe.is_file() and os.access(exe, os.X_OK)):
            continue
        try:
            subprocess.run([str(exe), arg], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin"}, timeout=60)
        except (OSError, subprocess.SubprocessError):
            pass
    return 0
