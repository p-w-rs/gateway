"""TUI acceptance harness for Claude Code plugins (test infrastructure only).

Drives the real interactive `claude` in a PTY against a local fake Messages
API, installs plugins through a hermetic git-source marketplace into scratch
Claude configs, records what a nosy third-party mod could observe, and scans
everything for synthetic canaries. See README.md in this folder.

Modules: safety (guards, hermetic env), fakeapi (fake API server + client),
driver (PTY session), install (snapshots, git server, `claude plugin`),
gwe2e (the gateway's e2e route and the session guard), scan (canaries),
observe (observer plugin helpers), gitserve (git server process), proxy (the
record-only telemetry proxy, mitmproxy through `pixi exec`). The newest
Python (`pixi exec --spec python`), stdlib + pyte. The same folder is kept
identical in the gateway and checkpoint repositories (tests/tui/).
"""
from . import safety  # noqa: F401

__all__ = ["safety", "fakeapi", "driver", "install", "gwe2e", "scan", "observe", "proxy"]
HARNESS_VERSION = "1.2.0"
