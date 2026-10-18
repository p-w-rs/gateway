"""gateway CLI — a thin human/script entry point to the same policy core.

Subcommands (run as `pixi run --manifest-path …/pixi.toml <task>` or
`python run.py <subcommand>` inside the pixi env):
  server                  Run the MCP stdio server.
  log [N]                 Show the last N audit entries (default 20).
  check <command>         Report whether a shell command would be redirected.
  gateway finish GRANT    Finish a setup, export or import Claude prepared where no
                          dialog could open (hidden prompt).
"""
from __future__ import annotations

import json
import sys

from . import policy


def cmd_log(argv: list[str]) -> int:
    n = int(argv[0]) if argv else 20
    path = policy.audit_log_path()
    if not path.exists():
        print("No audit log yet.")
        return 0
    lines = path.read_text().splitlines()[-n:]
    for line in lines:
        try:
            r = json.loads(line)
            d = r.get("detail", {})
            event = r.get("event", "")
            if event.startswith("vault_") and "command" in d:
                where = " ".join(x for x in (d.get("command"), d.get("target")) if x)
                extra = d.get("outcome", "")
            elif event == "run_privileged":
                where = f"{d.get('host', '')}: {d.get('command', '')}"
                extra = f"{d.get('approval', '')}, exit {d.get('exit_code')}"
            elif event == "refused":
                where = d.get("host") or d.get("action") or ""
                extra = (d.get("reason") or "")[:80]
            elif event in ("http_request", "download", "cert_inspect"):
                where = d.get("url") or d.get("host") or ""
                if d.get("ok") is False:
                    extra = "failed: " + (d.get("error") or "no reason recorded")[:80]
                elif d.get("status") is not None:
                    extra = str(d["status"])
                else:
                    extra = "ok" if d.get("ok") else ""
            else:
                where = (d.get("url") or d.get("host") or d.get("target")
                         or d.get("path") or d.get("tool") or d.get("ref") or "")
                extra = ""
            line_out = f"{r.get('ts','')}  {event:16}  {where}"
            print(f"{line_out}  [{extra}]" if extra else line_out)
        except Exception:
            print(line)
    return 0


def cmd_check(argv: list[str]) -> int:
    command = " ".join(argv)
    hit = policy.match_blocked(command) or policy.match_takeover(command)
    if hit:
        name, route = hit
        print(f"REDIRECT: '{name}' -> use {route}")
        return 1
    print("OK: command is not redirected.")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv:
        print(__doc__)
        return 0
    sub, rest = argv[0], argv[1:]
    if sub == "server":
        from . import mcp_server
        mcp_server.main()
        return 0
    if sub == "log":
        return cmd_log(rest)
    if sub == "check":
        return cmd_check(rest)
    if sub == "gateway" and rest[:1] == ["finish"]:
        return cmd_finish(rest[1:])
    if sub in ("vault", "gateway"):
        print("The v0.5 terminal commands (vault secret|sudo|account) are retired. Add or "
              "change things by typing /gate:add, /gate:update, /gate:delete, /gate:enable or "
              "/gate:disable in Claude Code; where no dialog can open, Claude gives you a "
              "`gateway finish GRANT` command to run here.")
        return 2
    print(__doc__)
    return 0


def cmd_finish(argv: list[str]) -> int:
    """`gateway finish GRANT`: finish a setup Claude prepared on a machine where
    no dialog could open. Shows the change, asks y/N, reads any secret hidden."""
    import getpass

    from . import setup
    if len(argv) != 1:
        print("usage: gateway finish GRANT   (the id Claude gave you, e.g. g-1a2b3c4d)")
        return 2
    if not sys.stdin.isatty():
        print("gateway: run this in an interactive terminal.", file=sys.stderr)
        return 2

    def confirm(summary: str) -> bool:
        print(summary)
        return input("Allow? [y/N] ").strip().lower() in ("y", "yes")

    def secret(label: str) -> str | None:
        v = getpass.getpass(f"{label}: ")
        return v if v else None

    try:
        print(setup.finish(argv[0], confirm, secret))
        return 0
    except setup.SetupError as e:
        print(f"gateway: {e}", file=sys.stderr)
        return 1
