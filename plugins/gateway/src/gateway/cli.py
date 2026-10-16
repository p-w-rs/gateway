"""gateway CLI — a thin human/script entry point to the same policy core.

Subcommands (run as `pixi run --manifest-path …/pixi.toml <task>` or
`python run.py <subcommand>` inside the pixi env):
  server                  Run the MCP stdio server.
  log [N]                 Show the last N audit entries (default 20).
  check <command>         Report whether a shell command would be redirected.
  vault secret|sudo ...   Terminal fallback for the slash commands (hidden prompt).
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
    hit = policy.match_blocked(command)
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
    if sub == "vault":
        return cmd_vault(rest)
    print(__doc__)
    return 0


def cmd_vault(argv: list[str]) -> int:
    """Terminal fallback for /gate:secret and /gate:sudo, for
    machines with no browser (ssh, headless Linux). Same commands; values are
    read at a hidden prompt. Session-only sudo enable isn't possible here (no
    Claude session), so use `sudo enable HOST always`."""
    import getpass

    from . import commands

    if not argv or argv[0] not in ("secret", "sudo"):
        print("usage: vault secret|sudo <command...>   (same as the slash commands)\n")
        print(commands.SECRET_HELP + "\n\n" + commands.SUDO_HELP)
        return 2
    if not sys.stdin.isatty():
        print("vault: run this in an interactive terminal (values are read at a "
              "hidden prompt).", file=sys.stderr)
        return 2

    def prompt(title, details, label, optional):
        print(title)
        for k, v in details:
            if v:
                print(f"  {k}: {v}")
        value = getpass.getpass(f"{label}{' (Enter to keep)' if optional else ''}: ")
        if not optional and not value:
            return None
        if not optional and argv[0] == "sudo":
            if getpass.getpass("Again: ") != value:
                print("They don't match; nothing was saved.")
                return None
        return value

    commands.VALUE_PROVIDER = prompt
    kind, rest = argv[0], " ".join(argv[1:])
    try:
        if kind == "secret":
            print(commands.run_secret(rest))
        else:
            print(commands.run_sudo(rest, session_id=""))
    except (commands.CommandError, commands.LooksLikeValue) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    policy.audit(f"vault_{kind}", commands._log_detail(kind, rest, "ok (terminal)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
