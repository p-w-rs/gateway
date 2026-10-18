"""gateway CLI — a thin human/script entry point to the same policy core.

Subcommands (run as `pixi run --manifest-path …/pixi.toml <task>` or
`python run.py <subcommand>` inside the pixi env):
  server                  Run the MCP stdio server.
  log [N]                 Show the last N audit entries (default 20).
  check <command>         Report whether a shell command would be redirected.
  vault secret|sudo|account ...
                          Terminal fallback for the slash commands (hidden prompt).
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
        return cmd_vault(rest)
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


def cmd_vault(argv: list[str]) -> int:
    """Terminal fallback for /gate:secret and /gate:sudo, for
    machines with no browser (ssh, headless Linux). Same commands; values are
    read at a hidden prompt. Session-only sudo enable isn't possible here (no
    Claude session), so use `sudo enable HOST always`."""
    import getpass

    from . import commands

    if not argv or argv[0] not in ("secret", "sudo", "account"):
        print("usage: vault secret|sudo|account <command...>   (same as the slash commands)\n")
        print(commands.SECRET_HELP + "\n\n" + commands.SUDO_HELP + "\n\n"
              + commands.ACCOUNT_HELP)
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

    def fields(title, details, specs):
        """The account form, one field at a time. A pasted key can't be typed
        at a hidden prompt, so 'paste' asks for the path of a key file."""
        print(title)
        for k, v in details:
            if v:
                print(f"  {k}: {v}")
        got = {}
        for f in specs:
            kind, label = f.get("type", "text"), f["label"]
            if kind == "password":
                got[f["name"]] = getpass.getpass(f"{label} (hidden; Enter to skip): ")
            elif kind == "select":
                opts = f["options"]
                for i, (_, text) in enumerate(opts, 1):
                    print(f"  {i}. {text}")
                pick = input(f"{label} [1]: ").strip() or "1"
                if not pick.isdigit() or not 1 <= int(pick) <= len(opts):
                    print("Not one of the choices; nothing was saved.")
                    return None
                got[f["name"]] = opts[int(pick) - 1][0]
            elif kind == "textarea":
                if got.get("ssh_key_mode") != "paste":
                    got[f["name"]] = ""
                    continue
                path = input("Path of the private key file to store: ").strip()
                try:
                    from pathlib import Path
                    got[f["name"]] = Path(path).expanduser().read_text()
                except OSError as e:
                    print(f"Could not read it ({e}); nothing was saved.")
                    return None
            else:
                shown = f" [{f['value']}]" if f.get("value") else ""
                got[f["name"]] = input(f"{label}{shown}: ").strip() or f.get("value", "")
            if f.get("required") and not got[f["name"]]:
                print(f"{label} is required; nothing was saved.")
                return None
        return got

    def show_code(code, url):
        print(f"Open {url} (on any device), enter the code {code}, approve, and finish any "
              "SSO step. Waiting...")

    commands.VALUE_PROVIDER = prompt
    commands.FIELDS_PROVIDER = fields
    commands.LOGIN_SHOW = show_code
    kind, rest = argv[0], " ".join(argv[1:])
    try:
        if kind == "secret":
            print(commands.run_secret(rest))
        elif kind == "sudo":
            print(commands.run_sudo(rest, session_id=""))
        else:
            print(commands.run_account(rest))
    except (commands.CommandError, commands.LooksLikeValue) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    policy.audit(f"vault_{kind}", commands._log_detail(kind, rest, "ok (terminal)"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
