#!/usr/bin/env python3
"""Single entry point for every gateway mode.

Putting src/ on sys.path here means the package imports work the same whether
Claude Code launches the MCP server, a hook, or the CLI. Invoked as:
    python run.py server        # MCP stdio server (.mcp.json)
    python run.py hook-route     # PreToolUse(Bash) hook
    python run.py hook-session   # SessionStart hook
    python run.py hook-prompt    # UserPromptSubmit hook (the /gate: commands)
    python run.py scrub PATH...  # internal: scrub typed values from transcripts
    python run.py log [N]        # show recent audit entries
    python run.py check <cmd>    # test whether a command would redirect
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))


def main() -> int:
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode == "server":
        from gateway import mcp_server
        mcp_server.main()
        return 0
    if mode == "hook-route":
        from gateway import hooks
        return hooks.route_main()
    if mode == "hook-files":
        from gateway import hooks
        return hooks.files_main()
    if mode == "hook-session":
        from gateway import hooks
        return hooks.session_main()
    if mode == "hook-prompt":
        from gateway import hooks
        return hooks.prompt_main()
    if mode == "scrub":
        from gateway import common
        return common.scrub_main(sys.argv[2:])
    from gateway import cli
    return cli.main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
