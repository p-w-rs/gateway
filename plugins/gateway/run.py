#!/usr/bin/env python3
"""Single entry point for every gateway mode (run with -I -S by the stubs
and hooks/launch.sh; it puts its own src/ on sys.path).

    run.py hook-session | hook-session-async | hook-subagent      SessionStart / SubagentStart
    run.py hook-bash | hook-files | hook-post | hook-prompt | hook-filechanged
    run.py mcp                                                    MCP stdio server
    run.py shim TOOL ARGS...                                      a stand-in (sudo, ssh, gh, ...)
    run.py askpass                                                gate-askpass (sudo -A)
    run.py git-credential get|store|erase                         git-credential-gateway
    run.py gate ARGS...                                           the gate CLI
    run.py gated serve [--detach] | start [--register] | status | stop   the gateway daemon
    run.py hook-daemon                                            async SessionStart: start gated,
                                                                  register the session
    run.py managed-sync                                           renew the managed shell's files
                                                                  (hooks/gate-sh, when gateway.toml
                                                                  is newer than its settings)

Hook modes read the hook's JSON on stdin and print the hook's JSON answer.
Failure policy: hook-files fails closed (exit 2, the hook has onFailure:
block); hook-prompt blocks the prompt; the others fail open (no output).

`--test` (first or second argument, and only for hook, MCP and gated modes)
makes them honour GATEWAY_TEST_ROOT (testing.from_env). Production never
passes it.
Fail closed: if GATEWAY_TEST_ROOT is set but this invocation isn't a valid
`--test` one (a misplaced flag, a stand-in), run.py exits 2 before resolving
any path, so a test can never reach the real ~/.config/gateway by mistake.

Data folder: hook and MCP modes take CLAUDE_PLUGIN_DATA (Claude Code sets
it); every other mode runs inside Claude's Bash and derives it from the
python that runs it (paths.data_dir).

The e2e suite's copy of the plugin (in a temp folder, with an `e2e-root`
marker next to this file) runs every mode with all locations inside the e2e
root (paths.e2e_marker, tests/e2e/README.md); without a valid marker nothing
changes.
"""
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

HOOKS = {
    "hook-session": ("hooks_session", "session_hook", "session"),
    "hook-session-async": ("hooks_session", "async_main", "open"),
    "hook-subagent": ("hooks_session", "subagent_main", "open"),
    "hook-bash": ("hooks_bash", "main", "open"),
    "hook-files": ("hooks_files", "main", "closed"),
    "hook-post": ("hooks_post", "main", "open"),
    "hook-prompt": ("hooks_prompt", "main", "block"),
    "hook-filechanged": ("hooks_filechanged", "main", "open"),
    "hook-daemon": ("hooks_session", "daemon_main", "open"),
}
TEST_MODES = set(HOOKS) | {"mcp", "gated"}
SHIMS = ("sudo", "ssh", "scp", "sftp", "gh", "hf", "databricks", "crane", "pijul", "asiml",
         "az", "dvc", "gate")


def _payload() -> dict:
    try:
        data = sys.stdin.read()
        p = json.loads(data) if data.strip() else {}
        return p if isinstance(p, dict) else {}
    except (ValueError, OSError):
        return {}


def run_hook(mode: str) -> int:
    import importlib
    modname, fn, policy = HOOKS[mode]
    payload = _payload()
    try:
        mod = importlib.import_module(f"gateway.{modname}")
        out = getattr(mod, fn)(payload)
    except Exception as e:  # noqa: BLE001
        if policy == "closed":
            print(f"gateway: the file guard failed ({type(e).__name__}); blocked to be safe",
                  file=sys.stderr)
            return 2
        if policy == "block":
            out = {"decision": "block",
                   "reason": f"gateway: couldn't check this prompt ({type(e).__name__}); it "
                             "wasn't sent. Try again, or run ~/.config/gateway/gate status."}
        elif policy == "session":
            from gateway import hooks_session
            out = hooks_session.degraded_output(e)
        else:
            return 0
    if out is not None:
        sys.stdout.write(json.dumps(out) + "\n")
    return 0


def _ensure_migrated(trigger: str) -> None:
    """SPEC 4: any v3 process may be the first; a stand-in or the MCP server
    migrates too (two stat calls when there is nothing to do)."""
    try:
        from gateway import paths
        if not paths.v2_store_path().is_file() or paths.vault_path().exists():
            return  # the common case: nothing to migrate, no extra imports
        from gateway import migrate
        r = migrate.ensure(trigger)
    except Exception as e:  # noqa: BLE001
        print(f"gateway: migration check failed ({type(e).__name__})", file=sys.stderr)
        return
    if r is not None:
        print(("gateway: " + r.message) if not r.ok
              else f"{r.message} (gate status --report shows what changed)", file=sys.stderr)


# Dropped from the environment of the gate CLI (it runs in Claude's Bash and
# verifies tokens the user just typed): a proxy or a CA Claude chose must
# never see them. gate_setup's own client ignores both already; this is the
# second layer. `gate with` keeps them: its child inherits the environment
# (SPEC 9.7).
GATE_ENV_DROP = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy",
                 "https_proxy", "all_proxy", "no_proxy", "SSL_CERT_FILE", "SSL_CERT_DIR")


def _gate_env(args: list) -> None:
    if args[:1] != ["with"]:
        for k in GATE_ENV_DROP:
            os.environ.pop(k, None)


def _vault_locked(tool: str) -> str | None:
    """A wrapped vault key the gateway daemon holds locked (or can't reach):
    the refusal to print before the tool runs (its rights are in the vault
    too), else None. The first scoped read is kept for this process."""
    try:
        from gateway import vault
        if not vault.brokered() or not vault.exists():
            return None
        vault.load()
    except Exception as e:  # noqa: BLE001
        from gateway import vault
        if not isinstance(e, vault.VaultLocked):
            return None
        try:
            from gateway import audit
            audit.refusal(tool, "vault", "the vault is locked")
        except Exception:  # noqa: BLE001
            pass
        return str(e)
    return None


def run_shim(tool: str, args: list) -> int:
    if tool != "gate":
        _ensure_migrated(f"shim {tool}")
        locked = _vault_locked(tool)
        if locked:
            print(locked, file=sys.stderr)
            return 1
    try:
        if tool in ("ssh", "scp", "sftp"):
            from gateway import ssh
            return int(ssh.main(tool, args) or 0)
        if tool == "sudo":
            from gateway import sudo
            return int(sudo.main(args) or 0)
        if tool in ("gh", "hf", "databricks", "crane", "pijul", "az"):
            from gateway import clis
            return int(clis.main(tool, args) or 0)
        if tool == "asiml":
            from gateway import asiml
            return int(asiml.main(args) or 0)
        if tool == "dvc":
            from gateway import asiml
            return int(asiml.dvc_main(args) or 0)
        if tool == "gate":
            from gateway import gate
            _gate_env(args)
            return int(gate.main(args) or 0)
    except NotImplementedError:
        # Interim (until the phase-B stand-in exists): refuse. Never fall back to
        # the system tool: it would use the user's own keys, agent and logins,
        # which others = "refuse" keeps away from Claude.
        print(f"gateway: {tool} isn't available in this build yet (the gateway's {tool} "
              "stand-in comes in a later update); tell the user once and carry on",
              file=sys.stderr)
        return 75
    except (SystemExit, KeyboardInterrupt):
        raise                              # exit codes (popup.StillOpen: 75) pass through
    except Exception as e:  # noqa: BLE001
        return _failed(tool, e)
    print(f"gateway: unknown stand-in {tool}", file=sys.stderr)
    return 2


def _failed(tool: str, e: BaseException) -> int:
    """One gateway line for an unexpected error, never a traceback: a stand-in
    may hold a credential, and a traceback's locals and messages could show
    it (or a path or value Claude then repeats)."""
    print(f"gateway: {tool} failed unexpectedly ({type(e).__name__}); try again, or run gate "
          "status", file=sys.stderr)
    try:
        from gateway import audit
        audit.log("error", tool=tool, error=type(e).__name__)
    except Exception:  # noqa: BLE001
        pass
    return 1


def dispatch(mode: str, args: list) -> int:
    from gateway import paths
    # Only Claude Code's own hook and MCP launches may name the data folder
    # through the environment (CLAUDE_PLUGIN_DATA); the daemon derives it from
    # its python, like the stand-ins.
    paths.trust_plugin_env(mode in HOOKS or mode == "mcp")
    paths.ENTRY_MODE = f"shim {args[0]}" if mode == "shim" and args else mode
    if mode in HOOKS:
        return run_hook(mode)
    if mode == "mcp":
        _ensure_migrated("mcp")
        from gateway import mcp_server
        mcp_server.main()
        return 0
    if mode == "shim" and args and args[0] in SHIMS:
        return run_shim(args[0], args[1:])
    if mode == "askpass":
        from gateway import sudo
        try:
            return int(sudo.askpass_main() or 0)
        except NotImplementedError:
            return 1
    if mode == "gated":
        from gateway.daemon import lifecycle
        return int(lifecycle.main(args) or 0)
    if mode == "managed-sync":
        from gateway import managed
        try:
            return int(managed.sync_now() or 0)
        except Exception as e:  # noqa: BLE001
            return _failed("managed-sync", e)
    if mode == "git-credential":
        from gateway import githelper
        try:
            return int(githelper.credential_main(args) or 0)
        except NotImplementedError:
            return 0
    if mode == "gate":
        from gateway import gate
        _gate_env(args)
        try:
            return int(gate.main(args) or 0)
        except (SystemExit, KeyboardInterrupt):
            raise
        except Exception as e:  # noqa: BLE001
            return _failed("gate", e)
    print(__doc__, file=sys.stderr)
    return 2


def parse_test_flag(argv: list) -> tuple[bool, list]:
    """(test, argv without the flag). --test counts only as the first or second
    argument; anywhere else it is an ordinary argument of the mode."""
    argv = list(argv)
    if argv[:1] == ["--test"]:
        return True, argv[1:]
    if argv[1:2] == ["--test"]:
        del argv[1]
        return True, argv
    return False, argv


def main(argv: list | None = None) -> int:
    test, argv = parse_test_flag(sys.argv[1:] if argv is None else argv)
    mode = argv[0] if argv else ""
    if test and mode not in TEST_MODES:
        print("gateway: --test is only for hook, MCP and gated entry points", file=sys.stderr)
        return 2
    if not test and os.environ.get("GATEWAY_TEST_ROOT"):
        print("gateway: GATEWAY_TEST_ROOT is set but this isn't a `run.py --test` hook or MCP "
              "call; refusing so the real gateway home is never used by a test", file=sys.stderr)
        return 2
    from gateway import paths, testing
    # e2e_context: only in a scratch copy of the plugin under a temp folder
    # that carries a valid e2e-root marker (paths.e2e_marker); a no-op
    # otherwise, and under --test (the test override comes first).
    with testing.from_env(test), paths.e2e_context():
        return dispatch(mode, argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
