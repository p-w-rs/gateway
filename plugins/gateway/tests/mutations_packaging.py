#!/usr/bin/env python3
"""Mutation checks for packaging (PLAN-v4 phase 1): locked installs, the
build lock's liveness, the cold window's Bash guard, bytecode kept out of the
plugin folder, the release check and the mod. Same format and runner as
tests/mutation_check.py: each mutation removes or weakens one property; the
named test must then FAIL.

    pixi run --locked python tests/mutations_packaging.py [-k SUBSTR] [--copy DIR]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutation_check  # noqa: E402

L = "hooks/launch.sh"
T = "test_packaging::"

# (name, file, old, new, test selector "module::substring")
MUTATIONS = [
    # --- locked resolution ---------------------------------------------------
    ("the launcher installs with --frozen", L,
     '    "$P" install --locked --manifest-path "$ENVD/pixi.toml" > "$ENVD/install.log" 2>&1 &\n',
     '    "$P" install --frozen --manifest-path "$ENVD/pixi.toml" > "$ENVD/install.log" 2>&1 &\n',
     "test_envfile::test_ensure_env_builds_with_pixi_and_cleans_old_envs"),
    ("optional tools install with --frozen", "src/gateway/clis.py",
     'r = subprocess.run([pixi, "install", "--locked", "--manifest-path", str(manifest),',
     'r = subprocess.run([pixi, "install", "--frozen", "--manifest-path", str(manifest),',
     T + "test_shipped_installs_use_locked_never_frozen"),
    ("requires-pixi gets an upper bound", "pixi.toml",
     '# says "update pixi: pixi self-update".\nrequires-pixi = ">=',
     '# says "update pixi: pixi self-update".\nrequires-pixi = "<99,>=',
     T + "test_requires_pixi_is_the_tested_pixi_with_no_upper_bound"),
    # --- build lock liveness -------------------------------------------------
    ("a dead builder keeps the lock (no liveness check)", L,
     '  gw_alive "$_pid" "$_start" && return 0\n',
     '  return 0\n',
     T + "test_a_reused_pid_does_not_keep_the_lock"),
    ("a reused pid counts as the builder (no start time check)", L,
     '  [ -z "$2" ] || [ "$GW_START" = "$2" ]          # else the pid was reused\n',
     '  return 0\n',
     T + "test_a_reused_pid_does_not_keep_the_lock"),
    ("a zombie builder counts as alive", L,
     "  case $GW_PS in Z*|' 'Z*) return 1 ;; esac      # a zombie: dead, not reaped yet\n",
     "",
     T + "test_a_zombie_builder_is_dead_and_an_orphaned_pixi_keeps_the_lock"),
    ("an orphaned pixi child doesn't hold the lock", L,
     '  [ -n "$_child" ] && gw_alive "$_child" "$_cstart" && return 0\n',
     "",
     T + "test_a_zombie_builder_is_dead_and_an_orphaned_pixi_keeps_the_lock"),
    ("the builder records no pixi child", L,
     '    gw_owner "$cpid"\n',
     "",
     T + "test_build_lock_records_the_builder_and_its_pixi_child"),
    ("a waiter never takes over from a dead builder", L,
     "    if ! lock_live; then                         # the builder died: take over\n",
     "    if false; then\n",
     T + "test_a_waiting_build_takes_over_when_the_builder_dies"),
    ("a SIGTERMed build leaves its pixi running", L,
     """  trap 'trap - EXIT; [ -n "$cpid" ] && kill "$cpid" 2>/dev/null; exit 143' HUP INT TERM\n""",
     """  trap 'trap - EXIT; exit 143' HUP INT TERM\n""",
     T + "test_a_terminated_build_stops_its_pixi"),
    ("a stale lock still reads as a running build", L,
     '  [ -f "$ENVD/install.log" ] && [ ! -e "$ENVD/.ready" ] && ! lock_live\n',
     '  [ -f "$ENVD/install.log" ] && [ ! -e "$ENVD/.ready" ] && [ ! -d "$LOCKD" ]\n',
     T + "test_a_killed_build_is_stale_at_once"),
    ("build lock: the machine is the network hostname again (drifts)", L,
     '  if [ -n "$_host" ] && [ "$_host" != "$(gw_hostid)" ]; then\n',
     '  if [ -n "$_host" ] && [ "$_host" != "$(uname -n 2>/dev/null)" ]; then\n',
     T + "test_build_lock_identifies_the_machine_by_a_stable_id"),
    ("build lock: the owner records the network hostname", L,
     '    printf \'pid=%s\\nstart=%s\\nhost=%s\\n\' "$$" "$_me" "$(gw_hostid)"\n',
     '    printf \'pid=%s\\nstart=%s\\nhost=%s\\n\' "$$" "$_me" "$(uname -n 2>/dev/null)"\n',
     T + "test_build_lock_identifies_the_machine_by_a_stable_id"),
    # --- the cold window's Bash guard ----------------------------------------
    ("the cold Bash hook gives no decision again", L,
     "  hook-bash) GW_PAYLOAD=$(cat); degraded_bash ;;\n",
     "",
     T + "test_cold_bash_guard_outputs_are_byte_identical"),
    ("cold guard: private folder reads pass", L,
     '  if printf \'%s\' "$_np" | grep -Eq -- "$DEG_PRIVATE" ||\n',
     "  if false ||\n",
     T + "test_cold_bash_guard_denies_private"),
    ("cold guard: a glob after .config/ passes", L,
     '     printf \'%s\' "$_np" | grep -Eq -- "$DEG_PRIVATE_GLOB" ||\n',
     "     false ||\n",
     T + "test_cold_bash_guard_denies_private"),
    ("cold guard: .config named with the gateway word passes", L,
     '       { printf \'%s\' "$_np" | grep -Eq -- "$DEG_GATEWORD" ||\n',
     "       { false ||\n",
     T + "test_cold_bash_guard_denies_private"),
    ("cold guard: .config named with a recursive reader passes", L,
     '         printf \'%s\' "$_np" | grep -Eq -- "$DEG_TREE"; }; }; then\n',
     "         false; }; }; then\n",
     T + "test_cold_bash_guard_denies_private"),
    ("cold guard: the .config parent rule passes", L,
     '     { printf \'%s\' "$_np" | grep -Eq -- "$DEG_CONFIG" &&\n',
     "     { false &&\n",
     T + "test_cold_bash_guard_denies_private"),
    ("cold guard: quotes and backslashes hide the gateway path", L,
     '  _dq=$(printf \'%s\' "$_lt" | tr -d "\\"\'\\\\\\\\")\n',
     "  _dq=$_lt\n",
     T + "test_cold_bash_guard_denies_private"),
    ("cold guard: gateway.toml is refused too", L,
     "  _np=$(printf '%s' \"$_dq\" | sed 's#\\.config/gateway/gateway\\.toml##g')\n",
     "  _np=$_dq\n",
     T + "test_cold_bash_guard_leaves_everything_else"),
    # --- the cold window's file guard: session transcripts -------------------
    ("cold file guard: Read of a session transcript passes", L,
     '  [ -n "$deny" ] || for k in file_path notebook_path path; do\n'
     '    if field_transcript "$(json_str "$k" "$lower")" "$cwd"; then deny=transcript; fi\n'
     "  done\n",
     "",
     "test_envfile::test_launch_degraded_file_guard_denies_transcripts"),
    ("cold file guard: Grep over the transcripts folder passes", L,
     '        if above_protected "$np"; then deny=parent\n'
     '        elif above_transcripts "$np"; then deny=transcript_search; fi ;;\n',
     '        if above_protected "$np"; then deny=parent; fi ;;\n',
     "test_envfile::test_launch_degraded_file_guard_denies_transcripts"),
    ("cold file guard: a Workflow journal is refused as a transcript", L,
     "    */subagents/workflows/*/journal.jsonl) return 1 ;;\n",
     "",
     "test_envfile::test_launch_degraded_file_guard_denies_transcripts"),
    ("cold guard: transcripts pass", L,
     "  if { printf '%s' \"$_nj\" | grep -q -- '\\.jsonl' && printf '%s' \"$_nj\" | grep -q -- 'projects/'; } ||\n",
     "  if false ||\n",
     T + "test_cold_bash_guard_denies_private"),
    ("cold guard: a Workflow journal is refused", L,
     "  _nj=$(printf '%s' \"$_lt\" | sed 's#/subagents/workflows/[^/\"[:space:]]*/journal\\.jsonl##g')\n",
     "  _nj=$_lt\n",
     T + "test_cold_bash_guard_leaves_everything_else"),
    ("cold guard: credential helpers and token shapes pass", L,
     '  if printf \'%s\' "$_lt" | grep -Eq -- "$DEG_CRED" || printf \'%s\' "$_raw" | grep -Eq -- "$DEG_SHAPES"; then\n',
     "  if false; then\n",
     T + "test_cold_bash_guard_denies_private"),
    # (the cold window's network class: mutations_network.py)
    ("cold guard: the payload's transcript path counts", L,
     """  _raw=$(printf '%s' "$GW_PAYLOAD" | sed 's/"[a-z_]*transcript_path"[[:space:]]*:[[:space:]]*"[^"]*"//g; s/"cwd"[[:space:]]*:[[:space:]]*"[^"]*"//g')\n""",
     """  _raw=$GW_PAYLOAD\n""",
     T + "test_cold_bash_guard_leaves_everything_else"),
    ("cold guard: sh and Python texts drift apart", "src/gateway/envfile.py",
     '    "transcript": "reading Claude Code\'s session transcripts",\n',
     '    "transcript": "reading session transcripts",\n',
     T + "test_cold_bash_guard_outputs_are_byte_identical"),
    # --- no bytecode in the plugin folder -------------------------------------
    ("hooks write __pycache__ into the plugin folder", L,
     '  exec "$_py" -I -S -X "pycache_prefix=$PYC" "$ROOT/run.py" "$@"\n}',
     '  exec "$_py" -I -S "$ROOT/run.py" "$@"\n}',
     T + "test_no_pycache_in_the_plugin_folder"),
    ("stand-ins write __pycache__ into the plugin folder", "src/gateway/envfile.py",
     '    return "-I -S -X " + sq(f"pycache_prefix={paths.pycache_dir()}")\n',
     '    return "-I -S"\n',
     "test_envfile::test_stub_text_bakes_paths_and_fallbacks"),
    # --- launch.sh status: existence only --------------------------------------
    ("status reports a vault that isn't there", L,
     '    "$(jb test -f "$_h/gateway.toml")" "$(jb test -e "$_h/private/vault.age")"\n',
     '    "$(jb test -f "$_h/gateway.toml")" true\n',
     T + "test_status_reports_each_state"),
    # (the cold guard no longer asks whether a vault exists: PLAN-0.11 §3.4)
    # --- the release check -----------------------------------------------------
    ("the release check ignores untracked shipped files", "tests/release_check.py",
     "    return path.startswith(USER_DATA)\n",
     "    return True\n",
     "test_release::test_release_check_on_a_throwaway_repo"),
    ("the release check reports Claude Code's plugin-root tsconfig.json", "tests/release_check.py",
     '    if len(parts) == 3 and parts[0] == "plugins" and parts[2] == "tsconfig.json":\n        return True\n',
     "",
     "test_release::test_release_check_on_a_throwaway_repo"),
    ("the reference check misses the mod's imports", "tests/test_release.py",
     """        for imp in re.findall(r\"\"\"from\\s+['"](\\.{1,2}/[^'"]+)['"]\"\"\", f.read_text()):\n""",
     """        for imp in []:\n""",
     "test_release::test_every_referenced_file_is_in_the_plugin"),
    # --- the gw MCP server's version tracks plugin.json --------------------------
    ("the gw server version is a hard-coded literal that can go stale", "src/gateway/mcp_server.py",
     'SERVER_INFO = {"name": "gw", "version": __version__}\n',
     'SERVER_INFO = {"name": "gw", "version": "0.7.0"}\n',
     "test_release::test_the_gw_server_version_tracks_plugin_json"),
    # --- the mod -----------------------------------------------------------------
    ("the mod starts a second build while one runs", "hooks/mod/lib.ts",
     "  return st !== undefined && (st.state === 'missing' || st.state === 'failed')\n",
     "  return st !== undefined && st.state !== 'ready'\n",
     "test_mod::test_claude_plugin_test_runs_the_mods_tests"),
    ("the mod provisions in -p and SDK sessions", "hooks/mod/register.tsx",
     "    if (e.isInteractive) {\n",
     "    if (true) {\n",
     "test_mod::test_claude_plugin_test_runs_the_mods_tests"),
    ("/gate-doctor leaves the home folder in its paths", "hooks/mod/lib.ts",
     "  if (home.length > 1 && (t === home || t.startsWith(home + '/'))) t = '~' + t.slice(home.length)\n",
     "",
     "test_mod::test_claude_plugin_test_runs_the_mods_tests"),
]

if __name__ == "__main__":
    mutation_check.MUTATIONS = MUTATIONS
    raise SystemExit(mutation_check.main(sys.argv[1:]))
