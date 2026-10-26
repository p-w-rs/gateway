#!/usr/bin/env python3
"""Mutation checks for 0.11.1 (the install-from-GitHub test of 0.11.0): the
first setup writing a missing gateway.toml as SessionStart would (never the
starter over approvals it can't restore); a pixi that is too old named in
gate-sh's not-ready notice and in what Claude is told at session start,
with the package manager's way to update it; the tool folders found but not
imported leaving out what the managed shell's PATH holds already, also
when gate-sh renews the settings. Same format and runner as
tests/mutation_check.py: each mutation removes or weakens one property; the
named test must then FAIL.

    pixi run --locked python tests/run_mutations.py mutations_setup.py [-k SUBSTR]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutation_check  # noqa: E402

G = "hooks/gate-sh"
L = "hooks/launch.sh"
M = "src/gateway/managed.py"
T = "test_managed::"
P = "test_packaging::"

# (name, file, old, new, test selector "module::substring")
MUTATIONS = [
    # --- the first setup writes the form ------------------------------------------
    ("the end of the first setup writes the starter over approvals it can't restore", M,
     "            hooks_session._missing_form([], data, True)\n",
     "            hooks_session._create_form(formmod.STARTER)\n",
     T + "test_the_first_setup_writes_the_starter_form_when_it_finishes"),
    ("launch.sh's setup leaves gateway.toml to the next session", L,
     '"$ROOT/run.py" managed-sync --setup </dev/null',
     '"$ROOT/run.py" managed-sync </dev/null',
     T + "test_launch_sh_writes_the_managed_files_once_a_build_finishes"),
    # --- pixi too old ----------------------------------------------------------------
    ("gate-sh's notice says setup failed and is retried for a pixi that is too old", G,
     '    if [ -f "${_log%/install.log}/.pixi-too-old" ]; then\n',
     "    if false; then\n",
     T + "test_an_unready_managed_shell_says_what_is_wrong"),
    ("Claude is told only pixi self-update for a pixi that is too old (none for a MacPorts pixi)", L,
     "Tell the user once to update pixi ($GW_PIXI_UPDATE) and",
     "Tell the user once to update pixi (pixi self-update) and",
     P + "test_pixi_too_old_is_recognized"),
    # --- the tool folders found but not imported --------------------------------------
    ("the tool folders found here include what the managed PATH holds already", M,
     " or d in on_path or d.startswith(_FOUND_SKIP)",
     " or d.startswith(_FOUND_SKIP)",
     T + "test_tool_folders_already_on_the_managed_path_are_not_listed_as_found"),
    ("gate-sh renews the settings with its own helper PATH, not Claude Code's", G,
     'then PATH=$GW_PATH0 "$GW_SYNC" <',
     'then "$GW_SYNC" <',
     T + "test_tool_folders_already_on_the_managed_path_are_not_listed_as_found"),
]

if __name__ == "__main__":
    mutation_check.MUTATIONS = MUTATIONS
    raise SystemExit(mutation_check.main(sys.argv[1:]))
