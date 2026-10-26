#!/usr/bin/env python3
"""Mutation checks for the relock and version plumbing (PLAN-0.11 section 5,
workstream WS-R): an older env only on the lock's Python minor (launch.sh
and envfile alike), pixi too old recognized and reported (only version
characters, valid JSON, the same words as Python, `gate status`), the
latest-only pins, the locked age's prompts against agepass, and update-deps
itself (the docs moved with requires-pixi, the pin before the runtime's
relock, all or nothing). Same
format and runner as tests/mutation_check.py: each mutation removes or
weakens one property; the named test must then FAIL.

    pixi run --locked python tests/run_mutations.py mutations_relock.py [-k SUBSTR]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutation_check  # noqa: E402

L = "hooks/launch.sh"
E = "src/gateway/envfile.py"
T = "test_packaging::"
U = "tests/update_deps.py"
TU = "test_update_deps::"

# (name, file, old, new, test selector "module::substring")
MUTATIONS = [
    # --- an older env only on the lock's Python minor ------------------------
    ("launch.sh runs the hooks on an older env of another Python minor", L,
     '    [ -n "$_m" ] && [ -x "$d/.pixi/envs/default/bin/python$_m" ] || continue\n',
     "",
     T + "test_an_older_env_on_another_python_minor_is_never_used"),
    ("launch.sh uses an older env when the lock's minor can't be told", L,
     '    [ -n "$_m" ] && [ -x "$d/.pixi/envs/default/bin/python$_m" ] || continue\n',
     '    [ -z "$_m" ] || [ -x "$d/.pixi/envs/default/bin/python$_m" ] || continue\n',
     T + "test_an_older_env_on_another_python_minor_is_never_used"),
    ("launch.sh reads every environment's python as the lock's", L,
     '    e && /^  [^ ]/ { d = ($0 == "  default:"); next }\n',
     "    e && /^  [^ ]/ { d = 1; next }\n",
     T + "test_the_locks_python_minor_is_read_alike"),
    ("launch.sh takes one of two Python minors in the lock", L,
     '      if (f == "") f = m; else if (f != m) bad = 1\n',
     "      f = m\n",
     T + "test_the_locks_python_minor_is_read_alike"),
    ("the stubs fall back to an older env of another Python minor", E,
     '    if f"{sys.version_info[0]}.{sys.version_info[1]}" != lock_python_minor():\n        return None\n',
     "",
     T + "test_stubs_fall_back_to_an_older_env_only_on_the_locks_minor"),
    ("envfile reads every environment's python as the lock's", E,
     '            in_default = line == "  default:"\n',
     "            in_default = True\n",
     T + "test_the_locks_python_minor_is_read_alike"),
    ("envfile takes one of two Python minors in the lock", E,
     '    return found.pop() if len(found) == 1 else ""\n',
     '    return found.pop() if found else ""\n',
     T + "test_the_locks_python_minor_is_read_alike"),
    # --- pixi too old ----------------------------------------------------------
    ("a build refused by an older pixi isn't recognized", L,
     '      note_pixi_too_old "$P"\n',
     "      :\n",
     T + "test_pixi_too_old_is_recognized"),
    ("a pixi-too-old record outlives the next build attempt", L,
     '  rm -f "$ENVD/.pixi-too-old"\n',
     "",
     T + "test_pixi_too_old_is_recognized"),
    ("pixi too old is reported while a build runs", L,
     '  [ -f "$ENVD/.pixi-too-old" ] && build_failed || return 1\n',
     '  [ -f "$ENVD/.pixi-too-old" ] || return 1\n',
     T + "test_pixi_too_old_needs_a_failed_build"),
    ("the stand-ins say setup failed instead of pixi too old", L,
     "  elif pixi_too_old; then\n"
     "    printf '%s' \"gateway: the gateway can't set itself up: $GW_TOOOLD; tell the user to update pixi "
     "(pixi self-update) and start a new session\"\n",
     "",
     T + "test_pixi_too_old_is_recognized"),
    ("the launcher's pixi-too-old text differs from Python's", E,
     '        return (f"gateway: the gateway can\'t set itself up: {pixi_too_old_words()}; update pixi "\n',
     '        return (f"gateway: the gateway can\'t set itself up: {pixi_too_old_words()}; upgrade pixi "\n',
     T + "test_pixi_too_old_is_recognized"),
    ("launch.sh keeps any character of the needed version", L,
     """sed -n "s/.*requires pixi '\\([^']*\\)'.*/\\1/p" | tr -cd '0-9A-Za-z.,<>=!*~ ')\n""",
     """sed -n "s/.*requires pixi '\\([^']*\\)'.*/\\1/p")\n""",
     T + "test_pixi_too_old_keeps_only_version_characters"),
    ("launch.sh keeps any character of the found version", L,
     "sed -n 's/.*you have pixi \\([0-9][^ ,]*\\).*/\\1/p' | tr -cd '0-9A-Za-z.+-')\n",
     "sed -n 's/.*you have pixi \\([0-9][^ ,]*\\).*/\\1/p')\n",
     T + "test_pixi_too_old_keeps_only_version_characters"),
    ("launch.sh keeps any character of pixi --version's", L,
     "sed -n 's/[^0-9]*\\([0-9][^ ]*\\).*/\\1/p' | tr -cd '0-9A-Za-z.+-')\n",
     "sed -n 's/[^0-9]*\\([0-9][^ ]*\\).*/\\1/p')\n",
     T + "test_pixi_too_old_keeps_only_version_characters"),
    ("launch.sh never asks pixi --version when the refusal names no version", L,
     '  [ -n "$_have" ] || _have=$("$1" --version',
     '  [ -n "$_have" ] || true || _have=$("$1" --version',
     T + "test_pixi_too_old_keeps_only_version_characters"),
    ("launch.sh words an unknown pixi version unlike Python", L,
     'else GW_TOOOLD="this pixi is too old"; fi\n',
     'else GW_TOOOLD="your pixi is too old"; fi\n',
     T + "test_pixi_too_old_keeps_only_version_characters"),
    ("Python words an unknown pixi version unlike launch.sh", E,
     ' else "this pixi is too old"\n',
     ' else "your pixi is too old"\n',
     T + "test_pixi_too_old_keeps_only_version_characters"),
    ("a quote in the record breaks SessionStart's JSON", L,
     '    msg="gateway: the gateway can\'t set itself up: $(json_esc "$GW_TOOOLD"). Update pixi:',
     '    msg="gateway: the gateway can\'t set itself up: $GW_TOOOLD. Update pixi:',
     T + "test_a_pixi_too_old_record_never_breaks_the_session_json"),
    ("a quote in the record breaks the not-ready context's JSON", L,
     "the gateway can't set itself up: $(json_esc \"$GW_TOOOLD\"). Tell the user once",
     "the gateway can't set itself up: $GW_TOOOLD. Tell the user once",
     T + "test_a_pixi_too_old_record_never_breaks_the_session_json"),
    ("gate status says nothing while pixi refuses the manifest", "src/gateway/gate.py",
     "        notes.insert(0, too_old)\n",
     "        pass\n",
     T + "test_gate_status_says_pixi_too_old"),
    ("gate status says pixi too old while a build runs", E,
     ' or (envd.parent / (envd.name + ".building")).exists():\n',
     ":\n",
     T + "test_gate_status_says_pixi_too_old"),
    ("gate status says pixi too old beside a ready env", E,
     "    if paths.env_ready() or not (envd / PIXI_TOO_OLD_FILE).is_file() \\\n",
     "    if not (envd / PIXI_TOO_OLD_FILE).is_file() \\\n",
     T + "test_gate_status_says_pixi_too_old"),
    ("gate status says pixi too old for a record without a build's log", E,
     '            or not (envd / "install.log").is_file() or',
     "            or",
     T + "test_gate_status_says_pixi_too_old"),
    # --- the latest-only pins --------------------------------------------------
    ("a dependency is pinned again", "pixi.toml",
     'python = "*"             # the gateway',
     'python = "3.*"           # the gateway',
     T + "test_every_dependency_is_latest"),
    ("a feature dependency is pinned", "pixi.toml",
     'databricks-cli = "*"\n',
     'databricks-cli = ">=1"\n',
     T + "test_every_dependency_is_latest"),
    ("the runtime's tmux is pinned", "runtime/pixi.toml",
     'tmux = "*"               # the remote supervisor',
     'tmux = "3.*"             # the remote supervisor',
     T + "test_every_dependency_is_latest"),
    ("pixi-unpack is a range, not pixi-pack's version", "runtime/pixi.toml",
     'pixi-unpack = "==',
     'pixi-unpack = ">=',
     T + "test_pixi_unpack_is_pixi_packs_version"),
    ("lib.ts goes back to a tested pixi range", "hooks/mod/lib.ts",
     "export const PIXI_TESTED = '",
     "export const PIXI_TESTED_MAX = '9.9.9'\nexport const PIXI_TESTED = '",
     T + "test_requires_pixi_is_the_tested_pixi"),
    ("pijul's cargo install takes a range", "pixi.toml",
     "cargo install pijul --version ",
     "cargo install pijul --version ^",
     T + "test_pijul_is_one_exact_release"),
    # --- the locked age's prompts ----------------------------------------------
    ("agepass waits for a prompt age never shows", "src/gateway/agepass.py",
     'PROMPT_RE = re.compile(rb"(?i)passphrase[^\\n]*:\\s*$")\n',
     'PROMPT_RE = re.compile(rb"(?i)password[^\\n]*:\\s*$")\n',
     T + "test_the_locked_age_prompts_match_agepass"),
    # --- update-deps -----------------------------------------------------------
    ("update-deps relocks with an older pixi", U,
     "        if version_key(running) < version_key(top):\n",
     "        if False:\n",
     TU + "test_a_run_with_an_older_pixi_changes_nothing"),
    ("update-deps leaves requires-pixi behind the pixi that locked", U,
     "        new = {MANIFEST: set_pijul(set_requires_pixi(old[MANIFEST], running), pj),\n",
     "        new = {MANIFEST: set_pijul(old[MANIFEST], pj),\n",
     TU + "test_a_run_relocks_both_manifests"),
    ("update-deps leaves the docs' requires-pixi behind (the suite then fails)", U,
     "               **{d: set_doc_pixi(old[d], running) for d in docs}}\n",
     "               }\n",
     TU + "test_a_run_relocks_both_manifests"),
    ("update-deps leaves pixi-unpack behind pixi-pack", U,
     "        _write(RUNTIME, old[RUNTIME], set_pixi_unpack(old[RUNTIME], pack))\n",
     "",
     TU + "test_a_run_relocks_both_manifests"),
    ("update-deps pins pixi-unpack only after the runtime's relock", U,
     "        _write(RUNTIME, old[RUNTIME], set_pixi_unpack(old[RUNTIME], pack))\n"
     "        _run([pixi, \"update\", \"--manifest-path\", str(RUNTIME)])\n",
     "        _run([pixi, \"update\", \"--manifest-path\", str(RUNTIME)])\n"
     "        _write(RUNTIME, old[RUNTIME], set_pixi_unpack(old[RUNTIME], pack))\n",
     TU + "test_a_run_relocks_both_manifests"),
    ("update-deps dies with a traceback when crates.io can't be reached", U,
     "        if not isinstance(e, (Stop, OSError, ValueError, KeyError)):\n",
     "        if not isinstance(e, (Stop, ValueError, KeyError)):\n",
     TU + "test_a_run_that_stops_half_way"),
    ("update-deps leaves a half-done relock behind", U,
     "        _restore(saved)\n",
     "        pass\n",
     TU + "test_a_run_that_stops_half_way"),
    ("update-deps skips pijul's pre-releases", U,
     "    return newest([v[\"num\"] for v in d.get(\"versions\", []) if not v.get(\"yanked\")])\n",
     "    return newest([v[\"num\"] for v in d.get(\"versions\", []) if not v.get(\"yanked\") and \"-\" not in v[\"num\"]])\n",
     TU + "test_versions_order_semver_with_prereleases"),
    ("update-deps counts a yanked release", U,
     "    return newest([v[\"num\"] for v in d.get(\"versions\", []) if not v.get(\"yanked\")])\n",
     "    return newest([v[\"num\"] for v in d.get(\"versions\", [])])\n",
     TU + "test_versions_order_semver_with_prereleases"),
    ("update-deps hides a package that went", U,
     "                out.append(f\"{label}{env}: {name} {a or '(new)'} -> {b or '(gone)'}\")\n",
     "                if b:\n                    out.append(f\"{label}{env}: {name} {a or '(new)'} -> {b}\")\n",
     TU + "test_moved_lists_what_changed"),
]

if __name__ == "__main__":
    mutation_check.MUTATIONS = MUTATIONS
    raise SystemExit(mutation_check.main(sys.argv[1:]))
