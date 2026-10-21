#!/usr/bin/env python3
"""Mutation checks for the e2e redirection (paths.e2e_marker, hooks/e2e.sh)
and the approval hook's remote-sudo rights (found by the e2e suite). Same
format and runner as tests/mutation_check.py: each mutation removes or
weakens one guard; the named test must then FAIL. Files are restored
afterwards (checked by hash).

    pixi run --locked python tests/mutations_e2e.py [-k SUBSTR] [--copy DIR]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutation_check  # noqa: E402

S = "src/gateway/"

# (name, file, old, new, test selector "module::substring")
MUTATIONS = [
    # --- the e2e marker (Python) ---------------------------------------------
    ("e2e marker: anywhere counts as a temp folder", S + "paths.py",
     '    if not _E2E_CHARS.fullmatch(s or ""):\n        return False\n',
     "    return True\n",
     "test_e2e_marker::test_marker_pointing_outside_temp_is_ignored"),
    ("e2e marker: the plugin folder need not be under temp", S + "paths.py",
     "        if os.lstat(pr).st_uid != me or not _e2e_tmp_ok(str(pr), roots):\n",
     "        if os.lstat(pr).st_uid != me:\n",
     "test_e2e_marker::test_marker_pointing_outside_temp_is_ignored"),
    ("e2e marker: honoured under a test override", S + "paths.py",
     "    if plugin is None:\n        if testing.active() is not None:\n            return None\n",
     "    if plugin is None:\n",
     "test_e2e_marker::test_production_call_reads_the_codes_own_folder"),
    ("e2e marker: any owner", S + "paths.py",
     "    me = os.getuid() if uid is None else uid\n",
     "    me = os.getuid()\n",
     "test_e2e_marker::test_marker_not_owned_by_the_user_is_ignored"),
    ("e2e marker: a marker others can write counts", S + "paths.py",
     "        if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_mode & 0o022:\n",
     "        if not stat.S_ISREG(st.st_mode) or st.st_uid != uid:\n",
     "test_e2e_marker::test_unsafe_marker_files_and_folders_are_ignored"),
    ("e2e marker: folders open to group/others count", S + "paths.py",
     "        if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid or stat.S_IMODE(st.st_mode) & 0o077:\n",
     "        if not stat.S_ISDIR(st.st_mode) or st.st_uid != uid:\n",
     "test_e2e_marker::test_unsafe_marker_files_and_folders_are_ignored"),
    ("e2e marker: a symlinked folder counts", S + "paths.py",
     "        st = os.lstat(raw)\n",
     "        st = os.stat(raw)\n",
     "test_e2e_marker::test_unsafe_marker_files_and_folders_are_ignored"),
    ("e2e config: any key is passed to the override", S + "paths.py",
     "        if isinstance(v, typ) and not (typ is not bool and isinstance(v, bool)):\n"
     "            out[k] = v\n",
     "        if isinstance(v, typ) and not (typ is not bool and isinstance(v, bool)):\n"
     "            out[k] = v\n    out.update({k: v for k, v in raw.items() if k not in out})\n",
     "test_e2e_marker::test_e2e_config_keeps_only_known_knobs"),
    ("e2e mode stops guarding the real private folder", S + "paths.py",
     '    if not testing.get("e2e"):\n        return []\n',
     "    return []\n",
     "test_e2e_marker::test_e2e_override_redirects_and_still_guards_the_real_home"),
    ("SessionStart doesn't say e2e mode", S + "hooks_session.py",
     '    e2e = testing.get("e2e")\n',
     "    e2e = None\n",
     "test_e2e_marker::test_session_start_says_e2e_mode"),
    # --- the e2e marker (sh) -------------------------------------------------
    ("hooks/e2e.sh: anywhere counts as a temp folder", "hooks/e2e.sh",
     "gw_e2e_tmp() {\n",
     "gw_e2e_tmp() {\n  return 0\n",
     "test_e2e_marker::test_marker_pointing_outside_temp_is_ignored"),
    ("hooks/e2e.sh: a marker others can write counts", "hooks/e2e.sh",
     "  [ -z \"$(find \"$_gm\" -prune \\( -perm -020 -o -perm -002 \\) -print 2>/dev/null)\" ] || return 1\n",
     "",
     "test_e2e_marker::test_unsafe_marker_files_and_folders_are_ignored"),
    # (`[ ! -L "$1" ]` in gw_e2e_dir is not mutated alone: the permission check
    # right after it also refuses a symlink, whose own mode is 0755 or 0777.)
    ("hooks/e2e.sh: folders open to group/others count", "hooks/e2e.sh",
     '  [ -z "$(find "$1" -prune \\( -perm -040 -o -perm -020 -o -perm -010 -o -perm -004 -o -perm -002 -o -perm -001 \\) -print 2>/dev/null)" ] || return 1\n',
     "",
     "test_e2e_marker::test_unsafe_marker_files_and_folders_are_ignored"),
    # --- the approval hook and remote sudo -----------------------------------
    ("hook: remote sudo on a sudo = false host isn't denied", S + "hooks_bash.py",
     "                    if rs is False and sudo_cmd:\n",
     "                    if False:\n",
     "test_hookbash_remote_sudo::test_remote_sudo_on_a_host_with_sudo_off"),
    ("hook: remote sudo on a sudo = \"ask\" host isn't asked", S + "hooks_bash.py",
     '                        ask.append((name, "sudo"))\n',
     '                        pass\n',
     "test_hookbash_remote_sudo::test_remote_sudo_on_a_host_with_sudo_ask"),
    ("hook: remote sudo allowed without an effective sudo right", S + "hooks_bash.py",
     '            if sudo_word and _eff_right(eff, name, "sudo") is not True:\n',
     "            if False:\n",
     "test_hookbash_remote_sudo::test_remote_sudo_with_sudo_true_is_allowed_and_pending"),
    ("hook: rsync --rsync-path isn't a remote command", S + "hooks_bash.py",
     '            if name == "rsync-path":\n                tr.remote_cmd = val\n',
     '            if name == "rsync-path":\n                pass\n',
     "test_hookbash_remote_sudo::test_remote_sudo_on_a_host_with_sudo_off"),
    # --- the optional jobs scenario (checkpoint): stays inside the e2e root ----
    ("e2e jobs: checkpoint's state folder or env file outside the e2e root accepted",
     "tests/e2e/run_e2e.py",
     "        if not _inside(p, root) or rp == real or real in rp.parents:\n",
     "        if False:\n",
     "test_e2e_marker::test_e2e_jobs_scenario_needs_checkpoint_next_to_the_repo"),
    ("e2e jobs: the kill switch ignores CHECKPOINT_GATEWAY_ENV's value", "tests/e2e/run_e2e.py",
     "    if m.group(1) != gw:\n",
     "    if False:\n",
     "test_e2e_marker::test_e2e_jobs_scenario_needs_checkpoint_next_to_the_repo"),
    ("e2e jobs: the kill switch ignores CHECKPOINT_HOME", "tests/e2e/run_e2e.py",
     "    if h is None or h.group(1) != home:\n",
     "    if False:\n",
     "test_e2e_marker::test_e2e_jobs_scenario_needs_checkpoint_next_to_the_repo"),
    ("e2e jobs: any folder named checkpoint counts as a checkout", "tests/e2e/run_e2e.py",
     '    if all((ck / f).is_file() for f in ("run.py", ".mcp.json", "pixi.toml")):\n',
     "    if ck.is_dir():\n",
     "test_e2e_marker::test_e2e_jobs_scenario_needs_checkpoint_next_to_the_repo"),
    # --- jobs: a classifier denial is "not reached", never a gateway result ---
    ("e2e jobs: a gateway (hook) denial counts as the classifier's", "tests/e2e/scenarios.py",
     '    if r.startswith("PreToolUse:") or "auto mode classifier" not in r:\n',
     '    if "auto mode classifier" not in r:\n',
     "test_e2e_marker::test_e2e_jobs_counts_a_classifier_denial_as_not_reached"),
    ("e2e jobs: a job step that ran counts as the classifier's", "tests/e2e/scenarios.py",
     "    if c is None or not c.denied:\n        return None\n    r = c.result",
     "    if c is None:\n        return None\n    r = c.result",
     "test_e2e_marker::test_e2e_jobs_counts_a_classifier_denial_as_not_reached"),
    ("e2e jobs: a classifier denial is judged like a gateway result", "tests/e2e/scenarios.py",
     "    elif classifier_denial(c) is not None:\n",
     "    elif False:\n",
     "test_e2e_marker::test_e2e_jobs_counts_a_classifier_denial_as_not_reached"),
    ("e2e jobs: a retried job step is judged by its first call (a classifier denial before "
     "the run hides it)", "tests/e2e/scenarios.py",
     "    for keep in (lambda c: not c.denied, lambda c: classifier_denial(c) is None):\n"
     "        hit = [c for c in cs if keep(c)]\n        if hit:\n            return hit[-1]\n",
     "    for keep in (lambda c: True,):\n"
     "        hit = [c for c in cs if keep(c)]\n        if hit:\n            return hit[0]\n",
     "test_e2e_marker::test_e2e_jobs_judges_the_job_step_that_ran"),
    ("e2e jobs: a gateway denial is passed over for a classifier denial of the same step",
     "tests/e2e/scenarios.py",
     "    for keep in (lambda c: not c.denied, lambda c: classifier_denial(c) is None):\n",
     "    for keep in (lambda c: not c.denied,):\n",
     "test_e2e_marker::test_e2e_jobs_judges_the_job_step_that_ran"),
]


def main(argv: list[str]) -> int:
    mutation_check.MUTATIONS = MUTATIONS
    return mutation_check.main(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
