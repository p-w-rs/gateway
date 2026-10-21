#!/usr/bin/env python3
"""Mutation checks for the security properties (SPEC 20): each mutation
removes or weakens one guard; the named tests must then FAIL. Files are
restored afterwards (checked by hash). Run from plugins/gateway:

    pixi run --locked python tests/mutation_check.py [-k SUBSTR] [--copy DIR]

`pixi run mutations` (tests/run_mutations.py) runs this file and every
tests/mutations_*.py on a scratch copy of the plugin.
"""
from __future__ import annotations

import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path

PLUGIN = Path(__file__).resolve().parents[1]
S = "src/gateway/"

# (name, file, old, new, test selector "module::substring")
MUTATIONS = [
    # --- checkpoint jobs: env.sh safe to source elsewhere; context ---
    ("env file applies without the stand-in folder", S + "envfile.py",
     "'if [ -d \"$GW_BIN\" ]; then',",
     "'if true; then',",
     "test_envfile::test_env_file_does_nothing_once_the_stand_in_folder_is_gone"),
    ("env.sh writes to stderr when sourced (a checkpoint job records 'failed')", S + "envfile.py",
     "    lines = [ENV_HEADER, f\"GW_BIN={sq(b)}\", 'if [ -d \"$GW_BIN\" ]; then',",
     "    lines = [ENV_HEADER, f\"GW_BIN={sq(b)}\", 'echo gateway >&2', 'if [ -d \"$GW_BIN\" ]; then',",
     "test_envfile::test_checkpoint_jobs_apply_env_sh_silently"),
    ("launch.sh's degraded env file applies without the stand-in folder", "hooks/launch.sh",
     "printf '%s\\n' 'if [ -d \"$GW_BIN\" ]; then'",
     "printf '%s\\n' 'if true; then'",
     "test_envfile::test_launch_degraded_session_matches_python"),
    ("context mentions checkpoint jobs without checkpoint", S + "hooks_session.py",
     "    out = [*HOWTO, JOBS_HOWTO] if jobs else list(HOWTO)\n",
     "    out = [*HOWTO, JOBS_HOWTO]\n",
     "test_session::test_context_mentions_checkpoint_jobs_only_when_checkpoint_is_there"),
    ("context never mentions checkpoint jobs", S + "hooks_session.py",
     "    out = [*HOWTO, JOBS_HOWTO] if jobs else list(HOWTO)\n",
     "    out = list(HOWTO)\n",
     "test_session::test_context_mentions_checkpoint_jobs_only_when_checkpoint_is_there"),
    ("checkpoint's state folder follows XDG_STATE_HOME under a test override", S + "paths.py",
     "    if testing.active() is None:\n        x = os.environ.get(\"XDG_STATE_HOME\", \"\")\n",
     "    if True:\n        x = os.environ.get(\"XDG_STATE_HOME\", \"\")\n",
     "test_session::test_context_mentions_checkpoint_jobs_only_when_checkpoint_is_there"),
    # --- jobs-lows round 2: a first SessionStart cancelled or killed ---
    ("launch.sh starts SessionStart's Python before the safe env file", "hooks/launch.sh",
     "    : > \"$ENVD/.used\" 2>/dev/null\n    pre_session\n",
     "    : > \"$ENVD/.used\" 2>/dev/null\n",
     "test_envfile::test_launch_writes_the_safe_env_before_python_runs_session_start"),
    ("launch.sh's pre-session step leaves missing stand-ins missing", "hooks/launch.sh",
     "    if [ ! -f \"$DATA/bin/$n\" ]; then write_stubs 2>/dev/null; break; fi\n",
     "    if false; then write_stubs 2>/dev/null; break; fi\n",
     "test_envfile::test_launch_writes_the_safe_env_before_python_runs_session_start"),
    ("launch.sh's pre-session step leaves a missing git reset missing", "hooks/launch.sh",
     "  [ -f \"$DATA/git/config\" ] || write_git_reset 2>/dev/null\n  return 0\n",
     "  return 0\n",
     "test_envfile::test_launch_writes_the_safe_env_before_python_runs_session_start"),
    ("the env file is truncated and written in place", S + "envfile.py",
     "    _atomic(Path(path), text, 0o644)\n",
     "    p = Path(path)\n    p.parent.mkdir(parents=True, exist_ok=True)\n"
     "    with open(p, \"w\", encoding=\"utf-8\") as f:\n        f.write(text)\n",
     "test_envfile::test_the_env_file_is_never_left_cut_short"),
    ("the starter form is created in place and then written", S + "hooks_session.py",
     "        _link_new(paths.form_path(), text, 0o600)\n",
     "        fd = os.open(paths.form_path(), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)\n"
     "        with os.fdopen(fd, \"w\", encoding=\"utf-8\") as f:\n            f.write(text)\n",
     "test_session::test_a_killed_session_start_leaves_nothing_half_written"),
    ("the session record is created in place and then written", S + "hooks_session.py",
     "        _link_new(final, \"\\n\".join(lines) + \"\\n\", 0o600)\n",
     "        with open(final, \"x\") as f:\n            f.write(\"\\n\".join(lines) + \"\\n\")\n",
     "test_session::test_a_killed_session_start_leaves_nothing_half_written"),
    ("a SessionStart past Claude Code's limit records its context anyway", S + "hooks_session.py",
     "    if started is None or time.time() - started < SESSION_TIMEOUT - 1:\n",
     "    if True:\n",
     "test_session::test_a_late_session_start_leaves_the_context_to_the_first_prompt"),
    # --- review round 2: hooks keep deciding while an update's env builds ---
    ("launch.sh doesn't fall back to an older finished env", "hooks/launch.sh",
     "    OLD=$(older_env)\n",
     "    OLD=\"\"\n",
     "test_envfile::test_launch_runs_on_an_older_env_while_an_update_builds"),
    # --- review round 2: a narrowing without a vault is persisted ---
    ("ratchet persists nothing before a vault exists", S + "consent.py",
     "    if not vault.exists():\n        if form is None:\n            form = formmod.load()\n",
     "    if not vault.exists():\n        return []\n        if form is None:\n            form = formmod.load()\n",
     "test_session::test_a_narrowing_outlives_a_syntax_error_and_a_deleted_form_without_a_vault"),
    ("ratchet leaves the session-start copy as the last good form", S + "consent.py",
     "        if last_good_ok(form):\n            cur[\"form_last_good\"] = form.used_text\n        vault.save(cur)",
     "        vault.save(cur)",
     "test_session::test_a_narrowing_outlives_a_syntax_error_and_a_deleted_form_without_a_vault"),
    # --- review round 2: a credential belongs to the approved name + kind ---
    ("approve keeps an old credential for a new / re-added / re-kinded account", S + "consent.py",
     "            if not keep_credentials and drops_credential(data, a):",
     "            if False:",
     "test_consent::test_a_stored_credential_never_outlives_its_entry_into_a_new_account"),
    ("gate check plans no secret when approval drops the old credential", S + "gate_setup.py",
     "                      or bool(p.changes and consent.drops_credential(data, a)))",
     "                      )",
     "test_consent::test_a_stored_credential_never_outlives_its_entry_into_a_new_account"),
    ("import keeps a removed entry's credential under an added name", S + "transfer.py",
     "            rec.pop(k, None)\n            if src.get(k):",
     "            if src.get(k):",
     "test_transfer_roundtrip::test_export_import_round_trip_with_localhost_remap"),
    ("migration moves store.age before writing", S + "migrate.py",
     "    target = paths.form_path() if not paths.form_path().exists() else paths.from_v2_form_path()\n",
     "    os.replace(store, paths.backups_dir() / 'early.age')\n"
     "    target = paths.form_path() if not paths.form_path().exists() else paths.from_v2_form_path()\n",
     "test_migrate::test_failure_paths"),
    ("migration keeps partial writes after a failure", S + "migrate.py",
     "        for p in reversed(created):\n            with contextlib.suppress(OSError):\n                p.unlink()\n",
     "        pass\n",
     "test_migrate::test_failure_paths"),
    ("migration skips the credential accounting", S + "migrate.py",
     "        if norm(value) in landed or ref in m.dropped_refs:\n            continue\n",
     "        continue\n",
     "test_migrate::test_check_catches"),
    ("vault.age created while v2 waits", S + "vault.py",
     "    if not migrating and not p.exists() and paths.v2_store_path().exists():\n",
     "    if False:\n",
     "test_vault::test_save_refuses_new_vault_while_v2_waits"),
    ("raised rights not detected", S + "consent.py",
     "        if RANK.get(f, 0) > RANK.get(a, 0):\n            W(",
     "        if False:\n            W(",
     "test_consent::test_consent_sudo_false_to_true"),
    ("effective rights take the form's value", S + "consent.py",
     "        setattr(e, k, rmin(a, f))\n",
     "        setattr(e, k, f)\n",
     "test_consent::test_consent_sudo_ask_to_true"),
    ("new addresses count as approved", S + "consent.py",
     "        if _covered(fa, approved_addrs):\n",
     "        if True:\n",
     "test_consent::test_consent_address_changed"),
    ("new destinations count as approved", S + "consent.py",
     "        ok = d in approved and (bound is None or d in bound)\n",
     "        ok = True\n",
     "test_consent::test_consent_api_key_new_site"),
    ("narrowing doesn't lower the approved snapshot", S + "consent.py",
     "    if not eff.narrowed and not p_hosts and not p_accts:\n        return []\n",
     "    return []\n",
     "test_consent::test_narrowing_ratchet"),
    ("approve ignores what the pop-up showed", S + "consent.py",
     "            if shown != sorted(c.render() for c in pending):\n",
     "            if False:\n",
     "test_consent::test_approve_records"),
    ("others = mine applies without an OK", S + "consent.py",
     "    elif f_oth == \"mine\" and a_oth != \"mine\":\n",
     "    elif False:\n",
     "test_consent::test_consent_others_mine"),
    ("private path rendered into context", S + "hooks_session.py",
     "    text = \"\\n\".join(lines + howto)\n",
     "    text = \"\\n\".join(lines + howto + [str(paths.private_dir())])\n",
     "test_session::test_context_never_mentions_private_dir"),
    ("notes rendered into context", S + "hooks_session.py",
     "    if e.scripts:\n        bits.append(\"scripts get credentials too\")\n",
     "    if e.host is not None and e.host.note:\n        bits.append(e.host.note)\n",
     "test_session::test_context_from_validated_form_only"),
    ("unsafe strings accepted in the form", S + "form.py",
     "    if isinstance(v, str):\n        return not unsafe_text(v)\n",
     "    if isinstance(v, str):\n        return True\n",
     "test_form::test_case_bidi_and_control_chars_refused"),
    ("unsafe names echoed in messages", S + "form.py",
     "    return s if isinstance(s, str) and SAFE_ECHO.fullmatch(s) else None\n",
     "    return s if isinstance(s, str) else None\n",
     "test_form::test_case_unsafe_name_never_echoed"),
    ("env file keeps the user's agent under refuse", S + "envfile.py",
     "    if others != \"mine\":\n",
     "    if False:\n",
     "test_envfile::test_env_file_idempotent_under_every_shell"),
    ("explicit GATE_ACCOUNT skips the bound check", S + "accounts.py",
     "            if not covers(bound, host):\n",
     "            if False:\n",
     "test_accounts::test_select_explicit_needs_a_vault_record"),
    ("file guard lets private/ through", S + "paths.py",
     "            return any(self._one_inside(c) for c in self.candidates(path, cwd))\n",
     "            return False\n",
     "test_harness_run::test_hook_files_placeholder_guard"),
    ("file guard compares spelling case-sensitively", S + "paths.py",
     "    return unicodedata.normalize(\"NFC\", os.fspath(p)).casefold()\n",
     "    return os.fspath(p)\n",
     "test_harness_run::test_hook_files_case_variant_before_private_exists"),
    ("file guard ignores same-file matches (hard links)", S + "paths.py",
     "            if i and i in self.inside:\n                return True\n",
     "            pass\n",
     "test_harness_run::test_hook_files_hard_link"),
    ("file guard lets Grep search a parent of private/", S + "paths.py",
     "            return any(self._one_parent(c) for c in self.candidates(path, cwd))\n",
     "            return False\n",
     "test_harness_run::test_hook_files_grep_from_a_parent"),
    ("file guard lets Glob patterns reach private files", S + "hooks_files.py",
     "                if _glob_match(parts, rel):\n                    return True\n",
     "                pass\n",
     "test_harness_run::test_hook_files_glob_patterns"),
    ("degraded sh file guard is case-sensitive", "hooks/launch.sh",
     "  lower=$(printf '%s' \"$payload\" | tr '[:upper:]' '[:lower:]')\n",
     "  lower=$payload\n",
     "test_envfile::test_launch_degraded_file_guard_case"),
    ("degraded sh file guard allows Grep from a parent", "hooks/launch.sh",
     '        if above_protected "$np"; then deny=parent\n',
     '        if false; then deny=parent\n',
     "test_envfile::test_launch_degraded_file_guard_case"),
    ("no ratchet before a form edit", S + "hooks_files.py",
     "    if tool in FORM_EDITS and files:\n        _ratchet_before_form_edit(files[0], cwd)\n",
     "",
     "test_harness_run::test_hook_files_ratchets_before_a_form_edit"),
    ("gate/subagent don't persist narrowings", S + "hooks_session.py",
     "    if not paths.v2_store_path().exists() and (\n            (data is None and not vault.exists())",
     "    if False and (\n            (data is None and not vault.exists())",
     "test_gate::test_status_writes_the_vault_only_to_persist"),
    ("a missing form ratchets approvals away", S + "consent.py",
     "    if form.syntax_error is not None or not form.exists:\n        return []\n    eff = compute(form, data)\n    p_hosts",
     "    if form.syntax_error is not None:\n        return []\n    eff = compute(form, data)\n    p_hosts",
     "test_consent::test_sync_narrowing_never_runs_on_a_missing_form"),
    ("a missing form is replaced by the starter", S + "hooks_session.py",
     "    if last:\n        if write and _create_form(last):\n",
     "    if False:\n        if write and _create_form(last):\n",
     "test_session::test_missing_form_is_restored"),
    ("migration loser skips the re-check under the locks", S + "migrate.py",
     "                if not store.is_file() or paths.vault_path().exists():\n                    return _leftover_locked(store, key)\n",
     "                pass\n",
     "test_migrate::test_two_processes_racing"),
    ("stand-ins trust CLAUDE_PLUGIN_DATA from the caller", S + "paths.py",
     "    if _TRUST_ENV_DATA:\n        v = _env_abs(\"CLAUDE_PLUGIN_DATA\")\n",
     "    if True:\n        v = _env_abs(\"CLAUDE_PLUGIN_DATA\")\n",
     "test_paths_audit::test_data_dir_precedence"),
    ("dispatch trusts the env for stand-ins", "run.py",
     '    paths.trust_plugin_env(mode in HOOKS or mode == "mcp")\n',
     "    paths.trust_plugin_env(True)\n",
     "test_paths_audit::test_run_dispatch_trusts_the_env"),
    ("git falls back to the user's credential helpers", S + "envfile.py",
     "    return (GIT_RESET if others != \"mine\" else \"\") + (helper_text or \"\")\n",
     "    return helper_text or \"\"\n",
     "test_envfile::test_git_config_resets_credential_helpers"),
    ("stub rewrite leaves a gap", S + "envfile.py",
     "        os.replace(tmp, final / name)\n",
     "        with contextlib.suppress(OSError):\n            (final / name).unlink()\n"
     "        time.sleep(0.002)\n        os.replace(tmp, final / name)\n",
     "test_envfile::test_stubs_never_missing_while_rewritten"),
    ("run.py runs a misplaced --test in production mode", "run.py",
     "    if not test and os.environ.get(\"GATEWAY_TEST_ROOT\"):\n",
     "    if False:\n",
     "test_envfile::test_run_py_fails_closed"),
    ("harness accepts --test anywhere", "tests/harness.py",
     "    return bool(test and rest and rest[0] in runmod.TEST_MODES and \"--test\" not in rest)\n",
     "    return \"--test\" in list(args)\n",
     "test_envfile::test_harness_refuses_misplaced"),
    ("invisible format characters accepted", S + "form.py",
     "    return not s.isascii() and any(_unsafe_char(c) for c in s)\n",
     "    return False\n",
     "test_form::test_case_invisible_format_characters_refused"),
    ("api-key sites may be a public suffix", S + "form.py",
     "                    if v.startswith(\".\") and too_broad_site(bare):\n",
     "                    if v.startswith(\".\") and bare.count(\".\") < 1:\n",
     "test_form::test_case_api_key_public_suffix"),
    ("invalid names rendered into context", S + "hooks_session.py",
     "        lines.append(f\"{n_off} {'entry is' if n_off == 1 else 'entries are'} off because of a \"\n",
     "        lines.append(\", \".join(form.disabled) + f\" {n_off} {'entry is' if n_off == 1 else 'entries are'} off because of a \"\n",
     "test_session::test_context_shows_a_count"),
    ("audit scrubs short literals", S + "audit.py",
     "x and len(x) >= MIN_LITERAL}",
     "x and len(x) >= 1}",
     "test_paths_audit::test_audit_fallback_scrubs_only_long"),
    ("select ignores consent without effective", S + "accounts.py",
     "        ea = effective.accounts.get(a.name)\n        return list(ea.destinations) if ea is not None else []\n",
     "        return destinations(a)\n",
     "test_accounts::test_select_respects_effective_rights_and_bound"),
    ("run.py honours --test for stand-ins", "run.py",
     "    if test and mode not in TEST_MODES:\n",
     "    if False:\n",
     "test_envfile::test_run_py_refuses_test_flag_for_stand_ins"),
    ("testing.override accepts the real home", S + "testing.py",
     "    if bad is not None:\n        raise UnsafeTestPath(",
     "    if False:\n        raise UnsafeTestPath(",
     "test_paths_audit::test_override_refuses_real_home_and_guard_trips"),
    # --- review round 3 ---------------------------------------------------
    # --- rolled back: the gateway doesn't change how Claude's commands end ---
    ("env file: an EXIT trap turns a failed command's exit status into 0", S + "envfile.py",
     "        f\"GIT_SSH_COMMAND={sq(b / 'ssh')}; RSYNC_RSH={sq(b / 'ssh')}; export GIT_SSH_COMMAND RSYNC_RSH\",\n    ]",
     "        f\"GIT_SSH_COMMAND={sq(b / 'ssh')}; RSYNC_RSH={sq(b / 'ssh')}; export GIT_SSH_COMMAND RSYNC_RSH\",\n"
     "        'if [ -n \"${CLAUDE_PID-}\" ]; then trap \\'__gw_rc=$?; trap - EXIT; exit 0\\' EXIT; fi',\n    ]",
     "test_envfile::test_a_failed_command_keeps_its_exit_code_in_claudes_shell"),
    ("launch.sh's degraded env file sets an EXIT trap", "hooks/launch.sh",
     "  printf '  GIT_SSH_COMMAND=%s; RSYNC_RSH=%s; export GIT_SSH_COMMAND RSYNC_RSH\\n' \"$(q \"$B/ssh\")\" \"$(q \"$B/ssh\")\"\n",
     "  printf '  GIT_SSH_COMMAND=%s; RSYNC_RSH=%s; export GIT_SSH_COMMAND RSYNC_RSH\\n' \"$(q \"$B/ssh\")\" \"$(q \"$B/ssh\")\"\n"
     "  printf '%s\\n' \"  trap 'exit 0' EXIT\"\n",
     "test_envfile::test_launch_degraded_session_matches_python"),
    ("transcripts: only <projects>/<project>/<name>.jsonl again", S + "paths.py",
     "                if below and TOOL_RESULTS not in below[:-1] and not _workflow_journal(r, below):",
     "                if below and len(below) == 2:",
     "test_hookbash_private::test_subagent_transcripts_are_denied_too"),
    ("transcripts: a session folder isn't a folder holding transcripts", S + "paths.py",
     "                if below is not None and TOOL_RESULTS not in below \\\n"
     "                        and not _workflow_journal(rp, below):",
     "                if below is not None and len(below) == 1:",
     "test_harness_run::test_hook_files_subagent_transcripts_are_not_read"),
    # --- workflow journals: readable by exact name and place only -------------
    ("transcripts: a Workflow run's journal is refused like a transcript", S + "paths.py",
     "                if below and TOOL_RESULTS not in below[:-1] and not _workflow_journal(r, below):",
     "                if below and TOOL_RESULTS not in below[:-1]:",
     "test_harness_run::test_hook_files_workflow_journals_are_readable"),
    ("transcripts: a Workflow run's journal refused to Bash", S + "paths.py",
     "                if below and TOOL_RESULTS not in below[:-1] and not _workflow_journal(r, below):",
     "                if below and TOOL_RESULTS not in below[:-1]:",
     "test_hookbash_private::test_workflow_journals_are_readable_from_bash_too"),
    ("transcripts: any file named journal.jsonl is readable", S + "paths.py",
     "    if len(below) != 6:\n        return False\n",
     "    if r.name == \"journal.jsonl\":\n        return True\n",
     "test_harness_run::test_hook_files_workflow_journals_are_readable"),
    ("transcripts: journal.jsonl at any depth under workflows/", S + "paths.py",
     "    if len(below) != 6:\n        return False\n",
     "    if len(below) < 6:\n        return False\n",
     "test_harness_run::test_hook_files_workflow_journals_are_readable"),
    ("transcripts: journal.jsonl in any case", S + "paths.py",
     "    if len(tail) != 4 or any(w is not None and w != t for w, t in zip(WORKFLOW_JOURNAL, tail)):",
     "    if len(tail) != 4 or any(w is not None and w != t.lower() for w, t in zip(WORKFLOW_JOURNAL, tail)):",
     "test_harness_run::test_hook_files_workflow_journals_are_readable"),
    ("transcripts: a hard link named journal.jsonl reads a transcript", S + "paths.py",
     "    return stat.S_ISREG(st.st_mode) and st.st_nlink == 1\n",
     "    return stat.S_ISREG(st.st_mode)\n",
     "test_harness_run::test_hook_files_workflow_journals_are_readable"),
    ("transcripts: a hard link named journal.jsonl reads a transcript (Bash)", S + "paths.py",
     "    return stat.S_ISREG(st.st_mode) and st.st_nlink == 1\n",
     "    return stat.S_ISREG(st.st_mode)\n",
     "test_hookbash_private::test_workflow_journals_are_readable_from_bash_too"),
    ("transcripts: a Grep over a Workflow run folder", S + "paths.py",
     "                if below is not None and TOOL_RESULTS not in below \\\n",
     "                if below is not None and TOOL_RESULTS not in below and \"workflows\" not in below \\\n",
     "test_harness_run::test_hook_files_workflow_journals_are_readable"),
    ("transcripts: a subagent's transcript_path names no config dir", S + "paths.py",
     "        for up in list(tp.parents)[1:4]:",
     "        for up in list(tp.parents)[1:2]:",
     "test_hookbash_private::test_subagent_transcripts_are_denied_too"),
    ("degraded launch.sh writes no terminal launcher", "hooks/launch.sh",
     "  write_launcher 2>/dev/null\n",
     "",
     "test_envfile::test_launch_degraded_session_matches_python"),
    ("stand-ins print a traceback on an unexpected error", "run.py",
     "    except Exception as e:  # noqa: BLE001\n        return _failed(tool, e)\n",
     "",
     "test_harness_run::test_stand_ins_and_gate_print_one_line_never_a_traceback"),
]


def sha(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def main(argv: list[str]) -> int:
    """`-k SUBSTR` picks mutations by name; `--copy DIR` mutates a copy of
    plugins/gateway (tests/run_mutations.py makes one) instead of this
    checkout, so nobody else's test run ever sees a mutated file."""
    global PLUGIN
    argv = list(argv)
    if "--copy" in argv:
        k = argv.index("--copy")
        PLUGIN = Path(argv[k + 1]).resolve()
        del argv[k:k + 2]
    pat = argv[argv.index("-k") + 1] if "-k" in argv else None
    killed = survived = 0
    for name, rel, old, new, sel in MUTATIONS:
        if pat and pat not in name:
            continue
        f = PLUGIN / rel
        orig = f.read_text()
        h = sha(f)
        if orig.count(old) != 1:
            print(f"  ERROR {name}: the snippet isn't found exactly once in {rel}")
            survived += 1
            continue
        mod, _, sub = sel.partition("::")
        try:
            f.write_text(orig.replace(old, new))
            r = subprocess.run([sys.executable, "tests/run_tests.py", "-q", "-k", sub, mod],
                               cwd=PLUGIN, capture_output=True, text=True, timeout=600,
                               env=dict(os.environ, GW_TEST_NO_LITTER_CHECK="1"))
        finally:
            f.write_text(orig)
            assert sha(f) == h, f"{rel} was not restored"
        tail = (r.stdout.strip().splitlines() or ["?"])[-1]
        m = re.search(r"(\d+) passed, (\d+) failed", tail)
        if r.returncode != 0 and m and int(m.group(2)) > 0:
            killed += 1
            print(f"  killed   {name}  ({sel}: {tail})")
        else:
            survived += 1
            print(f"  SURVIVED {name}  ({sel}: {tail})")
    print(f"\n{killed} mutations killed, {survived} survived")
    return 1 if survived else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
