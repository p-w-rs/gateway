#!/usr/bin/env python3
"""Mutation checks for WS-9, the last fixes before the 0.11.0 release
verification: the hidden-command rule's spellings (a command that hides
what it runs is refused when its text names a configured target; WS-10a
replaced its "ask" and the ask marker with the records of
mutations_asks.py); sudoedit refused like su while this
computer's sudo is configured, and huggingface-cli (hf's older name) while a
huggingface account exists, both by their bare names; an account that lists
`owners` covering only those and its login (gitroute, select, the configured
set, listing the first owner as a widening); the local sudo dialog's
Remember it starting unticked; an account's per-mode `use` from the gate CLI
and the /gate-accounts pane. Same format and runner as
tests/mutation_check.py: each mutation removes or weakens one property; the
named test must then FAIL.

    pixi run --locked python tests/mutations_final.py [-k SUBSTR] [--copy DIR]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutation_check  # noqa: E402

S = "src/gateway/"

MUTATIONS = [
    # --- WS-9: sudoedit and huggingface-cli (no stand-in of their own) ---------------------
    ("a bare sudoedit passes while this computer's sudo is configured", S + "hooks_bash.py",
     '_OTHER_ELEVATORS = frozenset({"su", "doas", "pkexec", "runuser", "sudoedit"})\n',
     '_OTHER_ELEVATORS = frozenset({"su", "doas", "pkexec", "runuser"})\n',
     "test_hookbash_table::test_posture_other_elevation_tools"),
    ("pre_bash.sh doesn't forward a bare sudoedit", "hooks/pre_bash.sh",
     "|osascript|slogin|sudoedit|huggingface-cli)", "|osascript|slogin|huggingface-cli)",
     "test_hookbash_prefilter::test_trigger_words_fire_and_reach_python"),
    ("pre_bash.sh doesn't forward a bare huggingface-cli", "hooks/pre_bash.sh",
     "|osascript|slogin|sudoedit|huggingface-cli)", "|osascript|slogin|sudoedit)",
     "test_hookbash_prefilter::test_trigger_words_fire_and_reach_python"),
    ("a bare huggingface-cli passes while a huggingface account exists", S + "hooks_bash.py",
     "            if base == \"huggingface-cli\":\n                return _route_deny(argv[0], base, tgt, HF_CLI_WHY)\n",
     "",
     "test_hookbash_table::test_posture_huggingface_cli_is_refused_with_the_way_through_hf"),
    ("a bare huggingface-cli in text the parser can't follow passes", S + "hooks_bash.py",
     "                return _route_deny(\"huggingface-cli\", \"huggingface-cli\", tgt, HF_CLI_WHY)\n",
     "                pass\n",
     "test_hookbash_table::test_posture_huggingface_cli_is_refused_with_the_way_through_hf"),
    ("the huggingface-cli refusal names a huggingface-cli stand-in that doesn't exist", S + "hooks_bash.py",
     "    if base == \"huggingface-cli\":\n        stand = \"hf\"",
     "    if False:\n        stand = \"hf\"",
     "test_hookbash_table::test_posture_huggingface_cli_is_refused_with_the_way_through_hf"),
    ("the huggingface-cli refusal says to run it by its bare name", S + "hooks_bash.py",
     "    elif base == \"huggingface-cli\":\n        use = ",
     "    elif False:\n        use = ",
     "test_hookbash_table::test_posture_huggingface_cli_is_refused_with_the_way_through_hf"),
    # --- WS-9: an account that lists owners covers only those and its login -------------------
    ("gitroute's only account covers every owner though it lists owners", S + "gitroute.py",
     "        return accounts.owner_covered(owner, a.owners, default=a.default, any_owner=a.any_owner,\n",
     "        return accounts.owner_covered(owner, a.owners, default=a.default, any_owner=True,\n",
     "test_git_standin::test_a_personal_repository_is_the_users_own_when_the_only_account_lists_owners"),
    ("the owner rule ignores whether the account lists owners", S + "accounts.py",
     "    return only and any_owner\n",
     "    return only\n",
     "test_posture::test_the_only_account_that_lists_owners_covers_only_those_and_its_login"),
    ("select's only account takes an owner it doesn't list", S + "accounts.py",
     "            owner, in_form[0].owner_names(), default=False, any_owner=not in_form[0].owners,\n",
     "            owner, in_form[0].owner_names(), default=False, any_owner=True,\n",
     "test_posture::test_the_only_account_that_lists_owners_covers_only_those_and_its_login"),
    ("the configured set takes the form's account as listing no owners", S + "consent.py",
     '                     a.owner_names(), bool(a.default), "form", any_owner=not a.owners)\n',
     '                     a.owner_names(), bool(a.default), "form", any_owner=True)\n',
     "test_posture::test_the_only_account_that_lists_owners_covers_only_those_and_its_login"),
    ("the configured set's git targets drop any_owner", S + "consent.py",
     "                any_owner=a.any_owner)\n",
     "                any_owner=True)\n",
     "test_git_standin::test_a_personal_repository_is_the_users_own_when_the_only_account_lists_owners"),
    ("listing the first owner applies at once (no dialog)", S + "consent.py",
     "    if a.owners and approved_any_owner(ap) and only:\n",
     "    if False:\n",
     "test_posture::test_listing_the_first_owner_takes_other_owners_out_only_after_the_ok"),
    ("the ratchet records the narrower reach of a first owner", S + "consent.py",
     '    out["any_owner"] = any_owner or not a.owners\n',
     '    out["any_owner"] = not a.owners\n',
     "test_posture::test_listing_the_first_owner_takes_other_owners_out_only_after_the_ok"),
    ("the approval's reach over every owner doesn't count in the configured set", S + "consent.py",
     "                     any_owner=approved_any_owner(a))\n",
     "                     any_owner=False)\n",
     "test_posture::test_listing_the_first_owner_takes_other_owners_out_only_after_the_ok"),
    ("the configured list forgets which accounts list no owners", S + "consent.py",
     '                       "default": ca.default, "any_owner": ca.any_owner}\n',
     '                       "default": ca.default}\n',
     "test_posture::test_listing_the_first_owner_takes_other_owners_out_only_after_the_ok"),
    # --- WS-9: an account's use per mode from the gate CLI and /gate-accounts -------------
    ("gate account set approves the use it writes (a widening without the dialog)", S + "manage.py",
     '    _write(formmod.set_key, f"accounts.{name}", key, value, entry=name, table=f"[accounts.{name}]")\n',
     '    _write(formmod.set_key, f"accounts.{name}", key, value, entry=name, table=f"[accounts.{name}]")\n'
     '    consent.approve(name)\n',
     "test_modes_ui::test_account_set_writes_use_as_one_word_or_per_mode_and_a_raise_waits_for_the_ok"),
    ("gate account set writes any key", S + "manage.py",
     "    if key not in ACCOUNT_SET_KEYS:\n",
     "    if False:\n",
     "test_modes_ui::test_account_set_writes_use_as_one_word_or_per_mode_and_a_raise_waits_for_the_ok"),
    ("gate account set isn't dispatched", S + "manage.py",
     '        if cmd == "account" and rest[:1] == ["set"] and len(rest) >= 4:\n',
     '        if False:\n',
     "test_modes_ui::test_account_set_writes_use_as_one_word_or_per_mode_and_a_raise_waits_for_the_ok"),
    ("the account edit line takes any key", "hooks/mod/manage.ts",
     "  if (a === 'account' && b === 'set' && w.length >= 5 && NAME.test(w[2]!) && w[3] === 'use') {\n",
     "  if (a === 'account' && b === 'set' && w.length >= 5 && NAME.test(w[2]!)) {\n",
     "test_mod::test_claude_plugin_test_runs_the_mods_tests"),
    ("the account edit line takes a malformed per-mode table", "hooks/mod/manage.ts",
     "      if (!modeTokens(w.slice(4))) return { error: 'use per mode takes MODE=WORD tokens, default first: "
     "default=ask auto=true' }\n    }\n    return { argv: ['gate', ...w], entry: w[2]! }\n",
     "    }\n    return { argv: ['gate', ...w], entry: w[2]! }\n",
     "test_mod::test_claude_plugin_test_runs_the_mods_tests"),
    ("/gate-accounts has no edit line", "hooks/mod/register.tsx",
     "        {e.surface !== 'mobile' ? <Input key=\"edit\" label=\"edit\" placeholder={ACCOUNTS_EDIT_HINT} "
     "submitLabel=\"apply\"\n",
     "        {false ? <Input key=\"edit\" label=\"edit\" placeholder={ACCOUNTS_EDIT_HINT} "
     "submitLabel=\"apply\"\n",
     "test_mod::test_claude_plugin_test_runs_the_mods_tests"),
    # WS-9 (PLAN-0.11 §9.1): the local sudo dialog's Remember it starts unticked, like the remote one
    ("the local sudo dialog's Remember it starts ticked (a typed password is kept unasked)",
     S + "sudo.py", "REMEMBER_DEFAULT = False\n", "REMEMBER_DEFAULT = True\n",
     "test_sudo_standin::test_missing_password_pop_up_stores_it_and_stale_opens_one_reentry"),
    ("the local sudo dialog's Remember it starts ticked (through gated)",
     S + "sudo.py", "REMEMBER_DEFAULT = False\n", "REMEMBER_DEFAULT = True\n",
     "test_dialogs::test_daemon_sudo_standin_control_unchanged_right_runs_and_stores"),
    ("the local sudo dialog's note drifts from the remote one's", S + "sudo.py",
     'REMEMBER_NOTE = ("Tick Remember it to keep it for later commands (unticked, it is used for this "\n',
     'REMEMBER_NOTE = ("Untick Remember it to use it once (ticked, it is kept for later commands; "\n',
     "test_sudo_standin::test_the_sudo_dialog_names_its_right_for_gated_and_offers_remember"),
    # --- WS-9 review M1: git the hook can't follow ----------------------------------------
    ("git with a variable for its subcommand or remote is asked about (the gated git then refuses)",
     S + "hooks_bash.py",
     "            if any(getattr(st, \"expands\", None) or []) and _git_hidden_text(words):\n",
     "            if False:\n",
     "test_git_standin::test_the_hook_denies_git_it_cant_follow_while_something_git_reaches_asks"),
    # --- WS-9 review M2: the spellings that got through the hidden-command rule -------------
    ("source, . or eval behind builtin, command or a reserved word isn't hidden",
     S + "hooks_bash.py",
     '            if not forked and (base in ("source", ".", "eval") or\n',
     "            if not forked and (base in () or\n",
     "test_hookbash_table::test_posture_a_hidden_command_gets_no_decision"),
    ("exec of a script or a shell isn't hidden (parsed)", S + "hooks_bash.py",
     '                               (base == "exec" and _exec_program(argv[1:]) is not None)):\n',
     "                               False):\n",
     "test_hookbash_table::test_posture_a_hidden_command_gets_no_decision"),
    ("exec of a script or a shell isn't hidden (text)", S + "hooks_bash.py",
     "    if _TEXT_HIDES.search(text) or _text_exec(text):\n",
     "    if _TEXT_HIDES.search(text):\n",
     "test_hookbash_table::test_posture_a_hidden_command_gets_no_decision"),
    ("exec with redirections only counts as running a program", S + "hooks_bash.py",
     "        m = _TEXT_REDIR.match(w) or _NAMED_FD.match(w)\n",
     "        m = None\n",
     "test_hookbash_table::test_posture_a_hidden_command_gets_no_decision"),
    ("the text scan starts no command after a reserved word, time, builtin or command",
     S + "hooks_bash.py",
     '                   r"(?:\\s*(?:then|do|else|elif|if|while|until|!|time(?:\\s+-p)?|builtin"\n'
     '                   r"|(?i:command)(?:\\s+--)?)(?=\\s)"\n'
     '                   r"|\\s*(?:\\S*/)?(?i:gate)',
     '                   r"(?:(?!)"\n'
     '                   r"|\\s*(?:\\S*/)?(?i:gate)',
     "test_hookbash_table::test_posture_a_hidden_command_gets_no_decision"),
    ("the text scan starts no command at a case arm", S + "hooks_bash.py",
     '|(?:(?<![\\w.-])in|;;&?|;&)\\s+\\(?[^;&()\\n]*\\)"\n',
     '"\n',
     "test_hookbash_table::test_posture_a_hidden_command_gets_no_decision"),
    ("a shell's value option before -c hides the -c string (text)", S + "hooks_bash.py",
     '    r")(?:\\s+(?:[-+][A-Za-z]*[oO]\\s+[^\\s;&|()<>]+|--(?:rcfile|init-file)\\s+[^\\s;&|()<>]+"\n'
     '    r"|[-+]\\S+))*?\\s+-[A-Za-z]*c\\b\\s*([^\\s;&|()<>]+)")\n',
     '    r")(?:\\s+-\\S+)*?\\s+-[A-Za-z]*c\\b\\s*([^\\s;&|()<>]+)")\n',
     "test_hookbash_table::test_posture_a_hidden_command_gets_no_decision"),
    ("a shell's value option before -c hides the -c string (parsed)", S + "hooks_bash.py",
     "        value = base in _SHELLS and _shell_value_opt(w)   # -o posix, +O extglob, --rcfile F\n",
     "        value = False\n",
     "test_hookbash_table::test_posture_a_hidden_command_gets_no_decision"),
    # --- WS-9 review should-fix 1 and 2: owners -------------------------------------------
    ("an approval without any_owner stops covering every owner (listing the first owner unasked)",
     S + "consent.py",
     '    return not [o for o in ap.get("owners") or [] if isinstance(o, str)]\n',
     "    return False\n",
     "test_consent::test_an_approval_without_any_owner_reads_as_the_form_does"),
    ("a configured list without any_owner narrows the reach", S + "consent.py",
     '                    "any_owner": a.get("any_owner") is not False}\n',
     '                    "any_owner": a.get("any_owner") is True}\n',
     "test_consent::test_a_configured_list_without_any_owner_covers_every_owner"),
    ("owners listed waits beside another account of its kind", S + "consent.py",
     "    if a.owners and approved_any_owner(ap) and only:\n",
     "    if a.owners and approved_any_owner(ap):\n",
     "test_consent::test_owners_listed_waits_only_for_the_only_account_of_its_kind"),
    ("the only account of its kind is taken for one beside another", S + "consent.py",
     "                                      mode, only=_only_of_kind(form, name))\n",
     "                                      mode, only=False)\n",
     "test_posture::test_listing_the_first_owner_takes_other_owners_out_only_after_the_ok"),
]


def main(argv: list[str]) -> int:
    mutation_check.MUTATIONS = MUTATIONS
    return mutation_check.main(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
