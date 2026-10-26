#!/usr/bin/env python3
"""Mutation checks for WS-6 (PLAN-0.11 §8, §9.1-9.3, §19.5): the vault
passphrase offer (after a store, outside the vault's lock: deferred to the
end of popup's helper job and sent with its lease; once per session; only
while due, the key without a passphrase and a dialog can open; Not now for
good and never waiting forever for the lock; Set passphrase opening the
passphrase dialog; the due mark only with a secret and no wrapped key, and
never undoing Not now; only gated's own choice wearing the mod's template,
whose words and options are gated's); masking every tool's output (the
output hooks' ".*" matcher, post.sh's skip list and its trust in the tool
name, the user's credential variables in sh and Python, a value starting
with "/" too, a failed call naming the variable); the AskUserQuestion guard
(its matcher, the words, tool_input only, JSON escapes); the remote sudo
dialog's "Remember it" unticked; export and import (the settings approved
in the one dialog, added or replaced, and a change meanwhile said to wait;
settings already waiting on this machine never shown as the file's, approved
only under their own heading and never by a peer import; this machine's
settings unticked and only replaced when picked; what a new entry brings
listed one key per line, each naming its entry; per-mode values kept
inline; a confirm too long for one dialog shown whole, in parts sized by
the rows a docked pane shows (a wide character two columns), each part's
question naming it, each limit held exactly, each line continued rather
than cut; the message pointing at a Claude Code session);
and a stored Entra credential that doesn't fit the approved account (or
any unapproved account's) refused at use, with the tokens minted before an
approved sign-in change dropped. Same
format and runner as tests/mutation_check.py: each mutation removes or
weakens one property; the named test must then FAIL. Mutations of the mod
(hooks/mod/) are killed by `claude plugin test` on the copy (test_mod),
which needs a claude binary.

    pixi run --locked python tests/mutations_offer.py [-k SUBSTR] [--copy DIR]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutation_check  # noqa: E402

S = "src/gateway/"
DS = S + "daemon/"
OF = DS + "offer.py"
TR = S + "transfer.py"
HP = S + "hooks_post.py"
M = "hooks/mod/"
T = "test_offer::"
TP = "test_portability::"
TU = "test_ux_hooks::"
MOD = "test_mod::test_claude_plugin_test_runs_the_mods_tests"

# (name, file, old, new, test selector "module::substring")
MUTATIONS = [
    # --- the passphrase offer: popup ----------------------------------------
    ("the helper offers at once (inside its job, the vault's lock maybe held)", S + "popup.py",
     '    if _MODE != "broker":\n        _OFFER_DUE = True\n',
     '    if False:\n        _OFFER_DUE = True\n',
     T + "test_offer_passphrase_asks_gated_only_with_native_dialogs_and_defers_in_the_helper"),
    ("the helper never offers when its job ends", S + "popup.py",
     "        _offer_if_due()            # a secret stored by the job: the vault passphrase offer\n",
     "",
     T + "test_the_helper_offers_only_after_its_job_with_its_lease"),
    ("a secret stored through the dialog makes no offer", S + "popup.py",
     "                    offer_passphrase()   # (in the helper: offered once its job has ended)\n",
     "",
     T + "test_offered_after_a_stored_secret_once_per_session_and_not_now_is_for_good"),
    ("a test's fake dialog asks gated for the offer", S + "popup.py",
     '    if dialog.backend()[0] != "native":\n        return "unavailable"',
     '    if False:\n        return "unavailable"',
     T + "test_offer_passphrase_asks_gated_only_with_native_dialogs_and_defers_in_the_helper"),
    ("the deferred offer goes without the helper's lease", S + "popup.py",
     "        if lease:\n            _offer_now(lease)\n",
     "        if lease:\n            _offer_now(None)\n",
     T + "test_offer_passphrase_asks_gated_only_with_native_dialogs_and_defers_in_the_helper"),
    ("gate check's token store makes no offer", S + "gate_setup.py",
     '    audit.log("secret_saved", entry=name, what="token", source=source)\n'
     "    popup.offer_passphrase()                 # PLAN-0.11 §8 (the vault's lock is released)\n",
     '    audit.log("secret_saved", entry=name, what="token", source=source)\n',
     T + "test_gate_checks_stores_offer_the_passphrase"),
    # --- the passphrase offer: gated -----------------------------------------
    ("gated's own sign-in store makes no offer (review should-fix 1)", DS + "oauth.py",
     "        self._offer(si)\n        return 200, PAGE_OK\n",
     "        return 200, PAGE_OK\n",
     T + "test_gated_offers_after_its_own_sign_in_store_with_the_vaults_lock_free"),
    ("gated offers its sign-in's passphrase with the vault's lock held", DS + "oauth.py",
     "                b.write(data)\n",
     "                b.write(data)\n                self._offer(si)\n",
     T + "test_gated_offers_after_its_own_sign_in_store_with_the_vaults_lock_free"),
    ("a failed offer fails gated's sign-in", DS + "oauth.py",
     "        try:\n            self.d.offers.offer(si.session)\n"
     "        except Exception:  # noqa: BLE001 - a later store offers it\n            pass\n",
     "        self.d.offers.offer(si.session)\n",
     T + "test_gated_offers_after_its_own_sign_in_store_with_the_vaults_lock_free"),
    ("a lease's session of another start time counts (review R7)", DS + "dialogs.py",
     "        if s is None or (le.session_start is not None and s.start != le.session_start):\n",
     "        if s is None:\n",
     T + "test_a_lease_proves_only_its_own_session_and_an_offer_that_didnt_open_comes_again"),
    ("an offer whose dialog didn't open counts as made (review R9)", OF,
     "                self.offered.discard(key)\n",
     "                pass\n",
     T + "test_a_lease_proves_only_its_own_session_and_an_offer_that_didnt_open_comes_again"),
    ("gated offers again in the same session", OF,
     "            self.offered.add(key)\n",
     "            pass\n",
     T + "test_a_program_below_the_session_asks_at_once_and_a_headless_session_gets_nothing"),
    ("gated offers after Not now", OF,
     "        if state != vault.OFFER_PENDING:\n",
     "        if state is None:\n",
     T + "test_offered_after_a_stored_secret_once_per_session_and_not_now_is_for_good"),
    ("gated offers with a wrapped key", OF,
     '        if mode != "unwrapped":\n',
     '        if mode == "none":\n',
     T + "test_set_passphrase_opens_the_passphrase_dialog_and_a_wrapped_key_is_never_offered"),
    ("Not now isn't recorded", OF,
     "                        vault.decline_offer(data)\n",
     "",
     T + "test_not_now_never_waits_forever_for_the_vaults_lock"),
    ("Not now waits for the vault's lock with no end", OF,
     "                with vault.locked(timeout=LOCK_WAIT):\n",
     "                with vault.locked():\n",
     T + "test_not_now_never_waits_forever_for_the_vaults_lock"),
    ("Set passphrase opens no passphrase dialog", OF,
     "            r = self.d.vault_dialog(session)\n",
     "            r = {}\n",
     T + "test_set_passphrase_opens_the_passphrase_dialog_and_a_wrapped_key_is_never_offered"),
    ("an option that isn't one counts as Not now", OF,
     "        if choice == LATER:\n",
     "        if choice != SET:\n",
     T + "test_not_now_never_waits_forever_for_the_vaults_lock"),
    # --- the passphrase offer: vault ------------------------------------------
    ("the offer is due without a secret", S + "vault.py",
     "    if all_values(data):\n        data[\"passphrase_offer\"] = OFFER_PENDING\n",
     "    if True:\n        data[\"passphrase_offer\"] = OFFER_PENDING\n",
     T + "test_the_offer_is_due_only_with_a_secret_and_a_key_without_a_passphrase"),
    ("a save undoes Not now", S + "vault.py",
     "    if offer_state(data) is not None or paths.wrapped_key_path().is_file():\n",
     "    if paths.wrapped_key_path().is_file():\n",
     T + "test_the_offer_is_due_only_with_a_secret_and_a_key_without_a_passphrase"),
    ("the offer is due with a wrapped key", S + "vault.py",
     "    if offer_state(data) is not None or paths.wrapped_key_path().is_file():\n",
     "    if offer_state(data) is not None:\n",
     T + "test_the_offer_is_due_only_with_a_secret_and_a_key_without_a_passphrase"),
    # --- the passphrase offer: dialogs and the mod ------------------------------
    ("a program's own dialog wears the offer's template", DS + "dialogs.py",
     '                    offer=spec.get("offer") if owner == "gated" and kind == "choice"\n',
     '                    offer=spec.get("offer") if kind == "choice"\n',
     T + "test_only_gateds_own_choice_carries_the_offer_marker"),
    ("gated's choice handler gets no pick", DS + "dialogs.py",
     '            values = [r.answer["choice"]]              # (the option picked, one of r.options)\n',
     "            pass\n",
     T + "test_only_gateds_own_choice_carries_the_offer_marker"),
    ("the mod's options aren't gated's", M + "dialog.ts",
     "export const OFFER_OPTIONS: readonly string[] = ['Set passphrase', 'Not now']\n",
     "export const OFFER_OPTIONS: readonly string[] = ['Set passphrase', 'Later']\n",
     T + "test_the_mods_template_is_gateds_text_and_options"),
    ("the mod shows gated's own words for the offer", M + "dialog.ts",
     "  if (o.offer === 'passphrase' && d.kind === 'choice') {\n",
     "  if (false) {\n",
     MOD),
    # --- every tool's output masked (§9.1) ------------------------------------
    ("PostToolUse takes only some tools again", "hooks/hooks.json",
     '"PostToolUse": [\n      {\n        "matcher": ".*",',
     '"PostToolUse": [\n      {\n        "matcher": "^(Bash|Read|Grep|mcp__plugin_check_jobs__job_tail)$",',
     TU + "test_hooks_json_sends_checkpoint_job_results_to_the_output_hooks"),
    ("PostToolUseFailure takes only some tools again", "hooks/hooks.json",
     '"PostToolUseFailure": [\n      {\n        "matcher": ".*",',
     '"PostToolUseFailure": [\n      {\n        "matcher": "^(Bash|Read)$",',
     TU + "test_hooks_json_sends_checkpoint_job_results_to_the_output_hooks"),
    ("post.sh skips tools that carry output", "hooks/post.sh",
     "            TodoWrite|TaskCreate|TaskGet|TaskList|TaskUpdate|EnterPlanMode|ExitPlanMode) exit 0 ;;\n",
     "            TaskOutput|WebFetch|TodoWrite|TaskCreate|TaskGet|TaskList|TaskUpdate|EnterPlanMode"
     "|ExitPlanMode) exit 0 ;;\n",
     TU + "test_post_sh_skips_only_the_tools_whose_response_is_fixed_text"),
    ("post.sh trusts a tool name the payload gives twice", "hooks/post.sh",
     "    *\\\"tool_name\\\"*) ;;\n    *)\n      t=${after#:}\n",
     "    *)\n      t=${after#:}\n",
     TU + "test_post_sh_skips_only_the_tools_whose_response_is_fixed_text"),
    ("post.sh never compares the credential variables", "hooks/post.sh",
     '    [ "${#v}" -ge 8 ] || continue\n',
     "    continue\n",
     TU + "test_post_sh_sends_a_credential_variables_value_to_python_without_a_vault"),
    ("post.sh counts a value under 8 characters", "hooks/post.sh",
     '    [ "${#v}" -ge 8 ] || continue\n',
     '    [ "${#v}" -ge 1 ] || continue\n',
     TU + "test_post_sh_sends_a_credential_variables_value_to_python_without_a_vault"),
    ("the credential variables' values aren't masked", HP,
     "        return scrub.scrub_text(text, extra=env)\n",
     "        return scrub.scrub_text(text)\n",
     TU + "test_post_masks_the_users_credential_variables_and_names_them_on_a_failure"),
    ("a credential variable named like one but unlisted isn't masked", HP,
     "        if n not in MASK_ENV_NAMES and not _CRED_NAME.search(n.upper()):\n",
     "        if n not in MASK_ENV_NAMES:\n",
     TU + "test_post_masks_the_users_credential_variables_and_names_them_on_a_failure"),
    # (the variable list's own drift: mutations_integration.py, WS-8's one list)
    ("a credential variable's value starting with / isn't masked (review R5)", HP,
     "        if len(v) < MIN_ENV_VALUE or not v.strip():\n",
     '        if len(v) < MIN_ENV_VALUE or v.startswith("/") or not v.strip():\n',
     TU + "test_post_masks_the_users_credential_variables_and_names_them_on_a_failure"),
    ("a failed call holding a variable's value says nothing", HP,
     "    if envs and not hits:\n",
     "    if False:\n",
     TU + "test_post_masks_the_users_credential_variables_and_names_them_on_a_failure"),
    # --- AskUserQuestion (§9.2) ---------------------------------------------
    ("tool_guard lets AskUserQuestion ask for a secret", "hooks/tool_guard.sh",
     "    AskUserQuestion) ask=1 ;;\n",
     "",
     TU + "test_ask_user_question_asking_for_a_secret_is_denied"),
    ("the AskUserQuestion guard isn't registered", "hooks/hooks.json",
     '"matcher": "AskUserQuestion",',
     '"matcher": "AskUserQuestionNever",',
     TU + "test_ask_user_question_asking_for_a_secret_is_denied"),
    ("tool_guard reads the whole payload (paths, ids)", "hooks/tool_guard.sh",
     '  ti=${input#*\\"tool_input\\"}\n',
     "  ti=$input\n",
     TU + "test_ask_user_question_asking_for_a_secret_is_denied"),
    ("tool_guard misses the word password", "hooks/tool_guard.sh",
     "  W='(passwords?|passphrases?|",
     "  W='(passphrases?|",
     TU + "test_ask_user_question_asking_for_a_secret_is_denied"),
    ("tool_guard denies a secret word merely named (review should-fix 4)", "hooks/tool_guard.sh",
     '-e "(^| )$R( [a-z0-9]+)?( [a-z0-9]+)?( [a-z0-9]+)? $W( |\\$)"',
     '-e "(^| )$W( |\\$)"',
     TU + "test_ask_user_question_asking_for_a_secret_is_denied"),
    ("tool_guard misses a header or an option that is the secret word", "hooks/tool_guard.sh",
     '      -e "^ ?((the|your|my|a|an) )?$W( please| here)? ?\\$" ',
     "      ",
     TU + "test_ask_user_question_asking_for_a_secret_is_denied"),
    ("tool_guard misses a secret word with please", "hooks/tool_guard.sh",
     ' -e "(^| )$W (please|here)( |\\$)"; then',
     "; then",
     TU + "test_ask_user_question_asking_for_a_secret_is_denied"),
    ("tool_guard reads the whole input as one line", "hooks/tool_guard.sh",
     "          tr '\"' '\\n' | tr -c",
     "          tr '\"' ' ' | tr -c",
     TU + "test_ask_user_question_asking_for_a_secret_is_denied"),
    ("tool_guard reads JSON escapes as letters", "hooks/tool_guard.sh",
     "-e 's/\\\\./ /g'",
     "-e 's/X\\\\./ /g'",
     TU + "test_ask_user_question_asking_for_a_secret_is_denied"),
    # --- the remote sudo dialog's Remember it (27g) -------------------------------
    ("the remote sudo dialog's Remember it starts ticked", S + "ssh_sudo.py",
     "REMEMBER_DEFAULT = False\n",
     "REMEMBER_DEFAULT = True\n",
     T + "test_the_remote_sudo_dialog_offers_remember_it_unticked"),
    # --- export and import (§9.3) -----------------------------------------------
    ("the imported settings aren't approved by the import's dialog", TR,
     '        if p.settings_add and "settings" not in names:\n            names.append("settings")\n',
     "",
     TP + "test_imported_settings_are_approved_in_the_import_dialog_not_left_waiting"),
    ("a change while the dialog was open waits unannounced", TR,
     "            waiting.append(n)\n",
     "            pass\n",
     TP + "test_imported_settings_are_approved_in_the_import_dialog_not_left_waiting"),
    ("this machine's settings are ticked by default", TR,
     "        items.append(ExportItem(LOCALHOST_ITEM, LOCALHOST_LABEL, checked=False))\n",
     "        items.append(ExportItem(LOCALHOST_ITEM, LOCALHOST_LABEL, checked=True))\n",
     TP + "test_export_items_pick_entries_secrets_and_settings_one_by_one"),
    ("this machine's settings replaced unasked", TR,
     '        if choices.get("localhost") == REPLACE:\n',
     "        if True:\n",
     TP + "test_this_machines_settings_are_kept_or_replaced_and_a_dropped_sudo_is_a_widening"),
    ("the import's dialog leaves out what a new entry brings", TR,
     "        if entry_details(sect, t):\n            p.details[name] = entry_details(sect, t)\n",
     "",
     TP + "test_a_round_trip_carries_everything_0_11_configures"),
    ("a per-mode value becomes a sub-table and is lost", TR,
     "        if not isinstance(v, dict) or k not in SUBTABLES:\n            continue\n",
     "        if not isinstance(v, dict):\n            continue\n",
     TP + "test_a_round_trip_carries_everything_0_11_configures"),
    ("an import too long for one dialog goes in one, cut short", TR,
     "    if sum(popup.pane_rows(ln) for ln in one) <= max_rows:\n",
     "    if True:\n",
     TP + "test_an_import_too_long_for_one_dialog_is_shown_in_parts_and_never_cut_short"),
    ("an import confirm that fits gated's lines is one dialog however many rows it takes", TR,
     "    if sum(popup.pane_rows(ln) for ln in one) <= max_rows:\n",
     "    if len(one) <= max_rows:\n",
     TP + "test_an_import_confirm_is_sized_by_the_rows_the_pane_shows"),
    ("an import part's question doesn't say which part it is", TR,
     "        return [\"\", f\"Part {i} of {n}. \" + (\n",
     "        return [\"\", \"\" + (\n",
     TP + "test_an_import_too_long_for_one_dialog_is_shown_in_parts_and_never_cut_short"),
    ("an import is applied after its first part", TR,
     "            for i, page in enumerate(pages, 1):\n",
     "            for i, page in enumerate(pages[:1], 1):\n",
     TP + "test_an_import_too_long_for_one_dialog_is_shown_in_parts_and_never_cut_short"),
    ("more parts than a confirm may have are shown", TR,
     "                               MAX_CONFIRM_PAGES, rows=max_rows)\n",
     "                               10 ** 6, rows=max_rows)\n",
     TP + "test_an_import_too_long_for_one_dialog_is_shown_in_parts_and_never_cut_short"),
    # --- WS-11b review: each limit exactly, wide characters ---------------------------
    ("an import confirm one row longer than a dialog is one dialog (gated drops its question)", TR,
     "    if sum(popup.pane_rows(ln) for ln in one) <= max_rows:\n",
     "    if sum(popup.pane_rows(ln) for ln in one) <= max_rows + 1:\n",
     TP + "test_an_import_confirm_sits_exactly_on_its_limits"),
    ("one part more than MAX_CONFIRM_PAGES is shown", S + "popup.py",
     "    if n > max_parts:\n",
     "    if n > max_parts + 1:\n",
     TP + "test_an_import_confirm_sits_exactly_on_its_limits"),
    ("exactly MAX_CONFIRM_PAGES parts are refused", S + "popup.py",
     "    if n > max_parts:\n",
     "    if n >= max_parts:\n",
     TP + "test_an_import_confirm_sits_exactly_on_its_limits"),
    ("a wide character in an import confirm counts as one column", S + "popup.py",
     "    return sum(2 if unicodedata.east_asian_width(ch) in \"WF\" else 1 for ch in text)\n",
     "    return len(text)\n",
     TP + "test_an_import_confirm_sits_exactly_on_its_limits"),
    ("a long confirm line is cut, not continued", TR,
     "        while len(cur) > width:\n",
     "        while False:\n",
     TP + "test_an_import_too_long_for_one_dialog_is_shown_in_parts_and_never_cut_short"),
    ("a new host's policy goes back on one line (its grants cut off)", TR,
     '            out.append(f"policy {k} = {_word(v)}" + (" (a forwarding grant)" if grant else ""))\n',
     '            out[-1:] = [(out[-1] + ", " if out and out[-1].startswith("policy ") else "policy ")'
     ' + f"{k} = {_word(v)}" + (" (a forwarding grant)" if grant else "")]\n',
     TP + "test_every_grant_a_new_host_brings_is_on_its_own_line_in_the_import_confirm"),
    ("a confirm line doesn't name its entry", TR,
     '                out.append(f"  - {shown}: {c}")\n',
     '                out.append("  - " + c)\n',
     TP + "test_every_grant_a_new_host_brings_is_on_its_own_line_in_the_import_confirm"),
    ("settings already waiting here are shown as the file's", TR,
     '            mine = {c.what for c in consent.compute(local_form, local_data).pending_for("settings")}\n',
     "            mine = set()\n",
     TP + "test_settings_already_waiting_here_are_never_shown_as_the_files"),
    ("the confirm leaves out the settings already waiting here", TR,
     '        if self.waiting_settings and self.changes.get("settings"):\n',
     "        if False:\n",
     TP + "test_settings_already_waiting_here_are_never_shown_as_the_files"),
    ("a peer import approves settings already waiting here", TR,
     "    mine_wait = settings and peer and bool(p.waiting_settings)\n",
     "    mine_wait = False\n",
     TP + "test_settings_already_waiting_here_are_never_shown_as_the_files"),
    ("file settings that need no OK approve the ones waiting here", TR,
     '    settings = ("settings" in p.replace or bool(p.settings_add)) and bool(p.changes.get("settings"))\n',
     '    settings = "settings" in p.replace or bool(p.settings_add)\n',
     TP + "test_settings_already_waiting_here_are_never_shown_as_the_files"),
    ("replaced settings aren't approved by the import's dialog (review R10)", TR,
     '    settings = ("settings" in p.replace or bool(p.settings_add)) and bool(p.changes.get("settings"))\n',
     '    settings = bool(p.settings_add) and bool(p.changes.get("settings"))\n',
     TP + "test_replaced_settings_are_approved_in_the_import_dialog_and_listed_once"),
    ("replaced and added settings list their lines twice", TR,
     '            if "settings" not in self.replace:      # else listed once, with the replace\n',
     "            if True:\n",
     TP + "test_replaced_settings_are_approved_in_the_import_dialog_and_listed_once"),
    ("the export message sends the user to a plain terminal", TR,
     '                + f" to {paths.describe(dest)} (passphrase-protected, mode 0600). To import it, "\n',
     '                + f" to {paths.describe(dest)} (passphrase-protected, mode 0600). Import it on the '
     'other machine with ~/.config/gateway/gate import FILE; To import it, "\n',
     TP + "test_the_export_message_points_at_importing_in_a_claude_code_session"),
    # --- §19.5: a stored Entra credential that doesn't fit -----------------------
    ("a credential made for other settings is used", S + "entra.py",
     "    if not acctmod.entra_fits(ap, vault.entra_info(a)):\n",
     "    if False:\n",
     "test_accounts_entra::test_a_credential_that_doesnt_fit_the_approved_account_is_refused_at_use"),
    ("an unapproved account's credential is used (review R6)", S + "entra.py",
     "    if ap is None:\n        raise EntraError(",
     "    if ap is None:\n        return e\n        raise EntraError(",
     "test_accounts_entra::test_an_account_that_isnt_approved_never_uses_its_stored_sign_in"),
    ("every PATH import named missing (review R8)", TR,
     "                if not os.path.isdir(where):\n",
     "                if True:\n",
     TP + "test_a_path_import_is_named_missing_only_when_it_isnt_a_folder_here"),
    # (Retired with the imported kind, PLAN-0.11 §19.12: a browser sign-in's
    # refresh token is never exported, so nothing is marked or labelled as
    # imported any more; mutations_integration.py holds the export's and the
    # import's mutations.)
    ("the account check sends a credential that doesn't fit (review should-fix 2)", S + "adapters.py",
     "    if e and (ap is None or not acctmod.entra_fits(ap, vault.entra_info(rec))):\n",
     "    if False:\n",
     "test_accounts_entra::test_the_account_check_never_sends_a_credential_that_doesnt_fit"),
    ("an approved sign-in change keeps the tokens minted before it", S + "consent.py",
     "                    # or scope go with them (PLAN-0.11 §19.5, WS-6)\n"
     "                    vault.cache_clear(entry)\n",
     "                    # or scope go with them (PLAN-0.11 §19.5, WS-6)\n"
     "                    pass\n",
     "test_accounts_entra::test_a_credential_that_doesnt_fit_the_approved_account_is_refused_at_use"),
]


def main(argv: list[str]) -> int:
    mutation_check.MUTATIONS = MUTATIONS
    return mutation_check.main(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
