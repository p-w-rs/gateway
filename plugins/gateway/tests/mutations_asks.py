#!/usr/bin/env python3
"""Mutation checks for WS-10a (lead decision 19.14): an "ask" is proved by
the approval hook's record for every stand-in (asks.py: the ssh, sudo and
account-CLI stand-ins pass an "ask" only for a command Claude typed with a
matching record; the hook records each stand-in stage it asks about and
refuses one whose words or folder it can't spell out; an account's use =
"ask" works for its CLI); program names compared without letter case (the
hook, pre_bash.sh, launch.sh's cold guard); the network class's new members
and a job's network class in its own mode. Its review's fixes: a record
lives until the session's next Bash or Monitor call (asks.drop, pre_bash.sh
while one is pending; dontAsk too, verify012); `gate with` honours the account's
use and credential policy; gate check / rotate / copy-to on an "ask" host
need the record; a hidden stage beside an asked one is recorded too; the
hook asks about the account the CLI stand-in chooses; pre_bash.sh sends a
plain account CLI only while an "ask" account exists; and the reviewer's
surviving mutations (R1, R3, R4, R5, R8, R9, R10). (The record's own
matching rules, shared with git, are in mutations_git.py.) Same format and
runner as
tests/mutation_check.py: each mutation removes or weakens one property; the
named test must then FAIL.

    pixi run --locked python tests/mutations_asks.py [-k SUBSTR] [--copy DIR]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutation_check  # noqa: E402

S = "src/gateway/"
AS = S + "asks.py"
HB = S + "hooks_bash.py"
SSH = S + "ssh.py"
SU = S + "sudo.py"
CL = S + "clis.py"
PB = "hooks/pre_bash.sh"
L = "hooks/launch.sh"
AR = "test_ask_records::"
SA = "test_ssh_ask::"
SS = "test_sudo_standin::"
N = "test_network::"
T = "test_hookbash_table::"

MUTATIONS = [
    # --- the stand-ins pass an "ask" only with the hook's record ---------------------------
    ("the ssh stand-in passes a typed command's ask with no record", SSH,
     "        return (True, \"\") if got == \"ok\" else (False, _UNASKED + got)\n",
     "        return True, \"\"\n",
     SA + "test_ssh_ask_with_the_real_process_tree"),
    ("the ssh stand-in takes another entry's record", SSH,
     "                           via or (\"hosts\", name))\n",
     "                           (\"hosts\", \"*\"))\n",
     SA + "test_ssh_ask_with_the_real_process_tree"),
    ("the sudo stand-in passes a typed command's ask with no record", SU,
     "            if got == \"ok\":\n                return None\n            return asks.refusal(",
     "            if True:\n                return None\n            return asks.refusal(",
     SS + "test_ask_needs_the_hooks_record_of_this_very_command"),
    ("the sudo stand-in's record is of other words", SU,
     "            got = asks.standin(\"sudo\", list(_CALL.get(\"argv\") or []), (\"hosts\", \"localhost\"))\n",
     "            got = asks.standin(\"sudo\", [], (\"hosts\", \"localhost\"))\n",
     SS + "test_ask_needs_the_hooks_record_of_this_very_command"),
    ("an account CLI uses an ask account with no record", CL,
     "    return None if got == \"ok\" else asks.refusal(got, [phrase], f\"{tool} ...\")\n",
     "    return None\n",
     AR + "test_an_account_cli_with_use_ask_is_asked_about_and_then_uses_the_account"),
    ("an account CLI uses an ask account from a script or a job", CL,
     "    if not typed:\n        if culprit == ancestry.CHECKPOINT:\n"
     "            return consent.job_ask_message([phrase])\n"
     "        if culprit == ancestry.TERMINAL:\n"
     "            return consent.pane_ask_message([phrase])\n        return CLI_ASK_SCRIPT",
     "    if False:\n        if culprit == ancestry.CHECKPOINT:\n"
     "            return consent.job_ask_message([phrase])\n"
     "        if culprit == ancestry.TERMINAL:\n"
     "            return consent.pane_ask_message([phrase])\n        return CLI_ASK_SCRIPT",
     AR + "test_an_account_cli_with_use_ask_is_asked_about_and_then_uses_the_account"),
    ("an account CLI's chosen ask account is never checked", CL,
     "    if sel.account is not None and sel.error is None and sel.account.name in asking:\n",
     "    if False:\n",
     AR + "test_an_account_cli_with_use_ask_is_asked_about_and_then_uses_the_account"),
    ("az hands a token for an account whose use is off or \"ask\"", CL,
     "    if not eff.accounts[a.name].use:\n",
     "    if False:\n",
     "test_accounts_clis::test_az_honours_the_accounts_use"),
    ("a record covers every entry a stand-in call meets", AS,
     "            return \"ok\" if want in held else \"none\"\n",
     "            return \"ok\"\n",
     AR + "test_a_stand_in_takes_its_record_once_per_call"),
    ("a stand-in call can't use its record twice (an ssh with a remote sudo fails)", AS,
     "            _HELD[(tool, argv)] = ents\n",
     "            pass\n",
     AR + "test_a_stand_in_takes_its_record_once_per_call"),
    # --- the hook records each stand-in stage it asks about --------------------------------
    ("the hook records no ssh or sudo stage", HB,
     "        if len(ask) > n0 and base in (\"ssh\", \"sudo\") and not (in_job or in_user_terminal):\n",
     "        if False:\n",
     AR + "test_the_hook_records_each_stand_in_stage_it_asks_about"),
    ("the hook asks about an account CLI but records nothing (refused after the OK)", HB,
     "            if len(ask) > n0 and not (in_job or in_user_terminal):\n"
     "                d = _pend(base, st, argv, here, [(\"accounts\", n)",
     "            if False:\n"
     "                d = _pend(base, st, argv, here, [(\"accounts\", n)",
     AR + "test_an_account_cli_with_use_ask_is_asked_about_and_then_uses_the_account"),
    ("the hook never asks about an account CLI's ask account", HB,
     "        return clis.ask_accounts(base, argv[1:], cwd, _eff_in(eff.form, mode), mode,\n"
     "                                 account, known)\n",
     "        return []\n",
     AR + "test_an_account_cli_with_use_ask_is_asked_about_and_then_uses_the_account"),
    ("the hook asks about an account CLI whose destination nothing configured covers", CL,
     "    covered, _target = destination(tool, argv, cwd, eff)\n    if not covered:\n        return []\n",
     "    covered, _target = destination(tool, argv, cwd, eff)\n",
     AR + "test_an_account_cli_with_use_ask_is_asked_about_and_then_uses_the_account"),
    ("a variable or glob in the words is recorded as written (refused after the OK)", HB,
     "    if any(flags(\"expands\")) or any(flags(\"globs\")):\n        return None\n",
     "    if False:\n        return None\n",
     AR + "test_words_or_a_folder_the_hook_cant_spell_out_are_refused_up_front"),
    ("a `~user` word is recorded as written", HB,
     "            if not homes or not (w == \"~\" or w.startswith(\"~/\")):\n                return None\n",
     "            if not homes:\n                return None\n",
     AR + "test_words_or_a_folder_the_hook_cant_spell_out_are_refused_up_front"),
    ("an unquoted $HOME is recorded as written", HB,
     "        if home:\n            if not homes:\n",
     "        if False:\n            if not homes:\n",
     AR + "test_the_hook_records_each_stand_in_stage_it_asks_about"),
    ("a folder a cd hides is recorded anyway", HB,
     "    if here is None:\n        return _deny(ASK_WHERE.format(",
     "    if False:\n        return _deny(ASK_WHERE.format(",
     AR + "test_words_or_a_folder_the_hook_cant_spell_out_are_refused_up_front"),
    ("text the parser can't follow gets no record (refused after the OK)", HB,
     "    for tool, words, entries, _ex in rest:\n        _ASK_PENDING.append(",
     "    for tool, words, entries, _ex in []:\n        _ASK_PENDING.append(",
     AR + "test_text_the_parser_cant_follow_is_recorded_where_it_can_be_read"),
    ("text whose ssh words can't be told is asked about (refused after the OK)", HB,
     "    if bad:\n        tool, example = bad[0]\n",
     "    if False:\n        tool, example = bad[0]\n",
     AR + "test_text_the_parser_cant_follow_is_recorded_where_it_can_be_read"),
    ("a variable in text the parser can't follow counts as written", HB,
     "        st[\"known\"] = False\n        st[\"started\"] = True\n        if text.startswith(\"$((\", j):\n",
     "        st[\"started\"] = True\n        if text.startswith(\"$((\", j):\n",
     AR + "test_text_the_parser_cant_follow_is_recorded_where_it_can_be_read"),
    # --- pre_bash.sh: a plain account CLI while its stand-in exists ------------------------
    ("pre_bash.sh never forwards a plain account CLI (its ask can't be recorded)", PB,
     "if [ -n \"$_clis\" ]; then\n",
     "if false; then\n",
     AR + "test_pre_bash_forwards_a_plain_account_cli_while_its_stand_in_exists"),
    # --- program names without letter case --------------------------------------------------
    ("the hook compares program names with their case", HB,
     "    return os.path.basename(word).lower()\n",
     "    return os.path.basename(word)\n",
     T + "test_posture_unconfigured_targets_get_no_decision_and_configured_ones_keep_every_guard"),
    ("the hook's network class compares names with their case", HB,
     "    return os.path.basename(word).lower()\n",
     "    return os.path.basename(word)\n",
     N + "test_program_names_are_compared_without_letter_case"),
    ("a user's extra name keeps its case", S + "consent.py",
     "                | {x.lower() for x in self.extra}) - {x.lower() for x in self.drop}\n",
     "                | set(self.extra)) - set(self.drop)\n",
     N + "test_program_names_are_compared_without_letter_case"),
    ("the text scan's tool paths keep their case ((/usr/bin/SSH box) passes)", HB,
     "_TEXT_TOOL_PATH = re.compile(rf\"[~$A-Za-z0-9_.{{}}/+-]*/((?i:{_TOOL_ALT}))(?![A-Za-z0-9_./-])\")\n",
     "_TEXT_TOOL_PATH = re.compile(rf\"[~$A-Za-z0-9_.{{}}/+-]*/({_TOOL_ALT})(?![A-Za-z0-9_./-])\")\n",
     T + "test_posture_unconfigured_targets_get_no_decision_and_configured_ones_keep_every_guard"),
    ("the text scan's network names keep their case ((CURL x) passes)", HB,
     "        rx = re.compile(r\"(?<![A-Za-z0-9_./:-])(?:[^\\s;&|()<>`:]*/)?((?i:\" + (alt + \"|\" if alt else \"\")\n",
     "        rx = re.compile(r\"(?<![A-Za-z0-9_./:-])(?:[^\\s;&|()<>`:]*/)?((?:\" + (alt + \"|\" if alt else \"\")\n",
     N + "test_program_names_are_compared_without_letter_case"),
    ("the text scan's slogin keeps its case", HB,
     "_TEXT_SLOGIN = re.compile(r\"(?<![\\w./-])slogin(?![\\w./-])\", re.I)\n",
     "_TEXT_SLOGIN = re.compile(r\"(?<![\\w./-])slogin(?![\\w./-])\")\n",
     T + "test_posture_unconfigured_targets_get_no_decision_and_configured_ones_keep_every_guard"),
    ("pre_bash.sh matches its trigger words with their case", PB,
     "if printf '%s' \"$words\" | grep -Eiq \"$pat\" 2>/dev/null; then\n",
     "if printf '%s' \"$words\" | grep -Eq \"$pat\" 2>/dev/null; then\n",
     N + "test_program_names_are_compared_without_letter_case"),
    ("pre_bash.sh's account-CLI routes keep their case (/usr/local/bin/GH)", PB,
     "    if printf '%s' \"$cmdw\" | grep -Eiq '/(gh|hf|databricks|crane|pijul|dvc)([^A-Za-z0-9_.-]|$)' 2>/dev/null; then\n",
     "    if printf '%s' \"$cmdw\" | grep -Eq '/(gh|hf|databricks|crane|pijul|dvc)([^A-Za-z0-9_.-]|$)' 2>/dev/null; then\n",
     "test_hookbash_prefilter::test_every_posture_deny_row_reaches_python"),
    ("the cold guard matches network names with their case", L,
     "  if printf '%s' \"$_dn\" | grep -Eiq -- \"(^|[^A-Za-z0-9_.-])($_names)",
     "  if printf '%s' \"$_dn\" | grep -Eq -- \"(^|[^A-Za-z0-9_.-])($_names)",
     "test_packaging::test_cold_bash_guard_asks_for_network_commands"),
    ("the cold guard misses php's server (-S)", L,
     " ||\n     printf '%s' \"$_dn\" | grep -Eq -- \"$DEG_NET_PHP\"; then\n",
     "; then\n",
     "test_packaging::test_cold_bash_guard_asks_for_network_commands"),
    # --- WS-10a review fixes: a record lives until the session's next call (MF1) -----------
    ("the hook keeps the records its earlier calls left", HB,
     "        if asks.drop():\n            return None\n",
     "        if True:\n            return None\n",
     AR + "test_a_record_left_by_an_earlier_call_serves_nothing_after_it"),
    ("drop keeps this session's records", AS,
     "            if s == me:\n                p.unlink()\n",
     "            if False:\n                p.unlink()\n",
     AR + "test_a_record_left_by_an_earlier_call_serves_nothing_after_it"),
    ("drop removes another session's live record too", AS,
     "            if s == me:\n                p.unlink()\n",
     "            if True:\n                p.unlink()\n",
     AR + "test_drop_takes_this_sessions_records_and_dead_ones_only"),
    ("drop keeps records no stand-in can take", AS,
     "            if t < now - ASK_TTL or t > now + FUTURE:\n                p.unlink()\n                continue\n",
     "",
     AR + "test_drop_takes_this_sessions_records_and_dead_ones_only"),
    ("drop says it cleared a record it couldn't remove", AS,
     "        except OSError:\n            ok = False\n    return ok\n",
     "        except OSError:\n            ok = True\n    return ok\n",
     AR + "test_drop_takes_this_sessions_records_and_dead_ones_only"),
    ("a record that couldn't be dropped lets the call go on", HB,
     "    return _deny(ASK_UNCLEARED, tool=\"Bash\", target=\"record\")\n",
     "    return None\n",
     AR + "test_drop_takes_this_sessions_records_and_dead_ones_only"),
    ("pre_bash.sh doesn't send a call to the hook while a record is pending", PB,
     "Bash|Monitor)\n  if [ -n \"$_gd\" ]; then\n    for _a in",
     "NoSuchTool)\n  if [ -n \"$_gd\" ]; then\n    for _a in",
     AR + "test_pre_bash_sends_every_call_to_the_hook_while_a_record_is_pending"),
    ("no $DATA/asks link for pre_bash.sh", AS,
     "    d.mkdir(mode=0o700, exist_ok=True)\n    _link(d)\n",
     "    d.mkdir(mode=0o700, exist_ok=True)\n",
     AR + "test_pre_bash_sends_every_call_to_the_hook_while_a_record_is_pending"),
    ("no record in dontAsk, where Claude Code asks too (verify012 bug B)", HB,
     "    if decision == \"ask\" and _ASK_PENDING and payload.get(\"tool_name\") in MANAGED_TOOLS:\n",
     "    if decision == \"ask\" and _ASK_PENDING and payload.get(\"tool_name\") in MANAGED_TOOLS \\\n"
     "            and _JUDGED[\"mode\"] != \"dontAsk\":\n",
     AR + "test_dontask_asks_too"),
    # --- gate with NAME -- CMD honours the account's use and credential policy (MF2) --------
    ("gate with hands over an account whose use is off", CL,
     "    if use != \"ask\" and not ea.use:\n        return WITH_OFF.format(name=name)\n",
     "",
     AR + "test_gate_with_honours_the_accounts_use_and_credential_policy"),
    ("gate with skips the credential policy", CL,
     "    if cred.word is not True and cred.word != \"ask\":\n        return cred.message(",
     "    if False:\n        return cred.message(",
     AR + "test_gate_with_honours_the_accounts_use_and_credential_policy"),
    ("gate with passes an ask with no record", CL,
     "    return None if got == \"ok\" else asks.refusal(got, [phrase], f\"gate with {name} -- ...\")\n",
     "    return None\n",
     AR + "test_gate_with_honours_the_accounts_use_and_credential_policy"),
    ("gate with passes an ask from a script, a job or a pane", CL,
     "    if not typed:\n        if culprit == ancestry.CHECKPOINT:\n"
     "            return consent.job_ask_message([phrase])\n"
     "        if culprit == ancestry.TERMINAL:\n"
     "            return consent.pane_ask_message([phrase])\n        return WITH_ASK_SCRIPT",
     "    if False:\n        if culprit == ancestry.CHECKPOINT:\n"
     "            return consent.job_ask_message([phrase])\n"
     "        if culprit == ancestry.TERMINAL:\n"
     "            return consent.pane_ask_message([phrase])\n        return WITH_ASK_SCRIPT",
     AR + "test_gate_with_honours_the_accounts_use_and_credential_policy"),
    ("gate with checks nothing", CL,
     "    why = _with_refused(resolved, ea, eff, [\"with\", *argv])\n    if why:\n",
     "    why = None\n    if why:\n",
     AR + "test_gate_with_honours_the_accounts_use_and_credential_policy"),
    ("the hook doesn't ask about gate with's ask account", HB,
     "            ask += _with_asks(argv, form, eff, [mode, None] if in_job else [mode])\n",
     "",
     AR + "test_gate_with_honours_the_accounts_use_and_credential_policy"),
    # --- gate check / rotate / copy-to on an "ask" host need the record (should-fix 1) ------
    ("the gate CLI's helpers trust the typed walk alone", SSH,
     "    return asks.current((\"hosts\", name)) == \"ok\"\n",
     "    return True\n",
     "test_ssh_setup::test_ssh_setup_helpers_honour_the_ssh_right"),
    ("the hook doesn't record a gate command it asks about", HB,
     "            if len(ask) > n0 and not (in_job or in_user_terminal):\n"
     "                # the gate CLI passes",
     "            if False:\n                # the gate CLI passes",
     "test_ssh_setup::test_ssh_setup_helpers_honour_the_ssh_right"),
    ("current() answers without a command begun", AS,
     "    if not _CURRENT:\n        return \"none\"\n",
     "    if not _CURRENT:\n        return \"ok\"\n",
     AR + "test_a_stand_in_takes_its_record_once_per_call"),
    # --- hidden stages beside another ask (should-fix 3) ------------------------------------
    ("a hidden stage beside an asked one gets no record", HB,
     "    if hidden:\n        # a shell, eval or exec",
     "    if hidden and not ask:\n        # a shell, eval or exec",
     AR + "test_a_hidden_stage_beside_another_ask_is_asked_about_and_recorded_too"),
    ("the prompt for text the parser can't follow names only the first target", HB,
     "        asks = list(dict.fromkeys(more0 + fbs + more_fb))\n",
     "        asks = list(dict.fromkeys(more0 + fbs[:1] + more_fb))\n",
     AR + "test_a_hidden_stage_beside_another_ask_is_asked_about_and_recorded_too"),
    ("a command the structured judge recorded is recorded twice", HB,
     "        if have.get(key, 0) > 0:\n            have[key] -= 1\n            continue\n",
     "",
     AR + "test_a_hidden_stage_beside_another_ask_is_asked_about_and_recorded_too"),
    # --- account CLI asks follow the stand-in's choice (should-fix 4) -----------------------
    ("the hook asks about every ask account, not the one the stand-in picks", CL,
     "    names = list(verbs) if not known else chosen(tool, argv, cwd, eff, mode, account)\n",
     "    names = list(verbs)\n",
     AR + "test_account_cli_asks_follow_the_stand_ins_own_choice"),
    ("the hook reads no GATE_ACCOUNT from the command", HB,
     "    if env is not None and \"GATE_ACCOUNT\" in env:\n",
     "    if False:\n",
     AR + "test_account_cli_asks_follow_the_stand_ins_own_choice"),
    ("an account CLI in text the parser can't follow gets no record", HB,
     "        elif clis_too and eff is not None and (\n",
     "        elif False and (\n",
     AR + "test_account_cli_asks_follow_the_stand_ins_own_choice"),
    # --- a plain account CLI goes to the hook only while an "ask" account exists (should-fix 7)
    ("pre_bash.sh sends every account CLI with a stand-in to the hook", PB,
     "  if [ -f \"$_gd/ask-clis\" ]; then\n",
     "  if false; then\n",
     AR + "test_pre_bash_forwards_a_plain_account_cli_while_its_stand_in_exists"),
    ("ask-clis misses an account that is ask in one mode only", S + "consent.py",
     "               for n, ea in eff.accounts.items() for m in modes.KEYS):\n",
     "               for n, ea in eff.accounts.items() for m in (\"default\",)):\n",
     AR + "test_python_keeps_the_list_of_clis_an_ask_account_serves"),
    ("a locked vault empties ask-clis", S + "consent.py",
     "        if not eff.unreadable:         # (a locked vault keeps the last list)\n",
     "        if True:\n",
     AR + "test_python_keeps_the_list_of_clis_an_ask_account_serves"),
    # --- the reviewer's surviving mutations (should-fix 5) ----------------------------------
    ("R1 an ask policy restriction passes a typed command with no record", SSH,
     "            asked, by = _asked(name, via=(\"hosts\", name) if act in (\"read\", \"write\") else None)\n",
     "            asked, by = (_typed() if act not in (\"read\", \"write\") else\n"
     "                         _asked(name, via=(\"hosts\", name)))\n",
     SA + "test_a_typed_command_needs_the_hooks_record_for_every_ask_it_meets"),
    ("R4 a remote elevation ask passes a typed command with no record", SSH,
     "            if d.word == \"ask\":\n                asked, by = _asked(name)\n",
     "            if d.word == \"ask\":\n                asked, by = _typed()\n",
     SA + "test_a_typed_command_needs_the_hooks_record_for_every_ask_it_meets"),
    ("R3 a sudo ask after the dialog passes a typed command with no record", SSH,
     "        asked, by = _asked(name)          # the record this call took (asks.standin)\n",
     "        asked, by = _typed()\n",
     "test_ssh_sudo::test_ssh_sudo_dialog_names_its_rights_offers_remember_and_rechecks_before_use"),
    ("R8 the record check fails open", AS,
     "    except Exception:  # noqa: BLE001 - fail closed\n        return \"none\"\n",
     "    except Exception:  # noqa: BLE001 - fail closed\n        return \"ok\"\n",
     AR + "test_a_stand_in_takes_its_record_once_per_call"),
    ("R5 a record dated ahead counts", AS,
     "        if t > now + FUTURE:\n            continue                      # from the future: not this hook's\n",
     "",
     AR + "test_a_record_is_this_very_command_used_once_and_for_15_minutes"),
    ("R9 the text scan's shell -c keeps its letter case", HB,
     "    r\"(?<![\\w./-])(?:\\S*/)?(?i:\" + \"|\".join(sorted(_SHELLS | {\"su\", \"runuser\"})) +\n",
     "    r\"(?<![\\w./-])(?:\\S*/)?(?:\" + \"|\".join(sorted(_SHELLS | {\"su\", \"runuser\"})) +\n",
     T + "test_decision_table_auto_and_default"),
    ("R10 the hidden-command text keeps osascript's letter case", HB,
     "    r\"|(?<![\\w.-])(?i:osascript)\\s[^;&|\\n]*?-e\\s*[$`]\")\n",
     "    r\"|(?<![\\w.-])(?:osascript)\\s[^;&|\\n]*?-e\\s*[$`]\")\n",
     T + "test_decision_table_auto_and_default"),
    # --- the network class's new members ---------------------------------------------------
    ("tcpdump isn't a member", S + "form.py",
     "    \"tcpdump\", \"tshark\", \"nikto\",",
     "    \"tshark\", \"nikto\",",
     N + "test_the_three_built_in_lists_are_equal"),
    ("pre_bash.sh doesn't forward iperf3", PB,
     "|arp-scan|iperf3'\n",
     "|arp-scan'\n",
     N + "test_the_three_built_in_lists_are_equal"),
    ("the cold guard misses nuclei", L,
     "|ffuf|nuclei|arp-scan|iperf3'\n",
     "|ffuf|arp-scan|iperf3'\n",
     N + "test_the_three_built_in_lists_are_equal"),
]


def main(argv: list[str]) -> int:
    mutation_check.MUTATIONS = MUTATIONS
    return mutation_check.main(argv)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
