#!/usr/bin/env python3
"""Mutation checks for terminals and jobs (PLAN-v4 phase 5): one writer at a
time (user takeover fails queued agent input, the stale-seq refusal, handing
back needs a fresh read, one agent holds the input, other sessions can't
write), the password-prompt path (the dialog's value only to the prompt it
was asked for, never on a command line, masked afterwards, refused typing
meanwhile), the managed environment (no user rc, no user tmux config, no
credential-looking variable, no TMUX), scrubbing, truthful survival (gone and
unknown), the planes (only the gw MCP server's tools, only the mod's pane),
the contract's session binding, the approval hook and permission decisions
for the gw tools, the sudo stand-in's terminal route, and the mod's pane.
Same format and runner as tests/mutation_check.py: each mutation removes or
weakens one property; the named test must then FAIL.

    pixi run --locked python tests/mutations_terminals.py [-k SUBSTR] [--copy DIR]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutation_check  # noqa: E402

S = "src/gateway/daemon/terminals.py"
T = "test_terminals::"
MOD = "test_mod::test_claude_plugin_test_runs_the_mods_tests"

DELIVERY = '''            with p.write_lock:
                with self.lock:
                    if p.owner_gen != gen:
                        raise TermError(409, "taken", f"gateway: {TAKEN}", owner=p.owner, seq=p.seq)
                    self._writable(p, who, agent)
                cap = self._capture(p)
                with self.lock:
                    if p.owner_gen != gen:
                        raise TermError(409, "taken", f"gateway: {TAKEN}", owner=p.owner, seq=p.seq)
'''
DELIVERY_UNCHECKED = '''            with p.write_lock:
                cap = self._capture(p)
                with self.lock:
'''

MUTATIONS = [
    # --- one writer at a time ---------------------------------------------------------
    ("a send that quotes an old seq is typed anyway", S,
     "        return current != quoted\n", "        return False\n",
     T + "test_reads_are_bounded_and_a_send_must_quote_the_current_seq"),
    ("a queued agent write is typed after the user took the input", S, DELIVERY, DELIVERY_UNCHECKED,
     T + "test_user_takeover_fails_a_queued_agent_write_and_handing_back_needs_a_fresh_read"),
    ("the agent types while the user holds the input", S,
     '        if p.owner == "user":\n            raise TermError(409, "user", USER_HOLDS)\n        if p.holder',
     "        if p.holder",
     T + "test_user_takeover_fails_a_queued_agent_write_and_handing_back_needs_a_fresh_read"),
    ("handing back keeps the seq, so the agent types without reading again", S,
     '        p.seq += 1\n        self._changed()\n        self._emit("terminal.owner"',
     '        self._changed()\n        self._emit("terminal.owner"',
     T + "test_user_takeover_fails_a_queued_agent_write_and_handing_back_needs_a_fresh_read"),
    ("any agent types while another holds the input", S,
     '        if p.holder is not None and agent != p.holder:\n', "        if False:\n",
     T + "test_one_agent_holds_the_input_and_another_takes_it_with_a_read"),
    ("the main agent (empty id) never claims the input, so a subagent writes into it", S,
     "                    if p.holder is None:\n                        p.holder = agent\n",
     "                    if agent and p.holder is None:\n                        p.holder = agent\n",
     T + "test_the_main_agent_holds_its_terminal_against_a_subagent"),
    ("an agent takes the input from the user", S,
     '            if p.owner == "user":\n                raise TermError(409, "user", USER_HOLDS)\n'
     '            if p.session_key() != session_key(who):\n                if self._live_session(p) is not None:',
     '            if p.session_key() != session_key(who):\n                if self._live_session(p) is not None:',
     T + "test_one_agent_holds_the_input_and_another_takes_it_with_a_read"),
    ("another Claude Code session types into a terminal", S,
     '        if p.session_key() != session_key(who):\n            raise TermError(403, "other_session", f"gateway: {p.id} belongs to another Claude Code "\n'
     '                            "session" +',
     '        if False:\n            raise TermError(403, "other_session", f"gateway: {p.id} belongs to another Claude Code "\n'
     '                            "session" +',
     T + "test_another_session_may_read_but_not_write_and_adopts_only_an_orphan"),
    # --- password prompts --------------------------------------------------------------
    ("the agent types into a waiting password prompt", S,
     '        if p.auth is not None and p.auth.get("state") == "asking":\n', "        if False:\n",
     T + "test_a_password_prompt_goes_through_the_dialog_to_that_pane_only_and_is_never_logged"),
    ("typed text from the pane goes to a password prompt", S,
     "                    if p.echo_off:\n                        refused = True\n                        continue\n"
     "                    self._deliver(p, t, [], False)",
     "                    self._deliver(p, t, [], False)",
     T + "test_a_password_prompt_goes_through_the_dialog_to_that_pane_only_and_is_never_logged"),
    ("the dialog's value goes to tmux on its command line", S,
     '            self.tmux.run("load-buffer", "-b", buf, "-", input=value.encode("utf-8"))\n'
     '            self.tmux.run("paste-buffer", "-d", "-b", buf, "-t", p.target)\n',
     '            self.tmux.run("send-keys", "-t", p.target, "-l", value)\n',
     T + "test_a_password_prompt_goes_through_the_dialog_to_that_pane_only_and_is_never_logged"),
    ("a supplied value isn't masked when the program prints it", S,
     "        # masked and noted before it goes in: the program may print before this returns\n"
     "        with self.lock:\n            before = p.last_auth\n"
     "            added = len(value) >= 8 and value not in p.secrets\n",
     "        # masked and noted before it goes in: the program may print before this returns\n"
     "        with self.lock:\n            before = p.last_auth\n"
     "            added = False\n",
     T + "test_a_password_prompt_goes_through_the_dialog_to_that_pane_only_and_is_never_logged"),
    ("the value goes in without checking the prompt still waits (same process group)", S,
     "        if mode is None or mode[0] or not mode[1] or foreground_pgrp(p.pane_pid) != tp:\n",
     "        if False:\n",
     T + "test_a_value_is_typed_only_into_the_prompt_it_was_asked_for"),
    # --- the managed environment ------------------------------------------------------
    ("any variable from the caller reaches the pane", S,
     "        if platform or (name in allowed_imports and not managed.credential_like(name)) or \\\n",
     "        if True or \\\n",
     T + "test_a_terminal_runs_the_gateway_bash_in_the_managed_environment_never_the_users_setup"),
    ("the pane keeps TMUX (its programs could drive the gateway's tmux)", S,
     'KEEP_NAMES = ("HOME|USER|LOGNAME', 'KEEP_NAMES = ("TMUX|TMUX_PANE|HOME|USER|LOGNAME',
     T + "test_a_terminal_runs_the_gateway_bash_in_the_managed_environment_never_the_users_setup"),
    ("the terminal's bash reads the user's rc", S,
     '            self._new_session(p, [bash, "--noprofile", "--rcfile", str(me), "-i"])',
     '            self._new_session(p, [bash, "-i"])',
     T + "test_a_terminal_runs_the_gateway_bash_in_the_managed_environment_never_the_users_setup"),
    ("tmux reads the user's ~/.tmux.conf", S,
     '        return [self.binary, "-u", "-S", str(self.sock), "-f", str(self.conf), *args]',
     '        return [self.binary, "-u", "-S", str(self.sock), *args]',
     T + "test_a_terminal_runs_the_gateway_bash_in_the_managed_environment_never_the_users_setup"),
    ("the pane's shell isn't where the stand-ins' direct rule starts (no CLAUDE_PID)", S,
     '    lines.append("export CLAUDE_PID=$$")\n', "",
     T + "test_a_terminal_runs_the_gateway_bash_in_the_managed_environment_never_the_users_setup"),
    # --- scrubbing ---------------------------------------------------------------------
    ("terminal reads aren't scrubbed", S,
     '        text = scrub.scrub_text("\\n".join(lines), extra=list(p.secrets))\n',
     '        text = "\\n".join(lines)\n',
     T + "test_vault_values_are_masked_in_terminal_reads_job_tails_and_the_pane_view"),
    ("job tails aren't scrubbed", S,
     "        text = scrub.scrub_text(text, extra=list(p.secrets))\n", "        text = text\n",
     T + "test_vault_values_are_masked_in_terminal_reads_job_tails_and_the_pane_view"),
    ("the terminal title isn't scrubbed (a value a program puts there leaks)", S,
     "        return _clean(scrub.scrub_text(s[:1000], extra=list(p.secrets)), limit)\n",
     "        return _clean(s, limit)\n",
     T + "test_a_vault_value_in_the_terminal_title_is_masked_everywhere"),
    ("a value split across a wrap boundary reaches the agent unmasked", S,
     "        joined = self._capture_joined(p, history=hist_n)\n", "        joined = None\n",
     T + "test_a_vault_value_split_across_a_wrap_boundary_is_masked"),
    # --- survival: ask tmux, never assume ---------------------------------------------
    ("records are taken as alive without asking tmux (adoption and the tick)", S,
     '        return info is None or info.get("@gw_nonce") != p.nonce\n', "        return False\n",
     T + "test_gated_restart_readopts_live_panes_and_a_lost_supervisor_is_reported_never_assumed"),
    ("a seq read before a gated restart still counts after it", S,
     "                p.seq += 1\n                if p.kind == \"job\" and p.alive:\n",
     "                if p.kind == \"job\" and p.alive:\n",
     T + "test_a_seq_read_before_a_gated_restart_is_stale_after_it"),
    ("the handed-out seq isn't persisted, so a restart's bump lands on it", S,
     "                    p.seq += 1\n                    if persist:\n                        self._save()\n",
     "                    p.seq += 1\n",
     T + "test_a_seq_from_screen_changes_not_yet_persisted_is_stale_after_a_restart"),
    ("a transient list-panes failure marks live panes gone", S,
     "        transient = query_failed and self._blip(fetched)\n",
     "        transient = False\n",
     T + "test_a_transient_list_panes_failure_doesnt_mark_live_panes_gone"),
    ("the interrupt escalation isn't re-armed after a restart", S,
     "                    if p.paused_as == \"interrupted\":\n"
     "                        # the SIGTERM timer died with the old gated; keep the\n"
     "                        # promise this restart would otherwise have dropped\n"
     "                        self._arm_term_escalation(p)\n",
     "                    if False:\n                        pass\n",
     T + "test_the_interrupt_escalation_survives_a_gated_restart"),
    ("the agent resumes a suspended job while the task is paused", S,
     "                if name in (\"CONT\",) and (self._paused(p.session_key()) or\n"
     "                                          self._paused(session_key(who))):\n"
     "                    raise TermError(409, \"paused\", PAUSED)\n",
     "                if False:\n                    raise TermError(409, \"paused\", PAUSED)\n",
     T + "test_a_paused_session_cannot_resume_a_suspended_job_with_cont"),
    ("terminal_list / job_list aren't bounded for the agent", S,
     "        if total > limit:\n", "        if False:\n",
     T + "test_terminal_list_and_job_list_are_bounded_for_the_agent"),
    ("an unknown job reports a concrete ended time", S,
     "            ended = None if p.state == \"unknown\" else (round(p.ended, 3) if p.ended else None)\n",
     "            ended = round(p.ended, 3) if p.ended else None\n",
     T + "test_gated_restart_readopts_live_panes_and_a_lost_supervisor_is_reported_never_assumed"),
    ("a pane with another nonce (not the one gated started) is adopted", S,
     '        return info is None or info.get("@gw_nonce") != p.nonce\n', "        return info is None\n",
     T + "test_a_pane_without_its_nonce_is_never_adopted"),
    ("a pane tmux lost while gated runs stays \"running\"", S,
     "                    elif p.created < fetched:      # (one started meanwhile isn't listed yet)\n",
     "                    elif False:\n",
     T + "test_gated_restart_readopts_live_panes_and_a_lost_supervisor_is_reported_never_assumed"),
    ("a suspend is reported without the job being stopped", S,
     "                stopped = self._stop_group(p, pg)\n", "                stopped = True\n",
     T + "test_on_pause_policies_report_what_actually_happened_and_resume_undoes_a_suspend"),
    ("closing a terminal leaves its tmux session running", S,
     '            self._tm(p).run("kill-session", "-t", f"={p.id}", check=False)\n'
     '        except TermError as e:\n            self._close_failed(p, prev, e)\n',
     '            pass\n        except TermError as e:\n            self._close_failed(p, prev, e)\n',
     T + "test_closing_a_terminal_ends_its_session_and_says_so"),
    ("a process inside a terminal doesn't belong to the pane's session (no mapping)",
     "src/gateway/daemon/lifecycle.py",
     "        self.registry.pane_session = self.terminals.session_for_pid\n", "",
     T + "test_a_process_inside_a_terminal_belongs_to_its_owner_session_while_that_lives"),
    ("a removed run dir leaves the unreachable tmux server running", "src/gateway/daemon/lifecycle.py",
     '            if self.stop_reason == "socket gone":\n                self.terminals.abandon()\n', "",
     T + "test_a_removed_run_dir_takes_the_unreachable_tmux_server_with_gated"),
    ("live terminals don't keep gated from its idle exit", "src/gateway/daemon/lifecycle.py",
     "        return self.terminals.busy()\n", '        return ""\n',
     T + "test_live_panes_keep_gated_from_idle_exit_and_restart"),
    # --- an uninstall while work runs; the tmux server after gated (0.9.1) --------------
    ("an uninstall that deletes the data folder isn't noticed (gated serves on)",
     "src/gateway/daemon/lifecycle.py",
     "        return not self.data_root.is_dir()\n", "        return False\n",
     T + "test_an_uninstall_while_a_job_runs_drains_gated_and_it_leaves_with_its_tmux_after_the_job"),
    ("a draining gated starts new terminals and jobs", S,
     '        if getattr(self.d, "draining", ""):\n            raise TermError(503, "draining", DRAINING)\n',
     '        if False:\n            raise TermError(503, "draining", DRAINING)\n',
     T + "test_an_uninstall_while_a_job_runs_drains_gated_and_it_leaves_with_its_tmux_after_the_job"),
    ("a draining gated leaves while a job still runs", "src/gateway/daemon/lifecycle.py",
     "                    if not self.busy_here():\n", "                    if True:\n",
     T + "test_an_uninstall_while_a_job_runs_drains_gated_and_it_leaves_with_its_tmux_after_the_job"),
    ("a pane record recreates the data folder an uninstall removed", S,
     "            self.state_path.parent.mkdir(exist_ok=True)\n",
     "            self.state_path.parent.mkdir(parents=True, exist_ok=True)\n",
     T + "test_an_uninstall_while_a_job_runs_drains_gated_and_it_leaves_with_its_tmux_after_the_job"),
    ("with its tmux deleted every failed query is a blip again (gated waits forever)", S,
     "        blind = query_failed and not self.tmux.runnable()\n", "        blind = False\n",
     T + "test_a_draining_gated_whose_tmux_was_deleted_watches_the_panes_processes"),
    ("with its tmux deleted a pane whose process still runs is called gone", S,
     "                        if p.pane_pid and peers.alive(p.pane_pid, p.pane_start):\n"
     "                            continue\n", "",
     T + "test_a_draining_gated_whose_tmux_was_deleted_watches_the_panes_processes"),
    ("with its tmux deleted the server is left running when gated exits", S,
     "            os.kill(pid, signal.SIGTERM)\n        self.d.log(\"terminals: no terminal or job runs and",
     "            pass\n        self.d.log(\"terminals: no terminal or job runs and",
     T + "test_a_draining_gated_whose_tmux_was_deleted_watches_the_panes_processes"),
    ("gated exits leaving its tmux server and watchdog with nothing running", S,
     "        if tm is None:\n            return\n        if tm.runnable():\n",
     "        if True:\n            return\n        if tm.runnable():\n",
     T + "test_a_gated_that_exits_with_nothing_running_stops_its_tmux_server"),
    ("gated stops its tmux server though a pane still runs (a restart can't re-adopt it)", S,
     "            if live:\n                self.d.log(", "            if False:\n                self.d.log(",
     T + "test_a_stopped_gateds_tmux_server_goes_with_its_socket_and_ends_with_its_last_session"),
    ("the watchdog never stops the server when gated is gone", S,
     "    '[ -n \"$g\" ] || continue; '\n", "    'continue; '\n",
     T + "test_the_watchdog_stops_the_server_once_gated_is_gone_and_no_pane_runs"),
    ("the watchdog stops the server though a pane still runs", S,
     "    '[ \"$n\" -ge 1 ] 2>/dev/null || continue; [ \"$n\" -gt 1 ] || break; '\n", "    'break; '\n",
     T + "test_the_watchdog_stops_the_server_once_gated_is_gone_and_no_pane_runs"),
    # --- re-fix (refix-gw): a killed gated, a job suspended at an uninstall, an update's sweep
    ("the watchdog takes a killed gated's leftover socket file for a live gated", S,
     "    'if [ -S \"$g\" ]; then [ -n \"$f\" ] && [ -f \"$f\" ] || continue; p=; l=; '\n",
     "    'if [ -S \"$g\" ]; then continue; p=; l=; '\n",
     T + "test_the_watchdog_stops_the_server_once_gated_was_killed_and_only_a_dead_pane_is_left"),
    ("gated writes no pid file for its watchdog", "src/gateway/daemon/lifecycle.py",
     "        self.write_pid()\n        self.bind()\n", "        self.bind()\n",
     T + "test_the_watchdog_stops_the_server_once_gated_was_killed_and_only_a_dead_pane_is_left"),
    ("the watchdog takes any live process with gated's pid for gated (a reused pid)", S,
     "    'case \"$1\" in Z*) ;; *) shift; [ -n \"$l\" ] && [ \"$*\" != \"$l\" ] || continue;; esac; '\n",
     "    'continue; '\n",
     T + "test_the_watchdog_stops_the_server_once_gated_was_killed_and_only_a_dead_pane_is_left"),
    ("gated records its start time in another time zone than its watchdog reads", S,
     "                           text=True, timeout=5, env=dict(PS_ENV), stdin=subprocess.DEVNULL)\n",
     "                           text=True, timeout=5, env={**PS_ENV, \"TZ\": \"EST5\"}, "
     "stdin=subprocess.DEVNULL)\n",
     T + "test_the_watchdog_stops_the_server_once_gated_was_killed_and_only_a_dead_pane_is_left"),
    ("the watchdog reads gated's start time in another time zone than gated wrote it", S,
     "    'c=$(LC_ALL=C TZ=UTC0 ps -o stat= -o lstart= -p \"$p\" 2>/dev/null) || continue; '\n",
     "    'c=$(LC_ALL=C TZ=EST5 ps -o stat= -o lstart= -p \"$p\" 2>/dev/null) || continue; '\n",
     T + "test_the_watchdog_stops_the_server_once_gated_was_killed_and_only_a_dead_pane_is_left"),
    ("a draining gated leaves a suspended job stopped (nothing could resume it)",
     "src/gateway/daemon/lifecycle.py",
     "            resumed = self.terminals.resume_stopped()\n", "            resumed = []\n",
     T + "test_a_job_left_suspended_at_an_uninstall_is_resumed_and_gated_leaves_after_it"),
    ("a draining gated takes a new pause", "src/gateway/daemon/lifecycle.py",
     "            if self.draining:\n                return False\n",
     "            if False:\n                return False\n",
     T + "test_a_job_left_suspended_at_an_uninstall_is_resumed_and_gated_leaves_after_it"),
    ("an update's sweep of the old version folder drains its gated like an uninstall",
     "src/gateway/daemon/lifecycle.py",
     "        if self.plugin_removed() and not self.newer_sibling():\n",
     "        if self.plugin_removed():\n",
     T + "test_an_updates_sweep_of_the_old_version_folder_is_no_uninstall"),
    ("a swept old version's gated stays though nothing runs", "src/gateway/daemon/lifecycle.py",
     "                if replaced and not self.busy():\n", "                if False:\n",
     T + "test_an_updates_sweep_of_the_old_version_folder_is_no_uninstall"),
    # --- planes and the contract ------------------------------------------------------
    ("any gateway entry point uses the terminal routes", "src/gateway/daemon/planes.py",
     'TERM_MODES = ("mcp",)', 'TERM_MODES = ("mcp", "gate", "hook-", "shim")',
     T + "test_terminal_routes_are_the_mcp_servers_and_the_panes_alone"),
    ("a process below the session takes a terminal on the UI plane's route", "src/gateway/daemon/server.py",
     '    ("POST", "/ui/term/take"): ("ui", r_ui_term_take),',
     '    ("POST", "/ui/term/take"): ("contract", r_ui_term_take),',
     T + "test_terminal_routes_are_the_mcp_servers_and_the_panes_alone"),
    ("a contract job names another session than its caller's", "src/gateway/daemon/server.py",
     '    if sid not in (None, "") and s is not None and s.session_id and sid != s.session_id:\n',
     "    if False:\n",
     T + "test_contract_job_routes_events_snapshot_and_their_plane"),
    # --- the approval hook and the permission decisions ----------------------------------
    ("terminal_send's text isn't judged by the Bash hook", "src/gateway/hooks_bash.py",
     '    if payload.get("tool_name") == GW_SEND_TOOL:\n', "    if False:\n",
     T + "test_the_approval_hook_judges_what_gw_jobs_run_and_terminals_are_sent"),
    ("a gw job's command isn't judged by the Bash hook", "src/gateway/hooks_bash.py",
     '    if payload.get("tool_name") in (JOB_TOOL, GW_JOB_TOOL):\n',
     '    if payload.get("tool_name") == JOB_TOOL:\n',
     T + "test_the_approval_hook_judges_what_gw_jobs_run_and_terminals_are_sent"),
    ("the Bash hook's matcher leaves terminal_send out", "hooks/hooks.json",
     "|mcp__plugin_gate_gw__job_start|mcp__plugin_gate_gw__terminal_send\"", "|mcp__plugin_gate_gw__job_start\"",
     T + "test_the_bash_hook_sees_the_gw_tools_that_type_or_run"),
    ("terminal_send is allowed without a prompt", "hooks/mcp_perm.sh",
     '      tool == "mcp__plugin_gate_gw__job_list") { print "allow-term-read"; exit }',
     '      tool == "mcp__plugin_gate_gw__job_list" || tool == "mcp__plugin_gate_gw__terminal_send") { print "allow-term-read"; exit }',
     T + "test_mcp_perm_allows_only_reads_and_an_idle_open"),
    ("job_start is allowed without a prompt", "hooks/mcp_perm.sh",
     '  if (tool == "mcp__plugin_gate_gw__terminal_resize") { print "allow-term-open"; exit }',
     '  if (tool == "mcp__plugin_gate_gw__terminal_resize" || tool == "mcp__plugin_gate_gw__job_start") { print "allow-term-open"; exit }',
     T + "test_mcp_perm_allows_only_reads_and_an_idle_open"),
    # --- the sudo stand-in's terminal route ----------------------------------------------
    ("in a terminal the sudo stand-in skips the form's sudo right", "src/gateway/sudo.py",
     "    data, msg, scripts = _rights_now()\n    if msg is not None:\n",
     "    data, msg, scripts = _rights_now()\n    if msg is not None and not _in_gateway_terminal():\n",
     T + "test_the_sudo_stand_in_hands_a_gateway_terminal_to_the_real_sudo_on_its_tty"),
    ("any GW_TERMINAL value counts as a gateway terminal", "src/gateway/sudo.py",
     '    if not re.fullmatch(r"[tj]_[0-9A-HJKMNP-TV-Z]{26}", t):\n', "    if not t:\n",
     T + "test_the_sudo_stand_in_hands_a_gateway_terminal_to_the_real_sudo_on_its_tty"),
    ("sudo -S is allowed in a gateway terminal", "src/gateway/sudo.py",
     "    if _has_S_or_A(argv):\n", "    if _has_S_or_A(argv) and not _in_gateway_terminal():\n",
     T + "test_the_sudo_stand_in_hands_a_gateway_terminal_to_the_real_sudo_on_its_tty"),
    # --- the mod's pane ------------------------------------------------------------------
    ("the pane's Client sends typed text to a password prompt", "hooks/mod/term.tsx",
     "    if (r.item.k === 'text' && me.props.echoOff) {\n", "    if (false) {\n", MOD),
    ("a click into the screen doesn't take the input", "hooks/mod/term.tsx",
     "    send([], true)\n    update({ note: '' })\n", "    update({ note: '' })\n", MOD),
    ("the main screen offers its line field during a password prompt", "hooks/mod/register.tsx",
     "!v.echoOff && e.surface !== 'mobile'", "e.surface !== 'mobile'", MOD),
    ("a re-sent batch of keys is typed twice", "hooks/mod/register.tsx",
     "        if ((TS.forwarded[inst] ?? 0) >= b.seq) continue\n", "", MOD),
    ("gated never hears which agent loop called a terminal tool", "hooks/mod/register.tsx",
     "{ tool_use_id: tid, agent: e.agentId ?? '' }", "{ tool_use_id: tid, agent: '' }", MOD),
    ("a stopped gated's tmux server outlives its removed socket (no watchdog)", S,
     "            threading.Thread(target=self._watch, daemon=True, name=\"gw-tmux-watch\").start()\n",
     "            pass\n",
     T + "test_a_stopped_gateds_tmux_server_goes_with_its_socket_and_ends_with_its_last_session"),
    ("the watchdog keeps an empty tmux server alive", S,
     "                f.write(TMUX_CONF + LOCAL_TMUX_CONF)", "                f.write(TMUX_CONF)",
     T + "test_a_stopped_gateds_tmux_server_goes_with_its_socket_and_ends_with_its_last_session"),
]

if __name__ == "__main__":
    mutation_check.MUTATIONS = MUTATIONS
    raise SystemExit(mutation_check.main(sys.argv[1:]))
