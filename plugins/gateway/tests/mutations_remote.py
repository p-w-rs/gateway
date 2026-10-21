#!/usr/bin/env python3
"""Mutation checks for the managed remote runtime (PLAN-v4 phase 6): host
binding (the host record's marker in the runtime folder, panes bound to their
host and machine), the changed host key and machine id gates, the sha256
verification (on the host and read back), no secret on any command line,
honest states (disconnected and waiting_auth never ended, a lost pane
unknown, a stale seq after a reconnect), safe cleanup of old runtime
versions, the rights (ssh "ask"/false, sudo off), staging failures reported
with their remedy, the managed environment, the approval hook and the
permission decisions for remote work; since the review fixes: lost answers
(a start or an input whose answer was lost is never "not done" and never runs
twice; the start file's claim), a failed list-panes is a blip, a close the
host didn't get is no cancel, the root-password rule over the whole foreground
group, the machine-token host form in the approval hook, stale host status.
Same format and runner as
tests/mutation_check.py: each mutation removes or weakens one property; the
named test must then FAIL.

    pixi run --locked python tests/mutations_remote.py [-k SUBSTR] [--copy DIR]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutation_check  # noqa: E402

R = "src/gateway/daemon/remote.py"
S = "src/gateway/daemon/terminals.py"
P = "src/gateway/runtime_pack.py"
T = "test_remote::"

MUTATIONS = [
    # --- host binding --------------------------------------------------------------------
    ("gated leaving stops any tmux server that took its old pid", S,
     "        if exe and os.path.realpath(exe) == binary and str(self.sock) in av:\n",
     "        if exe and os.path.realpath(exe) == binary:\n",
     T + "test_gated_leaving_never_stops_another_tmux_server_that_took_its_old_pid"),
    ("a command for a runtime runs without the host record's marker check", R,
     '                pre = bind_check(rt, self.host_id, str(self.info.get("nonce") or "-"))\n',
     '                pre = ""\n',
     T + "test_two_hosts_never_mix_their_work_and_a_wrong_runtime_runs_nothing"),
    ("the marker check passes whatever the marker holds", R,
     "            f'[ \"$gw_t\" = {q(nonce)} ] || {{ printf \"\\\\n%s\\\\n\" {WRONG_HOST}; exit 97; }}\\n')",
     "            f'true || {{ printf \"\\\\n%s\\\\n\" {WRONG_HOST}; exit 97; }}\\n')",
     T + "test_the_bind_check_needs_the_host_records_marker_and_nonce"),
    ("a pane's operations go to another host's connection", S,
     "        rh = self.d.remote.get(p.host)\n        if p.machine and rh.machine and p.machine != rh.machine:",
     "        rh = self.d.remote.get(sorted(self.d.remote.hosts)[0])\n"
     "        if p.machine and rh.machine and p.machine != rh.machine:",
     T + "test_two_hosts_never_mix_their_work_and_a_wrong_runtime_runs_nothing"),
    ("a pane started on another machine is attached anyway", S,
     "                if p.machine and rh.machine and p.machine != rh.machine:\n"
     "                    why = f\"{p.host} is another machine than the one it started on\"",
     "                if False:\n"
     "                    why = f\"{p.host} is another machine than the one it started on\"",
     T + "test_a_changed_machine_blocks_until_confirmed_and_work_from_another_machine_is_unknown"),
    # --- the host key and machine id gates ----------------------------------------------
    ("a changed host key is trusted without asking", R,
     "        def mismatch(name: str, addr: Any, pins: list[str], seen: list[str]) -> list[str]:\n"
     "            raise _Mismatch(name, addr, pins, seen)\n",
     "        def mismatch(name: str, addr: Any, pins: list[str], seen: list[str]) -> list[str]:\n"
     "            return list(seen)\n",
     T + "test_a_changed_host_key_at_the_address_choice_is_asked_and_nothing_is_trusted"),
    ("ssh's own refusal of a changed host key is retried silently instead of asked", R,
     "                    if seen and not ssh_conf.keys_match(seen, target.host_keys):\n",
     "                    if False:\n",
     T + "test_ssh_refusing_a_changed_host_key_asks_the_user_at_once"),
    ("a declined host key is asked again at once (or let through)", R,
     '        if c.get("state") == "declined" and time.time() - c.get("at", 0) > 600:\n',
     '        if c.get("state") == "declined":\n',
     T + "test_a_declined_host_key_stays_blocked_until_the_pin_changes"),
    ("a changed machine id is accepted without asking", R,
     "        if stored and stored != token:\n            raise self._machine_changed(stored, token, session)\n",
     "        if False:\n            raise self._machine_changed(stored, token, session)\n",
     T + "test_a_changed_machine_blocks_until_confirmed_and_work_from_another_machine_is_unknown"),
    ("the machine id isn't stored at first contact", R,
     "                r[\"machine_id\"] = token\n                r[\"machine_id_at\"] = vault.now()\n",
     "                r[\"machine_id_at\"] = vault.now()\n",
     T + "test_the_first_remote_terminal_stages_the_runtime_and_runs_the_managed_shell"),
    # --- sha256 ------------------------------------------------------------------------------
    ("a copy whose sha256 differs is unpacked anyway", R,
     '        bad = [f["path"] for f in m["files"] if got.get(f["path"]) != f["sha256"]]\n',
     "        bad = []\n",
     T + "test_a_corrupted_copy_fails_its_sha256_check_and_nothing_is_unpacked"),
    ("without a hash tool on the host nothing is checked", R,
     '            got = {rel: self._read_back_hash(rt, rel, session) for rel in rels}\n',
     '            got = {f["path"]: f["sha256"] for f in m["files"]}\n',
     T + "test_without_a_hash_tool_on_the_host_the_copy_is_read_back_and_hashed_here"),
    ("a local artifact changed since its build is used", P,
     '            if p.stat().st_size != f.get("size") or sha256_file(p) != f.get("sha256"):\n',
     "            if False:\n",
     T + "test_artifacts_are_built_once_hashed_and_rebuilt_when_a_file_changes"),
    ("the unpacker build takes any file of the packages", P,
     '            if name == "bin/pixi-unpack":\n                rel, mode = "unpacker/bin/pixi-unpack", 0o755\n'
     '            elif name.startswith("lib/") and "/" not in name[4:] and _SHLIB.fullmatch(name[4:]) \\\n'
     "                    and not _SKIP_LIB.match(name[4:]):\n",
     '            if name == "bin/pixi-unpack":\n                rel, mode = "unpacker/bin/pixi-unpack", 0o755\n'
     '            elif name.startswith("lib/"):\n',
     T + "test_the_unpacker_takes_only_pixi_unpack_and_its_shared_libraries_from_the_packages"),
    # --- no secret on a command line -------------------------------------------------------
    ("a remote password goes in on tmux's command line", S,
     '            tm.run("load-buffer", "-b", buf, "-", input=value.encode("utf-8"))\n'
     "            try:\n"
     '                tm.run("paste-buffer", "-d", "-b", buf, "-t", p.target, ";", "send-keys", "-t",\n'
     "                       p.target, \"Enter\")\n",
     '            tm.run("send-keys", "-t", p.target, "-l", value)\n'
     "            try:\n"
     '                tm.run("send-keys", "-t",\n'
     "                       p.target, \"Enter\")\n",
     T + "test_a_remote_password_prompt_goes_through_the_dialog_and_never_on_a_command_line"),
    # --- honest states -------------------------------------------------------------------------
    ("a command cut off by a dropped connection counts as an answer", R,
     "        if r.returncode == 255:\n            # the command started but ssh lost the connection under it",
     "        if False:\n            # the command started but ssh lost the connection under it",
     T + "test_an_answer_cut_off_by_a_dropped_connection_is_no_answer_never_no_panes"),
    ("a poll answer without its end reads as \"no panes\"", R,
     '        if not text.rstrip("\\n").endswith(POLL_END) or "__GW_TTYS__\\n" not in text:\n',
     "        if False:\n",
     T + "test_an_answer_cut_off_by_a_dropped_connection_is_no_answer_never_no_panes"),
    ("a host that can't be reached ends its panes", S,
     "                p.remote_note = e.message\n                if p.state != state:\n",
     "                self._mark_gone(p, e.message)\n                if p.state != state:\n",
     T + "test_disconnect_and_reconnect_report_a_surviving_job_and_ones_ended_meanwhile_honestly"),
    ("a refused key reads as an ordinary disconnect", S,
     '        state = "waiting_auth" if code == "auth" else "disconnected"\n',
     '        state = "disconnected"\n',
     T + "test_a_refused_key_is_waiting_auth_with_the_remedy_and_recovers_when_it_works_again"),
    ("a pane the host's tmux lost is taken as alive", S,
     "                if lost:\n                    if p.closing or (p.stop_req == \"unsure\" and infos",
     "                if False:\n                    if p.closing or (p.stop_req == \"unsure\" and infos",
     T + "test_disconnect_and_reconnect_report_a_surviving_job_and_ones_ended_meanwhile_honestly"),
    ("a seq read before a disconnect still counts after the reconnect", S,
     "                    p.seq += 1\n                    p.seen = True\n",
     "                    p.seen = True\n",
     T + "test_disconnect_and_reconnect_report_a_surviving_job_and_ones_ended_meanwhile_honestly"),
    ("a remote pane is taken as confirmed after a gated restart without asking the host", S,
     "        self.seen = not self.remote        # remote: confirmed by the host since gated started\n",
     "        self.seen = True\n",
     T + "test_a_gated_restart_asks_the_host_before_it_reports_or_accepts_input"),
    # --- cleanup of old runtime versions ------------------------------------------------------
    ("any folder under the base counts as an old runtime", R,
     'DIR_RE = re.compile(r"[0-9a-f]{12}-(?:linux-64|linux-aarch64|osx-arm64|osx-64)")\n',
     'DIR_RE = re.compile(r".+")\n',
     T + "test_old_runtime_versions_go_once_the_new_one_is_ready_but_only_idle_marked_ones"),
    ("an old runtime without the gateway's marker is removed", R,
     "                  f'  [ -f \"$d/{MARKER}\" ] || [ -f \"$d/hosts/{self.host_id}\" ] || continue\\n'\n",
     "",
     T + "test_old_runtime_versions_go_once_the_new_one_is_ready_but_only_idle_marked_ones"),
    ("an old runtime whose tmux still runs work is removed", R,
     "                  'echo \"busy $d\"; continue; fi\\n'\n",
     "                  'echo \"busy $d\"; fi\\n'\n",
     T + "test_old_runtime_versions_go_once_the_new_one_is_ready_but_only_idle_marked_ones"),
    # --- rights -----------------------------------------------------------------------------------
    ("an \"ask\" ssh host gets remote terminals and jobs", R,
     '        if eh.ssh == "ask":\n            raise RemoteError("right"',
     '        if False:\n            raise RemoteError("right"',
     T + "test_hosts_whose_ssh_is_ask_or_off_get_no_remote_terminal_or_job"),
    ("a root password is asked for on a host whose sudo is off", S,
     "                if self._remote_sudo_right(p.host) is False:\n",
     "                if False:\n",
     T + "test_a_root_password_prompt_on_a_host_whose_sudo_is_off_asks_nothing"),
    # --- staging failures and their remedies ----------------------------------------------------
    ("a noexec runtime folder reads as a generic failure", R,
     '        if rc == 4 or "GW_EXEC_FAILED" in text:\n',
     "        if False:\n",
     T + "test_a_noexec_runtime_folder_is_reported_with_the_runtime_path_remedy"),
    ("a full disk isn't noticed before copying", R,
     "        if avail < need_kb:\n",
     "        if False:\n",
     T + "test_a_full_disk_is_reported_before_anything_is_copied"),
    ("an unknown platform gets a linux-64 runtime", P,
     "    return _UNAME.get(((sysname or \"\").strip(), (machine or \"\").strip()))\n",
     "    return _UNAME.get(((sysname or \"\").strip(), (machine or \"\").strip()), \"linux-64\")\n",
     T + "test_an_unsupported_host_is_refused_with_the_remedy_and_nothing_is_copied"),
    ("the pack and the unpacker stay on the host after unpacking", R,
     "                  'rm -rf unpacker .unpack.err\\n')\n",
     "                  ':\\n')\n",
     T + "test_the_first_remote_terminal_stages_the_runtime_and_runs_the_managed_shell"),
    # --- the managed environment -------------------------------------------------------------------
    ("the remote pane keeps the login PATH", S,
     "             f\"export PATH={_remote_path_expr(rt, imports or [], SYSTEM_PATH)}\",\n",
     "             f\"export PATH={_remote_path_expr(rt, imports or [], SYSTEM_PATH)}:\\\"$PATH\\\"\",\n",
     T + "test_the_first_remote_terminal_stages_the_runtime_and_runs_the_managed_shell"),
    ("the runtime's tmux starts with the login session's environment", R,
     "        return (f'x() {{ env -i HOME=\"$HOME\" USER=\"${{USER:-}}\" LOGNAME=\"${{LOGNAME:-}}\" LANG={lang} '\n",
     "        return (f'x() {{ env HOME=\"$HOME\" USER=\"${{USER:-}}\" LOGNAME=\"${{LOGNAME:-}}\" LANG={lang} '\n",
     T + "test_the_first_remote_terminal_stages_the_runtime_and_runs_the_managed_shell"),
    # --- the approval hook and the permission decisions -------------------------------------------
    ("a remote job is judged as a local command", "src/gateway/hooks_bash.py",
     "        if rname:\n            return _main_job(payload, _as_ssh(rname, ti))\n",
     "        if False:\n            return _main_job(payload, _as_ssh(rname, ti))\n",
     T + "test_the_approval_hook_judges_remote_work_as_a_command_on_that_host"),
    ("text for a remote terminal is judged as a local command", "src/gateway/hooks_bash.py",
     '        host = _terminal_host(ti.get("id"))\n',
     "        host = None\n",
     T + "test_the_approval_hook_judges_remote_work_as_a_command_on_that_host"),
    ("a remote job without a trigger word never reaches the approval hook", "hooks/pre_bash.sh",
     "mcp__plugin_gate_gw__job_start)\n", "mcp__plugin_gate_gw__job_start_never)\n",
     T + "test_the_prefilter_sends_every_remote_job_to_the_approval_hook"),
    ("a remote terminal_open (which may stage the runtime) is allowed in every mode", "hooks/mcp_perm.sh",
     '    if (hashost == 0 || (hashost == 1 && (host == "" || host == "localhost"))) print "allow-term-open"\n',
     '    print "allow-term-open"\n',
     T + "test_the_permission_hook_allows_only_local_terminals_and_runtime_reads"),
    ("host_runtime provision is allowed in every mode", "hooks/mcp_perm.sh",
     '    if (hasaction == 0 || (hasaction == 1 && action == "status")) print "allow-runtime-read"\n',
     '    print "allow-runtime-read"\n',
     T + "test_the_permission_hook_allows_only_local_terminals_and_runtime_reads"),
    ("a runtime path change applies without the user's OK", "src/gateway/consent.py",
     "    e.runtime = a_rt\n", "    e.runtime = f_rt\n",
     T + "test_runtime_paths_are_plain_and_a_change_waits_for_the_users_ok"),
    # --- lost answers: never "not done", never twice ------------------------------------
    ("a remote start whose answer was lost keeps no record (and a retry runs it again)", S,
     '            if not e.extra.get("ambiguous"):\n                # provably not started',
     '            if True:\n                # provably not started',
     T + "test_a_remote_start_whose_answer_is_lost_stays_unknown_is_adopted_and_never_runs_twice"),
    ("no answer at all (255 before the marker) counts as \"not run\"", R,
     "                                         ambiguous=not NOT_SENT.search(text)))\n",
     "                                         ambiguous=False))\n",
     T + "test_a_remote_start_whose_answer_is_lost_stays_unknown_is_adopted_and_never_runs_twice"),
    ("an answer cut off after the marker counts as \"not run\"", R,
     '                                         "retries", ambiguous=True))\n',
     '                                         "retries"))\n',
     T + "test_a_remote_start_whose_answer_is_lost_stays_unknown_is_adopted_and_never_runs_twice"),
    ("a lost start the host lists stays unconfirmed", S,
     "                if p.unconfirmed and not lost:\n",
     "                if False:\n",
     T + "test_a_remote_start_whose_answer_is_lost_stays_unknown_is_adopted_and_never_runs_twice"),
    ("a lost start the host doesn't list is called lost without asking its start file", S,
     "                if lost and p.unconfirmed and not p.closing:\n                    claims.append(p)",
     "                if False:\n                    claims.append(p)",
     T + "test_a_lost_start_that_never_reached_the_host_is_settled_never_started_and_frees_its_key"),
    ("a start that provably never ran keeps its idempotency key", S,
     "                for k, (jid, _t) in list(self.idem.items()):\n"
     "                    if jid == p.id:\n                        self.idem.pop(k, None)\n",
     "",
     T + "test_a_lost_start_that_never_reached_the_host_is_settled_never_started_and_frees_its_key"),
    ("a start gated settled as never run still runs when its shell comes late", S,
     "{_q(me + '.run')} 2>/dev/null || exit 125\",\n",
     "{_q(me + '.run')} 2>/dev/null || true\",\n",
     T + "test_a_start_files_claim_lets_exactly_one_side_win"),
    ("typed text whose answer was lost reads as not typed (its buffer not asked)", S,
     "            left = self._buffer_left(tm, buf) if buf else None\n",
     "            left = True if buf else None\n",
     T + "test_typed_text_whose_answer_is_lost_is_checked_by_its_buffer_never_called_untyped"),
    ("input whose outcome is unknown can be repeated with the seq read before", S,
     "                p.seq += 1                 # a repeat quoting the old seq is stale now\n",
     "",
     T + "test_typed_text_whose_answer_is_lost_is_checked_by_its_buffer_never_called_untyped"),
    ("the buffer of an input whose outcome is unknown stays for a late paste", S,
     "            self._drop_pending_buffers(rh, ps)\n",
     "",
     T + "test_typed_text_whose_answer_is_lost_is_checked_by_its_buffer_never_called_untyped"),
    # --- a failed query is a blip, not death ----------------------------------------------
    ("a failed list-panes reads as \"no server\"", R,
     'f"    *) echo {NOANSWER} ;;\\n"',
     'f"    *) echo {NOSERVER} ;;\\n"',
     T + "test_a_failed_list_panes_is_a_blip_and_only_a_dead_server_loses_the_panes"),
    ("tmux's \"no server running\" reads as no server while the server it named still runs", R,
     "'      if [ \"$pid\" -gt 0 ] && kill -0 \"$pid\" 2>/dev/null && '",
     "'      if false && kill -0 \"$pid\" 2>/dev/null && '",
     T + "test_a_failed_list_panes_is_a_blip_and_only_a_dead_server_loses_the_panes"),
    # --- a close the host didn't get -------------------------------------------------------
    ("a close that didn't reach the host leaves cancel set (its own exit reads canceled)", S,
     "            p.closing, p.cancel = prev\n",
     "            pass\n",
     T + "test_a_close_that_doesnt_reach_the_host_is_no_cancel_and_the_job_reports_its_own_end"),
    ("a close whose answer was lost is never settled by the host's answer", S,
     '                    if p.closing or (p.stop_req == "unsure" and infos is not None):\n',
     "                    if p.closing:\n",
     T + "test_a_close_that_doesnt_reach_the_host_is_no_cancel_and_the_job_reports_its_own_end"),
    ("a pause the host couldn't take says \"already ended\"", S,
     "        except TermError as e:\n            if e.code.startswith(\"remote_\"):\n"
     "                return {**base, \"outcome\": self._not_applied(e)}\n"
     "            return {**base, \"outcome\": \"already ended\"}\n        except OSError:\n",
     "        except TermError as e:\n"
     "            return {**base, \"outcome\": \"already ended\"}\n        except OSError:\n",
     T + "test_a_close_that_doesnt_reach_the_host_is_no_cancel_and_the_job_reports_its_own_end"),
    # --- the root-password rule, the token form, stale status ----------------------------
    ("the root-password rule looks only at the foreground group's leader", S,
     '            root = next((n for n in names if n in REMOTE_SUDO_COMMS), "")\n',
     '            root = names[0] if names and names[0] in REMOTE_SUDO_COMMS else ""\n',
     T + "test_a_root_password_prompt_anywhere_in_the_foreground_pipeline_follows_the_sudo_rule"),
    ("a remote job naming its host by machine token isn't judged on that host", "src/gateway/hooks_bash.py",
     "        ids, saved = read_host_maps(paths.gated_dir())\n",
     "        ids, saved = read_host_maps(paths.gated_dir())[0], {}\n",
     T + "test_the_approval_hook_judges_remote_work_as_a_command_on_that_host"),
    ("a remote job whose host names no host is judged as some other command", "src/gateway/hooks_bash.py",
     "    return UNKNOWN_HOST\n\n\ndef _hostname()",
     "    return host\n\n\ndef _hostname()",
     T + "test_the_approval_hook_judges_remote_work_as_a_command_on_that_host"),
    ("host_runtime status reports a stale answer as current", R,
     '            if age > stale_after and (reach, auth) != ("unknown", "unknown"):\n',
     "            if False:\n",
     T + "test_host_runtime_status_says_when_the_host_last_answered_and_goes_unknown_when_stale"),
    # --- a plain uninstall with a remote job a pause suspended (fix2, 0.9.1) ----------------
    ("a draining gated whose env lost its ssh can't reach the host (no system ssh)",
     "src/gateway/ssh_conf.py",
     "        fb = _system_ssh()\n        if fb is not None:\n            return fb\n",
     "        fb = None\n        if fb is not None:\n            return fb\n",
     T + "test_a_plain_uninstall_resumes_a_remote_job_a_pause_suspended_through_the_live_master"),
    ("the drain never allows the system's ssh", "src/gateway/daemon/lifecycle.py",
     "        ssh_conf.allow_system_ssh()\n", "        pass\n",
     T + "test_a_plain_uninstall_resumes_a_remote_job_a_pause_suspended_through_the_live_master"),
    ("the system's ssh is used before any drain", "src/gateway/ssh_conf.py",
     "    if not _SYSTEM_SSH_OK.is_set():\n        return None\n", "",
     T + "test_a_plain_uninstall_resumes_a_remote_job_a_pause_suspended_through_the_live_master"),
    ("the system's ssh may start a master", "src/gateway/ssh_conf.py",
     '        no_master = ["-o", "ControlMaster=no"] if b == _system_ssh() else []\n',
     "        no_master = []\n",
     T + "test_a_plain_uninstall_resumes_a_remote_job_a_pause_suspended_through_the_live_master"),
    ("the drain's remote resume fails fast after a failed poll", R,
     "        _rc, out, _e = self._call(script, insist=True)\n",
     "        _rc, out, _e = self._call(script)\n",
     T + "test_a_plain_uninstall_resumes_a_remote_job_a_pause_suspended_through_the_live_master"),
]

if __name__ == "__main__":
    mutation_check.MUTATIONS = MUTATIONS
    raise SystemExit(mutation_check.main(sys.argv[1:]))
