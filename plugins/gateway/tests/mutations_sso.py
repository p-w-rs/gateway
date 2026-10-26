#!/usr/bin/env python3
"""Mutation checks for the browser sign-in (PLAN-0.11 §7, WS-5): authorization
code + PKCE, run by gated (daemon/oauth.py). The listener only on 127.0.0.1,
GET /cb only, its header cap, one deadline per connection however slowly it
sends, and at most MAX_CONNS handled at once; the listener stopped at once
on close and by its own timer, before the end is announced and the marker
goes; the state check (a wrong one,
also with an error, gets 400 and the listener keeps waiting) and one valid
callback only; PKCE S256 and the verifier in the token request; the token
exchange without redirects; an outcome that says nothing was stored always
true (the timer never ends an accepted callback, a store finding the
sign-in ended writes nothing, gated's stop waits for a store writing) and
the store's recheck of the account; the ml-catalog's authority, tenant and
scope never from its /api/config, its client id pinned and a change refused
until a new sign-in, and only a bound catalog signed in; nothing opened
before the person's Open (whose dialog rechecks the account), and only by
absolute path (never PATH, the knob only under a test override) with a
fixed environment (never gated's own, never SSH_CONNECTION); the display
check (a Mac over ssh has none); one sign-in at a time, joined only from
its own session, and only its lease waiting for it; a killed gated's marker
removed; the browser's error_description never shown; gated using the
approved settings, refusing an account that waits for the OK or is approved
as a service principal; the sign-in keys' changes as widenings; no older
gateway's refresh token, and the approved way of signing in picking the
credential; one rule (accounts.entra_fits) for gate check and every status
line; a browser sign-in's scope through export and import; only gated's
own confirm carrying the sign-in fields, its Open keeping only the display
variables and SSH_CONNECTION; the mod's fixed template (Cancel first); the
browser-tool deny while a sign-in runs (hooks/tool_guard.sh and its
hooks.json matcher). Same format and runner as tests/mutation_check.py:
each mutation removes or weakens one property; the named test must then
FAIL. Mutations of the mod (hooks/mod/) are killed by `claude plugin test`
on the copy (test_mod), which needs a claude binary.

    pixi run --locked python tests/mutations_sso.py [-k SUBSTR] [--copy DIR]
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import mutation_check  # noqa: E402

S = "src/gateway/"
DS = S + "daemon/"
OA = DS + "oauth.py"
M = "hooks/mod/"
TE = "test_accounts_entra::"
TA = "test_accounts_asiml::"
MOD = "test_mod::test_claude_plugin_test_runs_the_mods_tests"

# (name, file, old, new, test selector "module::substring")
MUTATIONS = [
    # --- the listener ----------------------------------------------------------
    ("the listener binds every interface", OA,
     "            s.bind((LOOPBACK, 0))\n",
     "            s.bind((\"0.0.0.0\", 0))\n",
     TE + "test_the_listener_is_on_127_0_0_1"),
    ("the listener's header cap is gone", OA,
     "MAX_HEAD = 8192                  # a callback's request line and headers\n",
     "MAX_HEAD = 1 << 30\n",
     TE + "test_the_listener_is_on_127_0_0_1"),
    ("a stalled connection to the listener is never timed out", OA,
     "        end = time.monotonic() + CONN_TIMEOUT    # the whole connection's deadline\n",
     "        end = time.monotonic() + 3600.0\n",
     TE + "test_the_listener_is_on_127_0_0_1"),
    ("the listener's deadline is per read, not the connection's", OA,
     "        left = end - time.monotonic()\n"
     "        if left <= 0:\n"
     "            raise TimeoutError(\"the connection's deadline passed\")\n"
     "        conn.settimeout(left)\n",
     "        conn.settimeout(CONN_TIMEOUT)\n",
     TE + "test_the_listeners_deadline_is_the_whole_connections"),
    ("the listener handles any number of connections at once", OA,
     "        self.slots = threading.BoundedSemaphore(MAX_CONNS)\n",
     "        self.slots = threading.BoundedSemaphore(1 << 20)\n",
     TE + "test_the_listeners_deadline_is_the_whole_connections"),
    ("closing the listener doesn't shut it down (on Linux it keeps listening)", OA,
     "        try:\n"
     "            self.sock.shutdown(socket.SHUT_RDWR)\n"
     "        except OSError:\n"
     "            _close(self.sock)\n",
     "        _close(self.sock)\n",
     TE + "test_closing_the_listener_stops_it_at_once"),
    ("closing the listener doesn't wait for its serve thread", OA,
     "        if th is not None and th is not threading.current_thread():\n"
     "            th.join(5)\n",
     "        pass\n",
     TE + "test_closing_the_listener_stops_it_at_once"),
    ("a connection accepted after the listener closed is served", OA,
     "            if self.closed.is_set():\n"
     "                _close(conn)                     # the sign-in ended: never served\n"
     "                break\n",
     "",
     TE + "test_closing_the_listener_stops_it_at_once"),
    # --- verify013: the listener's own deadline, and the end announced after it stopped ---
    ("the listener's own deadline timer never starts", OA,
     "        self.timer.daemon = True\n        self.thread.start()\n        self.timer.start()\n",
     "        self.timer.daemon = True\n        self.thread.start()\n",
     TE + "test_the_listener_stops_by_itself_at_its_deadline"),
    ("the end of a sign-in is announced while its listener still listens", OA,
     "            if lis is not None:\n                lis.stop()\n",
     "",
     TE + "test_the_end_of_a_sign_in_is_announced_only_after_its_listener_stopped"),
    ("the sign-in's marker goes only after the end is announced", OA,
     "            if self.active is None:\n                self._remove_active_file()\n"
     "            self.cond.notify_all()\n        if tim is not None:\n            tim.cancel()\n",
     "            idle = self.active is None\n"
     "            self.cond.notify_all()\n        if tim is not None:\n            tim.cancel()\n"
     "        if idle:\n            self._remove_active_file()\n",
     TE + "test_the_end_of_a_sign_in_is_announced_only_after_its_listener_stopped"),
    # --- state and PKCE ----------------------------------------------------------
    ("the callback's state isn't checked", OA,
     "            if len(got) != 1 or not want or not hmac.compare_digest(\n"
     "                    got[0].encode(\"utf-8\", \"surrogateescape\"), want):\n",
     "            if False:\n",
     TE + "test_a_wrong_state_gets_400"),
    ("a wrong state ends the sign-in instead of the listener waiting on", OA,
     "                return 400, PAGE_BAD             # and the listener keeps waiting\n",
     "                si.state, si.outcome, si.message = \"done\", \"failed\", \"x\"\n"
     "                self.cond.notify_all()\n"
     "                return 400, PAGE_BAD\n",
     TE + "test_a_wrong_state_gets_400"),
    ("the PKCE challenge is the verifier itself (plain)", OA,
     "        url = authorize_url(si.p, lis.redirect_uri, state, pkce_challenge(verifier))\n",
     "        url = authorize_url(si.p, lis.redirect_uri, state, verifier)\n",
     TE + "test_browser_sign_in_asks_first"),
    ("the token request leaves out the PKCE verifier", OA,
     "            \"redirect_uri\": redirect, \"code_verifier\": verifier, \"scope\": p.scope}\n",
     "            \"redirect_uri\": redirect, \"scope\": p.scope}\n",
     TE + "test_browser_sign_in_asks_first"),
    ("an error with a wrong state ends the sign-in", OA,
     "            if len(got) != 1 or not want or not hmac.compare_digest(\n"
     "                    got[0].encode(\"utf-8\", \"surrogateescape\"), want):\n",
     "            if \"error\" not in q and (len(got) != 1 or not want or not hmac.compare_digest(\n"
     "                    got[0].encode(\"utf-8\", \"surrogateescape\"), want)):\n",
     TE + "test_one_valid_callback_only_and_an_error_needs_the_state_too"),
    ("a second valid callback is exchanged too", OA,
     "            if si.accepted:\n                return 409, PAGE_BAD\n",
     "            if False:\n                return 409, PAGE_BAD\n",
     TE + "test_one_valid_callback_only_and_an_error_needs_the_state_too"),
    # --- the outcome against the vault ------------------------------------------------
    ("the timer ends a sign-in whose code is being exchanged", OA,
     "        self._finish(si, \"timeout\", TIMEOUT_TEXT.format(name=si.p.name), unless_accepted=True)\n",
     "        self._finish(si, \"timeout\", TIMEOUT_TEXT.format(name=si.p.name))\n",
     TE + "test_the_timer_or_gated_stopping_during_the_exchange"),
    ("the store writes a sign-in that already ended", OA,
     "                    if si.state != \"open\":\n"
     "                        # it ended meanwhile (gated stopping), and its outcome\n",
     "                    if False:\n"
     "                        # it ended meanwhile (gated stopping), and its outcome\n",
     TE + "test_the_timer_or_gated_stopping_during_the_exchange"),
    ("gated's stop doesn't wait for a store that is writing", OA,
     "                while si.storing:\n",
     "                while False:\n",
     TE + "test_the_timer_or_gated_stopping_during_the_exchange"),
    ("the store doesn't recheck the account in gateway.toml", OA,
     "        if a is None or a.kind != p.kind:\n",
     "        if False:\n",
     TE + "test_the_store_rechecks_the_account_in_gateway_toml"),
    # --- the token exchange --------------------------------------------------------
    ("the token exchange follows redirects", OA,
     "        with entra.urlopen(req, timeout=30) as r:\n",
     "        with urllib.request.urlopen(req, timeout=30) as r:\n",
     TE + "test_a_redirect_at_the_token_endpoint"),
    # --- ml-catalog: fixed authority, tenant and scope; the client pinned --------------
    ("the catalog's scope is taken from its /api/config", OA,
     "    api, scope = entra.catalog_scopes(client)\n",
     "    api, scope = entra.catalog_scopes(client)\n    scope = str(cfg.get(\"scope\") or scope)\n",
     TA + "test_the_catalog_sign_in_has_a_fixed_authority"),
    ("the catalog's tenant is taken from its /api/config", OA,
     "    api, scope = entra.catalog_scopes(client)\n    authority = entra.authority()\n",
     "    api, scope = entra.catalog_scopes(client)\n    authority = entra.authority()\n"
     "    tenant = str(cfg.get(\"tenantId\") or tenant)\n",
     TA + "test_the_catalog_sign_in_has_a_fixed_authority"),
    ("the catalog's authority is taken from its /api/config", OA,
     "    api, scope = entra.catalog_scopes(client)\n    authority = entra.authority()\n",
     "    api, scope = entra.catalog_scopes(client)\n"
     "    authority = str(cfg.get(\"authority\") or entra.authority())\n",
     TA + "test_the_catalog_sign_in_has_a_fixed_authority"),
    ("asiml doesn't check the catalog still names the pinned client", S + "asiml.py",
     "    if str(catalog_config(account.host).get(\"clientId\")) != pinned:\n",
     "    if False:\n",
     TA + "test_a_catalog_naming_another_client_id"),
    ("gate check misses a catalog's changed client", S + "gate_setup.py",
     "        if now and now != str((rec.get(\"entra\") or {}).get(\"client_id\") or \"\"):\n",
     "        if False:\n",
     TA + "test_a_catalog_naming_another_client_id"),
    # --- the person's Open, the browser by absolute path, the display ------------------
    ("the browser opens before the person's Open", OA,
     "            self.active = si\n",
     "            self.active = si\n"
     "            threading.Thread(target=self._open, args=(si, None), daemon=True).start()\n",
     TE + "test_browser_sign_in_asks_first"),
    ("the browser knob is honoured outside a test override", OA,
     "    if testing.active() is not None:\n        prog = testing.get(\"browser\")\n",
     "    if True:\n        prog = testing.get(\"browser\")\n",
     TE + "test_the_system_browser_is_opened_by_absolute_path_only"),
    ("xdg-open is looked up on PATH", OA,
     "        exe = clipboard._find(\"xdg-open\", LINUX_DIRS)\n",
     "        exe = __import__(\"shutil\").which(\"xdg-open\")\n",
     TE + "test_the_system_browser_is_opened_by_absolute_path_only"),
    ("the display variables of the Open answer go unchecked", OA,
     "        if isinstance(v, str) and len(v) <= ENV_MAX and pat.fullmatch(v):\n",
     "        if isinstance(v, str):\n",
     TE + "test_the_system_browser_is_opened_by_absolute_path_only"),
    ("gated's own environment reaches the system browser", OA,
     "        child.update({k: v for k, v in env.items() if k in BROWSER_ENV})\n",
     "        child.update({**os.environ, **env})\n",
     TE + "test_the_system_browser_is_opened_by_absolute_path_only"),
    ("the Open answer's ssh connection reaches the system browser", OA,
     "        child.update({k: v for k, v in env.items() if k in BROWSER_ENV})\n",
     "        child.update({k: v for k, v in env.items() if k in ENV_PATTERNS})\n",
     TE + "test_the_system_browser_is_opened_by_absolute_path_only"),
    ("the display check is skipped", OA,
     "        why = display_problem(env, platform())\n",
     "        why = \"\"\n",
     TE + "test_without_a_display"),
    ("a Mac in an ssh session counts as having a display", OA,
     "    return OVER_SSH if env.get(\"SSH_CONNECTION\") else \"\"\n",
     "    return \"\"\n",
     TE + "test_the_system_browser_is_opened_by_absolute_path_only"),
    ("the Open answer drops SSH_CONNECTION", DS + "dialogs.py",
     "              \"SSH_CONNECTION\")\n",
     "              )\n",
     TE + "test_only_gateds_own_confirm_carries_sign_in_fields"),
    # --- one at a time, the lease, the outcome --------------------------------------
    ("a sign-in is joined from another session", OA,
     "                if cur.p.name == p.name and cur.session_pid == session.pid:\n",
     "                if cur.p.name == p.name:\n",
     TE + "test_only_the_same_session_joins_a_sign_in"),
    ("a killed gated's marker stays (browser tools denied for good)", OA,
     "        self._remove_active_file()            # a killed gated's leftover\n",
     "        pass\n",
     TE + "test_only_the_same_session_joins_a_sign_in"),
    ("two sign-ins run at once", OA,
     "            if cur is not None and cur.state != \"done\":\n",
     "            if False:\n",
     TE + "test_one_sign_in_at_a_time"),
    ("any lease waits for the running sign-in", OA,
     "        if self.active is not None and any(hmac.compare_digest(h, w) for w in self.active.waiters):\n",
     "        if self.active is not None:\n",
     TE + "test_one_sign_in_at_a_time"),
    ("the browser's error_description reaches Claude", OA,
     "            self._finish(si, \"declined\", DECLINED_TEXT.format(name=name))\n",
     "            self._finish(si, \"declined\", DECLINED_TEXT.format(name=name) + \" \"\n"
     "                         + str(q.get(\"error_description\")))\n",
     TE + "test_an_error_from_the_browser"),
    # --- gated's own reading of the account ------------------------------------------
    ("gated signs in an account that waits for the user's OK", OA,
     "    if ea.new:\n",
     "    if False:\n",
     TE + "test_the_sign_in_waits_for_the_users_ok"),
    ("gated takes the form's settings, not the approved ones", OA,
     "        tenant, client = ea.tenant or \"\", ea.client_id or \"\"\n",
     "        tenant, client = a.tenant, a.client_id\n",
     TE + "test_the_sign_in_waits_for_the_users_ok"),
    ("gated signs in an azure account approved as a service principal", OA,
     "        if ea.sign_in != \"browser\":\n",
     "        if False:\n",
     TE + "test_gated_runs_a_browser_sign_in_only_for_an_account_approved_for_it"),
    ("gated signs in to a catalog that isn't bound", OA,
     "    if not host or host not in ea.destinations or not consent.bound_ok(data, name, host):\n",
     "    if not host:\n",
     TA + "test_gated_signs_in_only_a_catalog_that_is_bound"),
    ("the confirm dialog carries no recheck of the account", OA,
     "                \"check\": {\"section\": \"accounts\", \"entry\": p.name, \"kind\": p.kind}}\n",
     "                }\n",
     TE + "test_the_confirm_dialog_rechecks_the_account_before_anything_opens"),
    ("a sign-in that can't start now says to find a display", S + "gate_setup.py",
     "        elif r.get(\"reason\") in SIGNIN_LATER:\n",
     "        elif False:\n",
     TE + "test_a_sign_in_that_cant_start_now_says_when_to_retry"),
    # --- consent ----------------------------------------------------------------------
    ("changing sign_in is no widening", S + "consent.py",
     "                         (\"sign_in\", \"sign_in\", f_sign), (\"scope\", \"scope\", a.scope or None)):\n",
     "                         (\"scope\", \"scope\", a.scope or None)):\n",
     TE + "test_changing_a_sign_in_key_is_a_widening"),
    ("changing the sign-in's scope is no widening", S + "consent.py",
     "                         (\"sign_in\", \"sign_in\", f_sign), (\"scope\", \"scope\", a.scope or None)):\n",
     "                         (\"sign_in\", \"sign_in\", f_sign)):\n",
     TE + "test_changing_a_sign_in_key_is_a_widening"),
    # --- which credential is used -------------------------------------------------------
    ("an older gateway's refresh token is used", S + "entra.py",
     "        if older:\n            raise EntraError(",
     "        if False:\n            raise EntraError(",
     TE + "test_an_older_gateways_refresh_token_is_never_used"),
    ("a service principal's account uses a refresh token beside its secret", S + "entra.py",
     "    else:\n        e.pop(\"refresh_token\", None)\n",
     "    else:\n        pass\n",
     TE + "test_the_approved_way_of_signing_in_picks_the_credential"),
    # --- one rule for "signed in": gate check and the status lines -----------------------
    ("gate check takes a sign-in made for another scope", S + "accounts.py",
     "                and info.get(\"scope\") == request_scope(a))\n",
     "                and True)\n",
     TE + "test_gate_check_plans_the_browser_sign_in"),
    ("gate check takes a catalog sign-in made for another tenant", S + "accounts.py",
     "            return (info.get(\"tenant_id\") == (a.tenant or formmod.CATALOG_TENANT)\n",
     "            return (True\n",
     TA + "test_a_catalogs_changed_tenant_needs_a_new_sign_in"),
    ("the status line says signed in for a sign-in gate check won't use", S + "gate_setup.py",
     "                  if acctmod.entra_fits(a, ent) else \"needs a new sign-in\")\n",
     "                  if True else \"needs a new sign-in\")\n",
     TE + "test_the_status_says_signed_in_only_for_a_credential"),
    ("gate status says signed in for a sign-in gate check won't use", S + "gate.py",
     "        st = (\"signed in\" if a is not None and acctmod.entra_fits(a, am.get(\"entra_info\") or {})\n",
     "        st = (\"signed in\" if True\n",
     TE + "test_the_status_says_signed_in_only_for_a_credential"),
    ("Claude's context says signed in for a sign-in gate check won't use", S + "hooks_session.py",
     "    elif entra and not acctmod.entra_fits(a, ent):\n",
     "    elif False:\n",
     TE + "test_the_status_says_signed_in_only_for_a_credential"),
    ("the account check mints ARM for a sign-in made for another scope", S + "adapters.py",
     "            scope = own[0] if own else arm\n",
     "            scope = arm\n",
     TE + "test_a_browser_sign_in_is_checked_with_its_own_scope"),
    # --- export and import ----------------------------------------------------------------
    # (The two scope-check entries are retired: a file never carries a
    # browser sign-in, its refresh token or its scope any more, PLAN-0.11
    # §19.12, so ENTRA_SCOPE_RE is gone; a file holding either is refused,
    # mutations_integration.py.)
    # --- the confirm dialog ---------------------------------------------------------------
    ("a program's own dialog carries sign-in fields", DS + "dialogs.py",
     "                    signin=_signin_view(spec.get(\"signin\")) if owner == \"gated\" and kind == \"confirm\"\n"
     "                    else None,\n",
     "                    signin=_signin_view(spec.get(\"signin\")),\n",
     TE + "test_only_gateds_own_confirm_carries_sign_in_fields"),
    ("the Open answer keeps any variable", DS + "dialogs.py",
     "                r.env = {k: v for k, v in env.items() if k in SIGNIN_ENV and isinstance(v, str)\n",
     "                r.env = {k: v for k, v in env.items() if isinstance(v, str)\n",
     TE + "test_only_gateds_own_confirm_carries_sign_in_fields"),
    ("the mod shows gated's own words in the sign-in dialog", M + "dialog.ts",
     "    lines: s !== null ? signinLines(s) : [SIGNIN_UNREADABLE], ok_label: 'Open', cancel_label: 'Cancel',\n",
     "    lines: d.lines, ok_label: 'Open', cancel_label: 'Cancel',\n",
     MOD),
    ("the sign-in dialog doesn't focus Cancel first", M + "dialog.ts",
     "    default_cancel: true,\n  }\n}\n",
     "    default_cancel: d.default_cancel,\n  }\n}\n",
     MOD),
    ("the mod shows a sign-in field it didn't check", M + "dialog.ts",
     "  if (!SIGNIN_NAME.test(out.account) || !SIGNIN_TENANT.test(out.tenant) || !SIGNIN_GUID.test(out.client) || !SIGNIN_SCOPE.test(out.scope)) return null\n",
     "  if (!SIGNIN_NAME.test(out.account)) return null\n",
     MOD),
    # --- browser-automation tools while a sign-in runs -------------------------------------
    ("the browser-tool deny is missing", "hooks/tool_guard.sh",
     "if [ -n \"$browser\" ] && [ -e \"$run/signin-active\" ]; then\n",
     "if false; then\n",
     TE + "test_tool_guard_denies_browser_tools_only_while_a_sign_in_runs"),
    ("the guard misses Claude in Chrome", "hooks/tool_guard.sh",
     "    mcp__Claude_Browser__*|mcp__claude-in-chrome__*) browser=1 ;;\n",
     "    mcp__Claude_Browser__*) browser=1 ;;\n",
     TE + "test_tool_guard_denies_browser_tools_only_while_a_sign_in_runs"),
    ("hooks.json runs no guard for Claude in Chrome", "hooks/hooks.json",
     "\"matcher\": \"mcp__Claude_Browser__.*|mcp__claude-in-chrome__.*\",",
     "\"matcher\": \"mcp__Claude_Browser__.*\",",
     TE + "test_hooks_json_runs_tool_guard_for_the_browser_tools"),
    ("gated never writes the marker the guard checks", OA,
     "        self._write_active_file()\n",
     "        pass\n",
     TE + "test_the_timeout_names_the_redirect_cause"),
    ("removing the marker makes a deleted run dir again", OA,
     "            self.marker.unlink()\n",
     "            active_path().unlink()\n",
     "test_daemon::test_a_daemon_whose_socket_is_removed_exits"),
]


if __name__ == "__main__":
    mutation_check.MUTATIONS = MUTATIONS
    raise SystemExit(mutation_check.main(sys.argv[1:]))
