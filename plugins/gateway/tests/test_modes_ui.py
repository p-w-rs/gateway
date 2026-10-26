"""Per-mode values in the user's tools (PLAN-0.11 §2.8, §2.9, §2.11; WS-2):
the edit syntax (`gate host set NAME ssh|sudo MODE=WORD...`, `gate policy
set ... MODE=WORD...`, `gate network ...`) through the form writer, the
consent dialog's plain per-mode wording, the /gate-hosts and /gate-accounts
panes' per-mode values, and the CONTRACT-v1 rights mapping."""
from __future__ import annotations

import contextlib
import io

import harness as H
from gateway import consent, modes, vault
from gateway import form as F

HOST = '[hosts.box]\naddress = "u@box.example.com"\n'


def gate(*argv: str) -> tuple[int, str]:
    """`gate ARGV` through gate.main (the CLI's dispatch to manage.py)."""
    from gateway import gate as gatemod
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = gatemod.main(list(argv))
    return rc, out.getvalue() + err.getvalue()


def _rig(env, text: str = HOST) -> None:
    env.write_form(text)
    vault.save(vault.empty())
    consent.approve_all(env.form())


def _form() -> F.Form:
    F.clear_cache()
    return F.load(use_cache=False)


# ---------------------------------------------------------------------------
# The edit syntax (§2.9)
# ---------------------------------------------------------------------------


def test_host_set_writes_a_per_mode_table_from_mode_word_tokens():
    with H.gateway_env() as env:
        _rig(env)
        rc, out = gate("host", "set", "box", "sudo", "default=ask", "auto=true", "plan=false")
        assert rc == 0, out
        assert 'sudo = {default = "ask", auto = true, plan = false}' in env.form_path.read_text()
        mv = _form().hosts["box"].mode_value("sudo")
        assert mv.map() == {"default": "ask", "plan": "deny", "acceptEdits": "ask", "auto": "allow",
                            "bypass": "ask", "dontAsk": "ask"}
        assert "up to date" in out, out                     # below the bare true in every mode
        rc, out = gate("host", "set", "box", "sudo", "default=true")
        assert rc == 0 and "wait" in out and "gate check box" in out, out   # a widening: the OK
        # one word keeps the one-word form; the rights' words (cc too) in any spelling
        for word, written in (("cc", 'ssh = "cc"'), ("ask", 'ssh = "ask"'), ("allow", "ssh = true"),
                              ("off", "ssh = false"), ("true", "ssh = true")):
            rc, out = gate("host", "set", "box", "ssh", word)
            assert rc == 0 and written in env.form_path.read_text(), (word, out)
        rc, out = gate("host", "set", "localhost", "sudo", "manual=cc", "dontAsk=allow")
        assert rc == 0, out
        assert _form().hosts["localhost"].mode_value("sudo").map()["dontAsk"] == "allow"


def test_a_bad_per_mode_edit_is_refused_and_writes_nothing():
    with H.gateway_env() as env:
        _rig(env)
        before = env.form_path.read_text()
        for argv, words in (
                (("sudo", "auto=true"), "needs default"),
                (("sudo", "default=ask", "auto=true", "auto=false"), "names Auto mode twice"),
                (("sudo", "default=ask", "manual=true"), "names Manual mode twice"),
                (("sudo", "default=ask", "bypass=true", "bypassPermissions=deny"), "twice"),
                (("sudo", "default=maybe"), "MODE=WORD"),
                (("sudo", "Default=ask"), "MODE=WORD"),
                (("sudo", "default=ask", "auto"), "MODE=WORD"),
                (("sudo", "ask", "true"), "MODE=WORD"),
                (("sudo", "maybe"), "true, ask, cc or false"),
                (("note", "a", "b"), "only ssh and sudo"),
                (("address", "default=ask", "auto=true"), "only ssh and sudo"),
                (("address", "default=ask"), "address")):        # (one value: not an address)
            rc, out = gate("host", "set", "box", *argv)
            assert rc == 2 and words in out, (argv, out)
        rc, out = gate("host", "set", "localhost", "ssh", "true")
        assert rc == 2 and "isn't a localhost setting" in out, out
        assert env.form_path.read_text() == before


def test_policy_set_takes_a_per_mode_table_for_the_moded_keys_only():
    with H.gateway_env() as env:
        _rig(env)
        rc, out = gate("policy", "set", "all", "network", "default=ask", "auto=allow")
        assert rc == 0 and '[policy] network = {default = "ask", auto = "allow"}' in out, out
        mv = _form().policy_mode("network")
        assert mv.word("auto") == "allow" and mv.explicit_in("auto") and mv.word("default") == "ask"
        rc, out = gate("policy", "set", "box", "exec", "cc")
        assert rc == 0 and '[hosts.box.policy] exec = "cc"' in out, out
        rc, out = gate("policy", "set", "box", "exec", "default=deny", "dontAsk=true")
        assert rc == 0 and 'exec = {default = "deny", dontAsk = "allow"}' in env.form_path.read_text()
        before = env.form_path.read_text()
        for argv, words in ((("box", "provision", "default=ask"), "takes one word"),
                            (("box", "forward_agent", "cc"), "allow, ask or deny"),
                            (("box", "exec", "default=ask", "auto=sometimes"), "MODE=WORD"),
                            (("box", "exec", "auto=deny"), "needs default")):
            rc, out = gate("policy", "set", *argv)
            assert rc == 2 and words in out, (argv, out)
        assert env.form_path.read_text() == before
        # one word for the others, as before
        rc, out = gate("policy", "set", "box", "provision", "deny")
        assert rc == 0 and '[hosts.box.policy] provision = "deny"' in out, out


def test_gate_network_edits_commands_extra_and_drop():
    with H.gateway_env() as env:
        _rig(env)
        rc, out = gate("network", "commands", "default=ask", "bypassPermissions=allow")
        assert rc == 0, out
        text = env.form_path.read_text()
        assert "[network]" in text and 'commands = {default = "ask", bypassPermissions = "allow"}' in text
        f = _form()
        assert f.network.commands.word("bypass") == "allow" and not f.network.invalid
        assert "gate check settings" in out, out                     # a widening: the OK first
        rc, out = gate("network", "commands", "deny")
        assert rc == 0 and 'commands = "deny"' in env.form_path.read_text(), out
        rc, out = gate("network", "extra", "add", "dig")
        assert rc == 0 and _form().network.extra == ["dig"], out
        rc, out = gate("network", "drop", "add", "http-server")
        assert rc == 0 and _form().network.drop == ["http-server"], out
        rc, out = gate("network", "extra", "add", "dig")
        assert rc == 2 and "has dig already" in out, out
        rc, out = gate("network", "extra", "remove", "dig")
        assert rc == 0 and _form().network.extra == [], out
        before = env.form_path.read_text()
        for argv, words in ((("extra", "remove", "dig"), "doesn't have dig"),
                            (("extra", "add", "a b"), "a network name"),
                            (("extra", "add", ".."), "a network name"),
                            (("commands", "maybe"), "allow, ask, cc or deny"),
                            (("commands",), "allow, ask, cc or deny"),
                            (("other", "add", "dig"), "usage"),
                            (("commands", "auto=allow"), "needs default")):
            rc, out = gate("network", *argv)
            assert rc == 2 and words in out, (argv, out)
        assert env.form_path.read_text() == before
        # a list over the limit breaks [network]: rolled back, nothing written
        for i in range(F.NETWORK_LIST_MAX):
            assert gate("network", "extra", "add", f"tool{i}")[0] == 0
        before = env.form_path.read_text()
        rc, out = gate("network", "extra", "add", "onemore")
        assert rc == 2 and "nothing was written" in out and env.form_path.read_text() == before, out


def test_account_set_writes_use_as_one_word_or_per_mode_and_a_raise_waits_for_the_ok():
    """WS-9: an account's per-mode `use` from the gate CLI, like a host's ssh
    and sudo: one word or MODE=WORD tokens through the form writer; a
    lowered use applies at once, a raised one waits for the consent dialog
    (gate check NAME); anything else is refused and writes nothing."""
    gh = '[accounts.gh]\nkind = "github"\nlogin = "octocat"\n'
    with H.gateway_env() as env:
        _rig(env, HOST + gh)
        rc, out = gate("account", "set", "gh", "use", "default=ask", "auto=true", "plan=false")
        assert rc == 0 and 'gh: use set ({default = "ask", auto = true, plan = false})' in out, out
        assert 'use = {default = "ask", auto = true, plan = false}' in env.form_path.read_text()
        mv = _form().accounts["gh"].mode_value()
        assert mv.word("default") == "ask" and mv.word("auto") == "allow" and mv.word("plan") == "deny"
        assert "up to date" in out, out                       # below the bare true: at once
        data = vault.load()
        eff = consent.compute(consent.load_form(data), data)
        assert eff.word("gh", "use", "default") == "ask" and eff.word("gh", "use", "auto") == "allow"
        rc, out = gate("account", "set", "gh", "use", "default=true", "auto=allow")
        assert rc == 0 and "wait" in out and "gate check gh" in out, out    # a widening
        data = vault.load()
        eff = consent.compute(consent.load_form(data), data)
        assert eff.word("gh", "use", "default") == "ask", "nothing approved by the edit"
        for word, written in (("ask", 'use = "ask"'), ("cc", 'use = "cc"'), ("off", "use = false")):
            rc, out = gate("account", "set", "gh", "use", word)
            assert rc == 0 and written in env.form_path.read_text(), (word, out)
        before = env.form_path.read_text()
        for argv, words in ((("gh", "use", "auto=true"), "needs default"),
                            (("gh", "use", "maybe"), "true, ask, cc or false"),
                            (("gh", "use", "default=ask", "auto"), "MODE=WORD"),
                            (("gh", "login", "octo"), "changes use"),
                            (("nope", "use", "ask"), "isn't an account"),
                            (("box", "use", "ask"), "isn't an account"),
                            (("gh", "use"), "usage")):
            rc, out = gate("account", "set", *argv)
            assert rc == 2 and words in out, (argv, out)
        assert env.form_path.read_text() == before


def test_the_usage_names_the_new_shapes():
    with H.gateway_env():
        rc, out = gate("host", "set", "box")
        assert rc == 2 and "MODE=WORD" in out and "gate network commands" in out, out
        assert "gate account set NAME use" in out, out
        rc, out = gate("--help")
        assert "MODE=WORD" in out and "gate network" in out, out
        assert "gate account set NAME use" in out, out


# ---------------------------------------------------------------------------
# The consent dialog's wording (§2.8)
# ---------------------------------------------------------------------------


def _pending(old: str, new: str) -> list[str]:
    data = {"approved": {"rights": consent.snapshot(F.parse_text(old))}}
    return [c.render() for c in consent.compute(F.parse_text(new), data).pending]


def test_the_dialog_says_each_mode_that_rose_in_plain_words():
    """Mode by mode with Claude Code's own names; the modes that moved alike
    in one clause; an approval said only where the gateway gives one."""
    with H.gateway_env():
        w = _pending(HOST + 'sudo = "ask"\n',
                     HOST + 'sudo = { default = "ask", auto = true, plan = "cc" }\n')
        assert w == ["box: sudo on box: in Plan mode Claude Code decides; in Auto mode the gateway "
                     "now approves without asking you (was: asks you)"], w
        w = _pending('[hosts.localhost]\nsudo = "cc"\n',
                     '[hosts.localhost]\nsudo = { default = true, dontAsk = "cc" }\n')
        assert w == ["localhost: sudo on this computer: in Manual, Accept edits, Auto and Bypass "
                     "permissions modes the gateway now approves without asking you (was: Claude "
                     "Code decides)"], w
        w = _pending(HOST + 'ssh = false\n', HOST + 'ssh = { default = false, auto = "ask" }\n')
        assert w == ["box: ssh to box: in Auto mode you are asked (was: refused)"], w


def test_the_dialog_never_promises_an_approval_where_the_gateway_gives_none():
    """§2.5/§2.8: an account's use has no allow shape (its allow reads as
    Claude Code decides), and an explicit policy allow approves only for the
    network key on this machine; elsewhere it restricts nothing and says so."""
    with H.gateway_env():
        acct = '[accounts.key]\nkind = "api-key"\nsites = ["api.example.com"]\n'
        w = _pending(acct + 'use = "ask"\n', acct + 'use = { default = "ask", auto = true }\n')
        assert w == ["key: use: in Auto mode Claude Code decides (was: asks you)"], w
        assert not any("approve" in x for x in w)
        w = _pending("", '[hosts.localhost.policy]\nexec = { default = "allow" }\n')
        assert w and not any("approve" in x for x in w) and "no restriction, as an explicit allow" in \
            w[0], w
        w = _pending("", '[policy]\nnetwork = { default = "ask", dontAsk = "allow" }\n')
        assert any("in Don't ask mode the gateway now approves the http and download tools on this "
                   "computer without asking you" in x for x in w), w
        # review item 4: cc -> an explicit allow on a key with no allow shape is
        # the same in effect: the line says so instead of "X (was: X)"
        w = _pending(acct + "use = true\n", acct + "use = { default = true }\n")
        assert w == ["key: use: in Manual, Accept edits and Don't ask modes Claude Code decides, as "
                     "an explicit allow (the gateway approves nothing more for it) (was: Claude "
                     "Code decides)"], w


def test_network_commands_name_the_approval():
    with H.gateway_env():
        w = _pending("", '[network]\ncommands = { default = "ask", bypass = "allow" }\n')
        assert w == ["settings: network commands: in Bypass permissions mode the gateway now "
                     "approves without asking you (was: asks you)"], w


# ---------------------------------------------------------------------------
# The panes (/gate-hosts, /gate-accounts) and CONTRACT-v1 (§2.11)
# ---------------------------------------------------------------------------


def test_the_panes_get_per_mode_tables_as_six_mode_maps_and_bare_words_not_at_all():
    from gateway.daemon import lifecycle
    with H.gateway_env() as env:
        _rig(env, HOST + 'sudo = { default = "ask", auto = true }\n'
                  '[accounts.key]\nkind = "api-key"\nsites = ["api.example.com"]\n'
                  'use = { default = false, bypass = "cc" }\n'
                  '[accounts.gh]\nkind = "github"\nlogin = "octocat"\n')
        eff = consent.compute(env.form(), vault.load())
        assert lifecycle.ui_modes(eff.hosts["box"].modes) == {"sudo": {
            "default": "ask", "plan": "ask", "acceptEdits": "ask", "auto": "allow", "bypass": "ask",
            "dontAsk": "ask"}}
        assert lifecycle.ui_modes(eff.accounts["key"].modes) == {"use": {
            "default": "deny", "plan": "deny", "acceptEdits": "deny", "auto": "deny", "bypass": "cc",
            "dontAsk": "deny"}}
        assert lifecycle.ui_modes(eff.accounts["gh"].modes) == {}       # a bare true: not shown


def test_the_panes_get_each_per_mode_policy_as_its_decision_in_every_mode():
    """§2.9, review item 7: an action whose policy is a per-mode table (the
    entry's own or [policy]'s) reaches the panes as its effective decision in
    each mode (the base right and every layer), never as the one modeless
    word; an action with no table is left to `rights`."""
    from gateway.daemon import lifecycle
    with H.gateway_env() as env:
        _rig(env, HOST + '[hosts.box.policy]\nwrite = { default = "allow", auto = "deny" }\n'
                  'read = "ask"\n'
                  '[policy]\nnetwork = { default = "ask", dontAsk = "deny" }\n'
                  '[accounts.key]\nkind = "api-key"\nsites = ["api.example.com"]\n'
                  '[accounts.key.policy]\nwrite = { default = "allow", bypass = "ask" }\n')
        eff = consent.compute(env.form(), vault.load())
        box = lifecycle.ui_policy_modes(eff, host="box")
        assert set(box) == {"write", "network"}, box
        assert box["write"] == {"default": "cc", "plan": "cc", "acceptEdits": "cc", "auto": "deny",
                                "bypass": "allow", "dontAsk": "cc"}, box
        assert box["network"]["dontAsk"] == "deny" and box["network"]["auto"] == "ask", box
        local = lifecycle.ui_policy_modes(eff, host="localhost")
        assert set(local) == {"network"} and local["network"]["default"] == "ask", local
        key = lifecycle.ui_policy_modes(eff, account="key")
        assert set(key) == {"write", "network"}, key
        assert key["write"]["bypass"] == "ask" and key["write"]["auto"] == "allow", key


def test_gated_sends_the_panes_tables_and_the_snapshots_contract_words():
    """Through a real gated: /ui/manage (the panes) carries each per-mode
    right as its six-mode map, and /v1/snapshot's rights are CONTRACT-v1's
    words from the modeless rule."""
    import harness_daemon as D
    with D.daemon_env() as de:
        de.env.write_form('[hosts.box]\naddress = "u@box.example.com"\n'
                          'sudo = { default = "ask", auto = true }\n'
                          '[hosts.box.policy]\nwrite = { default = "allow", auto = "deny" }\n'
                          '[accounts.key]\nkind = "api-key"\nsites = ["api.example.com"]\n'
                          'use = { default = "cc", bypass = "ask" }\n')
        vault.save(vault.empty())
        consent.approve_all(de.env.form())
        fc = de.claude()
        st, view = fc.http("GET", "/ui/manage")
        assert st == 200, view
        box = next(h for h in view["hosts"] if h["name"] == "box")
        assert box["modes"] == {"sudo": {"default": "ask", "plan": "ask", "acceptEdits": "ask",
                                         "auto": "allow", "bypass": "ask", "dontAsk": "ask"}}, box
        key = next(a for a in view["accounts"] if a["account"] == "key")
        assert key["modes"]["use"]["bypass"] == "ask" and key["modes"]["use"]["default"] == "cc"
        # a per-mode policy as its decision in each mode (§2.9), never one word
        assert box["policy_modes"] == {"write": {"default": "cc", "plan": "cc", "acceptEdits": "cc",
                                                "auto": "deny", "bypass": "allow", "dontAsk": "cc"}}, box
        assert key["policy_modes"] == {}, key
        st, snap = de.probe(fc, D.probe_root(de.root) / "run.py", ["shim", "gh"], "/v1/snapshot",
                            method="GET")
        assert st == 200, snap
        rights = next(h for h in snap["hosts"] if h["name"] == "box")["rights"]
        assert rights["exec"] == "allow" and rights["write"] == "deny" and rights["elevation"] == "ask"
        acct = next(a for a in snap["accounts"] if a["account"] == "key")
        assert acct["rights"] == {"credential": "ask", "write": "ask", "network": "ask"}, acct


def test_contract_rights_map_the_modeless_word_to_allow_ask_deny():
    """§2.11: snapshot rights keep allow / ask / deny, from the modeless rule:
    cc and allow are allow, ask ask, deny deny (a per-mode table: its
    strictest word over every mode but plan)."""
    from gateway.daemon import lifecycle
    with H.gateway_env() as env:
        _rig(env, '[hosts.localhost]\nsudo = { default = true, plan = false }\n'
                  '[hosts.box]\naddress = "u@box.example.com"\nssh = "cc"\nsudo = "ask"\n'
                  '[hosts.box.policy]\nwrite = { default = "allow", auto = "deny" }\n'
                  'read = { default = "cc" }\n'
                  '[hosts.two]\naddress = "u@two.example.com"\nssh = { default = "ask", auto = true }\n'
                  '[accounts.key]\nkind = "api-key"\nsites = ["api.example.com"]\n'
                  'use = { default = true, bypass = "ask" }\n')
        eff = consent.compute(env.form(), vault.load())
        box = lifecycle.contract_rights(eff, host="box")
        assert box["exec"] == "allow" and box["read"] == "allow"         # cc -> allow
        assert box["write"] == "deny"                                   # deny in auto: modeless deny
        assert box["elevation"] == "ask" and box["forward_agent"] == "deny"
        assert set(box) == set(F.HOST_POLICY_KEYS)
        assert set(lifecycle.contract_rights(eff, host="two").values()) <= {"ask", "deny"}
        local = lifecycle.contract_rights(eff, host="localhost")
        assert local["elevation"] == "allow" and set(local) == set(F.LOCALHOST_POLICY_KEYS)
        assert lifecycle.contract_rights(eff, account="key") == {
            "credential": "ask", "write": "ask", "network": "ask"}
        assert set(lifecycle.CONTRACT_WORDS.values()) == {"allow", "ask", "deny"}
        assert set(lifecycle.CONTRACT_WORDS) == set(modes.RANK)
        # nothing configures this computer's sudo: the user's own, which the
        # gateway doesn't gate (PLAN-0.11 §1.5): allow
        _rig(env, HOST)
        eff = consent.compute(env.form(), vault.load())
        assert lifecycle.contract_rights(eff, host="localhost")["elevation"] == "allow"
