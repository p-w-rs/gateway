"""Per-mode values (PLAN-0.11 §2, modes.py): the words and their order, the
expansion of a bare word per kind, per-mode tables (default required, a
table's true is allow in that mode, plan degrades to cc), the modeless rule,
unknown modes, the strict ranks, the snapshot encoding, and policy.decide
per mode (the recorded mode for a typed command, the modeless rule
otherwise)."""
from __future__ import annotations

from pathlib import Path

import harness  # noqa: F401 - the guard
from gateway import consent, modes, policy
from gateway import form as F

ALL = modes.KEYS          # default, plan, acceptEdits, auto, bypass, dontAsk


def words(mv: modes.ModeValue) -> tuple[str, ...]:
    return tuple(mv.word(m) for m in ALL)


def parse(t: str) -> F.Form:
    return F.parse_text(t, Path("/x"))


def run(old: str, new: str, mode: str | None = None) -> consent.Effective:
    data = {"approved": {"rights": consent.snapshot(parse(old))}}
    return consent.compute(parse(new), data, mode)


def raises(fn, exc=Exception) -> str:
    try:
        fn()
    except exc as e:
        return str(e)
    raise AssertionError(f"{fn} must raise {exc.__name__}")


# --- §2.1 / §2.7: modes, words, order ---------------------------------------


def test_one_order_in_every_mode_and_unknown_words_raise():
    assert [modes.RANK[w] for w in ("deny", "ask", "cc", "allow", "unconfigured")] == [0, 1, 2, 3, 4]
    assert modes.wmin("cc", "ask") == "ask" and modes.wmin("allow", "unconfigured") == "allow"
    raises(lambda: modes.RANK["maybe"], KeyError)
    raises(lambda: modes.wmin("cc", "nope"), KeyError)
    # consent's RANK holds today's vocabulary on the same scale, and raises
    # for anything else instead of ranking it 0 (§2.6), `.get` included
    assert consent.RANK[False] == consent.RANK["deny"] == 0 and consent.RANK[True] == consent.RANK["cc"]
    for bad in (1, 0, None, "Allow", {"default": "ask"}, ("ask",)):
        raises(lambda b=bad: consent.RANK[b], (KeyError, TypeError))
        raises(lambda b=bad: consent.RANK.get(b, 0), (KeyError, TypeError))
    raises(lambda: consent.rmin("ask", {"default": "ask"}), (KeyError, TypeError))


def test_an_unknown_or_missing_mode_reads_as_default():
    mv = modes.parse({"default": "ask", "auto": True})
    assert mv.word("auto") == "allow"
    assert mv.word("bypassPermissions") == mv.word("bypass")
    assert mv.word("manual") == "ask"
    for m in ("", "AUTO", "yolo", 3):
        assert mv.word(m) == "ask", m           # never allow


# --- §2.3: what a bare word means -------------------------------------------


def test_the_expansion_table():
    #                         default plan acceptEdits auto bypass dontAsk
    assert words(modes.bare(True)) == ("cc", "cc", "cc", "allow", "allow", "cc")
    assert words(modes.bare("allow")) == words(modes.bare(True))
    assert words(modes.bare("ask")) == ("ask",) * 6
    assert words(modes.bare(False)) == ("deny",) * 6
    assert words(modes.bare("cc")) == ("cc",) * 6
    assert words(modes.bare("allow", "policy")) == ("allow", "cc", "allow", "allow", "allow", "allow")
    assert words(modes.bare(True, "network")) == words(modes.bare("allow", "policy"))
    for spelled in ("yes", "on", "TRUE", "Allow"):
        assert modes.bare(spelled) == modes.bare(True), spelled
    for spelled in ("no", "off", "false", "deny"):
        assert modes.bare(spelled) == modes.bare(False), spelled


def test_dont_ask_gets_cc_from_a_bare_true():
    """A bare `true` approves only in auto and bypass (invariant 5); dontAsk
    gets cc, so approving there takes an explicit dontAsk = "allow"."""
    assert modes.bare(True).word("dontAsk") == "cc"
    assert modes.parse({"default": "cc", "dontAsk": "allow"}).word("dontAsk") == "allow"


# --- §2.2: tables --------------------------------------------------------------


def test_a_table_needs_default_and_takes_known_modes_and_words_only():
    assert "default" in raises(lambda: modes.parse({"auto": True}), modes.ModeError)
    assert "isn't a mode" in raises(lambda: modes.parse({"default": "ask", "turbo": True}),
                                    modes.ModeError)
    assert "twice" in raises(lambda: modes.parse({"default": "ask", "manual": "cc"}), modes.ModeError)
    assert "twice" in raises(lambda: modes.parse({"default": "ask", "bypass": True,
                                                  "bypassPermissions": False}), modes.ModeError)
    raises(lambda: modes.parse({"default": "sometimes"}), modes.ModeError)
    raises(lambda: modes.parse({"default": 1}), modes.ModeError)
    raises(lambda: modes.parse("maybe"), modes.ModeError)
    raises(lambda: modes.parse(["ask"]), modes.ModeError)
    # a name that isn't plain is never echoed
    assert "‮" not in raises(lambda: modes.parse({"default": "ask", "x‮y": True}),
                                  modes.ModeError)


def test_a_tables_true_is_allow_in_that_mode_and_plan_degrades_to_cc():
    mv = modes.parse({"default": True, "auto": "ask", "plan": True})
    assert words(mv) == ("allow", "cc", "allow", "ask", "allow", "allow")
    mv = modes.parse({"default": "ask", "auto": True, "plan": False})
    assert words(mv) == ("ask", "deny", "ask", "allow", "ask", "ask")
    # an unlisted mode takes default's word (plan's allow still cc)
    assert modes.parse({"manual": "allow"}).word("plan") == "cc"


# --- §2.4: the modeless rule ---------------------------------------------------


def test_the_modeless_rule():
    """The strictest word over every mode but plan, allow capped at cc."""
    assert modes.bare(True).modeless() == "cc"                        # today's true
    assert modes.parse({"default": "ask", "auto": True}).modeless() == "ask"
    assert modes.parse({"default": False, "auto": True}).modeless() == "deny"
    assert modes.parse({"default": True}).modeless() == "cc"          # allow capped
    assert modes.parse({"default": "cc", "plan": False}).modeless() == "cc"   # plan excluded
    assert modes.parse({"default": "cc", "dontAsk": "ask"}).modeless() == "ask"
    assert modes.bare(True).word(None) == "cc"


def test_legacy_words_are_the_strict_reading():
    assert [modes.legacy(w) for w in ("allow", "cc", "ask", "deny")] == [True, True, "ask", False]
    assert modes.legacy("unconfigured") == "ask"
    raises(lambda: modes.legacy("nope"), KeyError)
    assert modes.parse({"default": "ask", "auto": True}).legacy() == "ask"
    assert modes.parse({"default": "ask", "auto": True}).legacy("auto") is True


def test_values_compare_and_meet_mode_by_mode():
    a = modes.bare("ask")
    f = modes.parse({"default": False, "auto": True})
    assert f.rises(a) == ["auto"]
    assert f.falls(a) == ["default", "plan", "acceptEdits", "bypass", "dontAsk"]
    assert words(f.minimum(a)) == ("deny", "deny", "deny", "ask", "deny", "deny")
    assert f.minimum(f) is f and modes.bare("cc").minimum(a) is a


def test_the_snapshot_encoding_round_trips():
    for v, kind in ((True, "right"), ("ask", "right"), (False, "right"), ("cc", "right"),
                    ("allow", "policy"), ("deny", "policy"), ("cc", "network")):
        mv = modes.parse(v, kind)
        s = mv.snapshot()
        assert not isinstance(s, dict), (v, s)          # a bare word stays a bare word
        assert modes.from_snapshot(s, kind) == mv
    t = modes.parse({"default": "ask", "auto": True})
    s = t.snapshot()
    assert s == dict(zip(ALL, ("ask", "ask", "ask", "allow", "ask", "ask")))
    assert modes.from_snapshot(s) == t
    for bad in ({"default": "ask"}, {**s, "auto": "maybe"}, "sometimes", 3, None):
        assert modes.from_snapshot(bad) is None, bad


def test_a_value_is_frozen_and_writes_back_as_written():
    t = modes.parse({"default": "ask", "auto": True, "plan": False})
    raises(lambda: setattr(t, "words", ("allow",) * 6), AttributeError)
    assert F.toml_value(t) == '{default = "ask", auto = true, plan = false}'
    assert F.toml_value(modes.parse("cc")) == '"cc"' and F.toml_value(modes.parse(True)) == "true"
    assert t.render() == "Manual: ask · Plan: deny · Auto: allow"


# --- the form keeps per-mode values beside strict legacy attributes (§2.6) ----


def test_a_table_never_reaches_a_legacy_reader_as_true():
    f = parse('[hosts.b]\naddress = "b.example.com"\nssh = { default = "ask", auto = true }\n'
              'sudo = { default = false, bypass = true }\n'
              '[accounts.g]\nkind = "github"\nuse = { default = "ask", auto = true }\n'
              '[policy]\nwrite = { default = "allow", dontAsk = "deny" }\n')
    h, a = f.hosts["b"], f.accounts["g"]
    assert h.ssh == "ask" and h.sudo is False
    assert a.use is False, "an account's use is True only where the modeless word is cc"
    assert f.policy["write"] is False
    e = consent.compute(f, {"approved": {"rights": consent.snapshot(f)}})
    assert e.hosts["b"].ssh == "ask" and e.hosts["b"].sudo is False and e.accounts["g"].use is False
    assert e.policy == {"write": False}
    # resolved for a mode instead
    e = consent.compute(f, {"approved": {"rights": consent.snapshot(f)}}, "auto")
    assert e.hosts["b"].ssh is True and e.accounts["g"].use is True and e.policy == {"write": True}


# --- consent per mode (§2.7) ---------------------------------------------------

HOST = '[hosts.box]\naddress = "u@box.example.com"\n'


def test_a_rise_in_any_mode_is_a_widening_and_the_effective_value_is_the_minimum():
    e = run(HOST, HOST + 'sudo = { default = true }\n')
    w = [c.what for c in e.pending_for("box")]
    # in plain words with Claude Code's mode names (WS-2, §2.8), the modes that
    # moved alike in one clause
    assert w == ["sudo on box: in Manual, Accept edits and Don't ask modes the gateway now "
                 "approves without asking you (was: Claude Code decides)"], w
    assert e.word("box", "sudo", "default") == "cc" and e.word("box", "sudo", "auto") == "allow"
    # rises and falls in one change: the fall applies at once, the rise waits
    e = run(HOST + 'sudo = "ask"\n', HOST + 'sudo = { default = false, auto = true }\n')
    assert [c.kind for c in e.pending] == ["widen"] and [c.kind for c in e.narrowed] == ["narrow"]
    assert [e.word("box", "sudo", m) for m in ALL] == ["deny", "deny", "deny", "ask", "deny", "deny"]


def test_ask_to_cc_is_a_widening():
    e = run(HOST + 'ssh = "ask"\n', HOST + 'ssh = "cc"\n')
    assert [c.what for c in e.pending] == [
        "ssh to box: in every mode Claude Code decides (was: asks you in every mode)"], e.pending
    assert e.word("box", "ssh", "default") == "ask"


def test_the_ratchet_keeps_the_per_mode_minimum():
    data = {"approved": {"rights": consent.snapshot(parse(HOST + 'sudo = "ask"\n'))}}
    f = parse(HOST + 'sudo = { default = false, auto = true }\n')
    assert consent.sync_narrowing(data, f)
    snap = data["approved"]["rights"]["hosts"]["box"]["sudo"]
    assert snap == dict(zip(ALL, ("deny", "deny", "deny", "ask", "deny", "deny"))), snap
    e = consent.compute(f, data)
    assert not e.narrowed and [c.what for c in e.pending] == [
        "sudo on box: in Auto mode the gateway now approves without asking you (was: asks you)"]


def test_a_per_mode_policy_compares_mode_by_mode():
    e = run(HOST + '[hosts.box.policy]\nwrite = "ask"\n',
            HOST + '[hosts.box.policy]\nwrite = { default = "ask", bypass = "deny", auto = "allow" }\n')
    assert [c.what for c in e.pending] == [
        "policy write: in Auto mode no restriction, as an explicit allow (was: asks you)"], \
        [c.what for c in e.pending]
    assert any("in Bypass permissions mode it is refused (was: asks you)" in c.what
               for c in e.narrowed)
    d = policy.decide(e, "write", host="box", mode="bypass")
    assert d.value == "deny" and d.word is False and d.mode == "bypass"
    assert policy.decide(e, "write", host="box", mode="auto").value == "ask"     # waits for the OK
    assert policy.decide(e, "write", host="box").value == "deny"                 # modeless


# --- policy.decide per mode ------------------------------------------------------


def test_decide_uses_the_mode_it_is_given_and_the_modeless_rule_without_one():
    f = HOST + 'ssh = { default = "ask", auto = true }\n'
    e = run(f, f)
    assert policy.decide(e, "exec", host="box", mode="auto").value == "allow"
    assert policy.decide(e, "exec", host="box", mode="auto").word is True
    assert policy.decide(e, "exec", host="box", mode="default").value == "ask"
    d = policy.decide(e, "exec", host="box")
    assert d.value == "ask" and d.word == "ask" and d.mode is None and d.mode_label == "modeless"
    assert policy.decide(e, "exec", host="box", mode="bypassPermissions").mode == "bypass"
    # a restriction's allow restricts nothing; the strictest layer names the rule
    g = HOST + '[policy]\nexec = { default = "allow", auto = "ask" }\n'
    e = run(g, g)
    d = policy.decide(e, "exec", host="box", mode="auto")
    assert d.value == "ask" and d.rule.startswith("[policy] exec"), d
    assert policy.decide(e, "exec", host="box", mode="bypass").value == "allow"


def test_this_computers_unconfigured_sudo_is_never_an_approval():
    e = run("", "")
    assert e.word("localhost", "sudo", "auto") == "unconfigured"
    d = policy.decide(e, "elevation", mode="auto")
    assert d.value == "unconfigured" and d.word == "ask", "the strict word for an older reader"
    # an elevation restriction's allow never turns it into the gateway's approval
    for g in ('[policy]\nelevation = "allow"\n',
              '[policy]\nelevation = { default = "allow", bypass = "deny" }\n'):
        e = run(g, g)
        assert policy.decide(e, "elevation", mode="auto").value == "unconfigured", g
    assert policy.decide(e, "elevation", mode="bypass").value == "deny"
    g = '[hosts.localhost.policy]\nelevation = { default = "ask", plan = "deny" }\n'
    e = run(g, g)
    assert policy.decide(e, "elevation", mode="plan").value == "deny"
    assert policy.decide(e, "elevation", mode="default").value == "ask"
    assert e.configured.local_elevation, "an elevation restriction configures this computer's elevation"


def test_an_explicit_per_mode_network_allow_is_flagged_and_a_bare_word_never():
    """Lead decision 19.1: only what the user explicitly wrote for a mode is
    approved; this computer's base stays Claude Code's own (cc)."""
    e = run("", "")
    d = policy.decide(e, "network", mode="auto")
    assert d.value == "cc" and not d.explicit_allow
    g = '[policy]\nnetwork = "allow"\n'
    e = run(g, g)
    assert not policy.decide(e, "network", mode="auto").explicit_allow
    g = '[policy]\nnetwork = { default = "ask", auto = "allow" }\n'
    e = run(g, g)
    assert policy.decide(e, "network", mode="auto").explicit_allow
    assert policy.decide(e, "network", mode="auto").value == "cc"
    assert not policy.decide(e, "network", mode="default").explicit_allow
    assert not policy.decide(e, "network").explicit_allow          # modeless: never
    e = run('[policy]\nnetwork = { default = "allow" }\n', '[policy]\nnetwork = { default = "allow" }\n')
    assert policy.decide(e, "network", mode="dontAsk").explicit_allow, "a table's default is explicit"
    # the approval's table while the form no longer says it: not the user's word now
    e = run(g, "")
    assert e.pending and not policy.decide(e, "network", mode="auto").explicit_allow
    g += '[hosts.localhost.policy]\nnetwork = "ask"\n'
    e = run(g, g)
    assert not policy.decide(e, "network", mode="auto").explicit_allow


def test_a_new_entry_is_deny_in_every_mode_and_an_unknown_one_unconfigured():
    e = consent.compute(parse(HOST + 'ssh = { default = true }\n'), {})
    assert [e.word("box", "ssh", m) for m in ALL] == ["deny"] * 6
    assert e.word("nowhere", "ssh", "auto") == "unconfigured"
    assert e.word("nobody", "use", "auto") == "unconfigured"
    raises(lambda: e.word("box", "write"), KeyError)
    bad = parse('[hosts.box]\naddress = "-bad"\n')
    e = consent.compute(bad, {})
    assert e.word("box", "ssh", "auto") == "deny" and e.refusal("box")


# --- lead decision 19.1: an explicit allow goes through the consent dialog ----


def test_an_explicit_allow_waits_for_the_ok_like_any_widening():
    """A policy table's allow is the user's explicit per-mode allow (on this
    machine the gateway then approves); "no restriction" and a bare "allow"
    share the word but aren't one, so gaining it is a widening: until the OK
    the effective allow is a plain one (Claude Code decides), after it only
    the modes the table allows are explicit."""
    for scope, entry in (("[policy]\n", "settings"), ("[hosts.localhost.policy]\n", "localhost")):
        for table in ('{ default = "allow" }', "{ default = true }"):
            new = scope + f"network = {table}\n"
            for old in ("", scope + 'network = "allow"\n'):
                e = run(old, new)
                w = [c.render() for c in e.pending]
                assert w == [f"{entry}: policy network: in every mode but Plan the gateway now "
                             "approves the http and download tools on this computer without "
                             "asking you (was: no restriction)"], (old, new, w)
                assert not e.narrowed, [c.render() for c in e.narrowed]
                for m in ALL:
                    d = policy.decide(e, "network", mode=m)
                    assert d.value == "cc" and not d.explicit_allow, (old, new, m)
            e = run(new, new)                 # after the OK: the approval is the form's snapshot
            assert not e.pending and not e.narrowed
            assert [policy.decide(e, "network", mode=m).explicit_allow for m in ALL] == \
                [True, False, True, True, True, True], (scope, table)
    # a remote host's table: the same comparison (it approves nothing there: the
    # host's ssh right is the base), worded without the approval note
    e = run(HOST, HOST + '[hosts.box.policy]\nexec = { default = "allow" }\n')
    assert [c.what for c in e.pending_for("box")] == [
        "policy exec: in every mode but Plan no restriction, as an explicit allow (was: no "
        "restriction)"]


def test_the_ratchet_never_records_an_explicit_allow():
    """A table that lowers one mode and explicitly allows the others: the
    lowered mode applies at once and is recorded, the explicit allows wait
    for the OK (the snapshot lists them as plain)."""
    data = {"approved": {"rights": consent.snapshot(parse(""))}}
    f = parse('[policy]\nnetwork = { default = "allow", bypass = "deny" }\n')
    assert consent.sync_narrowing(data, f)
    snap = data["approved"]["rights"]["settings"]["policy"]["network"]
    assert snap["bypass"] == "deny" and snap["plain"] == ["default", "acceptEdits", "auto", "dontAsk"]
    e = consent.compute(f, data)
    assert not e.narrowed and len(e.pending) == 1 and \
        "now approves the http and download tools on this computer without asking you" in \
        e.pending[0].what
    assert policy.decide(e, "network", mode="bypass").value == "deny"
    assert not any(policy.decide(e, "network", mode=m).explicit_allow for m in ALL)


def test_an_explicit_allow_taken_back_applies_at_once_and_one_kept_stays():
    g = '[policy]\nnetwork = { default = "allow" }\n'
    data = {"approved": {"rights": consent.snapshot(parse(g))}}
    f = parse('[policy]\nnetwork = "allow"\n')
    e = consent.compute(f, data)
    assert not e.pending and any(
        "in every mode but Plan no restriction (was: the gateway approves the http and download "
        "tools on this computer)" in c.what
        for c in e.narrowed), [c.what for c in e.narrowed]
    assert not policy.decide(e, "network", mode="default").explicit_allow
    assert consent.sync_narrowing(data, f)
    assert data["approved"]["rights"]["settings"]["policy"]["network"] is True
    assert not consent.compute(f, data).narrowed, "the ratchet settles (no write on every load)"
    # explicit on both sides where the effective value is the approval's own
    a = '[policy]\nnetwork = { default = "allow", auto = "ask" }\n'
    e = consent.compute(parse(g), {"approved": {"rights": consent.snapshot(parse(a))}})
    assert [c.what for c in e.pending] == [
        "policy network: in Auto mode the gateway now approves the http and download tools on "
        "this computer without asking you (was: asks you)"]
    assert policy.decide(e, "network", mode="default").explicit_allow
    assert policy.decide(e, "network", mode="auto").value == "ask"


def test_rights_and_network_commands_have_no_explicit_allow_of_their_own():
    """Their bare allow already approves (§2.3, 19.1): a table spelling the
    same words is no change."""
    e = run(HOST + "ssh = true\n", HOST + 'ssh = { default = "cc", auto = true, bypass = true }\n')
    assert not e.pending and not e.narrowed
    n = "[network]\n"
    e = run(n + 'commands = "allow"\n', n + 'commands = { default = "allow", plan = "cc" }\n')
    assert not e.pending and not e.narrowed
    assert modes.parse({"default": True}).explicit == frozenset()


def test_the_snapshot_keeps_which_allows_are_explicit():
    t = modes.parse({"default": "allow", "bypass": "deny"}, "policy")
    assert t.explicit == {"default", "acceptEdits", "auto", "dontAsk"}
    s = t.snapshot()
    assert "plain" not in s and modes.from_snapshot(s, "policy") == t
    m = t.minimum(modes.bare("allow", "policy"))
    assert m.words == t.words and m.explicit == frozenset() and m != t
    s = m.snapshot()
    assert s["plain"] == ["default", "acceptEdits", "auto", "dontAsk"], s
    assert modes.from_snapshot(s, "policy") == m
    assert modes.bare("allow", "policy").snapshot() is True
    for bad in ({**s, "plain": ["bypass"]}, {**s, "plain": "default"}, {**s, "plain": []}):
        assert modes.from_snapshot(bad, "policy") is None, bad
    assert modes.from_snapshot(s, "right") is None, "only a policy value has plain allows"
