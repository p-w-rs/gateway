"""Consent: every widening and narrowing case of SPEC 5, effective rights,
approve(), the narrowing ratchet and bindings."""
from __future__ import annotations

import copy
import re
from pathlib import Path

import harness as H
from gateway import consent, modes, paths, policy, vault
from gateway import form as F


def parse(t: str) -> F.Form:
    return F.parse_text(t, Path("/x"))


HOST = '[hosts.box]\naddress = "u@box.example.com"\n'
GH = '[accounts.gh]\nkind = "github"\nlogin = "me"\npackages = false\n'
KEY = '[accounts.key]\nkind = "api-key"\nsites = ["api.x.com"]\n'
AZ = '[accounts.az]\nkind = "azure"\ntenant = "t.example.com"\n'


def run(old: str, new: str, mode: str | None = None) -> consent.Effective:
    data = {"approved": {"rights": consent.snapshot(parse(old))}}
    return consent.compute(parse(new), data, mode)


# (id, old form, new form, [widen substrings], [narrow substrings], extra check)
TABLE = [
    # --- widening ---
    ("new_host", "", HOST, ["box: new host"], [],
     lambda e: e.hosts["box"].new and e.hosts["box"].ssh is False and e.hosts["box"].sudo is False),
    ("sudo_false_to_ask", HOST + "sudo = false\n", HOST + 'sudo = "ask"\n', ["sudo on box: in every mode you are asked (was: refused in every mode)"], [],
     lambda e: e.hosts["box"].sudo is False),
    ("sudo_ask_to_true", HOST + 'sudo = "ask"\n', HOST + "sudo = true\n", ["sudo on box: in Auto and Bypass permissions modes the gateway now approves without asking you; elsewhere Claude Code decides (was: asks you in every mode)"], [],
     lambda e: e.hosts["box"].sudo == "ask"),
    ("sudo_false_to_true", HOST + "sudo = false\n", HOST, ["sudo on box: in Auto and Bypass permissions modes the gateway now approves without asking you; elsewhere Claude Code decides (was: refused in every mode)"], [],
     lambda e: e.hosts["box"].sudo is False),
    ("ssh_false_to_true", HOST + "ssh = false\n", HOST, ["ssh to box: in Auto and Bypass permissions modes the gateway now approves without asking you; elsewhere Claude Code decides (was: refused in every mode)"], [],
     lambda e: e.hosts["box"].ssh is False),
    ("localhost_sudo_raised", '[hosts.localhost]\nsudo = false\n', '[hosts.localhost]\nsudo = true\n',
     ["localhost: sudo on this computer: in Auto and Bypass permissions modes the gateway now approves without asking you; elsewhere Claude Code decides (was: refused in every mode)"], [], lambda e: e.hosts["localhost"].sudo is False),
    ("host_scripts_on", HOST, HOST + "scripts = true\n", ["scripts false -> true"], [],
     lambda e: e.hosts["box"].scripts is False),
    # a dropped address is a widening too (PLAN-0.11 §1.1): it still
    # classifies (held) until the OK, and is never connected to
    ("address_changed", HOST, '[hosts.box]\naddress = "u@evil.example.com"\n',
     ["new address u@evil.example.com", "address u@box.example.com dropped"], [],
     lambda e: e.hosts["box"].addresses == [] and e.hosts["box"].ssh is False
     and [a.render() for a in e.hosts["box"].held_addresses] == ["u@box.example.com"]),
    ("address_user_changed", HOST, '[hosts.box]\naddress = "root@box.example.com"\n',
     ["new address root@box.example.com", "address u@box.example.com dropped"], [],
     lambda e: e.hosts["box"].ssh is False),
    ("also_added", HOST, HOST + 'also = ["u@box2.example.com:2222"]\n',
     ["new address u@box2.example.com:2222"], [],
     lambda e: [a.render() for a in e.hosts["box"].addresses] == ["u@box.example.com"] and e.hosts["box"].ssh is True),
    # any change of `when` waits, and the approved address (with its approved
    # `when`) applies meanwhile
    ("when_removed", HOST + 'when = "10.0.0.0/24"\n', HOST, ["on any network"], [],
     lambda e: [a.when for a in e.hosts["box"].addresses] == ["10.0.0.0/24"]),
    ("when_changed", HOST + 'when = "10.0.0.0/24"\n', HOST + 'when = "10.9.0.0/16"\n', ["10.9.0.0/16"], [],
     lambda e: [a.when for a in e.hosts["box"].addresses] == ["10.0.0.0/24"]),
    ("when_added", HOST, HOST + 'when = "10.0.0.0/24"\n',
     ["on 10.0.0.0/24 (was any network; outside that network it would stop going through the gateway"], [],
     lambda e: [a.when for a in e.hosts["box"].addresses] == [None] and e.hosts["box"].ssh is True),
    ("via_added", HOST + '[hosts.j]\naddress = "j.example.com"\n',
     HOST + 'via = "j"\n[hosts.j]\naddress = "j.example.com"\n', ["via j (was direct)"], [],
     lambda e: e.hosts["box"].via is None),
    ("via_changed", HOST + 'via = "j"\n[hosts.j]\naddress = "j.example.com"\n[hosts.k]\naddress = "k.example.com"\n',
     HOST + 'via = "k"\n[hosts.j]\naddress = "j.example.com"\n[hosts.k]\naddress = "k.example.com"\n',
     ["via k (was j)"], [], lambda e: e.hosts["box"].via == "j"),
    ("new_account", "", GH, ["gh: new github account"], [],
     lambda e: e.accounts["gh"].new and not e.accounts["gh"].use and e.accounts["gh"].destinations == []),
    ("api_key_new_site", KEY, KEY.replace('["api.x.com"]', '["api.x.com", "evil.example.com"]'),
     ["may now send to evil.example.com"], [],
     lambda e: e.accounts["key"].destinations == ["api.x.com"]),
    ("api_key_wildcard_site", KEY, KEY.replace('["api.x.com"]', '[".x.com"]'),
     ["may now send to .x.com", "no longer sends to api.x.com"], [],
     lambda e: e.accounts["key"].destinations == [] and e.accounts["key"].held_destinations == ["api.x.com"]),
    ("api_key_auth_changed", KEY, KEY + 'auth = "query:key"\n', ["auth placement bearer -> query:key"], [],
     lambda e: e.accounts["key"].auth == "bearer"),
    ("azure_workspace", AZ, AZ + 'databricks = ["adb-9.9.azuredatabricks.net"]\n', ["may now send to adb-9.9"], [], None),
    ("azure_storage", AZ, AZ + 'storage = ["acct"]\n', ["acct.blob.core.windows.net", "acct.dfs.core.windows.net"], [], None),
    ("azure_registry", AZ, AZ + 'registries = ["x.azurecr.io"]\n', ["may now send to x.azurecr.io"], [], None),
    ("azure_site", AZ, AZ + 'sites = ["api.custom.example.com"]\n', ["may now send to api.custom.example.com"], [], None),
    ("azure_tenant_changed", AZ, AZ.replace("t.example.com", "other.example.com"),
     ["tenant t.example.com -> other.example.com (needs a new sign-in)"], [],
     lambda e: e.accounts["az"].tenant == "t.example.com"),
    ("account_host_changed", GH, GH + 'host = "ghe.evil.example.com"\n',
     ["may now send to ghe.evil.example.com", "no longer sends to github.com"], [],
     lambda e: e.accounts["gh"].destinations == []),
    ("packages_on", GH, GH.replace("packages = false", "packages = true"), ["may now send to ghcr.io"], [], None),
    ("env_added", KEY, KEY + 'env = "X_KEY"\n', ["env X_KEY"], [], lambda e: e.accounts["key"].env is None),
    ("env_changed", KEY + 'env = "X_KEY"\n', KEY + 'env = "Y_KEY"\n', ["env Y_KEY", "was X_KEY"], [],
     lambda e: e.accounts["key"].env is None),
    ("account_scripts_on", GH, GH + "scripts = true\n", ["scripts false -> true"], [],
     lambda e: not e.accounts["gh"].scripts),
    ("use_back_on", GH + "use = false\n", GH, ["use: in every mode Claude Code decides (was: refused in every mode)"], [], lambda e: not e.accounts["gh"].use),
    # [settings] is gone (PLAN-0.11): a written one changes nothing
    ("settings_table_ignored", "", '[settings]\nothers = "mine"\n', [], [], None),
    ("kind_changed", GH, '[accounts.gh]\nkind = "huggingface"\n', ["kind changed to huggingface"], [],
     lambda e: e.accounts["gh"].new),
    # --- narrowing ---
    ("sudo_true_to_ask", HOST, HOST + 'sudo = "ask"\n', [], ["sudo on box: in every mode you are asked (was: the gateway approves in Auto and Bypass permissions modes, Claude Code decides elsewhere)"], lambda e: e.hosts["box"].sudo == "ask"),
    ("sudo_ask_to_false", HOST + 'sudo = "ask"\n', HOST + "sudo = false\n", [], ["sudo on box: in every mode it is refused (was: asks you in every mode)"], None),
    ("ssh_true_to_false", HOST, HOST + "ssh = false\n", [], ["ssh to box: in every mode it is refused (was: the gateway approves in Auto and Bypass permissions modes, Claude Code decides elsewhere)"], lambda e: e.hosts["box"].ssh is False),
    # --- taking a target out of the gateway: widenings (PLAN-0.11 §1.1); the
    #     approved entry keeps classifying and gating until the OK ---
    ("host_removed", HOST, "", ["box: box will stop going through the gateway"], [],
     lambda e: e.hosts["box"].removed and e.hosts["box"].ssh is True
     and [a.render() for a in e.hosts["box"].addresses] == ["u@box.example.com"]
     and "box" in e.configured.hosts),
    ("also_removed", HOST + 'also = ["u@b2.example.com"]\n', HOST, ["address u@b2.example.com dropped"], [],
     lambda e: [a.render() for a in e.hosts["box"].held_addresses] == ["u@b2.example.com"]
     and e.configured.host_named("b2.example.com") == "box"),
    ("via_removed", HOST + 'via = "j"\n[hosts.j]\naddress = "j.example.com"\n',
     HOST + '[hosts.j]\naddress = "j.example.com"\n', ["via j dropped"], [], lambda e: e.hosts["box"].via == "j"),
    ("site_removed", KEY.replace('["api.x.com"]', '["api.x.com", "b.x.com"]'), KEY,
     ["no longer sends to b.x.com"], [], lambda e: e.accounts["key"].held_destinations == ["b.x.com"]),
    ("account_removed", GH, "", ["gh: gh will stop going through the gateway"], [],
     lambda e: e.accounts["gh"].removed and e.accounts["gh"].use is True and "gh" in e.configured.accounts),
    ("owner_dropped", GH + 'owners = ["acme"]\n', GH, ["owner acme dropped"], [],
     lambda e: e.accounts["gh"].held_owners == ["acme"]),
    ("localhost_sudo_key_removed", '[hosts.localhost]\nsudo = "ask"\n', "[hosts.localhost]\nscripts = false\n",
     ["localhost: sudo stops going through the gateway"], [],
     lambda e: e.word("localhost", "sudo", "default") == "ask" and e.configured.localhost_sudo),
    ("localhost_table_removed", '[hosts.localhost]\nsudo = false\n', "",
     ["localhost: sudo stops going through the gateway"], [],
     lambda e: e.hosts["localhost"].sudo is False),
    ("use_off", GH, GH + "use = false\n", [], ["use: in every mode it is refused (was: Claude Code decides in every mode)"], lambda e: not e.accounts["gh"].use),
    ("env_removed", KEY + 'env = "X_KEY"\n', KEY, [], ["env X_KEY removed"], lambda e: e.accounts["key"].env is None),
    ("scripts_off", HOST + "scripts = true\n", HOST, [], ["scripts true -> false"], None),
    # an owner (or login) added goes through the gateway at once
    # (the first owner listed also takes every other owner out: a widening, WS-9)
    ("owners_added_narrows", GH, GH + 'owners = ["acme"]\n', ["owners listed (as the only github account"],
     ["owner acme now goes through the gateway"], lambda e: e.accounts["gh"].owners == ["acme"]),
    ("owner_added_beside_others_only_narrows", GH + 'owners = ["acme"]\n', GH + 'owners = ["acme", "umbrella"]\n',
     [], ["owner umbrella now goes through the gateway"], None),
    ("login_changed", GH, GH.replace('"me"', '"you"'), ["owner me dropped"], ["owner you now goes through the gateway"],
     None),
    # --- neither ---
    ("note_changes", HOST + GH, HOST + 'note = "x"\n' + GH, [], [], None),
    ("addresses_reordered", HOST + 'also = ["u@b2.example.com"]\n',
     '[hosts.box]\naddress = "u@b2.example.com"\nalso = ["u@box.example.com"]\n', [], [], None),
    ("disabled_entry_not_narrowing", HOST, '[hosts.box]\naddress = "-bad"\n', [], [], lambda e: "box" not in e.hosts),
]


def _make(cid, old, new, widen, narrow, check):
    def t():
        e = run(old, new)
        w = [c.render() for c in e.pending]
        n = [c.render() for c in e.narrowed]
        for s in widen:
            assert any(s in x for x in w), (s, w)
        for s in narrow:
            assert any(s in x for x in n), (s, n)
        if not widen:
            assert not w, w
        if not narrow:
            assert not n, n
        if check:
            assert check(e), (w, n)
    t.__name__ = f"test_consent_{cid}"
    return t


for _row in TABLE:
    globals()[f"test_consent_{_row[0]}"] = _make(*_row)


def test_unchanged_form_has_no_changes_and_full_rights():
    t = HOST + GH + KEY
    e = run(t, t)
    assert not e.pending and not e.narrowed
    assert e.hosts["box"].ssh is True and e.accounts["gh"].destinations == ["github.com", "api.github.com"]
    assert not hasattr(e, "others")


def test_baseline_without_approvals():
    with H.gateway_env():               # compute(form, None) reads the configured list
        e = consent.compute(parse(""), None)
        assert not e.pending and e.hosts["localhost"].sudo == "ask", \
            "with nothing approved, sudo on this computer asks each time"
        assert not e.unreadable, "no vault and no list: nothing approved, nothing unreadable"
        assert consent.baseline()["hosts"]["localhost"]["sudo"] == "ask"
        e = consent.compute(parse(F.STARTER), None)
        assert not e.pending and e.hosts["localhost"].sudo == "ask", \
            "the starter form needs no OK and asks for sudo each time"
    e = consent.compute(parse(HOST), {})
    assert e.pending_names() == ["box"]


def test_jump_host_off_makes_target_unreachable():
    old = HOST + 'via = "j"\n[hosts.j]\naddress = "j.example.com"\n'
    new = HOST + 'via = "j"\n[hosts.j]\naddress = "j.example.com"\nssh = "ask"\n'
    e = run(old, new)
    assert e.hosts["box"].ssh == "ask", "a jump host's lower right caps the target"


def test_bound_check_makes_destination_pending():
    f = parse(GH)
    data = {"approved": {"rights": consent.snapshot(f)},
            "accounts": {"gh": {"kind": "github", "bound": {"hosts": ["github.com"]}}}}
    e = consent.compute(f, data)
    assert e.accounts["gh"].destinations == ["github.com"]
    assert any("not yet bound to api.github.com" in c.what for c in e.pending)
    assert consent.unbound(f.accounts["gh"], data) == ["api.github.com"]
    assert consent.bound_ok(data, "gh", "github.com") and not consent.bound_ok(data, "gh", "api.github.com")


def test_approve_records_rights_bindings_and_event():
    with H.gateway_env() as env:
        env.write_form(HOST + KEY + 'env = "X_KEY"\n')
        f = env.form()
        e = consent.compute(f, None)
        assert set(e.pending_names()) == {"box", "key"}
        vault.save(vault.empty())
        shown = consent.compute(f, vault.load()).pending_for("box")
        lines = consent.approve("box", shown, form=f)
        assert lines and lines[0].startswith("box: new host")
        # the form changed while the pop-up was open: nothing is approved
        shown_key = [c.render() for c in consent.compute(f, vault.load()).pending_for("key")]
        env.write_form(HOST + KEY.replace('["api.x.com"]', '["api.x.com", "evil.example.com"]') + 'env = "X_KEY"\n')
        try:
            consent.approve("key", shown_key, form=env.form())
        except consent.ConsentChanged:
            pass
        else:
            raise AssertionError("approving changes the user didn't see must fail")
        assert "key" not in (vault.load()["approved"]["rights"]["accounts"])
        lines = consent.approve("key", shown_key, form=f)
        data = vault.load()
        e = consent.compute(f, data)
        assert not e.pending, [c.render() for c in e.pending]
        assert e.accounts["key"].env == "X_KEY" and e.accounts["key"].destinations == ["api.x.com"]
        assert data["accounts"]["key"]["bound"] == {"hosts": ["api.x.com"], "auth": "bearer"}
        assert [ev["what"] for ev in data["events"]] == ["widen", "widen"]
        try:
            consent.approve("nope", f)
        except KeyError:
            pass
        else:
            raise AssertionError("unknown entry must fail")


def test_narrowing_ratchet_requires_ok_to_widen_again():
    with H.gateway_env():
        on = parse(HOST + GH)
        data = vault.empty()
        data["approved"] = {"rights": consent.snapshot(on)}
        vault.account_record(data, "gh", "github")["bound"]["hosts"] = ["github.com", "api.github.com"]
        ch = consent.sync_narrowing(data, parse(HOST + "sudo = false\n"))
        assert any("sudo on box: in every mode it is refused" in c.render() for c in ch)
        # taking the account out is a widening (PLAN-0.11 §1.1): the ratchet
        # keeps its approval and bindings
        assert not any(c.entry == "gh" for c in ch)
        assert "gh" in data["approved"]["rights"]["accounts"]
        assert data["accounts"]["gh"]["bound"]["hosts"] == ["github.com", "api.github.com"]
        e = consent.compute(on, data)
        assert any("sudo on box: in Auto and Bypass permissions modes the gateway now approves"
                   in c.render() for c in e.pending), "raising again needs the OK"
        assert "gh" not in e.pending_names(), "the account never left the approval"


def test_sync_narrowing_skips_disabled_entries_and_syntax_errors():
    good = parse(HOST + "sudo = true\n")
    data = {"approved": {"rights": consent.snapshot(good)}}
    assert consent.sync_narrowing(data, parse('[hosts.box]\naddress = "-bad"\n')) == []
    assert "box" in data["approved"]["rights"]["hosts"]
    broken = F.parse_text("[hosts.box\n", Path("/x"))
    assert broken.syntax_error is not None
    assert consent.sync_narrowing(data, broken) == []


def test_sync_narrowing_never_widens():
    old = parse(HOST + 'sudo = "ask"\n')
    data = {"approved": {"rights": consent.snapshot(old)}}
    consent.sync_narrowing(data, parse(HOST + 'sudo = true\nssh = false\n'))
    r = data["approved"]["rights"]["hosts"]["box"]
    assert r["sudo"] == "ask" and r["ssh"] is False


def test_close_masters_called_for_narrowed_hosts():
    from gateway import ssh
    calls = []
    orig = ssh.close_masters
    ssh.close_masters = lambda n: calls.append(n) or 1
    try:
        e = run(HOST + 'also = ["u@b2.example.com"]\n[hosts.c]\naddress = "c.example.com"\n',
                HOST + 'also = ["u@b2.example.com"]\nssh = "ask"\n[hosts.c]\naddress = "c.example.com"\n'
                'sudo = false\n')
        closed = consent.close_masters_for(e.narrowed, parse(HOST))
        assert calls == ["box"] and closed == ["box"], (calls, [c.render() for c in e.narrowed])
    finally:
        ssh.close_masters = orig
    # the real ssh.close_masters, in a test env: it finds no master and the
    # host still counts as handled (it never raises)
    with H.gateway_env():
        assert consent.close_masters_for(e.narrowed) == ["box"]


def test_a_written_settings_table_is_a_warning_that_changes_nothing():
    """[settings] (its `others`) is gone (PLAN-0.11 §0.2): a written table is a
    warning that changes nothing and never reaches the approved snapshot."""
    form = parse('[settings]\nothers = "mine"\n')
    assert any("[settings] was removed" in w.render() for w in form.warnings), form.warnings
    assert "settings" not in consent.snapshot(form) or \
        "others" not in consent.snapshot(form)["settings"]
    e = consent.compute(form, {"approved": {"rights": consent.snapshot(parse(""))}})
    assert not e.pending and not e.narrowed


def test_name_clash_keeps_the_dropped_entrys_approval():
    old = parse(HOST + GH)
    data = {"approved": {"rights": consent.snapshot(old)},
            "accounts": {"gh": {"kind": "github", "bound": {"hosts": ["github.com", "api.github.com"]}}}}
    # a later [hosts.gh] clashes with nothing; a later [accounts.box] is dropped
    clash = parse(HOST + GH + '[accounts.box]\nkind = "huggingface"\n')
    assert clash.is_disabled("box", "accounts") and "box" in clash.hosts
    e = consent.compute(clash, data)
    assert not e.narrowed, [c.render() for c in e.narrowed]
    # the earlier entry still ratchets normally
    clash2 = parse(HOST + 'sudo = false\n' + GH + '[accounts.box]\nkind = "huggingface"\n')
    ch = consent.sync_narrowing(data, clash2)
    assert any("box: sudo on box: in every mode it is refused" in c.render() for c in ch)
    assert data["approved"]["rights"]["hosts"]["box"]["sudo"] is False
    assert data["accounts"]["gh"]["bound"]["hosts"] == ["github.com", "api.github.com"]


def test_a_0_6_conversions_imported_rights_grant_nothing():
    """A vault converted from 0.6 next to the user's own gateway.toml kept
    the converted entries' rights in `imported` (gateway.from-v2.toml).
    Nothing reads them any more: an entry copied into the form is new, waits
    for the user's OK like any other, and the ratchet moves nothing."""
    v2form = parse(HOST + GH)
    data = {"approved": {}, "imported": {"from": "v2", "rights": consent.snapshot(v2form)},
            "accounts": {"gh": {"kind": "github", "bound": {"hosts": ["github.com", "api.github.com"]}}}}
    copied = parse('[hosts.localhost]\nsudo = false\n' + HOST + 'sudo = "ask"\n' + GH)
    e = consent.compute(copied, data)
    assert sorted(e.pending_names()) == ["box", "gh"], [c.render() for c in e.pending]
    assert e.hosts["box"].ssh is False and e.accounts["gh"].destinations == []
    consent.sync_narrowing(data, copied)
    assert "box" not in data["approved"]["rights"]["hosts"]
    assert "gh" not in data["approved"]["rights"]["accounts"]
    assert consent.drops_credential({**data, "accounts": {"gh": {"kind": "github", "token": {
        "value": "t" * 20}}}}, copied.accounts["gh"]), "a stored token isn't kept by `imported`"


def test_ratchet_persists_and_is_cheap_when_nothing_narrowed():
    with H.gateway_env() as env:
        env.write_form(HOST + 'sudo = "ask"\n')
        vault.save(vault.empty())
        consent.approve_all(env.form())
        before = vault.load()
        assert consent.ratchet() == []
        assert vault.load() == before, "nothing narrowed: nothing written"
        env.write_form(HOST + "sudo = false\n")
        ch = consent.ratchet()
        assert ch and vault.load()["approved"]["rights"]["hosts"]["box"]["sudo"] is False
        assert vault.load()["events"][-1]["what"] == "narrow"
        # a missing form never ratchets
        env.form_path.unlink()
        assert consent.ratchet() == [] and "box" in vault.load()["approved"]["rights"]["hosts"]


def test_sync_narrowing_never_runs_on_a_missing_form():
    """A missing form would read as every key at its strictest default (and,
    before 0.11, every entry removed): nothing of it is persisted."""
    good = parse(HOST + GH + '[shell]\nmanaged = "off"\n')
    data = {"approved": {"rights": consent.snapshot(good)},
            "accounts": {"gh": {"kind": "github", "bound": {"hosts": ["github.com"]}}}}
    missing = parse("")
    missing.exists = False
    assert consent.compute(missing, data).narrowed, "the empty form is narrower (managed on)"
    assert consent.sync_narrowing(data, missing) == []
    assert "box" in data["approved"]["rights"]["hosts"] and data["accounts"]["gh"]["bound"]["hosts"]
    assert data["approved"]["rights"]["settings"]["shell"]["managed"] == "off"
    assert not consent.needs_sync(data, missing)


def test_a_stored_credential_never_outlives_its_entry_into_a_new_account():
    """Review round 2: removing an account kept its key; adding an entry of
    the same name with other sites (or changing its kind) showed "new api-key
    account" / "kind changed", planned no secret entry, and after the OK the
    old key went to the new destination. A credential belongs to the approved
    identity (name + kind): such an approval drops it and asks for a new one."""
    from gateway import gate_setup, web
    old = '[accounts.key]\nkind = "api-key"\nsites = ["api.x.com"]\n'
    new = '[accounts.key]\nkind = "api-key"\nsites = ["api.other.example"]\n'
    kind = '[accounts.key]\nkind = "registry"\nhost = "reg.other.example"\n'
    for label, second, url in (("re-added", new, "https://api.other.example/v1"),
                               ("kind changed", kind, "https://reg.other.example/v2/")):
        with H.gateway_env() as env:
            env.write_form(old)
            vault.save(vault.empty())
            consent.approve("key", form=env.form())
            with vault.edit() as d:
                vault.account_record(d, "key", "api-key")["token"] = {
                    "value": "SECRETVALUE-123456", "source": "pasted", "updated": "x",
                    "stale": False}
                vault.account_record(d, "key")["host_keys"] = ["ssh-ed25519 AAAAold"]
            if label == "re-added":
                env.write_form("")
                consent.ratchet(env.form())
                assert "key" in vault.load()["approved"]["rights"]["accounts"], \
                    "a removal waits for the OK (PLAN-0.11 §1.1)"
                consent.approve("key", form=env.form())         # the user OKs the removal
                assert "key" not in vault.load()["approved"]["rights"]["accounts"]
                assert vault.load()["accounts"]["key"].get("token"), "removal keeps it (gate forget)"
            env.write_form(second)
            form = env.form()
            data = vault.load()
            eff = consent.compute(form, data)
            assert consent.drops_credential(data, form.accounts["key"]), label
            p = gate_setup.plan_for("key", form, eff, data)
            assert p.needs_signin, (label, "the secret must be asked for again")
            consent.approve("key", eff.pending_for("key"), form=form)
            rec = vault.load()["accounts"]["key"]
            assert not any(rec.get(k) for k in consent.CREDENTIAL_FIELDS), (label, rec)
            assert any(e["what"] == "forget" for e in vault.load()["events"])
            try:
                c = web.credential("key", url)
            except web.Refused:
                c = None
            assert c is None, (label, "no credential is stored for the new account yet", c)
    # a plain widening of the same account keeps its credential
    with H.gateway_env() as env:
        env.write_form(old)
        vault.save(vault.empty())
        consent.approve("key", form=env.form())
        with vault.edit() as d:
            vault.account_record(d, "key", "api-key")["token"] = {
                "value": "SECRETVALUE-123456", "source": "pasted", "updated": "x", "stale": False}
        env.write_form(old.replace('["api.x.com"]', '["api.x.com", "api2.x.com"]'))
        form = env.form()
        assert not consent.drops_credential(vault.load(), form.accounts["key"])
        consent.approve("key", consent.compute(form, vault.load()).pending_for("key"), form=form)
        assert vault.load()["accounts"]["key"]["token"]["value"] == "SECRETVALUE-123456"


def test_a_catalog_account_without_host_is_off_until_named_and_keeps_its_approval():
    """No default catalog host any more: an existing ml-catalog account that
    relied on it is off (a named error) until `host` is added; meanwhile its
    approval, binding and sign-in are kept (a disabled entry never ratchets),
    so naming the same host again needs no new OK and drops nothing."""
    host = "catalog.example.com"
    with_host = f'[accounts.catalog]\nkind = "ml-catalog"\nhost = "{host}"\n'
    data = {"approved": {"rights": consent.snapshot(parse(with_host))},
            "accounts": {"catalog": {"kind": "ml-catalog", "bound": {"hosts": [host]},
                                     "entra": {"refresh_token": "rt-not-real-123"}}}}
    f = parse('[accounts.catalog]\nkind = "ml-catalog"\n')
    assert f.is_disabled("catalog", "accounts") and "catalog" not in f.accounts
    assert not consent.sync_narrowing(data, f)
    assert data["approved"]["rights"]["accounts"]["catalog"]["destinations"] == [host]
    assert data["accounts"]["catalog"]["bound"]["hosts"] == [host]
    f2 = parse(with_host)
    e = consent.compute(f2, data)
    assert not e.pending and e.accounts["catalog"].use is True
    assert consent.bound_ok(data, "catalog", host)
    assert not consent.drops_credential(data, f2.accounts["catalog"])


# ---------------------------------------------------------------------------
# PLAN-0.11: this computer's sudo, the configured set, removals, [network]
# ---------------------------------------------------------------------------

LOCAL = "[hosts.localhost]\n"
LOCAL_ASK_TO_TRUE = ("localhost: sudo on this computer: in Auto and Bypass permissions modes the gateway "
                     "now approves without asking you; elsewhere Claude Code decides (was: asks "
                     "you in every mode)")


def test_this_computers_sudo_unconfigured_is_the_users_own_and_configuring_it_narrows_up_to_ask():
    e = run("", "")
    assert e.word("localhost", "sudo", "auto") == "unconfigured" and not e.pending and not e.narrowed
    assert not e.configured.localhost_sudo
    assert "sudo" not in e.hosts["localhost"].modes and e.hosts["localhost"].sudo == "ask"
    # sudo = "ask" (gate host set localhost sudo ask) applies at once: a narrowing
    # from unconfigured that the ratchet records
    e = run("", LOCAL + 'sudo = "ask"\n')
    assert not e.pending and any("now goes through the gateway" in c.what for c in e.narrowed)
    assert e.word("localhost", "sudo", "auto") == "ask" and e.configured.localhost_sudo
    # above "ask" waits for the OK and runs as "ask" meanwhile (a stored
    # password never reaches a new true unasked)
    e = run("", LOCAL + "sudo = true\n")
    assert [c.render() for c in e.pending] == [LOCAL_ASK_TO_TRUE], e.pending
    assert [e.word("localhost", "sudo", m) for m in ("default", "auto")] == ["ask", "ask"]
    assert e.hosts["localhost"].sudo == "ask"
    e = run("", LOCAL + "sudo = false\n")
    assert not e.pending and e.hosts["localhost"].sudo is False
    # the ratchet records it configured: deleting the key later is a widening
    data = {"approved": {"rights": consent.snapshot(parse(""))}}
    assert consent.sync_narrowing(data, parse(LOCAL + 'sudo = { default = "ask", plan = false }\n'))
    snap = data["approved"]["rights"]["hosts"]["localhost"]
    assert snap["sudo_configured"] is True and snap["sudo"]["plan"] == "deny", snap
    e = consent.compute(parse(""), data)
    assert any("sudo stops going through the gateway" in c.what for c in e.pending_for("localhost"))
    assert e.word("localhost", "sudo", "plan") == "deny" and e.configured.localhost_sudo


def test_a_snapshot_from_before_0_11_counts_localhost_as_implicit():
    old = {"approved": {"rights": {"settings": {"others": "refuse", "shell": {"managed": "on", "import_path": [], "import_env": []}}, "accounts": {},
                                   "hosts": {"localhost": {"sudo": True, "scripts": False}}}}}
    e = consent.compute(parse(""), old)
    assert not e.pending and e.word("localhost", "sudo", "auto") == "unconfigured"
    e = consent.compute(parse(LOCAL + "sudo = true\n"), old)
    assert [c.render() for c in e.pending] == [LOCAL_ASK_TO_TRUE]


def test_a_new_entry_waits_and_nothing_recorded_approves_nothing():
    with H.gateway_env():
        e = consent.compute(parse(HOST + GH), None)
    assert sorted(e.pending_names()) == ["box", "gh"]
    assert e.hosts["box"].new and e.word("box", "ssh", "auto") == "deny"
    assert e.refusal("box") == "box waits for the user's OK (gate check box)"


def test_removal_keeps_the_approved_entry_gating_and_its_ok_takes_it_out():
    with H.gateway_env() as env:
        env.write_form(HOST + GH)
        vault.save(vault.empty())
        consent.approve_all(env.form())
        assert consent.load_listed()["hosts"]["box"]["addresses"][0]["host"] == "box.example.com"
        env.write_form('[policy]\nwrite = "deny"\n')          # the entries gone, and a narrowing
        assert [c.what for c in consent.ratchet(env.form())] == [
            "policy write: in every mode it is refused (was: Claude Code decides in Plan mode, no "
            "restriction elsewhere)"]
        data = vault.load()
        assert set(data["approved"]["rights"]["hosts"]) >= {"box"}, "the ratchet never removes"
        assert "gh" in data["approved"]["rights"]["accounts"]
        assert data["accounts"]["gh"]["bound"]["hosts"] == ["github.com", "api.github.com"]
        e = consent.compute(env.form(), data)
        assert e.hosts["box"].removed and e.hosts["box"].ssh is True
        assert e.hosts["box"].host.address.host == "box.example.com"
        assert e.accounts["gh"].removed and e.accounts["gh"].destinations == ["github.com", "api.github.com"]
        assert sorted(e.pending_names()) == ["box", "gh"]
        lines = consent.approve("box", e.pending_for("box"), form=env.form())
        assert lines == ["box: box will stop going through the gateway (its [hosts.box] is gone "
                         "from gateway.toml): from then on Claude uses your own ssh, agent and keys "
                         "for it"]
        assert "box" not in vault.load()["approved"]["rights"]["hosts"]
        assert "box" not in consent.load_listed()["hosts"], "the list follows the approval"
        e = consent.compute(env.form(), vault.load())
        assert "box" not in e.hosts and "box" not in e.configured
        assert e.word("box", "ssh", "auto") == "unconfigured"


def test_a_missing_or_unreadable_form_never_lets_a_configured_entry_through():
    good = parse(HOST + GH + LOCAL + 'sudo = "ask"\n')
    data = {"approved": {"rights": consent.snapshot(good)},
            "accounts": {"gh": {"kind": "github", "bound": {"hosts": ["github.com"]}}}}
    missing = parse("")
    missing.exists = False
    broken = F.parse_text("[hosts.box\n", Path("/x"))
    for label, f in (("missing", missing), ("broken", broken)):
        e = consent.compute(f, data)
        assert e.form_gone, label
        assert "box" not in e.hosts and "gh" not in e.accounts, label
        assert e.refused["box"] == consent.FORM_GONE and e.refused["gh"] == consent.FORM_GONE
        assert e.word("box", "ssh", "auto") == "deny" and e.word("gh", "use", "auto") == "deny"
        assert e.word("localhost", "sudo", "default") == "deny", (label, "configured, refused")
        assert not e.pending, label
        assert "box" in e.configured and "gh" in e.configured.accounts
    # with a last good copy the form is that copy, also for a missing file
    lg = F.parse_text("[hosts.box\n", Path("/x"), last_good=HOST + GH)
    e = consent.compute(lg, data)
    assert not e.form_gone and e.hosts["box"].ssh is True
    with H.gateway_env() as env:
        f = F.load(last_good=HOST + GH)
        assert not f.exists and f.from_last_good and "box" in f.hosts
        e = consent.compute(f, data)
        assert not e.form_gone and e.hosts["box"].ssh is True and not e.hosts["box"].removed
        assert not consent.sync_narrowing(data, f) and not consent.needs_sync(data, f)
        assert not F.load().from_last_good and list(F.load().hosts) == ["localhost"]
        del env


def test_nothing_is_approved_while_the_form_is_missing():
    with H.gateway_env() as env:
        env.write_form(HOST)
        vault.save(vault.empty())
        consent.approve_all(env.form())
        env.form_path.unlink()
        try:
            consent.approve("box", form=env.form())
        except consent.ConsentChanged as e:
            assert "missing or has a mistake" in str(e)
        else:
            raise AssertionError("an approval with no form would wipe the entry")
        assert "box" in vault.load()["approved"]["rights"]["hosts"]


def test_the_configured_set_is_the_form_the_approval_and_the_list():
    form = parse('[hosts.new]\naddress = "u@new.example.com"\n[hosts.off]\naddress = "-x"\n'
                 '[accounts.offacct]\nkind = "huggingface"\nlogin = 3\n'
                 '[hosts.off2]\naddress = "u@off2.example.com"\nssh = "maybe"\n'
                 '[hosts.chain]\naddress = "u@chain.example.com"\nvia = "nowhere"\n'
                 '[hosts.localhost.policy]\nelevation = "ask"\n')
    approved = parse(HOST + 'also = ["u@b2.example.com"]\n' + GH + 'owners = ["acme"]\n')
    listed = consent.configured_list(consent.snapshot(
        parse('[hosts.gone]\naddress = "gone.example.com"\n[accounts.reg]\nkind = "registry"\n'
              'host = "reg.example.com"\n')))
    data = {"approved": {"rights": consent.snapshot(approved)}}
    c = consent.compute(form, data, listed=listed).configured
    assert {"new", "off", "box", "gone"} <= set(c.hosts)
    assert c.disabled == {"off", "offacct", "off2", "chain"}
    # what a disabled host still spells keeps classifying
    assert c.host_named("off2.example.com") == "off2" and c.host_named("chain.example.com") == "chain"
    assert set(c.accounts) == {"offacct", "gh", "reg"}
    assert c.host_named("gw-box") == "box" and c.host_named("B2.example.com.") == "box"
    assert c.host_named("[gone.example.com]") == "gone" and c.host_named("other.example.com") is None
    assert c.accounts["gh"].owners == ["me", "acme"] and not c.accounts["gh"].default
    assert c.accounts["offacct"].default, "a disabled account counts for every owner"
    assert [a.name for a in c.accounts_for("github.com")] == ["gh"]
    assert c.local_elevation and not c.localhost_sudo
    assert c.sources["box"] == {"approved"} and c.sources["gone"] == {"list"}
    t = c.git_targets()
    assert t.hosts["box.example.com"] == "box" and {a.name for a in t.accounts} == {"offacct", "gh", "reg"}
    # entries only the list names are refused (the vault couldn't be read)
    e = consent.compute(form, None, listed=listed)
    assert e.refused["gone"] == consent.LISTED_ONLY and e.refused["reg"] == consent.LISTED_ONLY
    assert e.word("gone", "ssh", "auto") == "deny" and e.word("reg", "use", "auto") == "deny"
    assert e.refused["off"].startswith("[hosts.off] is off")


def test_the_configured_list_is_written_whole_on_approval_and_by_the_ratchet():
    with H.gateway_env() as env:
        env.write_form(HOST + LOCAL + 'sudo = "ask"\n')
        assert consent.load_listed() is None
        consent.ratchet(env.form())                       # a narrowing makes the vault
        lst = consent.load_listed()
        assert lst["localhost_sudo"] is True and lst["hosts"] == {}, "box isn't approved yet"
        consent.approve("box", form=env.form())
        lst = consent.load_listed()
        assert list(lst["hosts"]) == ["box"] and lst["version"] == 1
        import os
        import stat
        assert stat.S_IMODE(os.stat(paths.configured_path()).st_mode) == 0o600
        # a list that drifted from the approval is put back by the next ratchet
        paths.configured_path().write_text('{"version": 1, "hosts": {}, "accounts": {}}')
        consent.ratchet(env.form())
        assert list(consent.load_listed()["hosts"]) == ["box"]
        text = paths.configured_path().read_text()
        assert "secret" not in text.lower() and "token" not in text.lower()


def _without_any_owner(form_text: str) -> dict:
    """An approval of form_text as 0.10 recorded it: no login, owners or
    any_owner for its accounts."""
    snap = consent.snapshot(parse(form_text))
    for a in snap["accounts"].values():
        for k in ("login", "owners", "any_owner"):
            a.pop(k, None)
    return {"approved": {"rights": snap}}


def test_an_approval_without_any_owner_reads_as_the_form_does():
    """WS-9 review should-fix 1: an approval that doesn't record any_owner
    (0.10's records no owners at all) covers every owner as the only account
    of its kind, so listing the first owner still waits for the OK and the
    approval keeps covering the rest meanwhile; one that records owners
    (its own login too) lists them, as the form side reads `owners`."""
    data = _without_any_owner(GH)
    assert consent.approved_any_owner(data["approved"]["rights"]["accounts"]["gh"])
    e = consent.compute(parse(GH), data)
    assert not [c for c in e.pending if "owners listed" in c.what], e.pending
    assert e.configured.accounts["gh"].any_owner
    e = consent.compute(parse(GH + 'owners = ["acme"]\n'), data)
    assert [c.render() for c in e.pending if "owners listed" in c.what], \
        "listing the first owner of an older approval waits for the OK"
    assert e.configured.accounts["gh"].any_owner, "held until the OK"
    # owners = [its login]: both sides read it as listed, nothing to approve again
    snap = consent.snapshot(parse(GH + 'owners = ["me"]\n'))
    del snap["accounts"]["gh"]["any_owner"]
    assert not consent.approved_any_owner(snap["accounts"]["gh"])
    e = consent.compute(parse(GH + 'owners = ["me"]\n'), {"approved": {"rights": snap}})
    assert not [c for c in e.pending if "owners listed" in c.what], e.pending


def test_a_configured_list_without_any_owner_covers_every_owner():
    """WS-9 review should-fix 1: a configured list entry that doesn't say
    any_owner is read as covering every owner (the strict side while the
    vault can't be read: a configured account's owner is never handed to
    the user's own tools); one that says false lists its owners."""
    listed = consent.configured_list(consent.snapshot(parse(GH)))
    del listed["accounts"]["gh"]["any_owner"]
    assert consent.clean_listed(listed)["accounts"]["gh"]["any_owner"] is True
    e = consent.compute(parse(""), None, listed=listed)
    assert e.configured.accounts["gh"].any_owner
    listed["accounts"]["gh"]["any_owner"] = False
    assert consent.clean_listed(listed)["accounts"]["gh"]["any_owner"] is False


def test_owners_listed_waits_only_for_the_only_account_of_its_kind():
    """WS-9 review should-fix 2: beside another account of its kind for the
    same host an account covers no other owner anyway, so listing its first
    owner takes nothing out: no change line (and none that says "as the only
    github account"). Another host's account of the kind doesn't count."""
    other = '[accounts.mine]\nkind = "github"\nlogin = "octocat"\n'
    e = run(GH + other, GH + 'owners = ["acme"]\n' + other)
    assert not [c for c in e.pending if "owners listed" in c.what], e.pending
    ghe = '[accounts.ent]\nkind = "github"\nlogin = "octo"\nhost = "ghe.example.com"\n'
    e = run(GH + ghe, GH + 'owners = ["acme"]\n' + ghe)
    assert [c for c in e.pending if "owners listed (as the only github account" in c.what]


def test_owners_destinations_and_logins_held_for_classification():
    data = {"approved": {"rights": consent.snapshot(parse(GH + 'owners = ["acme"]\n' + KEY))}}
    e = consent.compute(parse(GH.replace('"me"', '"you"') + KEY.replace("api.x.com", "api.y.com")),
                        data)
    assert e.accounts["gh"].held_owners == ["me", "acme"]
    assert e.accounts["key"].held_destinations == ["api.x.com"]
    assert set(e.configured.accounts["gh"].owners) == {"you", "me", "acme"}
    assert set(e.configured.accounts["key"].destinations) == {"api.x.com", "api.y.com"}


def test_network_commands_and_names_compare_in_the_right_direction():
    N = "[network]\n"
    e = run("", N + 'commands = { default = "ask", auto = "cc" }\n')
    assert [c.render() for c in e.pending] == [
        "settings: network commands: in Auto mode Claude Code decides (was: asks you)"]
    assert e.network.word("auto") == "ask"
    e = run("", N + 'commands = "deny"\nextra = ["dig"]\n')
    assert not e.pending and {c.what for c in e.narrowed} == {
        "network commands: in every mode it is refused (was: asks you in every mode)",
        "network: dig joins the network commands"}
    assert e.network.word("default") == "deny" and "dig" in e.network.names()
    # a name leaving the class waits: approved extra stays, a drop applies only once approved
    e = run(N + 'extra = ["dig"]\n', N + 'drop = ["curl"]\n')
    assert {c.what.split(" (")[0] for c in e.pending} == {
        "network: dig leaves the network commands", "network: curl dropped from the network commands"}
    assert {"dig", "curl"} <= e.network.names()
    e = run(N + 'drop = ["curl"]\n', N + 'drop = ["curl"]\n')
    assert "curl" not in e.network.names() and "wget" in e.network.names()
    e = run(N + 'drop = ["curl"]\n', "")
    assert not e.pending and any("curl back among" in c.what for c in e.narrowed)
    assert "curl" in e.network.names()
    # a mistake keeps the approved [network] whole, and nothing ratchets
    data = {"approved": {"rights": consent.snapshot(parse(N + 'commands = "cc"\nextra = ["dig"]\n'))}}
    bad = parse(N + 'commands = "sometimes"\n')
    e = consent.compute(bad, data)
    assert e.network.word("default") == "cc" and e.network.extra == ["dig"] and not e.pending
    assert not consent.sync_narrowing(data, bad)
    # the ratchet records a fall and a name joining
    data = {"approved": {"rights": consent.snapshot(parse(""))}}
    consent.sync_narrowing(data, parse(N + 'commands = "deny"\nextra = ["dig"]\n'))
    assert data["approved"]["rights"]["settings"]["network"] == {
        "commands": False, "extra": ["dig"], "drop": []}


def test_a_written_warn_counts_as_on_and_changes_nothing():
    data = {"approved": {"rights": consent.snapshot(parse('[shell]\nmanaged = "off"\n'))}}
    bad = parse('[shell]\nmanaged = "warn"\n')
    e = consent.compute(bad, data)
    assert e.shell.managed == "on" and not e.pending and not e.narrowed
    assert not consent.sync_narrowing(data, bad)
    assert consent.approved_shell({"settings": {"shell": {"managed": "warn"}}})["managed"] == "on"
    e = run('[shell]\nmanaged = "off"\n', "")
    assert e.shell.managed == "on" and any('"off" -> "on"' in c.what for c in e.narrowed)


def test_the_docs_say_a_bad_managed_value_counts_as_on():
    """CONFIG.md and managed.md say what the test above checks: a bad
    `managed` value counts as "on" (never "keeps the approved mode")."""
    docs = [H.REPO / "docs" / "CONFIG.md", H.REPO / "docs" / "dev" / "modules" / "managed.md"]
    if not all(p.exists() for p in docs):      # a scratch copy of the plugin alone (mutations)
        print("    note: no repo docs next to this plugin folder; skipped")
        return
    for p in docs:
        text = " ".join(p.read_text().replace("`", "").replace('"', "").split())
        said = re.findall(r"A bad managed value[^.;]*", text)
        assert said and all("counts as on" in s for s in said), (p.name, said)


def test_sign_in_and_scope_changes_need_a_new_sign_in():
    azc = AZ + 'client_id = "11111111-2222-3333-4444-555555555555"\n'   # a browser sign-in needs one
    e = run(azc, azc + 'sign_in = "browser"\n')
    assert any("sign_in service-principal -> browser (needs a new sign-in)" in c.what
               for c in e.pending), [c.what for c in e.pending]
    assert e.accounts["az"].sign_in is None
    b = azc + 'sign_in = "browser"\n'
    e = run(b, b + 'scope = "https://management.azure.com/.default"\n')
    assert any("scope unset -> https://management.azure.com/.default (needs a new sign-in)" in c.what
               for c in e.pending)
    assert not run(AZ, AZ + 'sign_in = "service-principal"\n').pending, "the default spelled out"
    cat = '[accounts.cat]\nkind = "ml-catalog"\nhost = "c.example.com"\n'
    e = run(cat, cat + 'tenant = "t.example.com"\n')
    assert any("tenant unset -> t.example.com" in c.what for c in e.pending)


def test_readers_of_the_snapshot_take_a_per_mode_map():
    """The approved snapshot keeps a table as its six-mode map (§2.7); the
    FileChanged summary reads it without failing."""
    from gateway import hooks_filechanged
    old = consent.snapshot(parse(HOST))
    new = consent.snapshot(parse(HOST + 'sudo = { default = "ask", auto = true }\n'
                                 '[hosts.b2]\naddress = "u@b2.example.com"\nssh = { default = "cc" }\n'))
    assert isinstance(new["hosts"]["box"]["sudo"], dict) and new["hosts"]["box"]["ssh"] is True
    lines = hooks_filechanged.describe_changes(old, new)
    assert "box: sudo now per mode" in lines and "b2: new host (u@b2.example.com, ssh per mode, sudo on)" in lines, lines


def test_an_unreadable_approved_value_is_the_strictest_reading():
    snap = consent.snapshot(parse(HOST + GH + '[hosts.box.policy]\nwrite = "ask"\n'))
    snap["hosts"]["box"]["ssh"] = {"default": "allow"}            # not a six-mode map
    snap["hosts"]["box"]["sudo"] = "sometimes"
    snap["hosts"]["box"]["policy"]["write"] = ["ask"]
    snap["accounts"]["gh"]["use"] = 7
    e = consent.compute(parse(HOST + GH + '[hosts.box.policy]\nwrite = "ask"\n'),
                        {"approved": {"rights": snap}})
    assert [e.word("box", k, "auto") for k in ("ssh", "sudo")] == ["deny", "deny"]
    assert e.hosts["box"].policy == {"write": False} and e.word("gh", "use", "auto") == "deny"


def test_compute_resolves_the_legacy_attributes_for_its_mode():
    f = HOST + 'ssh = { default = "ask", auto = true }\n[hosts.box.policy]\nexec = { default = "allow", bypass = "ask" }\n'
    e = run(f, f)
    assert e.mode is None and e.hosts["box"].ssh == "ask" and e.hosts["box"].policy == {"exec": "ask"}
    e = run(f, f, "auto")
    assert e.mode == "auto" and e.hosts["box"].ssh is True and e.hosts["box"].policy == {"exec": True}
    e = run(f, f, "bypassPermissions")
    assert e.mode == "bypass" and e.hosts["box"].policy == {"exec": "ask"}


# ---------------------------------------------------------------------------
# WS-A1 review: the configured list while the approval can't be read,
# disabled accounts, kind changes, one name in both sections, texts
# ---------------------------------------------------------------------------


def test_the_configured_lists_sudo_here_is_refused_while_the_approval_cant_be_read():
    """PLAN-0.11 §1.1, §11.3: while the vault can't be read (or the form is
    gone), sudo on this computer that the configured list says goes through
    the gateway (or that an elevation restriction covers) is refused where
    the form doesn't say it, never the user's own sudo passing through; and
    compute reads the list itself."""
    listed = consent.configured_list(consent.snapshot(parse(LOCAL + "sudo = true\n" + HOST)))
    assert listed["localhost_sudo"] is True
    missing = parse("")
    missing.exists = False
    for label, f, why in (("key deleted", parse(HOST), consent.LISTED_SUDO),
                          ("form missing", missing, consent.FORM_GONE)):
        e = consent.compute(f, None, listed=listed)
        assert [e.word("localhost", "sudo", m) for m in modes.KEYS] == ["deny"] * 6, label
        assert e.hosts["localhost"].sudo is False and e.refused["localhost"] == why, label
        d = policy.decide(e, "elevation", mode="auto")
        assert d.value == "deny" and d.rule == why, (label, d.rule)
        assert policy.decide(e, "network", mode="auto").value == "cc", "only sudo here is refused"
    # the form's own sudo applies, capped at "ask" (no approval can be read)
    e = consent.compute(parse(LOCAL + "sudo = true\n"), None, listed=listed)
    assert e.word("localhost", "sudo", "auto") == "ask" and "localhost" not in e.refused
    # an elevation restriction the list records and the form dropped
    rl = consent.configured_list(consent.snapshot(parse('[policy]\nelevation = "deny"\n')))
    assert rl["local_elevation"] and not rl["localhost_sudo"]
    e = consent.compute(parse(""), None, listed=rl)
    assert policy.decide(e, "elevation", mode="auto").value == "deny"
    assert e.refused["localhost"] == consent.LISTED_SUDO
    e = consent.compute(parse('[policy]\nelevation = "ask"\n'), None, listed=rl)
    assert policy.decide(e, "elevation", mode="auto").value == "ask" and "localhost" not in e.refused
    # compute reads the list on disk when no approval could be read, and only then
    with H.gateway_env() as env:
        env.write_form(LOCAL + "sudo = true\n" + HOST)
        vault.save(vault.empty())
        consent.approve_all(env.form())
        env.write_form(HOST)
        e = consent.compute(env.form(), None)
        assert e.unreadable and e.word("localhost", "sudo", "auto") == "deny"
        env.form_path.unlink()
        e = consent.compute(env.form(), None)
        assert e.form_gone and "box" in e.configured and e.refused["box"] == consent.FORM_GONE
        assert e.refused["localhost"] == consent.FORM_GONE
        env.write_form(HOST)
        e = consent.compute(env.form(), vault.load())
        assert not e.unreadable and "localhost" not in e.refused


def test_a_disabled_account_classifies_its_own_destinations():
    """PLAN-0.11 §1.1: a malformed account stays configured and is refused
    by its own destinations, as far as they still parse (never its kind's
    defaults in their place); gitroute's reach of the form says the same."""
    from gateway import gitroute
    for text, name, want in (
            ('[accounts.reg]\nkind = "registry"\nhost = "reg.example.com"\nlogin = 3\n', "reg",
             ["reg.example.com"]),
            ('[accounts.ghe]\nkind = "github"\nhost = "ghe.example.com"\nlogin = 3\n', "ghe",
             ["ghe.example.com"]),
            ('[accounts.k]\nkind = "api-key"\nsites = ["api.x.com", 7, ".com"]\n', "k", ["api.x.com"]),
            ('[accounts.cat]\nkind = "ml-catalog"\nhost = "cat.example.com"\nlogin = 3\n', "cat",
             ["cat.example.com"]),
            ('[accounts.gh]\nkind = "github"\nhost = 5\n', "gh",
             ["github.com", "api.github.com", "ghcr.io"])):
        f = parse(text)
        assert f.is_disabled(name, "accounts") and name not in f.accounts, text
        c = consent.compute(f, {}).configured
        assert c.accounts[name].destinations == want, (text, c.accounts[name].destinations)
        for d in want:
            assert [a.name for a in c.accounts_for(d)] == [name], (text, d)
        t = gitroute.Targets.from_forms(f)
        assert [a.dests for a in t.accounts if a.name == name] == [tuple(want)], text
    c = consent.compute(parse('[accounts.ghe]\nkind = "github"\nhost = "ghe.example.com"\nowners = 3\n'),
                        {}).configured
    assert c.accounts_for("github.com") == [], "github.com isn't the malformed GHE account's"
    az = parse('[accounts.az]\nkind = "azure"\nsites = ["s.example.com"]\nstorage = ["acct", "BAD!"]\n')
    d = consent.compute(az, {}).configured.accounts["az"].destinations
    assert {"s.example.com", "acct.blob.core.windows.net"} <= set(d) and not any("bad" in x for x in d)


def test_a_kind_change_keeps_a_reach_per_kind():
    e = run('[accounts.w]\nkind = "github"\nlogin = "me"\n', '[accounts.w]\nkind = "huggingface"\nlogin = "me"\n')
    c = e.configured
    assert c.accounts["w"].kind == "huggingface" and "github.com" not in c.accounts["w"].destinations
    assert [a.kind for a in c.other_kinds] == ["github"] and "github.com" in c.other_kinds[0].destinations
    assert "huggingface.co" not in c.other_kinds[0].destinations
    assert [a.kind for a in c.accounts_for("github.com")] == ["github"]
    assert [a.kind for a in c.accounts_for("huggingface.co")] == ["huggingface"]
    t = c.git_targets()
    assert sorted((a.name, a.kind) for a in t.accounts) == [("w", "github"), ("w", "huggingface")]
    assert not any("github.com" in a.dests and "huggingface.co" in a.dests for a in t.accounts)


def test_approving_a_name_both_sections_used_takes_the_removed_one_out():
    """One namespace: an approved [hosts.x] replaced by [accounts.x]. The
    dialog for x shows the host's removal and the new account; its OK takes
    both (the host's approval leaves and its masters close)."""
    from gateway import ssh
    with H.gateway_env() as env:
        env.write_form('[hosts.x]\naddress = "x.example.com"\n')
        vault.save(vault.empty())
        consent.approve_all(env.form())
        env.write_form('[accounts.x]\nkind = "huggingface"\n')
        f = env.form()
        shown = consent.compute(f, vault.load()).pending_for("x")
        assert {c.what.split(" (")[0] for c in shown} == {
            "x will stop going through the gateway", "new huggingface account"}, shown
        calls: list[str] = []
        orig = ssh.close_masters
        ssh.close_masters = lambda n: calls.append(n) or 1
        try:
            consent.approve("x", shown, form=f)
        finally:
            ssh.close_masters = orig
        ap = vault.load()["approved"]["rights"]
        assert "x" not in ap["hosts"] and ap["accounts"]["x"]["kind"] == "huggingface"
        assert calls == ["x"] and "x" not in consent.load_listed()["hosts"]
        e = consent.compute(f, vault.load())
        assert not e.pending and "x" not in e.hosts


def test_approving_a_removal_closes_its_masters_and_unbinds_its_credential():
    from gateway import ssh
    with H.gateway_env() as env:
        env.write_form(HOST + GH)
        vault.save(vault.empty())
        consent.approve_all(env.form())
        assert vault.load()["accounts"]["gh"]["bound"]["hosts"] == ["github.com", "api.github.com"]
        env.write_form("")
        f = env.form()
        calls: list[str] = []
        orig = ssh.close_masters
        ssh.close_masters = lambda n: calls.append(n) or 1
        try:
            consent.approve("box", form=f)
            assert calls == ["box"], calls
            consent.approve("gh", form=f)
            assert calls == ["box"], "an account has no ssh master"
        finally:
            ssh.close_masters = orig
        data = vault.load()
        assert data["accounts"]["gh"]["bound"]["hosts"] == [], "its credential goes nowhere any more"
        assert not consent.bound_ok(data, "gh", "github.com")


def test_a_locked_or_unreadable_vault_says_so_instead_of_waits_for_the_ok():
    f = parse(HOST + GH)
    e = consent.compute(f, None, listed=None, locked=True)
    assert e.unreadable and e.locked
    assert e.refusal("box") == consent.LOCKED_ENTRY.format(name="box")
    assert "/gate-unlock" in e.refusal("gh")
    assert policy.decide(e, "exec", host="box", mode="auto").rule == e.refusal("box")
    assert policy.decide(e, "credential", account="gh", mode="auto").rule == e.refusal("gh")
    e = consent.compute(f, None, listed=consent.configured_list(consent.baseline()))
    assert e.unreadable and not e.locked
    assert e.refusal("box") == consent.UNREADABLE_ENTRY.format(name="box")


def test_a_malformed_configured_list_never_crashes_and_fails_closed():
    for bad in ({"version": 1, "hosts": 5}, {"version": 1, "hosts": ["a"]},
                {"version": 1, "accounts": "xyz"}, [1], "x", {"version": 2}):
        e = consent.compute(parse(""), None, listed=bad)
        assert e.refused.get("localhost") == consent.LISTED_SUDO, bad
        assert e.word("localhost", "sudo", "auto") == "deny", bad
    c = consent.clean_listed({"version": 1,
                              "hosts": {"box": {"addresses": [{"host": "box.example.com"}, 3]},
                                        "Bad Name": {}},
                              "accounts": {"k": {"kind": "api-key", "destinations": ["api.x.com", 4]},
                                           "j": {"kind": "nope"}}})
    assert list(c["hosts"]) == ["box"] and list(c["accounts"]) == ["k"] and not c.get("broken")
    assert c["accounts"]["k"]["destinations"] == ["api.x.com"] and c["localhost_sudo"] is False
    with H.gateway_env() as env:
        assert consent.load_listed() is None
        paths.ensure_private()
        paths.configured_path().write_text("{not json")
        assert consent.load_listed()["broken"]
        assert consent.compute(parse(""), None).word("localhost", "sudo", "auto") == "deny"
        # a readable vault puts it right at the next ratchet
        env.write_form(HOST)
        vault.save(vault.empty())
        consent.ratchet(env.form())
        assert not consent.load_listed().get("broken")


def test_the_ratchet_never_writes_an_older_list_over_a_newer_approval():
    with H.gateway_env() as env:
        env.write_form(HOST)
        vault.save(vault.empty())
        consent.ratchet(env.form())
        stale = vault.load()
        consent.approve("box", form=env.form())
        assert "box" in consent.load_listed()["hosts"]
        stale["form_last_good"] = env.form().used_text
        real, calls = vault.load, []

        def load() -> dict:
            calls.append(1)
            return copy.deepcopy(stale) if len(calls) == 1 else real()
        vault.load = load
        try:
            assert consent.ratchet(env.form()) == []
        finally:
            vault.load = real
        assert len(calls) == 2 and "box" in consent.load_listed()["hosts"], calls


def test_a_list_left_without_a_vault_is_removed():
    with H.gateway_env() as env:
        env.write_form(HOST)
        vault.save(vault.empty())
        consent.approve_all(env.form())
        assert consent.load_listed() is not None
        paths.vault_path().unlink()                  # the vault deleted by hand
        consent.ratchet(env.form())
        assert consent.load_listed() is None
        assert not consent.compute(env.form(), None).unreadable


def test_network_commands_default_to_ask_in_every_mode():
    """Lead decision 19.1: defaults stay conservative; with nothing written
    or approved no network command is approved, nor the http and download
    tools."""
    for e in (run("", ""), consent.compute(parse(""), {})):
        assert [e.network.word(m) for m in modes.KEYS] == ["ask"] * 6
        assert e.network.word() == "ask"
        assert not any(policy.decide(e, "network", mode=m).explicit_allow for m in modes.KEYS)


def test_a_change_line_says_what_each_mode_now_does_for_bare_words_too():
    """Lead decision 4: a change line names the modes that move and what each
    now does, in plain words, bare words included; a bare [network] commands
    = "allow" is named as an approval (decision 1)."""
    e = run("", '[network]\ncommands = "allow"\n')
    assert [c.render() for c in e.pending] == [
        "settings: network commands: in Plan mode Claude Code decides; elsewhere the gateway now "
        "approves without asking you (was: asks you in every mode)"]
    ap = ("ssh to box: in Auto and Bypass permissions modes the gateway now approves without asking "
          "you; elsewhere Claude Code decides (was: asks you in every mode)")
    e = run(HOST + 'ssh = "ask"\n', HOST + 'ssh = "allow"\n')
    assert [c.what for c in e.pending] == [ap]
    e = run(HOST + 'ssh = "ask"\n', HOST + "ssh = true\n")
    assert [c.what for c in e.pending] == [ap]
    e = run('[network]\ncommands = "allow"\n', "")
    assert [c.what for c in e.narrowed] == [
        "network commands: in every mode you are asked (was: Claude Code decides in Plan mode, "
        "the gateway approves elsewhere)"]
    # a policy key's bare words too
    e = run('[policy]\nnetwork = "deny"\n', '[policy]\nnetwork = "ask"\n')
    assert [c.what for c in e.pending] == [
        "policy network: in every mode you are asked (was: refused in every mode)"]
    # an account's use has no allow shape: never promised as an approval
    e = run(GH + "use = false\n", GH)
    assert [c.what for c in e.pending] == ["use: in every mode Claude Code decides (was: refused in "
                                           "every mode)"]
