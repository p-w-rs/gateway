"""Consent: every widening and narrowing case of SPEC 5, effective rights,
approve(), the narrowing ratchet and bindings."""
from __future__ import annotations

from pathlib import Path

import harness as H
from gateway import consent, migrate, vault
from gateway import form as F


def parse(t: str) -> F.Form:
    return F.parse_text(t, Path("/x"))


HOST = '[hosts.box]\naddress = "u@box.example.com"\n'
GH = '[accounts.gh]\nkind = "github"\nlogin = "me"\npackages = false\n'
KEY = '[accounts.key]\nkind = "api-key"\nsites = ["api.x.com"]\n'
AZ = '[accounts.az]\nkind = "azure"\ntenant = "t.example.com"\n'


def run(old: str, new: str) -> consent.Effective:
    data = {"approved": {"rights": consent.snapshot(parse(old))}}
    return consent.compute(parse(new), data)


# (id, old form, new form, [widen substrings], [narrow substrings], extra check)
TABLE = [
    # --- widening ---
    ("new_host", "", HOST, ["box: new host"], [],
     lambda e: e.hosts["box"].new and e.hosts["box"].ssh is False and e.hosts["box"].sudo is False),
    ("sudo_false_to_ask", HOST + "sudo = false\n", HOST + 'sudo = "ask"\n', ['sudo false -> "ask"'], [],
     lambda e: e.hosts["box"].sudo is False),
    ("sudo_ask_to_true", HOST + 'sudo = "ask"\n', HOST + "sudo = true\n", ['sudo "ask" -> true'], [],
     lambda e: e.hosts["box"].sudo == "ask"),
    ("sudo_false_to_true", HOST + "sudo = false\n", HOST, ["sudo false -> true"], [],
     lambda e: e.hosts["box"].sudo is False),
    ("ssh_false_to_true", HOST + "ssh = false\n", HOST, ["ssh false -> true"], [],
     lambda e: e.hosts["box"].ssh is False),
    ("localhost_sudo_raised", '[hosts.localhost]\nsudo = false\n', '[hosts.localhost]\nsudo = true\n',
     ["localhost: sudo false -> true"], [], lambda e: e.hosts["localhost"].sudo is False),
    ("host_scripts_on", HOST, HOST + "scripts = true\n", ["scripts false -> true"], [],
     lambda e: e.hosts["box"].scripts is False),
    ("address_changed", HOST, '[hosts.box]\naddress = "u@evil.example.com"\n',
     ["new address u@evil.example.com"], ["address u@box.example.com removed"],
     lambda e: e.hosts["box"].addresses == [] and e.hosts["box"].ssh is False),
    ("address_user_changed", HOST, '[hosts.box]\naddress = "root@box.example.com"\n',
     ["new address root@box.example.com"], ["address u@box.example.com removed"],
     lambda e: e.hosts["box"].ssh is False),
    ("also_added", HOST, HOST + 'also = ["u@box2.example.com:2222"]\n',
     ["new address u@box2.example.com:2222"], [],
     lambda e: [a.render() for a in e.hosts["box"].addresses] == ["u@box.example.com"] and e.hosts["box"].ssh is True),
    ("when_removed", HOST + 'when = "10.0.0.0/24"\n', HOST, ["on any network"], [],
     lambda e: e.hosts["box"].addresses == []),
    ("when_changed", HOST + 'when = "10.0.0.0/24"\n', HOST + 'when = "10.9.0.0/16"\n', ["10.9.0.0/16"], [], None),
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
     ["may now send to .x.com"], ["no longer sends to api.x.com"], lambda e: e.accounts["key"].destinations == []),
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
     ["may now send to ghe.evil.example.com"], ["no longer sends to github.com"],
     lambda e: e.accounts["gh"].destinations == []),
    ("packages_on", GH, GH.replace("packages = false", "packages = true"), ["may now send to ghcr.io"], [], None),
    ("env_added", KEY, KEY + 'env = "X_KEY"\n', ["env X_KEY"], [], lambda e: e.accounts["key"].env is None),
    ("env_changed", KEY + 'env = "X_KEY"\n', KEY + 'env = "Y_KEY"\n', ["env Y_KEY", "was X_KEY"], [],
     lambda e: e.accounts["key"].env is None),
    ("account_scripts_on", GH, GH + "scripts = true\n", ["scripts false -> true"], [],
     lambda e: not e.accounts["gh"].scripts),
    ("use_back_on", GH + "use = false\n", GH, ["use false -> true"], [], lambda e: not e.accounts["gh"].use),
    ("others_mine", "", '[settings]\nothers = "mine"\n', ['others = "mine"'], [], lambda e: e.others == "refuse"),
    ("kind_changed", GH, '[accounts.gh]\nkind = "huggingface"\n', ["kind changed to huggingface"], [],
     lambda e: e.accounts["gh"].new),
    # --- narrowing ---
    ("sudo_true_to_ask", HOST, HOST + 'sudo = "ask"\n', [], ['sudo true -> "ask"'], lambda e: e.hosts["box"].sudo == "ask"),
    ("sudo_ask_to_false", HOST + 'sudo = "ask"\n', HOST + "sudo = false\n", [], ['sudo "ask" -> false'], None),
    ("ssh_true_to_false", HOST, HOST + "ssh = false\n", [], ["ssh true -> false"], lambda e: e.hosts["box"].ssh is False),
    ("host_removed", HOST, "", [], ["box: host removed"], lambda e: "box" not in e.hosts),
    ("also_removed", HOST + 'also = ["u@b2.example.com"]\n', HOST, [], ["address u@b2.example.com removed"], None),
    ("when_added", HOST, HOST + 'when = "10.0.0.0/24"\n', [], ["only on 10.0.0.0/24 now"],
     lambda e: e.hosts["box"].addresses[0].when == "10.0.0.0/24"),
    ("via_removed", HOST + 'via = "j"\n[hosts.j]\naddress = "j.example.com"\n',
     HOST + '[hosts.j]\naddress = "j.example.com"\n', [], ["via j removed"], lambda e: e.hosts["box"].via is None),
    ("site_removed", KEY.replace('["api.x.com"]', '["api.x.com", "b.x.com"]'), KEY, [], ["no longer sends to b.x.com"], None),
    ("use_off", GH, GH + "use = false\n", [], ["use true -> false"], lambda e: not e.accounts["gh"].use),
    ("env_removed", KEY + 'env = "X_KEY"\n', KEY, [], ["env X_KEY removed"], lambda e: e.accounts["key"].env is None),
    ("scripts_off", HOST + "scripts = true\n", HOST, [], ["scripts true -> false"], None),
    ("others_back_to_refuse", '[settings]\nothers = "mine"\n', "", [], ['others = "refuse"'], lambda e: e.others == "refuse"),
    ("account_removed", GH, "", [], ["gh: account removed"], None),
    # --- neither ---
    ("owners_added_not_widening", GH, GH + 'owners = ["acme"]\n', [], [], lambda e: e.accounts["gh"].owners == ["acme"]),
    ("note_and_login_changes", HOST + GH, HOST + 'note = "x"\n' + GH.replace('"me"', '"you"'), [], [], None),
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
    t = HOST + GH + KEY + '[settings]\nothers = "mine"\n'
    e = run(t, t)
    assert not e.pending and not e.narrowed
    assert e.hosts["box"].ssh is True and e.accounts["gh"].destinations == ["github.com", "api.github.com"]
    assert e.others == "mine"


def test_baseline_without_approvals():
    e = consent.compute(parse(""), None)
    assert not e.pending and e.hosts["localhost"].sudo == "ask", \
        "with nothing approved, sudo on this computer asks each time"
    assert consent.baseline()["hosts"]["localhost"]["sudo"] == "ask"
    e = consent.compute(parse(migrate.STARTER), None)
    assert not e.pending and e.hosts["localhost"].sudo == "ask", \
        "a new install's starter form needs no OK and asks for sudo each time"
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
        off = parse(HOST + 'sudo = false\n' + GH.replace("packages = false", "packages = false\nhost = \"github.com\""))
        ch = consent.sync_narrowing(data, parse(HOST + "sudo = false\n"))
        assert any("sudo true -> false" in c.render() for c in ch)
        assert any("gh: account removed" in c.render() for c in ch)
        assert data["accounts"]["gh"]["bound"]["hosts"] == []
        e = consent.compute(on, data)
        assert any("sudo false -> true" in c.render() for c in e.pending), "raising again needs the OK"
        assert "gh" in e.pending_names(), "a removed account comes back only with an OK"
        del off


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
                HOST + '[hosts.c]\naddress = "c.example.com"\nsudo = false\n')
        closed = consent.close_masters_for(e.narrowed, parse(HOST))
        assert calls == ["box"] and closed == ["box"], (calls, [c.render() for c in e.narrowed])
    finally:
        ssh.close_masters = orig
    # the real ssh.close_masters, in a test env: it finds no master and the
    # host still counts as handled (it never raises)
    with H.gateway_env():
        assert consent.close_masters_for(e.narrowed) == ["box"]


def test_invalid_others_keeps_the_approval():
    mine = parse('[settings]\nothers = "mine"\n')
    data = {"approved": {"rights": consent.snapshot(mine)}}
    bad = parse('[settings]\nothers = "everything"\n')
    e = consent.compute(bad, data)
    assert e.others == "refuse" and not e.narrowed and not e.pending
    consent.sync_narrowing(data, bad)
    assert data["approved"]["rights"]["settings"]["others"] == "mine", "no ratchet on a typo"
    e = consent.compute(mine, data)
    assert e.others == "mine" and not e.pending, "fixing the typo needs no pop-up"


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
    assert any("box: sudo true -> false" in c.render() for c in ch)
    assert data["approved"]["rights"]["hosts"]["box"]["sudo"] is False
    assert data["accounts"]["gh"]["bound"]["hosts"] == ["github.com", "api.github.com"]


def test_imported_entries_count_as_approved_once_copied_in():
    v2form = parse(HOST + GH)
    data = {"approved": {}, "imported": {"from": "v2", "rights": consent.snapshot(v2form)},
            "accounts": {"gh": {"kind": "github", "bound": {"hosts": ["github.com", "api.github.com"]}}}}
    mine = parse('[hosts.localhost]\nsudo = false\n')
    e = consent.compute(mine, data)
    assert not any(c.entry in ("box", "gh") for c in e.narrowed), "not in the form yet: not removed"
    consent.sync_narrowing(data, mine)
    assert data["accounts"]["gh"]["bound"]["hosts"] == ["github.com", "api.github.com"], "bindings kept"
    copied = parse('[hosts.localhost]\nsudo = false\n' + HOST + 'sudo = "ask"\n' + GH)
    e = consent.compute(copied, data)
    assert not e.pending, [c.render() for c in e.pending]
    assert e.hosts["box"].ssh is True and e.hosts["box"].sudo == "ask"
    assert e.accounts["gh"].destinations == ["github.com", "api.github.com"]
    assert consent.needs_sync(data, copied), "copied-in entries are promoted by the ratchet"
    consent.sync_narrowing(data, copied)
    ap = data["approved"]["rights"]
    assert ap["hosts"]["box"]["sudo"] == "ask" and "gh" in ap["accounts"], "moved into approved"
    assert "box" not in data["imported"]["rights"]["hosts"]
    # more than the imported rights is still a widening
    wider = parse(HOST + 'scripts = true\n')
    data2 = {"approved": {}, "imported": {"rights": consent.snapshot(v2form)}}
    assert "box" in consent.compute(wider, data2).pending_names()


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
    good = parse(HOST + GH)
    data = {"approved": {"rights": consent.snapshot(good)},
            "accounts": {"gh": {"kind": "github", "bound": {"hosts": ["github.com"]}}}}
    missing = parse("")
    missing.exists = False
    assert consent.sync_narrowing(data, missing) == []
    assert "box" in data["approved"]["rights"]["hosts"] and data["accounts"]["gh"]["bound"]["hosts"]
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
