"""Vault v3: round trip, lock, cache, events, machine identity, keys (SPEC 3)."""
from __future__ import annotations

import json
import os
import stat
import threading
import time

import harness as H
from gateway import paths, testing, vault


def test_round_trip_and_modes():
    with H.gateway_env():
        assert not vault.exists()
        assert vault.load() == vault.empty()
        d = vault.empty()
        vault.set_sudo(d, "localhost", "me", "pw-local-123")
        vault.set_sudo(d, "box", "octo", "pw-box-456")
        d["aliases"]["github:work"] = "github-work"
        vault.save(d)
        assert vault.exists()
        back = vault.load()
        assert back["localhost"]["sudo"]["me"]["password"] == "pw-local-123"
        assert back["hosts"]["box"]["sudo"]["octo"]["password"] == "pw-box-456"
        assert vault.resolve(back, "github:work") == "github-work"
        assert vault.resolve({"aliases": {"hf": "hf-2"}}, "hf", entries={"hf", "hf-2"}) == "hf"
        assert stat.S_IMODE(paths.private_dir().stat().st_mode) == 0o700
        assert stat.S_IMODE(paths.key_path().stat().st_mode) == 0o600
        assert stat.S_IMODE(paths.vault_path().stat().st_mode) == 0o600
        raw = paths.vault_path().read_bytes()
        assert b"pw-local-123" not in raw and raw.startswith(b"age-encryption.org")


def test_edit_saves_only_on_change_and_lock_serializes():
    with H.gateway_env():
        vault.save(vault.empty())
        m1 = paths.vault_path().stat().st_mtime_ns
        time.sleep(0.01)
        with vault.edit() as d:
            pass
        assert paths.vault_path().stat().st_mtime_ns == m1
        errors: list[BaseException] = []
        o = testing.active()

        def bump(i: int) -> None:
            try:
                with testing.override(o.root, machine_id=o.machine_id):
                    with vault.edit() as d:
                        d.setdefault("counter", 0)
                        d["counter"] += 1
            except BaseException as e:  # noqa: BLE001
                errors.append(e)
        ts = [threading.Thread(target=bump, args=(i,)) for i in range(5)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        assert not errors, errors
        assert vault.load()["counter"] == 5


def test_save_refuses_a_new_vault_beside_a_gateway_06_vault():
    """The kept 0.6 detector: while store.age is here and vault.age isn't,
    no vault is created (gateway 0.10.0 converts it first), whatever the
    caller; once a vault exists, a leftover store.age changes nothing."""
    with H.gateway_env():
        paths.ensure_home()
        paths.v2_store_path().write_bytes(b"v2 ciphertext")
        assert vault.v06_waiting()
        try:
            vault.save(vault.empty())
        except vault.VaultError as e:
            assert str(e) == vault.V06_MESSAGE == (
                "gateway: a gateway 0.6 vault is here; convert it with gateway 0.10.0 first "
                "(see CHANGELOG 0.11.0)"), str(e)
        else:
            raise AssertionError("must not create vault.age while store.age waits")
        assert not vault.exists()
        # no way around it: no flag on save, gated's write or its client (the
        # daemon's write route took a "migrating" field from any client)
        import inspect
        from gateway.daemon import broker, client
        assert list(inspect.signature(vault.save).parameters) == ["data"]
        assert list(inspect.signature(broker.Broker.write).parameters) == ["self", "data"]
        assert list(inspect.signature(client.vault_write).parameters) == ["data"]
        try:
            broker.Broker().write(vault.empty())
        except vault.VaultError as e:
            assert str(e) == vault.V06_MESSAGE
        else:
            raise AssertionError("gated's write created vault.age while store.age waits")
        assert not vault.exists()
        paths.v2_store_path().unlink()
        assert not vault.v06_waiting()
        vault.save(vault.empty())
        paths.v2_store_path().write_bytes(b"left over")
        assert not vault.v06_waiting()
        vault.save(vault.load())  # an existing vault may be saved


def test_cache_expiry_and_clear():
    with H.gateway_env():
        vault.ensure_key()
        with vault.locked():
            vault.cache_put("azure", "arm", "tok-arm-valid-123456", time.time() + 3600)
            vault.cache_put("azure", "graph", "tok-graph-soon-12345", time.time() + 60)
        assert vault.cache_get("azure", "arm") == "tok-arm-valid-123456"
        assert vault.cache_get("azure", "graph") is None, "within 2 minutes of expiry"
        assert vault.cache_get("azure", "graph", margin=0) == "tok-graph-soon-12345"
        assert b"tok-arm" not in paths.cache_path().read_bytes()
        vault.cache_clear("azure")
        assert vault.cache_get("azure", "arm") is None
        paths.cache_path().write_bytes(b"garbage")
        assert vault.cache_load() == {"tokens": {}}


def test_events_last_100_and_new_since_seen():
    d = vault.empty()
    for i in range(130):
        vault.add_event(d, "widen", f"e{i}")
    assert len(d["events"]) == 100 and d["events"][0]["detail"] == "e30"
    assert len(vault.new_events(d)) == 100
    vault.mark_events_seen(d)
    assert vault.new_events(d) == []
    vault.add_event(d, "reject", "x")
    assert [e["detail"] for e in vault.new_events(d)] == ["x"]


def test_machine_identity():
    with H.gateway_env(machine_id="ABC-123"):
        d = vault.empty()
        assert vault.ensure_machine(d)
        assert d["machine"]["id"] == "ABC-123" and d["machine"]["name"]
        assert not vault.ensure_machine(d)
    with H.gateway_env(machine_id=None) as env:
        env.o.machine_id = None
        real = vault.machine_id()
        d = vault.empty()
        vault.ensure_machine(d)
        if real is None:
            assert d["machine"]["id"].startswith("random:")
            first = d["machine"]["id"]
            vault.ensure_machine(d)
            assert d["machine"]["id"] == first, "the random id is kept"
        else:
            assert d["machine"]["id"] == real


def test_meta_has_no_values_and_all_values_has_them():
    priv, pub = H.ssh_keypair("t")
    d = vault.empty()
    vault.set_sudo(d, "localhost", "me", "local-pw-123")
    h = vault.host_record(d, "box")
    h["keys"].append(vault.key_record(priv, pub))
    h["host_keys"] = [H.fake_host_key("hk")]
    a = vault.account_record(d, "gh", "github")
    a["token"] = {"value": "ghp_secret_value_123456", "source": "pasted", "updated": "", "stale": False}
    a["entra"] = {"refresh_token": "rt-secret-987654"}
    meta = json.dumps(vault.meta(d))
    for secret in ("local-pw-123", "ghp_secret_value_123456", "rt-secret-987654", "OPENSSH PRIVATE"):
        assert secret not in meta
    vals = vault.all_values(d)
    assert "local-pw-123" in vals and "ghp_secret_value_123456" in vals and "rt-secret-987654" in vals
    assert any("OPENSSH PRIVATE KEY" in v for v in vals)
    assert vault.meta(d)["hosts"]["box"]["keys"] == [vault.fingerprint_of(pub)]


def test_mark_stale():
    d = vault.empty()
    vault.set_sudo(d, "box", "j", "pw-123456789")
    assert vault.mark_stale(d, "box", "sudo", "j") and d["hosts"]["box"]["sudo"]["j"]["stale"]
    a = vault.account_record(d, "gh", "github")
    a["token"] = {"value": "x" * 20}
    assert vault.mark_stale(d, "gh", "token") and a["token"]["stale"]
    assert not vault.mark_stale(d, "nope", "token")


def test_key_helpers():
    priv, pub = H.ssh_keypair("helper")
    assert vault.public_key_of(priv) == " ".join(pub.split()[:2])
    assert vault.fingerprint_of(pub).startswith("SHA256:")
    assert vault.normalize_key(priv.replace("\n", "\r\n") + "  ") == vault.normalize_key(priv)
    for bad in ("nope", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----"):
        try:
            vault.public_key_of(bad)
        except ValueError:
            continue
        raise AssertionError("bad key accepted")
    with H.gateway_env():
        p2, pub2 = vault.generate_ssh_key("gen")
        assert vault.public_key_of(p2) == " ".join(pub2.split()[:2])
        assert not list(paths.private_dir().glob(".keygen-*"))


def test_builtin_host_keys_match_published_fingerprints():
    fps = {vault.fingerprint_of(k) for k in vault.GITHUB_HOST_KEYS}
    assert fps == {"SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
                   "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",
                   "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s"}
    assert vault.fingerprint_of(vault.HF_HOST_KEYS[0]) == "SHA256:dVjzGIdV7d6cwKIeZiCoRMa2gMvSKfGZAvHf4gMiMao"
    assert vault.fingerprint_of(vault.NEST_HOST_KEYS[0]) == "SHA256:iJjr1ZMOZNRGcEtLSDXFUUH0C4+5t7X9Wmhu4T4vcQI"
    assert vault.keyscan("github.com") == vault.GITHUB_HOST_KEYS
    assert vault.keyscan("ssh.github.com", 443) == vault.GITHUB_HOST_KEYS


def test_keyscan_override_and_host_key_helpers():
    k = H.fake_host_key("x")
    with H.gateway_env(keyscan={"box.example.com:2222": [k]}):
        assert vault.keyscan("box.example.com", 2222) == [k]
        assert vault.keyscan("other.example.com") == []
    assert vault.norm_host_key("10.0.0.5 " + k + " comment") == k
    assert vault.host_key_fingerprints(["10.0.0.5 " + k])[0].startswith("ssh-ed25519 SHA256:")


def test_load_rejects_wrong_version_and_missing_key():
    with H.gateway_env():
        vault.save(vault.empty())
        os.rename(paths.key_path(), paths.key_path().with_name("k.bak"))
        try:
            vault.load()
        except vault.VaultError as e:
            assert "key" in str(e)
        else:
            raise AssertionError("missing key must fail")


def test_vaults_carry_no_install_marks_and_export_only_their_secrets():
    """A new vault has no install mark and no 0.6 conversion record; a vault
    an older gateway wrote with them (`baseline`, `migrated`, `imported`)
    loads, edits and saves as any other (the fields are left alone, never
    read), and export_view carries only what an export needs, so the
    import's strict check never meets them."""
    old = {"version": 3, "machine": {"id": "m"}, "localhost": {"sudo": {}}, "hosts": {},
           "accounts": {}, "approved": {}, "form_last_good": None, "aliases": {"a": "b"},
           "events": [], "events_seen": 0, "migrated": {"from": "v2", "at": "2026-10-01"},
           "baseline": 2, "imported": {"rights": {}}, "sudo_choice": {}}
    assert set(vault.empty()) == {"version", "machine", "localhost", "hosts", "accounts",
                                  "approved", "form_last_good", "aliases", "events",
                                  "events_seen"}
    for name in ("BASELINE", "BASELINE_KEY", "older_install"):
        assert not hasattr(vault, name), name
    with H.gateway_env():
        vault.save(json.loads(json.dumps(old)))
        with vault.edit() as d:
            d["aliases"]["c"] = "d"
        d = vault.load()
        assert d["aliases"] == {"a": "b", "c": "d"}
        assert set(vault.export_view(d)) == set(vault.EXPORT_KEYS) == {
            "version", "localhost", "hosts", "accounts", "aliases"}


def test_sudo_choice_takes_only_password_and_ask():
    """`gate check`'s sudo choice is "password" or "ask"; "nopasswd" (when the
    gateway still installed a sudoers rule) is neither read nor written."""
    d = vault.empty()
    vault.set_sudo_choice(d, "localhost", "me", "ask")
    assert vault.sudo_choice(d, "localhost", "me") == "ask"
    vault.set_sudo_choice(d, "localhost", "me", "password")
    assert vault.sudo_choice(d, "localhost", "me") == "password"
    d["sudo_choice"]["localhost"]["me"] = "nopasswd"
    assert vault.sudo_choice(d, "localhost", "me") is None
    try:
        vault.set_sudo_choice(d, "localhost", "me", "nopasswd")
    except ValueError:
        pass
    else:
        raise AssertionError("nopasswd accepted")
    vault.set_sudo_choice(d, "localhost", "me", None)
    assert vault.sudo_choice(d, "localhost", "me") is None and "localhost" not in d["sudo_choice"]
