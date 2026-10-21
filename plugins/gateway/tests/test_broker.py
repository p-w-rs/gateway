"""The gateway daemon's broker (PLAN-v4 phase 2): the vault key wrapped by a
passphrase (age's scrypt recipient), unlock, lock (explicit, idle, exit),
scoped vault data per entry point and merged writes, and the stand-ins
getting their data through the daemon (sudo against the fake sudo, ssh
against a local sshd) with a clear refusal while the vault is locked."""
from __future__ import annotations

import contextlib
import json
import os
import stat
import subprocess
import time
from pathlib import Path

import harness as H
import harness_daemon as D
from gateway import consent, paths, testing, vault
from gateway import form as formmod
from gateway.daemon import broker, server

PASS = "a long test passphrase 4u"


def _sample() -> dict:
    d = vault.empty()
    vault.set_sudo(d, "localhost", "tester", "local-sudo-password-1")
    h = vault.host_record(d, "box")
    h["keys"].append({"private": "-----PRIVATE box key 1-----", "public": "ssh-ed25519 AAAA box",
                      "fingerprint": "SHA256:box", "created": "x", "retired": None})
    h["host_keys"] = ["ssh-ed25519 AAAAhostkey"]
    vault.set_sudo(d, "box", "root", "box-sudo-password-1")
    a = vault.account_record(d, "gh-me", "github")
    a["token"] = {"value": "ghp_tokenvalue_for_gh_me_0001", "source": "pasted", "updated": "x",
                  "stale": False}
    a["ssh_key"] = {"private": "-----PRIVATE gh key-----", "public": "ssh-ed25519 AAAA gh",
                    "fingerprint": "SHA256:gh"}
    b = vault.account_record(d, "az-work", "azure")
    b["entra"] = {"refresh_token": "refresh-token-for-az-work-0001", "client_id": "c", "tenant_id": "t"}
    return d


@contextlib.contextmanager
def _as_daemon(b: broker.Broker):
    """This process decrypts as the daemon does (vault._DAEMON_IDENTITY)."""
    old = vault._DAEMON_IDENTITY
    vault._DAEMON_IDENTITY = b.identity
    try:
        yield
    finally:
        vault._DAEMON_IDENTITY = old


# ---------------------------------------------------------------------------
# Scopes, views and merges
# ---------------------------------------------------------------------------


def test_each_entry_point_sees_only_its_classes():
    s = broker.scope_for
    assert s("shim sudo") == {"sudo_local"}
    assert s("shim ssh") == s("shim scp") == s("shim sftp") == {"ssh_hosts", "sudo_hosts", "account_keys"}
    assert s("git-credential") == s("mcp") == {"tokens", "signins", "cache"}
    assert s("shim gh") == s("shim hf") == s("shim az") == {"tokens", "signins", "account_keys", "cache"}
    assert s("gate") == s("shim gate") == broker.ALL
    assert s("hook-post") == s("hook-prompt") == s("hook-session") == broker.ALL   # they mask values
    assert s("hook-files") == s("askpass") == s("gated") == s("nonsense") == set()
    assert broker.direct_tool("shim sudo") == "sudo" and broker.direct_tool("git-credential") == \
        "git-credential"
    assert broker.direct_tool("gate") is None and broker.direct_tool("hook-post") is None
    assert broker.direct_tool("mcp") is None and broker.direct_tool("shim gate") is None


def test_a_view_replaces_what_the_peer_may_not_see_with_sentinels():
    d, key = _sample(), os.urandom(32)
    v = broker.make_view(d, broker.scope_for("shim sudo"), key)
    assert v["localhost"]["sudo"]["tester"]["password"] == "local-sudo-password-1"
    tok = v["accounts"]["gh-me"]["token"]["value"]
    assert broker.is_sentinel(tok) and vault.is_redacted(tok) and len(tok) == 44
    assert broker.is_sentinel(v["hosts"]["box"]["keys"][0]["private"])
    assert broker.is_sentinel(v["hosts"]["box"]["sudo"]["root"]["password"])
    assert broker.is_sentinel(v["accounts"]["az-work"]["entra"]["refresh_token"])
    # non-secret fields and metadata stay; a sentinel says nothing about its value
    assert v["hosts"]["box"]["host_keys"] == ["ssh-ed25519 AAAAhostkey"]
    assert vault.meta(v)["accounts"]["gh-me"]["token"] is True
    assert broker.sentinel(key, "a") == broker.sentinel(key, "a") != broker.sentinel(key, "b")
    assert broker.sentinel(key, "a") != broker.sentinel(os.urandom(32), "a")
    assert vault.all_values(v) == ["local-sudo-password-1"]
    assert [t[3] for t in vault.labeled_secrets(v)] == ["local-sudo-password-1"]
    assert d["accounts"]["gh-me"]["token"]["value"] == "ghp_tokenvalue_for_gh_me_0001"   # a copy
    # full scope: everything real
    assert broker.make_view(d, broker.ALL, key) == d


def test_a_withheld_entry_is_redacted_even_in_scope():
    d, key = _sample(), os.urandom(32)
    v = broker.make_view(d, broker.scope_for("shim gh"), key,
                         lambda section, name: name != "gh-me")
    assert broker.is_sentinel(v["accounts"]["gh-me"]["token"]["value"])
    assert v["accounts"]["az-work"]["entra"]["refresh_token"] == "refresh-token-for-az-work-0001"


def test_merges_restore_sentinels_and_refuse_changes_to_what_was_hidden():
    key = os.urandom(32)
    cur = _sample()
    sudo = broker.scope_for("shim sudo")
    v = broker.make_view(cur, sudo, key)
    assert broker.merge(v, cur, sudo, key) == cur
    # what the sudo stand-in may do: mark its password stale, store a new one
    v["localhost"]["sudo"]["tester"]["stale"] = True
    vault.set_sudo(v, "localhost", "tester", "new-local-password")
    m = broker.merge(v, cur, sudo, key)
    assert m["localhost"]["sudo"]["tester"]["password"] == "new-local-password"
    assert m["accounts"]["gh-me"]["token"]["value"] == "ghp_tokenvalue_for_gh_me_0001"
    assert m["hosts"]["box"]["keys"][0]["private"] == "-----PRIVATE box key 1-----"

    def refused(edit) -> None:
        w = broker.make_view(cur, sudo, key)
        edit(w)
        try:
            broker.merge(w, cur, sudo, key)
        except broker.Conflict:
            return
        raise AssertionError("merge accepted a change to a hidden value")

    refused(lambda w: w["accounts"]["gh-me"]["token"].__setitem__("value", "attacker-token-xx"))
    refused(lambda w: w["accounts"].pop("gh-me"))                         # dropped
    refused(lambda w: w["accounts"]["az-work"].__setitem__(                # moved
        "token", {"value": w["accounts"]["gh-me"]["token"]["value"]}))
    refused(lambda w: w["accounts"].__setitem__("evil", {"token": {"value": "x" * 20}}))   # added
    refused(lambda w: w["hosts"]["box"]["keys"].clear())
    refused(lambda w: w["hosts"]["box"]["sudo"]["root"].__setitem__("password", "guess-guess"))
    w = broker.make_view(cur, sudo, key)
    w["accounts"]["gh-me"]["token"]["value"] = broker.sentinel(key, "never-stored-value")
    try:
        broker.merge(w, cur, sudo, key)
    except broker.Conflict:
        pass
    else:
        raise AssertionError("an unknown sentinel was accepted")
    # a writer with full scope may change anything
    allv = broker.make_view(cur, broker.ALL, key)
    allv["accounts"].pop("gh-me")
    assert "gh-me" not in broker.merge(allv, cur, broker.ALL, key)["accounts"]


def test_the_token_cache_is_scoped_and_merged():
    cache = {"tokens": {"gh-me|repo": {"value": "t1", "expires": 9e9},
                        "az-work|https://x": {"value": "t2", "expires": 9e9}}}
    every = lambda a: True   # noqa: E731
    assert broker.cache_view(cache, broker.scope_for("shim sudo"), every) == {"tokens": {}}
    assert broker.cache_merge(cache, cache, broker.scope_for("shim sudo"), every) is None
    only_az = lambda a: a == "az-work"   # noqa: E731
    v = broker.cache_view(cache, broker.scope_for("mcp"), only_az)
    assert list(v["tokens"]) == ["az-work|https://x"]
    v["tokens"]["az-work|https://y"] = {"value": "t3", "expires": 9e9}
    m = broker.cache_merge(v, cache, broker.scope_for("mcp"), only_az)
    assert set(m["tokens"]) == {"gh-me|repo", "az-work|https://x", "az-work|https://y"}


# ---------------------------------------------------------------------------
# The passphrase: wrap, unlock, lock
# ---------------------------------------------------------------------------


def test_wrap_unlock_lock_and_lock_after_idle():
    with H.gateway_env() as env:
        vault.save(_sample())
        key_txt = paths.key_path().read_text()
        rec = vault.recipient()
        assert vault.key_mode() == "unwrapped"
        b = broker.Broker(lock_after=0.3)
        assert b.state() == "unwrapped"
        with _as_daemon(b):
            b.set_passphrase(PASS)
            assert not paths.key_path().exists()
            assert vault.key_mode() == "wrapped" and b.state() == "unlocked"
            for p in (paths.wrapped_key_path(), paths.recipient_path()):
                assert stat.S_IMODE(p.stat().st_mode) == 0o600, p
            assert paths.recipient_path().read_text().strip() == rec
            assert b"AGE-SECRET-KEY" not in paths.wrapped_key_path().read_bytes()
            assert b.read()["accounts"]["gh-me"]["token"]["value"] == "ghp_tokenvalue_for_gh_me_0001"
            # writes still encrypt to the same recipient, without key.txt
            with vault.edit() as cur:
                cur["aliases"] = {"x": "gh-me"}
            assert not paths.key_path().exists()
            assert b.read()["aliases"] == {"x": "gh-me"}
            assert b.lock("explicit") and b.state() == "locked" and not b.lock("again")
            try:
                b.read()
            except vault.VaultLocked:
                pass
            else:
                raise AssertionError("a locked broker read the vault")
            try:
                b.unlock("not the passphrase at all")
            except broker.BrokerError as e:
                assert "doesn't unlock" in str(e)
            else:
                raise AssertionError("a wrong passphrase unlocked")
            assert b.state() == "locked"
            b.unlock(PASS)
            assert b.state() == "unlocked" and b.read()["aliases"] == {"x": "gh-me"}
            b.tick()
            assert b.state() == "unlocked"          # used just now
            time.sleep(0.4)
            b.tick()
            assert b.state() == "locked", "idle for lock_after: locked"
            b.unlock(PASS)
            time.sleep(0.2)
            b.read()                                 # a use resets the idle clock
            time.sleep(0.2)
            b.tick()
            assert b.state() == "unlocked"
        # the identity never landed in a file
        assert key_txt.strip() not in "".join(p.read_text(errors="replace")
                                              for p in paths.private_dir().iterdir() if p.is_file())


def test_a_wrap_that_fails_its_check_keeps_key_txt():
    with H.gateway_env() as env:
        vault.save(_sample())
        before = paths.key_path().read_bytes()
        env.o.extra["gated_wrap_corrupt"] = True
        b = broker.Broker()
        try:
            b.set_passphrase(PASS)
        except broker.BrokerError as e:
            assert "failed its check" in str(e) and "nothing changed" in str(e)
        else:
            raise AssertionError("a corrupt wrap went through")
        assert paths.key_path().read_bytes() == before
        assert not paths.wrapped_key_path().exists() and not paths.recipient_path().exists()
        assert vault.key_mode() == "unwrapped" and b.state() == "unwrapped"
        assert not list(paths.private_dir().glob(".key.wrapped*"))
        assert vault.load()["accounts"]["gh-me"]["token"]["value"]


def test_wrap_refusals():
    with H.gateway_env():
        b = broker.Broker()
        for bad in ("short", "x" * 2000, "x" * 513, "\u00e9" * 257, "\ud800" + "x" * 20,
                    "tab\there-and-long-enough", None, 12345678901234):
            try:
                b.set_passphrase(bad)
            except broker.BrokerError:
                pass
            else:
                raise AssertionError(f"accepted {bad!r}")
        try:
            b.set_passphrase(PASS)                    # no key yet
        except broker.BrokerError as e:
            assert "no vault key" in str(e)
        vault.save(_sample())
        with _as_daemon(b):
            b.set_passphrase(PASS)
            try:
                b.set_passphrase(PASS + "2")
            except broker.BrokerError as e:
                assert "already has a passphrase" in str(e)
            else:
                raise AssertionError("wrapped twice")
        try:
            broker.Broker().unlock("")
        except broker.BrokerError:
            pass


def test_a_wrapped_key_is_never_replaced_by_a_new_key_txt():
    with H.gateway_env():
        vault.save(_sample())
        rec = vault.recipient()
        b = broker.Broker()
        with _as_daemon(b):
            b.set_passphrase(PASS)
        assert vault.ensure_key() == rec and not paths.key_path().exists()
        assert vault.recipient() == rec
        assert vault.brokered()                       # this process would ask the daemon


def test_lock_after_comes_from_the_form():
    with H.gateway_env() as env:
        assert broker.Broker().lock_after() == 8 * 3600
        env.write_form('[vault]\nlock_after = "30m"\n')
        assert broker.Broker().lock_after() == 1800
        env.write_form('[vault]\nlock_after = "2d"\n')
        f = env.form()
        assert f.vault.lock_after == 8 * 3600 and any("lock_after" in p.message for p in f.errors)
        env.write_form('[vault]\nlock_aftr = "1h"\n')
        assert any("lock_after" in p.message for p in env.form().problems)
        assert broker.Broker(lock_after=5).lock_after() == 5


# ---------------------------------------------------------------------------
# Through a real daemon
# ---------------------------------------------------------------------------


def test_the_test_routes_exist_only_under_a_test_override_that_enables_them():
    with D.daemon_env(knobs={"test_routes": False}) as de:
        vault.save(_sample())
        st, body = de.call("POST", "/test/vault/passphrase", {"passphrase": PASS})
        assert st == 404, body
        assert paths.key_path().exists()
    with D.daemon_env() as de:
        vault.save(_sample())
        de.wrap(PASS)
        assert not paths.key_path().exists() and de.health()["vault"] == "unlocked"
        st, body = de.unlock("wrong wrong wrong wrong")
        assert st == 400 and "doesn't unlock" in body["message"]


def _sudo_env(de: D.DaemonEnv, password: str = "correct horse"):
    fake = H.make_fake_sudo(de.root / "fake-sudo", password=password)
    drv = D.write_driver(de.env, de.run, tools={"sudo": str(fake.path)})
    de.env.write_form("[hosts.localhost]\nsudo = true\n")
    consent.approve_all(de.env.form())
    with vault.edit() as d:
        vault.set_sudo(d, "localhost", paths.local_user(), password)
        a = vault.account_record(d, "gh-me", "github")
        a["token"] = {"value": "ghp_tokenvalue_for_gh_me_0001", "source": "pasted", "updated": "x",
                      "stale": False}
    return fake, drv


def _proc_env(de: D.DaemonEnv, fc: D.FakeClaude) -> dict[str, str]:
    e = de.env.subprocess_env()
    e.pop("GATEWAY_TEST_ROOT")
    e["CLAUDE_PID"] = str(fc.pid)
    return e


def test_the_sudo_stand_in_gets_its_password_through_the_daemon():
    with D.daemon_env() as de:
        fake, drv = _sudo_env(de)
        de.wrap(PASS)
        fc = de.claude()
        r = fc.run([H.PY, "-I", "-S", drv, de.root, "shim", "sudo", "echo", "via-broker"],
                   env=_proc_env(de, fc))
        assert r.returncode == 0 and r.stdout == "via-broker\n", (r.stdout, r.stderr)
        log = fake.log()
        assert any(e.get("how") == "A" for e in log) and log[-1]["ran"] == ["echo", "via-broker"]
        # locked: a clear refusal, nothing run, the session has a screen
        st, body = fc.http("POST", "/ui/vault/lock")
        assert st == 200 and body["locked"] and de.health()["vault"] == "locked"
        n = len(fake.log())
        r = fc.run([H.PY, "-I", "-S", drv, de.root, "shim", "sudo", "echo", "x"], env=_proc_env(de, fc))
        assert r.returncode == 1 and r.stderr.strip() == server.LOCKED_INTERACTIVE, r.stderr
        assert len(fake.log()) == n and "x" not in r.stdout
        # a headless session (registered without a surface) gets the headless wording
        hl = de.claude(surface=None, session="s-print")
        r = hl.run([H.PY, "-I", "-S", drv, de.root, "shim", "sudo", "echo", "x"], env=_proc_env(de, hl))
        assert r.returncode == 1 and r.stderr.strip() == server.LOCKED_HEADLESS, r.stderr
        assert de.unlock(PASS)[0] == 200
        r = fc.run([H.PY, "-I", "-S", drv, de.root, "shim", "sudo", "echo", "again"],
                   env=_proc_env(de, fc))
        assert r.returncode == 0 and "again" in r.stdout, r.stderr


def test_each_stand_in_reads_only_its_scope_through_the_daemon():
    with D.daemon_env() as de:
        _fake, drv = _sudo_env(de)
        de.wrap(PASS)
        fc = de.claude()

        def dump(*mode: str, through: list[str] | None = None) -> dict:
            env = {**_proc_env(de, fc), "GW_DUMP": "1"}
            r = fc.run([*(through or []), H.PY, "-I", "-S", drv, de.root, *mode], env=env)
            assert r.returncode == 0, (r.stdout, r.stderr)
            out = json.loads(r.stdout)
            assert "slots" in out, out
            return {s[0]: s[2] for s in out["slots"]}

        assert dump("shim", "sudo") == {"sudo_local": "real", "tokens": "redacted"}
        assert dump("shim", "gh") == {"sudo_local": "redacted", "tokens": "real"}
        assert dump("git-credential", "get") == {"sudo_local": "redacted", "tokens": "real"}
        assert dump("gate", "status") == {"sudo_local": "real", "tokens": "real"}
        # not direct (a make-like program between Claude and the stand-in): only
        # entries with an effective scripts = true
        wrapper = de.root / "drivers" / "make.py"
        wrapper.write_text("import subprocess, sys\nsys.exit(subprocess.run(sys.argv[1:]).returncode)\n")
        assert dump("shim", "sudo", through=[H.PY, "-I", str(wrapper)]) == \
            {"sudo_local": "redacted", "tokens": "redacted"}


def test_a_limited_writer_keeps_what_it_cannot_see():
    with D.daemon_env() as de:
        fake, drv = _sudo_env(de, password="the-real-password")
        with vault.edit() as d:                       # a wrong stored password
            vault.set_sudo(d, "localhost", paths.local_user(), "a-stale-wrong-password")
        de.wrap(PASS)
        fc = de.claude()
        r = fc.run([H.PY, "-I", "-S", drv, de.root, "shim", "sudo", "true"], env=_proc_env(de, fc))
        assert r.returncode != 0, (r.stdout, r.stderr)
        full = D.full_vault(PASS)
        e = full["localhost"]["sudo"][paths.local_user()]
        assert e["stale"] is True and e["password"] == "a-stale-wrong-password"
        assert full["accounts"]["gh-me"]["token"]["value"] == "ghp_tokenvalue_for_gh_me_0001"
        assert any(ev["what"] == "reject" for ev in full["events"])


def test_hooks_and_gate_report_a_locked_vault():
    with D.daemon_env() as de:
        _fake, drv = _sudo_env(de)
        de.env.write_form("[hosts.localhost]\nsudo = true\n\n[hosts.box]\n"
                          "address = \"tester@10.9.8.7\"\nssh = true\n")
        de.wrap(PASS)
        assert fc_lock(de)
        fc = de.claude()
        env = de.env.subprocess_env(de.extra_env())
        run_py = [H.PY, "-I", "-S", *H.PYX, str(H.PLUGIN / "run.py"), "--test"]
        # box's ssh right is in the form but its approval is in the (locked) vault:
        # the hook says the vault is locked, not "waits for the user's OK"
        payload = {"tool_name": "Bash", "tool_input": {"command": "ssh box ls"},
                   "permission_mode": "auto", "session_id": "s", "cwd": str(de.root)}
        r = fc.run(run_py + ["hook-bash"], env=env, input=json.dumps(payload))
        out = json.loads(r.stdout)
        reason = out["hookSpecificOutput"]["permissionDecisionReason"]
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
        assert reason == server.LOCKED_INTERACTIVE, reason
        r = fc.run(run_py + ["hook-session"], env=env, input=json.dumps({"session_id": "s"}))
        out = json.loads(r.stdout)
        assert __import__("gateway.hooks_session", fromlist=["x"]).VAULT_LOCKED in out["systemMessage"]
        r = fc.run([H.PY, "-I", "-S", drv, de.root, "gate", "status"], env=_proc_env(de, fc))
        assert "vault locked" in r.stdout, (r.stdout, r.stderr)
        r = fc.run([H.PY, "-I", "-S", drv, de.root, "gate", "lock"], env=_proc_env(de, fc))
        assert "the vault is locked" in r.stdout, (r.stdout, r.stderr)


def fc_lock(de: D.DaemonEnv) -> bool:
    fc = de.claude(session="s-locker")
    st, body = fc.http("POST", "/ui/vault/lock")
    fc.close()
    return st == 200 and body["locked"]


def test_gate_lock_locks_and_says_when_there_is_nothing_to_lock():
    with D.daemon_env() as de:
        _fake, drv = _sudo_env(de)
        fc = de.claude()
        r = fc.run([H.PY, "-I", "-S", drv, de.root, "gate", "lock"], env=_proc_env(de, fc))
        assert "no passphrase, so there is nothing to lock" in r.stdout, r.stdout
        de.wrap(PASS)
        r = fc.run([H.PY, "-I", "-S", drv, de.root, "gate", "lock"], env=_proc_env(de, fc))
        assert r.stdout.strip() == "gateway: the vault is locked" and de.health()["vault"] == "locked"


def test_the_daemon_locks_the_vault_when_it_exits():
    with D.daemon_env() as de:
        vault.save(_sample())
        de.wrap(PASS)
        assert de.health()["vault"] == "unlocked"
        de.stop()
        assert de.wait_for(lambda: de.health() is None)
        de.start()
        assert de.health()["vault"] == "locked", "a new daemon starts locked"
        evs = [json.loads(l) for l in (paths.gated_dir() / "events" / "epoch-1.jsonl").read_text()
               .splitlines()]
        kinds = [e["kind"] for e in evs]
        assert "vault.wrapped" in kinds and kinds[-2:] == ["daemon.stopping", "vault.locked"], kinds


def test_idle_lock_in_the_daemon():
    with D.daemon_env(knobs={"lock_after": 0.5}) as de:
        vault.save(_sample())
        de.wrap(PASS)
        assert de.health()["vault"] == "unlocked"
        assert de.wait_for(lambda: de.health()["vault"] == "locked", timeout=5)


def test_the_ssh_stand_in_through_the_daemon_against_a_local_sshd():
    import harness_ssh as HS
    with HS.ssh_env() as s:
        sshd = s.sshd()
        s.write_form(f'[hosts.box]\naddress = "{HS.real_user()}@127.0.0.1:{sshd.port}"\nssh = true\n')
        s.approve()
        s.host("box", sshd)
        with D.attach(s.env, s.run_dir) as de:
            de.wrap(PASS)
            fc = de.claude()
            env = s.proc_env()
            env.pop("GATEWAY_TEST_ROOT", None)
            r = fc.run([str(s.stub("ssh")), "box", "echo", "through-the-broker"], env=env)
            assert r.returncode == 0 and r.stdout.strip() == "through-the-broker", (r.stdout, r.stderr)
            seen = sshd.accepted()
            assert fc.http("POST", "/ui/vault/lock")[0] == 200
            r = fc.run([str(s.stub("ssh")), "box", "echo", "locked"], env=env)
            assert r.returncode != 0 and server.LOCKED_INTERACTIVE in r.stderr, (r.stdout, r.stderr)
            assert "locked" not in r.stdout and sshd.accepted() == seen


def test_no_secret_reaches_events_snapshots_health_or_the_daemons_files():
    """Synthetic canaries (generated here, never printed) as the passphrase, a
    wrong passphrase, the sudo password, a token, an ssh key and a refused
    request's body, through wrap, a stand-in's read, lock, a failed and a
    good unlock: none of them is in the events (served and on disk), the
    snapshot, capabilities, health, contract.json, the session registry, the
    machine ids or the daemon's log. The vault itself holds them (positive
    control, so the scan is known to work)."""
    from tui import scan
    pw, wrong, sudo_pw, tok, key_c, body_c = (scan.Canary.new(x) for x in
                                              ("pass", "wrong", "sudo", "tok", "key", "body"))
    canaries = (pw, wrong, sudo_pw, tok, key_c, body_c)
    with D.daemon_env() as de:
        fake, drv = _sudo_env(de, password=sudo_pw.value)
        de.env.write_form("[hosts.localhost]\nsudo = true\n\n[hosts.box]\n"
                          "address = \"tester@10.9.8.7\"\nssh = true\n")
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), sudo_pw.value)
            d["accounts"]["gh-me"]["token"]["value"] = tok.value
            vault.host_record(d, "box")["keys"].append(
                {"private": key_c.value, "public": "ssh-ed25519 AAAA x", "fingerprint": "", "created": "x",
                 "retired": None})
        de.wrap(pw.value)
        fc = de.claude(session="s-canary")
        r = fc.run([H.PY, "-I", "-S", drv, de.root, "shim", "sudo", "echo", "ok"], env=_proc_env(de, fc))
        assert r.returncode == 0 and r.stdout == "ok\n", r.stderr
        st, _b = de.call("POST", "/ui/register", {"session_id": body_c.value, "note": body_c.value})
        assert st == 403
        assert fc.http("POST", "/ui/vault/lock")[0] == 200
        assert de.unlock(wrong.value)[0] == 400
        assert de.unlock(pw.value)[0] == 200
        gate = D.probe_root(de.root)
        served = {p: de.probe(fc, gate / "run.py", ["shim", "gh"], p, method="GET")
                  for p in ("/v1/events?since=0", "/v1/snapshot", "/v1/capabilities", "/health")}
        assert all(st == 200 for st, _ in served.values()), served
        kinds = [e["kind"] for e in served["/v1/events?since=0"][1]["events"]]
        assert {"vault.wrapped", "vault.locked", "vault.unlocked", "session.registered"} <= set(kinds)
        rep = scan.Report()
        for p, (_st, body) in served.items():
            rep.scan_text(json.dumps(body), p, *canaries)
        rep.scan_tree(paths.gated_dir(), *canaries, label="gated-data")
        rep.scan_tree(de.run, *canaries, label="run-dir")
        rep.scan_tree(paths.contract_dir(), *canaries, label="contract-dir")
        assert rep.clean(), rep.summary()
        # positive control: the vault holds them, and the scan finds them there
        ctl = scan.Report()
        ctl.scan_text(json.dumps(D.full_vault(pw.value)), "vault", sudo_pw, tok, key_c)
        assert len(ctl.hits) == 3, ctl.summary()


def test_a_stand_in_outside_a_known_session_is_refused_with_the_reason():
    with D.daemon_env() as de:
        _fake, drv = _sudo_env(de)
        de.wrap(PASS)
        stranger = de.claude(register=False)
        r = stranger.run([H.PY, "-I", "-S", drv, de.root, "shim", "sudo", "echo", "x"],
                         env=_proc_env(de, stranger))
        assert r.returncode == 1 and "isn't running inside a Claude Code session the gateway " \
            "knows" in r.stderr, r.stderr
        assert "x" not in r.stdout


def test_a_hook_registers_its_session_itself_and_masks_with_every_value():
    with D.daemon_env() as de:
        _fake, _drv = _sudo_env(de)
        de.wrap(PASS)
        fc = de.claude(register=False)                 # mods off: no UI registration
        env = de.env.subprocess_env(de.extra_env())
        payload = {"tool_name": "Bash", "session_id": "s", "hook_event_name": "PostToolUse",
                   "tool_input": {"command": "cat notes.txt"},
                   "tool_response": {"stdout": "token: ghp_tokenvalue_for_gh_me_0001 end",
                                     "stderr": "", "interrupted": False}}
        r = fc.run([H.PY, "-I", "-S", *H.PYX, str(H.PLUGIN / "run.py"), "--test", "hook-post"], env=env,
                   input=json.dumps(payload))
        assert r.returncode == 0, r.stderr
        assert "ghp_tokenvalue_for_gh_me_0001" not in r.stdout and "***" in r.stdout, r.stdout
        reg = json.loads((de.run / "gated-sessions.json").read_text())["sessions"]
        assert [(s["pid"], s["via"], s["ui"]) for s in reg] == [(fc.pid, "hook", False)], reg


def test_the_async_session_start_hook_starts_the_daemon_and_registers_the_session():
    with D.daemon_env(start=False) as de:
        fc = de.claude(register=False)
        env = de.env.subprocess_env(de.extra_env())
        r = fc.run([H.PY, "-I", "-S", *H.PYX, str(H.PLUGIN / "run.py"), "--test", "hook-daemon"], env=env,
                   input=json.dumps({"session_id": "s-async", "hook_event_name": "SessionStart"}))
        assert r.returncode == 0 and r.stdout == "", (r.stdout, r.stderr)
        h = de.health()
        assert h and h["sessions"] == 1, h
        reg = json.loads((de.run / "gated-sessions.json").read_text())["sessions"]
        assert reg[0]["pid"] == fc.pid and reg[0]["session_id"] == "s-async" and reg[0]["via"] == "hook"


def test_gated_start_names_its_parent_only_when_that_is_claude_code():
    with D.daemon_env() as de:
        fc = de.claude()
        env = de.env.subprocess_env(de.extra_env())
        r = fc.run([H.PY, "-I", "-S", *H.PYX, str(H.PLUGIN / "run.py"), "--test", "gated", "start"], env=env)
        out = json.loads(r.stdout)
        assert out["ok"] and out["parent_pid"] == fc.pid, out
        mine = de.start()                              # from the test runner (not Claude Code)
        assert "parent_pid" not in mine and mine["pid"] == out["pid"]
        r = fc.run([H.PY, "-I", "-S", *H.PYX, str(H.PLUGIN / "run.py"), "--test", "gated", "status"], env=env)
        assert json.loads(r.stdout)["pid"] == out["pid"]


def test_data_encrypted_to_this_machine_opens_through_the_daemon_for_gate_only():
    with D.daemon_env() as de:
        _fake, drv = _sudo_env(de)
        rec = vault.recipient()
        blob = de.root / "stream.age"
        p = subprocess.run([paths.tool("age"), "-e", "-r", rec, "-o", str(blob)],
                           input=b"copy-to stream payload", capture_output=True)
        assert p.returncode == 0
        de.wrap(PASS)
        fc = de.claude()
        env = {**_proc_env(de, fc), "GW_OPEN_OWN": str(blob)}
        r = fc.run([H.PY, "-I", "-S", drv, de.root, "gate", "import"], env=env)
        assert json.loads(r.stdout) == {"sha": D.sha16("copy-to stream payload")}, r.stdout
        r = fc.run([H.PY, "-I", "-S", drv, de.root, "shim", "sudo"], env=env)
        assert "error" in json.loads(r.stdout), r.stdout


def test_locked_refusals_reach_the_http_tool_and_the_git_helper_verbatim():
    from gateway import githelper, web
    with H.gateway_env():
        saved = vault.load, vault.exists
        try:
            vault.exists = lambda: True

            def locked():
                raise vault.VaultLocked("gateway: the gateway vault is locked (test)")
            vault.load = locked
            try:
                web._load_state()
            except web.Refused as e:
                assert str(e) == "gateway: the gateway vault is locked (test)"
            else:
                raise AssertionError("no refusal")
        finally:
            vault.load, vault.exists = saved
    src = (H.PLUGIN / "src" / "gateway" / "githelper.py").read_text()
    assert "except vault.VaultLocked as e:\n        return _refuse(host, str(e))" in src
    assert githelper   # imported


def test_the_vault_client_asks_the_daemon_on_every_read():
    """Nothing is kept in the calling process between reads (the verifier: a
    long-running process kept using its view after the vault was locked):
    each read is one request, and a lock answered by the daemon is
    VaultLocked at once."""
    from gateway.daemon import client
    with H.gateway_env():
        vault.save(_sample())
        calls = []
        answers = [{"data": {"aliases": {}}}, {"data": {"aliases": {}}}]
        saved = client._vault_call

        def fake(path, body):
            calls.append(path)
            if not answers:
                raise vault.VaultLocked("gateway: the gateway vault is locked (test)")
            return answers.pop(0)
        try:
            client._vault_call = fake
            assert client.vault_read() == {"aliases": {}}
            assert client.vault_read() == {"aliases": {}}
            assert calls == ["/agent/vault/read"] * 2
            try:
                client.vault_read()
            except vault.VaultLocked:
                pass
            else:
                raise AssertionError("a read after the daemon locked the vault got data")
            assert calls == ["/agent/vault/read"] * 3
        finally:
            client._vault_call = saved


LONG_RUNNING = """import json, os, sys, time
sys.path.insert(0, {src!r})
from gateway import paths, testing, vault
root = sys.argv[1]
with open(os.path.join(root, "entry-knobs.json")) as f:
    kw = json.load(f)
with testing.override(root, **kw):
    paths.ENTRY_MODE = "mcp"              # the MCP server: one process for the whole session
    def token():
        try:
            v = vault.load()["accounts"]["gh-me"]["token"]["value"]
            return "redacted" if vault.is_redacted(v) else "real"
        except vault.VaultLocked:
            return "VaultLocked"
        except vault.VaultError as e:
            return type(e).__name__
    for step in ("1", "2", "3"):
        while not os.path.exists(os.path.join(root, "go" + step)):
            time.sleep(0.02)
        with open(os.path.join(root, "out" + step), "w") as f:
            f.write(token())
"""


def test_a_long_running_process_gets_nothing_once_the_vault_is_locked():
    """The MCP server runs for the whole session: after a lock its next read
    is VaultLocked (the verifier saw it keep getting the real token while
    /health said locked), and after an unlock it reads again."""
    with D.daemon_env() as de:
        _sudo_env(de)
        de.wrap(PASS)
        fc = de.claude()
        script = de.root / "drivers" / "long_mcp.py"
        script.write_text(LONG_RUNNING.format(src=str(H.PLUGIN / "src")))
        pid = fc.spawn([H.PY, "-I", "-S", *H.PYX, script, de.root, "mcp"], env=_proc_env(de, fc))

        def step(n: str) -> str:
            (de.root / f"go{n}").write_text("")
            # the driver creates outN before it reads the vault (open, then write):
            # wait for its answer, not for the empty file (after an unlock the
            # daemon decrypts again, which can take longer than a short grace)
            out = de.root / f"out{n}"
            assert de.wait_for(lambda: out.exists() and out.read_text() != "", 30), f"step {n}"
            return out.read_text()
        assert step("1") == "real"
        st, body = fc.http("POST", "/ui/vault/lock")
        assert st == 200 and body["locked"] and de.health()["vault"] == "locked", body
        assert step("2") == "VaultLocked"
        assert de.unlock(PASS)[0] == 200
        assert step("3") == "real"
        r = fc.wait(pid)
        assert r.returncode == 0, r.stderr


def test_the_broker_keeps_one_decrypted_copy_and_forgets_it_when_locked():
    """The daemon decrypts once while vault.age stays the same file (the
    other processes ask on every read), decrypts again after a write, and a
    lock forgets the copy with the identity."""
    with H.gateway_env():
        vault.save(_sample())
        b = broker.Broker()
        n = []
        saved = vault._decrypt
        with _as_daemon(b):
            b.set_passphrase(PASS)
            try:
                vault._decrypt = lambda path: n.append(path) or saved(path)
                first = b.read()
                assert b.read() == first and len(n) == 1, n
                first["aliases"]["mutated"] = "x"               # the caller's copy only
                assert "mutated" not in b.read()["aliases"]
                b.write({**b.read(), "aliases": {"y": "gh-me"}})
                assert b.read()["aliases"] == {"y": "gh-me"} and len(n) == 2, n
                assert b._plain is not None
                assert b.lock("explicit") and b._plain is None
                try:
                    b.read()
                except vault.VaultLocked:
                    pass
                else:
                    raise AssertionError("a locked broker read the vault")
                b.unlock(PASS)
                assert b.read()["aliases"] == {"y": "gh-me"} and len(n) == 3, n
                vault.save({**b.read(), "aliases": {"z": "gh-me"}})   # a write elsewhere: a new file
                assert b.read()["aliases"] == {"z": "gh-me"}
            finally:
                vault._decrypt = saved


def test_unlock_refuses_a_wrapped_key_that_doesnt_match_key_recipient():
    """key.recipient is what new vault writes encrypt to; a passphrase that
    unwraps key.wrapped to another identity than key.recipient names (one of
    the two replaced) leaves the vault locked."""
    with H.gateway_env():
        vault.save(_sample())
        b = broker.Broker()
        with _as_daemon(b):
            b.set_passphrase(PASS)
        assert b.lock("explicit")
        p = subprocess.run([paths.tool("age-keygen")], capture_output=True, text=True)
        other = next(l.split(": ", 1)[1] for l in p.stdout.splitlines() if "public key" in l)
        good = paths.recipient_path().read_text()
        paths.recipient_path().write_text(other + "\n")
        try:
            b.unlock(PASS)
        except broker.BrokerError as e:
            assert "doesn't match key.recipient" in str(e), e
        else:
            raise AssertionError("unlocked a key that doesn't match key.recipient")
        assert b.state() == "locked"
        paths.recipient_path().write_text(good)
        b.unlock(PASS)
        assert b.state() == "unlocked"


def test_passphrases_are_bounded_in_utf8_bytes_below_the_tty_line_limit():
    """age reads the passphrase as one tty line, and macOS ends a line at
    1024 bytes: the verifier's 1024-character and 600 x "e-acute" (1200
    bytes) passphrases, both accepted, hung age for 130 s with the vault's
    flock held. The bound is 512 UTF-8 bytes, for wrap and unlock, and agepass
    refuses longer ones before age starts (export and import too). At the
    bound age finishes promptly."""
    from gateway import agepass, transfer
    ok, chk = broker.Broker._check_passphrase, broker.MAX_PASSPHRASE_BYTES
    assert chk == agepass.MAX_PASSPHRASE_BYTES == 512
    for good in ("x" * 512, "\u00e9" * 256, "\U0001F511" * 128, "y" * 12):
        assert ok(good) == good
    for bad in ("x" * 513, "\u00e9" * 257, "\U0001F511" * 129, "\u00e9" * 600, "x" * 1024):
        try:
            ok(bad)
        except broker.BrokerError as e:
            assert "512 bytes" in str(e), e
        else:
            raise AssertionError(f"accepted {len(bad)} characters ({len(bad.encode())} bytes)")
    with H.gateway_env():
        for pw in ("x" * 513, "\u00e9" * 300):
            t0 = time.time()
            for fn in (lambda: agepass.encrypt(b"x", pw), lambda: agepass.decrypt(b"x", pw)):
                try:
                    fn()
                except agepass.PassphraseTooLong:
                    pass
                else:
                    raise AssertionError("agepass took a passphrase over the bound")
            assert time.time() - t0 < 1, "refused before age starts"
            for fn in (lambda: transfer.encrypt_passphrase(b"x", pw),
                       lambda: transfer.decrypt_passphrase(b"x", pw)):
                try:
                    fn()
                except transfer.TransferError as e:
                    assert "at most 512 bytes" in str(e) and "nothing was" in str(e), e
                else:
                    raise AssertionError("transfer took a passphrase over the bound")
        for pw in ("k" * 512, "\u00e9" * 256):                # at the bound: age finishes
            t0 = time.time()
            blob = agepass.encrypt(b"AGE-SECRET-KEY-1TEST\n", pw)
            assert agepass.decrypt(blob, pw) == b"AGE-SECRET-KEY-1TEST\n"
            assert time.time() - t0 < 30, time.time() - t0
        vault.save(_sample())
        b = broker.Broker()
        with _as_daemon(b):
            b.set_passphrase("\u00e9" * 256)                  # 512 bytes: wrapped
        assert b.lock("explicit")
        for bad in ("\u00e9" * 257, "x" * 1024, "ok-length-but\rcontrol"):
            try:
                b.unlock(bad)
            except broker.BrokerError as e:
                assert "doesn't unlock" in str(e), e
            else:
                raise AssertionError("unlock took a passphrase the wrap never accepts")
        b.unlock("\u00e9" * 256)
        assert b.state() == "unlocked"


def test_setting_the_passphrase_runs_age_without_the_vault_lock_or_the_broker_mutex():
    """age's scrypt takes seconds (and up to its timeout when something goes
    wrong); while it runs, vault writers (the flock) and the daemon's reads
    (the broker's mutex) go on. Both are taken only to put the files in
    place."""
    import threading
    from gateway import agepass
    with H.gateway_env():
        vault.save(_sample())
        b = broker.Broker()
        inside, release = threading.Event(), threading.Event()
        real = agepass.encrypt
        errors: list = []

        def slow_encrypt(plain, pw):
            inside.set()
            release.wait(30)
            return real(plain, pw)

        def wrap() -> None:
            try:
                with _as_daemon(b):
                    b.set_passphrase(PASS)
            except Exception as e:  # noqa: BLE001
                errors.append(e)
        agepass.encrypt = slow_encrypt
        try:
            th = threading.Thread(target=wrap)
            th.start()
            assert inside.wait(30), "age never started"
            got = threading.Event()

            def take() -> None:
                with vault.locked():
                    with b.mutex:
                        got.set()
            t2 = threading.Thread(target=take, daemon=True)
            t2.start()
            assert got.wait(5), "the vault's flock or the broker's mutex is held while age runs"
            with vault.edit() as d:                            # a writer meanwhile
                d["aliases"] = {"during": "gh-me"}
            release.set()
            th.join(60)
        finally:
            agepass.encrypt = real
            release.set()
        assert not errors, errors
        assert vault.key_mode() == "wrapped" and b.state() == "unlocked"
        with _as_daemon(b):
            assert b.read()["aliases"] == {"during": "gh-me"}


def test_a_wrap_refuses_a_key_txt_replaced_while_age_ran():
    """The wrap is checked again under the flock: key.txt replaced meanwhile
    (a rotation) keeps the new key.txt and wraps nothing."""
    from gateway import agepass
    with H.gateway_env():
        vault.save(_sample())
        b = broker.Broker()
        real = agepass.encrypt
        new_key = subprocess.run([paths.tool("age-keygen")], capture_output=True, text=True).stdout

        def encrypt_then_rotate(plain, pw):
            out = real(plain, pw)
            paths.key_path().write_text(new_key)
            return out
        agepass.encrypt = encrypt_then_rotate
        try:
            b.set_passphrase(PASS)
        except broker.BrokerError as e:
            assert "changed while" in str(e) and "nothing changed" in str(e), e
        else:
            raise AssertionError("wrapped a key that was replaced meanwhile")
        finally:
            agepass.encrypt = real
        assert paths.key_path().read_text() == new_key and vault.key_mode() == "unwrapped"
        assert not paths.wrapped_key_path().exists() and not paths.recipient_path().exists()
        assert not list(paths.private_dir().glob(".key.wrapped*"))


def test_a_stand_in_starts_the_daemon_on_demand_and_a_new_daemon_is_locked():
    """With a wrapped key a stand-in that finds no daemon starts one (it
    detaches and outlives the stand-in); a new daemon holds the key locked,
    so the stand-in refuses with the locked wording for its session."""
    with D.daemon_env() as de:
        fake, drv = _sudo_env(de)
        de.wrap(PASS)
        fc = de.claude()
        de.stop()
        assert de.wait_for(lambda: de.health() is None)
        r = fc.run([H.PY, "-I", "-S", drv, de.root, "shim", "sudo", "echo", "x"], env=_proc_env(de, fc))
        assert r.returncode == 1 and r.stderr.strip() == server.LOCKED_INTERACTIVE, r.stderr
        h = de.health()
        assert h and h["vault"] == "locked" and h["epoch"] == 2, h
        assert not fake.log() or "x" not in str(fake.log()[-1].get("ran"))
