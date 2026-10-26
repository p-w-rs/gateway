"""The vault passphrase offer (PLAN-0.11 §8, WS-6): offered after a secret is
stored, never forced.

vault.save() marks the offer due ("pending") once the vault holds a secret
and its key has no passphrase; popup.offer_passphrase() asks gated after a
store, outside the vault's lock (in popup's detached helper only once its
job has ended, with its dialog lease; elsewhere at once on the agent
plane); gated (daemon/offer.py) offers once per session, only while due, the
key unwrapped and a dialog can open, as its own choice dialog that the mod
draws from a fixed template (hooks/mod/dialog.ts). Set passphrase opens the
set-a-passphrase dialog, Not now records "declined" for good, Cancel leaves
it pending. Also here: the remote sudo dialog's "Remember it" starts
unticked (PLAN-0.11 §9.1, 27g).

A real gated in a test root (harness_daemon), a FakeClaude playing the mod
(test_dialogs.Mod) and gateway entry points below it. Canaries are made here
and never printed."""
from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any

import harness as H
import harness_daemon as D
from gateway import consent, paths, popup, vault
from gateway.daemon import dialogs as dmod
from gateway.daemon import offer as omod
from test_dialogs import Mod, _driver, _Sess, _Daemon, seal, sha16

PASS = "a vault passphrase for the offer tests"


def canary(prefix: str = "pw") -> str:
    return f"{prefix}-{secrets.token_urlsafe(18)}"


def _is_offer(d: dict[str, Any]) -> bool:
    return d.get("offer") == "passphrase" and d.get("kind") == "choice"


def _setup(de: D.DaemonEnv) -> None:
    de.env.write_form('[hosts.localhost]\nsudo = true\n')
    vault.save(vault.empty())
    consent.approve_all(de.env.form())


def _sudo(de: D.DaemonEnv, fc: D.FakeClaude, mod: Mod, *, remember: bool | None = True
          ) -> dict[str, Any]:
    """`sudo echo hi` through the real stand-in (fake sudo, a canary password,
    none stored yet) below `fc`; the "mod" answers its password dialog sealed,
    with Remember it ticked unless `remember` says otherwise (the box starts
    unticked: None sends the dialog's own state). Returns the stand-in's exit
    and whether a password is stored now."""
    pw = canary()
    fake = H.make_fake_sudo(de.root / f"fsudo-{secrets.token_hex(3)}", password=pw)
    drv = _driver(de, tools={"sudo": str(fake.path)})
    env = de.env.subprocess_env()
    env.pop("GATEWAY_TEST_ROOT")
    env["CLAUDE_PID"] = str(fc.pid)
    pid = fc.spawn([H.PY, "-I", "-S", drv, str(de.root), "shim", "sudo", "echo", "hi"], env=env)
    d = mod.dialog(lambda d: d["kind"] == "secret", timeout=30)
    assert d["remember"] is False, "this computer's sudo dialog: Remember it, unticked (WS-9)"
    sealed = seal(d, [pw])
    if remember is not None:
        sealed["remember"] = remember
    mod.post("/ui/dialog/submit", sealed)
    r = fc.wait(pid, timeout=60)
    e = vault.sudo_entry(vault.load(), "localhost", paths.local_user())
    return {"rc": r.returncode, "stored": bool(e and e.get("password")),
            "stderr": r.stderr.replace(pw, "<PW>")[-400:]}


def _forget_local_sudo() -> None:
    with vault.edit() as d:
        d["localhost"]["sudo"] = {}


def _no_offer(mod: Mod, wait: float = 1.5) -> bool:
    end = time.time() + wait
    while time.time() < end:
        d = mod.view().get("dialog")
        if d and _is_offer(d):
            return False
        time.sleep(0.05)
    return True


OFFER_DRIVER = """import json, os, sys
sys.pycache_prefix = {pyc!r}
sys.path.insert(0, {src!r})
from gateway import testing
root = sys.argv[1]
with open(os.path.join(root, "entry-knobs.json")) as f:
    kw = json.load(f)
with testing.override(root, **kw):
    from gateway import paths, popup
    paths.ENTRY_MODE = sys.argv[2]
    print(json.dumps({{"offer": popup.offer_passphrase()}}))
"""


def _offer_from(de: D.DaemonEnv, fc: D.FakeClaude) -> str:
    """popup.offer_passphrase() in a gateway program below `fc` (not a helper:
    the agent plane, as gate check after a browser sign-in)."""
    _driver(de)                                       # entry-knobs.json (native dialogs)
    drv = de.root / "drivers" / "offer_entry.py"
    drv.write_text(OFFER_DRIVER.format(src=str(H.PLUGIN / "src"), pyc=H.PYC))
    env = de.env.subprocess_env()
    env.pop("GATEWAY_TEST_ROOT")
    r = fc.run([H.PY, "-I", "-S", str(drv), str(de.root), "gate"], env=env)
    lines = [ln for ln in r.stdout.splitlines() if ln.startswith("{")]
    assert lines, (r.returncode, r.stdout[-300:], r.stderr[-400:])
    return json.loads(lines[-1])["offer"]


# A gateway program below a FakeClaude that runs a flow's own code (a test
# entry point in the test root, native dialogs): the flows' real code, with
# only the network faked where the flow needs a remote host.
FLOW_DRIVER = """import json, os, sys
sys.pycache_prefix = {pyc!r}
sys.path.insert(0, {src!r})
from gateway import testing
root, mode, script = sys.argv[1], sys.argv[2], sys.argv[3]
with open(os.path.join(root, "entry-knobs.json")) as f:
    kw = json.load(f)
with testing.override(root, **kw):
    from gateway import paths
    paths.ENTRY_MODE = mode
    exec(compile(open(script).read(), script, "exec"))
"""


def _flow(de: D.DaemonEnv, fc: D.FakeClaude, body: str, **knobs: Any) -> int:
    """Run BODY (Python, under the test override) as `gate` below `fc`; its pid."""
    _driver(de, **knobs)                              # entry-knobs.json (native dialogs)
    d = de.root / "drivers"
    drv = d / "flow_entry.py"
    drv.write_text(FLOW_DRIVER.format(src=str(H.PLUGIN / "src"), pyc=H.PYC))
    script = d / f"flow-{secrets.token_hex(4)}.py"
    script.write_text(body)
    env = de.env.subprocess_env()
    env.pop("GATEWAY_TEST_ROOT")
    env["CLAUDE_PID"] = str(fc.pid)
    return fc.spawn([H.PY, "-I", "-S", str(drv), str(de.root), "gate", str(script)], env=env)


def _lock_free() -> bool:
    """Nobody holds the vault's lock now (set_passphrase takes it)."""
    try:
        with vault.locked(timeout=0.5):
            return True
    except vault.VaultError:
        return False


def _offered_with_the_lock_free(mod: Mod) -> dict[str, Any]:
    d = mod.dialog(_is_offer, timeout=30)
    assert _lock_free(), "the offer opened while the vault's lock was held"
    return d


# ---------------------------------------------------------------------------
# A real gated
# ---------------------------------------------------------------------------


def test_the_sudo_dialog_offers_only_once_a_password_is_remembered():
    """WS-8, through the sudo stand-in as WS-1 left it (this computer's sudo
    configured, the dialog with "Remember it"): unticked, the password is
    used for that command, nothing is stored and nothing is offered; ticked,
    it is stored and the offer opens right after the dialog, with the
    vault's lock free."""
    with D.daemon_env() as de:
        _setup(de)
        fc = de.claude()
        mod = Mod(fc)
        out = _sudo(de, fc, mod, remember=False)
        assert out["rc"] == 0 and not out["stored"], out
        assert vault.offer_state(vault.load()) is None and _no_offer(mod), "nothing stored: no offer"
        out = _sudo(de, fc, mod, remember=True)
        assert out["rc"] == 0 and out["stored"], out
        _offered_with_the_lock_free(mod)


REMOTE_SUDO_FLOW = """
import json
from gateway import ssh, ssh_conf, vault
from gateway import form as formmod
ssh.verify_remote_sudo = lambda name, user, pw: (True, "")      # (no host here)
st = ssh.State.__new__(ssh.State)
st.data = vault.load()
link = ssh_conf.Link(name="box", addr=formmod.parse_address("octo@box.example.com"),
                     host_keys=[], pubkeys=[])
pw, fresh, _upd = ssh._sudo_password("box", "octo", st, type("C", (), {"target": link})())
print(json.dumps({"fresh": fresh}))
"""


def test_a_remote_sudo_password_is_offered_only_when_remembered():
    """WS-8, the ssh stand-in's remote sudo dialog (ssh._sudo_password, its
    store and its unticked "Remember it", WS-1's ssh.py) through the real
    broker and gated, the remote host faked: used once, nothing is stored or
    offered; remembered, the offer follows the store with the lock free."""
    with D.daemon_env() as de:
        de.env.write_form('[hosts.box]\naddress = "octo@box.example.com"\nsudo = true\n')
        vault.save(vault.empty())
        consent.approve_all(de.env.form())
        fc = de.claude()
        mod = Mod(fc)
        for remember in (False, True):
            pid = _flow(de, fc, REMOTE_SUDO_FLOW)
            d = mod.dialog(lambda x: x["kind"] == "secret", timeout=30)
            assert d["entry"] == "box" and d["remember"] is False, d
            sealed = seal(d, [canary()])
            sealed["remember"] = remember
            mod.post("/ui/dialog/submit", sealed)
            r = fc.wait(pid, timeout=60)
            assert '"fresh": true' in r.stdout, (r.stdout[-300:], r.stderr[-400:])
            e = vault.sudo_entry(vault.load(), "box", "octo")
            assert bool(e and e.get("password")) is remember
            if not remember:
                assert vault.offer_state(vault.load()) is None and _no_offer(mod)
        _offered_with_the_lock_free(mod)


KEY_FLOW = """
import json
from gateway import gate_setup, vault
pins = vault.load()["hosts"]["lab"]["host_keys"]
gate_setup._keyscan = lambda name, h: (list(pins), "")          # (no host here)
logins = []


class Ssh:
    def test_login(self, name):
        logins.append(name)
        return (len(logins) > 1, "not installed yet")

    def install_key(self, name, method):
        return ""


gate_setup._ssh = lambda: Ssh()
print(json.dumps({"rc": gate_setup.check("lab")}))
"""


def test_gate_check_offers_after_its_job_stores_a_key_or_a_token():
    """WS-8, gate_setup's account and host setup through `gate check` and its
    dialog helper (only the host's network faked): an api-key account's
    token typed into the dialog, and a host's new SSH key (installed by
    hand: the public-key dialog), each make the offer once gate check's job
    has ended (its own dialogs first), with the vault's lock free."""
    with D.daemon_env() as de:
        de.env.write_form('[accounts.work-key]\nkind = "api-key"\nsites = ["api.example.com"]\n')
        vault.save(vault.empty())
        consent.approve_all(de.env.form())
        fc = de.claude()
        mod = Mod(fc)
        pid = _flow(de, fc, 'import json\nfrom gateway import gate_setup\n'
                            'print(json.dumps({"rc": gate_setup.check("work-key")}))\n')
        d = mod.dialog(lambda x: x["kind"] == "secret", timeout=30)
        assert d["entry"] == "work-key", d
        mod.post("/ui/dialog/submit", seal(d, ["sk-" + secrets.token_urlsafe(24)]))
        r = fc.wait(pid, timeout=60)
        assert '"rc": 0' in r.stdout, (r.stdout[-300:], r.stderr[-400:])
        _offered_with_the_lock_free(mod)
    with D.daemon_env() as de:
        de.env.write_form('[hosts.lab]\naddress = "octo@lab.example.com"\nsudo = false\n')
        vault.save(vault.empty())
        consent.approve_all(de.env.form())
        with vault.edit() as dd:
            vault.host_record(dd, "lab")["host_keys"] = [vault.norm_host_key(H.fake_host_key("lab"))]
        assert vault.offer_state(vault.load()) is None, "a pinned host key is no secret"
        fc = de.claude()
        mod = Mod(fc)
        pid = _flow(de, fc, KEY_FLOW)
        c = mod.dialog(lambda x: x["kind"] == "choice", timeout=30)
        show = next(k for k, v in gate_setup_choices().items() if v == "show")
        assert vault.live_keys(vault.load()["hosts"]["lab"]), "the key was made before this dialog"
        assert mod.view()["queue"] == [], "nothing offered while gate check's job goes on"
        mod.post("/ui/dialog/answer", {"id": c["id"], "button": "ok", "choice": show})
        t = mod.dialog(lambda x: x["kind"] == "text", timeout=30)
        assert not _is_offer(t)
        mod.post("/ui/dialog/answer", {"id": t["id"], "button": "ok"})
        r = fc.wait(pid, timeout=60)
        assert '"rc": 0' in r.stdout, (r.stdout[-300:], r.stderr[-400:])
        _offered_with_the_lock_free(mod)


def test_an_import_that_stores_secrets_offers_once_its_job_has_ended():
    """WS-8: an import is a credential store too (often a new machine's
    first): `gate import FILE` through its dialogs (the file's passphrase,
    the confirm) and a real gated offers right after, with the lock free."""
    import harness_ux as U
    from gateway import transfer
    fpass = "a long enough passphrase for the file"
    tmp = Path(H.tmp_base()) / f"gwoffer-import-{secrets.token_hex(4)}"
    tmp.mkdir()
    try:
        f = tmp / "accounts.age"
        with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
            U.setup(env, '[accounts.work-key]\nkind = "api-key"\nsites = ["api.example.com"]\n')
            U.set_token("work-key", "api-key", "sk-" + secrets.token_urlsafe(24))
            form, _e, data = transfer._load()
            f.write_bytes(transfer.encrypt_passphrase(json.dumps(transfer.export_content(
                form, data, {"account:work-key", "account-secrets:work-key"})).encode(), fpass))
        with D.daemon_env() as de:
            vault.save(vault.empty())
            fc = de.claude()
            mod = Mod(fc)
            drv = _driver(de)
            env = de.env.subprocess_env()
            env.pop("GATEWAY_TEST_ROOT")
            env["CLAUDE_PID"] = str(fc.pid)
            pid = fc.spawn([H.PY, "-I", "-S", drv, str(de.root), "gate", "import", str(f)], env=env)
            d = mod.dialog(lambda x: x["kind"] == "secret", timeout=30)
            mod.post("/ui/dialog/submit", seal(d, [fpass]))
            c = mod.dialog(lambda x: x["kind"] == "confirm", timeout=60)
            assert not _is_offer(c) and vault.offer_state(vault.load()) is None
            mod.post("/ui/dialog/answer", {"id": c["id"], "button": "ok"})
            r = fc.wait(pid, timeout=60)
            assert r.returncode == 0 and "gateway: imported" in r.stdout, (r.stdout[-300:],
                                                                          r.stderr[-400:])
            _offered_with_the_lock_free(mod)
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def gate_setup_choices() -> dict[str, str]:
    from gateway import gate_setup
    return dict(gate_setup.INSTALL_CHOICES)


def test_gateds_own_sign_in_store_offers_also_after_gate_check_stopped_waiting():
    """WS-8, the browser sign-in through a real gated (harness_oauth): gate
    check stops waiting (exit 75) before the person opens the browser; gated
    stores the sign-in itself and offers right after, with the vault's lock
    free."""
    import harness_oauth as HO
    from test_accounts_entra import AZB
    with HO.sso(AZB) as s:
        D.write_driver(s.de.env, s.de.run, native_dialogs=True, popup_wait=1, dialog_timeout=60,
                       gate_check_budget=1)
        pid = HO.gate(s, "check", "work-azure")
        d = s.mod.dialog(HO.is_signin, timeout=30)
        rc, out, err = HO.result(s, pid)
        assert rc == popup.EX_TEMPFAIL, (rc, out, err)
        assert vault.offer_state(vault.load()) is None
        s.mod.open(d)
        assert s.de.wait_for(lambda: (vault.load()["accounts"]["work-azure"].get("entra") or {})
                             .get("refresh_token"), 30)
        _offered_with_the_lock_free(s.mod)


def test_offered_after_a_stored_secret_once_per_session_and_not_now_is_for_good():
    with D.daemon_env() as de:
        _setup(de)
        assert vault.offer_state(vault.load()) is None, "nothing stored: nothing due"
        fc = de.claude()
        mod = Mod(fc)
        out = _sudo(de, fc, mod)
        assert out["rc"] == 0 and out["stored"], out
        assert vault.offer_state(vault.load()) == "pending"
        d = mod.dialog(_is_offer, timeout=20)
        assert d["entry"] == "vault" and d["what"] == omod.WHAT
        assert d["options"] == list(omod.OPTIONS) and d["title"] == omod.TITLE
        assert d["fields"] == 0 and "pub" not in d, "no secret goes into the offer"
        st, body = mod.post("/ui/dialog/answer", {"id": d["id"], "button": "ok", "choice": "Not now"})
        assert st == 200, body
        assert de.wait_for(lambda: vault.offer_state(vault.load()) == "declined", 20)
        assert paths.key_path().exists() and not paths.wrapped_key_path().exists(), "never forced"
        # another store, in this session and in a new one: never offered again
        _forget_local_sudo()
        assert _sudo(de, fc, mod)["stored"]
        assert _no_offer(mod)
        fc2 = de.claude(session="s-two")
        mod2 = Mod(fc2)
        _forget_local_sudo()
        assert _sudo(de, fc2, mod2)["stored"]
        assert _no_offer(mod2)
        assert vault.offer_state(vault.load()) == "declined"


def test_cancel_leaves_it_pending_for_a_later_session_but_never_twice_in_one():
    with D.daemon_env() as de:
        _setup(de)
        fc = de.claude()
        mod = Mod(fc)
        assert _sudo(de, fc, mod)["stored"]
        d = mod.dialog(_is_offer, timeout=20)
        mod.post("/ui/dialog/cancel", {"id": d["id"]})
        time.sleep(0.3)
        assert vault.offer_state(vault.load()) == "pending", "Cancel decides nothing"
        _forget_local_sudo()
        assert _sudo(de, fc, mod)["stored"]
        assert _no_offer(mod), "once per session"
        # a new session: offered after its first store
        fc2 = de.claude(session="s-two")
        mod2 = Mod(fc2)
        _forget_local_sudo()
        assert _sudo(de, fc2, mod2)["stored"]
        d2 = mod2.dialog(_is_offer, timeout=20)
        assert d2["id"] != d["id"]


def test_set_passphrase_opens_the_passphrase_dialog_and_a_wrapped_key_is_never_offered():
    with D.daemon_env() as de:
        _setup(de)
        fc = de.claude()
        mod = Mod(fc)
        assert _sudo(de, fc, mod)["stored"]
        d = mod.dialog(_is_offer, timeout=20)
        mod.post("/ui/dialog/answer", {"id": d["id"], "button": "ok", "choice": "Set passphrase"})
        p = mod.dialog(lambda x: x["kind"] == "passphrase", timeout=20)
        assert p["entry"] == "vault" and p["fields"] == 2
        mod.post("/ui/dialog/submit", seal(p, [PASS, PASS]))
        assert de.wait_for(lambda: de.health()["vault"] == "unlocked", 30)
        assert not paths.key_path().exists() and paths.wrapped_key_path().exists()
        assert D.full_vault(PASS).get("passphrase_offer") == "pending"
        # wrapped: nothing more to offer, in any session
        fc2 = de.claude(session="s-two")
        assert _offer_from(de, fc2) == "wrapped"
        assert _no_offer(Mod(fc2))


def test_a_program_below_the_session_asks_at_once_and_a_headless_session_gets_nothing():
    """The agent-plane path (gate check after gated stored a browser sign-in):
    a program below the session asks gated directly. Nothing stored: nothing
    is due. A session without a drawing surface (claude -p): never offered,
    and it stays pending."""
    with D.daemon_env() as de:
        _setup(de)
        fc = de.claude()
        mod = Mod(fc)
        assert _offer_from(de, fc) == "nothing_stored"
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), canary())
        assert vault.offer_state(vault.load()) == "pending"
        hl = de.claude(surface=None, session="s-print")
        assert _offer_from(de, hl) == "print"
        assert mod.view()["dialog"] is None
        assert _offer_from(de, fc) == "offered"
        d = mod.dialog(_is_offer)
        assert _offer_from(de, fc) == "already_offered"
        v = mod.view()
        assert v["dialog"]["id"] == d["id"] and v["queue"] == [], "one offer per session"
        assert vault.offer_state(vault.load()) == "pending"


def test_the_helper_offers_only_after_its_job_with_its_lease():
    """A store inside popup's detached helper defers the offer to the end of
    its job (its own dialogs first, every vault write done), where it goes to
    gated on the lease plane (the helper runs outside the session's process
    tree): the offer opens only after the store's own dialog closed."""
    with D.daemon_env() as de:
        _setup(de)
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), canary())
        fc = de.claude()
        mod = Mod(fc)
        drv = _driver(de)
        v = canary("tok")
        env = de.env.subprocess_env()
        env.pop("GATEWAY_TEST_ROOT")
        env["CLAUDE_PID"] = str(fc.pid)
        env["GW_ASK"] = json.dumps({"entry": "build", "what": "token", "ok": [sha16(v)],
                                    "store": str(de.root / "stored.sha")})
        pid = fc.spawn([H.PY, "-I", "-S", drv, str(de.root), "gate", "status"], env=env)
        d = mod.dialog(lambda x: x["kind"] == "secret")
        assert mod.view()["queue"] == [], "nothing offered before the store"
        mod.post("/ui/dialog/submit", seal(d, [v]))
        r = fc.wait(pid, timeout=60)
        assert '"outcome": "ok"' in r.stdout, r.stdout[-300:]
        o = mod.dialog(_is_offer, timeout=20)
        assert o["entry"] == "vault"


# ---------------------------------------------------------------------------
# In this process
# ---------------------------------------------------------------------------


def test_the_offer_is_due_only_with_a_secret_and_a_key_without_a_passphrase():
    with H.gateway_env() as env:
        vault.save(vault.empty())
        assert vault.offer_state(vault.load()) is None
        with vault.edit() as d:
            d["hosts"]["x"] = {"keys": [], "sudo": {}}
        assert vault.offer_state(vault.load()) is None, "no secret"
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", "me", canary())
        data = vault.load()
        assert vault.offer_state(data) == "pending"
        vault.decline_offer(data)
        vault.save(data)
        assert vault.offer_state(vault.load()) == "declined", "a save never undoes Not now"
        # a key with a passphrase: never marked due
        data = vault.empty()
        vault.set_sudo(data, "localhost", "me", canary())
        paths.wrapped_key_path().write_text("x")
        try:
            vault.note_offer(data)
            assert vault.offer_state(data) is None
        finally:
            paths.wrapped_key_path().unlink()
        assert vault.offer_state({"passphrase_offer": "maybe"}) is None
        assert "passphrase_offer" not in vault.export_view(vault.load()), "never exported"
        # the first 0.11 session's notice: recorded once
        data = vault.load()
        assert not vault.notice_shown(data, vault.POSTURE_NOTICE)
        vault.mark_notice(data, vault.POSTURE_NOTICE)
        assert vault.notice_shown(data, vault.POSTURE_NOTICE)


def test_not_now_never_waits_forever_for_the_vaults_lock():
    """gated records Not now under the vault's lock, waiting LOCK_WAIT at
    most: a program holding the lock can't hang gated's worker."""
    with H.gateway_env() as env:
        vault.save(vault.empty())
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", "me", canary())
        old = omod.LOCK_WAIT
        omod.LOCK_WAIT = 0.3
        try:
            import threading
            paths.ensure_private()
            with open(paths.lock_path(), "a+") as f:
                fcntl.flock(f, fcntl.LOCK_EX)
                got: list[Any] = []
                th = threading.Thread(target=lambda: got.append(
                    omod.Offers(None)._answer(None, [omod.LATER])), daemon=True)
                th.start()
                th.join(5)
                held = th.is_alive()
                fcntl.flock(f, fcntl.LOCK_UN)       # (a waiting worker finishes now)
                th.join(30)
                assert not held, "gated's worker waited for the vault's lock with no end"
                ok, why = got[0]
                assert ok is False and "couldn't be recorded" in why
            ok, _why = omod.Offers(None)._answer(None, [omod.LATER])
            assert ok and vault.offer_state(vault.load()) == "declined"
            assert omod.Offers(None)._answer(None, ["Delete everything"])[0] is False
        finally:
            omod.LOCK_WAIT = old


def test_offer_passphrase_asks_gated_only_with_native_dialogs_and_defers_in_the_helper():
    calls: list[tuple[str, Any]] = []
    from gateway.daemon import client
    real = client.call

    def fake_call(method: str, path: str, body: Any = None, **kw: Any) -> dict[str, Any]:
        calls.append((path, body))
        return {"ok": True, "offered": True}
    with H.gateway_env() as env:
        env.o.dialog = None
        client.call = fake_call
        try:
            # a test's fake dialog (or none): never offered
            env.o.extra["native_dialogs"] = False
            assert popup.offer_passphrase() == "unavailable" and calls == []
            env.o.extra["native_dialogs"] = True
            assert popup.offer_passphrase() == "offered"
            assert calls == [("/agent/vault/offer", {})]
            calls.clear()
            # inside the helper (direct mode): deferred to the end of its job, with its lease
            popup._MODE = "direct"
            from gateway import dialog
            dialog.set_lease("a" * 64)
            try:
                assert popup.offer_passphrase() == "deferred" and calls == []
                popup._offer_if_due()
                assert calls == [("/lease/vault/offer", {"lease": "a" * 64})]
                popup._offer_if_due()
                assert len(calls) == 1, "once per store"
            finally:
                popup._MODE = "broker"
                popup._OFFER_DUE = False
                dialog.set_lease(None)
        finally:
            client.call = real


def test_gate_checks_stores_offer_the_passphrase():
    """gate check's stores outside popup.secret (a pasted token, a generated
    SSH key, a pijul key, gated's browser sign-in) each make the offer, once
    their vault write is done; nothing stored, no offer."""
    import io
    import contextlib
    from gateway import entra, gate_setup
    calls: list[str] = []
    real = popup.offer_passphrase
    popup.offer_passphrase = lambda: calls.append("offer") or "deferred"
    try:
        with H.gateway_env() as env:
            env.write_form('[hosts.lab]\naddress = "u@lab.example.com"\n'
                           '[accounts.az]\nkind = "azure"\ntenant = "contoso.onmicrosoft.com"\n'
                           'client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"\nsign_in = "browser"\n')
            vault.save(vault.empty())
            consent.approve_all(env.form())
            gate_setup._store_token("gh", "github", "ghp_" + "a1" * 18, "pasted")
            assert calls == ["offer"]
            gate_setup._ensure_key("lab")
            assert calls == ["offer"] * 2, "a key made"
            gate_setup._ensure_key("lab")
            assert calls == ["offer"] * 2, "a key there already: nothing stored"
            rs, rw = entra.signin_start, entra.signin_wait
            entra.signin_start = lambda name: {"available": True, "lease": "a" * 64}
            entra.signin_wait = lambda lease, wait: {"state": "done", "outcome": "ok"}
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    assert gate_setup._browser_signin("az", "az--setup", "d") == 0
            finally:
                entra.signin_start, entra.signin_wait = rs, rw
            assert calls == ["offer"] * 3, "gated stored the sign-in"
    finally:
        popup.offer_passphrase = real


def test_gated_offers_after_its_own_sign_in_store_with_the_vaults_lock_free():
    """PLAN-0.11 §8 lists the SSO store (WS-6 review should-fix 1): gated
    offers right after it stores a browser sign-in, to the session that
    asked, with the vault's lock released (set_passphrase takes it), so the
    offer comes also when the gate check that asked stopped waiting (exit
    75). A failed sign-in stores nothing and offers nothing; an offer that
    fails never changes the sign-in's outcome."""
    from types import SimpleNamespace
    from gateway.daemon import oauth
    import test_accounts_entra as TE
    q = {"state": [TE.STATE], "code": ["CODE-1"]}
    for broken in (False, True):
        with TE._signins() as t, TE._exchange():
            offered: list[tuple[Any, bool]] = []

            def offer(session: Any) -> dict[str, Any]:
                try:
                    with vault.locked(timeout=0.2):
                        free = True
                except vault.VaultError:
                    free = False
                offered.append((session, free))
                if broken:
                    raise RuntimeError("the offer failed")
                return {"ok": True, "offered": True}
            t.d.offers = SimpleNamespace(offer=offer)
            si = TE._past_open(t)
            assert t.sis._callback(si, q) == (200, oauth.PAGE_OK)
            assert si.outcome == "ok" and TE._stored().startswith("UNIT-REFRESH-")
            assert offered == [(si.session, True)], offered
    with TE._signins() as t, TE._exchange():
        offered = []
        t.d.offers = SimpleNamespace(offer=lambda s: offered.append(s))
        si = TE._past_open(t)
        st, _page = t.sis._callback(si, {"state": [TE.STATE], "error": ["access_denied"]})
        assert si.outcome == "declined" and offered == [], (si.outcome, offered)


def test_only_gateds_own_choice_carries_the_offer_marker():
    import shutil
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="gwoffer-", dir=H.tmp_base()))
    try:
        d = _Daemon()
        s = _Sess(os.getpid())
        d.registry.s[s.pid] = s
        dl = dmod.Dialogs(d, tmp / "dialogs.json")
        r = dl.lease(s, os.getpid())
        o = dl.open(r["lease"], os.getpid(), {"kind": "choice", "entry": "vault", "options": ["a"],
                                              "offer": "passphrase", "lines": ["x"]})
        assert "offer" not in dl.view(s)["dialog"], "a program's dialog can't wear the template"
        dl.close(r["lease"], os.getpid(), o["id"], "cancelled")
        got: list[Any] = []
        o2 = dl.open_owned(s, {"entry": "vault", "options": list(omod.OPTIONS), "offer": "passphrase",
                               "lines": ["x"]}, lambda req, vals: (got.append(list(vals)) or True, "ok"),
                           kind="choice")
        v = dl.view(s)["dialog"]
        assert v["id"] == o2["id"] and v["offer"] == "passphrase"
        # an option that isn't one is refused; the pick reaches the handler
        try:
            dl.answer(s, {"id": v["id"], "button": "ok", "choice": "Delete everything"})
            raise AssertionError("an unknown option was taken")
        except dmod.DialogError as e:
            assert e.status == 400
        dl.answer(s, {"id": v["id"], "button": "ok", "choice": "Not now"})
        end = time.time() + 5
        while (not got or dl.view(s)["dialog"] is not None) and time.time() < end:
            time.sleep(0.02)
        assert got == [["Not now"]], got
        # an owned confirm still can't carry it
        dl.open_owned(s, {"entry": "vault", "offer": "passphrase", "lines": ["x"]},
                      lambda req, vals: (True, "ok"), kind="confirm")
        assert "offer" not in dl.view(s)["dialog"]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_a_lease_proves_only_its_own_session_and_an_offer_that_didnt_open_comes_again():
    """WS-6 review R7, R9: popup's helper proves its session with its dialog
    lease, and a session registered later under the same pid (another start
    time) isn't that session, so the offer goes nowhere. An offer whose
    dialog didn't open (unavailable, or opening failed) doesn't count as
    made: the next store offers again, once."""
    import shutil
    import tempfile
    from types import SimpleNamespace
    tmp = Path(tempfile.mkdtemp(prefix="gwoffer-", dir=H.tmp_base()))
    try:
        d = _Daemon()
        s = _Sess(os.getpid())
        d.registry.s[s.pid] = s
        dl = dmod.Dialogs(d, tmp / "dialogs.json")
        r = dl.lease(s, os.getpid())
        assert dl.lease_session(r["lease"], os.getpid()) is s
        later = _Sess(os.getpid(), sid="s-2")
        later.start = (s.start or 0.0) + 7.0
        d.registry.s[s.pid] = later
        assert dl.lease_session(r["lease"], os.getpid()) is None, "another session, the same pid"
        d.registry.s[s.pid] = s
        d.dialogs = dl
        d.broker = SimpleNamespace(mode=lambda: "unwrapped",
                                   read=lambda touch=True: {"passphrase_offer": vault.OFFER_PENDING})
        o = omod.Offers(d)
        real = dl.open_owned

        def boom(*_a: Any, **_k: Any) -> dict[str, Any]:
            raise RuntimeError("the dialog couldn't open")
        for fail in (lambda *_a, **_k: {"ok": True, "available": False, "reason": "busy"}, boom):
            dl.open_owned = fail
            got = o.offer(s)
            assert got["offered"] is False and got["reason"] != "already_offered", got
        dl.open_owned = real
        got = o.offer(s)
        assert got["offered"] is True and dl.view(s)["dialog"]["offer"] == "passphrase", got
        assert o.offer(s)["reason"] == "already_offered"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_the_mods_template_is_gateds_text_and_options():
    ts = (H.PLUGIN / "hooks" / "mod" / "dialog.ts").read_text()

    def const(name: str) -> str:
        m = re.search(rf"export const {name}(?:: [^=]+)? = (.+?)\n(?:export |//|$)", ts, re.S)
        assert m, name
        return m.group(1).strip()
    assert json.loads(const("OFFER_TITLE").replace("'", '"')) == omod.TITLE
    assert const("OFFER_WHAT") == f"'{omod.WHAT}'"
    opts = re.findall(r"'([^']*)'", const("OFFER_OPTIONS"))
    assert tuple(opts) == omod.OPTIONS
    lines = re.findall(r"'([^']*)'|\"([^\"]*)\"", const("OFFER_LINES"))
    assert tuple(a or b for a, b in lines) == omod.LINES


# ---------------------------------------------------------------------------
# The remote sudo dialog's "Remember it" starts unticked (27g)
# ---------------------------------------------------------------------------


def test_the_remote_sudo_dialog_offers_remember_it_unticked():
    from gateway import ssh, ssh_sudo
    assert ssh_sudo.REMEMBER_DEFAULT is False
    seen: dict[str, Any] = {}

    def fake_ask(name: str, what: str, prompt: str, **kw: Any) -> str:
        seen.update(kw, prompt=prompt)
        return "a-long-enough-password"
    from gateway import ssh_conf
    from gateway import form as formmod
    real = ssh._ask_secret
    ssh._ask_secret = fake_ask
    try:
        with H.gateway_env():
            st = ssh.State.__new__(ssh.State)
            st.data = vault.empty()
            link = ssh_conf.Link(name="box", addr=formmod.parse_address("u@box.example.com"),
                                 host_keys=[], pubkeys=[])
            conn = type("C", (), {"target": link})()
            pw, fresh, _upd = ssh._sudo_password("box", "u", st, conn)
    finally:
        ssh._ask_secret = real
    assert fresh and pw == "a-long-enough-password"
    assert seen["remember"] is False, "unticked: used for this call, stored only when ticked"
    assert "Tick Remember it" in seen["prompt"], seen["prompt"]
