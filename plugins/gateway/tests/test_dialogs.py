"""Native dialogs (PLAN-v4 phase 3): gated's dialog store, the sealed-box
intake, the lease plane, the one-at-a-time queue, cleanup on every exit path,
the request recheck, pause, the clipboard override, restart survival, the
vault's own dialogs and the unavailable surfaces.

Two layers: the Dialogs class in this process (a stub daemon: exact checks of
what is kept and dropped), and a real gated in a test root reached over its
socket, where a FakeClaude plays the gate mod (the UI plane) and the requester
is a gateway entry point below it (harness_daemon's driver with GW_ASK, which
prints only a sha256 prefix of what arrived). The Client's sealing is done
here with PyNaCl's Box, byte-compatible with the vendored TweetNaCl box the
mod uses (hooks/mod/seal.ts; hooks/mod/dialog.test.ts checks the mod's side).

Canaries are generated here and never printed: assertion messages carry
lengths and hashes only.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import signal
import threading
import time
from pathlib import Path
from typing import Any

import contextlib
import shutil
import tempfile

import harness as H
import harness_daemon as D
from gateway import consent, paths, vault
from gateway.daemon import clipboard
from gateway.daemon import dialogs as dmod

PASS = "a vault passphrase for the dialog tests"


@contextlib.contextmanager
def tempdir():
    d = Path(tempfile.mkdtemp(prefix="gwdlg-", dir=H.tmp_base()))
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)


def canary(prefix: str = "cv") -> str:
    return f"{prefix}-{secrets.token_urlsafe(18)}"


def sha16(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()[:16]


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def seal(view: dict[str, Any], values: list[str], *, rid: str | None = None,
         attempt: int | None = None, pub: str | None = None) -> dict[str, Any]:
    """What the Client posts: NaCl box of {rid, a, v} to the dialog's key under
    a fresh ephemeral key (no value in the clear)."""
    from nacl import public
    eph = public.PrivateKey.generate()
    box = public.Box(eph, public.PublicKey(base64.b64decode(pub or view["pub"])))
    nonce = os.urandom(24)
    plain = json.dumps({"rid": rid or view["id"], "a": attempt or view["attempt"],
                        "v": values}).encode()
    ct = box.encrypt(plain, nonce).ciphertext
    return {"id": view["id"], "attempt": attempt or view["attempt"],
            "epk": b64(bytes(eph.public_key)), "nonce": b64(nonce), "box": b64(ct)}


# ---------------------------------------------------------------------------
# The store in this process (a stub daemon)
# ---------------------------------------------------------------------------


class _Sess:
    def __init__(self, pid: int, *, ui: bool = True, surfaces: list[str] | None = None,
                 sid: str = "s-1"):
        from gateway.daemon import peers
        self.pid, self.start, self.session_id, self.ui = pid, peers.started(pid), sid, ui
        self.surfaces = ["terminal"] if surfaces is None else surfaces
        self.surface = self.surfaces[0] if self.surfaces else ""


class _Reg:
    def __init__(self) -> None:
        self.s: dict[int, _Sess] = {}

    def live(self, pid: int) -> _Sess | None:
        return self.s.get(pid)


class _Daemon:
    def __init__(self) -> None:
        self.registry = _Reg()
        self.events_seen: list[tuple[str, dict]] = []
        self.events = self
        self.eff = None

    def emit(self, kind: str, **kw: Any) -> None:
        self.events_seen.append((kind, kw))

    def effective(self) -> Any:
        return self.eff


def _store(tmp: Path, **sess: Any) -> tuple[dmod.Dialogs, _Daemon, _Sess]:
    d = _Daemon()
    s = _Sess(os.getpid(), **sess)
    d.registry.s[s.pid] = s
    return dmod.Dialogs(d, tmp / "dialogs.json"), d, s


def _open(dl: dmod.Dialogs, s: _Sess, **spec: Any) -> tuple[str, str]:
    r = dl.lease(s, os.getpid())
    assert r["available"], r
    o = dl.open(r["lease"], os.getpid(), {"kind": "secret", "entry": "build",
                                          "what": "sudo password", "lines": ["x"], **spec})
    assert o["available"], o
    return r["lease"], o["id"]


def test_store_a_sealed_value_reaches_the_owner_once_and_nothing_is_kept():
    with tempdir() as tmp:
        dl, d, s = _store(tmp)
        lease, rid = _open(dl, s)
        view = dl.view(s)["dialog"]
        assert view["id"] == rid and view["fields"] == 1 and len(base64.b64decode(view["pub"])) == 32
        v = canary()
        assert dl.submit(s, seal(view, [v]))["state"] == "checking"
        r = dl.requests[rid]
        assert r.key is None, "the key pair goes once a value arrived"
        disk = (tmp / "dialogs.json").read_text()
        assert v not in disk and b64(v.encode()) not in disk, "the waiting answer is never on disk"
        got = dl.wait(lease, os.getpid(), rid, 0)
        assert got["state"] == "answered" and sha16(got["answer"]["values"][0]) == sha16(v)
        assert r.answer is None, "handed over once, then dropped"
        assert dl.wait(lease, os.getpid(), rid, 0)["state"] == "checking"   # never twice
        dl.close(lease, os.getpid(), rid, "ok", "supplied")
        assert rid not in dl.requests and r.key is None and r.answer is None
        assert ("auth.supplied", {"request": rid, "outcome": "ok"}) in d.events_seen
        # nothing about the value on disk or in events
        text = (tmp / "dialogs.json").read_text() + json.dumps(d.events_seen)
        assert v not in text and b64(v.encode()) not in text and v.encode().hex() not in text


def test_store_takes_sealed_values_only():
    with tempdir() as tmp:
        dl, _d, s = _store(tmp)
        lease, rid = _open(dl, s)
        v = canary()
        for body in ({"id": rid, "value": v}, {"id": rid, "values": [v]},
                     {"id": rid, "value": v, **seal(dl.view(s)["dialog"], ["other"])}):
            try:
                dl.submit(s, body)
                raise AssertionError("a plaintext value was accepted")
            except dmod.DialogError as e:
                assert e.code == "plaintext", e.code
        assert dl.requests[rid].state == "open" and dl.requests[rid].answer is None


def test_store_refuses_a_box_for_another_dialog_attempt_or_key():
    with tempdir() as tmp:
        dl, _d, s = _store(tmp)
        lease, rid = _open(dl, s)
        _l2, rid2 = _open(dl, s, entry="other")
        view = dl.view(s)["dialog"]
        other = dl.requests[rid2]
        bad = [seal(view, ["x"], rid=rid2),                         # names another dialog
               seal(view, ["x"], attempt=2) | {"attempt": 1},        # another attempt inside
               seal(view, ["x"], pub=b64(bytes(other.key.public_key))),   # another dialog's key
               seal(view, ["x", "y"])]                               # two fields for one
        tampered = seal(view, ["x"])
        raw = bytearray(base64.b64decode(tampered["box"]))
        raw[-1] ^= 1
        bad.append(tampered | {"box": b64(bytes(raw))})
        for body in bad:
            try:
                dl.submit(s, body)
                raise AssertionError("a bad box was accepted")
            except dmod.DialogError as e:
                assert e.code == "box", e.code
        r = dl.requests[rid]
        assert r.state == "open" and r.attempt == 1 and r.answer is None
        assert "intact" in r.error


def test_store_one_dialog_at_a_time_and_the_queue_shows_who_waits():
    with tempdir() as tmp:
        dl, _d, s = _store(tmp)
        l1, r1 = _open(dl, s, entry="build", what="sudo password")
        l2, r2 = _open(dl, s, entry="gh-work", what="token")
        v = dl.view(s)
        assert v["dialog"]["id"] == r1 and v["queue"] == [
            {"id": r2, "kind": "secret", "entry": "gh-work", "what": "token"}]
        dl.cancel(s, {"id": r1})
        v = dl.view(s)
        assert v["dialog"]["id"] == r2 and v["queue"] == []
        assert dl.wait(l1, os.getpid(), r1, 0)["outcome"] == "cancelled"


def test_store_every_exit_path_drops_the_key_and_the_answer():
    def check(dl: dmod.Dialogs, rid: str, outcome: str) -> None:
        assert rid not in dl.requests, outcome
        r = dl._done[rid]
        assert r.key is None and r.answer is None and r.outcome == outcome, (r.outcome, outcome)

    with tempdir() as tmp:
        dl, d, s = _store(tmp)
        # cancel (the person)
        _l, rid = _open(dl, s)
        dl.cancel(s, {"id": rid})
        check(dl, rid, "cancelled")
        # timeout, with an answer waiting that was never handed over
        _l, rid = _open(dl, s, timeout=5)
        dl.submit(s, seal(dl.view(s)["dialog"], [canary()]))
        dl.requests[rid].deadline = time.time() - 1
        dl.tick()
        check(dl, rid, "timeout")
        # the requester's failure after three tries
        lease, rid = _open(dl, s)
        for i in range(dmod.MAX_TRIES):
            dl.submit(s, seal(dl.view(s)["dialog"], [canary()]))
            dl.wait(lease, os.getpid(), rid, 0)
            dl.retry(lease, os.getpid(), rid, "wrong")
        check(dl, rid, "failed")
        # the session ended
        _l, rid = _open(dl, s)
        dl.submit(s, seal(dl.view(s)["dialog"], [canary()]))
        sess = d.registry.s.pop(s.pid)
        dl.tick()
        check(dl, rid, "cancelled")
        d.registry.s[s.pid] = sess
        # the lease released (the helper finished) and expired
        lease, rid = _open(dl, s)
        dl.release(lease, os.getpid())
        check(dl, rid, "cancelled")
        lease, rid = _open(dl, s)
        dl.leases[dmod._hash(lease)].expires = time.time() - 1
        dl.tick()
        check(dl, rid, "cancelled")
        # the pause
        _l, rid = _open(dl, s)
        dl.pause(s.session_id)
        check(dl, rid, "paused")


def test_store_rechecks_the_request_before_the_value_is_used():
    with tempdir() as tmp:
        dl, d, s = _store(tmp)
        # the program that asked is gone: its pid recorded on the lease is dead
        lease, rid = _open(dl, s)
        le = dl.leases[dmod._hash(lease)]
        le.pids = {2 ** 22 + 7: 1.0}                    # nobody alive
        out = dl.submit(s, seal(dl.view(s)["dialog"], [canary()]))
        assert out["ok"] is False and out["error"] == "cancelled"
        assert dl._done[rid].answer is None
        # paused before the answer: refused, not delivered
        lease, rid = _open(dl, s)
        dl.paused.add(s.session_id)
        out = dl.submit(s, seal(dl.view(s)["dialog"], [canary()]))
        assert out["error"] == "paused" and dl._done[rid].answer is None
        dl.paused.clear()
        # timed out just before the answer
        lease, rid = _open(dl, s)
        dl.requests[rid].deadline = time.time() - 0.5
        out = dl.submit(s, seal(dl.view(s)["dialog"], [canary()]))
        assert out["error"] == "timeout"


def test_store_rechecks_the_form_entry(tmp: Path | None = None):
    with H.gateway_env() as env:
        env.write_form('[hosts.build]\naddress = "build.example.org"\nsudo = true\n')
        consent.approve_all(env.form())
        dl, d, s = _store(env.root)
        check = {"section": "hosts", "entry": "build", "right": "sudo"}
        lease, rid = _open(dl, s, check=check)
        env.write_form('[hosts.build]\naddress = "build.example.org"\nsudo = false\n')
        out = dl.submit(s, seal(dl.view(s)["dialog"], [canary()]))
        assert out["error"] == "failed" and "sudo right is off" in dl._done[rid].note
        env.write_form('[hosts.other]\naddress = "o.example.org"\n')
        lease, rid = _open(dl, s, check=check)
        out = dl.submit(s, seal(dl.view(s)["dialog"], [canary()]))
        assert out["error"] == "failed" and "isn't a host" in dl._done[rid].note
        env.write_form('[accounts.gh-work]\nkind = "huggingface"\n')
        lease, rid = _open(dl, s, check={"section": "accounts", "entry": "gh-work", "kind": "github"})
        out = dl.submit(s, seal(dl.view(s)["dialog"], [canary()]))
        assert out["error"] == "failed" and "not github" in dl._done[rid].note
        # several rights (a remote sudo runs over ssh): each one is rechecked
        both = {"section": "hosts", "entry": "build", "right": ["ssh", "sudo"]}
        env.write_form('[hosts.build]\naddress = "build.example.org"\nsudo = true\n')
        consent.approve_all(env.form())
        lease, rid = _open(dl, s, check=both)
        assert dl.submit(s, seal(dl.view(s)["dialog"], [canary()]))["state"] == "checking"
        dl.close(lease, os.getpid(), rid, "ok")
        env.write_form('[hosts.build]\naddress = "build.example.org"\nsudo = true\nssh = false\n')
        lease, rid = _open(dl, s, check=both)
        out = dl.submit(s, seal(dl.view(s)["dialog"], [canary()]))
        assert out["error"] == "failed" and "ssh right is off" in dl._done[rid].note
        env.write_form('[hosts.build]\naddress = "build.example.org"\nsudo = false\n')
        lease, rid = _open(dl, s, check=both)
        out = dl.submit(s, seal(dl.view(s)["dialog"], [canary()]))
        assert out["error"] == "failed" and "sudo right is off" in dl._done[rid].note


def test_store_remember_is_the_persons_choice_or_the_dialogs_default():
    """"Remember it" (offered where storing is optional): the post's choice
    when it carries one, the dialog's own default (ticked) when it doesn't;
    a dialog that offers no choice hands over none."""
    with tempdir() as tmp:
        dl, _d, s = _store(tmp)
        got = []
        for offered, sent in ((True, False), (True, None), (True, True), (None, False)):
            lease, rid = _open(dl, s, remember=offered)
            body = seal(dl.view(s)["dialog"], [canary()])
            if sent is not None:
                body["remember"] = sent
            assert dl.submit(s, body)["state"] == "checking"
            got.append(dl.wait(lease, os.getpid(), rid, 0)["answer"]["remember"])
            dl.close(lease, os.getpid(), rid, "ok")
        assert got == [False, True, True, None], got


def test_store_unavailable_surfaces_get_no_lease():
    with tempdir() as tmp:
        cases = [(dict(surfaces=[]), "print"), (dict(surfaces=["mobile"]), "mobile"),
                 (dict(surfaces=["vscode"]), "vscode"), (dict(ui=False), "no_mod")]
        for kw, why in cases:
            dl, _d, s = _store(tmp, **kw)
            r = dl.lease(s, os.getpid())
            assert r["available"] is False and r["reason"] == why and "lease" not in r, (kw, r)
            assert "unavailable" in r["message"] or "can't" in r["message"] or "no gateway" \
                in r["message"], r["message"]
        for surfaces in (["terminal"], ["desktop"], ["terminal", "mobile"]):
            dl, _d, s = _store(tmp, surfaces=surfaces)
            assert dl.lease(s, os.getpid())["available"], surfaces
        dl, _d, s = _store(tmp)
        assert dl.lease(None, os.getpid())["reason"] == "no_session"


def test_store_two_passphrase_fields_must_match_and_paste_is_one_field_only():
    with tempdir() as tmp:
        dl, _d, s = _store(tmp)
        r = dl.open_vault(s, "passphrase", {"title": "t", "entry": "vault", "lines": ["x"]})
        rid = r["id"]
        seen: list[list[str]] = []
        dl.handlers["passphrase"] = lambda req, vals: (seen.append(list(vals)) or True, "done")
        view = dl.view(s)["dialog"]
        assert view["fields"] == 2 and view["paste"] is False
        dl.submit(s, seal(view, ["one passphrase here", "another passphrase"]))
        assert dl.requests[rid].attempt == 2 and "differ" in dl.requests[rid].error and not seen
        try:
            dl.paste(s, {"id": rid})
            raise AssertionError("paste into a two-field dialog")
        except dmod.DialogError as e:
            assert e.code == "stale"
        same = "the same passphrase twice"
        dl.submit(s, seal(dl.view(s)["dialog"], [same, same]))
        for _ in range(100):
            if rid not in dl.requests:
                break
            time.sleep(0.02)
        assert seen and sha16(seen[0][0]) == sha16(same) and dl._done[rid].outcome == "ok"


def test_store_survives_a_restart_with_new_keys_and_no_secrets_on_disk():
    with tempdir() as tmp:
        dl, d, s = _store(tmp)
        lease, rid = _open(dl, s)
        old_pub = dl.view(s)["dialog"]["pub"]
        disk = (tmp / "dialogs.json").read_text()
        sk = bytes(dl.requests[rid].key)
        assert lease not in disk and old_pub not in disk and "PrivateKey" not in disk
        assert sk.hex() not in disk and b64(sk) not in disk, "the private key never touches disk"
        dl2 = dmod.Dialogs(d, tmp / "dialogs.json")
        v2 = dl2.view(s)["dialog"]
        assert v2["id"] == rid and v2["pub"] != old_pub
        # a box sealed to the old key is refused; to the new one it arrives
        try:
            dl2.submit(s, seal(v2, ["x"], pub=old_pub))
            raise AssertionError("an old-key box was accepted")
        except dmod.DialogError as e:
            assert e.code == "box"
        val = canary()
        dl2.submit(s, seal(v2, [val]))
        got = dl2.wait(lease, os.getpid(), rid, 0)
        assert sha16(got["answer"]["values"][0]) == sha16(val)


def test_store_a_lease_token_is_needed_and_dialogs_belong_to_their_lease():
    with tempdir() as tmp:
        dl, _d, s = _store(tmp)
        lease, rid = _open(dl, s)
        other = dl.lease(s, os.getpid())["lease"]
        for tok in ("", "0" * 64, "x" * 64, other):
            try:
                dl.wait(tok, os.getpid(), rid, 0)
                raise AssertionError("a wrong lease reached the dialog")
            except dmod.DialogError as e:
                assert e.code in ("lease", "no_dialog"), e.code


# ---------------------------------------------------------------------------
# The clipboard
# ---------------------------------------------------------------------------


def test_clipboard_accepts_one_line_of_text_only():
    assert clipboard.accept(b"tok\n") == "tok" and clipboard.accept(b"tok\r\n") == "tok"
    for raw, why in ((b"", "empty"), (b"\n", "empty"), (b"a\nb", "more than one line"),
                     (b"a\x07b", "control"), (b"\xff\xfe", "text"),
                     (b"x" * (clipboard.MAX_BYTES + 1), "more than")):
        try:
            clipboard.accept(raw)
            raise AssertionError(raw[:8])
        except clipboard.ClipboardError as e:
            assert why in str(e), (why, str(e))


def test_clipboard_under_a_test_override_reads_only_the_fake():
    real = clipboard.command

    def never(*a, **k):                  # the production reader must not even be chosen
        raise AssertionError("the real clipboard command was chosen under a test override")
    clipboard.command = never
    try:
        with H.gateway_env() as env:
            for knob in (None, "fake-clip", ""):
                env.o.extra["clipboard"] = knob
                try:
                    clipboard.read({})
                    raise AssertionError("read a clipboard without an absolute fake")
                except clipboard.ClipboardError as e:
                    assert "test override" in str(e), (knob, str(e))
    finally:
        clipboard.command = real
    with tempdir() as tmp:
        v = canary("clip")
        prog = tmp / "fake-clip"
        (tmp / "clip.txt").write_text(v)
        prog.write_text(f"#!/bin/sh\nexec /bin/cat {tmp / 'clip.txt'}\n")
        os.chmod(prog, 0o755)
        with H.gateway_env(clipboard=str(prog)):
            assert sha16(clipboard.read({})) == sha16(v)


def test_clipboard_commands_are_fixed_absolute_paths_and_env_is_checked():
    env = clipboard.clean_env({"DISPLAY": ":0", "WAYLAND_DISPLAY": "wayland-0",
                               "XAUTHORITY": "/home/u/.Xauthority", "XDG_RUNTIME_DIR": "/run/user/1",
                               "LD_PRELOAD": "/tmp/x.so", "PATH": "/tmp"})
    assert set(env) == {"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR"}
    assert clipboard.clean_env({"DISPLAY": ":0;rm -rf /"}) == {}
    if os.path.exists("/usr/bin/pbpaste"):
        argv, child = clipboard.command({}, "darwin")
        assert argv[0] == "/usr/bin/pbpaste" and set(child) <= {"PATH", "LANG", "HOME"}
    try:
        clipboard.command({}, "linux")
        raise AssertionError("a Linux clipboard without a display")
    except clipboard.ClipboardError as e:
        assert "no display" in str(e)
    # a program found on PATH is never used: only the fixed folders, and only a
    # file root owns that nobody else may change
    assert all(d.startswith("/") for d in clipboard.LINUX_DIRS)
    with tempdir() as tmp:
        mine = tmp / "xclip"
        mine.write_text("#!/bin/sh\necho planted\n")
        os.chmod(mine, 0o755)
        assert clipboard._find("xclip", (str(tmp),)) is None, "a file of this user's isn't trusted"
        assert not clipboard._trusted(str(mine))


# ---------------------------------------------------------------------------
# A real gated: the mod (FakeClaude) and a requester below it
# ---------------------------------------------------------------------------


class Mod:
    """The gate mod's side of the UI plane, played by a FakeClaude."""

    def __init__(self, fc: D.FakeClaude):
        self.fc = fc
        self.sent: list[str] = []          # every body the "mod" sent, as text

    def view(self) -> dict[str, Any]:
        st, body = self.fc.http("GET", "/ui/dialog/next?rev=0&wait=0")
        assert st == 200, body
        return body

    def dialog(self, pred: Any = None, timeout: float = 20) -> dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            d = self.view().get("dialog")
            if d and d.get("state") == "open" and (pred is None or pred(d)):
                return d
            time.sleep(0.05)
        raise AssertionError(f"no dialog (last view: {json.dumps(self.view())[:400]})")

    def post(self, path: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
        self.sent.append(json.dumps(body))
        return self.fc.http("POST", path, body)


def _driver(de: D.DaemonEnv, **knobs: Any) -> str:
    kw = {"native_dialogs": True, "popup_wait": 60, "dialog_timeout": 60, **knobs}
    return str(D.write_driver(de.env, de.run, **kw))


def _ask(de: D.DaemonEnv, fc: D.FakeClaude, drv: str, spec: dict[str, Any]) -> int:
    env = de.env.subprocess_env()
    env.pop("GATEWAY_TEST_ROOT")
    env["CLAUDE_PID"] = str(fc.pid)
    env["GW_ASK"] = json.dumps(spec)
    return fc.spawn([H.PY, "-I", "-S", drv, str(de.root), "gate", "status"], env=env)


def _result(fc: D.FakeClaude, pid: int, timeout: float = 60) -> dict[str, Any]:
    r = fc.wait(pid, timeout=timeout)
    lines = [ln for ln in r.stdout.splitlines() if ln.startswith("{")]
    assert lines, (r.returncode, r.stdout[-300:], r.stderr[-600:])
    out = json.loads(lines[-1])
    out["stderr"] = r.stderr
    return out


def _form(de: D.DaemonEnv) -> None:
    de.env.write_form('[hosts.build]\naddress = "build.example.org"\nsudo = true\n'
                      '[accounts.gh-work]\nkind = "github"\n')
    consent.approve_all(de.env.form())


def test_daemon_a_typed_value_reaches_the_requester_sealed_and_is_proven_by_hash():
    with D.daemon_env() as de:
        _form(de)
        fc = de.claude()
        mod = Mod(fc)
        drv = _driver(de)
        v = canary()
        store = de.root / "stored.sha"
        pid = _ask(de, fc, drv, {"entry": "build", "what": "sudo password", "ok": [sha16(v)],
                                 "store": str(store),
                                 "check": {"section": "hosts", "entry": "build", "right": "sudo"}})
        d = mod.dialog()
        assert d["entry"] == "build" and d["what"] == "sudo password" and d["paste"] is True
        assert any("The test asks." in ln for ln in d["lines"])
        st, body = mod.post("/ui/dialog/submit", seal(d, [v]))
        assert st == 200 and body["state"] == "checking", body
        out = _result(fc, pid)
        assert out["outcome"] == "ok" and out["sha"] == sha16(v), out["outcome"]
        assert store.read_text() == sha16(v)
        # the mod's bodies hold no plaintext form of the value (the http hop)
        sent = "".join(mod.sent)
        for form in (v, b64(v.encode()), v.encode().hex(), json.dumps(v)[1:-1]):
            assert form not in sent
        # nothing in the daemon's log, event files or dialog file
        blob = de.log() + "".join(p.read_text() for p in (paths.gated_dir() / "events").glob("*"))
        if paths.gated_dialogs().exists():
            blob += paths.gated_dialogs().read_text()
        assert v not in blob and b64(v.encode()) not in blob
        assert "auth.supplied" in blob and "auth.waiting" in blob


def test_daemon_a_wrong_value_then_the_right_one_reopens_the_same_dialog():
    with D.daemon_env() as de:
        _form(de)
        fc = de.claude()
        mod = Mod(fc)
        drv = _driver(de)
        good, bad = canary("good"), canary("bad")
        pid = _ask(de, fc, drv, {"ok": [sha16(good)]})
        d1 = mod.dialog()
        mod.post("/ui/dialog/submit", seal(d1, [bad]))
        d2 = mod.dialog(lambda d: d["attempt"] == 2)
        assert d2["id"] == d1["id"] and d2["pub"] != d1["pub"]
        assert d2["error"].startswith("That didn't work: the test's check said no"), d2["error"]
        mod.post("/ui/dialog/submit", seal(d2, [good]))
        out = _result(fc, pid)
        assert out["outcome"] == "ok" and out["sha"] == sha16(good)


def test_daemon_three_wrong_values_fail_and_nothing_is_stored():
    with D.daemon_env() as de:
        _form(de)
        fc = de.claude()
        mod = Mod(fc)
        drv = _driver(de)
        store = de.root / "stored.sha"
        pid = _ask(de, fc, drv, {"ok": [sha16(canary())], "store": str(store)})
        for n in (1, 2, 3):
            d = mod.dialog(lambda d, n=n: d["attempt"] == n)
            mod.post("/ui/dialog/submit", seal(d, [canary("wrong")]))
        out = _result(fc, pid)
        assert out["outcome"] == "failed" and out["sha"] is None and not store.exists()
        assert mod.view()["dialog"] is None


def test_daemon_cancel_and_timeout_reach_the_requester():
    with D.daemon_env() as de:
        _form(de)
        fc = de.claude()
        mod = Mod(fc)
        drv = _driver(de)
        pid = _ask(de, fc, drv, {})
        d = mod.dialog()
        st, body = mod.post("/ui/dialog/cancel", {"id": d["id"]})
        assert st == 200 and body["outcome"] == "cancelled"
        out = _result(fc, pid)
        assert out["outcome"] == "cancelled" and out["sha"] is None
        drv = _driver(de, dialog_timeout=5, popup_lifetime=5)
        pid = _ask(de, fc, drv, {})
        mod.dialog()
        out = _result(fc, pid, timeout=90)
        assert out["outcome"] == "timeout" and mod.view()["dialog"] is None


def test_daemon_two_requests_queue_one_at_a_time():
    with D.daemon_env() as de:
        _form(de)
        fc = de.claude()
        mod = Mod(fc)
        drv = _driver(de)
        a, b = canary("a"), canary("b")
        p1 = _ask(de, fc, drv, {"entry": "build", "what": "sudo password"})
        first = mod.dialog()
        p2 = _ask(de, fc, drv, {"entry": "gh-work", "what": "token"})
        deadline = time.time() + 20
        while time.time() < deadline and not mod.view()["queue"]:
            time.sleep(0.05)
        v = mod.view()
        assert v["dialog"]["id"] == first["id"] and v["dialog"]["entry"] == "build"
        assert [(q["entry"], q["what"]) for q in v["queue"]] == [("gh-work", "token")]
        mod.post("/ui/dialog/submit", seal(first, [a]))
        second = mod.dialog(lambda d: d["id"] != first["id"])
        assert second["entry"] == "gh-work"
        mod.post("/ui/dialog/submit", seal(second, [b]))
        r1, r2 = _result(fc, p1), _result(fc, p2)
        assert (r1["sha"], r2["sha"]) == (sha16(a), sha16(b))


def test_daemon_the_clipboard_route_reads_the_override_only():
    with D.daemon_env() as de:
        _form(de)
        v = canary("clip")
        prog = de.root / "fake-clip"
        (de.root / "clip.txt").write_text(v)
        os.chmod(de.root / "clip.txt", 0o600)
        prog.write_text(f"#!/bin/sh\nexec /bin/cat {de.root / 'clip.txt'}\n")
        os.chmod(prog, 0o755)
        fc = de.claude()
        mod = Mod(fc)
        drv = _driver(de)
        # the daemon's own override has no clipboard program: nothing is read
        pid = _ask(de, fc, drv, {"ok": [sha16(v)]})
        d = mod.dialog()
        st, body = mod.post("/ui/dialog/paste", {"id": d["id"], "env": {}})
        assert body["ok"] is False and "test override" in body["message"]
        assert mod.dialog()["error"].startswith("Paste didn't work")
        mod.post("/ui/dialog/cancel", {"id": d["id"]})
        _result(fc, pid)
        # with the knob (gated-test.json), the fake program's line is the value
        de.knobs(clipboard=str(prog))
        de.stop()
        de.start()
        fc2 = de.claude(session="s-clip")
        mod = Mod(fc2)
        pid = _ask(de, fc2, drv, {"ok": [sha16(v)]})
        d = mod.dialog()
        st, body = mod.post("/ui/dialog/paste", {"id": d["id"], "env": {}})
        assert st == 200 and body["state"] == "checking", body
        out = _result(fc2, pid)
        assert out["outcome"] == "ok" and out["sha"] == sha16(v)
        assert v not in "".join(mod.sent) and v not in de.log()


def test_daemon_a_restart_mid_dialog_reopens_it_and_the_requester_gets_the_value():
    with D.daemon_env() as de:
        _form(de)
        fc = de.claude()
        mod = Mod(fc)
        drv = _driver(de)
        v = canary()
        pid = _ask(de, fc, drv, {"ok": [sha16(v)]})
        d = mod.dialog()
        gpid = de.daemon_pid()
        os.kill(gpid, signal.SIGKILL)
        deadline = time.time() + 20
        while time.time() < deadline and (de.daemon_pid() in (None, gpid)):
            time.sleep(0.1)           # the requester's wait starts it again
        assert de.daemon_pid() not in (None, gpid)
        d2 = mod.dialog()
        assert d2["id"] == d["id"] and d2["pub"] != d["pub"]
        st, body = mod.post("/ui/dialog/submit", seal(d, [v]))       # the old key: refused
        assert st == 400 and body["error"] in ("box", "stale"), body
        mod.post("/ui/dialog/submit", seal(mod.dialog(), [v]))
        out = _result(fc, pid)
        assert out["outcome"] == "ok" and out["sha"] == sha16(v)


def test_daemon_pause_closes_the_sessions_dialogs_and_refuses_new_ones():
    with D.daemon_env() as de:
        _form(de)
        fc = de.claude(session="s-pause")
        mod = Mod(fc)
        drv = _driver(de)
        pid = _ask(de, fc, drv, {})
        d = mod.dialog()
        probe = D.probe_root(de.root)
        st, body = de.probe(fc, probe / "run.py", ["hook-post"], "/v1/pause",
                            {"session": "s-pause", "reason": "test"})
        assert st == 200 and body["paused"] and body["dialogs_closed"] == 1, body
        out = _result(fc, pid)
        assert out["outcome"] == "paused" and out["sha"] is None
        st, _ = mod.post("/ui/dialog/submit", seal(d, [canary()]))
        assert st == 404
        pid = _ask(de, fc, drv, {})
        out = _result(fc, pid)
        assert out["outcome"] == "unavailable" and "paused" in out["stderr"]
        st, body = de.probe(fc, probe / "run.py", ["hook-post"], "/v1/resume", {"session": "s-pause"})
        assert st == 200 and body["was_paused"]
        pid = _ask(de, fc, drv, {})
        assert mod.dialog()["entry"] == "build"
        mod.post("/ui/dialog/cancel", {"id": mod.dialog()["id"]})
        _result(fc, pid)


def test_daemon_unavailable_sessions_are_told_why_and_nothing_is_asked():
    with D.daemon_env() as de:
        _form(de)
        drv = _driver(de)
        for kw, words in ((dict(surface=None), "claude -p"), (dict(surface="mobile"), "mobile"),
                          (dict(surface="vscode"), "VS Code")):
            fc = de.claude(session=f"s-{words[:5]}", **kw)
            pid = _ask(de, fc, drv, {"entry": "build"})
            out = _result(fc, pid)
            assert out["outcome"] == "unavailable" and words in out["stderr"], (kw, out["stderr"])
            assert "terminal or the desktop app" in out["stderr"]
            st, body = fc.http("GET", "/ui/dialog/next?rev=0&wait=0")
            assert body["dialog"] is None and body["available"] is False
        # a session only a hook registered (mods off): no lease either
        hookonly = de.claude(register=False, session="s-hook")
        probe = D.probe_root(de.root)
        de.probe(hookonly, probe / "run.py", ["hook-daemon"], "/agent/register",
                 {"session_id": "s-hook"})
        pid = _ask(de, hookonly, drv, {})
        out = _result(hookonly, pid)
        assert out["outcome"] == "unavailable" and "mod isn't running" in out["stderr"]


def test_daemon_planes_the_lease_plane_needs_an_entry_point_and_the_ui_its_claude():
    with D.daemon_env() as de:
        _form(de)
        fc = de.claude()
        mod = Mod(fc)
        drv = _driver(de)
        pid = _ask(de, fc, drv, {})
        d = mod.dialog()
        probe = D.probe_root(de.root)
        # a process that isn't a gateway entry point: refused before any lease check
        st, body = de.probe(fc, probe / "run.py", ["x"], "/lease/dialog/wait",
                            {"lease": "0" * 64, "id": d["id"]}, test_entry=False,
                            options=("-S",))
        assert st == 403 and body["error"] == "peer", body
        # an entry point without the lease
        st, body = de.probe(fc, probe / "run.py", ["gate"], "/lease/dialog/wait",
                            {"lease": "0" * 64, "id": d["id"]})
        assert st == 403 and body["error"] == "lease", body
        # agents never reach the UI plane, nor strangers
        st, body = de.probe(fc, probe / "run.py", ["gate"], "/ui/dialog/submit", seal(d, ["x"]))
        assert st == 403 and body["error"] == "plane", body
        st, body = de.call("GET", "/ui/dialog/next")
        assert st == 403
        mod.post("/ui/dialog/cancel", {"id": d["id"]})
        _result(fc, pid)


def test_daemon_consent_choice_and_host_key_dialogs():
    with D.daemon_env() as de:
        _form(de)
        fc = de.claude()
        mod = Mod(fc)
        drv = _driver(de)
        pid = _ask(de, fc, drv, {"kind": "consent", "lines": ["ssh: true (was off)"]})
        d = mod.dialog()
        assert d["kind"] == "confirm" and d["ok_label"] == "Approve" and d["cancel_label"] == "Decline"
        assert any("ssh: true (was off)" in ln for ln in d["lines"]) and "pub" not in d
        mod.post("/ui/dialog/answer", {"id": d["id"], "button": "ok"})
        assert _result(fc, pid)["outcome"] == "ok"
        pid = _ask(de, fc, drv, {"kind": "consent", "lines": ["sudo: true"]})
        d = mod.dialog()
        mod.post("/ui/dialog/answer", {"id": d["id"], "button": "cancel"})
        assert _result(fc, pid)["outcome"] == "cancelled"
        pid = _ask(de, fc, drv, {"kind": "choice", "options": ["one", "two"]})
        d = mod.dialog()
        st, body = mod.post("/ui/dialog/answer", {"id": d["id"], "button": "ok", "choice": "three"})
        assert st == 400
        mod.post("/ui/dialog/answer", {"id": d["id"], "button": "ok", "choice": "two"})
        assert _result(fc, pid)["choice"] == "two"
        old, new = "SHA256:" + "A" * 43, "SHA256:" + "B" * 43
        pid = _ask(de, fc, drv, {"kind": "hostkey", "old": [old], "new": [new]})
        d = mod.dialog()
        assert d["ok_label"] == "Trust new key" and any(old in ln for ln in d["lines"]) \
            and any(new in ln for ln in d["lines"])
        from nacl import public
        other = b64(bytes(public.PrivateKey.generate().public_key))
        st, body = mod.post("/ui/dialog/submit", seal({**d, "pub": other}, ["x"]))
        assert st == 400                                  # no secret goes into a confirm
        mod.post("/ui/dialog/answer", {"id": d["id"], "button": "ok"})
        assert _result(fc, pid)["outcome"] == "ok"


def test_daemon_vault_passphrase_set_then_lock_and_unlock_through_dialogs():
    with D.daemon_env() as de:
        vault.save(vault.empty())
        assert paths.key_path().exists()
        fc = de.claude()
        mod = Mod(fc)
        st, body = fc.http("POST", "/ui/vault/unlock")
        assert st == 200 and body["available"], body
        d = mod.dialog()
        assert d["kind"] == "passphrase" and d["fields"] == 2 and d["paste"] is False
        mod.post("/ui/dialog/submit", seal(d, [PASS, PASS + "x"]))
        d = mod.dialog(lambda d: d["attempt"] == 2)
        assert "differ" in d["error"]
        mod.post("/ui/dialog/submit", seal(d, ["short", "short"]))
        d = mod.dialog(lambda d: d["attempt"] == 3)
        assert "at least 12" in d["error"]
        mod.post("/ui/dialog/submit", seal(d, [PASS, PASS]))
        assert de.wait_for(lambda: de.health()["vault"] == "unlocked", 30)
        assert not paths.key_path().exists() and paths.wrapped_key_path().exists()
        assert D.full_vault(PASS) is not None
        st, body = fc.http("POST", "/ui/vault/lock")
        assert body["locked"] and de.health()["vault"] == "locked"
        fc.http("POST", "/ui/vault/unlock")
        d = mod.dialog()
        assert d["kind"] == "unlock" and d["paste"] is True
        mod.post("/ui/dialog/submit", seal(d, ["not the passphrase at all"]))
        d = mod.dialog(lambda d: d["attempt"] == 2)
        assert "doesn't unlock" in d["error"]
        mod.post("/ui/dialog/submit", seal(d, [PASS]))
        assert de.wait_for(lambda: de.health()["vault"] == "unlocked", 30)
        st, body = fc.http("POST", "/ui/vault/unlock")
        assert body["available"] is True, body                # unlocked: the menu (§19.14)
        assert mod.dialog()["kind"] == "choice"
        assert PASS not in de.log()


def _gate(de: D.DaemonEnv, fc: D.FakeClaude, *args: str):
    """`gate ARGS` as a gateway program below `fc` (native dialogs)."""
    drv = _driver(de)
    env = de.env.subprocess_env()
    env.pop("GATEWAY_TEST_ROOT")
    env["CLAUDE_PID"] = str(fc.pid)
    return fc.run([H.PY, "-I", "-S", drv, str(de.root), "gate", *args], env=env)


def _opens(passphrase: str) -> bool:
    from gateway import agepass
    try:
        D.full_vault(passphrase)
        return True
    except agepass.AgePassError:
        return False


def _closed(mod: Mod, rid: str, timeout: float = 30) -> dict[str, Any]:
    """The closed dialog `rid` from the session's recent list (its outcome
    and note: what gated's own handler said)."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for x in mod.view()["recent"]:
            if x["id"] == rid:
                return x
        time.sleep(0.05)
    raise AssertionError(f"dialog {rid} never closed: {json.dumps(mod.view())[:400]}")


def _event_kinds() -> list[str]:
    """Every event kind gated logged in this test root, in order."""
    out: list[str] = []
    for f in sorted((paths.gated_dir() / "events").glob("epoch-*.jsonl")):
        out += [json.loads(ln)["kind"] for ln in f.read_text().splitlines() if ln.strip()]
    return out


def test_daemon_an_unlocked_vaults_passphrase_is_changed_or_removed_in_gateds_dialogs():
    """PLAN-0.11 §19.14: with the vault unlocked, /gate-unlock opens gated's
    menu (Change passphrase, Remove passphrase; one per session). Change: the
    two-field passphrase dialog; the new passphrase opens the key, the old
    one doesn't any more, the vault stays unlocked and readable. Remove: a
    confirm (Cancel the default; Cancel keeps the passphrase); its OK puts
    key.txt back, removes key.wrapped and key.recipient, keeps every secret,
    declines the passphrase offer and logs vault.unwrapped; a vault locked
    while the confirm waits keeps its passphrase. `gate passphrase` opens the
    change dialog, `gate passphrase --remove` the confirm. No value reaches
    the log."""
    new = "another vault passphrase for the change test"
    secret = canary("sv")
    with D.daemon_env() as de:
        vault.save(vault.empty())
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), secret)
        de.wrap(PASS)
        fc = de.claude()
        mod = Mod(fc)
        st, body = fc.http("POST", "/ui/vault/unlock")
        assert st == 200 and body["available"], body
        d = mod.dialog()
        assert d["kind"] == "choice" and d["entry"] == "vault" and d["fields"] == 0 and \
            d["options"] == ["Change passphrase", "Remove passphrase"], d
        fc.http("POST", "/ui/vault/unlock")
        v = mod.view()
        assert v["dialog"]["id"] == d["id"] and v["queue"] == [], "one menu per session"
        mod.post("/ui/dialog/answer", {"id": d["id"], "button": "ok", "choice": "Change passphrase"})
        p = mod.dialog(lambda x: x["kind"] == "passphrase")
        assert p["fields"] == 2 and p["what"] == "vault passphrase change", p
        old_wrapped = paths.wrapped_key_path().read_bytes()
        mod.post("/ui/dialog/submit", seal(p, [new, new]))
        # (wait on the dialog's close, cheap; then one scrypt each: a poll of
        # _opens would run age's scrypt again and again on a loaded machine)
        x = _closed(mod, p["id"], 60)
        assert x["outcome"] == "ok", x
        assert paths.wrapped_key_path().read_bytes() != old_wrapped
        assert _opens(new), "the new passphrase opens the key"
        assert not _opens(PASS), "the old one doesn't"
        assert de.health()["vault"] == "unlocked"
        assert vault.sudo_entry(D.full_vault(new), "localhost", paths.local_user())["password"] \
            == secret
        # `gate passphrase` opens the change dialog too
        r = _gate(de, fc, "passphrase")
        assert r.returncode == 0 and "set or change the vault passphrase is open" in r.stdout, \
            (r.stdout, r.stderr)
        p = mod.dialog(lambda x: x["kind"] == "passphrase")
        mod.post("/ui/dialog/cancel", {"id": p["id"]})
        # remove: Cancel keeps the passphrase
        fc.http("POST", "/ui/vault/unlock")
        d = mod.dialog(lambda x: x["kind"] == "choice")
        mod.post("/ui/dialog/answer", {"id": d["id"], "button": "ok", "choice": "Remove passphrase"})
        c = mod.dialog(lambda x: x["kind"] == "confirm")
        assert c["default_cancel"] is True and c["ok_label"] == "Remove passphrase", c
        assert any("any program running as you" in ln for ln in c["lines"]), c["lines"]
        mod.post("/ui/dialog/cancel", {"id": c["id"]})
        time.sleep(0.3)
        assert paths.wrapped_key_path().exists() and not paths.key_path().exists()
        # locked while the confirm waits: its OK removes nothing (the broker's own check)
        r = _gate(de, fc, "passphrase", "--remove")
        assert r.returncode == 0 and "remove the vault passphrase is open" in r.stdout, r.stdout
        c = mod.dialog(lambda x: x["kind"] == "confirm")
        fc.http("POST", "/ui/vault/lock")
        assert de.wait_for(lambda: de.health()["vault"] == "locked", 10)
        mod.post("/ui/dialog/answer", {"id": c["id"], "button": "ok"})
        x = _closed(mod, c["id"])
        assert x["outcome"] == "failed" and "must be unlocked" in x["note"], x
        assert paths.wrapped_key_path().exists() and paths.recipient_path().exists() and \
            not paths.key_path().exists() and de.health()["vault"] == "locked"
        st, _b = de.unlock(new)
        assert st == 200 and de.health()["vault"] == "unlocked", _b
        assert "vault.unwrapped" not in _event_kinds()
        r = _gate(de, fc, "passphrase", "--remove")
        assert r.returncode == 0 and "remove the vault passphrase is open" in r.stdout, r.stdout
        c = mod.dialog(lambda x: x["kind"] == "confirm")
        mod.post("/ui/dialog/answer", {"id": c["id"], "button": "ok"})
        assert de.wait_for(lambda: de.health()["vault"] == "unwrapped", 30)
        assert de.wait_for(lambda: "vault.unwrapped" in _event_kinds(), 10), _event_kinds()
        assert paths.key_path().exists() and not paths.wrapped_key_path().exists() and \
            not paths.recipient_path().exists()
        assert oct(paths.key_path().stat().st_mode & 0o777) == oct(0o600)
        data = vault.load()
        assert vault.sudo_entry(data, "localhost", paths.local_user())["password"] == secret
        assert vault.offer_state(data) == "declined", "not offered again"
        r = _gate(de, fc, "passphrase", "--remove")
        assert r.returncode == 1 and "no passphrase to remove" in r.stderr, r.stderr
        for v_ in (PASS, new, secret):
            assert v_ not in de.log()


def test_daemon_a_vault_whose_passphrase_is_lost_starts_over_only_after_the_ok():
    """PLAN-0.11 §19.14: `gate passphrase --start-over` (the vault locked)
    opens gated's confirm, Cancel the default. Cancel changes nothing; OK
    moves vault.age, key.wrapped, key.recipient and cache.age into
    private/backups/startover-* (nothing deleted: the old passphrase still
    opens them there), leaves gateway.toml, and the next store starts a new
    vault; an import then works (the README's "import your last export"),
    and vault.started_over is logged. It is refused while the vault is
    unlocked or has no passphrase, also when the vault is unlocked while its
    confirm waits. The unlock dialog and the locked messages name it."""
    with D.daemon_env() as de:
        de.env.write_form('[hosts.localhost]\nsudo = true\n')
        vault.save(vault.empty())
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), canary("sv"))
        de.wrap(PASS)
        paths.cache_path().write_bytes(b"an encrypted cache")
        fc = de.claude()
        mod = Mod(fc)
        r = _gate(de, fc, "passphrase", "--start-over")
        assert r.returncode == 1 and "nothing to start over" in r.stderr, r.stderr
        fc.http("POST", "/ui/vault/lock")
        before = {n: (paths.private_dir() / n).read_bytes() for n in vault.START_OVER_FILES}
        r = _gate(de, fc, "passphrase", "--start-over")
        assert r.returncode == 0 and "start the vault over" in r.stdout, (r.stdout, r.stderr)
        c = mod.dialog(lambda x: x["kind"] == "confirm")
        assert c["default_cancel"] is True and c["ok_label"] == "Start over", c
        assert any("nothing is deleted" in ln for ln in c["lines"]), c["lines"]
        mod.post("/ui/dialog/cancel", {"id": c["id"]})
        time.sleep(0.3)
        assert all((paths.private_dir() / n).read_bytes() == b for n, b in before.items())
        assert de.health()["vault"] == "locked"
        # the unlock dialog and the locked messages name the way out of a lost passphrase
        fc.http("POST", "/ui/vault/unlock")
        u = mod.dialog(lambda x: x["kind"] == "unlock")
        assert any("gate passphrase --start-over" in ln for ln in u["lines"]), u["lines"]
        mod.post("/ui/dialog/cancel", {"id": u["id"]})
        from gateway import hooks_session
        from gateway.daemon import server
        for text in (server.LOCKED_INTERACTIVE, server.LOCKED_HEADLESS, hooks_session.VAULT_LOCKED):
            assert "gate passphrase --start-over" in text, text
        # unlocked while the confirm waits: its OK moves nothing (the broker's own check)
        _gate(de, fc, "passphrase", "--start-over")
        c = mod.dialog(lambda x: x["kind"] == "confirm")
        st, _b = de.unlock(PASS)
        assert st == 200 and de.health()["vault"] == "unlocked", _b
        mod.post("/ui/dialog/answer", {"id": c["id"], "button": "ok"})
        x = _closed(mod, c["id"])
        assert x["outcome"] == "failed" and "vault is unlocked" in x["note"], x
        assert all((paths.private_dir() / n).exists() for n in before), "nothing moved"
        bk = paths.backups_dir()
        assert not (bk.exists() and any(f.name.startswith("startover-") for f in bk.iterdir()))
        assert de.health()["vault"] == "unlocked" and "vault.started_over" not in _event_kinds()
        fc.http("POST", "/ui/vault/lock")
        assert de.wait_for(lambda: de.health()["vault"] == "locked", 10)
        _gate(de, fc, "passphrase", "--start-over")
        c = mod.dialog(lambda x: x["kind"] == "confirm")
        mod.post("/ui/dialog/answer", {"id": c["id"], "button": "ok"})
        assert de.wait_for(lambda: de.health()["vault"] == "none", 30)
        assert de.wait_for(lambda: "vault.started_over" in _event_kinds(), 10), _event_kinds()
        moved = [f for f in paths.backups_dir().iterdir() if f.name.startswith("startover-")]
        assert len(moved) == 1 and oct(moved[0].stat().st_mode & 0o777) == oct(0o700), moved
        assert {n: (moved[0] / n).read_bytes() for n in vault.START_OVER_FILES} == before
        assert not any((paths.private_dir() / n).exists() for n in vault.START_OVER_FILES)
        assert paths.form_path().exists(), "gateway.toml stays"
        assert moved[0].name in [n for _g, ns in vault.older_copies() for n in ns]
        # a new vault from the next store; the old passphrase still opens the moved key
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), canary("sv"))
        assert paths.key_path().exists() and vault.key_mode() == "unwrapped"
        from gateway import agepass
        from gateway.daemon import broker as bmod
        ident = bmod.read_identity(agepass.decrypt((moved[0] / "key.wrapped").read_bytes(),
                                                   PASS).decode())
        assert "localhost" in json.loads(bmod.decrypt_file(ident, moved[0] / "vault.age"))
        r = _gate(de, fc, "passphrase", "--start-over")
        assert r.returncode == 1 and "nothing to start over" in r.stderr, r.stderr


def test_daemon_a_locked_read_opens_the_unlock_dialog_in_that_session():
    with D.daemon_env() as de:
        vault.save(vault.empty())
        de.wrap(PASS)
        fc = de.claude()
        mod = Mod(fc)
        fc.http("POST", "/ui/vault/lock")
        drv = _driver(de)
        env = de.env.subprocess_env()
        env.pop("GATEWAY_TEST_ROOT")
        r = fc.run([H.PY, "-I", "-S", drv, str(de.root), "gate", "status"], env=env)
        assert "vault locked" in r.stdout, (r.stdout[-300:], r.stderr[-300:])
        d = mod.dialog()
        assert d["kind"] == "unlock" and d["entry"] == "vault"
        # one per session: a second locked read reuses it
        fc.run([H.PY, "-I", "-S", drv, str(de.root), "gate", "status"], env=env)
        v = mod.view()
        assert v["dialog"]["id"] == d["id"] and v["queue"] == []
        # a headless session gets no dialog, only the refusal
        hl = de.claude(surface=None, session="s-print")
        fc.http("POST", "/ui/dialog/cancel", {"id": d["id"]})
        hl.run([H.PY, "-I", "-S", drv, str(de.root), "gate", "status"], env=env)
        assert mod.view()["dialog"] is None


# ---------------------------------------------------------------------------
# The sudo stand-in through gated (review of phase 3): the recheck of its
# right while its dialog is open, and "Remember it"
# ---------------------------------------------------------------------------


def _sudo_run(de: D.DaemonEnv, *, change: str | list[str] | None = None,
              remember: bool | None = None, cancel: bool = False) -> dict[str, Any]:
    """`sudo echo hi` through the real stand-in (fake sudo with a canary
    password, no password stored) below a FakeClaude; the "mod" answers its
    dialog with the canary, sealed. `change`: the form written while the
    dialog is open (each text then ratcheted, as any gateway process loading
    it does).
    Returns what ran, whether a password is stored, the dialog's view and the
    stand-in's exit; never a value."""
    de.env.write_form('[hosts.localhost]\nsudo = true\n')
    vault.save(vault.empty())
    consent.approve_all(de.env.form())
    pw = canary("pw")
    fake = H.make_fake_sudo(de.root / "fsudo", password=pw)
    fc = de.claude()
    mod = Mod(fc)
    drv = _driver(de, tools={"sudo": str(fake.path)})
    env = de.env.subprocess_env()
    env.pop("GATEWAY_TEST_ROOT")
    env["CLAUDE_PID"] = str(fc.pid)
    pid = fc.spawn([H.PY, "-I", "-S", drv, str(de.root), "shim", "sudo", "echo", "hi"], env=env)
    d = mod.dialog(timeout=30)
    for text in ([change] if isinstance(change, str) else change or []):
        de.env.write_form(text)
        consent.ratchet(consent.load_form(vault.load()))
    if cancel:
        st, body = mod.post("/ui/dialog/cancel", {"id": d["id"]})
    else:
        sealed = seal(d, [pw])
        if remember is not None:
            sealed["remember"] = remember
        st, body = mod.post("/ui/dialog/submit", sealed)
    r = fc.wait(pid, timeout=60)
    e = vault.sudo_entry(vault.load(), "localhost", paths.local_user())
    out = {"view": d, "submit": (st, body.get("state"), body.get("error")), "rc": r.returncode,
           "ran": [x.get("ran") for x in fake.log() if x.get("ran")],
           "stored": bool(e and e.get("password")),
           "stored_sha": sha16(e["password"]) if e and e.get("password") else None,
           "sha": sha16(pw), "stderr": r.stderr.replace(pw, "<PW>")[-600:],
           "recent": mod.view()["recent"]}
    return out


def test_daemon_sudo_standin_a_right_switched_off_while_its_dialog_is_open_is_never_used():
    """The sudo stand-in's dialog names localhost's sudo right for gated's
    recheck: switched off (or localhost's entry disabled) while the dialog is open,
    the password typed then is refused by gated, never handed over, verified,
    stored or used. Before the fix the stand-in passed no check: the password
    was stored and `echo hi` ran as root."""
    # (a form without [hosts.localhost] keeps the implicit localhost, sudo
    # on: form.py; an entry with a bad value is disabled, so localhost is gone)
    # (and switched off, then on again: the form says true, but the effective
    # right waits for the user's OK, so it is off too)
    for change, why in (('[hosts.localhost]\nsudo = false\n', "sudo right is off"),
                        ('[hosts.localhost]\nsudo = "maybe"\n', "isn't a host"),
                        (['[hosts.localhost]\nsudo = false\n', '[hosts.localhost]\nsudo = true\n'],
                         "sudo right is off")):
        with D.daemon_env() as de:
            out = _sudo_run(de, change=change)
            assert out["submit"][0] == 200 and out["submit"][2] == "failed", out["submit"]
            assert out["ran"] == [], "sudo ran after its right was switched off"
            assert not out["stored"], "a password was stored for a right that is off"
            assert out["rc"] != 0, out["stderr"]
            assert any(why in x["note"] for x in out["recent"]), out["recent"]
            assert "<PW>" not in out["stderr"]


def test_daemon_sudo_standin_control_unchanged_right_runs_and_stores():
    with D.daemon_env() as de:
        out = _sudo_run(de, remember=True)
        assert out["view"]["remember"] is False, \
            "a sudo password a command asks for offers Remember it, unticked (WS-9)"
        assert out["ran"] == [["echo", "hi"]] and out["rc"] == 0, out["stderr"]
        assert out["stored_sha"] == out["sha"], "ticked: stored"


def test_daemon_sudo_standin_remember_unticked_runs_once_and_stores_nothing():
    with D.daemon_env() as de:
        out = _sudo_run(de, remember=False)
        assert out["ran"] == [["echo", "hi"]] and out["rc"] == 0, out["stderr"]
        assert not out["stored"], "Remember it unticked: used for this command, never stored"
        e = vault.sudo_entry(vault.load(), "localhost", paths.local_user())
        assert e is None or not e.get("password")


def test_daemon_sudo_standin_cancel_runs_nothing():
    with D.daemon_env() as de:
        out = _sudo_run(de, cancel=True)
        assert out["ran"] == [] and out["rc"] != 0 and not out["stored"], out


def test_daemon_a_pem_dialog_takes_a_multi_line_paste_and_others_never_do():
    """PLAN-v4 phase 7 (an Azure service principal's certificate): a secret
    dialog asking for a PEM takes the clipboard's line breaks; every other
    secret dialog still takes one line only."""
    with tempdir() as tmp:
        pem = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----"
        (tmp / "clip.txt").write_text(pem + "\n")
        prog = tmp / "fake-clip"
        prog.write_text(f"#!/bin/sh\nexec /bin/cat {tmp / 'clip.txt'}\n")
        os.chmod(prog, 0o755)
        with D.daemon_env() as de:
            de.knobs(clipboard=str(prog))
            de.stop()
            de.start()
            _form(de)
            fc = de.claude()
            mod = Mod(fc)
            drv = _driver(de)
            # an ordinary secret dialog: the paste is refused, the dialog stays open
            pid = _ask(de, fc, drv, {"entry": "gh-work", "what": "token", "ok": [sha16(pem)],
                                     "check": {"section": "accounts", "entry": "gh-work",
                                               "kind": "github"}})
            d = mod.dialog()
            assert d["pem"] is False
            st, body = mod.post("/ui/dialog/paste", {"id": d["id"]})
            assert body.get("ok") is False and "more than one line" in body.get("message", ""), body
            mod.post("/ui/dialog/cancel", {"id": d["id"]})
            assert _result(fc, pid)["outcome"] == "cancelled"
            # a PEM dialog: the same paste arrives whole
            pid = _ask(de, fc, drv, {"entry": "gh-work", "what": "client certificate",
                                     "ok": [sha16(pem)], "pem": True,
                                     "check": {"section": "accounts", "entry": "gh-work",
                                               "kind": "github"}})
            d = mod.dialog()
            assert d["pem"] is True
            st, body = mod.post("/ui/dialog/paste", {"id": d["id"]})
            assert st == 200 and body.get("state") == "checking", body
            out = _result(fc, pid)
            assert out["outcome"] == "ok" and out["sha"] == sha16(pem), out
