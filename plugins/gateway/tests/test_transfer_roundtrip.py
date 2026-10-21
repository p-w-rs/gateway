"""transfer: export path rules, export -> import round trip with localhost
remap and host-key-based machine detection, v2 export import, strict
validation, machine-id detection, copy_to against a fake remote gate, the
--from-peer guards, pubkey."""
from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import sys
import tempfile
from pathlib import Path

import harness as H
import harness_ux as U
from gateway import consent, paths, popup, testing, transfer, vault
from gateway import form as formmod

PASS = "correct horse battery staple"
A_FORM = '''[hosts.localhost]
sudo = true

[hosts.powerslabs]
address = "joshua@10.0.0.5"

[hosts.builder]
address = "ci@builder.internal"
via = "powerslabs"
sudo = false

[accounts.github-work]
kind = "github"
login = "jpowers-asi"
owners = ["asirobots"]

[accounts.openai]
kind = "api-key"
sites = ["api.openai.com"]
'''
LAB_KEY = H.fake_host_key("labkey")
MAC_KEY = H.fake_host_key("macbook-hostkey")


def _etc(root: Path, key: str | None) -> Path:
    d = root / "etc-ssh"
    d.mkdir(parents=True, exist_ok=True)
    if key:
        (d / "ssh_host_ed25519_key.pub").write_text(key + " root@host\n")
    return d


def _machine_a(env) -> None:
    env.o.extra["etc_ssh"] = str(_etc(env.root, MAC_KEY))
    U.setup(env, A_FORM)
    k1, p1 = H.ssh_keypair("lab")
    k2, p2 = H.ssh_keypair("builder")
    with vault.edit() as d:
        d["machine"] = {"id": "MACHINE-A", "name": "macbook", "hostname": "macbook.local"}
        lab = vault.host_record(d, "powerslabs")
        lab["keys"] = [vault.key_record(k1, p1)]
        lab["host_keys"] = [vault.norm_host_key(LAB_KEY)]
        lab["pinned_at"] = "2026-01-01T00:00:00+0000"
        vault.set_sudo(d, "powerslabs", "joshua", "lab-sudo-pw-22")
        b = vault.host_record(d, "builder")
        b["keys"] = [vault.key_record(k2, p2)]
        b["host_keys"] = [vault.norm_host_key(H.fake_host_key("bkey"))]
        vault.set_sudo(d, "localhost", "alice", "mac-pw-alice-1")
        d["aliases"] = {"github:work": "github-work"}
    U.set_token("github-work", "github", "ghp_workTOKEN0123456789abcdefghij")
    U.set_token("openai", "api-key", "sk-test-openai-0123456789abcdef")


def _groups(form_text: str = A_FORM, sudo: bool = True) -> str:
    """The selection pane's lines for machine A (PLAN-v4 phase 7: one per
    item), all ticked (and this machine's sudo password when `sudo`)."""
    opts = ["Host powerslabs (joshua@10.0.0.5)", "powerslabs: its SSH key and sudo password",
            "Host builder (ci@builder.internal)", "builder: its SSH key",
            "Account github-work (github)", "github-work: its token",
            "Account openai (api-key)", "openai: its token"]
    if sudo:
        opts.append("This machine's sudo password")
    return "\n".join(opts)


def _run(fn, *args):
    out, err = io.StringIO(), io.StringIO()
    so, se = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        rc = fn(*args)
    finally:
        sys.stdout, sys.stderr = so, se
    return rc, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def _xfer_dir():
    d = Path(tempfile.mkdtemp(prefix="gwx-", dir=H.tmp_base()))
    try:
        yield d
    finally:
        import shutil
        shutil.rmtree(d, ignore_errors=True)


def test_export_path_rules():
    with H.gateway_env() as env:
        p = transfer.check_export_path(None)
        assert p.parent == (paths.user_home() / "Downloads").resolve() or p.parent == paths.user_home().resolve()
        assert p.name.startswith("gateway-") and p.suffix == ".age"
        (env.root / "repo" / ".git").mkdir(parents=True)
        (env.root / "Dropbox").mkdir()
        (paths.user_home() / "Library" / "CloudStorage" / "x").mkdir(parents=True)
        paths.ensure_home()
        (env.root / "taken.age").write_text("x")
        for raw, frag in [(str(env.root / "repo" / "e.age"), "git work tree"),
                          (str(env.root / "Dropbox" / "e.age"), "cloud"),
                          (str(paths.user_home() / "Library" / "CloudStorage" / "x" / "e.age"), "cloud"),
                          (str(paths.home() / "e.age"), "gateway's own folder"),
                          (str(env.root / "taken.age"), "never overwrites"),
                          (str(env.root / "e.txt"), "must end in .age"),
                          (str(env.root / "nope" / "e.age"), "isn't a folder")]:
            try:
                transfer.check_export_path(raw)
                raise AssertionError(raw)
            except transfer.TransferError as e:
                assert frag in str(e), (raw, e)


def test_export_import_round_trip_with_localhost_remap():
    with _xfer_dir() as x:
        f = x / "gw.age"
        ans = U.answers(("ok", _groups()), ("ok", PASS), ("ok", PASS))
        with U.ux_env(ans, local_user="alice", machine_id="MACHINE-A") as env:
            _machine_a(env)
            rc, out, err = _run(transfer.export_cmd, str(f))
            assert rc == 0, (out, err)
            assert "exported 2 hosts and 2 accounts and this machine's sudo password" in out
            assert os.stat(f).st_mode & 0o777 == 0o600 and f.read_bytes().startswith(b"age-encryption.org/v1")
            assert b"lab-sudo-pw-22" not in f.read_bytes()
            c = env.dialog.calls()
            assert c[0]["kind"] == "checklist" and "This machine's sudo password" in c[0]["default"]
            assert any(e["what"] == "export" for e in vault.load()["events"])
        ans = U.answers(("ok", PASS), ("ok", "Keep mine"), ("ok",))
        with U.ux_env(ans, local_user="joshua", machine_id="MACHINE-B") as env:
            env.o.extra["etc_ssh"] = str(_etc(env.root, LAB_KEY))       # this machine is powerslabs
            U.setup(env, '[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n')
            U.set_token("openai", "api-key", "sk-local-openai-key-99999999")
            # what this machine kept under a name it removed earlier is not what
            # the import's pop-up lists for that name (review round 2)
            with vault.edit() as d:
                vault.account_record(d, "github-work", "api-key")["entra"] = {"refresh_token": "OLD-RT-0123456789"}
            rc, out, err = _run(transfer.import_cmd, str(f))
            assert rc == 0, (out, err)
            c = env.dialog.calls()
            # PLAN-v4 phase 7: openai meets this machine's openai (another key):
            # the person decides per item, then confirms the whole import
            assert c[0]["kind"] == "secret" and c[1]["kind"] == "choice" and "openai" in c[1]["message"]
            assert c[2]["kind"] == "confirm" and c[2]["default"] == "Cancel"
            msg = c[2]["message"]
            assert "This machine is powerslabs in the file (found by host key)" in msg, msg
            assert "Adds:" in msg and "builder" in msg and "github-work" in msg and "macbook" in msg
            assert "Keeps yours: openai" in msg
            form = env.form()
            assert "powerslabs" not in form.hosts, "this machine isn't added as a host"
            assert form.hosts["builder"].via is None, "reached through this machine: direct now"
            mac = form.hosts["macbook"]
            assert mac.ssh is False and mac.address.user == "alice"
            assert mac.address.host == socket.gethostname().lower()
            data = vault.load()
            assert data["localhost"]["sudo"]["joshua"]["password"] == "lab-sudo-pw-22"
            assert data["hosts"]["macbook"]["host_keys"] == [vault.norm_host_key(MAC_KEY)]
            assert data["hosts"]["macbook"]["sudo"]["alice"]["password"] == "mac-pw-alice-1"
            assert data["accounts"]["openai"]["token"]["value"] == "sk-local-openai-key-99999999"
            assert data["accounts"]["github-work"]["token"]["value"] == "ghp_workTOKEN0123456789abcdefghij"
            assert "entra" not in data["accounts"]["github-work"], "the old record's sign-in is gone"
            assert data["accounts"]["github-work"]["kind"] == "github"
            assert data["aliases"]["github:work"] == "github-work"
            eff = consent.compute(form, data)
            assert not eff.pending_for("builder") and not eff.pending_for("github-work") \
                and not eff.pending_for("macbook"), [c.render() for c in eff.pending]
            assert "github.com" in data["accounts"]["github-work"]["bound"]["hosts"]
            assert any(e["what"] == "import" for e in data["events"])


def test_export_leaves_out_unticked_groups_and_needs_a_long_passphrase():
    with _xfer_dir() as x:
        f = x / "accounts-only.age"
        ans = U.answers(("ok", "Account github-work (github)\ngithub-work: its token\n"
                                 "Account openai (api-key)\nopenai: its token"), ("ok", "short"),
                        ("ok", PASS), ("ok", PASS))
        with U.ux_env(ans, local_user="alice", machine_id="MACHINE-A") as env:
            _machine_a(env)
            rc, out, err = _run(transfer.export_cmd, str(f))
            assert rc == 0, (out, err)
            assert "exported 0 hosts and 2 accounts" in out
            assert "at least 12 characters" in env.dialog.calls()[2]["message"]
            raw = transfer.decrypt_passphrase(f.read_bytes(), PASS)
            obj = json.loads(raw)
            assert obj["gateway_export"] == 3 and obj["vault"]["hosts"] == {}
            assert obj["vault"]["localhost"]["sudo"] == {}, "this machine's sudo password stays unless ticked"
            assert "[hosts." not in obj["form"] and "[accounts.openai]" in obj["form"]
            for k in ("approved", "form_last_good", "events", "cache"):
                assert k not in obj["vault"]
            assert obj["from"]["name"] == "macbook" and obj["from"]["ssh_host_keys"] == [vault.norm_host_key(MAC_KEY)]
        with U.ux_env(U.answers(("ok", _groups()), ("ok", PASS), ("cancelled",))) as env:
            _machine_a(env)
            rc, out, err = _run(transfer.export_cmd, str(x / "never.age"))
            assert rc == 1 and not (x / "never.age").exists()
            assert [c["kind"] for c in env.dialog.calls()] == ["checklist", "secret", "secret"]


def test_export_passphrase_is_never_on_a_dialog_command_line():
    """Review round 2: the generated passphrase was a dialog's default, so it
    sat on the dialog's command line (ps) for as long as it was open. The
    passphrase is now only typed, into hidden fields, and nothing a dialog is
    started with (its argv: message, default, options) holds it."""
    with _xfer_dir() as x:
        f = x / "gw.age"
        with U.ux_env(U.answers(("ok", _groups()), ("ok", PASS), ("ok", PASS)),
                      local_user="alice", machine_id="MACHINE-A") as env:
            _machine_a(env)
            rc, out, err = _run(transfer.export_cmd, str(f))
            calls = env.dialog.calls()
            assert PASS not in json.dumps(calls), "the passphrase is on a dialog's command line"
            assert rc == 0, (out, err)
            assert [c["kind"] for c in calls] == ["checklist", "secret", "secret"], calls
            assert not any("generated" in json.dumps(c).lower() for c in calls)
            assert PASS not in out + err
            assert json.loads(transfer.decrypt_passphrase(f.read_bytes(), PASS))["gateway_export"] == 3


def test_import_of_a_v2_export():
    with _xfer_dir() as x:
        with U.ux_env(local_user="joshua") as env:
            v2 = H.users_v2_vault("joshua")
            obj = {"gateway_export": 1, "created": "2026-10-01", "from_host": "oldmac.local",
                   "secrets": v2["secrets"], "sudo": v2["sudo"], "accounts": v2["accounts"],
                   "account_prompts": v2["account_prompts"]}
            f = x / "v2.age"
            f.write_bytes(transfer.encrypt_passphrase(json.dumps(obj).encode(), PASS))
        none = "None of them (this machine isn't in the file)"
        with U.ux_env(U.answers(("ok", PASS), ("ok", none), ("ok",)), local_user="joshua") as env:
            env.o.extra["etc_ssh"] = str(_etc(env.root, None))
            U.setup(env, "")
            rc, out, err = _run(transfer.import_cmd, str(f))
            assert rc == 0, (out, err)
            form = env.form()
            for n in ("powerslabs", "builder", "github-personal", "github-work", "hf", "azure", "catalog"):
                assert n in form.hosts or n in form.accounts, (n, out)
            assert "oldmac" in form.hosts and form.hosts["oldmac"].ssh is False
            data = vault.load()
            assert data["accounts"]["github-work"]["token"]["value"] == "ghp_workTOKEN0123456789abcdefghij"
            assert "entra" not in data["accounts"]["github-work"], "the old record's sign-in is gone"
            assert data["accounts"]["github-work"]["kind"] == "github"
            assert data["hosts"]["powerslabs"]["sudo"]["joshua"]["password"] == "lab-sudo-pw-22"
            assert data["accounts"]["azure"]["entra"]["refresh_token"] == "0.AAAA-azure-refresh-token-xyz"
            calls = env.dialog.calls()
            assert calls[1]["kind"] == "choice" and "Which host in the file is this machine" in calls[1]["message"]


def _content(env, **over):
    _machine_a(env)
    form, eff, data = transfer._load()
    c = transfer.export_content(form, data, {"hosts", "accounts", "sudo"})
    c.update(over)
    c["digest"] = transfer._digest(c)      # a well-formed file with these contents
    return c


def test_strict_validation_refuses_bad_files():
    with U.ux_env(local_user="alice") as env:
        good = _content(env)
        inc = transfer.parse_incoming(json.loads(json.dumps(good)))
        assert "powerslabs" in inc.form.hosts and inc.source_sudo["alice"]["password"] == "mac-pw-alice-1"

        def bad(mutate, frag, redigest=True):
            c = json.loads(json.dumps(good))
            mutate(c)
            if redigest:
                c["digest"] = transfer._digest(c)    # a well-formed file that says this
            try:
                transfer.parse_incoming(c)
                raise AssertionError(frag)
            except transfer.TransferError as e:
                assert frag in str(e) and "nothing was imported" in str(e), (frag, e)
        bad(lambda c: c.update(extra=1), "unknown fields")
        bad(lambda c: c["vault"]["hosts"].update(ghost={"keys": []}), "isn't in its form")
        bad(lambda c: c["vault"]["hosts"]["powerslabs"]["keys"][0].update(private="not a key"), "OpenSSH key")
        bad(lambda c: c["vault"]["accounts"]["openai"]["token"].update(value=5), "isn't valid")
        bad(lambda c: c["vault"]["accounts"]["openai"].update(kind="github"), "wrong kind")
        bad(lambda c: c["vault"]["accounts"]["openai"]["bound"].update(hosts=["bad host!"]), "binding")
        bad(lambda c: c["vault"]["accounts"]["openai"].update(sneaky={"x": 1}), "unknown fields")
        bad(lambda c: c.update(form=c["form"] + '\n[hosts.oops]\nadress = "x"\n'), "has a problem")
        bad(lambda c: c.update(form="[hosts.x\n"), "doesn't parse")
        bad(lambda c: c["vault"]["localhost"]["sudo"].update({"bad user!": {"password": "x"}}), "isn't valid")
        bad(lambda c: c.update(gateway_export=4), "newer gateway")
        # PLAN-v4 phase 7: the digest catches a changed body, the schema must match
        bad(lambda c: c["vault"]["accounts"]["openai"]["token"].update(value="sk-changed-0123456789"),
            "don't match their checksum", redigest=False)
        bad(lambda c: c.update(schema=2), "schema version")


def test_machine_id_detection_means_same_machine():
    with U.ux_env(local_user="alice", machine_id="MACHINE-A") as env:
        c = _content(env)
        env.o.extra["etc_ssh"] = str(_etc(env.root / "empty", None))
        inc = transfer.parse_incoming(c)
        this, how = transfer.find_this_machine(inc, vault.load())
        assert (this, how) == (None, "same machine")
        env.o.machine_id = "MACHINE-OTHER"
        c["from"]["machine_id"] = "MACHINE-A"
        inc = transfer.parse_incoming(c)
        assert transfer.find_this_machine(inc, {"machine": {"id": "X"}}) == (None, "")


@contextlib.contextmanager
def _remote_b(root_b: Path):
    """A fake remote: `gate pubkey` and `gate import --from-peer -` run against
    a second test home (root_b), in process."""
    calls: list[str] = []

    def remote(name, command, input=None, timeout=120):
        calls.append(command)
        if command.startswith("test -x"):
            return 0, b"gateway-present\n", b""
        with testing.override(root_b, local_user="joshua", machine_id="MACHINE-B",
                              etc_ssh=str(_etc(root_b, LAB_KEY)), peer_parent_ok=True):
            formmod.clear_cache()
            if command.endswith(" pubkey"):
                rc, out, err = _run(transfer.pubkey)
            elif "import --from-peer -" in command:
                stdin = sys.stdin
                sys.stdin = io.TextIOWrapper(io.BytesIO(input))
                try:
                    rc, out, err = _run(transfer.import_cmd, "-", True)
                finally:
                    sys.stdin = stdin
            else:
                rc, out, err = 127, "", "unknown"
            formmod.clear_cache()
        return rc, out.encode(), err.encode()
    with U.patch(transfer, "remote", remote):
        yield calls


def test_copy_to_a_fake_remote_gate():
    with _xfer_dir() as x:
        root_b = x / "machine-b"
        with testing.override(root_b, local_user="joshua", machine_id="MACHINE-B"):
            (root_b / "home").mkdir(parents=True, exist_ok=True)
            vault.save(vault.empty())
        ans = U.answers(("ok", _groups()), ("ok", "powerslabs"))
        with U.ux_env(ans, local_user="alice", machine_id="MACHINE-A") as env:
            _machine_a(env)
            with _remote_b(root_b) as calls:
                rc, out, err = _run(transfer.copy_to, "powerslabs")
            assert rc == 0, (out, err)
            assert "copied to powerslabs" in out and "added" in out, out
            # (the import call itself runs in the pop-up helper, a forked process)
            assert calls[0].startswith("test -x") and calls[1].endswith("gate pubkey")
            assert env.dialog.calls()[1]["kind"] == "text" and "Type the host name" in env.dialog.calls()[1]["message"]
            assert any(e["what"] == "copy" for e in vault.load()["events"])
            # the pop-ups say plainly that Claude's commands reach powerslabs, and show
            # the remote's recipient (to compare with gate pubkey on that machine)
            groups_msg = env.dialog.calls()[0]["message"]
            assert "Claude can run commands on powerslabs" in groups_msg, groups_msg
            assert "within reach of Claude's commands on powerslabs" in groups_msg
            with testing.override(root_b, local_user="joshua", machine_id="MACHINE-B"):
                recipient = vault.ensure_key()
            confirm_msg = env.dialog.calls()[1]["message"]
            assert recipient in confirm_msg and "gate pubkey" in confirm_msg, confirm_msg
        with testing.override(root_b, local_user="joshua", machine_id="MACHINE-B"):
            formmod.clear_cache()
            form = formmod.load(use_cache=False)
            data = vault.load()
            assert "builder" in form.hosts and "powerslabs" not in form.hosts and "macbook" in form.hosts
            assert data["localhost"]["sudo"]["joshua"]["password"] == "lab-sudo-pw-22"
            assert any(e["what"] == "import" and "copy from macbook" in e["detail"] for e in data["events"])
            formmod.clear_cache()


def test_copy_to_refusals():
    with _xfer_dir() as x:
        root_b = x / "machine-b"
        with testing.override(root_b, local_user="joshua", machine_id="MACHINE-B"):
            (root_b / "home").mkdir(parents=True, exist_ok=True)
            vault.save(vault.empty())
        with U.ux_env(U.answers(("ok", _groups()), ("ok", "powerslab"))) as env:
            _machine_a(env)
            with _remote_b(root_b) as calls:
                rc, out, err = _run(transfer.copy_to, "powerslabs")
                assert rc == 1 and "didn't match" in err, err
                assert not any("from-peer" in c for c in calls), "nothing was sent"
                rc, out, err = _run(transfer.copy_to, "localhost")
                assert rc == 2
                rc, out, err = _run(transfer.copy_to, "openai")
                assert rc == 2
                # pinned in this session: refused (the session record prompt.sh writes
                # into private/sessions at the first prompt)
                rec = popup.state_dir() / "sess-ux.env"
                rec.write_text("started=1\n")
                os.utime(rec, (rec.stat().st_mtime - 60, rec.stat().st_mtime - 60))
                with vault.edit() as d:
                    d["hosts"]["powerslabs"]["pinned_at"] = vault.now()
                rc, out, err = _run(transfer.copy_to, "powerslabs")
                assert rc == 2 and "pinned in this session" in err, err
                # the verifier's case: the session id unset (or unknown) no longer skips the rule
                for sid in (None, "made-up-session"):
                    with U.env_vars(CLAUDE_CODE_SESSION_ID=sid):
                        rc, out, err = _run(transfer.copy_to, "powerslabs")
                    assert rc == 2 and "less than 12 hours ago" in err, (sid, err)
                # a run-dir record Claude's commands could touch doesn't count
                (paths.session_dir() / "sess-ux.json").write_text("{}")
                rec.unlink()
                rc, out, err = _run(transfer.copy_to, "powerslabs")
                assert rc == 2 and "less than 12 hours ago" in err, err
                assert not any("from-peer" in c for c in calls), "nothing was sent"


def test_copy_to_pin_age_rules():
    with U.ux_env() as env:
        U.setup(env, "")
        now = transfer.time.time()
        iso = lambda t: transfer.time.strftime("%Y-%m-%dT%H:%M:%S%z", transfer.time.localtime(t))  # noqa: E731
        rec = popup.state_dir() / "sess-ux.env"
        rec.write_text("started=1\n")
        os.utime(rec, (now - 3600, now - 3600))           # this session started an hour ago
        f = transfer.pinned_too_recently
        assert f("h", {}, {"pinned_at": iso(now - 7200)}) is None, "pinned before this session"
        assert "in this session" in f("h", {}, {"pinned_at": iso(now - 600)})
        assert "isn't known" in f("h", {}, {}), "no pinned_at and no migration: unknown"
        assert f("h", {"migrated": {"at": iso(now - 86400 * 30)}}, {}) is None, "v2 pins: the migration's time"
        with U.env_vars(CLAUDE_CODE_SESSION_ID=None):
            assert "12 hours" in f("h", {}, {"pinned_at": iso(now - 7200)}), "no session: 12 hours"
            assert f("h", {}, {"pinned_at": iso(now - 13 * 3600)}) is None
        os.utime(rec, (now + 7200, now + 7200))            # a record from the future isn't trusted
        assert "12 hours" in f("h", {}, {"pinned_at": iso(now - 7200)})
        assert abs(transfer._ts("2026-01-01T00:00:00+0000") - 1767225600) < 1
        assert abs(transfer._ts("2026-01-01T02:00:00+0200") - 1767225600) < 1, "the offset counts"


def test_imported_host_keys_count_as_pinned_now():
    """An import file can't backdate a pin (pinned_at from the file is ignored)."""
    with U.ux_env() as env:
        U.setup(env, "")
        data = vault.empty()
        p = transfer.ImportPlan()
        p.vault_add = {"hosts": {"lab": {"rec": {"keys": [], "host_keys": [vault.norm_host_key(LAB_KEY)],
                                                 "sudo": {}, "pinned_at": "2020-01-01T00:00:00+0000"}}}}
        transfer._merge_vault(data, p, ["lab"])
        t = transfer._ts(data["hosts"]["lab"]["pinned_at"])
        assert t is not None and abs(t - transfer.time.time()) < 120


def test_peer_import_guards():
    with U.ux_env() as env:
        U.setup(env, "")
        stdin = sys.stdin
        sys.stdin = io.TextIOWrapper(io.BytesIO(b"age-encryption.org/v1\n-> X25519 abc\n"))
        try:
            rc, out, err = _run(transfer.import_cmd, "-", True)
        finally:
            sys.stdin = stdin
        assert rc == 2 and "only for `gate copy-to` over ssh" in err, err
        env.o.extra["peer_parent_ok"] = True
        blob = transfer.encrypt_passphrase(b'{"gateway_export": 2}', PASS)
        sys.stdin = io.TextIOWrapper(io.BytesIO(blob))
        try:
            rc, out, err = _run(transfer.import_cmd, "-", True)
        finally:
            sys.stdin = stdin
        assert rc == 2 and "--from-peer takes only a stream encrypted to this machine's" in err, err
        rc, out, err = _run(transfer.import_cmd, "somefile", True)
        assert rc == 2


def test_pubkey_prints_only_the_recipient():
    with H.gateway_env() as env:
        rc, out, err = _run(transfer.pubkey)
        assert rc == 0 and transfer.RECIPIENT_RE.fullmatch(out.strip())
        assert "SECRET" not in out


def test_without_a_dialog_export_asks_nothing_and_has_no_terminal_path():
    """PLAN-v4 phase 3: export, import and copy-to ask only in the gateway's
    dialog in Claude Code. Without one (claude -p, mods off, the user's own
    terminal) nothing is asked anywhere: no terminal prompt, no one-time code,
    nothing pending; the message says where it works."""
    import test_ux_gate_setup as G
    with _xfer_dir() as x, U.ux_env(dialog="none", session=None) as env:
        _machine_a(env)
        dest = x / "out.age"
        pty = G._Pty([], linger=0.5)
        env.o.extra["tty"] = (pty.fin, pty.fout)
        try:
            rc, out, err = _run(transfer.export_cmd, str(dest))
        finally:
            pty.close()
        assert rc == 1 and not dest.exists(), (rc, out, err)
        assert "nothing was asked" in err and "by running the same gate command there" in err, err
        assert "gate secret" not in err and "one-time code" not in err and "type the code" not in err, err
        assert pty.all == b"", "nothing was written to the terminal"
        assert popup.pending() == [] and not list(paths.pending_dir().glob("*.code"))


def test_forgotten_host_keys_stay_on_this_machine():
    """hosts[N].host_keys_previous (remembered by gate forget) is this machine's
    history: never exported; an older file that carries it still imports."""
    with U.ux_env() as env:
        _machine_a(env)
        with vault.edit() as d:
            d["hosts"]["builder"]["host_keys_previous"] = [vault.norm_host_key(H.fake_host_key("old-b"))]
        c = transfer.export_content(env.form(), vault.load(), {"hosts", "accounts"})
        assert "host_keys_previous" not in json.dumps(c["vault"]), c["vault"]["hosts"]["builder"]
        c["vault"]["hosts"]["builder"]["host_keys_previous"] = ["x"]
        c["digest"] = transfer._digest(c)
        inc = transfer.parse_incoming(json.loads(json.dumps(c)))
        assert "host_keys_previous" not in inc.vault["hosts"]["builder"]


def test_copy_to_a_remote_still_setting_up_or_without_the_gateway():
    """Round 3: the remote's launcher now exists from its first session on,
    while its env still builds (`gate pubkey` exits 75 there); and the
    install steps say the user signs in to Claude Code on the remote."""
    with U.ux_env() as env:
        _machine_a(env)
        calls: list[str] = []

        def building(name, command, input=None, timeout=120):
            calls.append(command)
            if command.startswith("test -x"):
                return 0, b"gateway-present\n", b""
            return 75, b"", b"gateway: still setting up (first run); try again in a minute\n"
        with U.patch(transfer, "remote", building):
            rc, out, err = _run(transfer.copy_to, "powerslabs")
        assert rc == 2 and "the gateway on powerslabs is still setting up" in err, err
        assert "try gate copy-to powerslabs again in a minute" in err

        def absent(name, command, input=None, timeout=120):
            return 1, b"", b""
        with U.patch(transfer, "remote", absent):
            rc, out, err = _run(transfer.copy_to, "powerslabs")
        assert rc == 1 and "signing in to Claude Code on powerslabs themselves" in err, err
        assert "first-time setup finishes" in err
