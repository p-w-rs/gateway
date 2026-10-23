"""The ssh side of `gate check` (group 'ssh'): resolve, keyscan_host,
install_key (show / password / my-login), test_login, rotate, close_masters.

Install and rotate write to the sshd's own authorized_keys through the
`ssh_authorized_keys` test override (never ~/.ssh)."""
from __future__ import annotations

import json
import os
import subprocess
import time

import harness  # noqa: F401
import harness_ssh as H
from gateway import paths, ssh, vault


def _approved(s: H.SshEnv, t: H.Sshd, name: str = "box", extra: str = "") -> None:
    s.write_form(f'[hosts.{name}]\naddress = "{t.addr()}"\n{extra}')
    s.approve()


def test_ssh_setup_resolve() -> None:
    with H.ssh_env() as s:
        t = s.sshd("target")
        s.write_form(f'[hosts.example]\naddress = "{t.addr()}"\n\n'
                     '[accounts.gh]\nkind = "github"\nlogin = "me"\n')
        r = ssh.resolve(["example", "uptime"])
        assert (r["kind"], r["name"], r["by"], r["user"]) == ("host", "example", "name",
                                                              H.real_user())
        assert r["addr"] == t.addr()
        r = ssh.resolve([f"{H.real_user()}@127.0.0.1", "-p", str(t.port), "uptime"])
        assert (r["kind"], r["name"], r["by"]) == ("host", "example", "address")
        r = ssh.resolve(["-o", "SendEnv=GIT_PROTOCOL", "git@github.com", "git-upload-pack 'a/b'"])
        assert (r["kind"], r["name"], r["user"]) == ("endpoint", "github.com", "git")
        r = ssh.resolve(["exmple", "x"])
        assert r["kind"] == "unknown" and r["suggest"] == "example"
        assert ssh.resolve(["-F", "/x", "example"])["kind"] == "refused"
        assert ssh.resolve(["localhost", "id"])["kind"] == "local"
        assert ssh.resolve([])["kind"] == "error"
        assert t.accepted() == 0                       # resolving never connects


def test_ssh_setup_keyscan_direct_and_via() -> None:
    with H.ssh_env() as s:
        j = s.sshd("jump")
        t = s.sshd("target")
        u = H.real_user()
        s.write_form(f'[hosts.gw1]\naddress = "{j.addr()}"\n\n'
                     f'[hosts.inner]\naddress = "{u}@127.0.0.1:{t.port}"\nvia = "gw1"\n')
        # before any consent: the direct host is scanned at its address
        assert ssh.keyscan_host("gw1") == [j.host_key]
        # the host behind gw1 needs gw1 set up (approved, pinned, key installed)
        try:
            ssh.keyscan_host("inner")
        except ssh.SshError as e:
            assert "gw1" in e.message
        else:
            raise AssertionError("scan through an unready jump host")
        s.approve()
        s.host("gw1", j)
        keys = ssh.keyscan_host("inner")
        assert keys == [t.host_key], keys
        assert t.accepted() == 0 and j.accepted() >= 1      # no login on the target
        assert [a["host"] for a in s.audit("keyscan")] == ["gw1", "inner"]
        t.stop()
        try:
            ssh.keyscan_host("inner")
        except ssh.SshError as e:
            assert "couldn't read inner's host key" in e.message
        else:
            raise AssertionError("scan of a stopped host")
        try:
            ssh.keyscan_host("nosuch")
        except ssh.SshError as e:
            assert "isn't a host in gateway.toml" in e.message


def test_ssh_setup_install_show_and_test_login() -> None:
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        pub = ssh.install_key("box", "show")
        assert pub.startswith("ssh-ed25519 ") and " gateway-box@" in pub
        assert ssh.install_key("box", "show") == pub              # idempotent: same key
        assert vault.live_keys(s.vault()["hosts"]["box"])[0]["public"] == pub
        with vault.edit() as d:
            vault.host_record(d, "box")["host_keys"] = [t.host_key]
        ok, msg = ssh.test_login("box")
        assert not ok and "box refused Claude's key (installed? run gate check box)" in msg
        t.authorize(pub)                                          # the user added it
        ok, msg = ssh.test_login("box")
        assert ok and msg.startswith("gateway: Claude's key works on box"), msg
        assert s.vault()["hosts"]["box"]["installed"]
        assert not s.masters()                    # the test login doesn't leave a master
        try:
            ssh.install_key("box", "carrier-pigeon")
        except ValueError:
            pass
        else:
            raise AssertionError("unknown method accepted")


def _fake_password_ssh(s: H.SshEnv, password: str) -> tuple[str, "os.PathLike[str]"]:
    """An ssh that emulates a password login (sshd here can't check real
    passwords): it asks SSH_ASKPASS once, checks a second ask fails (one-shot
    FIFO), then runs the remote command locally. Other calls go to the real ssh."""
    log = s.root / "fake-ssh.log"
    f = s.root / "fake-ssh"
    f.write_text(f"""#!/bin/sh
if [ "${{SSH_ASKPASS_REQUIRE-}}" = force ]; then
  pw=$("$SSH_ASKPASS" "password: ")
  if again=$("$SSH_ASKPASS" "password: " 2>/dev/null); then echo "SECOND-ASK-ANSWERED" >> {H.sq(log)}; fi
  case "$*" in *{H.sq(password)}*) echo "PASSWORD-ON-ARGV" >> {H.sq(log)};; esac
  env | grep -q '{password}' && echo "PASSWORD-IN-ENV" >> {H.sq(log)}
  for last; do :; done
  if [ "$pw" = {H.sq(password)} ]; then echo "LOGIN-OK" >> {H.sq(log)}; exec /bin/sh -c "$last"; fi
  echo "Permission denied (password)." >&2; exit 255
fi
exec {H.sq(H.ENV_BIN / 'ssh')} "$@"
""")
    os.chmod(f, 0o755)
    return str(f), log


def test_ssh_setup_install_password() -> None:
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        with vault.edit() as d:
            vault.host_record(d, "box")["host_keys"] = [t.host_key]
        fake, log = _fake_password_ssh(s, "login pass 1")
        s.set(tools={"ssh": fake}, ssh_authorized_keys=str(t.ak))
        try:
            ssh.install_key("box", "password", password="wrong one")
        except ssh.SshError as e:
            assert "didn't accept that password" in e.message
        else:
            raise AssertionError("wrong password accepted")
        line = ssh.install_key("box", "password", password="login pass 1")
        assert line.startswith("gateway: Claude's key is installed on box (SHA256:"), line
        pub = vault.live_keys(s.vault()["hosts"]["box"])[0]["public"]
        body = " ".join(pub.split()[:2])
        assert t.ak.read_text().count(body) == 1
        ssh.install_key("box", "password", password="login pass 1")   # idempotent
        assert t.ak.read_text().count(body) == 1
        text = log.read_text()
        assert text.count("LOGIN-OK") == 2 and "SECOND-ASK-ANSWERED" not in text
        assert "PASSWORD-IN-ENV" not in text and "PASSWORD-ON-ARGV" not in text
        assert not list(s.run_dir.glob("c-*"))           # FIFO and askpass removed
        # the password comes from the pop-up when not given
        s.set(popup={"secret": [["ok", "login pass 1"]]})
        ssh.install_key("box", "password")
        assert s.popup_calls()[-1]["what"] == "login password"
        # gated rechecks the host's ssh right before it hands the password over
        assert s.popup_calls()[-1]["check"] == {"section": "hosts", "entry": "box", "right": ["ssh"]}
        assert s.popup_calls()[-1]["remember"] is None, "used once by design: no Remember it"
        assert "login pass 1" not in str(s.audit())


def test_ssh_setup_install_my_login() -> None:
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        with vault.edit() as d:
            vault.host_record(d, "box")["host_keys"] = [t.host_key]
        upriv, upub = s.key("users-own")
        t.authorize(upub)
        (s.root / "user.pub").write_text(upub + "\n")
        ucfg = s.root / "user_ssh_config"
        ucfg.write_text(f"Host *\n  IdentitiesOnly yes\n  IdentityFile {s.root / 'user.pub'}\n")
        sock = s.run_dir / "user-agent.sock"
        agent = subprocess.Popen([str(H.ENV_BIN / "ssh-agent"), "-D", "-a", str(sock)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            while not sock.exists():
                time.sleep(0.01)
            subprocess.run([str(H.ENV_BIN / "ssh-add"), "-q", "-"], input=upriv.encode(),
                           env={"SSH_AUTH_SOCK": str(sock)}, check=True, capture_output=True)
            s.set(system_ssh=str(H.ENV_BIN / "ssh"), ssh_user_config=str(ucfg),
                  ssh_authorized_keys=str(t.ak))
            old = os.environ.get("SSH_AUTH_SOCK")
            os.environ["SSH_AUTH_SOCK"] = str(sock)
            try:
                line = ssh.install_key("box", "my-login")
            finally:
                if old is None:
                    os.environ.pop("SSH_AUTH_SOCK", None)
                else:
                    os.environ["SSH_AUTH_SOCK"] = old
            assert "Claude's key is installed on box" in line
            pub = vault.live_keys(s.vault()["hosts"]["box"])[0]["public"]
            assert t.ak.read_text().count(" ".join(pub.split()[:2])) == 1
            assert [a["method"] for a in s.audit("install_key")] == ["my-login"]
            # the user's own login is checked against the gateway's pinned host key
            with vault.edit() as d:
                vault.host_record(d, "box")["host_keys"] = [harness.fake_host_key("x")]
            s.set(keyscan={f"127.0.0.1:{t.port}": [harness.fake_host_key("x")]})
            os.environ["SSH_AUTH_SOCK"] = str(sock)
            try:
                ssh.install_key("box", "my-login")
            except ssh.SshError as e:
                assert "couldn't install Claude's key on box" in e.message
            else:
                raise AssertionError("installed past a wrong host key")
            finally:
                os.environ.pop("SSH_AUTH_SOCK", None)
        finally:
            agent.terminate()
            agent.wait(timeout=5)


def test_ssh_setup_rotate() -> None:
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        # review round 2: `gate rotate`'s copy is taken only when the rotation
        # is about to change the vault (before_change), never when it fails
        # first (here: no key of the gateway's on the host yet)
        calls: list[bytes] = []
        try:
            ssh.rotate("box", before_change=lambda: calls.append(paths.vault_path().read_bytes()))
        except ssh.SshError:
            pass
        else:
            raise AssertionError("a rotation without a key succeeded")
        assert calls == [], "before_change ran for a rotation that failed first"
        priv, old_pub = s.host("box", t)
        s.set(ssh_authorized_keys=str(t.ak))
        assert s.run("ssh", "box", "echo before").stdout == "before\n"
        line = ssh.rotate("box", before_change=lambda: calls.append(paths.vault_path().read_bytes()))
        assert "box has a new key (SHA256:" in line and "old one was removed" in line, line
        # once, just before the vault changed: the vault then held the old key alone
        assert len(calls) == 1
        snap = s.root / "before-rotate.age"
        snap.write_bytes(calls[0])
        then = json.loads(vault._decrypt(snap).decode())["hosts"]["box"]["keys"]
        assert [" ".join(k["public"].split()[:2]) for k in then] == [" ".join(old_pub.split()[:2])], then
        keys = s.vault()["hosts"]["box"]["keys"]
        live = vault.live_keys(s.vault()["hosts"]["box"])
        assert len(keys) == 2 and len(live) == 1 and live[0]["public"] != old_pub
        assert [k for k in keys if k["public"] == old_pub][0]["retired"]
        ak = t.ak.read_text()
        assert " ".join(old_pub.split()[:2]) not in ak
        assert ak.count(" ".join(live[0]["public"].split()[:2])) == 1
        assert not s.masters()                      # masters of the old key were closed
        r = s.run("ssh", "box", "echo after")
        assert r.returncode == 0 and r.stdout == "after\n", r
        assert s.audit("rotate")[-1]["new"] == live[0]["fingerprint"]
        # a failing rotation keeps the current key
        s.set(ssh_authorized_keys="/dev/null/authorized_keys")
        try:
            ssh.rotate("box")
        except ssh.SshError as e:
            assert "couldn't add the new key on box; the old key stays" in e.message
        else:
            raise AssertionError("rotation into an unwritable file succeeded")
        assert vault.live_keys(s.vault()["hosts"]["box"]) == live
        assert s.run("ssh", "box", "echo still").stdout == "still\n"


def test_ssh_setup_close_masters() -> None:
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        s.host("box", t)
        assert ssh.close_masters("box") == 0
        assert ssh.close_masters("nonexistent") == 0
        assert s.run("ssh", "box", "true").returncode == 0
        assert len(s.masters()) == 1
        assert ssh.close_masters("box") == 1
        assert not s.masters() and not (s.run_dir / "cm-box.list").exists()
        # narrowing the address closes masters too (consent.ratchet -> close_masters)
        assert s.run("ssh", "box", "true").returncode == 0
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nwhen = "127.0.0.0/8"\n')
        assert s.run("ssh", "box", "true").returncode == 0     # this run ratchets first
        assert t.accepted() == 3


def _lines(p: "os.PathLike[str]") -> list[str]:
    return [l for l in open(p).read().splitlines() if l.strip()]


def test_ssh_setup_authorized_keys_edits_are_line_safe() -> None:
    """ak_append_cmd / ak_remove_cmd on files the user wrote: no trailing
    newline, keys without a comment, options, commented-out keys. Matching
    is by whole fields (type + base64), never by substring."""
    with H.ssh_env() as s:
        f = s.root / "ak-test"
        s.set(ssh_authorized_keys=str(f))
        _upriv, upub = s.key("users-own")
        user_line = " ".join(upub.split()[:2])                  # no comment, no newline
        _gpriv, gpub = s.key("gateway-new")
        g_body = " ".join(gpub.split()[:2])
        f.write_text(f"# disabled: {g_body} old\n{user_line}")
        mode = 0o640
        os.chmod(f, mode)
        cmd = ssh.ak_append_cmd(gpub)
        assert str(f) in cmd and "$HOME" not in cmd               # never the real ~/.ssh
        for _ in range(2):                                        # idempotent
            subprocess.run(["/bin/sh", "-c", cmd], check=True)
        assert _lines(f) == [f"# disabled: {g_body} old", user_line, " ".join(gpub.split())]
        assert open(f).read().endswith("\n")
        # removing the gateway key: its own line only; the comment and the user's key stay
        subprocess.run(["/bin/sh", "-c", ssh.ak_remove_cmd([gpub])], check=True)
        assert _lines(f) == [f"# disabled: {g_body} old", user_line]
        assert os.stat(f).st_mode & 0o777 == mode                 # mode kept (cp -p + mv)
        # a line holding the key body only as part of another field isn't touched
        f.write_text(f'command="echo {g_body.split()[1]}" {user_line}\n')
        subprocess.run(["/bin/sh", "-c", ssh.ak_remove_cmd([gpub])], check=True)
        assert _lines(f) == [f'command="echo {g_body.split()[1]}" {user_line}']
        # options before the key don't hide it
        f.write_text(f'from="127.0.0.1",command="x" {gpub}\n{user_line}\n')
        subprocess.run(["/bin/sh", "-c", ssh.ak_remove_cmd([gpub])], check=True)
        assert _lines(f) == [user_line]


def test_ssh_setup_rotate_with_user_keys_and_no_newline() -> None:
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        s.host("box", t)
        _upriv, upub = s.key("users-own")
        with open(t.ak, "a") as fh:
            fh.write(f'command="{t.wrapper}" {upub}')               # the user's key, last, no \n
        s.set(ssh_authorized_keys=str(t.ak))
        old = vault.live_keys(s.vault()["hosts"]["box"])[0]["public"]
        line = ssh.rotate("box")
        assert "box has a new key" in line and "old one was removed" in line, line
        new = vault.live_keys(s.vault()["hosts"]["box"])[0]["public"]
        ak = _lines(t.ak)
        assert len(ak) == 2 and ak[0].endswith(upub) and ak[1] == " ".join(new.split()), ak
        assert " ".join(old.split()[:2]) not in t.ak.read_text()
        assert s.run("ssh", "box", "echo after").stdout == "after\n"


def test_ssh_setup_rotate_failure_keeps_every_other_line() -> None:
    """The new key doesn't work (it went to a file sshd doesn't read): only
    the new key's line is removed again; the user's key and the current
    gateway key stay, as the message says."""
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        _priv, cur = s.host("box", t)
        _upriv, upub = s.key("users-own")
        other = s.root / "elsewhere-authorized_keys"
        other.write_text(f"{' '.join(cur.split())}\n{' '.join(upub.split()[:2])}")   # no \n
        s.set(ssh_authorized_keys=str(other))
        live = vault.live_keys(s.vault()["hosts"]["box"])
        try:
            ssh.rotate("box")
        except ssh.SshError as e:
            assert "the new key didn't work on box; the old key stays" in e.message
        else:
            raise AssertionError("rotation with an unusable new key succeeded")
        assert _lines(other) == [" ".join(cur.split()), " ".join(upub.split()[:2])]
        assert vault.live_keys(s.vault()["hosts"]["box"]) == live
        assert s.run("ssh", "box", "echo still").stdout == "still\n"


def test_ssh_setup_rotate_raising_verification_removes_the_new_line() -> None:
    """Round 1 (LOW): when the check of the new key raised (instead of
    returning non-zero), only the vault copy of the new key was dropped and
    its authorized_keys line stayed on the server. Now the line is removed
    over the old key in every failure before the new key is verified."""
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        _priv, cur = s.host("box", t)
        s.set(ssh_authorized_keys=str(t.ak))
        before = _lines(t.ak)
        live = vault.live_keys(s.vault()["hosts"]["box"])
        real_fresh = ssh._fresh

        def raising_fresh(link, keys):
            raise ssh.SshError("gateway: simulated failure while checking the new key", 255)
        ssh._fresh = raising_fresh
        try:
            ssh.rotate("box")
        except ssh.SshError as e:
            assert "simulated failure" in e.message
        else:
            raise AssertionError("rotation with a raising check succeeded")
        finally:
            ssh._fresh = real_fresh
        assert _lines(t.ak) == before, (before, _lines(t.ak))
        assert vault.live_keys(s.vault()["hosts"]["box"]) == live
        assert s.run("ssh", "box", "echo still").stdout == "still\n"


def test_ssh_setup_run_in_process() -> None:
    """ssh.run: the gate process's own runner (copy-to): captured output,
    audited, the host's ssh right still applies."""
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        s.host("box", t)
        rc, out, err = ssh.run("box", "cat; echo err >&2; exit 4", input=b"data\n")
        assert (rc, out, err) == (4, b"data\n", b"err\n")
        use = s.audit("use")[-1]
        assert use["tool"] == "gate" and use["target"] == "box" and use["address"] == t.addr()
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nssh = false\n')
        n = len(t.commands())
        try:
            ssh.run("box", "true")
        except ssh.SshError as e:
            assert "ssh is off for box" in e.message
        else:
            raise AssertionError("ssh.run ignored ssh = false")
        assert len(t.commands()) == n
        try:
            ssh.run("nosuch", "true")
        except ssh.SshError as e:
            assert "isn't a host in gateway.toml" in e.message
        else:
            raise AssertionError("ssh.run on an unknown host")


def test_ssh_setup_gate_helpers_audited() -> None:
    """Every gate-check helper that logs in with the gateway's key writes an
    audit `use` line (tool gate): test_login, the NOPASSWD probe (not when
    cached), the sudo password check (the password never in the log), rotate."""
    pw = "correct horse battery"
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        s.host("box", t)
        s.set(ssh_authorized_keys=str(t.ak))

        def uses() -> list[dict]:
            return [u for u in s.audit("use") if u["tool"] == "gate"]

        assert ssh.test_login("box")[0] is True
        u = uses()[-1]
        assert (u["target"], u["argv"], u["address"]) == ("box", "ssh box true", t.addr()), u
        assert ssh.probe_remote_nopasswd("box", H.real_user()) is False
        assert uses()[-1]["argv"] == "ssh box sudo -n true" and len(uses()) == 2
        assert ssh.probe_remote_nopasswd("box", H.real_user()) is False     # cached: no login
        assert len(uses()) == 2
        assert ssh.verify_remote_sudo("box", H.real_user(), pw)[0] is True
        u = uses()[-1]
        assert u["argv"] == "ssh box sudo -k -A -v" and u["remote_sudo"] is True, u
        assert pw not in str(s.audit())
        assert ssh.verify_remote_sudo("box", H.real_user(), "short")[0] is False   # no login
        assert len(uses()) == 3
        ssh.rotate("box")
        assert uses()[-1]["argv"] == "ssh box rotate" and len(uses()) == 4
        assert all(u["address"] == t.addr() for u in uses())


def test_ssh_setup_helpers_honour_the_ssh_right() -> None:
    """Review round 2: the gateway's own helpers (test_login, the NOPASSWD
    probe, the sudo password check, rotate, run) logged in with
    Claude's key to a host whose ssh was false or "ask"; rotate rewrote its
    authorized_keys. Off refuses; "ask" needs the user present (a pop-up job,
    or a command Claude typed, which the approval hook asks about)."""
    from gateway import ancestry, popup, ssh_sudo
    pw = "correct horse battery"
    user = H.real_user()
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        s.host("box", t)
        s.set(ssh_authorized_keys=str(t.ak))
        assert ssh.test_login("box")[0] is True
        real_typed = ancestry.typed_by_claude

        def refused(right: str, frag: str) -> None:
            ancestry.typed_by_claude = lambda: (False, "make")
            before, ak = t.accepted(), t.ak.read_text()
            keys = s.vault()["hosts"]["box"]["keys"]
            ok, msg = ssh.test_login("box")
            assert not ok and frag in msg, (right, msg)
            for call in (lambda: ssh.rotate("box"), lambda: ssh.run("box", "true")):
                try:
                    call()
                    raise AssertionError(right)
                except ssh.SshError as e:
                    assert frag in e.message, (right, e.message)
            ssh_sudo.probe_clear("box")
            try:
                ssh.probe_remote_nopasswd("box", user)
                raise AssertionError(right)
            except ssh.SshError as e:
                assert frag in e.message
            ok, msg = ssh.verify_remote_sudo("box", user, pw)
            assert not ok and frag in msg, (right, msg)
            assert t.accepted() == before, (right, "no login with Claude's key")
            assert t.ak.read_text() == ak and s.vault()["hosts"]["box"]["keys"] == keys

        try:
            s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nssh = "ask"\n')
            refused('"ask"', 'ssh on box is set to "ask"')
            # "ask" with the user present: a pop-up job, or a command Claude typed
            old = popup._MODE
            popup._MODE = "direct"
            try:
                assert ssh.test_login("box")[0] is True
            finally:
                popup._MODE = old
            ancestry.typed_by_claude = lambda: (True, "")
            assert ssh.test_login("box")[0] is True
            s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nssh = false\n')
            refused("false", "ssh is off for box")
            old = popup._MODE
            popup._MODE = "direct"
            try:
                assert not ssh.test_login("box")[0], "off stays off, user present or not"
            finally:
                popup._MODE = old
        finally:
            ancestry.typed_by_claude = real_typed


def test_gate_check_never_probes_a_host_whose_ssh_is_off() -> None:
    """gate check's plan ran the remote `sudo -n true` probe even with ssh =
    false (review round 2)."""
    from gateway import consent, gate_setup
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        s.host("box", t)
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nssh = false\n')
        consent.ratchet()
        before = t.accepted()
        form, eff, data = gate_setup._load()
        p = gate_setup.plan_for("box", form, eff, data)
        assert not p.needs_sudo and not p.needs_key and t.accepted() == before


# ---------------------------------------------------------------------------
# Review round 3
# ---------------------------------------------------------------------------


def _quiet(fn, *args, **kw):
    import contextlib
    import io
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = fn(*args, **kw)
    return rc, out.getvalue(), err.getvalue()


def test_gate_check_notices_a_key_removed_from_the_host() -> None:
    """Round 3: with `installed` set, gate check never tried a login, so after
    the key left authorized_keys it said "ready ... key installed" while the
    stand-in said the host refused Claude's key."""
    from gateway import gate_setup
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        s.host("box", t)
        ok, _m = ssh.test_login("box")
        assert ok and s.vault()["hosts"]["box"]["installed"]
        t.ak.write_text("")                                  # the user removed the key
        r = s.run("ssh", "box", "echo hi")
        assert r.returncode == 255 and "box refused Claude's key" in r.stderr, r
        assert "installed" not in s.vault()["hosts"]["box"], "the stand-in forgets `installed`"
        form, eff, data = gate_setup._load()
        assert "key installed" not in gate_setup.status_line("box", form, eff, data)
        # gate check: a test login, so the key is installed again
        with vault.edit() as d:
            vault.host_record(d, "box")["installed"] = vault.now()   # as before round 3
        form, eff, data = gate_setup._load()
        p = gate_setup.plan_for("box", form, eff, data)
        assert p.needs_key and any("refused Claude's key" in n for n in p.notes), p
        assert "installed" not in s.vault()["hosts"]["box"]
        # a working key: nothing to do, no pop-up
        t.authorize(vault.live_keys(s.vault()["hosts"]["box"])[0]["public"])
        form, eff, data = gate_setup._load()
        p = gate_setup.plan_for("box", form, eff, data)
        assert not p.needs_key and not p.notes, p
        assert s.vault()["hosts"]["box"]["installed"], "the test login recorded it"


def test_gate_check_reads_the_host_key_of_a_host_that_is_set_up() -> None:
    """Round 3: with pins, gate check never re-read the host key, so after the
    stand-in said "box's host key changed ... ask the user to run gate check
    box", gate check printed "ready" and opened nothing."""
    from gateway import gate_setup, popup
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        s.host("box", t, pins=[harness.fake_host_key("old")])
        with vault.edit() as d:
            vault.host_record(d, "box")["installed"] = vault.now()
        form, eff, data = gate_setup._load()
        p = gate_setup.plan_for("box", form, eff, data)
        assert p.mismatch and p.scanned == [t.host_key] and p.anything(), p
        rc, out, err = _quiet(gate_setup.check_one, "box")    # no screen under the test override
        assert rc == 1 and "ready" not in out, (out, err)
        assert "nothing was asked" in err and popup.pending("box") == [], err


def test_gate_check_stops_for_a_jump_host_that_isnt_set_up() -> None:
    """Round 3: `gate check inner` (via gw1, gw1 not set up) said it couldn't
    read the host key, opened the consent pop-up, skipped the key and printed
    "inner ready: ssh off ..." with exit 0; `gate check all` hit it whenever
    inner came first in the form."""
    from gateway import gate_setup, popup
    with H.ssh_env() as s:
        j = s.sshd("jump")
        t = s.sshd("target")
        u = H.real_user()
        s.write_form(f'[hosts.inner]\naddress = "{u}@127.0.0.1:{t.port}"\nvia = "gw1"\n\n'
                     f'[hosts.gw1]\naddress = "{j.addr()}"\n')
        rc, out, err = _quiet(gate_setup.check_one, "inner")
        assert rc == 1 and out == "", (out, err)
        assert ("gateway: inner goes through gw1, which isn't set up yet; run gate check gw1 first, "
                "then gate check inner") in err, err
        assert popup.pending() == [] and t.accepted() == 0 and j.accepted() == 0
        form = s.env.form()
        assert gate_setup.hosts_jumps_first(form) == ["gw1", "inner", "localhost"]
        # once gw1 is set up, inner's own setup goes ahead (its key scanned through gw1)
        s.approve()
        s.host("gw1", j)
        with vault.edit() as d:
            vault.host_record(d, "gw1")["installed"] = vault.now()
        form, eff, data = gate_setup._load()
        assert gate_setup.jump_problem("inner", form, eff, data) is None
        p = gate_setup.plan_for("inner", form, eff, data)
        assert p.error is None and p.scanned == [t.host_key], p


def test_keyscan_failure_shows_the_ssh_reason() -> None:
    from gateway import gate_setup, form as F
    from pathlib import Path
    h = F.parse_text('[hosts.inner]\naddress = "u@10.9.9.9"\nvia = "gw1"\n[hosts.gw1]\n'
                     'address = "u@gw1.example.com"\n', Path("/x")).hosts["inner"]

    def boom(name):
        raise ssh.SshError("gateway: inner is reached via gw1, which is off or missing; see gate status")
    real = ssh.keyscan_host
    ssh.keyscan_host = boom
    try:
        keys, why = gate_setup._keyscan("inner", h)
    finally:
        ssh.keyscan_host = real
    assert keys == [] and why == "inner is reached via gw1, which is off or missing; see gate status"


def test_my_login_finds_the_users_agent_without_ssh_auth_sock() -> None:
    """Round 3: gate check runs in Claude's Bash, where SSH_AUTH_SOCK is unset
    (others = "refuse"); only macOS's launchd was asked, so on Linux "use my
    own SSH login once" had no agent. The session record (Claude Code's own
    environment) names it; on Linux the usual $XDG_RUNTIME_DIR sockets too."""
    from gateway import paths
    with H.ssh_env() as s:
        t = s.sshd("target")
        _approved(s, t)
        with vault.edit() as d:
            vault.host_record(d, "box")["host_keys"] = [t.host_key]
        upriv, upub = s.key("users-own")
        t.authorize(upub)
        (s.root / "user.pub").write_text(upub + "\n")
        ucfg = s.root / "user_ssh_config"
        ucfg.write_text(f"Host *\n  IdentitiesOnly yes\n  IdentityFile {s.root / 'user.pub'}\n")
        xdg = s.run_dir / "xdg"
        (xdg / "keyring").mkdir(parents=True)
        sock = xdg / "keyring" / "ssh"
        agent = subprocess.Popen([str(H.ENV_BIN / "ssh-agent"), "-D", "-a", str(sock)],
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sessions = paths.private_dir() / "sessions"
        sessions.mkdir(parents=True, exist_ok=True)
        saved = {k: os.environ.pop(k, None) for k in ("SSH_AUTH_SOCK", "CLAUDE_CODE_SESSION_ID",
                                                       "XDG_RUNTIME_DIR")}
        os.environ["CLAUDE_CODE_SESSION_ID"] = "sess-agent"
        try:
            while not sock.exists():
                time.sleep(0.01)
            subprocess.run([str(H.ENV_BIN / "ssh-add"), "-q", "-"], input=upriv.encode(),
                           env={"SSH_AUTH_SOCK": str(sock)}, check=True, capture_output=True)
            s.set(system_ssh=str(H.ENV_BIN / "ssh"), ssh_user_config=str(ucfg),
                  ssh_authorized_keys=str(t.ak))
            rec = sessions / "sess-agent.env"
            # a planted path that isn't the user's socket is never used
            (s.root / "not-a-socket").write_text("")
            rec.write_text(f"started=1\nSSH_AUTH_SOCK={s.root / 'not-a-socket'}\n")
            assert ssh._user_agent_sock() is None
            try:
                ssh.install_key("box", "my-login")
            except ssh.SshError as e:
                assert "couldn't install Claude's key on box" in e.message
            else:
                raise AssertionError("installed without the user's agent")
            # the session record names the agent (production: SSH_AUTH_SOCK unset)
            rec.write_text(f"started=1\nSSH_AUTH_SOCK={sock}\n")
            assert "SSH_AUTH_SOCK" not in os.environ
            line = ssh.install_key("box", "my-login")
            assert "Claude's key is installed on box" in line, line
            # Linux: the usual socket under XDG_RUNTIME_DIR from the record
            rec.write_text(f"started=1\nXDG_RUNTIME_DIR={xdg}\n")
            assert ssh._user_agent_sock() == str(sock)
            # nothing recorded or set: production looks in /run/user/<uid> on Linux; under a
            # test override never the machine's own folder (the Debian VM has a systemd
            # agent socket there), only the one a test names
            rec.write_text("started=1\n")
            assert ssh._user_agent_sock() is None
            s.set(linux_runtime_dir=str(xdg))
            assert ssh._user_agent_sock() == str(sock)
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
            agent.terminate()
            agent.wait(timeout=5)


def test_gate_check_of_a_silent_host_behind_a_jump_stops_quickly_and_asks_nothing() -> None:
    """Review round 4: _scan_via tried all three key types with a 10 s
    connect timeout each against a host that doesn't answer (30 s), then the
    consent pop-up waited its full 90 s: past Claude Code's 2-minute Bash
    timeout, before gate check printed anything. Now one attempt, then a stop
    before any pop-up."""
    from gateway import gate_setup, popup
    with H.ssh_env() as s:
        j = s.sshd("jump")
        hole = s.blackhole()
        u = H.real_user()
        s.write_form(f'[hosts.gw1]\naddress = "{j.addr()}"\n\n'
                     f'[hosts.inner]\naddress = "{u}@127.0.0.1:{hole.port}"\nvia = "gw1"\n')
        s.approve()
        s.host("gw1", j)
        with vault.edit() as d:
            vault.host_record(d, "gw1")["installed"] = vault.now()
            d["approved"]["rights"]["hosts"].pop("inner", None)    # inner: brand new
        t0 = time.time()
        rc, out, err = _quiet(gate_setup.check, "inner")
        took = time.time() - t0
        assert rc == 1 and "nothing was asked" in err, (rc, out, err)
        assert took < 25, f"took {took:.1f} s (one connect timeout, not three)"
        assert popup.pending() == [], "no pop-up was opened or left waiting"
        assert "inner" not in (vault.load().get("approved") or {}).get("rights", {}).get("hosts", {})
