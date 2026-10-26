"""Policy, workspaces and remote imports in the form (PLAN-v4 phase 7):
parsing, consent (a raised key waits for the user's OK, a lowered one applies
at once), decisions (strictest wins, never above the rights, the concrete
rule behind every refusal, a read grant never implies another action), and
the ssh stand-in enforcing them against a real local sshd (exec, read,
write, workspaces, forwarding)."""
from __future__ import annotations

from pathlib import Path

import harness as H
import harness_ssh as HS
from gateway import consent, policy, vault
from gateway import form as F


def parse(t: str) -> F.Form:
    return F.parse_text(t, Path("/x"))


def run(old: str, new: str) -> consent.Effective:
    data = {"approved": {"rights": consent.snapshot(parse(old))}}
    return consent.compute(parse(new), data)


HOST = '[hosts.box]\naddress = "u@box.example.com"\n'


# ---------------------------------------------------------------------------
# The form
# ---------------------------------------------------------------------------


def test_the_form_reads_policy_workspaces_and_a_hosts_imports():
    f = parse('[policy]\nexec = "ask"\nforward_x11 = "deny"\n'
              + HOST + '[hosts.box.policy]\nwrite = "deny"\nforward_agent = "allow"\n'
              '[hosts.box.workspaces.app]\nroot = "/srv/my app/ü"\nlocal = "~/src/app"\n'
              'exec = false\n'
              '[hosts.box.shell]\nimport_path = ["/opt/cuda/bin", "~/.cargo/bin"]\n'
              'import_env = ["CUDA_HOME"]\n'
              '[hosts.localhost.workspaces.notes]\nroot = "~/notes"\n'
              '[accounts.gh]\nkind = "github"\n[accounts.gh.policy]\nwrite = "ask"\n')
    assert f.ok, f.report_lines()
    assert f.policy == {"exec": "ask", "forward_x11": False}
    h = f.hosts["box"]
    assert h.policy == {"write": False, "forward_agent": True}
    w = h.workspaces["app"]
    assert (w.root, w.local, w.policy) == ("/srv/my app/ü", "~/src/app", {"exec": False})
    assert h.shell.import_path == ["/opt/cuda/bin", "~/.cargo/bin"] and h.shell.import_env == ["CUDA_HOME"]
    assert f.hosts["localhost"].workspaces["notes"].root == "~/notes"
    assert f.accounts["gh"].policy == {"write": "ask"}


def test_a_bad_policy_key_or_value_fails_closed():
    # a misspelt restriction on a host turns the host off (never quietly unenforced)
    f = parse(HOST + '[hosts.box.policy]\nexce = "deny"\n')
    assert "box" in f.disabled and "box" not in f.hosts
    f = parse(HOST + '[hosts.box.policy]\nexec = "maybe"\n')
    assert "box" in f.disabled
    # grants and remote-only actions don't apply to localhost
    f = parse('[hosts.localhost.policy]\nforward_agent = "allow"\n')
    assert "localhost" in f.disabled
    # a workspace with a bad root or an unknown key turns its host off
    for ws in ('root = "relative/path"', 'root = "/a/../b"', 'root = "/ok"\nbogus = 1'):
        f = parse(HOST + f"[hosts.box.workspaces.w]\n{ws}\n")
        assert "box" in f.disabled, ws
    # [policy]: a bad value counts as deny until fixed; it can't grant forwarding
    f = parse('[policy]\nexec = "sometimes"\nforward_agent = "allow"\n')
    assert f.policy == {"exec": False, "forward_agent": False}
    assert len(f.errors) == 2
    # a credential-looking or plumbing name is never a remote import
    f = parse(HOST + '[hosts.box.shell]\nimport_env = ["API_TOKEN"]\n')
    assert "box" in f.disabled


# ---------------------------------------------------------------------------
# Consent
# ---------------------------------------------------------------------------


def test_raising_or_removing_a_restriction_and_granting_forwarding_wait_for_the_ok():
    base = HOST + '[hosts.box.policy]\nexec = "deny"\n'
    e = run(base, HOST + '[hosts.box.policy]\nexec = "allow"\n')
    raised = ("policy exec: in Plan mode Claude Code decides; elsewhere no restriction (was: refused "
              "in every mode)")
    assert any(raised == c.what for c in e.pending_for("box")), e.pending
    assert e.hosts["box"].policy == {"exec": False}           # the approved value applies
    e = run(base, HOST)                                       # the table removed
    assert any(raised == c.what for c in e.pending_for("box")), e.pending   # (absent: none)
    assert policy.decide(e, "exec", host="box").word is False
    e = run(HOST, HOST + '[hosts.box.policy]\nforward_agent = "allow"\n')
    assert any("policy forward_agent: in Plan mode Claude Code decides; elsewhere it is on (was: "
               "off in every mode)" in c.what for c in e.pending_for("box")), e.pending
    assert policy.decide(e, "forward_agent", host="box").word is False
    # global restrictions belong to "settings"
    e = run('[policy]\nwrite = "deny"\n', '[policy]\nwrite = "ask"\n')
    assert any(c.entry == "settings" and c.what == "policy write: in every mode you are asked (was: "
               "refused in every mode)" for c in e.pending), e.pending
    assert e.policy == {"write": False}
    # an account's
    gh = '[accounts.gh]\nkind = "github"\n'
    e = run(gh + '[accounts.gh.policy]\nwrite = "deny"\n', gh)
    assert any(c.entry == "gh" for c in e.pending) and e.accounts["gh"].policy == {"write": False}


def test_lowering_or_adding_a_restriction_applies_at_once_and_the_ratchet_keeps_it():
    e = run(HOST, HOST + '[hosts.box.policy]\nwrite = "deny"\n')
    assert not e.pending and any("policy write" in c.what for c in e.narrowed)
    assert policy.decide(e, "write", host="box").word is False
    with H.gateway_env() as env:
        env.write_form(HOST)
        consent.approve_all(env.form())
        env.write_form(HOST + '[hosts.box.policy]\nwrite = "deny"\n')
        assert consent.ratchet(env.form())
        # put the restriction back out of the form: that is a widening now
        env.write_form(HOST)
        from gateway import vault
        eff = consent.compute(env.form(), vault.load())
        assert any("policy write" in c.what for c in eff.pending_for("box"))
        assert policy.decide(eff, "write", host="box").word is False


def test_a_new_or_moved_workspace_waits_for_the_ok_and_a_removed_one_goes_at_once():
    ws = '[hosts.box.workspaces.app]\nroot = "/srv/app"\n'
    e = run(HOST, HOST + ws)
    assert any("new workspace app (root /srv/app)" in c.what for c in e.pending_for("box"))
    assert "app" not in e.hosts["box"].workspaces
    d = policy.decide(e, "exec", host="box", workspace="app")
    assert d.word is False and "waits for the user's OK" in d.rule
    e = run(HOST + ws, HOST + ws.replace("/srv/app", "/etc"))
    assert any("workspace app root /etc (was /srv/app)" in c.what for c in e.pending_for("box"))
    assert e.hosts["box"].workspaces["app"].root == "/srv/app"    # the approved root still
    e = run(HOST + ws, HOST)
    assert any("workspace app removed" in c.what for c in e.narrowed) and not e.pending


def test_renaming_a_restricted_workspace_keeps_the_old_one_binding_until_the_ok():
    ws = '[hosts.box.workspaces.prod]\nroot = "/srv/prod"\nexec = "deny"\nread = "deny"\n'
    # renamed (without its restrictions): the new name waits as a new workspace,
    # the old one still binds with its root and restrictions
    e = run(HOST + ws, HOST + '[hosts.box.workspaces.prod2]\nroot = "/srv/prod"\n')
    whats = [c.what for c in e.pending_for("box")]
    assert any("new workspace prod2" in w for w in whats) and \
        any("workspace prod removed" in w for w in whats), whats
    assert not e.narrowed and list(e.hosts["box"].workspaces) == ["prod"]
    assert policy.decide(e, "exec", host="box", workspace="prod").word is False
    from gateway import ssh_args
    assert ssh_args.decide_path(e, "read", "box", "/srv/prod/x").word is False


def test_removing_or_renaming_a_restricted_workspace_waits_for_the_ok():
    ws = '[hosts.box.workspaces.prod]\nroot = "/srv/prod"\nexec = "deny"\nread = "deny"\n'
    # the table deleted by an edit: a widening; the approved root and restrictions still bind
    e = run(HOST + ws, HOST)
    assert not e.narrowed, [c.what for c in e.narrowed]
    assert any("workspace prod removed (root /srv/prod" in c.what and 'read "deny"' in c.what
               and 'exec "deny"' in c.what for c in e.pending_for("box")), e.pending
    ew = e.hosts["box"].workspaces["prod"]
    assert ew.root == "/srv/prod" and ew.policy == {"exec": False, "read": False}
    for act in ("exec", "read"):
        d = policy.decide(e, act, host="box", workspace="prod")
        assert d.word is False and d.rule.startswith(f'[hosts.box.workspaces.prod] {act} = "deny"')
        assert "waits for the user's OK" in d.message(), d.message()
    # a path under its root still maps to it (the ssh stand-in, gated's binding)
    from gateway import ssh_args
    assert ssh_args.decide_path(e, "read", "box", "/srv/prod/secret").word is False
    # the ratchet keeps it approved; the user's OK removes it
    with H.gateway_env() as env:
        from gateway import vault
        env.write_form(HOST + ws)
        consent.approve_all(env.form())
        env.write_form(HOST)
        assert consent.ratchet(env.form()) == []
        ap = vault.load()["approved"]["rights"]["hosts"]["box"]
        assert ap["workspaces"]["prod"]["policy"] == {"exec": False, "read": False}, ap
        eff = consent.compute(env.form(), vault.load())
        assert policy.decide(eff, "read", host="box", workspace="prod").word is False
        consent.approve("box", eff.pending_for("box"), env.form())
        eff = consent.compute(env.form(), vault.load())
        assert "prod" not in eff.hosts["box"].workspaces and not eff.pending
    # `gate workspace remove` (the /gate-hosts pane) says so truthfully
    with H.gateway_env() as env:
        import contextlib
        import io
        from gateway import manage
        env.write_form(HOST + ws + '[hosts.box.workspaces.app]\nroot = "/srv/app"\n')
        consent.approve_all(env.form())
        for name, want in (("prod", "keeps applying until the user approves"),
                           ("app", "a narrowing: it applies at once")):
            buf = io.StringIO()
            with contextlib.redirect_stdout(buf):
                assert manage.main("workspace", ["remove", "box", name]) == 0
            assert want in buf.getvalue(), (name, buf.getvalue())
        eff = consent.compute(env.form(), vault.load())
        assert list(eff.hosts["box"].workspaces) == ["prod"]
    # a workspace that restricts nothing (or only says "allow") goes at once
    e = run(HOST + '[hosts.box.workspaces.app]\nroot = "/srv/app"\nread = "allow"\n', HOST)
    assert any("workspace app removed" in c.what for c in e.narrowed) and not e.pending
    assert "app" not in e.hosts["box"].workspaces


# ---------------------------------------------------------------------------
# Decisions
# ---------------------------------------------------------------------------


def test_the_panes_edits_name_this_machine_as_localhost_and_a_new_host_cant_take_the_name():
    """`gate workspace add|remove localhost ...` and `gate host set localhost ...`
    (the /gate-hosts edit line) edit this machine's entry; localhost stays
    reserved as the NAME of a new host, and the other reserved words stay
    refused everywhere."""
    import contextlib
    import io
    from gateway import manage

    def gate(*argv: str) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = manage.main(argv[0], list(argv[1:]))
        return rc, out.getvalue() + err.getvalue()

    with H.gateway_env() as env:
        proj = env.root / "proj"
        proj.mkdir()
        env.write_form(HOST)
        consent.approve_all(env.form())
        rc, out = gate("workspace", "add", "localhost", "proj", str(proj))
        assert rc == 0, out
        text = env.form_path.read_text()
        assert "[hosts.localhost.workspaces.proj]" in text, text
        assert "wait" in out and "gate check localhost" in out, out      # a widening: the OK first
        eff = consent.compute(env.form(), vault.load())
        assert "proj" not in eff.hosts["localhost"].workspaces          # not approved yet
        consent.approve_all(env.form())
        eff = consent.compute(env.form(), vault.load())
        assert "proj" in eff.hosts["localhost"].workspaces
        rc, out = gate("host", "set", "localhost", "sudo", "ask")
        assert rc == 0, out
        assert F.load(use_cache=False).hosts["localhost"].explicit
        rc, out = gate("workspace", "remove", "localhost", "proj")
        assert rc == 0 and "removed workspace proj from localhost" in out, out
        assert "proj" not in F.load(use_cache=False).hosts["localhost"].workspaces
        # reserved: a new host named localhost, and the other reserved words anywhere
        rc, out = gate("host", "add", "localhost", "me@127.0.0.1")
        assert rc == 2 and "reserved word" in out, out
        for word in ("local", "all", "this", "gateway"):
            rc, out = gate("workspace", "add", word, "proj", str(proj))
            assert rc == 2 and "reserved word" in out, (word, out)
            rc, out = gate("host", "set", word, "sudo", "ask")
            assert rc == 2 and "reserved word" in out, (word, out)
        rc, out = gate("workspace", "add", "localhost", "all", str(proj))
        assert rc == 2 and "reserved word" in out, out                   # a workspace's own name


def test_strictest_wins_and_never_above_the_rights_with_the_concrete_rule():
    f = ('[policy]\nexec = "ask"\n' + HOST + 'sudo = true\n'
         '[hosts.box.policy]\nwrite = "deny"\n'
         '[hosts.box.workspaces.app]\nroot = "/srv/app"\nexec = "deny"\n')
    e = run(f, f)
    d = policy.decide(e, "exec", host="box")
    assert d.word == "ask" and d.rule == '[policy] exec = "ask" (gateway.toml line 2)'
    d = policy.decide(e, "exec", host="box", workspace="app")
    assert d.word is False and d.rule.startswith('[hosts.box.workspaces.app] exec = "deny"')
    d = policy.decide(e, "write", host="box")
    assert d.word is False and d.rule.startswith('[hosts.box.policy] write = "deny" (gateway.toml line')
    assert "write" in d.message() and d.rule in d.message()
    # elevation needs exec too; and a host's ssh = false caps everything
    assert policy.decide(e, "elevation", host="box").word == "ask"
    off = HOST + 'ssh = false\n[hosts.box.policy]\nread = "allow"\n'
    e = run(off, off)
    for act in ("read", "exec", "write", "provision", "network"):
        d = policy.decide(e, act, host="box")
        assert d.word is False and d.rule.startswith("[hosts.box] ssh = false"), (act, d.rule)
    # forwarding is off unless the host's own policy turns it on, whatever ssh says
    e = run(HOST, HOST)
    d = policy.decide(e, "forward_x11", host="box")
    assert d.word is False and "has no forward_x11" in d.rule
    # unknown hosts and accounts
    assert "no host nowhere" in policy.decide(e, "exec", host="nowhere").rule


def test_a_read_grant_never_implies_exec_write_elevation_or_credentials():
    f = (HOST + 'sudo = true\n[hosts.box.policy]\nread = "allow"\nexec = "deny"\nwrite = "deny"\n'
         'provision = "deny"\n'
         '[accounts.gh]\nkind = "github"\n[accounts.gh.policy]\ncredential = "deny"\n')
    e = run(f, f)
    from gateway.daemon import lifecycle
    r = lifecycle.contract_rights(e, host="box")
    assert r["read"] == "allow"
    assert r["exec"] == r["write"] == r["elevation"] == r["provision"] == "deny", r
    assert all(r[g] == "deny" for g in F.POLICY_GRANT)
    assert policy.decide(e, "credential", account="gh").word is False
    # raising read (or anything else) never moves another action
    f2 = f.replace('read = "allow"\n', "")
    e2 = run(f2, f2)
    for act in ("exec", "write", "elevation", "provision", "credential"):
        if act == "credential":
            assert policy.decide(e2, act, account="gh").word is False
        else:
            assert policy.decide(e2, act, host="box").word == policy.decide(e, act, host="box").word


def test_localhost_actions_follow_claude_codes_own_permissions_and_sudo():
    f = '[hosts.localhost]\nsudo = false\n[hosts.localhost.policy]\nnetwork = "deny"\n'
    e = run(f, f)
    assert policy.decide(e, "exec").word is True and policy.decide(e, "read").word is True
    d = policy.decide(e, "elevation")
    assert d.word is False and d.rule.startswith("[hosts.localhost] sudo = false")
    assert policy.decide(e, "network").word is False
    assert policy.decide(e, "write").word is True             # not a localhost action


# ---------------------------------------------------------------------------
# The ssh stand-in against a real sshd
# ---------------------------------------------------------------------------


def _box(s: HS.SshEnv, extra: str = "") -> HS.Sshd:
    t = s.sshd("target")
    s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n{extra}')
    s.approve()
    s.host("box", t)
    return t


def test_the_ssh_stand_in_decides_exec_read_and_write_each_on_its_own():
    with HS.ssh_env() as s:
        t = _box(s)
        d = t.dir / "data"
        d.mkdir()
        (d / "remote.txt").write_text("from the host\n")
        local = s.root / "up.txt"
        local.write_text("to the host\n")
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n'
                     '[hosts.box.policy]\nexec = "deny"\nwrite = "deny"\n')
        r = s.run("ssh", "box", "echo should-not-run")
        assert r.returncode == 2 and "should-not-run" not in r.stdout
        assert '[hosts.box.policy] exec = "deny" (gateway.toml line 4)' in r.stderr, r.stderr
        # a download is a read: allowed (the default scp protocol is sftp: the
        # stand-in tells the direction by scp's own operands)
        r = s.run("scp", f"box:{d}/remote.txt", str(s.root / "down.txt"))
        assert r.returncode == 0 and (s.root / "down.txt").read_text() == "from the host\n", r
        r = s.run("scp", "-O", f"box:{d}/remote.txt", str(s.root / "down2.txt"))
        assert r.returncode == 0, r
        # an upload is a write: refused, in both protocols, nothing written
        for opts in ([], ["-O"]):
            r = s.run("scp", *opts, str(local), f"box:{d}/up.txt")
            assert r.returncode != 0 and "write" in r.stderr and not (d / "up.txt").exists(), (opts, r)
        # sftp may do both: refused while write is denied
        r = s.run("sftp", "-b", "-", "box", input=f"ls {d}\n")
        assert r.returncode != 0 and 'write = "deny"' in r.stderr, r
        # a shell line that only starts like a transfer is exec
        r = s.run("ssh", "box", f"scp -f {d}/remote.txt; echo injected")
        assert r.returncode == 2 and "injected" not in r.stdout and "exec" in r.stderr
        refusals = [x for x in s.audit("refusal") if x.get("target") == "box"]
        assert refusals and all("deny" in x["reason"] for x in refusals)


def test_a_workspace_restricts_writes_under_its_root_only():
    with HS.ssh_env() as s:
        t = _box(s)
        ro, rw = t.dir / "ro", t.dir / "rw"
        ro.mkdir()
        rw.mkdir()
        f = s.root / "f.txt"
        f.write_text("x\n")
        form = (f'[hosts.box]\naddress = "{t.addr()}"\n'
                f'[hosts.box.workspaces.frozen]\nroot = "{ro}"\nwrite = "deny"\n')
        s.write_form(form)
        s.approve()
        r = s.run("scp", "-O", str(f), f"box:{ro}/f.txt")
        assert r.returncode != 0 and "[hosts.box.workspaces.frozen] write" in r.stderr, r
        assert not (ro / "f.txt").exists()
        r = s.run("scp", "-O", str(f), f"box:{rw}/f.txt")
        assert r.returncode == 0 and (rw / "f.txt").exists(), r
        r = s.run("scp", str(f), f"box:{ro}/g.txt")               # the sftp protocol too
        assert r.returncode != 0 and not (ro / "g.txt").exists(), r


def test_agent_forwarding_only_with_the_hosts_own_grant_and_only_claudes_key():
    with HS.ssh_env() as s:
        t = _box(s)
        r = s.run("ssh", "-A", "box", "ssh-add -L")
        assert r.returncode == 2 and "has no forward_agent" in r.stderr, r
        assert t.accepted() == 0
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n'
                     '[hosts.box.policy]\nforward_agent = "allow"\n')
        r = s.run("ssh", "-A", "box", "ssh-add -L")
        assert r.returncode == 2 and "waits for the user's OK" in r.stderr, r   # a widening
        s.approve()
        user_agent = s.root / "users-own-agent.sock"
        r = s.run("ssh", "-A", "box", 'ssh-add -L; echo "SOCK=${SSH_AUTH_SOCK:+set}"',
                  extra_env={"SSH_AUTH_SOCK": str(user_agent)})
        assert r.returncode == 0 and "SOCK=set" in r.stdout, r
        pub = " ".join(s.vault()["hosts"]["box"]["keys"][0]["public"].split()[:2])
        listed = [" ".join(ln.split()[:2]) for ln in r.stdout.splitlines() if ln.startswith("ssh-")]
        assert listed == [pub], (listed, pub)           # Claude's key for this host, nothing else
        # without -A nothing is forwarded, even with the grant
        r = s.run("ssh", "box", 'echo "SOCK=${SSH_AUTH_SOCK:-none}"')
        assert r.returncode == 0 and "SOCK=none" in r.stdout, r
        # [policy] keeps it off everywhere
        s.write_form(f'[policy]\nforward_agent = "deny"\n[hosts.box]\naddress = "{t.addr()}"\n'
                     '[hosts.box.policy]\nforward_agent = "allow"\n')
        r = s.run("ssh", "-A", "box", "true")
        assert r.returncode == 2 and '[policy] forward_agent = "deny"' in r.stderr, r


def test_x11_forwarding_states_its_prerequisite():
    with HS.ssh_env() as s:
        t = _box(s, '[hosts.box.policy]\nforward_x11 = "allow"\n')
        r = s.run("ssh", "-X", "box", "true", extra_env={"DISPLAY": ""})
        assert r.returncode == 2 and "no X server here" in r.stderr and "DISPLAY" in r.stderr, r
        assert t.accepted() == 0


def test_a_remote_forward_binds_only_to_the_hosts_loopback():
    with HS.ssh_env() as s:
        _box(s, '[hosts.box.policy]\nforward_remote = "allow"\n')
        r = s.run("ssh", "-R", "0.0.0.0:9999:localhost:22", "box", "true")
        assert r.returncode == 2 and "open a port to other machines" in r.stderr, r


def test_a_restricted_workspace_removed_by_an_edit_still_binds_until_the_ok():
    with HS.ssh_env() as s:
        t = _box(s)
        ro = t.dir / "ro"
        ro.mkdir()
        f = s.root / "f.txt"
        f.write_text("x\n")
        base = f'[hosts.box]\naddress = "{t.addr()}"\n'
        s.write_form(base + f'[hosts.box.workspaces.frozen]\nroot = "{ro}"\nwrite = "deny"\n')
        s.approve()
        # an agent-assisted edit deletes the table (no gate check): still refused
        s.write_form(base)
        r = s.run("scp", "-O", str(f), f"box:{ro}/a.txt")
        assert r.returncode != 0 and not (ro / "a.txt").exists(), r
        assert "[hosts.box.workspaces.frozen] write" in r.stderr and "waits for the user's OK" \
            in r.stderr, r.stderr
        # renamed without its restriction: the old name still binds
        s.write_form(base + f'[hosts.box.workspaces.open]\nroot = "{ro}"\n')
        r = s.run("scp", "-O", str(f), f"box:{ro}/b.txt")
        assert r.returncode != 0 and not (ro / "b.txt").exists(), r
        # after the user's OK the removal applies
        s.write_form(base)
        s.approve()
        r = s.run("scp", "-O", str(f), f"box:{ro}/c.txt")
        assert r.returncode == 0 and (ro / "c.txt").exists(), r


def _acts(cmd: str) -> list[tuple[str, str]]:
    from gateway import ssh_args
    return ssh_args.ssh_actions(ssh_args.parse_ssh(["box", cmd]))


def test_transfer_servers_are_recognised_by_their_exact_name_and_options():
    R, W, X = "read", "write", [("exec", "")]
    rs = "rsync --server --sender -vlogDtpre.iLsfxCIvu"
    # rsync 3.x and openrsync downloads and uploads, every path named
    assert _acts(f"{rs} . /a/b") == [(R, "/a/b")]
    assert _acts(f"{rs} . /a/b /c/d") == [(R, "/a/b"), (R, "/c/d")]
    assert _acts("rsync --server --sender -g -l -o -p -D -r -t --dirs . /a") == [(R, "/a")]
    assert _acts("rsync --server --sender -e.LsfxCIvu -B1024 --timeout=5 --bwlimit=100 . x") == \
        [(R, "x")]
    assert _acts("rsync --server -logDtprze.iLsfxCIvu --delete --partial --log-format=%i . /up/") \
        == [(W, "/up/")]
    assert _acts("rsync --server -O --backup --suffix .bak --ignore-times --fuzzy . /up/") == \
        [(W, "/up/")]
    # --remove-source-files deletes the sources: a write of each, besides the read
    assert _acts(f"{rs} --remove-source-files . /a /b") == \
        [(R, "/a"), (R, "/b"), (W, "/a"), (W, "/b")]
    assert (W, "/a") in _acts("rsync --server --sender -g -l --remove-sent-files . /a")
    # options outside the lists, protected args (paths on stdin), no paths: exec
    for c in (f"{rs} --log-file=/tmp/x . /a", f"{rs} --log-file-format=%f . /a",
              "rsync --server -logDtpre.iLsfxCIvu --temp-dir=/tmp . /up/",
              "rsync --server -blogDtpre.iLsfxCIvu --backup-dir /bk . /up/",
              "rsync --server -logDtpre.iLsfxCIvu --partial-dir=/x . /up/",
              "rsync --server -logDtpre.iLsfxCIvu --link-dest=/x . /up/",
              f"{rs} --files-from=- --from0 . /a", "rsync --server --sender -se.LsfxCIvu",
              "rsync --server -slogDtpre.iLsfxCIvu", f"{rs} .", f"{rs} /a",
              # protected args: the server reads its real paths from stdin, so the
              # paths on the line prove nothing
              "rsync --server --sender -se.LsfxCIvu . /srv/free/x",
              "rsync --server -s -logDtpre.iLsfxCIvu . /up/",
              "rsync --server --sender -vlogDtpre.iLsfxCIvu --suffix=/x . /a",
              "rsync --server --sender --daemon . /a", "rsync --sender --server . /a",
              # popt reads options after the "." too: a path like an option is exec
              f"{rs} . --remove-source-files /a", f"{rs} . /a --log-file=/tmp/x",
              "rsync --server -logDtpre.iLsfxCIvu . -- /up/",
              "rsync --server --sender -M . /a", "rsync --server --sender --iconv=x . /a"):
        assert _acts(c) == X, c
    # a transfer program named by a path, or under another name, is whatever that program is
    for c in ("/tmp/x/rsync --server --sender . /x", "./rsync --server --sender . /x",
              "/usr/bin/scp -f /x", "~/bin/scp -t /x", "/usr/bin/git-upload-pack /r.git",
              "bin/git-receive-pack /r.git", "rsync2 --server --sender . /x", "scpx -f /x"):
        assert _acts(c) == X, c
    # scp's server: -t one target, -f every path; only its own flags
    assert _acts("scp -t /x") == [(W, "/x")]
    assert _acts("scp -r -p -d -t -- /x") == [(W, "/x")]
    assert _acts("scp -pt /x") == [(W, "/x")]
    assert _acts("scp -f a /b") == [(R, "a"), (R, "/b")]
    assert _acts("scp -v -r -f -- /a /b") == [(R, "/a"), (R, "/b")]
    for c in ("scp -f -S x /a", "scp -t -f /a", "scp -f", "scp -o x -t /a", "scp -3 -t /a",
              "scp -f /a -t", "scp -t -- -x"):
        assert _acts(c) == X, c
    for c in ("git-upload-pack --strict", "git-receive-pack -x"):
        assert _acts(c) == X, c
    assert _acts("git-upload-pack '/r.git'") == [(R, "/r.git")]
    assert _acts("git-receive-pack 'r.git'") == [(W, "r.git")]


def test_a_path_is_decided_in_every_workspace_it_may_reach():
    from gateway import ssh_args
    f = (HOST + '[hosts.box.workspaces.prod]\nroot = "/srv/prod"\nread = "deny"\n'
         '[hosts.box.workspaces.app]\nroot = "/srv/prod/app"\n'
         '[hosts.box.workspaces.notes]\nroot = "~/notes"\nwrite = "deny"\n')
    e = run(f, f)

    def word(act: str, path: str) -> object:
        return ssh_args.decide_path(e, act, "box", path).word

    # written like the root: placed exactly (the innermost workspace binds)
    assert word("read", "/srv/prod/x") is False
    assert word("read", "/srv/prod/../prod/x") is False
    assert word("read", "//srv//prod/x") is False
    assert word("read", "/srv/prod/app/x") is True
    assert word("read", "/srv/other") is True
    assert word("write", "~/notes/a") is False and word("write", "notes/a") is False
    assert word("write", "~/other/a") is True          # prod and app restrict no write
    # a folder above a root reaches that workspace (a recursive transfer of it)
    d = ssh_args.decide_path(e, "read", "box", "/srv")
    assert d.word is False and "/srv holds workspace prod" in d.message(), d.message()
    assert word("write", "~") is False and word("write", ".") is False
    # written the other way than a root: the gateway doesn't know box's home
    d = ssh_args.decide_path(e, "read", "box", "data/x.txt")
    assert d.word is False and "doesn't know box's home folder" in d.message() and \
        "from / like that root" in d.message(), d.message()
    d = ssh_args.decide_path(e, "write", "box", "/home/u/x")
    assert d.word is False and "from ~/ like that root" in d.message(), d.message()
    # can't be placed at all: another user's home, leaving the home with ..
    assert word("read", "~root/x") is False and word("read", "../../srv/prod/x") is False
    # sftp may open any file
    d = ssh_args.decide_path(e, "read", "box", ssh_args.ANY_PATH)
    assert d.word is False and "sftp can open any file" in d.message()
    # a host without workspaces decides on the host alone
    e2 = run(HOST, HOST)
    for p in ("x", "~root/x", "/a", ssh_args.ANY_PATH):
        assert ssh_args.decide_path(e2, "read", "box", p).word is True


def test_rsync_remove_source_files_is_a_write_and_a_program_by_path_is_exec():
    import shutil
    import subprocess
    rsync = shutil.which("rsync", path="/opt/local/bin:/usr/local/bin:/usr/bin")
    with HS.ssh_env() as s:
        t = _box(s)
        d = t.dir / "data"
        d.mkdir()
        (d / "keep.txt").write_text("precious\n")
        bindir = t.dir / "bin"
        bindir.mkdir()
        marker = t.dir / "ran.txt"
        (bindir / "rsync").write_text(f"#!/bin/sh\necho ran > '{marker}'\n")
        (bindir / "rsync").chmod(0o755)
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n'
                     '[hosts.box.policy]\nexec = "deny"\nwrite = "deny"\n')
        # any program called rsync, by its path, is exec: refused, not run
        r = s.run("ssh", "box", f"{bindir}/rsync --server --sender . /x")
        assert r.returncode == 2 and not marker.exists(), r
        assert '[hosts.box.policy] exec = "deny"' in r.stderr, r.stderr
        r = s.run("ssh", "box", f"rsync --server --sender -e.Lsfx --log-file={t.dir}/l . {d}/keep.txt")
        assert r.returncode == 2 and "exec" in r.stderr and not (t.dir / "l").exists(), r
        if not rsync:
            print("       (rsync part skipped: no rsync on this machine)")
            return
        dest = s.root / "dl"
        dest.mkdir()
        r = subprocess.run([rsync, "--remove-source-files", f"box:{d}/keep.txt", f"{dest}/"],
                           capture_output=True, text=True, env=s.proc_env(), cwd=str(s.root),
                           timeout=60)
        assert r.returncode != 0 and (d / "keep.txt").exists(), (r.returncode, r.stderr)
        assert '[hosts.box.policy] write = "deny"' in r.stderr, r.stderr
        # the plain download is a read: it passes, and the source stays
        r = subprocess.run([rsync, f"box:{d}/keep.txt", f"{dest}/"], capture_output=True,
                           text=True, env=s.proc_env(), cwd=str(s.root), timeout=60)
        assert r.returncode == 0 and (dest / "keep.txt").exists() and (d / "keep.txt").exists(), \
            (r.returncode, r.stderr)


def test_every_path_of_a_transfer_is_decided_in_its_workspace():
    import shutil
    import subprocess
    rsync = shutil.which("rsync", path="/opt/local/bin:/usr/local/bin:/usr/bin")
    with HS.ssh_env() as s:
        t = _box(s)
        ro, free = t.dir / "ro", t.dir / "free"
        ro.mkdir()
        free.mkdir()
        (ro / "secret.txt").write_text("in the read-denied workspace\n")
        (free / "x.txt").write_text("free\n")
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n'
                     f'[hosts.box.workspaces.closed]\nroot = "{ro}"\nread = "deny"\n')
        s.approve()
        # the legacy scp server with two paths, the denied one first or last
        for paths_ in (f"{ro}/secret.txt {free}/x.txt", f"{free}/x.txt {ro}/secret.txt"):
            r = s.run("ssh", "box", f"scp -f {paths_}", input=b"\0" * 8)
            assert r.returncode == 2 and "in the read-denied" not in r.stdout, r
            assert "[hosts.box.workspaces.closed] read" in r.stderr, r.stderr
        # a folder above the workspace reaches it
        r = s.run("scp", "-O", "-r", f"box:{t.dir}", str(s.root / "all"))
        assert r.returncode != 0 and not (s.root / "all").exists(), r
        assert "holds workspace closed" in r.stderr, r.stderr
        # the free path alone passes
        r = s.run("scp", "-O", f"box:{free}/x.txt", str(s.root / "x.txt"))
        assert r.returncode == 0 and (s.root / "x.txt").exists(), r
        if not rsync:
            print("       (rsync part skipped: no rsync on this machine)")
            return
        dest = s.root / "dl"
        dest.mkdir()
        r = subprocess.run([rsync, f"box:{free}/x.txt", f"box:{ro}/secret.txt", f"{dest}/"],
                           capture_output=True, text=True, env=s.proc_env(), cwd=str(s.root),
                           timeout=60)
        assert r.returncode != 0 and not (dest / "secret.txt").exists(), (r.returncode, r.stderr)


def test_sftp_is_decided_against_every_workspace():
    with HS.ssh_env() as s:
        t = _box(s)
        ro = t.dir / "ro"
        ro.mkdir()
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n'
                     f'[hosts.box.workspaces.closed]\nroot = "{ro}"\nread = "deny"\n')
        s.approve()
        # plain sftp may open any file, the workspace's too: refused with why
        r = s.run("sftp", "-b", "-", f"box:{t.dir}", input="ls\n")
        assert r.returncode != 0 and "sftp can open any file on box" in r.stderr, r
        # scp (its sftp protocol) is decided by its own operands
        (t.dir / "ok.txt").write_text("fine\n")
        r = s.run("scp", f"box:{t.dir}/ok.txt", str(s.root / "ok.txt"))
        assert r.returncode == 0 and (s.root / "ok.txt").exists(), r


# ---------------------------------------------------------------------------
# The approval hook: policy decisions, alternate routes, the elevation notice
# ---------------------------------------------------------------------------


def _hook(command: str, mode: str = "auto") -> dict | None:
    from gateway import hooks_bash
    return hooks_bash.main({"tool_name": "Bash", "permission_mode": mode,
                            "tool_input": {"command": command}, "cwd": "/tmp"})


def _dec(out: dict | None) -> str | None:
    return ((out or {}).get("hookSpecificOutput") or {}).get("permissionDecision")


def _why(out: dict | None) -> str:
    return ((out or {}).get("hookSpecificOutput") or {}).get("permissionDecisionReason") or ""


def test_the_approval_hook_applies_policy_rules_with_their_text():
    form = (HOST + 'sudo = true\n[hosts.box.policy]\nexec = "ask"\nwrite = "deny"\n'
            '[hosts.box.workspaces.ro]\nroot = "/srv/ro"\nread = "deny"\n')
    with H.gateway_env() as env:
        env.write_form(form)
        consent.approve_all(env.form())
        # exec "ask": Claude Code asks (the stand-in honours it for this typed command)
        out = _hook("ssh box uptime")
        assert _dec(out) == "ask" and "exec on box" in _why(out), out
        # write denied: an upload, with the rule
        out = _hook("scp ./f box:/tmp/f")
        assert _dec(out) == "deny" and '[hosts.box.policy] write = "deny"' in _why(out), out
        out = _hook("rsync -a ./d box:/tmp/d")
        assert _dec(out) == "deny" and "write" in _why(out), out
        # a read from the workspace whose read is denied
        out = _hook("scp box:/srv/ro/x ./x")
        assert _dec(out) == "deny" and "[hosts.box.workspaces.ro] read" in _why(out), out
        # forwarding without the host's grant: denied with the rule
        out = _hook("ssh -A box true")
        assert _dec(out) == "deny" and "has no forward_agent" in _why(out), out
        # the rights' own refusals keep their own words
        env.write_form(form.replace("sudo = true", "sudo = false"))
        out = _hook("ssh box sudo reboot")
        assert _dec(out) == "deny" and "sudo is off for box" in _why(out), out


def test_the_hook_decides_transfers_as_the_stand_in_will():
    form = (HOST + '[hosts.box.policy]\nexec = "deny"\nwrite = "deny"\n'
            '[hosts.box.workspaces.closed]\nroot = "/srv/closed"\nread = "deny"\n')
    with H.gateway_env() as env:
        env.write_form(form)
        consent.approve_all(env.form())
        # --remove-source-files deletes the remote sources: a write
        out = _hook("rsync --remove-source-files box:/srv/x ./dl/")
        assert _dec(out) == "deny" and '[hosts.box.policy] write = "deny"' in _why(out), out
        # protected args hide the paths from the stand-in: exec
        out = _hook("rsync -s box:/srv/x ./dl/")
        assert _dec(out) == "deny" and '[hosts.box.policy] exec = "deny"' in _why(out), out
        # every source path, and a folder above a workspace
        out = _hook("rsync box:/srv/free/x box:/srv/closed/y ./dl/")
        assert _dec(out) == "deny" and "[hosts.box.workspaces.closed] read" in _why(out), out
        out = _hook("scp -r box:/srv ./all")
        assert _dec(out) == "deny" and "holds workspace closed" in _why(out), out
        # a plain download outside the workspace passes the policy
        assert _dec(_hook("scp box:/srv/free/x ./x")) != "deny"
        # sftp may open any file, the workspace's too
        env.write_form(HOST + '[hosts.box.workspaces.closed]\nroot = "/srv/closed"\nread = "deny"\n')
        consent.approve_all(env.form())
        out = _hook("sftp box:/srv/free")
        assert _dec(out) == "deny" and "sftp can open any file on box" in _why(out), out


def test_the_hook_refuses_credential_tools_reached_around_the_stand_ins():
    """PLAN-0.11 §1.7: a route around a stand-in is refused when it reaches a
    configured target, in every mode, managed shell on or off; one that
    reaches nothing configured is the user's own."""
    around = ("/usr/bin/ssh box uptime", "/usr/bin/scp f box:/tmp/f", "env -i ssh box uptime",
              "command -p ssh box uptime", "PATH=/usr/bin:/bin ssh box uptime",
              "rsync -e /usr/bin/ssh -a d box:/tmp/d", "timeout 5 /usr/bin/ssh box true")
    # nothing configured reached: this computer's sudo isn't configured, no
    # github account, no repository with a configured remote in /tmp
    theirs = ("/usr/bin/sudo -n true", "/opt/homebrew/bin/gh repo list",
              "GIT_SSH_COMMAND=/usr/bin/ssh git fetch", "git -c core.sshCommand=/usr/bin/ssh fetch")
    with H.gateway_env() as env:
        env.write_form(HOST)
        consent.approve_all(env.form())
        for c in around:
            for mode in ("auto", "default"):
                out = _hook(c, mode)
                assert _dec(out) == "deny" and "around the gateway" in _why(out), (c, mode, out)
        for c in theirs:
            for mode in ("auto", "default"):
                assert _dec(_hook(c, mode)) is None, (c, mode)
        # routed or harmless: git and rsync by path use the gateway's ssh; reading the binary is no route
        for c in ("/usr/bin/git fetch", "cat /usr/bin/ssh", "ssh box uptime", "rsync -a d box:/tmp/d"):
            assert _dec(_hook(c)) != "deny", c
        # this computer's sudo configured: sudo by its path goes around it
        env.write_form(HOST + '[hosts.localhost]\nsudo = true\n')
        consent.approve_all(env.form())
        out = _hook("/usr/bin/sudo -n true")
        assert _dec(out) == "deny" and "around the gateway" in _why(out), out
        # managed mode off: the same (the route checks hold in every mode)
        env.write_form(HOST + '[shell]\nmanaged = "off"\n')
        consent.approve_all(env.form())
        assert _dec(_hook("/usr/bin/ssh box uptime")) == "deny"
        assert _dec(_hook("/usr/bin/sudo -n true")) is None


def test_the_hook_refuses_routes_it_cant_follow():
    # typed commands whose credential tool the parser can't resolve: a shell string,
    # eval/exec, a function, a variable as the program, find -exec, PATH or a
    # transport variable changed earlier in the same command, combined options
    routes = [
        "sh -c '/usr/bin/ssh box uptime'", "bash -lc \"/usr/bin/ssh box uptime\"",
        "nohup bash -c '/usr/bin/ssh box true'", "echo '/usr/bin/ssh box id' | sh",
        "eval '/usr/bin/ssh box uptime'", "exec /usr/bin/ssh box uptime",
        "ssh(){ /usr/bin/ssh \"$@\"; }; ssh box uptime",
        "s=/usr/bin/ssh; $s box uptime", "x=/usr/bin; \"$x/ssh\" box uptime",
        "for t in ssh; do $t box uptime; done", "$(which -a ssh | tail -1) box uptime",
        "\"$SSH_BIN\" box uptime", "$X box uptime",
        "bash <<EOF\n/usr/bin/ssh box uptime\nEOF", "cat <<'EOF' | sh\n/usr/bin/sudo -n id\nEOF",
        "A=1 B=$(date) $SSH box uptime", "`which -a ssh | tail -1` box uptime",
        "find . -maxdepth 0 -exec /usr/bin/ssh box uptime \\;",
        "find . -maxdepth 0 -execdir sh -c '/usr/bin/ssh box true' \\;",
        "export PATH=/usr/bin:/bin; ssh box uptime", "export PATH=/usr/bin:/bin && sudo -n id",
        "PATH=/usr/bin:/bin; ssh box uptime", "unset PATH; ssh box uptime",
        "hash -p /usr/bin/ssh ssh; ssh box uptime", "export RSYNC_RSH=/usr/bin/ssh; rsync -a d box:/x",
        "env -- PATH=/usr/bin ssh box uptime", "rsync -ae /usr/bin/ssh d box:/tmp/d",
        "rsync -aze/usr/bin/ssh d box:/tmp/d", "rsync -avze '/usr/bin/ssh -v' d box:/tmp/d",
    ]
    # the same shapes reaching nothing configured (PLAN-0.11 §1.7: no github
    # account, no repository with a configured remote in /tmp, nothing "ask"
    # and no configured name in a function's text): the user's own
    theirs = [
        "function ssh { command -p ssh \"$@\"; }", "declare -x PATH=/usr/bin; gh repo list",
        "export GIT_SSH_COMMAND=/usr/bin/ssh; git fetch",
        "export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.sshCommand; git fetch",
        "env GIT_CONFIG_PARAMETERS=x git fetch", "git -ccore.sshCommand=/usr/bin/ssh fetch",
        "git config core.sshCommand /usr/bin/ssh", "git config --global ssh.variant ssh",
    ]
    harmless = [
        "ssh box uptime", "export PATH=\"$PATH:/opt/tools/bin\"; make", "bash -c 'echo hi'",
        "find . -name '*.py' -exec grep -l TODO {} +", "git config user.name Someone",
        "git config --get core.sshCommand", "rsync -az d box:/tmp/d", "rsync -aT /tmp/e d box:/x",
        "cat /usr/bin/ssh | wc -c", "for f in a b; do echo $f; done", "sudo -n true",
        "\"$HOME/bin/tool\" --version",
        "cat > notes.sh <<'EOF'\n#!/bin/sh\n/usr/bin/ssh box uptime\n$CMD\nEOF\nchmod +x notes.sh",
        "\"$(git rev-parse --show-toplevel)/scripts/test.sh\" --fast",
        "tmp=$(mktemp); echo hi > \"$tmp\"; cat \"$tmp\"",
    ]
    with H.gateway_env() as env:
        env.write_form(HOST + 'sudo = true\n[hosts.localhost]\nsudo = true\n')
        consent.approve_all(env.form())
        for c in routes:
            for mode in ("auto", "default", "bypassPermissions"):
                out = _hook(c, mode)
                assert _dec(out) == "deny" and ("around the gateway" in _why(out) or
                                                "hides the program or host" in _why(out)), \
                    (c, mode, out)
        for c in theirs:
            for mode in ("auto", "default"):
                assert _dec(_hook(c, mode)) is None, (c, mode, _why(_hook(c, mode)))
        for c in harmless:
            assert _dec(_hook(c)) != "deny", (c, _why(_hook(c)))
        # env's assignments after -- are still assignments: the program after them is judged
        # (curl: a network command, asked about: PLAN-0.11 §3)
        out = _hook("env -- A=1 curl https://example.com")
        assert _dec(out) == "ask" and "curl is a network command" in _why(out), out
        # managed mode off: the same (PLAN-0.11 §1.7: in every mode)
        env.write_form(HOST + 'sudo = true\n[hosts.localhost]\nsudo = true\n[shell]\nmanaged = "off"\n')
        consent.approve_all(env.form())
        for c in routes:
            assert _dec(_hook(c)) == "deny", c


def test_the_target_of_sudo_is_named_before_it_runs():
    with H.gateway_env() as env:
        env.write_form("[hosts.localhost]\nsudo = true\n" + HOST + "sudo = true\n")
        consent.approve_all(env.form())
        out = _hook("sudo -n true")
        assert _dec(out) == "allow" and "sudo runs as root on this machine (" in out["systemMessage"], out
        out = _hook("ssh box sudo -n true")
        assert _dec(out) == "allow" and "sudo runs as root on box (u@box.example.com)" in \
            out["systemMessage"], out
        assert "systemMessage" not in (_hook("ls") or {})
        # another target user is named as such, locally and on the host
        out = _hook("sudo -u builder -n true")
        assert "sudo runs as builder on this machine (" in out["systemMessage"], out
        out = _hook("sudo -nu builder true")
        assert "sudo runs as builder on this machine (" in out["systemMessage"], out
        from gateway import hooks_bash
        for words, who in ((["sudo", "--user=builder", "true"], "builder"),
                           (["sudo", "--user", "builder", "true"], "builder"),
                           (["sudo", "-p", "-u", "true"], "root"),
                           (["sudo", "-u", "#1001", "id"], "#1001"),
                           (["sudo", "-u", "$(id)", "id"], "another user"),
                           (["sudo", "--", "-u", "x"], "root")):
            assert hooks_bash._sudo_target(words) == who, (words, who)
        out = _hook("ssh box 'sudo -u www-data -n true'")
        assert "sudo runs as www-data on box (u@box.example.com)" in out["systemMessage"], out
        out = _hook("sudo -g staff -n true")
        assert "sudo runs as root on this machine (" in out["systemMessage"], out


def test_a_forwarding_option_doesnt_hide_a_remote_sudo_from_the_hook():
    with H.gateway_env() as env:
        env.write_form(HOST + 'sudo = false\n[hosts.box.policy]\nforward_agent = "allow"\n')
        consent.approve_all(env.form())
        out = _hook("ssh -A box sudo reboot")
        assert _dec(out) == "deny" and "sudo is off for box" in _why(out), out


def test_remote_sudo_follows_the_elevation_policy():
    with HS.ssh_env() as s:
        t = _box(s, '[hosts.box.policy]\nelevation = "deny"\n')
        r = s.run("ssh", "box", "sudo -n true")
        assert r.returncode == 2 and '[hosts.box.policy] elevation = "deny"' in r.stderr, r
        assert t.accepted() == 0
        r = s.run("ssh", "box", "echo plain")
        assert r.returncode == 0 and r.stdout == "plain\n", r


def test_an_accounts_write_policy_refuses_a_git_push_and_keeps_fetches():
    import test_ssh_git as G
    with HS.ssh_env() as s:
        t, _fps = G._setup(s, G.FORM + '\n[accounts.ghe-me.policy]\nwrite = "deny"\n')
        r = s.run("ssh", "git@ghe.test", "git-receive-pack 'me/own.git'")
        assert r.returncode == 2 and '[accounts.ghe-me.policy] write = "deny"' in r.stderr, r
        assert "a git push" in r.stderr
        r = s.run("ssh", "git@ghe.test", "git-upload-pack 'me/own.git'", input="0000")
        assert "write" not in r.stderr, r
        # and the account's credential restriction stops everything
        s.write_form(G.FORM + '\n[accounts.ghe-me.policy]\ncredential = "deny"\n')
        r = s.run("ssh", "git@ghe.test", "git-upload-pack 'me/own.git'", input="0000")
        assert r.returncode == 2 and "credential" in r.stderr and "ghe-me" in r.stderr, r


def test_this_machines_inspection_and_imports_follow_its_policy():
    from gateway import managed
    with H.gateway_env() as env:
        env.write_form('[shell]\nimport_path = ["/opt/local/bin"]\nimport_env = ["SOME_TOOL_HOME"]\n')
        consent.approve_all(env.form())
        from gateway import vault
        eff = consent.compute(env.form(), vault.load())
        assert "/opt/local/bin" in [d for d, _o in managed.path_plan(eff)]
        assert "SOME_TOOL_HOME" in [n for n, _o in managed.env_plan(eff)]
        assert managed.inspect(None, str(env.root))["ok"] is True
        env.write_form('[shell]\nimport_path = ["/opt/local/bin"]\nimport_env = ["SOME_TOOL_HOME"]\n'
                       '[hosts.localhost.policy]\nenv_import = "deny"\nread = "deny"\n')
        eff = consent.compute(env.form(), vault.load())
        assert "/opt/local/bin" not in [d for d, _o in managed.path_plan(eff)]
        assert managed.env_plan(eff) == [] and "imports=\n" in managed.conf_text(eff)
        r = managed.inspect(None, str(env.root))
        assert r["ok"] is False and '[hosts.localhost.policy] read = "deny"' in r["error"], r


def test_the_http_tools_follow_the_credential_write_and_network_policy():
    from gateway import vault, web
    acct = '[accounts.key]\nkind = "api-key"\nsites = ["api.example.com"]\n'
    with H.gateway_env() as env:
        env.write_form(acct + '[accounts.key.policy]\nwrite = "deny"\n')
        vault.save(vault.empty())
        consent.approve_all(env.form())
        with vault.edit() as d:
            r = vault.account_record(d, "key", "api-key")
            r["token"] = {"value": "k" * 32, "source": "pasted", "updated": vault.now(), "stale": False}
        # a write with the account: refused before anything is sent
        out = web.http({"url": "https://api.example.com/x", "method": "POST", "account": "key",
                        "json": {"a": 1}})
        assert out.get("ok") is False and '[accounts.key.policy] write = "deny"' in out["error"], out
        # the credential itself
        env.write_form(acct + '[accounts.key.policy]\ncredential = "deny"\n')
        out = web.http({"url": "https://api.example.com/x", "account": "key"})
        assert out.get("ok") is False and "credential" in out["error"] and "deny" in out["error"], out
        # requests without a credential: this machine's network policy
        env.write_form(acct + '[hosts.localhost.policy]\nnetwork = "deny"\n')
        out = web.http({"url": "https://example.org/"})
        assert out.get("ok") is False and '[hosts.localhost.policy] network = "deny"' in out["error"], out
        out = web.download({"url": "https://example.org/f.txt", "save_to": str(env.root / "f.txt")})
        assert out.get("ok") is False and "network" in out["error"], out
        assert not (env.root / "f.txt").exists()


def test_account_selection_refuses_a_credential_the_policy_denies():
    from gateway import accounts
    gh = '[accounts.gh]\nkind = "github"\nlogin = "me"\ndefault = true\n'
    f = parse(gh)
    data = {"approved": {"rights": consent.snapshot(f)},
            "accounts": {"gh": {"kind": "github", "bound": {"hosts": ["github.com", "api.github.com"]}}}}
    e = consent.compute(f, data)
    sel = accounts.select("github", "github.com", "me", f, effective=e, vault=data, env={})
    assert sel.account is not None and sel.error is None
    f2 = parse(gh + '[accounts.gh.policy]\ncredential = "deny"\n')
    e2 = consent.compute(f2, data)
    sel = accounts.select("github", "github.com", "me", f2, effective=e2, vault=data, env={})
    assert sel.account is None and '[accounts.gh.policy] credential = "deny"' in (sel.error or ""), sel
    # [policy] for every account
    f3 = parse('[policy]\ncredential = "ask"\n' + gh)
    e3 = consent.compute(f3, data)
    sel = accounts.select("github", "github.com", "me", f3, effective=e3, vault=data, env={})
    assert sel.account is None and '[policy] credential = "ask"' in (sel.error or ""), sel
