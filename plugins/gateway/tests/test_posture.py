"""The posture "ungated unless configured" (PLAN-0.11 §1): which stand-ins
exist, the pass-through to the user's own tools (user_tool, the recursion
guard, a missing tool, the audit line), and each stand-in's classification:
sudo (§1.5), ssh, scp and sftp (§1.4), the account CLIs and dvc. A target
nothing configures runs the user's own tool with the full argv and the
environment unchanged; a configured one keeps every guard. The user's own
tools are recording fakes (tests/fakes/fake_user_tool.py, the `user_tools`
test knob); `ssh -G` answers from a table, never from ~/.ssh/config."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import harness as H
import harness_accounts as HA
import harness_posture as HP
from gateway import audit, consent, envfile, paths, vault
from gateway import form as F

HOST = '[hosts.box]\naddress = "octo@box.invalid"\n'
GH = '[accounts.gh]\nkind = "github"\nlogin = "octo"\n'


def _eff(env, text: str, approve: bool = True):
    env.write_form(text)
    if not vault.exists():
        vault.save(vault.empty())
    if approve:
        consent.approve_all(env.form())
    data = vault.load()
    form = consent.load_form(data)
    return form, consent.compute(form, data)


# ---------------------------------------------------------------------------
# Which stand-ins exist (§1.2)
# ---------------------------------------------------------------------------


def test_a_new_install_shadows_nothing():
    """The starter form configures nothing: $DATA/bin holds gate and its
    helpers and the marker, no stand-in (the user's ssh, sudo, gh, ... run
    by their own names)."""
    with H.gateway_env() as env:
        env.write_form(F.STARTER)
        form = env.form()
        eff = consent.compute(form, None)
        assert envfile.standins_for(eff) == []
        envfile.sync(form, eff, {}, None)
        names = {p.name for p in paths.bin_dir().iterdir()}
        assert {"gate", "git-credential-gateway", "gate-askpass", envfile.STANDIN_MARKER} <= names
        assert not names & set(envfile.STANDIN_NAMES), names
        assert (paths.bin_dir() / envfile.STANDIN_MARKER).read_text() == envfile.MARKER_TEXT


def test_each_stand_in_exists_only_where_it_can_reach_something_configured():
    cases = [
        (HOST, {"ssh", "scp", "sftp", "git"}),
        ("[hosts.localhost]\nsudo = \"ask\"\n", {"sudo"}),
        ("[hosts.localhost.policy]\nelevation = \"ask\"\n", {"sudo"}),
        ("[policy]\nelevation = { default = \"allow\", auto = \"deny\" }\n", {"sudo"}),
        (GH, {"ssh", "scp", "sftp", "git", "gh", "crane"}),     # github.com: packages by default
        (GH + "packages = false\n", {"ssh", "scp", "sftp", "git", "gh"}),
        (GH + 'host = "ghe.example.com"\n', {"ssh", "scp", "sftp", "git", "gh"}),
        ('[accounts.hf]\nkind = "huggingface"\n', {"ssh", "scp", "sftp", "git", "hf"}),
        ('[accounts.az]\nkind = "azure"\ntenant = "t.example.com"\nclient_id = '
         '"11111111-2222-3333-4444-555555555555"\n', {"az", "databricks", "crane"}),
        ('[accounts.reg]\nkind = "registry"\nhost = "reg.example.com"\n', {"crane"}),
        ('[accounts.pj]\nkind = "pijul"\n', {"ssh", "scp", "sftp", "pijul"}),
        ('[accounts.cat]\nkind = "ml-catalog"\nhost = "cat.example.com"\n', {"asiml", "dvc"}),
        ('[accounts.key]\nkind = "api-key"\nsites = ["api.example.com"]\n', set()),
        ('[hosts.broken]\naddress = 5\n', {"ssh", "scp", "sftp", "git"}),   # disabled: still configured
        ("[hosts.localhost]\nscripts = true\n", set()),                 # no sudo key: not configured
    ]
    with H.gateway_env() as env:
        for text, want in cases:
            env.write_form(text)
            eff = consent.compute(env.form(), {})
            assert set(envfile.standins_for(eff)) == want, (text, envfile.standins_for(eff), want)


def test_a_removed_host_keeps_its_stand_in_until_the_ok_and_the_list_counts_while_locked():
    with H.gateway_env() as env:
        _eff(env, HOST)
        form, eff = _eff(env, "", approve=False)
        assert "box" in eff.hosts and eff.hosts["box"].removed
        assert "ssh" in envfile.standins_for(eff), "the approved entry keeps its stand-in"
        # the vault locked: the configured list classifies
        locked = consent.compute(env.form(), None, locked=True)
        assert "ssh" in envfile.standins_for(locked)


def test_the_stand_ins_follow_the_configured_set_when_it_changes():
    """sync_standins (the Bash hook, FileChanged, PostToolUse, consent's
    approve, SessionStart): a host added gets its ssh stand-in before the
    command that uses it; an approved removal takes it away."""
    with H.gateway_env() as env:
        form, eff = _eff(env, F.STARTER)
        envfile.write_stubs(envfile.stand_ins(form, eff))
        assert not (paths.bin_dir() / "ssh").exists()
        from gateway import hooks_bash
        env.write_form(HOST)
        hooks_bash._load_rights()
        assert (paths.bin_dir() / "ssh").is_file(), "the Bash hook adds the stand-in at once"
        consent.approve_all(env.form())
        env.write_form(F.STARTER)
        consent.approve("box", form=env.form())
        assert not (paths.bin_dir() / "ssh").exists(), "an approved removal takes it away"
        assert not envfile.sync_standins(env.form(), consent.compute(env.form(), vault.load()))


def test_write_stubs_keeps_the_marker():
    with H.gateway_env():
        envfile.write_stubs({"gate": "#!/bin/sh\n"})
        m = paths.bin_dir() / envfile.STANDIN_MARKER
        old = 0
        os.utime(m, (old, old))                       # older than an hour: kept all the same
        envfile.write_stubs({"gate": "#!/bin/sh\n"})
        assert m.is_file()


# ---------------------------------------------------------------------------
# user_tool and the pass-through (§1.3)
# ---------------------------------------------------------------------------


def _tool(d: Path, name: str) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    p = d / name
    p.write_text("#!/bin/sh\n")
    os.chmod(p, 0o755)
    return p


def test_user_tool_skips_every_stand_in_folder_and_the_pixi_envs():
    import shutil
    import tempfile
    base = Path(tempfile.mkdtemp(prefix="ut-", dir=H.tmp_base()))
    try:
        _user_tool_cases(base)
    finally:
        shutil.rmtree(base, ignore_errors=True)


def _user_tool_cases(base: Path) -> None:
    mine = _tool(base / "data" / "bin", "ssh").parent
    other = _tool(base / "otherconfig" / "bin", "ssh").parent
    (other / envfile.STANDIN_MARKER).write_text(envfile.MARKER_TEXT)
    # this plugin's own pixi envs: its data folder's, and a developer
    # checkout's .pixi (also reached through a symlink)
    roots = (str(base / "data" / "envs"), str(base / "plugin" / ".pixi"))
    env = _tool(base / "data" / "envs" / "abc123" / ".pixi" / "envs" / "default" / "bin",
                "ssh").parent
    pixi = _tool(base / "plugin" / ".pixi" / "envs" / "default" / "bin", "ssh").parent
    (base / "link").symlink_to(base / "plugin")
    linked = base / "link" / ".pixi" / "envs" / "default" / "bin"
    user = _tool(base / "brew" / "bin", "ssh").parent
    later = _tool(base / "later" / "bin", "ssh").parent
    path = os.pathsep.join(map(str, [mine, other, env, pixi, linked, user, later]))
    assert envfile.find_on_path("ssh", path, own=str(mine), skip=roots) == str(user / "ssh")
    assert envfile.find_on_path("ssh", os.pathsep.join(map(str, [mine, other, env, pixi, linked])),
                                own=str(mine), extra=(), skip=roots) is None
    assert envfile.find_on_path("nosuchtool", path, own=str(mine), extra=(), skip=roots) is None
    # relative PATH entries are never searched
    assert envfile.find_on_path("ssh", "brew/bin", own=str(mine), extra=(), skip=roots) is None
    # anyone else's pixi env is the user's own: `pixi global`'s ~/.pixi/bin, a project's env
    glob = _tool(base / "home" / ".pixi" / "bin", "ghx").parent
    proj = _tool(base / "proj" / ".pixi" / "envs" / "default" / "bin", "hf").parent
    assert envfile.find_on_path("ghx", os.pathsep.join(map(str, [mine, glob])), own=str(mine),
                                extra=(), skip=roots) == str(glob / "ghx")
    assert envfile.find_on_path("hf", str(proj), own=str(mine), extra=(),
                                skip=roots) == str(proj / "hf")


def test_user_tool_skips_this_plugins_own_envs_and_no_one_elses():
    """user_tool's skip list is this plugin's own pixi envs (its data
    folder's envs, the plugin folder's .pixi), so a tool from `pixi global`
    or a project env counts as the user's own."""
    with H.gateway_env() as env:
        assert envfile.own_env_roots() == (str(paths.envs_dir()),
                                           str(paths.plugin_root() / ".pixi"))
        ours = _tool(paths.envs_dir() / "abc123" / ".pixi" / "envs" / "default" / "bin",
                     "ghx").parent
        glob = _tool(env.user_home / ".pixi" / "bin", "ghx").parent
        path = os.pathsep.join(map(str, [ours, glob]))
        assert envfile.find_on_path("ghx", path, extra=()) == str(glob / "ghx")
        assert envfile.find_on_path("ghx", str(ours), extra=()) is None


def test_under_a_test_override_only_the_knobs_fakes_are_found():
    with H.gateway_env() as env:
        assert envfile.user_tool("ssh") is None, "never the machine's real ssh in a test"
        d = HP.user_tools(env, "ssh")
        assert envfile.user_tool("ssh") == str(d / "ssh")
        assert envfile.user_tool("gh") is None


def test_the_pass_through_execs_the_users_tool_with_the_full_argv_and_the_environment():
    with H.gateway_env() as env:
        env.write_form(HOST)
        d = HP.user_tools(env, "ssh")
        r = HP.run_standin(env, "ssh", "-F", "/dev/null", "-o", "ProxyCommand=nc %h %p",
                           "other.invalid", "uptime",
                           extra_env={"SSH_AUTH_SOCK": "/fake/agent.sock", "GH_TOKEN": "fake-token"})
        assert r.returncode == 0 and r.stdout == "fake ssh ran\n", (r.stdout, r.stderr)
        run, = HP.runs(d, "ssh")
        assert run["argv"] == ["-F", "/dev/null", "-o", "ProxyCommand=nc %h %p", "other.invalid",
                               "uptime"], "the full argv, refused options included"
        assert run["argv0"] == str(d / "ssh"), "argv[0] is the user's tool's own path"
        assert run["env"]["SSH_AUTH_SOCK"] == "/fake/agent.sock" and run["env"]["GH_TOKEN"] == \
            "fake-token", "the user's own agent and token reach their own tool"
        assert run["env"]["GW_PASSTHRU"].startswith("ssh:1:")
        lines = [json.loads(x) for x in paths.audit_path().read_text().splitlines()]
        pt = [x for x in lines if x.get("event") == "passthrough"]
        assert pt and pt[-1].get("tool") == "ssh" and pt[-1].get("target") == "other.invalid"
        assert "uptime" not in json.dumps(pt) and "ProxyCommand" not in json.dumps(pt), \
            "the audit line never holds argv"


def test_the_recursion_guard_refuses_a_loop_but_not_a_nested_call():
    with H.gateway_env() as env:
        env.write_form(HOST)
        d = HP.user_tools(env, "ssh")
        argv = ["other.invalid", "true"]
        same = f"ssh:1:{envfile._argv_digest('ssh', argv)}"
        r = HP.run_standin(env, "ssh", *argv, extra_env={"GW_PASSTHRU": same})
        assert r.returncode == 2 and "calls the gateway's stand-in again (a loop)" in r.stderr, r
        assert not HP.runs(d, "ssh")
        # a nested ssh with other arguments (a ProxyCommand's) is that ssh's own business
        r = HP.run_standin(env, "ssh", "jump.invalid", "-W", "x:22", extra_env={"GW_PASSTHRU": same})
        assert r.returncode == 0, r
        assert HP.runs(d, "ssh")[-1]["env"]["GW_PASSTHRU"].startswith("ssh:2:")
        # too deep, whatever the arguments
        r = HP.run_standin(env, "ssh", "x.invalid", "true",
                           extra_env={"GW_PASSTHRU": f"ssh:{envfile.PASSTHRU_MAX}:00"})
        assert r.returncode == 2 and "a loop" in r.stderr
        # another tool's mark doesn't count
        r = HP.run_standin(env, "ssh", *argv, extra_env={"GW_PASSTHRU": "git:3:00"})
        assert r.returncode == 0


def test_a_loops_refusal_is_audited_with_the_sessions_mode():
    """Lead decision 19.8 (verify013): the loop guard (envfile.pass_through,
    shared by the stand-ins) has no stand-in's mode at hand, so its audit
    line names the mode the hook recorded for a command Claude typed, else
    "modeless" (modes.standin_audit_mode's fallback)."""
    import contextlib
    import io
    from gateway import modes, ssh
    with H.gateway_env() as env:
        _ssh_world(env)
        argv = ["other.invalid", "true"]
        same = f"ssh:1:{envfile._argv_digest('ssh', argv)}"
        real = modes.current_for
        try:
            for recorded, want in (("acceptEdits", "acceptEdits"), (None, "modeless")):
                modes.current_for = lambda caller, m=recorded: m if caller == "standin" else None
                err = io.StringIO()
                with HA.env_vars(GW_PASSTHRU=same), contextlib.redirect_stderr(err):
                    rc = ssh.main("ssh", list(argv))
                assert rc == 2 and "a loop" in err.getvalue(), (rc, err.getvalue())
                last = [r for r in audit.read(0) if r.get("event") == "refusal"][-1]
                assert "a loop" in last["reason"] and last.get("mode") == want, (want, last)
        finally:
            modes.current_for = real                 # type: ignore[assignment]


def test_a_missing_user_tool_exits_127_and_names_what_the_gateway_handles():
    with H.gateway_env() as env:
        env.write_form(HOST)
        HP.user_tools(env, "gh")               # no ssh among the user's tools
        r = HP.run_standin(env, "ssh", "other.invalid", "true")
        assert r.returncode == 127, r
        assert "gateway: ssh isn't installed here. The gateway handles ssh only for box." in r.stderr


# ---------------------------------------------------------------------------
# This computer's sudo (§1.5)
# ---------------------------------------------------------------------------


def _sudo_world(env, form_text: str | None):
    import harness_sudo as HS
    if form_text is not None:
        env.write_form(form_text)
    vault.save(vault.empty())
    consent.approve_all(env.form())
    d = HP.user_tools(env, "sudo")
    fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
    return HS, d, fake


def test_unconfigured_sudo_is_the_users_own_sudo():
    """No `sudo` key: no gateway decision, no password supplied or asked;
    the user's sudo runs with the full argv (a configured stand-in's -S/-A
    refusal doesn't apply: the user's own business)."""
    with H.gateway_env() as env:
        HS, d, fake = _sudo_world(env, F.STARTER)
        r = HS.run_sudo(env, fake, "-S", "apt", "update", extra_env={"GW_USER_TOOLS": str(d)})
        assert r.returncode == 0 and r.stdout == "fake sudo ran\n", (r.stdout, r.stderr)
        assert HP.runs(d, "sudo")[-1]["argv"] == ["-S", "apt", "update"]
        assert fake.log() == [], "the gateway's sudo path never ran"


def test_an_elevation_restriction_alone_refuses_or_asks_then_passes_through():
    with H.gateway_env() as env:
        HS, d, fake = _sudo_world(env, '[hosts.localhost.policy]\nelevation = "deny"\n')
        r = HS.run_sudo(env, fake, "id", extra_env={"GW_USER_TOOLS": str(d)})
        assert r.returncode == 1 and "elevation" in r.stderr and not HP.runs(d, "sudo"), r
        HS, d, fake = _sudo_world(env, '[hosts.localhost.policy]\nelevation = "ask"\n')
        r = HS.run_sudo(env, fake, "id", extra_env={"GW_USER_TOOLS": str(d)})
        assert r.returncode == 1 and not HP.runs(d, "sudo"), "typed, but the hook didn't ask"
        assert "didn't ask you about this command" in r.stderr, r
        HS.asked("id")
        r = HS.run_sudo(env, fake, "id", extra_env={"GW_USER_TOOLS": str(d)})
        assert r.returncode == 0 and HP.runs(d, "sudo"), "typed by Claude: the hook asked"
        n = len(HP.runs(d, "sudo"))
        r = HS.run_sudo_from_shell(env, fake, "/bin/sh -c '{sudo}; true'; true", "id")
        assert "needs your OK" in r.stderr and len(HP.runs(d, "sudo")) == n, r


def test_configured_sudo_keeps_the_gated_path_and_a_removal_waits():
    with H.gateway_env() as env:
        HS, d, fake = _sudo_world(env, '[hosts.localhost]\nsudo = true\n')
        r = HS.run_sudo(env, fake, "echo", "gated", extra_env={"GW_USER_TOOLS": str(d)})
        assert r.stdout == "gated\n" and not HP.runs(d, "sudo"), "the gateway's own sudo path"
        assert fake.log()[-1]["ran"] == ["echo", "gated"]
        # the key taken out of the form: the approved sudo keeps gating until the
        # OK (PLAN-0.11 §1.1): still the gateway's path, never the user's sudo
        env.write_form("")
        r = HS.run_sudo(env, fake, "echo", "still", extra_env={"GW_USER_TOOLS": str(d)})
        assert r.stdout == "still\n" and not HP.runs(d, "sudo"), r
        assert fake.log()[-1]["ran"] == ["echo", "still"]
        # approved: the user's own from then on
        consent.approve("localhost", form=env.form())
        r = HS.run_sudo(env, fake, "echo", "mine", extra_env={"GW_USER_TOOLS": str(d)})
        assert HP.runs(d, "sudo")[-1]["argv"] == ["echo", "mine"], r


def test_the_configured_list_refuses_sudo_while_the_vault_cant_be_read():
    with H.gateway_env() as env:
        HS, d, fake = _sudo_world(env, '[hosts.localhost]\nsudo = true\n')
        assert consent.load_listed()["localhost_sudo"] is True
        env.write_form("")
        paths.vault_path().write_bytes(b"not an age file")          # unreadable now
        r = HS.run_sudo(env, fake, "echo", "x", extra_env={"GW_USER_TOOLS": str(d)})
        assert r.returncode == 1 and not HP.runs(d, "sudo"), r
        assert consent.LISTED_SUDO in r.stderr, r.stderr


# ---------------------------------------------------------------------------
# ssh, scp, sftp (§1.4)
# ---------------------------------------------------------------------------

TWO = (HOST + 'also = ["10.99.0.5"]\n\n[hosts.jump]\naddress = "u@jump.invalid"\n')


def _ssh_world(env, ssh_g: dict | None = None, form: str = TWO):
    env.write_form(form)
    vault.save(vault.empty())
    consent.approve_all(env.form())
    return HP.user_tools(env, "ssh", "scp", "sftp", ssh_g=ssh_g or {})


def test_ssh_to_an_unconfigured_host_runs_the_users_ssh():
    with H.gateway_env() as env:
        d = _ssh_world(env)
        r = HP.run_standin(env, "ssh", "-A", "-i", "~/.ssh/id_x", "other.invalid", "uptime")
        assert r.returncode == 0 and r.stdout == "fake ssh ran\n", (r.stdout, r.stderr)
        assert HP.runs(d, "ssh")[-1]["argv"] == ["-A", "-i", "~/.ssh/id_x", "other.invalid", "uptime"]
        # no destination at all (ssh -V): the user's own too
        assert HP.run_standin(env, "ssh", "-V").returncode == 0


def test_a_direct_hit_takes_the_gated_path_with_its_refusals():
    """By name, gw-NAME, address or `also` host: the gated path's full parse
    refuses -F (the gateway writes its own config); never passed through."""
    with H.gateway_env() as env:
        d = _ssh_world(env)
        for dest in ("box", "gw-box", "octo@box.invalid", "10.99.0.5"):
            r = HP.run_standin(env, "ssh", "-F", "/dev/null", dest, "uptime")
            assert r.returncode == 2 and "-F isn't allowed here" in r.stderr, (dest, r.stderr)
        assert not HP.runs(d, "ssh")


def test_a_configured_host_reached_only_indirectly_is_refused_with_a_hint():
    """Through the user's ssh config (`ssh -G` hostname), a ProxyJump hop
    (on the command line or in the config, followed through -G), or a
    ProxyCommand naming a configured address: refused, never routed."""
    with H.gateway_env() as env:
        d = _ssh_world(env, ssh_g={
            "alias.invalid": {"hostname": "box.invalid"},
            "hopper.invalid": {"proxyjump": "jump.invalid"},
            "deep.invalid": {"proxyjump": "mid.invalid"},
            "mid.invalid": {"hostname": "box.invalid"},
            "pc.invalid": {"proxycommand": "nc 10.99.0.5 22"},
        })
        cases = [
            (["alias.invalid", "uptime"], "your ssh config sends it to box.invalid"),
            (["-J", "jump.invalid", "x.invalid", "true"], "it goes through jump.invalid"),
            (["-o", "ProxyJump=jump", "x.invalid", "true"], "it goes through jump"),
            (["hopper.invalid", "true"], "it goes through jump.invalid"),
            (["deep.invalid", "true"], "which your ssh config sends to box.invalid"),
            (["pc.invalid", "true"], "its ProxyCommand names box"),
            (["-o", "ProxyCommand=ssh -W %h:%p gw-box", "y.invalid", "true"],
             "its ProxyCommand names box"),
        ]
        for argv, why in cases:
            r = HP.run_standin(env, "ssh", *argv)
            assert r.returncode == 2 and why in r.stderr and "use `ssh" in r.stderr, (argv, r.stderr)
        assert not HP.runs(d, "ssh")


def test_a_configured_address_found_by_resolving_the_name_is_refused():
    with H.gateway_env() as env:
        d = _ssh_world(env, form='[hosts.lo]\naddress = "u@127.0.0.1"\n')
        r = HP.run_standin(env, "ssh", "localhost", "true")
        assert r.returncode == 2 and "localhost is lo's address" in r.stderr, r.stderr
        assert not HP.runs(d, "ssh")


def test_scp_and_sftp_classify_every_remote_operand():
    with H.gateway_env() as env:
        d = _ssh_world(env)
        f = env.root / "f.txt"
        f.write_text("x\n")
        r = HP.run_standin(env, "scp", "-F", "/dev/null", str(f), "other.invalid:/tmp/f")
        assert r.returncode == 0 and HP.runs(d, "scp"), r
        r = HP.run_standin(env, "sftp", "u@other.invalid")
        assert r.returncode == 0 and HP.runs(d, "sftp"), r
        r = HP.run_standin(env, "scp", str(f), "box:/tmp/f", "other.invalid:/tmp/g")
        assert r.returncode == 2 and "copy in two steps" in r.stderr, r
        r = HP.run_standin(env, "scp", "-F", "/dev/null", str(f), "box:/tmp/f")
        assert r.returncode == 2 and "-F isn't allowed" in r.stderr, "configured: the gated path"
        r = HP.run_standin(env, "sftp", "-F", "/dev/null", "sftp://10.99.0.5/x")
        assert r.returncode == 2 and "-F isn't allowed" in r.stderr, r
        assert len(HP.runs(d, "sftp")) == 1


def test_scp_and_sftp_hand_their_ssh_config_to_the_users_ssh_g():
    """Review should-fix 7 (R11): scp -F CFG and sftp -F CFG give CFG to the
    user's `ssh -G`, so a config that sends an alias to a configured host is
    refused with a hint, never passed through; without it the alias is
    nobody's."""
    with H.gateway_env() as env:
        d = _ssh_world(env)
        cfg = env.root / "my ssh config.json"
        cfg.write_text(json.dumps({"alias.invalid": {"hostname": "box.invalid"}}))
        f = env.root / "f.txt"
        f.write_text("x\n")
        for tool, argv in (("scp", ["-F", str(cfg), str(f), "alias.invalid:/tmp/f"]),
                           ("scp", [f"-F{cfg}", str(f), "alias.invalid:/tmp/f"]),
                           ("sftp", ["-F", str(cfg), "alias.invalid"])):
            r = HP.run_standin(env, tool, *argv)
            assert r.returncode == 2 and "box.invalid" in r.stderr, (tool, argv, r.stderr)
        assert not HP.runs(d, "scp") and not HP.runs(d, "sftp")
        g = [x["argv"] for x in HP.runs(d, "ssh", with_g=True)]
        assert g and all(str(cfg) in " ".join(a) for a in g), g
        r = HP.run_standin(env, "scp", str(f), "alias.invalid:/tmp/f")
        assert r.returncode == 0 and HP.runs(d, "scp"), (r.stdout, r.stderr)


def test_git_over_ssh_passes_an_owner_no_account_covers_through():
    two = ('[accounts.work]\nkind = "github"\nlogin = "octo-work"\nowners = ["acme"]\n'
           '[accounts.mine]\nkind = "github"\nlogin = "octo"\nowners = ["octo"]\n')
    with H.gateway_env() as env:
        d = _ssh_world(env, form=two)
        r = HP.run_standin(env, "ssh", "git@github.com", "git-upload-pack 'someone/else.git'")
        assert r.returncode == 0 and HP.runs(d, "ssh"), (r.stdout, r.stderr)
        n = len(HP.runs(d, "ssh"))
        r = HP.run_standin(env, "ssh", "git@github.com", "git-upload-pack 'acme/repo.git'")
        assert len(HP.runs(d, "ssh")) == n and r.returncode != 0, "a covered owner: the account's"
        r = HP.run_standin(env, "ssh", "-T", "git@github.com")
        assert len(HP.runs(d, "ssh")) == n, "no owner named: an account of that host decides"


def test_a_locked_vault_still_classifies_an_unconfigured_target_passes_through():
    with H.gateway_env() as env:
        d = _ssh_world(env)
        from gateway import ssh

        def locked():
            raise vault.VaultLocked("gateway: the gateway vault is locked (test)")
        old = vault.load
        vault.load = locked
        try:
            with HP.capture_passthrough() as seen:
                try:
                    ssh.main("ssh", ["other.invalid", "true"])
                except HP.PassedThrough:
                    pass
            assert seen and seen[0].argv[1:] == ["other.invalid", "true"]
            import contextlib
            import io
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                rc = ssh.main("ssh", ["box", "true"])
            assert rc != 0 and "the gateway vault is locked (test)" in err.getvalue(), err.getvalue()
        finally:
            vault.load = old
        assert not HP.runs(d, "ssh")


# ---------------------------------------------------------------------------
# The account CLIs and dvc (§1.4)
# ---------------------------------------------------------------------------

TWO_GH = ('[accounts.work]\nkind = "github"\nlogin = "octo-work"\nowners = ["acme"]\n'
          '[accounts.mine]\nkind = "github"\nlogin = "octo"\nowners = ["octo"]\n')
AZ = ('[accounts.az]\nkind = "azure"\ntenant = "t.example.com"\n'
      'client_id = "11111111-2222-3333-4444-555555555555"\n'
      'databricks = ["adb-1.azuredatabricks.net"]\nregistries = ["acr1.azurecr.io"]\n')


def _cli(env, tool: str, argv: list[str], cwd: str | None = None, **envs: str | None):
    """The stand-in in-process: ("passed", argv) when it handed over to the
    user's own tool, else ("gated", rc, err)."""
    envs = {"GH_REPO": None, "GH_HOST": None, "HF_ENDPOINT": None, "DATABRICKS_HOST": None,
            **envs}
    with HA.env_vars(**envs), HP.capture_passthrough() as seen:
        try:
            rc, _out, err = HA.run_cli(tool, argv, cwd=cwd)
        except HP.PassedThrough as e:
            return "passed", e.argv[1:]
    assert not seen
    return "gated", rc, err


ONE_GH = '[accounts.work]\nkind = "github"\nlogin = "octo-work"\nowners = ["example-org"]\n'


def _gh_repo(env, name: str, url: str) -> str:
    d = env.root / "repos" / name
    d.mkdir(parents=True)
    genv = {"PATH": f"{H.ENV_BIN}:/usr/bin:/bin", "HOME": str(env.user_home),
            "GIT_CONFIG_NOSYSTEM": "1", "LANG": "C"}
    for args in (["init", "-q"], ["remote", "add", "origin", url]):
        r = subprocess.run([str(H.ENV_BIN / "git"), *args], cwd=str(d), env=genv,
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
    return str(d)


def test_the_only_account_that_lists_owners_covers_only_those_and_its_login():
    """WS-9: the only github account lists owners = ["example-org"]. A
    personal repository (octocat's) is the user's own: gh passes it to the
    user's gh, git over ssh to the user's ssh, select picks no account and the
    approval hook says nothing; example-org's and the account's own login's
    go through the gateway, as does a command that names no owner. Without
    `owners` (or with default = true) the only account covers every owner."""
    from gateway import accounts, hooks_bash
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        HA.build_vault(env, ONE_GH.replace('owners', 'use = "ask"\nowners'),
                       tokens={"work": "ghp_WORKtoken0123456789abcdefg"})
        # the gated gh is a recording fake: the offline suite never reaches
        # api.github.com (the bundled gh would, with this fake token)
        HA.install_fakes(env, gh=HA.fake_cli(env.root / "fake-bin", "gh"))
        tools = HP.user_tools(env, "gh")
        os.symlink(H.ENV_BIN / "git", tools / "git")   # the user's git: gh reads the remote with it
        mine = _gh_repo(env, "mine", "https://github.com/octocat/dots.git")
        work = _gh_repo(env, "work", "git@github.com:example-org/tool.git")
        assert _cli(env, "gh", ["pr", "list"], cwd=mine) == ("passed", ["pr", "list"])
        assert _cli(env, "gh", ["pr", "list", "-R", "octocat/hello"])[0] == "passed"
        assert _cli(env, "gh", ["pr", "list"], cwd=work)[0] == "gated"
        assert _cli(env, "gh", ["repo", "view", "octo-work/notes"])[0] == "gated"   # its login
        assert _cli(env, "gh", ["auth", "status"], cwd=str(env.root))[0] == "gated"  # no owner
        data = vault.load()
        form = consent.load_form(data)
        eff = consent.compute(form, data)

        def sel(owner):
            return accounts.select("github", "github.com", owner, form, effective=eff,
                                   asked={"work"}).name
        assert sel("octocat") is None and sel("example-org") == "work" and sel("octo-work") == "work"
        assert sel(None) == "work"

        def hook(cwd):
            out = hooks_bash.main({"tool_name": "Bash", "tool_input": {"command": "git push"},
                                   "permission_mode": "default", "cwd": cwd})
            return out and out["hookSpecificOutput"]["permissionDecision"]
        assert hook(mine) is None, "the user's own git: no decision"
        assert hook(work) == "ask", "work's use is \"ask\""
    with H.gateway_env() as env:
        d = _ssh_world(env, form=ONE_GH)
        r = HP.run_standin(env, "ssh", "git@github.com", "git-upload-pack 'octocat/dots.git'")
        assert r.returncode == 0 and HP.runs(d, "ssh"), (r.stdout, r.stderr)
        n = len(HP.runs(d, "ssh"))
        r = HP.run_standin(env, "ssh", "git@github.com", "git-upload-pack 'example-org/tool.git'")
        assert len(HP.runs(d, "ssh")) == n and r.returncode != 0, "example-org's: the account's"
    for text in (ONE_GH.replace('owners = ["example-org"]\n', ''),
                 ONE_GH + "default = true\n"):
        with H.gateway_env() as env:
            HA.set_direct((True, ""))
            HA.build_vault(env, text, tokens={"work": "ghp_WORKtoken0123456789abcdefg"})
            HA.install_fakes(env, gh=HA.fake_cli(env.root / "fake-bin", "gh"))
            HP.user_tools(env, "gh")
            assert _cli(env, "gh", ["pr", "list", "-R", "octocat/hello"])[:2] == ("gated", 0), text


def test_listing_the_first_owner_takes_other_owners_out_only_after_the_ok():
    """WS-9, invariant 3: the only account covers every owner while it lists
    none, so listing the first owner takes the other owners' repositories
    out of the gateway: a widening. Until the person's OK the approval keeps
    covering them (the ratchet never records the narrower reach), the
    configured list says so too, and the approval's dialog names it."""
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        HA.build_vault(env, ONE_GH.replace('owners = ["example-org"]\n', ''),
                       tokens={"work": "ghp_WORKtoken0123456789abcdefg"})
        HA.install_fakes(env, gh=HA.fake_cli(env.root / "fake-bin", "gh"))
        HP.user_tools(env, "gh")
        assert _cli(env, "gh", ["pr", "list", "-R", "octocat/hello"])[0] == "gated"
        env.write_form(ONE_GH)
        consent.ratchet()
        assert _cli(env, "gh", ["pr", "list", "-R", "octocat/hello"])[0] == "gated", "held"
        assert _cli(env, "gh", ["pr", "list", "-R", "example-org/tool"])[0] == "gated"
        data = vault.load()
        ap = data["approved"]["rights"]["accounts"]["work"]
        assert ap["any_owner"] is True and "example-org" in ap["owners"], ap
        assert json.loads(paths.configured_path().read_text())["accounts"]["work"]["any_owner"]
        pend = [c.render() for c in consent.compute(consent.load_form(data), data).pending]
        assert any("owners listed (as the only github account" in p for p in pend), pend
        consent.approve("work", form=env.form())
        assert _cli(env, "gh", ["pr", "list", "-R", "octocat/hello"])[0] == "passed"
        assert json.loads(paths.configured_path().read_text())["accounts"]["work"]["any_owner"] \
            is False
        # dropping every owner again covers them all at once (a narrowing)
        env.write_form(ONE_GH.replace('owners = ["example-org"]\n', ''))
        consent.ratchet()
        assert _cli(env, "gh", ["pr", "list", "-R", "octocat/hello"])[0] == "gated"


def test_gh_passes_a_destination_no_account_covers_and_keeps_the_rest():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        HA.build_vault(env, TWO_GH, tokens={"work": "ghp_WORKtoken0123456789abcdefg",
                                            "mine": "gho_MINEtoken0123456789abcdefg"})
        HA.install_fakes(env, gh=HA.fake_cli(env.root / "fake-bin", "gh"))
        HP.user_tools(env, "gh")
        assert _cli(env, "gh", ["pr", "list", "-R", "someone/else"]) == \
            ("passed", ["pr", "list", "-R", "someone/else"])
        assert _cli(env, "gh", ["api", "/repos/someone/x"])[0] == "passed"
        assert _cli(env, "gh", ["pr", "list", "-R", "ghe.other.example/acme/x"])[0] == "passed", \
            "a host no account has"
        assert _cli(env, "gh", ["pr", "list"], GH_REPO="someone/x")[0] == "passed"
        assert _cli(env, "gh", ["pr", "list", "-R", "acme/thing"])[:2] == ("gated", 0)
        # an owner that can't be told (gh api graphql, gh auth status, no repo here):
        # the gated path, never the user's full-scope token
        assert _cli(env, "gh", ["api", "graphql", "-f", "query=x"], cwd=str(env.root))[0] == "gated"
        assert _cli(env, "gh", ["auth", "status"], cwd=str(env.root))[0] == "gated"



def test_a_locked_vault_refuses_a_configured_account_and_passes_the_rest():
    """While the vault can't be read the configured list still classifies
    (PLAN-0.11 §16): a destination an account covers is refused with the
    lock's own text (never the user's token), any other runs the user's own
    gh."""
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        HA.build_vault(env, TWO_GH, tokens={"work": "ghp_WORKtoken0123456789abcdefg",
                                            "mine": "gho_MINEtoken0123456789abcdefg"})
        HP.user_tools(env, "gh")

        def locked():
            raise vault.VaultLocked("gateway: the gateway vault is locked (test)")
        old = vault.load
        vault.load = locked
        try:
            assert _cli(env, "gh", ["pr", "list", "-R", "someone/else"])[0] == "passed"
            got = _cli(env, "gh", ["pr", "list", "-R", "acme/thing"])
            assert got[0] == "gated" and got[1] != 0 and "vault is locked (test)" in got[2], got
        finally:
            vault.load = old

def test_one_github_account_covers_every_owner_of_its_host():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        HA.build_vault(env, GH, tokens={"gh": "ghp_ONEtoken0123456789abcdefghi"})
        HA.install_fakes(env, gh=HA.fake_cli(env.root / "fake-bin", "gh"))
        HP.user_tools(env, "gh")
        assert _cli(env, "gh", ["pr", "list", "-R", "anyone/x"])[:2] == ("gated", 0)


def test_hf_databricks_crane_az_and_pijul_resolve_their_destination():
    with H.gateway_env() as env:
        HA.set_direct((True, ""))
        HA.build_vault(env, '[accounts.hf]\nkind = "huggingface"\n' + AZ +
                       GH + 'packages = true\n[accounts.pj]\nkind = "pijul"\n',
                       tokens={"hf": "hf_TESTtoken0123456789abcdefgh",
                               "gh": "ghp_ONEtoken0123456789abcdefghi"})
        HP.user_tools(env, "hf", "databricks", "crane", "az", "pijul")
        assert _cli(env, "hf", ["download", "org/model"], HF_ENDPOINT="https://hub.other.example")[0] \
            == "passed"
        assert _cli(env, "hf", ["download", "org/model"])[0] == "gated"
        assert _cli(env, "databricks", ["clusters", "list"],
                    DATABRICKS_HOST="https://adb-9.azuredatabricks.net")[0] == "passed"
        assert _cli(env, "databricks", ["clusters", "list"],
                    DATABRICKS_HOST="https://adb-1.azuredatabricks.net")[0] == "gated"
        assert _cli(env, "databricks", ["clusters", "list"], cwd=str(env.root))[0] == "gated", \
            "a workspace that can't be told: the gated path"
        assert _cli(env, "crane", ["ls", "quay.io/org/img"])[0] == "passed"
        assert _cli(env, "crane", ["ls", "ghcr.io/octo/img"])[0] == "gated"
        assert _cli(env, "crane", ["ls", "acr1.azurecr.io/img"])[0] == "gated"
        assert _cli(env, "az", ["group", "list", "--tenant", "other.example.com"])[0] == "passed"
        assert _cli(env, "az", ["group", "list"])[0] == "gated"
        assert _cli(env, "pijul", ["clone", "https://other.example/x/y"])[0] == "passed"
        assert _cli(env, "pijul", ["clone", "https://nest.pijul.com/x/y"])[0] == "gated"


def test_dvc_outside_an_asiml_workspace_is_the_users_own():
    with H.gateway_env() as env:
        HP.user_tools(env, "dvc")
        from gateway import asiml
        with HP.capture_passthrough() as seen:
            try:
                asiml.dvc_main(["status"])
            except HP.PassedThrough:
                pass
        assert seen and seen[0].argv[1:] == ["status"]
        ws = env.root / "ws"
        (ws / ".asiml").mkdir(parents=True)
        (ws / ".asiml" / "workspace.json").write_text("{}")
        old = os.getcwd()
        os.chdir(ws)
        try:
            with HP.capture_passthrough() as seen:
                try:
                    asiml.dvc_main(["add", "x"])
                except HP.PassedThrough:
                    pass
            assert seen and seen[0].argv[1:] == ["add", "x"], "only pull and push go to asiml"
        finally:
            os.chdir(old)


# ---------------------------------------------------------------------------
# gate check brings a pending removal to the dialog (§1.1)
# ---------------------------------------------------------------------------


def _run_gate(fn, *args):
    import io
    import sys
    out, err = io.StringIO(), io.StringIO()
    so, se = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        rc = fn(*args)
    finally:
        sys.stdout, sys.stderr = so, se
    return rc, out.getvalue(), err.getvalue()


def test_gate_check_approves_a_pending_removal_and_check_all_finds_it():
    """A host taken out of gateway.toml keeps gating until the user's OK
    (§1.1); `gate check NAME` (no longer in the form) and `gate check all`
    bring the removal to the consent dialog, and the OK ends it: the host
    leaves the configured set and its stand-ins go."""
    import harness_ux as U
    from gateway import gate_setup
    for how in ("box", "all"):
        with U.ux_env(U.answers(("ok",))) as env:
            env.write_form(HOST)
            vault.save(vault.empty())
            consent.approve_all(env.form())
            env.write_form("")
            data = vault.load()
            form = consent.load_form(data)
            eff = consent.compute(form, data)
            assert gate_setup.removed_entries(form, eff) == ["box"], how
            assert "box" in eff.configured.hosts and "ssh" in envfile.standins_for(eff)
            rc, out, err = _run_gate(gate_setup.check, how)
            assert rc == 0, (how, out, err)
            calls = env.dialog.calls()
            assert len(calls) == 1 and "box" in json.dumps(calls[0]), (how, calls)
            data = vault.load()
            form = consent.load_form(data)
            eff = consent.compute(form, data)
            assert "box" not in eff.configured.hosts and not eff.pending, how
            assert gate_setup.removed_entries(form, eff) == [] and envfile.standins_for(eff) == []
            assert not (paths.bin_dir() / "ssh").exists(), "approve() took the stand-ins away"
        # a name that is neither in the form nor waiting: refused as before
        with U.ux_env(U.answers()) as env:
            env.write_form("")
            rc, out, err = _run_gate(gate_setup.check, "nothere")
            assert rc == 2 and env.dialog.calls() == [], (out, err)


# ---------------------------------------------------------------------------
# The first 0.11 session's notice, and the session's mode at SessionStart
# ---------------------------------------------------------------------------


def test_the_first_session_says_once_that_a_stored_sudo_password_is_unused():
    """§1.5: a vault holding this computer's sudo password while nothing
    configures sudo here gets one notice (a systemMessage: SessionStart can't
    wait for a dialog), recorded in the vault so it never repeats; a global
    [policy] deny that no longer reaches unconfigured targets is named too.
    Nothing while sudo here is configured, and nothing while the vault can't
    be read."""
    from gateway import hooks_session
    with H.gateway_env() as env:
        env.write_form('[policy]\nwrite = "deny"\n')
        vault.save(vault.empty())
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), "stored-password-0001")
        out = hooks_session.session_main({"session_id": "n1", "source": "startup"})
        msg = out.get("systemMessage", "")
        assert hooks_session.POSTURE_SUDO in msg, msg
        assert "[policy] write = deny now binds only" in msg, msg
        assert "stored-password-0001" not in json.dumps(out)
        assert vault.notice_shown(vault.load(), vault.POSTURE_NOTICE), "recorded in the vault"
        out = hooks_session.session_main({"session_id": "n2", "source": "startup"})
        assert hooks_session.POSTURE_SUDO not in out.get("systemMessage", ""), "said once"
    with H.gateway_env() as env:
        env.write_form('[hosts.localhost]\nsudo = true\n')
        vault.save(vault.empty())
        consent.approve_all(env.form())
        with vault.edit() as d:
            vault.set_sudo(d, "localhost", paths.local_user(), "stored-password-0001")
        out = hooks_session.session_main({"session_id": "n3", "source": "startup"})
        assert hooks_session.POSTURE_SUDO not in out.get("systemMessage", ""), "sudo is configured"
        assert not vault.notice_shown(vault.load(), vault.POSTURE_NOTICE)
    assert hooks_session.posture_notice(None, None) == [], "a vault that can't be read: nothing"


def test_session_start_records_the_payloads_permission_mode():
    """Lead decision 3: SessionStart records the payload's permission_mode
    (the sync hook, and the async hook-daemon once gated is up), so a
    stand-in's first call has the session's mode; no permission_mode in the
    payload, no record."""
    from gateway import hooks_bash, hooks_session
    from gateway.daemon import client, lifecycle
    seen: list[str] = []
    old = (hooks_bash.record_mode, lifecycle.ensure_running, client.call)
    hooks_bash.record_mode = lambda pm, eff: seen.append(pm) or True
    lifecycle.ensure_running = lambda *a, **k: None
    client.call = lambda *a, **k: {}
    try:
        with H.gateway_env() as env:
            env.write_form(HOST)
            hooks_session.session_main({"session_id": "m1", "permission_mode": "plan"})
            assert seen == ["plan"], seen
            hooks_session.daemon_main({"session_id": "m1", "permission_mode": "acceptEdits"})
            assert seen == ["plan", "acceptEdits"], seen
            hooks_session.session_main({"session_id": "m2"})
            hooks_session.daemon_main({"session_id": "m2"})
            assert seen == ["plan", "acceptEdits"], "no mode in the payload: no record"
    finally:
        hooks_bash.record_mode, lifecycle.ensure_running, client.call = old
