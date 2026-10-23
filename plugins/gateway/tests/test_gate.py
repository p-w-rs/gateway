"""The gate CLI: status rendering (table, entry, --report), log, why,
migrate, import-ssh, phase-B dispatch (SPEC 15)."""
from __future__ import annotations

import contextlib
import io
import os

import harness as H
from gateway import audit, consent, gate, paths, vault
from gateway import form as F


def run_gate(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = gate.main(list(args))
    return code, out.getvalue(), err.getvalue()


FORM = '''[hosts.localhost]
sudo = true
[hosts.example]
address = "octo@10.0.0.5"
[hosts.builder]
address = "ci@builder.internal"
via = "example"
sudo = false
[accounts.github-personal]
kind = "github"
login = "octocat"
default = true
[accounts.github-work]
kind = "github"
login = "octo-work"
owners = ["example-org"]
[accounts.openai]
kind = "api-key"
sites = ["api.openai.com"]
[accounts.off]
kind = "huggingface"
use = false
'''


def _setup(env, extra: str = ""):
    env.write_form(FORM + extra)
    vault.save(vault.empty())
    consent.approve_all(env.form())
    priv, pub = H.ssh_keypair("ps")
    with vault.edit() as d:
        vault.set_sudo(d, "localhost", paths.local_user(), "local-pw-1234")
        h = vault.host_record(d, "example")
        h["keys"].append(vault.key_record(priv, pub))
        vault.set_sudo(d, "example", "octo", "lab-pw-5678")
        vault.account_record(d, "github-personal", "github")["token"] = {
            "value": "gho_abcdefghijklmnop0123", "source": "gh-oauth", "stale": False}
        vault.account_record(d, "github-work", "github")["token"] = {
            "value": "ghp_abcdefghijklmnop0123", "source": "pasted", "stale": True}
        vault.account_record(d, "openai", "api-key")["token"] = {"value": "sk-abcdefghijklmnopqrstu"}
        vault.host_record(d, "oldbox")
        d["aliases"]["github:work"] = "github-work"


def test_status_table():
    with H.gateway_env() as env:
        _setup(env)
        env.write_form(FORM + '[hosts.broken]\naddress = "nope nope"\n[hosts.fresh]\naddress = "f.example.com"\n')
        code, out, _ = run_gate("status")
        assert code == 0
        lines = out.splitlines()
        assert lines[0] == "Hosts" and "Accounts" in lines
        row = {l.split()[0]: l for l in lines if l.startswith("  ") and l.split()}
        assert "sudo ✓ password saved" in row["localhost"]
        assert "ssh ✓ octo@10.0.0.5, key saved" in row["example"] and "password saved" in row["example"]
        assert "ssh ✓ via example, no key yet" in row["builder"] and "sudo ✗" in row["builder"]
        assert "waits for your OK (gate check fresh)" in row["fresh"]
        assert "octocat (default)" in row["github-personal"] and "signed in" in row["github-personal"]
        assert "example-org" in row["github-work"] and "token rejected (gate check github-work)" in row["github-work"]
        assert "api.openai.com" in row["openai"] and "key saved" in row["openai"]
        assert "off (use = false)" in row["off"]
        assert "Waiting for your OK" in out and "fresh: new host" in out
        assert "Problems in gateway.toml" in out and "broken" in out
        assert "Stored but not in the form: oldbox" in out
        assert out.rstrip().splitlines()[-1].startswith("File: ~/.config/gateway/gateway.toml   Just ask:")
        for secret in ("local-pw-1234", "lab-pw-5678", "gho_abc", "ghp_abc", "sk-abc", "PRIVATE"):
            assert secret not in out


def test_status_entry_and_alias():
    with H.gateway_env() as env:
        _setup(env)
        code, out, _ = run_gate("status", "github:work")
        assert code == 0 and out.startswith("github-work (github account)")
        assert "sends to github.com, api.github.com, ghcr.io" in out and "token rejected" in out
        code, out, _ = run_gate("status", "example")
        assert "address octo@10.0.0.5" in out and "keys    SHA256:" in out
        assert "sudo password for octo: saved" in out
        code, out, _ = run_gate("status", "nobody")
        assert "isn't in gateway.toml" in out


def test_status_writes_the_vault_only_to_persist_a_narrowing():
    with H.gateway_env() as env:
        _setup(env)
        before = paths.vault_path().read_bytes()
        run_gate("status")
        assert paths.vault_path().read_bytes() == before, "an unchanged form writes nothing"
        env.write_form(FORM.replace('sudo = true\n[hosts.example]', 'sudo = false\n[hosts.example]'))
        run_gate("status")
        d = vault.load()
        assert d["approved"]["rights"]["hosts"]["localhost"]["sudo"] is False, "the narrowing is persisted"
        env.write_form(FORM)
        code, out, _ = run_gate("status")
        assert "localhost: sudo false -> true" in out, "raising it again needs the user's OK"


def test_status_report_and_migrate_command():
    with H.gateway_env():
        code, out, _ = run_gate("status", "--report")
        assert "no migration report" in out
        paths.ensure_home()
        paths.v2_store_path().write_bytes(b"junk")
        paths.v2_key_path().write_text("AGE-SECRET-KEY-1X\n")
        code, out, err = run_gate("status", "--report")
        assert "gateway: migration failed" in err, "gate triggers migration and reports failure"
        assert "waiting to be migrated" in out and "last attempt" in out
        code, out, _ = run_gate("status")
        assert "Migration from 0.6 failed" in out
    with H.gateway_env():
        paths.ensure_home()
        H.write_v2_vault(paths.home(), {"version": 2, "secrets": {"K": {"value": "v" * 16, "hosts": ["k.example.com"]}},
                                        "sudo": {}, "accounts": {}})
        code, out, _ = run_gate("migrate")
        assert code == 0 and "migrated your 0.6 vault" in out and "K -> k" in out
        code, out, _ = run_gate("status", "--report")
        assert out.startswith("gateway: converted your 0.6 vault")
        code, out, _ = run_gate("migrate")
        assert code == 0 and "already migrated" in out


def test_log_and_why():
    with H.gateway_env():
        code, out, _ = run_gate("why")
        assert "no refusal recorded" in out
        old = os.environ.get("CLAUDE_CODE_SESSION_ID")
        os.environ["CLAUDE_CODE_SESSION_ID"] = "sess-why"
        try:
            audit.refusal("sudo", "builder", "gateway: sudo is off for builder (gateway.toml)",
                          fix="ask the user if it should be on")
            audit.use("ssh", "example", None, ["ssh", "example", "uptime"])
            code, out, _ = run_gate("why")
            assert "sudo is off for builder" in out and "Fix: ask the user" in out and "(sudo builder)" in out
            code, out, _ = run_gate("log", "5")
            assert "refusal" in out and "use" in out and "tool=ssh" in out
            assert run_gate("log", "x")[0] == 2
            assert run_gate("log", "\u00b2")[0] == 2, "a superscript digit is not a number"
        finally:
            if old is None:
                os.environ.pop("CLAUDE_CODE_SESSION_ID", None)
            else:
                os.environ["CLAUDE_CODE_SESSION_ID"] = old


def test_import_ssh_prints_toml_and_never_writes():
    with H.gateway_env() as env:
        env.write_form('[hosts.jump]\naddress = "me@bastion.example.com"\n')
        before = paths.form_path().read_text()
        cfg = env.user_home / ".ssh" / "config"
        cfg.parent.mkdir(parents=True)
        cfg.write_text("""
Host lab labbox
    HostName 10.0.0.5
    User octo
    Port 2222
Host inner
    HostName inner.internal
    User ci
    ProxyJump lab
Host viajump
    HostName v.example.com
    ProxyJump me@bastion.example.com
Host weird
    ProxyCommand nc %h %p
    HostName weird.example.com
Host *
    ServerAliveInterval 30
""")
        env.o.tools["ssh-system"] = str(H.ENV_BIN / "ssh")
        code, out, err = run_gate("import-ssh")
        assert code == 0, err
        assert paths.form_path().read_text() == before, "import-ssh never writes the form"
        assert '[hosts.lab]\naddress = "octo@10.0.0.5:2222"' in out
        assert '[hosts.inner]\naddress = "ci@inner.internal"\nvia     = "lab"' in out
        assert 'via     = "jump"' in out.split("[hosts.viajump]")[1]
        assert "ProxyCommand" in out.split("[hosts.weird]")[1]
        assert "Host *" not in out and "[hosts.labbox]" in out
        toml_part = "\n".join(l for l in out.splitlines())
        f = F.parse_text(before + "\n" + toml_part)
        assert {"lab", "inner", "viajump", "weird"} <= set(f.hosts), f.report_lines()
        code, out, _ = run_gate("import-ssh", "inner")
        assert "[hosts.inner]" in out and "[hosts.lab]" not in out


def test_import_ssh_never_proposes_a_second_table_for_a_form_host():
    with H.gateway_env() as env:
        form = '[hosts.box]\naddress = "me@box.example.com"\n'
        env.write_form(form)
        cfg = env.user_home / ".ssh" / "config"
        cfg.parent.mkdir(parents=True)
        cfg.write_text("Host box\n    HostName other.example.com\n    User me\n")
        env.o.tools["ssh-system"] = str(H.ENV_BIN / "ssh")
        code, out, _ = run_gate("import-ssh", "box")
        assert code == 0 and "[hosts.box]" not in out.replace("# [hosts.box]", "")
        assert "already in the form" in out and 'address = "me@other.example.com"' in out
        f = F.parse_text(form + "\n" + out)
        assert f.syntax_error is None, "pasting the whole proposal can't break the form"


def test_setup_and_transfer_commands_dispatch():
    """check/login/forget/rotate/secret (gate_setup), with (clis) and
    import/copy-to/pubkey (transfer) are real commands now: an unknown entry
    or file is refused by the command itself, never "not available"."""
    with H.gateway_env():
        for args in (["check", "box"], ["login", "gh"], ["rotate", "box"],
                     ["secret", "box"], ["with", "openai", "--", "env"],
                     ["import", "/nonexistent/f.age"], ["copy-to", "box"]):
            code, _, err = run_gate(*args)
            assert code != 0 and "isn't available in this build yet" not in err, (args, err)
            assert err.startswith("gateway:") or "gateway:" in err, (args, err)
        code, out, err = run_gate("forget", "gh")    # nothing stored: nothing to do
        assert "isn't available in this build yet" not in err, err
        code, out, err = run_gate("pubkey")
        assert code == 0 and out.startswith("age1"), (out, err)


def test_help_and_unknown():
    with H.gateway_env():
        code, out, _ = run_gate()
        assert code == 0 and "gate status" in out
        code, _, err = run_gate("frobnicate")
        assert code == 2 and "unknown or incomplete command: gate frobnicate" in err
        code, _, err = run_gate("check")
        assert code == 2


def test_status_on_a_fresh_install_says_no_form_yet():
    """Round 3: a new user's first `gate status` (before the starter form
    exists) said "gateway.toml is missing ... (approvals are kept)". It names
    this computer's sudo as it applies: "ask" on a new install, on for one an
    older gateway set up."""
    with H.gateway_env():
        assert not paths.form_path().exists() and not vault.exists()
        code, out, _ = run_gate("status")
        assert code == 0 and out.startswith("No gateway.toml yet"), out
        assert "missing" not in out and "approvals are kept" not in out
        assert "this computer's defaults apply (sudo asks each time)" in out.splitlines()[0], out
    # an older install (its vault an older gateway made, nothing approved or
    # kept as the last good form): its default then, sudo on
    with H.gateway_env():
        vault.save({"version": 3, "machine": {}, "localhost": {"sudo": {}}, "hosts": {},
                    "accounts": {}, "approved": {}, "form_last_good": None, "aliases": {},
                    "events": [], "events_seen": 0, "migrated": None})
        code, out, _ = run_gate("status")
        assert code == 0 and out.startswith("No gateway.toml yet"), out
        assert "this computer's defaults apply (sudo on)" in out.splitlines()[0], out


def test_status_footer_names_the_users_own_hosts():
    with H.gateway_env() as env:
        _setup(env)
        code, out, _ = run_gate("status")
        assert '"turn off sudo on example"' in out and "builder\"" not in out.splitlines()[-1]
        env.write_form('[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n')
        code, out, _ = run_gate("status")
        last = out.splitlines()[-1]
        assert '"add a server", "add my work GitHub"' in last and "builder" not in last, last
        env.write_form('[hosts.box]\naddress = "u@box.example.com"\nsudo = false\n')
        assert '"ask me before ssh to box"' in run_gate("status")[1].splitlines()[-1]


def test_why_in_the_users_own_terminal_shows_the_newest_refusal():
    """Round 3: without CLAUDE_CODE_SESSION_ID (the user's terminal, where
    README's Troubleshooting sends them) only refusals recorded without a
    session were found: "no refusal recorded in this session"."""
    with H.gateway_env():
        old = os.environ.get("CLAUDE_CODE_SESSION_ID")
        try:
            os.environ["CLAUDE_CODE_SESSION_ID"] = "sess-abc"
            audit.refusal("ssh", "box", "gateway: ssh is off for box (gateway.toml)")
            os.environ.pop("CLAUDE_CODE_SESSION_ID")
            code, out, _ = run_gate("why")
            assert code == 0 and "ssh is off for box" in out and "in session sess-abc" in out, out
        finally:
            if old is None:
                os.environ.pop("CLAUDE_CODE_SESSION_ID", None)
            else:
                os.environ["CLAUDE_CODE_SESSION_ID"] = old


def test_import_ssh_follows_includes_and_never_proposes_a_git_server():
    """Review round 4: Include'd hosts (OrbStack, 1Password, config.d/*) were
    missed, and a `Host github.com` block (User / IdentityFile) was proposed
    as a machine, whose address then took over git's ssh routing to GitHub."""
    with H.gateway_env() as env:
        env.write_form('[accounts.ghe]\nkind = "github"\nhost = "git.corp.example.com"\n'
                       'login = "me"\n')
        ssh_dir = env.user_home / ".ssh"
        (ssh_dir / "config.d").mkdir(parents=True)
        # absolute Include paths: ssh resolves relative ones against the REAL ~/.ssh
        (ssh_dir / "config.d" / "10-lab").write_text(
            "Host homelab\n    HostName 192.168.1.20\n    User alex\n")
        (ssh_dir / "config.d" / "20-build").write_text(
            f"Include {ssh_dir / 'more'}\n"
            "Host builder\n    HostName builder.example.com\n    User ci\n")
        (ssh_dir / "more").write_text("Host deep\n    HostName deep.example.com\n")
        cfg = ssh_dir / "config"
        cfg.write_text(f"Include {ssh_dir / 'config.d' / '*'}\n"
                       "Host github.com\n    User git\n    IdentityFile ~/.ssh/id_gh\n"
                       "Host gl\n    HostName gitlab.com\n"
                       "Host ghe\n    HostName git.corp.example.com\n"
                       "Host box\n    HostName box.example.com\n")
        # as ssh requires: upstream OpenSSH (the env's) refuses a group-writable
        # config, which a umask of 002 (Debian's user private groups) makes
        for f in (cfg, ssh_dir / "more", *(ssh_dir / "config.d").iterdir()):
            os.chmod(f, 0o600)
        os.chmod(ssh_dir, 0o700)
        assert gate.config_aliases(cfg) == ["homelab", "deep", "builder", "github.com", "gl",
                                            "ghe", "box"]
        env.o.tools["ssh-system"] = str(H.ENV_BIN / "ssh")
        code, out, err = run_gate("import-ssh")
        assert code == 0, err
        for n, addr in (("homelab", "alex@192.168.1.20"), ("builder", "ci@builder.example.com"),
                        ("deep", "deep.example.com"), ("box", "box.example.com")):
            assert f'[hosts.{n}]\naddress = ' in out and addr in out, (n, out)
        assert "[hosts.github-com]" not in out and "github.com is a git server" in out, out
        assert "[hosts.gl]" not in out and "gitlab.com is a git server" in out
        assert "[hosts.ghe]" not in out and "the git server of the account ghe" in out
        f = F.parse_text(paths.form_path().read_text() + "\n" + out)
        assert f.syntax_error is None and {"homelab", "builder", "deep", "box"} <= set(f.hosts)
        # a config ssh refuses: its own reason comes back (the home as ~), not just "error"
        os.chmod(ssh_dir / "config.d" / "10-lab", 0o666)
        code, out, err = run_gate("import-ssh", "homelab")
        assert "# homelab: ssh -G failed (Bad owner or permissions on ~/.ssh/config.d/10-lab" in out, out
        assert str(env.user_home) not in out


def test_a_host_at_a_git_servers_address_is_refused_by_the_form():
    """The form refuses a host whose address (or an also) is a git server:
    the ssh stand-in matches form hosts by address before account endpoints,
    so git@github.com would go to that host. An account endpoint of the form
    (GitHub Enterprise) only warns: its admin shell can be a machine."""
    from gateway import ssh, ssh_args
    with H.gateway_env():
        f = F.parse_text('[hosts.github-com]\naddress = "git@github.com"\n'
                         '[hosts.mirror]\naddress = "me@box.example.com"\nalso = ["git@gitlab.com"]\n'
                         '[hosts.ok]\naddress = "me@ok.example.com"\n'
                         '[accounts.gh]\nkind = "github"\nlogin = "me"\n')
        assert "github-com" not in f.hosts and "mirror" not in f.hosts and "ok" in f.hosts
        msgs = " ".join(p.message for p in f.errors)
        assert "github.com is a git server, not a machine: add a github account" in msgs, msgs
        assert "gitlab.com is a git server" in msgs
        t = ssh._classify(ssh_args.Destination(user="git", host="github.com", port=None), None, f)
        assert t.kind == "endpoint", t
        f = F.parse_text('[accounts.ghe]\nkind = "github"\nhost = "ghe.corp.example.com"\n'
                         '[hosts.ghe-admin]\naddress = "admin@ghe.corp.example.com:122"\n')
        assert "ghe-admin" in f.hosts
        assert any("ssh endpoint of the account ghe" in p.message for p in f.warnings), \
            f.report_lines()
        # an account host with a port (a web port: its ssh endpoint isn't known) doesn't warn
        f = F.parse_text('[accounts.git]\nkind = "github"\nhost = "127.0.0.1:8080"\n'
                         '[hosts.box]\naddress = "me@127.0.0.1:2222"\n')
        assert not f.warnings, f.report_lines()
