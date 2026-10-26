"""The gate CLI: status rendering (table, entry), log, why, import-ssh,
phase-B dispatch (SPEC 15)."""
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
        assert ("localhost: sudo on this computer: in Auto and Bypass permissions modes the gateway "
                "now approves without asking you; elsewhere Claude Code decides (was: refused in "
                "every mode)") in out, "raising it again needs the user's OK"


def test_a_gateway_06_vault_is_named_and_gate_migrate_is_gone():
    """A gateway 0.6 vault (store.age, no vault.age) gets one note in `gate
    status`: convert it with gateway 0.10.0 first. Nothing converts it here:
    `gate migrate` is refused like any command that isn't read-only (and is
    unknown without a 0.6 vault), `gate status --report` is a usage error, and
    no vault appears."""
    with H.gateway_env():
        paths.ensure_home()
        paths.v2_store_path().write_bytes(b"junk")
        paths.v2_key_path().write_text("AGE-SECRET-KEY-1X\n")
        code, out, err = run_gate("status")
        assert code == 0 and out.count(vault.V06_MESSAGE) == 1, out
        assert "migrat" not in out + err, (out, err)
        code, out, err = run_gate("migrate")
        assert code == 2 and err.strip() == vault.V06_MESSAGE, (code, err)
        assert "gate migrate" not in gate.USAGE and "--report" not in gate.USAGE
        assert not paths.vault_path().exists() and paths.v2_store_path().read_bytes() == b"junk"
    with H.gateway_env():
        code, out, _ = run_gate("status")
        assert vault.V06_MESSAGE not in out, "no 0.6 vault, no note"
        code, out, err = run_gate("migrate")
        assert code == 2 and "unknown or incomplete command: gate migrate" in err, (code, err)


def test_gate_status_refuses_flags_and_extra_names():
    """`gate status [NAME]` and nothing else: an unknown flag (the removed
    --report among them) or a second name is a usage error, never ignored."""
    with H.gateway_env() as env:
        env.write_form(FORM)
        for args in (["--report"], ["-x"], ["example", "--report"], ["--report", "example"],
                     ["example", "builder"]):
            code, out, err = run_gate("status", *args)
            assert code == 2 and not out and "usage: gate status [NAME]" in err, (args, code, out, err)
        code, out, _ = run_gate("status", "example")
        assert code == 0 and "example" in out


def test_beside_a_gateway_06_vault_only_read_only_commands_run():
    """Beside a gateway 0.6 vault every gate command that could ask the user
    or write the vault, its key or the form is refused with vault.V06_MESSAGE
    (exit 2) before it asks anything, so `gate check` never ends in "didn't
    work after 3 tries" and nothing lands beside store.age for gateway 0.10.0's
    conversion to find. status, log, why, import-ssh, lock and scrub run."""
    import harness_ux as U
    from gateway import gate_setup
    with U.ux_env(U.answers(("ok", gate_setup.SUDO_ASK), ("ok", "a-password-of-20-chars"))) as env:
        paths.ensure_home()
        paths.v2_store_path().write_bytes(b"age-encryption.org/v1 a 0.6 store")
        paths.v2_key_path().write_text("AGE-SECRET-KEY-1X\n")
        refused = (["check", "localhost"], ["check", "all"], ["login", "gh"], ["forget", "localhost"],
                   ["forget", "localhost", "sudo"], ["rotate", "box"], ["export"],
                   ["import", str(env.root / "x.age")], ["copy-to", "box"], ["pubkey"],
                   ["with", "gh", "--", "true"], ["host", "add", "box", "me@10.0.0.9"],
                   ["host", "set", "box", "sudo", "true"], ["workspace", "add", "box", "w", "/srv"],
                   ["workspace", "remove", "box", "w"], ["policy", "set", "all", "read", "ask"],
                   ["accounts"], ["accounts", "--check", "all"], ["secret", "x"], ["nonsense"])
        for argv in refused:
            code, out, err = run_gate(*argv)
            assert code == 2 and not out and err.strip() == vault.V06_MESSAGE, (argv, code, out, err)
        assert not env.dialog.calls(), env.dialog.calls()
        for argv in (["status"], ["log"], ["why"], ["import-ssh"], ["lock"]):
            code, out, err = run_gate(*argv)
            assert vault.V06_MESSAGE not in err, (argv, err)
        assert gate.BESIDE_V06 == {"scrub", "status", "log", "why", "import-ssh", "lock"}
        for p in (paths.vault_path(), paths.key_path(), paths.wrapped_key_path(), paths.form_path()):
            assert not p.exists(), p
        assert paths.v2_store_path().read_bytes() == b"age-encryption.org/v1 a 0.6 store"
        assert paths.v2_key_path().read_text() == "AGE-SECRET-KEY-1X\n"
    with U.ux_env() as env:                  # no 0.6 vault: pubkey makes the key as usual
        code, out, err = run_gate("pubkey")
        assert code == 0 and out.startswith("age1") and paths.key_path().exists(), (code, out, err)


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
    exists) said "gateway.toml is missing ... (approvals are kept)". PLAN-0.11
    §1.5: nothing goes through the gateway then (this computer's sudo is the
    user's own), also with a vault that holds nothing approved."""
    with H.gateway_env():
        assert not paths.form_path().exists() and not vault.exists()
        code, out, _ = run_gate("status")
        assert code == 0 and out.startswith("No gateway.toml yet"), out
        assert "missing" not in out and "approvals are kept" not in out
        assert "nothing goes through the gateway (your own ssh, git, gh and sudo)" in \
            out.splitlines()[0], out
        assert "sudo: your own (not through the gateway)" in out, out      # the localhost row
    with H.gateway_env():
        vault.save({"version": 3, "machine": {}, "localhost": {"sudo": {}}, "hosts": {},
                    "accounts": {}, "approved": {}, "form_last_good": None, "aliases": {},
                    "events": [], "events_seen": 0, "migrated": None})
        code, out, _ = run_gate("status")
        assert code == 0 and out.startswith("No gateway.toml yet"), out
        assert "nothing goes through the gateway" in out.splitlines()[0], out


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
