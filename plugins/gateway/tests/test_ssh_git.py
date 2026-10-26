"""git over ssh to account endpoints through the ssh stand-in (group 'ssh').

A github-like account `host = "ghe.test"` is served by the local sshd: the
`ssh_endpoint_map` test override sends ghe.test to 127.0.0.1:PORT as the
local user (sshd can't log in as git); the account keys have a forced
git-shell command rooted in the sshd's repos dir (like GitHub's)."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import harness  # noqa: F401
import harness_ssh as H
import harness_posture as HP
from gateway import vault

FORM = '''[accounts.ghe-work]
kind = "github"
host = "ghe.test"
login = "worker"
owners = ["acme"]

[accounts.ghe-me]
kind = "github"
host = "ghe.test"
login = "me"
default = true
'''


def _git() -> str:
    for p in ("/opt/local/bin/git", "/usr/local/bin/git", "/opt/homebrew/bin/git", "/usr/bin/git"):
        if os.access(p, os.X_OK):
            return p
    return str(H.ENV_BIN / "git")


def _setup(s: H.SshEnv, form: str = FORM) -> tuple[H.Sshd, dict[str, str]]:
    t = s.sshd("ghe")
    s.write_form(form)
    s.approve()
    fps = {}
    with vault.edit() as d:
        for name in ("ghe-work", "ghe-me"):
            priv, pub = s.key(name)
            t.authorize(pub, git=True)
            r = vault.account_record(d, name, "github")
            r["ssh_key"] = {"private": priv, "public": pub, "fingerprint": vault.fingerprint_of(pub)}
            r["host_keys"] = [t.host_key]
            fps[name] = vault.fingerprint_of(pub)
    for repo in ("acme/repo.git", "me/own.git", "other/x.git"):
        subprocess.run([_git(), "init", "-q", "--bare", "-b", "main", str(t.repos / repo)],
                       check=True, capture_output=True)
    s.set(ssh_endpoint_map={"ghe.test": {"host": "127.0.0.1", "port": t.port,
                                         "user": H.real_user()}})
    return t, fps


def _genv(s: H.SshEnv, extra: dict[str, str] | None = None) -> dict[str, str]:
    e = s.proc_env({"GIT_SSH_COMMAND": str(s.stub("ssh")), "HOME": str(s.env.user_home),
                    "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                    "GIT_TERMINAL_PROMPT": "0", "GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@x",
                    "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@x"})
    e.update(extra or {})
    return e


def _g(s: H.SshEnv, *args: str, cwd: Path | None = None,
       extra: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([_git(), *args], capture_output=True, text=True, env=_genv(s, extra),
                          cwd=str(cwd or s.root), timeout=90)


def test_ssh_git_clone_and_push_by_owner() -> None:
    with H.ssh_env() as s:
        t, fps = _setup(s)
        r = _g(s, "clone", "-q", "git@ghe.test:acme/repo.git", "work")
        assert r.returncode == 0, r
        work = s.root / "work"
        (work / "README").write_text("hello\n")
        assert _g(s, "add", "README", cwd=work).returncode == 0
        assert _g(s, "commit", "-qm", "first", cwd=work).returncode == 0
        r = _g(s, "push", "-q", "origin", "HEAD:main", cwd=work)
        assert r.returncode == 0, r
        log = subprocess.run([_git(), "--git-dir", str(t.repos / "acme/repo.git"), "log",
                              "--format=%s", "main"], capture_output=True, text=True)
        assert log.stdout == "first\n"
        uses = [u for u in s.audit("use") if u["tool"] == "ssh"]
        assert uses and all(u["account"] == "ghe-work" and u["target"] == "git@ghe.test"
                            for u in uses), uses
        assert {u["argv"].split()[0] for u in uses} == {"git-upload-pack", "git-receive-pack"}
        sshd_log = t.log.read_text()
        assert fps["ghe-work"] in sshd_log and fps["ghe-me"] not in sshd_log
        assert not s.masters()            # endpoints never share a connection


def test_ssh_git_account_selection() -> None:
    with H.ssh_env() as s:
        t, fps = _setup(s)
        assert _g(s, "clone", "-q", "git@ghe.test:me/own.git", "own").returncode == 0
        assert s.audit("use")[-1]["account"] == "ghe-me"                     # owner = login
        assert _g(s, "clone", "-q", "ssh://git@ghe.test/other/x.git", "x").returncode == 0
        assert s.audit("use")[-1]["account"] == "ghe-me"                     # the default
        r = _g(s, "clone", "-q", "git@ghe.test:me/own.git", "own2",
               extra={"GATE_ACCOUNT": "ghe-work"})
        assert r.returncode == 0 and s.audit("use")[-1]["account"] == "ghe-work"
        assert fps["ghe-work"] in t.log.read_text()
        r = _g(s, "clone", "-q", "git@ghe.test:me/own.git", "own3",
               extra={"GATE_ACCOUNT": "nobody"})
        assert r.returncode != 0 and "GATE_ACCOUNT=nobody isn't an account" in r.stderr


def test_ssh_git_refusals() -> None:
    with H.ssh_env() as s:
        form = FORM.replace("default = true\n", "")
        t, fps = _setup(s, form)
        # an owner no account covers (no owner match, no default, two accounts):
        # the user's own ssh and agent (PLAN-0.11 §1.4 step 9)
        d = HP.user_tools(s.env, "ssh")
        s.set(user_tools=str(d))
        r = s.run("ssh", "git@ghe.test", "git-upload-pack 'other/x.git'")
        assert r.returncode == 0 and r.stdout == "fake ssh ran\n", r
        assert HP.runs(d, "ssh")[-1]["argv"] == ["git@ghe.test", "git-upload-pack 'other/x.git'"]
        # only git commands, only as git@
        r = s.run("ssh", "git@ghe.test", "id")
        assert r.returncode == 2 and "only git commands go to ghe.test over ssh" in r.stderr
        r = s.run("ssh", "bob@ghe.test", "git-upload-pack 'acme/repo.git'")
        assert r.returncode == 2 and "takes git over ssh as git@ghe.test" in r.stderr
        # no ssh key: use https
        with vault.edit() as d:
            del d["accounts"]["ghe-work"]["ssh_key"]
        r = s.run("ssh", "git@ghe.test", "git-upload-pack 'acme/repo.git'")
        assert r.returncode == 2 and "ghe-work has no ssh key; use an https remote" in r.stderr
        # not direct, scripts false: no key
        with vault.edit() as d:
            priv, pub = s.key("ghe-work")
            d["accounts"]["ghe-work"]["ssh_key"] = {"private": priv, "public": pub}
        s.set(direct=False, culprit="npm")
        r = s.run("ssh", "git@ghe.test", "git-upload-pack 'acme/repo.git'")
        assert r.returncode == 2 and "git over ssh started by npm got no key" in r.stderr, r
        # no pinned host key
        s.set(direct=True)
        with vault.edit() as d:
            d["accounts"]["ghe-work"]["host_keys"] = []
        r = s.run("ssh", "git@ghe.test", "git-upload-pack 'acme/repo.git'")
        assert r.returncode == 2 and "no pinned host key for ghe.test" in r.stderr
        assert t.accepted() == 0 and t.commands() == []
        # github.com uses the built-in host keys
        assert vault.builtin_host_keys("github.com", 22)


def test_ssh_git_unbound_credential_never_sent() -> None:
    with H.ssh_env() as s:
        form = FORM.split("[accounts.ghe-me]")[0]          # ghe-work only
        t, fps = _setup(s, form)
        with vault.edit() as d:
            d["accounts"]["ghe-work"]["bound"]["hosts"] = []
        r = s.run("ssh", "git@ghe.test", "git-upload-pack 'acme/repo.git'")
        assert r.returncode == 2 and "ghe-work is the account for acme but can't be used yet" \
            in r.stderr, r
        r = s.run("ssh", "git@ghe.test", "git-upload-pack 'acme/repo.git'",
                  extra_env={"GATE_ACCOUNT": "ghe-work"})
        assert r.returncode == 2 and "ghe-work" in r.stderr, r
        assert t.accepted() == 0 and fps["ghe-work"] not in t.log.read_text()


def test_ssh_git_pending_owner_account_not_given_to_another() -> None:
    """A pending account's repos never go to the other account of the host
    (accounts.select refuses, naming the account that waits for the OK)."""
    with H.ssh_env() as s:
        form = FORM.replace("default = true\n", "")
        t, fps = _setup(s, form)
        with vault.edit() as d:
            d["accounts"]["ghe-work"]["bound"]["hosts"] = []
        r = s.run("ssh", "git@ghe.test", "git-upload-pack 'acme/repo.git'", input="0000")
        assert r.returncode == 2, r
        assert ("gateway: ghe-work is the account for acme but can't be used yet (it waits for the "
                "user's OK); run gate check ghe-work") in r.stderr, r.stderr
        assert t.accepted() == 0 and fps["ghe-me"] not in t.log.read_text()
        assert not [u for u in s.audit("use") if u.get("account") == "ghe-me"]
        # its own repos still go with ghe-me; GATE_ACCOUNT is the user's explicit choice
        assert _g(s, "clone", "-q", "git@ghe.test:me/own.git", "own").returncode == 0
        assert s.audit("use")[-1]["account"] == "ghe-me"
        r = _g(s, "clone", "-q", "git@ghe.test:acme/repo.git", "acme",
               extra={"GATE_ACCOUNT": "ghe-me"})
        assert r.returncode == 0 and s.audit("use")[-1]["account"] == "ghe-me", r


LFS_JSON = ('{"href":"https://ghe.test/acme/repo.git/info/lfs","header":{"Authorization":'
            '"RemoteAuth LFSTOKEN-abcdef0123456789"},"expires_in":3599}')


def test_ssh_git_lfs_authenticate_only_for_git_lfs() -> None:
    with H.ssh_env() as s:
        t = s.sshd("ghe")
        s.write_form(FORM.split("[accounts.ghe-me]")[0])
        s.approve()
        lfs = t.dir / "lfs.sh"
        lfs.write_text(f"#!/bin/sh\nprintf '%s\\n' {H.sq(LFS_JSON)}\n")
        os.chmod(lfs, 0o755)
        priv, pub = s.key("ghe-work")
        with open(t.ak, "a") as f:
            f.write(f'command="{lfs}" {pub}\n')
        with vault.edit() as d:
            r = vault.account_record(d, "ghe-work", "github")
            r["ssh_key"] = {"private": priv, "public": pub, "fingerprint": vault.fingerprint_of(pub)}
            r["host_keys"] = [t.host_key]
        s.set(ssh_endpoint_map={"ghe.test": {"host": "127.0.0.1", "port": t.port,
                                             "user": H.real_user()}})
        r = s.run("ssh", "git@ghe.test", "git-lfs-authenticate acme/repo download")
        assert r.returncode == 2 and "LFSTOKEN" not in r.stdout + r.stderr, r
        assert "only git-lfs may run it" in r.stderr
        assert t.accepted() == 0
        s.set(lfs_parent=True)                    # git-lfs started this ssh: it gets the token
        r = s.run("ssh", "git@ghe.test", "git-lfs-authenticate acme/repo download")
        assert r.returncode == 0 and "LFSTOKEN-abcdef0123456789" in r.stdout, r
        assert s.audit("use")[-1]["argv"].startswith("git-lfs-authenticate acme")


def test_ssh_git_lfs_parent_check() -> None:
    """_started_by_git_lfs walks up through shells to the first other
    executable (by path, ancestry's helpers) and fails closed."""
    from gateway import ancestry, ssh
    chains = {"git-lfs": True, "zsh git-lfs": True, "sh env git-lfs": True,
              "python3.12": False, "sh make git-lfs": False, "bash": False}
    saved = (ancestry._exe_name, ancestry._ppid)
    try:
        for chain, want in chains.items():
            names = chain.split()
            base = os.getppid()
            table = {base + k: n for k, n in enumerate(names)}
            ancestry._exe_name = lambda pid, t=table: t.get(pid, "")
            ancestry._ppid = lambda pid, t=table: pid + 1 if pid + 1 in t else 1
            assert ssh._started_by_git_lfs() is want, chain

        def broken(pid: int) -> str:
            raise OSError("no such process")

        ancestry._exe_name = broken
        assert ssh._started_by_git_lfs() is False
    finally:
        ancestry._exe_name, ancestry._ppid = saved
