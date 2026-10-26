"""The git stand-in (PLAN-0.11 §6): routing by repository (a repository with
a configured remote is gated for every command, status and commit included;
anything else runs the user's own git, untouched), the gated git's
environment (an allowlist, the include and the ssh stand-in at command
scope, a read-only global config with init defaults, no system config),
the -c pairs and `git config` writes the gateway refuses there, the
approval hook's up-front judging of remote commands (requirement 24: a push
to an "ask" host is asked about before it runs and then runs), git by path,
the cold stub, and the cost budget (§6.6).

The user's own git is a recording fake (harness_posture.user_tools); the
gated git is the env's own; the push end to end runs over a real sshd on
127.0.0.1 (harness_ssh) with the real process tree."""
from __future__ import annotations

import contextlib
import dataclasses
import json
import os
import shutil
import stat
import subprocess
import time
from pathlib import Path
from typing import Any, Iterator

import harness as H
import harness_accounts as HA
import harness_posture as HP
from gateway import ancestry, asks, audit, consent, envfile, githelper, hooks_bash, paths, vault

GIT = str(H.ENV_BIN / "git")
FORM = '''[accounts.work]
kind = "github"
login = "octo-work"
owners = ["example-org"]
name = "Octo Work"
email = "work@example.com"

[hosts.box]
address = "octo@box.invalid"
'''
WORK = "https://github.com/example-org/tool.git"        # configured (work's owner)
PLAIN = "https://git.example.org/team/x.git"             # nothing configured there
BOX = "box:srv/repo.git"                                 # the configured host by name
WTOK = "ghp_WORKtoken0123456789abcdefg"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _hermetic(env: H.GatewayEnv) -> dict[str, str]:
    """The test's own git calls: a scratch HOME, no system config."""
    home = env.root / "githome"
    home.mkdir(exist_ok=True)
    (home / ".gitconfig").touch()
    return {"PATH": f"{H.ENV_BIN}:/usr/bin:/bin", "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(home / ".gitconfig"), "LANG": "C"}


def _git(env: H.GatewayEnv, cwd: Path, *args: str, extra: dict[str, str] | None = None,
         check: bool = True) -> subprocess.CompletedProcess[str]:
    r = subprocess.run([GIT, *args], cwd=str(cwd), env={**_hermetic(env), **(extra or {})},
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 or not check, (args, r.stderr)
    return r


def _repo(env: H.GatewayEnv, name: str, *remotes: tuple[str, str]) -> Path:
    d = env.root / name
    d.mkdir(parents=True)
    _git(env, d, "init", "-q", "-b", "main")
    for rn, url in remotes:
        _git(env, d, "remote", "add", rn, url)
    return d


def _setup(env: H.GatewayEnv, form: str = FORM, tokens: dict[str, str] | None = None) -> None:
    """The form approved, a vault with work's token, and everything
    SessionStart writes (stubs, the include and identities, the global)."""
    env.o.entry = H.entry_cmd(env)
    HA.build_vault(env, form, tokens=tokens or {"work": WTOK})
    data = vault.load()
    envfile.sync(env.form(), consent.compute(env.form(), data), vault.meta(data), None)


class Ran(Exception):
    """The stand-in exec'd (the gated git or, passing through, the user's)."""

    def __init__(self, path: str, argv: list[str], env: dict[str, str]):
        super().__init__(path)
        self.path, self.argv, self.env = path, list(argv), dict(env)


@contextlib.contextmanager
def _inproc(cwd: Path, environ: dict[str, str], typed: tuple[bool, str]) -> Iterator[None]:
    saved_env, old = dict(os.environ), os.getcwd()

    def fake(path: str, argv: list[str], env: dict[str, str]) -> None:
        raise Ran(path, argv, env)
    saved = [(envfile, "_execve", envfile._execve), (githelper, "_execve", githelper._execve),
             (ancestry, "typed_by_claude", ancestry.typed_by_claude)]
    envfile._execve = fake
    githelper._execve = fake
    ancestry.typed_by_claude = lambda: typed
    os.environ.clear()
    os.environ.update(environ)
    os.chdir(cwd)
    try:
        yield
    finally:
        os.chdir(old)
        os.environ.clear()
        os.environ.update(saved_env)
        for mod, attr, val in saved:
            setattr(mod, attr, val)


def _run(env: H.GatewayEnv, cwd: Path, *argv: str, environ: dict[str, str] | None = None,
         typed: tuple[bool, str] = (True, "")) -> Ran | tuple[int, str]:
    """githelper.git_main in-process in `cwd`: the exec it ends in (Ran), or
    (exit code, stderr) when it refused."""
    e = {**_hermetic(env), **(environ or {})}
    with _inproc(cwd, e, typed):
        with HA.capture_fds() as box:
            try:
                rc = githelper.git_main(list(argv))
            except Ran as r:
                return r
    return rc, box["err"].decode()


def _gated(r: Any) -> bool:
    return isinstance(r, Ran) and os.path.realpath(r.path) == os.path.realpath(GIT)


def _passed(r: Any, fakes: Path) -> bool:
    return isinstance(r, Ran) and r.path == str(fakes / "git")


def _hook(command: str, cwd: Path, mode: str = "default", tool: str = "Bash") -> dict | None:
    old = os.environ.pop("CLAUDE_PROJECT_DIR", None)
    try:
        ti = {"command": command}
        return hooks_bash.main({"tool_name": tool, "tool_input": ti, "cwd": str(cwd),
                                "permission_mode": mode})
    finally:
        if old is not None:
            os.environ["CLAUDE_PROJECT_DIR"] = old


def _decision(out: dict | None) -> str | None:
    return None if out is None else out["hookSpecificOutput"]["permissionDecision"]


def _reason(out: dict | None) -> str:
    return "" if out is None else out["hookSpecificOutput"]["permissionDecisionReason"]


# ---------------------------------------------------------------------------
# Which git runs (§6.1, §6.2, §6.4)
# ---------------------------------------------------------------------------


def test_git_is_a_stand_in_only_where_something_configured_is_reachable():
    with H.gateway_env() as env:
        for text, want in ((FORM, True), ('[hosts.box]\naddress = "u@box.invalid"\n', True),
                           ('[accounts.hf]\nkind = "huggingface"\n', True),
                           ('[accounts.pj]\nkind = "pijul"\n', False),
                           ('[hosts.localhost]\nsudo = "ask"\n', False), ("", False)):
            env.write_form(text)
            assert ("git" in envfile.standins_for(consent.compute(env.form(), {}))) == want, text


def test_a_repository_with_a_configured_remote_is_gated_for_every_command():
    """Commit and status included (the account's identity applies there);
    a repository with no configured remote runs the user's own git with the
    full argv and the environment unchanged, and only a command that touches
    a remote writes the pass-through audit line."""
    with H.gateway_env() as env:
        _setup(env)
        fakes = HP.user_tools(env, "git")
        cfg = _repo(env, "cfg", ("origin", WORK))
        plain = _repo(env, "plain", ("origin", PLAIN))
        mine = {"SSH_AUTH_SOCK": "/tmp/agent-fake", "GH_TOKEN": "gho_fake_user_token"}
        for argv in (("status",), ("commit", "-qm", "x"), ("log", "-1"), ("push", "origin")):
            r = _run(env, cfg, *argv, environ=mine)
            assert _gated(r), (argv, r)
            assert r.argv == [r.path, *argv]
            assert "SSH_AUTH_SOCK" not in r.env and "GH_TOKEN" not in r.env
        before = len(audit.read(0))
        r = _run(env, plain, "status", environ=mine)
        assert _passed(r, fakes) and r.argv == [str(fakes / "git"), "status"], r
        assert r.env["SSH_AUTH_SOCK"] == "/tmp/agent-fake" and r.env["GH_TOKEN"].startswith("gho_")
        assert r.env["GW_PASSTHRU"].startswith("git:1:")
        assert not [x for x in audit.read(0)[before:] if x.get("event") == "passthrough"], \
            "git status writes nothing to the shared audit log"
        r = _run(env, plain, "fetch", "origin", environ=mine)
        assert _passed(r, fakes), r
        lines = [x for x in audit.read(0)[before:] if x.get("event") == "passthrough"]
        assert [(x["tool"], x["target"]) for x in lines] == [("git", "git.example.org")], lines
        assert "fetch" not in str(lines), "never argv"


def test_a_personal_repository_is_the_users_own_when_the_only_account_lists_owners():
    """WS-9: FORM's only github account lists owners = ["example-org"], so it
    covers only that owner and its own login: `git push` in octocat's
    repository runs the user's own git (never work's key), in example-org's
    or octo-work's the gated git. Without `owners` it covers every owner."""
    for text, mine_gated in ((FORM, False),
                             (FORM.replace('owners = ["example-org"]\n', ''), True)):
        with H.gateway_env() as env:
            _setup(env, text)
            fakes = HP.user_tools(env, "git")
            mine = _repo(env, "mine", ("origin", "https://github.com/octocat/dots.git"))
            ssh_mine = _repo(env, "ssh-mine", ("origin", "git@github.com:octocat/dots.git"))
            own = _repo(env, "own", ("origin", "https://github.com/octo-work/notes.git"))
            work = _repo(env, "work", ("origin", WORK))
            for repo in (mine, ssh_mine):
                r = _run(env, repo, "push", "origin", "main")
                assert (_gated(r) if mine_gated else _passed(r, fakes)), (text, repo, r)
            for repo in (own, work):
                assert _gated(_run(env, repo, "push", "origin", "main")), (text, repo)


def test_operands_options_and_accounts_route_the_command():
    with H.gateway_env() as env:
        _setup(env, FORM + '[accounts.ghes]\nkind = "github"\nhost = "ghe.example.com"\n'
                           'login = "octo-ghes"\n')
        fakes = HP.user_tools(env, "git")
        cfg = _repo(env, "cfg", ("origin", WORK))
        plain = _repo(env, "plain", ("origin", PLAIN))
        out = env.root / "nowhere"
        out.mkdir()
        assert _gated(_run(env, out, "clone", WORK))                       # a configured operand
        assert _gated(_run(env, out, "ls-remote", BOX))                    # the host by name
        assert _gated(_run(env, out, "ls-remote", "https://ghe.example.com/octo-ghes/x.git"))
        assert _passed(_run(env, out, "ls-remote", PLAIN), fakes)
        assert _gated(_run(env, plain, "-C", str(cfg), "status"))          # -C into it
        assert _gated(_run(env, plain, "status", environ={"GIT_DIR": str(cfg / ".git")}))
        assert _gated(_run(env, plain, "-c", f"remote.origin.url={WORK}", "status"))
        # the user's own config: passes through even in a gated repository
        r = _run(env, cfg, "config", "--global", "user.name", "Octo")
        assert _passed(r, fakes), r


def test_the_gated_environment_is_an_allowlist_with_the_gateways_settings():
    """§6.3: one case per name the gated git must never inherit; what it
    keeps; the include and the ssh stand-in at command scope, the read-only
    global config, no system config, and the mark for its children."""
    dropped = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "credential.helper",
               "GIT_CONFIG_VALUE_0": "!evil", "GIT_CONFIG_PARAMETERS": "'credential.helper'='x'",
               "GIT_ASKPASS": "/x/askpass", "SSH_ASKPASS": "/x/askpass", "GIT_SSH": "/x/ssh",
               "GIT_SSH_COMMAND": "/x/ssh", "GIT_SSH_VARIANT": "ssh", "GIT_PROXY_COMMAND": "/x/p",
               "GIT_EXEC_PATH": "/x/libexec", "GIT_SSL_NO_VERIFY": "1", "GIT_SSL_CAINFO": "/x/ca",
               "GIT_SSL_CAPATH": "/x", "GIT_TRACE": "1", "GIT_TRACE_PACKET": "1",
               "GIT_TRACE_CURL": "1", "GIT_TRACE_REDACT": "0", "GIT_CURL_VERBOSE": "1",
               "http_proxy": "http://p:1", "https_proxy": "http://p:1", "HTTPS_PROXY": "http://p:1",
               "ALL_PROXY": "socks5://p:1", "all_proxy": "socks5://p:1",
               "SSL_CERT_FILE": "/x/ca.pem", "CURL_CA_BUNDLE": "/x/ca.pem",
               "GIT_CONFIG_GLOBAL": "/x/global", "GIT_CONFIG_SYSTEM": "/x/system",
               "SSH_AUTH_SOCK": "/tmp/agent", "GH_TOKEN": "gho_x", "BASH_ENV": "/x/rc",
               githelper.GATED_MARK: "1:auto:hosts/box"}
    kept = {"TERM": "xterm", "GIT_EDITOR": "true", "GIT_PAGER": "cat", "PAGER": "cat",
            "LESS": "-R", "TZ": "UTC", "CLAUDE_PID": "4242", "GATE_ACCOUNT": "work",
            "GIT_AUTHOR_NAME": "A", "GIT_INDEX_FILE": "/x/index", "LC_TIME": "C"}
    with H.gateway_env() as env:
        _setup(env)
        cfg = _repo(env, "cfg", ("origin", WORK))
        r = _run(env, cfg, "status", environ={**dropped, **kept})
        assert _gated(r), r
        for k in dropped:
            if k in ("GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0",
                     "GIT_CONFIG_GLOBAL", githelper.GATED_MARK):
                continue                                   # the gateway's own, checked below
            assert k not in r.env, k
        for k, v in kept.items():
            assert r.env.get(k) == v, k
        assert r.env["GIT_CONFIG_COUNT"] == "2"
        assert (r.env["GIT_CONFIG_KEY_0"], r.env["GIT_CONFIG_VALUE_0"]) == \
            ("include.path", str(paths.git_config_path()))
        assert (r.env["GIT_CONFIG_KEY_1"], r.env["GIT_CONFIG_VALUE_1"]) == \
            ("core.sshCommand", str(paths.bin_dir() / "ssh"))
        assert r.env["GIT_CONFIG_GLOBAL"] == str(paths.git_global_path())
        assert r.env["GIT_CONFIG_NOSYSTEM"] == "1"
        assert r.env[githelper.GATED_MARK] == f"{os.getpid()}:-:-", "a forged mark isn't kept"
        p = r.env["PATH"].split(":")
        assert p[:2] == [str(paths.bin_dir()), str(paths.env_bin())], p
        assert "/usr/bin" in p, "the caller's PATH follows (a hook's own tools)"
    assert githelper.ssh_command("/a/b/ssh") == "/a/b/ssh"
    assert githelper.ssh_command("/a b/ssh") == "'/a b/ssh'"


def test_the_include_at_command_scope_beats_the_repositorys_own_settings():
    """A repository's credential.helper never answers for the configured
    host in the gated git (the include's URL-scoped reset comes after it),
    though it still does for another host; the account's identity beats the
    repository's user.email."""
    with H.gateway_env() as env:
        _setup(env)
        cfg = _repo(env, "cfg", ("origin", WORK))
        called = env.root / "evil-called"
        evil = env.root / "evil.sh"
        evil.write_text(f"#!/bin/sh\necho \"$1\" >> {called}\nexit 0\n")
        os.chmod(evil, 0o755)
        _git(env, cfg, "config", "credential.helper", str(evil))
        _git(env, cfg, "config", "user.email", "other@example.com")
        r = _run(env, cfg, "status")
        assert _gated(r)
        genv = {**r.env, "GIT_TERMINAL_PROMPT": "0"}

        def fill(host: str) -> None:
            subprocess.run([GIT, "credential", "fill"], cwd=str(cfg), env=genv, timeout=30,
                           input=f"protocol=https\nhost={host}\npath=example-org/tool.git\n\n",
                           capture_output=True, text=True)
        fill("github.com")
        assert not called.exists(), "the repository's helper answered for a configured host"
        fill("gitlab.example.com")
        assert called.exists(), "control: it still serves another host"
        r2 = subprocess.run([GIT, "config", "user.email"], cwd=str(cfg), env=genv,
                            capture_output=True, text=True, timeout=30)
        assert r2.stdout.strip() == "work@example.com", r2


def _user_git(env: H.GatewayEnv) -> Path:
    """The user's own git: the env's git under the user_tools knob."""
    d = env.root / "user-git"
    d.mkdir(exist_ok=True)
    if not (d / "git").exists():
        os.symlink(GIT, d / "git")
    env.o.extra["user_tools"] = str(d)
    return d


def _who(env: H.GatewayEnv, cfg: Path, genv: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """A commit with the gated git's environment, then its author and committer."""
    r = subprocess.run([GIT, "commit", "-q", "--allow-empty", "-m", "c"], cwd=str(cfg), env=genv,
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        return r
    return subprocess.run([GIT, "log", "-1", "--format=%an <%ae> / %cn <%ce>"], cwd=str(cfg),
                          env=genv, capture_output=True, text=True, timeout=30)


def _commit(env: H.GatewayEnv, cwd: Path, *before: str) -> Any:
    """`git [BEFORE...] commit` through the stand-in in `cwd` (the exec it
    ends in): a command that gets the identity read."""
    return _run(env, cwd, *before, "commit", "-q", "--allow-empty", "-m", "c")


def _pairs(r: Any) -> list[tuple[str, str]]:
    return [(r.env[f"GIT_CONFIG_KEY_{i}"], r.env[f"GIT_CONFIG_VALUE_{i}"])
            for i in range(int(r.env["GIT_CONFIG_COUNT"]))]


def test_the_gated_git_commits_as_the_user_when_the_account_names_no_one_and_never_guesses():
    """PLAN-0.11 §19.14: in a configured repository whose account names no
    name or email, the gated git commits with the user's own user.name and
    user.email as the user's git reads them there (the user's ~/.gitconfig,
    or the repository's own setting, which the user's git prefers), passed
    in the child's environment (GIT_CONFIG_KEY_n/VALUE_n), never on its
    command line; an account's name or email still wins, the user's fills in
    the rest; with no identity anywhere git refuses rather than guess
    (user.useConfigOnly in the gateway's global file)."""
    noid = FORM.replace('name = "Octo Work"\nemail = "work@example.com"\n', '')
    with H.gateway_env() as env:
        _setup(env, form=noid)
        _user_git(env)
        cfg = _repo(env, "cfg", ("origin", WORK))
        gitconfig = Path(_hermetic(env)["GIT_CONFIG_GLOBAL"])
        gitconfig.write_text('[user]\n\tname = Octo Cat\n\temail = octocat@example.com\n')
        r = _run(env, cfg, "commit", "-q", "--allow-empty", "-m", "c")
        assert _gated(r), r
        assert not any("user." in a or "octocat" in a for a in r.argv), r.argv
        pairs = [(r.env[f"GIT_CONFIG_KEY_{i}"], r.env[f"GIT_CONFIG_VALUE_{i}"])
                 for i in range(int(r.env["GIT_CONFIG_COUNT"]))]
        assert pairs[:3] == [("user.name", "Octo Cat"), ("user.email", "octocat@example.com"),
                             ("include.path", str(paths.git_config_path()))], pairs
        w = _who(env, cfg, r.env)
        assert w.stdout.strip() == ("Octo Cat <octocat@example.com> / "
                                    "Octo Cat <octocat@example.com>"), w
        # the repository's own email: the user's git prefers it, so does the gated git
        _git(env, cfg, "config", "user.email", "local@example.com")
        w = _who(env, cfg, _commit(env, cfg).env)
        assert w.stdout.strip().startswith("Octo Cat <local@example.com>"), w
        _git(env, cfg, "config", "--unset", "user.email")
        # nothing anywhere: git refuses instead of guessing user@host
        gitconfig.write_text("")
        r = _commit(env, cfg)
        assert not any(k.startswith("user.") for k, _v in _pairs(r)), r.env
        w = _who(env, cfg, r.env)
        assert w.returncode != 0 and "identity unknown" in w.stderr, w
        assert "useConfigOnly = true" in paths.git_global_path().read_text()
        # a read reached from the read itself (a wrapper `git`) reads nothing
        gitconfig.write_text('[user]\n\tname = Octo Cat\n')
        assert githelper.user_identity({**_hermetic(env), githelper.IDENTITY_GUARD: "1"},
                                       str(cfg)) == []
        assert githelper.user_identity(_hermetic(env), str(cfg)) == [("user.name", "Octo Cat")]
    named = FORM.replace('email = "work@example.com"\n', '')
    with H.gateway_env() as env:
        _setup(env, form=named)                        # the account names only a name
        _user_git(env)
        cfg = _repo(env, "cfg", ("origin", WORK))
        Path(_hermetic(env)["GIT_CONFIG_GLOBAL"]).write_text(
            '[user]\n\tname = Octo Cat\n\temail = octocat@example.com\n')
        w = _who(env, cfg, _commit(env, cfg).env)
        assert w.stdout.strip().startswith("Octo Work <octocat@example.com>"), w
    with H.gateway_env() as env:
        _setup(env)                                    # the account names both
        _user_git(env)
        cfg = _repo(env, "cfg", ("origin", WORK))
        Path(_hermetic(env)["GIT_CONFIG_GLOBAL"]).write_text(
            '[user]\n\tname = Octo Cat\n\temail = octocat@example.com\n')
        w = _who(env, cfg, _commit(env, cfg).env)
        assert w.stdout.strip().startswith("Octo Work <work@example.com>"), w


def test_the_identity_is_read_in_the_repository_the_command_works_on():
    """The user's identity comes from the repository the command works on,
    as gitroute resolved it (-C, --git-dir, --work-tree), never from the
    folder the command was typed in: `git -C B commit` run in repository A
    commits with B's own user.email (or the user's includeIf for B), never
    A's, also with B's git dir and a separate work tree."""
    noid = FORM.replace('name = "Octo Work"\nemail = "work@example.com"\n', '')
    with H.gateway_env() as env:
        _setup(env, form=noid)
        _user_git(env)
        a = _repo(env, "a")                                     # nothing configured
        _git(env, a, "config", "user.email", "a-only@example.com")
        b = _repo(env, "b", ("origin", WORK))                   # configured
        _git(env, b, "config", "user.email", "b-own@example.com")
        gitconfig = Path(_hermetic(env)["GIT_CONFIG_GLOBAL"])
        gitconfig.write_text('[user]\n\tname = Octo Cat\n\temail = octocat@example.com\n')
        r = _commit(env, a, "-C", str(b))
        assert _gated(r), r
        assert ("user.email", "b-own@example.com") in _pairs(r), _pairs(r)
        assert ("user.email", "a-only@example.com") not in _pairs(r), _pairs(r)
        w = _who(env, b, r.env)
        assert w.stdout.strip().startswith("Octo Cat <b-own@example.com>"), w
        # B's git dir with a work tree that holds no repository of its own
        wt = env.root / "wt"
        wt.mkdir()
        r = _commit(env, a, f"--git-dir={b / '.git'}", f"--work-tree={wt}")
        assert _gated(r) and ("user.email", "b-own@example.com") in _pairs(r), _pairs(r)
        # from a folder that is no repository: the user's includeIf for B
        _git(env, b, "config", "--unset", "user.email")
        inc = env.root / "work.inc"
        inc.write_text('[user]\n\temail = inc-work@example.com\n')
        gitconfig.write_text('[user]\n\tname = Octo Cat\n\temail = octocat@example.com\n'
                             f'[includeIf "gitdir:{b}/"]\n\tpath = {inc}\n')
        plain = env.root / "plain"
        plain.mkdir()
        r = _commit(env, plain, "-C", str(b))
        assert _gated(r) and ("user.email", "inc-work@example.com") in _pairs(r), _pairs(r)
        w = _who(env, b, r.env)
        assert w.stdout.strip().startswith("Octo Cat <inc-work@example.com>"), w


def test_commands_that_write_no_commit_skip_the_identity_read():
    """The identity read runs the user's git, so it runs only for a command
    that may write a commit, a tag or a note: `git status`, `diff`, `log`,
    `fetch` and the like in a configured repository don't run the user's
    git at all; commit, merge, tag, push and anything unknown do."""
    noid = FORM.replace('name = "Octo Work"\nemail = "work@example.com"\n', '')
    with H.gateway_env() as env:
        _setup(env, form=noid)
        d = env.root / "user-git"
        d.mkdir()
        log = env.root / "user-git.log"
        (d / "git").write_text(f'#!/bin/sh\necho "$*" >> "{log}"\nexec "{GIT}" "$@"\n')
        os.chmod(d / "git", 0o755)
        env.o.extra["user_tools"] = str(d)
        cfg = _repo(env, "cfg", ("origin", WORK))
        Path(_hermetic(env)["GIT_CONFIG_GLOBAL"]).write_text(
            '[user]\n\tname = Octo Cat\n\temail = octocat@example.com\n')
        for argv in (["status"], ["diff"], ["log", "-1"], ["show"], ["branch"], ["fetch"],
                     ["rev-parse", "HEAD"], ["checkout", "-b", "x"], ["add", "."], ["--version"]):
            r = _run(env, cfg, *argv)
            assert _gated(r) and not any(k.startswith("user.") for k, _v in _pairs(r)), argv
        assert not log.exists(), log.read_text()
        for argv in (["commit", "-m", "c"], ["merge", "x"], ["tag", "-a", "v1", "-m", "v1"],
                     ["push"], ["stash"], ["frobnicate"]):
            r = _run(env, cfg, *argv)
            assert _gated(r) and ("user.email", "octocat@example.com") in _pairs(r), argv
        assert log.read_text().count("config --get-regexp") == 6, log.read_text()


def test_the_global_config_is_read_only_and_a_gated_repository_stays_readable():
    with H.gateway_env() as env:
        _setup(env)
        g = paths.git_global_path()
        assert g.read_text() == githelper.GLOBAL_TEXT
        assert stat.S_IMODE(g.stat().st_mode) == 0o444
        assert "defaultRefFormat = files" in g.read_text() and \
            "defaultObjectFormat = sha1" in g.read_text()
        cfg = _repo(env, "cfg", ("origin", WORK))
        genv = _run(env, cfg, "status").env
        made = env.root / "made"
        made.mkdir()
        r = subprocess.run([GIT, "init", "-q", "-b", "main"], cwd=str(made), env=genv,
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, r.stderr
        text = (made / ".git" / "config").read_text()
        assert "refstorage" not in text.lower() and "objectformat" not in text.lower(), text
        subprocess.run([GIT, "-c", "user.name=T", "-c", "user.email=t@x", "commit", "-q",
                        "--allow-empty", "-m", "one"], cwd=str(made), env=genv, check=True,
                       capture_output=True, timeout=30)
        user_git = HA.system_git_path()
        r = subprocess.run([user_git, "log", "--format=%s"], cwd=str(made), env=_hermetic(env),
                           capture_output=True, text=True, timeout=30)
        assert r.returncode == 0 and r.stdout == "one\n", r
        # a session start rewrites it whole, 0444 again
        os.chmod(g, 0o644)
        g.write_text("[credential]\n\thelper = evil\n")
        githelper.write_global()
        assert g.read_text() == githelper.GLOBAL_TEXT and stat.S_IMODE(g.stat().st_mode) == 0o444


def test_below_a_gated_git_a_pass_through_drops_the_gateways_settings():
    """A hook's own `git config --global` under the gated git reaches the
    user's git with the user's config, never the gateway's global file."""
    with H.gateway_env() as env:
        _setup(env)
        fakes = HP.user_tools(env, "git")
        cfg = _repo(env, "cfg", ("origin", WORK))
        genv = _run(env, cfg, "status").env
        r = _run(env, cfg, "config", "--global", "user.name", "Octo", environ=genv)
        assert _passed(r, fakes), r
        for k in ("GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_COUNT",
                  "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", githelper.GATED_MARK):
            assert k not in r.env, k
        assert paths.git_global_path().read_text() == githelper.GLOBAL_TEXT
        # without the mark, the user's own GIT_CONFIG_* stay untouched
        mine = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "a.b", "GIT_CONFIG_VALUE_0": "1"}
        plain = _repo(env, "plain", ("origin", PLAIN))
        r = _run(env, plain, "status", environ=mine)
        assert _passed(r, fakes) and r.env["GIT_CONFIG_KEY_0"] == "a.b", r


# ---------------------------------------------------------------------------
# Refusals in a repository the gateway handles (§1.7, §6.5)
# ---------------------------------------------------------------------------

GUARDED_WRITES = [
    ("config", "credential.helper", "x"), ("config", "credential.https://github.com.helper", "x"),
    ("config", "core.sshCommand", "ssh -i k"), ("config", "url.https://x.example/.insteadOf", "y"),
    ("config", "remote.origin.url", "https://x.example/r"),
    ("config", "remote.origin.pushurl", "https://x.example/r"),
    ("config", "include.path", "/tmp/x"), ("config", "includeIf.gitdir:/x/.path", "/tmp/x"),
    ("config", "core.hooksPath", "/tmp/h"), ("config", "core.fsmonitor", "/tmp/m"),
    ("config", "set", "credential.helper", "x"), ("config", "--add", "credential.helper", "x"),
    ("config", "--replace-all", "core.hooksPath", "x"), ("config", "--unset", "remote.origin.url"),
    ("config", "unset", "core.sshcommand"), ("config", "--remove-section", "remote.origin"),
    ("config", "rename-section", "credential", "old"), ("config", "--edit"),
    ("config", "--local", "--type=path", "core.hooksPath", "x"),
    ("config", "remote.origin.proxy", "http://p.example:1"),
    ("config", "remote.origin.uploadpack", "/tmp/x"), ("config", "remote.origin.receivepack", "/tmp/x"),
    ("config", "alias.p", "-c core.sshCommand=/tmp/fake push"),
    ("config", "set", "alias.q", "--config-env=credential.helper=EDITOR fetch"),
]
FREE_CONFIG = [("config", "user.name", "Octo"), ("config", "--get", "remote.origin.url"),
               ("config", "remote.origin.url"), ("config", "core.autocrlf", "false"),
               ("config", "--list"), ("config", "get", "credential.helper"),
               ("config", "alias.st", "status"), ("config", "alias.lg", "-c color.ui=always log")]


def test_git_config_writes_of_guarded_keys_are_refused_there():
    with H.gateway_env() as env:
        _setup(env)
        fakes = HP.user_tools(env, "git")
        cfg = _repo(env, "cfg", ("origin", WORK))
        plain = _repo(env, "plain", ("origin", PLAIN))
        for argv in GUARDED_WRITES:
            rc = _run(env, cfg, *argv)
            assert isinstance(rc, tuple) and rc[0] == 2 and "doesn't change" in rc[1], (argv, rc)
            out = _hook("git " + " ".join(f"'{a}'" for a in argv), cfg)
            # (git's ssh setting meets the route check first: denied either way)
            assert _decision(out) == "deny" and ("doesn't change" in _reason(out) or
                                                 "goes around" in _reason(out)), (argv, out)
            assert _passed(_run(env, plain, *argv), fakes), argv          # the user's own repo
            assert _hook("git " + " ".join(f"'{a}'" for a in argv), plain) is None, argv
        for argv in FREE_CONFIG:
            assert _gated(_run(env, cfg, *argv)), argv
            assert _decision(_hook("git " + " ".join(argv), cfg)) is None, argv
        # the user's own config file
        r = _run(env, cfg, "config", "--global", "credential.helper", "osxkeychain")
        assert _passed(r, fakes), r
    assert githelper.config_writes(["user.name"]) == []
    assert githelper.config_writes(["--file", "x", "a.b", "c"]) == ["a.b"]
    assert githelper.config_writes(["--rename-section", "a", "b"]) == ["[a]", "[b]"]


def test_minus_c_pairs_after_the_gateways_settings_are_refused_there():
    """git reads -c (GIT_CONFIG_PARAMETERS) after GIT_CONFIG_COUNT: a helper
    there would be handed the token to store, an include could set anything,
    an ssh command would go around the ssh stand-in."""
    with H.gateway_env() as env:
        _setup(env)
        cfg = _repo(env, "cfg", ("origin", WORK))
        for pre in (("-c", "credential.helper=!cat"), ("-ccredential.https://github.com.helper=x"),
                    ("-c", "include.path=/tmp/x"), ("-c", "includeIf.onbranch:main.path=/tmp/x"),
                    ("--config-env=credential.helper=EVIL",), ("-c", "core.sshCommand=ssh -i k"),
                    ("-c", "ssh.variant=simple")):
            pre = (pre,) if isinstance(pre, str) else pre
            rc = _run(env, cfg, *pre, "push", "origin", "main", environ={"EVIL": "!cat"})
            assert isinstance(rc, tuple) and rc[0] == 2 and "come after the gateway" in rc[1], \
                (pre, rc)
            out = _hook("git " + " ".join(f"'{a}'" for a in pre) + " fetch", cfg)
            assert _decision(out) == "deny", (pre, out)
        assert _gated(_run(env, cfg, "-c", "user.name=Octo", "status"))


def test_git_by_its_path_is_refused_to_a_configured_remote():
    """§6.7: /usr/bin/git (or any git but the stand-in) in a repository the
    gateway handles goes around the stand-in; so do sudo git, env -i git and
    a login shell's git. Elsewhere: no decision."""
    with H.gateway_env() as env:
        _setup(env)
        cfg = _repo(env, "cfg", ("origin", WORK))
        plain = _repo(env, "plain", ("origin", PLAIN))
        for cmd in ("/usr/bin/git push origin main", "/opt/homebrew/bin/git status",
                    "sudo git push origin main", "env -i git fetch", "bash -lc 'git push'",
                    f"/usr/bin/git clone {WORK}", "xcrun git push origin main",
                    "xcrun --sdk macosx git fetch"):
            out = _hook(cmd, cfg)
            assert _decision(out) == "deny" and "git stand-in" in _reason(out), (cmd, out)
            if "clone" not in cmd:
                assert _decision(_hook(cmd, plain)) in (None, "ask"), (cmd, _hook(cmd, plain))
        assert _decision(_hook(f"{paths.bin_dir() / 'git'} push origin main", cfg)) is None
        assert _hook("xcrun --find git", cfg) is None, "xcrun only finds it"


# ---------------------------------------------------------------------------
# Up-front judging (§6.5, requirement 24) and the stand-in's own check
# ---------------------------------------------------------------------------

ASK_BOX = '[hosts.box]\naddress = "octo@box.invalid"\nssh = "ask"\n'


def test_the_hook_asks_or_denies_a_remote_command_before_it_runs():
    with H.gateway_env() as env:
        _setup(env, ASK_BOX)
        cfg = _repo(env, "cfg", ("origin", BOX))
        plain = _repo(env, "plain0", ("origin", PLAIN))
        for cmd in ("git push origin main", "git fetch", "git pull", "git ls-remote origin",
                    "git remote update", f"cd {cfg} && git push",
                    "git commit -qam x && git push origin main"):
            out = _hook(cmd, cfg)
            assert _decision(out) == "ask" and 'ssh on box is set to "ask"' in _reason(out), \
                (cmd, out)
        # judged in the folder the stage runs in, after its cd
        out = _hook(f"cd {cfg} && git push origin main", plain)
        assert _decision(out) == "ask" and "ssh on box" in _reason(out), out
        assert _hook(f"cd {plain} && git push origin main", cfg) is None
        # an alias the stand-in would refuse after the prompt: denied up front
        out = _hook("git -c alias.p=push p origin main", cfg)
        assert _decision(out) == "deny" and "is an alias" in _reason(out), out
        for cmd in ("git status", "git log -1", "git commit -m x", "git diff"):
            assert _hook(cmd, cfg) is None, cmd
        # a job can't be asked: denied
        out = hooks_bash.main({"tool_name": hooks_bash.JOB_TOOL, "cwd": str(cfg),
                               "permission_mode": "default",
                               "tool_input": {"command": "git push origin main", "cwd": str(cfg)}})
        assert _decision(out) == "deny" and "a job can't use" in _reason(out), out
        # elsewhere nothing changes
        plain = _repo(env, "plain", ("origin", PLAIN))
        assert _hook("git push origin main", plain) is None
    with H.gateway_env() as env:
        _setup(env, ASK_BOX.replace('"ask"', "false"))
        cfg = _repo(env, "cfg", ("origin", BOX))
        out = _hook("git push origin main", cfg)
        assert _decision(out) == "deny" and "box" in _reason(out), out
    with H.gateway_env() as env:
        _setup(env, ASK_BOX.replace('"ask"', '{ default = "ask", auto = true }'))
        cfg = _repo(env, "cfg", ("origin", BOX))
        assert _decision(_hook("git push origin main", cfg, "default")) == "ask"
        assert _hook("git push origin main", cfg, "auto") is None, "allow acts as cc for git"
        # a job runs with no mode: its stand-ins use the strictest (ask), so it is denied
        out = hooks_bash.main({"tool_name": hooks_bash.JOB_TOOL, "cwd": str(cfg),
                               "permission_mode": "auto",
                               "tool_input": {"command": "git push origin main", "cwd": str(cfg)}})
        assert _decision(out) == "deny" and "can't use" in _reason(out), out
    with H.gateway_env() as env:
        _setup(env, '[hosts.box]\naddress = "octo@box.invalid"\n'
                    '[hosts.box.policy]\nwrite = "ask"\n')
        cfg = _repo(env, "cfg", ("origin", BOX))
        out = _hook("git push origin main", cfg)
        assert _decision(out) == "ask" and "write on box" in _reason(out), out
        assert _hook("git fetch origin", cfg) is None, "a fetch reads"
    with H.gateway_env() as env:
        _setup(env, '[hosts.box]\naddress = 5\n')            # a mistake in it: still configured
        cfg = _repo(env, "cfg", ("origin", BOX))
        out = _hook("git push origin main", cfg)
        assert _decision(out) == "deny" and "box is refused" in _reason(out), out


def test_the_hook_judges_an_accounts_use_credential_and_write():
    with H.gateway_env() as env:
        _setup(env, FORM.replace('email = "work@example.com"\n',
                                 'email = "work@example.com"\nuse = "ask"\n'))
        cfg = _repo(env, "cfg", ("origin", WORK))
        out = _hook("git push origin main", cfg)
        assert _decision(out) == "ask" and "use on work" in _reason(out), out
    with H.gateway_env() as env:
        _setup(env, FORM + '[accounts.work.policy]\nwrite = "ask"\n')
        cfg = _repo(env, "cfg", ("origin", WORK))
        assert _decision(_hook("git push origin main", cfg)) == "ask"
        assert _hook("git fetch origin", cfg) is None, "a fetch writes nothing"
    with H.gateway_env() as env:
        _setup(env, FORM + '[accounts.work.policy]\ncredential = "deny"\n')
        cfg = _repo(env, "cfg", ("origin", WORK))
        out = _hook("git fetch origin", cfg)
        assert _decision(out) == "deny" and "credential = \"deny\"" in _reason(out), out


def test_the_stand_in_gives_an_ask_only_to_a_typed_spelled_out_remote_command():
    with H.gateway_env() as env:
        _setup(env, ASK_BOX)
        cfg = _repo(env, "cfg", ("origin", BOX))
        assert _decision(_hook("git push origin main", cfg)) == "ask"
        r = _run(env, cfg, "push", "origin", "main")
        assert _gated(r) and r.env[githelper.GATED_MARK] == f"{os.getpid()}:-:hosts/box", r
        r = _run(env, cfg, "status")
        assert _gated(r) and r.env[githelper.GATED_MARK].endswith(":-"), "nothing asked"
        for typed, want in (((False, "make"), "only ask about a command Claude runs itself"),
                            ((False, ancestry.CHECKPOINT), "a job can't use"),
                            ((False, ancestry.TERMINAL), "gateway terminal or job")):
            _hook("git push origin main", cfg)
            rc = _run(env, cfg, "push", "origin", "main", typed=typed)
            assert rc[0] == 2 and want in rc[1], (typed, rc)
        rc = _run(env, cfg, "-c", "alias.p=push", "p", "origin", "main")
        assert rc[0] == 2 and "is an alias" in rc[1], rc
    with H.gateway_env() as env:
        _setup(env)                                     # nothing "ask": an alias runs, unasked
        cfg = _repo(env, "cfg", ("origin", WORK))
        r = _run(env, cfg, "-c", "alias.p=push", "p", "origin", "main")
        assert _gated(r) and r.env[githelper.GATED_MARK].endswith(":-"), r
        r = _run(env, cfg, "push", "origin", "main", typed=(False, "make"))
        assert _gated(r) and r.env[githelper.GATED_MARK].endswith(":-"), "a script's: unasked"
    with H.gateway_env() as env:
        _setup(env, ASK_BOX.replace('"ask"', "false"))
        cfg = _repo(env, "cfg", ("origin", BOX))
        rc = _run(env, cfg, "push", "origin", "main")
        assert rc[0] == 2 and "git push on box is denied" in rc[1], rc
        assert _gated(_run(env, cfg, "status")), "a local command hands no credential to anyone"


def test_gated_parent_believes_the_mark_only_for_the_gated_gits_own_tree():
    """No mark, a malformed one, or a mark naming a process this one doesn't
    descend from through the env's git: not below the gated git."""
    with H.gateway_env():
        for v in (None, "", "x", "1:auto", "1:nomode:-", f"{os.getpid()}:-:2",
                  f"{os.getpid()}:-:hosts/Box", f"{os.getpid()}:-:users/box",
                  f"{os.getppid()}:-:hosts/box", f"{os.getpid()}:-:hosts/box",
                  f"{os.getpid()}:auto:-"):
            with HA.env_vars(**{githelper.GATED_MARK: v}):
                assert githelper.gated_parent() == githelper.GatedParent(), v
    assert githelper.mark_text(7, "auto", [("hosts", "b"), ("accounts", "a")]) == \
        "7:auto:accounts/a,hosts/b"


def _tree(chain: list[tuple[str, list[str]]]) -> tuple[Any, ...]:
    """Patch ancestry's process table: chain[0] is this process's parent,
    then its parent, ... (exe, argv)."""
    me = os.getpid()
    pids = [me] + [5000 + i for i in range(len(chain))]
    par = {pids[i]: pids[i + 1] for i in range(len(chain))}
    exe = {pids[i + 1]: chain[i][0] for i in range(len(chain))}
    argv = {pids[i + 1]: chain[i][1] for i in range(len(chain))}
    saved = (ancestry.parent_pid, ancestry.exe_path, ancestry._argv, ancestry.exe_name,
             ancestry.typed_from)
    ancestry.parent_pid = lambda pid: par.get(pid, 0)
    ancestry.exe_path = lambda pid: exe.get(pid)
    ancestry._argv = lambda pid: argv.get(pid)
    ancestry.exe_name = lambda pid: os.path.basename(exe.get(pid) or "")
    ancestry.typed_from = lambda pid: (pid == 9999, "")
    return saved, pids


def test_gated_parent_walks_gits_own_programs_hooks_and_lfs_filter_only():
    """The walk from a helper or stand-in up to the gated git the mark names:
    the env's git programs, one shell of git's own running a stand-in just
    above (never a pipeline), git-lfs's filter shell exactly as GLOBAL_TEXT
    names it, and git's hooks (hooked: a hook script's ssh and remote git
    don't take the approval); the top's parent decides typed."""
    with H.gateway_env():
        git = os.path.realpath(GIT)
        lfs = os.path.realpath(H.ENV_BIN / "git-lfs")
        stand = str(paths.bin_dir() / "git-credential-gateway")

        def walk(chain: list[tuple[str, list[str]]], typed: bool = True) -> Any:
            chain = chain + [("/bin/sh", ["sh", "-c", "claude's shell"])]
            saved, pids = _tree(chain)
            top = pids[len(chain) - 1]
            par = ancestry.parent_pid
            ancestry.parent_pid = lambda pid: 9999 if (pid == top and typed) else par(pid)
            try:
                with HA.env_vars(**{githelper.GATED_MARK: f"{top}:auto:hosts/box"}):
                    return githelper.gated_parent()
            finally:
                (ancestry.parent_pid, ancestry.exe_path, ancestry._argv, ancestry.exe_name,
                 ancestry.typed_from) = saved
        g = walk([(git, ["git", "push"])])
        assert g.below and g.typed and not g.hooked and g.strict() and g.mode == "auto" \
            and g.asked == {("hosts", "box")}, g
        assert walk([(git, ["git", "push"])], typed=False) == \
            githelper.GatedParent(below=True, top=g.top), "untyped: no mode, nothing asked"
        g = walk([("/bin/sh", ["sh", "-c", f"{stand} get"]), (git, ["git"]), (git, ["git"])])
        assert g.typed, "git's own shell running a stand-in, just above"
        assert not walk([("/bin/sh", ["sh", "-c", f"{stand} get | tee /tmp/x"]),
                         (git, ["git"]), (git, ["git"])]).below, "a pipeline"
        g = walk([(git, ["git", "credential", "fill"]), (lfs, ["git-lfs", "filter-process"]),
                  ("/bin/sh", ["sh", "-c", "git-lfs filter-process"]), (git, ["git", "pull"])])
        assert g.typed and not g.hooked, "git-lfs's filter shell"
        assert not walk([(git, ["git"]), (lfs, ["git-lfs"]),
                         ("/bin/sh", ["sh", "-c", "git-lfs filter-process; evil"]),
                         (git, ["git"])]).below, "another filter command"
        g = walk([(git, ["git", "credential", "fill"]), (lfs, ["git-lfs", "pre-push"]),
                  (git, ["git", "lfs", "pre-push"]),
                  ("/bin/sh", ["/bin/sh", ".git/hooks/pre-push", "origin", "x"]),
                  (git, ["git", "push"])])
        assert g.typed and g.hooked and not g.strict(), "a hook: hooked"
        assert not walk([(git, ["git"]), ("/bin/sh", ["/bin/sh", "deploy.sh"]),
                         (git, ["git"])]).below, "a script that isn't a hook"
        assert not walk([(git, ["git"]), ("/bin/sh", ["/bin/sh", "-c", "pre-push"]),
                         (git, ["git"])]).below, "a command string"
        assert not walk([("/usr/bin/git", ["git"]), (git, ["git"])]).below, "another git"
        assert not walk([("/tmp/x/git-remote-https", ["git"]), (git, ["git"])]).below


def test_a_push_to_an_ask_host_runs_once_the_hook_asked():
    """Requirement 24 end to end, with the real process tree (Claude's shell
    is a /bin/sh this test starts with CLAUDE_PID = this test): the hook asks
    about `git push` to a host whose ssh is "ask", the user approves, and
    the push runs through the git stand-in, the env's git and the ssh
    stand-in, instead of failing because git started the ssh. A script's
    git, or one wearing a forged mark, is still refused."""
    import harness_ssh as HS
    with HS.ssh_env() as s:
        t = s.sshd("box")
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nssh = "ask"\n')
        s.approve()
        s.host("box", t)
        data = vault.load()
        envfile.sync(s.env.form(), consent.compute(s.env.form(), data), vault.meta(data), None)
        envfile.write_stubs(envfile.stand_ins())
        s.set(typed="real")
        bare = t.dir / "repo.git"
        subprocess.run([GIT, "init", "-q", "--bare", "-b", "main", str(bare)], check=True,
                       capture_output=True)
        work = s.root / "work"
        work.mkdir()
        e = {**_hermetic(s.env), "GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@x",
             "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@x"}
        for args in (("init", "-q", "-b", "main"), ("remote", "add", "origin", f"box:{bare}"),
                     ("commit", "-q", "--allow-empty", "-m", "first")):
            subprocess.run([GIT, *args], cwd=str(work), env=e, check=True, capture_output=True)
        out = _hook("git push -q origin main", work)
        assert _decision(out) == "ask" and "ssh on box" in _reason(out), out
        stub = str(s.stub("git"))
        claude = s.proc_env({"CLAUDE_PID": str(os.getpid()), "HOME": e["HOME"],
                             "GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@x"})

        def sh(script: str) -> subprocess.CompletedProcess:
            return subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True,
                                  env=claude, cwd=str(work), timeout=120)
        r = sh(f"{stub} push -q origin main")
        assert r.returncode == 0, r
        log = subprocess.run([GIT, "--git-dir", str(bare), "log", "--format=%s", "main"],
                             capture_output=True, text=True, env=e)
        assert log.stdout == "first\n", log
        n = t.accepted()
        script = s.root / "deploy.sh"
        script.write_text(f"#!/bin/sh\n{stub} push -q origin main:other\necho done\n")
        os.chmod(script, 0o755)
        r = sh(f"{script}; true")
        assert "only ask about a command Claude runs itself" in r.stderr, r
        # the same push again: its record was used up
        r = sh(f"{stub} push -q origin main:again")
        assert r.returncode != 0 and "didn't ask you about this git command" in r.stderr, r
        # a script's own env git, wearing a mark that names itself
        forged = s.root / "forged.sh"
        forged.write_text("#!/bin/sh\n/bin/sh -c 'exec env GW_GATED_GIT=$$:-:hosts/box "
                          f"GIT_SSH_COMMAND={s.stub('ssh')} {GIT} push -q origin main:forged'\n"
                          "echo done\n")
        os.chmod(forged, 0o755)
        r = sh(f"{forged}; true")
        assert "asks the user each time" in r.stderr, r
        # the env git typed in Claude's shell itself, its mark saying nothing was asked
        r = sh(f"exec env GW_GATED_GIT=$$:-:- GIT_SSH_COMMAND={s.stub('ssh')} "
               f"{GIT} push -q origin main:zero")
        assert r.returncode != 0 and "asks the user each time" in r.stderr, r
        # ... or asked about another entry only
        r = sh(f"exec env GW_GATED_GIT=$$:-:hosts/other GIT_SSH_COMMAND={s.stub('ssh')} "
               f"{GIT} push -q origin main:other")
        assert r.returncode != 0 and "asks the user each time" in r.stderr, r
        assert t.accepted() == n, "nothing connected for the refused ones"
        refs = subprocess.run([GIT, "--git-dir", str(bare), "branch", "--format=%(refname:short)"],
                              capture_output=True, text=True, env=e).stdout.split()
        assert refs == ["main"], refs


def test_the_prefilter_sends_git_to_the_hook_only_with_a_remote_or_config_word():
    """§6.6: pre_bash.sh forwards git together with a later word that reaches
    a remote or writes its config; `git status` and friends never start
    Python there."""
    import json
    with H.gateway_env() as env:
        d = env.root / "rig"
        d.mkdir()
        pre = d / "pre_bash.sh"
        pre.write_text((H.PLUGIN / "hooks" / "pre_bash.sh").read_text())
        marker = d / "launched"
        (d / "launch.sh").write_text(f"#!/bin/sh\n: > {str(marker)!r}\ncat >/dev/null 2>&1\n")
        e = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PLUGIN_DATA",)}
        e["CLAUDE_CODE_SHELL_PREFIX"] = str(H.PLUGIN / "hooks" / "gate-sh")
        e["CLAUDE_PLUGIN_DATA"] = str(env.root / "no-data")

        def fires(cmd: str) -> bool:
            marker.unlink(missing_ok=True)
            subprocess.run(["/bin/sh", str(pre)], capture_output=True, text=True, timeout=15,
                           env=e, input=json.dumps({"tool_name": "Bash",
                                                    "tool_input": {"command": cmd}}))
            return marker.exists()
        for cmd in ("git push origin main", "git -C repo fetch", "git pull", "git clone x",
                    "git ls-remote origin", "git remote update", "git submodule update",
                    "git lfs push origin", "git config credential.helper x",
                    "git archive --remote=x HEAD", "cd r && git push",
                    "git remote-https origin x",
                    # a word split by quotes or backslashes is the same word to the shell
                    "git pu''sh origin main", 'git p""ull', "git p\\ush origin", "git 'fetch'",
                    # a subcommand in a variable or a command substitution
                    "p=push; git $p origin", "git $SUB origin", "git `echo push`"):
            assert fires(cmd), cmd
        for cmd in ("git status", "git log -1", "git commit -m wip", "git diff",
                    "git add .", "gitk", "echo git", "git-lfs version", "git push-x",
                    "git commit -m 'wip'", "git log; echo $HOME", 'git commit -m "$(cat msg)"',
                    "git log --format=$FMT"):
            assert not fires(cmd), cmd


# ---------------------------------------------------------------------------
# The approval hook's record (requirement 24): an "ask" passes only for the
# command the hook asked about; git the hook can't follow is denied
# ---------------------------------------------------------------------------


def _records() -> list[Path]:
    d = asks._dir()
    return sorted(p for p in d.iterdir() if not p.name.startswith(".")) if d.is_dir() else []


def test_the_stand_in_passes_an_ask_only_for_the_command_the_hook_asked_about():
    """The hook writes one record for each git stage it asks about, only when
    its answer is "ask" (Bash and Monitor); the stand-in takes an "ask" on
    only for a command that matches one: the same Claude Code process,
    folder and words, every "ask" entry covered, at most ASK_TTL old, each
    used once. Anything else is refused after the fact, naming what to do."""
    with H.gateway_env() as env:
        _setup(env, ASK_BOX)
        cfg = _repo(env, "cfg", ("origin", BOX))
        cfg2 = _repo(env, "cfg2", ("origin", BOX))
        rc = _run(env, cfg, "push", "origin", "main")
        assert rc[0] == 2 and "didn't ask you about this git command" in rc[1], rc
        assert "run `git push ...` as its own command" in rc[1], rc
        assert not _records()
        assert _decision(_hook("git push origin main", cfg)) == "ask"
        assert len(_records()) == 1
        for where, argv in ((cfg2, ("push", "origin", "main")), (cfg, ("push", "origin", "main:x")),
                            (cfg, ("push", "-f", "origin", "main"))):
            rc = _run(env, where, *argv)
            assert rc[0] == 2 and "didn't ask you" in rc[1], (where, argv, rc)
        r = _run(env, cfg, "push", "origin", "main")
        assert _gated(r) and r.env[githelper.GATED_MARK].endswith(":hosts/box"), r
        assert not _records(), "used up"
        rc = _run(env, cfg, "push", "origin", "main")
        assert rc[0] == 2 and "didn't ask you" in rc[1], rc
        # another Claude Code's record, or one that doesn't cover box
        asks.record("git", "123@456", str(cfg), ["push", "origin", "main"], [("hosts", "box")])
        asks.record("git", asks.session(), str(cfg), ["push", "origin", "main"],
                    [("hosts", "other"), ("accounts", "box")])
        # one for another tool with the same words
        asks.record("ssh", asks.session(), str(cfg), ["push", "origin", "main"], [("hosts", "box")])
        rc = _run(env, cfg, "push", "origin", "main")
        assert rc[0] == 2 and "didn't ask you" in rc[1], rc
        for p in _records():
            p.unlink()
        # too old: refused, saying why
        _hook("git push origin main", cfg)
        (p,) = _records()
        rec = json.loads(p.read_text())
        rec["t"] -= asks.ASK_TTL + 5
        p.write_text(json.dumps(rec))
        rc = _run(env, cfg, "push", "origin", "main")
        assert rc[0] == 2 and "more than 15 minutes" in rc[1], rc
        for p in _records():
            p.unlink()
        # no record for a deny, nor for the user's Terminal panel
        out = _hook("git push origin main && git -c credential.helper=x status", cfg)
        assert _decision(out) == "deny", out
        hooks_bash.main({"tool_name": "mcp__terminal__run_in_terminal", "cwd": str(cfg),
                         "permission_mode": "default",
                         "tool_input": {"command": "git push origin main"}})
        assert not _records()
        # two pushes in one command: a record each; Monitor's too (each call
        # first drops what the session's earlier calls left)
        assert _decision(_hook("git push origin main; git push origin main", cfg)) == "ask"
        assert len(_records()) == 2
        assert _gated(_run(env, cfg, "push", "origin", "main"))
        assert _gated(_run(env, cfg, "push", "origin", "main"))
        assert _decision(_hook("git fetch origin", cfg, tool="Monitor")) == "ask"
        assert len(_records()) == 1
        assert _gated(_run(env, cfg, "fetch", "origin"))
        # `~` is the home the shell gives git: judged and recorded there
        home = paths.user_home()
        proj = home / "proj"
        proj.mkdir(parents=True)
        _git(env, proj, "init", "-q", "-b", "main")
        _git(env, proj, "remote", "add", "origin", BOX)
        out = _hook("git -C ~/proj push origin main", cfg2)
        assert _decision(out) == "ask" and "ssh on box" in _reason(out), out
        assert _gated(_run(env, cfg2, "-C", str(proj), "push", "origin", "main"))
        # the run folder can't be written: denied up front, not refused after the OK
        for p in _records():
            p.unlink()
        asks._dir().rmdir()
        asks._dir().write_text("not a folder")
        out = _hook("git push origin main", cfg)
        assert _decision(out) == "deny" and "couldn't note" in _reason(out), out


TWO_POL = FORM + '''
[accounts.other]
kind = "github"
login = "octo-other"

[accounts.other.policy]
credential = "ask"
'''
OTOK = "ghp_OTHERtoken0123456789abcdef"


def test_the_hook_denies_git_it_cant_follow_while_something_git_reaches_asks():
    """The review's forms: git in a subshell, a group, exec, $(...), a shell
    string, the background, after an assignment, with a variable for its
    words, after a stage that sets up the repository or remote, or in a
    folder the hook can't tell, is denied while an entry git may reach is
    "ask" (the stand-in would refuse it after the prompt: no record); git's
    variables before it (env, export) are read as the stand-in reads them;
    with nothing "ask" none of this is the gateway's business."""
    with H.gateway_env() as env:
        _setup(env, ASK_BOX)
        cfg = _repo(env, "cfg", ("origin", BOX))
        plain = _repo(env, "plain", ("origin", PLAIN))
        bare = _repo(env, "bare")
        for cmd, cwd in (("(git push origin main)", cfg), ("{ git push origin main; }", cfg),
                         ("exec git push origin main", cfg), ("x=$(git push origin main)", cfg),
                         ("bash -c 'git push origin main'", cfg), ("git push origin main &", cfg),
                         ("nohup git fetch &", cfg),
                         (f"GIT_DIR={cfg}/.git git push origin main", plain),
                         ("p=push; git $p origin main", cfg), ("git $SUB origin main", cfg),
                         ("git push \"$R\" main", cfg)):
            out = _hook(cmd, cwd)
            assert _decision(out) == "deny" and ("can't follow" in _reason(out) or
                                                 "hides" in _reason(out)), (cmd, out)
        for cmd, cwd in ((f"git remote add h {BOX} && git push h main", bare),
                         (f"git clone -q {BOX} y && cd y && git push", plain),
                         (f"git init -q n && cd n && git remote add o {BOX} && git push o main", plain),
                         (f"git config remote.origin.url {BOX} && git push origin main", plain),
                         (f"git config url.{BOX[:-len('srv/repo.git')]}.insteadOf gh: && "
                          "git push gh:x main", plain)):
            out = _hook(cmd, cwd)
            assert _decision(out) == "deny" and "first and" in _reason(out), (cmd, out)
        # a set-up that reaches nothing configured: judged as usual
        for cmd, cwd in ((f"git remote add o {PLAIN} && git push -u o main", bare),
                         ("git init -q n && cd n && git push origin main", plain),
                         (f"git clone -q {PLAIN} y2 && cd y2 && git push", plain)):
            assert _decision(_hook(cmd, cwd)) != "deny", cmd
        out = _hook("cd - && git push origin main", cfg)
        assert _decision(out) == "deny" and "which folder" in _reason(out), out
        for cmd in (f"env GIT_DIR={cfg}/.git git push origin main",
                    f"export GIT_DIR={cfg}/.git; git push origin main",
                    f"export GIT_WORK_TREE={cfg} GIT_DIR={cfg}/.git && git push origin main"):
            out = _hook(cmd, plain)
            assert _decision(out) == "ask" and "ssh on box" in _reason(out), (cmd, out)
        assert _hook(f"export GIT_DIR={cfg}/.git; unset GIT_DIR; git push origin main", plain) \
            is None
        assert _hook("env -u GIT_DIR git push origin main", plain) is None
        # a variable in words that reach no remote hides nothing git's "ask" needs
        # (WS-9 review: no prompt, no refusal)
        assert _hook('git commit -m "$MSG"', cfg) is None
        for cmd in ("git status && git log -1", 'git commit -qm "$(echo wip)"',
                    "git commit -qm \"$(cat <<'EOF'\nfix the push flow\nEOF\n)\"",
                    "(git status)", "x=$(git log -1)"):
            assert _decision(_hook(cmd, cfg)) != "deny", cmd
    with H.gateway_env() as env:
        _setup(env)                                  # nothing "ask": the stand-in decides
        cfg = _repo(env, "cfg", ("origin", WORK))
        bare = _repo(env, "bare")
        for cmd, cwd in (("(git push origin main)", cfg), ("bash -c 'git push origin main'", cfg),
                         (f"git remote add h {WORK} && git push h main", bare),
                         ("cd - && git push origin main", cfg)):
            assert _decision(_hook(cmd, cwd)) != "deny", cmd


def test_the_account_gate_account_names_is_judged_and_needs_its_own_ask():
    """GATE_ACCOUNT=other on a push to a repository work owns: the helper
    would pick other, so other's credential "ask" is asked about (the
    prefix, env, export) and the stand-in passes it on only with that
    record (the review's GATE_ACCOUNT bypass)."""
    with H.gateway_env() as env:
        _setup(env, TWO_POL, {"work": WTOK, "other": OTOK})
        cfg = _repo(env, "cfg", ("origin", WORK))
        assert _hook("git push origin main", cfg) is None
        for cmd in ("GATE_ACCOUNT=other git push origin main",
                    "env GATE_ACCOUNT=other git push origin main",
                    "export GATE_ACCOUNT=other && git push origin main"):
            out = _hook(cmd, cfg)
            assert _decision(out) == "ask" and "credential on other" in _reason(out), (cmd, out)
        for p in _records():
            p.unlink()
        _hook("git push origin main", cfg)
        rc = _run(env, cfg, "push", "origin", "main", environ={"GATE_ACCOUNT": "other"})
        assert rc[0] == 2 and "credential on other" in rc[1] and "didn't ask you" in rc[1], rc
        _hook("GATE_ACCOUNT=other git push origin main", cfg)
        r = _run(env, cfg, "push", "origin", "main", environ={"GATE_ACCOUNT": "other"})
        assert _gated(r) and r.env[githelper.GATED_MARK].endswith(":accounts/other"), r


def test_an_aliass_own_minus_c_pairs_are_refused_there():
    """git applies an alias's own -c and --config-env pairs after the
    gateway's settings, like the command line's: guarded_c reads them
    (gitroute's alias_globals), in the stand-in and the hook, for an alias
    on the command line, in the repository's config or behind another
    alias; and `git config alias.X` refuses to write one (the review's
    core.sshCommand route around the ssh stand-in)."""
    with H.gateway_env() as env:
        _setup(env)
        fakes = HP.user_tools(env, "git")
        cfg = _repo(env, "cfg", ("origin", BOX))
        plain = _repo(env, "plain", ("origin", PLAIN))
        for alias in ("alias.p=-c core.sshCommand=/tmp/fakessh push",
                      "alias.p=--config-env=core.sshCommand=EDITOR push",
                      "alias.p=-c credential.helper=!cat fetch",
                      "alias.p=-c include.path=/tmp/x status"):
            rc = _run(env, cfg, "-c", alias, "p", "origin", "main", environ={"EDITOR": "/tmp/x"})
            assert isinstance(rc, tuple) and rc[0] == 2 and "come after the gateway" in rc[1], \
                (alias, rc)
            out = _hook(f"git -c '{alias}' p origin main", cfg)
            assert _decision(out) == "deny", (alias, out)
        _git(env, cfg, "config", "alias.q", "-c core.sshCommand=/tmp/fakessh push")
        _git(env, cfg, "config", "alias.r", "q")
        for a in ("q", "r"):
            rc = _run(env, cfg, a, "origin", "main")
            assert isinstance(rc, tuple) and rc[0] == 2 and "come after the gateway" in rc[1], (a, rc)
            assert _decision(_hook(f"git {a} origin main", cfg)) == "deny", a
        assert _gated(_run(env, cfg, "-c", "alias.l=-c color.ui=always log", "l", "-1"))
        assert _passed(_run(env, plain, "-c", "alias.p=-c core.sshCommand=/tmp/x push", "p"), fakes)


def test_git_config_file_into_the_repositorys_own_config_is_its_config():
    """`git config --file <git dir>/config` writes the repository's own config,
    not the user's: a guarded key there is refused in a repository the
    gateway handles (any spelling, -C, an alias for config); the user's own
    files, and the user's own repositories, are theirs."""
    with H.gateway_env() as env:
        _setup(env)
        fakes = HP.user_tools(env, "git")
        cfg = _repo(env, "cfg", ("origin", WORK))
        plain = _repo(env, "plain", ("origin", PLAIN))
        mine = env.root / "mine.cfg"
        for where, argv in ((cfg, ("config", "--file", ".git/config", "core.sshCommand", "x")),
                            (cfg, ("config", "--file=.git/config", "credential.helper", "x")),
                            (cfg, ("config", "-f", "./.git/config", "remote.origin.url",
                                   "https://x.example/r")),
                            (cfg, ("config", "--fil", f"{cfg}/.git/config", "include.path", "/x")),
                            (cfg, ("config", "set", "-f.git/config", "core.hooksPath", "/x")),
                            (cfg, ("config", "--file", ".git/config", "--rep", "core.hooksPath",
                                   "/x")),
                            (plain, ("config", "--file", f"{cfg}/.git/config", "core.hooksPath",
                                     "/tmp/h")),
                            (plain, ("-C", str(cfg), "config", "--file", ".git/config",
                                     "core.hooksPath", "/tmp/h")),
                            (cfg, ("-c", "alias.cf=config --file .git/config", "cf",
                                   "core.sshCommand", "x"))):
            rc = _run(env, where, *argv)
            assert isinstance(rc, tuple) and rc[0] == 2 and "doesn't change" in rc[1], (argv, rc)
            out = _hook("git " + " ".join(f"'{a}'" for a in argv), where)
            assert _decision(out) == "deny", (argv, out)
        for where, argv in ((cfg, ("config", "--file", str(mine), "core.sshCommand", "x")),
                            (plain, ("config", "--file", ".git/config", "core.sshCommand", "x")),
                            (cfg, ("config", "--file", ".git/config", "user.name", "x"))):
            assert _passed(_run(env, where, *argv), fakes), argv


def test_a_shell_alias_or_unreadable_settings_are_refused_there():
    """The resolver's fixed refusals, at the stand-in and in the hook: a `!`
    alias in a repository the gateway handles, and settings git can't read
    while something is configured (nothing runs); the user's own repository
    keeps its shell aliases."""
    with H.gateway_env() as env:
        _setup(env)
        fakes = HP.user_tools(env, "git")
        cfg = _repo(env, "cfg", ("origin", WORK))
        plain = _repo(env, "plain", ("origin", PLAIN))
        rc = _run(env, cfg, "-c", "alias.x=!echo hi", "x")
        assert isinstance(rc, tuple) and rc[0] == 2 and "a shell alias" in rc[1], rc
        out = _hook("git -c 'alias.x=!git push' x origin", cfg)
        assert _decision(out) == "deny" and "a shell alias" in _reason(out), out
        assert _passed(_run(env, plain, "-c", "alias.x=!echo hi", "x"), fakes)
        with open(cfg / ".git" / "config", "a") as f:
            f.write("[broken\n")
        rc = _run(env, cfg, "status")
        assert isinstance(rc, tuple) and rc[0] == 2 and "couldn't read the settings" in rc[1], rc
        out = _hook("git push origin main", cfg)
        assert _decision(out) == "deny" and "couldn't read the settings" in _reason(out), out


def test_the_stand_ins_refusals_name_their_mode():
    """Lead decision 19.8: every refusal's audit line names the mode it was
    decided in, the local ones (-c, config, a shell alias) included."""
    with H.gateway_env() as env:
        _setup(env)
        cfg = _repo(env, "cfg", ("origin", WORK))
        for argv in (("-c", "credential.helper=x", "status"), ("config", "core.sshCommand", "x"),
                     ("-c", "alias.x=!echo", "x")):
            rc = _run(env, cfg, *argv)
            assert isinstance(rc, tuple) and rc[0] == 2, (argv, rc)
            last = [x for x in audit.read(0) if x.get("event") == "refusal"][-1]
            assert last.get("tool") == "git" and last.get("mode") == "modeless", (argv, last)


def test_a_git_the_approved_gated_git_starts_keeps_its_mark():
    """git-lfs runs `git credential fill` (and a hook's `git lfs pre-push`)
    through the git stand-in: below the approved gated git that git keeps
    the approved git's mark, so the helper below it goes by that approval;
    a remote command the approved git's own programs make passes an "ask"
    the approval covers (never one it doesn't, nor through a hook script);
    a hook script's own remote command makes its own mark."""
    outer = githelper.GatedParent(below=True, typed=True, top=4242, mode="auto",
                                  asked=frozenset({("hosts", "box")}))
    mark = {githelper.GATED_MARK: "4242:auto:hosts/box"}
    saved = githelper.gated_parent
    try:
        with H.gateway_env() as env:
            _setup(env, ASK_BOX)
            cfg = _repo(env, "cfg", ("origin", BOX))
            for hooked in (False, True):
                githelper.gated_parent = lambda h=hooked: dataclasses.replace(outer, hooked=h)
                r = _run(env, cfg, "credential", "fill", environ=mark, typed=(False, "git-lfs"))
                assert _gated(r) and r.env[githelper.GATED_MARK] == mark[githelper.GATED_MARK], \
                    (hooked, r)
            githelper.gated_parent = lambda: outer
            r = _run(env, cfg, "push", "origin", "main", environ=mark, typed=(False, "git-lfs"))
            assert _gated(r) and r.env[githelper.GATED_MARK] == mark[githelper.GATED_MARK], r
            for other in (dataclasses.replace(outer, asked=frozenset({("hosts", "other")})),
                          dataclasses.replace(outer, hooked=True)):
                githelper.gated_parent = lambda o=other: o
                rc = _run(env, cfg, "push", "origin", "main", environ=mark,
                          typed=(False, "git-lfs"))
                assert isinstance(rc, tuple) and rc[0] == 2 and \
                    "only ask about a command Claude runs itself" in rc[1], (other, rc)
        with H.gateway_env() as env:
            _setup(env)                                  # nothing "ask"
            cfg = _repo(env, "cfg", ("origin", WORK))
            githelper.gated_parent = lambda: dataclasses.replace(outer, hooked=True)
            r = _run(env, cfg, "fetch", environ=mark, typed=(False, "sh"))
            assert _gated(r) and r.env[githelper.GATED_MARK] == f"{os.getpid()}:-:-", r
    finally:
        githelper.gated_parent = saved


def test_the_ssh_stand_in_takes_the_approval_only_for_its_entry_and_gits_own_actions():
    """Below the gated git of a command Claude typed (gated_parent, patched
    here; the ssh is git's, not typed), the ssh stand-in takes the mark's
    mode, and passes an "ask" only for an entry the hook asked about, only
    for git's own read or write (never a command), and never through a hook
    script."""
    import harness_ssh as HS
    from gateway import ssh
    saved = githelper.gated_parent

    def call(argv: list[str]) -> tuple[int, str]:
        with HA.capture_fds() as box:
            rc = ssh.main("ssh", argv)
        return rc, box["err"].decode()

    def below(mode: str | None = None, *asked: tuple[str, str], hooked: bool = False) -> Any:
        return githelper.GatedParent(below=True, typed=True, hooked=hooked, top=1, mode=mode,
                                     asked=frozenset(asked))
    up = ["git-upload-pack", "'/nonexistent.git'"]          # git's own read
    try:
        with HS.ssh_env() as s:
            t = s.sshd("box")
            for text, cases in (
                    ('ssh = "ask"\n', [((None, ("hosts", "box")), up, True),
                                       ((None, ("hosts", "other")), up, False),
                                       ((None,), up, False),
                                       ((None, ("hosts", "box")), ["true"], False)]),
                    ('[hosts.box.policy]\nexec = "ask"\nread = "ask"\n',
                     [((None, ("hosts", "box")), ["true"], False),
                      ((None, ("hosts", "box")), up, True)]),
                    ('ssh = { default = "ask", auto = true }\n',
                     [(("auto",), ["true"], True), (("default",), ["true"], False)])):
                s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\n{text}')
                s.approve()
                s.host("box", t)
                s.set(typed=False, direct=True)
                for (mode, *asked), cmd, ok in cases:
                    githelper.gated_parent = lambda m=mode, a=tuple(asked): below(m, *a)
                    rc, err = call(["box", *cmd])
                    refused = "asks the user" in err or '"ask"' in err
                    assert refused != ok, (text, mode, asked, cmd, rc, err)
                    if ok and cmd == ["true"]:
                        assert rc == 0, (text, rc, err)
            s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nssh = "ask"\n')
            s.approve()
            githelper.gated_parent = lambda: below(None, ("hosts", "box"), hooked=True)
            rc, err = call(["box", *up])
            assert rc != 0 and "asks the user" in err, ("a hook script's ssh", err)
    finally:
        githelper.gated_parent = saved


def _real_tree(s: Any, work: Path, e: dict[str, str]) -> Any:
    claude = s.proc_env({"CLAUDE_PID": str(os.getpid()), "HOME": e["HOME"],
                         "GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@x",
                         "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@x"})

    def sh(script: str, cwd: Path = work) -> subprocess.CompletedProcess:
        return subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True,
                              env=claude, cwd=str(cwd), timeout=120)
    return sh


def test_git_the_hook_cant_follow_never_reaches_an_ask_host():
    """The review's repro end to end (a real sshd, the real process tree):
    each form the hook can't follow is denied up front, and run anyway
    (Claude Code asked nothing) the stand-in refuses it: nothing lands on
    the host. git's variables before it are judged where they lead: asked,
    and then it runs."""
    import harness_ssh as HS
    with HS.ssh_env() as s:
        t = s.sshd("box")
        s.write_form(f'[hosts.box]\naddress = "{t.addr()}"\nssh = "ask"\n')
        s.approve()
        s.host("box", t)
        data = vault.load()
        envfile.sync(s.env.form(), consent.compute(s.env.form(), data), vault.meta(data), None)
        envfile.write_stubs(envfile.stand_ins())
        s.set(typed="real")
        bare = t.dir / "repo.git"
        subprocess.run([GIT, "init", "-q", "--bare", "-b", "main", str(bare)], check=True,
                       capture_output=True)
        e = {**_hermetic(s.env), "GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@x",
             "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@x"}
        work, plain = s.root / "work", s.root / "plain"
        for d, remote in ((work, f"box:{bare}"), (plain, None)):
            d.mkdir()
            subprocess.run([GIT, "init", "-q", "-b", "main"], cwd=str(d), env=e, check=True,
                           capture_output=True)
            if remote:
                subprocess.run([GIT, "remote", "add", "origin", remote], cwd=str(d), env=e,
                               check=True, capture_output=True)
            subprocess.run([GIT, "commit", "-q", "--allow-empty", "-m", "c"], cwd=str(d), env=e,
                           check=True, capture_output=True)
        sh = _real_tree(s, work, e)

        def refs() -> list[str]:
            return subprocess.run([GIT, "--git-dir", str(bare), "branch",
                                   "--format=%(refname:short)"], capture_output=True, text=True,
                                  env=e).stdout.split()
        for script, cwd in (("(git push -q origin main:a)", work),
                            ("{ git push -q origin main:b; }", work),
                            ("exec git push -q origin main:c", work),
                            ("x=$(git push -q origin main:d 2>&1); echo \"$x\"", work),
                            ("bash -c 'git push -q origin main:e'", work),
                            ("git push -q origin main:f & wait", work),
                            (f"GIT_DIR={work}/.git git push -q origin main:g", plain),
                            (f"git remote add h box:{bare} && git push -q h main:h", plain)):
            out = _hook(script, cwd)
            assert _decision(out) == "deny", (script, out)
            r = sh(script, cwd)
            assert refs() == [], (script, r)
        assert t.accepted() == 0
        out = _hook(f"env GIT_DIR={work}/.git git push -q origin main:i", plain)
        assert _decision(out) == "ask" and "ssh on box" in _reason(out), out
        r = sh(f"env GIT_DIR={work}/.git git push -q origin main:i", plain)
        assert r.returncode == 0 and refs() == ["i"], r


def _ghe(s: Any, use: str) -> Any:
    """An account endpoint served by the local sshd (test_ssh_git's way):
    ghe-work for acme, its `use` as given."""
    import harness_ssh as HS
    t = s.sshd("ghe")
    s.write_form(f'[accounts.ghe-work]\nkind = "github"\nhost = "ghe.test"\nlogin = "worker"\n'
                 f'owners = ["acme"]\nuse = {use}\n')
    s.approve()
    with vault.edit() as d:
        priv, pub = s.key("ghe-work")
        t.authorize(pub, git=True)
        r = vault.account_record(d, "ghe-work", "github")
        r["ssh_key"] = {"private": priv, "public": pub, "fingerprint": vault.fingerprint_of(pub)}
        r["host_keys"] = [t.host_key]
    subprocess.run([GIT, "init", "-q", "--bare", "-b", "main", str(t.repos / "acme/repo.git")],
                   check=True, capture_output=True)
    s.set(ssh_endpoint_map={"ghe.test": {"host": "127.0.0.1", "port": t.port,
                                         "user": HS.real_user()}})
    return t


def test_an_account_whose_use_is_ask_pushes_once_the_hook_asked_over_https_and_ssh():
    """Requirement 24 for an account set to "ask" (the review's must-fix 3),
    end to end with the real process tree: the hook asks about the push,
    and then it runs, over https (the credential helper, which used to say
    "use = false") and over ssh (git over ssh's account endpoint, which used
    to say it was off); the same push unasked is refused, and nothing is
    sent."""
    import harness_ssh as HS
    with HS.ssh_env() as s:
        git = HA.system_git_path()
        srv = HA.GitServer(s.root / "srv", git)
        try:
            form = (f'[accounts.work]\nkind = "github"\nhost = "{srv.host}"\nlogin = "octo-work"\n'
                    'owners = ["example-org"]\nuse = "ask"\n')
            HA.build_vault(s.env, form, tokens={"work": WTOK})
            data = vault.load()
            envfile.sync(s.env.form(), consent.compute(s.env.form(), data), vault.meta(data), None)
            envfile.write_stubs(envfile.stand_ins())
            s.set(typed="real")
            srv.make_repo("example-org", "work")
            e = {**_hermetic(s.env), "GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@x",
                 "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@x"}
            work = s.root / "w"
            work.mkdir()
            for args in (("init", "-q", "-b", "main"),
                         ("remote", "add", "origin", f"http://{srv.host}/example-org/work.git"),
                         ("commit", "-q", "--allow-empty", "-m", "first")):
                subprocess.run([GIT, *args], cwd=str(work), env=e, check=True, capture_output=True)
            sh = _real_tree(s, work, e)
            stub = s.stub("git")
            r = sh(f"{stub} push -q origin main:unasked")
            assert r.returncode != 0 and "didn't ask you" in r.stderr, r
            assert not any(c["password"] == WTOK for c in srv.auths())
            out = _hook("git push -q origin main", work)
            assert _decision(out) == "ask" and "use on work" in _reason(out), out
            r = sh(f"{stub} push -q origin main")
            assert r.returncode == 0, r
            assert any(c["method"] == "POST" and "git-receive-pack" in c["path"] and
                       c["password"] == WTOK for c in srv.auths()), srv.auths()
        finally:
            srv.close()
    with HS.ssh_env() as s:
        t = _ghe(s, '"ask"')
        data = vault.load()
        envfile.sync(s.env.form(), consent.compute(s.env.form(), data), vault.meta(data), None)
        envfile.write_stubs(envfile.stand_ins())
        s.set(typed="real")
        e = {**_hermetic(s.env), "GIT_AUTHOR_NAME": "T", "GIT_AUTHOR_EMAIL": "t@x",
             "GIT_COMMITTER_NAME": "T", "GIT_COMMITTER_EMAIL": "t@x"}
        work = s.root / "w"
        work.mkdir()
        for args in (("init", "-q", "-b", "main"),
                     ("remote", "add", "origin", "git@ghe.test:acme/repo.git"),
                     ("commit", "-q", "--allow-empty", "-m", "first")):
            subprocess.run([GIT, *args], cwd=str(work), env=e, check=True, capture_output=True)
        sh = _real_tree(s, work, e)
        stub = s.stub("git")
        r = sh(f"{stub} push -q origin main")
        assert r.returncode != 0 and "didn't ask you" in r.stderr, r
        out = _hook("git push -q origin main", work)
        assert _decision(out) == "ask" and "use on ghe-work" in _reason(out), out
        r = sh(f"{stub} push -q origin main")
        assert r.returncode == 0, r
        log = subprocess.run([GIT, "--git-dir", str(t.repos / "acme/repo.git"), "log",
                              "--format=%s", "main"], capture_output=True, text=True)
        assert log.stdout == "first\n", log


# ---------------------------------------------------------------------------
# The cold stub (§6.6) and the cost (§6.6)
# ---------------------------------------------------------------------------


def test_the_cold_git_stub_passes_through_only_while_nothing_may_be_configured():
    # launch.sh's cold rule and the git stub's use one ERE (envfile.CONFIGURED_ERE)
    text = (H.PLUGIN / "hooks" / "launch.sh").read_text()
    lit = text.split('\nCONFIGURED_ERE="', 1)[1].split('"\n', 1)[0]
    assert f'grep -Eq "{lit}" "$_h/gateway.toml"' in text
    got = subprocess.run(["/bin/sh", "-c", f'printf %s "{lit}"'], capture_output=True,
                         text=True).stdout
    assert got == envfile.CONFIGURED_ERE, got
    with H.gateway_env() as env:
        fakes = HP.user_tools(env, "git")
        other = env.root / "other-standins"             # another configuration's stand-ins
        other.mkdir()
        (other / envfile.STANDIN_MARKER).write_text(envfile.MARKER_TEXT)
        (other / "git").write_text("#!/bin/sh\necho other-standin\n")
        os.chmod(other / "git", 0o755)
        # the gateway's own env (a git there is the gated git's, never the user's)
        own = paths.envs_dir() / "env-x" / "bin"
        own.mkdir(parents=True)
        (own / "git").write_text("#!/bin/sh\necho gateway-env-git\n")
        os.chmod(own / "git", 0o755)
        envfile.write_stubs(envfile.stand_ins())        # no env is ready: the cold path
        stub = paths.bin_dir() / "git"
        assert not paths.env_python().exists()
        e = {**env.subprocess_env(), "PATH": f"{paths.bin_dir()}:{other}:{own}:{fakes}:"
                                              "/usr/bin:/bin"}
        r = subprocess.run([str(stub), "status", "--short"], capture_output=True, text=True,
                           env=e, timeout=30)
        assert r.returncode == 0 and r.stdout == "fake git ran\n", r
        assert HP.runs(fakes, "git")[-1]["argv"] == ["status", "--short"]
        env.write_form('[hosts.box]\naddress = "u@box.invalid"\n')
        r = subprocess.run([str(stub), "status"], capture_output=True, text=True, env=e,
                           timeout=30)
        assert r.returncode == 75 and envfile.STILL_SETTING_UP in r.stderr, r
        paths.form_path().unlink()
        paths.ensure_private()
        paths.configured_path().write_text("{}")
        r = subprocess.run([str(stub), "status"], capture_output=True, text=True, env=e,
                           timeout=30)
        assert r.returncode == 75, r


def test_the_git_stand_in_costs_little():
    """§6.6: a git call where the stub exists pays one Python start, the form
    and the configured list (no vault) and one git config call. Measured
    here as the stand-in's whole run through to the user's own git (a fake
    that exits at once), the median of several runs; the budget is 80 ms on
    macOS arm64 (GW_PERF_STRICT=1 holds it to that; under the suite's
    parallel load the bound is wider)."""
    with H.gateway_env() as env:
        _setup(env)
        fake = env.root / "fast-git"
        fake.mkdir()
        (fake / "git").write_text("#!/bin/sh\nexit 0\n")
        os.chmod(fake / "git", 0o755)
        plain = _repo(env, "plain", ("origin", PLAIN))
        drv = env.root / "perf_driver.py"
        drv.write_text(f"import sys\nsys.pycache_prefix = {H.PYC!r}\n"
                       f"sys.path.insert(0, {str(H.PLUGIN / 'src')!r})\n"
                       f"sys.path.insert(0, {str(H.PLUGIN)!r})\n"
                       "from gateway import testing\nimport run\n"
                       f"with testing.override({str(env.root)!r}, user_tools={str(fake)!r}):\n"
                       "    raise SystemExit(run.dispatch('shim', ['git', *sys.argv[1:]]))\n")
        e = env.subprocess_env()
        e.pop("GATEWAY_TEST_ROOT", None)
        times = []
        for _ in range(7):
            t0 = time.perf_counter()
            r = subprocess.run([H.PY, "-I", "-S", *H.PYX, str(drv), "status"], cwd=str(plain),
                               env=e, capture_output=True, text=True, timeout=60)
            times.append(time.perf_counter() - t0)
            assert r.returncode == 0, r
        times.sort()
        median = times[len(times) // 2]
        limit = 0.080 if os.environ.get("GW_PERF_STRICT") == "1" else 0.5
        print(f"NOTE: git stand-in pass-through median {median * 1000:.0f} ms "
              f"(budget 80 ms; runs {[round(x * 1000) for x in times]})")
        assert median <= limit, (median, times)
