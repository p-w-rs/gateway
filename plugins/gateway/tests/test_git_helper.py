"""The git credential helper and include file (SPEC 9.4), driven through the
real system git with the generated include via GIT_CONFIG_COUNT, plus
in-process unit tests for every refusal rule."""
from __future__ import annotations

import io
import os
import subprocess
import sys
from pathlib import Path

import harness as H
import harness_accounts as HA
from gateway import consent, envfile, githelper, vault
from gateway import form as formmod
from gateway import paths

TWO_GH = '''[accounts.github-personal]
kind = "github"
login = "octocat"
host = "{host}"
default = true
[accounts.github-work]
kind = "github"
login = "octo-work"
host = "{host}"
owners = ["example-org"]
'''
PTOK = "gho_PERSONALtoken0123456789abc"
WTOK = "ghp_WORKtoken0123456789abcdefg"


def _setup(env: H.GatewayEnv, srv: HA.GitServer, form_text: str, tokens: dict) -> None:
    env.o.entry = H.entry_cmd(env)
    HA.build_vault(env, form_text, tokens=tokens)
    data = vault.load()
    envfile.write_git_config(form=env.form(), vault_meta=vault.meta(data), others="refuse")
    envfile.write_stubs(envfile.stand_ins(env.form(), consent.compute(env.form(), data)))


def _clone(env, srv, git, owner, repo, extra_env=None):
    ge = HA.git_env(env, {"CLAUDE_PID": str(os.getpid()), **(extra_env or {})})
    wd = Path(env.root) / f"wd-{owner}-{repo}"
    wd.mkdir(exist_ok=True)
    return HA.git_run(git, ["clone", f"http://{srv.host}/{owner}/{repo}.git"], ge, cwd=str(wd))


# ---------------------------------------------------------------------------
# End-to-end through the real git
# ---------------------------------------------------------------------------


def test_clone_chooses_account_by_owner():
    with H.gateway_env() as env:
        git = HA.system_git_path()
        srv = HA.GitServer(Path(env.root) / "s", git)
        try:
            _setup(env, srv, TWO_GH.format(host=srv.host),
                   {"github-personal": PTOK, "github-work": WTOK})
            srv.make_repo("example-org", "work")
            srv.make_repo("octocat", "proj")
            r1 = _clone(env, srv, git, "example-org", "work")
            r2 = _clone(env, srv, git, "octocat", "proj")
            assert r1.returncode == 0 and r2.returncode == 0, (r1.stderr, r2.stderr)
            pw = {c["path"].split("/")[1]: c["password"] for c in srv.auths()}
            assert any(c["password"] == WTOK for c in srv.auths() if "example-org" in c["path"])
            assert any(c["password"] == PTOK for c in srv.auths() if "octocat" in c["path"])
        finally:
            srv.close()


def test_push_and_fetch_authenticate():
    with H.gateway_env() as env:
        git = HA.system_git_path()
        srv = HA.GitServer(Path(env.root) / "s", git)
        try:
            _setup(env, srv, TWO_GH.format(host=srv.host),
                   {"github-personal": PTOK, "github-work": WTOK})
            srv.make_repo("example-org", "work")
            r = _clone(env, srv, git, "example-org", "work")
            assert r.returncode == 0, r.stderr
            wd = Path(env.root) / "wd-example-org-work" / "work"
            ge = HA.git_env(env, {"CLAUDE_PID": str(os.getpid())})
            for k, v in (("user.email", "a@b.c"), ("user.name", "A"), ("commit.gpgsign", "false")):
                HA.git_run(git, ["config", k, v], ge, cwd=str(wd))
            (wd / "f.txt").write_text("hi")
            HA.git_run(git, ["add", "."], ge, cwd=str(wd))
            HA.git_run(git, ["commit", "-m", "x"], ge, cwd=str(wd))
            rp = HA.git_run(git, ["push", "origin", "HEAD:refs/heads/main"], ge, cwd=str(wd))
            assert rp.returncode == 0, rp.stderr
            assert any(c["method"] == "POST" and "git-receive-pack" in c["path"]
                       and c["password"] == WTOK for c in srv.auths())
        finally:
            srv.close()


def test_gate_account_override_beats_owner():
    with H.gateway_env() as env:
        git = HA.system_git_path()
        srv = HA.GitServer(Path(env.root) / "s", git)
        try:
            _setup(env, srv, TWO_GH.format(host=srv.host),
                   {"github-personal": PTOK, "github-work": WTOK})
            srv.make_repo("example-org", "work")
            r = _clone(env, srv, git, "example-org", "work",
                       extra_env={"GATE_ACCOUNT": "github-personal"})
            assert r.returncode == 0, r.stderr
            assert any(c["password"] == PTOK for c in srv.auths() if "example-org" in c["path"]), \
                "GATE_ACCOUNT=github-personal should win over the example-org owner"
            assert not any(c["password"] == WTOK for c in srv.auths())
        finally:
            srv.close()


def test_insteadof_rewrites_ssh_remote_to_https():
    with H.gateway_env() as env:
        git = HA.system_git_path()
        srv = HA.GitServer(Path(env.root) / "s", git)
        try:
            # a single token-only account whose ssh form is rewritten to http(s)
            form = ('[accounts.gh]\nkind = "github"\nlogin = "me"\nhost = "%s"\ndefault = true\n'
                    % srv.host)
            _setup(env, srv, form, {"gh": PTOK})
            srv.make_repo("me", "r")
            ge = HA.git_env(env, {"CLAUDE_PID": str(os.getpid())})
            wd = Path(env.root) / "wd"
            wd.mkdir()
            r = HA.git_run(git, ["clone", f"git@{srv.host.split(':')[0]}:me/r.git", "out"], ge,
                           cwd=str(wd))
            assert r.returncode == 0, ("insteadOf should rewrite ssh->http", r.stderr)
            assert srv.auths(), "the rewrite should have gone through the credential helper"
        finally:
            srv.close()


def test_identity_includeif_selects_commit_identity():
    with H.gateway_env() as env:
        git = HA.system_git_path()
        form = ('[accounts.github-work]\nkind = "github"\nlogin = "octo-work"\n'
                'owners = ["example-org"]\nname = "Octo Cat"\nemail = "work@example.com"\n')
        HA.build_vault(env, form, tokens={"github-work": WTOK})
        data = vault.load()
        envfile.write_git_config(form=env.form(), vault_meta=vault.meta(data), others="refuse")
        repo = Path(env.root) / "repo"
        repo.mkdir()
        ge = HA.git_env(env, {"CLAUDE_PID": str(os.getpid())})
        HA.git_run(git, ["init", "-q", "."], ge, cwd=str(repo))
        HA.git_run(git, ["remote", "add", "origin", "https://github.com/example-org/x.git"], ge,
                   cwd=str(repo))
        r = HA.git_run(git, ["config", "user.email"], ge, cwd=str(repo))
        assert r.stdout.strip() == "work@example.com", (r.stdout, r.stderr)
        HA.git_run(git, ["remote", "set-url", "origin", "https://github.com/other/y.git"], ge,
                   cwd=str(repo))
        r2 = HA.git_run(git, ["config", "user.email"], ge, cwd=str(repo))
        assert r2.stdout.strip() != "work@example.com", "other owners must not get the work identity"


def test_user_helper_not_consulted_but_other_hosts_left_alone():
    with H.gateway_env() as env:
        git = HA.system_git_path()
        srv = HA.GitServer(Path(env.root) / "s", git)
        try:
            _setup(env, srv, TWO_GH.format(host=srv.host),
                   {"github-personal": PTOK, "github-work": WTOK})
            srv.make_repo("example-org", "work")
            # a user global credential helper that would hand out a token for ANY host
            home = Path(env.root) / "githome"
            home.mkdir(exist_ok=True)
            leak = home / "leak.sh"
            leak.write_text("#!/bin/sh\n[ \"$1\" = get ] && printf 'username=u\\npassword=USERLEAK\\n'\n")
            os.chmod(leak, 0o755)
            (home / ".gitconfig").write_text(f"[credential]\n\thelper = {leak}\n")
            # github host: the global reset means the user helper is not consulted;
            # the gateway helper serves it instead.
            r = _clone(env, srv, git, "example-org", "work")
            assert r.returncode == 0, r.stderr
            assert not any(c["password"] == "USERLEAK" for c in srv.auths()), \
                "the user's own helper must not be consulted for a gateway host"
            assert any(c["password"] == WTOK for c in srv.auths())
        finally:
            srv.close()


def test_git_credential_fill_typed_directly_is_refused():
    with H.gateway_env() as env:
        git = HA.system_git_path()
        srv = HA.GitServer(Path(env.root) / "s", git)
        try:
            _setup(env, srv, TWO_GH.format(host=srv.host),
                   {"github-personal": PTOK, "github-work": WTOK})
            ge = HA.git_env(env, {"CLAUDE_PID": str(os.getpid())})
            req = f"protocol=http\nhost={srv.host}\npath=example-org/work.git\n\n"
            r = subprocess.run([git, "credential", "fill"], input=req, env=ge,
                               capture_output=True, text=True, timeout=30)
            assert WTOK not in r.stdout and PTOK not in r.stdout, \
                "a direct `git credential fill` must get no token from the helper"
        finally:
            srv.close()


def test_git_trace_redact_off_is_refused():
    with H.gateway_env() as env:
        git = HA.system_git_path()
        srv = HA.GitServer(Path(env.root) / "s", git)
        try:
            _setup(env, srv, TWO_GH.format(host=srv.host),
                   {"github-personal": PTOK, "github-work": WTOK})
            srv.make_repo("example-org", "work")
            r = _clone(env, srv, git, "example-org", "work",
                       extra_env={"GIT_TRACE_REDACT": "0"})
            # the helper refuses, so no token reaches the server
            assert not any(c["password"] in (WTOK, PTOK) for c in srv.auths()), \
                "with GIT_TRACE_REDACT=0 the helper must not hand over the token"
        finally:
            srv.close()


# ---------------------------------------------------------------------------
# In-process credential_main unit tests
# ---------------------------------------------------------------------------


def _helper_get(req: dict, *, parent_ok: bool = True, op: str = "get",
                extra_env: dict | None = None, real_ssl: bool = False) -> tuple[int, str, str]:
    """Run credential_main in-process. real_ssl=False stubs the git config
    sslVerify lookup (no config consulted); real_ssl=True runs the real one
    against the cwd's git config (the caller sets up a hermetic repo)."""
    from gateway import githelper as gh
    old_parent = gh._parent_is_git_remote_http
    old_ssl = gh._http_ssl_verify_false
    gh._parent_is_git_remote_http = lambda: parent_ok
    if not real_ssl:
        gh._http_ssl_verify_false = lambda url: None
    body = "".join(f"{k}={v}\n" for k, v in req.items()) + "\n"
    old_stdin, old_env = sys.stdin, dict(os.environ)
    for k in ("GIT_TRACE_REDACT", "GIT_SSL_NO_VERIFY", "GATE_ACCOUNT"):
        os.environ.pop(k, None)
    os.environ.update(extra_env or {})
    try:
        with HA.capture_fds() as box:
            buf = io.TextIOWrapper(io.BytesIO(body.encode()))
            buf.buffer.seek(0)
            sys.stdin = buf
            rc = gh.credential_main([op])
        return rc, box["out"].decode(), box["err"].decode()
    finally:
        sys.stdin = old_stdin
        os.environ.clear()
        os.environ.update(old_env)
        gh._parent_is_git_remote_http = old_parent
        gh._http_ssl_verify_false = old_ssl


def test_helper_refuses_when_parent_is_not_git_remote_http():
    with H.gateway_env() as env:
        HA.build_vault(env, '[accounts.gh]\nkind = "github"\nlogin = "me"\ndefault = true\n',
                       tokens={"gh": WTOK})
        rc, out, err = _helper_get(
            {"protocol": "https", "host": "github.com", "path": "me/r.git"}, parent_ok=False)
        assert WTOK not in out and "password=" not in out
        assert "only git itself" in err


def test_parent_check_takes_gits_own_shell_running_only_this_helper():
    """Debian's and Ubuntu's /bin/sh is dash, which forks the one command of
    `sh -c` where macOS's bash execs it: git runs an absolute-path helper as
    `sh -c "<helper> get"`, so on Debian the helper's parent is the shell and
    every git credential was refused (found in the Linux VM, PLAN-v4 phase 4).
    A shell between git-remote-http and the helper counts only when it runs
    exactly the gateway's helper with this operation; a snippet that wraps it
    (a pipe into tee, a function) or a shell Claude started does not."""
    from gateway import githelper as gh
    with H.gateway_env():
        helper = str(paths.bin_dir() / "git-credential-gateway")
        me = os.getpid()
        saved = (gh._parent_pid, gh._exe_base, gh._cmdline)

        def run(chain: list[tuple[str, list[str] | None]]) -> bool:
            # chain[0] is the helper's parent, then its parent, ...
            pids = [me] + [1000 + i for i in range(len(chain))]
            par = {pids[i]: pids[i + 1] for i in range(len(chain))}
            exe = {pids[i + 1]: chain[i][0] for i in range(len(chain))}
            cmd = {pids[i + 1]: chain[i][1] for i in range(len(chain))}
            gh._parent_pid = lambda pid: par.get(pid)
            gh._exe_base = lambda pid: exe.get(pid, "")
            gh._cmdline = lambda pid: cmd.get(pid)
            return gh._parent_is_git_remote_http("get")
        try:
            sh_ok = ["/bin/sh", "-c", f"{helper} get"]
            assert run([("git-remote-https", None)])
            assert run([("dash", sh_ok), ("git-remote-https", None)])
            assert run([("dash", ["/bin/sh", "-c", f'{helper} get "$@"', f'{helper} get "$@"']),
                        ("git-remote-http", None)])
            assert run([("bash", sh_ok), ("git-remote-http", None)])
            assert not run([("dash", sh_ok), ("bash", None)]), "a shell Claude started"
            assert not run([("dash", ["/bin/sh", "-c", f"{helper} get | tee /tmp/x"]),
                            ("git-remote-https", None)]), "a snippet wrapping the helper"
            assert not run([("dash", ["/bin/sh", "-c", "f() { " + helper + " get; }; f"]),
                            ("git-remote-https", None)])
            assert not run([("dash", ["/bin/sh", "-c", "/elsewhere/git-credential-gateway get"]),
                            ("git-remote-https", None)]), "another copy of the helper"
            assert not run([("dash", ["/bin/sh", "-c", f"{helper} erase"]), ("git-remote-https", None)])
            assert not run([("python3", sh_ok), ("git-remote-https", None)])
            assert not run([("git", None), ("bash", None)]), "git credential fill typed by Claude"
            assert run([("git", None), ("git-lfs", None)])
        finally:
            gh._parent_pid, gh._exe_base, gh._cmdline = saved


def test_helper_refuses_git_trace_redact_off():
    with H.gateway_env() as env:
        HA.build_vault(env, '[accounts.gh]\nkind = "github"\nlogin = "me"\ndefault = true\n',
                       tokens={"gh": WTOK})
        rc, out, err = _helper_get({"protocol": "https", "host": "github.com", "path": "me/r.git"},
                                   extra_env={"GIT_TRACE_REDACT": "0"})
        assert "password=" not in out and "GIT_TRACE_REDACT" in err


def test_helper_refuses_non_loopback_http():
    with H.gateway_env() as env:
        HA.build_vault(env, '[accounts.gh]\nkind = "github"\nlogin = "me"\ndefault = true\n',
                       tokens={"gh": WTOK})
        rc, out, err = _helper_get({"protocol": "http", "host": "github.com", "path": "me/r.git"})
        assert "password=" not in out and "https only" in err


def test_helper_refuses_ssl_no_verify():
    with H.gateway_env() as env:
        HA.build_vault(env, '[accounts.gh]\nkind = "github"\nlogin = "me"\ndefault = true\n',
                       tokens={"gh": WTOK})
        rc, out, err = _helper_get({"protocol": "https", "host": "github.com", "path": "me/r.git"},
                                   extra_env={"GIT_SSL_NO_VERIFY": "1"})
        assert "password=" not in out and "GIT_SSL_NO_VERIFY" in err


def test_helper_unknown_host_message():
    with H.gateway_env() as env:
        HA.build_vault(env, '[accounts.gh]\nkind = "github"\nlogin = "me"\ndefault = true\n',
                       tokens={"gh": WTOK})
        rc, out, err = _helper_get({"protocol": "https", "host": "gitlab.com", "path": "x/y.git"})
        assert "password=" not in out and "no account for gitlab.com" in err


def test_helper_ambiguity_message():
    with H.gateway_env() as env:
        form = ('[accounts.a]\nkind = "github"\nowners = ["dup"]\n'
                '[accounts.b]\nkind = "github"\nlogin = "dup"\n')
        HA.build_vault(env, form, tokens={"a": WTOK, "b": PTOK})
        rc, out, err = _helper_get({"protocol": "https", "host": "github.com", "path": "dup/r.git"})
        assert "password=" not in out and "fit; set GATE_ACCOUNT" in err


def test_helper_refuses_unbound_host():
    with H.gateway_env() as env:
        # approved in the form, but the credential was never bound (no vault
        # binding record): the helper's defence-in-depth bound check refuses.
        HA.build_vault(env, '[accounts.gh]\nkind = "github"\nlogin = "me"\ndefault = true\n',
                       tokens={"gh": WTOK}, approve=True)
        data = vault.load()
        del data["accounts"]["gh"]                           # no binding record at all
        vault.save(data)
        rc, out, err = _helper_get({"protocol": "https", "host": "github.com", "path": "me/r.git"})
        assert "password=" not in out and "isn't bound" in err


def test_helper_returns_x_access_token_for_github():
    with H.gateway_env() as env:
        HA.build_vault(env, '[accounts.gh]\nkind = "github"\nlogin = "me"\ndefault = true\n',
                       tokens={"gh": WTOK})
        rc, out, err = _helper_get({"protocol": "https", "host": "github.com", "path": "me/r.git"})
        assert "username=x-access-token" in out and f"password={WTOK}" in out


def test_helper_erase_marks_token_stale():
    with H.gateway_env() as env:
        HA.build_vault(env, '[accounts.gh]\nkind = "github"\nlogin = "me"\ndefault = true\n',
                       tokens={"gh": WTOK})
        _helper_get({"protocol": "https", "host": "github.com", "path": "me/r.git"}, op="erase")
        data = vault.load()
        assert data["accounts"]["gh"]["token"]["stale"] is True
        # a stale token is never handed out again
        rc, out, err = _helper_get({"protocol": "https", "host": "github.com", "path": "me/r.git"})
        assert "password=" not in out and "rejected" in err


# ---------------------------------------------------------------------------
# Certificate checking: GIT_SSL_NO_VERIFY (presence) and http.sslVerify
# (including URL-scoped keys), checked through the real git config
# ---------------------------------------------------------------------------

ONE_GH = '[accounts.gh]\nkind = "github"\nlogin = "me"\ndefault = true\n'


def _hermetic_repo(env, name: str, config: list[tuple[str, str]]) -> tuple[Path, dict]:
    """A repo with the given local config, and env vars that keep git away
    from the user's own global/system config."""
    git = HA.system_git_path()
    home = Path(env.root) / f"home-{name}"
    home.mkdir()
    (home / ".gitconfig").write_text("")
    genv = {"HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": str(home / ".gitconfig")}
    repo = Path(env.root) / f"repo-{name}"
    repo.mkdir()
    base = dict(os.environ, **genv)
    for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"):
        base.pop(k, None)
    subprocess.run([git, "init", "-q", "."], cwd=str(repo), env=base, check=True,
                   capture_output=True)
    for k, v in config:
        subprocess.run([git, "config", k, v], cwd=str(repo), env=base, check=True,
                       capture_output=True)
    return repo, genv


def _helper_in(repo: Path, genv: dict, req: dict, extra_env: dict | None = None):
    old = os.getcwd()
    os.chdir(str(repo))
    try:
        clear = {k: None for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_PARAMETERS",
                                   "GIT_CONFIG_COUNT")}
        with HA.env_vars(**clear):
            return _helper_get(req, extra_env={**genv, **(extra_env or {})}, real_ssl=True)
    finally:
        os.chdir(old)


def test_helper_refuses_url_scoped_ssl_verify_false():
    with H.gateway_env() as env:
        HA.build_vault(env, ONE_GH, tokens={"gh": WTOK})
        req = {"protocol": "https", "host": "github.com", "path": "me/r.git"}
        # control: nothing configured -> the real check passes and the token is given
        repo, genv = _hermetic_repo(env, "plain", [])
        rc, out, err = _helper_in(repo, genv, req)
        assert f"password={WTOK}" in out, err
        # the URL-scoped form (the common way to turn checking off for one host)
        repo, genv = _hermetic_repo(env, "scoped", [("http.https://github.com/.sslVerify", "false")])
        rc, out, err = _helper_in(repo, genv, req)
        assert "password=" not in out and "sslVerify is false" in err, (out, err)
        # scoped to the owner path
        repo, genv = _hermetic_repo(env, "path", [("http.https://github.com/me/.sslVerify", "false")])
        rc, out, err = _helper_in(repo, genv, req)
        assert "password=" not in out and "sslVerify is false" in err, (out, err)
        # the plain key
        repo, genv = _hermetic_repo(env, "global", [("http.sslVerify", "false")])
        rc, out, err = _helper_in(repo, genv, req)
        assert "password=" not in out and "sslVerify is false" in err, (out, err)
        # scoped to another host: this host is still checked, so the token is given
        repo, genv = _hermetic_repo(env, "other", [("http.https://gitlab.com/.sslVerify", "false")])
        rc, out, err = _helper_in(repo, genv, req)
        assert f"password={WTOK}" in out, err


def test_helper_fails_closed_when_git_cannot_read_ssl_verify():
    with H.gateway_env() as env:
        HA.build_vault(env, ONE_GH, tokens={"gh": WTOK})
        req = {"protocol": "https", "host": "github.com", "path": "me/r.git"}
        repo, genv = _hermetic_repo(env, "bad", [("http.sslVerify", "maybe")])
        rc, out, err = _helper_in(repo, genv, req)
        assert "password=" not in out and "couldn't read" in err, (out, err)


def test_helper_refuses_empty_ssl_no_verify():
    # git turns certificate checking off when GIT_SSL_NO_VERIFY is present at
    # all (getenv != NULL), even with an empty value.
    with H.gateway_env() as env:
        HA.build_vault(env, ONE_GH, tokens={"gh": WTOK})
        for value in ("", "0", "false"):
            rc, out, err = _helper_get({"protocol": "https", "host": "github.com",
                                        "path": "me/r.git"}, extra_env={"GIT_SSL_NO_VERIFY": value})
            assert "password=" not in out and "GIT_SSL_NO_VERIFY" in err, (value, err)


def test_url_scoped_ssl_verify_false_refused_through_real_git():
    with H.gateway_env() as env:
        git = HA.system_git_path()
        srv = HA.GitServer(Path(env.root) / "s", git)
        try:
            _setup(env, srv, TWO_GH.format(host=srv.host),
                   {"github-personal": PTOK, "github-work": WTOK})
            srv.make_repo("example-org", "work")
            ge = HA.git_env(env, {"CLAUDE_PID": str(os.getpid())})
            wd = Path(env.root) / "wd-ssl"
            wd.mkdir()
            r = HA.git_run(git, ["-c", f"http.http://{srv.host}/.sslVerify=false", "clone",
                                 f"http://{srv.host}/example-org/work.git"], ge, cwd=str(wd))
            assert r.returncode != 0
            assert "sslVerify is false" in r.stderr, r.stderr
            assert not any(c["password"] in (WTOK, PTOK) for c in srv.auths()), \
                "a URL-scoped http.sslVerify=false must keep the token back"
            # control: the same clone without it authenticates
            r2 = HA.git_run(git, ["clone", f"http://{srv.host}/example-org/work.git", "ok"], ge,
                            cwd=str(wd))
            assert r2.returncode == 0, r2.stderr
            assert any(c["password"] == WTOK for c in srv.auths())
        finally:
            srv.close()


# ---------------------------------------------------------------------------
# A rejected token (git's `erase` after a 401): the right account, and the
# true next step (review round 4)
# ---------------------------------------------------------------------------

TWO_GH_NO_DEFAULT = '''[accounts.github-personal]
kind = "github"
login = "octocat"
host = "{host}"
[accounts.github-work]
kind = "github"
login = "octo-work"
host = "{host}"
owners = ["example-org"]
'''


def _stale(name: str) -> bool:
    return bool(((vault.load().get("accounts") or {}).get(name) or {}).get("token", {})
                .get("stale"))


def test_a_401_marks_the_account_whose_token_was_rejected_not_the_default():
    """github-personal is the default, github-work owns example-org/*. The
    server rejects the work token (revoked): git erases it, and the work
    account (not the default) becomes stale; the personal account keeps
    working, and the revoked token isn't sent again on a retry."""
    with H.gateway_env() as env:
        git = HA.system_git_path()
        srv = HA.GitServer(Path(env.root) / "s", git)
        try:
            _setup(env, srv, TWO_GH.format(host=srv.host),
                   {"github-personal": PTOK, "github-work": WTOK})
            srv.make_repo("example-org", "work")
            srv.make_repo("octocat", "proj")
            srv.rejected.add(WTOK)
            r1 = _clone(env, srv, git, "example-org", "work")
            assert r1.returncode != 0
            assert _stale("github-work") and not _stale("github-personal")
            r2 = _clone(env, srv, git, "octocat", "proj")
            assert r2.returncode == 0, r2.stderr
            sent = sum(1 for c in srv.calls if c["password"] == WTOK)
            r3 = _clone(env, srv, git, "example-org", "work")
            assert r3.returncode != 0
            assert sum(1 for c in srv.calls if c["password"] == WTOK) == sent, \
                "the revoked token was sent again"
            assert "github-work's token was rejected; don't retry. Run gate check github-work" \
                in r3.stderr, r3.stderr
            data = vault.load()
            ev = [e["detail"] for e in data.get("events", []) if e.get("what") == "reject"]
            assert ev and all("github-work" in d for d in ev), ev
        finally:
            srv.close()


def test_erase_without_a_default_marks_the_rejected_account():
    """Two accounts and no default: the rejected one is still found (by its
    token), so the bad token isn't retried forever."""
    with H.gateway_env() as env:
        HA.build_vault(env, TWO_GH_NO_DEFAULT.format(host="github.com"),
                       tokens={"github-personal": PTOK, "github-work": WTOK})
        _helper_get({"protocol": "https", "host": "github.com", "path": "example-org/work.git",
                     "username": "x-access-token", "password": WTOK}, op="erase")
        assert _stale("github-work") and not _stale("github-personal")


def test_erase_with_an_unknown_password_marks_nothing_and_no_password_follows_the_owner():
    with H.gateway_env() as env:
        HA.build_vault(env, TWO_GH.format(host="github.com"),
                       tokens={"github-personal": PTOK, "github-work": WTOK})
        _helper_get({"protocol": "https", "host": "github.com", "path": "example-org/work.git",
                     "username": "x-access-token", "password": "ghp_somebodyElsesToken0123456789"},
                    op="erase")
        assert not _stale("github-work") and not _stale("github-personal")
        # a token bound elsewhere doesn't count either
        _helper_get({"protocol": "https", "host": "gitlab.example.com", "path": "x/y.git",
                     "username": "x", "password": WTOK}, op="erase")
        assert not _stale("github-work")
        # no password: the account `get` would choose for that path (the owner's)
        _helper_get({"protocol": "https", "host": "github.com", "path": "example-org/work.git"},
                    op="erase")
        assert _stale("github-work") and not _stale("github-personal")


def test_a_stale_token_message_never_claims_an_open_pop_up():
    """No pop-up opens by itself for a rejected token (popup.pending() stays
    empty); the message names the real next step, gate check NAME."""
    from gateway import popup
    with H.gateway_env() as env:
        HA.build_vault(env, ONE_GH, tokens={"gh": WTOK})
        with vault.edit() as d:
            vault.mark_stale(d, "gh", "token")
        rc, out, err = _helper_get({"protocol": "https", "host": "github.com", "path": "me/r.git"})
        assert "password=" not in out
        assert popup.pending() == []
        assert "pop-up" not in err and "gate check gh while the user is here" in err, err
