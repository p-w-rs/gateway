"""The shared git resolver (gitroute.py, PLAN-0.11 §6.2): repositories and
their effective URLs read through the bundled git as the user's git reads
them, aliases, insteadOf and pushInsteadOf, pushurl, several urls, branch
and push remotes, submodules, git-lfs URLs, the command line's -c and
--config-env, -C/--git-dir/GIT_DIR, configured hosts and accounts (GHES,
ssh endpoints, owners), the user's own config passing through, and the
unreadable-config refusal. Real git in scratch repositories under the test
root, with a scratch HOME and no system config; nothing touches a network."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import harness as H
from gateway import form as formmod
from gateway import gitroute as G

GIT = str(H.ENV_BIN / "git")

FORM = """
[hosts.box]
address = "tester@10.1.2.3:2222"
also = ["tester@box.example.net"]
ssh = true

[accounts.work]
kind = "github"
owners = ["example-org"]

[accounts.personal]
kind = "github"
login = "octocat"

[accounts.ghes]
kind = "github"
host = "ghe.example.com"
login = "octo-ghes"

[accounts.hf-a]
kind = "huggingface"
owners = ["shared-org"]

[accounts.hf-b]
kind = "huggingface"
login = "octocat"
"""

WORK = "https://github.com/example-org/tool.git"        # configured (work's owner)
MINE = "https://github.com/octocat/dots.git"             # configured (personal's login)
OTHER = "https://github.com/someone-else/lib.git"        # github.com, no account for that owner
PLAIN = "https://git.example.org/team/x.git"             # nothing configured there


class Box:
    """A scratch HOME and folder for repositories, a hermetic environment for
    git (no system config, no XDG or GIT_* of the test runner's), and the
    form's targets."""

    def __init__(self, env: H.GatewayEnv, form: str = FORM):
        self.root = env.root / "git-route"
        self.home = self.root / "home"
        (self.home / ".config").mkdir(parents=True)
        self.env = {"PATH": f"{H.ENV_BIN}:/usr/bin:/bin", "HOME": str(self.home),
                    "XDG_CONFIG_HOME": str(self.home / ".config"), "GIT_CONFIG_NOSYSTEM": "1",
                    "LANG": "C"}
        self.targets = G.Targets.from_forms(formmod.parse_text(form))

    def git(self, cwd: Path, *args: str) -> str:
        r = subprocess.run([GIT, *args], cwd=str(cwd), env=self.env, capture_output=True,
                           text=True, timeout=30)
        assert r.returncode == 0, (args, r.stderr)
        return r.stdout

    def repo(self, name: str, *remotes: tuple[str, str]) -> Path:
        d = self.root / name
        d.mkdir(parents=True)
        self.git(d, "init", "-q", "-b", "main")
        for rname, url in remotes:
            self.git(d, "remote", "add", rname, url)
        return d

    def route(self, argv: list[str], cwd: Path | None = None, env: dict | None = None,
              targets: G.Targets | None = None) -> G.Route:
        return G.resolve(argv, str(cwd or self.root), targets=self.targets if targets is None
                         else targets, env=self.env if env is None else env)


def _hits(r: G.Route) -> set[tuple[str, str]]:
    return set(r.entries())


# ---------------------------------------------------------------------------
# Repositories and their remotes
# ---------------------------------------------------------------------------


def test_every_command_in_a_repository_with_a_configured_remote_is_gated():
    with H.gateway_env() as env:
        b = Box(env)
        gated = b.repo("gated", ("origin", WORK))
        plain = b.repo("plain", ("origin", PLAIN))
        for argv in (["status"], ["log", "--oneline"], ["commit", "-m", "x"], ["diff"], ["push"],
                     ["fetch"], ["--no-pager", "show"]):
            r = b.route(argv, gated)
            assert r.gated and r.refusal == "" and _hits(r) == {("accounts", "work")}, (argv, r)
            r = b.route(argv, plain)
            assert not r.gated and r.urls and not r.configured, (argv, r)
        (gated / "sub").mkdir()
        r = b.route(["status"], gated / "sub")
        assert r.gated and r.repo == str((gated / ".git").resolve()) and \
            r.worktree == str(gated.resolve()), r
        # outside any repository nothing is configured
        r = b.route(["status"], b.root)
        assert not r.gated and r.repo == "" and r.urls == (), r
        assert b.route(["push"], gated).remote and not b.route(["status"], gated).remote


def test_owners_decide_which_github_urls_are_configured():
    with H.gateway_env() as env:
        b = Box(env)
        for url, want in ((WORK, {("accounts", "work")}), (MINE, {("accounts", "personal")}),
                          ("git@github.com:example-org/tool.git", {("accounts", "work")}),
                          ("ssh://git@ssh.github.com:443/example-org/tool.git", {("accounts", "work")}),
                          ("https://github.com/", {("accounts", "work"), ("accounts", "personal")}),
                          (OTHER, set()), (PLAIN, set())):
            r = b.route(["clone", url])
            assert _hits(r) == want and r.gated == bool(want), (url, r.urls)
        # the only account for its kind and host covers every owner there while it lists
        # no owners; one that lists them covers only those and its login (WS-9); a
        # default one covers every owner
        solo = G.Targets.from_forms(formmod.parse_text(
            '[accounts.only]\nkind = "github"\nlogin = "octo-work"\n'))
        assert b.route(["clone", OTHER], targets=solo).gated
        listed = G.Targets.from_forms(formmod.parse_text(
            '[accounts.only]\nkind = "github"\nlogin = "octo-work"\nowners = ["example-org"]\n'))
        assert not b.route(["clone", OTHER], targets=listed).gated
        for url in (WORK, "https://github.com/octo-work/dotfiles.git", "https://github.com/"):
            assert _hits(b.route(["clone", url], targets=listed)) == {("accounts", "only")}, url
        dflt = G.Targets.from_forms(formmod.parse_text(FORM + '[accounts.catchall]\nkind = "github"\n'
                                                       'default = true\n'))
        assert _hits(b.route(["clone", OTHER], targets=dflt)) == {("accounts", "catchall")}


def test_an_accounts_own_host_counts_so_github_enterprise_is_configured():
    with H.gateway_env() as env:
        b = Box(env)
        for url in ("https://ghe.example.com/team/x.git", "git@ghe.example.com:team/x.git",
                    "ssh://git@ghe.example.com/team/x.git"):
            r = b.route(["ls-remote", url])
            assert _hits(r) == {("accounts", "ghes")} and r.remote, (url, r.urls)
        port = G.Targets.from_forms(formmod.parse_text(
            '[accounts.p]\nkind = "github"\nhost = "ghe.example.com:8443"\nlogin = "x"\n'))
        assert b.route(["clone", "https://ghe.example.com:8443/team/x"], targets=port).gated
        assert not b.route(["clone", "https://ghe.example.com:9999/team/x"], targets=port).gated
        assert b.route(["clone", "git@ghe.example.com:team/x"], targets=port).gated


def test_huggingface_owners_skip_the_datasets_and_spaces_prefixes():
    with H.gateway_env() as env:
        b = Box(env)
        assert _hits(b.route(["clone", "https://huggingface.co/datasets/shared-org/d"])) == \
            {("accounts", "hf-a")}
        assert _hits(b.route(["clone", "https://hf.co/spaces/octocat/s"])) == {("accounts", "hf-b")}
        assert not b.route(["clone", "https://huggingface.co/someone-else/m"]).gated


def test_a_configured_host_counts_by_name_gw_name_address_and_also_entry():
    with H.gateway_env() as env:
        b = Box(env)
        for url in ("box:srv/repo.git", "gw-box:srv/repo.git", "ssh://tester@10.1.2.3:2222/srv/r",
                    "10.1.2.3:srv/r", "u@box.example.net:srv/r", "https://BOX.example.net/r",
                    "ssh://[10.1.2.3]/r", "ext::ssh -p 2222 tester@box.example.net %S /srv/r"):
            r = b.route(["fetch", url], b.repo(f"r{abs(hash(url))}"))
            assert _hits(r) == {("hosts", "box")} and r.gated, (url, r.urls)
        for url in ("localhost:repo", "boxy:srv/r", "/srv/box/r", "file:///box/r", "./box"):
            assert not b.route(["clone", url]).gated, url
        # a host with a mistake in it stays configured by its name (PLAN-0.11 §1.1)
        broken = G.Targets.from_forms(formmod.parse_text(
            '[hosts.lab]\naddress = "tester@10.9.9.9"\nalso = ["other@lab.example.net"]\n'))
        assert _hits(b.route(["clone", "lab:srv/r"], targets=broken)) == {("hosts", "lab")}
        assert b.route(["clone", "gw-lab:srv/r"], targets=broken).gated


def test_insteadof_rewrites_with_the_longest_match_as_git_does():
    with H.gateway_env() as env:
        b = Box(env)
        d = b.repo("rw", ("origin", "https://mirror.example.org/example-org/tool.git"))
        assert not b.route(["status"], d).gated
        b.git(d, "config", "url.https://github.com/.insteadOf", "https://mirror.example.org/")
        r = b.route(["status"], d)
        assert r.gated and _hits(r) == {("accounts", "work")}, r.urls
        assert r.urls[0].url == "https://github.com/example-org/tool.git", r.urls
        # a longer prefix wins
        b.git(d, "config", "url.https://git.example.org/.insteadOf",
              "https://mirror.example.org/example-org/")
        assert not b.route(["status"], d).gated
        # the user's global config counts (read as the user's git reads it)
        e = b.repo("rw2", ("origin", "gh:example-org/tool"))
        assert not b.route(["status"], e).gated
        (b.home / ".gitconfig").write_text('[url "https://github.com/"]\n\tinsteadOf = gh:\n')
        assert b.route(["status"], e).gated
        # so does an operand of a command, shorthand or not
        assert b.route(["clone", "gh:example-org/tool"]).gated


def test_pushinsteadof_and_pushurl_are_push_urls():
    with H.gateway_env() as env:
        b = Box(env)
        d = b.repo("p1", ("origin", PLAIN))
        b.git(d, "config", "url.https://github.com/example-org/.pushInsteadOf", "https://git.example.org/team/")
        r = b.route(["push"], d)
        assert r.gated and [u.use for u in r.configured] == [frozenset({"push"})], r.urls
        # an explicit pushurl: pushInsteadOf no longer applies to that remote
        b.git(d, "config", "remote.origin.pushurl", "https://git.example.org/other/x.git")
        assert not b.route(["push"], d).gated
        b.git(d, "config", "--add", "remote.origin.pushurl", MINE)
        r = b.route(["push"], d)
        assert _hits(r) == {("accounts", "personal")} and \
            r.configured[0].source == "remote.origin.pushurl", r.urls
        # a push operand is rewritten by pushInsteadOf too
        e = b.repo("p2")
        b.git(e, "config", "url.https://github.com/example-org/.pushInsteadOf", "https://git.example.org/team/")
        assert b.route(["push", PLAIN, "main"], e).gated
        assert not b.route(["fetch", PLAIN], e).gated


def test_every_url_of_a_remote_and_every_remote_counts():
    with H.gateway_env() as env:
        b = Box(env)
        d = b.repo("multi", ("origin", PLAIN), ("upstream", "https://git.example.org/up/x"))
        assert not b.route(["status"], d).gated
        b.git(d, "config", "--add", "remote.origin.url", WORK)      # a second url (push goes to both)
        assert _hits(b.route(["status"], d)) == {("accounts", "work")}
        e = b.repo("multi2", ("origin", PLAIN), ("backup", "box:srv/x.git"))
        assert _hits(b.route(["log"], e)) == {("hosts", "box")}


def test_branch_and_push_remotes_that_name_a_url_count():
    with H.gateway_env() as env:
        b = Box(env)
        for key, use in (("branch.main.pushRemote", "push"), ("remote.pushDefault", "push"),
                         ("branch.main.remote", "fetch")):
            d = b.repo(f"br-{key}", ("origin", PLAIN))
            b.git(d, "config", key, MINE)
            r = b.route(["status"], d)
            assert r.gated and r.configured[0].use == frozenset({use}), (key, r.urls)
            # naming a remote adds nothing of its own
            e = b.repo(f"br2-{key}", ("origin", PLAIN))
            b.git(e, "config", key, "origin")
            assert not b.route(["status"], e).gated, key


def test_submodule_urls_count_from_gitmodules_and_from_the_config():
    with H.gateway_env() as env:
        b = Box(env)
        d = b.repo("super", ("origin", PLAIN))
        (d / ".gitmodules").write_text('[submodule "lib"]\n\tpath = lib\n\turl = ../lib.git\n')
        assert not b.route(["status"], d).gated                   # relative: the same host
        (d / ".gitmodules").write_text('[submodule "lib"]\n\tpath = lib\n\turl = ' + WORK + "\n")
        r = b.route(["submodule", "update", "--init"], d)
        assert r.gated and r.remote and r.configured[0].source == "gitmodules", r.urls
        e = b.repo("super2", ("origin", PLAIN))
        b.git(e, "config", "submodule.lib.url", "box:srv/lib.git")
        assert _hits(b.route(["status"], e)) == {("hosts", "box")}
        # a submodule added from a configured URL
        assert b.route(["submodule", "add", MINE, "dots"], b.repo("super3")).gated


def test_git_lfs_urls_count_from_the_config_and_from_lfsconfig():
    with H.gateway_env() as env:
        b = Box(env)
        for key in ("lfs.url", "lfs.pushurl", "remote.origin.lfsurl", "remote.origin.lfspushurl"):
            d = b.repo(f"lfs-{key}", ("origin", PLAIN))
            b.git(d, "config", key, "https://github.com/example-org/tool.git/info/lfs")
            assert b.route(["lfs", "push", "origin"], d).gated, key
        e = b.repo("lfs-file", ("origin", PLAIN))
        (e / ".lfsconfig").write_text('[lfs]\n\turl = https://github.com/example-org/tool.git/info/lfs\n')
        r = b.route(["status"], e)
        assert r.gated and r.configured[0].source == "lfsconfig", r.urls


def test_the_command_lines_config_counts():
    with H.gateway_env() as env:
        b = Box(env)
        d = b.repo("cl", ("origin", PLAIN))
        assert b.route(["-c", f"remote.origin.url={WORK}", "fetch"], d).gated
        assert b.route(["-c", "remote.extra.url=box:x", "status"], d).gated
        env2 = {**b.env, "GW_URL": MINE}
        assert b.route(["--config-env=remote.origin.pushurl=GW_URL", "push"], d, env=env2).gated
        assert b.route(["--config-env", "remote.origin.pushurl=GW_URL", "push"], d, env=env2).gated
        assert b.route(["-c", "url.https://github.com/example-org/.insteadOf=https://git.example.org/team/",
                        "status"], d).gated
        # the environment's own config pairs, as git reads them
        env3 = {**b.env, "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "remote.origin.url",
                "GIT_CONFIG_VALUE_0": WORK}
        assert b.route(["status"], d, env=env3).gated
        # clone's own -c pairs apply before it fetches
        assert b.route(["clone", "-c", "url.https://github.com/example-org/.insteadOf=https://git.example.org/team/",
                        PLAIN]).gated
        r = b.route(["clone", "-c", "url.box:srv/.insteadOf=https://git.example.org/team/", PLAIN])
        assert _hits(r) == {("hosts", "box")}, r.urls
        r = b.route(["clone", f"--config=remote.origin.pushurl={MINE}", PLAIN])
        assert _hits(r) == {("accounts", "personal")}, r.urls


def test_the_repository_comes_from_c_git_dir_work_tree_and_git_dir_in_the_environment():
    with H.gateway_env() as env:
        b = Box(env)
        d = b.repo("elsewhere", ("origin", WORK))
        assert not b.route(["status"], b.root).gated
        assert b.route(["-C", str(d), "status"], b.root).gated
        assert b.route(["-C", "elsewhere", "log"], b.root).gated
        assert b.route(["--git-dir", str(d / ".git"), "log"], b.root).gated
        assert b.route([f"--git-dir={d / '.git'}", f"--work-tree={d}", "status"], b.root).gated
        assert b.route(["status"], b.root, env={**b.env, "GIT_DIR": str(d / ".git")}).gated
        bare = b.root / "bare.git"
        b.git(b.root, "init", "-q", "--bare", str(bare))
        b.git(bare, "remote", "add", "origin", "box:srv/x.git")
        r = b.route(["fetch"], bare)
        assert r.gated and r.repo == str(bare.resolve()) and r.worktree == "", r


def test_aliases_are_resolved_and_a_shell_alias_in_a_gated_repository_is_refused():
    with H.gateway_env() as env:
        b = Box(env)
        gated = b.repo("al", ("origin", WORK))
        plain = b.repo("al2", ("origin", PLAIN))
        for d in (gated, plain):
            b.git(d, "config", "alias.p", "push --force-with-lease")
            b.git(d, "config", "alias.pp", "p origin")
            b.git(d, "config", "alias.sh", "!git push origin && echo done")
            b.git(d, "config", "alias.status", "!echo never")      # git ignores it
            b.git(d, "config", "alias.cl", "clone")
            b.git(d, "config", "alias.wc", "-c remote.origin.url=box:srv/x.git fetch")
        r = b.route(["pp", "main"], plain)
        assert (r.command, r.args, r.alias, r.remote) == ("push", ("--force-with-lease", "origin", "main"),
                                                         "pp", True), r
        r = b.route(["sh"], gated)
        assert r.shell_alias and r.gated and r.refusal == G.SHELL_ALIAS, r
        r = b.route(["SH"], gated)                                  # alias names ignore case
        assert r.refusal == G.SHELL_ALIAS, r
        r = b.route(["sh"], plain)
        assert r.shell_alias and not r.gated and r.refusal == "", r
        r = b.route(["status"], gated)
        assert r.command == "status" and not r.shell_alias and r.refusal == "", r
        # an alias to clone takes its operand like clone
        assert b.route(["cl", WORK], plain).gated
        # an alias's own -c pairs are read
        r = b.route(["wc"], plain)
        assert r.command == "fetch" and _hits(r) == {("hosts", "box")}, r
        # an alias that changes the repository: git refuses it, nothing to resolve
        b.git(plain, "config", "alias.elsewhere", f"-C {gated} status")
        r = b.route(["elsewhere"], plain)
        assert r.command == "" and not r.gated, r


def test_subsection_aliases_and_deprecated_commands_resolve_as_git_2_56_does():
    """git 2.56: `[alias "NAME"] command = ...` is looked up first, its name
    matched case by case, then `alias.NAME` (any case); an alias replaces a
    deprecated command (git --list-cmds=deprecated)."""
    with H.gateway_env() as env:
        b = Box(env)
        gated = b.repo("sal", ("origin", WORK))
        plain = b.repo("sal2", ("origin", PLAIN))
        for d in (gated, plain):
            b.git(d, "config", "alias.cl.command", "clone")
            b.git(d, "config", "alias.sh.command", "!git push origin")
            b.git(d, "config", "alias.Up.command", "!echo up")
            b.git(d, "config", "alias.both", "status")             # plain first ...
            b.git(d, "config", "alias.both.command", "!echo sub")  # ... the subsection wins
            b.git(d, "config", "alias.both2.command", "!echo sub")
            b.git(d, "config", "alias.both2", "status")            # in either order
            b.git(d, "config", "alias.lo.command", "status")
            b.git(d, "config", "alias.LO", "!echo plain")          # git keeps it as alias.lo
            b.git(d, "config", "alias.dotted.name.command", "!echo dotted")
            b.git(d, "config", "alias.status.command", "!echo never")   # git ignores it
            b.git(d, "config", "alias.xx.foo", "!echo never")           # no alias at all
            b.git(d, "config", "alias.whatchanged", "!echo deprecated")
            b.git(d, "config", "alias.pack-redundant.command", "push origin")
        r = b.route(["cl", WORK], plain)
        assert (r.command, r.alias) == ("clone", "cl") and r.gated, r
        for word in ("sh", "Up", "both", "both2", "LO", "dotted.name", "whatchanged"):
            r = b.route([word], gated)
            assert r.shell_alias and r.gated and r.refusal == G.SHELL_ALIAS, (word, r)
            r = b.route([word], plain)
            assert r.shell_alias and not r.gated and r.refusal == "", (word, r)
        # a subsection's name is matched case by case: "up" is no alias, "lo" is
        # the subsection's (not the plain alias.lo that "LO" reaches)
        r = b.route(["up"], gated)
        assert (r.command, r.alias, r.shell_alias, r.refusal) == ("up", "", False, ""), r
        r = b.route(["lo"], gated)
        assert (r.command, r.alias, r.shell_alias, r.refusal) == ("status", "lo", False, ""), r
        for word in ("status", "xx"):
            r = b.route([word], gated)
            assert r.command == word and not r.shell_alias and r.refusal == "", (word, r)
        r = b.route(["pack-redundant"], plain)
        assert (r.command, r.args, r.remote) == ("push", ("origin",), True), r


def test_the_users_own_config_passes_through():
    with H.gateway_env() as env:
        b = Box(env)
        d = b.repo("cfg", ("origin", WORK))
        for argv in (["config", "--global", "user.name", "x"], ["config", "--system", "-l"],
                     ["config", "--file", "/tmp/x", "a.b", "c"], ["config", "-f", "x.cfg", "-l"],
                     ["config", "--file=x.cfg", "-l"], ["config", "set", "--global", "a.b", "c"],
                     ["-c", "x.y=z", "config", "--global", "-l"], ["config", "edit", "--global"],
                     ["config", "--type", "bool", "--global", "a.b", "true"],
                     ["config", "-t", "bool", "--global", "a.b", "true"], ["config", "-zf", "x.cfg", "-l"],
                     ["config", "--glo", "a.b", "c"], ["config", "set", "--g", "a.b", "c"]):
            r = b.route(argv, d)
            assert not r.gated and r.refusal == "", (argv, r)
        b.git(d, "config", "alias.cg", "config --global")
        assert not b.route(["cg", "user.email", "x@example.com"], d).gated
        # after the key every word is a value or a value pattern, never an option
        # (`git config set k --global` writes the repository's own config)
        for argv in (["config", "user.name", "x"], ["config", "--local", "-l"],
                     ["config", "--", "--global"], ["config", "core.sshCommand", "--global"],
                     ["config", "set", "probe.a", "--global"], ["config", "k.v", "x", "--file=/dev/null"],
                     ["config", "--add", "a.b", "--global"], ["config", "set", "--", "a.b", "--global"],
                     ["config", "--comment", "--global", "a.b", "c"],
                     ["config", "--comm", "--global", "a.b", "c"],
                     ["config", "set", "--value", "--global", "a.b", "c"],
                     ["config", "--global", "--no-global", "a.b", "c"],
                     ["config", "--global", "--no-gl", "a.b", "c"],
                     ["config", "--file", "x.cfg", "--no-file", "a.b", "c"],
                     ["config", "-f", "x.cfg", "--no-file", "a.b", "c"]):
            assert b.route(argv, d).gated, argv


# git config writes in each shape, and whether the resolver calls it the
# user's own config (pass-through) or the repository's (gated there)
CONFIG_WRITES = (
    ["config", "probe.a", "v"], ["config", "--global", "probe.a", "v"], ["config", "probe.a", "v", "--global"],
    ["config", "set", "probe.a", "--global"], ["config", "set", "--global", "probe.a", "v"],
    ["config", "--type", "bool", "--global", "probe.a", "true"], ["config", "-t", "bool", "--global", "probe.a", "true"],
    ["config", "--ty", "bool", "--global", "probe.a", "true"], ["config", "--type=bool", "--global", "probe.a", "true"],
    ["config", "--comment", "--global", "probe.a", "v"], ["config", "--comm", "--global", "probe.a", "v"],
    ["config", "set", "--comm", "--global", "probe.a", "v"], ["config", "set", "--value", "--global", "probe.a", "v"],
    ["config", "--glo", "probe.a", "v"], ["config", "set", "--g", "probe.a", "v"],
    ["config", "--no-global", "probe.a", "v"], ["config", "--global", "--no-global", "probe.a", "v"],
    ["config", "--global", "--no-gl", "probe.a", "v"], ["config", "--", "probe.a", "v"],
    ["config", "set", "--", "probe.a", "--global"], ["config", "--add", "probe.a", "--global"],
    ["config", "--file", "x.cfg", "probe.a", "v"], ["config", "-f", "x.cfg", "probe.a", "v"],
    ["config", "-zf", "x.cfg", "probe.a", "v"], ["config", "--file=x.cfg", "probe.a", "v"],
    ["config", "--file", "x.cfg", "--no-file", "probe.a", "v"], ["config", "-f", "x.cfg", "--no-file", "probe.a", "v"],
    ["config", "probe.a", "v", "--file=/dev/null"], ["config", "--replace-all", "probe.a", "v", "--global"],
)


def test_the_config_write_classification_matches_where_git_writes():
    """Each shape is run by the real git in a scratch repository: the
    resolver passes it through exactly when git didn't write the
    repository's own config (shapes git refuses write nothing and are
    skipped)."""
    with H.gateway_env() as env:
        b = Box(env)
        d = b.repo("cfgw", ("origin", WORK))
        checked = 0
        for argv in CONFIG_WRITES:
            local = (d / ".git" / "config").read_text()
            r = subprocess.run([GIT, *argv], cwd=str(d), env=b.env, capture_output=True, text=True,
                               timeout=30)
            wrote_local = (d / ".git" / "config").read_text() != local
            (d / ".git" / "config").write_text(local)
            for extra in (b.home / ".gitconfig", d / "x.cfg"):
                extra.unlink(missing_ok=True)
            if r.returncode != 0:
                continue
            checked += 1
            assert b.route(argv, d).gated == wrote_local, (argv, wrote_local)
        assert checked >= 25, checked


def test_clone_reads_no_repository_so_the_folders_own_config_doesnt_apply():
    """git clone ignores the repository it is run in (its local and worktree
    config, .gitmodules, .lfsconfig, its remotes); the user's global config,
    the command line's and clone's own -c pairs still apply, and an alias to
    clone comes from every scope."""
    with H.gateway_env() as env:
        b = Box(env)
        d = b.repo("cl-local")
        b.git(d, "config", "url.https://x.invalid/.insteadOf", "https://github.com/")
        r = b.route(["clone", WORK], d)
        assert r.gated and _hits(r) == {("accounts", "work")} and r.repo == "" and r.worktree == "", r
        assert r.urls[0].url == WORK, r.urls
        # ls-remote does read it: the rewritten URL reaches nothing configured
        r = b.route(["ls-remote", WORK], d)
        assert not r.gated and r.urls[0].url == "https://x.invalid/example-org/tool.git", r.urls
        b.git(d, "config", "alias.cl", "clone")
        assert b.route(["cl", WORK], d).gated
        b.git(d, "config", "alias.cl2.command", "clone")
        assert b.route(["cl2", WORK], d).gated
        # the worktree's own config too
        w = b.repo("cl-worktree")
        b.git(w, "config", "extensions.worktreeConfig", "true")
        b.git(w, "config", "--worktree", "url.https://x.invalid/.insteadOf", "https://github.com/")
        assert b.route(["ls-remote", WORK], w).urls[0].url.startswith("https://x.invalid/")
        assert b.route(["clone", WORK], w).gated
        # a gated folder doesn't make a clone of something else gated
        g = b.repo("cl-gated", ("origin", WORK))
        (g / ".gitmodules").write_text('[submodule "d"]\n\tpath = d\n\turl = ' + MINE + "\n")
        (g / ".lfsconfig").write_text('[lfs]\n\turl = box:srv/lfs\n')
        assert b.route(["status"], g).gated
        r = b.route(["clone", PLAIN], g)
        assert not r.gated and _hits(r) == set() and r.repo == "", r
        assert not b.route(["-C", str(g), "clone", PLAIN], b.root).gated
        # the command line's -c, the environment's pairs and the user's global config apply
        r = b.route(["-c", "url.https://x.invalid/.insteadOf=https://github.com/", "clone", WORK], d)
        assert not r.gated, r.urls
        env2 = {**b.env, "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "url.https://x.invalid/.insteadOf",
                "GIT_CONFIG_VALUE_0": "https://github.com/"}
        assert not b.route(["clone", WORK], b.root, env=env2).gated
        (b.home / ".gitconfig").write_text('[url "https://x.invalid/"]\n\tinsteadOf = https://github.com/\n')
        assert not b.route(["clone", WORK], d).gated
        assert not b.route(["clone", WORK], b.root).gated


def test_a_disabled_account_whose_kind_is_known_stays_configured_for_every_owner():
    """PLAN-0.11 §1.1: a malformed entry stays configured (its stand-in then
    refuses it). Its kind's own destinations and ssh endpoints count, for
    every owner, since its owners can't be read."""
    with H.gateway_env() as env:
        b = Box(env)
        f = formmod.parse_text('[accounts.hfb]\nkind = "huggingface"\nowners = 7\n')
        assert f.disabled_kinds == {"hfb": "huggingface"} and not f.accounts, f.disabled
        t = G.Targets.from_forms(f)
        for url in ("https://huggingface.co/someone/model", "https://hf.co/datasets/x/y",
                    "git@hf.co:someone/model"):
            r = b.route(["clone", url], targets=t)
            assert r.gated and _hits(r) == {("accounts", "hfb")}, (url, r.urls)
        assert not b.route(["clone", WORK], targets=t).gated
        # beside a valid account of its kind: neither is the only one, and the
        # disabled one covers the owners the valid one doesn't
        f = formmod.parse_text('[accounts.work]\nkind = "github"\nowners = ["example-org"]\n'
                               '[accounts.oops]\nkind = "github"\nlogin = 7\n')
        assert f.disabled_kinds == {"oops": "github"} and list(f.accounts) == ["work"]
        t = G.Targets.from_forms(f)
        assert _hits(b.route(["clone", OTHER], targets=t)) == {("accounts", "oops")}
        assert _hits(b.route(["clone", "git@ssh.github.com:someone-else/x"], targets=t)) == \
            {("accounts", "oops")}
        assert _hits(b.route(["clone", WORK], targets=t)) == {("accounts", "work"), ("accounts", "oops")}
        assert not b.route(["clone", PLAIN], targets=t).gated
        d = b.repo("dis", ("origin", OTHER))
        assert b.route(["status"], d, targets=t).gated


def test_the_remote_helpers_and_dumb_http_take_their_url_as_an_operand():
    with H.gateway_env() as env:
        b = Box(env)
        for argv in (["remote-https", "origin", WORK], ["remote-http", WORK],
                     ["remote-ftp", "origin", "ftp://box.example.net/srv/r"],
                     ["remote-ftps", "origin", "ftps://box.example.net/srv/r"],
                     ["http-fetch", "-a", "--stdin", WORK], ["http-push", "--all", WORK, "main"],
                     ["remote-ext", "origin", "ssh -p 2222 tester@box.example.net %S /srv/r"]):
            r = b.route(argv)
            assert r.gated and r.remote and r.entries(), (argv, r.urls)
        assert _hits(b.route(["remote-ext", "origin", "ssh box.example.net %S r"])) == {("hosts", "box")}
        for argv in (["remote-https", "origin", PLAIN], ["http-fetch", "-a", "HEAD", PLAIN]):
            r = b.route(argv)
            assert not r.gated and r.remote, (argv, r.urls)


def test_a_repository_git_wont_open_is_no_repository_unless_the_user_trusts_it():
    """A repository another user owns: git (the bundled one as the user's)
    opens it only when the user's safe.directory allows it, and otherwise
    treats the folder as no repository, so the user's own git would refuse it
    too. git's GIT_TEST_ASSUME_DIFFERENT_OWNER stands in for another owner."""
    with H.gateway_env() as env:
        b = Box(env)
        d = b.repo("theirs", ("origin", WORK))
        other = {**b.env, "GIT_TEST_ASSUME_DIFFERENT_OWNER": "1"}
        r = b.route(["status"], d, env=other)
        assert not r.gated and r.refusal == "" and r.repo == "" and r.urls == (), r
        assert b.route(["fetch", MINE], d, env=other).gated            # an operand still counts
        (b.home / ".gitconfig").write_text("[safe]\n\tdirectory = *\n")
        r = b.route(["status"], d, env=other)
        assert r.gated and r.repo, r


def test_operands_count_only_for_commands_that_name_a_repository():
    with H.gateway_env() as env:
        b = Box(env)
        d = b.repo("ops", ("origin", PLAIN))
        assert b.route(["push", WORK, "HEAD:main"], d).gated
        assert b.route(["push", "--repo", WORK], d).gated
        assert b.route(["fetch", "--upload-pack=git-upload-pack", MINE], d).gated
        assert b.route(["pull", "box:srv/x.git", "main"], d).gated
        assert b.route(["ls-remote", "--heads", WORK]).gated                # from anywhere
        assert b.route(["remote", "add", "work", WORK], d).gated
        assert b.route(["remote", "set-url", "--push", "origin", MINE], d).gated
        assert b.route(["archive", "--remote", "box:srv/x.git", "HEAD"], d).gated
        assert b.route(["archive", f"--remote={WORK}", "HEAD"], d).gated
        # a URL in a commit message, a tag message or a file name is not an operand
        for argv in (["commit", "-m", f"see {WORK}"], ["tag", "-m", WORK, "v1"],
                     ["add", "box:srv/x.git"], ["archive", "HEAD", WORK]):
            assert not b.route(argv, d).gated, argv
        # a remote's name is not a URL even when it looks like a host
        b.git(d, "remote", "add", "box", PLAIN)
        assert not b.route(["fetch", "box"], d).gated


def test_urls_in_a_route_carry_no_user_or_password():
    with H.gateway_env() as env:
        b = Box(env)
        d = b.repo("tok", ("origin", "https://x-access-token:ghp_canaryCANARYcanary123@github.com/example-org/t"))
        r = b.route(["status"], d)
        assert r.gated and "canary" not in repr(r).lower() and \
            r.urls[0].url == "https://github.com/example-org/t", r.urls
        assert G.shown("https://u:p@h.example.com:8443/a") == "https://h.example.com:8443/a"


def test_an_unreadable_config_is_refused_while_anything_is_configured():
    with H.gateway_env() as env:
        b = Box(env)
        d = b.repo("broken", ("origin", PLAIN))
        with open(d / ".git" / "config", "a") as f:
            f.write("[remote \"x\"\n\turl = \n")                    # a syntax error
        r = b.route(["status"], d)
        assert r.refusal == G.UNREADABLE and not r.gated and r.error, r
        r = b.route(["-C", str(b.root / "missing"), "status"])
        assert r.refusal == G.UNREADABLE, r
        r = b.route(["status"], b.root / "missing")
        assert r.refusal == G.UNREADABLE, r
        # the user's own config writes still pass; nothing configured: nothing to refuse
        assert b.route(["config", "--global", "a.b", "c"], d).refusal == ""
        r = b.route(["status"], d, targets=G.Targets())
        assert r.refusal == "" and not r.gated, r


def test_nothing_configured_reads_nothing():
    """With no configured host or account the resolver runs no git at all
    (the stand-in isn't even on PATH then, §1.2)."""
    with H.gateway_env() as env:
        b = Box(env)
        empty = G.Targets.from_forms(formmod.parse_text("[hosts.localhost]\nsudo = true\n"))
        assert not empty
        r = b.route(["status"], b.root / "missing", targets=empty)
        assert r.refusal == "" and r.error == "" and r.command == "status", r


def test_the_users_includes_and_conditions_are_resolved_by_git():
    with H.gateway_env() as env:
        b = Box(env)
        d = b.repo("inc", ("origin", "work:tool.git"))
        (b.home / "work.inc").write_text('[url "https://github.com/example-org/"]\n\tinsteadOf = work:\n')
        (b.home / ".gitconfig").write_text(
            f'[includeIf "gitdir:{d.resolve()}/"]\n\tpath = {b.home / "work.inc"}\n')
        assert b.route(["status"], d).gated
        other = b.repo("inc2", ("origin", "work:tool.git"))
        assert not b.route(["status"], other).gated


def test_url_parsing_follows_gits_rules():
    P = G.parse_url
    assert P("https://u@GitHub.com:443/o/r").host == "github.com"
    assert (P("ssh://git@[::1]:2222/o").host, P("ssh://git@[::1]:2222/o").port) == ("::1", "2222")
    assert P("git@github.com:o/r.git") == G.Where("scp", "github.com", "", "o/r.git")
    assert P("[::1]:repo").host == "::1" and P("user@[::1]:repo").host == "::1"
    assert P("host:path").host == "host" and P("dir/host:path").scheme == "local"
    assert P("C:\\x").scheme == "local" and P("./a:b").scheme == "local"
    assert P("file:///srv/r").scheme == "local" and P("/srv/r").scheme == "local"
    assert P("persistent-https::https://github.com/o/r").host == "github.com"
    ext = P("ext::ssh -i key git@box.example.net %S r")
    assert ext.scheme == "ext" and "box.example.net" in ext.words and "%s" not in ext.words, ext
    assert P("main:main").host == "main" and P("k=v:x").scheme == "local"
    assert P("a.b=https://github.com/o/r").scheme == "local"      # no valid scheme: not a URL
    assert G._rewrite("gh:o/r", [("https://github.com/", "gh:"), ("x", "g")]) == "https://github.com/o/r"
    assert G._rewrite("abc", [("1", "a"), ("2", "ab"), ("3", "ab")]) == "2c"
    assert G._rewrite("abc", [("1", "z")]) is None
    keep, cmd, rest, bad = G.split_globals(["-C", "d", "-c", "a=b", "--no-pager", "--git-dir=x",
                                            "--namespace", "n", "push", "-f"])
    assert (keep, cmd, rest, bad) == (["-C", "d", "-c", "a=b", "--git-dir=x"], "push", ["-f"], False)
    assert G.split_globals(["--version"])[1] == "version"
    assert G.split_globals(["-C"])[3] is True and G.split_globals(["--bogus", "x"])[3] is True
