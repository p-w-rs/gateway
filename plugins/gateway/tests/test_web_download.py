"""web.download: destination rules (never overwrite, no dotfiles or hidden
folders, no config/ssh/Claude/gateway/plugin folders), no exec bit, sha256,
size limit, credential use."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

import harness as H
import harness_ux as U
from gateway import paths, testing, web

PAYLOAD = b"\x7fELF\x02\x01" + os.urandom(3000)
ROUTES = {"/pkg/file.tar.gz": (200, {"Content-Type": "application/gzip"}, PAYLOAD),
          "/pkg/.env": (200, {}, b"X=1"),
          "/pkg/run.sh": (200, {"Content-Type": "text/x-sh"}, b"#!/bin/sh\necho hi\n"),
          "/missing": (404, {}, b"nope")}


def test_download_into_the_project_with_sha256_and_no_exec_bit():
    with H.gateway_env() as env, U.servers(ROUTES) as (a,):
        proj = env.root / "proj"
        proj.mkdir()
        r = web.download({"url": a.url("/pkg/file.tar.gz")}, cwd=str(proj))
        assert r["ok"], r
        p = proj / "file.tar.gz"
        assert r["path"] == str(p.resolve()) or r["path"] == str(p)
        assert p.read_bytes() == PAYLOAD and r["size"] == len(PAYLOAD)
        assert r["sha256"] == hashlib.sha256(PAYLOAD).hexdigest()
        (proj / "tools").mkdir()
        r = web.download({"url": a.url("/pkg/run.sh"), "save_to": "tools/run.sh"}, cwd=str(proj))
        assert r["ok"] and os.stat(proj / "tools" / "run.sh").st_mode & 0o111 == 0, "never executable"


def test_never_overwrites():
    with H.gateway_env() as env, U.servers(ROUTES) as (a,):
        proj = env.root / "proj"
        proj.mkdir()
        (proj / "file.tar.gz").write_bytes(b"precious")
        r = web.download({"url": a.url("/pkg/file.tar.gz")}, cwd=str(proj))
        assert not r["ok"] and "never overwrites" in r["error"]
        assert (proj / "file.tar.gz").read_bytes() == b"precious"
        os.symlink(proj / "elsewhere", proj / "link.bin")
        r = web.download({"url": a.url("/pkg/file.tar.gz"), "save_to": "link.bin"}, cwd=str(proj))
        assert not r["ok"] and not (proj / "elsewhere").exists(), "a dangling symlink isn't followed"


def test_dotfiles_and_hidden_folders_are_refused():
    with H.gateway_env() as env, U.servers(ROUTES) as (a,):
        proj = env.root / "proj"
        (proj / ".git" / "hooks").mkdir(parents=True)
        for args, frag in [({"url": a.url("/pkg/.env")}, "dotfile"),
                           ({"url": a.url("/pkg/run.sh"), "save_to": ".bashrc"}, "dotfile"),
                           ({"url": a.url("/pkg/run.sh"), "save_to": ".git/hooks/pre-commit"}, "hidden folder"),
                           ({"url": a.url("/pkg/run.sh"), "save_to": "nowhere/x.sh"}, "doesn't exist")]:
            r = web.download(args, cwd=str(proj))
            assert not r["ok"] and frag in r["error"], (args, r)
        assert not (proj / ".git" / "hooks" / "pre-commit").exists()


def test_config_ssh_claude_gateway_and_plugin_folders_are_refused():
    with H.gateway_env(plugin_root=None) as env, U.servers(ROUTES) as (a,):
        h = paths.user_home()
        plug = env.root / "plugin"
        plug.mkdir()
        env.o.plugin_root = plug
        for d in (h / ".ssh", h / ".config" / "x", h / "Library" / "LaunchAgents", paths.home(),
                  env.data, h / ".claude"):
            d.mkdir(parents=True, exist_ok=True)
        targets = [h / ".ssh" / "authorized_keys", h / ".config" / "x" / "y", paths.home() / "z",
                   h / ".claude" / "settings.json"]
        for t in targets:
            r = web.download({"url": a.url("/pkg/run.sh"), "save_to": str(t)}, cwd=str(env.root))
            assert not r["ok"] and not t.exists(), (t, r)
        # not hidden, but still protected
        for t in (h / "Library" / "LaunchAgents" / "evil.plist", env.data / "bin-x", plug / "run.py.new"):
            r = web.download({"url": a.url("/pkg/run.sh"), "save_to": str(t)}, cwd=str(env.root))
            assert not r["ok"] and "refusing to write there" in r["error"] and not t.exists(), (t, r)
        # a symlinked folder that leads into a protected one
        os.symlink(h / "Library" / "LaunchAgents", env.root / "innocent")
        r = web.download({"url": a.url("/pkg/run.sh"), "save_to": str(env.root / "innocent" / "a.plist")},
                         cwd=str(env.root))
        assert not r["ok"] and "refusing to write there" in r["error"]
        r = web.download({"url": a.url("/pkg/run.sh"), "save_to": "~/fine.sh"}, cwd=str(env.root))
        assert r["ok"] and (h / "fine.sh").exists(), "~ is the user's home"


def test_size_limit_and_errors_leave_nothing_behind():
    with H.gateway_env() as env, U.servers(ROUTES) as (a,):
        proj = env.root / "proj"
        proj.mkdir()
        env.o.extra["download_max"] = 100
        r = web.download({"url": a.url("/pkg/file.tar.gz")}, cwd=str(proj))
        assert not r["ok"] and "larger than" in r["error"] and not (proj / "file.tar.gz").exists()
        r = web.download({"url": a.url("/missing")}, cwd=str(proj))
        assert not r["ok"] and "404" in r["error"] and not (proj / "missing").exists()


def test_download_with_an_account_credential():
    token = "download-secret-token-42"
    form = '[accounts.pkg]\nkind = "api-key"\nsites = ["127.0.0.1"]\nauth = "header:X-Token"\n'
    routes = dict(ROUTES)
    routes["/echo.txt"] = lambda h, u, b: (200, {"Content-Type": "text/plain"},
                                           f"tok={h.headers.get('X-Token')}".encode())
    with H.gateway_env() as env, U.servers(routes) as (a,):
        U.setup(env, form)
        U.set_token("pkg", "api-key", token)
        proj = env.root / "proj"
        proj.mkdir()
        r = web.download({"url": a.url("/echo.txt"), "account": "pkg"}, cwd=str(proj))
        assert r["ok"], r
        assert a.rec.last()["headers"]["X-Token"] == token
        assert token not in (proj / "echo.txt").read_text(), "an echoed credential is masked in the file"
        r = web.download({"url": "https://elsewhere.example.com/x", "account": "pkg"}, cwd=str(proj))
        assert not r["ok"] and "goes only to" in r["error"]
        assert token not in json.dumps(r)


def test_downloads_go_only_to_the_project_downloads_or_temp():
    with H.gateway_env() as env, U.servers(ROUTES) as (a,):
        h = paths.user_home()
        proj = env.root / "proj"
        tmpd = env.root / "tmpdir"
        out = env.root / "elsewhere"
        for d in (proj, tmpd, out, h / "Downloads"):
            d.mkdir(parents=True, exist_ok=True)
        env.o.extra["download_temp_roots"] = [str(tmpd)]
        url = a.url("/pkg/file.tar.gz")
        r = web.download({"url": url, "save_to": str(out / "x.tgz")}, cwd=str(proj))
        assert not r["ok"] and "project folder, ~/Downloads or the temp folder" in r["error"], r
        assert not (out / "x.tgz").exists()
        for ok_path in (proj / "a.tgz", h / "Downloads" / "b.tgz", tmpd / "c.tgz"):
            r = web.download({"url": url, "save_to": str(ok_path)}, cwd=str(proj))
            assert r["ok"] and ok_path.exists(), (ok_path, r)
        # the working directory doesn't widen it when it is / (or a folder above the home)
        r = web.download({"url": url, "save_to": str(out / "y.tgz")}, cwd="/")
        assert not r["ok"] and not (out / "y.tgz").exists()
        r = web.download({"url": url, "save_to": str(out / "y.tgz")}, cwd=str(h.parent))
        assert not r["ok"] and not (out / "y.tgz").exists()


def test_files_python_runs_at_startup_are_refused():
    """download is allowed without a prompt in every mode: it must not create
    code that runs by itself (a .pth file, sitecustomize/usercustomize, anything
    in site-packages, anything in ~/Library)."""
    with H.gateway_env() as env, U.servers(ROUTES) as (a,):
        h = paths.user_home()
        proj = env.root / "proj"
        sp = proj / "venv" / "lib" / "python3.12" / "site-packages"
        lib = h / "Library" / "Python" / "3.12" / "lib" / "python" / "site-packages"
        appsup = h / "Library" / "Application Support" / "Foo"
        dp = proj / "usr" / "lib" / "python3" / "dist-packages"
        for d in (sp, lib, appsup, dp):
            d.mkdir(parents=True, exist_ok=True)
        url = a.url("/pkg/run.sh")
        bad = [(proj, "evil.pth"), (proj, "EVIL.PTH"), (proj, "sitecustomize.py"),
               (proj, "usercustomize.py"), (sp, "anything.py"), (dp, "x.txt"), (lib, "x.pth")]
        for d, name in bad:
            r = web.download({"url": url, "save_to": str(d / name)}, cwd=str(proj))
            assert not r["ok"] and "Python runs at startup" in r["error"], (d, name, r)
            assert not (d / name).exists()
        r = web.download({"url": url, "save_to": str(appsup / "notes.txt")}, cwd=str(h))
        assert not r["ok"] and "~/Library" in r["error"] and not (appsup / "notes.txt").exists(), r
        r = web.http({"url": url, "save_to": str(proj / "z.pth")})
        assert not r["ok"] and "Python runs at startup" in r["error"], "http save_to follows the same rules"
        r = web.download({"url": url, "save_to": str(proj / "tool.py")}, cwd=str(proj))
        assert r["ok"], r


def test_a_folder_swapped_for_a_symlink_during_the_request_is_refused():
    """The verifier's race: the destination is checked, then (while the server
    takes its time) a folder on the path is swapped for a symlink into ~/.ssh.
    The file is created inside the folder held open since the check, the folder
    is found moved, and nothing is left anywhere."""
    with H.gateway_env() as env, U.servers(ROUTES) as (a,):
        h = paths.user_home()
        ssh_dir = h / ".ssh"
        ssh_dir.mkdir(parents=True, exist_ok=True)
        proj = env.root / "proj"
        env.o.extra["download_temp_roots"] = [str(env.root)]     # http's save_to has no cwd here
        for tool in ("download", "http"):
            sub = proj / "sub"
            sub.mkdir(parents=True)
            real = web._send

            def racing(*args, **kw):
                os.rename(sub, proj / "sub-old")
                os.symlink(ssh_dir, sub)
                return real(*args, **kw)
            target = sub / "authorized_keys"
            with U.patch(web, "_send", racing):
                if tool == "download":
                    r = web.download({"url": a.url("/pkg/run.sh"), "save_to": str(target)}, cwd=str(proj))
                else:
                    r = web.http({"url": a.url("/pkg/run.sh"), "save_to": str(target)})
            assert not r["ok"] and "changed while the download ran" in r["error"], (tool, r)
            assert not (ssh_dir / "authorized_keys").exists(), f"{tool}: nothing in ~/.ssh"
            assert not (proj / "sub-old" / "authorized_keys").exists(), f"{tool}: nothing kept"
            os.unlink(sub)
            os.rename(proj / "sub-old", proj / f"done-{tool}")


def test_the_folder_walk_never_follows_a_symlink():
    with H.gateway_env() as env:
        real = env.root / "real"
        (real / "inner").mkdir(parents=True)
        os.symlink(real, env.root / "link")
        fd = web.open_dir_nofollow(real.resolve() / "inner")
        os.close(fd)
        for p in (env.root.resolve() / "link" / "inner", env.root.resolve() / "link"):
            try:
                fd = web.open_dir_nofollow(p)
                os.close(fd)
                raise AssertionError(f"followed a symlink: {p}")
            except web.Refused as e:
                assert "changed" in e.message, e.message
        (real / "afile").write_text("x")
        try:
            web.open_dir_nofollow(real.resolve() / "afile")
            raise AssertionError("a file isn't a folder")
        except web.Refused:
            pass


def test_plain_local_path_rules():
    """web.plain_local_path (round 1): where the approval hook lets scp / sftp
    / rsync read or write without a prompt: the download tool's rules, minus
    the new-file ones (existing files are fine), and never the home folder
    itself as a project."""
    with H.gateway_env() as env:
        home = paths.user_home()
        tmpd = env.root / "tmp-root"
        tmpd.mkdir()
        env.o.extra["download_temp_roots"] = [str(tmpd)]   # the home isn't under a temp folder
        proj = home / "code" / "proj"
        (proj / "dist").mkdir(parents=True)
        (proj / "notes.txt").write_text("x")
        (home / "Downloads").mkdir()
        ok = web.plain_local_path
        for p in ("dist/", "notes.txt", ".", "./out/new.bin", str(proj / "dist"),
                  "~/Downloads/x", str(tmpd / "a")):
            assert ok(p, str(proj)), p
        for p in ("~/.ssh/authorized_keys", "~/.bashrc", ".git/hooks/pre-commit",
                  ".claude/settings.json", "~/.claude/settings.json", "~/.config/x",
                  "~/Library/Fonts/x.ttf", "~/Library/LaunchAgents/x.plist", "~/x", "../other",
                  "/etc/x", "lib/site-packages/a.pth", "x.pth", "sitecustomize.py",
                  "~root/x", "", "a\nb"):
            assert not ok(p, str(proj)), p
        # a project inside ~/Library (an iCloud Drive folder, say) is still ~/Library
        lp = home / "Library" / "Mobile Documents" / "proj"
        lp.mkdir(parents=True)
        assert not ok("notes.txt", str(lp))
        # cwd = the home folder: not a project root (~/bin, ~/Documents ...)
        assert not ok("bin/x", str(home)) and not ok("notes.txt", str(home))
        assert ok("Downloads/x", str(home))
        # a symlink in the project pointing into ~/.ssh is judged by its target
        os.symlink(home / ".ssh", proj / "keys")
        assert not ok("keys/authorized_keys", str(proj))
        # the gateway's own folders
        assert not ok(str(paths.home() / "gateway.toml"), str(proj))


def test_plain_local_path_rules_under_a_symlinked_temp_root():
    """PLAN-v4 phase 2 (a phase-1 finding): with the test root behind a
    symlink (macOS keeps temp folders in /var/folders -> /private/var/folders),
    a path spelled through the symlink never matched the project root, which
    was resolved; both sides are resolved now. The refusals still hold, and a
    symlink out of the project is still judged by its target."""
    with H.gateway_env() as env:
        real = env.root / "real-base"
        real.mkdir()
        link = env.root / "link-base"
        link.symlink_to(real)
        with testing.override(root=link / "r", machine_id="TEST-MACHINE-0001"):
            home = paths.user_home()
            assert str(home).startswith(str(link)) and os.path.realpath(home) != str(home)
            tmpd = link / "r" / "tmp-root"
            tmpd.mkdir(parents=True)
            testing.active().extra["download_temp_roots"] = [str(tmpd)]
            proj = home / "code" / "proj"
            (proj / "dist").mkdir(parents=True)
            (proj / "notes.txt").write_text("x")
            (home / "Downloads").mkdir()
            ok = web.plain_local_path
            for p in ("dist/", "notes.txt", ".", "./out/new.bin", str(proj / "dist"),
                      str(Path(os.path.realpath(proj)) / "dist"), "~/Downloads/x",
                      str(tmpd / "a")):
                assert ok(p, str(proj)), p
            # the same, with the working directory spelled resolved
            assert ok("dist/", os.path.realpath(proj)) and ok(str(proj / "notes.txt"),
                                                             os.path.realpath(proj))
            for p in ("~/.ssh/authorized_keys", "~/.bashrc", ".git/hooks/pre-commit", "~/x",
                      "../other", "/etc/x", "x.pth", str(link / "r" / "elsewhere")):
                assert not ok(p, str(proj)), p
            outside = link / "r" / "outside"
            outside.mkdir()
            os.symlink(outside, proj / "out-link")
            assert not ok("out-link/x", str(proj))
            assert not ok("bin/x", str(home))
