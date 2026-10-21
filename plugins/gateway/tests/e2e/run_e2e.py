#!/usr/bin/env python3
"""Headless end-to-end suite for gateway v3 (SPEC 20): `pixi run e2e`.

Not part of `pixi run test`: it runs real `claude -p` sessions (model haiku)
against a scratch COPY of this plugin and local test servers. See
tests/e2e/README.md for the redirection and why it is safe.

    pixi run e2e                        everything (10 short sessions; jobs only with a
                                        checkpoint checkout next to the gateway repo)
    pixi run e2e --only ssh,git         some scenarios (context ssh git web refuse default leak
                                        notice midturn jobs)
    pixi run e2e --keep                 keep the scratch folder (and the transcripts)
    pixi run e2e --save DIR             copy the report, stream-json and debug logs to DIR

Environment: GW_E2E_TMP (base of the scratch folder; default the system temp
folder) and GW_E2E_RUN_BASE (base of the short run dir for unix sockets;
default /tmp). Both must be temp folders.

Outer part (this file run from the checkout): makes the e2e root (0700) under
a temp folder, copies the plugin into it (git-tracked plus untracked
non-ignored files), writes the `e2e-root` marker into the COPY only, runs the
inner part from the copy, then kills what is left and removes the folders.

Inner part (`--inner`, run from the copy): pre-flight (the marker is honoured
by Python and by the sh hooks, every gateway location is inside the e2e root,
none under the real ~/.config/gateway), the copy's pixi env built into the
e2e data folder, the fixtures (sshds with a fake password sudo on the remote
PATH, a smart-HTTP git server with Basic auth, an HTTP API, a fake dialog
that cancels and logs every pop-up), gateway.toml and the vault seeded through
the gateway's own API with fake secrets, then the claude sessions and the
assertions.

The optional `jobs` scenario also needs checkpoint: when a checkpoint
checkout sits next to the gateway repo (../checkpoint/plugins/checkpoint
from the repo root; find_checkpoint), the outer part copies that plugin into
the e2e root too and the session loads both plugins, with CHECKPOINT_HOME and
CHECKPOINT_GATEWAY_ENV set explicitly to folders inside the e2e root
(checkpoint_env) and a watcher that kills the session if checkpoint's MCP
server runs with anything else (server_env_verdict). Without a checkout the
scenario is skipped: the gateway stays self-contained.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
PLUGIN = HERE.parents[1]
SCENARIOS = ("context", "ssh", "git", "web", "refuse", "default", "leak", "notice", "midturn",
             "jobs")
SESSION_TIMEOUT = 90
JOBS_TIMEOUT = 150      # the jobs scenario: ten job steps and a ToolSearch in one session
# the scenarios that wait for Claude Code's "waiting for input" notice (45 s
# of quiet output, then the background command's end) get longer
LONG_TIMEOUT = 210
BUDGET_USD = "0.50"

DRIVER = (
    "You are an end-to-end test driver for a Claude Code plugin, working in a scratch test "
    "folder with local test servers on 127.0.0.1. Do exactly what the user message lists, in "
    "order. Run each shell command exactly as written, character for character, as its own "
    "Bash tool call: never combine, rewrite, quote differently, add flags or add commands. Do "
    "not call ToolSearch. If a step is denied, refused or fails, do not retry it and do not try "
    "anything else instead; go on to the next step. Run every listed step, including one that "
    "only waits, but never add a waiting command of your own (no sleep or timer that isn't a "
    "listed step): background work and subagents notify you when they finish. When every step "
    "is done, reply with the single word DONE.")


def die(msg: str) -> None:
    print(f"e2e: {msg}", file=sys.stderr)
    raise SystemExit(2)


def real_home() -> Path:
    import pwd
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


# ---------------------------------------------------------------------------
# checkpoint, for the optional jobs scenario
# ---------------------------------------------------------------------------

CK_IN_ROOT = Path("ck") / "checkpoint" / "plugins" / "checkpoint"   # matches ancestry's runner path


def find_checkpoint(plugin: Path = PLUGIN) -> Path | None:
    """The checkpoint plugin of a checkpoint checkout next to the gateway repo
    (`../checkpoint/plugins/checkpoint` from the repo root), or None: the jobs
    scenario is then skipped (the gateway never needs checkpoint)."""
    repo = Path(plugin).resolve().parents[1]
    ck = repo.parent / "checkpoint" / "plugins" / "checkpoint"
    if all((ck / f).is_file() for f in ("run.py", ".mcp.json", "pixi.toml")):
        return ck
    return None


def _inside(p: Path, root: Path) -> bool:
    r, rp = Path(root).resolve(), Path(p).resolve()
    return rp == r or r in rp.parents


def checkpoint_env(root: Path) -> dict[str, str]:
    """CHECKPOINT_HOME and CHECKPOINT_GATEWAY_ENV for the jobs session, both
    set explicitly and inside the e2e root: the state folder the gateway looks
    for under its e2e home (paths.checkpoint_state_dir) and the env.sh its
    SessionStart writes there. Unset, checkpoint would use the real state
    folder and source the real ~/.config/gateway/env.sh in jobs. Dies on any
    path that resolves outside the root or into the real gateway home."""
    home = Path(root) / "home" / ".local" / "state" / "checkpoint"
    gw = Path(root) / "home" / ".config" / "gateway" / "env.sh"
    real = real_home() / ".config" / "gateway"        # compared as text: never stat'ed
    for p in (home, gw):
        rp = p.resolve()
        if not _inside(p, root) or rp == real or real in rp.parents:
            die(f"checkpoint's {p.name} would be {rp}, outside the e2e root; refusing to start")
    return {"CHECKPOINT_HOME": str(home), "CHECKPOINT_GATEWAY_ENV": str(gw)}


_ENV_VAR = r"(?:^|\s){}=(\S*)(?=\s|$)"


def server_env_verdict(ps_text: str, gw: str, home: str) -> tuple[bool, str]:
    """Judge one checkpoint MCP server process from its `ps eww` line: True
    only when CHECKPOINT_GATEWAY_ENV is exactly `gw` and CHECKPOINT_HOME is
    exactly `home` (a path with a space can't be read this way: False, and
    the session is stopped)."""
    m = re.search(_ENV_VAR.format("CHECKPOINT_GATEWAY_ENV"), ps_text)
    h = re.search(_ENV_VAR.format("CHECKPOINT_HOME"), ps_text)
    if m is None:
        return False, "CHECKPOINT_GATEWAY_ENV missing"
    if m.group(1) != gw:
        return False, f"CHECKPOINT_GATEWAY_ENV={m.group(1)!r}"
    if h is None or h.group(1) != home:
        return False, f"CHECKPOINT_HOME={h.group(1) if h else None!r}"
    return True, "CHECKPOINT_GATEWAY_ENV and CHECKPOINT_HOME as set"


# ===========================================================================
# Outer part: from the checkout
# ===========================================================================


def plugin_files(src: Path) -> list[str]:
    r = subprocess.run(["git", "-C", str(src), "ls-files", "-z", "-co", "--exclude-standard"],
                       capture_output=True, timeout=60)
    if r.returncode != 0:
        die("git ls-files failed: " + r.stderr.decode(errors="replace")[:300])
    out = []
    for rel in r.stdout.decode().split("\0"):
        if not rel:
            continue
        p = src / rel
        if p.is_file() and not p.is_symlink():
            out.append(rel)
    return sorted(set(out))


def copy_plugin(src: Path, dst: Path) -> int:
    n = 0
    for rel in plugin_files(src):
        if rel == "e2e-root":
            die("the checkout carries an e2e-root marker; remove it")
        d = dst / rel
        d.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src / rel, d)
        n += 1
    return n


def procs_naming(marks: list[str]) -> list[tuple[int, str]]:
    out = subprocess.run(["ps", "-ax", "-o", "pid=,command="], capture_output=True,
                         text=True).stdout
    res = []
    for line in out.splitlines():
        pid, _, cmd = line.strip().partition(" ")
        if pid.isdigit() and int(pid) != os.getpid() and any(m in cmd for m in marks):
            if "ps -ax" in cmd:
                continue
            res.append((int(pid), cmd))
    return res


def kill_naming(marks: list[str]) -> list[str]:
    left = procs_naming(marks)
    for pid, _ in left:
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGTERM)
    if left:
        time.sleep(1)
    for pid, _ in procs_naming(marks):
        with contextlib.suppress(OSError):
            os.kill(pid, signal.SIGKILL)
    return [f"{p} {c[:160]}" for p, c in left]


def outer(a: argparse.Namespace, rest: list[str]) -> int:
    sys.path.insert(0, str(PLUGIN / "src"))
    from gateway import paths   # only its pure checks; nothing resolves the gateway home
    if (PLUGIN / paths.E2E_MARKER).exists():
        die(f"{PLUGIN} carries an e2e-root marker: run the suite from the checkout, and remove it")
    base = Path(a.base or os.environ.get("GW_E2E_TMP") or tempfile.gettempdir()).resolve()
    runbase = Path(a.run_base or os.environ.get("GW_E2E_RUN_BASE") or "/tmp").resolve()
    for what, p in (("GW_E2E_TMP", base), ("GW_E2E_RUN_BASE", runbase)):
        p.mkdir(parents=True, exist_ok=True)
        if not paths._e2e_tmp_ok(str(p) + "/x", paths.E2E_TEMP_ROOTS):
            die(f"{what} ({p}) must be a temp folder (/tmp, /var/tmp, /var/folders)")
    root = Path(tempfile.mkdtemp(prefix="gwe2e-", dir=base)).resolve()
    run = Path(tempfile.mkdtemp(prefix="gwr-", dir=runbase)).resolve()
    for d in (root, run):
        os.chmod(d, 0o700)
    if len(str(run)) > 48:
        die(f"the run dir {run} is too long for unix socket paths; set GW_E2E_RUN_BASE")
    rc = 1
    try:
        n = copy_plugin(PLUGIN, root / "plugin")
        marker = root / "plugin" / paths.E2E_MARKER
        marker.write_text(f"{root}\n{run}\n")
        os.chmod(marker, 0o600)
        assert not (PLUGIN / paths.E2E_MARKER).exists()
        print(f"e2e: root {root}\ne2e: run dir {run}\ne2e: copied {n} plugin files", flush=True)
        ck_arg: list[str] = []
        want = [x for x in (a.only or ",".join(SCENARIOS)).split(",") if x]
        ck_src = find_checkpoint() if "jobs" in want else None
        if ck_src is not None:
            nck = copy_plugin(ck_src, root / CK_IN_ROOT)
            ck_arg = ["--checkpoint", str(root / CK_IN_ROOT)]
            print(f"e2e: copied {nck} checkpoint files from {ck_src} (jobs scenario)", flush=True)
        elif "jobs" in want:
            print("e2e: no checkpoint checkout next to the gateway repo "
                  "(../checkpoint/plugins/checkpoint): the jobs scenario is skipped", flush=True)
        cmd = [sys.executable, "-I", "-S", str(root / "plugin" / "tests" / "e2e" / "run_e2e.py"),
               "--inner", str(root), str(run), *rest, *ck_arg]
        rc = subprocess.call(cmd)
    except KeyboardInterrupt:
        rc = 130
    finally:
        left = kill_naming([str(root), str(run)])
        if left:
            print("e2e: killed leftover processes:\n  " + "\n  ".join(left), flush=True)
        if a.keep:
            print(f"e2e: kept {root} and {run}", flush=True)
        else:
            shutil.rmtree(root, ignore_errors=True)
            shutil.rmtree(run, ignore_errors=True)
            gone = not root.exists() and not run.exists()
            print(f"e2e: scratch folders removed: {gone}", flush=True)
    return rc


# ===========================================================================
# Inner part: from the copy
# ===========================================================================


class E2E:
    def __init__(self, root: Path, run: Path, opts: argparse.Namespace):
        self.root = root
        self.run = run
        self.opts = opts
        self.plugin = root / "plugin"
        self.fx = root / "fixtures"
        self.work = root / "work"
        self.out = root / "out"
        for d in (self.fx, self.work, self.out):
            d.mkdir(parents=True, exist_ok=True)
        self.user = __import__("pwd").getpwuid(os.getuid()).pw_name
        self.sessions: dict[str, Any] = {}
        self.sshds: dict[str, Any] = {}
        self.servers: list[Any] = []
        self.claude = shutil.which("claude") or str(real_home() / ".local" / "bin" / "claude")
        # the checkpoint plugin copied into the root (the jobs scenario), or None
        ck = Path(opts.checkpoint).resolve() if getattr(opts, "checkpoint", "") else None
        if ck is not None and (not _inside(ck, root) or ck != (root / CK_IN_ROOT).resolve()):
            die(f"--checkpoint {ck} isn't the copy inside the e2e root")
        self.ck = ck
        # planted fake secrets (never real ones)
        self.tok_personal = "e2eP" + secrets.token_hex(16)
        self.tok_work = "ghp_" + secrets.token_hex(18)          # a token shape too
        self.api_key = "e2eK" + secrets.token_hex(16)
        self.remote_pw = "e2e-sudo-" + secrets.token_hex(6)
        self.planted_gh = "e2eG" + secrets.token_hex(16)        # GITHUB_TOKEN in Claude's env
        # round 3: a token shape that is no stored value (the leak scenario's
        # PostToolUseFailure warning; expected unmasked there, so not scanned)
        self.leak_shape = "ghp_" + secrets.token_hex(18)
        self.host_keys: dict[str, str] = {}                     # host -> private key text

    # -- pre-flight ---------------------------------------------------------
    def preflight(self, C: Any) -> None:
        from gateway import paths, testing
        root, run = self.root, self.run
        C.add("preflight", "this code runs from the scratch copy",
              paths.code_root() == self.plugin.resolve() and self.plugin.resolve() != PLUGIN_CHECKOUT,
              str(paths.code_root()))
        m = paths.e2e_marker()
        if not C.add("preflight", "Python honours the copy's e2e-root marker", m == (root, run),
                     str(m)):
            die("the marker isn't honoured; refusing to start anything")
        r = subprocess.run(["/bin/sh", str(self.plugin / "hooks" / "launch.sh"), "e2e-root"],
                           capture_output=True, text=True, timeout=30,
                           env={"PATH": "/usr/bin:/bin", "HOME": str(real_home())})
        sh = r.stdout.split("\n")[:2] if r.returncode == 0 else None
        if not C.add("preflight", "the sh hooks (hooks/e2e.sh) agree", sh == [str(root), str(run)],
                     str(sh)):
            die("sh and Python disagree about the marker; refusing to start anything")
        real_gw = real_home() / ".config" / "gateway"
        bad = []
        with paths.e2e_context():
            o = testing.active()
            ok_ctx = o is not None and o.extra.get("e2e") == str(root)
            locs = {}
            for fn in ("home", "user_home", "form_path", "private_dir", "key_path", "vault_path",
                       "pending_dir", "launcher_path", "env_sh_path", "v2_store_path",
                       "data_dir", "bin_dir", "git_config_path", "envs_dir", "audit_path",
                       "run_dir", "env_python"):
                p = Path(getattr(paths, fn)()).resolve()
                locs[fn] = str(p)
                inside = root in p.parents or p == root or run in p.parents or p == run
                if not inside or p == real_gw or real_gw in p.parents:
                    bad.append(f"{fn}={p}")
                testing.guard(p, fn)     # never the real home or the real plugin data folder
        C.add("preflight", "e2e_context is active with the e2e root", ok_ctx)
        if not C.add("preflight", "every gateway location is inside the e2e root (none under "
                     "the real ~/.config/gateway)", not bad, bad or locs):
            die("a location points outside the e2e root; refusing to start anything")

    # -- the copy's pixi env --------------------------------------------------
    def build_env(self, C: Any) -> None:
        from gateway import paths
        decoy = self.root / "decoy-data"
        pixi = shutil.which("pixi") or str(Path(os.environ.get("PIXI_HOME") or
                                                (real_home() / ".pixi")) / "bin" / "pixi")
        env = {"PATH": f"{Path(pixi).parent}:/usr/bin:/bin:/usr/sbin:/sbin",
               "HOME": str(real_home()), "CLAUDE_PLUGIN_DATA": str(decoy),
               "TMPDIR": os.environ.get("TMPDIR", "/tmp")}
        if os.environ.get("PIXI_HOME"):
            env["PIXI_HOME"] = os.environ["PIXI_HOME"]
        t0 = time.time()
        r = subprocess.run(["/bin/sh", str(self.plugin / "hooks" / "launch.sh"), "ensure-env"],
                           capture_output=True, text=True, timeout=900, env=env)
        with paths.e2e_context():
            ready = paths.env_ready()
            envd = paths.env_dir()
        C.add("setup", f"the copy's pixi env is built in the e2e data folder ({time.time() - t0:.0f} s)",
              r.returncode == 0 and ready and self.root in envd.parents and not decoy.exists(),
              {"rc": r.returncode, "stderr": r.stderr[-400:], "env": str(envd),
               "decoy_used": decoy.exists()})
        if not ready:
            die("the pixi env could not be built")

    # -- fixtures -----------------------------------------------------------
    def fixtures(self) -> None:
        import harness as H
        import harness_ssh as HS
        import harness_accounts as HA
        import harness_ux as HU
        from gateway import envfile, paths
        self.H, self.HS, self.HA = H, HS, HA
        for name in ("target", "nosudo", "jump", "behind"):
            self.sshds[name] = HS.Sshd(self.fx, name, sudo_password=self.remote_pw).start()
        t = self.sshds["target"]
        (t.dir / "remote.txt").write_text("e2e remote file\n")
        site = self.work / "site"
        site.mkdir(exist_ok=True)
        (site / "index.html").write_text("<p>e2e site</p>\n")
        euid = self.fx / "remote-euid.sh"
        euid.write_text(HS.REMOTE_EUID)
        os.chmod(euid, 0o755)
        with paths.e2e_context():
            git = envfile.system_git()
        if not git:
            die("no system git")
        self.git = git
        self.gitsrv = HA.GitServer(self.fx / "git", git)
        self.gitsrv.make_repo("e2eorg", "work")
        self.gitsrv.make_repo("e2euser", "proj")
        self.servers.append(self.gitsrv)
        key = self.api_key

        def data(handler: Any, u: Any, body: bytes) -> tuple:
            if handler.headers.get("Authorization") == f"Bearer {key}":
                return 200, {"Content-Type": "application/json"}, json.dumps(
                    {"answer": "e2e-api-data-42"})
            return 401, {"Content-Type": "application/json"}, '{"error": "no key"}'

        def echo(handler: Any, u: Any, body: bytes) -> tuple:
            return 200, {"Content-Type": "application/json"}, json.dumps(
                {"you_sent": handler.headers.get("Authorization", "")})

        self.api = HU.Server({"/data": data, "/echo": echo,
                              "/": (200, {"Content-Type": "text/plain"}, "e2e root")})
        self.servers.append(self.api)
        self.dialog = H.FakeDialog(self.fx / "dialog", [])     # every pop-up: cancelled, logged
        # local sudo: the real /usr/bin/sudo, but only ever as `sudo -n true`
        guard = self.fx / "e2e-sudo"
        guard.write_text("#!/bin/sh\n# e2e: the real sudo only as `sudo -n true` (NOPASSWD probe)\n"
                         'if [ "$#" -eq 2 ] && [ "$1" = -n ] && [ "$2" = true ]; then\n'
                         "  exec /usr/bin/sudo -n true\nfi\n"
                         'echo "e2e-sudo: refusing to run the real sudo with: $*" >&2\nexit 1\n')
        os.chmod(guard, 0o755)
        cfg = {"dialog": str(self.dialog.script), "tools": {"sudo": str(guard)},
               "ssh_remote_euid": str(euid), "machine_id": "E2E-MACHINE-0001",
               "popup_wait": 5, "popup_lifetime": 20, "dialog_timeout": 20}
        p = self.root / "e2e.json"
        p.write_text(json.dumps(cfg, indent=1))
        os.chmod(p, 0o600)
        (self.work / "probe.sh").write_text(PROBE)
        # round 3 (leak): a file holding stored values, and one with a token shape
        (self.work / "notes.txt").write_text(f"api_key={self.api_key}\nsudo_pw={self.remote_pw}\n")
        (self.work / "leak.txt").write_text(f"token={self.leak_shape}\n")

    def form_text(self) -> str:
        s = self.sshds
        u = self.user
        g = self.gitsrv.host
        return f"""# e2e test form (tests/e2e/run_e2e.py): local test servers only
[hosts.localhost]
sudo = true

[hosts.e2ehost]
address = "{u}@127.0.0.1:{s['target'].port}"

[hosts.e2enosudo]
address = "{u}@127.0.0.1:{s['nosudo'].port}"
sudo = false

[hosts.e2ejump]
address = "{u}@127.0.0.1:{s['jump'].port}"

[hosts.e2ebehind]
address = "{u}@127.0.0.1:{s['behind'].port}"
via = "e2ejump"

[hosts.e2eask]
address = "{u}@127.0.0.1:9"
ssh = "ask"

[accounts.e2e-personal]
kind = "github"
login = "e2euser"
host = "{g}"
default = true

[accounts.e2e-work]
kind = "github"
login = "e2e-worker"
host = "{g}"
owners = ["e2eorg"]
name = "E2E Worker"
email = "worker@e2e.invalid"

[accounts.e2eapi]
kind = "api-key"
sites = ["127.0.0.1"]
auth = "bearer"
"""

    def seed(self, C: Any) -> None:
        from gateway import consent, paths, vault
        from gateway import form as formmod
        HS = self.HS
        with paths.e2e_context():
            cfg_ok = paths.e2e_config(self.root).get("dialog") == str(self.dialog.script)
            paths.ensure_home()
            paths.form_path().write_text(self.form_text())
            formmod.clear_cache()
            vault.ensure_key()
            data = vault.empty()
            vault.ensure_machine(data)
            for host, sshd in (("e2ehost", "target"), ("e2enosudo", "nosudo"),
                               ("e2ejump", "jump"), ("e2ebehind", "behind")):
                priv, pub = HS.keypair(self.fx / "keys", host)
                self.host_keys[host] = priv
                self.sshds[sshd].authorize(pub)
                r = vault.host_record(data, host)
                r["keys"].append(vault.key_record(priv, pub))
                r["host_keys"] = [self.sshds[sshd].host_key]
                r["pinned_at"] = vault.now()
            vault.set_sudo(data, "e2ehost", self.user, self.remote_pw)
            for name, tok in (("e2e-personal", self.tok_personal), ("e2e-work", self.tok_work)):
                rec = vault.account_record(data, name, "github")
                rec["token"] = {"value": tok, "source": "pasted", "updated": vault.now(),
                                "stale": False}
            rec = vault.account_record(data, "e2eapi", "api-key")
            rec["token"] = {"value": self.api_key, "source": "pasted", "updated": vault.now(),
                            "stale": False}
            vault.save(data)
            form = formmod.load(use_cache=False)
            consent.approve_all(form)
            eff = consent.compute(form, vault.load())
            problems = [p.render() for p in form.problems]
            rights = {n: (h.ssh, h.sudo) for n, h in eff.hosts.items()}
            dests = {n: list(a.destinations) for n, a in eff.accounts.items()}
            vpath = paths.vault_path()
        C.add("setup", "e2e.json knobs are read (fake dialog, sudo guard, remote euid)", cfg_ok)
        C.add("setup", "gateway.toml validates and every entry is approved and bound",
              not problems and not eff.pending and rights.get("e2ehost") == (True, True)
              and rights.get("e2enosudo") == (True, False) and rights.get("e2eask") == ("ask", True)
              and all(dests.values()) and self.root in vpath.parents,
              {"problems": problems, "rights": rights, "dests": dests})

    # -- claude -------------------------------------------------------------
    def claude_env(self) -> dict[str, str]:
        dirs = [str(Path(self.claude).parent), "/opt/local/bin", "/opt/homebrew/bin",
                "/usr/local/bin", "/usr/bin", "/bin", "/usr/sbin", "/sbin"]
        env = {"HOME": str(real_home()), "USER": self.user, "LOGNAME": self.user,
               "PATH": ":".join(d for d in dict.fromkeys(dirs) if os.path.isdir(d)),
               "LANG": os.environ.get("LANG") or "en_US.UTF-8", "TERM": "dumb",
               "TMPDIR": os.environ.get("TMPDIR") or "/tmp",
               # planted: the env file must unset both in Claude's Bash
               "SSH_AUTH_SOCK": str(self.fx / "no-such-agent.sock"),
               "GITHUB_TOKEN": self.planted_gh,
               # only the plugin's MCP server: none of the account's claude.ai connectors
               "ENABLE_CLAUDEAI_MCP_SERVERS": "false"}
        if os.path.isabs(os.environ.get("CLAUDE_CONFIG_DIR", "")):
            env["CLAUDE_CONFIG_DIR"] = os.environ["CLAUDE_CONFIG_DIR"]
        return env

    def session(self, name: str, prompt: str, mode: str = "auto",
                timeout: float = SESSION_TIMEOUT, plugins: list[Path] | None = None,
                extra_env: dict[str, str] | None = None, driver: str = DRIVER,
                watch: Callable[[], tuple[bool | None, str]] | None = None) -> Any:
        """One `claude -p` session. `plugins`: more --plugin-dir folders (the
        jobs scenario's checkpoint copy); `watch`: polled every 0.1 s while
        the session runs; False kills it at once (s.envcheck says why)."""
        from e2elib import Session, load_events, parse_stream
        sid = str(uuid.uuid4())
        sp, dp, ep = (self.out / f"{name}.jsonl", self.out / f"{name}.debug",
                      self.out / f"{name}.stderr")
        cmd = [self.claude, "-p", "--plugin-dir", str(self.plugin)]
        for extra in plugins or []:
            cmd += ["--plugin-dir", str(extra)]
        cmd += ["--permission-mode", mode,
                "--model", "haiku", "--output-format", "stream-json", "--verbose",
                "--include-hook-events", "--session-id", sid, "--debug-file", str(dp),
                "--max-budget-usd", BUDGET_USD, "--append-system-prompt", driver, prompt]
        env = self.claude_env()
        env.update(extra_env or {})
        t0 = time.time()
        timed_out = False
        envcheck: dict[str, Any] = {"ok": None, "detail": "not watched" if watch is None
                                    else "the watched process was never seen"}
        with open(sp, "wb") as so, open(ep, "wb") as se:
            p = subprocess.Popen(cmd, cwd=str(self.work), env=env, stdout=so,
                                 stderr=se, stdin=subprocess.DEVNULL, start_new_session=True)
            stop = threading.Event()

            def poll() -> None:
                while watch is not None and not stop.is_set() and p.poll() is None:
                    ok, detail = watch()
                    if ok is False:
                        envcheck.update(ok=False, detail=detail)
                        with contextlib.suppress(OSError):
                            os.killpg(p.pid, signal.SIGKILL)
                        return
                    if ok:
                        envcheck.update(ok=True, detail=detail)
                    stop.wait(0.1)
            th = threading.Thread(target=poll, daemon=True)
            th.start()
            try:
                rc = p.wait(timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                with contextlib.suppress(OSError):
                    os.killpg(p.pid, signal.SIGTERM)
                try:
                    rc = p.wait(10)
                except subprocess.TimeoutExpired:
                    with contextlib.suppress(OSError):
                        os.killpg(p.pid, signal.SIGKILL)
                    rc = p.wait(10)
            stop.set()
            th.join(5)
        s = Session(name, sid, mode, rc, timed_out, time.time() - t0, load_events(sp), sp, dp, ep)
        s.limit = timeout
        s.envcheck = envcheck
        parse_stream(s)
        self.sessions[name] = s
        print(f"e2e: session {name} ({mode}) rc={rc} {s.seconds:.0f}s calls={len(s.calls)} "
              f"denials={len(s.denials)}{' TIMEOUT' if timed_out else ''}", flush=True)
        return s

    # -- the audit log and fixtures ------------------------------------------
    def audit(self) -> list[dict[str, Any]]:
        p = self.root / "data" / "audit.jsonl"
        out = []
        try:
            for line in p.read_text().splitlines():
                with contextlib.suppress(ValueError):
                    out.append(json.loads(line))
        except OSError:
            pass
        return out

    def transcripts(self) -> list[Path]:
        cfg = Path(os.environ.get("CLAUDE_CONFIG_DIR") or (real_home() / ".claude"))
        proj = cfg / "projects"
        slug = re.sub(r"[^A-Za-z0-9]", "-", str(self.work))
        out: list[Path] = []
        dirs = [proj / slug] if (proj / slug).is_dir() else []
        if not dirs:   # Claude Code may spell the project folder differently
            dirs = sorted({f.parent for s in self.sessions.values()
                           for f in proj.glob(f"*/{s.sid}.jsonl")})
        for s in self.sessions.values():
            for d in dirs:
                f = d / f"{s.sid}.jsonl"
                if f.exists():
                    out.append(f)
                sub = d / s.sid
                if sub.is_dir():
                    out += [p for p in sub.rglob("*.jsonl")]
        return out

    def cleanup_claude_state(self) -> list[str]:
        """Remove what the e2e sessions left in the Claude config dir: their
        transcripts (only files named after our session ids, in the work
        folder's project dir) and session-env dirs."""
        if self.opts.keep:
            return []
        cfg = Path(os.environ.get("CLAUDE_CONFIG_DIR") or (real_home() / ".claude"))
        slug = re.sub(r"[^A-Za-z0-9]", "-", str(self.work))
        proj = cfg / "projects" / slug
        if not proj.is_dir():
            found = sorted({f.parent for s in self.sessions.values()
                            for f in (cfg / "projects").glob(f"*/{s.sid}.jsonl")})
            if len(found) == 1:
                proj = found[0]
        removed = []
        sids = {s.sid for s in self.sessions.values()}
        for sid in sids:
            for p in (proj / f"{sid}.jsonl", proj / sid, cfg / "session-env" / sid,
                      cfg / "file-history" / sid):
                if p.is_dir() and not p.is_symlink():
                    shutil.rmtree(p, ignore_errors=True)
                    removed.append(str(p))
                elif p.exists():
                    p.unlink()
                    removed.append(str(p))
        # the project folder is named after this run's unique work folder
        # (gwe2e-XXXXXXXX/work), so whatever is left there (an empty auto-memory
        # folder) belongs to these sessions too
        if (proj.is_dir() and not proj.is_symlink()
                and re.sub(r"[^A-Za-z0-9]", "-", self.root.name) in proj.name):
            shutil.rmtree(proj, ignore_errors=True)
            removed.append(str(proj))
        return removed

    def stop(self) -> None:
        HS = getattr(self, "HS", None)
        ssh = None
        if HS is not None:
            ssh = str(HS.ENV_BIN / "ssh")
        for sock in self.run.glob("cm-*"):
            if ssh and not sock.name.endswith((".list", ".lock")):
                with contextlib.suppress(Exception):
                    subprocess.run([ssh, "-F", "/dev/null", "-S", str(sock), "-O", "exit", "x"],
                                   capture_output=True, timeout=10)
        pg: set[int] = set()
        for s in self.sshds.values():
            with contextlib.suppress(OSError):
                pg |= {int(x) for x in s.pgids.read_text().split() if x.strip().isdigit()}
        if pg:
            out = subprocess.run(["ps", "-ax", "-o", "pid=,pgid=,command="], capture_output=True,
                                 text=True).stdout
            for line in out.splitlines():
                parts = line.split(None, 2)
                if len(parts) == 3 and parts[1].isdigit() and int(parts[1]) in pg and (
                        parts[2].startswith("sleep 900") or "mktemp -d" in parts[2]):
                    with contextlib.suppress(OSError):
                        os.kill(int(parts[0]), signal.SIGTERM)
        for s in self.sshds.values():
            with contextlib.suppress(Exception):
                s.stop()
        for srv in self.servers:
            with contextlib.suppress(Exception):
                srv.close()


PLUGIN_CHECKOUT = Path("/nonexistent")   # the checkout (inner() takes it from --checkout)

PROBE = r"""#!/bin/sh
# e2e probe: what Claude's Bash environment looks like (prints no values of
# secret variables, only whether they are set).
tag=${1:-fg}
inc=
n=${GIT_CONFIG_COUNT:-0}
i=0
while [ "$i" -lt "$n" ]; do
  eval "k=\${GIT_CONFIG_KEY_$i-}; v=\${GIT_CONFIG_VALUE_$i-}"
  [ "$k" = include.path ] && inc=$v
  i=$((i + 1))
done
{
  echo "tag=$tag"
  echo "path_first=${PATH%%:*}"
  echo "ssh=$(command -v ssh)"
  echo "sudo=$(command -v sudo)"
  echo "git_include=$inc"
  echo "git_ssh_command=${GIT_SSH_COMMAND-}"
  echo "rsync_rsh=${RSYNC_RSH-}"
  echo "ssh_auth_sock=${SSH_AUTH_SOCK+set}"
  echo "github_token=${GITHUB_TOKEN+set}"
  echo "claude_pid=${CLAUDE_PID+set}"
} > "out-$tag.txt"
cat "out-$tag.txt"
"""


def inner(root: Path, run: Path, opts: argparse.Namespace) -> int:
    global PLUGIN_CHECKOUT
    plugin = root / "plugin"
    if HERE != (plugin / "tests" / "e2e").resolve():
        die("--inner runs only from the scratch copy")
    sys.path[:0] = [str(HERE), str(plugin / "tests"), str(plugin / "src"), str(plugin)]
    import harness  # noqa: F401  (the unit-test guard: no gateway path outside an override)
    from e2elib import Checks
    import scenarios
    C = Checks()
    e = E2E(root, run, opts)
    PLUGIN_CHECKOUT = Path(opts.checkout).resolve() if opts.checkout else Path("/nonexistent")
    only = [x for x in (opts.only or ",".join(SCENARIOS)).split(",") if x]
    try:
        e.preflight(C)
        e.build_env(C)
        e.fixtures()
        e.seed(C)
        scenarios.run_all(e, C, only)
    except SystemExit:
        raise
    except Exception as ex:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        C.add("suite", "the suite ran to the end", False, f"{type(ex).__name__}: {ex}")
    finally:
        try:
            scenarios.final_checks(e, C)
        except Exception as ex:  # noqa: BLE001
            C.add("suite", "final checks ran", False, f"{type(ex).__name__}: {ex}")
        e.stop()
        removed = e.cleanup_claude_state()
        if removed:
            print("e2e: removed the e2e sessions' Claude Code state:\n  " + "\n  ".join(removed))
        C.save(e.out / "report.json")
        print("\n" + C.table(), flush=True)
        if opts.save:
            dst = Path(opts.save)
            dst.mkdir(parents=True, exist_ok=True)
            for f in e.out.iterdir():
                shutil.copy2(f, dst / f.name)
            for name in ("audit.jsonl",):
                src = root / "data" / name
                if src.exists():
                    shutil.copy2(src, dst / name)
            print(f"e2e: report and logs copied to {dst}")
    return 1 if C.failed else 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="run_e2e.py")
    ap.add_argument("--inner", nargs=2, metavar=("ROOT", "RUN"))
    ap.add_argument("--only", default="")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--save", default="")
    ap.add_argument("--base", default="")
    ap.add_argument("--run-base", default="")
    ap.add_argument("--checkout", default="")
    ap.add_argument("--checkpoint", default="")     # set by the outer part only (find_checkpoint)
    a = ap.parse_args(argv)
    if a.inner:
        return inner(Path(a.inner[0]).resolve(), Path(a.inner[1]).resolve(), a)
    rest = []
    for k in ("only", "save"):
        v = getattr(a, k)
        if v:
            rest += [f"--{k}", str(Path(v).resolve()) if k == "save" else v]
    if a.keep:
        rest.append("--keep")
    rest += ["--checkout", str(PLUGIN)]
    return outer(a, rest)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
