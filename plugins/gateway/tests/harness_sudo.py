"""Fixtures for the 'sudo' group (sudo stand-in, gate-askpass, ancestry,
bashparse/hooks_bash). Hermetic; builds real process trees with the phase-A
fake sudo (tests/fakes/fake_sudo.py) reached through testing.override.

Only local, throwaway processes: a python "stand-in driver" that applies
testing.override and runs sudo.main / askpass_main, the fake sudo, and small
shell + python scripts that build the ancestry trees. No real /usr/bin/sudo
password call ever runs.
"""
from __future__ import annotations

import json
import os
import shlex
import subprocess
from pathlib import Path

import harness as H
from gateway import paths

PY = H.PY
SRC = str(H.PLUGIN / "src")
PLUGIN = str(H.PLUGIN)
FAKE_SUDO_PY = str(H.TESTS / "fakes" / "fake_sudo.py")

# ---------------------------------------------------------------------------
# Driver + stub scripts (written into env.root/drivers)
# ---------------------------------------------------------------------------

# (bytecode in the test run's folder, never the plugin's: harness.PYC)
_HEADER = (f"import sys\nsys.pycache_prefix = {H.PYC!r}\n"
           f"sys.path.insert(0, {SRC!r})\nsys.path.insert(0, {PLUGIN!r})\n")

# The sudo stand-in launcher: applies testing.override(ROOT) with the fake sudo
# as the trusted sudo, then runs sudo.main / askpass_main exactly as run.py does.
_DRIVER = _HEADER + """
import os
from gateway import testing, sudo
mode = sys.argv[1]
root = sys.argv[2]
rest = sys.argv[3:]
tools = {}
fs = os.environ.get("GW_FAKE_SUDO")
if fs:
    tools["sudo"] = fs
kw = {}
if os.environ.get("GW_ASKPASS_WAIT"):         # gate-askpass's FIFO deadline (round 3)
    kw["askpass_wait"] = float(os.environ["GW_ASKPASS_WAIT"])
if os.environ.get("GW_FAKE_DIALOG"):          # a fake dialog for the pop-up paths
    kw.update(dialog=os.environ["GW_FAKE_DIALOG"], popup_wait=20, popup_lifetime=30,
              dialog_timeout=30)
with testing.override(root, tools=tools, **kw):
    if mode == "sudo":
        raise SystemExit(sudo.main(rest))
    if mode == "askpass":
        raise SystemExit(sudo.askpass_main())
    raise SystemExit(2)
"""

# An ancestry probe: prints is_direct() as JSON. No override (ancestry reads
# only CLAUDE_PID and the live process tree).
_PROBE = _HEADER + """
import json
from gateway import ancestry
tool = sys.argv[1]
scripts = len(sys.argv) > 2 and sys.argv[2] == "1"
if tool == "typed":                       # the stricter test for an "ask" right
    print(json.dumps(ancestry.typed_by_claude()))
else:
    print(json.dumps(ancestry.is_direct(tool, scripts)))
"""

# "claude": sets CLAUDE_PID to its own pid (or clears it), then runs a shell
# command as a child (kept alive, so its ppid is this process).
_ROOT = """
import os, sys, subprocess
set_pid = sys.argv[1] == "1"
cmd = sys.argv[2]
env = dict(os.environ)
if set_pid:
    env["CLAUDE_PID"] = str(os.getpid())
else:
    env.pop("CLAUDE_PID", None)
r = subprocess.run(["/bin/sh", "-c", cmd], env=env)
sys.exit(r.returncode)
"""

# A python process that only *names* a checkpoint run.py in its argv and runs
# its last argument through sh.
_FAKE_CK = """
import sys, subprocess
sys.exit(subprocess.run(["/bin/sh", "-c", sys.argv[-1] + "; true"]).returncode)
"""

# checkpoint's job wrapper (jobs.WRAPPER), pinned: copied on 2026-10-19 from
# the checkpoint checkout next to this repo,
# ../checkpoint/plugins/checkpoint/src/checkpoint/jobs.py (uncommitted there
# then; its last commit touching jobs.py was 5838751, 2026-10-17). A copy,
# never an import across repos: the gateway's tests stay self-contained.
# Update it when checkpoint's wrapper changes. `/bin/sh -c WRAPPER
# checkpoint-job-ID CMD EXITFILE ENVFILE STATUSFILE`: ENVFILE (the gateway's
# env.sh, or "") is sourced first in a subshell; only if that prints nothing
# on stderr and the shell survives is it sourced for real and STATUSFILE says
# "applied", else "failed" (the job runs without it and says so on stderr).
CHECKPOINT_WRAPPER = """\
checkpoint_cmd=$1 checkpoint_exit=$2
if [ -n "$3" ]; then
  checkpoint_err=$(. "$3" 2>&1 >/dev/null </dev/null; echo checkpoint-ok)
  if [ "$checkpoint_err" = checkpoint-ok ]; then
    . "$3" >/dev/null 2>&1 </dev/null
    echo applied > "$4"
  else
    echo failed > "$4"
    echo "checkpoint: could not apply the gateway environment ($3); the job runs without it." >&2
    checkpoint_err=${checkpoint_err%?checkpoint-ok}
    [ -z "$checkpoint_err" ] || printf '%s\\n' "$checkpoint_err" >&2
  fi
fi
/bin/sh -c "$checkpoint_cmd"; rc=$?; echo $rc > "$checkpoint_exit"; exit $rc
"""

# The checkpoint plugin's job runner as it really starts a job (checkpoint's
# jobs.start): `python …/checkpoint/…/run.py server` (argv exactly that)
# runs `/bin/sh -c CHECKPOINT_WRAPPER checkpoint-job-ID CMD EXITFILE ENVFILE
# STATUSFILE` detached (its own session, stdin /dev/null, output to a log),
# and the wrapper runs CMD with `/bin/sh -c`. The command comes in GW_CK_CMD;
# GW_CK_PID sets the job's CLAUDE_PID: "" none, "parent" this runner's parent
# (a Claude Code above the runner), "self" the runner's own pid (forged).
# GW_CK_ENVFILE: the env file the wrapper sources ("" none; then no status
# file, as checkpoint does). GW_CK_DIRECT=1 skips the wrapper (`/bin/sh -c
# CMD` straight from the runner, which execs a lone command: the runner is
# then the stand-in's parent). Prints the job's log, and the status file's
# word on stderr ("gateway_env: applied").
_CK_JOB = "WRAPPER = " + repr(CHECKPOINT_WRAPPER) + "\n" + """
import os, subprocess, sys, tempfile
cmd = os.environ.pop("GW_CK_CMD")
how = os.environ.pop("GW_CK_PID", "")
direct = os.environ.pop("GW_CK_DIRECT", "") == "1"
envf = os.environ.pop("GW_CK_ENVFILE", "")
env = dict(os.environ)
env.pop("CLAUDE_PID", None)
if how == "parent":
    env["CLAUDE_PID"] = str(os.getppid())
elif how == "self":
    env["CLAUDE_PID"] = str(os.getpid())
d = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
log, exitf = os.path.join(d, "output.log"), os.path.join(d, "exit_code")
status = os.path.join(d, "gateway_env") if envf else ""
with open(log, "ab") as out:
    argv = (["/bin/sh", "-c", cmd] if direct else
            ["/bin/sh", "-c", WRAPPER, "checkpoint-job-probe-20261019-1", cmd, exitf, envf, status])
    p = subprocess.Popen(argv, env=env, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT,
                         start_new_session=True)
    rc = p.wait()
with open(log) as f:
    sys.stdout.write(f.read())
if status:
    try:
        word = open(status).read().strip()
    except OSError:
        word = ""
    sys.stderr.write("gateway_env: " + (word or "-") + "\\n")
sys.exit(rc)
"""

# A make-like python wrapper: runs its argv as a child (so it appears as a
# non-shell intermediate in the tree).
_WRAPPER = """
import sys, subprocess
sys.exit(subprocess.run(sys.argv[1:]).returncode)
"""


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    os.chmod(path, 0o755)
    return path


def write_drivers(env) -> dict[str, Path]:
    d = env.root / "drivers"
    files = {
        "driver": _write(d / "gw_driver.py", _DRIVER),
        "probe": _write(d / "gw_probe.py", _PROBE),
        "root": _write(d / "gw_root.py", _ROOT),
        "wrapper": _write(d / "gw_wrapper.py", _WRAPPER),
    }
    # The checkpoint job runner: same as _ROOT but its path matches
    # `.../checkpoint/.../run.py`, so ancestry recognises it by command line.
    ck = d / "checkpoint" / "plugin"
    files["checkpoint"] = _write(ck / "run.py", _ROOT)
    # The job runner as checkpoint really starts jobs, and the same script at
    # a path that isn't checkpoint's (not recognised: an ordinary program).
    files["ck_job"] = _write(d / "checkpoint" / "plugins" / "checkpoint" / "run.py", _CK_JOB)
    files["job_elsewhere"] = _write(d / "elsewhere" / "run.py", _CK_JOB)
    # The gate-askpass stub that the sudo stand-in sets as SUDO_ASKPASS.
    paths.bin_dir().mkdir(parents=True, exist_ok=True)
    ap = paths.bin_dir() / "gate-askpass"
    ap.write_text(f"#!/bin/sh\nexec {PY!r} -I {str(files['driver'])!r} askpass {str(env.root)!r} "
                  '"$@"\n')
    os.chmod(ap, 0o755)
    files["askpass"] = ap
    return files


def clean_env(env, extra: dict[str, str] | None = None, claude_pid: str | None = "self") -> dict[str, str]:
    """A controlled child environment: no SUDO_*, no inherited CLAUDE_PID unless
    asked. claude_pid='self' marks the child direct (its parent is this test)."""
    e = {
        "PATH": f"{H.ENV_BIN}:/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(env.user_home),
        "TMPDIR": str(env.root / "tmp"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    (env.root / "tmp").mkdir(exist_ok=True)
    if claude_pid == "self":
        e["CLAUDE_PID"] = str(os.getpid())
    elif claude_pid:
        e["CLAUDE_PID"] = claude_pid
    if extra:
        e.update(extra)
    return e


# ---------------------------------------------------------------------------
# Running the sudo stand-in
# ---------------------------------------------------------------------------


def run_sudo(env, fake, *args, input=None, extra_env=None, claude_pid="self",
             timeout=30):
    """Run the sudo stand-in (direct caller by default). `fake` is a FakeSudo."""
    files = write_drivers(env)
    e = clean_env(env, extra_env, claude_pid=claude_pid)
    e["GW_FAKE_SUDO"] = str(fake.path)
    cmd = [PY, "-I", str(files["driver"]), "sudo", str(env.root), *args]
    return subprocess.run(cmd, input=input, capture_output=True, text=True, env=e,
                          timeout=timeout)


def run_sudo_from_shell(env, fake, shell_cmd, *args, input=None, timeout=30):
    """Run the sudo stand-in from a shell command line under a "claude" root
    (CLAUDE_PID = the root): `shell_cmd` holds `{sudo}`, replaced by the
    stand-in's command (e.g. "{sudo} | cat", "/bin/sh -c '{sudo}; true'")."""
    files = write_drivers(env)
    e = clean_env(env, claude_pid=None)
    e["GW_FAKE_SUDO"] = str(fake.path)
    sudo = " ".join(shlex.quote(a) for a in [PY, "-I", str(files["driver"]), "sudo",
                                             str(env.root), *args])
    cmd = [PY, "-I", str(files["root"]), "1", shell_cmd.replace("{sudo}", sudo)]
    return subprocess.run(cmd, input=input, capture_output=True, text=True, env=e,
                          timeout=timeout)


def run_sudo_in_checkpoint_job(env, fake, *args, claude_pid="", timeout=30):
    """Run the sudo stand-in as a checkpoint job's command (checkpoint_job):
    `sudo ARGS` through the runner, its wrapper and `sh -c`."""
    files = write_drivers(env)
    sudo = " ".join(shlex.quote(a) for a in [PY, "-I", str(files["driver"]), "sudo",
                                             str(env.root), *args])
    return checkpoint_job(env, sudo, claude_pid=claude_pid,
                          extra_env={"GW_FAKE_SUDO": str(fake.path)}, timeout=timeout)


def pane_shell(script: str) -> list[str]:
    """argv of a gateway terminal's or job's shell as gated starts it: the
    env's bash, no profile or rc, CLAUDE_PID=$$ exported first (gated's start
    file does that for ancestry's direct rule; terminals.start_text), then
    `script`."""
    return [str(H.ENV_BIN / "bash"), "--noprofile", "--norc", "-c", f"export CLAUDE_PID=$$; {script}"]


def run_sudo_in_pane(env, fake, *args, script=False, timeout=30):
    """Run the sudo stand-in inside a gateway terminal or job (pane_shell):
    started by the pane's shell itself, or (script) by a script it runs."""
    files = write_drivers(env)
    e = clean_env(env, claude_pid=None)
    e["GW_FAKE_SUDO"] = str(fake.path)
    sudo = " ".join(shlex.quote(a) for a in [PY, "-I", str(files["driver"]), "sudo",
                                             str(env.root), *args])
    if script:
        sc = _write(env.root / "drivers" / "gw_pane_sudo.sh", f"#!/bin/sh\n{sudo}\nexit $?\n")
        sudo = f"/bin/sh {shlex.quote(str(sc))}"
    return subprocess.run(pane_shell(f"{sudo}; exit $?"), capture_output=True, text=True, env=e,
                          timeout=timeout)


def run_askpass_direct(env, fifo=None, extra_env=None, timeout=15):
    """Invoke gate-askpass directly from the test (its parent is NOT the real
    sudo), to check the parent-is-sudo refusal."""
    files = write_drivers(env)
    e = clean_env(env, claude_pid=None)
    if fifo is not None:
        e["GW_ASKPASS_FIFO"] = str(fifo)
    if extra_env:
        e.update(extra_env)
    return subprocess.run([str(files["askpass"])], capture_output=True, text=True, env=e,
                          timeout=timeout)


# A caller whose own path contains "fake_sudo", so the askpass's parent check
# (test seam) accepts it exactly as it would the phase-A fake sudo. It isolates
# the euid / SUDO_COMMAND / SUDO_USER refusals from the parent check.
_CALLER = "import subprocess, sys\nsys.exit(subprocess.run([sys.argv[1]]).returncode)\n"


def run_askpass_via_sudo_like_parent(env, fifo, extra_env=None, timeout=15):
    """Invoke gate-askpass from a process that passes the parent-is-sudo check,
    to isolate the SUDO_COMMAND / SUDO_USER refusals."""
    files = write_drivers(env)
    caller = _write(env.root / "drivers" / "gw_fake_sudo_caller.py", _CALLER)
    e = clean_env(env, claude_pid=None)
    e["GW_ASKPASS_FIFO"] = str(fifo)
    if extra_env:
        e.update(extra_env)
    return subprocess.run([PY, "-I", str(caller), str(files["askpass"])],
                          capture_output=True, text=True, env=e, timeout=timeout)


# ---------------------------------------------------------------------------
# Ancestry trees
# ---------------------------------------------------------------------------


def _probe_cmd(files, tool, scripts):
    return f"{PY!r} -I {str(files['probe'])!r} {tool} {'1' if scripts else '0'}"


def checkpoint_job(env, cmd, claude_pid="", runner="ck_job", extra_env=None, timeout=20,
                   direct=False, envfile=""):
    """Run CMD as a checkpoint job (the runner -> /bin/sh -c CHECKPOINT_WRAPPER
    checkpoint-job-ID CMD EXITFILE ENVFILE STATUSFILE -> /bin/sh -c CMD);
    stdout is the job's log, stderr "gateway_env: WORD" when `envfile` is
    given (the file the wrapper sources first). claude_pid: "" (none),
    "parent" or "self"; direct: no wrapper (see _CK_JOB)."""
    files = write_drivers(env)
    e = clean_env(env, extra_env, claude_pid=None)
    e["GW_CK_CMD"] = cmd
    e["GW_CK_PID"] = claude_pid
    e["GW_CK_ENVFILE"] = str(envfile or "")
    if direct:
        e["GW_CK_DIRECT"] = "1"
    return subprocess.run([PY, "-I", str(files[runner]), "server"], capture_output=True,
                          text=True, env=e, timeout=timeout)


# The job shapes for ancestry_tree: (CLAUDE_PID for the job, runner, command).
# The command calls a stand-in-like stub (`sudo` first on PATH: a sh script
# that execs the probe); "-list" keeps `sh -c CMD` in the tree (a lone
# command is exec'd by it, so the wrapper is the stub's parent).
_JOB_SHAPES = {
    "checkpoint-job": ("", "ck_job", "sudo -n true"),
    "checkpoint-job-list": ("", "ck_job", "true; sudo -n true; true"),
    "checkpoint-job-claude": ("parent", "ck_job", "sudo -n true"),
    "checkpoint-job-list-claude": ("parent", "ck_job", "true; sudo -n true; true"),
    "checkpoint-job-forged": ("self", "ck_job", "sudo -n true"),
    "job-elsewhere": ("", "job_elsewhere", "sudo -n true"),
    "checkpoint-runner-forged-direct": ("self", "ck_job", "sudo -n true"),
}


def _job_tree(env, shape, tool, scripts, timeout):
    files = write_drivers(env)
    stub_dir = env.root / "drivers" / "standins"
    _write(stub_dir / "sudo", f"#!/bin/sh\nexec {_probe_cmd(files, tool, scripts)}\n")
    how, runner, cmd = _JOB_SHAPES[shape]
    path = f"{stub_dir}:{clean_env(env)['PATH']}"
    return checkpoint_job(env, cmd, claude_pid=how, runner=runner, extra_env={"PATH": path},
                          timeout=timeout, direct=shape.endswith("-direct"))


def ancestry_tree(env, shape, tool="sudo", scripts=False, timeout=20):
    """Build a process tree and return ancestry.is_direct() from the leaf.

    shape:
      'direct'      claude(CLAUDE_PID) -> sh -> probe
      'wrapper'     claude(CLAUDE_PID) -> sh -> python wrapper -> probe
      'no-pid'      (no CLAUDE_PID)    -> sh -> probe
      'checkpoint'  checkpoint run.py server (no CLAUDE_PID) -> sh -> probe
      'subshell'    claude -> sh -> ( subshell: a fork of sh ) -> probe
      'pipeline'    claude -> sh -> probe | cat
      'sh-c'        claude -> sh -> sh -c '...' (a shell of its own) -> probe
      'script'      claude -> sh -> sh SCRIPT -> probe
      'checkpoint-job'         checkpoint's runner exactly as it starts a job:
                               python …/checkpoint/…/run.py server -> /bin/sh -c
                               CHECKPOINT_WRAPPER checkpoint-job-ID CMD EXITFILE "" ""
                               -> /bin/sh -c CMD -> stand-in stub (sh, exec) -> probe
      'checkpoint-job-list'    the same with `sh -c CMD` kept in the tree
      'checkpoint-job-claude'  the same, CLAUDE_PID = a Claude Code above the runner
      'checkpoint-job-list-claude'  both: `sh -c CMD` kept, CLAUDE_PID above the runner
      'checkpoint-job-forged'  the same, CLAUDE_PID = the runner itself
      'job-elsewhere'          the same runner script at a non-checkpoint path
      'checkpoint-runner-forged-direct'  CLAUDE_PID = the runner, which starts
                               the stand-in itself (`sh -c` execs it; no wrapper)
      'pane'        a gateway terminal's or job's shell as gated starts it (the
                    env's bash, `export CLAUDE_PID=$$` from its start file) -> probe
      'pane-script' the same shell -> sh SCRIPT -> probe
    tool 'typed' probes ancestry.typed_by_claude() instead of is_direct.
    """
    files = write_drivers(env)
    e = clean_env(env, claude_pid=None)
    probe = _probe_cmd(files, tool, scripts)
    if shape in _JOB_SHAPES:
        r = _job_tree(env, shape, tool, scripts, timeout)
        out = r.stdout.strip().splitlines()
        if not out:
            raise AssertionError(f"no probe output: {r.stdout!r} {r.stderr!r}")
        allowed, culprit = json.loads(out[-1])
        return allowed, culprit, r
    if shape == "direct":
        cmd = [PY, "-I", str(files["root"]), "1", probe]
    elif shape == "subshell":
        cmd = [PY, "-I", str(files["root"]), "1", f"( {probe}; true ); true"]
    elif shape == "pipeline":
        cmd = [PY, "-I", str(files["root"]), "1", f"{probe} | cat"]
    elif shape == "sh-c":
        cmd = [PY, "-I", str(files["root"]), "1", f"/bin/sh -c {shlex.quote(probe + '; true')}; true"]
    elif shape == "script":
        sc = _write(env.root / "drivers" / "gw_script.sh", f"#!/bin/sh\n{probe}\ntrue\n")
        cmd = [PY, "-I", str(files["root"]), "1", f"/bin/sh {shlex.quote(str(sc))}; true"]
    elif shape in ("pane", "pane-script"):
        inner = probe
        if shape == "pane-script":
            sc = _write(env.root / "drivers" / "gw_pane_script.sh", f"#!/bin/sh\n{probe}\ntrue\n")
            inner = f"/bin/sh {shlex.quote(str(sc))}"
        cmd = pane_shell(f"{inner}; true")
    elif shape == "wrapper":
        wrapped = f"{PY!r} -I {str(files['wrapper'])!r} {probe}"
        cmd = [PY, "-I", str(files["root"]), "1", wrapped]
    elif shape == "no-pid":
        cmd = [PY, "-I", str(files["root"]), "0", probe]
    elif shape == "checkpoint":
        cmd = [PY, "-I", str(files["checkpoint"]), "server", probe]
    elif shape == "checkpoint-shell":
        # A shell dressed up as the runner: argv[0] is the real run.py path
        # and `server` follows, but the executable is /bin/sh, not python.
        inner = probe + "; true"            # `; true` keeps sh as the parent
        outer = (f"exec -a {shlex.quote(str(files['checkpoint']))} /bin/sh -c "
                 f"{shlex.quote(inner)} server")
        cmd = ["/bin/bash", "-c", outer]
    elif shape == "checkpoint-missing":
        # A python process whose argv names a run.py that doesn't exist.
        fake = _write(env.root / "drivers" / "gw_fake_ck.py", _FAKE_CK)
        cmd = [PY, "-I", str(fake), str(env.root / "nowhere" / "checkpoint" / "p" / "run.py"),
               "server", probe]
    else:
        raise ValueError(shape)
    r = subprocess.run(cmd, capture_output=True, text=True, env=e, timeout=timeout)
    out = r.stdout.strip().splitlines()
    if not out:
        raise AssertionError(f"no probe output: {r.stdout!r} {r.stderr!r}")
    allowed, culprit = json.loads(out[-1])
    return allowed, culprit, r


# ---------------------------------------------------------------------------
# A form + approved vault with localhost sudo on
# ---------------------------------------------------------------------------


def setup_localhost(env, sudo="true", scripts=False, approve=True):
    """Write a form and an approved vault so localhost sudo is `sudo`."""
    from gateway import consent, vault
    lines = ["[hosts.localhost]", f"sudo = {sudo}"]
    if scripts:
        lines.append("scripts = true")
    env.write_form("\n".join(lines) + "\n")
    vault.save(vault.empty())
    if approve:
        consent.approve_all(env.form())
    return env.form()


# ---------------------------------------------------------------------------
# A one-attempt fake sudo (sudoers passwd_tries=1)
# ---------------------------------------------------------------------------

# Like the phase-A fake, but sudo gives up after ONE wrong password, so it
# never calls askpass a second time; it prints only `message` (real sudo:
# "sudo: 1 incorrect password attempt"). Its file name contains "fake_sudo", so
# gate-askpass's test-mode parent check accepts it as the real sudo.
_ONE_TRY = """
import json, os, subprocess, sys
state = sys.argv[1]
args = sys.argv[2:]
cfg = json.load(open(os.path.join(state, "config.json")))
def log(**kw):
    with open(os.path.join(state, "log.jsonl"), "a") as f:
        f.write(json.dumps(kw) + "\\n")
opts = []
i = 0
while i < len(args) and args[i].startswith("-") and args[i] != "-":
    if args[i] == "--":
        i += 1
        break
    if args[i] in ("-u", "-g", "-p"):
        opts.append(args[i]); i += 2; continue
    opts.extend("-" + c for c in args[i][1:])
    i += 1
cmd = args[i:]
if "-n" in opts:
    print("sudo: a password is required", file=sys.stderr)
    log(argv=args, code=1, how="n")
    sys.exit(1)
if "-A" not in opts:
    print("sudo: a terminal is required to read the password", file=sys.stderr)
    log(argv=args, code=1, how="tty")
    sys.exit(1)
r = subprocess.run([os.environ["SUDO_ASKPASS"], "[sudo] password: "], capture_output=True)
pw = r.stdout.decode().splitlines()[0] if r.returncode == 0 and r.stdout else None
if pw != cfg["password"]:
    print(cfg["message"], file=sys.stderr)
    log(argv=args, code=1, how="A", askpass_calls=1, ok=False)
    sys.exit(1)
env = dict(os.environ, SUDO_USER="you", SUDO_COMMAND=" ".join(cmd))
rc = subprocess.run(cmd, env=env).returncode
log(argv=args, code=rc, how="A", askpass_calls=1, ok=True, ran=cmd)
sys.exit(rc)
"""


class OneTryFakeSudo:
    def __init__(self, directory: Path, password: str = "correct horse",
                 message: str = "sudo: 1 incorrect password attempt"):
        directory.mkdir(parents=True, exist_ok=True)
        self.dir = directory
        (directory / "config.json").write_text(json.dumps(
            {"password": password, "message": message}))
        (directory / "log.jsonl").write_text("")
        script = _write(directory / "fake_sudo_1try.py", _ONE_TRY)
        self.path = _write(directory / "sudo", f"#!/bin/sh\nexec {PY!r} -I -S {str(script)!r} "
                                               f"{str(directory)!r} \"$@\"\n")

    def log(self) -> list[dict]:
        return [json.loads(l) for l in (self.dir / "log.jsonl").read_text().splitlines() if l]


def save_local_password(password: str) -> None:
    from gateway import vault
    with vault.edit() as d:
        vault.set_sudo(d, "localhost", paths.local_user(), password)


def local_entry() -> dict | None:
    from gateway import vault
    return vault.sudo_entry(vault.load(), "localhost", paths.local_user())
