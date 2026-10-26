"""Claude's environment (SPEC 7, 18; PLAN-0.11 §1.2, §1.3, §1.8): the env
file, the stand-in stubs and which of them exist, the pass-through to the
user's own tools, the terminal launcher and the generated git include file.

- The env file ($CLAUDE_ENV_FILE, and the same text in ~/.config/gateway/env.sh)
  is static, idempotent, `set -u` safe POSIX sh, written with truncate (Claude
  Code reuses the same file on resume/compact/clear). It puts the present
  stand-ins first on PATH and, in Claude Code's own shell (CLAUDECODE set),
  removes Claude Code's own credential variables and every alias and function
  named after a present stand-in. The user's own agent and token variables
  stay: they are the user's, for the user's own tools. It does nothing once
  $DATA/bin is gone, so other launchers (checkpoint jobs) may source env.sh
  even after the plugin is uninstalled.
- $DATA/bin holds the helpers (gate, git-credential-gateway, gate-askpass) and
  only the stand-ins that can reach something configured (standins_for), as
  tiny sh stubs with absolute paths baked in; each file is replaced
  atomically (write a temp file, rename it over the old one), so the folder
  never goes missing. Its `.gateway-standins` marker tells user_tool (here,
  and a second configuration's gateway) to skip the folder.
- A stand-in that finds its target unconfigured execs the user's own tool
  (pass_through): found on the user's PATH, every stand-in folder skipped,
  with the full argv and the environment unchanged.
- $DATA/git/config holds githelper's URL-scoped helpers (each section clears
  the helpers before it for its own URL only) and the commit identities, and
  $DATA/git/global the gated git's global settings (githelper.GLOBAL_TEXT,
  0444): only the gated git reads them (githelper.gated_env, at command
  scope in its own child); every other git is the user's own, untouched.
- hooks/launch.sh writes the same env file and stubs in sh when the pixi env
  isn't built yet; tests check that both produce identical bytes.
"""
from __future__ import annotations

import contextlib
import glob
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from . import paths, testing

# (shutil is imported where it is used: hooks_post reads MASK_ENV_NAMES from
# here for every response it masks.)

# The user's own credential variables (agents, tokens, cloud keys). Since
# PLAN-0.11 they stay in Claude's shell (the user's, for the user's own
# tools); the output masker masks their values (MASK_ENV_NAMES), and
# [shell] import_env never takes one (form.py).
ENV_UNSET = (
    "SSH_AUTH_SOCK", "SSH_AGENT_PID", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "GIT_ASKPASS",
    "GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
    "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_TOKEN",
    "AZURE_STORAGE_KEY", "AZURE_STORAGE_SAS_TOKEN", "AZURE_STORAGE_CONNECTION_STRING",
    "AZURE_CLIENT_SECRET", "ARM_CLIENT_SECRET", "ARM_ACCESS_KEY",
    "DATABRICKS_TOKEN", "DATABRICKS_CLIENT_SECRET", "DOCKER_AUTH_CONFIG",
    "REGISTRY_AUTH_FILE",
)
# Claude Code's own credential variables (PLAN-0.11 §1.6): never the user's,
# never in Claude's shell (gate-sh drops them and every CLAUDE_* / ANTHROPIC_*
# name with a credential word; the env file unsets these in Claude Code's
# shell). managed.py and hooks/gate-sh hold the same list (a test compares).
CLAUDE_CRED_NAMES = (
    "CLAUDE_CODE_OAUTH_TOKEN", "CLAUDE_CODE_MESSAGING_TOKEN", "CLAUDE_CODE_CLIENT_KEY",
    "CLAUDE_CODE_CLIENT_KEY_PASSPHRASE", "CLAUDE_CODE_CLIENT_CERT", "CLAUDE_CODE_HOST_CREDS_FILE",
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN",
)
# Names in the lists above that hold a socket, a program, a pid, a mode word
# or a file's path, never a secret: masking them would only garble output.
NOT_SECRET_NAMES = ("SSH_AUTH_SOCK", "SSH_AGENT_PID", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE",
                    "GIT_ASKPASS", "REGISTRY_AUTH_FILE", "CLAUDE_CODE_CLIENT_KEY",
                    "CLAUDE_CODE_CLIENT_CERT", "CLAUDE_CODE_HOST_CREDS_FILE")
# The one list of credential variables whose values the output masker hides
# (PLAN-0.11 §1.6): Claude's shell keeps the user's environment, so `env` and
# `printenv` print the user's tokens. It holds the user's own (ENV_UNSET's),
# the usual cloud and service tokens, and Claude Code's own (the managed
# shell removes those, but a file or another tool can still show them), each
# only where it holds a value. hooks_post masks these (and every
# credential-named variable); hooks/post.sh writes the same names out in
# its loop (a test compares); [shell] import_env never takes one (form.py).
MASK_ENV_NAMES = tuple(n for n in dict.fromkeys(ENV_UNSET + (
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "GOOGLE_API_KEY", "GOOGLE_APPLICATION_CREDENTIALS_JSON",
    "OPENAI_API_KEY", "GITLAB_TOKEN", "GL_TOKEN", "CI_JOB_TOKEN", "NPM_TOKEN", "NODE_AUTH_TOKEN",
    "PYPI_TOKEN", "TWINE_PASSWORD", "CARGO_REGISTRY_TOKEN", "CLOUDFLARE_API_TOKEN",
    "DIGITALOCEAN_ACCESS_TOKEN", "HCLOUD_TOKEN", "VAULT_TOKEN", "SLACK_TOKEN", "SLACK_BOT_TOKEN",
    "DOCKER_PASSWORD", "AZURE_DEVOPS_EXT_PAT",
) + CLAUDE_CRED_NAMES) if n not in NOT_SECRET_NAMES)

# The stand-ins (run.py's shims), each present only where it can reach
# something configured (standins_for); the helpers always.
STANDIN_NAMES = ("sudo", "ssh", "scp", "sftp", "git", "gh", "hf", "databricks", "crane", "pijul",
                 "asiml", "az", "dvc")
HELPERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("gate", ("gate",)), ("git-credential-gateway", ("git-credential",)),
    ("gate-askpass", ("askpass",)),
)
# The full base set, in this order (launch.sh has the same list): what the
# cold window writes (launch.sh's pre_session, before any Python can say
# which are needed) whenever something may be configured; Python narrows it.
BASE_STANDINS: tuple[tuple[str, tuple[str, ...]], ...] = tuple(
    (n, ("shim", n)) for n in STANDIN_NAMES) + HELPERS
# In $DATA/bin: user_tool skips every PATH folder that holds it (this
# install's and another configuration's stand-ins).
STANDIN_MARKER = ".gateway-standins"
MARKER_TEXT = "gateway stand-ins: user_tool skips this folder\n"
STILL_SETTING_UP = "gateway: still setting up (first run); try again in a minute"
REAL_SUDO = "/usr/bin/sudo"
KEEP_ENVS_DAYS = 7

# The Bash approval hook's answers while no env can run Python (launch.sh's
# degraded_bash; PLAN-v4 phase 1): one by kind, byte-identical to what
# launch.sh prints (tests compare them). The cold window never switches the
# guard off: private folder, transcripts and credential shapes are refused;
# the network class (PLAN-0.11 §3.4) is asked about, or refused while
# gateway.toml has a [network] table (its value can't be read in sh).
DEGRADED_BASH_HEAD = "gateway: still setting up (first run), so its guard works in a reduced form:"
DEGRADED_BASH_TAIL = ("is refused until setup finishes (about a minute; if it can't finish, the "
                      "session's first gateway message says why).")
DEGRADED_BASH_ASK_TAIL = ("is asked about until setup finishes (about a minute; if it can't "
                          "finish, the session's first gateway message says why).")
DEGRADED_BASH_WHAT = {
    "private": ("anything naming the gateway's private folder, keys or vault (~/.config/gateway "
                "other than gateway.toml)"),
    "transcript": "reading Claude Code's session transcripts",
    "cred": ("running a credential helper, decrypting with age, printing an access token or "
             "passing a token on the command line"),
    "network": "running a network command (curl, wget, nc, nmap, ...)",
    "network_table": ("running a network command (curl, wget, nc, nmap, ...; gateway.toml's "
                      "[network] table can't be read until then)"),
}
# the kinds that ask (the rest deny)
DEGRADED_BASH_ASKS = ("network",)


def degraded_bash_text(kind: str) -> str:
    """launch.sh's hook-bash output (stdout, one line) for KIND while the
    env builds: a deny, or an ask for the network class."""
    asks = kind in DEGRADED_BASH_ASKS
    tail = DEGRADED_BASH_ASK_TAIL if asks else DEGRADED_BASH_TAIL
    reason = f"{DEGRADED_BASH_HEAD} {DEGRADED_BASH_WHAT[kind]} {tail}"
    return ('{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": '
            f'"{"ask" if asks else "deny"}", "permissionDecisionReason": "{reason}"}}}}\n')


def sq(s: str | os.PathLike[str]) -> str:
    """POSIX single-quoting."""
    return "'" + str(s).replace("'", "'\\''") + "'"


# ---------------------------------------------------------------------------
# The env file
# ---------------------------------------------------------------------------


# No EXIT trap or anything else that changes how Claude's commands end: a
# failed command exits with its own code (DECISIONS, "Rolled back"). Its
# output goes to PostToolUseFailure, which can't mask it; hooks_post warns.
#
# Everything after GW_BIN= runs only while the stand-in folder exists, so
# env.sh stays safe for other launchers to source (a checkpoint job, the
# user's terminal) after the plugin is uninstalled or its data deleted: then
# it changes nothing (no PATH entry to a missing folder). POSIX, no `return`
# (it is sourced), nothing that assumes
# Claude's Bash (CLAUDE_PID). The rest only in Claude Code's own shell
# (CLAUDECODE set; PLAN-0.11 §1.8): Claude Code's own credential variables
# unset (names only), and every alias and function named after a present
# stand-in removed, so a snapshot's alias can't skip a stand-in after the
# hook judged the command (each step `|| :`: safe under set -eu in sh, dash,
# bash and zsh). The user's own agent and token variables stay.
ENV_HEADER = ("# gateway: Claude's environment (regenerated at every session start).\n"
              "# Safe to source elsewhere (a checkpoint job, a terminal): it does nothing once\n"
              "# the gateway's stand-in folder is gone.")


def env_text() -> str:
    b = paths.bin_dir()
    # (No git include and no GIT_SSH_COMMAND here since PLAN-0.11 §6: the
    # gated git gets the gateway's settings in its own child, the git
    # stand-in's githelper.gated_env; every other git is the user's own,
    # with the user's own core.sshCommand.)
    body = [
        'case ":${PATH-}:" in *":$GW_BIN:"*) ;; *) PATH="$GW_BIN${PATH:+:$PATH}"; export PATH;; esac',
        'if [ -n "${CLAUDECODE-}" ]; then',
        "  unset " + " ".join(CLAUDE_CRED_NAMES),
        "  for _gw_n in " + " ".join(STANDIN_NAMES) + "; do",
        '    if [ -f "$GW_BIN/$_gw_n" ]; then unalias "$_gw_n" 2>/dev/null || :; '
        'unset -f "$_gw_n" 2>/dev/null || :; fi',
        "  done",
        "  unset _gw_n",
        "fi",
    ]
    lines = [ENV_HEADER, f"GW_BIN={sq(b)}", 'if [ -d "$GW_BIN" ]; then',
             *("  " + line for line in body), "fi"]
    return "\n".join(lines) + "\n"


def write_env_file(path: str | os.PathLike[str], text: str) -> None:
    """Replace the whole file (never append; Claude Code reuses it on resume,
    compact and clear): a temp file renamed over it, so a SessionStart that
    is cancelled or killed meanwhile leaves the old text or the new one,
    never an empty or cut-short file (that would drop the stand-ins and keep
    the user's agent and tokens). Claude Code sources only names like
    sessionstart-hook-N.sh, never the temp file (launch.sh does the same)."""
    _atomic(Path(path), text, 0o644)


def write_env_sh(text: str) -> Path:
    paths.ensure_home()
    p = paths.env_sh_path()
    _atomic(p, text, 0o600)
    return p


def _atomic(p: Path, text: str, mode: int) -> None:
    """Write .NAME.PID.tmp, then rename it over NAME: readers see the old
    text or the new one, never part of it. A temp file a killed writer left
    goes at a later write, once it is an hour old."""
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    os.chmod(tmp, mode)
    os.replace(tmp, p)
    drop_stale_temps(p)


def drop_stale_temps(p: Path) -> None:
    """Remove .NAME.*.tmp files next to `p` older than an hour (a killed
    writer's; a live writer's is seconds old)."""
    now = time.time()
    for t in p.parent.glob(f".{glob.escape(p.name)}.*.tmp"):
        with contextlib.suppress(OSError):
            if now - t.lstat().st_mtime > 3600:
                t.unlink()


# ---------------------------------------------------------------------------
# Stand-in stubs
# ---------------------------------------------------------------------------


def exec_line(args: tuple[str, ...] | list[str]) -> tuple[str, str]:
    """(condition, exec command) for running run.py with args."""
    entry = testing.get("entry")
    tail = " ".join(sq(a) for a in args) + ' "$@"'
    if entry:
        return f"[ -x {sq(entry[0])} ]", "exec " + " ".join(sq(x) for x in entry) + " " + tail
    py = paths.env_python()
    cond = f"[ -x {sq(py)} ] && [ -e {sq(paths.env_dir() / '.ready')} ]"
    return cond, f"exec {sq(py)} {py_flags()} {sq(paths.run_py())} " + tail


def py_flags() -> str:
    """How every gateway process starts its env's Python (launch.sh says the
    same): isolated (-I -S), with the bytecode cache in the data folder, never
    in the plugin folder."""
    return "-I -S -X " + sq(f"pycache_prefix={paths.pycache_dir()}")


_LOCK_PYTHON = re.compile(r"      - conda: .*/python-(\d+\.\d+)\.[^/]*$")
_MINOR_CACHE: dict[tuple[str, int, int], str] = {}


def lock_python_minor(text: str | None = None) -> str:
    """The lock's Python minor ("3.15"): the python package of pixi.lock's
    default environment, one minor on every platform; "" when it can't be
    told (no lock, no python, two minors). launch.sh's lock_py_minor reads
    the same. The plugin's own lock is read once per process (each stub
    written during an update's build asks)."""
    if text is None:
        lock = paths.plugin_root() / "pixi.lock"
        try:
            st = lock.stat()
            key = (str(lock), st.st_mtime_ns, st.st_size)
            if key not in _MINOR_CACHE:
                _MINOR_CACHE[key] = lock_python_minor(lock.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError):
            return ""
        return _MINOR_CACHE[key]
    found: set[str] = set()
    in_envs = in_default = False
    for line in text.splitlines():
        if not line:
            continue
        if not line.startswith(" "):
            if in_envs:
                break
            in_envs = line.rstrip() == "environments:"
            continue
        if not in_envs:
            continue
        if line.startswith("  ") and not line.startswith("   "):
            in_default = line == "  default:"
            continue
        m = _LOCK_PYTHON.match(line) if in_default else None
        if m:
            found.add(m.group(1))
    return found.pop() if len(found) == 1 else ""


def older_env_python() -> Path | None:
    """The python of another finished env this process runs from, when the
    current env (named after pixi.lock) isn't built yet: launch.sh then runs
    the hooks on the newest older env, and the stubs written now fall back to
    it too until the current one is ready. Only on the lock's Python minor:
    new code never runs on the previous Python (PLAN-0.11 section 5), so
    while the new env builds the stubs' cold paths apply instead. None
    otherwise (and in tests)."""
    if testing.get("entry"):
        return None
    exe = Path(sys.executable or "")
    data = paths.data_from_executable(str(exe))
    if data is None or paths.env_ready():
        return None
    try:
        if data.resolve() != paths.data_dir().resolve():
            return None
        envd = exe.parents[4]
        if envd.resolve() == paths.env_dir().resolve() or not (envd / ".ready").exists():
            return None
    except (OSError, IndexError):
        return None
    if f"{sys.version_info[0]}.{sys.version_info[1]}" != lock_python_minor():
        return None
    return exe


def stub_text(name: str, args: tuple[str, ...], comment: str = "gateway stand-in") -> str:
    cond, cmd = exec_line(args)
    lines = ["#!/bin/sh",
             f"# {comment} (regenerated at every session start)",
             f"GW_DATA={sq(paths.data_dir())}; export GW_DATA; unset CLAUDE_PLUGIN_DATA",
             f"if {cond}; then {cmd}; fi"]
    old = older_env_python()
    if old is not None:
        # an update's env is still building: run on the previous one meanwhile
        tail = " ".join(sq(a) for a in args) + ' "$@"'
        lines.append(f"if [ -x {sq(old)} ] && [ -e {sq(old.parents[4] / '.ready')} ]; then "
                     f"exec {sq(old)} {py_flags()} {sq(paths.run_py())} {tail}; fi")
    if name == "sudo":
        lines.append(f'exec {REAL_SUDO} "$@"')
    else:
        if name == "git":
            lines += git_cold_lines()
        lines += [f"echo {sq(STILL_SETTING_UP)} >&2", "exit 75"]
    return "\n".join(lines) + "\n"


USER_TOOL_DIRS = ("/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin", "/usr/bin", "/bin")
# A line of gateway.toml that may start the hosts or accounts table (launch.sh's
# maybe_configured has the same ERE).
CONFIGURED_ERE = r"""^[[:space:]]*\[?\[?[[:space:]]*["']?(hosts|accounts)["']?[[:space:]]*[].=]"""


def git_cold_lines() -> list[str]:
    """The git stub's way while no env can run Python (PLAN-0.11 §6.6), before
    "still setting up": when nothing may be configured (no configured list,
    and no line of gateway.toml that may start the hosts or accounts table:
    launch.sh's cold rule), the user's own git runs, found as user_tool
    finds it (PATH, then USER_TOOL_DIRS; never a folder of stand-ins or this
    plugin's own env; macOS's /usr/bin/git only once the developer tools
    exist). Something configured: still setting up (git status there can't
    be classified without Python). launch.sh writes the same bytes."""
    skip = "|".join(f"{sq(r)}/*" for r in (paths.envs_dir(), paths.plugin_root() / ".pixi"))
    return [
        f"if [ ! -f {sq(paths.configured_path())} ] && ! grep -Eq {sq(CONFIGURED_ERE)} "
        f"{sq(paths.form_path())} 2>/dev/null; then",
        "  _gw_ifs=$IFS; IFS=:; set -f",
        "  for _gw_d in ${PATH-}:" + ":".join(USER_TOOL_DIRS) + "; do",
        "    case $_gw_d in /*) ;; *) continue ;; esac",
        f"    case $_gw_d/ in {skip}) continue ;; esac",
        f'    [ -f "$_gw_d/{STANDIN_MARKER}" ] && continue',
        '    [ -f "$_gw_d/git" ] && [ -x "$_gw_d/git" ] || continue',
        '    if [ "$_gw_d/git" = /usr/bin/git ] && [ -x /usr/bin/xcode-select ] && '
        "! /usr/bin/xcode-select -p >/dev/null 2>&1; then continue; fi",
        '    IFS=$_gw_ifs; set +f; exec "$_gw_d/git" "$@"',
        "  done",
        "  IFS=$_gw_ifs; set +f",
        "fi"]


def _stand_in_folder(d: str, own: str | None) -> bool:
    """A PATH folder of gateway stand-ins: this install's (`own`), or any
    folder with the marker (another configuration's gateway)."""
    try:
        if own and os.path.realpath(d) == os.path.realpath(own):
            return True
    except OSError:
        pass
    return os.path.isfile(os.path.join(d, STANDIN_MARKER))


def own_env_roots() -> tuple[str, ...]:
    """This plugin's own pixi env folders (its data folder's envs, and the
    plugin folder's `.pixi` in a developer checkout): their tools are the
    gateway's, never the user's own. Anyone else's `.pixi` (`pixi global`'s
    ~/.pixi/bin, a project's env) is the user's."""
    out = []
    for f in (paths.envs_dir, lambda: paths.plugin_root() / ".pixi"):
        try:
            out.append(str(f()))
        except (OSError, paths.PathError):
            continue
    return tuple(out)


def _under(d: str, roots: tuple[str, ...]) -> bool:
    """Is folder d (resolved) one of `roots` (already resolved) or inside one?"""
    try:
        rd = os.path.realpath(d)
    except OSError:
        return False
    return any(rd == r or rd.startswith(r.rstrip("/") + "/") for r in roots)


def find_on_path(name: str, path_value: str, own: str | None = None,
                 extra: tuple[str, ...] = USER_TOOL_DIRS,
                 skip: tuple[str, ...] | None = None) -> str | None:
    """The first executable `name` on `path_value` (absolute folders only),
    then in `extra`, skipping every folder of gateway stand-ins (`own`, and
    any with the marker) and every folder under `skip` (by default this
    plugin's own pixi envs, own_env_roots; compared by resolved path); on
    macOS /usr/bin/git counts only once the developer tools exist."""
    if skip is None:
        skip = own_env_roots()
    try:
        skip = tuple(os.path.realpath(r) for r in skip)
    except OSError:
        pass
    dirs = [d for d in path_value.split(os.pathsep) if d and os.path.isabs(d)]
    dirs += list(extra)
    for d in dict.fromkeys(dirs):
        if _stand_in_folder(d, own) or _under(d, skip):
            continue
        c = Path(d) / name
        if c.is_file() and os.access(c, os.X_OK):
            if name == "git" and str(c) == "/usr/bin/git" and os.path.exists("/usr/bin/xcode-select"):
                try:  # macOS: /usr/bin/git is a stub until the developer tools exist
                    r = subprocess.run(["/usr/bin/xcode-select", "-p"], capture_output=True,
                                       timeout=5, stdin=subprocess.DEVNULL)
                    if r.returncode != 0:
                        continue
                except (OSError, subprocess.TimeoutExpired):
                    continue
            return str(c)
    return None


def user_tool(name: str) -> str | None:
    """The user's own `name` (PLAN-0.11 §1.3), or None: the first executable
    file of that name on this process's PATH, skipping every folder of
    gateway stand-ins (_stand_in_folder) and this plugin's own pixi env
    folders (own_env_roots; `pixi global`'s ~/.pixi/bin is the user's), then
    the usual folders (USER_TOOL_DIRS). On macOS
    /usr/bin/git counts only once the developer tools exist (xcode-select).
    One rule for every tool, ssh included (the user's own Homebrew ssh is
    theirs). Under a test override only the `user_tools` knob's folder of
    fakes (git without that knob: the `system_git` knob, "pretend there is
    one", for the readers of a repository's remote: clis)."""
    if testing.active() is not None:
        folder = testing.get("user_tools")
        if not folder and name == "git" and testing.get("system_git") is not None:
            return "/usr/bin/git" if testing.get("system_git") else None
        if not folder:
            return None
        c = Path(folder) / name
        return str(c) if c.is_file() and os.access(c, os.X_OK) else None
    try:
        own: str | None = str(paths.bin_dir())
    except paths.PathError:
        own = None
    return find_on_path(name, os.environ.get("PATH", ""), own)


# ---------------------------------------------------------------------------
# Pass-through (PLAN-0.11 §1.3): a stand-in whose target isn't configured
# execs the user's own tool with the full argv and the environment unchanged
# ---------------------------------------------------------------------------

PASSTHRU_VAR = "GW_PASSTHRU"
# a loop: the same tool reached again with the same arguments, or this deep
# (a wrapper on PATH that calls the tool by name again, changing them)
PASSTHRU_MAX = 6
LOOP = ("gateway: {tool} on your PATH calls the gateway's stand-in again (a loop); run it by its "
        "full path.")
NOT_INSTALLED = ("gateway: {tool} isn't installed here. The gateway handles {tool} only for "
                 "{entries}.")
# the one exec (tests replace it to run a stand-in in-process)
_execve = os.execve


def _argv_digest(tool: str, argv: list[str]) -> str:
    import hashlib
    h = hashlib.sha256("\0".join([tool, *argv]).encode("utf-8", "surrogateescape"))
    return h.hexdigest()[:12]


def _passthru_state(tool: str) -> tuple[int, str]:
    """(depth, argv digest) GW_PASSTHRU says for `tool`: 0 when it names
    another tool (a nested ssh that the user's git or scp started is that
    ssh's own business) or nothing readable."""
    v = os.environ.get(PASSTHRU_VAR, "")
    t, _, rest = v.partition(":")
    n, _, digest = rest.partition(":")
    if t != tool or not n.isdigit():
        return 0, ""
    return int(n), digest


def pass_through(tool: str, argv: list[str], target: str | None = None,
                 entries: list[str] | None = None, log: bool = True) -> int:
    """Exec the user's own `tool` (user_tool) with `argv`, the environment
    unchanged but GW_PASSTHRU=<tool>:<depth>:<argv digest> (the recursion
    guard: the stand-in reached again for the same tool with the same
    arguments, or PASSTHRU_MAX deep, refuses; it never lets a configured
    target through, since every stand-in classifies before it gets here).
    argv[0] is the tool's absolute path, so a tool that runs itself again by
    its argv[0] (ssh's ProxyJump) runs the user's own, not the stand-in.
    One `passthrough` audit line: the tool and a validated host or owner
    name (`target`, else "-"), never argv; none when `log` is False (git's
    commands that touch no remote: `git status` writes nothing to the
    shared audit log, PLAN-0.11 §1.3). Returns only when it can't run:
    2 for a loop, 127 when the tool isn't installed (`entries`: what the
    gateway handles it for)."""
    from . import audit
    from . import form as formmod
    depth, digest = _passthru_state(tool)
    mine = _argv_digest(tool, argv)
    if depth >= 1 and (digest == mine or depth >= PASSTHRU_MAX):
        msg = LOOP.format(tool=tool)
        print(msg, file=sys.stderr, flush=True)
        with contextlib.suppress(Exception):
            from . import modes
            audit.refusal(tool, formmod.safe(target or "") or None, msg,
                          mode=modes.standin_audit_mode({}))
        return 2
    real = user_tool(tool)
    if real is None:
        shown = ", ".join(entries or []) or "the hosts and accounts in gateway.toml"
        print(NOT_INSTALLED.format(tool=tool, entries=shown), file=sys.stderr, flush=True)
        return 127
    if log:
        with contextlib.suppress(Exception):
            audit.log("passthrough", tool=tool, target=formmod.safe(target or "") or "-")
    env = dict(os.environ)
    env[PASSTHRU_VAR] = f"{tool}:{depth + 1}:{mine}"
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        _execve(real, [real, *argv], env)
    except OSError as e:
        print(f"gateway: couldn't run your own {tool} ({type(e).__name__})", file=sys.stderr)
        return 126
    return 0  # pragma: no cover - execve doesn't return


# ---------------------------------------------------------------------------
# Which stand-ins exist (PLAN-0.11 §1.2)
# ---------------------------------------------------------------------------

_SSH_KINDS = ("github", "huggingface", "pijul")
_GIT_KINDS = ("github", "huggingface")


def standins_for(eff: Any) -> list[str]:
    """The stand-ins that can reach something in the configured set
    (consent.Effective.configured), in STANDIN_NAMES order: ssh, scp and sftp
    for a host other than this computer or an account with an ssh endpoint;
    git for a host other than this computer or a git account (github,
    huggingface; PLAN-0.11 §6.1); sudo for this computer's configured sudo
    or an elevation restriction here; gh, hf, pijul for an account of that
    kind; az, databricks and crane
    for an azure account (crane also for a github account with packages and a
    registry account); asiml and dvc for an ml-catalog account. A disabled
    entry counts (its stand-in refuses it); an entry only the approval or the
    configured list names counts too. Wider than needed is safe (an
    unconfigured target passes through), narrower never."""
    c = getattr(eff, "configured", None)
    if c is None:
        return []
    out: set[str] = set()
    reaches = list(c.reaches())
    kinds = {r.kind for r in reaches}
    if c.hosts or any(r.ssh_hosts for r in reaches) or kinds & set(_SSH_KINDS):
        out |= {"ssh", "scp", "sftp"}
    if c.hosts or kinds & set(_GIT_KINDS):
        out.add("git")
    if c.localhost_sudo or c.local_elevation:
        out.add("sudo")
    if "github" in kinds:
        out.add("gh")
    if "huggingface" in kinds:
        out.add("hf")
    if "pijul" in kinds:
        out.add("pijul")
    if "azure" in kinds:
        out |= {"az", "databricks", "crane"}
    if "registry" in kinds or any(r.kind == "github" and "ghcr.io" in r.destinations
                                  for r in reaches):
        out.add("crane")
    if "ml-catalog" in kinds:
        out |= {"asiml", "dvc"}
    return [n for n in STANDIN_NAMES if n in out]


def stand_ins(form: Any = None, eff: Any = None) -> dict[str, str]:
    """{file name: stub text}: the helpers and the stand-ins standins_for
    names for `eff` (None: the full base set, as the cold window writes it)."""
    names = [n for n, _a in BASE_STANDINS[:len(STANDIN_NAMES)]] if eff is None \
        else standins_for(eff)
    out = {n: stub_text(n, ("shim", n)) for n in names}
    for n, args in HELPERS:
        out[n] = stub_text(n, args)
    return out


def present_standins() -> set[str]:
    """The stand-in names $DATA/bin holds now."""
    try:
        return {p.name for p in paths.bin_dir().iterdir() if p.name in STANDIN_NAMES}
    except (OSError, paths.PathError):
        return set()


def sync_standins(form: Any, eff: Any) -> bool:
    """Bring $DATA/bin's stand-ins to the ones the configured set needs
    (PLAN-0.11 §1.2: every process that loads the form and sees the
    configured set change: SessionStart, the Bash hook, FileChanged,
    PostToolUse after an edit of gateway.toml, consent's approve): the
    missing ones written, the ones nothing needs any more removed, a missing
    helper or marker written. Nothing else there is touched (SessionStart
    rewrites the whole folder). True when it wrote. Never raises."""
    try:
        want = set(standins_for(eff))
        have = present_standins()
        b = paths.bin_dir()
        helpers = [n for n, _a in HELPERS if not (b / n).exists()]
        if want == have and not helpers and (b / STANDIN_MARKER).is_file():
            return False
        stubs = stand_ins(form, eff)
        _write_stub_files({n: t for n, t in stubs.items()
                           if (n in want and n not in have) or n in helpers})
        for n in sorted(have - want):
            with contextlib.suppress(OSError):
                (b / n).unlink()
        return True
    except Exception:  # noqa: BLE001 - the next session start writes them anyway
        return False


def write_stubs(stubs: dict[str, str]) -> Path:
    """Replace each stub in $DATA/bin atomically (write .NAME.tmp.PID, then
    rename over NAME), then remove names that are no longer generated (a
    stand-in nothing configured needs: its name then finds the user's own
    tool). The folder itself is never moved, so a command running meanwhile
    always finds either the old or the new stub, never no stub. The marker
    (STANDIN_MARKER) stays."""
    d = paths.data_dir()
    final = _write_stub_files(stubs)
    now = time.time()
    for p in final.iterdir():
        with contextlib.suppress(OSError):
            if p.name == STANDIN_MARKER:
                continue
            if p.name.startswith("."):
                if now - p.lstat().st_mtime > 3600:   # a crashed writer's temp file
                    p.unlink()
            elif p.name not in stubs:
                p.unlink()
    for stale in list(d.glob("bin.new.*")) + list(d.glob("bin.old.*")):  # the old layout
        import shutil
        shutil.rmtree(stale, ignore_errors=True)
    return final


def _write_stub_files(stubs: dict[str, str]) -> Path:
    """Write each stub into $DATA/bin atomically (.NAME.tmp.PID, then rename
    over NAME), and the marker; the folder itself is made, never moved."""
    d = paths.data_dir()
    d.mkdir(parents=True, exist_ok=True)
    final = paths.bin_dir()
    if final.is_symlink() or (final.exists() and not final.is_dir()):
        final.unlink()
    final.mkdir(mode=0o755, exist_ok=True)
    os.chmod(final, 0o755)
    for name, text in stubs.items():
        if "/" in name or name.startswith("."):
            continue
        tmp = final / f".{name}.tmp.{os.getpid()}"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o755)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.chmod(tmp, 0o755)
        os.replace(tmp, final / name)
    marker = final / STANDIN_MARKER
    with contextlib.suppress(OSError):
        if not marker.is_file() or marker.read_text() != MARKER_TEXT:
            _atomic(marker, MARKER_TEXT, 0o644)
    return final


# ---------------------------------------------------------------------------
# The terminal launcher (~/.config/gateway/gate)
# ---------------------------------------------------------------------------


LAUNCHER_GONE = ("gateway: this launcher points at a gateway plugin that isn't there any more "
                 "(uninstalled, or updated since the last Claude Code session); start a Claude "
                 "Code session with the plugin to renew it, or delete ~/.config/gateway/gate if "
                 "you uninstalled the gateway")


LAUNCHER_NOPIXI = ("gateway: pixi isn't installed, so the gateway can't set itself up; install it "
                   "from https://pixi.sh and start a new Claude Code session")
# launch.sh's .pixi-too-old (written when pixi refused the manifest's
# requires-pixi): found= and needed= lines.
PIXI_TOO_OLD_FILE = ".pixi-too-old"


def pixi_too_old_words() -> str:
    """launch.sh's GW_TOOOLD for the current env's .pixi-too-old: "pixi
    0.81.0 is too old (the gateway needs pixi >=0.83.0)"."""
    vals = {"found": "", "needed": ""}
    try:
        for line in (paths.env_dir() / PIXI_TOO_OLD_FILE).read_text().splitlines():
            k, _, v = line.partition("=")
            if k in vals:
                vals[k] = v
    except OSError:
        pass
    words = f"pixi {vals['found']} is too old" if vals["found"] else "this pixi is too old"
    return words + (f" (the gateway needs pixi {vals['needed']})" if vals["needed"] else "")


def pixi_too_old_note() -> str:
    """`gate status`'s line while the current env can't be built because pixi
    refused the manifest, or "": the env isn't ready and its last build failed
    on that refusal (launch.sh's .pixi-too-old beside its install.log, and no
    build holds the lock; a build removes the record when it starts). With an
    older env on the lock's Python minor the hooks and `gate` keep running on
    it, so with mods off this is where the user learns why the update waits."""
    envd = paths.env_dir()
    if paths.env_ready() or not (envd / PIXI_TOO_OLD_FILE).is_file() \
            or not (envd / "install.log").is_file() or (envd.parent / (envd.name + ".building")).exists():
        return ""
    return (f"Environment: can't be set up: {pixi_too_old_words()}; update pixi ({PIXI_UPDATE}), "
            "then start a new session")


# How pixi is updated (lib.ts's PIXI_UPDATE, launch.sh's GW_PIXI_UPDATE): pixi
# self-update refuses a Homebrew or MacPorts pixi. (launcher_not_ready's text
# is launch.sh's, byte for byte; launch.sh's other not-ready texts and
# gate-sh's notice give the same advice.)
PIXI_UPDATE = "pixi self-update, or your package manager for a Homebrew or MacPorts pixi"


def launcher_failed(log: Path | str) -> str:
    return f"gateway: the gateway's setup failed (log: {log}); start a new Claude Code session to retry"


def launcher_not_ready(state: str = "building") -> str:
    """What the launcher says until the env is ready, by launch.sh's states:
    building, nopixi (pixi missing), pixiold (the build failed on pixi's
    "requires pixi" refusal) or failed (the build left its log). It is the
    user's own helper, so it speaks to the user (review round 4: in the
    pixi-missing and failed states it repeated the text written for Claude,
    "... tell the user")."""
    if state == "nopixi":
        return LAUNCHER_NOPIXI
    if state == "pixiold":
        return (f"gateway: the gateway can't set itself up: {pixi_too_old_words()}; update pixi "
                f"({PIXI_UPDATE}), then start a new Claude Code session")
    if state == "failed":
        return launcher_failed(paths.env_dir() / "install.log")
    return STILL_SETTING_UP


def launcher_text(state: str = "building") -> str:
    """~/.config/gateway/gate. launch.sh writes the same bytes while the env
    builds, in each of its states (round 3: the first session had no
    launcher, though no-screen messages name it); once the plugin is gone it
    says so instead of "still setting up" forever."""
    cond, cmd = exec_line(("gate",))
    return ("#!/bin/sh\n"
            "# The gateway's helper for your own terminal (regenerated at every Claude Code\n"
            "# session start). Try: ~/.config/gateway/gate status   or   gate log\n"
            f"GW_DATA={sq(paths.data_dir())}; export GW_DATA; unset CLAUDE_PLUGIN_DATA\n"
            f"if {cond}; then {cmd}; fi\n"
            f"if [ ! -f {sq(paths.run_py())} ]; then echo {sq(LAUNCHER_GONE)} >&2; exit 1; fi\n"
            f"echo {sq(launcher_not_ready(state))} >&2\nexit 75\n")


def write_launcher() -> Path:
    paths.ensure_home()
    p = paths.launcher_path()
    _atomic(p, launcher_text(), 0o700)
    return p


# ---------------------------------------------------------------------------
# git include file
# ---------------------------------------------------------------------------


def git_config_text(helper_text: str = "") -> str:
    """The include file: githelper's URL-scoped helpers and identities. Each
    credential section clears the helpers before it for its own URL only
    (`helper =` first), so the user's own keychain helper never answers for
    a configured account's host and keeps serving every other remote
    (PLAN-0.11: unconfigured remotes are the user's own)."""
    return helper_text or ""


def write_git_config(form: Any, vault_meta: dict[str, Any]) -> Path | None:
    """$DATA/git/config: githelper.include_config's text, plus its identity
    files. Written when there is any text; an empty result removes a stale
    file (git ignores an include that isn't there)."""
    from . import githelper
    try:
        helper = githelper.include_config(form, vault_meta) or ""
    except NotImplementedError:
        helper = ""
    text = git_config_text(helper)
    try:
        idents = githelper.identity_files(form) or {}
    except NotImplementedError:
        idents = {}
    gd = paths.git_dir()
    for name, content in idents.items():
        if "/" in name or name.startswith("."):
            continue
        _atomic(gd / name, content, 0o644)
    p = paths.git_config_path()
    if not text:
        with contextlib.suppress(FileNotFoundError):
            p.unlink()
        return None
    _atomic(p, text, 0o644)
    return p


# ---------------------------------------------------------------------------
# Everything at once (SessionStart)
# ---------------------------------------------------------------------------


def sync(form: Any, eff: Any, vault_meta: dict[str, Any] | None,
         env_file: str | None, *, vault_readable: bool = True) -> dict[str, Any]:
    """Write the env file, env.sh, stubs, git config, the gated git's global
    config, launcher and the managed shell's files (managed.py). The stubs
    are the ones the configured set needs (standins_for; all of them while
    `eff` is None). Each step is independent; failures are collected (no
    secrets in messages)."""
    from . import githelper
    text = env_text()
    done: dict[str, Any] = {"errors": []}
    steps = [
        ("env_file", lambda: write_env_file(env_file, text) if env_file else None),
        ("env_sh", lambda: write_env_sh(text)),
        ("stubs", lambda: write_stubs(stand_ins(form, eff))),
        ("git_config", lambda: write_git_config(form, vault_meta or {})),
        ("git_global", githelper.write_global),
        ("launcher", write_launcher),
    ]
    for name, fn in steps:
        try:
            done[name] = fn()
        except Exception as e:  # noqa: BLE001
            done["errors"].append(f"{name}: {type(e).__name__}")
    if eff is not None and hasattr(eff, "shell"):
        from . import managed
        try:
            done["errors"] += managed.sync(form, eff, vault_readable=vault_readable)["errors"]
        except Exception as e:  # noqa: BLE001
            done["errors"].append(f"managed: {type(e).__name__}")
    return done


def cleanup_envs(days: int = KEEP_ENVS_DAYS) -> list[str]:
    """Remove env dirs other than the current one unused for `days`."""
    removed = []
    cur = paths.env_dir().name
    d = paths.envs_dir()
    if not d.is_dir():
        return removed
    limit = time.time() - days * 86400
    for e in d.iterdir():
        if e.name == cur or not e.is_dir() or "." in e.name:
            continue
        used = e / ".used"
        try:
            t = used.stat().st_mtime if used.exists() else e.stat().st_mtime
        except OSError:
            continue
        if t < limit:
            import shutil
            shutil.rmtree(e, ignore_errors=True)
            removed.append(e.name)
    return removed
