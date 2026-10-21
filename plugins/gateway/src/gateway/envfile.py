"""Claude's environment (SPEC 7, 18): the env file, the stand-in stubs, the
terminal launcher and the generated git include file.

- The env file ($CLAUDE_ENV_FILE, and the same text in ~/.config/gateway/env.sh)
  is static, idempotent, `set -u` safe POSIX sh, written with truncate (Claude
  Code reuses the same file on resume/compact/clear). It does nothing once
  $DATA/bin is gone, so other launchers (checkpoint jobs) may source env.sh
  even after the plugin is uninstalled.
- $DATA/bin holds tiny sh stubs with absolute paths baked in, regenerated
  every session; each file is replaced atomically (write a temp file, rename
  it over the old one), so the folder never goes missing.
- $DATA/git/config starts with a global `credential.helper =` reset when
  others = "refuse" (envfile owns it; githelper adds the URL-scoped helpers).
- hooks/launch.sh writes the same env file, stubs and git reset in sh when the
  pixi env isn't built yet; tests check that both produce identical bytes.
"""
from __future__ import annotations

import contextlib
import glob
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from . import paths, testing

# The user's credential variables, removed from Claude's commands when
# others = "refuse" (v2's policy.ENV_UNSET).
ENV_UNSET = (
    "SSH_AUTH_SOCK", "SSH_AGENT_PID", "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "GIT_ASKPASS",
    "GITHUB_TOKEN", "GH_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN",
    "HF_TOKEN", "HUGGING_FACE_HUB_TOKEN", "HUGGINGFACE_TOKEN",
    "AZURE_STORAGE_KEY", "AZURE_STORAGE_SAS_TOKEN", "AZURE_STORAGE_CONNECTION_STRING",
    "AZURE_CLIENT_SECRET", "ARM_CLIENT_SECRET", "ARM_ACCESS_KEY",
    "DATABRICKS_TOKEN", "DATABRICKS_CLIENT_SECRET", "DOCKER_AUTH_CONFIG",
    "REGISTRY_AUTH_FILE",
)

# Always generated, in this order (launch.sh has the same list).
BASE_STANDINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("sudo", ("shim", "sudo")), ("ssh", ("shim", "ssh")), ("scp", ("shim", "scp")),
    ("sftp", ("shim", "sftp")), ("gh", ("shim", "gh")), ("hf", ("shim", "hf")),
    ("databricks", ("shim", "databricks")), ("crane", ("shim", "crane")),
    ("pijul", ("shim", "pijul")), ("asiml", ("shim", "asiml")), ("gate", ("gate",)),
    ("git-credential-gateway", ("git-credential",)), ("gate-askpass", ("askpass",)),
)
STILL_SETTING_UP = "gateway: still setting up (first run); try again in a minute"
# The global credential-helper reset for others = "refuse" (launch.sh writes
# the same bytes while the env builds).
GIT_RESET = "[credential]\n\thelper =\n"
REAL_SUDO = "/usr/bin/sudo"
KEEP_ENVS_DAYS = 7

# The Bash approval hook's answers while no env can run Python (launch.sh's
# degraded_bash; PLAN-v4 phase 1): a deny by kind, byte-identical to what
# launch.sh prints (tests compare them). The cold window never switches the
# guard off: private folder, transcripts, credential shapes, and curl/wget
# once a vault exists.
DEGRADED_BASH_HEAD = "gateway: still setting up (first run), so its guard works in a reduced form:"
DEGRADED_BASH_TAIL = ("is refused until setup finishes (about a minute; if it can't finish, the "
                      "session's first gateway message says why).")
DEGRADED_BASH_WHAT = {
    "private": ("anything naming the gateway's private folder, keys or vault (~/.config/gateway "
                "other than gateway.toml)"),
    "transcript": "reading Claude Code's session transcripts",
    "cred": ("running a credential helper, decrypting with age, printing an access token or "
             "passing a token on the command line"),
    "fetch": "curl and wget (a vault exists; the http tool replaces them once setup finishes)",
    "managed": ("running Bash outside the gateway's managed shell (it isn't active in this "
                "session: Claude Code's mods are off, older than 2.1.287, or another shell prefix "
                "is set)"),
}


def degraded_bash_text(kind: str) -> str:
    """launch.sh's hook-bash output (stdout, one line) for a deny of KIND
    while the env builds."""
    reason = f"{DEGRADED_BASH_HEAD} {DEGRADED_BASH_WHAT[kind]} {DEGRADED_BASH_TAIL}"
    return ('{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": '
            f'"deny", "permissionDecisionReason": "{reason}"}}}}\n')


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
# it changes nothing (no PATH entry to a missing folder, no GIT_SSH_COMMAND
# to a missing ssh, the user's agent and tokens left alone). POSIX, no
# `return` (it is sourced), nothing that assumes Claude's Bash (CLAUDE_PID).
ENV_HEADER = ("# gateway: Claude's environment (regenerated at every session start).\n"
              "# Safe to source elsewhere (a checkpoint job, a terminal): it does nothing once\n"
              "# the gateway's stand-in folder is gone.")


def env_text(others: str = "refuse") -> str:
    b = paths.bin_dir()
    body = [
        'case ":${PATH-}:" in *":$GW_BIN:"*) ;; *) PATH="$GW_BIN${PATH:+:$PATH}"; export PATH;; esac',
        'if [ "${GW_GITCFG_SET-}" != 1 ]; then',
        "  GW_GITCFG_SET=1; export GW_GITCFG_SET",
        "  _n=${GIT_CONFIG_COUNT:-0}",
        f"  export GIT_CONFIG_KEY_$_n=include.path GIT_CONFIG_VALUE_$_n={sq(paths.git_config_path())}",
        "  GIT_CONFIG_COUNT=$((_n+1)); export GIT_CONFIG_COUNT; unset _n",
        "fi",
        f"GIT_SSH_COMMAND={sq(b / 'ssh')}; RSYNC_RSH={sq(b / 'ssh')}; export GIT_SSH_COMMAND RSYNC_RSH",
    ]
    if others != "mine":
        body.append("unset " + " ".join(ENV_UNSET))
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


def older_env_python() -> Path | None:
    """The python of another finished env this process runs from, when the
    current env (named after pixi.lock) isn't built yet: launch.sh then runs
    the hooks on the newest older env, and the stubs written now fall back to
    it too until the current one is ready. None otherwise (and in tests)."""
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
        lines += [f"echo {sq(STILL_SETTING_UP)} >&2", "exit 75"]
    return "\n".join(lines) + "\n"


def git_stub_text(env_bin: Path) -> str:
    return ("#!/bin/sh\n# gateway: git from the gateway's pixi env (this system has no git)\n"
            f"PATH={sq(env_bin)}:\"$PATH\"; export PATH\n"
            f"exec {sq(env_bin / 'git')} \"$@\"\n")


def system_git() -> str | None:
    """The system's own git (not ours, not pixi's), or None."""
    o = testing.get("system_git")
    if o is not None:
        return "/usr/bin/git" if o else None
    skip = (str(paths.bin_dir()), "/.pixi/")
    dirs = [d for d in os.environ.get("PATH", "").split(os.pathsep) if d and not any(s in d for s in skip)]
    dirs += ["/usr/local/bin", "/opt/homebrew/bin", "/opt/local/bin", "/usr/bin", "/bin"]
    for d in dict.fromkeys(dirs):
        c = Path(d) / "git"
        if c.is_file() and os.access(c, os.X_OK):
            if str(c) == "/usr/bin/git" and os.path.exists("/usr/bin/xcode-select"):
                try:  # macOS: /usr/bin/git is a stub until the developer tools exist
                    r = subprocess.run(["/usr/bin/xcode-select", "-p"], capture_output=True,
                                       timeout=5, stdin=subprocess.DEVNULL)
                    if r.returncode != 0:
                        continue
                except (OSError, subprocess.TimeoutExpired):
                    continue
            return str(c)
    return None


def stand_ins(form: Any = None, eff: Any = None) -> dict[str, str]:
    """{file name: stub text} for this form."""
    out = {name: stub_text(name, args) for name, args in BASE_STANDINS}
    accts = list(getattr(form, "accounts", {}).values()) if form is not None else []
    eff_accts = getattr(eff, "accounts", {}) if eff is not None else {}
    if any(a.kind == "ml-catalog" for a in accts):
        out["dvc"] = stub_text("dvc", ("shim", "dvc"))
    for a in accts:
        if a.kind == "azure" and a.env:
            ea = eff_accts.get(a.name)
            if eff is None or (ea is not None and ea.env):
                out["az"] = stub_text("az", ("shim", "az"))
                break
    if system_git() is None:
        out["git"] = git_stub_text(paths.env_bin())
    return out


def write_stubs(stubs: dict[str, str]) -> Path:
    """Replace each stub in $DATA/bin atomically (write .NAME.tmp.PID, then
    rename over NAME), then remove names that are no longer generated. The
    folder itself is never moved, so a command running meanwhile always finds
    either the old or the new stub, never no stub (which would fall through to
    the system ssh or gh with the user's own keys)."""
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
    now = time.time()
    for p in final.iterdir():
        with contextlib.suppress(OSError):
            if p.name.startswith("."):
                if now - p.lstat().st_mtime > 3600:   # a crashed writer's temp file
                    p.unlink()
            elif p.name not in stubs:
                p.unlink()
    for stale in list(d.glob("bin.new.*")) + list(d.glob("bin.old.*")):  # the old layout
        shutil.rmtree(stale, ignore_errors=True)
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


def launcher_failed(log: Path | str) -> str:
    return f"gateway: the gateway's setup failed (log: {log}); start a new Claude Code session to retry"


def launcher_not_ready(state: str = "building") -> str:
    """What the launcher says until the env is ready, by launch.sh's states:
    building, nopixi (pixi missing) or failed (the build left its log). It is
    the user's own helper, so it speaks to the user (review round 4: in the
    pixi-missing and failed states it repeated the text written for Claude,
    "... tell the user")."""
    if state == "nopixi":
        return LAUNCHER_NOPIXI
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


def git_config_text(others: str, helper_text: str = "") -> str:
    """The include file: with others = "refuse" it always starts with the
    global `credential.helper =` reset (SPEC 5), so git never falls back to
    the user's keychain or osxkeychain helper; githelper's URL-scoped helpers
    and identities follow (an empty helper value clears the earlier ones, so
    the reset must come first)."""
    return (GIT_RESET if others != "mine" else "") + (helper_text or "")


def write_git_config(form: Any, vault_meta: dict[str, Any], others: str = "refuse") -> Path | None:
    """$DATA/git/config: the credential reset (others = "refuse") plus
    githelper.include_config's text, plus its identity files. Written when
    there is any text; an empty result removes a stale file."""
    from . import githelper
    try:
        helper = githelper.include_config(form, vault_meta) or ""
    except NotImplementedError:
        helper = ""
    text = git_config_text(others, helper)
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
    """Write the env file, env.sh, stubs, git config, launcher and the
    managed shell's files (managed.py). Each step is independent; failures
    are collected (no secrets in messages)."""
    others = getattr(eff, "others", "refuse") if eff is not None else "refuse"
    text = env_text(others)
    done: dict[str, Any] = {"errors": []}
    steps = [
        ("env_file", lambda: write_env_file(env_file, text) if env_file else None),
        ("env_sh", lambda: write_env_sh(text)),
        ("stubs", lambda: write_stubs(stand_ins(form, eff))),
        ("git_config", lambda: write_git_config(form, vault_meta or {}, others)),
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
            shutil.rmtree(e, ignore_errors=True)
            removed.append(e.name)
    return removed
