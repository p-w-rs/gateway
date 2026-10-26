"""The managed shell (PLAN-v4 phase 4; PLAN-0.11 §1.6; docs/dev/modules/managed.md).

In managed mode (`[shell] managed = "on"`, the default) the gateway mod sets
CLAUDE_CODE_SHELL_PREFIX to the shipped `hooks/gate-sh` at session start,
and GW_MANAGED_DIR to `$DATA/managed`, where this module writes what gate-sh
needs:

- `conf`: one KEY=VALUE per line (gate-sh reads it with `read`, never
  sources it): the managed bash, the rc, the stand-in folder, the approved
  import_path folders, the form's path and the `sync` stub (gate-sh renews
  the files when gateway.toml is newer than conf, so a narrowing applies to
  the next command even before FileChanged runs);
- `rc.bash`: what the managed bash sources in place of Claude Code's shell
  snapshot: the env file's text, Claude Code's own helpers (rg from its
  embedded copy when none is on PATH, its pkill guard), then the user's bash
  snapshot (its aliases, functions and options; a zsh snapshot gives only
  its PATH, which gate-sh reads), the managed PATH again, and the
  unshadowing tail: in POSIX mode, every function and alias named after a
  present stand-in, or after a builtin the tail relies on, removed, then
  `hash -r`, every line alias-proof (a backslash on each command word, no
  reserved word), so nothing in the snapshot shadows a stand-in;
- `state.json`: the mode, the PATH and variables with their origins, the
  bash version, readiness and pending widenings, for /gate-doctor (the mod)
  and `gate status`;
- `sync`: a stub like the stand-ins' that runs `run.py managed-sync`.

The environment is the user's (Claude Code's, inherited) minus, by name:
Claude Code's own credential variables (every CLAUDE_* or ANTHROPIC_* name
with a credential word, and CLAUDE_CRED_NAMES), the variables that make a
shell run code or change its parsing (STARTUP_NAMES, every BASH_FUNC_*), and
the gateway's GW_* names but GW_MANAGED_DIR. hooks/gate-sh holds the same
lists (tests/test_managed.py compares them); `dropped()` is its rule in
Python, and `fallback_shell()` the shell gate-sh runs a script in while the
managed shell isn't ready. The PATH is the present stand-ins ($DATA/bin), then the snapshot's
PATH (the inherited one without a snapshot), then other plugins' bin/
folders, then the approved import_path folders. Nothing here reads a secret:
the effective settings come from consent.compute.

Files are written whole (temp file, then rename).

`inspect()` is the host inspection behind the gw MCP tool `host_inspect`:
what this machine offers (login-shell PATH folders, toolchain folders,
project toolchain files, variable names), gathered by reading files and
listing folders, never by running or sourcing anything; reading never
imports anything.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from . import envfile, paths, testing

SYSTEM_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin")
# In step with hooks/gate-sh (tests/test_managed.py compares the two): what
# the managed shell removes from the inherited environment (PLAN-0.11 §1.6).
CLAUDE_CRED_NAMES = envfile.CLAUDE_CRED_NAMES
STARTUP_NAMES = ("BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "PS4", "PROMPT_COMMAND", "CDPATH",
                 "IFS", "GLOBIGNORE", "BASH_XTRACEFD")
DROP_PREFIXES = ("GW_", "BASH_FUNC_")
# The managed shell's own folder (the mod sets it with the prefix): a Claude
# Code started from a command keeps the prefix, so it needs this too.
GATEWAY_NAMES = ("GW_MANAGED_DIR",)
# Substrings of a credential-looking name (gate-sh's gw_credlike; also what
# import_env refuses, form.CREDENTIAL_NAME). A CLAUDE_* or ANTHROPIC_* name
# holding one is Claude Code's own credential (2.1.301's lists:
# CLAUDE_CODE_OAUTH_TOKEN, CLAUDE_CODE_CLIENT_KEY_PASSPHRASE, ...).
CREDENTIAL_WORDS = ("TOKEN", "SECRET", "PASSW", "PASSPHRASE", "CRED", "API_KEY", "APIKEY",
                    "ACCESS_KEY", "PRIVATE_KEY", "CLIENT_KEY", "CLIENT_CERT", "AUTH", "COOKIE",
                    "SESSION_KEY")
# The not-ready fallback (gate-sh's gw_fallback_shell; a test compares): the
# shell that made the script's snapshot, found the way Claude Code (2.1.310)
# finds its shell, in its usual places. Never /bin/sh: dash has no `source`,
# so the snapshot would be skipped.
FALLBACK_SHELLS = ("bash", "zsh")
FALLBACK_DIRS = ("/bin", "/usr/bin", "/usr/local/bin", "/opt/homebrew/bin")
STATE_VERSION = 1
GATE_SH = "gate-sh"

MODE_WORDS = {
    "on": ("on (Claude's Bash runs in the gateway's bash 5 with your own environment; without "
           "Claude Code's mods, in your own shell, with a notice each session)"),
    "off": "off (Claude's Bash runs in Claude Code's own shell, with your login setup)",
}


def credential_like(name: str) -> bool:
    """gate-sh's gw_credlike, in Python (the same words)."""
    up = name.upper()
    return any(w in up for w in CREDENTIAL_WORDS)


def dropped(name: str) -> bool:
    """Does the managed shell remove this inherited variable (gate-sh's rule,
    PLAN-0.11 §1.6)? Claude Code's own credentials, the startup and parsing
    variables, BASH_FUNC_*, GW_* but GW_MANAGED_DIR, and a name no shell
    takes as a variable (one holding a blank no shell imports: kept)."""
    import re as _re
    if any(c in name for c in " \t"):
        return False
    if name in GATEWAY_NAMES:
        return False
    if name.startswith(DROP_PREFIXES) or not _re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
        return True
    if name.startswith(("CLAUDE_", "ANTHROPIC_")) and credential_like(name):
        return True
    return name in CLAUDE_CRED_NAMES or name in STARTUP_NAMES


def shell_family(path: str) -> str:
    """What Claude Code calls the shell at `path` (its snapshot's name):
    "zsh" when the path holds zsh, else "bash" when it holds bash, else ""."""
    return "zsh" if "zsh" in path else "bash" if "bash" in path else ""


def snapshot_family(snapshot: str | None) -> str:
    """The shell that made a Claude Code shell snapshot, from its name
    (snapshot-zsh-*, snapshot-bash-*), or "" (none, or another name)."""
    name = os.path.basename(snapshot or "")
    return next((f for f in FALLBACK_SHELLS if name.startswith(f"snapshot-{f}-")), "")


def fallback_shell(environ: dict[str, str], dirs: tuple[str, ...] = FALLBACK_DIRS,
                   snapshot: str | None = None) -> str | None:
    """The shell gate-sh runs a script in while the managed shell isn't
    ready (gw_fallback_shell, PLAN-0.11 §19.15): the one that made the
    script's snapshot, found the way Claude Code finds its shell:
    CLAUDE_CODE_SHELL, then SHELL, then the preferred shell on PATH, in
    `dirs`, the other in `dirs`, the other on PATH (bash is preferred when
    SHELL holds "bash", else zsh). The first that fits: an absolute path
    without '=' to an executable file whose shell_family is the snapshot's
    (any bash or zsh without a snapshot). PATH lookups take absolute folders
    only. None: there is none, and gate-sh refuses the script (126)."""
    want = snapshot_family(snapshot)

    def fits(p: str) -> bool:
        f = shell_family(p)
        return (p.startswith("/") and "=" not in p and bool(f) and (not want or f == want)
                and os.path.isfile(p) and os.access(p, os.X_OK))
    path = [d for d in environ.get("PATH", "").split(":") if d.startswith("/") and "=" not in d]

    def which(name: str) -> str | None:
        p = next((f"{d}/{name}" for d in path
                  if os.path.isfile(f"{d}/{name}") and os.access(f"{d}/{name}", os.X_OK)), None)
        return p if p is not None and fits(p) else None

    def places(name: str) -> str | None:
        return next((f"{d}/{name}" for d in dirs if fits(f"{d}/{name}")), None)
    shell = environ.get("SHELL", "")
    first, second = ("bash", "zsh") if "bash" in shell else ("zsh", "bash")
    for c in (environ.get("CLAUDE_CODE_SHELL", ""), shell):
        if fits(c):
            return c
    return which(first) or places(first) or places(second) or which(second)


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------


def managed_dir() -> Path:
    return paths.data_dir() / "managed"


def conf_path() -> Path:
    return managed_dir() / "conf"


def rc_path() -> Path:
    return managed_dir() / "rc.bash"


def state_path() -> Path:
    return managed_dir() / "state.json"


def sync_path() -> Path:
    return managed_dir() / "sync"


def unlocked_marker() -> Path:
    """gated touches it when the vault is unlocked; gate-sh renews its
    settings when it is newer than conf (approved imports are in the vault)."""
    return paths.run_dir(create=False) / "gated-unlocked"


def gate_sh() -> Path:
    return paths.plugin_root() / "hooks" / GATE_SH


def gate_sh_copy() -> Path:
    """An executable copy of gate-sh in the data folder, written only when the
    plugin's own lost its exec bit (an install that doesn't keep file modes:
    Claude Code runs the prefix as a program, and the plugin folder is never
    written to)."""
    return managed_dir() / GATE_SH


def prefix_paths() -> list[Path]:
    """What CLAUDE_CODE_SHELL_PREFIX may name for this plugin: its gate-sh, or
    the data folder's copy."""
    return [gate_sh(), gate_sh_copy()]


def _gate_sh_for_prefix() -> Path:
    """The plugin's gate-sh when it is executable (the normal case: git keeps
    the mode), else a fresh executable copy in the data folder."""
    src = gate_sh()
    copy = gate_sh_copy()
    if os.access(src, os.X_OK):
        with contextlib.suppress(FileNotFoundError):
            copy.unlink()
        return src
    _write(copy, src.read_text(), 0o755)
    return copy


def env_bash() -> Path:
    o = testing.get("managed_bash")
    if o:
        return Path(o)
    return paths.env_bin() / "bash"


# ---------------------------------------------------------------------------
# Origins
# ---------------------------------------------------------------------------


def _home_s() -> str:
    try:
        return str(paths.user_home())
    except Exception:  # noqa: BLE001
        return os.path.expanduser("~")


def _tilde(p: str) -> str:
    h = _home_s()
    return "~" + p[len(h):] if h and (p == h or p.startswith(h + "/")) else p


def host_source(folder: str) -> str | None:
    """What usually puts this folder on a login PATH (a hint for people)."""
    h = _home_s()
    rel = folder[len(h) + 1:] if h and folder.startswith(h + "/") else None
    table = [
        (("/opt/homebrew/", "/usr/local/Homebrew/", "/home/linuxbrew/.linuxbrew/"), "Homebrew"),
        (("/opt/local/",), "MacPorts"),
        (("/nix/", ), "Nix"),
        (("/snap/",), "snap"),
        (("/usr/local/go/",), "Go"),
    ]
    f = folder.rstrip("/") + "/"
    for prefixes, name in table:
        if f.startswith(prefixes):
            return name
    if f == "/usr/local/bin/" or f == "/usr/local/sbin/":
        return "/usr/local (local installs; Homebrew on Intel Macs)"
    if rel is not None:
        user_table = [
            (".pyenv/", "pyenv"), (".nvm/", "nvm"), (".cargo/", "rustup/cargo"),
            (".pixi/", "pixi global"), (".local/bin", "~/.local/bin (pipx, uv, installers)"),
            ("go/", "Go"), (".sdkman/", "SDKMAN"), (".asdf/", "asdf"), (".rbenv/", "rbenv"),
            ("miniconda3/", "conda"), ("anaconda3/", "conda"), ("miniforge3/", "conda"),
            (".conda/", "conda"), (".deno/", "Deno"), (".bun/", "Bun"), (".volta/", "Volta"),
            (".juliaup/", "juliaup"), (".nix-profile/", "Nix"), (".local/share/mise/", "mise"),
            (".rustup/", "rustup"), (".ghcup/", "ghcup"), (".dotnet/", ".NET"),
            ("bin", "~/bin"),
        ]
        for prefix, name in user_table:
            if (rel + "/").startswith(prefix if prefix.endswith("/") else prefix + "/") or rel == prefix:
                return name
    return None


def _line(n: int | None) -> str:
    return f", line {n}" if n else ""


# ---------------------------------------------------------------------------
# What the managed shell gets
# ---------------------------------------------------------------------------


def imports_allowed(eff: Any, host: str | None = None) -> bool:
    """The policy's env_import for this machine (or a remote host): only an
    "allow" lets the consented imports in (PLAN-v4 phase 7); "ask" can't be
    asked for a shell's settings, so it keeps them out too."""
    try:
        from . import policy
        return policy.decide(eff, "env_import", host=host).word is True
    except Exception:  # noqa: BLE001 - no decision: keep the imports out
        return False


def import_path(eff: Any) -> list[str]:
    """The approved import_path folders, while the env_import policy allows
    them (imports_allowed)."""
    return list(eff.shell.import_path) if imports_allowed(eff) else []


SNAPSHOT_PATH = "$PATH"


def path_plan(eff: Any) -> list[tuple[str, str]]:
    """[(folder, origin)] in PATH order: the stand-ins, the user's own PATH
    (SNAPSHOT_PATH: the snapshot's, read by gate-sh at run time), the
    approved imports. gate-sh adds other plugins' bin/ folders the snapshot's
    PATH lacks before the imports."""
    form = getattr(eff, "form", None)
    line = getattr(getattr(form, "shell", None), "path_line", None)
    out: list[tuple[str, str]] = [
        (str(paths.bin_dir()), "the gateway's stand-ins"),
        (SNAPSHOT_PATH, "your own PATH (Claude Code's shell snapshot, else its own PATH)"),
    ]
    for p in import_path(eff):
        src = host_source(p)
        out.append((p, f"gateway.toml [shell] import_path{_line(line)}"
                       + (f"; {src}" if src else "")))
    seen: set[str] = set()
    uniq = []
    for d, o in out:
        if d not in seen:
            seen.add(d)
            uniq.append((d, o))
    return uniq


def env_plan(eff: Any) -> list[tuple[str, str]]:
    """[(name, origin)] for the variables [shell] import_env names (the
    inherited environment keeps them anyway, minus the removals)."""
    form = getattr(eff, "form", None)
    line = getattr(getattr(form, "shell", None), "env_line", None)
    return [(n, f"gateway.toml [shell] import_env{_line(line)}")
            for n in (eff.shell.import_env if imports_allowed(eff) else [])]


def conf_text(eff: Any) -> str:
    lines = [
        "# gateway: the managed shell's settings for hooks/gate-sh (regenerated; read, never sourced)",
        f"bash={env_bash()}",
        f"rc={rc_path()}",
        f"standins={paths.bin_dir()}",
        "imports=" + ":".join(import_path(eff)),
        f"form={paths.form_path()}",
        f"sync={sync_path()}",
        f"unlocked={unlocked_marker()}",
    ]
    return "\n".join(lines) + "\n"


# Claude Code's own helpers from its shell snapshot (not the user's): rg from
# its embedded copy when none is on PATH, and its guard against a pkill
# pattern that matches the Claude Code process (Linux, where /proc names it).
RC_HELPERS = r'''# Claude Code's own helpers its shell snapshot carries (not the user's rc):
# rg from Claude Code's embedded copy when none is on PATH; its pkill guard.
if ! command -v rg >/dev/null 2>&1 && [ -x "${CLAUDE_CODE_EXECPATH-}" ]; then
  rg() { (exec -a rg "$CLAUDE_CODE_EXECPATH" "$@"); }
fi
pkill() {
  if [ -n "${CLAUDE_PID-}" ] && [ -r "/proc/${CLAUDE_PID}/comm" ]; then
    local _gw_a _gw_skip=''
    local -a _gw_probe=()
    for _gw_a in "$@"; do
      if [ -n "$_gw_skip" ]; then _gw_skip=''; continue; fi
      case $_gw_a in
        --signal) _gw_skip=1 ;;
        --signal=*|-e|--echo|-[0-9]*) ;;
        -[PUGOF]?*) _gw_probe+=("$_gw_a") ;;
        -[A-Z][A-Z0-9]*) ;;
        *) _gw_probe+=("$_gw_a") ;;
      esac
    done
    if command pgrep "${_gw_probe[@]}" 2>/dev/null | command grep -qx "$CLAUDE_PID"; then
      printf 'pkill: refused: that pattern matches the Claude Code process (pid %s); narrow it, or use pkill -P $$ for your own children.\n' "$CLAUDE_PID" >&2
      return 1
    fi
  fi
  command pkill "$@"
}
'''

RC_HEADER = ("# gateway: the managed shell's rc (PLAN-v4 phase 4; PLAN-0.11 §1.6), sourced by the\n"
             "# gateway's bash in place of Claude Code's shell snapshot (its $1: a bash snapshot,\n"
             "# sourced here); regenerated at every session start, after a change of gateway.toml\n"
             "# and after an approval.\n")
# The commands the unshadowing tail relies on: their functions and aliases go
# first (POSIX mode puts the special builtins before functions; the others
# are taken out by name).
TAIL_BUILTINS = ("command", "builtin", "hash", "type", "unalias", "unset", "exec", "source", ".",
                 "test", "shopt", "trap", "readonly")
# The tail's refusals: a shell expansion error (`${VAR:?TEXT}`), which ends a
# non-interactive bash (status 127) whatever any function or trap does, so
# `. RC && COMMAND` never runs the command. (The word of a double-quoted
# ${VAR:?WORD}: no `, $, ", ' or } in them.)
TAIL_NO_POSIX = ("gateway: the managed shell could not enter POSIX mode (is POSIXLY_CORRECT "
                 "read-only in your shell snapshot?), so the stand-ins of the gateway could be "
                 "shadowed; the command was not run")
TAIL_READONLY = ("gateway: your shell snapshot makes a function read-only that the managed shell "
                 "must remove (one named after a gateway stand-in, or a builtin its rc uses), so "
                 "it would shadow the stand-in; the command was not run. Take readonly -f out "
                 "of your shell profile")


def rc_tail() -> str:
    """The rc's last lines (PLAN-0.11 §1.6): POSIX mode by assignment; the
    snapshot's DEBUG, RETURN and ERR traps cleared (they run code before
    each command, when a sourced file returns, or after a failure, and could
    define a function after the tail); the functions and aliases of
    TAIL_BUILTINS and of every stand-in present in $DATA/bin (each checked
    with `test -e` at run time) removed; then fail closed (TAIL_NO_POSIX,
    TAIL_READONLY) when POSIX mode didn't take or one of those functions
    survived (read-only), checked with the special builtin `readonly -f`;
    POSIX mode left (which turns alias expansion off in a non-interactive
    bash: back on where the user's snapshot had it on), `hash -r`. After the
    user's snapshot every line is alias-proof: a backslash before each
    command word, no reserved word."""
    b = paths.bin_dir()
    names = " ".join(TAIL_BUILTINS)
    out = ["# the stand-ins can't be shadowed: nothing below may be an alias or a function",
           "PATH=$_gw_path",
           "_gw_ea=${BASHOPTS-}",
           "POSIXLY_CORRECT=y",
           "\\trap - DEBUG RETURN ERR",
           f"\\unset -f {names} 2>/dev/null",
           f"\\unalias {names} 2>/dev/null",
           "\\export PATH"]
    for n in envfile.STANDIN_NAMES:
        q = envfile.sq(b / n)
        out.append(f"\\test -e {q} && \\unset -f {n} 2>/dev/null")
        out.append(f"\\test -e {q} && \\unalias {n} 2>/dev/null")
    out += ['_gw_ok=${SHELLOPTS#"${SHELLOPTS%%posix*}"}',
            f'\\: "${{_gw_ok:?{TAIL_NO_POSIX}}}"']
    out += [f"\\readonly -f {n} 2>/dev/null && _gw_ok=" for n in TAIL_BUILTINS]
    out += [f"\\test -e {envfile.sq(b / n)} && \\readonly -f {n} 2>/dev/null && _gw_ok="
            for n in envfile.STANDIN_NAMES]
    out += [f'\\: "${{_gw_ok:?{TAIL_READONLY}}}"',
            "\\unset POSIXLY_CORRECT",
            '\\test "${_gw_ea#*expand_aliases}" != "$_gw_ea" && \\shopt -s expand_aliases',
            "\\unset _gw_ea _gw_path _gw_ok", "\\hash -r", "\\:"]
    return "\n".join(out) + "\n"


RC_SNAPSHOT = """# the user's own bash snapshot (aliases, functions, options), then the managed PATH again
_gw_path=$PATH
case ${1-} in */shell-snapshots/snapshot-bash-*.sh) if [ -r "$1" ]; then . "$1" 2>/dev/null || :; fi ;; esac
"""


def rc_text(eff: Any) -> str:
    return RC_HEADER + envfile.env_text() + RC_HELPERS + RC_SNAPSHOT + rc_tail()


def bash_version(bash: Path) -> str:
    """The managed bash's version ("5.2.37"), or "" when it can't be run."""
    if not (bash.is_file() and os.access(bash, os.X_OK)):
        return ""
    try:
        r = subprocess.run([str(bash), "--norc", "--noprofile", "-c", "echo $BASH_VERSION"],
                           capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL,
                           env={"PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.TimeoutExpired):
        return ""
    m = re.match(r"(\d+\.\d+\.\d+)", r.stdout.strip())
    return m.group(1) if m else ""


def state_dict(eff: Any, *, vault_readable: bool = True, prefix: Path | None = None) -> dict[str, Any]:
    bash = env_bash()
    ver = bash_version(bash)
    form = getattr(eff, "form", None)
    fs = getattr(form, "shell", None)
    pending = [c.render() for c in getattr(eff, "pending", []) if c.entry == "settings"]
    return {
        "version": STATE_VERSION,
        "mode": eff.shell.managed,
        "form_mode": getattr(fs, "managed", "on") if fs is not None else "on",
        "form_mode_invalid": bool(getattr(fs, "managed_invalid", False)),
        "bash": str(bash),
        "bash_version": ver,
        "ready": bool(ver) and rc_path().exists(),
        "gate_sh": str(prefix or gate_sh()),
        "path": [{"dir": d, "origin": o} for d, o in path_plan(eff)],
        "env": [{"name": n, "origin": o} for n, o in env_plan(eff)],
        "pending": pending,
        "vault_readable": vault_readable,
        "found": found_not_imported(eff),
        "written": time.time(),
    }


# ---------------------------------------------------------------------------
# Writing
# ---------------------------------------------------------------------------


def _write(p: Path, text: str, mode: int) -> None:
    envfile._atomic(p, text, mode)


def sync(form: Any, eff: Any, *, vault_readable: bool = True) -> dict[str, Any]:
    """Write the managed shell's files for these effective settings. Each
    step is independent; failures are collected (no secrets in messages)."""
    done: dict[str, Any] = {"errors": []}
    try:
        managed_dir().mkdir(parents=True, exist_ok=True)
        os.chmod(managed_dir(), 0o700)
    except OSError as e:
        done["errors"].append(f"managed: {type(e).__name__}")
        return done
    prefix: list[Path] = []
    steps = [
        ("gate-sh", lambda: prefix.append(_gate_sh_for_prefix())),
        ("sync", lambda: _write(sync_path(), envfile.stub_text(
            "managed-sync", ("managed-sync",), "gateway: renews the managed shell's settings"),
            0o755)),
        ("rc", lambda: _write(rc_path(), rc_text(eff), 0o600)),
        ("state", lambda: _write(state_path(), json.dumps(
            state_dict(eff, vault_readable=vault_readable, prefix=(prefix or [None])[0]),
            indent=1) + "\n", 0o600)),
        # conf last: gate-sh renews when the form is newer than conf
        ("conf", lambda: _write_conf(conf_text(eff))),
    ]
    for name, fn in steps:
        try:
            fn()
        except Exception as e:  # noqa: BLE001
            done["errors"].append(f"managed {name}: {type(e).__name__}")
    return done


def _write_conf(text: str) -> None:
    p = conf_path()
    _write(p, text, 0o600)
    # never older than gateway.toml (a form dated in the future would make
    # gate-sh renew on every command)
    try:
        fm = paths.form_path().stat().st_mtime
        if fm >= p.stat().st_mtime:
            os.utime(p, (fm + 1, fm + 1))
    except OSError:
        pass


def sync_now() -> int:
    """run.py managed-sync (gate-sh, when gateway.toml is newer than conf;
    gated, after an unlock): load the form and the vault, persist a
    narrowing, write the files. Exit 0 when they were written."""
    from . import consent, vault
    from . import form as formmod
    data = None
    readable = True
    try:
        if vault.exists():
            data = vault.load()
    except vault.VaultError:
        data, readable = None, False
    formmod.clear_cache()
    form = formmod.load(last_good=(data or {}).get("form_last_good"))
    with contextlib.suppress(Exception):
        if consent.ratchet(form) and vault.exists():
            data = vault.load()
    eff = consent.compute(form, data)
    res = sync(form, eff, vault_readable=readable)
    return 1 if res["errors"] else 0


def load_state() -> dict[str, Any] | None:
    try:
        v = json.loads(state_path().read_text())
    except (OSError, ValueError):
        return None
    return v if isinstance(v, dict) else None


def status_lines(eff: Any) -> list[str]:
    """`gate status`'s managed-shell section (each PATH folder and variable
    with its origin)."""
    st = load_state() or {}
    out = [f"Managed shell: {MODE_WORDS.get(eff.shell.managed, eff.shell.managed)}"]
    fs = getattr(getattr(eff, "form", None), "shell", None)
    if fs is not None and fs.managed != eff.shell.managed and not fs.managed_invalid:
        out.append(f'  gateway.toml says "{fs.managed}"; that waits for your OK (gate check settings)')
    ver = st.get("bash_version") or ""
    bash = env_bash()
    out.append(f"  bash: {_tilde(str(bash))}" + (f" ({ver})" if ver else
                                                 " (not ready yet: the gateway is still setting up)"))
    out.append("  PATH (in order; other plugins' bin/ folders come before the imports):")
    for d, o in path_plan(eff):
        out.append(f"    {_tilde(d)}  ({o})")
    envs = env_plan(eff)
    out.append("  Environment: yours (Claude Code's), minus Claude Code's own credential "
               "variables, the shell startup variables (BASH_ENV, ENV, BASH_FUNC_*, ...) and the "
               "gateway's internal GW_* names; SHELL is the managed bash"
               + ("; [shell] import_env: " + ", ".join(f"{n} ({o})" for n, o in envs) if envs
                  else ""))
    pend = [c.render() for c in getattr(eff, "pending", []) if c.entry == "settings"]
    if pend:
        out.append("  waiting for your OK: " + "; ".join(pend) + " (gate check settings)")
    found = found_not_imported(eff)
    if found:
        out.append("  found here but not imported: " + ", ".join(found) + " (add them to [shell] "
                   "import_path, or ask Claude to; each needs your OK in the gateway's dialog)")
    if st and st.get("vault_readable") is False:
        out.append("  the vault was locked when these were written, so approved imports were "
                   "left out; they apply after /gate-unlock")
    return out


# ---------------------------------------------------------------------------
# Host inspection (the gw MCP tool host_inspect): read files and list folders
# ---------------------------------------------------------------------------

RC_FILES = (".zshenv", ".zprofile", ".zshrc", ".zlogin", ".bash_profile", ".bash_login",
            ".profile", ".bashrc", ".config/fish/config.fish")
SYSTEM_RC = ("/etc/paths", "/etc/zprofile", "/etc/zshenv", "/etc/profile", "/etc/environment")
TOOLCHAIN_DIRS = (
    ("Homebrew", ("/opt/homebrew/bin", "/opt/homebrew/sbin", "/usr/local/bin",
                  "/home/linuxbrew/.linuxbrew/bin")),
    ("MacPorts", ("/opt/local/bin", "/opt/local/sbin")),
    ("pixi global", ("~/.pixi/bin",)),
    ("~/.local/bin (pipx, uv, installers)", ("~/.local/bin",)),
    ("pyenv", ("~/.pyenv/shims", "~/.pyenv/bin")),
    ("nvm", ("~/.nvm/versions/node/*/bin",)),
    ("rustup/cargo", ("~/.cargo/bin",)),
    ("Go", ("~/go/bin", "/usr/local/go/bin")),
    ("SDKMAN", ("~/.sdkman/candidates/*/current/bin",)),
    ("asdf", ("~/.asdf/shims",)),
    ("mise", ("~/.local/share/mise/shims",)),
    ("rbenv", ("~/.rbenv/shims",)),
    ("conda", ("~/miniconda3/bin", "~/anaconda3/bin", "~/miniforge3/bin", "~/mambaforge/bin")),
    ("Deno", ("~/.deno/bin",)),
    ("Bun", ("~/.bun/bin",)),
    ("Volta", ("~/.volta/bin",)),
    ("juliaup", ("~/.juliaup/bin",)),
    ("Nix", ("~/.nix-profile/bin", "/nix/var/nix/profiles/default/bin")),
    ("snap", ("/snap/bin",)),
    ("~/bin", ("~/bin",)),
)
PROJECT_FILES = (".python-version", ".nvmrc", ".node-version", ".tool-versions",
                 "rust-toolchain", "rust-toolchain.toml", "go.mod", "pixi.toml",
                 "environment.yml", "package.json", ".ruby-version", "Pipfile", "pyproject.toml",
                 ".sdkmanrc", "mise.toml", ".mise.toml", "flake.nix", ".envrc", "Gemfile",
                 "pom.xml", "build.gradle", "Cargo.toml", "requirements.txt", "uv.lock",
                 ".java-version", ".terraform-version")
MAX_TOOLS = 12
MAX_READ = 256 * 1024

_ASSIGN = re.compile(r"""^\s*(?:export\s+|typeset\s+-x\s+|declare\s+-x\s+)?PATH\s*\+?=\s*(.+?)\s*;?\s*$""")
_ZSH_ARRAY = re.compile(r"""^\s*(?:typeset\s+-U\s+)?path\s*\+?=\s*\((.*)\)\s*$""")
_FISH = re.compile(r"""^\s*(?:fish_add_path(?:\s+-\w+)*|set\s+-[gUxa]+\s+(?:fish_user_paths|PATH))\s+(.+)$""")
_HINTS = (
    (re.compile(r"brew\s+shellenv"), "Homebrew (brew shellenv)", ("/opt/homebrew/bin", "/opt/homebrew/sbin",
                                                                  "/home/linuxbrew/.linuxbrew/bin")),
    (re.compile(r"pyenv\s+init"), "pyenv (pyenv init)", ("~/.pyenv/shims",)),
    (re.compile(r"\.cargo/env"), "rustup (~/.cargo/env)", ("~/.cargo/bin",)),
    (re.compile(r"nvm\.sh"), "nvm (nvm.sh)", ()),
    (re.compile(r"rbenv\s+init"), "rbenv (rbenv init)", ("~/.rbenv/shims",)),
    (re.compile(r"conda\s+(?:shell|init)|conda\.sh"), "conda (conda init)", ()),
    (re.compile(r"mise\s+activate"), "mise (mise activate)", ("~/.local/share/mise/shims",)),
    (re.compile(r"asdf\.sh"), "asdf (asdf.sh)", ("~/.asdf/shims",)),
    (re.compile(r"sdkman-init\.sh"), "SDKMAN (sdkman-init.sh)", ()),
    (re.compile(r"direnv\s+hook"), "direnv (direnv hook; never run by the gateway)", ()),
)


def _expand(word: str, home: str | None = None) -> str | None:
    """A PATH word from an rc file, with only ~, $HOME and ${HOME} expanded;
    None when it needs anything else (another variable, a command)."""
    h = home if home is not None else _home_s()
    w = word.strip().strip("\"'")
    if not w or "`" in w or "$(" in w:
        return None
    w = w.replace("${HOME}", h).replace("$HOME", h)
    if w == "~" or w.startswith("~/"):
        w = h + w[1:]
    if "$" in w or not w.startswith("/"):
        return None
    return os.path.normpath(w)


def _path_words(value: str) -> list[str]:
    v = value.strip()
    if v.startswith(("'", '"')) and v.endswith(v[0]) and len(v) > 1:
        v = v[1:-1]
    return [x for x in v.split(":")]


def _read_text(p: Path) -> str | None:
    try:
        if not p.is_file() or p.stat().st_size > MAX_READ:
            return None
        return p.read_text(errors="replace")
    except OSError:
        return None


def _glob_dirs(pattern: str) -> list[Path]:
    h = _home_s()
    pat = h + pattern[1:] if pattern.startswith("~/") else pattern
    if "*" not in pat:
        return [Path(pat)] if os.path.isdir(pat) else []
    import glob
    return sorted(Path(x) for x in glob.glob(pat) if os.path.isdir(x))[:8]


def _tools_in(d: Path) -> list[str]:
    try:
        names = sorted(e.name for e in os.scandir(d)
                       if not e.name.startswith(".") and (e.is_file() or e.is_symlink()))
    except OSError:
        return []
    return names[:MAX_TOOLS] + ([f"... ({len(names) - MAX_TOOLS} more)"] if len(names) > MAX_TOOLS else [])


def _gateway_home_names() -> tuple[str, str]:
    return str(paths.home()), str(paths.data_dir())


def login_path_entries() -> list[dict[str, Any]]:
    """Folders a login shell would put on PATH, as far as reading files can
    tell: /etc/paths(.d) and PATH lines in the user's and the system's rc
    files (nothing is run or sourced; a word that needs evaluation is left
    out), plus folders well-known setup lines add (brew shellenv, pyenv
    init, ~/.cargo/env, ...)."""
    h = Path(_home_s())
    files: list[tuple[Path, str]] = [(Path(p), p) for p in SYSTEM_RC]
    pd = Path("/etc/paths.d")
    with contextlib.suppress(OSError):
        if pd.is_dir():
            files += [(f, str(f)) for f in sorted(pd.iterdir())[:32] if f.is_file()]
    files += [(h / n, "~/" + n) for n in RC_FILES]
    texts = [(label, t) for p, label in files if (t := _read_text(p)) is not None]
    return path_entries(texts, _home_s(), os.path.isdir)


def path_entries(texts: list[tuple[str, str]], home: str, isdir: Any) -> list[dict[str, Any]]:
    """The PATH folders rc file texts name (label, text), with ~ and $HOME
    expanded to `home` (this machine's, or a remote host's for host_inspect
    there, PLAN-v4 phase 7); isdir(folder) says whether it exists."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add(d: str, source: str) -> None:
        if d in seen:
            return
        seen.add(d)
        out.append({"dir": d, "source": source, "exists": bool(isdir(d))})

    def expand(w: str) -> str | None:
        return _expand(w, home)

    for label, text in texts:
        plain = label in ("/etc/paths",) or label.startswith("/etc/paths.d/")
        for i, raw in enumerate(text.splitlines()[:5000], 1):
            line = raw.split("#", 1)[0] if not plain else raw.strip()
            if plain:
                d = expand(line)
                if d:
                    add(d, f"{label} line {i}")
                continue
            for rx, name, dirs in _HINTS:
                if rx.search(line):
                    for x in dirs:
                        d = expand(x)
                        if d:
                            add(d, f"{label} line {i}: {name}")
            m = _ASSIGN.match(line)
            words: list[str] = []
            if m:
                words = _path_words(m.group(1).split(";")[0])
            else:
                m2 = _ZSH_ARRAY.match(line) or _FISH.match(line)
                if m2:
                    words = m2.group(1).split()
            for w in words:
                d = expand(w)
                if d:
                    add(d, f"{label} line {i}")
    return out


# Tool folders this machine has that the managed PATH lacks (GW-UX-2b): the
# session context proposes importing them while the form has no [shell]
# import_path at all (an explicit `import_path = []` says no), and
# /gate-doctor and `gate status` list them. Nothing is imported by finding:
# an import is a form edit and the consent dialog, as always.
FOUND_MAX = 8
_FOUND_SAFE = re.compile(r"[A-Za-z0-9._+@/~-]{1,200}")
_FOUND_SKIP = ("/System/", "/Library/Apple/", "/usr/libexec/")


def found_not_imported(eff: Any) -> list[str]:
    """Folders (~ for the home) that hold programs and that a login shell
    puts on PATH (login_path_entries) or a well-known toolchain installs
    into (TOOLCHAIN_DIRS), minus the system folders, the macOS system ones,
    what is imported and the gateway's own folders; at most FOUND_MAX, names
    of plain characters only (they go into Claude's context). Reads files
    and lists folders only, like host_inspect."""
    imported = set(eff.shell.import_path) if getattr(eff, "shell", None) is not None else set()
    gw_home, gw_data = _gateway_home_names()
    out: list[str] = []
    seen: set[str] = set()

    def consider(d: str) -> None:
        d = os.path.normpath(d)
        if d in seen or len(out) >= FOUND_MAX:
            return
        seen.add(d)
        if d in SYSTEM_DIRS or d in imported or d.startswith(_FOUND_SKIP) \
                or d.startswith((gw_home, gw_data)):
            return
        t = _tilde(d)
        if not _FOUND_SAFE.fullmatch(t) or ".." in t.split("/") or not os.path.isdir(d):
            return
        if _tools_in(Path(d)):
            out.append(t)
    with contextlib.suppress(Exception):
        for e in login_path_entries():
            if e.get("exists"):
                consider(e["dir"])
    with contextlib.suppress(Exception):
        for _name, pats in TOOLCHAIN_DIRS:
            for pat in pats:
                for d in _glob_dirs(pat):
                    consider(str(d))
    return out


def toolchains() -> list[dict[str, Any]]:
    out = []
    for name, pats in TOOLCHAIN_DIRS:
        dirs = []
        for pat in pats:
            for d in _glob_dirs(pat):
                dirs.append({"dir": str(d), "tools": _tools_in(d)})
        if dirs:
            out.append({"name": name, "dirs": dirs})
    return out


# A version word in a toolchain file (3.12.4, v20.11.1, lts/iron, stable,
# 1.79-aarch64...): anything else is reported only as present.
_VERSION_WORD = re.compile(r"[vV]?\d[0-9A-Za-z.+-]{0,23}|lts/[A-Za-z*]{1,20}|node|stable|beta|nightly|"
                           r"system|latest|pypy[0-9.]{0,10}")


def _project_says(p: Path) -> str:
    """One short, non-secret line about a project toolchain file: a version
    line where the file is one, else only that it exists."""
    name = p.name
    if name in (".python-version", ".nvmrc", ".node-version", ".ruby-version", ".java-version",
                ".terraform-version", "rust-toolchain"):
        t = _read_text(p) or ""
        first = next((x.strip() for x in t.splitlines() if x.strip() and not x.startswith("#")), "")
        return f"version {first}" if _VERSION_WORD.fullmatch(first) else "present"
    if name == ".tool-versions":
        t = _read_text(p) or ""
        pairs = [" ".join(x.split()[:2]) for x in t.splitlines()
                 if re.fullmatch(r"[A-Za-z0-9_.-]+\s+[A-Za-z0-9._+-]+.*", x.strip())]
        return "; ".join(pairs[:8]) or "present"
    if name == "go.mod":
        m = re.search(r"(?m)^go\s+([0-9.]+)\s*$", _read_text(p) or "")
        return f"go {m.group(1)}" if m else "present"
    if name == "rust-toolchain.toml":
        m = re.search(r'(?m)^\s*channel\s*=\s*"([A-Za-z0-9._-]{1,40})"', _read_text(p) or "")
        return f"channel {m.group(1)}" if m else "present"
    if name == "pyproject.toml":
        m = re.search(r'(?m)^\s*requires-python\s*=\s*"([^"\n]{1,40})"', _read_text(p) or "")
        return f"requires-python {m.group(1)}" if m else "present"
    if name == "package.json":
        try:
            eng = json.loads(_read_text(p) or "{}").get("engines") or {}
        except (ValueError, AttributeError):
            eng = {}
        if isinstance(eng, dict) and eng:
            return "engines " + ", ".join(f"{k} {v}" for k, v in list(eng.items())[:4]
                                          if isinstance(v, str) and len(v) < 40)
        return "present"
    if name == ".envrc":
        return "present (direnv; the gateway never runs it)"
    return "present"


def project_files(project: str | None) -> list[dict[str, Any]]:
    if not project or not os.path.isdir(project):
        return []
    out = []
    for n in PROJECT_FILES:
        p = Path(project) / n
        if p.is_file():
            out.append({"file": n, "says": _project_says(p)})
    return out


def host_env_names() -> list[str]:
    """Names (never values) of the variables in Claude Code's environment
    that import_env could take: not credential-looking, not already passed,
    not refused (form.import_env_entry)."""
    from . import form as formmod
    out = []
    for n in sorted(os.environ):
        if n.startswith(("CLAUDE", "GW_", "GATEWAY_")):
            continue
        name, _why = formmod.import_env_entry(n)
        if name is not None:
            out.append(n)
    return out[:120]


# A remote host's inspection (PLAN-v4 phase 7, through gated's remote
# runtime connection): a POSIX script that only reads files and lists
# folders on the host (cat, ls, sed; no rc file is sourced, nothing found is
# run) and prints variable NAMES, never values; gated parses it here.
REMOTE_MAX = 64 * 1024


def remote_inspect_script() -> str:
    files = " ".join(f'"{p}"' for p in SYSTEM_RC) + " " + " ".join(f'"$HOME/{n}"' for n in RC_FILES)
    globs = " ".join(sorted({(p.replace("~/", '"$HOME"/')) for _n, ps in TOOLCHAIN_DIRS for p in ps}))
    return (
        'printf "==GW-HOME %s==\\n" "$HOME"\n'
        f"for f in {files} /etc/paths.d/*; do\n"
        '  [ -f "$f" ] && [ -r "$f" ] || continue\n'
        f'  n=$(wc -c < "$f" 2>/dev/null) || continue; [ "$n" -le {REMOTE_MAX} ] || continue\n'
        '  printf "\\n==GW-FILE %s==\\n" "$f"; cat -- "$f"; printf "\\n==GW-END==\\n"\n'
        "done\n"
        f"for d in {globs}; do\n"
        '  [ -d "$d" ] || continue\n'
        '  printf "==GW-DIR %s==\\n" "$d"; ls -1A -- "$d" 2>/dev/null | head -n 13; '
        'printf "==GW-END==\\n"\n'
        "done\n"
        'printf "==GW-ENV==\\n"; env | sed -n ' + r"'s/^\([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p'"
        + ' | sort -u | head -n 300\n'
        'printf "==GW-END==\\n"\n')


def parse_remote_inspection(text: str, imported: list[str], runtime_path: list[tuple[str, str]],
                            name: str) -> dict[str, Any]:
    """host_inspect's answer for a remote host from the script's output (no
    values: folder names, version words, variable names)."""
    from . import form as formmod
    home = ""
    files: list[tuple[str, str]] = []
    dirs: dict[str, list[str]] = {}
    env: list[str] = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.startswith("==GW-HOME ") and ln.endswith("=="):
            home = ln[len("==GW-HOME "):-2]
        elif ln.startswith("==GW-FILE ") and ln.endswith("=="):
            label = ln[len("==GW-FILE "):-2]
            body = []
            i += 1
            while i < len(lines) and lines[i] != "==GW-END==":
                body.append(lines[i])
                i += 1
            if home and label.startswith(home + "/"):
                label = "~/" + label[len(home) + 1:]
            files.append((label, "\n".join(body)))
        elif ln.startswith("==GW-DIR ") and ln.endswith("=="):
            d = ln[len("==GW-DIR "):-2]
            names = []
            i += 1
            while i < len(lines) and lines[i] != "==GW-END==":
                names.append(lines[i])
                i += 1
            dirs[d] = names
        elif ln == "==GW-ENV==":
            i += 1
            while i < len(lines) and lines[i] != "==GW-END==":
                n = lines[i].strip()
                if n and formmod.import_env_entry(n)[0] is not None:
                    env.append(n)
                i += 1
        i += 1

    def tilde(d: str) -> str:
        return "~/" + d[len(home) + 1:] if home and d.startswith(home + "/") else d

    imp = set(imported)
    login = path_entries(files, home or "/nonexistent", lambda d: d in dirs or d in SYSTEM_DIRS)
    for e in login:
        e["dir"] = tilde(e["dir"])
        e["imported"] = e["dir"] in imp
    tcs = []
    for tname, pats in TOOLCHAIN_DIRS:
        got = []
        for pat in pats:
            want = pat.replace("~", home, 1) if pat.startswith("~/") and home else pat
            for d, names in dirs.items():
                if d == want or ("*" in want and _fnmatch(d, want)):
                    shown = [x for x in names if x and not x.startswith(".")][:MAX_TOOLS]
                    got.append({"dir": tilde(d), "tools": shown, "imported": tilde(d) in imp})
        if got:
            tcs.append({"name": tname, "dirs": got})
    return {
        "ok": True, "host": name, "remote": True,
        "how": (f"read on {name} from files and folder listings only (through the gateway's own "
                "connection): nothing was run or sourced there, and nothing is imported by "
                "looking"),
        "managed": {"path": [{"dir": d, "origin": o} for d, o in runtime_path]},
        "login_path": login[:80], "toolchains": tcs, "env_names": env[:120],
        "to_import": (f"add folders to [hosts.{name}.shell] import_path or names to "
                      f"[hosts.{name}.shell] import_env in ~/.config/gateway/gateway.toml (only "
                      f"when the user asks), then run `gate check {name}`: each import needs the "
                      "user's OK in the gateway's dialog"),
    }


def _fnmatch(d: str, pat: str) -> bool:
    import fnmatch
    return fnmatch.fnmatchcase(d, pat)


def remote_path_plan(eh: Any, host: str, rt: str, line: int | None = None,
                     allowed: bool = True) -> list[tuple[str, str]]:
    """A remote managed shell's PATH with origins (the runtime's tools, the
    host's approved imports, the system folders)."""
    from .daemon.remote import SYSTEM_PATH
    out = [(f"{rt}/env/bin" if rt else "<runtime>/env/bin", "the gateway's remote runtime (bash, tmux)")]
    for p in (getattr(eh, "import_path", []) if allowed else []):
        out.append((p, f"gateway.toml [hosts.{host}.shell] import_path{_line(line)}"))
    out += [(d, "system") for d in SYSTEM_PATH.split(":")]
    return out


def inspect(host: str | None = None, project: str | None = None) -> dict[str, Any]:
    """The host_inspect tool's answer (read-only, scoped: the user's and the
    system's shell rc files, /etc/paths, well-known toolchain folders, the
    project's toolchain files, variable names). Never runs or sources
    anything, never reads the gateway's own folders, never returns a value
    from an rc file other than a folder name."""
    from . import consent, scrub
    from . import form as formmod
    from .daemon import is_local_host
    if not is_local_host(host):
        # a remote host is inspected by gated over its verified connection
        # (RemoteHost.inspect; the gw tool routes it there), never here
        return {"ok": False, "error": "gateway: managed.inspect reads this machine only; a remote "
                "host is inspected through the gateway's daemon (host_inspect with host)"}
    try:
        from . import vault
        data = vault.load() if vault.exists() else None
    except Exception:  # noqa: BLE001
        data = None
    form = formmod.load(last_good=(data or {}).get("form_last_good"))
    eff = consent.compute(form, data)
    from . import policy
    d = policy.decide(eff, "read")
    if d.word is not True:
        return {"ok": False, "error": policy.refuse(d, "host_inspect", "inspecting this machine")}
    imported = set(eff.shell.import_path)
    gw_home, gw_data = _gateway_home_names()
    login = [e for e in login_path_entries()
             if not e["dir"].startswith((gw_home, gw_data))]
    for e in login:
        e["imported"] = e["dir"] in imported or e["dir"] in SYSTEM_DIRS
        e["dir"] = _tilde(e["dir"])
    tc = toolchains()
    for t in tc:
        for d in t["dirs"]:
            d["imported"] = d["dir"] in imported or d["dir"] in SYSTEM_DIRS
            d["dir"] = _tilde(d["dir"])
    out = {
        "ok": True,
        "host": "localhost",
        "how": ("read from files and folder listings only: nothing was run or sourced, and "
                "nothing is imported by looking"),
        "managed": {"mode": eff.shell.managed,
                    "path": [{"dir": _tilde(d), "origin": o} for d, o in path_plan(eff)],
                    "env": [{"name": n, "origin": o} for n, o in env_plan(eff)]},
        "login_path": login[:80],
        "toolchains": tc,
        "project": project_files(project),
        "env_names": host_env_names(),
        "to_import": ("add folders to [shell] import_path or names to [shell] import_env in "
                      "~/.config/gateway/gateway.toml (only when the user asks), then run "
                      "`gate check settings`: each import needs the user's OK in the gateway's "
                      "dialog"),
    }
    text = scrub.scrub_text(json.dumps(out))
    try:
        return json.loads(text)
    except ValueError:
        return {"ok": False, "error": "gateway: host_inspect couldn't build its answer"}
