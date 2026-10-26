"""Account CLI stand-ins: gh, hf, databricks, crane, pijul, az; and `gate with` (SPEC 9.5, 9.6, 9.7).

Each stand-in: loads the form and the vault, ratchets the consent snapshot,
picks the account for the command's owner (accounts.select with effective
rights), checks the credential is bound to the destination, checks the caller
is direct (or the account has scripts = true, SPEC 10), refuses the
subcommands in the table, builds the child's environment from an allowlist
plus the forced endpoint variables and the credential, runs the real binary
from the pixi env by absolute path, streams its output through the scrubber,
and writes one audit line.

`gate with NAME -- CMD` (with_main) runs CMD with the account's credential in
the account's `env` variable (opt-in), the rest of the environment inherited,
output scrubbed, while the account's use and credential policy allow it in
the session's mode ("ask": the approval hook's record, _with_refused).

For the approval hook: `chosen` (the account a command line will use, the
stand-in's own choice) and `ask_accounts` (that account, when it is "ask").
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import sys
import tempfile
from shlex import quote as shlex_quote
from pathlib import Path
from typing import Any

from . import accounts as acctmod
from . import audit, consent, entra, scrub, vault
from . import form as formmod
from . import paths

# Environment a child may inherit (v2 runner.ENV_ALLOW). Everything else, in
# particular the user's tokens, proxies and CA overrides, is dropped.
ENV_ALLOW = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE",
             "LC_MESSAGES", "TMPDIR", "TZ")

# Which optional pixi feature environment a tool lives in (gh is in the default env).
FEATURE = {"hf": "hf", "databricks": "databricks", "crane": "registry", "dvc": "dvc"}
FEATURE_SIZE = {"hf": "about 54 MB", "databricks": "about 60 MB", "registry": "about 40 MB",
                "dvc": "about 120 MB"}

class CliError(Exception):
    """A refusal before anything ran (message starts with gateway:)."""


# ---------------------------------------------------------------------------
# Ancestry: direct vs scripts (SPEC 10)
# ---------------------------------------------------------------------------


def is_direct(tool: str, entry_scripts: bool = False) -> tuple[bool, str]:
    """(allowed, culprit) from ancestry.is_direct (SPEC 10), the one walker.
    Any error counts as not direct (fail closed): allowed only with
    scripts = true."""
    try:
        from . import ancestry
        return ancestry.is_direct(tool, entry_scripts)
    except Exception:  # noqa: BLE001
        return bool(entry_scripts), "?"


# ---------------------------------------------------------------------------
# Binaries and the child environment
# ---------------------------------------------------------------------------


def _feature_bin(feature: str) -> Path:
    return paths.env_dir() / ".pixi" / "envs" / feature / "bin"


def resolve_tool(name: str, feature: str | None = None, install: bool = True) -> str:
    """The absolute path of a tool's real binary, from the pixi env (never
    PATH). A feature tool is installed on first use (faked in tests)."""
    o = paths.testing.active()
    if o is not None and o.tools and name in o.tools:
        return o.tools[name]
    if feature:
        fb = paths.testing.get("feature_bins") or {}
        if feature in fb:
            cand = Path(fb[feature]) / name
            if cand.exists():
                return str(cand)
        cand = _feature_bin(feature) / name
        if cand.is_file() and os.access(cand, os.X_OK):
            return str(cand)
        if install and install_feature(feature):
            cand = _feature_bin(feature) / name
            if cand.is_file() and os.access(cand, os.X_OK):
                return str(cand)
        raise CliError(f"gateway: {name} isn't installed for the gateway and couldn't be set up; "
                       "try again in a minute")
    return paths.tool(name)


def install_feature(feature: str) -> bool:
    """Install an optional pixi feature env on first use, with one stderr line.
    Tests provide testing.override(install_feature=callable)."""
    hook = paths.testing.get("install_feature")
    if callable(hook):
        print(f"gateway: first use of {feature}: installing ({FEATURE_SIZE.get(feature, 'a bit')})",
              file=sys.stderr)
        return bool(hook(feature))
    if paths.testing.active() is not None:
        return False  # never run real pixi in a test
    envd = paths.env_dir()
    manifest = envd / "pixi.toml"
    if not manifest.exists():
        return False
    print(f"gateway: first use of {feature}: installing ({FEATURE_SIZE.get(feature, 'a bit')})",
          file=sys.stderr)
    pixi = _find_pixi()
    if not pixi:
        return False
    try:
        r = subprocess.run([pixi, "install", "--locked", "--manifest-path", str(manifest),
                            "-e", feature], capture_output=True, timeout=1800,
                           stdin=subprocess.DEVNULL)
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _find_pixi() -> str | None:
    import shutil
    p = shutil.which("pixi")
    if p:
        return p
    for d in (os.path.expanduser("~/.pixi/bin"), os.path.expanduser("~/.local/bin"),
              "/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin",
              "/home/linuxbrew/.linuxbrew/bin"):
        c = Path(d) / "pixi"
        if c.is_file() and os.access(c, os.X_OK):
            return str(c)
    return None


def child_env(extra: dict[str, str]) -> dict[str, str]:
    """Allowlisted base environment plus the tool's own variables. PATH puts
    the pixi env first so a nested git/ssh is the gateway's."""
    env = {k: v for k, v in os.environ.items() if k in ENV_ALLOW}
    try:
        base = f"{paths.env_bin()}:{paths.bin_dir()}:/usr/bin:/bin:/usr/sbin:/sbin"
    except Exception:  # noqa: BLE001
        base = env.get("PATH", "/usr/bin:/bin")
    env["PATH"] = base
    env.setdefault("HOME", str(paths.user_home()))
    env.update(extra)
    return env


# ---------------------------------------------------------------------------
# Shared selection
# ---------------------------------------------------------------------------


_UNREADABLE: dict[str, str] = {}


def _load() -> tuple[formmod.Form, Any, dict[str, Any]]:
    """The form, the effective rights in the session's mode (the one the hook
    recorded for a command Claude typed, modes.current_for; else the
    modeless rule) and the vault. A vault that can't be read (locked) still
    classifies through the configured list; its refusal text is kept for a
    configured target (_UNREADABLE)."""
    from . import modes
    _UNREADABLE.clear()
    locked = False
    try:
        data = vault.load()
    except vault.VaultLocked as e:
        data, locked = None, True
        _UNREADABLE["message"] = str(e)
    except vault.VaultError as e:
        data = None
        _UNREADABLE["message"] = f"gateway: the vault can't be read ({e}); run gate status"
    form = consent.load_form(data)
    if data is not None:
        try:
            consent.ratchet(form)
            data = vault.load()
        except Exception:  # noqa: BLE001
            pass
    try:
        mode = modes.current_for("standin")
    except Exception:  # noqa: BLE001 - the modeless rule
        mode = None
    _CALL["mode"] = modes.audit_word(mode)      # for its audit lines (lead decision 19.8)
    eff = consent.compute(form, data, mode, locked=locked)
    data = data if data is not None else vault.empty()
    try:
        scrub.note_vault(data)
    except Exception:  # noqa: BLE001
        pass
    return form, eff, data


# The command this stand-in call serves (main sets it): an account that is
# "ask" is used only with the approval hook's record of this very command
# (asks.standin; lead decision 19.14).
_CALL: dict[str, Any] = {}
CLI_ASK_SCRIPT = ("gateway: {what} is set to \"ask\", and Claude Code can only ask about a "
                  "command Claude runs itself; run `{tool} ...` as its own command (not inside a "
                  "script, sh -c or a wrapper).")


# "use" or "credential" when an account is "ask" in a mode (consent's, so
# the approval hook and SessionStart need not import this module)
_ask_verb = consent.account_ask_verb


def _unasked(name: str, verb: str) -> str | None:
    """None when Claude Code asked about this very command for account
    `name`: a command Claude typed (ancestry.typed_by_claude) with the
    approval hook's record of it (asks.standin); else why it can't be used."""
    from . import ancestry, asks
    tool, argv = str(_CALL.get("tool", "")), list(_CALL.get("argv", []))
    phrase = consent.ask_phrase(name, verb)
    try:
        typed, culprit = ancestry.typed_by_claude()
    except Exception:  # noqa: BLE001 - fail closed
        typed, culprit = False, "?"
    if not typed:
        if culprit == ancestry.CHECKPOINT:
            return consent.job_ask_message([phrase])
        if culprit == ancestry.TERMINAL:
            return consent.pane_ask_message([phrase])
        return CLI_ASK_SCRIPT.format(what=phrase, tool=tool)
    got = asks.standin(tool, argv, ("accounts", name))
    return None if got == "ok" else asks.refusal(got, [phrase], f"{tool} ...")


def _select(kind: str | tuple[str, ...], host: str, owner: str | None, form: formmod.Form,
            eff: Any, data: dict[str, Any]) -> acctmod.Selection:
    """accounts.select in the session's mode, as if Claude Code had asked
    about every account that is "ask" there; the one it chooses then needs
    that ask proved (_unasked), else the selection is that refusal."""
    mode = getattr(eff, "mode", None)
    kinds = (kind,) if isinstance(kind, str) else tuple(kind)
    asking = {n for n, a in form.accounts.items() if a.kind in kinds and _ask_verb(eff, n, mode)}
    sel = acctmod.select(kind, host, owner, form, effective=eff, vault=data, env=os.environ,
                         mode=mode, asked=asking)
    if sel.account is not None and sel.error is None and sel.account.name in asking:
        why = _unasked(sel.account.name, _ask_verb(eff, sel.account.name, mode) or "use")
        if why:
            return acctmod.Selection(candidates=list(sel.candidates or []), error=why)
    return sel


def _check_direct(tool: str, account: formmod.Account, eff: Any) -> None:
    ea = eff.accounts.get(account.name)
    scripts = bool(ea and ea.scripts)
    ok, culprit = is_direct(tool, scripts)
    if not ok:
        who = formmod.safe(culprit) or "a program Claude started"
        from . import ancestry
        if culprit in ("", ancestry.UNTRACED):
            who = ancestry.UNTRACED_WHO
        raise CliError(f"gateway: {tool} started by {who} got no credential (only Claude's own "
                       f"commands do); run it as its own command, or set scripts = true for "
                       f"{account.name}")


def _audit_mode() -> str:
    """The mode for this call's audit lines (lead decision 19.8): the one
    _load resolved with, else the recorded mode, else "modeless"."""
    from . import modes
    return modes.standin_audit_mode(_CALL)


def _refuse(tool: str, target: str | None, msg: str) -> int:
    audit.refusal(tool, target, msg, mode=_audit_mode())
    print(msg, file=sys.stderr)
    return 2


def _run(tool: str, real: str, argv: list[str], env: dict[str, str], secrets: list[str],
         account: str, target: str, users: tuple[str, ...] = (), cwd: str | None = None) -> int:
    audit.use(tool, target, account, argv=[tool, *argv], secrets=secrets, mode=_audit_mode())
    try:
        return scrub.run([real, *argv], secrets, env=env, cwd=cwd, users=users)
    except OSError as e:
        print(f"gateway: couldn't run {tool} ({type(e).__name__})", file=sys.stderr)
        return 2


# ---------------------------------------------------------------------------
# Owner extraction per tool (SPEC 9.6)
# ---------------------------------------------------------------------------

_OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")


def _flag_value(argv: list[str], *names: str) -> str | None:
    for i, a in enumerate(argv):
        for n in names:
            if a == n and i + 1 < len(argv):
                return argv[i + 1]
            if a.startswith(n + "="):
                return a.split("=", 1)[1]
    return None


def gh_owner(argv: list[str], cwd: str | None) -> str | None:
    repo = _flag_value(argv, "-R", "--repo")
    if repo:
        o = acctmod.owner_from_url(repo, "github")
        if o and o[1]:
            return o[1]
        return repo.split("/")[-2] if repo.count("/") >= 1 else repo.split("/")[0]
    for a in argv[1:]:
        if a.startswith(("http://", "https://", "git@", "ssh://")):
            o = acctmod.owner_from_url(a, "github")
            if o and o[1]:
                return o[1]
    top = argv[0] if argv else ""
    if top == "api":
        for a in argv[1:]:
            parts = a.lstrip("/").split("/")
            if len(parts) >= 2 and parts[0] in ("repos", "orgs", "users") and _OWNER.fullmatch(parts[1]):
                return parts[1]
    if top in ("repo", "pr", "issue", "release", "run", "workflow", "secret", "gist") and len(argv) >= 3:
        cand = argv[2]
        if not cand.startswith("-") and "/" in cand:
            o = cand.split("/")[0]
            if _OWNER.fullmatch(o):
                return o
    return _remote_owner(cwd, "github")


def _remote_owner(cwd: str | None, kind: str) -> str | None:
    """The owner of the cwd's upstream remote, else origin."""
    where = _remote_where(cwd, kind)
    return where[1] if where else None


def _remote_where(cwd: str | None, kind: str) -> tuple[str, str] | None:
    """(host, owner) of the cwd's upstream remote, else origin."""
    if not cwd:
        return None
    git = _system_git()
    if not git:
        return None
    for ref in ("@{upstream}", "origin"):
        remote = ref if ref == "origin" else None
        try:
            if ref == "@{upstream}":
                rp = subprocess.run([git, "-C", cwd, "rev-parse", "--abbrev-ref", "@{upstream}"],
                                    capture_output=True, text=True, timeout=5,
                                    stdin=subprocess.DEVNULL)
                remote = rp.stdout.strip().split("/")[0] if rp.returncode == 0 else None
            if not remote:
                continue
            u = subprocess.run([git, "-C", cwd, "remote", "get-url", remote],
                               capture_output=True, text=True, timeout=5, stdin=subprocess.DEVNULL)
            if u.returncode == 0:
                o = acctmod.owner_from_url(u.stdout.strip(), kind)
                if o and o[1]:
                    return (o[0] or "").lower(), o[1]
        except (OSError, subprocess.TimeoutExpired):
            return None
    return None


def _system_git() -> str | None:
    from . import envfile
    try:
        return envfile.user_tool("git")
    except Exception:  # noqa: BLE001
        return None


def hf_owner(argv: list[str]) -> str | None:
    for a in argv[1:]:
        if not a.startswith("-") and "/" in a and "://" not in a and not a.startswith((".", "/", "~")):
            return acctmod.owner_from_path(a, "huggingface")
    return None


def crane_owner(argv: list[str]) -> tuple[str | None, str | None]:
    """(registry host, owner) from the first image reference."""
    for a in argv[1:]:
        if a.startswith("-"):
            continue
        ref = a.split("@")[0].split(":")[0]
        parts = ref.split("/")
        if len(parts) >= 2 and ("." in parts[0] or ":" in parts[0] or parts[0] == "localhost"):
            return parts[0].lower(), parts[1]
        if len(parts) >= 2:
            return None, parts[0]
    return None, None


# ---------------------------------------------------------------------------
# gh
# ---------------------------------------------------------------------------

GH_REFUSED_TOP = {"extension", "extensions", "ext"}
# git-credential: gh's hidden credential-helper mode prints password=<token>.
GH_AUTH_REFUSED = ("login", "logout", "refresh", "setup-git", "git-credential")


def _gh_show_token(args: list[str]) -> bool:
    """Does `gh auth status ARGS` ask for the token? Covers --show-token,
    --show-token=VALUE, -t, -t=VALUE and -t inside a short-flag cluster
    (-at); -h takes a value, so letters after it in a cluster are that value."""
    for a in args:
        if a == "--":
            break
        if a == "--show-token" or a.startswith("--show-token="):
            return True
        if a.startswith("-") and not a.startswith("--"):
            for c in a[1:]:
                if c == "t":
                    return True
                if c in ("h", "="):
                    break
    return False


def _gh_refused(argv: list[str]) -> str | None:
    if not argv or argv[0].startswith("-"):
        return "gateway: put the gh command first, e.g. gh pr list"
    top = argv[0]
    if top.startswith("!"):
        return "gateway: gh aliases that run a shell command aren't run through the gateway"
    if top in GH_REFUSED_TOP:
        return f"gateway: 'gh {top}' isn't run through the gateway (it runs other programs)"
    sub = argv[1] if len(argv) > 1 else ""
    if top == "auth":
        # gh (cobra) finds the subcommand even after flags (gh auth -h HOST token),
        # so look at every word, not only argv[1]. No auth subcommand takes a
        # positional argument, so a refused name anywhere is the subcommand.
        words = [a for a in argv[1:] if not a.startswith("-")]
        for w in words:
            if w in GH_AUTH_REFUSED:
                return "gateway: the gateway manages GitHub sign-in; 'gh auth " + w + "' isn't run here"
        if "token" in words:
            return "gateway: 'gh auth token' would print the token; it isn't run here"
        if _gh_show_token(argv[1:]):
            return "gateway: 'gh auth status --show-token' would print the token; drop --show-token"
    if top == "config" and sub == "set":
        return "gateway: 'gh config set' isn't run through the gateway"
    return None


_GH_HOSTISH = re.compile(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?::[0-9]{1,5})?\Z")
_SCP_URL = re.compile(r"[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:")


def _gh_url_host(v: str) -> str | None:
    if "://" in v or _SCP_URL.match(v):
        o = acctmod.owner_from_url(v, "github")
        return o[0] if o else "an unreadable host"
    return None


def _gh_repo_host(v: str) -> str | None:
    """The host of a `-R [HOST/]OWNER/REPO` value (or a URL), else None."""
    h = _gh_url_host(v)
    if h:
        return h
    parts = v.split("/")
    return parts[0].lower() if len(parts) >= 3 and parts[0] else None


def gh_hosts(argv: list[str]) -> list[str]:
    """Every host a gh command line names, to which gh would send the token it
    holds (GH_ENTERPRISE_TOKEN goes to any host but github.com, GH_TOKEN to
    any *.ghe.com): `--hostname`, `auth -h`, `-R/--repo [HOST/]OWNER/REPO` or
    a URL, URL arguments (`gh api https://h/x`, `gh pr view https://h/o/r/pull/1`)
    and `HOST/OWNER/REPO` arguments."""
    out: list[str] = []
    top = argv[0] if argv else ""
    pos: list[str] = []
    i = 1
    while i < len(argv):
        a = argv[i]
        nxt = argv[i + 1] if i + 1 < len(argv) else ""
        if a == "--":
            pos += argv[i + 1:]
            break
        name, eq, val = a.partition("=")
        if name == "--hostname" or (top == "auth" and name == "-h"):
            out.append(val if eq else nxt)
            i += 1 if eq else 2
            continue
        if top == "auth" and a.startswith("-h") and not a.startswith("--") and len(a) > 2:
            out.append(a[2:])
            i += 1
            continue
        if name in ("-R", "--repo"):
            h = _gh_repo_host(val if eq else nxt)
            if h:
                out.append(h)
            i += 1 if eq else 2
            continue
        if a.startswith("-R") and not a.startswith("--") and len(a) > 2:
            h = _gh_repo_host(a[2:])
            if h:
                out.append(h)
        elif not a.startswith("-"):
            pos.append(a)
        i += 1
    for p in pos:
        h = _gh_url_host(p)
        if h is None and p.count("/") == 2 and _GH_HOSTISH.match(p.split("/")[0]):
            h = p.split("/")[0].lower()
        if h:
            out.append(h)
    return out


def _gh_host_refused(argv: list[str], a: formmod.Account, host: str,
                     data: dict[str, Any]) -> str | None:
    """A host on the command line other than the account's (or its api. host)
    and bound to it: refused, since gh would send the account's token there."""
    ok = {host.lower(), f"api.{host.lower()}"}
    for h in gh_hosts(argv):
        hl = (h or "").strip().lower().rstrip(".")
        if hl in ok and consent.bound_ok(data, a.name, hl):
            continue
        shown = formmod.safe(h) or "another host"
        return (f"gateway: gh would send {a.name}'s token to {shown}, which isn't its host "
                f"({host}); drop --hostname or the host part, or use an account for that host "
                f"(GATE_ACCOUNT=NAME)")
    return None


def _gh_pick(argv: list[str], form: formmod.Form, eff: Any, data: dict[str, Any],
             cwd: str | None, select: Any) -> acctmod.Selection:
    """The github account a gh command line uses (`select`: _select, or the
    approval hook's probe in `chosen`): each github host the form knows
    (github.com first), so a single GHES account is found too; GATE_ACCOUNT
    is handled inside select."""
    owner = gh_owner(argv, cwd)
    gh_hosts = sorted({a.host or "github.com" for a in form.accounts.values() if a.kind == "github"},
                      key=lambda h: (0 if h == "github.com" else 1, h))
    sel = select("github", "github.com", owner, form, eff, data)
    for h in (gh_hosts or ["github.com"]):
        s = select("github", h, owner, form, eff, data)
        if s.account is not None or s.error:
            return s
        sel = s
    return sel


def _gh(argv: list[str], form: formmod.Form, eff: Any, data: dict[str, Any],
        cwd: str | None) -> int:
    refuse = _gh_refused(argv)
    if refuse:
        return _refuse("gh", None, refuse)
    sel = _gh_pick(argv, form, eff, data, cwd, _select)
    if sel.error:
        return _refuse("gh", "github.com", sel.error)
    if sel.account is None:
        print(sel.note or "gateway: no GitHub account", file=sys.stderr)
        return 2
    a = sel.account
    host = a.host or "github.com"
    if not consent.bound_ok(data, a.name, host):
        return _refuse("gh", host, f"gateway: {a.name}'s token isn't bound to {host}; run gate "
                       f"check {a.name} while the user is here")
    other = _gh_host_refused(argv, a, host, data)
    if other:
        return _refuse("gh", host, other)
    _check_direct("gh", a, eff)
    rec = (data.get("accounts") or {}).get(a.name) or {}
    tok = rec.get("token") or {}
    if tok.get("stale"):
        return _refuse("gh", host, acctmod.stale_token_message(a.name))
    token = tok.get("value")
    if not token:
        return _refuse("gh", host, f"gateway: {a.name} has no token; run gate check {a.name}")
    real = resolve_tool("gh")
    bare = host.split(":", 1)[0]
    enterprise = not (bare == "github.com" or bare.endswith(".ghe.com"))
    tmp = tempfile.mkdtemp(prefix="gw-gh-", dir=paths.run_dir())
    os.chmod(tmp, 0o700)
    env = child_env({"GH_HOST": host, "GH_CONFIG_DIR": tmp, "GH_PROMPT_DISABLED": "1",
                     "GH_NO_UPDATE_NOTIFIER": "1", "GH_PAGER": "cat", "GH_BROWSER": "false",
                     "BROWSER": "false", "NO_COLOR": "1"})
    env["GH_ENTERPRISE_TOKEN" if enterprise else "GH_TOKEN"] = token
    try:
        return _run("gh", real, argv, env, [token], a.name, host,
                    users=("x-access-token",), cwd=cwd)
    finally:
        _rmtree(tmp)


# ---------------------------------------------------------------------------
# hf
# ---------------------------------------------------------------------------


def _hf_refused(argv: list[str]) -> str | None:
    if not argv or argv[0].startswith("-"):
        return "gateway: put the hf command first, e.g. hf download org/model"
    if argv[0] == "env":
        return "gateway: 'hf env' isn't run through the gateway"
    if argv[:2] == ["auth", "login"] or argv[:2] == ["auth", "logout"] or argv[:2] == ["auth", "token"]:
        return "gateway: the gateway manages Hugging Face sign-in; 'hf " + " ".join(argv[:2]) + \
               "' isn't run here"
    if any(a == "--token" or a.startswith("--token=") or a.startswith("--endpoint") for a in argv):
        return "gateway: the account decides the token and endpoint; drop --token/--endpoint"
    return None


def _hf_target(argv: list[str]) -> tuple[str, str, str | None]:
    """(kind, host, owner) hf's account is chosen by."""
    return "huggingface", "huggingface.co", hf_owner(argv)


def _hf(argv: list[str], form: formmod.Form, eff: Any, data: dict[str, Any], cwd: str | None) -> int:
    refuse = _hf_refused(argv)
    if refuse:
        return _refuse("hf", None, refuse)
    sel = _select(*_hf_target(argv), form, eff, data)
    if sel.error:
        return _refuse("hf", "huggingface.co", sel.error)
    if sel.account is None:
        print(sel.note or "gateway: no Hugging Face account", file=sys.stderr)
        return 2
    a = sel.account
    if not consent.bound_ok(data, a.name, "huggingface.co"):
        return _refuse("hf", "huggingface.co", f"gateway: {a.name}'s token isn't bound to "
                       f"huggingface.co; run gate check {a.name} while the user is here")
    _check_direct("hf", a, eff)
    rec = (data.get("accounts") or {}).get(a.name) or {}
    tok = rec.get("token") or {}
    if tok.get("stale"):
        return _refuse("hf", "huggingface.co", acctmod.stale_token_message(a.name))
    token = tok.get("value")
    if not token:
        return _refuse("hf", "huggingface.co", f"gateway: {a.name} has no token; run gate check {a.name}")
    real = resolve_tool("hf", feature="hf")
    cache = os.environ.get("HF_HUB_CACHE") or str(
        Path(os.environ.get("HF_HOME") or (paths.user_home() / ".cache" / "huggingface")) / "hub")
    tmp = tempfile.mkdtemp(prefix="gw-hf-", dir=paths.run_dir())
    os.chmod(tmp, 0o700)
    # The token in a 0600 file of the call's 0700 folder (HF_TOKEN_PATH), not
    # in HF_TOKEN: a process's environment is shown by `ps eww` to the same
    # user for as long as it runs (round 3). Still same-user readable.
    os.mkdir(f"{tmp}/hf", 0o700)
    fd = os.open(f"{tmp}/hf/token", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(token)
    env = child_env({"HF_ENDPOINT": "https://huggingface.co",
                     "HF_HOME": f"{tmp}/hf", "HF_TOKEN_PATH": f"{tmp}/hf/token",
                     "HF_STORED_TOKENS_PATH": f"{tmp}/hf/stored_tokens", "HF_HUB_CACHE": cache,
                     "HF_HUB_DISABLE_TELEMETRY": "1", "HF_HUB_DISABLE_PROGRESS_BARS": "1",
                     "HF_HUB_DISABLE_UPDATE_CHECK": "1", "NO_COLOR": "1"})
    try:
        return _run("hf", real, argv, env, [token], a.name, "huggingface.co", cwd=cwd)
    finally:
        _rmtree(tmp)


# ---------------------------------------------------------------------------
# databricks
# ---------------------------------------------------------------------------

DB_REFUSED_TOP = {"configure", "completion"}


def _db_refused(argv: list[str]) -> str | None:
    if not argv or argv[0].startswith("-"):
        return "gateway: put the databricks command first, e.g. databricks clusters list"
    if argv[0] in DB_REFUSED_TOP:
        return f"gateway: 'databricks {argv[0]}' isn't run through the gateway"
    if argv[:2] == ["auth", "login"] or argv[:2] == ["auth", "token"]:
        return "gateway: the gateway manages Databricks sign-in; 'databricks " + " ".join(argv[:2]) + \
               "' isn't run here"
    return None


def _db_workspace(argv: list[str], account: formmod.Account, cwd: str | None) -> str | None:
    """The workspace host, from DATABRICKS_HOST / --profile value / databricks.yml,
    defaulting to the single listed workspace."""
    def host_of(v: str) -> str:
        return v.split("://", 1)[-1].split("/", 1)[0].lower()
    env_h = os.environ.get("DATABRICKS_HOST")
    if env_h:
        return host_of(env_h)
    pf = _flag_value(argv, "--profile", "-p")
    if pf:
        return None  # a named profile the gateway can't map; caller must name the host
    if cwd:
        y = Path(cwd) / "databricks.yml"
        try:
            m = re.search(r"host:\s*(\S+)", y.read_text())
            if m:
                return host_of(m.group(1))
        except OSError:
            pass
    dbx = account.databricks
    if len(dbx) == 1:
        return dbx[0].lower()
    return None


def _db_ws(argv: list[str], form: formmod.Form, cwd: str | None) -> str | None:
    """The workspace host a databricks command line goes to, when an azure
    account lists it (the account is chosen by the workspace host it
    lists); else None."""
    azs = [a for a in form.accounts.values() if a.kind == "azure"]
    listed = {h.lower() for a in azs for h in a.databricks}
    for a in azs:
        cand = _db_workspace(argv, a, cwd)
        if cand and cand in listed:
            return cand
    return None


def _databricks(argv: list[str], form: formmod.Form, eff: Any, data: dict[str, Any],
                cwd: str | None) -> int:
    refuse = _db_refused(argv)
    if refuse:
        return _refuse("databricks", None, refuse)
    ws = _db_ws(argv, form, cwd)
    if not ws:
        return _refuse("databricks", None, "gateway: name the workspace with DATABRICKS_HOST (one "
                       "of the azure account's databricks hosts)")
    sel = _select("azure", ws, None, form, eff, data)
    if sel.error:
        return _refuse("databricks", ws, sel.error)
    if sel.account is None:
        print(sel.note or f"gateway: no azure account for {ws}", file=sys.stderr)
        return 2
    a = sel.account
    if not consent.bound_ok(data, a.name, ws):
        return _refuse("databricks", ws, f"gateway: {a.name} isn't bound to {ws}; run gate check "
                       f"{a.name} while the user is here")
    _check_direct("databricks", a, eff)
    try:
        token = entra.access_token(a.name, "databricks", mode=_audit_mode())
    except entra.EntraError as e:
        return _refuse("databricks", ws, str(e) if str(e).startswith("gateway:")
                       else f"gateway: {e}")
    real = resolve_tool("databricks", feature="databricks")
    tmp = tempfile.mkdtemp(prefix="gw-db-", dir=paths.run_dir())
    os.chmod(tmp, 0o700)
    cfg = Path(tmp) / "databrickscfg"
    cfg.write_text("")
    env = child_env({"DATABRICKS_HOST": f"https://{ws}", "DATABRICKS_TOKEN": token,
                     "DATABRICKS_AUTH_TYPE": "pat", "DATABRICKS_CONFIG_FILE": str(cfg),
                     "HOME": tmp, "NO_COLOR": "1"})
    try:
        return _run("databricks", real, argv, env, [token], a.name, ws, cwd=cwd)
    finally:
        _rmtree(tmp)


# ---------------------------------------------------------------------------
# crane
# ---------------------------------------------------------------------------


def _crane(argv: list[str], form: formmod.Form, eff: Any, data: dict[str, Any], cwd: str | None) -> int:
    if not argv or argv[0].startswith("-"):
        return _refuse("crane", None, "gateway: put the crane command first, e.g. crane ls ghcr.io/org/img")
    if argv[0] == "auth":
        return _refuse("crane", None, "gateway: 'crane auth' isn't run through the gateway")
    host, owner = crane_owner(argv)
    if not host:
        return _refuse("crane", None, "gateway: name a full image, e.g. ghcr.io/org/image")
    user, secret, account, kinds = _crane_credential(host, owner, form, eff, data)
    if isinstance(user, int):
        return user  # a refusal code
    real = resolve_tool("crane", feature="registry")
    tmp = tempfile.mkdtemp(prefix="gw-crane-", dir=paths.run_dir())
    os.chmod(tmp, 0o700)
    dconf = Path(tmp) / "docker"
    dconf.mkdir()
    auth = base64.b64encode(f"{user}:{secret}".encode()).decode()
    (dconf / "config.json").write_text(json.dumps({"auths": {host: {"auth": auth}}}))
    (dconf / "config.json").chmod(0o600)
    env = child_env({"DOCKER_CONFIG": str(dconf), "HOME": tmp, "NO_COLOR": "1"})
    try:
        return _run("crane", real, argv, env, [secret, auth], account, host,
                    users=(user,), cwd=cwd)
    finally:
        _rmtree(tmp)


def _crane_target(host: str, owner: str | None) -> tuple[str, str, str | None]:
    """(kind, host, owner) the account for an image on `host` is chosen by:
    ghcr.io -> a github account by the image's owner; *.azurecr.io -> an
    azure account by the registry; else a registry account."""
    bare = host.split(":", 1)[0].lower()
    if bare == "ghcr.io":
        return "github", "ghcr.io", owner
    if bare.endswith(".azurecr.io"):
        return "azure", host, None
    return "registry", host, owner


def _crane_credential(host: str, owner: str | None, form: formmod.Form, eff: Any,
                      data: dict[str, Any]):
    """(user, secret, account, kind). The image owner picks the account:
    ghcr.io -> a github account; *.azurecr.io -> an azure ACR exchange; else a
    registry account. Returns an int refusal code in the first slot on error."""
    bare = host.split(":", 1)[0].lower()
    if bare == "ghcr.io":
        sel = _select(*_crane_target(host, owner), form, eff, data)
        if sel.error:
            return _refuse("crane", host, sel.error), "", "", ""
        if sel.account is None:
            print(sel.note or "gateway: no GitHub account for ghcr.io", file=sys.stderr)
            return 2, "", "", ""
        a = sel.account
        if not consent.bound_ok(data, a.name, "ghcr.io"):
            return _refuse("crane", host, f"gateway: {a.name} isn't bound to ghcr.io; run gate "
                           f"check {a.name}"), "", "", ""
        _check_direct("crane", a, eff)
        tok = ((data.get("accounts") or {}).get(a.name) or {}).get("token") or {}
        if not tok.get("value"):
            return _refuse("crane", host, f"gateway: {a.name} has no token; run gate check {a.name}"), "", "", ""
        return (a.login or "x-access-token"), tok["value"], a.name, "github"
    if bare.endswith(".azurecr.io"):
        sel = _select(*_crane_target(host, owner), form, eff, data)
        if sel.error:
            return _refuse("crane", host, sel.error), "", "", ""
        if sel.account is None:
            print(sel.note or f"gateway: no azure account for {host}", file=sys.stderr)
            return 2, "", "", ""
        a = sel.account
        if not consent.bound_ok(data, a.name, host):
            return _refuse("crane", host, f"gateway: {a.name} isn't bound to {host}; run gate "
                           f"check {a.name}"), "", "", ""
        _check_direct("crane", a, eff)
        try:
            rt = entra.acr_token(host, a.name, mode=_audit_mode())
        except entra.EntraError as e:
            return _refuse("crane", host, str(e) if str(e).startswith("gateway:") else f"gateway: {e}"), "", "", ""
        return entra.ACR_USER, rt, a.name, "azure"
    sel = _select(*_crane_target(host, owner), form, eff, data)
    if sel.error:
        return _refuse("crane", host, sel.error), "", "", ""
    if sel.account is None:
        print(sel.note or f"gateway: no registry account for {host}", file=sys.stderr)
        return 2, "", "", ""
    a = sel.account
    if not consent.bound_ok(data, a.name, host):
        return _refuse("crane", host, f"gateway: {a.name} isn't bound to {host}; run gate check "
                       f"{a.name}"), "", "", ""
    _check_direct("crane", a, eff)
    tok = ((data.get("accounts") or {}).get(a.name) or {}).get("token") or {}
    if not tok.get("value"):
        return _refuse("crane", host, f"gateway: {a.name} has no token; run gate check {a.name}"), "", "", ""
    return (a.login or "user"), tok["value"], a.name, "registry"


# ---------------------------------------------------------------------------
# pijul
# ---------------------------------------------------------------------------

PIJUL_REFUSED = {"identity", "id", "key", "client"}


def _pijul_target(form: formmod.Form) -> tuple[str, str, None]:
    """(kind, host, owner) pijul's account is chosen by: the first pijul
    account's host."""
    pijuls = [a for a in form.accounts.values() if a.kind == "pijul"]
    return "pijul", (pijuls[0].host if pijuls else "nest.pijul.com"), None


def _pijul(argv: list[str], form: formmod.Form, eff: Any, data: dict[str, Any], cwd: str | None) -> int:
    if not argv or argv[0].startswith("-"):
        return _refuse("pijul", None, "gateway: put the pijul command first, e.g. pijul log")
    if argv[0] in PIJUL_REFUSED:
        return _refuse("pijul", None, f"gateway: 'pijul {argv[0]}' is managed by the gateway")
    if any(a == "--config" or a.startswith("--config=") for a in argv):
        return _refuse("pijul", None, "gateway: the gateway sets pijul's config; drop --config")
    sel = _select(*_pijul_target(form), form, eff, data)
    if sel.error:
        return _refuse("pijul", None, sel.error)
    if sel.account is None:
        print(sel.note or "gateway: no Pijul account", file=sys.stderr)
        return 2
    a = sel.account
    host = a.host or "nest.pijul.com"
    if not consent.bound_ok(data, a.name, host):
        return _refuse("pijul", host, f"gateway: {a.name} isn't bound to {host}; run gate check {a.name}")
    _check_direct("pijul", a, eff)
    rec = (data.get("accounts") or {}).get(a.name) or {}
    key = (rec.get("ssh_key") or {}).get("private")
    if not key:
        return _refuse("pijul", host, f"gateway: {a.name} has no SSH key; run gate check {a.name}")
    real = _pijul_bin()
    if not real:
        print(_build_pijul(), file=sys.stderr)
        return 75
    hostkeys = rec.get("host_keys") or vault.builtin_host_keys(host)
    return _run_pijul(real, argv, a, rec, key, hostkeys, cwd)


def _pijul_bin() -> str | None:
    o = paths.testing.active()
    if o is not None and o.tools and "pijul" in o.tools:
        return o.tools["pijul"]
    root = paths.data_dir() / "pijul"
    cand = root / "bin" / "pijul"
    if not (cand.is_file() and os.access(cand, os.X_OK)):
        return None
    # The binary finds its libraries through an rpath into the pijul env it
    # was built with; once that env is cleaned up (a newer lock), rebuild.
    try:
        env = (root / ".built-with").read_text().strip()
    except OSError:
        return str(cand)
    return str(cand) if not env or os.path.isdir(env) else None


PIJUL_BUILD_STALE = 3 * 3600      # a build dir older than this is from a dead build


def _build_pijul() -> str:
    """pijul isn't on conda-forge: build it on first use (SPEC 9.5), in the
    background, with the pijul feature env's Rust (pixi.toml's install-pijul
    task, CARGO_INSTALL_ROOT = <data>/pijul). Returns the line to print; the
    stand-in exits 75 (try again later). Tests: testing.override(
    pijul_build=callable) is called instead; without it nothing is built."""
    import time as _time
    hook = paths.testing.get("pijul_build")
    data = paths.data_dir()
    root = data / "pijul"
    lock = data / "pijul.building"
    log = root / "build.log"
    try:
        age = _time.time() - lock.stat().st_mtime
        if age < PIJUL_BUILD_STALE:
            return (f"gateway: pijul is still being built for the gateway (started "
                    f"{int(age // 60)} min ago); try again in a few minutes")
        import shutil
        shutil.rmtree(lock, ignore_errors=True)
    except OSError:
        pass
    failed = log.exists()
    if callable(hook):
        hook(root)
        return "gateway: first use of pijul: building it in the background (test)"
    if paths.testing.active() is not None:
        return "gateway: pijul isn't installed for the gateway (tests never build it)"
    manifest = paths.env_dir() / "pixi.toml"
    pixi = _find_pixi()
    if not manifest.exists() or not pixi:
        return "gateway: pijul isn't installed for the gateway and pixi can't build it here"
    try:
        root.mkdir(parents=True, exist_ok=True)
        lock.mkdir()
    except FileExistsError:
        return "gateway: pijul is being built for the gateway; try again in a few minutes"
    except OSError:
        return "gateway: pijul isn't installed for the gateway and couldn't be built here"
    q = shlex_quote
    built_with = paths.env_dir() / ".pixi" / "envs" / "pijul" / "lib"
    script = (f"{q(pixi)} install --locked --manifest-path {q(str(manifest))} -e pijul && "
              f"{q(pixi)} run --locked --manifest-path {q(str(manifest))} -e pijul install-pijul && "
              f"printf '%s\\n' {q(str(built_with))} > {q(str(root / '.built-with'))}; "
              f"rc=$?; rm -rf {q(str(lock))}; exit $rc")
    env = child_env({"CARGO_INSTALL_ROOT": str(root)})
    try:
        with open(log, "wb") as out:
            subprocess.Popen(["/bin/sh", "-c", script], stdin=subprocess.DEVNULL, stdout=out,
                             stderr=subprocess.STDOUT, env=env, start_new_session=True,
                             close_fds=True)
    except OSError:
        import shutil
        shutil.rmtree(lock, ignore_errors=True)
        return "gateway: pijul isn't installed for the gateway and couldn't be built here"
    return ("gateway: first use of pijul: building it from source in the background (several "
            "minutes; conda-forge has no pijul)" + (" — the last build failed, see "
                                                    f"{paths.describe(log)}; trying again"
                                                    if failed else "")
            + "; try again in a few minutes")


def _run_pijul(real: str, argv: list[str], a: formmod.Account, rec: dict[str, Any], key: str,
               hostkeys: list[str], cwd: str | None) -> int:
    tmp = Path(tempfile.mkdtemp(prefix="gw-pijul-", dir=paths.run_dir()))
    os.chmod(tmp, 0o700)
    agent_sock = None
    agent = None
    try:
        home = tmp / "home"
        (home / ".ssh").mkdir(parents=True)
        (home / ".ssh" / "known_hosts").write_text(
            "\n".join(f"{a.host or 'nest.pijul.com'} {k}" for k in hostkeys) + "\n")
        conf = tmp / "pijul"
        (conf / "identities").mkdir(parents=True)
        pub = (rec.get("ssh_key") or {}).get("public", "")
        env_extra = {"HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
                     "PIJUL_CONFIG_DIR": str(conf), "NO_COLOR": "1"}
        agent, agent_sock = _start_agent(tmp, key)
        if agent_sock:
            env_extra["SSH_AUTH_SOCK"] = agent_sock
        extra_argv = list(argv)
        if pub:
            (tmp / "id.pub").write_text(pub + "\n")
            name = re.sub(r"[^A-Za-z0-9._-]", "_", a.login or a.name)
            idd = conf / "identities" / name
            idd.mkdir()
            esc = lambda v: (v or "").replace("\\", "\\\\").replace('"', '\\"')  # noqa: E731
            (idd / "identity.toml").write_text(
                f'username = "{esc(a.login)}"\ndisplay_name = "{esc(a.commit_name or a.login)}"\n'
                f'origin = "{esc(a.host)}"\nemail = "{esc(a.email)}"\n\n'
                f'[public_key]\nkey = "{pub.split()[1] if len(pub.split()) > 1 else ""}"\n')
            extra_argv = ["--config", f"signing_key={tmp / 'id.pub'}", *argv]
        if rec.get("remote_pijul") or a.remote_pijul:
            env_extra["REMOTE_PIJUL"] = rec.get("remote_pijul") or a.remote_pijul
        env = child_env(env_extra)
        return _run("pijul", real, extra_argv, env, [key], a.name, a.host or "nest.pijul.com",
                    cwd=cwd)
    finally:
        if agent is not None:
            try:
                agent.terminate()
                agent.wait(timeout=5)
            except Exception:  # noqa: BLE001
                agent.kill()
        _rmtree(str(tmp))


def _start_agent(tmp: Path, key: str) -> tuple[Any, str | None]:
    try:
        ssh_agent = paths.tool("ssh-agent")
        ssh_add = paths.tool("ssh-add")
    except paths.ToolMissing:
        return None, None
    sock = str(tmp / "agent.sock")
    proc = subprocess.Popen([ssh_agent, "-D", "-a", sock], stdin=subprocess.DEVNULL,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            env=child_env({}))
    import time
    for _ in range(100):
        if os.path.exists(sock):
            break
        time.sleep(0.02)
    add = subprocess.run([ssh_add, "-q", "-"], input=vault.normalize_key(key).encode(),
                         env=child_env({"SSH_AUTH_SOCK": sock}), capture_output=True, timeout=15)
    if add.returncode != 0:
        proc.terminate()
        return None, None
    return proc, sock


# ---------------------------------------------------------------------------
# az (minimal)
# ---------------------------------------------------------------------------


_ARM_LEGACY = "management.core.windows.net"


def az_scope(a: formmod.Account, ea: Any, data: dict[str, Any], resource: str | None,
             scope: str | None) -> str:
    """The Entra scope `az account get-access-token [--resource R | --scope S]`
    may mint for azure account `a`: only what the http tool would use for one
    of the account's approved, bound destinations (web.azure_scope): Resource
    Manager (the default; its legacy `management.core.windows.net` audience
    too) and Graph, Storage when a storage account is listed (also a listed
    account's own URL), Databricks when a workspace is listed, and
    `https://SITE/.default` for a listed site. Raises CliError otherwise."""
    from . import web
    req = scope or (resource.rstrip("/") + "/.default" if resource else entra.SCOPES["arm"])
    req = req.strip()
    if not req.lower().endswith("/.default"):
        req = req.rstrip("/") + "/.default"
    body = req[:-len("/.default")]
    low = body.lower()
    shown = formmod.safe(req[:120]) or "that scope"
    refuse = CliError(f"gateway: az mints tokens only for {a.name}'s approved destinations "
                      f"(Resource Manager, Graph, and its listed storage, workspaces and sites); "
                      f"{shown} isn't one. Use the http tool with account \"{a.name}\" (and "
                      f"scope= for a listed site), or ask the user to list the site")
    if low in (entra.DATABRICKS_RESOURCE, "api://" + entra.DATABRICKS_RESOURCE):
        hosts = [w for w in a.databricks if not w.startswith(".")]     # listed workspaces
    else:
        m = re.fullmatch(r"https://([A-Za-z0-9.-]+)(?::443)?", body, re.I)
        if not m:
            raise refuse
        h = m.group(1).lower().rstrip(".")
        if h == _ARM_LEGACY:
            h = "management.azure.com"
        if h == "storage.azure.com":
            hosts = [f"{s}.{svc}.core.windows.net" for s in a.storage
                     for svc in acctmod.STORAGE_SERVICES]
        else:
            hosts = [h]
    for host in hosts:
        if not (ea.may_send_to(host) and consent.bound_ok(data, a.name, host)):
            continue
        try:
            sc = web.azure_scope(a, host, req)
        except web.Refused:
            continue
        if sc.lower() in (req.lower(), web.AZURE_SCOPES["storage"]) or (
                host == "management.azure.com"):
            return sc
    raise refuse


AZ_DIRECT = ("gateway: az account get-access-token gives a token only to a program that parses "
             "it (an Azure SDK that Claude's command starts, with scripts = true for {name}), "
             "never to a command's own output, which Claude reads; for Azure APIs use the http "
             "tool with account \"{name}\"")


def _az_account(form: formmod.Form, eff: Any) -> formmod.Account | None:
    """The azure account the az stand-in serves: the first with an approved
    `env`."""
    azs = [a for a in form.accounts.values() if a.kind == "azure"]
    enabled = [a for a in azs if (eff.accounts.get(a.name) and eff.accounts[a.name].env)]
    return enabled[0] if enabled else None


def _az(argv: list[str], form: formmod.Form, eff: Any, data: dict[str, Any]) -> int:
    a = _az_account(form, eff)
    if a is None:
        return _refuse("az", None, "gateway: the az stand-in is available only when an azure "
                       "account has env set (and the user has OK'd it)")
    if not eff.accounts[a.name].use:
        # its use is off, waiting, or "ask": an "ask" only for a command
        # Claude typed that the approval hook asked about (a program's
        # token request never is one)
        why = (_unasked(a.name, "use") if _ask_verb(eff, a.name, getattr(eff, "mode", None))
               == "use" else f"gateway: {a.name} has use = false (or is waiting for the user's "
               f"OK); see gate status {a.name}")
        if why:
            return _refuse("az", a.name, why)
    if argv[:2] == ["account", "show"]:
        who = {"environmentName": "AzureCloud", "tenantId": "", "user": {"name": a.login, "type": "user"}}
        e = (data.get("accounts") or {}).get(a.name, {}).get("entra") or {}
        who["tenantId"] = e.get("tenant_id", "")
        print(json.dumps(who, indent=2))
        audit.use("az", "management.azure.com", a.name, argv=["account", "show"],
                  mode=_audit_mode())
        return 0
    if argv[:2] == ["account", "get-access-token"]:
        resource = _flag_value(argv, "--resource")
        scope = _flag_value(argv, "--scope")
        # The raw token goes only to a program that parses it (an Azure SDK
        # Claude's command started) under scripts = true, never to Claude's own
        # command (a shell or wrapper chain up to Claude), whose output Claude
        # reads: Monitor turns each stdout line into a chat event and
        # PostToolUse never sees those (review round 2). Unknown ancestry: no.
        direct, culprit = is_direct("az", False)
        if direct:
            return _refuse("az", None, AZ_DIRECT.format(name=a.name))
        if not eff.accounts[a.name].scripts:
            _check_direct("az", a, eff)
        if culprit == "?":
            return _refuse("az", None, AZ_DIRECT.format(name=a.name))
        tok_scope = az_scope(a, eff.accounts[a.name], data, resource, scope)
        try:
            token = entra.access_token(a.name, tok_scope, mode=_audit_mode())
        except entra.EntraError as ex:
            return _refuse("az", None, str(ex) if str(ex).startswith("gateway:") else f"gateway: {ex}")
        import time
        out = {"accessToken": token, "expiresOn": "", "subscription": "",
               "tenant": ((data.get("accounts") or {}).get(a.name, {}).get("entra") or {}).get("tenant_id", ""),
               "tokenType": "Bearer",
               "expires_on": int(time.time()) + 3600}
        audit.use("az", tok_scope, a.name,
                  argv=["account", "get-access-token"], secrets=[token], mode=_audit_mode())
        # Phase C decision (docs/dev/phaseB-requests/RESOLUTION.md), narrowed in
        # review round 2: the raw token is printed only to a program started
        # by Claude's command (an SDK's AzureCliCredential parses accessToken,
        # so *** would break exactly the case az is for), and only with
        # scripts = true and an approved `env` (the user's opt-in for programs
        # to get its tokens, SPEC 2/9.7). Claude's own command was refused above.
        sys.stdout.write(json.dumps(out, indent=2) + "\n")
        return 0
    return _refuse("az", None, "gateway: the az stand-in supports only 'account get-access-token' "
                   "and 'account show'")


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def _split_cwd() -> str | None:
    cwd = os.getcwd()
    return cwd if os.path.isdir(cwd) else None


# ---------------------------------------------------------------------------
# Is the destination configured? (PLAN-0.11 §1.4: each stand-in resolves it
# the way the tool itself would; a covered destination takes the gated path,
# an uncovered one that can be told passes through to the user's own tool
# with the user's own GH_TOKEN and the like, and one that can't be told takes
# the gated path whenever an account of that kind exists for that host:
# never the user's full-scope token there.)
# ---------------------------------------------------------------------------

_URLISH = re.compile(r"(?:[A-Za-z][A-Za-z0-9+.-]*://|[A-Za-z0-9._-]+@[A-Za-z0-9.-]+:)")


def _hits(eff: Any, kinds: tuple[str, ...], host: str, owner: str | None) -> list[str]:
    """The configured accounts of these kinds that cover (host, owner): its
    destinations or ssh endpoints, and the owner by login and owners, the
    default, the only account of its kind there, or no owner named (the
    shared git resolver's rule, gitroute.Targets.hits)."""
    from . import gitroute
    c = getattr(eff, "configured", None)
    if c is None or not host:
        return []
    where = gitroute.parse_url(f"https://{host}/{owner}/x" if owner else f"https://{host}/")
    names = {n for sect, n in c.git_targets().hits(where) if sect == "accounts"}
    return [r.name for r in c.reaches() if r.kind in kinds and r.name in names]


def _env_host(var: str) -> str | None:
    v = (os.environ.get(var) or "").strip()
    if not v:
        return None
    return v.split("://", 1)[-1].split("/", 1)[0].lower() or None


# gh commands that act on the current repository when none is named (its
# remote's host and owner then decide, before GH_HOST)
_GH_REPO_CONTEXT = frozenset({"pr", "issue", "release", "run", "workflow", "secret", "variable",
                              "cache", "label", "browse", "ruleset", "attestation"})
_GH_REPO_SUBS = frozenset({"view", "edit", "sync", "rename", "archive", "unarchive", "delete",
                           "set-default", "deploy-key", "autolink", "fork"})


def _gh_dest(argv: list[str], cwd: str | None) -> tuple[str, str | None]:
    """(host, owner) a gh command line goes to, as gh resolves them: a host
    on the command line (--hostname, -R HOST/OWNER/REPO, a URL), GH_REPO's,
    the current repository's remote for a command that acts on it when no
    repository is named, GH_HOST, else github.com (gh's default; PLAN-0.11
    §1.4); the owner from -R, GH_REPO, a URL, an API path or an OWNER/REPO
    argument, else that remote's (None: it can't be told)."""
    hosts = [h for h in gh_hosts(argv) if h]
    repo_env = (os.environ.get("GH_REPO") or "").strip()
    host = hosts[0].lower() if hosts else None
    if host is None and repo_env.count("/") >= 2:
        host = repo_env.split("/", 1)[0].lower()
    named = gh_owner(argv, None)
    owner = named
    if owner is None and repo_env:
        parts = repo_env.split("/")
        owner = parts[-2] if len(parts) >= 2 else None
    top = argv[0] if argv else ""
    sub = argv[1] if len(argv) > 1 else ""
    if named is None and not repo_env and (
            top in _GH_REPO_CONTEXT or (top == "repo" and sub in _GH_REPO_SUBS)):
        where = _remote_where(cwd, "github")
        if where:
            host = host or where[0] or None
            owner = where[1]
    return host or _env_host("GH_HOST") or "github.com", owner


def destination(tool: str, argv: list[str], cwd: str | None, eff: Any) -> tuple[bool, str | None]:
    """(covered, target) for an account CLI's command line: covered False
    only when the destination can be told and no configured account covers
    it (the user's own tool runs); `target` is the host or owner for the
    pass-through's audit line."""
    if tool == "gh":
        host, owner = _gh_dest(argv, cwd)
        # an account's api. host counts as its own (the gated path decides
        # whether it is bound)
        api = host[4:] if host.startswith("api.") else None
        return bool(_hits(eff, ("github",), host, owner) or
                    (api and _hits(eff, ("github",), api, owner))), owner or host
    if tool == "hf":
        host = _env_host("HF_ENDPOINT") or "huggingface.co"
        owner = hf_owner(argv)
        return bool(_hits(eff, ("huggingface",), host, owner)), owner or host
    if tool == "databricks":
        ws = _env_host("DATABRICKS_HOST")
        if ws is None and cwd and not _flag_value(argv, "--profile", "-p"):
            try:
                m = re.search(r"host:\s*(\S+)", (Path(cwd) / "databricks.yml").read_text())
                ws = m.group(1).split("://", 1)[-1].split("/", 1)[0].lower() if m else None
            except OSError:
                ws = None
        if ws is None:
            return True, None                 # can't be told: the gated path decides
        return bool(_hits(eff, ("azure",), ws, None)), ws
    if tool == "crane":
        host, owner = crane_owner(argv)
        if not host:
            return True, None
        return bool(_hits(eff, ("github", "azure", "registry"), host, owner)), host
    if tool == "pijul":
        hosts = []
        for a in argv[1:]:
            if _URLISH.match(a):
                o = acctmod.owner_from_url(a, "pijul")
                if o:
                    hosts.append((o[0], o[1]))
        if not hosts:
            return True, None
        return any(_hits(eff, ("pijul",), h, o) for h, o in hosts), hosts[0][0]
    if tool == "az":
        tenant = _flag_value(argv, "--tenant", "-t")
        if tenant:
            known = {(a.tenant or "").lower() for a in eff.accounts.values() if a.kind == "azure"}
            if tenant.lower() not in known:
                return False, None
        return True, None
    return True, None


CLI_KINDS = consent.CLI_KINDS


def _cli_entries(tool: str, eff: Any) -> list[str]:
    c = getattr(eff, "configured", None)
    return [r.name for r in (c.reaches() if c is not None else [])
            if r.kind in CLI_KINDS.get(tool, ())]


def chosen(tool: str, argv: list[str], cwd: str | None, eff: Any, mode: str | None,
           account: str | None = None) -> list[str]:
    """The account this stand-in would use for `TOOL ARGV` in `cwd` (as
    _select sees it: every account that is "ask" in `mode` counted as asked
    about), with GATE_ACCOUNT = `account` (a name, aliases already
    followed); [] when it would use none (it refuses, or runs without one).
    The same choice the stand-in makes (_gh_pick, _hf_target, _db_ws,
    _crane_target, _pijul_target, _az_account), but no record is taken and
    no credential bound check is made. `eff` is computed for `mode`."""
    form = eff.form
    env = {"GATE_ACCOUNT": account} if account else {}

    def probe(kind: str | tuple[str, ...], host: str, owner: str | None, form: formmod.Form,
              eff: Any, data: dict[str, Any]) -> acctmod.Selection:
        kinds = (kind,) if isinstance(kind, str) else tuple(kind)
        asking = {n for n, a in form.accounts.items() if a.kind in kinds and _ask_verb(eff, n, mode)}
        return acctmod.select(kind, host, owner, form, effective=eff, vault=None, env=env,
                              mode=mode, asked=asking)
    if tool == "gh":
        sel = _gh_pick(argv, form, eff, {}, cwd, probe)
    elif tool == "hf":
        sel = probe(*_hf_target(argv), form, eff, {})
    elif tool == "databricks":
        ws = _db_ws(argv, form, cwd)
        if not ws:
            return []
        sel = probe("azure", ws, None, form, eff, {})
    elif tool == "crane":
        host, owner = crane_owner(argv)
        if not host:
            return []
        sel = probe(*_crane_target(host, owner), form, eff, {})
    elif tool == "pijul":
        sel = probe(*_pijul_target(form), form, eff, {})
    elif tool == "az":
        a = _az_account(form, eff)
        return [a.name] if a is not None else []
    else:
        return []
    return [sel.account.name] if sel.account is not None and sel.error is None else []


def ask_accounts(tool: str, argv: list[str], cwd: str | None, eff: Any,
                 mode: str | None, account: str | None = None,
                 known: bool = True) -> list[tuple[str, str]]:
    """For the approval hook (lead decision 19.14): (account, "use" or
    "credential") for the account this command line will use (chosen: the
    stand-in's own choice, with GATE_ACCOUNT = `account`) when it is "ask"
    in `mode` and the destination is covered (destination: this stand-in's
    own rule). The hook asks about the command and records it, so the
    stand-in may use that account after the user's OK (_select). A
    GATE_ACCOUNT the hook can't spell out (`known` False): every "ask"
    account of the tool's kinds, since any may be the one named. `eff` is
    computed for `mode`."""
    kinds = CLI_KINDS.get(tool, ())
    verbs = {n: v for n, ea in eff.accounts.items()
             if ea.kind in kinds and (v := _ask_verb(eff, n, mode))}
    if not verbs:
        return []                     # nothing "ask": no destination to work out
    covered, _target = destination(tool, argv, cwd, eff)
    if not covered:
        return []
    names = list(verbs) if not known else chosen(tool, argv, cwd, eff, mode, account)
    return [(n, verbs[n]) for n in names if n in verbs]


def main(tool: str, argv: list[str]) -> int:
    """Stand-in for tool in gh|hf|databricks|crane|pijul|az (SPEC 9.5;
    PLAN-0.11 §1.4): a destination no configured account covers runs the
    user's own tool (envfile.pass_through); everything else as before."""
    from . import asks
    asks.reset()
    _CALL.clear()
    _CALL.update(tool=tool, argv=list(argv))
    cwd = _split_cwd()
    try:
        form, eff, data = _load()
        covered, target = destination(tool, argv, cwd, eff)
        if not covered:
            from . import envfile
            return envfile.pass_through(tool, list(argv), target,
                                        entries=_cli_entries(tool, eff))
        if _UNREADABLE.get("message"):
            return _refuse(tool, target, _UNREADABLE["message"])
        if tool == "gh":
            return _gh(argv, form, eff, data, cwd)
        if tool == "hf":
            return _hf(argv, form, eff, data, cwd)
        if tool == "databricks":
            return _databricks(argv, form, eff, data, cwd)
        if tool == "crane":
            return _crane(argv, form, eff, data, cwd)
        if tool == "pijul":
            return _pijul(argv, form, eff, data, cwd)
        if tool == "az":
            return _az(argv, form, eff, data)
    except CliError as e:
        return _refuse(tool, None, str(e))
    print(f"gateway: unknown stand-in {tool}", file=sys.stderr)
    return 2


# ---------------------------------------------------------------------------
# gate with NAME -- CMD (SPEC 9.7)
# ---------------------------------------------------------------------------

ENV_BY_KIND = {"api-key": None, "huggingface": "HF_TOKEN", "github": "GH_TOKEN"}
WITH_OFF = ("gateway: {name} has use = false here (or a change to it waits for the user's OK); "
            "see gate status {name}")
WITH_ASK_SCRIPT = ("gateway: {what} is set to \"ask\", and Claude Code can only ask about a "
                   "command Claude runs itself; run `gate with {name} -- ...` as its own command "
                   "(not inside a script, sh -c or a wrapper).")


def _with_refused(name: str, ea: Any, eff: Any, words: list[str]) -> str | None:
    """Why `gate with NAME -- CMD` may not hand over NAME's key (the
    reviewer's MF2): its use in the session's mode is off or waits for the
    user's OK; its credential policy refuses (policy.decide); or either is
    "ask" and this isn't a command Claude typed that the approval hook asked
    about (asks.standin: its record of `gate WORDS`, that is `gate with NAME
    -- CMD`, taken once). None: hand it over."""
    from . import ancestry, asks, policy
    mode = getattr(eff, "mode", None)
    try:
        use = eff.word(name, "use", mode)
        cred = policy.decide(eff, "credential", account=name, mode=mode)
    except (AttributeError, KeyError, ValueError):
        return WITH_OFF.format(name=name)
    if use != "ask" and not ea.use:
        return WITH_OFF.format(name=name)
    if cred.word is not True and cred.word != "ask":
        return cred.message(f"using {name}'s credential")
    verb = "use" if use == "ask" else ("credential" if cred.word == "ask" else None)
    if verb is None:
        return None
    phrase = consent.ask_phrase(name, verb)
    try:
        typed, culprit = ancestry.typed_by_claude()
    except Exception:  # noqa: BLE001 - fail closed
        typed, culprit = False, "?"
    if not typed:
        if culprit == ancestry.CHECKPOINT:
            return consent.job_ask_message([phrase])
        if culprit == ancestry.TERMINAL:
            return consent.pane_ask_message([phrase])
        return WITH_ASK_SCRIPT.format(what=phrase, name=name)
    got = asks.standin("gate", words, ("accounts", name))
    return None if got == "ok" else asks.refusal(got, [phrase], f"gate with {name} -- ...")


def with_main(argv: list[str]) -> int:
    """`gate with NAME -- CMD` (SPEC 9.7): the account's key in its `env`
    variable for CMD, only while its use and credential policy allow it in
    the session's mode ("ask": the approval hook's record, _with_refused)."""
    from . import asks
    asks.reset()
    if "--" not in argv or argv.index("--") == 0:
        print("gateway: usage: gate with NAME -- COMMAND ...", file=sys.stderr)
        return 2
    sep = argv.index("--")
    name = argv[0]
    cmd = argv[sep + 1:]
    if len(argv[:sep]) != 1 or not cmd:
        print("gateway: usage: gate with NAME -- COMMAND ...", file=sys.stderr)
        return 2
    form, eff, data = _load()
    resolved = acctmod.resolve_name(name, (data.get("aliases") or {}), form)
    a = form.accounts.get(resolved)
    if a is None:
        print(f"gateway: {formmod.safe(name) or 'that name'} isn't an account in gateway.toml",
              file=sys.stderr)
        return 2
    ea = eff.accounts.get(resolved)
    if ea is None or not ea.env:
        if a.env:
            print(f"gateway: {resolved}'s env = \"{a.env}\" waits for the user's OK; run gate "
                  f"check {resolved} while the user is here", file=sys.stderr)
        else:
            print(f"gateway: {resolved} has no env variable; to use it with programs, ask the user "
                  f"whether to add `env = \"VARNAME\"` to [accounts.{resolved}] (then run gate "
                  f"check {resolved} for their OK)", file=sys.stderr)
        return 2
    if a.kind == "azure":
        print("gateway: azure accounts don't expose a raw token to programs; use the az stand-in "
              "or the http tool with account \"" + resolved + "\"", file=sys.stderr)
        return 2
    ok, culprit = is_direct("with", bool(ea.scripts))
    if not ok and not ea.scripts:
        print(f"gateway: `gate with` only gives the key to Claude's own command; {resolved} would "
              "need scripts = true to reach a program it starts", file=sys.stderr)
        return 2
    why = _with_refused(resolved, ea, eff, ["with", *argv])
    if why:
        return _refuse("with", resolved, why)
    rec = (data.get("accounts") or {}).get(resolved) or {}
    tok = rec.get("token") or {}
    if tok.get("stale"):
        print(acctmod.stale_token_message(resolved), file=sys.stderr)
        return 2
    value = tok.get("value")
    if not value:
        print(f"gateway: {resolved} has no credential; run gate check {resolved}", file=sys.stderr)
        return 2
    var = a.env  # the form's variable name (validated)
    env = dict(os.environ)
    env[var] = value
    audit.use("with", resolved, resolved, argv=["with", resolved, "--", *cmd[:8]], secrets=[value],
              mode=_audit_mode())
    try:
        return scrub.run(cmd, [value], env=env, cwd=_split_cwd())
    except FileNotFoundError:
        print(f"gateway: couldn't run {formmod.safe(cmd[0]) or 'that command'}", file=sys.stderr)
        return 127
    except OSError as e:
        print(f"gateway: couldn't run the command ({type(e).__name__})", file=sys.stderr)
        return 2


def _rmtree(path: str) -> None:
    import shutil
    shutil.rmtree(path, ignore_errors=True)
