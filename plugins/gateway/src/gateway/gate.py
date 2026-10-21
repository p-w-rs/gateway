"""The `gate` CLI (SPEC 15).

Here: status [NAME] [--report], migrate, log [N], why, import-ssh [ALIAS...],
help. The rest dispatch: check, login, forget, rotate -> gate_setup (secret: removed);
with -> clis.with_main; export, import, copy-to, pubkey -> transfer.
"""
from __future__ import annotations

import contextlib
import glob
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable

from . import accounts as acctmod
from . import audit, consent, hooks_session, migrate, paths, testing, vault
from . import form as formmod

OK, NO = "✓", "✗"
USAGE = """gate: the gateway's helper (the form is ~/.config/gateway/gateway.toml)

  gate status [NAME] [--report]   hosts, accounts, rights and what is stored (never a value)
  gate check NAME|all             set an entry up now: the user's OK, keys, passwords, tokens
  gate login NAME                 ask for an account's token (or client secret) again
  gate forget NAME [sudo|token|key|signin|host-keys]
                                  forget what is stored for an entry (all, or one kind)
  gate rotate HOST                give a host a new key
  gate with NAME -- CMD           run CMD with an account's key in its env variable
  gate export [FILE]              everything in one passphrase-protected file
  gate import FILE                merge an export
  gate copy-to HOST               send everything to another of your machines over ssh
  gate pubkey                     this machine's age recipient (what copy-to encrypts to)
  gate log [N]                    the audit log
  gate why                        the last refusal and its fix
  gate migrate                    convert a gateway 0.6 vault (or show the report)
  gate import-ssh [ALIAS...]      propose form entries from ~/.ssh/config (prints TOML only)
  gate lock                       lock the vault now (when its key has a passphrase;
                                  /gate-unlock in Claude Code unlocks it)
  gate host add NAME USER@HOST[:PORT] [KEY=VALUE...]   add a host (then gate check NAME)
  gate host set NAME KEY VALUE    change address, ssh, sudo, scripts, note, runtime or via
  gate workspace add HOST NAME ROOT [LOCAL]            a named root on a host (and its
                                  folder on this machine); gate workspace remove HOST NAME
  gate policy set all|HOST|ACCOUNT ACTION allow|ask|deny
                                  read, exec, write, network, elevation, credential,
                                  env_import, provision, forward_agent|x11|remote|stdio
  gate accounts [--check NAME|all] [--json]            account states (connected, expired,
                                  revoked, reauthentication required, ...)
  CMD | gate scrub                mask stored secrets and token shapes in CMD's output (optional)
"""


def _out(s: str = "") -> None:
    print(s)


def _err(s: str) -> None:
    print(s, file=sys.stderr)


def _phase_b(fn: Callable[..., int], *args: Any, what: str = "") -> int:
    try:
        return int(fn(*args) or 0)
    except NotImplementedError:
        _err(f"gateway: `gate {what}` isn't available in this build yet")
        return 2
    except (SystemExit, KeyboardInterrupt):
        raise                      # popup.StillOpen (exit 75) and friends
    except Exception as e:  # noqa: BLE001 - one gateway line, never a traceback (values could show)
        _err(f"gateway: gate {what} failed ({type(e).__name__}); try again, or run gate status")
        return 1


def _mark(r: Any) -> str:
    return OK if r is True else ("ask" if r == "ask" else NO)


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------


def _host_state(e: consent.EffectiveHost, meta: dict[str, Any]) -> tuple[str, str]:
    """(ssh column, sudo column)."""
    if e.new:
        return "waits for your OK (gate check %s)" % e.name, ""
    sudo_extra = ""
    if e.is_local:
        user = paths.local_user()
        st = (meta.get("localhost") or {}).get("sudo", {}).get(user)
        np = hooks_session._nopasswd_cached(user)
    else:
        hm = (meta.get("hosts") or {}).get(e.name) or {}
        users = hm.get("sudo") or {}
        st = users.get(e.host.user()) if e.host else None
        st = st or (next(iter(users.values())) if users else None)
        np = None
    if e.sudo is not False:
        if np:
            sudo_extra = " (no password needed)"
        elif st and st.get("stale"):
            sudo_extra = " password rejected (gate check %s)" % e.name
        elif st:
            sudo_extra = " password saved"
    sudo = f"sudo {_mark(e.sudo)}{sudo_extra}"
    if e.is_local:
        return sudo, ""
    hm = (meta.get("hosts") or {}).get(e.name) or {}
    where = f"via {e.via}" if e.via else (e.addresses[0].render() if e.addresses else "no address")
    key = "key installed" if hm.get("installed") else ("key saved" if hm.get("keys") else "no key yet")
    ssh = f"ssh {_mark(e.ssh)} {where}, {key}"
    return ssh, sudo


def _account_state(e: consent.EffectiveAccount, meta: dict[str, Any]) -> tuple[str, str]:
    a = e.account
    who = ""
    if a is not None:
        if a.kind == "api-key":
            who = ", ".join(a.sites) or "no sites"
        elif a.kind == "azure":
            who = a.login or a.tenant
        elif a.kind == "ml-catalog":
            who = a.login or a.host
        elif a.kind == "registry":
            who = (a.login + "@" if a.login else "") + a.host
        else:
            who = a.login or ""
            if a.kind == "github" and a.host and a.host != "github.com":
                who += f" ({a.host})"
        if a.owners:
            who += ("  " if who else "") + " ".join(a.owners)
        if a.default:
            who += " (default)"
    am = (meta.get("accounts") or {}).get(e.name) or {}
    if e.new:
        st = "waits for your OK (gate check %s)" % e.name
    elif not e.use:
        st = "off (use = false)"
    elif am.get("stale"):
        st = "token rejected (gate check %s)" % e.name
    elif am.get("entra"):
        st = "signed in"
    elif am.get("token"):
        if e.kind == "api-key":
            st = "key saved"
        else:
            st = "signed in" if am.get("token_source") == "gh-oauth" else "token saved"
    elif am.get("ssh_key"):
        st = "key saved"
    else:
        st = ("no key yet (gate check %s)" if e.kind == "api-key" else "not signed in (gate check %s)") % e.name
    if e.pending and not e.new:
        st += "; a change waits for your OK"
    return who, st


def render_status(form: formmod.Form, eff: consent.Effective, data: dict[str, Any] | None,
                  notes: list[str] | None = None) -> str:
    meta = vault.meta(data) if data else {}
    lines = []
    if not form.exists:
        if (data or {}).get("form_last_good") or (data or {}).get("approved"):
            lines.append("gateway.toml is missing: until it's back only this computer's defaults "
                         "apply (approvals are kept" + ("; the next session restores the last good "
                                                        "version)" if (data or {}).get("form_last_good")
                                                        else ")"))
        else:
            # A fresh install: nothing was ever there to go missing.
            lines.append("No gateway.toml yet: the gateway creates it at the next session start "
                         "(or ask Claude to add a host or account, which creates it); until then "
                         "only this computer's defaults apply (sudo on)")
    lines.append("Hosts")
    hw = max([len(n) for n in eff.hosts] + [8]) + 3
    for e in eff.hosts.values():
        a, b = _host_state(e, meta)
        row = f"  {e.name.ljust(hw)}{a}"
        if b:
            row = row.ljust(hw + 40) + "  " + b if len(row) < hw + 40 else row + "   " + b
        if e.pending and not e.new:
            row += "   (a change waits for your OK)"
        lines.append(row.rstrip())
    lines.append("Accounts")
    if not eff.accounts:
        lines.append("  (none yet)")
    aw = max([len(n) for n in eff.accounts] + [8]) + 3
    for e in eff.accounts.values():
        who, st = _account_state(e, meta)
        lines.append(f"  {e.name.ljust(aw)}{who.ljust(26)} {st}".rstrip())
    if eff.others == "mine":
        lines.append("Other machines and git servers: your own ssh/git setup (others = \"mine\")")
    if eff.pending:
        lines.append("Waiting for your OK")
        for c in eff.pending:
            lines.append(f"  {c.render()}   (gate check {c.entry})")
    probs = form.report_lines()
    if probs:
        lines.append("Problems in gateway.toml")
        lines += [f"  {p}" for p in probs]
    for w in form.warnings[:5]:
        lines.append(f"  warning: {w.render()}")
    if data:
        imp = consent.imported_rights(data)
        imported = set(imp["hosts"]) | set(imp["accounts"])
        orphans = [n for n in list((data.get("hosts") or {})) + list((data.get("accounts") or {}))
                   if n not in form.hosts and n not in form.accounts and n not in form.disabled]
        waiting = sorted({n for n in orphans if n in imported})
        others = sorted({n for n in orphans if n not in imported})
        if waiting:
            lines.append("Converted from 0.6, not in the form yet: " + ", ".join(waiting)
                         + " (copy them from gateway.from-v2.toml into gateway.toml to use them)")
        if others:
            lines.append("Stored but not in the form: " + ", ".join(others)
                         + " (gate forget NAME removes it)")
    pend = hooks_session.pending_requests()
    for d in pend:
        lines.append(f"Dialog waiting in Claude Code: {d['entry']} (/gate-dialog shows it)")
    for n in notes or []:
        lines.append(n)
    try:
        from . import managed
        lines += managed.status_lines(eff)
    except Exception:  # noqa: BLE001 - status is best effort
        lines.append("Managed shell: unknown (its settings couldn't be read)")
    lines.append(daemon_line())
    lines.append(f"File: {paths.describe(paths.form_path())}   Just ask: "
                 + ", ".join(f'"{x}"' for x in footer_examples(form)))
    return "\n".join(lines)


def footer_examples(form: formmod.Form) -> list[str]:
    """Two "just ask" examples that fit the form: one of its own hosts when
    there is one (never a name the user doesn't have)."""
    remote = [n for n, h in form.hosts.items() if not h.is_local]
    sudo_on = [n for n in remote if form.hosts[n].sudo is not False]
    if sudo_on:
        second = f"turn off sudo on {sudo_on[0]}"
    elif remote:
        second = f"ask me before ssh to {remote[0]}"
    else:
        second = "add my work GitHub"
    return ["add a server", second]


def render_entry(name: str, form: formmod.Form, eff: consent.Effective,
                 data: dict[str, Any] | None) -> str:
    meta = vault.meta(data) if data else {}
    name = acctmod.resolve_name(name, (data or {}).get("aliases") or {}, form)
    out: list[str] = []
    if name in form.disabled and name not in form.hosts and name not in form.accounts:
        out.append(f"{formmod.safe(name) or 'that entry'}: off (a mistake in gateway.toml)")
        out += [f"  {p.render()}" for p in form.problems_for(name)]
        return "\n".join(out)
    h, e = form.hosts.get(name), eff.hosts.get(name)
    if h is not None and e is not None:
        out.append(f"{name} (host{'' if h.explicit else ', implicit'})")
        if not h.is_local:
            for i, a in enumerate(h.addresses()):
                ok = any(x.key() == a.key() for x in e.addresses)
                out.append(f"  {'address' if i == 0 else 'also   '} {a.render()}"
                           + (f"  only on {a.when}" if a.when else "")
                           + ("" if ok else "  (waits for your OK)"))
            if h.via:
                out.append(f"  via     {h.via}" + ("" if e.via == h.via else "  (waits for your OK)"))
            out.append(f"  ssh     {_mark(e.ssh)}" + ("" if e.ssh == h.ssh else f" (form: {_mark(h.ssh)})"))
        out.append(f"  sudo    {_mark(e.sudo)}" + ("" if e.sudo == h.sudo else f" (form: {_mark(h.sudo)})"))
        out.append(f"  scripts {'true' if e.scripts else 'false'}")
        if not h.is_local:
            out += _remote_lines(name, h, e, data)
        if h.note:
            out.append(f"  note    {h.note}")
        hm = (meta.get("hosts") or {}).get(name) or {}
        if hm.get("keys"):
            out.append("  keys    " + ", ".join(hm["keys"]))
        if hm.get("host_keys"):
            out.append("  host keys " + "; ".join(hm["host_keys"]))
        sudo = hm.get("sudo") or ((meta.get("localhost") or {}).get("sudo") if h.is_local else {})
        for u, st in (sudo or {}).items():
            out.append(f"  sudo password for {u}: " + ("rejected" if st.get("stale") else "saved"))
    a, ea = form.accounts.get(name), eff.accounts.get(name)
    if a is not None and ea is not None:
        out.append(f"{name} ({a.kind} account)")
        for k in ("login", "host", "tenant", "client_id", "auth", "env", "remote_pijul"):
            v = getattr(a, k, "")
            if v:
                out.append(f"  {k.ljust(8)}{v}")
        if a.owners:
            out.append("  owners  " + ", ".join(a.owners))
        out.append("  sends to " + (", ".join(ea.destinations) or "nothing yet"))
        out.append(f"  use     {'true' if ea.use else 'false'}   scripts {'true' if ea.scripts else 'false'}")
        if a.note:
            out.append(f"  note    {a.note}")
        am = (meta.get("accounts") or {}).get(name) or {}
        stored = [k for k in ("token", "ssh_key", "entra") if am.get(k)]
        out.append("  stored  " + (", ".join(stored) or "nothing")
                   + (" (token rejected)" if am.get("stale") else ""))
        if am.get("ssh_fingerprint"):
            out.append(f"  ssh key {am['ssh_fingerprint']}")
        if am.get("bound"):
            out.append("  bound   " + ", ".join(am["bound"]))
    if not out:
        if formmod.syntax_note(form):
            return f"gateway: {formmod.syntax_note(form)}"
        return f"gateway: {formmod.safe(name) or 'that name'} isn't in gateway.toml"
    pend = eff.pending_for(name)
    if pend:
        out.append("  waiting for your OK (gate check %s):" % name)
        out += [f"    {c.what}" for c in pend]
    out += [f"  {p.level}: {p.render()}" for p in form.problems_for(name)]
    return "\n".join(out)


def _remote_lines(name: str, h: Any, e: Any, data: dict[str, Any] | None) -> list[str]:
    """The managed remote runtime of a host (PLAN-v4 phase 6): its folder, what
    gated last staged there and the machine identity met at first contact.
    Read from gated's state file and the vault; never asks the host."""
    import json
    out = []
    want = h.runtime or "~/.local/share/gateway-runtime"
    note = "" if (e.runtime or None) == (h.runtime or None) else "  (waits for your OK)"
    out.append(f"  runtime {want}{'' if h.runtime else ' (default)'}{note}")
    try:
        rec = json.loads(paths.gated_remote().read_text(encoding="utf-8")).get("hosts", {}).get(name) or {}
    except (OSError, ValueError, AttributeError):
        rec = {}
    if rec.get("rt_version") and rec.get("platform"):
        bits = [x for x in (rec.get("bash") and f"bash {rec['bash']}", rec.get("tmux")) if x]
        out.append(f"  remote runtime {rec['rt_version']}-{rec['platform']} staged"
                   + (f" ({', '.join(bits)})" if bits else ""))
    mid = ((data or {}).get("hosts") or {}).get(name, {}).get("machine_id")
    if isinstance(mid, str) and re.fullmatch(r"m_[a-z2-7]{26}", mid):
        out.append(f"  machine {mid}")
    return out


def status(args: list[str]) -> int:
    report = "--report" in args
    names = [a for a in args if not a.startswith("-")]
    notes: list[str] = []
    form, eff, data = hooks_session.prepare(notes, write=False)
    if report:
        rec = (data or {}).get("migrated")
        fail = migrate.last_failure()
        if rec:
            _out(rec.get("report") or "gateway: migrated from 0.6 (no report recorded)")
        elif migrate.needed():
            _out("gateway: a 0.6 vault is waiting to be migrated"
                 + (f"; last attempt: {fail['reason']}" if fail else "") + "; run gate migrate")
        else:
            _out("gateway: no migration report (this gateway didn't come from 0.6)")
        return 0
    if names:
        _out(render_entry(names[0], form, eff, data))
        return 0
    if migrate.needed():
        fail = migrate.last_failure()
        notes.append("Migration from 0.6 failed: " + (fail["reason"] if fail else "unknown")
                     + "; run gate migrate")
    _out(render_status(form, eff, data, notes))
    return 0


def _ago(sec: float) -> str:
    s = int(max(0, sec))
    if s < 120:
        return f"{s} s"
    if s < 7200:
        return f"{s // 60} min"
    return f"{s // 3600} h {s % 3600 // 60} min"


def daemon_line() -> str:
    """One line on the gateway daemon (PLAN-v4 phase 2) and the vault key's
    state; asks the daemon's /health, never starts it."""
    mode = vault.key_mode()
    key = {"none": "no vault key yet", "unwrapped": "vault key without a passphrase (unwrapped)",
           "wrapped": "vault key with a passphrase"}.get(mode, mode)
    try:
        from .daemon import client
        h = client.health(timeout=1.0)
    except Exception:  # noqa: BLE001
        h = None
    if h is None:
        return f"Gateway daemon: not running (it starts when needed); {key}" + \
            ("; locked until it runs and is unlocked" if mode == "wrapped" else "")
    state = str(h.get("vault") or "?")
    from .daemon import plugin_version, skew_text
    theirs = formmod.safe(str(h.get("version"))) or "?"
    skew = skew_text(theirs, plugin_version()) if theirs != "?" else ""
    return (f"Gateway daemon: running ({theirs}, epoch "
            f"{int(h.get('epoch') or 0)}, up {_ago(float(h.get('uptime') or 0))}); vault {state}"
            + (f"; {skew}" if skew else ""))


def lock_cmd(args: list[str]) -> int:
    """gate lock: forget the unlocked vault key in the gateway daemon."""
    if vault.key_mode() != "wrapped":
        _out("gateway: the vault key has no passphrase, so there is nothing to lock")
        return 0
    from .daemon import client
    if client.health(timeout=1.0) is None:
        _out("gateway: the vault is locked (the gateway daemon isn't running)")
        return 0
    try:
        r = client.call("POST", "/agent/vault/lock", {})
    except client.DaemonError as e:
        _err(e.message)
        return 1
    _out(str(r.get("message") or "gateway: the vault is locked"))
    return 0


# ---------------------------------------------------------------------------
# log, why, migrate
# ---------------------------------------------------------------------------


def log_cmd(args: list[str]) -> int:
    n = 40
    if args:
        if not re.fullmatch(r"[0-9]{1,6}", args[0]):
            _err("gateway: usage: gate log [N]")
            return 2
        n = int(args[0])
    _out(audit.render(audit.read(n)))
    return 0


def why(args: list[str]) -> int:
    if os.environ.get("CLAUDE_CODE_SESSION_ID"):
        rec = audit.last_refusal()
        if not rec:
            _out("gateway: no refusal recorded in this session")
            return 0
        where = ""
    else:
        # The user's own terminal has no session id: the newest refusal of any
        # session (README's Troubleshooting sends the user here).
        rec = audit.newest_refusal()
        if not rec:
            _out("gateway: no refusal recorded yet")
            return 0
        sess = rec.get("session")
        where = f" in session {sess}" if isinstance(sess, str) and formmod.safe(sess) else ""
    head = " ".join(str(x) for x in (rec.get("tool"), rec.get("target")) if x)
    _out(f"gateway: last refusal{(' (' + head + ')') if head else ''}{where} at "
         f"{rec.get('ts', '?')}:")
    _out(f"  {rec.get('reason', '')}")
    if rec.get("fix"):
        _out(f"  Fix: {rec['fix']}")
    return 0


def migrate_cmd(args: list[str]) -> int:
    r = migrate.run("gate migrate")
    _out(r.message)
    if r.report and r.status in ("migrated", "already"):
        _out(r.report)
    return 0 if r.ok else 1


# ---------------------------------------------------------------------------
# import-ssh
# ---------------------------------------------------------------------------


def _system_ssh() -> str | None:
    t = testing.get("tools") or {}
    if t.get("ssh-system"):
        return t["ssh-system"]
    if os.path.exists("/usr/bin/ssh"):
        return "/usr/bin/ssh"
    bin_dir = str(paths.bin_dir())
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if d and d != bin_dir and "/.pixi/" not in d and (Path(d) / "ssh").is_file():
            return str(Path(d) / "ssh")
    try:
        return paths.tool("ssh")
    except paths.ToolMissing:
        return None


_INCLUDE_DEPTH = 16          # ssh's own limit (READCONF_MAX_DEPTH)


def _include_files(spec: str, base: Path) -> list[Path]:
    """The files one `Include` argument names, as ssh reads them: `~` is the
    user's home, a relative path is taken from the folder of the user config
    (~/.ssh), globs expand in sorted order."""
    if spec.startswith("~"):
        spec = str(paths.user_home()) + spec[1:]
    p = spec if os.path.isabs(spec) else str(base / spec)
    if any(c in p for c in "*?["):
        return [Path(x) for x in sorted(glob.glob(p)) if os.path.isfile(x)]
    return [Path(p)] if os.path.isfile(p) else []


def config_aliases(config: Path, *, _base: Path | None = None, _depth: int = 0,
                   _seen: set[str] | None = None) -> list[str]:
    """Every concrete Host alias in ~/.ssh/config and the files it Includes
    (review round 4: configs built on `Include config.d/*` proposed nothing
    for those hosts). Patterns (`*`, `?`, `!`) are skipped."""
    out: list[str] = []
    seen = _seen if _seen is not None else set()
    base = _base or config.parent
    try:
        key = str(config.resolve())
        if key in seen or _depth > _INCLUDE_DEPTH:
            return out
        seen.add(key)
        text = config.read_text(errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        inc = re.match(r"\s*Include\s*[=\s]\s*(.+?)\s*(?:#.*)?$", line, re.I)
        if inc:
            try:
                specs = shlex.split(inc.group(1))
            except ValueError:
                specs = inc.group(1).split()
            for spec in specs:
                for f in _include_files(spec, base):
                    out += config_aliases(f, _base=base, _depth=_depth + 1, _seen=seen)
            continue
        m = re.match(r"\s*Host\s*[=\s]\s*(.+?)\s*(?:#.*)?$", line, re.I)
        if not m:
            continue
        for a in m.group(1).split():
            a = a.strip('"')
            if a and not any(c in a for c in "*?!") and formmod.SAFE_ECHO.fullmatch(a):
                out.append(a)
    return list(dict.fromkeys(out))


def _ssh_reason(e: BaseException) -> str:
    """ssh's own reason for a failed `ssh -G` (such as "Bad owner or
    permissions on ~/.ssh/config.d/lab": upstream OpenSSH refuses a
    group-writable config, which a umask of 002 makes on Debian), on one line,
    the home folder as ~, nothing unsafe."""
    text = str(e)
    with contextlib.suppress(Exception):
        home = str(paths.user_home())
        if home and home != "/":
            text = text.replace(home, "~")
    text = formmod.strip_unsafe(text).strip()[:160]
    return text or "error"


def ssh_g(alias: str, config: Path | None, ssh_bin: str) -> dict[str, str]:
    cmd = [ssh_bin, "-G"]
    if config is not None and config.exists():
        cmd += ["-F", str(config)]
    cmd += ["--", alias]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
    if r.returncode != 0:
        # the whole line (a home folder can be long); _ssh_reason shortens it after `~`
        raise ValueError((r.stderr.strip().splitlines() or ["ssh -G failed"])[-1][:2000])
    out: dict[str, str] = {}
    for line in r.stdout.splitlines():
        k, _, v = line.partition(" ")
        if k and k not in out:
            out[k.lower()] = v.strip()
    return out


def import_ssh(aliases: list[str], config: Path | None = None, ssh_bin: str | None = None,
               form: formmod.Form | None = None) -> str:
    """TOML proposals for ~/.ssh/config hosts (nothing is written)."""
    config = config if config is not None else paths.user_home() / ".ssh" / "config"
    ssh_bin = ssh_bin or _system_ssh()
    if not ssh_bin:
        raise RuntimeError("no ssh binary found to read ~/.ssh/config")
    form = form or formmod.load()
    wanted = aliases or config_aliases(config)
    if not wanted:
        return "# gate import-ssh: no hosts found in " + paths.describe(config)
    names: dict[str, str] = {}
    used = set(form.names()) | formmod.RESERVED
    for a in wanted:
        n = migrate._sanitize(a, "host")
        base, i = n, 2
        while n in used and n not in form.hosts:
            n = f"{base[:29]}-{i}"
            i += 1
        names[a] = n
        used.add(n)
    blocks = [f"# Proposed by gate import-ssh from {paths.describe(config)}. Add the ones the "
              "user wants to gateway.toml;", "# each new host needs the user's OK (gate check NAME)."]
    for a in wanted:
        n = names[a]
        try:
            g = ssh_g(a, config, ssh_bin)
        except (ValueError, OSError, subprocess.TimeoutExpired) as e:
            blocks.append(f"\n# {formmod.safe(a) or 'an alias'}: ssh -G failed ({_ssh_reason(e)})")
            continue
        user = g.get("user", "")
        host = g.get("hostname", a)
        port = g.get("port", "22")
        addr = migrate._fmt_addr(user or None, host, port)
        lines = [""]
        server = formmod.git_server_note(host) or _account_endpoint_note(host, form)
        if server:
            # A git server (a `Host github.com` block for User/IdentityFile): as
            # a host it would take over git's ssh routing to it.
            blocks += lines + [f"# {formmod.safe(a) or 'an alias'}: not proposed: {server}"]
            continue
        if n in form.hosts:
            # Never a second [hosts.N] table: pasted in, it would break the whole form.
            lines.append(f"# {n} is already in the form; its ~/.ssh/config entry would read "
                         "(compare, and change the existing table if needed):")
            try:
                formmod.parse_address(addr)
                lines.append(f"#   address = {formmod.toml_value(addr)}")
            except (ValueError, formmod.FormWriteError):
                lines.append("#   (its address isn't usable)")
            blocks += lines
            continue
        try:
            formmod.parse_address(addr)
        except ValueError as e:
            lines.append(f"# {formmod.safe(a) or 'an alias'}: {e}")
            blocks += lines
            continue
        lines.append(f"[hosts.{n}]")
        lines.append(f"address = {formmod.toml_value(addr)}")
        pj = g.get("proxyjump", "none")
        if pj and pj != "none":
            first = pj.split(",")[0]
            target = first.split("@")[-1].split(":")[0]
            via = names.get(first) or names.get(target)
            if not via:
                for hn, h in form.hosts.items():
                    if hn == target or (h.address and h.address.host == target.lower()):
                        via = hn
                        break
            if via:
                lines.append(f"via     = {formmod.toml_value(via)}")
            else:
                safe_t = formmod.safe(first) or "a jump host"
                lines.append(f"# ProxyJump {safe_t}: add it as a host first, then via = \"NAME\"")
        if g.get("proxycommand", "none") not in ("none", ""):
            lines.append("# this alias uses a ProxyCommand, which the gateway doesn't run")
        if "." not in host and ":" not in host:
            lines.append("# the HostName has no domain; check it resolves from here")
        blocks += lines
    return "\n".join(blocks) + "\n"


def _account_endpoint_note(host: str, form: formmod.Form) -> str | None:
    h = (host or "").lower()
    for acct in form.accounts.values():
        if any(eh == h for _u, eh in acct.ssh_endpoints()):
            return (f"{h} is the git server of the account {acct.name}, not a machine (git over ssh "
                    "to it already goes through that account)")
    return None


def import_ssh_cmd(args: list[str]) -> int:
    try:
        _out(import_ssh(args))
    except RuntimeError as e:
        _err(f"gateway: {e}")
        return 2
    return 0


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------


def scrub_cmd(args: list[str]) -> int:
    """`gate scrub`: a line filter that masks every stored secret (in every
    form) and anything shaped like a token. Optional: Claude may pipe output
    through it that reaches no output hook (Monitor's lines, a background
    command's output; the hooks no longer require it, DECISIONS "Rolled
    back"). It fails closed: if the vault can't be read, it passes nothing
    through."""
    if args:
        _err("gateway: usage: COMMAND | gate scrub")
        return 2
    from . import scrub
    try:
        if vault.exists():
            scrub.note_vault(vault.load())
    except Exception:  # noqa: BLE001 - VaultError etc.
        print("gateway: gate scrub can't read the vault, so it passes nothing through; run "
              "gate status", flush=True)
        return 1
    out = sys.stdout.buffer
    inp = sys.stdin.buffer
    try:
        while True:
            line = inp.readline(1 << 20)
            if not line:
                break
            text = line.decode("utf-8", "surrogateescape")
            out.write(scrub.scrub_text(text).encode("utf-8", "surrogateescape"))
            out.flush()
    except (BrokenPipeError, KeyboardInterrupt):
        return 0
    return 0


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        _out(USAGE)
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "scrub":
        return scrub_cmd(rest)   # a filter: no migration check, nothing printed before the lines
    if cmd != "migrate":
        try:
            r = migrate.ensure("gate")
            if r is not None:
                _err(("gateway: " + r.message) if not r.ok else r.message)
        except Exception as e:  # noqa: BLE001
            _err(f"gateway: migration check failed ({type(e).__name__})")
    if cmd == "status":
        return status(rest)
    if cmd == "log":
        return log_cmd(rest)
    if cmd == "why":
        return why(rest)
    if cmd == "migrate":
        return migrate_cmd(rest)
    if cmd == "import-ssh":
        return import_ssh_cmd(rest)
    if cmd == "lock" and not rest:
        return lock_cmd(rest)
    if cmd in ("host", "workspace", "policy", "accounts"):
        from . import manage
        return _phase_b(manage.main, cmd, rest, what=cmd)
    from . import clis, gate_setup, transfer
    if cmd == "check" and len(rest) == 1:
        return _phase_b(gate_setup.check, rest[0], what="check")
    if cmd == "login" and len(rest) == 1:
        return _phase_b(gate_setup.login, rest[0], what="login")
    if cmd == "forget" and len(rest) in (1, 2):
        return _phase_b(gate_setup.forget, rest[0], rest[1] if len(rest) == 2 else None,
                        what="forget")
    if cmd == "rotate" and len(rest) == 1:
        return _phase_b(gate_setup.rotate, rest[0], what="rotate")
    if cmd == "secret" and len(rest) == 1:
        return gate_setup.secret_removed(rest[0])
    if cmd == "with":
        return _phase_b(clis.with_main, rest, what="with")
    if cmd == "export" and len(rest) <= 1:
        return _phase_b(transfer.export_cmd, rest[0] if rest else None, what="export")
    if cmd == "import" and rest:
        peer = "--from-peer" in rest
        files = [a for a in rest if a != "--from-peer"]
        if len(files) == 1:
            return _phase_b(transfer.import_cmd, files[0], peer, what="import")
    if cmd == "copy-to" and len(rest) == 1:
        return _phase_b(transfer.copy_to, rest[0], what="copy-to")
    if cmd == "pubkey" and not rest:
        return _phase_b(transfer.pubkey, what="pubkey")
    _err(f"gateway: unknown or incomplete command: gate {formmod.safe(cmd) or '...'}\n")
    _err(USAGE)
    return 2
