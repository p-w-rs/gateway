"""The ssh family stand-ins: ssh, scp, sftp (and rsync via RSYNC_RSH, git via
GIT_SSH_COMMAND) (SPEC 9.2, 9.3), plus the ssh side of `gate check` (SPEC 15).

Stand-in flow (`main("ssh", argv)`):

1. Parse argv like OpenSSH (ssh_args); refused options exit 2 with a reason.
2. Map the destination to (a) a form host (by name, then gw-NAME, address,
   also or user@address), (b) an account ssh endpoint (git@github.com,
   git@hf.co, a GHES host), or (c) unknown: refused (with "did you mean")
   unless the user approved `others = "mine"`, which execs the system ssh
   unchanged, except for a name the user's ssh config sends to a form
   host's address (refused: use the form name so its rights apply).
3. No command and no -N: refused at once (interactive ssh can't work).
4. Effective rights (consent.compute, after consent's ratchet): ssh false
   refuses; "ask" (ssh, or sudo for a remote command with a sudo word)
   refuses unless Claude's own command shell started this ssh with nothing in
   between (ancestry.typed_by_claude: no git, rsync, scp, sftp, wrapper,
   script or `sh -c`; Claude Code can only ask about a command Claude typed);
   a non-direct caller gets nothing unless the entry has `scripts = true`
   (ancestry.is_direct).
5. Address choice and the per-call config (ssh_conf), host-key pinning
   (a changed key on the last candidate opens popup.hostkey), the private
   agent only when no master is alive, `ssh -G` on the final command line to
   verify what ssh will do, one audit line, then ssh runs as a child with
   stderr streamed through the stand-in; ssh's own messages go to an -E log
   in the call dir (streamed too), and only that log explains a failure.
6. Remote sudo (ssh_sudo) when the host's sudo right allows it: `sudo` in
   command position (scripts = false) or any `sudo` word (scripts = true).

Account endpoints: git commands only; git-lfs-authenticate (it prints a
token) only when git-lfs started this ssh; an owner-matched account that
isn't usable yet is never replaced by another account of the host.

scp and sftp exec the gateway's scp/sftp with `-S <bin/ssh stand-in>`.

gate check helpers: resolve, keyscan_host, install_key, test_login,
verify_remote_sudo, probe_remote_nopasswd, close_masters, rotate; run (the
gate process's own runner, for copy-to). They raise ssh.SshError (message
starting with "gateway:") when they can't proceed.
"""
from __future__ import annotations

import contextlib
import dataclasses
import difflib
import errno
import os
import re
import shlex
import stat
import subprocess
import sys
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from . import accounts, ancestry, audit, consent, paths, testing, vault
from . import form as formmod
from . import ssh_args, ssh_conf, ssh_sudo
from .ssh_conf import Conn, Link, SshError

__all__ = ["main", "resolve", "keyscan_host", "install_key", "test_login", "verify_remote_sudo",
           "probe_remote_nopasswd", "close_masters", "rotate", "run", "SshError"]

_SAFE_CULPRIT = re.compile(r"[A-Za-z0-9._+-]{1,40}")
SCAN_ALGOS = ("ssh-ed25519", "ecdsa-sha2-nistp256", "rsa-sha2-512")


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


@dataclass
class State:
    form: formmod.Form
    data: dict[str, Any]
    eff: consent.Effective


def _load() -> State:
    try:
        data = vault.load()
    except vault.VaultError as e:
        raise SshError(f"gateway: the vault can't be read ({e}); run gate status") from None
    form = consent.load_form(data)
    if consent.needs_sync(data, form) and not paths.v2_store_path().exists():
        with contextlib.suppress(Exception):
            consent.ratchet(form)
            data = vault.load()
    return State(form, data, consent.compute(form, data))


def _err(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def _refuse(tool: str, target: str | None, e: SshError | str, code: int = 2) -> int:
    printed = False
    if isinstance(e, SshError):
        msg, code, fix, printed = e.message, e.code, e.fix, e.printed
    else:
        msg, fix = e, None
    if not printed:
        _err(msg)
    audit.refusal(tool, target, msg, fix)
    return code


def _direct() -> tuple[bool, str]:
    """(direct, culprit). Fails closed: an ancestry error means not direct."""
    try:
        ok, culprit = ancestry.is_direct("ssh", False)
    except Exception:  # noqa: BLE001 - includes NotImplementedError
        return False, "an unknown program"
    c = os.path.basename(str(culprit or ""))
    if not ok and c in ("", ancestry.UNTRACED):
        return False, ancestry.UNTRACED_WHO
    return bool(ok), c if _SAFE_CULPRIT.fullmatch(c) else "a script"


def _typed() -> tuple[bool, str]:
    """(typed by Claude, culprit) for an "ask" right: started by Claude's own
    command shell (or a fork of it) with nothing in between, so the approval
    hook saw this very command (ancestry.typed_by_claude). Fails closed."""
    try:
        ok, culprit = ancestry.typed_by_claude()
    except Exception:  # noqa: BLE001 - fail closed, NotImplementedError too
        return False, "an unknown program"
    c = os.path.basename(str(culprit or ""))
    return bool(ok), c if _SAFE_CULPRIT.fullmatch(c) else "a script"


# Programs that start ssh by themselves: Claude Code can't ask about the ssh
# (or the remote sudo) they run, so an "ask" right refuses them.
_SSH_STARTERS = ("git", "git-lfs", "rsync", "scp", "sftp", "gh")


def _ask_refusal(name: str, what: str, culprit: str) -> SshError:
    """The refusal for an "ask" right reached by anything but a command Claude
    typed (SPEC 9: Claude Code can only prompt for that). Inside a checkpoint
    job: the approval hook's job wording (consent.job_ask_message); inside a
    gateway terminal or job: the pane's (consent.pane_ask_message)."""
    if culprit == ancestry.CHECKPOINT:
        return SshError(consent.job_ask_message([consent.ask_phrase(name, what)]))
    if culprit == ancestry.TERMINAL:
        return SshError(consent.pane_ask_message([consent.ask_phrase(name, what)]))
    starter = culprit if (culprit.startswith("git-remote-") or any(
        culprit == s or culprit.startswith(s + ".") or culprit.endswith(s) for s in _SSH_STARTERS)
    ) else ""                          # openrsync, rsync.samba, git-remote-ssh ...
    if starter:
        how = f"ssh {name} 'sudo CMD'" if what == "sudo" else f"ssh {name} CMD"
        return SshError(f"gateway: {what} on {name} asks the user each time, and Claude Code can "
                        f"only ask about a command Claude runs itself, not the ssh that {starter} "
                        f"starts; run it as its own command so Claude Code can ask you ({how}), "
                        f"or ask the user to set {what} = true for {name}")
    return SshError(f"gateway: {what} on {name} asks the user each time; run it as its own "
                    "command so Claude Code can ask you (not inside a script, sh -c or a "
                    "wrapper)")


def off_message(name: str, what: str, form_right: Any = False) -> str:
    """The refusal for an effective right that is off: off in the form, or
    (the form gives it) still waiting for the user's OK (round 3: the user had
    just turned it on, and "ask the user if it should be on" was the wrong
    next step)."""
    if form_right is not False and form_right is not None:
        return (f"gateway: {what} on {name} waits for the user's OK; run gate check {name} while "
                "the user is here")
    return f"gateway: {what} is off for {name} (gateway.toml); ask the user if it should be on"


def _gate_rights(name: str, right: Any, scripts: bool, what: str = "ssh",
                 who: tuple[bool, str] | None = None, form_right: Any = False) -> None:
    direct, culprit = who if who is not None else _direct()
    if right is False:
        raise SshError(off_message(name, what, form_right))
    if right == "ask":
        typed, by = _typed()
        if not typed:
            raise _ask_refusal(name, what, by)
    if not (direct or scripts):
        raise SshError(f"gateway: {what} started by {culprit} got no key (only Claude's own "
                       "commands do); run it as its own command, or set scripts = true for "
                       f"{name}")


def _popup():
    from . import popup
    return popup


def _outcome_ok(o: Any) -> bool:
    return str(o) == "ok"


def _popup_call(fn: Any, *args: Any, **kw: Any) -> Any:
    """Call a pop-up; its StillOpen (a SystemExit after a 90 s wait, message
    already printed) becomes SshError(code 75); a missing pop-up module is
    'unavailable'."""
    p = _popup()
    try:
        return fn(*args, **kw)
    except NotImplementedError:
        return "unavailable"
    except getattr(p, "StillOpen", ()) as e:  # type: ignore[misc]
        raise SshError(getattr(e, "message", "") or p.still_open_message(args[0]), 75,
                       printed=True) from None


def _popup_failed(name: str, what: str, outcome: Any, specific: str | None = None) -> SshError:
    """The refusal for a pop-up that didn't give an OK (popup.py prints the
    standard line itself for 'unavailable' and for a request cancelled before)."""
    o = str(outcome)
    p = _popup()
    msg = specific or (p.message(o, name, what) if hasattr(p, "message") else
                       f"gateway: the gateway dialog for {name} ({what}) didn't give an OK ({o})")
    return SshError(msg, 75 if o in ("unavailable", "timeout") else 1,
                    printed=(o == "unavailable" and specific is None))


# ---------------------------------------------------------------------------
# Classifying the destination
# ---------------------------------------------------------------------------


@dataclass
class Target:
    kind: str                     # host | endpoint | unknown | local | disabled | error
    name: str | None = None       # form host (kind host)
    by: str = ""                  # name | address | endpoint
    matches: list[formmod.Address] = field(default_factory=list)
    error: str | None = None


def _is_ip(h: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(h.strip("[]").split("%")[0])
        return True
    except ValueError:
        return False


def _suggest(h: str, form: formmod.Form) -> str | None:
    """A form host the user may have meant: a close spelling of a name or a
    DNS address; an IP address only when it is one of a host's addresses
    (round 3: `ssh 10.0.0.99` suggested an unrelated host at 10.0.0.9)."""
    pool: dict[str, str] = {}
    for n, x in form.hosts.items():
        if x.is_local:
            continue
        pool[n] = n
        for a in x.addresses():
            pool.setdefault(a.host, n)
    if _is_ip(h):
        return pool.get(h.strip("[]").lower())
    m = difflib.get_close_matches(h, [k for k in pool if not _is_ip(k)], n=1, cutoff=0.6)
    return pool[m[0]] if m else None


def _classify(dest: ssh_args.Destination, port: int | None, form: formmod.Form) -> Target:
    h = dest.host
    # gw-NAME is the generated alias of NAME, unless gw-NAME is itself a host
    if h.startswith("gw-") and h not in form.hosts and h[3:] in form.hosts:
        h = h[3:]
    if h == "localhost":
        return Target("local", error="gateway: localhost is this computer; run the command "
                                     "directly (sudo works as usual)")
    if h in form.hosts and not form.hosts[h].is_local:
        return Target("host", name=h, by="name")
    if form.is_disabled(h, "hosts"):
        return Target("disabled", error=f"gateway: {h} is off because of a mistake in "
                                        "gateway.toml; gate status shows the line to fix")
    hits: dict[str, list[formmod.Address]] = {}
    for n, x in form.hosts.items():
        for a in x.addresses():
            if a.host == h and (port is None or a.port == port):
                hits.setdefault(n, []).append(a)
    if len(hits) > 1:
        names = " and ".join(sorted(hits))
        return Target("error", error=f"gateway: {names} both use that address; run ssh with the "
                                     "host's name instead")
    if hits:
        (n, addrs), = hits.items()
        return Target("host", name=n, by="address", matches=addrs)
    if accounts.is_ssh_endpoint(h, form):
        return Target("endpoint", by="endpoint")
    return Target("unknown")


def _unknown_message(dest: ssh_args.Destination, command: str, form: formmod.Form) -> str:
    shown = formmod.safe(dest.host) or "that host"
    note = formmod.syntax_note(form)
    if note:
        return f"gateway: {shown} isn't in the form the gateway uses now: {note}"
    if accounts.owner_from_git_command(command) or \
            str(dest.host).lower() in accounts.GIT_ACCOUNT_HOSTS:
        # github.com, hf.co, nest.pijul.com: an account's endpoint, not a machine
        return accounts.no_git_account(dest.host)
    sugg = _suggest(dest.host, form)
    did = f" Did you mean {sugg}?" if sugg else ""
    return (f"gateway: {shown} isn't in gateway.toml.{did} To add it, ask the user (Claude can "
            "import it from ~/.ssh/config)")


def _check_users(name: str, fh: formmod.Host, users: list[str | None]) -> None:
    want = fh.user()
    for u in users:
        if u is not None and u != want:
            shown = formmod.safe(u) or "that user"
            raise SshError(f"gateway: {name} is reached as {want} (gateway.toml), not {shown}; "
                           "use sudo for root work, or ask the user to add a host entry for "
                           "that login")


# ---------------------------------------------------------------------------
# Building the chain (target + jump hosts)
# ---------------------------------------------------------------------------


def _with_user(a: formmod.Address) -> formmod.Address:
    return formmod.Address(host=a.host, port=a.port, user=a.effective_user(), when=a.when,
                           raw=a.raw)


def _user_knows(addr: formmod.Address, keys: list[str]) -> bool | None:
    kh = paths.user_home() / ".ssh" / "known_hosts"
    if not kh.is_file():
        return None
    q = addr.host if addr.port == 22 else f"[{addr.host}]:{addr.port}"
    try:
        r = subprocess.run([ssh_conf.tool("ssh-keygen"), "-F", q, "-f", str(kh)],
                           capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired, SshError):
        return None
    known = {vault.norm_host_key(l) for l in r.stdout.splitlines() if l and not l.startswith("#")}
    return any(vault.norm_host_key(k) in known for k in keys)


def _pin_host_keys(name: str, addr: formmod.Address, seen: list[str]) -> None:
    keys = list(dict.fromkeys(k for k in (vault.norm_host_key(x) for x in seen) if k))
    with vault.edit() as d:
        rec = vault.host_record(d, name)
        rec["host_keys"] = keys
        rec["pinned_at"] = vault.now()
        rec.pop("host_keys_previous", None)      # gate forget's memory: a pin replaces it
        vault.add_event(d, "hostkey", f"{name}: new host key accepted at {addr.render()} "
                                      f"({'; '.join(vault.host_key_fingerprints(keys))})")
    close_masters(name)


def _hostkey_changed(name: str, addr: formmod.Address, pins: list[str], seen: list[str]) -> list[str]:
    """The last candidate shows other host keys: ask the user (popup.hostkey,
    default Cancel; the new key is pinned where the pop-up runs, on OK).
    Returns the new pins on OK; raises SshError otherwise."""
    old = vault.host_key_fingerprints(pins)
    new = vault.host_key_fingerprints(seen)
    outcome = _popup_call(_popup().hostkey, name, old, new, address=addr.render(),
                          known=_user_knows(addr, seen),
                          on_ok=lambda: _pin_host_keys(name, addr, seen))
    audit.log("hostkey", host=name, address=addr.render(), outcome=str(outcome), old=old,
              new=new)
    if _outcome_ok(outcome):
        return list(seen)
    if str(outcome) == "cancelled":
        raise _popup_failed(name, "host key", outcome,
                            f"gateway: the user didn't accept {name}'s new host key; don't "
                            f"connect. If the machine was reinstalled, the user can run gate "
                            f"check {name}")
    if str(outcome) == "unavailable":
        raise _popup_failed(name, "host key", outcome,
                            f"gateway: {name}'s host key changed and no gateway dialog could "
                            f"ask the user; don't connect. Ask the user to run gate check {name} "
                            "in an interactive Claude Code session")
    raise _popup_failed(name, "host key", outcome)


def _user_present() -> bool:
    """For the gateway's own helpers on an "ask" host: the user is at hand,
    either answering a dialog job (the detached helper) or approving the
    command Claude typed, which the approval
    hook asks about (gate check / rotate / copy-to on an "ask" host)."""
    try:
        from . import popup
        if popup.mode() == "direct":
            return True
    except Exception:  # noqa: BLE001
        pass
    return _typed()[0]


def _helper_right(name: str, eh: Any) -> None:
    """The gateway's own ssh helpers (gate check's steps, the sudo probe and
    set-up, rotate, copy-to) log in with Claude's key like the stand-in, so
    they honour the host's effective ssh right the same way (review round 2):
    false refuses; "ask" needs the user present (_user_present)."""
    if eh.ssh is False:
        fh = getattr(eh, "host", None)
        raise SshError(off_message(name, "ssh", getattr(fh, "ssh", False)))
    if eh.ssh == "ask" and not _user_present():
        raise SshError(f'gateway: ssh on {name} is set to "ask"; run the gate command as its own '
                       f"command so Claude Code can ask the user (gate check {name}), or ask the "
                       f"user to set ssh = true for {name}")


def _build_link(name: str, st: State, cands: list[formmod.Address] | None = None, *,
                depth: int = 0, verify: bool = True, checked: bool = False,
                on_mismatch: Any = None) -> Link:
    """The connection to form host NAME (and its jump hosts). `checked=True`
    only from the stand-in and gated's remote runtime, which check the ssh
    right themselves; every other caller is held to _helper_right here.
    `on_mismatch(name, addr, pins, seen)` replaces the host-key pop-up (gated
    asks through its own dialog and raises; PLAN-v4 phase 6); it must raise
    or return the new pins."""
    eh = st.eff.hosts.get(name)
    fh = st.form.hosts.get(name)
    if eh is None or fh is None or fh.is_local:
        raise SshError(f"gateway: {name} isn't a host in gateway.toml")
    if eh.new:
        raise SshError(f"gateway: {name} waits for the user's OK; run gate check {name} while the "
                       "user is here")
    if not checked:
        _helper_right(name, eh)
    rec = (st.data.get("hosts") or {}).get(name) or {}
    pins = [k for k in rec.get("host_keys") or [] if vault.norm_host_key(k)]
    keys = vault.live_keys(rec)
    if not pins:
        raise SshError(f"gateway: {name} has no pinned host key yet; run gate check {name} while "
                       "the user is here")
    if not keys:
        raise SshError(f"gateway: {name} has no key yet; run gate check {name} while the user is "
                       "here")
    jump = None
    if eh.via:
        if depth >= formmod.MAX_CHAIN:
            raise SshError(f"gateway: {name}'s via chain is longer than {formmod.MAX_CHAIN}")
        je = st.eff.hosts.get(eh.via)
        if je is None or je.ssh is False:
            raise SshError(f"gateway: {name} is reached via {eh.via}, which is off or missing; "
                           "see gate status")
        # the jump's right caps this host's (consent), so it is checked with it
        jump = _build_link(eh.via, st, depth=depth + 1, verify=verify, checked=True,
                           on_mismatch=on_mismatch)
    choice = ssh_conf.choose(name, list(cands if cands is not None else eh.addresses), pins,
                             via=jump is not None, verify=verify)
    if choice.mismatch is not None:
        if on_mismatch is not None:
            pins = list(on_mismatch(name, choice.addr, pins, choice.mismatch))
        else:
            pins = _hostkey_changed(name, choice.addr, pins, choice.mismatch)
    return Link(name=name, addr=_with_user(choice.addr), host_keys=pins,
                pubkeys=[k["public"] for k in keys], privkeys=[k["private"] for k in keys],
                master=True, jump=jump, why=choice.why)


CRYPTO_KEYS = ("ciphers", "macs", "kexalgorithms", "hostkeyalgorithms",
               "pubkeyacceptedalgorithms", "casignaturealgorithms")


def _drop_agent_opts(kept: list[str]) -> list[str]:
    """-A and -o ForwardAgent=... out of the caller's options: a granted agent
    forward uses the call's own agent, set in the generated config (ssh's
    "yes" would forward SSH_AUTH_SOCK, which the stand-in never passes)."""
    out: list[str] = []
    i = 0
    while i < len(kept):
        x = kept[i]
        if x == "-A":
            i += 1
            continue
        if x == "-o" and i + 1 < len(kept) and kept[i + 1].lower().replace(" ", "").startswith(
                "forwardagent"):
            i += 2
            continue
        out.append(x)
        i += 1
    return out


def _verify_cmdline(conn: Conn, kept: list[str], command: list[str] | None = None,
                    granted: list[str] | None = None) -> None:
    """`ssh -G` on the final command line: refuse if anything the caller
    passed changed where or how ssh connects. `granted`: the forwarding kinds
    the host's policy allowed for this call (an agent forward then names the
    call's own agent socket; a remote forward may appear)."""
    granted = granted or []
    t = conn.target
    g = ssh_conf.ssh_g(conn.prepare(), [*kept, "--", t.alias, *(command or [])])
    assert conn.dir is not None
    want = {
        "hostkeyalias": t.alias, "hostname": t.addr.host, "port": str(t.addr.port),
        "user": t.addr.effective_user(), "userknownhostsfile": str(conn.dir / "known_hosts"),
        "globalknownhostsfile": "/dev/null",
        "stricthostkeychecking": "true", "identityagent": str(conn.dir / "agent.sock"),
        "forwardagent": str(conn.dir / "agent.sock") if "agent" in granted else "no",
        "permitlocalcommand": "no", "identitiesonly": "yes",
        "batchmode": "yes",
    }
    for k, v in want.items():
        got = g.get(k, [])
        if got != [v] and not (k == "hostname" and [x.lower() for x in got] == [v.lower()]):
            raise SshError(f"gateway: couldn't verify how ssh would connect ({k}); run plain "
                           f"`ssh {t.name} CMD`")
    pj = g.get("proxyjump", [])
    if (t.jump is None and pj not in ([], ["none"])) or (t.jump is not None and pj != [t.jump.alias]):
        raise SshError("gateway: couldn't verify how ssh would connect (proxyjump)")
    if g.get("proxycommand", ["none"]) != ["none"] or g.get("localcommand", ["none"]) != ["none"]:
        raise SshError("gateway: couldn't verify how ssh would connect (proxycommand)")
    for f in g.get("identityfile", []):
        if not f.startswith(str(conn.dir) + "/"):
            raise SshError("gateway: couldn't verify how ssh would connect (identityfile)")
    for fwd in g.get("localforward", []) + g.get("dynamicforward", []):
        if not ssh_args.listen_is_local(fwd.split()[0] if fwd.split() else ""):
            raise SshError("gateway: couldn't verify how ssh would connect (a forwarded port "
                           "open to other machines)")
    if g.get("remoteforward") and "remote" not in granted:
        raise SshError("gateway: couldn't verify how ssh would connect (remoteforward)")
    if "x11" not in granted and (g.get("forwardx11", ["no"]) != ["no"] or
                                 g.get("forwardx11trusted", ["no"]) != ["no"]):
        raise SshError("gateway: couldn't verify how ssh would connect (forwardx11)")
    # -c, -m and -o Ciphers/MACs/KexAlgorithms/HostKeyAlgorithms may narrow or
    # reorder what ssh offers by default, never add to it (no downgrade)
    base = ssh_conf.ssh_g(conn.prepare(), ["--", t.alias])
    for k in CRYPTO_KEYS:
        got = {x for v in g.get(k, []) for x in v.split(",") if x}
        allowed = {x for v in base.get(k, []) for x in v.split(",") if x}
        if not got <= allowed:
            extra = ", ".join(x for x in sorted(got - allowed)[:3] if formmod.safe(x))
            raise SshError(f"gateway: ssh may only use its default algorithms here ({k}: "
                           f"{extra or 'an added one'} isn't one of them); run the command "
                           "without -c/-m or that -o option")
    if t.master:
        conn._cp[t.alias] = (g.get("controlpath") or [""])[0]
        # scp/sftp pass -oControlMaster=no: they reuse a master, never start one
        conn.starts_master = g.get("controlmaster", ["auto"]) != ["false"]


# ---------------------------------------------------------------------------
# The stand-ins
# ---------------------------------------------------------------------------


def main(tool: str, argv: list[str]) -> int:
    """Stand-in entry for tool in ssh|scp|sftp (SPEC 9.2). Returns the exit code."""
    try:
        if tool == "ssh":
            return _ssh(list(argv))
        if tool in ("scp", "sftp"):
            return _copy(tool, list(argv))
    except SshError as e:
        return _refuse(tool, None, e)
    except paths.PathError as e:       # the run folder: its reason and remedy (GW-ROB-1), a path only
        return _refuse(tool, None, f"gateway: {tool} can't run: {paths.explain(e)}. Tell the user.")
    except vault.VaultError as e:      # its message holds no secret
        return _refuse(tool, None, f"gateway: {tool} can't run: {e}; run gate status")
    except OSError as e:
        return _refuse(tool, None, f"gateway: {tool} failed ({type(e).__name__}); try again, "
                                   "or run gate status")
    except Exception as e:  # noqa: BLE001 - one gateway line, never a traceback (values could show)
        return _refuse(tool, None, f"gateway: {tool} failed unexpectedly ({type(e).__name__}); "
                                   "try again, or run gate status", 1)
    _err(f"gateway: unknown stand-in {tool}")
    return 2


def _copy(tool: str, argv: list[str]) -> int:
    try:
        ssh_args.check_copy(tool, argv)
    except ssh_args.Refused as e:
        return _refuse(tool, None, e.message)
    shim = paths.bin_dir() / "ssh"
    if not os.access(shim, os.X_OK):
        return _refuse(tool, None, "gateway: the gateway's ssh stand-in is missing; start a new "
                                   "Claude Code session", 75)
    real = ssh_conf.tool(tool)
    os.execv(real, [real, "-S", str(shim), *argv])
    return 127  # pragma: no cover


def _system_ssh() -> str:
    t = testing.get("system_ssh")
    if t:
        return str(t)
    if os.access("/usr/bin/ssh", os.X_OK):
        return "/usr/bin/ssh"
    return ssh_conf.ssh_bin()


def _user_ssh_cmd() -> list[str]:
    """The system ssh with the user's own config (tests: -F ssh_user_config)."""
    cmd = [_system_ssh()]
    ucfg = testing.get("ssh_user_config")
    if ucfg:
        cmd += ["-F", str(ucfg)]
    return cmd


def _ips(name: str) -> frozenset[str]:
    import socket
    try:
        return frozenset(str(i[4][0]).split("%")[0] for i in socket.getaddrinfo(name, None))
    except (OSError, UnicodeError, ValueError):
        return frozenset()


def _form_host_behind(argv: list[str], form: formmod.Form) -> str | None:
    """others = "mine": where the system ssh would really go (`ssh -G` with
    the user's config: aliases, HostName). The form host at that address and
    port (by name, or by IP address), if any: it must be reached by its form
    name so its rights apply. None when -G can't tell (the system ssh then
    fails the same way)."""
    try:
        r = subprocess.run([*_user_ssh_cmd(), "-G", *argv], capture_output=True, text=True,
                           timeout=15, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0:
        return None
    g = ssh_conf.parse_g(r.stdout)
    h = (g.get("hostname") or [""])[0].strip().lower()
    try:
        port = int((g.get("port") or ["22"])[0])
    except ValueError:
        return None
    if not h:
        return None
    addrs = [(n, a) for n, x in form.hosts.items() if not x.is_local
             for a in x.addresses() if a.port == port]
    for n, a in addrs:
        if a.host.lower() == h:
            return n
    names = list(dict.fromkeys([h, *(a.host.lower() for _n, a in addrs)]))
    ips = dict(zip(names, ssh_conf.parallel(_ips, names, 1.5)))
    mine = ips.get(h) or frozenset()
    for n, a in addrs:
        if mine & (ips.get(a.host.lower()) or frozenset()):
            return n
    return None


# ---------------------------------------------------------------------------
# Policy (PLAN-v4 phase 7, docs/dev/modules/policy.md): what the call does on the
# host, each action decided on its own (a read never implies exec), with the
# rule behind a refusal
# ---------------------------------------------------------------------------

_SCP_REMOTE = re.compile(r"(?:scp://[^/]+(/.*)?|(?:\[[^\]]*\]|[^/\[]*?):(.*))\Z", re.S)


def _scp_remote_path(x: str) -> str | None:
    """The remote path of an scp operand (host:path, user@host:path,
    scp://host/path), None for a local one (a colon after a '/' is part of a
    local file name, as scp reads it)."""
    if not x or x.startswith(("/", "./", "../")):
        return None
    m = _SCP_REMOTE.match(x)
    if not m:
        return None
    return (m.group(1) or m.group(2) or "")


def _scp_parent_actions() -> list[tuple[str, str]] | None:
    """For the sftp subsystem: when the parent process is the gateway's own
    scp (by executable path), what its operands do: a remote target writes,
    a remote source reads (paths for the workspace match). None when the
    parent is anything else (sftp itself, or something that can't be read):
    then it may do both."""
    try:
        ppid = os.getppid()
        exe = ancestry.exe_path(ppid)
        real = ssh_conf.tool("scp")
        if not exe or os.path.realpath(exe) != os.path.realpath(real):
            return None
        argv = ancestry._argv(ppid)
    except Exception:  # noqa: BLE001 - can't tell: both
        return None
    if not argv:
        return None
    ops: list[str] = []
    i, n = 1, len(argv)
    while i < n:
        x = argv[i]
        if x == "--":
            ops += argv[i + 1:]
            break
        if x.startswith("-") and len(x) > 1:
            j = 1
            while j < len(x):
                c = x[j]
                if c in ssh_args.SCP_ARGOPTS:
                    if j + 1 == len(x):
                        i += 1
                    break
                j += 1
            i += 1
            continue
        ops.append(x)
        i += 1
    if len(ops) < 2:
        return None
    out: list[tuple[str, str]] = []
    target = _scp_remote_path(ops[-1])
    if target is not None:
        out.append(("write", target or "."))      # `box:` is the home folder
    for src in ops[:-1]:
        rp = _scp_remote_path(src)
        if rp is not None:
            out.append(("read", rp or "."))
    return out or None


def _policy_gate(name: str, a: ssh_args.SshArgs, st: State) -> None:
    """Decide every action of the call on host `name` (policy.decide): deny
    refuses with the rule; "ask" passes only for a command Claude typed (the
    approval hook asked the user). A granted X11 forward also needs an X
    server here."""
    for act, path in ssh_args.ssh_actions(a, _scp_parent_actions):
        # a path is decided in its workspace and in every one it may reach
        d = ssh_args.decide_path(st.eff, act, name, path)
        if d.word is True:
            continue
        what = ssh_args.FORWARD_WHAT.get(act[8:]) if act.startswith("forward_") else None
        if d.word == "ask":
            typed, _by = _typed()
            if typed:
                continue
        raise SshError(d.message(what))
    if "x11" in a.forwards and not os.environ.get("DISPLAY"):
        raise SshError(f"gateway: X11 forwarding to {name} is allowed, but there is no X server "
                       "here: DISPLAY isn't set in Claude's shell (add DISPLAY to [shell] "
                       "import_env in gateway.toml; on macOS XQuartz provides the server), and "
                       f"{name}'s sshd needs X11Forwarding yes")


def _ssh(argv: list[str]) -> int:
    try:
        a = ssh_args.parse_ssh(argv, forwards=True)
        port = ssh_args.parse_port(a.port)
    except ssh_args.Refused as e:
        return _refuse("ssh", None, e.message)
    if a.has("V") or any(c == "Q" for c, _ in a.opts):
        real = ssh_conf.ssh_bin()
        q = [v for c, v in a.opts if c == "Q"]
        os.execv(real, [real, "-Q", q[0]] if q else [real, "-V"])
    if a.dest is None:
        return _refuse("ssh", None, "gateway: ssh needs a host: ssh NAME COMMAND")
    try:
        dest = ssh_args.parse_destination(a.dest)
    except ssh_args.Refused as e:
        return _refuse("ssh", None, e.message)
    if port is None:
        port = dest.port
    st = _load()
    t = _classify(dest, port, st.form)
    if a.forwards and t.kind != "host":
        k = a.forwards[0]
        return _refuse("ssh", formmod.safe(dest.host),
                       f"gateway: {ssh_args.FORWARD_WHAT[k]} is only for a host in gateway.toml whose "
                       f"policy turns it on ([hosts.NAME.policy] forward_{k} = \"allow\"); run "
                       "the command without it")
    if t.kind == "unknown":
        if st.eff.others == "mine":
            behind = _form_host_behind(argv, st.form)
            if behind is not None:
                shown = formmod.safe(dest.host) or "that name"
                return _refuse("ssh", behind, f"gateway: {shown} is {behind} in gateway.toml (same "
                                              f"address); run `ssh {behind} CMD` so its rights apply")
            audit.log("others_mine", tool="ssh", target=formmod.safe(dest.host))
            real = _system_ssh()
            os.execv(real, [real, *argv])
        return _refuse("ssh", formmod.safe(dest.host), _unknown_message(dest, a.command_text,
                                                                        st.form))
    if t.kind in ("local", "disabled", "error"):
        return _refuse("ssh", formmod.safe(dest.host), t.error or "gateway: refused")
    if not a.command and not a.has("N"):
        return _refuse("ssh", formmod.safe(dest.host),
                       "gateway: pass a command; interactive ssh can't work here (ssh NAME CMD)")
    if t.kind == "endpoint":
        return _endpoint(a, dest, port, st)
    return _host(a, dest, port, st, t)


def _host(a: ssh_args.SshArgs, dest: ssh_args.Destination, port: int | None, st: State,
          t: Target) -> int:
    name = t.name or ""
    fh = st.form.hosts[name]
    eh = st.eff.hosts.get(name)
    try:
        if eh is None or eh.new:
            raise SshError(f"gateway: {name} waits for the user's OK; run gate check {name} while "
                           "the user is here")
        if eh.ssh is False and fh.ssh is not False and not eh.addresses:
            raise SshError(f"gateway: {name}'s address waits for the user's OK; run gate check "
                           f"{name} while the user is here")
        who = _direct()
        _gate_rights(name, eh.ssh, eh.scripts, who=who, form_right=fh.ssh)
        _check_users(name, fh, [a.login, dest.user])
        cands = list(eh.addresses)
        if t.by == "address":
            keys = {m.key() for m in t.matches}
            cands = [c for c in cands if c.key() in keys]
            if not cands:
                raise SshError(f"gateway: that address of {name} waits for the user's OK; run gate "
                               f"check {name} while the user is here")
        if port is not None:
            cands = [c for c in cands if c.port == port]
            if not cands:
                raise SshError(f"gateway: {name} isn't reached on port {port} (gateway.toml); run "
                               f"`ssh {name} CMD` without -p")
        cmd = a.command_text
        want_sudo = ssh_args.has_sudo_word(cmd)
        if eh.sudo is False and ssh_args.sudo_in_command_position(cmd):
            raise SshError(off_message(name, "sudo", fh.sudo))
        if want_sudo and eh.sudo == "ask":
            typed, by = _typed()
            if not typed:
                raise _ask_refusal(name, "sudo", by)
        # scripts = false: only `sudo` in command position in Claude's own command
        # gets the password (the askpass is a shell function, not exported), so
        # the password is staged only then; scripts = true: any `sudo` word.
        sudo_cmd = want_sudo if eh.scripts else ssh_args.sudo_in_command_position(cmd)
        use_sudo = sudo_cmd and eh.sudo is not False
        _policy_gate(name, a, st)
        if use_sudo:
            from . import policy
            d = policy.decide(st.eff, "elevation", host=name)
            if d.word is False or (d.word == "ask" and not _typed()[0]):
                raise SshError(d.message())
        link = _build_link(name, st, cands, checked=True)   # _gate_rights above
        overrides = None
        if "agent" in a.forwards or "x11" in a.forwards:
            # forwarding is set up by the ssh that connects: no shared master
            # for this call; the agent forwarded is the call's own, holding
            # only Claude's key for this host (never the user's agent)
            link = dataclasses.replace(link, master=False)
    except SshError as e:
        return _refuse("ssh", name, e)
    with Conn(link) as conn:
        try:
            kept = a.kept_options()
            if "agent" in a.forwards:
                assert conn.dir is not None
                conn.overrides = {link.alias: {"ForwardAgent": ssh_conf._q(conn.dir / "agent.sock")}}
                conn.cfg = ssh_conf.write_config(conn.dir, link, conn.overrides, conn.solo)
                kept = _drop_agent_opts(kept)
            _verify_cmdline(conn, kept, a.command, granted=a.forwards)
            reuse = conn.master_alive()
            audit.use("ssh", name, None, ["ssh", name, *a.command], address=link.addr.render(),
                      via=link.jump.name if link.jump else None, reuse=reuse,
                      remote_sudo=use_sudo, why=link.why)
            if use_sudo:
                return _run_sudo(conn, a, kept, name, link.addr.effective_user(), st,
                                 bool(eh.scripts), _sudo_names(cmd))
            # a nested sudo under scripts = false gets no password: say why if it asks
            return _run_plain(conn, a, kept, name,
                              sudo_hint=want_sudo and eh.sudo is not False and not eh.scripts)
        except SshError as e:
            return _refuse("ssh", name, e)


def _run_ssh(conn: Conn, kept: list[str], remote: list[str], scrub: list[str] | None = None
             ) -> tuple[int, str, str]:
    """ssh as a child with ssh's own messages in the call's -E log."""
    conn.ensure_agent()
    log = ssh_conf.log_arg(conn)
    argv = [*conn.base(), *kept, *log, "--", conn.alias, *remote]
    return ssh_conf.run_child(argv, conn, scrub=scrub, log=Path(log[1]))


def _forget_installed(name: str) -> None:
    """The host refused Claude's key: status stops saying "key installed",
    and the next gate check installs it again (round 3)."""
    with contextlib.suppress(Exception):
        with vault.edit() as d:
            rec = (d.get("hosts") or {}).get(name)
            if isinstance(rec, dict):
                rec.pop("installed", None)


def _after_run(name: str, rc: int, sshlog: str) -> None:
    """Explain an ssh failure from ssh's own log (never the remote's stderr)."""
    msg = ssh_conf.explain_failure(name, rc, sshlog)
    if msg:
        _err(msg)
        audit.log("ssh_failed", host=name, reason=msg)
        if ssh_conf.AUTH_FAIL.search(sshlog) and not ssh_conf.HOSTKEY_FAIL.search(sshlog):
            _forget_installed(name)
    elif rc != 255:
        ssh_conf.clear_authfail(name)
    elif ssh_conf.UNREACHABLE.search(sshlog):
        ssh_conf.cache_clear(name)        # the cached address stopped answering: probe again next time


def _sudo_hint(name: str) -> str:
    return (f"gateway: on {name} only `sudo` as a command of its own gets the password "
            f"(scripts = false for {name}); sudo inside another shell, a script, after "
            f"env/nohup/xargs or called by its path (/usr/bin/sudo) gets none. Run sudo directly "
            f"(ssh {name} 'sudo CMD'), or ask the user to set scripts = true for {name}")


def _run_plain(conn: Conn, a: ssh_args.SshArgs, kept: list[str], name: str,
               command: list[str] | None = None, scrub: list[str] | None = None,
               sudo_hint: bool = False) -> int:
    rc, err, sshlog = _run_ssh(conn, kept, a.command if command is None else command, scrub)
    conn.kill_agent()
    if sudo_hint and rc != 0 and ssh_sudo.NO_ASKPASS.search(err):
        _err(_sudo_hint(name))
    _after_run(name, rc, sshlog)
    return rc


# ---------------------------------------------------------------------------
# Remote sudo
# ---------------------------------------------------------------------------


def _note_probe(name: str, user: str, ok: bool, data: dict[str, Any]) -> None:
    np = (((data.get("hosts") or {}).get(name) or {}).get("probe") or {}).get("nopasswd") or {}
    if ok == (user in np):
        return
    with contextlib.suppress(Exception):
        with vault.edit() as d:
            r = vault.host_record(d, name)
            n = r.setdefault("probe", {}).setdefault("nopasswd", {})
            if ok:
                n[user] = vault.now()
            else:
                n.pop(user, None)


def _secret_prompt(name: str, link: Link, what: str, note: str | None = None) -> str:
    """The fixed secret pop-up text: what, for which user@address:port, the
    host-key fingerprint, and that Claude never sees it."""
    a = link.addr
    target = f"{a.effective_user()}@{a.hostport()}"
    fps = vault.host_key_fingerprints(link.host_keys)
    p = _popup()
    if hasattr(p, "secret_prompt"):
        return p.secret_prompt(what, name, target=target, fingerprint=fps[0] if fps else None,
                               note=note)
    return (f"The gateway needs the {what} for {name} ({target}).\n"
            + (f"Host key: {fps[0]}\n" if fps else "") + (note + "\n" if note else "")
            + "Claude never sees what you type here.")


def _ask_secret(name: str, what: str, prompt: str, verify: Any = None, store: Any = None,
                detail: dict | None = None, lazy: bool = True, load: Any = None,
                joined: str | None = None, *, check: dict | None = None,
                remember: bool | None = None) -> str:
    """popup.secret; returns the value or raises SshError. A request that
    joined another process's pop-up gets `load()` on OK (popup.py); with no
    value even then, `joined` (or a retry line) is the message. `check` is
    what gated rechecks before it hands the value over (host_check);
    `remember=True` offers "Remember it" (ticked) where storing is optional."""
    kw: dict[str, Any] = {"verify": verify, "store": store, "detail": detail, "lazy": lazy,
                          "check": check}
    if load is not None:
        kw["load"] = load
    if remember is not None:
        kw["remember"] = remember
    res = _popup_call(_popup().secret, name, what, prompt, **kw)
    outcome, value = res if isinstance(res, tuple) else (res, None)
    audit.log("popup", entry=name, what=what, outcome=str(outcome))
    if _outcome_ok(outcome) and value:
        return value
    if _outcome_ok(outcome):
        raise SshError(joined or f"gateway: the {what} for {name} was entered in another call's "
                                 "dialog; run the command again", 1)
    raise _popup_failed(name, what, outcome)


def host_check(name: str, *rights: str) -> dict[str, Any]:
    """What gated rechecks before it hands a value typed into the gateway's
    dialog over: host NAME still in the form, with these rights not off."""
    return {"section": "hosts", "entry": name, "right": list(rights)}


def _sudo_note(name: str, user: str) -> str:
    """The sudo pop-up's honest caveat (docs/dev/modules/ssh.md, residual risk)."""
    return (f"While sudo uses it, commands Claude runs on {name} could read it. Untick Remember "
            "it to use it for this command only.")


def _sudo_store(name: str, user: str) -> Any:
    def store(pw: str) -> None:
        with vault.edit() as d:
            vault.set_sudo(d, name, user, pw)
        audit.log("secret_saved", entry=name, what="sudo password", user=user)
    return store


def _sudo_verify(name: str, user: str) -> Any:
    """Runs where the pop-up runs (a detached helper that may outlive this
    call), so it opens its own connection."""
    return lambda pw: verify_remote_sudo(name, user, pw)


def _sudo_load(name: str, user: str) -> Any:
    def load() -> str | None:
        e = vault.sudo_entry(vault.load(), name, user) or {}
        return None if e.get("stale") else e.get("password")
    return load


def _sudo_password(name: str, user: str, st: State, conn: Conn) -> tuple[str, bool, str | None]:
    """(password, fresh, updated): fresh = just entered and verified in the
    pop-up; updated = the vault entry's time stamp (keys the verify cache)."""
    e = vault.sudo_entry(st.data, name, user)
    if e and e.get("stale"):
        # the one re-entry pop-up (popup dedupes it and remembers a cancel)
        raise SshError(_reentry_popup(name, user, conn.target), 1)
    if e and e.get("password"):
        pw = e["password"]
        if ssh_sudo.too_short(pw):
            raise SshError(ssh_sudo.short_message(name, user), 2)
        return pw, False, e.get("updated")
    pw = _ask_secret(name, "sudo password", _secret_prompt(name, conn.target, "sudo password",
                                                           note=_sudo_note(name, user)),
                     verify=_sudo_verify(name, user), store=_sudo_store(name, user),
                     detail={"user": user}, load=_sudo_load(name, user),
                     joined=(f"gateway: the sudo password for {name} was entered in another "
                             "command's gateway dialog and can't be read back here (it isn't kept "
                             "when Remember it is unticked); run the command again"),
                     check=host_check(name, "ssh", "sudo"), remember=True)
    if ssh_sudo.too_short(pw):          # verify refuses these; a joined/loaded value too
        raise SshError(ssh_sudo.short_message(name, user), 2)
    return pw, True, None


def _rights_after_dialog(name: str) -> None:
    """A sudo password just typed into the gateway's dialog (which may have
    been open for minutes): gated rechecked the host's rights before it
    handed the value over, and they are read once more here, before the
    password is placed on the host. Raises SshError when ssh or sudo is off
    now (or "ask" for a command Claude didn't type)."""
    st = _load()
    eh, fh = st.eff.hosts.get(name), st.form.hosts.get(name)
    if eh is None or fh is None:
        raise SshError(f"gateway: {name} left gateway.toml while its sudo dialog was open; "
                       "nothing was sent", 1)
    if eh.new:
        raise SshError(f"gateway: {name} waits for the user's OK; run gate check {name} while the "
                       "user is here", 1)
    if eh.ssh is False:
        raise SshError(off_message(name, "ssh", fh.ssh), 1)
    if eh.sudo is False:
        raise SshError(off_message(name, "sudo", fh.sudo), 1)
    if eh.sudo == "ask":
        typed, by = _typed()
        if not typed:
            raise _ask_refusal(name, "sudo", by)


def _mark_stale(name: str, user: str) -> None:
    with contextlib.suppress(Exception):
        with vault.edit() as d:
            vault.mark_stale(d, name, "sudo", user)
            vault.add_event(d, "reject", f"{name}: the saved sudo password of {user} was rejected")
    audit.log("reject", host=name, user=user, what="sudo password")


def _reentry_popup(name: str, user: str, link: Link) -> str:
    """One re-entry pop-up after a rejection, without waiting (SPEC 6);
    returns the line for the failing command."""
    stale = (f"gateway: the saved sudo password for {name} was rejected; a gateway dialog to "
             "enter it again is open in Claude Code; don't retry")
    p = _popup()
    if not hasattr(p, "reenter"):
        return stale
    try:
        msg = p.reenter(name, "sudo password",
                        _secret_prompt(name, link, "sudo password",
                                       note="The saved one was rejected. "
                                            + _sudo_note(name, user)),
                        _sudo_verify(name, user), store=_sudo_store(name, user),
                        detail={"user": user}, check=host_check(name, "ssh", "sudo"))
    except (Exception, SystemExit):  # noqa: BLE001 - the command fails either way
        return stale
    return msg if isinstance(msg, str) and msg.startswith("gateway: ") else stale


def _rejected(name: str, user: str, conn: Conn) -> str:
    """The saved password was rejected: stale (never retried), one re-entry
    pop-up; returns the line for the failing command (printed, audited)."""
    _mark_stale(name, user)
    ssh_sudo.forget_verified(name, user)
    msg = _reentry_popup(name, user, conn.target)
    _err(msg)
    audit.refusal("ssh", name, msg)
    return msg


def _sudo_names(cmd: str) -> tuple[str, ...]:
    """The shell functions scripts = false defines: `sudo`, plus `sudoedit`
    when the command runs it."""
    found = ssh_args.sudo_commands(cmd)
    return tuple(n for n in ssh_args.SUDO_NAMES if n in found) or ("sudo",)


def _run_sudo(conn: Conn, a: ssh_args.SshArgs, kept: list[str], name: str, user: str,
              st: State, scripts: bool = False, names: tuple[str, ...] = ("sudo",)) -> int:
    ok = ssh_sudo.probe(conn, name, user)
    _note_probe(name, user, ok, st.data)
    if ok:
        return _run_plain(conn, a, kept, name)
    pw, fresh, updated = _sudo_password(name, user, st, conn)
    if fresh:
        _rights_after_dialog(name)
    d: str | None = ssh_sudo.stage(conn, name, pw)
    report = (False, 0)
    rc, err, sshlog = 1, "", ""
    verify_answers = 0
    try:
        if not fresh and not ssh_sudo.verified_recently(name, user, updated):
            verify_answers = 1
            # one attempt with the staged askpass before the command runs
            vrc = ssh_sudo.verify_staged(conn, d)
            if vrc != 0:
                report = ssh_sudo.cleanup(conn, d)
                d = None
                if report[0] or report[1]:      # sudo asked twice, or took the answer and failed
                    _rejected(name, user, conn)  # (stale: never another failed attempt)
                    return 1
                raise SshError(f"gateway: sudo on {name} didn't take the saved password from the "
                               f"gateway's askpass (sudo -v exited {vrc}); check that {user} may "
                               f"use sudo there (gate check {name})", 1)
            ssh_sudo.note_verified(name, user, updated)
        rc, err, sshlog = _run_ssh(conn, kept, [ssh_sudo.prefix(d, scripts, names)
                                                + a.command_text],
                                   scrub=[pw])
    finally:
        if d is not None:
            report = ssh_sudo.cleanup(conn, d)
        conn.kill_agent()
    rejected, answers = report
    answers = max(0, answers - verify_answers)      # the command's own sudo processes
    if rejected:
        _rejected(name, user, conn)
        return rc            # the command's own exit code stays
    if answers and ssh_sudo.rejected(err):
        ssh_sudo.forget_verified(name, user)   # sudo's own lines: verify again next time
    if not scripts and answers == 0 and rc != 0 and ssh_sudo.NO_ASKPASS.search(err):
        _err(_sudo_hint(name))
    _after_run(name, rc, sshlog)
    return rc


def _verify_sudo(conn: Conn, name: str, user: str, password: str) -> tuple[bool, str]:
    if ssh_sudo.too_short(password):
        return False, ssh_sudo.short_message(name, user)
    _audit_gate(conn.target, "sudo -k -A -v", check="sudo password", user=user,
                remote_sudo=True, secrets=[password])
    if not ssh_sudo.posix_shell(conn):
        return False, (f"gateway: {name}'s login shell isn't POSIX; remote sudo needs sh, bash, "
                       "dash or zsh as the login shell")
    d = ssh_sudo.stage(conn, name, password)
    rc = 1
    try:
        rc = ssh_sudo.verify_staged(conn, d)
    finally:
        rejected, answers = ssh_sudo.cleanup(conn, d)
    if rc == 0:
        return True, f"gateway: the sudo password of {user} on {name} works"
    if rejected or answers:
        return False, f"gateway: sudo on {name} didn't accept that password"
    return False, (f"gateway: sudo on {name} didn't ask the gateway's askpass (sudo -v exited "
                   f"{rc}); check that {user} may use sudo there")


# ---------------------------------------------------------------------------
# Account endpoints (git over ssh)
# ---------------------------------------------------------------------------


def _started_by_git_lfs() -> bool:
    """git-lfs started this ssh: the first ancestor that isn't a shell (or
    env) is git-lfs, by executable path (ancestry's process helpers). Any
    error: no."""
    try:
        pid = os.getppid()
        for _ in range(8):
            if pid <= 1:
                return False
            name = ancestry.exe_name(pid)
            if name in ancestry.SHELLS or name == "env":
                pid = ancestry.parent_pid(pid)
                continue
            return name == "git-lfs"
    except Exception:  # noqa: BLE001 - fail closed
        return False
    return False


def _sel_host(acct: formmod.Account) -> str:
    if acct.kind == "github":
        return acct.host or "github.com"
    if acct.kind == "huggingface":
        return "hf.co"
    return acct.host


def _endpoint(a: ssh_args.SshArgs, dest: ssh_args.Destination, port: int | None,
              st: State) -> int:
    host = dest.host
    try:
        users = {u for u in (a.login, dest.user) if u}
        if len(users) > 1:
            raise SshError(f"gateway: two different users for {host}; use git@{host}")
        user = users.pop() if users else paths.local_user()
        accts = accounts.endpoint_accounts(user, host, st.form)
        if not accts:
            raise SshError(f"gateway: {host} takes git over ssh as git@{host}")
        kinds = tuple(sorted({x.kind for x in accts}))
        if "pijul" in kinds:
            raise SshError(f"gateway: use the pijul command for {host}; it brings the account's "
                           "key itself")
        parsed = accounts.owner_from_git_command(a.command_text)
        if not parsed:
            raise SshError(f"gateway: only git commands go to {host} over ssh (git clone, fetch, "
                           "push)")
        service, owner = parsed
        if service.startswith("git-lfs-authenticate") and not _started_by_git_lfs():
            raise SshError(f"gateway: git-lfs-authenticate hands out an access token for {host}; "
                           "only git-lfs may run it (git lfs pull / git lfs push do)")
        sel_host = _sel_host(accts[0])
        # accounts.select refuses when the owner's account isn't usable yet
        # (it never hands those repos to the default or the only other one)
        sel = accounts.select(kinds, sel_host, owner, st.form, effective=st.eff, vault=st.data)
        if sel.error:
            raise SshError(sel.error)
        if sel.account is None:
            raise SshError((sel.note or f"gateway: no account for {sel_host}")
                           + " (git over ssh needs an account's key)")
        acct = sel.account
        ea = st.eff.accounts.get(acct.name)
        _gate_rights(acct.name, bool(ea and ea.use), bool(ea and ea.scripts), what="git over ssh")
        from . import policy
        for act in ("credential",) + (("write",) if service.startswith("git-receive-pack") else ()):
            d = policy.decide(st.eff, act, account=acct.name)
            if d.word is False or (d.word == "ask" and not _typed()[0]):
                raise SshError(d.message("a git push" if act == "write" else None))
        if not consent.bound_ok(st.data, acct.name, sel_host):
            raise SshError(f"gateway: {acct.name}'s credential isn't bound to {sel_host}; run gate "
                           f"check {acct.name} while the user is here")
        rec = (st.data.get("accounts") or {}).get(acct.name) or {}
        key = rec.get("ssh_key") or {}
        if not key.get("private"):
            raise SshError(f"gateway: {acct.name} has no ssh key; use an https remote (git remote "
                           f"set-url origin https://{sel_host}/OWNER/REPO.git)")
        eport = port or 22
        pins = vault.builtin_host_keys(host, eport) or [k for k in rec.get("host_keys") or []]
        if not pins:
            raise SshError(f"gateway: no pinned host key for {host}; run gate check {acct.name} "
                           "while the user is here")
        pub = key.get("public") or vault.public_key_of(key["private"])
        addr = formmod.Address(host=host, port=eport, user=user)
        m = (testing.get("ssh_endpoint_map") or {})
        hit = m.get(f"{host}:{eport}") or m.get(host)
        if hit:   # tests only: a github-like name served by the local sshd
            addr = formmod.Address(host=hit["host"], port=int(hit["port"]), user=hit["user"])
        link = Link(name=acct.name, addr=addr, host_keys=pins, pubkeys=[pub],
                    privkeys=[key["private"]], master=False, why="account endpoint")
    except SshError as e:
        return _refuse("ssh", formmod.safe(host), e)
    with Conn(link) as conn:
        try:
            kept = a.kept_options()
            _verify_cmdline(conn, kept, a.command)
            audit.use("ssh", f"{user}@{host}", acct.name, [service, owner or ""],
                      address=addr.render())
            return _run_plain(conn, a, kept, acct.name)
        except SshError as e:
            return _refuse("ssh", formmod.safe(host), e)


# ---------------------------------------------------------------------------
# resolve (for hooks and gate)
# ---------------------------------------------------------------------------


RESOLVE_CFG = "# gateway: target resolution only\nHost *\n  BatchMode yes\n"


@contextlib.contextmanager
def _resolve_cfg():
    """A fresh private config for one `ssh -G` (a file left in the run dir
    could have been changed since; e.g. a `Match exec` would run here)."""
    import tempfile
    fd, name = tempfile.mkstemp(prefix="ssh-resolve-", suffix=".conf", dir=str(paths.run_dir()))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(RESOLVE_CFG)
        yield Path(name)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(name)


def resolve(argv: list[str], form: formmod.Form | None = None) -> dict:
    """Target of an ssh argv (SPEC 9.2), without connecting:
    {kind: host|endpoint|unknown|local|disabled|error|refused, name, user,
    addr, port, by, suggest, error}. `name` is the form host (kind host) or
    the destination host (endpoint/unknown). Every string is safe to render
    (form.safe): a typed name or user that isn't is None. Pass `form` if the
    caller has it loaded already (else it is loaded with the vault's last
    good text)."""
    out: dict[str, Any] = {"kind": "error", "name": None, "user": None, "addr": None,
                           "port": None, "by": "", "suggest": None, "error": None}
    try:
        a = ssh_args.parse_ssh(list(argv))
        port = ssh_args.parse_port(a.port)
        if a.dest is None:
            out["error"] = "gateway: ssh needs a host: ssh NAME COMMAND"
            return out
        dest = ssh_args.parse_destination(a.dest)
    except ssh_args.Refused as e:
        out.update(kind="refused", error=e.message)
        return out
    try:  # ssh's own view of the destination must agree with ours
        with _resolve_cfg() as cfg:
            g = ssh_conf.ssh_g(cfg, list(argv))
        gh = (g.get("hostname") or [""])[0].lower()
        if gh and gh != dest.host and ":" not in dest.host:
            out["error"] = "gateway: couldn't tell which host that ssh command goes to"
            return out
    except (SshError, OSError, subprocess.TimeoutExpired):
        pass
    port = port if port is not None else dest.port
    if form is None:
        form = consent.load_form()
    t = _classify(dest, port, form)
    out.update(kind=t.kind, by=t.by, port=port, error=t.error)
    user = a.login or dest.user
    shown_user = formmod.safe(user) if user is not None else None
    shown_host = formmod.safe(dest.host)
    if t.kind == "host" and t.name:
        fh = form.hosts[t.name]
        out.update(name=t.name, user=shown_user if user is not None else fh.user(),
                   addr=(t.matches[0] if t.matches else fh.addresses()[0]).render()
                   if fh.addresses() else None)
    elif t.kind == "endpoint":
        u = shown_user if user is not None else paths.local_user()
        out.update(name=shown_host, user=u,
                   addr=f"{u}@{shown_host}:{port or 22}" if u and shown_host else None)
    else:
        out.update(name=shown_host, user=shown_user)
        if t.kind == "unknown":
            out["suggest"] = _suggest(dest.host, form)
    return out


# ---------------------------------------------------------------------------
# gate check helpers
# ---------------------------------------------------------------------------


def _form_host(st: State, name: str) -> formmod.Host:
    fh = st.form.hosts.get(name)
    if fh is None or fh.is_local:
        raise SshError(f"gateway: {name} isn't a host in gateway.toml")
    return fh


_NO_MATCHING_KEY = "no matching host key type"


def _scan_via(jump: Link, name: str, addr: formmod.Address) -> list[str]:
    """Host keys of a host behind a jump: ssh through the jump with an empty
    known_hosts (accept-new into a scratch file), one key type at a time, no
    authentication offered. The next key type is tried only after a
    connection that offered no matching key (review round 4: three attempts
    of 10 s each against a host that doesn't answer pushed gate check past
    Claude Code's 2-minute Bash timeout)."""
    found: list[str] = []
    target = Link(name=name, addr=addr, host_keys=[], pubkeys=[], master=False, jump=jump)
    with Conn(target) as conn:
        assert conn.dir is not None
        for i, algo in enumerate(SCAN_ALGOS):
            scan = conn.dir / f"scan-{i}"
            ssh_conf._write(scan, "")
            extra = ["-o", f"UserKnownHostsFile={scan}", "-o", "StrictHostKeyChecking=accept-new",
                     "-o", f"HostKeyAlgorithms={algo}", "-o", "PubkeyAuthentication=no",
                     "-o", "IdentityAgent=none"]
            err = ""
            try:
                r = conn.capture("true", timeout=30, extra=extra)
                err = (r.stderr or b"").decode("utf-8", "replace")
            except SshError:
                pass
            got = [k for k in (vault.norm_host_key(x) for x in scan.read_text().splitlines()) if k]
            found += got
            if not got and _NO_MATCHING_KEY not in err:
                break                  # no connection at all: the other types won't get one
    return list(dict.fromkeys(found))


def keyscan_host(name: str) -> list[str]:
    """Read a form host's keys through its chosen address/jump (SPEC 15 gate
    check, before the consent pop-up); returns 'type base64' strings."""
    st = _load()
    fh = _form_host(st, name)
    cands = list(fh.addresses())
    if fh.via:
        jump = _build_link(fh.via, st)
        choice = ssh_conf.choose(name, cands, [], via=True)
        keys = _scan_via(jump, name, _with_user(choice.addr))
    else:
        choice = ssh_conf.choose(name, cands, [], verify=False, use_cache=False)
        keys = vault.keyscan(choice.addr.host, choice.addr.port)
    if not keys:
        raise SshError(f"gateway: couldn't read {name}'s host key at {choice.addr.render()}; is it "
                       "on?", 255)
    audit.log("keyscan", host=name, address=choice.addr.render(),
              keys=vault.host_key_fingerprints(keys))
    return keys


def _ak_file() -> str:
    t = testing.get("ssh_authorized_keys")
    return shlex.quote(str(t)) if t else '"$HOME/.ssh/authorized_keys"'


_KEY_TYPE = re.compile(r"(?:ssh|ecdsa|sk)-[A-Za-z0-9@._-]{1,60}")
_KEY_BLOB = re.compile(r"[A-Za-z0-9+/]{16,}={0,3}")


def _key_fields(pub: str) -> tuple[str, str]:
    """(type, base64) of a public key line."""
    w = pub.split()
    for i in range(len(w) - 1):
        if _KEY_TYPE.fullmatch(w[i]) and _KEY_BLOB.fullmatch(w[i + 1]):
            return w[i], w[i + 1]
    raise SshError("gateway: a stored public key can't be read; run gate check for that host")


def _key_body(pub: str) -> str:
    return " ".join(_key_fields(pub))


# authorized_keys lines are matched by whole fields (the key type followed by
# its base64), after any options, never by substring.
# Comment lines never count (a commented-out key isn't installed) and are kept.
_AK_HAS = "/^[ \t]*#/ {next} {for(i=1;i<NF;i++) if($i==t && $(i+1)==b) f=1} END{exit !f}"
_AK_DROP = ('BEGIN{n=split(k,K," ")} /^[ \t]*#/ {print; next} {d=0; for(i=1;i<NF;i++) '
            'for(j=1;j<n;j+=2) if($i==K[j] && $(i+1)==K[j+1]) d=1} !d')


def ak_append_cmd(pub: str) -> str:
    """Append a public key to authorized_keys unless it is there (idempotent).
    A last line without a newline gets one first (else the key would be
    glued onto it)."""
    t, b = _key_fields(pub)
    line = " ".join(pub.split())
    return (f"umask 077; f={_ak_file()}; mkdir -p \"$(dirname \"$f\")\" && touch \"$f\" || exit 1; "
            f"awk -v t={shlex.quote(t)} -v b={shlex.quote(b)} '{_AK_HAS}' \"$f\" && exit 0; "
            "if [ -s \"$f\" ] && [ -n \"$(tail -c 1 \"$f\")\" ]; then printf '\\n' >> \"$f\" || "
            f"exit 1; fi; printf '%s\\n' {shlex.quote(line)} >> \"$f\"")


def ak_remove_cmd(pubs: list[str]) -> str:
    """Remove the lines holding these keys (whole-field match). The file is
    rewritten through a temp copy that keeps its mode (cp -p), then moved
    into place; a symlinked file is written through."""
    keys = shlex.quote(" ".join(_key_body(p) for p in pubs))
    drop = f"awk -v k={keys} '{_AK_DROP}' \"$f\" > \"$t\""
    return (f"umask 077; f={_ak_file()}; [ -f \"$f\" ] || exit 0; t=\"$f.gw$$\"; "
            f"if [ -L \"$f\" ]; then {drop} && cat \"$t\" > \"$f\"; rc=$?; rm -f \"$t\"; exit $rc; fi; "
            f"cp -p \"$f\" \"$t\" && {drop} && mv -f \"$t\" \"$f\"; rc=$?; rm -f \"$t\"; exit $rc")


def _key_comment(name: str, data: dict[str, Any]) -> str:
    return vault.key_comment(name, data)


def _ensure_key(name: str) -> str:
    """The host's newest live public key, generated and stored if none."""
    data = vault.load()
    live = vault.live_keys(((data.get("hosts") or {}).get(name)) or {})
    if live:
        return live[-1]["public"]
    priv, pub = vault.generate_ssh_key(_key_comment(name, data))
    with vault.edit() as d:
        r = vault.host_record(d, name)
        if not vault.live_keys(r):
            r["keys"].append(vault.key_record(priv, pub))
        out = vault.live_keys(r)[-1]["public"]
    audit.log("key_generated", host=name, fingerprint=vault.fingerprint_of(out))
    return out


_SOCK_RE = re.compile(r"/[A-Za-z0-9._/@%+=,: -]{1,400}")
# The usual agent sockets under $XDG_RUNTIME_DIR on Linux: systemd's
# ssh-agent.socket, gnome-keyring, gcr (GNOME 46+), and openssh's own unit.
_XDG_AGENT_SOCKETS = ("ssh-agent.socket", "keyring/ssh", "gcr/ssh", "openssh_agent")


def _my_socket(p: str) -> bool:
    """An absolute path to a unix socket owned by this user (an agent socket
    someone else planted, or a file, never counts)."""
    if not p or not _SOCK_RE.fullmatch(p):
        return False
    try:
        st = os.stat(p)
    except OSError:
        return False
    return stat.S_ISSOCK(st.st_mode) and st.st_uid == os.getuid()


def _recorded(name: str) -> str:
    """A variable from this session's record (private/sessions/<sid>.env,
    written by the hooks from Claude Code's own environment, which Claude's
    commands can't change), or ""."""
    try:
        from . import dialog
        text = dialog._session_record() or ""
    except Exception:  # noqa: BLE001
        return ""
    for line in text.splitlines()[:40]:
        k, sep, v = line.partition("=")
        if sep and k == name:
            return v
    return ""


def _user_agent_sock() -> str | None:
    """The user's own ssh agent for "use my own SSH login once". Claude's Bash
    (where gate check and its pop-up helper start) has SSH_AUTH_SOCK unset
    (others = "refuse"), so (round 3) it comes from the session record (Claude
    Code's environment), else the caller's environment, else macOS's
    launchd, else the usual sockets under $XDG_RUNTIME_DIR on Linux; each
    only when it is a socket owned by the user."""
    for cand in (_recorded("SSH_AUTH_SOCK"), os.environ.get("SSH_AUTH_SOCK", "")):
        if _my_socket(cand):
            return cand
    if sys.platform == "darwin" and testing.active() is None:
        with contextlib.suppress(OSError, subprocess.TimeoutExpired):
            r = subprocess.run(["/bin/launchctl", "getenv", "SSH_AUTH_SOCK"], capture_output=True,
                               text=True, timeout=5, stdin=subprocess.DEVNULL)
            if r.returncode == 0 and _my_socket(r.stdout.strip()):
                return r.stdout.strip()
    xdg = _recorded("XDG_RUNTIME_DIR") or os.environ.get("XDG_RUNTIME_DIR", "")
    if not xdg:
        if testing.active() is not None:
            # never the test machine's own runtime folder (the Debian VM has a
            # systemd ssh-agent socket there); a test names one with this knob
            xdg = testing.get("linux_runtime_dir", "")
        elif sys.platform.startswith("linux"):
            xdg = f"/run/user/{os.getuid()}"
    if xdg and os.path.isabs(xdg):
        for rel in _XDG_AGENT_SOCKETS:
            p = os.path.join(xdg, rel)
            if _my_socket(p):
                return p
    return None


def _user_agent_env() -> dict[str, str]:
    env = dict(os.environ)
    env.pop("SSH_AUTH_SOCK", None)
    sock = _user_agent_sock()
    if sock:
        env["SSH_AUTH_SOCK"] = sock
    return env


def _install_my_login(name: str, st: State, link: Link, cmd: str) -> None:
    """The user's own ssh login, once, from gate check (the user's agent and
    ssh setup; the gateway's pins for the host key)."""
    addr = link.addr
    with Conn(link) as conn:
        assert conn.dir is not None
        argv = _user_ssh_cmd()
        for o in (f"HostKeyAlias={link.alias}", f"UserKnownHostsFile={conn.dir / 'known_hosts'}",
                  "GlobalKnownHostsFile=/dev/null", "StrictHostKeyChecking=yes",
                  "CheckHostIP=no", "UpdateHostKeys=no", "BatchMode=yes", "ControlMaster=no",
                  "ControlPath=none", "ForwardAgent=no", "ForwardX11=no",
                  "PermitLocalCommand=no", "ClearAllForwardings=yes"):
            argv += ["-o", o]
        if link.jump is not None:
            conn.ensure_agent()
            pc = shlex.join([ssh_conf.ssh_bin(), "-F", str(conn.prepare()), "-W", "[%h]:%p",
                             link.jump.alias])
            argv += ["-o", f"ProxyCommand={pc}"]
        argv += ["-p", str(addr.port), "-l", addr.effective_user(), "-T", "--", addr.host, cmd]
        try:
            r = subprocess.run(argv, env=_user_agent_env(), capture_output=True, timeout=90,
                               stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise SshError(f"gateway: logging in to {name} with your own ssh setup took too long",
                           255) from None
    audit.log("install_key", host=name, method="my-login", address=addr.render(),
              ok=r.returncode == 0)
    if r.returncode != 0:
        why = "it refused your own key" if ssh_conf.AUTH_FAIL.search(
            r.stderr.decode("utf-8", "replace")) else f"ssh exited with {r.returncode}"
        raise SshError(f"gateway: couldn't install Claude's key on {name} with your own ssh login "
                       f"({why}); try the password or show-the-key option of gate check {name}",
                       255)


class _OneShotFifo:
    """A FIFO a writer thread fills once and unlinks right after the first
    write (SPEC 9.1's one-shot askpass pattern)."""

    def __init__(self, path: Path, payload: bytes):
        self.path, self.payload = path, payload
        os.mkfifo(path, 0o600)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_NONBLOCK)
            except OSError as e:
                if e.errno in (errno.ENXIO, errno.EAGAIN):
                    self.stop.wait(0.02)
                    continue
                return
            try:
                with contextlib.suppress(FileNotFoundError):
                    os.unlink(self.path)
                os.set_blocking(fd, True)
                with contextlib.suppress(OSError):
                    os.write(fd, self.payload)
            finally:
                os.close(fd)
            return

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=2)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(self.path)


def _install_password(name: str, st: State, link: Link, cmd: str, password: str | None) -> None:
    """Type the login password once (SSH_ASKPASS with SSH_ASKPASS_REQUIRE=force
    reading a one-shot FIFO)."""
    if password is None:
        password = _ask_secret(name, "login password", _secret_prompt(
            name, link, "login password", note="It is used once, to install Claude's key; the "
            "gateway doesn't keep it."), lazy=False,
            joined=f"gateway: the login password for {name} was typed into another call's dialog "
                   f"and isn't kept; run gate check {name} again", check=host_check(name, "ssh"))
    target = dataclasses.replace(link, pubkeys=[], privkeys=[], master=False)
    over = {target.alias: {"PasswordAuthentication": "yes", "KbdInteractiveAuthentication": "yes",
                           "PubkeyAuthentication": "no", "BatchMode": "no",
                           "NumberOfPasswordPrompts": "1", "IdentityAgent": "none",
                           "PreferredAuthentications": "keyboard-interactive,password"}}
    with Conn(target, over) as conn:
        assert conn.dir is not None
        if target.jump is not None:
            conn.ensure_agent()
        fifo = conn.dir / "pw.fifo"
        ask = conn.dir / "askpass"
        ssh_conf._write(ask, f"#!/bin/sh\n[ -p {shlex.quote(str(fifo))} ] || exit 1\n"
                             f"exec cat {shlex.quote(str(fifo))}\n", 0o700)
        feed = _OneShotFifo(fifo, (password + "\n").encode("utf-8"))
        try:
            env = ssh_conf.child_env({"SSH_ASKPASS": str(ask), "SSH_ASKPASS_REQUIRE": "force",
                                      "DISPLAY": "gw:0"})
            r = subprocess.run([*conn.base(), "-T", "--", conn.alias, cmd], env=env,
                               capture_output=True, timeout=90, stdin=subprocess.DEVNULL,
                               start_new_session=True)
        except subprocess.TimeoutExpired:
            raise SshError(f"gateway: {name} took too long to answer", 255) from None
        finally:
            feed.close()
    audit.log("install_key", host=name, method="password", address=link.addr.render(),
              ok=r.returncode == 0)
    if r.returncode != 0:
        raise SshError(f"gateway: {name} didn't accept that password (or password logins are off "
                       f"there); try another option of gate check {name}", 255)


def install_key(name: str, method: str, password: str | None = None) -> str:
    """Install the host's public key (SPEC 15). method: 'my-login' (the
    user's own ssh setup, once), 'password' (typed once; pass `password` from
    popup.secret, or it is asked here), 'show' (returns the public key line
    for the user to add). Returns a status line (for 'show': the key)."""
    if method not in ("my-login", "password", "show"):
        raise ValueError(f"unknown install method {method!r}")
    st = _load()
    _form_host(st, name)
    pub = _ensure_key(name)
    if method == "show":
        return pub
    st = _load()
    link = _build_link(name, st)
    cmd = ak_append_cmd(pub)
    if method == "my-login":
        _install_my_login(name, st, link, cmd)
    else:
        _install_password(name, st, link, cmd, password)
    ok, msg = test_login(name)
    if not ok:
        raise SshError(f"gateway: the key was added on {name} but logging in with it failed: "
                       f"{msg.removeprefix('gateway: ')}", 255)
    return f"gateway: Claude's key is installed on {name} ({vault.fingerprint_of(pub)})"


def _fresh(link: Link, keys: list[dict[str, Any]] | None = None) -> Link:
    """The same target without the shared master (a real login test)."""
    if keys is None:
        return dataclasses.replace(link, master=False)
    return dataclasses.replace(link, master=False, pubkeys=[k["public"] for k in keys],
                               privkeys=[k["private"] for k in keys])


def _audit_gate(link: Link, command: str, **extra: Any) -> None:
    """One audit `use` line for a credential use by the gate process itself
    (gate check helpers, copy-to): host, address, via, command summary."""
    audit.use("gate", link.name, None, ["ssh", link.name, command], address=link.addr.render(),
              via=link.jump.name if link.jump else None, why=link.why, **extra)


def test_login(name: str) -> tuple[bool, str]:
    """Test login with the gateway's key, without the shared master (SPEC 6
    verification). Records hosts[NAME].installed on success. (ok, message)."""
    try:
        st = _load()
        link = _fresh(_build_link(name, st))
        with Conn(link) as conn:
            _audit_gate(link, "true", check="test login")
            r = conn.capture("true", timeout=60)
    except SshError as e:
        return False, e.message
    err = r.stderr.decode("utf-8", "replace")
    if r.returncode == 0:
        ssh_conf.clear_authfail(name)
        with contextlib.suppress(Exception):
            with vault.edit() as d:
                vault.host_record(d, name)["installed"] = vault.now()
        return True, f"gateway: Claude's key works on {name} ({link.addr.render()})"
    msg = ssh_conf.explain_failure(name, r.returncode, err)
    if msg is None and ssh_conf.UNREACHABLE.search(err):
        msg = f"gateway: {name} didn't answer at {link.addr.render()}"
    return False, msg or f"gateway: logging in to {name} failed (ssh exited with {r.returncode})"


def verify_remote_sudo(name: str, user: str, password: str) -> tuple[bool, str]:
    """Remote staging test of a sudo password (SPEC 9.3, 6). (ok, message)."""
    try:
        st = _load()
        link = _build_link(name, st)
        with Conn(link) as conn:
            return _verify_sudo(conn, name, user, password)
    except SshError as e:
        return False, e.message


def probe_remote_nopasswd(name: str, user: str) -> bool:
    """`sudo -n true` over the master, cached 10 min per (host, user) (SPEC 9.3)."""
    c = ssh_sudo.probe_cached(name, user)
    if c is not None:
        return c
    st = _load()
    link = _build_link(name, st)
    with Conn(link) as conn:
        _audit_gate(link, ssh_sudo.PROBE_CMD, check="sudo probe", user=user)
        ok = ssh_sudo.probe(conn, name, user, use_cache=False)
    _note_probe(name, user, ok, st.data)
    return ok


def run(name: str, command: str, input: bytes | None = None, timeout: float = 120
        ) -> tuple[int, bytes, bytes]:
    """One remote command on form host NAME with the gateway's key and config,
    output captured: (exit code, stdout, stderr). In-process, for the gate
    process itself (copy-to, after the user's typed confirmation), so there
    is no ancestry check; the host's ssh right is held to _helper_right (via
    _build_link), and the use is audited. Raises SshError."""
    st = _load()
    eh = st.eff.hosts.get(name)
    _form_host(st, name)
    if eh is None or eh.new:
        raise SshError(f"gateway: {name} waits for the user's OK; run gate check {name} while the "
                       "user is here")
    link = _build_link(name, st)
    with Conn(link) as conn:
        _audit_gate(link, command.split(" ", 1)[0])
        r = conn.capture(command, stdin=input, timeout=timeout)
    if r.returncode == 255:
        msg = ssh_conf.explain_failure(name, 255, r.stderr.decode("utf-8", "replace"))
        if msg:
            raise SshError(msg, 255)
    return r.returncode, r.stdout, r.stderr


def close_masters(name: str) -> int:
    """Close the shared connections of a host and of the hosts reached through
    it (`-O exit`, sockets removed); forget its address and sudo-probe
    caches. Returns how many masters answered. Never raises."""
    n = 0
    try:
        n += ssh_conf.close_recorded(name)
        ssh_conf.cache_clear(name)
        ssh_sudo.probe_clear(name)
        try:
            form = formmod.load()
            behind = []
            for h in form.hosts.values():
                cur, seen = h.via, {h.name}
                while cur and cur not in seen:
                    if cur == name:
                        behind.append(h.name)
                        break
                    seen.add(cur)
                    nxt = form.hosts.get(cur)
                    cur = nxt.via if nxt else None
            for b in behind:
                n += ssh_conf.close_recorded(b)
        except Exception:  # noqa: BLE001
            pass
    except Exception:  # noqa: BLE001
        pass
    return n


def rotate(name: str, before_change: Callable[[], Any] | None = None) -> str:
    """Rotate a host's key (SPEC 15): new key, installed with the current one,
    verified alone, the old authorized_keys lines removed, the old keys
    retired in the vault. Returns a status line; raises SshError.
    before_change runs once, under the vault's lock, just before the first
    change to the vault (`gate rotate` keeps its copy of the vault there),
    never when the rotation fails before (no key, an unusable link)."""
    st = _load()
    link = _build_link(name, st)
    rec = (st.data.get("hosts") or {}).get(name) or {}
    old = vault.live_keys(rec)
    priv, pub = vault.generate_ssh_key(_key_comment(name, st.data))
    new = vault.key_record(priv, pub)
    with vault.edit() as d:
        if before_change is not None:
            before_change()
        vault.host_record(d, name)["keys"].append(new)

    def drop_new() -> None:
        with vault.edit() as d:
            r = vault.host_record(d, name)
            r["keys"] = [k for k in r["keys"] if k.get("fingerprint") != new["fingerprint"]]

    _audit_gate(link, "rotate", check="key rotation")
    try:
        with Conn(link) as conn:
            r = conn.capture(ak_append_cmd(pub), timeout=60)
        if r.returncode != 0:
            raise SshError(f"gateway: couldn't add the new key on {name}; the old key stays", 255)
        with Conn(_fresh(link, [new])) as conn:
            r = conn.capture("true", timeout=60)
        if r.returncode != 0:
            raise SshError(f"gateway: the new key didn't work on {name}; the old key stays", 255)
    except BaseException:
        # Not verified (a failed or raising check, an interrupted append): take
        # the new key's line out again over the old key (best effort; removing
        # a line that isn't there changes nothing), then forget the new key.
        with contextlib.suppress(Exception), Conn(link) as conn:
            conn.capture(ak_remove_cmd([pub]), timeout=60)
        drop_new()
        raise
    # The new key works: from here on a failure keeps it (dropping it now could
    # leave no working key if the old lines were already removed).
    try:
        with Conn(_fresh(link, [new])) as conn:
            r = conn.capture(ak_remove_cmd([k["public"] for k in old]), timeout=60)
        removed = r.returncode == 0
    except SshError:
        removed = False
    olds = {k.get("fingerprint") for k in old}
    with vault.edit() as d:
        for k in vault.host_record(d, name)["keys"]:
            if k.get("fingerprint") in olds and not k.get("retired"):
                k["retired"] = vault.now()
    audit.log("rotate", host=name, old=sorted(x for x in olds if x), new=new["fingerprint"],
              removed_old=removed)
    close_masters(name)
    tail = ("the old one was removed from the server" if removed else
            "removing the old one from authorized_keys failed; it is retired here")
    return f"gateway: {name} has a new key ({new['fingerprint']}); {tail}"
