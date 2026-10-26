"""FileChanged on gateway.toml: validate and tell the user (SPEC 12).

The watch path is registered by SessionStart (watchPaths). On a change:
validate the form, persist narrowings (consent.ratchet, through
hooks_session.prepare), and send the user a systemMessage with the errors or
with what changed since the last version this machine saw (`example: sudo
now ask`), plus which widenings wait for their OK. The last seen version is a
snapshot of rights in the run dir (form-seen.json, also written by
SessionStart); without one, the approved rights are the baseline. Unchanged
content: no message.
"""
from __future__ import annotations

import json
import os
from typing import Any

from . import paths
from . import form as formmod

WORDS = {True: "on", "ask": "ask", False: "off", "cc": "cc"}


def _word(v: Any) -> str:
    """A right in a snapshot: on, ask, off, cc, or "per mode" for a six-mode
    map (PLAN-0.11 §2.7)."""
    return "per mode" if isinstance(v, dict) else WORDS.get(v, "?") if isinstance(v, (bool, str)) else "?"


def _seen_path():
    return paths.run_dir() / "form-seen.json"


def record_seen(form: formmod.Form) -> None:
    """Remember the rights of this form as the version the user last saw
    (FileChanged reports changes against it). SessionStart records the form it
    loaded, so a narrowing PostToolUse persisted before FileChanged ran is
    still reported (review round 2)."""
    from . import consent
    if not form.exists or form.syntax_error is not None:
        return
    try:
        p = _seen_path()
        tmp = p.with_name(p.name + f".{os.getpid()}")
        tmp.write_text(json.dumps({"sha256": form.sha256, "rights": consent.snapshot(form)}))
        os.replace(tmp, p)
    except (OSError, paths.PathError):
        pass


def _addr(d: dict[str, Any]) -> str:
    u, h, p = d.get("user"), d.get("host"), int(d.get("port") or 22)
    hp = f"[{h}]" if h and ":" in str(h) else str(h)
    return (f"{u}@" if u else "") + (hp if p == 22 else f"{hp}:{p}")


def describe_changes(old: dict[str, Any], new: dict[str, Any]) -> list[str]:
    """Short lines for the differences between two rights snapshots
    (consent.snapshot shapes). Names are validated form entry names."""
    out: list[str] = []
    o_set, n_set = (old.get("settings") or {}), (new.get("settings") or {})
    o_sh =o_set.get("shell") if isinstance(o_set.get("shell"), dict) else {}
    n_sh = n_set.get("shell") if isinstance(n_set.get("shell"), dict) else {}
    if o_sh.get("managed", "on") != n_sh.get("managed", "on"):
        out.append(f"managed shell now \"{n_sh.get('managed', 'on')}\"")
    for key, what in (("import_path", "PATH import"), ("import_env", "environment import")):
        ol, nl = list(o_sh.get(key) or []), list(n_sh.get(key) or [])
        out += [f"new {what} {x}" for x in nl if x not in ol]
        out += [f"{what} {x} removed" for x in ol if x not in nl]
    oh, nh = old.get("hosts") or {}, new.get("hosts") or {}
    for n in nh:
        if n not in oh:
            h = nh[n]
            bits = []
            if h.get("addresses"):
                bits.append(_addr(h["addresses"][0]))
            if "ssh" in h:
                bits.append(f"ssh {_word(h.get('ssh'))}")
            bits.append(f"sudo {_word(h.get('sudo'))}")
            out.append(f"{n}: new host (" + ", ".join(bits) + ")")
            continue
        a, b = oh[n], nh[n]
        for k in ("ssh", "sudo"):
            if k in b and a.get(k) != b.get(k):
                out.append(f"{n}: {k} now {_word(b.get(k))}")
        if bool(a.get("scripts")) != bool(b.get("scripts")):
            out.append(f"{n}: scripts now {'on' if b.get('scripts') else 'off'}")
        oa = [_addr(x) for x in a.get("addresses") or []]
        na = [_addr(x) for x in b.get("addresses") or []]
        for x in na:
            if x not in oa:
                out.append(f"{n}: new address {x}")
        for x in oa:
            if x not in na:
                out.append(f"{n}: address {x} removed")
        if a.get("via") != b.get("via"):
            out.append(f"{n}: via {b.get('via')}" if b.get("via") else f"{n}: direct now (no via)")
    for n in oh:
        if n not in nh:
            out.append(f"{n}: host removed")
    oa_, na_ = old.get("accounts") or {}, new.get("accounts") or {}
    for n in na_:
        b = na_[n]
        if n not in oa_ or oa_[n].get("kind") != b.get("kind"):
            out.append(f"{n}: new {b.get('kind')} account")
            continue
        a = oa_[n]
        if bool(a.get("use", True)) != bool(b.get("use", True)):
            out.append(f"{n}: use now {'true' if b.get('use', True) else 'false'}")
        if bool(a.get("scripts")) != bool(b.get("scripts")):
            out.append(f"{n}: scripts now {'on' if b.get('scripts') else 'off'}")
        if a.get("env") != b.get("env"):
            out.append(f"{n}: env {b.get('env')}" if b.get("env") else f"{n}: env removed")
        od, nd = list(a.get("destinations") or []), list(b.get("destinations") or [])
        for d in nd:
            if d not in od:
                out.append(f"{n}: may now send to {d}")
        for d in od:
            if d not in nd:
                out.append(f"{n}: no longer sends to {d}")
        for k in ("auth", "tenant", "client_id"):
            if (a.get(k) or None) != (b.get(k) or None):
                out.append(f"{n}: {k} changed")
    for n in oa_:
        if n not in na_:
            out.append(f"{n}: account removed")
    return out


def main(payload: dict) -> dict | None:
    """systemMessage with errors or what changed, or None (SPEC 12)."""
    if not isinstance(payload, dict):
        return None
    from . import hooks_post
    if not hooks_post.is_form_path(payload.get("file_path"), payload.get("cwd")):
        return None
    from . import consent, hooks_session
    msgs: list[str] = []
    formmod.clear_cache()
    form, eff, data = hooks_session.prepare(msgs, write=False)
    # the managed shell follows the form at once (a narrowing applies to the
    # next command; gate-sh renews too when it sees a newer form)
    try:
        from . import managed, vault
        managed.sync(form, eff, vault_readable=not (vault.exists() and data is None))
    except Exception:  # noqa: BLE001
        pass
    # the stand-ins on PATH follow the configured set (PLAN-0.11 §1.2)
    from . import envfile
    envfile.sync_standins(form, eff)
    consent.sync_network_words(eff)          # pre_bash.sh's extra trigger words (WS-3)
    lines: list[str] = []
    if not form.exists:
        if form.from_last_good:
            # PLAN-0.11 §1.1: the last good version applies meanwhile
            lines.append("gateway: gateway.toml was removed; until it's back the gateway uses the "
                         "last good version (your approvals are kept; the next session restores "
                         "it). Put it back, or ask Claude to write a new one.")
        else:
            lines.append("gateway: gateway.toml was removed; until it's back only this computer's "
                         "defaults apply and the hosts and accounts it named are refused (your "
                         "approvals are kept). Put it back, or ask Claude to write a new one.")
        return {"systemMessage": "\n".join(lines)}
    snap = consent.snapshot(form)
    try:
        seen = json.loads(_seen_path().read_text())
    except (OSError, ValueError, paths.PathError):
        seen = None
    if isinstance(seen, dict) and seen.get("sha256") == form.sha256 and not form.syntax_error:
        return None
    lines += hooks_session.form_messages(form)
    if form.syntax_error is None:
        old = seen.get("rights") if isinstance(seen, dict) and isinstance(seen.get("rights"), dict) \
            else consent.approved_rights(data)
        changes = describe_changes(old, snap)
        if changes:
            lines.append("gateway: gateway.toml changed: " + "; ".join(changes[:12])
                         + (f" (+{len(changes) - 12} more)" if len(changes) > 12 else ""))
        names = eff.pending_names()
        if names:
            lines.append("gateway: waiting for your OK: " + ", ".join(names[:8]) + ". "
                         + hooks_session.ok_how(names[0] if len(names) == 1 else "all", names))
        record_seen(form)
    lines += msgs
    return {"systemMessage": "\n".join(lines)} if lines else None
