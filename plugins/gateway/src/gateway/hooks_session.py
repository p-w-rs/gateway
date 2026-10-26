"""SessionStart (sync) and SubagentStart hooks (SPEC 7, 12, 13).

SessionStart: validate the form, sync approvals (narrowing applies and lowers
the approved snapshot), write $CLAUDE_ENV_FILE and env.sh, the stand-ins, the
git include file and the terminal launcher, then print additionalContext
(what Claude may use, generated from the validated form only: names, kinds,
rights, logins, owners, sites; never notes or other free text) and a
systemMessage for anything the user must know (a gateway 0.6 vault waiting
for its conversion, form errors, widenings waiting for an OK, pending
dialogs, new security events, the first 0.11 session's notice). Where the
payload carries `permission_mode`, it is recorded in gated (lead decision 3).
The context says the posture (PLAN-0.11 §1.9): the gateway stands only
between Claude and what gateway.toml configures.
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any

from . import accounts as acctmod
from . import consent, envfile, paths, testing, vault
from . import form as formmod

CONTEXT_MAX = 2500
# PLAN-0.11 §1.9: the gateway stands only between Claude and what
# gateway.toml configures; everything else is the user's own.
INTRO = ("Gateway (plugin): machines and accounts in gateway.toml go through the gateway, which "
         "supplies their passwords, keys and tokens. Anything not in gateway.toml uses your own "
         "ssh, git, gh and sudo directly, with no gateway involvement. Never ask the user for a "
         "password, token or key in chat.")
HOWTO = [
    "- Run sudo/ssh/scp/rsync for the machines below as their own command (optionally after cd) "
    "so the gateway can approve them (\"ask\" asks the user).",
    "- Don't remove or rename a gateway.toml entry, or reach a configured host by another name, "
    "address or path, to get past a refusal. Ask the user.",
    "- Web: the gateway's http and download tools; network commands (curl, wget, ...) are asked "
    "about. WebFetch reads pages.",
    "- Choose an account with GATE_ACCOUNT=NAME before the command if the gateway says two fit.",
    "- To add or change a host or account, edit ~/.config/gateway/gateway.toml (only when the "
    "user asks), then run `gate check NAME` while the user is here. Adding or widening needs the "
    "user's OK in the gateway's own dialog in Claude Code; secrets are typed only there.",
    "- If the gateway says its dialog is waiting, tell the user once and continue with other work.",
    "- `gate status` shows everything; `gate why` explains the last refusal.",
]
# Added while this computer's sudo isn't configured (PLAN-0.11 §1.5, §1.9):
# the user's own sudo, and Claude's Bash has no terminal for its password.
OWN_SUDO_HOWTO = ("- Your own sudo works only where it needs no password; Claude has no terminal "
                  "to type one. If sudo says a password or terminal is required, tell the user "
                  "that the gateway can ask in its dialog once [hosts.localhost] sudo is set "
                  "(gate host set localhost sudo ask).")
# Added when the checkpoint plugin is live: gated saw a CONTRACT-v1 client
# within CHECKPOINT_FRESH (its <run>/checkpoint-seen; PLAN-0.11 §9.4, lead
# decision 7). Its job_start runs commands as detached jobs (hooks_bash.JOB_TOOL). Checkpoint
# 0.6+ hands them to gated's contract job routes while gated serves the
# session (the managed environment, per-job on_pause); only otherwise does
# its own runner run them, with env.sh. A job of that runner still running
# after its session ends is re-parented to init, where ancestry no longer
# sees checkpoint's runner: not direct, so no credential without scripts =
# true (DECISIONS, "Integration lows"); a gated job gets nothing from a
# wrapped key once its session ends (Registry.pane_session).
JOBS_HOWTO = ("- checkpoint jobs (job_start) run on this machine under the gateway's own job "
              "supervisor while it serves this session (these stand-ins; on_pause says what a "
              "pause does), else under checkpoint's runner with the gateway's env.sh. Count on "
              "credentials only while this session is open, unless the entry has scripts = true. "
              "Jobs are judged like Bash, but nobody can be asked while a job runs: a network "
              "command that [network] asks about (curl, wget, ...) and an \"ask\" right are "
              "refused there, so run such a command with Bash. job_tail and job_stop mask stored "
              "secrets as *** like Bash output.")


# Added in managed mode (PLAN-v4 phase 4; PLAN-0.11 §1.6, §1.9): where
# Claude's commands run.
MANAGED_HOWTO = ("- Your Bash runs in the gateway's bash 5 with your own PATH, variables and "
                 "aliases. The gateway's stand-ins come first for the machines and accounts it "
                 "handles.")
# How fresh gated's record of a checkpoint client must be for JOBS_HOWTO (s).
CHECKPOINT_FRESH = 24 * 3600


# Added in managed mode while the form has no [shell] import_path at all
# (GW-UX-2b): the tool folders this machine has that Claude's commands can't
# reach yet (managed.found_not_imported), and how to offer them. Only when it
# fits in CONTEXT_MAX: the hosts and accounts come first.
IMPORT_OFFER = ("- Tool folders here your commands can't use yet (not imported): {dirs}. When "
                "the work needs one (brew, npm, cargo, ...), propose importing it: add it to "
                "[shell] import_path in ~/.config/gateway/gateway.toml, then `gate check "
                "settings`, and the user approves in the gateway's dialog. Never import "
                "without that OK.")


def _import_offer(eff: consent.Effective, form: formmod.Form) -> str | None:
    """IMPORT_OFFER for this machine, or None: managed mode, no import_path
    key in the form (`import_path = []` says no) and folders found."""
    if getattr(eff, "shell", None) is None or eff.shell.managed == "off" \
            or form.shell.path_line is not None:
        return None
    from . import managed
    found = managed.found_not_imported(eff)
    return IMPORT_OFFER.format(dirs=", ".join(found)) if found else None


# Added on Linux without a graphical display (neither DISPLAY nor
# WAYLAND_DISPLAY in Claude Code's environment, which the hook inherits): the
# dialog's Paste can't read a clipboard there (daemon/clipboard.py), and on
# Claude Code's main screen nothing can be typed into its field either
# (review round 2). Said once, in the context, after the hosts and accounts
# (NO_DISPLAY_SHORT when it doesn't fit); the dialog and /gate-doctor say it too
# (hooks/mod/dialog.ts NO_DISPLAY_MAIN, lib.ts secretLine).
NO_DISPLAY_NOTE = ("- No graphical display here (Linux, no DISPLAY or WAYLAND_DISPLAY): the "
                   "gateway dialog's Paste from clipboard can't work, nor typing on Claude Code's "
                   "main screen. If a credential is needed, tell the user: type /tui fullscreen "
                   "(it restarts and resumes the session) to type it, or set it from this "
                   "machine's desktop.")
# What stays when the whole note doesn't fit beside the hosts and accounts:
# the note never takes a host's or an account's place (on a headless Linux
# server those matter more, and the dialog and /gate-doctor say it in full).
NO_DISPLAY_SHORT = ("- No graphical display here: the gateway dialog's Paste and typing on the main "
                    "screen can't work (/gate-doctor says what to do).")


def _platform() -> str:
    return sys.platform


def _no_display_note() -> str | None:
    """NO_DISPLAY_NOTE on Linux without DISPLAY and WAYLAND_DISPLAY, else None."""
    if not _platform().startswith("linux") or os.environ.get("DISPLAY") \
            or os.environ.get("WAYLAND_DISPLAY"):
        return None
    return NO_DISPLAY_NOTE


def checkpoint_live() -> bool:
    """Did gated serve a checkpoint client (a CONTRACT-v1 route) in the last
    CHECKPOINT_FRESH seconds (its <run>/checkpoint-seen; PLAN-0.11 §9.4)? A
    session that checkpoint connects to later lacks JOBS_HOWTO; the next one
    has it. Never stats checkpoint's own folders."""
    try:
        t = paths.checkpoint_seen_path().stat().st_mtime
    except (OSError, paths.PathError):
        return False
    return 0 <= time.time() - t < CHECKPOINT_FRESH


def _own_sudo(eff: consent.Effective | None) -> bool:
    """This computer's sudo is the user's own (nothing configures it)."""
    lh = eff.hosts.get("localhost") if eff is not None else None
    return lh is not None and "sudo" not in lh.modes


def _howto(eff: consent.Effective | None = None) -> list[str]:
    out = list(HOWTO)
    if _own_sudo(eff):
        out.insert(1, OWN_SUDO_HOWTO)
    if checkpoint_live():
        out.append(JOBS_HOWTO)
    if eff is not None and getattr(eff, "shell", None) is not None and eff.shell.managed != "off":
        out.append(MANAGED_HOWTO)
    return out


# ---------------------------------------------------------------------------
# What Claude is told
# ---------------------------------------------------------------------------


def _nopasswd_cached(user: str) -> bool | None:
    try:
        p = paths.sudo_probe_path(user)
        txt = p.read_text().strip()
    except (OSError, paths.PathError):
        return None
    return txt.startswith("yes")


def _host_text(e: consent.EffectiveHost, meta: dict[str, Any]) -> str:
    n = e.name
    if e.new:
        return f"{n} (not active yet: waits for the user's OK; run `gate check {n}` while they're here)"
    bits: list[str] = []
    keyless = False
    if e.is_local and "sudo" not in e.modes:
        # PLAN-0.11 §1.5: nothing configures this computer's sudo
        return f"{n} (sudo: your own, not through the gateway; see below)"
    if e.is_local:
        if e.sudo is True:
            s = "sudo: yes"
        elif e.sudo == "ask":
            s = "sudo: asks the user each time"
        else:
            s = "sudo: off"
        if e.sudo is not False:
            user = paths.local_user()
            st = (meta.get("localhost") or {}).get("sudo", {}).get(user)
            np = _nopasswd_cached(user)
            if np:
                s += ", no password needed"
            elif st and st.get("stale"):
                s += ", the saved password was rejected (the gateway dialog asks again)"
            elif st:
                s += ", password saved"
        bits.append(s)
    else:
        if e.ssh is True:
            ssh = "ssh"
        elif e.ssh == "ask":
            ssh = "ssh (asks the user each time)"
        else:
            ssh = "ssh: off"
        if e.via and e.ssh is not False:
            ssh += f" via {e.via}"
        bits.append(ssh)
        if e.sudo is True:
            bits.append("sudo")
        elif e.sudo == "ask":
            bits.append("sudo asks the user")
        else:
            bits.append("sudo: off")
        hm = (meta.get("hosts") or {}).get(n) or {}
        keyless = e.ssh is not False and not hm.get("keys")
        if keyless:
            bits.append(f"no key installed yet: `gate check {n}` while the user is here")
    if e.scripts:
        bits.append("scripts get credentials too")
    tail = ""
    if not e.is_local and e.ssh is True and not e.via and not keyless:
        tail = f"; reach as `ssh {n} CMD`"
    pend = f"; a change waits for the user's OK (`gate check {n}`)" if e.pending else ""
    first, rest = bits[0], bits[1:]
    joiner = ", " if not e.is_local else "; "
    return f"{n} ({first}{(joiner if rest else '') + ', '.join(rest)}{tail}{pend})"


def _account_text(e: consent.EffectiveAccount, meta: dict[str, Any]) -> str:
    a = e.account
    n = e.name
    if a is None:
        return n
    if e.new:
        return f"{n} ({a.kind}; not active yet: run `gate check {n}` while the user is here)"
    if not e.use:
        return f"{n} (off)"
    bits: list[str] = []
    if a.kind == "github":
        if a.login:
            bits.append(a.login)
        if a.host and a.host != "github.com":
            bits.append(f"on {a.host}")
        if a.default:
            bits.append("default")
        own = [f"{o}/*" for o in a.owners]
        if own:
            bits = [", ".join(bits)] if bits else []
            bits.append(", ".join(own))
            text = "; ".join(b for b in bits if b)
            bits = [text]
    elif a.kind == "huggingface":
        if a.login:
            bits.append(a.login)
        if a.default:
            bits.append("default")
    elif a.kind == "azure":
        bits.append(f'use the http tool with account "{n}"')
        if a.databricks:
            bits.append("databricks CLI")
        if e.env:
            # `gate with` refuses azure accounts (no raw token in a variable);
            # SDKs get tokens from the az stand-in (AzureCliCredential), and a
            # program Claude starts is not Claude's own command
            bits.append("the az stand-in for Azure SDKs (programs need scripts = true)")
    elif a.kind == "ml-catalog":
        bits.append("asiml CLI")
    elif a.kind == "pijul":
        bits.append("pijul CLI" + (f" as {a.login}" if a.login else ""))
    elif a.kind == "registry":
        bits.append(f"crane for {a.host}")
    elif a.kind == "api-key":
        sites = ", ".join(e.destinations) or "no site yet"
        bits.append(f"api-key for {sites}")
        bits.append(f'http tool account "{n}"')
        if e.env:
            bits.append(f"`gate with {n} -- CMD` for programs")
    am = (meta.get("accounts") or {}).get(n) or {}
    ent = am.get("entra_info") or {}
    entra = a.kind in ("azure", "ml-catalog") and acctmod.entra_stored(ent)
    if meta and not (am.get("token") or am.get("ssh_key") or entra):
        bits.append(f"not signed in yet: `gate check {n}`")
    elif am.get("stale"):
        bits.append(f"token rejected: `gate check {n}`")
    elif entra and not acctmod.entra_fits(a, ent):
        # gate check's rule: an older gateway's sign-in, or one for settings
        # that changed since, isn't used
        bits.append(f"needs a new sign-in: `gate check {n}`")
    if e.pending:
        bits.append(f"a change waits for the user's OK (`gate check {n}`)")
    sep = "; " if a.kind in ("api-key", "azure") else ", "
    return f"{n} ({sep.join(bits)})" if bits else n


def context_text(form: formmod.Form, eff: consent.Effective, meta: dict[str, Any] | None) -> str:
    meta = meta or {}
    hosts = [_host_text(e, meta) for e in eff.hosts.values()]
    accts = [_account_text(e, meta) for e in eff.accounts.values()]
    n_off = form.n_off
    lines = [INTRO, "Hosts: " + "; ".join(hosts) + "."]
    if accts:
        lines.append("Accounts: " + ", ".join(accts) + ".")
    else:
        lines.append("Accounts: none yet.")
    if n_off:
        # A count, never the names: a name that failed validation isn't rendered.
        lines.append(f"{n_off} {'entry is' if n_off == 1 else 'entries are'} off because of a "
                     "mistake in gateway.toml (see `gate status`).")
    if form.syntax_error:
        lines.append("gateway.toml has a syntax error"
                     + (f" on line {form.syntax_error.line}" if form.syntax_error.line else "")
                     + ("; the gateway uses the last good version" if form.from_last_good
                        else "; until it's fixed only the defaults apply")
                     + " (see `gate status`).")
    howto = _howto(eff)
    text = "\n".join(lines + howto)
    note = _no_display_note()
    if note is not None:
        # after the details: whole when it fits, else short; when not even that
        # fits, the short one joins the how-to lines the cut form keeps
        for n in (note, NO_DISPLAY_SHORT):
            if len(text) + 1 + len(n) <= CONTEXT_MAX:
                text += "\n" + n
                break
        else:
            howto = [*howto, NO_DISPLAY_SHORT]
            text = "\n".join(lines + howto)
    if len(text) <= CONTEXT_MAX:
        offer = _import_offer(eff, form)
        if offer is not None and len(text) + 1 + len(offer) <= CONTEXT_MAX:
            text += "\n" + offer
        return text
    # Too long: the intro and every how-to line stay; then as many names as fit.
    tail = ["(Details: `gate status`.)", *howto]
    budget = CONTEXT_MAX - len("\n".join([INTRO, *tail])) - 2   # two newlines for two lines
    accts_full = _fit("Accounts", list(eff.accounts), budget)
    hosts_line = _fit("Hosts", list(eff.hosts), budget - min(len(accts_full), budget // 2))
    accts_line = _fit("Accounts", list(eff.accounts), budget - len(hosts_line))
    return "\n".join([INTRO, hosts_line, accts_line, *tail])


def _fit(label: str, names: list[str], room: int) -> str:
    """'Label: a, b and 7 more.' within room characters (names are validated)."""
    if not names:
        return f"{label}: none yet."
    shown: list[str] = []
    for n in names:
        rest = len(names) - len(shown) - 1
        cand = f"{label}: " + ", ".join(shown + [n]) + (f" and {rest} more" if rest else "") + "."
        if len(cand) > room:
            break
        shown.append(n)
    rest = len(names) - len(shown)
    return f"{label}: " + ", ".join(shown) + (
        f"{' and ' if shown else ''}{rest} more" if rest else "") + "."


# ---------------------------------------------------------------------------
# Session state for the prompt hook (form changed since the last context?)
# ---------------------------------------------------------------------------


def _sid(session_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9_-]", "_", session_id or "nosession")[:80]


def record_context(session_id: str, form: formmod.Form) -> None:
    """Remember that this session got the context for this form (prompt.sh
    sends a fresh one when there is no record or the form is newer).
    Replaced whole (temp file, rename)."""
    try:
        p = paths.session_dir() / f"{_sid(session_id)}.json"
        tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps({"form_mtime_ns": form.mtime_ns, "form_sha256": form.sha256}))
        os.replace(tmp, p)
    except (OSError, paths.PathError):
        pass


def context_state(session_id: str) -> dict[str, Any] | None:
    try:
        return json.loads((paths.session_dir() / f"{_sid(session_id)}.json").read_text())
    except (OSError, ValueError, paths.PathError):
        return None


# ---------------------------------------------------------------------------
# Pending dialogs (popup.py writes them; see its docstring)
# ---------------------------------------------------------------------------


def pending_requests() -> list[dict[str, Any]]:
    """Pop-up requests still waiting (state open or unavailable), after
    dropping the stale ones (a dead helper's request isn't "waiting")."""
    from . import popup
    try:
        popup.cleanup_stale()
        return [d for d in popup.pending() if d.get("state") in ("open", "unavailable")]
    except (OSError, paths.PathError):
        return []


# SSH_AUTH_SOCK: the user's own agent, for gate check's "use my own SSH login
# once", as Claude Code's own environment has it (a command in Claude's Bash
# may have changed or unset its own; ssh._user_agent_sock checks it is a
# socket of the user's before using it).
SESSION_VARS = ("DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR",
                "DBUS_SESSION_BUS_ADDRESS", "SSH_CONNECTION", "SSH_TTY", "SSH_AUTH_SOCK")
_SESSION_VALUE = re.compile(r"[A-Za-z0-9_.:/=,@%+ -]*")


def write_session_record(session_id: str) -> None:
    """private/sessions/<sid>.env, the same record prompt.sh writes at the
    first prompt (same format; written once, mode 0600, never overwritten):
    when the session started (its mtime: copy-to's "pinned before this
    session") and Claude Code's own display variables (dialog.py opens
    pop-ups there, not on a display Claude's commands name). Hooks get Claude
    Code's environment, not Claude's Bash's."""
    if not session_id:
        return
    try:
        paths.ensure_private()
        d = paths.private_dir() / "sessions"
        if not d.exists():
            os.mkdir(d, 0o700)
        if d.is_symlink() or not d.is_dir():
            return
        lines = [f"started={int(time.time())}"]
        for v in SESSION_VARS:
            val = os.environ.get(v, "")
            lines.append(f"{v}={val if _SESSION_VALUE.fullmatch(val) else ''}")
        # popup.sid_slug's name (_sid is the same; importing popup costs this
        # hook urllib and ssl). Written whole, then linked in place only if
        # there is no record yet: a killed hook leaves none rather than half
        # of one (prompt.sh then writes it at the first prompt).
        final = d / f"{_sid(session_id)}.env"
        if os.path.lexists(final):
            return                   # exists already (resume)
        _link_new(final, "\n".join(lines) + "\n", 0o600)
    except (OSError, paths.PathError):
        return                       # no private folder, or another writer won


# ---------------------------------------------------------------------------
# The hooks
# ---------------------------------------------------------------------------


VAULT_LOCKED = ("gateway: the gateway vault is locked (its key has a passphrase), so stored "
                "credentials are unavailable, the machines and accounts in gateway.toml and this "
                "computer's configured sudo are refused, and rights waiting in the vault don't "
                "apply until the user unlocks it (/gate-unlock in Claude Code; only "
                "if the user lost the passphrase: gate passphrase --start-over); /gate-doctor "
                "shows its state. Anything not in gateway.toml uses the user's own tools.")


def _load_vault(msgs: list[str]) -> dict[str, Any] | None:
    if not vault.exists():
        return None
    try:
        return vault.load()
    except vault.VaultLocked:
        msgs.append(VAULT_LOCKED)
        return None
    except paths.PathError as e:
        # a wrapped key's reads go to the daemon, at the run folder (GW-ROB-1)
        msgs.append(f"gateway: the vault can't be read: {paths.explain(e)}")
        return None
    except vault.VaultError as e:
        msgs.append(f"gateway: the vault can't be read ({e}); stored secrets are unavailable until it "
                    "can. If ~/.config/gateway/private/key.txt was changed or lost, put back the copy "
                    "that belongs to this vault from your backup; if that key is gone, move "
                    "private/vault.age aside and gate import an export, or set the entries up again "
                    "with gate check NAME")
        return None


def _link_new(final: Path, text: str, mode: int) -> None:
    """Create `final` with `text` only if nothing is there (not even a
    symlink), all at once: the text goes to a temp file, which is then hard
    linked as `final` (FileExistsError if something is there). Where hard
    links aren't supported: O_EXCL and write, as before."""
    tmp = final.with_name(f".{final.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        os.link(tmp, final)
    except FileExistsError:
        raise
    except OSError:
        fd = os.open(final, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                     mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
    finally:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        envfile.drop_stale_temps(final)


def _create_form(text: str) -> bool:
    """Write gateway.toml only if it doesn't exist, all at once (_link_new: a
    SessionStart killed meanwhile leaves no cut-short form). True if written."""
    try:
        paths.ensure_home()
        _link_new(paths.form_path(), text, 0o600)
    except OSError:
        return False
    formmod.clear_cache()
    return True


def _has_approvals(data: dict[str, Any] | None) -> bool:
    rights = ((data or {}).get("approved") or {}).get("rights") or {}
    st = rights.get("settings") or {}
    sh = st.get("shell") if isinstance(st.get("shell"), dict) else {}
    return bool(rights.get("hosts") or rights.get("accounts")
                or sh.get("import_path") or sh.get("import_env")
                or sh.get("managed", "on") != "on")


def _missing_form(msgs: list[str], data: dict[str, Any] | None, write: bool) -> None:
    """gateway.toml is missing. A gateway 0.6 vault waiting for its conversion
    (vault.v06_waiting): leave it missing (gateway 0.10.0's conversion writes
    it). A vault with a last good form: restore that (never the starter, which
    would read as "every entry removed" and wipe approvals and bindings). A
    vault with approvals but no copy: leave it missing (nothing ratchets on a
    missing form). Nothing stored: write the starter form (form.STARTER)."""
    if vault.v06_waiting():
        return
    if data is None and vault.exists():
        return       # the vault can't be read now: never write a starter over its approvals
    last = (data or {}).get("form_last_good")
    if last:
        if write and _create_form(last):
            msgs.append("gateway: gateway.toml was missing; restored the last good version from "
                        "the vault (" + paths.describe(paths.form_path()) + ")")
        return
    if _has_approvals(data):
        msgs.append("gateway: gateway.toml is missing; until it's back only this computer's "
                    "defaults apply (your approvals are kept). Put it back, or ask Claude to "
                    "write a new one.")
        return
    if write:
        _create_form(formmod.STARTER)


def prepare(msgs: list[str], *, write: bool) -> tuple[formmod.Form, consent.Effective,
                                                      dict[str, Any] | None]:
    """Load vault and form, persist narrowings (consent.ratchet, every mode),
    compute effective rights. write=True (SessionStart) also restores a missing
    form or writes the starter, and keeps form_last_good and the machine record."""
    data = _load_vault(msgs)
    last = (data or {}).get("form_last_good")
    form = formmod.load(last_good=last)
    if not form.exists:
        _missing_form(msgs, data, write)
        form = formmod.load(last_good=last, use_cache=False)
    if ((data is None and not vault.exists())
            or (data is not None and (consent.needs_sync(data, form) or (
                consent.last_good_ok(form) and data.get("form_last_good") != form.used_text)))):
        # (with no vault yet, ratchet creates one only for a narrowing)
        try:
            consent.ratchet(form)
            if vault.exists():
                data = vault.load()
        except vault.VaultError as e:
            msgs.append(f"gateway: couldn't update the vault ({e})")
    if write and data is not None:
        need_last_good = form.syntax_error is None and form.exists and not form.from_last_good \
            and data.get("form_last_good") != form.used_text
        need_machine = not (data.get("machine") or {}).get("id")
        if need_last_good or need_machine:
            try:
                with vault.edit() as cur:
                    if need_last_good:
                        cur["form_last_good"] = form.used_text
                    vault.ensure_machine(cur)
                    data = cur
            except vault.VaultError as e:
                msgs.append(f"gateway: couldn't update the vault ({e})")
    eff = consent.compute(form, data)
    return form, eff, data


# The first 0.11 session (PLAN-0.11 §1.5): said once, then recorded in the
# vault's one-time notices (vault.mark_notice(vault.POSTURE_NOTICE)).
POSTURE_SUDO = ("gateway: this computer's sudo now uses your own sudo unless gateway.toml sets "
                "[hosts.localhost] sudo. The stored password stays unused; gate forget localhost "
                "removes it.")
POSTURE_POLICY = ("gateway: gateway.toml's [policy] {keys} now binds only the machines and "
                  "accounts in gateway.toml; anything else is your own (it no longer reaches "
                  "everything it used to).")
GLOBAL_REACH_KEYS = ("read", "exec", "write", "credential")


def posture_notice(eff: consent.Effective, data: dict[str, Any] | None) -> list[str]:
    """The first 0.11 session's notice (once per vault): a stored local sudo
    password that the posture leaves unused (this computer's sudo isn't
    configured), and the global [policy] denies that no longer reach
    unconfigured targets. Written as a systemMessage (SessionStart can't wait
    for a dialog) and recorded in the vault so it never repeats. Nothing
    while the vault can't be read."""
    if data is None or vault.notice_shown(data, vault.POSTURE_NOTICE):
        return []
    out: list[str] = []
    try:
        entry = vault.sudo_entry(data, "localhost", paths.local_user())
    except Exception:  # noqa: BLE001
        entry = None
    if _own_sudo(eff) and entry and entry.get("password"):
        out.append(POSTURE_SUDO)
    keys = [k for k in GLOBAL_REACH_KEYS
            if (mv := eff.policy_modes.get(k)) is not None and "deny" in mv.words]
    if keys:
        out.append(POSTURE_POLICY.format(keys=", ".join(f"{k} = deny" for k in keys)))
    if not out:
        return []
    try:
        with vault.edit() as cur:
            vault.mark_notice(cur, vault.POSTURE_NOTICE)
    except vault.VaultError:
        return []        # said once it can be recorded (never every session)
    return out


# How much of an event's detail the "since your last session" notice shows.
EVENT_DETAIL = 120


def cut_words(text: Any, limit: int) -> str:
    """`text` whole when it fits `limit` characters, else cut at the last
    space that leaves at least half of it (inside a word only when there is
    none) and ended with "…", so a cut never reads as the whole line."""
    text = str(text or "")
    if len(text) <= limit:
        return text
    head = text[:limit - 1]
    sp = head.rfind(" ")
    if sp >= limit // 2:
        head = head[:sp]
    return head.rstrip(" ,;:") + "…"


def ok_how(target: str, names: list[str]) -> str:
    """How the user gives an OK that waits: the gateway's dialog in Claude
    Code, which Claude opens with gate check (PLAN-v4 phase 3: no pop-up on
    the desktop, no terminal command with a code)."""
    return (f"Claude can open the gateway's dialog for it with `gate check {target}`; it "
            "appears in Claude Code (a terminal session or the desktop app; not claude -p, "
            "VS Code, mobile or Remote Control, where it can't be answered).")


def form_messages(form: formmod.Form) -> list[str]:
    out = []
    if form.syntax_error:
        out.append(f"gateway: gateway.toml {form.syntax_error.render()}"
                   + ("; using the last good version" if form.from_last_good else ""))
    for p in form.errors[:8]:
        off = f" ({p.entry} is off until it's fixed)" if p.entry and p.entry in form.disabled else ""
        out.append(f"gateway: gateway.toml {p.render()}{off}")
    if len(form.errors) > 8:
        out.append(f"gateway: ... and {len(form.errors) - 8} more problems (gate status)")
    return out


# hooks.json: the sync SessionStart's timeout (s; a test keeps them equal).
# Claude Code drops the output of a hook that runs longer.
SESSION_TIMEOUT = 20


def session_hook(payload: dict[str, Any]) -> dict[str, Any]:
    """run.py hook-session: session_main, timed from this process's start
    (launch.sh execs Python in the process Claude Code started)."""
    try:
        from . import ancestry
        started = ancestry.started_at(os.getpid())
    except Exception:  # noqa: BLE001 - timing only
        started = None
    return session_main(payload, started=started)


def session_main(payload: dict[str, Any], started: float | None = None) -> dict[str, Any]:
    sid = str(payload.get("session_id") or os.environ.get("CLAUDE_CODE_SESSION_ID") or "")
    msgs: list[str] = []
    if vault.v06_waiting():
        msgs.append(vault.V06_MESSAGE)
    form, eff, data = prepare(msgs, write=True)
    from . import hooks_filechanged
    hooks_filechanged.record_seen(form)    # FileChanged reports against this session's start
    record_session_mode(payload, eff)
    meta = vault.meta(data) if data else {}
    res = envfile.sync(form, eff, meta, os.environ.get("CLAUDE_ENV_FILE"),
                       vault_readable=not (vault.exists() and data is None))
    consent.sync_network_words(eff)        # pre_bash.sh's extra trigger words (WS-3, §3.4)
    for err in res.get("errors", []):
        msgs.append(f"gateway: setup step failed: {err}")
    msgs += form_messages(form)
    msgs += posture_notice(eff, data)
    vault_unreadable = vault.exists() and data is None
    # pending dialogs; the "shown" markers are shared with the prompt and
    # PostToolUse hooks
    from . import hooks_post
    notices = hooks_post.pending_notice(sid or None, include_open=True)
    if eff.pending and not vault_unreadable:
        names = eff.pending_names()
        target = names[0] if len(names) == 1 else "all"
        lines = "; ".join(c.render() for c in eff.pending[:6])
        more = f" (+{len(eff.pending) - 6} more)" if len(eff.pending) > 6 else ""
        msgs.append(f"gateway: waiting for your OK: {lines}{more}. "
                    + ok_how(target, names))
    msgs += notices
    evs = vault.new_events(data) if data else []
    if evs:
        msgs.append("gateway: since your last session: " + "; ".join(
            f"{e.get('at', '')[:16]} {e.get('what')}: {cut_words(e.get('detail', ''), EVENT_DETAIL)}"
            for e in evs[-5:]))
    ctx = context_text(form, eff, meta)
    e2e = testing.get("e2e")
    if e2e:   # the e2e suite's scratch copy (paths.e2e_marker): say so, first
        msgs.insert(0, f"gateway: e2e test mode: this session uses the test vault in {e2e}, "
                       "not ~/.config/gateway")
    if evs:
        try:
            with vault.edit() as cur:
                vault.mark_events_seen(cur)
        except vault.VaultError:
            pass
    # Past Claude Code's limit the hook was cancelled and Claude never got
    # this context (nor, after a compact, the earlier one): with no record,
    # the next prompt's hook gives it.
    if started is None or time.time() - started < SESSION_TIMEOUT - 1:
        record_context(sid, form)
    else:
        with contextlib.suppress(OSError, paths.PathError):
            (paths.session_dir() / f"{_sid(sid)}.json").unlink()
    write_session_record(sid)
    out: dict[str, Any] = {"hookSpecificOutput": {
        "hookEventName": "SessionStart", "additionalContext": ctx,
        "watchPaths": [str(paths.form_path())]}}
    if msgs:
        out["systemMessage"] = "\n".join(msgs)
    return out


def subagent_main(payload: dict[str, Any]) -> dict[str, Any]:
    msgs: list[str] = []
    form, eff, data = prepare(msgs, write=False)
    meta = vault.meta(data) if data else {}
    return {"hookSpecificOutput": {"hookEventName": "SubagentStart",
                                   "additionalContext": context_text(form, eff, meta)}}


def daemon_main(payload: dict[str, Any]) -> None:
    """run.py hook-daemon, an async SessionStart hook (PLAN-v4 phase 2): start
    the gateway daemon if it isn't running and register this session with it
    (the Claude Code process above this hook), so checkpoint finds it
    (CONTRACT-v1) and the vault plane knows the session, also without mods
    and in `claude -p`. Prints nothing; a failure shows in /gate-doctor."""
    try:
        from .daemon import client, lifecycle
        lifecycle.ensure_running()
        sid = payload.get("session_id") if isinstance(payload.get("session_id"), str) else ""
        client.call("POST", "/agent/register",
                    {"session_id": sid or os.environ.get("CLAUDE_CODE_SESSION_ID", "")})
    except Exception:  # noqa: BLE001 - async and best effort: the next start retries
        pass
    record_session_mode(payload)
    return None


def record_session_mode(payload: dict[str, Any], eff: consent.Effective | None = None) -> bool:
    """Lead decision 3 (WS-1): where the SessionStart payload carries
    `permission_mode`, record it in gated (hooks_bash.record_mode: only
    while the effective form makes the mode matter, with the epoch marker),
    so a stand-in's first call has a record. The sync SessionStart tries
    (gated is up on a resume or a clear); the async hook-daemon tries again
    once it has started gated and registered the session. Until there is a
    record the stand-ins use the modeless rule (the strict reading). Never
    fails the hook."""
    pm = payload.get("permission_mode") if isinstance(payload, dict) else None
    if not isinstance(pm, str) or not pm:
        return False
    try:
        from . import hooks_bash
        if eff is None:
            _form, eff = hooks_bash._load_rights()
        return hooks_bash.record_mode(pm, eff)
    except Exception:  # noqa: BLE001 - a record is a guardrail; the modeless rule applies
        return False


def async_main(payload: dict[str, Any]) -> None:
    """The async SessionStart hook when Python runs (launch.sh normally does
    this in sh): clean up old env dirs."""
    envfile.cleanup_envs()
    return None


def main(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("hook_event_name") == "SubagentStart":
        return subagent_main(payload)
    return session_main(payload)


def degraded_output(exc: BaseException) -> dict[str, Any]:
    """When session_main crashed: still give Claude the safe env file."""
    path = os.environ.get("CLAUDE_ENV_FILE")
    if path:
        try:
            envfile.write_env_file(path, envfile.env_text())
        except OSError:
            pass
    return {"systemMessage": f"gateway: session setup failed ({type(exc).__name__}); "
                             "run ~/.config/gateway/gate status in a terminal",
            "hookSpecificOutput": {"hookEventName": "SessionStart",
                                   "additionalContext": INTRO + " (Setup failed this session; "
                                   "`gate status` shows what works.)"}}
