"""`gate check|login|forget|rotate` (SPEC 15, 6; PLAN-v4 phase 3).

check NAME (the eager setup, idempotent):
  1. validate the entry; compute its pending widenings (consent.compute);
  2. hosts: read the host keys (ssh.keyscan_host, through the chosen
     address/jump) when none are pinned, and compare them with the pins;
  3. if anything needs the user (consent, pins, key install, a sudo password,
     a token, a service principal's secret), one broker request "setup" runs
     the whole sequence in the detached dialog helper (popup.run), each step a
     native gateway dialog in Claude Code: one consent dialog listing
     exactly the changes plus the host-key fingerprints (default Cancel);
     consent.approve(NAME, the changes shown); the pins; then the key install
     (choice: use my own SSH login once / type the password once / show me
     the public key -> ssh.install_key, verified with ssh.test_login); the
     sudo password unless passwordless sudo is already configured
     (sudo.probe_nopasswd / ssh.probe_remote_nopasswd; the gateway never
     installs a sudoers rule) and the user didn't choose to be asked each
     time, verified (sudo.verify_local /
     ssh.verify_remote_sudo); an account's token (a GitHub personal access
     token, a Hugging Face token, an API key) or an Azure service principal's
     client secret, verified where the kind allows (GitHub GET /user, Hugging
     Face whoami, an Entra client-credentials token). Browser and device-code
     sign-ins are unavailable (popup.signin_unavailable says what works);
     an existing refresh token keeps working;
  4. one status line. An entry already set up prints its status and exits 0.

A request the user cancelled in this session isn't reopened by `gate check`
until the user writes again (the prompt hook clears the marker).

login NAME   ask for an account's credential again (forces the token step).
forget NAME [sudo|token|key|signin|host-keys]   forget stored secrets (no dialog: it narrows).
rotate HOST  ssh.rotate.
secret NAME  removed (it was a terminal prompt): says where credentials are
             entered now.

Where no native dialog can open (claude -p, the Agent SDK, mods off, mobile,
VS Code, Remote Control), `gate check` asks nothing and says so; nothing is
ever asked in a terminal, a browser or an OS dialog.

Each command returns an exit code and prints its own status line.
"""
from __future__ import annotations

import contextlib
import json
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from . import accounts as acctmod
from . import audit, consent, hooks_session, paths, popup, testing, vault
from . import form as formmod

OK = "✓"
INSTALL_CHOICES = {
    "Use my own SSH login once (recommended)": "my-login",
    "Type the account's password once": "password",
    "Show me the public key (I'll add it myself)": "show",
}
SUDO_STORE = "Store the sudo password"
# PLAN-v4 phase 7: never a sudoers change; the other answer leaves the
# password to the per-call dialog (with "Remember it", or for one call)
SUDO_ASK = "Ask me each time a command needs it"


FORGET_WHATS = ("sudo", "token", "key", "signin", "host-keys")


def _out(s: str) -> None:
    print(s, flush=True)


def _err(s: str) -> None:
    print(s, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------
# Adapters (other groups' modules; tests replace these)
# ---------------------------------------------------------------------------


def _ssh():
    from . import ssh
    return ssh


def _sudo():
    from . import sudo
    return sudo


def sp_token(tenant: str, client_id: str, secret: str) -> tuple[bool, str]:
    """Check an Azure service principal's client secret: an Entra
    client-credentials token for ARM (group 'accounts' owns entra.py)."""
    from . import entra
    try:
        entra.client_credentials(tenant, client_id, secret, entra.SCOPES["arm"])
    except entra.EntraError as e:
        return False, f"Entra didn't accept it ({formmod.strip_unsafe(str(e))[:120]})"
    return True, ""


def catalog_config(host: str) -> dict[str, Any]:
    """The catalog's sign-in settings (tenant, client): asiml's reader, which
    goes through entra.urlopen (no proxies, the build's CA bundle, no
    redirects), never through settings from the caller's environment."""
    from . import asiml
    return asiml.catalog_config(host)


def api_base(kind: str, host: str = "") -> str:
    o = testing.get(f"{kind}_api")
    if o:
        return str(o).rstrip("/")
    if kind == "github":
        h = acctmod._host_only(host or "github.com")
        return "https://api.github.com" if h == "github.com" else (
            f"https://api.{h}" if h.endswith(".ghe.com") else f"https://{h}/api/v3")
    return "https://huggingface.co"


def _urlopen(req: urllib.request.Request, timeout: float) -> Any:
    """entra.urlopen: no proxies, the Python build's own CA bundle (never
    HTTPS_PROXY/ALL_PROXY or SSL_CERT_FILE/SSL_CERT_DIR: `gate` runs with the
    environment of Claude's Bash, which Claude's commands control) and no
    automatic redirects (a 3xx comes back as an HTTPError)."""
    from . import entra
    return entra.urlopen(req, timeout=timeout)


def http_json(url: str, token: str) -> tuple[int, Any, dict[str, str]]:
    """GET url with the token the user just typed (GitHub /user and /orgs,
    Hugging Face whoami); (status, JSON body or None, headers)."""
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}",
                                               "Accept": "application/json",
                                               "User-Agent": "gateway"})
    try:
        with _urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode() or "null"), dict(r.headers.items())
    except urllib.error.HTTPError as e:
        return e.code, None, dict(e.headers.items()) if e.headers else {}
    except (urllib.error.URLError, OSError, ValueError):
        return 0, None, {}


# ---------------------------------------------------------------------------
# Loading and status
# ---------------------------------------------------------------------------


def _load() -> tuple[formmod.Form, consent.Effective, dict[str, Any]]:
    msgs: list[str] = []
    form, eff, data = hooks_session.prepare(msgs, write=False)
    for m in msgs:
        _err(m)
    if data is None:
        if vault.exists():
            raise SystemExit("gateway: the vault can't be read, so nothing was changed; tell the "
                             "user (gate status shows the reason; the key in "
                             "~/.config/gateway/private must match the vault)")
        data = vault.empty()
    return form, eff, data


def _reload() -> tuple[formmod.Form, consent.Effective, dict[str, Any]]:
    formmod.clear_cache()
    data = vault.load() if vault.exists() else vault.empty()
    form = formmod.load(last_good=data.get("form_last_good"), use_cache=False)
    return form, consent.compute(form, data), data


def _mark(r: Any) -> str:
    return OK if r is True else ("ask" if r == "ask" else "off")


def _nopasswd_local(user: str) -> bool:
    try:
        return bool(_sudo().probe_nopasswd(user))
    except NotImplementedError:
        return bool(hooks_session._nopasswd_cached(user))
    except Exception:  # noqa: BLE001
        return False


def _nopasswd_remote(name: str, user: str) -> bool:
    try:
        return bool(_ssh().probe_remote_nopasswd(name, user))
    except Exception:  # noqa: BLE001 - incl. NotImplementedError
        return False


def _remote_nopasswd_known(name: str, user: str, data: dict[str, Any]) -> bool:
    """The last remote probe found NOPASSWD (vault probe record)."""
    rec = ((data.get("hosts") or {}).get(name) or {}).get("probe") or {}
    return bool((rec.get("nopasswd") or {}).get(user))


def status_line(name: str, form: formmod.Form, eff: consent.Effective, data: dict[str, Any]) -> str:
    meta = vault.meta(data)
    if name in form.hosts:
        e = eff.hosts[name]
        h = form.hosts[name]
        if e.is_local:
            user = paths.local_user()
            st = meta["localhost"]["sudo"].get(user)
            extra = ""
            if e.sudo is not False:
                if hooks_session._nopasswd_cached(user):
                    extra = " (no password needed)"
                elif st:
                    extra = " (password rejected)" if st.get("stale") else " (password saved)"
                elif vault.sudo_choice(data, "localhost", user) == "ask":
                    extra = " (password asked each time)"
            return f"gateway: localhost ready: sudo {_mark(e.sudo)}{extra}"
        if h.ssh is not False and e.ssh is False and not e.new:
            # never "ready" with ssh off because of a widening or a jump host
            jump = jump_problem(name, form, eff, data)
            if jump:
                return jump.replace(" goes through", " isn't ready: it goes through", 1)
            return (f"gateway: {name} isn't ready: ssh waits for the user's OK; run gate check "
                    f"{name} while the user is here")
        hm = meta["hosts"].get(name) or {}
        where = e.addresses[0].render() if e.addresses else (h.address.render() if h.address else "?")
        if e.via:
            where += f" via {e.via}"
        key = "key installed" if hm.get("installed") else ("key saved" if hm.get("keys") else "no key yet")
        s = hm.get("sudo", {}).get(h.user())
        sx = ""
        if e.sudo is not False and s:
            sx = " (password rejected)" if s.get("stale") else " (password saved)"
        elif e.sudo is not False and _remote_nopasswd_known(name, h.user(), data):
            sx = " (no password needed)"
        elif e.sudo is not False and vault.sudo_choice(data, name, h.user()) == "ask":
            sx = " (password asked each time)"
        pend = "; a change still waits for the user's OK" if e.pending else ""
        return (f"gateway: {name} ready: ssh {_mark(e.ssh)} ({where}, {key}), "
                f"sudo {_mark(e.sudo)}{sx}{pend}")
    if name in form.accounts:
        e = eff.accounts[name]
        a = form.accounts[name]
        am = meta["accounts"].get(name) or {}
        if am.get("stale"):
            st = "token rejected"
        elif am.get("entra"):
            st = "signed in" + (f" as {a.login}" if a.login else "")
        elif am.get("token"):
            st = ("signed in" if am.get("token_source") == "gh-oauth" else "token saved") + (
                f" as {a.login}" if a.login and a.kind in ("github", "huggingface") else "")
            if a.kind == "api-key":
                st = "key saved"
        elif am.get("ssh_key"):
            st = "key saved"
        else:
            st = "not signed in"
        dests = ", ".join(e.destinations) or "nowhere yet"
        pend = "; a change still waits for the user's OK" if e.pending else ""
        return f"gateway: {name} ready: {st}; sends to {dests}{pend}"
    if name == "settings":
        sh = eff.shell
        imports = ", ".join(sh.import_path + sh.import_env) or "none"
        return (f"gateway: settings: others = \"{eff.others}\"; managed shell \"{sh.managed}\"; "
                f"imports: {imports}")
    return f"gateway: {name}: nothing to do"


# ---------------------------------------------------------------------------
# The plan (requester side, no pop-up)
# ---------------------------------------------------------------------------


@dataclass
class Plan:
    name: str
    section: str                       # hosts | accounts | settings
    changes: list[consent.Change] = field(default_factory=list)
    scanned: list[str] = field(default_factory=list)
    pinned: list[str] = field(default_factory=list)
    pin: bool = False                  # store `scanned` as the pins after the OK
    mismatch: bool = False             # pinned keys (or the forgotten ones) differ from the scan
    previous: list[str] = field(default_factory=list)   # forgotten pins (gate forget), when none are pinned
    needs_key: bool = False
    needs_sudo: bool = False
    needs_signin: bool = False
    force_signin: bool = False
    notes: list[str] = field(default_factory=list)
    error: str | None = None           # stop before any pop-up (exit 1) with this message

    def anything(self) -> bool:
        return bool(self.changes or self.pin or self.mismatch or self.needs_key or self.needs_sudo
                    or self.needs_signin)

    def digest(self) -> str:
        return popup._digest([c.render() for c in self.changes] + self.scanned
                             + [str(self.needs_key), str(self.needs_sudo), str(self.needs_signin)])


def _keyscan(name: str, h: formmod.Host) -> tuple[list[str], str | None]:
    """(host keys, why none were read): the ssh module's own message (it
    names a jump host that isn't set up, an address that didn't answer)
    rather than a guess (round 3)."""
    why: str | None = None
    try:
        keys = _ssh().keyscan_host(name)
    except NotImplementedError:
        a = h.address
        keys = vault.keyscan(a.host, a.port) if a is not None and not h.via else []
    except Exception as e:  # noqa: BLE001
        keys = []
        msg = getattr(e, "message", None)
        if isinstance(msg, str) and msg.startswith("gateway: "):
            why = formmod.strip_unsafe(msg.removeprefix("gateway: "))[:300]
    out = [k for k in (vault.norm_host_key(x) for x in keys or []) if k]
    if not out and why is None:
        why = f"couldn't read {name}'s host key (is it reachable from here?)"
    return out, why


def jump_problem(name: str, form: formmod.Form, eff: consent.Effective,
                 data: dict[str, Any]) -> str | None:
    """A host behind a jump host that isn't approved, pinned and holding an
    installed key can't be set up yet (round 3: gate check pinned nothing,
    skipped the key and printed "ready"). The message, or None."""
    h = form.hosts.get(name)
    if h is None or h.is_local or not h.via or h.ssh is False:
        return None
    j = h.via
    je = eff.hosts.get(j)
    jrec = (data.get("hosts") or {}).get(j) or {}
    if (je is not None and not je.new and je.ssh is not False and jrec.get("host_keys")
            and vault.live_keys(jrec) and jrec.get("installed")):
        return None
    return (f"gateway: {name} goes through {j}, which isn't set up yet; run gate check {j} first, "
            f"then gate check {name}")


def _relogin(name: str) -> tuple[bool, bool]:
    """(key works, refused): a test login with Claude's key, so a key removed
    from the host is noticed (round 3: gate check said "ready" while the
    stand-in said the host refused the key)."""
    ssh = _ssh()
    try:
        ok, _msg = ssh.test_login(name)
    except Exception:  # noqa: BLE001 - incl. NotImplementedError: nothing learned
        return True, False
    if ok:
        return True, False
    try:
        from . import ssh_conf
        refused = ssh_conf.recent_authfail(name)
    except Exception:  # noqa: BLE001
        refused = False
    return False, refused


def _account_has_credential(a: formmod.Account, rec: dict[str, Any]) -> bool:
    tok = rec.get("token") or {}
    if a.kind in ("github", "huggingface", "registry", "api-key"):
        return bool(tok.get("value")) and not tok.get("stale")
    if a.kind in ("azure", "ml-catalog"):
        ent = rec.get("entra") or {}
        if not ent.get("refresh_token") and not (a.kind == "azure" and ent.get("client_secret")):
            return False
        if a.kind == "ml-catalog" and not (rec.get("bound") or {}).get("scope"):
            return False
        return True
    if a.kind == "pijul":
        return bool((rec.get("ssh_key") or {}).get("private"))
    return True


def _changes_reach(changes: list[consent.Change]) -> bool:
    """A pending change that makes the gateway reach the host somewhere new
    (a new host, a new address, a new jump host): its key must be read first."""
    return any(c.what.startswith(("new host", "new address", "address ", "via "))
               for c in changes)


def plan_for(name: str, form: formmod.Form, eff: consent.Effective, data: dict[str, Any],
             *, force_signin: bool = False) -> Plan:
    if name == "settings":
        return Plan(name, "settings", changes=eff.pending_for("settings"))
    if name in form.hosts:
        p = Plan(name, "hosts", changes=eff.pending_for(name))
        h = form.hosts[name]
        e = eff.hosts[name]
        rec = (data.get("hosts") or {}).get(name) or {}
        if not h.is_local:
            p.error = jump_problem(name, form, eff, data)
            if p.error:
                return p
            p.pinned = list(rec.get("host_keys") or [])
            p.previous = [] if p.pinned else list(rec.get("host_keys_previous") or [])
            wants_ssh = h.ssh is not False
            if wants_ssh:
                # Every gate check reads the host key, also for a host that is
                # set up (round 3): a changed key goes to the host-key pop-up
                # here (and `gate secret NAME` answers a pending one this way).
                p.scanned, why = _keyscan(name, h)
                if not p.scanned:
                    why = why or f"couldn't read {name}'s host key"
                    if not p.pinned or _changes_reach(p.changes):
                        # Review round 4: a first pin or a new address with no
                        # key read: stop before any pop-up (the user would OK a
                        # host nobody reached, then be asked again for the pin).
                        p.error = (f"gateway: {why}; nothing was asked. Check that {name} is "
                                   "on and that its address in gateway.toml is right, then run "
                                   f"gate check {name} again")
                        return p
                    if p.changes:
                        p.notes.append(why)
                elif not p.pinned:
                    p.pin = True
                    # forgotten with `gate forget NAME host-keys`: a different key
                    # is still a host-key change, not a first pin
                    p.mismatch = bool(p.previous) and not set(p.scanned) & set(p.previous)
                elif not set(p.scanned) & set(p.pinned):
                    p.mismatch = True
            if wants_ssh:
                have = bool(vault.live_keys(rec))
                p.needs_key = not have or not rec.get("installed") or p.mismatch
                if (have and not p.mismatch and p.scanned and not e.new and e.ssh is True
                        and not p.changes):
                    ok, refused = _relogin(name)
                    if ok:
                        p.needs_key = False     # (test_login recorded `installed`)
                    elif refused:
                        p.needs_key = True
                        with contextlib.suppress(Exception):
                            with vault.edit() as d:
                                vault.host_record(d, name).pop("installed", None)
                        p.notes.append(f"{name} refused Claude's key; it will be installed again")
                    elif not ok:
                        p.notes.append(f"couldn't log in to {name} to check Claude's key")
        if h.sudo is not False:
            user = paths.local_user() if h.is_local else h.user()
            st = vault.sudo_entry(data, name, user)
            have = bool(st and st.get("password") and not st.get("stale"))
            # PLAN-v4 phase 7: a stored password is used as it is (there is no
            # passwordless rule to offer instead); "ask" leaves it to the
            # per-call dialog; otherwise the user chooses once
            if not have and vault.sudo_choice(data, name, user) != "ask":
                if h.is_local:
                    p.needs_sudo = not _nopasswd_local(user)
                elif h.ssh is False:
                    p.needs_sudo = False   # remote sudo runs over ssh: nothing to probe or set up
                elif not p.needs_key and not e.new:
                    p.needs_sudo = not _nopasswd_remote(name, user)
                else:
                    p.needs_sudo = True    # decided after the key works
        return p
    a = form.accounts[name]
    p = Plan(name, "accounts", changes=eff.pending_for(name), force_signin=force_signin)
    rec = (data.get("accounts") or {}).get(name) or {}
    # approving a new (or re-added, or re-kinded) account drops what was
    # stored under that name before (consent.drops_credential): ask anew
    p.needs_signin = (force_signin or not _account_has_credential(a, rec)
                      or bool(p.changes and consent.drops_credential(data, a)))
    # A sign-in only a browser or a device code could do: say so before any
    # dialog (nothing to approve that couldn't be used), with what works.
    if p.needs_signin and (a.kind == "ml-catalog" or (
            a.kind == "azure" and (not a.client_id or a.client_id == formmod.AZURE_CLI_CLIENT_ID))):
        p.error = popup.signin_unavailable(a.kind, name)
    return p


# ---------------------------------------------------------------------------
# The job (runs where the dialogs run: the detached helper)
# ---------------------------------------------------------------------------


class _Stop(Exception):
    def __init__(self, outcome: str, msg: str):
        super().__init__(msg)
        self.outcome = outcome
        self.msg = msg


def known_by_user(keys: list[str]) -> bool | None:
    """Does the user's own ~/.ssh/known_hosts hold one of these keys (any host
    spelling, hashed or not)? None if there is no such file."""
    kh = paths.user_home() / ".ssh" / "known_hosts"
    try:
        text = kh.read_text(errors="replace")
    except OSError:
        return None
    blobs = {k.split()[1] for k in keys if len(k.split()) >= 2}
    for line in text.splitlines():
        parts = line.split()
        if any(b in parts for b in blobs):
            return True
    return False


def _consent_step(p: Plan) -> None:
    changes = list(p.changes)
    extra: list[str] = []
    old = p.pinned or p.previous
    if p.mismatch and not changes:
        form = formmod.load()
        h = form.hosts.get(p.name)
        oc = popup.hostkey(p.name, vault.host_key_fingerprints(old),
                           vault.host_key_fingerprints(p.scanned),
                           address=h.address.render() if h is not None and h.address else None,
                           known=known_by_user(p.scanned), lazy=False)
        if oc != popup.Outcome.OK:
            raise _Stop(oc, popup.message(oc, p.name, "host key"))
    elif p.scanned and (p.pin or p.mismatch):
        fps = ", ".join(vault.host_key_fingerprints(p.scanned))
        extra.append(f"Host key of {p.name}: {fps}")
        if p.mismatch:
            extra.append(("This differs from the pinned key: " if p.pinned else
                          "This differs from the key pinned before (gate forget removed it): ")
                         + ", ".join(vault.host_key_fingerprints(old)))
            kb = known_by_user(p.scanned)
            if kb is not None:
                extra.append("Your own ~/.ssh/known_hosts " + ("knows" if kb else "doesn't know")
                             + " the new key.")
    for _attempt in range(popup.MAX_TRIES):
        if not changes and not extra:
            break
        oc = popup.consent(p.name, changes, extra_lines=extra)
        if oc != popup.Outcome.OK:
            raise _Stop(oc, popup.message(oc, p.name, "consent"))
        form, eff, _data = _reload()
        try:
            if changes:
                consent.approve(p.name, changes, form=form)
            break
        except consent.ConsentChanged:
            changes = eff.pending_for(p.name)
            continue
    else:
        raise _Stop(popup.Outcome.FAILED, f"gateway: {p.name} kept changing while the dialog was "
                                           "open; nothing was approved")
    if p.scanned and (p.pin or p.mismatch):
        with vault.edit() as data:
            rec = vault.host_record(data, p.name)
            rec["host_keys"] = list(p.scanned)
            rec["pinned_at"] = vault.now()
            rec.pop("host_keys_previous", None)
            vault.add_event(data, "hostkey", f"{p.name}: pinned "
                            + ", ".join(vault.host_key_fingerprints(p.scanned)))
        audit.log("pin", entry=p.name, host_keys=vault.host_key_fingerprints(p.scanned))


def _ensure_key(name: str) -> None:
    with vault.edit() as data:
        rec = vault.host_record(data, name)
        if not vault.live_keys(rec):
            priv, pub = vault.generate_ssh_key(vault.key_comment(name, data))
            rec["keys"].append(vault.key_record(priv, pub))


def _key_step(name: str, form: formmod.Form) -> list[str]:
    notes: list[str] = []
    ssh = _ssh()
    _ensure_key(name)
    try:
        ok, msg = ssh.test_login(name)
    except NotImplementedError:
        raise _Stop(popup.Outcome.FAILED, "gateway: the ssh part of the gateway isn't available in "
                                           "this build yet; the host was approved, the key isn't installed")
    if not ok:
        h = form.hosts[name]
        q = (f"Claude's key for {name} isn't installed on {h.address.render() if h.address else name} "
             "yet. How should the gateway install it?")
        oc, picked = popup.choice(name, q, list(INSTALL_CHOICES), what="install method")
        if oc != popup.Outcome.OK or picked is None:
            raise _Stop(oc, popup.message(oc, name, "install method"))
        method = INSTALL_CHOICES[picked]
        st = ssh.install_key(name, method)
        if method == "show":
            pub = ""
            data = vault.load()
            keys = vault.live_keys(vault.host_record(data, name))
            if keys:
                pub = keys[-1].get("public", "")
            user = h.user()
            oc, _ = popup.text(name, f"Add this line to ~/.ssh/authorized_keys for {user} on "
                               f"{h.address.host if h.address else name}, then press OK.",
                               default=pub, what="public key")
            if oc != popup.Outcome.OK:
                raise _Stop(oc, popup.message(oc, name, "public key"))
        elif isinstance(st, str) and st:
            notes.append(formmod.strip_unsafe(st)[:200])
        ok, msg = ssh.test_login(name)
        if not ok:
            raise _Stop(popup.Outcome.FAILED, f"gateway: {name} still refuses Claude's key "
                        f"({formmod.strip_unsafe(str(msg))[:120]}); run gate check {name} to try again")
    with vault.edit() as data:
        vault.host_record(data, name)["installed"] = vault.now()
    return notes


def _sudo_store(name: str, user: str) -> Callable[[str], None]:
    def store(pw: str) -> None:
        with vault.edit() as data:
            vault.set_sudo(data, name, user, pw)
            vault.set_sudo_choice(data, name, user, "password")
        audit.log("secret_saved", entry=name, what="sudo password", user=user)
    return store


def _sudo_verify(name: str, user: str, local: bool) -> Callable[[str], tuple[bool, str]]:
    def verify(pw: str) -> tuple[bool, str]:
        try:
            if local:
                return _sudo().verify_local(pw)
            return _ssh().verify_remote_sudo(name, user, pw)
        except NotImplementedError:
            return False, "the gateway can't check sudo passwords in this build yet"
    return verify


def sudo_prompt(name: str, form: formmod.Form, data: dict[str, Any], user: str) -> str:
    h = form.hosts.get(name)
    target = f"{user}@localhost" if name == "localhost" else (
        f"{user}@{h.address.hostport()}" if h is not None and h.address else user)
    fps = vault.host_key_fingerprints(((data.get("hosts") or {}).get(name) or {}).get("host_keys") or [])
    return popup.secret_prompt("sudo password", name, target=target,
                               fingerprint=fps[0] if fps else None)


def sudo_question(name: str, user: str, local: bool, have: bool) -> str:
    """The fixed text of the sudo choice pop-up. The gateway never changes
    the system's sudo rules (no passwordless sudoers rule): passwordless sudo
    is used only where it is already configured."""
    where = "this machine" if local else name
    q = (f"sudo on {where} asks {user}'s password. Store it now (encrypted in the gateway's "
         "vault; Claude's own sudo commands get it through a one-time helper), or leave it to "
         "the gateway's dialog each time a command needs sudo (its Remember it box keeps it then, "
         "unticked it is used once).")
    if not local:
        q += (f" A password is placed briefly on {name} for each sudo command, where other "
              "commands Claude runs there could read it.")
    return q


def sudo_check(name: str, local: bool) -> dict[str, Any]:
    """What gated rechecks before it hands a sudo password typed into the
    gateway's dialog over: the host still in the form, with sudo (and, for a
    remote host, ssh: remote sudo runs over it) not switched off."""
    return {"section": "hosts", "entry": name, "right": "sudo" if local else ["ssh", "sudo"]}


def _sudo_step(name: str) -> list[str]:
    form, eff, data = _reload()
    h = form.hosts[name]
    if eff.hosts[name].sudo is False:
        return []
    if not h.is_local and eff.hosts[name].ssh is False:
        return []          # remote sudo runs over ssh, which is off for this host
    local = h.is_local
    user = paths.local_user() if local else h.user()
    st = vault.sudo_entry(data, name, user)
    have = bool(st and st.get("password") and not st.get("stale"))
    choice = vault.sudo_choice(data, name, user)
    if have:
        if choice is None:
            with vault.edit() as cur:
                vault.set_sudo_choice(cur, name, user, "password")
        return []
    if choice == "ask":
        return []
    # passwordless sudo only as the system already has it (never installed here)
    if (local and _nopasswd_local(user)) or (not local and _nopasswd_remote(name, user)):
        return []
    oc, picked = popup.choice(name, sudo_question(name, user, local, have), [SUDO_STORE, SUDO_ASK],
                              what="sudo method")
    if oc != popup.Outcome.OK or picked is None:
        raise _Stop(oc, popup.message(oc, name, "sudo method"))
    if picked == SUDO_ASK:
        with vault.edit() as cur:
            vault.set_sudo_choice(cur, name, user, "ask")
        return []
    oc, _ = popup.secret(name, "sudo password", sudo_prompt(name, form, data, user),
                         verify=_sudo_verify(name, user, local), store=_sudo_store(name, user),
                         lazy=False, detail={"user": user}, check=sudo_check(name, local))
    if oc != popup.Outcome.OK:
        raise _Stop(oc, popup.message(oc, name, "sudo password"))
    return []


def _store_token(name: str, kind: str, value: str, source: str, login: str | None = None) -> None:
    with vault.edit() as data:
        rec = vault.account_record(data, name, kind)
        rec["token"] = {"value": value, "source": source, "updated": vault.now(), "stale": False}
        rec.pop("status", None)          # a new value: its adapter state starts over
        if login:
            rec["login"] = login
    vault.cache_clear(name) if paths.cache_path().exists() else None
    audit.log("secret_saved", entry=name, what="token", source=source)


def _fill_login(name: str, a: formmod.Account, login: str | None) -> None:
    if login and not a.login and formmod.LOGIN_RE.fullmatch(login):
        try:
            formmod.set_key(f"accounts.{name}", "login", login)
        except formmod.FormWriteError:
            pass


def github_verify(a: formmod.Account, found: dict[str, str]) -> Callable[[str], tuple[bool, str]]:
    base = api_base("github", a.host)

    def verify(token: str) -> tuple[bool, str]:
        code, body, _h = http_json(f"{base}/user", token)
        if code != 200 or not isinstance(body, dict):
            return False, f"GitHub didn't accept it (HTTP {code or 'error'})"
        login = str(body.get("login") or "")
        if a.login and login.lower() != a.login.lower():
            shown = login if formmod.LOGIN_RE.fullmatch(login) else "another account"
            return False, (f"it belongs to {shown}, not {a.login}; use a token of {a.login} "
                           "(a private browser window helps)")
        found["login"] = login
        return True, ""
    return verify


def sso_notes(a: formmod.Account, token: str) -> list[str]:
    notes = []
    base = api_base("github", a.host)
    for owner in a.owners:
        if a.login and owner.lower() == a.login.lower():
            continue
        code, _b, hdrs = http_json(f"{base}/orgs/{owner}", token)
        sso = {k.lower(): v for k, v in hdrs.items()}.get("x-github-sso", "")
        if code == 403 and sso:
            notes.append(f"{owner} uses SSO: authorize the token for {owner} on GitHub "
                         "(Settings > Applications), then it works there too")
    return notes


def sp_cert_token(tenant: str, client_id: str, pem: str) -> tuple[bool, str]:
    """Check an Azure service principal's certificate (PLAN-v4 phase 7): a
    client-credentials token for ARM with a client assertion signed by its
    private key."""
    from . import adapters, entra
    try:
        adapters.cert_parts(pem)
    except ValueError as e:
        return False, str(e)
    try:
        entra.client_certificate(tenant, client_id, pem, entra.SCOPES["arm"])
    except entra.EntraError as e:
        return False, f"Entra didn't accept it ({formmod.strip_unsafe(str(e))[:120]})"
    return True, ""


SP_SECRET = "A client secret"
SP_CERT = "A certificate (paste its PEM: the certificate and its private key)"


def hf_verify(a: formmod.Account, found: dict[str, str]) -> Callable[[str], tuple[bool, str]]:
    def verify(token: str) -> tuple[bool, str]:
        code, body, _h = http_json(f"{api_base('hf')}/api/whoami-v2", token)
        if code != 200 or not isinstance(body, dict):
            return False, f"Hugging Face didn't accept it (HTTP {code or 'error'})"
        login = str(body.get("name") or "")
        if a.login and login.lower() != a.login.lower():
            return False, f"it belongs to another account, not {a.login}"
        found["login"] = login
        return True, ""
    return verify


def _token_prompt(a: formmod.Account, what: str) -> str:
    where = ", ".join(a.destinations()[:3])
    return popup.secret_prompt(what, a.name, target=None,
                               note=f"It will be sent only to {where}." if where else None)


def _sp_store(name: str, kind: str, tenant: str, client_id: str,
              cert: bool = False) -> Callable[[str], None]:
    def store(secret: str) -> None:
        with vault.edit() as data:
            rec = vault.account_record(data, name, kind)
            field = "client_certificate" if cert else "client_secret"
            rec["entra"] = {field: secret, "client_id": client_id, "tenant_id": tenant,
                            "refreshed": vault.now(), "kind": "service-principal"}
            rec.pop("status", None)
            vault.add_event(data, "bind", f"{name}: service principal "
                                          f"{'certificate' if cert else 'secret'} stored")
        vault.cache_clear(name) if paths.cache_path().exists() else None
        audit.log("secret_saved", entry=name, what="client certificate" if cert else "client secret",
                  source="dialog")
    return store


def _account_check(a: formmod.Account) -> dict[str, Any]:
    """What the daemon rechecks before handing over the value: the account is
    still in the form, with the same kind."""
    return {"section": "accounts", "entry": a.name, "kind": a.kind}


def _signin_step(name: str) -> list[str]:
    form, eff, data = _reload()
    a = form.accounts[name]
    notes: list[str] = []
    found: dict[str, str] = {}
    if a.kind == "github":
        oc, tok = popup.secret(name, "token", _token_prompt(a, "github personal access token"),
                               verify=github_verify(a, found), lazy=False,
                               check=_account_check(a))
        if oc != popup.Outcome.OK or not tok:
            raise _Stop(oc, popup.message(oc, name, "token"))
        _store_token(name, "github", tok, "pasted", found.get("login"))
        notes += sso_notes(a, tok)
        _fill_login(name, a, found.get("login"))
    elif a.kind == "huggingface":
        oc, tok = popup.secret(name, "token", _token_prompt(a, "hugging face token"),
                               verify=hf_verify(a, found), lazy=False, check=_account_check(a))
        if oc != popup.Outcome.OK or not tok:
            raise _Stop(oc, popup.message(oc, name, "token"))
        _store_token(name, "huggingface", tok, "pasted", found.get("login"))
        _fill_login(name, a, found.get("login"))
    elif a.kind in ("registry", "api-key"):
        what = "api key" if a.kind == "api-key" else "registry token"
        oc, tok = popup.secret(name, "api key" if a.kind == "api-key" else "token",
                               _token_prompt(a, what), lazy=False, check=_account_check(a))
        if oc != popup.Outcome.OK or not tok:
            raise _Stop(oc, popup.message(oc, name, "token"))
        _store_token(name, a.kind, tok, "pasted")
    elif a.kind == "azure":
        # A service principal (the account's own app registration: tenant and
        # client_id in gateway.toml) and its client secret. Browser and
        # device-code sign-ins are unavailable (brief section 11).
        if not a.tenant or not a.client_id or a.client_id == formmod.AZURE_CLI_CLIENT_ID:
            raise _Stop(popup.Outcome.FAILED, popup.signin_unavailable("azure", name))
        tenant, client = a.tenant, a.client_id
        # PLAN-v4 phase 7: a client secret or a certificate (both the
        # service principal's own credentials; a certificate's private key
        # signs each token request and never leaves the gateway)
        oc, method = popup.choice(name, f"How does the service principal {client} of {name} "
                                  "prove itself to Entra?", [SP_SECRET, SP_CERT],
                                  what="credential method")
        if oc != popup.Outcome.OK or method is None:
            raise _Stop(oc, popup.message(oc, name, "credential method"))
        cert = method == SP_CERT

        def verify(secret: str) -> tuple[bool, str]:
            return sp_cert_token(tenant, client, secret) if cert else sp_token(tenant, client, secret)
        what = "client certificate" if cert else "client secret"
        prompt = popup.secret_prompt(
            what, name, target=None,
            note=(f"The {what} of the service principal {client} in tenant {tenant}"
                  + (" (copy its PEM, the certificate and private key, then press Paste from "
                     "clipboard; the key signs token requests here and is never sent)" if cert
                     else "") + ". Only Entra (login.microsoftonline.com) gets token requests."))
        oc, _sec = popup.secret(name, what, prompt, verify=verify,
                                store=_sp_store(name, "azure", tenant, client, cert=cert),
                                lazy=False, check=_account_check(a), pem=cert)
        if oc != popup.Outcome.OK:
            raise _Stop(oc, popup.message(oc, name, what))
    elif a.kind == "ml-catalog":
        raise _Stop(popup.Outcome.FAILED, popup.signin_unavailable("ml-catalog", name))
    elif a.kind == "pijul":
        with vault.edit() as data:
            rec = vault.account_record(data, name, "pijul")
            if not (rec.get("ssh_key") or {}).get("private"):
                priv, pub = vault.generate_ssh_key(vault.key_comment(name, data))
                rec["ssh_key"] = {"private": priv, "public": pub, "fingerprint": vault.fingerprint_of(pub)}
            pub = rec["ssh_key"]["public"]
        oc, _ = popup.text(name, f"Add this public key to your account on {a.host or 'nest.pijul.com'} "
                           "(profile > SSH keys), then press OK.", default=pub, what="public key")
        if oc != popup.Outcome.OK:
            raise _Stop(oc, popup.message(oc, name, "public key"))
    return notes


def with_notes(line: str, notes: list[str]) -> str:
    """The status line, then what the setup did after it (review round 4:
    the notes went inside the status's own parentheses, each with its own
    "gateway: " prefix)."""
    bits: list[str] = []
    for n in notes:
        n = n.strip().removeprefix("gateway: ").strip().rstrip(".")
        if n and n not in bits:
            bits.append(n)
    if not bits:
        return line
    return line.rstrip(".") + "; " + "; ".join(bits)    # names keep their case


def _job(p: Plan) -> tuple[str, str]:
    notes: list[str] = []
    try:
        if p.changes or p.pin or p.mismatch:
            _consent_step(p)
        form, eff, data = _reload()
        if p.section == "hosts":
            h = form.hosts[p.name]
            if not h.is_local and p.needs_key and eff.hosts[p.name].ssh is not False:
                pins = ((data.get("hosts") or {}).get(p.name) or {}).get("host_keys")
                if not pins:
                    raise _Stop(popup.Outcome.FAILED,
                                f"gateway: {p.name}'s host key couldn't be read (is it reachable "
                                f"from here?), so Claude's key wasn't installed; run gate check "
                                f"{p.name} again when it is")
                notes += _key_step(p.name, form)
            if h.sudo is not False and (p.needs_sudo or p.needs_key):
                notes += _sudo_step(p.name)
        elif p.section == "accounts":
            if p.needs_signin:
                notes += _signin_step(p.name)
        form, eff, data = _reload()
        return popup.Outcome.OK, with_notes(status_line(p.name, form, eff, data), notes)
    except _Stop as s:
        return s.outcome, s.msg


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


SETTINGS_CLASH = ("gateway: the name settings is reserved for the [settings] table, so the "
                  "gateway can't set up an entry called settings; rename [{sect}.settings] in "
                  "gateway.toml (only if the user agrees), then run gate check NEWNAME")


def settings_clash(form: formmod.Form) -> str | None:
    """A host or account named `settings` collides with the gateway-settings
    pseudo-entry (consent, pop-ups, gate check): the message, or None."""
    for sect, table in (("hosts", form.hosts), ("accounts", form.accounts)):
        # form.py reserves the name (the entry is off), so look at both
        if "settings" in table or form.is_disabled("settings", sect):
            return SETTINGS_CLASH.format(sect=sect)
    return None


def _resolve(name: str, form: formmod.Form, data: dict[str, Any]) -> str | None:
    if name == "settings":
        clash = settings_clash(form)
        if clash:
            _err(clash)
            return None
        return name
    real = acctmod.resolve_name(name, data.get("aliases") or {}, form)
    if not formmod.safe(real) or not formmod.NAME_RE.fullmatch(real):
        _err("gateway: that isn't a valid entry name (see gate status)")
        return None
    if real not in form.hosts and real not in form.accounts:
        if form.is_disabled(real, "hosts") or form.is_disabled(real, "accounts"):
            _err(f"gateway: {real} is off because of a mistake in gateway.toml:")
            for pr in form.problems_for(real)[:5]:
                _err(f"  {pr.render()}")
            _err("Fix the entry, then run gate check again.")
        elif formmod.syntax_note(form):
            _err(f"gateway: {formmod.syntax_note(form)}, then run gate check {real} (don't add "
                 f"{real} again: it may be in the part that can't be read)")
        else:
            _err(f"gateway: {real} isn't in gateway.toml; add it there first (only when the user "
                 f"asks), then run gate check {real}")
        return None
    return real


def check_one(name: str, *, force_signin: bool = False) -> int:
    form, eff, data = _load()
    real = _resolve(name, form, data)
    if real is None:
        if name == "settings" or not (form.is_disabled(name, "hosts")
                                      or form.is_disabled(name, "accounts")):
            return 2
        return 1
    if force_signin and real not in form.accounts:
        _err(f"gateway: {real} isn't an account; gate login is for accounts")
        return 2
    p = plan_for(real, form, eff, data, force_signin=force_signin)
    if p.error:
        _err(p.error)
        audit.refusal("gate", real, p.error)
        return 1
    for n in p.notes:
        _err(f"gateway: {n}")
    if not p.anything():
        _out(status_line(real, form, eff, data))
        return 0
    # Where no native dialog can open (claude -p, mods off, mobile, VS Code),
    # popup.run asks nothing and prints why; nothing is ever asked in a
    # terminal, an OS dialog or a browser.
    key = popup._key(real, "setup")
    if popup.was_cancelled(key, p.digest()):
        _err(f"gateway: the user cancelled the gateway dialog for {real} in this session; ask "
             f"them before running gate check {real} again")
        return 1
    try:
        outcome, line = popup.run(real, "setup", lambda: _job(p), kind="setup",
                                  digest=p.digest(), lazy=False,
                                  notice=f"gateway: waiting for the user in the gateway dialog "
                                         f"for {real} in Claude Code")
    except popup.StillOpen:
        return popup.EX_TEMPFAIL
    if outcome == popup.Outcome.OK:
        _out(line or status_line(real, *_reload()))
        return 0
    if outcome == popup.Outcome.UNAVAILABLE:
        return 1      # popup printed why no dialog could open
    if isinstance(line, str) and line:
        _err(line)
    else:
        _err(popup.message(outcome, real, "setup"))
    return 1


# Claude Code kills a Bash command after 2 minutes by default. gate check
# keeps inside that: every pop-up wait ends BUDGET seconds after the command
# started (so the exit-75 "tell the user once" line is printed), and gate
# check all starts no new entry after ALL_BUDGET seconds (review round 4).
BUDGET = 100.0
ALL_BUDGET = 60.0


def _budget(seconds: float, key: str = "gate_check_budget") -> float:
    return float(testing.get(key, seconds))


def check(name: str) -> int:
    """Eager setup of one entry or 'all' (SPEC 15)."""
    start = time.time()
    popup.set_deadline(start + _budget(BUDGET))
    try:
        if name != "all":
            return check_one(name)
        return _check_all(start)
    finally:
        popup.set_deadline(None)


def _check_all(start: float) -> int:
    form, eff, data = _load()
    names = (["settings"] if eff.pending_for("settings") else []) + \
        [n for n in [*hosts_jumps_first(form), *form.accounts] if n != "settings"]
    clash = settings_clash(form)
    if clash:
        _err(clash)
    worst = 2 if clash else 0
    limit = _budget(ALL_BUDGET, "gate_check_all_budget")
    for i, n in enumerate(names):
        if i and time.time() - start > limit:
            left = names[i:]
            shown = ", ".join(left[:8]) + (", ..." if len(left) > 8 else "")
            many = "y is" if len(left) == 1 else "ies are"
            _err(f"gateway: gate check all stopped after {int(limit)} s so it isn't cut off; "
                 f"{len(left)} entr{many} still to check ({shown}); run gate check all again")
            return popup.EX_TEMPFAIL
        rc = check_one(n)
        if rc == popup.EX_TEMPFAIL:
            return rc
        worst = max(worst, rc)
    return worst


def hosts_jumps_first(form: formmod.Form) -> list[str]:
    """The form's hosts in form order, each jump host before the hosts that
    go through it (gate check all sets the jump up first)."""
    out: list[str] = []

    def add(n: str, depth: int = 0) -> None:
        if n in out or n not in form.hosts or depth > formmod.MAX_CHAIN + 1:
            return
        via = form.hosts[n].via
        if via:
            add(via, depth + 1)
        if n not in out:
            out.append(n)
    for n in form.hosts:
        add(n)
    return out


def login(name: str) -> int:
    """Ask for an account's credential again: its token, API key or client
    secret, in the gateway dialog (SPEC 15). Browser and device-code sign-ins
    are unavailable (popup.signin_unavailable)."""
    popup.set_deadline(time.time() + _budget(BUDGET))
    try:
        return check_one(name, force_signin=True)
    finally:
        popup.set_deadline(None)


def forget(name: str, what: str | None) -> int:
    """Forget an entry's stored secrets (or one kind of them) (SPEC 15)."""
    if what is not None and what not in FORGET_WHATS:
        _err("gateway: usage: gate forget NAME [" + "|".join(FORGET_WHATS) + "]")
        return 2
    form, eff, data = _load()
    real = name if name in ("localhost",) else acctmod.resolve_name(name, data.get("aliases") or {}, form)
    if not formmod.NAME_RE.fullmatch(real or ""):
        _err("gateway: that isn't a valid entry name")
        return 2
    gone: list[str] = []
    with vault.edit() as d:
        if real == "localhost":
            if what in (None, "sudo") and d.get("localhost", {}).get("sudo"):
                d["localhost"]["sudo"] = {}
                gone.append("sudo passwords")
        hosts = d.get("hosts") or {}
        if real in hosts:
            rec = hosts[real]
            # Forgotten pins are remembered (public keys, no secret): the next
            # gate check shows a changed key as a change, not as a first pin.
            prev = remembered_host_keys(rec)
            if what is None:
                if rec.get("keys") or rec.get("host_keys") or rec.get("sudo"):
                    gone.append("everything stored for the host (keys, pinned host keys, sudo passwords)")
                if prev:
                    hosts[real] = {"keys": [], "host_keys": [], "sudo": {}, "probe": {"nopasswd": {}},
                                   "host_keys_previous": prev}
                else:
                    del hosts[real]
            else:
                if what == "sudo" and rec.get("sudo"):
                    rec["sudo"] = {}
                    gone.append("sudo passwords")
                if what == "key" and rec.get("keys"):
                    rec["keys"] = []
                    rec.pop("installed", None)
                    gone.append("its keys")
                if what == "host-keys" and rec.get("host_keys"):
                    rec["host_keys"] = []
                    rec.pop("pinned_at", None)
                    rec["host_keys_previous"] = prev
                    gone.append("its pinned host keys (a different key will still be pointed out)")
        accts = d.get("accounts") or {}
        if real in accts:
            rec = accts[real]
            if what is None:
                bound = rec.get("bound")
                kind = rec.get("kind")
                accts[real] = {"kind": kind, "bound": bound or {"hosts": []}}
                gone.append("its token, keys and sign-in")
            else:
                if what == "token" and rec.pop("token", None) is not None:
                    gone.append("its token")
                if what == "key" and rec.pop("ssh_key", None) is not None:
                    gone.append("its ssh key")
                if what == "signin" and rec.pop("entra", None) is not None:
                    gone.append("its sign-in")
        if what in (None, "sudo") and (d.get("sudo_choice") or {}).pop(real, None) is not None \
                and not gone:
            gone.append("the sudo choice (gate check asks again)")
        if gone:
            vault.add_event(d, "forget", f"{real}: " + ", ".join(gone))
    if gone and real in (data.get("accounts") or {}):
        try:
            vault.cache_clear(real)
        except Exception:  # noqa: BLE001
            pass
    popup.clear(real)
    if not gone:
        _out(f"gateway: nothing stored for {real}" + (f" ({what})" if what else ""))
        return 0
    audit.log("forget", entry=real, what=what or "all")
    _out(f"gateway: forgot {', '.join(gone)} for {real}")
    return 0


def remembered_host_keys(rec: dict[str, Any]) -> list[str]:
    """The host keys to compare a new scan with after a forget: the pins and
    the ones remembered from earlier forgets (newest first, at most 20)."""
    keys = [k for k in (rec.get("host_keys") or []) + (rec.get("host_keys_previous") or [])
            if isinstance(k, str) and k]
    return list(dict.fromkeys(keys))[:20]


def rotate(name: str) -> int:
    """`gate rotate HOST` (SPEC 15)."""
    form, eff, data = _load()
    real = _resolve(name, form, data)
    if real is None:
        return 2
    if real not in form.hosts or form.hosts[real].is_local:
        _err(f"gateway: {real} isn't a remote host; gate rotate gives a host a new key")
        return 2
    try:
        line = _ssh().rotate(real)
    except NotImplementedError:
        _err("gateway: `gate rotate` isn't available in this build yet")
        return 2
    except popup.StillOpen:
        return popup.EX_TEMPFAIL
    audit.log("rotate", entry=real)
    _out(formmod.strip_unsafe(str(line or f"gateway: {real} has a new key")))
    return 0


# ---------------------------------------------------------------------------
# gate secret (removed)
# ---------------------------------------------------------------------------

SECRET_REMOVED = ("gateway: gate secret was removed: the gateway asks for credentials only in its "
                  "own dialog inside Claude Code (a terminal session or the desktop app), never "
                  "in a terminal prompt. In Claude Code, ask Claude to run gate check {name} (or "
                  "type /gate-dialog to show a dialog that is waiting).")


def secret_removed(name: str) -> int:
    """`gate secret NAME`: the terminal path is gone (PLAN-v4 phase 3)."""
    shown = name if isinstance(name, str) and formmod.NAME_RE.fullmatch(name) and \
        formmod.safe(name) else "NAME"
    _err(SECRET_REMOVED.format(name=shown))
    return 2
