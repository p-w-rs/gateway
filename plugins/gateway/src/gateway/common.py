"""What the typed /gate: commands and gate_setup share: validation, account
records, listing, deleting, sudo switches, sign-ins, hook output and the
transcript scrubber.

Values are never typed in the chat. If a typed command looks like it holds
one anyway (a token-like word), the prompt is blocked so Claude never sees
it, and the typed words are scrubbed from the transcript and prompt history.
"""
from __future__ import annotations

import getpass
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from . import entra, logins, vault, web_form

# Set by `gateway finish` (a terminal) to print an SSO device code instead of
# opening a browser page.
LOGIN_SHOW = None


class CommandError(Exception):
    pass

class LooksLikeValue(Exception):
    """The typed text may contain a secret: block the prompt and scrub."""

    def __init__(self, msg: str, typed: list[str]):
        super().__init__(msg)
        self.typed = typed

def _name(name: str) -> str:
    if not vault.NAME_RE.fullmatch(name):
        raise CommandError(f"'{name}' is not a valid name (letters, digits, _; "
                           "not starting with a digit), e.g. HF_TOKEN.")
    return name

# What a secret pasted in by mistake tends to look like: known ***** prefixes,
# or one long word mixing letters and digits.
_TOKEN_LIKE = re.compile(
    r"^(?:hf_|ghp_|gho_|ghs_|ghu_|github_pat_|glpat-|sk-|xox[abprs]-|AKIA)\S{6,}$"
    r"|^(?=\S*[A-Za-z])(?=\S*\d)\S{20,}$")

_KNOWN_PREFIX = re.compile(r"^(?:hf_|ghp_|gho_|ghs_|ghu_|github_pat_|glpat-|sk-|xox[abprs]-|AKIA)")

_HOSTNAME = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$")

def _guard_text(words: list[str]) -> None:
    # A host name (adb-1234567890.7.azuredatabricks.net) is long and mixes
    # letters and digits too; only a known token prefix flags one.
    # So is a file path (/gate:import ~/Downloads/gateway-20261017.age).
    hits = [w for w in words if _TOKEN_LIKE.match(w)
            and (_KNOWN_PREFIX.match(w) or not (_HOSTNAME.match(w.lower())
                                                or w.startswith(("/", "~/", "./", "../"))))]
    if hits:
        raise LooksLikeValue(
            "That looks like it contains a secret value, so it was not sent to "
            "Claude and nothing was saved. Values are typed only in the gateway's own "
            "dialog: type /gate:add secret or /gate:update NAME. (Your typed text has been "
            "scrubbed from the transcript.)", hits)

def _describe(name: str, s: dict[str, Any]) -> str:
    hosts = ", ".join(s.get("hosts", [])) or "none yet"
    desc = s.get("description") or "(no description)"
    return f"{name}: {desc} [hosts: {hosts}]"

FIELD_INFO = {
    "host": ("Host", "where it lives, e.g. github.com, a GitHub Enterprise host, nest.pijul.com"),
    "login": ("Login / username", "your user name on that service"),
    "name": ("Name for commits", "the author name to commit as"),
    "email": ("Email for commits", "the author email to commit as"),
    "remote_pijul": ("pijul on the server (optional)",
                     "absolute path to pijul on a self-hosted server, if not on its PATH"),
    "tenant": ("Tenant", "the directory (tenant) ID or domain, e.g. contoso.onmicrosoft.com"),
    "client_id": ("Client ID (optional)",
                  "the app to sign in with; empty = the Azure CLI's public client"),
    "user": ("User", "the login user on that host"),
    "port": ("Port (optional)", "empty = 22"),
    "jump": ("Jump host (optional)", "another ssh account to go through, e.g. ssh:bastion"),
    "via": ("Sign in through (optional)", "github:NAME for ghcr.io, azure:NAME for an Azure "
                                          "Container Registry; empty = use the token below"),
}

def _acct_ref(ref: str, data: dict[str, Any] | None = None, exists: bool = True) -> str:
    ref = ref.strip()
    if not vault.parse_account_ref(ref):
        raise CommandError(f"'{ref}' is not an account name like github:work "
                           f"(kinds: {', '.join(vault.KINDS)}).")
    if data is not None and exists and ref not in data["accounts"]:
        raise CommandError(f"No account named {ref}; see /gate:list.")
    return ref

def _describe_account(ref: str, a: dict[str, Any], data: dict[str, Any]) -> str:
    v = vault.account_view(ref, a, data)
    who = v.get("login") or v.get("user") or ""
    bits = [f"{ref}: {v['description'] or '(no description)'}"]
    if who:
        bits.append(f"as {who}")
    if "owners" in v:
        bits.append("owners: " + (", ".join(v["owners"]) or "any"))
    bits.append("hosts: " + (", ".join(v["hosts"]) or "none yet"))
    if v.get("via"):
        bits.append(f"signs in through {v['via']}")
    else:
        bits.append("methods: " + (", ".join(v["methods"]) or "none yet"))
    if v.get("key_fingerprint"):
        bits.append(f"key {v['key_fingerprint']}")
    if a.get("kind") == "ssh":
        if a.get("routes"):
            bits.append("routes: " + ", ".join(r.get("name", "?") for r in a["routes"]))
        if a.get("old_public_keys"):
            bits.append(f"{len(a['old_public_keys'])} older key(s) kept")
        if a.get("host_key_policy") in ("accept-new", "ask"):
            bits.append(f"host key: {a['host_key_policy']}")
    p = v["prompts"]
    asks = [k for k in vault.PROMPT_CLASSES if p[k] != "auto"]
    bits.append("prompts: " + (", ".join(f"{k}={p[k]}" for k in asks) or "never ask"))
    return " | ".join(bits)

def _clean_setting(kind: str, f: str, v: str) -> str:
    v = v.strip()
    if not v:
        return ""
    ok = {"host": lambda x: vault.HOST_RE.fullmatch(x.lower()),
          "login": vault.LOGIN_RE.fullmatch, "user": vault.USER_RE.fullmatch,
          "email": vault.EMAIL_RE.fullmatch,
          "name": lambda x: len(x) <= 100 and x.isprintable(),
          "remote_pijul": lambda x: x.startswith("/") and x.isprintable() and " " not in x,
          "tenant": lambda x: vault.GUID_RE.fullmatch(x) or vault.HOST_RE.fullmatch(x.lower()),
          "client_id": vault.GUID_RE.fullmatch,
          "port": lambda x: x.isdigit() and 0 < int(x) < 65536,
          "jump": lambda x: vault.parse_account_ref(x) and x.startswith("ssh:"),
          "via": lambda x: vault.parse_account_ref(x) and x.split(":")[0] in ("github", "azure")}[f]
    if not ok(v):
        raise CommandError(f"'{v}' is not a valid {FIELD_INFO[f][0].lower()}.")
    return v.lower() if f in ("host",) else v

def _owners(words: list[str]) -> list[str]:
    for w in words:
        if not vault.OWNER_RE.fullmatch(w):
            raise CommandError(f"'{w}' is not an owner or org name.")
    return [w for w in words if w]

def _apply_form(ref: str, kind: str, got: dict[str, str],
                old: dict[str, Any] | None) -> tuple[dict[str, Any], str]:
    """The new account record from the submitted form, plus a note for the
    user (e.g. the generated public key). Raises CommandError if invalid."""
    spec = vault.KINDS[kind]
    old = old or {}
    rec = {k: v for k, v in old.items()}
    rec["kind"] = kind
    for f in spec["fields"]:
        rec[f] = _clean_setting(kind, f, got.get(f, ""))
    if kind == "azure" and not rec.get("client_id"):
        rec["client_id"] = vault.AZURE_CLI_CLIENT_ID
    if spec["owners"]:
        rec["owners"] = _owners(got.get("owners", "").replace(",", " ").split())
    host = rec.get("host") or spec["host"]
    if "host" in spec["fields"] or spec["host"]:
        rec["host"] = host
    old_defaults = vault.default_hosts(kind, old.get("host", "")) if old else []
    extra = [h for h in old.get("hosts", []) if h not in old_defaults]
    rec["hosts"] = list(dict.fromkeys(vault.default_hosts(kind, host) + extra))
    secrets = dict(old.get("secrets", {}))
    note = ""
    token = got.get("token", "").strip()
    if token:
        if any(c.isspace() for c in token) or len(token) > 4096:
            raise CommandError("That token has spaces in it or is too long; nothing was saved.")
        secrets["token"] = token
    if rec.get("via"):
        if token:
            raise CommandError("Set either 'Sign in through' or a token, not both (the token "
                               "would never be used); nothing was saved.")
        if secrets.pop("token", None):
            note = (f"{ref} now signs in through {rec['via']}; its own token was removed.")
    mode = got.get("ssh_key_mode", "")
    if mode == "generate":
        priv, pub = vault.generate_ssh_key(f"gateway {ref}")
        secrets["ssh_key"] = priv
        rec["public_key"] = pub
        note = f"New SSH public key (add it on {host}):\n{pub}"
    elif mode == "paste":
        priv = got.get("ssh_key", "").strip()
        if priv:
            priv = vault.normalize_key(priv).rstrip("\n")
        if not priv:
            raise CommandError("'Use a private key I paste' was chosen but no key was pasted; "
                               "nothing was saved.")
        try:
            rec["public_key"] = vault.public_key_of(priv)
        except ValueError as e:
            raise CommandError(f"{e}; nothing was saved.")
        secrets["ssh_key"] = priv + "\n"
    if rec.get("public_key") and secrets.get("ssh_key"):
        rec["key_fingerprint"] = vault.fingerprint_of(rec["public_key"])
    if kind in vault.PINNED_KINDS and (not rec.get("known_hosts") or host != old.get("host")
                                       or rec.get("port") != old.get("port")):
        rec["known_hosts"] = vault.keyscan(host, rec.get("port", ""))
        fps = vault.host_key_fingerprints(rec["known_hosts"])
        note += ("\n" if note else "") + (
            f"Host key pinned for {host}: " + "; ".join(fps) + " (check it if you can)"
            if fps else f"Could not read {host}'s SSH host key, so connections will be refused "
                        f"until it can be read: type /gate:update {ref} again"
                        + (" (if it is an alias from your ~/.ssh/config, give its real HostName "
                           "and Port)." if kind == "ssh" and "." not in host else "."))
    rec["secrets"] = secrets
    rec["updated"] = vault.now()
    return rec, note

def _sudo_target(user: str, host: str) -> tuple[str, str]:
    host = vault.norm_host(host)
    if not vault.USER_RE.fullmatch(user):
        raise CommandError(f"'{user}' is not a valid user name.")
    if not vault.HOST_RE.fullmatch(host):
        raise CommandError(f"'{host}' is not a host name, ssh alias or IP address.")
    if host == "localhost" and user != getpass.getuser():
        raise CommandError(f"On this machine sudo asks for the password of the user "
                           f"running Claude Code ({getpass.getuser()}), not {user}.")
    return user, host

def _entra_settings(ref: str, a: dict[str, Any]) -> tuple[str, str, str]:
    """(tenant, client_id, scope) to sign in with."""
    if a["kind"] == "mlcat":
        from . import mlcat
        cfg = mlcat.catalog_config(a.get("host", ""))
        return cfg["tenantId"], cfg["cliClientId"], mlcat.api_scope(cfg)
    if not a.get("tenant"):
        raise CommandError(f"{ref} has no tenant; set it with /gate:update {ref}")
    return a["tenant"], a.get("client_id") or vault.AZURE_CLI_CLIENT_ID, entra.SCOPES["arm"]

def _entra_login(ref: str, data: dict[str, Any]) -> str:
    a = data["accounts"][ref]
    try:
        tenant, client_id, scope = _entra_settings(ref, a)
        if LOGIN_SHOW is not None:
            tok = entra.login_device(tenant, client_id, scope, LOGIN_SHOW)
        else:
            tok = entra.login_browser(tenant, client_id, scope)
    except entra.EntraError as e:
        raise CommandError(f"{e}; nothing was saved.")
    except web_form.Unavailable:
        raise CommandError("No browser can be opened here, so nothing was saved.")
    except Exception as e:  # e.g. the catalog's config couldn't be read
        raise CommandError(f"{e}; nothing was saved.")
    if not tok.get("refresh_token"):
        raise CommandError("Entra returned no refresh token; nothing was saved.")
    claims = tok.get("claims", {})
    with vault.locked():
        data = vault.load()
        a = data["accounts"].get(ref)
        if a is None:
            raise CommandError(f"{ref} was deleted meanwhile; nothing was saved.")
        a.setdefault("secrets", {})["refresh_token"] = tok["refresh_token"]
        a["client_id"], a["tenant_id"] = client_id, claims.get("tid") or tenant
        if claims.get("preferred_username"):
            a["login"] = claims["preferred_username"]
        a["token_source"] = "entra"
        a["updated"] = vault.now()
        vault.save(data)
        who = f" as {a.get('login')}" if a.get("login") else ""
        return f"Signed in{who}; {ref} can now get tokens.\n{_describe_account(ref, a, data)}"

def block(reason: str) -> dict[str, Any]:
    """Block the prompt (only when it may hold a value). suppressOriginalPrompt
    keeps the typed line out of the notice and the transcript."""
    return {"decision": "block", "reason": reason,
            "hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                   "suppressOriginalPrompt": True}}

def passthrough(result: str) -> dict[str, Any]:
    """Let the prompt reach Claude with the result attached."""
    return {"hookSpecificOutput": {
        "hookEventName": "UserPromptSubmit",
        "additionalContext": ("<gateway-result>\nThe gateway already handled "
                              "the user's command. Result:\n" + result
                              + "\n</gateway-result>")}}

def _history_path() -> Path:
    base = os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")
    return Path(base) / "history.jsonl"

def _spawn_scrubber(transcript: str, values: list[str]) -> None:
    if not values:
        return
    paths = [p for p in (transcript, str(_history_path())) if p]
    run_py = Path(__file__).resolve().parents[2] / "run.py"
    kwargs: dict[str, Any] = dict(stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                                  stderr=subprocess.DEVNULL)
    if sys.platform == "win32":
        kwargs["creationflags"] = 0x00000008 | 0x00000200  # DETACHED | NEW_GROUP
    else:
        kwargs["start_new_session"] = True
    proc = subprocess.Popen([sys.executable, str(run_py), "scrub", *paths], **kwargs)
    proc.stdin.write(json.dumps(values).encode())  # values via stdin, never argv
    proc.stdin.close()

def _needles(value: str) -> list[bytes]:
    out = {value.encode("utf-8"),
           json.dumps(value)[1:-1].encode("utf-8"),
           json.dumps(value, ensure_ascii=False)[1:-1].encode("utf-8")}
    return sorted((n for n in out if n), key=len, reverse=True)

MARKERS = (b"gate:",)  # only lines holding a typed /gate: command are scrubbed

def scrub_file(path: Path, values: list[str]) -> int:
    """Overwrite values with '*' in place, only on lines holding a command.
    Same-length, in-place writes keep the file valid while Claude Code keeps
    appending to it."""
    try:
        data = path.read_bytes()
    except OSError:
        return 0
    needles = [n for v in values for n in _needles(v)]
    hits = []
    pos = 0
    for line in data.splitlines(keepends=True):
        if any(m in line for m in MARKERS):
            for n in needles:
                start = 0
                while (i := line.find(n, start)) != -1:
                    hits.append((pos + i, len(n)))
                    start = i + len(n)
        pos += len(line)
    if hits:
        with open(path, "r+b") as f:
            for off, ln in hits:
                f.seek(off)
                f.write(b"*" * ln)
    return len(hits)

def scrub_main(paths: list[str], duration: float = 10.0, interval: float = 0.25) -> int:
    """Keep scrubbing for a few seconds: Claude Code writes the blocked prompt
    to the transcript around the time the hook returns."""
    try:
        values = json.loads(sys.stdin.read() or "[]")
    except Exception:
        return 0
    end = time.time() + duration
    while time.time() < end:
        for p in paths:
            scrub_file(Path(p), values)
        time.sleep(interval)
    return 0



# ---------------------------------------------------------------------------
# Listing, deleting, sudo switches, sign-in (used by setup.py)
# ---------------------------------------------------------------------------


def list_all(session_id: str) -> str:
    data = vault.load()
    cat = vault.catalog(data)
    parts = ["\n".join(_describe(n, s) for n, s in cat["secrets"].items())
             or "No secrets yet.",
             "\n".join(_describe_account(r, a, data) for r, a in sorted(data["accounts"].items()))
             or "No accounts yet.",
             "\n".join(f"{k}  [{vault.sudo_state(e['host'], session_id, data)}]"
                       for k, e in sorted(data["sudo"].items()))
             or "No sudo passwords stored."]
    return "\n\n".join(parts)


def delete_secret(name: str) -> str:
    _name(name)
    with vault.locked():
        data = vault.load()
        if data["secrets"].pop(name, None) is None:
            raise CommandError(f"Nothing named {name}; see /gate:list.")
        vault.save(data)
    return f"Deleted the secret {name}."


def delete_account(ref: str) -> str:
    with vault.locked():
        data = vault.load()
        _acct_ref(ref, data)
        data["accounts"].pop(ref)
        (data.get("ssh_reuse") or {}).pop(ref, None)
        vault.save(data)
    return f"Deleted the account {ref}."


def delete_sudo(user: str, host: str) -> str:
    host = vault.norm_host(host)
    key = f"{user}@{host}"
    with vault.locked():
        data = vault.load()
        if data["sudo"].pop(key, None) is None:
            raise CommandError(f"No sudo password for {key}.")
        if not any(e.get("host") == host for e in data["sudo"].values()):
            vault.clear_sudo(data, host)
        vault.save(data)
    return f"Deleted the sudo password for {key}."


def sudo_switch(verb: str, words: list[str], session_id: str) -> str:
    """/gate:enable sudo HOST [always] and /gate:disable sudo HOST."""
    if not words or len(words) > 2 or (len(words) == 2 and words[1].lower() != "always") \
            or (verb == "disable" and len(words) != 1):
        raise CommandError(f"Usage: /gate:{verb} sudo HOST" + (" [always]" if verb == "enable" else ""))
    host = vault.norm_host(words[0])
    if not vault.HOST_RE.fullmatch(host):
        raise CommandError(f"'{host}' is not a host name, ssh alias or IP address.")
    always = len(words) == 2
    with vault.locked():
        data = vault.load()
        if verb == "enable":
            if not any(e.get("host") == host for e in data["sudo"].values()):
                raise CommandError(f"No sudo password stored for {host}; type /gate:add sudo "
                                   "first.")
            if always:
                if host not in data["sudo_enabled"]:
                    data["sudo_enabled"].append(host)
            else:
                if not session_id:
                    raise CommandError("This session's id is unknown, so it can't be "
                                       "enabled for this session only; add 'always'.")
                vault.enable_for_session(data, host, session_id)
        else:
            vault.clear_sudo(data, host)
        vault.save(data)
    if verb == "enable":
        scope = "in EVERY session" if always else "for THIS session only"
        return (f"sudo ENABLED on {host} {scope}: root commands there now run "
                f"WITHOUT asking. Turn off with /gate:disable sudo {host}.")
    return f"sudo disabled on {host} (all sessions): every root command there asks."


def login(ref: str) -> str:
    """Sign an account in through its provider (GitHub, Entra)."""
    data = vault.load()
    _acct_ref(ref, data)
    kind = data["accounts"][ref]["kind"]
    if kind in ("azure", "mlcat"):
        return _entra_login(ref, data)
    if kind != "github":
        raise CommandError(f"There is no browser sign-in for {kind} accounts.")
    host = data["accounts"][ref].get("host") or "github.com"
    try:
        token, user = logins.github_login(host, show=LOGIN_SHOW)
    except logins.LoginError as e:
        raise CommandError(f"{e}; nothing was saved.")
    except web_form.Unavailable:
        raise CommandError("No browser can be opened here, so nothing was saved.")
    with vault.locked():
        data = vault.load()
        a = data["accounts"].get(ref)
        if a is None:
            raise CommandError(f"{ref} was deleted meanwhile; nothing was saved.")
        a.setdefault("secrets", {})["token"] = token
        a["token_source"] = "gh-oauth"
        if user and not a.get("login"):
            a["login"] = user
        a["updated"] = vault.now()
        vault.save(data)
        who = f" as {user}" if user else ""
        return (f"Signed in to {host}{who}; {ref} now uses that sign-in's token "
                f"(OAuth, through gh).\n{_describe_account(ref, a, data)}")
