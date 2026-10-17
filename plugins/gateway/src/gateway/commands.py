"""The /gate:secret, /gate:sudo and /gate:account chat commands.

A UserPromptSubmit hook handles them. Values (secrets, sudo passwords) are
never typed in the chat: the hook opens a one-time browser form with a masked
field (web_form.py) and saves what the user submits. Because the command text
then holds no secret, the hook does NOT block the prompt: it lets it through
with a note saying what it did, and the command's own text tells Claude to
just confirm. No "blocked by hook" pop-up, nothing restored to the input box.

The one exception: if the text looks like it contains a value anyway (a
*****-like word, or a password after `sudo add USER HOST`), the prompt is
blocked so Claude never sees it, and the typed words are scrubbed from the
transcript and prompt history.

    /gate:secret add NAME description...     (browser form asks the value)
    /gate:secret up NAME [new description]   (browser form; empty = keep)
    /gate:secret desc NAME description...
    /gate:secret allow NAME HOST [HOST...]
    /gate:secret disallow NAME HOST [HOST...]
    /gate:secret del NAME
    /gate:secret list
    /gate:sudo add USER HOST                  (browser form asks the password)
    /gate:sudo up USER HOST
    /gate:sudo del USER HOST
    /gate:sudo enable HOST [always]           this session only, or all sessions
    /gate:sudo disable HOST
    /gate:sudo list
    /gate:account add KIND NAME description   (browser form: settings, token, ssh key)
    /gate:account up|desc|allow|disallow|prompts|pubkey|import|forget|del|list ...
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

from . import logins, policy, vault, web_form

PREFIX = re.compile(r"^\s*/(?:gate:)?(secret|sudo|account)(?=\s|$)(.*)$", re.S)

SECRET_HELP = (
    "/gate:secret add NAME description     store a secret (a browser form asks the value)\n"
    "/gate:secret up NAME [description]    new value (browser form) and/or description\n"
    "/gate:secret desc NAME description    change only the description\n"
    "/gate:secret allow NAME HOST...       let it be sent to these hosts\n"
    "/gate:secret disallow NAME HOST...    stop sending it to these hosts\n"
    "/gate:secret del NAME                 delete it\n"
    "/gate:secret list                     names, descriptions, hosts"
)
SUDO_HELP = (
    "/gate:sudo add USER HOST       store a sudo password (a browser form asks it);\n"
    "                                      HOST: localhost, an ssh alias, a name or an IP\n"
    "/gate:sudo up USER HOST        replace it\n"
    "/gate:sudo del USER HOST       delete it\n"
    "/gate:sudo enable HOST         root commands run WITHOUT asking, this session only\n"
    "/gate:sudo enable HOST always  ...in every session\n"
    "/gate:sudo disable HOST        every root command asks again (the default)\n"
    "/gate:sudo list                stored USER@HOST entries and where sudo is enabled"
)


KIND_LIST = ", ".join(vault.KINDS)
ACCOUNT_HELP = (
    "/gate:account add KIND NAME description   new account; a browser form asks its settings,\n"
    f"                                            token and/or SSH key. KIND: {KIND_LIST}\n"
    "/gate:account up KIND:NAME [description]   change settings, replace the token or key\n"
    "/gate:account desc KIND:NAME description   change only the description\n"
    "/gate:account allow KIND:NAME OWNER|HOST.. what it may be used for (a name with a dot\n"
    "                                            is a host, otherwise an owner/org)\n"
    "/gate:account disallow KIND:NAME OWNER|HOST..\n"
    "/gate:account prompts KIND:NAME|* [read|write|delete|exec=auto|ask|refuse ...|reset]\n"
    "                                            when tools using it must ask you first\n"
    "/gate:account pubkey KIND:NAME             show its public SSH key (to paste on the site)\n"
    "/gate:account import KIND:NAME SECRET      use a /gate:secret value as its token\n"
    "/gate:account forget KIND:NAME token|ssh_key  remove one credential\n"
    "/gate:account login KIND:NAME              sign in with SSO (GitHub now; others later)\n"
    "/gate:account del KIND:NAME                delete it\n"
    "/gate:account list                         accounts, scope, methods (never values)"
)


class CommandError(Exception):
    pass


class LooksLikeValue(Exception):
    """The typed text may contain a secret: block the prompt and scrub."""

    def __init__(self, msg: str, typed: list[str]):
        super().__init__(msg)
        self.typed = typed


def is_command(prompt: str) -> bool:
    return bool(PREFIX.match(prompt or ""))


def _words(rest: str, n: int) -> list[str]:
    """Split off the first n words; the remainder (verbatim) is element n."""
    parts = rest.strip().split(None, n)
    return parts + [""] * (n + 1 - len(parts))


def _name(name: str) -> str:
    if not vault.NAME_RE.fullmatch(name):
        raise CommandError(f"'{name}' is not a valid name (letters, digits, _; "
                           "not starting with a digit), e.g. HF_TOKEN.")
    return name


def _hosts(words: list[str]) -> list[str]:
    hosts = [h.lower() for h in words if h]
    if not hosts:
        raise CommandError("Give at least one host.")
    for h in hosts:
        if h == "*" or not vault.HOST_RE.fullmatch(h):
            raise CommandError(f"'{h}' is not a host name or IP address.")
    return hosts


# What a secret pasted in by mistake tends to look like: known ***** prefixes,
# or one long word mixing letters and digits.
_TOKEN_LIKE = re.compile(
    r"^(?:hf_|ghp_|gho_|ghs_|ghu_|github_pat_|glpat-|sk-|xox[abprs]-|AKIA)\S{6,}$"
    r"|^(?=\S*[A-Za-z])(?=\S*\d)\S{20,}$")


def _guard_text(words: list[str]) -> None:
    hits = [w for w in words if _TOKEN_LIKE.match(w)]
    if hits:
        raise LooksLikeValue(
            "That looks like it contains a secret value, so it was not sent to "
            "Claude and nothing was saved. Values go in the browser form: type only "
            "/gate:secret add NAME description. (Your typed text has been "
            "scrubbed from the transcript.)", hits)


def _describe(name: str, s: dict[str, Any]) -> str:
    hosts = ", ".join(s.get("hosts", [])) or "none yet"
    desc = s.get("description") or "(no description)"
    return f"{name}: {desc} [hosts: {hosts}]"


# Set by `run.py vault` (the terminal fallback) to read values at a hidden
# prompt instead of opening the browser form.
VALUE_PROVIDER = None


def terminal_command(args: str) -> str:
    """The terminal-fallback command for the same action, for messages."""
    from . import policy as _p
    return f"pixi run --manifest-path {_p.plugin_root() / 'pixi.toml'} vault {args}"


def _form(title: str, details: list[tuple[str, str]], label: str,
          optional: bool = False) -> str | None:
    if VALUE_PROVIDER is not None:
        return VALUE_PROVIDER(title, details, label, optional)
    try:
        return web_form.ask(title, details, label, optional=optional)
    except web_form.Unavailable:
        raise CommandError(
            "No browser can be opened here (no desktop, e.g. over ssh), so nothing "
            "was saved. Run the same command in a terminal on this machine instead; "
            "it asks for the value at a hidden prompt:\n  "
            + terminal_command(_CURRENT.get("args", "secret|sudo ...")))


_CURRENT: dict[str, str] = {}  # the command being handled, for the hint above

# Set by `run.py vault` to ask multi-field forms in the terminal.
FIELDS_PROVIDER = None
# Set by `run.py vault` to print an SSO one-time code instead of a page.
LOGIN_SHOW = None


def _fields_form(title: str, details: list[tuple[str, str]],
                 fields: list[dict[str, Any]]) -> dict[str, str] | None:
    if FIELDS_PROVIDER is not None:
        return FIELDS_PROVIDER(title, details, fields)
    try:
        return web_form.ask_form(title, details, fields)
    except web_form.Unavailable:
        raise CommandError(
            "No browser can be opened here (no desktop, e.g. over ssh), so nothing "
            "was saved. Run the same command in a terminal on this machine instead:\n  "
            + terminal_command(_CURRENT.get("args", "account ...")))


# ---------------------------------------------------------------------------
# /secret
# ---------------------------------------------------------------------------


def run_secret(rest: str) -> str:
    sub, tail = _words(rest, 1)
    sub = sub.lower()
    _guard_text(tail.split())
    if sub in ("", "help"):
        return SECRET_HELP
    if sub == "list":
        cat = vault.catalog()
        if not cat["secrets"]:
            return "No secrets stored yet."
        return "\n".join(_describe(n, s) for n, s in cat["secrets"].items())

    if sub in ("add", "up", "update"):
        name, desc = _words(tail, 1)
        _name(name)
        desc = desc.strip()
        existing = vault.secret(name)
        if sub == "add":
            if existing:
                raise CommandError(f"{name} already exists; use "
                                   f"/gate:secret up {name}.")
            if not desc:
                raise CommandError("Add a description so Claude knows what it is for: "
                                   f"/gate:secret add {name} what it is and what for")
        elif not existing:
            raise CommandError(f"No secret named {name}; use /gate:secret add.")
        value = _form(f"{'Store' if sub == 'add' else 'Update'} the secret {name}",
                      [("Description", desc or (existing or {}).get("description", "")),
                       ("Sent only to", ", ".join((existing or {}).get("hosts", []))
                        or "nowhere yet (allow a host afterwards)")],
                      f"Value for {name}" if sub == "add"
                      else "New value (leave empty to keep the current one)",
                      optional=sub != "add")
        if value is None:
            return f"Cancelled; nothing was saved for {name}."
        value = value.strip()
        if sub != "add" and not value and not desc:
            return f"Nothing changed for {name}."
        with vault.locked():
            data = vault.load()
            old = data["secrets"].get(name, {})
            data["secrets"][name] = {
                "value": value or old.get("value", ""),
                "description": desc or old.get("description", ""),
                "hosts": old.get("hosts", []), "updated": vault.now()}
            vault.save(data)
            s = data["secrets"][name]
        msg = f"{'Stored' if sub == 'add' else 'Updated'} {_describe(name, s)}."
        if not s["hosts"]:
            msg += (f" It can't be sent anywhere yet: /gate:secret allow {name} HOST")
        return msg

    with vault.locked():
        data = vault.load()
        secrets = data["secrets"]
        if sub == "desc":
            name, desc = _words(tail, 1)
            _name(name)
            if name not in secrets:
                raise CommandError(f"No secret named {name}.")
            secrets[name]["description"] = desc.strip()
            vault.save(data)
            return f"Updated {_describe(name, secrets[name])}."
        if sub in ("allow", "disallow"):
            parts = tail.split()
            if not parts:
                raise CommandError(f"Usage: /gate:secret {sub} NAME HOST [HOST...]")
            name = _name(parts[0])
            if name not in secrets:
                raise CommandError(f"No secret named {name}.")
            hosts = _hosts(parts[1:])
            cur = list(secrets[name].get("hosts", []))
            if sub == "allow":
                cur += [h for h in hosts if h not in cur]
            else:
                cur = [h for h in cur if h not in hosts]
            secrets[name]["hosts"] = cur
            vault.save(data)
            return f"Updated {_describe(name, secrets[name])}."
        if sub in ("del", "delete", "rm"):
            name = _name(tail.strip())
            if secrets.pop(name, None) is None:
                raise CommandError(f"No secret named {name}.")
            vault.save(data)
            return f"Deleted the secret {name}."
    raise CommandError(f"Unknown command '{sub}'.\n{SECRET_HELP}")


# ---------------------------------------------------------------------------
# /sudo
# ---------------------------------------------------------------------------


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


def run_sudo(rest: str, session_id: str) -> str:
    sub, tail = _words(rest, 1)
    sub = sub.lower()
    words = tail.split()
    if sub in ("", "help"):
        return SUDO_HELP
    if sub == "list":
        data = vault.load()
        if not data["sudo"]:
            return "No sudo passwords stored."
        lines = []
        for key, e in sorted(data["sudo"].items()):
            state = vault.sudo_state(e["host"], session_id, data)
            lines.append(f"{key}  [{state}]")
        return "\n".join(lines)

    if sub in ("add", "up", "update"):
        if len(words) > 2:
            # Anything after HOST would be a password typed into the chat.
            raise LooksLikeValue(
                "Nothing was saved, and this was not sent to Claude: type only "
                "/gate:sudo add USER HOST and enter the password in the "
                "browser form. (Your typed text has been scrubbed from the "
                "transcript.)", [" ".join(words[2:])] + words[2:])
        if len(words) != 2:
            raise CommandError(f"Usage: /gate:sudo {sub} USER HOST")
        user, host = _sudo_target(*words)
        key = f"{user}@{host}"
        exists = key in vault.load()["sudo"]
        if sub == "add" and exists:
            raise CommandError(f"{key} already has a password; use /gate:sudo up.")
        if sub != "add" and not exists:
            raise CommandError(f"No sudo password for {key}; use /gate:sudo add.")
        pw = _form(f"{'Store a' if sub == 'add' else 'Update the'} sudo password",
                   [("User", user),
                    ("Host", "this machine" if host == "localhost" else host),
                    ("Used for", "running commands as root via run_privileged")],
                   f"sudo password for {key}")
        if not pw:
            return f"Cancelled; nothing was saved for {key}."
        with vault.locked():
            data = vault.load()
            data["sudo"][key] = {"user": user, "host": host, "password": pw,
                                 "updated": vault.now()}
            vault.save(data)
        return (f"{'Stored' if sub == 'add' else 'Updated'} the sudo password for {key}. "
                f"sudo there: {vault.sudo_state(host, session_id)}.")

    _guard_text(words)
    if sub in ("del", "delete", "rm"):
        if len(words) != 2:
            raise CommandError("Usage: /gate:sudo del USER HOST")
        host = vault.norm_host(words[1])
        key = f"{words[0]}@{host}"
        with vault.locked():
            data = vault.load()
            if data["sudo"].pop(key, None) is None:
                raise CommandError(f"No sudo password for {key}.")
            if not any(e.get("host") == host for e in data["sudo"].values()):
                vault.clear_sudo(data, host)
            vault.save(data)
        return f"Deleted the sudo password for {key}."
    if sub in ("enable", "disable"):
        if not words or len(words) > 2 or (len(words) == 2 and words[1].lower() != "always"):
            raise CommandError(f"Usage: /gate:sudo {sub} HOST"
                               + (" [always]" if sub == "enable" else ""))
        host = vault.norm_host(words[0])
        if not vault.HOST_RE.fullmatch(host):
            raise CommandError(f"'{host}' is not a host name, ssh alias or IP address.")
        always = len(words) == 2
        with vault.locked():
            data = vault.load()
            if sub == "enable":
                if not any(e.get("host") == host for e in data["sudo"].values()):
                    raise CommandError(f"No sudo password stored for {host}; use "
                                       f"/gate:sudo add USER {host} first.")
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
        if sub == "enable":
            scope = "in EVERY session" if always else "for THIS session only"
            return (f"sudo ENABLED on {host} {scope}: root commands there now run "
                    f"WITHOUT asking. Turn off with /gate:sudo disable {host}.")
        return f"sudo disabled on {host} (all sessions): every root command there asks."
    raise CommandError(f"Unknown command '{sub}'.\n{SUDO_HELP}")


# ---------------------------------------------------------------------------
# /account
# ---------------------------------------------------------------------------

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
}


def _acct_ref(ref: str, data: dict[str, Any] | None = None, exists: bool = True) -> str:
    ref = ref.strip()
    if not vault.parse_account_ref(ref):
        raise CommandError(f"'{ref}' is not an account name like github:work "
                           f"(kinds: {KIND_LIST}).")
    if data is not None and exists and ref not in data["accounts"]:
        raise CommandError(f"No account named {ref}; see /gate:account list.")
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
    bits.append("methods: " + (", ".join(v["methods"]) or "none yet"))
    if v.get("key_fingerprint"):
        bits.append(f"key {v['key_fingerprint']}")
    p = v["prompts"]
    asks = [k for k in vault.PROMPT_CLASSES if p[k] != "auto"]
    bits.append("prompts: " + (", ".join(f"{k}={p[k]}" for k in asks) or "never ask"))
    return " | ".join(bits)


def _account_fields(kind: str, old: dict[str, Any] | None) -> list[dict[str, Any]]:
    spec = vault.KINDS[kind]
    old = old or {}
    fields: list[dict[str, Any]] = []
    for f in spec["fields"]:
        label, helptext = FIELD_INFO[f]
        value = old.get(f, spec["host"] if f == "host" else "")
        fields.append({"name": f, "label": label, "help": helptext, "value": str(value),
                       "required": f in ("host", "tenant") or (f == "user" and kind == "ssh")})
    if spec["owners"]:
        fields.append({"name": "owners", "label": "Owners / orgs (optional)",
                       "value": " ".join(old.get("owners", [])),
                       "help": "which owners it is for, e.g. asirobots; empty = any on its hosts"})
    if "token" in spec["secrets"]:
        fields.append({"name": "token", "label": "Token (optional)", "type": "password",
                       "help": ("leave empty to keep the current one" if old.get("secrets", {}).get("token")
                                else "a personal access token; leave empty to use SSH or sign in later")})
    if "ssh_key" in spec["secrets"]:
        has = bool(old.get("secrets", {}).get("ssh_key"))
        opts = ([("keep", "Keep the current SSH key")] if has else [("none", "No SSH key")])
        opts += [("generate", "Generate a new SSH key (shows the public key to add on the site)"),
                 ("paste", "Use a private key I paste below")]
        fields.append({"name": "ssh_key_mode", "label": "SSH key", "type": "select",
                       "options": opts, "value": opts[0][0]})
        fields.append({"name": "ssh_key", "label": "Private key (only for 'paste')",
                       "type": "textarea",
                       "help": "an OpenSSH private key without a passphrase; it stays in the vault"})
    return fields


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
          "port": lambda x: x.isdigit() and 0 < int(x) < 65536}[f]
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
    mode = got.get("ssh_key_mode", "")
    if mode == "generate":
        priv, pub = vault.generate_ssh_key(f"gateway {ref}")
        secrets["ssh_key"] = priv
        rec["public_key"] = pub
        note = f"New SSH public key (add it on {host}):\n{pub}"
    elif mode == "paste":
        priv = got.get("ssh_key", "").strip()
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
                        f"until it can be read: run /gate:account up {ref} again.")
    rec["secrets"] = secrets
    rec["updated"] = vault.now()
    return rec, note


def _prompts_cmd(target: str, words: list[str]) -> str:
    with vault.locked():
        data = vault.load()
        if target == "*":
            store = data.setdefault("account_prompts", {})
            label = "the default for all accounts"
        else:
            ref = _acct_ref(target, data)
            store = data["accounts"][ref].setdefault("prompts", {})
            label = ref
        if not words:
            shown = (vault.effective_prompts({}, data) if target == "*"
                     else vault.effective_prompts(data["accounts"][target], data))
            return f"Prompts for {label}: " + ", ".join(f"{k}={v}" for k, v in shown.items())
        if words == ["reset"]:
            store.clear()
        else:
            for w in words:
                k, _, v = w.partition("=")
                if k not in vault.PROMPT_CLASSES or v not in vault.PROMPT_VALUES:
                    raise CommandError(f"'{w}' should look like write=ask (classes: "
                                       f"{', '.join(vault.PROMPT_CLASSES)}; values: "
                                       f"{', '.join(vault.PROMPT_VALUES)}).")
                store[k] = v
        vault.save(data)
        shown = (vault.effective_prompts({}, data) if target == "*"
                 else vault.effective_prompts(data["accounts"][target], data))
    return f"Prompts for {label}: " + ", ".join(f"{k}={v}" for k, v in shown.items())


def run_account(rest: str) -> str:
    sub, tail = _words(rest, 1)
    sub = sub.lower()
    _guard_text(tail.split())
    if sub in ("", "help"):
        return ACCOUNT_HELP
    if sub == "list":
        data = vault.load()
        if not data["accounts"]:
            return "No accounts yet. Add one with /gate:account add KIND NAME description."
        return "\n".join(_describe_account(r, a, data) for r, a in sorted(data["accounts"].items()))

    if sub in ("add", "up", "update"):
        if sub == "add":
            kind, name, desc = _words(tail, 2)
            kind = kind.lower()
            if kind not in vault.KINDS:
                raise CommandError(f"Unknown kind '{kind}'. Kinds: {KIND_LIST}.")
            if ":" in name:
                raise CommandError(f"Give the kind and the name separately: "
                                   f"/gate:account add {kind} NAME description")
            ref = _acct_ref(f"{kind}:{name.lower()}", exists=False)
            if not desc.strip():
                raise CommandError("Add a description so Claude knows what it is for: "
                                   f"/gate:account add {kind} {name} what it is for")
            old = None
            if vault.account(ref):
                raise CommandError(f"{ref} already exists; use /gate:account up {ref}.")
        else:
            target, desc = _words(tail, 1)
            data = vault.load()
            ref = _acct_ref(target, data)
            kind = ref.split(":", 1)[0]
            old = data["accounts"][ref]
        spec = vault.KINDS[kind]
        details = [("Account", ref), ("Kind", spec["label"]),
                   ("Description", desc.strip() or (old or {}).get("description", ""))]
        if kind in ("azure", "mlcat"):
            details.append(("Sign-in", "SSO sign-in comes with /gate:account login "
                                       "in a later version"))
        got = _fields_form(f"{'Add' if sub == 'add' else 'Update'} the account {ref}",
                           details, _account_fields(kind, old))
        if got is None:
            return f"Cancelled; nothing was saved for {ref}."
        rec, note = _apply_form(ref, kind, got, old)
        rec["description"] = desc.strip() or (old or {}).get("description", "")
        with vault.locked():
            data = vault.load()
            if sub == "add" and ref in data["accounts"]:
                raise CommandError(f"{ref} already exists; use /gate:account up {ref}.")
            data["accounts"][ref] = rec
            vault.save(data)
            msg = f"{'Added' if sub == 'add' else 'Updated'} {_describe_account(ref, rec, data)}."
        return msg + (f"\n{note}" if note else "")

    if sub == "prompts":
        parts = tail.split()
        if not parts:
            raise CommandError("Usage: /gate:account prompts KIND:NAME|* [class=value ...|reset]")
        return _prompts_cmd(parts[0], parts[1:])

    if sub == "login":
        data = vault.load()
        ref = _acct_ref(tail.split()[0] if tail.split() else "", data)
        kind = data["accounts"][ref]["kind"]
        if kind != "github":
            raise CommandError(f"SSO sign-in for {kind} accounts comes in a later version of "
                               f"the gateway. For now add a token or SSH key with "
                               f"/gate:account up {ref}.")
        host = data["accounts"][ref].get("host") or "github.com"
        try:
            token, user = logins.github_login(host, show=LOGIN_SHOW)
        except logins.LoginError as e:
            raise CommandError(f"{e}; nothing was saved.")
        except web_form.Unavailable:
            raise CommandError(
                "No browser can be opened here, so nothing was saved. Run the same command "
                "in a terminal on this machine instead (it prints the code):\n  "
                + terminal_command(_CURRENT.get("args", "account login ...")))
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

    with vault.locked():
        data = vault.load()
        accounts = data["accounts"]
        parts = tail.split()
        if sub == "pubkey":
            ref = _acct_ref(parts[0] if parts else "", data)
            pub = accounts[ref].get("public_key")
            if not pub:
                raise CommandError(f"{ref} has no SSH key; add one with /gate:account up {ref}.")
            return f"Public SSH key of {ref} ({accounts[ref].get('key_fingerprint', '')}):\n{pub}"
        if sub == "desc":
            target, desc = _words(tail, 1)
            ref = _acct_ref(target, data)
            accounts[ref]["description"] = desc.strip()
            vault.save(data)
            return f"Updated {_describe_account(ref, accounts[ref], data)}."
        if sub in ("allow", "disallow"):
            if len(parts) < 2:
                raise CommandError(f"Usage: /gate:account {sub} KIND:NAME OWNER|HOST [...]")
            ref = _acct_ref(parts[0], data)
            a = accounts[ref]
            hosts = [w.lower() for w in parts[1:] if "." in w]
            owners = [w for w in parts[1:] if "." not in w]
            for h in hosts:
                if not vault.HOST_RE.fullmatch(h):
                    raise CommandError(f"'{h}' is not a host name.")
            if owners and not vault.KINDS[a["kind"]]["owners"]:
                raise CommandError(f"{ref} is scoped by host only; give host names "
                                   "(with a dot).")
            _owners(owners)
            if sub == "allow":
                a["hosts"] = list(dict.fromkeys(a.get("hosts", []) + hosts))
                a["owners"] = list(dict.fromkeys(a.get("owners", []) + owners)) \
                    if vault.KINDS[a["kind"]]["owners"] else a.get("owners", [])
            else:
                a["hosts"] = [h for h in a.get("hosts", []) if h not in hosts]
                if "owners" in a:
                    a["owners"] = [o for o in a["owners"] if o not in owners]
            vault.save(data)
            return f"Updated {_describe_account(ref, a, data)}."
        if sub == "import":
            if len(parts) != 2:
                raise CommandError("Usage: /gate:account import KIND:NAME SECRET_NAME")
            ref = _acct_ref(parts[0], data)
            name = _name(parts[1])
            if "token" not in vault.KINDS[accounts[ref]["kind"]]["secrets"]:
                raise CommandError(f"{ref} can't hold a token.")
            sec = data["secrets"].get(name)
            if not sec:
                raise CommandError(f"No secret named {name}.")
            accounts[ref].setdefault("secrets", {})["token"] = sec["value"]
            accounts[ref]["updated"] = vault.now()
            vault.save(data)
            return (f"{ref} now uses the value of {name} as its token. The secret {name} "
                    f"is still there; remove it with /gate:secret del {name} if you no "
                    f"longer need it.\n{_describe_account(ref, accounts[ref], data)}")
        if sub == "forget":
            if len(parts) != 2 or parts[1] not in vault.SECRET_FIELDS:
                raise CommandError("Usage: /gate:account forget KIND:NAME token|ssh_key")
            ref = _acct_ref(parts[0], data)
            a = accounts[ref]
            if a.get("secrets", {}).pop(parts[1], None) is None:
                raise CommandError(f"{ref} has no {parts[1]}.")
            if parts[1] == "ssh_key":
                a.pop("public_key", None)
                a.pop("key_fingerprint", None)
            vault.save(data)
            return f"Removed the {parts[1]} of {ref}.\n{_describe_account(ref, a, data)}"
        if sub in ("del", "delete", "rm"):
            ref = _acct_ref(tail.strip(), data)
            accounts.pop(ref)
            vault.save(data)
            return f"Deleted the account {ref}."
    raise CommandError(f"Unknown command '{sub}'.\n{ACCOUNT_HELP}")


# ---------------------------------------------------------------------------
# Hook glue
# ---------------------------------------------------------------------------


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


def handle(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Hook output for a /secret or /sudo prompt, or None for other prompts."""
    prompt = payload.get("prompt") or ""
    m = PREFIX.match(prompt)
    if not m:
        return None
    kind, rest = m.group(1), m.group(2)
    session_id = payload.get("session_id") or ""
    _CURRENT["args"] = f"{kind} {' '.join(rest.split())}".strip()
    try:
        result = (run_secret(rest) if kind == "secret" else run_sudo(rest, session_id)
                  if kind == "sudo" else run_account(rest))
        outcome = "cancelled" if result.startswith("Cancelled") else "ok"
    except LooksLikeValue as e:
        _spawn_scrubber(payload.get("transcript_path", ""), e.typed)
        policy.audit(f"vault_{kind}", _log_detail(kind, rest, "blocked: looked like a typed value"))
        return block(f"gateway: {e}")
    except CommandError as e:
        result, outcome = f"Error: {e}", "error"
    except Exception as e:  # report, but never let a typed value through
        _spawn_scrubber(payload.get("transcript_path", ""),
                        [w for w in rest.split()[1:] if len(w) >= 4])
        policy.audit(f"vault_{kind}", _log_detail(kind, rest, f"failed: {type(e).__name__}"))
        return block(f"gateway: could not process the command "
                     f"({type(e).__name__}: {e}); nothing was saved.")
    policy.audit(f"vault_{kind}", _log_detail(kind, rest, outcome))
    return passthrough(result)


def _log_detail(kind: str, rest: str, outcome: str) -> dict[str, Any]:
    """What to record for a command: subcommand and target, never values.
    Words that look like values are left out even if they fit a name."""
    words = rest.split()
    sub = words[0].lower() if words else "help"
    safe = [w for w in words[1:4] if not _TOKEN_LIKE.match(w)]
    target = ""
    if kind == "secret" and safe and vault.NAME_RE.fullmatch(safe[0]):
        target = safe[0]
        if sub in ("allow", "disallow"):
            hosts = [h for h in words[2:] if vault.HOST_RE.fullmatch(h)
                     and not _TOKEN_LIKE.match(h)]
            target += " -> " + ", ".join(hosts)
    elif kind == "account":
        if safe and (vault.parse_account_ref(safe[0]) or safe[0] == "*"):
            target = safe[0]
        elif sub == "add" and len(safe) >= 2 and safe[0].lower() in vault.KINDS \
                and vault.ACCOUNT_RE.fullmatch(f"{safe[0].lower()}:{safe[1].lower()}"):
            target = f"{safe[0].lower()}:{safe[1].lower()}"
        if target and sub in ("allow", "disallow"):
            scope = [w for w in words[2:] if vault.OWNER_RE.fullmatch(w)
                     and not _TOKEN_LIKE.match(w)]
            target += " -> " + ", ".join(scope)
    elif kind == "sudo":
        if sub in ("add", "up", "update", "del", "delete", "rm") and len(safe) >= 2 \
                and vault.USER_RE.fullmatch(safe[0]) and vault.HOST_RE.fullmatch(safe[1]):
            target = f"{safe[0]}@{vault.norm_host(safe[1])}"
        elif sub in ("enable", "disable") and safe and vault.HOST_RE.fullmatch(safe[0]):
            target = vault.norm_host(safe[0]) + (" (always)" if "always" in words[2:3] else "")
    return {"command": f"{kind} {sub}", "target": target, "outcome": outcome}


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


MARKERS = (b"/secret", b"/sudo", b"/account", b"gate:secret", b"gate:sudo",
           b"gate:account")


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
