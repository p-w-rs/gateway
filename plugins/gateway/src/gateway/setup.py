"""Short commands and guided setup (v2).

You type a short command; Claude guides the rest; a native dialog is the only
place a secret is typed or a change is approved.

    /gate:add secret|sudo|account|ssh|github|hf|...   start a guided setup
    /gate:update NAME                                  change something (guided)
    /gate:delete NAME                                  delete it (now)
    /gate:enable [sudo] HOST [always]                  root commands without asking
    /gate:disable [sudo] HOST                          every root command asks again
    /gate:list                                         what the gateway holds
    /gate:export / /gate:import                        (phase 5)

How the guided part stays safe: a typed /gate:add or /gate:update opens a
**setup grant**. It is stored inside the encrypted vault, so Claude's Bash
can't forge one. It is for this session only, for that one kind of change,
expires in 15 minutes, and can be used once. Claude asks the questions (in
Claude Code's question pop-ups), then calls the gate_setup tool with the
grant and a proposal. The gateway checks the grant and shows the proposal in
a native dialog. A secret is typed there (hidden), or the provider's sign-in
page opens. Only then is anything saved. Without a display, the gateway
keeps the proposal with the grant and the person finishes it in a terminal
(`gateway finish GRANT`).
"""
from __future__ import annotations

import os
import re
import secrets as _rand
import time
from pathlib import Path
from typing import Any

from . import commands, dialog, policy, vault

GRANT_TTL = 15 * 60
PREFIX = re.compile(r"^\s*/gate:(add|update|delete|enable|disable|list|export|import)(?=\s|$)(.*)$",
                    re.S)
WHATS = ("secret", "sudo", "account")
ACCOUNT_WORDS = {"ssh": "ssh", "github": "github", "gh": "github", "huggingface": "hf",
                 "hf": "hf", "pijul": "pijul", "nest": "pijul", "azure": "azure",
                 "databricks": "azure", "catalog": "mlcat", "mlcat": "mlcat",
                 "registry": "registry", "docker": "registry", "ghcr": "registry"}

HELP = (
    "/gate:add secret|sudo|account|ssh   add something; Claude asks a few questions, and a\n"
    "                                    dialog asks for any password or token\n"
    "/gate:update NAME                   change it (e.g. /gate:update github:work)\n"
    "/gate:delete NAME                   delete a secret, an account or USER@HOST sudo\n"
    "/gate:enable sudo HOST [always]     root commands there run without asking\n"
    "                                    (this session, or always)\n"
    "/gate:disable sudo HOST             every root command there asks again\n"
    "/gate:list                          what the gateway holds (never values)"
)


class SetupError(Exception):
    pass


def is_command(prompt: str) -> bool:
    return bool(PREFIX.match(prompt or ""))


def terminal_command(args: str) -> str:
    return f"pixi run --manifest-path {policy.plugin_root() / 'pixi.toml'} gateway {args}"


# ---------------------------------------------------------------------------
# Grants
# ---------------------------------------------------------------------------


def _prune(data: dict[str, Any]) -> None:
    now = time.time()
    data["grants"] = {g: v for g, v in data.get("grants", {}).items()
                      if v.get("expires", 0) > now and not v.get("used")}


def open_grant(op: str, what: str, target: str, session_id: str) -> str:
    gid = "g-" + _rand.token_hex(4)
    with vault.locked():
        data = vault.load()
        _prune(data)
        data["grants"][gid] = {"op": op, "what": what, "target": target,
                               "session": session_id, "expires": time.time() + GRANT_TTL,
                               "used": False, "pending": None}
        vault.save(data)
    return gid


def _grant(data: dict[str, Any], gid: str, session_id: str | None) -> dict[str, Any]:
    g = data.get("grants", {}).get(gid or "")
    if not g or g.get("used") or g.get("expires", 0) <= time.time():
        raise SetupError("no open setup for that id: ask the user to type the /gate: command "
                         "again (setups last 15 minutes and are used once)")
    if session_id is not None and g.get("session") and g["session"] != session_id:
        raise SetupError("that setup was opened in another session")
    return g


# ---------------------------------------------------------------------------
# The typed commands (UserPromptSubmit hook)
# ---------------------------------------------------------------------------


def _what(word: str) -> tuple[str, str]:
    """(what, account kind) for the word after /gate:add."""
    w = word.lower()
    if w in WHATS:
        return w, ""
    if w in ACCOUNT_WORDS:
        return "account", ACCOUNT_WORDS[w]
    if w in vault.KINDS:
        return "account", w
    return "", ""


def _guided(gid: str, op: str, what: str, kind: str, target: str, extra: str) -> str:
    bits = [f"Setup {gid} is open for: {op} {what}"
            + (f" (kind {kind})" if kind else "") + (f" {target}" if target else "") + "."]
    if extra.strip():
        bits.append(f"The user also said: {extra.strip()!r}.")
    bits.append("Load the gate:setup skill and follow it: ask the user the few questions "
                "it lists with your question pop-ups (AskUserQuestion), in plain words, then "
                f"call the gate_setup tool with grant=\"{gid}\" and the proposal. A native "
                "dialog then shows the user the change and asks for any secret; never ask "
                "for a password, token or key in the chat.")
    return " ".join(bits)


def _list(session_id: str) -> str:
    out = []
    for fn, arg in ((commands.run_secret, "list"), (commands.run_account, "list")):
        out.append(fn(arg))
    out.append(commands.run_sudo("list", session_id))
    return "\n\n".join(out)


def _delete(words: list[str], session_id: str) -> str:
    if not words:
        raise commands.CommandError("Say what to delete, e.g. /gate:delete github:work, "
                                    "/gate:delete OPENCODE_API_KEY or /gate:delete joshua@powerslabs.")
    if words[0].lower() in ("secret", "account", "sudo"):
        words = words[1:]
    target = " ".join(words)
    if vault.parse_account_ref(target.lower()):
        return commands.run_account(f"del {target.lower()}")
    if "@" in target and len(words) == 1:
        user, host = target.split("@", 1)
        return commands.run_sudo(f"del {user} {host}", session_id)
    if len(words) == 2 and vault.load()["sudo"].get(f"{words[0]}@{vault.norm_host(words[1])}"):
        return commands.run_sudo(f"del {words[0]} {words[1]}", session_id)
    return commands.run_secret(f"del {target}")


def run(verb: str, rest: str, session_id: str) -> str:
    words = rest.split()
    commands._guard_text(words)
    if verb == "list":
        return _list(session_id)
    if verb in ("export", "import"):
        return f"/gate:{verb} is coming in a later version of the gateway."
    if verb in ("enable", "disable"):
        if words and words[0].lower() == "sudo":
            words = words[1:]
        if not words:
            return HELP
        return commands.run_sudo(f"{verb} {' '.join(words)}", session_id)
    if verb == "delete":
        return _delete(words, session_id)
    if verb == "add":
        what, kind = _what(words[0]) if words else ("", "")
        extra = " ".join(words[1:])
        if not what:
            gid = open_grant("add", "", "", session_id)
            return (f"Setup {gid} is open for: add (the user didn't say what). Ask them with a "
                    "question pop-up whether it's an account (GitHub, Hugging Face, a server "
                    "over SSH, Azure, the ML Catalog, a container registry, Pijul), a secret "
                    "(an API key or token for a web service) or sudo (a root password for a "
                    "machine), then follow the gate:setup skill with grant=\"" + gid + "\".")
        gid = open_grant("add", what, kind, session_id)
        return _guided(gid, "add", what, kind, "", extra)
    if verb == "update":
        if not words:
            gid = open_grant("update", "", "", session_id)
            return _guided(gid, "update", "", "", "", "Ask which item to change (show "
                           "them the names from the session note).")
        target = words[0]
        data = vault.load()
        if vault.parse_account_ref(target.lower()) and target.lower() in data["accounts"]:
            what, target = "account", target.lower()
        elif target in data["secrets"]:
            what = "secret"
        elif target in data["sudo"]:
            what = "sudo"
        else:
            raise commands.CommandError(f"Nothing named {target}; see /gate:list.")
        gid = open_grant("update", what, target, session_id)
        return _guided(gid, "update", what, "", target, " ".join(words[1:]))
    raise commands.CommandError(HELP)


def handle(payload: dict[str, Any]) -> dict[str, Any] | None:
    prompt = payload.get("prompt") or ""
    m = PREFIX.match(prompt)
    if not m:
        return None
    verb, rest = m.group(1), m.group(2)
    try:
        result = run(verb, rest, payload.get("session_id") or "")
        outcome = "ok"
    except commands.LooksLikeValue as e:
        commands._spawn_scrubber(payload.get("transcript_path", ""), e.typed)
        policy.audit("gate_command", {"command": verb, "outcome": "blocked: looked like a value"})
        return commands.block(f"gateway: {e}")
    except (commands.CommandError, SetupError) as e:
        result, outcome = f"Error: {e}", "error"
    policy.audit("gate_command", {"command": verb, "target": " ".join(rest.split()[:2])[:80],
                                  "outcome": outcome})
    return commands.passthrough(result)


# ---------------------------------------------------------------------------
# gate_setup (MCP tool): check the grant, show the dialog, save
# ---------------------------------------------------------------------------


def _hosts(v: Any) -> list[str]:
    hosts = [str(h).strip().lower() for h in (v or []) if str(h).strip()]
    for h in hosts:
        if h == "*" or not vault.HOST_RE.fullmatch(h):
            raise SetupError(f"'{h}' is not a host name")
    return hosts


def _plan(g: dict[str, Any], p: dict[str, Any], data: dict[str, Any]) -> dict[str, Any]:
    """Validate a proposal against its grant; return a normalized plan with a
    plain-language summary. Raises SetupError so Claude can fix and retry."""
    op, what = g["op"], g["what"] or str(p.get("what", "")).lower()
    if g["what"] and p.get("what") and str(p["what"]).lower() != g["what"]:
        raise SetupError(f"this setup is for {g['what']}, not {p['what']}")
    if what not in WHATS:
        raise SetupError("say what this is: what = secret, sudo or account")
    plan: dict[str, Any] = {"op": op, "what": what, "lines": []}
    L = plan["lines"]
    if what == "secret":
        name = str(p.get("name") or g["target"] or "")
        try:
            commands._name(name)
        except commands.CommandError as e:
            raise SetupError(str(e))
        exists = name in data["secrets"]
        if op == "add" and exists:
            raise SetupError(f"a secret named {name} already exists; use /gate:update {name}")
        if op == "update" and not exists:
            raise SetupError(f"no secret named {name}")
        old = data["secrets"].get(name, {})
        desc = str(p.get("description") or old.get("description", "")).strip()
        if op == "add" and not desc:
            raise SetupError("add a short description of what the secret is for")
        hosts = _hosts(p["hosts"]) if "hosts" in p else list(old.get("hosts", []))
        new_value = op == "add" or bool(p.get("new_value"))
        plan.update(name=name, description=desc, hosts=hosts, ask_secret=new_value)
        L.append(f"{'Add' if op == 'add' else 'Change'} the secret “{name}”: {desc}.")
        L.append("It may be sent only to: " + (", ".join(hosts) or "nowhere yet") + ".")
        if new_value:
            L.append("You'll type its value next (hidden). Claude never sees it.")
        return plan
    if what == "sudo":
        target = g["target"]
        user, host = (target.split("@", 1) if target else
                      (str(p.get("user", "")), str(p.get("host", ""))))
        try:
            user, host = commands._sudo_target(user, host)
        except commands.CommandError as e:
            raise SetupError(str(e))
        key = f"{user}@{host}"
        if op == "add" and key in data["sudo"]:
            raise SetupError(f"{key} already has a password; use /gate:update {key}")
        plan.update(user=user, host=host, ask_secret=True)
        where = "this computer" if host == "localhost" else host
        L.append(f"Store the sudo (administrator) password of {user} on {where}.")
        L.append("Claude can then run commands as root there through the gateway; each one "
                 "still asks you unless you /gate:enable sudo " + host + ".")
        L.append("You'll type the password next (hidden). Claude never sees it.")
        return plan
    # account
    if op == "add":
        kind = str(p.get("kind") or g["target"] or "").lower()
        kind = ACCOUNT_WORDS.get(kind, kind)
        if kind not in vault.KINDS:
            raise SetupError(f"kind must be one of {', '.join(vault.KINDS)}")
        name = str(p.get("name", "")).lower()
        ref = f"{kind}:{name}"
        if not vault.parse_account_ref(ref):
            raise SetupError("name: a short lowercase name, e.g. work or personal")
        if ref in data["accounts"]:
            raise SetupError(f"{ref} already exists; use /gate:update {ref}")
        old = None
    else:
        ref = str(g["target"] or p.get("account", "")).lower()
        if ref not in data["accounts"]:
            raise SetupError(f"no account named {ref}")
        kind, old = data["accounts"][ref]["kind"], data["accounts"][ref]
    spec = vault.KINDS[kind]
    fields = dict(p.get("fields") or {})
    for f in fields:
        if f not in spec["fields"]:
            raise SetupError(f"{kind} accounts have no field {f!r} (fields: "
                             f"{', '.join(spec['fields'])})")
    got = {f: str(fields.get(f, (old or {}).get(f, spec["host"] if f == "host" else ""))
                  or "") for f in spec["fields"]}
    for f, v in got.items():
        try:
            commands._clean_setting(kind, f, v)
        except commands.CommandError as e:
            raise SetupError(str(e))
        if f in ("host", "tenant") and not v.strip():
            raise SetupError(f"{f} is required for {kind} accounts")
    if kind == "ssh" and not got.get("user"):
        raise SetupError("user is required for ssh accounts")
    if spec["owners"]:
        owners = p.get("owners")
        if owners is None:
            owners = (old or {}).get("owners", [])
        if isinstance(owners, str):
            owners = owners.replace(",", " ").split()
        try:
            commands._owners(list(owners))
        except commands.CommandError as e:
            raise SetupError(str(e))
        got["owners"] = " ".join(owners)
    desc = str(p.get("description") or (old or {}).get("description", "")).strip()
    if op == "add" and not desc:
        raise SetupError("add a short description, e.g. 'work GitHub (asirobots)'")
    cred = p.get("credentials") or {}
    token = cred.get("token")  # "ask" | None
    key = cred.get("ssh_key")  # "generate" | "file" | None
    browser = bool(cred.get("browser"))
    if token not in (None, "ask") or key not in (None, "generate", "file"):
        raise SetupError("credentials: token = 'ask', ssh_key = 'generate' or 'file', "
                         "browser = true/false")
    if token and "token" not in spec["secrets"]:
        raise SetupError(f"{kind} accounts don't use a token")
    if key and "ssh_key" not in spec["secrets"]:
        raise SetupError(f"{kind} accounts don't use an SSH key")
    if browser and kind not in ("github", "azure", "mlcat"):
        raise SetupError("browser sign-in is for GitHub, Azure and the ML Catalog")
    key_file = ""
    if key == "file":
        key_file = os.path.expanduser(str(cred.get("ssh_key_file", "")))
        if not key_file or not Path(key_file).is_file():
            raise SetupError("ssh_key_file: the path of an existing private key file "
                             "(the gateway reads it; Claude doesn't)")
    if kind == "registry" and got.get("via") and token:
        raise SetupError("a registry signs in either through another account (via) or "
                         "with its own token, not both")
    plan.update(ref=ref, kind=kind, got=got, description=desc, old=old,
                ask_secret=token == "ask", key=key, key_file=key_file, browser=browser)
    who = got.get("login") or got.get("user") or ""
    L.append(f"{'Add' if op == 'add' else 'Change'} the {spec['label']} account “{ref}”: {desc}."
             + (f" Login: {who}." if who else ""))
    if spec["owners"]:
        L.append("Used for: " + (", ".join(got["owners"].split()) or "anything") + " on "
                 + (got.get("host") or spec["host"]) + ".")
    elif got.get("host"):
        L.append(f"Host: {got['host']}" + (f", port {got['port']}" if got.get("port") else "") + ".")
    if browser:
        L.append("Sign-in: the provider's page opens in your browser.")
    if token:
        L.append("You'll type the token next (hidden). Claude never sees it.")
    if key == "generate":
        L.append("A new SSH key is made for it; you'll get its public half to add on the site.")
    if key == "file":
        L.append(f"Its SSH key is read from {key_file} (Claude never reads the file).")
    return plan


def _apply(plan: dict[str, Any], secret_value: str | None, session_id: str) -> str:
    what, op = plan["what"], plan["op"]
    if what == "secret":
        with vault.locked():
            data = vault.load()
            old = data["secrets"].get(plan["name"], {})
            data["secrets"][plan["name"]] = {
                "value": secret_value if plan["ask_secret"] else old.get("value", ""),
                "description": plan["description"], "hosts": plan["hosts"],
                "updated": vault.now()}
            vault.save(data)
            s = data["secrets"][plan["name"]]
        return (f"{'Stored' if op == 'add' else 'Updated'} {commands._describe(plan['name'], s)}.")
    if what == "sudo":
        key = f"{plan['user']}@{plan['host']}"
        with vault.locked():
            data = vault.load()
            data["sudo"][key] = {"user": plan["user"], "host": plan["host"],
                                 "password": secret_value, "updated": vault.now()}
            vault.save(data)
        return (f"Stored the sudo password for {key}. sudo there: "
                f"{vault.sudo_state(plan['host'], session_id)}.")
    got = dict(plan["got"])
    if plan["ask_secret"]:
        got["token"] = secret_value or ""
    got["ssh_key_mode"] = {"generate": "generate", "file": "paste"}.get(plan["key"] or "",
                                                                        "keep" if plan["old"] else "none")
    if plan["key"] == "file":
        got["ssh_key"] = Path(plan["key_file"]).read_text()
    try:
        rec, note = commands._apply_form(plan["ref"], plan["kind"], got, plan["old"])
    except commands.CommandError as e:
        raise SetupError(str(e))
    rec["description"] = plan["description"]
    with vault.locked():
        data = vault.load()
        if op == "add" and plan["ref"] in data["accounts"]:
            raise SetupError(f"{plan['ref']} already exists")
        data["accounts"][plan["ref"]] = rec
        vault.save(data)
        msg = f"{'Added' if op == 'add' else 'Updated'} {commands._describe_account(plan['ref'], rec, data)}."
    if note:
        msg += "\n" + note
    if plan["browser"]:
        try:
            msg += "\n" + commands.run_account(f"login {plan['ref']}")
        except commands.CommandError as e:
            msg += f"\nThe account is saved, but sign-in didn't finish: {e} Run /gate:update {plan['ref']} to try again."
    return msg


def _use(gid: str, pending: dict[str, Any] | None = None) -> None:
    with vault.locked():
        data = vault.load()
        g = data.get("grants", {}).get(gid)
        if g:
            if pending is None:
                g["used"] = True
            else:
                g["pending"] = pending
            vault.save(data)


def gate_setup(grant: str, proposal: dict[str, Any], session_id: str | None = None) -> dict[str, Any]:
    """The MCP tool. Never returns or logs a secret value."""
    if session_id is None:
        session_id = os.environ.get("CLAUDE_CODE_SESSION_ID", "")
    try:
        if not isinstance(proposal, dict):
            raise SetupError("proposal must be an object")
        data = vault.load()
        g = _grant(data, grant, session_id)
        plan = _plan(g, proposal, data)
    except SetupError as e:
        policy.audit("gate_setup", {"grant": str(grant)[:16], "outcome": f"refused: {e}"[:200]})
        return {"ok": False, "refused": True, "reason": str(e)}
    summary = "\n".join(plan["lines"])
    if not dialog.available():
        _use(grant, pending=proposal)
        policy.audit("gate_setup", {"grant": grant, "outcome": "needs terminal"})
        return {"ok": False, "needs_terminal": True, "summary": summary,
                "reason": ("There's no screen to show a dialog on here (e.g. over ssh). Ask the "
                           "user to finish it in a terminal on this machine:\n  "
                           + terminal_command(f"finish {grant}"))}
    try:
        if not dialog.confirm(summary + "\n\nAllow?"):
            policy.audit("gate_setup", {"grant": grant, "outcome": "declined in the dialog"})
            return {"ok": False, "declined": True,
                    "reason": "The user chose Cancel in the dialog; nothing was saved. Ask what "
                              "to change, and call gate_setup again with the same grant."}
        value = None
        if plan.get("ask_secret"):
            label = {"secret": f"the value of “{plan.get('name')}”",
                     "sudo": f"the password of {plan.get('user')} on {plan.get('host')}"}.get(
                plan["what"], f"the token for “{plan.get('ref')}”")
            value = dialog.secret(f"Type {label}.\nIt goes straight into the gateway's vault.")
            if value is None or (plan["what"] != "secret" and not value):
                return {"ok": False, "declined": True,
                        "reason": "No value was entered; nothing was saved."}
        result = _apply(plan, value, session_id)
    except dialog.Unavailable:
        _use(grant, pending=proposal)
        return {"ok": False, "needs_terminal": True, "summary": summary,
                "reason": "The dialog couldn't open. Ask the user to finish in a terminal:\n  "
                          + terminal_command(f"finish {grant}")}
    except SetupError as e:
        return {"ok": False, "refused": True, "reason": str(e)}
    _use(grant)
    policy.audit("gate_setup", {"grant": grant, "what": plan["what"], "op": plan["op"],
                                "target": plan.get("ref") or plan.get("name")
                                or f"{plan.get('user')}@{plan.get('host')}", "outcome": "ok"})
    return {"ok": True, "result": result}


def finish(gid: str, ask_confirm, ask_secret) -> str:
    """Terminal fallback: finish a setup Claude prepared where no dialog could
    open. The callables read the answers at the terminal (hidden for secrets)."""
    data = vault.load()
    g = _grant(data, gid, None)
    if not g.get("pending"):
        raise SetupError(f"setup {gid} has nothing to finish yet")
    plan = _plan(g, g["pending"], data)
    if not ask_confirm("\n".join(plan["lines"])):
        return "Cancelled; nothing was saved."
    value = None
    if plan.get("ask_secret"):
        value = ask_secret("Value (hidden)")
        if value is None or (plan["what"] != "secret" and not value):
            return "No value entered; nothing was saved."
    result = _apply(plan, value, g.get("session", ""))
    _use(gid)
    return result
