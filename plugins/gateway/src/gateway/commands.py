"""The /gate:secret and /gate:sudo chat commands.

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

from . import policy, vault, web_form

PREFIX = re.compile(r"^\s*/(?:gate:)?(secret|sudo)(?=\s|$)(.*)$", re.S)

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
        result = run_secret(rest) if kind == "secret" else run_sudo(rest, session_id)
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


MARKERS = (b"/secret", b"/sudo", b"gate:secret", b"gate:sudo")


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
