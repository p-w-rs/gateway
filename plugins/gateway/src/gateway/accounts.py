"""Accounts: where each kind's credential may go, ssh endpoints, owner
extraction and the one account-selection algorithm (SPEC 2 Kinds, 9.6).

Selection (used by every stand-in, the git helper and the http tool):
1. GATE_ACCOUNT=NAME (or an alias): must be the right kind, `use = true`, and
   the destination must be one of its destinations (and in its vault `bound`
   set when the vault is given); owners never restrict an explicit choice.
2. Otherwise the target owner picks: accounts of that kind for that host with
   `use = true` whose login or owners include it; else the one marked
   `default = true`; else, if exactly one account of that kind+host exists
   and it lists no `owners` (or no owner is named), that one: an account
   that lists `owners` covers only those and its login (owner_covered).
3. Exactly one -> use it. Several -> "both X and Y fit; set GATE_ACCOUNT=Y".
   None -> run without a credential: "no account for host/owner".
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from typing import Any, Container, Iterable, Mapping
from urllib.parse import urlsplit

from . import form as formmod

STORAGE_SERVICES = ("blob", "dfs", "file", "queue", "table")
FIXED_AZURE = ("management.azure.com", "graph.microsoft.com")


def _host_only(hostport: str) -> str:
    """'h:443' -> 'h'; '[::1]:22' -> '::1'."""
    if hostport.startswith("["):
        return hostport[1:].split("]", 1)[0]
    return hostport.rsplit(":", 1)[0] if hostport.count(":") == 1 else hostport


def destinations(a: formmod.Account) -> list[str]:
    """Hosts (or '.domain' patterns for api-key sites) the account's
    credential may be sent to, computed from the form. Account `host` values
    keep an explicit :port (what git and the http tool see)."""
    k = a.kind
    out: list[str] = []
    if k == "github":
        h = a.host or "github.com"
        out.append(h)
        bare = _host_only(h)
        if bare == "github.com" or bare.endswith(".ghe.com"):
            out.append(f"api.{bare}")
        if a.packages:
            out.append("ghcr.io")
    elif k == "huggingface":
        out += ["huggingface.co", "hf.co"]
    elif k == "azure":
        out += list(FIXED_AZURE)
        out += a.databricks
        out += [f"{s}.{svc}.core.windows.net" for s in a.storage for svc in STORAGE_SERVICES]
        out += a.registries
        out += a.sites
    elif k in ("ml-catalog", "pijul", "registry"):
        if a.host:
            out.append(a.host)
    elif k == "api-key":
        out += a.sites
    return list(dict.fromkeys(out))


# ---------------------------------------------------------------------------
# Entra credentials (azure, ml-catalog): which one fits the account
# ---------------------------------------------------------------------------

ARM_SCOPE = "https://management.azure.com/.default"


def browser_sign_in(a: Any) -> bool:
    """Does the account sign in through the browser (PLAN-0.11 §7)? An
    ml-catalog account always, an azure one with sign_in = "browser"."""
    return a.kind == "ml-catalog" or (a.kind == "azure" and a.sign_in == "browser")


def request_scope(a: Any) -> str:
    """The browser sign-in's request scope for an azure account (PLAN-0.11
    §7.4): its `scope` (ARM's .default when unset), with offline_access added
    (a refresh token). It shapes only the authorization request: each later
    token's audience is chosen by host (entra.scope_for_host)."""
    toks = [t for t in (getattr(a, "scope", "") or ARM_SCOPE).split() if t != "offline_access"]
    return " ".join(dict.fromkeys(toks + ["offline_access"]))


def entra_stored(info: Mapping[str, Any]) -> bool:
    """Is any Entra credential stored (vault.entra_info: no value)?"""
    return bool(info.get("refresh") or info.get("secret"))


def entra_fits(a: Any, info: Mapping[str, Any]) -> bool:
    """Is the stored Entra credential (vault.entra_info) one the account's
    settings `a` use: a browser sign-in made for its tenant, client and
    scope (a catalog's: its tenant, with the API scope pinned), or a service
    principal's secret or certificate for its tenant and client? Anything
    else (an older gateway's refresh token, a sign-in for settings that
    changed since) needs a new sign-in. The status lines and gate check
    decide with this one rule."""
    if a.kind not in ("azure", "ml-catalog"):
        return False
    if browser_sign_in(a):
        if not info.get("refresh") or info.get("kind") != "browser":
            return False
        if a.kind == "ml-catalog":
            return (info.get("tenant_id") == (a.tenant or formmod.CATALOG_TENANT)
                    and bool(info.get("pinned")))
        return (info.get("tenant_id") == a.tenant and info.get("client_id") == a.client_id
                and info.get("scope") == request_scope(a))
    return (bool(info.get("secret")) and info.get("tenant_id") == a.tenant
            and info.get("client_id") == a.client_id)


def destination_matches(pattern: str, host: str) -> bool:
    """'api.x.com' matches exactly; '.x.com' matches any subdomain of x.com
    (not x.com itself). Comparison ignores case; a pattern with :port must
    match the port too, a bare pattern matches the host on any port."""
    host = host.lower().rstrip(".")
    pattern = pattern.lower()
    if pattern.startswith("."):
        return _host_only(host).endswith(pattern) and len(_host_only(host)) > len(pattern)
    if ":" in pattern and not pattern.startswith("[") and pattern.count(":") == 1:
        return host == pattern
    return host == pattern or _host_only(host) == pattern


def covers(dests: Iterable[str], host: str) -> bool:
    return any(destination_matches(d, host) for d in dests)


def ssh_endpoints(a: formmod.Account) -> list[tuple[str, str]]:
    """(user, host) pairs git/ssh use to reach the account over ssh."""
    if a.kind == "github":
        h = _host_only(a.host or "github.com")
        out = [("git", h)]
        if h == "github.com":
            out.append(("git", "ssh.github.com"))
        return out
    if a.kind == "huggingface":
        return [("git", "hf.co")]  # huggingface.co has no ssh
    if a.kind == "pijul":
        return [(a.login or "", _host_only(a.host or "nest.pijul.com"))]
    return []


def endpoint_accounts(user: str, host: str, form: formmod.Form) -> list[formmod.Account]:
    """Accounts whose ssh endpoint is user@host (pijul: any user)."""
    host = host.lower()
    out = []
    for a in form.accounts.values():
        for u, h in a.ssh_endpoints():
            if h == host and (u == user or (a.kind == "pijul" and (not u or u == user))):
                out.append(a)
                break
    return out


def is_ssh_endpoint(host: str, form: formmod.Form) -> bool:
    host = host.lower()
    return any(h == host for a in form.accounts.values() for _u, h in a.ssh_endpoints())


def kinds_for_host(host: str, form: formmod.Form) -> list[str]:
    return sorted({a.kind for a in form.accounts.values() if covers(destinations(a), host)})


# ---------------------------------------------------------------------------
# Owners
# ---------------------------------------------------------------------------

_OWNER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,99}")
HF_PREFIXES = ("datasets", "spaces", "models")


def owner_from_path(path: str, kind: str = "github") -> str | None:
    """'owner/repo(.git)' (leading '/' or '~' ok) -> owner. For huggingface,
    'datasets/owner/name' and 'spaces/owner/name' too."""
    if not path:
        return None
    p = path.strip().strip("'\"").lstrip("/").lstrip("~")
    parts = [x for x in p.split("/") if x]
    if kind == "huggingface" and parts and parts[0] in HF_PREFIXES:
        parts = parts[1:]
    if not parts:
        return None
    owner = parts[0]
    if len(parts) == 1 and kind != "pijul":
        return None
    return owner if _OWNER.fullmatch(owner) else None


def owner_covered(owner: str | None, names: Iterable[str], *, default: bool, any_owner: bool,
                  only: bool) -> bool:
    """Does an account route for `owner` (the one rule gitroute, the account
    CLIs' destination, the hook and select share): an owner the destination
    doesn't name (any account's), its login or one of its `owners`, the
    default account; and the only account of its kind for that host only
    when it lists no `owners` (any_owner): one that lists them covers only
    those and its own login, so another owner's repository is the user's
    own, never sent with a work account's key."""
    if not owner:
        return True
    if owner.lower() in (n.lower() for n in names if n) or default:
        return True
    return only and any_owner


def owner_from_url(url: str, kind: str = "github") -> tuple[str, str | None] | None:
    """(host, owner) from https://host/owner/repo, ssh://git@host[:port]/owner/repo
    or the scp form git@host:owner/repo. None if it isn't a URL."""
    u = url.strip()
    m = re.fullmatch(r"(?:([A-Za-z0-9._-]+)@)?([A-Za-z0-9.-]+):(?!//)(.+)", u)
    if m and "://" not in u:
        host, path = m.group(2).lower(), m.group(3)
        return host, owner_from_path(path, kind)
    try:
        s = urlsplit(u)
        if s.scheme not in ("http", "https", "ssh", "git+ssh", "ssh+git") or not s.hostname:
            return None
        port = s.port          # raises ValueError for an invalid or out-of-range port
    except ValueError:
        return None
    host = s.hostname.lower()
    if port and s.scheme in ("http", "https") and port not in (80, 443):
        host = f"{host}:{port}"
    return host, owner_from_path(s.path, kind)


def owner_from_git_command(cmd: str) -> tuple[str, str | None] | None:
    """('git-upload-pack', owner) from the command git runs over ssh:
    git-upload-pack 'owner/repo.git', git-receive-pack '/owner/repo',
    git-lfs-authenticate owner/repo download."""
    try:
        words = shlex.split(cmd)
    except ValueError:
        return None
    if len(words) < 2 or not words[0].startswith(("git-upload-pack", "git-receive-pack",
                                                   "git-upload-archive", "git-lfs-authenticate",
                                                   "git-lfs-transfer")):
        return None
    return words[0], owner_from_path(words[1])


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------


@dataclass
class Selection:
    account: formmod.Account | None = None
    explicit: bool = False            # chosen with GATE_ACCOUNT
    reason: str = ""                  # "owner", "default", "only", "GATE_ACCOUNT"
    candidates: list[str] = field(default_factory=list)
    error: str | None = None          # refuse with this (gateway: ...)
    note: str | None = None           # run without a credential and print this

    @property
    def name(self) -> str | None:
        return self.account.name if self.account else None


def resolve_name(name: str, aliases: Mapping[str, str] | None = None,
                 form: formmod.Form | None = None) -> str:
    """An entry name, following vault aliases (github:work -> github-work). A
    name that is itself an entry in the form (valid or disabled) is never
    redirected by an alias."""
    if form is not None and (name in form.hosts or name in form.accounts or name in form.disabled):
        return name
    if aliases and name in aliases:
        return aliases[name]
    return name


def _select(kind: str | Iterable[str], host: str, owner: str | None, form: formmod.Form, *,
           effective: Any, vault: Mapping[str, Any] | None = None,
           env: Mapping[str, str] | None = None, mode: str | None = None,
           asked: Container[str] = ()) -> Selection:
    """The account to use for (kind, destination host, owner). `kind` may be a
    tuple of kinds. `effective` (consent.compute(form, vault_data, mode)) is
    required: only approved destinations, approved `use` and bound credentials
    count (never the raw form); a `use` of "ask" in `mode` counts for an
    account in `asked` (the approval hook asked about the command: the gated
    git's). `vault` (the vault dict) adds aliases and the `bound` check for
    GATE_ACCOUNT; an account without a vault record has an empty bound set."""
    kinds = (kind,) if isinstance(kind, str) else tuple(kind)
    env = os.environ if env is None else env
    aliases = (vault or {}).get("aliases") or {}
    label = f"{host}/{owner}" if owner else host

    def dests(a: formmod.Account) -> list[str]:
        ea = effective.accounts.get(a.name)
        return list(ea.destinations) if ea is not None else []

    def use_word(a: formmod.Account) -> str:
        try:
            return str(effective.word(a.name, "use", mode))
        except (AttributeError, KeyError):
            return "deny"

    def usable(a: formmod.Account) -> bool:
        ea = effective.accounts.get(a.name)
        if ea is None:
            return False
        return bool(ea.use) or (a.name in asked and use_word(a) == "ask")

    def ask_note(a: formmod.Account) -> str:
        return ("has use = \"ask\": only a git or account-CLI command that Claude runs as its "
                "own command (not inside a script, a hook or sh -c), which Claude Code asks you "
                "about first, may use it")

    explicit = (env.get("GATE_ACCOUNT") or "").strip()
    if explicit:
        name = resolve_name(explicit, aliases, form)
        a = form.accounts.get(name)
        shown = formmod.safe(explicit) or "that name"
        if a is None:
            why = ("is disabled (see gate status)" if form.is_disabled(name, "accounts")
                   else "isn't an account in gateway.toml")
            return Selection(error=f"gateway: GATE_ACCOUNT={shown} {why}")
        if a.kind not in kinds:
            return Selection(error=f"gateway: GATE_ACCOUNT={a.name} is a {a.kind} account; "
                                   f"this needs {' or '.join(kinds)}")
        if not usable(a):
            if use_word(a) == "ask":
                return Selection(error=f"gateway: {a.name} {ask_note(a)}")
            return Selection(error=f"gateway: {a.name} has use = false (or is waiting for the "
                                   f"user's OK); see gate status {a.name}")
        if not covers(dests(a), host):
            return Selection(error=f"gateway: {a.name} may not be used for {host} "
                                   f"(not one of its destinations in gateway.toml)")
        if vault is not None:
            rec = (vault.get("accounts") or {}).get(a.name) or {}
            bound = (rec.get("bound") or {}).get("hosts") or []
            if not covers(bound, host):
                return Selection(error=f"gateway: {a.name}'s credential isn't bound to {host}; "
                                       f"run gate check {a.name} while the user is here")
        return Selection(account=a, explicit=True, reason="GATE_ACCOUNT", candidates=[a.name])

    # Usable accounts (approved destinations, approved `use`, bound credential)
    # versus every account of this kind whose form destinations cover the host.
    pool = [a for a in form.accounts.values() if a.kind in kinds and covers(dests(a), host)]
    live = [a for a in pool if usable(a)]
    in_form = [a for a in form.accounts.values()
               if a.kind in kinds and covers(destinations(a), host)]
    blocked = [a for a in in_form if a not in live]

    def why(a: formmod.Account) -> str:
        ea = effective.accounts.get(a.name)
        if ea is not None and not ea.new and use_word(a) == "ask":
            return ask_note(a)
        if not a.use or (ea is not None and not ea.use and not ea.new and not ea.pending):
            return (f"has use = false (gateway.toml); ask the user if it should be used, or "
                    f"pick another account with GATE_ACCOUNT=NAME")
        return f"can't be used yet (it waits for the user's OK); run gate check {a.name} while " \
               "the user is here"

    cands: list[formmod.Account] = []
    reason = ""
    if owner:
        o = owner.lower()
        cands = [a for a in live if o in (x.lower() for x in a.owner_names())]
        reason = "owner"
        # An owner-matched account that isn't usable yet (waiting for the
        # user's OK, credential not bound, use = false) owns these repos: they
        # never fall back to the default or the only other account.
        held = [a for a in blocked if o in (x.lower() for x in a.owner_names())]
        if held:
            shown = formmod.safe(owner) or "that owner"
            if cands:
                both = " and ".join(sorted({a.name for a in cands + held}))
                return Selection(candidates=[a.name for a in cands + held],
                                 error=f"gateway: {both} are the accounts for {shown}, but "
                                       f"{held[0].name} {why(held[0])}; or set "
                                       f"GATE_ACCOUNT={cands[0].name}")
            return Selection(candidates=[held[0].name],
                             error=f"gateway: {held[0].name} is the account for {shown} but "
                                   f"{why(held[0])}")
    if not cands:
        cands = [a for a in live if a.default]
        reason = "default"
        held = [a for a in blocked if a.default]
        if not cands and held:
            return Selection(candidates=[held[0].name],
                             error=f"gateway: {held[0].name} is the default account for {host} "
                                   f"but {why(held[0])}")
    # SPEC 9.6: "if exactly one account of that kind+host exists" (in the
    # form, approved or not): a pending second account isn't "no other".
    # It covers an owner it doesn't list only when it lists no owners at
    # all (owner_covered; gitroute and the hook say the same).
    if not cands and len(in_form) == 1 and live and owner_covered(
            owner, in_form[0].owner_names(), default=False, any_owner=not in_form[0].owners,
            only=True):
        cands = live
        reason = "only"
    names = [a.name for a in cands]
    if len(cands) == 1:
        return Selection(account=cands[0], reason=reason, candidates=names)
    if len(cands) > 1:
        both = " and ".join(names) if len(names) == 2 else ", ".join(names)
        word = "both" if len(names) == 2 else "all of"
        return Selection(candidates=names,
                         error=f"gateway: {word} {both} fit; set GATE_ACCOUNT={names[-1]}")
    if live:
        # Accounts of this kind and host exist, but none is chosen for this
        # owner (round 3: "no account" sent Claude to ask for a new one).
        have = [a.name for a in live]
        shown = (" and ".join(have) if len(have) == 2 else ", ".join(have[:5]))
        who = formmod.safe(owner) if owner else None
        neither = "neither" if len(have) == 2 else ("it doesn't" if len(have) == 1 else "none")
        why = (f"{neither} lists {who} or is the default" if who else f"{neither} is the default")
        if len(have) == 1:
            why = (f"it doesn't list {who} and isn't the default" if who
                   else "it isn't the default")
        return Selection(candidates=have,
                         note=f"gateway: no account is chosen for {label} ({shown} "
                              f"{'exist' if len(have) > 1 else 'exists'}; {why}); set "
                              "GATE_ACCOUNT=NAME, or ask the user to add default = true or "
                              "owners in gateway.toml")
    return Selection(note=f"gateway: no account for {label}")


GIT_ACCOUNT_HOSTS = {"github.com": "github", "ssh.github.com": "github", "hf.co": "huggingface",
                     "huggingface.co": "huggingface", "nest.pijul.com": "pijul"}


def stale_token_message(name: str) -> str:
    """A saved token was rejected earlier (marked stale, never retried): the
    true next step. No pop-up opens by itself for a token; gate check asks for
    a new one (review round 4: the old text claimed an open pop-up)."""
    return (f"gateway: {name}'s token was rejected; don't retry. Run gate check {name} while the "
            "user is here to enter a new one")


def no_git_account(host: str) -> str:
    """No account for a git server: for one an account kind serves, ask for
    the account; otherwise say what does exist (review round 2: "ask the user
    to add one" sent Claude after a GitLab account no kind provides)."""
    shown = formmod.safe(host) or "that server"
    kind = GIT_ACCOUNT_HOSTS.get(str(host).lower())
    if kind:
        return f"gateway: no account for {shown}; ask the user to add one (gateway.toml, kind {kind})"
    return (f"gateway: no account for {shown}. The gateway has accounts for GitHub (also GitHub "
            "Enterprise: kind github with host), Hugging Face and Pijul; another git server, "
            "left out of gateway.toml, is reached with the user's own ssh and git")


def select(kind: str | tuple[str, ...], host: str, owner: str | None, form: formmod.Form,
           *, effective: Any, vault: dict[str, Any] | None = None,
           env: Any = None, mode: str | None = None, asked: Container[str] = ()) -> "Selection":
    """_select (above), then the chosen account's credential policy
    (PLAN-v4 phase 7: [accounts.NAME.policy] credential and [policy]
    credential) in `mode` (None: the modeless rule): only "allow" hands its
    credential to the git helper, the CLI stand-ins and git over ssh, and
    "ask" too for an account in `asked` (the gated git's command, which the
    approval hook asked about: githelper.gated_parent; its `use` too); the
    refusal names the rule."""
    sel = _select(kind, host, owner, form, effective=effective, vault=vault, env=env, mode=mode,
                  asked=asked)
    if sel.account is not None and sel.error is None:
        from . import policy
        d = policy.decide(effective, "credential", account=sel.account.name, mode=mode)
        if d.word is not True and not (sel.account.name in asked and d.word == "ask"):
            return Selection(candidates=list(sel.candidates or []),
                             error=d.message(f"using {sel.account.name}'s credential"))
    return sel
