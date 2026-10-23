"""Account selection (SPEC 9.6), destinations, endpoints and owner helpers."""
from __future__ import annotations

from pathlib import Path

import ast

import harness as H  # noqa: F401  (guard)
from gateway import accounts as A
from gateway import consent
from gateway import form as F


def approved_data(form: F.Form, aliases: dict | None = None) -> dict:
    """A vault dict in which every entry of `form` is approved and bound."""
    return {"approved": {"rights": consent.snapshot(form)}, "aliases": aliases or {},
            "accounts": {n: {"kind": a.kind, "bound": {"hosts": a.destinations()}}
                         for n, a in form.accounts.items()}}


def sel(kind, host, owner, form, env=None, aliases=None):
    data = approved_data(form, aliases)
    return A.select(kind, host, owner, form, effective=consent.compute(form, data), vault=data,
                    env=env or {})

FORM = F.parse_text('''
[accounts.github-personal]
kind = "github"
login = "octocat"
default = true
[accounts.github-work]
kind = "github"
login = "octo-work"
owners = ["example-org"]
[accounts.github-old]
kind = "github"
login = "oldme"
use = false
[accounts.ghes]
kind = "github"
host = "github.acme.com"
[accounts.hf]
kind = "huggingface"
login = "octocat"
[accounts.hf2]
kind = "huggingface"
owners = ["shared-org"]
[accounts.openai]
kind = "api-key"
sites = ["api.openai.com", ".openai.azure.com"]
[accounts.pijul]
kind = "pijul"
login = "octocat"
''', Path("/x"))

# (id, kind, host, owner, env, expected account | "ERR:substr" | "NONE")
SELECT = [
    ("owner_login_match", "github", "github.com", "octocat", {}, "github-personal"),
    ("owner_org_match", "github", "github.com", "example-org", {}, "github-work"),
    ("owner_case_insensitive", "github", "github.com", "Example-Org", {}, "github-work"),
    ("owner_work_login", "github", "github.com", "octo-work", {}, "github-work"),
    ("unknown_owner_default", "github", "github.com", "torvalds", {}, "github-personal"),
    ("no_owner_default", "github", "github.com", None, {}, "github-personal"),
    ("api_host_counts", "github", "api.github.com", "example-org", {}, "github-work"),
    ("ghcr_via_packages", "github", "ghcr.io", "example-org", {}, "github-work"),
    ("use_false_owner_never_falls_back", "github", "github.com", "oldme", {}, "ERR:github-old is the account for oldme but has use = false"),
    ("ghes_single", "github", "github.acme.com", "team", {}, "ghes"),
    ("explicit_overrides_owner", "github", "github.com", "example-org", {"GATE_ACCOUNT": "github-personal"}, "github-personal"),
    ("explicit_alias", "github", "github.com", None, {"GATE_ACCOUNT": "github:work"}, "github-work"),
    ("explicit_wrong_kind", "github", "github.com", None, {"GATE_ACCOUNT": "hf"}, "ERR:huggingface account"),
    ("explicit_wrong_host", "github", "github.acme.com", None, {"GATE_ACCOUNT": "github-work"}, "ERR:may not be used"),
    ("explicit_unknown", "github", "github.com", None, {"GATE_ACCOUNT": "nobody"}, "ERR:isn't an account"),
    ("explicit_use_false", "github", "github.com", None, {"GATE_ACCOUNT": "github-old"}, "ERR:use = false"),
    ("hf_owner", "huggingface", "huggingface.co", "shared-org", {}, "hf2"),
    ("hf_two_no_match_no_default", "huggingface", "hf.co", "someone", {}, "NONE"),
    ("api_key_exact", "api-key", "api.openai.com", None, {}, "openai"),
    ("api_key_subdomain", "api-key", "x.openai.azure.com", None, {}, "openai"),
    ("api_key_bare_domain_not_covered", "api-key", "openai.azure.com", None, {}, "NONE"),
    ("no_account_for_gitlab", "github", "gitlab.com", "acme", {}, "NONE"),
    ("pijul_single", "pijul", "nest.pijul.com", "octocat", {}, "pijul"),
]


def _make(cid, kind, host, owner, env, want):
    def t():
        s = sel(kind, host, owner, FORM, env=env, aliases={"github:work": "github-work"})
        if want == "NONE":
            assert s.account is None and s.error is None and s.note and (
                "no account for" in s.note or "no account is chosen for" in s.note), s
        elif want.startswith("ERR:"):
            assert s.account is None and s.error and want[4:] in s.error, s
        else:
            assert s.account is not None and s.account.name == want, s
            assert s.error is None
    t.__name__ = f"test_select_{cid}"
    return t


for _c in SELECT:
    globals()[f"test_select_{_c[0]}"] = _make(*_c)


def test_select_no_account_message_format():
    s = sel("github", "github.com", "acme", F.parse_text("", Path("/x")))
    assert s.note == "gateway: no account for github.com/acme"


def test_select_only_one_account_of_kind_host():
    f = F.parse_text('[accounts.gh]\nkind = "github"\n', Path("/x"))
    s = sel("github", "github.com", "whoever", f)
    assert s.name == "gh" and s.reason == "only"


def test_select_two_owner_matches_are_ambiguous():
    f = F.parse_text('[accounts.a]\nkind = "github"\nowners = ["x"]\n[accounts.b]\nkind = "github"\nlogin = "x"\n', Path("/x"))
    s = sel("github", "github.com", "x", f)
    assert s.error == "gateway: both a and b fit; set GATE_ACCOUNT=b"


def test_select_two_without_default_or_match_runs_without():
    f = F.parse_text('[accounts.a]\nkind = "github"\n[accounts.b]\nkind = "github"\n', Path("/x"))
    s = sel("github", "github.com", "x", f)
    # round 3: accounts of that kind exist, so the note names them and the ways to choose
    assert s.account is None and s.error is None and s.note == (
        "gateway: no account is chosen for github.com/x (a and b exist; neither lists x or is the "
        "default); set GATE_ACCOUNT=NAME, or ask the user to add default = true or owners in "
        "gateway.toml"), s.note
    s = sel("github", "github.com", None, f)
    assert "(a and b exist; neither is the default)" in s.note, s.note


def _pending(form_text: str, pending: str) -> tuple[F.Form, dict]:
    """Every account approved and bound except `pending` (never approved)."""
    f = F.parse_text(form_text, Path("/x"))
    data = approved_data(f)
    del data["approved"]["rights"]["accounts"][pending]
    del data["accounts"][pending]
    return f, data


TWO_GH = ('[accounts.me]\nkind = "github"\nlogin = "me"\n'
          '[accounts.work]\nkind = "github"\nowners = ["acme"]\n')


def test_select_pending_owner_account_blocks_the_only_other_account():
    # phase B request 3: work (owners = acme) waits for gate check; its repos
    # must not go to `me` because `me` is the only *usable* account.
    f, data = _pending(TWO_GH, "work")
    eff = consent.compute(f, data)
    s = A.select("github", "github.com", "acme", f, effective=eff, vault=data, env={})
    assert s.account is None and s.error == (
        "gateway: work is the account for acme but can't be used yet (it waits for the user's "
        "OK); run gate check work while the user is here"), s
    # me's own repos still work, and an unrelated owner isn't given to `me`
    # as "the only account" (two accounts exist for github.com)
    assert A.select("github", "github.com", "me", f, effective=eff, vault=data, env={}).name == "me"
    s = A.select("github", "github.com", "torvalds", f, effective=eff, vault=data, env={})
    assert s.account is None and s.error is None and "no account" in (s.note or ""), s
    # the user's explicit choice still wins
    s = A.select("github", "github.com", "acme", f, effective=eff, vault=data,
                 env={"GATE_ACCOUNT": "me"})
    assert s.name == "me"


def test_select_pending_owner_account_blocks_the_default():
    f, data = _pending(TWO_GH.replace('login = "me"\n', 'login = "me"\ndefault = true\n'), "work")
    eff = consent.compute(f, data)
    s = A.select("github", "github.com", "acme", f, effective=eff, vault=data, env={})
    assert s.account is None and "work is the account for acme" in (s.error or ""), s
    # unbound (approved but the credential isn't bound yet) blocks the same way
    f2 = F.parse_text(TWO_GH.replace('login = "me"\n', 'login = "me"\ndefault = true\n'), Path("/x"))
    d2 = approved_data(f2)
    d2["accounts"]["work"]["bound"]["hosts"] = []
    s = A.select("github", "github.com", "acme", f2, effective=consent.compute(f2, d2), vault=d2,
                 env={})
    assert s.account is None and "run gate check work" in (s.error or ""), s


def test_select_pending_default_is_named():
    f, data = _pending('[accounts.me]\nkind = "github"\nlogin = "me"\n'
                       '[accounts.dflt]\nkind = "github"\ndefault = true\n', "dflt")
    s = A.select("github", "github.com", "someone", f, effective=consent.compute(f, data),
                 vault=data, env={})
    assert s.account is None and s.error and "dflt is the default account for github.com" in s.error


def test_select_owner_matched_by_a_live_and_a_pending_account_is_ambiguous():
    f, data = _pending('[accounts.a]\nkind = "github"\nowners = ["x"]\n'
                       '[accounts.b]\nkind = "github"\nowners = ["x"]\n', "b")
    s = A.select("github", "github.com", "x", f, effective=consent.compute(f, data), vault=data,
                 env={})
    assert s.account is None and s.error and "a and b are the accounts for x" in s.error, s
    assert "GATE_ACCOUNT=a" in s.error


def test_select_respects_effective_rights_and_bound():
    f = F.parse_text('[accounts.gh]\nkind = "github"\npackages = true\n', Path("/x"))
    data = {"approved": {"rights": {"settings": {"others": "refuse"}, "hosts": {},
                                    "accounts": {"gh": {"kind": "github", "use": True,
                                                        "destinations": ["github.com", "api.github.com"]}}}},
            "accounts": {"gh": {"kind": "github", "bound": {"hosts": ["github.com", "api.github.com"]}}}}
    eff = consent.compute(f, data)
    assert A.select("github", "github.com", None, f, effective=eff, env={}).name == "gh"
    s = A.select("github", "ghcr.io", None, f, effective=eff, env={})
    assert s.account is None, "ghcr.io waits for consent"
    s = A.select("github", "ghcr.io", None, f, effective=eff, env={"GATE_ACCOUNT": "gh"}, vault=data)
    assert s.error and "may not be used" in s.error


def test_select_explicit_needs_a_vault_record_with_the_destination_bound():
    # Approved in the snapshot, but the vault has no record for the account: an
    # explicit GATE_ACCOUNT must still refuse (an empty bound set), not skip the check.
    f = F.parse_text('[accounts.gh]\nkind = "github"\n', Path("/x"))
    data = {"approved": {"rights": consent.snapshot(f)}, "accounts": {}}
    eff = consent.compute(f, data)
    assert "github.com" in eff.accounts["gh"].destinations
    s = A.select("github", "github.com", None, f, effective=eff, env={"GATE_ACCOUNT": "gh"}, vault=data)
    assert s.account is None and s.error and "isn't bound" in s.error, s
    data["accounts"]["gh"] = {"kind": "github", "bound": {"hosts": ["github.com"]}}
    s = A.select("github", "github.com", None, f, effective=eff, env={"GATE_ACCOUNT": "gh"}, vault=data)
    assert s.name == "gh"


def test_select_never_uses_unapproved_accounts():
    # A brand-new api-key account (not approved) is not picked for its site.
    f = F.parse_text('[accounts.k]\nkind = "api-key"\nsites = ["api.x.com"]\n', Path("/x"))
    eff = consent.compute(f, {"approved": {"rights": consent.baseline()}})
    s = A.select("api-key", "api.x.com", None, f, effective=eff, env={})
    assert s.account is None and s.note
    try:
        A.select("api-key", "api.x.com", None, f, env={})  # type: ignore[call-arg]
    except TypeError:
        pass
    else:
        raise AssertionError("select() without effective= must not run")


def test_every_select_call_in_src_passes_effective():
    # Phase B callers code against select(); the raw form must never decide.
    missing = []
    for py in sorted((H.PLUGIN / "src" / "gateway").glob("*.py")):
        tree = ast.parse(py.read_text(), str(py))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr == "select" and isinstance(node.func.value, ast.Name) \
                    and node.func.value.id in ("accounts", "acctmod", "A"):
                if not any(k.arg == "effective" for k in node.keywords):
                    missing.append(f"{py.name}:{node.lineno}")
    assert not missing, missing


def test_alias_never_shadows_a_live_entry():
    f = F.parse_text('[accounts.hf]\nkind = "huggingface"\n[accounts.hf-2]\nkind = "api-key"\n'
                     'sites = ["api.x.com"]\n', Path("/x"))
    assert A.resolve_name("hf", {"hf": "hf-2"}, f) == "hf"
    assert A.resolve_name("HF_OLD", {"HF_OLD": "hf-2"}, f) == "hf-2"
    s = sel("huggingface", "huggingface.co", None, f, env={"GATE_ACCOUNT": "hf"}, aliases={"hf": "hf-2"})
    assert s.name == "hf", s


def test_destination_matching():
    assert A.destination_matches("api.x.com", "API.X.com")
    assert not A.destination_matches("api.x.com", "x.com")
    assert A.destination_matches(".x.com", "a.b.x.com") and not A.destination_matches(".x.com", "x.com")
    assert not A.destination_matches(".x.com", "evilx.com")
    assert A.destination_matches("127.0.0.1:8080", "127.0.0.1:8080")
    assert not A.destination_matches("127.0.0.1:8080", "127.0.0.1:9090")
    assert A.destination_matches("github.com", "github.com:443")


def test_ssh_endpoints():
    ep = {a.name: a.ssh_endpoints() for a in FORM.accounts.values()}
    assert ("git", "github.com") in ep["github-work"] and ("git", "ssh.github.com") in ep["github-work"]
    assert ep["ghes"] == [("git", "github.acme.com")]
    assert ep["hf"] == [("git", "hf.co")]
    assert ep["pijul"] == [("octocat", "nest.pijul.com")]
    assert ep["openai"] == []
    names = {a.name for a in A.endpoint_accounts("git", "github.com", FORM)}
    assert names == {"github-personal", "github-work", "github-old"}
    assert A.is_ssh_endpoint("hf.co", FORM) and not A.is_ssh_endpoint("example", FORM)
    assert A.kinds_for_host("api.openai.com", FORM) == ["api-key"]


def test_owner_extraction():
    assert A.owner_from_path("example-org/repo.git") == "example-org"
    assert A.owner_from_path("/example-org/repo") == "example-org"
    assert A.owner_from_path("'~example-org/repo'") == "example-org"
    assert A.owner_from_path("lonely") is None
    assert A.owner_from_path("datasets/org/name", "huggingface") == "org"
    assert A.owner_from_url("https://github.com/acme/x.git") == ("github.com", "acme")
    assert A.owner_from_url("git@github.com:acme/x.git") == ("github.com", "acme")
    assert A.owner_from_url("ssh://git@github.com/acme/x") == ("github.com", "acme")
    assert A.owner_from_url("http://127.0.0.1:8080/acme/x") == ("127.0.0.1:8080", "acme")
    assert A.owner_from_url("https://huggingface.co/spaces/org/app", "huggingface") == ("huggingface.co", "org")
    assert A.owner_from_url("file:///tmp/x") is None
    assert A.owner_from_git_command("git-upload-pack 'acme/repo.git'") == ("git-upload-pack", "acme")
    assert A.owner_from_git_command("git-receive-pack '/acme/repo'") == ("git-receive-pack", "acme")
    assert A.owner_from_git_command("git-lfs-authenticate acme/repo download") == ("git-lfs-authenticate", "acme")
    assert A.owner_from_git_command("rm -rf /") is None
    # invalid ports in untrusted remote URLs: not a URL, never a crash
    assert A.owner_from_url("https://github.com:99999/a/b") is None
    assert A.owner_from_url("https://github.com:abc/a/b") is None
    assert A.owner_from_url("ssh://git@github.com:70000/a/b") is None
