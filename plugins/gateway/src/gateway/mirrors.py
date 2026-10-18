"""The git_mirror tool: keep one repo's branches and tags the same on several
remotes (e.g. a personal and a work GitHub), each pushed as its own account.

The mirror set is the repo's own `gateway.mirror` config (remote names, one
value each), so it can be changed from chat. Every fetch and push goes
through the git tool, so each remote uses its own account and prompt
policy. Sync is fast-forward only: a remote that is behind gets the newer
commit; a branch that has diverged, or a tag that points at different
commits, is reported and left alone. Nothing is ever forced or deleted.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from . import gitops, policy, runner


def _local(cwd: Path, *args: str) -> runner.Result:
    return runner.run("git", list(args), cwd=cwd, timeout=60)


def mirror_set(cwd: Path) -> list[str]:
    r = _local(cwd, "config", "--get-all", "gateway.mirror")
    return [x for x in r.stdout.split() if x] if r.ok else []


def _tracking(cwd: Path, remote: str) -> dict[str, str]:
    r = _local(cwd, "for-each-ref", "--format=%(refname) %(objectname)",
               f"refs/gateway-mirror/{remote}/heads/")
    pre = f"refs/gateway-mirror/{remote}/heads/"
    return {ref[len(pre):]: sha for ref, sha in
            (l.split() for l in r.stdout.splitlines() if l.strip())}


def _tags(cwd: Path, remote: str) -> dict[str, str]:
    r = _local(cwd, "for-each-ref", "--format=%(refname) %(objectname)",
               f"refs/gateway-mirror/{remote}/tags/")
    pre = f"refs/gateway-mirror/{remote}/tags/"
    return {ref[len(pre):]: sha for ref, sha in
            (l.split() for l in r.stdout.splitlines() if l.strip())}


def _is_ancestor(cwd: Path, a: str, b: str) -> bool:
    return a == b or _local(cwd, "merge-base", "--is-ancestor", a, b).ok


def _fetch_all(cwd: Path, remotes: list[str]) -> dict[str, str]:
    """Fetch each remote into refs/gateway-mirror/<remote>/ (its own account).
    Returns {remote: error} for the ones that failed."""
    errors = {}
    for r in remotes:
        res = gitops.git_tool(["fetch", "--no-tags", r,
                               f"+refs/heads/*:refs/gateway-mirror/{r}/heads/*",
                               f"+refs/tags/*:refs/gateway-mirror/{r}/tags/*"], str(cwd))
        if not res.get("ok"):
            errors[r] = res.get("reason") or res.get("stderr", "")[-300:] or "fetch failed"
    return errors


def _plan(cwd: Path, remotes: list[str], branches: list[str] | None) -> dict[str, Any]:
    heads = {r: _tracking(cwd, r) for r in remotes}
    names = sorted(set(branches or [b for h in heads.values() for b in h]))
    plan: dict[str, Any] = {"branches": {}, "tags": {}}
    for b in names:
        shas = {r: heads[r].get(b) for r in remotes}
        present = {r: s for r, s in shas.items() if s}
        if not present:
            plan["branches"][b] = {"state": "missing everywhere"}
            continue
        tip = next((s for s in set(present.values())
                    if all(_is_ancestor(cwd, o, s) for o in present.values())), None)
        if tip is None:
            plan["branches"][b] = {"state": "diverged",
                                   "heads": {r: s[:12] for r, s in present.items()}}
            continue
        behind = [r for r, s in shas.items() if s != tip]
        plan["branches"][b] = {"state": "in sync" if not behind else "behind",
                               "tip": tip, "behind": behind,
                               "missing": [r for r in behind if not shas[r]]}
    tags = {r: _tags(cwd, r) for r in remotes}
    for t in sorted({t for v in tags.values() for t in v}):
        shas = {r: tags[r].get(t) for r in remotes}
        distinct = {s for s in shas.values() if s}
        if len(distinct) > 1:
            plan["tags"][t] = {"state": "conflict", "heads": {r: s[:12] for r, s in shas.items() if s}}
        else:
            sha = distinct.pop()
            missing = [r for r, s in shas.items() if not s]
            plan["tags"][t] = {"state": "in sync" if not missing else "missing",
                               "sha": sha, "missing": missing}
    return plan


def git_mirror(cwd: str, action: str = "status", remotes: list[str] | None = None,
               branches: list[str] | None = None, tags: bool = True) -> dict[str, Any]:
    cwdp = Path(cwd).expanduser()
    try:
        gitops._check_paths(cwdp, [])
    except gitops.GitRefused as e:
        return {"ok": False, "refused": True, "reason": str(e)}
    if not _local(cwdp, "rev-parse", "--git-dir").ok:
        return {"ok": False, "reason": f"{cwdp} is not a git repository"}
    known = _local(cwdp, "remote").stdout.split()
    if action in ("add", "remove"):
        if not remotes:
            return {"ok": False, "reason": "give remotes=[...] to add or remove"}
        unknown = [r for r in remotes if r not in known]
        if unknown and action == "add":
            return {"ok": False, "reason": f"not remotes of this repo: {', '.join(unknown)} "
                                           "(add them with the git tool: remote add NAME URL)"}
        cur = mirror_set(cwdp)
        new = cur + [r for r in remotes if r not in cur] if action == "add" \
            else [r for r in cur if r not in remotes]
        _local(cwdp, "config", "--unset-all", "gateway.mirror")
        for r in new:
            _local(cwdp, "config", "--add", "gateway.mirror", r)
        policy.audit("git_mirror", {"cwd": str(cwdp), "action": action, "set": new})
        return {"ok": True, "mirror_set": new}
    if action not in ("status", "sync"):
        return {"ok": False, "reason": "action is status, sync, add or remove"}
    group = remotes or mirror_set(cwdp)
    if len(group) < 2:
        return {"ok": False, "reason": "a mirror needs at least two remotes: pass remotes=[...] "
                                       "or save a set with action=add"}
    unknown = [r for r in group if r not in known]
    if unknown:
        return {"ok": False, "reason": f"not remotes of this repo: {', '.join(unknown)}"}
    errors = _fetch_all(cwdp, group)
    if errors:
        return {"ok": False, "reason": "could not fetch every remote", "fetch_errors": errors}
    plan = _plan(cwdp, group, branches)
    if not tags:
        plan["tags"] = {}
    out: dict[str, Any] = {"ok": True, "remotes": group, **plan}
    if action == "status":
        policy.audit("git_mirror", {"cwd": str(cwdp), "action": "status", "remotes": group})
        return out
    pushed, needs_confirm, failed = [], [], []

    def push(remote: str, refspec: str) -> None:
        res = gitops.git_tool(["push", remote, refspec], str(cwdp))
        if res.get("ok"):
            pushed.append(f"{remote} {refspec}")
        elif res.get("use") == "git_confirm":
            needs_confirm.append({"remote": remote, "args": ["push", remote, refspec],
                                  "account": res.get("account")})
        else:
            failed.append({"remote": remote, "refspec": refspec,
                           "error": res.get("reason") or res.get("stderr", "")[-300:]})

    for b, st in plan["branches"].items():
        if st["state"] == "behind":
            for r in st["behind"]:
                push(r, f"{st['tip']}:refs/heads/{b}")
    for t, st in plan["tags"].items():
        if st["state"] == "missing":
            for r in st["missing"]:
                push(r, f"{st['sha']}:refs/tags/{t}")
    out.update({"pushed": pushed, "ok": not failed})
    if needs_confirm:
        out["needs_confirm"] = needs_confirm
        out["note"] = ("Some pushes need the user's OK under their account's policy: run each "
                       "listed args with git_confirm.")
    if failed:
        out["failed"] = failed
    left = [b for b, st in plan["branches"].items() if st["state"] == "diverged"] + \
           [t for t, st in plan["tags"].items() if st["state"] == "conflict"]
    if left:
        out["left_alone"] = left
        out.setdefault("note", "")
        out["note"] += (" Diverged branches / conflicting tags were left alone: merge or rebase "
                        "locally, then push, or ask the user which side should win.").strip()
    policy.audit("git_mirror", {"cwd": str(cwdp), "action": "sync", "remotes": group,
                                "pushed": len(pushed), "left_alone": len(left)})
    return out
