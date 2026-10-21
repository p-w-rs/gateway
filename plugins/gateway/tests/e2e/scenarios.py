"""The e2e scenarios: one short `claude -p` session each, then assertions on
its stream-json, debug log, the fixtures' records and the audit log.

    context  SessionStart context; the env file in foreground, background and
             subagent Bash; SubagentStart context
    ssh      ssh / remote sudo / scp / rsync / a jump host / local sudo -n true,
             all approved by the gateway's hook (no classifier) in auto mode
    git      clone and push over http to the local git server, the account
             picked by owner, the commit identity from the include
    web      curl denied; the http tool called directly (alwaysLoad) with an
             api-key account; a server echoing the key gets *** back
    refuse   sudo = false refused, ssh = "ask" denied in -p, unknown host refused,
             `gate secret` denied (round 5: the user's command)
    default  default permission mode: the allowed ssh is not auto-approved,
             denies still apply
    leak     a command's output masked; a failed command keeps its exit code
             (no EXIT trap: rolled back) and cwd tracking; a failure with a token
             shape gets the PostToolUseFailure warning; Monitor runs as typed,
             `| gate scrub` optional; round 5: a Read of stored values masked, a
             Write and an Edit of a plain project file pass (the file guard's sh
             fast path, no PostToolUse Python)
    notice   round 4: a background command runs as typed (the `gate scrub` rule
             is rolled back) and its raw "waiting for input" notice is held back
             by the prompt hook (Claude idle), as is the notice of a foreground
             command moved to the background; a failed background command's
             real exit code
    midturn  round 4: the same notice arriving mid-turn is held back too
    jobs     optional (a checkpoint checkout next to the gateway repo, else
             skipped): checkpoint's job_start with the gateway: the env probe
             in a job, an ssh job, a remote-sudo job and an argv job work;
             curl, an "ask" right and the private folder are denied for
             job_start; an "ask" right hidden in a script gets the job
             wording from the stand-in; job_tail's output is masked; a step
             Claude Code's classifier denies is "not reached (classifier)"
"""
from __future__ import annotations

import contextlib
import json
import os
import re
import shutil
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

from e2elib import (CLASSIFIER_SKIP, Checks, Session, dispatch_info, first_line, scan,
                    secret_forms)

LONG = 210        # run_e2e.LONG_TIMEOUT: the notice scenarios wait 45 s for the notice

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _approved_by_hook(s: Session, c: Any) -> tuple[bool | None, dict[str, Any]]:
    """The gateway's PreToolUse hook answered allow for this call (stream
    hook event) and Claude Code dispatched it on that answer: the debug log
    shows `Hook approved tool use` right before the call's dispatch, a
    permission decision in well under a second, and no classifier line."""
    stream_allow = any('"permissionDecision": "allow"' in o or '"permissionDecision":"allow"' in o
                       for o in c.hook_outputs)
    info = dispatch_info(s.debug, c.id)
    detail = {"stream_hook_allow": stream_allow, **info}
    if not info.get("found"):
        return (stream_allow or None), detail
    ok = (stream_allow and info["hook_approved"] and not info["permission_step"]
          and info["decision_ms"] is not None and info["decision_ms"] < 100)
    return ok, detail


def _probe(path: Path) -> dict[str, str]:
    try:
        return dict(l.split("=", 1) for l in path.read_text().splitlines() if "=" in l)
    except OSError:
        return {}


def _call(C: Checks, g: str, s: Session, needle: str, tool: str = "Bash") -> Any:
    c = s.find(needle, tool)
    if c is None:
        C.add(g, f"`{needle}` was run", None, "the model never made this call")
    return c


# ---------------------------------------------------------------------------
# scenarios
# ---------------------------------------------------------------------------


def context(e: Any, C: Checks) -> None:
    g = "context"
    s = e.session(g, "Steps:\n"
                  "1. Run: sh probe.sh fg\n"
                  "2. Run this command with the Bash tool's run_in_background option set to true: "
                  "sh probe.sh bg\n"
                  "3. Use the Agent tool once (subagent_type \"general-purpose\") with exactly this "
                  "prompt: \"Run the shell command `sh probe.sh sub` with the Bash tool exactly as "
                  "written, then reply with its output.\" Wait for it to finish.\n"
                  "4. Run: cat out-bg.txt")
    data = e.root / "data"
    want = {"path_first": str(data / "bin"), "ssh": str(data / "bin" / "ssh"),
            "sudo": str(data / "bin" / "sudo"), "git_include": str(data / "git" / "config"),
            "git_ssh_command": str(data / "bin" / "ssh"), "rsync_rsh": str(data / "bin" / "ssh"),
            "ssh_auth_sock": "", "github_token": "", "claude_pid": "set"}
    ctx = s.hook_text("SessionStart")
    names = ["e2ehost", "e2enosudo", "e2ejump", "e2ebehind", "e2eask", "e2e-personal", "e2e-work",
             "e2eapi"]
    C.add(g, "SessionStart context lists the hosts and accounts",
          "Gateway (plugin)" in ctx and all(n in ctx for n in names),
          {"missing": [n for n in names if n not in ctx], "ctx": first_line(ctx, 400)})
    C.add(g, "SessionStart tells the user it is the e2e test vault",
          "e2e test mode" in ctx and str(e.root) in ctx, first_line(ctx, 300))
    for tag, what in (("fg", "foreground"), ("bg", "background"), ("sub", "subagent")):
        got = _probe(e.work / f"out-{tag}.txt")
        diff = {k: (got.get(k), v) for k, v in want.items() if got.get(k) != v}
        C.add(g, f"env file applied in {what} Bash (stand-ins first on PATH, git include, "
                 "GIT_SSH_COMMAND/RSYNC_RSH, SSH_AUTH_SOCK and GITHUB_TOKEN unset)",
              bool(got) and not diff, diff or got or "no probe output (the step didn't run)")
    sub = s.hook_text("SubagentStart")
    C.add(g, "SubagentStart gives the subagent the same context",
          "Gateway (plugin)" in sub and "e2ehost" in sub,
          first_line(sub, 200) or "no SubagentStart hook event")
    C.add(g, "no permission denials", not s.denials, s.denials)


def ssh(e: Any, C: Checks) -> None:
    g = "ssh"
    t1 = e.sshds["target"]
    s = e.session(g, "Steps:\n"
                  "1. Run: ssh e2ehost echo e2e-ok\n"
                  "2. Run: ssh e2ehost sudo whoami\n"
                  f"3. Run: scp e2ehost:{t1.dir}/remote.txt ./got-scp.txt\n"
                  f"4. Run: rsync -a ./site/ e2ehost:{t1.dir}/site-copy/\n"
                  "5. Run: ssh e2ebehind echo e2e-via-jump\n"
                  "6. Run: sudo -n true")
    steps = [("ssh e2ehost echo e2e-ok", lambda c: "e2e-ok" in c.result),
             ("ssh e2ehost sudo whoami", lambda c: e.user in c.result),
             ("scp e2ehost:", lambda c: (e.work / "got-scp.txt").exists()),
             ("rsync -a ./site/", lambda c: (t1.dir / "site-copy" / "index.html").exists()),
             ("ssh e2ebehind", lambda c: "e2e-via-jump" in c.result),
             ("sudo -n true", lambda c: not c.is_error)]
    for needle, ok in steps:
        c = _call(C, g, s, needle)
        if c is None:
            continue
        C.add(g, f"`{c.command}` ran without a permission denial and worked",
              not c.denied and ok(c), {"denied": c.denied, "error": c.is_error,
                                       "result": first_line(c.result, 300)})
        ok, detail = _approved_by_hook(s, c)
        C.add(g, f"`{c.command}` approved by the gateway hook, no classifier call", ok, detail)
    runs = [r for r in t1.sudo.log() if r.get("ran") == ["whoami"]]
    C.add(g, "remote sudo used the staged askpass with the fake password sudo",
          bool(runs) and runs[-1].get("how") == "A" and runs[-1].get("code") == 0,
          runs[-1:] or t1.sudo.log()[-3:])
    cmds = t1.commands()
    C.add(g, "the remote saw the probe, staging, verification and cleanup",
          "sudo -n true" in cmds and any("mktemp -d" in x for x in cmds)
          and any(x.endswith("sudo -k -A -v") for x in cmds)
          and any("rm -rf --" in x for x in cmds), cmds[-8:])
    C.add(g, "nothing left in the remote staging folder", not any(t1.xdg.iterdir()),
          [p.name for p in t1.xdg.iterdir()])
    C.add(g, "the jump host carried the via login", e.sshds["jump"].accepted() >= 1,
          e.sshds["jump"].accepted())
    probe = e.run / f"sudo-nopasswd-{e.user}"
    txt = probe.read_text() if probe.exists() else ""
    C.add(g, "local sudo went through the stand-in (its NOPASSWD probe said yes)",
          txt.startswith("yes"), txt or "no probe cache in the e2e run dir")
    uses = [a for a in e.audit() if a.get("event") == "use" and a.get("tool") in ("ssh", "scp")]
    C.add(g, "audit log has ssh credential uses (with remote_sudo)",
          any(a.get("target") == "e2ehost" for a in uses)
          and any(a.get("remote_sudo") for a in uses),
          [{k: a.get(k) for k in ("tool", "target", "remote_sudo")} for a in uses][-6:])
    C.add(g, "no permission denials", not s.denials, s.denials)


def git(e: Any, C: Checks) -> None:
    g = "git"
    h = e.gitsrv.host
    s = e.session(g, "Steps:\n"
                  f"1. Run: git clone http://{h}/e2eorg/work.git\n"
                  f"2. Run: git clone http://{h}/e2euser/proj.git\n"
                  "3. Run: echo e2e > work/f.txt && git -C work add f.txt && git -C work -c "
                  "commit.gpgsign=false commit -qm e2e && git -C work push -q origin "
                  "HEAD:refs/heads/main\n"
                  "4. Run: git -C work log -1 --format=%ae")
    C.add(g, "both clones exist", (e.work / "work" / ".git").is_dir()
          and (e.work / "proj" / ".git").is_dir(),
          [first_line(c.result, 200) for c in s.calls if c.name == "Bash"][:2])
    auths = e.gitsrv.auths()
    work = [a for a in auths if "/e2eorg/" in a["path"]]
    proj = [a for a in auths if "/e2euser/" in a["path"]]
    C.add(g, "e2eorg/* used the e2e-work account (owner match)",
          bool(work) and all(a["password"] == e.tok_work and a["user"] == "x-access-token"
                             for a in work), [(a["method"], a["path"], a["user"]) for a in work][:4])
    C.add(g, "e2euser/* used the default e2e-personal account",
          bool(proj) and all(a["password"] == e.tok_personal for a in proj),
          [(a["method"], a["path"], a["user"]) for a in proj][:4])
    C.add(g, "the push authenticated with the work token",
          any(a["method"] == "POST" and "git-receive-pack" in a["path"]
              and a["password"] == e.tok_work for a in auths),
          [(a["method"], a["path"]) for a in auths][-4:])
    c = s.find("log -1 --format=%ae")
    C.add(g, "the commit identity came from the account's include (worker@e2e.invalid)",
          c is not None and "worker@e2e.invalid" in c.result,
          first_line(c.result if c else "not run", 200))
    uses = [a for a in e.audit() if a.get("tool") == "git-credential" and a.get("event") == "use"]
    C.add(g, "audit log has the git credential uses",
          {a.get("account") for a in uses} >= {"e2e-work", "e2e-personal"},
          sorted({str(a.get("account")) for a in uses}))
    C.add(g, "no permission denials", not s.denials, s.denials)


def web(e: Any, C: Checks) -> None:
    g = "web"
    base = e.api.url("")
    s = e.session(g, "Steps:\n"
                  f"1. Run: curl -s {base}/data\n"
                  f"2. Call the tool mcp__plugin_gate_gw__http with url \"{base}/data\" and account "
                  "\"e2eapi\".\n"
                  f"3. Call the tool mcp__plugin_gate_gw__http with url \"{base}/echo\" and account "
                  "\"e2eapi\".")
    c = _call(C, g, s, "curl -s")
    if c is not None:
        C.add(g, "curl is denied with the gateway's message",
              c.denied and "gateway: use the http tool" in c.result, first_line(c.result, 300))
    tools = s.init.get("tools") or []
    C.add(g, "the http tool is loaded at start (alwaysLoad)",
          "mcp__plugin_gate_gw__http" in tools, [t for t in tools if "gw" in t])
    http = [x for x in s.calls if x.name == "mcp__plugin_gate_gw__http"]
    first = s.calls.index(http[0]) if http else None
    searched = [x for x in s.calls[: first or 0] if x.name == "ToolSearch"]
    C.add(g, "the http tool was called directly, without ToolSearch",
          bool(http) and not searched, {"http_calls": len(http), "toolsearch": len(searched)})
    d = next((x for x in http if "/data" in json.dumps(x.input)), None)
    C.add(g, "http with account e2eapi returned the API's data",
          d is not None and not d.denied and "e2e-api-data-42" in d.result,
          first_line(d.result if d else "not called", 300))
    sent = [r for r in e.api.rec.requests if r["path"] == "/data"]
    C.add(g, "the API received the key as a bearer header",
          any(r["headers"].get("Authorization") == f"Bearer {e.api_key}" for r in sent),
          len(sent))
    ec = next((x for x in http if "/echo" in json.dumps(x.input)), None)
    C.add(g, "a server echoing the key gets *** back in the tool result",
          ec is not None and "***" in ec.result and e.api_key not in ec.result,
          first_line(ec.result if ec else "not called", 300))
    C.add(g, "no denial for the http tool calls", not any(x.denied for x in http),
          [x.id for x in http if x.denied])
    appr = [_approved_by_hook(s, x) for x in http]
    C.add(g, "the http tool calls were approved by the gateway's mcp_perm hook (no prompt, "
             "no classifier)", bool(appr) and all(ok for ok, _ in appr), [d for _, d in appr])


def refuse(e: Any, C: Checks) -> None:
    g = "refuse"
    s = e.session(g, "Steps:\n"
                  "1. Run: ssh e2enosudo sudo whoami\n"
                  "2. Run: ssh e2eask echo e2e-ask\n"
                  "3. Run: ssh nosuchhost.invalid echo e2e-unknown\n"
                  "4. Run: gate secret e2ehost")
    c = _call(C, g, s, "ssh e2enosudo")
    if c is not None:
        C.add(g, "sudo = false: refused with the gateway's message",
              c.denied and "gateway: sudo is off for e2enosudo" in c.result,
              first_line(c.result, 300))
    c = _call(C, g, s, "ssh e2eask")
    if c is not None:
        C.add(g, "ssh = \"ask\": a permission denial in -p (nobody can answer)",
              c.denied and "e2e-ask" not in c.result.replace("echo e2e-ask", ""),
              first_line(c.result, 300))
    c = _call(C, g, s, "ssh nosuchhost.invalid")
    if c is not None:
        # control for the ssh scenario's "approved by the gateway hook" check:
        # a command the hook leaves alone goes through auto mode's classifier
        ok, detail = _approved_by_hook(s, c)
        info = dispatch_info(s.debug, c.id)
        C.add(g, "control: the unknown host (no hook decision) went through Claude Code's "
                 "own permission step, which the hook check tells apart",
              ok is False and info.get("found") and not info.get("hook_approved")
              and bool(info.get("permission_step")), detail)
        if c.denied:
            C.add(g, "unknown host: refused with the 'not in gateway.toml' message", None,
                  "the classifier denied the command before the stand-in ran: "
                  + first_line(c.result, 200))
        else:
            C.add(g, "unknown host: refused with the 'not in gateway.toml' message",
                  "isn't in gateway.toml" in c.result and "e2e-unknown" not in
                  c.result.replace("echo e2e-unknown", ""), first_line(c.result, 300))
    c = _call(C, g, s, "gate secret")
    if c is not None:
        C.add(g, "round 5: `gate secret` is denied by the hook (it is the user's command)",
              c.denied and "gateway: gate secret is for the user" in c.result,
              first_line(c.result, 300))
    C.add(g, "nothing reached the e2enosudo sshd", e.sshds["nosudo"].commands() == [],
          e.sshds["nosudo"].commands())
    refs = [a for a in e.audit() if a.get("event") == "refusal"]
    C.add(g, "the refusals are in the audit log (for `gate why`)",
          any(a.get("target") == "e2enosudo" for a in refs)
          and any(a.get("target") == "nosuchhost.invalid" or "nosuchhost" in str(a.get("reason"))
                  for a in refs),
          [{k: a.get(k) for k in ("tool", "target")} for a in refs][-6:])


def default(e: Any, C: Checks) -> None:
    g = "default"
    base = e.api.url("")
    s = e.session(g, "Steps:\n"
                  "1. Run: ssh e2ehost echo e2e-default\n"
                  f"2. Run: curl -s {base}/data", mode="default")
    C.add(g, "the session ran in the default permission mode",
          s.init.get("permissionMode") == "default", s.init.get("permissionMode"))
    c = _call(C, g, s, "ssh e2ehost echo e2e-default")
    if c is not None:
        C.add(g, "the allowed ssh is NOT auto-approved (permission denied in -p)",
              c.denied and not any("e2e-default" in x for x in e.sshds["target"].commands()),
              first_line(c.result, 300))
    c = _call(C, g, s, "curl -s")
    if c is not None:
        C.add(g, "curl is still denied with the gateway's message",
              c.denied and "gateway: use the http tool" in c.result, first_line(c.result, 300))


def leak(e: Any, C: Checks) -> None:
    """Output Claude Code passes to no masking hook. The gateway doesn't change
    how Claude's commands end (the round 3 EXIT trap is rolled back): a
    command that succeeds comes back masked; a failed one keeps its exit code
    and Claude Code's cwd tracking, and when its (unmaskable) output holds a
    token shape the gateway warns; Monitor commands run as typed, with or
    without the optional `| gate scrub`."""
    g = "leak"
    s = e.session(g, "Steps:\n"
                  "1. Run: cat notes.txt\n"
                  "2. Run: mkdir -p sub && cd sub && false\n"
                  "3. Run: pwd\n"
                  "4. Run: cd sub\n"
                  "5. Run: pwd\n"
                  "6. Run: cat ../leak.txt; exit 3\n"
                  "7. Call the Monitor tool with command `echo e2e-monitor-plain`, description "
                  "\"e2e plain\" and timeout_ms 5000.\n"
                  "8. Call the Monitor tool with command `cat ../notes.txt | gate scrub`, description "
                  "\"e2e scrubbed\" and timeout_ms 5000.\n"
                  "9. Read the file notes.txt in the working directory you started in with the Read "
                  "tool.\n"
                  "10. Create the file e2e-edit.txt in that same directory with the Write tool, "
                  "content `e2e-hello`.\n"
                  "11. With the Edit tool, replace e2e-hello with e2e-bye in e2e-edit.txt.")
    c = _call(C, g, s, "cat notes.txt")
    if c is not None:
        C.add(g, "a `cat` of stored values comes back masked",
              not c.denied and "***" in c.result and e.api_key not in c.result
              and e.remote_pw not in c.result and not c.is_error,
              {"is_error": c.is_error, "result": first_line(c.result.replace(e.api_key, "<KEY>")
                                                            .replace(e.remote_pw, "<PW>"), 300)})
    c = _call(C, g, s, "cd sub && false")
    if c is not None:
        C.add(g, "a failed command is an error result with its own exit code (no EXIT trap)",
              c.is_error and "Exit code 0" not in c.result, first_line(c.result, 200))
    calls = [x for x in s.calls if x.name == "Bash" and x.command.strip() == "pwd"]
    if len(calls) >= 2:
        C.add(g, "Claude Code's cwd tracking: a failed `cd sub && false` leaves the cwd as "
                 "before; a plain `cd sub` moves it",
              calls[0].result.strip().endswith("/work") and calls[1].result.strip().endswith(
                  "/work/sub"), [first_line(x.result, 120) for x in calls[:2]])
    else:
        C.add(g, "Claude Code's cwd tracking", None, "the model didn't run both pwd steps")
    c = _call(C, g, s, "leak.txt")
    if c is not None:
        warn = s.hook_text("PostToolUseFailure")
        C.add(g, "a failed command whose output holds a token shape gets the gateway's "
                 "PostToolUseFailure warning, and keeps its exit code",
              c.is_error and re.search(r"(?i)exit code 3", c.result) is not None
              and "gateway: the output of that failed command held "
              "something shaped like a token" in warn,
              {"is_error": c.is_error, "result": first_line(c.result, 120),
               "hook": first_line(warn, 300)})
    mons = [x for x in s.calls if x.name == "Monitor"]
    plain = next((x for x in mons if "e2e-monitor-plain" in json.dumps(x.input)), None)
    sc = next((x for x in mons if "gate scrub" in json.dumps(x.input)), None)
    if plain is None:
        C.add(g, "a Monitor command without `| gate scrub` runs (no scrub rule)", None,
              "no such Monitor call")
    else:
        C.add(g, "a Monitor command without `| gate scrub` runs (no scrub rule)", not plain.denied,
              first_line(plain.result, 300))
    if sc is None:
        C.add(g, "a Monitor command ending in the optional `| gate scrub` runs", None,
              "no such Monitor call")
    else:
        C.add(g, "a Monitor command ending in the optional `| gate scrub` runs", not sc.denied,
              first_line(sc.result, 300))
    rd = next((x for x in s.calls if x.name == "Read" and "notes.txt" in json.dumps(x.input)), None)
    if rd is None:
        C.add(g, "round 5: a Read of stored values comes back masked", None, "no such Read call")
    else:
        C.add(g, "round 5: a Read of stored values comes back masked (file guard fast path, "
                 "PostToolUse still masks a Read)",
              not rd.denied and "***" in rd.result and e.api_key not in rd.result
              and e.remote_pw not in rd.result,
              first_line(rd.result.replace(e.api_key, "<KEY>").replace(e.remote_pw, "<PW>"), 200))
    wr = next((x for x in s.calls if x.name == "Write" and "e2e-edit.txt" in json.dumps(x.input)), None)
    ed = next((x for x in s.calls if x.name == "Edit" and "e2e-edit.txt" in json.dumps(x.input)), None)
    target = e.work / "e2e-edit.txt"
    try:
        text = target.read_text()
    except OSError:
        text = None
    if wr is None or ed is None:
        C.add(g, "round 5: a Write and an Edit of a plain project file pass", None,
              f"write call: {wr is not None}, edit call: {ed is not None}")
    else:
        C.add(g, "round 5: a Write and an Edit of a plain project file pass (no denial, no "
                 "hook output after them)",
              not wr.denied and not ed.denied and not wr.is_error and not ed.is_error
              and text is not None and "e2e-bye" in text
              and not any("updatedToolOutput" in o for o in wr.hook_outputs + ed.hook_outputs),
              {"file": text, "write": first_line(wr.result, 120), "edit": first_line(ed.result, 120)})


STALL = "cat notes.txt; printf 'Continue? [y/N] '; sleep 75"
BG_STALL = "cat notes.txt; printf 'Continue? [y/N] '; sleep 70"


def _notice_blocked(e: Any, s: Any) -> tuple[bool, Any]:
    """The prompt hook held back a task notification of this session: its
    systemMessage in the stream's hook events, or the audit log's leak event."""
    txt = s.hook_text("UserPromptSubmit")
    leaks = [a for a in e.audit() if a.get("event") == "leak"
             and a.get("where") == "task-notification"
             and s.sid in (str(a.get("session_id")), str(a.get("session")))]
    return ("background command's notice" in txt or bool(leaks)), {
        "hook": first_line(txt, 200), "audit": [{k: a.get(k) for k in ("entries", "shaped")}
                                                for a in leaks][:3]}


def _notices_blocked(e: Any, s: Any) -> int:
    """How many task notifications of this session the prompt hook held back
    (audit `leak` events)."""
    return len([a for a in e.audit() if a.get("event") == "leak"
                and a.get("where") == "task-notification"
                and s.sid in (str(a.get("session_id")), str(a.get("session")))])


def _notices_seen(s: Any) -> int:
    """How many 'waiting for interactive input' notices reached the model as a
    user message (informational: a blocked one should not)."""
    n = 0
    for ev in s.events:
        if ev.get("type") == "user":
            t = json.dumps(ev.get("message", ""))
            if "waiting for interactive input" in t:
                n += 1
    return n


def notice(e: Any, C: Checks) -> None:
    """Round 4: Claude Code quotes the raw end of a background command's output
    in a 'waiting for interactive input' notice, past every output hook. The
    gateway no longer requires `2>&1 | gate scrub` (rolled back): the
    background command runs as typed, and its notice (a new prompt while
    Claude is idle) is held back by the prompt hook, as is the notice of a
    foreground command moved to the background by its timeout. A failed
    background command keeps its real exit code (no EXIT trap)."""
    g = "notice"
    s = e.session(g, "Steps:\n"
                  "1. Run this exact command with the Bash tool's run_in_background option set to "
                  f"true: {BG_STALL}\n"
                  "2. Run this exact command with the Bash tool's run_in_background option set to "
                  "true: ls ./no-such-e2e-file > bg-fail.txt 2>&1\n"
                  "3. Run this exact command in the foreground (run_in_background false) with the "
                  f"Bash tool's timeout parameter set to 4000: {STALL}\n"
                  "4. Run: echo e2e-notice-done\n"
                  "Background notices may arrive later; answer each with the single word OK.",
                  timeout=LONG)
    bg = [x for x in s.calls if x.name == "Bash" and x.input.get("run_in_background")]
    stall = next((x for x in bg if "sleep 70" in x.command), None)
    if stall is None:
        C.add(g, "a background command without `gate scrub` runs (no scrub rule)", None, "no such call")
    else:
        C.add(g, "a background command without `gate scrub` runs (no scrub rule)", not stall.denied,
              first_line(stall.result, 300))
    fail = next((x for x in bg if "no-such-e2e-file" in x.command), None)
    raw = s.stream_path.read_text(errors="replace")
    C.add(g, "a failing background command runs, and Claude Code reports its real exit code",
          fail is not None and not fail.denied and re.search(r"(?i)exit code [1-9]", raw) is not None
          and not re.search(r"(?i)no-such-e2e-file[^\n]{0,300}exit code 0", raw),
          {"denied": getattr(fail, "denied", None),
           "codes": sorted(set(re.findall(r"(?i)exit code \d+", raw)))[:6]})
    ok, detail = _notice_blocked(e, s)
    C.add(g, "the background command's 'waiting for input' notice (raw stored values) was held "
             "back by the prompt hook while Claude was idle", stall is not None and ok, detail)
    fg = s.find("sleep 75")
    if fg is None:
        C.add(g, "the foreground stall ran and was moved to the background", None, "not run")
    else:
        C.add(g, "the foreground stall ran (moved to the background by its timeout)",
              not fg.denied, first_line(fg.result.replace(e.api_key, "<KEY>")
                                        .replace(e.remote_pw, "<PW>"), 200))
        C.add(g, "both notices were held back (the background and the moved foreground command)",
              _notices_blocked(e, s) >= 2, _notices_blocked(e, s))
    C.add(g, "no such notice reached the model (informational)", _notices_seen(s) == 0,
          _notices_seen(s))


def midturn(e: Any, C: Checks) -> None:
    """Round 4: the same notice arriving while a foreground command runs goes
    to the model as a queued attachment; it passes the prompt hook too."""
    g = "midturn"
    s = e.session(g, "Steps:\n"
                  "1. Run this exact command in the foreground (run_in_background false) with the "
                  f"Bash tool's timeout parameter set to 4000: {STALL}\n"
                  "2. Run this exact command in the foreground with the default timeout (it takes "
                  "about a minute): perl -e 'sleep 60'\n"
                  "3. Run: echo e2e-midturn-done\n"
                  "Background notices may arrive later; answer each with the single word OK.",
                  timeout=LONG)
    c = s.find("perl -e")
    C.add(g, "a long foreground command ran while the notice came", c is not None and not c.denied,
          first_line(c.result, 200) if c else "not run")
    ok, detail = _notice_blocked(e, s)
    C.add(g, "the notice that came mid-turn (raw stored values) was held back by the prompt hook",
          ok, detail)
    C.add(g, "no such notice reached the model (informational)", _notices_seen(s) == 0,
          _notices_seen(s))


# ---------------------------------------------------------------------------
# jobs (optional): checkpoint's job_start with the gateway
# ---------------------------------------------------------------------------

JOB_TOOL = "mcp__plugin_check_jobs__job_start"
JOB_DRIVER = (
    "You are an end-to-end test driver for Claude Code plugins, working in a scratch test folder "
    "with local test servers on 127.0.0.1. Do exactly what the user message lists, in order. Each "
    "job step is ONE call of the tool mcp__plugin_check_jobs__job_start with exactly the given "
    "name and command (or, when the step gives an argv list instead, that list as the argv "
    "field and no command; the command or list character for character: never rewrite it, quote "
    "it differently, split it, add flags or add commands), redo_hint \"rerun\" and no other "
    "fields. If that tool's schema is not loaded yet, load it once with ToolSearch (query "
    "\"select:mcp__plugin_check_jobs__job_start,mcp__plugin_check_jobs__job_tail\"). Never use "
    "the Bash tool. If a step is denied, refused or fails, do not retry it and do not try "
    "anything else instead; go on to the next step. Do not wait for jobs and do not poll them "
    "unless a step says so. When every step is done, reply with the single word DONE.")
MULTIPLEX_RACE = "already exists, disabling multiplexing"
# The session's project instructions (ROOT/work/CLAUDE.md, only for this
# session): what the folder and the hosts are and what the task is, so Claude
# Code's auto-mode classifier, which decides every job_start (the gateway
# never approves a job), sees the user's intent. Facts only, no instructions
# to the classifier.
JOBS_PROJECT = """\
# Gateway + checkpoint end-to-end test

This folder is a scratch project made by the gateway plugin's end-to-end test
suite (tests/e2e/run_e2e.py), which the user runs on their own machine to test
their two Claude Code plugins, gateway and checkpoint, together.

- e2ehost, e2enosudo, e2ejump, e2ebehind and e2eask are hosts in the user's
  test gateway.toml for this run: OpenSSH servers the suite started on
  127.0.0.1 with keys it generated, logging in as the user's own account. Their
  sudo is a test fake that only checks a generated password. e2eask points at
  a closed port.
- notes.txt and the API key, tokens and passwords of this run are fake values
  the suite generated, so it can check that the gateway masks them.
- The task: run the listed steps as checkpoint jobs (job_start) to test how the
  gateway treats jobs: its stand-ins (ssh with the stored test key, remote sudo
  through its askpass) and its refusals. Some steps are meant to be refused by
  the gateway (curl, the "ask" host e2eask, the gateway's private folder); the
  suite checks those refusals afterwards.
"""
NOT_REACHED_CLASSIFIER = CLASSIFIER_SKIP      # how Checks counts them


def _ck_registry(home: Path) -> dict[str, Any]:
    try:
        return json.loads((home / "jobs.json").read_text()).get("jobs", {})
    except (OSError, ValueError):
        return {}


def _ck_job(home: Path, name: str) -> dict[str, Any] | None:
    recs = [r for r in _ck_registry(home).values() if r.get("name") == name]
    return recs[-1] if recs else None


def _ck_files(rec: dict[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    if rec is None:
        return out
    d = Path(rec["log"]).parent
    for f in ("output.log", "exit_code", "gateway_env"):
        with contextlib.suppress(OSError):
            out[f] = (d / f).read_text(errors="replace")
    return out


def _ck_wait(home: Path, names: list[str], timeout: float = 60) -> None:
    t0 = time.time()
    while time.time() - t0 < timeout:
        recs = [_ck_job(home, n) for n in names]
        if all(r is None or Path(r["exit_file"]).exists() for r in recs):
            return
        time.sleep(0.5)


def _job_call(s: Session, name: str) -> Any:
    """The job_start call named `name` to judge. The model may retry a step
    (the last job record with the name is the one judged, _ck_job): the last
    call that wasn't denied (the job that ran), else the last one denied by
    anything but Claude Code's classifier (the gateway's hook), else the last
    call (every one was the classifier's: "not reached"); None if none."""
    cs = [c for c in s.calls if c.name == JOB_TOOL and c.input.get("name") == name]
    for keep in (lambda c: not c.denied, lambda c: classifier_denial(c) is None):
        hit = [c for c in cs if keep(c)]
        if hit:
            return hit[-1]
    return cs[-1] if cs else None


def _no_allow(s: Session, c: Any) -> tuple[bool, dict[str, Any]]:
    """No hook answered allow for a job (the approval hook never does): it
    went to Claude Code's own permission step."""
    allow = any('"permissionDecision": "allow"' in o or '"permissionDecision":"allow"' in o
                for o in c.hook_outputs)
    info = dispatch_info(s.debug, c.id)
    return (not allow and not info.get("hook_approved")), {"stream_hook_allow": allow, **info}


def classifier_denial(c: Any) -> str | None:
    """Why Claude Code's auto-mode classifier denied this call, or None. The
    gateway's own denials come first (a PreToolUse hook error, before any
    classifier) and never count here."""
    if c is None or not c.denied:
        return None
    r = c.result or ""
    if r.startswith("PreToolUse:") or "auto mode classifier" not in r:
        return None
    m = re.search(r"Reason: (.*?)(?:\. If you have other tasks|$)", r, re.S)
    return first_line(m.group(1) if m else r, 160)


def _reached(C: Checks, g: str, name: str, c: Any, *whats: str) -> bool:
    """False (and each check in `whats` reported as not reached) when the
    model never made the call or Claude Code's classifier denied it: neither
    says anything about the gateway, which never approves a job (DECISIONS)."""
    if c is None:
        why = "the model never made this call"
    elif classifier_denial(c) is not None:
        why = (f"{NOT_REACHED_CLASSIFIER}: {name} denied by Claude Code's auto-mode "
               f"classifier ({classifier_denial(c)})")
    else:
        return True
    for what in whats:
        C.add(g, what, None, why)
    return False


def _hook_ms(s: Session, needle: str) -> str:
    """How long a hook took, from Claude Code's debug log."""
    for line in s.debug.splitlines():
        if needle in line and ("finished with status" in line or "timed out" in line):
            m = re.search(r"\((\d+)ms\)\s*$", line)
            return (m.group(1) + " ms" if m else "?") + (" (timed out)" if "timed out" in line
                                                         else "")
    return "not in the debug log"


def jobs(e: Any, C: Checks) -> None:
    """checkpoint's job_start through the gateway (DECISIONS "Checkpoint jobs"),
    in one short session with both plugins: the job sources the e2e env.sh
    (stand-ins first, no agent or tokens), ssh, remote sudo and an argv job
    work with the gateway's key, the approval hook denies curl, an "ask" right
    and the private folder for job_start (never allows a job), an "ask" right
    hidden in a script is refused by the stand-in in the job wording, and
    job_tail's result is masked. Skipped without a checkpoint checkout next
    to the gateway repo.

    The gateway never approves a job, so Claude Code's auto-mode classifier
    decides every job_start the gateway doesn't deny. A job step it denies is
    reported as "not reached (classifier)": never a pass, never a gateway
    failure. The gateway's own denials come before the classifier and fail
    hard when wrong, as does every check on a job that ran."""
    import run_e2e as R
    g = "jobs"
    if e.ck is None:
        C.add(g, "skipped: no checkpoint checkout next to the gateway repo "
                 "(../checkpoint/plugins/checkpoint)", None, "the gateway needs no checkpoint")
        return
    ckenv = R.checkpoint_env(e.root)          # dies on anything outside the e2e root
    ck_home, env_sh = Path(ckenv["CHECKPOINT_HOME"]), Path(ckenv["CHECKPOINT_GATEWAY_ENV"])
    from gateway import paths
    with paths.e2e_context():
        same = (paths.checkpoint_state_dir() == ck_home and paths.env_sh_path() == env_sh)
    real_env_sh = str(R.real_home() / ".config" / "gateway" / "env.sh")
    if not C.add(g, "CHECKPOINT_HOME and CHECKPOINT_GATEWAY_ENV are the gateway's e2e state "
                    "folder and env.sh (inside the e2e root, never the real ones)",
                 same and str(env_sh) != real_env_sh, ckenv):
        return
    ck_home.mkdir(parents=True, exist_ok=True)   # the gateway's context mentions jobs then
    os.chmod(ck_home, 0o700)
    pixi = shutil.which("pixi") or str(R.real_home() / ".pixi" / "bin" / "pixi")
    r = subprocess.run([pixi, "install", "--locked", "--manifest-path", str(e.ck / "pixi.toml")],
                       capture_output=True, text=True, timeout=900,
                       env={"PATH": f"{Path(pixi).parent}:/usr/bin:/bin:/usr/sbin:/sbin",
                            "HOME": str(R.real_home()),
                            "TMPDIR": os.environ.get("TMPDIR", "/tmp")})
    if not C.add(g, "the checkpoint copy's pixi env is built", r.returncode == 0,
                 r.stderr[-300:]):
        return
    (e.work / "askscript.sh").write_text("ssh e2eask echo HIDDEN-ask\n")
    project = e.work / "CLAUDE.md"
    project.write_text(JOBS_PROJECT)
    priv = e.root / "home" / ".config" / "gateway" / "private" / "key.txt"
    base = e.api.url("").rstrip("/")
    mark = f"{e.ck}/run.py server"

    def watch() -> tuple[bool | None, str]:
        found = R.procs_naming([mark])
        if not found:
            return None, "no checkpoint server process yet"
        for pid, _ in found:
            txt = subprocess.run(["ps", "eww", "-o", "command=", "-p", str(pid)],
                                 capture_output=True, text=True).stdout
            if not txt.strip():
                continue                       # gone meanwhile
            ok, why = R.server_env_verdict(txt, str(env_sh), str(ck_home))
            if not ok:
                return False, f"pid {pid}: {why}"
        return True, f"{len(found)} checkpoint server process(es) carry the e2e values"

    n_audit = len(e.audit())
    t1 = e.sshds["target"]
    try:
        s = e.session(g, "This is the gateway's end-to-end test of checkpoint jobs (CLAUDE.md "
                      "says what this folder and the hosts are): e2ehost and e2eask are local "
                      "test servers on 127.0.0.1 started for this run, and the secrets in it are "
                      "fake. Steps:\n"
                      "1. Job step: name \"envprobe\", command: command -v ssh; sh probe.sh job\n"
                      "2. Job step: name \"jobssh\", command: ssh e2ehost echo JOBSSH-ok\n"
                      "3. Job step: name \"jobsudo\", command: ssh e2ehost sudo whoami\n"
                      f"4. Job step: name \"curljob\", command: curl -s {base}/\n"
                      "5. Job step: name \"askjob\", command: ssh e2eask echo JOBASK-x\n"
                      f"6. Job step: name \"privjob\", command: cat {priv}\n"
                      "7. Job step: name \"argvssh\", argv: [\"ssh\", \"e2ehost\", \"echo\", "
                      "\"ARGV-ok\"]\n"
                      "8. Job step: name \"hiddenask\", command: sh askscript.sh\n"
                      "9. Job step: name \"leak\", command: cat notes.txt\n"
                      "10. Call mcp__plugin_check_jobs__job_tail with name \"leak\".",
                      timeout=R.JOBS_TIMEOUT, plugins=[e.ck], extra_env=ckenv, driver=JOB_DRIVER,
                      watch=watch)
    finally:
        project.unlink(missing_ok=True)
    try:
        C.add(g, "checkpoint's MCP server ran with the e2e CHECKPOINT_HOME and "
                 "CHECKPOINT_GATEWAY_ENV (ps eww; the kill switch did not fire)",
              s.envcheck["ok"] is True, s.envcheck["detail"])
        if s.envcheck["ok"] is False:
            return
        plist = [x.get("name") for x in (s.init.get("plugins") or [])]
        C.add(g, "both plugins loaded (gate, check)", "gate" in plist and "check" in plist, plist)
        # SessionStart gives the context; when Claude Code cancels it (its 20 s
        # limit) the first prompt's hook does (no context record: prompt.sh)
        ss, ups = s.hook_text("SessionStart"), s.hook_text("UserPromptSubmit")
        took = _hook_ms(s, "launch.sh hook-session]")
        C.add(g, "the gateway's context mentions checkpoint jobs (its state folder exists)",
              "checkpoint jobs (job_start)" in ss + ups,
              {"from": "SessionStart" if "checkpoint jobs (job_start)" in ss else
               "the first prompt's hook" if "checkpoint jobs (job_start)" in ups else "neither",
               "hook-session": took, "ctx": first_line(ss, 160)})
        ran = ["envprobe", "jobssh", "jobsudo", "argvssh", "hiddenask", "leak"]
        _ck_wait(ck_home, ran, 60)
        data = e.root / "data"
        denied_by_classifier = {n: classifier_denial(_job_call(s, n)) for n in ran}
        # -- the env probe -------------------------------------------------------
        c, rec = _job_call(s, "envprobe"), _ck_job(ck_home, "envprobe")
        jf = _ck_files(rec)
        what = "envprobe: job_start not denied, the job ran with the gateway env applied"
        what2 = ("envprobe: the job runs in the gateway env (stand-ins first on PATH, git "
                 "include, GIT_SSH_COMMAND/RSYNC_RSH, SSH_AUTH_SOCK and GITHUB_TOKEN unset)")
        if _reached(C, g, "job_start envprobe", c, what, what2):
            C.add(g, what,
                  not c.denied and rec is not None
                  and jf.get("gateway_env", "").strip() == "applied"
                  and rec.get("gateway_env_file") == str(env_sh)
                  and jf.get("exit_code", "").strip() == "0",
                  {"result": first_line(getattr(c, "result", ""), 200),
                   "rec": {k: (rec or {}).get(k) for k in ("gateway_env", "gateway_env_file")},
                   "files": {k: first_line(v, 120) for k, v in jf.items()}})
            got = _probe(e.work / "out-job.txt")
            want = {"path_first": str(data / "bin"), "ssh": str(data / "bin" / "ssh"),
                    "sudo": str(data / "bin" / "sudo"),
                    "git_include": str(data / "git" / "config"),
                    "git_ssh_command": str(data / "bin" / "ssh"),
                    "rsync_rsh": str(data / "bin" / "ssh"), "ssh_auth_sock": "",
                    "github_token": ""}
            diff = {k: (got.get(k), v) for k, v in want.items() if got.get(k) != v}
            C.add(g, what2, bool(got) and not diff,
                  diff or got or first_line(jf.get("output.log", ""), 200))
        if c is not None:
            ok, det = _no_allow(s, c)
            C.add(g, "envprobe: no hook answered allow for the job (Claude Code's own "
                     "permission step decided)", ok, det)
        # -- ssh, remote sudo, argv ----------------------------------------------
        uses = [a for a in e.audit()[n_audit:] if a.get("event") == "use"]
        for name, needle in (("jobssh", "JOBSSH-ok"), ("argvssh", "ARGV-ok")):
            c, rec = _job_call(s, name), _ck_job(ck_home, name)
            jf = _ck_files(rec)
            what = (f"{name}: the job ran ssh with the gateway's key ({needle}, exit 0, gateway "
                    "env applied)" + (", from an argv list" if name == "argvssh" else ""))
            what2 = f"{name}: audit has the ssh credential use for e2ehost"
            if not _reached(C, g, f"job_start {name}", c, what, what2):
                continue
            C.add(g, what,
                  rec is not None and needle in jf.get("output.log", "")
                  and jf.get("exit_code", "").strip() == "0"
                  and jf.get("gateway_env", "").strip() == "applied"
                  and (name != "argvssh" or "argv" in c.input),
                  {"input": c.input, "denied": c.denied,
                   "log": first_line(jf.get("output.log", ""), 200), "exit": jf.get("exit_code")})
            C.add(g, what2,
                  any(a.get("tool") == "ssh" and a.get("target") == "e2ehost"
                      and needle in str(a.get("argv")) for a in uses),
                  [{k: a.get(k) for k in ("tool", "target", "argv")} for a in uses][-6:])
        c, rec = _job_call(s, "jobsudo"), _ck_job(ck_home, "jobsudo")
        what = "jobsudo: remote sudo through the staged askpass (the user in the log, exit 0)"
        what2 = "jobsudo: nothing left in the remote staging folder"
        if _reached(C, g, "job_start jobsudo", c, what, what2):
            jf = _ck_files(rec)
            runs = [x for x in t1.sudo.log() if x.get("ran") == ["whoami"]]
            C.add(g, what,
                  rec is not None and e.user in jf.get("output.log", "")
                  and jf.get("exit_code", "").strip() == "0" and bool(runs)
                  and runs[-1].get("how") == "A" and runs[-1].get("code") == 0,
                  {"log": first_line(jf.get("output.log", ""), 200), "exit": jf.get("exit_code"),
                   "sudo": runs[-1:] or t1.sudo.log()[-3:]})
            C.add(g, what2, not any(t1.xdg.iterdir()), [x.name for x in t1.xdg.iterdir()])
        logs = {n: _ck_files(_ck_job(ck_home, n)).get("output.log", "") for n in ran}
        what = ("no job printed OpenSSH's \"ControlSocket ... already exists\" (parallel "
                "ssh calls share one master)")
        if any(logs.get(n) for n in ("jobssh", "jobsudo", "argvssh")):
            C.add(g, what, not any(MULTIPLEX_RACE in v for v in logs.values()),
                  {n: first_line(v, 160) for n, v in logs.items() if MULTIPLEX_RACE in v})
        else:
            C.add(g, what, None, "no ssh job ran: " + json.dumps(
                {n: denied_by_classifier.get(n) for n in ("jobssh", "jobsudo", "argvssh")}))
        # -- denied for job_start: the gateway's hook, before any classifier ------
        for name, needle in (("curljob", "gateway: use the http tool"),
                             ("askjob", 'a job can\'t use the "ask" right for ssh on e2eask'),
                             ("privjob", "gateway:")):
            c, rec = _job_call(s, name), _ck_job(ck_home, name)
            if c is None:
                C.add(g, f"{name}: denied", None, "the model never made this call")
                continue
            C.add(g, f"{name}: job_start denied by the gateway ({needle!r}), no job created",
                  c.denied and needle in c.result and rec is None
                  and (name != "privjob" or "private" in c.result),
                  {"denied": c.denied, "result": first_line(c.result, 300),
                   "job": (rec or {}).get("id")})
        C.add(g, "curljob: the local API saw no request",
              not [x for x in e.api.rec.requests if x["path"] == "/"], len(e.api.rec.requests))
        # -- an "ask" right hidden in a script: the stand-in's job wording --------
        c, rec = _job_call(s, "hiddenask"), _ck_job(ck_home, "hiddenask")
        what = ("hiddenask: the ssh stand-in in the job refuses the \"ask\" right in the job "
                "wording (not \"run it as its own command so Claude Code can ask you\")")
        if _reached(C, g, "job_start hiddenask", c, what):
            log = _ck_files(rec).get("output.log", "")
            job_msg = ('gateway: a job can\'t use the "ask" right for ssh on e2eask (nobody can '
                       "be asked while it runs); run it with the Bash tool as its own command, "
                       "or ask the user to set it to true.")
            refs = [a for a in e.audit()[n_audit:] if a.get("event") == "refusal"
                    and a.get("target") == "e2eask" and a.get("tool") == "ssh"]
            C.add(g, what,
                  rec is not None and job_msg in log and "so Claude Code can ask you" not in log
                  and "HIDDEN-ask" not in log and any(a.get("reason") == job_msg for a in refs),
                  {"log": first_line(log, 300), "audit": [a.get("reason") for a in refs][:2]})
        # -- job_tail masked ---------------------------------------------------------
        tl = [x for x in s.calls if x.name == "mcp__plugin_check_jobs__job_tail"]
        what = "job_tail of a job that printed stored values comes back masked"
        if (_reached(C, g, "job_start leak", _job_call(s, "leak"), what)
                and _reached(C, g, "job_tail", tl[0] if tl else None, what)):
            res = tl[0].result
            C.add(g, what, "***" in res and e.api_key not in res and e.remote_pw not in res,
                  first_line(res.replace(e.api_key, "<KEY>").replace(e.remote_pw, "<PW>"), 300))
        # -- what stays on disk -------------------------------------------------------
        forms = {"e2eapi key": secret_forms(e.api_key),
                 "e2ehost sudo password": secret_forms(e.remote_pw),
                 "planted GITHUB_TOKEN": secret_forms(e.planted_gh)}
        joblogs = [x for x in sorted(ck_home.glob("jobs/*/output.log"))
                   if not x.parent.name.startswith("leak-")]   # its raw log: a known limit
        hits = scan(joblogs + [ck_home / "jobs.json", e.work / "out-job.txt"], forms)
        what = "no planted secret in the other job logs, checkpoint's registry or the probe"
        if joblogs or hits:
            C.add(g, what, not hits, hits[:6] or [str(x) for x in joblogs][:3])
        else:
            C.add(g, what, None, "no job ran (see the not-reached steps above)")
        regs = list(_ck_registry(ck_home).values())
        what = "no job named the real ~/.config/gateway/env.sh"
        if regs:
            C.add(g, what, all(x.get("gateway_env_file") in (None, str(env_sh)) for x in regs),
                  sorted({str(x.get("gateway_env_file")) for x in regs}))
        else:
            C.add(g, what, None, "no job ran (see the not-reached steps above)")
    finally:
        for rec in _ck_registry(ck_home).values():        # jobs run in their own groups
            if not Path(rec["exit_file"]).exists():
                with contextlib.suppress(OSError, KeyError, ValueError):
                    os.killpg(int(rec["pgid"]), signal.SIGTERM)


SCENARIOS = {"context": context, "ssh": ssh, "git": git, "web": web, "refuse": refuse,
             "default": default, "leak": leak, "notice": notice, "midturn": midturn,
             "jobs": jobs}


def run_all(e: Any, C: Checks, only: list[str]) -> None:
    for name in only:
        fn = SCENARIOS.get(name)
        if fn is None:
            C.add("suite", f"unknown scenario {name}", False)
            continue
        try:
            fn(e, C)
        except Exception as ex:  # noqa: BLE001
            import traceback
            traceback.print_exc()
            C.add(name, "scenario ran to the end", False, f"{type(ex).__name__}: {ex}")
        s = e.sessions.get(name)
        if s is not None:
            C.add(name, f"session finished in time ({s.seconds:.0f} s, limit {s.limit:.0f} s)",
                  not s.timed_out and s.result.get("subtype") is not None,
                  {"rc": s.rc, "result": first_line(str(s.result.get("result", "")), 120),
                   "cost": s.result.get("total_cost_usd")})


def final_checks(e: Any, C: Checks) -> None:
    if not e.sessions:
        return
    forms = {
        "e2e-personal token": secret_forms(e.tok_personal, ("x-access-token", "e2euser")),
        "e2e-work token": secret_forms(e.tok_work, ("x-access-token", "e2e-worker")),
        "e2eapi key": secret_forms(e.api_key),
        "e2ehost sudo password": secret_forms(e.remote_pw),
        "planted GITHUB_TOKEN": secret_forms(e.planted_gh),
    }
    for host, priv in e.host_keys.items():
        forms[f"{host} ssh private key"] = secret_forms(priv)
    streams = [s.stream_path for s in e.sessions.values()]
    trans = e.transcripts()
    audit = [e.root / "data" / "audit.jsonl"]
    C.add("secrets", "transcripts of the e2e sessions were found",
          len(trans) >= len(e.sessions), [str(p) for p in trans][:8])
    for label, files in (("stream-json", streams), ("transcript files", trans),
                         ("audit log", audit)):
        hits = scan(files, forms)
        C.add("secrets", f"no planted secret (or its base64/URL forms) in the {label}",
              not hits, hits[:10])
    hits = scan([s.debug_path for s in e.sessions.values()], forms)
    C.add("secrets", "no planted secret in Claude Code's debug logs (informational)",
          not hits, hits[:10])
    calls = e.dialog.calls()
    C.add("secrets", "no pop-up was needed (the fake dialog saw no call)", not calls,
          [{k: c.get(k) for k in ("kind", "title")} for c in calls][:5])
