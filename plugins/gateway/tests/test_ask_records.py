"""An "ask" is proved by a record, for every stand-in (lead decision 19.14,
invariant 6). The Bash hook writes a record for each stand-in stage it
answers "ask" for (ssh, sudo, the account CLIs, git: asks.record), with the
Claude Code process, the real folder, the tool and its exact words and the
entries it asked about; a stand-in passes an "ask" only for a command Claude
typed that matches one, used once, within 15 minutes (asks.take,
asks.standin). A sourced script, eval or a function reaches no record, so the
hook no longer asks about commands that hide what they run (only about a
named configured target), and nothing forwards every call to the hook any
more: `source .venv/bin/activate && pytest` gets no decision. An account's
use = "ask" works for its CLI as it does for git. The ssh stand-in's own
tests (a real process tree, a real sshd) are in test_ssh_ask, the sudo
stand-in's in test_sudo_standin."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import harness as H
import harness_accounts as HA
from gateway import ancestry, asks, consent, hooks_bash, paths, vault

HOST = '[hosts.box]\naddress = "octo@box.example.com"\n'
LOCAL_ASK = '[hosts.localhost]\nsudo = "ask"\n'
GH_ASK = '[accounts.gh]\nkind = "github"\nlogin = "octocat"\nuse = "ask"\n'
GHTOK = "ghp_ASKtoken0123456789abcdefghij"


def _approved(env: H.GatewayEnv, text: str) -> None:
    env.write_form(text)
    if not vault.exists():
        vault.save(vault.empty())
    consent.approve_all(env.form())


def _hook(cmd: str, cwd: Path | str | None, mode: str = "default", tool: str = "Bash"
          ) -> dict[str, Any] | None:
    p: dict[str, Any] = {"tool_name": tool, "tool_input": {"command": cmd},
                         "permission_mode": mode}
    if cwd is not None:
        p["cwd"] = str(cwd)
    out = hooks_bash.main(p)
    return out["hookSpecificOutput"] if out else None


def _dec(h: dict[str, Any] | None) -> str | None:
    return h["permissionDecision"] if h else None


def _records() -> list[tuple[str, dict[str, Any]]]:
    d = asks._dir()
    if not d.is_dir():
        return []
    return [(p.name, json.loads(p.read_text())) for p in sorted(d.iterdir())
            if not p.name.startswith(".")]


def _clear() -> None:
    for name, _r in _records():
        (asks._dir() / name).unlink()


def _has(tool: str, cwd: Path | str, words: list[str], entry: str) -> bool:
    """Is there a record for TOOL WORDS in cwd covering entry ("hosts/box")?
    (Taken, so a test checks each record once.)"""
    s, e = entry.split("/", 1)
    return asks.take(tool, asks.session(), str(cwd), words, [(s, e)]) == "ok"


# ---------------------------------------------------------------------------
# The record itself
# ---------------------------------------------------------------------------

def test_a_record_is_this_very_command_used_once_and_for_15_minutes():
    with H.gateway_env() as env:
        here, there = env.root / "a", env.root / "b"
        here.mkdir()
        there.mkdir()
        me = asks.session()
        asks.record("ssh", me, str(here), ["box", "uptime"], [("hosts", "box")])
        for tool, sess, cwd, words, ent in (
                ("sudo", me, here, ["box", "uptime"], ("hosts", "box")),    # another tool
                ("ssh", "1@2", here, ["box", "uptime"], ("hosts", "box")),  # another Claude Code
                ("ssh", me, there, ["box", "uptime"], ("hosts", "box")),    # another folder
                ("ssh", me, here, ["box", "id"], ("hosts", "box")),         # other words
                ("ssh", me, here, ["box", "uptime"], ("hosts", "other"))):  # not asked about
            assert asks.take(tool, sess, str(cwd), words, [ent]) == "none", (tool, sess, cwd, words)
        assert asks.take("ssh", me, str(here), ["box", "uptime"], [("hosts", "box")]) == "ok"
        assert asks.take("ssh", me, str(here), ["box", "uptime"], [("hosts", "box")]) == "none", \
            "used once"
        # the real folder: a symlink to it counts as it
        (env.root / "link").symlink_to(here)
        asks.record("ssh", me, str(env.root / "link"), ["box"], [("hosts", "box")])
        assert asks.take("ssh", me, str(here), ["box"], [("hosts", "box")]) == "ok"
        # older than 15 minutes: "expired", and the refusal says so
        asks.record("ssh", me, str(here), ["box", "uptime"], [("hosts", "box")])
        (name, rec), = _records()
        rec["t"] -= asks.ASK_TTL + 5
        (asks._dir() / name).write_text(json.dumps(rec))
        got = asks.take("ssh", me, str(here), ["box", "uptime"], [("hosts", "box")])
        assert got == "expired"
        assert "more than 15 minutes" in asks.refusal(got, ["ssh on box"], "ssh box ...")
        msg = asks.refusal("none", ["ssh on box"], "ssh box ...")
        assert "didn't ask you about this command" in msg and \
            "run `ssh box ...` as its own command" in msg, msg
        # dated more than a minute ahead (not this hook's): no match
        _clear()
        asks.record("ssh", me, str(here), ["box", "uptime"], [("hosts", "box")])
        (name, rec), = _records()
        rec["t"] += 3600
        (asks._dir() / name).write_text(json.dumps(rec))
        assert asks.take("ssh", me, str(here), ["box", "uptime"], [("hosts", "box")]) == "none"
        _clear()
        # records are 0600 in the 0700 run folder
        asks.record("ssh", me, str(here), ["x"], [("hosts", "box")])
        assert oct(asks._dir().stat().st_mode & 0o777) == oct(0o700)
        assert all(oct((asks._dir() / n).stat().st_mode & 0o777) == oct(0o600)
                   for n, _r in _records())


def test_a_stand_in_takes_its_record_once_per_call():
    """asks.standin: the stand-in's own command (this folder, this Claude
    Code); one call meets several "ask" decisions for the entries the hook
    asked about (an ssh right and a remote sudo), the record is taken at the
    first and the next call needs a new one."""
    with H.gateway_env() as env:
        old = os.getcwd()
        os.chdir(env.root)
        try:
            asks.reset()
            assert asks.standin("ssh", ["box", "sudo", "id"], ("hosts", "box")) == "none"
            asks.record("ssh", asks.session(), str(env.root), ["box", "sudo", "id"],
                        [("hosts", "box")])
            asks.reset()
            assert asks.standin("ssh", ["box", "sudo", "id"], ("hosts", "box")) == "ok"
            assert asks.standin("ssh", ["box", "sudo", "id"], ("hosts", "box")) == "ok"
            assert asks.standin("ssh", ["box", "sudo", "id"], ("hosts", "other")) == "none"
            assert _records() == []
            asks.reset()                          # the next stand-in call
            assert asks.standin("ssh", ["box", "sudo", "id"], ("hosts", "box")) == "none"
            # an error while looking fails closed
            asks.record("ssh", asks.session(), str(env.root), ["box", "id"], [("hosts", "box")])
            asks.reset()
            real = asks._take

            def broken(*a: Any, **k: Any) -> Any:
                raise OSError("unreadable")
            asks._take = broken                   # type: ignore[assignment]
            try:
                assert asks.standin("ssh", ["box", "id"], ("hosts", "box")) == "none"
            finally:
                asks._take = real                 # type: ignore[assignment]
            # the gate CLI's own command (gate.main: asks.begin)
            asks.begin("gate", ["check", "box"])
            assert asks.current(("hosts", "box")) == "none"
            asks.record("gate", asks.session(), str(env.root), ["check", "box"],
                        [("hosts", "box")])
            asks.begin("gate", ["check", "box"])
            assert asks.current(("hosts", "box")) == "ok"
            assert asks.current(("hosts", "other")) == "none"
            asks._CURRENT.clear()
            assert asks.current(("hosts", "box")) == "none", "no command begun: nothing"
            _clear()
        finally:
            os.chdir(old)


# ---------------------------------------------------------------------------
# The Bash hook writes one for each stand-in stage it asks about
# ---------------------------------------------------------------------------

def test_the_hook_records_each_stand_in_stage_it_asks_about():
    with H.gateway_env() as env:
        proj = env.root / "proj"
        (proj / "sub").mkdir(parents=True)
        _approved(env, HOST + 'ssh = "ask"\n' + LOCAL_ASK)
        assert _dec(_hook("ssh box uptime", proj)) == "ask"
        assert _has("ssh", proj, ["box", "uptime"], "hosts/box")
        assert _dec(_hook("sudo apt update && cd sub && ssh box 'sudo id'", proj)) == "ask"
        assert _has("sudo", proj, ["apt", "update"], "hosts/localhost")
        assert _has("ssh", proj / "sub", ["box", "sudo id"], "hosts/box")
        assert _records() == []
        # the words as the shell hands them over: quotes gone, `~/` and an
        # unquoted $HOME the home, a single-quoted $HOME as written
        home = paths.user_home()
        assert _dec(_hook("ssh box cat ~/a \"$HOME/b\" '$HOME/c'", proj)) == "ask"
        assert _has("ssh", proj, ["box", "cat", f"{home}/a", f"{home}/b", "$HOME/c"], "hosts/box")
        # wrappers that exec the stand-in: the words after them
        assert _dec(_hook("nice -n 5 ssh box uptime", proj)) == "ask"
        assert _has("ssh", proj, ["box", "uptime"], "hosts/box")
        # Monitor too; never for a deny, an answer that isn't "ask", the user's
        # Terminal panel (no stand-in typed by Claude there) or a job
        assert _dec(_hook("ssh box uptime", proj, tool="Monitor")) == "ask"
        assert _has("ssh", proj, ["box", "uptime"], "hosts/box")
        assert _dec(_hook("ssh box uptime && cat ~/.config/gateway/private/key.txt", proj)) == \
            "deny"
        _hook("ssh box uptime", proj, tool="mcp__terminal__run_in_terminal")
        _hook("ssh box uptime", proj, tool="mcp__plugin_check_jobs__job_start")
        assert _records() == []
        # nothing "ask": no prompt, no record
        _approved(env, HOST + "ssh = true\n")
        assert _dec(_hook("ssh box uptime", proj)) is None and _records() == []
        # a remote sudo or an "ask" policy restriction counts as the host's entry
        _approved(env, HOST + "ssh = true\n[hosts.box.policy]\nexec = \"ask\"\n")
        assert _dec(_hook("ssh box uptime", proj)) == "ask"
        assert _has("ssh", proj, ["box", "uptime"], "hosts/box")


def test_words_or_a_folder_the_hook_cant_spell_out_are_refused_up_front():
    """The stand-in would refuse after the prompt (no record matches): a
    variable or glob in the words, `~user`, or a folder a `cd` hides. (An
    ssh word with a variable is refused already as hiding its host while
    the text names it.)"""
    with H.gateway_env() as env:
        proj = env.root / "proj"
        proj.mkdir()
        _approved(env, HOST + 'ssh = "ask"\n' + LOCAL_ASK)
        for cmd, why in (('ssh box "$CMD"', "its text names box"),
                         ("ssh box ls *.txt", "can't spell out"),
                         ("ssh box ls {a,b}", "can't spell out"),
                         ('sudo cat "$F"', "can't spell out"),
                         ("sudo cat ~root/x", "can't spell out"),
                         ("sudo env X=~/y make", "can't spell out")):
            h = _hook(cmd, proj)
            assert _dec(h) == "deny", (cmd, h)
            assert why in h["permissionDecisionReason"], (cmd, h)
        h = _hook('cd "$D" && ssh box uptime', proj)
        assert _dec(h) == "deny" and "which folder" in h["permissionDecisionReason"], h
        assert _records() == []


def test_text_the_parser_cant_follow_is_recorded_where_it_can_be_read():
    """A command the parser gives up on that names an "ask" target is asked
    about (the named configured target) with records for the ssh and sudo
    commands the hook can read in its text (a here-document, the background,
    a subshell, eval's or a shell's written-out string, trap's action), and
    refused where it can't (a variable or $(...) in the words: the stand-in
    would refuse after the prompt)."""
    with H.gateway_env() as env:
        proj = env.root / "proj"
        proj.mkdir()
        _approved(env, HOST + 'ssh = "ask"\n' + LOCAL_ASK)
        for cmd, tool, words in (
                ("ssh box 'bash -s' <<'EOF'\nuptime\nEOF", "ssh", ["box", "bash -s"]),
                ("ssh box uptime &", "ssh", ["box", "uptime"]),
                ("(ssh box uptime)", "ssh", ["box", "uptime"]),
                ("ssh box uptime 2>&1 < /dev/null", "ssh", ["box", "uptime"]),
                ("eval 'sudo id'", "sudo", ["id"]),
                ("env bash -c 'ssh box uptime'", "ssh", ["box", "uptime"]),
                ("trap 'ssh box uptime' EXIT", "ssh", ["box", "uptime"]),
                ("x=$(sudo id -u)", "sudo", ["id", "-u"])):
            h = _hook(cmd, proj)
            assert _dec(h) == "ask", (cmd, h)
            entry = "hosts/localhost" if tool == "sudo" else "hosts/box"
            assert _has(tool, proj, words, entry), (cmd, _records())
            assert _records() == [], cmd
        for cmd in ('ssh box "$(cat cmd.txt)"', "for x in 1 2; do sudo echo $x; done",
                    "ssh box uptime $X &", "(sudo cat ~root/x)"):
            h = _hook(cmd, proj)
            assert _dec(h) == "deny" and "can't spell out" in h["permissionDecisionReason"], \
                (cmd, h)
        assert _records() == []


# ---------------------------------------------------------------------------
# A record lives until the session's next Bash or Monitor call
# ---------------------------------------------------------------------------

def _sourced_sudo(env: H.GatewayEnv, name: str, *args: str) -> Path:
    """A script whose one line is the sudo stand-in's `sudo ARGS` (the
    harness's driver), for `. script` in Claude's shell."""
    import shlex
    import harness_sudo as HS
    files = HS.write_drivers(env)
    script = env.root / name
    script.write_text(" ".join(shlex.quote(a) for a in [HS.PY, "-I", str(files["driver"]), "sudo",
                                                        str(env.root), *args]) + "\n")
    return script


def test_a_record_left_by_an_earlier_call_serves_nothing_after_it():
    """The reviewer's MF1: the hook writes its record when it answers "ask",
    before the user decides. A record left by a prompt the user declined, or
    by a stage that never ran (`false && sudo ...`), used to serve the same
    words from a sourced file (which gets no decision) for 15 minutes. Now
    the session's next Bash or Monitor call drops it before anything of that
    call runs."""
    import shlex
    import harness_sudo as HS
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo='"ask"')
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        here = os.getcwd()
        # the user declines `sudo echo replay`: nothing runs; then Claude
        # sources a script whose line is that very sudo
        assert _dec(_hook("sudo echo replay", here)) == "ask" and len(_records()) == 1
        script = _sourced_sudo(env, "x.sh", "echo", "replay")
        assert _hook(f". {script}", here) is None
        assert _records() == [], "the next call dropped the declined prompt's record"
        r = HS.run_sudo_from_shell(env, fake, f". {shlex.quote(str(script))}")
        assert r.returncode != 0 and "replay" not in r.stdout, (r.stdout, r.stderr)
        assert "didn't ask you about this command" in r.stderr, r.stderr
        # a stage that never ran: `false && sudo echo later`, then a sourced one
        assert _dec(_hook("false && sudo echo later", here)) == "ask"
        script = _sourced_sudo(env, "y.sh", "echo", "later")
        assert _hook(f". {script}", here, tool="Monitor") is None and _records() == []
        r = HS.run_sudo_from_shell(env, fake, f". {shlex.quote(str(script))}")
        assert r.returncode != 0 and "later" not in r.stdout, (r.stdout, r.stderr)
        # the asked command itself still runs after the OK (the stand-in takes it)
        assert _dec(_hook("sudo echo asked", here)) == "ask"
        r = HS.run_sudo_from_shell(env, fake, "{sudo}", "echo", "asked")
        assert r.returncode == 0 and r.stdout == "asked\n", (r.stdout, r.stderr)
        # a job, the Terminal panel or another tool's call leaves this
        # session's records alone (only Bash and Monitor, whose commands a
        # record can serve, drop them)
        assert _dec(_hook("sudo echo replay", here)) == "ask"
        _hook("sudo echo replay", here, tool="mcp__terminal__run_in_terminal")
        _hook("ls", here, tool="mcp__plugin_check_jobs__job_start")
        assert len(_records()) == 1


def test_dontask_asks_too_so_the_record_is_written_and_the_command_runs_after_the_ok():
    """verify012 bug B: Claude Code (2.1.310) shows a hook's "ask" in dontAsk
    too, but the hook wrote no record there, so after the user's Yes the
    stand-in refused ("didn't ask you"). The record is written in dontAsk as
    in every other mode; a declined prompt's record is dropped by the next
    call as usual."""
    import harness_sudo as HS
    with H.gateway_env() as env:
        HS.setup_localhost(env, sudo='"ask"')
        fake = H.make_fake_sudo(env.root / "fsudo", nopasswd=True)
        here = os.getcwd()
        h = _hook("sudo echo dontask", here, mode="dontAsk")
        assert _dec(h) == "ask" and len(_records()) == 1, (h, _records())
        r = HS.run_sudo_from_shell(env, fake, "{sudo}", "echo", "dontask")
        assert r.returncode == 0 and r.stdout == "dontask\n", (r.stdout, r.stderr)
        assert _records() == [], "used once"
        assert _dec(_hook("sudo echo declined", here, mode="dontAsk")) == "ask"
        assert _hook("ls", here, mode="dontAsk") is None and _records() == []


def test_drop_takes_this_sessions_records_and_dead_ones_only():
    """asks.drop: this Claude Code's records, and any no stand-in could take
    (older than 15 minutes, dated ahead, unreadable, a stale half-written
    file); another session's live record stays (its own next call drops
    it)."""
    with H.gateway_env() as env:
        here = str(env.root)
        me = asks.session()
        asks.record("ssh", me, here, ["box", "a"], [("hosts", "box")])
        asks.record("ssh", "1@2", here, ["box", "b"], [("hosts", "box")])
        for words, shift in ((["box", "old"], -asks.ASK_TTL - 5), (["box", "ahead"], 3600)):
            asks.record("ssh", "1@2", here, words, [("hosts", "box")])
            p = asks._dir() / _name_of("ssh", "1@2", here, words)
            rec = json.loads(p.read_text())
            rec["t"] += shift
            p.write_text(json.dumps(rec))
        (asks._dir() / "junk.x").write_text("not json")
        tmp = asks._dir() / ".half.tmp"
        tmp.write_text("{")
        os.utime(tmp, (time.time() - 120, time.time() - 120))
        assert asks.drop() is True
        left = [rec for _n, rec in _records()]
        assert len(left) == 1 and left[0]["s"] == "1@2", left
        assert asks.take("ssh", "1@2", here, ["box", "b"], [("hosts", "box")]) == "ok"
        assert not tmp.exists()
        # nothing there (no folder at all): nothing to do
        shutil.rmtree(asks._dir())
        assert asks.drop() is True
        # a record that can't be removed: False, and the hook refuses the call
        asks.record("ssh", me, here, ["box", "a"], [("hosts", "box")])
        real = os.unlink

        def stuck(p: Any, *a: Any, **k: Any) -> None:
            if str(p).startswith(str(asks._dir())):
                raise PermissionError(p)
            real(p, *a, **k)
        os.unlink = stuck                                  # type: ignore[assignment]
        try:
            assert asks.drop() is False
            h = _hook("ls", here)
            assert _dec(h) == "deny" and "couldn't clear" in h["permissionDecisionReason"], h
        finally:
            os.unlink = real                               # type: ignore[assignment]
        _clear()


def _name_of(tool: str, sess: str, cwd: str, words: list[str]) -> str:
    """The record file of TOOL WORDS (its key prefix: asks._key)."""
    key = asks._key(tool, sess, cwd, words)
    return next(n for n, _r in _records() if n.startswith(key + "."))


def test_pre_bash_sends_every_call_to_the_hook_while_a_record_is_pending():
    """End to end through pre_bash.sh, launch.sh and run.py hook-bash: after
    an ask, `$DATA/asks` links to the records, and while one is pending a
    call without a trigger word (`. x.sh`) reaches the hook, which drops it;
    with none pending such a call costs no Python start."""
    with H.gateway_env() as env:
        rig, pre, log = _real_rig(env)
        try:
            _approved(env, LOCAL_ASK)
            r = _prefilter(env, pre, "sudo ls", mode="default")
            assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask", r
            link = env.data / asks.LINK
            assert os.path.islink(link) and Path(os.readlink(link)) == asks._dir()
            assert len(_records()) == 1
            log.unlink()
            r = _prefilter(env, pre, ". ./x.sh", mode="default")
            assert r.returncode == 0 and r.stdout == "", (r.stdout, r.stderr[-300:])
            assert log.read_text().splitlines() == ["hook-bash"], "forwarded while one was pending"
            assert _records() == []
            log.unlink()
            r = _prefilter(env, pre, ". ./x.sh", mode="default")
            assert r.stdout == "" and not log.exists(), "nothing pending: no Python start"
        finally:
            shutil.rmtree(rig, ignore_errors=True)


def test_a_hidden_stage_beside_another_ask_is_asked_about_and_recorded_too():
    """The reviewer's should-fix 3: a shell string, eval or loop beside a stage
    the hook asks about (`sudo id; env bash -c 'ssh box x'`) got a record
    only for that stage, so the hidden ssh was refused after the OK; and the
    prompt for text the parser gives up on named only the first target. Now
    both are recorded (once each) and the prompt names both."""
    with H.gateway_env() as env:
        proj = env.root / "proj"
        (proj / "sub").mkdir(parents=True)
        _approved(env, HOST + 'ssh = "ask"\n' + LOCAL_ASK)
        for cmd in ("sudo id; env bash -c 'ssh box x'", "(sudo id) && ssh box x",
                    "sudo id && trap 'ssh box x' EXIT"):
            h = _hook(cmd, proj)
            assert _dec(h) == "ask", (cmd, h)
            why = h["permissionDecisionReason"]
            assert "sudo on this machine" in why and "ssh on box" in why, (cmd, why)
            assert _has("sudo", proj, ["id"], "hosts/localhost"), (cmd, _records())
            assert _has("ssh", proj, ["box", "x"], "hosts/box"), (cmd, _records())
            assert _records() == [], (cmd, "one record each")
        # a stage the structured judge followed into another folder keeps its
        # record there; the hidden one has no folder to tell (a cd): refused
        h = _hook("cd sub && sudo id; env bash -c 'echo done'", proj)
        assert _dec(h) == "ask", h
        assert _has("sudo", proj / "sub", ["id"], "hosts/localhost") and _records() == []
        h = _hook("cd sub && sudo id; env bash -c 'ssh box x'", proj)
        assert _dec(h) == "deny" and "tell its folder" in h["permissionDecisionReason"], h


GH2 = ('[accounts.gh]\nkind = "github"\nlogin = "octocat"\ndefault = true\n'
       '[accounts.work]\nkind = "github"\nlogin = "octo-work"\nowners = ["corp"]\nuse = "ask"\n')


def test_account_cli_asks_follow_the_stand_ins_own_choice():
    """The reviewer's should-fix 4: the hook asked about every "ask" account
    covering the destination, not the one the stand-in picks, and read no
    GATE_ACCOUNT: `gh api /user` asked about `work` though the default
    account serves it (a prompt for every owner-less gh command, and a
    leftover record), `GATE_ACCOUNT=work gh pr list -R octocat/x` got no
    prompt and was then refused, and `(gh ...)` / `x=$(gh ...)` got no
    record. Now the hook asks about the account the stand-in will choose
    (clis.chosen), GATE_ACCOUNT included, and records CLI commands in text
    the parser can't follow."""
    with H.gateway_env() as env:
        proj = env.root / "proj"
        proj.mkdir()
        HA.set_direct((True, ""))
        HA.install_fakes(env, gh=HA.fake_cli(Path(env.root) / "fakebin", "gh"))
        HA.build_vault(env, GH2, tokens={"gh": GHTOK, "work": "ghp_WORKtoken0123456789abcdefghi"})
        for cmd in ("gh api /user", "gh pr list -R octocat/x", "GATE_ACCOUNT=gh gh pr list -R corp/x"):
            assert _hook(cmd, proj) is None and _records() == [], cmd
        for cmd, words in (("gh pr list -R corp/x", ["pr", "list", "-R", "corp/x"]),
                           ("GATE_ACCOUNT=work gh pr list -R octocat/x",
                            ["pr", "list", "-R", "octocat/x"]),
                           ("export GATE_ACCOUNT=work; gh api /user", ["api", "/user"]),
                           ("env GATE_ACCOUNT=work gh api /user", ["api", "/user"]),
                           ('GATE_ACCOUNT="$A" gh api /user', ["api", "/user"]),
                           ("(gh pr list -R corp/x)", ["pr", "list", "-R", "corp/x"]),
                           ("x=$(gh pr list -R corp/x)", ["pr", "list", "-R", "corp/x"]),
                           ("(GATE_ACCOUNT=work gh api /user)", ["api", "/user"])):
            h = _hook(cmd, proj)
            assert _dec(h) == "ask" and "use on work" in h["permissionDecisionReason"], (cmd, h)
            assert _has("gh", proj, words, "accounts/work"), (cmd, _records())
            assert _records() == [], cmd
        assert _hook("(gh api /user)", proj) is None and _records() == []
        h = _hook("(gh pr list -R corp/$R)", proj)
        assert _dec(h) == "deny" and "can't spell out" in h["permissionDecisionReason"], h
        # the stand-in then uses the account the prompt named
        real = _typed((True, ""))
        old = os.environ.get("GATE_ACCOUNT")
        try:
            assert _dec(_hook("GATE_ACCOUNT=work gh pr list -R octocat/x", proj)) == "ask"
            os.environ["GATE_ACCOUNT"] = "work"
            rc, out, err = HA.run_cli("gh", ["pr", "list", "-R", "octocat/x"], cwd=str(proj))
            assert rc == 0 and "ghp_WORK" not in out, err
        finally:
            ancestry.typed_by_claude = real            # type: ignore[assignment]
            if old is None:
                os.environ.pop("GATE_ACCOUNT", None)
            else:
                os.environ["GATE_ACCOUNT"] = old
        # `gate with` in text the parser can't follow: recorded too
        HA.build_vault(env, OPENAI + 'use = "ask"\n', tokens={"openai": OPENKEY})
        h = _hook("(gate with openai -- python3 x.py)", proj)
        assert _dec(h) == "ask" and "use on openai" in h["permissionDecisionReason"], h
        assert _has("gate", proj, ["with", "openai", "--", "python3", "x.py"], "accounts/openai")


# ---------------------------------------------------------------------------
# Hidden commands: no decision, nothing forwarded
# ---------------------------------------------------------------------------

EVERYDAY = ("source .venv/bin/activate && pytest", ". .venv/bin/activate",
            'eval "$(pyenv init -)"', 'bash -c "$CMD"', "deploy() { make; }; deploy",
            "ls | xargs wc -l", "find . -name '*.pyc' -exec rm {} +")


def test_hidden_commands_get_no_decision_while_an_entry_is_ask():
    """No prompt for `source .venv/bin/activate && pytest` while
    this computer's sudo (or a host's ssh) is "ask": what such a command runs
    gets no record, so a stand-in it reaches refuses the "ask" itself; one
    that names a configured target is still refused."""
    with H.gateway_env() as env:
        proj = env.root / "proj"
        proj.mkdir()
        for form in (LOCAL_ASK, HOST + 'ssh = "ask"\n',
                     HOST + 'ssh = true\n[hosts.box.policy]\nexec = "ask"\n'):
            _approved(env, form)
            for mode in ("default", "auto"):
                for cmd in EVERYDAY:
                    assert _hook(cmd, proj, mode) is None, (form, mode, cmd)
        _approved(env, HOST + 'ssh = "ask"\n')
        h = _hook("source ./deploy.sh box", proj)
        assert _dec(h) == "deny" and "its text names box" in h["permissionDecisionReason"], h
        assert not (env.data / "ask-marker").exists()


def _real_rig(env: H.GatewayEnv) -> tuple[Path, Path, Path]:
    """A plugin-shaped folder whose launch.sh logs its mode and runs the real
    launch.sh with --test, with a (fake) ready env: run.py hook-bash runs for
    real behind the real pre_bash.sh."""
    import harness_ux as U
    U.fake_ready_env(env)
    if not (paths.env_bin() / "age").exists():
        os.symlink(H.ENV_BIN / "age", paths.env_bin() / "age")   # the vault is read for real
    rig = Path(tempfile.mkdtemp(prefix="gwar-", dir=H.tmp_base()))
    hooks = rig / "hooks"
    hooks.mkdir()
    for name in ("pre_bash.sh", "e2e.sh", "home.sh"):
        (hooks / name).write_text((H.PLUGIN / "hooks" / name).read_text())
    log = rig / "launched"
    launch = H.PLUGIN / "hooks" / "launch.sh"
    (hooks / "launch.sh").write_text(f"#!/bin/sh\nprintf '%s\\n' \"$1\" >> {str(log)!r}\n"
                                     f"exec /bin/sh {str(launch)!r} \"$1\" --test\n")
    return rig, hooks / "pre_bash.sh", log


def _prefilter(env: H.GatewayEnv, pre: Path, cmd: str, mode: str = "auto"
               ) -> subprocess.CompletedProcess[str]:
    p = {"tool_name": "Bash", "tool_input": {"command": cmd}, "permission_mode": mode}
    e = env.subprocess_env({"CLAUDE_PLUGIN_DATA": str(env.data),
                            "CLAUDE_CODE_SHELL_PREFIX": str(pre.parent / "gate-sh"),
                            "CLAUDE_PROJECT_DIR": str(env.root)})
    return subprocess.run(["/bin/sh", str(pre)], input=json.dumps(p), capture_output=True,
                          text=True, timeout=60, env=e)


def test_nothing_forwards_every_call_to_the_hook_any_more():
    """End to end through pre_bash.sh, launch.sh and run.py hook-bash: with
    this computer's sudo "ask" (the README's own advice) everyday commands
    with no trigger word never start Python, and a typed `sudo ls` is asked
    about (and recorded) as before. An ask-marker file left by an older
    version changes nothing."""
    with H.gateway_env() as env:
        rig, pre, log = _real_rig(env)
        try:
            _approved(env, LOCAL_ASK)
            (env.data / "ask-marker").write_text("x\n")
            for cmd in EVERYDAY:
                r = _prefilter(env, pre, cmd)
                assert r.returncode == 0 and r.stdout == "", (cmd, r.stdout, r.stderr[-300:])
            assert not log.exists(), "nothing reached Python"
            r = _prefilter(env, pre, "sudo ls")
            assert json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask", r
            assert log.read_text().splitlines() == ["hook-bash"]
        finally:
            shutil.rmtree(rig, ignore_errors=True)


def test_pre_bash_forwards_a_plain_account_cli_while_its_stand_in_exists():
    """A plain `gh pr list` reaches the hook only while gh's stand-in exists
    ($DATA/bin/gh: a github account is configured), so its "ask" can be asked
    about and recorded; any letter case."""
    with tempfile.TemporaryDirectory(dir=H.tmp_base()) as td:
        import test_hookbash_prefilter as P
        pre, marker = P._rig(Path(td) / "rig")
        data = Path(td) / "data"
        (data / "bin").mkdir(parents=True)

        def fires(cmd: str) -> bool:
            marker.unlink(missing_ok=True)
            p = {"tool_name": "Bash", "tool_input": {"command": cmd},
                 "permission_mode": "default"}
            e = {k: v for k, v in os.environ.items() if k not in ("CLAUDE_PLUGIN_DATA",)}
            e.update(CLAUDE_PLUGIN_DATA=str(data), GATEWAY_TEST_ROOT="/nonexistent-test-root",
                     CLAUDE_CONFIG_DIR="/nonexistent-config")
            r = subprocess.run(["/bin/sh", str(pre)], input=json.dumps(p), capture_output=True,
                               text=True, timeout=20, env=e)
            assert r.returncode == 0, r.stderr
            return marker.exists()
        for cmd in ("gh pr list", "hf download x", "pijul pull"):
            assert not fires(cmd), cmd
        for name in ("gh", "hf", "databricks", "crane", "pijul"):
            (data / "bin" / name).write_text("#!/bin/sh\n")
        for cmd in ("gh pr list", "GH pr list", "hf download x", "databricks fs ls",
                    "crane ls ghcr.io/octocat/x", "pijul pull", "echo x | gh issue list"):
            assert fires(cmd), cmd
        for cmd in ("ls", "echo ghost", "git status", "cat high.txt"):
            assert not fires(cmd), cmd
        # Python's list of the CLIs an "ask" account may serve (should-fix 7):
        # only those cost a Python start; none listed, none does
        (data / "ask-clis").write_text("gh\npijul\nnot-a-cli\n")
        for cmd in ("gh pr list", "GH pr list", "pijul pull"):
            assert fires(cmd), cmd
        for cmd in ("hf download x", "databricks fs ls", "crane ls ghcr.io/octocat/x"):
            assert not fires(cmd), cmd
        (data / "ask-clis").write_text("")
        assert not fires("gh pr list")
        (data / "bin" / "gh").unlink()
        (data / "ask-clis").write_text("gh\n")
        assert not fires("gh pr list"), "no stand-in: the user's own gh, never the hook"


def test_a_call_the_records_send_to_the_hook_costs_one_python_start():
    """What the records cost a call, on the real path (pre_bash.sh, launch.sh,
    run.py hook-bash): a plain `gh` with no "ask" account is sh only; with
    one (ask-clis lists gh) and a call without a trigger word while a record
    is pending each take one Python start. The medians are printed for
    TESTING.md; the bounds catch only a pathological slowdown."""
    import statistics
    with H.gateway_env() as env:
        rig, pre, log = _real_rig(env)
        proj = env.root / "proj"
        proj.mkdir()
        try:
            def median(cmd: str, before: Any = None, n: int = 5) -> float:
                ts = []
                for _ in range(n):
                    if before:
                        before()
                    t0 = time.perf_counter()
                    r = _prefilter(env, pre, cmd, mode="default")
                    ts.append(time.perf_counter() - t0)
                    assert r.returncode == 0, r.stderr[-300:]
                return statistics.median(ts)
            HA.build_vault(env, GH_ASK.replace('use = "ask"', "use = true"), tokens={"gh": GHTOK})
            _hook("ls", proj)                          # the stand-ins and ask-clis, as a session start
            plain = median("gh pr list")
            assert not log.exists(), "no ask account: Python never starts"
            HA.build_vault(env, GH_ASK, tokens={"gh": GHTOK})
            _hook("ls", proj)
            asked = median("gh pr list")
            assert log.read_text().splitlines() == ["hook-bash"] * 5
            pending = median("ls", lambda: asks.record("ssh", "1@2", str(proj), ["x"],
                                                        [("hosts", "x")]))
            assert log.read_text().splitlines() == ["hook-bash"] * 10
            print(f"    note: a plain gh call: {plain * 1000:.0f} ms (sh only, no \"ask\" account), "
                  f"{asked * 1000:.0f} ms with an \"ask\" account (one Python start, hook-bash); "
                  f"a call without a trigger word while a record is pending: "
                  f"{pending * 1000:.0f} ms")
            assert plain < 2.0 and asked < 15.0 and pending < 15.0, (plain, asked, pending)
        finally:
            shutil.rmtree(rig, ignore_errors=True)


def test_python_keeps_the_list_of_clis_an_ask_account_serves():
    """$DATA/ask-clis (consent.ask_clis, written wherever network-words is):
    the CLIs whose kinds have an account that is "ask" in some mode, its use
    or its credential policy (a github account serves gh and crane's
    ghcr.io); a locked vault keeps the last list."""
    with H.gateway_env() as env:
        proj = env.root / "proj"
        proj.mkdir()
        p = paths.ask_clis_path()
        HA.build_vault(env, GH_ASK, tokens={"gh": GHTOK})
        _hook("ls", proj)
        assert p.read_text() == "gh\ncrane\n"
        HA.build_vault(env, GH_ASK.replace('use = "ask"', 'use = { default = true, plan = "ask" }'),
                       tokens={"gh": GHTOK})
        _hook("ls", proj)
        assert p.read_text() == "gh\ncrane\n", "ask in one mode is enough"
        HA.build_vault(env, GH_ASK.replace('use = "ask"', "use = true") +
                       '[accounts.gh.policy]\ncredential = "ask"\n', tokens={"gh": GHTOK})
        _hook("ls", proj)
        assert p.read_text() == "gh\ncrane\n", "the credential policy counts too"
        HA.build_vault(env, GH_ASK.replace('use = "ask"', "use = true"), tokens={"gh": GHTOK})
        _hook("ls", proj)
        assert p.read_text() == ""
        p.write_text("gh\n")
        eff = consent.compute(env.form(), None, locked=True)
        consent.sync_network_words(eff)
        assert p.read_text() == "gh\n", "locked: the last list stays"


# ---------------------------------------------------------------------------
# gate with NAME -- CMD honours the account's use and credential policy
# ---------------------------------------------------------------------------

OPENAI = ('[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n'
          'env = "OPENAI_API_KEY"\n')
OPENKEY = "sk-openaikeyvalue0123456789abcd"


def _with_prog(env: H.GatewayEnv) -> list[str]:
    """`python3 prog.py`, which prints how long OPENAI_API_KEY is."""
    import sys
    prog = env.root / "prog.py"
    prog.write_text("import os\nprint('KEY=' + str(len(os.environ.get('OPENAI_API_KEY', ''))))\n")
    return [sys.executable, str(prog)]


def test_gate_with_honours_the_accounts_use_and_credential_policy():
    """The reviewer's MF2: `gate with NAME -- CMD` handed the key over with
    the account's use = false or "ask", and past its credential policy. Now
    use off (or waiting) and a refusing credential policy refuse; "ask" (use
    or credential) is asked about by the hook, with its record of the exact
    command, and the gate CLI hands the key over only to a command Claude
    typed with that record, once; never from a script or a job."""
    import shlex
    with H.gateway_env() as env:
        proj = env.root / "proj"
        proj.mkdir()
        HA.set_direct((True, ""))
        cmd = _with_prog(env)
        words = ["openai", "--", *cmd]
        line = shlex.join(["gate", "with", *words])
        want = f"KEY={len(OPENKEY)}"
        HA.build_vault(env, OPENAI + "use = false\n", tokens={"openai": OPENKEY})
        assert _hook(line, proj) is None, "use off: no prompt; the gate CLI refuses"
        real = _typed((True, ""))
        try:
            rc, out, err = HA.run_with(words, cwd=str(proj))
            assert rc == 2 and want not in out and "openai has use = false" in err, (rc, out, err)
            # use = true and a credential policy that refuses: refused, naming the rule
            HA.build_vault(env, OPENAI + '[accounts.openai.policy]\ncredential = "deny"\n',
                           tokens={"openai": OPENKEY})
            rc, out, err = HA.run_with(words, cwd=str(proj))
            assert rc == 2 and want not in out and "credential" in err, (rc, out, err)
            # use = "ask": asked about, recorded, then handed over once
            HA.build_vault(env, OPENAI + 'use = "ask"\n', tokens={"openai": OPENKEY})
            h = _hook(line, proj)
            assert _dec(h) == "ask" and "use on openai" in h["permissionDecisionReason"], h
            (_n, rec), = _records()
            assert rec["entries"] == ["accounts/openai"]
            rc, out, err = HA.run_with(words, cwd=str(proj))
            assert rc == 0 and out.strip() == want, (rc, out, err)
            rc, out, err = HA.run_with(words, cwd=str(proj))
            assert rc == 2 and want not in out and "didn't ask you" in err, (rc, out, err)
            assert "run `gate with openai -- ...` as its own command" in err, err
            # a credential policy of "ask" (use true) works the same way
            HA.build_vault(env, OPENAI + '[accounts.openai.policy]\ncredential = "ask"\n',
                           tokens={"openai": OPENKEY})
            h = _hook(line, proj)
            assert _dec(h) == "ask" and "credential on openai" in h["permissionDecisionReason"], h
            rc, out, err = HA.run_with(words, cwd=str(proj))
            assert rc == 0 and out.strip() == want, (rc, out, err)
            HA.build_vault(env, OPENAI + 'use = "ask"\n', tokens={"openai": OPENKEY})
            _hook(line, proj)
        finally:
            ancestry.typed_by_claude = real            # type: ignore[assignment]
        # a script's, a job's or a pane's `gate with`: refused even with the record
        for who, frag in (((False, "make"), "can only ask about a command Claude runs itself"),
                          ((False, ancestry.CHECKPOINT), "a job can't use"),
                          ((False, ancestry.TERMINAL), "a gateway terminal or job can't use")):
            real = _typed(who)
            try:
                rc, out, err = HA.run_with(words, cwd=str(proj))
            finally:
                ancestry.typed_by_claude = real        # type: ignore[assignment]
            assert rc == 2 and want not in out and frag in err, (who, err)
        h = _hook(line, proj, tool="mcp__plugin_check_jobs__job_start")
        assert _dec(h) == "deny" and "a job can't use" in h["permissionDecisionReason"], h
        # use = true: no prompt, the key goes to Claude's own command as before
        HA.build_vault(env, OPENAI, tokens={"openai": OPENKEY})
        assert _hook(line, proj) is None and _records() == []
        rc, out, err = HA.run_with(words, cwd=str(proj))
        assert rc == 0 and out.strip() == want, (rc, out, err)


# ---------------------------------------------------------------------------
# An account's use = "ask" works for its CLI
# ---------------------------------------------------------------------------

def _typed(value: tuple[bool, str]):
    real = ancestry.typed_by_claude
    ancestry.typed_by_claude = lambda: value       # type: ignore[assignment]
    return real


def test_an_account_cli_with_use_ask_is_asked_about_and_then_uses_the_account():
    """`gh pr list` with the account's use = "ask" (Manual mode): the hook
    asks and records the command, and after the OK the gh stand-in uses the
    account; without the record (a script's gh, or the record used up) or
    from a job, it is refused, saying what to do."""
    with H.gateway_env() as env:
        proj = env.root / "proj"
        proj.mkdir()
        HA.set_direct((True, ""))
        d = Path(env.root) / "fakebin"
        HA.install_fakes(env, gh=HA.fake_cli(d, "gh"))
        HA.build_vault(env, GH_ASK, tokens={"gh": GHTOK})
        argv = ["pr", "list", "-R", "octocat/thing"]
        # a destination nothing configured covers: the user's own tool, no prompt
        assert _hook("crane ls other.example.com/x", proj) is None
        assert _hook("gh api --hostname other.example.com /user", proj) is None
        h = _hook("gh pr list -R octocat/thing", proj)
        assert _dec(h) == "ask" and "use on gh" in h["permissionDecisionReason"], h
        # the next call (Plan mode asks too) drops the first call's record
        assert _dec(_hook("gh pr list -R octocat/thing", proj, mode="plan")) == "ask"
        assert len(_records()) == 1
        real = _typed((True, ""))
        try:
            rc, out, err = HA.run_cli("gh", argv, cwd=str(proj))
            assert rc == 0, err
            j = json.loads(out.splitlines()[0])
            assert "GH_TOKEN" in j["env"] and GHTOK not in out, out
            assert _records() == [], "used once"
            rc, out, err = HA.run_cli("gh", argv, cwd=str(proj))
            assert rc == 2 and "didn't ask you about this command" in err, err
            assert "run `gh ...` as its own command" in err and "TOKEN-SEEN" not in out, err
            # another command's record doesn't count
            _hook("gh issue list -R octocat/thing", proj)
            rc, out, err = HA.run_cli("gh", argv, cwd=str(proj))
            assert rc == 2 and "didn't ask you" in err, err
        finally:
            ancestry.typed_by_claude = real            # type: ignore[assignment]
        _clear()
        _hook("gh pr list -R octocat/thing", proj)
        for who, words in (((False, "make"), "can only ask about a command Claude runs itself"),
                           ((False, ancestry.CHECKPOINT), "a job can't use"),
                           ((False, ancestry.TERMINAL), "a gateway terminal or job can't use")):
            real = _typed(who)
            try:
                rc, out, err = HA.run_cli("gh", argv, cwd=str(proj))
            finally:
                ancestry.typed_by_claude = real        # type: ignore[assignment]
            assert rc == 2 and words in err and "TOKEN-SEEN" not in out, (who, err)
        # a job's gh: denied by the hook (nobody can be asked while it runs)
        h = _hook("gh pr list -R octocat/thing", proj, tool="mcp__plugin_check_jobs__job_start")
        assert _dec(h) == "deny" and "a job can't use" in h["permissionDecisionReason"], h
        # use = true: no prompt, no record; an owner no account covers: the user's own gh
        _clear()
        HA.build_vault(env, GH_ASK.replace('use = "ask"', "use = true"), tokens={"gh": GHTOK})
        assert _hook("gh pr list -R octocat/thing", proj) is None and _records() == []


def test_an_account_clis_refusals_are_audited_with_their_mode():
    """Lead decision 19.8 (verify012): the account CLIs' refusals name the
    mode the stand-in decided in: the session's mode the hook recorded for a
    command Claude typed, else "modeless"."""
    from gateway import audit, modes
    with H.gateway_env() as env:
        proj = env.root / "proj"
        proj.mkdir()
        HA.set_direct((True, ""))
        HA.install_fakes(env, gh=HA.fake_cli(Path(env.root) / "fakebin", "gh"))
        HA.build_vault(env, GH_ASK, tokens={"gh": GHTOK})
        argv = ["pr", "list", "-R", "octocat/thing"]
        real, real_mode = _typed((True, "")), modes.current_for
        try:
            for recorded, want in (("acceptEdits", "acceptEdits"), (None, "modeless")):
                modes.current_for = lambda caller, m=recorded: m if caller == "standin" else None
                rc, out, err = HA.run_cli("gh", argv, cwd=str(proj))
                assert rc == 2 and "didn't ask you" in err, err
                last = [r for r in audit.read(0) if r.get("event") == "refusal"][-1]
                assert last["tool"] == "gh" and last.get("mode") == want, last
            # the mode it decided in, not a later read (verify013): the
            # record answers once, then is gone (gated restarted)
            left = ["acceptEdits"]
            modes.current_for = lambda caller: left.pop() if caller == "standin" and left else None
            rc, out, err = HA.run_cli("gh", argv, cwd=str(proj))
            assert rc == 2 and "didn't ask you" in err and left == [], err
            last = [r for r in audit.read(0) if r.get("event") == "refusal"][-1]
            assert last.get("mode") == "acceptEdits", last
        finally:
            ancestry.typed_by_claude = real            # type: ignore[assignment]
            modes.current_for = real_mode              # type: ignore[assignment]


def test_an_account_clis_credential_use_is_audited_with_its_mode():
    """Lead decision 19.8 (verify013): the account CLIs' use lines name the
    mode the stand-in decided in, as their refusals do."""
    from gateway import audit, modes
    with H.gateway_env() as env:
        proj = env.root / "proj"
        proj.mkdir()
        HA.set_direct((True, ""))
        HA.install_fakes(env, gh=HA.fake_cli(Path(env.root) / "fakebin", "gh"))
        HA.build_vault(env, GH_ASK.replace('use = "ask"', "use = true"), tokens={"gh": GHTOK})
        argv = ["pr", "list", "-R", "octocat/thing"]
        real, real_mode = _typed((True, "")), modes.current_for
        try:
            for recorded, want in (("auto", "auto"), (None, "modeless")):
                modes.current_for = lambda caller, m=recorded: m if caller == "standin" else None
                rc, out, err = HA.run_cli("gh", argv, cwd=str(proj))
                assert rc == 0, err
                last = [r for r in audit.read(0) if r.get("event") == "use"][-1]
                assert last["tool"] == "gh" and last["account"] == "gh" and last.get("mode") == want, last
        finally:
            ancestry.typed_by_claude = real            # type: ignore[assignment]
            modes.current_for = real_mode              # type: ignore[assignment]
