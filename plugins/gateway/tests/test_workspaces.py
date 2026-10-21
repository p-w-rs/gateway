"""Workspaces and the policy in gated's terminals and jobs (PLAN-v4 phase 7):
every terminal and job is bound to a host and, when its folder lies in one,
a workspace (w_ ids bound to the host's id and the root: the same path on two
hosts is two workspaces); cwd defaults to the workspace's root and is refused
outside it; a remote workspace's `local` folder maps to its root; a
workspace of another host is refused; exec is decided by the policy (the
workspace's own restriction too, also when the workspace isn't named)."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import harness_daemon as D
import harness_remote as R
from gateway import consent
from gateway.daemon import workspace_id
from test_terminals import Agent


def _approve(env: Any, text: str) -> None:
    env.write_form(text)
    consent.approve_all(env.form())


def _snapshot(de: D.DaemonEnv, fc: D.FakeClaude) -> dict[str, Any]:
    probe = D.probe_root(de.root)
    r = fc.run([D.PY, "-I", "-S", str(probe / "run.py")],
               env={**{k: v for k, v in D.py_env().items() if k != "PYTHONHOME"},
                    "GW_PROBE_SOCK": str(de.sock), "GW_PROBE_PATH": "/v1/snapshot",
                    "GW_PROBE_METHOD": "GET"})
    return json.loads(r.stdout)["body"]


def test_a_local_workspace_binds_terminals_and_jobs_and_its_exec_restriction_holds():
    with D.daemon_env() as de:
        notes = de.root / "my notes"
        (notes / "sub").mkdir(parents=True)
        other = de.root / "other"
        other.mkdir()
        _approve(de.env, f'[hosts.localhost.workspaces.notes]\nroot = "{notes}"\n')
        fc = de.claude()
        a = Agent(de, fc)
        snap = _snapshot(de, fc)
        local_id = next(h["host"] for h in snap["hosts"] if h["name"] == "localhost")
        wid = workspace_id(local_id, str(notes))
        assert [w["workspace"] for w in snap["workspaces"]] == [wid]
        assert snap["workspaces"][0]["root"] == str(notes) and snap["workspaces"][0]["host"] == local_id
        assert snap["features"] if "features" in snap else True
        # named: cwd defaults to the root; by id the same
        v = a.ok("/agent/term/open", {"workspace": "notes", "cols": 80, "rows": 20})
        assert v["cwd"] == str(notes) and v["workspace"] == wid, v
        j = a.ok("/agent/job/start", {"workspace": wid, "argv": ["pwd"]})
        assert j["workspace"] == wid and j["cwd"] == str(notes)
        # a cwd outside the named workspace is refused; inside it is fine
        st, e = a.call("/agent/job/start", {"workspace": "notes", "cwd": str(other), "argv": ["true"]})
        assert st == 400 and e["error"] == "bad_cwd", e
        j = a.ok("/agent/job/start", {"workspace": "notes", "cwd": str(notes / "sub"), "argv": ["true"]})
        assert j["cwd"] == str(notes / "sub")
        # not named: the workspace whose root holds cwd is bound anyway
        j = a.ok("/agent/job/start", {"cwd": str(notes / "sub"), "argv": ["true"]})
        assert j["workspace"] == wid
        j = a.ok("/agent/job/start", {"cwd": str(other), "argv": ["true"]})
        assert "workspace" not in j
        st, e = a.call("/agent/job/start", {"workspace": "nope", "argv": ["true"]})
        assert st == 404 and e["error"] == "no_workspace"
        # the workspace's exec restriction (a narrowing: at once), named or not
        de.env.write_form(f'[hosts.localhost.workspaces.notes]\nroot = "{notes}"\nexec = "deny"\n')
        for body in ({"workspace": "notes", "argv": ["true"]},
                     {"cwd": str(notes / "sub"), "argv": ["true"]}):
            st, e = a.call("/agent/job/start", body)
            assert st == 403 and e["error"] == "policy", e
            assert e["rule"].startswith('[hosts.localhost.workspaces.notes] exec = "deny"'), e
            assert e["rule"] in e["message"]
        st, e = a.call("/agent/term/open", {"cwd": str(notes), "cols": 80, "rows": 20})
        assert st == 403 and e["error"] == "policy"
        assert a.ok("/agent/job/start", {"cwd": str(other), "argv": ["true"]})["state"]
        # the person's own terminal (the pane) is theirs
        st, ui = fc.http("POST", "/ui/term/open", {"cwd": str(notes), "cols": 80, "rows": 20})
        assert st == 200 and ui["ok"] is True, ui
        ev = [e for e in __import__("test_terminals")._events(de, ("policy.denied",))]
        assert ev and ev[-1]["action"] == "exec" and ev[-1]["workspace"] == wid


def test_a_workspace_waiting_for_the_ok_is_not_usable():
    with D.daemon_env() as de:
        d = de.root / "w"
        d.mkdir()
        _approve(de.env, "")
        de.env.write_form(f'[hosts.localhost.workspaces.w]\nroot = "{d}"\n')     # not approved
        fc = de.claude()
        a = Agent(de, fc)
        st, e = a.call("/agent/job/start", {"workspace": "w", "argv": ["true"]})
        assert st == 409 and "waits for the user's OK" in e["message"], e
        assert _snapshot(de, fc)["workspaces"] == []


def test_identical_paths_on_two_hosts_are_two_workspaces_and_never_mix():
    with R.remote_env() as re_:
        s1 = re_.se.sshd("one")
        s2 = re_.se.sshd("two")
        work = re_.root / "app"
        (work / "sub").mkdir(parents=True)
        mirror = re_.root / "mirror"
        (mirror / "sub").mkdir(parents=True)
        re_.add_host("one", s1, extra=f'[hosts.one.workspaces.app]\nroot = "{work}"\nlocal = "{mirror}"\n')
        re_.add_host("two", s2, extra=f'[hosts.two.workspaces.app]\nroot = "{work}"\n')
        fc = re_.de.claude()
        a = Agent(re_.de, fc)
        snap = _snapshot(re_.de, fc)
        ws = {w["host_name"]: w for w in snap["workspaces"]}
        assert set(ws) == {"one", "two"} and ws["one"]["root"] == ws["two"]["root"] == str(work)
        assert ws["one"]["workspace"] != ws["two"]["workspace"]
        assert ws["one"]["host"] != ws["two"]["host"] and ws["one"].get("local") == str(mirror)
        # named on its host: runs in the root there
        j = a.ok("/agent/job/start", {"host": "one", "workspace": "app", "command": "pwd; sleep 30"})
        assert j["workspace"] == ws["one"]["workspace"] and j["cwd"] == str(work)
        # another host's workspace id is refused: the same path elsewhere is another place
        st, e = a.call("/agent/job/start", {"host": "two", "workspace": ws["one"]["workspace"],
                                            "argv": ["true"]})
        assert st == 409 and e["error"] == "workspace_host", e
        # outside the root: refused, nothing reached the host
        n = len(s1.commands())
        st, e = a.call("/agent/job/start", {"host": "one", "workspace": "app", "cwd": "/",
                                            "argv": ["true"]})
        assert st == 400 and e["error"] == "bad_cwd"
        assert not any("new-session" in c for c in s1.commands()[n:])     # (the poller still asks)
        # a folder under the local mapping is the host's folder under the root
        j = a.ok("/agent/job/start", {"host": "one", "workspace": "app", "cwd": str(mirror / "sub"),
                                      "argv": ["pwd"]})
        assert j["cwd"] == str(work / "sub"), j
        # the same path on host two is two's workspace, with its own restriction
        re_.rewrite_form(re_.form_text.replace(
            f'[hosts.two.workspaces.app]\nroot = "{work}"\n',
            f'[hosts.two.workspaces.app]\nroot = "{work}"\nexec = "deny"\n'), approve=False)
        n2 = len(s2.commands())
        st, e = a.call("/agent/job/start", {"host": "two", "cwd": str(work / "sub"), "argv": ["true"]})
        assert st == 403 and e["error"] == "policy" and "[hosts.two.workspaces.app]" in e["rule"], e
        assert not any("new-session" in c for c in s2.commands()[n2:])
        j = a.ok("/agent/job/start", {"host": "one", "cwd": str(work / "sub"), "argv": ["true"]})
        assert j["workspace"] == ws["one"]["workspace"]


def test_provisioning_a_runtime_follows_the_hosts_policy():
    with R.remote_env() as re_:
        s1 = re_.se.sshd("box")
        re_.add_host("box", s1, extra='[hosts.box.policy]\nprovision = "deny"\n')
        fc = re_.de.claude()
        a = Agent(re_.de, fc)
        st, e = a.call("/agent/job/start", {"host": "box", "cwd": str(re_.root), "argv": ["true"]})
        assert st == 403 and "provision" in e["message"] + json.dumps(e) and \
            '[hosts.box.policy] provision = "deny"' in e["message"], e
        assert not re_.rt_dir("box").exists(), "nothing was staged"
        # exec denied on the host: no job, whatever the runtime
        re_.rewrite_form(re_.form_text.replace('provision = "deny"', 'exec = "deny"'))
        st, e = a.call("/agent/job/start", {"host": "box", "cwd": str(re_.root), "argv": ["true"]})
        assert st == 403 and e["error"] == "policy" and 'exec = "deny"' in e["rule"], e


def _fake_home(sshd: Any, home: Path, extra_env: dict[str, str] | None = None) -> None:
    """The harness sshd's sessions get a test HOME (and variables) instead of
    the real one: its forced-command wrapper sets them."""
    text = sshd.wrapper.read_text()
    env = "".join(f"{k}={v!r}; export {k}\n".replace("'", "'") for k, v in (extra_env or {}).items())
    text = text.replace("#!/bin/sh\n", f"#!/bin/sh\nHOME='{home}'; export HOME\n{env}", 1)
    sshd.wrapper.write_text(text)


def test_a_remote_host_is_inspected_read_only_with_names_never_values():
    with R.remote_env() as re_:
        s1 = re_.se.sshd("box")
        home = re_.root / "box-home"
        (home / ".cargo" / "bin").mkdir(parents=True)
        (home / ".cargo" / "bin" / "cargo").write_text("#!/bin/sh\n")
        marker = re_.root / "rc-ran"
        (home / ".zshrc").write_text(f'export PATH="$HOME/.cargo/bin:$PATH"\ntouch {marker}\n')
        secret = "hv-" + "q" * 20
        _fake_home(s1, home, {"HOST_VAR_NAME": secret})
        re_.add_host("box", s1)
        fc = re_.de.claude()
        a = Agent(re_.de, fc)
        r = a.ok("/agent/remote/inspect", {"host": "box"})
        assert r["host"] == "box" and r["remote"] is True, r
        dirs = {e["dir"]: e for e in r["login_path"]}
        assert "~/.cargo/bin" in dirs and dirs["~/.cargo/bin"]["exists"] is True, r["login_path"]
        assert dirs["~/.cargo/bin"]["source"].startswith("~/.zshrc line 1")
        cargo = [t for t in r["toolchains"] if t["name"] == "rustup/cargo"]
        assert cargo and "cargo" in cargo[0]["dirs"][0]["tools"]
        assert "HOST_VAR_NAME" in r["env_names"]
        assert secret not in json.dumps(r), "a value left the host"
        assert not marker.exists(), "an rc file was run"
        assert r["managed"]["path"][0]["origin"].startswith("the gateway's remote runtime")
        # the host's read policy decides
        re_.rewrite_form(re_.form_text + '[hosts.box.policy]\nread = "deny"\n', approve=False)
        st, e = a.call("/agent/remote/inspect", {"host": "box"})
        assert st == 200 and e["ok"] is False and '[hosts.box.policy] read = "deny"' in e["message"], e


def test_a_remote_shell_gets_the_hosts_approved_imports_with_their_origin():
    with R.remote_env() as re_:
        s1 = re_.se.sshd("box")
        home = re_.root / "box-home"
        tools = home / "tools"
        tools.mkdir(parents=True)
        val = "value with 'quotes' and $dollar"
        _fake_home(s1, home, {"IMPORT_ME_VAR": "x"})
        # the wrapper's export can't carry those characters safely: write it raw
        text = s1.wrapper.read_text().replace("IMPORT_ME_VAR='x'", "IMPORT_ME_VAR=\"$(cat " +
                                              str(re_.root / "val.txt") + ")\"")
        s1.wrapper.write_text(text)
        (re_.root / "val.txt").write_text(val)
        re_.add_host("box", s1, extra=f'[hosts.box.shell]\nimport_path = ["~/tools"]\n'
                                       'import_env = ["IMPORT_ME_VAR", "NOT_SET_VAR"]\n')
        fc = re_.de.claude()
        a = Agent(re_.de, fc)
        out = re_.root / "env-out"
        j = a.ok("/agent/job/start", {"host": "box", "cwd": str(re_.root),
                                      "command": f'{{ echo "P=$PATH"; echo "V=$IMPORT_ME_VAR"; '
                                                 f'echo "U=${{NOT_SET_VAR-unset}}"; }} > {out}'})["id"]
        deadline = time.time() + 20
        while time.time() < deadline and not (out.exists() and "U=" in out.read_text()):
            time.sleep(0.2)
        got = dict(ln.split("=", 1) for ln in out.read_text().splitlines())
        parts = got["P"].split(":")
        assert parts[0].endswith("/env/bin") and parts[1] == str(tools), parts
        assert got["V"] == val and got["U"] == "unset", got
        assert not list(Path(re_.rt_dir("box") / "terms").glob("*.imp")), "the imports were left behind"
        # nothing of the value on any command line seen by the host
        assert all(val not in c for c in s1.commands())
        _ = j
        # env_import denied by policy: no imports at all
        re_.rewrite_form(re_.form_text + '[hosts.box.policy]\nenv_import = "deny"\n', approve=False)
        out.unlink()
        a.ok("/agent/job/start", {"host": "box", "cwd": str(re_.root),
                                  "command": f'{{ echo "P=$PATH"; echo "V=${{IMPORT_ME_VAR-unset}}"; }} > {out}'})
        deadline = time.time() + 20
        while time.time() < deadline and not (out.exists() and "V=" in out.read_text()):
            time.sleep(0.2)
        got = dict(ln.split("=", 1) for ln in out.read_text().splitlines())
        assert str(tools) not in got["P"] and got["V"] == "unset", got


def test_remote_imports_wait_for_the_ok():
    from gateway import form as F
    text = ('[hosts.box]\naddress = "u@box.example.com"\n')
    f0 = F.parse_text(text, Path("/x"))
    f1 = F.parse_text(text + '[hosts.box.shell]\nimport_path = ["/opt/x/bin"]\n', Path("/x"))
    eff = consent.compute(f1, {"approved": {"rights": consent.snapshot(f0)}})
    assert any("PATH import /opt/x/bin on box" in c.what for c in eff.pending_for("box"))
    assert eff.hosts["box"].import_path == []
    eff = consent.compute(f1, {"approved": {"rights": consent.snapshot(f1)}})
    assert eff.hosts["box"].import_path == ["/opt/x/bin"]


def test_snapshots_and_the_ticker_never_keep_an_idle_vault_unlocked():
    """gated's own looks at the rights (the snapshot's hosts, workspaces and
    accounts, the ticker's rights.changed watch) read the vault without
    counting as a use: a consumer polling /v1/snapshot can't keep an idle
    vault unlocked past `lock_after`."""
    from gateway import vault
    with D.daemon_env(knobs={"lock_after": 1.0, "tick": 0.2}) as de:
        _approve(de.env, '[hosts.localhost.workspaces.w]\nroot = "/tmp"\n'
                         '[accounts.gh]\nkind = "github"\n')
        de.wrap("correct horse battery staple")
        fc = de.claude()
        assert de.health()["vault"] == "unlocked"
        end = time.time() + 4
        locked = False
        while time.time() < end:
            snap = _snapshot(de, fc)
            assert snap.get("ok") is not False
            if de.health()["vault"] == "locked":
                locked = True
                break
            time.sleep(0.2)
        assert locked, "polling the snapshot kept the vault unlocked"
        _ = vault


def test_the_contract_doc_names_this_daemon_s_id_and_features_and_matches_checkpoint_s_copy():
    """docs/CONTRACT-v1.md is the contract checkpoint codes against: its id
    and the features its discovery example lists are the daemon's, and
    checkpoint's copy (when its checkout sits next to this repo) is the same
    file byte for byte."""
    import re
    from gateway import daemon as gd
    plugin = Path(__file__).resolve().parent.parent
    doc = plugin.parent.parent / "docs" / "CONTRACT-v1.md"
    text = doc.read_text(encoding="utf-8")
    assert f"Contract id: `{gd.CONTRACT_ID}`" in text
    m = re.search(r'"features": \[([^\]]*)\]', text)
    assert m, "the discovery example lists features"
    listed = re.findall(r'"([a-z_]+)"', m.group(1))
    assert listed == list(gd.FEATURES), (listed, gd.FEATURES)
    sib = plugin.parent.parent.parent / "checkpoint" / "docs" / "CONTRACT-v1.md"
    if sib.is_file():
        assert sib.read_bytes() == doc.read_bytes(), "checkpoint's CONTRACT-v1.md differs"
    else:
        print("note: no checkpoint checkout next to this repo; the copy wasn't compared")
