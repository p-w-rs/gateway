#!/usr/bin/env python3
"""Brief 11.1, 14.9 and 14.13 in the real TUI with BOTH plugins installed:
synthetic canaries through every input route, authorized service access,
alternate read paths, and a scan of everything either plugin, Claude Code,
its telemetry and a nosy third-party mod could have recorded.

    pixi exec --spec python=3.12 --spec pyte python tests/acceptance_canaries.py \\
        --tmp DIR [--keep] [--pixi-cache DIR] [--checkpoint DIR]

The gateway (e2e route) and checkpoint (check@checkpoint) are installed from
local git-source marketplaces into one scratch config; both runtimes are
built before the sessions (outside the record-only proxy). The session runs
with Claude Code's telemetry ON behind the record-only proxy (tests/tui
proxy.py), the observer plugin, --debug-file, the fullscreen layout, the
recording shims for open/osascript/xdg-open/zenity/kdialog/terminal programs
first on PATH, and a process-table sampler (argv). Canaries are generated
here, never printed and never in a prompt.

Steps (acceptance_dialogs.py's steps reused, with checkpoint recording every
tool call):
  sudo      the consent for the form's sudo = true first (a new install's sudo
            here is "ask" since 0.10.0: Approve), then
            the sudo dialog: typing BEFORE the click (held back by the guard),
            a wrong value (validation: "That didn't work"), a partial value
            then the focus moved away (Escape: dropped), the right value (Enter)
  paste     a canary PASTED (bracketed paste) into the prompt box while a
            secret dialog waits: held back, never submitted; the dialog then
            cancelled (nothing stored)
  clip      Paste from clipboard (gated reads the clipboard itself)
  queue     two requests: one dialog, the other queued; Cancel and Decline
  kill      gated SIGKILLed while a token dialog is open (an exception path):
            it comes back, a canary typed then is stored
  reload    /reload-plugins while a dialog waits: it reopens and is answered
  service   an api-key account bound to a local service (127.0.0.1): its key
            typed into the dialog, then the gw http tool calls the service
            with the account: the service receives the key (by hash), echoes
            it back in its body, and the tool result Claude gets is masked
  vault     /gate-unlock sets a vault passphrase (two fields), /gate-lock,
            /gate-unlock with a wrong passphrase (refused), then the right one
  alt       alternate read and execution paths, as Claude would try them: the
            private folder by Bash and by Read (refused by the hooks), and a
            script (written with Write, run with the system python3, no
            gateway path on its command line) that reads the private folder
            and asks gated's socket for the vault: only ciphertext, and gated
            refuses the vault read (not a gateway entry point)
  export    checkpoint's export bundle of the task (an unencrypted file)

Broker receipt is proven by hash before the vault is wrapped (the scratch
key). Then every canary is searched for (raw, base64, hex, URL, JSON, UTF-16,
gzip; ANSI stripped for the PTY) in: the scratch Claude config (transcripts,
history, plugin data), the debug log, every fake-API request, every proxied
telemetry payload, the observer's records, the gateway's data (gated log,
events, audit log, terminals), its home (form, encrypted vault), its run dir,
checkpoint's state (journal, spool, sessions, registry) and its export
bundle, the session homes (shell history files), the probe's outputs, the
process-table argv samples and the PTY output. Prints one line per check and
a JSON summary to --tmp/acceptance-canaries.json; exits non-zero on any
failure.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.server
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
PLUGIN = HERE.parent
REPO = PLUGIN.parents[1]
sys.dont_write_bytecode = True
sys.path.insert(0, str(HERE))
import acceptance_dialogs as AD  # noqa: E402
from tui import driver, install, proxy, safety, scan  # noqa: E402
from tui.fakeapi import result_text, tool_results  # noqa: E402

check, note = AD.check, AD.note
SUMMARY: dict = {}
HTTP = "mcp__plugin_gate_gw__http"


def sha(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()


class Service(threading.Thread):
    """A local service an api-key account is bound to: it keeps only the
    sha256 of each Authorization header it gets, and echoes the header back
    in its body (a service that reflects a credential: the gateway must mask
    it before Claude sees the result)."""

    def __init__(self):
        super().__init__(daemon=True)
        hashes = self.hashes = []

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                auth = self.headers.get("Authorization", "")
                hashes.append(sha(auth.split(" ", 1)[1]) if " " in auth else sha(auth))
                body = json.dumps({"you_sent": auth, "ok": True}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):  # never log a header
                pass

        self.srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]

    def run(self):
        self.srv.serve_forever(poll_interval=0.2)

    def stop(self):
        self.srv.shutdown()
        self.srv.server_close()


PROBE = r'''
import json, os, socket, sys
out = {}
home = "@@HOME@@"          # in real use ~/.config/gateway, which any same-user script can compute
c = os.path.join(home, "run", "contract.json")
priv = os.path.join(home, "private")
out["private_listed"] = sorted(os.listdir(priv)) if os.path.isdir(priv) else None
out["key_txt_exists"] = os.path.exists(os.path.join(priv, "key.txt"))
data = b""
for n in ("vault.age", "key.wrapped"):
    p = os.path.join(priv, n)
    if os.path.isfile(p):
        data += open(p, "rb").read()
out["read_bytes"] = len(data)
try:
    sock = json.load(open(c))["socket"]
    s = socket.socket(socket.AF_UNIX)
    s.settimeout(10)
    s.connect(sock)
    body = b"{}"
    s.sendall(b"POST /agent/vault/read HTTP/1.1\r\nHost: gated\r\nContent-Type: application/json\r\n"
              b"Content-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
    resp = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        resp += chunk
    out["vault_read_status"] = resp.split(b" ", 2)[1].decode() if resp.startswith(b"HTTP/") else "?"
    out["vault_read_len"] = len(resp)
except Exception as e:
    out["vault_read_error"] = type(e).__name__
open(sys.argv[1], "w").write(json.dumps(out))
'''


def wait(s, cond, timeout, step=0.3):
    return AD.wait(s, cond, timeout, step)


def prebuild_checkpoint(root: Path, h, p, env: dict) -> tuple[bool, str]:
    for d in ("c-home", "c-tmp"):
        (root / d).mkdir(exist_ok=True)
    cenv = safety.hermetic_env(config_dir=h.inst.config_dir, home=root / "c-home", tmpdir=root / "c-tmp",
                               extra={**{k: v for k, v in env.items() if k != "PATH"},
                                      "CLAUDE_PLUGIN_DATA": str(p.data_path), "CLAUDE_PLUGIN_ROOT": str(p.cache_path)})
    r = subprocess.run(["sh", str(Path(p.cache_path) / "hooks" / "env.sh"), "ensure"], env=cenv, cwd=root / "c-tmp",
                       capture_output=True, text=True, timeout=1800)
    return r.returncode == 0, f"env.sh ensure rc={r.returncode} {r.stderr[-300:]}"


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--tmp", default=tempfile.gettempdir())
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--pixi-cache", default=None)
    ap.add_argument("--checkpoint", default=str(REPO.parent / "checkpoint"))
    a = ap.parse_args(argv)
    before = safety.real_settings_fingerprint()
    root = Path(tempfile.mkdtemp(prefix="acc-canaries-", dir=a.tmp))
    safety.check_scratch(root, "acceptance root")
    print(f"acceptance (canaries, both plugins): root {root}", flush=True)
    env = {"PIXI_CACHE_DIR": a.pixi_cache or str(root / "pixi-cache")}
    names = ("sudo-right", "sudo-wrong", "focus-partial", "guard-typed", "clipboard", "token-after-kill",
             "pasted", "service-key", "vault-pass", "vault-wrong")
    C = {n: scan.Canary.new(n) for n in names}
    shims, shim_log = AD.path_shims(root)
    env["PATH"] = AD.shimmed_path(shims)
    watcher = AD.Watcher(list(C.values()))
    watcher.start()
    svc = Service()
    svc.start()
    t0 = time.time()
    try:
        run(root, env, C, watcher, svc, Path(a.checkpoint).resolve())
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        check(f"the run went to its end ({type(e).__name__}: {str(e)[:300]})", False)
    finally:
        watcher.stop.set()
        watcher.join(5)
        svc.stop()
        driver._close_all()
        for line in subprocess.run(["ps", "-A", "-ww", "-o", "pid=,command="], capture_output=True,
                                   text=True).stdout.splitlines():
            pid, _, cmd = line.strip().partition(" ")
            if str(root) in cmd and "gated" in cmd and pid.isdigit():
                with contextlib.suppress(OSError):
                    os.kill(int(pid), signal.SIGTERM)
    ran = [ln for ln in shim_log.read_text().splitlines() if ln.strip()]
    check("no osascript, zenity, kdialog, open, xdg-open or terminal program was run by name (recording shims "
          "first on PATH)", not ran, ", ".join(ran[:10]))
    check(f"best effort: no such program in the process table either ({watcher.samples} samples, 0.25 s)",
          not watcher.banned, ", ".join(watcher.banned[:10]))
    check("no canary appeared in any process's argv (process-table samples)", not watcher.argv_hits,
          ", ".join(sorted(watcher.argv_hits)))
    time.sleep(1.0)
    left = [ln for ln in subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True,
                                        text=True).stdout.splitlines() if str(root) in ln and "ps -axo" not in ln]
    check("no process left naming the scratch root", not left, "\n".join(left))
    check("real ~/.config/claude settings and plugin registry unchanged", before == safety.real_settings_fingerprint())
    failed = [r for r in AD.RESULTS if not r["ok"]]
    summary = {"when": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "seconds": round(time.time() - t0),
               "claude": subprocess.run([driver.find_claude(), "--version"], capture_output=True,
                                        text=True).stdout.strip(),
               "passed": len(AD.RESULTS) - len(failed), "failed": len(failed), "checks": AD.RESULTS,
               "notes": AD.NOTES, **SUMMARY}
    out = Path(a.tmp) / "acceptance-canaries.json"
    out.write_text(json.dumps(summary, indent=1, default=str))
    print(f"\n{summary['passed']} passed, {summary['failed']} failed in {summary['seconds']} s; {out}")
    if not a.keep:
        shutil.rmtree(root, ignore_errors=True)
    return 1 if failed else 0


def run(root: Path, env: dict, C: dict, watcher, svc: Service, ck_src: Path) -> None:
    build_env = {k: v for k, v in env.items() if k != "PATH"}
    with install.Hermetic(root / "h", extra_env=build_env) as h, proxy.RecordProxy(root / "proxy") as px:
        gi = h.install_gateway_e2e(REPO)
        check("the gateway is installed through the e2e route (marker proven)", gi.proof is not None)
        p = h.install_from(ck_src, repo="checkpoint", plugin="check")
        check("checkpoint is installed the normal way (check@checkpoint)", p.cache_path is not None)
        ok, detail = AD.prebuild_env(root, h, gi, build_env)
        if not check("the gateway's env is built before any session (outside the proxy)", ok, detail):
            return
        ok, detail = prebuild_checkpoint(root, h, p, build_env)
        if not check("checkpoint's runtime is built before any session", ok, detail):
            return
        PY = AD.env_python()
        fs = gi.root / "fake-sudo"
        fs.mkdir()
        (fs / "config.json").write_text(json.dumps({"password": C["sudo-right"].value, "nopasswd": False,
                                                     "timeout": 300, "sudoers_dir": None}))
        os.chmod(fs / "config.json", 0o600)
        (fs / "log.jsonl").write_text("")
        (fs / "sudo").write_text(f"#!/bin/sh\nexec '{PY}' -I -S '{PLUGIN}/tests/fakes/fake_sudo.py' "
                                 f"--state '{fs}' \"$@\"\n")
        os.chmod(fs / "sudo", 0o755)
        fc = gi.root / "fake-clip"
        fc.mkdir()
        (fc / "value").write_text(C["clipboard"].value)
        os.chmod(fc / "value", 0o600)
        (fc / "paste").write_text(f"#!/bin/sh\nexec /bin/cat '{fc / 'value'}'\n")
        os.chmod(fc / "paste", 0o755)
        (gi.root / "e2e.json").write_text(json.dumps({"tools": {"sudo": str(fs / "sudo")},
                                                       "clipboard": str(fc / "paste"), "popup_wait": 8}))
        os.chmod(gi.root / "e2e.json", 0o600)
        gi.gateway_home.mkdir(parents=True, exist_ok=True)
        (gi.gateway_home / "gateway.toml").write_text(AD.FORM)
        proj = root / "proj"
        proj.mkdir()
        s = driver.Session(root / "s1", proj, config_dir=h.inst.config_dir,
                           extra_env={**env, **px.env(), "CLAUDE_CODE_NO_FLICKER": "1"},
                           replies=[AD.bash("gate check localhost", "set up sudo"), "sudo step answered"],
                           debug_file=True, observer=True, cols=170, rows=50,
                           permission_mode="bypassPermissions", start=False)
        s.redact(*[c.value for c in C.values()])
        home = safety.state_root_for(h.inst.config_dir) / ".local" / "state" / "checkpoint"
        try:
            s.start()
            check("telemetry is on behind the record-only proxy", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC" not in s.env
                  and s.env.get("HTTPS_PROXY") == px.url)
            s.wait_ready(180)
            reg = gi.run / "gated-sessions.json"
            wait(s, lambda: any(x.get("via") == "ui" for x in json.loads(reg.read_text())["sessions"]), 180, 1.0)
            check("checkpoint is recording in the same session", wait(s, lambda: "check: recording" in s.text(), 60))
            watcher.roots.add(s.pid)
            AD.step_sudo(s, gi, C["sudo-right"], C["sudo-wrong"], C["focus-partial"], C["guard-typed"])
            form2 = (AD.FORM + AD.ACCOUNTS
                     + '\n[accounts.pastey]\nkind = "api-key"\nsites = ["api.pastey.example"]\n'
                     + '\n[accounts.svc]\nkind = "api-key"\nsites = ["127.0.0.1"]\nauth = "bearer"\n')
            (gi.gateway_home / "gateway.toml").write_text(form2)
            step_paste(s, C["pasted"])
            s.api.script([AD.bash("gate check clip", "add the clip account"), "clip step answered"])
            AD.step_clip(s, gi)
            s.api.script([AD.bash("gate check qa & gate check qb; wait", "two accounts at once"), "queue step answered"])
            AD.step_queue(s)
            s.api.script([AD.bash("gate check killme", "add killme"), "kill step answered"])
            AD.step_kill(s, gi, C["token-after-kill"])
            s.api.script([AD.bash("gate check reload", "add reload"), "reload step answered"])
            AD.step_reload(s, gi)
            step_service(s, svc, C["service-key"])
            receipts(gi, C)
            step_vault(s, gi, C["vault-pass"], C["vault-wrong"])
            step_alt(s, gi, proj)
            s.pump(2.0)
        finally:
            s.close()
        bundle = step_export(root, h, p, home)
        scans(root, s, gi, px, C, h, home, bundle, proj)


def step_paste(s, pasted) -> None:
    print("paste: a canary pasted into the prompt box while a secret dialog waits", flush=True)
    s.api.script([AD.bash("gate check pastey", "add pastey"), "paste step answered"])
    s.submit("add the pastey account")
    ok = AD.wait(s, lambda: "Approve" in AD.screen(s) and "pastey" in AD.screen(s), 120)
    if ok:
        AD.press(s, "Approve", lambda: "api key for pastey" in AD.screen(s))
    ok = AD.wait(s, lambda: "api key for pastey" in AD.screen(s) and AD.FIELD in AD.screen(s), 60)
    check("paste: the pastey key dialog is open", ok, s.dump(20))
    if not ok:
        return
    n0 = len(s.api.main_requests())
    s.paste(pasted.value)
    s.pump(0.6)
    check("paste: a bracketed paste into the prompt box while the secret dialog waits doesn't stay there "
          "(the guard holds it back)", AD.wait(s, lambda: s.composer().strip() == "", 3, 0.2),
          f"{len(s.composer().strip())} character(s) left")
    s.key("enter")
    s.pump(1.5)
    check("paste: Enter after the paste submits nothing to the model", len(s.api.main_requests()) == n0)
    AD.press(s, "Cancel", lambda: "api key for pastey" not in AD.screen(s), settle=3.0)
    check("paste: the dialog is cancelled (Cancel)", AD.wait(s, lambda: "api key for pastey" not in AD.screen(s), 30))
    AD.wait(s, lambda: "paste step answered" in s.all_text(), 60)


def step_service(s, svc: Service, key) -> None:
    print("service: an api-key account bound to a local service; the gw http tool", flush=True)
    s.api.script([AD.bash("gate check svc", "add the service account"), "svc step answered"])
    s.submit("add the svc account")
    ok = AD.wait(s, lambda: "Approve" in AD.screen(s) and "svc" in AD.screen(s), 120)
    if ok:
        AD.press(s, "Approve", lambda: "api key for svc" in AD.screen(s))
    ok = AD.wait(s, lambda: "api key for svc" in AD.screen(s) and AD.FIELD in AD.screen(s), 60)
    check("service: the svc key dialog opens after the OK", ok, s.dump(20))
    if not ok:
        return
    AD.focus_field(s)
    s.type(key.value)
    s.key("enter")
    ok = AD.wait(s, lambda: AD.FIELD not in AD.screen(s), 60)
    check("service: the key typed into the private field is taken", ok, s.dump(20))
    AD.wait(s, lambda: "svc step answered" in s.all_text(), 60)
    n0 = len(s.api.main_requests())
    s.api.script([{"tool": HTTP, "input": {"url": f"http://127.0.0.1:{svc.port}/echo", "account": "svc"}},
                  "service answered"])
    s.submit("call the service")
    AD.wait(s, lambda: len(s.api.main_requests()) >= n0 + 2, 120)
    check("service: the service received the account's key from the gateway (Bearer, by sha256)",
          sha(key.value) in svc.hashes, f"{len(svc.hashes)} request(s)")
    reqs = s.api.main_requests()
    res = "\n".join(result_text(b) for b in tool_results(reqs[n0 + 1])) if len(reqs) > n0 + 1 else ""
    SUMMARY["service_result_head"] = res[:200].replace(key.value, "<k>")
    check("service: the http tool's result reached the model (status 200, the echo body) with the key masked",
          '200' in res and "you_sent" in res and key.value not in res, res[-300:].replace(key.value, "<k>"))
    SUMMARY["service_requests"] = len(svc.hashes)


def receipts(gi, C) -> None:
    age = AD.age_binary(gi.root)
    if age is None:
        check("the gateway's age binary is found to read the scratch vault", False)
        return
    data = AD.read_vault(gi, age)
    user = next(iter(((data.get("localhost") or {}).get("sudo") or {}).keys()), None)
    stored = ((data.get("localhost") or {}).get("sudo") or {}).get(user or "", {}).get("password", "")
    check("broker receipt (typed): the stored sudo password is the right canary (sha256)",
          bool(stored) and sha(stored) == sha(C["sudo-right"].value))
    tok = lambda n: (((data.get("accounts") or {}).get(n) or {}).get("token") or {}).get("value", "")  # noqa: E731
    check("broker receipt (clipboard): clip's token is the clipboard canary", sha(tok("clip")) == sha(C["clipboard"].value))
    check("broker receipt (after gated was killed): killme's token is the canary typed after the restart",
          sha(tok("killme")) == sha(C["token-after-kill"].value))
    check("broker receipt (service): svc's key is the typed canary", sha(tok("svc")) == sha(C["service-key"].value))
    check("nothing stored for the pasted (cancelled), queued (cancelled/declined) and reloaded (cancelled) requests",
          not tok("pastey") and not tok("qa") and not tok("qb") and not tok("reload"))


def step_vault(s, gi, vpass, vwrong) -> None:
    print("vault: set a passphrase, lock, a wrong unlock, the right one", flush=True)
    priv = gi.gateway_home / "private"
    s.submit("/gate-unlock")
    ok = AD.wait(s, lambda: "Set a vault passphrase" in AD.screen(s) and AD.FIELD in AD.screen(s), 60)
    check("vault: /gate-unlock opens 'Set a vault passphrase' (two private fields)", ok, s.dump(25))
    if not ok:
        return
    AD.focus_field(s)
    s.type(vpass.value)
    s.key("tab")
    s.type(vpass.value)
    s.key("enter")
    ok = AD.wait(s, lambda: (priv / "key.wrapped").exists() and not (priv / "key.txt").exists(), 90)
    check("vault: the key is wrapped with the passphrase (key.wrapped, no key.txt left)", ok,
          str(sorted(x.name for x in priv.iterdir())))
    AD.wait(s, lambda: "Set a vault passphrase" not in AD.screen(s), 30)
    s.submit("/gate-lock")
    check("vault: /gate-lock locks it", AD.wait(s, lambda: "locked" in s.all_text(), 30), s.dump(10))
    s.pump(1.0)
    s.submit("/gate-unlock")
    ok = AD.wait(s, lambda: "Unlock the gateway vault" in AD.screen(s) and AD.FIELD in AD.screen(s), 60)
    check("vault: /gate-unlock opens the unlock dialog", ok, s.dump(25))
    if not ok:
        return
    AD.focus_field(s)
    s.type(vwrong.value)
    s.key("enter")
    ok = AD.wait(s, lambda: "That didn't work" in AD.screen(s) or "doesn't unlock" in AD.screen(s), 60)
    check("vault: a wrong passphrase is refused and the dialog asks again", ok, s.dump(25))
    AD.focus_field(s)
    s.type(vpass.value)
    s.key("enter")
    ok = AD.wait(s, lambda: "Unlock the gateway vault" not in AD.screen(s), 60)
    check("vault: the right passphrase unlocks it (the dialog closes)", ok, s.dump(25))


def step_alt(s, gi, proj: Path) -> None:
    print("alt: alternate read and execution paths", flush=True)
    priv = gi.gateway_home / "private"
    n0 = len(s.api.main_requests())
    s.api.script([AD.bash(f"cat '{priv}/vault.age' > /dev/null && echo read > alt-a.txt", "read the vault"),
                  {"tool": "Read", "input": {"file_path": str(priv / "key.wrapped")}},
                  {"tool": "Write", "input": {"file_path": str(proj / "probe.py"),
                                              "content": PROBE.replace("@@HOME@@", str(gi.gateway_home))}},
                  AD.bash("python3 probe.py probe-out.json", "probe"),
                  "alt step answered"])
    s.submit("look around")
    AD.wait(s, lambda: "alt step answered" in s.all_text() or len(s.api.main_requests()) >= n0 + 5, 180)
    reqs = s.api.main_requests()
    res = ["\n".join(result_text(b) for b in tool_results(r)) for r in reqs[n0 + 1:n0 + 5]]
    SUMMARY["alt_results"] = [x[:300] for x in res]
    check("alt: Bash reading the gateway's private folder is refused by the hook (no file written)",
          not (proj / "alt-a.txt").exists() and len(res) > 0 and "gateway" in res[0], res[0][-300:] if res else "")
    check("alt: Read of the private folder is refused by the file guard",
          len(res) > 1 and "gateway" in res[1] and "age-encryption" not in res[1], res[1][-300:] if len(res) > 1 else "")
    out = proj / "probe-out.json"
    got = json.loads(out.read_text()) if out.exists() else {}
    SUMMARY["alt_probe"] = got
    check("alt: a script (no gateway path on its command line) reads the private folder: no key.txt, ciphertext only",
          got.get("key_txt_exists") is False and got.get("read_bytes", 0) > 0, json.dumps(got))
    check("alt: gated refuses the script's vault read on its socket (not a gateway entry point: 403)",
          got.get("vault_read_status") == "403", json.dumps(got))


def step_export(root: Path, h, p, home: Path) -> Path | None:
    print("export: checkpoint's export bundle", flush=True)
    p2 = h.inst.plugin("check@checkpoint")
    # checkpoint's CLI from the test process: scratch gateway locations only (unset, it would
    # fall back to the real ~/.config/gateway's contract.json and env.sh)
    e = dict(os.environ, CHECKPOINT_HOME=str(home), CLAUDE_CONFIG_DIR=str(h.inst.config_dir),
             CLAUDE_PLUGIN_DATA=str(p2.data_path), CHECKPOINT_GATEWAY_CONTRACT=str(root / "none.json"),
             CHECKPOINT_GATEWAY_ENV=str(root / "none-env.sh"))
    sids = sorted((home / "spool").glob("*")) if (home / "spool").is_dir() else []
    for sd in sids:
        subprocess.run(["sh", str(Path(p2.cache_path) / "hooks" / "env.sh"), "run", "ingest", sd.name], env=e,
                       capture_output=True, timeout=120)
    dest = root / "ck-export"
    dest.mkdir()
    r = subprocess.run(["sh", str(Path(p2.cache_path) / "hooks" / "env.sh"), "run", "export", "last", str(dest)],
                       env=e, capture_output=True, text=True, timeout=120)
    files = [x for x in dest.rglob("*") if x.is_file()]
    check("checkpoint's export bundle of the task is written (an unencrypted file)", r.returncode == 0 and files,
          (r.stdout + r.stderr)[-300:])
    return dest if files else None


def scans(root: Path, s, gi, px, C: dict, h, home: Path, bundle: Path | None, proj: Path) -> None:
    print("scans: every canary everywhere it must not be", flush=True)
    secret = [C[n] for n in ("sudo-right", "sudo-wrong", "focus-partial", "clipboard", "token-after-kill",
                             "service-key", "vault-pass", "vault-wrong")]
    allc = list(C.values())
    places = {
        "the scratch Claude config (transcripts, history, plugin data, caches)": h.inst.config_dir,
        "the gateway's data (gated log, events, audit log, terminals, managed shell)": gi.root / "data",
        "the gateway's home (form, encrypted vault, pending)": gi.gateway_home,
        "the gateway's run dir": gi.run,
        "checkpoint's state (journal, spool, sessions, registry, checkpoints)": home,
        "checkpoint's export bundle (unencrypted)": bundle,
        "the session's home (shell history files)": s.home,
        "the project folder (the probe's output, files Claude wrote)": proj,
        "the observer plugin's records (a nosy third-party mod)": s.observer.root if s.observer else None,
        "the proxied first-party telemetry payloads": px.root,
    }
    for what, where in places.items():
        if where is None or not Path(where).exists():
            check(f"scan: {what} exists to be scanned", False)
            continue
        rep = scan.Report()
        exclude = [gi.root / "fake-sudo", gi.root / "fake-clip"]
        rep.scan_tree(where, *(allc if what.startswith(("checkpoint", "the scratch Claude", "the proxied",
                                                          "the session")) else secret), exclude=exclude)
        check(f"scan: no canary in {what}", rep.clean(), rep.summary())
    rep = scan.Report()
    if s.debug_path and s.debug_path.exists():
        rep.scan_tree(s.debug_path.parent, *secret, exclude=[s.observer.root] if s.observer else [])
        check("scan: no canary in the --debug-file log", rep.clean(), rep.summary())
    rep = scan.Report()
    rep.scan_api_log(s.api.log_path, *allc)
    check("scan: no canary (typed, pasted, guarded, service key, vault passphrases) in any fake-API request "
          "(the model's inputs, tool results included)", rep.clean(), rep.summary())
    rep = scan.Report()
    rep.scan_bytes(bytes(s.raw), "pty", *[c for c in secret if c.id not in ("vault-wrong",)], ansi=True)
    check("scan: no typed or stored canary in the PTY output (bullets only)", rep.clean(), rep.summary())
    n = len(px.requests())
    check(f"telemetry: first-party requests captured before encryption and scanned ({n})", n > 0)
    SUMMARY["telemetry_requests"] = n
    SUMMARY["telemetry_hosts"] = sorted({r["host"] for r in px.requests()})
    obs = [r for r in (s.observer.records() if s.observer else []) if r.get("ev") == "prompt.edit"]
    note(f"documented limit (FEASIBILITY-v4 P1): keys typed or pasted into the prompt box before the field is "
         f"clicked reach every plugin's prompt.edit hook ({len(obs)} prompt.edit records in the observer; the "
         "guard and pasted canaries are excluded from the observer scan above for that reason) and are painted "
         "for a frame")
    rep = scan.Report()
    if s.observer:
        rep.scan_tree(s.observer.root, C["guard-typed"], C["pasted"])
    note(f"the guard-typed and pasted canaries {'were' if not rep.clean() else 'were not'} seen by the observer "
         "plugin's prompt.edit hook (the documented exposure)")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
