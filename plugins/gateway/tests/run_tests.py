#!/usr/bin/env python3
"""Self-contained tests for gateway. Pure stdlib; run with:
    pixi run test
or:
    python tests/run_tests.py
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import time
import http.server
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

# Never write test activity into the real audit log.
TMP = Path(tempfile.mkdtemp(prefix="gateway-test-"))
os.environ["GATEWAY_AUDIT_LOG"] = str(TMP / "audit.jsonl")
# ...nor touch the real vault, nor ever open a real pop-up on screen.
os.environ["GATEWAY_HOME"] = str(TMP / "vault")
os.environ["GATEWAY_DIALOG"] = "none"

from gateway import actions, policy  # noqa: E402

PASS = 0
FAIL = 0


def check(name, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  ok   {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}")


# --- Hook redirect detection -------------------------------------------------
print("hook redirect detection:")
REDIRECT = [
    "curl https://x.com",
    "curl -X POST https://api.x.com -d @body",
    "wget https://x.com/f.tgz",
    "/usr/bin/curl https://x.com",
    "nmap -p 80 10.0.0.1",
    "masscan 10.0.0.0/8 -p443",
    "certutil -hashfile a.exe SHA256",
    "cmdkey /list",
    "security find-generic-password -s github -w",
    "security dump-keychain",
    "Invoke-WebRequest https://x.com",
    "iwr https://x.com -OutFile a",
    "irm https://api.x.com",
    "python3 -c 'import requests; requests.get(1)'",
    "node -e 'fetch(\"https://x\")'",
]
for c in REDIRECT:
    check(f"redirect: {c[:40]}", policy.match_blocked(c) is not None)

ALLOW = [
    "ls -la",
    "git status",
    "echo curling is a sport",          # word boundary, not the curl binary
    "grep security /etc/hosts",          # 'security' without keychain verb
    "python3 app.py",
    "cat README.md",
]
for c in ALLOW:
    check(f"allow:    {c[:40]}", policy.match_blocked(c) is None)

# --- Policy decisions --------------------------------------------------------
print("policy decisions:")
cfg = policy.load_config()
check("read auto", not policy.decide("read_request", host="example.com", cfg=cfg).needs_ask)
check("write auto", not policy.decide("write_request", host="example.com", cfg=cfg).needs_ask)
check("download auto", not policy.decide("download", host="example.com", cfg=cfg).needs_ask)
# Settings rules already 'ask' for these, so the gateway must not ask again.
check("port_check: no second prompt", not policy.decide("port_check", host="10.0.0.1", cfg=cfg).needs_ask)
check("secret_list: no second prompt", not policy.decide("secret_list", cfg=cfg).needs_ask)
check("secret_use: no second prompt", not policy.decide("secret_use", cfg=cfg).needs_ask)
check("no keychain/env secret_hosts config any more", "secret_hosts" not in cfg)
check("reveal refused", not policy.decide("secret_reveal", cfg=cfg).allowed)

# allow_domains='*' means any host is in scope (user chose this)
check("host '*' allows any", policy.host_allowed("whatever.net", ["*"]))
check("subdomain match", policy.host_allowed("api.example.com", ["example.com"]))
check("non-match blocked", not policy.host_allowed("evil.com", ["example.com"]))

# --- Plugin root / config fallback ------------------------------------------
print("plugin root:")
_saved = os.environ.get("CLAUDE_PLUGIN_ROOT")
os.environ["CLAUDE_PLUGIN_ROOT"] = "${CLAUDE_PLUGIN_ROOT}"
check("unexpanded env var ignored", policy.plugin_root() == ROOT)
os.environ["CLAUDE_PLUGIN_ROOT"] = "relative/dir"
check("relative env var ignored", policy.plugin_root() == ROOT)
if _saved is None:
    del os.environ["CLAUDE_PLUGIN_ROOT"]
else:
    os.environ["CLAUDE_PLUGIN_ROOT"] = _saved
mcp_cfg = json.loads((ROOT / ".mcp.json").read_text())
check(".mcp.json has no env block", "env" not in mcp_cfg["mcpServers"]["gw"])
d = policy.DEFAULT_CONFIG["approvals"]
check("fallback defaults ask for port/secret tools",
      all(d[a] == "ask" for a in ("port_check", "secret_list", "secret_use")))

# --- Redaction ---------------------------------------------------------------
print("redaction:")
red = policy.redact({"Authorization": "Bearer abc", "X-Api-Key": "k", "ok": "v"}, cfg)
check("authz redacted", red["Authorization"] == "***REDACTED***")
check("apikey redacted", red["X-Api-Key"] == "***REDACTED***")
check("normal kept", red["ok"] == "v")

# --- Local echo servers (127.0.0.1 only; no external network) ---------------
HITS = []


class Echo(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        HITS.append(self.path)
        if self.path.startswith("/to/"):          # /to/<url> -> 302 <url>
            self.send_response(302)
            self.send_header("Location", self.path[len("/to/"):])
            self.end_headers()
            return
        if self.path.startswith("/missing"):
            self.send_response(404)
            self.end_headers()
            return
        out = json.dumps({k.lower(): v for k, v in self.headers.items()}).encode()
        self.send_response(200)
        self.end_headers()
        self.wfile.write(out)

    do_POST = do_GET

    def log_message(self, *a):
        pass


def serve():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.server_address[1]


PA = serve()
A = f"http://127.0.0.1:{PA}"          # host "127.0.0.1"
B = f"http://localhost:{PA}"          # same server, different host name

SECRET = "s3cr3t-VALUE-0123456789"
os.environ["GATEWAY_TEST_SECRET"] = SECRET  # env refs must NOT reach this any more


def use_config(extra):
    p = TMP / "policy.json"
    base = json.loads((ROOT / "config" / "policy.json").read_text())
    base.update(extra)
    p.write_text(json.dumps(base))
    os.environ["GATEWAY_CONFIG"] = str(p)


def echoed(r):
    try:
        return json.loads(r.get("body") or "{}")
    except ValueError:
        return {}


use_config({})
from gateway import vault  # noqa: E402
with vault.locked():
    _d = vault.load()
    _d["secrets"]["TEST_SECRET"] = {"value": SECRET, "description": "test",
                                    "hosts": ["127.0.0.1"], "updated": ""}
    _d["secrets"]["STAR_SECRET"] = {"value": "star-0123456789", "description": "test",
                                    "hosts": ["*"], "updated": ""}
    vault.save(_d)

print("secret binding:")
n = len(HITS)
r = actions.http_request("GET", A + "/x", auth_ref="env:GATEWAY_TEST_SECRET")
check("env: refs no longer work", r.get("ok") is False and SECRET not in json.dumps(r))
check("env: ref: no request made", len(HITS) == n)
r = actions.http_request("GET", A + "/x", auth_ref="keychain:anything")
check("keychain: refs no longer work", r.get("ok") is False and len(HITS) == n)
r = actions.http_request("GET", A + "/x", auth_ref="NOT_IN_VAULT")
check("unknown vault name refused, nothing sent", r.get("ok") is False and len(HITS) == n)
r = actions.http_request("GET", A + "/x", auth_ref="STAR_SECRET")
check("'*' binding not accepted", r.get("refused") is True)
r = actions.http_request("GET", B + "/x", auth_ref="TEST_SECRET")
check("ref refused for unbound host", r.get("refused") is True)
r = actions.http_request("GET", A + "/x", auth_ref="TEST_SECRET")
check("ref allowed for bound host", r.get("ok") is True)
check("server received the secret", "authorization" in echoed(r))
check("secret value hidden from result", SECRET not in json.dumps(r))
r = actions.secret_use_check("NOT_IN_VAULT")
check("secret_use refuses unbound ref", r.get("refused") is True)

print("redirects:")
r = actions.http_request("GET", f"{A}/to/{B}/echo", auth_ref="TEST_SECRET",
                         headers={"X-Api-Key": "k-123456", "Cookie": "sid=1",
                                  "Accept": "text/plain"})
e = echoed(r)
check("cross-host redirect followed", r.get("ok") is True and "accept" in e)
check("cross-host: Authorization stripped", "authorization" not in e)
check("cross-host: X-Api-Key stripped", "x-api-key" not in e)
check("cross-host: Cookie stripped", "cookie" not in e)
r = actions.http_request("GET", f"{A}/to/{A}/echo", auth_ref="TEST_SECRET")
check("same-host redirect keeps auth", "authorization" in echoed(r))
r = actions.http_request("GET", f"{A}/to/file:///etc/hosts")
check("redirect to file:// refused", r.get("ok") is False and "Host Database" not in json.dumps(r))
use_config({"allow_domains": ["127.0.0.1"]})
r = actions.http_request("GET", f"{A}/to/{B}/echo")
check("redirect outside allow_domains refused", r.get("ok") is False)
use_config({})

print("url schemes:")
for u in ("file:///etc/hosts", "ftp://127.0.0.1/x", "data:text/plain,hi"):
    r = actions.http_request("GET", u)
    check(f"http_request refuses {u.split(':')[0]}", r.get("refused") is True)
r = actions.download("file:///etc/hosts")
check("download refuses file", r.get("refused") is True)

print("download:")
QDIR = TMP / "quarantine"
use_config({"download_dir": str(QDIR)})
r1 = actions.download(A + "/file.json")
r2 = actions.download(A + "/file.json")
check("download saves with a streamed sha256",
      r1.get("ok") is True and len(r1.get("sha256", "")) == 64 and Path(r1["path"]).exists())
check("download never overwrites an earlier one",
      r2.get("ok") is True and r2["path"] != r1["path"] and r2["path"].endswith("file-1.json"))
use_config({"download_dir": str(QDIR), "max_download_bytes": 10})
r = actions.download(A + "/big.json")
check("download over max_download_bytes: refused and partial file deleted",
      r.get("ok") is False and "max_download_bytes" in r.get("reason", "")
      and not (QDIR / "big.json").exists())
use_config({})

print("audit value scrubbing:")
from gateway import hooks  # noqa: E402
import contextlib  # noqa: E402
import io  # noqa: E402
LEAKS = ["ghp_LEAKME0123456789", "QQQSECRETQQQ", "LEAKKEY99", "hunter2pass",
         "sk-abcdefghijklmnopqrstuv", "AKIAABCDEFGHIJKLMNOP"]
old_stdin = sys.stdin
sys.stdin = io.StringIO(json.dumps({"tool_name": "Bash", "tool_input": {"command": (
    "curl -H 'Authorization: Bearer ghp_LEAKME0123456789' -u bob:hunter2pass "
    "'https://api.x.com/u?access_token=QQQSECRETQQQ' -H 'X: sk-abcdefghijklmnopqrstuv' "
    "--data AKIAABCDEFGHIJKLMNOP")}}))
with contextlib.redirect_stdout(io.StringIO()):
    hooks.route_main()
sys.stdin = old_stdin
actions.http_request("GET", A + "/x?api_key=LEAKKEY99")
actions.http_request("GET", f"http://alice:hunter2pass@127.0.0.1:{PA}/y")
log = Path(os.environ["GATEWAY_AUDIT_LOG"]).read_text()
for leak in LEAKS:
    check(f"audit hides {leak[:10]}", leak not in log)
check("audit never holds env secret", SECRET not in log)
check("audit keeps host info", "api.x.com" in log and "127.0.0.1" in log)
_s = socket.socket()
_s.bind(("127.0.0.1", 0))
CLOSED = _s.getsockname()[1]
_s.close()
actions.http_request("GET", A + "/okay")
actions.http_request("GET", A + "/missing?api_key=LEAKKEY98")
actions.http_request("GET", f"http://127.0.0.1:{CLOSED}/down")
from gateway import cli  # noqa: E402
_out = io.StringIO()
with contextlib.redirect_stdout(_out):
    cli.cmd_log(["3"])
_rows = _out.getvalue().splitlines()
check("/gate:log shows a request's status", len(_rows) == 3 and _rows[0].endswith("/okay  [200]"))
check("/gate:log marks an HTTP error as failed",
      "/missing" in _rows[1] and "[failed: HTTP Error 404" in _rows[1])
check("/gate:log marks a connection error as failed",
      "/down" in _rows[2] and "[failed: " in _rows[2])
check("audit error text never holds the query secret",
      "LEAKKEY98" not in Path(os.environ["GATEWAY_AUDIT_LOG"]).read_text())
check("scrub leaves plain text", policy.scrub("git status --short", policy.load_config())
      == "git status --short")

# --- Vault + /secret and /sudo chat commands (throwaway vault in TMP) --------
print("vault commands:")
from gateway import commands, vault  # noqa: E402

os.environ["GATEWAY_HOME"] = str(TMP / "vault")
SID = "test-session-1"
TRANSCRIPT = TMP / "transcript.jsonl"
TRANSCRIPT.write_text("")
SUDO_PW = "pa$$ w0rd'\"=x"
ME = __import__("getpass").getuser()

# A fake "browser" for the value form: records the URL; then, per the plan
# file, fills the form like a user would (save VALUE / cancel / nothing).
FAKE_BROWSER = TMP / "fake_browser.py"
FAKE_BROWSER.write_text(r'''
import json, os, re, sys, urllib.parse, urllib.request
url = sys.argv[1]
open(os.environ["FAKE_URL_FILE"], "w").write(url)
f = os.environ["FAKE_FORM_FILE"]
plan = json.loads(open(f).read() or "null") if os.path.exists(f) else None
if not plan:
    sys.exit(0)
page = urllib.request.urlopen(url, timeout=10).read().decode()
open(os.environ["FAKE_PAGE_FILE"], "w").write(page)
nonce = re.search(r'name="nonce" value="([^"]+)"', page).group(1)
data = urllib.parse.urlencode({"nonce": nonce, "action": plan["action"],
                               "value": plan.get("value", "")}).encode()
urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10).read()
''')
FAKE_BROWSER_SH = TMP / "fake_browser.sh"
FAKE_BROWSER_SH.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE_BROWSER}" "$1"\n')
FAKE_BROWSER_SH.chmod(0o755)
URL_FILE, PAGE_FILE, PLAN_FILE = TMP / "form.url", TMP / "form.html", TMP / "form.plan"
os.environ.update(GATEWAY_BROWSER=str(FAKE_BROWSER_SH), FAKE_URL_FILE=str(URL_FILE),
                  FAKE_PAGE_FILE=str(PAGE_FILE), FAKE_FORM_FILE=str(PLAN_FILE),
                  GATEWAY_FORM_TIMEOUT="10")


def form_plan(plan):
    PLAN_FILE.write_text(json.dumps(plan))
    for f in (URL_FILE, PAGE_FILE):
        if f.exists():
            f.unlink()


def say(prompt, sid=SID):
    """Run a prompt through the UserPromptSubmit handler. Adds out["reason"]:
    the text the user/Claude gets, whether passed through or blocked."""
    out = commands.handle({"prompt": prompt, "session_id": sid,
                           "transcript_path": str(TRANSCRIPT)})
    if out is not None:
        out["reason"] = out.get("reason") or out["hookSpecificOutput"]["additionalContext"]
    return out


def passed(out):
    return out is not None and "decision" not in out and \
        "<gateway-result>" in out["hookSpecificOutput"]["additionalContext"]


def add_secret(name, value, desc):
    form_plan({"action": "save", "value": value})
    return say(f"/gate:secret add {name} {desc}")


def add_sudo(user, host, pw):
    form_plan({"action": "save", "value": pw})
    return say(f"/gate:sudo add {user} {host}")


out = add_secret("HF_TOKEN", "hf_abc123456789", "Hugging Face token for the Hub API")
check("/secret add: passes through to Claude (no block, no pop-up)", passed(out))
check("/secret add: value came from the browser form",
      vault.secret("HF_TOKEN")["value"] == "hf_abc123456789")
check("/secret add: result names it, never the value",
      "Stored HF_TOKEN" in out["reason"] and "hf_abc123456789" not in out["reason"])
check("form page shows name and description, masked field",
      "HF_TOKEN" in PAGE_FILE.read_text() and "Hugging Face token" in PAGE_FILE.read_text()
      and 'type="password"' in PAGE_FILE.read_text())
check("vault key is mode 600", oct(vault.key_path().stat().st_mode & 0o777) == "0o600")
check("vault file is encrypted", b"hf_abc123456789" not in vault.store_path().read_bytes())
check("ordinary prompt is not handled", say("please list my secrets") is None)
check("short /secret form handled too", passed(say("  /secret list")))
out = add_secret("HF_TOKEN", "other_value_123", "dup")
check("add refuses an existing name (passed through as an error, no form)",
      passed(out) and "already exists" in out["reason"] and not URL_FILE.exists()
      and vault.secret("HF_TOKEN")["value"] == "hf_abc123456789")
check("bad name refused", "not a valid name" in add_secret("9BAD", "v12345", "x")["reason"])
check("add needs a description", "Add a description" in say("/gate:secret add NODESC")["reason"]
      and not vault.secret("NODESC"))
form_plan({"action": "cancel"})
out = say("/gate:secret add CANCELLED something")
check("form cancelled: nothing stored", "Cancelled" in out["reason"] and not vault.secret("CANCELLED"))
out = say("/gate:secret list")
check("/secret list shows name, description, hosts",
      "HF_TOKEN: Hugging Face token for the Hub API [hosts: none yet]" in out["reason"])
out = say("/gate:secret allow HF_TOKEN huggingface.co")
check("/secret allow", passed(out) and vault.secret("HF_TOKEN")["hosts"] == ["huggingface.co"])
check("allow refuses '*'", "not a host" in say("/gate:secret allow HF_TOKEN *")["reason"])
form_plan({"action": "save", "value": "hf_new_987654321"})
say("/gate:secret up HF_TOKEN")
check("/secret up: new value from form, description and hosts kept",
      vault.secret("HF_TOKEN")["value"] == "hf_new_987654321"
      and vault.secret("HF_TOKEN")["description"].startswith("Hugging Face token")
      and vault.secret("HF_TOKEN")["hosts"] == ["huggingface.co"])
form_plan({"action": "save", "value": ""})
say("/gate:secret up HF_TOKEN Hub token, renamed")
check("/secret up: empty value keeps it, changes description",
      vault.secret("HF_TOKEN")["value"] == "hf_new_987654321"
      and vault.secret("HF_TOKEN")["description"] == "Hub token, renamed")
say("/gate:secret desc HF_TOKEN Hub token: write access to my models")
check("/secret desc", vault.secret("HF_TOKEN")["description"] == "Hub token: write access to my models")
say("/gate:secret disallow HF_TOKEN huggingface.co")
check("/secret disallow", vault.secret("HF_TOKEN")["hosts"] == [])
add_secret("TMP_X", "tmp_value_123", "temp")
say("/gate:secret del TMP_X")
check("/secret del", vault.secret("TMP_X") is None)
check("unknown subcommand gives help", "Unknown command" in say("/gate:secret frob")["reason"])

print("typed values are blocked, never passed through:")
out = say("/gate:secret add LEAK hf_abcdefghij123456 my token")
check("token-like word: blocked, not stored", out["decision"] == "block"
      and out["hookSpecificOutput"]["suppressOriginalPrompt"] is True and not vault.secret("LEAK"))
check("block message never repeats it", "hf_abcdefghij123456" not in out["reason"])
out = say("/gate:secret allow HF_TOKEN ghp_abcdefghijklmnop1234")
check("token-like word anywhere: blocked", out["decision"] == "block")
_log = Path(os.environ["GATEWAY_AUDIT_LOG"]).read_text()
check("blocked attempt is logged with name and reason",
      '"secret add"' in _log and '"LEAK"' in _log and "looked like a typed value" in _log)
check("blocked attempt's value is not logged",
      "hf_abcdefghij123456" not in _log and "ghp_abcdefghijklmnop1234" not in _log)
check("log names the secret command and target",
      '"command": "secret allow", "target": "HF_TOKEN -> huggingface.co", "outcome": "ok"' in _log)
check("ordinary description words are fine",
      passed(add_secret("DOCS_TOKEN", "docs_value_1", "Readme token for docs site")))
out = say(f"/gate:sudo add {ME} localhost {SUDO_PW}")
check("password after /sudo add USER HOST: blocked, not stored",
      out["decision"] == "block" and not vault.sudo_entries("localhost")
      and SUDO_PW not in out["reason"])

print("sudo commands:")
out = add_sudo(ME, "localhost", SUDO_PW)
check("/sudo add: password from form (spaces/quotes kept), passes through",
      passed(out) and vault.sudo_entries("localhost")[0]["password"] == SUDO_PW
      and SUDO_PW not in out["reason"])
check("sudo form page names user and host",
      ME in PAGE_FILE.read_text() and "this machine" in PAGE_FILE.read_text())
out = add_sudo("someoneelse", "localhost", SUDO_PW)
check("/sudo localhost must be the current user", "asks for the password of" in out["reason"])
add_sudo("admin", "myserver", SUDO_PW)
add_sudo("admin", "10.0.0.5", "not-the-password")
out = say("/gate:sudo list")
check("/sudo list shows user@host and state, never passwords",
      out["reason"].count("@") == 3 and SUDO_PW not in out["reason"]
      and "disabled" in out["reason"])
check("/sudo host can't look like an ssh option",
      "not a host" in add_sudo("admin", "-oProxyCommand=x", "pw123456")["reason"])
form_plan({"action": "cancel"})
out = say("/gate:sudo add admin box1")
check("/sudo add cancelled: nothing stored", "Cancelled" in out["reason"]
      and not vault.sudo_entries("box1"))

print("sudo enable for one session vs always:")
check("disabled by default", not vault.sudo_enabled("myserver", SID))
out = say("/gate:sudo enable myserver")
check("enable HOST: this session only", passed(out) and "THIS session only" in out["reason"]
      and vault.sudo_enabled("myserver", SID)
      and not vault.sudo_enabled("myserver", "another-session")
      and not vault.sudo_enabled("myserver"))
check("/sudo list shows session state", "ENABLED for this session"
      in say("/gate:sudo list")["reason"])
check("other sessions still see it disabled", "admin@myserver  [disabled"
      in say("/gate:sudo list", sid="another-session")["reason"])
out = say("/gate:sudo enable myserver always")
check("enable HOST always: every session", "EVERY session" in out["reason"]
      and vault.sudo_enabled("myserver", "another-session") and vault.sudo_enabled("myserver"))
say("/gate:sudo disable myserver")
check("disable clears both", not vault.sudo_enabled("myserver", SID)
      and not vault.sudo_enabled("myserver"))
check("can't enable without a stored password",
      "No sudo password stored" in say("/gate:sudo enable nowhere.example")["reason"])
check("enable usage checked", "Usage" in say("/gate:sudo enable myserver forever")["reason"])

print("transcript scrubbing (only for blocked typed values):")
line_cmd = json.dumps({"type": "queue-operation",
                       "content": f"/sudo add {ME} localhost {SUDO_PW}"}) + "\n"
line_note = json.dumps({"type": "system", "content":
                        "Original prompt: /secret add HF_TOKEN hf_abc123456789 x"}) + "\n"
line_other = json.dumps({"type": "user", "content": "unrelated pa$$ hf_abc123456789"}) + "\n"
TRANSCRIPT.write_text(line_cmd + line_note + line_other)
size = TRANSCRIPT.stat().st_size
n = commands.scrub_file(TRANSCRIPT, [SUDO_PW, "hf_abc123456789"])
t = TRANSCRIPT.read_text()
check("scrub removes values from command lines", SUDO_PW not in t.splitlines()[0]
      and "hf_abc123456789" not in t.splitlines()[1] and n == 2)
check("scrub keeps file size (safe while appending)", TRANSCRIPT.stat().st_size == size)
check("scrub keeps every line valid JSON", all(json.loads(x) for x in t.splitlines()))
check("scrub leaves non-command lines alone", t.splitlines()[2] == line_other.strip())
TRANSCRIPT.write_text("")
say("/gate:secret add LATE hf_latevalue123456789 written after the hook returns")
with TRANSCRIPT.open("a") as f:
    f.write(json.dumps({"content": "/gate:secret add LATE hf_latevalue123456789 x"}) + "\n")
deadline = time.time() + 8
while time.time() < deadline and "hf_latevalue123456789" in TRANSCRIPT.read_text():
    time.sleep(0.2)
check("background scrubber catches a later write",
      "hf_latevalue123456789" not in TRANSCRIPT.read_text())

print("prompt hook wrapper:")
PROMPT_SH = ROOT / "hooks" / "prompt.sh"


def run_sh(prompt, root=ROOT):
    payload = json.dumps({"prompt": prompt, "session_id": SID,
                          "transcript_path": str(TRANSCRIPT)})
    p = subprocess.run(["sh", str(PROMPT_SH), str(root)], input=payload,
                       capture_output=True, text=True, timeout=60)
    return p.stdout.strip()


t0 = time.time()
check("wrapper: normal prompt passes untouched", run_sh("hello there") == "")
check("wrapper: normal prompt is fast (no Python)", time.time() - t0 < 0.5)
out = json.loads(run_sh("/gate:secret desc HF_TOKEN via the wrapper"))
check("wrapper: command handled and passed through", "decision" not in out
      and vault.secret("HF_TOKEN")["description"] == "via the wrapper")
out = json.loads(run_sh("/gate:secret list", root=TMP / "no-such-plugin"))
check("wrapper: gateway failure blocks (fail closed)", out["decision"] == "block")

print("vault-backed tools:")
use_config({})
add_secret("API_KEY", "key_abcdef123456", "Test API on 127.0.0.1")
r = actions.http_request("GET", A + "/x", auth_ref="API_KEY")
check("not-yet-allowed secret refused with /secret allow hint",
      r.get("refused") is True and "/gate:secret allow API_KEY 127.0.0.1" in r["reason"])
say("/secret allow API_KEY 127.0.0.1")
r = actions.http_request("GET", A + "/x", auth_ref="API_KEY")
check("allowed secret sent as Bearer", echoed(r).get("authorization") == "***REDACTED***"
      or "authorization" in echoed(r))
check("vault value hidden from result", "key_abcdef123456" not in json.dumps(r))
r = actions.http_request("GET", A + "/x", auth_ref="API_KEY",
                         auth_header="X-Api-Key", auth_scheme="")
check("custom header, raw value", "x-api-key" in echoed(r) and "authorization" not in echoed(r))
r = actions.http_request("GET", A + "/x", auth_ref="API_KEY", auth_header="X: y")
check("bad header name refused", r.get("ok") is False)
r = actions.http_request("GET", B + "/x", auth_ref="API_KEY")
check("vault secret refused for other host", r.get("refused") is True)
r = actions.http_request("GET", A + "/x", auth_ref="NOPE")
check("unknown secret refused", r.get("ok") is False)
r = actions.secret_list()
check("secret_list shows vault catalog",
      r["secrets"]["API_KEY"]["hosts"] == ["127.0.0.1"] and "admin@myserver" in r["sudo"])
check("secret_list has no values",
      not any(v in json.dumps(r) for v in ("key_abcdef123456", "hf_new_987654321", SUDO_PW)))
for c_ in ("cat ~/.config/gateway/key.txt", "age -d -i k s", "age --decrypt s",
           "secret get HF_TOKEN", "cat ~/.config/age/keys.txt"):
    check(f"redirect: {c_[:40]}", policy.match_blocked(c_) is not None)
for c_ in ("secret list", "age-keygen -y k", "echo page -d", "sudo -n true"):
    check(f"allow:    {c_[:40]}", policy.match_blocked(c_) is None)

# --- run_privileged (fake sudo/ssh first on PATH; nothing real runs) --------
print("run_privileged:")
FAKEBIN = TMP / "fakebin"
FAKEBIN.mkdir()
(FAKEBIN / "sudo").write_text(r'''#!/bin/sh
# Fake sudo: -S -p "" -v checks the password, -n runs if validated, -k clears.
# FAKE_SUDO_NOPASSWD=1 acts like a NOPASSWD rule: -v reads nothing from stdin.
case "$1" in
  -S) if [ -n "$FAKE_SUDO_NOPASSWD" ]; then : > "$FAKE_SUDO_TS"; exit 0; fi
      IFS= read -r pw
      echo "fake-sudo saw: $pw" >&2
      if [ "$pw" = "$FAKE_SUDO_PW" ]; then : > "$FAKE_SUDO_TS"; exit 0; fi
      echo "Sorry, try again." >&2; exit 1 ;;
  -n) shift; [ "$1" = "--" ] && shift
      [ -f "$FAKE_SUDO_TS" ] || { echo "sudo: a password is required" >&2; exit 1; }
      "$@"; exit $? ;;
  -k) rm -f "$FAKE_SUDO_TS"; exit 0 ;;
esac
echo "fake-sudo: unexpected: $*" >&2; exit 99
''')
(FAKEBIN / "ssh").write_text(r'''#!/bin/sh
# Fake ssh: check the option layout, log the target, run the string in a POSIX
# sh the way a remote login shell would.
[ "$1 $2 $3 $4" = "-o BatchMode=yes -T --" ] || { echo "fake-ssh: bad args: $*" >&2; exit 98; }
printf '%s\n' "$5" > "$FAKE_SSH_LOG"
exec /bin/sh -c "$6"
''')
for f_ in FAKEBIN.iterdir():
    f_.chmod(0o755)
os.environ["PATH"] = f"{FAKEBIN}{os.pathsep}{os.environ['PATH']}"
os.environ["FAKE_SUDO_PW"] = SUDO_PW
os.environ["FAKE_SUDO_TS"] = str(TMP / "sudo.ts")
os.environ["FAKE_SSH_LOG"] = str(TMP / "ssh.log")
MARK = TMP / "ran.marker"
ASKED = []


def approver(answer):
    def ask(message, remember=None):
        ASKED.append(message)
        REMEMBER_LABELS.append(remember)
        return answer
    return ask


REMEMBER_LABELS = []


touch = ["sh", "-c", f"echo ran > {MARK}"]


def confirmed(*a, **k):
    """run_privileged_confirm: what runs after Claude Code's prompt is approved."""
    return actions.run_privileged(*a, confirmed=True, **k)


r = confirmed("elsewhere", touch)
check("host without stored password refused with /sudo add hint",
      r.get("refused") is True and "/gate:sudo add USER elsewhere" in r["reason"])
r = confirmed("-oProxyCommand=x", touch)
check("option-like host refused", r.get("refused") is True)
r = confirmed("localhost", "rm -rf /")
check("shell string (not argv) refused", r.get("refused") is True)
r = confirmed("localhost", ["curl", "https://x"])
check("blocked command refused even when confirmed", r.get("refused") is True)
r = confirmed("localhost", ["cat", str(vault.key_path())])
check("vault file access refused", r.get("refused") is True)
r = actions.run_privileged("localhost", touch, approve=approver(True))
check("disabled host: run_privileged refuses, points to run_privileged_confirm",
      r.get("refused") is True and "run_privileged_confirm" in r["reason"]
      and not MARK.exists())
check("...without using the gateway's own prompt (desktop auto-cancels it)", not ASKED)
_auto = dict(json.loads((ROOT / "config" / "policy.json").read_text())["approvals"],
             run_privileged="auto")
use_config({"approvals": _auto})
r = actions.run_privileged("localhost", ["true"])
check("'auto' in policy.json doesn't bypass a disabled host", r.get("refused") is True)
use_config({})

r = confirmed("127.0.0.1", ["sh", "-c", "cat; echo ran"])
check("confirmed (127.0.0.1 = localhost): runs", r.get("ok") is True and r.get("exit_code") == 0)
check("local: command never gets the password on stdin", r.get("stdout") == "ran\n")
check("local: password scrubbed from output",
      SUDO_PW not in json.dumps(r) and "***REDACTED***" in r.get("stderr", ""))
check("local: cached credential dropped after", not Path(os.environ["FAKE_SUDO_TS"]).exists())
os.environ["FAKE_SUDO_NOPASSWD"] = "1"
r = confirmed("localhost", ["sh", "-c", "cat; echo ran"])
check("NOPASSWD: password still never reaches the command", r.get("stdout") == "ran\n")
r = confirmed("myserver", ["sh", "-c", "cat; echo ran"])
check("NOPASSWD remote: password never reaches the command", r.get("stdout") == "ran\n")
del os.environ["FAKE_SUDO_NOPASSWD"]
r = confirmed("localhost", ["sh", "-c", "exit 3"])
check("exit code passed through", r.get("ok") is False and r.get("exit_code") == 3)
r = confirmed("localhost", ["sleep", "5"], timeout=1)
check("timeout enforced", r.get("ok") is False and "timed out" in r.get("reason", ""))
r = confirmed("10.0.0.5", touch)
check("wrong password: command not run", r.get("ok") is False and not MARK.exists())

weird = ["printf", "%s|", "a; touch PWNED", "$(id)", "it's", "two  spaces"]
r = confirmed("myserver", weird)
check("remote: ssh as the stored user@host",
      r.get("ok") is True and Path(os.environ["FAKE_SSH_LOG"]).read_text() == "admin@myserver\n")
check("remote: argv arrives intact (no injection)",
      r.get("stdout") == "a; touch PWNED|$(id)|it's|two  spaces|"
      and not Path("PWNED").exists() and not (TMP / "PWNED").exists())
check("remote: password scrubbed", SUDO_PW not in json.dumps(r))
add_sudo("other", "myserver", SUDO_PW)
r = confirmed("myserver", ["true"])
check("several users: must pick one", r.get("refused") is True and "user=" in r["reason"])
r = confirmed("myserver", ["true"], user="other")
check("user= picks the entry", r.get("ok") is True
      and Path(os.environ["FAKE_SSH_LOG"]).read_text() == "other@myserver\n")
log = Path(os.environ["GATEWAY_AUDIT_LOG"]).read_text()
check("audit logs run_privileged", '"run_privileged"' in log and "admin@myserver" in log)
check("confirmed root runs are logged as approved, not 'without asking'",
      "approved in Claude Code's prompt" in log and "ran_without_asking" not in log)
from gateway import cli  # noqa: E402
import contextlib as _cl  # noqa: E402
_buf = io.StringIO() if "io" in globals() else __import__("io").StringIO()
with _cl.redirect_stdout(_buf):
    cli.cmd_log(["400"])
_view = _buf.getvalue()
check("/gate:log shows root runs with approval and exit code",
      "admin@myserver: printf" in _view and "[approved in Claude Code's prompt, exit 0]" in _view)
check("/gate:log shows vault commands with target and outcome",
      "secret add HF_TOKEN  [ok]" in _view and "blocked: looked like a typed value" in _view)
check("/gate:log never shows vault values",
      not any(v in _view for v in (SUDO_PW, "hf_abc123456789", "hf_new_987654321")))
print("sudo enable/disable:")
say("/sudo del other myserver")
check("disabled by default", not vault.sudo_enabled("localhost")
      and not vault.sudo_enabled("myserver"))
r = actions.run_privileged("localhost", ["echo", "x"])
check("disabled: refused with confirm and enable hints", r.get("refused") is True
      and "run_privileged_confirm" in r["reason"]
      and "/gate:sudo enable localhost" in r["reason"])
out = say("/sudo enable localhost always")
check("/sudo enable localhost always", vault.sudo_enabled("localhost")
      and "WITHOUT asking" in out["reason"])
check("/sudo 127.0.0.1 counts as localhost", vault.sudo_enabled("127.0.0.1"))
r = actions.run_privileged("localhost", ["echo", "enabled"])
check("enabled: run_privileged runs without any prompt",
      r.get("ok") is True and r.get("stdout") == "enabled\n" and not ASKED)
r = actions.run_privileged("localhost", ["curl", "https://x"])
check("enabled: blocked commands still refused", r.get("refused") is True)
r = actions.run_privileged("myserver", ["echo", "x"])
check("enabled on one host only", r.get("refused") is True)
_refuse_cfg = dict(json.loads((ROOT / "config" / "policy.json").read_text())["approvals"],
                   run_privileged="refuse")
use_config({"approvals": _refuse_cfg})
r = actions.run_privileged("localhost", ["echo", "x"])
check("'refuse' in policy.json beats enabled", r.get("refused") is True)
r = confirmed("localhost", ["echo", "x"])
check("'refuse' in policy.json beats confirmed", r.get("refused") is True)
use_config({})
out = say("/sudo list")
check("/sudo list shows enabled state", f"{ME}@localhost  [ENABLED" in out["reason"]
      and "admin@myserver  [disabled" in out["reason"] and SUDO_PW not in out["reason"])
check("Claude's catalog shows enabled hosts",
      f"{ME}@localhost: sudo ENABLED in every session" in hooks._catalog_note(SID))
check("user gets a session-start warning while enabled",
      "ENABLED" in (hooks._enabled_warning() or "") and "localhost" in hooks._enabled_warning())
out = say("/sudo disable localhost")
check("/sudo disable HOST (either word order)", not vault.sudo_enabled("localhost"))
r = actions.run_privileged("localhost", ["echo", "x"])
check("disabled again: refused without confirm", r.get("refused") is True)
check("no session warning when nothing is enabled", hooks._enabled_warning() is None)
out = say("/sudo enable nowhere.example always")
check("can't enable a host without a stored password",
      "No sudo password stored" in out["reason"] and not vault.sudo_enabled("nowhere.example"))
say("/sudo enable myserver always")
say("/sudo del admin myserver")
check("/sudo del of the last entry also disables the host", not vault.sudo_enabled("myserver"))
add_sudo("admin", "myserver", SUDO_PW)
check("re-added host starts disabled", not vault.sudo_enabled("myserver"))

# Session-only enable: run_privileged reads the session id Claude Code gives
# each MCP server (CLAUDE_CODE_SESSION_ID).
say("/sudo enable myserver", sid="sess-A")
os.environ["CLAUDE_CODE_SESSION_ID"] = "sess-A"
r = actions.run_privileged("myserver", ["echo", "sess"])
check("session-enabled: runs in that session without asking", r.get("ok") is True)
os.environ["CLAUDE_CODE_SESSION_ID"] = "sess-B"
r = actions.run_privileged("myserver", ["echo", "sess"])
check("...but not in another session", r.get("refused") is True)
del os.environ["CLAUDE_CODE_SESSION_ID"]
r = actions.run_privileged("myserver", ["echo", "sess"])
check("...nor with no session id", r.get("refused") is True)
check("session-start warning only for that session",
      "myserver" in (hooks._enabled_warning("sess-A") or "")
      and hooks._enabled_warning("sess-B") is None)
say("/sudo disable myserver")

# Secrets: a new host is refused with a /secret allow hint; once allowed
# (Claude Code's prompt gates that tool) it goes through without asking.
add_secret("NEWHOST_KEY", "nh_value_123456", "test key")
say("/secret allow NEWHOST_KEY localhost")
n = len(HITS)
r = actions.http_request("GET", A + "/x", auth_ref="NEWHOST_KEY", approve=approver(True))
check("new host: refused, not sent, no gateway prompt",
      r.get("refused") is True and len(HITS) == n and not ASKED)
check("new host: hint gives the exact /secret allow command",
      "/gate:secret allow NEWHOST_KEY 127.0.0.1" in r["reason"])
check("refusal never shows the value", "nh_value_123456" not in json.dumps(r))
say("/secret allow NEWHOST_KEY 127.0.0.1")
check("/secret allow adds the host", True
      and vault.secret("NEWHOST_KEY")["hosts"] == ["localhost", "127.0.0.1"])
r = actions.http_request("GET", A + "/x", auth_ref="NEWHOST_KEY")
check("allowed host: sent without asking", r.get("ok") is True and "authorization" in echoed(r))

check("audit never holds vault values",
      not any(v in log for v in (SUDO_PW, "hf_new_987654321", "key_abcdef123456")))

# --- MCP server protocol (subprocess, stdio JSON-RPC) ------------------------
print("mcp server protocol:")
# Force "ask" tiers here to exercise the elicitation path.
_asking = dict(json.loads((ROOT / "config" / "policy.json").read_text())["approvals"],
               port_check="ask", secret_list="ask", secret_use="ask")
use_config(dict(approvals=_asking))
env = dict(os.environ, CLAUDE_PLUGIN_ROOT="${CLAUDE_PLUGIN_ROOT}")


class Client:
    def __init__(self, caps):
        self.p = subprocess.Popen(
            [sys.executable, str(ROOT / "run.py"), "server"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env)
        self.n = 0
        self.init = self.rpc("initialize", {"protocolVersion": "2025-06-18",
                                            "capabilities": caps})

    def send(self, obj):
        self.p.stdin.write(json.dumps(obj) + "\n")
        self.p.stdin.flush()

    def recv(self):
        return json.loads(self.p.stdout.readline())

    def rpc(self, method, params):
        self.n += 1
        self.send({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params})
        return self.recv()

    def call(self, name, args, answer=None, content=None):
        """tools/call; if the server elicits, reply with `answer` action
        (and form `content`, e.g. {"remember": True})."""
        self.n += 1
        self.send({"jsonrpc": "2.0", "id": self.n, "method": "tools/call",
                   "params": {"name": name, "arguments": args}})
        msg, elicited = self.recv(), None
        if msg.get("method") == "elicitation/create":
            elicited = msg
            self.send({"jsonrpc": "2.0", "id": 900, "method": "ping"})
            result = {"action": answer or "cancel"}
            if content is not None:
                result["content"] = content
            self.send({"jsonrpc": "2.0", "id": msg["id"], "result": result})
            pong = self.recv()
            check("ping answered during elicitation", pong.get("id") == 900)
            msg = self.recv()
        return json.loads(msg["result"]["content"][0]["text"]), elicited

    def close(self):
        self.p.stdin.close()
        self.p.wait(timeout=5)


# Client without elicitation support: "ask" actions must not run.
c = Client({})
check("initialize", c.init["result"]["serverInfo"]["name"] == "gateway")
tools = c.rpc("tools/list", {})["result"]["tools"]
names = {t["name"] for t in tools}
check("tools listed", {"http_request", "port_check", "secret_list", "run_privileged",
                       "run_privileged_confirm", "cert_inspect", "file_hash",
                       "download"} <= names)
body, el = c.call("run_privileged", {"host": "localhost", "argv": ["echo", "hi"]})
check("run_privileged on disabled host: refused, not run",
      el is None and body.get("refused") is True and "stdout" not in body)
check("no model-settable 'approved' arg",
      not any("approved" in t["inputSchema"].get("properties", {}) for t in tools))

with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
    f.write("hello")
    tmp = f.name
body, _ = c.call("file_hash", {"path": tmp})
check("file_hash sha256",
      body.get("sha256") == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824")
os.unlink(tmp)

n = len(HITS)
body, el = c.call("port_check", {"target": "127.0.0.1", "ports": [PA]})
check("port_check needs approval (no elicitation)", body.get("needs_approval") is True)
body, _ = c.call("port_check", {"target": "127.0.0.1", "ports": [PA], "approved": True})
check("approved=true from model is ignored", body.get("needs_approval") is True)
check("port_check made no connection", len(HITS) == n)
body, _ = c.call("secret_list", {})
check("secret_list gated", body.get("needs_approval") is True and "names" not in body)
body, _ = c.call("secret_use", {"ref": "TEST_SECRET"})
check("secret_use gated", body.get("needs_approval") is True)
c.close()

# Client with elicitation: the USER's answer decides.
c = Client({"elicitation": {}})
check("negotiates client protocol", c.init["result"]["protocolVersion"] == "2025-06-18")
body, el = c.call("port_check", {"target": "127.0.0.1", "ports": [PA]}, "accept")
check("port_check elicits the user", el is not None and "127.0.0.1" in el["params"]["message"])
check("accepted port_check runs", body.get("ok") is True
      and body["ports"].get(str(PA)) == "open")
body, el = c.call("port_check", {"target": "127.0.0.1", "ports": [PA]}, "decline")
check("declined port_check refused", body.get("refused") is True)
body, el = c.call("secret_use", {"ref": "TEST_SECRET"}, "accept")
check("secret_use works when user accepts", body.get("ok") is True
      and body.get("allowed_hosts") == ["127.0.0.1"])
check("secret_use never returns value", SECRET not in json.dumps(body))
body, el = c.call("http_request", {"url": A + "/x", "auth_ref": "TEST_SECRET"})
check("auto tier: no elicitation", el is None and body.get("ok") is True)
check("mcp result hides secret", SECRET not in json.dumps(body))
body, el = c.call("run_privileged_confirm", {"host": "localhost", "argv": ["echo", "hi"]})
check("run_privileged_confirm runs (Claude Code's prompt gates it), no gateway form",
      el is None and body.get("ok") is True and body.get("stdout") == "hi\n")
say("/sudo enable localhost always")
body, el = c.call("run_privileged", {"host": "localhost", "argv": ["echo", "mcp"]})
check("enabled sudo over MCP: run_privileged runs, no prompt",
      el is None and body.get("ok") is True)
say("/sudo disable localhost")
body, el = c.call("run_privileged", {"host": "localhost", "argv": ["echo", "mcp"]})
check("disabled again over MCP: refused", el is None and body.get("refused") is True)
add_secret("MCP_KEY", "mcp_value_123456", "test")
body, el = c.call("http_request", {"url": A + "/x", "auth_ref": "MCP_KEY"})
check("secret to new host over MCP: refused with hint, no gateway form",
      el is None and body.get("refused") is True and "/gate:secret allow" in body["reason"])
say("/secret allow MCP_KEY 127.0.0.1")
check("/secret allow, then MCP sees the host",
      el is None and vault.secret("MCP_KEY")["hosts"] == ["127.0.0.1"])
body, el = c.call("http_request", {"url": A + "/x", "auth_ref": "MCP_KEY"})
check("allowed secret host over MCP: sent", el is None and body.get("ok") is True)

print("browser form (web_form):")
from gateway import web_form  # noqa: E402
import http.client  # noqa: E402
import re as _re  # noqa: E402
import urllib.request as _ur  # noqa: E402

# A fake "browser": records the URL; then, per FAKE_FORM, fills the form like
# a user would (save VALUE / cancel / nothing).
FAKE_BROWSER = TMP / "fake_browser.py"
FAKE_BROWSER.write_text(r'''
import json, os, re, sys, urllib.parse, urllib.request
url = sys.argv[1]
open(os.environ["FAKE_URL_FILE"], "w").write(url)
plan = json.loads(open(os.environ["FAKE_FORM_FILE"]).read() or "null") if os.path.exists(os.environ["FAKE_FORM_FILE"]) else None
if not plan:
    sys.exit(0)
page = urllib.request.urlopen(url, timeout=10).read().decode()
open(os.environ["FAKE_PAGE_FILE"], "w").write(page)
nonce = re.search(r'name="nonce" value="([^"]+)"', page).group(1)
data = urllib.parse.urlencode({"nonce": nonce, "action": plan["action"],
                               "value": plan.get("value", "")}).encode()
urllib.request.urlopen(urllib.request.Request(url, data=data), timeout=10).read()
''')
FAKE_BROWSER_SH = TMP / "fake_browser.sh"
FAKE_BROWSER_SH.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{FAKE_BROWSER}" "$1"\n')
FAKE_BROWSER_SH.chmod(0o755)
URL_FILE, PAGE_FILE = TMP / "form.url", TMP / "form.html"
PLAN_FILE = TMP / "form.plan"
os.environ.update(GATEWAY_BROWSER=str(FAKE_BROWSER_SH), FAKE_URL_FILE=str(URL_FILE),
                  FAKE_PAGE_FILE=str(PAGE_FILE), FAKE_FORM_FILE=str(PLAN_FILE))


def form_plan(plan):
    PLAN_FILE.write_text(json.dumps(plan))
    for f in (URL_FILE, PAGE_FILE):
        if f.exists():
            f.unlink()


# Security of the form server itself: probe it while it waits.
form_plan(None)
os.environ["GATEWAY_FORM_TIMEOUT"] = "8"
box = {}
th = threading.Thread(target=lambda: box.update(
    v=web_form.ask("Store the secret <X>", [("Description", "<b>desc</b>")], "Value")))
th.start()
deadline = time.time() + 5
while not URL_FILE.exists() and time.time() < deadline:
    time.sleep(0.05)
url = URL_FILE.read_text()
parsed = urllib.parse.urlparse(url)
check("form served on loopback with a long random path",
      parsed.hostname == "127.0.0.1" and len(parsed.path) > 20)


def status(method, path, host=None, body=None):
    conn = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=5)
    headers = {"Host": host or parsed.netloc}
    if body is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    conn.request(method, path, body=body, headers=headers)
    r = conn.getresponse()
    data = r.read().decode()
    conn.close()
    return r.status, data


check("wrong path: 404", status("GET", "/nope")[0] == 404)
check("rebinding Host header: 404", status("GET", parsed.path, host="evil.example")[0] == 404)
code, page = status("GET", parsed.path)
check("page: masked field, no autocomplete",
      code == 200 and 'type="password"' in page and 'autocomplete="new-password"' in page)
check("page: text is HTML-escaped", "&lt;b&gt;desc&lt;/b&gt;" in page and "<b>desc" not in page)
conn = http.client.HTTPConnection("127.0.0.1", parsed.port, timeout=5)
conn.request("GET", parsed.path, headers={"Host": parsed.netloc})
resp = conn.getresponse(); resp.read(); conn.close()
check("page headers: CSP, no-store, X-Frame-Options",
      "default-src 'none'" in resp.getheader("Content-Security-Policy", "")
      and resp.getheader("Cache-Control") == "no-store"
      and resp.getheader("X-Frame-Options") == "DENY")
check("POST without the page's nonce: 403",
      status("POST", parsed.path, body="nonce=wrong&action=save&value=x")[0] == 403)
nonce = _re.search(r'name="nonce" value="([^"]+)"', page).group(1)
code, _ = status("POST", parsed.path, body=f"nonce={nonce}&action=save&value=s%20cret%3D1")
th.join(10)
check("correct POST: value returned exactly (spaces, =)", code == 200 and box.get("v") == "s cret=1")
try:
    status("GET", parsed.path)
    check("one-time: server gone after submit", False)
except OSError:
    check("one-time: server gone after submit", True)

form_plan(None)
os.environ["GATEWAY_FORM_TIMEOUT"] = "1"
t0 = time.time()
check("not submitted: times out with None", web_form.ask("t", [], "v") is None
      and time.time() - t0 < 5)
os.environ["GATEWAY_FORM_TIMEOUT"] = "10"
form_plan({"action": "cancel"})
check("Cancel button: None", web_form.ask("t", [], "v") is None)
os.environ["GATEWAY_BROWSER"] = "none"
try:
    web_form.ask("t", [], "v")
    check("no browser: raises Unavailable", False)
except web_form.Unavailable:
    check("no browser: raises Unavailable", True)
os.environ["GATEWAY_BROWSER"] = str(FAKE_BROWSER_SH)

print("tool list and settings:")
names = {t["name"] for t in c.rpc("tools/list", {})["result"]["tools"]}
check("no vault_* tools any more", not any(n.startswith("vault_") for n in names))
c.close()
_proposed = json.loads((ROOT.parents[1] / "settings.rules.json").read_text())["permissions"]
_gw = "mcp__plugin_gate_gw__"
check("rules template: run_privileged_confirm and port_check on 'ask', not 'allow'",
      all(_gw + t in _proposed["ask"] and _gw + t not in _proposed["allow"]
          for t in ("run_privileged_confirm", "port_check")))
check("rules template: no vault_* rules, no personal paths",
      not any("vault_" in r for k in ("allow", "ask") for r in _proposed[k])
      and "/Users/" not in json.dumps(_proposed) and "/home/" not in json.dumps(_proposed))

print("installer (merge logic, no real settings touched):")
sys.path.insert(0, str(ROOT))
import install  # noqa: E402
rules = install.load_rules(Path.home() / "x" / "plugins" / "gateway")
check("installer: {PLUGIN_DIR} under home becomes ~/...",
      "Edit(~/x/plugins/gateway/config/**)" in rules["deny"])
check("installer: path outside home becomes //abs",
      install.rule_path(Path("/opt/ng")) == "//opt/ng")
before = {"theme": "dark",
          "permissions": {"allow": ["Bash(ls:*)", _gw + "port_check"], "deny": ["Bash(rm:*)"]}}
after, changes = install.merge(before, rules)
check("installer: keeps unrelated settings and rules",
      after["theme"] == "dark" and "Bash(ls:*)" in after["permissions"]["allow"]
      and "Bash(rm:*)" in after["permissions"]["deny"])
check("installer: a stray 'allow' for an ask-tool is moved to 'ask'",
      _gw + "port_check" not in after["permissions"]["allow"]
      and _gw + "port_check" in after["permissions"]["ask"]
      and f"- allow: {_gw}port_check" in changes)
again, changes2 = install.merge(after, rules)
check("installer: idempotent", again == after and changes2 == [])
check("installer: input not mutated", before["permissions"]["allow"] == ["Bash(ls:*)", _gw + "port_check"])

print("linux / headless value entry:")
_saved_env = {k: os.environ.get(k) for k in ("GATEWAY_BROWSER", "DISPLAY", "WAYLAND_DISPLAY",
                                             "SSH_CONNECTION")}
for k in _saved_env:
    os.environ.pop(k, None)
_plat = sys.platform
try:
    sys.platform = "linux"
    check("linux without DISPLAY: no browser (never a console browser)",
          not web_form.gui_available())
    os.environ["DISPLAY"] = ":0"
    check("linux with DISPLAY: browser", web_form.gui_available())
    del os.environ["DISPLAY"]
    os.environ["WAYLAND_DISPLAY"] = "wayland-0"
    check("linux with Wayland: browser", web_form.gui_available())
    del os.environ["WAYLAND_DISPLAY"]
    sys.platform = "darwin"
    os.environ["SSH_CONNECTION"] = "1.2.3.4 1 5.6.7.8 22"
    check("macOS over ssh: no browser", not web_form.gui_available())
finally:
    sys.platform = _plat
    for k, v in _saved_env.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v

os.environ["GATEWAY_BROWSER"] = "none"
out = say("/gate:secret add HEADLESS_K a key added over ssh")
check("no browser: passes through an error with the exact terminal command",
      passed(out) and "pixi run --manifest-path" in out["reason"]
      and "vault secret add HEADLESS_K a key added over ssh" in out["reason"]
      and not vault.secret("HEADLESS_K"))
os.environ["GATEWAY_BROWSER"] = str(FAKE_BROWSER_SH)

# The terminal fallback reuses the same command code with a hidden prompt.
from gateway import commands as _cmds  # noqa: E402
_cmds.VALUE_PROVIDER = lambda title, details, label, optional: "term_value_123456"
try:
    msg = _cmds.run_secret("add TERM_K added from a terminal")
    check("terminal fallback: stores the value, reply has none",
          vault.secret("TERM_K")["value"] == "term_value_123456"
          and "term_value_123456" not in msg)
    _cmds.run_sudo("add termuser box7", session_id="")
    check("terminal fallback: sudo add works", vault.sudo_entries("box7")[0]["password"]
          == "term_value_123456")
    try:
        _cmds.run_sudo("enable box7", session_id="")
        check("terminal fallback: session-only enable needs 'always'", False)
    except _cmds.CommandError as e:
        check("terminal fallback: session-only enable needs 'always'", "always" in str(e))
finally:
    _cmds.VALUE_PROVIDER = None
p = subprocess.run([sys.executable, str(ROOT / "run.py"), "vault", "secret", "add", "X", "d"],
                   stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=30)
check("terminal fallback refuses without a real terminal (never reads a piped value)",
      p.returncode == 2 and "interactive terminal" in p.stderr)
check("/gate:help command exists, mentions the fallback",
      "vault secret add" in (ROOT / "commands" / "help.md").read_text())

# --- Accounts: vault v2 + /gate:account --------------------------------------
print("accounts:")
from gateway import hooks as _hooks  # noqa: E402

# A fake browser that fills every field of the form (plan["fields"]).
ACCT_BROWSER = TMP / "acct_browser.py"
ACCT_BROWSER.write_text(r'''
import json, os, re, sys, urllib.parse, urllib.request
url = sys.argv[1]
plan = json.loads(open(os.environ["ACCT_PLAN"]).read() or "null")
if not plan:
    sys.exit(0)
page = urllib.request.urlopen(url, timeout=10).read().decode()
open(os.environ["ACCT_PAGE"], "w").write(page)
nonce = re.search(r'name="nonce" value="([^"]+)"', page).group(1)
fields = {"nonce": nonce, "action": plan["action"]}
fields.update(plan.get("fields", {}))
urllib.request.urlopen(urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode()),
                       timeout=10).read()
''')
ACCT_BROWSER_SH = TMP / "acct_browser.sh"
ACCT_BROWSER_SH.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{ACCT_BROWSER}" "$1"\n')
ACCT_BROWSER_SH.chmod(0o755)
ACCT_PLAN, ACCT_PAGE = TMP / "acct.plan", TMP / "acct.html"
_old_browser = os.environ["GATEWAY_BROWSER"]
os.environ.update(GATEWAY_BROWSER=str(ACCT_BROWSER_SH), ACCT_PLAN=str(ACCT_PLAN),
                  ACCT_PAGE=str(ACCT_PAGE), GATEWAY_FORM_TIMEOUT="10")


def acct_form(fields=None, action="save"):
    ACCT_PLAN.write_text(json.dumps({"action": action, "fields": fields or {}}))
    if ACCT_PAGE.exists():
        ACCT_PAGE.unlink()


def acct(prompt):
    out = commands.handle({"prompt": prompt, "session_id": SID,
                           "transcript_path": str(TRANSCRIPT)})
    if out is not None:
        out["reason"] = out.get("reason") or out["hookSpecificOutput"]["additionalContext"]
    return out


# v1 vault (no accounts) still reads, and is saved as v2.
_main_home = os.environ["GATEWAY_HOME"]
os.environ["GATEWAY_HOME"] = str(TMP / "vault-v1")
_recipient = vault._ensure_key()
subprocess.run([vault._age(), "-e", "-r", _recipient, "-o", str(vault.store_path())],
               input=json.dumps({"version": 1, "secrets": {"OLD": {"value": "old_value_1",
                                 "description": "d", "hosts": ["a.com"]}}, "sudo": {},
                                 "sudo_enabled": [], "sudo_session": {}}).encode(),
               check=True, capture_output=True)
_d = vault.load()
check("v1 vault loads with an empty accounts section",
      _d["accounts"] == {} and _d["secrets"]["OLD"]["value"] == "old_value_1")
vault.save(_d)
check("v1 vault is saved as version 2", vault.load()["version"] == 2)
os.environ["GATEWAY_HOME"] = _main_home

GH_TOKEN_V = "gho_testtoken0123456789abcdefABCDEF"
acct_form({"host": "github.com", "login": "octo-work", "name": "Octo Work",
           "email": "octo@example.com", "owners": "asirobots, other-org",
           "token": GH_TOKEN_V, "ssh_key_mode": "none", "ssh_key": ""})
out = acct("/gate:account add github work Work GitHub (SSO org)")
a = vault.account("github:work")
check("account add: passes through (no block)", passed(out))
check("account add: token came from the form", a and a["secrets"]["token"] == GH_TOKEN_V)
check("account add: settings and owners stored",
      a["login"] == "octo-work" and a["owners"] == ["asirobots", "other-org"])
check("account add: default hosts for github.com",
      a["hosts"] == ["github.com", "api.github.com"])
check("account add: result never holds the token", GH_TOKEN_V not in out["reason"])
_page = ACCT_PAGE.read_text()
check("account form: kind-specific fields, masked token, no value prefilled",
      'name="login"' in _page and 'name="token" type="password"' in _page
      and 'name="ssh_key_mode"' in _page and GH_TOKEN_V not in _page)
_cat = json.dumps(vault.catalog())
check("catalog: account listed with methods, never the token",
      '"github:work"' in _cat and '"token"' in _cat and GH_TOKEN_V not in _cat)
check("all_values covers account tokens", GH_TOKEN_V in vault.all_values())
check("account add: refuses an existing name",
      "already exists" in acct("/gate:account add github work again")["reason"])
check("account add: unknown kind refused",
      "Unknown kind" in acct("/gate:account add gitlab x desc")["reason"])
check("account add: needs a description",
      "Add a description" in acct("/gate:account add github nodesc")["reason"])
check("account add: bad name refused",
      "not an account name" in acct("/gate:account add github Bad/Name d")["reason"])
check("pasted token in the command is blocked, nothing saved",
      acct(f"/gate:account add github leak {GH_TOKEN_V}").get("decision") == "block"
      and vault.account("github:leak") is None)
acct_form(action="cancel")
check("account form cancelled: nothing stored",
      "Cancelled" in acct("/gate:account add hf c desc")["reason"]
      and vault.account("hf:c") is None)

# up: an empty token keeps the old one; the token field is never prefilled.
acct_form({"host": "github.com", "login": "octo-work", "name": "", "email": "",
           "owners": "asirobots", "token": "", "ssh_key_mode": "none", "ssh_key": ""})
out = acct("/gate:account up github:work Work GitHub, asirobots only")
a = vault.account("github:work")
check("account up: empty token keeps it; owners and description updated",
      a["secrets"]["token"] == GH_TOKEN_V and a["owners"] == ["asirobots"]
      and a["description"] == "Work GitHub, asirobots only")
check("account up: form shows current settings but not the token",
      'value="octo-work"' in ACCT_PAGE.read_text() and GH_TOKEN_V not in ACCT_PAGE.read_text())

# SSH keys: generate, paste, refuse a passphrase-protected key.
acct_form({"host": "nest.pijul.com", "login": "powers", "name": "", "email": "",
           "remote_pijul": "", "owners": "", "ssh_key_mode": "generate", "ssh_key": ""})
out = acct("/gate:account add pijul nest My Nest account")
a = vault.account("pijul:nest")
check("ssh key generated: private key only in the vault",
      a and a["secrets"]["ssh_key"].startswith("-----BEGIN OPENSSH PRIVATE KEY-----"))
check("ssh key generated: the public key is shown to the user",
      a["public_key"].startswith("ssh-ed25519 ") and a["public_key"] in out["reason"])
check("ssh key generated: private key never in the result or catalog",
      "PRIVATE KEY" not in out["reason"] and "PRIVATE KEY" not in json.dumps(vault.catalog()))
check("ssh key generated: fingerprint in the catalog",
      vault.catalog()["accounts"]["pijul:nest"]["key_fingerprint"].startswith("SHA256:"))
check("ssh key generated: no key files left behind",
      not list(vault.home().glob(".keygen-*")))
check("all_values covers account ssh keys", a["secrets"]["ssh_key"].strip() in
      [v.strip() for v in vault.all_values()])
_kd = TMP / "keys"
_kd.mkdir()
subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "x", "-f", str(_kd / "plain")],
               check=True)
subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "a passphrase", "-C", "x",
                "-f", str(_kd / "locked")], check=True)
acct_form({"host": "box.example.com", "user": "deploy", "port": "",
           "ssh_key_mode": "paste", "ssh_key": (_kd / "plain").read_text()})
out = acct("/gate:account add ssh box Deploy box")
a = vault.account("ssh:box")
check("ssh key pasted: stored, public key derived (no file)",
      a and a["public_key"] == (_kd / "plain.pub").read_text().strip().rsplit(" ", 1)[0])
check("fingerprint matches ssh-keygen -l", a["key_fingerprint"] == subprocess.run(
      ["ssh-keygen", "-l", "-f", str(_kd / "plain.pub")], capture_output=True, text=True).stdout.split()[1])
acct_form({"host": "box2.example.com", "user": "deploy", "port": "",
           "ssh_key_mode": "paste", "ssh_key": (_kd / "locked").read_text()})
out = acct("/gate:account add ssh box2 Locked key")
check("passphrase-protected key refused, nothing saved",
      "passphrase" in out["reason"] and vault.account("ssh:box2") is None)
acct_form({"host": "box3.example.com", "user": "deploy", "port": "",
           "ssh_key_mode": "paste", "ssh_key": "not a key"})
check("garbage key refused", "not an OpenSSH private key" in
      acct("/gate:account add ssh box3 Bad key")["reason"])
acct_form({"host": "-oProxyCommand=x", "user": "deploy", "port": "",
           "ssh_key_mode": "none", "ssh_key": ""})
check("host that looks like an ssh option refused",
      "not a valid host" in acct("/gate:account add ssh evil Bad host")["reason"])
check("pubkey shows the public key",
      vault.account("pijul:nest")["public_key"] in acct("/gate:account pubkey pijul:nest")["reason"])

# Scope: owners and hosts.
acct("/gate:account allow github:work p-w-rs ghe.example.com")
a = vault.account("github:work")
check("allow: owner and host (dot = host)",
      "p-w-rs" in a["owners"] and "ghe.example.com" in a["hosts"])
acct("/gate:account disallow github:work p-w-rs ghe.example.com")
a = vault.account("github:work")
check("disallow: owner and host removed",
      "p-w-rs" not in a["owners"] and "ghe.example.com" not in a["hosts"])
check("owners refused on a host-only kind",
      "scoped by host only" in acct("/gate:account allow ssh:box someone")["reason"])

# Prompt policy (stored in the vault, so Claude can't loosen it).
check("prompts: defaults", "read=auto, write=auto, delete=ask, exec=ask"
      in acct("/gate:account prompts github:work")["reason"])
acct("/gate:account prompts github:work write=ask delete=refuse")
check("prompts: per account", vault.effective_prompts(vault.account("github:work"), vault.load())
      == {"read": "auto", "write": "ask", "delete": "refuse", "exec": "ask"})
acct("/gate:account prompts * read=ask")
check("prompts: '*' default applies to other accounts",
      vault.effective_prompts(vault.account("pijul:nest"), vault.load())["read"] == "ask")
check("prompts: bad value refused",
      "should look like" in acct("/gate:account prompts github:work write=yes")["reason"])
acct("/gate:account prompts * reset")
acct("/gate:account prompts github:work reset")
check("prompts: reset", vault.effective_prompts(vault.account("github:work"), vault.load())
      == vault.DEFAULT_PROMPTS)

# Import a /gate:secret value as a token; forget; azure default client.
with vault.locked():
    _d = vault.load()
    _d["secrets"]["HF_IMPORT"] = {"value": "hf_importvalue123456", "description": "to import",
                                  "hosts": [], "updated": ""}
    vault.save(_d)
acct_form({"login": "me", "owners": "", "token": "", "ssh_key_mode": "none", "ssh_key": ""})
acct("/gate:account add hf me My HF")
acct("/gate:account import hf:me HF_IMPORT")
check("import: secret value becomes the account token",
      vault.account("hf:me")["secrets"]["token"] == "hf_importvalue123456")
acct("/gate:account forget hf:me token")
check("forget: token removed", "token" not in vault.account("hf:me")["secrets"])
acct_form({"tenant": "contoso.onmicrosoft.com", "client_id": "", "login": ""})
acct("/gate:account add azure work Work Azure")
check("azure: default client id is the Azure CLI's public client",
      vault.account("azure:work")["client_id"] == vault.AZURE_CLI_CLIENT_ID)
check("login: not available yet, says so",
      "later version" in acct("/gate:account login azure:work")["reason"])

# http_request with an account as auth_ref: only to its hosts.
n = len(HITS)
r = actions.http_request("GET", A + "/x", auth_ref="github:work")
check("account auth_ref refused for a host outside its scope, with the allow hint",
      r.get("refused") is True and "/gate:account allow github:work 127.0.0.1" in r["reason"]
      and len(HITS) == n)
acct("/gate:account allow github:work 127.0.0.1")
r = actions.http_request("GET", A + "/x", auth_ref="github:work")
check("account auth_ref sent to an allowed host", r.get("ok") is True
      and "authorization" in echoed(r))
check("account token hidden from the result", GH_TOKEN_V not in json.dumps(r))
r = actions.http_request("GET", A + "/x", auth_ref="pijul:nest")
check("account without a token can't be used as auth_ref", r.get("ok") is False)

# Logs, session note, wrapper, terminal fallback, delete.
_log = Path(os.environ["GATEWAY_AUDIT_LOG"]).read_text()
check("audit log: account commands logged, no token or key",
      '"account add"' in _log and GH_TOKEN_V not in _log and "PRIVATE KEY" not in _log)
_note = _hooks._catalog_note(SID)
check("session note lists accounts, never values",
      "github:work" in _note and "pijul:nest" in _note and GH_TOKEN_V not in _note
      and "PRIVATE KEY" not in _note)
check("session note tells Claude about /gate:account", "/gate:account add" in _hooks.SESSION_NOTE)
out = json.loads(run_sh("/gate:account list"))
check("wrapper routes /gate:account", "decision" not in out
      and "github:work" in out["hookSpecificOutput"]["additionalContext"])
_cmds.FIELDS_PROVIDER = lambda title, details, fields: {
    "host": "registry.example.com", "login": "bot", "owners": "", "token": "tok_terminal_123456"}
try:
    msg = _cmds.run_account("add registry term From a terminal")
    check("terminal fallback: account add stores the token, reply has none",
          vault.account("registry:term")["secrets"]["token"] == "tok_terminal_123456"
          and "tok_terminal_123456" not in msg)
finally:
    _cmds.FIELDS_PROVIDER = None
acct("/gate:account del registry:term")
check("del", vault.account("registry:term") is None)
check("account help lists the kinds", "github, hf, pijul" in acct("/gate:account help")["reason"])
os.environ["GATEWAY_BROWSER"] = _old_browser

# --- Runner core: credentials for one call, hardened git -----------------------
print("runner:")
import base64 as _b64  # noqa: E402
import shutil as _shutil  # noqa: E402
from gateway import runner  # noqa: E402

RT = TMP / "runner"
RT.mkdir()
RUN_TOKEN = "gho_runnerTOKEN0123456789abcdefXYZ"
GIT_SEEN: list[str] = []
_HTTP_BACKEND = Path(subprocess.run(["git", "--exec-path"], capture_output=True,
                                    text=True).stdout.strip()) / "git-http-backend"


def _git(*a, cwd=None, check=True):
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(["git", *a], cwd=cwd, env=env, capture_output=True, text=True,
                          check=check)


class GitHTTP(http.server.BaseHTTPRequestHandler):
    """git smart HTTP via git-http-backend, behind Basic auth with RUN_TOKEN."""
    def _handle(self):
        auth = self.headers.get("Authorization", "")
        GIT_SEEN.append(auth)
        want = "Basic " + _b64.b64encode(f"x-access-token:{RUN_TOKEN}".encode()).decode()
        if auth != want:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="test"')
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            body = b""
            while True:
                n = int(self.rfile.readline().strip(), 16)
                if n == 0:
                    self.rfile.readline()
                    break
                body += self.rfile.read(n)
                self.rfile.readline()
        else:
            body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        path, _, query = self.path.partition("?")
        env = {"PATH": os.environ["PATH"], "GIT_PROJECT_ROOT": str(RT / "srv"),
               "GIT_HTTP_EXPORT_ALL": "1", "PATH_INFO": path, "QUERY_STRING": query,
               "REQUEST_METHOD": self.command, "REMOTE_USER": "tester",
               "REMOTE_ADDR": "127.0.0.1", "CONTENT_TYPE": self.headers.get("Content-Type", ""),
               "CONTENT_LENGTH": str(len(body)), "GIT_CONFIG_NOSYSTEM": "1",
               "HOME": str(RT), "HTTP_CONTENT_ENCODING": self.headers.get("Content-Encoding", ""),
               "GIT_PROTOCOL": self.headers.get("Git-Protocol", "")}
        p = subprocess.run([str(_HTTP_BACKEND)], input=body, env=env, capture_output=True)
        head, _, rest = p.stdout.partition(b"\r\n\r\n")
        status, headers = 200, []
        for line in head.decode().split("\r\n"):
            k, _, v = line.partition(":")
            if k.lower() == "status":
                status = int(v.strip().split()[0])
            elif k:
                headers.append((k, v.strip()))
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(rest)))
        self.end_headers()
        self.wfile.write(rest)

    do_GET = do_POST = _handle

    def log_message(self, *a):
        pass


(RT / "srv").mkdir()
_git("init", "-q", "--bare", "-b", "main", str(RT / "srv" / "repo.git"))
_git("config", "http.receivepack", "true", cwd=RT / "srv" / "repo.git")
_gsrv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), GitHTTP)
threading.Thread(target=_gsrv.serve_forever, daemon=True).start()
GPORT = _gsrv.server_address[1]
GURL = f"http://127.0.0.1:{GPORT}/repo.git"


def _client(name):
    d = RT / name
    _git("init", "-q", "-b", "main", str(d))
    _git("config", "user.email", "t@example.com", cwd=d)
    _git("config", "user.name", "T", cwd=d)
    (d / "f.txt").write_text(name + "\n")
    _git("add", "f.txt", cwd=d)
    _git("commit", "-q", "-m", name, cwd=d)
    return d


HTTP_CREDS = runner.Creds(host=f"127.0.0.1:{GPORT}", token=RUN_TOKEN, protocols=("http",))

c1 = _client("c1")
n = len(GIT_SEEN)
r = runner.run("git", ["push", GURL, "main"], cwd=c1, creds=HTTP_CREDS, allow_http=True,
               account="github:test", timeout=30)
check("runner: push over http with the account token", r.ok)
check("runner: the server got exactly that token",
      any(RUN_TOKEN not in a and a.startswith("Basic ") for a in GIT_SEEN[n:]))
check("runner: the token is not in the output", RUN_TOKEN not in r.stdout + r.stderr)
check("runner: the pushed commit arrived",
      _git("rev-parse", "main", cwd=RT / "srv" / "repo.git").stdout.strip()
      == _git("rev-parse", "HEAD", cwd=c1).stdout.strip())

c2 = _client("c2")
t0 = time.time()
r = runner.run("git", ["push", GURL, "main:other"], cwd=c2, creds=None, allow_http=True,
               timeout=30)
check("runner: without credentials the push fails at once (no prompt, no hang)",
      not r.ok and time.time() - t0 < 15)

n = len(GIT_SEEN)
r = runner.run("git", ["push", f"http://localhost:{GPORT}/repo.git", "main:other"], cwd=c2,
               creds=HTTP_CREDS, allow_http=True, timeout=30)
check("runner: the token is never offered to another host",
      not r.ok and all("Basic" not in a for a in GIT_SEEN[n:]))

# The user's own environment never reaches the child.
_saved = {k: os.environ.get(k) for k in ("GITHUB_TOKEN", "SSH_AUTH_SOCK", "HTTPS_PROXY", "HF_TOKEN")}
os.environ.update(GITHUB_TOKEN="ghp_ambient_should_not_leak_1234", SSH_AUTH_SOCK="/tmp/nope",
                  HTTPS_PROXY="http://127.0.0.1:9", HF_TOKEN="hf_ambient_should_not_leak")
try:
    _env = runner.child_env()
    check("runner: ambient tokens, agent and proxies are not inherited",
          not any(k in _env for k in ("GITHUB_TOKEN", "SSH_AUTH_SOCK", "HTTPS_PROXY", "HF_TOKEN")))
    r = runner.run("git", ["push", GURL, "main:ambient"], cwd=c2, creds=HTTP_CREDS,
                   allow_http=True, timeout=30)
    check("runner: works with ambient junk set (proxy ignored)", r.ok)
finally:
    for k, v in _saved.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
_fake_home = RT / "home"
_fake_home.mkdir()
(_fake_home / ".gitconfig").write_text("[gwtest]\n\tglobalmarker = yes\n")
_saved_home = os.environ["HOME"]
os.environ["HOME"] = str(_fake_home)
try:
    r = runner.run("git", ["config", "--list", "--show-origin"], cwd=c1)
finally:
    os.environ["HOME"] = _saved_home
check("runner: no global or system git config is read",
      r.ok and "globalmarker" not in r.stdout)

# A hostile repo: every config key / hook that could run code or capture
# credentials during a credentialed call.
evil = _client("evil")
MARK = RT / "marks"
MARK.mkdir()


def _marker(name):
    p = RT / f"{name}.sh"
    p.write_text(f"#!/bin/sh\ntouch {MARK / name}\ncat > {MARK / (name + '.in')} 2>/dev/null\nexit 0\n")
    p.chmod(0o755)
    return str(p)


for hook in ("pre-push", "reference-transaction", "post-checkout", "pre-commit"):
    hp = evil / ".git" / "hooks" / hook
    hp.write_text(f"#!/bin/sh\ntouch {MARK / ('hook-' + hook)}\n")
    hp.chmod(0o755)
for k, v in (("core.fsmonitor", _marker("fsmonitor")), ("core.sshCommand", _marker("sshcmd")),
             ("credential.helper", "!" + _marker("credhelper")), ("core.askPass", _marker("askpass")),
             ("http.proxy", "http://127.0.0.1:9"), ("core.hooksPath", str(evil / ".git" / "hooks")),
             ("remote.origin.url", str(RT / "srv" / "repo.git")),
             ("remote.origin.uploadpack", _marker("uploadpack")),
             ("remote.origin.receivepack", _marker("receivepack"))):
    _git("config", k, v, cwd=evil)
r = runner.run("git", ["push", GURL, "main:evil"], cwd=evil, creds=HTTP_CREDS, allow_http=True,
               timeout=30)
check("hostile repo: push still works through the runner", r.ok)
r2 = runner.run("git", ["fetch", "origin"], cwd=evil, creds=None, timeout=30)
r3 = runner.run("git", ["push", "origin", "main:evil2"], cwd=evil, creds=None, timeout=30)
check("hostile repo: fetch/push to a file remote work", r2.ok and r3.ok)
_marks = sorted(p.name for p in MARK.iterdir())
check("hostile repo: no hook, fsmonitor, sshCommand, askpass, helper or pack program ran",
      _marks == [])
check("hostile repo: the repo's own credential helper never saw the token",
      not (MARK / "credhelper.in").exists())

# Local commands never get a credential (no agent, no helper), but values
# are still scrubbed from what they print.
PLAIN_VALUE = "plain-account-value-without-any-known-prefix"
_git("config", "test.k", PLAIN_VALUE, cwd=c1)
_orig_agent, _orig_feed = runner._Agent, runner._TokenFeed
runner._Agent = runner._TokenFeed = lambda *a, **k: (_ for _ in ()).throw(AssertionError("used"))
try:
    try:
        r = runner.run("git", ["config", "--get", "test.k"], cwd=c1,
                       creds=runner.Creds(host="x", token=PLAIN_VALUE, ssh_key="k"))
    except AssertionError:
        r = None
    check("runner: local commands get no agent and no helper", r is not None and r.ok)
    check("runner: account values are scrubbed from local output too",
          r is not None and PLAIN_VALUE not in r.stdout and "***" in r.stdout)
finally:
    runner._Agent, runner._TokenFeed = _orig_agent, _orig_feed

# Refused before anything runs.
for argv in (["credential", "fill"], ["-c", "core.sshCommand=x", "fetch"], ["fetch", "--upload-pack=x"],
             ["clone", "-u", "x", GURL], ["submodule", "foreach", "id"], ["filter-branch"],
             ["difftool"], ["rebase", "--exec", "id"], ["--git-dir=/tmp", "status"],
             ["bisect", "run", "id"], ["daemon"]):
    try:
        runner.run("git", argv, cwd=c1)
        check(f"runner refuses git {' '.join(argv)[:30]}", False)
    except runner.RunnerError:
        check(f"runner refuses git {' '.join(argv)[:30]}", True)
try:
    runner.run("curl", ["x"], cwd=c1)
    check("runner refuses tools it doesn't know", False)
except runner.RunnerError:
    check("runner refuses tools it doesn't know", True)

# Timeout: a server that accepts and never answers.
_hang = socket.socket()
_hang.bind(("127.0.0.1", 0))
_hang.listen(5)
t0 = time.time()
r = runner.run("git", ["ls-remote", f"http://127.0.0.1:{_hang.getsockname()[1]}/x.git"],
               cwd=c1, allow_http=True, timeout=2)
check("runner: timeout kills the call", r.timed_out and not r.ok and time.time() - t0 < 10)
_hang.close()

_log = Path(os.environ["GATEWAY_AUDIT_LOG"]).read_text()
check("runner: calls are audited without the token",
      '"tool": "git"' in _log and '"account": "github:test"' in _log and RUN_TOKEN not in _log)
check("runner: temp dirs are removed",
      not list(Path(tempfile.gettempdir()).glob("gw-run-*")))

# SSH: a user-level sshd on 127.0.0.1 (no root), a key only in a private agent.
_sshd = _shutil.which("sshd")
SSHD_DIR = RT / "sshd"
SSHD_DIR.mkdir()
_ssh_ok = False
if _sshd:
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(SSHD_DIR / "host")],
                   check=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "acct",
                    "-f", str(SSHD_DIR / "client")], check=True)
    _s = socket.socket()
    _s.bind(("127.0.0.1", 0))
    SPORT = _s.getsockname()[1]
    _s.close()
    (SSHD_DIR / "authorized_keys").write_text((SSHD_DIR / "client.pub").read_text())
    _git_dir = os.path.dirname(_shutil.which("git"))
    (SSHD_DIR / "sshd_config").write_text(
        f"Port {SPORT}\nListenAddress 127.0.0.1\nHostKey {SSHD_DIR / 'host'}\n"
        f"PidFile {SSHD_DIR / 'pid'}\nAuthorizedKeysFile {SSHD_DIR / 'authorized_keys'}\n"
        "PasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n"
        f"StrictModes no\nSetEnv PATH={_git_dir}:/usr/bin:/bin\n")
    subprocess.run([_sshd, "-f", str(SSHD_DIR / "sshd_config"), "-E", str(SSHD_DIR / "log")])
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", SPORT), timeout=0.2).close()
            _ssh_ok = True
            break
        except OSError:
            time.sleep(0.05)
if not _ssh_ok:
    print("  skip ssh runner tests (no sshd could start)")
else:
    _hostpub = (SSHD_DIR / "host.pub").read_text().split()
    KNOWN = f"[127.0.0.1]:{SPORT} {_hostpub[0]} {_hostpub[1]}"
    SSH_URL = f"ssh://{ME}@127.0.0.1:{SPORT}{RT / 'srv' / 'repo.git'}"
    SSH_CREDS = runner.Creds(host=f"127.0.0.1:{SPORT}",
                             ssh_key=(SSHD_DIR / "client").read_text(),
                             public_key=(SSHD_DIR / "client.pub").read_text().strip(),
                             known_hosts=KNOWN)
    cs = _client("cs")
    r = runner.run("git", ["push", SSH_URL, "main:viassh"], cwd=cs, creds=SSH_CREDS, timeout=60)
    check("runner: push over ssh with the account key (private agent)", r.ok)
    check("runner: the private key is never in the output",
          "PRIVATE KEY" not in r.stdout + r.stderr)
    r = runner.run("git", ["push", SSH_URL, "main:nokey"], cwd=cs, creds=None, timeout=60)
    check("runner: ssh without the account key fails (no user keys or agent used)", not r.ok)
    _wrong = runner.Creds(**{**SSH_CREDS.__dict__,
                             "known_hosts": f"[127.0.0.1]:{SPORT} ssh-ed25519 "
                             "AAAAC3NzaC1lZDI1NTE5AAAAIFnM1NquNb+tyuxnElS3PHRWHsDaqb+vuZXJq9vKl1m7"})
    r = runner.run("git", ["push", SSH_URL, "main:wronghost"], cwd=cs, creds=_wrong, timeout=60)
    check("runner: a pinned host key that doesn't match is refused", not r.ok)
    _tofu = runner.Creds(**{**SSH_CREDS.__dict__, "known_hosts": ""})
    r = runner.run("git", ["push", SSH_URL, "main:tofu"], cwd=cs, creds=_tofu, timeout=60)
    check("runner: unpinned host: works, and reports the host key it saw",
          r.ok and any(_hostpub[1] in k for k in r.seen_host_keys))
    _agents = subprocess.run(["pgrep", "-f", "gw-run-"], capture_output=True, text=True).stdout
    check("runner: the private agent is gone after the call", _agents.strip() == "")
    try:
        os.kill(int((SSHD_DIR / "pid").read_text()), 15)
    except (OSError, ValueError):
        pass
_gsrv.shutdown()

# --- git tool, gh tool, GitHub sign-in ---------------------------------------------
print("git tool:")
from gateway import ghops, gitops, logins, mcp_server  # noqa: E402

P = gitops.parse_remote
check("parse: https", P("https://github.com/Acme/repo.git") ==
      {"scheme": "https", "host": "github.com", "port": None, "owner": "Acme", "repo": "repo",
       "cred_host": "github.com"})
check("parse: scp-style ssh", P("git@github.com:acme/r.git")["scheme"] == "ssh"
      and P("git@github.com:acme/r.git")["owner"] == "acme")
check("parse: ssh:// with port", P("ssh://git@host.x:2222/o/r")["cred_host"] == "host.x:2222")
check("parse: local paths and file:// are local", P("/srv/repo.git") is None
      and P("file:///srv/repo.git") is None and P("../other") is None)
try:
    P("https://user:pw@github.com/o/r")
    check("parse: password in URL refused", False)
except gitops.GitRefused:
    check("parse: password in URL refused", True)

_D = {"accounts": {
    "github:acme": {"kind": "github", "hosts": ["github.com", "api.github.com"], "owners": ["acme"]},
    "github:me": {"kind": "github", "hosts": ["github.com", "api.github.com"], "owners": []},
    "hf:me": {"kind": "hf", "hosts": ["huggingface.co"], "owners": []}}}
_R = lambda owner, host="github.com": {"host": host, "owner": owner}  # noqa: E731
check("choose: the owner's account wins over a catch-all",
      gitops.choose_account(_R("Acme"), None, _D)[0] == "github:acme")
check("choose: other owners get the catch-all account",
      gitops.choose_account(_R("someone"), None, _D)[0] == "github:me")
check("choose: no account for an unknown host", gitops.choose_account(_R("x", "gitlab.com"), None, _D) is None)
try:
    gitops.choose_account(_R("someone"), "github:acme", _D)
    check("choose: a named account outside its owners is refused, with the allow hint", False)
except gitops.GitRefused as e:
    check("choose: a named account outside its owners is refused, with the allow hint",
          "/gate:account allow github:acme someone" in str(e))
_D2 = {"accounts": {"github:a": {"kind": "github", "hosts": ["github.com"], "owners": []},
                    "github:b": {"kind": "github", "hosts": ["github.com"], "owners": []}}}
try:
    gitops.choose_account(_R("x"), None, _D2)
    check("choose: two catch-alls are ambiguous", False)
except gitops.GitRefused as e:
    check("choose: two catch-alls are ambiguous", "pass account=" in str(e))
for args, want in ((["status"], "local"), (["commit", "-m", "x"], "local"), (["fetch", "origin"], "read"),
                   (["clone", "u"], "read"), (["push", "origin", "main"], "write"),
                   (["push", "origin", "--delete", "b"], "delete"), (["push", "origin", ":b"], "delete"),
                   (["push", "--force-with-lease", "origin", "main"], "delete"),
                   (["push", "-f", "origin", "main"], "force"), (["push", "origin", "+main"], "force"),
                   (["lfs", "push", "origin"], "write"), (["lfs", "fetch"], "read")):
    check(f"classify git {' '.join(args)}", gitops.classify(args[0], args[1:]) == want)

# A GitHub-like account on the loopback git server (owner "acme").
_acme_srv = RT / "srv" / "acme"
_acme_srv.mkdir(parents=True)
_git("init", "-q", "--bare", "-b", "main", str(_acme_srv / "repo.git"))
_git("config", "http.receivepack", "true", cwd=_acme_srv / "repo.git")
_gsrv2 = http.server.ThreadingHTTPServer(("127.0.0.1", 0), GitHTTP)
threading.Thread(target=_gsrv2.serve_forever, daemon=True).start()
ACME_URL = f"http://127.0.0.1:{_gsrv2.server_address[1]}/acme/repo.git"
with vault.locked():
    _d = vault.load()
    _d["accounts"]["github:acme"] = {
        "kind": "github", "description": "test", "host": "127.0.0.1", "login": "octo",
        "name": "Octo Acme", "email": "octo@acme.example", "owners": ["acme"],
        "hosts": ["127.0.0.1"], "secrets": {"token": RUN_TOKEN}, "prompts": {}}
    _d["accounts"].pop("github:work", None)  # its 127.0.0.1 scope would compete
    vault.save(_d)

W = RT / "work"
W.mkdir()
G = lambda *a, **k: gitops.git_tool(list(a), str(W), **k)  # noqa: E731
check("git tool: local init", G("init", "-q", "-b", "main")["ok"])
r = gitops.git_identity(str(W), "github:acme")
check("git_identity: repo commits as the account",
      r["ok"] and _git("config", "user.email", cwd=W).stdout.strip() == "octo@acme.example")
(W / "a.txt").write_text("a\n")
check("git tool: add + commit (non-interactive)", G("add", "a.txt")["ok"]
      and G("commit", "-q", "-m", "first")["ok"])
r = G("commit", "--allow-empty")
check("git tool: an editor is never opened (with a hint)", not r["ok"] and "-m" in r.get("hint", ""))
G("remote", "add", "origin", ACME_URL)
n = len(GIT_SEEN)
r = G("push", "origin", "main")
check("git tool: push picks the account for host+owner", r["ok"] and r["account"] == "github:acme"
      and r["class"] == "write")
check("git tool: the token reached the server, not the result",
      len(GIT_SEEN) > n and RUN_TOKEN not in json.dumps(r))
check("git tool: fetch works too", G("fetch", "origin")["ok"])

with vault.locked():
    _d = vault.load()
    _d["accounts"]["github:acme"]["prompts"] = {"write": "ask"}
    vault.save(_d)
(W / "b.txt").write_text("b\n")
G("add", "b.txt")
G("commit", "-q", "-m", "second")
r = G("push", "origin", "main")
check("prompt policy ask: git refuses and points at git_confirm",
      r.get("refused") and r.get("use") == "git_confirm")
r = G("push", "origin", "main", confirmed=True)
check("prompt policy ask: git_confirm runs it", r["ok"])
with vault.locked():
    _d = vault.load()
    _d["accounts"]["github:acme"]["prompts"] = {"write": "refuse"}
    vault.save(_d)
check("prompt policy refuse: even git_confirm is refused",
      G("push", "origin", "main", confirmed=True).get("refused") is True)
with vault.locked():
    _d = vault.load()
    _d["accounts"]["github:acme"]["prompts"] = {}
    vault.save(_d)
G("push", "origin", "main:tmpbranch")
r = G("push", "origin", "--delete", "tmpbranch")
check("deletes ask by default (git_confirm)", r.get("use") == "git_confirm")
check("git_confirm deletes", G("push", "origin", "--delete", "tmpbranch", confirmed=True)["ok"])
check("plain force push refused, even confirmed",
      G("push", "-f", "origin", "main", confirmed=True).get("refused") is True)

check("vault guard: cwd in the vault refused",
      gitops.git_tool(["status"], str(vault.home())).get("refused") is True)
check("vault guard: diff --no-index on the vault key refused",
      G("diff", "--no-index", str(vault.key_path()), "/dev/null").get("refused") is True)
check("git config: credential/ssh/hook keys can't be set",
      G("config", "core.sshCommand", "x").get("refused") is True
      and G("config", "credential.helper", "x").get("refused") is True
      and G("config", "url.https://evil/.insteadOf", "https://github.com/").get("refused") is True)
check("git config: ordinary keys and reads are fine",
      G("config", "pull.rebase", "true")["ok"] and G("config", "--get", "pull.rebase")["ok"])
check("plain http to a non-loopback host refused",
      G("ls-remote", "http://example.com/acme/repo.git").get("refused") is True)
r = G("ls-remote", f"http://localhost:{_gsrv2.server_address[1]}/other/repo.git")
check("no matching account: runs without credentials and says so",
      not r["ok"] and r["account"].startswith("none"))
check("args must be a list", G.__call__ and gitops.git_tool("status", str(W))["ok"] is False)

print("gh tool:")
FAKE_GH = RT / "fake-gh"
FAKE_GH.write_text(f'''#!/bin/sh
if [ "$1" = auth ] && [ "$2" = login ]; then
  echo "! One-time code (ABCD-1234) copied to clipboard"
  echo "Open this URL to continue in your web browser: https://github.com/login/device"
  sleep "${{FAKE_GH_SLEEP:-1}}"
  printf 'github.com:\\n    oauth_token: gho_fakeLOGINtoken123456\\n    user: octo-login\\n' > "$GH_CONFIG_DIR/hosts.yml"
  exit 0
fi
echo "args: $*"
[ -n "$GH_ENTERPRISE_TOKEN" ] && [ -z "$GH_TOKEN" ] && echo "gh-token-present"
echo "raw=$GH_ENTERPRISE_TOKEN"
[ -n "$GH_TOKEN" ] && [ -z "$GH_ENTERPRISE_TOKEN" ] && echo "dotcom-token-present"
echo "gh-host=$GH_HOST"
echo "ambient: [$GITHUB_TOKEN]"
[ -n "$GH_CONFIG_DIR" ] && case "$GH_CONFIG_DIR" in *gw-run-*) echo "config: temp";; esac
exit 0
''')
FAKE_GH.chmod(0o755)
os.environ["GATEWAY_BIN_GH"] = str(FAKE_GH)
os.environ["GITHUB_TOKEN"] = "ghp_ambient_must_not_show_0000"
try:
    r = ghops.gh_tool(["pr", "list"], cwd=str(W))
    check("gh: account from the repo's origin", r["ok"] and r["account"] == "github:acme"
          and r["class"] == "read")
    check("gh: GHES host gets GH_ENTERPRISE_TOKEN, hidden from the result",
          "gh-token-present" in r["stdout"] and RUN_TOKEN not in json.dumps(r))
    check("gh: host pinned, temp config dir, no ambient token",
          "gh-host=127.0.0.1" in r["stdout"] and "config: temp" in r["stdout"]
          and "ambient: []" in r["stdout"])
finally:
    os.environ.pop("GITHUB_TOKEN", None)
for args in (["auth", "token"], ["repo", "clone", "a/b"], ["pr", "checkout", "1"],
             ["extension", "install", "x"], ["pr", "view", "--web"],
             ["api", "https://evil.example.com/x"], ["config", "set", "x", "y"],
             ["repo", "create", "a/b", "--clone"], ["repo", "fork", "a/b", "--remote"]):
    check(f"gh refuses {' '.join(args)}",
          ghops.gh_tool(args, cwd=str(W)).get("refused") is True)
for args, want in ((["pr", "list"], "read"), (["pr", "create", "-t", "x"], "write"),
                   (["repo", "delete", "a/b"], "delete"), (["api", "repos/a/b"], "read"),
                   (["api", "-X", "DELETE", "repos/a/b"], "delete"),
                   (["api", "repos/a/b/issues", "-f", "title=x"], "write")):
    check(f"classify gh {' '.join(args)}", ghops.classify(args) == want)
check("gh repo create without clone/push is allowed",
      ghops.gh_tool(["repo", "create", "acme/new", "--private"], cwd=str(W))["ok"])
r = ghops.gh_tool(["repo", "delete", "acme/repo", "--yes"], cwd=str(W))
check("gh: deletes ask by default (gh_confirm)", r.get("use") == "gh_confirm")
check("gh_confirm runs it", ghops.gh_tool(["repo", "delete", "acme/repo", "--yes"],
                                          cwd=str(W), confirmed=True)["ok"])

print("GitHub sign-in:")
with vault.locked():
    _d = vault.load()
    _d["accounts"]["github:sso"] = {"kind": "github", "description": "SSO org", "host": "github.com",
                                    "owners": ["asirobots"], "hosts": ["github.com", "api.github.com"],
                                    "secrets": {}, "prompts": {}}
    vault.save(_d)
acct_form(None)  # the fake browser only opens the page
ACCT_PLAN.write_text("null")
os.environ["GATEWAY_BROWSER"] = str(ACCT_BROWSER_SH)
out = acct("/gate:account login github:sso")
a = vault.account("github:sso")
check("login: token from gh's sign-in stored in the vault",
      a["secrets"].get("token") == "gho_fakeLOGINtoken123456" and a.get("token_source") == "gh-oauth")
check("login: login name filled in from gh", a.get("login") == "octo-login")
check("login: the result never holds the token",
      passed(out) and "gho_fakeLOGINtoken123456" not in out["reason"])
check("login: gh's temp config dir is removed",
      not list(Path(tempfile.gettempdir()).glob("gw-login-*")))
ACCT_PLAN.write_text(json.dumps({"action": "cancel", "fields": {}}))
os.environ["FAKE_GH_SLEEP"] = "20"
with vault.locked():
    _d = vault.load()
    _d["accounts"]["github:sso"]["secrets"] = {}
    vault.save(_d)
t0 = time.time()
out = acct("/gate:account login github:sso")
os.environ.pop("FAKE_GH_SLEEP")
check("login: Cancel on the page stops gh, nothing saved",
      "cancelled" in out["reason"] and not vault.account("github:sso")["secrets"].get("token")
      and time.time() - t0 < 15)
_shown = []
_cmds.LOGIN_SHOW = lambda code, url: _shown.append((code, url))
try:
    msg = _cmds.run_account("login github:sso")
finally:
    _cmds.LOGIN_SHOW = None
check("login (terminal): prints the code instead of a page",
      _shown == [("ABCD-1234", "https://github.com/login/device")] and "Signed in" in msg)
r = ghops.gh_tool(["issue", "list"], account="github:sso")
check("gh: a github.com account gets GH_TOKEN", r["ok"] and "dotcom-token-present" in r["stdout"]
      and "gho_fakeLOGINtoken123456" not in json.dumps(r))
check("login: other kinds say it comes later",
      "later version" in acct("/gate:account login azure:work")["reason"])
os.environ.pop("GATEWAY_BIN_GH")

print("MCP + settings:")
_names = {t["name"] for t in mcp_server.TOOLS}
check("MCP lists the new tools",
      {"account_list", "git", "git_confirm", "git_identity", "gh", "gh_confirm"} <= _names)
r = mcp_server.dispatch("git", {"args": ["status", "--short"], "cwd": str(W)})
check("MCP dispatch: git", r["ok"] is True)
r = mcp_server.dispatch("account_list", {})
check("MCP account_list: never values", r["ok"] and RUN_TOKEN not in json.dumps(r)
      and "github:acme" in r["accounts"])
_rules = json.loads((ROOT.parents[1] / "settings.rules.json").read_text())["permissions"]
check("settings rules: git/gh allowed, the _confirm tools ask",
      all(f"mcp__plugin_gate_gw__{t}" in _rules["allow"] for t in ("git", "gh", "git_identity", "account_list"))
      and all(f"mcp__plugin_gate_gw__{t}" in _rules["ask"] for t in ("git_confirm", "gh_confirm")))
_gsrv2.shutdown()

print(f"\n{PASS} passed, {FAIL} failed")
sys.exit(1 if FAIL else 0)
