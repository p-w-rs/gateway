"""The gateway mod (hooks/mod/, PLAN-v4 phase 1) under Claude Code's own
tools: `claude plugin validate` for the plugin and the marketplace, and
`claude plugin test` for the mod's *.test.ts (the doctor command's output,
the status line and provisioning, against the engine's test kit). Skipped
with a note when no claude binary is found.

Every claude run here gets a fresh scratch CLAUDE_CONFIG_DIR and HOME, an
ANTHROPIC_BASE_URL on a local recording server (never the real API) and
CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1, and none of this process's own
CLAUDE_* variables."""
from __future__ import annotations

import http.server
import json
import os
import re
import shutil
import tempfile
import threading
from pathlib import Path

import harness as H


def _claude() -> str | None:
    for c in (shutil.which("claude"), str(Path.home() / ".local" / "bin" / "claude")):
        if c and os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


class _Api(http.server.BaseHTTPRequestHandler):
    seen: list[str] = []

    def log_message(self, *a):  # noqa: D401 - quiet
        pass

    def _answer(self):
        _Api.seen.append(f"{self.command} {self.path}")
        n = int(self.headers.get("content-length") or 0)
        if n:
            self.rfile.read(n)
        self.send_response(404)
        self.send_header("content-length", "0")
        self.end_headers()

    do_GET = do_POST = _answer


def _run_claude(*args: str, cwd: Path, timeout: float = 180):
    import subprocess
    claude = _claude()
    assert claude
    tmp = Path(tempfile.mkdtemp(prefix="gw-claude-", dir=H.tmp_base()))
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Api)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        (tmp / "cfg").mkdir()
        (tmp / "home").mkdir()
        env = {"PATH": f"{Path(claude).parent}:/usr/bin:/bin:/usr/sbin:/sbin",
               "HOME": str(tmp / "home"), "TMPDIR": str(tmp), "LANG": os.environ.get("LANG", "C.UTF-8"),
               "CLAUDE_CONFIG_DIR": str(tmp / "cfg"),
               "ANTHROPIC_BASE_URL": f"http://127.0.0.1:{srv.server_address[1]}",
               "ANTHROPIC_API_KEY": "sk-ant-api03-test-not-a-key",
               "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1", "DISABLE_AUTOUPDATER": "1"}
        r = subprocess.run([claude, *args], cwd=str(cwd), env=env, capture_output=True,
                           text=True, timeout=timeout, stdin=subprocess.DEVNULL)
        return r
    finally:
        srv.shutdown()
        shutil.rmtree(tmp, ignore_errors=True)


def test_claude_plugin_validate_passes_for_the_plugin_and_the_marketplace():
    if _claude() is None:
        print("    note: claude not found; claude plugin validate skipped")
        return
    r = _run_claude("plugin", "validate", str(H.PLUGIN), cwd=H.PLUGIN)
    out = r.stdout + r.stderr
    assert r.returncode == 0 and "Validation passed" in out, out
    # the hooks module is seen as written: what it hooks, and that its
    # immediate commands answer themselves (literal names it registers); the
    # dialog pane, the Client field module and the guard (PLAN-v4 phase 3)
    assert "./mod/register.tsx hooks: session.start, session.attach, session.detach, " \
        "command.run{command=gate-doctor}" in out, out
    for c in ("gate-doctor", "gate-dialog", "gate-unlock", "gate-lock"):
        assert f"answers its own command: command.run{{command={c}}}" in out, out
    assert "ui.render{component=Pane, requestId=gate-dialog}, ui.message, prompt.edit" in out, out
    assert "surface modules: hooks/mod/field.tsx" in out, out
    # managed execution (PLAN-v4 phase 4): the mod writes exactly these
    # variables (the prefix, the shell Claude Code starts it from, the folder
    # of gate-sh's settings, and SHLVL where it is missing or 0, so the shell
    # that starts the prefix doesn't source ~/.bashrc: 0.9.1) and no other
    assert "env writes: CLAUDE_CODE_SHELL, CLAUDE_CODE_SHELL_PREFIX, GW_MANAGED_DIR, SHLVL\n" in out, out
    # the marketplace: only where this plugin folder sits in its repository (a copy of the
    # plugin folder alone, as the Linux VM runs got before, has no marketplace to validate)
    if not (H.REPO / ".claude-plugin" / "marketplace.json").is_file():
        print("    note: no .claude-plugin/marketplace.json two folders up (a copy of the plugin "
              "folder alone); the marketplace validation is skipped")
        return
    r = _run_claude("plugin", "validate", str(H.REPO), cwd=H.REPO)
    assert r.returncode == 0 and "Validation passed" in r.stdout + r.stderr, r.stdout + r.stderr


def test_claude_plugin_test_runs_the_mods_tests():
    if _claude() is None:
        print("    note: claude not found; claude plugin test skipped")
        return
    before = set(p.name for p in (H.PLUGIN / ".claude-plugin").iterdir())
    r = _run_claude("plugin", "test", str(H.PLUGIN), cwd=H.PLUGIN)
    out = r.stdout + r.stderr
    m = re.search(r"(\d+) pass\s+(\d+) fail", out)
    assert r.returncode == 0 and m and m.group(2) == "0" and int(m.group(1)) >= 21, out
    for name in ("register.test.ts", "lib.test.ts", "dialog.test.ts", "manage.test.ts"):
        assert f"hooks/mod/{name}:" in out, out
    print(f"    note: claude plugin test: {m.group(1)} pass, {m.group(2)} fail")
    assert "/gate-hosts opens the pane" in out and "/gate-accounts shows each state" in out, out
    assert "a typed secret leaves the Client only sealed" in out
    assert "the guard holds back composer typing" in out
    assert "/gate-doctor answers without a model turn (terminal)" in out
    assert "a missing env: provisions by argv" in out
    assert "the daemon is started by argv and this session registers on its UI plane" in out
    assert "/gate-doctor shows the daemon from its /health" in out
    assert "managed mode: session start sets the prefix to gate-sh" in out
    assert "an approved managed = \"off\": no prefix" in out
    # the test kit writes nothing into the plugin folder
    assert set(p.name for p in (H.PLUGIN / ".claude-plugin").iterdir()) == before


def test_hooks_json_keeps_every_classic_hook_beside_the_module():
    hooks = json.loads((H.PLUGIN / "hooks" / "hooks.json").read_text())
    assert hooks["modules"] == ["./mod/register.tsx"]
    events = set(hooks["hooks"])
    assert {"SessionStart", "SubagentStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
            "PostToolUseFailure", "FileChanged"} <= events, events
    starts = [h["args"][1] for h in hooks["hooks"]["SessionStart"][0]["hooks"]]
    # the async build stays (mods may be off); the async hook-daemon starts the
    # gateway daemon and registers the session without mods too (PLAN-v4 phase 2)
    assert starts == ["hook-session", "ensure-env", "hook-daemon"], starts
    daemon = hooks["hooks"]["SessionStart"][0]["hooks"][2]
    assert daemon.get("async") is True and daemon["command"] == "sh", daemon


def test_the_mod_spawns_argv_only_and_reads_no_secret_location():
    src = (H.PLUGIN / "hooks" / "mod" / "register.tsx").read_text()
    assert "['sh', `${$.plugin.root}/hooks/launch.sh`, 'ensure-env']" in src
    assert "['sh', `${$.plugin.root}/hooks/launch.sh`, 'gated', sub]" in src
    assert "'-c'" not in src and '"-c"' not in src, "no shell strings"
    for f in (H.PLUGIN / "hooks" / "mod").glob("*.ts*"):
        if f.name.endswith((".test.ts", ".test.tsx")):
            continue
        text = f.read_text()
        assert "private/" not in text and "vault.age" not in text, f   # never reads the vault
        assert "fs.write" not in text, f


VENDORED_SHA256 = "c2b4c66a6fa3b366c9c64e737621561ac2e6aff33ed620a75d20fbf42586b177"
PUBLISHED_SHA256 = "6bcd37a3b20dce913f82d4b23e4e2b661058b4b953df8a3f8c45d56ac4f72447"
PUBLISHED_LAST = ("})(typeof module !== 'undefined' && module.exports ? module.exports : "
                  "(self.nacl = self.nacl || {}));")
VENDORED_LAST = "})(naclExports = {}); var naclExports; export default naclExports;"
INTEGRITY = "sha512-6rt+RN7aOi1nGMyC4Xa5DdYiukl2UWCbcJft7YhxReBGQD7OAM8Pbxw6YMo4r2diNEA8FEmu32YOn9rhaiE5yw=="


def test_vendored_tweetnacl_is_the_published_file_but_for_its_last_line():
    import hashlib
    vendor = H.PLUGIN / "hooks" / "mod" / "vendor"
    data = (vendor / "nacl-fast.js").read_bytes()
    assert hashlib.sha256(data).hexdigest() == VENDORED_SHA256
    text = data.decode()
    lines = text.split("\n")
    last = [i for i, ln in enumerate(lines) if ln.strip()][-1]
    assert lines[last] == VENDORED_LAST, lines[last]
    lines[last] = PUBLISHED_LAST
    assert hashlib.sha256("\n".join(lines).encode()).hexdigest() == PUBLISHED_SHA256
    doc = (vendor / "VENDOR.md").read_text()
    for value in (VENDORED_SHA256, PUBLISHED_SHA256, INTEGRITY, PUBLISHED_LAST, VENDORED_LAST, "1.0.3"):
        assert value in doc, value
    assert (vendor / "LICENSE.tweetnacl").exists()
    # the random source is set explicitly, never left to the library's sniffing
    seal = (H.PLUGIN / "hooks" / "mod" / "seal.ts").read_text()
    assert "nacl.setPRNG(" in seal and "crypto.getRandomValues(" in seal and "\nsetPrng()\n" in seal


def _lib_matrix() -> list[tuple[str, list[str], str, str]]:
    text = (H.PLUGIN / "hooks" / "mod" / "lib.ts").read_text()
    rows = re.findall(r"\{ feature: '([^']+)', cells: \{ terminal: '(\w+)', desktop: '(\w+)', "
                      r"vscode: '(\w+)', mobile: '(\w+)', print: '(\w+)', remote: '(\w+)' \}, "
                      r"min: '([^']+)', withoutMods: (true|false) \}", text)
    return [(r[0], list(r[1:7]), r[7], "yes" if r[8] == "true" else "no") for r in rows]


def _doc_matrix() -> list[tuple[str, list[str], str, str]]:
    text = (H.REPO / "docs" / "CAPABILITIES.md").read_text()
    head = "| Feature | terminal | desktop | VS Code | mobile | -p / SDK | Remote Control | minimum | without mods |"
    assert head in text
    out = []
    for line in text.split(head, 1)[1].splitlines()[2:]:
        if not line.startswith("|"):
            break
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        out.append((cells[0], cells[1:7], cells[7], cells[8]))
    return out


def test_the_capability_matrix_in_the_docs_is_the_one_the_doctor_prints():
    if not (H.REPO / "docs" / "CAPABILITIES.md").exists():   # a scratch copy (mutations)
        print("    note: no repo docs next to this plugin folder; skipped")
        return
    lib, doc = _lib_matrix(), _doc_matrix()
    assert len(lib) == 14 and lib == doc, (lib, doc)
    allowed = {"yes", "no", "planned", "untested"}
    assert all(set(r[1]) <= allowed for r in lib)
    # every guard works without mods (Anthropic can switch mods off)
    assert all(r[3] == "yes" for r in lib if "classic hooks" in r[0] or "Cold-start guard" in r[0])
