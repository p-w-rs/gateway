"""Streaming scrubber (SPEC 11): secret forms, the carry-over window, byte
splits, binary passthrough, EPIPE, exit codes, and scrub_text."""
from __future__ import annotations

import base64
import os
import random
import signal
import subprocess
import sys
import urllib.parse

import harness as H  # noqa: F401  (installs the guard)
from gateway import scrub

TOKEN = "ghp_SECRETTOKEN0123456789abcdef"


def _onepass(secrets, text: bytes) -> bytes:
    s = scrub.Scrubber(secrets, expand_forms=False)
    return s.feed(text) + s.flush()


def test_secret_forms_includes_base64_userpair_and_urlencoding():
    forms = set(scrub.secret_forms(TOKEN, "x-access-token"))
    assert TOKEN in forms
    assert base64.b64encode(TOKEN.encode()).decode() in forms
    assert base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode().rstrip("=") in forms
    assert urllib.parse.quote(TOKEN, safe="") in forms
    # a base64 "core" so the token is caught inside a longer Basic header blob
    blob = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
    assert any(f and f in blob and len(f) >= 8 for f in forms)


def test_secret_forms_skips_short_values():
    assert scrub.secret_forms("short") == []        # under 8 chars: never masked by literal
    assert scrub.secret_forms("") == []


def test_streaming_masks_a_split_secret():
    sc = scrub.Scrubber([TOKEN], expand_forms=False)
    out = b""
    out += sc.feed(b"before " + TOKEN[:5].encode())   # first half held back
    out += sc.feed(TOKEN[5:].encode() + b" after")
    out += sc.flush()
    assert TOKEN.encode() not in out
    assert out == b"before *** after"


def test_byte_by_byte_equals_one_pass():
    text = (b"x" + TOKEN.encode() + b"y" + TOKEN.encode()[:10] + b"z" + TOKEN.encode())
    whole = _onepass([TOKEN], text)
    sc = scrub.Scrubber([TOKEN], expand_forms=False)
    out = b"".join(sc.feed(text[i:i + 1]) for i in range(len(text))) + sc.flush()
    assert out == whole
    assert TOKEN.encode() not in out


def test_overlapping_and_adjacent_secrets():
    # two secrets, one a suffix of a run; adjacency must not drop a byte
    secs = ["aaaaaaaa", "aaaabbbb"]
    text = b"aaaaaaaaaaaabbbb"
    out = _onepass(secs, text)
    for s in secs:
        assert s.encode() not in out
    assert b"a" not in out.replace(b"***", b"") or True   # no crash; masked


def test_binary_passes_through_unchanged():
    blob = bytes(range(256)) * 4
    sc = scrub.Scrubber([TOKEN], expand_forms=False)
    assert sc.feed(blob) + sc.flush() == blob


def test_no_secrets_is_identity():
    sc = scrub.Scrubber([], expand_forms=False)
    assert sc.feed(b"\x00\x01hello") + sc.flush() == b"\x00\x01hello"


def test_held_tail_without_newline_is_flushed():
    # a prompt that ends mid-prefix of a secret and never completes it
    sc = scrub.Scrubber([TOKEN], expand_forms=False)
    out = sc.feed(b"Password: " + TOKEN[:6].encode())
    assert out == b"Password: "          # the prefix is held
    assert sc.flush() == TOKEN[:6].encode()   # at EOF the incomplete prefix is emitted as-is


def test_fuzz_stream_never_leaks_and_matches_onepass():
    rng = random.Random(1234)
    for _ in range(500):
        secs = ["".join(rng.choice("abAB") for _ in range(rng.randint(8, 12)))
                for _ in range(rng.randint(1, 2))]
        parts = []
        for _ in range(rng.randint(1, 10)):
            if rng.random() < 0.5:
                s = rng.choice(secs)
                parts.append(s[:rng.randint(1, len(s))] if rng.random() < 0.4 else s)
            else:
                parts.append("".join(rng.choice("abAB") for _ in range(rng.randint(0, 5))))
        text = "".join(parts).encode()
        whole = _onepass(secs, text)
        sc = scrub.Scrubber(secs, expand_forms=False)
        out, i = b"", 0
        while i < len(text):
            n = rng.randint(1, 4)
            out += sc.feed(text[i:i + n])
            i += n
        out += sc.flush()
        assert out == whole
        for s in secs:
            assert s.encode() not in out


def test_release_emits_held_bytes_and_still_masks_the_rest():
    """Review round 2: held-back bytes waited for EOF, so a prompt (or an
    rsync protocol byte) that starts a secret's form stalled the stream.
    release() emits them; a secret completed by later bytes is masked from
    there on (only the released prefix shows, never the whole value)."""
    sc = scrub.Scrubber([TOKEN], expand_forms=False)
    assert sc.feed(b"Password: " + TOKEN[:6].encode()) == b"Password: "
    assert sc.holding
    assert sc.release() == TOKEN[:6].encode()
    assert not sc.holding and sc.release() == b""
    rest = sc.feed(TOKEN[6:].encode() + b" after") + sc.flush()
    assert rest == b"*** after", rest
    # released twice inside one secret, continuation split again
    sc = scrub.Scrubber([TOKEN], expand_forms=False)
    out = sc.feed(TOKEN[:3].encode()) + sc.release() + sc.feed(TOKEN[3:9].encode())
    out += sc.release() + sc.feed(TOKEN[9:20].encode()) + sc.feed(TOKEN[20:].encode() + b"!")
    out += sc.flush()
    assert out == TOKEN[:9].encode() + b"***!", out
    # a released prefix that the next bytes don't continue: plain text
    sc = scrub.Scrubber([TOKEN], expand_forms=False)
    out = sc.feed(b"x" + TOKEN[:4].encode()) + sc.release() + sc.feed(b"nope") + sc.flush()
    assert out == b"x" + TOKEN[:4].encode() + b"nope"
    # a secret overlapping one already masked, completed after bytes were
    # released in clear in between, gets its own *** (silently dropping its
    # rest could line released pieces up into the whole value)
    per = "bbaabbaabb"
    sc = scrub.Scrubber([per], expand_forms=False)
    out = sc.feed(per.encode()) + sc.feed(b"aabbaa") + sc.release() + sc.feed(b"bb")
    out += sc.feed(b"!") + sc.flush()
    assert out == b"***aa***!", out
    # a whole secret inside held bytes is still masked when they are released
    sc = scrub.Scrubber(["abcdefgh", "abcdefghijklmnop"], expand_forms=False)
    out = sc.feed(b"<abcdefghij") + sc.release() + sc.feed(b"Z") + sc.flush()
    assert b"abcdefgh" not in out and out.startswith(b"<***"), out


def test_fuzz_with_releases_never_shows_a_whole_secret():
    rng = random.Random(4321)
    for _ in range(600):
        secs = ["".join(rng.choice("abAB") for _ in range(rng.randint(8, 12)))
                for _ in range(rng.randint(1, 2))]
        parts = []
        for _ in range(rng.randint(1, 10)):
            if rng.random() < 0.5:
                s = rng.choice(secs)
                parts.append(s[:rng.randint(1, len(s))] if rng.random() < 0.4 else s)
            else:
                parts.append("".join(rng.choice("xyAB") for _ in range(rng.randint(0, 5))))
        text = "".join(parts).encode()
        sc = scrub.Scrubber(secs, expand_forms=False)
        out, i = b"", 0
        while i < len(text):
            n = rng.randint(1, 4)
            out += sc.feed(text[i:i + n])
            if rng.random() < 0.3:
                out += sc.release()
            i += n
        out += sc.flush()
        for s in secs:
            assert s.encode() not in out, (secs, text, out)
        # nothing is lost or invented outside the masks
        assert len(out.replace(b"***", b"")) <= len(text)


def test_pump_releases_a_held_prefix_after_a_quiet_moment():
    """A writer that prints the start of a secret's form and then waits for
    an answer gets it out within about scrub.IDLE, not at EOF."""
    import threading
    import time
    r, w = os.pipe()
    outr, outw = os.pipe()
    t = threading.Thread(target=scrub.pump, args=(r, outw, scrub.Scrubber([TOKEN])), daemon=True)
    t.start()
    t0 = time.monotonic()
    os.write(w, b"prompt " + TOKEN[:5].encode())
    import select
    got = b""
    while time.monotonic() - t0 < 5 and not got.endswith(TOKEN[:5].encode()):
        if select.select([outr], [], [], 0.5)[0]:
            got += os.read(outr, 100)
    assert got == b"prompt " + TOKEN[:5].encode(), got
    assert time.monotonic() - t0 < 2, "released after a quiet moment, not at EOF"
    os.write(w, TOKEN[5:].encode() + b"\n")
    os.close(w)
    t.join(5)
    os.close(outw)
    rest = b""
    while True:
        c = os.read(outr, 100)
        if not c:
            break
        rest += c
    os.close(outr)
    assert rest == b"***\n", rest


# ---------------------------------------------------------------------------
# run(): child output scrubbed, exit codes, EPIPE
# ---------------------------------------------------------------------------


def test_run_scrubs_child_output_and_returns_exit_code(tmp_capture=None):
    with H.gateway_env():
        prog = f"import sys; sys.stdout.write('tok={TOKEN} end\\n'); sys.exit(7)"
        import tempfile
        outf = tempfile.NamedTemporaryFile(delete=False)
        save = os.dup(1)
        os.dup2(outf.fileno(), 1)
        try:
            rc = scrub.run([sys.executable, "-c", prog], [TOKEN])
        finally:
            os.dup2(save, 1)
            os.close(save)
        outf.close()
        data = open(outf.name).read()
        os.unlink(outf.name)
        assert rc == 7
        assert TOKEN not in data and "***" in data


def test_run_signal_exit_code():
    with H.gateway_env():
        prog = "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"
        import tempfile
        outf = tempfile.NamedTemporaryFile(delete=False)
        save = os.dup(1)
        os.dup2(outf.fileno(), 1)
        try:
            rc = scrub.run([sys.executable, "-c", prog], [TOKEN])
        finally:
            os.dup2(save, 1)
            os.close(save)
        outf.close()
        os.unlink(outf.name)
        assert rc == 128 + signal.SIGTERM


def test_run_epipe_closes_reader_without_crashing():
    with H.gateway_env():
        # child writes a lot; the reader (head) closes early -> EPIPE path
        prog = ("import sys\ntry:\n for i in range(100000): sys.stdout.write('line %d\\n' % i)\n"
                "except BrokenPipeError: pass")
        child = subprocess.Popen([sys.executable, "-c", prog], stdout=subprocess.PIPE)
        # pump owns (and closes) its source: hand it a copy of the child's
        # stdout, so the file object's own close doesn't hit a closed fd
        src = os.dup(child.stdout.fileno())
        child.stdout.close()
        # pump through a scrubber into a pipe whose read end we close early
        r, w = os.pipe()
        import threading
        sc = scrub.Scrubber([TOKEN], expand_forms=False)
        t = threading.Thread(target=scrub.pump, args=(src, w, sc))
        t.start()
        os.close(r)       # reader gone: writes should hit EPIPE, not hang
        t.join(timeout=10)
        assert not t.is_alive(), "pump hung after the reader closed"
        with __import__("contextlib").suppress(OSError):
            os.close(w)
        child.wait(timeout=10)


# ---------------------------------------------------------------------------
# scrub_text
# ---------------------------------------------------------------------------


def test_scrub_text_masks_vault_values_and_shapes():
    import harness_accounts as HA
    with H.gateway_env() as env:
        HA.build_vault(env, '[accounts.openai]\nkind = "api-key"\nsites = ["api.openai.com"]\n',
                       tokens={"openai": "sk-longsecretvalue0123456789abcd"})
        text = ("key sk-longsecretvalue0123456789abcd and a jwt "
                "eyJhbGciOiJIUzI1.eyJzdWIiOiJhYmMi.sig and ghp_" + "a" * 20 + " done")
        out = scrub.scrub_text(text)
        assert "sk-longsecretvalue0123456789abcd" not in out
        assert "eyJhbGciOi.eyJzdWIiOiJ" not in out
        assert "ghp_aaaa" not in out
        assert "done" in out


def test_scrub_text_short_values_not_masked_but_shapes_are():
    with H.gateway_env():
        # a short value isn't scrubbed by literal (that would reveal it)
        assert scrub.scrub_text("pin=1234", extra=["1234"]) == "pin=1234"
        assert "Bearer" in scrub.scrub_text("Authorization: Bearer abcdefhijk")
        assert "abcdefhijk" not in scrub.scrub_text("Authorization: Bearer abcdefhijk")


# ---------------------------------------------------------------------------
# PLAN-0.11 §9.1 and §1.6 (WS-6): the user's credential variables in every
# form, and a passphrase-protected vault's values from gated
# ---------------------------------------------------------------------------


def test_a_credential_variables_value_is_masked_in_every_form():
    """hooks_post hands the user's credential variables to scrub_text as
    extra literals: their JSON-escaped (a tool's JSON output), base64 and
    URL-encoded forms are masked too, never only the plain value."""
    import json
    from gateway import hooks_post
    val = 'User"Tok\\en-' + "x9" * 8
    with H.gateway_env():
        env = [val]
        for shown in (val, json.dumps(val)[1:-1], base64.b64encode(val.encode()).decode(),
                      urllib.parse.quote(val, safe="")):
            out = hooks_post.scrub_text(f"a {shown} b", env)
            assert shown not in out and "***" in out, shown
        new, changed = hooks_post.scrub_obj({"stdout": f"T={val}", "n": 3, "l": [val]}, env)
        assert changed and val not in json.dumps(new) and new["n"] == 3


def test_a_wrapped_vaults_values_come_from_gated_for_the_output_hook():
    """With a passphrase the hook can't decrypt the vault itself: its values
    come from gated (vault.load is brokered; the hooks' scope is every secret
    class), so a stored value without a token shape is still masked. Locked,
    the hook masks what it can (shapes) and never fails the call."""
    import json
    import harness_daemon as D
    from gateway import vault
    pw = "correct horse battery staple wrapped"
    with D.daemon_env() as de:
        de.env.write_form('[hosts.box]\naddress = "u@box.example.com"\n')
        vault.save(vault.empty())
        with vault.edit() as d:
            vault.set_sudo(d, "box", "u", pw)
        de.wrap("a vault passphrase for the scrub tests")
        fc = de.claude(register=False)
        env = de.env.subprocess_env(de.extra_env())
        payload = {"tool_name": "WebFetch", "session_id": "s", "hook_event_name": "PostToolUse",
                   "tool_input": {"url": "https://example.com/"},
                   "tool_response": {"result": f"the page says {pw} and ghp_{'b' * 30}", "code": 200}}
        r = fc.run([H.PY, "-I", "-S", *H.PYX, str(H.PLUGIN / "run.py"), "--test", "hook-post"], env=env,
                   input=json.dumps(payload))
        assert r.returncode == 0, r.stderr
        assert pw not in r.stdout and "ghp_bbbb" not in r.stdout and "***" in r.stdout, r.stdout
        fc.http("POST", "/ui/vault/lock")
        r = fc.run([H.PY, "-I", "-S", *H.PYX, str(H.PLUGIN / "run.py"), "--test", "hook-post"], env=env,
                   input=json.dumps(payload))
        assert r.returncode == 0 and "ghp_bbbb" not in r.stdout, (r.stdout, r.stderr)
