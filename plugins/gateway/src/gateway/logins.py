"""SSO sign-in for accounts, run only from the user's /gate:account login.

GitHub: the plugin's own gh runs `gh auth login --web` in a throwaway
GH_CONFIG_DIR with --insecure-storage, so it writes the OAuth token into
that dir instead of the keychain. A local page shows gh's one-time code and
a link to GitHub's device page (where an SSO org's sign-in happens as
usual). When gh finishes, the token is read from the dir into the vault
and the dir is removed. gh's OAuth app is one many orgs already allow; this
doesn't copy its client id into the gateway. Verified to work for the
SSO-only asirobots org on 2026-10-17.
"""
from __future__ import annotations

import os
import re
import select
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Callable

from . import runner, web_form

GITHUB_SCOPES = "workflow,read:packages,write:packages"  # gh adds repo, read:org, gist
LOGIN_TIMEOUT = 270  # the UserPromptSubmit hook allows 330 s in all
_CODE = re.compile(r"one-time code[^A-Z0-9]*([A-Z0-9]{4}-[A-Z0-9]{4})", re.I)


class LoginError(Exception):
    pass


def github_login(host: str, show: Callable[[str, str], object] | None = None,
                 timeout: float = LOGIN_TIMEOUT) -> tuple[str, str]:
    """Sign in to GitHub (host) through gh's web flow. Returns (token, user).
    show(code, url) presents the code (terminal fallback); default: a local
    page. Raises LoginError."""
    gh = runner._which("gh")
    tmp = Path(tempfile.mkdtemp(prefix="gw-login-"))
    notice = None
    try:
        os.chmod(tmp, 0o700)
        env = runner.child_env({"GH_CONFIG_DIR": str(tmp), "GH_BROWSER": "true",
                                "BROWSER": "true", "GH_NO_UPDATE_NOTIFIER": "1",
                                "GH_PROMPT_DISABLED": "", "NO_COLOR": "1"})
        proc = subprocess.Popen(
            [gh, "auth", "login", "--hostname", host, "--git-protocol", "https", "--web",
             "--insecure-storage", "--skip-ssh-key", "--scopes", GITHUB_SCOPES],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=env, cwd=tmp, start_new_session=True)
        proc.stdin.write(b"\n")  # "Press Enter to open ... in your browser"
        proc.stdin.flush()
        out, code, url = b"", "", f"https://{host}/login/device"
        deadline = time.time() + 30
        while not code and time.time() < deadline and proc.poll() is None:
            r, _, _ = select.select([proc.stdout], [], [], 0.25)
            if r:
                chunk = os.read(proc.stdout.fileno(), 4096)
                out += chunk
                m = _CODE.search(out.decode("utf-8", "replace"))
                if m:
                    code = m.group(1)
                found = re.search(rb"https://\S+/login/device", out)
                if found:
                    url = found.group(0).decode()
        if not code:
            proc.kill()
            raise LoginError("gh did not start a sign-in (no one-time code); "
                             + out.decode("utf-8", "replace").strip()[-300:])
        cancelled = None
        if show is not None:
            show(code, url)
        else:
            notice = web_form.Notice(
                f"Sign in to {host}", "Open GitHub, enter this code, approve, and finish any "
                "SSO step. Then come back to Claude; this page can be closed.",
                code, url, "Open GitHub")
            cancelled = notice.cancelled
        end = time.time() + timeout
        while proc.poll() is None:
            if (cancelled is not None and cancelled.is_set()) or time.time() > end:
                proc.kill()
                proc.wait()
                raise LoginError("sign-in cancelled" if cancelled is not None
                                 and cancelled.is_set() else "sign-in timed out")
            r, _, _ = select.select([proc.stdout], [], [], 0.25)
            if r:
                out += os.read(proc.stdout.fileno(), 4096)
        if proc.returncode != 0:
            raise LoginError("gh sign-in failed: "
                             + out.decode("utf-8", "replace").strip()[-300:])
        hosts = (tmp / "hosts.yml").read_text() if (tmp / "hosts.yml").exists() else ""
        token = re.search(r"oauth_token:\s*(\S+)", hosts)
        user = re.search(r"^\s+user:\s*(\S+)", hosts, re.M)
        if not token:
            raise LoginError("gh finished but left no token")
        return token.group(1), (user.group(1) if user else "")
    finally:
        if notice is not None:
            notice.close()
        shutil.rmtree(tmp, ignore_errors=True)
