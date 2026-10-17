"""Run a CLI as an account: credentials injected for one call, never on disk.

The MCP tools that act as an account (git first; gh, hf, pijul, ... later)
all go through run(). For each call it:

- builds the child's environment from a short allowlist, so the user's own
  credentials (GITHUB_TOKEN, HF_TOKEN, SSH_AUTH_SOCK, proxies, ...) never
  reach the child;
- makes a private temp dir (0700) for that call: agent socket, credential
  helper, known_hosts, per-tool config dirs; removed afterwards;
- for an SSH key, starts a private ssh-agent and loads the key with
  `ssh-add -` from stdin, so the key exists only in the vault and that
  agent; ssh runs with `-F /dev/null` and offers only that key;
- for a token, gives git a one-shot credential helper that answers only for
  the account's host and reads the token from a FIFO the runner writes;
- for git, overrides every repo-config key that could run code or redirect
  credentials during the call (hooks, fsmonitor, sshCommand, askpass,
  credential helpers, upload/receive-pack, proxies, protocols);
- caps and scrubs the output (the account's values, plus the policy's
  secret patterns), enforces a timeout, and audits the call.

This is a guardrail for a cooperative model, not a sandbox: see
ARCHITECTURE (threat model) for what a CLI holding a token can still do.
"""
from __future__ import annotations

import os
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import policy

# Environment variables a child may inherit. Everything else is dropped.
ENV_ALLOW = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "LC_CTYPE",
             "LC_MESSAGES", "TMPDIR", "TZ", "SYSTEMROOT", "COMSPEC", "PATHEXT")

MAX_OUTPUT = 1_000_000      # bytes kept per stream
DEFAULT_TIMEOUT = 300       # seconds


class RunnerError(Exception):
    """The call was refused before anything ran."""


@dataclass
class Creds:
    """What one call may use. host is what git sees: host or host:port."""
    host: str = ""
    token: str = ""
    username: str = "x-access-token"
    ssh_key: str = ""                 # OpenSSH private key text
    public_key: str = ""              # its public line (selects the agent key)
    known_hosts: str = ""             # pinned known_hosts lines; "" = accept new
    protocols: tuple[str, ...] = ("https",)  # where the token may be offered

    def values(self) -> list[str]:
        return [v for v in (self.token, self.ssh_key.strip()) if v]


@dataclass
class Result:
    ok: bool
    exit_code: int | None
    stdout: str
    stderr: str
    truncated: bool = False
    timed_out: bool = False
    seen_host_keys: list[str] = field(default_factory=list)
    duration_s: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        d = {"ok": self.ok, "exit_code": self.exit_code, "stdout": self.stdout,
             "stderr": self.stderr, "duration_s": round(self.duration_s, 2)}
        if self.truncated:
            d["truncated"] = True
        if self.timed_out:
            d["timed_out"] = True
        if self.seen_host_keys:
            d["seen_host_keys"] = self.seen_host_keys
        return d


def child_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k in ENV_ALLOW}
    env.update(extra or {})
    return env


def _which(tool: str) -> str:
    """GATEWAY_BIN_<TOOL> (tests), then the plugin's own pixi binary (its
    OpenSSH matches the agent we start), then PATH."""
    forced = os.environ.get("GATEWAY_BIN_" + tool.upper().replace("-", "_"))
    if forced:
        return forced
    own = Path(sys.executable).parent / tool
    if own.is_file() and os.access(own, os.X_OK):
        return str(own)
    path = shutil.which(tool)
    if not path:
        raise RunnerError(f"{tool} was not found on PATH")
    return path


# ---------------------------------------------------------------------------
# Private ssh-agent
# ---------------------------------------------------------------------------


class _Agent:
    """A private ssh-agent holding one key, for the length of one call."""

    def __init__(self, tmp: Path, private_key: str):
        self.sock = tmp / "agent.sock"
        self.proc = subprocess.Popen([_which("ssh-agent"), "-D", "-a", str(self.sock)],
                                     stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=subprocess.DEVNULL, env=child_env())
        deadline = time.time() + 5
        while not self.sock.exists():
            if time.time() > deadline or self.proc.poll() is not None:
                self.close()
                raise RunnerError("could not start a private ssh-agent")
            time.sleep(0.02)
        add = subprocess.run([_which("ssh-add"), "-q", "-"],
                             input=private_key.strip().encode() + b"\n",
                             env=child_env({"SSH_AUTH_SOCK": str(self.sock)}),
                             capture_output=True, timeout=15)
        if add.returncode != 0:
            self.close()
            raise RunnerError("the account's SSH key could not be loaded")

    def close(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


# ---------------------------------------------------------------------------
# One-shot credential helper for git over https
# ---------------------------------------------------------------------------

_HELPER = """#!/bin/sh
# gateway: answers `get` for {proto}://{host} only, from a FIFO the gateway writes.
[ "$1" = get ] || exit 0
host=; proto=
while IFS= read -r line; do
  case "$line" in
    host=*) host=${{line#host=}} ;;
    protocol=*) proto=${{line#protocol=}} ;;
    "") break ;;
  esac
done
[ "$host" = {qhost} ] || exit 0
case "$proto" in {protos}) ;; *) exit 0 ;; esac
exec cat {qfifo}
"""


class _TokenFeed:
    """Writes the credential into a FIFO each time the helper reads it,
    until the call ends."""

    def __init__(self, fifo: Path, payload: bytes):
        self.fifo, self.payload = fifo, payload
        self.stop = threading.Event()
        os.mkfifo(fifo, 0o600)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                with open(self.fifo, "wb") as f:  # blocks until the helper reads
                    if self.stop.is_set():
                        return
                    f.write(self.payload)
            except OSError:
                return

    def close(self) -> None:
        self.stop.set()
        try:  # release a writer blocked in open()
            fd = os.open(self.fifo, os.O_RDONLY | os.O_NONBLOCK)
            os.close(fd)
        except OSError:
            pass
        self.thread.join(timeout=2)


# ---------------------------------------------------------------------------
# git
# ---------------------------------------------------------------------------

# Subcommands that talk to a remote (credentials only ever go to these).
GIT_REMOTE = {"fetch", "pull", "push", "clone", "ls-remote", "remote", "submodule",
              "archive", "lfs"}
# Never run through the gateway: they run arbitrary programs, serve
# repositories, or print credentials.
GIT_REFUSED = {"credential", "credential-cache", "credential-store", "daemon",
               "instaweb", "http-backend", "upload-pack", "receive-pack", "shell",
               "upload-archive", "difftool", "mergetool", "filter-branch",
               "remote-ext", "remote-fd", "web--browse", "send-email", "imap-send",
               "p4", "svn", "cvsimport", "cvsserver", "cvsexportcommit", "quiltimport",
               "archimport", "fast-import"}
# Global options a caller may not pass (the runner owns config and paths).
GIT_REFUSED_GLOBAL = ("-c", "--config-env", "--exec-path", "-C", "--git-dir",
                      "--work-tree", "--namespace", "--super-prefix", "--list-cmds")
# Per-call flags that point git at another program.
GIT_REFUSED_FLAGS = ("--upload-pack", "--receive-pack", "-u", "--exec", "-x",
                     "--extcmd", "--tool", "--config", "--template", "--separate-git-dir")


def check_git_argv(argv: list[str]) -> str:
    """Refuse argv the runner won't run; return the subcommand."""
    if not argv:
        raise RunnerError("no git subcommand given")
    sub = argv[0]
    if sub.startswith("-"):
        if sub.split("=", 1)[0] in GIT_REFUSED_GLOBAL or sub.startswith("-c"):
            raise RunnerError(f"git option {sub.split('=', 1)[0]} is not allowed here "
                              "(the gateway sets git's config and paths itself)")
        raise RunnerError("put the git subcommand first, e.g. ['status', '--short']")
    if sub in GIT_REFUSED:
        raise RunnerError(f"'git {sub}' is not run through the gateway")
    for a in argv[1:]:
        flag = a.split("=", 1)[0]
        if flag in GIT_REFUSED_FLAGS and not (sub == "push" and flag == "-u"):
            raise RunnerError(f"git flag {flag} is not allowed here")
    if sub == "submodule" and "foreach" in argv[1:]:
        raise RunnerError("'git submodule foreach' runs shell commands; not allowed here")
    if sub == "bisect" and "run" in argv[1:]:
        raise RunnerError("'git bisect run' runs a command; not allowed here")
    return sub


# A repo's remote.<name>.uploadpack/receivepack is a program git runs (locally
# for file remotes); the explicit flag beats it.
_PACK_FLAG = {"fetch": "--upload-pack=git-upload-pack", "pull": "--upload-pack=git-upload-pack",
              "ls-remote": "--upload-pack=git-upload-pack", "clone": "--upload-pack=git-upload-pack",
              "push": "--receive-pack=git-receive-pack"}


def _with_pack_flag(argv: list[str]) -> list[str]:
    flag = _PACK_FLAG.get(argv[0])
    return [argv[0], flag, *argv[1:]] if flag else list(argv)


def _ssh_command(tmp: Path, creds: Creds | None, agent: _Agent | None) -> tuple[str, Path]:
    """GIT_SSH_COMMAND: no user/system ssh config, only the account's key (or
    none), batch mode, and its own known_hosts."""
    kh = tmp / "known_hosts"
    kh.write_text((creds.known_hosts.strip() + "\n") if creds and creds.known_hosts else "")
    opts = ["-F", "/dev/null", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
            "-o", f"UserKnownHostsFile={kh}", "-o", "GlobalKnownHostsFile=/dev/null",
            "-o", "StrictHostKeyChecking=" + ("yes" if creds and creds.known_hosts else "accept-new"),
            "-o", "IdentitiesOnly=yes"]
    if agent is not None and creds is not None:
        pub = tmp / "id.pub"
        pub.write_text(creds.public_key.strip() + "\n")
        opts += ["-o", f"IdentityAgent={agent.sock}", "-o", f"IdentityFile={pub}"]
    else:
        opts += ["-o", "IdentityAgent=none", "-o", "IdentityFile=none"]
    return shlex.join([_which("ssh"), *opts]), kh


def git_config_overrides(tmp: Path, creds: Creds | None, helper: Path | None,
                         allow_http: bool = False) -> list[str]:
    """`-c` pairs that beat any repo config (command-line config wins)."""
    pairs = [
        "core.hooksPath=/dev/null", "core.fsmonitor=false", "core.askPass=",
        "core.gitProxy=", "core.alternateRefsCommand=", "credential.helper=",
        "credential.interactive=never", "http.proxy=", "https.proxy=",
        "http.sslVerify=true", "http.extraHeader=", "http.cookieFile=",
        "protocol.allow=never", "protocol.https.allow=always",
        "protocol.ssh.allow=always", "protocol.file.allow=always",
        "protocol.ext.allow=never", "protocol.git.allow=never",
        "uploadpack.packObjectsHook=", "submodule.recurse=false",
        "safe.bareRepository=explicit",
    ]
    if allow_http:  # tests and loopback servers only
        pairs.append("protocol.http.allow=always")
    if helper is not None and creds is not None:
        for proto in creds.protocols:
            pairs.append(f"credential.{proto}://{creds.host}.helper={helper}")
    out: list[str] = []
    for p in pairs:
        out += ["-c", p]
    return out


def run(tool: str, argv: list[str], *, cwd: str | Path, creds: Creds | None = None,
        timeout: float = DEFAULT_TIMEOUT, account: str = "", allow_http: bool = False,
        env_extra: dict[str, str] | None = None, stdin: bytes | None = None,
        max_output: int = MAX_OUTPUT) -> Result:
    """Run one command as an account. Only `git` exists so far."""
    if tool != "git":
        raise RunnerError(f"{tool} is not run through the gateway (yet)")
    sub = check_git_argv(argv)
    cwd = Path(cwd)
    if not cwd.is_dir():
        raise RunnerError(f"{cwd} is not a directory")
    secrets = creds.values() if creds else []  # scrubbed from output either way
    if creds is not None and sub not in GIT_REMOTE:
        creds = None  # local commands never see a credential
    tmp = Path(tempfile.mkdtemp(prefix="gw-run-"))
    agent: _Agent | None = None
    feed: _TokenFeed | None = None
    started = time.time()
    try:
        os.chmod(tmp, 0o700)
        if creds and creds.ssh_key:
            agent = _Agent(tmp, creds.ssh_key)
        helper = None
        if creds and creds.token:
            if not creds.host:
                raise RunnerError("a token needs the account's host")
            fifo = tmp / "cred.fifo"
            feed = _TokenFeed(fifo, f"username={creds.username}\npassword={creds.token}\n"
                              .encode())
            helper = tmp / "cred-helper"
            helper.write_text(_HELPER.format(
                proto="|".join(creds.protocols), host=creds.host,
                qhost=shlex.quote(creds.host), protos="|".join(creds.protocols),
                qfifo=shlex.quote(str(fifo))))
            helper.chmod(0o700)
        ssh_cmd, kh = _ssh_command(tmp, creds, agent)
        env = child_env({
            "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull, "GIT_SSH_COMMAND": ssh_cmd,
            "GIT_PAGER": "cat", "PAGER": "cat", "GIT_EDITOR": "false",
            "GIT_SEQUENCE_EDITOR": "false", "GIT_OPTIONAL_LOCKS": "0",
            **(env_extra or {})})
        cmd = [_which("git"), *git_config_overrides(tmp, creds, helper, allow_http),
               *_with_pack_flag(argv)]
        res = _exec(cmd, cwd, env, timeout, stdin, max_output, secrets, started)
        if not (creds and creds.known_hosts):
            res.seen_host_keys = [l for l in kh.read_text().splitlines() if l.strip()]
    finally:
        if feed is not None:
            feed.close()
        if agent is not None:
            agent.close()
        shutil.rmtree(tmp, ignore_errors=True)
    policy.audit("run", {"tool": tool, "account": account, "argv": argv[:40],
                         "cwd": str(cwd), "exit_code": res.exit_code, "ok": res.ok,
                         "timed_out": res.timed_out,
                         "duration_s": round(res.duration_s, 2)})
    return res


# CLIs other than git that run as an account. Their argv rules live with
# their tools (ghops.py, ...); here they only get a clean env, a temp dir
# for config, scrubbed output and the audit.
CLI_TOOLS = {"gh"}


def run_cli(tool: str, argv: list[str], *, cwd: str | Path | None, secrets: list[str],
            env_fn=None, timeout: float = DEFAULT_TIMEOUT, account: str = "",
            stdin: bytes | None = None, max_output: int = MAX_OUTPUT) -> Result:
    """Run `tool argv` with env_fn(tmp) -> extra env (credentials, config
    dirs). The child never inherits the user's environment."""
    if tool not in CLI_TOOLS:
        raise RunnerError(f"{tool} is not run through the gateway (yet)")
    cwd = Path(cwd) if cwd else Path(tempfile.gettempdir())
    if not cwd.is_dir():
        raise RunnerError(f"{cwd} is not a directory")
    tmp = Path(tempfile.mkdtemp(prefix="gw-run-"))
    started = time.time()
    try:
        os.chmod(tmp, 0o700)
        env = child_env({"GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1",
                         "GIT_CONFIG_GLOBAL": os.devnull, "PAGER": "cat",
                         **(env_fn(tmp) if env_fn else {})})
        res = _exec([_which(tool), *argv], cwd, env, timeout, stdin, max_output, secrets,
                    started)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    policy.audit("run", {"tool": tool, "account": account, "argv": argv[:40],
                         "cwd": str(cwd), "exit_code": res.exit_code, "ok": res.ok,
                         "timed_out": res.timed_out, "duration_s": round(res.duration_s, 2)})
    return res


def _exec(cmd: list[str], cwd: Path, env: dict[str, str], timeout: float,
          stdin: bytes | None, max_output: int, secrets: list[str], started: float) -> Result:
    proc = subprocess.Popen(cmd, cwd=cwd, env=env,
                            stdin=subprocess.PIPE if stdin else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)
    timed_out = False
    try:
        out, err = proc.communicate(stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _kill_group(proc)
        out, err = proc.communicate()
    return Result(ok=proc.returncode == 0 and not timed_out,
                  exit_code=None if timed_out else proc.returncode,
                  stdout=_clean(out[:max_output], secrets),
                  stderr=_clean(err[:max_output], secrets),
                  truncated=len(out) > max_output or len(err) > max_output,
                  timed_out=timed_out, duration_s=time.time() - started)


def _kill_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (OSError, AttributeError):
        proc.kill()


def _clean(raw: bytes, secrets: list[str]) -> str:
    text = raw.decode("utf-8", "replace")
    for s in sorted(secrets, key=len, reverse=True):
        text = text.replace(s, "***")
        for line in s.splitlines():  # an SSH key printed line by line
            if len(line) >= 16:
                text = text.replace(line, "***")
    return policy.scrub(text, policy.load_config())
