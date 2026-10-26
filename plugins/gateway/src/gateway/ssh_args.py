"""Command lines of the ssh family stand-ins (SPEC 9.2): parsing and the
refused options.

ssh is parsed the way OpenSSH's own (BSD) getopt does it: options until the
first operand (the destination), then options again after the destination
unless `--` came first, then the remote command. The flag sets are OpenSSH
10.x's (`1246ACGKMNTVXYZafgknqstvxy` and the options taking an argument
`BDEFIJLOPQRSWbceilmopw`).

Refused (exit 2 with a reason): options that change identity, known hosts,
proxying, agent use, local commands or connection sharing (-F -i -S -A -J -W
-w -R -O -M -I -X -Y -K -g -G -Z) and every `-o` keyword outside a small
allowlist (and, for some keywords, outside the safe value: `ForwardAgent=no`
is fine, `ForwardAgent=yes` is not). `-o Port`/`-o User` are treated like
`-p`/`-l`: the stand-in checks them against the form and drops them.
Forwarded ports (-L, -D, LocalForward, DynamicForward) must listen on this
machine's loopback: an explicit bind address like `*`, `0.0.0.0`, an empty
one or a LAN address is refused (like -g; ssh honours explicit bind
addresses whatever GatewayPorts says).

scp and sftp are only checked for refused options here; the ssh stand-in
they run (`-S`) does the rest.
"""
from __future__ import annotations

import os
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from typing import Any

SSH_FLAGS = frozenset("1246ACGKMNTVXYZafgknqstvxy")
SSH_ARGOPTS = frozenset("BDEFIJLOPQRSWbceilmopw")
SCP_FLAGS = frozenset("12346ABCTdfOpqRrstv")
SCP_ARGOPTS = frozenset("DFJMPSXcilo")
SFTP_FLAGS = frozenset("1246AafhNpqrvC")
SFTP_ARGOPTS = frozenset("cDiloSsbBFJPRX")

SSH_REFUSED = {
    "F": "the gateway writes its own ssh config",
    "i": "Claude's keys come from the gateway",
    "S": "the gateway manages shared connections itself",
    "A": "agent forwarding is off",
    "J": "use via = \"JUMP\" in gateway.toml instead",
    "W": "stdio forwarding isn't available",
    "w": "tunnel devices aren't available",
    "R": "remote forwarding isn't available",
    "O": "the gateway manages shared connections itself",
    "M": "the gateway manages shared connections itself",
    "I": "PKCS#11 keys aren't used",
    "X": "X11 forwarding is off",
    "Y": "X11 forwarding is off",
    "K": "GSSAPI credentials aren't forwarded",
    "g": "it would let other machines use forwarded ports",
    "G": "gate status shows how hosts are reached",
    "Z": "gate status shows the keys",
}
SCP_REFUSED = {
    "S": "the gateway runs its own ssh",
    "F": "the gateway writes its own ssh config",
    "i": "Claude's keys come from the gateway",
    "J": "use via = \"JUMP\" in gateway.toml instead",
    "A": "agent forwarding is off",
    "D": "a local sftp server isn't run",
    "M": "isn't available here",
    "T": "scp's filename checks stay on",
    "f": "server mode isn't available",
    "t": "server mode isn't available",
}
SFTP_REFUSED = {
    "S": "the gateway runs its own ssh",
    "F": "the gateway writes its own ssh config",
    "i": "Claude's keys come from the gateway",
    "J": "use via = \"JUMP\" in gateway.toml instead",
    "A": "agent forwarding is off",
    "D": "a local sftp server isn't run",
    "s": "a server path there runs that command on the host (sudo too)",
}

# -o keywords the stand-ins pass through: None = any value, else the only
# accepted values (lowercase). Everything else is refused.
O_ALLOWED: dict[str, frozenset[str] | None] = {
    "addressfamily": None, "batchmode": frozenset({"yes"}), "bindaddress": None,
    "bindinterface": None, "channeltimeout": None, "checkhostip": frozenset({"no"}),
    "ciphers": None, "clearallforwardings": frozenset({"yes"}), "compression": None,
    "connectionattempts": None, "connecttimeout": None, "controlmaster": frozenset({"no"}),
    "dynamicforward": None, "enableescapecommandline": None, "escapechar": None,
    "exitonforwardfailure": None, "fingerprinthash": None, "forkafterauthentication": None,
    "forwardagent": frozenset({"no"}), "forwardx11": frozenset({"no"}),
    "forwardx11trusted": frozenset({"no"}), "forwardx11timeout": None,
    "gatewayports": frozenset({"no"}), "hostkeyalgorithms": None, "ipqos": None,
    "kexalgorithms": None, "localforward": None, "loglevel": None, "logverbose": None,
    "macs": None, "numberofpasswordprompts": None, "obscurekeystroketiming": None,
    "permitlocalcommand": frozenset({"no"}), "rekeylimit": None,
    "remotecommand": frozenset({"none"}), "requesttty": None, "sendenv": None,
    "serveraliveinterval": None, "serveralivecountmax": None, "sessiontype": None,
    "setenv": None, "stdinnull": None, "streamlocalbindmask": None,
    "streamlocalbindunlink": None, "stricthostkeychecking": frozenset({"yes"}),
    "syslogfacility": None, "tag": None, "tcpkeepalive": None,
    "updatehostkeys": frozenset({"no"}), "visualhostkey": None, "warnweakcrypto": None,
    # checked against the form and dropped by the stand-in (like -p / -l)
    "port": None, "user": None,
}
_O_RE = re.compile(r"\s*([A-Za-z][A-Za-z0-9]*)\s*(?:=\s*|\s+)(.*?)\s*\Z", re.S)


class Refused(Exception):
    """A command line the stand-in won't run (exit 2). `message` starts with
    'gateway:' and says what to do instead."""

    def __init__(self, message: str, option: str = ""):
        super().__init__(message)
        self.message = message
        self.option = option


@dataclass
class OOpt:
    key: str            # lowercase keyword
    value: str
    raw: str            # as given (passed through unchanged)


@dataclass
class SshArgs:
    argv: list[str]
    opts: list[tuple[str, str | None]] = field(default_factory=list)   # in order, -o included
    # PLAN-v4 phase 7: the forwarding kinds asked for (agent, x11, remote,
    # stdio), parsed only with parse_ssh(..., forwards=True): the stand-in
    # then decides each by the host's policy (off unless the host's own policy
    # table turns it on)
    oopts: list[OOpt] = field(default_factory=list)
    dest: str | None = None
    command: list[str] = field(default_factory=list)
    login: str | None = None          # -l or -o User
    port: str | None = None           # -p or -o Port
    terminated: bool = False          # "--" came before the destination
    forwards: list[str] = field(default_factory=list)

    def has(self, letter: str) -> bool:
        return any(c == letter for c, _ in self.opts)

    @property
    def command_text(self) -> str:
        """The remote command as ssh sends it (words joined by spaces)."""
        return " ".join(self.command)

    def kept_options(self) -> list[str]:
        """The caller's options to pass on: -l/-p and -o Port/User dropped
        (the generated config has them), everything else as given."""
        out: list[str] = []
        oi = iter(self.oopts)
        for c, v in self.opts:
            if c == "o":
                o = next(oi)
                if o.key in ("port", "user"):
                    continue
                out += ["-o", o.raw]
            elif c in ("l", "p"):
                continue
            else:
                out.append("-" + c)
                if v is not None:
                    out.append(v)
        return out


def _parse_o(raw: str, tool: str) -> OOpt:
    m = _O_RE.match(raw)
    if not m:
        raise Refused(f"gateway: {tool} -o needs Key=Value (got an option without a value)", "o")
    key, value = m.group(1).lower(), m.group(2)
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if key not in O_ALLOWED:
        raise Refused(f"gateway: {tool} -o {m.group(1)} isn't allowed here (it changes how the "
                      "gateway connects); run the command without it", "o " + key)
    allowed = O_ALLOWED[key]
    if allowed is not None and value.strip().lower() not in allowed:
        raise Refused(f"gateway: {tool} -o {m.group(1)}={value.strip()[:20]} isn't allowed here; "
                      "run the command without it", "o " + key)
    return OOpt(key=key, value=value.strip(), raw=raw)


def _getopt(argv: list[str], i: int, flags: frozenset[str], argopts: frozenset[str], tool: str,
            out: list[tuple[str, str | None]]) -> tuple[int, bool]:
    """BSD getopt from argv[i]: (index of the first operand, saw "--")."""
    n = len(argv)
    while i < n:
        a = argv[i]
        if a == "--":
            return i + 1, True
        if not a.startswith("-") or a == "-":
            return i, False
        j = 1
        while j < len(a):
            c = a[j]
            if c in flags:
                out.append((c, None))
                j += 1
                continue
            if c in argopts:
                if j + 1 < len(a):
                    val = a[j + 1:]
                else:
                    i += 1
                    if i >= n:
                        raise Refused(f"gateway: {tool} -{c} needs a value", c)
                    val = argv[i]
                out.append((c, val))
                break
            raise Refused(f"gateway: {tool} doesn't know the option -{c}", c)
        i += 1
    return i, False


# The forwarding options a host's policy may grant (PLAN-v4 phase 7): option
# letter -> policy kind; and the -o keywords (value "yes") that ask for them.
FORWARD_FLAGS = {"A": "agent", "X": "x11", "Y": "x11", "R": "remote", "W": "stdio"}
FORWARD_O = {"forwardagent": "agent", "forwardx11": "x11", "forwardx11trusted": "x11",
             "remoteforward": "remote"}


def _check(tool: str, opts: list[tuple[str, str | None]], refused: dict[str, str],
           forwards: list[str] | None = None) -> list[OOpt]:
    oopts = []
    for c, v in opts:
        if forwards is not None and c in FORWARD_FLAGS:
            if FORWARD_FLAGS[c] not in forwards:
                forwards.append(FORWARD_FLAGS[c])
            if c == "R":
                check_forward(v or "", False, "ssh -R")
            elif c == "W" and not re.fullmatch(r"[A-Za-z0-9._\[\]:%-]{1,300}:[0-9]{1,5}", v or ""):
                raise Refused("gateway: ssh -W takes HOST:PORT", "W")
            continue
        if c in refused:
            raise Refused(f"gateway: {tool} -{c} isn't allowed here ({refused[c]}); run "
                          f"`{tool}` without it", c)
        if c == "o":
            raw = v or ""
            m = _O_RE.match(raw)
            key = m.group(1).lower() if m else ""
            if forwards is not None and key in FORWARD_O:
                val = m.group(2).strip().strip("\"'") if m else ""
                if key == "remoteforward":
                    w = val.split()
                    check_forward(f"{w[0]}:{w[1]}" if len(w) >= 2 else (w[0] if w else ""), False,
                                  "ssh -o RemoteForward")
                    kind = "remote"
                elif val.lower() == "yes":
                    kind = FORWARD_O[key]
                else:
                    oopts.append(_parse_o(raw, tool))
                    continue
                if kind not in forwards:
                    forwards.append(kind)
                oopts.append(OOpt(key=key, value=val, raw=raw))
                continue
            oopts.append(_parse_o(raw, tool))
    return oopts


# ---------------------------------------------------------------------------
# Forwarded ports: only on this machine's loopback (like -g, an explicit bind
# address such as `*`, `0.0.0.0` or a LAN address would open the port to
# other machines; ssh honours it whatever GatewayPorts says).
# ---------------------------------------------------------------------------

LOOPBACK = frozenset({"localhost", "127.0.0.1", "::1"})


def _fwd_fields(spec: str) -> list[tuple[str, bool]] | None:
    """Split a forwarding spec like OpenSSH's parse_fwd_field: fields split by
    ':', `[...]` taken literally, a backslash escapes the next character, a
    field containing '/' is a unix socket path. None if malformed."""
    s = spec.lstrip(" \t")
    i, out = 0, []
    while len(out) < 4 and i < len(s):
        if s[i] == "[":
            j = s.find("]", i + 1)
            if j < 0 or (j + 1 < len(s) and s[j + 1] != ":"):
                return None
            arg = s[i + 1:j]
            out.append((arg, "/" in arg))
            i = j + 2
            continue
        buf: list[str] = []
        ispath = False
        j = i
        while j < len(s):
            c = s[j]
            if c == "\\":
                if j + 1 >= len(s):
                    return None
                buf.append(s[j + 1])
                j += 2
                continue
            if c == ":":
                break
            if c == "/":
                ispath = True
            buf.append(c)
            j += 1
        out.append(("".join(buf), ispath))
        i = j + 1 if j < len(s) else j
    if i < len(s) or not out:
        return None
    return out


def forward_listen_host(spec: str, dynamic: bool) -> str | None:
    """The bind address of a -L/-D spec (OpenSSH parse_forward), None when
    there is none (the default: loopback) or it listens on a unix socket.
    Raises Refused for a spec ssh wouldn't take either."""
    f = _fwd_fields(spec)
    if f is None or (dynamic and len(f) > 2):
        raise Refused(f"gateway: ssh -{'D' if dynamic else 'L'} {spec[:40]} isn't a forwarding "
                      "spec ssh takes", "D" if dynamic else "L")
    n = len(f)
    if n == 1:
        return None
    if n == 2:
        if f[1][1]:                       # PORT:REMOTE_SOCKET or LOCAL_SOCKET:REMOTE_SOCKET
            return None
        return f[0][0]                    # (dynamic) HOST:PORT
    if n == 3:
        if f[0][1]:                       # LOCAL_SOCKET:HOST:PORT
            return None
        return f[0][0] if f[2][1] else None    # HOST:PORT:REMOTE_SOCKET / PORT:HOST:PORT
    return f[0][0]                        # HOST:PORT:HOST:PORT


def check_forward(spec: str, dynamic: bool, what: str) -> None:
    host = forward_listen_host(spec, dynamic)
    if host is not None and host.lower() not in LOOPBACK:
        raise Refused(f"gateway: {what} {spec[:40]} would open a port to other machines; bind it "
                      f"to localhost (for example {'-D 1080' if dynamic else '-L 8080:HOST:PORT'})",
                      "D" if dynamic else "L")


def listen_is_local(listen: str) -> bool:
    """The listen side of `ssh -G`'s localforward/dynamicforward lines: a port
    alone, a unix socket path, or [HOST]:PORT with a loopback HOST."""
    if listen.startswith("/"):
        return True
    if listen.startswith("["):
        return listen[1:].split("]", 1)[0].lower() in LOOPBACK
    return listen.isdigit()


def parse_ssh(argv: list[str], forwards: bool = False) -> SshArgs:
    """Parse an ssh command line. Raises Refused. With forwards=True the
    forwarding options a host's policy may grant (-A -X -Y -R -W and their -o
    forms) are collected into `.forwards` instead of refused; the caller must
    decide each one (a remote forward still binds only to the host's
    loopback)."""
    argv = list(argv)
    a = SshArgs(argv=argv)
    i, term = _getopt(argv, 0, SSH_FLAGS, SSH_ARGOPTS, "ssh", a.opts)
    a.terminated = term
    if i < len(argv):
        a.dest = argv[i]
        i += 1
        if not term and i < len(argv):
            i, _ = _getopt(argv, i, SSH_FLAGS, SSH_ARGOPTS, "ssh", a.opts)
    a.command = argv[i:]
    a.oopts = _check("ssh", a.opts, SSH_REFUSED, a.forwards if forwards else None)
    for c, v in a.opts:
        if c in ("L", "D"):
            check_forward(v or "", c == "D", f"ssh -{c}")
    for o in a.oopts:
        if o.key in ("localforward", "dynamicforward"):
            w = o.value.split()
            spec = (f"{w[0]}:{w[1]}" if len(w) >= 2 and o.key == "localforward"
                    else (w[0] if w else ""))
            check_forward(spec, o.key == "dynamicforward", f"ssh -o {o.key}")
    for c, v in a.opts:
        if c == "l":
            a.login = v
        elif c == "p":
            a.port = v
    for o in a.oopts:   # ssh: the first value wins, and -l/-p beat -o
        if o.key == "user" and a.login is None:
            a.login = o.value
        elif o.key == "port" and a.port is None:
            a.port = o.value
    return a


@dataclass
class Lenient:
    """What a lenient parse finds (PLAN-0.11 §1.4 step 1): the destination,
    its options and the remote command, refusing nothing (the refusals apply
    only on a configured target's gated path)."""
    dest: str | None = None
    opts: list[tuple[str, str | None]] = field(default_factory=list)
    command: list[str] = field(default_factory=list)
    login: str | None = None
    port: str | None = None

    def o_values(self, key: str) -> list[str]:
        """Every `-o KEY=VALUE` value for this (lowercase) keyword."""
        out = []
        for c, v in self.opts:
            if c == "o" and v:
                m = _O_RE.match(v)
                if m and m.group(1).lower() == key:
                    out.append(m.group(2).strip().strip("\"'"))
        return out

    def jumps(self) -> list[str]:
        """ProxyJump hops (-J, -o ProxyJump), each [user@]host[:port]."""
        out: list[str] = []
        for v in [v for c, v in self.opts if c == "J" and v] + self.o_values("proxyjump"):
            out += [h.strip() for h in v.split(",") if h.strip() and h.strip().lower() != "none"]
        return out

    @property
    def command_text(self) -> str:
        return " ".join(self.command)


def _getopt_lenient(argv: list[str], i: int, flags: frozenset[str], argopts: frozenset[str],
                    out: list[tuple[str, str | None]]) -> tuple[int, bool]:
    """_getopt that refuses nothing: an unknown letter counts as a flag, a
    missing value ends the options."""
    n = len(argv)
    while i < n:
        a = argv[i]
        if a == "--":
            return i + 1, True
        if not a.startswith("-") or a == "-":
            return i, False
        j = 1
        while j < len(a):
            c = a[j]
            if c in argopts:
                if j + 1 < len(a):
                    val: str | None = a[j + 1:]
                else:
                    i += 1
                    val = argv[i] if i < n else None
                out.append((c, val))
                break
            out.append((c, None))
            j += 1
        i += 1
    return i, False


def parse_lenient(argv: list[str], tool: str = "ssh") -> Lenient:
    """ssh's (or scp's / sftp's) command line as OpenSSH reads it, refusing
    nothing. For ssh: options, the destination, options again unless `--`
    came first, then the remote command. For scp and sftp: `dest` is None;
    their operands are in `command` (classified one by one by the caller)."""
    argv = list(argv)
    lp = Lenient()
    if tool == "ssh":
        i, term = _getopt_lenient(argv, 0, SSH_FLAGS, SSH_ARGOPTS, lp.opts)
        if i < len(argv):
            lp.dest = argv[i]
            i += 1
            if not term and i < len(argv):
                i, _ = _getopt_lenient(argv, i, SSH_FLAGS, SSH_ARGOPTS, lp.opts)
        lp.command = argv[i:]
    else:
        flags, argopts = (SCP_FLAGS, SCP_ARGOPTS) if tool == "scp" else (SFTP_FLAGS, SFTP_ARGOPTS)
        ops: list[str] = []
        i = 0
        while i < len(argv):          # scp and sftp take options among their operands too
            i, term = _getopt_lenient(argv, i, flags, argopts, lp.opts)
            if term:
                ops += argv[i:]
                break
            if i < len(argv):
                ops.append(argv[i])
                i += 1
        lp.command = ops
    port_letter = "p" if tool == "ssh" else "P"
    for c, v in lp.opts:
        if c == "l" and lp.login is None:
            lp.login = v
        elif c == port_letter and v is not None and lp.port is None:
            lp.port = v
    if lp.login is None:
        lp.login = (lp.o_values("user") or [None])[0]
    if lp.port is None:
        lp.port = (lp.o_values("port") or [None])[0]
    return lp


def check_copy(tool: str, argv: list[str]) -> None:
    """Refused options of scp / sftp (their operands are checked by the ssh
    stand-in they run). Raises Refused."""
    if tool == "scp":
        flags, argopts, refused = SCP_FLAGS, SCP_ARGOPTS, SCP_REFUSED
    else:
        flags, argopts, refused = SFTP_FLAGS, SFTP_ARGOPTS, SFTP_REFUSED
    opts: list[tuple[str, str | None]] = []
    _getopt(list(argv), 0, flags, argopts, tool, opts)
    _check(tool, opts, refused)


@dataclass
class Destination:
    user: str | None
    host: str
    port: int | None


def parse_destination(dest: str) -> Destination:
    """`[user@]host` or `ssh://[user@]host[:port]` (IPv6 in brackets in the
    URI form). Raises Refused for something ssh wouldn't take either."""
    d = dest
    if d.lower().startswith("ssh://"):
        rest = d[6:]
        if rest.endswith("/"):
            rest = rest[:-1]
        if "/" in rest:
            raise Refused("gateway: an ssh:// destination can't have a path")
        user = None
        if "@" in rest:
            user, _, rest = rest.rpartition("@")
        port = None
        if rest.startswith("["):
            m = re.fullmatch(r"\[([^\]]+)\](?::([0-9]{1,5}))?", rest)
            if not m:
                raise Refused("gateway: write IPv6 addresses like ssh://user@[::1]:22")
            host, p = m.group(1), m.group(2)
        else:
            host, sep, p = rest.partition(":")
            if sep and not re.fullmatch(r"[0-9]{1,5}", p):
                raise Refused("gateway: that ssh:// destination has a bad port")
        if p:
            port = int(p)
        return Destination(user or None, host.lower(), port)
    user = None
    if "@" in d:
        user, _, d = d.rpartition("@")
    host = d
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return Destination(user or None, host.lower(), None)


def parse_port(v: str | None) -> int | None:
    if v is None:
        return None
    if not re.fullmatch(r"[0-9]{1,5}", v.strip()) or not 0 < int(v) < 65536:
        raise Refused(f"gateway: ssh -p needs a port number")
    return int(v)


# ---------------------------------------------------------------------------
# The remote command
# ---------------------------------------------------------------------------

# sudo and sudoedit (the same setuid binary), also called by a path
# (/usr/bin/sudo): the path part is a word without separators ending in '/'.
SUDO_NAMES = ("sudo", "sudoedit")
_SUDO_WORD = re.compile(r"(?:^|[\s;&|(){}`'\"!])(?:[^\s;&|(){}`'\"!<>]*/)?(?:sudoedit|sudo)"
                        r"(?=$|[\s;&|()`'\"<>])")
_SEP = re.compile(r"&&|\|\||[;&|()\n`{}]|\$\(")
_WRAPPERS = frozenset({"env", "nohup", "time", "nice", "ionice", "stdbuf", "exec", "command",
                       "builtin", "xargs", "timeout", "then", "do", "else", "elif", "!"})
_ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_REDIR_DUP = re.compile(r"([<>])&")
_REDIR = re.compile(r"([0-9]*[<>][<>|-]*)")
_REDIR_OP = re.compile(r"[0-9]*[<>][<>|-]*")


def has_sudo_word(cmd: str) -> bool:
    """A `sudo` or `sudoedit` word anywhere in the remote command, also by its
    path (`/usr/bin/sudo`): remote sudo may be needed."""
    return bool(_SUDO_WORD.search(cmd))


def sudo_in_command_position(cmd: str) -> bool:
    """`sudo` or `sudoedit` (also by its path) as the command of some list or
    pipeline segment (after assignments and wrappers like env/nohup/time/timeout)."""
    return bool(sudo_commands(cmd))


def sudo_commands(cmd: str) -> set[str]:
    """The sudo commands (`sudo`, `sudoedit`: the basename) in command position
    (redirections before or attached to the command are skipped)."""
    found: set[str] = set()
    cmd = _REDIR_DUP.sub(r"\1", cmd)          # 2>&1 -> 2>1, so `&` doesn't split it
    for seg in _SEP.split(cmd):
        seg = _REDIR.sub(r" \1 ", seg)
        try:
            words = shlex.split(seg)              # A='x y' sudo ...: one assignment word
        except ValueError:                        # a quote split by a separator above
            words = seg.replace("'", " ").replace('"', " ").split()
        k = 0
        while k < len(words):
            w = words[k]
            if _REDIR_OP.fullmatch(w):            # a redirection and its target
                k += 2
                continue
            if _ASSIGN.match(w) or w in _WRAPPERS or (w.startswith("-") and k > 0):
                k += 1
                continue
            if words[k - 1:k] == ["timeout"] and re.fullmatch(r"[0-9.]+[smhd]?", w):
                k += 1
                continue
            break
        if k < len(words) and words[k].rsplit("/", 1)[-1] in SUDO_NAMES:
            found.add(words[k].rsplit("/", 1)[-1])
    return found


# ---------------------------------------------------------------------------
# Policy actions of an ssh call (PLAN-v4 phase 7; the stand-in and the
# approval hook decide each with policy.decide)
# ---------------------------------------------------------------------------

# A remote command that is one of the transfer programs' own server commands,
# in plain words (no shell syntax: anything else is a shell line, so exec).
_PLAIN_REMOTE = re.compile(r"[A-Za-z0-9._/~@%+=,:^ '\"-]*")
FORWARD_WHAT = {"agent": "ssh agent forwarding (-A)", "x11": "X11 forwarding (-X/-Y)",
                 "remote": "remote port forwarding (-R)", "stdio": "stdio forwarding (-W)"}
# A path the call may reach without naming it (sftp: any file the login can
# open): decided against every workspace of the host.
ANY_PATH = "\x00any"

# The transfer programs' server commands are recognised only by their exact
# bare name as the first word (`/tmp/x/rsync --server ...` is whatever
# program that is: exec) and only with the options below; anything else is
# exec.
#
# scp's server mode: `scp [-r] [-p] [-d] [-v] -t|-f [--] PATH...` (what
# OpenSSH's scp sends; -t receives one target, -f sends every path named).
_SCP_SERVER_FLAGS = frozenset("tfrpdvq")
# rsync's server: `rsync --server [--sender] OPTIONS . PATH...` (rsync 3.x
# and openrsync). Short flags that only shape the transfer of the named paths
# (never -s: protected args move the options and paths to stdin, out of the
# stand-in's sight), the capability string after `e.` (3.x), `-B<n>`, and
# long options likewise. --remove-source-files (and its old name) deletes the
# sources: a write of each. Everything else is exec, notably --log-file,
# --log-file-format, --temp-dir, --backup-dir, --partial-dir, --*-dest,
# --files-from, --from0, --iconv and whatever -M/--remote-option passes on.
_RSYNC_SERVER_FLAGS = frozenset("vqhlLkKHAXpEogDtUNOJrdRCxzcuWSnImyb")
_RSYNC_SERVER_LONG = frozenset({
    "numeric-ids", "ignore-errors", "copy-unsafe-links", "safe-links", "munge-links",
    "no-implied-dirs", "relative", "dirs", "existing", "ignore-existing", "ignore-non-existing",
    "ignore-missing-args", "delete-missing-args", "size-only", "ignore-times", "inplace",
    "append", "append-verify", "mkpath", "delay-updates", "fsync", "preallocate", "partial",
    "delete", "delete-before", "delete-during", "delete-delay", "delete-after",
    "delete-excluded", "force", "backup", "fuzzy", "list-only", "sparse", "whole-file",
    "checksum", "update", "links", "copy-links", "hard-links", "perms", "times", "recursive",
    "group", "owner", "devices", "specials", "verbose", "compress", "one-file-system",
    "dry-run", "prune-empty-dirs", "omit-dir-times", "omit-link-times"})
_RSYNC_SERVER_VALUE = {
    **{k: re.compile(r"[0-9.]{1,20}[A-Za-z]{0,3}") for k in (
        "timeout", "bwlimit", "max-size", "min-size", "block-size", "compress-level",
        "modify-window", "max-delete", "checksum-seed")},
    "checksum-choice": re.compile(r"[A-Za-z0-9,+-]{1,40}"),
    "compress-choice": re.compile(r"[A-Za-z0-9,+-]{1,40}"),
    "log-format": re.compile(r"[A-Za-z0-9%]{1,20}"),        # the itemize format (no file)
    "suffix": re.compile(r"[A-Za-z0-9._~+-]{1,20}"),         # beside the file: no '/'
}
_RSYNC_CLUSTER = re.compile(r"-([A-Za-z]*?)(?:e\.[A-Za-z]*)?")
_RSYNC_REMOVE = frozenset({"--remove-source-files", "--remove-sent-files"})


def _scp_server(words: list[str]) -> list[tuple[str, str]] | None:
    """`scp -t|-f [flags] [--] PATH...` as (write|read, path) per path; None
    for anything else."""
    mode, i, n = "", 1, len(words)
    while i < n:
        w = words[i]
        if w == "--":
            i += 1
            break
        if not w.startswith("-") or w == "-":
            break
        for c in w[1:]:
            if c not in _SCP_SERVER_FLAGS:
                return None
            if c in "tf":
                if mode and mode != c:
                    return None
                mode = c
        i += 1
    paths = words[i:]
    if not mode or not paths or any(p.startswith("-") for p in paths):
        return None
    return [("write" if mode == "t" else "read", p or ".") for p in paths]


def _rsync_server(words: list[str]) -> list[tuple[str, str]] | None:
    """`rsync --server [--sender] OPTIONS . PATH...`: a sender reads every
    path (and with --remove-source-files writes them too), a receiver writes
    them; None for anything else (exec)."""
    if len(words) < 2 or words[1] != "--server":
        return None
    sender = remove = False
    i, n = 2, len(words)
    while i < n and words[i] != ".":
        w = words[i]
        if w == "--sender":
            sender = True
        elif w in _RSYNC_REMOVE:
            remove = True
        elif w.startswith("--"):
            name, eq, val = w[2:].partition("=")
            if name in _RSYNC_SERVER_VALUE:
                if not eq:
                    i += 1
                    val = words[i] if i < n else ""
                if not _RSYNC_SERVER_VALUE[name].fullmatch(val):
                    return None
            elif eq or name not in _RSYNC_SERVER_LONG:
                return None
        elif re.fullmatch(r"-B[0-9]{1,12}", w):
            pass
        else:
            m = _RSYNC_CLUSTER.fullmatch(w)
            if not m or w == "-" or any(c not in _RSYNC_SERVER_FLAGS for c in m.group(1)):
                return None
        i += 1
    paths = words[i + 1:]
    # rsync's option parser (popt) reads options after the "." too
    # (`. --remove-source-files /x` removes /x): a path like an option is exec
    if i >= n or not paths or any(p.startswith("-") for p in paths):
        return None
    if not sender:
        return [("write", p or ".") for p in paths]
    out = [("read", p or ".") for p in paths]
    if remove:
        out += [("write", p or ".") for p in paths]
    return out


def ssh_actions(a: SshArgs, subsystem: Any = None) -> list[tuple[str, str]]:
    """(policy action, remote path or "") for what this ssh call does:
    `scp -t`/`rsync --server` and git-receive-pack write, `scp -f`/`rsync
    --server --sender` and git-upload-pack read (each path named, every one
    of them), sftp (-s) reads and writes anywhere (ANY_PATH), any other
    command execs (also a transfer program named by a path, or with an
    option outside the lists above); -L/-D/-N are network; each forwarding
    kind its own grant. `subsystem()`: what an sftp-subsystem call does,
    when the caller can tell (the stand-in reads scp's own operands), else
    both, on any path."""
    out: list[tuple[str, str]] = []
    text = a.command_text
    if a.has("s"):
        # the sftp subsystem: scp (its default protocol) tells its direction by
        # its own operands, read from the parent process when it is the
        # gateway's scp; anything else (sftp) may read and write any file
        out += ((subsystem() if subsystem is not None else None)
                or [("read", ANY_PATH), ("write", ANY_PATH)])
    elif text:
        words: list[str] = []
        if _PLAIN_REMOTE.fullmatch(text):
            try:
                words = shlex.split(text)
            except ValueError:
                words = []
        prog = words[0] if words else ""
        acts = None
        if prog == "scp":
            acts = _scp_server(words)
        elif prog == "rsync":
            acts = _rsync_server(words)
        elif prog in ("git-upload-pack", "git-upload-archive") and len(words) == 2 and \
                not words[1].startswith("-"):
            acts = [("read", words[1] or ".")]
        elif prog == "git-receive-pack" and len(words) == 2 and not words[1].startswith("-"):
            acts = [("write", words[1] or ".")]
        out += acts if acts else [("exec", "")]
    if any(c in ("L", "D") for c, _ in a.opts) or a.has("N") or \
            any(o.key in ("localforward", "dynamicforward") for o in a.oopts):
        out.append(("network", ""))
    for k in a.forwards:
        out.append((f"forward_{k}", ""))
    return out


# ---------------------------------------------------------------------------
# Which workspaces a remote path may reach. The stand-ins don't know a host's
# home folder, so a path is placed by how it is written: from / against roots
# written from /, from the home (`~/x`, `x`) against roots written from ~.
# Where that can't settle it, the path counts as possibly in the workspace and
# the stricter decision applies (a workspace only narrows): a root written the
# other way, a path naming another user's home (`~bob/x`) or leaving the home
# with `..`, a folder above a root (a transfer of it reaches the workspace),
# and ANY_PATH.
# ---------------------------------------------------------------------------


def _norm_abs(p: str) -> str:
    q = posixpath.normpath(p)
    return "/" + q.lstrip("/")                  # normpath keeps a leading `//`


def _inside(p: str, root: str) -> bool:
    r = root.rstrip("/") or "/"
    return p == r or r == "/" or p.startswith(r + "/")


def workspaces_for(eh: Any, path: str) -> list[tuple[str | None, str]]:
    """The workspaces of a host `path` may reach, each with how it was found:
    "in" (the most specific root that holds it, as written), "above" (a root
    below the path), "unplaced" (the path is written the other way than the
    root, or can't be placed at all). The first entry is the workspace that
    holds it ("in"), or (None, "in") when none does."""
    wss = dict(getattr(eh, "workspaces", None) or {})
    if path == ANY_PATH:
        return [(None, "in")] + [(wn, "any") for wn in wss]
    p = (path or ".").strip("'\"") or "."
    if p.startswith("~") and p != "~" and not p.startswith("~/"):
        return [(None, "in")] + [(wn, "unplaced") for wn in wss]      # ~bob/x
    home_rel = p == "~" or p.startswith("~/") or not p.startswith("/")
    if home_rel:
        rel = p[2:] if p.startswith("~/") else ("" if p == "~" else p)
        q = posixpath.normpath(rel) if rel else "."
        if q == ".." or q.startswith("../"):
            return [(None, "in")] + [(wn, "unplaced") for wn in wss]  # leaves the home
        q = "/" + ("" if q == "." else q)       # placed within an imaginary home "/"
    else:
        q = _norm_abs(p)
    best, blen = None, -1
    rest: list[tuple[str, str]] = []
    for wn, ew in wss.items():
        root = ew.root
        r_home = root == "~" or root.startswith("~/")
        if r_home != home_rel:
            rest.append((wn, "unplaced"))
            continue
        r = _norm_abs(root[1:] if r_home else root) if root != "~" else "/"
        if _inside(q, r):
            if len(r) > blen:
                if best is not None:
                    rest.append((best, "in-outer"))
                best, blen = wn, len(r)
            else:
                rest.append((wn, "in-outer"))
        elif _inside(r, q):
            rest.append((wn, "above"))
    # an outer root that also holds the path is shadowed by the inner one
    # (the most specific workspace binds, as gated's terminals do)
    return [(best, "in")] + [(wn, how) for wn, how in rest if how != "in-outer"]


def _shown(p: str) -> str:
    s = "".join(c if c.isprintable() else "?" for c in p)
    return s if len(s) <= 80 else s[:77] + "..."


def decide_path(eff: Any, action: str, host: str, path: str | None,
                mode: str | None = None) -> Any:
    """policy.decide for one action of an ssh call on `host` (a form host's
    name) in `mode` (None: the modeless rule): with a path, in the workspace
    that holds it and in every workspace it may reach (workspaces_for); the
    strictest decision applies (by its per-mode word), and a refusal from a
    workspace that only may be reached says why."""
    from . import policy
    if not path:
        return policy.decide(eff, action, host=host, mode=mode)
    eh = eff.hosts.get(host)
    best, best_how = None, "in"
    for ws, how in workspaces_for(eh, path):
        d = policy.decide(eff, action, host=host, workspace=ws, mode=mode)
        if best is None or policy.RANK[d.value] < policy.RANK[best.value]:
            best, best_how = d, how
    if best.word is not True and best.workspace and best_how != "in":
        ew = eh.workspaces.get(best.workspace) if eh is not None else None
        root = ew.root if ew is not None else "?"
        ws = f"workspace {best.workspace} ({root})"
        if best_how == "any":
            best.note = f"sftp can open any file on {host}, {ws} too; use scp or rsync with paths"
        elif best_how == "above":
            best.note = f"{_shown(path)} holds {ws}"
        elif root == "~" or root.startswith("~/"):
            best.note = (f"{_shown(path)} may reach {ws}: the gateway compares paths as they "
                         f"are written and doesn't know {host}'s home folder; write the path "
                         "from ~/ like that root, or write the root from / in gateway.toml")
        else:
            best.note = (f"{_shown(path)} may reach {ws}: the gateway compares paths as they "
                         f"are written and doesn't know {host}'s home folder; write the path "
                         "from / like that root")
    return best
