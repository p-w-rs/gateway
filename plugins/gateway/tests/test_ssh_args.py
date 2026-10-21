"""ssh family command lines (group 'ssh'): parsing like OpenSSH, refused
options, the -o allowlist, destinations, and the remote sudo word."""
from __future__ import annotations

import harness  # noqa: F401  (path guard)
from gateway import ssh_args as A


def _refused(argv: list[str], tool: str = "ssh") -> str:
    try:
        if tool == "ssh":
            A.parse_ssh(argv)
        else:
            A.check_copy(tool, argv)
    except A.Refused as e:
        assert e.message.startswith("gateway: "), e.message
        return e.message
    raise AssertionError(f"not refused: {argv}")


def test_ssh_args_parse_like_openssh() -> None:
    a = A.parse_ssh(["-v", "-o", "SendEnv=GIT_PROTOCOL", "git@github.com", "git-upload-pack",
                     "'o/r.git'"])
    assert a.dest == "git@github.com"
    assert a.command == ["git-upload-pack", "'o/r.git'"]
    assert a.kept_options() == ["-v", "-o", "SendEnv=GIT_PROTOCOL"]
    # options after the destination are options (ssh re-parses), until the command
    a = A.parse_ssh(["box", "-l", "bob", "-p", "2222", "-T", "ls", "-la"])
    assert (a.dest, a.login, a.port, a.command) == ("box", "bob", "2222", ["ls", "-la"])
    assert a.kept_options() == ["-T"]           # -l/-p are dropped (the config has them)
    # "--" before the destination: everything after it is the command
    a = A.parse_ssh(["-q", "--", "box", "-v", "x"])
    assert a.dest == "box" and a.command == ["-v", "x"] and a.terminated
    # "--" after the destination ends the options
    a = A.parse_ssh(["box", "--", "-v"])
    assert a.command == ["-v"]
    # attached arguments and grouped flags
    a = A.parse_ssh(["-qTp2200", "-luser", "box", "true"])
    assert a.port == "2200" and a.login == "user" and a.kept_options() == ["-q", "-T"]
    # -o User / -o Port count like -l / -p, and the first value wins
    a = A.parse_ssh(["-o", "User=alice", "-oPort 2201", "box", "x"])
    assert (a.login, a.port) == ("alice", "2201") and a.kept_options() == []
    a = A.parse_ssh(["-l", "bob", "-o", "User=alice", "box", "x"])
    assert a.login == "bob"
    assert A.parse_ssh(["box"]).command == [] and A.parse_ssh([]).dest is None


def test_ssh_args_what_scp_and_sftp_pass() -> None:
    # exactly what OpenSSH 10's scp and sftp pass to their -S program
    a = A.parse_ssh(["-x", "-oPermitLocalCommand=no", "-oClearAllForwardings=yes",
                     "-oRemoteCommand=none", "-oRequestTTY=no", "-oControlMaster=no",
                     "-oForwardAgent=no", "-p", "2222", "-l", "u", "-s", "--", "gwtx", "sftp"])
    assert (a.dest, a.login, a.port, a.command) == ("gwtx", "u", "2222", ["sftp"])
    a = A.parse_ssh(["-oForwardX11 no", "-oPermitLocalCommand no", "-oClearAllForwardings yes",
                     "-oControlMaster no", "-oForwardAgent no", "-oPort 2200", "-l", "u", "-s",
                     "--", "gwtx", "sftp"])
    assert a.port == "2200" and "-oPort 2200" not in a.kept_options()
    a = A.parse_ssh(["-x", "-oPermitLocalCommand=no", "--", "gwtx", "scp", "-t", "/x/y"])
    assert a.command == ["scp", "-t", "/x/y"]


def test_ssh_args_refused_options() -> None:
    for opt, argv in {
        "-F": ["-F", "/tmp/cfg", "box", "x"], "-i": ["-i", "k", "box", "x"],
        "-S": ["-S", "/tmp/s", "box", "x"], "-A": ["-A", "box", "x"],
        "-J": ["-J", "jump", "box", "x"], "-W": ["-W", "h:22", "box"],
        "-R": ["box", "-R", "2222:localhost:22", "x"], "-w": ["-w", "0", "box", "x"],
        "-O": ["-O", "forward", "box"], "-M": ["-M", "box", "x"], "-X": ["-X", "box", "x"],
        "-Y": ["-Y", "box", "x"], "-K": ["-K", "box", "x"], "-g": ["-g", "box", "x"],
        "-G": ["-G", "box"], "-I": ["-I", "lib", "box", "x"], "-Z": ["-Z", "box"],
    }.items():
        msg = _refused(argv)
        assert f"ssh {opt} isn't allowed" in msg, (opt, msg)
    assert "use via" in _refused(["-J", "j", "box", "x"])
    # grouped and attached spellings are refused too
    assert "-A" in _refused(["-qA", "box", "x"])
    assert "-F" in _refused(["-F/tmp/cfg", "box", "x"])


def test_ssh_args_o_allowlist() -> None:
    for kv in ("ProxyCommand=sh -c x", "ProxyJump=j", "LocalCommand=id", "PermitLocalCommand=yes",
               "KnownHostsCommand=x", "IdentityAgent=/tmp/a", "IdentityFile=/k",
               "ForwardAgent=yes", "RemoteForward=1 a:2", "Include=/etc/x", "Match=all",
               "HostName=evil.example", "HostKeyAlias=other", "UserKnownHostsFile=/dev/null",
               "StrictHostKeyChecking=no", "StrictHostKeyChecking=accept-new",
               "GlobalKnownHostsFile=/tmp/k", "ControlPath=/tmp/c", "ControlMaster=yes",
               "ControlPersist=yes", "NoHostAuthenticationForLocalhost=yes",
               "CanonicalizeHostname=yes", "PKCS11Provider=/x", "SecurityKeyProvider=/x",
               "CertificateFile=/x", "AddKeysToAgent=yes", "ForwardX11=yes", "GatewayPorts=yes",
               "RemoteCommand=id", "PermitRemoteOpen=any", "Tunnel=yes", "ProxyUseFdpass=yes",
               "PasswordAuthentication=yes", "BatchMode=no", "UpdateHostKeys=yes",
               "VerifyHostKeyDNS=yes", "GSSAPIDelegateCredentials=yes"):
        msg = _refused(["-o", kv, "box", "x"])
        assert "isn't allowed" in msg, (kv, msg)
    assert "needs Key=Value" in _refused(["-o", "ProxyCommand", "box", "x"])
    for kv in ("SendEnv=GIT_PROTOCOL", "ConnectTimeout=5", "ServerAliveInterval 10",
               "BatchMode=yes", "ForwardAgent=no", "LogLevel=ERROR", "SetEnv=FOO=1",
               "Compression=yes", "ForwardX11 no", "RequestTTY=no", 'StrictHostKeyChecking="yes"'):
        A.parse_ssh(["-o", kv, "box", "x"])


def test_ssh_args_scp_sftp_refused() -> None:
    for argv in (["-S", "/bin/sh", "a", "b:"], ["-F", "c", "a", "b:"], ["-i", "k", "a", "b:"],
                 ["-J", "j", "a", "b:"], ["-o", "ProxyCommand=x", "a", "b:"], ["-A", "a", "b:"],
                 ["-D", "/x", "a", "b:"], ["-t", "/x"], ["-f", "/x"], ["-T", "a", "b:"]):
        assert "isn't allowed" in _refused(argv, "scp"), argv
    for argv in (["-S", "/bin/sh", "h"], ["-F", "c", "h"], ["-i", "k", "h"], ["-J", "j", "h"],
                 ["-D", "/usr/libexec/sftp-server", "h"], ["-oProxyCommand=x", "h"]):
        assert "isn't allowed" in _refused(argv, "sftp"), argv
    A.check_copy("scp", ["-r", "-P", "2222", "-o", "ConnectTimeout=5", "dir", "box:/tmp/"])
    A.check_copy("sftp", ["-b", "-", "-P", "2222", "box"])


def test_ssh_args_destinations() -> None:
    d = A.parse_destination("joshua@10.0.0.5")
    assert (d.user, d.host, d.port) == ("joshua", "10.0.0.5", None)
    d = A.parse_destination("ssh://u@Lab.Example.com:2222/")
    assert (d.user, d.host, d.port) == ("u", "lab.example.com", 2222)
    d = A.parse_destination("ssh://u@[::1]:2200")
    assert (d.host, d.port) == ("::1", 2200)
    assert A.parse_destination("a@b@box").user == "a@b"     # ssh splits at the last @
    assert A.parse_destination("box").user is None
    for bad in ("ssh://h/path", "ssh://h:xx"):
        try:
            A.parse_destination(bad)
        except A.Refused:
            continue
        raise AssertionError(bad)
    assert A.parse_port("22") == 22 and A.parse_port(None) is None
    try:
        A.parse_port("99999")
    except A.Refused:
        pass
    else:
        raise AssertionError("bad port accepted")


def test_ssh_args_sudo_word() -> None:
    yes = ["sudo ls", "cd /x && sudo make install", "echo x | sudo tee /f", "env A=1 sudo -u x id",
           "timeout 5 sudo x", "A=1 sudo x", "(sudo x)", "true; sudo x", "nohup sudo x"]
    for c in yes:
        assert A.has_sudo_word(c) and A.sudo_in_command_position(c), c
    word_only = ["grep sudo /var/log/auth.log", 'bash -c "sudo x"', "man sudo"]
    for c in word_only:
        assert A.has_sudo_word(c) and not A.sudo_in_command_position(c), c
    for c in ("pseudo x", "sudoers", "ls /etc/sudoers.d", "echo visudo"):
        assert not A.has_sudo_word(c) and not A.sudo_in_command_position(c), c


def test_ssh_args_sudo_by_path_sudoedit_and_redirections() -> None:
    """A path-qualified sudo and sudoedit count like sudo (scripts = true
    stages the askpass for them; sudo = false refuses them); redirections
    before the command don't hide it."""
    both = {"/usr/bin/sudo id": {"sudo"}, "cd /x && /usr/bin/sudo make": {"sudo"},
            "./sudo x": {"sudo"}, "sudoedit /etc/hosts": {"sudoedit"},
            "SUDO_EDITOR='sed -i s/a/b/' sudoedit /f": {"sudoedit"},
            "/usr/bin/sudoedit /f": {"sudoedit"}, "sudo a; sudoedit b": {"sudo", "sudoedit"},
            "</dev/null sudo id": {"sudo"}, "sudo</dev/null id": {"sudo"},
            "2>&1 sudo id": {"sudo"}, "cmd 2>&1 | sudo tee f": {"sudo"},
            ">log sudo id": {"sudo"}, "sudo -u x id 2>/dev/null": {"sudo"}}
    for c, names in both.items():
        assert A.has_sudo_word(c) and A.sudo_in_command_position(c), c
        assert A.sudo_commands(c) == names, (c, A.sudo_commands(c))
    for c in ("ls /usr/bin/sudo", "echo x > sudo", "man sudoedit"):
        assert A.has_sudo_word(c) and not A.sudo_in_command_position(c), c
    for c in ("/usr/bin/sudoers", "pseudoedit x", "cat <sudo", "ls /etc/sudo.conf"):
        assert not A.has_sudo_word(c) and not A.sudo_in_command_position(c), c
