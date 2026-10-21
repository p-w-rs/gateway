"""SPEC 8 step 5: the sudo destructive list withholds `allow` (auto mode) from a
few catastrophic root commands, so they reach the classifier / a human even
with localhost sudo true. A plugin `allow` skips the classifier, so the list
must hold against the natural ways of writing those commands: wrappers
(`sudo timeout 5 rm -rf /`), command strings (`sudo sh -c '…'`), commands from
stdin (`… | sudo bash`, `sudo xargs`), assignments, other spellings of the
flags and targets. Regressions for the 2026-10 verification (HIGH finding)."""
from __future__ import annotations

import os

import harness as H
from gateway import consent, hooks_bash, vault

FORM = """
[hosts.localhost]
sudo = true
"""


def _decide(command, mode="auto", cwd=None):
    payload = {"tool_name": "Bash", "tool_input": {"command": command}, "permission_mode": mode}
    if cwd:
        payload["cwd"] = str(cwd)
    out = hooks_bash.main(payload)
    return None if out is None else out["hookSpecificOutput"]["permissionDecision"]


def _setup(env):
    env.write_form(FORM)
    vault.save(vault.empty())
    consent.approve_all(env.form())


def _check(rows, cwd=None):
    bad = []
    for cmd, want in rows:
        for mode in ("auto", "default"):
            exp = want if (mode == "auto" or want != "allow") else None
            got = _decide(cmd, mode, cwd=cwd)
            if got != exp:
                bad.append(f"{mode:7} {cmd!r}: got {got} want {exp}")
    assert not bad, "\n".join(bad)


def test_wrappers_cannot_hide_a_destructive_command():
    with H.gateway_env() as env:
        _setup(env)
        _check([
            ("sudo env rm -rf /", None),
            ("sudo env -i rm -rf /", None),
            ("sudo timeout 5 rm -rf /", None),
            ("sudo timeout -s KILL 300 rm -rf /", None),
            ("sudo nice rm -rf /", None),
            ("sudo nice -n 10 rm -rf /", None),
            ("sudo nohup rm -rf /", None),
            ("sudo time rm -rf /", None),
            ("sudo stdbuf -oL rm -rf /", None),
            ("sudo ionice -c3 rm -rf /", None),
            ("sudo chrt 1 rm -rf /", None),           # a wrapper nobody listed
            ("sudo caffeinate rm -rf /", None),
            ("sudo env /bin/rm -rf /", None),
            ("sudo nice /usr/local/opt/coreutils/libexec/gnubin/rm -rf /", None),
            ("sudo timeout 5 dd if=/dev/zero of=/dev/sda", None),
            ("sudo nice mkfs.ext4 /dev/sdb", None),
            ("sudo env chmod -R 777 /", None),
            ("sudo systemctl reboot", None),
            ("sudo systemctl poweroff", None),
            ("sudo script -q /dev/null rm -rf /", None),
            ("sudo -u root -- env rm -rf /", None),
            # The same wrappers around harmless commands are still allowed.
            ("sudo nice -n 10 make install", "allow"),
            ("sudo timeout 60 apt update", "allow"),
            ("sudo env make install", "allow"),
            ("sudo nohup systemctl restart nginx", "allow"),
            ("sudo systemctl restart nginx", "allow"),
            ("sudo cat /etc/passwd", "allow"),        # a data path, not the passwd program
        ])


def test_hidden_command_runners_are_never_vouched_for():
    with H.gateway_env() as env:
        _setup(env)
        _check([
            ("sudo sh -c 'rm -rf /'", None),
            ("sudo bash -c 'rm -rf /'", None),
            ("sudo bash -c 'cd / && rm -rf usr'", None),
            ("sudo zsh -c 'echo hi > /etc/motd'", None),
            ("sudo timeout 5 sh -c 'rm -rf /'", None),
            ("sudo bash", None),                      # reads commands from a pipe
            ("echo 'rm -rf /' | sudo bash", None),
            ("cat steps.txt | sudo sh", None),
            ("sudo /bin/sh -s", None),
            ("echo / | sudo xargs rm -rf", None),
            ("sudo xargs rm -rf", None),
            ("sudo parallel rm -rf ::: /", None),
            ("echo 'rm -rf /' | sudo at now", None),
            ("sudo su", None),
            ("sudo su -c 'rm -rf /'", None),
            ("sudo runuser -u root -- rm x", None),
            ("sudo -u root sudo -s", None),
            ("sudo doas -s", None),
            ("sudo find / -delete", None),
            ("sudo find / -exec rm -rf {} +", None),
            ("sudo find /srv -name x -execdir rm '{}' +", None),
            ("sudo find /srv -exec rm -rf '{}' +", None),
            ("sudo nice find /srv -ok rm '{}' +", None),
            ("sudo env -S 'rm -rf /'", None),
            ("sudo env -iS 'rm -rf /'", None),
            ("sudo env --split-string='rm -rf /'", None),
            # find without a command-running action is an ordinary command.
            ("sudo find /var/log -name '*.gz'", "allow"),
        ])


def test_command_strings_are_checked():
    # A string that some program runs as a command (watch, script -c, flock -c,
    # a wrapper nobody listed) is split and checked against the list too.
    with H.gateway_env() as env:
        _setup(env)
        _check([
            ("sudo watch 'rm -rf /'", None),
            ("sudo script -c 'rm -rf /' /dev/null", None),
            ("sudo flock /tmp/l -c 'rm -rf /'", None),
            ("sudo chrt 1 something 'rm -rf / '", None),
            ("sudo something 'reboot now'", None),
            ("sudo something 'dd if=/dev/zero of=/dev/sda'", None),
            ("sudo something 'x; rm -rf /'", None),
            ("sudo something \"it's open\"", None),   # doesn't split: not vouched for
            ("sudo something 'harmless words here'", "allow"),
        ])


def test_assignments_under_sudo_are_not_vouched_for():
    with H.gateway_env() as env:
        _setup(env)
        _check([
            ("sudo FOO=b rm -rf /", None),
            ("sudo FOO=b make install", None),
            ("sudo PATH=/tmp/evil:/usr/bin make install", None),
            ("sudo -u root LD_PRELOAD=/tmp/x.so ls", None),
            ("sudo env FOO=b make install", None),
            ("sudo env -u X PATH=/tmp/evil make", None),
            ("sudo env -i - FOO=1 make", None),
            ("sudo env --unset=X make", None),        # long options aren't modelled
            # dd's operands look like assignments but aren't in that position.
            ("sudo dd if=/dev/zero of=/tmp/img bs=1m count=1", "allow"),
        ])


def test_spellings_of_recursive_and_targets():
    with H.gateway_env() as env:
        _setup(env)
        _check([
            ("sudo rm -Rf /", None),
            ("sudo rm -fR /usr", None),
            ("sudo rm --recursive --force /", None),
            ("sudo rm --rec -f /", None),
            ("sudo rm --r -f /etc", None),
            ("sudo rm -rf //", None),
            ("sudo rm -rf ///usr", None),
            ("sudo rm -rf /usr/", None),
            ("sudo rm -rf /usr/local/..", None),
            ("sudo rm -rf /Users", None),
            ("sudo rm -rf /Applications", None),
            ("sudo rm -rf /private/etc", None),
            ("sudo rm -rf /private/var/", None),
            ("sudo rm -rf /srv", None),
            ("sudo rm -rf ~/", None),
            ("sudo rm -rf ~root", None),
            ("sudo grm -rf /", None),
            ("sudo /bin/rm -rf /", None),
            ("sudo chown -R me /", None),
            ("sudo chmod -R 777 /etc", None),
            ("sudo chgrp -R staff /usr", None),
            ("sudo diskutil eraseDisk APFS X disk2", None),
            ("sudo newfs_apfs /dev/disk2", None),
            ("sudo shred /dev/sda", None),
            ("sudo dd if=/dev/zero of=//dev/sda", None),
            ("sudo dd if=/dev/zero of=/dev/../dev/disk2", None),
            ("sudo init 0", None),
            ("sudo telinit 6", None),
            ("sudo kill 1", None),
            ("sudo kill -9 1", None),
            ("sudo kill -s KILL 1", None),
            ("sudo kill -9 -1", None),
            ("sudo kill -- -1", None),
            ("sudo killall -9 launchd", None),
            ("sudo pkill systemd", None),
            ("sudo kill -1 1234", "allow"),           # -1 here is the signal (HUP)
            ("sudo kill -9 4321", "allow"),
            ("sudo tee /etc//sudoers", None),
            ("sudo cp x /etc/./sudoers.d/y", None),
            ("sudo cp x /private/etc/sudoers", None),
            ("sudo dd if=x of=/etc/sudoers", None),
            ("sudo dd if=/dev/zero of=/dev/null count=1", "allow"),
            # Below the top level is not on the list (SPEC 8: a small list).
            ("sudo rm -rf /tmp/build", "allow"),
            ("sudo rm -rf /usr/local/share/foo", "allow"),
            ("sudo chown -R me /srv/app", "allow"),
            ("sudo chmod -r x.txt", "allow"),         # -r: remove read, not recursive
            ("sudo rm -r build", "allow"),
        ])
        # realpath() already folds `//`; the spelling check holds on its own too
        # (normpath keeps a leading `//`, and realpath can fail).
        for p in ("//", "//usr", "///", "//private/etc"):
            assert hooks_bash._top_or_home(p, set()), p
        assert not hooks_bash._top_or_home("//usr/local", set())


def test_relative_targets_use_the_working_directory():
    with H.gateway_env() as env:
        _setup(env)
        home = env.user_home
        proj = home / "proj"
        proj.mkdir(parents=True)
        _check([
            ("cd / && sudo rm -rf usr", None),
            ("cd /usr && sudo rm -rf ..", None),
            ("cd ~ && sudo rm -rf .", None),
            ("cd / && sudo chmod -R 777 etc", None),
            ("sudo rm -rf ..", None),                 # proj/.. is the home
            ("sudo rm -rf build", "allow"),
            ("cd /tmp && sudo rm -rf build", "allow"),
        ], cwd=proj)
        _check([("sudo rm -rf .", None), ("sudo rm -rf usr", None)], cwd="/")
        _check([("sudo dd if=/dev/zero of=sda", None)], cwd="/dev")
        _check([("sudo tee sudoers", None), ("sudo cp x sudoers.d/y", None)], cwd="/etc")


def test_home_directories_by_absolute_path_and_symlink():
    with H.gateway_env() as env:
        _setup(env)
        home = env.user_home
        link = env.root / "homelink"
        os.symlink(home, link)
        _check([
            (f"sudo rm -rf {home}", None),
            (f"sudo rm -rf {home}/", None),
            (f"sudo rm -rf {link}/", None),           # resolves to the home
            (f"sudo chown -R me {home}", None),
            (f"sudo rm -rf {home}/proj/build", "allow"),
        ])


def test_tilde_user_is_a_home_even_when_unresolvable():
    # `~user` names some user's home whether or not it resolves here.
    with H.gateway_env() as env:
        _setup(env)
        orig = hooks_bash._home_dirs
        hooks_bash._home_dirs = lambda: []
        try:
            assert hooks_bash._danger_target("~nosuchuser", ["/x"])
            assert hooks_bash._danger_target("~nosuchuser/", ["/x"])
            assert not hooks_bash._danger_target("~nosuchuser/src", ["/x"])
        finally:
            hooks_bash._home_dirs = orig


def test_sudoers_and_user_database_editors_are_never_vouched_for():
    """`visudo` edits /etc/sudoers with no path argument, `vipw` /etc/passwd
    (-s: /etc/shadow), `vigr` /etc/group: none of their words names a sudoers
    path, yet SPEC 8 keeps editing sudoers off the allow list (review round 4).
    By name, by path, behind a wrapper; a benign sudo command is still allowed."""
    with H.gateway_env() as env:
        _setup(env)
        _check([
            ("sudo visudo", None),
            ("sudo visudo -s", None),
            ("sudo /usr/sbin/visudo", None),
            ("sudo nice visudo", None),
            ("sudo -u root visudo", None),
            ("sudo vipw", None),
            ("sudo vipw -s", None),
            ("sudo vigr", None),
            ("sudo timeout 60 vigr -s", None),
            ("sudo apt install visudo-docs", "allow"),   # only the program counts
            ("sudo systemctl restart nginx", "allow"),
        ])
