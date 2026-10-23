# ssh family (group "ssh"): `ssh.py`, `ssh_args.py`, `ssh_conf.py`, `ssh_sudo.py`

SPEC 9.2 (ssh, scp, sftp, rsync, git over ssh), 9.3 (remote sudo, hardened:
see "Remote sudo") and the ssh side of `gate check` (SPEC 15). Stdlib only.
Binaries come from `paths.tool()` (the pixi OpenSSH: ssh, scp, sftp,
ssh-agent, ssh-add, ssh-keygen, ssh-keyscan), never from PATH, except
`others = "mine"`, which execs the system ssh (`/usr/bin/ssh`) unchanged.

## Public API (`gateway.ssh`)

| function | does |
|---|---|
| `main(tool, argv) -> int` | the stand-in for `ssh`, `scp`, `sftp` (run.py `shim`). Exit codes: ssh's own; 2 = refused by the gateway; 75 = a pop-up is still open / no screen; 1 = a pop-up was cancelled, a sudo password was rejected, or an unexpected error (one `gateway:` line naming the exception type, never a traceback). A run folder it can't use (`paths.PathError`) says what is wrong and the remedy: `gateway: TOOL can't run: <paths.explain(e)>. Tell the user.` (review round 2). |
| `resolve(argv, form=None) -> dict` | where an ssh command line goes, without connecting: `{kind, name, user, addr, port, by, suggest, error}`; kind is `host` (name = form host, by = `name`/`address`), `endpoint` (an account ssh endpoint; name = the host), `unknown` (suggest = a close form name), `local`, `disabled`, `error` or `refused` (a refused option; error = the reason). Every string is safe to render (`form.safe`): a typed host or user that isn't comes back as `None` (and an endpoint's `addr` then too). Cross-checked with `ssh -G` against a fresh private config per call. For hooks and `gate`. |
| `keyscan_host(name) -> [str]` | the host keys (`"type base64"`) at the chosen address (probe, no pins needed: gate check runs it before consent); behind `via`, read through the jump chain (ssh with an empty accept-new known_hosts per key type, no authentication offered). Raises `SshError`. |
| `install_key(name, method, password=None) -> str` | `show`: returns the public key line (generates and stores the host's key if it has none). `my-login`: the system ssh with the user's own agent and config, once, appending the key to `~/.ssh/authorized_keys` idempotently; the host key is still checked against the gateway's pins (`HostKeyAlias` + pinned known_hosts + `StrictHostKeyChecking yes`); behind `via` the jump goes through the gateway's own config. `password`: `SSH_ASKPASS` + `SSH_ASKPASS_REQUIRE=force`, the askpass reads a one-shot FIFO (unlinked right after the first write); the password comes from the caller or, if `None`, from `popup.secret("login password")` (its dialog names the host's ssh right for gated's recheck: `host_check(name, "ssh")`; a request that joined another call's pop-up gets "typed into another call's pop-up and isn't kept; run gate check NAME again"); never stored, never in argv or env. Both then run `test_login`. Returns a status line; raises `SshError`. |
| `test_login(name) -> (ok, message)` | a fresh login with the gateway's key (no shared master); on success records `hosts[NAME].installed`. Audited (`use`, tool `gate`). |
| `verify_remote_sudo(name, user, password) -> (ok, message)` | refuses passwords shorter than 8 characters (they can't be scrubbed), checks the login shell is POSIX (`x=ok; printf '%s\n' "$x"`), stages the password, runs `sudo -k -A -v` with the askpass (one attempt), cleans up. Opens its own connection (it is the verify callback of the sudo pop-up, which runs in popup's detached helper). Audited (`use`, tool `gate`, `remote_sudo`; the password is in the line's redaction set). |
| `probe_remote_nopasswd(name, user) -> bool` | `sudo -n true` over the master, cached 10 min per (host, user) in the run dir (`rsudo-NAME@USER`); also keeps `hosts[NAME].probe.nopasswd[USER]` in the vault (written only when it changes). Audited when it connects (not on a cache hit). |
| `run(name, command, input=None, timeout=120) -> (rc, stdout, stderr)` | the gate process's own runner (requested by ux for `gate copy-to`): one remote command on a form host with the gateway's key and config, output captured (bytes), audited (`use`, tool `gate`). No ancestry check (it is called in-process after the user's typed confirmation); the host must be approved and its ssh right not false. Raises `SshError` (also for an ssh-level failure it can explain). |
| `close_masters(name) -> int` | `-O exit` for every master recorded for the host and for the hosts reached through it (via chains), removes the sockets and the host's address and sudo caches. Never raises. consent.ratchet calls it on narrowing. |
| `rotate(name, before_change=None) -> str` | `before_change()` runs once, under the vault's lock, just before the first vault write (`gate rotate` keeps its copy of the vault there), never when the rotation fails before (no key, an unusable link); then the new key stored as a second live key, appended with the current key, verified alone on a fresh connection, old `authorized_keys` lines removed (with the new key), old keys marked `retired`, masters closed. Any failure before the verification (a failed check, a raising one, an interrupted append: round 1) removes only the new key's line again over the old key (best effort), drops the new key and keeps the old one; once the new key is verified, a failure removing the old lines keeps it (reported as "removing the old one failed"). Audited before it connects (`use`, argv `ssh NAME rotate`) and after (`rotate`). Raises `SshError`. |
| `SshError(message, code=2, fix=None, printed=False)` | `message` starts with `gateway:`. |

Every helper above that logs in with Claude's key (`install_key`,
`test_login`, `verify_remote_sudo`,
`probe_remote_nopasswd` when it connects, `run`, `rotate`, `keyscan_host`'s
jump) goes through `_build_link`, which holds it to the host's **effective**
ssh right (`_helper_right`, review round 2): `false` refuses ("ssh is off for
NAME"), `"ask"` needs the user present: a dialog job (`popup.mode()` is
`direct` in the detached helper) or a command
Claude typed (`ancestry.typed_by_claude`; the approval hook asks about `gate
check|rotate|copy-to` on an `"ask"` host). The stand-in passes
`checked=True` (it has applied the same rule itself). gate check's plan
doesn't probe remote sudo on a host whose form ssh is `false`, and its sudo
step does nothing there.

`ssh_args`: `parse_ssh(argv) -> SshArgs`, `check_copy(tool, argv)`,
`parse_destination`, `parse_port`, `has_sudo_word`, `sudo_in_command_position`,
`sudo_commands`, `SUDO_NAMES`,
`forward_listen_host(spec, dynamic)`, `check_forward`, `listen_is_local`,
`Refused`. `ssh_conf`: `Link`, `Conn`, `write_config`, `choose`, `parallel`,
`Agent`, `run_child`, `log_arg`, `explain_failure`, `close_recorded`,
`when_ok`, `answers_ssh`, `net_fingerprint`. `ssh_sudo`: `askpass_script`,
`stage_script`/`STAGE`, `prefix(d, scripts, names)`, `verify_cmd`, `cleanup_cmd`,
`probe`, `stage`, `verify_staged`, `cleanup`, `ASK_LIMIT`, `MIN_PASSWORD`.

## The stand-in, step by step

1. **Parse** like OpenSSH 10 (BSD getopt: options, the destination, options
   again unless `--`, then the command). Refused (exit 2, nothing connects):
   `-F -i -S -J -w -O -M -I -K -g -G -Z`, and `-A -X -Y -R -W` (and their
   `-o ForwardAgent/ForwardX11/ForwardX11Trusted/RemoteForward` forms) unless
   the host's own policy grants that kind of forwarding (PLAN-v4 phase 7,
   "Policy and forwarding" below), every `-o`
   keyword outside an allowlist (SendEnv, SetEnv, ConnectTimeout,
   ServerAlive*, BatchMode=yes, ForwardAgent=no, ControlMaster=no,
   RemoteCommand=none, LocalForward, DynamicForward, ciphers, ... — the safe
   values scp/sftp/git pass; `-c`, `-m` and `-o
   Ciphers/MACs/KexAlgorithms/HostKeyAlgorithms` may only narrow or reorder
   ssh's defaults, checked in step 6), and forwarded ports (`-L`, `-D`,
   `LocalForward`, `DynamicForward`) whose bind address isn't loopback
   (`*`, empty, `0.0.0.0`, `::`, a LAN address: like `-g`, they would open
   the port to other machines; the spec is split like OpenSSH's
   `parse_fwd_field`). `-l`/`-p`/`-o User`/`-o Port` are checked against the
   form and dropped. `-V`/`-Q` exec the pixi ssh directly.
2. **Map** the destination (`[user@]host`, `ssh://user@host:port`, `-l`,
   `-p`): form host by exact name first, then `gw-NAME` as NAME's alias
   (only when no host is called `gw-NAME`), then by address/also (host +
   port), two hosts on one address = refused; account endpoint
   (`accounts.is_ssh_endpoint`); `localhost` = refused (run it directly);
   unknown = `gateway: X isn't in gateway.toml. Did you mean Y? To add it,
   ask the user (Claude can import it from ~/.ssh/config)` (git commands:
   `gateway: no account for X; ask the user to add one`). With an approved
   `others = "mine"` the system ssh is exec'd with the argv unchanged —
   unless the system ssh's own view (`ssh -G` with the user's config:
   aliases, HostName) is a form host's address and port, by name or by IP
   address (resolved with a 1.5 s deadline): then `gateway: myalias is box
   in gateway.toml (same address); run `ssh box CMD` so its rights apply`.
   A user other than the form's is refused.
3. **No command and no `-N`**: `gateway: pass a command; interactive ssh
   can't work here (ssh NAME CMD)`.
4. **Rights** from `consent.compute` (after `consent.ratchet` when the form
   narrowed): `false` → off message; `"ask"` (ssh, or sudo for a command with
   a sudo word) needs `ancestry.typed_by_claude()`: Claude's own command
   shell (or a fork of it) started this ssh with nothing in between, since
   Claude Code can only ask about a command Claude typed (round 1: git,
   rsync, scp and sftp counted as direct, so `rsync f "box:/x; sudo id"`,
   `git clone --upload-pack="sudo …"` and git over ssh skipped "ask").
   Otherwise `gateway: ssh on NAME asks the user each time, and Claude Code
   can only ask about a command Claude runs itself, not the ssh that rsync
   starts; run it as its own command so Claude Code can ask you (ssh NAME
   CMD), or ask the user to set ssh = true for NAME` (for git, rsync, scp,
   sftp, gh, git-lfs, git-remote-*), else `... run it as its own command so
   Claude Code can ask you (not inside a script, sh -c or a wrapper)`.
   Inside a checkpoint job (culprit `checkpoint`: the job runner is the
   stand-in's parent or above it) the approval hook's job wording instead
   (`consent.job_ask_message`): `gateway: a job can't use the "ask" right for
   ssh on NAME (nobody can be asked while it runs); run it with the Bash tool
   as its own command, or ask the user to set it to true.` (`sudo (root) on
   NAME` for remote sudo), so Claude doesn't start another job. Inside a
   gateway terminal or job (culprit `gateway-terminal`, `ancestry.TERMINAL`)
   `consent.pane_ask_message`: `gateway: a gateway terminal or job can't use
   the "ask" right for ssh on NAME (nobody can be asked about what runs
   there); ...`.
   Non-direct without `scripts = true` → `gateway: ssh started by make got
   no key ...` (with no program to name, ancestry's `?`, "started by a
   program the gateway can't trace back to Claude (such as a job still
   running after its session ended)", `ancestry.UNTRACED_WHO`, for remote
   sudo too). Directness is `ancestry.is_direct("ssh")`; any error from it
   or from `typed_by_claude` counts as no (tested). A new host, an unapproved address and a missing pin
   or key each have their own `gate check NAME` message.
5. **Address choice** (`ssh_conf.choose`): approved candidates in form order;
   per candidate, in a daemon thread, the `when` check (this machine's
   source address toward it, UDP connect, nothing sent) and a 1 s TCP +
   `SSH-` banner probe, all within one 2 s deadline, so a slow resolver
   (offline) can't stretch the probe or the process exit; the first in list
   order that answered; its keys are read once (ssh-keyscan) and compared
   with the pins: a non-last candidate with other keys is skipped (audit
   `hostkey_skip`), the last one's mismatch opens `popup.hostkey` (address,
   old/new fingerprints, whether the user's own known_hosts knows the new
   key; on OK the new key is pinned where the pop-up runs, a vault
   `hostkey` event is logged, `pinned_at` set and masters closed). Cached 5
   min per (host, network fingerprint = default-route source addresses,
   candidate list) in `<run>/addr-NAME.json`; an unreachable cached address
   is forgotten. Hosts behind `via` aren't probed (first `when`-matching
   candidate).
6. **Config** per call in `<run>/c-PID-RAND/` (0700): `Host gw-NAME` per hop
   with HostName/Port/User, `HostKeyAlias gw-NAME`, the pins in a per-call
   known_hosts, `GlobalKnownHostsFile /dev/null`, `StrictHostKeyChecking
   yes`, `CheckHostIP no`, `UpdateHostKeys no`, `BatchMode yes`, no
   password/keyboard auth, `IdentitiesOnly yes`, `IdentityAgent <call
   dir>/agent.sock`, `IdentityFile` = each live public key, `ForwardAgent
   no`, `ForwardX11 no`, `PermitLocalCommand no`, `ServerAliveInterval 30`,
   `ConnectTimeout 10`, `ControlMaster auto` + `ControlPath <run>/cm-%C` +
   `ControlPersist 120` (form hosts; account endpoints use no master, since
   two accounts share `git@github.com`), `ProxyJump gw-JUMP` (ssh re-runs
   itself with the same `-F`), final `Host *` with no identity and an empty
   known_hosts. Then `ssh -G` on the final command line must show exactly
   these (alias, address, user, known_hosts, global known_hosts, strict
   checking, agent, no proxy/local command, identity files inside the call
   dir, no remote forward, local/dynamic forwards on loopback only) or the
   call is refused. The ciphers, MACs, key exchange, host key, public key
   and CA signature algorithms of the final command line must be a subset
   of what `ssh -G` gives without the caller's options (OpenSSH's defaults):
   `-c 3des-cbc` or `-o KexAlgorithms=+diffie-hellman-group1-sha1` →
   `gateway: ssh may only use its default algorithms here (ciphers:
   3des-cbc isn't one of them); run the command without -c/-m or that -o
   option` (exit 2, before ssh runs).
7. **Masters and the agent**: with no live master (`ssh -O check`), the
   call first takes the lock file next to each master socket of its chain
   (`<run>/cm-%C.lock`, `fcntl.flock`, in sorted order, polled for at most
   `ssh_conf.MASTER_LOCK_WAIT` = 5 s in all, `ssh_conf.lock_wait()`), checks
   again (a parallel call may have started the master meanwhile: reuse it,
   no agent), and otherwise keeps the locks until its own master answers or
   ssh exits (`Conn.lock_masters` / `unlock_masters`; `Conn.master_watch`,
   the agent watcher, runs around the stand-in's ssh and the gate process's
   `Conn.capture` alike, so a long remote command doesn't keep them;
   `close` releases them too). So parallel calls to one host (checkpoint
   jobs) share one master and OpenSSH's `ControlSocket ... already exists,
   disabling multiplexing` doesn't reach the output. Only a lock holder
   starts a master: a hop whose lock the call doesn't hold (the wait ran
   out) is reached without multiplexing (`Conn.solo`: `ControlMaster no`,
   `ControlPath none` for that hop in the call's config, rewritten in
   place). A later ssh run on the same connection (remote sudo's steps;
   its earlier run released the locks without a master coming up) takes
   only the locks that are free at once. A command line with
   `ControlMaster=no` (scp/sftp) never starts a master: it waits for the
   lock, then drops it and reaches every hop on its own
   (`Conn.starts_master`, from `ssh -G`). Lock files are never removed (a
   waiter could lock an unlinked file).
   The agent: only when no live master answers: `ssh-agent -D
   -a <call dir>/agent.sock` under a small watchdog shell that holds a pipe
   from the stand-in and kills the agent when it closes (so the agent dies
   with the stand-in even after SIGKILL); every key of the chain loaded with
   `ssh-add -t 300 -` from stdin. A call holding the target's lock
   (`Conn.owns_target`) kills it as soon as the target's master answers
   (polled while the command runs; no other call can start that master
   meanwhile); any other call keeps it until its ssh ends. ssh's environment
   is an allowlist (PATH, HOME, USER, LOGNAME, LANG, LC_*, TZ, TERM, TMPDIR,
   GIT_PROTOCOL): never `SSH_AUTH_SOCK`.
   The binary is the env's ssh (`ssh_bin`, `paths.tool`). One exception
   (fix2, 0.9.1): a draining gated (the plugin uninstalled while work runs;
   `ssh_conf.allow_system_ssh`, called by `Daemon.drain`, never by a
   stand-in or `gate`) whose env lost its ssh with the data folder uses the
   system's (`SYSTEM_SSH`, `/usr/bin/ssh`, by path) with the same generated
   config (`-F`: no user or system ssh config is read) and
   `-o ControlMaster=no` (`Conn.base`), so it only rides the gateway's live
   master; with none the call stops before ssh runs (the agent it would
   need is the env's ssh-agent, gone too). It lets the drain resume a remote
   job a pause suspended (terminals.md, "Draining").
8. **Audit**: one `use` line per credential use (tool, target, account for
   endpoints, `ssh NAME CMD...` summary, address, via, master reuse, remote
   sudo, why that address); the session id comes from audit.py. The gate
   process's own logins (`run`, `test_login`, `probe_remote_nopasswd`,
   `verify_remote_sudo`, `rotate`) write one too, with tool `gate`.
9. **Run** ssh as a child: stdin inherited, stdout passed through (scrubbed
   when a sudo password was sent), the remote's stderr streamed through the
   stand-in (after ssh exits, read until 0.5 s of quiet or 5 s at most, so
   nothing else holding the pipe can keep the stand-in waiting); signals
   forwarded; exit code passed on. ssh's own messages go to `-E <call
   dir>/ssh.log`, followed while ssh runs and copied to stderr (so `-v`
   output still streams, and a master that ssh -v backgrounds doesn't hold
   the stand-in's stderr). On exit 255 only that log is classified (the
   remote command's stderr can't pose as an ssh failure; the patterns are
   anchored at line start): host key mismatch → `don't connect; gate check
   NAME`; `Permission denied (publickey)` → `gateway: NAME refused Claude's
   key (installed? run gate check NAME)` (marker for 90 s); a reset/kex
   failure right after that → `gateway: NAME is rate-limiting after failed
   logins; wait a minute` (no failover, no retry); `ssh: connect to host`
   → the cached address is forgotten.

scp/sftp: refused options checked (`-S -F -i -J -A -D`, scp `-T -f -t -M`,
sftp `-s` (round 1: a server path runs that command on the host, sudo
included), the same `-o` allowlist), then `exec <pixi scp|sftp> -S <bin/ssh> ARGS`; the
ssh stand-in they run does everything else (they pass
`-oControlMaster=no`, so they reuse a master but never start one). rsync uses
`RSYNC_RSH`.

## git over ssh (account endpoints)

`git@github.com`, `git@ssh.github.com`, `git@hf.co`, `git@<GHES host>`: the
command must be a git command (`accounts.owner_from_git_command`);
`git-lfs-authenticate` (it prints a bearer token for the LFS API) only when
git-lfs started this ssh (the first ancestor that isn't a shell or `env`
is `git-lfs`, by executable path through ancestry's process helpers; any
error: refused), so Claude running it directly gets `gateway:
git-lfs-authenticate hands out an access token for HOST; only git-lfs may
run it`. The account is `accounts.select(kind, host, owner, form,
effective=..., vault=...)` (GATE_ACCOUNT honoured); select itself refuses
when the owner matches an account of that kind and host which isn't usable
yet (waiting for the user's OK, `use = false`, credential not bound), naming
it, instead of handing the repos to the default or the only other account
(phase C; the stand-in's earlier work-around is gone). The caller must
be direct (or the account has `scripts = true`), the credential must be
bound to the host (`consent.bound_ok`), the account needs an `ssh_key` in
the vault, and the host keys are the built-in ones
(`vault.builtin_host_keys`) or the account record's `host_keys`. Pijul
endpoints are refused (the pijul stand-in brings its own key).

## Remote sudo (SPEC 9.3, hardened)

When: the host's sudo right is true (or "ask" for a command Claude typed,
step 4 above) and the
command has `sudo` in command position (scripts = false, the default) or a
`sudo` word anywhere (scripts = true). `sudoedit` counts as `sudo`, and so
does either called by its path (`/usr/bin/sudo`); command position skips
assignments (also quoted: `A='x y' sudo`), wrappers (env, nohup, time,
timeout, xargs, ...) and redirections (`</dev/null sudo`, `2>&1 sudo`).
`sudo`/`sudoedit` in command position with sudo `false` is refused; a
`sudo` word elsewhere just gets no password.

1. Probe `sudo -n true` (cached 10 min, `rsudo-NAME@USER`) → run untouched.
2. The stored password (`hosts[X].sudo[login user]`): missing →
   `popup.secret` with `verify=verify_remote_sudo`, `store=` and `load=`
   (a request that joined another call's pop-up re-reads the vault; the
   pop-up's note tells the user that commands Claude runs on the host could
   read the password while sudo uses it, and that unticking Remember it
   uses it for this command only; the re-entry pop-up says the same); stale
   → refused at once, with the one re-entry pop-up (`popup.reenter`, which
   dedupes and remembers a cancel); shorter than 8 characters → refused
   (`gateway: the sudo password of USER on NAME is shorter than 8
   characters, so the gateway can't keep it out of command output; remote
   sudo with it is off. Ask the user to run the root command themselves, or
   to use a longer password`).
3. Staging call (password on stdin; SPEC 9.3's script) writes `$d/p` and the
   askpass `$d/a` into a fresh 0700 dir. The askpass (absolute paths and
   builtins only, `PATH=/usr/bin:/bin`) answers only when its parent runs
   as root (effective uid 0 from `/proc/$PPID/status`, else `/bin/ps -o
   uid=`: real sudo is setuid root, a shell or script calling the askpass
   is not), once per sudo process (`used.$PPID`), at most `ASK_LIMIT` (6)
   times per call, and never again after a sudo process asked twice (that
   means its answer was rejected: markers `rejected` and `no`).
4. A saved password not verified in the last 10 minutes (`rsudov-NAME@USER`,
   keyed by the vault entry's `updated`) is verified first with `sudo -k -A
   -v` (one attempt). Rejected (sudo asked twice, or took the answer and
   still failed, as a sudo with `passwd_tries=1` does) → stale (vault
   `reject` event), the re-entry pop-up, and the command doesn't run (exit
   1); so a wrong saved password costs one failed attempt in all, not one
   per call. A password just entered in the pop-up was verified there.
5. The command runs with the askpass scoped to it: scripts = false →
   `sudo() { SUDO_ASKPASS=<dir>/a DISPLAY="${DISPLAY:-gw:0}" command sudo
   "$@"; }; CMD` (plus the same `sudoedit() {...}` when CMD runs sudoedit;
   only `sudo` in command position in Claude's own command gets it; nothing
   is exported to programs the command starts; a sudo in a nested shell, a
   script, after env/nohup/xargs or called by its path, which skips shell
   functions, fails with a gateway hint to run sudo directly or ask for
   `scripts = true`); scripts = true → `export SUDO_ASKPASS=<dir>/a; [ -n
   "${DISPLAY-}" ] || export DISPLAY=gw:0; CMD` (SPEC 9.3 step 3).
   stdout/stderr go through `scrub.Scrubber([password])`, which masks the
   literal password and its base64, URL-encoded and line-split forms; it is
   a guard against accidental echoes, not against a command that transforms
   the value (see the residual risk below).
6. Cleanup (always): `rm -rf` the dir and report the markers. `rejected` →
   stale + the re-entry pop-up + `gateway: the saved sudo password for NAME
   was rejected; a pop-up is open; don't retry`, the command's own exit code
   kept. The command's own output never marks a password stale; sudo's own
   lines (`^Sorry, try again.$`, `^sudo: N incorrect password attempts$`)
   after an answer only drop the verification cache, so the next call
   verifies again.

Residual risk (decided in phase C, docs/dev/phaseB-requests/RESOLUTION.md):
while a call runs, anything running as the login user on the remote can
find the staging dir (`$XDG_RUNTIME_DIR`, `/dev/shm`, `/tmp`) and read
`$d/p` directly, or run real sudo with its own askpass that execs `$d/a`
with stdout redirected. That includes Claude's own command under the
default scripts = false: `ssh box 'sudo true; cat "$XDG_RUNTIME_DIR"/gw.*/p
| rev'` prints the password reversed, and the scrubber doesn't catch a
reversed, hex or spaced-out value. So with a stored sudo password, a host
whose sudo right is true lets Claude learn that password (which may also
work elsewhere), not only run root commands there. The measures above stop
the askpass from handing the password to anything but sudo, keep it out of
the environment (scripts = false) and mask its literal forms in the output
(short passwords refused), stage it only when needed and remove it right
after; they don't stop a deliberate same-user reader on the remote.
What the gateway offers instead (PLAN-v4 phase 7): sudo the host already
allows without a password is used as it is (the probe succeeds, nothing is
staged), but the gateway never installs a sudoers rule (it used to offer
one; a rule like that gives root to every program running as that user
there, which is worse than the residual risk above). `gate check` offers
"Store the sudo password" or "Ask me each time a command needs it"; a
command's dialog has Remember it (untick: used for that command only), and
the host's `elevation` policy (`"ask"`, `"deny"`) limits sudo further. The
pop-up tells the user that Claude's commands on the host could read the
password while sudo uses it.

The sudo password a command asks for (`_sudo_password`): its dialog names
the host's ssh and sudo rights for gated's recheck (`host_check(name, "ssh",
"sudo")`; the re-entry dialog too) and offers "Remember it", ticked
(unticked: used for this command, never stored); after a dialog gave it,
`_rights_after_dialog` reads the rights again before anything is staged on
the host (PLAN-v4 phase 3 review).

## Run dir files

`cm-<hash>` master sockets, `cm-<hash>.lock` (the lock a call holds while
it starts that master; never removed), `cm-NAME.list` (recorded socket
paths for close_masters), `c-PID-RAND/` per-call dirs with `ssh_config`,
`known_hosts`, public keys, `agent.sock`, `ssh.log` (swept when their
process is gone), `addr-NAME.json`, `rsudo-NAME@USER`, `rsudov-NAME@USER`,
`authfail-NAME`; `ssh-resolve-*.conf` exists only during one resolve().

## Tests

`tests/harness_ssh.py` (real sshd on 127.0.0.1 with forced-command wrappers,
fake remote sudo, the `ssh_remote_euid` override that reports the fake sudo
as root to the askpass, short run dir under /tmp for socket paths, stand-in
stubs that exec `harness_ssh.py --entry ROOT`, scripted ancestry (also
"raise"), git-lfs parent and pop-ups (also a joined request), process
cleanup) and `tests/test_ssh_{args,exec,copy,route,sudo,git,setup,hardening,ask}.py`
(104 tests; `test_ssh_ask.py` runs real rsync and git with the real process
tree, `typed="real"`). `tests/mutations_ssh.py` holds 88 mutations of the security
guards (same format as mutation_check.py; `--copy DIR` mutates a scratch
copy so concurrent test runs never see a mutated file; all killed).

## Review round 3 (2026-10-19)

- `off_message(name, what, form_right)`: an effective right that is off
  while the form gives it says `... waits for the user's OK; run gate check
  NAME while the user is here` (stand-in ssh, remote sudo, the gateway's own
  helpers), not "is off ... ask the user if it should be on".
- An auth failure the stand-in explains (`refused Claude's key`) also drops
  the host's `installed` mark (`_forget_installed`), so status stops saying
  "key installed" and the next `gate check` installs the key again.
- `_suggest`: an IP address suggests a host only when it is one of its
  addresses; `_unknown_message` for github.com, hf.co, nest.pijul.com asks
  for an account of that kind (`accounts.no_git_account`).
- `_user_agent_sock()` for "use my own SSH login once": the session record's
  `SSH_AUTH_SOCK` (Claude Code's own environment; `hooks_session.SESSION_VARS`
  and prompt.sh record it), else the caller's, else macOS's launchd, else
  `$XDG_RUNTIME_DIR/{ssh-agent.socket,keyring/ssh,gcr/ssh,openssh_agent}`
  (from the record or the environment; `/run/user/UID` on Linux); each only
  when it is a socket owned by the user (`_my_socket`). Claude's Bash has
  `SSH_AUTH_SOCK` unset, so on Linux the old code had no agent at all.
- Tests: `test_ssh_setup::test_gate_check_notices_a_key_removed_from_the_host`,
  `test_gate_check_reads_the_host_key_of_a_host_that_is_set_up`,
  `test_gate_check_stops_for_a_jump_host_that_isnt_set_up`,
  `test_my_login_finds_the_users_agent_without_ssh_auth_sock`,
  `test_ssh_exec_remote_sudo_turned_on_but_waiting_says_so`; mutations in
  `mutations_ssh.py`.

## Limits

- Hosts behind `via` aren't probed; `when` is evaluated from this machine.
- `install_key("my-login")` from Claude's Bash finds the user's agent only
  if `SSH_AUTH_SOCK` is set or (macOS) `launchctl getenv SSH_AUTH_SOCK`
  knows it (others = "refuse" unsets it in Claude's env).
- The remote login shell must be POSIX for remote sudo; `-tt` (a remote pty)
  makes remote sudo prompt on the pty instead of using the askpass. A
  remote whose sudo doesn't run as root while asking (sudo-rs without
  askpass support, `hidepid=2` on /proc hiding sudo) gets no password; a
  PAM stack asking twice (password then OTP) reads as a rejection.
- Finding `sudo` in the remote command is lexical, not a shell parser: a
  separator inside quotes (`bash -c 'a; sudo x'`) counts as command
  position (more staging or refusals, never fewer passwords given out);
  sudo reached through `eval`, an alias or a name built at run time isn't
  seen (under scripts = false it gets no password).
- The others = "mine" alias check compares the address the user's ssh
  config resolves to; a name that only DNS (not the form) maps to a form
  host's address is caught by IP when it resolves within 1.5 s.
- `git-lfs-authenticate` trusts an ancestor whose executable file is named
  `git-lfs` (the same by-path trust model as ancestry.py).
- A signal (SIGTERM/SIGINT/SIGHUP) is forwarded and the stand-in ends at
  once, but a remote command running on a shared master runs to its end
  (OpenSSH's own mux clients behave the same way).

## Review round 4 (2026-10-19)

- `_scan_via` (keyscan through a jump host) tries the next key type only
  after a connection that offered no matching key (`no matching host key
  type` in ssh's stderr); a target that doesn't answer costs one connect
  timeout, not three (gate check stayed under Claude Code's 2-minute Bash
  timeout only by luck). Test: `test_ssh_setup::test_gate_check_of_a_silent_host_behind_a_jump_stops_quickly_and_asks_nothing`.
- `_classify` still matches form hosts by address before account endpoints;
  the form now refuses a host whose address is a git server
  (`form.GIT_SERVERS`) and warns about one at an account's ssh endpoint, so
  `git@github.com` can't be taken over by a `[hosts.github-com]` entry.

## Integration lows (2026-10-19)

- Parallel calls to one host (checkpoint jobs run in parallel) raced under
  `ControlMaster auto`: two clients that started before the master listened
  both tried to become it, and the second printed OpenSSH's `ControlSocket
  ... already exists, disabling multiplexing` into the command's output.
  `Conn.ensure_agent` now holds the ControlPath lock while it checks for a
  live master and starts one (step 7). Tests:
  `test_ssh_exec::test_ssh_exec_parallel_calls_share_one_master` (two
  stand-ins at once, three rounds: both succeed, neither prints the line,
  one master, one login per round) and
  `test_ssh_exec::test_ssh_exec_master_lock_wait_is_bounded` (a stuck holder:
  `lock_masters` gives up after its wait and the stand-in still works after
  `MASTER_LOCK_WAIT`; a `ControlMaster=no` call doesn't keep the lock); 3
  mutations (no lock, an unbounded wait, scp/sftp keeping the lock).
- Follow-up: `Conn.capture` (the gate process's own calls: copy-to's
  `run`, the passwordless setup of the time (removed in phase 7), `rotate`, the sudo probe) kept the lock
  for its whole remote command, so a parallel stand-in call waited the full
  `MASTER_LOCK_WAIT`; it now releases it when its master answers, through
  the same `Conn.master_watch` as `run_child` (step 7). Tests:
  `test_ssh_exec::test_ssh_exec_long_call_frees_the_lock_once_its_master_answers`
  and `test_ssh_exec::test_ssh_exec_gate_capture_frees_the_lock_once_its_master_answers`
  (the first call, a stand-in or `ssh.run`, runs `sleep 4`; a stand-in
  started while it holds the lock ends within 2.5 s, before it); 3
  mutations (the watcher keeping the lock, `run_child` or `capture` without
  the watch).
- Follow-up (verifier): a call that gave up on the lock after
  `MASTER_LOCK_WAIT` still ran the agent watcher and multiplexed. When the
  holder's master then answered, the watcher killed the call's agent while
  its own ssh was still logging in: `Permission denied (publickey)`, "box
  refused Claude's key", and `gate check` reported the key refused for 90 s
  (`mark_authfail`); the verifier's proxy delaying the first login 7 s
  failed the second call 4 of 4 times (stand-in and `ssh.run`). A call
  that gives up now reaches the hops it couldn't lock without multiplexing
  (`Conn.solo`), keeps its agent until its ssh exits, and runs no watcher;
  only a call holding the target's lock kills its agent early, and nothing
  else can start a master on that ControlPath meanwhile, so the master it
  sees is its own. The same goes for scp/sftp once they drop the lock; a
  later ssh run on the same connection takes only the locks free at once
  (no second wait).
  Tests (a proxy in the harness, `harness_ssh.HoldProxy`, holds each login
  before authentication until the test releases it; the lock wait is
  shortened to 1 s through `testing.override(master_lock_wait=...)`):
  `test_ssh_exec::test_ssh_exec_a_call_that_gives_up_on_the_lock_keeps_its_agent_and_starts_no_master`
  and `test_ssh_exec::test_ssh_exec_gate_capture_that_gives_up_on_the_lock_keeps_its_agent_and_starts_no_master`
  (the holder's master answers first, then the other call logs in; or the
  other call finishes first and leaves no master), and
  `test_ssh_exec::test_ssh_exec_hops_without_their_lock_are_reached_on_their_own`
  (a jump chain with one lock taken); `test_ssh_exec_master_lock_wait_is_bounded`
  now checks that the stand-in that waited starts no master and that a
  `ControlMaster=no` call is solo. 8 mutations (the watcher without the
  target's lock, stand-in and capture; no solo hops, stand-in, capture and
  scp/sftp; the config ignoring solo; one held lock counting for every hop;
  a later run waiting again).
- An `"ask"` right reached inside a checkpoint job gets the approval hook's
  job wording (step 4). Test:
  `test_ssh_ask::test_ask_inside_a_checkpoint_job_gets_the_job_wording`;
  mutation.

## PLAN-v4 phase 7: policy and forwarding (2026-10-20)

- `_policy_gate(name, a, st)`: after the rights, every action of the call
  is decided by `policy.decide` (docs/dev/modules/policy.md):
  `ssh_args.ssh_actions` names them (a remote command: exec; `scp -t` /
  `rsync --server` / `git-receive-pack`: write; `scp -f` / `rsync --server
  --sender` / `git-upload-pack`: read; the sftp subsystem: read and write
  on any path (`ANY_PATH`), or the gateway's own scp's direction and
  operands, read from its argv by executable, `_scp_parent_actions`;
  `-L/-D/-N`: network; each forwarding kind its own grant). A transfer
  server counts only by its exact bare name as the first word
  (`/tmp/x/rsync --server ...` is whatever program that is: exec) and only
  with its own options: scp's `-t|-f` with `r p d v q`; rsync's
  `--server [--sender]` with the short flags, `e.` capability string, `-B<n>`
  and long options that only shape the transfer of the named paths
  (`_RSYNC_SERVER_*`), never `-s` (protected args put the paths on stdin);
  `--remove-source-files` makes each source a write too; any other option
  (`--log-file`, `--temp-dir`, `--backup-dir`, `--*-dest`, `--files-from`,
  whatever `-M` passes) is exec, and so is a path that starts with `-` (rsync's
  option parser reads options after the `.` too: `. --remove-source-files /x`
  removes /x, verified with rsync 3.5). Every path named is decided
  (`ssh_args.decide_path`), in the workspace that holds it and in every
  workspace it may reach (`workspaces_for`, docs/dev/modules/policy.md
  "Workspaces"): the strictest decision applies. A deny refuses with the
  rule (and, for a workspace the path only may reach, why); an "ask"
  passes only for a command Claude typed. Remote sudo is decided as
  `elevation`.
- Forwarding (`parse_ssh(argv, forwards=True)` collects `-A -X -Y -R -W`
  into `SshArgs.forwards`): only for a form host whose `[hosts.NAME.policy]`
  grants the kind (never an account endpoint or an unknown host); `-R` still
  binds only to the host's loopback; `-W HOST:PORT` only; X11 needs `DISPLAY`
  here (said in the refusal). A granted agent forward forwards the call's own
  agent (`ForwardAgent <call dir>/agent.sock`: only the gateway's key for
  that host, never the user's agent), the call skips the shared master (the
  forward belongs to it), and the caller's own `ForwardAgent` options are
  dropped (`_drop_agent_opts`); `_verify_cmdline(granted)` accepts exactly
  the granted forwards in `ssh -G`.
- Account endpoints: the account's `credential` and `write` (a push) are
  decided before the key is used.
- The remote passwordless setup is gone (no sudoers rule is ever installed); the
  sudo dialog's note says "Untick Remember it to use it for this command
  only".
- Tests: `test_policy` (exec, read, write each on its own, workspaces,
  agent/X11/remote forwarding against a local sshd, remote sudo's elevation
  policy, an account's write policy on a push); mutations in
  `mutations_policy.py`.
