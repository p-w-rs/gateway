# The network class (PLAN-0.11 §3)

`src/gateway/hooks_bash.py` (`_network`, `_net_scan`, `_net_stages`,
`_net_argv`, `_net_text`, `_net_member`, `_net_value`), the `[network]`
table in `form.py` and its consent in `consent.py` (`EffectiveNetwork`,
`sync_network_words`), the prefilter `hooks/pre_bash.sh`, and the cold
window's guard in `hooks/launch.sh` (`degraded_bash`, byte-identical to
`envfile.degraded_bash_text("network" | "network_table")`). Tests:
`tests/test_network.py`; mutations: `tests/mutations_network.py`.

Network commands are one configurable class. curl and wget are ordinary
members: there is no special refusal of them any more. It is a guardrail
for a cooperative model, not a sandbox (see "Known misses").

## Members

Built-in names (`form.NETWORK_BUILTIN`; pre_bash.sh's `net` and launch.sh's
`DEG_NET_NAMES` hold the same list, compared by a test):

```
curl wget wget2 aria2c xh http https lynx w3m links links2
nmap nping masscan zmap rustscan hping3 ssh-keyscan
nc ncat netcat socat telnet ftp tftp lftp smbclient certutil
tcpdump tshark nikto sqlmap hydra gobuster ffuf nuclei arp-scan iperf3
```

Names are compared without letter case everywhere (the hook's `_prog`,
`EffectiveNetwork.names()` for `extra` and `drop`, pre_bash.sh's `grep -i`,
the cold guard's `grep -Ei` but php's server flag `-S`, which keeps its
case): macOS's file systems ignore it, so `CURL` runs curl.

Structural members, found by their shape and named by a reserved name
(`form.NETWORK_RESERVED`) that `drop` can take out. A program called by a
reserved name is not a member (`busybox ls` isn't one):

| reserved name | matches |
|---|---|
| `openssl-tls` | `openssl s_client`, `s_server`, `s_time` (not `rand`, `dgst`, `genrsa`, ...) |
| `http-server` | `python[3] -m http.server`, `-m SimpleHTTPServer`, `-m http` (also `-mhttp.server`, after other options); `php -S`; `ruby -run -e httpd`; `busybox httpd` |
| `dev-tcp` | `/dev/tcp/...` or `/dev/udp/...` as a redirection's target (`> /dev/tcp/h/80`, `exec 3<>/dev/tcp/h/80`, `< /dev/udp/h/53`), also in a shell string |
| `rsync-daemon` | `rsync` with an `rsync://` URL or a `HOST::MODULE` operand |
| `busybox` | `busybox APPLET` where the applet is a class member (`busybox wget`, `busybox nc`) |

Not built in (the user adds them with `extra`): `dig`, `nslookup`, `host`,
`whois`, `ping`, `ping6`, `traceroute`, `mtr`. The ssh family (ssh, scp,
sftp, rsync over ssh) isn't in the class: to configured hosts the rights
gate it, to unconfigured hosts it is the user's own (decision 1). `extra =
["ssh"]` brings it in; even then the class's allow never approves an ssh
family tool, sudo, gate, git or a plain reader: their own rules decide.

## Config and consent

```toml
[network]
commands = "ask"            # a word or a per-mode table; "ask" in every mode when absent
extra    = ["dig", "ping"]  # names added to the class
drop     = ["openssl-tls"]  # names (or reserved names) taken out
```

- `commands` takes deny, ask, cc and allow, bare or per mode. A bare
  `"allow"`/`true` is allow in every mode but plan (cc there); a table's
  allow is allow in its own mode. Lead decision 19.1: an explicit allow is
  honoured (the gateway approves a network command in that mode); `cc`
  leaves it to Claude Code.
- `extra`/`drop`: safe basenames (`[A-Za-z0-9._-]{1,32}`) or reserved names,
  at most 32 each. A name entering the class (added to `extra`, removed from
  `drop`) is a narrowing and applies at once; one leaving it is a widening.
  Raising `commands` in any mode is a widening. Effective names: built-ins
  and reserved names, plus approved and written `extra`, minus the names
  both approved and written in `drop` (`EffectiveNetwork.names`).
- A malformed `[network]` keeps the approved one ("ask" and the built-ins
  if none). Its consent entry is `settings` (`gate check settings`).
- The consent dialog names each mode that moves and what it now does (lead
  decision 4): `network commands: in Plan mode Claude Code decides;
  elsewhere the gateway now approves without asking you (was: asks you in
  every mode)`. A change line is never cut: `popup.consent_text` wraps it
  (`wrap_line`, at most `CONSENT_WRAP` characters per line, below gated's and
  the pane's 400).

## Where it is judged

`_net_scan` runs for every Bash, Monitor, run_in_terminal, checkpoint
job_start, gateway job_start and terminal_send call, configured or not:

- **Parsed commands** (`_net_stages`, `_net_argv`): each stage's program
  after the wrappers (`_unwrap(fork=True, stop={"busybox"})`: env, nice,
  nohup, timeout, time, command, builtin, exec-style wrappers, xargs, sudo,
  doas), the runners (strace, sshpass, flock, chroot, watch, ...), `gate with
  NAME --`; `find -exec/-execdir/-ok`; every command string (`_cmd_strings`:
  a shell's or su's `-c`, trap, alias, `-C` callbacks), parsed and judged
  the same way, else scanned as text; an `ssh HOST CMD` remote command
  (configured host or not; a configured host is remembered for the value);
  a `/dev/tcp` redirection; a shell reading a pipe (`... | sh`: the whole
  text is scanned).
- **Text the parser can't split** (`_net_text`, the same reading as
  `_route_text`: quotes and backslashes dropped, data here-documents left
  out): every class name or shape in program position (`_net_runs`:
  `_text_program`'s walk through wrappers, runners, `-c` strings and `find
  -exec`, plus `gate with NAME --`; anywhere in text piped into a shell or a
  shell's here-string), subshells, groups, `&`, `$( )`, backticks, process
  substitution, `exec`, loops; an ssh remote command; a `/dev/tcp`
  redirection. A word glued to a URL or a value (`https://...`,
  `--opt=curl`) is never a program.

## The value and the effect

`_net_value(eff, mode, host)`: the stricter of `[network] commands` and this
computer's `network` policy (`[hosts.localhost.policy]`, `[policy]`), both
in the call's mode; for a configured host's remote command its own
`[hosts.NAME.policy] network` too. A policy's `allow` (bare or explicit)
restricts nothing and never approves a network command: only `[network]
commands`' own allow does; a policy's ask, deny or cc lowers it. A job or
gateway terminal is judged at its payload's mode (lead decision 19.14:
nothing re-checks the class when the job runs, so the mode it was started
from is the one that counts; its rights still take the modeless rule too).
The reason names the key that decided, its value and its
line (and a wider value waiting for the user's OK).

`_network` then, for the strictest hit:

- **deny**: denied, before any other ask (`NET_DENY`).
- **ask**: joins the rights' asks in one prompt; in a job or gateway
  terminal it is a refusal (`NET_JOB`: nobody can be asked).
- **cc**: no decision from the class.
- **allow**: the allow step may approve the network stages (a bare program,
  no write, no expansion; never under `gate with`, in run_in_terminal or a
  job).
- **any hit short of allow** keeps the gateway's allow off the whole
  command (`net.blocks`): `sudo nmap` with an approved `sudo = true` asks.
- **under `gate with`** (anywhere in the command: its key, or its output
  through a pipe, reaches the network command) anything above ask is ask.

The http and download tools aren't in the class: they go by the `network`
policy only (`hooks_mcp`, `web._network_ok`), and `policy.decide` never
reads `[network]`.

## Prefilter and word file

`pre_bash.sh` forwards a call to Python when its text (the transcript path
left out, JSON's `\n`/`\r`/`\t` made spaces, every quote and backslash
dropped, so `c''url`, `c\url`, `cu""rl` and a name after a newline read as
what the shell runs) has a trigger word: the class's names (not glued to a
dot, dash or colon after them: `curling`, `nc.openbsd` and `https://` don't
fire), `openssl`, `php`, `ruby`, `busybox`, `-m http`/`SimpleHTTPServer`,
`/dev/tcp`, `/dev/udp`, and the user's `extra` names from
`$DATA/network-words` (one per line; a `.` is escaped, it is a regex
wildcard).

`consent.sync_network_words(eff)` writes `network-words` whole (temp file,
rename) whenever its text changes or gateway.toml is newer than it, and
keeps `$DATA/network-form`, a symlink to gateway.toml. It runs wherever the
stand-ins are synced: SessionStart, the Bash hook (`_load_rights`),
FileChanged, PostToolUse after an edit of gateway.toml, and
`consent.approve`. While gateway.toml is newer than `network-words`
(`[ network-form -nt network-words ]`, a built-in test: a hand edit may have
added names), pre_bash.sh sends every call to Python, which rewrites the
file.

## The cold window

While no env can run Python, `launch.sh degraded_bash` matches the same
names (plus `network-words`) and shapes on the same normalised text and
**asks** (`degraded_bash_text network`), or **denies** while gateway.toml
has a `[network]` table, whose value sh can't read (`network_table`: a
`[network]`/`[network.x]` header or a top-level `network` key; a policy's
`network` key is not one). This replaced 0.10's refusal of curl and wget
once a vault existed.

## Known misses (guardrail, not sandbox)

Also in the README's Limits:

- inline networking in interpreters: `python -c` with sockets, `node -e`,
  `perl -MIO::Socket`, `ruby -e` (other than `-run -e httpd`);
- `osascript -e 'do shell script ...'`;
- ssh's `ProxyCommand`, `LocalCommand`, `KnownHostsCommand` and `Match exec`,
  which run locally even for pass-through ssh (a `-o ProxyCommand=nc ...` the
  text scan sees is a hit);
- git `!` aliases, `core.pager` and hooks;
- scheduled runs: crontab, at, launchctl, systemd-run;
- a name computed at run time, `eval "$x"`, a variable `-c` string, a
  script on disk (`bash script.sh`, `cat script | sh` reads a file the hook
  can't see), a function;
- other HTTP servers (npm's `http-server`, `serve`, ...): add them with
  `extra`.
- The text scan shares `_route_text`'s reading: after a `)` it takes the
  next word as a command (`echo $(date) curl` asks).
