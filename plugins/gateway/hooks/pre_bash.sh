#!/bin/sh
# PreToolUse prefilter (SPEC 8) for Bash, Monitor, the user's Terminal panel
# (mcp__terminal__run_in_terminal), checkpoint's job_start
# (mcp__plugin_check_jobs__job_start: its `command`, or its `argv` list, is in
# the payload as JSON text, so the same word list finds the same words; the
# tool name itself holds none) and the gateway's own job_start and
# terminal_send (PLAN-v4 phase 5: what they run or type; same word list).
# POSIX sh; fail open.
#
# No output and exit 0 unless the command mentions one of the gateway's trigger
# words AS A WORD (so "storage" or "package" don't fire on "age"/"gate"):
#
#   sudo ssh scp sftp rsync gate gateway age credential
#   GIT_TRACE_REDACT key.txt claude jsonl az su doas pkexec runuser osascript
#   slogin sudoedit huggingface-cli
#
# and, run by a path (a "/" right before the name: `/usr/local/bin/gh pr
# list`, `./dvc push`) or by name where the command changes how names are
# found (`PATH=/usr/bin gh`, `command -p gh`, `env -i gh`, `env - gh`, `env
# -u PATH gh`), the account CLIs, which have no trigger word above:
#
#   gh hf databricks crane pijul dvc
#
# (those routes skip the stand-in, and the hook refuses them while an
# account of that kind exists, PLAN-0.11 §19.10; slogin, sudoedit and
# huggingface-cli have no stand-in of their own, so they go by name: slogin
# is ssh by another name, sudoedit is refused like su while this computer's
# sudo goes through the gateway, and huggingface-cli, hf's older name, while
# a huggingface account exists), and a plain `gh ...` (hf, databricks,
# crane, pijul) while its stand-in exists ($DATA/bin/gh: an account of that
# kind is configured) and an account of its kinds is "ask" ($DATA/ask-clis),
# so that account is asked about, and the hook's record lets the stand-in
# use it after the OK (lead decision 19.14)
#
# and every Bash and Monitor call while one of the hook's records of what it
# asked about is pending ($DATA/asks), so the hook drops the ones this
# session's earlier calls left before anything of this call runs
#
# and the network class (PLAN-0.11 §3.4: curl, wget, nc, nmap, ... and the
# user's `extra` names, openssl, php, ruby, busybox, `-m http`, /dev/tcp), so
# Python judges every network command. A quote or backslash inside a word
# doesn't hide it (c''url). While gateway.toml is newer than Python's
# $DATA/network-words, every call goes to Python (a hand edit's new names).
#
# Words are matched without letter case: macOS's file systems ignore it, so
# `CURL`, `Sudo` and `/usr/bin/SSH` run curl, sudo and ssh.
#
# ("su", "doas", "pkexec", "runuser" and "osascript" reach the refusal of the
# other elevation tools while this computer's sudo goes through the gateway,
# PLAN-0.11 §9.5; the Python hook decides whether anything is configured.)
# ("az" reaches the deny of `az account get-access-token` as Claude's own
# command: the az stand-in gives tokens only to programs.)
# ("age" also covers vault.age / cache.age; "key.txt" is the age identity, so
# a read of it through a symlinked alias of the gateway folder that spells no
# other trigger still reaches the Python hook's private-path deny; "claude"
# and "jsonl" reach the deny of Claude Code's session transcripts under
# ~/.claude/projects or ~/.config/claude/projects, which can hold the one-time
# codes the gateway shows the user.)
#
# This is a text prefilter, not a boundary: symlinks and computed names can
# strip every trigger word from a command (`tar c /tmp/alias-of-config`). The
# private-folder deny is a guardrail for a cooperative model; see
# docs/dev/modules/sudo.md.
#
# Monitor calls and Bash calls with run_in_background go by the same word
# list: the gateway doesn't change how Claude's ordinary commands run
# (DECISIONS, "Rolled back").
#
# On a hit, hand the raw hook payload to the Python approval hook through
# launch.sh (which starts the pixi env's python, or degrades quietly). Any
# trouble here means no decision (the classifier / normal prompt decides).
set -u 2>/dev/null || true

case $0 in */*) dir=${0%/*} ;; *) dir=. ;; esac   # dirname, without a process
payload=$(cat 2>/dev/null) || exit 0

# (Without the gateway's managed shell, PLAN-0.11 §1.8, Claude's commands run
# in the user's own shell and are judged by the same word list as any other
# call: there is no blanket check any more.)
# (A JSON payload escapes the quotes inside strings, so the last unescaped
# "tool_name" is the real one.)
tool=$(printf '%s' "$payload" | sed -n 's/.*"tool_name"[[:space:]]*:[[:space:]]*"\([A-Za-z0-9_]*\)".*/\1/p' 2>/dev/null | head -n 1)
case $tool in
mcp__plugin_gate_gw__job_start)
  # A job on a remote host (PLAN-v4 phase 6) is judged as `ssh HOST CMD`: that
  # host's rights apply whatever words the command has, so it always goes to
  # Python. A top-level "host" key other than "" or "localhost" (a string
  # inside the command is escaped, \"host\", and never matches).
  if printf '%s' "$payload" | grep -Eq '"host"[[:space:]]*:[[:space:]]*"[^"]' 2>/dev/null &&
     ! printf '%s' "$payload" | grep -Eq '"host"[[:space:]]*:[[:space:]]*"localhost"' 2>/dev/null; then
    printf '%s' "$payload" | sh "$dir/launch.sh" hook-bash 2>/dev/null
    exit 0
  fi ;;
esac

# $DATA, found as launch.sh finds it: the e2e copy's root, else
# CLAUDE_PLUGIN_DATA (absolute; Claude Code sets it for every hook, so this
# costs no process), else the default folder under the passwd home (none at
# all with GATEWAY_TEST_ROOT: never the real one). Sets _gd ("" for none).
gw_data() {
  _gd=
  if [ -f "$dir/../e2e-root" ] && [ -f "$dir/e2e.sh" ]; then
    _gr=$(CDPATH='' cd -- "$dir/.." 2>/dev/null && pwd -P) || _gr=
    . "$dir/e2e.sh"
    if [ -n "$_gr" ] && gw_e2e "$_gr"; then _gd="$GW_E2E_ROOT/data"; else _gd=; fi
  fi
  if [ -z "$_gd" ]; then
    case ${CLAUDE_PLUGIN_DATA-} in
      /*) _gd=$CLAUDE_PLUGIN_DATA ;;
      *) if [ -z "${GATEWAY_TEST_ROOT-}" ] && [ -f "$dir/home.sh" ]; then
           . "$dir/home.sh"
           _gd="${CLAUDE_CONFIG_DIR:-$(gw_user_home)/.claude}/plugins/data/gate-gateway"
         fi ;;
    esac
  fi
}
gw_data

# The approval hook's records of what it asked about (lead decision 19.14,
# asks.py): while one is pending ($DATA/asks links to the run folder's
# records; a glob, no process), every Bash and Monitor call goes to the hook,
# which first drops the ones this session's earlier calls left (a prompt
# declined or never shown, a stage that never ran), so a sourced file's or a
# function's stand-in, which gets no decision, can't use them. Right after
# an ask only: the stand-in uses the record up when the command runs.
case $tool in
Bash|Monitor)
  if [ -n "$_gd" ]; then
    for _a in "$_gd/asks"/*; do
      if [ -e "$_a" ]; then
        printf '%s' "$payload" | sh "$dir/launch.sh" hook-bash 2>/dev/null
        exit 0
      fi
      break
    done
  fi ;;
esac

# Trigger words, each bounded by a non-word character (or start/end of line).
# "gateway" covers config/gateway and gateway.toml (bounded by / and .).
# The network class (PLAN-0.11 §3.4) has its own bounds: never glued to a
# dot, a dash or a colon after it (`curling`, `nc.openbsd` and `https://...`
# don't fire; Python judges a program by its name anyway). Its structural
# members fire by their words: openssl, an HTTP server's `-m http` (or
# SimpleHTTPServer), php, ruby, busybox, /dev/tcp and /dev/udp (rsync is a
# trigger word already). The user's `extra` names come from
# $DATA/network-words (Python writes it, one name per line; a "." in a name
# is escaped, since it is a regex wildcard). `net` is form.NETWORK_BUILTIN
# (a test compares the three lists: here, launch.sh's cold guard, Python).
# git only together with a later subcommand word that reaches a remote or
# writes its config, or a `$` or backquote as its next word (a subcommand in
# a variable) (PLAN-0.11 §6.5, §6.6: the hook judges a push to an "ask" host
# before it runs; `git status` never starts Python here). Matched without
# letter case (grep -i).
net='curl|wget|wget2|aria2c|xh|http|https|lynx|w3m|links|links2|nmap|nping|masscan|zmap|rustscan|hping3|ssh-keyscan|nc|ncat|netcat|socat|telnet|ftp|tftp|lftp|smbclient|certutil|tcpdump|tshark|nikto|sqlmap|hydra|gobuster|ffuf|nuclei|arp-scan|iperf3'
if [ -n "$_gd" ] && [ -f "$_gd/network-words" ]; then
  while IFS= read -r _w || [ -n "$_w" ]; do
    case $_w in ''|*[!A-Za-z0-9._-]*) continue ;; esac
    _e=; _r=$_w
    while :; do
      case $_r in
        *.*) _e="$_e${_r%%.*}\\."; _r=${_r#*.} ;;
        *) _e="$_e$_r"; break ;;
      esac
    done
    net="$net|$_e"
  done < "$_gd/network-words"
fi
pat="(^|[^A-Za-z0-9_])(sudo|ssh|scp|sftp|rsync|gate|gateway|age|credential|GIT_TRACE_REDACT|key\\.txt|claude|jsonl|az|su|doas|pkexec|runuser|osascript|slogin|sudoedit|huggingface-cli)([^A-Za-z0-9_]|\$)|(^|[^A-Za-z0-9_.-])($net|openssl|php[0-9.]*|ruby[0-9.]*|busybox)([^A-Za-z0-9_.:-]|\$)|-[A-Za-z]*m[[:space:]]*(http|SimpleHTTPServer)|/dev/(tcp|udp)/\
|(^|[^A-Za-z0-9_])git([^A-Za-z0-9_-].*[^A-Za-z0-9_-]|[^A-Za-z0-9_-])(push|fetch|pull|clone|ls-remote|remote(-[a-z]+)?|submodule|lfs|archive|fetch-pack|send-pack|request-pull|http-fetch|http-push|config)([^A-Za-z0-9_-]|\$)\
|(^|[^A-Za-z0-9_])git[[:space:]]+[\$\`]"

# The session's recorded mode (PLAN-0.11 §2.4): while the effective form makes
# the permission mode matter, the Python hook keeps $DATA/mode-epoch
# (modes.set_marker), and a call without a trigger word still goes to Python,
# as `launch.sh hook-mode`, which only records the payload's mode in gated
# (no decision; nothing it prints is passed on). So a mode switched to Manual
# reaches gated before a stand-in of the next command reads it, whatever the
# command's words.
gw_mode_marker() {
  [ -n "$_gd" ] && [ -f "$_gd/mode-epoch" ]
}

# The words checked: the payload's transcript_path (always under
# .../claude/projects/....jsonl) left out, since it would fire
# "claude"/"jsonl" on every command; then JSON's \n, \r and \t escapes made
# spaces and every quote and backslash dropped, as the shell drops them, so
# c''url, c\url, cu""rl and a name after a newline read as the word they run
# (launch.sh's _dq does the same; Python judges the real words).
words=$(printf '%s' "$payload" | sed -e 's/"transcript_path"[[:space:]]*:[[:space:]]*"[^"]*"//g' \
  -e 's/\\[nrt]/ /g' -e "s/[\"'\\\\]//g" 2>/dev/null) || words=$payload
if printf '%s' "$words" | grep -Eiq "$pat" 2>/dev/null; then
  printf '%s' "$payload" | sh "$dir/launch.sh" hook-bash 2>/dev/null
  exit 0
fi
# An account CLI that skips its stand-in: run by a path (a "/"
# right before its name, never glued to a dash, a dot or a word after it),
# or by its name in a command that changes where names are found (PATH
# changed or unset, `command -p`, env clearing its environment or unsetting
# a variable: -i, a lone -, -u, -P, --ignore-environment, --unset, -S).
# Judged on the words without the payload's cwd, so working in a folder
# named like one (~/src/dvc) doesn't start Python for every command; the
# cases (built in, any letter case) spare that sed for every other call.
gw_cmdw() {
  cmdw=$(printf '%s' "$payload" | sed -e 's/"transcript_path"[[:space:]]*:[[:space:]]*"[^"]*"//g' \
    -e 's/"cwd"[[:space:]]*:[[:space:]]*"[^"]*"//g' -e 's/\\[nrt]/ /g' -e "s/[\"'\\\\]//g" \
    2>/dev/null) || cmdw=$words
}
case $words in
  */[Gg][Hh]*|*/[Hh][Ff]*|*/[Dd][Aa][Tt][Aa][Bb][Rr][Ii][Cc][Kk][Ss]*|*/[Cc][Rr][Aa][Nn][Ee]*|\
  */[Pp][Ii][Jj][Uu][Ll]*|*/[Dd][Vv][Cc]*)
    gw_cmdw
    if printf '%s' "$cmdw" | grep -Eiq '/(gh|hf|databricks|crane|pijul|dvc)([^A-Za-z0-9_.-]|$)' 2>/dev/null; then
      printf '%s' "$payload" | sh "$dir/launch.sh" hook-bash 2>/dev/null
      exit 0
    fi ;;
esac
case $words in
  *PATH*|*[Cc][Oo][Mm][Mm][Aa][Nn][Dd]\ *|*[Cc][Oo][Mm][Mm][Aa][Nn][Dd],*|*[Ee][Nn][Vv]\ *|\
  *[Ee][Nn][Vv],*)
    case $words in
      *[Gg][Hh]*|*[Hh][Ff]*|*[Dd][Aa][Tt][Aa][Bb][Rr][Ii][Cc][Kk][Ss]*|*[Cc][Rr][Aa][Nn][Ee]*|\
      *[Pp][Ii][Jj][Uu][Ll]*|*[Dd][Vv][Cc]*)
        gw_cmdw
        if printf '%s' "$cmdw" | grep -Eiq '(^|[^A-Za-z0-9_.-])(gh|hf|databricks|crane|pijul|dvc)([^A-Za-z0-9_.-]|$)' 2>/dev/null &&
           printf '%s' "$cmdw" | grep -Eiq '(^|[^A-Za-z0-9_])PATH([^A-Za-z0-9_]|$)|(^|[^A-Za-z0-9_-])command(,?[[:space:]]+-[A-Za-z]*)*,?[[:space:]]+-[A-Za-z]*p|(^|[^A-Za-z0-9_-])env[^;&|]*[[:space:]](-[A-Za-z0-9]*[iuPS]|-([[:space:],]|$)|--ignore-environment|--unset|--split-string)' 2>/dev/null; then
          printf '%s' "$payload" | sh "$dir/launch.sh" hook-bash 2>/dev/null
          exit 0
        fi ;;
    esac ;;
esac
# A plain account CLI while its stand-in exists (an account of that kind is
# configured) and an account of its kinds is "ask" in some mode (Python's
# $DATA/ask-clis, one name per line; every CLI with a stand-in while that
# file is missing): the hook asks about the account and its record lets the
# stand-in use it after the OK (lead decision 19.14). The stand-ins are
# files in $DATA/bin (test -e and read are built in).
_clis=
if [ -n "$_gd" ]; then
  if [ -f "$_gd/ask-clis" ]; then
    while IFS= read -r _c || [ -n "$_c" ]; do
      case $_c in gh|hf|databricks|crane|pijul) ;; *) continue ;; esac
      if [ -e "$_gd/bin/$_c" ]; then _clis="$_clis${_clis:+|}$_c"; fi
    done < "$_gd/ask-clis"
  else
    for _c in gh hf databricks crane pijul; do
      if [ -e "$_gd/bin/$_c" ]; then _clis="$_clis${_clis:+|}$_c"; fi
    done
  fi
fi
if [ -n "$_clis" ]; then
  gw_cmdw
  if printf '%s' "$cmdw" | grep -Eiq "(^|[^A-Za-z0-9_.-])($_clis)([^A-Za-z0-9_.-]|\$)" 2>/dev/null; then
    printf '%s' "$payload" | sh "$dir/launch.sh" hook-bash 2>/dev/null
    exit 0
  fi
fi
# gateway.toml changed since Python last wrote network-words (a hand edit may
# have added `extra` names): Python judges this call and rewrites the file.
# ($DATA/network-form is Python's symlink to gateway.toml; -nt is built in.)
if [ -n "$_gd" ] && [ "$_gd/network-form" -nt "$_gd/network-words" ]; then
  printf '%s' "$payload" | sh "$dir/launch.sh" hook-bash 2>/dev/null
  exit 0
fi
if gw_mode_marker; then
  printf '%s' "$payload" | sh "$dir/launch.sh" hook-mode >/dev/null 2>&1
fi
exit 0
