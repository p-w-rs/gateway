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
#   sudo ssh scp sftp rsync curl wget gate gateway age credential
#   GIT_TRACE_REDACT key.txt claude jsonl az
#
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
# docs/modules/sudo.md.
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

# Managed execution (PLAN-v4 phase 4, docs/modules/managed.md): in managed
# mode Bash and Monitor run in the gateway's managed bash through
# CLAUDE_CODE_SHELL_PREFIX, which the mod sets to hooks/gate-sh at session
# start. When it isn't this plugin's gate-sh (mods off, Claude Code older
# than 2.1.287, another prefix, a session started before managed mode was
# switched on), every such call goes to the Python hook, which reads the
# effective [shell] managed mode: "on" denies (managed shell unavailable),
# "warn" runs with a notice once per session, "off" judges it as before.
# (A JSON payload escapes the quotes inside strings, so the last unescaped
# "tool_name" is the real one.)
tool=$(printf '%s' "$payload" | sed -n 's/.*"tool_name"[[:space:]]*:[[:space:]]*"\([A-Za-z0-9_]*\)".*/\1/p' 2>/dev/null | head -n 1)
case $tool in
Bash | Monitor)
  # (the data folder's executable copy, written when the plugin's gate-sh lost
  # its exec bit, is told apart by the Python hook: one start per call)
  if [ "${CLAUDE_CODE_SHELL_PREFIX-}" != "$dir/gate-sh" ] &&
     ! { [ -n "${CLAUDE_CODE_SHELL_PREFIX-}" ] && [ "$CLAUDE_CODE_SHELL_PREFIX" -ef "$dir/gate-sh" ]; }; then
    printf '%s' "$payload" | GW_MANAGED_CHECK=1 sh "$dir/launch.sh" hook-bash 2>/dev/null
    exit 0
  fi ;;
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

# Trigger words, each bounded by a non-word character (or start/end of line).
# "gateway" covers config/gateway and gateway.toml (bounded by / and .).
pat='(^|[^A-Za-z0-9_])(sudo|ssh|scp|sftp|rsync|curl|wget|gate|gateway|age|credential|GIT_TRACE_REDACT|key\.txt|claude|jsonl|az)([^A-Za-z0-9_]|$)'

# The payload's transcript_path (always under .../claude/projects/....jsonl)
# would fire "claude"/"jsonl" on every command: leave it out of the check.
words=$(printf '%s' "$payload" | sed 's/"transcript_path"[[:space:]]*:[[:space:]]*"[^"]*"//g' 2>/dev/null) || words=$payload
printf '%s' "$words" | grep -Eq "$pat" 2>/dev/null || exit 0

printf '%s' "$payload" | sh "$dir/launch.sh" hook-bash 2>/dev/null
exit 0
