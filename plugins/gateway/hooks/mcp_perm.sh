#!/bin/sh
# PreToolUse decisions for the gateway's own MCP tools (SPEC 14). POSIX sh + awk,
# no Python. Matcher (phase C): mcp__plugin_gate_gw__.*
#
#   host_inspect                   -> allow (every mode: reads files and lists folders on
#                                     this machine, runs nothing, imports nothing)
#   terminal_read, terminal_list,  -> allow (every mode: bounded, scrubbed reads of the
#   job_status, job_tail, job_list    gateway's own terminals and jobs; nothing typed or run)
#   terminal_open on localhost,    -> allow (an idle managed shell, a window size: nothing
#   terminal_resize                   of the model's runs)
#   terminal_open with another     -> no decision (PLAN-v4 phase 6: it may stage the gateway's
#   host                              runtime on that host first; Claude Code's mode decides)
#   host_runtime, action status    -> allow (a read of a remote host's identity and readiness)
#   (or no action)
#   host_runtime, provision/clean  -> no decision (it writes or removes on the host)
#   terminal_send, job_start       -> no decision here: the approval hook (pre_bash.sh)
#                                     judges what they type or run (Bash's denies; never
#                                     allow), then Claude Code's mode decides
#   terminal_signal, terminal_close, job_signal -> no decision (Claude Code's mode decides)
#   http, download                 -> Python decides (launch.sh hook-mcp, hooks_mcp.py;
#                                     PLAN-0.11 §2.10): the network policy in the
#                                     payload's mode (this machine's, and an account's
#                                     own with an account) gives deny or ask, an
#                                     explicit per-mode allow of the user's gives allow
#                                     in that mode (never with an account), anything else
#                                     no decision, so nothing is approved by default;
#                                     never an allow from sh. Python not ready: no output
#   anything else                  -> no output (Claude Code's mode decides)
#
# Only TOP-LEVEL keys of tool_input count: a "host" or "action" key inside an
# object or a string of the input never decides anything. The payload is
# tokenized properly: escape sequences are neutralized first (so every
# remaining double quote delimits a string), then awk splits on quotes and
# tracks the object depth outside strings.
#
#   mcp_perm.sh [--test]   --test (the test runner only) passes launch.sh's --test on
#                          (GATEWAY_TEST_ROOT); without it launch.sh never uses that root
set -u

case $0 in */*) here=${0%/*} ;; *) here=. ;; esac   # dirname, without a process
test_mode=""
if [ "${1-}" = "--test" ] && [ -n "${GATEWAY_TEST_ROOT-}" ]; then
  case $GATEWAY_TEST_ROOT in /*) test_mode=--test ;; esac
fi

input=$(cat)

# shellcheck disable=SC2016  # awk program
decision=$(printf '%s' "$input" | tr '\n\r' '  ' | sed 's/\\./_/g' | awk -F'"' '
function out_chars(s,   n, j, c) {
  n = length(s)
  for (j = 1; j <= n; j++) {
    c = substr(s, j, 1)
    if (c == "{" || c == "[") {
      depth++
      owner[depth] = (lastkey != "" && lastdepth == depth - 1) ? lastkey : "#"
      kind[depth] = c
      lastkey = ""
    } else if (c == "}" || c == "]") {
      depth--
      lastkey = ""
    } else if (c == ",") {
      lastkey = ""
    }
  }
}
BEGIN { depth = 0; lastkey = ""; lastdepth = -1; tool = ""; bad = 0; host = ""; hashost = 0;
        action = ""; hasaction = 0 }
{
  for (i = 1; i <= NF; i++) {
    if (i % 2 == 1) { out_chars($i); continue }
    nxt = (i < NF) ? $(i + 1) : ""
    if (nxt !~ /^[ \t]*:/) continue                 # a string value, not a key
    k = $i
    lastkey = k; lastdepth = depth
    strval = (nxt ~ /^[ \t]*:[ \t]*$/ && i + 2 <= NF) ? 1 : 0
    if (depth == 1 && kind[1] == "{" && k == "tool_name") {
      if (strval) tool = $(i + 2); else bad = 1
    }
    if (depth == 2 && kind[2] == "{" && owner[2] == "tool_input") {
      if (k == "host") {
        hashost++
        if (strval) host = $(i + 2); else host = "?"
      }
      if (k == "action") {
        hasaction++
        if (strval) action = $(i + 2); else action = "?"
      }
    }
  }
}
END {
  if (bad || depth != 0) { print "none"; exit }
  if (tool == "mcp__plugin_gate_gw__host_inspect") { print "allow-inspect"; exit }
  if (tool == "mcp__plugin_gate_gw__terminal_read" || tool == "mcp__plugin_gate_gw__terminal_list" ||
      tool == "mcp__plugin_gate_gw__job_status" || tool == "mcp__plugin_gate_gw__job_tail" ||
      tool == "mcp__plugin_gate_gw__job_list") { print "allow-term-read"; exit }
  if (tool == "mcp__plugin_gate_gw__terminal_resize") { print "allow-term-open"; exit }
  if (tool == "mcp__plugin_gate_gw__terminal_open") {
    if (hashost == 0 || (hashost == 1 && (host == "" || host == "localhost"))) print "allow-term-open"
    else print "none"
    exit }
  if (tool == "mcp__plugin_gate_gw__host_runtime") {
    if (hasaction == 0 || (hasaction == 1 && action == "status")) print "allow-runtime-read"
    else print "none"
    exit }
  if (tool == "mcp__plugin_gate_gw__http" || tool == "mcp__plugin_gate_gw__download") {
    print "python"; exit }
  print "none"
}')

allow() {
  printf '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "allow", "permissionDecisionReason": "%s"}}\n' "$1"
}

case $decision in
  allow-inspect) allow "gateway: a read-only look at what this machine offers (nothing is run or imported)" ;;
  allow-term-read) allow "gateway: a bounded, scrubbed read of a gateway terminal or job (nothing is typed or run)" ;;
  allow-term-open) allow "gateway: an idle managed shell or a window size (nothing of the model's runs)" ;;
  allow-runtime-read) allow "gateway: a read of a remote host's identity and runtime readiness (nothing is run or staged)" ;;
  # shellcheck disable=SC2086  # $test_mode is empty or one word
  python) printf '%s' "$input" | sh "$here/launch.sh" hook-mcp $test_mode 2>/dev/null ;;
  *) : ;;
esac
exit 0
