#!/bin/sh
# PreToolUse guards that need no Python (POSIX sh, builtins plus sed, tr and
# grep).
# Fails open (no output) like the other non-file hooks: Claude Code's own
# permissions still apply.
#
#   browser tools  (matcher mcp__Claude_Browser__.*|mcp__claude-in-chrome__.*:
#                  the desktop app's Browser pane, Claude in Chrome) -> deny while
#                  a browser sign-in runs (PLAN-0.11 §7.2: gated's
#                  <run>/signin-active exists from the person's Open until the
#                  sign-in ends). A browser-automation tool could read the
#                  sign-in page while the person types a password there.
#
#   AskUserQuestion (matcher AskUserQuestion) -> deny when a question, a
#                  header or an option asks for a secret (PLAN-0.11 §9.2): a
#                  password, passphrase, passcode, token, secret, API key,
#                  private or access key, credentials, PIN, 2FA/MFA/OTP or a
#                  one-time, recovery, security or verification code, asked
#                  for (after a request such as "your", "enter", "paste",
#                  "what is"; or the word alone as a header or an option),
#                  not merely named ("how many tokens"). Its answer would go
#                  to the model and the transcript; a secret is typed only in
#                  the gateway's own dialog. Only the payload's tool_input is
#                  read (the rest names paths and ids). A guardrail for a
#                  cooperative model, not a boundary: a rephrased request or a
#                  look-alike letter passes.
#
#   tool_guard.sh [--test]   --test (the test runner only) honours
#                            GATEWAY_TEST_ROOT (and GATEWAY_TEST_RUN, the
#                            daemon tests' short run dir)
set -u
set -f        # no globbing of the names read from the payload

case $0 in */*) here=${0%/*} ;; *) here=. ;; esac   # dirname, without a process
here=$(CDPATH='' cd -- "$here" && pwd -P) || exit 0

run=
if [ "${1-}" = "--test" ] && [ -n "${GATEWAY_TEST_ROOT-}" ]; then
  case $GATEWAY_TEST_ROOT in /*) run=${GATEWAY_TEST_RUN:-$GATEWAY_TEST_ROOT/run} ;; esac
  case $run in /*) ;; *) run= ;; esac
elif [ -f "${here%/*}/e2e-root" ] && [ -f "$here/e2e.sh" ]; then
  # the e2e suite's scratch copy (hooks/e2e.sh): its run folder
  . "$here/e2e.sh"
  if gw_e2e "${here%/*}"; then
    run=${GW_E2E_RUN:-$GW_E2E_ROOT/run}
  fi
fi
# gated's run folder (paths.run_dir): /tmp/gw-$UID
[ -n "$run" ] || run="/tmp/gw-$(id -u)"

input=$(cat)

# Every top-level-shaped "tool_name": "..." pair (a key; an escaped quote
# inside a string never matches). The matcher already chose the tool; a
# browser tool's name anywhere among them makes the guard apply (the safe side).
names=$(printf '%s' "$input" | tr '\n\r' '  ' | sed -n 's/"tool_name"[[:space:]]*:[[:space:]]*"\([^"\\]*\)"/\
@@\1@@\
/gp' | sed -n 's/^@@\(.*\)@@$/\1/p')

browser=
ask=
for n in $names; do
  case $n in
    mcp__Claude_Browser__*|mcp__claude-in-chrome__*) browser=1 ;;
    AskUserQuestion) ask=1 ;;
  esac
done

if [ -n "$browser" ] && [ -e "$run/signin-active" ]; then
  printf '%s\n' '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "gateway: browser tools are paused while a browser sign-in is open (the page may show what the user types there); try again after the sign-in ends (gate check prints its outcome)"}}'
  exit 0
fi

if [ -n "$ask" ]; then
  # tool_input only: from its key up to tool_use_id (Claude Code's order),
  # the whole payload when it can't be found (the safe side)
  ti=${input#*\"tool_input\"}
  ti=${ti%\"tool_use_id\"*}
  # JSON escapes (\n, \", \uXXXX) become spaces, each JSON string its own
  # line (a question, a header, an option's label or description), then
  # every character but a letter or a digit: the words stand between single
  # spaces
  lines=$(printf '%s' "$ti" | tr '\n\r' '  ' | sed -e 's/\\u[0-9A-Fa-f]\{4\}/ /g' -e 's/\\./ /g' |
          tr '"' '\n' | tr -c 'A-Za-z0-9\n' ' ' | tr -s ' ')
  low=$(printf '%s\n' "$lines" | tr 'A-Z' 'a-z')
  # A secret word asked for, not merely named (WS-6 review: "how many
  # tokens", "a CSRF token check", "rotate the secrets" are ordinary
  # questions): after a request (your, enter, paste, input, supply, type
  # the, provide the, share the, give me, send me, tell me, what is) with
  # at most three words between; or a line that is the word alone (a header, an
  # option: "API key", "the password"), or the word with "please" or "here";
  # or PIN in capitals anywhere.
  W='(passwords?|passphrases?|pass phrases?|passcodes?|pass codes?|tokens?|secrets?|api ?keys?|private keys?|access (keys?|tokens?)|credentials?|2fa|mfa|otp|one time (codes?|passwords?)|pin (codes?|numbers?)|recovery codes?|security codes?|verification codes?)'
  R='(your|enter|paste|input|supply|type (the|in|a|an)|provide (the|a|an)|share (the|a)|give (me|us)|send (me|us)|tell me|what is|what s|whats)'
  secret=
  if printf '%s\n' "$low" | grep -Eq -e "(^| )$R( [a-z0-9]+)?( [a-z0-9]+)?( [a-z0-9]+)? $W( |\$)" \
      -e "^ ?((the|your|my|a|an) )?$W( please| here)? ?\$" -e "(^| )$W (please|here)( |\$)"; then
    secret=1
  fi
  if printf '%s\n' "$lines" | grep -Eq '(^| )PINs?( |$)'; then
    secret=1
  fi
  if [ -n "$secret" ]; then
    printf '%s\n' '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": "gateway: ask for secrets only through the gateway'"'"'s dialog (gate check NAME, gate login NAME)."}}'
  fi
fi
exit 0
