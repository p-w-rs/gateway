#!/bin/sh
# PostToolUse and PostToolUseFailure prefilter (SPEC 12). POSIX sh; Python
# runs only on a hit (a failure payload carries the output in "error"):
#  - a vault exists: then every response goes to Python, since vault values
#    without a token shape (sudo passwords, prefix-less API keys, refresh
#    tokens, base64 forms) can be in any output, file or terminal Claude reads;
#    except an Edit's, Write's or MultiEdit's (review round 5): Claude Code
#    gives Claude only "The file X has been updated successfully" / "File
#    created successfully at: X" for them, no file content (checked in
#    Claude Code 2.1.301), so starting Python and age for each edit masked
#    nothing Claude reads; their responses still go to Python for a token
#    shape, gateway.toml or a pending notice, below,
#  - the tool response matches a token shape (ghp_, hf_, sk-, JWT, PEM key, ...),
#  - an Edit/Write/MultiEdit touched gateway.toml,
#  - the desktop app's transcript search or event listing (round 4: other
#    sessions' text, which can hold stored values).
# Then: sh launch.sh hook-post (scrubbed updatedToolOutput, form validation
# context; for a failure, which no hook can rewrite, a warning when it holds
# a stored secret or a token
# shape). Fails open (no output).
#
#   post.sh [--test]     --test (the test runner only) honours GATEWAY_TEST_ROOT
set -u

case $0 in */*) here=${0%/*} ;; *) here=. ;; esac   # dirname, without a process
here=$(CDPATH='' cd -- "$here" && pwd -P) || exit 0
test_mode=""
if [ "${1-}" = "--test" ] && [ -n "${GATEWAY_TEST_ROOT-}" ]; then
  case $GATEWAY_TEST_ROOT in /*) test_mode=--test ;; esac
fi
if [ -n "$test_mode" ]; then
  GWHOME="$GATEWAY_TEST_ROOT/home/.config/gateway"
else
  # The passwd home, as Python's paths.user_home() (hooks/home.sh), never $HOME;
  # none at all with GATEWAY_TEST_ROOT but no valid --test (a test never
  # reaches the real ~/.config/gateway; run.py exits 2 then too).
  UHOME=${HOME:-/nonexistent}
  if [ -n "${GATEWAY_TEST_ROOT-}" ]; then
    UHOME=/nonexistent
  elif [ -f "$here/home.sh" ]; then
    . "$here/home.sh"
    UHOME=$(gw_user_home)
  fi
  GWHOME="$UHOME/.config/gateway"
  # The e2e suite's scratch copy (hooks/e2e.sh): the e2e root's home.
  if [ -f "${here%/*}/e2e-root" ] && [ -f "$here/e2e.sh" ]; then
    . "$here/e2e.sh"
    if gw_e2e "${here%/*}"; then
      GWHOME="$GW_E2E_ROOT/home/.config/gateway"
    fi
  fi
fi

input=$(cat)

SHAPES='gh[pousr]_[A-Za-z0-9_]{10,}|github_pat_[A-Za-z0-9_]{10,}|hf_[A-Za-z0-9]{10,}|glpat-[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9_-]{16,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}|AGE-SECRET-KEY-1|-----BEGIN [A-Z0-9 ]*PRIVATE KEY|[Aa]uthorization: *([Bb]earer|[Bb]asic|[Tt]oken) '

hit=""
# Vault values have no shape a word list could catch: with a vault, Python
# (scrub.scrub_text knows every value in every form) sees every response but
# an edit tool's (Edit, Write, MultiEdit; see above). An edit tool counts
# only when the payload names "tool_name" exactly once (JSON escapes a quote
# inside a string, so that one is the top-level key) and names one of the
# three; anything else is another tool (Python: the safe side).
if [ -f "$GWHOME/private/vault.age" ]; then
  hit=1
  after=${input#*\"tool_name\"}
  case $after in
    :\"Edit\"*|:\"Write\"*|:\"MultiEdit\"*|': "Edit"'*|': "Write"'*|': "MultiEdit"'*)
      case $after in *\"tool_name\"*) ;; *) hit="" ;; esac ;;
  esac
fi

if [ -z "$hit" ] && printf '%s' "$input" | grep -Eq -- "$SHAPES"; then
  hit=1
fi

if [ -z "$hit" ]; then
  case $input in
    *'"tool_name":"mcp__ccd_session_mgmt__'*|*'"tool_name": "mcp__ccd_session_mgmt__'*) hit=1 ;;
  esac
fi

if [ -z "$hit" ]; then
  case $input in
    *'"tool_name":"Edit"'*|*'"tool_name": "Edit"'*|*'"tool_name":"Write"'*|*'"tool_name": "Write"'*|*'"tool_name":"MultiEdit"'*|*'"tool_name": "MultiEdit"'*)
      case $input in *gateway.toml*) hit=1 ;; esac ;;
  esac
fi

[ -n "$hit" ] || exit 0
# shellcheck disable=SC2086  # $test_mode is empty or one word
printf '%s' "$input" | exec sh "$here/launch.sh" hook-post $test_mode
