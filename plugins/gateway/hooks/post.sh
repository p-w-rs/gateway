#!/bin/sh
# PostToolUse and PostToolUseFailure prefilter (SPEC 12). hooks.json sends
# every tool here (matcher ".*", PLAN-0.11 §9.1): WebFetch, WebSearch, Read,
# Glob, Grep, AskUserQuestion's answers, the desktop app's Browser pane,
# Claude in Chrome, the Terminal panel and every other MCP server. A tool
# whose response is fixed text or Claude's own input is skipped (SKIP_TOOLS,
# the same as hooks_post.SKIP_TOOLS; a test compares them): its response
# holds nothing Claude didn't write. POSIX sh; Python runs only on a hit (a
# failure payload carries the output in "error"):
#  - a vault exists: then every response goes to Python, since vault values
#    without a token shape (sudo passwords, prefix-less API keys, refresh
#    tokens, base64 forms) can be in any output, file or terminal Claude reads;
#    except an Edit's, Write's or MultiEdit's (review round 5): Claude Code
#    gives Claude only "The file X has been updated successfully" / "File
#    created successfully at: X" for them, no file content (checked in
#    Claude Code 2.1.301), so starting Python and age for each edit masked
#    nothing Claude reads; their responses still go to Python for a token
#    shape or gateway.toml, below,
#  - the tool response matches a token shape (ghp_, hf_, sk-, JWT, PEM key, ...),
#  - it holds the value (8 characters or more) of one of the user's
#    credential variables in Claude Code's environment (envfile.MASK_ENV_NAMES,
#    the one list; compared with builtins, the value
#    never on a command line): Claude's shell keeps the user's environment,
#    so `env` or `echo $GH_TOKEN` would show it (PLAN-0.11 §1.6),
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

# Tools whose response is fixed text or Claude's own input (a todo list,
# plan mode): nothing to mask. Not TaskOutput or Task/Agent, whose responses
# carry a command's or a subagent's output. The name is the value of the
# payload's "tool_name" key, trusted only when the payload names
# "tool_name" exactly once (JSON escapes a quote inside a string, so that
# one is the top-level key); anything else goes on (the safe side). (The
# lists are written out, never in a variable: zsh splits no variable.)
after=${input#*\"tool_name\"}
if [ "$after" != "$input" ]; then
  case $after in
    *\"tool_name\"*) ;;
    *)
      t=${after#:}
      t=${t# }
      case $t in
        \"*)
          t=${t#\"}
          t=${t%%\"*}
          case $t in
            # SKIP_TOOLS (hooks_post.SKIP_TOOLS)
            TodoWrite|TaskCreate|TaskGet|TaskList|TaskUpdate|EnterPlanMode|ExitPlanMode) exit 0 ;;
          esac ;;
      esac ;;
  esac
fi

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

# A credential variable's value in the response (builtins only: eval reads
# a fixed name, the comparison is a case pattern, nothing runs with it).
# The names: envfile.MASK_ENV_NAMES, the one list (PLAN-0.11 §1.6), in its
# order (a test compares).
if [ -z "$hit" ]; then
  for n in GITHUB_TOKEN GH_TOKEN GH_ENTERPRISE_TOKEN GITHUB_ENTERPRISE_TOKEN \
      HF_TOKEN HUGGING_FACE_HUB_TOKEN HUGGINGFACE_TOKEN \
      AZURE_STORAGE_KEY AZURE_STORAGE_SAS_TOKEN AZURE_STORAGE_CONNECTION_STRING \
      AZURE_CLIENT_SECRET ARM_CLIENT_SECRET ARM_ACCESS_KEY \
      DATABRICKS_TOKEN DATABRICKS_CLIENT_SECRET DOCKER_AUTH_CONFIG \
      AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN GOOGLE_API_KEY GOOGLE_APPLICATION_CREDENTIALS_JSON \
      OPENAI_API_KEY GITLAB_TOKEN GL_TOKEN CI_JOB_TOKEN NPM_TOKEN NODE_AUTH_TOKEN \
      PYPI_TOKEN TWINE_PASSWORD CARGO_REGISTRY_TOKEN CLOUDFLARE_API_TOKEN \
      DIGITALOCEAN_ACCESS_TOKEN HCLOUD_TOKEN VAULT_TOKEN SLACK_TOKEN SLACK_BOT_TOKEN \
      DOCKER_PASSWORD AZURE_DEVOPS_EXT_PAT \
      CLAUDE_CODE_OAUTH_TOKEN CLAUDE_CODE_MESSAGING_TOKEN CLAUDE_CODE_CLIENT_KEY_PASSPHRASE \
      ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN; do
    eval "v=\${$n-}"
    [ "${#v}" -ge 8 ] || continue
    case $input in *"$v"*) hit=1; break ;; esac
  done
  v=""
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
