#!/bin/sh
# UserPromptSubmit prefilter (SPEC 12). POSIX sh; Python runs only on a hit:
#  (a) paste guard: a known token prefix or a PEM private key header in the
#      payload -> launch.sh hook-prompt decides; if Python can't run (env still
#      building, crash, no output) the prompt is BLOCKED (fail closed);
#  (b) gateway.toml is newer than this session's last context record, or
#  (c) a gateway dialog request (private/pending/*.json) newer than what this
#      session was shown -> launch.sh hook-prompt adds a systemMessage (fails
#      open);
#  (d) a Claude Code task notification (<task-notification>) once a vault
#      exists: its "waiting for input" notice quotes a background command's raw
#      output, which can hold a stored value with no token shape -> launch.sh
#      hook-prompt blocks it if it holds one; if Python can't run, the notice
#      is BLOCKED (fail closed, like the paste guard).
# Every prompt but a task notification also clears the "cancelled dialog"
# markers (the user has spoken again, so a cancelled dialog may be asked
# again). The first prompt of a
# session writes its record, private/sessions/<session>.env: when it started
# (the file's mtime; copy-to's "pinned before this session") and Claude Code's
# own display variables and SSH_AUTH_SOCK (the user's agent, for gate check's
# "use my own SSH login once"). Hooks get Claude Code's environment,
# not Claude's.
#
#   prompt.sh [--test]   --test (the test runner only) honours GATEWAY_TEST_ROOT
set -u

case $0 in */*) here=${0%/*} ;; *) here=. ;; esac   # dirname, without a process
here=$(CDPATH='' cd -- "$here" && pwd -P) || here=.
test_mode=""
if [ "${1-}" = "--test" ] && [ -n "${GATEWAY_TEST_ROOT-}" ]; then
  case $GATEWAY_TEST_ROOT in /*) test_mode=--test ;; esac
fi
if [ -n "$test_mode" ]; then
  GWHOME="$GATEWAY_TEST_ROOT/home/.config/gateway"
  RUN="$GATEWAY_TEST_ROOT/run"
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
  RUN="/tmp/gw-$(id -u 2>/dev/null || echo x)"
  # The e2e suite's scratch copy (hooks/e2e.sh): the e2e root's home and run dir.
  case $here in
    /*) if [ -f "${here%/*}/e2e-root" ] && [ -f "$here/e2e.sh" ]; then
          . "$here/e2e.sh"
          if gw_e2e "${here%/*}"; then
            GWHOME="$GW_E2E_ROOT/home/.config/gateway"
            RUN=${GW_E2E_RUN:-$GW_E2E_ROOT/run}
          fi
        fi ;;
  esac
fi

# The paste guard's refusal is hooks_prompt.BLOCK_REASON word for word (a test compares them).
BLOCK='{"decision": "block", "reason": "gateway: that looked like a secret, so it wasn'\''t sent; Claude can open the gateway'\''s dialog for it (gate check NAME), where it is typed privately", "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": true}}'
BLOCK_NOTICE='{"decision": "block", "reason": "gateway: a background command notice was held back from Claude: it quotes raw output, and the check for stored secrets could not run, so it was blocked to be safe", "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": true}}'
# Same alternatives as hooks_prompt.TOKEN_PATTERNS (a test keeps them in sync).
# The payload is JSON: a token at the start of a line follows the two
# characters \n (or \r, \t, \b, \f, \uXXXX), so those count as a boundary too.
TOKENS='(^|[^A-Za-z0-9_]|\\[nrtbf]|\\u[0-9A-Fa-f]{4})(gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|hf_[A-Za-z0-9]{30,}|glpat-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AGE-SECRET-KEY-1[0-9A-Z]{50,})|-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----'

input=$(cat)

# A task notification: Claude Code's notice for a background task (see (d)).
notice=""
case $input in *'task-notification>'*) notice=1 ;; esac

priv="$GWHOME/private"
pend="$priv/pending"
sdir="$priv/sessions"
sid=$(printf '%s' "$input" | sed -n 's/.*"session_id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
if [ -n "$sid" ]; then
  sid=$(printf '%s' "$sid" | tr -c 'A-Za-z0-9_-' '_' | cut -c1-80)
fi
if [ -d "$priv" ] && [ ! -L "$priv" ]; then
  if [ -z "$notice" ] && [ -d "$pend" ] && [ ! -L "$pend" ]; then
    find "$pend" -maxdepth 1 -type f -name '*.cancelled' -exec rm -f {} + 2>/dev/null
  fi
  if [ -n "$sid" ]; then
    [ -d "$sdir" ] || mkdir -m 700 "$sdir" 2>/dev/null
    rec="$sdir/$sid.env"
    if [ -d "$sdir" ] && [ ! -L "$sdir" ] && [ ! -e "$rec" ] && [ ! -L "$rec" ]; then
      (
        umask 077
        set -C
        {
          printf 'started=%s\n' "$(date +%s)"
          for v in DISPLAY WAYLAND_DISPLAY XAUTHORITY XDG_RUNTIME_DIR DBUS_SESSION_BUS_ADDRESS SSH_CONNECTION SSH_TTY SSH_AUTH_SOCK; do
            eval "val=\${$v-}"
            case $val in *[!A-Za-z0-9_.:/=,@%+\ -]*) val= ;; esac
            printf '%s=%s\n' "$v" "$val"
          done
        } > "$rec"
      ) 2>/dev/null
      find "$sdir" -type f -mtime +30 -exec rm -f {} + 2>/dev/null
    fi
  fi
fi

paste=""
if printf '%s' "$input" | grep -Eq -- "$TOKENS"; then
  paste=1
fi
# Stored values have no shape: with a vault, Python checks every notice.
if [ -n "$notice" ] && [ -f "$priv/vault.age" ]; then
  paste=1
fi

if [ -n "$paste" ]; then
  # shellcheck disable=SC2086
  out=$(printf '%s' "$input" | sh "$here/launch.sh" hook-prompt $test_mode 2>/dev/null)
  case $out in
    *'"decision"'*|*'"continue"'*|*'"hookSpecificOutput"'*|*'"systemMessage"'*) printf '%s\n' "$out" ;;
    *) if [ -n "$notice" ]; then printf '%s\n' "$BLOCK_NOTICE"; else printf '%s\n' "$BLOCK"; fi ;;
  esac
  exit 0
fi

other=""
form="$GWHOME/gateway.toml"
if [ -n "$sid" ] && [ -f "$form" ]; then
  state="$RUN/sessions/$sid.json"
  if [ ! -f "$state" ] || [ -n "$(find "$form" -newer "$state" 2>/dev/null)" ]; then
    other=1
  fi
fi
if [ -z "$other" ] && [ -n "$sid" ] && [ -d "$pend" ]; then
  if [ -n "$(find "$pend" -maxdepth 1 -name '*.json' 2>/dev/null | head -n 1)" ]; then
    marker="$sdir/$sid.shown.json"
    if [ ! -f "$marker" ] || [ -n "$(find "$pend" -name '*.json' -newer "$marker" 2>/dev/null)" ]; then
      other=1
    fi
  fi
fi

[ -n "$other" ] || exit 0
# shellcheck disable=SC2086
printf '%s' "$input" | exec sh "$here/launch.sh" hook-prompt $test_mode
