#!/bin/sh
# UserPromptSubmit hook. Usage: prompt.sh PLUGIN_ROOT
#
# /gate:secret and /gate:sudo prompts go to the gateway, which
# handles them (opening a browser form for values) and lets the prompt through
# with the result. If the gateway can't run, the prompt is blocked rather than
# risk a typed value reaching Claude. Every other prompt passes untouched
# without starting Python.
root=$1
input=$(cat)

if printf '%s' "$input" | grep -Eq '"prompt"[[:space:]]*:[[:space:]]*"[[:space:]]*/(gate:)?(secret|sudo)([[:space:]"\\]|$)'; then
    out=$(printf '%s' "$input" | pixi run --manifest-path "$root/pixi.toml" --frozen \
        python "$root/run.py" hook-prompt 2>/dev/null)
    case $out in
        *'"hookSpecificOutput"'*|*'"decision"'*) printf '%s\n' "$out" ;;
        *) printf '%s\n' '{"decision": "block", "reason": "gateway: could not run, so nothing was changed.", "hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": true}}' ;;
    esac
fi
exit 0
