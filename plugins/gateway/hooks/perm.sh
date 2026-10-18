#!/bin/sh
# PreToolUse hook for the gateway's own tools and for file tools.
# Usage: perm.sh PLUGIN_ROOT
#
# Plugins can't ship permission rules, so the rules live here:
# - gateway tools: the *_confirm tools and port_check ask (Claude Code shows
#   its permission prompt with the exact arguments); every other gateway tool
#   is allowed (each one enforces its own policy and accounts).
# - file tools (Read, Grep, Glob, Edit, Write, ...): calls that mention a
#   credential location go to the gateway for a precise check (hook-files);
#   everything else passes without starting Python.
root=$1
input=$(cat)

decide() {
    printf '{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "%s", "permissionDecisionReason": "%s"}}\n' "$1" "$2"
}

tool=$(printf '%s' "$input" | grep -o '"tool_name"[[:space:]]*:[[:space:]]*"[^"]*"' | head -n 1 | sed 's/.*"\([^"]*\)"$/\1/')
case $tool in
    mcp__plugin_gate_gw__*_confirm|mcp__plugin_gate_gw__port_check)
        decide ask "gateway: this call needs your OK" ;;
    mcp__plugin_gate_gw__*)
        decide allow "gateway tool" ;;
    *)
        # Cheap prefilter: only paths that could be credentials go to Python.
        if printf '%s' "$input" | grep -Eq '\.ssh|\.config/(gateway|age|secrets|gh|git)|\.git-credentials|\.docker|huggingface|\.azure|databricks|pijul|asiml|\.pem|/gateway/config|plugins/data/gate'; then
            # Silence from hook-files means "fine"; a failure to run blocks.
            if out=$(printf '%s' "$input" | pixi run --manifest-path "$root/pixi.toml" --frozen \
                    python "$root/run.py" hook-files 2>/dev/null); then
                [ -n "$out" ] && printf '%s\n' "$out"
            else
                decide deny "gateway: could not check this path, so it was blocked"
            fi
        fi ;;
esac
exit 0
