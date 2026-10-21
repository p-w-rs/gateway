---
description: What the gateway lets Claude use - hosts, accounts, rights and what is stored (never a value)
argument-hint: "[NAME]"
allowed-tools: Bash(gate status *) Bash(true)
disable-model-invocation: true
---

Output of `gate status` (the gateway's own helper; it never prints a secret):

!`gate status || true`

Entry the user named after the command (may be empty): $ARGUMENTS

Show the user the output above exactly as printed, in a code block. If the
user named an entry, also run `gate status NAME` in Bash (nothing else) and
show its output the same way.

Only when it applies (otherwise say nothing about it):
- the output says the gateway is still setting up, or that `gate` wasn't
  found: the gateway builds its tools in the background during the first
  session (about a minute) and works once a new session starts;
- it says pixi isn't installed: point to https://pixi.sh; it says setup
  failed: name the log file it shows (setup is retried at the next session
  start);
- it lists a gateway dialog waiting (`/gate-dialog` shows it), a change
  waiting for their OK or problems in gateway.toml: point that out once.

The output ends with the form file, `~/.config/gateway/gateway.toml` (they
can open and edit it), and a "Just ask" line with examples from their own
form; don't add another. End with one short line only: adding or widening
something needs their OK in the gateway's dialog in Claude Code (secrets are
typed only there, never in chat).
