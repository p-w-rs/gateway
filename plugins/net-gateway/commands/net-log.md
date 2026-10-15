---
description: Show this machine's net-gateway audit log (recent network/credential/cert activity)
---

Run the net-gateway audit log viewer and summarize the results for the user.

Use the Bash tool to run:

```
pixi run --manifest-path "${CLAUDE_PLUGIN_ROOT}/pixi.toml" --frozen python "${CLAUDE_PLUGIN_ROOT}/run.py" log 40
```

Then give the user a short summary: which hosts were contacted, how many
requests, any downloads, any credential uses, and anything that was refused.
Flag anything that looks unexpected.
