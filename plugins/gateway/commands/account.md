---
description: Manage gateway accounts (GitHub, Hugging Face, Pijul, Azure, ML Catalog, SSH, registries); credentials go in a browser form, never the chat
argument-hint: add KIND NAME description | up KIND:NAME | allow KIND:NAME OWNER|HOST | prompts KIND:NAME|* class=value | pubkey KIND:NAME | import KIND:NAME SECRET | forget KIND:NAME token|ssh_key | del KIND:NAME | list
disable-model-invocation: true
---

The gateway hook has already handled this command: its result is in the
<gateway-result> block attached to this message. Relay that result to the
user in one or two short lines (keep any list or public key it contains,
verbatim). Do not call any tools and do not do anything else.

If there is no <gateway-result> block, the hook did not run: tell the user
"The gateway hook did not handle this command, so nothing was changed."
and stop. Never repeat the command's arguments.
