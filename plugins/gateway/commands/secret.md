---
description: Manage gateway secrets (add, up, desc, allow, disallow, del, list); values go in a browser form, never the chat
argument-hint: add NAME description | up NAME | desc NAME text | allow NAME HOST | disallow NAME HOST | del NAME | list
disable-model-invocation: true
---

The gateway hook has already handled this command: its result is in the
<gateway-result> block attached to this message. Relay that result to the
user in one or two short lines (keep any list it contains). Do not call any
tools and do not do anything else.

If there is no <gateway-result> block, the hook did not run: tell the user
"The gateway hook did not handle this command, so nothing was changed."
and stop. Never repeat the command's arguments.
