---
description: Manage net-gateway secrets (add, up, desc, allow, disallow, del, list); values go in a browser form, never the chat
argument-hint: add NAME description | up NAME | desc NAME text | allow NAME HOST | disallow NAME HOST | del NAME | list
disable-model-invocation: true
---

The net-gateway hook has already handled this command: its result is in the
<net-gateway-result> block attached to this message. Relay that result to the
user in one or two short lines (keep any list it contains). Do not call any
tools and do not do anything else.

If there is no <net-gateway-result> block, the hook did not run: tell the user
"The net-gateway hook did not handle this command, so nothing was changed."
and stop. Never repeat the command's arguments.
