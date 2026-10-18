---
description: No prompt for an account's read/write/delete/exec calls or a host's root commands (this session, or always), or keep an ssh connection open
argument-hint: CLASS KIND:NAME [always] | sudo HOST [always] | reuse ssh:NAME
disable-model-invocation: true
---

The gateway hook has already handled this command: its result is in the
<gateway-result> block attached to this message. Relay it to the user in one
or two short lines (keep any list verbatim). Do not call any tools.

If there is no <gateway-result> block, the hook did not run: tell the user
"The gateway hook did not handle this command, so nothing was changed." and
stop.
