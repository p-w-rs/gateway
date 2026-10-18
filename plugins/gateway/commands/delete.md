---
description: Delete an account, a secret or a sudo password from the gateway
argument-hint: NAME, e.g. github:work or OPENCODE_API_KEY or joshua@powerslabs
disable-model-invocation: true
---

The gateway hook has already handled this command: its result is in the
<gateway-result> block attached to this message. Relay it to the user in one
or two short lines (keep any list verbatim). Do not call any tools.

If there is no <gateway-result> block, the hook did not run: tell the user
"The gateway hook did not handle this command, so nothing was changed." and
stop.
