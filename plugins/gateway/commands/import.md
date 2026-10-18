---
description: Import a file made by /gate:export (asks for its passphrase and shows what changes first)
argument-hint: FILE
disable-model-invocation: true
---

The gateway hook has already handled this command; its note is in the
<gateway-result> block attached to this message.

- If the note says a setup is open (it gives a grant id like g-1a2b3c4d),
  ask the user the one question the note gives, with a question pop-up, in
  plain words, then call the gateway's gate_setup tool with that grant and
  the proposal the note shows. Never ask for the passphrase in the chat: the
  gateway asks for it in its own dialog.
- Otherwise, relay the note to the user in one or two short lines and stop.

If there is no <gateway-result> block, the hook did not run: tell the user
"The gateway hook did not handle this command, so nothing was changed." and
stop.
