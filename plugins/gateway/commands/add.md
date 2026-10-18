---
description: Add an account (GitHub, Hugging Face, a server over SSH, Azure, ML Catalog, registry, Pijul), a secret or a sudo password; Claude guides you, a dialog asks for the value
argument-hint: account | secret | sudo | ssh | github | hf | azure | catalog | registry | pijul
disable-model-invocation: true
---

The gateway hook has already handled this command; its note is in the
<gateway-result> block attached to this message.

- If the note says a setup is open (it gives a grant id like g-1a2b3c4d),
  load the gate:setup skill and follow it: ask the user the few questions it
  lists with your question pop-ups, in plain words, then call the gateway's
  gate_setup tool with that grant and the proposal. Never ask for a password,
  token or key in the chat: the gateway asks for those in its own dialog.
- Otherwise, relay the note to the user in one or two short lines (keep any
  list or public key verbatim) and stop.

If there is no <gateway-result> block, the hook did not run: tell the user
"The gateway hook did not handle this command, so nothing was changed." and
stop. Never repeat a value the user typed.
