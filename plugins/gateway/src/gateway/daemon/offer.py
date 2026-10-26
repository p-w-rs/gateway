"""The vault passphrase offer, asked by gated (PLAN-0.11 §8).

Offered, never forced. vault.save() marks the offer due (`passphrase_offer`
"pending") once the vault holds a secret and its key has no passphrase.
After a gateway program stores a secret, popup.offer_passphrase() asks gated
to offer it, once the vault's lock is released (set_passphrase takes the
lock): POST /agent/vault/offer from a gateway program below the session, or
POST /lease/vault/offer {lease} from popup's detached helper (it runs outside
the session's process tree and proves its session with its dialog lease).

gated offers at most once per session (`Offers.offered`, in memory: a
restarted gated may offer again), only while the vault's offer is "pending"
and the key has no passphrase (key mode "unwrapped"; once key.wrapped exists
there is nothing to offer), and only where its dialog can open (a session
that draws on a terminal or the desktop app; claude -p, the SDK, mods off,
mobile and VS Code get nothing, and the offer stays pending).

The dialog is gated's own choice dialog (owner "gated", `offer`
"passphrase"), drawn by the mod from a fixed template (hooks/mod/dialog.ts:
OFFER_TITLE, OFFER_LINES, OFFER_OPTIONS; never gated's words):
  - Set passphrase: gated's set-a-passphrase dialog opens (Daemon.vault_dialog,
    the SET path of /gate-unlock: broker.set_passphrase);
  - Not now: `passphrase_offer` becomes "declined" (gated writes it under the
    vault's lock, waiting at most LOCK_WAIT); it is never offered again unasked,
    and /gate-unlock still sets one;
  - Cancel, a timeout, the session ending: nothing changes ("pending": offered
    after a later store, in a later session).
"""
from __future__ import annotations

import threading
from typing import Any

from .. import vault

WHAT = "vault passphrase offer"
OFFER = "passphrase"
SET, LATER = "Set passphrase", "Not now"
OPTIONS = (SET, LATER)
TITLE = "Protect the vault with a passphrase?"
LINES = ("Without one, any program running as you can read the stored secrets.",
         "Set passphrase opens the gateway's dialog to set one. Not now: the gateway won't "
         "offer it again (/gate-unlock sets one any time).")
LOCK_WAIT = 30.0


class Offers:
    """gated's passphrase offers: which sessions were offered one."""

    def __init__(self, daemon: Any):
        self.d = daemon
        self.lock = threading.Lock()
        self.offered: set[tuple[int, Any]] = set()

    def offer(self, session: Any) -> dict[str, Any]:
        """Offer a vault passphrase in `session` if it is due: {offered: true,
        id} or {offered: false, reason}. Never raises for a reason not to."""
        if session is None:
            return {"ok": True, "offered": False, "reason": "no_session"}
        key = (session.pid, session.start)
        with self.lock:
            if key in self.offered:
                return {"ok": True, "offered": False, "reason": "already_offered"}
        mode = self.d.broker.mode()
        if mode != "unwrapped":
            return {"ok": True, "offered": False, "reason": "wrapped" if mode == "wrapped" else "none"}
        try:
            data = self.d.broker.read(touch=False)
        except Exception:  # noqa: BLE001 - nothing offered when it can't be read
            return {"ok": True, "offered": False, "reason": "unreadable"}
        state = vault.offer_state(data)
        if state != vault.OFFER_PENDING:
            return {"ok": True, "offered": False, "reason": state or "nothing_stored"}
        ok, why = self.d.dialogs.available(session)
        if not ok:
            return {"ok": True, "offered": False, "reason": why}
        with self.lock:
            if key in self.offered:
                return {"ok": True, "offered": False, "reason": "already_offered"}
            self.offered.add(key)
        spec = {"title": TITLE, "entry": "vault", "what": WHAT, "lines": list(LINES),
                "options": list(OPTIONS), "offer": OFFER}
        try:
            r = self.d.dialogs.open_owned(session, spec,
                                          lambda _req, values: self._answer(session, values),
                                          kind="choice")
        except Exception:  # noqa: BLE001 - not offered: a later store may
            r = {"available": False, "reason": "failed"}
        if not r.get("available"):
            with self.lock:
                self.offered.discard(key)
            return {"ok": True, "offered": False, "reason": str(r.get("reason") or "unavailable")}
        return {"ok": True, "offered": True, "id": r.get("id")}

    def _answer(self, session: Any, values: list[str]) -> tuple[bool, str]:
        """The person picked an option (a worker thread, no dialog lock held)."""
        choice = values[0] if values else ""
        if choice == SET:
            r = self.d.vault_dialog(session)
            if r.get("available"):
                return True, "set it in the dialog that opened"
            return True, str(r.get("message") or "nothing to set").removeprefix("gateway: ")
        if choice == LATER:
            try:
                with vault.locked(timeout=LOCK_WAIT):
                    data = vault.load()
                    if vault.offer_state(data) != vault.OFFER_DECLINED:
                        vault.decline_offer(data)
                        vault.save(data)
            except vault.VaultError:
                return False, "the answer couldn't be recorded; it may be offered again"
            return True, "not offered again (/gate-unlock sets one any time)"
        return False, "not one of the options"
