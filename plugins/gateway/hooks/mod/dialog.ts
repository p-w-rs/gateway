// The gateway dialog's pure logic (no `$`): what gated's /ui/dialog/next
// answers, what the pane shows, the status lines and the guard's words.
// register.tsx draws it; dialog.test.ts tests it under `claude plugin test`.
//
// gated (daemon/dialogs.py) owns the requests: their ids, their queue (one
// dialog at a time per session, the others shown by identity), their key
// pairs. Nothing here is secret: a dialog's view holds names, fixed texts and
// a public key; a typed value exists only inside the Client field (field.tsx),
// and leaves it sealed.

export const PANE = 'gate-dialog'
export const SECRET_KINDS: readonly string[] = ['secret', 'passphrase', 'unlock']
export const CLIENT_SURFACES: readonly string[] = ['terminal', 'desktop']
export const GUARD_TEXT = "click the gateway dialog's field first, then type there (what you type here is held back)"
// The one keyboard route to the dialog's buttons where no click reaches them
// (the terminal's main screen): /gate-dialog gives the pane the keys, Tab
// moves to Paste from clipboard, Enter presses it (tests/acceptance_dialogs.py
// presses Paste this way, live). Every text here says it the same way.
export const MAIN_KEYS = '/gate-dialog, then Tab and Enter'
// What Paste leaves behind: gated reads the clipboard and never clears it.
export const PASTE_NOTE = 'Paste leaves the value on your clipboard: clear it yourself afterwards (copy something else).'
// How to get the fullscreen view, where the field takes a click and keys:
// Claude Code's own /tui fullscreen (it restarts and resumes the session;
// the command and its words are in Claude Code 2.1.310).
export const FULLSCREEN_CMD = '/tui fullscreen'
export const FULLSCREEN_HINT = `For a field you can type into, type ${FULLSCREEN_CMD} (Claude Code's fullscreen view; it restarts and resumes this session).`
// The guard's words where the field can't take keys: the terminal's main
// screen (no clicks reach plugins there) and a pane the person closed.
export const GUARD_MAIN_TEXT = `a gateway dialog waits for a secret, so typing here is held back: this terminal can't type into its field (the main screen); copy the secret and press the dialog's Paste from clipboard (${MAIN_KEYS}; it stays on your clipboard), or type ${FULLSCREEN_CMD} (it restarts and resumes the session) to type it there`
export const GUARD_CLOSED_TEXT = "a gateway dialog waits for a secret, so typing here is held back: /gate-dialog shows it again (type or paste it there, or cancel it)"
// What the guard lets into the prompt box while a secret dialog waits: one
// of the gateway's own commands being typed (so /gate-dialog can bring the
// dialog back), or an emptied box. Never any other text: a secret typed
// into the prompt box (the reflex at a password prompt) would reach every
// plugin's prompt hooks and, on Enter, the model.
export const GATE_COMMANDS: readonly string[] = ['/gate-dialog', '/gate-unlock', '/gate-lock', '/gate-doctor']
export const NOT_RECEIVED = "the gateway couldn't open what was sent (its dialog changed meanwhile); type it again"
export const MAIN_SCREEN = `This terminal can't type into the gateway's field: it shows Claude Code's main screen (CLAUDE_CODE_NO_FLICKER=0, or tmux), where clicks don't reach plugins. Copy the secret and press Paste from clipboard (${MAIN_KEYS}). ${PASTE_NOTE} Don't type it into the prompt. ${FULLSCREEN_HINT}`
// Linux without DISPLAY or WAYLAND_DISPLAY in Claude Code's environment (a
// console, ssh without X forwarding): gated can't read a clipboard there
// (daemon/clipboard.py needs one of them), so on the main screen neither
// typing nor Paste works (review round 2). The Paste button stays (a test
// override's clipboard program works anywhere); these texts say what to do.
export const NO_DISPLAY = "this Linux session has no graphical display (no DISPLAY or WAYLAND_DISPLAY), so the gateway can't read a clipboard"
export const NO_DISPLAY_TODO = `type ${FULLSCREEN_CMD} (Claude Code's fullscreen view, where the field takes a click and keys; it restarts and resumes the session), or set the credential from a Claude Code session in this machine's desktop (where Paste works)`
export const NO_DISPLAY_MAIN = `Neither typing nor Paste can work in this terminal: it shows Claude Code's main screen, where clicks don't reach plugins, so the field can't take keys; and ${NO_DISPLAY}. Cancel this dialog, then ${NO_DISPLAY_TODO}, and ask again. Don't type it into the prompt.`
export const NO_DISPLAY_PASTE = `Paste from clipboard can't work here: ${NO_DISPLAY}. Type the secret into the field.`
export const GUARD_NODISPLAY_TEXT = 'a gateway dialog waits for a secret, so typing here is held back: neither typing nor Paste can work in this terminal (the main screen, and no graphical display for the clipboard); /gate-dialog shows what to do'
export const UNAVAILABLE_SURFACE = "Credential entry isn't available on this surface (it has no private field). Answer it at the computer, in the terminal or the desktop app, or cancel."

// The browser sign-in's confirm dialog (PLAN-0.11 §7.1): gated sends only its
// validated fields (`signin`), the words are this fixed template. Open makes
// gated bind its 127.0.0.1 listener and open the system browser; nothing
// happens before it, and Cancel is focused first. The Open answer carries the
// display and desktop variables the browser needs on Linux, and
// SSH_CONNECTION (over ssh a Mac's browser opens on its own screen):
// SIGNIN_ENV, in register.tsx's order.
export const SIGNIN_WHAT = 'browser sign-in'
export const SIGNIN_ENV: readonly string[] = ['DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'XDG_CURRENT_DESKTOP', 'XDG_DATA_DIRS', 'SSH_CONNECTION']
export const SIGNIN_UNREADABLE = "The gateway sent a browser sign-in this pane can't show; press Cancel."
export const SIGNIN_NOTE = "Open starts the sign-in in your system browser; its result goes straight into the gateway's vault, never to Claude. Nothing happens before you press Open."
export type Signin = { account: string; kind: string; tenant: string; client: string; scope: string; host: string; previous_client: string }

const SIGNIN_NAME = /^[a-z][a-z0-9-]{0,31}$/
const SIGNIN_GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/
const SIGNIN_TENANT = /^[A-Za-z0-9.-]{1,100}$/
const SIGNIN_HOST = /^[A-Za-z0-9_.@:-]{1,48}$/
const SIGNIN_SCOPE = /^[A-Za-z0-9._:/~-]{1,200}( [A-Za-z0-9._:/~-]{1,200}){0,8}$/

// The sign-in's fields, each checked again here; null when any isn't valid.
export function parseSignin(v: unknown): Signin | null {
  if (typeof v !== 'object' || v === null) return null
  const o = v as Record<string, unknown>
  const s = (k: string): string => (typeof o[k] === 'string' ? (o[k] as string) : '')
  const out: Signin = { account: s('account'), kind: s('kind'), tenant: s('tenant'), client: s('client'), scope: s('scope'), host: s('host'), previous_client: s('previous_client') }
  if (!SIGNIN_NAME.test(out.account) || !SIGNIN_TENANT.test(out.tenant) || !SIGNIN_GUID.test(out.client) || !SIGNIN_SCOPE.test(out.scope)) return null
  if (out.kind === 'ml-catalog' ? !SIGNIN_HOST.test(out.host) : out.kind !== 'azure' || out.host !== '') return null
  if (out.previous_client !== '' && !SIGNIN_GUID.test(out.previous_client)) return null
  return out
}

export function signinTitle(s: Signin): string {
  return `Sign in to ${s.account} in your browser`
}

export function signinLines(s: Signin): string[] {
  const lines = [s.kind === 'ml-catalog'
    ? `Claude asks to sign in to the model catalog ${s.host} as you (account ${s.account}), in your web browser.`
    : `Claude asks to sign in to Azure as you (account ${s.account}), in your web browser.`]
  lines.push(`Tenant: ${s.tenant}`)
  lines.push(s.kind === 'ml-catalog' ? `Client id (from the catalog): ${s.client}` : `Client id: ${s.client}`)
  if (s.previous_client !== '') lines.push(`The catalog's client id changed since the last sign-in (it was ${s.previous_client}).`)
  lines.push(`Scope: ${s.scope}`)
  lines.push(SIGNIN_NOTE)
  return lines
}

// The vault passphrase offer (PLAN-0.11 §8): gated's own choice dialog
// (daemon/offer.py) after a secret was stored while the vault's key has no
// passphrase; gated sends only `offer: "passphrase"`, the words are this
// fixed template. The options are gated's too (an answer must be one of
// them): Set passphrase opens the set-a-passphrase dialog, Not now stops the
// offer for good, Cancel (or Escape) leaves it for a later store.
export const OFFER_WHAT = 'vault passphrase offer'
export const OFFER_TITLE = 'Protect the vault with a passphrase?'
export const OFFER_LINES: readonly string[] = [
  'Without one, any program running as you can read the stored secrets.',
  "Set passphrase opens the gateway's dialog to set one. Not now: the gateway won't offer it again (/gate-unlock sets one any time).",
]
export const OFFER_OPTIONS: readonly string[] = ['Set passphrase', 'Not now']

export type DialogView = {
  id: string
  kind: string
  title: string
  entry: string
  what: string
  target: string
  lines: string[]
  options: string[]
  checked: string[]
  default: string
  ok_label: string
  cancel_label: string
  default_cancel: boolean
  fields: number
  remember: boolean | null
  paste: boolean
  input: boolean
  attempt: number
  max: number
  error: string
  state: string
  expires_in: number
  pub: string
  signin: Signin | null
}

export type QueueItem = { id: string; kind: string; entry: string; what: string }
export type Recent = { id: string; entry: string; what: string; outcome: string; note: string }
export type NextView = { rev: number; dialog: DialogView | null; queue: QueueItem[]; recent: Recent[]; available: boolean }

const ID = /^d_[0-9a-f]{16}$/

function str(o: Record<string, unknown>, k: string, max = 4000): string {
  const v = o[k]
  return typeof v === 'string' ? v.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, max) : ''
}

function strs(o: Record<string, unknown>, k: string, max = 400): string[] {
  const v = o[k]
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string').map((x) => x.replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, max)).slice(0, 40) : []
}

function num(o: Record<string, unknown>, k: string): number {
  const v = o[k]
  return typeof v === 'number' && Number.isFinite(v) ? v : 0
}

export function parseDialog(v: unknown): DialogView | null {
  if (typeof v !== 'object' || v === null) return null
  const o = v as Record<string, unknown>
  const id = str(o, 'id', 64)
  if (!ID.test(id)) return null
  const remember = o.remember === true ? true : o.remember === false ? false : null
  const d: DialogView = {
    id, kind: str(o, 'kind', 20), title: str(o, 'title', 120), entry: str(o, 'entry', 64),
    what: str(o, 'what', 48), target: str(o, 'target', 120), lines: strs(o, 'lines'),
    options: strs(o, 'options', 120), checked: strs(o, 'checked', 120), default: str(o, 'default'),
    ok_label: str(o, 'ok_label', 40) || 'OK', cancel_label: str(o, 'cancel_label', 40) || 'Cancel',
    default_cancel: o.default_cancel === true, fields: num(o, 'fields'), remember,
    paste: o.paste === true, input: o.input === true, attempt: num(o, 'attempt') || 1,
    max: num(o, 'max') || 3, error: str(o, 'error', 300), state: str(o, 'state', 20),
    expires_in: num(o, 'expires_in'), pub: str(o, 'pub', 64), signin: null,
  }
  if (o.offer === 'passphrase' && d.kind === 'choice') {
    // the passphrase offer: the fixed template, never gated's own words
    return { ...d, title: OFFER_TITLE, lines: [...OFFER_LINES], options: [...OFFER_OPTIONS], cancel_label: 'Cancel', default_cancel: false }
  }
  if (o.signin === undefined || o.signin === null) return d
  // a browser sign-in: the fixed template, never gated's own words
  const s = d.kind === 'confirm' ? parseSignin(o.signin) : null
  return {
    ...d, signin: s, title: s !== null ? signinTitle(s) : 'Browser sign-in',
    lines: s !== null ? signinLines(s) : [SIGNIN_UNREADABLE], ok_label: 'Open', cancel_label: 'Cancel',
    default_cancel: true,
  }
}

export function parseNext(text: string): NextView | undefined {
  let v: unknown
  try {
    v = JSON.parse(text)
  } catch {
    return undefined
  }
  if (typeof v !== 'object' || v === null) return undefined
  const o = v as Record<string, unknown>
  if (typeof o.rev !== 'number') return undefined
  const queue: QueueItem[] = Array.isArray(o.queue)
    ? o.queue.filter((q): q is Record<string, unknown> => typeof q === 'object' && q !== null)
        .map((q) => ({ id: str(q, 'id', 64), kind: str(q, 'kind', 20), entry: str(q, 'entry', 64), what: str(q, 'what', 48) }))
        .filter((q) => ID.test(q.id))
    : []
  const recent: Recent[] = Array.isArray(o.recent)
    ? o.recent.filter((q): q is Record<string, unknown> => typeof q === 'object' && q !== null)
        .map((q) => ({ id: str(q, 'id', 64), entry: str(q, 'entry', 64), what: str(q, 'what', 48), outcome: str(q, 'outcome', 20), note: str(q, 'note', 200) }))
        .filter((q) => ID.test(q.id))
    : []
  return { rev: o.rev, dialog: parseDialog(o.dialog), queue, recent, available: o.available === true }
}

export function isSecret(d: DialogView | null | undefined): boolean {
  return d !== null && d !== undefined && SECRET_KINDS.includes(d.kind)
}

export function clientSurface(surface: string | null | undefined): boolean {
  return surface !== null && surface !== undefined && CLIENT_SURFACES.includes(surface)
}

// The prompt box's text after an edit (prompt.edit's splice).
export function afterEdit(e: { text: string; start: number; end: number; inputText: string }): string {
  return e.text.slice(0, e.start) + e.inputText + e.text.slice(e.end)
}

// May the prompt box hold this text while a secret dialog waits?
export function guardPasses(text: string): boolean {
  return text === '' || GATE_COMMANDS.some((c) => c.startsWith(text))
}

// The guard's answer to one composer edit while a secret dialog waits.
// `base` is the text the guard last let the box hold (undefined before the
// guard's first edit, when the box holds the person's draft from before the
// dialog). The editor paints each edit at once and may hand the next edit a
// draft that still holds keys whose refusal hadn't come back yet (seen on
// 2.1.304: a few characters from the middle of a typed value stayed, because
// a later refusal answered with that draft). So the draft an edit was made to
// is trusted only when it is `base`, or itself may stay (emptied, a gateway
// command being typed); otherwise the box goes back to `base`. A trusted edit
// passes when its result may stay, or when it only deletes or moves (taking
// characters out of a trusted text adds nothing typed meanwhile).
export type GuardAnswer = { pass: boolean; text: string; cursor: number }

export function guardEdit(e: { text: string; cursor: number; start: number; end: number; inputText: string }, base: string | undefined): GuardAnswer {
  const trusted = base === undefined || e.text === base || guardPasses(e.text)
  if (!trusted) {
    const b = base ?? ''
    return { pass: false, text: b, cursor: b.length }
  }
  const after = afterEdit(e)
  if (guardPasses(after) || e.inputText === '') {
    return { pass: true, text: after, cursor: Math.max(0, Math.min(e.start + e.inputText.length, after.length)) }
  }
  return { pass: false, text: e.text, cursor: Math.max(0, Math.min(e.cursor, e.text.length)) }
}

// A prompt the person submits while a secret dialog waits: it goes only when
// it is what the guard let the box hold (the draft from before the dialog, a
// gateway command), so characters that reached the box some other way (the
// editor's paint, a skipped hook) never reach the model.
export const GUARD_DROP_TEXT = "gateway: a gateway dialog waits for a secret, so this prompt wasn't sent (it may hold what was meant for the dialog). /gate-dialog shows the dialog; type or paste the secret there, or cancel it."

export function guardSubmitPasses(text: string, base: string | undefined): boolean {
  return base === undefined || text === base || guardPasses(text)
}

// The guard's status line: the field can take keys (click it), the
// terminal's main screen (Paste, or the fullscreen view; neither without a
// display on Linux), or a closed pane.
export function guardText(placed: boolean, fieldUsable: boolean, noDisplay = false): string {
  if (!fieldUsable) return noDisplay ? GUARD_NODISPLAY_TEXT : GUARD_MAIN_TEXT
  return placed ? GUARD_TEXT : GUARD_CLOSED_TEXT
}

export function who(q: { entry: string; what: string }): string {
  if (q.entry && q.what) return q.entry === 'vault' ? `the ${q.what}` : `${q.what} for ${q.entry}`
  return q.entry || q.what || 'a request'
}

// "Also waiting: token for gh-work, sudo password for build" (the queue,
// shown by identity).
export function queueLine(q: readonly QueueItem[]): string | undefined {
  if (q.length === 0) return undefined
  const names = q.slice(0, 4).map(who)
  return `Also waiting: ${names.join(', ')}${q.length > 4 ? `, and ${q.length - 4} more` : ''}`
}

export function fieldLabels(d: DialogView): string[] {
  if (d.kind === 'passphrase') return ['New passphrase', 'Type it again']
  if (d.kind === 'unlock') return ['Passphrase']
  const w = d.what || 'secret'
  return [w.charAt(0).toUpperCase() + w.slice(1)]
}

export function attemptLine(d: DialogView): string | undefined {
  if (!d.error) return undefined
  return d.attempt > 1 ? `${d.error} (try ${d.attempt} of ${d.max})` : d.error
}

// The status line while a dialog waits but its pane isn't drawn (a narrow
// terminal; the person closed it): how to bring it back.
export function waitingLine(d: DialogView): string {
  return `${who(d)}: the gateway dialog is waiting; /gate-dialog shows it`
}

// A short fixed line for a dialog that ended (a toast): never a value.
export function resultText(r: Recent): string | undefined {
  const w = who(r)
  if (r.what === OFFER_WHAT && r.outcome === 'ok') return `vault passphrase: ${r.note || 'answered'}`
  switch (r.outcome) {
    case 'ok':
      if (r.what === SIGNIN_WHAT) return `${w}: opened in your browser`
      return r.what === 'consent' ? `approved: ${r.entry}` : `${w}: supplied`
    case 'cancelled':
      return `${w}: cancelled`
    case 'timeout':
      return `${w}: nobody answered in time`
    case 'paused':
      return `${w}: not used (the task is paused)`
    case 'failed':
      return `${w}: didn't work${r.note ? ` (${r.note})` : ''}`
    default:
      return undefined
  }
}

// The Client's props for a dialog: what it needs to seal (id, attempt, the
// public key) and draw (how many fields, their labels), plus the reset epoch
// and the last acknowledged post.
export function fieldProps(d: DialogView, epoch: number, ack: number): Record<string, unknown> {
  return { id: d.id, attempt: d.attempt, pub: d.pub, fields: Math.max(1, Math.min(2, d.fields || 1)), labels: fieldLabels(d), epoch, ack }
}

// What a Client post holds that the hooks module forwards: sealed items only.
export type Submit = { seq: number; id: string; attempt: number; epk: string; nonce: string; box: string }

export function parsePost(data: unknown): { seq: number; items: Submit[] } | undefined {
  if (typeof data !== 'object' || data === null) return undefined
  const o = data as Record<string, unknown>
  if (typeof o.seq !== 'number' || !Array.isArray(o.items)) return undefined
  const items: Submit[] = []
  for (const it of o.items) {
    if (typeof it !== 'object' || it === null) continue
    const x = it as Record<string, unknown>
    if (x.t !== 'submit' || typeof x.seq !== 'number' || typeof x.attempt !== 'number') continue
    const id = typeof x.id === 'string' ? x.id : ''
    const b64 = (k: string, max: number): string => (typeof x[k] === 'string' && /^[A-Za-z0-9+/=]+$/.test(x[k] as string) && (x[k] as string).length <= max ? (x[k] as string) : '')
    const epk = b64('epk', 64)
    const nonce = b64('nonce', 64)
    const box = b64('box', 40000)
    if (!ID.test(id) || !epk || !nonce || !box) continue
    items.push({ seq: x.seq, id, attempt: x.attempt, epk, nonce, box })
  }
  return { seq: o.seq, items }
}
