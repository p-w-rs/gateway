// `claude plugin test plugins/gateway`: the gateway dialog (PLAN-v4 phase 3)
// against the engine's test kit. The test's hooks stand beneath the plugin and
// play the engine and gated: launch.sh answers, and /ui/dialog/* over the
// socket. The test plays gated with its own X25519 key pair, so it can open
// what the Client sealed and check that nothing else carries the value.
import { expect, mock, test } from 'claude-code/testing'
import { b64encode, keyPairForTest, openForTest, plaintext, seal } from './seal.ts'
import { FULLSCREEN_HINT, GUARD_CLOSED_TEXT, GUARD_DROP_TEXT, GUARD_MAIN_TEXT, GUARD_NODISPLAY_TEXT, GUARD_TEXT, MAIN_KEYS, MAIN_SCREEN, NO_DISPLAY_MAIN, NO_DISPLAY_PASTE, NOT_RECEIVED, OFFER_LINES, OFFER_OPTIONS, OFFER_TITLE, OFFER_WHAT, PASTE_NOTE, SIGNIN_ENV, SIGNIN_NOTE, SIGNIN_UNREADABLE, SIGNIN_WHAT, UNAVAILABLE_SURFACE, guardEdit, guardPasses, guardSubmitPasses, parseNext, parsePost, queueLine, resultText } from './dialog.ts'
import { printable } from './field.tsx'

const HOME = '/Users/tester'
const CONFIG = `${HOME}/.claude`
const SOCKET = '/tmp/gw-501/gated.sock'
const ID = 'd_0123456789abcdef'
const ID2 = 'd_fedcba9876543210'

const statusJson = (): string => JSON.stringify({
  state: 'ready', root: '/plugin', data: `${CONFIG}/plugins/data/gate-inline`,
  env: `${CONFIG}/plugins/data/gate-inline/envs/0123456789ab`, lock: '0123456789ab', warm: true, older: '',
  build_running: false, install_log: false, pixi: `${HOME}/.pixi/bin/pixi`, pixi_version: 'pixi 0.81.0',
  home: `${HOME}/.config/gateway`, form: true, vault: true, managed: true,
}) + '\n'

const daemonJson = (extra: Record<string, unknown> = {}): string => JSON.stringify({
  ok: true, version: '0.7.0', protocol: 1, pid: 777, epoch: 3, started: 1792450000, uptime: 5,
  vault: 'unwrapped', sessions: 1, socket: SOCKET, lock_after: 28800, parent_pid: 4242, ...extra,
}) + '\n'

type Dialog = Record<string, unknown>

function secretDialog(pub: Uint8Array, extra: Dialog = {}): Dialog {
  return {
    id: ID, kind: 'secret', title: 'Gateway: sudo password for build', entry: 'build', what: 'sudo password',
    target: 'me@build:22', lines: ['The gateway needs the sudo password for build (me@build:22).', 'Claude never sees what you type here.'],
    options: [], checked: [], default: '', ok_label: 'Save', cancel_label: 'Cancel', default_cancel: false,
    fields: 1, remember: null, paste: true, input: false, attempt: 1, max: 3, error: '', state: 'open',
    expires_in: 1700, pub: b64encode(pub), ...extra,
  }
}

// The engine and gated beneath the plugin. `views` are what /ui/dialog/next
// answers in turn; after the last one the long poll never answers (gated
// waiting for a change), so the plugin's loop parks.
// opts.env: Claude Code's environment beyond HOME, CLAUDE_CONFIG_DIR and
// DISPLAY=:0 (undefined unsets one); opts.paste: gated's answer to a paste.
function world(on: any, views: Record<string, unknown>[], gated: string = daemonJson(),
  submit?: (body: any) => Record<string, unknown>, placed = true,
  opts: { env?: Record<string, string | undefined>; paste?: (body: any) => Record<string, unknown> } = {}) {
  const fetches: { url: string; body: any }[] = []
  const statuses: (string | undefined)[] = []
  const opened: any[] = []
  const toasts: string[] = []
  mock.env(on, { HOME, CLAUDE_CONFIG_DIR: CONFIG, DISPLAY: ':0', ...(opts.env ?? {}) })
  const clock = mock.clock(on, { now: 1_000_000 })
  on('session.start', (_$: any, e: any) => ({ cwd: e.cwd }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.surfaces', () => ({ value: ['terminal'] }))
  on('command.register', (_$: any, e: any) => ({ value: { command: e.name } }))
  on('ui.status', (_$: any, e: any) => { statuses.push(e.text); return { value: undefined } })
  on('ui.toast', (_$: any, e: any) => { toasts.push(e.text); return { value: undefined } })
  on('ui.open', (_$: any, e: any) => { opened.push(e); return { value: { isPlaced: placed } } })
  on('ui.close', () => ({ value: undefined }))
  on('prompt.edit', (_$: any, e: any) => ({ text: e.text.slice(0, e.start) + e.inputText + e.text.slice(e.end), cursor: e.start + e.inputText.length }))
  // the prompt box as the engine holds it (a test sets box.text), and what the plugin refilled it with
  const box = { text: '' }
  const fills: string[] = []
  const submitted: string[] = []
  on('prompt.read', () => ({ value: { text: box.text, cursor: box.text.length } }))
  on('prompt.fill', (_$: any, e: any) => { fills.push(e.text); box.text = e.text; return { isFilled: true, text: e.text, cursor: e.text.length } })
  on('prompt.submit', (_$: any, e: any) => { submitted.push(e.text); return { text: e.text } })
  on('process.run', (_$: any, e: any) => ({ value: { exitCode: 0, stdout: e.argv[2] === 'gated' ? gated : statusJson(), stderr: '' } }))
  on('session.version', () => ({ value: { version: '2.1.301', base: '2.1.301', builtAt: '2026-10-15T12:58:20Z' } }))
  const queue = [...views]
  // after the scripted views, a long poll waits until the test pushes a change
  const waiting: ((v: Record<string, unknown>) => void)[] = []
  const push = (v: Record<string, unknown>) => {
    const r = waiting.shift()
    if (r !== undefined) r(v)
    else queue.push(v)
  }
  on('http.fetch', (_$: any, e: any) => {
    const body = typeof e.init?.body === 'string' ? JSON.parse(e.init.body) : undefined
    fetches.push({ url: e.url, body })
    if (String(e.url).includes('/ui/dialog/next')) {
      const v = queue.shift()
      const answer = (x: Record<string, unknown>) => ({ value: { status: 200, ok: true, headers: {}, text: JSON.stringify(x) } })
      if (v === undefined) return new Promise((resolve) => waiting.push((x) => resolve(answer(x))))
      return answer(v)
    }
    if (opts.paste !== undefined && String(e.url).includes('/ui/dialog/paste')) {
      return { value: { status: 200, ok: true, headers: {}, text: JSON.stringify(opts.paste(body)) } }
    }
    if (submit !== undefined && String(e.url).includes('/ui/dialog/submit')) {
      const r = submit(body)
      return { value: { status: r.ok === true ? 200 : 400, ok: r.ok === true, headers: {}, text: JSON.stringify(r) } }
    }
    if (String(e.url).includes('/ui/vault/unlock')) {
      return { value: { status: 200, ok: true, headers: {}, text: JSON.stringify({ ok: true, available: true, id: ID }) } }
    }
    if (String(e.url).includes('/ui/vault/lock')) {
      return { value: { status: 200, ok: true, headers: {}, text: JSON.stringify({ ok: true, locked: true, message: 'gateway: the vault is locked' }) } }
    }
    return { value: { status: 200, ok: true, headers: {}, text: '{"ok": true, "state": "checking"}' } }
  })
  return { fetches, statuses, opened, toasts, clock, push, box, fills, submitted }
}

// the dialog loop applies gated's answer a few turns after session.start
async function settle(): Promise<void> {
  for (let i = 0; i < 50; i++) await Promise.resolve()
}

const start = async ($: any, surface: string | null = 'terminal', isInteractive = true) => {
  const r = await $.session.start({ cwd: '/work', surface, isInteractive })
  await settle()
  return r
}

const view = (dialog: Dialog | null, extra: Record<string, unknown> = {}) =>
  ({ ok: true, rev: 2, dialog, queue: [], recent: [], available: true, ...extra })

const PANE_PROPS = { title: 'Gateway', isFocused: true, bodyColumns: 100, placement: 'inline', scroll: { offset: 0, bodyRows: 12 }, view: {} }

const mount = ($: any, surface = 'terminal', props: Record<string, unknown> = {}) =>
  $.ui.mount({ plugin: 'gate', surface, component: 'Pane', requestId: 'gate-dialog', props: { ...PANE_PROPS, ...props } })

const FIELD = `field-${ID}-1-0`

async function type(ui: any, text: string, field = FIELD) {
  for (const ch of text) await ui.key({ key: ch, in: field })
}

function sealedInto(fetches: { url: string; body: any }[]): any[] {
  return fetches.filter((f) => f.url.endsWith('/ui/dialog/submit')).map((f) => f.body)
}

test('seal: TweetNaCl box under a fresh ephemeral key opens only with the dialog key', async () => {
  const kp = keyPairForTest()
  const a = seal(b64encode(kp.publicKey), plaintext(ID, 1, ['hunter2-not-real']))
  const b = seal(b64encode(kp.publicKey), plaintext(ID, 1, ['hunter2-not-real']))
  expect(a.epk).not.toBe(b.epk)                    // a new ephemeral key each time (the PRNG works)
  expect(a.nonce).not.toBe(b.nonce)
  const opened = openForTest(a, kp.secretKey)
  expect(opened).not.toBe(null)
  expect(JSON.parse(new TextDecoder().decode(opened!))).toEqual({ rid: ID, a: 1, v: ['hunter2-not-real'] })
  const other = keyPairForTest()
  expect(openForTest(a, other.secretKey)).toBe(null)
  const plain = plaintext(ID, 1, ['x'])
  seal(b64encode(kp.publicKey), plain)
  expect([...plain].every((x) => x === 0)).toBe(true)  // the plaintext bytes are overwritten
})

test('the field takes printable keys only', () => {
  expect(printable({ key: 'a' })).toBe(true)
  expect(printable({ key: 'Z', shift: true })).toBe(true)
  expect(printable({ key: 'é' })).toBe(true)
  expect(printable({ key: '😀' })).toBe(true)
  for (const k of [{ key: 'return' }, { key: 'tab' }, { key: 'up' }, { key: 'x', meta: true as const }, { key: 'c', ctrl: true as const }, { key: '\u001bOP' }, { key: '\u0007' }, { key: 'ab' }]) {
    expect(printable(k as any)).toBe(false)
  }
})

test('a typed secret leaves the Client only sealed, and the box opens to exactly what was typed', async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))])
  let testSawMessage = false
  on('ui.message', ($$: any, e: any, next: any) => { testSawMessage = true; return next(e) })
  await start($)
  expect(w.opened.at(-1)).toMatchObject({ id: 'gate-dialog', focus: true })
  const ui = await mount($)
  const typed = 'sudo-pw-1234-not-real'
  await type(ui, typed)
  // only bullets are drawn
  const drawn = JSON.stringify(await ui.drawn({ in: FIELD }))
  expect(drawn).toContain('•'.repeat(typed.length))
  expect(drawn).not.toContain(typed)
  await ui.key({ key: 'return', in: FIELD })
  const sent = sealedInto(w.fetches)
  expect(sent.length).toBe(1)
  expect(Object.keys(sent[0]).sort()).toEqual(['attempt', 'box', 'epk', 'id', 'nonce'])
  expect(sent[0].id).toBe(ID)
  // nothing the plugin sent anywhere holds the value, in any plain form
  const all = JSON.stringify(w.fetches)
  for (const form of [typed, b64encode(new TextEncoder().encode(typed)), [...new TextEncoder().encode(typed)].map((x) => x.toString(16).padStart(2, '0')).join('')]) {
    expect(all.includes(form)).toBe(false)
  }
  const opened = openForTest({ epk: sent[0].epk, nonce: sent[0].nonce, box: sent[0].box }, kp.secretKey)
  expect(JSON.parse(new TextDecoder().decode(opened!))).toEqual({ rid: ID, a: 1, v: [typed] })
  expect(testSawMessage).toBe(false)               // ui.message reaches only the drawing plugin
  // the field shows it was sent, and nothing typed is left
  expect(JSON.stringify(await ui.drawn({ in: FIELD }))).toContain('checking')
})

test('backspace, Ctrl-U and a second field; two passphrases must match before anything is sealed', async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey, { kind: 'passphrase', fields: 2, paste: false, entry: 'vault', what: 'new vault passphrase' }))])
  await start($)
  const ui = await mount($)
  await type(ui, 'abcX')
  await ui.key({ key: 'backspace', in: FIELD })
  await ui.key({ key: 'return', in: FIELD })      // to the second field
  await type(ui, 'zzz')
  await ui.key({ key: 'u', ctrl: true, in: FIELD })
  await type(ui, 'abd')
  await ui.key({ key: 'return', in: FIELD })      // abc != abd: nothing sealed, both cleared
  expect(sealedInto(w.fetches).length).toBe(0)
  expect(JSON.stringify(await ui.drawn({ in: FIELD }))).toContain('differ')
  await type(ui, 'same-pass')
  await ui.key({ key: 'tab', in: FIELD })
  await type(ui, 'same-pass')
  await ui.key({ key: 'return', in: FIELD })
  const sent = sealedInto(w.fetches)
  expect(sent.length).toBe(1)
  const opened = openForTest(sent[0], kp.secretKey)
  expect(JSON.parse(new TextDecoder().decode(opened!)).v).toEqual(['same-pass', 'same-pass'])
  // no paste button for a new passphrase (type it twice)
  expect(await ui.find({ key: 'paste' })).toBe(undefined)
})

test('a post is forwarded once per sequence number, so re-sent outboxes lose and repeat nothing', async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  const ui = await mount($)
  const one = { seq: 1, t: 'submit', id: ID, attempt: 1, ...seal(b64encode(kp.publicKey), plaintext(ID, 1, ['a'])) }
  const two = { seq: 2, t: 'submit', id: ID, attempt: 1, ...seal(b64encode(kp.publicKey), plaintext(ID, 1, ['b'])) }
  await ui.post({ seq: 1, items: [one] }, { in: FIELD })
  await ui.post({ seq: 2, items: [one, two] }, { in: FIELD })     // a coalesced re-send with both
  await ui.post({ seq: 2, items: [one, two] }, { in: FIELD })
  const sent = sealedInto(w.fetches)
  expect(sent.length).toBe(2)
  expect(sent.map((b) => b.box)).toEqual([one.box, two.box])
  // anything but sealed items is dropped
  await ui.post({ seq: 3, items: [{ seq: 3, t: 'submit', id: ID, attempt: 1, value: 'plain' }] }, { in: FIELD })
  expect(sealedInto(w.fetches).length).toBe(2)
  expect(parsePost({ seq: 1, items: [{ seq: 1, t: 'submit', id: ID, attempt: 1, value: 'x' }] })!.items).toEqual([])
})

test('a retry (the next attempt, a new field) is forwarded too: its posts start over at 1', async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  const ui = await mount($)
  await type(ui, 'first-try-wrong')
  await ui.key({ key: 'return', in: FIELD })
  const kp2 = keyPairForTest()
  w.push(view(secretDialog(kp2.publicKey, { attempt: 2, error: "That didn't work: no" }), { rev: 3 }))
  await settle()
  await ui.redraw()
  const f2 = `field-${ID}-2-0`
  expect(JSON.stringify(await ui.drawn())).toContain("That didn't work: no (try 2 of 3)")
  await type(ui, 'second-try-right', f2)
  await ui.key({ key: 'return', in: f2 })
  const sent = sealedInto(w.fetches)
  expect(sent.map((b) => b.attempt)).toEqual([1, 2])
  const opened = openForTest(sent[1], kp2.secretKey)
  expect(JSON.parse(new TextDecoder().decode(opened!)).v).toEqual(['second-try-right'])
})

test('gated restarted (the same dialog, a new key pair): a new field, and what is typed is sealed to the new key', async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  const ui = await mount($)
  await type(ui, 'typed-before-the-kill')
  const kp2 = keyPairForTest()
  w.push(view(secretDialog(kp2.publicKey), { rev: 1 }))          // a new gated counts from 1 again
  await settle()
  await ui.redraw()
  expect(await ui.find({ key: FIELD })).toBe(undefined)
  const f2 = `field-${ID}-1-1`
  expect(JSON.stringify(await ui.drawn({ in: f2 }))).not.toContain('•')
  await type(ui, 'after-restart', f2)
  await ui.key({ key: 'return', in: f2 })
  const sent = sealedInto(w.fetches)
  expect(sent.length).toBe(1)
  expect(openForTest(sent[0], kp.secretKey)).toBe(null)               // not to the old key
  expect(JSON.parse(new TextDecoder().decode(openForTest(sent[0], kp2.secretKey)!)).v).toEqual(['after-restart'])
})

test("a box gated can't open (the dialog changed meanwhile) starts the field over and says to type again", async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))], daemonJson(),
    () => ({ ok: false, error: 'box', message: "gateway: the sealed value couldn't be opened" }))
  await start($)
  const ui = await mount($)
  await type(ui, 'sealed-to-a-gone-key')
  await ui.key({ key: 'return', in: FIELD })
  await settle()
  await ui.redraw()
  expect(await ui.find({ key: FIELD })).toBe(undefined)
  expect(await ui.find({ key: `field-${ID}-1-1` })).not.toBe(undefined)
  expect(w.statuses).toContain(NOT_RECEIVED)
})

test('Paste from clipboard asks gated (the value never comes through the mod), with the display variables', async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  const ui = await mount($)
  await ui.press({ key: 'paste' })
  const p = w.fetches.filter((f) => f.url.endsWith('/ui/dialog/paste'))
  expect(p.length).toBe(1)
  expect(p[0]!.body).toEqual({ id: ID, env: { DISPLAY: ':0' } })
  // gated took the value and never clears the clipboard: the person is told (GW-UX-6)
  expect(w.toasts).toContain(PASTE_NOTE)
  await ui.press({ key: 'cancel' })
  expect(w.fetches.filter((f) => f.url.endsWith('/ui/dialog/cancel')).map((f) => f.body)).toEqual([{ id: ID }])
})

test('the clipboard note shows after a pasted value failed its recheck too, never when the clipboard could not be read (review round 2)', async ($: any, on: any) => {
  const kp = keyPairForTest()
  const answers: Record<string, unknown>[] = [
    { ok: false, error: 'session_gone', state: 'done', message: "gateway: the session that asked isn't running any more" },
    { ok: false, error: 'clipboard', message: 'gateway: the clipboard is empty' },
  ]
  const w = world(on, [view(secretDialog(kp.publicKey))], daemonJson(), undefined, true, { paste: () => answers.shift()! })
  await start($)
  const ui = await mount($)
  await ui.press({ key: 'paste' })
  await settle()
  // gated read the value (it failed the recheck): it is still on the clipboard
  expect(w.toasts.filter((t) => t === PASTE_NOTE).length).toBe(1)
  await ui.press({ key: 'paste' })
  await settle()
  // nothing could be read: no note
  expect(w.toasts.filter((t) => t === PASTE_NOTE).length).toBe(1)
  expect(w.fetches.filter((f) => f.url.endsWith('/ui/dialog/paste')).length).toBe(2)
})

test('the remember choice goes with the sealed value', async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey, { remember: true }))])
  await start($)
  const ui = await mount($)
  expect(JSON.stringify(await ui.find({ key: 'remember' }))).toContain('[x] Remember it')
  await ui.press({ key: 'remember' })
  await type(ui, 'once-only')
  await ui.key({ key: 'return', in: FIELD })
  expect(sealedInto(w.fetches)[0].remember).toBe(false)
})

test('the guard holds back composer typing while a secret dialog is on screen, and only then', async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  const edit = { origin: { kind: 'composer' }, text: 'hi', cursor: 2, start: 2, end: 2, inputText: 'p' }
  const held = await $.prompt.edit(edit)
  expect(held).toMatchObject({ text: 'hi', cursor: 2 })
  expect(w.statuses).toContain(GUARD_TEXT)
})

test('no guard without a secret dialog', async ($: any, on: any) => {
  world(on, [view({ ...secretDialog(new Uint8Array(32)), kind: 'confirm', pub: '' })])
  await start($)
  const edit = { origin: { kind: 'composer' }, text: 'hi', cursor: 2, start: 2, end: 2, inputText: 'p' }
  const r = await $.prompt.edit(edit)
  expect(r.text).toBe('hip')
})

test('a consent dialog has Approve and Decline, Decline focused first; a choice has its options', async ($: any, on: any) => {
  const consent = { ...secretDialog(new Uint8Array(32)), kind: 'confirm', pub: '', ok_label: 'Approve', cancel_label: 'Decline', default_cancel: true, lines: ['Claude asks for more rights for build:', '  - ssh: true'] }
  const w = world(on, [view(consent)])
  await start($)
  const ui = await mount($)
  expect((await ui.find({ key: 'ok' }))?.text).toBe('Approve')
  const dec = await ui.find({ key: 'cancel' })
  expect(dec?.text).toBe('Decline')
  expect(JSON.stringify(dec)).toContain('autoFocus')
  expect(await ui.find({ key: FIELD })).toBe(undefined)            // no field for a consent
  await ui.press({ key: 'ok' })
  expect(w.fetches.filter((f) => f.url.endsWith('/ui/dialog/answer')).map((f) => f.body)).toEqual([{ id: ID, button: 'ok' }])
})

const MAIN_VIEWPORT = { columns: 120, rows: 40, isFullscreen: false }
const edit = (text: string, inputText: string) => ({ origin: { kind: 'composer' }, text, cursor: text.length, start: text.length, end: text.length, inputText })

test("on the terminal's main screen (no fullscreen: no clicks) the field isn't drawn, Paste is, and typing is still held back", async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  const ui = await $.ui.mount({ plugin: 'gate', surface: 'terminal', component: 'Pane', requestId: 'gate-dialog',
                                props: PANE_PROPS, viewport: MAIN_VIEWPORT })
  const t = JSON.stringify(await ui.drawn())
  expect(t).toContain('/tui fullscreen')
  expect(t).not.toContain('field.tsx')
  expect(await ui.find({ key: 'paste' })).not.toBe(undefined)
  // the reflex at a password prompt: typing it into the prompt box. Held back
  // (it would reach every plugin's prompt hooks and, on Enter, the model)
  const held = await $.prompt.edit(edit('', 'p'))
  expect(held).toMatchObject({ text: '', cursor: 0 })
  const burst = await $.prompt.edit(edit('', 'pw-typed-at-the-prompt'))      // a paste or a burst of keys
  expect(burst.text).toBe('')
  expect(w.statuses).toContain(GUARD_MAIN_TEXT)
  expect(GUARD_MAIN_TEXT).toContain('Paste from clipboard')
  expect(GUARD_MAIN_TEXT).toContain('/tui fullscreen')
  // Claude Code's own command (it restarts and resumes the session), never a
  // quit-and-restart with an environment variable
  for (const x of [GUARD_MAIN_TEXT, FULLSCREEN_HINT, MAIN_SCREEN]) {
    expect(x).toContain('restarts and resumes')
    expect(x).not.toContain('NO_FLICKER=1')
    expect(x).not.toContain('quit Claude Code')
  }
  // GW-UX-6: the pane says plainly that this terminal can't type into the
  // field, that Paste leaves the value on the clipboard, and how to get the
  // fullscreen view; one keyboard route everywhere
  expect(t).toContain("This terminal can't type into the gateway's field")
  expect(t).toContain(MAIN_KEYS)
  expect(t).toContain('clear it yourself')
  expect(t).toContain(FULLSCREEN_HINT)
  for (const x of [MAIN_SCREEN, GUARD_MAIN_TEXT]) {
    expect(x).toContain(MAIN_KEYS)
    expect(x).not.toContain('ctrl+x')
  }
  expect(MAIN_SCREEN).toContain(PASTE_NOTE)
  // the gateway's own commands pass, so /gate-dialog can still be typed
  expect((await $.prompt.edit(edit('', '/'))).text).toBe('/')
  expect((await $.prompt.edit(edit('/gate-d', 'ialog'))).text).toBe('/gate-dialog')
  expect((await $.prompt.edit(edit('', '/gate-dialog'))).text).toBe('/gate-dialog')
  // other text starting with a slash doesn't (a secret may start with one)
  expect((await $.prompt.edit(edit('', '/hunter2-not-real'))).text).toBe('')
  expect((await $.prompt.edit(edit('/gate-dialog', 'x'))).text).toBe('/gate-dialog')
})

test('on Linux without a display the main screen says neither typing nor Paste works, and what to do (review round 2)', async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))], daemonJson({ platform: 'linux' }), undefined, true,
                  { env: { DISPLAY: undefined } })
  await start($)
  const ui = await $.ui.mount({ plugin: 'gate', surface: 'terminal', component: 'Pane', requestId: 'gate-dialog',
                                props: PANE_PROPS, viewport: MAIN_VIEWPORT })
  const t = JSON.stringify(await ui.drawn())
  expect(t).toContain('Neither typing nor Paste can work in this terminal')
  expect(t).toContain('no DISPLAY or WAYLAND_DISPLAY')
  expect(t).toContain('/tui fullscreen')
  expect(t).toContain("this machine's desktop")
  expect(t).not.toContain("This terminal can't type into the gateway's field")     // MAIN_SCREEN's Paste advice
  expect(NO_DISPLAY_MAIN).toContain("Don't type it into the prompt")
  expect(await ui.find({ key: 'cancel' })).not.toBe(undefined)
  // the guard says it too
  expect((await $.prompt.edit(edit('', 'p'))).text).toBe('')
  expect(w.statuses).toContain(GUARD_NODISPLAY_TEXT)
  expect(w.statuses).not.toContain(GUARD_MAIN_TEXT)
})

test('on Linux without a display the fullscreen field takes keys and Paste is said not to work; with a display (or on macOS) nothing changes', async ($: any, on: any) => {
  const kp = keyPairForTest()
  world(on, [view(secretDialog(kp.publicKey))], daemonJson({ platform: 'linux' }), undefined, true,
        { env: { DISPLAY: undefined, WAYLAND_DISPLAY: undefined } })
  await start($)
  const ui = await mount($)
  const t = JSON.stringify(await ui.drawn())
  expect(t).toContain('field.tsx')
  expect(t).toContain(NO_DISPLAY_PASTE)
})

for (const [platform, env] of [['linux', { WAYLAND_DISPLAY: 'wayland-0', DISPLAY: undefined }], ['darwin', { DISPLAY: undefined }]] as const) {
  test(`${platform} with ${JSON.stringify(env)}: the main screen offers Paste as before`, async ($: any, on: any) => {
    const kp = keyPairForTest()
    world(on, [view(secretDialog(kp.publicKey))], daemonJson({ platform }), undefined, true, { env })
    await start($)
    const ui = await $.ui.mount({ plugin: 'gate', surface: 'terminal', component: 'Pane', requestId: 'gate-dialog',
                                  props: PANE_PROPS, viewport: MAIN_VIEWPORT })
    const t = JSON.stringify(await ui.drawn())
    expect(t).toContain("This terminal can't type into the gateway's field")
    expect(t).not.toContain('Neither typing nor Paste')
    expect(t).not.toContain(NO_DISPLAY_PASTE)
  })
}

test("a pane that isn't placed (too narrow, or closed by the person) keeps the guard: typing is held back and /gate-dialog passes", async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))], daemonJson(), undefined, false)
  await start($)
  expect(w.statuses.some((t) => typeof t === 'string' && t.includes('/gate-dialog shows it'))).toBe(true)
  const held = await $.prompt.edit(edit('', 's'))
  expect(held.text).toBe('')
  expect(w.statuses).toContain(GUARD_CLOSED_TEXT)
  expect((await $.prompt.edit(edit('', '/gate-dialog'))).text).toBe('/gate-dialog')
})

// what the editor hands the hook: the draft (maybe holding keys it painted
// before the last refusal came back), the splice, the cursor after the draft
const splice = (text: string, inputText: string, start = text.length, end = start) =>
  ({ origin: { kind: 'composer' }, text, cursor: text.length, start, end, inputText })

test('guardEdit: the box goes back to what the guard let it hold, never to a draft holding keys painted meanwhile', () => {
  // first edit: the draft from before the dialog is the person's own
  expect(guardEdit(splice('', 'a'), undefined)).toEqual({ pass: false, text: '', cursor: 0 })
  expect(guardEdit(splice('fix the bug', 'x'), undefined)).toEqual({ pass: false, text: 'fix the bug', cursor: 11 })
  // the race seen on 2.1.304: the next edit came with a draft holding characters
  // whose refusal hadn't arrived; the old guard answered with that draft and they stayed
  expect(guardEdit(splice('3Dp', 'q'), '')).toEqual({ pass: false, text: '', cursor: 0 })
  expect(guardEdit(splice('fix the bug3Dp', 'q'), 'fix the bug')).toEqual({ pass: false, text: 'fix the bug', cursor: 11 })
  expect(guardEdit(splice('fix3D the bug', 'q', 5), 'fix the bug').text).toBe('fix the bug')
  // even a deletion made to such a draft goes back (what is left could be typed text)
  expect(guardEdit(splice('3Dp', '', 2, 3), '').text).toBe('')
  // a deletion or a cursor move made to the trusted text passes (the draft can be cleared)
  expect(guardEdit(splice('fix the bug', '', 10, 11), 'fix the bug')).toEqual({ pass: true, text: 'fix the bu', cursor: 10 })
  expect(guardEdit({ ...splice('fix the bug', '', 3, 3), cursor: 11 }, 'fix the bug')).toEqual({ pass: true, text: 'fix the bug', cursor: 3 })
  // the gateway's commands and an emptied box pass from any trusted draft
  expect(guardEdit(splice('', '/gate-dialog'), '')).toMatchObject({ pass: true, text: '/gate-dialog' })
  expect(guardEdit(splice('/gate-d', 'ialog'), '')).toMatchObject({ pass: true, text: '/gate-dialog' })
  expect(guardEdit(splice('fix the bug', '', 0, 11), 'fix the bug')).toMatchObject({ pass: true, text: '' })
  // a slash command can't carry painted keys in: '3D/' isn't a gateway command
  expect(guardEdit(splice('3D', '/'), '')).toEqual({ pass: false, text: '', cursor: 0 })
})

test('a submitted prompt passes the guard only as the guard let the box hold it', () => {
  expect(guardSubmitPasses('anything', undefined)).toBe(true)          // nothing typed while the dialog waited
  expect(guardSubmitPasses('fix the bug', 'fix the bug')).toBe(true)   // the draft from before the dialog
  expect(guardSubmitPasses('', 'fix the bug')).toBe(true)
  expect(guardSubmitPasses('/gate-dialog', '')).toBe(true)
  expect(guardSubmitPasses('t', '')).toBe(false)                       // a stray character of a secret
  expect(guardSubmitPasses('fix the bug3Dp', 'fix the bug')).toBe(false)
})

test('keys the editor painted before a refusal came back never stay: each refusal answers the guarded box', async ($: any, on: any) => {
  const kp = keyPairForTest()
  world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  // typed fast: each edit after the first comes with the draft the editor painted
  expect((await $.prompt.edit(splice('', 'h'))).text).toBe('')
  expect((await $.prompt.edit(splice('h', 'u'))).text).toBe('')
  expect((await $.prompt.edit(splice('hu', 'n'))).text).toBe('')
  // a burst of keys folded into one edit, then a key on top of its painted draft
  expect((await $.prompt.edit(splice('', 'ter2-not'))).text).toBe('')
  const r = await $.prompt.edit(splice('ter2-not', '-'))
  expect(r).toMatchObject({ text: '', cursor: 0 })
  // the gateway's command still goes in from the guarded (empty) box
  expect((await $.prompt.edit(splice('', '/gate-dialog'))).text).toBe('/gate-dialog')
})

test("a draft from before the dialog stays, keys painted onto it don't, and it can be deleted", async ($: any, on: any) => {
  const kp = keyPairForTest()
  world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  expect((await $.prompt.edit(splice('run the tests', 'p'))).text).toBe('run the tests')
  expect((await $.prompt.edit(splice('run the testsp', 'w'))).text).toBe('run the tests')
  expect((await $.prompt.edit(splice('run the tests', '', 12, 13))).text).toBe('run the test')
  expect((await $.prompt.edit(splice('run the tests', 'x'))).text).toBe('run the test')    // a stale draft: the guarded one
})

test("the guard's status line stays until 4 s after the last held-back key, not the first", async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  await $.prompt.edit(splice('', 'a'))
  await w.clock.advance(3000)
  await $.prompt.edit(splice('', 'b'))
  await w.clock.advance(1500)                       // 4.5 s after the first key, 1.5 s after the last
  expect(w.statuses[w.statuses.length - 1]).toBe(GUARD_TEXT)
  await w.clock.advance(3000)
  expect(w.statuses[w.statuses.length - 1]).toBe(undefined)
})

test('characters that reached the box without an edit the guard answered are taken out after the typing stops', async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  await $.prompt.edit(splice('', 'h'))
  w.box.text = 'unt'                                 // what the editor shows: keys it applied on its own
  await w.clock.advance(400)
  await settle()
  expect(w.fills).toEqual([''])
  expect(w.box.text).toBe('')
  // a box that holds only what the guard allowed is left alone
  await $.prompt.edit(splice('', '/gate-d'))
  await $.prompt.edit(splice('/gate-d', 'x'))
  w.box.text = '/gate-d'
  await w.clock.advance(400)
  await settle()
  expect(w.fills).toEqual([''])
})

test("no box check, no refill and no dropped prompt without a secret dialog", async ($: any, on: any) => {
  const w = world(on, [view({ ...secretDialog(new Uint8Array(32)), kind: 'confirm', pub: '' })])
  await start($)
  w.box.text = 'hello'
  expect((await $.prompt.edit(splice('hell', 'o'))).text).toBe('hello')
  await w.clock.advance(1000)
  await settle()
  expect(w.fills).toEqual([])
  const r = await $.prompt.submit({ text: 'hello', origin: { kind: 'composer' }, wait: false })
  expect(r.drop).toBe(undefined)
  expect(w.submitted).toEqual(['hello'])
})

test('a prompt submitted while a secret dialog waits is dropped unless the guard let the box hold it', async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  await $.prompt.edit(splice('', 't'))               // held back: the guarded box is ''
  const dropped = await $.prompt.submit({ text: 't', origin: { kind: 'composer' }, wait: false })
  expect(dropped.drop).toBe(GUARD_DROP_TEXT)
  expect(w.submitted).toEqual([])
  // a slash command (/gate-dialog) and what the box was allowed to hold go
  await $.prompt.submit({ text: '/gate-dialog', origin: { kind: 'composer' }, wait: false, command: { name: 'gate-dialog', args: '' } })
  await $.prompt.edit(splice('', '/gate-dialog'))
  const ok = await $.prompt.submit({ text: '/gate-dialog', origin: { kind: 'composer' }, wait: false })
  expect(ok.drop).toBe(undefined)
  // another plugin's or a notification's prompt isn't the person's typing
  const other = await $.prompt.submit({ text: 'from a plugin', origin: { kind: 'plugin', name: 'other' }, wait: false })
  expect(other.drop).toBe(undefined)
})

test('the guard passes only the gateway commands being typed, or an emptied box', () => {
  for (const t of ['', '/', '/g', '/gate-', '/gate-dialog', '/gate-unlock', '/gate-lock', '/gate-doctor']) expect(guardPasses(t)).toBe(true)
  for (const t of ['p', ' /', '/gate-dialogx', '/gate-dialog now', '/hunter2', '//', 'gate-dialog']) expect(guardPasses(t)).toBe(false)
})

test("on the main screen Remember it is offered with Paste and goes with it", async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey, { remember: true }))])
  await start($)
  const ui = await $.ui.mount({ plugin: 'gate', surface: 'terminal', component: 'Pane', requestId: 'gate-dialog',
                                props: PANE_PROPS, viewport: MAIN_VIEWPORT })
  expect(JSON.stringify(await ui.find({ key: 'remember' }))).toContain('[x] Remember it')
  await ui.press({ key: 'remember' })
  expect(JSON.stringify(await ui.find({ key: 'remember' }))).toContain('[ ] Remember it')
  await ui.press({ key: 'paste' })
  const p = w.fetches.filter((f) => f.url.endsWith('/ui/dialog/paste'))
  expect(p.length).toBe(1)
  expect(p[0]!.body.remember).toBe(false)
})

test('the dialogs without a field answer keys (y, n, a digit per option); a secret dialog has none', async ($: any, on: any) => {
  const choice = { ...secretDialog(new Uint8Array(32)), kind: 'choice', pub: '', options: ['First way', 'Second way'] }
  const w = world(on, [view(choice)])
  await start($)
  const ui = await mount($)
  expect(JSON.stringify(await ui.find({ key: 'opt1' }))).toContain('"hotkey":"2"')
  expect(JSON.stringify(await ui.find({ key: 'cancel' }))).toContain('"hotkey":"n"')
  await ui.press({ key: 'opt1' })
  expect(w.fetches.filter((f) => f.url.endsWith('/ui/dialog/answer')).map((f) => f.body)).toEqual([{ id: ID, button: 'ok', choice: 'Second way' }])
})

test('no hotkey on a secret dialog (typed letters must never press a button)', async ($: any, on: any) => {
  const kp = keyPairForTest()
  world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  const ui = await mount($)
  for (const k of ['paste', 'cancel']) expect(JSON.stringify(await ui.find({ key: k }))).not.toContain('hotkey')
})

test('on mobile a secret dialog draws no field and says credential entry is unavailable there', async ($: any, on: any) => {
  const kp = keyPairForTest()
  world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  const ui = await mount($, 'mobile')
  const t = JSON.stringify(await ui.drawn())
  expect(t).toContain(UNAVAILABLE_SURFACE)
  expect(t).not.toContain('field.tsx')
  expect(await ui.find({ key: 'paste' })).toBe(undefined)
})

// PLAN-0.11 §7.1: the browser sign-in's confirm dialog (gated's own, its fields only)
const SIGNIN = { account: 'work-azure', kind: 'azure', tenant: 'contoso.onmicrosoft.com', client: '11111111-1111-1111-1111-111111111111', scope: 'https://management.azure.com/.default offline_access', host: '', previous_client: '' }

function signinDialog(extra: Dialog = {}): Dialog {
  return {
    ...secretDialog(new Uint8Array(32)), kind: 'confirm', pub: '', fields: 0, paste: false,
    title: 'gated title, never shown', entry: 'work-azure', what: SIGNIN_WHAT,
    lines: ['gated words, never shown'], ok_label: 'OK', cancel_label: 'No', default_cancel: false,
    signin: SIGNIN, ...extra,
  }
}

test('a browser sign-in is drawn from the fixed template: the account, tenant, client and scope, with Open and Cancel', () => {
  const d = parseNext(JSON.stringify(view(signinDialog())))!.dialog!
  expect(d.signin).toEqual(SIGNIN)
  expect(d.title).toBe('Sign in to work-azure in your browser')
  expect(d.lines).toEqual([
    'Claude asks to sign in to Azure as you (account work-azure), in your web browser.',
    'Tenant: contoso.onmicrosoft.com', 'Client id: 11111111-1111-1111-1111-111111111111',
    'Scope: https://management.azure.com/.default offline_access', SIGNIN_NOTE])
  expect([d.ok_label, d.cancel_label, d.default_cancel]).toEqual(['Open', 'Cancel', true])
  // a catalog: its host, the client id it gave, and a change from the one pinned before
  const cat = { ...SIGNIN, account: 'models', kind: 'ml-catalog', tenant: 'organizations', host: 'catalog.example.com', previous_client: '22222222-2222-2222-2222-222222222222', scope: 'api://11111111-1111-1111-1111-111111111111/access_as_user offline_access' }
  const c = parseNext(JSON.stringify(view(signinDialog({ signin: cat, entry: 'models' }))))!.dialog!
  expect(c.lines[0]).toBe('Claude asks to sign in to the model catalog catalog.example.com as you (account models), in your web browser.')
  expect(c.lines).toContain('Client id (from the catalog): 11111111-1111-1111-1111-111111111111')
  expect(c.lines).toContain("The catalog's client id changed since the last sign-in (it was 22222222-2222-2222-2222-222222222222).")
  // a field that isn't valid: nothing of it is shown, and the pane says to cancel
  for (const bad of [{ ...SIGNIN, tenant: 'evil tenant' }, { ...SIGNIN, client: 'not-a-guid' }, { ...SIGNIN, scope: 'a‮b' },
    { ...SIGNIN, kind: 'github' }, { ...SIGNIN, host: 'x.example.com' }, { ...cat, host: '' }, 'text']) {
    const b = parseNext(JSON.stringify(view(signinDialog({ signin: bad }))))!.dialog!
    expect(b.signin).toBe(null)
    expect(b.lines).toEqual([SIGNIN_UNREADABLE])
    expect(b.default_cancel).toBe(true)
  }
  // only a confirm carries a sign-in; any other dialog keeps its own words
  const other = parseNext(JSON.stringify(view({ ...secretDialog(new Uint8Array(32)) })))!.dialog!
  expect(other.signin).toBe(null)
  expect(resultText({ id: ID, entry: 'work-azure', what: SIGNIN_WHAT, outcome: 'ok', note: '' })).toBe('browser sign-in for work-azure: opened in your browser')
  expect(resultText({ id: ID, entry: 'work-azure', what: SIGNIN_WHAT, outcome: 'cancelled', note: '' })).toBe('browser sign-in for work-azure: cancelled')
})

test('the sign-in pane focuses Cancel first, and Open sends only the display, desktop and ssh variables', async ($: any, on: any) => {
  const w = world(on, [view(signinDialog())], daemonJson(), undefined, true,
                  { env: { WAYLAND_DISPLAY: 'wayland-0', DBUS_SESSION_BUS_ADDRESS: 'unix:path=/run/user/501/bus', XDG_CURRENT_DESKTOP: 'ubuntu:GNOME', SSH_CONNECTION: '192.0.2.1 50000 192.0.2.2 22', ANTHROPIC_API_KEY: 'sk-not-real-0123456789abcdef' } })
  await start($)
  const ui = await mount($)
  const t = JSON.stringify(await ui.drawn())
  expect(t).toContain('Sign in to work-azure in your browser')
  expect(t).toContain('Scope: https://management.azure.com/.default offline_access')
  expect(t).not.toContain('gated words, never shown')
  expect(await ui.find({ key: FIELD })).toBe(undefined)
  expect((await ui.find({ key: 'ok' }))?.text).toBe('Open')
  const cancel = await ui.find({ key: 'cancel' })
  expect(cancel?.text).toBe('Cancel')
  expect(JSON.stringify(cancel)).toContain('autoFocus')
  await ui.press({ key: 'ok' })
  expect(w.fetches.filter((f) => f.url.endsWith('/ui/dialog/answer')).map((f) => f.body)).toEqual([
    { id: ID, button: 'ok', env: { DISPLAY: ':0', WAYLAND_DISPLAY: 'wayland-0', DBUS_SESSION_BUS_ADDRESS: 'unix:path=/run/user/501/bus', XDG_CURRENT_DESKTOP: 'ubuntu:GNOME', SSH_CONNECTION: '192.0.2.1 50000 192.0.2.2 22' } }])
  expect(SIGNIN_ENV).not.toContain('ANTHROPIC_API_KEY')
})

// PLAN-0.11 §8: the vault passphrase offer (gated's own choice, its marker only)
function offerDialog(extra: Dialog = {}): Dialog {
  return {
    ...secretDialog(new Uint8Array(32)), kind: 'choice', pub: '', fields: 0, paste: false,
    title: 'gated title, never shown', entry: 'vault', what: OFFER_WHAT,
    lines: ['gated words, never shown'], options: ['Set passphrase', 'Not now'], ok_label: 'Continue',
    cancel_label: 'No', default_cancel: true, offer: 'passphrase', ...extra,
  }
}

test('the passphrase offer is drawn from the fixed template: Set passphrase, Not now and Cancel', () => {
  const d = parseNext(JSON.stringify(view(offerDialog())))!.dialog!
  expect(d.title).toBe(OFFER_TITLE)
  expect(d.title).toBe('Protect the vault with a passphrase?')
  expect(d.lines).toEqual([...OFFER_LINES])
  expect(d.lines[0]).toBe('Without one, any program running as you can read the stored secrets.')
  expect(d.options).toEqual(['Set passphrase', 'Not now'])
  expect([d.cancel_label, d.default_cancel]).toEqual(['Cancel', false])
  // gated's own options can't change what the pane offers
  const odd = parseNext(JSON.stringify(view(offerDialog({ options: ['Something else'] }))))!.dialog!
  expect(odd.options).toEqual([...OFFER_OPTIONS])
  // only a choice carries the offer; another kind keeps its own words
  const conf = parseNext(JSON.stringify(view(offerDialog({ kind: 'confirm' }))))!.dialog!
  expect(conf.lines).toEqual(['gated words, never shown'])
  expect(resultText({ id: ID, entry: 'vault', what: OFFER_WHAT, outcome: 'ok', note: 'set it in the dialog that opened' })).toBe('vault passphrase: set it in the dialog that opened')
  expect(resultText({ id: ID, entry: 'vault', what: OFFER_WHAT, outcome: 'cancelled', note: '' })).toBe('the vault passphrase offer: cancelled')
})

test('the passphrase offer pane sends the option picked, and Cancel only cancels', async ($: any, on: any) => {
  const w = world(on, [view(offerDialog())])
  await start($)
  const ui = await mount($)
  const t = JSON.stringify(await ui.drawn())
  expect(t).toContain('Protect the vault with a passphrase?')
  expect(t).not.toContain('gated words, never shown')
  expect(await ui.find({ key: FIELD })).toBe(undefined)
  expect((await ui.find({ key: 'opt0' }))?.text).toBe('Set passphrase')
  expect((await ui.find({ key: 'opt1' }))?.text).toBe('Not now')
  expect((await ui.find({ key: 'cancel' }))?.text).toBe('Cancel')
  await ui.press({ key: 'opt1' })
  expect(w.fetches.filter((f) => f.url.endsWith('/ui/dialog/answer')).map((f) => f.body)).toEqual([
    { id: ID, button: 'ok', choice: 'Not now' }])
})

test('the queue is shown by identity', () => {
  expect(queueLine([{ id: ID2, kind: 'secret', entry: 'gh-work', what: 'token' }])).toBe('Also waiting: token for gh-work')
  expect(queueLine([])).toBe(undefined)
  const v = parseNext(JSON.stringify(view(null, { queue: [{ id: ID2, kind: 'secret', entry: 'gh-work', what: 'token' }, { id: 'bad', entry: 'x' }] })))
  expect(v!.queue.map((q) => q.id)).toEqual([ID2])
  expect(resultText({ id: ID, entry: 'build', what: 'sudo password', outcome: 'ok', note: '' })).toBe('sudo password for build: supplied')
})

test('a click on the field (what gives it the keys again after the focus moved away) starts it over', async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  const ui = await mount($)
  await type(ui, 'half')
  expect(JSON.stringify(await ui.drawn({ in: FIELD }))).toContain('••••')
  await ui.pointer({ type: 'down', x: 3, y: 0, button: 'left', in: FIELD })
  await ui.pointer({ type: 'up', x: 3, y: 0, button: 'left', in: FIELD })
  expect(JSON.stringify(await ui.drawn({ in: FIELD }))).not.toContain('•')
  await type(ui, 'right')
  await ui.key({ key: 'return', in: FIELD })
  const sent = sealedInto(w.fetches)
  expect(sent.length).toBe(1)
  const opened = openForTest({ epk: sent[0].epk, nonce: sent[0].nonce, box: sent[0].box }, kp.secretKey)
  expect(JSON.parse(new TextDecoder().decode(opened!))).toEqual({ rid: ID, a: 1, v: ['right'] })   // nothing of 'half'
})

test("the pane's ring moving onto a button (focus leaving the field) resets the field", async ($: any, on: any) => {
  const kp = keyPairForTest()
  world(on, [view(secretDialog(kp.publicKey))])
  on('ui.focus', () => ({}))                        // the engine's ring: it moved
  await start($)
  const ui = await mount($)
  await type(ui, 'half')
  await $.ui.focus({ requestId: 'gate-dialog', key: 'cancel' })
  await settle()
  expect(await ui.find({ key: FIELD })).toBe(undefined)            // a new instance, nothing typed in it
  const next = `field-${ID}-1-1`
  expect(await ui.find({ key: next })).not.toBe(undefined)
  expect(JSON.stringify(await ui.drawn({ in: next }))).not.toContain('•')
})

test('/gate-dialog, /gate-unlock and /gate-lock answer without a model turn', async ($: any, on: any) => {
  const kp = keyPairForTest()
  const w = world(on, [view(secretDialog(kp.publicKey))])
  await start($)
  const run = (command: string) => $.command.run({ command, args: '', origin: { kind: 'composer' }, presentation: { isFullscreen: false, columns: 100 } })
  expect((await run('gate-dialog')).text).toBe('the gateway dialog is open')
  expect((await run('gate-unlock')).text).toBe('the gateway dialog for the vault passphrase is open')
  expect((await run('gate-lock')).text).toBe('the vault is locked')
  expect(w.fetches.some((f) => f.url.endsWith('/ui/vault/unlock'))).toBe(true)
})

test('claude -p runs no dialog loop', async ($: any, on: any) => {
  const w = world(on, [view(null)])
  await start($, null, false)
  expect(w.fetches.some((f) => f.url.includes('/ui/dialog/next'))).toBe(false)
  expect(w.fetches.some((f) => f.url.endsWith('/ui/register'))).toBe(true)
})

test("the daemon's version-skew notice is shown on the status line once", async ($: any, on: any) => {
  const w = world(on, [view(null)], daemonJson({ skew: 'a newer gateway daemon (0.8.0) answers this plugin (0.7.0); start a new session to use the new plugin' }))
  await start($)
  const shown = w.statuses.filter((s) => typeof s === 'string' && s.startsWith('daemon: a newer gateway daemon'))
  expect(shown.length).toBe(1)
  await w.clock.advance(21000)
  expect(w.statuses.at(-1)).toBe(undefined)
})
