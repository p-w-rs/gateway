// `claude plugin test plugins/gateway`: the gateway terminal pane (PLAN-v4
// phase 5) against the engine's test kit. The test's hooks stand beneath the
// plugin and play the engine and gated: launch.sh answers, and /ui/term/* over
// the socket.
import { expect, mock, test } from 'claude-code/testing'
import { ECHO_OFF, FULLSCREEN_MODE, MAIN_MODE, coalesce, headerLine, keyItem, ownerLine, parseScreen, parseTermPost, withCursor } from './terminal.ts'

const HOME = '/Users/tester'
const CONFIG = `${HOME}/.claude`
const SOCKET = '/tmp/gw-501/gated.sock'
const TID = 't_01M5D7R9CM0TTWWSWZ02Y54RNW'
const JID = 'j_01M5D7RA310NDZ3C7E2C4ZBHVE'

const statusJson = (): string => JSON.stringify({
  state: 'ready', root: '/plugin', data: `${CONFIG}/plugins/data/gate-inline`,
  env: `${CONFIG}/plugins/data/gate-inline/envs/0123456789ab`, lock: '0123456789ab', warm: true, older: '',
  build_running: false, install_log: false, pixi: `${HOME}/.pixi/bin/pixi`, pixi_version: 'pixi 0.81.0',
  home: `${HOME}/.config/gateway`, form: true, vault: true, managed: true,
}) + '\n'

const daemonJson = (): string => JSON.stringify({
  ok: true, version: '0.8.0', protocol: 1, pid: 777, epoch: 3, started: 1792450000, uptime: 5,
  vault: 'unwrapped', sessions: 1, socket: SOCKET, lock_after: 28800, parent_pid: 4242,
}) + '\n'

function screen(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ok: true, id: TID, kind: 'terminal', state: 'open', owner: 'agent', seq: 5, rev: 9, cols: 80, rows: 4,
    cursor: { x: 2, y: 1 }, alternate_screen: false, title: 'Mac',
    lines: [[{ t: 'hello ', fg: 'red' }, { t: 'world', b: 1 }], [{ t: '$ ' }], [], []],
    echo_off: false, auth: '', agent: '', queued: 0, exit: null, command: '', ...extra,
  }
}

// The engine and gated beneath the plugin. /ui/term/screen answers `screens`
// in turn, then waits for a push; every fetch is recorded.
function world(on: any, screens: Record<string, unknown>[], list: Record<string, unknown> = { ok: true, terminals: [], jobs: [] }) {
  const fetches: { url: string; body: any }[] = []
  const opened: any[] = []
  mock.env(on, { HOME, CLAUDE_CONFIG_DIR: CONFIG })
  mock.clock(on, { now: 1_000_000 })
  on('session.start', (_$: any, e: any) => ({ cwd: e.cwd }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.surfaces', () => ({ value: ['terminal'] }))
  on('command.register', (_$: any, e: any) => ({ value: { command: e.name } }))
  on('ui.status', () => ({ value: undefined }))
  on('ui.toast', () => ({ value: undefined }))
  on('ui.open', (_$: any, e: any) => { opened.push(e); return { value: { isPlaced: true } } })
  on('ui.close', () => ({ value: undefined }))
  on('process.run', (_$: any, e: any) => ({ value: { exitCode: 0, stdout: e.argv[2] === 'gated' ? daemonJson() : statusJson(), stderr: '' } }))
  on('session.version', () => ({ value: { version: '2.1.301', base: '2.1.301', builtAt: '2026-10-15T12:58:20Z' } }))
  const queue = [...screens]
  const waiting: ((v: Record<string, unknown>) => void)[] = []
  const push = (v: Record<string, unknown>) => {
    const r = waiting.shift()
    if (r !== undefined) r(v)
    else queue.push(v)
  }
  const answer = (x: unknown, status = 200) => ({ value: { status, ok: status === 200, headers: {}, text: JSON.stringify(x) } })
  on('http.fetch', (_$: any, e: any) => {
    const body = typeof e.init?.body === 'string' ? JSON.parse(e.init.body) : undefined
    const url = String(e.url)
    if (url.includes('/ui/dialog/next')) return new Promise(() => {})
    fetches.push({ url, body })
    if (url.includes('/ui/term/screen')) {
      const v = queue.shift()
      if (v === undefined) return new Promise((resolve) => waiting.push((x) => resolve(answer(x))))
      return answer(v)
    }
    if (url.includes('/ui/term/list')) return answer(list)
    if (url.includes('/ui/term/open')) return answer({ ok: true, id: TID, owner: 'user' })
    if (url.includes('/ui/term/keys')) return answer({ ok: true, sent: (body?.items ?? []).length, owner: 'user' })
    if (url.includes('/ui/term/take')) return answer({ ok: true, owner: 'user', seq: 6 })
    if (url.includes('/ui/term/release')) return answer({ ok: true, owner: 'agent', seq: 7 })
    return answer({ ok: true })
  })
  return { fetches, opened, push }
}

async function settle(): Promise<void> {
  for (let i = 0; i < 80; i++) await Promise.resolve()
}

const start = async ($: any) => {
  await $.session.start({ cwd: '/work', surface: 'terminal', isInteractive: true })
  await settle()
}

const term = ($: any, args: string, isFullscreen = true) =>
  $.command.run({ command: 'gate-terminal', args, origin: { kind: 'composer' }, presentation: { isFullscreen, columns: 120 } })

const PANE_PROPS = { title: 'Gateway terminal', isFocused: true, bodyColumns: 100, placement: 'inline', scroll: { offset: 0, bodyRows: 20 }, view: {} }

const mount = ($: any, isFullscreen = true, surface = 'terminal') =>
  $.ui.mount({ plugin: 'gate', surface, component: 'Pane', requestId: 'gate-terminal', props: PANE_PROPS,
               viewport: { columns: 120, rows: 40, isFullscreen } } as any)

const CLIENT = `term-${TID}`
const keysSent = (w: { fetches: { url: string; body: any }[] }) => w.fetches.filter((f) => f.url.endsWith('/ui/term/keys')).map((f) => f.body)

test('parseScreen keeps known fields, checks ids and colours, bounds the lines', () => {
  const v = parseScreen(JSON.stringify(screen({ lines: [[{ t: 'x', fg: 'url(evil)', bg: '#00ff00', b: 1, r: 2 }]] })))!
  expect(v.id).toBe(TID)
  expect(v.lines[0]).toEqual([{ t: 'x', bg: '#00ff00', b: 1 }])
  expect(v.cursor).toEqual({ x: 2, y: 1 })
  expect(parseScreen(JSON.stringify(screen({ id: 't_bad' })))).toBe(undefined)
  expect(parseScreen('not json')).toBe(undefined)
  const many = parseScreen(JSON.stringify(screen({ lines: Array.from({ length: 500 }, () => [{ t: 'a\u0007b' }]) })))!
  expect(many.lines.length).toBe(200)
  expect(many.lines[0]![0]!.t).toBe('ab')
})

test('keys: printable text, named keys, ctrl and meta, F-keys, and the Ctrl-] prefix', () => {
  expect(keyItem({ key: 'a' }, false)).toEqual({ item: { k: 'text', v: 'a' }, prefix: false })
  expect(keyItem({ key: 'return' }, false).item).toEqual({ k: 'key', v: 'Enter' })
  expect(keyItem({ key: 'space' }, false).item).toEqual({ k: 'text', v: ' ' })       // the engine names the space bar
  expect(keyItem({ key: ' ' }, false).item).toEqual({ k: 'text', v: ' ' })
  expect(keyItem({ key: 'space', ctrl: true }, false).item).toEqual({ k: 'key', v: 'C-Space' })
  expect(keyItem({ key: 'tab', shift: true }, false).item).toEqual({ k: 'key', v: 'BTab' })
  expect(keyItem({ key: 'l', ctrl: true }, false).item).toEqual({ k: 'key', v: 'C-l' })
  expect(keyItem({ key: 'x', meta: true }, false).item).toEqual({ k: 'key', v: 'M-x' })
  expect(keyItem({ key: '\u001b[15~' }, false).item).toEqual({ k: 'key', v: 'F5' })
  expect(keyItem({ key: '\u001b[99~' }, false).item).toBe(undefined)
  // ^] is a prefix: c ^C, d ^D, z ^Z, [ Esc, ] a literal ^]; anything else cancels it
  expect(keyItem({ key: ']', ctrl: true }, false)).toEqual({ prefix: true })
  for (const [k, v] of [['c', 'C-c'], ['d', 'C-d'], ['z', 'C-z'], ['[', 'Escape'], [']', 'C-]']]) {
    expect(keyItem({ key: k! }, true)).toEqual({ item: { k: 'key', v: v! }, prefix: false })
  }
  expect(keyItem({ key: 'q' }, true)).toEqual({ prefix: false })
  expect(coalesce([{ k: 'text', v: 'l' }, { k: 'text', v: 's' }, { k: 'key', v: 'Enter' }, { k: 'text', v: 'x' }]))
    .toEqual([{ k: 'text', v: 'ls' }, { k: 'key', v: 'Enter' }, { k: 'text', v: 'x' }])
})

test('the cursor cell is drawn inverse, also past the end of a line', () => {
  const rows = withCursor([[{ t: 'ab' }, { t: 'cd', fg: 'red' }], [{ t: 'x' }]], { x: 2, y: 0 }, true)
  expect(rows[0]).toEqual([{ t: 'ab' }, { t: 'c', fg: 'red', r: 1 }, { t: 'd', fg: 'red' }])
  const past = withCursor([[{ t: 'ab' }]], { x: 4, y: 0 }, true)
  expect(past[0]).toEqual([{ t: 'ab' }, { t: '  ' }, { t: ' ', r: 1 }])
})

test('a terminal post is checked: batches with sequence numbers, known item kinds, a sane size', () => {
  const p = parseTermPost({ t: 'term', id: TID, seq: 3, size: { cols: 90, rows: 3 }, batches: [{ seq: 3, take: true, items: [{ k: 'text', v: 'ls' }, { k: 'evil', v: 'x' }] }] })!
  expect(p.batches).toEqual([{ seq: 3, take: true, items: [{ k: 'text', v: 'ls' }] }])
  expect(p.size).toBe(undefined)                     // too few rows to be a terminal
  expect(parseTermPost({ t: 'term', id: 'x', seq: 1, batches: [] })).toBe(undefined)
  expect(parseTermPost({ seq: 1, items: [] })).toBe(undefined)      // a dialog field's post
})

test('/gate-terminal is registered and says when there is nothing to show', async ($: any, on: any) => {
  const w = world(on, [])
  await start($)
  const out = await term($, '')
  expect(out.text).toContain('no gateway terminal is open')
  expect(w.opened.filter((o) => o.id === 'gate-terminal')).toHaveLength(0)
  expect((await term($, 'nonsense')).text).toContain('usage: /gate-terminal')
})

test('/gate-terminal picks this session\'s newest live terminal and polls its screen', async ($: any, on: any) => {
  const w = world(on, [screen()], { ok: true, jobs: [{ id: JID, state: 'running', mine: true, created: 5 }],
    terminals: [{ id: 't_01M5D7R9CM0TTWWSWZ02Y54RNX', state: 'open', mine: false, created: 9 },
                { id: TID, state: 'open', mine: true, created: 7 }, { id: 't_01M5D7R9CM0TTWWSWZ02Y54RNY', state: 'exited', mine: true, created: 8 }] })
  await start($)
  const out = await term($, '')
  expect(out.text).toBe(`${TID} is open in the gateway terminal pane`)
  await settle()
  expect(w.opened.at(-1)).toMatchObject({ id: 'gate-terminal', focus: true })
  const polls = w.fetches.filter((f) => f.url.includes('/ui/term/screen'))
  expect(polls[0]!.url).toContain(`id=${TID}&seq=0&wait=10`)
})

test('fullscreen: the screen in a Client, the mode line, Take; a click takes the input', async ($: any, on: any) => {
  const w = world(on, [screen()])
  await start($)
  await term($, TID)
  await settle()
  const ui = await mount($, true)
  const drawn = JSON.stringify(await ui.drawn())
  expect(drawn).toContain(FULLSCREEN_MODE)
  expect(drawn).toContain(headerLine(parseScreen(JSON.stringify(screen()))!))
  expect(drawn).toContain('Input: Claude holds it')
  expect(ownerLine(parseScreen(JSON.stringify(screen({ owner: 'user', queued: 0 })))!)).toBe('Input: you hold it')
  expect(ownerLine(parseScreen(JSON.stringify(screen({ queued: 1, agent: 'a-1' })))!)).toBe('Input: Claude holds it (agent a-1) · 1 queued from Claude')
  expect(await ui.find({ key: 'take' })).not.toBe(undefined)
  expect(await ui.find({ key: 'line' })).toBe(undefined)                 // no line field in fullscreen
  const inner = JSON.stringify(await ui.drawn({ in: CLIENT }))
  expect(inner).toContain('hello ')
  expect(inner).toContain('"color":"red"')
  await ui.pointer({ type: 'down', x: 1, y: 0, button: 'left', in: CLIENT })
  await settle()
  expect(w.fetches.some((f) => f.url.endsWith('/ui/term/take') && f.body.id === TID)).toBe(true)
  // keys go in order, once each, the prefix included
  for (const k of [{ key: 'l' }, { key: 's' }, { key: 'space' }, { key: '-' }, { key: 'return' }, { key: ']', ctrl: true }, { key: 'c' }]) {
    await ui.key({ ...k, in: CLIENT })
  }
  await settle()
  const sent = keysSent(w).flatMap((b) => b.items)
  expect(sent).toEqual([{ k: 'text', v: 'l' }, { k: 'text', v: 's' }, { k: 'text', v: ' ' }, { k: 'text', v: '-' },
    { k: 'key', v: 'Enter' }, { k: 'key', v: 'C-c' }])
})

test('a re-sent batch is forwarded once, and the size follows the region', async ($: any, on: any) => {
  const w = world(on, [screen()])
  await start($)
  await term($, TID)
  await settle()
  const ui = await mount($, true)
  const b1 = { seq: 1, take: true, items: [{ k: 'text', v: 'a' }] }
  const b2 = { seq: 2, take: true, items: [{ k: 'key', v: 'Enter' }] }
  await ui.post({ t: 'term', id: TID, seq: 1, batches: [b1] }, { in: CLIENT })
  await ui.post({ t: 'term', id: TID, seq: 2, batches: [b1, b2], size: { cols: 96, rows: 18 } }, { in: CLIENT })
  await ui.post({ t: 'term', id: TID, seq: 2, batches: [b1, b2], size: { cols: 96, rows: 18 } }, { in: CLIENT })
  expect(keysSent(w).map((b) => b.items)).toEqual([[{ k: 'text', v: 'a' }], [{ k: 'key', v: 'Enter' }]])
  // the region's own size when it is laid out, then each new size once
  const resizes = w.fetches.filter((f) => f.url.endsWith('/ui/term/resize')).map((f) => f.body)
  expect(resizes.at(-1)).toEqual({ id: TID, cols: 96, rows: 18 })
  expect(resizes.filter((r) => r.cols === 96)).toHaveLength(1)
})

test('the main screen (no clicks): a line field, Enter and the control buttons; Hand back once held', async ($: any, on: any) => {
  const w = world(on, [screen({ owner: 'user' })])
  await start($)
  await term($, TID, false)
  await settle()
  const ui = await mount($, false)
  expect(JSON.stringify(await ui.drawn())).toContain(MAIN_MODE)
  await ui.input({ key: 'line', text: 'echo hi' })
  await ui.press({ key: 'int' })
  await ui.press({ key: 'enter' })
  expect(keysSent(w).map((b) => b.items)).toEqual([[{ k: 'line', v: 'echo hi' }], [{ k: 'key', v: 'C-c' }], [{ k: 'key', v: 'Enter' }]])
  expect(await ui.find({ key: 'take' })).toBe(undefined)
  await ui.press({ key: 'release' })
  expect(w.fetches.some((f) => f.url.endsWith('/ui/term/release'))).toBe(true)
})

test('a password prompt: no line field, typed keys stay in the Client, the dialog is named', async ($: any, on: any) => {
  const w = world(on, [screen({ echo_off: true })])
  await start($)
  await term($, TID, true)
  await settle()
  const ui = await mount($, true)
  expect(JSON.stringify(await ui.drawn())).toContain(ECHO_OFF)
  for (const ch of 'hunter2-not-real') await ui.key({ key: ch, in: CLIENT })
  await ui.key({ key: 'return', in: CLIENT })
  await settle()
  const all = JSON.stringify(w.fetches)
  expect(all.includes('hunter2')).toBe(false)
  expect(keysSent(w).flatMap((b) => b.items)).toEqual([{ k: 'key', v: 'Enter' }])
  await ui.unmount()
  const ms = await mount($, false)
  expect(JSON.stringify(await ms.drawn())).toContain(MAIN_MODE)
  expect(await ms.find({ key: 'line' })).toBe(undefined)
})

test('a terminal tool call names its agent loop to gated; other tools pass untouched', async ($: any, on: any) => {
  const w = world(on, [])
  on('tool.call', () => ({ result: 'ran' }))
  await start($)
  await $.tool.call({ tool: 'mcp__plugin_gate_gw__terminal_send', tool_use_id: 'toolu_42', id: TID, seq: 1, text: 'ls', agentId: 'a-sub-7' } as any)
  await $.tool.call({ tool: 'mcp__plugin_gate_gw__http', tool_use_id: 'toolu_43', url: 'https://x' } as any)
  const named = w.fetches.filter((f) => f.url.endsWith('/ui/term/agent')).map((f) => f.body)
  expect(named).toEqual([{ tool_use_id: 'toolu_42', agent: 'a-sub-7' }])
})
