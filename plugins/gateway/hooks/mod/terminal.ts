// The terminal pane's pure logic (PLAN-v4 phase 5; no `$`): what gated's
// /ui/term/screen answers, how a Client key becomes what gated types, the
// Ctrl-] prefix, the pane's texts. register.tsx draws the pane, term.tsx is
// the Client that shows the screen and takes keys; terminal.test.ts tests it
// under `claude plugin test`.
//
// gated (daemon/terminals.py) owns the terminal: its tmux pane, its screen
// sequence, who holds the input. The pane only shows what gated captured and
// forwards the person's keys; a key (or a click into the screen) is a
// takeover. Typed text never goes to a password prompt from here: gated's
// credential dialog takes it (the field seals it).

export const TERM_PANE = 'gate-terminal'
export const TERM_ID = /^[tj]_[0-9A-HJKMNP-TV-Z]{26}$/
export const POLL_WAIT_S = 10            // one /ui/term/screen long poll at gated
export const MIN_FRAME_MS = 100          // at most 10 redraws a second

export type Run = { t: string; fg?: string; bg?: string; b?: 1; d?: 1; i?: 1; u?: 1; s?: 1; r?: 1 }
export type ScreenView = {
  id: string
  kind: string
  state: string
  owner: 'agent' | 'user'
  seq: number
  cols: number
  rows: number
  cursor: { x: number; y: number }
  alt: boolean
  title: string
  lines: Run[][]
  echoOff: boolean
  auth: string
  agent: string
  queued: number
  exit: number | null
  command: string
  ended: boolean
}

export type Item = { k: 'text' | 'key' | 'line'; v: string }
export type Batch = { seq: number; items: Item[]; take: boolean }
export type TermPost = { t: 'term'; id: string; seq: number; batches: Batch[]; size?: { cols: number; rows: number } }

const COLOR = /^(?:#[0-9a-f]{6}|black|red|green|yellow|blue|magenta|cyan|white)$/

function clean(s: unknown, max = 2000): string {
  return typeof s === 'string' ? s.replace(/[\u0000-\u001f\u007f]/g, '').slice(0, max) : ''
}

function num(v: unknown, d = 0): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : d
}

function parseRun(v: unknown): Run | undefined {
  if (typeof v !== 'object' || v === null) return undefined
  const o = v as Record<string, unknown>
  const t = clean(o.t)
  if (t === '') return undefined
  const r: Run = { t }
  if (typeof o.fg === 'string' && COLOR.test(o.fg)) r.fg = o.fg
  if (typeof o.bg === 'string' && COLOR.test(o.bg)) r.bg = o.bg
  for (const k of ['b', 'd', 'i', 'u', 's', 'r'] as const) if (o[k] === 1) r[k] = 1
  return r
}

// gated's /ui/term/screen answer, checked and bounded (or undefined).
export function parseScreen(text: string | undefined): ScreenView | undefined {
  let v: unknown
  try {
    v = JSON.parse(text ?? '')
  } catch {
    return undefined
  }
  if (typeof v !== 'object' || v === null) return undefined
  const o = v as Record<string, unknown>
  const id = typeof o.id === 'string' ? o.id : ''
  if (!TERM_ID.test(id)) return undefined
  const rows = Math.max(0, Math.min(200, num(o.rows)))
  const lines = Array.isArray(o.lines)
    ? o.lines.slice(0, 200).map((ln) => (Array.isArray(ln) ? ln.slice(0, 400).map(parseRun).filter((x): x is Run => x !== undefined) : []))
    : []
  const cur = typeof o.cursor === 'object' && o.cursor !== null ? (o.cursor as Record<string, unknown>) : {}
  return {
    id,
    kind: o.kind === 'job' ? 'job' : 'terminal',
    state: clean(o.state, 24),
    owner: o.owner === 'user' ? 'user' : 'agent',
    seq: num(o.seq),
    cols: Math.max(0, Math.min(500, num(o.cols))),
    rows,
    cursor: { x: Math.max(0, num(cur.x)), y: Math.max(0, num(cur.y)) },
    alt: o.alternate_screen === true,
    title: clean(o.title, 120),
    lines,
    echoOff: o.echo_off === true,
    auth: clean(o.auth, 300),
    agent: clean(o.agent, 80),
    queued: num(o.queued),
    exit: typeof o.exit === 'number' ? o.exit : null,
    command: clean(o.command, 200),
    ended: o.ended === true,
  }
}

// F-keys arrive as their raw escape sequence (FEASIBILITY-v4 P3b)
const FKEYS: Record<string, string> = {
  '\u001bOP': 'F1', '\u001bOQ': 'F2', '\u001bOR': 'F3', '\u001bOS': 'F4',
  '\u001b[15~': 'F5', '\u001b[17~': 'F6', '\u001b[18~': 'F7', '\u001b[19~': 'F8',
  '\u001b[20~': 'F9', '\u001b[21~': 'F10', '\u001b[23~': 'F11', '\u001b[24~': 'F12',
}
const NAMED: Record<string, string> = {
  return: 'Enter', enter: 'Enter', tab: 'Tab', backspace: 'BSpace', delete: 'DC', insert: 'IC', space: 'Space',
  up: 'Up', down: 'Down', left: 'Left', right: 'Right', home: 'Home', end: 'End',
  pageup: 'PageUp', pagedown: 'PageDown', escape: 'Escape',
}
// after Ctrl-]: c ^C, d ^D, z ^Z, [ Esc, ] a literal ^] (the engine keeps
// ^C, ^D, ^Z and Escape for itself: P3b)
const PREFIXED: Record<string, string> = { c: 'C-c', d: 'C-d', z: 'C-z', '[': 'Escape', ']': 'C-]' }

export type KeyIn = { key: string; ctrl?: boolean; shift?: boolean; meta?: boolean }

// One Client key, given whether the Ctrl-] prefix is pending: what to send
// (or nothing), and whether the prefix is pending after it.
export function keyItem(k: KeyIn, prefix: boolean): { item?: Item; prefix: boolean } {
  if (prefix) {
    const name = PREFIXED[k.key.toLowerCase()]
    return name !== undefined ? { item: { k: 'key', v: name }, prefix: false } : { prefix: false }
  }
  if (k.ctrl && k.key === ']') return { prefix: true }
  if (FKEYS[k.key] !== undefined) return { item: { k: 'key', v: FKEYS[k.key]! }, prefix: false }
  const named = NAMED[k.key]
  if (named !== undefined) {
    if (named === 'Tab' && k.shift) return { item: { k: 'key', v: 'BTab' }, prefix: false }
    // the engine names the space bar (Claude Code 2.1.301): typed text, unless with a modifier
    if (named === 'Space' && !k.ctrl && !k.meta) return { item: { k: 'text', v: ' ' }, prefix: false }
    if (named === 'Space' && k.ctrl) return { item: { k: 'key', v: 'C-Space' }, prefix: false }
    return { item: { k: 'key', v: named }, prefix: false }
  }
  const cps = [...k.key]
  if (cps.length !== 1) return { prefix: false }
  const c = cps[0]!.codePointAt(0)!
  if (k.ctrl) {
    const ch = cps[0]!.toLowerCase()
    return /^[a-z@\\^_ ]$/.test(ch) ? { item: { k: 'key', v: ch === ' ' ? 'C-Space' : `C-${ch}` }, prefix: false } : { prefix: false }
  }
  if (k.meta) return c > 32 && c !== 127 ? { item: { k: 'key', v: `M-${cps[0]}` }, prefix: false } : { prefix: false }
  if (c < 32 || c === 127 || (c >= 0x80 && c < 0xa0)) return { prefix: false }
  return { item: { k: 'text', v: cps[0]! }, prefix: false }
}

// Consecutive typed characters go as one text item (fewer tmux calls).
export function coalesce(items: Item[]): Item[] {
  const out: Item[] = []
  for (const it of items) {
    const last = out[out.length - 1]
    if (it.k === 'text' && last !== undefined && last.k === 'text' && last.v.length < 4000) last.v += it.v
    else out.push({ ...it })
  }
  return out
}

// The Client's posts (term.tsx): checked; anything else is not a terminal post.
export function parseTermPost(data: unknown): TermPost | undefined {
  if (typeof data !== 'object' || data === null) return undefined
  const o = data as Record<string, unknown>
  if (o.t !== 'term' || typeof o.id !== 'string' || !TERM_ID.test(o.id)) return undefined
  const batches: Batch[] = []
  for (const b of Array.isArray(o.batches) ? o.batches.slice(0, 256) : []) {
    if (typeof b !== 'object' || b === null) continue
    const bo = b as Record<string, unknown>
    const items: Item[] = []
    for (const it of Array.isArray(bo.items) ? bo.items.slice(0, 256) : []) {
      if (typeof it !== 'object' || it === null) continue
      const x = it as Record<string, unknown>
      if ((x.k === 'text' || x.k === 'key' || x.k === 'line') && typeof x.v === 'string' && x.v.length <= 16384) {
        items.push({ k: x.k, v: x.v })
      }
    }
    if (num(bo.seq) > 0) batches.push({ seq: num(bo.seq), items, take: bo.take === true })
  }
  const out: TermPost = { t: 'term', id: o.id, seq: num(o.seq), batches }
  const sz = typeof o.size === 'object' && o.size !== null ? (o.size as Record<string, unknown>) : undefined
  if (sz !== undefined && num(sz.cols) >= 20 && num(sz.rows) >= 5) {
    out.size = { cols: Math.min(400, Math.floor(num(sz.cols))), rows: Math.min(150, Math.floor(num(sz.rows))) }
  }
  return out
}

export const FULLSCREEN_MODE = 'Typing: click into the screen (the click takes the input from Claude), then type. Ctrl-] then c, d, z or [ sends ^C, ^D, ^Z or Esc.'
export const MAIN_MODE = "Typing: this is Claude Code's main screen, where no clicks reach the pane: type a line below (Enter sends it) or use the buttons. Not for passwords: a password prompt opens the gateway's own dialog."
export const ECHO_OFF = "A password prompt waits: answer it in the gateway's dialog (it opened by itself; /gate-dialog shows it). Typed text isn't sent to it from here."

// The pane's first line: what it shows and its state (the id stays whole).
export function headerLine(v: ScreenView): string {
  const what = v.kind === 'job' ? `job ${v.id}` : `terminal ${v.id}`
  const st = v.ended || v.state === 'exited' ? `ended${v.exit !== null ? ` (exit ${v.exit})` : ''}` : v.state
  return `${what} · ${st}${v.kind === 'job' && v.command !== '' ? ` · ${v.command}` : ''}`
}

// The second line: who holds the input, and Claude's input waiting to go in.
export function ownerLine(v: ScreenView): string {
  const who = v.owner === 'user' ? 'Input: you hold it' : `Input: Claude holds it${v.agent !== '' ? ` (agent ${v.agent})` : ''}`
  return `${who}${v.queued > 0 ? ` · ${v.queued} queued from Claude` : ''}`
}

export function paneRows(v: ScreenView | undefined): number {
  return Math.max(10, Math.min(44, (v?.rows ?? 24) + 6))
}

// The Client's rows: the screen's lines, the cursor's cell drawn inverse.
export function withCursor(lines: Run[][], cursor: { x: number; y: number }, show: boolean): Run[][] {
  if (!show) return lines
  return lines.map((runs, y) => {
    if (y !== cursor.y) return runs
    const out: Run[] = []
    let col = 0
    let done = false
    for (const r of runs) {
      const cps = [...r.t]
      if (!done && cursor.x >= col && cursor.x < col + cps.length) {
        const k = cursor.x - col
        if (k > 0) out.push({ ...r, t: cps.slice(0, k).join('') })
        out.push({ ...r, t: cps[k]!, r: r.r === 1 ? undefined : 1 } as Run)
        if (k + 1 < cps.length) out.push({ ...r, t: cps.slice(k + 1).join('') })
        done = true
      } else {
        out.push(r)
      }
      col += cps.length
    }
    if (!done) {
      if (cursor.x > col) out.push({ t: ' '.repeat(cursor.x - col) })
      out.push({ t: ' ', r: 1 })
    }
    return out
  })
}
