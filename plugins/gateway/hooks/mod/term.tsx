// The terminal pane's screen: a Client region (PLAN-v4 phase 5).
//
// It draws the screen gated captured (styled runs, the cursor's cell
// inverse) and, once the person clicked into it (a Client takes keys only
// after a click; Claude Code 2.1.301 reports clicks only in its fullscreen
// layout), takes their keys: the click itself takes the input from Claude
// (gated flips the owner at once, and Claude's queued input fails). Keys are
// batched with sequence numbers and re-sent until the hooks module
// acknowledges them in the props it hands back (posts coalesce per frame).
// Ctrl-] is a prefix: c ^C, d ^D, z ^Z, [ Esc, ] a literal ^] (the engine
// keeps those keys for itself). While a password prompt waits (echoOff) no
// typed text leaves the region: the gateway's credential dialog takes it.
// The region's size goes to gated too, so the terminal follows the pane.
import type { ClientKeyEvent, ClientModule, ClientPointerEvent, ClientSurface } from 'claude-code'
import { coalesce, keyItem, withCursor, type Item, type Run } from './terminal.ts'

export type TermProps = {
  id: string
  lines: Run[][]
  cursor: { x: number; y: number }
  owner: 'agent' | 'user'
  echoOff: boolean
  ack?: number
  epoch?: number
}

type State = { prefix: boolean; note: string; n: number }
type Inst = {
  outbox: { seq: number; items: Item[]; take: boolean }[]
  seq: number
  props: TermProps
  size: string
  stopRetry?: () => void
  tries: number
}

const INSTANCES = new WeakMap<object, Inst>()
const RETRY_MS = 250
const MAX_TRIES = 40

const Term: ClientModule<TermProps, State> = (props, surface) => {
  const { Box, Text } = surface.elements
  let inst = INSTANCES.get(surface)
  if (inst === undefined) {
    inst = { outbox: [], seq: 0, props, size: '', tries: 0 }
    INSTANCES.set(surface, inst)
  }
  const me = inst
  me.props = props
  if (typeof props.ack === 'number') {
    const ack = props.ack
    me.outbox = me.outbox.filter((b) => b.seq > ack)
  }
  if (surface.state === undefined) {
    surface.setState({ prefix: false, note: '', n: 0 })
    surface.onKey((k) => onKey(k))
    surface.onPointer((p) => onPointer(p))
  }
  const s: State = surface.state ?? { prefix: false, note: '', n: 0 }

  function post(): void {
    const p = me.props
    const sizeNow = surface.columns > 0 && surface.rows > 0 ? `${surface.columns}x${surface.rows}` : ''
    const batches = me.outbox.map((b) => ({ seq: b.seq, items: coalesce(b.items), take: b.take }))
    const data: Record<string, unknown> = { t: 'term', id: p.id, seq: me.seq, batches }
    if (sizeNow !== '' && sizeNow !== me.size) {
      me.size = sizeNow
      data.size = { cols: surface.columns, rows: surface.rows }
    }
    if (batches.length === 0 && data.size === undefined) return
    surface.post(data as any)
  }

  function retry(): void {
    me.stopRetry?.()
    me.tries = 0
    me.stopRetry = surface.every(RETRY_MS, () => {
      me.tries++
      if (me.outbox.length === 0 || me.tries > MAX_TRIES) {
        me.stopRetry?.()
        me.stopRetry = undefined
        if (me.outbox.length === 0) post()   // a size change still to send
        return
      }
      post()
    })
  }

  function send(items: Item[], take: boolean): void {
    me.outbox.push({ seq: ++me.seq, items, take })
    post()
    retry()
  }

  function update(patch: Partial<State>): void {
    const cur = surface.state ?? s
    surface.setState({ ...cur, ...patch, n: cur.n + 1 })
  }

  // The click is the takeover (and what gives this region the keys).
  function onPointer(p: ClientPointerEvent): void {
    if (p.type !== 'down') return
    send([], true)
    update({ note: '' })
  }

  function onKey(k: ClientKeyEvent): void {
    const cur = surface.state ?? s
    const r = keyItem(k, cur.prefix)
    if (r.item === undefined) {
      update({ prefix: r.prefix, note: r.prefix ? 'Ctrl-]: now c, d, z, [ or ]' : '' })
      return
    }
    if (r.item.k === 'text' && me.props.echoOff) {
      update({ prefix: false, note: "a password prompt waits: use the gateway's dialog" })
      return
    }
    send([r.item], true)
    update({ prefix: false, note: '' })
  }

  // the size, once laid out (and whenever the pane changes it)
  const sizeNow = surface.columns > 0 && surface.rows > 0 ? `${surface.columns}x${surface.rows}` : ''
  if (sizeNow !== '' && sizeNow !== me.size) post()

  const rows = withCursor(props.lines, props.cursor, true)
  const height = Math.max(1, surface.rows || rows.length)
  const shown = rows.slice(0, height - (s.note !== '' ? 1 : 0))
  return (
    <Box flexDirection="column">
      {shown.map((runs, y) => (
        <Text key={`l${y}`} wrap="truncate-end">
          {runs.length === 0 ? ' ' : runs.map((r, i) => (
            <Text key={`r${i}`} color={r.fg} backgroundColor={r.bg} bold={r.b === 1 || undefined}
              dimColor={r.d === 1 || undefined} italic={r.i === 1 || undefined}
              underline={r.u === 1 || undefined} strikethrough={r.s === 1 || undefined}
              inverse={r.r === 1 || undefined}>{r.t}</Text>
          ))}
        </Text>
      ))}
      {s.note !== '' ? <Text dimColor>{s.note}</Text> : null}
    </Box>
  )
}

export default Term
