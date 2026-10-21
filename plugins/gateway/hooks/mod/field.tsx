// The gateway dialog's private field: a Client region (PLAN-v4 phase 3).
//
// Typed keys reach only this module's onKey once the person clicked the
// region (FEASIBILITY-v4 P1, P3b): not the prompt box, not another plugin's
// hooks, not the transcript. The typed characters live in an array of this
// instance (never in surface state, never posted); the region shows a bullet
// per character. On Enter the value is sealed to the dialog's public key
// (seal.ts, vendored TweetNaCl box) and only {id, attempt, epk, nonce, box}
// is posted to the hooks module, which forwards it to gated. The array is
// overwritten at once (and on every reset: new props, a reset epoch, Ctrl-U,
// the instance unmounting with the pane), so nothing typed outlives the
// dialog's attempt.
//
// Posts coalesce per frame (a later post in the same frame replaces an
// undelivered one), so every post carries the whole outbox with sequence
// numbers, re-sent on a timer until the hooks module acknowledges it in the
// props it hands back (`ack`): nothing is lost when posts coalesce.
//
// Two fields (setting a vault passphrase): Tab, an arrow or Enter moves to the
// second; the two must match before anything is sealed (gated checks too).
import type { ClientKeyEvent, ClientModule, ClientPointerEvent, ClientSurface } from 'claude-code'
import { plaintext, seal } from './seal.ts'

export type FieldProps = {
  id: string
  attempt: number
  pub: string
  fields: number
  labels: string[]
  ack?: number
  epoch?: number
}

type State = { n: number[]; cur: number; note: string; sent: boolean }

type Item = { seq: number; t: 'submit'; id: string; attempt: number; epk: string; nonce: string; box: string }

type Inst = {
  buf: string[][]
  outbox: Item[]
  seq: number
  key: string            // id/attempt/epoch/public key the buffer belongs to
  props: FieldProps      // the latest props: what a seal uses (the listeners outlive a render)
  stopRetry?: () => void
  tries: number
}

const INSTANCES = new WeakMap<object, Inst>()
const SPECIAL = new Set(['return', 'enter', 'tab', 'backspace', 'delete', 'up', 'down', 'left', 'right',
  'home', 'end', 'pageup', 'pagedown', 'escape', 'insert'])
const RETRY_MS = 300
const MAX_TRIES = 60

function wipe(inst: Inst): void {
  for (const f of inst.buf) {
    for (let i = 0; i < f.length; i++) f[i] = ''
    f.length = 0
  }
}

function counts(inst: Inst): number[] {
  return inst.buf.map((f) => f.length)
}

// One printable character (one code point, no control character): what a
// key press types. Names of special keys and escape sequences are not.
export function printable(k: ClientKeyEvent): boolean {
  if (k.ctrl || k.meta) return false
  if (SPECIAL.has(k.key)) return false
  const cps = [...k.key]
  if (cps.length !== 1) return false
  const c = cps[0]!.codePointAt(0)!
  return c >= 32 && c !== 127 && !(c >= 0x80 && c < 0xa0)
}

function instance(props: FieldProps, surface: ClientSurface<State>): [Inst, boolean] {
  // a new public key (gated restarted and restored the request with a new
  // key pair) is a new attempt too: nothing typed for the old key is kept
  const key = `${props.id}/${props.attempt}/${props.epoch ?? 0}/${props.pub}`
  let inst = INSTANCES.get(surface)
  let reset = false
  if (inst === undefined) {
    inst = { buf: [], outbox: [], seq: 0, key, tries: 0, props }
    INSTANCES.set(surface, inst)
  }
  inst.props = props
  const n = Math.max(1, Math.min(2, props.fields || 1))
  if (inst.key !== key || inst.buf.length !== n) {
    wipe(inst)                         // another attempt, a reset: nothing typed carries over
    inst.buf = Array.from({ length: n }, () => [] as string[])
    reset = inst.key !== key
    inst.key = key
  }
  if (typeof props.ack === 'number') {
    const ack = props.ack
    inst.outbox = inst.outbox.filter((it) => it.seq > ack)
  }
  return [inst, reset]
}

const Field: ClientModule<FieldProps, State> = (props, surface) => {
  const { Box, Text } = surface.elements
  const [inst, reset] = instance(props, surface)
  const fresh: State = { n: counts(inst), cur: 0, note: '', sent: false }
  if (surface.state === undefined) {
    surface.setState(fresh)
    surface.onKey((k) => onKey(k))
    surface.onPointer((p) => onPointer(p))
  } else if (reset) {
    surface.setState(fresh)              // a new attempt or a reset: bullets and "sent" go too
  }
  const s: State = surface.state === undefined || reset ? fresh : surface.state

  function post(): void {
    if (inst.outbox.length === 0) return
    surface.post({ seq: inst.seq, items: inst.outbox.map((it) => ({ ...it })) })
  }

  function retry(): void {
    inst.stopRetry?.()
    inst.tries = 0
    inst.stopRetry = surface.every(RETRY_MS, () => {
      inst.tries++
      if (inst.outbox.length === 0 || inst.tries > MAX_TRIES) {
        inst.stopRetry?.()
        inst.stopRetry = undefined
        return
      }
      post()
    })
  }

  function update(patch: Partial<State>): void {
    const cur = surface.state ?? s
    surface.setState({ ...cur, n: counts(inst), ...patch })
  }

  function submit(): void {
    const p = inst.props                         // never the first render's: the key may have changed
    const values = inst.buf.map((f) => f.join(''))
    const cur = (surface.state ?? s).cur
    if (values.some((v) => v.length === 0)) {
      update({ note: inst.buf.length > 1 ? 'type it in both fields' : 'type it first', cur: values[0] ? 1 : 0 })
      return
    }
    if (values.length === 2 && values[0] !== values[1]) {
      wipe(inst)
      inst.buf = [[], []]
      update({ note: 'the two entries differ; type them again', cur: 0 })
      return
    }
    let item: Item
    try {
      const sealed = seal(p.pub, plaintext(p.id, p.attempt, values))
      item = { seq: ++inst.seq, t: 'submit', id: p.id, attempt: p.attempt, ...sealed }
    } catch {
      update({ note: "couldn't seal it; close the dialog and try again", cur })
      return
    } finally {
      for (let i = 0; i < values.length; i++) values[i] = ''
      wipe(inst)
    }
    inst.outbox.push(item)
    post()
    retry()
    update({ sent: true, note: '', cur: 0 })
  }

  // Every click (which is what gives the region the keys) starts it over.
  function onPointer(p: ClientPointerEvent): void {
    if (p.type !== 'down') return
    const cur = surface.state ?? s
    if (cur.sent) return
    wipe(inst)
    inst.buf = inst.buf.map(() => [] as string[])
    update({ cur: 0, note: '' })
  }

  function onKey(k: ClientKeyEvent): void {
    const cur = surface.state ?? s
    if (cur.sent) return                         // sent: the next attempt brings new props
    const f = inst.buf[cur.cur]
    if (f === undefined) return
    if (k.ctrl && k.key === 'u') {
      for (let i = 0; i < f.length; i++) f[i] = ''
      f.length = 0
      update({ note: '' })
      return
    }
    if (k.key === 'return' || k.key === 'enter') {
      if (cur.cur + 1 < inst.buf.length) update({ cur: cur.cur + 1, note: '' })
      else submit()
      return
    }
    if (k.key === 'tab' || k.key === 'down') {
      update({ cur: (cur.cur + 1) % inst.buf.length })
      return
    }
    if (k.key === 'up') {
      update({ cur: (cur.cur + inst.buf.length - 1) % inst.buf.length })
      return
    }
    if (k.key === 'backspace' || k.key === 'delete') {
      if (f.length > 0) {
        f[f.length - 1] = ''
        f.length -= 1
      }
      update({ note: '' })
      return
    }
    if (printable(k)) {
      f.push(k.key)
      update({ note: '' })
    }
  }

  const labels = inst.buf.map((_, i) => props.labels[i] ?? (i === 0 ? 'Secret' : 'Again'))
  const hint = s.sent ? 'sent sealed; checking…' : s.note || 'click here, then type; Enter submits'
  return (
    <Box flexDirection="column">
      {labels.map((l, i) => (
        <Text key={`l${i}`}>{`${i === s.cur && !s.sent ? '› ' : '  '}${l}: ${'•'.repeat(s.n[i] ?? 0)}${i === s.cur && !s.sent ? '▏' : ''}`}</Text>
      ))}
      <Text dimColor>{hint}</Text>
    </Box>
  )
}

export default Field
