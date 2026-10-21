// The /gate-hosts and /gate-accounts panes' pure logic (PLAN-v4 phase 7; no
// `$`): what gated's /ui/manage answers, the panes' lines, and the edit line
// a person types into the pane's field (non-secret: names, addresses,
// folders, rights words) turned into one fixed `gate` subcommand's argv.
// register.tsx draws the panes and runs the commands (launch.sh gate ...,
// an argv, never a shell string); manage.test.ts tests this under
// `claude plugin test`.
//
// Nothing here widens anything: an edit is written through the gateway's
// form writer, and a widening it causes waits for the person's OK in the
// gateway's consent dialog, which the pane opens next (`gate check NAME`).
// A credential is never typed here: "Enter credential" runs `gate login
// NAME`, whose dialog has the private field.

export const HOSTS_PANE = 'gate-hosts'
export const ACCOUNTS_PANE = 'gate-accounts'
export const EDIT_HINT = 'host add NAME USER@HOST[:PORT] | host set NAME KEY VALUE | workspace add HOST NAME ROOT [LOCAL] | workspace remove HOST NAME | policy set all|HOST|ACCOUNT ACTION allow|ask|deny'
export const NAME = /^[a-z][a-z0-9-]{0,31}$/
const SAFE_WORD = /^[^\u0000-\u001f\u007f]{1,300}$/

export type HostRow = {
  name: string
  local: boolean
  address: string
  user: string
  identity: string
  reachable: string
  auth: string
  runtime: string
  rights: Record<string, string>
  pending: string[]
}
export type WorkspaceRow = { name: string; host: string; root: string; local: string; id: string }
export type AccountRow = {
  account: string
  kind: string
  state: string
  login: string
  credential: string
  checkedAt: string
  pending: string[]
}
export type ManageView = { hosts: HostRow[]; workspaces: WorkspaceRow[]; accounts: AccountRow[]; settingsPending: string[] }

const str = (v: unknown, n = 200): string => (typeof v === 'string' ? clean(v).slice(0, n) : '')
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x) => typeof x === 'string').map((x) => clean(x as string).slice(0, 200)).slice(0, 20) : [])
const word = (v: unknown): string => (v === true ? 'yes' : v === false ? 'no' : typeof v === 'string' ? clean(v).slice(0, 40) : 'unknown')

export function clean(s: string): string {
  return s.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, ' ')
}

export function parseManage(raw: unknown): ManageView | undefined {
  if (typeof raw !== 'object' || raw === null) return undefined
  const r = raw as Record<string, unknown>
  if (r.ok !== true) return undefined
  const hosts: HostRow[] = (Array.isArray(r.hosts) ? r.hosts : []).filter((h) => typeof h === 'object' && h !== null).map((h0) => {
    const h = h0 as Record<string, unknown>
    const rights: Record<string, string> = {}
    if (typeof h.rights === 'object' && h.rights !== null) {
      for (const [k, v] of Object.entries(h.rights as Record<string, unknown>)) {
        if (/^[a-z0-9_]{1,20}$/.test(k) && (v === 'allow' || v === 'ask' || v === 'deny')) rights[k] = v
      }
    }
    return {
      name: str(h.name, 32), local: h.local === true, address: str(h.address), user: str(h.user, 64),
      identity: str(h.identity, 20), reachable: h.local === true ? 'yes' : word(h.reachable),
      auth: h.local === true ? 'yes' : word(h.auth), runtime: word(h.runtime), rights, pending: strs(h.pending),
    }
  }).filter((h) => NAME.test(h.name) || h.name === 'localhost')
  const workspaces: WorkspaceRow[] = (Array.isArray(r.workspaces) ? r.workspaces : []).filter((w) => typeof w === 'object' && w !== null).map((w0) => {
    const w = w0 as Record<string, unknown>
    return { name: str(w.name, 32), host: str(w.host_name, 32), root: str(w.root, 300), local: str(w.local, 300), id: str(w.workspace, 40) }
  })
  const accounts: AccountRow[] = (Array.isArray(r.accounts) ? r.accounts : []).filter((a) => typeof a === 'object' && a !== null).map((a0) => {
    const a = a0 as Record<string, unknown>
    return {
      account: str(a.account, 32), kind: str(a.kind, 20), state: str(a.state, 40), login: str(a.login, 100),
      credential: str(a.credential, 80), checkedAt: str(a.checked_at, 40), pending: strs(a.pending),
    }
  }).filter((a) => NAME.test(a.account))
  return { hosts, workspaces, accounts, settingsPending: strs(r.settings_pending) }
}

const RIGHT_ORDER = ['read', 'exec', 'write', 'elevation', 'provision', 'network', 'credential', 'env_import',
  'forward_agent', 'forward_x11', 'forward_remote', 'forward_stdio']

// One host's state: where it is, whether it answers and takes the gateway's
// key, its runtime, and the actions that aren't simply allowed.
export function hostLine(h: HostRow): string {
  const where = h.local ? 'this machine' : `remote${h.address !== '' ? ` ${h.address}` : ''}`
  const st = h.local ? `runtime ${h.runtime}` : `reachable ${h.reachable}, auth ${h.auth}, runtime ${h.runtime}`
  const not = RIGHT_ORDER.filter((k) => h.rights[k] !== undefined && h.rights[k] !== 'allow' && !k.startsWith('forward_'))
    .map((k) => `${k} ${h.rights[k]}`)
  const fwd = RIGHT_ORDER.filter((k) => k.startsWith('forward_') && h.rights[k] === 'allow').map((k) => k.replace('forward_', ''))
  const rights = not.length > 0 ? `; ${not.join(', ')}` : ''
  const fw = fwd.length > 0 ? `; forwarding: ${fwd.join(', ')}` : ''
  const pend = h.pending.length > 0 ? `; ${h.pending.length} change${h.pending.length === 1 ? '' : 's'} wait for your OK` : ''
  return `${h.name}: ${where}; ${st}${rights}${fw}${pend}`
}

export function workspaceLine(w: WorkspaceRow): string {
  return `  workspace ${w.name}: ${w.root}${w.local !== '' ? ` (here: ${w.local})` : ''}`
}

const STATE_WORDS: Record<string, string> = {
  connected: 'connected', configured: 'stored, not checked yet', expired: 'expired', revoked: 'revoked',
  reauthentication_required: 'needs you to sign in again', missing: 'no credential stored', unknown: 'unknown',
}

export function accountLine(a: AccountRow): string {
  const st = STATE_WORDS[a.state] ?? a.state
  const who = [a.login !== '' ? a.login : '', a.credential].filter((x) => x !== '').join(', ')
  const when = a.checkedAt !== '' ? `; checked ${a.checkedAt.slice(0, 16).replace('T', ' ')}` : ''
  const pend = a.pending.length > 0 ? `; ${a.pending.length} change${a.pending.length === 1 ? '' : 's'} wait for your OK` : ''
  return `${a.account} (${a.kind}): ${st}${who !== '' ? ` (${who})` : ''}${when}${pend}`
}

export function needsCredential(a: AccountRow): boolean {
  return a.state !== 'connected' && a.state !== 'configured'
}

// Words of an edit line: spaces separate, "double quotes" keep a folder with
// spaces together. No other shell syntax: the words go into an argv as they are.
export function words(line: string): string[] | undefined {
  const out: string[] = []
  let cur = ''
  let quoted = false
  let any = false
  for (const ch of line.trim()) {
    if (ch === '"') {
      quoted = !quoted
      any = true
      continue
    }
    if (!quoted && (ch === ' ' || ch === '\t')) {
      if (any) out.push(cur)
      cur = ''
      any = false
      continue
    }
    cur += ch
    any = true
  }
  if (quoted) return undefined
  if (any) out.push(cur)
  return out
}

export type Edit = { argv: string[]; entry: string } | { error: string }

// An edit line -> `gate ...` argv (launch.sh runs it) and the entry whose
// pending changes `gate check` asks the person about next. Only these
// subcommands, each with its shape; names checked; nothing secret.
export function editArgv(line: string): Edit {
  const w = words(line)
  if (w === undefined) return { error: 'a quote is not closed' }
  if (w.length === 0) return { error: `type one of: ${EDIT_HINT}` }
  if (w.length > 12 || w.some((x) => !SAFE_WORD.test(x))) return { error: 'too many words, or a control character' }
  const [a, b] = w
  if (a === 'host' && b === 'add' && w.length >= 4 && NAME.test(w[2]!)) {
    if (w.slice(4).some((x) => !/^(ssh|sudo|scripts|note|runtime|via)=/.test(x))) return { error: 'host add takes KEY=VALUE for ssh, sudo, scripts, note, runtime, via' }
    return { argv: ['gate', ...w], entry: w[2]! }
  }
  if (a === 'host' && b === 'set' && w.length === 5 && (NAME.test(w[2]!) || w[2] === 'localhost') &&
      ['address', 'ssh', 'sudo', 'scripts', 'note', 'runtime', 'via'].includes(w[3]!)) {
    return { argv: ['gate', ...w], entry: w[2]! }
  }
  if (a === 'workspace' && b === 'add' && (w.length === 5 || w.length === 6) && (NAME.test(w[2]!) || w[2] === 'localhost') && NAME.test(w[3]!)) {
    return { argv: ['gate', ...w], entry: w[2]! }
  }
  if (a === 'workspace' && b === 'remove' && w.length === 4 && (NAME.test(w[2]!) || w[2] === 'localhost') && NAME.test(w[3]!)) {
    return { argv: ['gate', ...w], entry: w[2]! }
  }
  if (a === 'policy' && b === 'set' && w.length === 5 && (w[2] === 'all' || NAME.test(w[2]!) || w[2] === 'localhost') &&
      /^[a-z0-9_]{1,20}$/.test(w[3]!) && ['allow', 'ask', 'deny'].includes(w[4]!)) {
    return { argv: ['gate', ...w], entry: w[2] === 'all' ? 'settings' : w[2]! }
  }
  return { error: `not one of: ${EDIT_HINT}` }
}

// The last useful line a gate command printed (its own "gateway: ..." words).
export function lastLine(out: string, err: string): string {
  const lines = `${out}\n${err}`.split('\n').map((x) => clean(x).trim()).filter((x) => x !== '')
  return lines.length > 0 ? lines[lines.length - 1]!.slice(0, 300) : ''
}
