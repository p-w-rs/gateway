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
export const EDIT_HINT = 'host add NAME USER@HOST[:PORT] | host set NAME KEY VALUE | host set NAME ssh|sudo MODE=WORD... | account set NAME use WORD|MODE=WORD... | workspace add HOST NAME ROOT [LOCAL] | workspace remove HOST NAME | policy set all|HOST|ACCOUNT ACTION allow|ask|deny|cc|MODE=WORD... | network commands VALUE|MODE=WORD... | network extra|drop add|remove NAME'
// The /gate-accounts pane's edit line: an account's use (one word or per
// mode, like a host's ssh and sudo) and its policy.
export const ACCOUNTS_EDIT_HINT = 'account set NAME use true|ask|cc|false|MODE=WORD... | policy set ACCOUNT credential|write|network allow|ask|deny|cc|MODE=WORD...'
export const NAME = /^[a-z][a-z0-9-]{0,31}$/
const SAFE_WORD = /^[^\u0000-\u001f\u007f]{1,300}$/
// A per-mode token (PLAN-0.11 §2.9; manage.py's MODE_TOKEN says the same): the
// only shape in which an edit line's value words may hold "=".
export const MODE_TOKEN = /^(default|manual|plan|acceptEdits|auto|bypass|bypassPermissions|dontAsk)=(true|false|allow|deny|ask|cc)$/
// Claude Code's mode keys and names (modes.KEYS, modes.DISPLAY).
export const MODE_KEYS = ['default', 'plan', 'acceptEdits', 'auto', 'bypass', 'dontAsk'] as const
const MODE_NAMES: Record<string, string> = {
  default: 'Manual', plan: 'Plan', acceptEdits: 'Accept edits', auto: 'Auto', bypass: 'Bypass permissions', dontAsk: "Don't ask",
}
const MODE_WORDS = ['deny', 'ask', 'cc', 'allow']
const NETWORK_NAME = /^[A-Za-z0-9._-]{1,32}$/

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
  // ssh and sudo per mode (PLAN-0.11 §2.8): mode key -> deny | ask | cc | allow
  modes: Record<string, Record<string, string>>
  // the actions whose policy is a per-mode table: each one's decision per mode (§2.9)
  policy: Record<string, Record<string, string>>
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
  modes: Record<string, Record<string, string>>        // use per mode
  policy: Record<string, Record<string, string>>       // credential, write, network per mode (§2.9)
  pending: string[]
}
export type ManageView = { hosts: HostRow[]; workspaces: WorkspaceRow[]; accounts: AccountRow[]; settingsPending: string[] }

const str = (v: unknown, n = 200): string => (typeof v === 'string' ? clean(v).slice(0, n) : '')
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x) => typeof x === 'string').map((x) => clean(x as string).slice(0, 200)).slice(0, 20) : [])
const word = (v: unknown): string => (v === true ? 'yes' : v === false ? 'no' : typeof v === 'string' ? clean(v).slice(0, 40) : 'unknown')

export function clean(s: string): string {
  return s.replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, ' ')
}

// gated's per-mode values for the given keys: each a full six-mode map of
// known words, anything else dropped (never shown as an object).
function modeMaps(v: unknown, keys: string[]): Record<string, Record<string, string>> {
  const out: Record<string, Record<string, string>> = {}
  if (typeof v !== 'object' || v === null) return out
  for (const k of keys) {
    const m = (v as Record<string, unknown>)[k]
    if (typeof m !== 'object' || m === null) continue
    const mm = m as Record<string, unknown>
    if (MODE_KEYS.every((x) => typeof mm[x] === 'string' && MODE_WORDS.includes(mm[x] as string))) {
      out[k] = Object.fromEntries(MODE_KEYS.map((x) => [x, mm[x] as string]))
    }
  }
  return out
}

// A per-mode value in words (PLAN-0.11 §2.8): one word when every mode has
// it, else `Manual: ask · Auto: allow · Plan: deny` (Manual first, then the
// modes that differ from it).
export function modeText(m: Record<string, string>): string {
  const first = m.default ?? '?'
  if (MODE_KEYS.every((k) => m[k] === first)) return first
  return [`${MODE_NAMES.default}: ${first}`,
    ...MODE_KEYS.slice(1).filter((k) => m[k] !== first).map((k) => `${MODE_NAMES[k]}: ${m[k]}`)].join(' · ')
}

function modesPart(modes: Record<string, Record<string, string>>, keys: string[]): string {
  const parts = keys.filter((k) => modes[k] !== undefined).map((k) => `${k} ${modeText(modes[k]!)}`)
  return parts.length > 0 ? `; ${parts.join(', ')}` : ''
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
      auth: h.local === true ? 'yes' : word(h.auth), runtime: word(h.runtime), rights,
      modes: modeMaps(h.modes, ['ssh', 'sudo']), policy: modeMaps(h.policy_modes, RIGHT_ORDER),
      pending: strs(h.pending),
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
      credential: str(a.credential, 80), checkedAt: str(a.checked_at, 40), modes: modeMaps(a.modes, ['use']),
      policy: modeMaps(a.policy_modes, ACCOUNT_ORDER), pending: strs(a.pending),
    }
  }).filter((a) => NAME.test(a.account))
  return { hosts, workspaces, accounts, settingsPending: strs(r.settings_pending) }
}

const RIGHT_ORDER = ['read', 'exec', 'write', 'elevation', 'provision', 'network', 'credential', 'env_import',
  'forward_agent', 'forward_x11', 'forward_remote', 'forward_stdio']
const ACCOUNT_ORDER = ['credential', 'write', 'network']

// An action's per-mode decisions worth a word in a line: anything but the
// same allow (or Claude Code deciding) in every mode.
function policyShown(m: Record<string, string>): boolean {
  const first = m.default
  return !(MODE_KEYS.every((k) => m[k] === first) && (first === 'allow' || first === 'cc'))
}

// One host's state: where it is, whether it answers and takes the gateway's
// key, its runtime, its ssh and sudo per mode, and the actions that aren't
// simply allowed (an action whose policy is a per-mode table in §2.8's
// words, `write Manual: allow · Auto: deny`, never as one word).
export function hostLine(h: HostRow): string {
  const where = h.local ? 'this machine' : `remote${h.address !== '' ? ` ${h.address}` : ''}`
  const st = h.local ? `runtime ${h.runtime}` : `reachable ${h.reachable}, auth ${h.auth}, runtime ${h.runtime}`
  const not = RIGHT_ORDER.filter((k) => h.policy[k] !== undefined ? policyShown(h.policy[k]!)
    : h.rights[k] !== undefined && h.rights[k] !== 'allow' && !k.startsWith('forward_'))
    .map((k) => `${k} ${h.policy[k] !== undefined ? modeText(h.policy[k]!) : h.rights[k]}`)
  const fwd = RIGHT_ORDER.filter((k) => k.startsWith('forward_') && h.policy[k] === undefined && h.rights[k] === 'allow')
    .map((k) => k.replace('forward_', ''))
  const rights = not.length > 0 ? `; ${not.join(', ')}` : ''
  const fw = fwd.length > 0 ? `; forwarding: ${fwd.join(', ')}` : ''
  const pend = h.pending.length > 0 ? `; ${h.pending.length} change${h.pending.length === 1 ? '' : 's'} wait for your OK` : ''
  return `${h.name}: ${where}; ${st}${modesPart(h.modes, ['ssh', 'sudo'])}${rights}${fw}${pend}`
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
  const pol = ACCOUNT_ORDER.filter((k) => a.policy[k] !== undefined && policyShown(a.policy[k]!))
    .map((k) => `${k} ${modeText(a.policy[k]!)}`)
  return `${a.account} (${a.kind}): ${st}${who !== '' ? ` (${who})` : ''}${when}${modesPart(a.modes, ['use'])}` +
    `${pol.length > 0 ? `; ${pol.join(', ')}` : ''}${pend}`
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
  if (a === 'host' && b === 'set' && w.length >= 5 && (NAME.test(w[2]!) || w[2] === 'localhost') &&
      ['address', 'ssh', 'sudo', 'scripts', 'note', 'runtime', 'via'].includes(w[3]!)) {
    // ssh and sudo: one word or MODE=WORD tokens (a per-mode table); the rest one value
    if (['ssh', 'sudo'].includes(w[3]!) && (w.length > 5 || w[4]!.includes('='))) {
      if (!modeTokens(w.slice(4))) return { error: `${w[3]} per mode takes MODE=WORD tokens, default first: default=ask auto=true` }
    } else if (w.length !== 5) {
      return { error: `${w[3]} takes one value (only ssh and sudo take MODE=WORD)` }
    }
    return { argv: ['gate', ...w], entry: w[2]! }
  }
  if (a === 'account' && b === 'set' && w.length >= 5 && NAME.test(w[2]!) && w[3] === 'use') {
    // one word or MODE=WORD tokens (a per-mode table), as host set's ssh and sudo
    if (w.length > 5 || w[4]!.includes('=')) {
      if (!modeTokens(w.slice(4))) return { error: 'use per mode takes MODE=WORD tokens, default first: default=ask auto=true' }
    }
    return { argv: ['gate', ...w], entry: w[2]! }
  }
  if (a === 'workspace' && b === 'add' && (w.length === 5 || w.length === 6) && (NAME.test(w[2]!) || w[2] === 'localhost') && NAME.test(w[3]!)) {
    return { argv: ['gate', ...w], entry: w[2]! }
  }
  if (a === 'workspace' && b === 'remove' && w.length === 4 && (NAME.test(w[2]!) || w[2] === 'localhost') && NAME.test(w[3]!)) {
    return { argv: ['gate', ...w], entry: w[2]! }
  }
  if (a === 'policy' && b === 'set' && w.length >= 5 && (w[2] === 'all' || NAME.test(w[2]!) || w[2] === 'localhost') &&
      /^[a-z0-9_]{1,20}$/.test(w[3]!) &&
      ((w.length === 5 && ['allow', 'ask', 'deny', 'cc'].includes(w[4]!)) || modeTokens(w.slice(4)))) {
    return { argv: ['gate', ...w], entry: w[2] === 'all' ? 'settings' : w[2]! }
  }
  if (a === 'network' && b === 'commands' && w.length >= 3 &&
      ((w.length === 3 && ['allow', 'ask', 'deny', 'cc'].includes(w[2]!)) || modeTokens(w.slice(2)))) {
    return { argv: ['gate', ...w], entry: 'settings' }
  }
  if (a === 'network' && (b === 'extra' || b === 'drop') && w.length === 4 && ['add', 'remove'].includes(w[2]!) &&
      NETWORK_NAME.test(w[3]!) && w[3] !== '.' && w[3] !== '..') {
    return { argv: ['gate', ...w], entry: 'settings' }
  }
  return { error: `not one of: ${EDIT_HINT}` }
}

// MODE=WORD tokens only, each mode once (manual is default, bypassPermissions
// bypass), with default among them; manage.py checks the same again.
export function modeTokens(ws: string[]): boolean {
  if (ws.length === 0 || ws.length > MODE_KEYS.length || !ws.every((x) => MODE_TOKEN.test(x))) return false
  const keys = ws.map((x) => {
    const m = x.split('=')[0]!
    return m === 'manual' ? 'default' : m === 'bypassPermissions' ? 'bypass' : m
  })
  return new Set(keys).size === keys.length && keys.includes('default')
}

// The last useful line a gate command printed (its own "gateway: ..." words).
export function lastLine(out: string, err: string): string {
  const lines = `${out}\n${err}`.split('\n').map((x) => clean(x).trim()).filter((x) => x !== '')
  return lines.length > 0 ? lines[lines.length - 1]!.slice(0, 300) : ''
}
