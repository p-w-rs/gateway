// The gateway mod's pure logic (no `$`): where the plugin's data folder is,
// what `launch.sh status` says, the setup status line, the pixi verdict, the
// capability matrix and the /gate-doctor report. register.tsx wires it to the
// engine; lib.test.ts and register.test.ts test it under `claude plugin test`.
//
// Everything security-relevant stays in the classic hooks (hooks.json):
// Anthropic can switch mods off, and the guards must hold without them.

// pixi versions that install this plugin's lock (format v7) with the
// launcher's own `pixi install --locked --manifest-path`, tested 2026-10-19 on
// macOS arm64: 0.68.0, 0.69.0, 0.70.0, 0.81.0, 0.82.0 (0.61.0-0.67.0 refuse
// the lock). pixi.toml's requires-pixi is the lower bound, with no upper
// bound; a newer pixi only gets a warning here. tests/test_packaging.py
// keeps these, pixi.toml and the docs in step.
export const PIXI_TESTED_MIN = '0.68.0'
export const PIXI_TESTED_MAX = '0.82.0'

// Mods (hooks modules) load from these Claude Code versions on.
export const MODS_MIN_TERMINAL = '2.1.287'
export const MODS_MIN_DESKTOP = '2.1.286'

export const DOCTOR_COMMAND = 'gate-doctor'

// Managed execution (PLAN-v4 phase 4; docs/modules/managed.md): the prefix
// Claude Code runs every shell command through, the folder Python writes the
// managed shell's files to (named to gate-sh by GW_MANAGED_DIR), and the
// state.json /gate-doctor reads.
export const GATE_SH = 'hooks/gate-sh'

export type ManagedState = {
  mode: 'on' | 'warn' | 'off'
  formMode: string
  gateSh: string                  // the prefix to use: hooks/gate-sh, or the data folder's copy
  bash: string
  bashVersion: string
  ready: boolean
  path: { dir: string; origin: string }[]
  env: { name: string; origin: string }[]
  pending: string[]
  vaultReadable: boolean
}

const MODES: readonly string[] = ['on', 'warn', 'off']

export function parseManagedState(text: string | undefined): ManagedState | undefined {
  if (text === undefined || text.trim() === '') return undefined
  let v: unknown
  try {
    v = JSON.parse(text)
  } catch {
    return undefined
  }
  if (typeof v !== 'object' || v === null) return undefined
  const o = v as Record<string, unknown>
  if (typeof o.mode !== 'string' || !MODES.includes(o.mode)) return undefined
  const s = (k: string): string => (typeof o[k] === 'string' ? (o[k] as string) : '')
  const list = <T>(k: string, f: (x: Record<string, unknown>) => T | undefined): T[] =>
    Array.isArray(o[k]) ? (o[k] as unknown[]).map((x) => (typeof x === 'object' && x !== null ? f(x as Record<string, unknown>) : undefined)).filter((x): x is T => x !== undefined) : []
  return {
    mode: o.mode as ManagedState['mode'],
    formMode: s('form_mode'),
    gateSh: s('gate_sh'),
    bash: s('bash'),
    bashVersion: s('bash_version'),
    ready: o.ready === true,
    path: list('path', (x) => (typeof x.dir === 'string' ? { dir: x.dir, origin: typeof x.origin === 'string' ? x.origin : '' } : undefined)),
    env: list('env', (x) => (typeof x.name === 'string' ? { name: x.name, origin: typeof x.origin === 'string' ? x.origin : '' } : undefined)),
    pending: Array.isArray(o.pending) ? (o.pending as unknown[]).filter((x): x is string => typeof x === 'string') : [],
    vaultReadable: o.vault_readable !== false,
  }
}

// What the mod sets at session start: CLAUDE_CODE_SHELL_PREFIX (gate-sh)
// unless the effective mode is "off" or the plugin's path can't be carried
// by the prefix (Claude Code splits a prefix at its last " -" to allow flags);
// CLAUDE_CODE_SHELL (the managed bash, so even the shell Claude Code starts
// gate-sh from is the gateway's, not the login shell) once the env is ready.
// state.json (in the data folder, which a command can rewrite) decides only
// the mode and whether the data folder's gate-sh copy is the prefix (only
// that path, and only while it holds the plugin's gate-sh, copyOk); the
// managed bash comes from launch.sh's status (the env it names), never from
// state.json's `bash`. So a rewritten state.json can only take the prefix
// away (the classic Bash hook then denies in managed mode).
export type ManagedPlan = {
  dir: string
  prefix: string | undefined
  shell: string | undefined
  mode: 'on' | 'warn' | 'off'
  inactive: string | undefined    // why there is no prefix, in words
}

export function managedPlan(f: { root: string; data: string; state: ManagedState | undefined; envDir: string; envReady: boolean; copyOk?: boolean }): ManagedPlan {
  const mode = f.state?.mode ?? 'on'
  const dir = `${f.data.replace(/\/+$/, '')}/managed`
  const bash = f.envReady && f.envDir !== '' ? `${f.envDir.replace(/\/+$/, '')}/.pixi/envs/default/bin/bash` : undefined
  if (mode === 'off') {
    return { dir, prefix: undefined, shell: undefined, mode, inactive: 'gateway.toml [shell] managed = "off" (approved): Claude Code\'s own shell runs commands' }
  }
  // the plugin's gate-sh; the data folder's executable copy when Python wrote one (an
  // install that dropped the exec bit), and only that copy, by its exact place, while
  // its text is the plugin's gate-sh (copyOk: the caller compared the two)
  const own = gateShPaths(f.root, f.data).own
  const copy = gateShPaths(f.root, f.data).copy
  const prefix = f.state?.gateSh === copy && f.copyOk === true ? copy : own
  if (prefix.includes(' -')) {
    return { dir, prefix: undefined, shell: undefined, mode, inactive: 'the plugin\'s folder holds " -", which CLAUDE_CODE_SHELL_PREFIX can\'t carry (Claude Code splits the prefix there); the classic Bash hook reports it' }
  }
  return { dir, prefix, shell: bash, mode, inactive: undefined }
}

// The plugin's gate-sh and the data folder's copy (managed.gate_sh_copy).
export function gateShPaths(root: string, data: string): { own: string; copy: string } {
  return { own: `${root.replace(/\/+$/, '')}/${GATE_SH}`, copy: `${data.replace(/\/+$/, '')}/managed/gate-sh` }
}

// The doctor's managed-shell lines.
export function managedLines(plan: ManagedPlan | undefined, state: ManagedState | undefined, replaced: string, home: string): string[] {
  const c = (s: string): string => clean(s, home)
  const mode = state?.mode ?? plan?.mode ?? 'on'
  const out: string[] = []
  let session: string
  if (plan === undefined) session = 'not set up in this session (the mod couldn\'t locate its data folder)'
  else if (plan.prefix === undefined) session = `inactive: ${c(plan.inactive ?? "no prefix")}`
  else session = `active (CLAUDE_CODE_SHELL_PREFIX = ${c(plan.prefix)}${plan.shell !== undefined ? '; Claude Code starts it from the managed bash' : ''})`
  out.push(`Managed shell: ${mode}; this session: ${session}`)
  if (replaced !== '') out.push(`  replaced another CLAUDE_CODE_SHELL_PREFIX (${c(replaced)}) for managed mode`)
  if (state === undefined) {
    out.push('  its settings aren\'t written yet (the gateway\'s setup writes them at session start)')
    return out
  }
  if (state.formMode !== '' && state.formMode !== state.mode) out.push(`  gateway.toml says "${state.formMode}"; that waits for the user's OK (gate check settings)`)
  out.push(`  bash: ${state.ready ? `${c(state.bash)} (${state.bashVersion})` : 'not ready yet (the gateway is still setting up)'}`)
  out.push(`  PATH: ${state.path.map((p) => `${c(p.dir)} (${p.origin})`).join('; ')}; then other plugins' bin/ folders`)
  out.push(`  Environment: platform variables, SHELL, Claude Code's own; imported: ${state.env.length > 0 ? state.env.map((e) => `${e.name} (${e.origin})`).join('; ') : 'nothing'}`)
  if (state.pending.length > 0) out.push(`  waiting for the user's OK: ${state.pending.join('; ')}`)
  if (!state.vaultReadable) out.push('  the vault was locked when these were written: approved imports apply after /gate-unlock')
  return out
}

export type EnvState = 'ready' | 'building' | 'failed' | 'nopixi' | 'missing'

// One line of `sh hooks/launch.sh status [pixi]`.
export type EnvStatus = {
  state: EnvState
  root: string
  data: string
  env: string
  lock: string
  warm: boolean
  managed: boolean        // the managed shell's settings are written (gate-sh runs nothing before)
  older: string
  build_running: boolean
  install_log: boolean
  pixi: string
  pixi_version: string
  home: string
  form: boolean
  vault: boolean
  vault_v2: boolean
}

const STATES: readonly string[] = ['ready', 'building', 'failed', 'nopixi', 'missing']

export function parseStatus(stdout: string): EnvStatus | undefined {
  const line = stdout.split('\n').find((l) => l.trim().startsWith('{'))
  if (line === undefined) return undefined
  let v: unknown
  try {
    v = JSON.parse(line)
  } catch {
    return undefined
  }
  if (typeof v !== 'object' || v === null) return undefined
  const o = v as Record<string, unknown>
  if (typeof o.state !== 'string' || !STATES.includes(o.state)) return undefined
  const s = (k: string): string => (typeof o[k] === 'string' ? (o[k] as string) : '')
  const b = (k: string): boolean => o[k] === true
  return {
    state: o.state as EnvState,
    root: s('root'), data: s('data'), env: s('env'), lock: s('lock'), warm: b('warm'),
    // absent (a launch.sh before 0.9.1): counted as written, as it then was
    managed: o.managed !== false,
    older: s('older'), build_running: b('build_running'), install_log: b('install_log'),
    pixi: s('pixi'), pixi_version: s('pixi_version'), home: s('home'), form: b('form'),
    vault: b('vault'), vault_v2: b('vault_v2'),
  }
}

// Where Claude Code keeps this plugin's data (what its hooks get as
// CLAUDE_PLUGIN_DATA, which a mod is not given): an installed copy lives in
// <config>/plugins/cache/<marketplace>/<plugin>/<version>, its data in
// <config>/plugins/data/<plugin>-<marketplace>; a plugin loaded with
// --plugin-dir has <config>/plugins/data/<plugin>-inline. (A folder
// marketplace read in place is not a supported install: installs come from a
// git source; README.)
export type Located = { data: string; provenance: string; how: 'installed' | 'folder' }

const safeName = (s: string): string => s.replace(/[^A-Za-z0-9_-]/g, '-')

export function locate(root: string, name: string, configDir: string): Located {
  const m = /^(.*)\/plugins\/cache\/([^/]+)\/[^/]+\/[^/]+\/?$/.exec(root)
  if (m !== null && m[1] !== undefined && m[2] !== undefined) {
    return {
      data: `${m[1]}/plugins/data/${safeName(name)}-${safeName(m[2])}`,
      provenance: `${name}@${m[2]}`,
      how: 'installed',
    }
  }
  return {
    data: `${configDir.replace(/\/+$/, '')}/plugins/data/${safeName(name)}-inline`,
    provenance: `${name}@inline`,
    how: 'folder',
  }
}

// Version compare of dotted numbers ("0.81.0" < "0.82.0"); missing parts count 0.
export function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map((x) => parseInt(x, 10) || 0)
  const pb = b.split('.').map((x) => parseInt(x, 10) || 0)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0)
    if (d !== 0) return d < 0 ? -1 : 1
  }
  return 0
}

export function parsePixiVersion(s: string): string | undefined {
  const m = /(\d+\.\d+\.\d+)/.exec(s)
  return m === null ? undefined : m[1]
}

export type PixiVerdict = { kind: 'tested' | 'newer' | 'older' | 'unknown'; text: string }

export function pixiVerdict(version: string | undefined): PixiVerdict {
  const range = `${PIXI_TESTED_MIN}-${PIXI_TESTED_MAX}`
  if (version === undefined) return { kind: 'unknown', text: `version unknown (tested range ${range})` }
  if (compareVersions(version, PIXI_TESTED_MIN) < 0) {
    return {
      kind: 'older',
      text: `${version} is older than ${PIXI_TESTED_MIN}, which this plugin needs (its lock is format v7); update pixi (pixi self-update)`,
    }
  }
  if (compareVersions(version, PIXI_TESTED_MAX) > 0) {
    return {
      kind: 'newer',
      text: `${version} is newer than the tested range ${range} (a warning only: it should work; if setup fails, say so)`,
    }
  }
  return { kind: 'tested', text: `${version}, inside the tested range ${range}` }
}

export function formatElapsed(ms: number): string {
  const s = Math.max(0, Math.floor(ms / 1000))
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`
}

// Should the mod start provisioning? Only when nothing is building, pixi is
// there and the env isn't ready (missing, or an earlier attempt failed or was
// killed: its lock is stale). A build the async classic hook already runs
// shows as `building`; were the two to start at once, the build lock makes
// the second one wait (launch.sh), so there is never a duplicate build.
export function shouldProvision(st: EnvStatus | undefined): boolean {
  return st !== undefined && (st.state === 'missing' || st.state === 'failed')
}

// Is SHLVL one that keeps a `bash -c` with a socket on stdin from sourcing
// ~/.bashrc (bash counts itself started by sshd/rshd at shell level 1: SHLVL
// unset, 0 or garbage; from 1000 on bash resets it to 1)? The mod sets 1
// otherwise (managedSetup; docs/modules/managed.md, "Known limits").
export function shlvlOk(v: string | undefined): boolean {
  return v !== undefined && /^[1-9][0-9]{0,2}$/.test(v) && Number(v) < 999
}

// Is setup done, so that Claude's commands run? The env is built and, when
// this session runs them through the managed shell (`managed`: the mod set
// the prefix), the managed shell's settings are written too: launch.sh
// ensure-env writes them right after the build, and until then gate-sh
// refuses every command (exit 75), so "ready" must wait for them.
export function setupReady(st: EnvStatus | undefined, managed: boolean): boolean {
  return st !== undefined && st.state === 'ready' && (st.managed || !managed)
}

// The status line under the prompt while the gateway can't run yet. Claude
// Code draws it after the plugin's name ("gate: setting up… 0:12"), so the
// text doesn't repeat it.
export function statusLine(st: EnvStatus | undefined, elapsedMs: number, managed = false): string | undefined {
  if (st === undefined) return undefined
  switch (st.state) {
    case 'ready':
      return setupReady(st, managed) ? 'ready' : `finishing setup… ${formatElapsed(elapsedMs)}`
    case 'building':
    case 'missing':
      return `setting up… ${formatElapsed(elapsedMs)}`
    case 'failed':
      return `setup failed; /${DOCTOR_COMMAND} says why`
    case 'nopixi':
      return `pixi isn't installed (https://pixi.sh); /${DOCTOR_COMMAND}`
  }
}

// The capability matrix (docs/CAPABILITIES.md has the same rows and cells,
// with notes; tests/test_mod.py keeps the two in step). Cells: 'yes' (works,
// and was exercised on macOS arm64 with Claude Code 2.1.301), 'untested'
// (expected to work, not exercised), 'no' (not available there), 'planned'
// (a later PLAN-v4 phase). One row per line, every cell spelled out.
export type Cell = 'yes' | 'no' | 'planned' | 'untested'
export type Surface = 'terminal' | 'desktop' | 'vscode' | 'mobile' | 'print' | 'remote'
export type CapabilityRow = {
  feature: string
  cells: Record<Surface, Cell>
  min: string
  withoutMods: boolean
}

export const CAPABILITIES: readonly CapabilityRow[] = [
  { feature: 'Bash approval hook, file guard, output masking, paste guard (classic hooks)', cells: { terminal: 'yes', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'yes', remote: 'untested' }, min: '2.1.299 (tested)', withoutMods: true },
  { feature: 'Stand-ins on PATH (sudo, ssh, git, gh, ...) and the gw MCP tools (http, download)', cells: { terminal: 'untested', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'yes', remote: 'untested' }, min: '2.1.299 (tested)', withoutMods: true },
  { feature: 'Cold-start guard while the env builds (sh, no Python)', cells: { terminal: 'yes', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'yes', remote: 'untested' }, min: '2.1.301 (tested)', withoutMods: true },
  { feature: '/gate:status and /gate:help (Markdown commands, a model turn)', cells: { terminal: 'untested', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'untested', remote: 'untested' }, min: '2.1.299 (tested)', withoutMods: true },
  { feature: '/gate-doctor (immediate, no model turn)', cells: { terminal: 'yes', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'yes', remote: 'untested' }, min: '2.1.287 terminal, 2.1.286 desktop', withoutMods: false },
  { feature: 'Setup status line and provisioning at session start (mod)', cells: { terminal: 'yes', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'no', remote: 'untested' }, min: '2.1.287 terminal, 2.1.286 desktop', withoutMods: false },
  { feature: 'Gateway daemon (gated): CONTRACT-v1 discovery, snapshot and events; the vault broker', cells: { terminal: 'yes', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'untested', remote: 'untested' }, min: '2.1.301 (tested)', withoutMods: true },
  { feature: 'Native gateway dialogs: credential field with sealed delivery, consent, host key, vault passphrase; /gate-dialog, /gate-unlock, /gate-lock', cells: { terminal: 'yes', desktop: 'untested', vscode: 'no', mobile: 'no', print: 'no', remote: 'no' }, min: '2.1.301 (tested)', withoutMods: false },
  { feature: 'Managed shell (CLAUDE_CODE_SHELL_PREFIX -> gate-sh): Bash, background, ! commands, subagents, skill injection', cells: { terminal: 'yes', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'yes', remote: 'untested' }, min: '2.1.301 (tested)', withoutMods: false },
  { feature: 'Terminals and jobs (tmux supervisor in gated): gw terminal_* and job_* tools, CONTRACT-v1 job routes, password prompts through the dialog', cells: { terminal: 'yes', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'untested', remote: 'untested' }, min: '2.1.301 (tested)', withoutMods: true },
  { feature: 'Remote terminals and jobs (the managed remote runtime over ssh): host on terminal_open, job_start and CONTRACT-v1 jobs, host_runtime, the host key and machine checks', cells: { terminal: 'untested', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'untested', remote: 'untested' }, min: '2.1.299 (the gw tools)', withoutMods: true },
  { feature: 'Shared terminal pane and takeover (Client): /gate-terminal', cells: { terminal: 'yes', desktop: 'untested', vscode: 'no', mobile: 'no', print: 'no', remote: 'no' }, min: '2.1.301 (tested)', withoutMods: false },  { feature: 'Policy (allow, ask, deny per host, workspace, account and action), workspaces, forwarding grants, account states, export and import format 3', cells: { terminal: 'untested', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'untested', remote: 'untested' }, min: '2.1.299 (the hooks and stand-ins)', withoutMods: true },
  { feature: 'Hosts and accounts panes (immediate): /gate-hosts, /gate-accounts', cells: { terminal: 'untested', desktop: 'untested', vscode: 'no', mobile: 'no', print: 'no', remote: 'no' }, min: '2.1.287 terminal, 2.1.286 desktop', withoutMods: false },
]

const SURFACE_NAMES: Record<Surface, string> = {
  terminal: 'terminal', desktop: 'desktop app', vscode: 'VS Code', mobile: 'mobile',
  print: '-p / SDK', remote: 'Remote Control',
}

// The surfaces a session draws on, as matrix columns (no surface: -p / SDK).
export function sessionColumns(surfaces: readonly string[]): Surface[] {
  if (surfaces.length === 0) return ['print']
  const out: Surface[] = []
  for (const s of surfaces) {
    const c: Surface | undefined = s === 'terminal' || s === 'desktop' || s === 'vscode' || s === 'mobile' ? s : undefined
    if (c !== undefined && !out.includes(c)) out.push(c)
  }
  return out.length > 0 ? out : ['terminal']
}

export function capabilityLines(surfaces: readonly string[]): string[] {
  const cols = sessionColumns(surfaces)
  return CAPABILITIES.map((r) => {
    const cells = cols.map((c) => (cols.length > 1 ? `${SURFACE_NAMES[c]} ${r.cells[c]}` : r.cells[c])).join(', ')
    return `  - ${r.feature}: ${cells}${r.withoutMods ? ' (works without mods)' : ''}`
  })
}

// Text safe to show: no control characters, the home folder as ~.
export function clean(s: string, home: string): string {
  let t = s.replace(/[\u0000-\u001f\u007f]/g, '?')
  if (home.length > 1 && (t === home || t.startsWith(home + '/'))) t = '~' + t.slice(home.length)
  return t
}

// The gateway daemon (PLAN-v4 phase 2): one JSON line from `sh hooks/launch.sh
// gated status|start`, which is its GET /health (start also starts it and
// names the Claude Code process as parent_pid when that is its parent).
export type DaemonHealth = {
  running: boolean
  version: string
  epoch: number
  uptime: number
  vault: string
  sessions: number
  socket: string
  parentPid: number
  skew: string
  terminals: number        // live gateway terminals and jobs (PLAN-v4 phase 5)
  jobs: number
}

export function parseDaemon(stdout: string): DaemonHealth | undefined {
  const line = stdout.split('\n').find((l) => l.trim().startsWith('{'))
  if (line === undefined) return undefined
  let v: unknown
  try {
    v = JSON.parse(line)
  } catch {
    return undefined
  }
  if (typeof v !== 'object' || v === null) return undefined
  const o = v as Record<string, unknown>
  const s = (k: string): string => (typeof o[k] === 'string' ? (o[k] as string) : '')
  const n = (k: string): number => (typeof o[k] === 'number' && Number.isFinite(o[k]) ? (o[k] as number) : 0)
  return {
    running: o.ok === true, version: s('version'), epoch: n('epoch'), uptime: n('uptime'),
    vault: s('vault'), sessions: n('sessions'), socket: s('socket'), parentPid: n('parent_pid'),
    skew: s('skew'), terminals: n('terminals'), jobs: n('jobs'),
  }
}

export function formatUptime(sec: number): string {
  const s = Math.max(0, Math.floor(sec))
  if (s < 120) return `${s} s`
  if (s < 7200) return `${Math.floor(s / 60)} min`
  return `${Math.floor(s / 3600)} h ${Math.floor((s % 3600) / 60)} min`
}

const VAULT_WORDS: Record<string, string> = {
  none: 'not set up yet (no key)',
  unwrapped: 'unwrapped (its key has no passphrase)',
  locked: 'locked (its key has a passphrase)',
  unlocked: 'unlocked (its key has a passphrase)',
}

// The doctor's daemon line: running, version, epoch, uptime, sessions and the
// vault key's state, or why there is none.
export function daemonLine(d: DaemonHealth | undefined): string {
  if (d === undefined) return "Gateway daemon: unknown (it can't be asked until setup finishes)"
  if (!d.running) return 'Gateway daemon: not running (it starts when a session or tool needs it)'
  const vault = VAULT_WORDS[d.vault] ?? (d.vault === '' ? 'unknown' : d.vault)
  const sessions = `${d.sessions} session${d.sessions === 1 ? '' : 's'}`
  const panes = [d.terminals > 0 ? `${d.terminals} terminal${d.terminals === 1 ? '' : 's'}` : '',
    d.jobs > 0 ? `${d.jobs} job${d.jobs === 1 ? '' : 's'}` : ''].filter((x) => x !== '').join(', ')
  const skew = d.skew !== '' ? `; ${d.skew}` : ''
  return `Gateway daemon: running (${d.version || '?'}, epoch ${d.epoch}, up ${formatUptime(d.uptime)}, ${sessions}${panes !== '' ? `, ${panes}` : ''}); vault ${vault}${skew}`
}

export type DoctorFacts = {
  pluginVersion: string | undefined
  claude: { version: string; base?: string } | undefined
  surfaces: readonly string[]
  located: Located
  status: EnvStatus | undefined
  daemon?: DaemonHealth | undefined
  managed?: { plan: ManagedPlan | undefined; state: ManagedState | undefined; replaced: string }
}

function envLine(st: EnvStatus, home: string): string {
  const env = clean(st.env, home)
  switch (st.state) {
    case 'ready':
      return `ready${st.warm ? ' (warmed)' : ''} at ${env}${st.managed ? '' : "; the managed shell's settings aren't written yet"}`
    case 'building':
      return `being set up (a build is running) at ${env}${st.older ? `; meanwhile the hooks run on ${clean(st.older, home)}` : ''}`
    case 'failed':
      return `setup failed or was interrupted; log: ${env}/install.log (retried at the next session start)`
    case 'nopixi':
      return "can't be set up: pixi isn't installed (https://pixi.sh), then start a new session"
    case 'missing':
      return `not built yet (${env})`
  }
}

// The /gate-doctor report: versions, surfaces, mods, pixi and its tested
// range, the env, managed mode, vault presence (existence only), the gateway
// daemon's state (its /health), and the capability matrix rows for this
// session's surfaces. No secret can be in it:
// it is built from versions, paths and yes/no facts only.
export function doctorText(f: DoctorFacts): string {
  const st = f.status
  const userHome = st !== undefined && st.home.endsWith('/.config/gateway') ? st.home.slice(0, -'/.config/gateway'.length) : ''
  const c = (s: string): string => clean(s, userHome)
  const lines: string[] = []
  // Claude Code shows the output after the plugin's name ("gate: gateway plugin 0.7.0 ...")
  lines.push(`gateway plugin ${f.pluginVersion ?? '(version unknown)'} (${f.located.provenance}), diagnostics`)
  lines.push(`Claude Code: ${f.claude?.version ?? 'unknown'} (mods need ${MODS_MIN_TERMINAL} in the terminal, ${MODS_MIN_DESKTOP} in the desktop app)`)
  lines.push(`Surfaces: ${f.surfaces.length > 0 ? f.surfaces.join(', ') : 'none (-p or SDK)'}`)
  lines.push('Mods: on (this report comes from the gateway mod)')
  // launch.sh's answer is what the hooks use; the mod's own reading of the
  // install path is the fallback
  const data = st !== undefined && st.data !== '' ? st.data : f.located.data
  lines.push(`Data folder: ${c(data)} (${f.located.how === 'installed' ? 'installed copy' : 'loaded from a folder, --plugin-dir'})`)
  if (st === undefined) {
    lines.push("Environment: unknown (hooks/launch.sh status didn't answer)")
  } else {
    const pv = parsePixiVersion(st.pixi_version)
    lines.push(st.pixi === '' ? "pixi: not found (install it from https://pixi.sh)" : `pixi: ${c(st.pixi)}, ${pixiVerdict(pv).text}`)
    lines.push(`Environment: ${envLine(st, userHome)}`)
  }
  lines.push(...managedLines(f.managed?.plan, f.managed?.state, f.managed?.replaced ?? '', userHome))
  if (st !== undefined) {
    const vault = st.vault
      ? 'present'
      : st.vault_v2
        ? 'a 0.6 vault (store.age), converted once setup finishes'
        : 'not set up yet'
    lines.push(`Vault: ${vault}; form (gateway.toml): ${st.form ? 'present' : 'not written yet'} (checked by existence only; the vault is never read)`)
  }
  lines.push(clean(daemonLine(f.daemon), userHome))
  lines.push(`Capabilities here (Claude Code ${f.claude?.version ?? '?'}, ${sessionColumns(f.surfaces).map((s) => SURFACE_NAMES[s]).join(' + ')}):`)
  lines.push(...capabilityLines(f.surfaces))
  lines.push('Full matrix: docs/CAPABILITIES.md in the gateway repository.')
  return lines.join('\n')
}
