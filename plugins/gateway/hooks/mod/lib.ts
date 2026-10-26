// The gateway mod's pure logic (no `$`): where the plugin's data folder is,
// what `launch.sh status` says, the setup status line, the version verdicts, the
// capability matrix and the /gate-doctor report. register.tsx wires it to the
// engine; lib.test.ts and register.test.ts test it under `claude plugin test`.
//
// Everything security-relevant stays in the classic hooks (hooks.json):
// Anthropic can switch mods off, and the guards must hold without them.

import { FULLSCREEN_HINT, MAIN_KEYS, NO_DISPLAY, NO_DISPLAY_TODO, PASTE_NOTE } from './dialog.ts'

// Latest only (PLAN-0.11 section 5): the one pixi and the one Claude Code this
// release is tested with. PIXI_TESTED is the pixi that made pixi.lock, the
// newest at the relock, and pixi.toml's requires-pixi is ">=" it
// (tests/update_deps.py sets both; tests/test_packaging.py keeps them in
// step). CLAUDE_TESTED is the Claude Code the live acceptance runs used. An
// older version gets a warning (update: only the latest is supported), a
// newer one an info line.
export const PIXI_TESTED = '0.83.0'
export const CLAUDE_TESTED = '2.1.310'

export const DOCTOR_COMMAND = 'gate-doctor'

// How pixi is updated: its own self-update, or the package manager that
// installed it (pixi self-update refuses a Homebrew or MacPorts pixi).
export const PIXI_UPDATE = 'pixi self-update, or your package manager for a Homebrew or MacPorts pixi'

// Managed execution (PLAN-v4 phase 4; docs/dev/modules/managed.md): the prefix
// Claude Code runs every shell command through, the folder Python writes the
// managed shell's files to (named to gate-sh by GW_MANAGED_DIR), and the
// state.json /gate-doctor reads.
export const GATE_SH = 'hooks/gate-sh'

export type ManagedState = {
  mode: 'on' | 'off'
  formMode: string
  gateSh: string                  // the prefix to use: hooks/gate-sh, or the data folder's copy
  bash: string
  bashVersion: string
  ready: boolean
  path: { dir: string; origin: string }[]
  env: { name: string; origin: string }[]
  pending: string[]
  vaultReadable: boolean
  found: string[]                 // tool folders here the managed PATH lacks (managed.found_not_imported)
}

// PLAN-0.11 §1.6: "warn" is gone (a written one is a mistake and counts as "on")
const MODES: readonly string[] = ['on', 'off']

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
    found: Array.isArray(o.found) ? (o.found as unknown[]).filter((x): x is string => typeof x === 'string').slice(0, 8) : [],
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
// away: Claude's commands then run in the user's own shell, still judged by
// the classic Bash hook (PLAN-0.11 §1.8: no refusal, a notice once).
export type ManagedPlan = {
  dir: string
  prefix: string | undefined
  shell: string | undefined
  mode: 'on' | 'off'
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
    return { dir, prefix: undefined, shell: undefined, mode, inactive: 'the plugin\'s folder holds " -", which CLAUDE_CODE_SHELL_PREFIX can\'t carry (Claude Code splits the prefix there); Claude\'s commands run in your own shell (the classic Bash hook still judges them)' }
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
  out.push(`  PATH: ${state.path.map((p) => `${c(p.dir)} (${p.origin})`).join('; ')} (other plugins' bin/ folders come before the imports)`)
  out.push(`  Environment: yours (Claude Code's), minus Claude Code's own credential variables, the shell startup variables and the gateway's GW_* names; SHELL is the managed bash${state.env.length > 0 ? `; [shell] import_env: ${state.env.map((e) => `${e.name} (${e.origin})`).join('; ')}` : ''}`)
  if (state.pending.length > 0) out.push(`  waiting for the user's OK: ${state.pending.join('; ')}`)
  if (state.found.length > 0) out.push(`  found here but not imported: ${state.found.map(c).join(', ')} (Claude can propose importing them: [shell] import_path, then your OK in the gateway's dialog)`)
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
  // the last build failed because pixi refused the manifest ("requires
  // pixi"): the pixi it found and the requires-pixi it needs
  pixi_too_old: boolean
  pixi_found: string
  pixi_needed: string
  home: string
  form: boolean
  vault: boolean
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
    managed: b('managed'),
    older: s('older'), build_running: b('build_running'), install_log: b('install_log'),
    pixi: s('pixi'), pixi_version: s('pixi_version'),
    pixi_too_old: b('pixi_too_old'), pixi_found: s('pixi_found'), pixi_needed: s('pixi_needed'),
    home: s('home'), form: b('form'), vault: b('vault'),
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

// /gate-doctor's verdict on a version against the one tested (latest only,
// PLAN-0.11 section 5): the tested one is fine, an older one is a warning
// with the way to update, a newer one an info line.
export type VersionVerdict = { kind: 'tested' | 'newer' | 'older' | 'unknown'; text: string }

function versionVerdict(version: string | undefined, tested: string, update: string): VersionVerdict {
  if (version === undefined) return { kind: 'unknown', text: `version unknown (tested with ${tested})` }
  const c = compareVersions(version, tested)
  if (c < 0) return { kind: 'older', text: `${version}, older than the tested ${tested}: warning: ${update}: only the latest is supported` }
  if (c > 0) return { kind: 'newer', text: `${version}, newer than the tested ${tested} (info: it should work; if something fails, say so)` }
  return { kind: 'tested', text: `${version}, the tested version` }
}

export function pixiVerdict(version: string | undefined): VersionVerdict {
  return versionVerdict(version, PIXI_TESTED, `update pixi (${PIXI_UPDATE})`)
}

export function claudeVerdict(version: string | undefined): VersionVerdict {
  return versionVerdict(version, CLAUDE_TESTED, 'update Claude Code (claude update)')
}

// What the doctor and the status line say when the last build failed
// because pixi refused the manifest (launch.sh status: pixi_too_old).
export function pixiTooOldText(st: EnvStatus): string {
  const found = st.pixi_found !== '' ? `pixi ${st.pixi_found}` : 'this pixi'
  const needed = st.pixi_needed !== '' ? ` (the gateway needs pixi ${st.pixi_needed})` : ''
  return `${found} is too old${needed}; update pixi (${PIXI_UPDATE}), then start a new session`
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
// otherwise (managedSetup; docs/dev/modules/managed.md, "Known limits").
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
      return st.pixi_too_old ? `pixi is too old: update it; /${DOCTOR_COMMAND} says how` : `setup failed; /${DOCTOR_COMMAND} says why`
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
  withoutMods: boolean
}

export const CAPABILITIES: readonly CapabilityRow[] = [
  { feature: 'Bash approval hook, file guard, output masking, paste guard (classic hooks)', cells: { terminal: 'yes', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'yes', remote: 'untested' }, withoutMods: true },
  { feature: 'Stand-ins on PATH (sudo, ssh, git, gh, ...) and the gw MCP tools (http, download)', cells: { terminal: 'untested', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'yes', remote: 'untested' }, withoutMods: true },
  { feature: 'Cold-start guard while the env builds (sh, no Python)', cells: { terminal: 'yes', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'yes', remote: 'untested' }, withoutMods: true },
  { feature: '/gate:status and /gate:help (Markdown commands, a model turn)', cells: { terminal: 'untested', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'untested', remote: 'untested' }, withoutMods: true },
  { feature: '/gate-doctor (immediate, no model turn)', cells: { terminal: 'yes', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'yes', remote: 'untested' }, withoutMods: false },
  { feature: 'Setup status line and provisioning at session start (mod)', cells: { terminal: 'yes', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'no', remote: 'untested' }, withoutMods: false },
  { feature: 'Gateway daemon (gated): CONTRACT-v1 discovery, snapshot and events; the vault broker', cells: { terminal: 'yes', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'untested', remote: 'untested' }, withoutMods: true },
  { feature: 'Native gateway dialogs: credential field with sealed delivery, consent, host key, vault passphrase; /gate-dialog, /gate-unlock, /gate-lock', cells: { terminal: 'yes', desktop: 'untested', vscode: 'no', mobile: 'no', print: 'no', remote: 'no' }, withoutMods: false },
  { feature: 'Managed shell (CLAUDE_CODE_SHELL_PREFIX -> gate-sh): Bash, background, ! commands, subagents, skill injection', cells: { terminal: 'yes', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'yes', remote: 'untested' }, withoutMods: false },
  { feature: 'Terminals and jobs (tmux supervisor in gated): gw terminal_* and job_* tools, CONTRACT-v1 job routes, password prompts through the dialog', cells: { terminal: 'yes', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'untested', remote: 'untested' }, withoutMods: true },
  { feature: 'Remote terminals and jobs (the managed remote runtime over ssh): host on terminal_open, job_start and CONTRACT-v1 jobs, host_runtime, the host key and machine checks', cells: { terminal: 'untested', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'untested', remote: 'untested' }, withoutMods: true },
  { feature: 'Shared terminal pane and takeover (Client): /gate-terminal', cells: { terminal: 'yes', desktop: 'untested', vscode: 'no', mobile: 'no', print: 'no', remote: 'no' }, withoutMods: false },
  { feature: 'Policy (allow, ask, deny per host, workspace, account and action), workspaces, forwarding grants, account states, export and import format 3', cells: { terminal: 'untested', desktop: 'untested', vscode: 'untested', mobile: 'untested', print: 'untested', remote: 'untested' }, withoutMods: true },
  { feature: 'Hosts and accounts panes (immediate): /gate-hosts, /gate-accounts', cells: { terminal: 'untested', desktop: 'untested', vscode: 'no', mobile: 'no', print: 'no', remote: 'no' }, withoutMods: false },
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
  claudeInstall: string    // how the Claude Code that asked was installed ("" not recognized)
  parentExe: string        // what asked, when it isn't recognized as Claude Code
  error: string            // why it can't run ("run_dir": its run folder can't be used)
  message: string          // ... in words, with the remedy
  otherConfig: string      // it serves another Claude Code configuration: in words ("" it serves this one)
  platform: string         // this machine's sys.platform ("linux", "darwin"; "" from an older gated)
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
    claudeInstall: s('claude_install'), parentExe: s('parent_exe'),
    error: s('error'), message: s('message'), otherConfig: s('other_config'), platform: s('platform'),
  }
}

// gated's answer to /ui/register: refused because it is stopping (its idle
// exit began: 503 "stopping")? Then the session isn't registered, and
// `gated start` (which waits for the old daemon to go) makes a new one to
// register with. A 200 is a session gated serves.
export const REGISTER_TRIES = 3
export function registerStopping(status: number, text: string): boolean {
  if (status !== 503) return false
  try {
    const v: unknown = JSON.parse(text)
    return typeof v === 'object' && v !== null && (v as Record<string, unknown>).error === 'stopping'
  } catch {
    return false
  }
}

// The doctor's install line: how this Claude Code was installed, as the
// gateway daemon's side sees it (`gated status` names the process that ran
// it: ancestry.claude_install). One it doesn't recognize as Claude Code can't
// register with the daemon, so no gateway dialog can open in it.
export function installLine(d: DaemonHealth | undefined): string | undefined {
  if (d === undefined) return undefined
  if (d.claudeInstall !== '') return `Claude Code install: ${d.claudeInstall}`
  if (d.parentExe === '') return undefined
  return `Claude Code install: not recognized (the process that asked is ${d.parentExe}): the gateway daemon can't register this session, so no gateway dialog (credentials, consent, sudo) can open. Recognized: the native installer, npm (@anthropic-ai/claude-code), the desktop app, an executable named claude`
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
  // its run folder can't be used (another user's, a link, open to others):
  // gated's own explanation and remedy (GW-ROB-1)
  if (!d.running && d.error === 'run_dir' && d.message !== '') return `Gateway daemon: can't start: ${d.message.replace(/^gateway: /, '')}`
  if (!d.running) return 'Gateway daemon: not running (it starts when a session or tool needs it)'
  const vault = VAULT_WORDS[d.vault] ?? (d.vault === '' ? 'unknown' : d.vault)
  const sessions = `${d.sessions} session${d.sessions === 1 ? '' : 's'}`
  const panes = [d.terminals > 0 ? `${d.terminals} terminal${d.terminals === 1 ? '' : 's'}` : '',
    d.jobs > 0 ? `${d.jobs} job${d.jobs === 1 ? '' : 's'}` : ''].filter((x) => x !== '').join(', ')
  const skew = d.skew !== '' ? `; ${d.skew}` : ''
  // a second Claude Code configuration: the daemon answers, but serves the
  // other one's data folder (`gated status`'s other_config; review round 2)
  const other = d.otherConfig !== '' ? `; ${d.otherConfig}` : ''
  return `Gateway daemon: running (${d.version || '?'}, epoch ${d.epoch}, up ${formatUptime(d.uptime)}, ${sessions}${panes !== '' ? `, ${panes}` : ''}); vault ${vault}${skew}${other}`
}

export type DoctorFacts = {
  pluginVersion: string | undefined
  claude: { version: string; base?: string } | undefined
  surfaces: readonly string[]
  located: Located
  status: EnvStatus | undefined
  daemon?: DaemonHealth | undefined
  managed?: { plan: ManagedPlan | undefined; state: ManagedState | undefined; replaced: string }
  fullscreen?: boolean | undefined    // command.run's presentation.isFullscreen
  tmux?: boolean                      // TMUX is set
  noDisplay?: boolean                 // Linux without DISPLAY or WAYLAND_DISPLAY (noDisplayHere)
}

// Linux without a graphical display in Claude Code's environment: gated
// reads the clipboard with wl-paste (WAYLAND_DISPLAY) or xclip/xsel
// (DISPLAY), so without either Paste can't work (review round 2).
export function noDisplayHere(platform: string, display: string | undefined, wayland: string | undefined): boolean {
  return platform.startsWith('linux') && (display ?? '') === '' && (wayland ?? '') === ''
}

// Can a secret be typed into the gateway's field here (GW-UX-6)? A Client
// takes keys only after a click, and the terminal reports clicks to plugins
// only in its fullscreen layout: on the main screen (CLAUDE_CODE_NO_FLICKER=0,
// tmux by default) only Paste works. Said before any dialog opens.
// On Linux without a display (noDisplay) Paste can't work either: on the
// main screen neither route does, and the line says what to do.
export function secretLine(surfaces: readonly string[], fullscreen: boolean | undefined, tmux: boolean, noDisplay = false): string | undefined {
  if (surfaces.includes('terminal')) {
    const noPaste = noDisplay ? `; Paste from clipboard can't work here: ${NO_DISPLAY}` : ''
    if (fullscreen === true) return `Secrets here: the fullscreen view, so the gateway dialog's field takes a click, then keys${noPaste}`
    if (fullscreen === false && noDisplay) {
      return `Secrets here: neither typing nor Paste can work in this terminal: it shows Claude Code's main screen${tmux ? ' (inside tmux)' : ''}, so a secret can't be typed into the gateway dialog's field, and ${NO_DISPLAY}. To enter one, ${NO_DISPLAY_TODO}.`
    }
    if (fullscreen === false) {
      return `Secrets here: this terminal shows Claude Code's main screen${tmux ? ' (inside tmux)' : ''}, so a secret can't be typed into the gateway dialog's field: copy it and press Paste from clipboard (${MAIN_KEYS}). ${PASTE_NOTE} ${FULLSCREEN_HINT}`
    }
    return noDisplay ? `Secrets here: Paste from clipboard can't work: ${NO_DISPLAY}` : undefined
  }
  if (surfaces.includes('desktop')) return "Secrets here: the desktop app: click the gateway dialog's field, then type"
  return undefined
}

function envLine(st: EnvStatus, home: string): string {
  const env = clean(st.env, home)
  switch (st.state) {
    case 'ready':
      return `ready${st.warm ? ' (warmed)' : ''} at ${env}${st.managed ? '' : "; the managed shell's settings aren't written yet"}`
    case 'building':
      return `being set up (a build is running) at ${env}${st.older ? `; meanwhile the hooks run on ${clean(st.older, home)}` : ''}`
    case 'failed':
      if (st.pixi_too_old) return `can't be set up: ${pixiTooOldText(st)}`
      return `setup failed or was interrupted; log: ${env}/install.log (retried at the next session start)`
    case 'nopixi':
      return "can't be set up: pixi isn't installed (https://pixi.sh), then start a new session"
    case 'missing':
      return `not built yet (${env})`
  }
}

// The /gate-doctor report: versions (Claude Code and pixi against the tested
// ones), surfaces, mods, the env, managed mode, vault presence (existence only), the gateway
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
  lines.push(`Tested with pixi ${PIXI_TESTED} and Claude Code ${CLAUDE_TESTED} (only the latest is supported)`)
  lines.push(`Claude Code: ${claudeVerdict(f.claude?.version || undefined).text}`)
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
  const sec = secretLine(f.surfaces, f.fullscreen, f.tmux === true, f.noDisplay === true)
  if (sec !== undefined) lines.push(sec)
  if (st !== undefined) {
    const vault = st.vault ? 'present' : 'not set up yet'
    lines.push(`Vault: ${vault}; form (gateway.toml): ${st.form ? 'present' : 'not written yet'} (checked by existence only; the vault is never read)`)
  }
  lines.push(clean(daemonLine(f.daemon), userHome))
  const inst = installLine(f.daemon)
  if (inst !== undefined) lines.push(clean(inst, userHome))
  lines.push(`Capabilities here (Claude Code ${f.claude?.version ?? '?'}, ${sessionColumns(f.surfaces).map((s) => SURFACE_NAMES[s]).join(' + ')}):`)
  lines.push(...capabilityLines(f.surfaces))
  lines.push('Full matrix: docs/CAPABILITIES.md in the gateway repository.')
  return lines.join('\n')
}
