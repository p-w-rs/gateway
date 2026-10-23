// `claude plugin test plugins/gateway`: the mod against the engine's test kit.
// The test's hooks stand beneath the plugin, so they answer what a session's
// engine would: launch.sh (process.run / process.spawn), the clock, the env.
import { expect, mock, test } from 'claude-code/testing'

const HOME = '/Users/tester'
const CONFIG = `${HOME}/.claude`
const DATA_ROOT = `${CONFIG}/plugins/data/`

type Run = { argv: readonly string[]; init?: { env?: Record<string, string> } }

function statusJson(state: string, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    state, root: '/plugin', data: `${CONFIG}/plugins/data/gate-inline`,
    env: `${CONFIG}/plugins/data/gate-inline/envs/0123456789ab`, lock: '0123456789ab', warm: true, older: '',
    build_running: state === 'building', install_log: false, pixi: `${HOME}/.pixi/bin/pixi`,
    pixi_version: 'pixi 0.81.0', home: `${HOME}/.config/gateway`, form: true, vault: true,
    vault_v2: false, ...extra,
  }) + '\n'
}

const SOCKET = '/tmp/gw-501/gated.sock'

function daemonJson(extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    ok: true, version: '0.7.0', protocol: 1, pid: 777, epoch: 3, started: 1792450000, uptime: 754.2,
    vault: 'unwrapped', sessions: 2, socket: SOCKET, lock_after: 28800, ...extra,
  }) + '\n'
}

// The engine beneath the plugin: launch.sh answers from `answers` (the last
// one repeats), `launch.sh gated ...` from `gated` (the last one repeats);
// every run, spawn and fetch is recorded.
function world(on: any, answers: string[], gated: string[] = [daemonJson({ parent_pid: 4242 })],
               files: Record<string, string> = {}, startEnv: Record<string, string> = {}) {
  const runs: Run[] = []
  const spawns: Run[] = []
  const fetches: { url: string; init: any }[] = []
  const statuses: (string | undefined)[] = []
  const toasts: string[] = []
  const registered: any[] = []
  // the process environment: $.env.set writes it, $.env.get reads it back
  const env: Record<string, string | undefined> = { HOME, CLAUDE_CONFIG_DIR: CONFIG, ...startEnv }
  const envSets: { name: string; value: string | undefined }[] = []
  on('env.get', (_$: any, e: any) => ({ value: env[e.name] }))
  on('env.set', (_$: any, e: any) => { env[e.name] = e.value; envSets.push({ name: e.name, value: e.value }); return { value: undefined } })
  const clock = mock.clock(on, { now: 1_000_000 })
  on('session.start', (_$: any, e: any) => ({ cwd: e.cwd }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('command.register', (_$: any, e: any) => { registered.push(e); return { value: { command: e.name } } })
  on('ui.status', (_$: any, e: any) => { statuses.push(e.text); return { value: undefined } })
  on('ui.toast', (_$: any, e: any) => { toasts.push(e.text); return { value: undefined } })
  on('process.run', (_$: any, e: any) => {
    runs.push(e)
    const q = e.argv[2] === 'gated' ? gated : answers
    const out = q.length > 1 ? q.shift()! : q[0]!
    return { value: { exitCode: 0, stdout: out, stderr: '' } }
  })
  on('http.fetch', (_$: any, e: any) => {
    // the dialog loop's long poll at gated: no change while the test runs
    if (String(e.url).includes('/ui/dialog/next')) return new Promise(() => {})
    fetches.push(e)
    return { value: { status: 200, ok: true, headers: {}, text: '{"ok": true}' } }
  })
  on('process.spawn', async function* (_$: any, e: any) {
    spawns.push(e)
    return { value: { code: 0, signal: null } }
  })
  on('session.version', () => ({ value: { version: '2.1.301', base: '2.1.301', builtAt: '2026-10-15T12:58:20Z' } }))
  // files['<root>/hooks/gate-sh'] stands for the plugin's own gate-sh, wherever the kit puts the plugin
  on('fs.read', (_$: any, e: any) => ({ value: e.path.endsWith('/.claude-plugin/plugin.json') ? '{"name":"gate","version":"0.7.0"}'
    : e.path.endsWith('/hooks/gate-sh') && !e.path.startsWith(DATA_ROOT) ? (files['<root>/hooks/gate-sh'] ?? '') : (files[e.path] ?? '') }))
  return { runs, spawns, fetches, statuses, toasts, registered, clock, env, envSets }
}

const gatedRuns = (w: { runs: Run[] }) => w.runs.filter((r) => r.argv[2] === 'gated')

const start = ($: any, isInteractive = true) =>
  $.session.start({ cwd: '/work', surface: isInteractive ? 'terminal' : null, isInteractive })

const doctor = ($: any) =>
  $.command.run({ command: 'gate-doctor', args: '', origin: { kind: 'composer' },
                  presentation: { isFullscreen: false, columns: 100 } })

test('registers /gate-doctor as an immediate command', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')])
  await start($)
  expect(w.registered).toEqual([
    expect.objectContaining({ name: 'gate-doctor', immediate: true }),
    expect.objectContaining({ name: 'gate-dialog', immediate: true }),
    expect.objectContaining({ name: 'gate-unlock', immediate: true }),
    expect.objectContaining({ name: 'gate-lock', immediate: true }),
    expect.objectContaining({ name: 'gate-terminal', immediate: true }),
    expect.objectContaining({ name: 'gate-hosts', immediate: true }),
    expect.objectContaining({ name: 'gate-accounts', immediate: true }),
  ])
})

for (const surface of ['terminal', 'desktop'] as const) {
  test(`/gate-doctor answers without a model turn (${surface})`, async ($: any, on: any) => {
    const w = world(on, [statusJson('ready')])
    on('session.surfaces', () => ({ value: [surface] }))
    await start($)
    const out = await doctor($)
    const text: string = out.text
    // launch.sh is asked by argv (no shell string), with the hooks' data folder
    const last = w.runs.filter((r) => r.argv[2] === 'status').at(-1)!
    expect(last.argv.slice(-3)).toEqual(['hooks/launch.sh', 'status', 'pixi'].map((x, i) => (i === 0 ? last.argv[1]! : x)))
    expect(last.argv[0]).toBe('sh')
    expect(String(last.argv[1])).toMatch(/\/hooks\/launch\.sh$/)
    expect(last.init?.env?.CLAUDE_PLUGIN_DATA).toBe(`${CONFIG}/plugins/data/gate-inline`)
    const lines = text.split('\n')
    expect(lines[0]).toBe('gateway plugin 0.7.0 (gate@inline), diagnostics')
    expect(lines).toContain('Claude Code: 2.1.301 (mods need 2.1.287 in the terminal, 2.1.286 in the desktop app)')
    expect(lines).toContain(`Surfaces: ${surface}`)
    expect(lines).toContain('Mods: on (this report comes from the gateway mod)')
    expect(lines).toContain('Data folder: ~/.claude/plugins/data/gate-inline (loaded from a folder, --plugin-dir)')
    expect(lines).toContain('pixi: ~/.pixi/bin/pixi, 0.81.0, inside the tested range 0.68.0-0.82.0')
    expect(lines).toContain('Environment: ready (warmed) at ~/.claude/plugins/data/gate-inline/envs/0123456789ab')
    expect(lines.find((l) => l.startsWith('Managed shell: on; this session: active (CLAUDE_CODE_SHELL_PREFIX = '))).toMatch(/\/hooks\/gate-sh; Claude Code starts it from the managed bash\)$/)
    expect(lines).toContain('Vault: present; form (gateway.toml): present (checked by existence only; the vault is never read)')
    expect(text).toContain('Capabilities here (Claude Code 2.1.301,')
    expect(text).toContain('(works without mods)')
    expect(text).not.toContain(HOME)                       // sanitized: the home is ~
    expect(/[\u0000-\u0009\u000b-\u001f]/.test(text)).toBe(false)
  })
}

test('/gate-doctor says whether a secret can be typed here: the main screen (and tmux) only pastes (GW-UX-6)', async ($: any, on: any) => {
  world(on, [statusJson('ready')], undefined, {}, { TMUX: '/tmp/tmux-501/default,1,0' })
  on('session.surfaces', () => ({ value: ['terminal'] }))
  await start($)
  const main: string = (await doctor($)).text
  const line = main.split('\n').find((l) => l.startsWith('Secrets here: '))!
  expect(line).toContain("this terminal shows Claude Code's main screen (inside tmux), so a secret can't be typed")
  expect(line).toContain('Paste from clipboard (/gate-dialog, then Tab and Enter)')
  expect(line).toContain('clear it yourself')
  expect(line).toContain('CLAUDE_CODE_NO_FLICKER=1')
  const full: string = (await $.command.run({ command: 'gate-doctor', args: '', origin: { kind: 'composer' },
                                              presentation: { isFullscreen: true, columns: 140 } })).text
  expect(full).toContain("Secrets here: the fullscreen view, so the gateway dialog's field takes a click, then keys")
  expect(full).not.toContain('main screen')
})

test('/gate-doctor on Linux without a display says neither typing nor Paste works here, and what to do (review round 2)', async ($: any, on: any) => {
  world(on, [statusJson('ready')], [daemonJson({ parent_pid: 4242, platform: 'linux' })])
  on('session.surfaces', () => ({ value: ['terminal'] }))
  await start($)
  const line = ((await doctor($)).text as string).split('\n').find((l) => l.startsWith('Secrets here: '))!
  expect(line).toContain('neither typing nor Paste can work in this terminal')
  expect(line).toContain('no DISPLAY or WAYLAND_DISPLAY')
  expect(line).toContain('CLAUDE_CODE_NO_FLICKER=1')
  expect(line).toContain("this machine's desktop")
  expect(line).not.toContain('press Paste')
})

test('/gate-doctor warns about a pixi newer than the tested range and names a failed setup', async ($: any, on: any) => {
  world(on, [statusJson('failed', { pixi_version: 'pixi 0.95.1', warm: false, vault: false, form: false })])
  on('session.surfaces', () => ({ value: [] }))
  const text: string = (await doctor($)).text
  expect(text).toContain('0.95.1 is newer than the tested range 0.68.0-0.82.0 (a warning only')
  expect(text).toContain('Environment: setup failed or was interrupted; log: ~/.claude/plugins/data/gate-inline/envs/0123456789ab/install.log')
  expect(text).toContain('Vault: not set up yet; form (gateway.toml): not written yet')
  expect(text).toContain('Surfaces: none (-p or SDK)')
})

test('/gate-doctor reports an unmigrated 0.6 vault instead of "not set up yet"', async ($: any, on: any) => {
  // store.age but no private/vault.age: the cold Bash guard counts it as "a
  // vault exists", so the doctor must not contradict it by saying there is none.
  world(on, [statusJson('building', { vault: false, vault_v2: true })])
  on('session.surfaces', () => ({ value: ['terminal'] }))
  const text: string = (await doctor($)).text
  expect(text).toContain('Vault: a 0.6 vault (store.age), converted once setup finishes')
  expect(text).not.toContain('Vault: not set up yet')
})

test('a missing env: provisions by argv and shows setting up, then a ready toast, then nothing', async ($: any, on: any) => {
  const w = world(on, [statusJson('missing'), statusJson('building'), statusJson('ready')])
  await start($)
  expect(w.spawns).toHaveLength(1)
  expect(w.spawns[0]!.argv[0]).toBe('sh')
  expect(String(w.spawns[0]!.argv[1])).toMatch(/\/hooks\/launch\.sh$/)
  expect(w.spawns[0]!.argv[2]).toBe('ensure-env')
  expect(w.spawns[0]!.argv).toHaveLength(3)
  expect(w.spawns[0]!.init?.env?.CLAUDE_PLUGIN_DATA ?? (w.spawns[0] as any).env?.CLAUDE_PLUGIN_DATA)
    .toBe(`${CONFIG}/plugins/data/gate-inline`)
  expect(w.statuses).toEqual(['setting up… 0:00'])
  await w.clock.advance(1000)
  expect(w.statuses.at(-1)).toBe('setting up… 0:01')
  await w.clock.advance(2000)                     // the 3 s poll: building
  expect(w.statuses.at(-1)).toBe('setting up… 0:03')
  expect(w.toasts).toEqual([])
  await w.clock.advance(3000)                     // the next poll: ready
  // a normal state: Claude Code draws every status line with its warning
  // glyph, so the line goes at once and "ready" is a toast (drawn without one)
  expect(w.statuses.at(-1)).toBeUndefined()
  expect(w.statuses).not.toContain('ready')
  expect(w.toasts).toEqual(['ready'])
  const n = w.statuses.length
  await w.clock.advance(10_000)
  expect(w.statuses).toHaveLength(n)              // the timer stopped
  expect(w.toasts).toEqual(['ready'])
  expect(w.spawns).toHaveLength(1)                // one build only
})

test("ready waits for the managed shell's settings: the env built, the line says finishing setup until they are written", async ($: any, on: any) => {
  // launch.sh ensure-env writes them right after the build; until then gate-sh
  // refuses every command (exit 75), so a "ready" before them would be wrong
  const w = world(on, [statusJson('building'), statusJson('ready', { managed: false }), statusJson('ready', { managed: false }),
                       statusJson('ready', { managed: true })])
  await start($)
  expect(w.statuses).toEqual(['setting up… 0:00'])
  await w.clock.advance(3000)                     // the env is built: the daemon is started, the line goes on
  expect(w.statuses.at(-1)).toBe('finishing setup… 0:03')
  expect(gatedRuns(w).length).toBeGreaterThan(0)
  await w.clock.advance(3000)
  expect(w.statuses.at(-1)).toBe('finishing setup… 0:06')
  expect(w.toasts).toEqual([])
  await w.clock.advance(3000)                     // the settings are written
  expect(w.statuses.at(-1)).toBeUndefined()
  expect(w.toasts).toEqual(['ready'])
})

test("a built env without the managed shell's settings (a setup interrupted after the build): finishing setup, the daemon at once", async ($: any, on: any) => {
  const w = world(on, [statusJson('ready', { managed: false }), statusJson('ready', { managed: true })])
  await start($)
  expect(w.spawns).toHaveLength(0)                // nothing to build: ensure-env (classic, async) writes them
  expect(w.statuses).toEqual(['finishing setup… 0:00'])
  expect(gatedRuns(w).length).toBeGreaterThan(0)
  await w.clock.advance(3000)
  expect(w.statuses.at(-1)).toBeUndefined()
  expect(w.statuses).not.toContain('ready')
  expect(w.toasts).toEqual(['ready'])
})

test("managed off (no prefix): ready doesn't wait for the managed shell's settings", async ($: any, on: any) => {
  const w = world(on, [statusJson('ready', { managed: false })], undefined,
                  { [`${CONFIG}/plugins/data/gate-inline/managed/state.json`]: JSON.stringify({ mode: 'off' }) })
  await start($)
  expect(w.statuses).toEqual([])
})

test('a build already running (the async classic hook): no second build, just the status line', async ($: any, on: any) => {
  const w = world(on, [statusJson('building')])
  await start($)
  expect(w.spawns).toHaveLength(0)
  expect(w.statuses).toEqual(['setting up… 0:00'])
})

test('a ready env: no status line and no build', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')])
  await start($)
  expect(w.spawns).toHaveLength(0)
  expect(w.statuses).toEqual([])
})

test('pixi missing: says so and builds nothing', async ($: any, on: any) => {
  const w = world(on, [statusJson('nopixi', { pixi: '', pixi_version: '' })])
  await start($)
  expect(w.spawns).toHaveLength(0)
  expect(w.statuses.at(-1)).toContain("pixi isn't installed")
})

test('-p and the SDK (not interactive): no status line, no build', async ($: any, on: any) => {
  const w = world(on, [statusJson('missing')])
  await start($, false)
  expect(w.spawns).toHaveLength(0)
  expect(w.statuses).toEqual([])
  expect(w.registered).toHaveLength(7)            // /gate-doctor and the others are still there
})

test('launch.sh not answering never breaks the session', async ($: any, on: any) => {
  const w = world(on, ['garbage'])
  const r = await start($)
  expect(r).toEqual({ cwd: '/work' })
  expect(w.spawns).toHaveLength(0)
  const text: string = (await doctor($)).text
  expect(text).toContain("Environment: unknown (hooks/launch.sh status didn't answer)")
})

test('a build that never finishes: after 20 minutes the line says so and polling stops', async ($: any, on: any) => {
  const w = world(on, [statusJson('building')])
  await start($)
  await w.clock.advance(20 * 60 * 1000 + 2000)
  expect(w.statuses.at(-1)).toBe('setup is taking long; /gate-doctor says what is happening')
  const runs = w.runs.length
  await w.clock.advance(60_000)
  expect(w.runs.length).toBe(runs)
})

test('a failed setup that fails again keeps its line, also after polling stops', async ($: any, on: any) => {
  const w = world(on, [statusJson('failed')])
  await start($)
  expect(w.spawns).toHaveLength(1)                 // one retry, at session start
  expect(w.statuses[0]).toBe('setting up… 0:00')
  await w.clock.advance(3000)
  expect(w.statuses.at(-1)).toBe('setup failed; /gate-doctor says why')
  await w.clock.advance(21 * 60 * 1000)
  expect(w.statuses.at(-1)).toBe('setup failed; /gate-doctor says why')
  expect(w.spawns).toHaveLength(1)
})

// --- the gateway daemon (PLAN-v4 phase 2) ------------------------------------

const fetchArgs = (f: { url: string; init: any } | any) => ({
  url: f.url ?? f[0], init: f.init ?? f[1] ?? f,
})

test('a ready env: the daemon is started by argv and this session registers on its UI plane', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')])
  await start($)
  const g = gatedRuns(w)
  expect(g).toHaveLength(1)
  expect(g[0]!.argv[0]).toBe('sh')
  expect(String(g[0]!.argv[1])).toMatch(/\/hooks\/launch\.sh$/)
  expect(g[0]!.argv.slice(2)).toEqual(['gated', 'start'])
  expect(g[0]!.init?.env?.CLAUDE_PLUGIN_DATA).toBe(`${CONFIG}/plugins/data/gate-inline`)
  expect(w.fetches).toHaveLength(1)
  const f = fetchArgs(w.fetches[0])
  expect(f.url).toBe('http://gated/ui/register')
  expect(f.init.method).toBe('POST')
  expect(f.init.socketPath).toBe(SOCKET)
  const body = JSON.parse(f.init.body)
  expect(body).toEqual({ session_id: 'sess-1', surface: 'terminal', surfaces: [], version: '2.1.301', claude_pid: 4242 })
})

test('no claude_pid is claimed when launch.sh could not name its parent as Claude Code', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')], [daemonJson()])
  await start($)
  const body = JSON.parse(fetchArgs(w.fetches[0]).init.body)
  expect('claude_pid' in body).toBe(false)
  expect(body.session_id).toBe('sess-1')
})

test('-p registers too (no surface), without a status line', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')])
  await start($, false)
  expect(w.statuses).toEqual([])
  expect(gatedRuns(w)).toHaveLength(1)
  expect(JSON.parse(fetchArgs(w.fetches[0]).init.body).surface).toBe('')
})

test('a missing env: no daemon until setup finishes, then one registration', async ($: any, on: any) => {
  const w = world(on, [statusJson('missing'), statusJson('building'), statusJson('ready')])
  await start($)
  expect(gatedRuns(w)).toHaveLength(0)
  expect(w.fetches).toHaveLength(0)
  await w.clock.advance(6000)                     // two polls: building, then ready
  expect(w.toasts).toEqual(['ready'])
  expect(gatedRuns(w)).toHaveLength(1)
  expect(w.fetches).toHaveLength(1)
  await w.clock.advance(10_000)
  expect(w.fetches).toHaveLength(1)
})

test('a daemon that does not answer never breaks the session start', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')], ['still setting up'])
  const r = await start($)
  expect(r).toEqual({ cwd: '/work' })
  expect(w.fetches).toHaveLength(0)
})

test('/gate-doctor shows the daemon from its /health (version, epoch, uptime, sessions, vault)', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')], [daemonJson({ vault: 'locked' })])
  on('session.surfaces', () => ({ value: ['terminal'] }))
  const text: string = (await doctor($)).text
  expect(gatedRuns(w).at(-1)!.argv.slice(2)).toEqual(['gated', 'status'])
  expect(text.split('\n')).toContain('Gateway daemon: running (0.7.0, epoch 3, up 12 min, 2 sessions); vault locked (its key has a passphrase)')
})

test('/gate-doctor says when the daemon is not running, and asks nothing while setup runs', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')], [JSON.stringify({ ok: false, running: false, socket: SOCKET }) + '\n'])
  on('session.surfaces', () => ({ value: ['terminal'] }))
  expect((await doctor($)).text).toContain('Gateway daemon: not running (it starts when a session or tool needs it)')
  const w2runs = gatedRuns(w).length
  expect(w2runs).toBe(1)
})

// Managed execution (PLAN-v4 phase 4): what session.start sets.
const DATA = `${CONFIG}/plugins/data/gate-inline`
const GATE_SH_TEXT = '#!/bin/sh\n# gate-sh: the gateway\'s CLAUDE_CODE_SHELL_PREFIX\n'
const ENVD = `${DATA}/envs/0123456789ab`
const STATE = `${DATA}/managed/state.json`

function managedState(extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    version: 1, mode: 'on', form_mode: 'on', form_mode_invalid: false,
    bash: `${ENVD}/.pixi/envs/default/bin/bash`, bash_version: '5.2.37', ready: true,
    path: [{ dir: `${DATA}/bin`, origin: "the gateway's stand-ins" },
           { dir: `${DATA}/managed/bin`, origin: "the gateway's runtime tools (bash, pixi)" },
           { dir: '/opt/homebrew/bin', origin: 'gateway.toml [shell] import_path, line 4; Homebrew' },
           { dir: '/usr/bin', origin: 'system' }],
    env: [{ name: 'JAVA_HOME', origin: 'gateway.toml [shell] import_env, line 5' }],
    pending: [], vault_readable: true, ...extra,
  })
}

const rootOf = (w: { runs: Run[] }) => String(w.runs.find((r) => r.argv[2] === 'status')!.argv[1]).replace(/\/hooks\/launch\.sh$/, '')

test('managed mode: session start sets the prefix to gate-sh, names its folder and the managed bash', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')])
  await start($)
  const root = rootOf(w)
  expect(w.env.CLAUDE_CODE_SHELL_PREFIX).toBe(`${root}/hooks/gate-sh`)
  expect(w.env.GW_MANAGED_DIR).toBe(`${DATA}/managed`)
  expect(w.env.CLAUDE_CODE_SHELL).toBe(`${ENVD}/.pixi/envs/default/bin/bash`)
  // before the dialog loop or the daemon: the prefix is the first thing set
  // (SHLVL first where it is missing: the next test)
  expect(w.envSets.map((x) => x.name)).toEqual(['GW_MANAGED_DIR', 'SHLVL', 'CLAUDE_CODE_SHELL_PREFIX', 'CLAUDE_CODE_SHELL'])
})

// bash -c with a socket on stdin (as Claude Code starts the shell it runs the
// prefix from) sources ~/.bashrc at shell level 1: SHLVL unset, 0 or garbage
// (tests/test_managed.py shows it with the env's bash). A Claude Code started
// from a terminal has SHLVL >= 1 and keeps it.
for (const [start_, want] of [[undefined, '1'], ['', '1'], ['0', '1'], ['-3', '1'], ['x', '1'], ['999', '1'],
                              ['1', '1'], ['2', '2'], ['998', '998']] as const) {
  test(`managed mode: SHLVL ${JSON.stringify(start_)} becomes ${want} before the prefix`, async ($: any, on: any) => {
    const w = world(on, [statusJson('ready')], undefined, {}, start_ === undefined ? {} : { SHLVL: start_ })
    await start($)
    expect(w.env.SHLVL).toBe(want)
    const names = w.envSets.map((x) => x.name)
    expect(names.includes('SHLVL')).toBe(want !== start_)
    if (names.includes('SHLVL')) expect(names.indexOf('SHLVL')).toBeLessThan(names.indexOf('CLAUDE_CODE_SHELL_PREFIX'))
  })
}

test('managed off: SHLVL is left alone (Claude Code runs its own shell as before)', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')], undefined, { [STATE]: managedState({ mode: 'off', form_mode: 'off' }) })
  await start($)
  expect(w.env.SHLVL).toBe(undefined)
  expect(w.envSets.map((x) => x.name)).not.toContain('SHLVL')
})

test('managed mode in -p (no surface): the prefix is set as well', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')])
  await start($, false)
  expect(w.env.CLAUDE_CODE_SHELL_PREFIX).toBe(`${rootOf(w)}/hooks/gate-sh`)
})

test('an env still building: the prefix now (gate-sh says not ready), the managed bash once it is', async ($: any, on: any) => {
  const w = world(on, [statusJson('missing'), statusJson('building'), statusJson('ready')])
  await start($)
  expect(w.env.CLAUDE_CODE_SHELL_PREFIX).toBe(`${rootOf(w)}/hooks/gate-sh`)
  expect(w.env.CLAUDE_CODE_SHELL).toBe(undefined)
  await w.clock.advance(6000)
  expect(w.env.CLAUDE_CODE_SHELL).toBe(`${ENVD}/.pixi/envs/default/bin/bash`)
})

test('an approved managed = "off": no prefix, and /gate-doctor says why', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')], undefined, { [STATE]: managedState({ mode: 'off', form_mode: 'off' }) })
  on('session.surfaces', () => ({ value: ['terminal'] }))
  await start($)
  expect(w.env.CLAUDE_CODE_SHELL_PREFIX).toBe(undefined)
  expect(w.env.CLAUDE_CODE_SHELL).toBe(undefined)
  const text: string = (await doctor($)).text
  expect(text).toContain('Managed shell: off; this session: inactive: gateway.toml [shell] managed = "off" (approved)')
})

test('"warn" sets the prefix like "on"', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')], undefined, { [STATE]: managedState({ mode: 'warn', form_mode: 'warn' }) })
  await start($)
  expect(w.env.CLAUDE_CODE_SHELL_PREFIX).toBe(`${rootOf(w)}/hooks/gate-sh`)
})

for (const garbled of ['{"mode": "of', '{"mode": "maybe"}', '[]', '{"mode": 0}']) {
  test(`a garbled state file counts as "on": ${garbled}`, async ($: any, on: any) => {
    const w = world(on, [statusJson('ready')], undefined, { [STATE]: garbled })
    await start($)
    expect(w.env.CLAUDE_CODE_SHELL_PREFIX).toBe(`${rootOf(w)}/hooks/gate-sh`)
  })
}

test('another prefix is replaced, and /gate-doctor names it', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')], undefined, {}, { CLAUDE_CODE_SHELL_PREFIX: '/usr/local/bin/audit-log' })
  on('session.surfaces', () => ({ value: ['terminal'] }))
  await start($)
  expect(w.env.CLAUDE_CODE_SHELL_PREFIX).toBe(`${rootOf(w)}/hooks/gate-sh`)
  expect((await doctor($)).text).toContain('  replaced another CLAUDE_CODE_SHELL_PREFIX (/usr/local/bin/audit-log) for managed mode')
})

test('/gate-doctor: the managed PATH and imports with their origins, and what waits for an OK', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')], undefined, { [STATE]: managedState({ form_mode: 'warn', pending: ['settings: managed shell "on" -> "warn" (...)'] }) })
  on('session.surfaces', () => ({ value: ['terminal'] }))
  await start($)
  const lines: string[] = (await doctor($)).text.split('\n')
  expect(lines).toContain('  gateway.toml says "warn"; that waits for the user\'s OK (gate check settings)')
  expect(lines).toContain('  bash: ~/.claude/plugins/data/gate-inline/envs/0123456789ab/.pixi/envs/default/bin/bash (5.2.37)')
  expect(lines.find((l) => l.startsWith('  PATH: '))).toBe("  PATH: ~/.claude/plugins/data/gate-inline/bin (the gateway's stand-ins); ~/.claude/plugins/data/gate-inline/managed/bin (the gateway's runtime tools (bash, pixi)); /opt/homebrew/bin (gateway.toml [shell] import_path, line 4; Homebrew); /usr/bin (system); then other plugins' bin/ folders")
  expect(lines).toContain('  Environment: platform variables, SHELL, Claude Code\'s own; imported: JAVA_HOME (gateway.toml [shell] import_env, line 5)')
  expect(lines).toContain('  waiting for the user\'s OK: settings: managed shell "on" -> "warn" (...)')
  expect(w.runs.length).toBeGreaterThan(0)
})

test('a session whose prefix was taken away later: /gate-doctor says the classic hook reports it', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')])
  on('session.surfaces', () => ({ value: ['terminal'] }))
  await start($)
  w.env.CLAUDE_CODE_SHELL_PREFIX = '/somewhere/else'
  expect((await doctor($)).text).toContain('Managed shell: on; this session: inactive: another CLAUDE_CODE_SHELL_PREFIX is set (/somewhere/else); the classic Bash hook reports it')
})

test('a gate-sh copy in the data folder (the plugin lost its exec bit) is the prefix; any other path is not', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')], undefined, { [STATE]: managedState({ gate_sh: `${DATA}/managed/gate-sh` }),
                                                         '<root>/hooks/gate-sh': GATE_SH_TEXT, [`${DATA}/managed/gate-sh`]: GATE_SH_TEXT })
  await start($)
  expect(w.env.CLAUDE_CODE_SHELL_PREFIX).toBe(`${DATA}/managed/gate-sh`)
})

for (const [what, copyText] of [['another program', '#!/bin/sh\nexec /bin/sh -c "$1"\n'], ['an empty file', '']]) {
  test(`a gate-sh copy that isn't the plugin's gate-sh (${what}, rewritten with state.json) is never the prefix`, async ($: any, on: any) => {
    const w = world(on, [statusJson('ready')], undefined, { [STATE]: managedState({ gate_sh: `${DATA}/managed/gate-sh` }),
                                                           '<root>/hooks/gate-sh': GATE_SH_TEXT, [`${DATA}/managed/gate-sh`]: copyText })
    await start($)
    expect(w.env.CLAUDE_CODE_SHELL_PREFIX).toBe(`${rootOf(w)}/hooks/gate-sh`)
  })
}

test('CLAUDE_CODE_SHELL comes from the env launch.sh names, never from state.json\'s bash', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')], undefined, { [STATE]: managedState({ bash: '/tmp/not-the-gateway/bash' }) })
  await start($)
  expect(w.env.CLAUDE_CODE_SHELL).toBe(`${ENVD}/.pixi/envs/default/bin/bash`)
  expect(w.env.CLAUDE_CODE_SHELL_PREFIX).toBe(`${rootOf(w)}/hooks/gate-sh`)
})

test('an env not ready: no CLAUDE_CODE_SHELL, whatever state.json says', async ($: any, on: any) => {
  const w = world(on, [statusJson('building')], undefined, { [STATE]: managedState({ bash: '/tmp/not-the-gateway/bash', ready: true }) })
  await start($)
  expect(w.env.CLAUDE_CODE_SHELL).toBe(undefined)
  expect(w.env.CLAUDE_CODE_SHELL_PREFIX).toBe(`${rootOf(w)}/hooks/gate-sh`)
})

test('a state naming a prefix elsewhere is ignored', async ($: any, on: any) => {
  const w = world(on, [statusJson('ready')], undefined, { [STATE]: managedState({ gate_sh: '/tmp/evil/gate-sh' }) })
  await start($)
  expect(w.env.CLAUDE_CODE_SHELL_PREFIX).toBe(`${rootOf(w)}/hooks/gate-sh`)
})
