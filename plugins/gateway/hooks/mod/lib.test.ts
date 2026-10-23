// `claude plugin test plugins/gateway`: the mod's pure logic.
import { describe, expect, test } from 'claude-code/testing'
import {
  CAPABILITIES,
  PIXI_TESTED_MAX,
  PIXI_TESTED_MIN,
  capabilityLines,
  clean,
  compareVersions,
  daemonLine,
  doctorText,
  formatUptime,
  formatElapsed,
  locate,
  managedLines,
  managedPlan,
  noDisplayHere,
  parseDaemon,
  parseManagedState,
  parsePixiVersion,
  parseStatus,
  pixiVerdict,
  secretLine,
  sessionColumns,
  setupReady,
  shouldProvision,
  statusLine,
  type EnvStatus,
} from './lib.ts'

const base: EnvStatus = {
  state: 'missing', root: '/r', data: '/d', env: '/d/envs/abc', lock: 'abc', warm: false, managed: true, older: '',
  build_running: false, install_log: false, pixi: '/u/.pixi/bin/pixi', pixi_version: '', home: '/u/.config/gateway',
  form: false, vault: false, vault_v2: false,
}

describe('launch.sh status', () => {
  test('parses its JSON line and refuses anything else', () => {
    const line = JSON.stringify({ ...base, state: 'building', warm: true, extra: 1 })
    expect(parseStatus(`noise\n${line}\n`)).toEqual({ ...base, state: 'building', warm: true })
    expect(parseStatus('')).toBeUndefined()
    expect(parseStatus('{not json')).toBeUndefined()
    expect(parseStatus(JSON.stringify({ ...base, state: 'exploded' }))).toBeUndefined()
  })
  test("reads whether the managed shell's settings are written (absent: an older launch.sh, counted as written)", () => {
    expect(parseStatus(JSON.stringify({ ...base, state: 'ready', managed: false }))!.managed).toBe(false)
    expect(parseStatus(JSON.stringify({ ...base, state: 'ready', managed: true }))!.managed).toBe(true)
    const { managed: _m, ...old } = base
    expect(parseStatus(JSON.stringify({ ...old, state: 'ready' }))!.managed).toBe(true)
  })
  test('provisions only when nothing is building and the env is missing or failed', () => {
    expect(shouldProvision({ ...base, state: 'missing' })).toBe(true)
    expect(shouldProvision({ ...base, state: 'failed' })).toBe(true)
    expect(shouldProvision({ ...base, state: 'building' })).toBe(false)
    expect(shouldProvision({ ...base, state: 'ready' })).toBe(false)
    expect(shouldProvision({ ...base, state: 'nopixi' })).toBe(false)
    expect(shouldProvision(undefined)).toBe(false)
  })
})

describe('status line', () => {
  test('says setting up with the elapsed time, then ready', () => {
    expect(statusLine({ ...base, state: 'building' }, 0)).toBe('setting up… 0:00')
    expect(statusLine({ ...base, state: 'missing' }, 75_400)).toBe('setting up… 1:15')
    expect(statusLine({ ...base, state: 'ready' }, 9_000)).toBe('ready')
    // Claude Code prefixes the plugin's name itself
    for (const s of ['ready', 'building', 'failed', 'nopixi'] as const) {
      expect(statusLine({ ...base, state: s }, 0)!.startsWith('gate')).toBe(false)
    }
    expect(statusLine({ ...base, state: 'failed' }, 0)).toContain('/gate-doctor')
    expect(statusLine({ ...base, state: 'nopixi' }, 0)).toContain('https://pixi.sh')
    expect(statusLine(undefined, 0)).toBeUndefined()
    expect(formatElapsed(-5)).toBe('0:00')
    expect(formatElapsed(600_000)).toBe('10:00')
  })
  test("says ready only once the managed shell's settings are written, in a session that runs commands through it", () => {
    // the env built, the settings not yet: gate-sh refuses every command (75) until they are
    const built = { ...base, state: 'ready' as const, managed: false }
    expect(statusLine(built, 9_000, true)).toBe('finishing setup… 0:09')
    expect(setupReady(built, true)).toBe(false)
    expect(statusLine({ ...built, managed: true }, 9_000, true)).toBe('ready')
    expect(setupReady({ ...built, managed: true }, true)).toBe(true)
    // a session without the prefix (managed off) doesn't need them
    expect(statusLine(built, 9_000, false)).toBe('ready')
    expect(setupReady(built, false)).toBe(true)
    expect(setupReady({ ...base, state: 'building' }, false)).toBe(false)
    expect(setupReady(undefined, false)).toBe(false)
  })
})

describe('data folder', () => {
  test('an installed copy: <config>/plugins/data/<plugin>-<marketplace>', () => {
    const l = locate('/u/.claude/plugins/cache/gateway/gate/0.7.0', 'gate', '/elsewhere')
    expect(l).toEqual({ data: '/u/.claude/plugins/data/gate-gateway', provenance: 'gate@gateway', how: 'installed' })
    const s = locate('/c d/é/plugins/cache/gateway/gate/0.7.1/', 'gate', '/x')
    expect(s.data).toBe('/c d/é/plugins/data/gate-gateway')
  })
  test('a --plugin-dir folder: <config>/plugins/data/<plugin>-inline', () => {
    const l = locate('/src/gateway/plugins/gateway', 'gate', '/u/.config/claude/')
    expect(l).toEqual({ data: '/u/.config/claude/plugins/data/gate-inline', provenance: 'gate@inline', how: 'folder' })
  })
})

describe('pixi range', () => {
  test('tested inside, warns when newer, refuses older', () => {
    expect(compareVersions('0.81.0', '0.82.0')).toBe(-1)
    expect(compareVersions('0.82', '0.82.0')).toBe(0)
    expect(compareVersions('1.0.0', '0.99.9')).toBe(1)
    expect(parsePixiVersion('pixi 0.81.0')).toBe('0.81.0')
    expect(parsePixiVersion('weird')).toBeUndefined()
    expect(pixiVerdict(PIXI_TESTED_MIN).kind).toBe('tested')
    expect(pixiVerdict(PIXI_TESTED_MAX).kind).toBe('tested')
    expect(pixiVerdict('0.81.0').text).toContain('inside the tested range')
    const newer = pixiVerdict('0.90.0')
    expect(newer.kind).toBe('newer')
    expect(newer.text).toContain('a warning only')
    const older = pixiVerdict('0.67.0')
    expect(older.kind).toBe('older')
    expect(older.text).toContain('pixi self-update')
    expect(pixiVerdict(undefined).kind).toBe('unknown')
  })
})

describe('capabilities', () => {
  test('rows for the surfaces this session draws on', () => {
    expect(sessionColumns([])).toEqual(['print'])
    expect(sessionColumns(['terminal', 'mobile', 'terminal'])).toEqual(['terminal', 'mobile'])
    const lines = capabilityLines(['terminal'])
    expect(lines).toHaveLength(CAPABILITIES.length)
    expect(lines[0]).toContain('(works without mods)')
    expect(capabilityLines(['terminal', 'desktop'])[0]).toContain('desktop app')
    for (const r of CAPABILITIES) {
      expect(Object.keys(r.cells).sort()).toEqual(['desktop', 'mobile', 'print', 'remote', 'terminal', 'vscode'])
    }
  })
})

describe('doctor text', () => {
  test('cleans control characters and shows the home as ~', () => {
    expect(clean('/u/x\u001b[2Jy', '/u')).toBe('~/x?[2Jy')
    expect(clean('/user/x', '/u')).toBe('/user/x')
  })
  test('reports what it knows and says so when launch.sh did not answer', () => {
    const located = locate('/u/.claude/plugins/cache/gateway/gate/0.7.0', 'gate', '/u/.claude')
    const t = doctorText({ pluginVersion: undefined, claude: undefined, surfaces: [], located, status: undefined })
    expect(t).toContain('(version unknown)')
    expect(t).toContain("Environment: unknown (hooks/launch.sh status didn't answer)")
    expect(t).toContain('Surfaces: none (-p or SDK)')
    expect(t).not.toContain('Vault:')
  })
})

describe('gateway daemon', () => {
  const health = { ok: true, version: '0.7.0', protocol: 1, pid: 9, epoch: 4, started: 1, uptime: 59.9,
                   vault: 'unwrapped', sessions: 1, socket: '/tmp/gw-501/gated.sock', lock_after: 28800 }
  test('parses launch.sh gated status|start, and nothing else', () => {
    const d = parseDaemon(`noise\n${JSON.stringify({ ...health, parent_pid: 4242, skew: 'x' })}\n`)!
    expect(d).toEqual({ running: true, version: '0.7.0', epoch: 4, uptime: 59.9, vault: 'unwrapped',
                        sessions: 1, socket: '/tmp/gw-501/gated.sock', parentPid: 4242, skew: 'x', terminals: 0, jobs: 0,
                        claudeInstall: '', parentExe: '', error: '', message: '', otherConfig: '', platform: '' })
    expect(parseDaemon('gateway: still setting up')).toBeUndefined()
    expect(parseDaemon('{nope')).toBeUndefined()
    expect(parseDaemon(JSON.stringify({ ok: false, running: false }))!.running).toBe(false)
    expect(parseDaemon(JSON.stringify({ ...health, epoch: 'four', parent_pid: '1' }))!.epoch).toBe(0)
  })
  test('says what the doctor shows', () => {
    expect(formatUptime(59.9)).toBe('59 s')
    expect(formatUptime(754)).toBe('12 min')
    expect(formatUptime(3 * 3600 + 120)).toBe('3 h 2 min')
    expect(daemonLine(parseDaemon(JSON.stringify(health)))).toBe(
      'Gateway daemon: running (0.7.0, epoch 4, up 59 s, 1 session); vault unwrapped (its key has no passphrase)')
    expect(daemonLine({ ...parseDaemon(JSON.stringify({ ...health, terminals: 2, jobs: 1 }))! }))
      .toBe('Gateway daemon: running (0.7.0, epoch 4, up 59 s, 1 session, 2 terminals, 1 job); vault unwrapped (its key has no passphrase)')
    expect(daemonLine(parseDaemon(JSON.stringify({ ...health, vault: 'unlocked', sessions: 3, skew: 'a newer gateway daemon (0.9.0) answers' })))).toBe(
      'Gateway daemon: running (0.7.0, epoch 4, up 59 s, 3 sessions); vault unlocked (its key has a passphrase); a newer gateway daemon (0.9.0) answers')
    expect(daemonLine(parseDaemon('{"ok": false}'))).toBe('Gateway daemon: not running (it starts when a session or tool needs it)')
    expect(daemonLine(undefined)).toContain("can't be asked until setup finishes")
    // GW-ROB-1: a run folder it can't use is said, with gated's remedy
    expect(daemonLine(parseDaemon(JSON.stringify({ ok: false, running: false, error: 'run_dir',
      message: "gateway: the gateway's run folder /tmp/gw-501 belongs to another user; the gateway won't use it; only that user or the machine's administrator can remove it" }))))
      .toBe("Gateway daemon: can't start: the gateway's run folder /tmp/gw-501 belongs to another user; the gateway won't use it; only that user or the machine's administrator can remove it")
  })
  test('a daemon serving another Claude Code configuration is said, not shown as plainly running (review round 2)', () => {
    const note = 'the gateway daemon running now serves another Claude Code configuration (its data folder is ~/.claude-a/plugins/data/gate-gateway; this one\'s is ~/.claude-b/plugins/data/gate-gateway): ...'
    const d = parseDaemon(JSON.stringify({ ...health, other_config: note, platform: 'linux' }))!
    expect(d.otherConfig).toBe(note)
    expect(d.platform).toBe('linux')
    expect(daemonLine(d)).toBe(`Gateway daemon: running (0.7.0, epoch 4, up 59 s, 1 session); vault unwrapped (its key has no passphrase); ${note}`)
    expect(daemonLine(parseDaemon(JSON.stringify(health)))).not.toContain('another Claude Code configuration')
  })
  test('the doctor shows the daemon line', () => {
    const located = locate('/u/.claude/plugins/cache/gateway/gate/0.7.0', 'gate', '/u/.claude')
    const t = doctorText({ pluginVersion: '0.7.0', claude: undefined, surfaces: [], located, status: undefined,
                           daemon: parseDaemon(JSON.stringify({ ...health, vault: 'locked' })) })
    expect(t).toContain('Gateway daemon: running (0.7.0, epoch 4, up 59 s, 1 session); vault locked (its key has a passphrase)')
  })
  test('the doctor names how Claude Code was installed, and says when the daemon does not recognize it (GW-COMPAT-1)', () => {
    const located = locate('/u/.claude/plugins/cache/gateway/gate/0.7.0', 'gate', '/u/.claude')
    const npm = doctorText({ pluginVersion: '0.7.0', claude: undefined, surfaces: [], located, status: undefined,
                             daemon: parseDaemon(JSON.stringify({ ...health, claude_install: 'npm (its native binary)', parent_pid: 7 })) })
    expect(npm).toContain('Claude Code install: npm (its native binary)')
    expect(npm).not.toContain('not recognized')
    const other = doctorText({ pluginVersion: '0.7.0', claude: undefined, surfaces: [], located, status: undefined,
                               daemon: parseDaemon(JSON.stringify({ ...health, claude_install: '', parent_exe: 'bun' })) })
    expect(other).toContain('Claude Code install: not recognized (the process that asked is bun)')
    expect(other).toContain('no gateway dialog')
    // an older gated status without the fields: no line
    const old = doctorText({ pluginVersion: '0.7.0', claude: undefined, surfaces: [], located, status: undefined,
                             daemon: parseDaemon(JSON.stringify(health)) })
    expect(old).not.toContain('Claude Code install')
  })
})

// Managed execution (PLAN-v4 phase 4)
test('managedPlan: gate-sh under the plugin root; "off" and a " -" path leave no prefix', () => {
  const base = { root: '/cfg/plugins/cache/gateway/gate/0.8.0', data: '/cfg/plugins/data/gate-gateway', state: undefined, envDir: '/cfg/plugins/data/gate-gateway/envs/abc', envReady: true }
  const on = managedPlan(base)
  expect(on).toEqual({ dir: '/cfg/plugins/data/gate-gateway/managed', prefix: '/cfg/plugins/cache/gateway/gate/0.8.0/hooks/gate-sh', shell: '/cfg/plugins/data/gate-gateway/envs/abc/.pixi/envs/default/bin/bash', mode: 'on', inactive: undefined })
  expect(managedPlan({ ...base, envReady: false }).shell).toBe(undefined)
  const off = managedPlan({ ...base, state: parseManagedState('{"mode":"off"}') })
  expect(off.prefix).toBe(undefined)
  expect(off.inactive).toContain('managed = "off"')
  const dash = managedPlan({ ...base, root: '/Users/a b -c/plugins/cache/gateway/gate/0.8.0' })
  expect(dash.prefix).toBe(undefined)
  expect(dash.inactive).toContain('" -"')
  // a space alone is fine (Claude Code quotes the prefix)
  expect(managedPlan({ ...base, root: '/Users/a b/x' }).prefix).toBe('/Users/a b/x/hooks/gate-sh')
})

test('managedPlan: the managed bash only from the env launch.sh names; the gate-sh copy only when it is the plugin\'s', () => {
  const base = { root: '/cfg/plugins/cache/gateway/gate/0.8.0', data: '/cfg/plugins/data/gate-gateway', state: undefined, envDir: '/cfg/plugins/data/gate-gateway/envs/abc', envReady: true }
  const envBash = '/cfg/plugins/data/gate-gateway/envs/abc/.pixi/envs/default/bin/bash'
  // a rewritten state.json naming another program as the bash (verifier, phase 4 review)
  const evil = parseManagedState(JSON.stringify({ mode: 'on', ready: true, bash: '/tmp/not-the-gateway/bash' }))
  expect(managedPlan({ ...base, state: evil }).shell).toBe(envBash)
  expect(managedPlan({ ...base, state: evil, envReady: false }).shell).toBe(undefined)
  expect(managedPlan({ ...base, state: evil, envDir: '' }).shell).toBe(undefined)
  // the data folder's copy: only by its exact place and only while copyOk
  const copy = '/cfg/plugins/data/gate-gateway/managed/gate-sh'
  const named = parseManagedState(JSON.stringify({ mode: 'on', gate_sh: copy }))
  expect(managedPlan({ ...base, state: named, copyOk: true }).prefix).toBe(copy)
  expect(managedPlan({ ...base, state: named }).prefix).toBe('/cfg/plugins/cache/gateway/gate/0.8.0/hooks/gate-sh')
  expect(managedPlan({ ...base, state: named, copyOk: false }).prefix).toBe('/cfg/plugins/cache/gateway/gate/0.8.0/hooks/gate-sh')
  const elsewhere = parseManagedState(JSON.stringify({ mode: 'on', gate_sh: '/tmp/x/gate-sh' }))
  expect(managedPlan({ ...base, state: elsewhere, copyOk: true }).prefix).toBe('/cfg/plugins/cache/gateway/gate/0.8.0/hooks/gate-sh')
})

test('parseManagedState: only a known mode counts; lists keep their well-formed items', () => {
  expect(parseManagedState(undefined)).toBe(undefined)
  expect(parseManagedState('')).toBe(undefined)
  expect(parseManagedState('{"mode":"maybe"}')).toBe(undefined)
  expect(parseManagedState('not json')).toBe(undefined)
  const s = parseManagedState(JSON.stringify({ mode: 'warn', path: [{ dir: '/a', origin: 'x' }, { nodir: 1 }, 'str'], env: [{ name: 'A' }], pending: ['p', 3], vault_readable: false }))!
  expect(s.mode).toBe('warn')
  expect(s.path).toEqual([{ dir: '/a', origin: 'x' }])
  expect(s.env).toEqual([{ name: 'A', origin: '' }])
  expect(s.pending).toEqual(['p'])
  expect(s.vaultReadable).toBe(false)
  expect(s.found).toEqual([])
})

test('managedLines: the tool folders found here but not imported (GW-UX-2b)', () => {
  const st = parseManagedState(JSON.stringify({ mode: 'on', ready: true, bash: '/b', bash_version: '5.2.37', path: [], env: [],
                                                found: ['/opt/homebrew/bin', '/u/.cargo/bin', 3] }))!
  expect(st.found).toEqual(['/opt/homebrew/bin', '/u/.cargo/bin'])
  const lines = managedLines(undefined, st, '', '/u')
  expect(lines).toContain("  found here but not imported: /opt/homebrew/bin, ~/.cargo/bin (Claude can propose importing them: [shell] import_path, then your OK in the gateway's dialog)")
  expect(managedLines(undefined, { ...st, found: [] }, '', '/u').some((l) => l.includes('found here'))).toBe(false)
})

test('secretLine: says before any dialog whether a secret can be typed here (GW-UX-6)', () => {
  const main = secretLine(['terminal'], false, false)!
  expect(main).toContain("main screen, so a secret can't be typed into the gateway dialog's field")
  expect(main).toContain('(/gate-dialog, then Tab and Enter)')
  expect(main).toContain('Paste leaves the value on your clipboard: clear it yourself')
  expect(main).toContain('CLAUDE_CODE_NO_FLICKER=1')
  expect(main).not.toContain('tmux')
  expect(secretLine(['terminal'], false, true)).toContain('main screen (inside tmux)')
  expect(secretLine(['terminal'], true, true)).toContain('the fullscreen view')
  expect(secretLine(['terminal'], undefined, false)).toBe(undefined)
  expect(secretLine(['desktop'], undefined, false)).toContain('desktop app')
  expect(secretLine([], false, false)).toBe(undefined)                 // -p: no dialog anyway
})

test('secretLine: on Linux without a display neither typing nor Paste works on the main screen, and it says what to do (review round 2)', () => {
  expect(noDisplayHere('linux', undefined, undefined)).toBe(true)
  expect(noDisplayHere('linux', '', '')).toBe(true)
  expect(noDisplayHere('linux', ':0', undefined)).toBe(false)
  expect(noDisplayHere('linux', undefined, 'wayland-0')).toBe(false)
  expect(noDisplayHere('darwin', undefined, undefined)).toBe(false)
  expect(noDisplayHere('', undefined, undefined)).toBe(false)              // an older gated: not known
  const main = secretLine(['terminal'], false, true, true)!
  expect(main).toContain('neither typing nor Paste can work in this terminal')
  expect(main).toContain('main screen (inside tmux)')
  expect(main).toContain('no DISPLAY or WAYLAND_DISPLAY')
  expect(main).toContain('CLAUDE_CODE_NO_FLICKER=1')
  expect(main).toContain("from a Claude Code session in this machine's desktop")
  expect(main).not.toContain('press Paste')
  const full = secretLine(['terminal'], true, false, true)!
  expect(full).toContain("the fullscreen view, so the gateway dialog's field takes a click, then keys")
  expect(full).toContain("Paste from clipboard can't work here")
  expect(secretLine(['terminal'], undefined, false, true)).toContain("Paste from clipboard can't work")
  expect(secretLine(['terminal'], true, false, false)).not.toContain('Paste')
})
