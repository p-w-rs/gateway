// `claude plugin test plugins/gateway`: the /gate-hosts and /gate-accounts
// panes (PLAN-v4 phase 7) against the engine's test kit. The test's hooks
// stand beneath the plugin and play the engine and gated (/ui/manage over the
// socket) and launch.sh (process.run).
import { expect, mock, test } from 'claude-code/testing'
import { accountLine, editArgv, hostLine, lastLine, needsCredential, parseManage, words } from './manage.ts'

const HOME = '/Users/tester'
const CONFIG = `${HOME}/.claude`
const SOCKET = '/tmp/gw-501/gated.sock'

const statusJson = (): string => JSON.stringify({
  state: 'ready', root: '/plugin', data: `${CONFIG}/plugins/data/gate-inline`,
  env: `${CONFIG}/plugins/data/gate-inline/envs/0123456789ab`, lock: '0123456789ab', warm: true, older: '',
  build_running: false, install_log: false, pixi: `${HOME}/.pixi/bin/pixi`, pixi_version: 'pixi 0.81.0',
  home: `${HOME}/.config/gateway`, form: true, vault: true, vault_v2: false,
}) + '\n'
const daemonJson = (): string => JSON.stringify({
  ok: true, version: '0.9.0', protocol: 1, pid: 777, epoch: 3, started: 1792450000, uptime: 5,
  vault: 'unwrapped', sessions: 1, socket: SOCKET, lock_after: 28800, parent_pid: 4242,
}) + '\n'

const MANAGE = {
  ok: true,
  hosts: [
    { host: 'm_aaaaaaaaaaaaaaaaaaaaaaaaaa', name: 'localhost', local: true, address: '', runtime: 'ready',
      rights: { read: 'allow', exec: 'allow', elevation: 'ask' }, pending: [] },
    { host: 'm_bbbbbbbbbbbbbbbbbbbbbbbbbb', name: 'lab', local: false, address: 'u@lab.example.com',
      reachable: true, auth: true, runtime: 'ready', user: 'u',
      rights: { read: 'allow', exec: 'deny', write: 'ask', forward_agent: 'allow', forward_x11: 'deny' },
      pending: ['policy exec "deny" -> "allow"'] },
  ],
  workspaces: [{ workspace: 'w_cccccccccccccccccccccccccc', name: 'app', host: 'm_bbbbbbbbbbbbbbbbbbbbbbbbbb',
                 host_name: 'lab', root: '/srv/my app', local: '~/src/app' }],
  accounts: [
    { account: 'gh', kind: 'github', state: 'connected', login: 'octo', credential: 'fine-grained personal access token',
      checked_at: '2026-10-20T10:00:00+0000', pending: [] },
    { account: 'az', kind: 'azure', state: 'reauthentication_required', pending: [] },
  ],
  settings_pending: [],
}

test('parseManage keeps the known fields and drops what it can\'t trust', () => {
  const v = parseManage({ ...MANAGE, hosts: [...MANAGE.hosts, { name: 'Bad Name!', local: false }] })!
  expect(v.hosts.map((h) => h.name)).toEqual(['localhost', 'lab'])
  expect(v.hosts[1]!.rights).toEqual({ read: 'allow', exec: 'deny', write: 'ask', forward_agent: 'allow', forward_x11: 'deny' })
  expect(v.workspaces[0]).toEqual({ name: 'app', host: 'lab', root: '/srv/my app', local: '~/src/app', id: 'w_cccccccccccccccccccccccccc' })
  expect(parseManage({ ok: false })).toBe(undefined)
  expect(parseManage('nope')).toBe(undefined)
})

test('the lines say where a host is, its state, what isn\'t allowed and what waits for the OK', () => {
  const v = parseManage(MANAGE)!
  expect(hostLine(v.hosts[0]!)).toBe('localhost: this machine; runtime ready; elevation ask')
  expect(hostLine(v.hosts[1]!)).toBe('lab: remote u@lab.example.com; reachable yes, auth yes, runtime ready; exec deny, write ask; forwarding: agent; 1 change wait for your OK')
  expect(accountLine(v.accounts[0]!)).toBe('gh (github): connected (octo, fine-grained personal access token); checked 2026-10-20 10:00')
  expect(accountLine(v.accounts[1]!)).toBe('az (azure): needs you to sign in again')
  expect(needsCredential(v.accounts[1]!)).toBe(true)
  expect(needsCredential(v.accounts[0]!)).toBe(false)
})

test('an edit line becomes one fixed gate subcommand, nothing else', () => {
  expect(editArgv('host add build u@build.example.com sudo=ask')).toEqual({ argv: ['gate', 'host', 'add', 'build', 'u@build.example.com', 'sudo=ask'], entry: 'build' })
  expect(editArgv('workspace add lab app "/srv/my app" ~/src/app')).toEqual({ argv: ['gate', 'workspace', 'add', 'lab', 'app', '/srv/my app', '~/src/app'], entry: 'lab' })
  expect(editArgv('policy set all exec ask')).toEqual({ argv: ['gate', 'policy', 'set', 'all', 'exec', 'ask'], entry: 'settings' })
  expect(editArgv('policy set lab forward_agent allow')).toEqual({ argv: ['gate', 'policy', 'set', 'lab', 'forward_agent', 'allow'], entry: 'lab' })
  for (const bad of ['host add Build x', 'rm -rf /', 'host set lab token abc', 'host add lab u@x password=1',
    'policy set lab exec maybe', 'workspace add lab app "/srv', 'login gh', 'host set lab address a\u0007b', '']) {
    expect('error' in editArgv(bad)).toBe(true)
  }
  expect(words('a "b c" d')).toEqual(['a', 'b c', 'd'])
  expect(words('"unclosed')).toBe(undefined)
  expect(lastLine('gateway: added host build\ngateway: 1 change for build waits\n', '')).toBe('gateway: 1 change for build waits')
})

function world(on: any) {
  const fetches: string[] = []
  const runs: string[][] = []
  const opened: any[] = []
  mock.env(on, { HOME, CLAUDE_CONFIG_DIR: CONFIG })
  mock.clock(on, { now: 1_000_000 })
  on('session.start', (_$: any, e: any) => ({ cwd: e.cwd }))
  on('session.id', () => ({ value: 'sess-1' }))
  on('session.surfaces', () => ({ value: ['terminal'] }))
  on('command.register', (_$: any, e: any) => ({ value: { command: e.name } }))
  on('ui.status', () => ({ value: undefined }))
  on('ui.toast', () => ({ value: undefined }))
  on('ui.invalidate', () => ({ value: undefined }))
  on('ui.open', (_$: any, e: any) => { opened.push(e); return { value: { isPlaced: true } } })
  on('ui.close', () => ({ value: undefined }))
  on('session.version', () => ({ value: { version: '2.1.301', base: '2.1.301', builtAt: '2026-10-15T12:58:20Z' } }))
  on('process.run', (_$: any, e: any) => {
    if (e.argv[2] === 'gate') {
      runs.push(e.argv.slice(2))
      const out = e.argv[3] === 'host' ? "gateway: added host build\ngateway: 1 change for build waits for the user's OK in the gateway dialog: gate check build\n" : 'gateway: build is up to date\n'
      return { value: { exitCode: 0, stdout: out, stderr: '' } }
    }
    return { value: { exitCode: 0, stdout: e.argv[2] === 'gated' ? daemonJson() : statusJson(), stderr: '' } }
  })
  const answer = (x: unknown) => ({ value: { status: 200, ok: true, headers: {}, text: JSON.stringify(x) } })
  on('http.fetch', (_$: any, e: any) => {
    const url = String(e.url)
    if (url.includes('/ui/dialog/next')) return new Promise(() => {})
    fetches.push(url)
    if (url.includes('/ui/manage')) return answer(MANAGE)
    return answer({ ok: true })
  })
  return { fetches, runs, opened }
}

async function settle(): Promise<void> {
  for (let i = 0; i < 80; i++) await Promise.resolve()
}

const PROPS = (title: string) => ({ title, isFocused: true, bodyColumns: 100, placement: 'inline', scroll: { offset: 0, bodyRows: 20 }, view: {} })
const mountPane = ($: any, id: string, title: string) =>
  $.ui.mount({ plugin: 'gate', surface: 'terminal', component: 'Pane', requestId: id, props: PROPS(title),
               viewport: { columns: 120, rows: 40, isFullscreen: true } } as any)

test('/gate-hosts opens the pane from gated\'s view; an edit runs its gate command, then the consent check', async ($: any, on: any) => {
  const w = world(on)
  await $.session.start({ cwd: '/work', surface: 'terminal', isInteractive: true })
  await settle()
  const r = await $.command.run({ command: 'gate-hosts', args: '', origin: { kind: 'composer' } })
  expect(r.text).toBe('the gateway hosts pane is open')
  expect(w.opened.some((o) => o.id === 'gate-hosts')).toBe(true)
  expect(w.fetches.some((u) => u.endsWith('/ui/manage'))).toBe(true)
  const ui = await mountPane($, 'gate-hosts', 'Gateway hosts')
  const drawn = JSON.stringify(await ui.drawn())
  expect(drawn).toContain('lab: remote u@lab.example.com')
  expect(drawn).toContain('workspace app: /srv/my app (here: ~/src/app)')
  expect(await ui.find({ key: 'ok-lab' })).not.toBe(undefined)          // its pending change: Review
  await ui.input({ key: 'edit', text: 'host add build u@build.example.com' })
  await settle()
  expect(w.runs[0]).toEqual(['gate', 'host', 'add', 'build', 'u@build.example.com'])
  expect(w.runs[1]).toEqual(['gate', 'check', 'build'])
  await ui.input({ key: 'edit', text: 'rm -rf /' })
  await settle()
  expect(w.runs.length).toBe(2)
  await ui.press({ key: 'ok-lab' })
  await settle()
  expect(w.runs[2]).toEqual(['gate', 'check', 'lab'])
})

test('/gate-accounts shows each state and runs the check or the credential dialog', async ($: any, on: any) => {
  const w = world(on)
  await $.session.start({ cwd: '/work', surface: 'terminal', isInteractive: true })
  await settle()
  await $.command.run({ command: 'gate-accounts', args: '', origin: { kind: 'composer' } })
  const ui = await mountPane($, 'gate-accounts', 'Gateway accounts')
  const drawn = JSON.stringify(await ui.drawn())
  expect(drawn).toContain('az (azure): needs you to sign in again')
  expect(drawn).toContain('never an API credential')
  await ui.press({ key: 'check-gh' })
  await settle()
  expect(w.runs[0]).toEqual(['gate', 'accounts', '--check', 'gh', '--json'])
  await ui.press({ key: 'login-az' })
  await settle()
  expect(w.runs[1]).toEqual(['gate', 'login', 'az'])
})
