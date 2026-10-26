// The gateway mod (PLAN-v4 phases 1-4): the setup status line, provisioning at
// session start, managed execution (CLAUDE_CODE_SHELL_PREFIX -> hooks/gate-sh,
// so Claude's Bash runs in the gateway's managed bash; docs/dev/modules/managed.md),
// the gateway daemon started and this session registered on
// its UI plane, the immediate /gate-doctor, /gate-dialog, /gate-unlock and
// /gate-lock commands, and the gateway's dialogs: a native pane for every
// question the gateway asks (consent, host keys, choices, secrets), with a
// private Client field for secrets (field.tsx) whose value leaves it only
// sealed to gated. hooks/hooks.json names this module under "modules"; every
// classic hook stays, so the gateway's guards hold when mods are off (old
// Claude Code, or switched off); without the mod no dialog can open and the
// gateway says so instead of asking any other way.
//
// Commands are /gate-doctor etc., not /gate:doctor: $.command.register takes
// letters, digits, _ and - only (a colon is refused) and the engine doesn't
// prefix a mod's command with its plugin; /doctor alone is Claude Code's own
// (refused). Verified on 2.1.301.
import type { EngineInterface, Register } from 'claude-code'
import {
  DOCTOR_COMMAND,
  doctorText,
  gateShPaths,
  locate,
  managedPlan,
  noDisplayHere,
  parseDaemon,
  parseManagedState,
  parseStatus,
  REGISTER_TRIES,
  registerStopping,
  setupReady,
  shlvlOk,
  shouldProvision,
  statusLine,
  type DaemonHealth,
  type EnvStatus,
  type Located,
  type ManagedPlan,
  type ManagedState,
} from './lib.ts'
import {
  MAIN_SCREEN,
  NO_DISPLAY_MAIN,
  NO_DISPLAY_PASTE,
  NOT_RECEIVED,
  PANE,
  PASTE_NOTE,
  SIGNIN_ENV,
  UNAVAILABLE_SURFACE,
  attemptLine,
  clientSurface,
  fieldProps,
  GUARD_DROP_TEXT,
  guardEdit,
  guardPasses,
  guardSubmitPasses,
  guardText,
  isSecret,
  parseNext,
  parsePost,
  queueLine,
  resultText,
  waitingLine,
  type DialogView,
  type NextView,
} from './dialog.ts'
import {
  ACCOUNTS_EDIT_HINT,
  ACCOUNTS_PANE,
  EDIT_HINT,
  HOSTS_PANE,
  accountLine,
  editArgv,
  hostLine,
  lastLine,
  needsCredential,
  parseManage,
  workspaceLine,
  type ManageView,
} from './manage.ts'
import {
  ECHO_OFF,
  FULLSCREEN_MODE,
  MAIN_MODE,
  MIN_FRAME_MS,
  POLL_WAIT_S,
  TERM_ID,
  TERM_PANE,
  headerLine,
  ownerLine,
  paneRows,
  parseScreen,
  parseTermPost,
  type ScreenView,
} from './terminal.ts'

const POLL_MS = 3000          // launch.sh status while the env isn't ready
const TICK_MS = 1000          // the elapsed time on the status line
const READY_SHOWN_MS = 5000   // the "ready" toast (a normal state: no status line, whose glyph warns)
const GIVE_UP_MS = 20 * 60 * 1000
const LONG_POLL_S = 20        // one /ui/dialog/next wait at gated
const SKEW_SHOWN_MS = 20000   // the daemon's version-skew notice, once
const GUARD_SHOWN_MS = 4000

type Engine = EngineInterface

// What this session's mod knows (module state starts over at a reload:
// gated keeps the dialogs, and the loop fetches them again).
const S = {
  located: undefined as Located | undefined,
  socket: '',
  surface: null as string | null,
  interactive: false,
  loop: 0,                       // the running loop's generation
  view: undefined as NextView | undefined,
  rev: 0,
  epoch: 0,                      // bumped to reset the Client (the pane's ring moved onto a button, the composer was typed into)
  acked: {} as Record<string, number>,
  forwarded: {} as Record<string, number>,
  opened: '',                    // the dialog id the pane was opened for
  placed: false,
  fieldUsable: true,             // the private field can take keys here (a fullscreen terminal, the desktop app)
  noDisplay: false,              // Linux without DISPLAY or WAYLAND_DISPLAY: Paste can't work (noDisplayHere)
  remember: {} as Record<string, boolean>,
  picks: {} as Record<string, string[]>,
  toasted: new Set<string>(),
  status: {} as Record<string, string | undefined>,
  shown: undefined as string | undefined,     // what the status line shows now
  shownSet: false,
  skewShown: false,
  failures: 0,
  managed: undefined as ManagedPlan | undefined,   // what session.start set (managed execution)
  managedReplaced: '',                            // another prefix it replaced
  guardBox: undefined as string | undefined,      // what the guard let the prompt box hold (dialog.ts guardEdit)
  guardGen: 0,                                    // the guard's status line: the last refusal's
  sweepGen: 0,                                    // the box check after a refusal: the last one's
}

// The terminal pane (PLAN-v4 phase 5): which terminal it shows, gated's last
// screen, and what the Client sent (module state starts over at a reload:
// gated keeps the terminal, its screen and its owner).
const TS = {
  id: '',
  view: undefined as ScreenView | undefined,
  open: false,
  loop: 0,
  acked: {} as Record<string, number>,
  forwarded: {} as Record<string, number>,
  size: '',
  note: '',
}
const TERM_TOOL = /^mcp__plugin_gate_gw__(terminal|job)_[a-z]+$/

// The /gate-hosts and /gate-accounts panes (PLAN-v4 phase 7): gated's view,
// the last command's own line, which pane shows.
const MS = {
  view: undefined as ManageView | undefined,
  note: '',
  busy: false,
}

const STATUS_ORDER = ['guard', 'dialog', 'skew', 'setup']
const SWEEP_MS = 300          // the prompt box is checked this long after the last held-back edit

// Is the prompt-box guard on? While a dialog that asks for a secret waits
// (open, on a surface with the private field), wherever its pane is.
function guardOn(): boolean {
  const d = S.view?.dialog
  return isSecret(d) && d?.state === 'open' && clientSurface(S.surface)
}

// The guard's status line, shown until GUARD_SHOWN_MS after the LAST
// refusal (each refusal's own timer clears it only while no later one came).
function guardStatus($: Engine, text: string): void {
  const g = ++S.guardGen
  status($, 'guard', text)
  $.clock.after(GUARD_SHOWN_MS, () => {
    if (g === S.guardGen) status($, 'guard', undefined)
  })
}

// After a held-back edit, look at the box itself: characters that reached it
// without an edit the guard answered (the editor's paint, a hook the engine
// skipped) are put back to what the guard let it hold. Never a value written
// anywhere: the box is read, compared and, if needed, refilled with the
// guard's own text (the draft from before the dialog, a gateway command, or
// nothing).
function sweepSoon($: Engine): void {
  const g = ++S.sweepGen
  $.clock.after(SWEEP_MS, () => {
    if (g === S.sweepGen) void sweep($, g).catch(() => undefined)
  })
}

async function sweep($: Engine, g: number): Promise<void> {
  if (!guardOn() || S.guardBox === undefined) return
  const box = await $.prompt.read()
  const want = S.guardBox
  if (g !== S.sweepGen || !guardOn() || want === undefined) return
  if (box.text === want || guardPasses(box.text)) return
  await $.prompt.fill({ text: want, mode: 'replace' })
  S.epoch++
  $.ui.invalidate('ui.render')
}

// One status line per plugin: the most urgent of what the parts want shown.
function status($: Engine, kind: string, text: string | undefined): void {
  S.status[kind] = text
  const top = STATUS_ORDER.map((k) => S.status[k]).find((t) => t !== undefined && t !== '')
  if (top === S.shown && S.shownSet) return
  S.shown = top
  S.shownSet = true
  $.ui.status(top)
}

export const register: Register = (on) => {
  on('session.start', async ($, e, next) => {
    const started = await next(e)
    // each spelled as a literal, so validate sees the commands this module answers
    const regs = [
      () => $.command.register({ name: 'gate-doctor', description: 'Gateway diagnostics: versions, setup, pixi, vault, the gateway daemon and capabilities (no model turn)', immediate: true }),
      () => $.command.register({ name: 'gate-dialog', description: "Show the gateway's dialog that is waiting (a credential, a consent, a host key)", immediate: true }),
      () => $.command.register({ name: 'gate-unlock', description: 'Unlock the gateway vault, or set, change or remove its passphrase, in a private dialog', immediate: true }),
      () => $.command.register({ name: 'gate-lock', description: 'Lock the gateway vault now', immediate: true }),
      () => $.command.register({ name: 'gate-terminal', description: "Show a gateway terminal or job in a pane: watch it, take its input, hand it back (/gate-terminal [ID|new])", immediate: true }),
      () => $.command.register({ name: 'gate-hosts', description: "The gateway's hosts and workspaces: state, rights, add and edit (widenings need your OK in the gateway's dialog)", immediate: true }),
      () => $.command.register({ name: 'gate-accounts', description: "The gateway's accounts: connected, expired, revoked or needing a new sign-in; check them or enter a credential in the private dialog", immediate: true }),
    ]
    for (const reg of regs) {
      try {
        await reg()
      } catch {
        // another plugin refused it: /gate:status still works
      }
    }
    S.surface = e.surface
    S.interactive = e.isInteractive
    let located: Located | undefined
    try {
      located = await where($)
    } catch {
      located = undefined
    }
    S.located = located
    if (located !== undefined) {
      const first = await envStatus($, located, false)
      // Managed execution first, before any command can run: the prefix
      // (and, once the env is built, the shell Claude Code starts it from).
      try {
        await managedSetup($, located, first)
      } catch {
        // no prefix: Claude's commands run in the user's own shell, still judged by
        // the classic Bash hook (PLAN-0.11 §1.8)
      }
      let ready = false
      if (e.isInteractive) {
        try {
          ready = await watchSetup($, located, first)
        } catch {
          // the status line is a convenience; the classic hooks do the guarding
        }
      } else {
        ready = first?.state === 'ready'
      }
      // the gateway daemon: started if needed, this session registered on its
      // UI plane (from this process); -p too. A failure only shows in /gate-doctor.
      if (ready) await registerSession($, located)
    }
    return started
  })

  // A surface attached or left (Remote Control, the desktop app): gated hears
  // which ones draw, since only a terminal or the desktop app has the private field.
  on('session.attach', async ($, e, next) => {
    const r = await next(e)
    if (S.located !== undefined && S.socket !== '') void registerSession($, S.located, false)
    return r
  })
  on('session.detach', async ($, e, next) => {
    const r = await next(e)
    if (S.located !== undefined && S.socket !== '') void registerSession($, S.located, false)
    return r
  })

  on('command.run', { command: 'gate-doctor' }, async ($, e) => {
    const located = await where($)
    const [pluginVersion, claude, surfaces, st] = await Promise.all([
      $.fs.read(`${$.plugin.root}/.claude-plugin/plugin.json`)
        .then((t) => {
          const v = (JSON.parse(typeof t === 'string' ? t : '{}') as { version?: unknown }).version
          return typeof v === 'string' ? v : undefined
        })
        .catch(() => undefined),
      $.session.version().catch(() => undefined),
      $.session.surfaces().catch(() => [] as readonly string[]),
      envStatus($, located, true),
    ])
    const daemon = st?.state === 'ready' ? await daemonRun($, located, 'status') : undefined
    const managed = await managedNow($, located, st)
    // can a secret be typed here (GW-UX-6): the terminal says whether it is
    // in the fullscreen layout, fixed for the session
    const fullscreen = e.presentation?.isFullscreen
    const tmux = ((await $.env.get('TMUX').catch(() => undefined)) ?? '') !== ''
    const noDisplay = await displayless($, daemon?.platform ?? '')
    return { text: doctorText({ pluginVersion, claude, surfaces, located, status: st, daemon, managed, fullscreen, tmux, noDisplay }) }
  })

  // /gate-dialog: show the dialog that waits (an open the person asked for is
  // placed at any terminal width).
  on('command.run', { command: 'gate-dialog' }, async ($) => {
    const d = S.view?.dialog
    if (d === null || d === undefined) return { text: 'no gateway dialog is waiting' }
    // opened anew, so the keyboard request is made again (an open pane only retitles)
    if (S.opened !== '') await $.ui.close({ id: PANE }).catch(() => undefined)
    const r = await $.ui.open({ id: PANE, title: d.title || 'Gateway', focus: true, holdToasts: true, rows: rowsFor(d) }).catch(() => undefined)
    S.placed = r?.isPlaced === true
    S.opened = d.id
    if (S.placed) status($, 'dialog', undefined)
    return { text: S.placed ? 'the gateway dialog is open' : "the gateway dialog couldn't be shown here" }
  })

  // /gate-unlock: the unlock dialog (a locked vault), the first-time "set a
  // vault passphrase" dialog (a vault whose key has none), or gated's menu to
  // change or remove the passphrase (an unlocked vault: PLAN-0.11 §19.14).
  on('command.run', { command: 'gate-unlock' }, async ($) => {
    const r = await ui($, 'POST', '/ui/vault/unlock', {})
    if (r === undefined) return { text: "the gateway daemon isn't reachable (/gate-doctor says why)" }
    if (r.available === true) return { text: 'the gateway dialog for the vault passphrase is open' }
    return { text: clean(String(r.message ?? "the vault can't be unlocked here")) }
  })

  on('command.run', { command: 'gate-lock' }, async ($) => {
    const r = await ui($, 'POST', '/ui/vault/lock', {})
    if (r === undefined) return { text: "the gateway daemon isn't reachable (/gate-doctor says why)" }
    return { text: clean(String(r.message ?? (r.locked === true ? 'the vault is locked' : 'nothing to lock'))) }
  })

  // /gate-terminal [ID|new]: a gateway terminal (or job) in a pane. No ID:
  // this session's newest live terminal (else anyone's); `new` opens one
  // the person holds from the start.
  on('command.run', { command: 'gate-terminal' }, async ($, e) => {
    const arg = e.args.trim()
    let id = ''
    if (arg === 'new') {
      const r = await ui($, 'POST', '/ui/term/open', { cols: Math.max(40, Math.min(200, (e.presentation?.columns ?? 100) - 6)), rows: 24 })
      if (r === undefined) return { text: "the gateway daemon isn't reachable (/gate-doctor says why)" }
      if (r.ok !== true || typeof r.id !== 'string') return { text: clean(String(r.message ?? "the terminal couldn't be opened")) }
      id = r.id
    } else if (arg !== '') {
      if (!TERM_ID.test(arg)) return { text: 'usage: /gate-terminal [t_... | j_... | new]' }
      id = arg
    } else {
      const r = await ui($, 'GET', '/ui/term/list')
      if (r === undefined) return { text: "the gateway daemon isn't reachable (/gate-doctor says why)" }
      const all = [...(Array.isArray(r.terminals) ? r.terminals : []), ...(Array.isArray(r.jobs) ? r.jobs : [])] as Record<string, unknown>[]
      const live = all.filter((t) => t.state === 'open' || t.state === 'running' || t.state === 'waiting_auth' || t.state === 'suspended')
        .sort((a, b) => Number(b.created ?? 0) - Number(a.created ?? 0))
      const chosen = (live.find((t) => t.mine === true) ?? live[0])?.id
      if (typeof chosen !== 'string') return { text: 'no gateway terminal is open (/gate-terminal new opens one; Claude opens one with terminal_open)' }
      id = chosen
    }
    await openTerminal($, id)
    return { text: `${id} is open in the gateway terminal pane` }
  })

  // The terminal pane: the screen in a Client (term.tsx), whose click takes
  // the input; on the main screen (no clicks reach plugins) a line field and
  // buttons instead. Never a field for a password (ECHO_OFF).
  on('ui.render', { component: 'Pane', requestId: 'gate-terminal' }, ($, e) => {
    const { Box, Text, Button, Client, Input } = $.ui.resolve(e) as any
    const v = TS.view
    if (v === undefined) return <Box><Text dimColor>{TS.id !== '' ? `Loading ${TS.id}…` : 'No gateway terminal is shown.'}</Text></Box>
    const full = e.surface === 'desktop' || (e.surface === 'terminal' && e.viewport?.isFullscreen !== false)
    const bodyRows = typeof (e.props as any)?.scroll?.bodyRows === 'number' ? (e.props as any).scroll.bodyRows as number : 0
    const height = Math.max(5, Math.min(v.rows > 0 ? v.rows : 24, bodyRows > 0 ? bodyRows - (full ? 5 : 7) : 200))
    const rows: any[] = []
    rows.push(<Text key="hdr" bold wrap="truncate-end">{headerLine(v)}</Text>)
    rows.push(<Text key="owner" color={v.owner === 'user' ? 'green' : undefined} wrap="truncate-end">{ownerLine(v)}</Text>)
    rows.push(<Text key="mode" dimColor wrap="truncate-end">{full ? FULLSCREEN_MODE : MAIN_MODE}</Text>)
    if (v.echoOff) rows.push(<Text key="echo" color="yellow">{ECHO_OFF}</Text>)
    else if (v.auth !== '') rows.push(<Text key="auth" dimColor>{v.auth}</Text>)
    rows.push(<Client key={`term-${v.id}`} module="./term.tsx" width="100%" height={height}
      props={{ id: v.id, lines: v.lines, cursor: v.cursor, owner: v.owner, echoOff: v.echoOff, ack: TS.acked[`term-${v.id}`] ?? 0 }} />)
    if (!full && !v.ended && v.state !== 'exited' && !v.echoOff && e.surface !== 'mobile') {
      rows.push(<Input key="line" label="line" placeholder="type a line; Enter sends it (never a password)" submitLabel="send" autoFocus
        onSubmit={(t: string) => void termKeys($, v.id, [{ k: 'line', v: t }])} />)
    }
    if (TS.note !== '') rows.push(<Text key="note" dimColor>{TS.note}</Text>)
    const buttons: any[] = []
    if (!v.ended && v.state !== 'exited') {
      buttons.push(v.owner === 'user'
        ? <Button key="release" onPress={() => void termPost($, '/ui/term/release', { id: v.id })}>Hand back to Claude</Button>
        : <Button key="take" variant="primary" onPress={() => void termPost($, '/ui/term/take', { id: v.id })}>Take</Button>)
      buttons.push(<Button key="int" onPress={() => void termKeys($, v.id, [{ k: 'key', v: 'C-c' }])}>Interrupt (^C)</Button>)
      buttons.push(<Button key="eof" onPress={() => void termKeys($, v.id, [{ k: 'key', v: 'C-d' }])}>EOF (^D)</Button>)
      buttons.push(<Button key="esc" onPress={() => void termKeys($, v.id, [{ k: 'key', v: 'Escape' }])}>Esc</Button>)
      if (!full) buttons.push(<Button key="enter" onPress={() => void termKeys($, v.id, [{ k: 'key', v: 'Enter' }])}>Enter</Button>)
    }
    return (
      <Box flexDirection="column">
        {rows}
        <Box flexDirection="row" gap={2}>{buttons}</Box>
      </Box>
    )
  })

  // /gate-hosts and /gate-accounts (PLAN-v4 phase 7): the management panes.
  on('command.run', { command: 'gate-hosts' }, async ($) => {
    if (!(await loadManage($))) return { text: "the gateway daemon isn't reachable (/gate-doctor says why)" }
    const r = await $.ui.open({ id: HOSTS_PANE, title: 'Gateway hosts', focus: true, rows: 20 }).catch(() => undefined)
    return { text: r?.isPlaced === true ? 'the gateway hosts pane is open' : "the gateway hosts pane couldn't be shown here" }
  })
  on('command.run', { command: 'gate-accounts' }, async ($) => {
    if (!(await loadManage($))) return { text: "the gateway daemon isn't reachable (/gate-doctor says why)" }
    const r = await $.ui.open({ id: ACCOUNTS_PANE, title: 'Gateway accounts', focus: true, rows: 16 }).catch(() => undefined)
    return { text: r?.isPlaced === true ? 'the gateway accounts pane is open' : "the gateway accounts pane couldn't be shown here" }
  })

  on('ui.render', { component: 'Pane', requestId: HOSTS_PANE }, ($, e) => {
    const { Box, Text, Button, Input } = $.ui.resolve(e) as any
    const v = MS.view
    if (v === undefined) return <Box><Text dimColor>Loading the gateway's hosts…</Text></Box>
    const rows: any[] = []
    for (const hr of v.hosts) {
      rows.push(<Text key={`h-${hr.name}`} wrap="wrap">{hostLine(hr)}</Text>)
      for (const w of v.workspaces.filter((x) => x.host === hr.name)) {
        rows.push(<Text key={`w-${hr.name}-${w.name}`} dimColor wrap="wrap">{workspaceLine(w)}</Text>)
      }
    }
    if (v.settingsPending.length > 0) rows.push(<Text key="settings" color="yellow">{`settings: ${v.settingsPending.length} change(s) wait for your OK`}</Text>)
    const buttons: any[] = v.hosts.filter((hr) => hr.pending.length > 0)
      .map((hr) => <Button key={`ok-${hr.name}`} onPress={() => void gateCheck($, hr.name)}>{`Review ${hr.name}…`}</Button>)
    if (v.settingsPending.length > 0) buttons.push(<Button key="ok-settings" onPress={() => void gateCheck($, 'settings')}>Review settings…</Button>)
    buttons.push(<Button key="refresh" onPress={() => void refreshManage($)}>Refresh</Button>)
    return (
      <Box flexDirection="column">
        {rows.length > 0 ? rows : <Text dimColor>No hosts yet besides this machine.</Text>}
        {e.surface !== 'mobile' ? <Input key="edit" label="edit" placeholder={EDIT_HINT} submitLabel="apply"
          onSubmit={(t: string) => void editLine($, t)} /> : null}
        {MS.note !== '' ? <Text key="note" dimColor wrap="wrap">{MS.note}</Text> : null}
        <Box flexDirection="row" gap={2}>{buttons}</Box>
      </Box>
    )
  })

  on('ui.render', { component: 'Pane', requestId: ACCOUNTS_PANE }, ($, e) => {
    const { Box, Text, Button, Input } = $.ui.resolve(e) as any
    const v = MS.view
    if (v === undefined) return <Box><Text dimColor>Loading the gateway's accounts…</Text></Box>
    const rows: any[] = []
    for (const a of v.accounts) {
      rows.push(<Text key={`a-${a.account}`} color={needsCredential(a) ? 'yellow' : undefined} wrap="wrap">{accountLine(a)}</Text>)
      rows.push(
        <Box key={`b-${a.account}`} flexDirection="row" gap={2}>
          <Button key={`check-${a.account}`} onPress={() => void accountCheck($, a.account)}>{`Check ${a.account}`}</Button>
          <Button key={`login-${a.account}`} onPress={() => void gateLogin($, a.account)}>{`Enter a credential for ${a.account}…`}</Button>
          {a.pending.length > 0 ? <Button key={`review-${a.account}`} onPress={() => void gateCheck($, a.account)}>{`Review ${a.account}…`}</Button> : null}
        </Box>)
    }
    return (
      <Box flexDirection="column">
        {rows.length > 0 ? rows : <Text dimColor>No accounts in gateway.toml yet.</Text>}
        <Text dimColor wrap="wrap">A browser login is never an API credential here: states come from each service's own API with the gateway's stored credential.</Text>
        {e.surface !== 'mobile' ? <Input key="edit" label="edit" placeholder={ACCOUNTS_EDIT_HINT} submitLabel="apply"
          onSubmit={(t: string) => void editLine($, t)} /> : null}
        {MS.note !== '' ? <Text key="note" dimColor wrap="wrap">{MS.note}</Text> : null}
        <Box flexDirection="row" gap={2}><Button key="refresh" onPress={() => void refreshManage($)}>Refresh</Button></Box>
      </Box>
    )
  })

  // Which agent loop (the main one, a subagent) made a terminal or job tool
  // call: gated hears it on the UI plane, keyed by the tool use id the gw MCP
  // server passes on (its _meta), so one agent at a time holds a terminal's
  // input. Without the mod gated can't tell agents apart (all count as one).
  on('tool.call', async ($, e, next) => {
    const tool = (e as unknown as { tool?: unknown }).tool
    const tid = (e as unknown as { tool_use_id?: unknown }).tool_use_id
    if (typeof tool === 'string' && TERM_TOOL.test(tool) && typeof tid === 'string' && tid !== '' && S.socket !== '') {
      await ui($, 'POST', '/ui/term/agent', { tool_use_id: tid, agent: e.agentId ?? '' })
    }
    return next(e)
  }).catch(($, e, next) => (next.called ? undefined : next(e)))

  // The dialog pane.
  on('ui.render', { component: 'Pane', requestId: 'gate-dialog' }, ($, e) => {
    const { Box, Text, Button } = $.ui.resolve(e) as any
    const d = S.view?.dialog ?? null
    // A Client takes keys only after a click, and the terminal reports clicks
    // only in its fullscreen layout: on the main screen (CLAUDE_CODE_NO_FLICKER=0,
    // tmux) the field can't be focused, so it isn't drawn (Paste still works).
    const usable = clientSurface(e.surface) && !(e.surface === 'terminal' && e.viewport?.isFullscreen === false)
    S.fieldUsable = usable
    if (d === null) return <Box><Text dimColor>No gateway dialog is waiting.</Text></Box>
    const rows: any[] = []
    rows.push(<Text key="title" bold>{d.title || 'Gateway'}</Text>)
    d.lines.forEach((l, i) => rows.push(<Text key={`line${i}`}>{l}</Text>))
    const err = attemptLine(d)
    if (err !== undefined) rows.push(<Text key="err" color="red">{err}</Text>)
    const buttons: any[] = []
    // Keys for the dialogs without a field (the pane holds the keyboard after
    // ctrl+x tab, a click or /gate-dialog): y and n, a digit per option. A
    // secret's dialog has none: letters meant for the field must never press.
    const secret = isSecret(d)
    const cancel = (label = d.cancel_label) => (
      <Button key="cancel" role="dismiss" hotkey={secret ? undefined : 'n'} autoFocus={d.default_cancel || undefined}
        onPress={() => void cancelDialog($, d)}>{label}</Button>
    )
    // "Remember it" (where storing is optional: a sudo password a command
    // asks for): unticked, the value is used once and never stored. It goes
    // with a typed value and with Paste alike.
    const remember = () => {
      const keep = S.remember[d.id] ?? d.remember
      return <Button key="remember" onPress={() => { S.remember[d.id] = !keep; $.ui.invalidate('ui.render') }}>{keep ? '[x] Remember it' : '[ ] Remember it'}</Button>
    }
    if (d.state !== 'open') {
      rows.push(<Text key="checking" dimColor>Checking…</Text>)
    } else if (isSecret(d)) {
      if (usable && d.pub !== '') {
        const { Client } = $.ui.resolve(e) as any
        rows.push(
          <Client key={fieldKey(d)} module="./field.tsx" width="100%" height={(d.fields > 1 ? 2 : 1) + 1}
            props={fieldProps(d, S.epoch, S.acked[fieldKey(d)] ?? 0)} />,
        )
        if (d.paste && S.noDisplay) rows.push(<Text key="nopaste" dimColor>{NO_DISPLAY_PASTE}</Text>)
        if (d.paste) buttons.push(<Button key="paste" onPress={() => void paste($, d)}>Paste from clipboard</Button>)
        if (d.remember !== null) buttons.push(remember())
      } else if (clientSurface(e.surface)) {
        // on Linux without a display Paste can't work either: say so and what to do
        rows.push(<Text key="nofield">{S.noDisplay ? NO_DISPLAY_MAIN : MAIN_SCREEN}</Text>)
        if (d.paste) buttons.push(<Button key="paste" onPress={() => void paste($, d)}>Paste from clipboard</Button>)
        if (d.paste && d.remember !== null) buttons.push(remember())
      } else {
        rows.push(<Text key="nofield">{UNAVAILABLE_SURFACE}</Text>)
      }
      buttons.push(cancel())
    } else if (d.kind === 'choice') {
      // one option per row: the labels are sentences
      d.options.forEach((o, i) => rows.push(<Button key={`opt${i}`} hotkey={i < 9 ? String(i + 1) : undefined} onPress={() => void answer($, d, { choice: o })}>{o}</Button>))
      buttons.push(cancel())
    } else if (d.kind === 'checklist') {
      const picked = S.picks[d.id] ?? d.checked
      d.options.forEach((o, i) => rows.push(
        <Button key={`chk${i}`} plain hotkey={i < 9 ? String(i + 1) : undefined} onPress={() => { S.picks[d.id] = picked.includes(o) ? picked.filter((x) => x !== o) : [...picked, o]; $.ui.invalidate('ui.render') }}>
          {`${picked.includes(o) ? '[x]' : '[ ]'} ${o}`}
        </Button>,
      ))
      buttons.push(<Button key="ok" variant="primary" hotkey="y" onPress={() => void answer($, d, { picked })}>{d.ok_label}</Button>)
      buttons.push(cancel())
    } else if (d.kind === 'text') {
      if (d.input && e.surface !== 'mobile') {
        const { Input } = $.ui.resolve(e) as any
        rows.push(<Input key="text" placeholder="type it here, then Enter" onSubmit={(v: string) => void answer($, d, { text: v })} />)
      } else if (d.default !== '') {
        rows.push(<Text key="default">{d.default}</Text>)
        buttons.push(<Button key="copy" onPress={(p: any) => void $.ui.copy({ text: d.default, surface: p.surface })}>Copy</Button>)
      }
      if (!d.input) buttons.push(<Button key="ok" variant="primary" hotkey="y" onPress={() => void answer($, d, {})}>{d.ok_label}</Button>)
      buttons.push(cancel())
    } else {
      // confirm (consent, host key, import summary) and info
      buttons.push(<Button key="ok" variant={d.default_cancel ? undefined : 'primary'} hotkey="y" onPress={() => void answer($, d, {})}>{d.ok_label}</Button>)
      if (d.kind !== 'info') buttons.push(cancel())
    }
    const q = queueLine(S.view?.queue ?? [])
    return (
      <Box flexDirection="column">
        {rows}
        <Box flexDirection="row" gap={2}>{buttons}</Box>
        {q !== undefined ? <Text dimColor>{q}</Text> : null}
      </Box>
    )
  })

  // The Client's posts: sealed items only, forwarded to gated as they are,
  // each sequence number of one field instance (its key: dialog, attempt,
  // reset epoch) once.
  on('ui.message', async ($, e) => {
    // the terminal pane's Client: the person's keys (each batch once), a
    // click (the takeover), the region's size (the terminal follows it)
    const tp = parseTermPost(e.data)
    if (tp !== undefined) {
      const inst = e.element
      for (const b of tp.batches) {
        if ((TS.forwarded[inst] ?? 0) >= b.seq) continue
        TS.forwarded[inst] = b.seq
        if (b.items.length > 0) await termKeys($, tp.id, b.items, b.seq)
        else if (b.take) await termPost($, '/ui/term/take', { id: tp.id })
      }
      if (tp.size !== undefined) {
        const sz = `${tp.id}:${tp.size.cols}x${tp.size.rows}`
        if (sz !== TS.size) {
          TS.size = sz
          await ui($, 'POST', '/ui/term/resize', { id: tp.id, cols: tp.size.cols, rows: tp.size.rows })
        }
      }
      TS.acked[inst] = Math.max(TS.acked[inst] ?? 0, tp.seq)
      const v = TS.view
      return v !== undefined && v.id === tp.id
        ? { props: { id: v.id, lines: v.lines, cursor: v.cursor, owner: v.owner, echoOff: v.echoOff, ack: TS.acked[inst] } }
        : {}
    }
    const p = parsePost(e.data)
    const d = S.view?.dialog
    if (p === undefined || d === undefined || d === null) return {}
    const inst = e.element
    for (const it of p.items) {
      if ((S.forwarded[inst] ?? 0) >= it.seq) continue
      S.forwarded[inst] = it.seq
      const body: Record<string, unknown> = { id: it.id, attempt: it.attempt, epk: it.epk, nonce: it.nonce, box: it.box }
      if (d.id === it.id && d.remember !== null) body.remember = S.remember[d.id] ?? d.remember
      const r = await ui($, 'POST', '/ui/dialog/submit', body)
      // gated couldn't open it (a key that changed under the field, a stale
      // attempt): the field starts over, and the person is told to type again
      if (r !== undefined && r.ok !== true && (r.error === 'box' || r.error === 'stale') && d.id === it.id) {
        S.epoch++
        guardStatus($, NOT_RECEIVED)
        $.ui.invalidate('ui.render')
      }
    }
    S.acked[inst] = Math.max(S.acked[inst] ?? 0, p.seq)
    return { props: fieldProps(d, S.epoch, S.acked[inst] ?? 0) }
  })

  // The guard: while a dialog waits for a secret, what is typed into the
  // prompt box is held back (it was meant for the dialog), wherever the
  // dialog is: drawn with its field (click it first), on the terminal's main
  // screen where no field can be drawn (Paste, or the fullscreen view), or in
  // a pane the person closed (/gate-dialog). Only the gateway's own commands
  // pass (/gate-dialog brings the dialog back). It can't hide those keys
  // from other plugins' prompt.edit hooks or the editor's one-frame paint
  // (FEASIBILITY-v4 P1). The box goes back to what the guard let it hold,
  // never to the draft an edit came with (which can hold keys the editor
  // painted before an earlier refusal arrived: dialog.ts guardEdit); a hook
  // failure or re-entry gets the same answer from the .catch (never the edit
  // let through); and the box is checked once more after the typing stops.
  on('prompt.edit', ($, e, next) => {
    if (!guardOn()) {
      S.guardBox = undefined
      return next(e)
    }
    S.epoch++                                    // the keys are in the composer: the field starts over
    $.ui.invalidate('ui.render')
    const g = guardEdit(e, S.guardBox)
    S.guardBox = g.text
    if (g.pass) return next(e)
    guardStatus($, guardText(S.placed, S.fieldUsable, S.noDisplay))
    sweepSoon($)
    return { text: g.text, cursor: g.cursor }
  }).catch(($, e, next) => {
    if (next.called) return next(e)
    if (!guardOn()) return next(e)
    const g = guardEdit(e, S.guardBox)
    S.guardBox = g.text
    return g.pass ? next(e) : { text: g.text, cursor: g.cursor }
  })

  // The last line: a prompt the person submits while a secret dialog waits
  // goes only when it is what the guard let the box hold (or a slash command:
  // /gate-dialog), so stray characters of a secret never reach the model.
  on('prompt.submit', ($, e, next) => {
    if (!guardOn() || e.origin?.kind !== 'composer' || e.command !== undefined) return next(e)
    const ok = guardSubmitPasses(e.text, S.guardBox)
    S.guardBox = ''                              // Enter empties the box
    if (ok) return next(e)
    guardStatus($, guardText(S.placed, S.fieldUsable, S.noDisplay))
    return { drop: GUARD_DROP_TEXT }
  }).catch(($, e, next) => {
    if (next.called) return next(e)
    if (!guardOn() || e.origin?.kind !== 'composer' || e.command !== undefined) return next(e)
    return guardSubmitPasses(e.text, S.guardBox) ? next(e) : { drop: GUARD_DROP_TEXT }
  })

  // Focus moving away from the field: the pane's ring moving onto one of its
  // buttons (Tab, a click on Paste or Cancel) takes the keys from the field,
  // so the field starts over (a new instance, nothing typed in it). Escape
  // and a click outside the pane give no event; the field itself starts over
  // at the click that gives it the keys again (field.tsx).
  on('ui.focus', { requestId: 'gate-dialog' }, async ($, e, next) => {
    const r = await next(e)
    // `element`: the key now holding the ring (absent on the engine's close
    // mark); `key` where only $.ui.focus's own arguments arrive (the test kit)
    const onto = e.element ?? (e as unknown as { key?: string }).key
    if (r?.deny === undefined && onto !== undefined && isSecret(S.view?.dialog)) {
      S.epoch++
      $.ui.invalidate('ui.render')
    }
    return r
  }).catch(($, e, next) => (next.called ? undefined : next(e)))

  // The person closed the pane (close mark, Escape): the dialog waits in
  // gated; the status line says how to bring it back. Never keeps a pane open.
  on('ui.close', async ($, e, next) => {
    const r = await next(e)
    if (e.id === TERM_PANE) {
      // the terminal lives on in gated; /gate-terminal shows it again
      TS.open = false
      TS.loop++
    }
    if (e.id === PANE) {
      S.placed = false
      const d = S.view?.dialog
      if (d !== null && d !== undefined && e.origin.kind === 'person') status($, 'dialog', waitingLine(d))
    }
    return r
  }).catch(($, e, next) => (next.called ? undefined : next(e)))
}

// The terminal pane: opened (or retitled) for `id`, its screen loop started.
async function openTerminal($: Engine, id: string): Promise<void> {
  if (TS.id !== id) {
    TS.view = undefined
    TS.size = ''
    TS.note = ''
  }
  TS.id = id
  TS.open = true
  await $.ui.open({ id: TERM_PANE, title: `Gateway ${id.startsWith('j_') ? 'job' : 'terminal'} ${id.slice(0, 8)}…`, focus: true, rows: paneRows(TS.view) }).catch(() => undefined)
  void termLoop($).catch(() => undefined)
}

// gated's screen for the open pane: a long poll that answers when the screen
// changes (at most MIN_FRAME_MS apart: a bounded redraw rate).
async function termLoop($: Engine): Promise<void> {
  const gen = ++TS.loop
  let failures = 0
  while (gen === TS.loop && TS.open && TS.id !== '') {
    const seq = TS.view?.id === TS.id ? TS.view.seq : 0
    let v: ScreenView | undefined
    try {
      const r = await $.http.fetch(`http://gated/ui/term/screen?id=${TS.id}&seq=${seq}&wait=${POLL_WAIT_S}`, { socketPath: S.socket })
      v = r.ok ? parseScreen(r.text) : undefined
      if (r.status === 404 || r.status === 400) {
        TS.note = 'that terminal is gone'
        $.ui.invalidate('ui.render')
        return
      }
    } catch {
      v = undefined
    }
    if (gen !== TS.loop) return
    if (v === undefined) {
      failures++
      await $.clock.sleep(Math.min(5000, 300 * failures))
      continue
    }
    failures = 0
    TS.view = v
    $.ui.invalidate('ui.render')
    if (v.ended) return
    await $.clock.sleep(MIN_FRAME_MS)
  }
}

async function termPost($: Engine, path: string, body: Record<string, unknown>): Promise<void> {
  const r = await ui($, 'POST', path, body)
  TS.note = r !== undefined && r.ok === false ? clean(String(r.message ?? '')) : ''
  if (TS.view !== undefined && r !== undefined && (r.owner === 'user' || r.owner === 'agent')) {
    TS.view = { ...TS.view, owner: r.owner }
  }
  $.ui.invalidate('ui.render')
}

async function termKeys($: Engine, id: string, items: { k: string; v: string }[], seq?: number): Promise<void> {
  const r = await ui($, 'POST', '/ui/term/keys', { id, items, ...(seq !== undefined ? { seq } : {}) })
  TS.note = r === undefined ? "the gateway daemon isn't reachable" : typeof r.refused === 'string' ? clean(r.refused)
    : r.ok === false ? clean(String(r.message ?? '')) : ''
  if (TS.view !== undefined && r !== undefined && r.owner === 'user') TS.view = { ...TS.view, owner: 'user' }
  $.ui.invalidate('ui.render')
}

function clean(s: string): string {
  return s.replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/^gateway: /, '').slice(0, 400)
}

// The field instance's key: a new one (nothing typed in it) for every
// dialog, attempt and reset.
function fieldKey(d: DialogView): string {
  return `field-${d.id}-${d.attempt}-${S.epoch}`
}

function rowsFor(d: DialogView): number {
  return Math.min(24, 5 + d.lines.length + (d.kind === 'checklist' ? d.options.length : 0) + (isSecret(d) ? 2 : 0))
}

// A request on gated's UI plane from this process; the parsed JSON or undefined.
async function ui($: Engine, method: string, path: string, body?: Record<string, unknown>): Promise<Record<string, unknown> | undefined> {
  if (S.socket === '') return undefined
  try {
    const r = await $.http.fetch(`http://gated${path}`, {
      method,
      socketPath: S.socket,
      headers: { 'content-type': 'application/json' },
      ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
    })
    const v = JSON.parse(r.text) as unknown
    return typeof v === 'object' && v !== null ? (v as Record<string, unknown>) : undefined
  } catch {
    return undefined
  }
}

// -- the management panes (PLAN-v4 phase 7) -----------------------------------

async function loadManage($: Engine): Promise<boolean> {
  if (S.socket === '' && S.located !== undefined) await registerSession($, S.located, false)
  const v = parseManage(await ui($, 'GET', '/ui/manage'))
  if (v === undefined) return false
  MS.view = v
  return true
}

async function refreshManage($: Engine): Promise<void> {
  await loadManage($)
  $.ui.invalidate('ui.render')
}

// `launch.sh gate ARGV...` (an argv: no shell string, nothing secret on it).
async function gateRun($: Engine, argv: string[]): Promise<{ code: number; out: string; err: string } | undefined> {
  const located = S.located ?? await where($).catch(() => undefined)
  if (located === undefined) return undefined
  try {
    const r = await $.process.run(['sh', `${$.plugin.root}/hooks/launch.sh`, ...argv], {
      env: { CLAUDE_PLUGIN_DATA: located.data }, timeoutMs: 60000,
    })
    return { code: r.exitCode ?? 1, out: r.stdout, err: r.stderr }
  } catch {
    return undefined
  }
}

// A command that opens the gateway's dialogs (gate check, gate login): run in
// the background, the panes refresh when it ends.
function gateDialog($: Engine, argv: string[], note: string): void {
  MS.note = note
  $.ui.invalidate('ui.render')
  void (async () => {
    const r = await gateRun($, argv)
    MS.note = r === undefined ? "the gateway command couldn't run" : (lastLine(r.out, r.err) || note)
    await refreshManage($)
  })()
}

function gateCheck($: Engine, entry: string): void {
  gateDialog($, ['gate', 'check', entry], `${entry}: the gateway's dialog asks for your OK`)
}

function gateLogin($: Engine, account: string): void {
  gateDialog($, ['gate', 'login', account], `${account}: the gateway's private dialog takes the credential`)
}

async function accountCheck($: Engine, account: string): Promise<void> {
  if (MS.busy) return
  MS.busy = true
  try {
    MS.note = `checking ${account}…`
    $.ui.invalidate('ui.render')
    const r = await gateRun($, ['gate', 'accounts', '--check', account, '--json'])
    MS.note = r === undefined || r.code !== 0 ? (r ? lastLine(r.out, r.err) : "the check couldn't run") : `${account} checked`
    await refreshManage($)
  } finally {
    MS.busy = false
  }
}

// The pane's edit line: one fixed gate subcommand (manage.ts editArgv), then
// the gateway's consent dialog for whatever it widened (gate check ENTRY).
async function editLine($: Engine, line: string): Promise<void> {
  const ed = editArgv(line)
  if ('error' in ed) {
    MS.note = ed.error
    $.ui.invalidate('ui.render')
    return
  }
  const r = await gateRun($, ed.argv)
  MS.note = r === undefined ? "the gateway command couldn't run" : lastLine(r.out, r.err)
  await refreshManage($)
  if (r !== undefined && r.code === 0 && /wait.* for the user's OK/.test(`${r.out}`)) gateCheck($, ed.entry)
}

async function cancelDialog($: Engine, d: DialogView): Promise<void> {
  await ui($, 'POST', '/ui/dialog/cancel', { id: d.id })
}

async function answer($: Engine, d: DialogView, extra: Record<string, unknown>): Promise<void> {
  const body: Record<string, unknown> = { id: d.id, button: 'ok', ...extra }
  // a browser sign-in's Open (PLAN-0.11 §7.2): the system browser gated opens
  // needs Claude Code's display variables on Linux; they are checked there
  if (d.signin !== null) body.env = await signinEnv($)
  await ui($, 'POST', '/ui/dialog/answer', body)
}

// Claude Code's display and desktop variables for the system browser, and
// SSH_CONNECTION (SIGNIN_ENV, in its order, each read by its literal name;
// gated's own environment has none).
async function signinEnv($: Engine): Promise<Record<string, string>> {
  const got = await Promise.all([
    $.env.get('DISPLAY').catch(() => undefined),
    $.env.get('WAYLAND_DISPLAY').catch(() => undefined),
    $.env.get('XAUTHORITY').catch(() => undefined),
    $.env.get('XDG_RUNTIME_DIR').catch(() => undefined),
    $.env.get('DBUS_SESSION_BUS_ADDRESS').catch(() => undefined),
    $.env.get('XDG_CURRENT_DESKTOP').catch(() => undefined),
    $.env.get('XDG_DATA_DIRS').catch(() => undefined),
    $.env.get('SSH_CONNECTION').catch(() => undefined),
  ])
  const env: Record<string, string> = {}
  got.forEach((v, i) => {
    if (typeof v === 'string' && v !== '') env[SIGNIN_ENV[i]!] = v
  })
  return env
}

// "Paste from clipboard": gated reads the OS clipboard itself; the value never
// passes through Claude Code. On Linux it needs Claude Code's display
// variables (gated's own environment has none); they are checked there.
async function paste($: Engine, d: DialogView): Promise<void> {
  const env: Record<string, string> = {}
  const got = await Promise.all([
    $.env.get('DISPLAY').catch(() => undefined),
    $.env.get('WAYLAND_DISPLAY').catch(() => undefined),
    $.env.get('XAUTHORITY').catch(() => undefined),
    $.env.get('XDG_RUNTIME_DIR').catch(() => undefined),
  ])
  const names = ['DISPLAY', 'WAYLAND_DISPLAY', 'XAUTHORITY', 'XDG_RUNTIME_DIR']
  got.forEach((v, i) => {
    if (typeof v === 'string' && v !== '') env[names[i]!] = v
  })
  const body: Record<string, unknown> = { id: d.id, env }
  if (d.remember !== null) body.remember = S.remember[d.id] ?? d.remember
  const r = await ui($, 'POST', '/ui/dialog/paste', body)
  // gated read the clipboard (whether the value then passed its recheck or
  // not); it never clears it (GW-UX-6). Only a clipboard it couldn't read
  // (error "clipboard": empty, unavailable) gets no note.
  if (r !== undefined && r.error !== 'clipboard') $.ui.toast(PASTE_NOTE)
}

// Linux without DISPLAY or WAYLAND_DISPLAY in Claude Code's environment
// (gated's `platform`): Paste can't work there (review round 2).
async function displayless($: Engine, platform: string): Promise<boolean> {
  if (!platform.startsWith('linux')) return false
  const [x, w] = await Promise.all([
    $.env.get('DISPLAY').catch(() => undefined),
    $.env.get('WAYLAND_DISPLAY').catch(() => undefined),
  ])
  return noDisplayHere(platform, x, w)
}

// What gated said changed: the pane opens, redraws or closes; a dialog that
// ended gets a toast with its fixed result line.
async function apply($: Engine, next: NextView): Promise<void> {
  const before = S.view?.dialog ?? null
  S.view = next
  // the same dialog and attempt with a new key pair (gated restarted): a new
  // field (a new attempt has a new field anyway)
  if (before !== null && next.dialog !== null && before.id === next.dialog.id &&
      before.attempt === next.dialog.attempt && before.pub !== next.dialog.pub) S.epoch++
  for (const r of next.recent) {
    if (S.toasted.has(r.id)) continue
    S.toasted.add(r.id)
    const t = resultText(r)
    if (t !== undefined && before !== null) $.ui.toast(t)
  }
  const d = next.dialog
  if (!guardOn()) S.guardBox = undefined          // the guard is off: its next start reads the box anew
  if (d === null) {
    status($, 'dialog', undefined)
    if (S.opened !== '') {
      S.opened = ''
      S.placed = false
      await $.ui.close({ id: PANE }).catch(() => undefined)
    }
  } else if (S.opened !== d.id) {
    S.opened = d.id
    const r = await $.ui.open({ id: PANE, title: d.title || 'Gateway', focus: true, holdToasts: true, rows: rowsFor(d) }).catch(() => undefined)
    S.placed = r?.isPlaced === true
    status($, 'dialog', S.placed ? undefined : waitingLine(d))
  }
  $.ui.invalidate('ui.render')
}

// The dialog loop: a long poll at gated's /ui/dialog/next (one change at a
// time). When gated stops answering (killed, crashed), it is started again
// and this session registered again; the dialogs it kept come back.
async function dialogLoop($: Engine): Promise<void> {
  const gen = ++S.loop
  while (gen === S.loop) {
    let next: NextView | undefined
    let status403 = false
    try {
      const r = await $.http.fetch(`http://gated/ui/dialog/next?rev=${S.rev}&wait=${LONG_POLL_S}`, { socketPath: S.socket })
      next = r.ok ? parseNext(r.text) : undefined
      status403 = r.status === 403
    } catch {
      next = undefined
    }
    if (gen !== S.loop) return
    if (next === undefined) {
      S.failures++
      if ((status403 || S.failures >= 2) && S.located !== undefined) {
        await registerSession($, S.located, false)
        if (gen !== S.loop) return
      }
      await $.clock.sleep(Math.min(5000, 500 * S.failures))
      continue
    }
    S.failures = 0
    S.rev = next.rev
    await apply($, next)
  }
}

// `sh hooks/launch.sh gated status|start`: the daemon's /health as one JSON
// line (start also starts it when it isn't running).
async function daemonRun($: Engine, located: Located, sub: 'status' | 'start'): Promise<DaemonHealth | undefined> {
  try {
    const r = await $.process.run(['sh', `${$.plugin.root}/hooks/launch.sh`, 'gated', sub], {
      env: { CLAUDE_PLUGIN_DATA: located.data },
      timeoutMs: 15000,
    })
    return parseDaemon(r.stdout)
  } catch {
    return undefined
  }
}

// Registers this session on the daemon's UI plane, with every surface it
// draws on. The request goes from this process (the mod runs inside Claude
// Code), so the daemon sees the Claude Code pid from the kernel; claude_pid,
// when launch.sh's Python could name its parent as Claude Code, must match
// it. A daemon that refuses it because it is stopping (its idle exit began:
// lib.ts registerStopping) is replaced: `gated start` again (it waits for the
// old one to go and starts a new one), then the registration again, at most
// REGISTER_TRIES times. An interactive session then runs the dialog loop.
async function registerSession($: Engine, located: Located, first = true): Promise<void> {
  for (let tries = 0; tries < REGISTER_TRIES; tries++) {
    const d = await daemonRun($, located, 'start')
    if (d !== undefined) S.noDisplay = await displayless($, d.platform)
    if (d === undefined || !d.running || d.socket === '') return
    S.socket = d.socket
    if (first && d.skew !== '' && !S.skewShown) {
      // the version-skew notice of `gated start`, once per session
      S.skewShown = true
      status($, 'skew', `daemon: ${clean(d.skew)}`)
      $.clock.after(SKEW_SHOWN_MS, () => status($, 'skew', undefined))
    }
    let stopping = false
    try {
      const claude = await $.session.version().catch(() => undefined)
      const surfaces = await $.session.surfaces().catch(() => [] as readonly string[])
      const body: Record<string, unknown> = {
        session_id: await $.session.id().catch(() => ''),
        surface: S.surface ?? '',
        surfaces: [...surfaces],
        version: claude?.version ?? '',
      }
      if (d.parentPid > 0) body.claude_pid = d.parentPid
      const r = await $.http.fetch('http://gated/ui/register', {
        method: 'POST',
        socketPath: d.socket,
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      })
      stopping = registerStopping(r.status, r.text)
    } catch {
      // the classic hook-daemon hook registers the session too (without a UI)
    }
    if (!stopping) break
  }
  if (first && S.interactive) void dialogLoop($).catch(() => undefined)
}

// Managed execution (PLAN-v4 phase 4): the effective mode comes from the
// state.json the gateway's Python writes (a missing file counts as "on", the
// default). It sits in the data folder, which a command can rewrite, so the
// plan takes only the mode from it and the gate-sh copy's place (used only
// while that copy holds the plugin's gate-sh); the managed bash comes from
// launch.sh's status. A tampered state.json can thus only take the prefix
// away, and then Claude's commands run in the user's own shell, still judged
// by the classic Bash hook (lib.ts
// managedPlan). GW_MANAGED_DIR tells gate-sh where its settings are;
// CLAUDE_CODE_SHELL makes the managed bash, not the login shell, the shell
// Claude Code starts gate-sh from (once the env is built).
async function readManagedState($: Engine, data: string): Promise<ManagedState | undefined> {
  try {
    const t = await $.fs.read(`${data.replace(/\/+$/, '')}/managed/state.json`)
    return parseManagedState(typeof t === 'string' ? t : undefined)
  } catch {
    return undefined
  }
}

// Does the data folder's gate-sh copy hold the plugin's gate-sh (byte for byte)?
async function gateShCopyOk($: Engine, data: string, state: ManagedState | undefined): Promise<boolean> {
  const p = gateShPaths($.plugin.root, data)
  if (state?.gateSh !== p.copy) return false
  try {
    const [own, copy] = await Promise.all([$.fs.read(p.own), $.fs.read(p.copy)])
    return typeof own === 'string' && own !== '' && own === copy
  } catch {
    return false
  }
}

async function managedSetup($: Engine, located: Located, st: EnvStatus | undefined): Promise<void> {
  const data = st !== undefined && st.data !== '' ? st.data : located.data
  const state = await readManagedState($, data)
  const copyOk = await gateShCopyOk($, data, state)
  const plan = managedPlan({ root: $.plugin.root, data, state, envDir: st?.env ?? '', envReady: st?.state === 'ready', copyOk })
  const before = (await $.env.get('CLAUDE_CODE_SHELL_PREFIX').catch(() => undefined)) ?? ''
  if (S.managed === undefined && plan.prefix !== undefined && before !== '' && before !== plan.prefix) S.managedReplaced = before
  S.managed = plan
  await $.env.set('GW_MANAGED_DIR', plan.dir)
  if (plan.prefix !== undefined) {
    // bash run with -c, stdin a socket (as Claude Code starts the shell it
    // runs the prefix from) and SHLVL unset or 0 counts itself started by
    // sshd/rshd and sources ~/.bashrc before the command (upstream bash's
    // isnetconn check; Debian also checks SSH_CLIENT): the rc's variables
    // never reach a command (gate-sh removes them), but whatever its lines
    // do runs. A Claude Code started from a terminal has SHLVL >= 1 already;
    // one started without it (a launcher, a service, a harness) gets 1 here.
    const lv = (await $.env.get('SHLVL').catch(() => undefined)) ?? ''
    if (!shlvlOk(lv)) await $.env.set('SHLVL', '1')
    await $.env.set('CLAUDE_CODE_SHELL_PREFIX', plan.prefix)
  }
  if (plan.shell !== undefined) await $.env.set('CLAUDE_CODE_SHELL', plan.shell)
}

// For /gate-doctor: what is set now (after a /reload-plugins the module's
// memory is new, the process's environment isn't).
async function managedNow($: Engine, located: Located, st: EnvStatus | undefined): Promise<{ plan: ManagedPlan | undefined; state: ManagedState | undefined; replaced: string }> {
  const data = st !== undefined && st.data !== '' ? st.data : located.data
  const state = await readManagedState($, data)
  const copyOk = await gateShCopyOk($, data, state)
  const expected = managedPlan({ root: $.plugin.root, data, state, envDir: st?.env ?? '', envReady: st?.state === 'ready', copyOk })
  const prefix = (await $.env.get('CLAUDE_CODE_SHELL_PREFIX').catch(() => undefined)) ?? ''
  const shell = (await $.env.get('CLAUDE_CODE_SHELL').catch(() => undefined)) ?? ''
  const ours = expected.prefix !== undefined && prefix === expected.prefix
    || prefix === `${$.plugin.root.replace(/\/+$/, '')}/hooks/gate-sh` || prefix === `${expected.dir}/gate-sh`
  const plan: ManagedPlan = ours
    ? { ...expected, prefix, inactive: undefined, shell: shell !== '' ? shell : undefined }
    : {
        ...expected,
        prefix: undefined,
        shell: undefined,
        inactive: expected.inactive ?? (prefix !== '' ? `another CLAUDE_CODE_SHELL_PREFIX is set (${prefix}); Claude's commands run in your own shell (the classic Bash hook still judges them)` : 'no prefix was set in this session (it is set at session start; a new session sets it)'),
      }
  return { plan, state, replaced: S.managedReplaced }
}

async function where($: Engine): Promise<Located> {
  const cfg = await $.env.get('CLAUDE_CONFIG_DIR')
  const home = await $.env.get('HOME')
  return locate($.plugin.root, $.plugin.name, cfg ?? `${home ?? ''}/.claude`)
}

// `sh hooks/launch.sh status [pixi]` with the data folder the hooks get:
// launch.sh stays the one place that knows the env's path and its states.
async function envStatus($: Engine, located: Located, withPixi: boolean): Promise<EnvStatus | undefined> {
  try {
    const argv = ['sh', `${$.plugin.root}/hooks/launch.sh`, 'status', ...(withPixi ? ['pixi'] : [])]
    const r = await $.process.run(argv, { env: { CLAUDE_PLUGIN_DATA: located.data }, timeoutMs: 15000 })
    return parseStatus(r.stdout)
  } catch {
    return undefined
  }
}

// Provisioning through the OS's POSIX sh (macOS and Linux): an argv, no
// shell string. Output goes to the env's install.log, not here. The child
// lives as long as the loop; were the session to end first, the build lock
// shows a dead builder and the next start takes over (launch.sh).
function provision($: Engine, located: Located): void {
  void (async () => {
    try {
      const child = $.process.spawn({
        argv: ['sh', `${$.plugin.root}/hooks/launch.sh`, 'ensure-env'],
        env: { CLAUDE_PLUGIN_DATA: located.data },
      })
      for await (const _ of child) {
        // nothing: progress is in install.log; the status line polls
      }
    } catch {
      // the next poll shows the failure
    }
  })()
}

// The setup status line; true when the env is ready already (the caller
// registers with the daemon then; otherwise this does once it gets ready).
// "ready" waits for the managed shell's settings too (lib.ts setupReady):
// between the env's build and them, the line says "finishing setup".
async function watchSetup($: Engine, located: Located, first: EnvStatus | undefined): Promise<boolean> {
  if (first === undefined) return false
  const managed = (): boolean => S.managed?.prefix !== undefined
  const envReady = first.state === 'ready'
  if (setupReady(first, managed())) return true
  if (shouldProvision(first)) provision($, located)
  const t0 = await $.clock.now()
  let last: EnvStatus = first.state === 'failed' && shouldProvision(first) ? { ...first, state: 'building' } : first
  let busy = false
  let sincePoll = 0
  let envDone = envReady                // managedSetup ran with the built env; the caller registers
  status($, 'setup', statusLine(last, 0, managed()))
  const tick = $.clock.every(TICK_MS, () => {
    void (async () => {
      if (busy) return
      busy = true
      try {
        const now = await $.clock.now()
        sincePoll += TICK_MS
        if (sincePoll >= POLL_MS) {
          sincePoll = 0
          last = (await envStatus($, located, false)) ?? last
        }
        if (last.state === 'ready' && !envDone) {
          envDone = true
          // the managed bash exists now: name it (the prefix is set already)
          await managedSetup($, located, last).catch(() => undefined)
          await registerSession($, located)
        }
        if (setupReady(last, managed())) {
          tick.cancel()
          // "ready" is the normal state: Claude Code draws every status line
          // with its warning glyph (⚠; $.ui.status takes only the text, no
          // level), so the status line goes and "ready" is a toast, which it
          // draws without one. The warning stays for what is one: setting up
          // (commands wait), failures, a waiting dialog, a refusal.
          status($, 'setup', undefined)
          $.ui.toast(statusLine(last, now - t0, managed()) ?? 'ready', { timeoutMs: READY_SHOWN_MS })
          return
        }
        if (now - t0 > GIVE_UP_MS) {
          // stop polling; a build still going gets a hint, a failure keeps its line
          tick.cancel()
          if (last.state === 'building' || last.state === 'missing' || last.state === 'ready') {
            status($, 'setup', `setup is taking long; /${DOCTOR_COMMAND} says what is happening`)
          }
          return
        }
        status($, 'setup', statusLine(last, now - t0, managed()))
      } finally {
        busy = false
      }
    })()
  })
  return envReady
}
