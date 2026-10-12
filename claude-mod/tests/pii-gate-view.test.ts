import type { RenderElement } from 'claude-code'
import { expect, mock, test } from 'claude-code/testing'

const LOG = 'H:/home/.claude/logs/pii-gate-events.log'
const row = (o: object) => JSON.stringify(o) + '\n'

// 시작 전부터 있던 기록 — 이 세션(S1) 차단 1, 다른 세션(S2) 탐지 1
const OLD =
  row({ ts: '2026-10-12T01:00:00.000Z', sessionId: 'S1', tool: 'mcp__idea__execute_sql_query', decision: 'block', categories: {}, reason: 'widget-down' }) +
  row({ ts: '2026-10-12T01:00:05.000Z', sessionId: 'S2', tool: 'Bash', decision: 'detect', categories: { 이메일: 1 } })
// 시작 후 새로 생긴 기록 — 이 세션 탐지
const NEW = row({ ts: '2026-10-12T01:00:10.000Z', sessionId: 'S1', tool: 'Bash', decision: 'detect', categories: { 이메일: 1 } })

const BAND = {
  component: 'AbovePrompt',
  props: {
    hasSurvey: false, isWorking: false, maxRows: 10, bodyColumns: 120,
    scroll: { offset: 0, bodyRows: 10 }, view: {},
  },
} as const
const FOOTER = { component: 'SessionMode', props: { modes: [] } } as const
const PANE = {
  component: 'Pane',
  requestId: 'pii-events',
  props: {
    title: 'PII GATE // TELEMETRY', isFocused: false, bodyColumns: 100, placement: 'dock',
    scroll: { offset: 0, bodyRows: 30 }, view: {},
  },
} as const

test('HUD — 하단 칩 · 경보 카드 도착 연출 · 텔레메트리 패널', async ($, on) => {
  let text = OLD
  const statuses: (string | undefined)[] = []
  const toasts: string[] = []

  const clock = mock.clock(on, { now: Date.parse('2026-10-12T01:00:30.000Z') })
  mock.env(on, { USERPROFILE: 'H:/home' })
  on('session.id', () => ({ value: 'S1' }))
  on('fs.stat', ($, e) => {
    if (e.path.replaceAll('\\', '/') !== LOG) throw new Error(`unexpected path ${e.path}`)
    return { value: { kind: 'file' as const, size: text.length, mtimeMs: 0, isLink: false } }
  })
  on('fs.read', () => ({ value: text }))
  on('command.register', ($, e) => ({ value: { command: e.name } }))
  on('ui.status', ($, e) => { statuses.push(e.text); return { value: undefined } })
  on('ui.toast', ($, e) => { toasts.push(e.text); return { value: undefined } })
  // 엔진 기본 그림 대신 — 모드가 next(e) 로 넘기면 이 줄이 보인다
  on('ui.render', { component: 'AbovePrompt' }, ($, e) => {
    const { Text } = $.ui.resolve(e)
    return h(Text, {}, 'base') as RenderElement
  })
  on('session.start', ($, e) => ({ cwd: e.cwd }))

  await $.session.start({ cwd: 'H:/w', surface: 'terminal', isInteractive: true })
  expect(toasts).toEqual([]) // 시작 전 기록으로는 경보를 띄우지 않는다

  // 하단 칩: 이 세션 건수 차단 1 · 탐지 0 · 허용 0 — 두 화면 모두
  for (const surface of ['terminal', 'desktop'] as const) {
    const ui = await $.ui.mount({ plugin: 'pii-gate-view', surface, ...FOOTER })
    expect(await ui.find({ type: 'Text', text: /PII SHIELD.*1 · 0 · 0/ })).toBeDefined()
    await ui.unmount()
  }

  text += NEW
  await clock.advance(2000)
  expect(toasts).toEqual(['◈ PII DETECTED · Bash · 이메일×1']) // 다른 세션(S2) 것은 띄우지 않는다

  // 도착 직후엔 라벨이 해독 중이라 아직 온전한 글자가 아니다
  const arriving = await $.ui.mount({ plugin: 'pii-gate-view', surface: 'terminal', ...BAND })
  expect(await arriving.find({ type: 'Text', text: /PII \/\/ DETECTED/ })).toBeUndefined()
  await arriving.unmount()

  await clock.advance(1500) // 30프레임 × 40ms 를 넘긴다
  for (const surface of ['terminal', 'desktop'] as const) {
    const ui = await $.ui.mount({ plugin: 'pii-gate-view', surface, ...BAND })
    expect(await ui.find({ type: 'Text', text: /PII \/\/ DETECTED/ })).toBeDefined()
    expect(await ui.find({ type: 'Text', text: /기록됨/ })).toBeDefined()
    await ui.unmount()
  }

  const footer = await $.ui.mount({ plugin: 'pii-gate-view', surface: 'terminal', ...FOOTER })
  expect(await footer.find({ type: 'Text', text: /PII SHIELD.*1 · 1 · 0/ })).toBeDefined()
  await footer.unmount()
  expect(statuses).toEqual([]) // 하단 칩이 그려졌으니 노란 상태줄은 쓰지 않는다

  const pane = await $.ui.mount({ plugin: 'pii-gate-view', surface: 'terminal', ...PANE })
  expect(await pane.find({ type: 'Text', text: 'DETECT' })).toBeDefined()
  expect(await pane.find({ type: 'Text', text: /다른 세션/ })).toBeDefined()
  await pane.unmount()

  const band = await $.ui.mount({ plugin: 'pii-gate-view', surface: 'terminal', ...BAND })
  await band.press({ key: 'ack' })
  expect(await band.find({ type: 'Text', text: /PII \/\/ DETECTED/ })).toBeUndefined() // 「확인」으로 내려간다
  expect(await band.find({ type: 'Text', text: 'base' })).toBeDefined()
  await band.unmount()
})
