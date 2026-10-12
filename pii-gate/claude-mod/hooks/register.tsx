import { atom, read, update } from 'claude-code'
import type { Elements, EngineInterface, Register, Timer } from 'claude-code'

import type { PiiCounts, PiiDecision, PiiEvent } from '../types'

/**
 * PII 게이트 감사로그(~/.claude/logs/pii-gate-events.log)를 HUD 로 띄운다.
 * 기록은 pii-gate-hook.js 가 하고, 이 모드는 읽어서 보여주기만 한다.
 *
 *   하단 칩    프롬프트 아래 오른쪽 ◈ PII SHIELD │ 차단·탐지·허용
 *   경보 카드  이 세션에 새 차단·탐지가 오면 프롬프트 위에 — 라벨이 해독되듯 맞춰지고
 *             빛줄기가 한 번 훑고 지나간 뒤 멈춘다. 「확인」까지 남는다
 *   /pii      오늘의 텔레메트리 — 판정 타일, 시간대별 스파크라인, 타임라인
 *
 * 외부 라이브러리 없이 글자 단위 트루컬러로 그린다 — 터미널과 데스크톱이 같은 트리를 그린다.
 */
const PANE = 'pii-events'
const TITLE = 'PII GATE // TELEMETRY'
const POLL_MS = 2000
const FX_MS = 40 // 경보 카드는 터미널에서 초당 30회까지 — 25fps
const FX_FRAMES = 30 // 1.2초
const FOOTER_WAIT_MS = 5000 // 이 안에 하단 칩이 한 번도 안 그려지면 상태줄로 대신한다

const today = atom({ plugin: 'pii-gate-view', key: 'today' } as const, [])
const unseen = atom({ plugin: 'pii-gate-view', key: 'unseen' } as const, null)
const sidAtom = atom({ plugin: 'pii-gate-view', key: 'sid' } as const, '')
const counts = atom({ plugin: 'pii-gate-view', key: 'counts' } as const, { block: 0, detect: 0, pass: 0 })
const fx = atom({ plugin: 'pii-gate-view', key: 'fx' } as const, { seq: 0, frame: FX_FRAMES })

// 네온 팔레트 — 브랜드는 시안→바이올렛, 판정은 핑크·앰버·그린
const C = {
  cyan: '#00E5FF',
  violet: '#7C4DFF',
  pink: '#FF3D71',
  amber: '#FFB300',
  green: '#00E676',
  chrome: '#3A4150',
  dim: '#7A8396',
} as const

const LOOK = {
  block: { tag: 'BLOCKED', word: '차단', color: C.pink },
  pass: { tag: 'PASSED', word: '허용', color: C.green },
  detect: { tag: 'DETECTED', word: '탐지', color: C.amber },
} as const

const REASON: Record<string, string> = {
  'widget-down': '위젯 꺼짐',
  'no-response': '응답 없음',
  'user-deny': '사용자 차단',
  timeout: '시간 초과',
  'internal-error': '훅 오류',
}

type TextEl = Elements['terminal']['Text']
type BoxEl = Elements['terminal']['Box']

// ── 색 ──────────────────────────────────────────────────────────────
const rgb = (c: string): [number, number, number] => {
  const n = parseInt(c.slice(1), 16)
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
}

/** a→b 사이 t(0~1) 지점의 색 */
function mix(a: string, b: string, t: number) {
  const k = Math.max(0, Math.min(1, t))
  const [ar, ag, ab] = rgb(a)
  const [br, bg, bb] = rgb(b)
  const ch = (x: number, y: number) => Math.round(x + (y - x) * k).toString(16).padStart(2, '0')
  return `#${ch(ar, br)}${ch(ag, bg)}${ch(ab, bb)}`
}

/** 글자마다 색을 옮겨 칠한 그라데이션 */
function gradient(Text: TextEl, s: string, from: string, to: string) {
  const chars = [...s]
  const last = Math.max(1, chars.length - 1)
  return chars.map((ch, i) => (
    <Text color={mix(from, to, i / last)} bold>
      {ch}
    </Text>
  ))
}

// ── 연출 ────────────────────────────────────────────────────────────
const GLYPHS = '▓▒░<>/\\|#*+=-_:'

/** 해독 효과 — i 번째 글자는 i*1.6+3 프레임째에 제자리를 찾고, 그 전엔 기호가 돈다 */
function scramble(s: string, frame: number) {
  return [...s]
    .map((ch, i) => (ch === ' ' || frame >= i * 1.6 + 3 ? ch : (GLYPHS[(i * 7 + frame * 13) % GLYPHS.length] ?? ch)))
    .join('')
}

/** 빛줄기 — 꼬리 8칸짜리 혜성이 왼쪽에서 오른쪽으로 한 번 지나간다 */
function sweep(Text: TextEl, width: number, frame: number, color: string) {
  const head = Math.round((frame / FX_FRAMES) * (width + 8)) - 1
  return Array.from({ length: width }, (_, i) => {
    const d = head - i
    const t = d >= 0 && d < 8 ? 1 - d / 8 : 0
    return <Text color={t > 0 ? mix(C.chrome, color, t) : C.chrome}>{t > 0 ? '━' : '─'}</Text>
  })
}

// ── 데이터 ──────────────────────────────────────────────────────────
// 로그의 ts 는 UTC. 사용자가 한국에 있으므로 KST 로 고정해 보여준다
// (모드 실행 환경의 시간대에 기대지 않는다).
const KST_MS = 9 * 3600 * 1000
const kst = (ms: number) => new Date(ms + KST_MS).toISOString()
const dayOf = (ts: string) => kst(Date.parse(ts)).slice(0, 10)
const timeOf = (ts: string) => kst(Date.parse(ts)).slice(11, 19)
const hourOf = (ts: string) => Number(kst(Date.parse(ts)).slice(11, 13))

/** mcp__idea__execute_sql_query → idea · execute_sql_query */
const toolName = (tool: string) =>
  tool.startsWith('mcp__') ? tool.slice(5).replace('__', ' · ') : tool

/** 이메일×1 · 위젯 꺼짐 — 로그에 값은 없고 종류·건수·사유뿐이다 */
const detail = (ev: PiiEvent) => {
  const cats = Object.entries(ev.categories ?? {}).map(([k, n]) => `${k}×${n}`).join(', ')
  const why = ev.reason ? (REASON[ev.reason] ?? ev.reason) : ''
  return [cats, why].filter(Boolean).join(' · ')
}

const tally = (list: PiiEvent[]): PiiCounts => {
  const n = (d: PiiDecision) => list.filter((e) => e.decision === d).length
  return { block: n('block'), detect: n('detect'), pass: n('pass') }
}

const toastLine = (ev: PiiEvent) => {
  const more = detail(ev)
  return `◈ PII ${LOOK[ev.decision].tag} · ${toolName(ev.tool)}${more ? ` · ${more}` : ''}`
}

const statusLine = (n: PiiCounts) => `◈ PII SHIELD │ 차단 ${n.block} · 탐지 ${n.detect} · 허용 ${n.pass} · /pii`

function parse(text: string): PiiEvent[] {
  const out: PiiEvent[] = []
  for (const raw of text.split('\n')) {
    if (!raw.trim()) continue
    try {
      const j = JSON.parse(raw)
      if (j && typeof j.ts === 'string' && Object.hasOwn(LOOK, j.decision)) out.push(j)
    } catch {
      // 깨진 줄(쓰는 도중 읽힌 줄 등)은 건너뛴다 — 다음 폴링 때 온전한 줄로 다시 읽힌다
    }
  }
  return out
}

// ── 패널 조각 ───────────────────────────────────────────────────────
const BARS = '▁▂▃▄▅▆▇█'
// 한 시간 = 2칸, 24시간 = 48칸
const AXIS = '00          06          12          18        24'

function spark(Text: TextEl, list: PiiEvent[]) {
  const hours = Array.from({ length: 24 }, () => 0)
  for (const ev of list) hours[hourOf(ev.ts)] = (hours[hourOf(ev.ts)] ?? 0) + 1
  const max = Math.max(1, ...hours)
  return hours.map((v) => {
    const bar = v === 0 ? '·' : (BARS[Math.min(7, Math.ceil((v / max) * 8) - 1)] ?? '█')
    return <Text color={v === 0 ? C.chrome : mix(C.cyan, C.pink, v / max)}>{bar + bar}</Text>
  })
}

function tile(Box: BoxEl, Text: TextEl, label: string, value: number, color: string) {
  const on = value > 0
  return (
    <Box borderStyle="round" borderColor={on ? color : C.chrome} paddingX={2} flexDirection="column">
      <Text color={C.dim}>{label}</Text>
      <Text color={on ? color : C.dim} bold>
        {String(value).padStart(4, ' ')}
      </Text>
    </Box>
  )
}

// ── 상태 ────────────────────────────────────────────────────────────
// 모듈 변수 — 리로드 때마다 처음부터. 시작 시점의 줄 수를 기준으로 잡아
// 이미 있던 기록으로 경보가 쏟아지지 않게 한다.
let logPath = ''
let seen = 0
let lastSize = -1
let footerSeen = false
let useStatus = false
let fxTimer: Timer | undefined

async function sync($: EngineInterface, isFirst: boolean) {
  const stat = await $.fs.stat(logPath).catch(() => undefined)
  const size = stat?.size ?? 0
  if (!isFirst && size === lastSize) return
  lastSize = size

  let all: PiiEvent[] = []
  if (stat) {
    try {
      all = parse(String(await $.fs.read(logPath)))
    } catch {
      $.ui.status('◈ PII SHIELD │ 로그를 읽지 못함')
      return
    }
  }
  if (all.length < seen) seen = 0 // 잘리거나 교체됨
  const fresh = isFirst ? [] : all.slice(seen)
  seen = all.length

  const sid = await read($, sidAtom)
  const now = dayOf(new Date(await $.clock.now()).toISOString())
  const n = tally(all.filter((e) => e.sessionId === sid))
  await update($, today, () => all.filter((e) => dayOf(e.ts) === now).slice(-500))
  await update($, counts, () => n)
  if (useStatus) $.ui.status(statusLine(n))

  const mine = fresh.filter((e) => e.sessionId === sid)
  for (const ev of mine) $.ui.toast(toastLine(ev), { timeoutMs: 6000 })
  const alert = [...mine].reverse().find((e) => e.decision !== 'pass')
  if (alert) {
    await update($, unseen, () => alert)
    await startFx($)
  }
}

async function startFx($: EngineInterface) {
  fxTimer?.cancel()
  await update($, fx, (f) => ({ seq: f.seq + 1, frame: 0 }))
  fxTimer = $.clock.every(FX_MS, () => void stepFx($))
}

async function stepFx($: EngineInterface) {
  const f = await read($, fx)
  if (f.frame >= FX_FRAMES) {
    fxTimer?.cancel()
    fxTimer = undefined
    return
  }
  await update($, fx, (v) => ({ ...v, frame: v.frame + 1 }))
}

async function fallbackToStatus($: EngineInterface) {
  if (footerSeen) return
  useStatus = true
  $.ui.status(statusLine(await read($, counts)))
}

export const register: Register = (on) => {
  on('session.start', async ($, e, next) => {
    const home = (await $.env.get('USERPROFILE')) ?? (await $.env.get('HOME')) ?? ''
    logPath = `${home}/.claude/logs/pii-gate-events.log`
    const sid = await $.session.id()
    await update($, sidAtom, () => sid)
    await $.command.register({ name: 'pii', description: 'PII 게이트 텔레메트리(오늘)를 패널로 연다' })
    await sync($, true)
    $.clock.every(POLL_MS, () => void sync($, false))
    $.clock.after(FOOTER_WAIT_MS, () => void fallbackToStatus($))

    return next(e)
  })

  on('command.run', { command: 'pii' }, async ($) => {
    const opened = await $.ui.open({ id: PANE, title: TITLE })

    return { text: opened.isPlaced ? 'PII 게이트 텔레메트리를 열었습니다.' : 'PII 게이트 패널을 이 화면에 놓지 못했습니다.' }
  })

  // 하단 칩 — 프롬프트 아래 오른쪽. 엔진의 모드 라벨은 그대로 앞에 둔다.
  on('ui.render', { component: 'SessionMode' }, async ($, e) => {
    footerSeen = true
    const { Text } = $.ui.resolve(e)
    const n = await read($, counts)
    const modes = e.props.modes.join(' & ')
    const num = (v: number, color: string) => (
      <Text color={v > 0 ? color : C.dim} bold={v > 0}>
        {String(v)}
      </Text>
    )

    return (
      <Text>
        {modes !== '' && <Text dimColor>{modes}  </Text>}
        <Text color={C.cyan} bold>
          ◈{' '}
        </Text>
        {gradient(Text, 'PII SHIELD', C.cyan, C.violet)}
        <Text color={C.chrome}> │ </Text>
        {num(n.block, C.pink)}
        <Text color={C.chrome}> · </Text>
        {num(n.detect, C.amber)}
        <Text color={C.chrome}> · </Text>
        {num(n.pass, C.green)}
      </Text>
    )
  })

  // 경보 카드 — 이 세션의 최근 차단·탐지 하나. 「확인」으로 내린다.
  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    const ev = await read($, unseen)
    if (e.props.hasSurvey || ev === null) return next(e)

    const { Box, Button, Text } = $.ui.resolve(e)
    const look = LOOK[ev.decision]
    const { frame } = await read($, fx)
    const isArriving = frame < FX_FRAMES
    const label = `PII // ${look.tag}`
    const more = detail(ev)
    const border = isArriving && frame % 6 >= 3 ? mix(look.color, C.chrome, 0.55) : look.color

    return (
      <Box borderStyle="round" borderColor={border} paddingX={1} flexDirection="column">
        <Box gap={2}>
          <Text color={look.color} bold>
            ◈ {isArriving ? scramble(label, frame) : label}
          </Text>
          <Text bold>{toolName(ev.tool)}</Text>
          {more !== '' && <Text color={C.dim}>{more}</Text>}
          <Text color={C.dim}>{timeOf(ev.ts)} KST</Text>
        </Box>
        <Box gap={2}>
          {isArriving ? (
            <Text>{sweep(Text, 34, frame, look.color)}</Text>
          ) : (
            <Text color={C.dim}>▸ pii-gate-events.log 에 기록됨</Text>
          )}
          <Button key="ack" label="확인" onPress={() => update($, unseen, () => null)} />
          <Button key="list" label="텔레메트리" onPress={() => $.ui.open({ id: PANE, title: TITLE })} />
        </Box>
      </Box>
    )
  })

  // /pii 패널 — 판정 타일, 시간대별 스파크라인, 타임라인(최신이 위, 다른 세션은 흐리게)
  on('ui.render', { component: 'Pane', requestId: PANE }, async ($, e) => {
    const { Box, Text } = $.ui.resolve(e)
    const list = await read($, today)
    const sid = await read($, sidAtom)
    const n = tally(list)
    const room = Math.max(1, (e.viewport?.rows ?? 32) - 14)
    const rows = [...list].reverse().slice(0, room)

    return (
      <Box flexDirection="column" gap={1}>
        <Box gap={2}>
          <Text>{gradient(Text, TITLE, C.cyan, C.violet)}</Text>
          <Text color={C.dim}>오늘 · 모든 세션 · KST</Text>
        </Box>
        <Box gap={1}>
          {tile(Box, Text, 'BLOCK', n.block, C.pink)}
          {tile(Box, Text, 'DETECT', n.detect, C.amber)}
          {tile(Box, Text, 'PASS', n.pass, C.green)}
        </Box>
        <Box flexDirection="column">
          <Text color={C.dim}>ACTIVITY / HOUR</Text>
          <Text>{spark(Text, list)}</Text>
          <Text color={C.chrome}>{AXIS}</Text>
        </Box>
        <Box flexDirection="column">
          {rows.length === 0 && <Text color={C.dim}>오늘 기록이 없습니다.</Text>}
          {rows.map((ev) => {
            const look = LOOK[ev.decision]
            const isMine = ev.sessionId === sid
            const more = detail(ev)
            return (
              <Box gap={1}>
                <Text color={isMine ? look.color : C.chrome}>●</Text>
                <Text color={C.dim}>{timeOf(ev.ts)}</Text>
                <Text color={look.color} bold>
                  {look.tag.padEnd(8, ' ')}
                </Text>
                <Text dimColor={!isMine}>{toolName(ev.tool)}</Text>
                <Text color={C.dim}>
                  {more}
                  {isMine ? '' : `${more ? ' · ' : ''}다른 세션`}
                </Text>
              </Box>
            )
          })}
        </Box>
      </Box>
    )
  })
}
