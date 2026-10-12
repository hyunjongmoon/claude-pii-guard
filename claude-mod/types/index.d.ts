export type PiiDecision = 'block' | 'pass' | 'detect'

/** pii-gate-events.log 한 줄 — pii-gate-hook.js 가 쓰는 형식 그대로 */
export type PiiEvent = {
  ts: string
  sessionId: string | null
  tool: string
  decision: PiiDecision
  categories: Record<string, number>
  reason?: string
}

export type PiiCounts = { block: number; detect: number; pass: number }

/** 도착 연출 — 새 경보마다 seq 가 오르고 frame 이 0 에서 끝 프레임까지 간다 */
export type PiiFx = { seq: number; frame: number }

declare module 'claude-code' {
  interface PluginState {
    'pii-gate-view': {
      /** 오늘(KST) 기록 전체, 모든 세션, 오래된 것이 앞 */
      today: PiiEvent[]
      /** 이 세션에서 아직 확인하지 않은 최근 차단·탐지 — 프롬프트 위 띠에 뜬다 */
      unseen: PiiEvent | null
      /** 이 세션 id — 패널에서 내 세션과 다른 세션을 가른다 */
      sid: string
      /** 이 세션의 판정별 건수 — 하단 칩 */
      counts: PiiCounts
      fx: PiiFx
    }
  }
}
