#!/usr/bin/env node
/**
 * analyze_pii_log.js — PII 훅 로그 분석기 (UserPromptSubmit 훅 + pii-gate 훅)
 *
 * 사용법:
 *   node analyze_pii_log.js                # 전체 기간, text 출력
 *   node analyze_pii_log.js 30             # 최근 30일
 *   node analyze_pii_log.js 30 markdown    # 최근 30일, 마크다운 출력
 *   node analyze_pii_log.js all markdown   # 전체 기간 + 마크다운
 *   node analyze_pii_log.js 30 --log gate  # pii-gate 감사로그(~/.claude/logs/pii-gate-events.log)
 *   node analyze_pii_log.js --log <경로>    # 다른 로그 파일
 *
 * 입력: ~/.claude/logs/sensitive-prompt-scan.log (JSON Lines, --log 로 바꿀 수 있음)
 *
 * Entry 케이스 — 프롬프트 스캔 훅 3종:
 *   { ts, sessionId, originalLen, maskedLen, replacements, categories: {RRN:1, PHONE:2, ...} }  ← 차단
 *   { ts, sessionId, bypassed: true, via: 'env'|'token' }                                       ← 우회
 *   { ts, sessionId, error: 'mask-apply-failed', message }                                      ← 에러
 * pii-gate 훅 3종 (decision 키):
 *   { ts, sessionId, tool, decision: 'block', categories, reason }  ← 게이트 차단 (reason 별로 집계)
 *   { ts, sessionId, tool, decision: 'pass', categories }           ← 사용자 허용
 *   { ts, sessionId, tool, decision: 'detect', categories }         ← 실행 후 탐지
 * 어느 쪽에도 맞지 않는 줄은 버리지 않고 '분류 불가'로 센다 — 형식이 바뀌어 0건이
 * 정상처럼 보이는 일을 막기 위해서다.
 *
 * 보안 / 운영:
 *   - 파일 시스템: 로그 한 파일 읽기 전용 (기본 ~/.claude/logs/sensitive-prompt-scan.log)
 *   - 외부 호출: 없음 (child_process / http / net 미사용)
 *   - 외부 의존성: 없음 (순수 Node.js)
 *   - 깨진 JSON 라인은 silent skip + 카운트만
 *   - 시간 비교는 ISO 8601 → epoch ms (Number.isFinite 검사)
 *   - 로그 미존재 / 0건은 친절 메시지 + 적절한 exit code
 */

const fs = require('fs');
const os = require('os');
const path = require('path');

const LOG_DIR = path.join(os.homedir(), '.claude', 'logs');
const DAY_MS = 24 * 60 * 60 * 1000;

// ─── 인자 파싱 ─────────────────────────────────────────────────
// --log <경로|gate> 는 어디에 와도 되고, 나머지 위치 인자(기간·출력형식)는 그대로다.
const args = process.argv.slice(2);
let LOG_PATH = path.join(LOG_DIR, 'sensitive-prompt-scan.log');
const logFlag = args.indexOf('--log');
if (logFlag !== -1) {
  const target = args[logFlag + 1];
  if (!target) {
    console.error('--log 뒤에 로그 파일 경로(또는 gate)를 주어야 합니다.');
    process.exit(1);
  }
  LOG_PATH = target === 'gate' ? path.join(LOG_DIR, 'pii-gate-events.log') : path.resolve(target);
  args.splice(logFlag, 2);
}
const firstArg = args[0];

let days = null; // null = 전체 기간
if (firstArg && firstArg.toLowerCase() !== 'all') {
  const n = parseInt(firstArg, 10);
  if (Number.isInteger(n) && n > 0) {
    days = n;
  } else {
    console.error(`첫 번째 인자는 양의 정수(일 수) 또는 'all' 이어야 합니다: ${firstArg}`);
    process.exit(1);
  }
}

const mode = (args[1] || 'text').toLowerCase();
if (!['text', 'markdown'].includes(mode)) {
  console.error(`두 번째 인자는 'text' 또는 'markdown' 이어야 합니다: ${mode}`);
  process.exit(1);
}

// ─── 로그 파일 확인 ─────────────────────────────────────────────
if (!fs.existsSync(LOG_PATH)) {
  console.error(`로그 파일이 없습니다: ${LOG_PATH}`);
  console.error('훅이 한 번도 기록하지 않았거나, 훅이 다른 경로에 설치되어 있습니다.');
  process.exit(1);
}

// ─── 읽기 + 라인별 파싱 (깨진 라인 silent skip) ─────────────────
const raw = fs.readFileSync(LOG_PATH, 'utf8');
const lines = raw.split(/\r?\n/).filter(l => l.trim() !== '');

const allEntries = [];
let parseErrors = 0;
for (const line of lines) {
  try {
    allEntries.push(JSON.parse(line));
  } catch (_e) {
    parseErrors += 1;
  }
}

// ─── 기간 필터 ──────────────────────────────────────────────────
const now = Date.now();
const cutoff = days !== null ? now - (days * DAY_MS) : 0;
const periodEntries = allEntries.filter(e => {
  if (!e || !e.ts) return false;
  const t = new Date(e.ts).getTime();
  return Number.isFinite(t) && t >= cutoff;
});

// ─── 테스트 세션 제외 ───────────────────────────────────────────
// 실제 Claude Code 세션 ID 는 UUID. 비-UUID sessionId(수동 stdin 테스트 등)는
// 운영 통계를 오염시키므로 제외하고, 제외 건수만 별도로 보고한다.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isProdSession = id => typeof id === 'string' && UUID_RE.test(id);
const entries = periodEntries.filter(e => isProdSession(e.sessionId));
const testEntryCount = periodEntries.length - entries.length;

// ─── 빈 결과 처리 ───────────────────────────────────────────────
if (entries.length === 0) {
  const period = days !== null ? `최근 ${days}일` : '전체 기간';
  console.log(`(${period} 동안 운영 로그 entry 0건)`);
  if (testEntryCount > 0) console.log(`(테스트 세션 제외: ${testEntryCount}건)`);
  if (parseErrors > 0) console.log(`(파싱 실패 라인: ${parseErrors}건)`);
  process.exit(0);
}

// ─── 카테고리별 분류 ────────────────────────────────────────────
const blocks = [];
const bypasses = [];
const errorEntries = [];
const gateBlocks = [];
const gatePasses = [];
const detects = [];
const unknownEntries = [];
for (const e of entries) {
  if (e.bypassed) bypasses.push(e);
  else if (e.error) errorEntries.push(e);
  else if (typeof e.replacements === 'number' && e.replacements > 0) blocks.push(e);
  else if (e.decision === 'block') gateBlocks.push(e);
  else if (e.decision === 'pass') gatePasses.push(e);
  else if (e.decision === 'detect') detects.push(e);
  else unknownEntries.push(e);
}

// 프롬프트 스캔 쪽 절은 그 기록이 있거나, 게이트 기록도 없을 때 그린다 —
// 예전 로그의 출력이 한 글자도 바뀌지 않게.
const hasGate = gateBlocks.length + gatePasses.length + detects.length > 0;
const hasPrompt = blocks.length + bypasses.length + errorEntries.length > 0 || !hasGate;

const sessions = new Set(entries.map(e => e.sessionId).filter(Boolean));

const tsList = entries.map(e => new Date(e.ts).getTime()).filter(Number.isFinite).sort((a, b) => a - b);
const firstTs = tsList[0];
const lastTs = tsList[tsList.length - 1];
const spanDays = Math.max(1, Math.ceil((lastTs - firstTs) / DAY_MS) || 1);

function fmtDate(t) { return new Date(t).toISOString().slice(0, 10); }

// ─── 카테고리 누적 ──────────────────────────────────────────────
const catCounts = {};
for (const e of blocks) {
  if (!e.categories || typeof e.categories !== 'object') continue;
  for (const [k, v] of Object.entries(e.categories)) {
    const n = Number(v);
    if (Number.isFinite(n)) catCounts[k] = (catCounts[k] || 0) + n;
  }
}
const totalCat = Object.values(catCounts).reduce((a, b) => a + b, 0);
const catSorted = Object.entries(catCounts).sort((a, b) => b[1] - a[1]);

// ─── Bypass 분포 ────────────────────────────────────────────────
const bypassByVia = {};
for (const e of bypasses) {
  const via = e.via || 'unknown';
  bypassByVia[via] = (bypassByVia[via] || 0) + 1;
}

// ─── 게이트 차단 사유 · 탐지 카테고리 ───────────────────────────
// no-response(훅이 기다리다 끊음)와 timeout(위젯이 거절)은 원인이 거의 같아 합친다.
const REASON_LABEL = {
  'widget-down': '위젯 꺼짐',
  'no-response': '응답 없음',
  timeout: '응답 없음',
  'user-deny': '사용자 차단',
  'internal-error': '훅 오류',
};
const gateReasons = {};
for (const e of gateBlocks) {
  const label = REASON_LABEL[e.reason] || e.reason || '사유 없음';
  gateReasons[label] = (gateReasons[label] || 0) + 1;
}
const gateReasonSorted = Object.entries(gateReasons).sort((a, b) => b[1] - a[1]);

const detectCats = {};
for (const e of detects) {
  if (!e.categories || typeof e.categories !== 'object') continue;
  for (const [k, v] of Object.entries(e.categories)) {
    const n = Number(v);
    if (Number.isFinite(n)) detectCats[k] = (detectCats[k] || 0) + n;
  }
}
const detectCatSorted = Object.entries(detectCats).sort((a, b) => b[1] - a[1]);

// ─── 일별 추이 (최근 14일, 전체 기간 더 짧으면 그만큼) ──────────
const trendDays = Math.min(14, Math.max(spanDays, 1));
const trend = {};
for (let i = trendDays - 1; i >= 0; i -= 1) {
  const d = fmtDate(now - i * DAY_MS);
  trend[d] = { blocked: 0, bypassed: 0, gateBlock: 0, gatePass: 0, detect: 0 };
}
for (const e of entries) {
  const t = new Date(e.ts).getTime();
  if (!Number.isFinite(t)) continue;
  const d = fmtDate(t);
  if (!trend[d]) continue;
  if (e.bypassed) trend[d].bypassed += 1;
  else if (typeof e.replacements === 'number' && e.replacements > 0) trend[d].blocked += 1;
  else if (e.decision === 'block') trend[d].gateBlock += 1;
  else if (e.decision === 'pass') trend[d].gatePass += 1;
  else if (e.decision === 'detect') trend[d].detect += 1;
}

// 일별 추이 열 — [trend 키, text 머리, markdown 머리]. 있는 기록의 열만 보인다.
const trendCols = [
  ...(hasPrompt ? [['blocked', 'blocked', '차단'], ['bypassed', 'bypassed', '우회']] : []),
  ...(hasGate ? [['gateBlock', 'g.block', '게이트 차단'], ['gatePass', 'g.pass', '게이트 허용'], ['detect', 'detect', '탐지']] : []),
];

const sourceName = path.dirname(LOG_PATH) === LOG_DIR
  ? `~/.claude/logs/${path.basename(LOG_PATH)}`
  : path.basename(LOG_PATH);

const totalEvents = blocks.length + bypasses.length;
const bypassRatio = totalEvents > 0 ? (bypasses.length / totalEvents * 100) : 0;

// ─── 출력: text ─────────────────────────────────────────────────
function renderText() {
  const lines = [];
  lines.push('PII Hook 운영 통계');
  lines.push(`기간: ${fmtDate(firstTs)} ~ ${fmtDate(lastTs)} (${spanDays}일)`);
  lines.push(`고유 세션: ${sessions.size}`);
  lines.push('');
  lines.push('이벤트 요약:');
  if (hasPrompt) {
    lines.push(`  차단         ${String(blocks.length).padStart(3)}  (일평균 ${(blocks.length / spanDays).toFixed(1)})`);
    lines.push(`  우회         ${String(bypasses.length).padStart(3)}  (일평균 ${(bypasses.length / spanDays).toFixed(1)})`);
  }
  if (hasGate) {
    lines.push(`  게이트 차단  ${String(gateBlocks.length).padStart(3)}  (일평균 ${(gateBlocks.length / spanDays).toFixed(1)})`);
    lines.push(`  게이트 허용  ${String(gatePasses.length).padStart(3)}  (일평균 ${(gatePasses.length / spanDays).toFixed(1)})`);
    lines.push(`  실행 후 탐지 ${String(detects.length).padStart(3)}  (일평균 ${(detects.length / spanDays).toFixed(1)})`);
  }
  if (errorEntries.length > 0) lines.push(`  에러         ${String(errorEntries.length).padStart(3)}`);
  if (parseErrors > 0) lines.push(`  파싱 실패    ${String(parseErrors).padStart(3)}`);
  if (testEntryCount > 0) lines.push(`  테스트 제외   ${String(testEntryCount).padStart(3)}  (비-UUID 세션)`);
  if (unknownEntries.length > 0) lines.push(`  분류 불가    ${String(unknownEntries.length).padStart(3)}  (알 수 없는 형식 — 버리지 않고 셈)`);
  lines.push('');

  if (catSorted.length > 0) {
    lines.push('카테고리별 차단 빈도:');
    const maxLabel = Math.max(...catSorted.map(([k]) => k.length));
    const maxCount = catSorted[0][1];
    for (const [k, v] of catSorted) {
      const pct = (v / totalCat * 100).toFixed(1);
      const barLen = Math.max(1, Math.round((v / maxCount) * 24));
      const bar = '█'.repeat(barLen);
      lines.push(`  ${k.padEnd(maxLabel)}  ${String(v).padStart(3)}  ${pct.padStart(5)}%  ${bar}`);
    }
    lines.push('');
  } else if (blocks.length === 0 && hasPrompt) {
    lines.push('(차단 0건 — 카테고리 통계 없음)');
    lines.push('');
  }

  if (bypasses.length > 0) {
    lines.push('Bypass 분포:');
    for (const [via, count] of Object.entries(bypassByVia).sort((a, b) => b[1] - a[1])) {
      lines.push(`  ${via.padEnd(10)} ${count}`);
    }
    lines.push(`  → 전체 이벤트 대비 우회 비율: ${bypassRatio.toFixed(1)}%`);
    lines.push('');
  }

  if (gateReasonSorted.length > 0) {
    lines.push('게이트 차단 사유:');
    for (const [label, count] of gateReasonSorted) lines.push(`  ${label.padEnd(8)} ${count}`);
    lines.push('');
  }

  if (detectCatSorted.length > 0) {
    lines.push('실행 후 탐지 카테고리:');
    const maxLabel = Math.max(...detectCatSorted.map(([k]) => k.length));
    const maxCount = detectCatSorted[0][1];
    for (const [k, v] of detectCatSorted) {
      const bar = '█'.repeat(Math.max(1, Math.round((v / maxCount) * 24)));
      lines.push(`  ${k.padEnd(maxLabel)}  ${String(v).padStart(3)}  ${bar}`);
    }
    lines.push('');
  }

  lines.push(`일별 추이 (최근 ${trendDays}일):`);
  lines.push(`  ${'date'.padEnd(10)}  ${trendCols.map(([, h]) => h).join('  ')}`);
  for (const [d, v] of Object.entries(trend)) {
    lines.push(`  ${d}  ${trendCols.map(([k, h]) => String(v[k]).padStart(h.length)).join('  ')}`);
  }

  return lines.join('\n');
}

// ─── 출력: markdown (THREAT_MODEL 부록 B용) ─────────────────────
function renderMarkdown() {
  const lines = [];
  lines.push(`## 운영 실측 데이터 (${fmtDate(now)} 기준)`);
  lines.push('');
  lines.push(`- 측정 기간: \`${fmtDate(firstTs)}\` ~ \`${fmtDate(lastTs)}\` (${spanDays}일)`);
  lines.push(`- 고유 세션: **${sessions.size}**`);
  if (testEntryCount > 0) lines.push(`- 테스트 세션 제외: ${testEntryCount}건 (비-UUID sessionId)`);
  if (parseErrors > 0) lines.push(`- 파싱 실패 라인: ${parseErrors} (skip 처리)`);
  lines.push('');

  lines.push('### 이벤트 요약');
  lines.push('');
  lines.push('| 이벤트 | 건수 | 일평균 |');
  lines.push('|--------|------|--------|');
  if (hasPrompt) {
    lines.push(`| 차단 | ${blocks.length} | ${(blocks.length / spanDays).toFixed(1)} |`);
    lines.push(`| 우회 | ${bypasses.length} | ${(bypasses.length / spanDays).toFixed(1)} |`);
  }
  if (hasGate) {
    lines.push(`| 게이트 차단 | ${gateBlocks.length} | ${(gateBlocks.length / spanDays).toFixed(1)} |`);
    lines.push(`| 게이트 허용 | ${gatePasses.length} | ${(gatePasses.length / spanDays).toFixed(1)} |`);
    lines.push(`| 실행 후 탐지 | ${detects.length} | ${(detects.length / spanDays).toFixed(1)} |`);
  }
  if (errorEntries.length > 0) lines.push(`| 에러 | ${errorEntries.length} | - |`);
  if (unknownEntries.length > 0) lines.push(`| 분류 불가 | ${unknownEntries.length} | - |`);
  lines.push('');

  if (catSorted.length > 0) {
    lines.push('### 카테고리별 차단 빈도');
    lines.push('');
    lines.push('| 카테고리 | 건수 | 비율 |');
    lines.push('|---------|------|------|');
    for (const [k, v] of catSorted) {
      const pct = (v / totalCat * 100).toFixed(1);
      lines.push(`| ${k} | ${v} | ${pct}% |`);
    }
    lines.push('');
  }

  if (bypasses.length > 0) {
    lines.push('### Bypass 분포');
    lines.push('');
    lines.push('| 우회 경로 | 건수 |');
    lines.push('|----------|------|');
    for (const [via, count] of Object.entries(bypassByVia).sort((a, b) => b[1] - a[1])) {
      lines.push(`| ${via} | ${count} |`);
    }
    lines.push('');
    lines.push(`> 전체 이벤트 대비 우회 비율: **${bypassRatio.toFixed(1)}%**`);
    lines.push('');
  }

  if (gateReasonSorted.length > 0) {
    lines.push('### 게이트 차단 사유');
    lines.push('');
    lines.push('| 사유 | 건수 |');
    lines.push('|------|------|');
    for (const [label, count] of gateReasonSorted) lines.push(`| ${label} | ${count} |`);
    lines.push('');
  }

  if (detectCatSorted.length > 0) {
    lines.push('### 실행 후 탐지 카테고리');
    lines.push('');
    lines.push('| 카테고리 | 건수 |');
    lines.push('|---------|------|');
    for (const [k, v] of detectCatSorted) lines.push(`| ${k} | ${v} |`);
    lines.push('');
  }

  lines.push(`### 일별 추이 (최근 ${trendDays}일)`);
  lines.push('');
  lines.push(`| 날짜 | ${trendCols.map(([, , m]) => m).join(' | ')} |`);
  lines.push(`|------|${trendCols.map(() => '------').join('|')}|`);
  for (const [d, v] of Object.entries(trend)) {
    lines.push(`| ${d} | ${trendCols.map(([k]) => v[k]).join(' | ')} |`);
  }
  lines.push('');
  lines.push(`> 데이터 추출: \`analyze_pii_log.js\` / \`${sourceName}\` (${fmtDate(now)}).`);

  return lines.join('\n');
}

console.log(mode === 'markdown' ? renderMarkdown() : renderText());
