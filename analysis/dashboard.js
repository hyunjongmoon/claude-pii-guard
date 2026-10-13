#!/usr/bin/env node
'use strict';
/**
 * dashboard.js — PII 가드 현황을 HTML 한 장으로 만든다. 전산 담당·관리자에게 보여주는 용도.
 *
 *   node analysis/dashboard.js                        # ./pii-dashboard.html
 *   node analysis/dashboard.js --out 보고/현황.html
 *   node analysis/dashboard.js --with-source      # 내부 검토용 — 기록마다 출처(조회·명령·파일) 문구까지
 *
 * 읽는 것 (읽기 전용):
 *   ~/.claude/logs/pii-gate-events.log        (+ .exclude.jsonl)  게이트 판정 · 실행 후 탐지
 *   ~/.claude/logs/sensitive-prompt-scan.log  (+ .exclude.jsonl)  프롬프트 검사
 *   ~/.claude/settings.json   훅·플러그인 등록 여부만 본다 — 내용은 페이지에 싣지 않는다
 *   ~/.claude/hooks/          설치 여부 · 설치 시각
 *   ~/.claude/logs/pii-gate.json  확인창(위젯) 실행 여부
 * 싣지 않는 것: 개인정보 값(로그에 원래 없다), 세션 ID, 명령·SQL 원문(그런 로그는 읽지도 않는다).
 * 화면 틀은 같은 폴더의 dashboard-page.html — 이 스크립트는 데이터만 채워 넣는다.
 * 만든 페이지는 외부 파일·네트워크 없이 혼자 열린다 — 메일 첨부·USB 로 그대로 넘길 수 있다.
 */
const fs = require('fs');
const os = require('os');
const path = require('path');

const HOME = os.homedir();
const LOGS = path.join(HOME, '.claude', 'logs');
const HOOKS = path.join(HOME, '.claude', 'hooks');
const GATE_LOG = path.join(LOGS, 'pii-gate-events.log');
const PROMPT_LOG = path.join(LOGS, 'sensitive-prompt-scan.log');

const args = process.argv.slice(2);
const outFlag = args.indexOf('--out');
if (outFlag !== -1 && !args[outFlag + 1]) {
  console.error('--out 뒤에 만들 파일 경로를 주어야 합니다.');
  process.exit(1);
}
const OUT = path.resolve(outFlag !== -1 ? args[outFlag + 1] : 'pii-dashboard.html');
// 출처(조회·명령·파일) 문구까지 싣는다 — 리터럴은 훅이 이미 ? 로 바꿨지만 테이블·컬럼 이름이 드러나므로
// 기본은 판정(요청 여부)만 싣고, 내부 검토용일 때만 켠다.
const WITH_SOURCE = args.includes('--with-source');
const { classify } = require('./requested');

// ─── 읽기 ───────────────────────────────────────────────────────
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const readJsonl = (file) => {
  if (!fs.existsSync(file)) return [];
  const out = [];
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    if (!line.trim()) continue;
    try { out.push(JSON.parse(line)); } catch (_e) { /* 깨진 줄은 건너뛴다 */ }
  }
  return out;
};
const excludeKey = (e) => `${e.ts}|${e.sessionId}|${e.tool || ''}|${e.decision || ''}`;
const EXCLUDE_LABEL = { 'false-positive': '오탐', 'test-value': '테스트 값', 'masked-output': '가린 출력' };
const loadExcludes = (log) => {
  const m = new Map();
  for (const x of readJsonl(log.replace(/\.log$/, '') + '.exclude.jsonl')) {
    m.set(excludeKey(x), { label: EXCLUDE_LABEL[x.reason] || x.reason || '사유 없음', note: x.note || '' });
  }
  return m;
};

const CAT_KO = {
  RRN: '주민등록번호', PHONE: '휴대전화', EMAIL: '이메일', PERSON: '성명', STUDENT_NUM: '학번·사번',
  ACCOUNT: '계좌번호', CARD: '카드번호', ADDRESS: '주소', BIRTH: '생년월일',
};
const REASON_KO = {
  'widget-down': '확인창 꺼짐', 'no-response': '응답 없음', timeout: '응답 없음',
  'user-deny': '사용자가 차단', 'internal-error': '검사 오류',
};
function friendlyTool(t) {
  if (!t) return '-';
  if (t === 'Bash') return '명령 실행';
  if (t === 'Read') return '파일 읽기';
  if (t === 'Write' || t === 'Edit') return '파일 수정';
  if (/^mcp__(claude-in-chrome|Claude_Browser)__/.test(t)) return '브라우저 조작';
  if (/^mcp__.*__(execute_sql_query|exec_query_select|fetch_query_result|preview_table_data)$/.test(t)) return 'DB 조회';
  if (t.startsWith('mcp__')) return '외부 도구 · ' + t.split('__')[1];
  return t;
}
const mapCats = (c) => {
  const out = {};
  if (c && typeof c === 'object') {
    for (const [k, v] of Object.entries(c)) {
      const n = Number(v);
      if (Number.isFinite(n) && n > 0) out[CAT_KO[k] || k] = (out[CAT_KO[k] || k] || 0) + n;
    }
  }
  return out;
};

let testExcluded = 0;
let unknown = 0;
const events = [];
// 출처 기록 이전 기록의 사후 복원 출처 — 세션 기록에서 옮겨 둔 <로그>.backfill.jsonl
const loadBackfill = (log) => {
  const m = new Map();
  for (const x of readJsonl(log.replace(/\.log$/, '') + '.backfill.jsonl')) if (x.source) m.set(excludeKey(x), x.source);
  return m;
};

function take(file, kind) {
  const excludes = loadExcludes(file);
  const backfill = loadBackfill(file);
  for (const raw of readJsonl(file)) {
    const rebuilt = raw && !raw.source ? backfill.get(excludeKey(raw)) : undefined;
    const e = rebuilt ? { ...raw, source: rebuilt } : raw;
    const t = Date.parse(e && e.ts);
    if (!Number.isFinite(t)) continue;
    if (!(typeof e.sessionId === 'string' && UUID_RE.test(e.sessionId))) { testExcluded += 1; continue; }
    let row = null;
    if (kind === 'prompt') {
      if (e.bypassed) row = { stage: 'prompt', decision: 'bypass' };
      else if (e.error) row = { stage: 'prompt', decision: 'error' };
      else if (typeof e.replacements === 'number' && e.replacements > 0) row = { stage: 'prompt', decision: 'block' };
    } else if (e.decision === 'block') row = { stage: 'gate', decision: 'block', reason: REASON_KO[e.reason] || e.reason || null };
    else if (e.decision === 'pass') row = { stage: 'gate', decision: 'pass' };
    else if (e.decision === 'detect') row = { stage: 'detect', decision: 'detect' };
    if (!row) { unknown += 1; continue; }
    const judged = kind === 'gate' ? classify(e) : null;
    events.push({
      t,
      ...row,
      tool: kind === 'prompt' ? '프롬프트 입력' : friendlyTool(e.tool),
      cats: mapCats(e.categories),
      excluded: excludes.get(excludeKey(e)) || null,
      req: judged ? { verdict: judged.verdict, label: judged.label } : null,
      ...(rebuilt ? { rebuilt: true } : {}),
      ...(WITH_SOURCE && e.source ? { src: `[${e.source.kind}${rebuilt ? ' · 사후 복원' : ''}] ${e.source.text}` } : {}),
    });
  }
}
take(PROMPT_LOG, 'prompt');
take(GATE_LOG, 'gate');
events.sort((a, b) => a.t - b.t);

// ─── 설치·등록 상태 (settings.json 은 불리언만 뽑고 버린다) ─────────
let settings = {};
try { settings = JSON.parse(fs.readFileSync(path.join(HOME, '.claude', 'settings.json'), 'utf8')); } catch (_e) { /* 없음 */ }
const hookCommands = (event) => {
  const list = (settings.hooks && settings.hooks[event]) || [];
  return list.flatMap((g) => (g.hooks || []).map((h) => String(h.command || '')));
};
const registered = (event, name) => hookCommands(event).some((c) => c.includes(name));
const fileTime = (f) => { try { return fs.statSync(f).mtimeMs; } catch (_e) { return null; } };
const widgetUp = (() => {
  try {
    const j = JSON.parse(fs.readFileSync(path.join(LOGS, 'pii-gate.json'), 'utf8'));
    if (!j.port || !j.pid) return false;
    process.kill(j.pid, 0); // 살아 있는지만 본다
    return true;
  } catch (_e) { return false; }
})();
const promptHook = path.join(HOOKS, 'sensitive-prompt-scan.js');
const gateHook = path.join(HOOKS, 'pii-gate-hook.js');
const lastGate = readJsonl(GATE_LOG).map((e) => Date.parse(e.ts)).filter(Number.isFinite).sort((a, b) => b - a)[0] || null;
const plugins = settings.enabledPlugins || {};

const status = [
  {
    label: '프롬프트 검사',
    ok: registered('UserPromptSubmit', 'sensitive-prompt-scan') && fileTime(promptHook) !== null,
    on: '켜짐 — 질문에 개인정보가 섞이면 보내기 전에 막습니다',
    off: '꺼짐 — 질문에 섞인 개인정보를 막지 못합니다',
    installed: fileTime(promptHook),
  },
  {
    label: 'DB 조회 확인',
    ok: registered('PreToolUse', 'pii-gate-hook') && fileTime(gateHook) !== null,
    on: widgetUp
      ? '켜짐 · 확인창 실행 중 — DB 조회 전에 허용/차단을 묻습니다'
      : '켜짐 · 확인창 꺼짐 — DB 조회 도구는 자동으로 막힙니다(안전한 쪽)',
    off: '꺼짐 — DB 조회 결과가 확인 없이 넘어갈 수 있습니다',
    installed: fileTime(gateHook),
  },
  {
    label: '실행 후 탐지',
    ok: registered('PostToolUse', 'pii-gate-hook') && fileTime(gateHook) !== null,
    on: '켜짐 — 결과에 개인정보가 보이면 경보를 띄우고 기록합니다',
    off: '꺼짐 — 결과에 섞인 개인정보를 알아채지 못합니다',
    installed: fileTime(gateHook),
  },
  {
    label: '감사로그',
    ok: fs.existsSync(GATE_LOG),
    on: '기록 중 — 판정마다 한 줄씩 남깁니다(개인정보 값은 남기지 않음)',
    off: '아직 기록 파일이 없습니다',
    last: lastGate,
  },
  {
    label: '화면 표시',
    ok: Object.keys(plugins).some((k) => k.startsWith('pii-gate-view@') && plugins[k]),
    on: '켜짐 — Claude Code 화면 아래에 현황 칩이 보입니다',
    off: '꺼짐(선택 사항) — 현황 칩 없이도 보호는 그대로입니다',
    optional: true,
  },
];

const data = { generatedAt: Date.now(), status, events, testExcluded, unknown, withSource: WITH_SOURCE };
const json = JSON.stringify(data).replace(/</g, '\\u003c');

// 화면은 dashboard-page.html 한 파일 — 데이터 자리(__DATA__)만 채운다
const PAGE = fs.readFileSync(path.join(__dirname, 'dashboard-page.html'), 'utf8');
fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, PAGE.replace('__DATA__', () => json));
console.log(`만들었습니다: ${OUT}`);
console.log(`기록 ${events.length}건 (검토 제외 ${events.filter((e) => e.excluded).length} · 테스트 세션 제외 ${testExcluded}${unknown ? ` · 분류 불가 ${unknown}` : ''})`);
