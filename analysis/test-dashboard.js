'use strict';
/**
 * dashboard.js 검증 — 임시 홈의 가짜 로그·설정으로만 돈다(실제 ~/.claude 는 건드리지 않음).
 *   node analysis/test-dashboard.js
 */
const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const BIN = path.join(__dirname, 'dashboard.js');
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'dash-test-'));
const C = path.join(HOME, '.claude');
fs.mkdirSync(path.join(C, 'logs'), { recursive: true });
fs.mkdirSync(path.join(C, 'hooks'), { recursive: true });
const env = { ...process.env, USERPROFILE: HOME, HOME };

const S1 = '11111111-1111-4111-8111-111111111111';
const SECRET = 'TOP-SECRET-SETTING-9f3a'; // 설정 파일에만 있는 문자열 — 페이지에 새면 안 된다
const at = (min) => new Date(Date.now() - min * 60e3).toISOString();
const jsonl = (rows) => rows.map((r) => JSON.stringify(r)).join('\n') + '\n';

fs.writeFileSync(path.join(C, 'settings.json'), JSON.stringify({
  hooks: {
    UserPromptSubmit: [{ hooks: [{ type: 'command', command: 'node "<HOME>/.claude/hooks/sensitive-prompt-scan.js"' }] }],
    PreToolUse: [{ matcher: 'mcp__.*', hooks: [{ type: 'command', command: 'node "<HOME>/.claude/hooks/pii-gate-hook.js"' }] }],
    PostToolUse: [{ matcher: 'Bash|Read|mcp__.*', hooks: [{ type: 'command', command: 'node "<HOME>/.claude/hooks/pii-gate-hook.js"' }] }],
  },
  enabledPlugins: {},
  autoMode: { environment: [SECRET] },
}));
fs.writeFileSync(path.join(C, 'hooks', 'sensitive-prompt-scan.js'), '// stub');
fs.writeFileSync(path.join(C, 'hooks', 'pii-gate-hook.js'), '// stub');

const gate = [
  { ts: at(90), sessionId: S1, tool: 'mcp__idea__execute_sql_query', decision: 'block', categories: {}, reason: 'widget-down' },
  { ts: at(80), sessionId: S1, tool: 'mcp__idea__execute_sql_query', decision: 'pass', categories: {} },
  { ts: at(70), sessionId: S1, tool: 'Bash', decision: 'detect', categories: { 주민등록번호: 1 } },
  { ts: at(60), sessionId: S1, tool: 'Read', decision: 'detect', categories: { 이메일: 2 } }, // 검토 제외로 판정
  { ts: at(50), sessionId: 'manual', tool: 'Bash', decision: 'detect', categories: { 이메일: 1 } }, // 비-UUID
];
fs.writeFileSync(path.join(C, 'logs', 'pii-gate-events.log'), jsonl(gate));
fs.writeFileSync(path.join(C, 'logs', 'pii-gate-events.exclude.jsonl'),
  jsonl([{ ts: gate[3].ts, sessionId: S1, tool: 'Read', decision: 'detect', reason: 'test-value', note: '테스트 파일' }]));
fs.writeFileSync(path.join(C, 'logs', 'sensitive-prompt-scan.log'), jsonl([
  { ts: at(40), sessionId: S1, originalLen: 30, maskedLen: 20, replacements: 2, categories: { RRN: 1, PHONE: 1 } },
  { ts: at(30), sessionId: S1, bypassed: true, via: 'token' },
]));

let pass = 0;
let fail = 0;
const check = (name, ok) => { ok ? pass++ : fail++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`); };

const out = path.join(HOME, 'out', 'dash.html');
execFileSync('node', [BIN, '--out', out], { env, encoding: 'utf8' });
const html = fs.readFileSync(out, 'utf8');
const data = JSON.parse(html.match(/<script type="application\/json" id="data">([\s\S]*?)<\/script>/)[1]);

console.log('=== 상태 ===');
const st = Object.fromEntries(data.status.map((s) => [s.label, s.ok]));
check('훅 세 개 등록 → 정상', st['프롬프트 검사'] && st['DB 조회 확인'] && st['실행 후 탐지']);
check('감사로그 있음 → 정상', st['감사로그'] === true);
check('플러그인 꺼짐 → 선택(꺼짐)', st['화면 표시'] === false && data.status.find((s) => s.label === '화면 표시').optional);
check('확인창 없으면 "자동으로 막힙니다" 안내', /자동으로 막힙니다/.test(data.status.find((s) => s.label === 'DB 조회 확인').on));

console.log('\n=== 기록 ===');
const by = (d) => data.events.filter((e) => e.decision === d).length;
check('게이트 차단 1 · 허용 1 · 탐지 2(제외 포함) · 프롬프트 차단 1 · 우회 1', by('pass') === 1 && by('detect') === 2 && by('block') === 2 && by('bypass') === 1);
check('검토 제외 표시는 그 한 건에만', data.events.filter((e) => e.excluded).length === 1 && data.events.find((e) => e.excluded).excluded.label === '테스트 값');
check('비-UUID 세션은 빼고 센다', data.testExcluded === 1);
check('도구 이름은 쉬운 말로', data.events.some((e) => e.tool === 'DB 조회') && data.events.some((e) => e.tool === '프롬프트 입력'));
check('프롬프트 검사 카테고리는 한글로', data.events.some((e) => e.cats['주민등록번호'] === 1 && e.cats['휴대전화'] === 1));
check('차단 사유는 쉬운 말로', data.events.some((e) => e.reason === '확인창 꺼짐'));

console.log('\n=== 싣지 않아야 하는 것 ===');
check('세션 ID 없음', !html.includes(S1) && !/sessionId/.test(JSON.stringify(data)));
check('설정 파일 내용 없음', !html.includes(SECRET) && !html.includes('autoMode'));
check('원래 도구 이름(mcp__…) 없음', !/mcp__/.test(JSON.stringify(data)));
check('홈 경로 없음', !html.includes(HOME));

console.log('\n=== 인자 오류 ===');
const bad = spawnSync('node', [BIN, '--out'], { env, encoding: 'utf8' });
check('--out 뒤 경로 없음 → 종료코드 1', bad.status === 1);

fs.rmSync(HOME, { recursive: true, force: true });
console.log(`\n합계: ${pass} pass / ${fail} fail`);
process.exit(fail ? 1 : 0);
