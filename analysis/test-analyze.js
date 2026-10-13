'use strict';
/**
 * analyze_pii_log.js 검증 — 임시 폴더의 로그만 읽는다(실제 ~/.claude/logs 는 건드리지 않음).
 *   node analysis/test-analyze.js
 */
const { execFileSync, spawnSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const BIN = path.join(__dirname, 'analyze_pii_log.js');
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'analyze-test-'));
const LOGS = path.join(HOME, '.claude', 'logs');
fs.mkdirSync(LOGS, { recursive: true });

const S1 = '11111111-1111-4111-8111-111111111111';
const S2 = '22222222-2222-4222-8222-222222222222';
const ts = new Date(Date.now() - 3600 * 1000).toISOString(); // 한 시간 전 — 일별 추이 창 안
const jsonl = (rows) => rows.map((r) => JSON.stringify({ ts, ...r })).join('\n') + '\n';

const PROMPT = [
  { sessionId: S1, originalLen: 40, maskedLen: 30, replacements: 2, categories: { PHONE: 1, EMAIL: 1 } },
  { sessionId: S1, originalLen: 20, maskedLen: 15, replacements: 1, categories: { RRN: 1 } },
  { sessionId: S2, bypassed: true, via: 'token' },
];
const GATE = [
  { sessionId: S1, tool: 'mcp__idea__execute_sql_query', decision: 'block', categories: {}, reason: 'widget-down' },
  { sessionId: S1, tool: 'mcp__idea__execute_sql_query', decision: 'block', categories: {}, reason: 'no-response' },
  { sessionId: S2, tool: 'mcp__idea__execute_sql_query', decision: 'block', categories: {}, reason: 'timeout' },
  { sessionId: S1, tool: 'mcp__idea__execute_sql_query', decision: 'pass', categories: {} },
  { sessionId: S1, tool: 'Bash', decision: 'detect', categories: { 이메일: 2 } },
  { sessionId: S2, tool: 'Read', decision: 'detect', categories: { 이메일: 1, 주민등록번호: 1 } },
];
const ODD = [{ sessionId: S1, somethingElse: 1 }]; // 어느 형식에도 안 맞는 줄
const TEST_SESSION = [{ sessionId: 't', tool: 'Bash', decision: 'detect', categories: { 이메일: 9 } }];

const write = (name, rows) => {
  const p = path.join(HOME, name);
  fs.writeFileSync(p, jsonl(rows));
  return p;
};
const run = (args, env = {}) =>
  execFileSync('node', [BIN, ...args], { encoding: 'utf8', env: { ...process.env, ...env } });

let pass = 0;
let fail = 0;
function check(name, ok) {
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
}

console.log('=== 1. 프롬프트 스캔 로그 (기존 형식) ===');
let out = run(['all', '--log', write('prompt.log', PROMPT)]);
check('차단 2 · 우회 1', /차단\s+2\b/.test(out) && /우회\s+1\b/.test(out));
check('카테고리 집계', /PHONE\s+1/.test(out) && /RRN\s+1/.test(out));
check('게이트 절 없음', !out.includes('게이트'));
check('분류 불가 없음', !out.includes('분류 불가'));
check('일별 추이 머리 그대로', out.includes('date        blocked  bypassed'));

console.log('\n=== 2. pii-gate 로그 (decision) ===');
out = run(['all', '--log', write('gate.log', [...GATE, ...ODD, ...TEST_SESSION])]);
check('게이트 차단 3 · 허용 1 · 탐지 2', /게이트 차단\s+3\b/.test(out) && /게이트 허용\s+1\b/.test(out) && /실행 후 탐지\s+2\b/.test(out));
check('no-response 와 timeout 을 합쳐 응답 없음 2', /응답 없음\s+2/.test(out) && /위젯 꺼짐\s+1/.test(out));
check('탐지 카테고리 합산 (이메일 3)', /이메일\s+3/.test(out) && /주민등록번호\s+1/.test(out));
check('형식이 다른 줄은 분류 불가로 센다', /분류 불가\s+1\b/.test(out));
check('비-UUID 세션은 제외', /테스트 제외\s+1\b/.test(out) && !/이메일\s+12/.test(out));
check('프롬프트 스캔 절은 안 그림 (거짓 "차단 0건" 없음)', !out.includes('차단 0건') && !/^\s+차단\s+\d/m.test(out));
check('일별 추이는 게이트 열만', out.includes('date        g.block  g.pass  detect') && !out.includes('bypassed'));

console.log('\n=== 3. 두 형식이 섞인 로그 ===');
out = run(['all', '--log', write('mixed.log', [...PROMPT, ...GATE])]);
check('양쪽 요약이 다 나온다', /^\s+차단\s+2\b/m.test(out) && /게이트 차단\s+3\b/.test(out));
check('일별 추이 다섯 열', out.includes('date        blocked  bypassed  g.block  g.pass  detect'));

console.log('\n=== 4. markdown ===');
out = run(['all', 'markdown', '--log', path.join(HOME, 'gate.log')]);
check('요약 표에 게이트 줄', out.includes('| 게이트 차단 | 3 |') && out.includes('| 분류 불가 | 1 | - |'));
check('사유·카테고리 표', out.includes('### 게이트 차단 사유') && out.includes('| 응답 없음 | 2 |') && out.includes('### 실행 후 탐지 카테고리'));
check('일별 추이 머리', out.includes('| 날짜 | 게이트 차단 | 게이트 허용 | 탐지 |'));
check('출처는 파일 이름만 (로컬 경로 노출 없음)', out.includes('/ `gate.log` (') && !out.includes(HOME));

console.log('\n=== 5. --log gate · 기본 경로 ===');
fs.writeFileSync(path.join(LOGS, 'pii-gate-events.log'), jsonl(GATE));
fs.writeFileSync(path.join(LOGS, 'sensitive-prompt-scan.log'), jsonl(PROMPT));
const env = { USERPROFILE: HOME, HOME };
out = run(['all', '--log', 'gate'], env);
check('--log gate 는 ~/.claude/logs/pii-gate-events.log', /게이트 차단\s+3\b/.test(out));
out = run(['all', 'markdown', '--log', 'gate'], env);
check('출처 표기 ~/.claude/logs/pii-gate-events.log', out.includes('`~/.claude/logs/pii-gate-events.log`'));
out = run(['all'], env);
check('--log 없으면 예전처럼 프롬프트 스캔 로그', /^\s+차단\s+2\b/m.test(out) && !out.includes('게이트'));

console.log('\n=== 7. 검토 제외 목록 (<로그>.exclude.jsonl) ===');
// 시각이 다 다른 기록 — 제외 키는 ts·sessionId·tool·decision 이다
const at = (min) => new Date(Date.now() - min * 60e3).toISOString();
const REVIEW = [
  { ts: at(50), sessionId: S1, tool: 'Bash', decision: 'detect', categories: { 주민등록번호: 2 } }, // 오탐으로 판정
  { ts: at(40), sessionId: S1, tool: 'Read', decision: 'detect', categories: { 이메일: 1 } }, // 테스트 값으로 판정
  { ts: at(30), sessionId: S2, tool: 'Bash', decision: 'detect', categories: { 휴대전화: 1 } }, // 남는다
  { ts: at(20), sessionId: S1, tool: 'mcp__idea__execute_sql_query', decision: 'block', categories: {}, reason: 'widget-down' }, // 남는다
];
const reviewLog = path.join(HOME, 'review.log');
fs.writeFileSync(reviewLog, REVIEW.map((r) => JSON.stringify(r)).join('\n') + '\n');
const pick = (r, reason) => JSON.stringify({ ts: r.ts, sessionId: r.sessionId, tool: r.tool, decision: r.decision, reason });
fs.writeFileSync(path.join(HOME, 'review.exclude.jsonl'), [
  pick(REVIEW[0], 'false-positive'),
  pick(REVIEW[1], 'test-value'),
  JSON.stringify({ ts: at(999), sessionId: S1, tool: 'Bash', decision: 'detect', reason: 'test-value' }), // 로그에 없는 항목
].join('\n') + '\n');

out = run(['all', '--log', reviewLog]);
check('제외 후 탐지 1 · 차단 1', /실행 후 탐지\s+1\b/.test(out) && /게이트 차단\s+1\b/.test(out));
check('뺀 건수와 사유를 보인다', /검토 제외\s+2\s+\(오탐 1 · 테스트 값 1/.test(out));
check('제외 목록에만 있는 항목을 알린다', /제외 불일치\s+1\b/.test(out));
check('뺀 기록의 카테고리는 집계에서 빠진다', !/주민등록번호/.test(out.split('실행 후 탐지 카테고리:')[1] || '') && /휴대전화\s+1/.test(out));
out = run(['all', '--log', reviewLog, '--no-exclude']);
check('--no-exclude 면 원래 숫자', /실행 후 탐지\s+3\b/.test(out) && !/검토 제외\s+\d/.test(out) && out.includes('--no-exclude'));
out = run(['all', 'markdown', '--log', reviewLog]);
check('markdown 에도 검토 제외 표기', out.includes('- 검토 제외: 2건 (오탐 1 · 테스트 값 1)'));
check('원본 감사로그는 그대로', fs.readFileSync(reviewLog, 'utf8').split('\n').filter(Boolean).length === 4);

console.log('\n=== 8. --detail: 출처와 요청 여부 ===');
const SRC = [
  { ts: at(15), sessionId: S1, tool: 'mcp__idea__execute_sql_query', decision: 'detect', categories: { 주민등록번호: 1 },
    source: { kind: 'sql', text: 'SELECT EMP_NO, RRN FROM T WHERE NAME=?' } },
  { ts: at(10), sessionId: S1, tool: 'mcp__idea__execute_sql_query', decision: 'detect', categories: { 계좌번호: 1 },
    source: { kind: 'sql', text: 'SELECT ENTITY_ID, NAME FROM ERD' } },
  { ts: at(5), sessionId: S1, tool: 'Bash', decision: 'detect', categories: { 이메일: 1 } }, // 출처 기록 이전
];
const srcLog = path.join(HOME, 'src.log');
fs.writeFileSync(srcLog, SRC.map((r) => JSON.stringify(r)).join('\n') + '\n');
out = run(['all', '--log', srcLog, '--detail']);
check('판정 집계', /요청함 1/.test(out) && /요청 안 함 — 오탐 가능성 1/.test(out) && /근거 없음\(출처 기록 이전\) 1/.test(out));
check('종류별 지정 여부', /주민등록번호 지정함/.test(out) && /계좌번호 지정 안 함/.test(out));
check('출처를 그대로 보인다', out.includes('출처: [sql] SELECT EMP_NO, RRN FROM T WHERE NAME=?'));
check('--detail 없으면 기존 출력 그대로', !run(['all', '--log', srcLog]).includes('요청 여부'));
out = run(['all', 'markdown', '--log', srcLog, '--detail']);
check('markdown 표', out.includes('| 시각 | 판정 | 도구 | 걸린 종류 | 요청 여부 | 출처 |'));

console.log('\n=== 6. 인자 오류 ===');
const bad = spawnSync('node', [BIN, '--log'], { encoding: 'utf8' });
check('--log 뒤 경로 없음 → 종료코드 1', bad.status === 1 && bad.stderr.includes('--log'));

fs.rmSync(HOME, { recursive: true, force: true });
console.log(`\n합계: ${pass} pass / ${fail} fail`);
process.exit(fail ? 1 : 0);
