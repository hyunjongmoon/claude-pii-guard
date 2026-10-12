'use strict';
/**
 * 게이트 훅 검증 — 목 서버(별도 프로세스)를 위젯 대신 세워 판정만 확인한다.
 * 실제 DB 접속은 일어나지 않는다.
 */
const { execFileSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// 훅이 감사로그(pii-gate-events.log)를 남기므로 임시 홈에서 돈다 — 실제 로그에 테스트가 섞이지 않게.
// 자식 프로세스(훅·목 서버)도 이 환경을 물려받는다.
process.env.USERPROFILE = process.env.HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-home-'));

const HOOK = path.join(__dirname, 'pii-gate-hook.js');
const MOCK = path.join(__dirname, 'mock-server.js');
const GATE_INFO = path.join(os.homedir(), '.claude', 'logs', 'pii-gate.json');
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'gate-test-'));
const DECISION = path.join(DIR, 'decision.txt');
const CAPTURE = path.join(DIR, 'capture.jsonl');
const TOKEN = 'test-token';

const SQL_CALL = {
  tool_name: 'mcp__idea__execute_sql_query',
  tool_input: { query: 'SELECT EMP_NO, ACCOUNT_NO, HOLDER_NAME FROM USER_ACCOUNT' },
};

let pass = 0, fail = 0;
function check(name, got, want) {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (기대=${want} 실제=${got})`}`);
}
function setDecision(d) { fs.writeFileSync(DECISION, d); }
function captured() {
  try {
    return fs.readFileSync(CAPTURE, 'utf8').trim().split('\n')
      .filter(Boolean).map((l) => JSON.parse(l));
  } catch (_) { return []; }
}
function run(payload) {
  try {
    const out = execFileSync('node', [HOOK], {
      input: JSON.stringify(payload), encoding: 'utf8', timeout: 20000,
    });
    return out.trim() ? JSON.parse(out) : {};
  } catch (e) { return { _error: String(e.message).slice(0, 100) }; }
}
function decisionOf(r) {
  if (r._error) return 'ERROR:' + r._error;
  return (r.hookSpecificOutput && r.hookSpecificOutput.permissionDecision) || '(none)';
}

function startMock() {
  return new Promise((resolve) => {
    const p = spawn('node', [MOCK, DIR, TOKEN], { stdio: ['ignore', 'pipe', 'inherit'] });
    p.stdout.on('data', (d) => { if (String(d).startsWith('ready')) resolve(p); });
  });
}

(async () => {
  // 파일을 그냥 지우면, 살아있는 위젯이 자가복구로 3초 안에 되찾아간다. 그러면 이후
  // 훅 호출이 목이 아니라 실제 위젯으로 가서 사용자에게 엉뚱한 확인창이 뜬다.
  // 그래서 "게이트 정보 없음"은 지우는 대신, port·token 이 빠진 파일을 우리 pid 로
  // 붙잡아 재현한다 — gateInfo() 는 어느 쪽이든 null 을 돌려주므로 같은 분기를 탄다.
  fs.mkdirSync(path.dirname(GATE_INFO), { recursive: true });
  fs.writeFileSync(GATE_INFO, JSON.stringify({ pid: process.pid }));

  console.log('=== 1. 게이트 정보 없음 — fail-closed 여야 함 ===');
  check('SQL 조회 도구 → 차단', decisionOf(run(SQL_CALL)), 'deny');
  check('일반 도구(Read) → 통과',
    decisionOf(run({ tool_name: 'Read', tool_input: { file_path: 'x' } })), 'allow');

  const mock = await startMock();

  console.log('\n=== 2. 위젯 실행 + 사용자가 "차단" ===');
  setDecision('deny');
  check('SQL 조회 도구 → 차단', decisionOf(run(SQL_CALL)), 'deny');

  console.log('\n=== 3. 위젯 실행 + 사용자가 "허용" ===');
  setDecision('allow');
  check('SQL 조회 도구 → 통과', decisionOf(run(SQL_CALL)), 'allow');
  check('테이블 미리보기 → 통과', decisionOf(run({
    tool_name: 'mcp__idea__preview_table_data', tool_input: { table: 'USER_ACCOUNT' } })), 'allow');
  check('스키마 조회는 게이트 대상 아님', decisionOf(run({
    tool_name: 'mcp__idea__introspect_schema', tool_input: {} })), 'allow');
  check('마스킹 보장 경로(masked-db) → 확인 없이 통과', decisionOf(run({
    tool_name: 'mcp__masked-db__exec_query_select', tool_input: {} })), 'allow');

  console.log('\n=== 4. 위젯으로 보내는 페이로드에 PII 값이 실리는가 ===');
  fs.writeFileSync(CAPTURE, '');
  run({ tool_name: 'mcp__idea__execute_sql_query',
    tool_input: { query: "SELECT * FROM T WHERE RRN='900101-1234567'" } });
  const gateBodies = captured().filter((c) => c.url === '/gate');
  const leaked = JSON.stringify(gateBodies).includes('900101-1234567');
  check('주민번호가 페이로드에 없음', leaked ? 'leaked' : 'redacted', 'redacted');
  check('대신 종류·건수 요약이 있음',
    JSON.stringify(gateBodies).includes('주민등록번호') ? 'summary' : 'missing', 'summary');

  console.log('\n=== 5. 사후 탐지 (PostToolUse) — 막지는 못하고 알린다 ===');
  fs.writeFileSync(CAPTURE, '');
  const postRes = run({
    tool_name: 'mcp__idea__execute_sql_query',
    tool_input: {},
    tool_response: { rows: [{ ACCOUNT_NO: '1002-345-678901', RRN: '900101-1234567' }] },
  });
  const events = captured().filter((c) => c.url === '/event');
  check('경보 이벤트 발생', events.length && events[0].body.kind === 'leak' ? 'leak' : 'none', 'leak');
  check('경보에 값이 아닌 요약만',
    JSON.stringify(events).includes('900101-1234567') ? 'has-value' : 'summary-only', 'summary-only');
  const ctx = postRes.hookSpecificOutput && postRes.hookSpecificOutput.additionalContext;
  check('모델에게도 경보 전달', ctx && ctx.includes('PII 경보') ? 'yes' : 'no', 'yes');

  mock.kill('SIGTERM');
  await new Promise((r) => setTimeout(r, 400));
  try { fs.unlinkSync(GATE_INFO); } catch (_) {}
  fs.rmSync(DIR, { recursive: true, force: true });

  console.log(`\n합계: ${pass} pass / ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
