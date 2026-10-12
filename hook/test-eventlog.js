'use strict';
/**
 * 감사로그(pii-gate-events.log) 검증
 *   (a) 위젯이 꺼져 있어도 파일에 남는가
 *   (b) 경보 문구가 실제 기록 결과(성공/실패·위젯 표시 여부)대로 나가는가
 *   (c) 공백 구분·외국인등록번호를 잡는가
 *
 * 훅과 목 서버를 임시 홈(USERPROFILE/HOME)으로 돌려 실제 ~/.claude/logs 를 건드리지 않는다.
 * 여기 나오는 번호는 전부 가짜 값이다.
 */
const { execFileSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const HOOK = path.join(__dirname, 'pii-gate-hook.js');
const MOCK = path.join(__dirname, 'mock-server.js');
const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'eventlog-test-'));
const ENV = { ...process.env, USERPROFILE: HOME, HOME };
const LOGS = path.join(HOME, '.claude', 'logs');
const EVENT_LOG = path.join(LOGS, 'pii-gate-events.log');
const DIR = path.join(HOME, 'mock');
const TOKEN = 'test-token';
const SID = 'test-session';

let pass = 0, fail = 0;
function check(name, got, want) {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (기대=${want} 실제=${got})`}`);
}
function run(payload) {
  const out = execFileSync('node', [HOOK], {
    input: JSON.stringify({ session_id: SID, ...payload }),
    encoding: 'utf8', timeout: 20000, env: ENV,
  });
  return out.trim() ? JSON.parse(out) : {};
}
function lines() {
  try {
    return fs.readFileSync(EVENT_LOG, 'utf8').trim().split('\n').filter(Boolean)
      .map((l) => JSON.parse(l));
  } catch (_) { return []; }
}
function reset() { fs.rmSync(EVENT_LOG, { recursive: true, force: true }); }
const ctx = (r) => (r.hookSpecificOutput && r.hookSpecificOutput.additionalContext) || '';
const decisionOf = (r) => (r.hookSpecificOutput && r.hookSpecificOutput.permissionDecision) || '(none)';

const SQL_CALL = { tool_name: 'mcp__idea__execute_sql_query', tool_input: { query: 'SELECT 1 FROM DUAL' } };
const leakPost = (text) => ({
  tool_name: 'mcp__idea__execute_sql_query', tool_input: {}, tool_response: { rows: [{ V: text }] },
});

function startMock() {
  fs.mkdirSync(DIR, { recursive: true });
  return new Promise((resolve) => {
    const p = spawn('node', [MOCK, DIR, TOKEN], { stdio: ['ignore', 'pipe', 'inherit'], env: ENV });
    p.stdout.on('data', (d) => { if (String(d).startsWith('ready')) resolve(p); });
  });
}

(async () => {
  console.log('=== (a) 위젯 꺼짐 — 파일에는 남아야 함 ===');
  reset();
  check('게이트 대상 → 차단', decisionOf(run(SQL_CALL)), 'deny');
  let L = lines();
  check('차단이 기록됨', L.length === 1 && L[0].decision, 'block');
  check('차단 사유 = widget-down', L[0] && L[0].reason, 'widget-down');
  check('sessionId 기록', L[0] && L[0].sessionId, SID);
  check('tool 기록', L[0] && L[0].tool, SQL_CALL.tool_name);

  reset();
  run(leakPost('contact test.user@example.com'));
  L = lines();
  check('사후 탐지가 기록됨', L.length === 1 && L[0].decision, 'detect');
  check('categories 는 건수만', JSON.stringify(L[0] && L[0].categories), '{"이메일":1}');
  check('로그에 원문 없음', fs.readFileSync(EVENT_LOG, 'utf8').includes('example.com'), false);

  reset();
  run({ tool_name: 'Read', tool_input: { file_path: 'x' } });
  run({ tool_name: 'Bash', tool_input: { command: 'echo' }, tool_response: { stdout: 'ok' } });
  check('게이트 밖·PII 없음 → 기록 안 함', lines().length, 0);

  console.log('\n=== (b) 경보 문구 = 실제 결과 ===');
  reset();
  let c = ctx(run(leakPost('test.user@example.com')));
  check('위젯 꺼짐: 기록됨 + 위젯 미표시',
    c.includes('pii-gate-events.log 에 기록됨 (위젯 미표시)'), true);
  check('옛 문구("위젯에 기록되었습니다") 없음', c.includes('위젯에 기록되었습니다'), false);

  // 로그 자리에 디렉터리를 만들어 쓰기를 실패시킨다.
  reset();
  fs.mkdirSync(EVENT_LOG, { recursive: true });
  c = ctx(run(leakPost('test.user@example.com')));
  check('쓰기 실패: "기록 실패" 를 그대로 알림', c.includes('기록 실패: pii-gate-events.log 에 쓰지 못함'), true);
  check('쓰기 실패: "기록됨" 이라고 하지 않음', c.includes('에 기록됨'), false);
  reset();

  const mock = await startMock();
  c = ctx(run(leakPost('test.user@example.com')));
  check('위젯 켜짐: 기록됨 + 위젯 표시', c.includes('pii-gate-events.log 에 기록됨 + 위젯 표시'), true);

  reset();
  fs.writeFileSync(path.join(DIR, 'decision.txt'), 'allow');
  check('사용자 허용 → 통과', decisionOf(run(SQL_CALL)), 'allow');
  fs.writeFileSync(path.join(DIR, 'decision.txt'), 'deny');
  check('사용자 차단 → 차단', decisionOf(run(SQL_CALL)), 'deny');
  L = lines();
  check('허용·차단 순서대로 기록', L.map((l) => l.decision + (l.reason ? ':' + l.reason : '')).join(','),
    'pass,block:user-deny');
  mock.kill('SIGTERM');
  await new Promise((r) => setTimeout(r, 400));

  console.log('\n=== (c) 주민번호 — 공백 구분·외국인등록번호 ===');
  const rrn = (text) => {
    reset();
    run(leakPost(text));
    const l = lines()[0];
    return !!(l && l.categories && l.categories['주민등록번호']);
  };
  check('하이픈 내국인', rrn('900101-1234567'), true);
  check('공백 구분 내국인', rrn('900101 2234567'), true);
  check('외국인등록번호(5)', rrn('900101-5234567'), true);
  check('외국인등록번호(8)·공백', rrn('900101 8234567'), true);
  check('로그에 원문 없음', fs.readFileSync(EVENT_LOG, 'utf8').includes('8234567'), false);
  check('뒷자리 첫 숫자 9 → 아님', rrn('900101-9234567'), false);

  fs.rmSync(HOME, { recursive: true, force: true });
  console.log(`\n합계: ${pass} pass / ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
