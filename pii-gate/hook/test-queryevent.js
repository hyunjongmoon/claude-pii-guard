'use strict';
/**
 * DB 조회 이벤트 검증 — PII 가 없는 조회도 위젯에 남는지 확인한다.
 * 목 서버를 별도 프로세스로 띄워 훅이 보내는 페이로드를 잡는다.
 */
const { execFileSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { describeQuery } = require('../renderer/format.js');

// 훅이 감사로그(pii-gate-events.log)를 남기므로 임시 홈에서 돈다 — 실제 로그에 테스트가 섞이지 않게.
// 자식 프로세스(훅·목 서버)도 이 환경을 물려받는다.
process.env.USERPROFILE = process.env.HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'qev-home-'));

const HOOK = path.join(__dirname, 'pii-gate-hook.js');
const MOCK = path.join(__dirname, 'mock-server.js');
const GATE_INFO = path.join(os.homedir(), '.claude', 'logs', 'pii-gate.json');
const DIR = fs.mkdtempSync(path.join(os.tmpdir(), 'qev-'));
const CAPTURE = path.join(DIR, 'capture.jsonl');

let pass = 0, fail = 0;
const check = (n, got, want) => {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${n}${ok ? '' : `  기대=${want} 실제=${got}`}`);
};
const captured = () => {
  try {
    return fs.readFileSync(CAPTURE, 'utf8').trim().split('\n').filter(Boolean).map(JSON.parse);
  } catch (_) { return []; }
};
const run = (p) => {
  try { execFileSync('node', [HOOK], { input: JSON.stringify(p), encoding: 'utf8', timeout: 20000 }); }
  catch (_) {}
};

// MCP 응답 형태 — 마스킹 MCP 서버의 응답 형태를 본떴다
const RESP_PLAIN = { content: [{ type: 'text', text: JSON.stringify({
  columns: ['TABLE_NAME', 'COMMENTS'],
  rows: [{ TABLE_NAME: 'TB_PERSON_CONTACT', COMMENTS: '개인연락처' }],
  row_count: 1, truncated: false, masked: '해당 없음',
}) }] };
const RESP_MASKED = { content: [{ type: 'text', text: JSON.stringify({
  columns: ['TELNO', 'EMAIL'],
  rows: [{ TELNO: '[PHONE_1]', EMAIL: '[EMAIL_1]' }],
  row_count: 4, truncated: true, masked: 'PHONE 5건 · EMAIL 4건',
}) }] };

(async () => {
  try { fs.unlinkSync(GATE_INFO); } catch (_) {}
  const mock = await new Promise((res) => {
    const p = spawn('node', [MOCK, DIR, 'test-token'], { stdio: ['ignore', 'pipe', 'inherit'] });
    p.stdout.on('data', (d) => { if (String(d).startsWith('ready')) res(p); });
  });
  fs.writeFileSync(path.join(DIR, 'decision.txt'), 'allow');

  console.log('=== PII 없는 메타데이터 조회도 기록되는가 (핵심) ===');
  fs.writeFileSync(CAPTURE, '');
  run({ tool_name: 'mcp__masked-db__exec_query_select',
    tool_input: { sql: 'SELECT TABLE_NAME FROM ALL_TABLES WHERE OWNER=\'APPDB\'', account: 'appdb' },
    tool_response: RESP_PLAIN });
  let ev = captured().filter((c) => c.url === '/event').map((c) => c.body)[0];
  check('이벤트 발생', !!ev, true);
  check('종류 = query', ev && ev.kind, 'query');
  check('SQL 기록됨', !!(ev && ev.detail && ev.detail.query.includes('ALL_TABLES')), true);
  check('계정 기록됨', ev && ev.detail && ev.detail.account, 'appdb');
  check('행수 기록됨', ev && ev.detail && ev.detail.rows, 1);
  if (ev) console.log('   표시: ' + describeQuery(ev.tool, ev.detail));

  console.log('\n=== 마스킹된 조회 ===');
  fs.writeFileSync(CAPTURE, '');
  run({ tool_name: 'mcp__masked-db__exec_query_select',
    tool_input: { sql: 'SELECT TELNO, EMAIL FROM APPDB.TB_PERSON_CONTACT', account: 'appdb' },
    tool_response: RESP_MASKED });
  ev = captured().filter((c) => c.url === '/event').map((c) => c.body)[0];
  check('종류 = masked', ev && ev.kind, 'masked');
  check('마스킹 요약 기록', !!(ev && ev.detail && /PHONE/.test(ev.detail.masked || '')), true);
  if (ev) console.log('   표시: ' + describeQuery(ev.tool, ev.detail));

  console.log('\n=== SQL 안의 PII 는 가려지는가 ===');
  fs.writeFileSync(CAPTURE, '');
  run({ tool_name: 'mcp__masked-db__exec_query_select',
    tool_input: { sql: "SELECT * FROM T WHERE RRN='900101-1234567'", account: 'appdb' },
    tool_response: RESP_PLAIN });
  ev = captured().filter((c) => c.url === '/event').map((c) => c.body)[0];
  check('주민번호 원본 없음', !/900101-1234567/.test(JSON.stringify(ev || {})), true);

  console.log('\n=== 메타데이터 도구 ===');
  fs.writeFileSync(CAPTURE, '');
  run({ tool_name: 'mcp__masked-db__get_table_metadata',
    tool_input: { schema: 'APPDB', table: 'TB_PERSON_CONTACT', account: 'appdb' },
    tool_response: RESP_PLAIN });
  ev = captured().filter((c) => c.url === '/event').map((c) => c.body)[0];
  check('테이블 지정이 기록됨', !!(ev && ev.detail && /CONTACT/.test(ev.detail.query)), true);
  if (ev) console.log('   표시: ' + describeQuery(ev.tool, ev.detail));

  console.log('\n=== 무관한 도구는 조용해야 한다 ===');
  fs.writeFileSync(CAPTURE, '');
  run({ tool_name: 'Read', tool_input: { file_path: 'x.txt' }, tool_response: { content: 'hello' } });
  check('이벤트 없음', captured().filter((c) => c.url === '/event').length, 0);

  mock.kill('SIGTERM');
  await new Promise((r) => setTimeout(r, 300));
  try { fs.unlinkSync(GATE_INFO); } catch (_) {}
  fs.rmSync(DIR, { recursive: true, force: true });
  console.log(`\n합계: ${pass} pass / ${fail} fail`);
  process.exit(fail ? 1 : 0);
})();
