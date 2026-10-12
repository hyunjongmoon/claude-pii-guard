'use strict';
/** 표시 함수 검증 — 실제 감사로그 항목으로 확인한다 */
const { explain, shorten, hhmmss } = require('./format.js');
const fs = require('fs');
const path = require('path');
const os = require('os');

let pass = 0, fail = 0;
function check(name, got, want) {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}`);
  if (!ok) console.log(`        기대=${want}\n        실제=${got}`);
}

console.log('=== 1. 시각 — UTC 를 현지시각으로 ===');
// 2026-08-06T00:38:47Z 는 KST 09:38:47
check('UTC→KST 변환', hhmmss('2026-08-06T00:38:47.835Z'), '09:38:47');
check('자정 넘김', hhmmss('2026-08-05T15:00:00.000Z'), '00:00:00');
check('빈 값', hhmmss(null), '--:--:--');
check('깨진 값', hhmmss('not-a-date'), '--:--:--');

console.log('\n=== 2. 차단 사유 — 정규식 소스를 한글로 ===');
const cases = [
  ['\\boracledb\\b', 'Oracle 드라이버를 직접 부름'],
  ['\\bcx_Oracle\\b', 'Oracle 드라이버를 직접 부름'],
  ['\\bdbhelper\\b', '내부 DB 접속 모듈을 부름'],
  ['\\bsqlplus\\b', 'Oracle 명령줄 도구를 실행함'],
  ['\\btnsping\\b', 'DB 서버 접속을 확인하려 함'],
  [':\\d{4,5}\\/MYDB\\b', 'DB 접속 주소가 들어 있음'],
  ['sys\\.path\\.insert[^\\n]*\\.dbcreds', '자격증명 폴더를 import 경로에 추가함'],
  ['\\.dbcreds[\\/\\\\]\\.env', '자격증명 파일에 직접 접근함'],
  ['__import__\\s*\\(', '모듈명을 숨길 수 있는 동적 import'],
  ['\\bimportlib\\b', '모듈명을 숨길 수 있는 동적 import'],
  ['\\bexec\\s*\\(', '문자열을 코드로 실행함'],
  ['\\b_connect\\s*\\(', 'DB 접속 함수를 직접 호출함'],
];
for (const [src, want] of cases) check(`"${src}"`, explain(src), want);
check('빈 값은 빈 문자열', explain(null), '');
check('미매핑 패턴도 읽히게', explain('\\bfoobar\\b'), '차단 규칙: foobar');

console.log('\n=== 3. 명령 축약 ===');
// 디렉터리만 접고 파일명은 남긴다 — 무엇을 실행했는지가 로그의 요지다
check('임시 경로 접기(파일명 유지)',
  shorten('node "C:/Users/me/AppData/Local/Temp/claude/C--Project-MyApp/abc/scratchpad/x.js"'),
  'node "%임시%/x.js"');
check('프로젝트 경로 접기',
  shorten('cd "C:/Project/MyApp/tools/pii-gate/hook" && node test-gate.js'),
  'node test-gate.js');
check('홈 경로 접기', shorten('cat C:/Users/me/.claude/settings.json'), 'cat ~/.claude/settings.json');
check('공백 정리', shorten('ls    -la\n  foo'), 'ls -la foo');
check('빈 값', shorten(null), '');

console.log('\n=== 4. 실제 감사로그로 확인 ===');
const LOG = path.join(os.homedir(), '.claude', 'logs', 'bash-audit.log');
try {
  const rows = fs.readFileSync(LOG, 'utf8').trim().split('\n')
    .filter(Boolean).map(JSON.parse);
  const denies = rows.filter((r) => r.decision === 'deny').slice(-4);
  console.log(`  로그 ${rows.length}줄 · 차단 항목 표시 예시:`);
  for (const r of denies) {
    console.log(`   ${hhmmss(r.ts)}  차단 · ${explain(r.matched)}`);
    console.log(`             ${shorten(r.cmd).slice(0, 84)}`);
  }
  // 이 PC 의 실제 가드 규칙에 달린 점검이라 실패로 치지 않는다 — 미매핑이 있으면
  // format.js 의 REASONS 를 자기 db-access-guard 규칙에 맞추라는 신호다.
  const unmapped = rows.filter((r) => r.decision === 'deny' && explain(r.matched).startsWith('차단 규칙:'));
  console.log(unmapped.length
    ? `  ⚠ 미매핑 차단 사유 ${unmapped.length}건 — REASONS 를 자기 가드 규칙에 맞추십시오`
    : '  미매핑 차단 사유 없음');
} catch (e) {
  console.log('  로그 읽기 실패: ' + e.message);
}

console.log(`\n합계: ${pass} pass / ${fail} fail`);
process.exit(fail ? 1 : 0);
