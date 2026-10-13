'use strict';
/**
 * requested.js 검증 — "그 종류를 요청한 조회였나" 판정
 *   node analysis/test-requested.js
 */
const { classify } = require('./requested');

let pass = 0;
let fail = 0;
const check = (name, got, want) => {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `  (기대=${want} 실제=${got})`}`);
};
const det = (cats, kind, text) => ({ decision: 'detect', categories: cats, ...(kind ? { source: { kind, text } } : {}) });
const gate = (kind, text) => ({ decision: 'block', categories: {}, source: { kind, text } });

console.log('=== 실행 후 탐지 ===');
check('지정한 컬럼의 종류 → 요청함', classify(det({ 주민등록번호: 1 }, 'sql', 'SELECT EMP_NO, RRN FROM T WHERE NAME=?')).verdict, 'requested');
check('지정 안 한 종류 → 요청 안 함', classify(det({ 계좌번호: 1 }, 'sql', 'SELECT EMP_NO, NAME FROM T')).verdict, 'not-requested');
const mixed = classify(det({ 이메일: 1, 주민등록번호: 1 }, 'sql', 'SELECT EMAIL FROM T'));
check('일부만 지정 → 요청 안 함', mixed.verdict, 'not-requested');
check('종류별로 무엇을 지정했는지', mixed.cats.map((c) => `${c.cat}:${c.requested}`).join(','), '이메일:true,주민등록번호:false');
check('SELECT * → 판단 불가', classify(det({ 이메일: 1 }, 'sql', 'SELECT * FROM T')).verdict, 'unknown');
check('SELECT t.* → 판단 불가', classify(det({ 이메일: 1 }, 'sql', 'SELECT t.* FROM T t')).verdict, 'unknown');
check('파일 읽기 → 판단 불가', classify(det({ 이메일: 1 }, 'file', 'C:/work/a.csv')).verdict, 'unknown');
check('명령은 낱말이 있어도 판단 불가(약한 근거)', classify(det({ 이메일: 1 }, 'command', 'grep -i email data.csv')).verdict, 'unknown');
check('게이트 기록도 명령이면 판단 불가', classify({ decision: 'block', categories: {}, source: { kind: 'command', text: 'grep ACCNO x' } }).verdict, 'unknown');
check('출처 없음 → 근거 없음', classify(det({ 이메일: 1 })).verdict, 'no-source');
check('한글 컬럼 이름', classify(det({ 주민등록번호: 1 }, 'sql', 'SELECT 주민번호 FROM T')).verdict, 'requested');
check('공공 표준 용어(MBTLNUM)', classify(det({ 휴대전화: 1 }, 'sql', 'SELECT MBTLNUM FROM T')).verdict, 'requested');
check('번호 컬럼이 아닌 PHONETIC 은 요청 아님', classify(det({ 휴대전화: 1 }, 'sql', 'SELECT PHONETIC FROM T')).verdict, 'not-requested');
check('CARD_TYPE 은 카드번호 요청 아님', classify(det({ 카드번호: 1 }, 'sql', 'SELECT CARD_TYPE FROM T')).verdict, 'not-requested');

console.log('\n=== 게이트 차단·허용 (탐지 종류 없음) ===');
const asked = classify(gate('sql', 'SELECT RRN, EMAIL FROM T'));
check('개인정보 컬럼을 지정한 조회 → 요청함', asked.verdict, 'requested');
check('어떤 종류를 지정했는지', asked.cats.map((c) => c.cat).join(','), '주민등록번호,이메일');
check('개인정보 컬럼 없음', classify(gate('sql', 'SELECT ? FROM DUAL')).verdict, 'no-pii-columns');
check('SELECT * → 판단 불가', classify(gate('sql', 'SELECT * FROM T')).verdict, 'unknown');

console.log(`\n합계: ${pass} pass / ${fail} fail`);
process.exit(fail ? 1 : 0);
