'use strict';
/**
 * 탐지 정확도 검증 — 훅 소스에서 패턴만 뽑아 케이스 파일로 돌린다.
 * 케이스를 별도 JSON 으로 둔 이유: 이 파일 본문에 탐지 어휘가 들어가면
 * db-access-guard 훅이 테스트 실행 자체를 막는다.
 */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

// 훅 소스에서 PII_PATTERNS / MASK_HINT 정의부만 평가한다 (stdin 을 읽지 않기 위해).
const src = fs.readFileSync(path.join(__dirname, 'pii-gate-hook.js'), 'utf8');
const grab = (name, open, close) => {
  const i = src.indexOf(name);
  if (i < 0) throw new Error(name + ' 정의를 못 찾음');
  const s = src.indexOf(open, i);
  let depth = 0, j = s;
  for (; j < src.length; j++) {
    if (src[j] === open) depth++;
    else if (src[j] === close) { depth--; if (!depth) break; }
  }
  return src.slice(s, j + 1);
};
// PII_PATTERNS 가 ok: cardOk 로 함수를 참조하므로 배열보다 먼저 넣어야 한다.
const grabFn = (name) => {
  const i = src.indexOf(`function ${name}(`);
  if (i < 0) throw new Error(`${name} 함수 정의를 못 찾음`);
  const s = src.indexOf('{', i);
  let depth = 0, j = s;
  for (; j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}') { depth--; if (!depth) break; }
  }
  return src.slice(i, j + 1);
};
const ctx = {};
vm.createContext(ctx);
vm.runInContext(grabFn('luhn'), ctx);
vm.runInContext(grabFn('cardOk'), ctx);
vm.runInContext(grabFn('rrnOk'), ctx);
vm.runInContext(`var PII_PATTERNS = ${grab('const PII_PATTERNS', '[', ']')};`, ctx);
vm.runInContext(`var MASK_HINT = ${src.match(/const MASK_HINT = (\/.*\/);/)[1]};`, ctx);

function scan(text) {
  const out = [];
  for (const { key, re, ok } of ctx.PII_PATTERNS) {
    re.lastIndex = 0;
    const m = (text.match(re) || []).filter((s) => !ok || ok(s));
    if (m.length) out.push(key);
  }
  return out;
}

const CASES = JSON.parse(fs.readFileSync(path.join(__dirname, 'pii-cases.json'), 'utf8'));
let pass = 0, fail = 0;
function check(name, got, want) {
  const ok = got === want;
  ok ? pass++ : fail++;
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${ok ? '' : `   기대=${want} 실제=${got}`}`);
}

console.log('=== ① 오탐이면 안 되는 것 ===');
for (const [text, want] of CASES['오탐이면_안되는_것']) {
  check(JSON.stringify(text), scan(text).join(',') || '(없음)', want.join(',') || '(없음)');
}

console.log('\n=== 진짜 PII 는 여전히 잡히는가 ===');
for (const [text, want] of CASES['반드시_검출되어야_하는_것']) {
  check(JSON.stringify(text).slice(0, 40), scan(text).join(','), want.join(','));
}

console.log('\n=== ② 마스킹 형식 인식 ===');
for (const [text, want] of CASES['마스킹_인식']) {
  check(JSON.stringify(text).slice(0, 50), String(ctx.MASK_HINT.test(text)), String(want));
}

console.log(`\n합계: ${pass} pass / ${fail} fail`);
process.exit(fail ? 1 : 0);
