'use strict';
/**
 * 훅 설치 — 저장소 원본을 ~/.claude/hooks/ 로 복사하고 원본·설치본 해시를 나란히 찍는다.
 *
 * 손으로 복사하다 두 사본이 어긋난 적이 있다(주민번호 정규식 한 줄, 2026-10 발견).
 * 설치 전 상태도 함께 보여 주므로 "어긋나 있었는지"를 그 자리에서 알 수 있다.
 *
 *   node hook\install.js
 *
 * 해시가 불일치하면 종료코드 1.
 */
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const FILES = ['pii-gate-hook.js'];
const DEST_DIR = path.join(os.homedir(), '.claude', 'hooks');

function sha256(p) {
  try { return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex'); }
  catch (_) { return null; }
}

fs.mkdirSync(DEST_DIR, { recursive: true });
let mismatch = 0;

for (const name of FILES) {
  const src = path.join(__dirname, name);
  const dst = path.join(DEST_DIR, name);
  const before = sha256(dst);
  fs.copyFileSync(src, dst);
  const s = sha256(src);
  const d = sha256(dst);
  if (s !== d) mismatch += 1;

  const was = before === null ? '신규 설치'
    : before === s ? '이미 일치 (변경 없음)'
    : `어긋나 있었음 → 갱신 (이전 ${before.slice(0, 12)})`;
  console.log(name);
  console.log(`  원본    ${s}  ${src}`);
  console.log(`  설치본  ${d}  ${dst}`);
  console.log(`  ${s === d ? '일치' : '불일치'} · 설치 전: ${was}`);
}

process.exit(mismatch ? 1 : 0);
