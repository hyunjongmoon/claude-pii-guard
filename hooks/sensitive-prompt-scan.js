#!/usr/bin/env node
/**
 * UserPromptSubmit 훅 — 사용자 프롬프트의 민감정보 감지·차단
 *
 * 동작:
 *   1. stdin JSON 페이로드의 prompt 필드 검사
 *   2. 민감정보 패턴 매칭 (값 기반 + 라벨 prefix 기반)
 *   3. 매치가 있으면:
 *      - 마스킹된 버전 생성 (stable pseudonym)
 *      - PowerShell Set-Clipboard 로 클립보드에 복사
 *      - stderr 로 안내 출력
 *      - exit 2 (차단)
 *   4. 매치 없으면 exit 0 (통과)
 *
 * 매칭 못 잡는 케이스:
 *   - 자유 텍스트의 한글 이름 (라벨/마커 없으면 false positive 위험으로 제외)
 *   - 컬럼명 헤더만 있는 표 (TSV/markdown table) — 후속 버전에서 다룰 수 있음
 *
 * 안전장치:
 *   - 어떤 단계든 예외 발생 시 exit 0 (통과). 훅 오류로 Claude Code 가 막히지 않도록.
 *   - stdin이 비거나 JSON 파싱 실패 시 exit 0.
 */

const { spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

// ─────────────────────────────────────────────────────────────────
// 패턴 정의
// ─────────────────────────────────────────────────────────────────

// 값 기반 정규식 (텍스트 어디서든 매칭)
// 주민번호, 휴대폰, 이메일은 패턴 자체가 충분히 specific해서 false positive 적음
const VALUE_PATTERNS = [
  {
    id: 'RRN',
    label: '주민번호',
    // 6자리 - [1-4]+6자리 (조선/외국인 구분자 1~4). 8 또는 0 으로 시작하면 외국인.
    regex: /(?<!\d)\d{6}[-\s]?[1-8]\d{6}(?!\d)/g,
  },
  {
    id: 'PHONE',
    label: 'PHONE',
    // 한국 휴대폰: 010/011/016/017/018/019
    regex: /(?<!\d)01[016789][-\s]?\d{3,4}[-\s]?\d{4}(?!\d)/g,
  },
  {
    id: 'EMAIL',
    label: 'EMAIL',
    regex: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g,
  },
];

// 라벨 prefix 패턴 — "성명: 홍길동", "학번: 20231234" 같은 케이스
// 캡쳐 1=prefix, 캡쳐 2=value (마스킹 대상)
const LABEL_PATTERNS = [
  {
    id: 'PERSON',
    label: '학생',
    // 성명류 라벨 뒤의 한글 2~4글자 OR 영문 이름
    regex: /((?:^|[\s,|\t])(?:한글성명|영문성명|성명|예금주|이름|학생명|학생|담당자|대표자명?)\s*[:：=]\s*)([가-힣]{2,4}|[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})(?=$|[\s,|\t.])/gm,
  },
  {
    id: 'STUDENT_NUM',
    label: '학번',
    regex: /((?:^|[\s,|\t])(?:학번|학생번호|신분번호|사번|직번)\s*[:：=]\s*)(\d{6,10})(?=$|[\s,|\t.])/gm,
  },
  {
    id: 'ADDR',
    label: 'ADDR',
    // "주소: ..." 뒤의 한 줄
    regex: /((?:^|[\s,|\t])(?:주소[0-9]*|거주지|현주소|본적)\s*[:：=]\s*)([^\n,|\t]{4,100})(?=$|\n|[,|\t])/gm,
  },
  {
    id: 'ACCT',
    label: '계좌번호',
    // 자유 텍스트("계좌번호: 123-456-789")와 JSON 키("계좌번호":"123456789012") 모두 매칭.
    // 키/값을 감싸는 큰따옴표(선택)와 JSON 종결자(" , } ])를 허용한다.
    regex: /((?:^|[\s,|\t{])"?(?:계좌(?:번호)?)"?\s*[:：=]\s*"?)(\d[\d\-\s]{8,20}\d)(?=["'\s,|\t.\]}]|$)/gm,
  },
];

// ─────────────────────────────────────────────────────────────────
// 마스킹 로직
// ─────────────────────────────────────────────────────────────────

function applyMasks(text) {
  const counters = {};
  const maps = {};

  function getPlaceholder(id, label, originalValue) {
    if (!maps[id]) {
      maps[id] = new Map();
      counters[id] = 0;
    }
    const map = maps[id];
    if (map.has(originalValue)) return map.get(originalValue);
    counters[id] += 1;
    const placeholder = `[${label}_${counters[id]}]`;
    map.set(originalValue, placeholder);
    return placeholder;
  }

  let masked = text;
  let totalReplacements = 0;

  // 라벨 기반 먼저: prefix는 보존하고 두 번째 그룹(value)만 치환.
  // 라벨로 카테고리가 확정되는 값(예: "계좌번호":"...")은 값 기반(RRN 등)보다
  // 우선 적용해야 한다. 그렇지 않으면 13자리 계좌번호가 RRN 정규식에 먼저 걸려
  // [주민번호_N]으로 잘못 마스킹된다.
  for (const p of LABEL_PATTERNS) {
    masked = masked.replace(p.regex, (m, prefix, value) => {
      totalReplacements += 1;
      return prefix + getPlaceholder(p.id, p.label, value);
    });
  }

  // 값 기반: 라벨로 안 잡힌 나머지를 매치 전체 치환
  for (const p of VALUE_PATTERNS) {
    masked = masked.replace(p.regex, (m) => {
      totalReplacements += 1;
      return getPlaceholder(p.id, p.label, m);
    });
  }

  return { masked, totalReplacements, maps };
}

function buildSummaryLines(maps) {
  const lines = [];
  for (const [id, map] of Object.entries(maps)) {
    if (map.size === 0) continue;
    lines.push(`  · ${id}: ${map.size}건`);
  }
  return lines;
}

// ─────────────────────────────────────────────────────────────────
// 클립보드
// ─────────────────────────────────────────────────────────────────

function setClipboard(text) {
  // PowerShell의 stdin 경유는 한글 인코딩이 깨지는 경우가 잦아,
  // 임시 파일(UTF-8 BOM)에 쓰고 Get-Content -Encoding UTF8 로 읽어 클립보드에 넣는 방식 사용.
  let tmpPath = null;
  try {
    tmpPath = path.join(
      os.tmpdir(),
      `claude-sensitive-mask-${process.pid}-${Date.now()}.txt`
    );
    // UTF-8 BOM + text — PowerShell이 인코딩을 정확히 감지하도록
    fs.writeFileSync(tmpPath, '﻿' + text, { encoding: 'utf8' });

    const result = spawnSync(
      'powershell',
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        `Get-Content -Raw -Encoding UTF8 -LiteralPath '${tmpPath.replace(/'/g, "''")}' | Set-Clipboard`,
      ],
      { encoding: 'utf8', windowsHide: true }
    );
    return result.status === 0;
  } catch (_e) {
    return false;
  } finally {
    if (tmpPath) {
      try { fs.unlinkSync(tmpPath); } catch (_e) { /* ignore */ }
    }
  }
}

// ─────────────────────────────────────────────────────────────────
// 로그
// ─────────────────────────────────────────────────────────────────

function appendLog(entry) {
  try {
    const logDir = path.join(os.homedir(), '.claude', 'logs');
    fs.mkdirSync(logDir, { recursive: true });
    const logPath = path.join(logDir, 'sensitive-prompt-scan.log');
    fs.appendFileSync(logPath, JSON.stringify(entry) + '\n', 'utf8');
  } catch (_e) {
    // 로깅 실패는 통과
  }
}

// ─────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────

function safeExit(code) {
  // stdout flush 보장 후 종료
  try {
    process.stdout.write('', () => process.exit(code));
  } catch (_e) {
    process.exit(code);
  }
}

let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk) => { raw += chunk; });
process.stdin.on('end', () => {
  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (_e) {
    // 입력 파싱 실패 — 안전하게 통과
    return safeExit(0);
  }

  const prompt = (payload && typeof payload.prompt === 'string') ? payload.prompt : '';
  const sessionId = payload && payload.session_id;

  if (!prompt) return safeExit(0);

  // 일시 해제: 환경변수 또는 프롬프트 안에 토큰 포함
  const bypassEnv = process.env.SENSITIVE_PROMPT_BYPASS;
  const bypassedByEnv = bypassEnv && bypassEnv !== '0' && bypassEnv.toLowerCase() !== 'false';
  if (bypassedByEnv || prompt.includes('--allow-pii')) {
    appendLog({
      ts: new Date().toISOString(),
      sessionId,
      bypassed: true,
      via: bypassedByEnv ? 'env' : 'token',
    });
    return safeExit(0);
  }

  let scanResult;
  try {
    scanResult = applyMasks(prompt);
  } catch (e) {
    appendLog({
      ts: new Date().toISOString(),
      sessionId,
      error: 'mask-apply-failed',
      message: e && e.message,
    });
    return safeExit(0);
  }

  const { masked, totalReplacements, maps } = scanResult;

  if (totalReplacements === 0) {
    // 민감정보 미감지 — 통과
    return safeExit(0);
  }

  appendLog({
    ts: new Date().toISOString(),
    sessionId,
    originalLen: prompt.length,
    maskedLen: masked.length,
    replacements: totalReplacements,
    categories: Object.fromEntries(
      Object.entries(maps).map(([k, m]) => [k, m.size])
    ),
  });

  const clipboardOk = setClipboard(masked);
  const summary = buildSummaryLines(maps);

  const out = [];
  out.push('');
  out.push('[!] 민감정보 감지 — 프롬프트 차단');
  out.push('─────────────────────────────────────────────');
  out.push('감지된 카테고리:');
  out.push(...summary);
  out.push('─────────────────────────────────────────────');
  if (clipboardOk) {
    out.push('마스킹된 버전이 클립보드에 복사되었습니다.');
    out.push('Ctrl+V 로 다시 붙여넣고 제출하세요.');
  } else {
    out.push('클립보드 복사 실패. 아래 마스킹된 버전을 수동 복사:');
    out.push('');
    out.push('--- 마스킹된 프롬프트 ---');
    out.push(masked);
    out.push('--- 끝 ---');
  }
  out.push('');
  out.push('(원본 강제 통과: 프롬프트에 --allow-pii 포함하거나 SENSITIVE_PROMPT_BYPASS=1 환경변수)');

  process.stderr.write(out.join('\n') + '\n');
  return safeExit(2);
});

// 30초 안에 stdin 안 닫히면 강제 종료 (Claude Code 가 막히지 않도록)
setTimeout(() => {
  process.stderr.write('[sensitive-prompt-scan] stdin timeout — passing through\n');
  safeExit(0);
}, 30000).unref();
