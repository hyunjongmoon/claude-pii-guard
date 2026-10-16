#!/usr/bin/env node
// -*- coding: utf-8 -*-
/**
 * PII 전송 게이트 훅 — 위젯(pii-guard-widget)과 짝을 이룬다.
 *
 * 두 단계로 동작하며, 입력에 tool_response 가 있으면 사후 단계로 본다.
 *
 *   PreToolUse  (예방)  DB 조회 계열 도구 호출을 실행 전에 붙들고, 위젯에서
 *                       "넘기시겠습니까" 확인을 받는다. 사용자가 차단하면 도구가
 *                       아예 실행되지 않으므로 결과가 존재하지 않는다.
 *
 *   PostToolUse (탐지)  결과에 마스킹 안 된 PII 가 있으면 위젯에 경보만 보낸다.
 *                       이 시점에는 결과가 이미 모델 컨텍스트에 들어가 있어
 *                       되돌릴 수 없다 — 막는 게 아니라 보이게 하는 층이다.
 *
 * 감사로그 (~/.claude/logs/pii-gate-events.log, JSON Lines)
 *   게이트 판정(block/pass)과 사후 탐지(detect)를 위젯보다 먼저 파일에 남긴다.
 *   위젯은 보여주는 뷰어일 뿐 기록 저장소가 아니다 — 화면에만 있는 기록은
 *   위젯을 닫는 순간 사라진다.
 *
 * fail-closed
 *   위젯이 떠 있지 않으면(게이트 정보 파일 없음/응답 없음) 대상 도구는 차단한다.
 *   위젯을 끄는 것만으로 게이트를 무력화할 수 있으면 게이트가 아니기 때문이다.
 *
 * 값 비노출
 *   위젯에는 필드명·건수·자릿수만, 감사로그에는 종류별 건수만 보낸다.
 *   PII 값 자체는 어디에도 싣지 않는다.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const http = require('http');

const GATE_INFO = path.join(os.homedir(), '.claude', 'logs', 'pii-gate.json');
const EVENT_LOG = path.join(os.homedir(), '.claude', 'logs', 'pii-gate-events.log');
const ASK_TIMEOUT_MS = 90000;     // 위젯 서버(120s)보다 짧게 — 여기서 먼저 deny 한다
const EVENT_TIMEOUT_MS = 1500;
const MAX_SCAN_CHARS = 2 * 1024 * 1024;

/**
 * 실행 전 확인이 필요한 도구 — DB 에서 실데이터·접속정보를 끌어오는 경로.
 * 마지막 패턴은 "서버 이름"에 db 가 든 경우(예: my-db)를 노린 것이라
 * 서버가 idea 처럼 다른 이름이면 적용되지 않는다. 그래서 idea 계열은 손으로 나열한다.
 *
 * 스키마 메타데이터 계열(introspect_schema, list_schema_objects,
 * get_database_object_description 등)은 개인정보를 담지 않으므로 일부러 뺀다.
 */
const GATED_TOOLS = [
  /^mcp__.*__execute_sql_query$/i,
  /^mcp__.*__fetch_query_result$/i,
  /^mcp__.*__preview_table_data$/i,
  /^mcp__.*__list_recent_sql_queries$/i,
  /^mcp__.*__list_database_connections$/i,   // 접속정보(호스트·포트·계정)를 반환한다
  /^mcp__.*db.*__(?!.*(?:schema|describe|list_schema|object_kind)).*$/i,
];

/** 마스킹이 보장된 경로 — 확인 없이 통과시킨다 */
const TRUSTED_TOOLS = [
  /^mcp__masked-db__/i, // 자기 환경의 마스킹 보장 MCP 서버 이름으로 바꾼다
];

/**
 * 카드번호 검사식(Luhn, mod 10). 실제로 발급되는 카드번호는 예외 없이 이 검사를
 * 통과하므로, 통과하지 못하는 16자리 숫자는 카드번호가 아니다.
 * 반대로 임의의 16자리가 우연히 통과할 확률은 1/10 이라, 이 한 줄로 오탐이 90% 준다.
 */
function luhn(s) {
  const d = String(s).replace(/\D/g, '');
  if (d.length !== 16) return false;
  let sum = 0;
  for (let i = 0; i < 16; i += 1) {
    let n = Number(d[15 - i]);
    if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return sum % 10 === 0;
}

/**
 * 하이픈으로 끊어 쓴 4-4-4-4 는 그 자체가 카드번호 표기라 그대로 인정한다.
 * 업무 데이터가 그 모양으로 찍히는 일은 없기 때문. 실제 오탐은 전부
 * 구분자 없는 16자리에서 나왔으므로 거기에만 Luhn 을 건다 — 탐지력은 그대로 두고
 * 오탐만 걷어내는 쪽이, 잡던 것까지 놓치는 것보다 낫다.
 */
function cardOk(s) {
  return /^\d{4}(-\d{4}){3}$/.test(s) || luhn(s);
}

/**
 * 주민번호 앞 6자리는 생년월일이다 — 월이 01~12, 일이 01~31 이 아니면 주민번호가 아니다.
 * 실제 오탐(2026-10-12): Git Bash 의 ls -la 는 그룹 ID(197121)와 파일 크기를 공백으로 이어
 * 찍어 "197121 1234567" 이 된다 — 월 71. 체크섬은 쓰지 않는다: 2020-10 이후 발급분은
 * 검증 숫자 규칙이 없어, 체크섬으로 거르면 진짜 번호를 놓친다.
 */
function rrnOk(s) {
  const d = String(s).replace(/\D/g, '');
  const mm = Number(d.slice(2, 4));
  const dd = Number(d.slice(4, 6));
  return mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31;
}

/**
 * 이메일의 맨 끝 마디(TLD)는 글자이고 카멜표기가 아니다(com · kr · COM · Com).
 * 실제 오탐(2026-10-13): Spring DevTools 로그의 「패키지.클래스명@패키지.클래스로더」 — TLD 자리가
 * RestartClassLoader 처럼 카멜표기다. 패키지 버전 표기(이름@18.3.1)는 TLD 가 숫자뿐이다.
 * @ 앞쪽 카멜표기로 거르면 안 된다 — Mary.McDonald@… 같은 진짜 주소를 놓친다.
 */
function emailOk(s) {
  const tld = String(s).split('.').pop();
  return /[A-Za-z]/.test(tld) && !/[a-z][A-Z]/.test(tld);
}

/**
 * 오탐이 잦으면 경보가 상시 울리고, 그러면 진짜 유출이 묻힌다.
 * 그래서 형태가 겹치는 것들(날짜·지역번호 전화·소수점 숫자)을 선제 배제한다.
 * 형태만으로 못 거르는 것은 ok() 로 값 자체를 한 번 더 검증한다.
 */
const PII_PATTERNS = [
  // 뒷자리 첫 숫자 5~8 은 외국인등록번호 — 유학생 데이터가 있으므로 같이 잡는다.
  // 구분자는 하이픈·공백 한 칸만: \s 는 줄바꿈·탭까지 받아 표의 줄 끝 6자리와
  // 다음 줄 앞 7자리를 이어 붙여 잡는다.
  // 앞뒤 경계 — 다음은 제외한다 (N = 숫자 13자리 자리표시):
  //   더 긴 숫자의 일부                          N 앞뒤에 숫자가 더 붙은 것
  //   ASCII 식별자 안에 박힌 숫자(실제 오탐)       DIV|N_wframe , mf_N_body , abcN
  //   소수                                       0.N , N.5
  // 마침표는 숫자에 붙을 때만 막는다 — 문장 끝(N.)과 확장자(N.pdf)는 잡아야 한다.
  // 한글·공백·기호에 붙은 것은 그대로 잡는다: 주민번호N , 홍길동_N.hwp
  // 이 훅은 JSON.stringify 한 결과를 검사하므로 줄바꿈·탭이 \n · \t 두 글자가 된다 —
  // 줄 첫머리·탭 뒤의 번호 앞에는 늘 n · t 가 온다. 역슬래시 뒤 영문자는 식별자가 아니라
  // 이스케이프이므로 경계로 본다. (이 예외가 없으면 CSV·표의 줄 첫 번호를 전부 놓친다.)
  {
    key: '주민등록번호',
    re: /(?<!(?<!\\)[A-Za-z]|\d|[A-Za-z\d]_|\d\.)\d{6}[- ]?[1-8]\d{6}(?![A-Za-z\d]|_[A-Za-z\d]|\.\d)/g,
    ok: rrnOk,
  },
  // 앞의 두 부정형 선읽기가 각각 ISO 날짜(2026-08-05)와 지역번호 전화(02-953-1234)를 뺀다.
  // 이 배제가 없으면 문서·조회 결과의 날짜가 전부 계좌번호로 잡힌다.
  {
    key: '계좌번호',
    // 세 번째 선읽기는 카드번호 형태를 넘기고, 앞의 되읽기는 그 카드번호 "중간부터"
    // 다시 잡히는 것을 막는다 — 같은 값이 계좌·카드로 이중 계상되지 않게.
    // 되읽기의 [A-Fa-f] 는 GUID(8-4-4-4-12 16진) 안의 숫자 구간을 뺀다 — 실제 오탐(2026-10-12):
    // ERD 비교 출력의 GUID. GUID 안에서 일치가 시작되려면 앞이 하이픈·숫자(이미 배제)이거나
    // 16진 영문자뿐이라 이것으로 다 막힌다. 뒤쪽 "-숫자" 로 거르면 안 된다 — 4마디 계좌
    // (농협 3-4-4-2)를 놓친다. 대가: a~f 에 딱 붙은 계좌번호는 놓친다.
    re: /(?<![\d-]|[A-Fa-f])(?!(?:19|20)\d{2}-(?:0?[1-9]|1[0-2])-(?:0?[1-9]|[12]\d|3[01])\b)(?!0\d{1,2}-)(?!(?:\d{4}[-\s]){3}\d{4})\d{2,6}-\d{2,6}-\d{2,8}\b/g,
  },
  // 앞뒤 숫자와 "숫자에 붙은 마침표"를 막아 1.2000000000000002 같은 부동소수점 출력이
  // 걸리지 않게 한다. 마침표를 무조건 막으면 문장 끝(…-1111.)의 진짜 번호를 놓친다.
  // 구분자가 선택적이라 16자리 연속 숫자면 무엇이든 걸린다 — 업무 데이터에는
  // 날짜 두 개를 이어붙인 값(20260301+20260831 → BEGIN_DT/END_DT)처럼
  // 16자리가 흔하다. 그래서 형태만으로 판단하지 않고 Luhn 으로 한 번 더 거른다.
  { key: '카드번호', re: /(?<!\d|\d\.)(?:\d{4}[-\s]?){3}\d{4}(?!\d|\.\d)/g, ok: cardOk },
  // 경계는 카드번호와 같다 — 문장 끝(…-5678.)은 잡고, 소수(0.010… · …5678.5)는 뺀다.
  { key: '휴대전화', re: /(?<!\d|\d\.)01[016-9][-\s]?\d{3,4}[-\s]?\d{4}(?!\d|\.\d)/g },
  { key: '이메일', re: /\b[\w.+-]+@[\w-]+\.[\w.]{2,}\b/g, ok: emailOk },
];

/**
 * 마스킹 흔적 — 이게 보이면 정해진 경로를 탄 결과로 본다.
 * 마스킹 MCP 서버와 헬퍼는 [STAFF_1] · [PERSON_1] 형태로 치환하므로 그 형식도 인식해야
 * 정상 조회에 초록 이벤트가 뜬다.
 */
const MASK_HINT = /[●*▪·]{3,}|X{4,}|\[[A-Z_]+_\d+\]/;

function readStdin() {
  try { return fs.readFileSync(0, 'utf8'); } catch (_) { return ''; }
}

function gateInfo() {
  try {
    const j = JSON.parse(fs.readFileSync(GATE_INFO, 'utf8'));
    if (j && j.port && j.token) return j;
  } catch (_) {}
  return null;
}

function match(name, list) {
  return list.some((re) => re.test(name));
}

/** 값은 버리고 종류·건수·자릿수만 남긴다 */
function scanPii(text) {
  const fields = [];
  for (const { key, re, ok } of PII_PATTERNS) {
    re.lastIndex = 0;
    const m = (text.match(re) || []).filter((s) => !ok || ok(s));
    if (m.length) {
      const len = m.reduce((a, s) => Math.max(a, s.length), 0);
      fields.push({ key, count: m.length, len });
    }
  }
  return fields;
}

/**
 * 감사로그 한 줄 — sensitive-prompt-scan.log 와 같은 형식(ts·sessionId·categories)이라
 * 기존 분석기를 그대로 쓸 수 있다. categories 에는 종류별 건수만 싣는다.
 * 실패를 삼키지 않고 오류 코드를 돌려준다 — 경보 문구가 기록 여부를 사실대로 말해야 한다.
 * source 는 이 판정을 낳은 조회·명령·파일 — "그 종류를 요청한 조회였나"를 나중에 확인하는 근거.
 */
function logEvent(payload, decision, fields, reason) {
  try {
    const source = sourceOf(payload && payload.tool_input);
    fs.mkdirSync(path.dirname(EVENT_LOG), { recursive: true });
    fs.appendFileSync(EVENT_LOG, JSON.stringify({
      ts: new Date().toISOString(),
      sessionId: (payload && payload.session_id) || null,
      tool: String((payload && payload.tool_name) || ''),
      decision,
      categories: Object.fromEntries((fields || []).map((f) => [f.key, f.count])),
      ...(reason ? { reason } : {}),
      ...(source ? { source } : {}),
    }) + '\n', 'utf8');
    return null;
  } catch (e) {
    return (e && e.code) || 'unknown';
  }
}

/** 화면·로그에 실릴 문자열에서 PII 를 지운다 */
function redact(text) {
  let out = String(text || '');
  for (const { re, ok } of PII_PATTERNS) {
    re.lastIndex = 0;
    // 검증에서 탈락한 값은 PII 가 아니므로 지우지 않는다 — 지우면 화면에서
    // 무슨 쿼리였는지 알아볼 수 없게 되고, 그게 이 위젯을 만든 이유를 무너뜨린다.
    out = out.replace(re, (s) => (ok && !ok(s) ? s : '●'.repeat(Math.min(s.length, 12))));
  }
  return out;
}

/**
 * 감사로그에 남길 출처 — 값은 남기지 않는다.
 *   SQL   문자열·숫자 리터럴을 ? 로 바꾼다. 이름(WHERE NAME='…')처럼 정규식이 못 잡는 값까지 빠지고,
 *         "무슨 컬럼을 달라고 했나"는 그대로 남는다 — 그게 확인하려는 것이다.
 *   명령  PII 모양을 가리고(redact) 비밀값(password=… 등)을 *** 로 가린다.
 *   파일  경로만.
 * 도구마다 인자 이름이 다르다 — 마스킹 MCP 는 sql, IDE(idea) 는 queryText·tableName·resultSetId.
 * (2026-10-16 실측: idea 의 queryText 를 몰라 차단 기록에 출처가 비었다.)
 */
function sourceOf(inp) {
  if (!inp || typeof inp !== 'object') return null;
  const clip = (s) => String(s).replace(/\s+/g, ' ').trim().slice(0, 400);
  const sql = inp.sql || inp.query || inp.queryText;
  if (typeof sql === 'string' && sql.trim()) return { kind: 'sql', text: clip(normalizeSql(sql)) };
  if (typeof inp.command === 'string') return { kind: 'command', text: clip(maskSecrets(redact(inp.command))) };
  const file = inp.file_path || inp.path;
  if (typeof file === 'string') return { kind: 'file', text: clip(file) };
  if (typeof inp.table === 'string') return { kind: 'sql', text: clip([inp.schema, inp.table].filter(Boolean).join('.')) };
  // 표 미리보기는 컬럼을 고르지 않고 전부 가져온다 — SELECT * 로 적어 판정이 「판단 불가」가 되게 한다
  if (typeof inp.tableName === 'string') {
    return { kind: 'sql', text: clip(`SELECT * FROM ${[inp.schemaName, inp.tableName].filter(Boolean).join('.')} (미리보기)`) };
  }
  if (typeof inp.resultSetId === 'string') return { kind: 'input', text: clip(`이전 조회 결과 이어받기 resultSetId=${inp.resultSetId}`) };
  for (const k of ['url', 'text', 'code']) {
    if (typeof inp[k] === 'string' && inp[k].trim()) return { kind: 'input', text: clip(maskSecrets(redact(inp[k]))) };
  }
  if (typeof inp.connectionId === 'string') return { kind: 'input', text: clip(`connectionId=${inp.connectionId}`) };
  return null;
}

function normalizeSql(s) {
  return String(s)
    .replace(/'(?:[^']|'')*'/g, '?')
    .replace(/(?<![\w.])\d+(?:\.\d+)?(?![\w.])/g, '?');
}

function maskSecrets(s) {
  return String(s).replace(/((?:password|passwd|pwd|secret|token|api[_-]?key)["']?\s*[:=]\s*["']?)[^\s"'&,;]+/gi, '$1***');
}

function post(info, urlPath, body, timeoutMs) {
  return new Promise((resolve) => {
    const data = Buffer.from(JSON.stringify(body), 'utf8');
    const req = http.request({
      host: '127.0.0.1', port: info.port, path: urlPath, method: 'POST',
      headers: {
        'content-type': 'application/json',
        'content-length': data.length,
        'x-gate-token': info.token,
      },
    }, (res) => {
      let b = '';
      res.on('data', (c) => { b += c; });
      res.on('end', () => { try { resolve(JSON.parse(b)); } catch (_) { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.setTimeout(timeoutMs, () => { req.destroy(); resolve(null); });
    req.end(data);
  });
}

function emit(obj) {
  process.stdout.write(JSON.stringify(obj));
  process.exit(0);
}

const allow = () => emit({
  hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: 'allow' },
});

const deny = (reason) => emit({
  hookSpecificOutput: {
    hookEventName: 'PreToolUse',
    permissionDecision: 'deny',
    permissionDecisionReason: reason,
  },
});

/** DB 조회 계열 MCP 도구인가 — 무엇을 조회했는지 항상 남겨야 할 대상 */
function isDbQueryTool(tool) {
  return /^mcp__.*__(exec_query_select|execute_sql_query|fetch_query_result|preview_table_data|get_table_metadata|list_schemas|list_recent_sql_queries|get_source|get_dependencies|list_database_connections)$/i
    .test(tool);
}

/**
 * 응답에서 행수·마스킹요약을 뽑는다.
 * MCP 응답은 {content:[{text:"<JSON 문자열>"}]} 형태라, 바깥에서 stringify 하면
 * 안쪽 따옴표가 \" 로 이스케이프된다. 먼저 한 겹 풀고 찾는다.
 */
function pickMeta(text) {
  const t = String(text).replace(/\\"/g, '"');
  const rows = /"row_count"\s*:\s*(\d+)/.exec(t);
  const masked = /"masked"\s*:\s*"([^"]*)"/.exec(t);
  return {
    rows: rows ? Number(rows[1]) : null,
    masked: masked ? masked[1] : null,
    truncated: /"truncated"\s*:\s*true/.test(t),
  };
}

/** 사후 탐지 — 알리기만 하고 통과시킨다 */
async function post_phase(payload) {
  let text;
  try { text = JSON.stringify(payload.tool_response).slice(0, MAX_SCAN_CHARS); }
  catch (_) { process.exit(0); }

  const fields = scanPii(text);
  const info = gateInfo();
  const tool = String(payload.tool_name || '');

  // 어떤 도구든 "무엇 때문에 이 줄이 생겼는지" 를 붙인다.
  // PII 경보가 떴는데 도구명만 있으면 어느 명령이 원인인지 알 수 없어 추적이 불가능하다.
  const inp = payload.tool_input || {};
  const isDb = isDbQueryTool(tool);
  let detail = null;
  if (isDb) {
    const meta = pickMeta(text);
    const q = inp.sql || inp.query || inp.queryText || inp.table
      || [inp.schema || inp.schemaName, inp.table || inp.tableName].filter(Boolean).join('.') || '';
    detail = {
      account: inp.account || null,
      schema: inp.schema || null,
      query: redact(String(q)).replace(/\s+/g, ' ').slice(0, 300),
      rows: meta.rows,
      masked: meta.masked,
      truncated: meta.truncated,
    };
  } else if (inp.command) {
    detail = { command: redact(String(inp.command)).replace(/\s+/g, ' ').slice(0, 300) };
  } else if (inp.file_path || inp.path) {
    detail = { file: String(inp.file_path || inp.path).slice(0, 300) };
  }

  // 파일이 먼저다. 기록을 위젯에 맡기면 위젯이 꺼져 있던 동안의 탐지는 흔적 없이 사라진다.
  const logErr = fields.length ? logEvent(payload, 'detect', fields) : null;
  let shown = false;

  if (info) {
    if (fields.length) {
      const r = await post(info, '/event', { kind: 'leak', tool, summary: { fields }, detail },
        EVENT_TIMEOUT_MS);
      shown = !!(r && r.ok);
    } else if (isDb && MASK_HINT.test(text)) {
      // 마스킹 여부는 DB 조회 결과에만 의미가 있다.
      // Bash 출력의 [ABC_1] · XXXX 같은 문자열까지 '마스킹 조회'로 부르면 오탐만 늘어난다.
      await post(info, '/event', { kind: 'masked', tool, detail }, EVENT_TIMEOUT_MS);
    } else if (isDb) {
      await post(info, '/event', { kind: 'query', tool, detail }, EVENT_TIMEOUT_MS);
    }
  }

  if (fields.length) {
    // 되돌릴 수는 없지만, 모델에게도 사실을 알려 이후 처리에서 값을 다루지 않게 한다.
    // 기록 여부는 실제 결과대로만 말한다 — 보안 도구가 하지 않은 기록을 했다고 하면 안 된다.
    const logged = logErr
      ? `기록 실패: pii-gate-events.log 에 쓰지 못함(${logErr})`
      : 'pii-gate-events.log 에 기록됨';
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PostToolUse',
        additionalContext:
          `[PII 경보] 방금 결과에 마스킹되지 않은 개인정보가 포함되었습니다 ` +
          `(${fields.map((f) => `${f.key}×${f.count}`).join(', ')}). ` +
          `이 값들을 출력·요약·재전송하지 마십시오. ` +
          `${logged}${shown ? ' + 위젯 표시' : ' (위젯 미표시)'}.`,
      },
    }));
  }
  process.exit(0);
}

/** 사전 게이트 — 실행 전에 붙든다 */
async function pre_phase(payload) {
  const tool = String(payload.tool_name || '');
  if (match(tool, TRUSTED_TOOLS)) allow();
  if (!match(tool, GATED_TOOLS)) allow();

  let inputText = '';
  try { inputText = JSON.stringify(payload.tool_input || {}); } catch (_) {}
  const fields = scanPii(inputText);

  // 판정마다 deny()/allow() 전에 기록한다 — 둘 다 process.exit 로 끝나기 때문.
  const info = gateInfo();
  if (!info) {
    logEvent(payload, 'block', fields, 'widget-down');
    deny(
      `PII 게이트 위젯이 실행 중이 아니어서 차단했습니다 (fail-closed).\n` +
      `이 도구(${tool})는 마스킹되지 않은 DB 데이터를 클로드 서버로 보낼 수 있습니다.\n` +
      `tools/pii-guard-widget 에서 "npm start" 로 위젯을 띄운 뒤 다시 시도하십시오.`);
  }

  const res = await post(info, '/gate', {
    tool,
    cmd: redact(inputText).slice(0, 1200),
    reason: '마스킹되지 않은 DB 데이터가 클로드 서버로 전송될 수 있습니다.',
    summary: { fields },
  }, ASK_TIMEOUT_MS + 5000);

  if (!res) {
    logEvent(payload, 'block', fields, 'no-response');
    deny(
      `게이트 응답이 없어 차단했습니다 (fail-closed).\n` +
      `위젯이 응답하지 않거나 ${Math.round(ASK_TIMEOUT_MS / 1000)}초 안에 확인되지 않았습니다.`);
  }
  if (res.decision === 'allow') {
    logEvent(payload, 'pass', fields);
    allow();
  }
  logEvent(payload, 'block', fields, res.reason === 'timeout' ? 'timeout' : 'user-deny');
  deny(`사용자가 전송을 차단했습니다 (위젯에서 "차단" 선택).`);
}

/** catch 에서 참조한다 — stdin(fd 0)은 한 번만 읽을 수 있어 재파싱이 불가능하다. */
let PAYLOAD = null;

async function main() {
  const raw = readStdin();
  if (!raw) allow();

  try { PAYLOAD = JSON.parse(raw); } catch (_) { allow(); }

  if (PAYLOAD.tool_response !== undefined) return post_phase(PAYLOAD);
  return pre_phase(PAYLOAD);
}

// 예기치 못한 예외에서도 fail-closed 를 지킨다.
// 사후 단계는 이미 실행된 뒤라 막을 것이 없으므로 조용히 통과시킨다.
main().catch((e) => {
  const tool = (PAYLOAD && PAYLOAD.tool_name) || '';
  const isPost = !!(PAYLOAD && PAYLOAD.tool_response !== undefined);
  if (!isPost && match(tool, GATED_TOOLS) && !match(tool, TRUSTED_TOOLS)) {
    logEvent(PAYLOAD, 'block', [], 'internal-error');
    deny(`게이트 훅 내부 오류로 차단했습니다 (fail-closed): ${String(e).slice(0, 200)}`);
  }
  if (isPost) process.exit(0);
  allow();
});
