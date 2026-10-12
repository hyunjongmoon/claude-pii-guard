'use strict';
/**
 * 표시용 순수 함수 — DOM 을 건드리지 않으므로 node 에서 그대로 테스트할 수 있다.
 * (renderer.js 는 DOM 배선만 담당한다)
 */

/**
 * 훅이 감사로그에 남기는 matched 는 정규식 "소스 문자열"이다.
 *   예: "\\boracledb\\b", "sys\\.path\\.insert[^\\n]*\\.dbcreds"
 * 사람이 읽을 수 없으므로 한글 사유로 옮긴다.
 * 훅 파일은 권한상 수정할 수 없어 매핑을 화면 쪽에 둔다.
 * 소스 문자열 안의 특징적인 낱말만 보므로 이스케이프에 좌우되지 않는다.
 */
const REASONS = [
  [/oracledb|cx_Oracle/i, 'Oracle 드라이버를 직접 부름'],
  [/pyodbc|pymssql|jaydebeapi/i, 'DB 드라이버를 직접 부름'],
  [/jdbc:oracle/i, 'JDBC 접속 문자열이 들어 있음'],
  [/sqlplus|sqlcl/i, 'Oracle 명령줄 도구를 실행함'],
  [/tnsping/i, 'DB 서버 접속을 확인하려 함'],
  // 아래 셋은 환경마다 다르다 — MYDB(DB 서비스명) · dbhelper(내부 접속 모듈) · .dbcreds(자격증명 폴더)를
  // 자기 db-access-guard 규칙에 맞춰 바꾼다.
  [/MYDB/i, 'DB 접속 주소가 들어 있음'],
  [/dbhelper/i, '내부 DB 접속 모듈을 부름'],
  [/path.*insert/i, '자격증명 폴더를 import 경로에 추가함'],
  [/dbcreds.*env/i, '자격증명 파일에 직접 접근함'],
  [/__import__|importlib/i, '모듈명을 숨길 수 있는 동적 import'],
  [/exec|eval/i, '문자열을 코드로 실행함'],
  [/_connect/i, 'DB 접속 함수를 직접 호출함'],
];

function explain(matched) {
  if (!matched) return '';
  for (const [re, ko] of REASONS) if (re.test(matched)) return ko;
  // 훅에 새 패턴이 추가되어 매핑이 없는 경우 — 최소한 읽히도록 정규식 기호를 걷어낸다.
  const bare = String(matched).replace(/\\[bsdwn]|[\\^$*+?{}()[\]|]/g, '').trim();
  return bare ? `차단 규칙: ${bare}` : '차단 규칙에 걸림';
}

/**
 * 긴 절대경로를 접어 명령의 요지가 보이게 한다.
 * 임시경로는 디렉터리만 접고 파일명은 남긴다 — 파일명까지 지우면
 * "무엇을 실행했는지" 가 사라져 로그가 쓸모없어진다.
 */
const SHORTEN = [
  [/[A-Za-z]:[\/\\]Users[\/\\][^\/\\]+[\/\\]AppData[\/\\]Local[\/\\]Temp[\/\\]claude[\/\\][^\s"']*[\/\\]/gi, '%임시%/'],
  [/[A-Za-z]:[\/\\]Project[\/\\]([^\/\\]+)[\/\\]/gi, '$1/'],
  [/[A-Za-z]:[\/\\]Users[\/\\][^\/\\]+[\/\\]/gi, '~/'],
];

/** MCP 이벤트의 detail 을 한 줄 요약으로. detail 이 없어도 도구명은 읽기 좋게 다듬는다. */
function describeQuery(tool, d) {
  const name = String(tool || '').replace(/^mcp__/, '').replace(/__/g, ' ');
  if (!d) return name;
  const bits = [];
  if (d.account) bits.push(d.account);
  if (d.rows !== null && d.rows !== undefined) bits.push(d.rows + '행' + (d.truncated ? '+' : ''));
  if (d.masked && d.masked !== '해당 없음') bits.push('마스킹 ' + d.masked);
  return name + (bits.length ? '  [' + bits.join(' · ') + ']' : '');
}

function shorten(cmd) {
  let s = String(cmd || '').trim();
  // `cd "..." && 진짜명령` 은 뒤쪽이 요지다
  const m = s.match(/^cd\s+(?:"[^"]*"|'[^']*'|\S+)\s*&&\s*([\s\S]+)$/);
  if (m) s = m[1];
  for (const [re, to] of SHORTEN) s = s.replace(re, to);
  s = s.replace(/\s+/g, ' ');
  return s.length > 200 ? s.slice(0, 130) + ' … ' + s.slice(-60) : s;
}

/**
 * 감사로그의 ts 는 UTC(ISO 8601) 다. 그대로 잘라 쓰면 KST 기준 9시간이 밀린다.
 * 반드시 Date 로 파싱해 현지시각으로 표시할 것.
 */
function hhmmss(ts) {
  if (!ts) return '--:--:--';
  const d = new Date(ts);
  if (isNaN(d.getTime())) return '--:--:--';
  return d.toLocaleTimeString('ko-KR', {
    hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit',
  });
}

if (typeof module !== 'undefined' && module.exports) {
  module.exports = { explain, shorten, hhmmss, describeQuery, REASONS };
}
