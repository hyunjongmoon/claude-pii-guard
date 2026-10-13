'use strict';
/**
 * requested.js — 탐지가 "그 종류를 요청한 조회"에서 나왔는지 판정한다. 분석기·대시보드가 같이 쓴다.
 *
 * 감사로그의 source(훅이 남긴 출처: SQL 은 리터럴을 ? 로 바꾼 것)를 보고, 탐지된 종류마다
 * 그 종류의 컬럼 이름이 조회에 들어 있는지 본다. 이름으로 추정하는 것이라 증명은 아니다 —
 * 그래서 판정과 함께 출처를 보여 사람이 확인할 수 있게 한다.
 *
 *   requested      탐지된 종류를 모두 컬럼으로 지정한 조회        → 요청한 것
 *   not-requested  지정하지 않은 종류가 탐지됨(SQL)              → 오탐 가능성, 검토 대상
 *   unknown        SELECT * · 파일 읽기 · 명령 출력 등           → 출처를 보고 판단
 *   no-source      출처 기록 기능 이전의 기록
 * 탐지된 종류가 없는 기록(게이트의 차단·허용 — 실행 전 판정)은 "이 조회가 어떤 개인정보 컬럼을
 * 달라고 했나"를 본다: 하나라도 지정했으면 requested, 없으면 no-pii-columns.
 */

// 종류별 컬럼 이름 단서 — 흔한 약어, 공공 표준 용어(IHIDNUM·MBTLNUM·ACNUT_NO), 한글.
// "번호" 컬럼만 노린다: PHONE\w* 처럼 넓히면 PHONETIC, CARD_TYPE 같은 엉뚱한 컬럼이 요청으로 잡힌다.
// 자기 스키마의 이름을 더해 쓴다.
const KEYWORDS = {
  주민등록번호: /\b(?:RRN|SSN|JUMIN\w*|RES(?:ID)?_?NO|IHIDNUM)\b|주민/i,
  계좌번호: /\b(?:ACC(?:T|OUNT)?_?(?:NO|NUM(?:BER)?)|ACCNO|ACNUT_?NO|BANK_?ACC(?:T|OUNT)?(?:_?NO)?)\b|계좌/i,
  이메일: /\bE_?MAIL\w*\b|메일/i,
  휴대전화: /\b(?:TEL_?NO|PHONE(?:_?(?:NO|NUM(?:BER)?))?|MOBILE(?:_?NO)?|CELL_?(?:PHONE|NO)|HP_?NO|MBTL_?NUM|MBL_?NO)\b|전화|휴대/i,
  카드번호: /\b(?:CARD_?(?:NO|NUM(?:BER)?)|CRD_?NO)\b|카드/i,
};

const LABEL = {
  requested: '요청함',
  'not-requested': '요청 안 함 — 오탐 가능성',
  unknown: '판단 불가 — 출처 확인',
  'no-source': '근거 없음(출처 기록 이전)',
  'no-pii-columns': '개인정보 컬럼 지정 없음',
};

/** @returns {{ verdict: string, label: string, cats: Array<{cat: string, requested: boolean|null}> }} */
function classify(entry) {
  const cats = Object.keys((entry && entry.categories) || {});
  const src = entry && entry.source;
  const out = (verdict, perCat) => ({ verdict, label: LABEL[verdict], cats: perCat });
  if (!src || !src.text) return out('no-source', cats.map((cat) => ({ cat, requested: null })));

  const named = (cat) => (KEYWORDS[cat] ? KEYWORDS[cat].test(src.text) : false);
  // 컬럼을 이름으로 고르지 않은 조회·명령·파일은 "안 했다"고 말할 수 없다
  const star = src.kind === 'sql' && /\bselect\s+(?:distinct\s+)?(?:\w+\.)?\*/i.test(src.text);
  const undecidable = src.kind !== 'sql' || star;

  if (cats.length === 0) {
    const asked = Object.keys(KEYWORDS).filter(named).map((cat) => ({ cat, requested: true }));
    if (asked.length) return out('requested', asked);
    return out(undecidable ? 'unknown' : 'no-pii-columns', []);
  }

  const perCat = cats.map((cat) => ({ cat, requested: named(cat) }));
  if (perCat.every((c) => c.requested)) return out('requested', perCat);
  if (undecidable) return out('unknown', perCat.map((c) => (c.requested ? c : { ...c, requested: null })));
  return out('not-requested', perCat);
}

module.exports = { classify, KEYWORDS, LABEL };
