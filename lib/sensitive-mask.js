/**
 * 민감정보 마스킹 모듈
 *
 * - Stable pseudonymization: 동일 값은 항상 동일 placeholder로 치환
 *   (예: 같은 행에서 "홍길동"이 여러 번 등장해도 모두 [학생_1])
 * - 카테고리별 prefix: [학생_N], [학번_N], [PHONE_N], [EMAIL_N], [ADDR_N], [RRN_N], [ACCT_N]
 * - 매핑은 createMasker() 호출 단위로 fresh (스크립트 1회 실행 = 1 세션)
 *
 * 비활성화: SENSITIVE_MASK=0 또는 SENSITIVE_MASK=false 환경변수
 *           또는 createMasker({ enabled: false })
 */

// 컬럼명 → 마스킹 규칙 (정규식 매칭)
// 위에서부터 순서대로 검사, 첫 매치 적용
//
// 매칭 정책:
//   - 부분 매치 허용 (예: "지도교수성명"도 성명류로 매칭)
//   - 단, "*ID" 접미사 (신분ID, 학생ID 등 DB 내부 FK)는 별도 정규식에서 명시적 제외
const COLUMN_RULES = [
  // === 최고 민감도 (식별 즉시 마스킹) ===
  { match: /주민(등록)?번호|^RRN$|resident.?registration/i, category: 'RRN', label: '주민번호' },
  { match: /식별번호$/i, category: 'RRN', label: '주민번호' },  // 학적뷰의 식별번호 = 주민번호
  { match: /외국인등록번호|foreigner.?registration/i, category: 'FRN', label: '외국인등록번호' },
  { match: /비밀번호|^password$|^pwd$|^pw$/i, category: 'PWD', label: '비밀번호' },
  { match: /계좌번호|account.?number/i, category: 'ACCT', label: '계좌번호' },
  { match: /^예금주|account.?holder/i, category: 'PERSON', label: '학생' },

  // === 이름 (성명 포함 컬럼 + 영문/한문 변형) ===
  { match: /성명|^이름$|name$|^대표자명$/i, category: 'PERSON', label: '학생' },

  // === 연락처 ===
  { match: /휴대(폰|전화)|핸드폰|^HP$|^모바일$|mobile|cell.?phone/i, category: 'PHONE', label: 'PHONE' },
  { match: /연락처|전화번호|^TEL$|^전화$|telephone/i, category: 'PHONE', label: 'PHONE' },
  { match: /비상연락망/i, category: 'PHONE', label: 'PHONE' },

  // === 이메일 ===
  { match: /이메일|^E.?MAIL$|메일주소|email/i, category: 'EMAIL', label: 'EMAIL' },

  // === 주소 ===
  { match: /^주소[0-9]*$|거주지|^현주소|^본적|address/i, category: 'ADDR', label: 'ADDR' },
  { match: /^우편번호$|^우편$|postal.?code|zip.?code/i, category: 'ZIP', label: 'ZIP' },

  // === 생년월일 ===
  { match: /생년월일|^생일$|birth.?date|date.?of.?birth|birthday/i, category: 'BIRTH', label: 'BIRTH' },

  // === 학번 (사용자에게 노출된 식별번호) ===
  // 주의: "*ID" 접미사 (신분ID, 학생ID 등 DB 내부 FK)는 마스킹 제외
  { match: /^학번$|^학생번호$|^신분번호$|student.?number/i, category: 'STUDENT_NUM', label: '학번' },
  { match: /^사번$|^직번$|employee.?number/i, category: 'EMP_NUM', label: '사번' },

  // === 사진 ===
  { match: /^사진(ID|파일|경로)?$|^photo|^picture/i, category: 'PHOTO', label: 'PHOTO' },
];

/**
 * 컬럼명에 매칭되는 마스킹 규칙 반환 (없으면 null)
 */
function getRuleForColumn(columnName) {
  if (columnName == null) return null;
  for (const rule of COLUMN_RULES) {
    if (rule.match.test(columnName)) return rule;
  }
  return null;
}

/**
 * 환경변수로 마스킹 활성화 여부 판단
 */
function isMaskingEnabledByEnv() {
  const v = process.env.SENSITIVE_MASK;
  if (v === undefined || v === null || v === '') return true;
  const lower = String(v).toLowerCase();
  return lower !== '0' && lower !== 'false' && lower !== 'off' && lower !== 'no';
}

/**
 * 마스커 생성. 한 번 만들면 같은 값은 같은 placeholder를 받음.
 * @param {object} opts
 * @param {boolean} [opts.enabled] - 명시적으로 on/off 지정 (생략 시 환경변수 기준)
 * @returns {object} masker
 */
function createMasker(opts = {}) {
  const enabled = opts.enabled !== undefined ? !!opts.enabled : isMaskingEnabledByEnv();

  // category → Map(rawValue → placeholder)
  const maps = {};
  // category → 카운터
  const counters = {};

  function maskOneValue(value, rule) {
    if (value === null || value === undefined) return value;
    const strValue = String(value);
    if (strValue === '' || strValue === 'NULL') return value;

    if (!maps[rule.category]) {
      maps[rule.category] = new Map();
      counters[rule.category] = 0;
    }
    const map = maps[rule.category];
    if (map.has(strValue)) return map.get(strValue);

    counters[rule.category] += 1;
    const placeholder = `[${rule.label}_${counters[rule.category]}]`;
    map.set(strValue, placeholder);
    return placeholder;
  }

  /**
   * recordset(배열-of-object)을 마스킹된 복사본으로 반환
   * 원본 배열/객체는 변경하지 않음
   */
  function maskRecordset(recordset) {
    if (!enabled || !Array.isArray(recordset) || recordset.length === 0) return recordset;

    const columns = Object.keys(recordset[0]);
    const columnRules = {};
    for (const col of columns) {
      columnRules[col] = getRuleForColumn(col);
    }

    // 마스킹할 컬럼이 하나도 없으면 원본 그대로 반환
    const anyMasked = Object.values(columnRules).some(r => r !== null);
    if (!anyMasked) return recordset;

    return recordset.map(row => {
      const newRow = {};
      for (const col of columns) {
        const rule = columnRules[col];
        newRow[col] = rule ? maskOneValue(row[col], rule) : row[col];
      }
      return newRow;
    });
  }

  /**
   * 매핑 요약 문자열 반환 (사용자 콘솔용 footer)
   * Claude/AI 에게는 전달하지 말 것 — 사용자 본인만 참고
   */
  function getMappingSummary() {
    if (!enabled) return '';
    const sections = [];
    for (const [category, map] of Object.entries(maps)) {
      if (map.size === 0) continue;
      sections.push(`  · ${category}: ${map.size}건`);
    }
    if (sections.length === 0) return '';
    return [
      '',
      '─── 마스킹 적용 (사용자 전용, AI에 붙여넣지 말 것) ───',
      ...sections,
      '─────────────────────────────────────────────────────',
    ].join('\n');
  }

  /**
   * 실제로 마스킹이 일어났는지 여부
   */
  function hasMasked() {
    return enabled && Object.keys(maps).some(k => maps[k].size > 0);
  }

  /**
   * 마스킹된 컬럼 카테고리 목록 반환
   */
  function getCategories() {
    if (!enabled) return [];
    return Object.entries(maps)
      .filter(([, map]) => map.size > 0)
      .map(([category]) => category);
  }

  return {
    get enabled() { return enabled; },
    maskRecordset,
    getMappingSummary,
    hasMasked,
    getCategories,
  };
}

module.exports = {
  createMasker,
  getRuleForColumn,
  isMaskingEnabledByEnv,
  COLUMN_RULES,
};
