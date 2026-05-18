/**
 * 테이블 출력 포맷 공통 모듈
 *
 * 민감정보 마스킹 옵션 통합:
 *   formatTable(recordset, maxWidth, { masker })
 *   - masker 가 주어지면 결과셋을 마스킹한 뒤 포맷
 *   - masker 가 없거나 비활성이면 원본 그대로
 */

/**
 * recordset을 테이블 형식 문자열로 변환
 * @param {Array} recordset - 쿼리 결과 배열
 * @param {number} [maxWidth=40] - 컬럼 최대 너비
 * @param {object} [opts]
 * @param {object} [opts.masker] - createMasker()로 만든 마스커 인스턴스
 * @returns {string}
 */
function formatTable(recordset, maxWidth = 40, opts = {}) {
  if (!recordset || recordset.length === 0) {
    return '(결과 없음)';
  }

  // 마스킹 적용
  const masker = opts && opts.masker;
  const data = masker && masker.enabled
    ? masker.maskRecordset(recordset)
    : recordset;

  const columns = Object.keys(data[0]);

  const widths = {};
  for (const col of columns) {
    widths[col] = col.length;
    for (const row of data) {
      const val = row[col] === null ? 'NULL' : String(row[col]);
      widths[col] = Math.max(widths[col], val.length);
    }
    widths[col] = Math.min(widths[col], maxWidth);
  }

  let output = '';
  const headerLine = columns.map(col => col.padEnd(widths[col])).join(' | ');
  const separator = columns.map(col => '-'.repeat(widths[col])).join('-+-');

  output += headerLine + '\n';
  output += separator + '\n';

  for (const row of data) {
    const line = columns.map(col => {
      let val = row[col] === null ? 'NULL' : String(row[col]);
      if (val.length > maxWidth) val = val.substring(0, maxWidth - 3) + '...';
      return val.padEnd(widths[col]);
    }).join(' | ');
    output += line + '\n';
  }

  output += `\n(${data.length}개 행)`;
  return output;
}

module.exports = { formatTable };
