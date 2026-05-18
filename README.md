# claude-pii-guard — PII Egress Defense for Claude Code

도메인 무관하게 재사용 가능한 PII 외부 송출 방어 도구. Claude Code 와 Node.js DB 유틸리티에서
민감정보가 콘솔·프롬프트로 새어 나가는 것을 2단 방어선으로 차단한다.

## 구성

```
claude-pii-guard/
├── hooks/
│   └── sensitive-prompt-scan.js     ← Claude Code UserPromptSubmit 훅
├── lib/
│   ├── sensitive-mask.js            ← 컬럼 기반 마스킹 모듈 (Node.js)
│   └── format.js                    ← 테이블 출력 포맷터 (마스킹 통합됨)
├── analysis/
│   └── analyze_pii_log.js           ← 훅 로그 운영 통계 분석기
└── settings.json.template           ← Claude Code 훅 등록 템플릿
```

## 작동 원리 (2단 방어선)

| 단계 | 위치 | 시점 | 차단 대상 |
|------|------|------|----------|
| 1단 | `lib/sensitive-mask.js` + `format.js` | DB 도구가 콘솔 출력 직전 | 컬럼명 매칭 (성명·휴대폰·주민번호·계좌 등 14종) |
| 2단 | `hooks/sensitive-prompt-scan.js` | 사용자가 Claude Code에 프롬프트 제출 직전 | 값 패턴 + 라벨 prefix |

두 단계는 독립적으로 동작하므로 한쪽만 설치해도 된다.

## 설치 (신규 PC)

### 1단 (DB 도구에 통합)
`lib/sensitive-mask.js` 와 `format.js` 를 본인 DB 유틸 폴더의 `lib/` 디렉토리에 복사. 도구 스크립트에서:

```js
const { createMasker } = require('./lib/sensitive-mask');
const { formatTable } = require('./lib/format');

const masker = createMasker();  // SENSITIVE_MASK=0 또는 인자로 끄기
console.log(formatTable(recordset, 40, { masker }));
if (masker.hasMasked()) console.log(masker.getMappingSummary());
```

### 2단 (UserPromptSubmit 훅)

1. `hooks/sensitive-prompt-scan.js` 를 `~/.claude/hooks/` 로 복사
2. `settings.json.template` 의 `hooks` 섹션을 `~/.claude/settings.json` 에 머지
3. `{{USER_HOME}}` 플레이스홀더를 실제 경로로 치환 (Windows: `C:/Users/<id>`)
4. Claude Code 재시작 후 민감정보 포함 프롬프트로 검증

```powershell
# 검증
$payload = @{ prompt='학번:20231234 성명:홍길동 010-1234-5678 hong@test.com' } | ConvertTo-Json -Compress
$payload | node "$env:USERPROFILE\.claude\hooks\sensitive-prompt-scan.js"
echo "exit code: $LASTEXITCODE (2 = 차단 성공)"
Get-Clipboard  # 마스킹된 버전이 들어있어야 함
```

## 우회

| 방법 | 효과 |
|------|------|
| 프롬프트에 `--allow-pii` 토큰 포함 | 일회성, 로그 남음 |
| `$env:SENSITIVE_PROMPT_BYPASS=1` | 세션 전체 우회, 로그 남음 |
| `~/.claude/settings.json` hooks 제거 | 영구 비활성 |

## 마스킹 대상/제외

**대상**: 주민(등록)번호, 식별번호, 계좌번호, 예금주, 성명류, 휴대폰/전화/연락처, 이메일, 주소·거주지, 생년월일, 학번/사번, 사진(ID)
**제외 (의도적)**: `*ID` 접미사 DB 내부 FK — 후속 쿼리 작성 가능하도록

## 새 컬럼 패턴 추가

`sensitive-mask.js` 의 `COLUMN_RULES` 배열 또는 `sensitive-prompt-scan.js` 의 `VALUE_PATTERNS`/`LABEL_PATTERNS` 에 정규식 추가. **single source of truth는 코드 자체** — 별도 doc로 빼서 drift 만들지 말 것.

## 의존성

- Node.js 18+ (Windows / macOS / Linux)
- PowerShell 5+ (Windows 클립보드 복사용; 다른 OS는 `setClipboard` 함수 교체 필요)

## 로그

`~/.claude/logs/sensitive-prompt-scan.log` — JSON Lines. 차단·우회·에러 모두 기록.

Entry 케이스 3종:
```jsonc
// 차단: 마스킹 적용 후 사용자에게 클립보드 복사 메시지
{ "ts": "2026-05-15T...", "sessionId": "...", "originalLen": 104, "maskedLen": 85,
  "replacements": 4, "categories": { "RRN": 1, "PHONE": 1, "EMAIL": 1, "STUDENT_NUM": 1 } }

// 우회: --allow-pii 토큰 또는 SENSITIVE_PROMPT_BYPASS 환경변수
{ "ts": "...", "sessionId": "...", "bypassed": true, "via": "token" | "env" }

// 에러: 마스킹 로직 자체 실패 (안전한 fallback 처리)
{ "ts": "...", "sessionId": "...", "error": "mask-apply-failed", "message": "..." }
```

## 운영 통계 분석

`analysis/analyze_pii_log.js` — 위 로그를 분석해서 카테고리별 차단 빈도·우회 비율·일별 추이 출력.

```bash
# 본인 PC에서 (Node.js 만 있으면 됨, 외부 의존성 0)
node analysis/analyze_pii_log.js              # 전체 기간, text 출력
node analysis/analyze_pii_log.js 30           # 최근 30일
node analysis/analyze_pii_log.js 30 markdown  # THREAT_MODEL.md 부록 B 용
node analysis/analyze_pii_log.js all markdown # 전체 기간 + 마크다운
```

**출력 항목**: 기간/세션 수 / 이벤트 요약(차단·우회·에러) / 카테고리별 차단 빈도 + 비율 / Bypass 분포 + 비율 / 일별 추이(최근 14일)

**활용 패턴**:
- 주간 모니터링: `node analysis/analyze_pii_log.js 7 markdown > weekly_report.md`
- 보안 문서 부록: `node analysis/analyze_pii_log.js 30 markdown` → 출력 그대로 위협 모델 문서의 운영 통계 자리에 붙이기
- 정책 튜닝 신호: 우회 비율 15%+ 면 정규식 false positive 조정 검토
