# claude-pii-guard — PII Egress Defense for Claude Code

도메인 무관하게 재사용 가능한 PII 외부 송출 방어 도구. Claude Code 와 Node.js DB 유틸리티에서
민감정보가 콘솔·프롬프트·도구 호출로 새어 나가는 것을 단계별 방어선으로 차단한다.

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
├── pii-gate/                        ← MCP 도구 호출 게이트 + 감사로그 + 위젯·HUD (pii-gate/README.md)
└── settings.json.template           ← Claude Code 훅 등록 템플릿
```

## 작동 원리 (단계별 방어선)

| 단계 | 위치 | 시점 | 차단 대상 |
|------|------|------|----------|
| 1단 | `lib/sensitive-mask.js` + `format.js` | DB 도구가 콘솔 출력 직전 | 컬럼명 매칭 (성명·휴대폰·주민번호·계좌 등 14종) |
| 2단 | `hooks/sensitive-prompt-scan.js` | 사용자가 Claude Code에 프롬프트 제출 직전 | 값 패턴 + 라벨 prefix |
| 3단 | `pii-gate/hook/pii-gate-hook.js` | Claude 가 MCP DB 조회 도구를 실행하기 직전 | 도구 호출 자체 — 위젯에서 사용자가 허용하지 않으면 차단 (fail-closed) |
| 사후 | `pii-gate/hook/pii-gate-hook.js` | 도구 실행 직후 | 결과의 PII 탐지 → 경보·감사로그 (이미 넘어간 뒤라 되돌리지는 못함) |

각 단계는 독립적으로 동작하므로 일부만 설치해도 된다. 3단·사후는 [`pii-gate/README.md`](pii-gate/README.md) 참고.

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
node analysis/analyze_pii_log.js 30 markdown  # 최근 30일, markdown 출력
node analysis/analyze_pii_log.js all markdown # 전체 기간 + 마크다운
node analysis/analyze_pii_log.js 30 --log gate  # pii-gate 감사로그(~/.claude/logs/pii-gate-events.log)
node analysis/analyze_pii_log.js --log <경로>   # 다른 로그 파일
node analysis/analyze_pii_log.js --no-exclude   # 검토 제외 목록을 적용하지 않은 원래 숫자
node analysis/test-analyze.js                 # 분석기 검증 (임시 폴더에서만 돎)
```

**출력 항목**: 기간/세션 수 / 이벤트 요약(차단·우회·에러) / 카테고리별 차단 빈도 + 비율 / Bypass 분포 + 비율 / 일별 추이(최근 14일)

실측 예시 출력은 [`docs/operational-stats.md`](docs/operational-stats.md) 참고.

**활용 패턴**:
- 주간 모니터링: `node analysis/analyze_pii_log.js 7 markdown > weekly_report.md`
- 보안 문서 부록: `node analysis/analyze_pii_log.js 30 markdown` → 출력 그대로 위협 모델 문서의 운영 통계 자리에 붙이기
- 정책 튜닝 신호: 우회 비율 15%+ 면 정규식 false positive 조정 검토

`pii-gate/` 의 감사로그는 형식이 다르다(`replacements` 대신 `decision`). `--log gate` 로 넣으면
게이트 차단(사유별 — `no-response`·`timeout` 은 「응답 없음」으로 합산)·허용·실행 후 탐지(카테고리별)를 따로 센다.
어느 형식에도 맞지 않는 줄은 버리지 않고 **분류 불가**로 센다 — 형식이 바뀌어 0건이 정상처럼 보이는 일을 막기 위해서다.
예전 형식 로그의 출력은 바뀌지 않는다.

**검토 제외** — 검토해서 오탐·테스트 값으로 판정한 기록은 감사로그를 고치지 않고(사후에 지운 감사로그는 감사로그가 아니다)
옆 파일 `<로그>.exclude.jsonl` 에 한 줄씩 적는다. 분석기는 그 기록을 빼고 세고, 뺀 건수를 사유별로 늘 보인다.

```jsonc
{ "ts": "<감사로그의 ts>", "sessionId": "...", "tool": "Bash", "decision": "detect",
  "reason": "false-positive" | "test-value" | "masked-output", "note": "판정 근거" }
```

키는 `ts`·`sessionId`·`tool`·`decision` 네 개다. 제외 목록에만 있고 로그에 없는 항목은 「제외 불일치」로 따로 보인다.

**출처와 요청 여부** — 게이트 훅은 기록마다 `source`(이 판정을 낳은 조회·명령·파일)를 남긴다. SQL 은 문자열·숫자
리터럴을 `?` 로 바꾸고, 명령은 PII 모양과 비밀값을 가린다. `analysis/requested.js` 가 이걸 보고 판정한다:
탐지된 종류를 SQL 이 컬럼으로 지정했으면 **요청함**, 지정하지 않았으면 **요청 안 함(오탐 가능성)**,
`SELECT *`·명령·파일이면 **판단 불가**. `--detail` 로 기록별로 본다.

```bash
node analysis/analyze_pii_log.js --log gate --detail
```

출처 기록 기능 이전의 기록은 세션 기록에서 찾은 출처를 옆 파일 `<로그>.backfill.jsonl` 에 옮겨 두면
**사후 복원** 표시를 달고 같이 판정한다(원본 감사로그는 그대로). Claude Code 세션 기록은 보관 기간이 지나면
지워지므로, 근거가 필요한 기록은 그 전에 옮겨 둔다.

## 현황 대시보드 (보여주기용 HTML 한 장)

전산 담당·관리자에게 보여주는 용도. 두 로그와 훅 등록 상태를 읽어 혼자 열리는 HTML 한 장을 만든다
(외부 파일·네트워크 없음 — 메일 첨부·USB 로 그대로 넘긴다).

```bash
node analysis/dashboard.js --out pii-dashboard.html
node analysis/test-dashboard.js        # 검증 (임시 폴더에서만 돎)
```

- **지금 상태** — 보호 장치별 켜짐/꺼짐(✓·✕ + 쉬운 설명), 설치 시각, 마지막 기록 시각
- **기간별 숫자** — 오늘 · 7일 · 30일 · 전체: 막음 · 확인 후 허용 · 실행 후 탐지 · 검토 제외, 추이 막대(숫자로 보기 표 포함)
- **어떤 개인정보가 걸렸나 · 최근 기록** — 검토 제외 기록도 숨기지 않고 흐리게 표시
- **싣지 않는 것** — 개인정보 값, 세션 ID, 명령·SQL 원문, 설정 파일 내용 (테스트로 고정)
