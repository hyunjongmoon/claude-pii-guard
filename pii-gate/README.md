# PII Guard Widget

감사로그를 실시간으로 보여주고, **마스킹되지 않은 DB 데이터가 클로드 서버로 넘어가기 전에** 사용자 확인을 받는 Electron 위젯.

## 무엇을 막고, 무엇은 못 막는가

| 시점 | 훅 이벤트 | 할 수 있는 일 |
| --- | --- | --- |
| 도구 실행 **전** | `PreToolUse` | **진짜로 막는다.** 사용자가 차단하면 도구가 실행되지 않아 결과 자체가 생기지 않는다. |
| 도구 실행 **후** | `PostToolUse` | **막지 못한다.** 결과는 이미 모델 컨텍스트에 들어가 있다. 경보만 띄운다. |

`PostToolUse` 에서 "안 보낸 걸로" 만들 수는 없다. 그래서 사전 게이트가 본체이고,
사후 탐지는 놓친 것을 *보이게* 하는 보조 층이다.

## 구성

```
main.js              Electron 메인 — 창, 게이트 HTTP 서버, 감사로그 tail
preload.js           contextBridge (renderer 는 node 접근 없음)
renderer/            화면 — 색상 분류 목록 + 컨펌 패널
hook/pii-gate-hook.js  훅 본체 (hook/install.js 로 ~/.claude/hooks/ 에 설치)
hook/install.js        설치 — 원본 → 설치본 복사 + 두 사본 해시 비교
hook/test-gate.js      검증 (12 케이스)
hook/test-eventlog.js  감사로그·경보 문구·주민번호 탐지 검증 (23 케이스)
hook/mock-server.js    테스트용 목 게이트 서버
```

## 실행

```powershell
cd <이 저장소>/pii-gate
npm install
npm start
```

위젯이 뜨면 `~/.claude/logs/pii-gate.json` 에 `{port, token}` 을 쓰고, 종료 시 지운다.
훅은 **이 파일의 존재로 위젯 실행 여부를 판단**하므로 수동으로 만들지 말 것.

## 훅 등록

손으로 복사하지 말고 설치 스크립트를 쓴다. 손 복사로 원본과 설치본이 어긋난 적이 있다.

```powershell
node hook\install.js
```

원본·설치본 해시와 설치 전 상태(신규 / 이미 일치 / 어긋나 있었음)를 찍는다. 불일치면 종료코드 1.

처음 등록할 때는 `~/.claude/settings.json` 의 `hooks` 에 아래를 병합한다.
`<HOME>` 은 자기 홈 경로(예: `C:/Users/me`)로 바꾼다. `db-access-guard` 는 Bash 로 DB 에 직접 붙는 것을 막는 별도 훅이라, 없으면 그 항목은 뺀다.

```json
"PreToolUse": [
  { "matcher": "Bash",
    "hooks": [{ "type": "command",
      "command": "node \"<HOME>/.claude/hooks/db-access-guard.js\"",
      "timeout": 10 }] },
  { "matcher": "mcp__.*",
    "hooks": [{ "type": "command",
      "command": "node \"<HOME>/.claude/hooks/pii-gate-hook.js\"",
      "timeout": 120, "statusMessage": "PII 게이트 확인 대기" }] }
],
"PostToolUse": [
  { "matcher": "Bash|Read|mcp__.*",
    "hooks": [{ "type": "command",
      "command": "node \"<HOME>/.claude/hooks/pii-gate-hook.js\"",
      "timeout": 10 }] }
]
```

`PreToolUse` 타임아웃(120s)은 훅 내부 타임아웃(90s)보다 길어야 한다.
훅이 먼저 시간초과되어 **스스로 deny** 를 반환하게 하기 위한 순서다.

## fail-closed

위젯이 떠 있지 않으면 게이트 대상 도구는 **차단**된다. 위젯을 끄는 것만으로
게이트를 무력화할 수 있으면 게이트가 아니기 때문이다. 대상 도구를 쓰려면
위젯을 먼저 띄워야 한다.

## 감사로그

`~/.claude/logs/pii-gate-events.log` (JSON Lines). 훅이 **위젯보다 먼저** 파일에 쓴다.
위젯은 기록 저장소가 아니라 뷰어다 — 위젯이 꺼져 있어도 기록은 남는다.

```json
{"ts":"…","sessionId":"…","tool":"mcp__idea__execute_sql_query","decision":"block","categories":{},"reason":"widget-down"}
```

| decision | 언제 | reason |
| --- | --- | --- |
| `block` | 게이트 대상 도구 차단 | `widget-down` · `no-response` · `user-deny` · `timeout` · `internal-error` |
| `pass` | 게이트 대상 도구를 사용자가 허용 | — |
| `detect` | 결과에서 마스킹 안 된 PII 탐지 (사후) | — |

`categories` 는 종류별 건수만 담는다 (`{"주민등록번호":2}`). 형식은 `sensitive-prompt-scan.log` 와 같다.
게이트 밖 도구의 통과와 PII 없는 결과는 기록하지 않는다 — 마스킹 MCP 조회는 그 서버의 자체 로그가,
Bash 는 `bash-audit.log` 가 이미 남긴다.

모델에게 주는 경보 문구는 실제 결과만 말한다: `pii-gate-events.log 에 기록됨` 또는
`기록 실패: …(오류코드)`, 그 뒤에 `+ 위젯 표시` / `(위젯 미표시)`.

### Claude Code 화면 표시 (`claude-mod/`)

감사로그를 Claude Code 안에서 보여주는 모드(플러그인 `pii-gate-view`). 읽기만 한다 — 실행 전 확인창은 여전히 위젯 몫.

외부 라이브러리 없이 글자 단위 트루컬러(네온 시안→바이올렛)로 그린다.

- 하단 칩(프롬프트 아래 오른쪽): `◈ PII SHIELD │ 차단 · 탐지 · 허용` — 정지 화면(맥박 없음).
  5초 안에 칩이 한 번도 안 그려지는 화면이면 상태줄로 대신한다
- 경보 카드(프롬프트 위) + 토스트: 이 세션에 새 차단·탐지가 오면 라벨이 해독되듯 맞춰지고
  빛줄기가 한 번 훑은 뒤(1.2초, 25fps) 멈춘다. 「확인」까지 남는다
- `/pii`: 텔레메트리 패널 — 판정 타일 3개, 시간대별 스파크라인, 타임라인(다른 세션은 흐리게)

설치(사용자 범위, 모든 세션). 이 폴더 자체가 마켓플레이스라 설치 후에도 이 폴더를 읽는다 —
고친 뒤 `/reload-plugins` 또는 새 세션이면 반영된다.

```powershell
claude plugin marketplace add "<이 저장소>/pii-gate/claude-mod"
claude plugin install pii-gate-view@pii-gate-local --scope user
```

검증: `claude plugin validate claude-mod` · `claude plugin test claude-mod`

## 게이트 대상

DB 에서 실데이터를 끌어오는 MCP 도구 (`pii-gate-hook.js` 의 `GATED_TOOLS`):

- `mcp__*__execute_sql_query`, `fetch_query_result`, `preview_table_data`, `list_recent_sql_queries`
- 이름에 `db` 가 든 MCP 서버의 도구 (스키마 조회 계열은 제외)

`mcp__masked-db__*`(자기 환경의 마스킹 보장 MCP 서버 이름으로 바꿀 것)는 마스킹이 보장된 경로로 보고 확인 없이 통과시킨다 (`TRUSTED_TOOLS`).
Bash 를 통한 직접 접속은 이 훅이 아니라 별도 훅(`db-access-guard.js` 같은 것)의 몫이다.

## 값 비노출 원칙

위젯에도, 감사로그에도, 모델에게 주는 경보에도 **PII 값 자체는 싣지 않는다.**
필드 종류·건수·자릿수만 전달한다. 유출을 감시하려고 화면에 유출하면 자기모순이다.
게이트 패널에 표시되는 명령문도 `redact()` 를 거쳐 PII 가 지워진 상태로 온다.

## 색상

| 색 | 의미 |
| --- | --- |
| 초록 | 마스킹 확인됨 |
| 빨강(진함) | 마스킹 안 된 PII 가 결과에 포함됨 — 이미 전송된 뒤 |
| 빨강 | 차단됨 |
| 주황 | 확인 대기 / 사용자 허용 |
| 회색 | 일반 명령 |

## 검증

```powershell
node hook\test-gate.js
node hook\test-eventlog.js
```

test-gate 12 케이스: fail-closed, 사용자 허용/차단, 게이트 제외 대상, PII 값 비노출, 사후 탐지.
test-eventlog 23 케이스: 위젯 꺼짐 상태 파일 기록, 경보 문구(기록 성공·실패, 위젯 표시 여부),
주민번호 공백 구분·외국인등록번호(뒷자리 5~8) 탐지.
훅을 부르는 테스트는 전부 임시 홈(`USERPROFILE`/`HOME`)에서 돌아 실제 `~/.claude/logs` 를 건드리지 않는다.
목 서버는 **별도 프로세스**여야 한다 — 테스트가 `execFileSync` 로 훅을 부르는 동안
이벤트 루프가 막혀 같은 프로세스의 서버는 응답하지 못한다.

## 한계

- 사후 탐지는 되돌리지 못한다 (위 표 참조).
- 정규식 기반 PII 탐지라 형식이 다른 데이터는 놓친다.
- 같은 OS 계정에서 도는 다른 프로세스는 게이트 서버에 직접 요청할 수 있다.
  토큰은 우발적 접근만 막는다.
