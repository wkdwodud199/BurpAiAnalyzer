# AI Security Analyzer - 파일별 기능 명세

## 프로젝트 구조

```
BurpAIAnalyzer/
├── server/                         # Flask 미들웨어 서버 (Python 3)
│   ├── config.py                   # 설정 파일ㅋ
│   ├── server.py                   # REST API 서버
│   ├── providers.py                # AI Provider 추상화
│   ├── prompts.py                  # AI 시스템 프롬프트
│   ├── oauth.py                    # Anthropic OAuth 2.0 PKCE
│   └── requirements.txt            # 패키지 의존성
│
├── extension/                      # Burp Suite Extension (Jython 2.7)
│   ├── ai_security_analyzer.py     # 메인 엔트리포인트
│   ├── models.py                   # 데이터 모델
│   ├── ui_components.py            # 공통 UI 컴포넌트
│   ├── table_models.py             # JTable 모델
│   ├── scanner_panel.py            # Scanner 탭
│   ├── cve_panel.py                # CVE Analyzer 탭
│   └── critical_panel.py           # Critical Analyzer 탭
│
├── README.md                       # 설치/사용법
└── FUNCREADME.md                   # 이 파일
```

---

## Server 파일

### `server/config.py` (37줄)

중앙 설정 파일. 인증 방식, API Key, 모델, 컴포넌트별 기본값 정의.

| 변수 | 설명 |
|------|------|
| `AUTH_METHOD` | Provider별 인증 방식 (`"oauth"` 또는 `"api_key"`) |
| `API_KEYS` | Provider별 API Key (OAuth 사용 시 비워둠) |
| `MODELS` | Provider별 기본 모델명 |
| `COMPONENT_DEFAULTS` | 컴포넌트별 기본 provider/model (scanner, cve_analysis, cve_verify, critical_analysis, critical_chat_claude, critical_chat_codex + legacy aliases) |

의존성: 없음 (순수 설정 파일)

---

### `server/server.py` (~930줄)

Flask 기반 REST API 미들웨어 서버. Extension과 AI API 사이의 브릿지 역할.
Tool Execution Layer를 포함하여 AI가 요청한 HTTP 테스트를 실제로 실행합니다.

**주요 함수:**

| 함수 | 설명 |
|------|------|
| `generate_session_id(lane)` | 충돌 방지 세션 ID 생성 (`{lane}_{ts}_{uuid8}` 형식) |
| `get_or_create_provider(component)` | 컴포넌트별 AI provider 인스턴스 생성/캐시 |
| `get_conversation(session_id)` | 세션별 대화 히스토리 조회/생성 |
| `add_to_conversation(session_id, role, content)` | 메시지 추가 (슬라이딩 윈도우) |
| `do_chat(component, system_prompt, user_prompt, ...)` | AI provider로 채팅 실행 |
| `_extract_domains_from_items(items)` | HTTP items에서 host:port 추출 (도메인 화이트리스트 생성) |
| `_execute_tool_requests(session_id, tool_requests)` | AI 요청 HTTP 테스트 실행 (안전 제어 포함) |
| `_format_tool_results_for_ai(results, warnings)` | 실행 결과를 AI 분석용 텍스트로 포매팅 |

**REST 엔드포인트:**

| Method | Path | 설명 |
|--------|------|------|
| GET | `/health` | 서버 상태 + OAuth 인증 상태 |
| POST | `/config/<component>` | Provider/Model 설정 변경 |
| GET | `/config/<component>` | 현재 설정 조회 |
| POST | `/analyze/versions` | 소프트웨어 버전 노출 분석 |
| POST | `/analyze/weaknesses` | 보안 약점 분석 |
| POST | `/analyze/cve` | CVE 분석 + PoC 생성 |
| POST | `/analyze/response-check` | PoC 실행 결과 검증 |
| POST | `/analyze/critical/start` | Critical 분석 세션 시작 (도메인 화이트리스트 + tool 카운터 초기화) |
| POST | `/analyze/critical/continue` | Critical 분석 반복 (tool_requests 감지 시 실제 HTTP 실행 + 결과 AI 피드백 루프) |
| POST | `/analyze/critical/chat` | Critical 분석 중 채팅 - 단일 lane (max_tokens: 16384) |
| POST | `/analyze/critical/chat/multi` | 멀티 AI 채팅 - Claude/Codex/Both 모드 |
| GET | `/auth/login` | OAuth 로그인 페이지 (HTML) |
| POST | `/auth/complete` | OAuth 코드 → 토큰 교환 |
| GET | `/auth/status` | OAuth 인증 상태 확인 |
| POST | `/auth/logout` | OAuth 토큰 삭제 |
| GET | `/vulnerability-types` | 취약점 유형 목록 |
| GET/DELETE | `/sessions/<session_id>` | 세션 히스토리 조회/삭제 (tool 상태도 정리) |
| GET | `/config/available` | 유효한 Provider 목록 |
| GET | `/logs/recent` | 최근 API 호출 로그 |

**주요 상태 변수:**

| 변수 | 설명 |
|------|------|
| `provider_configs` | 컴포넌트별 런타임 provider 설정 |
| `providers` | 캐시된 provider 인스턴스 |
| `_provider_cache_keys` | 설정 변경 감지용 캐시 키 |
| `conversations` | session_id별 대화 히스토리 |
| `_session_allowed_domains` | 세션별 도메인 화이트리스트 (host:port set) |
| `_session_tool_counters` | 세션별 tool 실행 카운터 |

**Tool Execution 상수:**

| 상수 | 값 | 설명 |
|------|-----|------|
| `TOOL_MAX_REQUESTS_PER_ROUND` | 10 | 라운드당 최대 HTTP 요청 수 |
| `TOOL_MAX_REQUESTS_PER_SESSION` | 50 | 세션당 총 최대 HTTP 요청 수 |
| `TOOL_REQUEST_TIMEOUT` | 10초 | 개별 요청 타임아웃 |
| `TOOL_RATE_LIMIT_DELAY` | 0.5초 | 요청 간 딜레이 |
| `TOOL_MAX_RESPONSE_BODY` | 8000자 | AI에 전달할 응답 body 최대 크기 |
| `MAX_TOOL_ROUNDS` | 3 | /continue 호출당 최대 tool 실행 라운드 |
| `TOOL_ALLOWED_METHODS` | GET/POST/PUT/PATCH/DELETE/OPTIONS/HEAD | 허용 HTTP 메서드 |

의존성: `config`, `providers`, `prompts`, `oauth`, `requests`

---

### `server/providers.py` (277줄)

AI Provider 추상화 레이어. 4개의 provider 구현 + 팩토리 함수.

**클래스:**

| 클래스 | 설명 |
|--------|------|
| `ProviderError` | Provider 관련 커스텀 예외 |
| `BaseProvider` | 추상 기본 클래스. `chat(messages, temperature, max_tokens)` 인터페이스 |
| `OpenAIProvider` | OpenAI API 구현. `openai` 라이브러리 사용 |
| `AnthropicProvider` | Anthropic API Key 구현. `anthropic` 라이브러리 사용 |
| `AnthropicOAuthProvider` | Anthropic OAuth 구현. Bearer 토큰 + `requests` 직접 호출 |
| `GoogleProvider` | Google Gemini 구현. `google.generativeai` 라이브러리 사용 |

**AnthropicOAuthProvider 특이사항:**
- `Authorization: Bearer <token>` 헤더 사용
- `anthropic-beta: oauth-2025-04-20` 헤더 필수
- `user-agent: claude-cli/2.1.2 (external, cli)` 설정
- `oauth.get_valid_access_token()`으로 토큰 자동 갱신

**팩토리 함수:**

```python
create_provider(provider_name, api_key, model, auth_method="api_key")
```
- `auth_method="oauth"` + `provider_name="anthropic"` → `AnthropicOAuthProvider` 반환
- 그 외 → 해당 provider의 API Key 구현 반환

의존성: `oauth` (AnthropicOAuthProvider에서 런타임 import)

---

### `server/prompts.py` (~320줄)

AI 시스템 프롬프트 템플릿과 사용자 프롬프트 빌더 함수.

**시스템 프롬프트:**

| 상수 | 용도 | 핵심 지시 |
|------|------|----------|
| `VERSION_ANALYSIS_SYSTEM` | Scanner - 버전 분석 | 헤더/응답에서 소프트웨어 버전 식별 → CVE/CWE 매핑 |
| `WEAKNESS_ANALYSIS_SYSTEM` | Scanner - 약점 분석 | CWE/CCE 패턴 식별 (injection, misconfiguration 등) |
| `CVE_ANALYSIS_SYSTEM` | CVE Analyzer | CVE 검색 + Python PoC 스크립트 생성 |
| `RESPONSE_CHECK_SYSTEM` | CVE Analyzer | PoC 실행 결과 분석 → 취약점 확인/수정 PoC 제공 |
| `CRITICAL_ANALYSIS_SYSTEM` | Critical Analyzer | **4단계 강제 분석 + Tool Execution System** (아래 상세) |
| `CRITICAL_CHAT_SYSTEM` | Critical Analyzer 채팅 (레거시) | 분석 세션 중 사용자 질문 응답 |
| `CRITICAL_CHAT_CLAUDE_SYSTEM` | Claude 채팅 lane | 분석 맥락 설명 + 페이로드/전략 의도 해설 |
| `CRITICAL_CHAT_CODEX_SYSTEM` | Codex 채팅 lane | PoC 검토 + 가정 비판 + 다음 테스트 제안 |

**CRITICAL_ANALYSIS_SYSTEM 4단계 + Tool Execution:**

```
Phase 1 (Reconnaissance): 모든 입력 포인트 식별 (visible + inferred hidden params)
Phase 2 (Analysis):        입력 포인트별 취약점 가능성 분석 + 근거
Phase 3 (Testing):         tool_requests로 실제 HTTP 테스트 요청 + Python PoC 생성
Phase 4 (Evaluation):      실제 응답 데이터 기반 판정 (여기서만 ANALYSIS_COMPLETE 허용)
```

AI는 `tool_requests` 배열을 JSON 출력에 포함하여 실제 HTTP 요청을 서버에 요청할 수 있습니다.
서버가 실행한 실제 응답 데이터를 기반으로 취약점 존재 여부를 판단합니다.

**빌더 함수:**

| 함수 | 설명 |
|------|------|
| `build_version_prompt(http_items)` | HTTP 항목 → 버전 분석 프롬프트 |
| `build_weakness_prompt(http_items)` | HTTP 항목 → 약점 분석 프롬프트 |
| `build_cve_prompt(http_items)` | HTTP 항목 → CVE 분석 프롬프트 |
| `build_response_check_prompt(cve_info, poc_code, output)` | PoC 결과 → 검증 프롬프트 |
| `build_critical_prompt(http_items, vuln_type)` | HTTP 항목 + 취약점 유형 → Critical 프롬프트 |
| `build_critical_followup(iteration, poc_code, tool_results_msg)` | 반복별 follow-up 메시지 생성 (tool 결과 피드백 포함) |
| `validate_critical_phase(iteration, content)` | 서버 측 phase 진행 규칙 검증 |
| `_truncate(text, max_length=8000)` | 텍스트 길이 제한 유틸리티 |

| 상수 | 설명 |
|------|------|
| `VULNERABILITY_TYPES` | 10가지 취약점 유형 리스트 |
| `CRITICAL_PHASES` | `["reconnaissance", "analysis", "testing", "evaluation"]` |

의존성: 없음

---

### `server/oauth.py` (223줄)

Anthropic Claude OAuth 2.0 PKCE 인증 플로우.

**주요 함수:**

| 함수 | 설명 |
|------|------|
| `generate_pkce()` | PKCE code_verifier + code_challenge(S256) 생성 |
| `build_auth_url()` | OAuth 인가 URL 생성 → `(url, flow_id)` 반환 |
| `exchange_code(code_with_state, flow_id)` | 인가 코드 → access/refresh 토큰 교환 |
| `refresh_access_token()` | refresh_token으로 access_token 갱신 |
| `get_valid_access_token()` | 유효한 토큰 반환 (만료 5분 전 자동 갱신) |
| `load_tokens()` | `oauth_tokens.json`에서 토큰 로드 |
| `_save_tokens(tokens)` | `oauth_tokens.json`에 토큰 저장 |
| `is_authenticated()` | 인증 여부 확인 |
| `clear_tokens()` | 토큰 파일 삭제 (로그아웃) |

**주요 상수:**

| 상수 | 값 |
|------|-----|
| `CLIENT_ID` | `9d1c250a-e61b-44d9-88ed-5944d1962f5e` |
| `AUTH_URL` | `https://claude.ai/oauth/authorize` |
| `TOKEN_URL` | `https://console.anthropic.com/v1/oauth/token` |
| `REDIRECT_URI` | `https://console.anthropic.com/oauth/code/callback` |
| `SCOPES` | `org:create_api_key user:profile user:inference` |

**토큰 정보:**

| 항목 | 형식 | 수명 |
|------|------|------|
| Access Token | `sk-ant-oat01-...` | 8시간 (28800초) |
| Refresh Token | `sk-ant-ort01-...` | 무기한 (취소 전까지) |

의존성: 없음 (stdlib + `requests`)

---

## Extension 파일

### `extension/ai_security_analyzer.py` (208줄)

Burp Suite Extension 메인 엔트리포인트. 탭 등록, 컨텍스트 메뉴, 패널 간 통신.

**클래스: `BurpExtender`**

구현 인터페이스: `IBurpExtender`, `ITab`, `IContextMenuFactory`

| 메서드 | 설명 |
|--------|------|
| `registerExtenderCallbacks(callbacks)` | Extension 이름 설정, 컨텍스트 메뉴 등록, UI 빌드 |
| `_build_ui()` | 메인 `JTabbedPane` 생성 (Scanner + Analyze 탭) |
| `getTabCaption()` | `"AI Security Analyzer"` 반환 |
| `getUiComponent()` | 메인 탭 패널 반환 |
| `createMenuItems(invocation)` | 우클릭 메뉴: "Send to AI CVE Analyzer", "Send to AI Critical Analyzer" |
| `_extract_http_items(invocation)` | Burp 메시지 → `HttpItem` 리스트 변환 |
| `send_to_cve_analyzer(items)` | CVE 패널로 항목 전송 + 탭 전환 |
| `send_to_critical_analyzer(items)` | Critical 패널로 항목 전송 + 탭 전환 |

`__file__` 미정의 대응: `inspect.getfile()`로 스크립트 경로를 추출하여 `sys.path`에 추가.

의존성: `scanner_panel`, `cve_panel`, `critical_panel`, `ui_components`, `models`

---

### `extension/models.py` (122줄)

데이터 모델 클래스. 순수 데이터 컨테이너.

| 클래스 | 필드 | 용도 |
|--------|------|------|
| `HttpItem` | index, method, url, status_code, content_type, request_str, response_str, host, port, protocol, path, length | HTTP 요청/응답 쌍 |
| `AnalysisResult` | result_type, content, elapsed, usage, error | AI 분석 결과 |
| `ChatMessage` | role, content | 채팅 메시지 (ROLE_USER, ROLE_ASSISTANT, ROLE_SYSTEM) |
| `CVEEntry` | cve_id, cvss, severity, description, affected_versions, poc_code, poc_usage, verification_status | CVE 정보 (verification_status 기본값 UNVERIFIED) |
| `FindingEntry` | finding_type, finding_id, name, severity, description, evidence, remediation, source | 보안 발견 사항 |

`HttpItem.to_dict()`: JSON 직렬화 시 request/response를 8000자로 truncate.

의존성: 없음

---

### `extension/ui_components.py` (377줄)

공통 UI 컴포넌트와 유틸리티 함수.

**클래스:**

| 클래스 | 설명 |
|--------|------|
| `UIUpdater(Runnable)` | 함수를 Swing EDT에서 실행하기 위한 래퍼 |
| `APIConfigPanel(JPanel)` | Provider/Model 선택 패널 (1행 레이아웃: Provider 드롭다운 + Model 드롭다운 + Apply/Refresh 버튼 + 상태 라벨) |
| `LoadingIndicator(JPanel)` | 로딩/성공/에러 상태 표시기 |

**유틸리티 함수:**

| 함수 | 설명 |
|------|------|
| `run_on_edt(fn)` | Swing EDT에서 함수 실행 |
| `append_to_pane(text_pane, text, color, bold, size)` | JTextPane에 스타일 텍스트 추가 |
| `clear_pane(text_pane)` | JTextPane 내용 삭제 |
| `server_request(path, method, data, server_url)` | Flask 서버에 HTTP 요청 (`java.net.HttpURLConnection` 사용) |

**주요 상수:**

| 상수 | 설명 |
|------|------|
| `DEFAULT_SERVER_URL` | `"http://127.0.0.1:10512"` |
| `PROVIDERS` | `["openai", "anthropic", "google"]` |
| `DEFAULT_MODELS` | Provider별 기본 모델명 |
| `PROVIDER_MODELS` | Provider별 선택 가능한 모델 리스트 |
| `SEVERITY_COLORS` | 심각도별 색상 (Critical=빨강, High=주황, Medium=노랑, Low=녹색, Info=파랑) |

의존성: 없음 (javax.swing, java.awt 사용)

---

### `extension/table_models.py` (244줄)

Swing `AbstractTableModel` 구현. JTable 데이터 표시용.

| 클래스 | 컬럼 | 용도 |
|--------|------|------|
| `ScannerTableModel` | #, Method, URL, Status, Content-Type, Length | Proxy History 표시 |
| `CVETableModel` | CVE ID, CVSS, Severity, Status, Description, Affected Versions | CVE 목록 표시 (verification_status 포함) |
| `CriticalTableModel` | #, Method, URL, Status | Critical 분석 대상 항목 표시 |
| `FindingsTableModel` | Type, ID, Name, Severity, Description | 보안 발견사항 표시 |

공통 메서드: `set_items/entries()`, `add_items/entries()`, `get_item/entry()`, `clear()`

의존성: 없음

---

### `extension/scanner_panel.py` (468줄)

Scanner 탭 패널. Proxy History 로드 + 버전/약점 분석 + 다른 패널로 전송.

**클래스: `ScannerPanel(JPanel)`**

| 메서드 | 설명 |
|--------|------|
| `_build_ui()` | Config 패널 + 버튼바(Refresh/Clear/Analyze/Send) + History 테이블 + Findings 테이블 + Detail 패인 |
| `_on_refresh()` | `callbacks.getProxyHistory()`로 Burp Proxy History 로드 (스레드) |
| `_on_clear_history()` | History 테이블 초기화 |
| `_on_analyze_versions()` | `/analyze/versions` 호출 → FindingEntry 파싱 → Findings 테이블 표시 |
| `_on_analyze_weaknesses()` | `/analyze/weaknesses` 호출 → FindingEntry 파싱 → Findings 테이블 표시 |
| `_on_send_to_cve()` | 선택 항목을 CVE Analyzer로 전송 |
| `_on_send_to_critical()` | 선택 항목을 Critical Analyzer로 전송 |
| `_parse_version_findings(content)` | AI JSON 응답 → `FindingEntry` 리스트 |
| `_parse_weakness_findings(content)` | AI JSON 응답 → `FindingEntry` 리스트 |
| `_extract_json(text)` | 마크다운 코드 블록에서 JSON 추출 |

의존성: `models`, `ui_components`, `table_models`

---

### `extension/cve_panel.py` (431줄)

CVE Analyzer 탭 패널. CVE 검색 + PoC 생성 + 실행 결과 검증.

**클래스: `CVEAnalyzerPanel(JPanel)`**

| 메서드 | 설명 |
|--------|------|
| `_build_ui()` | Config 패널 + 항목 정보 + CVE 테이블 + PoC 코드 뷰어(복사 버튼) + Response Checker(입력 + 결과) |
| `receive_items(items)` | Scanner/컨텍스트 메뉴에서 항목 수신 |
| `_on_analyze()` | `/analyze/cve` 호출 → CVEEntry 파싱 → CVE 테이블 표시 |
| `_on_cve_selected()` | CVE 선택 시 PoC 코드 + 상세정보 표시 |
| `_on_copy_poc()` | PoC 코드 클립보드 복사 |
| `_on_check_response()` | `/analyze/response-check` 호출 → 취약점 확인/수정 PoC 표시 |
| `_parse_cve_response(content)` | AI JSON 응답 → `CVEEntry` 리스트 |
| `_parse_check_response(content)` | Response Check JSON 파싱 |

의존성: `models`, `ui_components`, `table_models`

---

### `extension/critical_panel.py` (~555줄)

Critical Analyzer 탭 패널. 재귀적 심층 분석 + Tool Execution 표시 + 실시간 로그 + AI 채팅.

**클래스: `CriticalAnalyzerPanel(JPanel)`**

| 메서드 | 설명 |
|--------|------|
| `_build_ui()` | Config 패널 + 취약점 유형 드롭다운 + Start/Stop/Clear + Work Log(좌) + PoC 뷰어(좌하) + Chat(우) |
| `receive_items(items)` | 항목 수신 |
| `_on_start()` | 분석 루프 시작 (최대 10회 반복, Phase 4 전 ANALYSIS_COMPLETE 차단) |
| `_on_stop()` | 분석 중지 플래그 설정 |
| `_on_send_chat()` | `/analyze/critical/chat/multi` 호출 (Claude/Codex/Both 모드, 분석과 별도 session) |
| `_on_copy_poc()` | PoC 클립보드 복사 |
| `_on_clear()` | 전체 상태 초기화 |
| `_parse_critical_response(content)` | AI JSON 응답 파싱 (stage, findings, poc_code, input_points, status) |

**분석 루프 동작:**
```
Iteration 1 → Phase 1 (Reconnaissance) 결과 수신 → "Phase 2로 진행하라" 지시
Iteration 2 → Phase 2 (Analysis) 결과 수신 → "Phase 3 (Testing)로 진행하라" 지시
Iteration 3 → Phase 3 (Testing) 결과 수신 → 서버가 tool_requests 실행 → 실제 결과 AI 피드백
Iteration 4+ → Phase 4 (Evaluation) → 실제 데이터 기반 판정 → ANALYSIS_COMPLETE 허용
```

**Work Log 색상 코드:**
- 파란색: visible 파라미터
- 주황색: inferred 파라미터
- 보라색: Tool Execution 요청 정보 (`[test_id] GET http://target/path`)
- 초록색: Tool 실행 성공 (`HTTP 200 (4828 chars, 0.015s)`)
- 빨간색: Tool 실행 에러 (`ERROR - Connection refused`)
- 주황색: Tool 경고 (요청 제한 초과 등)

의존성: `models`, `ui_components`, `table_models`

---

## 데이터 플로우

### 일반 분석 (Scanner, CVE)
```
Burp Proxy History
    ↓ callbacks.getProxyHistory()
ScannerPanel (HttpItem 리스트)
    ↓ server_request("/analyze/...")
Flask server.py → do_chat() → Provider.chat()
    ↓ AI API 호출
AI 응답 (JSON)
    ↓ 파싱
Findings/CVE/Critical 결과 → JTable + JTextPane 표시
```

### Critical Analyzer (Tool Execution 포함)
```
Extension: /critical/start → 서버: 도메인 화이트리스트 생성 + AI 분석 시작
    ↓
Extension: /critical/continue → 서버: AI에게 다음 Phase 진행 지시
    ↓
AI: tool_requests 배열 출력 (Phase 3 Testing)
    ↓
서버: _execute_tool_requests() → 실제 HTTP 요청 실행 (안전 제어 적용)
    ↓
서버: _format_tool_results_for_ai() → 실제 응답을 AI에 피드백
    ↓
AI: 실제 데이터 기반 분석 + 추가 tool_requests (최대 3라운드)
    ↓
AI: Phase 4 Evaluation → 실제 응답 기반 최종 판정
    ↓
Extension: Work Log에 tool execution 결과 색상 표시
```
