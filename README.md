# BurpAIAnalyzer

AI-powered HTTP traffic security analyzer for Burp Suite. Identifies software versions, detects vulnerabilities (CWE/CCE/CVE), generates PoC exploit code, and performs deep recursive analysis — all through a Burp Suite extension UI.

## Architecture

```
Burp Suite (Jython 2.7)          Flask Server (Python 3)          AI Providers
┌─────────────────────┐   HTTP    ┌──────────────────┐   HTTPS    ┌───────────┐
│  Extension UI       │ ───────→  │  server.py       │ ───────→  │ Anthropic │
│  ├─ Scanner         │ localhost │  ├─ REST API      │           │ OpenAI    │
│  ├─ CVE Analyzer    │  :10512   │  ├─ OAuth         │           │ Google    │
│  └─ Critical        │ ←─────── │  ├─ Prompts       │ ←─────── │ Gemini    │
│     Analyzer        │          │  ├─ Session Mgmt  │           │           │
└─────────────────────┘          │  └─ Tool Exec ────│──→ Target │           │
                                 └──────────────────┘    Server  └───────────┘
```

The **Tool Execution Layer** enables the Critical Analyzer's AI to request real HTTP tests against the target. The server executes these requests with strict safety controls and returns actual responses for evidence-based analysis.

The extension runs inside Burp Suite via Jython (Python 2.7). A Flask middleware server handles AI provider communication, prompt management, OAuth authentication, and conversation history — keeping the extension lightweight and the prompt logic centrally updatable.

## Features

### Scanner
- Load Burp Proxy History into the extension
- **Version Analysis**: Detect software/framework versions exposed in HTTP headers and response bodies, map to known CVEs with CVSS v3.1 scoring
- **Weakness Analysis**: Identify CWE/CCE patterns (injection points, misconfigurations, information disclosure)
- Send selected items to CVE Analyzer or Critical Analyzer

### CVE Analyzer
- Search for CVEs affecting detected software versions
- Auto-generate Python PoC scripts for each CVE
- **Response Checker**: Paste PoC execution output and let AI determine if the vulnerability was confirmed, with modified PoC if needed

### Critical Analyzer
- Deep, recursive 4-phase vulnerability analysis for a specific vulnerability type:
  - **Phase 1 — Reconnaissance**: Identify all visible and inferred input points
  - **Phase 2 — Analysis**: Analyze input flow, validation, and attack vectors per parameter
  - **Phase 3 — Testing**: AI requests real HTTP tests via `tool_requests`; server executes them and returns actual responses
  - **Phase 4 — Evaluation**: Evidence-based verdict using real response data
- **Tool Execution Engine**: Server-side HTTP execution with safety controls (domain whitelist, rate limits, request caps)
- **Work Log**: Real-time progress display with color-coded findings and tool execution results
- **PoC Panel**: Current PoC code with copy-to-clipboard
- **Communication**: Chat with AI during analysis — supports **Claude**, **Codex**, or **Both** modes with speaker-separated rendering

## Requirements

- **Burp Suite** Professional or Community Edition
- **Jython** 2.7.x Standalone JAR ([download](https://www.jython.org/download))
- **Python** 3.8+
- **AI Provider** (one or more):
  - Anthropic Claude — OAuth (Pro/Max subscription, no extra API fee) or API Key
  - OpenAI — API Key
  - Google Gemini — API Key

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/BurpAIAnalyzer.git
cd BurpAIAnalyzer
```

### 2. Install server dependencies

```bash
cd server
pip install -r requirements.txt
```

### 3. Configure authentication

```bash
cp config.example.py config.py
```

Edit `server/config.py` and choose your authentication method:

**Option A: Anthropic OAuth (recommended for Claude Pro/Max subscribers)**

No API fees — uses your existing Claude subscription.

```python
AUTH_METHOD = {
    "anthropic": "oauth",
    "openai": "api_key",
    "google": "api_key",
}
```

**Option B: API Key**

```python
AUTH_METHOD = {
    "anthropic": "api_key",
    "openai": "api_key",
    "google": "api_key",
}

API_KEYS = {
    "openai": "sk-...",
    "anthropic": "sk-ant-...",
    "google": "AI...",
}
```

### 4. Configure Jython in Burp Suite (one-time)

1. Open Burp Suite
2. **Settings** > **Extensions** > **Python environment**
3. Set **Location of Jython standalone JAR file** to your `jython-standalone-2.7.x.jar`

## Usage

### Start the server

```bash
cd server
python3 server.py
```

```
16:46:21 [INFO] AI Security Analyzer Server starting
16:46:21 [INFO] Listening on 127.0.0.1:10512
16:46:21 [INFO]   scanner: anthropic/claude-sonnet-4-5-20250929 [OAuth: NOT logged in]
```

### OAuth login (if using OAuth)

1. Open http://127.0.0.1:10512/auth/login in your browser
2. Click **Login with Claude** → Authorize on claude.ai
3. Copy the `code#state` string shown on Anthropic's page
4. Paste into the input field and click **Submit**
5. Confirm "Login successful!"

Tokens auto-save to `server/oauth_tokens.json` and auto-refresh (8-hour expiry).

### Load the extension

1. Burp Suite > **Extensions** > **Installed** > **Add**
2. Extension type: **Python**
3. Extension file: select `extension/ai_security_analyzer.py`
4. The **AI Security Analyzer** tab appears in Burp's top bar

### Scanner workflow

1. Browse your target through Burp Proxy
2. Go to **AI Security Analyzer** > **Scanner**
3. Click **Refresh History** to load Proxy History
4. Select items (Shift/Ctrl for multi-select)
5. Click **Analyze Versions** or **Analyze Weaknesses**
6. Review findings in the results table

### CVE Analyzer workflow

1. From Scanner, select items and click **Send to CVE Analyzer**
   — or right-click in Proxy History > **Send to AI CVE Analyzer**
2. Click **Analyze** → CVEs listed with auto-generated PoC code
3. Copy and execute the PoC against your authorized target
4. Paste execution output into **Response Checker** for AI verification

### Critical Analyzer workflow

1. From Scanner, select items and click **Send to Critical Analyzer**
   — or right-click in Proxy History > **Send to AI Critical Analyzer**
2. Select vulnerability type (SQL Injection, XSS, Command Injection, etc.)
3. Click **Start Analysis** → AI performs recursive 4-phase deep analysis
4. Monitor progress in the **Work Log** panel — tool execution results shown in color
5. In Phase 3 (Testing), the server automatically executes AI-requested HTTP tests and feeds real responses back
6. Use **Communication** to chat with AI during analysis
7. Analysis completes when AI signals `ANALYSIS_COMPLETE` (Phase 4+) with evidence-based verdict

### Runtime AI configuration

Each tab has an **AI Configuration** panel where you can change provider and model without restarting:

1. Select **Provider** (openai / anthropic / google)
2. Select **Model** (or type a custom model name)
3. Click **Apply**

## Project Structure

```
BurpAIAnalyzer/
├── extension/                      # Burp Suite Extension (Jython 2.7)
│   ├── ai_security_analyzer.py     # Main entry point (BurpExtender)
│   ├── models.py                   # Data models (HttpItem, CVEEntry, etc.)
│   ├── ui_components.py            # Shared UI (APIConfigPanel, server_request)
│   ├── table_models.py             # JTable models (Scanner, CVE, Findings)
│   ├── scanner_panel.py            # Scanner tab
│   ├── cve_panel.py                # CVE Analyzer tab
│   └── critical_panel.py           # Critical Analyzer tab
│
├── server/                         # Flask middleware server (Python 3)
│   ├── server.py                   # REST API + session management
│   ├── config.example.py           # Configuration template
│   ├── providers.py                # AI provider abstraction layer
│   ├── prompts.py                  # System prompts + phase management
│   ├── oauth.py                    # Anthropic OAuth 2.0 PKCE flow
│   └── requirements.txt            # Python dependencies
│
├── .gitignore
└── README.md
```

## REST API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Server status and component configuration |
| GET | `/auth/login` | OAuth login page |
| POST | `/auth/complete` | Exchange OAuth code for tokens |
| GET | `/auth/status` | Check OAuth authentication status |
| POST | `/auth/logout` | Clear OAuth tokens |
| GET/POST | `/config/<component>` | Get/set provider configuration |
| GET | `/config/available` | List configured providers |
| POST | `/analyze/versions` | Software version analysis |
| POST | `/analyze/weaknesses` | Security weakness analysis |
| POST | `/analyze/cve` | CVE analysis + PoC generation |
| POST | `/analyze/response-check` | PoC execution result verification |
| POST | `/analyze/critical/start` | Start critical analysis session (initializes domain whitelist + tool counters) |
| POST | `/analyze/critical/continue` | Continue critical analysis (auto-executes tool_requests if present) |
| POST | `/analyze/critical/chat` | Chat during critical analysis (single lane, legacy) |
| POST | `/analyze/critical/chat/multi` | Multi-AI chat (Claude / Codex / Both mode) |
| GET | `/vulnerability-types` | List supported vulnerability types |
| GET/DELETE | `/sessions/<id>` | View/clear conversation history |
| GET | `/logs/recent` | Recent API call logs |

## Technical Details

### Token Management
- **max_tokens**: Set to 16384 across all endpoints as a ceiling (not a target). AI generates only as many tokens as needed; the limit prevents mid-response truncation.
- **Session-based history limits**: Different session types have different sliding window sizes to balance context retention and token usage:
  - Critical analysis: 12 messages (preserves phase context)
  - Critical chat: 10 messages
  - CVE analysis: 8 messages
  - Default: 10 messages
- **Phase summary preservation**: When critical analysis history is trimmed, key findings from earlier phases are summarized and retained.

### Tool Execution Layer (Critical Analyzer)
The Critical Analyzer includes a server-side HTTP execution engine that allows AI to request and receive real HTTP test results instead of generating hypothetical PoC output.

**Flow**: AI outputs `tool_requests` array → Server executes real HTTP requests → Server feeds actual responses back to AI → AI analyzes real data

**Safety Controls**:
| Control | Value |
|---------|-------|
| Domain whitelist | Only host:port pairs from original HTTP items |
| Allowed methods | GET, POST, PUT, PATCH, DELETE, OPTIONS, HEAD |
| Requests per round | Max 10 |
| Requests per session | Max 50 |
| Request timeout | 10 seconds |
| Inter-request delay | 0.5 seconds |
| Response body size | 8000 chars (truncated for AI) |
| Tool rounds per /continue | Max 3 |
| Redirects | Disabled |
| SSL verification | Disabled (testing environments) |

### Server-side Prompt Management
All AI prompts are managed in `server/prompts.py`. Changes take effect on server restart without needing to reload the Burp extension. This includes:
- System prompts for each analysis type
- Phase progression logic (`build_critical_followup`)
- Phase validation (`validate_critical_phase`) — prevents premature `ANALYSIS_COMPLETE`
- JSON response extraction (`_extract_ai_json`) — centralized parsing

### Provider Support
| Provider | Auth Methods | Special Handling |
|----------|-------------|------------------|
| Anthropic | OAuth, API Key | System message via `system` param; OAuth uses PKCE flow with auto-refresh |
| OpenAI | API Key | Standard Chat Completions API |
| Google Gemini | API Key | JSON instruction reinforcement in user messages (Gemini's `system_instruction` is less strict) |

### Timeouts
- AI provider API call: **300 seconds** (accommodates large responses with Opus models)
- Client → Server read timeout: **330 seconds** (30s buffer over server timeout)
- Client → Server connect timeout: **10 seconds**

## Security Notice

This tool is designed for **authorized security testing only**. Always ensure you have explicit permission before testing any target. The generated PoC code should only be executed against systems you are authorized to test.

## License

MIT

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.
