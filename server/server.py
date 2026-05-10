"""
AI Security Analyzer - Middleware Server
Flask server that bridges Burp Suite Extension with AI APIs.
Provides REST endpoints for security analysis operations.
"""
import os
import sys
import json
import time
import uuid
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse

import requests as http_requests  # renamed to avoid conflict with flask.request

from flask import Flask, request, jsonify
from flask_cors import CORS

from providers import create_provider, ProviderError
from prompts import (
    VERSION_ANALYSIS_SYSTEM, WEAKNESS_ANALYSIS_SYSTEM,
    CVE_ANALYSIS_SYSTEM, RESPONSE_CHECK_SYSTEM,
    CRITICAL_ANALYSIS_SYSTEM, CRITICAL_CHAT_SYSTEM,
    CRITICAL_CHAT_CLAUDE_SYSTEM, CRITICAL_CHAT_CODEX_SYSTEM,
    VULNERABILITY_TYPES,
    build_version_prompt, build_weakness_prompt,
    build_cve_prompt, build_response_check_prompt,
    build_critical_prompt, build_critical_followup,
    validate_critical_phase,
)
from config import API_KEYS, MODELS, COMPONENT_DEFAULTS, AUTH_METHOD
from oauth import (
    build_auth_url, exchange_code, is_authenticated,
    clear_tokens, get_valid_access_token, load_tokens,
)

# ── App Setup ────────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

# ── Logging ──────────────────────────────────────────────────
LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
os.makedirs(LOG_DIR, exist_ok=True)

# File handler - detailed logs
file_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, "server.log"),
    maxBytes=10 * 1024 * 1024,  # 10MB
    backupCount=5,
)
file_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s - %(message)s"
))
file_handler.setLevel(logging.DEBUG)

# Console handler - concise
console_handler = logging.StreamHandler()
console_handler.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(message)s", datefmt="%H:%M:%S"
))
console_handler.setLevel(logging.INFO)

# Root logger
logging.basicConfig(level=logging.DEBUG, handlers=[file_handler, console_handler])
logger = logging.getLogger("server")

# Request/Response log for AI API calls
api_log_handler = RotatingFileHandler(
    os.path.join(LOG_DIR, "api_calls.log"),
    maxBytes=10 * 1024 * 1024,
    backupCount=5,
)
api_log_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
api_logger = logging.getLogger("api_calls")
api_logger.addHandler(api_log_handler)
api_logger.setLevel(logging.DEBUG)


# ── State ────────────────────────────────────────────────────
# Provider configs per component - auto-loaded from config.py
provider_configs = {}
for _comp, _defaults in COMPONENT_DEFAULTS.items():
    _prov = _defaults["provider"]
    _auth = AUTH_METHOD.get(_prov, "api_key")
    provider_configs[_comp] = {
        "provider": _prov,
        "api_key": API_KEYS.get(_prov, ""),
        "model": _defaults.get("model") or MODELS.get(_prov, ""),
        "auth_method": _auth,
    }
# Active provider instances and their cache keys
providers = {}
_provider_cache_keys = {}
# Conversation histories (sliding window per session type)
conversations = {}
# Session-type-based history limits (matched by session_id prefix)
# Order matters: longer prefixes must come first for correct matching
_SESSION_HISTORY_LIMITS = {
    "critical_chat_codex_": 10,   # Codex chat: moderate context
    "critical_chat_claude_": 10,  # Claude chat: moderate context
    "critical_chat_": 10,         # Legacy chat fallback
    "critical_analysis_": 12,     # 4-phase analysis: needs phase results
    "critical_": 12,              # Legacy critical fallback
    "cve_verify_": 8,             # CVE verification rounds
    "cve_analysis_": 8,           # CVE analysis
    "cve_": 8,                    # Legacy CVE fallback
}
_DEFAULT_MAX_HISTORY = 10

# ── Tool Execution State & Constants ─────────────────────────
_session_allowed_domains = {}     # session_id → set("host:port")
_session_tool_counters = {}       # session_id → {"count": int}
TOOL_MAX_REQUESTS_PER_ROUND = 10
TOOL_MAX_REQUESTS_PER_SESSION = 50
TOOL_REQUEST_TIMEOUT = 10         # seconds
TOOL_RATE_LIMIT_DELAY = 0.5       # delay between requests
TOOL_MAX_RESPONSE_BODY = 8000     # max chars of response body sent to AI
MAX_TOOL_ROUNDS = 3               # max tool execution rounds per /continue call
TOOL_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"}

# ── Thread Safety ───────────────────────────────────────────
import threading
_state_lock = threading.Lock()


# ── Session ID Helper ──────────────────────────────────────
def generate_session_id(lane):
    """Generate a collision-free session ID with hybrid format.

    Format: {lane}_{unix_timestamp}_{uuid4_short}
    - lane: purpose identifier (e.g. critical_analysis, cve_analysis)
    - unix_timestamp: used by cleanup for TTL expiration
    - uuid4_short: 8-char hex to prevent same-second collisions
    """
    ts = int(time.time())
    short_uuid = uuid.uuid4().hex[:8]
    return "{}_{}_{}" .format(lane, ts, short_uuid)


# ── Session Garbage Collection ──────────────────────────────
import time as _time

_last_cleanup = _time.time()
SESSION_TTL = 7200  # 2 hours


def _cleanup_expired_sessions():
    """Remove sessions older than SESSION_TTL."""
    global _last_cleanup
    now = _time.time()

    # Only run every 5 minutes
    if now - _last_cleanup < 300:
        return
    _last_cleanup = now

    expired = []
    for sid in list(conversations.keys()):
        # Extract timestamp from session ID format: "type_timestamp" or "type_timestamp_suffix"
        parts = sid.split("_")
        for part in parts:
            try:
                ts = float(part)
                if ts > 1000000000 and now - ts > SESSION_TTL:  # Valid unix timestamp and expired
                    expired.append(sid)
                break
            except (ValueError, TypeError):
                continue

    for sid in expired:
        conversations.pop(sid, None)
        _session_allowed_domains.pop(sid, None)
        _session_tool_counters.pop(sid, None)

    if expired:
        logger.info("Cleaned up %d expired sessions", len(expired))


@app.before_request
def before_request_cleanup():
    _cleanup_expired_sessions()


def _get_max_history(session_id):
    """Get max history size based on session type."""
    if session_id:
        for prefix, limit in _SESSION_HISTORY_LIMITS.items():
            if session_id.startswith(prefix):
                return limit
    return _DEFAULT_MAX_HISTORY


# ── Helper Functions ─────────────────────────────────────────

def get_or_create_provider(component):
    """Get existing provider or create new one for a component."""
    config = provider_configs.get(component)
    if not config or not config["provider"]:
        raise ProviderError("No API configuration for component '{}'. Please configure it first.".format(component))

    auth_method = config.get("auth_method", "api_key")

    # For api_key mode, require a key
    if auth_method == "api_key" and not config["api_key"]:
        raise ProviderError("No API key for component '{}'. Configure in server/config.py.".format(component))

    # For oauth mode, check authentication
    if auth_method == "oauth" and not is_authenticated():
        raise ProviderError("OAuth not authenticated. Visit http://127.0.0.1:10512/auth/login to login.")

    # Build cache key from current config
    cache_key = "{}_{}_{}_{}_{}".format(component, config["provider"], config["model"], auth_method, config["api_key"][:8] if config["api_key"] else "oauth")

    # Check if the cached provider matches current config
    current_cache = _provider_cache_keys.get(component)
    if current_cache != cache_key or component not in providers:
        logger.info("Creating provider for %s: %s/%s [%s]", component, config["provider"], config["model"], auth_method)
        providers[component] = create_provider(
            config["provider"], config["api_key"], config["model"], auth_method=auth_method,
        )
        _provider_cache_keys[component] = cache_key

    return providers[component]


def _get_conversation_unlocked(session_id):
    """Get or create conversation history (caller must hold _state_lock)."""
    if session_id not in conversations:
        conversations[session_id] = []
    return conversations[session_id]


def get_conversation(session_id):
    """Get or create conversation history."""
    with _state_lock:
        return _get_conversation_unlocked(session_id)


def add_to_conversation(session_id, role, content):
    """Add message to conversation with sliding window.

    For critical analysis sessions, preserves phase summaries so later phases
    retain context from earlier reconnaissance and analysis results.
    Uses session-type-based history limits instead of a global constant.
    """
    with _state_lock:
        history = _get_conversation_unlocked(session_id)
        history.append({"role": role, "content": content})
        max_hist = _get_max_history(session_id)
        # Keep system message + last max_hist messages
        if len(history) > max_hist + 1:
            system_msgs = [m for m in history if m["role"] == "system"]
            other_msgs = [m for m in history if m["role"] != "system"]

            # For critical sessions, build a summary of trimmed phases
            is_critical = session_id and (session_id.startswith("critical_analysis_") or
                          (session_id.startswith("critical_") and not session_id.startswith("critical_chat_")))
            if is_critical and len(other_msgs) > max_hist:
                trimmed = other_msgs[:len(other_msgs) - max_hist]
                summary = _build_phase_summary(trimmed)
                if summary:
                    # Insert phase summary as first non-system message
                    kept = other_msgs[-(max_hist):]
                    kept.insert(0, {"role": "user", "content": summary})
                    conversations[session_id] = system_msgs + kept[-max_hist:]
                    return

            conversations[session_id] = system_msgs + other_msgs[-(max_hist):]


def _build_phase_summary(trimmed_messages):
    """Extract key findings from trimmed critical analysis messages."""
    phases_found = []
    for msg in trimmed_messages:
        if msg["role"] != "assistant":
            continue
        content = msg["content"]
        # Try to extract stage and key findings from JSON responses
        try:
            import re
            # Find JSON in the content
            start = content.find("{")
            end = content.rfind("}")
            if start != -1 and end > start:
                import json
                parsed = json.loads(content[start:end + 1])
                stage = parsed.get("stage", "")
                findings = parsed.get("findings", "")
                input_points = parsed.get("input_points", [])
                if stage and findings:
                    summary = "Phase {}: {}".format(stage, str(findings)[:300])
                    if input_points:
                        params = [p.get("name", "?") for p in input_points[:10]]
                        summary += " | Params: {}".format(", ".join(params))
                    phases_found.append(summary)
        except Exception:
            continue

    if phases_found:
        return "[PHASE SUMMARY from earlier analysis]\n" + "\n".join(phases_found)
    return None


def _extract_ai_json(content):
    """Extract and parse JSON from AI response content.

    Handles raw JSON, markdown-fenced JSON, and JSON embedded in text.
    Returns parsed dict on success, None on failure.
    """
    import re
    if not content:
        return None

    text = content.strip()

    # 1. Direct JSON (ideal case with our new prompts)
    if text.startswith("{"):
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # May have trailing text after the JSON object
            depth = 0
            for i, c in enumerate(text):
                if c == "{":
                    depth += 1
                elif c == "}":
                    depth -= 1
                    if depth == 0:
                        try:
                            return json.loads(text[:i + 1])
                        except json.JSONDecodeError:
                            break
            pass

    # 2. Markdown code fence
    for pattern in [r'```json\s*\n(.*?)\n```', r'```\s*\n(\{.*?\})\n```']:
        match = re.search(pattern, text, re.DOTALL)
        if match:
            try:
                return json.loads(match.group(1))
            except json.JSONDecodeError:
                continue

    # 3. First { to last } fallback
    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            pass

    # 4. Attempt JSON repair: fix common LLM output defects
    try:
        # Remove trailing commas (most common LLM JSON defect)
        repaired = re.sub(r',\s*([}\]])', r'\1', text)
        # Remove single-line comments
        repaired = re.sub(r'//.*?$', '', repaired, flags=re.MULTILINE)
        result = json.loads(repaired)
        if isinstance(result, dict):
            logger.debug("JSON parsed after repair (trailing commas/comments removed)")
            return result
    except (json.JSONDecodeError, ValueError):
        pass

    return None


def _detect_hallucinated_output(content):
    """Detect patterns indicating fabricated execution results.

    Returns list of warning strings if hallucination indicators are found.
    Checks for fake HTTP responses, fabricated command output, and
    invented data extraction results that the AI could not have produced.
    """
    import re
    if not content:
        return []

    warnings = []
    text = content

    # Pattern 1: Fake HTTP status/response blocks (e.g., "Status: 200 | Len: 4828")
    status_pattern = re.findall(r'Status:\s*\d{3}\s*\|\s*Len:\s*\d+', text)
    if len(status_pattern) >= 2:
        warnings.append("Fabricated HTTP response pattern detected ({} occurrences)".format(len(status_pattern)))

    # Pattern 2: Fake execution output blocks with step numbering
    step_blocks = re.findall(r'(?:STEP|Step)\s+\d+.*?={3,}', text)
    if step_blocks:
        warnings.append("Fabricated step-by-step execution output detected")

    # Pattern 3: Fake response with specific byte counts
    byte_pattern = re.findall(r'\d+\s*bytes?\b.*?->', text)
    if len(byte_pattern) >= 3:
        warnings.append("Fabricated response size data detected ({} occurrences)".format(len(byte_pattern)))

    # Pattern 4: Claims of extracting specific DB data
    extraction = re.findall(
        r'(?:MySQL|MariaDB|PostgreSQL|Oracle|MSSQL)\s+(?:Version|version)[:\s]+\d+\.\d+\.\d+',
        text
    )
    if extraction:
        warnings.append("Claims specific database version extraction: {}".format(extraction[0]))

    # Pattern 5: Fake timing data (e.g., "Time: 5.02s" for sleep injection)
    timing = re.findall(r'Time:\s*(\d+\.\d+)s', text)
    if timing:
        sleep_like = [t for t in timing if float(t) >= 4.5]
        if sleep_like:
            warnings.append("Suspicious timing data suggesting fabricated sleep-based results")

    # Pattern 6: Simulated code execution blocks (```\noutput...\n```)
    # Multiple consecutive output blocks suggest fabrication
    output_blocks = re.findall(r'```\n(?!python|bash|sql)(.+?)```', text, re.DOTALL)
    if len(output_blocks) >= 3:
        warnings.append("Multiple simulated output blocks detected ({})".format(len(output_blocks)))

    # Pattern 7: "confirmed vulnerable" without tool execution evidence
    # (Only flag if no tool_requests results appear in the text)
    confirmed_patterns = [
        r'confirmed\s+vulnerable',
        r'vulnerability\s+confirmed',
        r'successfully\s+exploited',
    ]
    has_tool_results = 'tool_results' in text.lower() or 'execution result' in text.lower() or 'status_code' in text.lower()
    if not has_tool_results:
        for pattern in confirmed_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                warnings.append(
                    "AI claims vulnerability confirmed but no tool execution results detected. "
                    "Require real test evidence before trusting this verdict."
                )
                break

    return warnings


def _validate_ai_response(parsed, response_type):
    """Validate AI-generated identifiers and scores for hallucination.

    Args:
        parsed: Parsed JSON dict from AI response
        response_type: "cve", "version", "weakness", or "critical"

    Returns:
        list of warning strings for any validation failures
    """
    import re
    warnings = []

    if not isinstance(parsed, dict):
        return warnings

    CVE_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,7}$')
    CWE_PATTERN = re.compile(r'^CWE-\d+$')
    CCE_PATTERN = re.compile(r'^CCE-\d+-\d+$')
    current_year = 2026  # Update as needed

    def validate_cve_id(cve_id, context=""):
        if not cve_id or cve_id == "N/A":
            return
        if not CVE_PATTERN.match(cve_id):
            warnings.append("Invalid CVE format: %s %s" % (cve_id, context))
            return
        # Check for future year
        try:
            year = int(cve_id.split("-")[1])
            if year > current_year:
                warnings.append("CVE with future year: %s %s" % (cve_id, context))
        except (IndexError, ValueError):
            pass

    def validate_cvss(score, context=""):
        if score is None or score == "N/A":
            return
        try:
            val = float(score)
            if val < 0.0 or val > 10.0:
                warnings.append("CVSS score out of range (0-10): %s %s" % (score, context))
        except (ValueError, TypeError):
            warnings.append("Invalid CVSS score format: %s %s" % (score, context))

    def validate_cwe_cce(finding_id, finding_type, context=""):
        if not finding_id or finding_id == "N/A":
            return
        if finding_type == "CWE" and not CWE_PATTERN.match(finding_id):
            warnings.append("Invalid CWE format: %s %s" % (finding_id, context))
        elif finding_type == "CCE" and not CCE_PATTERN.match(finding_id):
            warnings.append("Invalid CCE format: %s %s" % (finding_id, context))

    # Validate based on response type
    if response_type == "cve":
        for i, cve in enumerate(parsed.get("cves", [])):
            ctx = "(CVE entry %d)" % (i + 1)
            validate_cve_id(cve.get("id"), ctx)
            validate_cvss(cve.get("cvss"), ctx)
            # Flag entries missing verification_status
            if not cve.get("verification_status"):
                cve["verification_status"] = "UNVERIFIED"
                warnings.append("Missing verification_status, marked UNVERIFIED: %s" % cve.get("id", "unknown"))

    elif response_type == "version":
        for finding in parsed.get("findings", []):
            for vuln in finding.get("vulnerabilities", []):
                ctx = "(version finding: %s)" % finding.get("software", "?")
                validate_cve_id(vuln.get("id"), ctx)

    elif response_type == "weakness":
        for finding in parsed.get("findings", []):
            ftype = finding.get("type", "")
            fid = finding.get("id", "")
            ctx = "(weakness finding)"
            validate_cwe_cce(fid, ftype, ctx)

    elif response_type == "critical":
        # For critical analysis, validate any CVE-like strings in findings
        findings_text = str(parsed.get("findings", ""))
        cve_mentions = re.findall(r'CVE-\d{4}-\d+', findings_text)
        for cve_id in cve_mentions:
            validate_cve_id(cve_id, "(in critical findings text)")

    return warnings


def _extract_domains_from_items(items):
    """Extract allowed host:port pairs from HTTP items."""
    domains = set()
    for item in items:
        url = item.get("url", "")
        if url:
            try:
                parsed = urlparse(url)
                host = parsed.hostname or ""
                port = parsed.port
                if not port:
                    port = 443 if parsed.scheme == "https" else 80
                if host:
                    domains.add("{}:{}".format(host, port))
            except Exception:
                continue
    return domains


def _execute_tool_requests(session_id, tool_requests):
    """Execute AI-requested HTTP tests with safety controls.

    Returns (results_list, warnings_list).
    Each result: {"id", "status_code"|"error", "headers", "body", "elapsed", "request_info"}
    """
    results = []
    warnings = []
    with _state_lock:
        allowed = _session_allowed_domains.get(session_id, set())
        counter = _session_tool_counters.get(session_id, {"count": 0})

    if not allowed:
        warnings.append("No allowed domains for session — tool requests blocked")
        return results, warnings

    # Enforce per-round limit
    requests_this_round = tool_requests[:TOOL_MAX_REQUESTS_PER_ROUND]
    if len(tool_requests) > TOOL_MAX_REQUESTS_PER_ROUND:
        warnings.append("Trimmed to {} requests (round limit)".format(TOOL_MAX_REQUESTS_PER_ROUND))

    for req in requests_this_round:
        req_id = req.get("id", "unknown")
        url = req.get("url", "")
        method = (req.get("method", "GET") or "GET").upper()

        # Session-wide limit
        if counter["count"] >= TOOL_MAX_REQUESTS_PER_SESSION:
            warnings.append("Session limit reached ({} requests) — remaining requests skipped".format(
                TOOL_MAX_REQUESTS_PER_SESSION))
            break

        # Method whitelist
        if method not in TOOL_ALLOWED_METHODS:
            results.append({
                "id": req_id, "error": "Method '{}' not allowed".format(method),
                "request_info": {"method": method, "url": url},
            })
            continue

        # Domain whitelist
        try:
            parsed = urlparse(url)
            host = parsed.hostname or ""
            port = parsed.port
            if not port:
                port = 443 if parsed.scheme == "https" else 80
            domain_key = "{}:{}".format(host, port)
        except Exception:
            results.append({
                "id": req_id, "error": "Invalid URL: {}".format(url),
                "request_info": {"method": method, "url": url},
            })
            continue

        if domain_key not in allowed:
            results.append({
                "id": req_id,
                "error": "Domain '{}' not in whitelist (allowed: {})".format(
                    domain_key, ", ".join(sorted(allowed))),
                "request_info": {"method": method, "url": url},
            })
            continue

        # Execute the request
        counter["count"] += 1
        req_headers = req.get("headers") or {}
        req_body = req.get("body")
        start = time.time()

        try:
            resp = http_requests.request(
                method=method,
                url=url,
                headers=req_headers,
                data=req_body if isinstance(req_body, (str, bytes, type(None))) else json.dumps(req_body),
                timeout=TOOL_REQUEST_TIMEOUT,
                allow_redirects=False,
                verify=False,
            )
            elapsed = round(time.time() - start, 3)

            body = resp.text or ""
            truncated = False
            if len(body) > TOOL_MAX_RESPONSE_BODY:
                body = body[:TOOL_MAX_RESPONSE_BODY]
                truncated = True

            resp_headers = dict(resp.headers)

            results.append({
                "id": req_id,
                "status_code": resp.status_code,
                "headers": resp_headers,
                "body": body,
                "body_length": len(resp.text or ""),
                "truncated": truncated,
                "elapsed": elapsed,
                "request_info": {"method": method, "url": url},
            })
            logger.info("Tool exec [%s] %s %s -> %d (%d chars, %.3fs)",
                        session_id, method, url, resp.status_code, len(resp.text or ""), elapsed)

        except http_requests.exceptions.Timeout:
            elapsed = round(time.time() - start, 3)
            results.append({
                "id": req_id, "error": "Timeout after {}s".format(TOOL_REQUEST_TIMEOUT),
                "elapsed": elapsed,
                "request_info": {"method": method, "url": url},
            })
            logger.warning("Tool exec [%s] %s %s -> TIMEOUT", session_id, method, url)

        except http_requests.exceptions.ConnectionError as e:
            elapsed = round(time.time() - start, 3)
            results.append({
                "id": req_id, "error": "Connection error: {}".format(str(e)[:200]),
                "elapsed": elapsed,
                "request_info": {"method": method, "url": url},
            })
            logger.warning("Tool exec [%s] %s %s -> CONN_ERROR", session_id, method, url)

        except Exception as e:
            elapsed = round(time.time() - start, 3)
            results.append({
                "id": req_id, "error": "Request failed: {}".format(str(e)[:200]),
                "elapsed": elapsed,
                "request_info": {"method": method, "url": url},
            })
            logger.warning("Tool exec [%s] %s %s -> ERROR: %s", session_id, method, url, str(e)[:100])

        # Rate limit delay between requests
        if req != requests_this_round[-1]:
            time.sleep(TOOL_RATE_LIMIT_DELAY)

    with _state_lock:
        _session_tool_counters[session_id] = counter
    return results, warnings


def _format_tool_results_for_ai(results, warnings):
    """Format tool execution results as a message for the AI to analyze."""
    parts = ["=== TOOL EXECUTION RESULTS (REAL DATA) ==="]
    parts.append("The following are ACTUAL HTTP responses from the target server.\n")

    for r in results:
        req_info = r.get("request_info", {})
        parts.append("--- [{}] {} {} ---".format(
            r.get("id", "?"), req_info.get("method", "?"), req_info.get("url", "?")))

        if "error" in r:
            parts.append("ERROR: {}".format(r["error"]))
        else:
            parts.append("Status: {}".format(r.get("status_code", "?")))
            parts.append("Response Length: {} chars{}".format(
                r.get("body_length", "?"),
                " (truncated)" if r.get("truncated") else ""))
            parts.append("Elapsed: {}s".format(r.get("elapsed", "?")))

            # Include key response headers
            headers = r.get("headers", {})
            interesting = ["Content-Type", "Server", "X-Powered-By", "Set-Cookie",
                           "Location", "WWW-Authenticate", "Content-Length"]
            header_lines = []
            for h in interesting:
                for k, v in headers.items():
                    if k.lower() == h.lower():
                        header_lines.append("  {}: {}".format(k, v[:200]))
            if header_lines:
                parts.append("Key Headers:\n{}".format("\n".join(header_lines)))

            body = r.get("body", "")
            if body:
                parts.append("Body:\n{}".format(body))

        parts.append("")

    if warnings:
        parts.append("WARNINGS: " + "; ".join(warnings))

    parts.append("=== END TOOL RESULTS ===")
    parts.append("Analyze these REAL responses. Base your assessment on this actual data.")
    return "\n".join(parts)


def do_chat(component, system_prompt, user_prompt, session_id=None, temperature=0.3, max_tokens=4096):
    """Execute a chat with the AI provider."""
    start_time = time.time()
    provider = get_or_create_provider(component)

    if session_id:
        # Conversational mode
        history = get_conversation(session_id)
        if not history or history[0].get("role") != "system":
            history.insert(0, {"role": "system", "content": system_prompt})
            conversations[session_id] = history
        add_to_conversation(session_id, "user", user_prompt)
        messages = conversations[session_id]
    else:
        # Single-shot mode
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

    # Log the request
    api_logger.debug("REQUEST [%s] session=%s messages=%d user_prompt_len=%d",
                     component, session_id, len(messages), len(user_prompt))

    result = provider.chat(messages, temperature=temperature, max_tokens=max_tokens)
    elapsed = time.time() - start_time

    # Log the response
    api_logger.debug("RESPONSE [%s] session=%s tokens=%s elapsed=%.2fs content_len=%d",
                     component, session_id, result.get("usage"), elapsed, len(result.get("content", "")))

    if session_id:
        add_to_conversation(session_id, "assistant", result["content"])

    result["elapsed"] = round(elapsed, 2)

    # Server-side JSON parsing — clients can use 'parsed' directly
    parsed = _extract_ai_json(result.get("content", ""))
    if parsed is not None:
        result["parsed"] = parsed

    # Run hallucination detection on ALL AI responses (not just critical)
    hallucination_warnings = _detect_hallucinated_output(result.get("content", ""))

    # Structural validation of AI-generated identifiers
    if parsed is not None:
        response_type = "critical" if session_id and session_id.startswith("critical_") else \
                        "cve" if session_id and session_id.startswith("cve_") else \
                        "version" if component == "scanner" and "version" in user_prompt.lower()[:200] else \
                        "weakness" if component == "scanner" else "unknown"
        structural_warnings = _validate_ai_response(parsed, response_type)
        hallucination_warnings.extend(structural_warnings)

    if hallucination_warnings:
        result["hallucination_warnings"] = hallucination_warnings
        logger.warning("Hallucination detected in %s: %s", session_id or component, hallucination_warnings)

    return result


# ── API Endpoints ────────────────────────────────────────────

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint."""
    comp_status = {}
    for k, v in provider_configs.items():
        auth = v.get("auth_method", "api_key")
        if auth == "oauth":
            comp_status[k] = is_authenticated()
        else:
            comp_status[k] = bool(v["provider"] and v["api_key"])
    return jsonify({
        "status": "ok",
        "timestamp": datetime.now().isoformat(),
        "configured_components": comp_status,
        "oauth_authenticated": is_authenticated(),
    })


@app.route("/config/<component>", methods=["POST"])
def configure(component):
    """Configure AI provider for a component (scanner/cve/critical).
    API keys are loaded from config.py - only provider and model are needed.
    """
    if component not in provider_configs:
        return jsonify({"error": "Unknown component: {}".format(component)}), 400

    data = request.json
    if not data:
        return jsonify({"error": "Request body required"}), 400

    provider_name = data.get("provider")
    model = data.get("model")

    if not provider_name:
        return jsonify({"error": "provider is required"}), 400

    auth_method = AUTH_METHOD.get(provider_name, "api_key")

    if auth_method == "api_key":
        api_key = API_KEYS.get(provider_name, "")
        if not api_key or api_key.startswith("sk-your-") or api_key.startswith("your-"):
            return jsonify({"error": "API key for '{}' not configured in server/config.py".format(provider_name)}), 400
    elif auth_method == "oauth":
        api_key = ""
        if not is_authenticated():
            return jsonify({"error": "OAuth not authenticated. Visit /auth/login first."}), 400
    else:
        api_key = API_KEYS.get(provider_name, "")

    if not model:
        model = MODELS.get(provider_name, "")

    new_config = {
        "provider": provider_name,
        "api_key": api_key,
        "model": model,
        "auth_method": auth_method,
    }

    # Legacy → new lane propagation: when UI configures a legacy component,
    # propagate to all associated new lanes so actual routes pick up the change.
    _LEGACY_PROPAGATION = {
        "critical": ["critical_analysis", "critical_chat_claude"],
        "cve":      ["cve_analysis", "cve_verify"],
    }

    targets = [component] + _LEGACY_PROPAGATION.get(component, [])
    for target in targets:
        if target in provider_configs:
            provider_configs[target] = dict(new_config)
            providers.pop(target, None)
            _provider_cache_keys.pop(target, None)

    logger.info("Configured %s: %s/%s (propagated to: %s)", component, provider_name, model,
                ", ".join(targets))
    return jsonify({
        "status": "configured",
        "component": component,
        "provider": provider_name,
        "model": model,
    })


@app.route("/config/<component>", methods=["GET"])
def get_config(component):
    """Get current configuration for a component (without api_key)."""
    if component not in provider_configs:
        return jsonify({"error": "Unknown component"}), 400

    config = provider_configs[component]
    auth_method = config.get("auth_method", "api_key")
    if auth_method == "oauth":
        configured = is_authenticated()
    else:
        configured = bool(config["provider"] and config["api_key"])
    return jsonify({
        "provider": config["provider"],
        "model": config["model"],
        "configured": configured,
        "auth_method": auth_method,
    })


@app.route("/analyze/versions", methods=["POST"])
def analyze_versions():
    """Analyze HTTP items for software version exposure."""
    data = request.json
    if not data or "items" not in data:
        return jsonify({"error": "items array required"}), 400

    try:
        user_prompt = build_version_prompt(data["items"])
        result = do_chat("scanner", VERSION_ANALYSIS_SYSTEM, user_prompt, max_tokens=16384)
        return jsonify(result)
    except ProviderError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Version analysis failed")
        return jsonify({"error": "Analysis failed: {}".format(str(e))}), 500


@app.route("/analyze/weaknesses", methods=["POST"])
def analyze_weaknesses():
    """Analyze HTTP items for security weaknesses."""
    data = request.json
    if not data or "items" not in data:
        return jsonify({"error": "items array required"}), 400

    try:
        user_prompt = build_weakness_prompt(data["items"])
        result = do_chat("scanner", WEAKNESS_ANALYSIS_SYSTEM, user_prompt, max_tokens=16384)
        return jsonify(result)
    except ProviderError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Weakness analysis failed")
        return jsonify({"error": "Analysis failed: {}".format(str(e))}), 500


@app.route("/analyze/cve", methods=["POST"])
def analyze_cve():
    """Analyze HTTP items for CVEs and generate PoC."""
    data = request.json
    if not data or "items" not in data:
        return jsonify({"error": "items array required"}), 400

    session_id = data.get("session_id", generate_session_id("cve_analysis"))

    try:
        user_prompt = build_cve_prompt(data["items"])
        result = do_chat("cve_analysis", CVE_ANALYSIS_SYSTEM, user_prompt, session_id=session_id, max_tokens=16384)
        result["session_id"] = session_id
        return jsonify(result)
    except ProviderError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("CVE analysis failed")
        return jsonify({"error": "Analysis failed: {}".format(str(e))}), 500


@app.route("/analyze/response-check", methods=["POST"])
def response_check():
    """Check PoC execution results."""
    data = request.json
    if not data:
        return jsonify({"error": "Request body required"}), 400

    cve_info = data.get("cve_info", "")
    poc_code = data.get("poc_code", "")
    execution_output = data.get("execution_output", "")
    session_id = data.get("session_id")

    if not execution_output:
        return jsonify({"error": "execution_output is required"}), 400

    # Use cve_verify lane — separate from cve_analysis to prevent prompt contamination
    if not session_id:
        session_id = generate_session_id("cve_verify")

    try:
        user_prompt = build_response_check_prompt(cve_info, poc_code, execution_output)
        result = do_chat("cve_verify", RESPONSE_CHECK_SYSTEM, user_prompt, session_id=session_id, max_tokens=16384)
        if session_id:
            result["session_id"] = session_id
        return jsonify(result)
    except ProviderError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Response check failed")
        return jsonify({"error": "Check failed: {}".format(str(e))}), 500


@app.route("/analyze/critical/start", methods=["POST"])
def critical_start():
    """Start critical analysis session."""
    data = request.json
    if not data or "items" not in data:
        return jsonify({"error": "items array required"}), 400

    vuln_type = data.get("vuln_type", "SQL Injection")
    session_id = generate_session_id("critical_analysis")

    # Clear any existing conversation for this session
    with _state_lock:
        conversations[session_id] = []

    # Extract allowed domains from HTTP items for tool execution whitelist
    allowed_domains = _extract_domains_from_items(data["items"])
    with _state_lock:
        _session_allowed_domains[session_id] = allowed_domains
        _session_tool_counters[session_id] = {"count": 0}
    if allowed_domains:
        logger.info("Tool whitelist for %s: %s", session_id, sorted(allowed_domains))

    try:
        user_prompt = build_critical_prompt(data["items"], vuln_type)
        result = do_chat("critical_analysis", CRITICAL_ANALYSIS_SYSTEM, user_prompt, session_id=session_id, max_tokens=16384)
        result["session_id"] = session_id
        return jsonify(result)
    except ProviderError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Critical analysis start failed")
        return jsonify({"error": "Analysis failed: {}".format(str(e))}), 500


@app.route("/analyze/critical/continue", methods=["POST"])
def critical_continue():
    """Continue critical analysis with server-managed phase progression.

    If the AI outputs tool_requests, the server executes them, feeds results
    back to the AI, and repeats up to MAX_TOOL_ROUNDS times per call.
    """
    data = request.json
    if not data or "session_id" not in data:
        return jsonify({"error": "session_id required"}), 400

    session_id = data["session_id"]
    iteration = data.get("iteration", 1)
    poc_code = data.get("poc_code")

    # Server generates follow-up message (centralized prompt logic)
    # Falls back to client-provided message for backward compatibility
    user_message = data.get("message") or build_critical_followup(iteration, poc_code=poc_code)

    try:
        result = do_chat("critical_analysis", CRITICAL_ANALYSIS_SYSTEM, user_message, session_id=session_id, max_tokens=16384)
        result["session_id"] = session_id
        content = result.get("content", "")
        all_tool_executions = []

        # Tool execution loop: if AI includes tool_requests, execute and feed back
        parsed = result.get("parsed")
        tool_round = 0
        while (parsed and parsed.get("tool_requests")
               and tool_round < MAX_TOOL_ROUNDS):
            tool_round += 1
            tool_reqs = parsed["tool_requests"]
            logger.info("Tool round %d for %s: %d requests", tool_round, session_id, len(tool_reqs))

            # Execute the HTTP requests
            exec_results, exec_warnings = _execute_tool_requests(session_id, tool_reqs)

            # Record for client display
            all_tool_executions.append({
                "round": tool_round,
                "requests": [{"id": r.get("id"), "method": r.get("request_info", {}).get("method"),
                               "url": r.get("request_info", {}).get("url")} for r in exec_results],
                "results": exec_results,
                "warnings": exec_warnings,
            })

            # Format results and feed back to AI
            tool_msg = _format_tool_results_for_ai(exec_results, exec_warnings)
            followup = build_critical_followup(iteration, poc_code=poc_code, tool_results_msg=tool_msg)

            result = do_chat("critical_analysis", CRITICAL_ANALYSIS_SYSTEM, followup,
                             session_id=session_id, max_tokens=16384)
            result["session_id"] = session_id
            content = result.get("content", "")
            parsed = result.get("parsed")

        if all_tool_executions:
            result["tool_executions"] = all_tool_executions

        # Server-side phase validation
        is_valid, violation = validate_critical_phase(iteration + 1, content)
        if not is_valid:
            logger.warning("Phase violation in session %s: %s", session_id, violation)
            result["phase_violation"] = violation
            result["is_complete"] = False
        else:
            result["is_complete"] = "ANALYSIS_COMPLETE" in content

        return jsonify(result)
    except ProviderError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Critical analysis continue failed")
        return jsonify({"error": "Analysis failed: {}".format(str(e))}), 500


@app.route("/analyze/critical/chat", methods=["POST"])
def critical_chat():
    """Chat with AI during critical analysis."""
    data = request.json
    if not data or "message" not in data:
        return jsonify({"error": "message required"}), 400

    session_id = data.get("session_id", generate_session_id("critical_chat_claude"))

    try:
        result = do_chat("critical_chat_claude", CRITICAL_CHAT_SYSTEM, data["message"], session_id=session_id, max_tokens=16384)
        result["session_id"] = session_id
        return jsonify(result)
    except ProviderError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Critical chat failed")
        return jsonify({"error": "Chat failed: {}".format(str(e))}), 500


@app.route("/analyze/critical/chat/multi", methods=["POST"])
def critical_chat_multi():
    """Multi-AI chat: Claude, Codex, or Both.

    Request:
        message: user message
        analysis_session_id: (optional) read-only reference to analysis context
        mode: "claude" | "codex" | "both"
        claude_session_id: (optional) existing Claude chat session
        codex_session_id: (optional) existing Codex chat session
    """
    data = request.json
    if not data or "message" not in data:
        return jsonify({"error": "message required"}), 400

    message = data["message"]
    mode = data.get("mode", "claude").lower()
    analysis_session_id = data.get("analysis_session_id")

    # Build context prefix from analysis session if available
    context_prefix = ""
    if analysis_session_id:
        analysis_history = conversations.get(analysis_session_id, [])
        if analysis_history:
            # Extract last assistant message as analysis context summary
            for msg in reversed(analysis_history):
                if msg["role"] == "assistant":
                    snippet = msg["content"][:2000]
                    context_prefix = "[Analysis context]\n{}\n\n[User question]\n".format(snippet)
                    break

    enriched_message = context_prefix + message if context_prefix else message
    response_messages = []

    def run_lane(lane_component, lane_system_prompt, lane_session_key):
        """Run a single chat lane."""
        sid = data.get(lane_session_key) or generate_session_id(lane_component)
        try:
            result = do_chat(lane_component, lane_system_prompt, enriched_message,
                             session_id=sid, max_tokens=16384)
            return {
                "speaker": lane_component.replace("critical_chat_", ""),
                "session_id": sid,
                "content": result.get("content", ""),
                "elapsed": result.get("elapsed", 0),
                "hallucination_warnings": result.get("hallucination_warnings", []),
            }
        except ProviderError as e:
            return {
                "speaker": lane_component.replace("critical_chat_", ""),
                "session_id": sid,
                "error": str(e),
            }
        except Exception as e:
            return {
                "speaker": lane_component.replace("critical_chat_", ""),
                "session_id": sid,
                "error": "Chat failed: {}".format(str(e)),
            }

    try:
        if mode in ("claude", "both"):
            response_messages.append(
                run_lane("critical_chat_claude", CRITICAL_CHAT_CLAUDE_SYSTEM, "claude_session_id"))

        if mode in ("codex", "both"):
            response_messages.append(
                run_lane("critical_chat_codex", CRITICAL_CHAT_CODEX_SYSTEM, "codex_session_id"))

        if not response_messages:
            return jsonify({"error": "Invalid mode: {}. Use 'claude', 'codex', or 'both'.".format(mode)}), 400

        return jsonify({
            "mode": mode,
            "analysis_session_id": analysis_session_id,
            "messages": response_messages,
        })
    except Exception as e:
        logger.exception("Critical multi-chat failed")
        return jsonify({"error": "Multi-chat failed: {}".format(str(e))}), 500


@app.route("/sessions/<session_id>", methods=["GET"])
def get_session(session_id):
    """Get conversation history for a session."""
    history = conversations.get(session_id, [])
    return jsonify({
        "session_id": session_id,
        "messages": [
            {"role": m["role"], "content": m["content"][:500] + "..." if len(m["content"]) > 500 else m["content"]}
            for m in history
        ],
        "message_count": len(history),
    })


@app.route("/sessions/<session_id>", methods=["DELETE"])
def delete_session(session_id):
    """Clear conversation history and tool state for a session."""
    with _state_lock:
        if session_id in conversations:
            del conversations[session_id]
        _session_allowed_domains.pop(session_id, None)
        _session_tool_counters.pop(session_id, None)
    return jsonify({"status": "cleared", "session_id": session_id})


@app.route("/config/available", methods=["GET"])
def get_available_providers():
    """Get available providers (those with API keys configured)."""
    available = {}
    for prov, key in API_KEYS.items():
        if key and not key.startswith("sk-your-") and not key.startswith("your-"):
            available[prov] = MODELS.get(prov, "")
    return jsonify({
        "providers": available,
        "component_defaults": COMPONENT_DEFAULTS,
    })


# ── OAuth Endpoints ──────────────────────────────────────────

@app.route("/auth/login", methods=["GET"])
def auth_login():
    """Start OAuth login flow. Returns a page with the auth URL."""
    auth_url, flow_id = build_auth_url()
    html = """<!DOCTYPE html>
<html><head><title>Claude OAuth Login</title>
<style>
  body {{ font-family: -apple-system, sans-serif; max-width: 600px; margin: 60px auto; padding: 20px; }}
  h1 {{ color: #333; }}
  .step {{ margin: 20px 0; padding: 15px; background: #f5f5f5; border-radius: 8px; }}
  .step-num {{ font-weight: bold; color: #d97706; }}
  a.btn {{ display: inline-block; padding: 12px 24px; background: #d97706; color: white;
           text-decoration: none; border-radius: 6px; font-weight: bold; }}
  a.btn:hover {{ background: #b45309; }}
  input {{ width: 100%; padding: 10px; font-size: 14px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }}
  button {{ padding: 10px 20px; background: #2563eb; color: white; border: none;
           border-radius: 4px; cursor: pointer; font-size: 14px; }}
  button:hover {{ background: #1d4ed8; }}
  .success {{ color: #16a34a; font-weight: bold; }}
  .error {{ color: #dc2626; font-weight: bold; }}
</style>
</head><body>
<h1>Claude OAuth Login</h1>

<div class="step">
  <p><span class="step-num">Step 1:</span> Click the button below to login with your Claude account.</p>
  <a class="btn" href="{auth_url}" target="_blank">Login with Claude</a>
</div>

<div class="step">
  <p><span class="step-num">Step 2:</span> After login, you'll see a code on Anthropic's page. Copy the entire code (including the # part).</p>
</div>

<div class="step">
  <p><span class="step-num">Step 3:</span> Paste the code below and click Submit.</p>
  <form id="codeForm">
    <input type="text" id="codeInput" placeholder="Paste the code#state string here..." style="margin-bottom: 10px;" />
    <button type="submit">Submit</button>
  </form>
  <p id="result"></p>
</div>

<script>
document.getElementById('codeForm').addEventListener('submit', function(e) {{
  e.preventDefault();
  var code = document.getElementById('codeInput').value.trim();
  if (!code) return;
  document.getElementById('result').textContent = 'Exchanging code for tokens...';
  fetch('/auth/complete', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{code: code, flow_id: '{flow_id}'}})
  }})
  .then(function(r) {{ return r.json(); }})
  .then(function(data) {{
    if (data.error) {{
      document.getElementById('result').innerHTML = '<span class="error">Error: ' + data.error + '</span>';
    }} else {{
      document.getElementById('result').innerHTML = '<span class="success">Login successful! You can close this page. The server is ready.</span>';
    }}
  }})
  .catch(function(err) {{
    document.getElementById('result').innerHTML = '<span class="error">Request failed: ' + err + '</span>';
  }});
}});
</script>
</body></html>""".format(auth_url=auth_url, flow_id=flow_id)

    return html, 200, {"Content-Type": "text/html"}


@app.route("/auth/complete", methods=["POST"])
def auth_complete():
    """Exchange OAuth code for tokens."""
    data = request.json
    if not data or "code" not in data or "flow_id" not in data:
        return jsonify({"error": "code and flow_id required"}), 400

    result = exchange_code(data["code"], data["flow_id"])
    if "error" in result:
        return jsonify(result), 400

    # Invalidate cached providers so they pick up OAuth
    providers.clear()
    _provider_cache_keys.clear()

    logger.info("OAuth login successful")
    return jsonify({"status": "authenticated", "expires_at": result["expires_at"]})


@app.route("/auth/status", methods=["GET"])
def auth_status():
    """Check OAuth authentication status."""
    tokens = load_tokens()
    if tokens and tokens.get("access_token"):
        import time
        remaining = tokens.get("expires_at", 0) - time.time()
        return jsonify({
            "authenticated": True,
            "expires_in_seconds": max(0, int(remaining)),
            "token_prefix": tokens["access_token"][:20] + "...",
        })
    return jsonify({"authenticated": False})


@app.route("/auth/logout", methods=["POST"])
def auth_logout():
    """Clear OAuth tokens."""
    clear_tokens()
    providers.clear()
    _provider_cache_keys.clear()
    return jsonify({"status": "logged_out"})


@app.route("/vulnerability-types", methods=["GET"])
def get_vulnerability_types():
    """Get available vulnerability types for critical analysis."""
    return jsonify({"types": VULNERABILITY_TYPES})


@app.route("/logs/recent", methods=["GET"])
def recent_logs():
    """Get recent API call logs."""
    count = request.args.get("count", 20, type=int)
    log_file = os.path.join(LOG_DIR, "api_calls.log")

    if not os.path.exists(log_file):
        return jsonify({"logs": []})

    try:
        with open(log_file, "r") as f:
            lines = f.readlines()
        return jsonify({"logs": lines[-count:]})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Main ─────────────────────────────────────────────────────
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="AI Security Analyzer Server")
    parser.add_argument("--host", default="127.0.0.1", help="Host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=10512, help="Port (default: 10512)")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    args = parser.parse_args()

    logger.info("=" * 60)
    logger.info("AI Security Analyzer Server starting")
    logger.info("Listening on %s:%d", args.host, args.port)
    logger.info("Log directory: %s", LOG_DIR)
    for comp, cfg in provider_configs.items():
        auth = cfg.get("auth_method", "api_key")
        if auth == "oauth":
            status = "OAuth: " + ("authenticated" if is_authenticated() else "NOT logged in -> visit /auth/login")
        else:
            has_key = bool(cfg["api_key"] and not cfg["api_key"].startswith("sk-your-") and not cfg["api_key"].startswith("your-"))
            status = "key: " + ("OK" if has_key else "MISSING")
        logger.info("  %s: %s/%s [%s]", comp, cfg["provider"], cfg["model"], status)
    logger.info("=" * 60)

    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)
