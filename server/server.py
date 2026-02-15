"""
AI Security Analyzer - Middleware Server
Flask server that bridges Burp Suite Extension with AI APIs.
Provides REST endpoints for security analysis operations.
"""
import os
import sys
import json
import time
import logging
from datetime import datetime
from logging.handlers import RotatingFileHandler

from flask import Flask, request, jsonify
from flask_cors import CORS

from providers import create_provider, ProviderError
from prompts import (
    VERSION_ANALYSIS_SYSTEM, WEAKNESS_ANALYSIS_SYSTEM,
    CVE_ANALYSIS_SYSTEM, RESPONSE_CHECK_SYSTEM,
    CRITICAL_ANALYSIS_SYSTEM, CRITICAL_CHAT_SYSTEM,
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
_SESSION_HISTORY_LIMITS = {
    "critical_chat_": 10,  # Chat: moderate context
    "critical_": 12,       # 4-phase analysis: needs phase results
    "cve_": 8,             # CVE: analysis + verification rounds
}
_DEFAULT_MAX_HISTORY = 10


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
        raise ProviderError("OAuth not authenticated. Visit http://127.0.0.1:8089/auth/login to login.")

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


def get_conversation(session_id):
    """Get or create conversation history."""
    if session_id not in conversations:
        conversations[session_id] = []
    return conversations[session_id]


def add_to_conversation(session_id, role, content):
    """Add message to conversation with sliding window.

    For critical analysis sessions, preserves phase summaries so later phases
    retain context from earlier reconnaissance and analysis results.
    Uses session-type-based history limits instead of a global constant.
    """
    history = get_conversation(session_id)
    history.append({"role": role, "content": content})
    max_hist = _get_max_history(session_id)
    # Keep system message + last max_hist messages
    if len(history) > max_hist + 1:
        system_msgs = [m for m in history if m["role"] == "system"]
        other_msgs = [m for m in history if m["role"] != "system"]

        # For critical sessions, build a summary of trimmed phases
        is_critical = session_id and session_id.startswith("critical_") and not session_id.startswith("critical_chat_")
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

    return None


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

    provider_configs[component] = {
        "provider": provider_name,
        "api_key": api_key,
        "model": model,
        "auth_method": auth_method,
    }

    # Invalidate cached provider so next request creates a new one
    providers.pop(component, None)
    _provider_cache_keys.pop(component, None)

    logger.info("Configured %s: %s/%s", component, provider_name, model)
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

    session_id = data.get("session_id", "cve_{}".format(int(time.time())))

    try:
        user_prompt = build_cve_prompt(data["items"])
        result = do_chat("cve", CVE_ANALYSIS_SYSTEM, user_prompt, session_id=session_id, max_tokens=16384)
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

    try:
        user_prompt = build_response_check_prompt(cve_info, poc_code, execution_output)
        result = do_chat("cve", RESPONSE_CHECK_SYSTEM, user_prompt, session_id=session_id, max_tokens=16384)
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
    session_id = "critical_{}".format(int(time.time()))

    # Clear any existing conversation for this session
    conversations[session_id] = []

    try:
        user_prompt = build_critical_prompt(data["items"], vuln_type)
        result = do_chat("critical", CRITICAL_ANALYSIS_SYSTEM, user_prompt, session_id=session_id, max_tokens=16384)
        result["session_id"] = session_id
        return jsonify(result)
    except ProviderError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Critical analysis start failed")
        return jsonify({"error": "Analysis failed: {}".format(str(e))}), 500


@app.route("/analyze/critical/continue", methods=["POST"])
def critical_continue():
    """Continue critical analysis with server-managed phase progression."""
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
        result = do_chat("critical", CRITICAL_ANALYSIS_SYSTEM, user_message, session_id=session_id, max_tokens=16384)
        result["session_id"] = session_id
        content = result.get("content", "")

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

    session_id = data.get("session_id", "critical_chat_{}".format(int(time.time())))

    try:
        result = do_chat("critical", CRITICAL_CHAT_SYSTEM, data["message"], session_id=session_id, max_tokens=16384)
        result["session_id"] = session_id
        return jsonify(result)
    except ProviderError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        logger.exception("Critical chat failed")
        return jsonify({"error": "Chat failed: {}".format(str(e))}), 500


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
    """Clear conversation history for a session."""
    if session_id in conversations:
        del conversations[session_id]
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
    parser.add_argument("--port", type=int, default=8089, help="Port (default: 8089)")
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
