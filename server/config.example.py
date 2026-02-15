"""
AI Security Analyzer - Configuration
Copy this file to config.py and fill in your settings.

  cp config.example.py config.py
"""

# ── Authentication Method ────────────────────────────────────
# "api_key" = API Key direct usage
# "oauth"   = OAuth token (Claude Pro/Max subscription, no extra API fee)
AUTH_METHOD = {
    "anthropic": "oauth",
    "openai": "api_key",
    "google": "api_key",
}

# ── API Keys (only needed when AUTH_METHOD is "api_key") ─────
API_KEYS = {
    "openai": "sk-your-openai-api-key-here",
    "anthropic": "",
    "google": "your-google-api-key-here",
}

# ── Models per Provider ──────────────────────────────────────
MODELS = {
    "openai": "gpt-4o",
    "anthropic": "claude-sonnet-4-5-20250929",
    "google": "gemini-2.0-flash",
}

# ── Component Default Assignments ────────────────────────────
# Which provider/model each component uses by default.
# Can be changed at runtime via the Burp UI or REST API.
COMPONENT_DEFAULTS = {
    "scanner":  {"provider": "anthropic", "model": "claude-sonnet-4-5-20250929"},
    "cve":      {"provider": "anthropic", "model": "claude-sonnet-4-5-20250929"},
    "critical": {"provider": "anthropic", "model": "claude-sonnet-4-5-20250929"},
}
