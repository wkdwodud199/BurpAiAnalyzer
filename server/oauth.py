"""
OAuth 2.0 PKCE flow for Anthropic Claude.
Authenticates via claude.ai and obtains access tokens for API usage.
"""
import os
import json
import time
import base64
import hashlib
import secrets
import logging
import requests

logger = logging.getLogger(__name__)

# ── OAuth Constants ──────────────────────────────────────────
CLIENT_ID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
AUTH_URL = "https://claude.ai/oauth/authorize"
TOKEN_URL = "https://console.anthropic.com/v1/oauth/token"
REDIRECT_URI = "https://console.anthropic.com/oauth/code/callback"
SCOPES = "org:create_api_key user:profile user:inference"

TOKENS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "oauth_tokens.json")

# In-memory state for pending OAuth flows
_pending_flows = {}


def generate_pkce():
    """Generate PKCE code_verifier and code_challenge."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("utf-8")).digest()
    ).decode("utf-8").rstrip("=")
    return verifier, challenge


def build_auth_url():
    """Build the OAuth authorization URL and store PKCE verifier.
    Returns (auth_url, flow_id).
    """
    verifier, challenge = generate_pkce()
    flow_id = secrets.token_hex(8)

    _pending_flows[flow_id] = {
        "verifier": verifier,
        "created_at": time.time(),
    }

    params = {
        "code": "true",
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": SCOPES,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": verifier,
    }

    from urllib.parse import urlencode
    url = "{}?{}".format(AUTH_URL, urlencode(params))
    return url, flow_id


def exchange_code(code_with_state, flow_id):
    """Exchange authorization code for access/refresh tokens.

    Args:
        code_with_state: The 'code#state' string from Anthropic's callback page.
        flow_id: The flow ID returned by build_auth_url().

    Returns:
        dict with access_token, refresh_token, expires_at on success.
        dict with error on failure.
    """
    flow = _pending_flows.pop(flow_id, None)
    if not flow:
        return {"error": "Invalid or expired flow_id. Please start login again."}

    # Parse code#state format
    parts = code_with_state.strip().split("#")
    auth_code = parts[0]
    state = parts[1] if len(parts) > 1 else None

    payload = {
        "code": auth_code,
        "state": state,
        "grant_type": "authorization_code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": flow["verifier"],
    }

    try:
        resp = requests.post(
            TOKEN_URL,
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )

        if not resp.ok:
            logger.error("Token exchange failed: %d %s", resp.status_code, resp.text)
            return {"error": "Token exchange failed: {} {}".format(resp.status_code, resp.text[:200])}

        data = resp.json()
        tokens = {
            "access_token": data["access_token"],
            "refresh_token": data["refresh_token"],
            "expires_at": time.time() + data.get("expires_in", 28800),
        }

        _save_tokens(tokens)
        logger.info("OAuth tokens obtained successfully (expires in %ds)", data.get("expires_in", 28800))
        return tokens

    except Exception as e:
        logger.exception("Token exchange error")
        return {"error": "Token exchange error: {}".format(str(e))}


def refresh_access_token():
    """Refresh the access token using the stored refresh token.

    Returns:
        dict with new tokens on success, dict with error on failure.
    """
    tokens = load_tokens()
    if not tokens or not tokens.get("refresh_token"):
        return {"error": "No refresh token available. Please login again."}

    payload = {
        "grant_type": "refresh_token",
        "refresh_token": tokens["refresh_token"],
        "client_id": CLIENT_ID,
    }

    try:
        resp = requests.post(
            TOKEN_URL,
            headers={"Content-Type": "application/json"},
            json=payload,
            timeout=30,
        )

        if not resp.ok:
            logger.error("Token refresh failed: %d %s", resp.status_code, resp.text)
            return {"error": "Token refresh failed. Please login again."}

        data = resp.json()
        new_tokens = {
            "access_token": data["access_token"],
            "refresh_token": data.get("refresh_token", tokens["refresh_token"]),
            "expires_at": time.time() + data.get("expires_in", 28800),
        }

        _save_tokens(new_tokens)
        logger.info("OAuth tokens refreshed successfully")
        return new_tokens

    except Exception as e:
        logger.exception("Token refresh error")
        return {"error": "Token refresh error: {}".format(str(e))}


def get_valid_access_token():
    """Get a valid access token, refreshing if needed.

    Returns:
        access_token string on success, None on failure.
    """
    tokens = load_tokens()
    if not tokens or not tokens.get("access_token"):
        return None

    # Refresh if expiring within 5 minutes
    if tokens.get("expires_at", 0) < time.time() + 300:
        logger.info("Access token expiring soon, refreshing...")
        result = refresh_access_token()
        if "error" in result:
            logger.error("Auto-refresh failed: %s", result["error"])
            return None
        return result["access_token"]

    return tokens["access_token"]


def load_tokens():
    """Load tokens from file."""
    if not os.path.exists(TOKENS_FILE):
        return None
    try:
        with open(TOKENS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return None


def _save_tokens(tokens):
    """Save tokens to file."""
    try:
        with open(TOKENS_FILE, "w") as f:
            json.dump(tokens, f, indent=2)
        logger.debug("Tokens saved to %s", TOKENS_FILE)
    except Exception as e:
        logger.error("Failed to save tokens: %s", str(e))


def is_authenticated():
    """Check if we have valid OAuth tokens."""
    tokens = load_tokens()
    if not tokens or not tokens.get("access_token"):
        return False
    return True


def clear_tokens():
    """Remove stored tokens (logout)."""
    if os.path.exists(TOKENS_FILE):
        os.remove(TOKENS_FILE)
        logger.info("OAuth tokens cleared")
