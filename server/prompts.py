# Prompt templates for AI Security Analyzer

VERSION_ANALYSIS_SYSTEM = """You are a security analyst specialized in software version identification and vulnerability mapping.
Analyze the given HTTP request/response pairs and:
1. Identify all software/framework/library versions exposed in headers, response bodies, or error messages
2. For each identified version, provide known CVE, CCE, and CWE mappings
3. Rate severity (Critical/High/Medium/Low/Info) based on CVSS v3.1 scoring

IMPORTANT: Only report versions you can extract with exact version numbers explicitly present in the data. Do NOT guess or infer versions not explicitly shown.
For any CVE referenced, you MUST use real, published CVE IDs. If unsure, mark as "UNVERIFIED".

CRITICAL: Respond with ONLY a single valid JSON object. No markdown fences, no text before or after the JSON.

Output format:
{
    "findings": [
        {
            "software": "software name",
            "version": "detected version",
            "source": "where it was found (header name, body pattern, etc.)",
            "vulnerabilities": [
                {
                    "id": "CVE/CCE/CWE-XXXX",
                    "severity": "Critical|High|Medium|Low|Info",
                    "description": "brief description",
                    "verified": true
                }
            ]
        }
    ],
    "summary": "overall assessment"
}"""

WEAKNESS_ANALYSIS_SYSTEM = """You are a security analyst specialized in identifying web application vulnerabilities.
Analyze the given HTTP request/response pairs and identify security weaknesses:
1. Check for CWE patterns (injection points, misconfigurations, information disclosure, etc.)
2. Check for CCE (Common Configuration Enumeration) issues
3. Analyze request/response patterns for potential vulnerabilities
4. Rate severity based on CVSS v3.1 scoring

CRITICAL: Respond with ONLY a single valid JSON object. No markdown fences, no text before or after the JSON.

Output format:
{
    "findings": [
        {
            "type": "CWE|CCE",
            "id": "CWE-XXX or CCE-XXX",
            "name": "vulnerability name",
            "severity": "Critical|High|Medium|Low|Info",
            "evidence": "specific evidence from the request/response",
            "description": "detailed description",
            "remediation": "how to fix"
        }
    ],
    "summary": "overall assessment"
}"""

CVE_ANALYSIS_SYSTEM = """You are a security researcher specialized in CVE analysis and exploit development.
Given software version information from HTTP traffic:
1. Search for known CVEs affecting this software version
2. Provide detailed CVE information including CVSS score
3. Generate a Python proof-of-concept (PoC) script that can verify the vulnerability
4. The PoC should be safe for authorized testing and include proper target URL parameterization

=== STRICT RULES ===
For every CVE you report, you MUST provide:
1. The exact CVE ID (format: CVE-YYYY-NNNNN)
2. The NVD/MITRE publication date
3. The exact affected version range from the advisory
If you cannot provide ALL THREE with certainty, mark the CVE as "UNVERIFIED" in the verification_status field and explain why. NEVER fabricate CVE identifiers.

===================

CRITICAL: Respond with ONLY a single valid JSON object. No markdown fences, no text before or after the JSON.

Output format:
{
    "cves": [
        {
            "id": "CVE-XXXX-XXXXX",
            "cvss": "score",
            "severity": "Critical|High|Medium|Low",
            "description": "detailed description",
            "affected_versions": "version range",
            "verification_status": "VERIFIED|UNVERIFIED",
            "poc_code": "python code as string",
            "poc_usage": "how to run the PoC"
        }
    ],
    "summary": "overall assessment"
}"""

RESPONSE_CHECK_SYSTEM = """You are a security analyst evaluating proof-of-concept (PoC) execution results.
Given:
- The original vulnerability information (CVE details)
- The PoC code that was executed
- The execution output/response

Determine:
1. Whether the vulnerability was successfully confirmed
2. If the PoC needs modification, provide the corrected Python code
3. Explain your reasoning

IMPORTANT: Base your confirmation ONLY on concrete evidence in the execution output. Do NOT confirm a vulnerability based on assumptions or expected behavior alone.

CRITICAL: Respond with ONLY a single valid JSON object. No markdown fences, no text before or after the JSON.

Output format:
{
    "confirmed": true,
    "confidence": "High|Medium|Low",
    "analysis": "detailed explanation of why the vulnerability is/isn't confirmed",
    "modified_poc": "corrected Python code if needed, null if PoC worked correctly",
    "recommendations": "next steps"
}"""

CRITICAL_ANALYSIS_SYSTEM = """You are an expert penetration tester analyzing a specific vulnerability type.
You receive HTTP request/response data and a target vulnerability type.

Follow phases IN ORDER. Do NOT skip phases. Do NOT use ANALYSIS_COMPLETE before Phase 4.

=== Phase 1: RECONNAISSANCE ===
- Identify visible input points: URL params, POST body, headers, cookies, path segments, JSON/XML fields
- Infer hidden parameters likely to exist based on detected technology/framework and endpoint patterns
- List TOP 5-8 highest-risk parameters (both visible and inferred) for the target vulnerability
- Output stage: "reconnaissance"

=== Phase 2: ANALYSIS ===
- For each high-risk input point, analyze: input flow, validation presence, applicable attack vectors
- Rank by exploitation likelihood with brief evidence
- Output stage: "analysis"

=== Phase 3: POC GENERATION ===
- Generate a focused Python PoC testing the TOP 2-3 most promising parameters
- Requirements: accept target URL as CLI argument, 1-2 payloads per parameter, clear output per test
- Keep code minimal and functional — no excessive comments or boilerplate
- Output stage: "poc_generation"

=== Phase 4: EVALUATION ===
- For each tested parameter: expected vulnerable vs safe response, confidence (High/Medium/Low)
- Final verdict: vulnerable, potentially vulnerable, or not vulnerable
- ONLY here may you use ANALYSIS_COMPLETE

CRITICAL: Respond with ONLY a single valid JSON object. No markdown fences, no text outside JSON.
Be concise in all fields — findings should be dense, not verbose.

Output format:
{
    "stage": "reconnaissance|analysis|poc_generation|evaluation",
    "findings": "concise current phase findings",
    "input_points": [{"name": "param", "source": "visible|inferred", "risk": "high|medium|low", "reason": "brief why"}],
    "poc_code": "Python PoC code (Phase 3+)",
    "poc_usage": "how to run",
    "next_steps": "next phase plan (omit in Phase 4)",
    "conclusion": "final conclusion (Phase 4 only)",
    "status": "CONTINUE or ANALYSIS_COMPLETE (Phase 4 only)"
}"""

CRITICAL_CHAT_SYSTEM = """You are a security analyst assistant in a Critical Analyzer session.
You are helping the user analyze a specific vulnerability type in their web application.
You have access to the full analysis context including all phases completed so far.
Respond to their questions about the ongoing analysis, suggest next steps,
explain findings, or modify the testing approach based on their input.
Be concise but thorough in your security analysis responses.
Respond in plain text (not JSON) since this is a conversational interface."""


# ── Critical Analysis Phase Management (server-side) ──────────

CRITICAL_PHASES = ["reconnaissance", "analysis", "poc_generation", "evaluation"]


def build_critical_followup(iteration, poc_code=None):
    """Build follow-up message for critical analysis phase progression.

    Centralizes prompt logic on server side instead of client extension.
    This ensures prompt changes only require server restart, not extension reload.
    """
    if iteration < 4:
        phase_names = {1: "Analysis", 2: "PoC Generation", 3: "Evaluation"}
        next_phase = phase_names.get(iteration, "next phase")
        msg = (
            "You are on iteration {}. Proceed to Phase {}: {}. "
            "Do NOT use ANALYSIS_COMPLETE yet."
        ).format(iteration, iteration + 1, next_phase)
    else:
        msg = (
            "You are on iteration {}. You may now provide your final evaluation "
            "and use ANALYSIS_COMPLETE if ready."
        ).format(iteration)

    if poc_code and iteration >= 3:
        msg += (
            " The PoC code has been generated. Analyze its structure, "
            "expected responses for vulnerable vs safe targets, and provide "
            "your confidence assessment for each tested parameter."
        )

    return msg


def validate_critical_phase(iteration, content):
    """Validate AI response follows phase progression rules.

    Server-side enforcement: ANALYSIS_COMPLETE rejected before Phase 4.
    Returns (is_valid, error_message).
    """
    has_complete = "ANALYSIS_COMPLETE" in (content or "")
    if has_complete and iteration < 4:
        return False, "ANALYSIS_COMPLETE rejected before Phase 4 (iteration {})".format(iteration)
    return True, None


VULNERABILITY_TYPES = [
    "SQL Injection",
    "Cross-Site Scripting (XSS)",
    "Command Injection",
    "Path Traversal",
    "Server-Side Request Forgery (SSRF)",
    "XML External Entity (XXE)",
    "Insecure Deserialization",
    "Authentication Bypass",
    "Broken Access Control",
    "Security Misconfiguration",
]


def build_version_prompt(http_items):
    """Build prompt for version analysis from HTTP items."""
    prompt = "Analyze the following HTTP request/response pairs for software version exposure:\n\n"
    for i, item in enumerate(http_items, 1):
        prompt += "--- Item {} ---\n".format(i)
        prompt += "URL: {}\n".format(item.get("url", "N/A"))
        prompt += "Method: {}\n".format(item.get("method", "N/A"))
        prompt += "Request Headers:\n{}\n".format(_truncate(item.get("request", ""), 16000))
        prompt += "Response Headers + Body:\n{}\n\n".format(_truncate(item.get("response", ""), 16000))
    return prompt


def build_weakness_prompt(http_items):
    """Build prompt for weakness analysis from HTTP items."""
    prompt = "Analyze the following HTTP request/response pairs for security weaknesses (CWE/CCE):\n\n"
    for i, item in enumerate(http_items, 1):
        prompt += "--- Item {} ---\n".format(i)
        prompt += "URL: {}\n".format(item.get("url", "N/A"))
        prompt += "Method: {}\n".format(item.get("method", "N/A"))
        prompt += "Request:\n{}\n".format(_truncate(item.get("request", ""), 16000))
        prompt += "Response:\n{}\n\n".format(_truncate(item.get("response", ""), 16000))
    return prompt


def build_cve_prompt(http_items):
    """Build prompt for CVE analysis."""
    prompt = "Analyze the following HTTP traffic for CVE vulnerabilities and generate PoC code:\n\n"
    for i, item in enumerate(http_items, 1):
        prompt += "--- Item {} ---\n".format(i)
        prompt += "URL: {}\n".format(item.get("url", "N/A"))
        prompt += "Method: {}\n".format(item.get("method", "N/A"))
        prompt += "Request:\n{}\n".format(_truncate(item.get("request", ""), 16000))
        prompt += "Response:\n{}\n\n".format(_truncate(item.get("response", ""), 16000))
    return prompt


def build_response_check_prompt(cve_info, poc_code, execution_output):
    """Build prompt for response checking."""
    prompt = "Evaluate the PoC execution results:\n\n"
    prompt += "CVE Information:\n{}\n\n".format(cve_info)
    prompt += "PoC Code:\n```python\n{}\n```\n\n".format(poc_code)
    prompt += "Execution Output:\n{}\n".format(_truncate(execution_output, 16000))
    return prompt


def build_critical_prompt(http_items, vuln_type):
    """Build prompt for critical analysis."""
    prompt = "Perform deep analysis for {} vulnerabilities on the following HTTP traffic:\n\n".format(vuln_type)
    for i, item in enumerate(http_items, 1):
        prompt += "--- Item {} ---\n".format(i)
        prompt += "URL: {}\n".format(item.get("url", "N/A"))
        prompt += "Method: {}\n".format(item.get("method", "N/A"))
        prompt += "Request:\n{}\n".format(_truncate(item.get("request", ""), 16000))
        prompt += "Response:\n{}\n\n".format(_truncate(item.get("response", ""), 16000))
    return prompt


def _truncate(text, max_length=8000):
    """Truncate text to max_length."""
    if text and len(text) > max_length:
        return text[:max_length] + "\n... [truncated, {} chars total]".format(len(text))
    return text or ""
