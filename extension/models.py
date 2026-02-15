# -*- coding: utf-8 -*-
"""
Data models for AI Security Analyzer Burp Extension.
Jython 2.7 compatible (Python 2.7 syntax).
"""


class HttpItem:
    """Represents an HTTP request/response pair from Burp proxy history."""

    def __init__(self, index, method, url, status_code, content_type,
                 request_str, response_str, host, port, protocol, path, length):
        self.index = index
        self.method = method
        self.url = url
        self.status_code = status_code
        self.content_type = content_type
        self.request_str = request_str
        self.response_str = response_str
        self.host = host
        self.port = port
        self.protocol = protocol
        self.path = path
        self.length = length

    def to_dict(self):
        """Convert to dict for JSON serialization (sending to server)."""
        return {
            "url": self.url,
            "method": self.method,
            "status_code": self.status_code,
            "content_type": self.content_type,
            "host": self.host,
            "port": self.port,
            "protocol": self.protocol,
            "path": self.path,
            "request": self.request_str[:8000] if self.request_str else "",
            "response": self.response_str[:8000] if self.response_str else "",
        }

    def __repr__(self):
        return "HttpItem(%s %s [%s])" % (self.method, self.url, self.status_code)


class AnalysisResult:
    """Represents an AI analysis result."""

    def __init__(self, result_type, content, elapsed=0, usage=None, error=None):
        self.result_type = result_type  # "version", "weakness", "cve", "critical"
        self.content = content
        self.elapsed = elapsed
        self.usage = usage or {}
        self.error = error
        self.timestamp = None

        import time
        self.timestamp = time.time()

    @property
    def is_error(self):
        return self.error is not None

    def __repr__(self):
        if self.is_error:
            return "AnalysisResult(ERROR: %s)" % self.error
        return "AnalysisResult(%s, %.1fs)" % (self.result_type, self.elapsed)


class ChatMessage:
    """Represents a message in the Critical Analyzer chat."""

    ROLE_USER = "user"
    ROLE_ASSISTANT = "assistant"
    ROLE_SYSTEM = "system"

    def __init__(self, role, content):
        self.role = role
        self.content = content
        self.timestamp = None

        import time
        self.timestamp = time.time()

    def __repr__(self):
        preview = self.content[:50] + "..." if len(self.content) > 50 else self.content
        return "ChatMessage(%s: %s)" % (self.role, preview)


class CVEEntry:
    """Represents a CVE finding from analysis."""

    def __init__(self, cve_id, cvss, severity, description, affected_versions,
                 poc_code=None, poc_usage=None):
        self.cve_id = cve_id
        self.cvss = cvss
        self.severity = severity
        self.description = description
        self.affected_versions = affected_versions
        self.poc_code = poc_code
        self.poc_usage = poc_usage

    def __repr__(self):
        return "CVEEntry(%s [%s] %s)" % (self.cve_id, self.severity, self.cvss)


class FindingEntry:
    """Represents a security finding (version/weakness analysis)."""

    def __init__(self, finding_type, finding_id, name, severity, description,
                 evidence=None, remediation=None, source=None):
        self.finding_type = finding_type  # "CVE", "CWE", "CCE"
        self.finding_id = finding_id
        self.name = name
        self.severity = severity
        self.description = description
        self.evidence = evidence
        self.remediation = remediation
        self.source = source

    def __repr__(self):
        return "FindingEntry(%s-%s [%s])" % (self.finding_type, self.finding_id, self.severity)
