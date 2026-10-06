"""Dork grammar + safety policy (§24, §45).

Operators are declared generically (matching QuerySpec fields) and compiled per
engine. The safe policy REJECTS query intents that target credentials, private
access or exploitation — the system is defensive/discovery oriented only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Generic operator vocabulary (mapped to QuerySpec fields by providers/base.py)
OPERATOR_GRAMMAR: dict[str, str] = {
    "exact":     "quoted phrase match",
    "exclude":   "-term negation",
    "site":      "domain-limited search",
    "filetype":  "document type filter",
    "intitle":   "title-term constraint",
    "inurl":     "url-term constraint",
    "inbody":    "body-term constraint",
    "daterange": "publication window (julian)",
    "language":  "language filter",
    "region":    "regional filter",
}

CATEGORIES = [
    "EXACT_MATCH", "SITE", "DOMAIN", "TITLE", "URL", "BODY_TEXT", "FILETYPE",
    "DOCUMENT", "DATE_RANGE", "LANGUAGE", "LOCATION", "ORGANIZATION", "PERSON",
    "USERNAME", "PUBLIC_EMAIL_CONTEXT", "PUBLIC_PHONE_CONTEXT", "SOCIAL",
    "GITHUB", "CODE", "PACKAGE", "INFRASTRUCTURE", "CERTIFICATE", "CTI",
    "VULNERABILITY", "ARCHIVE", "NEWS", "GOVERNMENT", "ACADEMIC",
    "PROCUREMENT", "LEGAL",
]

# ---- safety policy (§45): never build credential/exploitation search --------
FORBIDDEN_PATTERNS = [
    re.compile(r"(?i)\b(inurl|intext|filetype)\s*:\s*[\"']?(wp-content/uploads|\.env\b|id_rsa|shadow\b)"),
    re.compile(r"(?i)\b(passwords?|credentials?|logins?)\s+(list|database|dump|leak|combo|txt|file)"),
    re.compile(r"(?i)\b(session[_ ]?cookie|auth[_ ]?token|api[_ ]?key)\s*(leak|dump|harvest|search)"),
    re.compile(r"(?i)\bprivate key\b.*\b(filetype|inurl|ext)\b"),
    re.compile(r"(?i)\bcombo ?list\b"),
    re.compile(r"(?i)\bconfig\.php\b.*\bdatabase\b"),
    re.compile(r"(?i)\b(admin panel|login page)\b.*\b(default|bypass|exploit)\b"),
    re.compile(r"(?i)\b(exploit|0day|sqlmap|lfi|rfi|xss payload|webshell)\b"),
    re.compile(r"(?i)\bbypass\b.*\b(captcha|paywall|2fa|mfa|authentication)\b"),
    re.compile(r"(?i)\bstolen\b.*\b(session|account|cookie)\b"),
]

_INJECTION = re.compile(r"(?i)(ignore (previous|above) instructions|system prompt)")


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str = ""
    category: str = "SAFE"


def check_query_safety(query_string: str, *, family: str = "") -> PolicyDecision:
    """Deterministic gate executed BEFORE any provider call (§27, §45)."""
    if _INJECTION.search(query_string):
        return PolicyDecision(False, "prompt-injection-like content in query string",
                              "INJECTION")
    for pat in FORBIDDEN_PATTERNS:
        if pat.search(query_string):
            return PolicyDecision(
                False,
                "query targets credentials/private access/exploitation material; "
                "TraceAtlas policy prohibits collection objective of this kind (§45)",
                "CREDENTIAL_OR_EXPLOIT")
    return PolicyDecision(True, "", "SAFE")


def redact_exposure(text: str) -> tuple[str, bool]:
    """If captured content INCIDENTALLY contains secret material, keep the
    finding but remove the value (§12: flag exposure, do not use it)."""
    from traceatlas.search_discovery.providers.base import redact_secrets
    clean, n = redact_secrets(text)
    return clean, n > 0
