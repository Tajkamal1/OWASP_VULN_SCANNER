"""
=============================================================================
  OWASP Top 10 Checker — analyzer.py
=============================================================================
  Module   : Response Analysis Engine
  Purpose  : Analyse HTTP responses against each OWASP category, produce
             structured findings with confidence scores and evidence.
=============================================================================
"""

from __future__ import annotations

import re
import time
import difflib
import logging
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple, Any

from payloads import (
    Payload, OWASPCategory, InjectionType, Severity,
    SECURITY_HEADERS, DANGEROUS_RESPONSE_HEADERS, WEAK_CRYPTO_INDICATORS,
    IDOR_PATHS, SENSITIVE_PATHS,
)
from utils import HTTPResponse, ScanConfig, colour, RED, GREEN, YELLOW, CYAN, MAGENTA, BOLD, RESET, DIM

log = logging.getLogger("owasp.analyzer")


# ─────────────────────────────────────────────────────────────────────────────
# Finding
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    owasp_category: OWASPCategory
    injection_type: Optional[InjectionType]
    severity:       Severity
    url:            str
    parameter:      Optional[str]        # form field / URL param name
    payload:        Optional[str]        # exact payload that triggered
    evidence:       str                  # extracted proof from response
    confidence:     int                  # 0-100
    description:    str
    remediation:    str                  = ""
    request_method: str                  = "GET"
    response_code:  int                  = 0
    response_time:  float                = 0.0
    tags:           List[str]            = field(default_factory=list)

    @property
    def severity_colour(self) -> str:
        colours = {
            Severity.CRITICAL: RED + BOLD,
            Severity.HIGH:     RED,
            Severity.MEDIUM:   YELLOW + BOLD,
            Severity.LOW:      YELLOW,
            Severity.INFO:     CYAN,
        }
        return colours.get(self.severity, "")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "owasp_category":  self.owasp_category.value,
            "injection_type":  self.injection_type.value if self.injection_type else None,
            "severity":        self.severity.value,
            "url":             self.url,
            "parameter":       self.parameter,
            "payload":         self.payload,
            "evidence":        self.evidence,
            "confidence":      self.confidence,
            "description":     self.description,
            "remediation":     self.remediation,
            "request_method":  self.request_method,
            "response_code":   self.response_code,
            "response_time":   self.response_time,
            "tags":            self.tags,
        }


# ─────────────────────────────────────────────────────────────────────────────
# SQL Error Signatures
# ─────────────────────────────────────────────────────────────────────────────

SQL_ERROR_PATTERNS: List[Tuple[str, str, int]] = [
    # (pattern, engine, confidence)
    (r"you have an error in your sql syntax", "MySQL", 95),
    (r"warning: mysql", "MySQL", 85),
    (r"unclosed quotation mark after the character string", "MSSQL", 95),
    (r"quoted string not properly terminated", "Oracle", 90),
    (r"pg_query\(\).*failed", "PostgreSQL", 90),
    (r"supplied argument is not a valid mysql", "MySQL", 85),
    (r"error: syntax error at or near", "PostgreSQL", 90),
    (r"ora-\d{5}", "Oracle", 95),
    (r"microsoft ole db provider for sql server", "MSSQL", 90),
    (r"odbc microsoft access driver", "MSAccess", 90),
    (r"jdbc\|microsoft\|sql server", "MSSQL", 85),
    (r"com\.mysql\.jdbc\.exceptions", "MySQL", 90),
    (r"org\.postgresql\.util\.psqlexception", "PostgreSQL", 95),
    (r"com\.microsoft\.sqlserver\.jdbc", "MSSQL", 90),
    (r"sqlite_error|sqlite3\.operationalerror", "SQLite", 95),
    (r"mysql_num_rows\(\) expects parameter 1", "MySQL", 85),
    (r"division by zero", "Generic", 60),
    (r"mysql_fetch_array\(\) expects parameter", "MySQL", 80),
    (r"invalid use of group function", "MySQL", 85),
    (r"column .* does not exist", "PostgreSQL", 75),
    (r"table or view does not exist", "Oracle", 80),
    (r"sqlstate\[", "Generic", 75),
]

XSS_REFLECTION_PATTERNS: List[str] = [
    r"<script[^>]*>.*?alert",
    r"onerror\s*=",
    r"onload\s*=",
    r"onfocus\s*=",
    r"<svg[^>]*onload",
    r"javascript:",
    r"<iframe[^>]*src",
]

TEMPLATE_ERROR_PATTERNS: List[Tuple[str, str]] = [
    (r"jinja2\.exceptions\.", "Jinja2"),
    (r"TemplateNotFound", "Jinja2"),
    (r"TemplateSyntaxError", "Generic"),
    (r"Twig_Error|TwigError", "Twig"),
    (r"mako\.exceptions\.", "Mako"),
    (r"SmartyCompilerException", "Smarty"),
    (r"freemarker\.core\.", "FreeMarker"),
    (r"django\.template", "Django"),
    (r"tornado\.template", "Tornado"),
]

CMD_OUTPUT_PATTERNS: List[Tuple[str, int]] = [
    (r"uid=\d+\(.+?\)\s+gid=\d+", 95),
    (r"root:x:0:0:", 95),
    (r"(linux|darwin|freebsd) .* #\d+", 80),
    (r"volume in drive [a-z]", 75),        # Windows dir
    (r"directory of c:\\", 75),
    (r"www-data|apache|nginx", 55),
]

PATH_TRAVERSAL_PATTERNS: List[Tuple[str, int]] = [
    (r"root:x:0:0:", 95),
    (r"bin:x:\d+:\d+:", 90),
    (r"\[fonts\]", 90),                   # win.ini
    (r"for 16-bit app support", 85),
    (r"linux version \d+\.\d+", 90),
    (r"path=.+?home=", 80),
]

SSRF_INDICATORS: List[Tuple[str, int]] = [
    (r"ami-id|instance-id|local-ipv4", 90),  # AWS metadata
    (r"computeMetadata|project/project-id", 90),  # GCP
    (r"ssh-rsa|ssh-dss|-----begin rsa", 85),  # SSH keys
    (r'"token"\s*:\s*"[A-Za-z0-9+/=]{20,}"', 80),  # JWT/access token
    (r"pong\s*$|\+pong", 75),               # Redis
    (r"mysql_native_password|5\.7\.\d+ mysql", 80),  # MySQL
    (r'"compute#instance"', 85),            # GCP
]

REDIRECT_INDICATORS: List[str] = [
    "evil.com", "attacker.com", "localtest.me",
]

# ─────────────────────────────────────────────────────────────────────────────
# Remediation Database
# ─────────────────────────────────────────────────────────────────────────────

REMEDIATIONS: Dict[InjectionType, str] = {
    InjectionType.SQL_ERROR:    "Use parameterized queries / prepared statements. Never interpolate user input into SQL.",
    InjectionType.SQL_BOOLEAN:  "Use parameterized queries. Implement least-privilege DB accounts.",
    InjectionType.SQL_TIME:     "Use parameterized queries. Monitor and limit query execution time.",
    InjectionType.SQL_UNION:    "Use parameterized queries. Restrict error verbosity in production.",
    InjectionType.XSS_REFLECTED:"Output-encode all user-controlled data. Implement a strict Content-Security-Policy.",
    InjectionType.XSS_STORED:  "Output-encode stored data. Use CSP. Sanitize HTML with an allowlist.",
    InjectionType.XSS_DOM:     "Avoid dangerous DOM sinks (innerHTML, eval). Use textContent.",
    InjectionType.SSTI:        "Never pass user input to template render() functions. Use sandboxed environments.",
    InjectionType.CMD_INJECTION:"Avoid shell calls. Use language APIs instead. Whitelist allowable inputs.",
    InjectionType.PATH_TRAVERSAL:"Canonicalize and validate paths. Restrict to an allowlisted base directory.",
    InjectionType.XXE:         "Disable external entity processing in your XML parser. Use JSON where possible.",
    InjectionType.OPEN_REDIRECT:"Validate redirect URLs against an allowlist. Never trust user-supplied URLs.",
    InjectionType.SSRF:        "Allowlist permitted outbound URLs/IPs. Block internal IP ranges at firewall.",
    InjectionType.IDOR:        "Enforce access control checks on all resource IDs. Use indirect references.",
    InjectionType.HEADER_INJECTION:"Validate and sanitize all values placed in HTTP response headers.",
}


# ─────────────────────────────────────────────────────────────────────────────
# Response Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class ResponseAnalyzer:
    """
    Analyse one HTTP response to determine if a payload triggered a vulnerability.
    Returns a Finding (or None) for each check.
    """

    def __init__(self, cfg: ScanConfig):
        self.cfg = cfg

    # ── Public entry point ───────────────────────────────────────────────────

    def analyze(self, payload: Payload, resp: HTTPResponse,
                baseline: HTTPResponse, url: str,
                parameter: Optional[str] = None,
                method: str = "POST") -> Optional[Finding]:
        """Route to the correct checker based on injection type."""
        t = payload.injection_type
        if t in (InjectionType.SQL_ERROR, InjectionType.SQL_BOOLEAN,
                 InjectionType.SQL_TIME, InjectionType.SQL_UNION):
            return self._check_sqli(payload, resp, baseline, url, parameter, method)
        if t in (InjectionType.XSS_REFLECTED, InjectionType.XSS_STORED, InjectionType.XSS_DOM):
            return self._check_xss(payload, resp, baseline, url, parameter, method)
        if t == InjectionType.SSTI:
            return self._check_ssti(payload, resp, baseline, url, parameter, method)
        if t == InjectionType.CMD_INJECTION:
            return self._check_cmdi(payload, resp, baseline, url, parameter, method)
        if t == InjectionType.PATH_TRAVERSAL:
            return self._check_lfi(payload, resp, baseline, url, parameter, method)
        if t == InjectionType.XXE:
            return self._check_xxe(payload, resp, url, parameter, method)
        if t == InjectionType.SSRF:
            return self._check_ssrf(payload, resp, url, parameter, method)
        if t == InjectionType.OPEN_REDIRECT:
            return self._check_redirect(payload, resp, url, parameter, method)
        if t == InjectionType.HEADER_INJECTION:
            return self._check_header_injection(payload, resp, url, parameter, method)
        return None

    # ── Helper: body changed significantly ───────────────────────────────────

    def _body_changed(self, baseline: HTTPResponse, resp: HTTPResponse,
                      threshold: float = 0.10) -> bool:
        if baseline.body_hash == resp.body_hash:
            return False
        ratio = difflib.SequenceMatcher(None,
                                        baseline.body[:5000],
                                        resp.body[:5000]).ratio()
        return (1 - ratio) > threshold

    def _extract_evidence(self, body: str, pattern: str,
                           context: int = 80) -> str:
        m = re.search(pattern, body, re.IGNORECASE | re.DOTALL)
        if not m:
            return ""
        start = max(0, m.start() - context)
        end   = min(len(body), m.end() + context)
        snippet = body[start:end].strip()
        return snippet[:300]

    # ── SQL Injection ─────────────────────────────────────────────────────────

    def _check_sqli(self, p: Payload, resp: HTTPResponse,
                    baseline: HTTPResponse, url: str,
                    param: Optional[str], method: str) -> Optional[Finding]:
        body_lower = resp.body.lower()

        # Time-based
        if p.time_based and resp.elapsed >= self.cfg.time_delay:
            return Finding(
                owasp_category=p.owasp_category,
                injection_type=p.injection_type,
                severity=Severity.HIGH,
                url=url, parameter=param,
                payload=p.raw,
                evidence=f"Response delayed {resp.elapsed:.2f}s (threshold {self.cfg.time_delay}s)",
                confidence=80,
                description=f"Time-based blind SQL injection via '{param}'",
                remediation=REMEDIATIONS[p.injection_type],
                request_method=method, response_code=resp.status_code,
                response_time=resp.elapsed, tags=["sqli", "time-based"],
            )

        # Error-based
        for pattern, engine, conf in SQL_ERROR_PATTERNS:
            if re.search(pattern, body_lower):
                ev = self._extract_evidence(resp.body, pattern)
                return Finding(
                    owasp_category=p.owasp_category,
                    injection_type=p.injection_type,
                    severity=Severity.HIGH,
                    url=url, parameter=param,
                    payload=p.raw,
                    evidence=ev or f"SQL error from {engine} detected",
                    confidence=conf,
                    description=f"SQL injection ({engine}) detected in '{param}'",
                    remediation=REMEDIATIONS[p.injection_type],
                    request_method=method, response_code=resp.status_code,
                    response_time=resp.elapsed,
                    tags=["sqli", "error-based", engine.lower()],
                )

        # Expected value / regex
        if p.expected and p.expected in resp.body:
            if self._body_changed(baseline, resp):
                return Finding(
                    owasp_category=p.owasp_category,
                    injection_type=p.injection_type,
                    severity=p.severity,
                    url=url, parameter=param, payload=p.raw,
                    evidence=f"Expected value '{p.expected}' found in response",
                    confidence=70,
                    description=f"SQL injection suspected in '{param}' (expected value reflected)",
                    remediation=REMEDIATIONS[p.injection_type],
                    request_method=method, response_code=resp.status_code,
                    response_time=resp.elapsed, tags=["sqli"],
                )

        if p.expect_regex and re.search(p.expect_regex, resp.body, re.I):
            ev = self._extract_evidence(resp.body, p.expect_regex)
            return Finding(
                owasp_category=p.owasp_category,
                injection_type=p.injection_type,
                severity=p.severity,
                url=url, parameter=param, payload=p.raw,
                evidence=ev,
                confidence=75,
                description=f"SQL injection pattern matched in '{param}'",
                remediation=REMEDIATIONS[p.injection_type],
                request_method=method, response_code=resp.status_code,
                response_time=resp.elapsed, tags=["sqli"],
            )
        return None

    # ── XSS ───────────────────────────────────────────────────────────────────

    def _check_xss(self, p: Payload, resp: HTTPResponse,
                   baseline: HTTPResponse, url: str,
                   param: Optional[str], method: str) -> Optional[Finding]:
        # Direct reflection
        raw_lower = p.raw.lower()
        body_lower = resp.body.lower()

        # Unescaped reflection
        if raw_lower in body_lower:
            # Check it's not HTML-escaped
            escaped = p.raw.replace("<", "&lt;").replace(">", "&gt;")
            if escaped.lower() not in body_lower:
                ev = self._extract_evidence(resp.body, re.escape(p.raw[:30]))
                return Finding(
                    owasp_category=p.owasp_category,
                    injection_type=p.injection_type,
                    severity=Severity.HIGH,
                    url=url, parameter=param, payload=p.raw,
                    evidence=ev or f"Payload reflected unescaped in response",
                    confidence=88,
                    description=f"Reflected XSS in '{param}' — payload not encoded",
                    remediation=REMEDIATIONS[p.injection_type],
                    request_method=method, response_code=resp.status_code,
                    response_time=resp.elapsed, tags=["xss", "reflected"],
                )

        # Event handler / script tag in body
        for pat in XSS_REFLECTION_PATTERNS:
            if re.search(pat, resp.body, re.I):
                if p.raw[:20].lower() in body_lower:
                    ev = self._extract_evidence(resp.body, pat)
                    return Finding(
                        owasp_category=p.owasp_category,
                        injection_type=p.injection_type,
                        severity=Severity.HIGH,
                        url=url, parameter=param, payload=p.raw,
                        evidence=ev,
                        confidence=80,
                        description=f"XSS event handler reflected in '{param}'",
                        remediation=REMEDIATIONS[p.injection_type],
                        request_method=method, response_code=resp.status_code,
                        response_time=resp.elapsed, tags=["xss"],
                    )
        return None

    # ── SSTI ──────────────────────────────────────────────────────────────────

    def _check_ssti(self, p: Payload, resp: HTTPResponse,
                    baseline: HTTPResponse, url: str,
                    param: Optional[str], method: str) -> Optional[Finding]:
        if p.expected and p.expected in resp.body:
            if p.expected not in baseline.body:
                sev = Severity.CRITICAL if any(
                    kw in p.description.lower() for kw in ["rce", "command", "system"]
                ) else Severity.HIGH
                return Finding(
                    owasp_category=p.owasp_category,
                    injection_type=p.injection_type,
                    severity=sev,
                    url=url, parameter=param, payload=p.raw,
                    evidence=f"Template evaluated: payload '{p.raw}' → '{p.expected}'",
                    confidence=92,
                    description=f"SSTI confirmed in '{param}' — template expression evaluated",
                    remediation=REMEDIATIONS[p.injection_type],
                    request_method=method, response_code=resp.status_code,
                    response_time=resp.elapsed,
                    tags=["ssti", p.engine or ""],
                )

        if p.expect_regex and re.search(p.expect_regex, resp.body, re.I):
            ev = self._extract_evidence(resp.body, p.expect_regex)
            return Finding(
                owasp_category=p.owasp_category,
                injection_type=p.injection_type,
                severity=p.severity,
                url=url, parameter=param, payload=p.raw,
                evidence=ev,
                confidence=85,
                description=f"SSTI pattern matched in '{param}' — {p.description}",
                remediation=REMEDIATIONS[p.injection_type],
                request_method=method, response_code=resp.status_code,
                response_time=resp.elapsed, tags=["ssti"],
            )

        # Template engine error in response
        for pat, engine in TEMPLATE_ERROR_PATTERNS:
            if re.search(pat, resp.body, re.I):
                if not re.search(pat, baseline.body, re.I):
                    ev = self._extract_evidence(resp.body, pat)
                    return Finding(
                        owasp_category=p.owasp_category,
                        injection_type=p.injection_type,
                        severity=Severity.MEDIUM,
                        url=url, parameter=param, payload=p.raw,
                        evidence=ev,
                        confidence=70,
                        description=f"SSTI — {engine} error triggered by '{param}'",
                        remediation=REMEDIATIONS[p.injection_type],
                        request_method=method, response_code=resp.status_code,
                        response_time=resp.elapsed, tags=["ssti", "error", engine.lower()],
                    )
        return None

    # ── Command Injection ─────────────────────────────────────────────────────

    def _check_cmdi(self, p: Payload, resp: HTTPResponse,
                    baseline: HTTPResponse, url: str,
                    param: Optional[str], method: str) -> Optional[Finding]:
        if p.time_based and resp.elapsed >= self.cfg.time_delay:
            return Finding(
                owasp_category=p.owasp_category,
                injection_type=p.injection_type,
                severity=Severity.CRITICAL,
                url=url, parameter=param, payload=p.raw,
                evidence=f"Response delayed {resp.elapsed:.2f}s — blind command injection",
                confidence=80,
                description=f"Blind command injection via '{param}' (time-based)",
                remediation=REMEDIATIONS[p.injection_type],
                request_method=method, response_code=resp.status_code,
                response_time=resp.elapsed, tags=["cmdi", "blind"],
            )

        for pat, conf in CMD_OUTPUT_PATTERNS:
            if re.search(pat, resp.body, re.I):
                if not re.search(pat, baseline.body, re.I):
                    ev = self._extract_evidence(resp.body, pat)
                    return Finding(
                        owasp_category=p.owasp_category,
                        injection_type=p.injection_type,
                        severity=Severity.CRITICAL,
                        url=url, parameter=param, payload=p.raw,
                        evidence=ev,
                        confidence=conf,
                        description=f"Command injection confirmed in '{param}' — OS output in response",
                        remediation=REMEDIATIONS[p.injection_type],
                        request_method=method, response_code=resp.status_code,
                        response_time=resp.elapsed, tags=["cmdi", "rce"],
                    )
        return None

    # ── Path Traversal / LFI ──────────────────────────────────────────────────

    def _check_lfi(self, p: Payload, resp: HTTPResponse,
                   baseline: HTTPResponse, url: str,
                   param: Optional[str], method: str) -> Optional[Finding]:
        for pat, conf in PATH_TRAVERSAL_PATTERNS:
            if re.search(pat, resp.body, re.I):
                if not re.search(pat, baseline.body, re.I):
                    ev = self._extract_evidence(resp.body, pat)
                    return Finding(
                        owasp_category=p.owasp_category,
                        injection_type=p.injection_type,
                        severity=Severity.CRITICAL,
                        url=url, parameter=param, payload=p.raw,
                        evidence=ev,
                        confidence=conf,
                        description=f"Path traversal / LFI confirmed in '{param}'",
                        remediation=REMEDIATIONS[p.injection_type],
                        request_method=method, response_code=resp.status_code,
                        response_time=resp.elapsed, tags=["lfi", "path-traversal"],
                    )
        return None

    # ── XXE ───────────────────────────────────────────────────────────────────

    def _check_xxe(self, p: Payload, resp: HTTPResponse,
                   url: str, param: Optional[str], method: str) -> Optional[Finding]:
        patterns = [r"root:x:0:0:", r"\[fonts\]", r"linux version", r"PATH=.*HOME="]
        for pat in patterns:
            if re.search(pat, resp.body, re.I):
                ev = self._extract_evidence(resp.body, pat)
                return Finding(
                    owasp_category=p.owasp_category,
                    injection_type=p.injection_type,
                    severity=Severity.CRITICAL,
                    url=url, parameter=param, payload=p.raw[:100] + "…",
                    evidence=ev,
                    confidence=92,
                    description="XXE injection confirmed — server-side file read",
                    remediation=REMEDIATIONS[p.injection_type],
                    request_method=method, response_code=resp.status_code,
                    response_time=resp.elapsed, tags=["xxe"],
                )
        return None

    # ── SSRF ──────────────────────────────────────────────────────────────────

    def _check_ssrf(self, p: Payload, resp: HTTPResponse,
                    url: str, param: Optional[str], method: str) -> Optional[Finding]:
        for pat, conf in SSRF_INDICATORS:
            if re.search(pat, resp.body, re.I):
                ev = self._extract_evidence(resp.body, pat)
                sev = Severity.CRITICAL if "meta" in p.raw or "credentials" in p.raw else Severity.HIGH
                return Finding(
                    owasp_category=p.owasp_category,
                    injection_type=p.injection_type,
                    severity=sev,
                    url=url, parameter=param, payload=p.raw,
                    evidence=ev,
                    confidence=conf,
                    description=f"SSRF confirmed via '{param}' — internal resource accessed",
                    remediation=REMEDIATIONS[p.injection_type],
                    request_method=method, response_code=resp.status_code,
                    response_time=resp.elapsed, tags=["ssrf"],
                )
        # Status code / content-length heuristic
        if resp.status_code == 200 and len(resp.body) > 0:
            for indicator in REDIRECT_INDICATORS:
                if indicator in p.raw and len(resp.body) > 100:
                    pass  # Would need OOB to confirm
        return None

    # ── Open Redirect ─────────────────────────────────────────────────────────

    def _check_redirect(self, p: Payload, resp: HTTPResponse,
                        url: str, param: Optional[str], method: str) -> Optional[Finding]:
        # Was redirected to our payload URL?
        if resp.redirect_url:
            for indicator in REDIRECT_INDICATORS:
                if indicator in resp.redirect_url:
                    return Finding(
                        owasp_category=p.owasp_category,
                        injection_type=p.injection_type,
                        severity=Severity.MEDIUM,
                        url=url, parameter=param, payload=p.raw,
                        evidence=f"Redirected to: {resp.redirect_url}",
                        confidence=90,
                        description=f"Open redirect via '{param}'",
                        remediation=REMEDIATIONS[p.injection_type],
                        request_method=method, response_code=resp.status_code,
                        response_time=resp.elapsed, tags=["open-redirect"],
                    )

        # Location header in body
        location = resp.headers.get("Location", "")
        for indicator in REDIRECT_INDICATORS:
            if indicator in location:
                return Finding(
                    owasp_category=p.owasp_category,
                    injection_type=p.injection_type,
                    severity=Severity.MEDIUM,
                    url=url, parameter=param, payload=p.raw,
                    evidence=f"Location header: {location}",
                    confidence=85,
                    description=f"Open redirect — Location header points to external site",
                    remediation=REMEDIATIONS[p.injection_type],
                    request_method=method, response_code=resp.status_code,
                    response_time=resp.elapsed, tags=["open-redirect"],
                )
        return None

    # ── HTTP Header Injection ─────────────────────────────────────────────────

    def _check_header_injection(self, p: Payload, resp: HTTPResponse,
                                url: str, param: Optional[str], method: str) -> Optional[Finding]:
        if "Set-Cookie" in resp.headers and "evil" in resp.headers.get("Set-Cookie", ""):
            return Finding(
                owasp_category=p.owasp_category,
                injection_type=p.injection_type,
                severity=Severity.HIGH,
                url=url, parameter=param, payload=p.raw,
                evidence=f"Set-Cookie: {resp.headers['Set-Cookie']}",
                confidence=88,
                description=f"HTTP Response Splitting — injected cookie via '{param}'",
                remediation=REMEDIATIONS[p.injection_type],
                request_method=method, response_code=resp.status_code,
                response_time=resp.elapsed, tags=["crlf", "header-injection"],
            )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Passive Checks (no payloads needed)
# ─────────────────────────────────────────────────────────────────────────────

class PassiveAnalyzer:
    """Passive checks against the baseline response (A02, A05, A06)."""

    def analyze_headers(self, resp: HTTPResponse, url: str) -> List[Finding]:
        findings: List[Finding] = []

        # Missing security headers (A05)
        missing = [h for h in SECURITY_HEADERS if h not in resp.headers]
        if missing:
            findings.append(Finding(
                owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                injection_type=None,
                severity=Severity.LOW,
                url=url, parameter=None, payload=None,
                evidence=f"Missing: {', '.join(missing)}",
                confidence=95,
                description="Missing security response headers",
                remediation=("Add missing HTTP security headers: "
                             "Strict-Transport-Security, Content-Security-Policy, "
                             "X-Frame-Options, X-Content-Type-Options, Referrer-Policy."),
                tags=["headers", "misconfiguration"],
            ))

        # Verbose server headers (A05 / A06)
        for hdr, sigs in DANGEROUS_RESPONSE_HEADERS.items():
            val = resp.headers.get(hdr, "")
            if val:
                matched = not sigs or any(s.lower() in val.lower() for s in sigs)
                if matched:
                    findings.append(Finding(
                        owasp_category=OWASPCategory.A05_SECURITY_MISCONFIGURATION,
                        injection_type=None,
                        severity=Severity.LOW,
                        url=url, parameter=None, payload=None,
                        evidence=f"{hdr}: {val}",
                        confidence=90,
                        description=f"Version disclosure via '{hdr}' header",
                        remediation=f"Remove or mask the '{hdr}' response header.",
                        tags=["info-disclosure", "headers"],
                    ))

        # Cookie flags (A02)
        set_cookie = resp.headers.get("Set-Cookie", "")
        if set_cookie:
            missing_flags = []
            if "Secure" not in set_cookie:
                missing_flags.append("Secure")
            if "HttpOnly" not in set_cookie:
                missing_flags.append("HttpOnly")
            if "SameSite" not in set_cookie:
                missing_flags.append("SameSite")
            if missing_flags:
                findings.append(Finding(
                    owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                    injection_type=None,
                    severity=Severity.MEDIUM,
                    url=url, parameter=None, payload=None,
                    evidence=f"Set-Cookie: {set_cookie[:150]}",
                    confidence=95,
                    description=f"Cookie missing flags: {', '.join(missing_flags)}",
                    remediation="Set Secure, HttpOnly, and SameSite=Lax/Strict on all cookies.",
                    tags=["cookies", "crypto"],
                ))

        # HTTP (no TLS) (A02)
        if url.startswith("http://"):
            findings.append(Finding(
                owasp_category=OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES,
                injection_type=None,
                severity=Severity.HIGH,
                url=url, parameter=None, payload=None,
                evidence="Target uses plain HTTP — data transmitted in cleartext",
                confidence=100,
                description="No TLS/HTTPS — connection is not encrypted",
                remediation="Enforce HTTPS. Redirect all HTTP traffic to HTTPS. Add HSTS.",
                tags=["crypto", "tls"],
            ))

        return findings

    def analyze_path(self, path: str, resp: HTTPResponse, url: str) -> Optional[Finding]:
        """Check if a sensitive path returned interesting content."""
        if resp.status_code in (200, 206):
            cat = OWASPCategory.A05_SECURITY_MISCONFIGURATION
            sev = Severity.HIGH
            desc = f"Sensitive path accessible: {path}"

            # Credential files
            if any(x in path for x in [".env", "config", "credentials", "secrets", "wp-config"]):
                sev = Severity.CRITICAL
                cat = OWASPCategory.A02_CRYPTOGRAPHIC_FAILURES
                desc = f"Credential/config file exposed: {path}"

            # Git
            elif ".git" in path:
                sev = Severity.HIGH
                desc = f"Git repository exposed: {path}"

            # Actuator
            elif "actuator" in path:
                sev = Severity.HIGH
                cat = OWASPCategory.A05_SECURITY_MISCONFIGURATION
                desc = f"Spring Boot Actuator endpoint exposed: {path}"

            # Backup
            elif any(x in path for x in [".bak", ".sql", ".zip", ".tar"]):
                sev = Severity.CRITICAL
                desc = f"Backup file exposed: {path}"

            return Finding(
                owasp_category=cat,
                injection_type=None,
                severity=sev,
                url=url, parameter=None, payload=None,
                evidence=f"HTTP {resp.status_code} — {len(resp.body)} bytes returned",
                confidence=85,
                description=desc,
                remediation="Remove or restrict access to sensitive files. Use web server rules.",
                tags=["path-exposure", "misconfiguration"],
            )
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Scan Aggregator
# ─────────────────────────────────────────────────────────────────────────────

class ScanAggregator:
    """Collects and deduplicates findings across the full scan."""

    def __init__(self):
        self._findings: List[Finding] = []
        self._seen: set = set()

    def add(self, f: Finding) -> None:
        key = (f.owasp_category, f.injection_type, f.parameter,
               f.payload, f.url, f.severity)
        if key not in self._seen:
            self._seen.add(key)
            self._findings.append(f)

    def add_all(self, findings: List[Finding]) -> None:
        for f in findings:
            self.add(f)

    @property
    def findings(self) -> List[Finding]:
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO]
        return sorted(self._findings, key=lambda f: order.index(f.severity))

    def by_category(self, cat: OWASPCategory) -> List[Finding]:
        return [f for f in self._findings if f.owasp_category == cat]

    def by_severity(self, sev: Severity) -> List[Finding]:
        return [f for f in self._findings if f.severity == sev]

    def stats(self) -> Dict[str, Any]:
        from collections import Counter
        sev_counts = Counter(f.severity.value for f in self._findings)
        cat_counts = Counter(f.owasp_category.value for f in self._findings)
        return {
            "total":      len(self._findings),
            "by_severity": dict(sev_counts),
            "by_category": dict(cat_counts),
            "critical":    sev_counts.get("CRITICAL", 0),
            "high":        sev_counts.get("HIGH", 0),
            "medium":      sev_counts.get("MEDIUM", 0),
            "low":         sev_counts.get("LOW", 0),
        }

    def to_dict_list(self) -> List[Dict[str, Any]]:
        return [f.to_dict() for f in self.findings]
