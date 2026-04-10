"""
OWASP Checker Web API — Vercel Python Serverless Function
Wraps the CLI scanner into a JSON API endpoint.
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler

# ─── Add lib/ to path so we can import scanner modules ───────────────────────
_LIB = os.path.join(os.path.dirname(__file__), "lib")
if _LIB not in sys.path:
    sys.path.insert(0, _LIB)

# ─── CORS helper ─────────────────────────────────────────────────────────────
CORS_HEADERS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json",
}


def _json_response(handler: BaseHTTPRequestHandler, status: int, body: dict):
    data = json.dumps(body).encode()
    handler.send_response(status)
    for k, v in CORS_HEADERS.items():
        handler.send_header(k, v)
    handler.send_header("Content-Length", str(len(data)))
    handler.end_headers()
    handler.wfile.write(data)


class handler(BaseHTTPRequestHandler):

    def log_message(self, *args):
        pass  # silence default access log

    # ── OPTIONS preflight ─────────────────────────────────────────────────────
    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in CORS_HEADERS.items():
            self.send_header(k, v)
        self.end_headers()

    # ── POST /api/scan ────────────────────────────────────────────────────────
    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0))
            raw    = self.rfile.read(length) if length else b"{}"
            body   = json.loads(raw)
        except Exception as exc:
            _json_response(self, 400, {"error": f"Bad JSON: {exc}"})
            return

        url = (body.get("url") or "").strip()
        if not url:
            _json_response(self, 400, {"error": "url is required"})
            return

        # Reject obviously internal/localhost targets
        import re
        if re.search(r"(localhost|127\.|10\.|192\.168\.|::1)", url):
            _json_response(self, 400, {"error": "Scanning internal/private addresses is not allowed."})
            return

        try:
            result = run_scan(body)
            _json_response(self, 200, result)
        except Exception as exc:
            traceback.print_exc()
            _json_response(self, 500, {"error": str(exc)})


# ─────────────────────────────────────────────────────────────────────────────
# Core scan runner (no argparse)
# ─────────────────────────────────────────────────────────────────────────────

def run_scan(params: dict) -> dict:
    from utils import ScanConfig, normalise_url
    from scanner import TargetScanner
    from analyzer import ScanAggregator, PassiveAnalyzer
    from thread_engine import ThreadEngine
    from payloads import (
        get_library,
        IDOR_PATHS, SENSITIVE_PATHS, DEFAULT_CREDENTIALS,
        SQL_ERROR_PAYLOADS, SQL_BOOLEAN_PAYLOADS, SQL_UNION_PAYLOADS,
        XSS_PAYLOADS, SSTI_PAYLOADS, CMD_INJECTION_PAYLOADS,
        PATH_TRAVERSAL_PAYLOADS, XXE_PAYLOADS, SSRF_PAYLOADS,
        OPEN_REDIRECT_PAYLOADS, AUTH_BYPASS_PAYLOADS,
    )

    url        = normalise_url(params["url"])
    quick      = bool(params.get("quick", True))   # default quick=True for web
    workers    = min(int(params.get("workers", 3)), 6)
    timeout    = min(int(params.get("timeout", 8)), 15)
    checks     = params.get("checks") or []        # [] means all

    cookie_str = params.get("cookie", "")
    cookies    = {}
    if cookie_str:
        for part in cookie_str.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k.strip()] = v.strip()

    # Determine which checks to run
    run_all  = not checks
    run_sqli = run_all or "sqli"     in checks
    run_xss  = run_all or "xss"      in checks
    run_ssti = run_all or "ssti"     in checks
    run_cmdi = run_all or "cmdi"     in checks
    run_lfi  = run_all or "lfi"      in checks
    run_xxe  = run_all or "xxe"      in checks
    run_ssrf = run_all or "ssrf"     in checks
    run_redir= run_all or "redirect" in checks
    run_hdrs = run_all or "headers"  in checks
    run_path = run_all or "paths"    in checks
    run_auth = run_all or "auth"     in checks

    cfg = ScanConfig(
        target_url=url,
        workers=workers,
        delay=0.1,
        timeout=timeout,
        time_delay=5.0,
        verify_ssl=False,
        follow_redirects=False,
        cookies=cookies,
        scan_sqli=run_sqli,
        scan_xss=run_xss,
        scan_ssti=run_ssti,
        scan_cmdi=run_cmdi,
        scan_lfi=run_lfi,
        scan_xxe=run_xxe,
        scan_ssrf=run_ssrf,
        scan_redirect=run_redir,
        scan_headers=run_hdrs,
        scan_paths=run_path,
        scan_auth=run_auth,
        quick_mode=quick,
        verbose=False,
    )

    agg     = ScanAggregator()
    engine  = ThreadEngine(cfg, agg, on_finding=None)
    passive = PassiveAnalyzer()
    t_start = time.perf_counter()

    # 1. Crawl
    scanner = TargetScanner(cfg)
    target  = scanner.scan()

    # 2. Passive header analysis
    if target.baseline and target.baseline.ok and run_hdrs:
        h_findings = passive.analyze_headers(target.baseline, target.url)
        agg.add_all(h_findings)

    # 3. Active injections
    payloads = _select_payloads(
        quick, run_sqli, run_xss, run_ssti, run_cmdi,
        run_lfi, run_xxe, run_ssrf, run_redir,
        SQL_ERROR_PAYLOADS, SQL_BOOLEAN_PAYLOADS, SQL_UNION_PAYLOADS,
        XSS_PAYLOADS, SSTI_PAYLOADS, CMD_INJECTION_PAYLOADS,
        PATH_TRAVERSAL_PAYLOADS, XXE_PAYLOADS, SSRF_PAYLOADS,
        OPEN_REDIRECT_PAYLOADS, AUTH_BYPASS_PAYLOADS,
    )
    if payloads and (target.forms or target.query_params):
        engine.run_injections(target, payloads)

    # 4. Path scan
    if run_path:
        all_paths = list(dict.fromkeys(SENSITIVE_PATHS + IDOR_PATHS))
        if quick:
            all_paths = all_paths[:50]
        engine.run_path_scan(target, all_paths)

    # 5. Auth check
    if run_auth and target.forms:
        creds = DEFAULT_CREDENTIALS[:20] if quick else DEFAULT_CREDENTIALS
        engine.run_auth_check(target, creds)

    duration = time.perf_counter() - t_start

    # Serialize findings
    findings_out = []
    for f in agg.findings:
        findings_out.append({
            "severity":       f.severity.value,
            "description":    f.description,
            "owasp_category": f.owasp_category.value,
            "injection_type": f.injection_type.value if f.injection_type else None,
            "url":            f.url,
            "parameter":      f.parameter,
            "payload":        f.payload,
            "evidence":       f.evidence,
            "confidence":     f.confidence,
            "remediation":    f.remediation,
        })

    stats = agg.stats()
    return {
        "url":         url,
        "duration":    round(duration, 2),
        "findings":    findings_out,
        "stats":       stats,
        "tech_stack":  list(target.tech_stack),
        "forms_found": len(target.forms),
        "params_found":len(target.query_params),
    }


def _select_payloads(
    quick,
    run_sqli, run_xss, run_ssti, run_cmdi,
    run_lfi, run_xxe, run_ssrf, run_redir,
    SQL_ERROR, SQL_BOOL, SQL_UNION,
    XSS, SSTI, CMDI, LFI, XXE, SSRF, REDIR, AUTH,
):
    payloads = []
    if run_sqli:
        payloads += SQL_ERROR + SQL_BOOL + SQL_UNION
    if run_xss:
        payloads += XSS
    if run_ssti:
        payloads += SSTI
    if run_cmdi:
        payloads += CMDI
    if run_lfi:
        payloads += LFI
    if run_xxe:
        payloads += XXE
    if run_ssrf:
        payloads += SSRF
    if run_redir:
        payloads += REDIR + AUTH

    if quick:
        from payloads import Severity
        payloads = [p for p in payloads
                    if p.severity.value in ("CRITICAL", "HIGH") or p.expected]

    seen, unique = set(), []
    for p in payloads:
        if p.raw not in seen:
            seen.add(p.raw)
            unique.append(p)
    return unique
