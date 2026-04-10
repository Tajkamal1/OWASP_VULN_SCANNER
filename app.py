"""
OWASP Shield — Flask Web Server
Real-time vulnerability scanner with Server-Sent Events streaming.
"""

from __future__ import annotations

import json
import os
import queue
import re
import sys
import threading
import time
import uuid
from datetime import datetime

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

# ── Add lib/ to path ──────────────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

# ── In-memory scan registry ───────────────────────────────────────────────────
# { scan_id: { "queue": Queue, "result": dict|None, "done": bool, "error": str|None } }
_SCANS: dict[str, dict] = {}
_LOCK  = threading.Lock()

BLOCKED_HOSTS = re.compile(
    r"(localhost|127\.|10\.\d+\.\d+\.\d+|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|0\.0\.0\.0)",
    re.I,
)

# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    body = request.get_json(force=True, silent=True) or {}
    url  = (body.get("url") or "").strip()

    if not url:
        return jsonify(error="url is required"), 400
    if not url.startswith(("http://", "https://")):
        return jsonify(error="URL must start with http:// or https://"), 400
    if BLOCKED_HOSTS.search(url):
        return jsonify(error="Scanning private/internal addresses is not allowed."), 400

    scan_id = str(uuid.uuid4())
    q       = queue.Queue()

    with _LOCK:
        _SCANS[scan_id] = {"queue": q, "result": None, "done": False, "error": None}

    t = threading.Thread(target=_run_scan, args=(scan_id, body, q), daemon=True)
    t.start()

    return jsonify(scan_id=scan_id)


@app.route("/api/stream/<scan_id>")
def stream(scan_id):
    with _LOCK:
        entry = _SCANS.get(scan_id)
    if not entry:
        return jsonify(error="Scan not found"), 404

    def generate():
        q = entry["queue"]
        while True:
            try:
                msg = q.get(timeout=30)
                yield f"data: {json.dumps(msg)}\n\n"
                if msg.get("type") == "done" or msg.get("type") == "error":
                    break
            except queue.Empty:
                # Send heartbeat to keep connection alive
                yield "data: {\"type\":\"ping\"}\n\n"

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
            "Connection":       "keep-alive",
        },
    )


@app.route("/api/result/<scan_id>")
def result(scan_id):
    with _LOCK:
        entry = _SCANS.get(scan_id)
    if not entry:
        return jsonify(error="Scan not found"), 404
    if not entry["done"]:
        return jsonify(error="Scan still running"), 202
    if entry["error"]:
        return jsonify(error=entry["error"]), 500
    return jsonify(entry["result"])


# ── Background scan runner ────────────────────────────────────────────────────

def _push(q: queue.Queue, type_: str, **kwargs):
    q.put({"type": type_, "ts": datetime.now().strftime("%H:%M:%S"), **kwargs})


def _run_scan(scan_id: str, params: dict, q: queue.Queue):
    try:
        _do_scan(scan_id, params, q)
    except Exception as exc:
        import traceback
        tb = traceback.format_exc()
        _push(q, "log", level="error", msg=f"Unexpected error: {exc}")
        _push(q, "error", msg=str(exc))
        with _LOCK:
            _SCANS[scan_id]["error"] = str(exc)
            _SCANS[scan_id]["done"]  = True


def _do_scan(scan_id: str, params: dict, q: queue.Queue):
    from utils      import ScanConfig, normalise_url
    from scanner    import TargetScanner
    from analyzer   import ScanAggregator, PassiveAnalyzer
    from thread_engine import ThreadEngine
    from payloads   import (
        IDOR_PATHS, SENSITIVE_PATHS, DEFAULT_CREDENTIALS,
        SQL_ERROR_PAYLOADS, SQL_BOOLEAN_PAYLOADS, SQL_UNION_PAYLOADS,
        XSS_PAYLOADS, SSTI_PAYLOADS, CMD_INJECTION_PAYLOADS,
        PATH_TRAVERSAL_PAYLOADS, XXE_PAYLOADS, SSRF_PAYLOADS,
        OPEN_REDIRECT_PAYLOADS, AUTH_BYPASS_PAYLOADS, Severity,
    )

    url     = normalise_url(params["url"])
    quick   = bool(params.get("quick", False))
    workers = min(int(params.get("workers", 4)), 10)
    timeout = min(int(params.get("timeout", 10)), 20)
    checks  = params.get("checks") or []

    cookie_str = params.get("cookie", "")
    cookies    = {}
    if cookie_str:
        for part in cookie_str.split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                cookies[k.strip()] = v.strip()

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
        target_url=url, workers=workers, delay=0.15,
        timeout=timeout, time_delay=5.0, verify_ssl=False,
        follow_redirects=False, cookies=cookies,
        scan_sqli=run_sqli, scan_xss=run_xss, scan_ssti=run_ssti,
        scan_cmdi=run_cmdi, scan_lfi=run_lfi, scan_xxe=run_xxe,
        scan_ssrf=run_ssrf, scan_redirect=run_redir, scan_headers=run_hdrs,
        scan_paths=run_path, scan_auth=run_auth,
        quick_mode=quick, verbose=False,
    )

    agg     = ScanAggregator()
    passive = PassiveAnalyzer()
    t_start = time.perf_counter()

    _push(q, "log", level="info",    msg=f"Target  : {url}")
    _push(q, "log", level="info",    msg=f"Mode    : {'Quick (Critical/High)' if quick else 'Full'}")
    _push(q, "log", level="info",    msg=f"Workers : {workers}  Timeout: {timeout}s")
    _push(q, "log", level="info",    msg="─" * 48)

    # ── 1. Crawl ──────────────────────────────────────────────────────────────
    _push(q, "phase", phase="crawl", msg="Phase 1 — Target Discovery")
    _push(q, "log",   level="info",  msg="Crawling target for forms and parameters...")

    scanner = TargetScanner(cfg)
    target  = scanner.scan()

    _push(q, "log", level="success",
          msg=f"Found: {len(target.forms)} form(s), {len(target.query_params)} param(s)")
    if target.tech_stack:
        _push(q, "log", level="info", msg=f"Tech stack: {', '.join(target.tech_stack)}")

    # ── 2. Passive header analysis ─────────────────────────────────────────────
    h_count = 0
    if target.baseline and target.baseline.ok and run_hdrs:
        _push(q, "phase", phase="headers", msg="Phase 2 — Header Analysis (A02 / A05 / A06)")
        h_findings = passive.analyze_headers(target.baseline, target.url)
        agg.add_all(h_findings)
        h_count = len(h_findings)
        for f in h_findings:
            _push(q, "finding", severity=f.severity.value,
                  description=f.description, category=f.owasp_category.value)
        _push(q, "log", level="info" if h_count==0 else "warn",
              msg=f"Header check: {h_count} issue(s)")

    # ── 3. Active injection ────────────────────────────────────────────────────
    payloads = _build_payloads(
        quick, run_sqli, run_xss, run_ssti, run_cmdi, run_lfi,
        run_xxe, run_ssrf, run_redir,
        SQL_ERROR_PAYLOADS, SQL_BOOLEAN_PAYLOADS, SQL_UNION_PAYLOADS,
        XSS_PAYLOADS, SSTI_PAYLOADS, CMD_INJECTION_PAYLOADS,
        PATH_TRAVERSAL_PAYLOADS, XXE_PAYLOADS, SSRF_PAYLOADS,
        OPEN_REDIRECT_PAYLOADS, AUTH_BYPASS_PAYLOADS, Severity,
    )

    if payloads:
        _push(q, "phase", phase="inject",
              msg=f"Phase 3 — Active Injection ({len(payloads)} payloads)")
        if not (target.forms or target.query_params):
            _push(q, "log", level="warn", msg="No injection points found — skipping active tests")
        else:
            # Live finding callback
            def on_finding(f):
                _push(q, "finding", severity=f.severity.value,
                      description=f.description, category=f.owasp_category.value,
                      url=f.url, parameter=f.parameter)

            engine = ThreadEngine(cfg, agg, on_finding=on_finding)
            n = engine.run_injections(target, payloads)
            _push(q, "log", level="success" if n==0 else "warn",
                  msg=f"Injection phase: {n} finding(s)")

    # ── 4. Path scan ───────────────────────────────────────────────────────────
    if run_path:
        _push(q, "phase", phase="paths", msg="Phase 4 — Sensitive Path Scan (A01 / A05)")
        all_paths = list(dict.fromkeys(SENSITIVE_PATHS + IDOR_PATHS))
        engine2   = ThreadEngine(cfg, agg, on_finding=None)
        n = engine2.run_path_scan(target, all_paths)
        _push(q, "log", level="success" if n==0 else "warn",
              msg=f"Path scan: {n} exposure(s)")

    # ── 5. Auth check ──────────────────────────────────────────────────────────
    if run_auth and target.forms:
        _push(q, "phase", phase="auth", msg="Phase 5 — Authentication Check (A07)")
        engine3 = ThreadEngine(cfg, agg, on_finding=None)
        n = engine3.run_auth_check(target, DEFAULT_CREDENTIALS)
        _push(q, "log", level="warn" if n else "success",
              msg=f"Auth check: {n} default credential hit(s)")

    # ── Build result ───────────────────────────────────────────────────────────
    duration = time.perf_counter() - t_start
    findings_out = [_serialize_finding(f) for f in agg.findings]
    stats        = agg.stats()

    _push(q, "log", level="info", msg="─" * 48)
    _push(q, "log", level="success", msg=f"Scan complete — {len(findings_out)} finding(s) in {duration:.1f}s")

    for sev in ("critical","high","medium","low","info"):
        n = stats.get(sev, 0)
        if n:
            _push(q, "log", level="error" if sev in ("critical","high") else "warn",
                  msg=f"  {sev.upper()}: {n}")

    result = {
        "url":         url,
        "duration":    round(duration, 2),
        "findings":    findings_out,
        "stats":       stats,
        "tech_stack":  list(target.tech_stack),
        "forms_found": len(target.forms),
        "params_found":len(target.query_params),
    }

    with _LOCK:
        _SCANS[scan_id]["result"] = result
        _SCANS[scan_id]["done"]   = True

    _push(q, "done", result=result)


def _serialize_finding(f) -> dict:
    return {
        "severity":       f.severity.value,
        "description":    f.description,
        "owasp_category": f.owasp_category.value,
        "injection_type": f.injection_type.value if f.injection_type else None,
        "url":            f.url,
        "parameter":      f.parameter,
        "payload":        f.payload,
        "evidence":       str(f.evidence)[:300] if f.evidence else None,
        "confidence":     f.confidence,
        "remediation":    f.remediation,
    }


def _build_payloads(quick, sqli, xss, ssti, cmdi, lfi, xxe, ssrf, redir,
                    SQL_E, SQL_B, SQL_U, XSS, SSTI, CMDI, LFI, XXE, SSRF, REDIR, AUTH, Severity):
    p = []
    if sqli:  p += SQL_E + SQL_B + SQL_U
    if xss:   p += XSS
    if ssti:  p += SSTI
    if cmdi:  p += CMDI
    if lfi:   p += LFI
    if xxe:   p += XXE
    if ssrf:  p += SSRF
    if redir: p += REDIR + AUTH
    if quick:
        p = [x for x in p if x.severity.value in ("CRITICAL","HIGH") or x.expected]
    seen, out = set(), []
    for x in p:
        if x.raw not in seen:
            seen.add(x.raw); out.append(x)
    return out


# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, threaded=True)
