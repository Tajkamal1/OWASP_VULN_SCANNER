"""
=============================================================================
  OWASP Top 10 Checker — reporter.py
=============================================================================
  Module   : Reporting Engine
  Purpose  : Terminal, JSON, and HTML reporting for scan findings.
=============================================================================
"""

from __future__ import annotations

import html as _html  # FIX-005: html.escape for all user-controlled data in HTML report
import json
import datetime
from typing import List, Dict, Any, Optional

from analyzer import Finding, ScanAggregator
from payloads import OWASPCategory, Severity
from utils import (
    colour, success, warning, error, info, vuln, critical,
    RED, GREEN, YELLOW, CYAN, MAGENTA, BLUE, BOLD, DIM, RESET,
    BG_RED, BG_GREEN, BG_YELLOW, truncate, save_json,
)


# ─────────────────────────────────────────────────────────────────────────────
# Terminal Printer
# ─────────────────────────────────────────────────────────────────────────────

_WHITE = "\033[97m"  # FIX-006: Remove := walrus side-effect inside dict literal
SEVERITY_COLOUR = {
    Severity.CRITICAL: (BG_RED, _WHITE, BOLD),
    Severity.HIGH:     (RED,    BOLD),
    Severity.MEDIUM:   (YELLOW, BOLD),
    Severity.LOW:      (YELLOW,),
    Severity.INFO:     (CYAN,),
}

SEVERITY_ICON = {
    Severity.CRITICAL: "💀",
    Severity.HIGH:     "🔴",
    Severity.MEDIUM:   "🟠",
    Severity.LOW:      "🟡",
    Severity.INFO:     "🔵",
}


def print_banner(target: str, version: str = "1.0.0") -> None:
    w = 72
    bar = "═" * w
    print(colour(f"╔{bar}╗", CYAN, BOLD))
    print(colour(f"║{'OWASP Top 10 Vulnerability Checker':^{w}}║", CYAN, BOLD))
    print(colour(f"║{f'v{version}  |  Authorized Use Only':^{w}}║", CYAN, BOLD))
    print(colour(f"╠{bar}╣", CYAN, BOLD))
    print(colour(f"║  Target : {truncate(target, w-12):<{w-11}}║", CYAN))
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(colour(f"║  Time   : {ts:<{w-11}}║", CYAN))
    print(colour(f"╚{bar}╝", CYAN, BOLD))
    print()


def print_section(title: str) -> None:
    bar = "─" * 64
    print(colour(f"\n{bar}", MAGENTA, BOLD))
    print(colour(f"  ► {title}", MAGENTA, BOLD))
    print(colour(f"{bar}", MAGENTA, BOLD))


def print_finding(f: Finding, index: int) -> None:
    sev_str = colour(f" {f.severity.value:<8} ", *SEVERITY_COLOUR.get(f.severity, ()))
    icon    = SEVERITY_ICON.get(f.severity, "•")
    print(f"\n  {icon} [{index}] {sev_str}  {colour(f.description, BOLD)}")
    print(f"      {colour('Category:', DIM)} {f.owasp_category.value}")
    if f.injection_type:
        print(f"      {colour('Type:', DIM)}     {f.injection_type.value}")
    print(f"      {colour('URL:', DIM)}      {colour(f.url, CYAN)}")
    if f.parameter:
        print(f"      {colour('Param:', DIM)}    {colour(f.parameter, YELLOW)}")
    if f.payload:
        print(f"      {colour('Payload:', DIM)}  {colour(truncate(f.payload, 70), RED)}")
    if f.evidence:
        print(f"      {colour('Evidence:', DIM)} {colour(truncate(f.evidence, 120), GREEN)}")
    print(f"      {colour('Confidence:', DIM)} {f.confidence}%  |  "
          f"{colour('HTTP ' + str(f.response_code), DIM)}  |  "
          f"{colour(f'{f.response_time:.2f}s', DIM)}")
    if f.remediation:
        print(f"      {colour('Fix:', DIM)}      {f.remediation}")


def print_summary(agg: ScanAggregator, duration: float) -> None:
    stats = agg.stats()
    print_section("SCAN SUMMARY")
    width = 40
    print(f"\n  {'Total findings':<{width}} {colour(str(stats['total']), BOLD)}")
    for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
        n   = stats["by_severity"].get(sev.value, 0)
        clr = SEVERITY_COLOUR.get(sev, ())
        bar = "█" * min(n, 20)
        print(f"  {sev.value:<{width}} {colour(f'{n:>3}  {bar}', *clr)}")

    print(f"\n  {'Scan duration':<{width}} {duration:.1f}s")

    if stats["total"] == 0:
        print(f"\n  {colour('✓ No vulnerabilities detected', GREEN, BOLD)}")
    elif stats.get("critical", 0) > 0:
        print(f"\n  {colour('✘ CRITICAL vulnerabilities found — immediate remediation required!', BG_RED, BOLD)}")
    elif stats.get("high", 0) > 0:
        print(f"\n  {colour('⚠ HIGH severity findings — prioritize remediation', RED, BOLD)}")

    print()


def print_owasp_coverage(agg: ScanAggregator) -> None:
    print_section("OWASP TOP 10 COVERAGE")
    print()
    for cat in OWASPCategory:
        count  = len(agg.by_category(cat))
        icon   = "🔴" if count > 0 else "✅"
        status = colour(f"VULNERABLE ({count})", RED, BOLD) if count > 0 else colour("PASSED", GREEN)
        print(f"  {icon}  {cat.value:<55} {status}")
    print()


# ─────────────────────────────────────────────────────────────────────────────
# JSON Export
# ─────────────────────────────────────────────────────────────────────────────

def export_json(agg: ScanAggregator, target: str, path: str,
                duration: float, tech_stack: List[str]) -> None:
    data = {
        "meta": {
            "tool":    "OWASP Top 10 Checker v1.0.0",
            "target":  target,
            "scanned": datetime.datetime.now().isoformat(),
            "duration_seconds": round(duration, 2),
            "tech_stack": tech_stack,
        },
        "summary": agg.stats(),
        "findings": agg.to_dict_list(),
    }
    save_json(path, data)
    print(success(f"JSON report saved → {colour(path, CYAN)}"))


# ─────────────────────────────────────────────────────────────────────────────
# HTML Report
# ─────────────────────────────────────────────────────────────────────────────

def _sev_css(sev: str) -> str:
    return {"CRITICAL": "#c0392b", "HIGH": "#e74c3c",
            "MEDIUM": "#e67e22", "LOW": "#f39c12", "INFO": "#3498db"}.get(sev, "#7f8c8d")


def export_html(agg: ScanAggregator, target: str, path: str,
                duration: float, tech_stack: List[str]) -> None:
    stats    = agg.stats()
    findings = agg.findings
    ts       = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    owasp_rows = ""
    for cat in OWASPCategory:
        count  = len(agg.by_category(cat))
        status = f'<span style="color:#c0392b;font-weight:bold">VULNERABLE ({count})</span>' if count else '<span style="color:#27ae60">PASSED</span>'
        owasp_rows += f"<tr><td>{cat.value}</td><td>{status}</td></tr>\n"

    # FIX-005: All user-controlled finding data MUST be HTML-escaped before interpolation.
    # Unescaped payloads/evidence from the scanned server can contain <script> tags that
    # execute when the report is opened in a browser.
    finding_cards = ""
    for i, f in enumerate(findings, 1):
        sev_color = _sev_css(f.severity.value)
        esc = _html.escape  # convenience alias
        finding_cards += f"""
        <div class="card" style="border-left:6px solid {sev_color};margin:12px 0;padding:14px;background:#1e2530;border-radius:6px">
          <div style="display:flex;align-items:center;gap:10px">
            <span style="background:{sev_color};color:#fff;padding:3px 10px;border-radius:4px;font-weight:bold;font-size:.85em">{esc(f.severity.value)}</span>
            <span style="font-weight:bold;color:#ecf0f1">{esc(f.description)}</span>
          </div>
          <table style="margin-top:10px;width:100%;color:#bdc3c7;font-size:.9em">
            <tr><td style="width:130px;color:#7f8c8d">OWASP Category</td><td>{esc(f.owasp_category.value)}</td></tr>
            {'<tr><td style="color:#7f8c8d">Type</td><td>' + esc(f.injection_type.value) + '</td></tr>' if f.injection_type else ''}
            <tr><td style="color:#7f8c8d">URL</td><td style="color:#3498db">{esc(f.url)}</td></tr>
            {'<tr><td style="color:#7f8c8d">Parameter</td><td style="color:#e67e22">' + esc(str(f.parameter)) + '</td></tr>' if f.parameter else ''}
            {'<tr><td style="color:#7f8c8d">Payload</td><td style="color:#e74c3c;word-break:break-all"><code>' + esc((f.payload or '')[:200]) + '</code></td></tr>' if f.payload else ''}
            {'<tr><td style="color:#7f8c8d">Evidence</td><td style="color:#2ecc71;word-break:break-all">' + esc((f.evidence or '')[:300]) + '</td></tr>' if f.evidence else ''}
            <tr><td style="color:#7f8c8d">Confidence</td><td>{f.confidence}%</td></tr>
            <tr><td style="color:#7f8c8d">Remediation</td><td style="color:#f39c12">{esc(f.remediation)}</td></tr>
          </table>
        </div>"""

    sev_bars = ""
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        n = stats["by_severity"].get(sev, 0)
        clr = _sev_css(sev)
        pct = min(n * 5, 100)
        sev_bars += f"""
        <div style="display:flex;align-items:center;gap:12px;margin:6px 0">
          <span style="width:80px;font-weight:bold;color:{clr}">{sev}</span>
          <div style="background:#2c3e50;border-radius:4px;height:18px;width:300px">
            <div style="background:{clr};width:{pct}%;height:100%;border-radius:4px"></div>
          </div>
          <span style="color:#ecf0f1">{n}</span>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>OWASP Scan Report — {_html.escape(target)}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:'Segoe UI',Arial,sans-serif;background:#0d1117;color:#c9d1d9;line-height:1.6}}
    .header{{background:linear-gradient(135deg,#1a2332,#0d2137);padding:36px;border-bottom:3px solid #e74c3c}}
    .header h1{{font-size:1.9em;color:#fff;margin-bottom:6px}}
    .header p{{color:#8b9eb0;font-size:.95em}}
    .container{{max-width:1100px;margin:0 auto;padding:24px}}
    .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin:24px 0}}
    .stat{{background:#1e2530;border-radius:8px;padding:18px;text-align:center}}
    .stat .num{{font-size:2.2em;font-weight:bold}}
    .stat .lbl{{color:#7f8c8d;font-size:.85em;margin-top:4px}}
    h2{{color:#3498db;margin:28px 0 12px;font-size:1.3em;border-bottom:1px solid #1e2530;padding-bottom:6px}}
    table{{width:100%;border-collapse:collapse;background:#1e2530;border-radius:8px;overflow:hidden}}
    th{{background:#2c3e50;color:#ecf0f1;padding:10px 14px;text-align:left;font-size:.9em}}
    td{{padding:9px 14px;border-bottom:1px solid #2c3e50;font-size:.88em}}
    tr:last-child td{{border-bottom:none}}
    .footer{{text-align:center;padding:24px;color:#555;font-size:.85em;border-top:1px solid #1e2530;margin-top:40px}}
  </style>
</head>
<body>
<div class="header">
  <div style="max-width:1100px;margin:0 auto">
    <h1>🛡 OWASP Top 10 Vulnerability Report</h1>
    <p>Target: <strong style="color:#3498db">{_html.escape(target)}</strong> &nbsp;|&nbsp; Scanned: {ts} &nbsp;|&nbsp; Duration: {duration:.1f}s</p>
    {f'<p style="margin-top:6px">Tech: {", ".join(tech_stack)}</p>' if tech_stack else ''}
  </div>
</div>
<div class="container">
  <div class="grid">
    <div class="stat"><div class="num" style="color:#ecf0f1">{stats['total']}</div><div class="lbl">Total Findings</div></div>
    <div class="stat"><div class="num" style="color:#c0392b">{stats['by_severity'].get('CRITICAL',0)}</div><div class="lbl">Critical</div></div>
    <div class="stat"><div class="num" style="color:#e74c3c">{stats['by_severity'].get('HIGH',0)}</div><div class="lbl">High</div></div>
    <div class="stat"><div class="num" style="color:#e67e22">{stats['by_severity'].get('MEDIUM',0)}</div><div class="lbl">Medium</div></div>
    <div class="stat"><div class="num" style="color:#f39c12">{stats['by_severity'].get('LOW',0)}</div><div class="lbl">Low</div></div>
  </div>

  <h2>Severity Distribution</h2>
  {sev_bars}

  <h2>OWASP Top 10 Coverage</h2>
  <table><thead><tr><th>Category</th><th>Status</th></tr></thead>
  <tbody>{owasp_rows}</tbody></table>

  <h2>Findings ({len(findings)})</h2>
  {finding_cards if finding_cards else '<p style="color:#555;padding:16px">No findings detected.</p>'}
</div>
<div class="footer">
  Generated by OWASP Top 10 Checker v1.0.0 &nbsp;|&nbsp; Authorized and Educational Use Only<br>
  This report is confidential. Handle in accordance with your organization's security policies.
</div>
</body>
</html>"""

    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(success(f"HTML report saved → {colour(path, CYAN)}"))
