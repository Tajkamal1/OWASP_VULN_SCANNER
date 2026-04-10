"""
=============================================================================
  OWASP Top 10 Checker — thread_engine.py
=============================================================================
  Module   : Concurrent Injection Engine
  Purpose  : Thread-pool driven parallel payload testing across all forms,
             parameters, and endpoint paths.
=============================================================================
"""

from __future__ import annotations

import time
import queue
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Any, Dict

from payloads import Payload, get_library, OWASPCategory, InjectionType
from scanner import (
    ScanTarget, FormData, InputField,
    build_injection_data, submit_injection, inject_query_param,
    QueryParam,
)
from analyzer import ResponseAnalyzer, PassiveAnalyzer, Finding, ScanAggregator
from utils import (
    ScanConfig, build_session, safe_get, safe_post, join_url,
    info, success, warning, error, colour, vuln,
    GREEN, YELLOW, RED, CYAN, MAGENTA, BOLD, RESET, DIM, truncate,
)

log = logging.getLogger("owasp.engine")


# ─────────────────────────────────────────────────────────────────────────────
# Injection Job
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InjectionJob:
    job_id:     int
    payload:    Payload
    url:        str
    method:     str          # GET | POST
    param_name: Optional[str]
    form:       Optional[FormData]
    query_param:Optional[QueryParam]
    baseline_body: str
    cfg:        ScanConfig

    @property
    def label(self) -> str:
        return (f"[{self.job_id}] {self.param_name!r} "
                f"← {truncate(self.payload.raw, 32)!r}")


# ─────────────────────────────────────────────────────────────────────────────
# Thread Engine
# ─────────────────────────────────────────────────────────────────────────────

class ThreadEngine:
    """
    Manages parallel payload injection and collects findings.
    """

    def __init__(self, cfg: ScanConfig, aggregator: ScanAggregator,
                 on_finding: Optional[Callable[[Finding], None]] = None):
        self.cfg        = cfg
        self.aggregator = aggregator
        self.on_finding = on_finding
        self._lock      = threading.Lock()
        self._counter   = 0
        self._stop      = threading.Event()

    def _next_id(self) -> int:
        with self._lock:
            self._counter += 1
            return self._counter

    def stop(self):
        self._stop.set()

    # ── Build job list ────────────────────────────────────────────────────────

    def _build_jobs(self, target: ScanTarget,
                    payloads: List[Payload]) -> List[InjectionJob]:
        jobs: List[InjectionJob] = []
        baseline_body = target.baseline.body if target.baseline else ""

        # Form-based jobs
        for form in target.forms:
            for f_field in form.injectable_fields:
                for p in payloads:
                    jobs.append(InjectionJob(
                        job_id=self._next_id(),
                        payload=p,
                        url=form.action,
                        method=form.method,
                        param_name=f_field.name,
                        form=form,
                        query_param=None,
                        baseline_body=baseline_body,
                        cfg=self.cfg,
                    ))

        # URL-param-based jobs
        for qp in target.query_params:
            for p in payloads:
                jobs.append(InjectionJob(
                    job_id=self._next_id(),
                    payload=p,
                    url=qp.url,
                    method="GET",
                    param_name=qp.name,
                    form=None,
                    query_param=qp,
                    baseline_body=baseline_body,
                    cfg=self.cfg,
                ))
        return jobs

    # ── Thread-local session pool ─────────────────────────────────────────────
    # FIX-007: Create ONE session per worker thread (not per job). A per-job session
    # spawns a new TCP connection for every payload, exhausting file descriptors and
    # negating all connection-pool benefits. threading.local() gives each thread its
    # own session without locks.
    _tls = threading.local()

    def _get_session(self) -> requests.Session:
        if not hasattr(self._tls, "session"):
            self._tls.session = build_session(self.cfg)
        return self._tls.session

    # ── Execute one job ───────────────────────────────────────────────────────

    def _run_job(self, job: InjectionJob) -> Optional[Finding]:
        if self._stop.is_set():
            return None

        session = self._get_session()
        analyzer = ResponseAnalyzer(job.cfg)

        try:
            if job.form is not None:
                data = build_injection_data(job.form, job.param_name, job.payload.raw)
                resp = submit_injection(session, job.form, data, job.cfg)
            else:
                injected_url = inject_query_param(job.url, job.param_name, job.payload.raw)
                resp = safe_get(session, injected_url, job.cfg)

            if not resp.ok:
                return None

            # FIX-008: Removed dead anonymous-class `baseline` that was constructed but never used.
            from utils import HTTPResponse as HR
            baseline_resp = HR(200, job.baseline_body, {}, 0.0, job.url)

            finding = analyzer.analyze(job.payload, resp, baseline_resp,
                                       job.url, job.param_name, job.method)
            if job.cfg.delay > 0:
                time.sleep(job.cfg.delay)
            return finding

        except Exception as exc:
            log.debug("Job %d failed: %s", job.job_id, exc)
            return None

    # ── Public: run all injection jobs ────────────────────────────────────────

    def run_injections(self, target: ScanTarget, payloads: List[Payload]) -> int:
        """Run all payload injections. Returns count of findings."""
        jobs = self._build_jobs(target, payloads)
        if not jobs:
            print(warning("No injectable parameters found for active injection"))
            return 0

        print(info(f"Queued {colour(str(len(jobs)), CYAN, BOLD)} injection job(s) "
                   f"across {self.cfg.workers} worker(s)"))

        found = 0
        # FIX-009: Track consecutive 429s for adaptive back-off; cancel remaining futures on stop
        _rate_limit_hits = 0
        with ThreadPoolExecutor(max_workers=self.cfg.workers,
                                thread_name_prefix="owasp-worker") as executor:
            futures = {executor.submit(self._run_job, job): job for job in jobs}
            for future in as_completed(futures):
                if self._stop.is_set():
                    for f in futures:
                        f.cancel()
                    break
                job = futures[future]
                try:
                    finding = future.result()
                    if finding:
                        # Detect rate-limiting from HTTP-429 response code
                        if finding.response_code == 429:
                            _rate_limit_hits += 1
                            backoff = min(2 ** _rate_limit_hits, 60)
                            log.warning("Rate-limited (429) — backing off %ds", backoff)
                            time.sleep(backoff)
                        else:
                            _rate_limit_hits = 0
                        self.aggregator.add(finding)
                        found += 1
                        if self.on_finding:
                            self.on_finding(finding)
                        if self.cfg.verbose:
                            print(vuln(f"{finding.severity.value} | "
                                       f"{finding.injection_type.value if finding.injection_type else 'N/A'} | "
                                       f"param={job.param_name} | "
                                       f"conf={finding.confidence}%"))
                except Exception as exc:
                    log.debug("Future exception: %s", exc)
        return found

    # ── Passive path scan ─────────────────────────────────────────────────────

    def run_path_scan(self, target: ScanTarget, paths: List[str]) -> int:
        """Check sensitive/IDOR paths for exposure."""
        print(info(f"Scanning {colour(str(len(paths)), CYAN, BOLD)} paths…"))
        passive = PassiveAnalyzer()
        session = build_session(self.cfg)
        found = 0

        def _check(path: str) -> Optional[Finding]:
            if self._stop.is_set():
                return None
            url = join_url(target.url, path)
            resp = safe_get(session, url, self.cfg)
            if resp.ok:
                f = passive.analyze_path(path, resp, url)
                if f:
                    return f
                if self.cfg.delay:
                    time.sleep(self.cfg.delay)
            return None

        with ThreadPoolExecutor(max_workers=self.cfg.workers,
                                thread_name_prefix="owasp-path") as executor:
            futures = {executor.submit(_check, p): p for p in paths}
            for future in as_completed(futures):
                if self._stop.is_set():
                    break
                try:
                    f = future.result()
                    if f:
                        self.aggregator.add(f)
                        found += 1
                        if self.on_finding:
                            self.on_finding(f)
                except Exception:
                    pass
        return found

    # ── Auth brute-force ──────────────────────────────────────────────────────

    def run_auth_check(self, target: ScanTarget,
                       credentials: List[Dict[str, str]]) -> int:
        """Try default credentials on login forms."""
        login_forms = [f for f in target.forms
                       if any(fld.input_type == "password" for fld in f.fields)]
        if not login_forms:
            return 0

        session = build_session(self.cfg)
        found = 0
        print(info(f"Testing {len(credentials)} default credential pairs on "
                   f"{len(login_forms)} login form(s)"))

        for form in login_forms:
            user_field  = next((f for f in form.fields if "user" in f.name.lower()
                                or "email" in f.name.lower()), None)
            pass_field  = next((f for f in form.fields if f.input_type == "password"), None)
            if not user_field or not pass_field:
                continue

            baseline_data = form.base_data()
            baseline_resp = submit_injection(session, form, baseline_data, self.cfg)
            baseline_len  = len(baseline_resp.body)

            for cred in credentials:
                if self._stop.is_set():
                    break
                data = form.base_data()
                data[user_field.name] = cred["username"]
                data[pass_field.name] = cred["password"]
                resp = submit_injection(session, form, data, self.cfg)

                # FIX-010: Detect account lockout / CAPTCHA / rate-limit before proceeding.
                # Continuing to hammer after lockout can permanently block real users.
                lockout_signals = (
                    resp.status_code == 429 or
                    resp.status_code == 423 or  # 423 Locked
                    any(kw in resp.body.lower() for kw in
                        ["account locked", "too many attempts", "captcha",
                         "temporarily disabled", "account suspended"])
                )
                if lockout_signals:
                    log.warning("Lockout/CAPTCHA detected on %s — halting auth check", form.action)
                    break  # Stop trying this form to avoid locking out real users

                # Heuristic: shorter, redirect, or very different response = login success
                success_signals = (
                    resp.redirect_url is not None or
                    resp.status_code in (302, 303) or
                    (resp.status_code == 200 and
                     abs(len(resp.body) - baseline_len) > 500 and
                     any(kw in resp.body.lower() for kw in
                         ["dashboard", "logout", "welcome", "profile"]))
                )
                if success_signals:
                    from analyzer import Finding
                    from payloads import OWASPCategory, Severity
                    finding = Finding(
                        owasp_category=OWASPCategory.A07_AUTH_FAILURES,
                        injection_type=None,
                        severity=Severity.CRITICAL,
                        url=form.action,
                        parameter=f"{user_field.name}/{pass_field.name}",
                        payload=f"{cred['username']}:{cred['password']}",
                        evidence=f"Login succeeded — redirect or success page detected",
                        confidence=78,
                        description=f"Default credentials accepted: {cred['username']}:{cred['password']}",
                        remediation="Disable default accounts. Enforce strong password policy. Use MFA.",
                        request_method=form.method,
                        response_code=resp.status_code,
                        tags=["auth", "default-creds"],
                    )
                    self.aggregator.add(finding)
                    if self.on_finding:
                        self.on_finding(finding)
                    found += 1
                    break  # one hit per form is enough

                if self.cfg.delay:
                    time.sleep(self.cfg.delay)

        return found
