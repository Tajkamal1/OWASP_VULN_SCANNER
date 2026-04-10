"""
=============================================================================
  OWASP Top 10 Checker — scanner.py
=============================================================================
  Module   : HTTP Scanner & Crawler
  Purpose  : Crawl the target, discover forms/params/endpoints, capture
             baseline responses, and structure injection targets.
=============================================================================
"""

from __future__ import annotations

import re
import time
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Set, Tuple, Any
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import requests
from bs4 import BeautifulSoup, Tag

from utils import (
    ScanConfig, HTTPResponse, build_session,
    safe_get, safe_post, normalise_url, join_url,
    info, success, warning, error, colour,
    CYAN, GREEN, YELLOW, RED, BOLD, RESET, DIM, truncate,
)

log = logging.getLogger("owasp.scanner")


# ─────────────────────────────────────────────────────────────────────────────
# Data Structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class InputField:
    name:         str
    input_type:   str  = "text"
    value:        str  = ""
    placeholder:  str  = ""
    required:     bool = False
    is_injectable:bool = True
    form_index:   int  = 0

    @property
    def is_hidden(self) -> bool:
        return self.input_type == "hidden"


@dataclass
class FormData:
    action:     str
    method:     str                         # GET | POST
    fields:     List[InputField]            = field(default_factory=list)
    enctype:    str                         = "application/x-www-form-urlencoded"
    form_id:    str                         = ""
    origin_url: str                         = ""

    @property
    def injectable_fields(self) -> List[InputField]:
        NON_INJECTABLE = {"submit", "button", "image", "reset", "checkbox", "radio", "file"}
        return [f for f in self.fields
                if f.is_injectable and f.input_type not in NON_INJECTABLE]

    def base_data(self) -> Dict[str, str]:
        """Return dict with all fields populated with default/placeholder values."""
        d: Dict[str, str] = {}
        for f in self.fields:
            d[f.name] = f.value or f.placeholder or "test"
        return d


@dataclass
class QueryParam:
    name:  str
    value: str
    url:   str


@dataclass
class ScanTarget:
    url:          str
    forms:        List[FormData]   = field(default_factory=list)
    query_params: List[QueryParam] = field(default_factory=list)
    links:        List[str]        = field(default_factory=list)
    baseline:     Optional[HTTPResponse] = None
    title:        str              = ""
    server:       str              = ""
    tech_stack:   List[str]        = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Form Parser
# ─────────────────────────────────────────────────────────────────────────────

NON_INJECTABLE_TYPES = {"submit", "button", "image", "reset", "file", "hidden"}
INJECTABLE_TYPES     = {"text", "email", "search", "url", "tel", "number",
                        "password", "textarea", "select"}

def _parse_fields(form_tag: Tag, form_index: int) -> List[InputField]:
    fields: List[InputField] = []
    for tag in form_tag.find_all(["input", "textarea", "select"]):
        name = (tag.get("name") or tag.get("id") or "").strip()
        if not name:
            continue
        itype = (tag.get("type") or ("textarea" if tag.name == "textarea"
                                     else "select")).lower()
        value = tag.get("value") or tag.get("placeholder") or ""
        fields.append(InputField(
            name=name,
            input_type=itype,
            value=value,
            placeholder=tag.get("placeholder", ""),
            required=tag.has_attr("required"),
            is_injectable=itype not in NON_INJECTABLE_TYPES,
            form_index=form_index,
        ))
    return fields


def parse_forms(html: str, base_url: str) -> List[FormData]:
    soup = BeautifulSoup(html, "html.parser")
    forms: List[FormData] = []
    for idx, form_tag in enumerate(soup.find_all("form")):
        action = form_tag.get("action") or base_url
        action = urljoin(base_url, action)
        # FIX-011: Enforce same-origin scope — form actions pointing to external hosts
        # (including SSRF targets like 169.254.169.254) must not be followed.
        from urllib.parse import urlparse as _up
        _base_host = _up(base_url).netloc
        if _up(action).netloc and _up(action).netloc != _base_host:
            action = base_url  # fall back to the page URL
        method = (form_tag.get("method") or "GET").upper()
        enctype = form_tag.get("enctype", "application/x-www-form-urlencoded")
        form_id = form_tag.get("id", f"form_{idx}")
        fields = _parse_fields(form_tag, idx)
        if fields:
            forms.append(FormData(
                action=action,
                method=method,
                fields=fields,
                enctype=enctype,
                form_id=form_id,
                origin_url=base_url,
            ))
    return forms


def parse_links(html: str, base_url: str) -> List[str]:
    soup = BeautifulSoup(html, "html.parser")
    links: Set[str] = set()
    parsed_base = urlparse(base_url)
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(("#", "mailto:", "tel:", "javascript:")):
            continue
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        if parsed.netloc == parsed_base.netloc:
            links.add(full.split("#")[0])
    return sorted(links)


def parse_query_params(url: str) -> List[QueryParam]:
    parsed = urlparse(url)
    params: List[QueryParam] = []
    for name, values in parse_qs(parsed.query).items():
        params.append(QueryParam(name=name, value=values[0], url=url))
    return params


def inject_query_param(url: str, param_name: str, payload: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param_name] = [payload]
    new_query = urlencode({k: v[0] for k, v in qs.items()})
    return urlunparse(parsed._replace(query=new_query))


def build_injection_data(form: FormData, field_name: str,
                          payload: str) -> Dict[str, str]:
    data = form.base_data()
    data[field_name] = payload
    return data


def submit_injection(session: requests.Session, form: FormData,
                     data: Dict[str, str], cfg: ScanConfig) -> HTTPResponse:
    from utils import safe_get, safe_post, do_request
    if form.method == "POST":
        if "multipart" in form.enctype:
            return do_request(session, "POST", form.action, cfg, files={k: (None, v) for k, v in data.items()})
        return safe_post(session, form.action, cfg, data=data)
    else:
        return safe_get(session, form.action, cfg, params=data)


# ─────────────────────────────────────────────────────────────────────────────
# Technology Fingerprinting
# ─────────────────────────────────────────────────────────────────────────────

TECH_PATTERNS: List[Tuple[str, str]] = [
    # By response header
    ("PHP",        r"(?i)x-powered-by.*php"),
    ("ASP.NET",    r"(?i)x-aspnet-version|x-powered-by.*asp"),
    ("Java/JSP",   r"(?i)x-powered-by.*servlet|jsessionid"),
    ("Node.js",    r"(?i)x-powered-by.*express"),
    ("Django",     r"(?i)csrftoken|django"),
    ("Flask",      r"(?i)werkzeug"),
    ("Ruby/Rails", r"(?i)x-runtime.*ruby|_rails_"),
    ("WordPress",  r"(?i)wp-content|wp-login"),
    ("Drupal",     r"(?i)drupal|x-generator.*drupal"),
    ("Joomla",     r"(?i)joomla"),
    ("Nginx",      r"(?i)server.*nginx"),
    ("Apache",     r"(?i)server.*apache"),
    ("IIS",        r"(?i)server.*iis|x-aspnet"),
    ("Cloudflare", r"(?i)cf-ray|cloudflare"),
    ("React",      r"(?i)react|__next|_next/static"),
    ("Angular",    r"(?i)ng-version|angular"),
    ("Vue",        r"(?i)__vue__|vue-router"),
]

def fingerprint_tech(resp: HTTPResponse) -> List[str]:
    found: List[str] = []
    combined = " ".join(f"{k}: {v}" for k, v in resp.headers.items()) + " " + resp.body[:4000]
    for name, pattern in TECH_PATTERNS:
        if re.search(pattern, combined):
            found.append(name)
    return list(dict.fromkeys(found))


# ─────────────────────────────────────────────────────────────────────────────
# Main Crawler / Scanner
# ─────────────────────────────────────────────────────────────────────────────

class TargetScanner:
    """Crawls the target URL and builds a ScanTarget."""

    def __init__(self, cfg: ScanConfig):
        self.cfg     = cfg
        self.session = build_session(cfg)
        self.log     = logging.getLogger("owasp.scanner")

    def scan(self) -> ScanTarget:
        url = normalise_url(self.cfg.target_url)
        print(info(f"Scanning target: {colour(url, CYAN, BOLD)}"))

        baseline = safe_get(self.session, url, self.cfg)
        if not baseline.ok:
            print(error(f"Failed to reach target: {baseline.error}"))
            return ScanTarget(url=url, baseline=baseline)

        print(success(f"Target alive — HTTP {baseline.status_code} "
                      f"({baseline.elapsed:.2f}s, {len(baseline.body)} bytes)"))

        soup = BeautifulSoup(baseline.body, "html.parser")
        title = (soup.title.string or "").strip() if soup.title else ""
        tech  = fingerprint_tech(baseline)
        server = baseline.headers.get("Server", "Unknown")

        forms  = parse_forms(baseline.body, url)
        params = parse_query_params(url)
        links  = parse_links(baseline.body, url)

        if forms:
            print(success(f"Found {colour(str(len(forms)), GREEN, BOLD)} form(s)"))
        if params:
            print(success(f"Found {colour(str(len(params)), GREEN, BOLD)} URL parameter(s)"))
        if tech:
            print(info(f"Technology stack: {colour(', '.join(tech), YELLOW)}"))

        return ScanTarget(
            url=url, forms=forms, query_params=params,
            links=links, baseline=baseline,
            title=title, server=server, tech_stack=tech,
        )
