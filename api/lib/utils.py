"""
=============================================================================
  OWASP Top 10 Checker — utils.py
=============================================================================
  Shared utilities: logging, HTTP sessions, config, colour helpers.
=============================================================================
"""

from __future__ import annotations

import re
import time
import json
import logging
import hashlib
import urllib.parse
from dataclasses import dataclass, field
from typing import Optional, Dict, List, Any, Tuple
from datetime import datetime

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# ─────────────────────────────────────────────────────────────────────────────
# Colour constants
# ─────────────────────────────────────────────────────────────────────────────
try:
    from colorama import Fore, Style, Back, init as colorama_init
    colorama_init(autoreset=True)
    RED     = Fore.RED;     GREEN   = Fore.GREEN;  YELLOW  = Fore.YELLOW
    CYAN    = Fore.CYAN;    MAGENTA = Fore.MAGENTA; BLUE    = Fore.BLUE
    WHITE   = Fore.WHITE;   BOLD    = Style.BRIGHT; DIM     = Style.DIM
    RESET   = Style.RESET_ALL
    BG_RED  = Back.RED;     BG_GREEN = Back.GREEN;  BG_YELLOW = Back.YELLOW
    BG_BLUE = Back.BLUE
except ImportError:
    RED="\033[91m"; GREEN="\033[92m"; YELLOW="\033[93m"; CYAN="\033[96m"
    MAGENTA="\033[95m"; BLUE="\033[94m"; WHITE="\033[97m"; BOLD="\033[1m"
    DIM="\033[2m"; RESET="\033[0m"; BG_RED="\033[41m"; BG_GREEN="\033[42m"
    BG_YELLOW="\033[43m"; BG_BLUE="\033[44m"

def colour(text: str, *codes: str) -> str:
    return "".join(codes) + text + RESET

def success(msg: str) -> str: return colour(f"[+] {msg}", GREEN, BOLD)
def warning(msg: str) -> str: return colour(f"[!] {msg}", YELLOW, BOLD)
def error(msg: str)   -> str: return colour(f"[-] {msg}", RED, BOLD)
def info(msg: str)    -> str: return colour(f"[*] {msg}", CYAN)
def vuln(msg: str)    -> str: return colour(f"[VULN] {msg}", BG_RED, WHITE, BOLD)
def critical(msg: str)-> str: return colour(f"[CRITICAL] {msg}", BG_RED, WHITE, BOLD)
def found(msg: str)   -> str: return colour(f"[FOUND] {msg}", BG_GREEN, WHITE, BOLD)

# ─────────────────────────────────────────────────────────────────────────────
# Logging
# ─────────────────────────────────────────────────────────────────────────────

class ColourFormatter(logging.Formatter):
    COLOURS = {
        logging.DEBUG:    DIM + WHITE,
        logging.INFO:     CYAN,
        logging.WARNING:  YELLOW + BOLD,
        logging.ERROR:    RED + BOLD,
        logging.CRITICAL: BG_RED + WHITE + BOLD,
    }
    def format(self, record: logging.LogRecord) -> str:
        c = self.COLOURS.get(record.levelno, "")
        ts = datetime.fromtimestamp(record.created).strftime("%H:%M:%S")
        return f"{DIM}{ts}{RESET} {c}{record.levelname:<8}{RESET} {record.getMessage()}"

def build_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    log = logging.getLogger(f"owasp.{name}")
    if not log.handlers:
        h = logging.StreamHandler()
        h.setFormatter(ColourFormatter())
        log.addHandler(h)
    log.setLevel(level)
    return log

# ─────────────────────────────────────────────────────────────────────────────
# Scan Configuration
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class ScanConfig:
    target_url:    str
    workers:       int   = 4
    delay:         float = 0.3          # seconds between requests
    timeout:       int   = 10
    time_delay:    float = 6.0          # min seconds to flag time-based
    user_agent:    str   = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/120.0.0.0 Safari/537.36")
    verify_ssl:    bool  = True   # FIX-001: Default to True — never silently accept bad certs
    follow_redirects: bool = False       # Set False to detect open redirects
    proxy:         Optional[str] = None
    headers:       Dict[str, str] = field(default_factory=dict)
    cookies:       Dict[str, str] = field(default_factory=dict)
    # Scan scope flags
    scan_sqli:     bool = True
    scan_xss:      bool = True
    scan_ssti:     bool = True
    scan_cmdi:     bool = True
    scan_lfi:      bool = True
    scan_xxe:      bool = True
    scan_ssrf:     bool = True
    scan_redirect: bool = True
    scan_headers:  bool = True
    scan_paths:    bool = True
    scan_auth:     bool = True
    quick_mode:    bool = False         # Critical payloads only
    verbose:       bool = False

# ─────────────────────────────────────────────────────────────────────────────
# HTTP Response Wrapper
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class HTTPResponse:
    status_code:    int
    body:           str
    headers:        Dict[str, str]
    elapsed:        float           # seconds
    url:            str
    redirect_url:   Optional[str]  = None
    error:          Optional[str]  = None
    body_hash:      str            = ""

    def __post_init__(self):
        # FIX-002: SHA-256 replaces MD5 (collision-resistant)
        self.body_hash = hashlib.sha256(self.body.encode("utf-8", errors="replace")).hexdigest()

    @property
    def ok(self) -> bool:
        return self.error is None

    def contains(self, pattern: str, regex: bool = False) -> bool:
        if regex:
            return bool(re.search(pattern, self.body, re.IGNORECASE | re.DOTALL))
        return pattern.lower() in self.body.lower()

# ─────────────────────────────────────────────────────────────────────────────
# HTTP Session
# ─────────────────────────────────────────────────────────────────────────────

def build_session(cfg: ScanConfig) -> requests.Session:
    s = requests.Session()
    # FIX-003: Only retry idempotent methods — POST retries can cause duplicate mutations
    retry = Retry(total=2, backoff_factor=0.5,
                  allowed_methods={"GET", "HEAD", "OPTIONS"},
                  status_forcelist=[429, 502, 503, 504])
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({
        "User-Agent": cfg.user_agent,
        "Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    })
    s.headers.update(cfg.headers)
    s.cookies.update(cfg.cookies)
    if cfg.proxy:
        s.proxies = {"http": cfg.proxy, "https": cfg.proxy}
    s.verify = cfg.verify_ssl
    return s

def do_request(session: requests.Session, method: str, url: str,
               cfg: ScanConfig, **kwargs) -> HTTPResponse:
    kwargs.setdefault("timeout", cfg.timeout)
    kwargs.setdefault("allow_redirects", cfg.follow_redirects)
    try:
        t0 = time.perf_counter()
        r = session.request(method, url, **kwargs)
        elapsed = time.perf_counter() - t0
        redir = None
        if r.history:
            redir = r.url
        body = r.text or ""
        return HTTPResponse(r.status_code, body,
                            dict(r.headers), elapsed, r.url, redir)
    except requests.exceptions.Timeout:
        return HTTPResponse(0, "", {}, cfg.timeout, url, error="Timeout")
    except Exception as e:
        return HTTPResponse(0, "", {}, 0.0, url, error=str(e))

def safe_get(session, url, cfg, params=None) -> HTTPResponse:
    return do_request(session, "GET", url, cfg, params=params)

def safe_post(session, url, cfg, data=None, json=None,
              content_type=None) -> HTTPResponse:
    kwargs: Dict[str, Any] = {}
    if json is not None:
        kwargs["json"] = json
    elif data is not None:
        kwargs["data"] = data
    if content_type:
        kwargs["headers"] = {"Content-Type": content_type}
    return do_request(session, "POST", url, cfg, **kwargs)

# ─────────────────────────────────────────────────────────────────────────────
# URL helpers
# ─────────────────────────────────────────────────────────────────────────────

def normalise_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url.rstrip("/")

def join_url(base: str, path: str) -> str:
    return urllib.parse.urljoin(base.rstrip("/") + "/", path.lstrip("/"))

# ─────────────────────────────────────────────────────────────────────────────
# Misc helpers
# ─────────────────────────────────────────────────────────────────────────────

def truncate(s: str, n: int = 60) -> str:
    return s if len(s) <= n else s[:n] + "…"

def save_json(path: str, data: Any) -> None:
    # FIX-004: Atomic write — prevents corrupted output if the process is killed mid-write
    import tempfile, os
    dir_ = os.path.dirname(os.path.abspath(path)) or "."
    with tempfile.NamedTemporaryFile("w", dir=dir_, delete=False,
                                     suffix=".tmp", encoding="utf-8") as tmp:
        json.dump(data, tmp, indent=2, default=str)
        tmp_path = tmp.name
    os.replace(tmp_path, path)

def load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def banner(title: str, width: int = 72) -> str:
    bar = "═" * width
    pad = (width - len(title) - 2) // 2
    return (colour(f"╔{bar}╗\n", CYAN, BOLD) +
            colour(f"║{' ' * pad} {title} {' ' * pad}║\n", CYAN, BOLD) +
            colour(f"╚{bar}╝", CYAN, BOLD))

def section_header(title: str, width: int = 60) -> str:
    bar = "─" * width
    return colour(f"\n{bar}\n  {title}\n{bar}", MAGENTA, BOLD)
