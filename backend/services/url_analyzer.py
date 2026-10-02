"""Static URL analysis. URLs are NEVER visited - only parsed as strings.

Reminder: HTTPS only means the connection is encrypted. Attackers get free TLS
certificates too, so HTTPS is reported as neutral information, never as proof
of safety.
"""
import re
from typing import Dict, List, Optional
from urllib.parse import unquote, urlparse

from backend.utils.constants import SHORTENER_DOMAINS, URL_KEYWORDS
from backend.utils.domain_utils import brand_findings, is_ip_address, split_host


def _finding(description: str, severity: str, points: int) -> Dict:
    return {"description": description, "severity": severity, "points": points}


def defang_url(url: str) -> str:
    """Make a URL non-clickable for safe display/storage: http://a.b -> hxxp://a[.]b"""
    safe = re.sub(r"(?i)^http", "hxxp", url.strip())
    return safe.replace(".", "[.]")


def url_risk_level(score: int) -> str:
    return "HIGH" if score >= 50 else "MEDIUM" if score >= 20 else "LOW"


def analyze_url(url: str) -> Dict:
    """Analyze one URL string. Returns score (0-100), findings, and parsed details."""
    raw = (url or "").strip()
    findings: List[Dict] = []
    details = {"scheme": "", "hostname": "", "path": "", "query": "", "url_length": len(raw),
               "hostname_length": 0, "subdomain_count": 0, "is_ip": False, "is_shortener": False,
               "https": False, "keyword_hits": []}

    if not raw:
        return {"url_safe": "", "risk_score": 0, "risk_level": "LOW",
                "findings": [_finding("Empty URL", "info", 0)], "details": details}

    has_scheme = "://" in raw
    try:
        parsed = urlparse(raw if has_scheme else "http://" + raw)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        return {"url_safe": defang_url(raw), "risk_score": 40, "risk_level": "MEDIUM",
                "findings": [_finding("URL is malformed and could not be parsed", "medium", 40)], "details": details}

    scheme = parsed.scheme.lower() if has_scheme else ""
    subs, registered, _ = split_host(host)
    details.update(scheme=scheme, hostname=host, path=parsed.path, query=parsed.query,
                   hostname_length=len(host), subdomain_count=len(subs), https=(scheme == "https"))

    # --- Scheme -------------------------------------------------------
    if scheme == "https":
        findings.append(_finding("HTTPS is present (this does NOT prove the site is trustworthy)", "info", 0))
    elif scheme == "http":
        findings.append(_finding("Non-HTTPS URL (traffic is not encrypted)", "low", 10))
    elif scheme == "":
        findings.append(_finding("URL has no explicit scheme", "low", 5))
    else:
        findings.append(_finding(f"Unusual URL scheme '{scheme}'", "medium", 15))

    # --- Host ---------------------------------------------------------
    if is_ip_address(host):
        details["is_ip"] = True
        findings.append(_finding("Raw IP address used instead of a domain name", "high", 30))
    elif re.fullmatch(r"\d+|0x[0-9a-f]+", host):
        details["is_ip"] = True
        findings.append(_finding("Obfuscated numeric IP address in hostname", "high", 30))
    else:
        if len(subs) >= 3:
            findings.append(_finding(f"Excessive subdomains ({len(subs)})", "medium", 15))
        elif len(subs) == 2:
            findings.append(_finding("Multiple subdomains (2)", "low", 5))
        if host.count("-") >= 3:
            findings.append(_finding("Hostname contains many hyphens", "low", 10))
        if len(host) > 30:
            findings.append(_finding(f"Unusually long hostname ({len(host)} chars)", "low", 5))
        if "xn--" in host:
            findings.append(_finding("Punycode (xn--) hostname: may hide look-alike characters", "medium", 15))
        if any(ord(c) > 127 for c in host):
            findings.append(_finding("Non-ASCII characters in hostname", "medium", 15))
        for desc, sev, pts in brand_findings(host):
            findings.append(_finding(desc, sev, pts))
        if host in SHORTENER_DOMAINS or registered in SHORTENER_DOMAINS:
            details["is_shortener"] = True
            findings.append(_finding("URL shortener hides the real destination", "medium", 15))

    # --- Structure ----------------------------------------------------
    if "@" in parsed.netloc:
        findings.append(_finding("'@' in the address can disguise the real host (userinfo trick)", "high", 20))
    if port not in (None, 80, 443):
        findings.append(_finding(f"Non-standard port {port}", "medium", 10))
    if len(raw) > 150:
        findings.append(_finding(f"Very long URL ({len(raw)} chars)", "low", 10))
    elif len(raw) > 75:
        findings.append(_finding(f"Long URL ({len(raw)} chars)", "low", 5))
    if len(re.findall(r"%[0-9a-fA-F]{2}", raw)) >= 3:
        findings.append(_finding("Heavy percent-encoding (may obscure content)", "low", 5))

    # --- Keywords (whole tokens only) ----------------------------------
    tokens = set(re.split(r"[^a-z0-9]+", unquote(host + parsed.path + "?" + parsed.query).lower()))
    hits = sorted(k for k in URL_KEYWORDS if k in tokens)
    details["keyword_hits"] = hits
    if len(hits) >= 3:
        findings.append(_finding(f"Multiple credential-related keywords in URL: {', '.join(hits)}", "high", 25))
    elif hits:
        findings.append(_finding(f"Credential-related keyword in URL: {', '.join(hits)}", "medium", 15))

    score = min(100, sum(f["points"] for f in findings))
    return {"url_safe": defang_url(raw), "risk_score": score, "risk_level": url_risk_level(score),
            "findings": findings, "details": details}


def check_link_mismatch(display_text: str, href: str) -> Optional[Dict]:
    """If a link's visible text looks like a URL/domain that differs from where it points, flag it."""
    shown = (display_text or "").strip().lower()
    if not re.search(r"\.[a-z]{2,}|\d+\.\d+\.\d+\.\d+", shown) or " " in shown:
        return None
    shown_host = urlparse(shown if "://" in shown else "http://" + shown).hostname or ""
    try:
        real_host = urlparse(href).hostname or ""
    except ValueError:
        return None
    if shown_host and real_host and shown_host != real_host:
        return _finding(f"Link text shows '{shown_host}' but points to '{real_host}'", "high", 25)
    return None
