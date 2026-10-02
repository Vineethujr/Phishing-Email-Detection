"""Sender analysis. Unfamiliar domains are NOT automatically malicious;
we only score specific, explainable patterns."""
import re
from typing import Dict, List, Optional

from backend.utils.constants import BRAND_NAMES, SENDER_DOMAIN_KEYWORDS
from backend.utils.domain_utils import brand_findings, is_trusted_domain, split_host
from backend.utils.preprocessing import EMAIL_REGEX, parse_sender


def _f(description: str, severity: str, points: int) -> Dict:
    return {"description": description, "severity": severity, "points": points}


def analyze_sender(sender: str, display_name: Optional[str] = None, expected_org: Optional[str] = None) -> Dict:
    """Return {'sender_risk_score': 0-100, 'sender_findings': [...], 'domain': str, ...}.

    sender        - 'user@domain' or 'Display Name <user@domain>'
    display_name  - optional override for the display name
    expected_org  - optional organisation the email CLAIMS to be from (e.g. 'ExampleBank')
    """
    parsed_display, address = parse_sender(sender)
    display = (display_name or parsed_display or "").strip()
    findings: List[Dict] = []
    m = EMAIL_REGEX.match(address)

    if not m:
        findings.append(_f("Sender address is missing or not a valid email format", "high", 40))
        return {"sender_risk_score": 40, "sender_findings": findings, "domain": "", "local_part": "",
                "subdomain_count": 0, "domain_length": 0, "display_name": display}

    domain = m.group(1).lower()
    local = address.rsplit("@", 1)[0].lower()
    subs, registered, _ = split_host(domain)

    if len(domain) > 25:
        findings.append(_f(f"Long sender domain ({len(domain)} chars)", "low", 5))
    if len(subs) >= 3:
        findings.append(_f(f"Excessive subdomains in sender domain ({len(subs)})", "medium", 10))
    elif len(subs) == 2:
        findings.append(_f("Multiple subdomains in sender domain (2)", "low", 5))
    if domain.count("-") >= 2:
        findings.append(_f("Sender domain contains several hyphens", "low", 10))
    if "xn--" in domain:
        findings.append(_f("Punycode sender domain (may hide look-alike characters)", "medium", 15))
    if any(re.search(r"[a-z][0-9]|[0-9][a-z]", label) for label in domain.split(".")[:-1]):
        findings.append(_f("Sender domain mixes letters and digits (common in look-alike domains)", "low", 5))

    dom_hits = sorted({k for k in SENDER_DOMAIN_KEYWORDS if k in re.split(r"[^a-z0-9]+", domain)})
    if dom_hits:
        findings.append(_f(f"Sender domain contains security/account words: {', '.join(dom_hits)}", "low", 10))
    local_hits = sorted({k for k in SENDER_DOMAIN_KEYWORDS if k in re.split(r"[^a-z0-9]+", local)})
    if local_hits:
        findings.append(_f(f"Sender name uses authority words: {', '.join(local_hits)}", "low", 5))
    if len(re.findall(r"\d", local)) >= 5:
        findings.append(_f("Sender name contains many digits (looks auto-generated)", "low", 5))

    for desc, sev, pts in brand_findings(domain):
        findings.append(_f(desc, sev, pts))

    # Display-name checks -------------------------------------------------
    compact = re.sub(r"[^a-z0-9]", "", display.lower())
    claimed = [b for b in BRAND_NAMES if b in compact]
    if expected_org:
        claimed.append(re.sub(r"[^a-z0-9]", "", expected_org.lower()))
    dom_compact = re.sub(r"[^a-z0-9]", "", domain)
    for org in dict.fromkeys(claimed):
        if org and org not in dom_compact and not is_trusted_domain(domain):
            findings.append(_f(f"Display name suggests '{org}' but the sender domain does not match", "high", 25))
    embedded = re.search(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", display)
    if embedded and embedded.group(1).lower() != domain:
        findings.append(_f("Display name contains a different email domain than the real sender", "high", 25))

    score = min(100, sum(f["points"] for f in findings))
    return {"sender_risk_score": score, "sender_findings": findings, "domain": domain, "local_part": local,
            "subdomain_count": len(subs), "domain_length": len(domain), "display_name": display}
