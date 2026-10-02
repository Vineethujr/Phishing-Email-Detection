"""Turns one email into a structured feature dictionary (for the rule engine and ML)."""
from typing import Dict, List, Optional

from backend.services.attachment_analyzer import analyze_attachment
from backend.services.content_analyzer import analyze_email_content
from backend.services.sender_analyzer import analyze_sender
from backend.services.url_analyzer import analyze_url, check_link_mismatch
from backend.utils.constants import MAX_BODY_CHARS
from backend.utils.preprocessing import (ANCHOR_REGEX, clean_text_light, extract_html_links, extract_urls,
                                         strip_html)


def run_analyzers(sender: str, subject: str, body: str, attachment_name: str = "",
                  display_name: Optional[str] = None, expected_org: Optional[str] = None) -> Dict:
    """Run every analyzer once and return their raw results (no scoring here)."""
    subject = clean_text_light(subject, 500)
    raw_body = (body or "")[:MAX_BODY_CHARS]
    links = extract_html_links(raw_body)
    body = clean_text_light(strip_html(raw_body) if ANCHOR_REGEX.search(raw_body) or "</" in raw_body else raw_body)

    urls: List[str] = extract_urls(body) + [href for _, href in links if href]
    urls = list(dict.fromkeys(urls))
    url_results = [analyze_url(u) for u in urls]
    mismatch = [m for text, href in links if (m := check_link_mismatch(text, href))]

    return {
        "subject": subject, "body": body, "sender": sender,
        "sender_result": analyze_sender(sender, display_name, expected_org),
        "content_result": analyze_email_content(subject, body),
        "url_results": url_results, "link_mismatches": mismatch,
        "attachment_result": analyze_attachment(attachment_name),
    }


def features_from_results(r: Dict) -> Dict:
    """Build the named feature dictionary from analyzer results."""
    cats = r["content_result"]["categories"]
    urls = r["url_results"]
    cred_matches = " ".join(cats["credential"]["matches"])
    return {
        "urgent_keyword_count": cats["urgency"]["count"],
        "credential_keyword_count": cats["credential"]["count"],
        "financial_keyword_count": cats["financial"]["count"],
        "threat_keyword_count": cats["fear"]["count"],
        "reward_keyword_count": cats["reward"]["count"],
        "url_count": len(urls),
        "suspicious_url_count": sum(1 for u in urls if u["risk_score"] >= 30),
        "has_ip_url": int(any(u["details"]["is_ip"] for u in urls)),
        "has_shortened_url_pattern": int(any(u["details"]["is_shortener"] for u in urls)),
        "has_non_https_url": int(any(u["details"]["scheme"] != "https" for u in urls)),
        "sender_domain_length": r["sender_result"]["domain_length"],
        "subdomain_count": r["sender_result"]["subdomain_count"],
        "suspicious_attachment": int(r["attachment_result"]["attachment_risk_score"] >= 30),
        "generic_greeting": int(r["content_result"]["generic_greeting"]),
        "contains_password_request": int(any(w in cred_matches for w in ("password", "otp", "pin", "one-time", "one time"))),
        "contains_personal_info_request": int(cats["personal_info"]["count"] > 0),
        "exclamation_count": r["content_result"]["exclamation_count"],
        "uppercase_ratio": r["content_result"]["uppercase_ratio"],
        "body_length": len(r["body"]),
        "subject_length": len(r["subject"]),
    }


def extract_email_features(sender: str, subject: str, body: str, attachment_name: str = "") -> Dict:
    """Public helper: analyze an email and return only the feature dictionary."""
    return features_from_results(run_analyzers(sender, subject, body, attachment_name))
