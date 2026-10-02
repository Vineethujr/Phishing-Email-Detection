"""Rule-based phishing risk engine with explainable output.

IMPORTANT: weights and thresholds below are PROJECT ASSUMPTIONS for learning.
They should be calibrated against validation data and analyst feedback before
any real use. The score supports an analyst's judgment; it does not replace it.
"""
from typing import Dict, List, Optional, Tuple

from backend.services.feature_extractor import features_from_results, run_analyzers
from backend.utils.constants import MAX_BODY_CHARS

WEIGHTS = {
    "sender_high": 15, "sender_med": 8,
    "urgency": 10, "credential": 20, "fear": 10, "financial": 10, "reward": 10, "personal_info": 10,
    "url_high": 20, "url_med": 10, "link_mismatch": 10,
    "attachment_high": 25, "attachment_med": 12,
    "generic_greeting": 5, "formatting": 5,
    "credential_plus_bad_link": 5,   # combination bonus: two signals together are stronger evidence
}

THRESHOLDS = [(20, "LOW RISK"), (40, "MODERATE RISK"), (70, "SUSPICIOUS"), (100, "HIGH RISK / LIKELY PHISHING")]
DISCLAIMER = ("Automated risk estimate based on static indicators. It is not proof of phishing or of legitimacy; "
              "verify through a trusted channel and follow your organisation's process.")


def classify(score: int) -> str:
    """Map 0-100 to a label (thresholds are project assumptions)."""
    for upper, label in THRESHOLDS:
        if score <= upper:
            return label
    return THRESHOLDS[-1][1]


def _ind(itype: str, description: str, severity: str, points: int) -> Dict:
    return {"indicator_type": itype, "description": description, "severity": severity, "points": points}


def calculate_phishing_score(r: Dict) -> Tuple[int, List[Dict]]:
    """Combine analyzer results into (score 0-100, list of indicators with points)."""
    ind: List[Dict] = []
    W = WEIGHTS

    s = r["sender_result"]["sender_risk_score"]
    if s >= 25:
        ind.append(_ind("sender", f"Suspicious sender pattern (sender risk {s}/100)", "high", W["sender_high"]))
    elif s >= 10:
        ind.append(_ind("sender", f"Some sender warning signs (sender risk {s}/100)", "medium", W["sender_med"]))

    cats = r["content_result"]["categories"]
    rules = [("urgency", "Urgent / time-pressure language detected", "medium"),
             ("credential", "Credential request detected", "high"),
             ("fear", "Threat or fear language detected", "medium"),
             ("financial", "Financial pressure language detected", "medium"),
             ("reward", "Prize / reward claim detected", "medium"),
             ("personal_info", "Personal-information request detected", "high")]
    for key, desc, sev in rules:
        if cats[key]["count"]:
            ind.append(_ind(key, f"{desc} ({', '.join(cats[key]['matches'][:3])})", sev, W[key]))
    if r["content_result"]["generic_greeting"]:
        ind.append(_ind("generic_greeting", "Generic greeting instead of your name", "low", W["generic_greeting"]))
    if r["content_result"]["formatting_anomalies"]:
        ind.append(_ind("formatting", "Unusual formatting: " + "; ".join(r["content_result"]["formatting_anomalies"]),
                        "low", W["formatting"]))

    url_max = max((u["risk_score"] for u in r["url_results"]), default=0)
    if url_max >= 40:
        worst = max(r["url_results"], key=lambda u: u["risk_score"])
        why = ", ".join(f["description"] for f in worst["findings"] if f["points"] > 0)[:160]
        ind.append(_ind("url", f"Suspicious URL structure ({why})", "high", W["url_high"]))
    elif url_max >= 20:
        ind.append(_ind("url", "URL has some risky characteristics", "medium", W["url_med"]))
    if r["link_mismatches"]:
        ind.append(_ind("link_mismatch", r["link_mismatches"][0]["description"], "high", W["link_mismatch"]))

    a = r["attachment_result"]["attachment_risk_score"]
    if a >= 60:
        ind.append(_ind("attachment", "Attachment requires caution: " + r["attachment_result"]["explanation"], "high", W["attachment_high"]))
    elif a >= 30:
        ind.append(_ind("attachment", "Attachment type needs caution: " + r["attachment_result"]["explanation"], "medium", W["attachment_med"]))

    if cats["credential"]["count"] and url_max >= 20:
        ind.append(_ind("combination", "Credential request paired with a risky link", "high", W["credential_plus_bad_link"]))

    return min(100, sum(i["points"] for i in ind)), ind


def get_recommendations(classification: str, indicators: List[Dict]) -> List[str]:
    types = {i["indicator_type"] for i in indicators}
    if classification == "LOW RISK" and not indicators:
        return ["No strong warning signs found. Stay alert: this check does not guarantee the email is safe.",
                "If anything feels unexpected, verify through a channel you trust."]
    recs = []
    if classification in ("SUSPICIOUS", "HIGH RISK / LIKELY PHISHING"):
        recs += ["Do not click links.", "Do not open unexpected attachments.",
                 "Verify the sender through a trusted channel (a phone number or website you already know).",
                 "Report the email to your security team.",
                 "Use the organisation's official website or app directly instead of email links."]
    else:
        recs += ["Read the flagged indicators and decide whether the message is expected.",
                 "If unsure, verify with the sender through a trusted channel."]
    if "credential" in types or "personal_info" in types:
        recs.append("Never share passwords, codes or personal data by email. If you did, change your password and tell your security team.")
    if "attachment" in types:
        recs.append("Do not open the attachment; ask IT/security to inspect it in a safe environment.")
    if "financial" in types:
        recs.append("Confirm payment requests by calling a known number before paying anything.")
    return recs


def analyze_email(sender: str = "", subject: str = "", body: str = "", attachment_name: str = "",
                  display_name: Optional[str] = None, expected_org: Optional[str] = None) -> Dict:
    """Full pipeline: analyzers -> score -> classification -> explanations -> recommendations."""
    r = run_analyzers(sender, subject, body, attachment_name, display_name, expected_org)
    score, indicators = calculate_phishing_score(r)
    classification = classify(score)
    return {
        "risk_score": score, "classification": classification, "indicators": indicators,
        "sender_analysis": {k: r["sender_result"][k] for k in ("sender_risk_score", "sender_findings", "domain")},
        "content_analysis": r["content_result"],
        "url_analyses": r["url_results"], "link_mismatches": r["link_mismatches"],
        "attachment_analysis": r["attachment_result"],
        "features": features_from_results(r),
        "recommendations": get_recommendations(classification, indicators),
        "disclaimer": DISCLAIMER,
    }


def format_report(result: Dict) -> str:
    """Human-readable explanation (used by the demo script; the dashboard will render the same data)."""
    L = [f"PHISHING RISK SCORE: {result['risk_score']}/100", f"CLASSIFICATION: {result['classification']}", "", "WHY?"]
    L += [f"  ✓ {i['description']}  (+{i['points']})" for i in result["indicators"]] or ["  (no indicators triggered)"]
    sa = result["sender_analysis"]
    L += ["", f"Sender Risk: {sa['sender_risk_score']}/100"] + [f"  - {f['description']}" for f in sa["sender_findings"]]
    for u in result["url_analyses"]:
        L += ["", f"URL: {u['url_safe']}  ->  {u['risk_score']}/100 ({u['risk_level']})"]
        L += [f"  - {f['description']}" for f in u["findings"]]
    att = result["attachment_analysis"]
    if att["extension"]:
        L += ["", f"Attachment Risk: {att['attachment_risk_score']}/100 - {att['explanation']}"]
    L += ["", "RECOMMENDED ACTION:"] + [f"  - {x}" for x in result["recommendations"]] + ["", result["disclaimer"]]
    return "\n".join(L)
