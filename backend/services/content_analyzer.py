"""Content analysis: urgency, fear, financial pressure, credential requests, etc.

Phrase matching is intentionally simple and transparent. It WILL produce false
positives (a real HR email saying "urgent") and false negatives (a calm,
well-written phishing email). That is why the engine combines many signals.
"""
import re
from typing import Dict, List

CATEGORIES = {
    "urgency": {
        "label": "Urgency / time pressure", "severity": "medium",
        "explanation": "Attackers create time pressure so victims act before thinking.",
        "patterns": [r"\burgent(ly)?\b", r"\bimmediately\b", r"\bact now\b", r"\bright away\b",
                     r"\bwithin (the next )?\d+ ?(hours?|hrs?|minutes?)\b", r"\basap\b",
                     r"\bfinal (notice|warning)\b", r"\blast chance\b", r"\bexpires? (today|soon)\b",
                     r"\btoday only\b", r"\bimmediate action\b", r"\bexpires? in \d+"],
    },
    "fear": {
        "label": "Fear / threat language", "severity": "medium",
        "explanation": "Threats of suspension, loss or legal action push people to comply out of fear.",
        "patterns": [r"\bsuspend(ed|sion)?\b", r"\bwill be (locked|closed|disabled|terminated|deactivated|deleted)\b",
                     r"\bhas been (locked|limited|compromised|restricted)\b",
                     r"\bunauthori[sz]ed (activity|access|login|transaction)s?\b", r"\blegal action\b",
                     r"\bpermanently (deleted|closed|disabled)\b", r"\bsecurity breach\b", r"\blose access\b",
                     r"\bunusual (sign-?in )?activity\b"],
    },
    "financial": {
        "label": "Financial pressure", "severity": "medium",
        "explanation": "Unexpected invoices, overdue payments and gift-card requests are common fraud lures.",
        "patterns": [r"\boutstanding (payment|balance|invoice)\b", r"\binvoice (is )?(due|overdue)\b",
                     r"\boverdue\b", r"\bpayment (failed|declined|pending)\b", r"\bwire transfer\b",
                     r"\bgift cards?\b", r"\bunpaid\b", r"\bpast due\b", r"\bupdate your (billing|payment)\b",
                     r"\bbank transfer\b"],
    },
    "credential": {
        "label": "Credential request", "severity": "high",
        "explanation": "Legitimate organisations do not ask you to verify or send passwords through email links.",
        "patterns": [r"\bverify your (password|account|identity|login|credentials|email)\b",
                     r"\bconfirm your (password|login|credentials|identity|account)\b",
                     r"\b(enter|provide|send|share|submit|reply with) your (password|username|login|credentials|pin|otp|one[- ]time (code|password))\b",
                     r"\blog ?in (now )?to (verify|confirm|restore|unlock|keep|avoid)\b",
                     r"\b(update|reset|re-?enter) your (password|login|credentials)\b",
                     r"\bsign ?in (now )?to (verify|confirm|restore|unlock)\b", r"\baccount verification\b"],
    },
    "reward": {
        "label": "Reward / prize claim", "severity": "medium",
        "explanation": "Unexpected prizes are bait to collect personal data or payment.",
        "patterns": [r"\byou (have|'ve) won\b", r"\byou are (a |the )?winner\b", r"\bclaim your (prize|reward|gift)\b",
                     r"\bcongratulations\b", r"\bfree (gift|iphone)\b", r"\blottery\b", r"\bselected (as|to receive)\b"],
    },
    "personal_info": {
        "label": "Personal information request", "severity": "high",
        "explanation": "Requests for identity or banking details are a strong social-engineering signal.",
        "patterns": [r"\bconfirm your (personal|billing|payroll|account) (details|information)\b",
                     r"\bdate of birth\b", r"\bsocial security\b", r"\bssn\b", r"\bnational id\b",
                     r"\b(bank account|card|credit card) (number|details)\b", r"\bcvv\b",
                     r"\bmother'?s maiden name\b", r"\bprovide your (full name|address|phone)\b"],
    },
}
_COMPILED = {k: [re.compile(p, re.I) for p in v["patterns"]] for k, v in CATEGORIES.items()}
GENERIC_GREETING = re.compile(
    r"^\s*(dear|hello|hi|greetings)[,\s]+(valued\s+)?(customer|user|member|client|account holder|sir|madam|sir/madam|sir or madam|employee|friend|winner)\b",
    re.I)
DOUBLED_WORD = re.compile(r"\b(\w+)\s+\1\b", re.I)


def analyze_email_content(subject: str, body: str) -> Dict:
    """Scan subject+body. Returns per-category matches, formatting anomalies and explained findings."""
    subject, body = subject or "", body or ""
    text = f"{subject}\n{body}"
    result = {"categories": {}, "findings": [], "formatting_anomalies": [], "grammar_notes": []}

    for key, patterns in _COMPILED.items():
        matches = [m.group(0).lower() for p in patterns for m in p.finditer(text)]
        result["categories"][key] = {"count": len(matches), "matches": sorted(set(matches))}
        if matches:
            info = CATEGORIES[key]
            result["findings"].append({
                "category": key, "description": f"{info['label']} detected", "severity": info["severity"],
                "evidence": sorted(set(matches))[:5], "explanation": info["explanation"]})

    result["generic_greeting"] = bool(GENERIC_GREETING.search(body[:150]))
    if result["generic_greeting"]:
        result["findings"].append({"category": "generic_greeting", "description": "Generic greeting", "severity": "low",
                                   "evidence": [body[:40].strip()],
                                   "explanation": "Real organisations usually address you by name."})

    letters = [c for c in text if c.isalpha()]
    upper_ratio = (sum(c.isupper() for c in letters) / len(letters)) if letters else 0.0
    subj_letters = [c for c in subject if c.isalpha()]
    subj_upper = (sum(c.isupper() for c in subj_letters) / len(subj_letters)) if subj_letters else 0.0
    excl = text.count("!")
    result.update(uppercase_ratio=round(upper_ratio, 3), exclamation_count=excl)

    anomalies = result["formatting_anomalies"]
    if len(letters) >= 30 and upper_ratio > 0.35:
        anomalies.append("Large share of UPPERCASE text")
    elif len(subj_letters) >= 8 and subj_upper > 0.6:
        anomalies.append("ALL-CAPS subject line")
    if excl >= 3:
        anomalies.append(f"Excessive exclamation marks ({excl})")
    if re.search(r"[!?]{2,}", text) and excl < 3:
        anomalies.append("Repeated punctuation")
    for a in anomalies:
        result["findings"].append({"category": "formatting", "description": a, "severity": "low", "evidence": [],
                                   "explanation": "Shouting and heavy punctuation are used to create emotion."})

    doubled = DOUBLED_WORD.findall(text)
    if doubled:
        result["grammar_notes"].append(f"Repeated words found (e.g. '{doubled[0]}'). Weak signal only.")
    return result
