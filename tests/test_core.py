"""Phase 1 tests: analyzers, risk engine, preprocessing, dataset generator.
(Database / API / ML / history tests arrive with their phases: T22-T25.)"""
import csv
import os
import re

import pytest

from backend.services.attachment_analyzer import analyze_attachment
from backend.services.content_analyzer import analyze_email_content
from backend.services.feature_extractor import extract_email_features
from backend.services.risk_engine import analyze_email, calculate_phishing_score, classify
from backend.services.sender_analyzer import analyze_sender
from backend.services.url_analyzer import analyze_url, check_link_mismatch, defang_url
from backend.utils.eml_parser import parse_eml
from backend.utils.preprocessing import (clean_text_light, extract_attachment_extension, extract_sender_domain,
                                         extract_urls, preprocess_dataframe)
from run_demo import LEGIT, PHISH

DATASET = os.path.join(os.path.dirname(__file__), "..", "data", "phishing_email_dataset.csv")


def test_t01_legitimate_email(actual):
    """Legitimate workshop reminder
    Input: training@example.org / Cybersecurity Workshop Reminder
    Expected: LOW RISK, score <= 20, no indicators"""
    r = analyze_email(**LEGIT)
    actual(f"{r['risk_score']}/100 {r['classification']}, {len(r['indicators'])} indicators")
    assert r["classification"] == "LOW RISK" and r["risk_score"] <= 20 and not r["indicators"]


def test_t02_urgent_phishing_email(actual):
    """Urgent synthetic phishing email (demo scenario)
    Input: security-alert@account-check.invalid.test, URGENT verify subject, raw-IP URL
    Expected: HIGH RISK / LIKELY PHISHING (score >= 71)"""
    r = analyze_email(**PHISH)
    types = {i["indicator_type"] for i in r["indicators"]}
    actual(f"{r['risk_score']}/100 {r['classification']}; types={sorted(types)}")
    assert r["classification"] == "HIGH RISK / LIKELY PHISHING"
    assert {"urgency", "credential", "sender", "url", "fear"} <= types


def test_t03_credential_request(actual):
    """Credential request wording
    Input: 'Please verify your password and enter your password below.'
    Expected: credential category detected"""
    c = analyze_email_content("Hello", "Please verify your password and enter your password below.")
    actual(c["categories"]["credential"])
    assert c["categories"]["credential"]["count"] >= 2


def test_t04_financial_request(actual):
    """Financial pressure wording
    Input: 'Your invoice is overdue. Buy gift cards for the outstanding payment.'
    Expected: financial category detected"""
    c = analyze_email_content("Payment", "Your invoice is overdue. Buy gift cards to clear the outstanding payment.")
    actual(c["categories"]["financial"])
    assert c["categories"]["financial"]["count"] >= 2


def test_t05_generic_greeting(actual):
    """Generic greeting
    Input: 'Dear Customer, ...' vs 'Hi Maya, ...'
    Expected: True for 'Dear Customer', False for a named greeting"""
    a = analyze_email_content("x", "Dear Customer,\nHello there.")["generic_greeting"]
    b = analyze_email_content("x", "Hi Maya,\nSee you soon.")["generic_greeting"]
    actual(f"generic={a}, named={b}")
    assert a is True and b is False


def test_t06_safe_url(actual):
    """Ordinary HTTPS URL
    Input: https://example.org/workshops/cybersecurity
    Expected: risk 0, HTTPS shown as info only"""
    u = analyze_url("https://example.org/workshops/cybersecurity")
    actual(f"risk={u['risk_score']} findings={[f['description'][:30] for f in u['findings']]}")
    assert u["risk_score"] == 0 and u["details"]["https"]


def test_t07_raw_ip_url(actual):
    """Raw IP URL
    Input: http://198.51.100.10/verify-account
    Expected: raw-IP, non-HTTPS and keyword findings; HIGH level"""
    u = analyze_url("http://198.51.100.10/verify-account")
    text = " | ".join(f["description"] for f in u["findings"])
    actual(f"risk={u['risk_score']} {u['risk_level']}")
    assert "Raw IP" in text and "Non-HTTPS" in text and "keyword" in text and u["risk_level"] == "HIGH"


def test_t08_non_https_url(actual):
    """Non-HTTPS URL
    Input: http://example.org/page
    Expected: non-HTTPS finding worth 10 points"""
    u = analyze_url("http://example.org/page")
    actual(f"risk={u['risk_score']}")
    assert u["risk_score"] == 10


def test_t09_excessive_subdomains(actual):
    """Excessive subdomains
    Input: https://a.b.c.d.example.com/
    Expected: 'Excessive subdomains' finding, subdomain_count = 4"""
    u = analyze_url("https://a.b.c.d.example.com/")
    actual(f"subdomains={u['details']['subdomain_count']} risk={u['risk_score']}")
    assert u["details"]["subdomain_count"] == 4 and any("Excessive" in f["description"] for f in u["findings"])


def test_t10_url_keyword(actual):
    """Suspicious keyword in URL
    Input: https://example.net/login/verify/password-reset
    Expected: multiple credential keywords flagged"""
    u = analyze_url("https://example.net/login/verify/password-reset")
    actual(u["details"]["keyword_hits"])
    assert {"login", "verify", "password", "reset"} <= set(u["details"]["keyword_hits"])


def test_t11_no_url(actual):
    """Email without URLs
    Input: plain body with no links
    Expected: url_count 0 and no URL indicator"""
    r = analyze_email("a@example.org", "Hi", "See you at lunch.")
    actual(f"url_count={r['features']['url_count']}")
    assert r["features"]["url_count"] == 0 and not any(i["indicator_type"] == "url" for i in r["indicators"])


def test_t12_multiple_urls(actual):
    """Multiple URLs (duplicates removed)
    Input: 3 distinct URLs plus one repeated
    Expected: 3 analyses"""
    body = "See https://example.org/a and http://198.51.100.5/x and https://example.net/b. Again https://example.org/a"
    r = analyze_email("a@example.org", "Links", body)
    actual(f"url_count={r['features']['url_count']} suspicious={r['features']['suspicious_url_count']}")
    assert r["features"]["url_count"] == 3 and r["features"]["suspicious_url_count"] == 1


def test_t13_normal_attachment(actual):
    """Normal attachment
    Input: agenda.pdf
    Expected: risk 0"""
    a = analyze_attachment("agenda.pdf")
    actual(f"risk={a['attachment_risk_score']}")
    assert a["attachment_risk_score"] == 0


@pytest.mark.parametrize("name", [".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".ps1"])
def test_t14_executable_attachment(name, actual):
    """Executable/script attachment
    Input: setup.<ext> for exe, scr, bat, cmd, js, vbs, ps1
    Expected: high risk (>= 60) for every extension"""
    a = analyze_attachment("setup" + name)
    actual(f"{name}: {a['attachment_risk_score']}")
    assert a["attachment_risk_score"] >= 60


def test_t15_double_extension(actual):
    """Double extension
    Input: invoice.pdf.exe
    Expected: double-extension finding, risk >= 95"""
    a = analyze_attachment("invoice.pdf.exe")
    actual(f"risk={a['attachment_risk_score']}")
    assert any("Double extension" in f["description"] for f in a["findings"]) and a["attachment_risk_score"] >= 95


def test_t16_empty_subject(actual):
    """Empty subject
    Input: subject='' with normal body
    Expected: no crash, subject_length 0"""
    r = analyze_email("a@example.org", "", "Hello, see you tomorrow.")
    actual(f"score={r['risk_score']} subject_length={r['features']['subject_length']}")
    assert r["features"]["subject_length"] == 0


def test_t17_empty_body(actual):
    """Empty body
    Input: body=''
    Expected: no crash, score 0 for a clean sender"""
    r = analyze_email("a@example.org", "Hello", "")
    actual(f"score={r['risk_score']} body_length={r['features']['body_length']}")
    assert r["risk_score"] == 0 and r["features"]["body_length"] == 0


@pytest.mark.parametrize("bad", ["not-an-email", "", "user@", "@example.com", "user@nodot"])
def test_t18_invalid_sender(bad, actual):
    """Invalid sender
    Input: 'not-an-email', '', 'user@', '@example.com', 'user@nodot'
    Expected: sender risk 40 with 'not a valid email format' finding"""
    s = analyze_sender(bad)
    actual(f"{bad!r}: {s['sender_risk_score']}")
    assert s["sender_risk_score"] == 40 and "valid email" in s["sender_findings"][0]["description"]


def test_t19_high_uppercase_ratio(actual):
    """High uppercase ratio
    Input: 'URGENT!!! CLICK NOW TO VERIFY YOUR ACCOUNT TODAY'
    Expected: uppercase ratio > 0.8 and a formatting anomaly"""
    c = analyze_email_content("NOTICE", "URGENT CLICK NOW TO VERIFY YOUR ACCOUNT TODAY PLEASE")
    actual(f"ratio={c['uppercase_ratio']} anomalies={c['formatting_anomalies']}")
    assert c["uppercase_ratio"] > 0.8 and c["formatting_anomalies"]


def test_t20_multiple_exclamations(actual):
    """Multiple exclamation marks
    Input: 'Win big!!! Act now!!!'
    Expected: exclamation_count 6 and anomaly flagged"""
    c = analyze_email_content("Hey", "Win big!!! Act now!!!")
    actual(f"count={c['exclamation_count']} anomalies={c['formatting_anomalies']}")
    assert c["exclamation_count"] == 6 and any("exclamation" in a.lower() for a in c["formatting_anomalies"])


def test_t21_score_boundaries(actual):
    """Rule-score boundaries
    Input: scores 0, 20, 21, 40, 41, 70, 71, 100
    Expected: LOW, LOW, MODERATE, MODERATE, SUSPICIOUS, SUSPICIOUS, HIGH, HIGH"""
    got = [classify(s) for s in (0, 20, 21, 40, 41, 70, 71, 100)]
    actual(got)
    assert got == ["LOW RISK", "LOW RISK", "MODERATE RISK", "MODERATE RISK", "SUSPICIOUS", "SUSPICIOUS",
                   "HIGH RISK / LIKELY PHISHING", "HIGH RISK / LIKELY PHISHING"]


def test_t26_score_cap(actual):
    """Score never exceeds 100
    Input: fake results with 200 points of indicators
    Expected: 100"""
    r = {"sender_result": {"sender_risk_score": 90}, "url_results": [{"risk_score": 100, "findings": []}], "link_mismatches": [],
         "attachment_result": {"attachment_risk_score": 100, "explanation": "x"},
         "content_result": {"categories": {k: {"count": 1, "matches": ["m"]} for k in
                            ("urgency", "credential", "fear", "financial", "reward", "personal_info")},
                            "generic_greeting": True, "formatting_anomalies": ["x"]}}
    score, _ = calculate_phishing_score(r)
    actual(score)
    assert score == 100


def test_t27_shortener(actual):
    """URL shortener pattern
    Input: https://bit.ly/abc123 and http://short.example/xyz
    Expected: both flagged as shorteners"""
    a, b = analyze_url("https://bit.ly/abc123"), analyze_url("http://short.example/xyz")
    actual(f"{a['details']['is_shortener']}, {b['details']['is_shortener']}")
    assert a["details"]["is_shortener"] and b["details"]["is_shortener"]


def test_t28_lookalike_and_brand(actual):
    """Lookalike domain and brand misuse
    Input: examp1ebank.example.net (swap) and examplebank.example.com (trusted)
    Expected: lookalike flagged; trusted domain not flagged"""
    bad = analyze_sender("support@examp1ebank.example.net")
    good = analyze_sender("alerts@examplebank.example.com")
    actual(f"lookalike={bad['sender_risk_score']} trusted={good['sender_risk_score']}")
    assert any("look" in f["description"].lower() for f in bad["sender_findings"]) and good["sender_risk_score"] == 0


def test_t29_display_name_mismatch(actual):
    """Display-name / domain mismatch
    Input: 'ExampleBank Support <alerts@verify-mail.invalid.test>'
    Expected: mismatch finding (+25)"""
    s = analyze_sender("ExampleBank Support <alerts@verify-mail.invalid.test>")
    actual(s["sender_risk_score"])
    assert any("Display name suggests" in f["description"] for f in s["sender_findings"])


def test_t30_https_not_trusted(actual):
    """HTTPS is not proof of safety
    Input: https://198.51.100.10/verify-account
    Expected: still flagged HIGH despite HTTPS"""
    u = analyze_url("https://198.51.100.10/verify-account")
    actual(f"risk={u['risk_score']} {u['risk_level']}")
    assert u["details"]["https"] and u["risk_level"] in ("MEDIUM", "HIGH") and u["risk_score"] >= 40


def test_t31_link_text_mismatch(actual):
    """Link text vs destination mismatch
    Input: <a href='http://198.51.100.9/x'>www.example.org</a>
    Expected: mismatch finding and engine indicator"""
    m = check_link_mismatch("www.example.org", "http://198.51.100.9/x")
    r = analyze_email("a@example.org", "Hi", "<p>Please open <a href='http://198.51.100.9/x'>www.example.org</a></p>")
    actual(m["description"] if m else None)
    assert m and any(i["indicator_type"] == "link_mismatch" for i in r["indicators"])


def test_t32_defang(actual):
    """URLs are stored defanged
    Input: http://198.51.100.10/verify-account
    Expected: no clickable 'http://' in stored form"""
    d = defang_url("http://198.51.100.10/verify-account")
    actual(d)
    assert "http://" not in d and d.startswith("hxxp")


def test_t33_false_positive_hr(actual):
    """Legitimate urgent HR email (known false-positive risk)
    Input: 'Urgent: Submit your documents today' from hr@example.com
    Expected: urgency is flagged but the email is NOT classified HIGH"""
    r = analyze_email("hr@example.com", "Urgent: Submit your documents today",
                      "Hi Sam,\n\nPlease submit your signed documents today. Upload at https://hr.example.com/documents.")
    actual(f"{r['risk_score']}/100 {r['classification']}")
    assert any(i["indicator_type"] == "urgency" for i in r["indicators"]) and r["classification"] != "HIGH RISK / LIKELY PHISHING"


def test_t34_false_negative_subtle(actual):
    """Subtle phishing can evade rules (known false-negative risk)
    Input: calm 'document shared' email with an unfamiliar https link
    Expected: LOW RISK - documents the limitation honestly"""
    r = analyze_email("docs-share@example-docs.example.net", "Document shared with you",
                      "Hi Sam,\n\nA colleague shared notes. View: https://docs-share.example.net/view/12345")
    actual(f"{r['risk_score']}/100 {r['classification']}")
    assert r["classification"] == "LOW RISK"


def test_t35_feature_dictionary(actual):
    """Feature extraction returns all named features
    Input: demo phishing email
    Expected: 18 required features present with expected values"""
    f = extract_email_features(PHISH["sender"], PHISH["subject"], PHISH["body"])
    need = ["urgent_keyword_count", "credential_keyword_count", "financial_keyword_count", "threat_keyword_count",
            "url_count", "suspicious_url_count", "has_ip_url", "has_shortened_url_pattern", "sender_domain_length",
            "subdomain_count", "suspicious_attachment", "generic_greeting", "contains_password_request",
            "contains_personal_info_request", "exclamation_count", "uppercase_ratio", "body_length", "subject_length"]
    actual({k: f[k] for k in ("url_count", "has_ip_url", "generic_greeting", "contains_password_request")})
    assert all(k in f for k in need) and f["has_ip_url"] == 1 and f["contains_password_request"] == 1


def test_t36_preprocessing(actual):
    """Preprocessing keeps evidence and removes duplicates
    Input: DataFrame with duplicate row, HTML entity, ALL CAPS, missing values
    Expected: 1 unique row kept; caps and URL preserved; sender domain extracted"""
    import pandas as pd
    df = pd.DataFrame({"sender": ["A <x@Example.ORG>"] * 2 + [None], "subject": ["HELLO&amp;!"] * 2 + ["s"],
                       "body": ["Go to http://198.51.100.7/x NOW"] * 2 + [None],
                       "urls": ["", "", ""], "attachment_name": ["a.PDF.exe"] * 2 + [None], "label": ["phishing"] * 2 + ["legitimate"]})
    out = preprocess_dataframe(df)
    actual(f"rows={len(out)} subject={out.loc[0, 'subject']!r} domain={out.loc[0, 'sender_domain']}")
    assert len(out) == 2 and out.loc[0, "subject"] == "HELLO&!" and "NOW" in out.loc[0, "body"]
    assert out.loc[0, "sender_domain"] == "example.org" and out.loc[0, "attachment_ext"] == ".exe"


def test_t37_helpers(actual):
    """Small preprocessing helpers
    Input: URL with trailing punctuation, filename with double ext, control chars
    Expected: punctuation trimmed, '.exe' returned, control chars removed"""
    urls = extract_urls("Visit https://example.org/a, then (http://198.51.100.1/b).")
    actual(urls)
    assert urls == ["https://example.org/a", "http://198.51.100.1/b"]
    assert extract_attachment_extension("Report.PDF.EXE") == ".exe" and extract_sender_domain("bad") == ""
    assert clean_text_light("a\x00b\x07  c") == "ab c"


def test_t38_eml_parsing(actual):
    """Safe .eml parsing
    Input: raw RFC-822 message with a text body and an attachment
    Expected: sender, subject, body and attachment FILENAME extracted (payload not used)"""
    raw = (b"From: Team <team@example.org>\r\nTo: you@example.com\r\nSubject: Notes\r\nMIME-Version: 1.0\r\n"
           b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nHello there\r\n"
           b"--B\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"a.pdf.exe\"\r\n\r\nAAAA\r\n--B--\r\n")
    p = parse_eml(raw)
    actual(f"{p['sender']} | {p['subject']} | {p['attachment_name']}")
    assert p["subject"] == "Notes" and "Hello" in p["body"] and p["attachment_name"] == "a.pdf.exe"
    with pytest.raises(ValueError):
        parse_eml(b"x" * 2_000_000)


def test_t39_dataset_safety(actual):
    """Synthetic dataset is large, balanced enough and uses only fictional infrastructure
    Input: data/phishing_email_dataset.csv
    Expected: >= 500 rows, unique IDs, only reserved domains and documentation IPs"""
    with open(DATASET, encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    allowed = re.compile(r"(example\.(com|org|net)|invalid\.test|\.example)$")
    ip_ok = re.compile(r"^(192\.0\.2|198\.51\.100|203\.0\.113)\.\d+$")
    bad = []
    for r in rows:
        hosts = [r["sender_domain"]] + [re.sub(r"^\w+://", "", u).split("/")[0].split(":")[0] for u in r["urls"].split()]
        bad += [h for h in hosts if h and not (allowed.search(h) or ip_ok.match(h))]
    labels = {r["label"] for r in rows}
    actual(f"rows={len(rows)} labels={sorted(labels)} unexpected_hosts={bad[:3]}")
    assert len(rows) >= 500 and len({r["email_id"] for r in rows}) == len(rows) and not bad and labels == {"LEGITIMATE", "PHISHING"}
