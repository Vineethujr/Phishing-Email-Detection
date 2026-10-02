"""Phase 3 tests: database, REST API, validation, history, security controls."""
import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.config import Settings
from backend.database import Database
from run_demo import LEGIT, PHISH


def make_client(tmp_path, **kw):
    s = Settings(db_path=str(tmp_path / "t.db"), log_path=str(tmp_path / "sec.log"),
                 model_path=str(tmp_path / "no_model.joblib"), **kw)
    return TestClient(create_app(s)), s


@pytest.fixture
def client(tmp_path):
    return make_client(tmp_path)[0]


def analyze(c, mail):
    return c.post("/api/analyze", json=mail)


# ------------------------------------------------------------------ T22 database
def test_t22a_database_save_and_read(tmp_path, actual):
    """Database save
    Input: one analysis result saved through Database.save_analysis
    Expected: row, indicators and URL rows retrievable by id"""
    c, s = make_client(tmp_path)
    r = analyze(c, PHISH).json()
    got = Database(s.db_path).get_analysis(r["analysis_id"])
    actual(f"id={got['analysis_id']} indicators={len(got['indicators'])} urls={len(got['url_analyses'])} score={got['risk_score']}")
    assert got["classification"].startswith("HIGH") and len(got["indicators"]) >= 5 and len(got["url_analyses"]) == 1


def test_t22b_no_email_body_or_raw_url_stored(tmp_path, actual):
    """Privacy: body and clickable URLs are not stored
    Input: analyze phishing email, then dump the whole database
    Expected: body text and 'http://' absent from every stored value"""
    c, s = make_client(tmp_path)
    analyze(c, PHISH)
    conn = sqlite3.connect(s.db_path)
    dump = "\n".join(conn.iterdump())
    conn.close()
    actual(f"body_fragment_found={'Enter your password' in dump} clickable_url_found={'http://198' in dump}")
    assert "Enter your password" not in dump and "http://198" not in dump and "hxxp://198[.]51[.]100[.]10" in dump


def test_t22c_cascade_delete(tmp_path, actual):
    """Foreign keys cascade
    Input: delete an analysis
    Expected: its indicators and URL rows disappear too"""
    c, s = make_client(tmp_path)
    aid = analyze(c, PHISH).json()["analysis_id"]
    assert c.delete(f"/api/analyses/{aid}").status_code == 204
    conn = sqlite3.connect(s.db_path)
    left = conn.execute("SELECT (SELECT COUNT(*) FROM indicators), (SELECT COUNT(*) FROM url_analyses)").fetchone()
    conn.close()
    actual(f"indicators={left[0]} url_rows={left[1]}")
    assert left == (0, 0)


# ------------------------------------------------------------------ T23 API validation
def test_t23a_analyze_ok(client, actual):
    """POST /api/analyze with valid data
    Input: demo phishing email
    Expected: 200, HIGH RISK, analysis_id, recommendations, disclaimer"""
    r = analyze(client, PHISH)
    j = r.json()
    actual(f"{r.status_code} {j['risk_score']} {j['classification']} id={j['analysis_id']} mode={j['mode']}")
    assert r.status_code == 200 and j["classification"].startswith("HIGH") and j["recommendations"] and j["disclaimer"]


def test_t23b_empty_request_rejected(client, actual):
    """Validation: nothing to analyze
    Input: {}
    Expected: 422"""
    r = client.post("/api/analyze", json={})
    actual(r.status_code)
    assert r.status_code == 422


@pytest.mark.parametrize("payload", [
    {"body": "x" * 200_001},
    {"subject": "s" * 501, "body": "b"},
    {"body": "hi", "attachment_name": "../../etc/passwd"},
    {"body": "hi", "attachment_name": "a\\b.exe"},
    {"body": 123},
])
def test_t23c_bad_payloads(client, payload, actual):
    """Validation: oversized fields, path traversal in filename, wrong types
    Input: several malformed payloads
    Expected: 422 for each"""
    r = client.post("/api/analyze", json=payload)
    actual(r.status_code)
    assert r.status_code == 422


def test_t23d_url_endpoint(client, actual):
    """POST /api/analyze/url
    Input: http://198.51.100.10/verify-account
    Expected: HIGH level, defanged URL, nothing stored"""
    r = client.post("/api/analyze/url", json={"url": "http://198.51.100.10/verify-account"})
    j = r.json()
    total = client.get("/api/analyses").json()["total"]
    actual(f"{r.status_code} {j['risk_level']} {j['url_safe']} stored={total}")
    assert r.status_code == 200 and j["risk_level"] == "HIGH" and j["url_safe"].startswith("hxxp") and total == 0
    assert client.post("/api/analyze/url", json={"url": ""}).status_code == 422


def test_t23e_upload_eml(client, actual):
    """POST /api/analyze/upload with a safe .eml
    Input: eml with attachment named invoice.pdf.exe (payload ignored)
    Expected: 200 and attachment indicator present"""
    raw = (b"From: Billing <billing@invoice-center.example.net>\r\nSubject: Invoice overdue\r\nMIME-Version: 1.0\r\n"
           b"Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-Type: text/plain\r\n\r\nDear Customer, your invoice is overdue.\r\n"
           b"--B\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\r\nAAAA\r\n--B--\r\n")
    r = client.post("/api/analyze/upload", files={"file": ("mail.eml", raw, "message/rfc822")})
    types = {i["indicator_type"] for i in r.json()["indicators"]}
    actual(f"{r.status_code} {r.json()['classification']} types={sorted(types)}")
    assert r.status_code == 200 and "attachment" in types


def test_t23f_upload_plain_txt(client, actual):
    """Upload a headerless .txt file
    Input: text body only
    Expected: 200, analyzed as body text"""
    r = client.post("/api/analyze/upload", files={"file": ("note.txt", b"Dear Customer, verify your password immediately.", "text/plain")})
    actual(f"{r.status_code} {r.json().get('classification')}")
    assert r.status_code == 200 and any(i["indicator_type"] == "credential" for i in r.json()["indicators"])


def test_t23g_upload_restrictions(tmp_path, actual):
    """Upload validation
    Input: .exe file, oversized .txt
    Expected: 415 for wrong type, 413 for too large"""
    c, _ = make_client(tmp_path, max_upload_bytes=1000)
    a = c.post("/api/analyze/upload", files={"file": ("a.exe", b"MZ", "application/octet-stream")})
    b = c.post("/api/analyze/upload", files={"file": ("a.txt", b"x" * 2000, "text/plain")})
    actual(f"exe={a.status_code} big={b.status_code}")
    assert a.status_code == 415 and b.status_code == 413


# ------------------------------------------------------------------ T25 history
def _seed(c):
    analyze(c, PHISH)
    analyze(c, LEGIT)
    analyze(c, dict(sender="hr@example.com", subject="Urgent: Submit your documents today", body="Hi Sam, please submit today."))


def test_t25a_history_list(client, actual):
    """History retrieval
    Input: 3 analyses then GET /api/analyses
    Expected: total 3, newest first, no body field"""
    _seed(client)
    j = client.get("/api/analyses").json()
    actual(f"total={j['total']} ids={[i['analysis_id'] for i in j['items']]}")
    assert j["total"] == 3 and [i["analysis_id"] for i in j["items"]] == [3, 2, 1] and "body" not in j["items"][0]


def test_t25b_filter_sort_search(client, actual):
    """History filter, sort, search
    Input: classification=HIGH; sort=risk_asc; q=workshop
    Expected: only HIGH rows; ascending scores; subject match"""
    _seed(client)
    hi = client.get("/api/analyses?classification=HIGH").json()
    asc = [i["risk_score"] for i in client.get("/api/analyses?sort=risk_asc").json()["items"]]
    q = client.get("/api/analyses?q=workshop").json()
    actual(f"high={hi['total']} asc={asc} search={q['total']}")
    assert hi["total"] == 1 and asc == sorted(asc) and q["total"] == 1


def test_t25c_get_one_and_404(client, actual):
    """GET /api/analyses/{id}
    Input: existing id and unknown id
    Expected: 200 with indicators and URL analyses; 404 for unknown"""
    aid = analyze(client, PHISH).json()["analysis_id"]
    ok, missing = client.get(f"/api/analyses/{aid}"), client.get("/api/analyses/9999")
    actual(f"{ok.status_code}/{missing.status_code}")
    assert ok.status_code == 200 and ok.json()["indicators"] and missing.status_code == 404
    assert client.get("/api/analyses/abc").status_code == 422


def test_t25d_query_validation_and_injection(client, actual):
    """Bad query params and SQL-injection-looking search
    Input: limit=0, sort=evil, classification=bogus, q="' OR 1=1 --"
    Expected: 422 for invalid params; injection string treated as plain text (0 results, no error)"""
    _seed(client)
    bad = [client.get(u).status_code for u in ("/api/analyses?limit=0", "/api/analyses?sort=evil;DROP", "/api/analyses?classification=bogus")]
    inj = client.get("/api/analyses", params={"q": "' OR 1=1 --"})
    actual(f"bad={bad} injection={inj.status_code} total={inj.json()['total']}")
    assert bad == [422, 422, 422] and inj.status_code == 200 and inj.json()["total"] == 0
    assert client.get("/api/analyses").json()["total"] == 3       # tables intact


def test_t25e_like_wildcards_escaped(client, actual):
    """Search wildcards are literal
    Input: q='%'
    Expected: no rows (a literal % is not in any subject)"""
    _seed(client)
    j = client.get("/api/analyses", params={"q": "%"}).json()
    actual(j["total"])
    assert j["total"] == 0


def test_t25f_pagination(client, actual):
    """Pagination
    Input: 3 analyses, limit=2 offset=2
    Expected: total 3, 1 item returned"""
    _seed(client)
    j = client.get("/api/analyses?limit=2&offset=2").json()
    actual(f"total={j['total']} returned={len(j['items'])}")
    assert j["total"] == 3 and len(j["items"]) == 1


# ------------------------------------------------------------------ dashboard
def test_t26a_dashboard_stats(client, actual):
    """GET /api/dashboard/stats
    Input: 3 analyses
    Expected: totals add up; 14 trend days; 10 score buckets"""
    _seed(client)
    j = client.get("/api/dashboard/stats").json()
    actual(f"total={j['total']} avg={j['average_risk_score']} classes={j['by_classification']}")
    assert j["total"] == 3 and sum(j["by_classification"].values()) == 3 and len(j["trend"]) == 14
    assert len(j["score_distribution"]) == 10 and sum(b["count"] for b in j["score_distribution"]) == 3
    assert j["likely_phishing"] == 1 and sum(t["total"] for t in j["trend"]) == 3


def test_t26b_dashboard_empty(client, actual):
    """Stats on an empty database
    Input: no analyses
    Expected: zeros, no crash"""
    j = client.get("/api/dashboard/stats").json()
    actual(f"total={j['total']} avg={j['average_risk_score']}")
    assert j["total"] == 0 and j["average_risk_score"] == 0


def test_t26c_indicator_stats(client, actual):
    """GET /api/dashboard/indicators
    Input: phishing + legitimate analyses
    Expected: credential/urgency in top indicators and their phrases in top keywords"""
    _seed(client)
    j = client.get("/api/dashboard/indicators").json()
    types = [t["indicator_type"] for t in j["top_indicators"]]
    kws = [k["keyword"] for k in j["top_keywords"]]
    actual(f"types={types[:4]} keywords={kws[:3]}")
    assert "credential" in types and "urgency" in types and "urgent" in kws


# ------------------------------------------------------------------ security controls
def test_t27a_xss_payload_is_data(client, actual):
    """XSS-looking input is treated as data
    Input: subject '<script>alert(1)</script>'
    Expected: 200; stored/returned as plain text (frontend must escape when rendering)"""
    r = client.post("/api/analyze", json={"sender": "a@example.org", "subject": "<script>alert(1)</script>", "body": "hi"})
    got = client.get(f"/api/analyses/{r.json()['analysis_id']}").json()
    actual(f"{r.status_code} stored={got['subject']!r} content-type={client.get('/api/health').headers['content-type']}")
    assert r.status_code == 200 and got["subject"] == "<script>alert(1)</script>"


def test_t27b_security_headers(client, actual):
    """Security headers
    Input: any API response
    Expected: nosniff, DENY framing, no-store caching"""
    h = client.get("/api/health").headers
    actual({k: h.get(k) for k in ("x-content-type-options", "x-frame-options", "cache-control")})
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY" and h["cache-control"] == "no-store"


def test_t27c_rate_limit(tmp_path, actual):
    """Rate limiting
    Input: 4 rapid analyze calls with limit 3/min
    Expected: first 3 succeed, 4th returns 429 with Retry-After"""
    c, _ = make_client(tmp_path, rate_limit_per_minute=3)
    codes = [analyze(c, LEGIT).status_code for _ in range(3)]
    r = analyze(c, LEGIT)
    actual(f"{codes} then {r.status_code} retry-after={r.headers.get('retry-after')}")
    assert codes == [200] * 3 and r.status_code == 429 and "retry-after" in r.headers


def test_t27d_request_size_limit(tmp_path, actual):
    """Oversized request body
    Input: Content-Length above limit
    Expected: 413"""
    c, _ = make_client(tmp_path, max_request_bytes=500)
    r = c.post("/api/analyze", json={"body": "x" * 2000})
    actual(r.status_code)
    assert r.status_code == 413


def test_t27e_security_log_written(tmp_path, actual):
    """Security events are logged without email content
    Input: rate-limit hit and a delete
    Expected: log has events but not the email subject"""
    c, s = make_client(tmp_path, rate_limit_per_minute=1)
    aid = analyze(c, PHISH).json()["analysis_id"]
    analyze(c, PHISH)
    c.delete(f"/api/analyses/{aid}")
    log = open(s.log_path, encoding="utf-8").read()
    actual(f"rate_limited={'rate_limited' in log} deleted={'analysis_deleted' in log} subject_in_log={'Verify Your Account' in log}")
    assert "rate_limited" in log and "analysis_deleted" in log and "Verify Your Account" not in log


def test_t27f_health(client, actual):
    """GET /api/health
    Input: none
    Expected: status ok, ml_model_loaded False (no model in the temp path)"""
    j = client.get("/api/health").json()
    actual(j)
    assert j["status"] == "ok" and j["ml_model_loaded"] is False


# ------------------------------------------------------------------ authentication
CRED = {"username": "alice_admin", "password": "S3cure-pass!"}


def test_t28a_register_login_logout(tmp_path, actual):
    """Auth flow
    Input: register, login, logout, then reuse token
    Expected: 201 (first user is admin), 200 with token, 204, then token invalid"""
    c, s = make_client(tmp_path, auth_required=True)
    reg = c.post("/api/register", json=CRED)
    tok = c.post("/api/login", json=CRED).json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    ok = c.get("/api/analyses", headers=h).status_code
    out = c.post("/api/logout", headers=h).status_code
    after = c.get("/api/analyses", headers=h).status_code
    actual(f"register={reg.status_code} role={reg.json()['role']} use={ok} logout={out} reuse={after}")
    assert (reg.status_code, ok, out, after) == (201, 200, 204, 401) and reg.json()["role"] == "admin"


def test_t28b_protected_endpoints_need_token(tmp_path, actual):
    """Authentication required
    Input: calls without a token when AUTH_REQUIRED=true
    Expected: 401 for analyze, history, stats; health stays public"""
    c, _ = make_client(tmp_path, auth_required=True)
    codes = [c.post("/api/analyze", json=LEGIT).status_code, c.get("/api/analyses").status_code,
             c.get("/api/dashboard/stats").status_code, c.get("/api/health").status_code]
    actual(codes)
    assert codes == [401, 401, 401, 200]


def test_t28c_authorization_delete_admin_only(tmp_path, actual):
    """Authorization (roles)
    Input: analyst tries DELETE, admin deletes
    Expected: 403 for analyst, 204 for admin"""
    c, _ = make_client(tmp_path, auth_required=True)
    c.post("/api/register", json=CRED)
    c.post("/api/register", json={"username": "bob_analyst", "password": "An0ther-pass!"})
    admin = {"Authorization": "Bearer " + c.post("/api/login", json=CRED).json()["access_token"]}
    bob = {"Authorization": "Bearer " + c.post("/api/login", json={"username": "bob_analyst", "password": "An0ther-pass!"}).json()["access_token"]}
    aid = c.post("/api/analyze", json=LEGIT, headers=bob).json()["analysis_id"]
    a, b = c.delete(f"/api/analyses/{aid}", headers=bob).status_code, c.delete(f"/api/analyses/{aid}", headers=admin).status_code
    actual(f"analyst={a} admin={b}")
    assert (a, b) == (403, 204)


def test_t28d_bad_login_and_duplicates(tmp_path, actual):
    """Login failures and duplicate usernames
    Input: wrong password, unknown user, duplicate register, weak password
    Expected: identical 401 message, 409, 422"""
    c, _ = make_client(tmp_path)
    c.post("/api/register", json=CRED)
    wrong = c.post("/api/login", json={**CRED, "password": "WrongPass123"})
    unknown = c.post("/api/login", json={"username": "nobody_here", "password": "WrongPass123"})
    dup = c.post("/api/register", json=CRED).status_code
    weak = c.post("/api/register", json={"username": "carol", "password": "short"}).status_code
    actual(f"wrong={wrong.status_code} unknown={unknown.status_code} same_msg={wrong.json()==unknown.json()} dup={dup} weak={weak}")
    assert wrong.status_code == unknown.status_code == 401 and wrong.json() == unknown.json() and dup == 409 and weak == 422


def test_t28e_passwords_hashed_tokens_hashed(tmp_path, actual):
    """Secrets are not stored in plain text
    Input: register + login, then inspect the database
    Expected: password and token absent; hash uses pbkdf2"""
    c, s = make_client(tmp_path)
    c.post("/api/register", json=CRED)
    tok = c.post("/api/login", json=CRED).json()["access_token"]
    conn = sqlite3.connect(s.db_path)
    dump = "\n".join(conn.iterdump())
    conn.close()
    actual(f"password_in_db={CRED['password'] in dump} token_in_db={tok in dump} pbkdf2={'pbkdf2$' in dump}")
    assert CRED["password"] not in dump and tok not in dump and "pbkdf2$" in dump


def test_t28f_login_rate_limit(tmp_path, actual):
    """Login brute-force protection
    Input: 3 wrong logins with limit 2/min
    Expected: 401, 401, then 429"""
    c, _ = make_client(tmp_path, login_limit_per_minute=2)
    codes = [c.post("/api/login", json={"username": "someone", "password": "WrongPass123"}).status_code for _ in range(3)]
    actual(codes)
    assert codes == [401, 401, 429]


def test_t28g_expired_session(tmp_path, actual):
    """Expired sessions are rejected
    Input: session with ttl 0 hours
    Expected: 401"""
    c, _ = make_client(tmp_path, auth_required=True, session_ttl_hours=0)
    c.post("/api/register", json=CRED)
    tok = c.post("/api/login", json=CRED).json()["access_token"]
    r = c.get("/api/analyses", headers={"Authorization": f"Bearer {tok}"})
    actual(r.status_code)
    assert r.status_code == 401
