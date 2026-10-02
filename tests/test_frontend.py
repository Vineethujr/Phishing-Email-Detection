"""Phase 4 tests: dashboard is served safely (T29) and behaves correctly in a real browser (T30).
Browser tests need Playwright + Chromium and are skipped automatically if unavailable."""
import re
import socket
import threading
import time

import pytest
import uvicorn
from fastapi.testclient import TestClient

from backend.app import create_app
from backend.config import ROOT, Settings


def make_settings(tmp_path, **kw):
    return Settings(db_path=str(tmp_path / "ui.db"), log_path=str(tmp_path / "ui.log"), model_path=str(tmp_path / "none.joblib"), **kw)


# ------------------------------------------------------------------ T29 static serving / CSP (no browser)
def test_t29a_index_served_with_csp(tmp_path, actual):
    """Dashboard page and CSP
    Input: GET /
    Expected: 200 HTML with a strict Content-Security-Policy (self only, no inline)"""
    r = TestClient(create_app(make_settings(tmp_path))).get("/")
    csp = r.headers.get("content-security-policy", "")
    actual(f"{r.status_code} csp={csp[:60]}...")
    assert r.status_code == 200 and "Phishing Detection" in r.text
    assert "script-src 'self'" in csp and "style-src 'self'" in csp and "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp


def test_t29b_assets_served_locally(tmp_path, actual):
    """Assets are local (no CDN dependency)
    Input: GET /static/app.js, styles.css, vendor/chart.umd.js
    Expected: all 200; index.html references no external http(s) resources"""
    c = TestClient(create_app(make_settings(tmp_path)))
    codes = [c.get(f"/static/{f}").status_code for f in ("app.js", "styles.css", "vendor/chart.umd.js")]
    html = c.get("/").text
    external = re.findall(r'(?:src|href)="(https?://[^"]+)"', html)
    actual(f"{codes} external={external}")
    assert codes == [200, 200, 200] and not external


def test_t29c_html_is_csp_compliant(actual):
    """No inline code in the HTML or JS (would be blocked by CSP and is an XSS risk)
    Input: frontend/index.html and app.js source
    Expected: no inline <script>, no style= or on*= attributes, no innerHTML/eval/document.write"""
    html = open(f"{ROOT}/frontend/index.html", encoding="utf-8").read()
    js = open(f"{ROOT}/frontend/static/app.js", encoding="utf-8").read()
    js = re.sub(r"/\*.*?\*/", "", js, flags=re.S)          # ignore comments (they may mention the banned words)
    js = re.sub(r"(?<!:)//[^\n]*", "", js)
    inline_scripts = re.findall(r"<script(?![^>]*\bsrc=)[^>]*>", html)
    bad_attrs = re.findall(r'\s(?:style|onclick|onload|onerror|onchange)\s*=', html)
    banned = [w for w in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(") if w in js]
    actual(f"inline_scripts={inline_scripts} attrs={bad_attrs} banned_js={banned}")
    assert not inline_scripts and not bad_attrs and not banned


# ------------------------------------------------------------------ T30 real browser
@pytest.fixture(scope="module")
def live(tmp_path_factory):
    sync_api = pytest.importorskip("playwright.sync_api")
    tmp = tmp_path_factory.mktemp("live")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_app(make_settings(tmp)), host="127.0.0.1", port=port, log_level="warning"))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    for _ in range(50):
        if server.started:
            break
        time.sleep(0.1)
    try:
        pw = sync_api.sync_playwright().start()
        browser = pw.chromium.launch()
    except Exception as e:  # browser not installed
        server.should_exit = True
        pytest.skip(f"Chromium not available: {e}")
    yield f"http://127.0.0.1:{port}", browser
    browser.close(); pw.stop(); server.should_exit = True; thread.join(timeout=5)


def new_page(live):
    base, browser = live
    page = browser.new_page(viewport={"width": 1300, "height": 1200})
    problems = []
    page.on("console", lambda m: problems.append(m.text) if m.type in ("error", "warning") else None)
    page.on("pageerror", lambda e: problems.append(str(e)))
    return base, page, problems


def test_t30a_xss_subject_rendered_as_text(live, actual):
    """XSS: script-like subject is displayed as text and never executes
    Input: subject '<img src=x onerror=window.__pwned=1><script>window.__pwned=1</script>' analyzed then viewed in History
    Expected: text visible on the page, window.__pwned undefined, no DOM <img src=x>, no console errors"""
    base, page, problems = new_page(live)
    payload = "<img src=x onerror=window.__pwned=1><script>window.__pwned=1</script>"
    page.goto(base + "/#analyze")
    page.fill("#f-sender", "a@example.org"); page.fill("#f-subject", payload); page.fill("#f-body", "hello")
    page.click("#analyze-btn"); page.wait_for_selector(".gauge")
    page.click('.tab[data-view="history"]'); page.wait_for_selector("#h-body td.subj")
    shown = page.inner_text("#h-body td.subj")
    pwned = page.evaluate("window.__pwned")
    injected = page.locator("#h-body img").count() + page.locator("#h-body script").count()
    actual(f"shown={shown[:40]!r} pwned={pwned} injected_elements={injected} console={problems}")
    assert payload in shown and pwned is None and injected == 0 and not problems
    page.close()


def test_t30b_analyze_flow(live, actual):
    """Analyze flow in the UI
    Input: load phishing sample, click ANALYZE EMAIL; then the legitimate sample
    Expected: HIGH badge with a why-list and defanged URL; then LOW badge"""
    base, page, problems = new_page(live)
    page.goto(base + "/#analyze")
    page.click('[data-sample="phish"]'); page.click("#analyze-btn"); page.wait_for_selector(".badge.k-high")
    high = page.inner_text("#result-panel .badge")
    why = page.locator("#result-panel ul.why li").count()
    url_text = page.inner_text("#result-panel .urlbox code")
    page.click('[data-sample="legit"]'); page.click("#analyze-btn"); page.wait_for_selector(".badge.k-low")
    low = page.inner_text("#result-panel .badge")
    actual(f"{high} why={why} url={url_text} | {low} | console={problems}")
    assert high.startswith("HIGH") and why >= 5 and url_text.startswith("hxxp://") and low == "LOW RISK" and not problems
    page.close()


def test_t30c_validation_error_shown(live, actual):
    """Validation errors are shown to the user
    Input: click ANALYZE EMAIL with all fields empty
    Expected: visible notice, no result rendered"""
    base, page, _ = new_page(live)
    page.goto(base + "/#analyze")
    page.click("#analyze-btn"); page.wait_for_selector("#notice:not([hidden])")
    msg = page.inner_text("#notice")
    actual(msg)
    assert "at least one" in msg.lower() and page.locator(".gauge").count() == 0
    page.close()


def test_t30d_history_filter_search_delete(live, actual):
    """History controls
    Input: search 'workshop', filter HIGH, delete one row
    Expected: search narrows rows, HIGH filter shows only HIGH badges, delete removes the row"""
    base, page, _ = new_page(live)
    page.goto(base + "/#analyze")
    for sample in ("phish", "legit"):
        page.click(f'[data-sample="{sample}"]'); page.click("#analyze-btn"); page.wait_for_selector(".gauge")
    page.click('.tab[data-view="history"]'); page.wait_for_selector("#h-body td.subj")
    page.fill("#h-q", "Workshop"); page.wait_for_timeout(600)
    searched = [t for t in page.locator("#h-body td.subj").all_inner_texts()]
    page.fill("#h-q", ""); page.select_option("#h-class", "HIGH"); page.wait_for_timeout(500)
    badges = set(page.locator("#h-body .badge").all_inner_texts())
    page.select_option("#h-class", ""); page.wait_for_timeout(500)
    before = page.locator("#h-body tr").count()
    page.once("dialog", lambda d: d.accept())
    page.locator("#h-body tr").first.locator("button:has-text('Delete')").click(); page.wait_for_timeout(700)
    after = page.locator("#h-body tr").count()
    actual(f"search={searched} high_badges={badges} rows {before}->{after}")
    assert searched and all("Workshop" in t for t in searched) and badges == {"HIGH RISK"} and after == before - 1
    page.close()


def test_t30e_dashboard_and_awareness(live, actual):
    """Dashboard cards/charts and awareness checklist
    Input: open Dashboard after analyses exist; then Awareness and tick 3 checklist boxes
    Expected: 5 KPI cards, 6 chart canvases, 10 tips, checklist progress '3 of 10'"""
    base, page, problems = new_page(live)
    page.goto(base + "/#dashboard"); page.wait_for_selector(".card .value")
    cards, canvases = page.locator(".card").count(), page.locator("canvas").count()
    page.click('.tab[data-view="learn"]')
    tips = page.locator(".tip").count()
    for i in range(3):
        page.check(f"#chk{i}")
    status = page.inner_text("#check-status")
    actual(f"cards={cards} canvases={canvases} tips={tips} status={status!r} console={problems}")
    assert cards == 5 and canvases == 6 and tips == 10 and status == "3 of 10 checks done" and not problems
    page.close()
