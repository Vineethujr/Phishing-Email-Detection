"""Drive the running dashboard in a headless browser, report console/CSP errors, save proof screenshots.

1) start the server (with seeded data):   uvicorn backend.app:app --port 8000
2) pip install playwright && playwright install chromium
3) python scripts/capture_screenshots.py [http://127.0.0.1:8000]

Creates the browser-based items of the proof checklist (05-17, 19-21). Terminal/GitHub items
(01, 03, 04, 18, 22-26) you capture yourself from your own machine.
"""
import os
import shutil
import sys
from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "screenshots")
os.makedirs(OUT, exist_ok=True)
problems = []

with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1360, "height": 1300})   # tall viewport: avoids resize re-animating charts
    page.on("console", lambda m: problems.append(f"console.{m.type}: {m.text}") if m.type in ("error", "warning") else None)
    page.on("pageerror", lambda e: problems.append(f"pageerror: {e}"))
    page.on("requestfailed", lambda r: problems.append(f"requestfailed: {r.url}"))
    shot = lambda name, target=None: (target or page).screenshot(path=f"{OUT}/{name}.png")
    section = lambda title: page.locator("#result-panel .section", has_text=title)

    # ---- dashboard + chart crops (14, 15, 16, 17)
    page.goto(BASE + "/#dashboard")
    page.wait_for_selector(".card .value")
    page.wait_for_timeout(2500)
    shot("14_dashboard_overview")
    for name, canvas in (("15_classification_chart", "ch-class"), ("16_risk_score_distribution", "ch-dist"), ("17_top_detected_indicators", "ch-ind")):
        shot(name, page.locator(".panel", has=page.locator("#" + canvas)))

    # ---- analyzer page (05) and phishing analysis (07, 08, 09, 11, 12, 13)
    page.click('.tab[data-view="analyze"]')
    shot("05_email_analyzer_page")
    page.click('[data-sample="phish"]')
    page.click("#analyze-btn")
    page.wait_for_selector(".gauge")
    page.wait_for_timeout(400)
    shot("07_synthetic_phishing_analysis")
    shot("11_phishing_risk_score", page.locator("#result-panel .score-head"))
    shot("12_explainable_indicators", section("Why?"))
    shot("08_sender_risk_findings", section("Sender analysis"))
    shot("09_url_risk_findings", section("URL analysis"))
    shot("13_recommended_actions", section("Recommended actions"))

    # ---- attachment analysis (10), synthetic invoice lure with a double extension
    page.fill("#f-sender", "billing@invoice-center.example.net")
    page.fill("#f-subject", "Invoice #48213 overdue - payment failed")
    page.fill("#f-body", "Dear Sir/Madam,\n\nYour invoice is past due and payment failed. Open the attached invoice and settle the outstanding balance today.")
    page.fill("#f-att", "Invoice_48213.pdf.exe")
    page.click("#analyze-btn")
    page.wait_for_selector("#result-panel .section:has-text('filename check only')")
    page.wait_for_timeout(300)
    shot("10_attachment_analysis", section("filename check only"))

    # ---- legitimate example (06)
    page.click('[data-sample="legit"]')
    page.click("#analyze-btn")
    page.wait_for_selector(".badge.k-low")
    page.wait_for_timeout(400)
    shot("06_legitimate_email_analysis")

    # ---- history (20, 20b)
    page.click('.tab[data-view="history"]')
    page.wait_for_selector("#h-body tr td")
    page.wait_for_timeout(300)
    shot("20_analysis_history")
    page.click("#h-body tr:first-child button:has-text('View')")
    page.wait_for_selector("#detail-dialog[open]")
    shot("20b_analysis_detail")
    page.click("#detail-close")

    # ---- awareness (21)
    page.click('.tab[data-view="learn"]')
    for i in (0, 2, 4):
        page.check(f"#chk{i}")
    shot("21_awareness_module")
    browser.close()

cm = os.path.join(ROOT, "docs", "confusion_matrix.png")
if os.path.exists(cm):
    shutil.copy(cm, os.path.join(OUT, "19_confusion_matrix.png"))
print("Screenshots saved to", OUT)
print("Console/CSP problems:", problems or "none")
