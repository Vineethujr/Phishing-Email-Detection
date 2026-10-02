# Architecture, Structure and Walkthrough

![Architecture](../screenshots/02_architecture_diagram.png)

## 1. Data flow (one analysis)

1. **Dashboard** sends JSON (or a `.eml`/`.txt` upload) to `POST /api/analyze`.
2. **API layer** (`backend/app.py`, `dependencies.py`, `schemas.py`): size limit → optional auth → rate limit → Pydantic validation.
3. **Preprocessing** (`utils/preprocessing.py`): light cleaning only; extract URLs, sender domain, attachment extension, HTML link pairs. Evidence such as CAPS, `!!!`, raw IPs and `.exe` is preserved on purpose.
4. **Analyzers** (`services/`): sender, content, URL, attachment. Each returns a 0–100 score plus human-readable findings.
5. **Feature extraction** (`feature_extractor.py`): 20 named features for the rules and the ML model.
6. **Scoring** (`risk_engine.py`): weighted indicators, combination bonus, cap at 100 → rule score.
7. **Optional ML** (`ml/predict.py`): TF-IDF + indicators → phishing probability; **hybrid** = 0.4 × rules + 0.6 × ML. If no model file exists, the app silently uses rules only.
8. **Classification + explanation + recommendations** (`risk_engine.py`, `analysis_service.py`).
9. **Storage** (`database.py`): metadata only; URLs defanged; no email body.
10. **Response** rendered by `frontend/static/app.js` using text-only DOM APIs.

## 2. Folder guide

| Path | Purpose |
|---|---|
| `backend/app.py` | FastAPI app factory, security headers, CSP, static hosting |
| `backend/routes/` | HTTP endpoints: `analysis.py`, `dashboard.py`, `auth.py` |
| `backend/services/` | Detection logic: sender/content/URL/attachment analyzers, feature extraction, risk engine, orchestration |
| `backend/models/schemas.py` | Request validation (Pydantic) |
| `backend/utils/` | Constants, domain helpers, preprocessing, safe `.eml` parser |
| `backend/database.py`, `security.py`, `config.py`, `dependencies.py` | SQLite layer; hashing, rate limit, logging; env config; auth/rate-limit dependencies |
| `backend/seed_demo.py` | Fills history with synthetic analyses for demos |
| `ml/` | `train_model.py` (3 models + evaluation), `predict.py`, `hybrid.py`, `evaluation.py`, `ml_features.py` |
| `data/` | Dataset generator, statistics, rule-engine baseline evaluation, the CSV |
| `frontend/` | `index.html` + `static/` (JS, CSS, vendored Chart.js) |
| `tests/` | 98 automated tests (`test_core`, `test_ml`, `test_api`, `test_frontend`) |
| `docs/` | API reference, this file, concepts, generated ML/test reports, charts |
| `screenshots/` | Proof images (see `PROOF_PLAN.md`) |
| `scripts/` | `capture_screenshots.py` |
| `models/` | Trained model output (git-ignored) |
| `reports/` | Place your final PDF/Word report here |

**Differences from the original brief (deliberate).** The frontend is plain HTML/JS served by the backend instead of a `frontend/src/components/pages/services` React app (one command to run, no Node.js); routes live in `backend/routes/` as requested, while analyzers are in `backend/services/`. Extra modules were added for security and testing (`security.py`, `dependencies.py`, `eml_parser.py`).

## 3. Database design (SQLite)

```
users 1 ──< sessions
analyses 1 ──< indicators
analyses 1 ──< url_analyses
```

| Table | Key columns |
|---|---|
| `analyses` | `analysis_id` PK, `sender_domain`, `subject` (≤200 chars), `risk_score` (0–100 CHECK), `classification`, `rule_score`, `ml_probability`, `mode`, `created_at` |
| `indicators` | `indicator_id` PK, `analysis_id` FK (ON DELETE CASCADE), `indicator_type`, `description`, `severity`, `evidence` (matched suspicious phrases only) |
| `url_analyses` | `url_analysis_id` PK, `analysis_id` FK (CASCADE), `url_safe_representation` (defanged), `risk_score`, `findings` (JSON list) |
| `users` | `user_id` PK, `username` UNIQUE, `password_hash` (PBKDF2), `role` (`admin`/`analyst`) |
| `sessions` | `token_hash` PK (SHA-256), `user_id` FK, `expires_at` |

One analysis has many indicators and many analysed URLs; deleting an analysis removes its children. Email bodies and raw clickable URLs are never stored.

## 4. Run it locally (exact commands)

```bash
# 1-2. project folder + virtual environment
cd Phishing-Email-Detection-Awareness-Dashboard
python -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\activate
# 3. dependencies
pip install -r requirements.txt
# 4. synthetic dataset
python data/generate_dataset.py
python data/dataset_stats.py
# 5. optional ML model (writes models/phishing_model.joblib, docs/ml_results.md, charts)
python ml/train_model.py
# 6. optional: synthetic history for the dashboard
python -m backend.seed_demo --n 150
# 7-8. start backend + dashboard (one server does both)
uvicorn backend.app:app --port 8000
# open http://127.0.0.1:8000/     (API docs: http://127.0.0.1:8000/docs)
# 9-11. analyze the two demo emails from the Analyze tab (buttons: "Synthetic phishing", "Legitimate") or:
python run_demo.py
# 12. view analytics on the Dashboard tab; run the tests any time:
python -m pytest -v
```

## 5. Demonstration scenario (real output)

| | Synthetic phishing | Legitimate |
|---|---|---|
| Sender | `security-alert@account-check.invalid.test` | `training@example.org` |
| Subject | URGENT: Verify Your Account Immediately | Cybersecurity Workshop Reminder |
| URL | `http://198.51.100.10/verify-account` (documentation-range IP) | `https://example.org/workshops/cybersecurity` |
| Rule score | **78/100** | **0/100** |
| ML probability | 0.986 | 0.01 |
| Hybrid score / class | **90 · HIGH RISK / LIKELY PHISHING** | **0 · LOW RISK** |
| Indicators | urgency, credential request, threat language, generic greeting, suspicious sender (20/100), raw-IP + non-HTTPS + credential-keyword URL (55/100), credential + risky link | none |

**Why the difference:** the phishing example stacks several independent signals (pressure, credential request, threats, deceptive-looking link and sender). The legitimate reminder is informational, names no credentials, uses a plain HTTPS link on a normal domain and asks for no action. Neither result is certainty; both are estimates with reasons.

## 6. Testing strategy

98 tests: `test_core` (45: analyzers, engine, preprocessing, dataset safety), `test_ml` (9), `test_api` (36: database, validation, history, auth, rate limits, privacy), `test_frontend` (8: CSP compliance, XSS-as-text, UI flows; 5 browser tests need Chromium and skip otherwise). `docs/test_report.md` is regenerated on every run with Test ID, Scenario, Input, Expected, **Actual** and Pass/Fail. Your original 25-scenario list maps to: T01–T21 (core), T22 (`test_api::t22*`), T23 (`t23*`), T24 (`test_ml::t24*`), T25 (`t25*`).
