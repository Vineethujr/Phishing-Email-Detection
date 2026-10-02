# GitHub Upload Strategy

**Repository name:** `Phishing-Email-Detection-Awareness-Dashboard`

**Description:** Defensive cybersecurity dashboard for analyzing synthetic email content, sender patterns, URLs, attachments, and social-engineering indicators to generate explainable phishing risk assessments.

**Topics:** `cybersecurity` `phishing-detection` `email-security` `soc` `python` `machine-learning` `nlp` `threat-detection` `security-awareness` `url-analysis` `defensive-security`

## 1. Before you push (checklist)
- [ ] `python -m pytest -q` passes (98 tests; 5 browser tests skip without Chromium)
- [ ] `git status` shows **no** `.env`, `*.db`, `logs/`, `models/*.joblib`, `career/` (all git-ignored)
- [ ] Only synthetic data in the repo (a test enforces fictional domains and documentation-range IPs)
- [ ] README author/links filled in; screenshots present
- [ ] You can explain every file (see "Integrity" below)

## 2. Create the repository
On github.com: **New repository** → name above → public → **do not** add a README/.gitignore/licence (you already have them). Then:

```bash
cd Phishing-Email-Detection-Awareness-Dashboard
git init -b main
git config user.name  "Your Name"
git config user.email "you@example.com"
```

## 3. Commit sequence (14 commits)
Make each commit **when you actually finish that piece**. The helper `career/git_commit_plan.sh` stages the right files for each step:

```bash
bash career/git_commit_plan.sh 1     # ... run 2, 3, ... 14 as you go
```

| # | Commit message | Files |
|---|---|---|
| 1 | Initialize phishing detection project | `.gitignore`, `requirements.txt`, `.env.example`, `pytest.ini`, package `__init__` files, architecture doc, placeholder README |
| 2 | Implement email preprocessing | `utils/constants.py`, `utils/preprocessing.py` |
| 3 | Add synthetic email dataset generator | `data/generate_dataset.py`, `dataset_stats.py`, CSV |
| 4 | Add sender analysis module | `sender_analyzer.py`, `domain_utils.py` |
| 5 | Implement phishing content analyzer | `content_analyzer.py` |
| 6 | Add static URL risk analysis | `url_analyzer.py` |
| 7 | Implement attachment filename analysis | `attachment_analyzer.py` |
| 8 | Build phishing risk scoring engine | `feature_extractor.py`, `risk_engine.py`, `run_demo.py`, `evaluate_rules.py` |
| 9 | Add optional ML detection model | `ml_features.py`, `hybrid.py`, `predict.py` |
| 10 | Implement model evaluation | `evaluation.py`, `train_model.py`, generated ML report and charts |
| 11 | Build backend API with analysis history storage | `app.py`, `database.py`, routes, schemas, security, `api.md` |
| 12 | Build cybersecurity dashboard with phishing awareness module | `frontend/`, `scripts/`, `screenshots/` |
| 13 | Add automated security tests | `tests/`, `docs/test_report.md` |
| 14 | Complete README and documentation | full README, concepts guide, this guide, project report |

**Two deliberate changes to the list you were given:** (a) steps 2 and 3 are swapped because the dataset generator imports the preprocessing helpers, so every commit still runs; (b) your separate "dashboard / awareness / history" commits are merged into steps 11–12 because history, awareness and dashboard share the same API and front-end files, and splitting one file across commits would mean committing code that does not exist yet.

**Do not backdate commits.** GitHub shows real dates and reviewers notice inconsistencies. If you want a multi-day history, follow the 13-day plan and commit daily as you really work.

## 4. Push
```bash
git remote add origin https://github.com/<your-username>/Phishing-Email-Detection-Awareness-Dashboard.git
git push -u origin main
git tag -a v1.0.0 -m "Phishing Email Detection & Awareness Dashboard v1.0.0"
git push origin v1.0.0
```

## 5. Description and topics
Web: repository page → gear icon next to **About** → paste description, add the topics, tick nothing else.
CLI (optional, needs GitHub CLI):
```bash
gh repo edit --description "Defensive cybersecurity dashboard for analyzing synthetic email content, sender patterns, URLs, attachments, and social-engineering indicators to generate explainable phishing risk assessments." \
  --add-topic cybersecurity,phishing-detection,email-security,soc,python,machine-learning,nlp,threat-detection,security-awareness,url-analysis,defensive-security
```

## 6. Make the repo look professional
Pin it on your profile · add a licence (MIT is common: **Add file → Create new file → LICENSE**) · keep README screenshots at the top · create a GitHub Release from tag `v1.0.0` · use small, meaningful commits after launch (fix a limitation, add a test).

## 7. Integrity note
You will be asked about this project. Run every command yourself, read each module, change something small (a keyword, a weight) and watch the tests react, and be able to explain the limitations in the README. Follow your course's rules on AI assistance, and disclose it where required; being open about how you built it, and understanding it, is what makes the project credible.
