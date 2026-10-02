# Concepts Guide

Background you need to explain this project confidently. Numbers quoted here come from this repository's own runs (see `docs/ml_results.md`, `docs/test_report.md`, `docs/dataset_stats.txt`).

## 1. What is phishing?

**Simple explanation.** Phishing is a trick where someone pretends to be a trustworthy sender (a bank, your university, your manager) to make you do something unsafe: type a password, open a file, pay money, or click a link.

**Technical explanation.** Phishing is a social-engineering technique for initial access and fraud. The attacker sends a message crafted to exploit human decision-making rather than a software bug. Email phishing typically delivers (a) a link to a deceptive site, (b) an attachment that runs code, or (c) a plain-text request (payment, gift cards, credentials). It stays effective because email is cheap to send at scale, easy to spoof visually, and one successful victim can expose an entire organisation.

**Why it is dangerous.** A single stolen password can lead to account takeover, data theft, fraud and ransomware. It also bypasses many technical defences because the victim performs the risky action.

**How lures manipulate people.** Urgency ("within 24 hours"), fear ("account suspended"), authority ("from the CEO"), greed ("you have won"), and routine ("invoice attached"). Each one pushes people to act before thinking.

**What an indicator is.** A measurable clue that correlates with phishing (a raw-IP link, a credential request, a `.pdf.exe` attachment). **No single indicator proves phishing**: real HR emails say "urgent", real services use link shorteners, and a careful attacker avoids every obvious clue. Detection therefore combines many weak signals into a *risk estimate*.

**Why explainability matters.** A bare "PHISHING" label is not actionable. Analysts need the reasons to verify quickly and to tune rules; end users learn from the reasons; and reviewers can challenge a wrong call. This project always returns the ✓ "Why?" list with points per indicator.

**Workflow implemented**

```
Email input → preprocessing → sender / subject / content / URL / attachment analysis
→ feature extraction → rule score (+ optional ML probability) → hybrid blend
→ classification → explanation → recommendations → stored metadata → dashboard
```

## 2. Industry relevance

Similar techniques appear in secure email gateways, anti-spam engines, SOC phishing-triage tooling, managed security providers and awareness-training platforms: header/sender checks, URL and attachment inspection, content classifiers, scoring, and user reporting. This project is a small, transparent, educational version of that pipeline.

| Role | Typical responsibility | Where this project shows related skills |
|---|---|---|
| SOC Analyst | Triage reported emails, decide benign/malicious, escalate | Explainable score + indicators, history, analyst-review workflow |
| Email Security Analyst | Tune filters, review false positives/negatives, investigate campaigns | Sender/URL/attachment analyzers, FP/FN analysis, threshold calibration |
| Cybersecurity Analyst | Detect and reduce risk across systems | Defence-in-depth design, secure coding, security logging |
| Threat Intelligence Analyst | Turn observed lures into patterns and detections | Indicator catalogue, ATT&CK mapping, keyword statistics |
| Incident Response Analyst | Contain and remediate after a user interacts | "If you already clicked" playbook, recommended actions |

## 3. Indicators implemented

| Group | Indicators (all static, explainable) |
|---|---|
| Sender | invalid format; long domain; excessive subdomains; many hyphens; punycode; letter/digit mixing; security words in domain or name; brand name in an untrusted domain; character-swap lookalike (`examp1ebank`); display-name vs domain mismatch; email address embedded in the display name |
| Subject/Body | urgency; fear/threat; financial pressure; credential request; reward claim; personal-information request; generic greeting; ALL-CAPS; excessive `!`; repeated punctuation; repeated words (weak note only) |
| URL | raw/obfuscated IP; non-HTTPS; unusual scheme; excessive subdomains; shorteners; credential keywords; `@` userinfo trick; punycode / non-ASCII; long URL; non-standard port; heavy percent-encoding; brand misuse; link text vs destination mismatch |
| Attachment | executable (`.exe .scr .bat .cmd`); script (`.js .vbs .ps1`); macro-enabled Office; archives/disk images; HTML; double extensions such as `invoice.pdf.exe` |

Important design points: HTTPS is shown as neutral information (encryption is not trust); unfamiliar domains are **not** automatically penalised; weights and thresholds are **project assumptions** and are not calibrated on real mail.

## 4. False positives and false negatives (with real outputs)

Measured by running this project's engine:

| Case | Rule score | ML estimate | Result | Lesson |
|---|---|---|---|---|
| Legitimate IT notice: "Your password expires in 3 days… update your password at https://it.example.com/password-reset", greeting "Dear Employee" | 35 | 0.14 | Rules: **MODERATE RISK** (35); hybrid: 22 | **False alarm.** Legitimate IT/HR mail can look like a credential lure. Context (expected? sender verified?) decides. |
| Legitimate HR email: "Urgent: Submit your documents today", named greeting | 10 | 0.02 | LOW RISK; urgency indicator still fires | One indicator alone does not change the class, which is why the engine combines signals. |
| Polished request: "Could you pick up some gift cards for a client meeting…" (no urgency words) | 10 | 0.76 | Rules alone: **LOW RISK (missed)**; hybrid 50 (SUSPICIOUS) | **False negative for rules.** Hybrid helped, but that lure style is in the synthetic training data, so it is not proof of real-world recall. |
| "Document shared with you" from an unfamiliar domain, https link, calm tone | 0 | not seen in training (stress test) | Missed by rules; ML recall was **0.00** when this category was held out | Quiet, well-written phishing is the hardest case. |

**Why false negatives are especially risky:** a missed phishing email looks trusted to the user. A false positive costs analyst time; a false negative can cost an account. That is why **recall** matters, while **precision** protects analysts from alert fatigue.

## 5. Security and privacy design

| Control | Where |
|---|---|
| Never execute attachments; filename checks only | `attachment_analyzer.py` |
| Never visit URLs; static string parsing only; stored/displayed **defanged** (`hxxp://198[.]51[.]100[.]10/...`) | `url_analyzer.py`, `database.py` |
| Do not store email bodies (metadata only); test dumps the database to prove it | `database.py`, `test_api.py::t22b` |
| Sanitise/validate input; length limits; filename must not contain path separators | `schemas.py` |
| Escape rendered content: all API data inserted with `textContent`; guard test forbids `innerHTML`; browser test injects `<script>`/`<img onerror>` | `app.js`, `test_frontend.py` |
| Strict Content-Security-Policy (self only, no inline code, no CDN) | `app.py` |
| File upload validation: `.eml`/`.txt` only, size limit, only text + filenames read, nothing written to disk | `routes/analysis.py` |
| Parameterised SQL; sort options whitelisted; LIKE wildcards escaped | `database.py` |
| Authentication + roles (first user admin; delete is admin-only); PBKDF2-SHA256 salted hashes; only token hashes stored; same error for unknown user / wrong password | `routes/auth.py`, `security.py` |
| Rate limiting on analysis and login endpoints | `security.py`, `dependencies.py` |
| Secrets/config from environment variables; `.env` git-ignored | `config.py`, `.env.example` |
| Security event log without email content | `security.py` |
| Security headers (nosniff, DENY framing, no-store) | `app.py` |
| HTTPS in production (run behind a TLS-terminating reverse proxy) | deployment note |

**Why rendering raw HTML email is itself risky:** an HTML email can contain scripts, tracking pixels, hidden forms and remote images that fire when displayed. Rendering it in the dashboard could execute attacker code in the analyst's browser (XSS) or leak that the message was opened. This project treats every email field as plain text.

## 6. SOC analyst workflow

```
Email reported → initial triage → sender analysis → URL analysis → attachment metadata
→ content analysis → risk score + reasons → ANALYST REVIEW → classification → response
```

1. **Triage:** paste or upload the reported message.
2. **Read the evidence, not just the number:** open each indicator; confirm the sender through a trusted channel.
3. **Decide:** benign, suspicious (escalate), or malicious. Record the decision.
4. **Respond:** block sender/URL, search for other recipients, reset credentials if anyone interacted, notify the user.

The score is a **decision aid**. It orders the queue and points to evidence; the analyst owns the verdict.

## 7. MITRE ATT&CK mapping (high level)

Verified against MITRE ATT&CK during this project: **Phishing (T1566)**, tactic *Initial Access*, has four sub-techniques.

| ATT&CK technique | What it means | Related detections in this project |
|---|---|---|
| **T1566.001** Spearphishing Attachment | Malicious file sent by email | Attachment filename analyzer (executables, scripts, macros, archives, double extensions) |
| **T1566.002** Spearphishing Link | Malicious link sent by email | URL analyzer (raw IP, shorteners, lookalikes, credential keywords, link-text mismatch) |
| **T1566.003** Spearphishing via Service | Phishing through third-party services (e.g. social/messaging) | Not covered (email only); listed as future work |
| **T1566.004** Spearphishing Voice | Phishing by phone/voice | Not covered; awareness content mentions verifying callers |
| **T1204** User Execution *(follow-on)* | User opens the file/link, enabling execution | Recommendations and awareness checklist target this human step |
| **T1078** Valid Accounts *(follow-on)* | Stolen credentials reused | Credential-request detection; "change your password" guidance |

Why map to a framework? It gives detections a shared vocabulary, shows coverage gaps (rows above marked "not covered"), and lets reports link to recognised mitigations such as user training. Note: this project *detects lure characteristics*; it does not prove which technique an attacker actually used.

## 8. Future improvements (defensive)

Email-header analysis (Received chain, Reply-To mismatch); SPF/DKIM/DMARC result ingestion; domain age/reputation and URL reputation services; attachment hash reputation; stronger NLP models with explainable AI (LIME/SHAP); a user "report phishing" workflow; SOC ticket and SIEM integration; threat-intelligence enrichment; awareness quizzes; feedback-based retraining with drift monitoring; a larger, more diverse, ideally real (authorized) dataset. Keep every addition defensive: analyse and report, never send or exploit.
