# REST API Reference

Base URL: `http://127.0.0.1:8000`. Interactive docs: `/docs`. All bodies are JSON unless noted.
Set `AUTH_REQUIRED=true` to require `Authorization: Bearer <token>` on every endpoint except `/api/health`, `/api/register`, `/api/login`.
Errors always look like `{"detail": "..."}`. Status codes used: 200, 201, 204, 400, 401, 403, 404, 409, 413, 415, 422, 429, 500.

Common protections: Pydantic validation (422), request-size limit (413), per-IP rate limit on analysis endpoints (429 + `Retry-After`), security headers, generic 500 messages (details only in the server log).

## POST /api/analyze
Analyze pasted email fields, store **metadata only**, return the explainable result.
- **Request:** `{"sender": "...", "subject": "...", "body": "...", "attachment_name": "...", "display_name": null, "use_ml": true}` (at least one of sender/subject/body; max lengths 320/500/200000/255; filename may not contain `/`, `\` or NUL).
- **Response 200:** `analysis_id, risk_score, classification, rule_score, ml_probability (null if no model), mode ("hybrid"|"rules_only"), indicators[], sender_analysis, content_analysis, url_analyses[], attachment_analysis, features, recommendations[], disclaimer`.
- **Auth:** required only if `AUTH_REQUIRED`. **Authorization:** any authenticated user.
- **Errors:** 422 invalid input, 401, 413, 429.

## POST /api/analyze/upload  (multipart/form-data, field `file`, optional `use_ml`)
Analyze a `.eml` or `.txt` file. Only text and attachment *filenames* are read; nothing is executed or written to disk.
- **Validation:** extension must be `.eml`/`.txt` (415), size ≤ `MAX_UPLOAD_BYTES` (413), parseable (400), non-empty (422).
- **Response:** same as `/api/analyze`.

## POST /api/analyze/url
Static analysis of one URL string (never visited, not stored).
- **Request:** `{"url": "http://198.51.100.10/verify-account"}`
- **Response 200:** `url_safe` (defanged), `risk_score`, `risk_level`, `findings[]`, `details{}`.
- **Errors:** 422 empty/too long (max 2048), 401, 429.

## GET /api/analyses
List history. **Query:** `classification` (`LOW|MODERATE|SUSPICIOUS|HIGH`), `q` (search subject/sender domain, max 100), `sort` (`newest|oldest|risk_desc|risk_asc`), `limit` (1–200, default 50), `offset`.
- **Response 200:** `{"total", "limit", "offset", "items": [ {analysis_id, sender_domain, subject, risk_score, classification, rule_score, ml_probability, mode, created_at} ]}`
- **Errors:** 422 invalid query values, 401.

## GET /api/analyses/{id}
One analysis with `indicators[]` (type, description, severity, evidence phrases) and `url_analyses[]` (defanged URL, score, findings). **404** if unknown, **422** if `id` is not an integer.

## DELETE /api/analyses/{id}
Delete an analysis (cascades to indicators and URL rows). **204** on success, **404** unknown.
- **Authorization:** when `AUTH_REQUIRED=true`, **admin only** (403 for analysts, 401 without token). Deletions are logged.

## GET /api/dashboard/stats  (query: `days` 1–90, default 14)
`total, average_risk_score, likely_phishing, suspicious, low_risk, by_classification{}, phishing_vs_legitimate{}, score_distribution[10 buckets], trend[per-day total/flagged]`. "flagged" = SUSPICIOUS or HIGH (score ≥ 41).

## GET /api/dashboard/indicators  (query: `limit` 1–50)
`top_indicators[{indicator_type,count}]`, `top_keywords[{keyword,count}]` (matched suspicious phrases only, never free text).

## Optional authentication
| Endpoint | Request | Response | Notes |
|---|---|---|---|
| `POST /api/register` | `{"username" (3–32, `[A-Za-z0-9_.-]`), "password" (8–128)}` | 201 `{user_id, username, role}` | First user becomes `admin`, others `analyst`. 409 duplicate, 422 invalid. Passwords stored as salted PBKDF2-SHA256. |
| `POST /api/login` | same | 200 `{access_token, token_type, expires_in, role}` | Same 401 message for unknown user and wrong password. Rate-limited (429). Only a SHA-256 hash of the token is stored. |
| `POST /api/logout` | Bearer token | 204 | Invalidates the session. |

## GET /api/health
`{"status":"ok","ml_model_loaded":bool,"auth_required":bool}`. Public.
