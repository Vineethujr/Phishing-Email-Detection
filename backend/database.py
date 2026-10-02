"""SQLite storage (standard library only). All queries are parameterised (no SQL injection).

Privacy: we store METADATA ONLY - sender domain, truncated subject, scores, indicator
descriptions and DEFANGED URLs. The email body is never written to the database.
"""
import hashlib
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

SCHEMA = """
CREATE TABLE IF NOT EXISTS analyses (
    analysis_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_domain   TEXT NOT NULL DEFAULT '',
    subject         TEXT NOT NULL DEFAULT '',
    risk_score      INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    classification  TEXT NOT NULL,
    rule_score      INTEGER,
    ml_probability  REAL,
    mode            TEXT NOT NULL DEFAULT 'rules_only',
    created_at      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS indicators (
    indicator_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id     INTEGER NOT NULL REFERENCES analyses(analysis_id) ON DELETE CASCADE,
    indicator_type  TEXT NOT NULL,
    description     TEXT NOT NULL,
    severity        TEXT NOT NULL,
    evidence        TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS url_analyses (
    url_analysis_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id            INTEGER NOT NULL REFERENCES analyses(analysis_id) ON DELETE CASCADE,
    url_safe_representation TEXT NOT NULL,
    risk_score             INTEGER NOT NULL,
    findings               TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS users (
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'analyst',
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    expires_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_analyses_created ON analyses(created_at);
CREATE INDEX IF NOT EXISTS idx_analyses_class ON analyses(classification);
CREATE INDEX IF NOT EXISTS idx_indicators_analysis ON indicators(analysis_id);
"""

CLASS_LABELS = ["LOW RISK", "MODERATE RISK", "SUSPICIOUS", "HIGH RISK / LIKELY PHISHING"]
CLASS_CODES = {"LOW": "LOW RISK", "MODERATE": "MODERATE RISK", "SUSPICIOUS": "SUSPICIOUS", "HIGH": "HIGH RISK / LIKELY PHISHING"}
SORTS = {"newest": "created_at DESC, analysis_id DESC", "oldest": "created_at ASC, analysis_id ASC",
         "risk_desc": "risk_score DESC, analysis_id DESC", "risk_asc": "risk_score ASC, analysis_id ASC"}
CONTENT_TYPES = {"urgency", "credential", "fear", "financial", "reward", "personal_info"}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


class Database:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with self.connect() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def connect(self):
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------ analyses
    def save_analysis(self, result: Dict, sender_domain: str, subject: str, created_at: Optional[str] = None) -> int:
        """Store metadata for one analysis. `result` is the API result dict (no body inside)."""
        cats = result["content_analysis"]["categories"]
        with self.connect() as c:
            cur = c.execute(
                "INSERT INTO analyses (sender_domain, subject, risk_score, classification, rule_score, ml_probability, mode, created_at)"
                " VALUES (?,?,?,?,?,?,?,?)",
                (sender_domain[:255], subject[:200], int(result["risk_score"]), result["classification"],
                 result.get("rule_score"), result.get("ml_probability"), result.get("mode", "rules_only"), created_at or _now()))
            aid = cur.lastrowid
            for ind in result["indicators"]:
                ev = cats.get(ind["indicator_type"], {}).get("matches", []) if ind["indicator_type"] in CONTENT_TYPES else []
                c.execute("INSERT INTO indicators (analysis_id, indicator_type, description, severity, evidence) VALUES (?,?,?,?,?)",
                          (aid, ind["indicator_type"], ind["description"][:300], ind["severity"], json.dumps(ev[:10])))
            for u in result["url_analyses"]:
                c.execute("INSERT INTO url_analyses (analysis_id, url_safe_representation, risk_score, findings) VALUES (?,?,?,?)",
                          (aid, u["url_safe"][:500], u["risk_score"], json.dumps([f["description"] for f in u["findings"]])))
        return aid

    def list_analyses(self, classification: Optional[str] = None, q: Optional[str] = None, sort: str = "newest",
                      limit: int = 50, offset: int = 0) -> Tuple[List[Dict], int]:
        where, params = [], []
        if classification:
            where.append("classification = ?")
            params.append(classification)
        if q:
            where.append("(subject LIKE ? ESCAPE '\\' OR sender_domain LIKE ? ESCAPE '\\')")
            params += [_like(q), _like(q)]
        clause = ("WHERE " + " AND ".join(where)) if where else ""
        order = SORTS.get(sort, SORTS["newest"])      # whitelist: user text never reaches ORDER BY
        with self.connect() as c:
            total = c.execute(f"SELECT COUNT(*) FROM analyses {clause}", params).fetchone()[0]
            rows = c.execute(f"SELECT * FROM analyses {clause} ORDER BY {order} LIMIT ? OFFSET ?", params + [limit, offset]).fetchall()
        return [dict(r) for r in rows], total

    def get_analysis(self, analysis_id: int) -> Optional[Dict]:
        with self.connect() as c:
            row = c.execute("SELECT * FROM analyses WHERE analysis_id = ?", (analysis_id,)).fetchone()
            if not row:
                return None
            out = dict(row)
            out["indicators"] = [dict(r, evidence=json.loads(r["evidence"])) for r in
                                 c.execute("SELECT * FROM indicators WHERE analysis_id = ? ORDER BY indicator_id", (analysis_id,))]
            out["url_analyses"] = [dict(r, findings=json.loads(r["findings"])) for r in
                                   c.execute("SELECT * FROM url_analyses WHERE analysis_id = ? ORDER BY url_analysis_id", (analysis_id,))]
        return out

    def delete_analysis(self, analysis_id: int) -> bool:
        with self.connect() as c:
            return c.execute("DELETE FROM analyses WHERE analysis_id = ?", (analysis_id,)).rowcount > 0

    # ------------------------------------------------------------ dashboard
    def stats(self, days: int = 14) -> Dict:
        with self.connect() as c:
            total = c.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
            avg = c.execute("SELECT AVG(risk_score) FROM analyses").fetchone()[0]
            by_class = {label: 0 for label in CLASS_LABELS}
            for r in c.execute("SELECT classification, COUNT(*) n FROM analyses GROUP BY classification"):
                by_class[r["classification"]] = r["n"]
            buckets = [0] * 10
            for r in c.execute("SELECT risk_score, COUNT(*) n FROM analyses GROUP BY risk_score"):
                buckets[min(r["risk_score"] // 10, 9)] += r["n"]
            start = (datetime.now(timezone.utc) - timedelta(days=days - 1)).date()
            trend_map = {r["d"]: (r["n"], r["f"]) for r in c.execute(
                "SELECT substr(created_at,1,10) d, COUNT(*) n, SUM(risk_score >= 41) f FROM analyses WHERE substr(created_at,1,10) >= ? GROUP BY d",
                (start.isoformat(),))}
        trend = []
        for i in range(days):
            d = (start + timedelta(days=i)).isoformat()
            n, f = trend_map.get(d, (0, 0))
            trend.append({"date": d, "total": n, "flagged": int(f or 0)})
        flagged = by_class["SUSPICIOUS"] + by_class["HIGH RISK / LIKELY PHISHING"]
        return {
            "total": total, "average_risk_score": round(avg, 1) if avg is not None else 0.0,
            "likely_phishing": by_class["HIGH RISK / LIKELY PHISHING"], "suspicious": by_class["SUSPICIOUS"],
            "low_risk": by_class["LOW RISK"], "by_classification": by_class,
            "phishing_vs_legitimate": {"flagged_suspicious_or_high": flagged, "not_flagged": total - flagged},
            "score_distribution": [{"bucket": f"{i*10}-{i*10+9 if i < 9 else 100}", "count": n} for i, n in enumerate(buckets)],
            "trend": trend,
        }

    def indicator_stats(self, limit: int = 10) -> Dict:
        with self.connect() as c:
            top = [dict(r) for r in c.execute(
                "SELECT indicator_type, COUNT(*) AS count FROM indicators GROUP BY indicator_type ORDER BY count DESC, indicator_type LIMIT ?", (limit,))]
            counts: Dict[str, int] = {}
            for r in c.execute("SELECT evidence FROM indicators WHERE evidence != '[]' ORDER BY indicator_id DESC LIMIT 5000"):
                for kw in json.loads(r["evidence"]):
                    counts[kw] = counts.get(kw, 0) + 1
        kws = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:limit]
        return {"top_indicators": top, "top_keywords": [{"keyword": k, "count": n} for k, n in kws]}

    # ------------------------------------------------------------ users
    def create_user(self, username: str, password_hash: str) -> Optional[Dict]:
        """First user becomes admin; later users are analysts. Returns None if the username exists."""
        with self.connect() as c:
            role = "admin" if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0 else "analyst"
            try:
                cur = c.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
                                (username, password_hash, role, _now()))
            except sqlite3.IntegrityError:
                return None
            return {"user_id": cur.lastrowid, "username": username, "role": role}

    def get_user_by_name(self, username: str) -> Optional[Dict]:
        with self.connect() as c:
            row = c.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None

    def create_session(self, user_id: int, ttl_hours: int) -> str:
        token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(hours=ttl_hours)).isoformat(timespec="seconds")
        with self.connect() as c:
            c.execute("DELETE FROM sessions WHERE expires_at < ?", (_now(),))
            c.execute("INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?,?,?)",
                      (hashlib.sha256(token.encode()).hexdigest(), user_id, expires))
        return token   # only the hash is stored

    def get_user_by_token(self, token: str) -> Optional[Dict]:
        with self.connect() as c:
            row = c.execute("SELECT u.user_id, u.username, u.role FROM sessions s JOIN users u ON u.user_id = s.user_id "
                            "WHERE s.token_hash = ? AND s.expires_at > ?", (hashlib.sha256(token.encode()).hexdigest(), _now())).fetchone()
        return dict(row) if row else None

    def delete_session(self, token: str) -> None:
        with self.connect() as c:
            c.execute("DELETE FROM sessions WHERE token_hash = ?", (hashlib.sha256(token.encode()).hexdigest(),))
