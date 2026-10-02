"""Configuration from environment variables (secrets never live in source code)."""
import os
from dataclasses import dataclass, field

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@dataclass
class Settings:
    db_path: str = field(default_factory=lambda: os.getenv("DATABASE_PATH", os.path.join(ROOT, "analysis_history.db")))
    model_path: str = field(default_factory=lambda: os.getenv("MODEL_PATH", os.path.join(ROOT, "models", "phishing_model.joblib")))
    log_path: str = field(default_factory=lambda: os.getenv("LOG_PATH", os.path.join(ROOT, "logs", "security.log")))
    auth_required: bool = field(default_factory=lambda: _bool("AUTH_REQUIRED", False))
    rate_limit_per_minute: int = field(default_factory=lambda: int(os.getenv("RATE_LIMIT_PER_MINUTE", "30")))
    login_limit_per_minute: int = field(default_factory=lambda: int(os.getenv("LOGIN_LIMIT_PER_MINUTE", "10")))
    max_upload_bytes: int = field(default_factory=lambda: int(os.getenv("MAX_UPLOAD_BYTES", "1000000")))
    max_request_bytes: int = field(default_factory=lambda: int(os.getenv("MAX_REQUEST_BYTES", "2000000")))
    session_ttl_hours: int = field(default_factory=lambda: int(os.getenv("SESSION_TTL_HOURS", "8")))
