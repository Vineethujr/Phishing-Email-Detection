"""Security helpers: password hashing, rate limiting, security-event logging."""
import hashlib
import hmac
import logging
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler
from typing import Deque, Dict, Tuple

PBKDF2_ITERATIONS = 200_000
_DUMMY_HASH = None
logger = logging.getLogger("phishing.security")


def hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 with a random salt. Format: pbkdf2$iterations$salt$hash"""
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS).hex()
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt}${digest}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt, digest = stored.split("$")
        test = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters)).hex()
        return hmac.compare_digest(test, digest)
    except (ValueError, TypeError):
        return False


def fake_verify(password: str) -> None:
    """Spend similar time when the username does not exist (reduces user-enumeration timing leaks)."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("dummy-password")
    verify_password(password, _DUMMY_HASH)


class SlidingWindowLimiter:
    """Tiny in-memory rate limiter (per key). Fine for a single-process student project;
    production would use a shared store such as Redis or a gateway."""

    def __init__(self, max_calls: int, window_seconds: int = 60):
        self.max_calls, self.window = max_calls, window_seconds
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str) -> Tuple[bool, int]:
        now = time.monotonic()
        with self._lock:
            q = self._hits[key]
            while q and now - q[0] > self.window:
                q.popleft()
            if len(q) >= self.max_calls:
                return False, max(1, int(self.window - (now - q[0])))
            q.append(now)
            return True, 0


def setup_logging(log_path: str) -> None:
    """Security-event log (auth failures, deletes, rejected uploads, rate limits). No email content is logged."""
    for h in list(logger.handlers):
        logger.removeHandler(h)
        h.close()
    logger.setLevel(logging.INFO)
    logger.propagate = False
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    for handler in (RotatingFileHandler(log_path, maxBytes=500_000, backupCount=2, encoding="utf-8"), logging.StreamHandler()):
        handler.setFormatter(fmt)
        logger.addHandler(handler)


def security_log(event: str, **fields) -> None:
    safe = " ".join(f"{k}={str(v)[:80]!r}" for k, v in fields.items())
    logger.info("%s %s", event, safe)
