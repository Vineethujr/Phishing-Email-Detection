"""FastAPI dependencies: database access, authentication, authorisation, rate limiting."""
from typing import Optional

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.security import security_log

_bearer = HTTPBearer(auto_error=False)


def get_db(request: Request):
    return request.app.state.db


def get_settings(request: Request):
    return request.app.state.settings


def current_user(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(_bearer)) -> Optional[dict]:
    """Return the logged-in user. If AUTH_REQUIRED is on, a missing/invalid token gives 401."""
    user = request.app.state.db.get_user_by_token(creds.credentials) if creds else None
    if request.app.state.settings.auth_required and not user:
        security_log("auth_denied", path=request.url.path, ip=request.client.host if request.client else "?")
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
    return user


def require_admin(request: Request, user: Optional[dict] = Depends(current_user)) -> Optional[dict]:
    """Authorisation: deleting records needs the admin role when authentication is enabled."""
    if request.app.state.settings.auth_required and (not user or user["role"] != "admin"):
        security_log("forbidden", path=request.url.path, user=(user or {}).get("username", "?"))
        raise HTTPException(403, "Admin role required")
    return user


def _limit(request: Request, limiter_name: str) -> None:
    ip = request.client.host if request.client else "unknown"
    ok, retry = getattr(request.app.state, limiter_name).allow(ip)
    if not ok:
        security_log("rate_limited", limiter=limiter_name, ip=ip, path=request.url.path)
        raise HTTPException(429, "Too many requests. Please slow down.", headers={"Retry-After": str(retry)})


def rate_limit_analyze(request: Request) -> None:
    _limit(request, "analyze_limiter")


def rate_limit_login(request: Request) -> None:
    _limit(request, "login_limiter")
