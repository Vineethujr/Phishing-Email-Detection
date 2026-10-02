"""Optional authentication: register, login, logout (bearer tokens; only token hashes are stored)."""
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.dependencies import get_db, get_settings, rate_limit_login
from backend.models.schemas import Credentials
from backend.security import fake_verify, hash_password, security_log, verify_password

router = APIRouter()
_bearer = HTTPBearer(auto_error=True)


@router.post("/register", status_code=201, dependencies=[Depends(rate_limit_login)])
def register(body: Credentials, db=Depends(get_db)):
    user = db.create_user(body.username, hash_password(body.password))
    if not user:
        raise HTTPException(409, "Username already exists")
    security_log("user_registered", username=user["username"], role=user["role"])
    return user


@router.post("/login", dependencies=[Depends(rate_limit_login)])
def login(body: Credentials, request: Request, db=Depends(get_db), settings=Depends(get_settings)):
    user = db.get_user_by_name(body.username)
    if user and verify_password(body.password, user["password_hash"]):
        token = db.create_session(user["user_id"], settings.session_ttl_hours)
        security_log("login_ok", username=body.username)
        return {"access_token": token, "token_type": "bearer", "expires_in": settings.session_ttl_hours * 3600,
                "role": user["role"]}
    if not user:
        fake_verify(body.password)
    security_log("login_failed", username=body.username, ip=request.client.host if request.client else "?")
    raise HTTPException(401, "Invalid username or password")     # same message either way


@router.post("/logout", status_code=204)
def logout(creds: HTTPAuthorizationCredentials = Depends(_bearer), db=Depends(get_db)):
    db.delete_session(creds.credentials)
    return Response(status_code=204)
