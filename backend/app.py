"""FastAPI application factory.  Run:  uvicorn backend.app:app --reload --port 8000"""
import os
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from backend.config import ROOT, Settings
from backend.database import Database
from backend.routes import analysis, auth, dashboard
from backend.security import SlidingWindowLimiter, logger, security_log, setup_logging


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    settings = settings or Settings()
    setup_logging(settings.log_path)
    app = FastAPI(title="Phishing Email Detection & Awareness API", version="1.0.0",
                  description="Defensive, educational API. Analyzes synthetic/authorized email content statically. "
                              "URLs are never visited and attachments are never opened.")
    app.state.settings = settings
    app.state.db = Database(settings.db_path)
    app.state.analyze_limiter = SlidingWindowLimiter(settings.rate_limit_per_minute)
    app.state.login_limiter = SlidingWindowLimiter(settings.login_limit_per_minute)

    @app.middleware("http")
    async def guards(request: Request, call_next):
        length = request.headers.get("content-length")
        if length and length.isdigit() and int(length) > settings.max_request_bytes:
            security_log("request_too_large", path=request.url.path)
            return JSONResponse({"detail": "Request too large"}, status_code=413)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store"
        if request.url.path == "/" or request.url.path.startswith("/static"):
            # Strict CSP for the dashboard: only our own scripts/styles (no inline code, no CDNs).
            response.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                                           "connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
        return response

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        logger.exception("unhandled_error path=%s", request.url.path)     # details stay in the log, not the response
        return JSONResponse({"detail": "Internal server error"}, status_code=500)

    @app.get("/api/health")
    def health():
        model_ready = os.path.exists(settings.model_path)
        return {"status": "ok", "ml_model_loaded": model_ready, "auth_required": settings.auth_required}

    frontend_dir = os.path.join(ROOT, "frontend")
    if os.path.isdir(frontend_dir):
        app.mount("/static", StaticFiles(directory=os.path.join(frontend_dir, "static")), name="static")

        @app.get("/", include_in_schema=False)
        def index():
            return FileResponse(os.path.join(frontend_dir, "index.html"))

    app.include_router(analysis.router, prefix="/api")
    app.include_router(dashboard.router, prefix="/api")
    app.include_router(auth.router, prefix="/api")
    return app


app = create_app()
