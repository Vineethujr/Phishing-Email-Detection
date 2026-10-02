"""Analysis endpoints: analyze email, upload .eml/.txt, analyze URL, history CRUD."""
import os
from typing import Literal, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, Response, UploadFile

from backend.database import CLASS_CODES
from backend.dependencies import current_user, get_db, get_settings, rate_limit_analyze, require_admin
from backend.models.schemas import AnalyzeRequest, UrlRequest
from backend.security import security_log
from backend.services.analysis_service import assess_email
from backend.services.url_analyzer import analyze_url
from backend.utils.eml_parser import parse_eml
from backend.utils.preprocessing import extract_sender_domain

router = APIRouter()
ALLOWED_UPLOADS = {".eml", ".txt"}


def _run_and_store(db, settings, sender, subject, body, attachment, display, use_ml):
    result = assess_email(sender, subject, body, attachment, display, use_ml, settings.model_path)
    result["analysis_id"] = db.save_analysis(result, extract_sender_domain(sender), subject)
    return result


@router.post("/analyze", status_code=200, dependencies=[Depends(current_user), Depends(rate_limit_analyze)])
def analyze(req: AnalyzeRequest, db=Depends(get_db), settings=Depends(get_settings)):
    return _run_and_store(db, settings, req.sender, req.subject, req.body, req.attachment_name, req.display_name, req.use_ml)


@router.post("/analyze/upload", dependencies=[Depends(current_user), Depends(rate_limit_analyze)])
async def analyze_upload(file: UploadFile = File(...), use_ml: bool = True, db=Depends(get_db), settings=Depends(get_settings)):
    """Analyze a .eml/.txt file. We only read text and attachment FILENAMES; nothing is executed or saved to disk."""
    ext = os.path.splitext(file.filename or "")[1].lower()
    if ext not in ALLOWED_UPLOADS:
        security_log("upload_rejected", reason="extension", ext=ext)
        raise HTTPException(415, "Only .eml or .txt files are accepted")
    data = await file.read(settings.max_upload_bytes + 1)
    if len(data) > settings.max_upload_bytes:
        security_log("upload_rejected", reason="too_large")
        raise HTTPException(413, f"File exceeds {settings.max_upload_bytes} bytes")
    try:
        parsed = parse_eml(data)
    except Exception:
        raise HTTPException(400, "File could not be parsed as an email")
    if not parsed["sender"] and not parsed["subject"]:     # plain text with no headers
        parsed["body"] = data.decode("utf-8", errors="replace")[:200_000]
    if not (parsed["sender"] or parsed["subject"] or parsed["body"].strip()):
        raise HTTPException(422, "File contains no analyzable content")
    return _run_and_store(db, settings, parsed["sender"], parsed["subject"], parsed["body"], parsed["attachment_name"], None, use_ml)


@router.post("/analyze/url", dependencies=[Depends(current_user), Depends(rate_limit_analyze)])
def analyze_single_url(req: UrlRequest):
    """Static analysis of one URL string. The URL is never visited and this check is not stored."""
    return analyze_url(req.url)


@router.get("/analyses", dependencies=[Depends(current_user)])
def list_analyses(classification: Optional[Literal["LOW", "MODERATE", "SUSPICIOUS", "HIGH"]] = None,
                  q: Optional[str] = Query(None, max_length=100),
                  sort: Literal["newest", "oldest", "risk_desc", "risk_asc"] = "newest",
                  limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0), db=Depends(get_db)):
    items, total = db.list_analyses(CLASS_CODES.get(classification), q, sort, limit, offset)
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@router.get("/analyses/{analysis_id}", dependencies=[Depends(current_user)])
def get_analysis(analysis_id: int, db=Depends(get_db)):
    found = db.get_analysis(analysis_id)
    if not found:
        raise HTTPException(404, "Analysis not found")
    return found


@router.delete("/analyses/{analysis_id}", status_code=204)
def delete_analysis(analysis_id: int, user=Depends(require_admin), db=Depends(get_db)):
    if not db.delete_analysis(analysis_id):
        raise HTTPException(404, "Analysis not found")
    security_log("analysis_deleted", analysis_id=analysis_id, user=(user or {}).get("username", "anonymous"))
    return Response(status_code=204)
