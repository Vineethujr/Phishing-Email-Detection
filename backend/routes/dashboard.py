"""Dashboard statistics endpoints."""
from fastapi import APIRouter, Depends, Query

from backend.dependencies import current_user, get_db

router = APIRouter(prefix="/dashboard", dependencies=[Depends(current_user)])


@router.get("/stats")
def stats(days: int = Query(14, ge=1, le=90), db=Depends(get_db)):
    return db.stats(days)


@router.get("/indicators")
def indicators(limit: int = Query(10, ge=1, le=50), db=Depends(get_db)):
    return db.indicator_stats(limit)
