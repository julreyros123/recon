from fastapi import APIRouter, Depends, Query
from app.database.database import get_db
from app.routes.auth import get_current_user
import sqlite3
from typing import Optional

router = APIRouter()


@router.get("/sessions")
def list_scan_sessions(
    limit: int = Query(50, ge=1, le=200),
    skip: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    """List all past scan sessions from the reports table, newest first."""
    cursor = db.cursor()
    cursor.execute(
        "SELECT * FROM reports ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (limit, skip)
    )
    rows = cursor.fetchall()
    return [dict(row) for row in rows]


@router.get("/")
def list_scan_history(
    scan_id: Optional[int] = Query(None, description="Filter by scan session ID"),
    limit: int = Query(200, ge=1, le=1000),
    skip: int = Query(0, ge=0),
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    """List discovered devices from scan history, optionally filtered by scan session."""
    cursor = db.cursor()
    if scan_id is not None:
        cursor.execute(
            "SELECT sh.*, r.timestamp as scan_timestamp, r.summary as scan_summary "
            "FROM scan_history sh LEFT JOIN reports r ON sh.scan_id = r.id "
            "WHERE sh.scan_id = ? ORDER BY sh.discovered_at DESC LIMIT ? OFFSET ?",
            (scan_id, limit, skip)
        )
    else:
        cursor.execute(
            "SELECT sh.*, r.timestamp as scan_timestamp, r.summary as scan_summary "
            "FROM scan_history sh LEFT JOIN reports r ON sh.scan_id = r.id "
            "ORDER BY sh.discovered_at DESC LIMIT ? OFFSET ?",
            (limit, skip)
        )
    rows = cursor.fetchall()
    return [dict(row) for row in rows]
