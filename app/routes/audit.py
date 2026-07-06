from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from app.models.device import AuditLog
from app.database.database import get_db
import sqlite3
from app.routes.auth import RoleChecker
from typing import List, Optional
import csv
import io

router = APIRouter()

@router.get("/", response_model=List[AuditLog])
def list_audit_logs(
    current_user: dict = Depends(RoleChecker(["super_admin", "operator"])),
    action: Optional[str] = Query(None, description="Filter by action type (e.g. SCAN, REGISTER, POLICY, DELETE, AUTH)"),
    username: Optional[str] = Query(None, description="Filter by operator username"),
    conn: sqlite3.Connection = Depends(get_db)
):
    cursor = conn.cursor()

    query = "SELECT * FROM audit_logs WHERE 1=1"
    params = []

    if action:
        query += " AND UPPER(action) = UPPER(?)"
        params.append(action)

    if username:
        query += " AND username LIKE ?"
        params.append(f"%{username}%")

    query += " ORDER BY timestamp DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

@router.get("/export/csv")
def export_audit_csv(
    current_user: dict = Depends(RoleChecker(["super_admin", "operator"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Exports all audit logs as a downloadable CSV file."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC")
    rows = cursor.fetchall()

    output = io.StringIO()
    writer = csv.writer(output)

    # Header row
    writer.writerow(["ID", "Timestamp", "Operator", "Role", "Action", "Target", "IP Address", "Details"])

    for row in rows:
        writer.writerow([
            row["id"],
            row["timestamp"],
            row["username"] or "system",
            row["role"] or "system",
            row["action"] or "",
            row["target"] or "",
            row["ip_address"] or "",
            row["details"] or ""
        ])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=recon_nds_audit_logs.csv"}
    )
