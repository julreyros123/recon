from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
from app.database.database import get_db, log_audit_event
import sqlite3
from app.routes.auth import RoleChecker, get_current_user

router = APIRouter()

ALLOWED_WORKSPACE_FIELDS = {"name", "description", "location"}

class WorkspaceCreate(BaseModel):
    name: str
    description: Optional[str] = None
    location: Optional[str] = None

class WorkspaceUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    location: Optional[str] = None

def _workspace_with_devices(ws_row: dict, cursor) -> dict:
    """Attach device list to a workspace row."""
    result = dict(ws_row)
    cursor.execute("""
        SELECT d.id, d.ip, d.hostname, d.mac, d.os_type, d.status, d.trust_level, wd.date_added
        FROM workspace_devices wd
        JOIN devices d ON wd.device_id = d.id
        WHERE wd.workspace_id = ?
        ORDER BY d.hostname
    """, (result["id"],))
    result["devices"] = [dict(r) for r in cursor.fetchall()]
    result["device_count"] = len(result["devices"])
    return result

@router.get("/")
def list_workspaces(
    current_user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Returns all workspaces with their assigned devices."""
    cursor = conn.cursor()
    if current_user.get("role") == "user":
        cursor.execute("SELECT department FROM employees WHERE user_id = (SELECT id FROM users WHERE username = ?)", (current_user["username"],))
        emp_row = cursor.fetchone()
        if emp_row and emp_row["department"]:
            dept = emp_row["department"]
            search_term_alt = dept
            if dept == "Human Resources":
                search_term_alt = "HR"
            elif dept == "IT":
                search_term_alt = "IT"
            elif dept == "Finance":
                search_term_alt = "Finance"
            cursor.execute(
                "SELECT * FROM workspaces WHERE name LIKE ? OR name LIKE ? OR description LIKE ? ORDER BY name",
                (f"%{dept}%", f"%{search_term_alt}%", f"%{dept}%")
            )
        else:
            return []
    else:
        cursor.execute("SELECT * FROM workspaces ORDER BY name")
    rows = cursor.fetchall()
    return [_workspace_with_devices(dict(r), cursor) for r in rows]

@router.get("/{workspace_id}")
def get_workspace(
    workspace_id: int, 
    current_user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Returns a single workspace with its devices."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM workspaces WHERE id = ?", (workspace_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Workspace not found")
    return _workspace_with_devices(dict(row), cursor)

@router.post("/")
def create_workspace(
    ws: WorkspaceCreate, 
    current_user: dict = Depends(RoleChecker(["super_admin", "operator"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Create a new workspace. Super Admin or Operator."""
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO workspaces (name, description, location, created_by) VALUES (?, ?, ?, ?)",
            (ws.name, ws.description, ws.location, current_user["username"])
        )
        conn.commit()
        new_id = cursor.lastrowid

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="REGISTER",
            target=ws.name,
            ip_address="127.0.0.1",
            details=f"Created workspace: '{ws.name}' at {ws.location or 'N/A'}"
        )
        cursor.execute("SELECT * FROM workspaces WHERE id = ?", (new_id,))
        return _workspace_with_devices(dict(cursor.fetchone()), cursor)
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Workspace creation failed")

@router.put("/{workspace_id}")
def update_workspace(
    workspace_id: int, 
    data: WorkspaceUpdate, 
    current_user: dict = Depends(RoleChecker(["super_admin", "operator"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Update a workspace. Super Admin or Operator."""
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM workspaces WHERE id = ?", (workspace_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Workspace not found")

        updates = data.model_dump(exclude_unset=True)
        for key in list(updates.keys()):
            if key not in ALLOWED_WORKSPACE_FIELDS:
                del updates[key]

        if not updates:
            return _workspace_with_devices(dict(row), cursor)

        # Merge updates with existing database values
        name = updates.get("name", row["name"])
        description = updates.get("description", row["description"])
        location = updates.get("location", row["location"])

        cursor.execute(
            """
            UPDATE workspaces SET
                name = ?,
                description = ?,
                location = ?
            WHERE id = ?
            """,
            (name, description, location, workspace_id)
        )
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="UPDATE",
            target=row["name"],
            ip_address="127.0.0.1",
            details=f"Updated workspace '{row['name']}': {list(updates.keys())}"
        )
        cursor.execute("SELECT * FROM workspaces WHERE id = ?", (workspace_id,))
        return _workspace_with_devices(dict(cursor.fetchone()), cursor)
    except Exception as e:
        conn.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Update failed")

@router.delete("/{workspace_id}")
def delete_workspace(
    workspace_id: int, 
    current_user: dict = Depends(RoleChecker(["super_admin"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Delete a workspace. Super Admin only."""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM workspaces WHERE id = ?", (workspace_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Workspace not found")

        cursor.execute("DELETE FROM workspaces WHERE id = ?", (workspace_id,))
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="DELETE",
            target=row["name"],
            ip_address="127.0.0.1",
            details=f"Deleted workspace: '{row['name']}'"
        )
        return {"message": f"Workspace '{row['name']}' deleted successfully"}
    except Exception as e:
        conn.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Delete failed")

@router.post("/{workspace_id}/add-device/{device_id}")
def add_device_to_workspace(
    workspace_id: int, 
    device_id: int, 
    current_user: dict = Depends(RoleChecker(["super_admin", "operator"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Add a device to a workspace."""
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT name FROM workspaces WHERE id = ?", (workspace_id,))
        ws = cursor.fetchone()
        if not ws:
            raise HTTPException(status_code=404, detail="Workspace not found")

        cursor.execute("SELECT hostname, ip FROM devices WHERE id = ?", (device_id,))
        dev = cursor.fetchone()
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found")

        cursor.execute(
            "INSERT OR IGNORE INTO workspace_devices (workspace_id, device_id, added_by) VALUES (?, ?, ?)",
            (workspace_id, device_id, current_user["username"])
        )
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="UPDATE",
            target=ws["name"],
            ip_address="127.0.0.1",
            details=f"Added device '{dev['hostname'] or dev['ip']}' to workspace '{ws['name']}'"
        )
        return {"status": "success", "message": f"Device added to workspace '{ws['name']}'"}
    except Exception as e:
        conn.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Failed to add device")

@router.delete("/{workspace_id}/remove-device/{device_id}")
def remove_device_from_workspace(
    workspace_id: int, 
    device_id: int, 
    current_user: dict = Depends(RoleChecker(["super_admin", "operator"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Remove a device from a workspace."""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM workspaces WHERE id = ?", (workspace_id,))
        ws = cursor.fetchone()
        if not ws:
            raise HTTPException(status_code=404, detail="Workspace not found")

        cursor.execute(
            "DELETE FROM workspace_devices WHERE workspace_id = ? AND device_id = ?",
            (workspace_id, device_id)
        )
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="UPDATE",
            target=ws["name"],
            ip_address="127.0.0.1",
            details=f"Removed device ID {device_id} from workspace '{ws['name']}'"
        )
        return {"status": "success", "message": "Device removed from workspace"}
    except Exception as e:
        conn.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Failed to remove device")