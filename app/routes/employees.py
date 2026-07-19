from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from typing import List, Optional
from app.database.database import get_db, log_audit_event
import sqlite3
from app.routes.auth import RoleChecker, get_current_user
from app.utils.encryption import encrypt_pii, decrypt_pii

router = APIRouter()

ALLOWED_EMPLOYEE_FIELDS = {"full_name", "position", "department", "email", "phone", "date_hired", "user_id", "is_active"}

class EmployeeCreate(BaseModel):
    employee_id: Optional[str] = None
    full_name: str
    position: Optional[str] = None
    department: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    date_hired: Optional[str] = None
    user_id: Optional[int] = None
    is_active: bool = True

class EmployeeUpdate(BaseModel):
    full_name: Optional[str] = None
    position: Optional[str] = None
    department: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    date_hired: Optional[str] = None
    user_id: Optional[int] = None
    is_active: Optional[bool] = None

def _row_with_user(row: dict, cursor) -> dict:
    """Attach linked username to an employee row if user_id is set."""
    result = dict(row)
    if result.get("user_id"):
        cursor.execute("SELECT username, role FROM users WHERE id = ?", (result["user_id"],))
        u = cursor.fetchone()
        result["linked_username"] = u["username"] if u else None
        result["linked_role"] = u["role"] if u else None
    else:
        result["linked_username"] = None
        result["linked_role"] = None
        
    for field in ["email", "phone", "full_name", "position", "department", "employee_id"]:
        if field in result and result[field]:
            result[field] = decrypt_pii(result[field])
        
    return result

@router.get("/")
def list_employees(
    current_user: dict = Depends(RoleChecker(["network_admin", "network_operator"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Returns all employee HR profiles."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM employees ORDER BY department, full_name")
    rows = cursor.fetchall()
    return [_row_with_user(dict(r), cursor) for r in rows]

@router.get("/{employee_id_pk}")
def get_employee(
    employee_id_pk: int, 
    current_user: dict = Depends(RoleChecker(["network_admin", "network_operator"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Returns a single employee profile by internal ID."""
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM employees WHERE id = ?", (employee_id_pk,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Employee not found")
    return _row_with_user(dict(row), cursor)

@router.post("/")
def create_employee(
    emp: EmployeeCreate, 
    current_user: dict = Depends(RoleChecker(["network_admin"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Register a new HR employee profile. Super Admin only."""
    cursor = conn.cursor()
    try:
        cursor.execute(
            """INSERT INTO employees (user_id, employee_id, full_name, position, department, email, phone, date_hired, is_active, created_by)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (emp.user_id, encrypt_pii(emp.employee_id), encrypt_pii(emp.full_name), encrypt_pii(emp.position), encrypt_pii(emp.department),
             encrypt_pii(emp.email), encrypt_pii(emp.phone), emp.date_hired, int(emp.is_active), current_user["username"])
        )
        conn.commit()
        new_id = cursor.lastrowid

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="REGISTER",
            target=emp.employee_id or emp.full_name,
            ip_address="127.0.0.1",
            details=f"Created HR employee profile: {emp.full_name} ({emp.department or 'N/A'}) | ID: {emp.employee_id}"
        )

        cursor.execute("SELECT * FROM employees WHERE id = ?", (new_id,))
        return _row_with_user(dict(cursor.fetchone()), cursor)
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail="Employee creation failed")

@router.put("/{employee_id_pk}")
def update_employee(
    employee_id_pk: int, 
    data: EmployeeUpdate, 
    current_user: dict = Depends(RoleChecker(["network_admin"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Update an employee profile. Super Admin only."""
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM employees WHERE id = ?", (employee_id_pk,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Employee not found")

        updates = data.model_dump(exclude_unset=True)
        if not updates:
            return _row_with_user(dict(row), cursor)

        for field in ["email", "phone", "full_name", "position", "department", "employee_id"]:
            if field in updates and updates[field]:
                updates[field] = encrypt_pii(updates[field])

        for key in list(updates.keys()):
            if key not in ALLOWED_EMPLOYEE_FIELDS:
                del updates[key]

        if not updates:
            return _row_with_user(dict(row), cursor)

        set_parts = []
        params = []
        for k, v in updates.items():
            set_parts.append(f"{k} = ?")
            params.append(int(v) if isinstance(v, bool) else v)
        params.append(employee_id_pk)

        cursor.execute(f"UPDATE employees SET {', '.join(set_parts)} WHERE id = ?", params)
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="UPDATE",
            target=row["employee_id"] or str(employee_id_pk),
            ip_address="127.0.0.1",
            details=f"Updated employee {row['full_name']}: {list(updates.keys())}"
        )
        cursor.execute("SELECT * FROM employees WHERE id = ?", (employee_id_pk,))
        return _row_with_user(dict(cursor.fetchone()), cursor)
    except Exception as e:
        conn.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Update failed")

@router.delete("/{employee_id_pk}")
def delete_employee(
    employee_id_pk: int, 
    current_user: dict = Depends(RoleChecker(["network_admin"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Delete an employee profile. Super Admin only."""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM employees WHERE id = ?", (employee_id_pk,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Employee not found")

        cursor.execute("DELETE FROM employees WHERE id = ?", (employee_id_pk,))
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="DELETE",
            target=row["employee_id"] or str(employee_id_pk),
            ip_address="127.0.0.1",
            details=f"Deleted employee profile: {row['full_name']} ({row['department']})"
        )
        return {"message": f"Employee '{row['full_name']}' deleted successfully"}
    except Exception as e:
        conn.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Delete failed")

@router.post("/{employee_id_pk}/assign-device/{device_id}")
def assign_device_to_employee(
    employee_id_pk: int, 
    device_id: int, 
    current_user: dict = Depends(RoleChecker(["network_admin", "network_operator"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Assign a network device (PC/workstation) to an employee as their primary device."""
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM employees WHERE id = ?", (employee_id_pk,))
        emp = cursor.fetchone()
        if not emp:
            raise HTTPException(status_code=404, detail="Employee not found")

        cursor.execute("SELECT hostname, ip, mac FROM devices WHERE id = ?", (device_id,))
        dev = cursor.fetchone()
        if not dev:
            raise HTTPException(status_code=404, detail="Device not found")

        cursor.execute(
            "UPDATE devices SET owner_name = ?, department = ? WHERE id = ?",
            (emp["full_name"], emp["department"], device_id)
        )
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="UPDATE",
            target=dev["mac"] or dev["ip"],
            ip_address="127.0.0.1",
            details=f"Assigned device {dev['hostname'] or dev['ip']} to employee {emp['full_name']} ({emp['department']})"
        )
        return {
            "status": "success",
            "message": f"Device '{dev['hostname'] or dev['ip']}' assigned to {emp['full_name']}",
            "employee": emp["full_name"],
            "device": dev["hostname"] or dev["ip"]
        }
    except Exception as e:
        conn.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Assignment failed")