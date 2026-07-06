from fastapi import APIRouter, HTTPException, Depends, Request
from app.models.device import User, UserCreate
from app.database.database import (
    get_db, verify_password, hash_password, log_audit_event
)
import sqlite3
from app.routes.auth import (
    generate_token, RoleChecker, get_current_user,
    is_account_locked, increment_login_attempts, reset_login_attempts
)
from pydantic import BaseModel
from typing import List, Optional
import time
import datetime
from app.utils.encryption import encrypt_pii, decrypt_pii

router = APIRouter()

# ── Request Models ────────────────────────────────────────────
class UserLogin(BaseModel):
    username: str
    password: str

class PinVerify(BaseModel):
    pin: str

class PinSet(BaseModel):
    current_password: str
    pin: str  # 6-digit PIN

class ChangePassword(BaseModel):
    current_password: str
    new_password: str

class UserUpdateModel(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    allowed_ip: Optional[str] = None

# ── Login ─────────────────────────────────────────────────────
@router.post("/login")
def login(
    credentials: UserLogin, 
    request: Request,
    conn: sqlite3.Connection = Depends(get_db)
):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s", (credentials.username,))
        row = cursor.fetchone()

        if not row:
            raise HTTPException(status_code=400, detail="Invalid username or password")

        # Check if account is disabled
        if not row["is_active"]:
            raise HTTPException(status_code=403, detail="Account is disabled. Contact your administrator.")

        # Check if account is locked out
        if is_account_locked(row):
            raise HTTPException(
                status_code=429,
                detail=f"Account temporarily locked due to too many failed attempts. Try again in {15} minutes."
            )

        # Check allowed_ip
        allowed_ip = row["allowed_ip"] if "allowed_ip" in row.keys() else "*"
        if allowed_ip and allowed_ip != "*":
            client_ip = (request.client.host if request.client else "127.0.0.1")
            if client_ip != allowed_ip:
                log_audit_event(
                    username=credentials.username,
                    role=row.get("role", "unknown"),
                    action="AUTH",
                    target="system",
                    ip_address=client_ip,
                    details=f"Login blocked due to IP whitelist mismatch (expected {allowed_ip})"
                )
                raise HTTPException(status_code=403, detail="Login from this IP address is not allowed.")

        # Verify password
        if not verify_password(credentials.password, row["password_hash"]):
            attempts = increment_login_attempts(conn, row["id"])
            remaining = max(0, 5 - attempts)
            if remaining == 0:
                raise HTTPException(
                    status_code=429,
                    detail="Account locked for 15 minutes due to 5 failed login attempts."
                )
            raise HTTPException(
                status_code=400,
                detail=f"Invalid password. {remaining} attempt{'s' if remaining != 1 else ''} remaining before lockout."
            )

        # Successful password — reset counter
        reset_login_attempts(conn, row["id"])

        # For super_admin: issue a pre-auth token requiring PIN verification
        role = row["role"]
        pin_required = (role == "super_admin")

        if role == "super_admin":
            exp_time = time.time() + 300  # 5 minutes for pre-auth
        else:
            exp_time = time.time() + 86400

        fn = row["full_name"] or row["username"]
        if fn and fn.startswith("gAAAAA"):
            fn = decrypt_pii(fn)

        payload = {
            "username": row["username"],
            "role": role,
            "full_name": fn,
            "exp": exp_time,
            "pin_verified": not pin_required,  # False if PIN is still needed
        }
        token = generate_token(payload)

        log_audit_event(
            username=row["username"],
            role=role,
            action="AUTH",
            target="system",
            ip_address=(request.client.host if request.client else "127.0.0.1"),
            details=f"Login successful for {row['username']} ({role})"
        )

        return {
            "access_token": token,
            "token_type": "bearer",
            "username": row["username"],
            "full_name": fn,
            "role": role,
            "pin_required": pin_required,
        }
    finally:
        pass

# ── Super Admin PIN Verification ──────────────────────────────
@router.post("/verify-pin")
def verify_pin(
    pin_data: PinVerify, 
    request: Request, 
    current_user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Second-factor PIN verification for super_admin accounts."""
    if current_user.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="PIN verification is only required for Super Admin accounts")

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT super_admin_pin_hash FROM users WHERE username = %s", (current_user["username"],))
        row = cursor.fetchone()
        if not row or not row["super_admin_pin_hash"]:
            raise HTTPException(status_code=400, detail="No PIN configured for this account")

        if not verify_password(pin_data.pin, row["super_admin_pin_hash"]):
            raise HTTPException(status_code=400, detail="Invalid PIN")

        # Issue a new token with pin_verified=True
        # Need to decrypt full_name for the token if it's encrypted
        fn = current_user.get("full_name", current_user["username"])
        if fn and fn.startswith("gAAAAA"):
            fn = decrypt_pii(fn)
            
        payload = {
            "username": current_user["username"],
            "role": current_user["role"],
            "full_name": fn,
            "exp": time.time() + 1800,
            "pin_verified": True,
        }
        token = generate_token(payload)

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="AUTH",
            target="system",
            ip_address=(request.client.host if request.client else "127.0.0.1"),
            details=f"Super Admin PIN verified for {current_user['username']}"
        )

        return {"access_token": token, "token_type": "bearer", "pin_verified": True}
    finally:
        pass

# ── Set Super Admin PIN ───────────────────────────────────────
@router.post("/set-pin")
def set_pin(
    pin_data: PinSet, 
    request: Request, 
    current_user: dict = Depends(RoleChecker(["super_admin"], require_pin=False)),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Allows a super_admin to set or update their 6-digit security PIN."""
    if len(pin_data.pin) != 6 or not pin_data.pin.isdigit():
        raise HTTPException(status_code=400, detail="PIN must be exactly 6 digits")

    try:
        cursor = conn.cursor()
        
        # Verify current password before allowing PIN change
        cursor.execute("SELECT password_hash FROM users WHERE username = %s", (current_user["username"],))
        row = cursor.fetchone()
        if not row or not verify_password(pin_data.current_password, row["password_hash"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        pin_hash = hash_password(pin_data.pin)
        cursor.execute("UPDATE users SET super_admin_pin_hash = %s WHERE username = %s",
                       (pin_hash, current_user["username"]))
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="POLICY",
            target=current_user["username"],
            ip_address=(request.client.host if request.client else "127.0.0.1"),
            details=f"Super Admin security PIN updated for {current_user['username']}"
        )
        return {"status": "success", "message": "Security PIN updated successfully"}
    finally:
        pass

# ── Change Password ───────────────────────────────────────────
@router.post("/change-password")
def change_password(
    data: ChangePassword, 
    request: Request, 
    current_user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Any authenticated user can change their own password."""
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = %s", (current_user["username"],))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        if not verify_password(data.current_password, row["password_hash"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        new_hash = hash_password(data.new_password)
        cursor.execute("UPDATE users SET password_hash = %s WHERE username = %s",
                       (new_hash, current_user["username"]))
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="POLICY",
            target=current_user["username"],
            ip_address=(request.client.host if request.client else "127.0.0.1"),
            details=f"Password changed for user {current_user['username']}"
        )
        return {"status": "success", "message": "Password updated successfully"}
    finally:
        pass

# ── List Users (super_admin only) ─────────────────────────────
@router.get("/", response_model=List[User])
def list_users(
    current_user: dict = Depends(RoleChecker(["super_admin"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users ORDER BY role DESC, username ASC")
        rows = cursor.fetchall()
        for row in rows:
            for field in ["email", "full_name"]:
                if field in row and row[field]:
                    row[field] = decrypt_pii(row[field])
        return [dict(row) for row in rows]
    finally:
        pass

# ── Create User (super_admin only) ────────────────────────────
@router.post("/", response_model=User)
def create_user(
    user: UserCreate, 
    request: Request, 
    current_user: dict = Depends(RoleChecker(["super_admin"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    # Validate role
    allowed_roles = ["super_admin", "operator", "user"]
    if user.role not in allowed_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {allowed_roles}")

    cursor = conn.cursor()
    default_pw = user.username + "123"
    pw_hash = hash_password(default_pw)

    try:
        cursor.execute(
            "INSERT INTO users (username, email, role, is_active, password_hash, allowed_ip) VALUES (%s, %s, %s, %s, %s, %s)",
            (user.username, encrypt_pii(user.email), user.role, int(user.is_active), pw_hash, user.allowed_ip)
        )
        conn.commit()
        user_id = cursor.lastrowid

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="REGISTER",
            target=user.username,
            ip_address=(request.client.host if request.client else "127.0.0.1"),
            details=f"Created new user account: {user.username} with role '{user.role}'. Default password set."
        )

        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = dict(cursor.fetchone())
        for field in ["email", "full_name"]:
            if field in row and row[field]:
                row[field] = decrypt_pii(row[field])
        return row
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail=f"User creation failed: {e}")
    finally:
        pass

# ── Update User (super_admin only) ────────────────────────────
@router.put("/{user_id}")
def update_user(
    user_id: int, 
    data: UserUpdateModel, 
    request: Request, 
    current_user: dict = Depends(RoleChecker(["super_admin"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        updates = data.model_dump(exclude_unset=True)
        if not updates:
            return dict(row)

        if "role" in updates and updates["role"] not in ["super_admin", "operator", "user"]:
            raise HTTPException(status_code=400, detail="Invalid role value")

        for field in ["email", "full_name"]:
            if field in updates and updates[field]:
                updates[field] = encrypt_pii(updates[field])

        set_parts = [f"{k} = %s" for k in updates.keys()]
        params = list(updates.values()) + [user_id]
        cursor.execute(f"UPDATE users SET {', '.join(set_parts)} WHERE id = %s", params)
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="UPDATE",
            target=row["username"],
            ip_address=(request.client.host if request.client else "127.0.0.1"),
            details=f"Updated user {row['username']}: {list(updates.keys())}"
        )
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = dict(cursor.fetchone())
        for field in ["email", "full_name"]:
            if field in row and row[field]:
                row[field] = decrypt_pii(row[field])
        return row
    except Exception as e:
        conn.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=f"Update failed: {e}")
    finally:
        pass

# ── Unlock Locked Account (super_admin only) ──────────────────
@router.post("/{user_id}/unlock")
def unlock_user(
    user_id: int, 
    request: Request, 
    current_user: dict = Depends(RoleChecker(["super_admin"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        cursor.execute("UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = %s", (user_id,))
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="POLICY",
            target=row["username"],
            ip_address=(request.client.host if request.client else "127.0.0.1"),
            details=f"Unlocked account for user: {row['username']}"
        )
        return {"status": "success", "message": f"Account '{row['username']}' unlocked successfully"}
    finally:
        pass

# ── Delete User (super_admin only) ────────────────────────────
@router.delete("/{user_id}")
def delete_user(
    user_id: int, 
    request: Request, 
    current_user: dict = Depends(RoleChecker(["super_admin"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        # Prevent self-deletion
        if row["username"] == current_user["username"]:
            raise HTTPException(status_code=400, detail="Cannot delete your own account")

        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="DELETE",
            target=row["username"],
            ip_address=(request.client.host if request.client else "127.0.0.1"),
            details=f"Deleted user account: {row['username']} (role: {row['role']})"
        )
        return {"message": "User deleted successfully"}
    except Exception as e:
        conn.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail=f"Failed to delete user: {e}")
    finally:
        pass
