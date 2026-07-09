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
from pydantic import BaseModel, field_validator, EmailStr
from typing import List, Optional
import time
import datetime
import base64
from app.utils.encryption import encrypt_pii, decrypt_pii
from app.utils.security import (
    sanitize_str, get_client_ip,
    validate_username, validate_pin, validate_password
)

router = APIRouter()

ALLOWED_USER_FIELDS = {"email", "full_name", "role", "is_active", "allowed_ip"}

class UserLogin(BaseModel):
    username: str
    password: str

    @field_validator("username")
    @classmethod
    def check_username(cls, v):
        v = sanitize_str(v, max_length=64) or ""
        if not v:
            raise ValueError("Username is required")
        return v

    @field_validator("password")
    @classmethod
    def check_password(cls, v):
        if not v or len(v) > 128:
            raise ValueError("Password must be 1–128 characters")
        return v

class PinVerify(BaseModel):
    pin: str

    @field_validator("pin")
    @classmethod
    def check_pin(cls, v):
        import re
        if not re.match(r"^\d{6}$", str(v)):
            raise ValueError("PIN must be exactly 6 digits")
        return v

class PinSet(BaseModel):
    current_password: str
    pin: str

    @field_validator("pin")
    @classmethod
    def check_pin(cls, v):
        import re
        if not re.match(r"^\d{6}$", str(v)):
            raise ValueError("PIN must be exactly 6 digits")
        return v

class ChangePassword(BaseModel):
    current_password: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def check_new_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if len(v) > 128:
            raise ValueError("Password must not exceed 128 characters")
        return v

class UserUpdateModel(BaseModel):
    email: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    allowed_ip: Optional[str] = None

@router.post("/login")
def login(
    credentials: UserLogin,
    request: Request,
    conn: sqlite3.Connection = Depends(get_db)
):
    client_ip = get_client_ip(request)

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (credentials.username,))
        row = cursor.fetchone()

        INVALID_CREDS = HTTPException(status_code=400, detail="Invalid username or password")

        if not row:
            raise INVALID_CREDS

        if not row["is_active"]:
            raise HTTPException(status_code=403, detail="Account is disabled. Contact your administrator.")

        if is_account_locked(row):
            raise HTTPException(
                status_code=429,
                detail=f"Account temporarily locked due to too many failed attempts. Try again in {15} minutes."
            )

        allowed_ip = row["allowed_ip"] if "allowed_ip" in row.keys() else "*"
        if allowed_ip and allowed_ip != "*":
            if client_ip != allowed_ip:
                log_audit_event(
                    username=credentials.username,
                    role=row["role"] if "role" in row.keys() else "unknown",
                    action="AUTH",
                    target="system",
                    ip_address=client_ip,
                    details=f"Login blocked due to IP whitelist mismatch (expected {allowed_ip}, got {client_ip})"
                )
                raise HTTPException(status_code=403, detail="Login from this IP address is not allowed.")

        try:
            provided_password = base64.b64decode(credentials.password).decode('utf-8')
        except Exception:
            provided_password = credentials.password

        if not verify_password(provided_password, row["password_hash"]):
            attempts = increment_login_attempts(conn, row["id"])
            remaining = max(0, 5 - attempts)
            if remaining == 0:
                raise HTTPException(
                    status_code=429,
                    detail="Account locked for 15 minutes due to 5 failed login attempts."
                )
            raise INVALID_CREDS

        reset_login_attempts(conn, row["id"])

        role = row["role"]
        pin_required = (role == "super_admin")

        if role == "super_admin":
            exp_time = time.time() + 300
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
            "pin_verified": not pin_required,
        }
        token = generate_token(payload)

        log_audit_event(
            username=row["username"],
            role=role,
            action="AUTH",
            target="system",
            ip_address=client_ip,
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

@router.post("/verify-pin")
def verify_pin(
    pin_data: PinVerify,
    request: Request,
    current_user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    if current_user.get("role") != "super_admin":
        raise HTTPException(status_code=403, detail="PIN verification is only required for Super Admin accounts")

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT super_admin_pin_hash FROM users WHERE username = ?", (current_user["username"],))
        row = cursor.fetchone()
        if not row or not row["super_admin_pin_hash"]:
            raise HTTPException(status_code=400, detail="No PIN configured for this account")

        provided_pin = pin_data.pin
        try:
            import base64
            provided_pin = base64.b64decode(pin_data.pin).decode("utf-8")
        except Exception:
            provided_pin = pin_data.pin

        if not verify_password(provided_pin, row["super_admin_pin_hash"]):
            raise HTTPException(status_code=400, detail="Invalid PIN")

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
            ip_address=get_client_ip(request),
            details=f"Super Admin PIN verified for {current_user['username']}"
        )

        return {"access_token": token, "token_type": "bearer", "pin_verified": True}
    finally:
        pass

@router.post("/set-pin")
def set_pin(
    pin_data: PinSet,
    request: Request,
    current_user: dict = Depends(RoleChecker(["super_admin"], require_pin=False)),
    conn: sqlite3.Connection = Depends(get_db)
):
    try:
        cursor = conn.cursor()

        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (current_user["username"],))
        row = cursor.fetchone()
        if not row or not verify_password(pin_data.current_password, row["password_hash"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        new_pin = pin_data.pin
        try:
            import base64
            new_pin = base64.b64decode(pin_data.pin).decode("utf-8")
        except Exception:
            new_pin = pin_data.pin

        pin_hash = hash_password(new_pin)
        cursor.execute("UPDATE users SET super_admin_pin_hash = ? WHERE username = ?",
                       (pin_hash, current_user["username"]))
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="POLICY",
            target=current_user["username"],
            ip_address=get_client_ip(request),
            details=f"Super Admin security PIN updated for {current_user['username']}"
        )
        return {"status": "success", "message": "Security PIN updated successfully"}
    finally:
        pass

@router.post("/change-password")
def change_password(
    data: ChangePassword,
    request: Request,
    current_user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE username = ?", (current_user["username"],))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        if not verify_password(data.current_password, row["password_hash"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        new_hash = hash_password(data.new_password)
        cursor.execute("UPDATE users SET password_hash = ? WHERE username = ?",
                       (new_hash, current_user["username"]))
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="POLICY",
            target=current_user["username"],
            ip_address=get_client_ip(request),
            details=f"Password changed for user {current_user['username']}"
        )
        return {"status": "success", "message": "Password updated successfully"}
    finally:
        pass

@router.get("/", response_model=List[User])
def list_users(
    current_user: dict = Depends(RoleChecker(["super_admin"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users ORDER BY role DESC, username ASC")
        rows = cursor.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            for field in ["email", "full_name"]:
                if field in d and d[field]:
                    d[field] = decrypt_pii(d[field])
            result.append(d)
        return result
    finally:
        pass

@router.post("/", response_model=User)
def create_user(
    user: UserCreate,
    request: Request,
    current_user: dict = Depends(RoleChecker(["super_admin"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    allowed_roles = ["super_admin", "operator", "user"]
    if user.role not in allowed_roles:
        raise HTTPException(status_code=400, detail=f"Invalid role. Must be one of: {allowed_roles}")

    safe_username = sanitize_str(user.username, max_length=64)
    validate_username(safe_username or "")

    cursor = conn.cursor()
    default_pw = user.username + "123"
    pw_hash = hash_password(default_pw)

    try:
        cursor.execute(
            "INSERT INTO users (username, email, role, is_active, password_hash, allowed_ip) VALUES (?, ?, ?, ?, ?, ?)",
            (safe_username, encrypt_pii(user.email), user.role, int(user.is_active), pw_hash, user.allowed_ip)
        )
        conn.commit()
        user_id = cursor.lastrowid

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="REGISTER",
            target=user.username,
            ip_address=get_client_ip(request),
            details=f"Created new user account: {user.username} with role '{user.role}'. Default password set."
        )

        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            d = dict(row)
            for field in ["email", "full_name"]:
                if field in d and d[field]:
                    d[field] = decrypt_pii(d[field])
            return d
        return None
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=400, detail="User creation failed")
    finally:
        pass

@router.put("/{user_id}", response_model=User)
def update_user(
    user_id: int,
    data: UserUpdateModel,
    request: Request,
    current_user: dict = Depends(RoleChecker(["super_admin"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        updates = data.model_dump(exclude_unset=True)
        # Filter fields to only allowed fields
        for key in list(updates.keys()):
            if key not in ALLOWED_USER_FIELDS:
                del updates[key]

        if not updates:
            return dict(row)

        if "role" in updates and updates["role"] not in ["super_admin", "operator", "user"]:
            raise HTTPException(status_code=400, detail="Invalid role value")

        for field in ["full_name"]:
            if field in updates and updates[field]:
                updates[field] = sanitize_str(updates[field])

        for field in ["email", "full_name"]:
            if field in updates and updates[field]:
                updates[field] = encrypt_pii(updates[field])

        # Merge updates with existing database values
        email = updates.get("email", row["email"])
        full_name = updates.get("full_name", row["full_name"])
        role = updates.get("role", row["role"])
        is_active = updates.get("is_active", row["is_active"])
        allowed_ip = updates.get("allowed_ip", row["allowed_ip"])

        cursor.execute(
            """
            UPDATE users SET
                email = ?,
                full_name = ?,
                role = ?,
                is_active = ?,
                allowed_ip = ?
            WHERE id = ?
            """,
            (email, full_name, role, is_active, allowed_ip, user_id)
        )
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="UPDATE",
            target=row["username"],
            ip_address=get_client_ip(request),
            details=f"Updated user {row['username']}: {list(updates.keys())}"
        )
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if row:
            d = dict(row)
            for field in ["email", "full_name"]:
                if field in d and d[field]:
                    d[field] = decrypt_pii(d[field])
            return d
        return None
    except Exception as e:
        conn.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Update failed")
    finally:
        pass

@router.post("/{user_id}/unlock")
def unlock_user(
    user_id: int,
    request: Request,
    current_user: dict = Depends(RoleChecker(["super_admin"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        cursor.execute("UPDATE users SET login_attempts = 0, locked_until = NULL WHERE id = ?", (user_id,))
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="POLICY",
            target=row["username"],
            ip_address=get_client_ip(request),
            details=f"Unlocked account for user: {row['username']}"
        )
        return {"status": "success", "message": f"Account '{row['username']}' unlocked successfully"}
    finally:
        pass

@router.delete("/{user_id}")
def delete_user(
    user_id: int,
    request: Request,
    current_user: dict = Depends(RoleChecker(["super_admin"])),
    conn: sqlite3.Connection = Depends(get_db)
):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")

        if row["username"] == current_user["username"]:
            raise HTTPException(status_code=400, detail="Cannot delete your own account")

        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()

        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="DELETE",
            target=row["username"],
            ip_address=get_client_ip(request),
            details=f"Deleted user account: {row['username']} (role: {row['role']})"
        )
        return {"message": "User deleted successfully"}
    except Exception as e:
        conn.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Failed to delete user")
    finally:
        pass