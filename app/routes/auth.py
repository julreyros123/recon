import os
import secrets
import base64
import json
import hmac
import hashlib
import time
import datetime
from typing import Optional, List
from fastapi import Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# ── Secret key management ─────────────────────────────────────
# Prefer SESSION_SECRET_KEY from .env (more secure than a plain file)
from dotenv import load_dotenv
load_dotenv()

SECRET_KEY = os.getenv("SESSION_SECRET_KEY")
if not SECRET_KEY:
    # Migration fallback: read from .session_key file if it exists
    KEY_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), ".session_key")
    if os.path.exists(KEY_FILE):
        try:
            with open(KEY_FILE, "r") as f:
                SECRET_KEY = f.read().strip()
        except Exception:
            pass
if not SECRET_KEY:
    SECRET_KEY = secrets.token_hex(32)
    print("WARNING: SESSION_SECRET_KEY not set. Tokens will be invalidated on restart. Add it to .env!")

security_scheme = HTTPBearer()

# ── RBAC Role Hierarchy ───────────────────────────────────────
# network_admin > network_operator > user
ROLE_HIERARCHY = {
    "network_admin": 3,
    "network_operator": 2,
    "staff": 1,
}

MAX_LOGIN_ATTEMPTS = 3        # Lock account after this many consecutive failures
LOCKOUT_PERMANENT = True      # Lockout requires admin reset (not time-based)
LOCKOUT_MINUTES = 15          # Fallback if LOCKOUT_PERMANENT is False

# ── Token functions ───────────────────────────────────────────
def generate_token(payload: dict) -> str:
    payload_str = json.dumps(payload)
    payload_b64 = base64.urlsafe_b64encode(payload_str.encode()).decode().rstrip("=")
    sig = hmac.new(SECRET_KEY.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
    return f"{payload_b64}.{sig}"

def verify_token(token: str) -> Optional[dict]:
    try:
        parts = token.split('.')
        if len(parts) != 2:
            return None
        payload_b64, sig = parts
        expected_sig = hmac.new(SECRET_KEY.encode(), payload_b64.encode(), hashlib.sha256).hexdigest()
        if not secrets.compare_digest(sig, expected_sig):
            return None

        # Restore base64 padding
        padding = len(payload_b64) % 4
        if padding:
            payload_b64 += "=" * (4 - padding)

        payload_str = base64.urlsafe_b64decode(payload_b64.encode()).decode()
        payload = json.loads(payload_str)

        # Check expiration
        if "exp" in payload and time.time() > payload["exp"]:
            return None

        return payload
    except Exception:
        return None

# ── Account lockout helpers ───────────────────────────────────
def is_account_locked(user_row) -> bool:
    """Returns True if account is currently locked out."""
    locked_until = user_row["locked_until"] if "locked_until" in user_row.keys() else None
    if not locked_until:
        return False
    try:
        lock_dt = datetime.datetime.fromisoformat(str(locked_until))
        if lock_dt.tzinfo is None:
            lock_dt = lock_dt.replace(tzinfo=datetime.timezone.utc)
        return datetime.datetime.now(datetime.timezone.utc) < lock_dt
    except Exception:
        return False

def increment_login_attempts(conn, user_id: int) -> int:
    """Increments failed attempts counter. Applies tiered lockouts:
       - 5 attempts -> 15 min lock
       - 8 attempts -> 30 min lock
       - 11 attempts -> permanent lock
    """
    cursor = conn.cursor()
    cursor.execute("SELECT login_attempts FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    attempts = (row["login_attempts"] or 0) + 1 if row else 1

    if attempts == 5:
        lock_until = (datetime.datetime.now(datetime.timezone.utc) +
                      datetime.timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?",
            (attempts, lock_until, user_id)
        )
    elif attempts == 8:
        lock_until = (datetime.datetime.now(datetime.timezone.utc) +
                      datetime.timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
        cursor.execute(
            "UPDATE users SET login_attempts = ?, locked_until = ? WHERE id = ?",
            (attempts, lock_until, user_id)
        )
    elif attempts >= 11:
        cursor.execute(
            "UPDATE users SET login_attempts = ?, locked_until = '9999-12-31 23:59:59' WHERE id = ?",
            (attempts, user_id)
        )
    else:
        cursor.execute("UPDATE users SET login_attempts = ? WHERE id = ?", (attempts, user_id))

    conn.commit()
    return attempts

def reset_login_attempts(conn, user_id: int):
    """Resets failed login counter and clears lockout after successful login."""
    cursor = conn.cursor()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "UPDATE users SET login_attempts = 0, locked_until = NULL, last_login = ? WHERE id = ?",
        (now_str, user_id)
    )
    conn.commit()

# ── FastAPI dependencies ──────────────────────────────────────
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security_scheme)) -> dict:
    token = credentials.credentials
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return payload

class RoleChecker:
    """Dependency that enforces minimum role level access."""
    def __init__(self, allowed_roles: List[str], require_pin: bool = True):
        self.allowed_roles = allowed_roles
        self.require_pin = require_pin

    def __call__(self, user: dict = Depends(get_current_user)):
        role = user.get("role", "")
        if role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: requires one of {self.allowed_roles}",
            )
        if self.require_pin and role == "network_admin" and not user.get("pin_verified", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Super admin PIN verification required.",
            )
        return user

class MinRoleChecker:
    """Dependency that enforces minimum role hierarchy level."""
    def __init__(self, min_role: str, require_pin: bool = True):
        self.min_level = ROLE_HIERARCHY.get(min_role, 0)
        self.require_pin = require_pin

    def __call__(self, user: dict = Depends(get_current_user)):
        role = user.get("role", "")
        user_level = ROLE_HIERARCHY.get(role, 0)
        if user_level < self.min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: insufficient privilege level",
            )
        if self.require_pin and role == "network_admin" and not user.get("pin_verified", False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Super admin PIN verification required.",
            )
        return user
