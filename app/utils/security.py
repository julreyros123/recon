"""
security.py — Centralized security utilities for Recon NDS

Provides:
  - sanitize_str()     : Strip HTML/XSS payloads from user input before DB writes
  - escape_html()      : HTML-encode a value for safe text display
  - get_client_ip()    : Extract the real client IP from a FastAPI Request
  - validate_agent_key(): Validate pre-shared API key for workstation agent telemetry
"""

import os
import re
import html
import bleach
from fastapi import Request, HTTPException, Header
from typing import Optional

# ── Agent API Key ─────────────────────────────────────────────────────────────
AGENT_API_KEY = os.getenv("AGENT_API_KEY", "")

# ── XSS / HTML Sanitization ───────────────────────────────────────────────────

def sanitize_str(value: Optional[str], max_length: int = 1024) -> Optional[str]:
    """
    Strip all HTML tags and encode dangerous characters from a user-supplied string.
    This prevents stored XSS when values are later rendered in the frontend.
    Returns None if the input is None or empty.
    """
    if value is None:
        return None
    # bleach.clean with no allowed tags strips all HTML
    cleaned = bleach.clean(str(value), tags=[], attributes={}, strip=True)
    # Truncate to max_length to prevent oversized inputs
    return cleaned[:max_length].strip()


def sanitize_ip(value: Optional[str]) -> Optional[str]:
    """Validate that a string looks like a valid IPv4/IPv6 address or CIDR, or '*'."""
    if value is None:
        return None
    value = str(value).strip()
    if value == "*":
        return value
    # Allow valid IPv4, IPv4 CIDR, IPv6
    pattern = r"^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$|^[\da-fA-F:]+$"
    if re.match(pattern, value):
        return value
    raise ValueError(f"Invalid IP address format: {value}")


def escape_html(value: Optional[str]) -> Optional[str]:
    """HTML-encode a string for safe rendering in HTML context."""
    if value is None:
        return None
    return html.escape(str(value))


# ── Client IP Extraction ──────────────────────────────────────────────────────

_TRUSTED_PROXIES = os.getenv("TRUSTED_PROXIES", "127.0.0.1,::1").split(",")
_TRUSTED_PROXIES = [p.strip() for p in _TRUSTED_PROXIES if p.strip()]

def get_client_ip(request: Request) -> str:
    """
    Extract the real client IP address, accounting for reverse proxies.
    Only trusts X-Forwarded-For when the request comes from a trusted proxy.
    """
    client_host = request.client.host if request.client else "unknown"
    
    if client_host not in _TRUSTED_PROXIES:
        if request.headers.get("X-Real-IP"):
            real_ip = request.headers.get("X-Real-IP")
            if real_ip and _is_valid_ip(real_ip):
                return real_ip.strip()
        return client_host
    
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        first_client = forwarded_for.split(",")[0].strip()
        if _is_valid_ip(first_client):
            return first_client
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip and _is_valid_ip(real_ip):
        return real_ip.strip()
    
    return client_host


def _is_valid_ip(ip_str: str) -> bool:
    """Validate that a string is a valid IPv4 or IPv6 address."""
    if not ip_str:
        return False
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$'
    ipv6_pattern = r'^[\da-fA-F:]+$'
    if re.match(ipv4_pattern, ip_str):
        parts = ip_str.split("/")[0].split(".")
        return all(0 <= int(p) <= 255 for p in parts)
    if re.match(ipv6_pattern, ip_str):
        return True
    return False


# ── Agent API Key Validation ──────────────────────────────────────────────────

def validate_agent_key(x_agent_key: Optional[str] = Header(default=None)) -> str:
    """
    FastAPI dependency that enforces the X-Agent-Key header on telemetry endpoints.
    The key must match the AGENT_API_KEY environment variable.
    """
    if not AGENT_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="Server is not configured to accept agent telemetry (missing AGENT_API_KEY)."
        )
    if not x_agent_key or x_agent_key != AGENT_API_KEY:
        raise HTTPException(
            status_code=401,
            detail="Invalid or missing agent API key. Set the X-Agent-Key header."
        )
    return x_agent_key


# ── Input Validation Helpers ──────────────────────────────────────────────────

USERNAME_RE = re.compile(r"^[a-zA-Z0-9._\-]{1,64}$")
PIN_RE = re.compile(r"^\d{6}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_username(username: str) -> str:
    """Username: 1-64 chars, alphanumeric + . _ -"""
    if not USERNAME_RE.match(username):
        raise HTTPException(
            status_code=422,
            detail="Username must be 1–64 characters and contain only letters, digits, '.', '_', or '-'."
        )
    return username


def validate_pin(pin: str) -> str:
    """PIN must be exactly 6 digits."""
    if not PIN_RE.match(pin):
        raise HTTPException(status_code=422, detail="PIN must be exactly 6 digits.")
    return pin


def validate_email(email: Optional[str]) -> Optional[str]:
    """Basic email format check."""
    if not email:
        return email
    if not EMAIL_RE.match(email):
        raise HTTPException(status_code=422, detail=f"Invalid email format: {email}")
    return email


def validate_password(password: str) -> str:
    """Password: 8-128 characters."""
    if len(password) < 8:
        raise HTTPException(status_code=422, detail="Password must be at least 8 characters.")
    if len(password) > 128:
        raise HTTPException(status_code=422, detail="Password must not exceed 128 characters.")
    return password
