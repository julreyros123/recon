"""
cve_checker.py — NIST NVD CVE Lookup with SQLite Caching

Queries the NIST National Vulnerability Database REST API v2 to find known CVEs
matching a device's vendor/firmware keyword.

Rate limiting: NVD allows ~5 requests/30s without an API key.
Caching: Results are cached in the cve_cache table for 24 hours.

Usage:
    from app.scanner.cve_checker import check_cves
    cves = check_cves(conn, device_id=1, vendor="Cisco", firmware_version="15.7(3)M4")
"""
import hashlib
import json
import time
import sqlite3
import datetime
from typing import List, Dict, Any, Optional

try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

NVD_API_BASE   = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_TTL_HOURS = 24
REQUEST_TIMEOUT = 10  # seconds


def _cvss_to_severity(score: Optional[float]) -> str:
    """Maps a CVSS base score to a human-readable severity label."""
    if score is None:
        return "Unknown"
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _build_query_key(vendor: str, firmware_version: str) -> str:
    """Builds a deterministic cache key from vendor + firmware."""
    raw = f"{vendor.lower().strip()}:{firmware_version.lower().strip()}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _get_cached(conn: sqlite3.Connection, query_key: str) -> Optional[List[Dict]]:
    """Returns cached CVE data if fresh (< 24h), else None."""
    cursor = conn.cursor()
    cursor.execute("SELECT cve_data, fetched_at FROM cve_cache WHERE query_key = ?", (query_key,))
    row = cursor.fetchone()
    if not row:
        return None
    try:
        fetched_at = datetime.datetime.fromisoformat(str(row["fetched_at"]))
        if fetched_at.tzinfo is None:
            fetched_at = fetched_at.replace(tzinfo=datetime.timezone.utc)
        age = datetime.datetime.now(datetime.timezone.utc) - fetched_at
        if age.total_seconds() < CACHE_TTL_HOURS * 3600:
            return json.loads(row["cve_data"])
    except Exception:
        pass
    return None


def _save_cache(conn: sqlite3.Connection, query_key: str, cves: List[Dict]):
    """Upserts CVE results into the cve_cache table."""
    cursor = conn.cursor()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute(
        "INSERT INTO cve_cache (query_key, cve_data, fetched_at) VALUES (?, ?, ?) "
        "ON CONFLICT(query_key) DO UPDATE SET cve_data = excluded.cve_data, fetched_at = excluded.fetched_at",
        (query_key, json.dumps(cves), now_str)
    )
    conn.commit()


def _fetch_nvd(keyword: str, api_key: Optional[str] = None) -> List[Dict]:
    """
    Queries the NVD CVE API for CVEs matching the keyword.
    Returns a list of parsed CVE dicts.
    """
    if not HTTPX_AVAILABLE:
        print("[CVE] httpx not available -- cannot query NVD API")
        return []

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": 20,
        "startIndex": 0,
    }
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        response = httpx.get(NVD_API_BASE, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        if response.status_code == 429:
            print("[CVE] NVD rate limit hit — backing off 35 seconds")
            time.sleep(35)
            response = httpx.get(NVD_API_BASE, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        data = response.json()
    except Exception as e:
        print(f"[CVE] NVD API request failed: {e}")
        return []

    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve_item = vuln.get("cve", {})
        cve_id = cve_item.get("id", "")

        # Extract CVSS score (prefer v3.1, fallback to v3.0, then v2)
        cvss_score = None
        severity = "Unknown"
        metrics = cve_item.get("metrics", {})
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity") or _cvss_to_severity(cvss_score)
                break

        # Description (English preferred)
        description = ""
        for desc in cve_item.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")[:500]
                break

        published_date = cve_item.get("published", "")[:10]  # yyyy-mm-dd

        cves.append({
            "cve_id": cve_id,
            "severity": severity,
            "cvss_score": cvss_score,
            "description": description,
            "published_date": published_date,
        })

    return cves


def check_cves(
    conn: sqlite3.Connection,
    device_id: int,
    vendor: str,
    firmware_version: Optional[str] = None,
    api_key: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Main entry point. Looks up CVEs for a device, using cache when available.
    Stores results in device_cves table.

    Returns list of CVE dicts.
    """
    # Build search keyword: vendor + firmware version for precision
    keyword_parts = [vendor.strip()] if vendor.strip() else []
    if firmware_version and firmware_version.strip():
        keyword_parts.append(firmware_version.strip())
    keyword = " ".join(keyword_parts)

    if not keyword:
        return []

    query_key = _build_query_key(vendor, firmware_version or "")

    # Try cache first
    cached = _get_cached(conn, query_key)
    if cached is not None:
        print(f"[CVE] Cache hit for '{keyword}' ({len(cached)} CVEs)")
        cves = cached
    else:
        print(f"[CVE] Fetching NVD for '{keyword}'")
        cves = _fetch_nvd(keyword, api_key=api_key)
        _save_cache(conn, query_key, cves)

    if not cves:
        return []

    # Persist to device_cves table (replace existing entries for this device)
    cursor = conn.cursor()
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("DELETE FROM device_cves WHERE device_id = ?", (device_id,))
    for cve in cves:
        cursor.execute(
            """INSERT INTO device_cves (device_id, cve_id, severity, cvss_score, description, published_date, last_checked)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (device_id, cve["cve_id"], cve["severity"], cve["cvss_score"],
             cve["description"], cve["published_date"], now_str)
        )
    conn.commit()

    return cves
