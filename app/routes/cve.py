"""
cve.py — CVE Vulnerability REST Endpoints

Routes:
  GET  /api/cve/{device_id}        — Returns stored CVEs for a device
  GET  /api/cve/summary            — Returns CVE counts by severity across all devices
  POST /api/cve/{device_id}/check  — Triggers on-demand NVD lookup for a device
"""
import sqlite3
from fastapi import APIRouter, HTTPException, Depends, BackgroundTasks
from app.database.database import get_db, get_db_connection
from app.routes.auth import get_current_user, RoleChecker
from app.scanner.cve_checker import check_cves

router = APIRouter()


@router.get("/summary")
def get_cve_summary(
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    """Returns aggregate CVE counts across all devices, grouped by severity."""
    cursor = db.cursor()
    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM device_cves
        GROUP BY severity
        ORDER BY count DESC
    """)
    rows = cursor.fetchall()
    severity_counts = {r["severity"]: r["count"] for r in rows}

    # Total unique devices with at least one CVE
    cursor.execute("SELECT COUNT(DISTINCT device_id) as count FROM device_cves")
    devices_with_cves = cursor.fetchone()["count"]

    # Top 5 most vulnerable devices
    cursor.execute("""
        SELECT d.id, d.hostname, d.ip, d.vendor, COUNT(dc.id) as cve_count,
               MAX(dc.cvss_score) as max_cvss
        FROM device_cves dc
        JOIN devices d ON dc.device_id = d.id
        GROUP BY dc.device_id
        ORDER BY max_cvss DESC, cve_count DESC
        LIMIT 5
    """)
    top_vulnerable = [dict(r) for r in cursor.fetchall()]

    return {
        "severity_counts": severity_counts,
        "devices_with_cves": devices_with_cves,
        "top_vulnerable_devices": top_vulnerable,
    }


@router.get("/{device_id}")
def get_device_cves(
    device_id: int,
    current_user: dict = Depends(get_current_user),
    db: sqlite3.Connection = Depends(get_db)
):
    """Returns all stored CVEs for a specific device."""
    cursor = db.cursor()

    # Confirm device exists
    cursor.execute("SELECT id, hostname, ip, vendor, firmware_version FROM devices WHERE id = %s", (device_id,))
    device = cursor.fetchone()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    cursor.execute(
        "SELECT * FROM device_cves WHERE device_id = %s ORDER BY cvss_score DESC",
        (device_id,)
    )
    cves = [dict(r) for r in cursor.fetchall()]

    return {
        "device_id": device_id,
        "hostname": device["hostname"],
        "ip": device["ip"],
        "vendor": device["vendor"],
        "firmware_version": device["firmware_version"],
        "cve_count": len(cves),
        "cves": cves,
    }


@router.post("/{device_id}/check")
def trigger_cve_check(
    device_id: int,
    background_tasks: BackgroundTasks,
    current_user: dict = Depends(RoleChecker(["super_admin", "operator"])),
    db: sqlite3.Connection = Depends(get_db)
):
    """
    Triggers an on-demand NVD CVE lookup for a specific device.
    Runs in background to avoid blocking the request.
    """
    cursor = db.cursor()
    cursor.execute("SELECT id, hostname, ip, vendor, firmware_version FROM devices WHERE id = %s", (device_id,))
    device = cursor.fetchone()
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    vendor          = device["vendor"] or ""
    firmware        = device["firmware_version"] or ""
    hostname        = device["hostname"] or device["ip"]

    if not vendor:
        raise HTTPException(
            status_code=400,
            detail="Device has no vendor information — cannot perform CVE lookup. Set vendor first."
        )

    def _run_check():
        conn = get_db_connection()
        try:
            cves = check_cves(conn, device_id=device_id, vendor=vendor, firmware_version=firmware)
            print(f"[CVE] Check complete for {hostname}: {len(cves)} CVEs found")
        except Exception as e:
            print(f"[CVE] Background check failed for device {device_id}: {e}")
        finally:
            conn.close()

    background_tasks.add_task(_run_check)

    return {
        "status": "queued",
        "device_id": device_id,
        "hostname": hostname,
        "vendor": vendor,
        "firmware_version": firmware,
        "message": f"CVE check initiated for {hostname}. Results will be stored in /api/cve/{device_id}."
    }
