from fastapi import APIRouter, Depends
from app.database.database import get_db
import sqlite3
from app.routes.auth import get_current_user
import json

router = APIRouter()

@router.get("/stats")
def get_dashboard_stats(
    current_user: dict = Depends(get_current_user),
    conn: sqlite3.Connection = Depends(get_db)
):
    """Returns aggregate statistics for the admin dashboard charts."""
    try:
        cursor = conn.cursor()

        # 1. Device counts by trust level
        cursor.execute("""
            SELECT trust_level, COUNT(*) as count
            FROM devices
            GROUP BY trust_level
        """)
        trust_rows = cursor.fetchall()
        trust_counts = {"Trusted": 0, "Unknown": 0, "Blocked": 0, "Pending": 0}
        for row in trust_rows:
            lvl = row["trust_level"] or "Unknown"
            if lvl in trust_counts:
                trust_counts[lvl] = row["count"]
            else:
                trust_counts["Unknown"] += row["count"]

        # 2. Device counts by department
        cursor.execute("""
            SELECT COALESCE(department, 'Unassigned') as dept, COUNT(*) as count
            FROM devices
            GROUP BY dept
            ORDER BY count DESC
        """)
        dept_rows = cursor.fetchall()
        dept_labels = [r["dept"] for r in dept_rows]
        dept_values = [r["count"] for r in dept_rows]

        # 3. Device counts by OS/type
        cursor.execute("""
            SELECT COALESCE(os_type, 'generic') as os_type, COUNT(*) as count
            FROM devices
            GROUP BY os_type
            ORDER BY count DESC
        """)
        os_rows = cursor.fetchall()
        os_labels = [r["os_type"] for r in os_rows]
        os_values = [r["count"] for r in os_rows]

        # 4. Total devices and active count
        cursor.execute("SELECT COUNT(*) as total FROM devices")
        total_devices = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as active FROM devices WHERE status = 'active'")
        active_devices = cursor.fetchone()["active"]

        # 5. Active unresolved workstation alerts
        cursor.execute("""
            SELECT COUNT(*) as count FROM workstation_alerts
            WHERE status = 'Unresolved'
        """)
        active_alerts = cursor.fetchone()["count"]

        # 6. Scan report counts for last 7 days
        cursor.execute("""
            SELECT DATE(timestamp) as scan_date, COUNT(*) as count
            FROM reports
            WHERE timestamp >= DATE('now', '-7 days')
            GROUP BY scan_date
            ORDER BY scan_date ASC
        """)
        scan_rows = cursor.fetchall()
        scan_dates = [r["scan_date"] for r in scan_rows]
        scan_counts = [r["count"] for r in scan_rows]

        # 7. Last scan timestamp
        cursor.execute("SELECT timestamp FROM reports ORDER BY timestamp DESC LIMIT 1")
        last_scan_row = cursor.fetchone()
        last_scan = last_scan_row["timestamp"] if last_scan_row else None

        # 8. Trusted percentage
        trusted_pct = round((trust_counts["Trusted"] / total_devices * 100), 1) if total_devices > 0 else 0.0

        return {
            "total_devices": total_devices,
            "active_devices": active_devices,
            "active_alerts": active_alerts,
            "trusted_percent": trusted_pct,
            "last_scan": last_scan,
            "trust_distribution": trust_counts,
            "department_distribution": {
                "labels": dept_labels,
                "values": dept_values
            },
            "os_distribution": {
                "labels": os_labels,
                "values": os_values
            },
            "scan_history": {
                "dates": scan_dates,
                "counts": scan_counts
            }
        }
    finally:
        pass
