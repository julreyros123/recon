from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import json
import sqlite3
import datetime
from app.database.database import get_db_connection, get_db, log_audit_event
from app.routes.auth import get_current_user, RoleChecker
from app.scanner.anomaly_detector import analyze_telemetry
from app.routes.events import push_event

router = APIRouter()

# --- Request/Response Models ---

class TelemetryReport(BaseModel):
    ip: str = Field(..., description="IP Address of the workstation")
    mac: Optional[str] = Field(None, description="MAC Address of the workstation")
    hostname: Optional[str] = Field(None, description="Hostname of the workstation")
    cpu_usage: float = Field(0.0, description="CPU usage percentage")
    ram_usage: float = Field(0.0, description="RAM usage percentage")
    disk_usage: float = Field(0.0, description="Disk storage usage percentage")
    running_processes: List[Dict[str, Any]] = Field([], description="List of active processes")
    network_connections: List[Dict[str, Any]] = Field([], description="List of active network connections")
    logged_in_users: List[Dict[str, Any]] = Field([], description="List of logged-in sessions")
    usb_devices: List[Dict[str, Any]] = Field([], description="List of connected USB devices")
    os_info: Optional[str] = Field(None, description="OS distribution and version details")
    update_status: Optional[Dict[str, Any]] = Field(None, description="OS patch/update compliance status")

class AlertResolve(BaseModel):
    resolution_notes: str = Field(..., description="Notes on how the alert was investigated/fixed")

# --- Endpoints ---

def process_telemetry_report(report: TelemetryReport, db: sqlite3.Connection):
    """Internal function to process and store telemetry data from both local agents and agentless SNMP polls."""
    cursor = db.cursor()
    
    try:
        # 1. Identify or register the workstation device
        device_id = None
        cursor.execute("SELECT id, is_trusted, status, mac FROM devices WHERE mac = %s AND mac != 'unknown' AND mac != ''", (report.mac,))
        row = cursor.fetchone()
        
        if not row:
            # Fallback to IP search
            cursor.execute("SELECT id, is_trusted, status, mac FROM devices WHERE ip = %s", (report.ip,))
            row = cursor.fetchone()
            
        if row:
            device_id = row["id"]
            db_status = row["status"]
            db_mac = row["mac"]
            # If the device is isolated/blocked, don't override the status back to active,
            # but if it was unknown/inactive, set it to active
            new_status = db_status
            if db_status in ('unknown', 'inactive'):
                new_status = 'active'
                
            # If the MAC address is currently unknown/missing in DB but the agent reported a real one, update it
            mac_sql = ""
            params = [report.ip, report.hostname, new_status]
            if (not db_mac or db_mac == 'unknown' or db_mac == '') and report.mac and report.mac != 'unknown' and report.mac != '':
                mac_sql = ", mac = %s"
                params.append(report.mac)
                
            params.append(device_id)
            
            cursor.execute(
                f"UPDATE devices SET ip = %s, hostname = COALESCE(%s, hostname), status = %s, os_type = 'workstation', last_seen = CURRENT_TIMESTAMP {mac_sql} WHERE id = %s",
                tuple(params)
            )
        else:
            # Register brand new workstation
            cursor.execute(
                """INSERT INTO devices (ip, mac, hostname, vendor, status, os_type, is_trusted, trust_level, last_seen) 
                   VALUES (%s, %s, %s, 'Generic Workstation', 'active', 'workstation', 0, 'Unknown', CURRENT_TIMESTAMP)""",
                (report.ip, report.mac or "unknown", report.hostname or "unknown-workstation")
            )
            device_id = cursor.lastrowid
            
            # Log auto-discovery of workstation using active cursor
            cursor.execute(
                "INSERT INTO audit_logs (username, role, action, target, ip_address, details) VALUES ('system', 'system', 'REGISTER', %s, %s, %s)",
                (report.mac or report.ip, report.ip, f"Workstation agent auto-registered new device: {report.hostname or 'Unknown'} (IP: {report.ip})")
            )
            
        if device_id is None:
            raise Exception("Failed to identify or register workstation device.")
            
        # 2. Write telemetry report to database
        processes_str = json.dumps(report.running_processes)
        connections_str = json.dumps(report.network_connections)
        users_str = json.dumps(report.logged_in_users)
        usb_str = json.dumps(report.usb_devices)
        update_status_str = json.dumps(report.update_status) if report.update_status else None
        
        cursor.execute(
            """INSERT INTO workstation_telemetry (device_id, cpu_usage, ram_usage, disk_usage, running_processes, network_connections, logged_in_users, usb_devices, os_info, update_status)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (device_id, report.cpu_usage, report.ram_usage, report.disk_usage, processes_str, connections_str, users_str, usb_str, report.os_info, update_status_str)
        )
        
        # 3. Analyze Telemetry for Threats
        telemetry_dict = report.model_dump()
        detected_alerts = analyze_telemetry(device_id, telemetry_dict, db)
        
        alerts_created = 0
        for alert in detected_alerts:
            # Check if this alert is already outstanding (Unresolved) for this device
            cursor.execute(
                "SELECT id FROM workstation_alerts WHERE device_id = %s AND alert_type = %s AND title = %s AND status = 'Unresolved'",
                (device_id, alert["alert_type"], alert["title"])
            )
            if not cursor.fetchone():
                cursor.execute(
                    """INSERT INTO workstation_alerts (device_id, alert_type, severity, title, description, status)
                       VALUES (%s, %s, %s, %s, %s, 'Unresolved')""",
                    (device_id, alert["alert_type"], alert["severity"], alert["title"], alert["description"])
                )
                alerts_created += 1

                # SSE: broadcast security alert event in real-time
                push_event("security_alert", {
                    "device_id": device_id,
                    "hostname": report.hostname or report.ip,
                    "ip": report.ip,
                    "alert_type": alert["alert_type"],
                    "severity": alert["severity"],
                    "title": alert["title"],
                    "message": f"[{alert['severity']}] {alert['title']} on {report.hostname or report.ip}"
                })

                # Log security alert in audit trail using active cursor
                cursor.execute(
                    "INSERT INTO audit_logs (username, role, action, target, ip_address, details) VALUES ('system', 'system', 'POLICY', %s, %s, %s)",
                    (report.mac or report.ip, report.ip, f"SECURITY ALERT [{alert['severity']}]: {alert['title']} on host {report.hostname or 'Unknown'}")
                )
                
        db.commit()
        return {"status": "success", "device_id": device_id, "alerts_detected": len(detected_alerts), "alerts_created": alerts_created}
        
    except Exception as e:
        db.rollback()
        raise e

@router.post("/report")
def report_workstation_telemetry(report: TelemetryReport, db: sqlite3.Connection = Depends(get_db)):
    """
    Ingest point for the EDR agent running on monitored workstations.
    Saves state metrics and runs the heuristic threat detection engine.
    """
    try:
        return process_telemetry_report(report, db)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process workstation report: {e}")

@router.get("/monitored")
def get_monitored_workstations(current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    """
    Returns list of all devices classified as workstations with their monitoring status,
    latest basic utilization metrics, and count of outstanding security alerts.
    """
    cursor = db.cursor()
    
    # Select devices classified as workstations (restricted by ownership for staff role)
    if current_user.get("role") == "user":
        cursor.execute("SELECT full_name FROM employees WHERE user_id = (SELECT id FROM users WHERE username = %s)", (current_user["username"],))
        emp_row = cursor.fetchone()
        emp_name = emp_row["full_name"] if emp_row else current_user["username"]
        cursor.execute("SELECT * FROM devices WHERE os_type = 'workstation' AND owner_name = %s ORDER BY last_seen DESC", (emp_name,))
    else:
        cursor.execute("SELECT * FROM devices WHERE os_type = 'workstation' ORDER BY last_seen DESC")
    devices = [dict(row) for row in cursor.fetchall()]
    
    results = []
    for dev in devices:
        dev_id = dev["id"]
        
        # Fetch count of active (Unresolved) alerts
        cursor.execute("SELECT COUNT(*) FROM workstation_alerts WHERE device_id = %s AND status = 'Unresolved'", (dev_id,))
        active_alerts = cursor.fetchone()[0]
        
        # Fetch latest telemetry snapshot
        cursor.execute(
            """SELECT cpu_usage, ram_usage, disk_usage, timestamp, os_info 
               FROM workstation_telemetry 
               WHERE device_id = %s 
               ORDER BY timestamp DESC LIMIT 1""", 
            (dev_id,)
        )
        telemetry_row = cursor.fetchone()
        
        is_monitored = False
        agent_status = "Offline"
        latest_utilization = {"cpu": 0.0, "ram": 0.0, "disk": 0.0}
        os_info = "Unknown"
        last_contact = None
        
        if telemetry_row:
            is_monitored = True
            latest_utilization = {
                "cpu": telemetry_row["cpu_usage"],
                "ram": telemetry_row["ram_usage"],
                "disk": telemetry_row["disk_usage"] if "disk_usage" in telemetry_row.keys() else 0.0
            }
            os_info = telemetry_row["os_info"] or "Unknown"
            last_contact = telemetry_row["timestamp"]

            # Check if any telemetry arrived in the last 25 seconds — agent is Online
            cursor.execute(
                "SELECT 1 FROM workstation_telemetry WHERE device_id = %s AND timestamp > datetime('now', '-25 seconds')",
                (dev_id,)
            )
            if cursor.fetchone():
                agent_status = "Online"
                
        results.append({
            "id": dev_id,
            "ip": dev["ip"],
            "mac": dev["mac"],
            "hostname": dev["hostname"],
            "status": dev["status"],
            "is_trusted": bool(dev["is_trusted"]),
            "trust_level": dev["trust_level"],
            "is_monitored": is_monitored,
            "agent_status": agent_status,
            "os_info": os_info,
            "latest_utilization": latest_utilization,
            "active_alerts_count": active_alerts,
            "last_contact": last_contact or dev["last_seen"]
        })
        
    return results

@router.get("/alerts")
def get_workstation_alerts(device_id: Optional[int] = None, unresolved_only: bool = True, skip: int = 0, limit: int = 100, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    """
    Retrieves all workstation security threat alerts.
    """
    cursor = db.cursor()
    
    query = """
        SELECT wa.*, d.hostname, d.ip, d.mac
        FROM workstation_alerts wa
        JOIN devices d ON wa.device_id = d.id
    """
    params = []
    filters = []
    
    if device_id is not None:
        if current_user.get("role") == "user":
            cursor.execute("SELECT full_name FROM employees WHERE user_id = (SELECT id FROM users WHERE username = %s)", (current_user["username"],))
            emp_row = cursor.fetchone()
            emp_name = emp_row["full_name"] if emp_row else current_user["username"]
            cursor.execute("SELECT owner_name FROM devices WHERE id = %s", (device_id,))
            dev_row = cursor.fetchone()
            if not dev_row or dev_row["owner_name"] != emp_name:
                raise HTTPException(status_code=403, detail="Operation not permitted for this user role")
        filters.append("wa.device_id = ?")
        params.append(device_id)
        
    if unresolved_only:
        filters.append("wa.status = 'Unresolved'")
        
    if current_user.get("role") == "user":
        cursor.execute("SELECT full_name FROM employees WHERE user_id = (SELECT id FROM users WHERE username = %s)", (current_user["username"],))
        emp_row = cursor.fetchone()
        emp_name = emp_row["full_name"] if emp_row else current_user["username"]
        filters.append("d.owner_name = ?")
        params.append(emp_name)
        
    if filters:
        query += " WHERE " + " AND ".join(filters)
        
    query += " ORDER BY wa.timestamp DESC LIMIT %s OFFSET %s"
    params.extend([limit, skip])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

@router.post("/alerts/{alert_id}/resolve")
def resolve_workstation_alert(alert_id: int, resolution: AlertResolve, current_user: dict = Depends(RoleChecker(["super_admin", "operator"])), db: sqlite3.Connection = Depends(get_db)):
    """
    Resolves an open threat alert, logging administrative notes and audit trailing.
    """
    cursor = db.cursor()
    
    cursor.execute("""
        SELECT wa.*, d.hostname, d.ip, d.mac 
        FROM workstation_alerts wa 
        JOIN devices d ON wa.device_id = d.id 
        WHERE wa.id = %s
    """, (alert_id,))
    row = cursor.fetchone()
    
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    username = current_user["username"]
    
    try:
        cursor.execute(
            """UPDATE workstation_alerts 
               SET status = 'Resolved', resolved_by = %s, resolution_notes = %s, date_resolved = %s 
               WHERE id = %s""",
            (username, resolution.resolution_notes, now_str, alert_id)
        )
        db.commit()
        
        # Log to audit trail
        log_audit_event(
            username=username,
            role=current_user["role"],
            action="POLICY",
            target=row["mac"] or row["ip"],
            ip_address="127.0.0.1",
            details=f"Resolved alert '{row['title']}' on workstation {row['hostname'] or 'Unknown'}. Notes: {resolution.resolution_notes}"
        )
        
        return {"status": "success", "alert_id": alert_id, "resolved_by": username, "date_resolved": now_str}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to resolve alert: {e}")

@router.get("/{device_id}/telemetry")
def get_workstation_detail_telemetry(device_id: int, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    """
    Returns the latest complete telemetry snapshot (processes, connections, usb, logged-in sessions)
    as well as recent CPU/RAM utilization log data for visualization.
    """
    cursor = db.cursor()
    
    # Check ownership for staff role
    if current_user.get("role") == "user":
        cursor.execute("SELECT full_name FROM employees WHERE user_id = (SELECT id FROM users WHERE username = %s)", (current_user["username"],))
        emp_row = cursor.fetchone()
        emp_name = emp_row["full_name"] if emp_row else current_user["username"]
        cursor.execute("SELECT owner_name FROM devices WHERE id = %s", (device_id,))
        dev_row = cursor.fetchone()
        if not dev_row or dev_row["owner_name"] != emp_name:
            raise HTTPException(status_code=403, detail="Operation not permitted for this user role")

    # 1. Fetch latest full telemetry
    cursor.execute(
        "SELECT * FROM workstation_telemetry WHERE device_id = %s ORDER BY timestamp DESC LIMIT 1",
        (device_id,)
    )
    row = cursor.fetchone()
    
    # 2. Fetch resource history (last 15 points)
    cursor.execute(
        """SELECT cpu_usage, ram_usage, timestamp 
           FROM workstation_telemetry 
           WHERE device_id = %s 
           ORDER BY timestamp DESC LIMIT 15""",
        (device_id,)
    )
    history_rows = cursor.fetchall()
    utilization_history = [
        {
            "cpu": r["cpu_usage"],
            "ram": r["ram_usage"],
            "timestamp": r["timestamp"]
        } for r in reversed(history_rows)
    ]
    
    if not row:
        return {
            "device_id": device_id,
            "has_telemetry": False,
            "latest": None,
            "history": []
        }
        
    try:
        update_status = json.loads(row["update_status"]) if row["update_status"] else None
    except Exception:
        update_status = None

    return {
        "device_id": device_id,
        "has_telemetry": True,
        "latest": {
            "timestamp": row["timestamp"],
            "cpu_usage": row["cpu_usage"],
            "ram_usage": row["ram_usage"],
            "disk_usage": row["disk_usage"] if "disk_usage" in row.keys() else 0.0,
            "os_info": row["os_info"],
            "update_status": update_status,
            "running_processes": processes,
            "network_connections": connections,
            "logged_in_users": users,
            "usb_devices": usbs
        },
        "history": utilization_history
    }

@router.post("/{device_id}/isolate")
def isolate_workstation(device_id: int, current_user: dict = Depends(RoleChecker(["super_admin", "operator"])), db: sqlite3.Connection = Depends(get_db)):
    """
    Simulates Network Access Control (NAC) isolation of a workstation.
    Flags status as 'Blocked' and is_trusted as 0.
    """
    cursor = db.cursor()
    
    cursor.execute("SELECT hostname, ip, mac, status FROM devices WHERE id = %s", (device_id,))
    row = cursor.fetchone()
    
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
        
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    username = current_user["username"]
    
    try:
        cursor.execute(
            """UPDATE devices 
               SET status = 'Blocked', is_trusted = 0, trust_level = 'Blocked', last_seen = CURRENT_TIMESTAMP 
               WHERE id = %s""",
            (device_id,)
        )
        db.commit()
        
        # Log to audit trail
        log_audit_event(
            username=username,
            role=current_user["role"],
            action="POLICY",
            target=row["mac"] or row["ip"],
            ip_address="127.0.0.1",
            details=f"ISOLATED WORKSTATION: Network Access Blocked for {row['hostname'] or 'Unknown'} (IP: {row['ip']})"
        )
        
        return {"status": "success", "message": f"Workstation {row['hostname']} successfully isolated from network.", "device_id": device_id}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to isolate host: {e}")
