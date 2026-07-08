from fastapi import APIRouter, HTTPException, BackgroundTasks, Depends
from app.models.device import Device, DeviceCreate, DeviceUpdate
from app.database.database import get_db_connection, get_db, log_audit_event
from app.scanner.network_scan import run_scan, run_port_scan, run_os_detection
from app.scanner.snmp_scan import enrich_device_via_snmp
from app.routes.events import push_event
import sqlite3
from app.routes.auth import get_current_user, RoleChecker
from typing import List, Optional
import json
import datetime
import re

router = APIRouter()

ALLOWED_UPDATE_FIELDS = {
    "hostname", "vendor", "status", "open_ports", "os_type", "is_trusted",
    "owner_name", "department", "purpose", "trust_level", "registered_by",
    "date_registered", "serial_number", "model", "firmware_version",
    "latest_firmware", "firmware_eol", "warranty_expiry", "purchase_date",
    "vlan", "switch_port", "site_location", "rack_position", "admin_contact",
    "ssh_enabled", "telnet_enabled", "snmp_enabled", "http_mgmt_enabled",
    "mfa_enforced", "local_users", "baseline_os", "current_os"
}

def _build_safe_update_query(data: dict, allowed_fields: set) -> tuple:
    if not data:
        return "", []
    query_parts = []
    params = []
    for key, val in data.items():
        if key not in allowed_fields:
            continue
        if key == "is_trusted":
            query_parts.append("is_trusted = ?")
            params.append(int(val))
        elif key == "date_registered" and val is not None:
            query_parts.append("date_registered = ?")
            params.append(val.strftime("%Y-%m-%d %H:%M:%S") if isinstance(val, datetime.datetime) else str(val))
        else:
            query_parts.append(f"{key} = ?")
            params.append(val)
    if not query_parts:
        return "", []
    return f"SET {', '.join(query_parts)}", params

def _sanitize_string_for_sql(value: str, max_len: int = 1024) -> str:
    if not value:
        return value
    return str(value)[:max_len]

@router.get("/", response_model=List[Device])
def list_devices(skip: int = 0, limit: int = 1000, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    if current_user.get("role") == "user":
        cursor.execute("SELECT full_name FROM employees WHERE user_id = (SELECT id FROM users WHERE username = ?)", (current_user["username"],))
        emp_row = cursor.fetchone()
        emp_name = emp_row["full_name"] if emp_row else current_user["username"]
        cursor.execute("SELECT * FROM devices WHERE owner_name = ? ORDER BY last_seen DESC LIMIT ? OFFSET ?", (emp_name, limit, skip))
    else:
        cursor.execute("SELECT * FROM devices ORDER BY last_seen DESC LIMIT ? OFFSET ?", (limit, skip))
        
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

@router.get("/{device_id}", response_model=Device)
def get_device(device_id: int, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
        
    if current_user.get("role") == "user":
        cursor.execute("SELECT full_name FROM employees WHERE user_id = (SELECT id FROM users WHERE username = ?)", (current_user["username"],))
        emp_row = cursor.fetchone()
        emp_name = emp_row["full_name"] if emp_row else current_user["username"]
        if row["owner_name"] != emp_name:
            raise HTTPException(status_code=403, detail="Operation not permitted for this user role")
        
    return dict(row)

@router.post("/", response_model=Device)
def create_device(device: DeviceCreate, current_user: dict = Depends(RoleChecker(["super_admin", "operator"])), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    trust_lvl = device.trust_level or ("Trusted" if device.is_trusted else "Unknown")
    registered_by = device.registered_by or current_user["username"]
    date_reg = device.date_registered or (datetime.datetime.now(datetime.timezone.utc) if device.is_trusted else None)
    try:
        cursor.execute(
            "INSERT INTO devices (ip, mac, hostname, vendor, status, open_ports, os_type, is_trusted, owner_name, department, purpose, trust_level, registered_by, date_registered) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (device.ip, device.mac, device.hostname, device.vendor, device.status, device.open_ports, device.os_type, int(device.is_trusted), device.owner_name, device.department, device.purpose, trust_lvl, registered_by, date_reg)
        )
        db.commit()
        device_id = cursor.lastrowid
        
        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="REGISTER",
            target=device.mac or device.ip,
            ip_address="127.0.0.1",
            details=f"Manually registered device {device.hostname or 'Unknown'} with IP {device.ip}"
        )
        
        cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
        row = cursor.fetchone()
        return dict(row)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail="Device creation failed")

@router.put("/{device_id}", response_model=Device)
def update_device(device_id: int, device: DeviceUpdate, current_user: dict = Depends(RoleChecker(["super_admin", "operator"])), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    
    cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
        
    update_data = device.model_dump(exclude_unset=True)
    if not update_data:
        return dict(row)
        
    if "is_trusted" in update_data and "trust_level" not in update_data:
        update_data["trust_level"] = "Trusted" if update_data["is_trusted"] else "Pending"
    
    if update_data.get("trust_level") == "Trusted" and not row["registered_by"]:
        update_data["registered_by"] = current_user["username"]
        update_data["date_registered"] = datetime.datetime.now(datetime.timezone.utc)
    
    set_clause, params = _build_safe_update_query(update_data, ALLOWED_UPDATE_FIELDS)
    if not set_clause:
        return dict(row)
    
    params.append(device_id)
    query = f"UPDATE devices {set_clause}, last_seen = CURRENT_TIMESTAMP WHERE id = ?"
    
    try:
        cursor.execute(query, params)
        db.commit()
        
        update_fields = list(update_data.keys())
        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="UPDATE",
            target=row["mac"] or row["ip"],
            ip_address="127.0.0.1",
            details=f"Updated device metadata: {', '.join(update_fields)} for {row['hostname'] or 'Unknown'}"
        )
        
        cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
        row = cursor.fetchone()
        return dict(row)
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=400, detail="Device update failed")

@router.delete("/{device_id}")
def delete_device(device_id: int, current_user: dict = Depends(RoleChecker(["super_admin"])), db: sqlite3.Connection = Depends(get_db)):
    try:
        cursor = db.cursor()
        cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Device not found")
            
        cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
        cursor.execute(
            "INSERT INTO audit_logs (username, role, action, target, ip_address, details) VALUES (?, ?, 'DELETE', ?, '127.0.0.1', ?)",
            (current_user["username"], current_user["role"], row["mac"] or row["ip"], f"Deleted device {row['hostname'] or 'Unknown'} (IP: {row['ip']})")
        )
        db.commit()
        return {"message": "Device deleted successfully"}
    except Exception as e:
        db.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Failed to delete device")

def execute_background_scan(subnet: Optional[str] = None):
    scan_result = run_scan(subnet)
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        
        cursor.execute("SELECT ip, mac, hostname, status FROM devices")
        old_devices = {row["ip"]: dict(row) for row in cursor.fetchall()}
        
        active_count = 0
        total_count = len(scan_result["devices"])
        scanned_ips = set()
        
        for dev in scan_result["devices"]:
            ip = dev["ip"]
            scanned_ips.add(ip)
            
            if dev["status"] == "active":
                active_count += 1
                
            if ip in old_devices:
                old_dev = old_devices[ip]
                changes = []
                
                if old_dev["status"] != dev["status"]:
                    changes.append(f"status: {old_dev['status']} -> {dev['status']}")
                    
                new_mac = dev.get("mac")
                if new_mac and old_dev["mac"] != new_mac and new_mac != "unknown":
                    changes.append(f"MAC: {old_dev['mac']} -> {new_mac}")
                    
                new_hn = dev.get("hostname")
                if new_hn and old_dev["hostname"] != new_hn:
                    changes.append(f"hostname: {old_dev['hostname']} -> {new_hn}")
                    
                old_ports = old_dev.get("open_ports")
                new_ports = dev.get("open_ports")
                if new_ports and old_ports != new_ports:
                    try:
                        old_p_list = [p["port"] for p in json.loads(old_ports)] if old_ports else []
                        new_p_list = [p["port"] for p in json.loads(new_ports)]
                        new_opened = set(new_p_list) - set(old_p_list)
                        if new_opened:
                            changes.append(f"new ports: {list(new_opened)}")
                            cursor.execute(
                                "INSERT INTO network_alerts (alert_type, severity, title, description, source_ip, source_mac) VALUES (?, ?, ?, ?, ?, ?)",
                                ('ANOMALOUS_NETWORK', 'Medium', 'Anomalous Port Opened', f"Device unexpectedly opened new ports: {list(new_opened)}", ip, dev.get("mac", "unknown"))
                            )
                            push_event("network_alert", {
                                "alert_type": "ANOMALOUS_NETWORK",
                                "severity": "Medium",
                                "title": "Anomalous Port Opened",
                                "description": f"Device {ip} unexpectedly opened new ports: {list(new_opened)}",
                                "source_ip": ip,
                                "source_mac": dev.get("mac", "unknown")
                            })
                    except Exception:
                        pass
                
                if changes:
                    cursor.execute(
                        "INSERT INTO audit_logs (username, role, action, target, ip_address, details) VALUES ('system', 'system', 'UPDATE', ?, '127.0.0.1', ?)",
                        (dev.get("mac") or ip, f"Scan detected changes on device at {ip}: {', '.join(changes)}")
                    )
                    
                detected_os = dev.get("current_os") or ""
                cursor.execute("""
                    UPDATE devices SET
                        mac = COALESCE(?, mac),
                        hostname = COALESCE(?, hostname),
                        vendor = COALESCE(?, vendor),
                        status = ?,
                        open_ports = COALESCE(?, open_ports),
                        os_type = COALESCE(?, os_type),
                        current_os = CASE WHEN ? != '' THEN ? ELSE current_os END,
                        last_seen = CURRENT_TIMESTAMP
                    WHERE ip = ?
                """, (dev.get("mac"), dev.get("hostname"), dev.get("vendor"), dev["status"],
                      dev.get("open_ports"), dev.get("os_type"),
                      detected_os, detected_os, ip))
                
            else:
                cursor.execute(
                    "INSERT INTO audit_logs (username, role, action, target, ip_address, details) VALUES ('system', 'system', 'REGISTER', ?, '127.0.0.1', ?)",
                    (dev.get("mac") or ip, f"New device auto-discovered on network scan: {dev.get('hostname') or 'Unknown'} (IP: {ip})")
                )
                
                cursor.execute(
                    "INSERT INTO network_alerts (alert_type, severity, title, description, source_ip, source_mac) VALUES (?, ?, ?, ?, ?, ?)",
                    ('UNKNOWN_DEVICE', 'Low', 'Untrusted Device Connected', f"A new, unregistered device connected to the network (Hostname: {dev.get('hostname', 'Unknown')}).", ip, dev.get("mac", "unknown"))
                )
                push_event("network_alert", {
                    "alert_type": "UNKNOWN_DEVICE",
                    "severity": "Low",
                    "title": "Untrusted Device Connected",
                    "description": f"A new, unregistered device connected to the network (Hostname: {dev.get('hostname', 'Unknown')}).",
                    "source_ip": ip,
                    "source_mac": dev.get("mac", "unknown")
                })
                
                detected_os = run_os_detection(ip)

                cursor.execute("""
                    INSERT INTO devices (ip, mac, hostname, vendor, status, open_ports, os_type,
                                        is_trusted, trust_level, baseline_os, current_os, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, 0, 'Unknown', ?, ?, CURRENT_TIMESTAMP)
                """, (ip, dev.get("mac"), dev.get("hostname"), dev.get("vendor"),
                      dev["status"], dev.get("open_ports"), dev.get("os_type"),
                      detected_os or None, detected_os or None))

                push_event("new_device", {
                    "ip": ip,
                    "mac": dev.get("mac"),
                    "hostname": dev.get("hostname") or "Unknown",
                    "vendor": dev.get("vendor") or "Unknown",
                    "os_type": dev.get("os_type") or "generic",
                    "message": f"New unregistered device detected: {dev.get('hostname') or ip}"
                })

        for dev in scan_result["devices"]:
            if dev["status"] != "active":
                continue
            ip = dev["ip"]
            cursor.execute("SELECT id, open_ports FROM devices WHERE ip = ?", (ip,))
            db_row = cursor.fetchone()
            if not db_row:
                continue
            dev_id   = db_row["id"]
            op_json  = db_row["open_ports"]
            enriched = enrich_device_via_snmp(ip, open_ports_json=op_json)
            if enriched:
                set_clauses = []
                params      = []
                cursor.execute(
                    "SELECT firmware_version, model, site_location, admin_contact, "
                    "ssh_enabled, telnet_enabled, snmp_enabled, http_mgmt_enabled FROM devices WHERE id = ?",
                    (dev_id,)
                )
                existing = cursor.fetchone()
                for field, value in enriched.items():
                    if field in ("hostname", "site_location", "admin_contact", "firmware_version", "model"):
                        if existing and existing[field] if field in existing.keys() else True:
                            if not (existing and field in existing.keys() and existing[field]):
                                set_clauses.append(f"{field} = ?")
                                params.append(value)
                    else:
                        set_clauses.append(f"{field} = ?")
                        params.append(1 if value else 0)
                if set_clauses:
                    params.append(dev_id)
                    cursor.execute(
                        f"UPDATE devices SET {', '.join(set_clauses)} WHERE id = ?",
                        params
                    )

        for old_ip, old_dev in old_devices.items():
            if old_ip not in scanned_ips and old_dev["status"] == "active":
                cursor.execute("UPDATE devices SET status = 'inactive', last_seen = CURRENT_TIMESTAMP WHERE ip = ?", (old_ip,))
                
                cursor.execute(
                    "INSERT INTO audit_logs (username, role, action, target, ip_address, details) VALUES ('system', 'system', 'UPDATE', ?, '127.0.0.1', ?)",
                    (old_dev["mac"] or old_ip, f"Device {old_dev['hostname'] or 'Unknown'} went offline (status changed: active -> inactive)")
                )

                push_event("device_offline", {
                    "ip": old_ip,
                    "mac": old_dev.get("mac"),
                    "hostname": old_dev.get("hostname") or "Unknown",
                    "message": f"Device {old_dev.get('hostname') or old_ip} went offline"
                })

        summary = f"Completed {scan_result['scan_method']} scan on {scan_result['subnet']}. Duration: {scan_result['duration_seconds']}s."
        cursor.execute(
            "INSERT INTO reports (devices_found, active_devices, scan_duration_secs, summary) VALUES (?, ?, ?, ?)",
            (total_count, active_count, scan_result["duration_seconds"], summary)
        )
        
        cursor.execute(
            "INSERT INTO audit_logs (username, role, action, target, ip_address, details) VALUES ('system', 'system', 'SCAN', ?, '127.0.0.1', ?)",
            (subnet or "192.168.1.0/24", f"Automated background scan completed on {subnet or '192.168.1.0/24'}. Found {total_count} devices, {active_count} active.")
        )
        
        conn.commit()

        push_event("scan_complete", {
            "subnet": scan_result["subnet"],
            "total_found": total_count,
            "active_count": active_count,
            "duration_seconds": scan_result["duration_seconds"],
            "message": f"Scan complete on {scan_result['subnet']}: {total_count} devices ({active_count} active)"
        })
    except Exception as e:
        conn.rollback()
        print(f"Error during execute_background_scan: {e}")
    finally:
        conn.close()

@router.post("/scan")
def trigger_scan(background_tasks: BackgroundTasks, subnet: Optional[str] = None, current_user: dict = Depends(RoleChecker(["super_admin", "operator"]))):
    if subnet:
        cidr_pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
        if not re.match(cidr_pattern, subnet):
            raise HTTPException(status_code=400, detail="Invalid subnet format. Use CIDR notation like 192.168.1.0/24")
    
    log_audit_event(
        username=current_user["username"],
        role=current_user["role"],
        action="SCAN",
        target=subnet or "192.168.1.0/24",
        ip_address="127.0.0.1",
        details=f"Triggered manual network scan on {subnet or '192.168.1.0/24'}"
    )
    background_tasks.add_task(execute_background_scan, subnet)
    return {"message": "Scan initiated in background. Check /reports or list devices for updates."}

@router.post("/{device_id}/scan-ports")
async def scan_device_ports(device_id: int, current_user: dict = Depends(RoleChecker(["super_admin", "operator"])), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT ip, hostname, mac FROM devices WHERE id = ?", (device_id,))
    row = cursor.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")
    
    ip = row["ip"]
    try:
        open_ports = await run_port_scan(ip)
        
        open_ports_str = json.dumps(open_ports)
        
        cursor.execute(
            "UPDATE devices SET open_ports = ?, last_seen = CURRENT_TIMESTAMP WHERE id = ?",
            (open_ports_str, device_id)
        )
        db.commit()
        
        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="SCAN",
            target=row["mac"] or ip,
            ip_address="127.0.0.1",
            details=f"Completed port scan on device {row['hostname'] or 'Unknown'} (IP: {ip})"
        )
        
        return {"device_id": device_id, "ip": ip, "open_ports": open_ports}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Port scan failed")

@router.post("/{device_id}/toggle-trust")
def toggle_device_trust(device_id: int, current_user: dict = Depends(RoleChecker(["super_admin", "operator"])), db: sqlite3.Connection = Depends(get_db)):
    try:
        cursor = db.cursor()
        cursor.execute("SELECT mac, ip, hostname, is_trusted FROM devices WHERE id = ?", (device_id,))
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Device not found")
            
        new_state = 1 if row["is_trusted"] == 0 else 0
        new_trust_level = "Trusted" if new_state == 1 else "Pending"
        now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        registered_by = current_user["username"]
        
        cursor.execute(
            "UPDATE devices SET is_trusted = ?, trust_level = ?, registered_by = ?, date_registered = ? WHERE id = ?",
            (new_state, new_trust_level, registered_by, now_str, device_id)
        )
        cursor.execute(
            "INSERT INTO audit_logs (username, role, action, target, ip_address, details) VALUES (?, ?, 'POLICY', ?, '127.0.0.1', ?)",
            (current_user["username"], current_user["role"], row["mac"] or row["ip"], f"Toggled device trust state to {new_trust_level} for {row['hostname'] or 'Unknown'}")
        )
        db.commit()
        return {"device_id": device_id, "is_trusted": bool(new_state), "trust_level": new_trust_level}
    except Exception as e:
        db.rollback()
        if isinstance(e, HTTPException):
            raise e
        raise HTTPException(status_code=500, detail="Failed to toggle device trust")

@router.post("/clear")
def clear_all_devices(current_user: dict = Depends(RoleChecker(["super_admin"])), db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    try:
        cursor.execute("DELETE FROM devices")
        db.commit()
        log_audit_event(
            username=current_user["username"],
            role=current_user["role"],
            action="DELETE",
            target="all_devices",
            ip_address="127.0.0.1",
            details="Cleared all registered and discovered devices from the database."
        )
        return {"message": "All devices cleared successfully."}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail="Database clear failed")