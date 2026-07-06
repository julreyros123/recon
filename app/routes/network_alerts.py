from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from typing import List, Optional
import sqlite3
import datetime
from app.database.database import get_db, log_audit_event
from app.routes.auth import get_current_user, RoleChecker
from app.scanner.network_sniffer import sniffer

router = APIRouter()

class AlertResolve(BaseModel):
    resolution_notes: str = Field(..., description="Notes on how the alert was investigated/fixed")

@router.get("/")
def get_network_alerts(unresolved_only: bool = True, skip: int = 0, limit: int = 100, current_user: dict = Depends(get_current_user), db: sqlite3.Connection = Depends(get_db)):
    """Retrieves all infrastructure-level network security threat alerts."""
    cursor = db.cursor()
    
    query = "SELECT * FROM network_alerts"
    filters = []
    params = []
    
    if unresolved_only:
        filters.append("status = 'Unresolved'")
        
    if filters:
        query += " WHERE " + " AND ".join(filters)
        
    query += " ORDER BY timestamp DESC LIMIT %s OFFSET %s"
    params.extend([limit, skip])
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    return [dict(row) for row in rows]

@router.post("/{alert_id}/resolve")
def resolve_network_alert(alert_id: int, resolution: AlertResolve, current_user: dict = Depends(RoleChecker(["super_admin", "operator"])), db: sqlite3.Connection = Depends(get_db)):
    """Resolves an open network threat alert."""
    cursor = db.cursor()
    
    cursor.execute("SELECT * FROM network_alerts WHERE id = %s", (alert_id,))
    row = cursor.fetchone()
    
    if not row:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    now_str = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    username = current_user["username"]
    
    try:
        cursor.execute(
            """UPDATE network_alerts 
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
            target=row["source_ip"],
            ip_address="127.0.0.1",
            details=f"Resolved network alert '{row['title']}'. Notes: {resolution.resolution_notes}"
        )
        
        return {"status": "success", "alert_id": alert_id, "resolved_by": username, "date_resolved": now_str}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Failed to resolve alert: {e}")

# --- SIMULATION ENDPOINTS ---

@router.post("/simulate/arp-spoof")
def simulate_arp_spoof(current_user: dict = Depends(RoleChecker(["super_admin", "operator"]))):
    """Simulates an ARP spoofing attack for demonstration purposes."""
    sniffer.trigger_alert(
        alert_type="ARP_SPOOF",
        severity="Critical",
        title="ARP Poisoning Detected (Simulated)",
        description="Conflicting MAC address for Gateway IP 192.168.1.1. Known MAC: 00:11:22:33:44:55, New MAC: DE:AD:BE:EF:CA:FE",
        source_ip="192.168.1.1",
        source_mac="DE:AD:BE:EF:CA:FE"
    )
    return {"status": "success", "message": "ARP Spoof alert generated."}

@router.post("/simulate/dhcp-spoof")
def simulate_dhcp_spoof(current_user: dict = Depends(RoleChecker(["super_admin", "operator"]))):
    """Simulates a rogue DHCP server attack for demonstration purposes."""
    sniffer.trigger_alert(
        alert_type="DHCP_SPOOF",
        severity="Critical",
        title="Rogue DHCP Server Detected (Simulated)",
        description="Unauthorized DHCP Offer received from unknown server IP.",
        source_ip="192.168.1.250",
        source_mac="FE:DC:BA:98:76:54"
    )
    return {"status": "success", "message": "DHCP Spoof alert generated."}

@router.post("/simulate/mac-spoof")
def simulate_mac_spoof(current_user: dict = Depends(RoleChecker(["super_admin", "operator"]))):
    """Simulates MAC spoofing / impossible travel for demonstration purposes."""
    sniffer.trigger_alert(
        alert_type="MAC_SPOOF",
        severity="High",
        title="MAC Address Spoofing Detected (Simulated)",
        description="Device MAC address changed but hostname and OS fingerprint remained identical, indicating possible spoofing.",
        source_ip="192.168.1.101",
        source_mac="AA:BB:CC:DD:EE:FF"
    )
    return {"status": "success", "message": "MAC Spoof alert generated."}

@router.post("/simulate/ip-spoof")
def simulate_ip_spoof(current_user: dict = Depends(RoleChecker(["super_admin", "operator"]))):
    """Simulates IP spoofing anomaly detection for demonstration purposes."""
    sniffer.trigger_alert(
        alert_type="IP_SPOOF",
        severity="High",
        title="Potential IP Spoofing (Simulated)",
        description="Traffic carrying internal RFC1918 source IP arrived on an external ingress interface.",
        source_ip="192.168.1.55",
        source_mac="unknown"
    )
    return {"status": "success", "message": "IP Spoof alert generated."}
