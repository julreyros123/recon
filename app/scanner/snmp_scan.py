"""
snmp_scan.py — SNMP v2c Device Enrichment Scanner

Queries devices using SNMPv2c to extract:
  - System description / firmware version heuristic
  - System name, location, contact
  - Security control hints (SSH/Telnet/HTTP port inference from open_ports)

Uses pysnmp (sync walk). Falls back gracefully if device doesn't respond.
Community string defaults to 'public' (read-only SNMPv2c).
"""
import re
import json
from typing import Dict, Any, Optional

# Standard SNMP OIDs (MIB-II system group)
OID_SYS_DESCR    = "1.3.6.1.2.1.1.1.0"  # sysDescr
OID_SYS_NAME     = "1.3.6.1.2.1.1.5.0"  # sysName
OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0"  # sysLocation
OID_SYS_CONTACT  = "1.3.6.1.2.1.1.4.0"  # sysContact

SNMP_TIMEOUT  = 2   # seconds per request
SNMP_RETRIES  = 0   # no retries — fast scan mode

try:
    from pysnmp.hlapi import (
        getCmd, SnmpEngine, CommunityData, UdpTransportTarget,
        ContextData, ObjectType, ObjectIdentity
    )
    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False


def _snmp_get(ip: str, community: str, oid: str) -> Optional[str]:
    """Fetches a single SNMP OID value from a device. Returns None on failure."""
    if not PYSNMP_AVAILABLE:
        return None
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community, mpModel=1),  # mpModel=1 -> SNMPv2c
            UdpTransportTarget((ip, 161), timeout=SNMP_TIMEOUT, retries=SNMP_RETRIES),
            ContextData(),
            ObjectType(ObjectIdentity(oid))
        )
        error_indication, error_status, error_index, var_binds = next(iterator)
        if error_indication or error_status:
            return None
        for name, val in var_binds:
            result = str(val)
            if result and result not in ("", "No Such Object currently exists at this OID"):
                return result
        return None
    except Exception:
        return None


def _infer_firmware_from_descr(sys_descr: str) -> Optional[str]:
    """
    Attempts to parse a firmware/OS version string from sysDescr.
    Examples:
      'Cisco IOS Software, Version 15.7(3)M4' -> '15.7(3)M4'
      'Linux 5.15.0-72-generic #79-Ubuntu SMP' -> '5.15.0-72-generic'
      'FortiGate-60F v7.2.4,build1396'         -> 'v7.2.4'
    """
    if not sys_descr:
        return None

    # Cisco IOS pattern
    m = re.search(r'Version\s+([\d\w\.\(\)]+)', sys_descr, re.IGNORECASE)
    if m:
        return m.group(1)

    # Linux kernel pattern
    m = re.search(r'Linux\s+([\d\.\w\-]+)', sys_descr)
    if m:
        return m.group(1)

    # FortiOS / generic vX.Y.Z pattern
    m = re.search(r'v(\d+\.\d+[\.\d]*)', sys_descr)
    if m:
        return "v" + m.group(1)

    # Generic: first version-like token
    m = re.search(r'(\d+\.\d+[\.\d\w\-]*)', sys_descr)
    if m:
        return m.group(1)

    return None


def _infer_security_controls(open_ports_json: Optional[str]) -> Dict[str, bool]:
    """
    Infers active management protocols from the device's open ports list.
    """
    controls = {
        "ssh_enabled": False,
        "telnet_enabled": False,
        "snmp_enabled": False,
        "http_mgmt_enabled": False,
    }
    if not open_ports_json:
        return controls

    try:
        ports = json.loads(open_ports_json)
        for entry in ports:
            port = entry.get("port")
            if port == 22:
                controls["ssh_enabled"] = True
            elif port == 23:
                controls["telnet_enabled"] = True
            elif port == 161:
                controls["snmp_enabled"] = True
            elif port in (80, 8080, 443, 8443):
                controls["http_mgmt_enabled"] = True
    except Exception:
        pass

    return controls


def enrich_device_via_snmp(
    ip: str,
    community: str = "public",
    open_ports_json: Optional[str] = None
) -> Dict[str, Any]:
    """
    Queries the target IP via SNMPv2c and returns a dict of enrichment fields
    ready to be merged into a device record.

    Always returns a dict (may be empty if SNMP is unavailable or device
    does not respond to SNMP queries).
    """
    result: Dict[str, Any] = {}

    if not PYSNMP_AVAILABLE:
        print(f"[SNMP] pysnmp not available -- skipping enrichment for {ip}")
        # Still infer security controls from port scan data
        controls = _infer_security_controls(open_ports_json)
        result.update(controls)
        return result

    # --- System MIB queries ---
    sys_descr    = _snmp_get(ip, community, OID_SYS_DESCR)
    sys_name     = _snmp_get(ip, community, OID_SYS_NAME)
    sys_location = _snmp_get(ip, community, OID_SYS_LOCATION)
    sys_contact  = _snmp_get(ip, community, OID_SYS_CONTACT)

    if not any([sys_descr, sys_name, sys_location, sys_contact]):
        # Device did not respond to SNMP -- not unusual, skip silently
        # but still infer controls from ports
        controls = _infer_security_controls(open_ports_json)
        result.update(controls)
        return result

    print(f"[SNMP] Enriched {ip}: sysName={sys_name!r}, sysLocation={sys_location!r}")

    if sys_name:
        result["hostname"] = sys_name
    if sys_location:
        result["site_location"] = sys_location
    if sys_contact:
        result["admin_contact"] = sys_contact
    if sys_descr:
        fw = _infer_firmware_from_descr(sys_descr)
        if fw:
            result["firmware_version"] = fw
        # Store first 200 chars of sysDescr as model hint
        result["model"] = sys_descr[:200]

    # --- Security controls from port scan ---
    controls = _infer_security_controls(open_ports_json)
    result.update(controls)

    return result

def fetch_snmp_telemetry(ip: str, community: str = "public") -> Optional[Dict[str, Any]]:
    """
    Attempts to fetch CPU, RAM, and Disk telemetry from a device via SNMP (UCD-SNMP-MIB).
    Returns a telemetry dictionary matching the agent's payload if successful.
    """
    if not PYSNMP_AVAILABLE:
        return None

    try:
        cpu_idle = _snmp_get(ip, community, "1.3.6.1.4.1.2021.11.11.0")
        mem_total = _snmp_get(ip, community, "1.3.6.1.4.1.2021.4.5.0")
        mem_avail = _snmp_get(ip, community, "1.3.6.1.4.1.2021.4.6.0")
        
        # If the device doesn't support these basic resource MIBs, abort telemetry
        if not mem_total:
            return None
            
        cpu_usage = 0.0
        if cpu_idle and cpu_idle.isdigit():
            cpu_usage = max(0.0, 100.0 - float(cpu_idle))
            
        ram_usage = 0.0
        if mem_total and mem_avail and mem_total.isdigit() and mem_avail.isdigit():
            mt = float(mem_total)
            ma = float(mem_avail)
            if mt > 0:
                ram_usage = round(100.0 * (mt - ma) / mt, 1)
                
        dsk_total = _snmp_get(ip, community, "1.3.6.1.4.1.2021.9.1.6.1")
        dsk_used = _snmp_get(ip, community, "1.3.6.1.4.1.2021.9.1.8.1")
        disk_usage = 0.0
        if dsk_total and dsk_used and dsk_total.isdigit() and dsk_used.isdigit():
            dt = float(dsk_total)
            du = float(dsk_used)
            if dt > 0:
                disk_usage = round(100.0 * du / dt, 1)

        sys_name = _snmp_get(ip, community, OID_SYS_NAME) or "SNMP-Device"
        sys_descr = _snmp_get(ip, community, OID_SYS_DESCR) or ""

        return {
            "ip": ip,
            "mac": "unknown", # The backend will coalesce this with the known MAC
            "hostname": sys_name,
            "cpu_usage": cpu_usage,
            "ram_usage": ram_usage,
            "disk_usage": disk_usage,
            "running_processes": [],
            "network_connections": [],
            "logged_in_users": [],
            "usb_devices": [],
            "os_info": sys_descr[:100]
        }
    except Exception:
        return None

