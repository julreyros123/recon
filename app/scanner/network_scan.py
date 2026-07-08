import socket
import time
import subprocess
import defusedxml.ElementTree as ET
import json
import asyncio
import re
from typing import List, Dict, Any, Optional

def is_valid_ip_or_cidr(val: str) -> bool:
    """Strictly validates an IP address or CIDR to prevent command injection."""
    # Match standard IPv4 or CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)
    pattern = r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$"
    return bool(re.match(pattern, val))

def get_local_ip() -> str:
    """Retrieves the system's local IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Doesn't even need to be reachable
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_subnet(ip: str) -> str:
    """Deduces the subnet prefix (assumes /24 for simplicity)."""
    parts = ip.split('.')
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "192.168.1.0/24"

def classify_device(hostname: str, vendor: str, open_ports: List[Dict[str, Any]]) -> str:
    """Classifies a device type based on hostname, vendor, and open ports."""
    hn = (hostname or "").lower()
    vnd = (vendor or "").lower()
    
    # 1. Vendor check
    if "cisco" in vnd or "ubiquiti" in vnd or "linksys" in vnd or "netgear" in vnd or "tp-link" in vnd:
        return "router"
    if "dell" in vnd or "supermicro" in vnd or "hp enterprise" in vnd:
        return "server"
    if "samsung" in vnd or "lg" in vnd or "sony" in vnd:
        return "smart-tv"
    if "epson" in vnd or "canon" in vnd or "hp" in vnd and ("printer" in hn or "laserjet" in hn):
        return "printer"
    if "apple" in vnd:
        if "iphone" in hn or "ipad" in hn:
            return "mobile"
        return "workstation"
        
    # 2. Hostname check
    if "router" in hn or "gateway" in hn or "switch" in hn or "firewall" in hn:
        return "router"
    if "server" in hn or "nas" in hn or "ubuntu" in hn or "debian" in hn or "proxmox" in hn or "ldap" in hn or "dns" in hn:
        return "server"
    if "tv" in hn or "display" in hn or "kodi" in hn:
        return "smart-tv"
    if "printer" in hn or "copier" in hn:
        return "printer"
    if "phone" in hn or "mobile" in hn or "android" in hn:
        return "mobile"
        
    # 3. Port check
    ports = [p.get("port") for p in open_ports if isinstance(p, dict)]
    if 53 in ports or 161 in ports:  # DNS, SNMP
        return "router"
    if 9100 in ports or 631 in ports or 515 in ports:  # Printing protocols
        return "printer"
    if 8080 in ports or 8443 in ports or 3389 in ports:
        return "workstation"
        
    return "workstation" if hn else "generic"

def run_os_detection(ip: str) -> str:
    """Runs nmap OS fingerprinting on a single IP and returns a human-readable OS string.
    Requires nmap with root/admin privileges for raw socket access."""
    if not is_valid_ip_or_cidr(ip):
        return ""
    try:
        result = subprocess.run(
            ["nmap", "-O", "--osscan-guess", "--max-retries", "2", "-oX", "-", ip],
            capture_output=True, text=True, timeout=30
        )
        root = ET.fromstring(result.stdout)
        host_node = root.find("host")
        if host_node is None:
            return ""
        os_node = host_node.find("os")
        if os_node is None:
            return ""
        # Pick the best match (highest accuracy)
        best_match = None
        best_accuracy = 0
        for osmatch in os_node.findall("osmatch"):
            accuracy = int(osmatch.get("accuracy", "0"))
            if accuracy > best_accuracy:
                best_accuracy = accuracy
                best_match = osmatch.get("name", "")
        return best_match or ""
    except Exception as e:
        print(f"[OS Detection] Failed for {ip}: {e}")
        return ""

def scan_network_nmap(ip_range: str) -> List[Dict[str, Any]]:
    """Scan the network using Nmap ping sweep with XML parsing."""
    if not is_valid_ip_or_cidr(ip_range):
        raise ValueError(f"Invalid IP range provided: {ip_range}")
        
    print(f"Starting Nmap scan on range: {ip_range}")
    
    # Run: nmap -sn -oX - <ip_range>
    # -sn: Ping scan (Host discovery)
    # -oX -: Output XML format to stdout
    result = subprocess.run(
        ["nmap", "-sn", "-oX", "-", ip_range],
        capture_output=True,
        text=True,
        check=True
    )
    
    # Parse Nmap XML output
    root = ET.fromstring(result.stdout)
    devices = []
    
    for host in root.findall("host"):
        # Check if host is up
        status_node = host.find("status")
        if status_node is None or status_node.get("state") != "up":
            continue
            
        ip = None
        mac = None
        vendor = None
        
        # Extract addresses
        for addr in host.findall("address"):
            addrtype = addr.get("addrtype")
            if addrtype == "ipv4":
                ip = addr.get("addr")
            elif addrtype == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor")
                
        if not ip:
            continue
            
        # Extract hostname
        hostname = None
        hostnames_node = host.find("hostnames")
        if hostnames_node is not None:
            hn_nodes = hostnames_node.findall("hostname")
            if hn_nodes:
                hostname = hn_nodes[0].get("name")
                
        if not hostname:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = f"device-{ip.replace('.', '-')}"
                
        devices.append({
            "ip": ip,
            "mac": mac or "unknown",
            "hostname": hostname,
            "vendor": vendor or "Unknown Vendor",
            "status": "active",
            "open_ports": "[]" # Initial placeholder
        })
        
    return devices

async def run_port_scan(ip: str) -> List[Dict[str, Any]]:
    """Runs a fast Nmap port scan asynchronously on a single IP and parses open ports."""
    if not is_valid_ip_or_cidr(ip):
        raise ValueError(f"Invalid IP address provided: {ip}")

    print(f"Starting async Nmap port scan on host: {ip}")
    try:
        # Run nmap -F -oX - <ip>
        # -F: Fast scan mode (scans top 100 ports)
        # -oX -: Output XML format to stdout
        process = await asyncio.create_subprocess_exec(
            "nmap", "-F", "-oX", "-", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        if process.returncode != 0:
            raise Exception(f"Nmap failed with error: {stderr.decode()}")
            
        root = ET.fromstring(stdout.decode())
        open_ports = []
        
        host_node = root.find("host")
        if host_node is not None:
            ports_node = host_node.find("ports")
            if ports_node is not None:
                for port_node in ports_node.findall("port"):
                    state_node = port_node.find("state")
                    if state_node is not None and state_node.get("state") == "open":
                        port_id_raw = port_node.get("portid")
                        if port_id_raw is not None:
                            port_id = int(port_id_raw)
                            protocol = port_node.get("protocol")
                            
                            service_name = "unknown"
                            service_node = port_node.find("service")
                            if service_node is not None:
                                service_name = service_node.get("name", "unknown")
                                
                            open_ports.append({
                                "port": port_id,
                                "protocol": protocol,
                                "service": service_name
                            })
        return open_ports
    except Exception as e:
        print(f"Nmap port scan failed for {ip}: {e}")
        return []

def run_scan(subnet: Optional[str] = None) -> Dict[str, Any]:
    """Runs the network scan, measuring duration and returning device results."""
    if not subnet:
        local_ip = get_local_ip()
        subnet = get_subnet(local_ip)
    
    start_time = time.time()
    devices = []
    scan_method = "nmap"
    
    try:
        devices = scan_network_nmap(subnet)
    except Exception as e:
        print(f"Nmap scan failed. Error: {e}")
        devices = []
        
    duration = round(time.time() - start_time, 2)
    
    # Auto-classify device types and write initial open ports array
    for dev in devices:
        if "open_ports" not in dev or not dev["open_ports"]:
            dev["open_ports"] = "[]"
        if "os_type" not in dev or dev["os_type"] == "generic":
            try:
                ports_list = json.loads(dev["open_ports"])
            except Exception:
                ports_list = []
            dev["os_type"] = classify_device(dev.get("hostname", ""), dev.get("vendor", ""), ports_list)
            
    return {
        "timestamp": time.time(),
        "subnet": subnet,
        "scan_method": scan_method,
        "duration_seconds": duration,
        "devices": devices
    }
