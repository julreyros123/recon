import json
import sqlite3
from typing import List, Dict, Any

SUSPICIOUS_PROCESSES = {
    "mimikatz.exe": ("Critical", "Mimikatz Credential Dumper Detected", "Mimikatz is an open-source tool used to dump credentials, passwords, PINs, and Kerberos tickets from memory."),
    "mimikatz": ("Critical", "Mimikatz Credential Dumper Detected", "Mimikatz tool or script execution detected."),
    "pypykatz": ("Critical", "PyPyKatz Credential Dumper Detected", "Python implementation of Mimikatz credentials harvester detected."),
    "nc.exe": ("High", "Netcat Backdoor Tool Detected", "Netcat is a utility used for reading/writing network connections, often used to establish unauthorized reverse shells."),
    "nc": ("High", "Netcat Utility Detected", "Netcat execution detected."),
    "netcat": ("High", "Netcat Utility Detected", "Netcat execution detected."),
    "nmap.exe": ("Medium", "Nmap Network Scanner Detected", "Nmap network mapper utility detected on a workstation, indicating unauthorized network scanning."),
    "nmap": ("Medium", "Nmap Network Scanner Detected", "Nmap network mapper utility detected on a workstation, indicating unauthorized network scanning."),
    "wireshark.exe": ("Medium", "Wireshark Packet Sniffer Detected", "Wireshark network analyzer utility detected, indicating potential packet sniffing and traffic capture."),
    "tshark": ("Medium", "TShark Packet Sniffer Detected", "Command-line packet sniffer utility detected."),
    "responder": ("High", "LLMNR/NBT-NS Poisoning Tool (Responder)", "Responder tool detected, which poisons LLMNR, NBT-NS, and MDNS traffic to harvest credentials."),
    "hydra": ("High", "Hydra Brute Force Tool", "Hydra network login hacking tool detected."),
    "john.exe": ("High", "John the Ripper Password Cracker", "Password cracker utility detected."),
    "john": ("High", "John the Ripper Password Cracker", "Password cracker utility detected."),
    "metasploit": ("Critical", "Metasploit Framework Activity", "Metasploit penetration testing framework process or file detected.")
}

SUSPICIOUS_COMMANDS = [
    ("-encodedcommand", "Critical", "Powershell Encoded Command Execution", "Obfuscated powershell command execution utilizing Base64 encoded payload, typical of script-based malware load."),
    ("-enc", "Critical", "Powershell Encoded Command Execution", "Obfuscated powershell command execution utilizing Base64 encoded payload, typical of script-based malware load."),
    ("vssadmin.exe delete shadows", "Critical", "Volume Shadow Copy Deletion", "Command to delete volume shadow copies, which is a key technique used by ransomware to prevent file recovery."),
    ("vssadmin delete shadows", "Critical", "Volume Shadow Copy Deletion", "Command to delete volume shadow copies, which is a key technique used by ransomware to prevent file recovery."),
    ("shadowcopy delete", "Critical", "Volume Shadow Copy Deletion", "Command to delete volume shadow copies, which is a key technique used by ransomware to prevent file recovery."),
    ("mimikatz", "Critical", "Mimikatz Arguments Detected", "Command line invocation containing credential dumping parameters."),
    ("reverse_shell", "High", "Potential Reverse Shell Script", "Command line arguments suggest interactive remote shell spawn."),
    ("downloadstring", "High", "PowerShell Fileless Malware Download", "PowerShell download code execution command (DownloadString), indicating fileless remote code launch."),
    ("invoke-expression", "High", "PowerShell Expression Execution", "PowerShell Expression execution command (IEX), commonly used to execute files downloaded directly to memory.")
]

SUSPICIOUS_PORTS = {
    4444: ("Critical", "Metasploit Default Connection", "Active network connection to port 4444, which is the default port used by Metasploit payloads for reverse shells."),
    31337: ("Critical", "BackOrifice Backdoor Connection", "Active network connection to port 31337, associated with the classic BackOrifice backdoor/trojan."),
    6667: ("High", "IRC Botnet Connection", "Outbound connection to IRC port 6667, commonly used by legacy command-and-control botnets."),
    5555: ("High", "Suspicious Shell Port", "Active network connection on port 5555, commonly used by Trojans and root shells."),
    9999: ("High", "Suspicious Shell Port", "Active network connection on port 9999, commonly used by backdoors.")
}

def analyze_telemetry(device_id: int, telemetry: Dict[str, Any], conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """
    Analyzes workstation telemetry data for indicators of compromise (IoCs) and anomalies.
    Returns a list of alert dictionaries to be written to the database.
    """
    alerts = []

    # 1. Resource Utilization Checks
    cpu = telemetry.get("cpu_usage", 0.0)
    ram = telemetry.get("ram_usage", 0.0)

    if cpu > 90.0:
        # Check if running processes include a cryptominer
        is_miner = False
        procs = telemetry.get("running_processes", [])
        for p in procs:
            p_name = p.get("name", "").lower()
            if "xmrig" in p_name or "miner" in p_name or "cryptonight" in p_name:
                is_miner = True
                break
        
        if is_miner:
            alerts.append({
                "device_id": device_id,
                "alert_type": "resource",
                "severity": "High",
                "title": "Cryptomining Process Running",
                "description": f"High CPU utilization ({cpu}%) with known cryptomining processes detected in execution queue."
            })
        else:
            alerts.append({
                "device_id": device_id,
                "alert_type": "resource",
                "severity": "Medium",
                "title": "Abnormally High CPU Load",
                "description": f"CPU utilization is spiked at {cpu}%. Continuous high resource usage can indicate active malware infections, cryptojacking, or system abuse."
            })

    if ram > 90.0:
        alerts.append({
            "device_id": device_id,
            "alert_type": "resource",
            "severity": "Low",
            "title": "Abnormally High Memory Usage",
            "description": f"Workstation RAM consumption is at {ram}%, which may cause denial of service (DoS) or performance degradation."
        })

    # 2. Suspicious Process Check
    running_processes = telemetry.get("running_processes", [])
    for proc in running_processes:
        p_name = proc.get("name", "")
        p_cmd = proc.get("command_line", "")
        
        # Check process name matches
        p_name_lower = p_name.lower()
        if p_name_lower in SUSPICIOUS_PROCESSES:
            severity, title, desc = SUSPICIOUS_PROCESSES[p_name_lower]
            alerts.append({
                "device_id": device_id,
                "alert_type": "process",
                "severity": severity,
                "title": title,
                "description": f"{desc} (Process: {p_name}, PID: {proc.get('pid')})"
            })
            continue

        # Check command line matches
        p_cmd_lower = p_cmd.lower()
        for cmd_pattern, severity, title, desc in SUSPICIOUS_COMMANDS:
            if cmd_pattern in p_cmd_lower:
                alerts.append({
                    "device_id": device_id,
                    "alert_type": "process",
                    "severity": severity,
                    "title": title,
                    "description": f"{desc} (Process: {p_name}, Command: {p_cmd})"
                })
                break

    # 3. Suspicious Network Socket Check
    network_connections = telemetry.get("network_connections", [])
    for conn_data in network_connections:
        r_port = conn_data.get("remote_port")
        l_port = conn_data.get("local_port")
        state = conn_data.get("state", "").upper()
        
        # Check against suspicious ports
        if r_port in SUSPICIOUS_PORTS:
            severity, title, desc = SUSPICIOUS_PORTS[r_port]
            alerts.append({
                "device_id": device_id,
                "alert_type": "network",
                "severity": severity,
                "title": title,
                "description": f"{desc} (Connection: {conn_data.get('local_ip')}:{l_port} -> {conn_data.get('remote_ip')}:{r_port}, State: {state})"
            })
        elif l_port in SUSPICIOUS_PORTS and state == "LISTEN":
            severity, title, desc = SUSPICIOUS_PORTS[l_port]
            alerts.append({
                "device_id": device_id,
                "alert_type": "network",
                "severity": severity,
                "title": f"Local Listener on {title.split(' ')[0]} Port",
                "description": f"The workstation is listening locally on port {l_port}, which is associated with malicious tools. Details: {desc}"
            })

    # 4. USB Device Connection Check
    usb_devices = telemetry.get("usb_devices", [])
    for usb in usb_devices:
        desc = usb.get("description", "")
        desc_lower = desc.lower()
        
        # Check for badUSB or hacking hardware
        if "rubber ducky" in desc_lower or "hak5" in desc_lower or "bash bunny" in desc_lower:
            alerts.append({
                "device_id": device_id,
                "alert_type": "usb",
                "severity": "Critical",
                "title": "Malicious Key Injector USB Connected",
                "description": f"A keystroke injector hacking device ({desc}) has been detected connected to the workstation. This is an active intrusion attempt."
            })
        elif "usb mass storage" in desc_lower or "sandisk" in desc_lower or "kingston" in desc_lower or "cruzer" in desc_lower or "usb drive" in desc_lower or "external drive" in desc_lower:
            # Generate a medium severity warning alert for data exfiltration risk
            alerts.append({
                "device_id": device_id,
                "alert_type": "usb",
                "severity": "Medium",
                "title": "Unauthorized USB Storage Connection",
                "description": f"An unauthorized USB storage drive ({desc}) was connected to the workstation, creating a risk of data exfiltration or malware propagation."
            })

    # 5. User Login/Session Checks
    logged_in_users = telemetry.get("logged_in_users", [])
    if len(logged_in_users) > 3:
        alerts.append({
            "device_id": device_id,
            "alert_type": "login",
            "severity": "Low",
            "title": "Multiple Active Sessions",
            "description": f"There are {len(logged_in_users)} active user sessions concurrent on this workstation, which may indicate compromise or credential sharing."
        })
        
    for user in logged_in_users:
        usr_name = user.get("username", "").lower()
        sess_type = user.get("session_type", "").lower()
        if usr_name == "administrator" and ("rdp" in sess_type or "remote" in sess_type):
            alerts.append({
                "device_id": device_id,
                "alert_type": "login",
                "severity": "High",
                "title": "Remote Administrator Login Alert",
                "description": f"Remote connection (RDP/SSH) detected using the default local Administrator account. Admin access should be restricted to user-linked personal accounts."
            })

    # Deduplicate alerts that may be generated in the same telemetry sweep (e.g. duplicate processes or sockets)
    unique_alerts = []
    seen_keys = set()
    for alert in alerts:
        key = (alert["alert_type"], alert["title"])
        if key not in seen_keys:
            seen_keys.add(key)
            unique_alerts.append(alert)

    return unique_alerts
