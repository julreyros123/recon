import threading
import time
import datetime
import sqlite3
from typing import Optional
from app.database.database import get_db_connection
from app.routes.events import push_event

try:
    from scapy.all import sniff, ARP, DHCP, BOOTP, Ether, IP  # type: ignore[import-untyped]
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Scapy is not installed. Real-time packet sniffing is disabled.")

class NetworkSniffer:
    def __init__(self):
        self.running = False
        self.thread = None
        self.known_arp_mappings = {} # ip -> mac
        self.authorized_dhcp_servers = ["192.168.1.1"] # Example baseline

    def start(self):
        if not SCAPY_AVAILABLE:
            print("Cannot start NetworkSniffer without Scapy.")
            return
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._sniff_loop, daemon=True)
        self.thread.start()
        print("NetworkSniffer started in background.")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)

    def _sniff_loop(self):
        # We use a filter to only capture ARP and UDP 67/68 (DHCP) to keep CPU low
        try:
            sniff(filter="arp or (udp and (port 67 or port 68))", prn=self._process_packet, stop_filter=lambda x: not self.running, store=False)
        except Exception as e:
            print(f"Network sniffer error: {e}")

    def _process_packet(self, packet):
        try:
            # 1. ARP Spoofing Detection
            if packet.haslayer(ARP):
                if packet[ARP].op == 2: # ARP Reply
                    ip = packet[ARP].psrc
                    mac = packet[ARP].hwsrc
                    
                    if ip in self.known_arp_mappings:
                        if self.known_arp_mappings[ip] != mac:
                            # MAC changed for this IP! Possible ARP spoofing
                            self.trigger_alert(
                                alert_type="ARP_SPOOF",
                                severity="Critical",
                                title="ARP Poisoning Detected",
                                description=f"Conflicting MAC address for IP {ip}. Known MAC: {self.known_arp_mappings[ip]}, New MAC: {mac}",
                                source_ip=ip,
                                source_mac=mac
                            )
                    else:
                        self.known_arp_mappings[ip] = mac

            # 2. DHCP Spoofing Detection
            if packet.haslayer(DHCP) and packet.haslayer(BOOTP):
                # DHCP Offer message type is usually 2
                dhcp_options = packet[DHCP].options
                message_type = next((opt[1] for opt in dhcp_options if opt[0] == 'message-type'), None)
                
                if message_type == 2: # DHCP OFFER
                    server_ip = packet[IP].src
                    server_mac = packet[Ether].src
                    if server_ip not in self.authorized_dhcp_servers:
                        self.trigger_alert(
                            alert_type="DHCP_SPOOF",
                            severity="Critical",
                            title="Rogue DHCP Server Detected",
                            description=f"Unauthorized DHCP Offer received from IP {server_ip} (MAC: {server_mac}).",
                            source_ip=server_ip,
                            source_mac=server_mac
                        )
        except Exception as e:
            pass # Ignore packet parsing errors to prevent thread crash

    def trigger_alert(self, alert_type: str, severity: str, title: str, description: str, source_ip: str, source_mac: str):
        conn = get_db_connection()
        try:
            cursor = conn.cursor()
            
            five_min_ago = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("""
                SELECT id FROM network_alerts 
                WHERE alert_type = ? AND source_ip = ? AND source_mac = ? AND status = 'Unresolved'
                AND timestamp > ?
            """, (alert_type, source_ip, source_mac, five_min_ago))
            if cursor.fetchone():
                return
                
            cursor.execute("""
                INSERT INTO network_alerts (alert_type, severity, title, description, source_ip, source_mac)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (alert_type, severity, title, description, source_ip, source_mac))
            conn.commit()
            
            push_event("network_alert", {
                "alert_type": alert_type,
                "severity": severity,
                "title": title,
                "description": description,
                "source_ip": source_ip,
                "source_mac": source_mac
            })
            
            cursor.execute(
                "INSERT INTO audit_logs (username, role, action, target, ip_address, details) VALUES (?, ?, ?, ?, ?, ?)",
                ("system", "system", "SECURITY_ALERT", source_ip, "127.0.0.1", f"[{severity}] {title}: {description}")
            )
            conn.commit()
        except Exception as e:
            print(f"Failed to record network alert: {e}")
        finally:
            conn.close()

# Global instance for the app
sniffer = NetworkSniffer()
