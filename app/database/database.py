import os
import hashlib
import secrets
import datetime
import sqlite3
from dotenv import load_dotenv

from app.utils.encryption import encrypt_pii

load_dotenv()

DB_PATH = os.getenv("DB_PATH", "recon_nds.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def get_db():
    conn = get_db_connection()
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass

import bcrypt

def hash_password(password: str, salt: bytes | None = None) -> str:
    pwd_bytes = password.encode('utf-8')
    salt_bytes = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt_bytes).decode('utf-8')

def verify_password(password: str, stored_hash: str) -> bool:
    try:
        if not stored_hash:
            return False
        pwd_bytes = password.encode('utf-8')
        hash_bytes = stored_hash.encode('utf-8')
        return bcrypt.checkpw(pwd_bytes, hash_bytes)
    except Exception:
        return False

ALLOWED_TABLES = {"devices", "users", "employees", "workspaces", "workspace_devices", "reports", "audit_logs", "workstation_telemetry", "workstation_alerts", "network_alerts", "cve_cache", "device_cves"}
ALLOWED_COLUMNS = {
    "devices": {"id", "ip", "mac", "hostname", "vendor", "status", "last_seen", "open_ports", "os_type", "is_trusted", "owner_name", "department", "purpose", "trust_level", "registered_by", "date_registered", "serial_number", "model", "firmware_version", "latest_firmware", "firmware_eol", "warranty_expiry", "purchase_date", "vlan", "switch_port", "site_location", "rack_position", "admin_contact", "ssh_enabled", "telnet_enabled", "snmp_enabled", "http_mgmt_enabled", "mfa_enforced", "local_users", "baseline_os", "current_os"},
    "users": {"id", "username", "email", "full_name", "role", "is_active", "password_hash", "login_attempts", "locked_until", "super_admin_pin_hash", "last_login", "allowed_ip"},
    "employees": {"id", "user_id", "employee_id", "full_name", "position", "department", "email", "phone", "date_hired", "is_active", "created_by", "date_created"},
    "workspaces": {"id", "name", "description", "location", "created_by", "date_created"},
    "workspace_devices": {"id", "workspace_id", "device_id", "added_by", "date_added"},
    "reports": {"id", "timestamp", "devices_found", "active_devices", "scan_duration_secs", "summary"},
    "audit_logs": {"id", "timestamp", "username", "role", "action", "target", "ip_address", "details"},
    "workstation_telemetry": {"id", "device_id", "timestamp", "cpu_usage", "ram_usage", "disk_usage", "running_processes", "network_connections", "logged_in_users", "usb_devices", "os_info"},
    "workstation_alerts": {"id", "device_id", "timestamp", "alert_type", "severity", "title", "description", "status", "resolved_by", "resolution_notes", "date_resolved"},
    "network_alerts": {"id", "timestamp", "alert_type", "severity", "title", "description", "source_ip", "source_mac", "status", "resolved_by", "resolution_notes", "date_resolved"},
    "cve_cache": {"id", "query_key", "cve_data", "fetched_at"},
    "device_cves": {"id", "device_id", "cve_id", "severity", "cvss_score", "description", "published_date", "last_checked"}
}

def _add_column_if_missing(cursor, table: str, col: str, definition: str):
    if table not in ALLOWED_TABLES or col not in ALLOWED_COLUMNS.get(table, set()):
        return
    cursor.execute(f"PRAGMA table_info({table})")
    columns = [row[1] for row in cursor.fetchall()]
    if col not in columns:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {definition}")

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE NOT NULL,
            mac TEXT,
            hostname TEXT,
            vendor TEXT,
            status TEXT DEFAULT 'unknown',
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            open_ports TEXT,
            os_type TEXT DEFAULT 'generic',
            is_trusted INTEGER DEFAULT 0,
            owner_name TEXT,
            department TEXT,
            purpose TEXT,
            trust_level TEXT DEFAULT 'Unknown',
            registered_by TEXT,
            date_registered DATETIME,
            serial_number TEXT,
            model TEXT,
            firmware_version TEXT,
            latest_firmware TEXT,
            firmware_eol INTEGER DEFAULT 0,
            warranty_expiry TEXT,
            purchase_date TEXT,
            vlan TEXT,
            switch_port TEXT,
            site_location TEXT,
            rack_position TEXT,
            admin_contact TEXT,
            ssh_enabled INTEGER DEFAULT 0,
            telnet_enabled INTEGER DEFAULT 0,
            snmp_enabled INTEGER DEFAULT 0,
            http_mgmt_enabled INTEGER DEFAULT 0,
            mfa_enforced INTEGER DEFAULT 0,
            local_users TEXT,
            baseline_os TEXT,
            current_os TEXT
        )
    """)
    
    for col, defn in [
        ("open_ports",        "TEXT"),
        ("os_type",           "TEXT DEFAULT 'generic'"),
        ("is_trusted",        "INTEGER DEFAULT 0"),
        ("owner_name",        "TEXT"),
        ("department",        "TEXT"),
        ("purpose",           "TEXT"),
        ("trust_level",       "TEXT DEFAULT 'Unknown'"),
        ("registered_by",     "TEXT"),
        ("date_registered",   "DATETIME"),
        ("serial_number",     "TEXT"),
        ("model",             "TEXT"),
        ("firmware_version",  "TEXT"),
        ("latest_firmware",   "TEXT"),
        ("firmware_eol",      "INTEGER DEFAULT 0"),
        ("warranty_expiry",   "TEXT"),
        ("purchase_date",     "TEXT"),
        ("vlan",              "TEXT"),
        ("switch_port",       "TEXT"),
        ("site_location",     "TEXT"),
        ("rack_position",     "TEXT"),
        ("admin_contact",     "TEXT"),
        ("ssh_enabled",       "INTEGER DEFAULT 0"),
        ("telnet_enabled",    "INTEGER DEFAULT 0"),
        ("snmp_enabled",      "INTEGER DEFAULT 0"),
        ("http_mgmt_enabled", "INTEGER DEFAULT 0"),
        ("mfa_enforced",      "INTEGER DEFAULT 0"),
        ("local_users",       "TEXT"),
        ("baseline_os",       "TEXT"),
        ("current_os",        "TEXT"),
    ]:
        _add_column_if_missing(cursor, "devices", col, defn)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT,
            full_name TEXT,
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1,
            password_hash TEXT,
            login_attempts INTEGER DEFAULT 0,
            locked_until DATETIME,
            super_admin_pin_hash TEXT,
            last_login DATETIME,
            allowed_ip TEXT DEFAULT '*'
        )
    """)
    
    for col, defn in [
        ("full_name",            "TEXT"),
        ("login_attempts",       "INTEGER DEFAULT 0"),
        ("locked_until",         "DATETIME"),
        ("super_admin_pin_hash", "TEXT"),
        ("last_login",           "DATETIME"),
        ("password_hash",        "TEXT"),
        ("allowed_ip",           "TEXT DEFAULT '*'"),
    ]:
        _add_column_if_missing(cursor, "users", col, defn)
    
    cursor.execute("UPDATE users SET role = 'super_admin' WHERE role = 'administrator'")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            employee_id TEXT UNIQUE,
            full_name TEXT NOT NULL,
            position TEXT,
            department TEXT,
            email TEXT,
            phone TEXT,
            date_hired TEXT,
            is_active INTEGER DEFAULT 1,
            created_by TEXT,
            date_created DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workspaces (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            location TEXT,
            created_by TEXT,
            date_created DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workspace_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            workspace_id INTEGER NOT NULL,
            device_id INTEGER NOT NULL,
            added_by TEXT,
            date_added DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE (workspace_id, device_id),
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
            FOREIGN KEY (device_id)   REFERENCES devices(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            devices_found INTEGER,
            active_devices INTEGER,
            scan_duration_secs REAL,
            summary TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            username TEXT,
            role TEXT,
            action TEXT,
            target TEXT,
            ip_address TEXT,
            details TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workstation_telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            cpu_usage REAL,
            ram_usage REAL,
            disk_usage REAL DEFAULT 0.0,
            running_processes TEXT,
            network_connections TEXT,
            logged_in_users TEXT,
            usb_devices TEXT,
            os_info TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        )
    """)
    _add_column_if_missing(cursor, "workstation_telemetry", "disk_usage", "REAL DEFAULT 0.0")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workstation_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            alert_type TEXT,
            severity TEXT,
            title TEXT,
            description TEXT,
            status TEXT DEFAULT 'Unresolved',
            resolved_by TEXT,
            resolution_notes TEXT,
            date_resolved DATETIME,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            alert_type TEXT,
            severity TEXT,
            title TEXT,
            description TEXT,
            source_ip TEXT,
            source_mac TEXT,
            status TEXT DEFAULT 'Unresolved',
            resolved_by TEXT,
            resolution_notes TEXT,
            date_resolved DATETIME
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_key TEXT UNIQUE NOT NULL,
            cve_data TEXT,
            fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_cves (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_id INTEGER NOT NULL,
            cve_id TEXT NOT NULL,
            severity TEXT,
            cvss_score REAL,
            description TEXT,
            published_date TEXT,
            last_checked DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        )
    """)

    cursor.execute("SELECT COUNT(*) AS cnt FROM devices")
    if cursor.fetchone()["cnt"] == 0:
        demo_devices = [
            ("192.168.1.1",   "00:11:22:33:44:55", "Gateway-Router",   "Cisco Systems",       "active",
             '[{"port":80,"service":"http"},{"port":443,"service":"https"}]',
             "router",      1, "None",     "Admin",   "Core Gateway Router",        "Trusted", "admin", "2026-06-17 08:00:00"),
            ("192.168.1.10",  "AA:BB:CC:DD:EE:FF", "Recon-NDS-Server", "Dell Inc.",           "active",
             '[{"port":22,"service":"ssh"},{"port":80,"service":"http"},{"port":8000,"service":"http-alt"}]',
             "server",      1, "IT Dept",  "IT",      "Recon NDS Main Server Host", "Trusted", "admin", "2026-06-17 08:05:00"),
            ("192.168.1.101", "33:44:55:66:77:88", "Workstation-PC",   "HP",                  "active",
             '[{"port":135,"service":"msrpc"},{"port":445,"service":"microsoft-ds"}]',
             "workstation", 1, "Jane Doe", "HR",      "Jane Workstation Laptop",    "Trusted", "admin", "2026-06-17 08:10:00"),
            ("192.168.1.150", "99:88:77:66:55:44", "Smart-TV",         "Samsung Electronics", "inactive",
             '[]',           "smart-tv",  1, "None",  "Finance", "Conference Room TV", "Trusted", "admin", "2026-06-17 08:15:00"),
        ]
        cursor.executemany(
            "INSERT INTO devices (ip, mac, hostname, vendor, status, open_ports, os_type, is_trusted, "
            "owner_name, department, purpose, trust_level, registered_by, date_registered) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            demo_devices,
        )

    cursor.execute("SELECT COUNT(*) AS cnt FROM users")
    if cursor.fetchone()["cnt"] == 0:
        cursor.executemany(
            "INSERT INTO users (username, email, role, is_active, password_hash, full_name, allowed_ip) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                ("admin",    encrypt_pii("admin@reconnds.local"),    "super_admin", 1, hash_password("admin123"),    encrypt_pii("System Administrator"), "*"),
                ("operator", encrypt_pii("operator@reconnds.local"), "operator",    1, hash_password("operator123"), encrypt_pii("IT Operator"),          "*"),
                ("jane.doe", encrypt_pii("jane@reconnds.local"),     "user",        1, hash_password("jane123"),     encrypt_pii("Jane Doe"),             "*"),
            ],
        )
    else:
        cursor.execute("SELECT id, username FROM users WHERE password_hash IS NULL")
        for row in cursor.fetchall():
            uid, uname = row["id"], row["username"]
            pw = "admin123" if uname in ("admin", "super_admin") else ("operator123" if uname == "operator" else "jane123")
            cursor.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(pw), uid))
        cursor.execute("UPDATE users SET username = 'jane.doe' WHERE username = 'Jane Doe'")

    cursor.execute("SELECT COUNT(*) AS cnt FROM employees")
    if cursor.fetchone()["cnt"] == 0:
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        r = cursor.fetchone(); admin_uid = r["id"] if r else None
        cursor.execute("SELECT id FROM users WHERE username IN ('jane.doe', 'Jane Doe')")
        r = cursor.fetchone(); jane_uid = r["id"] if r else None
        cursor.executemany(
            "INSERT INTO employees (user_id, employee_id, full_name, position, department, email, phone, date_hired, created_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (admin_uid, encrypt_pii("EMP-001"), encrypt_pii("System Administrator"), encrypt_pii("Super Admin"),      encrypt_pii("IT"),              encrypt_pii("admin@reconnds.local"),   encrypt_pii("+1-555-0001"), "2020-01-01", "admin"),
                (jane_uid,  encrypt_pii("EMP-002"), encrypt_pii("Jane Doe"),             encrypt_pii("HR Coordinator"),   encrypt_pii("Human Resources"), encrypt_pii("jane@reconnds.local"),    encrypt_pii("+1-555-0002"), "2022-03-15", "admin"),
                (None,      encrypt_pii("EMP-003"), encrypt_pii("John Smith"),           encrypt_pii("Network Engineer"), encrypt_pii("IT"),              encrypt_pii("jsmith@reconnds.local"),  encrypt_pii("+1-555-0003"), "2021-07-10", "admin"),
                (None,      encrypt_pii("EMP-004"), encrypt_pii("Maria Garcia"),         encrypt_pii("Finance Analyst"),  encrypt_pii("Finance"),         encrypt_pii("mgarcia@reconnds.local"), encrypt_pii("+1-555-0004"), "2023-01-20", "admin"),
            ],
        )

    cursor.execute("SELECT COUNT(*) AS cnt FROM workspaces")
    if cursor.fetchone()["cnt"] == 0:
        cursor.executemany(
            "INSERT INTO workspaces (name, description, location, created_by) VALUES (?, ?, ?, ?)",
            [
                ("IT Operations Center", "Main server room and network infrastructure workspace", "Building A - Floor 1", "admin"),
                ("HR Department",        "Human Resources office workstations and printers",     "Building B - Floor 2", "admin"),
                ("Finance Floor",        "Finance department computing environment",              "Building B - Floor 3", "admin"),
            ],
        )
        cursor.execute("SELECT id FROM workspaces WHERE name = 'IT Operations Center'")
        ws_it = cursor.fetchone()
        cursor.execute("SELECT id FROM workspaces WHERE name = 'HR Department'")
        ws_hr = cursor.fetchone()
        cursor.execute("SELECT id FROM devices WHERE hostname = 'Recon-NDS-Server'")
        d_srv = cursor.fetchone()
        cursor.execute("SELECT id FROM devices WHERE hostname = 'Workstation-PC'")
        d_ws = cursor.fetchone()
        if ws_it and d_srv:
            cursor.execute(
                "INSERT OR IGNORE INTO workspace_devices (workspace_id, device_id, added_by) VALUES (?, ?, ?)",
                (ws_it["id"], d_srv["id"], "admin"),
            )
        if ws_hr and d_ws:
            cursor.execute(
                "INSERT OR IGNORE INTO workspace_devices (workspace_id, device_id, added_by) VALUES (?, ?, ?)",
                (ws_hr["id"], d_ws["id"], "admin"),
            )

    cursor.execute("SELECT COUNT(*) AS cnt FROM audit_logs")
    if cursor.fetchone()["cnt"] == 0:
        cursor.executemany(
            "INSERT INTO audit_logs (username, role, action, target, ip_address, details) VALUES (?, ?, ?, ?, ?, ?)",
            [
                ("admin",  "super_admin", "AUTH",   "system",           "127.0.0.1", "Admin console login successful"),
                ("system", "system",      "SCAN",   "192.168.1.0/24",   "127.0.0.1", "Automated background subnet scan completed"),
                ("admin",  "super_admin", "POLICY", "00:11:22:33:44:55","127.0.0.1", "Toggled device trust state to Trusted"),
            ],
        )

    conn.commit()
    cursor.close()
    conn.close()


def log_audit_event(username=None, role=None, action=None, target=None, ip_address=None, details=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO audit_logs (username, role, action, target, ip_address, details) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (username, role, action, target, ip_address, details),
        )
        conn.commit()
    except Exception as e:
        print(f"Failed to log audit event: {e}")
    finally:
        cursor.close()
        conn.close()