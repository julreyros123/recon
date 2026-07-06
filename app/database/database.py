import os
import hashlib
import secrets
import datetime
import mysql.connector
from dotenv import load_dotenv

from app.utils.encryption import encrypt_pii

# Load credentials from .env
load_dotenv()

DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "port":     int(os.getenv("DB_PORT", 3306)),
    "database": os.getenv("DB_NAME", "recon"),
    "user":     os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "autocommit": False,
    "charset": "utf8mb4",
}

class DictConnectionWrapper:
    """Wraps a MySQL connection to ensure cursor() defaults to dictionary=True, mimicking sqlite3.Row."""
    def __init__(self, conn):
        self._conn = conn

    def cursor(self, *args, **kwargs):
        kwargs.setdefault('dictionary', True)
        return self._conn.cursor(*args, **kwargs)

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        return self._conn.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)

def get_db_connection():
    """Open a new MySQL connection (dictionary cursor rows)."""
    conn = mysql.connector.connect(**DB_CONFIG)
    return DictConnectionWrapper(conn)

def get_db():
    """FastAPI dependency: yields a MySQL connection, closes on exit."""
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

def _add_column_if_missing(cursor, table: str, col: str, definition: str):
    cursor.execute(
        "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s AND COLUMN_NAME = %s",
        (table, col),
    )
    if cursor.fetchone() is None:
        cursor.execute(f"ALTER TABLE `{table}` ADD COLUMN `{col}` {definition}")

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # ── Devices ──────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS devices (
            id        INT AUTO_INCREMENT PRIMARY KEY,
            ip        VARCHAR(45) UNIQUE NOT NULL,
            mac       VARCHAR(17),
            hostname  VARCHAR(255),
            vendor    VARCHAR(255),
            status    VARCHAR(32) DEFAULT 'unknown',
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    for col, defn in [
        ("open_ports",        "LONGTEXT"),
        ("os_type",           "VARCHAR(64) DEFAULT 'generic'"),
        ("is_trusted",        "TINYINT(1) DEFAULT 0"),
        ("owner_name",        "VARCHAR(255)"),
        ("department",        "VARCHAR(128)"),
        ("purpose",           "TEXT"),
        ("trust_level",       "VARCHAR(32) DEFAULT 'Unknown'"),
        ("registered_by",     "VARCHAR(128)"),
        ("date_registered",   "DATETIME"),
        # Extended hardware & network
        ("serial_number",     "VARCHAR(128)"),
        ("model",             "VARCHAR(255)"),
        ("firmware_version",  "VARCHAR(128)"),
        ("latest_firmware",   "VARCHAR(128)"),
        ("firmware_eol",      "TINYINT(1) DEFAULT 0"),
        ("warranty_expiry",   "VARCHAR(32)"),
        ("purchase_date",     "VARCHAR(32)"),
        ("vlan",              "VARCHAR(32)"),
        ("switch_port",       "VARCHAR(64)"),
        ("site_location",     "VARCHAR(255)"),
        ("rack_position",     "VARCHAR(64)"),
        ("admin_contact",     "VARCHAR(255)"),
        # Security controls
        ("ssh_enabled",       "TINYINT(1) DEFAULT 0"),
        ("telnet_enabled",    "TINYINT(1) DEFAULT 0"),
        ("snmp_enabled",      "TINYINT(1) DEFAULT 0"),
        ("http_mgmt_enabled", "TINYINT(1) DEFAULT 0"),
        ("mfa_enforced",      "TINYINT(1) DEFAULT 0"),
        ("local_users",       "LONGTEXT"),
        # OS tracking
        ("baseline_os",       "VARCHAR(255)"),
        ("current_os",        "VARCHAR(255)"),
    ]:
        _add_column_if_missing(cursor, "devices", col, defn)

    # ── Users ─────────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id                   INT AUTO_INCREMENT PRIMARY KEY,
            username             VARCHAR(128) UNIQUE NOT NULL,
            email                TEXT,
            full_name            TEXT,
            role                 VARCHAR(32) DEFAULT 'user',
            is_active            TINYINT(1) DEFAULT 1,
            password_hash        TEXT,
            login_attempts       INT DEFAULT 0,
            locked_until         DATETIME,
            super_admin_pin_hash TEXT,
            last_login           DATETIME,
            allowed_ip           VARCHAR(255) DEFAULT '*'
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    for col, defn in [
        ("full_name",            "VARCHAR(255)"),
        ("login_attempts",       "INT DEFAULT 0"),
        ("locked_until",         "DATETIME"),
        ("super_admin_pin_hash", "TEXT"),
        ("last_login",           "DATETIME"),
        ("password_hash",        "TEXT"),
        ("allowed_ip",           "VARCHAR(255) DEFAULT '*'"),
    ]:
        _add_column_if_missing(cursor, "users", col, defn)
    # Migrate old 'administrator' role → 'super_admin'
    cursor.execute("UPDATE users SET role = 'super_admin' WHERE role = 'administrator'")

    # ── Employees (HR Profiles) ────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            user_id      INT,
            employee_id  VARCHAR(255) UNIQUE,
            full_name    VARCHAR(255) NOT NULL,
            position     VARCHAR(255),
            department   VARCHAR(255),
            email        VARCHAR(255),
            phone        VARCHAR(255),
            date_hired   VARCHAR(32),
            is_active    TINYINT(1) DEFAULT 1,
            created_by   VARCHAR(128),
            date_created DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    # ── Workspaces ────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workspaces (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            name         VARCHAR(255) UNIQUE NOT NULL,
            description  TEXT,
            location     VARCHAR(255),
            created_by   VARCHAR(128),
            date_created DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    # ── Workspace ↔ Device Junction ───────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workspace_devices (
            id           INT AUTO_INCREMENT PRIMARY KEY,
            workspace_id INT NOT NULL,
            device_id    INT NOT NULL,
            added_by     VARCHAR(128),
            date_added   DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE KEY uq_ws_dev (workspace_id, device_id),
            FOREIGN KEY (workspace_id) REFERENCES workspaces(id) ON DELETE CASCADE,
            FOREIGN KEY (device_id)   REFERENCES devices(id)    ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    # ── Reports ───────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id                 INT AUTO_INCREMENT PRIMARY KEY,
            timestamp          DATETIME DEFAULT CURRENT_TIMESTAMP,
            devices_found      INT,
            active_devices     INT,
            scan_duration_secs DOUBLE,
            summary            TEXT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    # ── Audit Logs ────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            timestamp  DATETIME DEFAULT CURRENT_TIMESTAMP,
            username   VARCHAR(128),
            role       VARCHAR(32),
            action     VARCHAR(64),
            target     VARCHAR(255),
            ip_address VARCHAR(45),
            details    TEXT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    # ── Workstation Telemetry ─────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workstation_telemetry (
            id                  INT AUTO_INCREMENT PRIMARY KEY,
            device_id           INT NOT NULL,
            timestamp           DATETIME DEFAULT CURRENT_TIMESTAMP,
            cpu_usage           FLOAT,
            ram_usage           FLOAT,
            disk_usage          FLOAT DEFAULT 0.0,
            running_processes   LONGTEXT,
            network_connections LONGTEXT,
            logged_in_users     TEXT,
            usb_devices         TEXT,
            os_info             TEXT,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)
    _add_column_if_missing(cursor, "workstation_telemetry", "disk_usage", "FLOAT DEFAULT 0.0")

    # ── Workstation Alerts ────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS workstation_alerts (
            id               INT AUTO_INCREMENT PRIMARY KEY,
            device_id        INT NOT NULL,
            timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP,
            alert_type       VARCHAR(64),
            severity         VARCHAR(32),
            title            VARCHAR(255),
            description      TEXT,
            status           VARCHAR(32) DEFAULT 'Unresolved',
            resolved_by      VARCHAR(128),
            resolution_notes TEXT,
            date_resolved    DATETIME,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    # ── Network Alerts ────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS network_alerts (
            id               INT AUTO_INCREMENT PRIMARY KEY,
            timestamp        DATETIME DEFAULT CURRENT_TIMESTAMP,
            alert_type       VARCHAR(64),
            severity         VARCHAR(32),
            title            VARCHAR(255),
            description      TEXT,
            source_ip        VARCHAR(45),
            source_mac       VARCHAR(17),
            status           VARCHAR(32) DEFAULT 'Unresolved',
            resolved_by      VARCHAR(128),
            resolution_notes TEXT,
            date_resolved    DATETIME
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    # ── CVE Cache ─────────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cve_cache (
            id         INT AUTO_INCREMENT PRIMARY KEY,
            query_key  VARCHAR(512) UNIQUE NOT NULL,
            cve_data   LONGTEXT,
            fetched_at DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    # ── Device CVEs ───────────────────────────────────────────────
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS device_cves (
            id             INT AUTO_INCREMENT PRIMARY KEY,
            device_id      INT NOT NULL,
            cve_id         VARCHAR(32) NOT NULL,
            severity       VARCHAR(16),
            cvss_score     FLOAT,
            description    TEXT,
            published_date VARCHAR(32),
            last_checked   DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    """)

    # ── Seed Data ─────────────────────────────────────────────────
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
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
            demo_devices,
        )

    cursor.execute("SELECT COUNT(*) AS cnt FROM users")
    if cursor.fetchone()["cnt"] == 0:
        cursor.executemany(
            "INSERT INTO users (username, email, role, is_active, password_hash, full_name, allowed_ip) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s)",
            [
                ("admin",    encrypt_pii("admin@reconnds.local"),    "super_admin", 1, hash_password("admin123"),    encrypt_pii("System Administrator"), "127.0.0.1"),
                ("operator", encrypt_pii("operator@reconnds.local"), "operator",    1, hash_password("operator123"), encrypt_pii("IT Operator"),          "*"),
                ("jane.doe", encrypt_pii("jane@reconnds.local"),     "user",        1, hash_password("jane123"),     encrypt_pii("Jane Doe"),             "*"),
            ],
        )
    else:
        # Fix NULL password hashes
        cursor.execute("SELECT id, username FROM users WHERE password_hash IS NULL")
        for row in cursor.fetchall():
            uid, uname = row["id"], row["username"]
            pw = "admin123" if uname in ("admin", "super_admin") else ("operator123" if uname == "operator" else "jane123")
            cursor.execute("UPDATE users SET password_hash = %s WHERE id = %s", (hash_password(pw), uid))
        cursor.execute("UPDATE users SET username = 'jane.doe' WHERE username = 'Jane Doe'")
        cursor.execute("UPDATE users SET allowed_ip = '127.0.0.1' WHERE username = 'admin' AND allowed_ip = '*'")

    cursor.execute("SELECT COUNT(*) AS cnt FROM employees")
    if cursor.fetchone()["cnt"] == 0:
        cursor.execute("SELECT id FROM users WHERE username = 'admin'")
        r = cursor.fetchone(); admin_uid = r["id"] if r else None
        cursor.execute("SELECT id FROM users WHERE username IN ('jane.doe', 'Jane Doe')")
        r = cursor.fetchone(); jane_uid = r["id"] if r else None
        cursor.executemany(
            "INSERT INTO employees (user_id, employee_id, full_name, position, department, email, phone, date_hired, created_by) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)",
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
            "INSERT INTO workspaces (name, description, location, created_by) VALUES (%s, %s, %s, %s)",
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
                "INSERT IGNORE INTO workspace_devices (workspace_id, device_id, added_by) VALUES (%s, %s, %s)",
                (ws_it["id"], d_srv["id"], "admin"),
            )
        if ws_hr and d_ws:
            cursor.execute(
                "INSERT IGNORE INTO workspace_devices (workspace_id, device_id, added_by) VALUES (%s, %s, %s)",
                (ws_hr["id"], d_ws["id"], "admin"),
            )

    cursor.execute("SELECT COUNT(*) AS cnt FROM audit_logs")
    if cursor.fetchone()["cnt"] == 0:
        cursor.executemany(
            "INSERT INTO audit_logs (username, role, action, target, ip_address, details) VALUES (%s, %s, %s, %s, %s, %s)",
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
    """Insert an audit log record into MySQL."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO audit_logs (username, role, action, target, ip_address, details) "
            "VALUES (%s, %s, %s, %s, %s, %s)",
            (username, role, action, target, ip_address, details),
        )
        conn.commit()
    except Exception as e:
        print(f"Failed to log audit event: {e}")
    finally:
        cursor.close()
        conn.close()
