"""
migrate_sqlite_to_mysql.py
--------------------------
One-shot migration: copies all data from recon_nds.db (SQLite)
into the MySQL "recon" database.

Usage:
    .\venv\Scripts\python migrate_sqlite_to_mysql.py
"""
import sqlite3
import os
import sys
from dotenv import load_dotenv
import mysql.connector

load_dotenv()

SQLITE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "recon_nds.db")

MYSQL_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "port":     int(os.getenv("DB_PORT", 3306)),
    "database": os.getenv("DB_NAME", "recon"),
    "user":     os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "charset":  "utf8mb4",
}

# Migration order: parents before children (foreign key safety)
TABLES = [
    "users",
    "devices",
    "employees",
    "workspaces",
    "workspace_devices",
    "reports",
    "audit_logs",
    "workstation_telemetry",
    "workstation_alerts",
    "network_alerts",
    "cve_cache",
    "device_cves",
]

CHUNK_SIZE = 50  # rows per INSERT batch (small to avoid max_allowed_packet)


def migrate():
    if not os.path.exists(SQLITE_PATH):
        print("[!] SQLite file not found:", SQLITE_PATH)
        print("    Nothing to migrate — MySQL will start fresh.")
        return

    print("[*] Connecting to SQLite:", SQLITE_PATH)
    src = sqlite3.connect(SQLITE_PATH)
    src.row_factory = sqlite3.Row

    host = MYSQL_CONFIG["host"]
    port = MYSQL_CONFIG["port"]
    db   = MYSQL_CONFIG["database"]
    print(f"[*] Connecting to MySQL: {host}:{port}/{db}")

    try:
        dst = mysql.connector.connect(**MYSQL_CONFIG)
    except mysql.connector.Error as e:
        print("[!] MySQL connection failed:", e)
        sys.exit(1)

    cur = dst.cursor()
    cur.execute("SET FOREIGN_KEY_CHECKS=0")
    cur.execute("SET SESSION net_write_timeout=600")
    cur.execute("SET SESSION net_read_timeout=600")
    total = 0

    for table in TABLES:
        sc = src.cursor()

        # Check table exists in SQLite
        sc.execute(
            "SELECT name FROM sqlite_master WHERE type=? AND name=?",
            ("table", table),
        )
        if not sc.fetchone():
            print(f"  [skip] {table} — not in SQLite")
            continue

        sc.execute(f"SELECT * FROM {table}")
        rows = sc.fetchall()

        if not rows:
            print(f"  [skip] {table} — empty")
            continue

        sqlite_cols = [d[0] for d in sc.description]

        # Get columns available in MySQL
        cur.execute(
            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s",
            (table,),
        )
        mysql_cols = {r[0] for r in cur.fetchall()}

        # Migrate only columns present in both; skip auto-increment id
        cols = [c for c in sqlite_cols if c in mysql_cols and c != "id"]
        if not cols:
            print(f"  [skip] {table} — no matching columns")
            continue

        placeholders = ", ".join(["%s"] * len(cols))
        col_list = ", ".join([f"`{c}`" for c in cols])
        sql = f"INSERT IGNORE INTO `{table}` ({col_list}) VALUES ({placeholders})"
        data = [tuple(row[c] for c in cols) for row in rows]

        # Insert in chunks to avoid max_allowed_packet issues
        migrated = 0
        errors = 0
        for i in range(0, len(data), CHUNK_SIZE):
            chunk = data[i:i + CHUNK_SIZE]
            try:
                cur.executemany(sql, chunk)
                dst.commit()
                migrated += len(chunk)
            except mysql.connector.Error as e:
                print(f"  [err]  {table} chunk {i}-{i+CHUNK_SIZE}: {e}")
                errors += 1
                try:
                    dst.rollback()
                except Exception:
                    pass

        total += migrated
        if errors:
            print(f"  [warn] {table} — {migrated} rows OK, {errors} chunks failed")
        else:
            print(f"  [ok]   {table} — {migrated} rows migrated")

    cur.execute("SET FOREIGN_KEY_CHECKS=1")
    dst.commit()
    cur.close()
    dst.close()
    src.close()

    print()
    print(f"Migration complete: {total} total rows copied to MySQL.")
    print("Your original SQLite file has NOT been deleted (kept as backup).")


if __name__ == "__main__":
    migrate()
