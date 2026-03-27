#!/usr/bin/env python3

import sqlite3
import os
import time

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "device_logs.db")


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=DELETE;")
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER,
        device_node TEXT,
        vendor_id TEXT,
        product_id TEXT,
        manufacturer TEXT,
        product TEXT,
        serial_number TEXT,
        bus_number TEXT,
        device_number TEXT,
        device_class TEXT,
        trust_score INTEGER,
        decision TEXT,
        risk_level TEXT,
        score_reasons TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER,
        alert_type TEXT,
        description TEXT,
        device_node TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS malware_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER,
        device_node TEXT,
        infected_files INTEGER,
        clean_files INTEGER,
        suspicious_files TEXT,
        infected_list TEXT,
        file_results TEXT
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS blocked_devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vendor_id TEXT,
        product_id TEXT,
        serial_number TEXT,
        manufacturer TEXT,
        product TEXT,
        timestamp INTEGER,
        reason TEXT,
        UNIQUE(vendor_id, product_id, serial_number)
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS device_whitelist (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        vendor_id TEXT,
        product_id TEXT,
        serial_number TEXT,
        manufacturer TEXT,
        product TEXT,
        timestamp INTEGER,
        trusted_score INTEGER,
        last_scan_timestamp INTEGER,
        UNIQUE(vendor_id, product_id, serial_number)
    )""")

    c.execute("""
    CREATE TABLE IF NOT EXISTS file_forwarding_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp INTEGER,
        device_node TEXT,
        file_path TEXT,
        file_hash TEXT,
        destination TEXT,
        status TEXT,
        verification_hash TEXT
    )""")

    # Migrate: add score_reasons column if missing
    try:
        c.execute("ALTER TABLE devices ADD COLUMN score_reasons TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # Migrate: add file_results column to malware_reports if missing
    try:
        c.execute("ALTER TABLE malware_reports ADD COLUMN file_results TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    conn.commit()
    conn.close()


def store_device(device_info):
    import json
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=DELETE;")
    c = conn.cursor()
    score_reasons = device_info.get("score_reasons", [])
    c.execute("""
    INSERT INTO devices (
        timestamp, device_node, vendor_id, product_id,
        manufacturer, product, serial_number,
        bus_number, device_number, device_class, trust_score, decision, risk_level, score_reasons
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        int(time.time()),
        device_info.get("device_node"),
        device_info.get("vendor_id"),
        device_info.get("product_id"),
        device_info.get("manufacturer"),
        device_info.get("product"),
        device_info.get("serial_number"),
        device_info.get("bus_number"),
        device_info.get("device_number"),
        device_info.get("device_class"),
        device_info.get("trust_score"),
        device_info.get("decision"),
        device_info.get("risk_level"),
        json.dumps(score_reasons),
    ))
    conn.commit()
    conn.close()


def insert_alert(alert_data):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=DELETE;")
    c = conn.cursor()
    c.execute("""
    INSERT INTO alerts (timestamp, alert_type, description, device_node)
    VALUES (?, ?, ?, ?)
    """, (
        alert_data.get("timestamp", int(time.time())),
        alert_data.get("alert_type"),
        alert_data.get("description"),
        alert_data.get("device_node"),
    ))
    conn.commit()
    conn.close()


def store_malware_report(report):
    import json
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=DELETE;")
    c = conn.cursor()
    c.execute("""
    INSERT INTO malware_reports (
        timestamp, device_node, infected_files,
        clean_files, suspicious_files, infected_list, file_results
    ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        int(time.time()),
        report.get("device_node"),
        report.get("infected_files", 0),
        report.get("clean_files", 0),
        str(report.get("suspicious_files", [])),
        str(report.get("infected_list", [])),
        json.dumps(report.get("file_results", [])),
    ))
    conn.commit()
    conn.close()


def get_recent_devices(limit=10):
    import json
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM devices ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = []
    for r in c.fetchall():
        row = dict(r)
        try:
            row["score_reasons"] = json.loads(row.get("score_reasons") or "[]")
        except (ValueError, TypeError):
            row["score_reasons"] = []
        rows.append(row)
    conn.close()
    return rows


def get_latest_device():
    rows = get_recent_devices(limit=1)
    return rows[0] if rows else None


def get_recent_alerts(limit=10):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def update_device_status(device_node, status):
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=DELETE;")
    c = conn.cursor()
    c.execute("UPDATE devices SET decision=? WHERE device_node=? ORDER BY timestamp DESC LIMIT 1",
              (status, device_node))
    conn.commit()
    conn.close()


def get_recent_malware_reports(limit=10):
    import json
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM malware_reports ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = []
    for r in c.fetchall():
        row = dict(r)
        try:
            row["file_results"] = json.loads(row.get("file_results") or "[]")
        except (ValueError, TypeError):
            row["file_results"] = []
        rows.append(row)
    conn.close()
    return rows


# ── Device Whitelist Management ─────────────────────────────────────────────────
def is_device_whitelisted(vendor_id, product_id, serial_number):
    """Check if device is in trusted whitelist."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""SELECT * FROM device_whitelist 
                     WHERE vendor_id=? AND product_id=? AND serial_number=?""",
                  (vendor_id, product_id, serial_number))
        result = c.fetchone()
        conn.close()
        return result is not None
    except:
        return False


def add_to_whitelist(device_info, trusted_score):
    """Add device to trusted whitelist."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""INSERT OR REPLACE INTO device_whitelist 
                     (vendor_id, product_id, serial_number, manufacturer, product, timestamp, trusted_score, last_scan_timestamp)
                     VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                  (device_info.get("vendor_id"), device_info.get("product_id"), 
                   device_info.get("serial_number"), device_info.get("manufacturer"),
                   device_info.get("product"), int(time.time()), trusted_score, int(time.time())))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Whitelist add failed: {e}")
        return False


def remove_from_whitelist(vendor_id, product_id, serial_number):
    """Remove device from whitelist."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""DELETE FROM device_whitelist 
                     WHERE vendor_id=? AND product_id=? AND serial_number=?""",
                  (vendor_id, product_id, serial_number))
        conn.commit()
        conn.close()
        return True
    except:
        return False


# ── Device Blocking Management ──────────────────────────────────────────────────
def is_device_blocked(vendor_id, product_id, serial_number):
    """Check if device is permanently blocked."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""SELECT * FROM blocked_devices 
                     WHERE vendor_id=? AND product_id=? AND serial_number=?""",
                  (vendor_id, product_id, serial_number))
        result = c.fetchone()
        conn.close()
        return result is not None
    except:
        return False


def add_to_blocklist(device_info, reason):
    """Add device to permanent blocklist."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""INSERT OR REPLACE INTO blocked_devices 
                     (vendor_id, product_id, serial_number, manufacturer, product, timestamp, reason)
                     VALUES (?, ?, ?, ?, ?, ?, ?)""",
                  (device_info.get("vendor_id"), device_info.get("product_id"),
                   device_info.get("serial_number"), device_info.get("manufacturer"),
                   device_info.get("product"), int(time.time()), reason))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Blocklist add failed: {e}")
        return False


def remove_from_blocklist(vendor_id, product_id, serial_number):
    """Remove device from blocklist."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""DELETE FROM blocked_devices 
                     WHERE vendor_id=? AND product_id=? AND serial_number=?""",
                  (vendor_id, product_id, serial_number))
        conn.commit()
        conn.close()
        return True
    except:
        return False


# ── File Forwarding Logs ────────────────────────────────────────────────────────
def log_file_forward(device_node, file_path, file_hash, destination, status):
    """Log file forwarding operation."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("""INSERT INTO file_forwarding_logs 
                     (timestamp, device_node, file_path, file_hash, destination, status)
                     VALUES (?, ?, ?, ?, ?, ?)""",
                  (int(time.time()), device_node, file_path, file_hash, destination, status))
        conn.commit()
        conn.close()
        return True
    except:
        return False


def verify_file_forward(device_node, file_path, file_hash, verification_hash):
    """Verify file forwarding with hash comparison."""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        status = "verified" if file_hash == verification_hash else "failed"
        c.execute("""UPDATE file_forwarding_logs 
                     SET status=?, verification_hash=? 
                     WHERE device_node=? AND file_path=? AND file_hash=?""",
                  (status, verification_hash, device_node, file_path, file_hash))
        conn.commit()
        conn.close()
        return status == "verified"
    except:
        return False
