#!/usr/bin/env python3
"""
Database Module for USB Security Gateway

Handles SQLite database operations for:

? Detected USB devices
? Security alerts
? Malware scan reports
"""

import sqlite3
import os
import threading
import time
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "device_logs.db")

LOG_PATH = os.path.join(BASE_DIR, "../../logs/gateway.log")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("USB-Database")

db_lock = threading.Lock()


# -----------------------------------------------------
# Database Connection
# -----------------------------------------------------

def get_connection():
    try:

        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row

        return conn

    except Exception as e:

        logger.error(f"Database connection failed: {str(e)}")

        return None


# -----------------------------------------------------
# Initialize Database
# -----------------------------------------------------

def init_db():

    try:

        with db_lock:

            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("""
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
                device_number TEXT
            )
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                alert_type TEXT,
                description TEXT,
                device_node TEXT
            )
            """)

            cursor.execute("""
            CREATE TABLE IF NOT EXISTS malware_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                device_node TEXT,
                infected_files INTEGER,
                clean_files INTEGER,
                report TEXT
            )
            """)

            conn.commit()
            conn.close()

            logger.info("Database initialized successfully")

    except Exception as e:

        logger.error(f"Database initialization failed: {str(e)}")
# -----------------------------------------------------
# Store USB Device
# -----------------------------------------------------

def store_device(device_info):

    try:

        with db_lock:

            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("""
            INSERT INTO devices (
                timestamp,
                device_node,
                vendor_id,
                product_id,
                manufacturer,
                product,
                serial_number,
                bus_number,
                device_number
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (

                int(time.time()),
                device_info.get("device_node"),
                device_info.get("vendor_id"),
                device_info.get("product_id"),
                device_info.get("manufacturer"),
                device_info.get("product"),
                device_info.get("serial_number"),
                device_info.get("bus_number"),
                device_info.get("device_number")

            ))

            conn.commit()
            conn.close()

            logger.info("Device stored in database")

    except Exception as e:

        logger.error(f"Failed to store device: {str(e)}")


# -----------------------------------------------------
# Insert Alert
# -----------------------------------------------------

def insert_alert(alert_data):

    try:

        with db_lock:

            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("""
            INSERT INTO alerts (
                timestamp,
                alert_type,
                description,
                device_node
            ) VALUES (?, ?, ?, ?)
            """, (

                alert_data.get("timestamp"),
                alert_data.get("alert_type"),
                alert_data.get("description"),
                alert_data.get("device_node")

            ))

            conn.commit()
            conn.close()

            logger.info("Alert inserted into database")

    except Exception as e:

        logger.error(f"Failed to insert alert: {str(e)}")


# -----------------------------------------------------
# Insert Malware Report
# -----------------------------------------------------

def insert_malware_report(report_data):

    try:

        with db_lock:

            conn = get_connection()
            cursor = conn.cursor()

            cursor.execute("""
            INSERT INTO malware_reports (
                timestamp,
                device_node,
                infected_files,
                clean_files,
                report
            ) VALUES (?, ?, ?, ?, ?)
            """, (

                int(time.time()),
                report_data.get("device_node"),
                report_data.get("infected_files"),
                report_data.get("clean_files"),
                report_data.get("report")

            ))

            conn.commit()
            conn.close()

            logger.info("Malware report stored")

    except Exception as e:

        logger.error(f"Failed to store malware report: {str(e)}")
# -----------------------------------------------------
# Retrieve Devices
# -----------------------------------------------------

def get_recent_devices(limit=10):

    try:

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        SELECT * FROM devices
        ORDER BY timestamp DESC
        LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()

        conn.close()

        return [dict(row) for row in rows]

    except Exception as e:

        logger.error(f"Failed to fetch devices: {str(e)}")
        return []


# -----------------------------------------------------
# Retrieve Alerts
# -----------------------------------------------------

def get_recent_alerts(limit=10):

    try:

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        SELECT * FROM alerts
        ORDER BY timestamp DESC
        LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()

        conn.close()

        return [dict(row) for row in rows]

    except Exception as e:

        logger.error(f"Failed to fetch alerts: {str(e)}")
        return []


# -----------------------------------------------------
# Retrieve Malware Reports
# -----------------------------------------------------
def get_recent_malware_reports(limit=10):

    try:

        conn = get_connection()
        cursor = conn.cursor()

        cursor.execute("""
        SELECT * FROM malware_reports
        ORDER BY timestamp DESC
        LIMIT ?
        """, (limit,))

        rows = cursor.fetchall()

        conn.close()

        return [dict(row) for row in rows]

    except Exception as e:

        logger.error(f"Failed to fetch malware reports: {str(e)}")
        return []
