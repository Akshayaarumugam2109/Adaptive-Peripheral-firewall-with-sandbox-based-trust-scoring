#!/usr/bin/env python3

import os
import logging
import yaml
from flask import Flask, jsonify, send_from_directory, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

from api_server.routes.device_routes import device_routes
from api_server.routes.alert_routes import alert_routes
from api_server.routes.scan_routes import scan_routes

from gateway.database.db import (
    get_recent_devices,
    get_recent_alerts,
    get_latest_device,
    get_recent_malware_reports,
)
from gateway.shared_state import get_connected, add_device, update_device, remove_device

BASE_DIR    = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "../gateway/config/gateway_config.yaml")
LOG_PATH    = os.path.join(BASE_DIR, "../logs/gateway.log")

logging.basicConfig(
    filename=LOG_PATH, level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("API-Server")


def load_config():
    try:
        with open(CONFIG_PATH) as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Config load failed: {e}")
        return {}

config = load_config()

# ── Static ────────────────────────────────────────────────────────────────────

@app.route("/")
def serve_dashboard():
    return send_from_directory(os.path.abspath("dashboard"), "index.html")

@app.route("/<path:path>")
def serve_static(path):
    return send_from_directory(os.path.abspath("dashboard"), path)

# ── Blueprints ────────────────────────────────────────────────────────────────

app.register_blueprint(device_routes)
app.register_blueprint(alert_routes)
app.register_blueprint(scan_routes)

# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.route("/demo_state", methods=["POST"])
def demo_state():
    """Receive scan state updates from sandbox_demo.py and push into shared_state."""
    data = request.get_json(force=True) or {}
    node = data.pop("device_node", "demo_usb")
    if data.pop("_clear", False):
        remove_device(node)
    elif not get_connected() or not any(d.get("device_node") == node for d in get_connected()):
        add_device(node, {"device_node": node, **data})
    else:
        update_device(node, **data)
    return jsonify({"ok": True})


@app.route("/scan_status")
def scan_status():
    devices = get_connected()
    if not devices:
        return jsonify({"scan_step": "idle", "status": "idle", "device_node": None,
                        "file_count": 0, "suspicious": False})
    d = next((x for x in reversed(devices) if x.get("status") != "idle"), devices[-1])
    return jsonify({
        "scan_step":   d.get("scan_step", "idle"),
        "status":      d.get("status", "idle"),
        "device_node": d.get("device_node"),
        "device_class":d.get("device_class"),
        "file_count":  d.get("file_count", 0),
        "suspicious":  d.get("suspicious", False),
        "file_results":d.get("file_results", []),
        "trust_score": d.get("trust_score"),
        "decision":    d.get("decision"),
    })

@app.route("/health")
def health():
    return jsonify({"status": "running", "service": "USB Security Gateway"})

@app.route("/current_device")
def current_device():
    devices = get_connected()
    if not devices:
        latest = get_recent_devices(limit=1)
        if latest:
            latest[0]["status"] = "done"
            # Restore file_results from malware report
            reports = get_recent_malware_reports(limit=1)
            if reports and reports[0].get("file_results"):
                latest[0]["file_results"] = reports[0]["file_results"]
            devices = latest
    else:
        # Patch any device missing score_reasons from DB
        for d in devices:
            if not d.get("score_reasons") and d.get("status") == "done":
                db_rows = get_recent_devices(limit=5)
                match = next((r for r in db_rows if r["device_node"] == d.get("device_node")), None)
                if match and match.get("score_reasons"):
                    d["score_reasons"] = match["score_reasons"]
    return jsonify({"devices": devices})

@app.route("/devices")
def devices():
    try:
        rows = get_recent_devices()
        return jsonify({"count": len(rows), "devices": rows})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/alerts")
def alerts():
    try:
        rows = get_recent_alerts()
        return jsonify({"count": len(rows), "alerts": rows})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/scan_results")
def scan_results():
    try:
        rows = get_recent_malware_reports()
        return jsonify({"count": len(rows), "reports": rows})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/file_results")
def file_results():
    devices = get_connected()
    # Return file results from the most recently analysed storage device
    for d in reversed(devices):
        if d.get("file_results"):
            return jsonify({"files": d["file_results"]})
    return jsonify({"files": []})

@app.route("/score_reasons")
def score_reasons():
    devices = get_connected()
    for d in reversed(devices):
        if d.get("score_reasons"):
            return jsonify({"score": d.get("trust_score"), "reasons": d["score_reasons"]})
    return jsonify({"score": None, "reasons": []})

@app.route("/sandbox_proof")
def sandbox_proof():
    import subprocess
    proof = {}

    # Show active sandbox mounts
    try:
        mounts = open("/proc/mounts").read()
        sandbox_mounts = [line for line in mounts.splitlines() if "usb_gateway" in line]
        proof["active_mounts"] = sandbox_mounts
        proof["mount_count"]   = len(sandbox_mounts)
    except:
        proof["active_mounts"] = []

    # Show mount flags proof
    proof["mount_flags"] = {
        "ro":     "Read-only — cannot modify USB contents",
        "noexec": "No execution — cannot run files from USB",
        "nosuid": "No SUID — privilege escalation blocked",
        "nodev":  "No device files — hardware access blocked"
    }

    # Show sandbox directory
    import os
    sandbox_dir = "/tmp/usb_gateway"
    proof["sandbox_path"] = sandbox_dir
    proof["sandbox_exists"] = os.path.exists(sandbox_dir)
    if os.path.exists(sandbox_dir):
        proof["mounted_devices"] = os.listdir(sandbox_dir)

    # ClamAV available
    r = subprocess.run(["which", "clamscan"], capture_output=True, text=True)
    proof["clamav_available"] = r.returncode == 0
    proof["clamav_path"]      = r.stdout.strip()

    # YARA available
    r = subprocess.run(["which", "yara"], capture_output=True, text=True)
    proof["yara_available"] = r.returncode == 0

    return jsonify(proof)


# ── Start ─────────────────────────────────────────────────────────────────────

def start_server():
    host = config.get("api_server", {}).get("host", "0.0.0.0")
    port = config.get("api_server", {}).get("port", 5000)
    app.run(host=host, port=port, use_reloader=False)

if __name__ == "__main__":
    start_server()
