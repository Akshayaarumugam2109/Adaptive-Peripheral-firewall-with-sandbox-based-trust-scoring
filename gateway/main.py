#!/usr/bin/env python3

import time
import os
import threading
import subprocess
import shutil

from api_server.server import app
from gateway.usb_monitor.monitor import start_usb_monitor
from gateway.usb_monitor.enumeration import enumerate_device
from gateway.classification.classify_device import classify_device
from gateway.classification.suspicious_detector import detect_suspicious
from gateway.trust_engine import compute_trust_score
from gateway.decision_engine import make_decision, enforce_decision
from gateway.alerts.alert_manager import (
    create_alert,
    create_device_block_alert,
    create_malware_alert,
    create_suspicious_device_alert,
)
from gateway.database.db import (
    init_db, store_device, store_malware_report, update_device_status,
    is_device_whitelisted, add_to_whitelist, is_device_blocked
)
from gateway.shared_state import add_device, update_device, remove_device
from sandbox.mount_usb import mount_usb, unmount_usb
from sandbox.file_extractor import extract_files
from sandbox.malware_scan import run_malware_scan
from gateway.forwarder import forward_clean_files
from gateway.firmware_detection import detect_hid_attack


def cleanup_stale_mounts():
    """
    Cleanup stale USB mounts and temp files from previous crashes.
    Runs at startup to ensure clean state.
    """
    print("\n🧹 Cleanup: Checking for stale mounts...")
    
    sandbox_base = "/tmp/usb_gateway"
    
    # Unmount any leftover USB mounts
    try:
        result = subprocess.run(["mount"], capture_output=True, text=True)
        for line in result.stdout.split('\n'):
            if sandbox_base in line and 'on' in line:
                mount_path = line.split(' on ')[1].split(' ')[0]
                try:
                    subprocess.run(["umount", mount_path], capture_output=True, timeout=5)
                    print(f"   ✅ Unmounted stale: {mount_path}")
                except Exception as e:
                    print(f"   ⚠️  Failed to unmount {mount_path}: {e}")
    except Exception as e:
        print(f"   ⚠️  Cleanup mount check failed: {e}")
    
    # Clean sandbox directory
    try:
        if os.path.exists(sandbox_base):
            for item in os.listdir(sandbox_base):
                item_path = os.path.join(sandbox_base, item)
                try:
                    if os.path.isdir(item_path):
                        shutil.rmtree(item_path)
                    else:
                        os.remove(item_path)
                    print(f"   ✅ Removed stale: {item_path}")
                except Exception as e:
                    print(f"   ⚠️  Failed to remove {item_path}: {e}")
    except Exception as e:
        print(f"   ⚠️  Sandbox cleanup failed: {e}")
    
    print("✅ Cleanup complete\n")


def process_device(device_node, device_type):
    print(f"\n🔍 Processing: {device_node}  type={device_type}")

    # For storage, wait up to 5s for /dev/sdX to exist
    if device_type == "storage":
        for _ in range(6):
            if os.path.exists(device_node):
                break
            time.sleep(0.2)
        if not os.path.exists(device_node):
            print(f"⚠️  {device_node} not ready — skipping")
            remove_device(device_node)
            return
    # For USB/HID sysfs nodes, just check sysfs path exists
    elif not device_node.startswith("/dev/"):
        sysfs = f"/sys/bus/usb/devices/{device_node}"
        if not os.path.exists(sysfs):
            print(f"⚠️  sysfs {sysfs} not found — skipping")
            remove_device(device_node)
            return

    # ── 1. Enumerate ──────────────────────────────────────────────────────────
    device_info = enumerate_device(device_node, device_type)
    if not device_info:
        print(f"❌ Enumeration failed for {device_node}")
        remove_device(device_node)
        return

    device_info["status"]      = "analysing"
    device_info["device_node"] = device_node
    device_info["score_reasons"] = []
    device_info["suspicious_reasons"] = []
    device_info["file_results"] = []
    device_info["scan_step"]   = "enumerated"
    add_device(device_node, device_info)          # update placeholder with real info
    print(f"✅ Enumerated: {device_info}")

    # ── 2. Classify ───────────────────────────────────────────────────────────
    update_device(device_node, scan_step="classifying")
    device_class = classify_device(device_info, device_info)
    # If classifier returns unknown but we know it's storage/hid, use that
    if device_class == "unknown" and device_type in ("storage", "hid", "network", "video"):
        device_class = device_type
    device_info["device_class"] = device_class
    update_device(device_node, device_class=device_class, status="analysing", scan_step="classified")
    print(f"📦 Class: {device_class}")

    # ── 2.5. Whitelist Check (fast-track known good devices) ────────────────────
    vendor_id  = device_info.get("vendor_id", "unknown")
    product_id = device_info.get("product_id", "unknown")
    serial_num = device_info.get("serial_number", "unknown")
    
    if is_device_blocked(vendor_id, product_id, serial_num):
        print(f"🚫 Device in blocklist — rejecting immediately")
        device_info["status"]      = "done"
        device_info["decision"]    = "block"
        device_info["trust_score"] = 0
        device_info["risk_level"]  = "HIGH"
        device_info["score_reasons"] = [{"label": "Device in permanent blocklist", "points": -100, "positive": False}]
        update_device(device_node, status="done", decision="block", trust_score=0, risk_level="HIGH",
                      score_reasons=[{"label": "Device in permanent blocklist", "points": -100, "positive": False}])
        store_device(device_info)
        create_device_block_alert(device_node)
        enforce_decision("block", device_node, device_info)
        return

    if is_device_whitelisted(vendor_id, product_id, serial_num):
        # Re-scan if whitelisted more than 7 days ago
        conn = __import__('sqlite3').connect(
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database/device_logs.db'))
        row = conn.execute(
            "SELECT last_scan_timestamp FROM device_whitelist WHERE vendor_id=? AND product_id=? AND serial_number=?",
            (vendor_id, product_id, serial_num)).fetchone()
        conn.close()
        stale = (not row) or (__import__('time').time() - (row[0] or 0) > 7 * 86400)

        if not stale:
            print(f"✅ Device whitelisted — fast-track ALLOW (skipping full scan)")
            # For storage: mount, list files as clean, unmount — no scan needed
            fast_file_results = []
            if device_class == "storage":
                update_device(device_node, status="scanning")
                mount_point = mount_usb(device_node)
                if mount_point:
                    file_list = extract_files(mount_point)
                    fast_file_results = [
                        {"file": os.path.basename(f), "path": f, "status": "clean"}
                        for f in file_list
                    ]
                    unmount_usb(device_node)
            device_info["status"]      = "done"
            device_info["decision"]    = "allow"
            wl_score, wl_reasons = compute_trust_score(
                device_info, False,
                {"infected_files": 0, "suspicious_files": []}
            )
            device_info["trust_score"] = wl_score
            device_info["risk_level"]  = trust_score_to_risk(wl_score)
            device_info["score_reasons"] = wl_reasons
            device_info["file_results"] = fast_file_results
            update_device(device_node, status="done", decision="allow",
                          trust_score=wl_score, risk_level=trust_score_to_risk(wl_score),
                          score_reasons=wl_reasons, file_results=fast_file_results)
            store_device(device_info)
            create_alert("DEVICE_ALLOWED", f"Device whitelisted (fast-track)", device_node)
            enforce_decision("allow", device_node, device_info)
            if device_class == "storage" and fast_file_results:
                update_device(device_node, status="forwarding")
                forward_clean_files([f["path"] for f in fast_file_results], device_node)
            return
        else:
            print(f"🔄 Whitelist entry stale (>7 days) — running full re-scan")

    # ── 3. Suspicious check ───────────────────────────────────────────────────
    update_device(device_node, scan_step="behaviour_check")
    suspicious, suspicious_reasons = detect_suspicious(device_info, device_info)

    # ── 3.5 HID firmware / injection check ───────────────────────────────────
    if device_class in ("hid", "unknown"):
        hid_suspicious, hid_reasons = detect_hid_attack(device_info)
        if hid_suspicious:
            suspicious = True
            suspicious_reasons = suspicious_reasons + hid_reasons

    device_info["suspicious"] = suspicious
    device_info["suspicious_reasons"] = suspicious_reasons
    update_device(device_node, suspicious=suspicious, scan_step="behaviour_done")
    if suspicious:
        print(f"⚠️  Suspicious behaviour on {device_node}")
        create_suspicious_device_alert(device_node, suspicious_reasons)

    # ── 4. Sandbox scan (storage only) ────────────────────────────────────────
    scan_report  = None
    file_results = []

    if device_class == "storage":
        update_device(device_node, status="scanning", scan_step="mounting")
        mount_point = mount_usb(device_node)

        if mount_point:
            update_device(device_node, scan_step="extracting")
            file_list = extract_files(mount_point)
            print(f"📂 {len(file_list)} files in {device_node}")
            update_device(device_node, scan_step="clamav", file_count=len(file_list))

            if file_list:
                scan_report = run_malware_scan(file_list)
                scan_report["device_node"] = device_node

                update_device(device_node, scan_step="yara")

                infected_set   = set(scan_report.get("infected_list", []))
                suspicious_set = set(scan_report.get("suspicious_files", []))
                for f in file_list:
                    if f in infected_set:       fstatus = "infected"
                    elif f in suspicious_set:   fstatus = "suspicious"
                    else:                       fstatus = "clean"
                    file_results.append({
                        "file":   os.path.basename(f),
                        "path":   f,
                        "status": fstatus
                    })

                # Fallback: if file_results empty but scan ran, build from clamav clean list
                if not file_results:
                    infected_set = set(scan_report.get("infected_list", []))
                    for f in scan_report.get("_clean_list", []):
                        file_results.append({"file": os.path.basename(f), "path": f,
                                             "status": "infected" if f in infected_set else "clean"})
                store_malware_report({**scan_report, "file_results": file_results})
                if scan_report.get("infected_files", 0) > 0:
                    create_malware_alert(device_node, scan_report["infected_list"])

            unmount_usb(device_node)

    # ── 5. Trust Score ────────────────────────────────────────────────────────
    update_device(device_node, scan_step="scoring")
    trust_score, score_reasons = compute_trust_score(device_info, suspicious, scan_report)
    device_info["trust_score"]   = trust_score
    device_info["score_reasons"] = score_reasons
    device_info["file_results"]  = file_results
    print(f"🔢 Trust Score: {trust_score}")

    # ── 6. Decision ───────────────────────────────────────────────────────────
    update_device(device_node, scan_step="deciding")
    decision   = make_decision(trust_score)
    risk_level = trust_score_to_risk(trust_score)
    device_info["decision"]   = decision
    device_info["risk_level"] = risk_level
    device_info["scan_report"] = scan_report or {}
    print(f"⚖️  Decision: {decision.upper()}")

    update_device(device_node,
        trust_score   = trust_score,
        score_reasons = score_reasons,
        file_results  = file_results,
        decision      = decision,
        risk_level    = risk_level,
        status        = "done"
    )

    # ── 7. Enforce + Forward ──────────────────────────────────────────────────
    enforce_decision(decision, device_node, device_info)

    if decision == "allow" and device_class == "storage":
        update_device(device_node, status="forwarding", scan_step="forwarding")
        clean_files = [f["path"] for f in file_results if f["status"] == "clean"]
        forward_clean_files(clean_files, device_node)
        create_alert("DEVICE_ALLOWED",
                     f"Device allowed — {len(clean_files)} clean files forwarded (score={trust_score})",
                     device_node)
    elif decision == "allow":
        create_alert("DEVICE_ALLOWED",   f"Device allowed (score={trust_score})", device_node)
    elif decision == "sandbox":
        create_alert("DEVICE_SANDBOXED", f"Device sandboxed (score={trust_score})", device_node)
    elif decision == "block":
        create_device_block_alert(device_node)

    # ── 7.5 Whitelist Management ──────────────────────────────────────────────
    if decision == "allow" and trust_score > 70:
        if add_to_whitelist(device_info, trust_score):
            print(f"⭐ Added to whitelist: {vendor_id}:{product_id} SN:{serial_num}")

    # ── 8. Store ──────────────────────────────────────────────────────────────
    update_device(device_node, status="done")
    store_device(device_info)
    print(f"💾 Done — {device_node}  decision={decision}  score={trust_score}")


def trust_score_to_risk(score):
    if score > 70:    return "LOW"
    elif score >= 40: return "MEDIUM"
    else:             return "HIGH"


_browser_opened = False
_browser_lock   = threading.Lock()

def _open_browser():
    global _browser_opened
    with _browser_lock:
        if _browser_opened:
            return
        _browser_opened = True
    time.sleep(1)
    try:
        subprocess.Popen(
            ["sudo", "-u", "glitch",
             "env", "DISPLAY=:0",
             "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
             "chromium", "--new-window", "http://localhost:5000"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        print("🌐 Browser opened")
    except Exception as e:
        print(f"⚠️  Browser open failed: {e}")


def usb_event_callback(event):
    print(f"\n🔌 Event: {event}")
    device_node = event["device"]
    action      = event.get("action", "add")
    device_type = event.get("type", "usb")

    if action == "remove":
        remove_device(device_node)
        print(f"   {device_node} removed from dashboard")
        return

    # Open browser on first device insertion
    threading.Thread(target=_open_browser, daemon=True).start()

    # Show placeholder card immediately — real info filled in by process_device
    add_device(device_node, {
        "device_node":  device_node,
        "status":       "analysing",
        "device_class": device_type,
        "manufacturer": "Detecting...",
        "product":      "",
    })

    threading.Thread(
        target=process_device,
        args=(device_node, device_type),
        daemon=True
    ).start()


def start_api():
    print("🌐 Starting API server...")
    app.run(host="0.0.0.0", port=5000, use_reloader=False)


def main():
    print("\n🛡️  USB Security Gateway Started\n")
    init_db()
    cleanup_stale_mounts()
    threading.Thread(target=start_api, daemon=True).start()
    start_usb_monitor(usb_event_callback)
    while True:
        time.sleep(5)


if __name__ == "__main__":
    main()
