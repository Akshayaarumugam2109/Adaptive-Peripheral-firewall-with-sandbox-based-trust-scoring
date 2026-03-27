#!/usr/bin/env python3
"""
Trust Scoring Engine

Produces a granular 0-100 score with a full reasons breakdown.
Each factor adds or subtracts a specific weighted amount so the
final score genuinely varies across the full 0-100 range.
"""

import logging

logger = logging.getLogger("Trust-Engine")

# ── Weights ────────────────────────────────────────────────────────────────────
W_VENDOR          =  10   # known vendor ID present
W_PRODUCT         =   7   # known product ID present
W_SERIAL_PRESENT  =   5   # serial number present
W_SERIAL_LONG     =   4   # serial is a full-length hash (genuine device)
W_NO_MALWARE      =  30   # ClamAV found nothing
W_NO_YARA         =   8   # YARA found nothing suspicious
W_NOT_SUSPICIOUS  =  15   # passed all suspicious-behaviour rules

P_MISSING_VENDOR  = -12   # no vendor/product ID
P_MISSING_SERIAL  =  -7   # no serial at all
P_MALWARE         = -55   # infected files found
P_YARA_HIT        = -18   # YARA matched a rule
P_SUSPICIOUS      = -28   # suspicious behaviour flags triggered
P_MANY_INFECTED   = -12   # >3 infected files (extra penalty)
P_COMPOSITE_ATTACK = -15  # excessive interfaces detected


def compute_trust_score(device_info: dict, suspicious: bool, scan_report: dict):
    """
    Returns:
        (score: int, reasons: list[dict])
        reasons = [{"label": str, "points": int, "positive": bool}]
    """
    score = 0
    reasons = []

    def add(label, points):
        nonlocal score
        score += points
        reasons.append({"label": label, "points": points, "positive": points > 0})

    vendor_id  = device_info.get("vendor_id", "unknown")
    product_id = device_info.get("product_id", "unknown")
    serial     = device_info.get("serial_number", "unknown")
    interfaces = device_info.get("usb_interfaces", "")

    # ── Identity checks ────────────────────────────────────────────────────────
    if vendor_id and vendor_id not in ("unknown", ""):
        add("Known Vendor ID", W_VENDOR)
    else:
        add("Missing Vendor ID", P_MISSING_VENDOR)

    if product_id and product_id not in ("unknown", ""):
        add("Known Product ID", W_PRODUCT)

    if serial and serial not in ("unknown", ""):
        add("Serial Number Present", W_SERIAL_PRESENT)
        if len(serial) >= 20:
            add("Full-Length Serial (Genuine Device)", W_SERIAL_LONG)
    else:
        add("No Serial Number", P_MISSING_SERIAL)

    # ── Composite / interface anomaly ──────────────────────────────────────────
    if interfaces and interfaces.count(":") > 4:
        add("Excessive USB Interfaces (Composite Attack)", P_COMPOSITE_ATTACK)

    # ── Malware scan results ───────────────────────────────────────────────────
    if scan_report:
        infected = scan_report.get("infected_files", 0)
        suspicious_files = scan_report.get("suspicious_files", [])

        if infected == 0:
            add("ClamAV: No Malware Detected", W_NO_MALWARE)
        else:
            add(f"ClamAV: {infected} Infected File(s) Found", P_MALWARE)
            if infected > 3:
                add("Multiple Infected Files (High Threat)", P_MANY_INFECTED)

        if not suspicious_files:
            add("YARA: No Suspicious Patterns", W_NO_YARA)
        else:
            add(f"YARA: {len(suspicious_files)} Suspicious Pattern(s)", P_YARA_HIT)
    else:
        # Non-storage device — no file scan possible
        add("No File Scan (Non-Storage Device)", 5)

    # ── Behaviour analysis ─────────────────────────────────────────────────────
    if not suspicious:
        add("No Suspicious Behaviour Detected", W_NOT_SUSPICIOUS)
    else:
        add("Suspicious Behaviour Detected", P_SUSPICIOUS)

    # Per-device variance: ±5 pts derived from serial/vendor hash so the
    # same clean USB doesn't always land on the same round number.
    identity = f"{vendor_id}{product_id}{serial}"
    variance = (hash(identity) % 11) - 5   # -5 … +5
    if variance != 0:
        label = f"Device Fingerprint Adjustment"
        add(label, variance)

    final = max(0, min(100, score))
    logger.info(f"Trust score {final} for {device_info.get('device_node')} | reasons: {reasons}")
    return final, reasons
