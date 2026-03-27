#!/usr/bin/env python3
"""
HID Injection / BadUSB Detector

Detects keyboard/mouse devices that may be rubber ducky or HID injection attacks.
Called from main.py for HID-class devices before allowing them.
"""

import os
import logging

logger = logging.getLogger("Firmware-Detector")

# Known legitimate HID vendor IDs (keyboards, mice)
TRUSTED_HID_VENDORS = {
    "046d",  # Logitech
    "045e",  # Microsoft
    "04f2",  # Chicony
    "0461",  # Primax
    "04b3",  # IBM
    "04d9",  # Holtek (generic keyboards)
    "1c4f",  # SiGma Micro
    "258a",  # SINOWEALTH
    "0c45",  # Microdia
}

# Vendors commonly used in attack hardware (Hak5, cheap clones)
SUSPICIOUS_HID_VENDORS = {
    "1b4f",  # Hak5 / Rubber Ducky
    "f000",  # Common fake vendor
    "0000",  # Zero vendor
}


def detect_hid_attack(device_info: dict):
    """
    Analyse a HID device for injection attack indicators.

    Returns:
        (suspicious: bool, reasons: list[str])
    """
    suspicious = False
    reasons = []

    vendor_id  = (device_info.get("vendor_id") or "").lower().strip()
    product_id = (device_info.get("product_id") or "").lower().strip()
    serial     = (device_info.get("serial_number") or "").strip()
    interfaces = device_info.get("usb_interfaces", "")

    # Rule 1: Known attack vendor
    if vendor_id in SUSPICIOUS_HID_VENDORS:
        reasons.append(f"Known attack hardware vendor ID: {vendor_id}")
        suspicious = True

    # Rule 2: HID device with no vendor ID
    if not vendor_id or vendor_id in ("unknown", ""):
        reasons.append("HID device missing vendor ID — potential spoofed device")
        suspicious = True

    # Rule 3: HID + Storage composite (BadUSB classic pattern)
    if interfaces:
        iface_classes = [
            interfaces[i+1:i+3]
            for i in range(len(interfaces))
            if interfaces[i] == ":" and i+3 <= len(interfaces)
        ]
        has_hid     = "03" in iface_classes
        has_storage = "08" in iface_classes
        if has_hid and has_storage:
            reasons.append("Composite HID+Storage device — classic BadUSB attack pattern")
            suspicious = True

    # Rule 4: HID device with suspiciously short or missing serial
    if not serial or serial in ("unknown", ""):
        if vendor_id not in TRUSTED_HID_VENDORS:
            reasons.append("Untrusted HID vendor with no serial number")
            suspicious = True

    if suspicious:
        logger.warning(f"HID attack indicators on {device_info.get('device_node')}: {reasons}")
    else:
        logger.info(f"HID device {device_info.get('device_node')} passed firmware check")

    return suspicious, reasons
