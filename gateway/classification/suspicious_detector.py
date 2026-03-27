#!/usr/bin/env python3
"""
Suspicious Device Detection Module

Detects firmware-level USB attacks such as:

? BadUSB
? Fake HID devices
? Descriptor mismatch
? Device impersonation

Author: USB Security Gateway
"""

import logging
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "../../logs/gateway.log")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("Suspicious-Detector")


def detect_suspicious(metadata, sysfs_data):
    """
    Analyze device fingerprint for suspicious behavior.

    Returns:
        tuple: (suspicious: bool, reasons: list of strings explaining why)
    """

    try:

        logger.info("Running suspicious device analysis")

        suspicious = False
        reasons = []

        vendor_id = metadata.get("vendor_id")
        product_id = metadata.get("product_id")
        serial = metadata.get("serial_number")

        interfaces = metadata.get("usb_interfaces")
        sysfs_class = sysfs_data.get("device_class")

        # Rule 1: Missing vendor or product ID
        # Skip this check for storage devices — they are identified by block device node
        if sysfs_class and sysfs_class.lower() not in ("storage", "unknown", ""):
            if not vendor_id or vendor_id == "unknown" or not product_id or product_id == "unknown":
                reason = "Device is missing vendor ID or product ID in USB descriptor (potential firmware spoofing)"
                logger.warning(reason)
                reasons.append(reason)
                suspicious = True

        # -------------------------------------
        # Rule 2: No serial number
        # (skip if unknown — many valid devices omit serial)
        # -------------------------------------
        if serial and serial != "unknown" and len(serial.strip()) == 0:
            reason = "Device has empty serial number field (indicates missing device identity)"
            logger.warning(reason)
            reasons.append(reason)
            suspicious = True

        # -------------------------------------
        # Rule 3: Descriptor mismatch
        # -------------------------------------
        if interfaces and sysfs_class and sysfs_class.lower() not in ("unknown", ""):
            # Parse interface classes from colon-delimited string e.g. ":080650:"
            iface_classes = [interfaces[i+1:i+3] for i in range(len(interfaces)) if interfaces[i] == ":" and i+3 <= len(interfaces)]

            if "08" in iface_classes and sysfs_class.lower() != "storage":
                reason = f"Descriptor mismatch: Device reports storage class (0x08) but kernel detected as {sysfs_class} (BadUSB signature)"
                logger.warning(reason)
                reasons.append(reason)
                suspicious = True

        # -------------------------------------
        # Rule 4: Composite attack
        # -------------------------------------
        if interfaces and ":" in interfaces:

            interface_count = interfaces.count(":")

            if interface_count > 4:

                reason = f"Excessive interfaces detected ({interface_count}): Device claims {interface_count + 1} different USB classes (composite device attack vector)"
                logger.warning(reason)
                reasons.append(reason)
                suspicious = True

        # -------------------------------------
        # Rule 5: Fake HID attack
        # -------------------------------------
        if interfaces and sysfs_class and sysfs_class.lower() not in ("unknown", ""):
            iface_classes = [interfaces[i+1:i+3] for i in range(len(interfaces)) if interfaces[i] == ":" and i+3 <= len(interfaces)]

            if "03" in iface_classes and sysfs_class.lower() != "hid":
                reason = f"HID class mismatch: Device reports HID (0x03) interface but kernel detected as {sysfs_class} (BadUSB/rubber ducky attack signature)"
                logger.warning(reason)
                reasons.append(reason)
                suspicious = True

        if suspicious:

            logger.warning(f"Device marked as suspicious with {len(reasons)} violations")

        else:

            logger.info("Device appears normal")

        return suspicious, reasons

    except Exception as e:

        logger.error(f"Suspicious detection failed: {str(e)}")

        return True, [f"Detection error: {str(e)}"]
