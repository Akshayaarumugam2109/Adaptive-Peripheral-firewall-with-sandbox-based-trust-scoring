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
        True if suspicious
    """

    try:

        logger.info("Running suspicious device analysis")

        suspicious = False

        vendor_id = metadata.get("vendor_id")
        product_id = metadata.get("product_id")
        serial = metadata.get("serial_number")

        interfaces = metadata.get("usb_interfaces")
        sysfs_class = sysfs_data.get("device_class")

        # -------------------------------------
        # Rule 1: Missing vendor or product ID
        # -------------------------------------
        if not vendor_id or not product_id:

            logger.warning("Missing vendor/product ID")
            suspicious = True

        # -------------------------------------
        # Rule 2: No serial number
        # -------------------------------------
        if not serial:

            logger.warning("Device has no serial number")
            suspicious = True

        # -------------------------------------
        # Rule 3: Descriptor mismatch
        # -------------------------------------
        if interfaces and sysfs_class:

            if "08" in interfaces and sysfs_class.lower() != "storage":

                logger.warning("Descriptor mismatch detected")
                suspicious = True

        # -------------------------------------
        # Rule 4: Composite attack
        # -------------------------------------
        if interfaces and ":" in interfaces:

            interface_count = interfaces.count(":")

            if interface_count > 4:

                logger.warning("Excessive interfaces detected")
                suspicious = True

        # -------------------------------------
        # Rule 5: Fake HID attack
        # -------------------------------------
        if interfaces and "03" in interfaces and sysfs_class != "HID":

            logger.warning("Possible BadUSB HID attack")
            suspicious = True

        if suspicious:

            logger.warning("Device marked as suspicious")

        else:

            logger.info("Device appears normal")

        return suspicious

    except Exception as e:

        logger.error(f"Suspicious detection failed: {str(e)}")

        return True
