#!/usr/bin/env python3
"""
USB Device Classification Module

Determines the real type of a USB device using:
? Metadata interfaces
? SysFS device class
? Kernel subsystem

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

logger = logging.getLogger("Device-Classification")


# USB interface class mapping
USB_CLASS_MAP = {
    "03": "HID",
    "08": "Storage",
    "02": "Network",
    "0e": "Video",
    "09": "Hub",
    "0a": "CDC Data"
}


def classify_device(metadata, sysfs_data):
    """
    Determine device type using metadata and sysfs.

    Returns:
        device_type (str)
    """

    try:

        logger.info("Starting device classification")

        device_class = sysfs_data.get("device_class")
        subsystem = metadata.get("subsystem")
        interfaces = metadata.get("usb_interfaces")

        # Priority 1: sysfs hardware class
        if device_class and device_class.lower() not in ("unknown", ""):
            logger.info(f"Classification via sysfs: {device_class}")
            return device_class.lower()

        # Priority 2: interface descriptor (parse colon-delimited e.g. ":080650:")
        if interfaces:
            iface_classes = [interfaces[i+1:i+3] for i in range(len(interfaces)) if interfaces[i] == ":" and i+3 <= len(interfaces)]
            for class_code, class_name in USB_CLASS_MAP.items():
                if class_code in iface_classes:
                    logger.info(f"Classification via interface: {class_name}")
                    return class_name.lower()

        # Priority 3: subsystem fallback
        if subsystem == "block":

            logger.info("Device classified as storage via subsystem")
            return "storage"

        logger.warning("Unable to determine device type")

        return "unknown"

    except Exception as e:

        logger.error(f"Classification failed: {str(e)}")

        return "unknown"
