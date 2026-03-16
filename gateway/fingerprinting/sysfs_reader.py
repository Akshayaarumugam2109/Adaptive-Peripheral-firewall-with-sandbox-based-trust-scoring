#!/usr/bin/env python3
"""
SysFS USB Reader Module

Reads USB device information directly from the Linux kernel
sysfs filesystem.

Location:
    /sys/bus/usb/devices/

This provides reliable hardware-level information about USB
interfaces and classes.

Used for:
? Device fingerprinting
? Detecting firmware manipulation
? Identifying real device class

Author: USB Security Gateway
"""

import os
import subprocess
import logging

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "../../logs/gateway.log")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("SysFS-Reader")


def get_sysfs_path(device_node):
    """
    Convert device node (/dev/sdb) to sysfs path.
    """

    try:

        result = subprocess.run(
            ["udevadm", "info", "-q", "path", "-n", device_node],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode != 0:
            logger.error("Unable to determine sysfs path")
            return None

        return "/sys" + result.stdout.strip()

    except Exception as e:
        logger.error(f"Sysfs path retrieval failed: {str(e)}")

    return None


def read_file_safe(path):
    """
    Safely read sysfs file.
    """

    try:

        if os.path.exists(path):

            with open(path, "r") as f:
                return f.read().strip()

    except Exception as e:

        logger.error(f"Failed reading {path}: {str(e)}")

    return None


def detect_device_class(interface_class):
    """
    Convert USB interface class code to readable type.
    """

    class_map = {

        "03": "HID",
        "08": "Storage",
        "02": "Network",
        "0a": "CDC Data",
        "0e": "Video",
        "09": "Hub"

    }

    return class_map.get(interface_class.lower(), "Unknown")


def read_sysfs(device_node):
    """
    Read USB device attributes from sysfs.

    Returns dictionary describing hardware interfaces.
    """

    try:

        logger.info(f"Reading sysfs for {device_node}")

        sysfs_path = get_sysfs_path(device_node)

        if not sysfs_path:
            return None

        # Device attributes
        vendor_id = read_file_safe(os.path.join(sysfs_path, "idVendor"))
        product_id = read_file_safe(os.path.join(sysfs_path, "idProduct"))
        manufacturer = read_file_safe(os.path.join(sysfs_path, "manufacturer"))
        product = read_file_safe(os.path.join(sysfs_path, "product"))
        serial = read_file_safe(os.path.join(sysfs_path, "serial"))

        interface_class = read_file_safe(os.path.join(sysfs_path, "bDeviceClass"))

        device_class = detect_device_class(interface_class)

        sysfs_data = {

            "device_node": device_node,
            "vendor_id": vendor_id,
            "product_id": product_id,
            "manufacturer": manufacturer,
            "product": product,
            "serial_number": serial,
            "interface_class": interface_class,
            "device_class": device_class,
            "sysfs_path": sysfs_path

        }

        logger.info(f"SysFS data collected: {sysfs_data}")

        return sysfs_data

    except Exception as e:

        logger.error(f"Sysfs read failed: {str(e)}")

    return None
