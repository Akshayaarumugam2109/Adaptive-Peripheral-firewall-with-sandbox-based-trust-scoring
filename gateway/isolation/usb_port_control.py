#!/usr/bin/env python3
"""
USB Port Control Module

Provides low-level USB port control functions.

Capabilities:
? Disable USB port
? Enable USB port
? Reset USB device

Uses Linux sysfs interface.

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

logger = logging.getLogger("USB-Port-Control")


def get_usb_sysfs_path(device_node):
    """
    Retrieve sysfs path for a USB device.
    """

    try:

        result = subprocess.run(
            ["udevadm", "info", "-q", "path", "-n", device_node],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode != 0:
            return None

        return "/sys" + result.stdout.strip()

    except Exception as e:

        logger.error(f"Failed to get sysfs path: {str(e)}")

    return None


def disable_usb_port(device_node):
    """
    Disable USB port using sysfs authorized flag.
    """

    try:

        path = get_usb_sysfs_path(device_node)

        if not path:
            logger.error("Sysfs path not found")
            return False

        auth_file = os.path.join(path, "authorized")

        if not os.path.exists(auth_file):
            logger.error("Authorized control file missing")
            return False

        with open(auth_file, "w") as f:
            f.write("0")

        logger.info(f"USB port disabled for {device_node}")

        return True

    except PermissionError:

        logger.error("Permission denied (run as root)")

    except Exception as e:

        logger.error(f"Port disable failed: {str(e)}")

    return False


def enable_usb_port(device_node):
    """
    Re-enable USB port.
    """

    try:

        path = get_usb_sysfs_path(device_node)

        auth_file = os.path.join(path, "authorized")

        with open(auth_file, "w") as f:
            f.write("1")

        logger.info(f"USB port enabled for {device_node}")

        return True

    except Exception as e:

        logger.error(f"Port enable failed: {str(e)}")

    return False
