#!/usr/bin/env python3
"""
USB Port Disable Module

Disables the USB port connected to a malicious device
using Linux sysfs interface.

Author: USB Security Gateway
"""

import subprocess
import logging
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "../../logs/gateway.log")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("USB-Port-Disable")


def get_sysfs_path(device_node):
    """
    Retrieve sysfs path for USB device.

    Example:
        /dev/sdb ? /sys/bus/usb/devices/1-1.3
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


def disable_usb_port(device_node):
    """
    Disable USB port connected to device.
    """

    try:

        logger.info(f"Disabling USB port for {device_node}")

        sysfs_path = get_sysfs_path(device_node)

        if not sysfs_path:
            return False

        authorized_file = os.path.join(sysfs_path, "authorized")

        if not os.path.exists(authorized_file):

            logger.error("USB port authorization file not found")
            return False

        with open(authorized_file, "w") as f:

            f.write("0")

        logger.warning(f"USB port disabled for {device_node}")

        return True

    except PermissionError:

        logger.error("Permission denied (run gateway as root)")

    except Exception as e:

        logger.error(f"USB port disable failed: {str(e)}")

    return False
