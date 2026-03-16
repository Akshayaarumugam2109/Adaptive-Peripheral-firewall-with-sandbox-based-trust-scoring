#!/usr/bin/env python3
"""
USB Device Blocking Module

Blocks malicious USB devices by unbinding them from the
kernel USB driver.

This prevents the device from interacting with the system.

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

logger = logging.getLogger("USB-Blocker")


def get_usb_id(device_node):
    """
    Extract USB device ID from udev sys path.

    Example:
        /dev/sdb ? 1-1.3
    """

    try:

        result = subprocess.run(
            ["udevadm", "info", "-q", "path", "-n", device_node],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode != 0:
            logger.error("Failed to retrieve udev path")
            return None

        path = result.stdout.strip()

        parts = path.split("/")

        for part in parts:

            if "-" in part:
                return part

    except Exception as e:

        logger.error(f"USB ID extraction failed: {str(e)}")

    return None


def block_device(device_node):
    """
    Block USB device by unbinding kernel driver.
    """

    try:

        logger.info(f"Blocking USB device {device_node}")

        usb_id = get_usb_id(device_node)

        if not usb_id:

            logger.error("Unable to determine USB ID")
            return False

        unbind_path = "/sys/bus/usb/drivers/usb/unbind"

        if not os.path.exists(unbind_path):

            logger.error("USB unbind interface missing")
            return False

        with open(unbind_path, "w") as f:

            f.write(usb_id)

        logger.warning(f"USB device blocked: {usb_id}")

        return True

    except PermissionError:

        logger.error("Permission denied (run gateway as root)")

    except Exception as e:

        logger.error(f"Device block failed: {str(e)}")

    return False
