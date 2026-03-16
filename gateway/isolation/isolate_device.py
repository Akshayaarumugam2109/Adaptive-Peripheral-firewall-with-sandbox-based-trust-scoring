#!/usr/bin/env python3
"""
Device Isolation Module

Immediately isolates a USB device after detection
to prevent interaction with the host system.

Isolation methods:
? Driver unbinding
? USBGuard policy blocking (optional)

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

logger = logging.getLogger("USB-Isolation")


def get_usb_id(device_node):
    """
    Extract USB device ID from sysfs path using udevadm.

    Example return:
        1-1.3
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

        for p in parts:
            if "-" in p:
                return p

    except Exception as e:
        logger.error(f"USB ID extraction failed: {str(e)}")

    return None


def isolate_usb_device(device_node):
    """
    Isolate USB device using driver unbinding.
    """

    try:

        usb_id = get_usb_id(device_node)

        if not usb_id:
            logger.error("USB ID not found")
            return False

        unbind_path = "/sys/bus/usb/drivers/usb/unbind"

        if not os.path.exists(unbind_path):
            logger.error("USB driver interface missing")
            return False

        with open(unbind_path, "w") as f:
            f.write(usb_id)

        logger.info(f"USB device isolated: {usb_id}")

        return True

    except PermissionError:

        logger.error("Permission denied - run as root")

    except Exception as e:

        logger.error(f"Isolation failed: {str(e)}")

    return False
