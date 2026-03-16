#!/usr/bin/env python3
"""
Driver Control Module

Prevents automatic interaction between the host OS
and newly inserted USB devices.

Uses Linux driver unbinding mechanism:

/sys/bus/usb/drivers/usb/unbind

This stops the kernel from communicating with the device
until the security analysis completes.

Author: USB Security Gateway
"""

import logging
import os
import subprocess


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "../../logs/gateway.log")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("Driver-Control")


def get_usb_device_id(device_node):
    """
    Determine USB device identifier from sysfs.

    Example result:
        1-1.3
    """

    try:

        output = subprocess.run(
            ["udevadm", "info", "-q", "path", "-n", device_node],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if output.returncode != 0:
            logger.error("Failed to retrieve device path")
            return None

        path = output.stdout.strip()

        # Extract USB device identifier
        parts = path.split("/")

        for part in parts:

            if "-" in part:
                return part

    except Exception as e:
        logger.error(f"Device ID extraction failed: {str(e)}")

    return None


def unbind_driver(device_node):
    """
    Unbind USB driver to prevent OS interaction.

    Returns:
        True if successful
    """

    try:

        usb_id = get_usb_device_id(device_node)

        if not usb_id:
            logger.error("Unable to determine USB device ID")
            return False

        unbind_path = "/sys/bus/usb/drivers/usb/unbind"

        if not os.path.exists(unbind_path):

            logger.error("USB unbind interface not available")
            return False

        with open(unbind_path, "w") as f:
            f.write(usb_id)

        logger.info(f"Driver unbound for USB device {usb_id}")

        return True

    except PermissionError:

        logger.error("Permission denied (run gateway as root)")

    except Exception as e:

        logger.error(f"Driver unbind failed: {str(e)}")

    return False
