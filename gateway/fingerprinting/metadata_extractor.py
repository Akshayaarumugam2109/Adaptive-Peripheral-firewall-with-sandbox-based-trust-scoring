#!/usr/bin/env python3
"""
USB Metadata Extraction Module

Uses Linux udevadm to extract detailed metadata for a USB device.
This metadata is used to build a fingerprint profile and detect
suspicious or malicious devices.

Data extracted:
? Vendor ID
? Product ID
? Manufacturer
? Product Name
? Serial Number
? Device Type
? Interface Class
? Subsystem

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

logger = logging.getLogger("USB-Metadata")


def run_command(cmd):
    """
    Safely execute Linux command and return output.
    """

    try:

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10
        )

        if result.returncode != 0:
            logger.error(f"Command failed: {' '.join(cmd)}")
            logger.error(result.stderr)
            return None

        return result.stdout.strip()

    except Exception as e:

        logger.error(f"Command execution error: {str(e)}")

    return None


def parse_udev_properties(output):
    """
    Convert udevadm property output into dictionary.
    """

    metadata = {}

    for line in output.splitlines():

        if "=" not in line:
            continue

        key, value = line.split("=", 1)

        metadata[key.strip()] = value.strip()

    return metadata


def extract_metadata(device_node):
    """
    Extract USB device metadata using udevadm.

    Example device node:
        /dev/sdb

    Returns:
        dict containing USB metadata
    """

    try:

        logger.info(f"Extracting metadata for {device_node}")

        output = run_command(
            ["udevadm", "info", "--query=property", "--name", device_node]
        )

        if not output:
            logger.error("udevadm returned no output")
            return None

        properties = parse_udev_properties(output)

        metadata = {

            "device_node": device_node,
            "vendor_id": properties.get("ID_VENDOR_ID"),
            "product_id": properties.get("ID_MODEL_ID"),
            "manufacturer": properties.get("ID_VENDOR"),
            "product": properties.get("ID_MODEL"),
            "serial_number": properties.get("ID_SERIAL_SHORT"),
            "device_type": properties.get("DEVTYPE"),
            "subsystem": properties.get("SUBSYSTEM"),
            "bus": properties.get("ID_BUS"),
            "usb_interfaces": properties.get("ID_USB_INTERFACES")

        }

        logger.info(f"Metadata extracted: {metadata}")

        return metadata

    except Exception as e:

        logger.error(f"Metadata extraction failed: {str(e)}")

    return None
