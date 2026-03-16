#!/usr/bin/env python3
"""
USB Enumeration Module

Extracts USB device descriptor information using:
? udevadm
? lsusb
? /sys filesystem

Used during the enumeration phase of the USB Security Gateway pipeline.

Outputs structured device metadata used for classification
and security analysis.

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

logger = logging.getLogger("USB-Enumeration")


def run_command(cmd):
    """
    Safely run a Linux command and return output.
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
    Convert udevadm output into dictionary.
    """

    data = {}

    for line in output.splitlines():

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        data[key.strip()] = value.strip()

    return data


def get_lsusb_data(vendor_id, product_id):
    """
    Find bus and device number using lsusb.
    """

    try:

        output = run_command(["lsusb"])

        if not output:
            return None, None

        for line in output.splitlines():

            if f"{vendor_id}:{product_id}" in line:

                parts = line.split()

                bus = parts[1]
                device = parts[3].replace(":", "")

                return bus, device

    except Exception as e:
        logger.error(f"lsusb parsing error: {str(e)}")

    return None, None


def enumerate_device(device_node):
    """
    Perform USB enumeration.

    Parameters:
        device_node (str) : Example /dev/sdb

    Returns:
        dict containing device metadata
    """

    try:

        logger.info(f"Starting enumeration for {device_node}")

        # Query device metadata from udev
        output = run_command(
            ["udevadm", "info", "--query=property", "--name", device_node]
        )

        if not output:
            logger.error("Failed to retrieve udev metadata")
            return None

        udev_data = parse_udev_properties(output)

        vendor_id = udev_data.get("ID_VENDOR_ID")
        product_id = udev_data.get("ID_MODEL_ID")

        manufacturer = udev_data.get("ID_VENDOR")
        product = udev_data.get("ID_MODEL")

        serial = udev_data.get("ID_SERIAL_SHORT")

        # Get USB bus/device info
        bus, device = get_lsusb_data(vendor_id, product_id)

        device_info = {

            "device_node": device_node,
            "vendor_id": vendor_id,
            "product_id": product_id,
            "manufacturer": manufacturer,
            "product": product,
            "serial_number": serial,
            "bus_number": bus,
            "device_number": device

        }

        logger.info(f"Enumeration complete: {device_info}")

        return device_info

    except Exception as e:

        logger.error(f"Enumeration error: {str(e)}")

        return None
