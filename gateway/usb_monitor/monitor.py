"""
USB Monitor Module

Detects USB devices in real time using Linux udev.

Triggers callback when a new device appears.

Supports detection of:
? USB storage devices
? HID devices
? composite USB devices

Uses:
pyudev
"""

import pyudev
import logging
import os


# -----------------------------
# Logging Setup
# -----------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "../../logs/gateway.log")

os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("USB-Monitor")


# -----------------------------
# Extract Device Node
# -----------------------------

def extract_device_node(device):
    """
    Extract device node such as /dev/sdb
    """

    try:

        if device.device_node:
            return device.device_node

        for child in device.children:
            if child.device_node:
                return child.device_node

    except Exception as e:

        logger.error(f"Device node extraction error: {str(e)}")

    return None

def start_usb_monitor(callback):
    """
    Start real-time USB monitoring.

    callback(device_node)
    """

    logger.info("Starting USB monitor")

    context = pyudev.Context()

    monitor = pyudev.Monitor.from_netlink(context)

    monitor.filter_by(subsystem="usb")
    monitor.filter_by(subsystem="block")

    monitor.start()

    logger.info("USB monitor running")

    for device in iter(monitor.poll, None):

        try:

            handle_event(device.action, device, callback)

        except Exception as e:

            logger.error(f"Monitor loop error: {str(e)}")


# -----------------------------
# Handle USB Events
# -----------------------------

def handle_event(action, device, callback):
    """
    Handle udev events
    """

    try:

        if action != "add":
            return

        logger.info(f"USB event detected: {device}")

        device_node = extract_device_node(device)

        if device_node:

            logger.info(f"Device node detected: {device_node}")

            callback(device_node)

        else:

            logger.warning("USB detected but device node not found")

    except Exception as e:

        logger.error(f"USB monitor error: {str(e)}")
