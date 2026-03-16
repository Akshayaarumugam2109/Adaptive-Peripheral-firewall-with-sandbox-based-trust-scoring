"""
USB Security Gateway - Main Controller

Controls the entire USB security workflow.

Pipeline:
USB Detect ? Enumeration ? Driver Control ? Isolation
? Fingerprinting ? Classification ? Suspicious Detection
? Block or Sandbox ? Alert

Runs on Raspberry Pi (Kali / Debian).
"""

import os
import sys
import time
import logging

from gateway.usb_monitor.monitor import start_usb_monitor
from gateway.usb_monitor.enumeration import enumerate_device
from gateway.usb_monitor.driver_control import unbind_driver

from gateway.isolation.isolate_device import isolate_usb_device

from gateway.fingerprinting.metadata_extractor import extract_metadata
from gateway.fingerprinting.sysfs_reader import read_sysfs

from gateway.classification.classify_device import classify_device
from gateway.classification.suspicious_detector import detect_suspicious

from gateway.blocking.block_device import block_device

from gateway.alerts.alert_manager import create_alert

from gateway.database.db import init_db, store_device

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "../logs/gateway.log")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("USB-Gateway")

def process_device(device_node):
    """
    Full device processing pipeline.
    """

    try:

        logger.info(f"Processing device: {device_node}")

        # --------------------------------
        # ENUMERATION
        # --------------------------------
        device_info = enumerate_device(device_node)

        if not device_info:
            logger.warning("Enumeration failed")
            return

        store_device(device_info)

        # --------------------------------
        # DRIVER CONTROL
        # --------------------------------
        unbind_driver(device_node)

        # --------------------------------
        # ISOLATION
        # --------------------------------
        isolate_usb_device(device_node)

        # --------------------------------
        # FINGERPRINTING
        # --------------------------------
        metadata = extract_metadata(device_node)
        sysfs_data = read_sysfs(device_node)

        # --------------------------------
        # CLASSIFICATION
        # --------------------------------
        device_class = classify_device(metadata, sysfs_data)

        logger.info(f"Device classified as: {device_class}")

        # --------------------------------
        # SUSPICIOUS DETECTION
        # --------------------------------
        suspicious = detect_suspicious(metadata, sysfs_data)

        if suspicious:

            logger.warning("Suspicious USB detected")

            block_device(device_node)

            create_alert(
                "Suspicious USB Device",
                f"Blocked device {device_node}"
            )

            return

        # --------------------------------
        # SANDBOX (STORAGE DEVICES)
        # --------------------------------
        if device_class == "storage":

            logger.info("Sending device to sandbox")

            mount_path = mount_usb(device_node)

            files = extract_files(mount_path)

            scan_report = run_malware_scan(files)

            logger.info(f"Malware scan report: {scan_report}")

        logger.info("Device processing completed")

    except Exception as e:

        logger.error(f"Device processing error: {str(e)}")
def usb_event_callback(device_node):
    """
    Called when monitor detects a USB device.
    """

    logger.info(f"USB event triggered for {device_node}")

    process_device(device_node)


def main():

    print("\nUSB Security Gateway Started\n")

    logger.info("Gateway started")

    # Initialize database
    init_db()

    try:

        # Start monitoring USB events
        start_usb_monitor(usb_event_callback)

        # Keep program alive
        while True:
            time.sleep(5)

    except KeyboardInterrupt:

        logger.info("Gateway shutdown")

        print("Stopping gateway...")


if __name__ == "__main__":
    main()
