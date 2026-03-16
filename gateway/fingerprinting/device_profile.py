#!/usr/bin/env python3
"""
Device Fingerprint Profile Module

Builds a structured fingerprint profile for a USB device
using metadata, enumeration data, and sysfs hardware info.

The fingerprint is used for:

? Device identity tracking
? Suspicious firmware detection
? Known device recognition
? Behavioral analysis

Author: USB Security Gateway
"""

import hashlib
import json
import logging
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "../../logs/gateway.log")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("Device-Fingerprint")


def generate_fingerprint_hash(profile_data):
    """
    Generate SHA256 fingerprint for the device profile.
    """

    try:

        profile_string = json.dumps(profile_data, sort_keys=True)

        fingerprint = hashlib.sha256(profile_string.encode()).hexdigest()

        return fingerprint

    except Exception as e:

        logger.error(f"Fingerprint hash generation failed: {str(e)}")

        return None


def build_device_profile(enum_data, metadata, sysfs_data):
    """
    Build a unified fingerprint profile.

    Parameters:
        enum_data : dict from enumeration module
        metadata : dict from metadata extractor
        sysfs_data : dict from sysfs reader

    Returns:
        device profile dictionary
    """

    try:

        logger.info("Building device fingerprint profile")

        profile = {

            "device_node": enum_data.get("device_node"),

            # Vendor information
            "vendor_id": enum_data.get("vendor_id") or sysfs_data.get("vendor_id"),
            "product_id": enum_data.get("product_id") or sysfs_data.get("product_id"),

            "manufacturer": metadata.get("manufacturer"),
            "product_name": metadata.get("product"),

            # Serial number
            "serial_number": metadata.get("serial_number"),

            # Bus information
            "bus_number": enum_data.get("bus_number"),
            "device_number": enum_data.get("device_number"),

            # Interface information
            "usb_interfaces": metadata.get("usb_interfaces"),
            "device_class": sysfs_data.get("device_class"),

            # Kernel subsystem
            "subsystem": metadata.get("subsystem"),

            # Hardware path
            "sysfs_path": sysfs_data.get("sysfs_path")

        }

        # Generate fingerprint hash
        fingerprint_hash = generate_fingerprint_hash(profile)

        profile["fingerprint_hash"] = fingerprint_hash

        logger.info(f"Device fingerprint generated: {fingerprint_hash}")

        return profile

    except Exception as e:

        logger.error(f"Device profile creation failed: {str(e)}")

        return None


def compare_profiles(profile_a, profile_b):
    """
    Compare two device profiles.

    Used for detecting device impersonation
    or firmware manipulation.

    Returns similarity score.
    """

    try:

        score = 0
        total = 0

        for key in profile_a:

            if key == "fingerprint_hash":
                continue

            total += 1

            if profile_a.get(key) == profile_b.get(key):
                score += 1

        similarity = score / total if total else 0

        return similarity

    except Exception as e:

        logger.error(f"Profile comparison failed: {str(e)}")

        return 0
