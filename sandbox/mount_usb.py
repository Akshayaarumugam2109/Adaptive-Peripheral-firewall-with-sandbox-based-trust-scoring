#!/usr/bin/env python3
"""
USB Mount Module

Safely mounts USB device in sandbox environment.

Mount options:
ro      ? read-only
nosuid  ? ignore suid bits
nodev   ? ignore device files
noexec  ? prevent execution
"""

import os
import subprocess
import logging

MOUNT_PATH = "/sandbox/usb_mount"

logging.basicConfig(
    filename="logs/gateway.log",
    level=logging.INFO
)

logger = logging.getLogger("Sandbox-Mount")


def mount_usb(device_node):

    try:

        if not os.path.exists(MOUNT_PATH):
            os.makedirs(MOUNT_PATH)

        mount_cmd = [
            "mount",
            "-o",
            "ro,nosuid,nodev,noexec",
            device_node,
            MOUNT_PATH
        ]

        subprocess.run(mount_cmd, check=True)

        logger.info(f"USB mounted at {MOUNT_PATH}")

        return MOUNT_PATH

    except Exception as e:

        logger.error(f"USB mount failed: {str(e)}")

        return None
