#!/usr/bin/env python3

import os
import re
import subprocess
import logging

logging.basicConfig(filename="logs/gateway.log", level=logging.INFO)
logger = logging.getLogger("Sandbox-Mount")

BASE_MOUNT = "/tmp/usb_gateway"


def _mount_path(device_node):
    # e.g. /dev/sda -> /tmp/usb_gateway/sda
    safe = re.sub(r"[^a-zA-Z0-9]", "_", device_node.lstrip("/"))
    return os.path.join(BASE_MOUNT, safe)


def mount_usb(device_node):
    path = _mount_path(device_node)
    try:
        os.makedirs(path, exist_ok=True)
        subprocess.run(
            ["mount", "-o", "ro,nosuid,nodev,noexec", device_node, path],
            check=True, capture_output=True
        )
        logger.info(f"Mounted {device_node} at {path}")
        return path
    except subprocess.CalledProcessError as e:
        logger.error(f"Mount failed for {device_node}: {e.stderr.decode().strip()}")
        return None
    except Exception as e:
        logger.error(f"Mount error for {device_node}: {e}")
        return None


def unmount_usb(device_node):
    path = _mount_path(device_node)
    try:
        subprocess.run(["umount", path], check=True, capture_output=True)
        logger.info(f"Unmounted {path}")
    except Exception as e:
        logger.warning(f"Unmount warning for {device_node}: {e}")
