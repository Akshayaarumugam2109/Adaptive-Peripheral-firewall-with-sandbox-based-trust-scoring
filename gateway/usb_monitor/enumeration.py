#!/usr/bin/env python3

import subprocess
import logging
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_PATH = os.path.join(BASE_DIR, "../../logs/gateway.log")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

logging.basicConfig(
    filename=LOG_PATH, level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("USB-Enumeration")


def _run(cmd):
    try:
        r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=10)
        return r.stdout.strip() if r.returncode == 0 else None
    except Exception as e:
        logger.error(f"Command error: {e}")
        return None


def _parse(output):
    data = {}
    for line in (output or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()
    return data


def _find_usb_parent(dev_node):
    """
    Given a block device like /dev/sda1, walk sysfs upward to find
    the parent USB device and return its sysfs path.
    e.g. /sys/block/sda/device -> resolves to /sys/bus/usb/devices/1-1.2
    """
    try:
        # /dev/sda1 -> sda1, parent disk is sda
        name = os.path.basename(dev_node)          # sda1
        disk = name.rstrip('0123456789')            # sda
        block_path = f"/sys/block/{disk}/device"   # /sys/block/sda/device
        if not os.path.exists(block_path):
            return None
        # Resolve symlink to get real sysfs path
        real = os.path.realpath(block_path)
        # Walk up until we find a USB device (has idVendor)
        path = real
        for _ in range(6):
            if os.path.exists(os.path.join(path, "idVendor")):
                return path
            path = os.path.dirname(path)
        return None
    except Exception as e:
        logger.warning(f"USB parent lookup failed for {dev_node}: {e}")
        return None


def enumerate_device(device_node, device_type="usb"):
    """
    Enumerate any USB device.
    device_node can be:
      - /dev/sda        → storage, use --name
      - 2-1 / 1-1.2    → sysfs basename, use --path /sys/bus/usb/devices/X
      - full syspath    → use --path directly
    """
    try:
        logger.info(f"Enumerating {device_node} (type={device_type})")

        # Build udevadm command
        if device_node.startswith("/dev/"):
            if not os.path.exists(device_node):
                logger.warning(f"Device node missing: {device_node}")
                return None
            cmd = ["udevadm", "info", "--query=property", "--name", device_node]

        elif device_node.startswith("/sys/"):
            cmd = ["udevadm", "info", "--query=property", "--path", device_node]

        else:
            # sysfs basename like "2-1" or "1-1.2"
            sysfs = f"/sys/bus/usb/devices/{device_node}"
            if not os.path.exists(sysfs):
                logger.warning(f"Sysfs path not found: {sysfs}")
                return None
            cmd = ["udevadm", "info", "--query=property", "--path", sysfs]

        output = _run(cmd)
        data   = _parse(output)

        # For block devices (/dev/sda1), udevadm on the partition gives
        # limited info. Walk up sysfs to the parent USB device for full metadata.
        if device_node.startswith("/dev/"):
            usb_parent = _find_usb_parent(device_node)
            if usb_parent:
                parent_out  = _run(["udevadm", "info", "--query=property", "--path", usb_parent])
                parent_data = _parse(parent_out)
                for key in ("ID_VENDOR_ID", "ID_MODEL_ID", "ID_VENDOR", "ID_MODEL",
                            "ID_SERIAL_SHORT", "ID_USB_INTERFACES", "ID_USB_CLASS_FROM_DATABASE",
                            "BUSNUM", "DEVNUM"):
                    if not data.get(key) and parent_data.get(key):
                        data[key] = parent_data[key]

        # Fallback: read directly from sysfs if udevadm gave nothing for non-block devices
        if not data and not device_node.startswith("/dev/"):
            sysfs = f"/sys/bus/usb/devices/{device_node}"
            def r(f):
                try: return open(os.path.join(sysfs, f)).read().strip()
                except: return "unknown"
            return {
                "device_node":    device_node,
                "vendor_id":      r("idVendor"),
                "product_id":     r("idProduct"),
                "manufacturer":   r("manufacturer"),
                "product":        r("product"),
                "serial_number":  r("serial"),
                "bus_number":     r("busnum"),
                "device_number":  r("devnum"),
                "usb_interfaces": "",
                "subsystem":      "usb",
                "device_class":   device_type,
            }

        usb_interfaces = data.get("ID_USB_INTERFACES", "")
        raw_class = data.get("ID_USB_CLASS_FROM_DATABASE", "unknown")

        # Derive device_class from interfaces if udevadm didn't provide one
        if not raw_class or raw_class.lower() in ("unknown", ""):
            IFACE_MAP = {"08": "storage", "03": "hid", "02": "network", "0e": "video", "09": "hub"}
            iface_classes = [usb_interfaces[i+1:i+3] for i in range(len(usb_interfaces)) if usb_interfaces[i] == ":" and i+3 <= len(usb_interfaces)]
            raw_class = next((IFACE_MAP[c] for c in iface_classes if c in IFACE_MAP), "unknown")

        # Also use device_type hint passed in from monitor
        if raw_class == "unknown" and device_type in ("storage", "hid", "network", "video"):
            raw_class = device_type

        info = {
            "device_node":    device_node,
            "vendor_id":      data.get("ID_VENDOR_ID",                "unknown"),
            "product_id":     data.get("ID_MODEL_ID",                 "unknown"),
            "manufacturer":   data.get("ID_VENDOR",                   "unknown"),
            "product":        data.get("ID_MODEL",                    "unknown"),
            "serial_number":  data.get("ID_SERIAL_SHORT",             "unknown"),
            "bus_number":     data.get("BUSNUM",                      "unknown"),
            "device_number":  data.get("DEVNUM",                      "unknown"),
            "usb_interfaces": usb_interfaces,
            "subsystem":      data.get("SUBSYSTEM",                   "usb"),
            "device_class":   raw_class,
        }

        logger.info(f"Enumerated: {info}")
        return info

    except Exception as e:
        logger.error(f"Enumeration error: {e}")
        return None
