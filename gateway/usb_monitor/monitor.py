#!/usr/bin/env python3

import os
import time
import subprocess

SKIP_VENDORS = {"1d6b", "2109", "0424", "05e3", "0bda", "1a40"}

_serial_cache      = set()
_serial_cache_time = 0.0
_SERIAL_TTL        = 2.0


def _read(path):
    try:
        return open(path).read().strip()
    except:
        return ""


def _get_storage():
    """Return mountable partitions only (e.g. sda1, sdb1). Skip whole-disk nodes."""
    devs = set()
    try:
        all_names = set(os.listdir("/dev"))
        for name in all_names:
            if not name.startswith("sd") or len(name) < 4:
                continue
            # Only partitions: sda1, sdb2 — skip bare sda, sdb
            suffix = name[3:]
            if not suffix.isdigit():
                continue
            # Skip if a higher partition of same disk exists (take lowest only)
            disk = name[:3]
            part_num = int(suffix)
            # Use partition 1 of each disk (first partition is the data partition)
            if part_num == 1 or not any(
                n.startswith(disk) and n[3:].isdigit() and int(n[3:]) < part_num
                for n in all_names
            ):
                devs.add("/dev/" + name)
    except:
        pass
    return devs


def _get_storage_serials():
    """Return set of vendor:product keys for all current storage devices (cached)."""
    global _serial_cache, _serial_cache_time
    now = time.monotonic()
    if now - _serial_cache_time < _SERIAL_TTL:
        return _serial_cache
    keys = set()
    for devname in _get_storage():
        try:
            out = subprocess.run(
                ["udevadm", "info", "--query=property", "--name", devname],
                capture_output=True, text=True, timeout=5
            ).stdout
            vid = ser = pid = ""
            for line in out.splitlines():
                if line.startswith("ID_VENDOR_ID="):  vid = line.split("=",1)[1]
                if line.startswith("ID_MODEL_ID="):   pid = line.split("=",1)[1]
                if line.startswith("ID_SERIAL="):     ser = line.split("=",1)[1]
            key = ser if ser else f"{vid}:{pid}"
            if key:
                keys.add(key)
        except:
            pass
    _serial_cache, _serial_cache_time = keys, now
    return keys


def _get_usb():
    """Return set of sysfs IDs for non-storage USB devices (HID, network, etc)."""
    devs = set()
    storage_keys = _get_storage_serials()
    base = "/sys/bus/usb/devices"
    try:
        for name in os.listdir(base):
            if ":" in name or name.startswith("usb"):
                continue
            path = os.path.join(base, name)
            vendor = _read(os.path.join(path, "idVendor"))
            if not vendor or vendor in SKIP_VENDORS:
                continue
            bclass = _read(os.path.join(path, "bDeviceClass"))
            if bclass == "09":   # hub
                continue
            # Skip ALL storage-class devices — handled exclusively via /dev/sdX1
            ifaces = _read(os.path.join(path, "bInterfaceClass"))
            if ifaces == "08" or bclass == "08":
                continue
            # Also skip if any interface is storage
            iface_str = ""
            try:
                for child in os.listdir(path):
                    ic_path = os.path.join(path, child, "bInterfaceClass")
                    if os.path.exists(ic_path):
                        ic = _read(ic_path)
                        if ic == "08":
                            iface_str = "08"
                            break
            except:
                pass
            if iface_str == "08":
                continue
            serial = _read(os.path.join(path, "serial"))
            pid    = _read(os.path.join(path, "idProduct"))
            key    = serial if serial else f"{vendor}:{pid}"
            if key and key in storage_keys:
                continue
            devs.add(name)
    except:
        pass
    return devs


def start_usb_monitor(callback):
    print("🔍 USB Monitor Started...")

    prev_storage = _get_storage()
    prev_usb     = _get_usb()

    print(f"   Storage at startup: {prev_storage}")
    print(f"   USB at startup:     {prev_usb}")

    # Fire add for everything already connected at startup
    for dev in prev_storage:
        callback({"type": "storage", "device": dev, "action": "add"})
    for dev in prev_usb:
        callback({"type": "usb", "device": dev, "action": "add"})

    while True:
        time.sleep(0.5)

        curr_storage = _get_storage()
        curr_usb     = _get_usb()

        for dev in curr_storage - prev_storage:
            print(f"\n💾 STORAGE ADD → {dev}")
            callback({"type": "storage", "device": dev, "action": "add"})

        for dev in prev_storage - curr_storage:
            print(f"\n🔴 STORAGE REMOVE → {dev}")
            callback({"type": "storage", "device": dev, "action": "remove"})

        for dev in curr_usb - prev_usb:
            print(f"\n🔌 USB ADD → {dev}")
            callback({"type": "usb", "device": dev, "action": "add"})

        for dev in prev_usb - curr_usb:
            print(f"\n🔴 USB REMOVE → {dev}")
            callback({"type": "usb", "device": dev, "action": "remove"})

        prev_storage = curr_storage
        prev_usb     = curr_usb
