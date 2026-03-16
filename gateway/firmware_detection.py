import pyudev
import os

# Suspicious device classes
HID_CLASS = "03"
MASS_STORAGE_CLASS = "08"

def get_usb_attributes(device):
    """Extract USB enumeration metadata"""

    info = {
        "vendor_id": device.get("ID_VENDOR_ID"),
        "product_id": device.get("ID_MODEL_ID"),
        "manufacturer": device.get("ID_VENDOR"),
        "product": device.get("ID_MODEL"),
        "serial": device.get("ID_SERIAL_SHORT"),
        "device_type": device.get("ID_USB_DRIVER"),
        "device_class": device.get("ID_USB_CLASS")
    }

    return info


def detect_firmware_attack(device_info):
    """
    Detect suspicious USB firmware behavior
    """

    suspicious = False
    reason = ""

    device_class = device_info.get("device_class")
    device_type = device_info.get("device_type")

    # HID attack detection
    if device_class == HID_CLASS:
        suspicious = True
        reason = "Possible HID Injection Device"

    # Composite device detection
    if device_type == "usb-storage" and device_class == HID_CLASS:
        suspicious = True
        reason = "Possible BadUSB (Storage + HID)"

    return suspicious, reason


def start_usb_enumeration_monitor():

    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='usb')

    print("USB Enumeration Monitor Started...\n")

    for device in monitor:

        if device.action == 'add':

            print("USB Device Detected")
            print("Starting Enumeration Analysis...\n")

            device_info = get_usb_attributes(device)

            print("Device Information:")
            for k, v in device_info.items():
                print(f"{k} : {v}")

            suspicious, reason = detect_firmware_attack(device_info)

            if suspicious:

                print("\n? Firmware Attack Detected!")
                print("Reason:", reason)
                print("Blocking USB Device...\n")

                return {
                    "status": "blocked",
                    "reason": reason,
                    "device": device_info
                }

            else:

                print("\nDevice appears safe")
                print("Proceed to sandbox analysis\n")

                return {
                    "status": "safe",
                    "device": device_info
                }
