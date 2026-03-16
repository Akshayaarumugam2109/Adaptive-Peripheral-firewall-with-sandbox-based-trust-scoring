#!/bin/bash

# USB Driver Unbind Script
# Usage: sudo ./usb_unbind.sh /dev/sdb

DEVICE_NODE=$1

if [ -z "$DEVICE_NODE" ]; then
    echo "Usage: sudo ./usb_unbind.sh <device_node>"
    exit 1
fi

USB_PATH=$(udevadm info -q path -n $DEVICE_NODE)

if [ -z "$USB_PATH" ]; then
    echo "Unable to find device path"
    exit 1
fi

USB_ID=$(echo $USB_PATH | grep -o '[0-9]-[0-9]\+\(\.[0-9]\+\)*')

if [ -z "$USB_ID" ]; then
    echo "Unable to determine USB device ID"
    exit 1
fi

echo "Unbinding USB device: $USB_ID"

echo $USB_ID | sudo tee /sys/bus/usb/drivers/usb/unbind > /dev/null

echo "Device successfully unbound"
