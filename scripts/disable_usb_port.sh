#!/bin/bash

# Disable USB Port Script
# Usage: sudo ./disable_usb_port.sh /dev/sdb

DEVICE_NODE=$1

if [ -z "$DEVICE_NODE" ]; then
    echo "Usage: sudo ./disable_usb_port.sh <device_node>"
    exit 1
fi

USB_PATH=$(udevadm info -q path -n $DEVICE_NODE)

if [ -z "$USB_PATH" ]; then
    echo "Device path not found"
    exit 1
fi

SYSFS_PATH="/sys$USB_PATH"

AUTH_FILE="$SYSFS_PATH/authorized"

if [ ! -f "$AUTH_FILE" ]; then
    echo "USB authorization file not found"
    exit 1
fi

echo "Disabling USB port..."

echo 0 | sudo tee $AUTH_FILE > /dev/null

echo "USB port disabled"
