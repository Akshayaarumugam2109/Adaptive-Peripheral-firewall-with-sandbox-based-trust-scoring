#!/bin/bash

# USB Metadata Retrieval Script
# Usage: ./get_usb_metadata.sh /dev/sdb

DEVICE_NODE=$1

if [ -z "$DEVICE_NODE" ]; then
    echo "Usage: ./get_usb_metadata.sh <device_node>"
    exit 1
fi

echo "Fetching USB metadata for $DEVICE_NODE"
echo "--------------------------------------"

udevadm info --query=property --name $DEVICE_NODE

echo ""
echo "USB Descriptor Information"
echo "--------------------------------------"

lsusb
