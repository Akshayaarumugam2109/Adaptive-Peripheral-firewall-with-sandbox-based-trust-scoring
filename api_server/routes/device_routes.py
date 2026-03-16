#!/usr/bin/env python3
"""
Device Routes

Provides API endpoints related to USB devices detected
by the USB Security Gateway.
"""

from flask import Blueprint, jsonify
import logging

from gateway.database.db import get_recent_devices

device_routes = Blueprint("device_routes", __name__)

logger = logging.getLogger("Device-Routes")


@device_routes.route("/devices", methods=["GET"])
def get_devices():
    """
    Return recent detected USB devices.
    """

    try:

        devices = get_recent_devices()

        return jsonify({
            "status": "success",
            "count": len(devices),
            "devices": devices
        })

    except Exception as e:

        logger.error(f"Device retrieval failed: {str(e)}")

        return jsonify({
            "status": "error",
            "message": "Failed to fetch device data"
        }), 500


@device_routes.route("/devices/recent", methods=["GET"])
def get_recent_device_logs():
    """
    Return last 10 devices detected.
    """

    try:

        devices = get_recent_devices(limit=10)

        return jsonify({
            "status": "success",
            "devices": devices
        })

    except Exception as e:

        logger.error(f"Recent device query failed: {str(e)}")

        return jsonify({
            "status": "error"
        }), 500
