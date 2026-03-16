#!/usr/bin/env python3
"""
Alert Routes

Provides API endpoints for retrieving security alerts.
"""

from flask import Blueprint, jsonify
import logging

from gateway.database.db import get_recent_alerts

alert_routes = Blueprint("alert_routes", __name__)

logger = logging.getLogger("Alert-Routes")


@alert_routes.route("/alerts", methods=["GET"])
def get_alerts():
    """
    Return all recent security alerts.
    """

    try:

        alerts = get_recent_alerts()

        return jsonify({
            "status": "success",
            "count": len(alerts),
            "alerts": alerts
        })

    except Exception as e:

        logger.error(f"Alert retrieval failed: {str(e)}")

        return jsonify({
            "status": "error",
            "message": "Failed to retrieve alerts"
        }), 500


@alert_routes.route("/alerts/recent", methods=["GET"])
def get_recent_alert_logs():
    """
    Return last 10 security alerts.
    """

    try:

        alerts = get_recent_alerts(limit=10)

        return jsonify({
            "status": "success",
            "alerts": alerts
        })

    except Exception as e:

        logger.error(f"Recent alert query failed: {str(e)}")

        return jsonify({
            "status": "error"
        }), 500
