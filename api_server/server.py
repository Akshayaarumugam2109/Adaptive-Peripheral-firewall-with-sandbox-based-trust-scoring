#!/usr/bin/env python3
"""
USB Security Gateway - API Server

Provides REST API endpoints for the Windows dashboard
to retrieve system data.

Endpoints:

GET /devices
GET /alerts
GET /scan_results
GET /health

Author: USB Security Gateway
"""

import os
import logging
import yaml
from flask import Flask, jsonify
from flask_cors import CORS

# ---------------------------------------------------
# Import route modules
# ---------------------------------------------------

from api_server.routes.device_routes import device_routes
from api_server.routes.alert_routes import alert_routes
from api_server.routes.scan_routes import scan_routes

# Import database functions
from gateway.database.db import (
    get_recent_devices,
    get_recent_alerts
)

# ---------------------------------------------------
# Paths
# ---------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

CONFIG_PATH = os.path.join(
    BASE_DIR,
    "../gateway/config/gateway_config.yaml"
)

LOG_PATH = os.path.join(
    BASE_DIR,
    "../logs/gateway.log"
)

# ---------------------------------------------------
# Logging
# ---------------------------------------------------

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

logger = logging.getLogger("API-Server")

# ---------------------------------------------------
# Load configuration
# ---------------------------------------------------
def load_config():

    try:

        with open(CONFIG_PATH, "r") as f:
            config = yaml.safe_load(f)

        return config

    except Exception as e:

        logger.error(f"Failed to load config: {str(e)}")

        return {}

config = load_config()

# ---------------------------------------------------
# Flask Application
# ---------------------------------------------------

app = Flask(__name__)

CORS(app)

# ---------------------------------------------------
# Register Blueprint Routes
# ---------------------------------------------------

app.register_blueprint(device_routes)
app.register_blueprint(alert_routes)
app.register_blueprint(scan_routes)

# ---------------------------------------------------
# Health Endpoint
# ---------------------------------------------------

@app.route("/health", methods=["GET"])
def health():
    """
    Health check endpoint
    """

    return jsonify({

        "status": "running",
        "service": "USB Security Gateway API"

    })


# ---------------------------------------------------
# Devices Endpoint
# ---------------------------------------------------

@app.route("/devices", methods=["GET"])
def devices():
    """
    Return recent USB devices detected
    """

    try:

        device_list = get_recent_devices()

        return jsonify({

            "count": len(device_list),
            "devices": device_list

        })

    except Exception as e:

        logger.error(f"Failed to fetch devices: {str(e)}")

        return jsonify({

            "error": "Failed to retrieve devices"

        }), 500


# ---------------------------------------------------
# Alerts Endpoint
# ---------------------------------------------------
@app.route("/alerts", methods=["GET"])
def alerts():
    """
    Return recent security alerts
    """

    try:

        alert_list = get_recent_alerts()

        return jsonify({

            "count": len(alert_list),
            "alerts": alert_list

        })

    except Exception as e:

        logger.error(f"Failed to fetch alerts: {str(e)}")

        return jsonify({

            "error": "Failed to retrieve alerts"

        }), 500


# ---------------------------------------------------
# Scan Results Endpoint
# ---------------------------------------------------

@app.route("/scan_results", methods=["GET"])
def scan_results():
    """
    Return malware scan results
    """

    try:

        from gateway.database.db import get_recent_malware_reports

        reports = get_recent_malware_reports()

        return jsonify({

            "count": len(reports),
            "reports": reports

        })

    except Exception as e:

        logger.error(f"Failed to fetch scan results: {str(e)}")

        return jsonify({

            "error": "Failed to retrieve scan results"

        }), 500


# ---------------------------------------------------
# Start API Server
# ---------------------------------------------------

def start_server():
    """
    Start API server using configuration
    """

    host = config.get("api_server", {}).get("host", "0.0.0.0")
    port = config.get("api_server", {}).get("port", 5000)
    debug = config.get("api_server", {}).get("debug", False)

    logger.info(f"Starting API server on {host}:{port}")

    app.run(
        host=host,
        port=port,
        debug=debug
    )


# ---------------------------------------------------
# Main
# ---------------------------------------------------

if __name__ == "__main__":

    start_server()
