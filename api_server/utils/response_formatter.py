#!/usr/bin/env python3
"""
API Response Formatter

Provides standardized JSON responses for the USB Security Gateway API.

All API endpoints should use these helpers to ensure
consistent response formatting.

Standard Response Format:

{
    "status": "success | error",
    "timestamp": 1719915500,
    "message": "description",
    "data": {...}
}

Author: USB Security Gateway
"""

import time
from flask import jsonify


def success_response(data=None, message="Request successful", code=200):
    """
    Standard success response.

    Parameters:
        data (dict or list): response data
        message (str): optional message
        code (int): HTTP status code

    Returns:
        Flask JSON response
    """

    response = {
        "status": "success",
        "timestamp": int(time.time()),
        "message": message,
        "data": data
    }

    return jsonify(response), code


def list_response(items=None, message="Request successful", code=200):
    """
    Response for list data.

    Parameters:
        items (list): list of results
        message (str): optional message
        code (int): HTTP status code

    Returns:
        Flask JSON response
    """

    if items is None:
        items = []

    response = {
        "status": "success",
        "timestamp": int(time.time()),
        "count": len(items),
        "message": message,
        "data": items
    }

    return jsonify(response), code


def error_response(message="An error occurred", code=500, error=None):
    """
    Standard error response.

    Parameters:
        message (str): error description
        code (int): HTTP error code
        error (str): optional detailed error

    Returns:
        Flask JSON response
    """

    response = {
        "status": "error",
        "timestamp": int(time.time()),
        "message": message
    }

    if error:
        response["error"] = str(error)

    return jsonify(response), code


def health_response(service="USB Security Gateway API"):
    """
    Health check response.

    Used by monitoring systems.

    Returns:
        Flask JSON response
    """

    response = {
        "status": "running",
        "service": service,
        "timestamp": int(time.time())
    }

    return jsonify(response), 200
