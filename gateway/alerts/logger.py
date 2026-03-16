#!/usr/bin/env python3
"""
Gateway Logging Module

Provides centralized logging utilities for the USB Security Gateway.

Logs are stored in:
logs/gateway.log
logs/security_alerts.log

Author: USB Security Gateway
"""

import logging
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

GATEWAY_LOG = os.path.join(BASE_DIR, "../../logs/gateway.log")
SECURITY_LOG = os.path.join(BASE_DIR, "../../logs/security_alerts.log")


def setup_logger(name, log_file, level=logging.INFO):
    """
    Create a reusable logger instance.
    """

    formatter = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(name)s : %(message)s"
    )

    handler = logging.FileHandler(log_file)
    handler.setFormatter(formatter)

    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not logger.handlers:
        logger.addHandler(handler)

    return logger


# Main gateway logger
gateway_logger = setup_logger("USB-Gateway", GATEWAY_LOG)

# Security alert logger
security_logger = setup_logger("USB-Security", SECURITY_LOG)


def log_info(message):
    gateway_logger.info(message)


def log_warning(message):
    gateway_logger.warning(message)


def log_error(message):
    gateway_logger.error(message)


def log_security_event(message):
    security_logger.warning(message)
