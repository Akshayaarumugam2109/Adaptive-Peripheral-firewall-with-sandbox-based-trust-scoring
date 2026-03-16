#!/usr/bin/env python3
"""
YARA Malware Scanner
"""

import subprocess
import logging

YARA_RULES = "sandbox/yara_rules"

logging.basicConfig(
    filename="logs/gateway.log",
    level=logging.INFO
)

logger = logging.getLogger("YARA-Scanner")


def scan_with_yara(file_list):

    suspicious = []

    for file in file_list:

        try:

            result = subprocess.run(
                ["yara", YARA_RULES, file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            if result.stdout.strip():

                suspicious.append(file)

        except Exception as e:

            logger.error(f"YARA scan failed: {str(e)}")

    return suspicious
