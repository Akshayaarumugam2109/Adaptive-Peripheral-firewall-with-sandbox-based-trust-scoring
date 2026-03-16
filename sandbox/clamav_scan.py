#!/usr/bin/env python3
"""
ClamAV Malware Scanner
"""

import subprocess
import logging

logging.basicConfig(
    filename="logs/gateway.log",
    level=logging.INFO
)

logger = logging.getLogger("ClamAV-Scanner")


def scan_with_clamav(file_list):

    infected = []
    clean = []

    for file in file_list:

        try:

            result = subprocess.run(
                ["clamscan", "--infected", file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )

            output = result.stdout

            if "FOUND" in output:

                infected.append(file)

            else:

                clean.append(file)

        except Exception as e:

            logger.error(f"ClamAV scan error: {str(e)}")

    return {

        "infected": infected,
        "clean": clean

    }
