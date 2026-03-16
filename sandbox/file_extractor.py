#!/usr/bin/env python3
"""
File Extraction Module

Scans mounted USB directory and lists files for analysis.
"""

import os
import logging

logging.basicConfig(
    filename="logs/gateway.log",
    level=logging.INFO
)

logger = logging.getLogger("Sandbox-Extractor")


def extract_files(mount_path):

    file_list = []

    try:

        for root, dirs, files in os.walk(mount_path):

            for file in files:

                full_path = os.path.join(root, file)

                file_list.append(full_path)

        logger.info(f"{len(file_list)} files extracted")

        return file_list

    except Exception as e:

        logger.error(f"File extraction failed: {str(e)}")

        return []
