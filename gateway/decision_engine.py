#!/usr/bin/env python3
"""
Decision Engine

Maps trust score to a decision and enforces it:
  score > 70  -> allow (forward clean files)
  40-70       -> sandbox (isolate, read-only access only)
  < 40        -> block (permanent block, add to blocklist)
"""

import logging
from gateway.blocking.block_device import block_device
from gateway.isolation.isolate_device import isolate_usb_device
from gateway.database.db import add_to_blocklist, is_device_blocked

logger = logging.getLogger("Decision-Engine")


def make_decision(trust_score: int) -> str:
    if trust_score > 70:
        return "allow"
    elif trust_score >= 40:
        return "sandbox"
    else:
        return "block"


def enforce_decision(decision: str, device_node: str, device_info: dict = None):
    """
    Enforce decision on device:
    - allow: No enforcement needed (file forwarding handles it)
    - sandbox: Isolate (unbind temporarily)
    - block: Block permanently and add to blocklist
    """
    logger.info(f"Enforcing '{decision}' on {device_node}")

    if decision == "block":
        block_device(device_node)
        # Only permanently blocklist if malware was actually found — not just low score
        if device_info:
            scan = device_info.get("scan_report") or {}
            has_malware = scan.get("infected_files", 0) > 0 or scan.get("suspicious_files", [])
            if has_malware:
                reason = f"Malware detected: {scan.get('infected_files',0)} infected file(s)"
                add_to_blocklist(device_info, reason)
                logger.warning(f"Device blocklisted (malware): {device_info.get('vendor_id')}:{device_info.get('product_id')}")
            else:
                logger.info(f"Device blocked this session (low score) but NOT permanently blocklisted — no malware found")

    elif decision == "sandbox":
        # Temporary isolation: unbind but mark as sandbox mode for logging
        logger.info(f"Sandboxing device {device_node} - temporary isolation")
        isolate_usb_device(device_node)

    # allow: no action needed, device proceeds normally (files forwarded)
