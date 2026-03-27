#!/usr/bin/env python3
"""
Shared in-memory state.
`connected` is a dict keyed by device_node holding each device's current info.
Both the gateway thread and the Flask thread import this module — Python's
module cache guarantees they reference the exact same dict object.
"""

import threading

_lock = threading.Lock()

# { device_node: { ...device_info, status, trust_score, decision, ... } }
connected = {}


def add_device(device_node, info: dict):
    with _lock:
        connected[device_node] = dict(info)


def update_device(device_node, **kwargs):
    with _lock:
        if device_node in connected:
            connected[device_node].update(kwargs)


def remove_device(device_node):
    with _lock:
        connected.pop(device_node, None)


def get_connected():
    with _lock:
        return list(connected.values())
