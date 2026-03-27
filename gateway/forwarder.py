#!/usr/bin/env python3
"""
File Forwarder

Forwards only clean files from the Pi sandbox to the host system.
Mode is read from gateway_config.yaml:
  local — copy to a local path (mount a Samba/NFS share there)
  ssh   — SCP to host over network using key-based auth
"""

import os
import shutil
import subprocess
import hashlib
import logging
import yaml

logger = logging.getLogger("Forwarder")

_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "config/gateway_config.yaml")


def _load_fwd_config():
    try:
        with open(_CONFIG_PATH) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("forwarding", {})
    except Exception as e:
        logger.error(f"Could not load forwarding config: {e}")
        return {}


def _sha256(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        logger.error(f"Hash failed for {path}: {e}")
        return None


def forward_clean_files(clean_files: list, device_node: str):
    if not clean_files:
        logger.info("No clean files to forward")
        return

    cfg = _load_fwd_config()
    mode = cfg.get("mode", "local")

    logger.info(f"Forwarding {len(clean_files)} clean file(s) via mode={mode}")

    if mode == "ssh":
        _forward_ssh(clean_files, device_node, cfg.get("ssh", {}))
    else:
        _forward_local(clean_files, device_node, cfg.get("local_dest", "/home/glitch/usb_output"))


def _forward_local(files: list, device_node: str, dest_root: str):
    from gateway.database.db import log_file_forward
    os.makedirs(dest_root, exist_ok=True)

    for src in files:
        try:
            src_hash = _sha256(src)
            # Preserve relative path from mount point
            # e.g. /tmp/usb_gateway/dev_sda1/docs/file.txt -> docs/file.txt
            parts = src.split(os.sep)
            try:
                gw_idx = parts.index("usb_gateway")
                rel = os.path.join(*parts[gw_idx+2:])  # skip usb_gateway/<mount_dir>
            except ValueError:
                rel = os.path.basename(src)

            dest = os.path.join(dest_root, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            shutil.copy2(src, dest)

            dest_hash = _sha256(dest)
            status = "verified" if src_hash and src_hash == dest_hash else "hash_mismatch"
            logger.info(f"{'✅' if status == 'verified' else '⚠️ '} {rel} → {dest} [{status}]")
            log_file_forward(device_node, src, src_hash or "", dest, status)

        except Exception as e:
            logger.error(f"Local copy failed for {src}: {e}")
            log_file_forward(device_node, src, "", "", "failed")


def _forward_ssh(files: list, device_node: str, ssh_cfg: dict):
    from gateway.database.db import log_file_forward

    host_ip   = ssh_cfg.get("host_ip", "")
    host_user = ssh_cfg.get("host_user", "")
    host_dest = ssh_cfg.get("host_dest", "/home/user/usb_received/")
    ssh_key   = ssh_cfg.get("ssh_key", "")

    if not host_ip or not host_user:
        logger.error("SSH forwarding configured but host_ip/host_user not set in gateway_config.yaml")
        return

    ssh_opts = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"]
    if ssh_key and os.path.exists(ssh_key):
        ssh_opts += ["-i", ssh_key]

    for src in files:
        try:
            src_hash = _sha256(src)
            dest_str = f"{host_user}@{host_ip}:{host_dest}"
            cmd = ["scp"] + ssh_opts + [src, dest_str]
            result = subprocess.run(cmd, timeout=30, capture_output=True, text=True)

            if result.returncode == 0:
                logger.info(f"✅ SCP: {os.path.basename(src)} → {dest_str}")
                log_file_forward(device_node, src, src_hash or "", dest_str, "transferred")
            else:
                logger.error(f"❌ SCP failed: {src} — {result.stderr.strip()}")
                log_file_forward(device_node, src, src_hash or "", dest_str, "scp_failed")

        except subprocess.TimeoutExpired:
            logger.error(f"SCP timeout: {src}")
            log_file_forward(device_node, src, "", f"{host_user}@{host_ip}:{host_dest}", "timeout")
        except Exception as e:
            logger.error(f"SCP error: {src} — {e}")
            log_file_forward(device_node, src, "", "", "error")
