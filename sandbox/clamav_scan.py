#!/usr/bin/env python3
import subprocess
import logging
import os

logger = logging.getLogger("ClamAV-Scanner")


def _run_scan(cmd, mount_dir, file_list):
    """Run a clam scan command, return (infected, clean) lists."""
    infected = []
    clean = []
    try:
        result = subprocess.run(
            cmd + ["--recursive", "--infected", "--no-summary", mount_dir],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=120
        )
        infected_paths = set()
        for line in result.stdout.splitlines():
            if "FOUND" in line:
                path = line.split(":")[0].strip()
                infected_paths.add(path)

        for f in file_list:
            if f in infected_paths:
                infected.append(f)
                print(f"   🚨 INFECTED: {os.path.basename(f)}")
            else:
                clean.append(f)

        print(f"   ✅ ClamAV done: {len(clean)} clean, {len(infected)} infected")
        return infected, clean

    except subprocess.TimeoutExpired:
        logger.error("ClamAV scan timed out")
        return [], file_list
    except Exception as e:
        logger.error(f"ClamAV scan error: {e}")
        return [], file_list


def scan_with_clamav(file_list):
    if not file_list:
        return {"infected": [], "clean": []}

    mount_dir = os.path.dirname(file_list[0])

    # Try clamdscan first (daemon — database stays loaded, very fast)
    # Fall back to clamscan if daemon is not running
    clamdscan = subprocess.run(["which", "clamdscan"], capture_output=True, text=True)
    if clamdscan.returncode == 0:
        # Check daemon is actually running
        ping = subprocess.run(["clamdscan", "--ping", "1"], capture_output=True, text=True)
        if ping.returncode == 0:
                infected, clean = _run_scan(["clamdscan"], mount_dir, file_list)
                return {"infected": infected, "clean": clean}

    # Fallback: clamscan (slower — loads DB each time)
    logger.warning("clamav-daemon not running, falling back to clamscan")
    infected, clean = _run_scan(["clamscan"], mount_dir, file_list)
    return {"infected": infected, "clean": clean}
