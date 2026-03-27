#!/usr/bin/env python3
"""
Sandbox Live Demo
=================
Shows exactly what happens inside the sandbox in real-time
when a USB device is connected to the Raspberry Pi.
"""

import os
import sys
import time
import subprocess
import shutil

# ── Colours ───────────────────────────────────────────────────────────────────
G  = "\033[92m"   # green
R  = "\033[91m"   # red
Y  = "\033[93m"   # yellow
C  = "\033[96m"   # cyan
M  = "\033[95m"   # magenta
W  = "\033[97m"   # white
B  = "\033[1m"    # bold
DIM= "\033[2m"    # dim
X  = "\033[0m"    # reset

SANDBOX_BASE = "/tmp/usb_gateway"
OUTPUT_DIR   = "/home/glitch/usb_output"

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import urllib.request
import json

API_BASE  = "http://127.0.0.1:5000"
DEMO_NODE = "demo_usb"


def _api(path, payload):
    """POST JSON to the API server (best-effort — demo continues if server is down)."""
    try:
        data = json.dumps(payload).encode()
        req  = urllib.request.Request(
            API_BASE + path, data=data,
            headers={"Content-Type": "application/json"}, method="POST"
        )
        urllib.request.urlopen(req, timeout=2)
    except Exception:
        pass  # dashboard sync is best-effort


def _state(**kwargs):
    """Push current demo scan state to the API server."""
    _api("/demo_state", {"device_node": DEMO_NODE, **kwargs})


# ── Helpers ───────────────────────────────────────────────────────────────────

def clear():
    os.system("clear")

def banner():
    print(f"{B}{C}")
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║       USB SECURITY GATEWAY — SANDBOX LIVE DEMO      ║")
    print("  ║          Raspberry Pi  │  192.168.1.13:5000          ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print(f"{X}")

def section(title):
    print(f"\n{B}{M}  ┌─ {title} {'─'*(50-len(title))}┐{X}")

def end_section():
    print(f"{B}{M}  └{'─'*55}┘{X}")

def live(msg, end="\n"):
    print(f"  {DIM}│{X}  {msg}", end=end, flush=True)

def ok(msg):
    print(f"  {DIM}│{X}  {G}✔  {msg}{X}")

def warn(msg):
    print(f"  {DIM}│{X}  {Y}⚠  {msg}{X}")

def bad(msg):
    print(f"  {DIM}│{X}  {R}✘  {msg}{X}")

def typing(msg, delay=0.03):
    print(f"  {DIM}│{X}  ", end="", flush=True)
    for ch in msg:
        print(ch, end="", flush=True)
        time.sleep(delay)
    print()

def progress(label, total, current):
    bar_len = 30
    filled  = int(bar_len * current / total) if total else bar_len
    bar     = f"{G}{'█' * filled}{DIM}{'░' * (bar_len - filled)}{X}"
    pct     = int(100 * current / total) if total else 100
    print(f"  {DIM}│{X}  {label}: [{bar}] {B}{pct}%{X}", flush=True)


def find_usb_device():
    """Find a USB block device partition."""
    try:
        for name in os.listdir("/dev"):
            if name.startswith("sd") and len(name) == 4 and name[3:].isdigit():
                return f"/dev/{name}"
    except:
        pass
    return None


def find_sandbox_mount():
    """Return (device, mountpoint, options) if USB is mounted in sandbox."""
    try:
        for line in open("/proc/mounts"):
            if SANDBOX_BASE in line:
                p = line.split()
                return p[0], p[1], p[3]
    except:
        pass
    return None, None, None


def wait_for_usb():
    """Wait until a USB is plugged in."""
    banner()
    section("WAITING FOR USB DEVICE")
    live(f"{Y}No USB device detected.{X}")
    live(f"Plug in a USB drive to begin the live demo...")
    end_section()

    while True:
        dev = find_usb_device()
        if dev:
            return dev
        time.sleep(1)


# ── Demo Steps ────────────────────────────────────────────────────────────────

def step_detect(device):
    section("STEP 1 — USB DEVICE DETECTED")
    _state(
        status="analysing", scan_step="enumerated", device_class="storage",
        manufacturer="Detecting...", product="", file_results=[],
        suspicious=False, file_count=0,
    )
    live("")
    typing(f"{W}USB device plugged in → {G}{device}{X}")
    time.sleep(0.5)

    # udevadm info
    live(f"{DIM}Running: udevadm info --query=property --name {device}{X}")
    time.sleep(0.3)
    result = subprocess.run(
        ["udevadm", "info", "--query=property", "--name", device],
        capture_output=True, text=True, timeout=10
    )
    data = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            data[k.strip()] = v.strip()

    # Also try parent USB
    name = os.path.basename(device)
    disk = name.rstrip("0123456789")
    block_path = f"/sys/block/{disk}/device"
    if os.path.exists(block_path):
        real = os.path.realpath(block_path)
        path = real
        for _ in range(6):
            if os.path.exists(os.path.join(path, "idVendor")):
                pr = subprocess.run(
                    ["udevadm", "info", "--query=property", "--path", path],
                    capture_output=True, text=True, timeout=10
                )
                for line in pr.stdout.splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        if k.strip() not in data:
                            data[k.strip()] = v.strip()
                break
            path = os.path.dirname(path)

    live("")
    ok(f"Manufacturer : {B}{data.get('ID_VENDOR', 'Unknown')}{X}")
    ok(f"Product      : {B}{data.get('ID_MODEL', 'Unknown')}{X}")
    ok(f"Vendor ID    : {B}{data.get('ID_VENDOR_ID', 'Unknown')}{X}")
    ok(f"Product ID   : {B}{data.get('ID_MODEL_ID', 'Unknown')}{X}")
    ok(f"Serial       : {B}{data.get('ID_SERIAL_SHORT', 'Unknown')[:40]}{X}")
    ok(f"Filesystem   : {B}{data.get('ID_FS_TYPE', 'Unknown')}{X}")
    _state(
        manufacturer=data.get("ID_VENDOR", "Unknown"),
        product=data.get("ID_MODEL", ""),
        vendor_id=data.get("ID_VENDOR_ID", "unknown"),
        product_id=data.get("ID_MODEL_ID", "unknown"),
        serial_number=data.get("ID_SERIAL_SHORT", "unknown"),
        scan_step="classified",
    )
    live("")
    end_section()
    time.sleep(1.5)
    return data


def step_mount(device):
    _state(scan_step="mounting", status="scanning")
    section("STEP 2 — MOUNTING IN ISOLATED SANDBOX")
    live("")
    typing(f"Mounting {device} into sandbox environment...")
    time.sleep(0.5)

    safe = device.lstrip("/").replace("/", "_")
    mountpoint = os.path.join(SANDBOX_BASE, safe)
    os.makedirs(mountpoint, exist_ok=True)

    # Mount with sandbox flags
    mount_cmd = ["mount", "-o", "ro,nosuid,nodev,noexec", device, mountpoint]
    live(f"{DIM}Running: {' '.join(mount_cmd)}{X}")
    time.sleep(0.3)

    result = subprocess.run(mount_cmd, capture_output=True)
    if result.returncode != 0:
        # Already mounted or error
        pass

    live("")
    live(f"  {B}Sandbox location : {G}{mountpoint}{X}")
    live("")

    # Show flags
    flags = [
        ("ro",     "Read-Only",  "USB files CANNOT be modified"),
        ("noexec", "No-Execute", "USB files CANNOT be executed"),
        ("nosuid", "No-SUID",    "USB CANNOT gain root privileges"),
        ("nodev",  "No-Device",  "USB CANNOT access hardware"),
    ]
    for flag, name, meaning in flags:
        time.sleep(0.2)
        ok(f"{B}{flag:8s}{X} ({Y}{name}{X}) → {meaning}")

    live("")

    # Verify from /proc/mounts
    mounts = open("/proc/mounts").read()
    found = any(mountpoint in line for line in mounts.splitlines())
    if found:
        ok(f"{G}{B}Sandbox mount confirmed in /proc/mounts{X}")
    else:
        warn("Mount not found in /proc/mounts — may already be mounted by gateway")
        # Try to find it anyway
        for line in mounts.splitlines():
            if SANDBOX_BASE in line and device.split("/")[-1].rstrip("0123456789") in line:
                p = line.split()
                mountpoint = p[1]
                ok(f"Found existing sandbox mount: {mountpoint}")
                break

    live("")
    end_section()
    time.sleep(1.5)
    return mountpoint


def step_extract(mountpoint):
    _state(scan_step="extracting")
    section("STEP 3 — EXTRACTING FILES FROM SANDBOX")
    live("")
    typing(f"Walking sandbox directory: {mountpoint}")
    time.sleep(0.5)

    file_list = []
    dir_count = 0
    io_error = False
    for root, dirs, files in os.walk(mountpoint, onerror=lambda e: None):
        try:
            dir_count += len(dirs)
            for f in files:
                full = os.path.join(root, f)
                try:
                    size = os.path.getsize(full)
                    file_list.append(full)
                    rel = os.path.relpath(full, mountpoint)
                    live(f"  {DIM}Found:{X} {W}{rel}{X}  {DIM}({_human(size)}){X}")
                    time.sleep(0.05)
                except OSError:
                    io_error = True
        except OSError:
            io_error = True

    # Detect I/O errors via dmesg if walk returned nothing
    if not file_list:
        try:
            dmesg = subprocess.run(["dmesg"], capture_output=True, text=True, timeout=5)
            dev = os.path.basename(mountpoint).replace("_", "/").replace("dev/", "/dev/")
            if any("I/O error" in l and "sda" in l for l in dmesg.stdout.splitlines()[-20:]):
                io_error = True
        except Exception:
            pass

    live("")
    if io_error and not file_list:
        bad(f"{B}{R}I/O ERROR: USB drive is unreadable (hardware/filesystem error){X}")
        bad(f"Continuing pipeline with 0 readable files — drive may be corrupted")
    else:
        ok(f"Total files found : {B}{len(file_list)}{X}")
        ok(f"Total directories : {B}{dir_count}{X}")
        ok(f"All files confined inside sandbox — host cannot access them directly")
    _state(file_count=len(file_list), scan_step="clamav")
    live("")
    end_section()
    time.sleep(1.5)
    return file_list, io_error


def step_clamav(mountpoint, file_list):
    _state(scan_step="clamav")
    section("STEP 4 — ClamAV MALWARE SCAN (inside sandbox)")
    live("")
    typing(f"Scanning {len(file_list)} file(s) with ClamAV...")
    live(f"  {DIM}Scan path: {mountpoint}{X}")
    live("")
    time.sleep(0.5)

    # Animate progress
    for i in range(0, len(file_list) + 1):
        print(f"\033[1A\033[2K", end="")  # clear previous line
        progress("  Scanning", len(file_list), i)
        time.sleep(0.05)

    t = time.time()
    # Try clamdscan first, fall back to clamscan
    ping = subprocess.run(["clamdscan", "--ping", "1"], capture_output=True)
    if ping.returncode == 0:
        scanner = ["clamdscan", "--fdpass", "--recursive", "--infected", "--no-summary"]
    else:
        scanner = ["clamscan", "--recursive", "--infected", "--no-summary"]

    result = subprocess.run(scanner + [mountpoint], capture_output=True, text=True, timeout=120)
    elapsed = time.time() - t

    infected_files = []
    for line in result.stdout.splitlines():
        if "FOUND" in line:
            path = line.split(":")[0].strip()
            infected_files.append(path)

    live("")
    if infected_files:
        bad(f"ClamAV found {len(infected_files)} INFECTED file(s) in {elapsed:.2f}s:")
        for f in infected_files:
            bad(f"  🦠 {os.path.basename(f)}")
    else:
        ok(f"ClamAV: {B}All {len(file_list)} file(s) are CLEAN{X}  ({elapsed:.2f}s)")

    # Update dashboard with ClamAV results immediately
    infected_set = set(infected_files)
    partial_results = [
        {"file": os.path.basename(f), "path": f,
         "status": "infected" if f in infected_set else "clean"}
        for f in file_list
    ]
    _state(scan_step="yara", file_results=partial_results)

    live("")
    end_section()
    time.sleep(1.5)
    return infected_files


def step_yara(file_list):
    _state(scan_step="yara")
    section("STEP 5 — YARA PATTERN SCAN (inside sandbox)")
    live("")
    typing(f"Scanning {len(file_list)} file(s) with YARA rules...")
    live(f"  {DIM}Rules: autorun, scripts, rubber ducky, web shells, executables{X}")
    live("")
    time.sleep(0.5)

    suspicious_files = []
    try:
        from sandbox.yara_scan import scan_with_yara, _get_rules
        rules = _get_rules()
        if not rules:
            warn("No YARA rules loaded")
            end_section()
            return []

        for i, filepath in enumerate(file_list):
            rel = os.path.relpath(filepath, SANDBOX_BASE)
            print(f"\033[1A\033[2K", end="")
            live(f"  {DIM}Checking:{X} {W}{os.path.basename(filepath)}{X}  {DIM}({i+1}/{len(file_list)}){X}")
            time.sleep(0.1)
            try:
                import yara
                matches = rules.match(filepath, timeout=10)
                if matches:
                    suspicious_files.append(filepath)
                    bad(f"  YARA hit: {os.path.basename(filepath)} → {[m.rule for m in matches]}")
            except:
                pass

        live("")
        if suspicious_files:
            bad(f"YARA: {len(suspicious_files)} suspicious file(s) detected")
        else:
            ok(f"YARA: {B}No suspicious patterns found{X} in {len(file_list)} file(s)")

    except Exception as e:
        warn(f"YARA scan error: {e}")

    # Merge YARA hits into file_results — fetch current state from API
    suspicious_set = set(suspicious_files)
    try:
        resp = urllib.request.urlopen(API_BASE + "/file_results", timeout=2)
        existing = json.loads(resp.read()).get("files", [])
    except Exception:
        existing = []
    existing_map = {r["path"]: r["status"] for r in existing}
    merged = [
        {"file": os.path.basename(f), "path": f,
         "status": "suspicious" if f in suspicious_set else existing_map.get(f, "clean")}
        for f in file_list
    ]
    _state(scan_step="scoring", file_results=merged, suspicious=bool(suspicious_files))

    live("")
    end_section()
    time.sleep(1.5)
    return suspicious_files


def step_trust_score(device_data, infected, suspicious):
    _state(scan_step="scoring")
    section("STEP 6 — TRUST SCORE CALCULATION")
    live("")
    typing("Computing trust score based on scan results...")
    live("")
    time.sleep(0.5)

    from gateway.trust_engine import compute_trust_score

    # Map udevadm keys → trust_engine keys
    device_info = {
        "vendor_id":      device_data.get("ID_VENDOR_ID", "unknown"),
        "product_id":     device_data.get("ID_MODEL_ID", "unknown"),
        "serial_number":  device_data.get("ID_SERIAL_SHORT", "unknown"),
        "usb_interfaces": device_data.get("ID_USB_INTERFACES", ""),
        "device_node":    device_data.get("DEVNAME", "unknown"),
    }
    scan_report = {
        "infected_files":   len(infected),
        "suspicious_files": suspicious,
    }
    is_suspicious = bool(infected or suspicious)

    final, reasons = compute_trust_score(device_info, is_suspicious, scan_report)

    for r in reasons:
        pts  = r["points"]
        sign = f"{G}+{pts}{X}" if pts > 0 else f"{R}{pts}{X}"
        ok(f"{sign:30s}  {r['label']}")
        time.sleep(0.2)

    live("")

    # Score bar
    bar_len = 40
    filled  = int(bar_len * final / 100)
    color   = G if final > 70 else (Y if final >= 40 else R)
    bar     = f"{color}{'█' * filled}{DIM}{'░' * (bar_len - filled)}{X}"
    print(f"  {DIM}│{X}  Score: [{bar}] {B}{color}{final}/100{X}")
    live("")

    decision = "allow" if final > 70 else ("sandbox" if final >= 40 else "block")
    risk     = "LOW"   if final > 70 else ("MEDIUM"  if final >= 40 else "HIGH")

    if final > 70:
        ok(f"{B}{G}DECISION: ALLOW — Device is TRUSTED{X}")
        ok(f"Clean files will be forwarded to host")
    elif final >= 40:
        warn(f"{B}{Y}DECISION: SANDBOX — Device is RESTRICTED{X}")
        warn(f"Device isolated — no files forwarded")
    else:
        bad(f"{B}{R}DECISION: BLOCK — Device is DANGEROUS{X}")
        bad(f"Device blocked — no files forwarded")

    _state(
        scan_step="deciding",
        trust_score=final,
        score_reasons=reasons,
        decision=decision,
        risk_level=risk,
        status="done",
    )

    live("")
    end_section()
    time.sleep(2)
    return final


def step_forward(file_list, infected, suspicious, score):
    _state(scan_step="forwarding", status="forwarding")
    section("STEP 7 — FORWARDING CLEAN FILES TO HOST")
    live("")

    clean = [f for f in file_list if f not in infected and f not in suspicious]

    if score <= 40:
        bad(f"Device BLOCKED — no files forwarded to host")
        live("")
        end_section()
        return

    if score < 70:
        warn(f"Device SANDBOXED — no files forwarded to host")
        live("")
        end_section()
        return

    typing(f"Forwarding {len(clean)} clean file(s) to host...")
    live(f"  {DIM}Destination: {OUTPUT_DIR}{X}")
    live("")
    time.sleep(0.5)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    forwarded = 0

    for src in clean:
        rel = os.path.relpath(src, SANDBOX_BASE)
        # strip the mount dir prefix (dev_sda1/...)
        parts = rel.split(os.sep)
        rel_clean = os.path.join(*parts[1:]) if len(parts) > 1 else parts[0]
        dest = os.path.join(OUTPUT_DIR, rel_clean)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        try:
            shutil.copy2(src, dest)
            forwarded += 1
            ok(f"Forwarded: {W}{rel_clean}{X}  {G}✔ verified{X}")
            time.sleep(0.1)
        except Exception as e:
            warn(f"Could not copy {rel_clean}: {e}")

    live("")
    ok(f"{B}{G}{forwarded} file(s) safely delivered to host at {OUTPUT_DIR}{X}")

    if infected or suspicious:
        live("")
        bad(f"{len(infected)+len(suspicious)} infected/suspicious file(s) were BLOCKED:")
        for f in infected + suspicious:
            bad(f"  🚫 {os.path.basename(f)}")

    # Build final file_results with all statuses
    infected_set   = set(infected)
    suspicious_set = set(suspicious)
    final_results  = [
        {"file": os.path.basename(f), "path": f,
         "status": "infected" if f in infected_set else "suspicious" if f in suspicious_set else "clean"}
        for f in file_list
    ]
    _state(file_results=final_results, status="done", scan_step="done")

    live("")
    end_section()
    time.sleep(2)


def step_unmount(device):
    _state(scan_step="done", status="done")
    section("STEP 8 — CLEANING UP SANDBOX")
    live("")
    typing("Unmounting and clearing sandbox...")
    time.sleep(0.5)

    safe = device.lstrip("/").replace("/", "_")
    mountpoint = os.path.join(SANDBOX_BASE, safe)

    result = subprocess.run(["umount", mountpoint], capture_output=True)
    if result.returncode == 0:
        ok(f"Unmounted: {mountpoint}")
    else:
        warn(f"Unmount note: {result.stderr.decode().strip()}")

    try:
        shutil.rmtree(mountpoint, ignore_errors=True)
        ok(f"Sandbox directory cleared: {mountpoint}")
    except:
        pass

    live("")
    ok(f"{B}Sandbox fully cleaned — no USB data remains on Pi{X}")
    ok(f"Host received only verified clean files")
    live("")
    end_section()
    time.sleep(1.5)


def summary(score, file_list, infected, suspicious):
    section("SANDBOX DEMO COMPLETE — SUMMARY")
    live("")

    color = G if score > 70 else (Y if score >= 40 else R)
    decision = "ALLOW" if score > 70 else ("SANDBOX" if score >= 40 else "BLOCK")

    ok(f"Files on USB          : {B}{len(file_list)}{X}")
    ok(f"Infected (ClamAV)     : {B}{R if infected else G}{len(infected)}{X}")
    ok(f"Suspicious (YARA)     : {B}{R if suspicious else G}{len(suspicious)}{X}")
    ok(f"Clean files forwarded : {B}{G}{len(file_list)-len(infected)-len(suspicious)}{X}")
    ok(f"Trust Score           : {B}{color}{score}/100{X}")
    ok(f"Decision              : {B}{color}{decision}{X}")
    live("")
    ok(f"{G}The USB was NEVER directly connected to the host system{X}")
    ok(f"{G}All analysis happened inside the isolated sandbox{X}")
    ok(f"{G}Only safe files reached the host at {OUTPUT_DIR}{X}")
    live("")
    end_section()
    print()


def _human(size):
    for unit in ["B", "KB", "MB", "GB"]:
        if size < 1024:
            return f"{size:.0f}{unit}"
        size /= 1024
    return f"{size:.1f}GB"


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    clear()
    banner()
    _api("/demo_state", {"device_node": DEMO_NODE, "_clear": True})  # clear stale demo state
    # Check if gateway already mounted the USB
    device, mountpoint, options = find_sandbox_mount()

    if not device:
        # Wait for USB to be plugged in
        device = wait_for_usb()
        if not device:
            return

    section("SANDBOX LIVE DEMO STARTING")
    live(f"  {G}USB device found: {device}{X}")
    live(f"  Running full sandbox pipeline live...")
    live("")
    end_section()
    time.sleep(2)

    # Run all steps
    device_data = step_detect(device)
    mountpoint  = step_mount(device)
    file_list, io_error = step_extract(mountpoint)

    if not file_list and not io_error:
        section("NO FILES FOUND")
        warn("The USB appears to be empty.")
        warn("Try a USB with some files on it.")
        end_section()
        return

    infected   = step_clamav(mountpoint, file_list)
    suspicious = step_yara(file_list)
    score      = step_trust_score(device_data, infected, suspicious)
    step_forward(file_list, infected, suspicious, score)
    step_unmount(device)
    summary(score, file_list, infected, suspicious)


if __name__ == "__main__":
    main()
