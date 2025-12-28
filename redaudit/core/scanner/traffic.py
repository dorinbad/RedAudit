#!/usr/bin/env python3
"""
Scanner Traffic Logic - RedAudit
Separated from scanner.py for modularity.
"""

import os
import re
import subprocess
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional

from redaudit.utils.constants import (
    TRAFFIC_CAPTURE_DEFAULT_DURATION,
    TRAFFIC_CAPTURE_MAX_DURATION,
    TRAFFIC_CAPTURE_PACKETS,
)
from redaudit.core.scanner.utils import sanitize_ip
from redaudit.core.scanner.nmap import _make_runner, _is_dry_run


def capture_traffic_snippet(
    host_ip: str,
    output_dir: str,
    networks: List[Dict],
    extra_tools: Dict,
    duration: int = TRAFFIC_CAPTURE_DEFAULT_DURATION,
    logger=None,
    dry_run: Optional[bool] = None,
) -> Optional[Dict]:
    """
    Capture small PCAP snippet with tcpdump + optional tshark summary.
    """
    if not extra_tools.get("tcpdump"):
        return None

    if _is_dry_run(dry_run):
        if logger:
            logger.info("[dry-run] skipping traffic capture snippet")
        return None

    safe_ip = sanitize_ip(host_ip)
    if not safe_ip:
        return None

    if (
        not isinstance(duration, (int, float))
        or duration <= 0
        or duration > TRAFFIC_CAPTURE_MAX_DURATION
    ):
        if logger:
            logger.warning("Invalid capture duration %s, using default", duration)
        duration = TRAFFIC_CAPTURE_DEFAULT_DURATION

    # Find interface for the IP
    iface = None
    try:
        ip_obj = ipaddress.ip_address(safe_ip)
        for net in networks:
            try:
                net_obj = ipaddress.ip_network(net["network"], strict=False)
                if ip_obj in net_obj:
                    iface = net.get("interface")
                    break
            except Exception:
                continue
    except ValueError:
        return None

    if not iface:
        if logger:
            logger.info("No interface found for host %s, skipping traffic capture", safe_ip)
        return None

    if not re.match(r"^[a-zA-Z0-9\-_]+$", iface):
        return None

    ts = datetime.now().strftime("%H%M%S")
    os.makedirs(output_dir, exist_ok=True)
    pcap_file = os.path.join(output_dir, f"traffic_{safe_ip.replace('.', '_')}_{ts}.pcap")

    cmd = [
        extra_tools["tcpdump"],
        "-i",
        iface,
        "host",
        safe_ip,
        "-c",
        str(TRAFFIC_CAPTURE_PACKETS),
        "-G",
        str(int(duration)),
        "-W",
        "1",
        "-w",
        pcap_file,
    ]

    # v3.1.4: Use relative path for portability, keep absolute for internal use
    pcap_filename = os.path.basename(pcap_file)
    info = {"pcap_file": pcap_filename, "pcap_file_abs": pcap_file, "iface": iface}

    try:
        runner = _make_runner(logger=logger, dry_run=dry_run, timeout=float(duration) + 5.0)
        res = runner.run(
            cmd,
            capture_output=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            text=True,
            timeout=float(duration) + 5.0,
        )
        if res.timed_out:
            info["tcpdump_error"] = f"Timeout after {int(duration) + 5}s"
    except Exception as exc:
        info["tcpdump_error"] = str(exc)

    # Optional tshark summary
    if extra_tools.get("tshark"):
        try:
            runner = _make_runner(logger=logger, dry_run=dry_run, timeout=10.0)
            res = runner.run(
                [extra_tools["tshark"], "-r", pcap_file, "-q", "-z", "io,phs"],
                capture_output=True,
                check=False,
                text=True,
                timeout=10.0,
            )
            if res.timed_out:
                info["tshark_error"] = "Timeout after 10s"
            else:
                info["tshark_summary"] = (str(res.stdout or "") or str(res.stderr or ""))[:2000]
        except Exception as exc:
            info["tshark_error"] = str(exc)

    return info


def start_background_capture(
    host_ip: str,
    output_dir: str,
    networks: List[Dict],
    extra_tools: Dict,
    logger=None,
    dry_run: Optional[bool] = None,
) -> Optional[Dict]:
    """
    Start background traffic capture for concurrent scanning (v2.8.0).
    """
    if not extra_tools.get("tcpdump"):
        return None

    if _is_dry_run(dry_run):
        if logger:
            logger.info("[dry-run] skipping background traffic capture")
        return None

    safe_ip = sanitize_ip(host_ip)
    if not safe_ip:
        return None

    # Find interface for the IP
    iface = None
    try:
        ip_obj = ipaddress.ip_address(safe_ip)
        for net in networks:
            try:
                net_obj = ipaddress.ip_network(net["network"], strict=False)
                if ip_obj in net_obj:
                    iface = net.get("interface")
                    break
            except Exception:
                continue
    except ValueError:
        return None

    if not iface:
        if logger:
            logger.info("No interface found for host %s, skipping traffic capture", safe_ip)
        return None

    if not re.match(r"^[a-zA-Z0-9\-_]+$", iface):
        return None

    ts = datetime.now().strftime("%H%M%S")
    os.makedirs(output_dir, exist_ok=True)
    pcap_file = os.path.join(output_dir, f"traffic_{safe_ip.replace('.', '_')}_{ts}.pcap")

    # v2.8.1: Limit capture to 200 packets for smaller PCAP files (~50-150KB)
    cmd = [
        extra_tools["tcpdump"],
        "-i",
        iface,
        "-c",
        "200",  # Capture max 200 packets
        "host",
        safe_ip,
        "-w",
        pcap_file,
    ]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # v3.1.4: Keep reports portable by storing relative filename; keep absolute for internal use.
        pcap_filename = os.path.basename(pcap_file)
        return {
            "process": proc,
            "pcap_file": pcap_filename,
            "pcap_file_abs": pcap_file,
            "iface": iface,
        }
    except Exception as exc:
        if logger:
            logger.debug("Failed to start background capture for %s: %s", safe_ip, exc)
        return None


def stop_background_capture(
    capture_info: Dict,
    extra_tools: Dict,
    logger=None,
    dry_run: Optional[bool] = None,
) -> Optional[Dict]:
    """
    Stop background traffic capture and collect results (v2.8.0).
    """
    if not capture_info or "process" not in capture_info:
        return None

    proc = capture_info["process"]
    pcap_file_abs = capture_info.get("pcap_file_abs") or capture_info.get("pcap_file", "")
    iface = capture_info.get("iface", "")

    pcap_file = capture_info.get("pcap_file")
    if not pcap_file:
        pcap_file = os.path.basename(pcap_file_abs) if pcap_file_abs else ""
    # If older capture_info stored an absolute path in pcap_file, normalize to portable filename.
    if pcap_file and ("/" in pcap_file or "\\" in pcap_file):
        pcap_file = os.path.basename(pcap_file)

    result = {"pcap_file": pcap_file, "pcap_file_abs": pcap_file_abs, "iface": iface}

    # Terminate the capture process
    try:
        proc.terminate()
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        result["tcpdump_error"] = "Process killed after timeout"
    except Exception as exc:
        result["tcpdump_error"] = str(exc)

    # Generate tshark summary if available
    if pcap_file_abs and os.path.exists(pcap_file_abs):
        # Ensure PCAP is stored with secure permissions (best-effort).
        try:
            os.chmod(pcap_file_abs, 0o600)
        except Exception:
            pass

    if extra_tools.get("tshark") and pcap_file_abs and os.path.exists(pcap_file_abs):
        try:
            if _is_dry_run(dry_run):
                return result
            runner = _make_runner(logger=logger, timeout=10.0)
            res = runner.run(
                [extra_tools["tshark"], "-r", pcap_file_abs, "-q", "-z", "io,phs"],
                capture_output=True,
                check=False,
                text=True,
                timeout=10.0,
            )
            if res.timed_out:
                result["tshark_error"] = "Timeout after 10s"
            else:
                summary = (str(res.stdout or "") or str(res.stderr or ""))[:2000]
                if summary.strip():
                    result["tshark_summary"] = summary
        except Exception as exc:
            result["tshark_error"] = str(exc)

    return result
