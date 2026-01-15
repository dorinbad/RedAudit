"""
masscan_scanner.py - Fast port discovery using masscan for HyperScan-First.

v4.7.0: New module to replace slow scapy SYN scanner with masscan.
Masscan can scan 65535 ports in seconds vs minutes with scapy.
"""

import os
import re
import shutil
import subprocess
from typing import Dict, List


def is_masscan_available() -> bool:
    """Check if masscan is installed and we have root privileges."""
    if not shutil.which("masscan"):
        return False
    return os.geteuid() == 0


def masscan_sweep(
    target_ip: str,
    ports: str = "1-10000",
    rate: int = 1000,
    timeout_s: int = 60,
    logger=None,
) -> List[int]:
    """
    Run masscan on a single IP and return list of open ports.

    Args:
        target_ip: Single IP address to scan
        ports: Port specification (default: "1-10000" for top 10K)
        rate: Packets per second (default: 1000)
        timeout_s: Command timeout in seconds
        logger: Optional logger

    Returns:
        List of open port numbers
    """
    if not is_masscan_available():
        if logger:
            logger.debug("masscan_sweep: masscan not available, returning empty")
        return []

    cmd = [
        "masscan",
        target_ip,
        "-p",
        ports,
        "--rate",
        str(rate),
        "--wait",
        "2",  # Wait 2s for responses after scan
        "--open-only",
    ]

    if logger:
        logger.debug("masscan_sweep: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        output = (result.stdout or "") + "\n" + (result.stderr or "")
    except subprocess.TimeoutExpired:
        if logger:
            logger.warning("masscan_sweep timeout for %s", target_ip)
        return []
    except Exception as e:
        if logger:
            logger.warning("masscan_sweep error for %s: %s", target_ip, e)
        return []

    # Parse masscan output: "Discovered open port 22/tcp on 192.168.1.1"
    open_ports: List[int] = []
    for line in output.splitlines():
        match = re.search(
            r"Discovered open port (\d+)/tcp on",
            line,
            re.IGNORECASE,
        )
        if match:
            try:
                port = int(match.group(1))
                if port not in open_ports:
                    open_ports.append(port)
            except ValueError:
                pass

    if logger:
        logger.debug("masscan_sweep %s: %d open ports", target_ip, len(open_ports))

    return sorted(open_ports)


def masscan_batch_sweep(
    target_ips: List[str],
    ports: str = "1-10000",
    rate: int = 2000,
    timeout_s: int = 120,
    logger=None,
) -> Dict[str, List[int]]:
    """
    Scan multiple IPs at once with masscan (more efficient than individual calls).

    Args:
        target_ips: List of IP addresses
        ports: Port specification
        rate: Packets per second (higher for batch)
        timeout_s: Command timeout
        logger: Optional logger

    Returns:
        Dict mapping IP -> list of open ports
    """
    if not target_ips:
        return {}

    if not is_masscan_available():
        if logger:
            logger.debug("masscan_batch_sweep: not available")
        return {}

    cmd = [
        "masscan",
        "-p",
        ports,
        "--rate",
        str(rate),
        "--wait",
        "3",
        "--open-only",
    ] + target_ips

    if logger:
        logger.debug("masscan_batch_sweep: %d targets, ports=%s", len(target_ips), ports)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        output = (result.stdout or "") + "\n" + (result.stderr or "")
    except subprocess.TimeoutExpired:
        if logger:
            logger.warning("masscan_batch_sweep timeout")
        return {}
    except Exception as e:
        if logger:
            logger.warning("masscan_batch_sweep error: %s", e)
        return {}

    # Parse output
    results: Dict[str, List[int]] = {ip: [] for ip in target_ips}
    for line in output.splitlines():
        match = re.search(
            r"Discovered open port (\d+)/tcp on (\d{1,3}(?:\.\d{1,3}){3})",
            line,
            re.IGNORECASE,
        )
        if match:
            try:
                port = int(match.group(1))
                ip = match.group(2)
                if ip in results and port not in results[ip]:
                    results[ip].append(port)
            except (ValueError, KeyError):
                pass

    # Sort ports for each IP
    for ip in results:
        results[ip] = sorted(results[ip])

    if logger:
        total_ports = sum(len(p) for p in results.values())
        logger.debug("masscan_batch_sweep: %d total ports found", total_ports)

    return results
