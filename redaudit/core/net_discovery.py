#!/usr/bin/env python3
"""
RedAudit - Enhanced Network Discovery Module
Copyright (C) 2025  Dorin Badea
GPLv3 License

v3.2: Active discovery of guest networks, hidden VLANs, and additional network segments.

Goals:
- Detect DHCP servers on multiple VLANs (including guest networks)
- Enumerate NetBIOS/mDNS hostnames for entity resolution
- Fast L2 mapping via netdiscover/fping
- Optional Red Team techniques for deeper enumeration
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple


def _run_cmd(
    args: List[str],
    timeout_s: int,
    logger=None,
) -> Tuple[int, str, str]:
    """Execute a command with timeout, returning (returncode, stdout, stderr)."""
    try:
        res = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        return res.returncode, res.stdout or "", res.stderr or ""
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        err = exc.stderr or ""
        if logger:
            logger.info("Net discovery command timed out: %s", args)
        return 124, out if isinstance(out, str) else "", err if isinstance(err, str) else ""
    except Exception as exc:
        if logger:
            logger.warning("Net discovery command failed: %s (%s)", args, exc)
        return 1, "", str(exc)


def _check_tools() -> Dict[str, bool]:
    """Check availability of discovery tools."""
    return {
        "nmap": bool(shutil.which("nmap")),
        "fping": bool(shutil.which("fping")),
        "nbtscan": bool(shutil.which("nbtscan")),
        "netdiscover": bool(shutil.which("netdiscover")),
        "avahi-browse": bool(shutil.which("avahi-browse")),
        "snmpwalk": bool(shutil.which("snmpwalk")),
        "enum4linux": bool(shutil.which("enum4linux")),
        "masscan": bool(shutil.which("masscan")),
    }


# =============================================================================
# DHCP Discovery
# =============================================================================

def dhcp_discover(
    interface: Optional[str] = None,
    timeout_s: int = 10,
    logger=None,
) -> Dict[str, Any]:
    """
    Discover DHCP servers using nmap broadcast-dhcp-discover script.
    
    Returns:
        {
            "servers": [{"ip": "...", "subnet": "...", "gateway": "...", "dns": [...]}],
            "error": None or "error message"
        }
    """
    result: Dict[str, Any] = {"servers": [], "error": None}
    
    if not shutil.which("nmap"):
        result["error"] = "nmap not available"
        return result
    
    cmd = ["nmap", "--script", "broadcast-dhcp-discover"]
    if interface:
        cmd.extend(["-e", interface])
    
    rc, out, err = _run_cmd(cmd, timeout_s, logger)
    
    if rc != 0 and not out.strip():
        result["error"] = err.strip() or "nmap dhcp-discover failed"
        return result
    
    # Parse DHCP responses
    # Example output:
    # | DHCPOFFER:
    # |   Server Identifier: 192.168.178.1
    # |   IP Address Offered: 192.168.178.50
    # |   Subnet Mask: 255.255.255.0
    # |   Router: 192.168.178.1
    # |   Domain Name Server: 8.8.8.8
    
    current_server: Dict[str, Any] = {}
    for line in out.splitlines():
        line = line.strip()
        
        if "DHCPOFFER" in line or "DHCPACK" in line:
            if current_server.get("ip"):
                result["servers"].append(current_server)
            current_server = {"dns": []}
        
        if "Server Identifier:" in line:
            match = re.search(r"Server Identifier:\s*(\S+)", line)
            if match:
                current_server["ip"] = match.group(1)
        
        if "Subnet Mask:" in line:
            match = re.search(r"Subnet Mask:\s*(\S+)", line)
            if match:
                current_server["subnet"] = match.group(1)
        
        if "Router:" in line:
            match = re.search(r"Router:\s*(\S+)", line)
            if match:
                current_server["gateway"] = match.group(1)
        
        if "Domain Name Server:" in line:
            match = re.search(r"Domain Name Server:\s*(\S+)", line)
            if match:
                current_server.setdefault("dns", []).append(match.group(1))
    
    if current_server.get("ip"):
        result["servers"].append(current_server)
    
    return result


# =============================================================================
# Fping Sweep
# =============================================================================

def fping_sweep(
    target: str,
    timeout_s: int = 30,
    logger=None,
) -> Dict[str, Any]:
    """
    Fast ICMP host discovery using fping.
    
    Args:
        target: Network range (e.g., "192.168.178.0/24")
    
    Returns:
        {
            "alive_hosts": ["192.168.178.1", "192.168.178.2", ...],
            "error": None or "error message"
        }
    """
    result: Dict[str, Any] = {"alive_hosts": [], "error": None}
    
    if not shutil.which("fping"):
        result["error"] = "fping not available"
        return result
    
    cmd = ["fping", "-a", "-g", target, "-q"]
    rc, out, err = _run_cmd(cmd, timeout_s, logger)
    
    # fping returns non-zero if some hosts are unreachable, but stdout still has alive hosts
    for line in out.splitlines():
        ip = line.strip()
        if ip and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", ip):
            result["alive_hosts"].append(ip)
    
    # Also check stderr for alive hosts (some versions output there)
    for line in err.splitlines():
        if "is alive" in line:
            match = re.match(r"^(\d{1,3}(?:\.\d{1,3}){3})", line)
            if match and match.group(1) not in result["alive_hosts"]:
                result["alive_hosts"].append(match.group(1))
    
    return result


# =============================================================================
# NetBIOS Discovery
# =============================================================================

def netbios_discover(
    target: str,
    timeout_s: int = 30,
    logger=None,
) -> Dict[str, Any]:
    """
    Discover Windows hosts via NetBIOS name queries.
    
    Args:
        target: Network range (e.g., "192.168.178.0/24")
    
    Returns:
        {
            "hosts": [{"ip": "...", "name": "...", "workgroup": "...", "mac": "..."}],
            "error": None or "error message"
        }
    """
    result: Dict[str, Any] = {"hosts": [], "error": None}
    
    # Try nbtscan first (faster), fall back to nmap
    if shutil.which("nbtscan"):
        cmd = ["nbtscan", "-r", target]
        rc, out, err = _run_cmd(cmd, timeout_s, logger)
        
        if rc == 0 or out.strip():
            # Parse nbtscan output
            # IP             NetBIOS Name     Server    User              MAC
            # 192.168.178.10 DESKTOP-ABC      <server>  <user>           aa:bb:cc:dd:ee:ff
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", parts[0]):
                    host = {"ip": parts[0], "name": parts[1]}
                    if len(parts) >= 5:
                        host["mac"] = parts[-1] if ":" in parts[-1] else None
                    result["hosts"].append(host)
            return result
    
    # Fallback to nmap
    if shutil.which("nmap"):
        cmd = ["nmap", "-sU", "-p", "137", "--script", "nbstat", target]
        rc, out, err = _run_cmd(cmd, timeout_s, logger)
        
        if rc == 0 or out.strip():
            # Parse nmap nbstat output
            current_ip = None
            for line in out.splitlines():
                ip_match = re.search(r"Nmap scan report for (\S+)", line)
                if ip_match:
                    current_ip = ip_match.group(1)
                
                name_match = re.search(r"NetBIOS name:\s*(\S+)", line, re.IGNORECASE)
                if name_match and current_ip:
                    result["hosts"].append({
                        "ip": current_ip,
                        "name": name_match.group(1),
                    })
            return result
    
    result["error"] = "Neither nbtscan nor nmap available"
    return result


# =============================================================================
# Netdiscover (ARP)
# =============================================================================

def netdiscover_scan(
    target: str,
    timeout_s: int = 15,
    logger=None,
) -> Dict[str, Any]:
    """
    Fast L2 ARP discovery using netdiscover.
    
    Args:
        target: Network range (e.g., "192.168.178.0/24")
    
    Returns:
        {
            "hosts": [{"ip": "...", "mac": "...", "vendor": "..."}],
            "error": None or "error message"
        }
    """
    result: Dict[str, Any] = {"hosts": [], "error": None}
    
    if not shutil.which("netdiscover"):
        result["error"] = "netdiscover not available"
        return result
    
    # -P = passive/parseable output, -r = range
    cmd = ["netdiscover", "-r", target, "-P", "-N"]
    rc, out, err = _run_cmd(cmd, timeout_s, logger)
    
    # Parse netdiscover output
    # IP               At MAC Address     Count     Len  MAC Vendor
    # 192.168.178.1    d4:24:dd:07:7c:c5      1      60  Unknown vendor
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", parts[0]):
            host = {
                "ip": parts[0],
                "mac": parts[1] if len(parts) > 1 else None,
            }
            # Vendor is everything after the first few columns
            if len(parts) > 4:
                host["vendor"] = " ".join(parts[4:])
            result["hosts"].append(host)
    
    return result


# =============================================================================
# mDNS Discovery
# =============================================================================

def mdns_discover(
    timeout_s: int = 5,
    logger=None,
) -> Dict[str, Any]:
    """
    Discover services via mDNS/Bonjour.
    
    Returns:
        {
            "services": [{"ip": "...", "name": "...", "type": "..."}],
            "error": None or "error message"
        }
    """
    result: Dict[str, Any] = {"services": [], "error": None}
    
    if shutil.which("avahi-browse"):
        # -a = all services, -p = parseable, -t = terminate after timeout
        cmd = ["avahi-browse", "-apt", "--resolve"]
        rc, out, err = _run_cmd(cmd, timeout_s, logger)
        
        # Parse avahi-browse output
        # =;eth0;IPv4;hostname;_http._tcp;local
        for line in out.splitlines():
            if line.startswith("="):
                parts = line.split(";")
                if len(parts) >= 5:
                    service = {
                        "interface": parts[1],
                        "name": parts[3],
                        "type": parts[4],
                    }
                    # Look for IP in resolved output
                    if len(parts) >= 8:
                        service["ip"] = parts[7]
                    result["services"].append(service)
        return result
    
    # Fallback to nmap dns-service-discovery
    if shutil.which("nmap"):
        cmd = ["nmap", "--script", "dns-service-discovery", "-p", "5353", "224.0.0.251"]
        rc, out, err = _run_cmd(cmd, timeout_s, logger)
        # Basic parsing - nmap output is more complex
        if "_tcp" in out or "_udp" in out:
            result["services"].append({"raw": out[:500], "type": "nmap_raw"})
        return result
    
    result["error"] = "Neither avahi-browse nor nmap available"
    return result


# =============================================================================
# UPNP Discovery
# =============================================================================

def upnp_discover(
    timeout_s: int = 10,
    logger=None,
) -> Dict[str, Any]:
    """
    Discover UPNP devices (routers, NAS, media servers).
    
    Returns:
        {
            "devices": [{"ip": "...", "device": "...", "services": [...]}],
            "error": None or "error message"
        }
    """
    result: Dict[str, Any] = {"devices": [], "error": None}
    
    if not shutil.which("nmap"):
        result["error"] = "nmap not available"
        return result
    
    cmd = ["nmap", "--script", "broadcast-upnp-info"]
    rc, out, err = _run_cmd(cmd, timeout_s, logger)
    
    # Parse UPNP responses
    current_device: Dict[str, Any] = {}
    for line in out.splitlines():
        line = line.strip()
        
        if "Server:" in line:
            if current_device.get("ip"):
                result["devices"].append(current_device)
            current_device = {"services": []}
            match = re.search(r"Server:\s*(.+)", line)
            if match:
                current_device["device"] = match.group(1)
        
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}:", line):
            current_device["ip"] = line.split(":")[0]
        
        if "urn:" in line:
            current_device.setdefault("services", []).append(line.strip())
    
    if current_device.get("ip") or current_device.get("device"):
        result["devices"].append(current_device)
    
    return result


# =============================================================================
# Main Discovery Function
# =============================================================================

def discover_networks(
    target_networks: List[str],
    interface: Optional[str] = None,
    protocols: Optional[List[str]] = None,
    redteam: bool = False,
    extra_tools: Optional[Dict[str, str]] = None,
    logger=None,
) -> Dict[str, Any]:
    """
    Main entry point for enhanced network discovery.
    
    Args:
        target_networks: List of network ranges to scan
        interface: Network interface to use (optional)
        protocols: List of protocols to use (dhcp, netbios, mdns, upnp, arp, fping)
                   If None, uses all available
        redteam: Enable Red Team techniques (slower, noisier)
        extra_tools: Override tool paths
        logger: Logger instance
    
    Returns:
        Complete net_discovery result object for JSON report
    """
    if protocols is None:
        protocols = ["dhcp", "fping", "netbios", "mdns", "upnp", "arp"]
    
    tools = _check_tools()
    errors: List[str] = []
    
    result: Dict[str, Any] = {
        "enabled": True,
        "generated_at": datetime.now().isoformat(),
        "protocols_used": protocols,
        "redteam_enabled": redteam,
        "tools": tools,
        "dhcp_servers": [],
        "alive_hosts": [],
        "netbios_hosts": [],
        "arp_hosts": [],
        "mdns_services": [],
        "upnp_devices": [],
        "candidate_vlans": [],
        "errors": errors,
    }
    
    # DHCP Discovery
    if "dhcp" in protocols:
        dhcp_result = dhcp_discover(interface=interface, logger=logger)
        if dhcp_result.get("servers"):
            result["dhcp_servers"] = dhcp_result["servers"]
        if dhcp_result.get("error"):
            errors.append(f"dhcp: {dhcp_result['error']}")
    
    # Fping sweep (for each target network)
    if "fping" in protocols:
        all_alive = []
        for target in target_networks:
            fping_result = fping_sweep(target, logger=logger)
            all_alive.extend(fping_result.get("alive_hosts", []))
            if fping_result.get("error"):
                errors.append(f"fping ({target}): {fping_result['error']}")
        result["alive_hosts"] = list(set(all_alive))
    
    # NetBIOS discovery
    if "netbios" in protocols:
        all_netbios = []
        for target in target_networks:
            netbios_result = netbios_discover(target, logger=logger)
            all_netbios.extend(netbios_result.get("hosts", []))
            if netbios_result.get("error"):
                errors.append(f"netbios ({target}): {netbios_result['error']}")
        result["netbios_hosts"] = all_netbios
    
    # ARP discovery via netdiscover
    if "arp" in protocols:
        all_arp = []
        for target in target_networks:
            arp_result = netdiscover_scan(target, logger=logger)
            all_arp.extend(arp_result.get("hosts", []))
            if arp_result.get("error"):
                errors.append(f"arp ({target}): {arp_result['error']}")
        result["arp_hosts"] = all_arp
    
    # mDNS discovery
    if "mdns" in protocols:
        mdns_result = mdns_discover(logger=logger)
        if mdns_result.get("services"):
            result["mdns_services"] = mdns_result["services"]
        if mdns_result.get("error"):
            errors.append(f"mdns: {mdns_result['error']}")
    
    # UPNP discovery
    if "upnp" in protocols:
        upnp_result = upnp_discover(logger=logger)
        if upnp_result.get("devices"):
            result["upnp_devices"] = upnp_result["devices"]
        if upnp_result.get("error"):
            errors.append(f"upnp: {upnp_result['error']}")
    
    # Analyze for candidate VLANs
    result["candidate_vlans"] = _analyze_vlans(result)
    
    # Red Team techniques (optional)
    if redteam:
        _run_redteam_discovery(result, target_networks, logger)
    
    return result


def _analyze_vlans(discovery_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Analyze discovery results to identify potential VLANs/guest networks.
    """
    candidates = []
    
    # If multiple DHCP servers found with different subnets, likely different VLANs
    dhcp_servers = discovery_result.get("dhcp_servers", [])
    seen_subnets = set()
    
    for server in dhcp_servers:
        subnet = server.get("subnet")
        gateway = server.get("gateway")
        if subnet and gateway:
            network_key = f"{gateway}/{subnet}"
            if network_key not in seen_subnets:
                seen_subnets.add(network_key)
                if len(seen_subnets) > 1:
                    candidates.append({
                        "source": "dhcp_server",
                        "gateway": gateway,
                        "subnet": subnet,
                        "description": "Additional DHCP server detected (possible guest/VLAN)",
                    })
    
    return candidates


def _run_redteam_discovery(
    result: Dict[str, Any],
    target_networks: List[str],
    logger=None,
) -> None:
    """
    Run optional Red Team discovery techniques.
    Modifies result in place.
    """
    # TODO: Implement in Phase 2
    # - SNMP walking
    # - SMB enumeration
    # - Masscan sweep
    # - VLAN enumeration (yersinia)
    result["redteam"] = {
        "snmp": {"status": "not_implemented"},
        "smb": {"status": "not_implemented"},
        "vlan_enum": {"status": "not_implemented"},
    }
