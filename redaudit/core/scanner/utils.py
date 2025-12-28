#!/usr/bin/env python3
"""
Scanner Utilities - RedAudit
Separated from scanner.py for modularity.
"""

import re
import ipaddress
from typing import Optional

from redaudit.utils.constants import (
    MAX_INPUT_LENGTH,
    WEB_SERVICES_KEYWORDS,
    WEB_SERVICES_EXACT,
    SUSPICIOUS_SERVICE_KEYWORDS,
)


def sanitize_ip(ip_str) -> Optional[str]:
    """
    Sanitize and validate IP address (supports both IPv4 and IPv6).
    """
    if ip_str is None:
        return None
    if not isinstance(ip_str, str):
        return None
    ip_str = ip_str.strip()
    if not ip_str:
        return None
    if len(ip_str) > MAX_INPUT_LENGTH:
        return None
    try:
        ipaddress.ip_address(ip_str)
        return ip_str
    except (ValueError, TypeError):
        return None


def is_ipv6(ip_str: str) -> bool:
    """
    Check if an IP address string is IPv6.
    """
    try:
        return ipaddress.ip_address(ip_str).version == 6
    except (ValueError, TypeError):
        return False


def is_ipv6_network(network_str: str) -> bool:
    """
    Check if a network CIDR string is IPv6.
    """
    try:
        return ipaddress.ip_network(network_str, strict=False).version == 6
    except (ValueError, TypeError):
        return False


def sanitize_hostname(hostname) -> Optional[str]:
    """
    Sanitize and validate hostname.
    """
    if hostname is None:
        return None
    if not isinstance(hostname, str):
        return None
    hostname = hostname.strip()
    if not hostname:
        return None
    if len(hostname) > MAX_INPUT_LENGTH:
        return None
    if re.match(r"^[a-zA-Z0-9\.\-]+$", hostname):
        return hostname
    return None


def is_web_service(name: str) -> bool:
    """
    Check if a service name indicates a web service.
    """
    if not name:
        return False
    n = name.lower()
    if n in WEB_SERVICES_EXACT:
        return True
    return any(k in n for k in WEB_SERVICES_KEYWORDS)


def is_suspicious_service(name: str) -> bool:
    """
    Check if a service name indicates a suspicious/interesting service.
    """
    if not name:
        return False
    lname = name.lower()
    return any(k in lname for k in SUSPICIOUS_SERVICE_KEYWORDS)


def is_port_anomaly(port: int, service_name: str) -> bool:
    """
    v3.2.2b: Detect anomalous services on standard ports.
    """
    from redaudit.utils.constants import STANDARD_PORT_SERVICES

    if not service_name or port not in STANDARD_PORT_SERVICES:
        return False

    expected = STANDARD_PORT_SERVICES.get(port, [])
    if not expected:
        return False

    svc_lower = service_name.lower()
    # Check if any expected keyword appears in the service name
    for exp in expected:
        if exp in svc_lower:
            return False

    # Service doesn't match any expected - anomaly!
    return True
