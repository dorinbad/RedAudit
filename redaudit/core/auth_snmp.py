#!/usr/bin/env python3
"""
RedAudit - SNMP v3 Authenticated Scanner (Phase 4.3)
Uses PySNMP to perform authenticated enumeration of network devices.
"""

import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

from redaudit.core.credentials import Credential

# Optional Dependency: PySNMP
try:
    from pysnmp.hlapi import (
        SnmpEngine,
        UsmUserData,
        UdpTransportTarget,
        ContextData,
        ObjectType,
        ObjectIdentity,
        getCmd,
        usmHMACSHAAuthProtocol,
        usmAesCfb128Protocol,
    )

    PYSNMP_AVAILABLE = True
except ImportError:
    PYSNMP_AVAILABLE = False

    class UsmUserData:  # type: ignore[no-redef]
        pass


logger = logging.getLogger("redaudit.auth_snmp")


@dataclass
class SNMPHostInfo:
    sys_descr: str = "unknown"
    sys_name: str = "unknown"
    sys_uptime: str = "unknown"
    sys_contact: str = "unknown"
    sys_location: str = "unknown"
    interfaces: List[Dict[str, str]] = None
    routes: List[Dict[str, str]] = None
    arp_table: List[Dict[str, str]] = None
    error: Optional[str] = None


class SNMPScanner:
    """Authenticated SNMP v3 scanner wrapper."""

    def __init__(self, credential: Credential, timeout: int = 5, retries: int = 1):
        if not PYSNMP_AVAILABLE:
            raise ImportError("PySNMP library not found. Install via 'pip install pysnmp'.")

        self.credential = credential
        self.timeout = timeout
        self.retries = retries
        self.snmp_engine = SnmpEngine()

        # Determine Auth/Priv protocols
        # Credential object defines username/pass.
        # But SNMP v3 needs: Auth Proto, Auth Pass, Priv Proto, Priv Pass.
        # We need to extend Credential or pass extra config.
        # For now, we'll assume extra fields are passed in specific config keys,
        # or we rely on extended Credential properties (which don't strictly exist yet in base class).
        # Or we map from CLI args passed via a specialized dict/object if needed.
        # Implementation Plan says CLI: --snmp-auth-proto etc.
        # But Credentials class is generic.
        # We will parse these from 'extra' or assume standard if generic.
        # Let's assume for MVP: generic Credential stores user/pass.
        # Extra fields (protos) might need to be passed in __init__?
        # Let's add them to `__init__` for flexibility.

        self.auth_proto = usmHMACSHAAuthProtocol
        self.auth_key = credential.password

        self.priv_proto = usmAesCfb128Protocol
        self.priv_key = None  # Derived or same?
        # Wait, usually AuthPass and PrivPass differ.
        # We need a way to pass extended creds.

        # TODO: Refactor Credential to support extra fields, or pass them here.
        # For now, we will use attributes if they exist on credential, or defaults.
        if hasattr(credential, "snmp_auth_proto"):
            self.auth_proto = credential.snmp_auth_proto
        if hasattr(credential, "snmp_priv_proto"):
            self.priv_proto = credential.snmp_priv_proto
        if hasattr(credential, "snmp_priv_pass"):
            self.priv_key = credential.snmp_priv_pass

        # Setup User Data
        # User, AuthKey, AuthProto, PrivKey, PrivProto
        self.user_data = UsmUserData(
            credential.username,
            self.auth_key,
            self.auth_proto,
            self.priv_key,
            (
                self.priv_protocol_map(self.priv_proto)
                if hasattr(self, "priv_protocol_map")
                else self.priv_proto
            ),
        )

    def priv_protocol_map(self, name_or_obj):
        # Helper to map string names to PySNMP objects if needed
        # For MVP we assume correct objects passed or we use defaults.
        # Implementation Detail:
        # We need to map string args (from CLI) to PySNMP objects.
        pass

    def get_system_info(self, host: str, port: int = 161) -> SNMPHostInfo:
        """Query system MIBs."""
        info = SNMPHostInfo(interfaces=[], routes=[], arp_table=[])
        target = UdpTransportTarget((host, port), timeout=self.timeout, retries=self.retries)

        try:
            # sysDescr .1.3.6.1.2.1.1.1.0
            # sysName .1.3.6.1.2.1.1.5.0
            errorIndication, errorStatus, errorIndex, varBinds = next(
                getCmd(
                    self.snmp_engine,
                    self.user_data,
                    target,
                    ContextData(),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysDescr", 0)),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysName", 0)),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysUpTime", 0)),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysContact", 0)),
                    ObjectType(ObjectIdentity("SNMPv2-MIB", "sysLocation", 0)),
                )
            )

            if errorIndication:
                info.error = str(errorIndication)
            elif errorStatus:
                info.error = f"{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or '?'}"
            else:
                info.sys_descr = str(varBinds[0][1])
                info.sys_name = str(varBinds[1][1])
                info.sys_uptime = str(varBinds[2][1])
                info.sys_contact = str(varBinds[3][1])
                info.sys_location = str(varBinds[4][1])

            return info

        except Exception as e:
            info.error = str(e)
            return info
