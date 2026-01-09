#!/usr/bin/env python3
"""
Unit tests for SNMP v3 Scanner (auth_snmp.py)
"""

import unittest
from unittest.mock import MagicMock, patch
import sys

# Mock pysnmp if not present
sys.modules["pysnmp"] = MagicMock()
sys.modules["pysnmp.hlapi"] = MagicMock()

from redaudit.core.auth_snmp import SNMPScanner, SNMPHostInfo
from redaudit.core.credentials import Credential


@patch("redaudit.core.auth_snmp.PYSNMP_AVAILABLE", True)
class TestSNMPScanner(unittest.TestCase):

    def setUp(self):
        self.credential = Credential(
            username="snmpuser",
            # We assume these fields are present on credential object
            # or dynamically assigned in real flow.
            # In test, we assign them.
            password="authpass",  # Generic generic password used as fallback/primary
        )
        self.credential.snmp_auth_proto = "SHA"
        self.credential.snmp_priv_proto = "AES"
        self.credential.snmp_priv_pass = "privpass"

    def test_init_raises_if_missing_dependency(self):
        with patch("redaudit.core.auth_snmp.PYSNMP_AVAILABLE", False):
            with self.assertRaises(ImportError):
                SNMPScanner(self.credential)

    @patch("redaudit.core.auth_snmp.getCmd")
    def test_get_system_info_success(self, mock_getCmd):
        """Test successful retrieval of system info."""
        scanner = SNMPScanner(self.credential)

        # Mock getCmd return = (errorIndication, errorStatus, errorIndex, varBinds)
        # varBinds is list of (oid, value)

        # We queried 5 OIDs
        var_binds = [
            (None, "Linux System"),  # sysDescr
            (None, "host1"),  # sysName
            (None, "1000"),  # sysUpTime
            (None, "admin@corp"),  # sysContact
            (None, "DC1"),  # sysLocation
        ]

        # return iterator
        mock_getCmd.return_value = iter([(None, 0, 0, var_binds)])

        info = scanner.get_system_info("192.168.1.1")

        self.assertEqual(info.sys_descr, "Linux System")
        self.assertEqual(info.sys_name, "host1")
        self.assertEqual(info.sys_uptime, "1000")
        self.assertIsNone(info.error)

    @patch("redaudit.core.auth_snmp.getCmd")
    def test_get_system_info_error(self, mock_getCmd):
        """Test error handling."""
        scanner = SNMPScanner(self.credential)

        # Simulate timeout
        mock_getCmd.return_value = iter([("Request Timed Out", 0, 0, [])])

        info = scanner.get_system_info("192.168.1.1")
        self.assertEqual(info.error, "Request Timed Out")


if __name__ == "__main__":
    unittest.main()
