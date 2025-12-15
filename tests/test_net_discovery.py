#!/usr/bin/env python3
"""
Tests for net_discovery module.
"""

import unittest
from unittest.mock import MagicMock, patch

from redaudit.core.net_discovery import (
    _check_tools,
    dhcp_discover,
    fping_sweep,
    netbios_discover,
    netdiscover_scan,
    mdns_discover,
    upnp_discover,
    discover_networks,
    _analyze_vlans,
)


class TestToolCheck(unittest.TestCase):
    """Test tool availability detection."""

    @patch("shutil.which")
    def test_check_tools_all_available(self, mock_which):
        mock_which.return_value = "/usr/bin/tool"
        tools = _check_tools()
        self.assertTrue(tools["nmap"])
        self.assertTrue(tools["fping"])
        self.assertTrue(tools["nbtscan"])

    @patch("shutil.which")
    def test_check_tools_none_available(self, mock_which):
        mock_which.return_value = None
        tools = _check_tools()
        self.assertFalse(tools["nmap"])
        self.assertFalse(tools["fping"])


class TestDHCPDiscover(unittest.TestCase):
    """Test DHCP discovery parsing."""

    @patch("shutil.which")
    def test_dhcp_no_nmap(self, mock_which):
        mock_which.return_value = None
        result = dhcp_discover()
        self.assertEqual(result["error"], "nmap not available")
        self.assertEqual(result["servers"], [])

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_dhcp_parse_single_server(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/nmap"
        mock_run.return_value = (0, """
Pre-scan script results:
| broadcast-dhcp-discover:
|   Response 1 of 1:
|     DHCPOFFER:
|       Server Identifier: 192.168.178.1
|       IP Address Offered: 192.168.178.50
|       Subnet Mask: 255.255.255.0
|       Router: 192.168.178.1
|       Domain Name Server: 8.8.8.8
""", "")
        
        result = dhcp_discover()
        self.assertIsNone(result["error"])
        self.assertEqual(len(result["servers"]), 1)
        self.assertEqual(result["servers"][0]["ip"], "192.168.178.1")
        self.assertEqual(result["servers"][0]["gateway"], "192.168.178.1")


class TestFpingSweep(unittest.TestCase):
    """Test fping sweep parsing."""

    @patch("shutil.which")
    def test_fping_not_available(self, mock_which):
        mock_which.return_value = None
        result = fping_sweep("192.168.1.0/24")
        self.assertEqual(result["error"], "fping not available")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_fping_parse_hosts(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/fping"
        mock_run.return_value = (0, """192.168.1.1
192.168.1.2
192.168.1.10
""", "")
        
        result = fping_sweep("192.168.1.0/24")
        self.assertIsNone(result["error"])
        self.assertEqual(len(result["alive_hosts"]), 3)
        self.assertIn("192.168.1.1", result["alive_hosts"])


class TestNetBIOSDiscover(unittest.TestCase):
    """Test NetBIOS discovery parsing."""

    @patch("shutil.which")
    def test_netbios_no_tools(self, mock_which):
        mock_which.return_value = None
        result = netbios_discover("192.168.1.0/24")
        self.assertEqual(result["error"], "Neither nbtscan nor nmap available")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_netbios_nbtscan_parse(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/nbtscan"
        mock_run.return_value = (0, """
IP               NetBIOS Name     Server    User              MAC
192.168.1.10     DESKTOP-ABC      <server>  ADMIN             aa:bb:cc:dd:ee:ff
192.168.1.20     LAPTOP-XYZ       <server>  USER              11:22:33:44:55:66
""", "")
        
        result = netbios_discover("192.168.1.0/24")
        self.assertIsNone(result["error"])
        self.assertEqual(len(result["hosts"]), 2)
        self.assertEqual(result["hosts"][0]["name"], "DESKTOP-ABC")


class TestNetdiscoverScan(unittest.TestCase):
    """Test netdiscover ARP scan parsing."""

    @patch("shutil.which")
    def test_netdiscover_not_available(self, mock_which):
        mock_which.return_value = None
        result = netdiscover_scan("192.168.1.0/24")
        self.assertEqual(result["error"], "netdiscover not available")

    @patch("redaudit.core.net_discovery._run_cmd")
    @patch("shutil.which")
    def test_netdiscover_parse(self, mock_which, mock_run):
        mock_which.return_value = "/usr/bin/netdiscover"
        mock_run.return_value = (0, """
192.168.1.1     d4:24:dd:07:7c:c5      1      60  Unknown vendor
192.168.1.10    aa:bb:cc:dd:ee:ff      1      60  Intel Corporation
""", "")
        
        result = netdiscover_scan("192.168.1.0/24")
        self.assertIsNone(result["error"])
        self.assertEqual(len(result["hosts"]), 2)
        self.assertEqual(result["hosts"][0]["mac"], "d4:24:dd:07:7c:c5")


class TestVLANAnalysis(unittest.TestCase):
    """Test VLAN candidate detection."""

    def test_single_dhcp_no_vlan(self):
        result = {
            "dhcp_servers": [
                {"ip": "192.168.1.1", "subnet": "255.255.255.0", "gateway": "192.168.1.1"}
            ]
        }
        candidates = _analyze_vlans(result)
        self.assertEqual(len(candidates), 0)

    def test_multiple_dhcp_suggests_vlan(self):
        result = {
            "dhcp_servers": [
                {"ip": "192.168.1.1", "subnet": "255.255.255.0", "gateway": "192.168.1.1"},
                {"ip": "192.168.2.1", "subnet": "255.255.255.0", "gateway": "192.168.2.1"},
            ]
        }
        candidates = _analyze_vlans(result)
        self.assertEqual(len(candidates), 1)
        self.assertIn("guest", candidates[0]["description"].lower())


class TestDiscoverNetworks(unittest.TestCase):
    """Test main discover_networks function."""

    @patch("redaudit.core.net_discovery._check_tools")
    @patch("redaudit.core.net_discovery.dhcp_discover")
    @patch("redaudit.core.net_discovery.fping_sweep")
    def test_discover_networks_basic(self, mock_fping, mock_dhcp, mock_tools):
        mock_tools.return_value = {"nmap": True, "fping": True, "nbtscan": False}
        mock_dhcp.return_value = {"servers": [], "error": None}
        mock_fping.return_value = {"alive_hosts": ["192.168.1.1"], "error": None}
        
        result = discover_networks(
            target_networks=["192.168.1.0/24"],
            protocols=["dhcp", "fping"],
        )
        
        self.assertTrue(result["enabled"])
        self.assertIn("dhcp", result["protocols_used"])
        self.assertEqual(len(result["alive_hosts"]), 1)


if __name__ == "__main__":
    unittest.main()
