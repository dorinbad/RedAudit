#!/usr/bin/env python3
"""
RedAudit - Topology Discovery Tests
Copyright (C) 2025  Dorin Badea
GPLv3 License

Unit tests for redaudit/core/topology.py (best-effort topology discovery).
"""

import os
import sys
import json
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from redaudit.core.topology import (
    _discover_topology_async,
    _discover_topology_sync,
    _extract_lldp_neighbors,
    _networks_from_route_table,
    _parse_ip_neigh,
    _parse_ip_route,
    _parse_vlan_ids_from_ip_link,
    discover_topology,
)


class TestTopologyDiscovery(unittest.TestCase):
    def test_discover_topology_parses_outputs(self):
        route_out = "\n".join(
            [
                "default via 192.168.1.1 dev eth0 proto dhcp metric 100",
                "10.0.0.0/8 via 192.168.1.254 dev eth0 metric 200",
                "192.168.1.0/24 dev eth0 proto kernel scope link src 192.168.1.100 metric 100",
            ]
        )

        arp_out = "\n".join(
            [
                "Interface: eth0, datalink type: EN10MB (Ethernet)",
                "Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)",
                "192.168.1.1\tAA:BB:CC:DD:EE:FF\tExampleVendor",
                "Ending arp-scan 1.10.0: 256 hosts scanned in 2.000 seconds (1.28 hosts/sec). 1 responded",
            ]
        )

        neigh_out = "192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE\n"

        ip_link_out = "\n".join(
            [
                "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP mode DEFAULT group default qlen 1000",
                "    link/ether aa:bb:cc:dd:ee:01 brd ff:ff:ff:ff:ff:ff",
                "    vlan protocol 802.1Q id 10 <REORDER_HDR>",
            ]
        )

        tcpdump_vlan_out = "12:34:56.789012 vlan 20, p 0, ethertype IPv4, length 60: 192.168.1.2 > 192.168.1.255: UDP\n"

        lldp_json_obj = {
            "lldp": {
                "interface": {
                    "eth0": {
                        "chassis": {
                            "name": "sw1",
                            "descr": "Example Switch",
                            "mgmt-ip": "192.168.1.2",
                            "id": {"value": "aa:bb:cc:dd:ee:ff"},
                        },
                        "port": {
                            "id": {"value": "Gi1/0/1"},
                            "descr": "Uplink",
                        },
                    }
                }
            }
        }
        lldp_out = json.dumps(lldp_json_obj)

        tcpdump_cdp_out = "\n".join(
            [
                "12:00:00.000000 aa:bb:cc:dd:ee:01 > 01:00:0c:cc:cc:cc, ethertype Unknown (0x2000), length 102: CDP",
                "12:00:01.000000 aa:bb:cc:dd:ee:01 > 01:00:0c:cc:cc:cc, ethertype Unknown (0x2000), length 102: CDP",
            ]
        )

        def fake_which(name: str):
            return f"/usr/bin/{name}"

        def fake_run_cmd(args, timeout_s, logger=None):
            if args == ["ip", "route", "show"]:
                return 0, route_out, ""
            if args == ["lldpctl", "-f", "json"]:
                return 0, lldp_out, ""
            if args[:4] == ["arp-scan", "--localnet", "--interface", "eth0"]:
                return 0, arp_out, ""
            if args == ["ip", "neigh", "show", "dev", "eth0"]:
                return 0, neigh_out, ""
            if args == ["ip", "-d", "link", "show", "dev", "eth0"]:
                return 0, ip_link_out, ""
            if args[:6] == ["tcpdump", "-nn", "-e", "-i", "eth0", "-c"] and args[-1] == "vlan":
                return 0, tcpdump_vlan_out, ""
            if (
                args[:6] == ["tcpdump", "-nn", "-e", "-i", "eth0", "-c"]
                and args[-1] == "01:00:0c:cc:cc:cc"
            ):
                return 0, tcpdump_cdp_out, ""
            return 1, "", "unexpected command"

        network_info = [
            {
                "interface": "eth0",
                "ip": "192.168.1.100",
                "network": "192.168.1.0/24",
                "hosts_estimated": 256,
            }
        ]

        with patch("redaudit.core.topology.shutil.which", side_effect=fake_which):
            with patch("redaudit.core.topology._run_cmd", side_effect=fake_run_cmd):
                topo = discover_topology(
                    target_networks=["192.168.1.0/24"],
                    network_info=network_info,
                    extra_tools={"tcpdump": "/usr/bin/tcpdump"},
                )

        self.assertTrue(topo.get("enabled"))
        self.assertIn("generated_at", topo)
        self.assertEqual(topo.get("default_gateway", {}).get("ip"), "192.168.1.1")

        self.assertEqual(topo.get("candidate_networks"), ["10.0.0.0/8"])

        interfaces = topo.get("interfaces") or []
        self.assertEqual(len(interfaces), 1)
        iface0 = interfaces[0]
        self.assertEqual(iface0.get("interface"), "eth0")

        vlan_ids = (iface0.get("vlan") or {}).get("ids") or []
        self.assertIn(10, vlan_ids)
        self.assertIn(20, vlan_ids)

        arp_hosts = (iface0.get("arp") or {}).get("hosts") or []
        self.assertEqual(len(arp_hosts), 1)
        self.assertEqual(arp_hosts[0].get("ip"), "192.168.1.1")
        self.assertEqual(arp_hosts[0].get("mac"), "aa:bb:cc:dd:ee:ff")

        lldp_neighbors = (iface0.get("lldp") or {}).get("neighbors") or []
        self.assertEqual(len(lldp_neighbors), 1)
        self.assertEqual((lldp_neighbors[0].get("chassis") or {}).get("name"), "sw1")

        cdp_obs = (iface0.get("cdp") or {}).get("observations") or []
        self.assertTrue(cdp_obs)

    def test_discover_topology_handles_missing_tools(self):
        with patch("redaudit.core.topology.shutil.which", return_value=None):
            topo = discover_topology(target_networks=[], network_info=[], extra_tools={})

        self.assertTrue(topo.get("enabled"))
        self.assertEqual(topo.get("tools", {}).get("ip"), False)
        self.assertIsInstance(topo.get("errors"), list)


if __name__ == "__main__":
    unittest.main()


def test_parse_ip_neigh_mac_exception():
    """Test _parse_ip_neigh with mac exception (lines 137, 140)."""
    # Force exception in index access
    stdout = "192.168.1.1 dev eth0 lladdr"
    neigh = _parse_ip_neigh(stdout)
    assert neigh[0]["ip"] == "192.168.1.1"
    assert "mac" not in neigh[0]


def test_parse_vlan_ids_from_ip_link_empty():
    """Test _parse_vlan_ids_from_ip_link with empty/none (lines 150-151)."""
    assert _parse_vlan_ids_from_ip_link(None) == []


def test_parse_vlan_ids_duplicate():
    """Test _parse_vlan_ids_from_ip_link deduplication (line 161)."""
    stdout = "vlan id 10 ... vlan id 10"
    vids = _parse_vlan_ids_from_ip_link(stdout)
    assert vids == [10]


def test_extract_lldp_neighbors_invalid_entry():
    """Test _extract_lldp_neighbors with non-dict entry (lines 194-195)."""
    lldp_json = {"lldp": {"interface": {"eth0": ["not-a-dict"]}}}
    neighs = _extract_lldp_neighbors(lldp_json, "eth0")
    assert neighs == []


def test_networks_from_route_table_exception():
    """Test _networks_from_route_table with invalid network (lines 237-238)."""
    routes = [{"dst": "invalid/33"}]
    assert _networks_from_route_table(routes) == []


def test_discover_topology_async_fallback_and_errors():
    """Test discover_topology async fallback and error paths (lines 252-253, 332, 339, 360, 363-364)."""
    # Test "ip command not found" (360)
    with patch("shutil.which", side_effect=lambda x: None):
        res = discover_topology([], [], logger=MagicMock())
        assert any("ip command not found" in e for e in res["errors"])

    # Test lldp result error (363-364)
    with patch("shutil.which", side_effect=lambda x: "/bin/" + x):
        with patch("redaudit.core.topology._run_cmd", return_value=(1, "", "socket error")):
            res = discover_topology([], [], logger=MagicMock())
            assert any("lldpctl failed" in e for e in res["errors"])


def test_discover_topology_async_exception():
    """Test discover_topology async exception handling."""
    with patch(
        "redaudit.core.topology._discover_topology_async", side_effect=Exception("Async fail")
    ):
        with patch("redaudit.core.topology._discover_topology_sync", return_value={"sync": True}):
            res = discover_topology([], [], logger=MagicMock())
            assert res["sync"] is True


def test_discover_topology_no_selected_ifaces():
    """Test discover_topology when no interfaces overlap with targets."""
    network_info = [{"interface": "eth0", "ip": "10.0.0.1", "network": "10.0.0.0/24"}]
    target_networks = ["192.168.1.0/24"]
    with patch("shutil.which", return_value="/bin/ip"):
        with patch("redaudit.core.topology._run_cmd", return_value=(0, "", "")):
            res = discover_topology(target_networks, network_info)
            assert "eth0" in [i["interface"] for i in res["interfaces"]]


def test_collect_iface_async_errors():
    """Test _collect_iface async error paths (lines 439, 442, 452, 463)."""
    # This is internal to _discover_topology_async, we'll test it via the main entry
    with patch("shutil.which", return_value="/bin/ip"):
        with patch(
            "redaudit.core.topology._run_cmd", return_value=(0, "default via 1.1.1.1 dev eth0", "")
        ):
            # Force empty/error responses for sub-commands
            res = discover_topology(["1.1.1.1/32"], [{"interface": "eth0"}])
            assert "eth0" in [i["interface"] for i in res["interfaces"]]


def test_parse_ip_route_via_exception():
    """Test _parse_ip_route via index exception (line 65)."""
    stdout = "default via"
    routes = _parse_ip_route(stdout)
    assert routes[0]["dst"] == "default"
    assert "via" not in routes[0]


def test_parse_ip_route_dev_exception():
    """Test _parse_ip_route dev index exception (line 73)."""
    stdout = "default dev"
    routes = _parse_ip_route(stdout)
    assert "dev" not in routes[0]


def test_parse_ip_route_src_exception():
    """Test _parse_ip_route src index exception (line 78)."""
    stdout = "default src"
    routes = _parse_ip_route(stdout)
    assert "src" not in routes[0]


def test_parse_ip_route_metric_exception():
    """Test _parse_ip_route metric exception (line 83)."""
    stdout = "default metric abc"
    routes = _parse_ip_route(stdout)
    assert "metric" not in routes[0]


def test_parse_ip_neigh_dev_exception():
    """Test _parse_ip_neigh dev exception (line 134)."""
    stdout = "1.1.1.1 dev"
    neigh = _parse_ip_neigh(stdout)
    assert "dev" not in neigh[0]


def test_parse_vlan_ids_from_ip_link_int_exception():
    """Test _parse_vlan_ids_from_ip_link int exception (line 159)."""
    stdout = "vlan id abc"
    assert _parse_vlan_ids_from_ip_link(stdout) == []


def test_discover_topology_sync_lldp_socket_hint():
    """Test sync discovery lldp socket hint (line 705)."""
    with patch("shutil.which", side_effect=lambda x: "/bin/" + x):
        with patch(
            "redaudit.core.topology._run_cmd",
            side_effect=[
                (0, "default via 1.1.1.1 dev eth0", ""),  # route
                (1, "", "unable to connect"),  # lldp
                (0, "", ""),  # arp-scan
                (0, "", ""),  # ip neigh
                (0, "", ""),  # ip link
                (0, "", ""),  # tcpdump vlan
                (0, "", ""),  # tcpdump cdp
            ],
        ):
            res = _discover_topology_sync([], [{"interface": "eth0"}], logger=MagicMock())
            assert "Hint: try" in res["errors"][0]


def test_extract_default_gateway_no_default():
    """Test _extract_default_gateway with no default route."""
    from redaudit.core.topology import _extract_default_gateway

    routes = [{"dst": "10.0.0.0/8", "via": "192.168.1.1"}]
    gw = _extract_default_gateway(routes)
    assert gw is None


def test_extract_default_gateway_with_default():
    """Test _extract_default_gateway with default route."""
    from redaudit.core.topology import _extract_default_gateway

    routes = [{"dst": "default", "via": "192.168.1.1", "dev": "eth0"}]
    gw = _extract_default_gateway(routes)
    assert gw["ip"] == "192.168.1.1"
    assert gw["interface"] == "eth0"


def test_parse_arp_scan_empty():
    """Test _parse_arp_scan with empty output."""
    from redaudit.core.topology import _parse_arp_scan

    result = _parse_arp_scan("")
    assert result == []


def test_parse_arp_scan_valid():
    """Test _parse_arp_scan with valid output."""
    from redaudit.core.topology import _parse_arp_scan

    stdout = "192.168.1.1\tAA:BB:CC:DD:EE:FF\tVendor Name"
    result = _parse_arp_scan(stdout)
    assert len(result) == 1
    assert result[0]["ip"] == "192.168.1.1"
    assert result[0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_parse_arp_scan_skip_header():
    """Test _parse_arp_scan skips header lines."""
    from redaudit.core.topology import _parse_arp_scan

    stdout = """Interface: eth0, datalink type: EN10MB (Ethernet)
Starting arp-scan 1.10.0
192.168.1.1\tAA:BB:CC:DD:EE:FF\tVendor
Ending arp-scan"""
    result = _parse_arp_scan(stdout)
    assert len(result) == 1


def test_parse_vlan_ids_from_tcpdump():
    """Test _parse_vlan_ids_from_tcpdump function."""
    from redaudit.core.topology import _parse_vlan_ids_from_tcpdump

    stdout = "12:34:56.789 vlan 10, p 0, ethertype IPv4\n12:34:57.000 vlan 20, p 0, ethertype IPv6"
    result = _parse_vlan_ids_from_tcpdump(stdout)
    assert 10 in result
    assert 20 in result


def test_parse_vlan_ids_from_tcpdump_empty():
    """Test _parse_vlan_ids_from_tcpdump with empty output."""
    from redaudit.core.topology import _parse_vlan_ids_from_tcpdump

    result = _parse_vlan_ids_from_tcpdump("")
    assert result == []


def test_extract_lldp_neighbors_empty():
    """Test _extract_lldp_neighbors with empty data."""
    result = _extract_lldp_neighbors({}, "eth0")
    assert result == []


def test_extract_lldp_neighbors_no_interface():
    """Test _extract_lldp_neighbors with missing interface."""
    lldp_json = {"lldp": {"interface": {}}}
    result = _extract_lldp_neighbors(lldp_json, "eth0")
    assert result == []
