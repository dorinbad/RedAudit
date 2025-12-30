"""Tests for topology.py to push coverage to 95%+
Targets missing lines including LLDP edge cases, route parsing, and async fallbacks.
"""

from redaudit.core.topology import (
    _parse_ip_route,
    _parse_ip_neigh,
    _parse_vlan_ids_from_ip_link,
    _extract_lldp_neighbors,
    _networks_from_route_table,
    discover_topology,
    _discover_topology_async,
    _discover_topology_sync,
)
from unittest.mock import patch, MagicMock
import pytest
import asyncio


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
