"""
Final coverage push V3 (expanded) targeting missing lines in topology.py and hyperscan.py.
"""

import pytest
import asyncio
import socket
import json
import re
from unittest.mock import patch, MagicMock, AsyncMock
from redaudit.core.topology import (
    _parse_ip_route,
    _parse_vlan_ids_from_ip_link,
    _parse_vlan_ids_from_tcpdump,
    _extract_lldp_neighbors,
)
from redaudit.core.hyperscan import (
    hyperscan_tcp_sweep,
    hyperscan_udp_sweep,
    _udp_probe,
    _build_ssdp_msearch,
    _build_mdns_query,
    _build_wiz_discovery,
)


# --- topology.py ---
def test_topology_parse_ip_route_exceptions():
    """Test exception handling in _parse_ip_route (lines 65-66, 73-74, 78-79, 83-84)."""
    # Trigger IndexError/ValueError by malforming lines
    stdout = """
    default via
    192.168.1.0/24 dev
    192.168.2.0/24 src
    192.168.3.0/24 metric
    192.168.4.0/24 metric invalid
    """
    # Each line is missing the value after keyword OR value is invalid type
    routes = _parse_ip_route(stdout)
    # Ensure no crashes
    assert len(routes) == 5
    # Check default (line 64-66)
    r_default = [r for r in routes if r.get("dst") == "default"][0]
    assert "via" not in r_default

    # Check dev (line 72-74)
    r_dev = [r for r in routes if "dev" in r["raw"]][0]
    assert "dev" not in r_dev

    # Check src (line 77-79)
    r_src = [r for r in routes if "src" in r["raw"]][0]
    assert "src" not in r_src

    # Check metric index error (line 82-84)
    r_metric = [r for r in routes if "metric" in r["raw"] and "invalid" not in r["raw"]][0]
    assert "metric" not in r_metric

    # Check metric value error
    r_metric_val = [r for r in routes if "invalid" in r["raw"]][0]
    assert "metric" not in r_metric_val


def test_topology_parse_vlan_ids_exceptions():
    """Test exception handling in _parse_vlan_ids... (lines 159-160, 171-172)."""
    # We can't mock global `int` because `re` module uses it internally for compiling regexes!
    # So we patch re.finditer to return a mock match object that returns "invalid" string for group(1)
    # The code `int(m.group(1))` will then execute `int("invalid")` and raise ValueError.

    with patch("re.finditer") as mock_find:
        m = MagicMock()
        m.group.return_value = "invalid"  # int("invalid") raises ValueError
        mock_find.return_value = [m]

        res = _parse_vlan_ids_from_ip_link("vlan id 100")
        assert res == []

    with patch("re.finditer") as mock_find:
        m = MagicMock()
        m.group.return_value = "invalid"
        mock_find.return_value = [m]
        res = _parse_vlan_ids_from_tcpdump("vlan 100")
        assert res == []


# --- hyperscan.py ---
@pytest.mark.asyncio
async def test_hyperscan_udp_probe_exceptions():
    """Test exceptions in _udp_probe (lines 266-267, 267-268 - verify logic)."""
    # _udp_probe lines:
    # 263: except asyncio.TimeoutError: return None
    # 265: finally: sock.close()
    # 267: except Exception: return None

    # 1. Timeout
    sem = asyncio.Semaphore(1)
    with patch("socket.socket") as MockSocket:
        sock = MockSocket.return_value
        loop = MagicMock()
        with patch("asyncio.get_event_loop", return_value=loop):
            # Send ok
            loop.sock_sendto = AsyncMock()
            # Recv timeout
            loop.sock_recv = AsyncMock(side_effect=asyncio.TimeoutError())

            res = await _udp_probe(sem, "1.2.3.4", 99, 0.1)
            assert res is None
            sock.close.assert_called()

    # 2. General Exception (e.g. during sock setup or send)
    with patch("socket.socket", side_effect=Exception("Socket fail")):
        # Should catch and return None
        res = await _udp_probe(sem, "1.2.3.4", 99, 0.1)
        assert res is None


@pytest.mark.asyncio
async def test_hyperscan_tcp_logging_and_empty():
    """Test TCP sweep logging (lines 178-183) and empty results."""
    # lines 178-183: logging total probes
    logger = MagicMock()
    with patch("redaudit.core.hyperscan._tcp_connect", return_value=None):
        await hyperscan_tcp_sweep(["1.2.3.4"], [80], logger=logger)
        logger.info.assert_any_call("HyperScan TCP: %d targets x %d ports = %d probes", 1, 1, 1)


@pytest.mark.asyncio
async def test_hyperscan_udp_sweep_empty_ports():
    """Test UDP sweep with default ports (line 293-294)."""
    with patch("redaudit.core.hyperscan.UDP_DISCOVERY_PORTS", {123: "ntp"}):
        # We invoke without ports argument
        # But to avoid actual network I/O, we must mock _udp_probe or semaphore
        with patch("redaudit.core.hyperscan._udp_probe", return_value=None) as mock_probe:
            await hyperscan_udp_sweep(["1.1.1.1"], ports=None)
            # Should use default port 123
            mock_probe.assert_called()
            args = mock_probe.call_args
            assert args[0][2] == 123


def test_hyperscan_packet_builders():
    """Test packet builder functions for coverage (lines 364-370, 376-383, 396)."""
    # Simply call them to ensure logic is covered
    pkt = _build_ssdp_msearch()
    assert b"M-SEARCH" in pkt

    pkt = _build_mdns_query()
    assert b"_services" in pkt

    pkt = _build_wiz_discovery()
    assert b"registration" in pkt
