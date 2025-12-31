"""Tests for hyperscan.py to push coverage to 95%+
Targets missing lines in parallel discovery, IoT broadcast, and backdoor detection.
"""

import asyncio
import socket
import time
from unittest.mock import patch, MagicMock
import pytest
import ipaddress

from redaudit.core.hyperscan import (
    hyperscan_tcp_sweep,
    hyperscan_tcp_sweep_sync,
    hyperscan_udp_sweep,
    hyperscan_udp_sweep_sync,
    hyperscan_udp_broadcast,
    hyperscan_arp_aggressive,
    hyperscan_full_discovery,
    detect_potential_backdoors,
    hyperscan_with_progress,
    hyperscan_with_nmap_enrichment,
    _tcp_connect,
    _udp_probe,
)


@pytest.mark.asyncio
async def test_tcp_connect_exceptions():
    """Test _tcp_connect with various exceptions (lines 132-133)."""
    sem = asyncio.Semaphore(1)
    with patch("asyncio.open_connection", side_effect=ConnectionRefusedError()):
        assert await _tcp_connect(sem, "1.1.1.1", 80, 0.1) is None
    with patch("asyncio.open_connection", side_effect=asyncio.TimeoutError()):
        assert await _tcp_connect(sem, "1.1.1.1", 80, 0.1) is None
    with patch("asyncio.open_connection", side_effect=OSError()):
        assert await _tcp_connect(sem, "1.1.1.1", 80, 0.1) is None


@pytest.mark.asyncio
async def test_hyperscan_tcp_sweep_empty():
    """Test hyperscan_tcp_sweep with empty targets (lines 160-161)."""
    assert await hyperscan_tcp_sweep([], [80]) == {}
    assert await hyperscan_tcp_sweep(["1.1.1.1"], []) == {}


@pytest.mark.asyncio
async def test_udp_probe_exceptions():
    """Test _udp_probe with various exceptions (lines 261, 264-265)."""
    sem = asyncio.Semaphore(1)
    # 261: Timeout
    with patch("socket.socket"):
        with patch("asyncio.get_event_loop") as mock_loop:
            mock_loop.return_value.sock_sendto = MagicMock()
            mock_loop.return_value.sock_recv = MagicMock(side_effect=asyncio.TimeoutError())
            assert await _udp_probe(sem, "1.1.1.1", 53, 0.1) is None
    # 264: General exception
    with patch("socket.socket", side_effect=Exception("Failed")):
        assert await _udp_probe(sem, "1.1.1.1", 53, 0.1) is None


def test_hyperscan_udp_broadcast_edge():
    """Test hyperscan_udp_broadcast with invalid CIDR and socket failures (lines 419, 432, 446-462)."""
    # 419: Invalid network
    assert hyperscan_udp_broadcast("invalid") == []

    # 432, 466: Socket exceptions
    with patch("socket.socket", side_effect=Exception("Socket Fail")):
        res = hyperscan_udp_broadcast("192.168.1.0/24")
        assert res == []


def test_hyperscan_arp_aggressive_failures():
    """Test hyperscan_arp_aggressive with missing tools and timeouts (lines 597, 627, 632, 659)."""
    # 559: arp-scan missing, 632: arping missing
    with patch("shutil.which", return_value=None):
        assert hyperscan_arp_aggressive("1.1.1.0/24") == []

    # 597: arp-scan timeout
    with patch("shutil.which", side_effect=lambda x: "/bin/arp-scan" if x == "arp-scan" else None):
        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(timed_out=True, stdout="")
        with patch("redaudit.core.hyperscan._make_runner", return_value=mock_runner):
            res = hyperscan_arp_aggressive("1.1.1.0/24")
            assert res == []

    # 627: arp-scan exception
    with patch("shutil.which", side_effect=lambda x: "/bin/arp-scan" if x == "arp-scan" else None):
        mock_runner = MagicMock()
        mock_runner.run.side_effect = Exception("Runner Crash")
        with patch("redaudit.core.hyperscan._make_runner", return_value=mock_runner):
            res = hyperscan_arp_aggressive("1.1.1.0/24")
            assert res == []


def test_hyperscan_full_discovery_invalid_net():
    """Test hyperscan_full_discovery with invalid networks (lines 761, 764)."""
    res = hyperscan_full_discovery(["invalid"])
    assert res["total_hosts_found"] == 0


def test_hyperscan_full_discovery_sampling():
    """Test hyperscan_full_discovery network sampling logic (lines 843-852)."""
    # Create a large network (/24)
    ips = [f"1.1.1.{i}" for i in range(1, 255)]
    with patch("redaudit.core.hyperscan.hyperscan_arp_aggressive", return_value=[]):
        with patch("redaudit.core.hyperscan.hyperscan_udp_broadcast", return_value=[]):
            with patch(
                "redaudit.core.hyperscan.hyperscan_tcp_sweep_sync", return_value={}
            ) as mock_tcp:
                hyperscan_full_discovery(["1.1.1.0/24"], include_arp=True, include_udp=True)
                # Check targets length (should be around 150)
                targets = mock_tcp.call_args[0][0]
                assert len(targets) <= 150


def test_detect_potential_backdoors_sev():
    """Test detect_potential_backdoors severity and anomalies (lines 965, 975, 980)."""
    # 965: High port medium severity
    res = detect_potential_backdoors({"1.1.1.1": [50000]})
    assert res[0]["severity"] == "medium"

    # 975: Suspicious service
    with patch("redaudit.core.scanner.is_suspicious_service", return_value=True):
        with patch("redaudit.core.scanner.is_port_anomaly", return_value=False):
            res = detect_potential_backdoors({"1.1.1.1": [80]}, {"1.1.1.1": {80: "backdoor"}})
            assert res[0]["severity"] == "high"
            assert "Suspicious service" in res[0]["reason"]


def test_hyperscan_with_progress_fallback():
    """Test hyperscan_with_progress rich missing fallback (lines 1109, 1111)."""
    # Mock the rich.progress import to raise ImportError
    import sys

    # Temporarily remove rich from sys.modules cache to force re-import attempt
    orig_rich = sys.modules.get("rich.progress")
    sys.modules["rich.progress"] = None  # This will cause ImportError during import

    try:
        # Now when hyperscan_with_progress tries `from rich.progress import ...` it will fail
        with patch("redaudit.core.hyperscan.hyperscan_full_discovery", return_value={"ok": True}):
            res = hyperscan_with_progress(["1.1.1.0/24"])
            assert res["ok"] is True
    finally:
        # Restore original
        if orig_rich is not None:
            sys.modules["rich.progress"] = orig_rich
        elif "rich.progress" in sys.modules:
            del sys.modules["rich.progress"]


def test_hyperscan_with_nmap_enrichment_missing():
    """Test hyperscan_with_nmap_enrichment nmap missing (lines 1142-1143, 1146-1147)."""
    # 1142: Missing nmap
    with patch("shutil.which", return_value=None):
        res = hyperscan_with_nmap_enrichment({"tcp_hosts": {"1.1.1.1": [80]}})
        assert "service_info" not in res

    # 1146: Empty tcp_hosts
    with patch("shutil.which", return_value="/bin/nmap"):
        res = hyperscan_with_nmap_enrichment({"tcp_hosts": {}})
        assert "service_info" not in res


def test_hyperscan_with_nmap_enrichment_parse():
    """Test hyperscan_with_nmap_enrichment output parsing (lines 1165-1176)."""
    with patch("shutil.which", return_value="/bin/nmap"):
        mock_runner = MagicMock()
        mock_runner.run.return_value = MagicMock(
            stdout="80/tcp open http\n443/tcp open https", stderr=""
        )
        with patch("redaudit.core.hyperscan._make_runner", return_value=mock_runner):
            res = hyperscan_with_nmap_enrichment({"tcp_hosts": {"1.1.1.1": [80, 443]}})
            assert res["service_info"]["1.1.1.1"][80] == "http"
            assert res["service_info"]["1.1.1.1"][443] == "https"
