"""
Final coverage push V4 targeting _run_cmd in topology.py and unicast probing in hyperscan.py.
"""

import pytest
import socket
from unittest.mock import patch, MagicMock
from redaudit.core.topology import _run_cmd
from redaudit.core.hyperscan import hyperscan_udp_broadcast


# --- topology.py ---
def test_topology_run_cmd():
    """Test _run_cmd function directly (lines 29-45)."""
    with patch("redaudit.core.topology.CommandRunner") as MockRunner:
        runner = MockRunner.return_value
        res = MagicMock()
        res.returncode = 0
        res.stdout = "output"
        res.stderr = "error"
        runner.run.return_value = res

        rc, out, err = _run_cmd(["ls"], 5)
        assert rc == 0
        assert out == "output"
        assert err == "error"

        # Test with non-string output (None/bytes) for coverage of lines 43-44
        res.stdout = None
        res.stderr = None
        rc, out, err = _run_cmd(["ls"], 5)
        assert out == ""
        assert err == ""


# --- hyperscan.py ---
def test_hyperscan_unicast_probe_coverage():
    """Test unicast probing logic in hyperscan_udp_broadcast (lines 485-512)."""
    # This logic runs when network is small or limited to 50 hosts?
    # Logic:
    # 480: if len(all_hosts) <= 100: ...
    # 485: for host in hosts_to_probe: ...
    # 489: sock = socket.socket(...)
    # 493: sock.sendto(...)
    # 495: sock.recvfrom(...)

    # We need to hit lines 496-505 (success response) and 509-510 (exception)

    with patch("ipaddress.ip_network") as mock_net:
        # Mock network to have hosts
        mock_net.return_value.hosts.return_value = ["192.168.1.1"]

        with patch("socket.socket") as MockSocket:
            sock = MockSocket.return_value
            # Success case
            sock.recvfrom.return_value = (b"response", ("192.168.1.1", 12345))

            res = hyperscan_udp_broadcast("192.168.1.0/24")

            # Check results
            # The result structure is complicated, it returns {ip: [...]}?
            # Or dictionary?
            # It returns Dict with results.
            # discovered is accumulated, then deduplicated.
            # Let's verify we got something.
            assert len(res) > 0

            # Exception case (line 509)
            sock.sendto.side_effect = Exception("Send fail")
            res_fail = hyperscan_udp_broadcast("192.168.1.0/24")
            # Should not crash
            assert isinstance(res_fail, list)


def test_hyperscan_unicast_probe_wiz_timeout():
    """Test WiZ timeout logic (lines 491-492)."""
    with patch("ipaddress.ip_network") as mock_net:
        mock_net.return_value.hosts.return_value = ["192.168.1.1"]

        with patch("socket.socket") as MockSocket:
            sock = MockSocket.return_value
            sock.recvfrom.side_effect = socket.timeout()

            # Force "wiz" protocol check
            # We need to change UDP_PROBE_PAYLOADS or mock it?
            # The loop iterates `for port, packet, protocol in probes:`
            # `probes` comes from:
            # probes = [ (1900, msearch, "ssdp"), (5353, mdns, "mdns"), (38899, wiz, "wiz") ]
            # So if we run it, it should hit "wiz" eventually.

            hyperscan_udp_broadcast("192.168.1.0/24")

            # Verify sock.settimeout was called with 0.3
            sock.settimeout.assert_any_call(0.3)
            sock.settimeout.assert_any_call(0.1)
