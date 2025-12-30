"""
Tests for scanner/traffic.py to push coverage to 95%+.
Targets: 40, 45, 52-54, 68-69, 73, 77, 115, 131, 134-135, 156, 175-176, 180, 184, 219, 244, 284-285
"""

from unittest.mock import patch, MagicMock
import tempfile
import pytest

from redaudit.core.scanner.traffic import (
    capture_traffic_snippet,
    start_background_capture,
    stop_background_capture,
)


def test_capture_traffic_snippet_dry_run():
    """Test capture_traffic_snippet in dry run mode (line 40)."""
    logger = MagicMock()
    result = capture_traffic_snippet(
        "192.168.1.1", "/tmp", [], {"tcpdump": "/usr/bin/tcpdump"}, logger=logger, dry_run=True
    )
    assert result is None
    assert logger.info.called


def test_capture_traffic_snippet_invalid_ip():
    """Test capture_traffic_snippet with invalid IP (line 45)."""
    result = capture_traffic_snippet("invalid-ip", "/tmp", [], {"tcpdump": "/usr/bin/tcpdump"})
    assert result is None


def test_capture_traffic_snippet_invalid_duration():
    """Test capture_traffic_snippet with invalid duration (lines 52-54)."""
    logger = MagicMock()
    with tempfile.TemporaryDirectory() as tmpdir:
        result = capture_traffic_snippet(
            "192.168.1.1",
            tmpdir,
            [{"network": "192.168.1.0/24", "interface": "eth0"}],
            {"tcpdump": "/usr/bin/tcpdump"},
            duration=-5,  # Invalid
            logger=logger,
        )
        assert logger.warning.called


def test_capture_traffic_snippet_network_exception():
    """Test capture_traffic_snippet with network exception (lines 68-69)."""
    networks = [{"network": "invalid", "interface": "eth0"}]
    result = capture_traffic_snippet(
        "192.168.1.1", "/tmp", networks, {"tcpdump": "/usr/bin/tcpdump"}
    )
    # Should handle exception gracefully


def test_capture_traffic_snippet_no_interface():
    """Test capture_traffic_snippet with no interface found (line 73)."""
    logger = MagicMock()
    result = capture_traffic_snippet(
        "192.168.1.1", "/tmp", [], {"tcpdump": "/usr/bin/tcpdump"}, logger=logger  # No networks
    )
    assert result is None
    assert logger.info.called


def test_capture_traffic_snippet_invalid_interface_name():
    """Test capture_traffic_snippet with invalid interface name (line 77)."""
    networks = [{"network": "192.168.1.0/24", "interface": "eth0; rm -rf /"}]
    result = capture_traffic_snippet(
        "192.168.1.1", "/tmp", networks, {"tcpdump": "/usr/bin/tcpdump"}
    )
    assert result is None


def test_capture_traffic_snippet_subprocess_error():
    """Test capture_traffic_snippet with subprocess error (line 115)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("redaudit.core.scanner.traffic._make_runner") as mock_runner_factory:
            mock_runner = MagicMock()
            mock_runner_factory.return_value = mock_runner
            mock_runner.run.side_effect = Exception("Subprocess failed")

            logger = MagicMock()
            result = capture_traffic_snippet(
                "192.168.1.1",
                tmpdir,
                [{"network": "192.168.1.0/24", "interface": "eth0"}],
                {"tcpdump": "/usr/bin/tcpdump"},
                logger=logger,
            )
            # Should handle exception


def test_start_background_capture_dry_run():
    """Test start_background_capture in dry run (line 156)."""
    logger = MagicMock()
    result = start_background_capture(
        "192.168.1.1", "/tmp", [], {"tcpdump": "/usr/bin/tcpdump"}, logger=logger, dry_run=True
    )
    assert result is None


def test_start_background_capture_no_interface():
    """Test start_background_capture with no interface (line 180)."""
    logger = MagicMock()
    result = start_background_capture(
        "192.168.1.1", "/tmp", [], {"tcpdump": "/usr/bin/tcpdump"}, logger=logger
    )
    assert result is None
    assert logger.info.called


def test_start_background_capture_invalid_interface():
    """Test start_background_capture with invalid interface (line 184)."""
    networks = [{"network": "192.168.1.0/24", "interface": "eth0; rm -rf /"}]
    result = start_background_capture(
        "192.168.1.1", "/tmp", networks, {"tcpdump": "/usr/bin/tcpdump"}
    )
    assert result is None


def test_start_background_capture_subprocess_error():
    """Test start_background_capture with subprocess error (line 219)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with patch("subprocess.Popen", side_effect=Exception("Failed")):
            logger = MagicMock()
            result = start_background_capture(
                "192.168.1.1",
                tmpdir,
                [{"network": "192.168.1.0/24", "interface": "eth0"}],
                {"tcpdump": "/usr/bin/tcpdump"},
                logger=logger,
            )
            assert result is None
            assert logger.debug.called


def test_stop_background_capture_path_normalization():
    """Test stop_background_capture with path normalization (line 244)."""
    proc = MagicMock()
    capture_info = {
        "process": proc,
        "pcap_file": "/absolute/path/to/file.pcap",  # Absolute path
        "pcap_file_abs": "/absolute/path/to/file.pcap",
        "iface": "eth0",
    }

    result = stop_background_capture(capture_info, {})
    assert result is not None
    assert "/" not in result["pcap_file"]  # Should be normalized to basename


def test_stop_background_capture_tshark_error():
    """Test stop_background_capture with tshark error (lines 284-285)."""
    with tempfile.NamedTemporaryFile(suffix=".pcap") as tmpfile:
        proc = MagicMock()
        capture_info = {
            "process": proc,
            "pcap_file": "test.pcap",
            "pcap_file_abs": tmpfile.name,
            "iface": "eth0",
        }

        with patch("redaudit.core.scanner.traffic._make_runner") as mock_runner_factory:
            mock_runner = MagicMock()
            mock_runner_factory.return_value = mock_runner
            mock_runner.run.side_effect = Exception("tshark failed")

            logger = MagicMock()
            result = stop_background_capture(
                capture_info, {"tshark": "/usr/bin/tshark"}, logger=logger
            )
            assert "tshark_error" in result
