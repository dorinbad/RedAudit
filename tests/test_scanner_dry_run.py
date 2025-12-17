#!/usr/bin/env python3
"""
RedAudit - Scanner dry-run behavior tests
"""

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from redaudit.core.scanner import start_background_capture, stop_background_capture


class TestScannerDryRun(unittest.TestCase):
    @patch("redaudit.core.scanner.subprocess.Popen")
    @patch("redaudit.core.scanner.os.makedirs")
    def test_start_background_capture_skips_in_dry_run(self, mock_makedirs, mock_popen):
        with patch.dict(os.environ, {"REDAUDIT_DRY_RUN": "1"}):
            res = start_background_capture(
                "192.168.1.10",
                "/tmp/redaudit",
                [{"network": "192.168.1.0/24", "interface": "eth0"}],
                {"tcpdump": "/usr/sbin/tcpdump"},
            )
        self.assertIsNone(res)
        mock_popen.assert_not_called()
        mock_makedirs.assert_not_called()

    @patch("redaudit.core.scanner._make_runner")
    def test_stop_background_capture_skips_tshark_in_dry_run(self, mock_make_runner):
        proc = MagicMock()
        capture_info = {"process": proc, "pcap_file_abs": "/tmp/traffic.pcap", "iface": "eth0"}
        extra_tools = {"tshark": "/usr/bin/tshark"}

        with (
            patch.dict(os.environ, {"REDAUDIT_DRY_RUN": "1"}),
            patch("redaudit.core.scanner.os.path.exists", return_value=True),
            patch("redaudit.core.scanner.os.chmod"),
        ):
            result = stop_background_capture(capture_info, extra_tools)

        self.assertIsInstance(result, dict)
        mock_make_runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()

