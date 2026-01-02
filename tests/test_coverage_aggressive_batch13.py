import unittest
from unittest.mock import Mock, patch, MagicMock
from redaudit.core.auditor_scan import AuditorScanMixin


class TestCoverageAggressiveBatch13(unittest.TestCase):
    def setUp(self):
        class MockApp(AuditorScanMixin):
            def __init__(self):
                self.config = {"dry_run": False}
                self.extra_tools = {}
                self.logger = Mock()
                # Dummy _extract_mdns_name
                self.t = lambda x, *args: x

            def _extract_mdns_name(self, data):
                return "MyDevice.local"

        self.app = MockApp()

    def test_enrichment_dry_run(self):
        self.app.config["dry_run"] = True
        res = self.app._run_low_impact_enrichment("1.1.1.1")
        self.assertEqual(res, {})

    def test_enrichment_invalid_ip(self):
        res = self.app._run_low_impact_enrichment("invalid")
        self.assertEqual(res, {})

    @patch("redaudit.core.auditor_scan.CommandRunner")
    def test_enrichment_dns_dig_success(self, mock_runner_cls):
        self.app.extra_tools["dig"] = "/usr/bin/dig"
        mock_runner = mock_runner_cls.return_value
        # Mock dig output
        mock_runner.run.return_value = Mock(stdout="host.example.com.\n", stderr="")

        # Disable mDNS/SNMP for isolation (mock socket/shutil inside test or rely on defaults)
        with patch("socket.socket") as mock_sock, patch("shutil.which", return_value=False):
            res = self.app._run_low_impact_enrichment("1.2.3.4")
            self.assertEqual(res.get("dns_reverse"), "host.example.com")

    @patch("redaudit.core.auditor_scan.CommandRunner")
    def test_enrichment_dns_dig_fail(self, mock_runner_cls):
        self.app.extra_tools["dig"] = "/usr/bin/dig"
        mock_runner = mock_runner_cls.return_value
        mock_runner.run.return_value = Mock(stdout="", stderr="error")

        with patch("socket.socket") as mock_sock, patch("shutil.which", return_value=False):
            res = self.app._run_low_impact_enrichment("1.2.3.4")
            self.assertIsNone(res.get("dns_reverse"))

    @patch("socket.gethostbyaddr")
    def test_enrichment_dns_socket_success(self, mock_gethost):
        # No dig
        self.app.extra_tools = {}
        mock_gethost.return_value = ("fallback.example.com", [], [])

        with patch("socket.socket") as mock_sock, patch("shutil.which", return_value=False):
            res = self.app._run_low_impact_enrichment("1.2.3.4")
            self.assertEqual(res.get("dns_reverse"), "fallback.example.com")

    @patch("socket.gethostbyaddr")
    def test_enrichment_dns_socket_exception(self, mock_gethost):
        self.app.extra_tools = {}
        mock_gethost.side_effect = Exception("NXDOMAIN")

        with patch("socket.socket") as mock_sock, patch("shutil.which", return_value=False):
            res = self.app._run_low_impact_enrichment("1.2.3.4")
            self.assertIsNone(res.get("dns_reverse"))

    @patch("socket.socket")
    def test_enrichment_mdns_success(self, mock_socket_cls):
        mock_sock = mock_socket_cls.return_value
        # Mock recvfrom return (data, addr)
        mock_sock.recvfrom.return_value = (b"some bytes", ("1.2.3.4", 5353))

        with patch("shutil.which", return_value=False):
            res = self.app._run_low_impact_enrichment("1.2.3.4")
            self.assertEqual(res.get("mdns_name"), "MyDevice.local")

    @patch("socket.socket")
    def test_enrichment_mdns_exception_and_finally(self, mock_socket_cls):
        # Exception during sendto
        mock_sock = mock_socket_cls.return_value
        mock_sock.sendto.side_effect = Exception("Network unreachable")
        mock_sock.close.side_effect = Exception("Close error")  # Coverage for close exception

        with patch("shutil.which", return_value=False):
            res = self.app._run_low_impact_enrichment("1.2.3.4")
            self.assertIsNone(res.get("mdns_name"))

    @patch("redaudit.core.auditor_scan.CommandRunner")
    @patch("shutil.which")
    def test_enrichment_snmp_success(self, mock_which, mock_runner_cls):
        mock_which.return_value = True  # snmpwalk exists
        mock_runner = mock_runner_cls.return_value
        # SNMP Output
        mock_runner.run.return_value = Mock(
            stdout='SNMPv2-MIB::sysDescr.0 = "Cisco IOS Software"', stderr=""
        )
        # We simulate simpler output to avoid regex issues with "STRING:" prefix

        with patch("socket.socket"):
            res = self.app._run_low_impact_enrichment("1.2.3.4")
            self.assertEqual(res.get("snmp_sysDescr"), "Cisco IOS Software")

    @patch("redaudit.core.auditor_scan.CommandRunner")
    @patch("shutil.which")
    def test_enrichment_snmp_fail_or_timeout(self, mock_which, mock_runner_cls):
        mock_which.return_value = True
        mock_runner = mock_runner_cls.return_value
        # Timeout
        mock_runner.run.return_value = Mock(stdout="Timeout: No Response from ...", stderr="")

        with patch("socket.socket"):
            res = self.app._run_low_impact_enrichment("1.2.3.4")
            self.assertIsNone(res.get("snmp_sysDescr"))


if __name__ == "__main__":
    unittest.main()
